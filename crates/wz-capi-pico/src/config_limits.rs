// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! [`WZ_EXT_CONFIG_LIMITS_KEY`]: the limits of the session `z_open` opens from a config, stated
//! through the numbered keys every build of this ABI reads (`zp_config_insert`).
//!
//! A session opens its tables at a few (`crate::session::opening_limits`) and takes no memory
//! after its open, so a program that holds more says so before it opens, as a DDS reader names
//! its resource limits in its QoS. The build's value of each limit is the bound: what the build
//! reserves memory for at most, and a statement past it is refused. The key needs no
//! `config-policy`, so the zenoh-pico preset, which leaves those doors out, has it too.
//!
//! Its value is `NAME=count` items, separated by commas, each `NAME` a session limit's id as the
//! declaration spells it (`MAX_SUBSCRIPTIONS=4,MAX_PUBLISHERS=2`). Items apply left to right, so a
//! limit named twice takes the later count.

use wz_session_core::limit_binding::LimitValue;
use wz_session_core::limits::{SessionLimits, SESSION_LIMITS};

use crate::result::{ZResult, Z_ERR_CONFIG_INVALID_VALUE};

/// The config key whose value states the session's limits (`wz_ext.h`). Past zenoh-pico's own
/// keys, which end at `Z_CONFIG_LISTEN_EXIT_ON_FAILURE_KEY` (0x5A), so no upstream key is taken.
pub const WZ_EXT_CONFIG_LIMITS_KEY: u8 = 0xC0;

/// `limits` with each count `text` states selected over it, or `Z_ERR_CONFIG_INVALID_VALUE` and
/// `limits` as it was: for an item that is not `NAME=count`, a name that is no limit of a
/// session (a runtime's limit included), a limit no machine reads from the snapshot, a count the
/// build's domain leaves out, and a count past the build's value, the bound the build reserves.
pub(crate) fn state_over(text: &str, limits: &mut SessionLimits) -> Result<(), ZResult> {
    let mut stated = *limits;
    for item in text
        .split(',')
        .map(str::trim_ascii)
        .filter(|item| !item.is_empty())
    {
        let (name, count) = item.split_once('=').ok_or(Z_ERR_CONFIG_INVALID_VALUE)?;
        let entry = SESSION_LIMITS
            .iter()
            .find(|entry| entry.id() == name.trim_ascii())
            .ok_or(Z_ERR_CONFIG_INVALID_VALUE)?;
        let count = count
            .trim_ascii()
            .parse::<usize>()
            .map_err(|_| Z_ERR_CONFIG_INVALID_VALUE)?;
        if let LimitValue::Integer(bound) = entry.value_in(&SessionLimits::BUILD) {
            if count > bound {
                return Err(Z_ERR_CONFIG_INVALID_VALUE);
            }
        }
        match entry.select(&mut stated, LimitValue::Integer(count)) {
            Some(Ok(())) => {}
            Some(Err(_)) | None => return Err(Z_ERR_CONFIG_INVALID_VALUE),
        }
    }
    *limits = stated;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::state_over;
    use crate::result::Z_ERR_CONFIG_INVALID_VALUE;
    use wz_session_core::limit_binding::Quota;
    use wz_session_core::limits::SessionLimits;

    /// The build's value of `MAX_SUBSCRIPTIONS`, the bound a statement is held to, where it is a
    /// count.
    fn subscriptions_bound() -> Option<usize> {
        SessionLimits::BUILD.max_subscriptions().most()
    }

    /// A count under the bound is selected over the limits the session opens under, and the
    /// limits it does not name keep their values. Turned red by a door that drops the statement.
    #[test]
    fn a_stated_count_under_the_bound_is_what_the_session_opens_with() {
        let opening = crate::session::opening_limits();
        let mut probe = opening;
        if probe.select_max_subscriptions(Quota::at_most(2)).is_err()
            || subscriptions_bound().is_some_and(|bound| bound < 2)
        {
            return;
        }
        let mut limits = opening;
        assert_eq!(state_over(" MAX_SUBSCRIPTIONS = 2 ,", &mut limits), Ok(()));
        assert_eq!(limits.max_subscriptions(), Quota::at_most(2));
        assert_eq!(limits.max_publishers(), opening.max_publishers());
    }

    /// A count past the build's value is refused and leaves the limits as they were, though an
    /// earlier item of the same text was good. Turned red by a door that holds a count to the
    /// domain alone, which a build that sizes nothing ahead leaves open past the bound.
    #[test]
    fn a_count_past_the_builds_value_is_refused() {
        let Some(bound) = subscriptions_bound() else {
            return;
        };
        let opening = crate::session::opening_limits();
        let mut limits = opening;
        let past = alloc::format!("MAX_PUBLISHERS=1,MAX_SUBSCRIPTIONS={}", bound + 1);
        assert_eq!(
            state_over(&past, &mut limits),
            Err(Z_ERR_CONFIG_INVALID_VALUE)
        );
        assert_eq!(limits, opening);
    }

    /// A name that is no limit of a session, a runtime's limit included, an item with no count
    /// and a count that is no number are refused, each leaving the limits as they were. Turned
    /// red by a door that skips what it does not know.
    #[test]
    fn what_is_no_session_limit_or_no_count_is_refused() {
        let opening = crate::session::opening_limits();
        for text in [
            "NO_SUCH_LIMIT=1",
            "HELD_SESSIONS=1",
            "MAX_SUBSCRIPTIONS",
            "MAX_SUBSCRIPTIONS=many",
            "MAX_SUBSCRIPTIONS=-1",
        ] {
            let mut limits = opening;
            assert_eq!(
                state_over(text, &mut limits),
                Err(Z_ERR_CONFIG_INVALID_VALUE),
                "{text}"
            );
            assert_eq!(limits, opening, "{text}");
        }
    }

    /// A text that states nothing leaves the limits as they are.
    #[test]
    fn an_empty_text_states_nothing() {
        let opening = crate::session::opening_limits();
        let mut limits = opening;
        assert_eq!(state_over("", &mut limits), Ok(()));
        assert_eq!(limits, opening);
    }
}
