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
//! limit named twice takes the later count. Where the build has process pools, `NAME` may also be
//! one of the values a program holds apart from any session (`HELD_SAMPLES`,
//! `HELD_SMALL_PAYLOAD_BLOCKS`, ...): the first open reserves those pools from its statement and
//! fixes them, so a later open that states more of one is refused (`crate::process_pool`).

use wz_session_core::limit_binding::LimitValue;
use wz_session_core::limits::{SessionLimits, SESSION_LIMITS};

use crate::result::{ZResult, Z_ERR_CONFIG_INVALID_VALUE};

/// The config key whose value states the session's limits (`wz_ext.h`). Past zenoh-pico's own
/// keys, which end at `Z_CONFIG_LISTEN_EXIT_ON_FAILURE_KEY` (0x5A), so no upstream key is taken.
pub const WZ_EXT_CONFIG_LIMITS_KEY: u8 = 0xC0;

/// What an open composes from a config: the limits of the session it opens and, where the build
/// has process pools, the counts of the values a program holds apart from any session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Stated {
    pub(crate) limits: SessionLimits,
    #[cfg(wz_process_pools)]
    pub(crate) held: crate::process_pool::Held,
}

impl Stated {
    /// `limits`, and the build's held values, before the key states any.
    pub(crate) const fn over(limits: SessionLimits) -> Self {
        Self {
            limits,
            #[cfg(wz_process_pools)]
            held: crate::process_pool::Held::BUILD,
        }
    }
}

/// `stated` with each count `text` states selected over it, or `Z_ERR_CONFIG_INVALID_VALUE` and
/// `stated` as it was: for an item that is not `NAME=count`, a name that is no limit of a
/// session nor a held value of the process pools (any other runtime limit included), a limit no
/// machine reads from the snapshot, a count the build's domain leaves out, and a count past the
/// build's value, the bound the build reserves.
pub(crate) fn state_over(text: &str, stated: &mut Stated) -> Result<(), ZResult> {
    let mut next = *stated;
    for item in text
        .split(',')
        .map(str::trim_ascii)
        .filter(|item| !item.is_empty())
    {
        let (name, count) = item.split_once('=').ok_or(Z_ERR_CONFIG_INVALID_VALUE)?;
        let name = name.trim_ascii();
        let count = count
            .trim_ascii()
            .parse::<usize>()
            .map_err(|_| Z_ERR_CONFIG_INVALID_VALUE)?;
        #[cfg(wz_process_pools)]
        {
            if let Some(admitted) = next.held.select(name, count) {
                if !admitted {
                    return Err(Z_ERR_CONFIG_INVALID_VALUE);
                }
                continue;
            }
        }
        let entry = SESSION_LIMITS
            .iter()
            .find(|entry| entry.id() == name)
            .ok_or(Z_ERR_CONFIG_INVALID_VALUE)?;
        if let LimitValue::Integer(bound) = entry.value_in(&SessionLimits::BUILD) {
            if count > bound {
                return Err(Z_ERR_CONFIG_INVALID_VALUE);
            }
        }
        match entry.select(&mut next.limits, LimitValue::Integer(count)) {
            Some(Ok(())) => {}
            Some(Err(_)) | None => return Err(Z_ERR_CONFIG_INVALID_VALUE),
        }
    }
    *stated = next;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{state_over, Stated};
    use crate::result::Z_ERR_CONFIG_INVALID_VALUE;
    use wz_session_core::limit_binding::Quota;
    use wz_session_core::limits::SessionLimits;

    /// The build's value of `MAX_SUBSCRIPTIONS`, the bound a statement is held to, where it is a
    /// count.
    fn subscriptions_bound() -> Option<usize> {
        SessionLimits::BUILD.max_subscriptions().most()
    }

    /// What an open composes before the key states anything.
    fn opening() -> Stated {
        Stated::over(crate::session::opening_limits())
    }

    /// A count under the bound is selected over the limits the session opens under, and the
    /// limits it does not name keep their values. Turned red by a door that drops the statement.
    #[test]
    fn a_stated_count_under_the_bound_is_what_the_session_opens_with() {
        let opening = opening();
        let mut probe = opening.limits;
        if probe.select_max_subscriptions(Quota::at_most(2)).is_err()
            || subscriptions_bound().is_some_and(|bound| bound < 2)
        {
            return;
        }
        let mut stated = opening;
        assert_eq!(state_over(" MAX_SUBSCRIPTIONS = 2 ,", &mut stated), Ok(()));
        assert_eq!(stated.limits.max_subscriptions(), Quota::at_most(2));
        assert_eq!(
            stated.limits.max_publishers(),
            opening.limits.max_publishers()
        );
    }

    /// A count past the build's value is refused and leaves the statement as it was, though an
    /// earlier item of the same text was good. Turned red by a door that holds a count to the
    /// domain alone, which a build that sizes nothing ahead leaves open past the bound.
    #[test]
    fn a_count_past_the_builds_value_is_refused() {
        let Some(bound) = subscriptions_bound() else {
            return;
        };
        let opening = opening();
        let mut stated = opening;
        let past = alloc::format!("MAX_PUBLISHERS=1,MAX_SUBSCRIPTIONS={}", bound + 1);
        assert_eq!(
            state_over(&past, &mut stated),
            Err(Z_ERR_CONFIG_INVALID_VALUE)
        );
        assert_eq!(stated, opening);
    }

    /// A name that is no limit of a session nor a held value, any other runtime limit included,
    /// an item with no count and a count that is no number are refused, each leaving the
    /// statement as it was. Turned red by a door that skips what it does not know.
    #[test]
    fn what_is_no_session_limit_or_no_count_is_refused() {
        let opening = opening();
        for text in [
            "NO_SUCH_LIMIT=1",
            "HELD_SESSIONS=1",
            "HELD_CONFIGS=1",
            "MAX_SUBSCRIPTIONS",
            "MAX_SUBSCRIPTIONS=many",
            "MAX_SUBSCRIPTIONS=-1",
        ] {
            let mut stated = opening;
            assert_eq!(
                state_over(text, &mut stated),
                Err(Z_ERR_CONFIG_INVALID_VALUE),
                "{text}"
            );
            assert_eq!(stated, opening, "{text}");
        }
    }

    /// A text that states nothing leaves the statement as it is.
    #[test]
    fn an_empty_text_states_nothing() {
        let opening = opening();
        let mut stated = opening;
        assert_eq!(state_over("", &mut stated), Ok(()));
        assert_eq!(stated, opening);
    }

    /// A held value's count is stated beside the session's limits, and one past the build's value
    /// is refused with the whole text. Turned red by a door that reads only the session's limits,
    /// or one that holds a held value to no bound.
    #[cfg(wz_process_pools)]
    #[test]
    fn a_held_value_is_stated_up_to_the_builds_value() {
        use wz_session_core::caps;
        let opening = opening();
        let mut stated = opening;
        let text = alloc::format!(
            "HELD_SAMPLES={},HELD_LARGE_PAYLOAD_BLOCKS=0",
            caps::HELD_SAMPLES
        );
        assert_eq!(state_over(&text, &mut stated), Ok(()));
        let mut expected = crate::process_pool::Held::BUILD;
        assert_eq!(expected.select("HELD_LARGE_PAYLOAD_BLOCKS", 0), Some(true));
        assert_eq!(stated.held, expected);
        assert_eq!(stated.limits, opening.limits);

        let mut refused = opening;
        let past = alloc::format!("HELD_SAMPLES=1,HELD_REPLIES={}", caps::HELD_REPLIES + 1);
        assert_eq!(
            state_over(&past, &mut refused),
            Err(Z_ERR_CONFIG_INVALID_VALUE)
        );
        assert_eq!(refused, opening);
    }
}
