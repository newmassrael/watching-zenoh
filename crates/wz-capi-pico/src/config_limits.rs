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

use wz_session_core::limit_binding::{LimitEntry, LimitValue};
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

impl Stated {
    /// `self` with the count of the limit `name` at `count`; `false`, and `self` as it was,
    /// for a name that is no limit of a session nor a held value of the process pools, a limit
    /// no machine reads from the snapshot, a count the build's domain leaves out, and a count past
    /// the build's value, the bound the build reserves.
    fn select(&mut self, name: &[u8], count: usize) -> bool {
        #[cfg(wz_process_pools)]
        {
            if let Some(admitted) = self.held.select(name, count) {
                return admitted;
            }
        }
        let at = position_named(session_limit_id, name);
        let Some(entry) = at.and_then(|at| SESSION_LIMITS.get(at)) else {
            return false;
        };
        if let LimitValue::Integer(bound) = entry.value_in(&SessionLimits::BUILD) {
            if count > bound {
                return false;
            }
        }
        matches!(
            entry.select(&mut self.limits, LimitValue::Integer(count)),
            Some(Ok(()))
        )
    }
}

/// What an open composes over `limits`: [`Stated::over`] them, each count `text`, the key's value
/// where the config holds one, states selected over it ([`Stated::select`]);
/// `Z_ERR_CONFIG_INVALID_VALUE` for an item that is not `NAME=count` or one the build refuses.
/// One body for every door that reads the key: `zp_config_insert` judges a value with it as the
/// open composes it, and an open whose config holds none composes through it too.
#[inline(never)]
pub(crate) fn state_over(text: Option<&str>, limits: &SessionLimits) -> Result<Stated, ZResult> {
    let mut next = Stated::over(*limits);
    // Read as bytes: the separators are ASCII, and a byte's search is a plain loop where a
    // `char`'s pulls in the string searcher. No value states nothing, as an empty one does.
    for item in text
        .unwrap_or_default()
        .as_bytes()
        .split(|byte| *byte == b',')
        .map(<[u8]>::trim_ascii)
        .filter(|item| !item.is_empty())
    {
        let mut halves = item.splitn(2, |byte| *byte == b'=');
        let (Some(name), Some(count)) = (halves.next(), halves.next()) else {
            return Err(Z_ERR_CONFIG_INVALID_VALUE);
        };
        // The item is trimmed at both ends, so a name has spaces only before the `=` and a count
        // only after it.
        let count = count_of(count.trim_ascii_start()).ok_or(Z_ERR_CONFIG_INVALID_VALUE)?;
        if !next.select(name.trim_ascii_end(), count) {
            return Err(Z_ERR_CONFIG_INVALID_VALUE);
        }
    }
    Ok(next)
}

/// Whether `name` spells the id `id`, byte for byte: a name that is no text spells none.
fn names(id: &str, name: &[u8]) -> bool {
    id.as_bytes() == name
}

/// The id of the session limit at `at` among [`SESSION_LIMITS`], or `None` past the last.
fn session_limit_id(at: usize) -> Option<&'static str> {
    SESSION_LIMITS.get(at).map(LimitEntry::id)
}

/// The first place, counted from `0`, whose id `id_at` answers is the one `name` spells
/// ([`names`]), or `None` when `id_at` answers none before its first `None`. One loop every
/// table a statement's name is found in shares, each id read through the table's own function: a
/// short table known when compiled, walked where it is named, is unrolled into a comparison of its
/// own for each row, and a table handed as an iterator object brings every method of its iterator.
#[inline(never)]
pub(crate) fn position_named(
    id_at: fn(usize) -> Option<&'static str>,
    name: &[u8],
) -> Option<usize> {
    let mut at = 0;
    while let Some(id) = id_at(at) {
        if names(id, name) {
            return Some(at);
        }
        at += 1;
    }
    None
}

/// The count `digits` spell in decimal, read as `usize`'s `FromStr` reads one: an optional `+`
/// and one digit or more, none past `usize::MAX`; `None` for anything else.
fn count_of(digits: &[u8]) -> Option<usize> {
    let digits = digits.strip_prefix(b"+").unwrap_or(digits);
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0usize, |count, digit| {
        let value = digit.checked_sub(b'0').filter(|value| *value < 10)?;
        count.checked_mul(10)?.checked_add(usize::from(value))
    })
}

#[cfg(test)]
mod tests {
    use super::{count_of, names, position_named, state_over, Stated};
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
        let stated = state_over(Some(" MAX_SUBSCRIPTIONS = 2 ,"), &opening.limits)
            .expect("a count under the bound is stated");
        assert_eq!(stated.limits.max_subscriptions(), Quota::at_most(2));
        assert_eq!(
            stated.limits.max_publishers(),
            opening.limits.max_publishers()
        );
    }

    /// A count past the build's value is refused, though an earlier item of the same text was
    /// good. Turned red by a door that holds a count to the domain alone, which a build that sizes
    /// nothing ahead leaves open past the bound.
    #[test]
    fn a_count_past_the_builds_value_is_refused() {
        let Some(bound) = subscriptions_bound() else {
            return;
        };
        let past = alloc::format!("MAX_PUBLISHERS=1,MAX_SUBSCRIPTIONS={}", bound + 1);
        assert_eq!(
            state_over(Some(past.as_str()), &opening().limits),
            Err(Z_ERR_CONFIG_INVALID_VALUE)
        );
    }

    /// A name that is no limit of a session nor a held value, any other runtime limit included,
    /// a name one letter short or long of a limit's, an item with no count and a count that is
    /// no number are refused. Turned red by a door that skips what it does not know, or a name
    /// found by its prefix.
    #[test]
    fn what_is_no_session_limit_or_no_count_is_refused() {
        let opening = opening();
        for text in [
            "MAX_SUBSCRIPTION=1",
            "MAX_SUBSCRIPTIONSS=1",
            "NO_SUCH_LIMIT=1",
            "HELD_SESSIONS=1",
            "HELD_CONFIGS=1",
            "MAX_SUBSCRIPTIONS",
            "MAX_SUBSCRIPTIONS=many",
            "MAX_SUBSCRIPTIONS=-1",
        ] {
            assert_eq!(
                state_over(Some(text), &opening.limits),
                Err(Z_ERR_CONFIG_INVALID_VALUE),
                "{text}"
            );
        }
    }

    /// A name is found at the place of the id it spells, the first of two that it spells, and
    /// nowhere among ids it does not spell. Turned red by a search that answers the last place it
    /// looked at, or a place counted from one.
    #[test]
    fn a_name_is_found_at_its_ids_place() {
        const IDS: [&str; 4] = [
            "HELD_SAMPLES",
            "MAX_PUBLISHERS",
            "MAX_PUBLISHERS",
            "HELD_REPLIES",
        ];
        let listed = |at: usize| IDS.get(at).copied();
        assert_eq!(position_named(listed, b"HELD_SAMPLES"), Some(0));
        assert_eq!(position_named(listed, b"MAX_PUBLISHERS"), Some(1));
        assert_eq!(position_named(listed, b"HELD_REPLIES"), Some(3));
        assert_eq!(position_named(listed, b"HELD_REPLIE"), None);
        assert_eq!(position_named(|_| None, b"HELD_REPLIES"), None);
    }

    /// The session limits' ids are read in their table's order and end with it. Turned red by a
    /// reading that skips a row or reads past the last.
    #[test]
    fn the_session_limits_ids_are_read_in_order() {
        use super::session_limit_id;
        use wz_session_core::limits::SESSION_LIMITS;
        for (at, entry) in SESSION_LIMITS.iter().enumerate() {
            assert_eq!(session_limit_id(at), Some(entry.id()));
        }
        assert_eq!(session_limit_id(SESSION_LIMITS.len()), None);
    }

    /// A name spells an id when its bytes are the id's, and no prefix of the id, no longer name
    /// and no bytes that are no text spell it. Turned red by a comparison of the shorter length.
    #[test]
    fn a_name_spells_an_id_byte_for_byte() {
        assert!(names("MAX_PUBLISHERS", b"MAX_PUBLISHERS"));
        assert!(!names("MAX_PUBLISHERS", b"MAX_PUBLISHER"));
        assert!(!names("MAX_PUBLISHERS", b"MAX_PUBLISHERSS"));
        assert!(!names("MAX_PUBLISHERS", b"max_publishers"));
        assert!(!names("MAX_PUBLISHERS", b"MAX_PUBLISHER\xff"));
        assert!(!names("MAX_PUBLISHERS", b""));
    }

    /// A count is read as `usize`'s `FromStr` reads it: a sign of `+` and digits are a count, up
    /// to `usize::MAX`, and no digit, a sign alone, a minus, a space inside or a count past the
    /// largest is none. Turned red by a reading that admits what `FromStr` refuses, or the other
    /// way round.
    #[test]
    fn a_count_is_read_as_a_usize_is_parsed() {
        let largest = alloc::format!("{}", usize::MAX);
        let past = alloc::format!("{}0", usize::MAX);
        for text in [
            "0",
            "7",
            "+7",
            "0042",
            "",
            "+",
            "-1",
            "1x",
            " 1",
            "1 ",
            "++1",
            largest.as_str(),
            past.as_str(),
        ] {
            assert_eq!(
                count_of(text.as_bytes()),
                text.parse::<usize>().ok(),
                "{text:?}"
            );
        }
        assert_eq!(count_of(largest.as_bytes()), Some(usize::MAX));
        assert_eq!(count_of(past.as_bytes()), None);
    }

    /// Spaces and tabs around a name, its `=` and its count state what the bare item states.
    /// Turned red by a reading that keeps a space at either side of the `=`.
    #[test]
    fn spaces_around_an_items_parts_state_what_the_bare_item_does() {
        let opening = opening();
        let limits = &opening.limits;
        let mut stated_any = false;
        for (name, count) in [
            ("MAX_PUBLISHERS", limits.max_publishers().most()),
            ("MAX_SUBSCRIPTIONS", limits.max_subscriptions().most()),
            (
                "MAX_DECLARED_KEYEXPRS",
                limits.max_declared_keyexprs().most(),
            ),
        ] {
            let Some(count) = count else {
                continue;
            };
            let bare = alloc::format!("{name}={count}");
            let spaced = alloc::format!(" \t{name} \t=\t {count}\t , ");
            let stated = state_over(Some(bare.as_str()), limits);
            stated_any |= stated.is_ok();
            assert_eq!(state_over(Some(spaced.as_str()), limits), stated, "{name}");
        }
        assert!(stated_any, "an opening count of an entity is stated");
    }

    /// A text that states nothing, and no text, leave the statement as it is. Turned red by a
    /// door that refuses a config without the key, or an empty item.
    #[test]
    fn an_empty_text_states_nothing() {
        let opening = opening();
        assert_eq!(state_over(None, &opening.limits), Ok(opening));
        assert_eq!(state_over(Some(""), &opening.limits), Ok(opening));
        assert_eq!(state_over(Some(" , ,"), &opening.limits), Ok(opening));
    }

    /// A held value's count is stated beside the session's limits, and one past the build's value
    /// is refused with the whole text. Turned red by a door that reads only the session's limits,
    /// or one that holds a held value to no bound.
    #[cfg(wz_process_pools)]
    #[test]
    fn a_held_value_is_stated_up_to_the_builds_value() {
        use wz_session_core::caps;
        let opening = opening();
        let text = alloc::format!(
            "HELD_SAMPLES={},HELD_LARGE_PAYLOAD_BLOCKS=0",
            caps::HELD_SAMPLES
        );
        let stated = state_over(Some(text.as_str()), &opening.limits)
            .expect("held values under their bounds");
        let mut expected = crate::process_pool::Held::BUILD;
        assert_eq!(expected.select(b"HELD_LARGE_PAYLOAD_BLOCKS", 0), Some(true));
        assert_eq!(stated.held, expected);
        assert_eq!(stated.limits, opening.limits);

        let past = alloc::format!("HELD_SAMPLES=1,HELD_REPLIES={}", caps::HELD_REPLIES + 1);
        assert_eq!(
            state_over(Some(past.as_str()), &opening.limits),
            Err(Z_ERR_CONFIG_INVALID_VALUE)
        );
    }
}
