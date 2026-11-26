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

    /// What an open composes its config's statements over: the limits a session opens under
    /// before its config states any (`crate::session::opening_limits`) and the build's held
    /// values. A constant, so each door that composes a statement starts from a copy of it.
    pub(crate) const OPENING: Self = Self::over(crate::session::opening_limits());
}

impl Stated {
    /// `self` with the count of the limit `name` at `count`; `false`, and `self` as it was,
    /// for a name that is no limit of a session nor a held value of the process pools, a limit
    /// no machine reads from the snapshot, a count the build's domain leaves out, and a count past
    /// the build's value, the bound the build reserves.
    fn select(&mut self, name: &[u8], count: usize) -> bool {
        let Some(at) = position_named(statement_id, name) else {
            return false;
        };
        #[cfg(wz_process_pools)]
        let at = match at.checked_sub(crate::process_pool::HELD) {
            Some(at) => at,
            None => return self.held.select_at(at, count),
        };
        let Some(entry) = SESSION_LIMITS.get(at) else {
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

/// Select over `stated` each count `text`, the key's value where the config holds one, states
/// ([`Stated::select`]), left to right; `Z_ERR_CONFIG_INVALID_VALUE` for an item that is not
/// `NAME=count` or one the build refuses, and then what was written is no statement, which the
/// caller drops. Written in place: an open composes its config's limits and then these over the
/// one statement it opens from, which no layer copies out. One body for every door that reads the
/// key: `zp_config_insert` judges a value with it as the open composes it, and an open whose
/// config holds none composes through it too.
#[inline(never)]
pub(crate) fn state_over(text: Option<&str>, stated: &mut Stated) -> Result<(), ZResult> {
    // Read as bytes: the separators are ASCII, and a byte's search is a plain loop where a
    // `char`'s pulls in the string searcher. No value states nothing, as an empty one does.
    // Walked by hand rather than through a splitting iterator, whose end states each reached the
    // trim apart.
    // The text after the last comma is its last item, and an empty rest holds none: an item
    // that is empty states nothing, so a text that ends in a comma loses nothing by the stop.
    let mut rest = text.unwrap_or_default().as_bytes();
    while !rest.is_empty() {
        let (item, after) = split_at_first(rest, b',').unwrap_or((rest, Default::default()));
        rest = after;
        let item = trimmed(item);
        if item.is_empty() {
            continue;
        }
        let (name, count) = split_at_first(item, b'=').ok_or(Z_ERR_CONFIG_INVALID_VALUE)?;
        let count = count_of(trimmed(count)).ok_or(Z_ERR_CONFIG_INVALID_VALUE)?;
        if !stated.select(trimmed(name), count) {
            return Err(Z_ERR_CONFIG_INVALID_VALUE);
        }
    }
    Ok(())
}

/// `bytes` before and after the first `separator`, which neither holds; `None` where `bytes`
/// holds none.
fn split_at_first(bytes: &[u8], separator: u8) -> Option<(&[u8], &[u8])> {
    let at = bytes.iter().position(|byte| *byte == separator)?;
    let (before, after) = bytes.split_at(at);
    Some((before, after.get(1..).unwrap_or_default()))
}

/// `bytes` without the ASCII whitespace at either end. Out of line: an item, its name and its
/// count are each trimmed, and inlined each trim carried its two loops of its own.
#[inline(never)]
fn trimmed(bytes: &[u8]) -> &[u8] {
    bytes.trim_ascii()
}

/// Whether `name` spells the id `id`, byte for byte: a name that is no text spells none.
fn names(id: &str, name: &[u8]) -> bool {
    id.as_bytes() == name
}

/// The id of the statement at `at` among those an item may name, or `None` past the last: the
/// values a program holds apart from any session first, where the build has process pools
/// (`crate::process_pool::held_id`), then the session limits ([`SESSION_LIMITS`]). One table, so
/// an item's name is found by one walk whichever it names.
fn statement_id(at: usize) -> Option<&'static str> {
    #[cfg(wz_process_pools)]
    let at = match at.checked_sub(crate::process_pool::HELD) {
        Some(at) => at,
        None => return crate::process_pool::held_id(at),
    };
    SESSION_LIMITS.get(at).map(LimitEntry::id)
}

/// The first place, counted from `0`, whose id `id_at` answers is the one `name` spells
/// ([`names`]), or `None` when `id_at` answers none before its first `None`. One loop for any
/// table a name is found in, each id read through the table's own function: a
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
        at = at.saturating_add(1);
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
    use super::{count_of, names, position_named, split_at_first, state_over, trimmed, Stated};
    use crate::result::{ZResult, Z_ERR_CONFIG_INVALID_VALUE};
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

    /// What an open composes from `text` over what it opens from, as the open writes it.
    fn state(text: Option<&str>) -> Result<Stated, ZResult> {
        let mut stated = Stated::OPENING;
        state_over(text, &mut stated).map(|()| stated)
    }

    /// An open composes from the limits a session opens under and the build's held values.
    /// Turned red by a constant built over other limits than the open's.
    #[test]
    fn an_open_composes_from_the_opening_limits() {
        assert_eq!(Stated::OPENING, opening());
    }

    /// A text is stated over what the statement holds, so a limit the text does not name keeps
    /// the value an earlier layer wrote. Turned red by a door that starts again from the
    /// limits a session opens under.
    #[test]
    fn a_text_is_stated_over_what_the_statement_holds() {
        let mut stated = Stated::OPENING;
        let opening = stated.limits.max_publishers();
        let Some(written) = [Quota::at_most(1), Quota::at_most(2)]
            .into_iter()
            .find(|quota| *quota != opening)
        else {
            return;
        };
        if stated.limits.select_max_publishers(written).is_err() {
            return;
        }
        let Some(count) = stated.limits.max_subscriptions().most() else {
            return;
        };
        let text = alloc::format!("MAX_SUBSCRIPTIONS={count}");
        assert_eq!(state_over(Some(text.as_str()), &mut stated), Ok(()));
        assert_eq!(stated.limits.max_publishers(), written);
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
        let stated =
            state(Some(" MAX_SUBSCRIPTIONS = 2 ,")).expect("a count under the bound is stated");
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
        assert_eq!(state(Some(past.as_str())), Err(Z_ERR_CONFIG_INVALID_VALUE));
    }

    /// A session's reassembly buffers are stated by `REASSEMBLY_CHAINS` as any count of what its
    /// open reserves: none, one, and the build's value itself, which the open lays out at; a count
    /// past the build's value is refused where the build bounds it. Turned red by a statement the
    /// door drops, or a name the door does not find among a session's limits.
    #[test]
    fn a_session_states_its_reassembly_buffers_up_to_the_builds_value() {
        use wz_session_core::caps;

        for count in [0, 1, caps::REASSEMBLY_CHAINS]
            .into_iter()
            .filter(|count| *count <= caps::REASSEMBLY_CHAINS)
        {
            let text = alloc::format!("REASSEMBLY_CHAINS={count}");
            let stated = state(Some(text.as_str())).expect("a count up to the build's is stated");
            assert_eq!(stated.limits.reassembly_chains(), Quota::at_most(count));
        }
        if let Some(bound) = SessionLimits::BUILD.reassembly_chains().most() {
            let past = alloc::format!("REASSEMBLY_CHAINS={}", bound + 1);
            assert_eq!(state(Some(past.as_str())), Err(Z_ERR_CONFIG_INVALID_VALUE));
        }
    }

    /// A name that is no limit of a session nor a held value, any other runtime limit included,
    /// a name one letter short or long of a limit's, an item with no count and a count that is
    /// no number are refused. Turned red by a door that skips what it does not know, or a name
    /// found by its prefix.
    #[test]
    fn what_is_no_session_limit_or_no_count_is_refused() {
        for text in [
            "MAX_SUBSCRIPTION=1",
            "MAX_SUBSCRIPTIONSS=1",
            "MAX_SUBSCRIPTIONS==1",
            "=1",
            "NO_SUCH_LIMIT=1",
            "HELD_SESSIONS=1",
            "HELD_CONFIGS=1",
            "MAX_SUBSCRIPTIONS",
            "MAX_SUBSCRIPTIONS=many",
            "MAX_SUBSCRIPTIONS=-1",
        ] {
            assert_eq!(state(Some(text)), Err(Z_ERR_CONFIG_INVALID_VALUE), "{text}");
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

    /// The statements' ids are the held values' in their table's order, where the build has
    /// process pools, then the session limits' in theirs, and end with the last; no held value is
    /// spelled as a session limit, which the one walk would find in its place. Turned red by a
    /// reading that skips a row, reads past the last, or reads the session limits first.
    #[test]
    fn the_statements_ids_are_read_in_order() {
        use super::statement_id;
        use wz_session_core::limits::SESSION_LIMITS;
        #[cfg(wz_process_pools)]
        let held = {
            use crate::process_pool::{held_id, HELD};
            for at in 0..HELD {
                let id = held_id(at).expect("a held value's row");
                assert_eq!(statement_id(at), Some(id));
                assert!(SESSION_LIMITS.iter().all(|entry| entry.id() != id), "{id}");
            }
            assert_eq!(held_id(HELD), None);
            HELD
        };
        #[cfg(not(wz_process_pools))]
        let held = 0;
        for (at, entry) in SESSION_LIMITS.iter().enumerate() {
            assert_eq!(statement_id(held + at), Some(entry.id()));
        }
        assert_eq!(statement_id(held + SESSION_LIMITS.len()), None);
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
            let stated = state(Some(bare.as_str()));
            stated_any |= stated.is_ok();
            assert_eq!(state(Some(spaced.as_str())), stated, "{name}");
        }
        assert!(stated_any, "an opening count of an entity is stated");
    }

    /// A trim takes the ASCII whitespace off both ends and keeps what lies between, so a name
    /// with a space inside it is still no id. Turned red by a trim of one end only, or of every
    /// space.
    #[test]
    fn a_trim_takes_only_the_whitespace_at_the_ends() {
        assert_eq!(trimmed(b" \tMAX PUBLISHERS\t "), b"MAX PUBLISHERS");
        assert_eq!(trimmed(b"2 \t"), b"2");
        assert_eq!(trimmed(b" \t "), b"");
        assert_eq!(trimmed(b""), b"");
    }

    /// A text is cut at the first separator alone, which neither side keeps, and a text without
    /// one is not cut. Turned red by a cut at the last separator, or one that keeps it.
    #[test]
    fn a_text_is_cut_at_its_first_separator() {
        assert_eq!(
            split_at_first(b"A=1=2", b'='),
            Some((&b"A"[..], &b"1=2"[..]))
        );
        assert_eq!(split_at_first(b",", b','), Some((&b""[..], &b""[..])));
        assert_eq!(split_at_first(b"A1", b'='), None);
        assert_eq!(split_at_first(b"", b','), None);
    }

    /// Each item is stated whatever empty items lie before, between or after it, the last one
    /// with no separator after it as well. Turned red by a walk that stops at an empty item, or
    /// drops the item after the last separator.
    #[test]
    fn items_among_empty_ones_state_what_they_state_alone() {
        let opening = opening();
        let fewer = |most: Option<usize>| most.and_then(|count| count.checked_sub(1));
        let (Some(publishers), Some(subscriptions)) = (
            fewer(opening.limits.max_publishers().most()),
            fewer(opening.limits.max_subscriptions().most()),
        ) else {
            return;
        };
        let alone = alloc::format!("MAX_PUBLISHERS={publishers},MAX_SUBSCRIPTIONS={subscriptions}");
        let Ok(stated) = state(Some(alone.as_str())) else {
            return;
        };
        assert_ne!(
            stated, opening,
            "CONTROL: the two items state counts of their own"
        );
        let among =
            alloc::format!(" ,MAX_PUBLISHERS={publishers},, \t,MAX_SUBSCRIPTIONS={subscriptions}");
        assert_eq!(state(Some(among.as_str())), Ok(stated));
        let refused = alloc::format!(",,MAX_PUBLISHERS={publishers},NO_SUCH_LIMIT=1");
        assert_eq!(
            state(Some(refused.as_str())),
            Err(Z_ERR_CONFIG_INVALID_VALUE)
        );
    }

    /// A text that states nothing, and no text, leave the statement as it is. Turned red by a
    /// door that refuses a config without the key, or an empty item.
    #[test]
    fn an_empty_text_states_nothing() {
        let opening = opening();
        assert_eq!(state(None), Ok(opening));
        assert_eq!(state(Some("")), Ok(opening));
        assert_eq!(state(Some(" , ,")), Ok(opening));
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
        let stated = state(Some(text.as_str())).expect("held values under their bounds");
        let mut expected = crate::process_pool::Held::BUILD;
        assert_eq!(expected.select(b"HELD_LARGE_PAYLOAD_BLOCKS", 0), Some(true));
        assert_eq!(stated.held, expected);
        assert_eq!(stated.limits, opening.limits);

        let past = alloc::format!("HELD_SAMPLES=1,HELD_REPLIES={}", caps::HELD_REPLIES + 1);
        assert_eq!(state(Some(past.as_str())), Err(Z_ERR_CONFIG_INVALID_VALUE));
    }
}
