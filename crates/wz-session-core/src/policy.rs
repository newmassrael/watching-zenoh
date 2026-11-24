// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The policies of a build: behaviour wz has that upstream does not, each switchable.
//!
//! # What a policy is
//!
//! A capability is a surface upstream also has; turning it on adds code. A policy is a
//! decision upstream does not make: what to do where upstream leaves the matter to the
//! operating system, or to nobody. Its default is always upstream's behaviour, so a build that
//! states nothing behaves as the original does, and the generator refuses an upstream defconfig
//! in which any policy is on.
//!
//! # Where the values come from
//!
//! Every policy is declared in `deploy/wz-config.toml` (`[[policy]]`: its kind, its values, the
//! upstream behaviour it departs from, its help). The generated [`crate::policy::SessionPolicy`]
//! holds one field for each, bound inside the build's domain of the policy, and its build
//! defaults ([`crate::policy::SessionPolicy::defaults`]) read `WZ_POLICY_<NAME>` from the build's environment, or
//! take upstream's behaviour when the build states none. For a Zephyr image the environment is
//! made from Kconfig; for a host build it is the resolved preset (`wz_config.py --resolve-env`).
//!
//! # Who reads a value
//!
//! A `SessionPolicy` is a snapshot. A creator (a runtime, a session, a link, an entity) resolves
//! the snapshot of its scope once, starting from the build defaults, and hands it to the machines
//! it creates; a machine reads its policies through the snapshot's accessors and never from the
//! build. `scripts/lib/policy_read_gate.py` refuses a read of the build defaults anywhere but at a
//! creator it lists.
//!
//! A policy is a value and not a cargo feature (C3): features unify across a dependency graph and
//! can only add code, and a policy changes behaviour. So one binary can hold every value its
//! domain allows, and a test names the one it is about by selecting it:
//!
//! ```ignore
//! let mut policy = SessionPolicy::defaults();
//! policy.select_multicast_loopback(MulticastLoopback::Off)?;
//! ```
//!
//! `scripts/lib/wz_config.py --check` fails when a crate reads a `WZ_POLICY_*` itself, so the
//! value a policy has is decided in one place.

#[path = "policy_generated.rs"]
mod generated;

pub use generated::*;

impl SnResolution {
    /// The two-bit code the width has in an InitSyn and a Join (`seq_num_res`): zenoh's
    /// `Resolution` for a frame's sequence number, and zenoh-pico's `Z_SN_RESOLUTION`, which it
    /// puts in its InitSyn and its Join (`vendor/zenoh-pico/src/protocol/definitions/transport.c` @
    /// `msg._body._init._seq_num_res = Z_SN_RESOLUTION;`) and has fixed at `0x02`.
    pub const fn wire_code(self) -> u8 {
        match self {
            Self::Bits8 => 0x00,
            Self::Bits16 => 0x01,
            Self::Bits32 => 0x02,
            Self::Bits64 => 0x03,
        }
    }

    /// Every width, in the order a test walks them.
    pub const WIDTHS: [Self; 4] = [Self::Bits32, Self::Bits8, Self::Bits16, Self::Bits64];

    /// The width as zenoh's configuration spells it, the value of
    /// `transport/link/tx/sequence_number_resolution`
    /// (`commons/zenoh-protocol/src/core/resolution.rs` @ `const S8: &'static str = "8bit";`
    /// and its three siblings).
    pub const fn zenoh_name(self) -> &'static str {
        match self {
            Self::Bits8 => "8bit",
            Self::Bits16 => "16bit",
            Self::Bits32 => "32bit",
            Self::Bits64 => "64bit",
        }
    }

    /// The width zenoh's configuration names `text`, or `None` for a text it refuses: the four
    /// spellings of [`Self::zenoh_name`] and nothing else, as upstream's deserializer takes them.
    pub fn from_zenoh_name(text: &str) -> Option<Self> {
        Self::WIDTHS
            .into_iter()
            .find(|width| width.zenoh_name() == text)
    }
}

/// The value of a bool policy: `on` or `off` as the build states it, or `off`, which is
/// upstream's behaviour for every bool policy, when it states none. `None` is a word that is
/// neither, which the generated module refuses to build with.
#[doc(hidden)]
pub const fn policy_bool(stated: Option<&str>) -> Option<bool> {
    match stated {
        None => Some(false),
        Some(text) => on_or_off(text),
    }
}

/// Whether the build allows one value of a policy (`WZ_POLICY_<NAME>_ALLOWS_<VALUE>`): `on`
/// allows it, `off` leaves it out of the policy's domain, and a build that states nothing gets
/// `unstated`, which [`crate::policy_binding::Domain::from_stated`] decides by
/// [`policy_defaults_only`]. `None` is a word that is neither `on` nor `off`.
#[doc(hidden)]
pub const fn policy_allows(stated: Option<&str>, unstated: bool) -> Option<bool> {
    match stated {
        None => Some(unstated),
        Some(text) => on_or_off(text),
    }
}

/// Whether an allowance the build does not state keeps only the build default of its policy, from
/// what the build states as `WZ_POLICY_DOMAINS`: `full` allows every such value, `defaults` keeps
/// the default alone, and a build that states nothing gets `unstated_keeps_default` of its
/// target and of whether anything in it selects a policy (the `policy-selection` feature).
/// `None` is any other word, which the generated module refuses to build with.
#[doc(hidden)]
pub const fn policy_defaults_only(stated: Option<&str>) -> Option<bool> {
    let Some(text) = stated else {
        return Some(unstated_keeps_default(
            cfg!(target_os = "none"),
            cfg!(feature = "policy-selection"),
        ));
    };
    if same(text, "full") {
        Some(false)
    } else if same(text, "defaults") {
        Some(true)
    } else {
        None
    }
}

/// The rule of an allowance the build does not state: the default alone on a target with no
/// operating system (`no_os`), so an image pays for a second value only where it allows one on
/// purpose, and in a build where nothing selects a policy after it (`!selects`), where a second
/// value could never be reached; every value otherwise. The feature that says `selects` only
/// widens: unified across a graph, one crate's door widens the others' builds and never narrows
/// its own.
const fn unstated_keeps_default(no_os: bool, selects: bool) -> bool {
    no_os || !selects
}

/// The value the build states, found by its word in `choices` and taken from `values` at the
/// same place, or `default`, upstream's behaviour, when it states none. `None` is a word that is
/// none of the choices, which the generated module refuses to build with. The two arrays share
/// their length by type, so every word names a value.
#[doc(hidden)]
pub const fn policy_choice<T: Copy, const N: usize>(
    stated: Option<&str>,
    choices: &[&str; N],
    values: &[T; N],
    default: T,
) -> Option<T> {
    let Some(text) = stated else {
        return Some(default);
    };
    let (mut choices, mut values): (&[&str], &[T]) = (choices, values);
    while let ([choice, choices_tail @ ..], [value, values_tail @ ..]) = (choices, values) {
        if same(text, choice) {
            return Some(*value);
        }
        choices = choices_tail;
        values = values_tail;
    }
    None
}

/// `on` as `true`, `off` as `false`, and any other word as `None`.
const fn on_or_off(text: &str) -> Option<bool> {
    if same(text, "on") {
        Some(true)
    } else if same(text, "off") {
        Some(false)
    } else {
        None
    }
}

/// `a == b` where the language allows it in a constant.
const fn same(a: &str, b: &str) -> bool {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    while let ([x, a_rest @ ..], [y, b_rest @ ..]) = (a, b) {
        if *x != *y {
            return false;
        }
        a = a_rest;
        b = b_rest;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_binding::{Binding, Mutability, PolicyValue, Scope, Wire};

    const CHOICES: [&str; 3] = ["os-default", "on", "off"];
    const VALUES: [u8; 3] = [10, 11, 12];

    #[test]
    fn a_build_that_states_nothing_is_upstreams_behaviour() {
        assert_eq!(policy_bool(None), Some(false));
        assert_eq!(policy_choice(None, &CHOICES, &VALUES, 10), Some(10));
        assert_eq!(policy_choice(None, &CHOICES, &VALUES, 12), Some(12));
    }

    #[test]
    fn a_stated_value_is_read_as_the_value_it_names() {
        assert_eq!(policy_bool(Some("on")), Some(true));
        assert_eq!(policy_bool(Some("off")), Some(false));
        assert_eq!(
            policy_choice(Some("os-default"), &CHOICES, &VALUES, 11),
            Some(10)
        );
        assert_eq!(policy_choice(Some("on"), &CHOICES, &VALUES, 10), Some(11));
        assert_eq!(policy_choice(Some("off"), &CHOICES, &VALUES, 10), Some(12));
    }

    #[test]
    fn a_value_is_matched_whole_not_by_prefix() {
        assert!(!same("on", "one"));
        assert!(!same("one", "on"));
        assert!(same("", ""));
        assert_eq!(policy_choice(Some("of"), &CHOICES, &VALUES, 10), None);
        assert_eq!(policy_choice(Some("offf"), &CHOICES, &VALUES, 10), None);
        assert_eq!(policy_bool(Some("o")), None);
    }

    /// A word the policy does not take is no value at all, not upstream's: the generated module
    /// turns the `None` into a build that does not compile.
    #[test]
    fn a_bool_value_that_is_neither_is_no_value() {
        assert_eq!(policy_bool(Some("yes")), None);
        assert_eq!(policy_bool(Some("")), None);
    }

    #[test]
    fn a_choice_value_that_is_not_a_choice_is_no_value() {
        assert_eq!(
            policy_choice(Some("sometimes"), &CHOICES, &VALUES, 10),
            None
        );
        assert_eq!(policy_choice(Some(""), &CHOICES, &VALUES, 10), None);
        assert_eq!(policy_choice::<u8, 0>(Some("on"), &[], &[], 10), None);
    }

    /// A policy with no choices names no value by any word, and takes its default when the build
    /// states none.
    #[test]
    fn a_policy_with_no_choices_takes_its_default_when_nothing_is_stated() {
        assert_eq!(policy_choice::<u8, 0>(None, &[], &[], 7), Some(7));
    }

    /// Every width is its own two-bit code, in the order of the width, and the widths walked by
    /// the tests are all the declaration states.
    #[test]
    fn each_sn_width_is_its_own_two_bit_code() {
        // Each code 0..=3 is taken by exactly one width.
        for code in 0..=3u8 {
            let owners = SnResolution::WIDTHS
                .iter()
                .filter(|width| width.wire_code() == code)
                .count();
            assert_eq!(owners, 1, "code {code}");
        }
        assert_eq!(SnResolution::Bits8.wire_code(), 0);
        assert_eq!(SnResolution::Bits64.wire_code(), 3);
        assert_eq!(SnResolution::Bits16.id(), "bits-16");
    }

    /// Each width reads back from zenoh's spelling of it, and the texts zenoh refuses (the
    /// declaration's own spelling, a bare number, a different case) name no width.
    #[test]
    fn each_sn_width_reads_back_from_zenohs_spelling_and_nothing_else_does() {
        for width in SnResolution::WIDTHS {
            assert_eq!(
                SnResolution::from_zenoh_name(width.zenoh_name()),
                Some(width)
            );
        }
        assert_eq!(SnResolution::Bits16.zenoh_name(), "16bit");
        assert_eq!(SnResolution::Bits32.zenoh_name(), "32bit");
        for refused in ["bits-16", "16", "16BIT", "", "128bit"] {
            assert_eq!(SnResolution::from_zenoh_name(refused), None, "{refused:?}");
        }
    }

    #[test]
    fn the_generated_policy_of_a_build_that_states_nothing_is_the_default() {
        assert_eq!(SessionPolicy::default(), SessionPolicy::from_build());
        assert_eq!(SessionPolicy::defaults(), SessionPolicy::from_build());
    }

    /// Each accessor of the build defaults reads the build's value of its policy: the value type's
    /// `DEFAULT`, a bool policy as the `bool` it converts to.
    #[test]
    fn each_accessor_of_the_build_defaults_reads_the_builds_value() {
        let defaults = SessionPolicy::defaults();
        assert_eq!(defaults.multicast_loopback(), MulticastLoopback::DEFAULT);
        assert_eq!(defaults.sn_resolution(), SnResolution::DEFAULT);
        assert_eq!(defaults.link_tie_order(), LinkTieOrder::DEFAULT);
        assert_eq!(defaults.key_set(), KeySet::DEFAULT);
        assert_eq!(
            defaults.targeted_query(),
            TargetedQuery::DEFAULT.is_on(),
            "a bool policy reads as its value's `bool`"
        );
        assert_eq!(
            defaults.tx_expiry_keeps_session(),
            bool::from(TxExpiryKeepsSession::DEFAULT)
        );
    }

    /// A snapshot holds a byte for each policy whose domain is wider than one value and none for
    /// the rest, so a build that fixes every policy (a target with no operating system that
    /// widens none) carries a snapshot of no byte.
    #[test]
    fn a_snapshot_holds_a_byte_only_for_a_policy_with_more_than_one_value() {
        // Counted over every policy the declaration states, so a policy added is counted with
        // the others and no list here is kept by hand.
        let held: usize = POLICIES
            .iter()
            .map(|policy| usize::from(policy.domain().iter().count() > 1))
            .sum();
        assert_eq!(core::mem::size_of::<SessionPolicy>(), held);
        assert_eq!(KeySet::HELD, KeySet::DOMAIN.held());
    }

    /// The accessors are `const`, so a constant can still be computed from a snapshot.
    #[test]
    fn an_accessor_is_read_in_a_constant() {
        const ORDER: LinkTieOrder = SessionPolicy::defaults().link_tie_order();
        const TARGETED: bool = SessionPolicy::defaults().targeted_query();
        assert_eq!(ORDER, LinkTieOrder::DEFAULT);
        assert_eq!(TARGETED, TargetedQuery::DEFAULT.is_on());
    }

    /// A value the build's domain holds is selected and read back; one it leaves out is refused
    /// with the value, and the snapshot keeps what it held. Every value is tried, so whichever
    /// `WZ_POLICY_*_ALLOWS_*` the test build states, each answer is the domain's.
    #[test]
    fn select_takes_a_value_inside_the_domain_and_refuses_one_outside() {
        for &order in <LinkTieOrder as PolicyValue>::ALL {
            let mut policy = SessionPolicy::defaults();
            let selected = policy.select_link_tie_order(order);
            if LinkTieOrder::DOMAIN.contains(order) {
                assert_eq!(selected, Ok(()), "{}", order.id());
                if !LinkTieOrder::DOMAIN.is_singleton() {
                    assert_eq!(policy.link_tie_order(), order, "{}", order.id());
                }
            } else {
                assert_eq!(
                    selected,
                    Err(crate::policy_binding::OutsideDomain { value: order })
                );
                assert_eq!(
                    policy,
                    SessionPolicy::defaults(),
                    "a refusal changes nothing"
                );
            }
        }
        for &value in <TargetedQuery as PolicyValue>::ALL {
            let mut policy = SessionPolicy::defaults();
            let selected = policy.select_targeted_query(value);
            assert_eq!(selected.is_ok(), TargetedQuery::DOMAIN.contains(value));
            if selected.is_ok() && !TargetedQuery::DOMAIN.is_singleton() {
                assert_eq!(policy.targeted_query(), value.is_on());
            }
        }
    }

    /// Two snapshots differ only in what was selected into them: selecting one policy leaves
    /// every other at its build default.
    #[test]
    fn selecting_one_policy_leaves_the_others_at_their_build_default() {
        let mut policy = SessionPolicy::defaults();
        let other = if LinkTieOrder::DEFAULT == LinkTieOrder::ZidNumber {
            LinkTieOrder::ZidBytes
        } else {
            LinkTieOrder::ZidNumber
        };
        if policy.select_link_tie_order(other).is_err() || LinkTieOrder::DOMAIN.is_singleton() {
            // The build allows one order: there is no other to select.
            return;
        }
        assert_eq!(policy.link_tie_order(), other);
        assert_ne!(policy, SessionPolicy::defaults());
        assert_eq!(policy.sn_resolution(), SnResolution::DEFAULT);
        assert_eq!(policy.multicast_loopback(), MulticastLoopback::DEFAULT);
    }

    /// An allowance the build does not name takes what the domain rule gives it; one the build
    /// states wins over that rule either way, so an image may widen a domain on purpose.
    #[test]
    fn a_value_the_build_does_not_name_takes_the_domain_rule() {
        assert_eq!(policy_allows(None, true), Some(true));
        assert_eq!(policy_allows(None, false), Some(false));
        assert_eq!(policy_allows(Some("on"), false), Some(true));
        assert_eq!(policy_allows(Some("on"), true), Some(true));
        assert_eq!(policy_allows(Some("off"), true), Some(false));
        assert_eq!(policy_allows(Some("off"), false), Some(false));
    }

    #[test]
    fn an_allowance_that_is_neither_on_nor_off_is_no_value() {
        assert_eq!(policy_allows(Some("y"), true), None);
        assert_eq!(policy_allows(Some("y"), false), None);
    }

    /// `WZ_POLICY_DOMAINS` forces either rule, and a build that states nothing gets the rule of
    /// its target and of its `policy-selection`, which this crate's tests always name.
    #[test]
    fn the_domain_rule_is_stated_or_the_targets() {
        assert_eq!(policy_defaults_only(Some("full")), Some(false));
        assert_eq!(policy_defaults_only(Some("defaults")), Some(true));
        assert_eq!(policy_defaults_only(None), Some(cfg!(target_os = "none")));
    }

    /// An unstated allowance keeps the default alone on a target with no operating system and in
    /// a build where nothing selects a policy, and allows its value only where both are false.
    #[test]
    fn an_unstated_allowance_keeps_the_default_where_no_stage_selects_a_policy() {
        assert!(!unstated_keeps_default(false, true));
        assert!(unstated_keeps_default(true, true));
        assert!(unstated_keeps_default(false, false));
        assert!(unstated_keeps_default(true, false));
    }

    #[test]
    fn a_domain_rule_that_is_neither_is_no_value() {
        assert_eq!(policy_defaults_only(Some("all")), None);
        assert_eq!(policy_defaults_only(Some("default")), None);
    }

    /// The value types agree with the fields of `SessionPolicy` in whatever build the test runs:
    /// the default of each is the build's value, and the build's domain holds it.
    #[test]
    fn each_policy_value_type_defaults_to_the_builds_value_inside_its_domain() {
        let build = SessionPolicy::from_build();
        assert_eq!(
            bool::from(TxNoProgressDeadline::DEFAULT),
            build.tx_no_progress_deadline()
        );
        assert_eq!(MulticastLoopback::DEFAULT, build.multicast_loopback());
        assert_eq!(SnResolution::DEFAULT, build.sn_resolution());
        assert!(TxNoProgressDeadline::DOMAIN.contains(TxNoProgressDeadline::DEFAULT));
        assert!(MulticastLoopback::DOMAIN.contains(MulticastLoopback::DEFAULT));
        assert_eq!(
            TxNoProgressDeadline::default(),
            TxNoProgressDeadline::DEFAULT
        );
        assert_eq!(MulticastLoopback::default(), MulticastLoopback::DEFAULT);
    }

    #[test]
    fn a_bool_policy_value_converts_to_and_from_its_field() {
        assert_eq!(TxNoProgressDeadline::from(true), TxNoProgressDeadline::On);
        assert_eq!(TxNoProgressDeadline::from(false), TxNoProgressDeadline::Off);
        assert!(bool::from(TxNoProgressDeadline::On));
        assert!(!bool::from(TxNoProgressDeadline::Off));
        assert_eq!(TxNoProgressDeadline::On.id(), "on");
        assert_eq!(
            <TxNoProgressDeadline as PolicyValue>::IDS,
            &["off", "on"][..]
        );
    }

    /// Where each policy is bound is the declaration's, carried into its value type.
    #[test]
    fn a_policy_value_type_carries_where_its_policy_is_bound() {
        assert_eq!(MulticastLoopback::POLICY, "multicast-loopback");
        assert_eq!(MulticastLoopback::SCOPE, Scope::Link);
        assert_eq!(MulticastLoopback::BINDING, Binding::Open);
        assert_eq!(MulticastLoopback::MUTABILITY, Mutability::Fixed);
        assert_eq!(MulticastLoopback::WIRE, Wire::None);
        assert_eq!(MulticastLoopback::BOUNDARY, None);
        assert_eq!(DeclarationSyncPacing::MUTABILITY, Mutability::Quiescent);
        assert_eq!(
            DeclarationSyncPacing::BOUNDARY,
            Some("the start of the next replay of declarations")
        );
        assert_eq!(
            <MulticastLoopback as PolicyValue>::ALL,
            &[
                MulticastLoopback::OsDefault,
                MulticastLoopback::On,
                MulticastLoopback::Off
            ][..]
        );
    }
}
