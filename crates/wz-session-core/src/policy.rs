// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The policies of a build: behaviour wz has that upstream does not, each switchable.
//!
//! # What a policy is
//!
//! A capability is a surface upstream also has; turning it on adds code. A policy is a
//! decision upstream does not make: what to do where upstream leaves the matter to the
//! operating system, or to nobody. Its default is always upstream's behaviour, so a build that
//! states nothing behaves as the original does (`docs/build-configuration.md`, C2).
//!
//! # Where the values come from
//!
//! Every policy is declared in `deploy/wz-config.toml` (`[[policy]]`: its kind, its values, the
//! upstream behaviour it departs from, its help). The generated [`crate::policy::SessionPolicy`] holds one typed
//! field for each, and its `Default` reads `WZ_POLICY_<NAME>` from the build's environment, or
//! takes upstream's behaviour when the build states none. For a Zephyr image the environment is
//! made from Kconfig; for a host build it is the resolved preset (`wz_config.py --resolve-env`).
//!
//! A policy is a value and not a cargo feature (C3): features unify across a dependency graph and
//! can only add code, and a policy changes behaviour. So one binary can hold both values, and a
//! test names the one it is about by setting the field:
//!
//! ```ignore
//! let mut policy = SessionPolicy::default();
//! policy.multicast_loopback = MulticastLoopback::Off;
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
}

/// The value of a bool policy: `on` or `off` as the build states it, or `off`, which is
/// upstream's behaviour for every bool policy, when it states none.
#[doc(hidden)]
pub const fn policy_bool(stated: Option<&str>) -> bool {
    let Some(text) = stated else {
        return false;
    };
    if same(text, "on") {
        true
    } else if same(text, "off") {
        false
    } else {
        panic!("a WZ_POLICY_* value of a bool policy is neither `on` nor `off`")
    }
}

/// The index in `choices` of the value the build states, or `default`, the index of upstream's
/// behaviour, when it states none. A value that is not one of the choices stops the build.
#[doc(hidden)]
pub const fn policy_choice(stated: Option<&str>, choices: &[&str], default: usize) -> usize {
    let Some(text) = stated else {
        return default;
    };
    let mut index = 0;
    while index < choices.len() {
        if same(text, choices[index]) {
            return index;
        }
        index += 1;
    }
    panic!("a WZ_POLICY_* value is not one of its policy's choices")
}

/// `a == b` where the language allows it in a constant.
const fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut index = 0;
    while index < a.len() {
        if a[index] != b[index] {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHOICES: [&str; 3] = ["os-default", "on", "off"];

    #[test]
    fn a_build_that_states_nothing_is_upstreams_behaviour() {
        assert!(!policy_bool(None));
        assert_eq!(policy_choice(None, &CHOICES, 0), 0);
        assert_eq!(policy_choice(None, &CHOICES, 2), 2);
    }

    #[test]
    fn a_stated_value_is_read_as_the_value_it_names() {
        assert!(policy_bool(Some("on")));
        assert!(!policy_bool(Some("off")));
        assert_eq!(policy_choice(Some("os-default"), &CHOICES, 1), 0);
        assert_eq!(policy_choice(Some("on"), &CHOICES, 0), 1);
        assert_eq!(policy_choice(Some("off"), &CHOICES, 0), 2);
    }

    #[test]
    fn a_value_is_matched_whole_not_by_prefix() {
        assert!(!same("on", "one"));
        assert!(!same("one", "on"));
        assert!(same("", ""));
    }

    #[test]
    #[should_panic(expected = "neither `on` nor `off`")]
    fn a_bool_value_that_is_neither_stops_the_build() {
        policy_bool(Some("yes"));
    }

    #[test]
    #[should_panic(expected = "not one of its policy's choices")]
    fn a_choice_value_that_is_not_a_choice_stops_the_build() {
        policy_choice(Some("sometimes"), &CHOICES, 0);
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

    #[test]
    fn the_generated_policy_of_a_build_that_states_nothing_is_the_default() {
        assert_eq!(SessionPolicy::default(), SessionPolicy::from_build());
    }
}
