// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_result_t` — zenoh-c's return-code type and the codes this slice returns.
//!
//! `typedef int8_t z_result_t;` (`zenoh_commons.h:374`), so every exported
//! function returning a status returns an `i8` and a C caller's
//! `if (z_open(..) < 0)` works unchanged.
//!
//! ## The values differ from zenoh-pico's, which is why they live here
//!
//! Both C ABIs wz exports typedef the result to `int8_t` and then disagree about
//! what the numbers MEAN: pico's generic failure is `-128` and its null-argument
//! error is `-127`, while zenoh-c's are the `Z_E*` set below. That is exactly why
//! `wz-capi-core` reports neutral error enums instead of a code — shared code
//! returning one ABI's constant would be silently wrong in the other.
//!
//! Values transcribed from `zenoh_concrete.h`, which defines them as plain
//! `#define`s.

/// zenoh-c's status type: `int8_t`.
pub type ZResult = i8;

/// Success (`Z_OK`).
pub const Z_OK: ZResult = 0;
/// An argument was invalid (`Z_EINVAL`).
pub const Z_EINVAL: ZResult = -1;
/// A string could not be parsed (`Z_EPARSE`) — a malformed json5 config value, a
/// non-canonical keyexpr.
pub const Z_EPARSE: ZResult = -2;
/// An I/O operation failed (`Z_EIO`) — a config file that cannot be read.
pub const Z_EIO: ZResult = -3;
/// A network operation failed (`Z_ENETWORK`) — the session could not be opened.
pub const Z_ENETWORK: ZResult = -4;
/// A required argument was null (`Z_ENULL`).
pub const Z_ENULL: ZResult = -5;
/// A resource could not be obtained (`Z_EUNAVAILABLE`) — the id space behind a
/// declaration is exhausted.
pub const Z_EUNAVAILABLE: ZResult = -6;
/// An unclassified failure (`Z_EGENERIC` = `INT8_MIN`). zenoh-c spells its
/// catch-all as the type's minimum rather than as another small negative, so the
/// value is transcribed rather than chosen.
pub const Z_EGENERIC: ZResult = i8::MIN;

#[cfg(test)]
mod tests {
    use super::*;

    /// The codes must not collide with each other, and `Z_OK` must be the only
    /// non-negative one — a C caller's `< 0` test is the whole contract.
    #[test]
    fn the_codes_are_distinct_and_only_ok_is_non_negative() {
        let errs = [
            Z_EINVAL,
            Z_EPARSE,
            Z_EIO,
            Z_ENETWORK,
            Z_ENULL,
            Z_EUNAVAILABLE,
            Z_EGENERIC,
        ];
        for (i, a) in errs.iter().enumerate() {
            assert!(*a < 0, "{a} must be negative to satisfy `if (rc < 0)`");
            for b in &errs[i + 1..] {
                assert_ne!(a, b, "two distinct conditions share a code");
            }
        }
        assert_eq!(Z_OK, 0);
    }

    /// These are NOT zenoh-pico's values, and the difference is the reason the
    /// shared core returns neutral errors. pico's generic failure is -128 and its
    /// null is -127; if this file ever drifted onto those, a zenoh-c program's
    /// error handling would be reading another ABI's vocabulary.
    #[test]
    fn the_codes_are_not_zenoh_picos() {
        // `Z_EGENERIC` is deliberately absent from this sweep: zenoh-c's own
        // catch-all IS `INT8_MIN`, the same number pico spells `_Z_ERR_GENERIC`,
        // so the two ABIs COINCIDE there. Asserting otherwise would be asserting
        // a difference upstream does not have. The `-127` half still holds — a
        // null argument is `Z_ENULL` here and `_Z_ERR_NULL` there, and those
        // genuinely differ.
        for code in [
            Z_EINVAL,
            Z_EPARSE,
            Z_EIO,
            Z_ENETWORK,
            Z_ENULL,
            Z_EUNAVAILABLE,
        ] {
            assert_ne!(code, -128, "that is zenoh-pico's _Z_ERR_GENERIC");
            assert_ne!(code, -127, "that is zenoh-pico's _Z_ERR_NULL");
        }
        assert_eq!(Z_EGENERIC, i8::MIN, "zenoh-c's Z_EGENERIC is INT8_MIN");
    }
}
