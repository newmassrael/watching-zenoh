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
/// A value could not be deserialized (`Z_EDESERIALIZE`) — the payload ended
/// mid-value, or its bytes do not decode as the requested type.
pub const Z_EDESERIALIZE: ZResult = -7;
/// The session was closed (`Z_ESESSION_CLOSED`).
pub const Z_ESESSION_CLOSED: ZResult = -8;
/// A channel is disconnected and will never yield again
/// (`Z_CHANNEL_DISCONNECTED` = 1). zenoh-c spells the two channel statuses as
/// POSITIVE values, not errors, so a C caller's `if (rc < 0)` does not treat a
/// drained channel as a failure — and `z_queryable_with_channels.c`'s
/// `for (rc = z_recv(..); rc == Z_OK; ..)` loop exits on either.
///
/// The value is 1 and NODATA is 2, which is the opposite of the order the names
/// suggest; transcribed from `zenoh_concrete.h:25-26` rather than guessed.
pub const Z_CHANNEL_DISCONNECTED: ZResult = 1;
/// A channel is alive but empty and the caller asked not to block
/// (`Z_CHANNEL_NODATA` = 2).
pub const Z_CHANNEL_NODATA: ZResult = 2;
/// A mutex handle was not usable (`Z_EINVAL_MUTEX` = -22). zenoh-c forwards
/// `pthread`'s own `errno` values for the mutex family rather than mapping them
/// onto its `Z_E*` set, which is why this number is -22 and not a small one.
pub const Z_EINVAL_MUTEX: ZResult = -22;
/// A `z_mutex_try_lock` found the mutex already HELD (`Z_EBUSY_MUTEX` = -16).
///
/// MEASURED against the real `libzenohc.so`, not derived: a probe took the lock
/// and tried again, and upstream answered `-16` — `pthread_mutex_trylock`'s
/// `EBUSY`, negated the way zenoh-c negates every forwarded errno. It is a
/// DIFFERENT verdict from [`Z_EINVAL_MUTEX`], and a caller that could not tell
/// them apart would spin forever on an unusable handle.
pub const Z_EBUSY_MUTEX: ZResult = -16;
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
            Z_EDESERIALIZE,
            Z_ESESSION_CLOSED,
            Z_EINVAL_MUTEX,
            Z_EBUSY_MUTEX,
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

    /// The two CHANNEL statuses are positive and distinct from `Z_OK` — the
    /// property `z_queryable_with_channels.c`'s `rc == Z_OK` loop rests on, and
    /// the reason they are not in the sweep above. Their numbering is the
    /// opposite of what the names suggest, which is exactly the kind of thing a
    /// reader assumes rather than checks.
    #[test]
    fn the_channel_statuses_are_positive_and_not_ok() {
        assert_eq!(Z_CHANNEL_DISCONNECTED, 1);
        assert_eq!(Z_CHANNEL_NODATA, 2);
        for code in [Z_CHANNEL_DISCONNECTED, Z_CHANNEL_NODATA] {
            assert!(code > 0, "a channel status must not read as an error");
            assert_ne!(code, Z_OK, "a channel status must not read as success");
        }
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
