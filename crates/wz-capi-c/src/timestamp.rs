// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `z_timestamp_t` — zenoh-c's HLC timestamp, and the family that makes the
//! `timestamp` field on the put / delete / publisher option structs READABLE.
//!
//! ## Why the field was unread until R311y557
//!
//! Every one of those structs has carried `timestamp` since the option surface
//! was first laid out, as `*const c_void`, for LAYOUT only. The blocker was not
//! the plumbing below it — wz has had a body-level timestamp on the publish path
//! since R232 ([`PublishOptions::with_timestamp`], the `MsgPut`/`MsgDel` T-flag)
//! — it was that the TYPE the pointer points at did not exist in this crate, so
//! there was nothing to dereference and no way for a C program to construct one.
//! This module is that type plus its three accessors, which is what turns the
//! field from a hole in the struct into a value the wire carries.
//!
//! ## The layout, and why it is stated as a struct rather than a byte array
//!
//! Upstream declares `z_timestamp_t` OPAQUE — `ALIGN(8) { uint8_t _0[24]; }`
//! (`zenoh_opaque.h:257-259`) — because its Rust side holds a `uhlc::Timestamp`
//! and the generator only knows the size. wz declares the same 24 bytes at the
//! same alignment with its own fields named, which is the convention this crate
//! already follows for [`z_id_t`](crate::zid::z_id_t): the C contract is the
//! SIZE and the ALIGNMENT, both of which are asserted below and gated by the
//! four-arm footprint comparison against upstream's own generator. A C program
//! cannot see the difference — it only ever holds the struct through the
//! accessors.
//!
//! `u64` then `[u8; 16]` is exactly 24 at align 8 with no padding, so the
//! declaration is not merely the right size, it has no dead bytes in it.

use std::ffi::c_void;

use crate::abi::z_loaned_session_t;
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_ENULL, Z_OK};
use crate::session::session_state;
use crate::zid::{z_id_t, Z_ID_SIZE};

/// zenoh-c `z_timestamp_t` (`zenoh_opaque.h:257-259`) — 24 bytes at ALIGNMENT 8.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct z_timestamp_t {
    /// The NTP64 time word, as `z_timestamp_ntp64_time` returns it and as the
    /// wire `_z_timestamp_t._time` carries it.
    pub _time: u64,
    /// The originating zid, LEFT-aligned and zero-padded to the wire width —
    /// the same convention [`z_id_t`] uses, and the reason a shorter wire zid
    /// round-trips without the accessor having to know its length.
    pub _id: [u8; Z_ID_SIZE],
}

const _: () = {
    assert!(std::mem::size_of::<z_timestamp_t>() == 24);
    assert!(std::mem::align_of::<z_timestamp_t>() == 8);
};

impl z_timestamp_t {
    /// The all-zero timestamp — what a failed [`z_timestamp_new`] leaves behind
    /// and what an unstamped sample would report if one were ever asked for.
    pub(crate) fn empty() -> Self {
        Self {
            _time: 0,
            _id: [0u8; Z_ID_SIZE],
        }
    }

    /// Project a wz [`TimestampHint`](wz_runtime_tokio::sample::TimestampHint)
    /// into the C struct. The hint's zid is the ON-WIRE byte count (zenoh
    /// transmits a zid prefix, not always 16), so a short one is copied into
    /// the low bytes and the rest stays zero.
    pub(crate) fn from_hint(hint: &wz_runtime_tokio::sample::TimestampHint) -> Self {
        let mut out = Self::empty();
        out._time = hint.time;
        let n = hint.zid.len().min(Z_ID_SIZE);
        out._id[..n].copy_from_slice(&hint.zid[..n]);
        out
    }

    /// The inverse — what [`crate::put`] hands to `PublishOptions`.
    ///
    /// The TRAILING zero bytes are trimmed, because the hint's `zid` is the
    /// wire-length prefix and a 16-byte right-padded value would put four extra
    /// zero bytes on the wire for a 12-byte zid. Trimming is the same rule
    /// [`z_id_t::from_wire`](crate::zid::z_id_t) reads in the other direction.
    pub(crate) fn to_hint(self) -> wz_runtime_tokio::sample::TimestampHint {
        let end = self
            ._id
            .iter()
            .rposition(|b| *b != 0)
            .map_or(0, |last| last + 1);
        wz_runtime_tokio::sample::TimestampHint {
            time: self._time,
            zid: self._id[..end].to_vec(),
        }
    }
}

/// Read a caller-supplied `const z_timestamp_t*` option field.
///
/// NULL is upstream's "no timestamp", not an error — every option struct
/// defaults the field to null and the overwhelming majority of programs leave
/// it there.
///
/// # Safety
/// `ptr` must be null or point at a valid `z_timestamp_t`.
pub(crate) unsafe fn timestamp_hint(
    ptr: *const c_void,
) -> Option<wz_runtime_tokio::sample::TimestampHint> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let ts = unsafe { &*(ptr as *const z_timestamp_t) };
    Some(ts.to_hint())
}

/// Mint a timestamp from a session (zenoh-c `z_timestamp_new`).
///
/// Upstream's takes the session because the HLC belongs to the node, and it
/// FAILS when that node has no clock configured. wz's session mints from the
/// same two inputs — this session's own zid and its monotonic-anchored NTP64
/// word — so the value a C program stamps is attributable to the session that
/// stamped it, which is the whole point of the zid half.
///
/// # Safety
/// `this_` must be null or valid and writable; `session` must be null or a live
/// loaned session.
#[no_mangle]
pub unsafe extern "C" fn z_timestamp_new(
    this_: *mut z_timestamp_t,
    session: *const z_loaned_session_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract. Written on EVERY path, including the
        // failure one: upstream's out-parameter contract leaves no readable
        // garbage behind, and a caller that ignores the code must not then
        // stamp a message with whatever was on its stack.
        unsafe { *this_ = z_timestamp_t::empty() };
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { session_state(session) }) else {
            return Z_ENULL;
        };
        let now = state.shared.now_monotonic_ms();
        let mut stamped = z_timestamp_t::empty();
        stamped._time = ntp64_from_millis(now);
        stamped._id = state.zid();
        // SAFETY: checked non-null above.
        unsafe { *this_ = stamped };
        Z_OK
    })
}

/// The NTP64 encoding of a millisecond count: seconds in the high 32 bits,
/// binary fraction of a second in the low 32.
///
/// This is the shape `uhlc` puts on the wire and the one wz's own codec reads
/// back, so a timestamp minted here and a timestamp decoded from a peer are
/// comparable numbers rather than two different units that happen to share a
/// field.
fn ntp64_from_millis(millis: u64) -> u64 {
    let secs = millis / 1_000;
    let rem = millis % 1_000;
    // (rem / 1000) * 2^32, computed without a float so the value is exact and
    // reproducible on every target.
    let frac = (rem << 32) / 1_000;
    (secs << 32) | frac
}

/// The NTP64 time word (zenoh-c `z_timestamp_ntp64_time`).
///
/// # Safety
/// `this_` must be null or a valid timestamp.
#[no_mangle]
pub unsafe extern "C" fn z_timestamp_ntp64_time(this_: *const z_timestamp_t) -> u64 {
    guard_val(0, || {
        if this_.is_null() {
            return 0;
        }
        // SAFETY: the caller's contract.
        unsafe { (*this_)._time }
    })
}

/// The originating zid (zenoh-c `z_timestamp_id`).
///
/// # Safety
/// `this_` must be null or a valid timestamp.
#[no_mangle]
pub unsafe extern "C" fn z_timestamp_id(this_: *const z_timestamp_t) -> z_id_t {
    guard_val(z_id_t::empty(), || {
        if this_.is_null() {
            return z_id_t::empty();
        }
        // SAFETY: the caller's contract.
        z_id_t {
            id: unsafe { (*this_)._id },
        }
    })
}

// `z_sample_timestamp` lives in [`crate::sample`], beside the other sample
// accessors and the private marshal reader they all share.

#[cfg(test)]
mod tests {
    use super::*;

    /// The C struct and the wz hint round-trip, INCLUDING the short-zid case.
    ///
    /// The short case is the one with a rule in it: zenoh transmits a zid
    /// PREFIX, so a hint whose `zid` is 12 bytes must come back as 12 bytes and
    /// not as 16 with four zeros appended — the padded form would put four extra
    /// bytes on the wire and compare unequal to the peer's own value.
    #[test]
    fn a_hint_round_trips_through_the_c_struct_at_both_zid_widths() {
        for width in [16usize, 12, 8, 1] {
            let hint = wz_runtime_tokio::sample::TimestampHint {
                time: 0x0000_1234_8000_0000,
                // Non-zero in the LAST byte, so the trailing-zero trim cannot
                // shorten a value that is genuinely `width` long.
                zid: (1..=width as u8).collect(),
            };
            let back = z_timestamp_t::from_hint(&hint).to_hint();
            assert_eq!(back, hint, "round trip failed at zid width {width}");
        }
    }

    /// An all-zero zid trims to EMPTY rather than to 16 zeros, which is the
    /// honest reading: there is no zid there.
    #[test]
    fn an_empty_zid_stays_empty() {
        let back = z_timestamp_t::empty().to_hint();
        assert_eq!(back.time, 0);
        assert!(back.zid.is_empty());
    }

    /// The NTP64 packing is the seconds/fraction split, not a millisecond count
    /// stored raw — the difference a peer would decode as a timestamp ~1000x
    /// off.
    #[test]
    fn millis_pack_into_the_ntp64_seconds_and_fraction_halves() {
        assert_eq!(ntp64_from_millis(0), 0);
        assert_eq!(ntp64_from_millis(1_000), 1u64 << 32);
        // 500 ms is exactly half a second: the fraction half is 2^31.
        assert_eq!(ntp64_from_millis(1_500), (1u64 << 32) | (1u64 << 31));
        // And it is monotonic across the second boundary, which a naive
        // `millis << 32` would also satisfy but a swapped-halves packing
        // would not.
        assert!(ntp64_from_millis(1_999) < ntp64_from_millis(2_000));
    }

    /// NULL is answered, not dereferenced — the accessors are the surface a C
    /// program reaches with an unstamped sample's NULL pointer.
    #[test]
    fn the_accessors_answer_null_without_dereferencing_it() {
        // SAFETY: passing NULL is exactly the contract under test.
        unsafe {
            assert_eq!(z_timestamp_ntp64_time(std::ptr::null()), 0);
            assert_eq!(z_timestamp_id(std::ptr::null()).id, [0u8; Z_ID_SIZE]);
            assert_eq!(
                z_timestamp_new(std::ptr::null_mut(), std::ptr::null()),
                Z_ENULL
            );
        }
    }
}
