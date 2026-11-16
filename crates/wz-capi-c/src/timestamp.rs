// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
//! since R232 (`PublishOptions::with_timestamp`, the `MsgPut`/`MsgDel` T-flag)
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
//! already follows for [`z_id_t`]: the C contract is the
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
use crate::session::{not_a_registry, session_handle};
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
/// Upstream's is `session.new_timestamp()`, which reads the node's clock when the node holds one
/// and the system time with the session's id when it does not, and answers `Z_OK` either way. So
/// is this: the session's node clock (the registry's or the node's), read for the program, with no
/// stamping policy applied. The
/// `clock-quality-stamping` policy is about the data the node stamps (a publication, a reply, a put
/// it forwards); a program that asks for the time is given the clock's, so what it is given and
/// what the node stamps are one clock and interleave.
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
        // The clock and the zid exist on a node as well as on the registry, so the handle is
        // read, not the registry's state.
        let Some(handle) = (unsafe { session_handle(session) }) else {
            return unsafe { not_a_registry(session) };
        };
        let stamped = session_timestamp(&handle.node_hlc(), handle.zid());
        // SAFETY: checked non-null above.
        unsafe { *this_ = stamped };
        Z_OK
    })
}

/// What [`z_timestamp_new`] gives a session whose node clock is `hlc` and whose id is `zid`: the
/// clock's next time, or, for a node that holds no clock (its role does not timestamp) or whose
/// source cannot say what time it is, the system time, upstream's `None` arm of
/// `Session::new_timestamp`.
///
/// The system time is read through [`wall_clock_ntp64`](wz_runtime_tokio::timestamp_source::wall_clock_ntp64),
/// the NTP64 recipe the storage stack stamps with, so its seconds half is the Unix epoch's and not
/// a session uptime, which the real library was measured to print (`ntp_secs == time(NULL)`).
fn session_timestamp(
    hlc: &wz_runtime_tokio::node_clock::NodeHlc,
    zid: [u8; Z_ID_SIZE],
) -> z_timestamp_t {
    let time = match hlc.clock_stamp() {
        Some(stamp) => stamp.time,
        None => wz_runtime_tokio::timestamp_source::wall_clock_ntp64(),
    };
    z_timestamp_t {
        _time: time,
        _id: zid,
    }
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

    /// R311y569 — the minted NTP64's SECONDS half is the UNIX EPOCH, not an
    /// uptime.
    ///
    /// The test the packing helper used to carry checked that milliseconds
    /// split correctly into the two halves, and it PASSED throughout the whole
    /// life of the defect: the arithmetic was right and its INPUT was wrong.
    /// That is why this asserts the magnitude against the process's own clock
    /// instead — the one property a unit-conversion test cannot express.
    ///
    /// The bound is loose on purpose (a decade either side): the claim is "this
    /// is wall-clock time", not "this is the same instant", and a tight window
    /// would make the test a rate measurement of the machine it runs on.
    #[test]
    fn the_minted_ntp64_seconds_half_is_the_unix_epoch_not_an_uptime() {
        let word = wz_runtime_tokio::timestamp_source::wall_clock_ntp64();
        let secs = word >> 32;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the system clock is after 1970")
            .as_secs();
        let decade = 10 * 365 * 24 * 60 * 60;
        assert!(
            secs.abs_diff(now) < decade,
            "the NTP64 seconds half is {secs}, which is not within a decade of \
             the UNIX time {now}. A session-uptime word reads as 1970 on every \
             peer that decodes it — the defect this replaced."
        );
    }

    /// A node whose clock is not trusted stamps none of its data under `trusted-only`, and a
    /// program that asks for the time is given the clock's all the same: one clock, so what the
    /// program is given and what the node stamps once the clock is trusted interleave. Only a
    /// build whose node holds a clock (`timestamping`, the runtime's `time-hlc`) can ask it.
    #[cfg(feature = "timestamping")]
    #[test]
    fn a_trusted_only_node_gives_a_program_the_time_of_the_clock_it_stamps_data_with() {
        use wz_runtime_tokio::node_clock::{NodeHlc, TimestampingEnabled};
        use wz_runtime_tokio::session_glue::WhatAmI;
        use wz_runtime_tokio::timestamp_source::SystemEpoch;

        let zid = [0x5a; Z_ID_SIZE];
        let hlc = NodeHlc::for_node_over_source(
            &zid,
            WhatAmI::Router,
            TimestampingEnabled::all(true),
            SystemEpoch,
        )
        .with_trusted_only_stamping(true);
        assert!(
            hlc.stamp().is_none(),
            "no reference reported: no data is stamped"
        );
        let first = session_timestamp(&hlc, zid);
        assert_eq!(first._id, zid);
        assert!(hlc.report_sync_acquired());
        let stamped = hlc.stamp().expect("a trusted clock stamps data").time;
        let second = session_timestamp(&hlc, zid);
        assert!(
            first._time < stamped && stamped < second._time,
            "one clock: {} {stamped} {}",
            first._time,
            second._time
        );
    }

    /// A node that holds no clock (its role does not timestamp) gives the system time with the
    /// session's id, upstream's `None` arm.
    #[test]
    fn a_node_that_holds_no_clock_gives_the_system_time() {
        let zid = [0x5b; Z_ID_SIZE];
        let given = session_timestamp(&wz_runtime_tokio::node_clock::NodeHlc::disabled(), zid);
        assert_eq!(given._id, zid);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the system clock is after 1970")
            .as_secs();
        assert!((given._time >> 32).abs_diff(now) < 60, "the system time");
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
