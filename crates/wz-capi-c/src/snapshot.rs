// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_capi_c_snapshot_*`: the node's resource snapshot, taken and read from C
//! (`docs/observation-plane.md` M4).
//!
//! A door wz has and zenoh-c has not, so each carries the `wz_capi_c_` prefix and is declared in
//! `wz_capi_c.h`. A snapshot is a fixed-layout, versioned record
//! (`wz_session_core::resource_snapshot`): the CPU use, the heap and the tasks the platform
//! reports, and how the messages the session received were spaced. The platform is the program's:
//! it registers a source (`wz_capi_c_snapshot_set_source`) that answers what it can, and a part
//! it cannot answer is marked unavailable in the record and not read as zero. The library holds no
//! thread and no timer: the program calls `wz_capi_c_snapshot_poll` on its own cadence, which
//! takes a snapshot when the build's period (`SNAPSHOT_PERIOD_MS`) has passed since the last, and
//! `wz_capi_c_snapshot_read` copies the latest out as bytes.
//!
//! The source runs on the thread that called `poll`, with no lock of the library held, so it may
//! call any of these doors. Time is microseconds on the monotonic clock since the first call,
//! counted in 32 bits that wrap, which the sampler's comparison is written to survive.
//!
//! A hosted node serves the same record as JSON at `wz/@/<zid>/snapshot` on its own; these doors
//! are for a program that wants the bytes, or that wants a node with no admin space to have them.
//!
//! What the sampler does is [`wz_capi_port::observation::snapshot`]'s, which the pico ABI's
//! `wz_ext_snapshot_*` doors act on too; this file is this ABI's names and result codes for it,
//! and the session whose received messages the snapshot counts.

use std::ffi::c_void;

use wz_capi_port::observation::snapshot;
use wz_capi_port::observation::Refusal;

use crate::abi::z_loaned_session_t;
use crate::ffi::guarded;
use crate::result::{ZResult, WZ_CAPI_C_E_FULL, Z_EGENERIC, Z_ENULL, Z_OK};
use crate::session::session_state;

/// What a source writes: the readings it has, and which of them it has.
///
/// `available` is the bits `WZ_CAPI_C_SNAPSHOT_HAS_CPU`, `_HAS_HEAP` and `_HAS_TASKS`; a field
/// whose bit is clear is not read, whatever the source left in it.
#[allow(non_camel_case_types)]
pub type wz_capi_c_resource_reading_t = snapshot::ResourceReadingC;

/// The program's resource source: fills `out` and returns 0, or returns anything else when it
/// cannot answer at all, which takes the snapshot with no part available.
#[allow(non_camel_case_types)]
pub type wz_capi_c_snapshot_source_fn = snapshot::SourceFn;

/// The source answers the CPU use.
pub const WZ_CAPI_C_SNAPSHOT_HAS_CPU: u8 = snapshot::AVAILABLE_CPU;
/// The source answers the heap.
pub const WZ_CAPI_C_SNAPSHOT_HAS_HEAP: u8 = snapshot::AVAILABLE_HEAP;
/// The source answers the task count.
pub const WZ_CAPI_C_SNAPSHOT_HAS_TASKS: u8 = snapshot::AVAILABLE_TASKS;

/// This ABI's code for a refusal of the snapshot doors.
fn code(refusal: Refusal) -> ZResult {
    match refusal {
        Refusal::Full => WZ_CAPI_C_E_FULL,
        Refusal::Invalid | Refusal::Unavailable => Z_EGENERIC,
    }
}

/// Set the source `wz_capi_c_snapshot_poll` asks for the platform's readings, or clear it with a
/// null `read`. With none set, a snapshot is still taken, with the message counts and no part of
/// the platform's available.
///
/// # Safety
/// `read` must be safe to call from the thread that calls `wz_capi_c_snapshot_poll` for as long
/// as it is set, and `context` must stay valid as long.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_snapshot_set_source(
    read: Option<wz_capi_c_snapshot_source_fn>,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract.
        unsafe { snapshot::set_source(read, context) };
        Z_OK
    })
}

/// Take a snapshot if the build's period has passed since the last, of the session `session`'s
/// received messages and whatever the source answers. 1 when one was taken, 0 when none was due,
/// `Z_ENULL` for a null or closed session. The first call takes one.
///
/// # Safety
/// `session` is a loaned session of this library, or null.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_snapshot_poll(session: *const z_loaned_session_t) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { session_state(session) }) else {
            return Z_ENULL;
        };
        ZResult::from(snapshot::poll(|| Some(state.shared.message_reading())))
    })
}

/// How many bytes `wz_capi_c_snapshot_read` writes: the size of the snapshot of this build, which
/// grows with `SNAPSHOT_HISTOGRAM_BUCKETS`.
#[no_mangle]
pub extern "C" fn wz_capi_c_snapshot_size() -> usize {
    snapshot::size()
}

/// Copy the latest snapshot into `out`, which has room for `capacity` bytes, and write its length
/// to `length`. The record is little-endian and starts with its own layout version and size, so a
/// reader of an older build can tell a newer one (`docs/observation-plane.md` M4).
/// `Z_EGENERIC` before the first snapshot, `WZ_CAPI_C_E_FULL` when `capacity` is less than
/// `wz_capi_c_snapshot_size`, `Z_ENULL` for a null `out` or `length`.
///
/// # Safety
/// `out` is writable for `capacity` bytes and `length` for one `size_t`.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_snapshot_read(
    out: *mut u8,
    capacity: usize,
    length: *mut usize,
) -> ZResult {
    guarded(|| {
        if out.is_null() || length.is_null() {
            return Z_ENULL;
        }
        // SAFETY: `out` is writable for `capacity` bytes, the contract above.
        let buffer = unsafe { std::slice::from_raw_parts_mut(out, capacity) };
        match snapshot::read_latest(buffer) {
            Ok(written) => {
                // SAFETY: `length` is writable, the contract above.
                unsafe { *length = written };
                Z_OK
            }
            Err(refusal) => code(refusal),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_null_session_and_null_outputs_are_refused_without_a_write() {
        // SAFETY: the nulls are what the doors refuse.
        unsafe {
            assert_eq!(wz_capi_c_snapshot_poll(std::ptr::null()), Z_ENULL);
            let mut length = 5usize;
            assert_eq!(
                wz_capi_c_snapshot_read(std::ptr::null_mut(), 0, &mut length),
                Z_ENULL
            );
            let mut byte = 0u8;
            assert_eq!(
                wz_capi_c_snapshot_read(&mut byte, 1, std::ptr::null_mut()),
                Z_ENULL
            );
            assert_eq!(length, 5, "a refused read writes nothing");
        }
    }

    #[test]
    fn a_buffer_smaller_than_the_record_is_refused_with_the_full_code_or_nothing_was_taken() {
        let mut buffer = vec![0u8; 4];
        let mut length = 0usize;
        // SAFETY: a writable buffer of four bytes and a writable length.
        let rc = unsafe { wz_capi_c_snapshot_read(buffer.as_mut_ptr(), 4, &mut length) };
        // Before the first snapshot there is nothing to give, and after it a short buffer is full:
        // either way nothing was written.
        assert!(rc == Z_EGENERIC || rc == WZ_CAPI_C_E_FULL, "{rc}");
        assert_eq!(length, 0);
        assert!(wz_capi_c_snapshot_size() > 4);
    }
}
