// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_snapshot_*`: the node's resource snapshot, taken and read from C
//! (`docs/observation-plane.md` M4).
//!
//! A door wz has and zenoh-pico does not, so each is `wz_ext_*`, declared in `wz_ext.h`
//! (docs/build-configuration.md, decision C10), and part of the unstable surface: a build without
//! `unstable-api` carries none of it.
//!
//! A snapshot is a fixed-layout, versioned record (`wz_session_core::resource_snapshot`): the CPU
//! use, the heap and the tasks the platform reports, and how the messages the session received
//! were spaced. The platform is the program's: it registers a source
//! (`wz_ext_snapshot_set_source`) that answers what it can, and a part it cannot answer is marked
//! unavailable in the record and not read as zero. The library holds no thread and no timer: the
//! program calls `wz_ext_snapshot_poll` on its own cadence, which takes a snapshot when the
//! build's period (`SNAPSHOT_PERIOD_MS`) has passed since the last, and
//! `wz_ext_snapshot_read` copies the latest out as bytes.
//!
//! The source runs on the thread that called `poll`, with no lock of the library held, so it may
//! call any of these doors. Time is microseconds on the monotonic clock since the first call,
//! counted in 32 bits that wrap, which the sampler's comparison is written to survive.
//!
//! What the sampler does is [`wz_capi_port::observation::snapshot`]'s, which the zenoh-c ABI's
//! doors act on too; this file is the pico ABI's names and result codes for it, and the session
//! whose received messages the snapshot counts.

use std::ffi::c_void;

use wz_capi_port::observation::snapshot;
use wz_capi_port::observation::Refusal;

use crate::result::{ZResult, Z_ERR_GENERIC, Z_ERR_NULL, Z_ERR_OVERFLOW, Z_OK};
use crate::session::{session_handle, z_loaned_session_t};

/// What a source writes: the readings it has, and which of them it has.
///
/// `available` is the bits [`WZ_EXT_SNAPSHOT_HAS_CPU`], `_HAS_HEAP` and `_HAS_TASKS`; a field whose
/// bit is clear is not read, whatever the source left in it.
#[allow(non_camel_case_types)]
pub type wz_ext_resource_reading_t = snapshot::ResourceReadingC;

/// The program's resource source: fills `out` and returns 0, or returns anything else when it
/// cannot answer at all, which takes the snapshot with no part available.
#[allow(non_camel_case_types)]
pub type wz_ext_snapshot_source_fn = snapshot::SourceFn;

/// The source answers the CPU use.
pub const WZ_EXT_SNAPSHOT_HAS_CPU: u8 = snapshot::AVAILABLE_CPU;
/// The source answers the heap.
pub const WZ_EXT_SNAPSHOT_HAS_HEAP: u8 = snapshot::AVAILABLE_HEAP;
/// The source answers the task count.
pub const WZ_EXT_SNAPSHOT_HAS_TASKS: u8 = snapshot::AVAILABLE_TASKS;

/// The latest snapshot as the admin space's JSON document, or `None` before the program has taken
/// the first one: the node does not sample on its own, so there is nothing to say until it is
/// asked to.
#[cfg(feature = "admin-space")]
pub(crate) fn latest_json() -> Option<String> {
    snapshot::latest_json()
}

/// The pico code of a refusal of the snapshot doors.
fn code(refusal: Refusal) -> ZResult {
    match refusal {
        Refusal::Full => Z_ERR_OVERFLOW,
        Refusal::Invalid | Refusal::Unavailable => Z_ERR_GENERIC,
    }
}

/// Set the source `wz_ext_snapshot_poll` asks for the platform's readings, or clear it with a null
/// `read`. With none set, a snapshot is still taken, with the message counts and no part of the
/// platform's available.
///
/// # Safety
/// `read` must be safe to call from the thread that calls `wz_ext_snapshot_poll` for as long as it
/// is set, and `context` must stay valid as long.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_snapshot_set_source(
    read: Option<wz_ext_snapshot_source_fn>,
    context: *mut c_void,
) -> ZResult {
    crate::ffi::guarded(|| {
        snapshot::set_source(read, context);
        Z_OK
    })
}

/// Take a snapshot if the build's period has passed since the last, of the session `session`'s
/// received messages and whatever the source answers. 1 when one was taken, 0 when none was due,
/// `Z_ERR_NULL` for a null or spent session. The first call takes one.
///
/// # Safety
/// `session` is a loaned session of this library, or null.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_snapshot_poll(session: *const z_loaned_session_t) -> ZResult {
    crate::ffi::guarded(|| {
        let Some(handle) = session_handle(session) else {
            return Z_ERR_NULL;
        };
        ZResult::from(snapshot::poll(|| {
            handle.drive.engine_ref().message_reading()
        }))
    })
}

/// How many bytes `wz_ext_snapshot_read` writes: the size of the snapshot of this build, which
/// grows with `SNAPSHOT_HISTOGRAM_BUCKETS`.
#[no_mangle]
pub extern "C" fn wz_ext_snapshot_size() -> usize {
    snapshot::size()
}

/// Copy the latest snapshot into `out`, which has room for `capacity` bytes, and write its length
/// to `length`. The record is little-endian and starts with its own layout version and size, so a
/// reader of an older build can tell a newer one (`docs/observation-plane.md` M4).
/// `Z_ERR_GENERIC` before the first snapshot, `Z_ERR_OVERFLOW` when `capacity` is less than
/// `wz_ext_snapshot_size`, `Z_ERR_NULL` for a null `out` or `length`.
///
/// # Safety
/// `out` is writable for `capacity` bytes and `length` for one `size_t`.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_snapshot_read(
    out: *mut u8,
    capacity: usize,
    length: *mut usize,
) -> ZResult {
    crate::ffi::guarded(|| {
        if out.is_null() || length.is_null() {
            return Z_ERR_NULL;
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
