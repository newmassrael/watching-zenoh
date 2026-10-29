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

use std::ffi::c_void;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::Instant;

use wz_session_core::resource_snapshot::{
    feature_bits, BuildSampler, HeapReading, MessageReading, ResourceReading, Snapshot, HAS_CPU,
    HAS_HEAP, HAS_TASKS,
};

use crate::result::{ZResult, Z_ERR_GENERIC, Z_ERR_NULL, Z_ERR_OVERFLOW, Z_OK};
use crate::session::{session_handle, z_loaned_session_t};

/// The snapshot this build takes: `SNAPSHOT_HISTOGRAM_BUCKETS` buckets.
type BuildSnapshot = Snapshot<{ wz_session_core::caps::SNAPSHOT_HISTOGRAM_BUCKETS }>;

/// What a source writes: the readings it has, and which of them it has.
///
/// `available` is the bits [`WZ_EXT_SNAPSHOT_HAS_CPU`], `_HAS_HEAP` and `_HAS_TASKS`; a field whose
/// bit is clear is not read, whatever the source left in it.
#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Default)]
pub struct wz_ext_resource_reading_t {
    pub available: u8,
    pub reserved: u8,
    /// How much of the time the CPU was busy since the last reading, in thousandths.
    pub cpu_permille: u16,
    /// How many tasks the node runs.
    pub tasks: u16,
    pub reserved2: u16,
    /// Bytes on the heap in use now.
    pub heap_in_use: u64,
    /// The most bytes there have been in use.
    pub heap_high_water: u64,
}

/// The program's resource source: fills `out` and returns 0, or returns anything else when it
/// cannot answer at all, which takes the snapshot with no part available.
#[allow(non_camel_case_types)]
pub type wz_ext_snapshot_source_fn =
    unsafe extern "C" fn(context: *mut c_void, out: *mut wz_ext_resource_reading_t) -> i8;

/// The source answers the CPU use.
pub const WZ_EXT_SNAPSHOT_HAS_CPU: u8 = HAS_CPU;
/// The source answers the heap.
pub const WZ_EXT_SNAPSHOT_HAS_HEAP: u8 = HAS_HEAP;
/// The source answers the task count.
pub const WZ_EXT_SNAPSHOT_HAS_TASKS: u8 = HAS_TASKS;

#[derive(Clone, Copy)]
struct Source {
    read: wz_ext_snapshot_source_fn,
    context: *mut c_void,
}

// SAFETY: the program owns the source's thread-safety and the context's lifetime; the context is
// opaque here and only handed back to the source.
unsafe impl Send for Source {}

impl Source {
    /// What the source answers, or nothing for a source that could not.
    ///
    /// # Safety
    /// Under the contract of `wz_ext_snapshot_set_source`.
    unsafe fn read(self) -> ResourceReading {
        let mut out = wz_ext_resource_reading_t::default();
        if (self.read)(self.context, &mut out) != 0 {
            return ResourceReading::default();
        }
        ResourceReading {
            cpu_permille: (out.available & HAS_CPU != 0).then_some(out.cpu_permille),
            heap: (out.available & HAS_HEAP != 0).then_some(HeapReading {
                in_use: out.heap_in_use,
                high_water: out.heap_high_water,
            }),
            tasks: (out.available & HAS_TASKS != 0).then_some(out.tasks),
        }
    }
}

struct Doors {
    sampler: BuildSampler,
    source: Option<Source>,
    origin: Instant,
}

impl Doors {
    /// Microseconds since the first call, in the 32 bits the sampler compares.
    fn now(&self) -> u32 {
        self.origin.elapsed().as_micros() as u32
    }
}

/// The instruments of the observation plane this image was built with, as the bits of
/// [`feature_bits`]: this snapshot's own, and each of the other three this crate has a feature for.
fn features() -> u64 {
    let mut word = feature_bits::RESOURCE_SNAPSHOT;
    if cfg!(feature = "clock-source") {
        word |= feature_bits::CLOCK_SOURCE;
    }
    if cfg!(feature = "event-ring") {
        word |= feature_bits::EVENT_RING;
    }
    if cfg!(feature = "supervision") {
        word |= feature_bits::SUPERVISION;
    }
    word
}

/// The latest snapshot as the admin space's JSON document, or `None` before the program has taken
/// the first one: the node does not sample on its own, so there is nothing to say until it is
/// asked to.
pub(crate) fn latest_json() -> Option<String> {
    let doors = locked();
    let mut text = String::new();
    doors.sampler.latest()?.write_json(&mut text).ok()?;
    Some(text)
}

fn doors() -> &'static Mutex<Doors> {
    static DOORS: OnceLock<Mutex<Doors>> = OnceLock::new();
    DOORS.get_or_init(|| {
        Mutex::new(Doors {
            sampler: BuildSampler::for_build(features()),
            source: None,
            origin: Instant::now(),
        })
    })
}

fn locked() -> std::sync::MutexGuard<'static, Doors> {
    doors().lock().unwrap_or_else(PoisonError::into_inner)
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
        locked().source = read.map(|read| Source { read, context });
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
        let (now, source) = {
            let doors = locked();
            let now = doors.now();
            if !doors.sampler.is_due(now) {
                return 0;
            }
            (now, doors.source)
        };
        // The program's source and the engine's counters are read with no lock of the library
        // held, so a source that calls back into a door does not wait on this one.
        let reading = match source {
            // SAFETY: the program's source, under the contract of `set_source`.
            Some(source) => unsafe { source.read() },
            None => ResourceReading::default(),
        };
        let messages = handle
            .drive
            .engine_ref()
            .message_reading()
            .unwrap_or_else(MessageReading::empty);
        locked().sampler.take(now, reading, messages);
        1
    })
}

/// How many bytes `wz_ext_snapshot_read` writes: the size of the snapshot of this build, which
/// grows with `SNAPSHOT_HISTOGRAM_BUCKETS`.
#[no_mangle]
pub extern "C" fn wz_ext_snapshot_size() -> usize {
    BuildSnapshot::SIZE
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
        let doors = locked();
        let Some(latest) = doors.sampler.latest() else {
            return Z_ERR_GENERIC;
        };
        if capacity < BuildSnapshot::SIZE {
            return Z_ERR_OVERFLOW;
        }
        // SAFETY: `out` is writable for `capacity` bytes, the contract above.
        let buffer = unsafe { std::slice::from_raw_parts_mut(out, capacity) };
        match latest.to_bytes(buffer) {
            Some(written) => {
                // SAFETY: `length` is writable, the contract above.
                unsafe { *length = written };
                Z_OK
            }
            None => Z_ERR_OVERFLOW,
        }
    })
}
