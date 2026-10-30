// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The node's resource snapshot, taken and read from C (`docs/observation-plane.md` M4).
//!
//! The node does not sample on its own: the program polls ([`poll`]), the sampler takes a snapshot
//! when its period has passed, and the program reads the latest ([`read_latest`]). A snapshot is
//! the session's received-message count (the engine's own meter), what the program's resource
//! source says about the platform, and the event ring's loss when the build has the ring. A part
//! the source did not measure is not available in the record, whatever the source left in it.
//!
//! The record is versioned and fixed-layout ([`wz_session_core::resource_snapshot`]); it starts
//! with its own layout version and size, so a reader of an older build can tell a newer one.

use std::ffi::c_void;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Instant;

use wz_session_core::resource_snapshot::{
    BuildMessageReading, BuildSampler, HeapReading, ResourceReading, Snapshot, HAS_CPU, HAS_HEAP,
    HAS_TASKS,
};

use super::Refusal;

/// The snapshot this build takes: `SNAPSHOT_HISTOGRAM_BUCKETS` buckets.
type BuildSnapshot = Snapshot<{ wz_session_core::caps::SNAPSHOT_HISTOGRAM_BUCKETS }>;

/// What a source writes: the readings it has, and which of them it has.
///
/// `available` is the bits [`AVAILABLE_CPU`], [`AVAILABLE_HEAP`] and [`AVAILABLE_TASKS`]; a field
/// whose bit is clear is not read, whatever the source left in it.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ResourceReadingC {
    /// Which of the readings the source answers.
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
pub type SourceFn = unsafe extern "C" fn(context: *mut c_void, out: *mut ResourceReadingC) -> i8;

/// The source answers the CPU use.
pub const AVAILABLE_CPU: u8 = HAS_CPU;
/// The source answers the heap.
pub const AVAILABLE_HEAP: u8 = HAS_HEAP;
/// The source answers the task count.
pub const AVAILABLE_TASKS: u8 = HAS_TASKS;

#[derive(Clone, Copy)]
struct Source {
    read: SourceFn,
    context: *mut c_void,
}

// SAFETY: the program owns the source's thread-safety and the context's lifetime; the context is
// opaque here and only handed back to the source.
unsafe impl Send for Source {}

impl Source {
    /// What the source answers, or nothing for a source that could not.
    ///
    /// # Safety
    /// Under the contract of [`set_source`].
    unsafe fn read(self) -> ResourceReading {
        let mut out = ResourceReadingC::default();
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
            events_dropped: None,
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
/// [`feature_bits`](wz_session_core::resource_snapshot::feature_bits): the capabilities of the
/// declaration that this crate has a feature of the same name for. An ABI crate forwards each of
/// its own to this one, so the word is the image's.
fn features() -> u64 {
    wz_session_core::built_feature_bits!()
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

fn locked() -> MutexGuard<'static, Doors> {
    doors().lock().unwrap_or_else(PoisonError::into_inner)
}

/// Set the source [`poll`] asks for the platform's readings, or clear it with `None`. With none
/// set, a snapshot is still taken, with the message counts and no part of the platform's
/// available.
///
/// # Safety
/// `read` must be safe to call from the thread that calls [`poll`] for as long as it is set, and
/// `context` must stay valid as long.
pub unsafe fn set_source(read: Option<SourceFn>, context: *mut c_void) {
    locked().source = read.map(|read| Source { read, context });
}

/// Take a snapshot if the build's period has passed since the last, of the messages `messages`
/// says the node has received and whatever the source answers. True when one was taken, false when
/// none was due. The first call takes one.
pub fn poll(messages: impl FnOnce() -> Option<BuildMessageReading>) -> bool {
    let (now, source) = {
        let doors = locked();
        let now = doors.now();
        if !doors.sampler.is_due(now) {
            return false;
        }
        (now, doors.source)
    };
    // The program's source and the engine's counters are read with no lock of the library held,
    // so a source that calls back into a door does not wait on this one.
    let reading = match source {
        // SAFETY: the program's source, under the contract of `set_source`.
        Some(source) => unsafe { source.read() },
        None => ResourceReading::default(),
    };
    // The event ring's loss is the library's to say, not the program's source's: a build with the
    // ring states how many events it refused, so a reader of the snapshot is told of a log that is
    // losing events beside the load that may be the reason.
    #[cfg(feature = "event-ring")]
    let reading = ResourceReading {
        events_dropped: Some(wz_node_time::event_log::global().dropped()),
        ..reading
    };
    let messages = messages().unwrap_or_else(BuildMessageReading::empty);
    locked().sampler.take(now, reading, messages);
    true
}

/// How many bytes [`read_latest`] writes: the size of the snapshot of this build, which grows with
/// `SNAPSHOT_HISTOGRAM_BUCKETS`.
pub fn size() -> usize {
    BuildSnapshot::SIZE
}

/// Copy the latest snapshot into `out` and return its length. The record is little-endian.
/// [`Refusal::Unavailable`] before the first snapshot, [`Refusal::Full`] when `out` is smaller than
/// [`size`].
pub fn read_latest(out: &mut [u8]) -> Result<usize, Refusal> {
    let doors = locked();
    let Some(latest) = doors.sampler.latest() else {
        return Err(Refusal::Unavailable);
    };
    if out.len() < BuildSnapshot::SIZE {
        return Err(Refusal::Full);
    }
    latest.to_bytes(out).ok_or(Refusal::Full)
}

/// The latest snapshot as the admin space's JSON document, or `None` before the program has taken
/// the first one: the node does not sample on its own, so there is nothing to say until it is
/// asked to.
pub fn latest_json() -> Option<String> {
    let doors = locked();
    let mut text = String::new();
    doors.sampler.latest()?.write_json(&mut text).ok()?;
    Some(text)
}
