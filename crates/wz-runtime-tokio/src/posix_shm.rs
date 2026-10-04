// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2862 (`transport-shm`) — the ONE implementation of a POSIX shared-memory
//! segment the way upstream makes one, for every segment wz creates or opens:
//! the auth segment of the establishment challenge, and the metadata and data
//! segments of an SHM payload.
//!
//! Upstream has one such type, `posix_shm::segment::Segment<ID>` over
//! `shm::unix::SegmentImpl` (`commons/zenoh-shm/src/shm/unix.rs` @
//! `format!("{id}.zenoh")`), and every segment kind is a `Segment` of some id
//! width. wz had the naming, the shared advisory lock and the create-and-retry
//! loop written inside the auth segment, and a second, INCOMPATIBLE naming
//! (`wz-shm-<hex>.wz`) inside the payload provider — so a payload segment was
//! one no zenoh peer could ever open. Everything that is wire format about a
//! segment lives here:
//!
//! * the NAME: `shm_open("{id}.zenoh")`, which glibc resolves to
//!   `/dev/shm/{id}.zenoh`, with the id in decimal whatever its width;
//! * the MODE: 0600, upstream's `S_IRUSR | S_IWUSR`;
//! * the LOCK: a shared, non-blocking `flock` on create and on open, as
//!   upstream takes (`try_lock(FileLockMode::Shared)`); shared locks coexist,
//!   so this never blocks a zenoh peer, and it keeps wz inside the protocol
//!   upstream's cleanup uses to tell a live segment from an orphan.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use memmap2::{Mmap, MmapMut, MmapOptions};

/// How many ids a create tries before giving up — upstream's
/// `SEGMENT_DEDICATE_TRIES` (`commons/zenoh-shm/src/posix_shm/segment.rs` @
/// `const SEGMENT_DEDICATE_TRIES: usize = 100;`).
pub const SEGMENT_DEDICATE_TRIES: usize = 100;

/// Per-process candidate-id source, ONE for every segment kind this process
/// makes. Collisions BETWEEN processes are caught by `create_new` (`O_EXCL`)
/// and retried, so this only needs to spread. Moved here from the auth segment
/// in R2862: the payload provider's metadata and data segments share the same
/// `/dev/shm/{id}.zenoh` namespace, and two counters would be two chances to
/// hand out one id twice.
///
/// ⚠ `create_new` does NOT cover a collision between two draws of THIS
/// counter, which is why [`candidate_id`] must be injective in `c`. Retry only
/// helps while the colliding id is still occupied; an id whose segment has just
/// been unlinked is free, and a second draw then lands on it legitimately.
static ID_COUNTER: AtomicU32 = AtomicU32::new(1);

/// The candidate id for counter value `c` in process `pid`, as a pure function
/// so its one load-bearing property can be asserted over a range a test picks.
///
/// INJECTIVE in `c` (R2201). The earlier form `pid * K + c | 1` flattened the
/// low bit, so every other pair of consecutive counter values collapsed onto
/// one id, and a reader still holding the first id then read the second
/// segment — Layer C1bn caught it hosted. `c << 1` leaves bit 0 free for the
/// `| 1`, so every id is odd (hence never 0) and distinct `c` give distinct
/// ids; the period is 2^31 draws, irrelevant against a retry budget of
/// [`SEGMENT_DEDICATE_TRIES`].
pub fn candidate_id(pid: u32, c: u32) -> u32 {
    pid.wrapping_mul(0x9E37_79B1).wrapping_add(c << 1) | 1
}

/// The next candidate id from this process's counter.
pub fn next_candidate_id() -> u32 {
    candidate_id(
        std::process::id(),
        ID_COUNTER.fetch_add(1, Ordering::Relaxed),
    )
}

/// The `/dev/shm` path upstream's `shm_open("{id}.zenoh", ..)` resolves to.
/// This name IS interop: a foreign peer opens exactly this string.
pub fn segment_path(id: u64) -> PathBuf {
    PathBuf::from(format!("/dev/shm/{id}.zenoh"))
}

/// Take a SHARED advisory lock, as upstream does on both create and open.
fn lock_shared(file: &File) -> io::Result<()> {
    // SAFETY: `flock` takes a borrowed fd and returns an error code; the fd is
    // valid for the borrow and the call has no other effect on process state.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// R2954 — remove every POSIX shm segment no process holds any more: upstream's
/// `cleanup_orphaned_segments` (`commons/zenoh-shm/src/posix_shm/cleanup.rs` @
/// `fn cleanup_orphaned_segments_inner() -> ZResult<()> {`), which zenoh-c
/// exports as `zc_cleanup_orphaned_shm_segments`.
///
/// A segment whose creator crashed persists in `/dev/shm` — that is POSIX, not
/// a bug of either side — so upstream enumerates every `{id}.zenoh` there
/// whose stem is a `u64` and removes the ones that are DANGLING: gone between
/// the listing and the open, or openable with an EXCLUSIVE non-blocking
/// `flock` (`commons/zenoh-shm/src/shm/unix.rs` @ `.try_lock(FileLockMode::Exclusive)`). Every live
/// holder, wz's included, keeps the SHARED lock `lock_shared` takes for as
/// long as it maps the segment, so an exclusive lock succeeds exactly when no
/// one does. Any other open error (a segment of another user, say) keeps the
/// segment, as upstream's does.
///
/// Best-effort and silent, as upstream's is: it runs from exit paths where no
/// error has anywhere to go. A no-op off Linux, where upstream's is too.
pub fn cleanup_orphaned_segments() {
    #[cfg(target_os = "linux")]
    {
        let Ok(entries) = std::fs::read_dir("/dev/shm") else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.extension() != Some(std::ffi::OsStr::new("zenoh")) {
                continue;
            }
            let Some(id) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| stem.parse::<u64>().ok())
            else {
                continue;
            };
            if segment_is_dangling(id) {
                let _ = std::fs::remove_file(segment_path(id));
            }
        }
    }
}

/// Whether segment `id` is held by no process — upstream's
/// `is_dangling_segment`
/// (`commons/zenoh-shm/src/shm/unix.rs` @ `fn is_dangling_segment(id: ID) -> bool {`).
#[cfg(target_os = "linux")]
fn segment_is_dangling(id: u64) -> bool {
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .open(segment_path(id))
    {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return true,
        Err(_) => return false,
    };
    // SAFETY: `flock` takes a borrowed fd and returns an error code; the fd is
    // valid for the borrow, and the lock it may take is released when `file`
    // closes at the end of this function.
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

/// A segment THIS process created: mapped read-write, and unlinked on drop.
///
/// The file is held so the shared lock lives as long as the segment does —
/// `flock` locks are released when the last fd for the open file closes.
pub struct OwnedSegment {
    map: MmapMut,
    id: u64,
    path: PathBuf,
    _file: File,
}

impl OwnedSegment {
    /// Create a segment of `len` bytes under the first free id `next_id`
    /// yields, trying at most [`SEGMENT_DEDICATE_TRIES`] of them. The new
    /// segment is zero-filled (`ftruncate` of a fresh object).
    pub fn create(len: usize, mut next_id: impl FnMut() -> u64) -> io::Result<Self> {
        let mut last_err = None;
        for _ in 0..SEGMENT_DEDICATE_TRIES {
            let id = next_id();
            let path = segment_path(id);
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => {
                    file.set_len(len as u64)?;
                    lock_shared(&file)?;
                    // SAFETY: the file was just created exclusively by this
                    // process, and this mapping is the only writer it makes.
                    let map = unsafe { MmapOptions::new().map_mut(&file)? };
                    return Ok(Self {
                        map,
                        id,
                        path,
                        _file: file,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last_err = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::other(format!(
                "could not dedicate a POSIX shm segment after {SEGMENT_DEDICATE_TRIES} tries"
            ))
        }))
    }

    /// The id this segment is named by — the value a peer is told.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The segment's bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.map
    }

    /// The segment's bytes, writable.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.map
    }

    /// Flush the mapping to the object.
    pub fn flush(&self) -> io::Result<()> {
        self.map.flush()
    }
}

impl Drop for OwnedSegment {
    fn drop(&mut self) {
        // Best-effort unlink, matching upstream's cleanup registration. A
        // failure leaves a stale object in /dev/shm, which reads as "absent" to
        // any peer once no one maps it; it is not worth panicking in a drop.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A segment ANOTHER process created, opened by id and mapped read-only.
pub struct PeerSegment {
    map: Mmap,
    _file: File,
}

impl PeerSegment {
    /// Open the segment named by `id`. An error — never a panic — when it does
    /// not exist or cannot be locked or mapped: to a caller that is "this peer
    /// holds no such segment", which is an ordinary outcome of shared memory.
    pub fn open(id: u64) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(segment_path(id))?;
        lock_shared(&file)?;
        // SAFETY: a read-only view of a peer-owned mapping. The peer may write
        // it concurrently, which is the shared-memory contract; every reader of
        // this view reads fields whose torn value fails a comparison rather
        // than being unsound.
        let map = unsafe { MmapOptions::new().map(&file)? };
        Ok(Self { map, _file: file })
    }

    /// The segment's bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.map
    }
}

/// R3038 -- a segment ANOTHER process created, opened by id and mapped
/// READ-WRITE, for a reader that has to write what it reads.
///
/// A receiver gives a buffer's reference back by decrementing the `refcount` in
/// the PROVIDER's metadata segment, so its view of that segment cannot be
/// read-only (a write through a read-only mapping is a SIGSEGV, found the hard
/// way). Upstream's reader maps it writable for the same reason. The data
/// segment stays a [`PeerSegment`]: a reader of a payload writes nothing there.
///
/// What is exposed is a POINTER with write provenance, not a `&[u8]`: the
/// contents are atomics, and a shared reference to bytes is a promise that
/// nothing writes them.
pub struct PeerSegmentRw {
    /// Taken from `as_mut_ptr` at open, so it carries the right to write; the
    /// mapping it points into lives exactly as long as `_map`.
    ptr: *mut u8,
    len: usize,
    _map: MmapMut,
    _file: File,
}

impl PeerSegmentRw {
    /// Open the segment named by `id`. An error, never a panic, when it does not
    /// exist or cannot be locked or mapped, as for [`PeerSegment::open`].
    pub fn open(id: u64) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(segment_path(id))?;
        lock_shared(&file)?;
        // SAFETY: a writable view of a peer-owned mapping. The peer and this
        // process both write it concurrently, which is the shared-memory
        // contract; every field a caller reaches through it is an atomic.
        let mut map = unsafe { MmapOptions::new().map_mut(&file)? };
        let ptr = map.as_mut_ptr();
        let len = map.len();
        Ok(Self {
            ptr,
            len,
            _map: map,
            _file: file,
        })
    }

    /// The segment's size in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the segment is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The segment's first byte, as a pointer that may be written through. Valid
    /// for [`Self::len`] bytes for as long as `self` lives.
    pub fn base(&self) -> *mut u8 {
        self.ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R2954 — the cleanup removes a segment no one holds and keeps one a
    /// process holds, by upstream's rule (an exclusive `flock` succeeds only on
    /// the first). The orphan's id sits above the `u32` range every
    /// [`candidate_id`] draws from, so it can collide with no live segment.
    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_removes_an_orphaned_segment_and_keeps_a_held_one() {
        let orphan_id = (1u64 << 40) + u64::from(std::process::id());
        let orphan = segment_path(orphan_id);
        std::fs::write(&orphan, [0u8; 64]).expect("write an orphaned segment");
        let held = OwnedSegment::create(64, || u64::from(next_candidate_id()))
            .expect("create a held segment");
        let held_path = segment_path(held.id());

        cleanup_orphaned_segments();

        assert!(!orphan.exists(), "a segment no process holds is removed");
        assert!(held_path.exists(), "a segment this process holds is kept");
        drop(held);
        assert!(!held_path.exists(), "and its own drop still unlinks it");
    }
}
