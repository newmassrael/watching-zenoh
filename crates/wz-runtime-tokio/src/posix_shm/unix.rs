// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Unix segment: a `/dev/shm/{id}.zenoh` file, `flock`ed and `mmap`ed, the way
//! upstream's `shm::unix::SegmentImpl` makes one (`commons/zenoh-shm/src/shm/unix.rs`
//! @ `format!("{id}.zenoh")`). The platform-neutral half (the id source and its
//! injectivity rationale) lives in the parent module.
//!
//! * the NAME: `shm_open("{id}.zenoh")`, which glibc resolves to
//!   `/dev/shm/{id}.zenoh`, with the id in decimal whatever its width;
//! * the MODE: 0600, upstream's `S_IRUSR | S_IWUSR`;
//! * the LOCK: a shared, non-blocking `flock` on create and on open, as
//!   upstream takes (`try_lock(FileLockMode::Shared)`); shared locks coexist,
//!   so this never blocks a zenoh peer, and it keeps wz inside the protocol
//!   upstream's cleanup uses to tell a live segment from an orphan;
//! * the BIRTH: a segment is made, locked and sized under a staging name and only
//!   then linked to its protocol name, so no sweep ever finds it unlocked;
//! * the LIFETIME: every segment object is entered in the process's registry
//!   (`lifetime`), whose first entry sweeps the orphans and whose exit stage
//!   removes what no other process holds, as upstream's `Cleanup` does.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use memmap2::{Mmap, MmapMut, MmapOptions};

use super::SEGMENT_DEDICATE_TRIES;

mod lifetime;
use lifetime::Registration;

/// The `/dev/shm` path upstream's `shm_open("{id}.zenoh", ..)` resolves to.
/// This name IS interop: a foreign peer opens exactly this string.
pub fn segment_path(id: u64) -> PathBuf {
    PathBuf::from(format!("/dev/shm/{id}.zenoh"))
}

/// The extension of a staging name. It is not `zenoh`, so no sweep of the segment
/// protocol, upstream's included, reads a staging name as a segment's.
const STAGING_EXTENSION: &str = "zenoh-staging";

/// Per-process counter of staging names: with the pid it makes each one unique.
static STAGING_SEQ: AtomicU64 = AtomicU64::new(0);

/// Where process `pid` makes its `seq`-th segment before publishing it.
fn staging_path(pid: u32, seq: u64) -> PathBuf {
    PathBuf::from(format!("/dev/shm/{pid}-{seq}.{STAGING_EXTENSION}"))
}

/// A name in `/dev/shm` the sweep judges.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SweptName {
    /// A segment's protocol name, `{id}.zenoh`.
    Segment(u64),
    /// A staging name of process `pid`: one a creator that died before publishing left
    /// behind, or one a live creator is still publishing.
    Staging { pid: u32 },
}

/// What `path` is to the sweep, or `None` for a name it leaves alone.
#[cfg(target_os = "linux")]
fn swept_name(path: &Path) -> Option<SweptName> {
    let stem = path.file_stem()?.to_str()?;
    match path.extension()?.to_str()? {
        "zenoh" => stem.parse().ok().map(SweptName::Segment),
        STAGING_EXTENSION => {
            let (pid, seq) = stem.split_once('-')?;
            seq.parse::<u64>().ok()?;
            Some(SweptName::Staging {
                pid: pid.parse().ok()?,
            })
        }
        _ => None,
    }
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
/// whose stem is a `u64` and removes the ones that are DANGLING: openable with
/// an EXCLUSIVE non-blocking
/// `flock` (`commons/zenoh-shm/src/shm/unix.rs` @ `.try_lock(FileLockMode::Exclusive)`). Every live
/// holder, wz's included, keeps the SHARED lock `lock_shared` takes for as
/// long as it maps the segment, so an exclusive lock succeeds exactly when no
/// one does. Any open error (a segment of another user, say) keeps the
/// segment, as upstream's does. The staging names of creators that died before
/// publishing are judged by the same lock; this process's own are left alone,
/// because each is a create still running.
///
/// Best-effort and silent, as upstream's is: it runs from exit paths where no
/// error has anywhere to go. A no-op off Linux, where upstream's is too.
pub fn cleanup_orphaned_segments() {
    #[cfg(target_os = "linux")]
    {
        let own = SweptName::Staging {
            pid: std::process::id(),
        };
        cleanup_orphaned_segments_where(|name| name != own);
    }
}

/// [`cleanup_orphaned_segments`] over the names `wanted` accepts.
///
/// R3040 -- a test that ran the whole sweep could not be left alone in a process
/// whose other tests made segments, because a segment then existed for an instant
/// before the shared lock that marks it held, and the sweep removed it in that
/// instant (MEASURED: the test beside it failed opening its own segment with
/// `NotFound`). `OwnedSegment::create` now publishes a segment only once it is
/// locked, but a test still writes unlocked files by hand to stand in for other
/// processes, so a test that watches the sweep decide names the ids it owns.
#[cfg(target_os = "linux")]
fn cleanup_orphaned_segments_where(wanted: impl Fn(SweptName) -> bool) {
    let Ok(entries) = std::fs::read_dir("/dev/shm") else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let Some(name) = swept_name(&path) else {
            continue;
        };
        if wanted(name) {
            remove_if_dangling(&path);
        }
    }
}

/// Remove the object at `path` when no process holds it — upstream's
/// `is_dangling_segment` and `cleanup_segment`
/// (`commons/zenoh-shm/src/shm/unix.rs` @ `fn is_dangling_segment(id: ID) -> bool {`).
///
/// The name is removed while the exclusive lock is held and only if it still names
/// the object locked: between the listing and the removal the object may have gone
/// and a new segment been published under the same name, and that one is live.
#[cfg(target_os = "linux")]
fn remove_if_dangling(path: &Path) {
    use std::os::unix::fs::MetadataExt;

    let Ok(file) = OpenOptions::new().read(true).write(true).open(path) else {
        return;
    };
    // SAFETY: `flock` takes a borrowed fd and returns an error code; the fd is
    // valid for the borrow, and the lock it may take is released when `file`
    // closes at the end of this function.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return;
    }
    let (Ok(locked), Ok(named)) = (file.metadata(), std::fs::metadata(path)) else {
        return;
    };
    if (locked.dev(), locked.ino()) == (named.dev(), named.ino()) {
        let _ = std::fs::remove_file(path);
    }
}

/// A segment THIS process created: mapped read-write, and unlinked on drop.
///
/// The file is held so the shared lock lives as long as the segment does —
/// `flock` locks are released when the last fd for the open file closes.
pub struct OwnedSegment {
    /// Taken from `as_mut_ptr` at creation, so it carries the right to write; the
    /// mapping it points into lives exactly as long as `map`. A POOL's chunks are
    /// written through this and never through a reference to `map`: they are disjoint
    /// ranges written by different holders at once, which a `&mut [u8]` over the whole
    /// mapping would claim nobody else does.
    base: *mut u8,
    map: MmapMut,
    id: u64,
    path: PathBuf,
    _registration: Registration,
    _file: File,
}

// SAFETY: `base` points into `map`, which this value owns and which is `Send`; the pointer
// is only ever handed out as a raw pointer whose uses are the caller's.
unsafe impl Send for OwnedSegment {}
// SAFETY: as for `Send`; sharing the value shares the address of a mapping that is itself
// shared memory, and nothing reached through `&self` writes it except through `base`, whose
// callers own disjoint ranges.
unsafe impl Sync for OwnedSegment {}

impl OwnedSegment {
    /// Create a segment of `len` bytes under the first free id `next_id`
    /// yields, trying at most [`SEGMENT_DEDICATE_TRIES`] of them. The new
    /// segment is zero-filled (`ftruncate` of a fresh object).
    ///
    /// The object is made under a staging name, locked and sized there, and only
    /// then given its protocol name by a hard link, which refuses a name that is
    /// taken as `O_EXCL` does. Upstream creates under the protocol name and locks
    /// after, so a sweep that runs in between (every process sweeps at its first
    /// segment and at exit) reads the new segment as an orphan and removes it;
    /// published this way, the name never names an unlocked object.
    pub fn create(len: usize, mut next_id: impl FnMut() -> u64) -> io::Result<Self> {
        let mut last_err = None;
        for _ in 0..SEGMENT_DEDICATE_TRIES {
            let id = next_id();
            let staging = staging_path(
                std::process::id(),
                STAGING_SEQ.fetch_add(1, Ordering::Relaxed),
            );
            let file = match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&staging)
            {
                Ok(file) => file,
                // A staging name a dead process of the same pid left: take the next one.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    last_err = Some(e);
                    continue;
                }
                Err(e) => return Err(e),
            };
            let path = segment_path(id);
            let published = lock_shared(&file)
                .and_then(|()| file.set_len(len as u64))
                .and_then(|()| std::fs::hard_link(&staging, &path));
            let _ = std::fs::remove_file(&staging);
            match published {
                Ok(()) => return Self::adopt(file, id, path),
                // The id is taken (`AlreadyExists`), or another process's sweep judged
                // the staging name before it was locked: holding it (`WouldBlock`) or
                // having removed it (`NotFound` from the link). Each is another try.
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::AlreadyExists
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::NotFound
                    ) =>
                {
                    last_err = Some(e)
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::other(format!(
                "could not dedicate a POSIX shm segment after {SEGMENT_DEDICATE_TRIES} tries"
            ))
        }))
    }

    /// Map the segment just published as `path` and enter it in the process's
    /// registry. When either fails the name is taken back, so a failed create
    /// publishes nothing.
    fn adopt(file: File, id: u64, path: PathBuf) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let mapped = file.metadata().and_then(|meta| {
            // SAFETY: the file was just created exclusively by this
            // process, and this mapping is the only writer it makes.
            let map = unsafe { MmapOptions::new().map_mut(&file) }?;
            Ok((meta, map))
        });
        let (meta, mut map) = match mapped {
            Ok(mapped) => mapped,
            Err(e) => {
                let _ = std::fs::remove_file(&path);
                return Err(e);
            }
        };
        let base = map.as_mut_ptr();
        let registration = Registration::new(id, &file, (meta.dev(), meta.ino()));
        Ok(Self {
            base,
            map,
            id,
            path,
            _registration: registration,
            _file: file,
        })
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

    /// The segment's first byte, as a pointer that may be written through. Valid for
    /// [`Self::len`] bytes for as long as `self` lives. This is how a chunk of a pool is
    /// reached: by an address into the mapping, not by a reference to all of it.
    pub fn base(&self) -> *mut u8 {
        self.base
    }

    /// The segment's size in bytes.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the segment is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
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
    id: u64,
    /// Which object this mapping is of: the device and inode the open file had. A segment name
    /// can be reused after its owner exits, so a holder that keeps the mapping for reuse asks
    /// [`Self::is_current`] before it trusts one.
    identity: (u64, u64),
    _registration: Registration,
    _file: File,
}

impl PeerSegment {
    /// Open the segment named by `id`. An error — never a panic — when it does
    /// not exist or cannot be locked or mapped: to a caller that is "this peer
    /// holds no such segment", which is an ordinary outcome of shared memory.
    pub fn open(id: u64) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(segment_path(id))?;
        lock_shared(&file)?;
        let meta = file.metadata()?;
        // SAFETY: a read-only view of a peer-owned mapping. The peer may write
        // it concurrently, which is the shared-memory contract; every reader of
        // this view reads fields whose torn value fails a comparison rather
        // than being unsound.
        let map = unsafe { MmapOptions::new().map(&file)? };
        let identity = (meta.dev(), meta.ino());
        Ok(Self {
            map,
            id,
            identity,
            _registration: Registration::new(id, &file, identity),
            _file: file,
        })
    }

    /// The segment's bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.map
    }

    /// Whether the name this segment was opened by still names the same object: false once its
    /// owner has unlinked it, or unlinked it and another process has made a new segment under
    /// the same id. The twin of [`PeerSegmentRw::is_current`].
    pub fn is_current(&self) -> bool {
        use std::os::unix::fs::MetadataExt;

        std::fs::metadata(segment_path(self.id))
            .map(|m| (m.dev(), m.ino()) == self.identity)
            .unwrap_or(false)
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
    id: u64,
    /// Which object this mapping is of: the device and inode the open file had.
    /// A segment name can be reused after its owner exits, and a mapping of the
    /// old object would read a dead provider's headers as if they were live.
    identity: (u64, u64),
    _map: MmapMut,
    _registration: Registration,
    _file: File,
}

// SAFETY: `ptr` points into `_map`, which this value owns and which is `Send`; the
// pointer is only ever handed out as a raw pointer whose uses are the caller's, and
// every field reached through it is an atomic.
unsafe impl Send for PeerSegmentRw {}
// SAFETY: as for `Send`; sharing the value shares the address of a mapping that is
// itself shared memory, and nothing here reads or writes it.
unsafe impl Sync for PeerSegmentRw {}

impl PeerSegmentRw {
    /// Open the segment named by `id`. An error, never a panic, when it does not
    /// exist or cannot be locked or mapped, as for [`PeerSegment::open`].
    pub fn open(id: u64) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(segment_path(id))?;
        lock_shared(&file)?;
        let meta = file.metadata()?;
        // SAFETY: a writable view of a peer-owned mapping. The peer and this
        // process both write it concurrently, which is the shared-memory
        // contract; every field a caller reaches through it is an atomic.
        let mut map = unsafe { MmapOptions::new().map_mut(&file)? };
        let ptr = map.as_mut_ptr();
        let len = map.len();
        let identity = (meta.dev(), meta.ino());
        Ok(Self {
            ptr,
            len,
            id,
            identity,
            _map: map,
            _registration: Registration::new(id, &file, identity),
            _file: file,
        })
    }

    /// Whether the name this segment was opened by still names the same object.
    ///
    /// False once its owner has unlinked it, or unlinked it and another process
    /// has made a new segment under the same id. A holder that keeps a mapping
    /// for reuse asks this before it trusts one.
    pub fn is_current(&self) -> bool {
        use std::os::unix::fs::MetadataExt;

        std::fs::metadata(segment_path(self.id))
            .map(|m| (m.dev(), m.ino()) == self.identity)
            .unwrap_or(false)
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
    use super::super::next_candidate_id;
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

        // Scoped to the two ids this test owns: the whole-directory sweep would also
        // judge the files other tests write by hand to stand in for other processes.
        let held_id = held.id();
        cleanup_orphaned_segments_where(|name| {
            name == SweptName::Segment(orphan_id) || name == SweptName::Segment(held_id)
        });

        assert!(!orphan.exists(), "a segment no process holds is removed");
        assert!(held_path.exists(), "a segment this process holds is kept");
        drop(held);
        assert!(!held_path.exists(), "and its own drop still unlinks it");
    }

    /// The sweep reads a segment's name and a staging name, and nothing else in
    /// `/dev/shm`: a file of another program is not judged at all.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_sweep_reads_segment_and_staging_names_and_nothing_else() {
        let name = |path: &str| swept_name(Path::new(path));
        assert_eq!(name("/dev/shm/123.zenoh"), Some(SweptName::Segment(123)));
        assert_eq!(
            swept_name(&staging_path(42, 7)),
            Some(SweptName::Staging { pid: 42 })
        );
        assert_eq!(name("/dev/shm/123.wz"), None);
        assert_eq!(name("/dev/shm/abc.zenoh"), None);
        assert_eq!(name("/dev/shm/42.zenoh-staging"), None);
        assert_eq!(name("/dev/shm/42-x.zenoh-staging"), None);
    }

    /// A staging name a creator left when it died before publishing is swept, and
    /// one a live creator holds is kept. The pids are above any pid Linux hands
    /// out, and the sequence number is this process's pid, so the names are this
    /// test's alone.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_dead_creators_staging_name_is_swept_and_a_held_one_is_kept() {
        // The process's first segment sweeps the whole directory; made here, that
        // sweep is over before the live name below exists unlocked for an instant.
        let _first = OwnedSegment::create(64, || u64::from(next_candidate_id())).expect("create");
        let seq = u64::from(std::process::id());
        let dead = staging_path(u32::MAX, seq);
        let live = staging_path(u32::MAX - 1, seq);
        std::fs::write(&dead, [0u8; 64]).expect("leave a dead creator's staging name");
        std::fs::write(&live, [0u8; 64]).expect("make a live creator's staging name");
        let holder = File::options()
            .read(true)
            .write(true)
            .open(&live)
            .expect("open the live staging name");
        lock_shared(&holder).expect("the live creator's lock");

        cleanup_orphaned_segments_where(|name| {
            name == SweptName::Staging { pid: u32::MAX }
                || name == SweptName::Staging { pid: u32::MAX - 1 }
        });

        assert!(
            !dead.exists(),
            "a dead creator's staging name outlived the sweep"
        );
        assert!(
            live.exists(),
            "the sweep removed a staging name a creator holds"
        );
        drop(holder);
        std::fs::remove_file(&live).expect("clean up");
    }

    /// A created segment is published already locked and sized: an exclusive lock
    /// on its name, which is what every sweep tries, is refused.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_created_segment_is_published_locked() {
        let segment = OwnedSegment::create(64, || u64::from(next_candidate_id())).expect("create");
        let path = segment_path(segment.id());
        let probe = File::options()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open the published name");
        // SAFETY: `flock` takes a borrowed fd and returns an error code.
        let rc = unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_ne!(
            rc, 0,
            "a sweep could take the exclusive lock of a live segment"
        );
        assert_eq!(std::fs::metadata(&path).expect("metadata").len(), 64);
    }

    /// A create whose first id is taken publishes under the next one and leaves the
    /// segment that held the first id as it was.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_create_whose_id_is_taken_takes_the_next_and_leaves_the_holder() {
        let holder = OwnedSegment::create(64, || u64::from(next_candidate_id())).expect("create");
        let taken = holder.id();
        let free = u64::from(next_candidate_id());
        let mut ids = [taken, free].into_iter();
        let segment = OwnedSegment::create(32, || ids.next().expect("two ids are enough"))
            .expect("create past a taken id");
        assert_eq!(segment.id(), free);
        assert_eq!(segment.len(), 32);
        assert_eq!(
            std::fs::metadata(segment_path(taken))
                .expect("the holder's name")
                .len(),
            64,
            "the create touched the segment that held the taken id"
        );
    }

    /// R3039 -- a cached mapping is trusted only while its name still names the
    /// object it was opened as: true while its owner holds the segment, false once
    /// the owner has unlinked it, and false again if another segment is made under
    /// the same id (a new inode), which is the case a reader that keeps a mapping
    /// must not read a dead provider's headers through.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_mapping_is_current_only_while_its_name_names_its_object() {
        let owner = OwnedSegment::create(64, || u64::from(next_candidate_id())).expect("create");
        let id = owner.id();
        let peer = PeerSegmentRw::open(id).expect("open writable");
        assert!(peer.is_current(), "the owner still holds the segment");
        assert_eq!(peer.len(), 64);

        drop(owner);
        assert!(!peer.is_current(), "the owner unlinked it");

        // The same id, made again: a different object under the same name. A real
        // segment rather than a file written by hand, so no sweep can take it.
        let successor = OwnedSegment::create(64, || id).expect("make another segment of that id");
        assert!(
            !peer.is_current(),
            "the name now names a different inode, so the mapping is of a dead object"
        );
        drop(successor);
    }

    /// The read-only mapping of a DATA segment is trusted on the same terms as the writable one of
    /// a metadata segment: while its name names its object, and not after the owner unlinks it or
    /// another segment is made under the same id.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_read_only_mapping_is_current_only_while_its_name_names_its_object() {
        let owner = OwnedSegment::create(64, || u64::from(next_candidate_id())).expect("create");
        let id = owner.id();
        let peer = PeerSegment::open(id).expect("open read-only");
        assert!(peer.is_current(), "the owner still holds the segment");

        drop(owner);
        assert!(!peer.is_current(), "the owner unlinked it");

        let successor = OwnedSegment::create(64, || id).expect("make another segment of that id");
        assert!(
            !peer.is_current(),
            "the name now names a different inode, so the mapping is of a dead object"
        );
        drop(successor);
    }
}
