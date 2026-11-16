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
//!   removes what no other process holds, as upstream's `Cleanup` does;
//! * the LAST HOLDER OUT: an object that lets go of a segment removes its name
//!   only when it can take the exclusive lock, so the name lives for as long as
//!   anyone maps the object, creator or reader, as upstream's
//!   (`commons/zenoh-shm/src/shm/unix.rs` @ `impl<ID: SegmentID> Drop for SegmentImpl<ID> {`);
//! * the PROVIDER'S LIVENESS: a reader that keeps a mapping can no longer learn
//!   that its provider is gone from the name, so the provider holds a second
//!   lock for as long as it lives and a reader asks whether anyone holds it.
//!
//! # The liveness lock, and why it is not a watchdog bit
//!
//! Upstream's watchdog runs the other way: holders confirm a bit every 50 ms and
//! the PROVIDER validates it, so the provider learns that its holders died
//! (`commons/zenoh-shm/src/watchdog/confirmator.rs` @
//! `WatchdogConfirmator::new(Duration::from_millis(50));`), and a reader keeps a
//! segment it mounted for its own whole life
//! (`commons/zenoh-shm/src/reader.rs` @ `// fastest path: try to get access to already mounted SHM segment`).
//! wz's readers let go of a dead provider's segments, which needs the reverse
//! signal, and a bit of the provider's in the segment would move the segment
//! layout a zenoh peer reads. The kernel keeps that signal without one: the
//! provider takes an open-file-description read lock on the segment's first
//! byte (`F_OFD_SETLK`), the kernel holds it exactly as long as the provider's
//! file is open, through a crash too, and a reader in ANY process asks with
//! `F_OFD_GETLK` whether some other open file holds it. Record locks and the
//! `flock` the segment protocol uses do not see each other, so a zenoh peer's
//! protocol is untouched. Only wz providers take the lock, so a reader trusts
//! its absence only for a segment it found locked when it opened it; a segment
//! a zenoh provider made, or one made where the lock cannot be taken, keeps
//! being judged by its name.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
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

/// The record-lock range of the provider's liveness lock, the segment's first
/// byte, with the lock type `kind`.
#[cfg(target_os = "linux")]
fn liveness_range(kind: libc::c_int) -> libc::flock {
    // SAFETY: `flock` is a plain C struct of integers, for which all-zero is a value.
    let mut range: libc::flock = unsafe { std::mem::zeroed() };
    range.l_type = kind as libc::c_short;
    range.l_whence = libc::SEEK_SET as libc::c_short;
    range.l_start = 0;
    range.l_len = 1;
    range
}

/// Take the provider's liveness lock on `file`, held for as long as this open file
/// lives (its descriptors and its mappings). Best-effort: a kernel that refuses it leaves a segment
/// its readers judge by its name, which is how they judge a zenoh provider's.
fn hold_liveness(file: &File) {
    #[cfg(target_os = "linux")]
    {
        let range = liveness_range(libc::F_RDLCK);
        // SAFETY: `fcntl` reads the `flock` the pointer names for the length of the
        // call; the descriptor is valid for the borrow of `file`.
        let _ = unsafe {
            libc::fcntl(
                file.as_raw_fd(),
                libc::F_OFD_SETLK,
                &range as *const libc::flock,
            )
        };
    }
    #[cfg(not(target_os = "linux"))]
    let _ = file;
}

/// Whether some open file other than `file` holds the segment's liveness lock:
/// `Some(true)` its provider lives, `Some(false)` no provider holds it, `None`
/// when the kernel could not be asked.
fn provider_holds_liveness(file: &File) -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        let mut probe = liveness_range(libc::F_WRLCK);
        // SAFETY: `fcntl` reads and writes the `flock` the pointer names for the
        // length of the call; the descriptor is valid for the borrow of `file`.
        let rc = unsafe {
            libc::fcntl(
                file.as_raw_fd(),
                libc::F_OFD_GETLK,
                &mut probe as *mut libc::flock,
            )
        };
        if rc != 0 {
            return None;
        }
        Some(probe.l_type != libc::F_UNLCK as libc::c_short)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
        None
    }
}

/// Remove the name `path` when no one but `file`'s holder holds the object and
/// the name still names it: upstream's rule for a segment its holder lets go of
/// (`commons/zenoh-shm/src/shm/unix.rs` @ `impl<ID: SegmentID> Drop for SegmentImpl<ID> {`).
///
/// The exclusive lock is asked of `file`'s own open file, so this holder's shared
/// lock does not stand in its way and any other holder's does. On Linux a refused
/// conversion also drops the shared lock, which is why only a holder about to close
/// its file asks.
fn remove_if_unshared(file: &File, path: &Path) {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: `flock` takes a borrowed fd and returns an error code; the fd is
    // valid for the borrow of `file`.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return;
    }
    let (Ok(held), Ok(named)) = (file.metadata(), std::fs::metadata(path)) else {
        return;
    };
    if (held.dev(), held.ino()) == (named.dev(), named.ino()) {
        let _ = std::fs::remove_file(path);
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
    // The lock `remove_if_unshared` may take is released when `file` closes at
    // the end of this function.
    if let Ok(file) = OpenOptions::new().read(true).write(true).open(path) {
        remove_if_unshared(&file, path);
    }
}

/// A segment THIS process created: mapped read-write, and unlinked by the last
/// holder to let go of it, this value or a reader.
///
/// The file is held so the shared lock and the liveness lock live as long as the
/// segment does — both belong to the open file, which goes when its last fd is
/// closed and its last mapping unmapped, and both go with it.
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
                .map(|()| hold_liveness(&file))
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
        // A reader that still maps the segment keeps its name, and removes it
        // when it lets go last. Its liveness lock goes when the file closes right
        // after, which is how that reader learns this provider is gone.
        remove_if_unshared(&self._file, &self.path);
    }
}

/// One segment object: the id it was opened under and the device and inode of
/// the object. A holder that saw an object's provider go remembers it by this,
/// because the same id may later name another object.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SegmentObject {
    id: u64,
    identity: (u64, u64),
}

impl SegmentObject {
    /// Whether the object's id still names it.
    pub fn is_named(&self) -> bool {
        names_object(self.id, self.identity)
    }
}

/// Whether the name of segment `id` still names the object of `identity`.
fn names_object(id: u64, identity: (u64, u64)) -> bool {
    use std::os::unix::fs::MetadataExt;

    std::fs::metadata(segment_path(id))
        .map(|meta| (meta.dev(), meta.ino()) == identity)
        .unwrap_or(false)
}

/// A segment ANOTHER process created, opened by id and mapped read-only.
pub struct PeerSegment {
    map: Mmap,
    id: u64,
    /// Which object this mapping is of: the device and inode the open file had. A segment name
    /// can be reused after its owner exits, so a holder that keeps the mapping for reuse asks
    /// [`Self::is_current`] before it trusts one.
    identity: (u64, u64),
    /// Whether the provider held its liveness lock when this was opened, which is
    /// what lets the lock's absence later mean the provider is gone.
    signalled: bool,
    _registration: Registration,
    _file: File,
}

impl Drop for PeerSegment {
    fn drop(&mut self) {
        remove_if_unshared(&self._file, &segment_path(self.id));
    }
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
            signalled: provider_holds_liveness(&file) == Some(true),
            _registration: Registration::new(id, &file, identity),
            _file: file,
        })
    }

    /// The segment's bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.map
    }

    /// Whether the provider of this segment is still there: its name still names
    /// this object, and, when the provider signalled its liveness at open, it
    /// still does. The question a holder that keeps the mapping for reuse asks
    /// before it trusts one. The twin of [`PeerSegmentRw::provider_is_live`].
    pub fn provider_is_live(&self) -> bool {
        let lapsed = self.signalled && provider_holds_liveness(&self._file) == Some(false);
        self.is_current() && !lapsed
    }

    /// The object this maps.
    pub fn object(&self) -> SegmentObject {
        SegmentObject {
            id: self.id,
            identity: self.identity,
        }
    }

    /// Whether the name this segment was opened by still names the same object: false once the
    /// last holder has unlinked it, or unlinked it and another process has made a new segment
    /// under the same id. The twin of [`PeerSegmentRw::is_current`].
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
    /// Whether the provider held its liveness lock when this was opened.
    signalled: bool,
    _map: MmapMut,
    _registration: Registration,
    _file: File,
}

impl Drop for PeerSegmentRw {
    fn drop(&mut self) {
        remove_if_unshared(&self._file, &segment_path(self.id));
    }
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
            signalled: provider_holds_liveness(&file) == Some(true),
            _map: map,
            _registration: Registration::new(id, &file, identity),
            _file: file,
        })
    }

    /// Whether the name this segment was opened by still names the same object.
    ///
    /// False once the last holder has unlinked it, or unlinked it and another
    /// process has made a new segment under the same id.
    pub fn is_current(&self) -> bool {
        use std::os::unix::fs::MetadataExt;

        std::fs::metadata(segment_path(self.id))
            .map(|m| (m.dev(), m.ino()) == self.identity)
            .unwrap_or(false)
    }

    /// Whether the provider of this segment is still there, as
    /// [`PeerSegment::provider_is_live`] judges it. A holder that keeps a mapping
    /// for reuse asks this before it trusts one: a mapping of a dead provider's
    /// metadata would read its headers as if they were live.
    pub fn provider_is_live(&self) -> bool {
        let lapsed = self.signalled && provider_holds_liveness(&self._file) == Some(false);
        self.is_current() && !lapsed
    }

    /// The object this maps.
    pub fn object(&self) -> SegmentObject {
        SegmentObject {
            id: self.id,
            identity: self.identity,
        }
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

    /// R3039 -- a kept mapping is trusted only while its provider is live, and a
    /// reader learns the provider is gone from its liveness lock, not from the
    /// name: the name outlives the provider for as long as the reader maps it,
    /// and no other segment can take the id meanwhile. The reader that lets go
    /// last removes the name.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_mapping_is_trusted_only_while_its_provider_is_live() {
        let owner = OwnedSegment::create(64, || u64::from(next_candidate_id())).expect("create");
        let id = owner.id();
        let peer = PeerSegmentRw::open(id).expect("open writable");
        assert!(
            peer.provider_is_live(),
            "the provider still holds the segment"
        );
        assert_eq!(peer.len(), 64);

        drop(owner);
        assert!(
            !peer.provider_is_live(),
            "a reader did not see its provider go"
        );
        assert!(
            peer.is_current(),
            "the provider's drop removed a name a reader still maps"
        );
        assert!(
            OwnedSegment::create(64, || id).is_err(),
            "another segment took an id a reader still maps"
        );

        drop(peer);
        assert!(
            !segment_path(id).exists(),
            "the last holder to let go left the name"
        );
    }

    /// The read-only mapping of a DATA segment is trusted on the same terms as the
    /// writable one of a metadata segment.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_read_only_mapping_is_trusted_only_while_its_provider_is_live() {
        let owner = OwnedSegment::create(64, || u64::from(next_candidate_id())).expect("create");
        let id = owner.id();
        let peer = PeerSegment::open(id).expect("open read-only");
        assert!(
            peer.provider_is_live(),
            "the provider still holds the segment"
        );

        drop(owner);
        assert!(
            !peer.provider_is_live(),
            "a reader did not see its provider go"
        );
        assert!(
            peer.is_current(),
            "the provider's drop removed a name a reader still maps"
        );

        drop(peer);
        assert!(
            !segment_path(id).exists(),
            "the last holder to let go left the name"
        );
    }

    /// Two readers stand in for two processes (a lock belongs to an open file, so
    /// two open files conflict within one process as across two): each sees the
    /// provider go on its own, neither's drop takes the name from the other, and
    /// the last one out removes it.
    #[cfg(target_os = "linux")]
    #[test]
    fn every_reader_sees_the_provider_go_and_the_last_one_out_removes_the_name() {
        let owner = OwnedSegment::create(64, || u64::from(next_candidate_id())).expect("create");
        let id = owner.id();
        let first = PeerSegment::open(id).expect("one reader");
        let second = PeerSegmentRw::open(id).expect("another reader");

        drop(owner);
        assert!(!first.provider_is_live(), "the first reader did not see it");
        assert!(
            !second.provider_is_live(),
            "the second reader did not see it"
        );

        drop(first);
        assert!(
            segment_path(id).exists(),
            "a reader's drop removed a name another reader maps"
        );
        drop(second);
        assert!(
            !segment_path(id).exists(),
            "the last holder to let go left the name"
        );
    }

    /// A provider that never signals its liveness, as a zenoh provider does not,
    /// is judged by its name: alive while the name names its object. A file locked
    /// by hand stands in for it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_provider_that_signals_nothing_is_judged_by_its_name() {
        // The process's first segment sweeps the whole directory; made here, that
        // sweep is over before the stand-in below exists unlocked for an instant.
        let _first = OwnedSegment::create(64, || u64::from(next_candidate_id())).expect("create");
        let id = (1u64 << 42) + u64::from(std::process::id());
        let path = segment_path(id);
        std::fs::write(&path, [0u8; 64]).expect("the stand-in provider's segment");
        let provider = File::options()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open the stand-in");
        lock_shared(&provider).expect("the stand-in's shared lock");

        let peer = PeerSegment::open(id).expect("open read-only");
        assert!(
            peer.provider_is_live(),
            "a provider that never signalled was read as gone"
        );
        std::fs::remove_file(&path).expect("the stand-in leaves");
        assert!(
            !peer.provider_is_live(),
            "a name that no longer names the object was trusted"
        );
        drop(peer);
        drop(provider);
    }

    /// The owner's drop keeps a name a reader maps, and removes the name of a
    /// segment no one else maps.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_owner_removes_the_name_only_when_no_one_else_maps_it() {
        let alone = OwnedSegment::create(64, || u64::from(next_candidate_id())).expect("create");
        let alone_path = segment_path(alone.id());
        drop(alone);
        assert!(
            !alone_path.exists(),
            "an unshared segment outlived its owner"
        );

        let owner = OwnedSegment::create(64, || u64::from(next_candidate_id())).expect("create");
        let path = segment_path(owner.id());
        let reader = PeerSegment::open(owner.id()).expect("open read-only");
        drop(owner);
        assert!(path.exists(), "the owner removed a name a reader maps");
        drop(reader);
        assert!(!path.exists(), "the reader, last out, left the name");
    }
}
