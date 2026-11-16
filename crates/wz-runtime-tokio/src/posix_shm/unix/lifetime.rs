// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The process's segment registry: what upstream's `Cleanup` does for the segments of one
//! process.
//!
//! * The FIRST segment this process creates or opens sweeps `/dev/shm` of the orphans a
//!   crashed process left
//!   (`commons/zenoh-shm/src/cleanup.rs` @ `// on first cleanup subsystem touch we perform zenoh segment cleanup`).
//!   Upstream reaches it from both `Segment::create` and `Segment::open`
//!   (`commons/zenoh-shm/src/posix_shm/segment.rs` @ `CLEANUP.read().register_cleanup(id);`),
//!   after the segment exists, and so does this registry.
//! * At a clean exit the process sweeps again and removes each segment it still holds that
//!   no other process holds
//!   (`commons/zenoh-shm/src/cleanup.rs` @ `// on finalization stage we perform zenoh segment cleanup`,
//!   then `commons/zenoh-shm/src/shm/unix.rs` @ `pub fn ensure_not_persistent(id: ID) {`
//!   per registered id).
//!
//! Upstream's exit stage is the drop of a lazily made static
//! (`commons/zenoh-shm/src/cleanup.rs` @ `#[dynamic(lazy, drop)]`). Rust statics are never
//! dropped, and the segments wz keeps in statics keep their files, and so their shared
//! locks, open past `main`. So the exit stage here is an `atexit` handler that releases this
//! process's own locks first and then asks, per segment, whether an exclusive lock can be
//! taken: the question upstream's dangling test asks, answered for the segments upstream's
//! static drops would already have closed.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use super::{names_object, segment_path};

/// One live segment object of this process.
struct Held {
    id: u64,
    /// The object's own descriptor. Read only under the registry's lock, and an object leaves
    /// the registry (its `Registration` drops) before its file closes, so the descriptor
    /// read here is never one that was closed and reused.
    fd: RawFd,
    /// The device and inode the object mapped. A name reused after its owner exited names
    /// another object, and the exit stage removes a name only when it still names this one.
    identity: (u64, u64),
}

/// The segments this process holds, by the token each holder was given.
struct Registry {
    held: Mutex<BTreeMap<u64, Held>>,
    next_token: AtomicU64,
    /// The process the table belongs to. A child made by `fork` inherits the table and
    /// the open files in it, which are the PARENT's open files: its exit stage letting go
    /// of their locks and unlinking what then looks unheld would take live segments from
    /// the parent, so a child's exit stage leaves them alone.
    owner_pid: u32,
}

impl Registry {
    /// A registry made at the first touch of the subsystem, which runs `sweep` first.
    fn opened_with(sweep: impl FnOnce()) -> Self {
        sweep();
        Self {
            held: Mutex::new(BTreeMap::new()),
            next_token: AtomicU64::new(0),
            owner_pid: std::process::id(),
        }
    }

    /// The table, also after a holder panicked while holding it: the table is only inserted
    /// into and removed from, so a poisoned one is still whole.
    fn held(&self) -> MutexGuard<'_, BTreeMap<u64, Held>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn register(&self, id: u64, fd: RawFd, identity: (u64, u64)) -> u64 {
        let token = self.next_token.fetch_add(1, Ordering::Relaxed);
        self.held().insert(token, Held { id, fd, identity });
        token
    }

    fn unregister(&self, token: u64) {
        self.held().remove(&token);
    }

    /// The exit stage for the segments this process still holds: remove each one no other
    /// process holds, and leave the rest to their holders.
    ///
    /// Every lock of this process is let go first, because two objects of one process
    /// holding one segment (a provider and a reader of its own metadata, say) would
    /// otherwise each refuse the other's exclusive lock and the segment would outlive them
    /// both. The table is emptied, so a second run finds nothing, and its lock is kept until
    /// the end, so no holder's file closes under a descriptor read here.
    fn release_unshared(&self) {
        if std::process::id() != self.owner_pid {
            return;
        }
        let mut table = self.held();
        let held = std::mem::take(&mut *table);
        for entry in held.values() {
            // SAFETY: `flock` takes a descriptor and returns a code; `entry.fd` is open while
            // the table's lock is held (see `Held::fd`).
            unsafe { libc::flock(entry.fd, libc::LOCK_UN) };
        }
        let mut judged = BTreeSet::new();
        for entry in held.values() {
            if !judged.insert((entry.id, entry.identity)) {
                continue;
            }
            // SAFETY: as above.
            let alone = unsafe { libc::flock(entry.fd, libc::LOCK_EX | libc::LOCK_NB) } == 0;
            if alone && names_object(entry.id, entry.identity) {
                let _ = std::fs::remove_file(segment_path(entry.id));
            }
        }
        drop(table);
    }

    /// Whether some live object of this process holds segment `id`.
    #[cfg(all(test, target_os = "linux"))]
    fn holds(&self, id: u64) -> bool {
        self.held().values().any(|entry| entry.id == id)
    }
}

static REGISTRY: OnceLock<Registry> = OnceLock::new();

/// The process's registry, made at the first call: that call sweeps the orphans and arms
/// the exit stage.
fn registry() -> &'static Registry {
    REGISTRY.get_or_init(|| {
        let registry = Registry::opened_with(super::cleanup_orphaned_segments);
        // SAFETY: `release_at_exit` takes nothing, returns nothing and does not unwind out.
        // A refusal (the table of exit handlers is full) costs only the exit stage; the next
        // process's first touch still sweeps what this one leaves.
        let _ = unsafe { libc::atexit(release_at_exit) };
        registry
    })
}

/// The exit stage, in upstream's order: the orphans first, then this process's own.
extern "C" fn release_at_exit() {
    super::cleanup_orphaned_segments();
    if let Some(registry) = REGISTRY.get() {
        registry.release_unshared();
    }
}

/// A segment object's entry in the process's registry, held as a field declared BEFORE the
/// object's file, so the entry leaves the registry before the file closes.
pub(super) struct Registration {
    token: u64,
}

impl Registration {
    /// Enter segment `id`, mapped from `file` as the object `identity`, in the process's
    /// registry. The first entry of the process is the subsystem's first touch.
    pub(super) fn new(id: u64, file: &File, identity: (u64, u64)) -> Self {
        Self {
            token: registry().register(id, file.as_raw_fd(), identity),
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let Some(registry) = REGISTRY.get() {
            registry.unregister(self.token);
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::super::super::next_candidate_id;
    use super::super::{lock_shared, OwnedSegment, PeerSegment, PeerSegmentRw};
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// The identity a segment object recorded, read back from its file.
    fn identity_of(file: &File) -> (u64, u64) {
        let meta = file.metadata().expect("metadata of a segment's file");
        (meta.dev(), meta.ino())
    }

    /// The registry is made by sweeping: a first touch that did not sweep would leave a
    /// crashed process's segments for good.
    #[test]
    fn the_first_touch_sweeps_before_anything_is_registered() {
        let mut swept = false;
        let registry = Registry::opened_with(|| swept = true);
        assert!(swept, "the registry was made without sweeping");
        assert!(registry.held().is_empty());
    }

    /// Each object that creates or opens a segment is in the process's registry while it
    /// lives, and leaves it when it drops; a second holder of the same id keeps it there.
    #[test]
    fn every_segment_object_is_registered_while_it_lives() {
        let owner = OwnedSegment::create(64, || u64::from(next_candidate_id())).expect("create");
        let id = owner.id();
        assert!(registry().holds(id), "a created segment is not registered");

        let reader = PeerSegment::open(id).expect("open read-only");
        let writer = PeerSegmentRw::open(id).expect("open writable");
        drop(owner);
        assert!(registry().holds(id), "the readers still hold the segment");
        drop(reader);
        assert!(
            registry().holds(id),
            "the writable reader still holds the segment"
        );
        drop(writer);
        assert!(!registry().holds(id), "a dropped object stayed registered");
    }

    /// At exit a segment only this process holds is removed, even while this process still
    /// maps it: nothing else will ever unlink it.
    #[test]
    fn the_exit_stage_removes_a_segment_no_other_process_holds() {
        let owner = OwnedSegment::create(64, || u64::from(next_candidate_id())).expect("create");
        let id = owner.id();
        let registry = Registry::opened_with(|| ());
        registry.register(id, owner._file.as_raw_fd(), identity_of(&owner._file));

        registry.release_unshared();
        assert!(
            !segment_path(id).exists(),
            "a segment no other process holds outlived the exit stage"
        );
        assert!(registry.held().is_empty(), "the exit stage left its table");
    }

    /// Two objects of this process on one segment do not keep it alive at exit by refusing
    /// each other's exclusive lock.
    #[test]
    fn the_exit_stage_removes_a_segment_two_objects_of_this_process_hold() {
        let owner = OwnedSegment::create(64, || u64::from(next_candidate_id())).expect("create");
        let id = owner.id();
        let reader = PeerSegment::open(id).expect("open read-only");
        let registry = Registry::opened_with(|| ());
        registry.register(id, owner._file.as_raw_fd(), identity_of(&owner._file));
        registry.register(id, reader._file.as_raw_fd(), identity_of(&reader._file));

        registry.release_unshared();
        assert!(
            !segment_path(id).exists(),
            "this process's own two holders kept the segment"
        );
    }

    /// A segment another holder still locks is left to it. A second open file stands in for
    /// the other process: `flock` locks belong to an open file, so two of them conflict
    /// within one process as across two.
    #[test]
    fn the_exit_stage_keeps_a_segment_another_holder_locks() {
        let owner = OwnedSegment::create(64, || u64::from(next_candidate_id())).expect("create");
        let id = owner.id();
        let other = File::options()
            .read(true)
            .write(true)
            .open(segment_path(id))
            .expect("open the segment as another holder");
        lock_shared(&other).expect("the other holder's shared lock");
        let registry = Registry::opened_with(|| ());
        registry.register(id, owner._file.as_raw_fd(), identity_of(&owner._file));

        registry.release_unshared();
        assert!(
            segment_path(id).exists(),
            "the exit stage removed a segment another holder locks"
        );
        drop(other);
        drop(owner);
        assert!(!segment_path(id).exists(), "the owner's drop unlinks it");
    }

    /// A table inherited across `fork` is not released by the child: its open files are
    /// the parent's, and so are the segments.
    #[test]
    fn the_exit_stage_of_another_process_releases_nothing() {
        let owner = OwnedSegment::create(64, || u64::from(next_candidate_id())).expect("create");
        let id = owner.id();
        let mut registry = Registry::opened_with(|| ());
        registry.owner_pid = std::process::id().wrapping_add(1);
        registry.register(id, owner._file.as_raw_fd(), identity_of(&owner._file));

        registry.release_unshared();
        assert!(
            segment_path(id).exists(),
            "the exit stage of a forked child removed its parent's segment"
        );
        assert!(
            registry.holds(id),
            "a child's exit stage emptied its parent's table"
        );
        let probe = File::options()
            .read(true)
            .write(true)
            .open(segment_path(id))
            .expect("open the segment");
        // SAFETY: `flock` takes a borrowed fd and returns an error code.
        let rc = unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_ne!(rc, 0, "a child's exit stage let go of its parent's lock");
    }

    /// A name that now names another object is not removed for the object it used to name.
    #[test]
    fn the_exit_stage_keeps_a_name_that_names_another_object() {
        let owner = OwnedSegment::create(64, || u64::from(next_candidate_id())).expect("create");
        let id = owner.id();
        let reader = PeerSegment::open(id).expect("open read-only");
        let registry = Registry::opened_with(|| ());
        registry.register(id, reader._file.as_raw_fd(), identity_of(&reader._file));
        drop(owner);
        // The reader keeps the name; take it from under the reader, as a hand or a
        // foreign sweep could, so another segment can be made under the id.
        std::fs::remove_file(segment_path(id)).expect("take the name");
        let successor = OwnedSegment::create(64, || id).expect("another segment of that id");

        registry.release_unshared();
        assert!(
            segment_path(id).exists(),
            "the exit stage removed the successor of the object it held"
        );
        drop(successor);
        drop(reader);
    }
}
