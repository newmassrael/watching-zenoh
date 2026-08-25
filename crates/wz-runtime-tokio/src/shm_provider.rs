// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The AP POSIX shared-memory provider for the scoped same-host SHM transport
//! (`transport-shm`) — the `std` half of the split (the no_std descriptor +
//! marker codec + the [`ShmResolver`](wz_session_core::extshm::ShmResolver) trait
//! live in `wz-session-core::extshm`).
//!
//! A /dev/shm tmpfs file mmap'd `MAP_SHARED` is exactly POSIX shared memory for
//! same-host peers (the wz analogue of zenoh-shm's `shm_open` + `mmap`,
//! `commons/zenoh-shm/src/shm/unix.rs`). The wire carries only the descriptor
//! (`segment_id` + `length`), so the local mmap mechanism is an implementation
//! detail; memmap2 is the version-steady wrapper (vs nix's shifting `mman` API).
//!
//! SCOPED (R3a): one segment per payload, no pool, no watchdog / advisory-lock.
//! The owner ([`ShmBackedPayload`]) keeps the segment alive until dropped (which
//! unlinks it); a reader ([`PosixShmResolver`]) opens it by id while it is alive.
//! The reader COPIES the bytes out of the shared page into wz's owned Sample
//! payload (wz's Sample is an owned `Vec`, so the wire is zero-copy but the local
//! Sample is a single bounded copy). R3a is the inert provider + resolver
//! (`is_shm` is always false, so neither is on the live path yet); R3b wires them
//! to the negotiated handshake + the publish/subscribe swap.

use std::fs::OpenOptions;
use std::io::{self, ErrorKind};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use memmap2::{Mmap, MmapMut, MmapOptions};
use wz_session_core::extshm::{ShmDescriptor, ShmResolver};

/// Per-process candidate-id source: a pid-mixed atomic counter. Collisions are
/// caught by `create_new` (O_EXCL) and retried, so this only needs to spread.
static SHM_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

fn next_candidate_id() -> u32 {
    let pid = std::process::id();
    let c = SHM_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    pid.wrapping_mul(0x9E37_79B1).wrapping_add(c)
}

/// The /dev/shm backing path for a segment id (zenoh uses `<id>.zenoh`; wz uses
/// `wz-shm-<id>.wz` so the two never collide on a shared host).
fn shm_path(segment_id: u32) -> PathBuf {
    PathBuf::from(format!("/dev/shm/wz-shm-{segment_id:08x}.wz"))
}

/// An owner-side SHM-backed payload: a freshly-created /dev/shm segment the
/// application writes its payload into, then publishes by [`Self::descriptor`]
/// instead of by bytes. Kept alive until dropped (which unlinks the segment).
pub struct ShmBackedPayload {
    mmap: MmapMut,
    segment_id: u32,
    len: usize,
    path: PathBuf,
}

impl ShmBackedPayload {
    /// Create a fresh segment of `len` bytes (retrying on an id collision). The
    /// segment lives in /dev/shm until this value drops.
    pub fn alloc(len: usize) -> io::Result<Self> {
        for _ in 0..16 {
            let segment_id = next_candidate_id();
            let path = shm_path(segment_id);
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => {
                    file.set_len(len as u64)?;
                    // SAFETY: the file was just created exclusively by this
                    // process and is only mutated through this owning mapping;
                    // no external truncation races the scoped same-host model.
                    let mmap = unsafe { MmapOptions::new().map_mut(&file)? };
                    return Ok(Self {
                        mmap,
                        segment_id,
                        len,
                        path,
                    });
                }
                Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            ErrorKind::AlreadyExists,
            "exhausted SHM id candidates",
        ))
    }

    /// Copy `bytes` into the shared segment (truncated to the allocated `len`).
    pub fn write(&mut self, bytes: &[u8]) {
        let n = bytes.len().min(self.len);
        self.mmap[..n].copy_from_slice(&bytes[..n]);
    }

    /// The wire descriptor for this segment — what a Put carries instead of the
    /// payload bytes once SHM is negotiated.
    pub fn descriptor(&self) -> ShmDescriptor {
        ShmDescriptor {
            segment_id: self.segment_id,
            length: self.len as u32,
            generation: 0,
        }
    }

    /// The payload bytes in the shared segment — the source for the inline-bytes
    /// fallback when a session did NOT negotiate SHM (`publish_shm` then ships the
    /// bytes the ordinary way).
    pub fn bytes(&self) -> &[u8] {
        &self.mmap[..self.len]
    }
}

impl Drop for ShmBackedPayload {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The reader-side resolver: the AP impl of the no_std [`ShmResolver`] seam. Maps
/// a descriptor's segment read-only and copies its `length` bytes out (the
/// bounded scoped copy off the shared page into wz's owned Sample payload).
#[derive(Debug, Clone, Copy, Default)]
pub struct PosixShmResolver;

impl ShmResolver for PosixShmResolver {
    fn resolve(&self, descriptor: &ShmDescriptor) -> Option<Vec<u8>> {
        let path = shm_path(descriptor.segment_id);
        let file = OpenOptions::new().read(true).open(&path).ok()?;
        // SAFETY: read-only view of a same-host segment the peer owns; the
        // scoped model keeps it alive until delivery (the owner unlinks on drop).
        let mmap: Mmap = unsafe { MmapOptions::new().map(&file).ok()? };
        mmap.get(..descriptor.length as usize).map(<[u8]>::to_vec)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// A payload written into a fresh /dev/shm segment is read back byte-exact by
    /// the resolver opening it by descriptor — the real-syscall same-host
    /// round-trip (no #[ignore]: /dev/shm is present).
    #[test]
    fn shm_payload_round_trips_through_dev_shm() {
        let data = b"zero-copy-over-dev-shm".to_vec();
        let mut payload = ShmBackedPayload::alloc(data.len()).expect("alloc /dev/shm segment");
        payload.write(&data);
        let descriptor = payload.descriptor();

        let resolved = PosixShmResolver
            .resolve(&descriptor)
            .expect("resolve the descriptor");
        assert_eq!(
            resolved, data,
            "the resolver reads the owner's bytes off the shared page"
        );
    }

    /// Dropping the owner unlinks the segment — a later resolve of the same
    /// descriptor fails (the lifecycle contract: the owner backs the segment).
    #[test]
    fn dropping_the_owner_unlinks_the_segment() {
        let descriptor = {
            let mut payload = ShmBackedPayload::alloc(8).expect("alloc");
            payload.write(b"transient");
            payload.descriptor()
            // payload drops here -> unlink
        };
        assert!(
            PosixShmResolver.resolve(&descriptor).is_none(),
            "a resolve after the owner dropped finds no segment"
        );
    }

    /// Two concurrently-allocated segments get distinct ids (the id source
    /// spreads + create_new retries on collision).
    #[test]
    fn concurrent_allocs_get_distinct_ids() {
        let a = ShmBackedPayload::alloc(4).expect("alloc a");
        let b = ShmBackedPayload::alloc(4).expect("alloc b");
        assert_ne!(a.descriptor().segment_id, b.descriptor().segment_id);
    }
}
