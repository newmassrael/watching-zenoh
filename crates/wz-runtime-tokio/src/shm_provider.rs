// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The AP POSIX shared-memory provider for the same-host SHM transport
//! (`transport-shm`) — the `std` half of the split (the no_std descriptor +
//! marker codec + the [`ShmResolver`](wz_session_core::extshm::ShmResolver) trait
//! live in `wz-session-core::extshm`).
//!
//! # R2862 — the payload is addressed the way upstream addresses it
//!
//! Upstream never names a data segment on the wire. Its `ShmBufInfo` names a
//! header SLOT in a METADATA segment (`commons/zenoh-shm/src/metadata/segment.rs`
//! @ `pub struct Metadata<const S: usize> {`), and that header holds the data
//! segment's id, the chunk's offset in it, the chunk's length, the protocol
//! that made it, a refcount, a generation and an invalidation flag
//! (`commons/zenoh-shm/src/header/chunk_header.rs` @
//! `pub struct ChunkHeaderType {`). A receiver maps the metadata segment,
//! checks the header's generation against the descriptor's, and only then maps
//! the data (`commons/zenoh-shm/src/reader.rs` @ `pub fn read_shmbuf(`).
//!
//! wz used to put a data segment id where that slot address goes, under a name
//! (`wz-shm-<hex>.wz`) no zenoh peer opens. This module now keeps a metadata
//! segment in upstream's byte layout and names every segment through
//! [`crate::posix_shm`], so the descriptor wz sends is one a zenoh receiver can
//! follow and the one it receives is one wz can.
//!
//! # The layout is a MIRROR, not a transcription
//!
//! Upstream's two structs are `#[stabby::stabby]`, which admits only
//! `#[repr(C)]` (stabby-macros' struct derive refuses any other repr), so their
//! layout is C's. [`ChunkHeader`] and [`Metadata`] below are the same fields in
//! the same order under `#[repr(C)]`, which makes the byte layout a property
//! the compiler computes rather than a table someone copied; the tests pin the
//! resulting offsets so a later edit to either struct is caught.
//!
//! # What this increment does NOT do yet
//!
//! * No POOL: each payload still gets its own data segment, at chunk offset 0.
//! * No WATCHDOG: the slot's watchdog bit is neither confirmed nor validated.
//! * The receiver takes no refcount; it copies the bytes out while the owner
//!   keeps the slot live, the same scoped lifecycle as before.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use wz_session_core::extshm::{ShmDescriptor, ShmResolver};

use crate::posix_shm::{next_candidate_id, OwnedSegment, PeerSegment};

/// upstream `POSIX_PROTOCOL_ID`
/// (`commons/zenoh-shm/src/api/protocol_implementations/posix/protocol_id.rs` @
/// `pub const POSIX_PROTOCOL_ID: ProtocolID = 0;`): the protocol a header names
/// for a chunk that lives in a POSIX segment.
pub const POSIX_PROTOCOL_ID: u32 = 0;

/// Header slots per metadata segment — upstream's default `S` for
/// `MetadataSegment` (`commons/zenoh-shm/src/metadata/segment.rs` @
/// `pub struct MetadataSegment<const S: usize = 32768> {`).
pub const METADATA_SLOTS: usize = 32768;

/// One header slot: upstream's `ChunkHeaderType`, field for field, under the
/// `#[repr(C)]` stabby imposes on it.
#[repr(C)]
pub struct ChunkHeader {
    refcount: AtomicU32,
    watchdog_invalidated: AtomicBool,
    generation: AtomicU32,
    protocol: AtomicU32,
    segment: AtomicU32,
    chunk: AtomicU32,
    len: AtomicUsize,
}

/// A metadata segment's whole contents: upstream's `Metadata<S>`, the headers
/// followed by one watchdog word per header.
#[repr(C)]
pub struct Metadata {
    headers: [ChunkHeader; METADATA_SLOTS],
    watchdogs: [AtomicU64; METADATA_SLOTS],
}

/// View `bytes` as a [`Metadata`], or `None` when they are too short or
/// misaligned to be one.
fn metadata_of(bytes: &[u8]) -> Option<&Metadata> {
    if bytes.len() < core::mem::size_of::<Metadata>()
        || bytes
            .as_ptr()
            .align_offset(core::mem::align_of::<Metadata>())
            != 0
    {
        return None;
    }
    // SAFETY: the length and alignment were just checked; every field is an
    // atomic integer (or an atomic bool, upstream's own choice) for which the
    // mapping's bytes are read through atomic loads only; a zero-filled page
    // is a valid value of every field.
    Some(unsafe { &*(bytes.as_ptr().cast::<Metadata>()) })
}

/// This process's metadata segment and the slots it has not handed out.
struct MetadataStore {
    segment: OwnedSegment,
    id: u16,
    free: Vec<u16>,
}

impl MetadataStore {
    fn create() -> io::Result<Self> {
        // A metadata id is a `u16` on the wire. The draw is the shared counter's
        // low half, which is odd and so never 0; a collision with any segment
        // on the host is caught by `create_new` and retried.
        let segment = OwnedSegment::create(core::mem::size_of::<Metadata>(), || {
            u64::from(next_candidate_id() & 0xFFFF)
        })?;
        let id = u16::try_from(segment.id()).expect("metadata ids are drawn as u16");
        // Handed out from the low end first; a Vec popped from its tail.
        let free = (0..METADATA_SLOTS as u16).rev().collect();
        Ok(Self { segment, id, free })
    }

    fn metadata(&self) -> &Metadata {
        metadata_of(self.segment.bytes()).expect("the segment was created at size_of::<Metadata>()")
    }
}

/// The process-wide store, created on first use. `None` inside means the
/// creation failed; it is retried on the next allocation.
fn store() -> &'static Mutex<Option<MetadataStore>> {
    static STORE: OnceLock<Mutex<Option<MetadataStore>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(None))
}

/// An owner-side SHM-backed payload: a data segment the application writes its
/// payload into, and the metadata slot that describes it to a receiver. The
/// payload is published by [`Self::descriptor`] instead of by bytes; dropping
/// it invalidates the slot and unlinks the data segment.
pub struct ShmBackedPayload {
    data: OwnedSegment,
    len: usize,
    metadata_id: u16,
    slot: u16,
    generation: u32,
}

impl ShmBackedPayload {
    /// Allocate a `len`-byte payload: a fresh data segment, and a metadata slot
    /// whose header names it. `len` must be non-zero — upstream's `data_len`
    /// is a `NonZeroUsize`, so a 0-byte descriptor is not one a receiver takes.
    pub fn alloc(len: usize) -> io::Result<Self> {
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an SHM payload must be at least one byte (upstream's data_len is NonZero)",
            ));
        }
        // The descriptor carries `data_len` as a `u32`.
        u32::try_from(len).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "an SHM payload is at most u32::MAX bytes",
            )
        })?;
        let data = OwnedSegment::create(len, || u64::from(next_candidate_id()))?;
        let data_id = u32::try_from(data.id()).expect("data segment ids are drawn as u32");

        let mut guard = store()
            .lock()
            .map_err(|_| io::Error::other("SHM store poisoned"))?;
        if guard.is_none() {
            *guard = Some(MetadataStore::create()?);
        }
        let store = guard.as_mut().expect("just filled");
        let slot = store
            .free
            .pop()
            .ok_or_else(|| io::Error::other("every SHM metadata slot is in use"))?;
        let header = &store.metadata().headers[slot as usize];
        // A new generation per use of the slot, so a descriptor from its last
        // use no longer matches the header.
        let generation = header.generation.load(Ordering::Relaxed).wrapping_add(1);
        header.generation.store(generation, Ordering::Relaxed);
        header.protocol.store(POSIX_PROTOCOL_ID, Ordering::Relaxed);
        header.segment.store(data_id, Ordering::Relaxed);
        header.chunk.store(0, Ordering::Relaxed);
        header.len.store(len, Ordering::Relaxed);
        header.refcount.store(1, Ordering::Relaxed);
        // Last, and with Release: a receiver that sees the slot valid sees the
        // fields written above.
        header.watchdog_invalidated.store(false, Ordering::Release);
        Ok(Self {
            data,
            len,
            metadata_id: store.id,
            slot,
            generation,
        })
    }

    /// Copy `bytes` into the shared segment (truncated to the allocated `len`).
    pub fn write(&mut self, bytes: &[u8]) {
        let n = bytes.len().min(self.len);
        self.data.bytes_mut()[..n].copy_from_slice(&bytes[..n]);
    }

    /// The wire descriptor for this payload — what a Put carries instead of the
    /// payload bytes once SHM is negotiated.
    pub fn descriptor(&self) -> ShmDescriptor {
        ShmDescriptor {
            data_len: self.len as u32,
            metadata_id: self.metadata_id,
            metadata_index: self.slot,
            generation: self.generation,
        }
    }

    /// The payload bytes in the shared segment — the source for the inline-bytes
    /// fallback when a session did NOT negotiate SHM (`publish_shm` then ships the
    /// bytes the ordinary way).
    pub fn bytes(&self) -> &[u8] {
        &self.data.bytes()[..self.len]
    }
}

impl Drop for ShmBackedPayload {
    fn drop(&mut self) {
        // Invalidate BEFORE the slot is reusable and before the data segment
        // is unlinked, so a receiver racing the drop refuses rather than reads.
        if let Ok(mut guard) = store().lock() {
            if let Some(store) = guard.as_mut() {
                let header = &store.metadata().headers[self.slot as usize];
                header.watchdog_invalidated.store(true, Ordering::Release);
                header.refcount.store(0, Ordering::Relaxed);
                store.free.push(self.slot);
            }
        }
        // `self.data` unlinks the data segment when it drops, after this.
    }
}

/// The reader-side resolver: the AP impl of the no_std [`ShmResolver`] seam.
///
/// Follows a descriptor as upstream's reader does: open the metadata segment it
/// names, read the header at its slot, refuse an invalidated header or one
/// whose generation or protocol does not match, then open the data segment the
/// header names and copy `data_len` bytes from the chunk's offset (the bounded
/// scoped copy off the shared page into wz's owned Sample payload).
#[derive(Debug, Clone, Copy, Default)]
pub struct PosixShmResolver;

impl ShmResolver for PosixShmResolver {
    fn resolve(&self, descriptor: &ShmDescriptor) -> Option<Vec<u8>> {
        let metadata_segment = PeerSegment::open(u64::from(descriptor.metadata_id)).ok()?;
        let metadata = metadata_of(metadata_segment.bytes())?;
        let header = metadata.headers.get(descriptor.metadata_index as usize)?;
        if header.watchdog_invalidated.load(Ordering::Acquire)
            || header.generation.load(Ordering::Relaxed) != descriptor.generation
            || header.protocol.load(Ordering::Relaxed) != POSIX_PROTOCOL_ID
        {
            return None;
        }
        let data_len = descriptor.data_len as usize;
        let chunk = header.chunk.load(Ordering::Relaxed) as usize;
        if data_len > header.len.load(Ordering::Relaxed) {
            return None;
        }
        let data = PeerSegment::open(u64::from(header.segment.load(Ordering::Relaxed))).ok()?;
        data.bytes()
            .get(chunk..chunk.checked_add(data_len)?)
            .map(<[u8]>::to_vec)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use core::mem::{offset_of, size_of};

    /// R2862 — the header's byte layout, pinned. Upstream's `ChunkHeaderType`
    /// is `repr(C)` with these fields in this order; the offsets are what C
    /// gives them on a 64-bit target, and a receiver reads exactly these bytes.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn the_header_layout_is_upstreams() {
        assert_eq!(offset_of!(ChunkHeader, refcount), 0);
        assert_eq!(offset_of!(ChunkHeader, watchdog_invalidated), 4);
        assert_eq!(offset_of!(ChunkHeader, generation), 8);
        assert_eq!(offset_of!(ChunkHeader, protocol), 12);
        assert_eq!(offset_of!(ChunkHeader, segment), 16);
        assert_eq!(offset_of!(ChunkHeader, chunk), 20);
        assert_eq!(offset_of!(ChunkHeader, len), 24);
        assert_eq!(size_of::<ChunkHeader>(), 32);
        assert_eq!(offset_of!(Metadata, watchdogs), 32 * METADATA_SLOTS);
        assert_eq!(size_of::<Metadata>(), (32 + 8) * METADATA_SLOTS);
    }

    /// A payload written into its data segment is read back byte-exact by the
    /// resolver following the descriptor through the metadata slot — the
    /// real-syscall same-host round trip.
    #[test]
    fn shm_payload_round_trips_through_the_metadata_slot() {
        let data = b"zero-copy-over-dev-shm".to_vec();
        let mut payload = ShmBackedPayload::alloc(data.len()).expect("alloc");
        payload.write(&data);
        let descriptor = payload.descriptor();
        assert_eq!(descriptor.data_len as usize, data.len());

        let resolved = PosixShmResolver.resolve(&descriptor).expect("resolve");
        assert_eq!(resolved, data, "the resolver reads the owner's bytes");
    }

    /// The descriptor names the METADATA segment, not the data one: opening the
    /// segment it names finds a metadata-sized object whose header at the named
    /// slot points at a different, payload-sized segment.
    #[test]
    fn the_descriptor_addresses_a_slot_not_a_data_segment() {
        let payload = ShmBackedPayload::alloc(5).expect("alloc");
        let d = payload.descriptor();
        let meta = PeerSegment::open(u64::from(d.metadata_id)).expect("metadata segment");
        assert_eq!(meta.bytes().len(), size_of::<Metadata>());
        let header = &metadata_of(meta.bytes()).expect("view").headers[d.metadata_index as usize];
        let data_id = header.segment.load(Ordering::Relaxed);
        assert_ne!(u64::from(data_id), u64::from(d.metadata_id));
        assert_eq!(
            PeerSegment::open(u64::from(data_id))
                .expect("data")
                .bytes()
                .len(),
            5
        );
    }

    /// Dropping the owner invalidates its slot — a later resolve of the same
    /// descriptor fails, even if the slot is reused at once.
    #[test]
    fn dropping_the_owner_invalidates_the_slot() {
        let descriptor = {
            let mut payload = ShmBackedPayload::alloc(9).expect("alloc");
            payload.write(b"transient");
            payload.descriptor()
        };
        assert!(PosixShmResolver.resolve(&descriptor).is_none());
        // Reuse: a new payload may land on the same slot, with a new generation.
        let reused = ShmBackedPayload::alloc(9).expect("alloc again");
        assert!(
            PosixShmResolver.resolve(&descriptor).is_none(),
            "a stale descriptor stays refused while its slot serves another payload"
        );
        drop(reused);
    }

    /// A descriptor naming the right slot with the wrong generation is refused:
    /// the generation is what tells a live buffer from a reused slot.
    #[test]
    fn a_stale_generation_is_refused() {
        let mut payload = ShmBackedPayload::alloc(3).expect("alloc");
        payload.write(b"abc");
        let mut stale = payload.descriptor();
        stale.generation = stale.generation.wrapping_sub(1);
        assert!(PosixShmResolver.resolve(&stale).is_none());
        assert!(PosixShmResolver.resolve(&payload.descriptor()).is_some());
    }

    /// Upstream's `data_len` is `NonZeroUsize`; a 0-byte payload is refused at
    /// allocation rather than producing a descriptor no receiver takes.
    #[test]
    fn a_zero_byte_payload_is_refused() {
        assert!(ShmBackedPayload::alloc(0).is_err());
    }

    /// Two concurrently-allocated payloads get distinct slots.
    #[test]
    fn concurrent_allocs_get_distinct_slots() {
        let a = ShmBackedPayload::alloc(4).expect("alloc a");
        let b = ShmBackedPayload::alloc(4).expect("alloc b");
        assert_ne!(a.descriptor().metadata_index, b.descriptor().metadata_index);
    }
}
