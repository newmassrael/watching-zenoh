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
//! header SLOT in a METADATA segment
//! (`commons/zenoh-shm/src/metadata/segment.rs` @ `pub struct Metadata<const S: usize> {`),
//! and that header holds the data
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
//! # R3038 — the buffer lives by upstream's reference count, not by its owner
//!
//! Until this round the owner's `Drop` invalidated the slot and unlinked the data
//! segment, so a publisher that let go of its payload the moment `publish_shm`
//! returned (which is what every real publisher does) left a receiver reading a
//! segment that no longer existed. Upstream does not work that way, and the
//! protocol is small enough to state whole:
//!
//! * the header's `refcount` starts at 1 and is the owner's own reference
//!   (`commons/zenoh-shm/src/metadata/allocated_descriptor.rs` @
//!   `.store(1, std::sync::atomic::Ordering::SeqCst);`);
//! * SERIALIZING the descriptor takes one more reference FOR THE RECEIVER
//!   (`commons/zenoh-codec/src/core/zbuf.rs` @ `unsafe { shmb.inc_ref_count() };`),
//!   and a read takes none, because the sender already did
//!   (`commons/zenoh-shm/src/reader.rs` @
//!   `// Read does not increment the reference count as it is assumed`);
//! * every holder, the owner and each receiver, gives its reference back when it
//!   lets go (`commons/zenoh-shm/src/lib.rs` @ `impl Drop for ShmBufInner {`);
//! * the provider reclaims a chunk when its count reads zero, by a collection
//!   that runs when it allocates
//!   (`commons/zenoh-shm/src/api/provider/shm_provider.rs` @
//!   `fn garbage_collect_impl<const SAFE: bool>(&self) -> usize {`), and a slot
//!   advances its generation when it is reclaimed, which is what turns every
//!   outstanding descriptor of it stale
//!   (`commons/zenoh-shm/src/metadata/storage.rs` @ `pub fn reclaim(`).
//!
//! So here: [`ShmBackedPayload::wire_reference`](crate::shm_provider::ShmBackedPayload::wire_reference)
//! is the serialization point,
//! [`PosixShmResolver::resolve`](crate::shm_provider::PosixShmResolver) releases the reference the sender took for it,
//! the owner's `Drop` releases its own and parks the data segment on a busy list
//! instead of unlinking it, and the busy list is collected at the next
//! allocation and at every owner drop. The data segment stays mapped and locked
//! while it is parked, which is not decoration: upstream's orphan cleanup
//! removes any segment nobody holds a shared lock on, so an unmapped parked
//! segment could be deleted by a zenoh peer while a receiver still references
//! it.
//!
//! # What this increment does NOT do yet
//!
//! * No POOL: each payload still gets its own data segment, at chunk offset 0.
//! * No WATCHDOG: the slot's watchdog bit is neither confirmed nor validated, so
//!   a holder that dies without releasing leaves its chunk parked until the
//!   process ends.
//! * The receiver still copies the bytes off the page into an owned buffer
//!   before it releases, so a delivered sample is not the segment.
//! * A reference taken for a frame that is then dropped before it leaves (a
//!   congestion drop after the send call returned) is never released, which is
//!   upstream's behaviour too.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use wz_session_core::extshm::{ShmDescriptor, ShmResolver};

use crate::posix_shm::{next_candidate_id, OwnedSegment, PeerSegment, PeerSegmentRw};

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

/// View a metadata segment a PEER made, mapped writable, as a [`Metadata`], or
/// `None` when it is too short or misaligned to be one.
///
/// The writable twin of `metadata_of`, and the reason it exists is the
/// reference count: a receiver releases a buffer by writing the provider's
/// header, which a read-only view cannot do.
fn metadata_of_rw(segment: &PeerSegmentRw) -> Option<&Metadata> {
    if segment.len() < core::mem::size_of::<Metadata>()
        || segment
            .base()
            .align_offset(core::mem::align_of::<Metadata>())
            != 0
    {
        return None;
    }
    // SAFETY: the length and alignment were just checked; the pointer was taken
    // from the mapping's `as_mut_ptr`, so it carries the right to write, and the
    // mapping lives as long as `segment`; every field is an atomic integer (or
    // an atomic bool, upstream's own choice), accessed through atomic operations
    // only; a zero-filled page is a valid value of every field.
    Some(unsafe { &*segment.base().cast::<Metadata>() })
}

/// The header at `slot` of `segment`, a metadata segment this process created.
///
/// A free function over the segment rather than a method on the store, so a
/// caller can hold a header while it changes the store's lists: the two borrows
/// are of different fields.
fn header_of(segment: &OwnedSegment, slot: u16) -> &ChunkHeader {
    &metadata_of(segment.bytes())
        .expect("the segment was created at size_of::<Metadata>()")
        .headers[slot as usize]
}

/// Give one reference back, never going below zero.
///
/// Upstream's release is a plain `fetch_sub` (`commons/zenoh-shm/src/lib.rs` @
/// `unsafe fn dec_ref_count(&self) {`), which wraps. A descriptor names a header
/// in a segment a PEER made, so a stranger's mistake or a replayed descriptor
/// would send a wrapped count to four billion, a chunk that is never reclaimed;
/// saturating costs nothing a correct holder can see and ends that.
fn release_reference(header: &ChunkHeader) {
    let _ = header
        .refcount
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
}

/// An owner's chunk that is no longer held by its owner but may still be held by
/// a receiver: its slot and the data segment it names, kept mapped and locked
/// until the count reads zero.
struct BusyChunk {
    slot: u16,
    /// Never read: it is held for what dropping it does, which is to unlink the
    /// segment, and for what holding it is, a mapping that keeps its shared lock.
    _data: OwnedSegment,
}

/// This process's metadata segment, the slots it has not handed out, and the
/// chunks that were handed out and have not come home.
struct MetadataStore {
    segment: OwnedSegment,
    id: u16,
    /// First in, first out, as upstream's `available` queue is: a reclaimed slot
    /// goes to the back, so a stale descriptor meets a reused slot as late as it
    /// can, on top of the generation check that refuses it then.
    free: VecDeque<u16>,
    busy: Vec<BusyChunk>,
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
        let free = (0..METADATA_SLOTS as u16).collect();
        Ok(Self {
            segment,
            id,
            free,
            busy: Vec::new(),
        })
    }

    /// Reclaim every busy chunk whose count reads zero: upstream's safe garbage
    /// collection, which frees a chunk on the count and on nothing else.
    ///
    /// A reclaimed slot advances its generation (so every descriptor still
    /// naming it goes stale), joins the back of the free queue, and its data
    /// segment is unlinked as it drops. Returns how many chunks came home.
    fn collect_garbage(&mut self) -> usize {
        let mut collected = 0;
        let mut i = 0;
        while i < self.busy.len() {
            let header = header_of(&self.segment, self.busy[i].slot);
            if header.refcount.load(Ordering::SeqCst) != 0 {
                i += 1;
                continue;
            }
            let chunk = self.busy.swap_remove(i);
            header.generation.fetch_add(1, Ordering::SeqCst);
            self.free.push_back(chunk.slot);
            collected += 1;
            // `chunk` drops here and unlinks its segment; the slot is already
            // stale, so a receiver that races the unlink refuses on the generation.
        }
        collected
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
/// payload is published by a descriptor instead of by bytes
/// ([`Self::wire_reference`] takes the reference that descriptor carries).
///
/// Dropping it releases the owner's own reference. The data segment is NOT
/// unlinked then unless that was the last reference: a receiver that was sent
/// the descriptor still holds one, and the segment stays until it lets go.
pub struct ShmBackedPayload {
    /// `Some` for the whole life of the handle; `Drop` moves it onto the busy
    /// list so the segment outlives the handle for as long as a receiver needs it.
    data: Option<OwnedSegment>,
    len: usize,
    metadata_id: u16,
    slot: u16,
    generation: u32,
}

/// R3038 -- one reference taken for a receiver, and the descriptor that carries it.
///
/// Serializing a descriptor onto the wire is what takes the reference upstream
/// (`commons/zenoh-codec/src/core/zbuf.rs` @ `unsafe { shmb.inc_ref_count() };`),
/// so a descriptor handed to a codec without one is a receiver releasing a
/// reference nobody took. This guard is how a caller cannot forget: build the
/// frame from [`Self::descriptor`], send it, and [`Self::commit`] once the
/// frame is on its way; a guard dropped any other way, because the frame did
/// not build or the send refused, gives the reference back.
pub struct WireReference<'a> {
    payload: &'a ShmBackedPayload,
    committed: bool,
}

impl WireReference<'_> {
    /// The descriptor this reference is for.
    pub fn descriptor(&self) -> ShmDescriptor {
        self.payload.descriptor()
    }

    /// The frame carrying the descriptor has been handed to the link, so the
    /// receiver now owns the reference and releases it when it lets go.
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for WireReference<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Ok(guard) = store().lock() {
            if let Some(store) = guard.as_ref() {
                release_reference(header_of(&store.segment, self.payload.slot));
            }
        }
    }
}

/// What a descriptor's chunk is doing, as its own metadata slot says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceState {
    /// The slot still holds the buffer the descriptor names, with this many
    /// references outstanding (the owner's, and one per descriptor sent and not
    /// yet released). Zero means every holder has let go and the provider has not
    /// yet collected it.
    Held(u32),
    /// The slot's generation has moved on: the provider collected this chunk, so
    /// every holder had let go and any descriptor naming it is stale.
    Reclaimed,
}

/// Read a descriptor's chunk state from its metadata segment, or `None` when that
/// segment cannot be opened (its provider is gone).
///
/// A diagnostic, and the instrument the cross-implementation witnesses use to
/// read the OTHER side's bookkeeping: whether a zenoh publisher's chunk was
/// released by a wz receiver is a fact in a segment zenoh owns, and a witness
/// that asked the wz side would be grading wz with wz.
pub fn reference_state(descriptor: &ShmDescriptor) -> Option<ReferenceState> {
    let segment = PeerSegment::open(u64::from(descriptor.metadata_id)).ok()?;
    let header = metadata_of(segment.bytes())?
        .headers
        .get(descriptor.metadata_index as usize)?;
    if header.generation.load(Ordering::SeqCst) != descriptor.generation {
        return Some(ReferenceState::Reclaimed);
    }
    Some(ReferenceState::Held(header.refcount.load(Ordering::SeqCst)))
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
        // Upstream collects when an allocation would otherwise fail; collecting
        // first costs one scan of the busy list and means exhaustion is reported
        // only when every slot really is held.
        store.collect_garbage();
        let slot = store
            .free
            .pop_front()
            .ok_or_else(|| io::Error::other("every SHM metadata slot is in use"))?;
        let header = header_of(&store.segment, slot);
        // The generation is NOT touched here: it advanced when this slot was
        // reclaimed, which is the moment every descriptor of its last use went
        // stale, and a descriptor of THIS use is stamped with the value read here.
        let generation = header.generation.load(Ordering::SeqCst);
        header.protocol.store(POSIX_PROTOCOL_ID, Ordering::Relaxed);
        header.segment.store(data_id, Ordering::Relaxed);
        header.chunk.store(0, Ordering::Relaxed);
        header.len.store(len, Ordering::Relaxed);
        // The owner's own reference.
        header.refcount.store(1, Ordering::SeqCst);
        // Last, and with Release: a receiver that sees the slot valid sees the
        // fields written above.
        header.watchdog_invalidated.store(false, Ordering::Release);
        Ok(Self {
            data: Some(data),
            len,
            metadata_id: store.id,
            slot,
            generation,
        })
    }

    /// Copy `bytes` into the shared segment (truncated to the allocated `len`).
    pub fn write(&mut self, bytes: &[u8]) {
        let n = bytes.len().min(self.len);
        self.segment_mut().bytes_mut()[..n].copy_from_slice(&bytes[..n]);
    }

    /// The wire descriptor for this payload, as a value.
    ///
    /// It takes NO reference, so it is for inspection and for tests that name a
    /// descriptor without sending it. A descriptor that goes onto the wire is
    /// built through [`Self::wire_reference`], which takes the reference the
    /// receiver will release.
    pub fn descriptor(&self) -> ShmDescriptor {
        ShmDescriptor {
            data_len: self.len as u32,
            metadata_id: self.metadata_id,
            metadata_index: self.slot,
            generation: self.generation,
        }
    }

    /// Take one reference for a receiver and return the guard that carries it.
    ///
    /// Taken before the descriptor is built, so the chunk cannot be reclaimed
    /// between the two; returned if the guard is dropped without
    /// [`WireReference::commit`].
    pub fn wire_reference(&self) -> WireReference<'_> {
        if let Ok(guard) = store().lock() {
            if let Some(store) = guard.as_ref() {
                header_of(&store.segment, self.slot)
                    .refcount
                    .fetch_add(1, Ordering::SeqCst);
            }
        }
        WireReference {
            payload: self,
            committed: false,
        }
    }

    /// The payload bytes in the shared segment — the source for the inline-bytes
    /// fallback when a session did NOT negotiate SHM (`publish_shm` then ships the
    /// bytes the ordinary way).
    pub fn bytes(&self) -> &[u8] {
        &self.segment().bytes()[..self.len]
    }

    fn segment(&self) -> &OwnedSegment {
        self.data
            .as_ref()
            .expect("the data segment lives as long as the handle")
    }

    fn segment_mut(&mut self) -> &mut OwnedSegment {
        self.data
            .as_mut()
            .expect("the data segment lives as long as the handle")
    }
}

impl Drop for ShmBackedPayload {
    fn drop(&mut self) {
        let Some(data) = self.data.take() else {
            return;
        };
        // A poisoned store forfeits the chunk: `data` drops and unlinks, which is
        // the honest end for a process whose bookkeeping died, and a receiver
        // that was mid-read refuses on the missing segment.
        let Ok(mut guard) = store().lock() else {
            return;
        };
        let Some(store) = guard.as_mut() else {
            return;
        };
        // Give the owner's own reference back, then park the segment. Whether a
        // receiver still holds one is the count's to say, so the chunk goes to
        // the busy list either way and the collection decides: at zero it is
        // reclaimed on the spot, otherwise it waits for the receiver.
        release_reference(header_of(&store.segment, self.slot));
        store.busy.push(BusyChunk {
            slot: self.slot,
            _data: data,
        });
        store.collect_garbage();
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

/// Gives the receiver's reference back when it goes out of scope, on whichever
/// way `resolve` leaves.
struct ReleaseOnDrop<'a>(&'a ChunkHeader);

impl Drop for ReleaseOnDrop<'_> {
    fn drop(&mut self) {
        release_reference(self.0);
    }
}

impl ShmResolver for PosixShmResolver {
    /// R3038 -- the receiver's end of the reference count: the descriptor was
    /// sent with one reference taken for this reader, and this call gives it
    /// back after it has read, which is what upstream's `Drop for ShmBufInner`
    /// does when the received buffer is let go.
    ///
    /// The release is made exactly once on every way out once the header's
    /// generation shows that reference is ours (a read that finds the chunk
    /// invalidated, a length that does not fit, a protocol this node does not
    /// speak, a data segment that will not open all still release, as upstream's
    /// does by dropping the buffer it built). A header of ANOTHER generation is
    /// another buffer's and its count is not ours to touch, so that one returns
    /// without a release; upstream would decrement it, which is its defect and
    /// not copied.
    fn resolve(&self, descriptor: &ShmDescriptor) -> Option<Vec<u8>> {
        // Mapped WRITABLE: releasing the reference below writes the header.
        let metadata_segment = PeerSegmentRw::open(u64::from(descriptor.metadata_id)).ok()?;
        let metadata = metadata_of_rw(&metadata_segment)?;
        let header = metadata.headers.get(descriptor.metadata_index as usize)?;
        if header.generation.load(Ordering::SeqCst) != descriptor.generation {
            return None;
        }
        let _release = ReleaseOnDrop(header);
        if header.watchdog_invalidated.load(Ordering::Acquire)
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

    /// A descriptor sent the way production sends one: the reference is taken
    /// for the receiver and the frame is treated as having left.
    fn sent(payload: &ShmBackedPayload) -> ShmDescriptor {
        let wire = payload.wire_reference();
        let descriptor = wire.descriptor();
        wire.commit();
        descriptor
    }

    /// The data segment id a descriptor's header names, read the way a peer reads it.
    fn data_segment_of(descriptor: &ShmDescriptor) -> u64 {
        let meta = PeerSegment::open(u64::from(descriptor.metadata_id)).expect("metadata segment");
        let header =
            &metadata_of(meta.bytes()).expect("view").headers[descriptor.metadata_index as usize];
        u64::from(header.segment.load(Ordering::Relaxed))
    }

    /// A payload written into its data segment is read back byte-exact by the
    /// resolver following the descriptor through the metadata slot — the
    /// real-syscall same-host round trip.
    #[test]
    fn shm_payload_round_trips_through_the_metadata_slot() {
        let data = b"zero-copy-over-dev-shm".to_vec();
        let mut payload = ShmBackedPayload::alloc(data.len()).expect("alloc");
        payload.write(&data);
        let descriptor = sent(&payload);
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

    /// R3038 -- an owner that lets go with no descriptor outstanding takes its
    /// chunk home at once: the count reads zero, the slot's generation moves on
    /// and the descriptor it had is stale.
    #[test]
    fn an_owner_with_no_receiver_reclaims_its_chunk_when_it_lets_go() {
        let descriptor = {
            let mut payload = ShmBackedPayload::alloc(9).expect("alloc");
            payload.write(b"transient");
            payload.descriptor()
        };
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Reclaimed),
            "the owner's reference was the last, so the chunk was collected"
        );
        assert!(PosixShmResolver.resolve(&descriptor).is_none());
    }

    /// R3038 -- THE LIFECYCLE ARM: an owner that lets go while a receiver holds a
    /// reference leaves the chunk standing for that receiver, which reads it and
    /// then releases it, and only then does the chunk go home.
    ///
    /// Read off the slot's own header and off the filesystem, not off this
    /// module's bookkeeping: the data segment must still OPEN after the owner is
    /// gone and must not open once the chunk is collected.
    #[test]
    fn an_owner_that_lets_go_leaves_its_chunk_standing_for_the_receiver_that_holds_it() {
        let mut payload = ShmBackedPayload::alloc(4).expect("alloc");
        payload.write(b"held");
        let descriptor = sent(&payload);
        let data_id = data_segment_of(&descriptor);
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Held(2)),
            "the owner's reference and the one the descriptor carries"
        );

        drop(payload);
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Held(1)),
            "the owner's reference is back and the receiver's is not"
        );
        assert!(
            PeerSegment::open(data_id).is_ok(),
            "the data segment is still there for the receiver"
        );

        assert_eq!(
            PosixShmResolver.resolve(&descriptor).as_deref(),
            Some(&b"held"[..]),
            "and a receiver that comes after the owner is gone reads it byte-exact"
        );
        // Other tests allocate in this process and every allocation collects, so
        // the chunk may already be collected; either way the count is not 1.
        assert!(matches!(
            reference_state(&descriptor),
            Some(ReferenceState::Held(0) | ReferenceState::Reclaimed)
        ));

        // The next allocation collects it.
        let _next = ShmBackedPayload::alloc(1).expect("alloc");
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Reclaimed),
            "every holder let go, so the chunk was collected"
        );
        assert!(
            PeerSegment::open(data_id).is_err(),
            "and its data segment is unlinked"
        );
        assert!(PosixShmResolver.resolve(&descriptor).is_none());
    }

    /// R3038 -- a resolve gives back exactly ONE reference, however many were
    /// taken: the count steps down by one per receiver.
    #[test]
    fn a_resolve_gives_back_exactly_one_reference() {
        let mut payload = ShmBackedPayload::alloc(2).expect("alloc");
        payload.write(b"ok");
        let first = sent(&payload);
        let second = sent(&payload);
        assert_eq!(reference_state(&first), Some(ReferenceState::Held(3)));

        assert!(PosixShmResolver.resolve(&first).is_some());
        assert_eq!(reference_state(&first), Some(ReferenceState::Held(2)));
        assert!(PosixShmResolver.resolve(&second).is_some());
        assert_eq!(reference_state(&first), Some(ReferenceState::Held(1)));

        drop(payload);
        assert_eq!(
            reference_state(&first),
            Some(ReferenceState::Reclaimed),
            "the owner's was the last reference"
        );
    }

    /// R3038 -- a reference taken for a frame that never left is given back, so a
    /// failed build or a refused send does not raise the count for good.
    #[test]
    fn a_wire_reference_that_is_not_committed_is_returned() {
        let payload = ShmBackedPayload::alloc(2).expect("alloc");
        let descriptor = payload.descriptor();
        let wire = payload.wire_reference();
        assert_eq!(reference_state(&descriptor), Some(ReferenceState::Held(2)));
        drop(wire);
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Held(1)),
            "back to the owner's alone"
        );
    }

    /// A descriptor naming the right slot with the wrong generation is refused:
    /// the generation is what tells a live buffer from a reused slot. R3038 -- and
    /// it is refused WITHOUT touching the count, because a header of another
    /// generation is another buffer's.
    #[test]
    fn a_stale_generation_is_refused_and_touches_no_count() {
        let mut payload = ShmBackedPayload::alloc(3).expect("alloc");
        payload.write(b"abc");
        let live = sent(&payload);
        let mut stale = live;
        stale.generation = stale.generation.wrapping_sub(1);
        assert!(PosixShmResolver.resolve(&stale).is_none());
        assert_eq!(
            reference_state(&live),
            Some(ReferenceState::Held(2)),
            "the refused descriptor released nothing"
        );
        assert!(PosixShmResolver.resolve(&live).is_some());
        assert_eq!(reference_state(&live), Some(ReferenceState::Held(1)));
    }

    /// R3038 -- the count saturates at zero. A descriptor names a header in a
    /// segment a peer made, so a replayed one must not wrap the count to four
    /// billion and strand the chunk for good.
    #[test]
    fn a_replayed_descriptor_cannot_drive_the_count_below_zero() {
        let payload = ShmBackedPayload::alloc(2).expect("alloc");
        let descriptor = sent(&payload);
        // Three resolves against two references: the third has nothing to give.
        for _ in 0..3 {
            let _ = PosixShmResolver.resolve(&descriptor);
        }
        assert!(
            matches!(
                reference_state(&descriptor),
                Some(ReferenceState::Held(0) | ReferenceState::Reclaimed)
            ),
            "never a wrapped count"
        );
    }

    /// R3038 -- a reclaimed slot goes to the back of the queue, as upstream's
    /// does, so the next allocation does not land on it.
    #[test]
    fn a_reclaimed_slot_goes_to_the_back_of_the_queue() {
        let first = ShmBackedPayload::alloc(1).expect("alloc");
        let slot = first.descriptor().metadata_index;
        drop(first);
        let second = ShmBackedPayload::alloc(1).expect("alloc");
        assert_ne!(
            second.descriptor().metadata_index,
            slot,
            "a first-in first-out queue does not hand the reclaimed slot straight back"
        );
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
