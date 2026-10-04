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
//! # R3039 — the watchdog, and the receiver's hold
//!
//! A chunk's slot has a watchdog bit, and the protocol is two halves that never
//! meet (`crate::shm_watchdog` states it with upstream's anchors): every holder
//! CONFIRMS the bit while it holds, and the provider VALIDATES it every 100 ms,
//! marking a chunk whose bit no one set in the whole window as invalidated.
//! Here the owner's handle confirms for as long as it lives, the store validates
//! what it provides on the watchdog thread's clock, and a receiver's
//! [`ChunkHold`](crate::shm_provider::ChunkHold) confirms for as long as it holds
//! and releases its reference when it drops, which is upstream's received buffer
//! as a lifecycle, with the bytes still to come. Metadata segments a receiver
//! opens are kept, by id, and let go of once their name names another object.
//!
//! # What this increment does NOT do yet
//!
//! * No POOL: each payload still gets its own data segment, at chunk offset 0.
//! * An invalidated chunk is only MARKED, and a holder that dies without
//!   releasing leaves its chunk parked until the process ends: reclaiming is the
//!   reference count's alone, as upstream's default collection leaves it.
//! * The receiver still copies the bytes off the page into an owned buffer
//!   before it releases, so a delivered sample is not the segment.
//! * A reference taken for a frame that is then dropped before it leaves (a
//!   congestion drop after the send call returned) is never released, which is
//!   upstream's behaviour too.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use wz_session_core::extshm::{ShmDescriptor, ShmResolver};

use crate::posix_shm::{next_candidate_id, OwnedSegment, PeerSegment, PeerSegmentRw};
use crate::shm_watchdog::{confirmator, Confirmed, WatchdogBit};

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

/// The watchdog word and the mask of `slot`'s bit in a metadata segment: bit
/// `slot % 64` of word `slot / 64`, as upstream computes it.
fn watchdog_position(metadata: &Metadata, slot: u16) -> (&AtomicU64, u64) {
    (
        &metadata.watchdogs[(slot / 64) as usize],
        1u64 << (slot % 64),
    )
}

/// `slot`'s watchdog bit in the metadata segment THIS process made, kept alive
/// by the segment.
fn own_bit(segment: &Arc<OwnedSegment>, slot: u16) -> WatchdogBit {
    let metadata =
        metadata_of(segment.bytes()).expect("the segment was created at size_of::<Metadata>()");
    let (word, mask) = watchdog_position(metadata, slot);
    WatchdogBit::new(word, mask, segment.clone())
}

/// `slot`'s watchdog bit in a metadata segment a PEER made, or `None` when the
/// segment is not a metadata segment.
fn peer_bit(segment: &Arc<PeerSegmentRw>, slot: u16) -> Option<WatchdogBit> {
    let metadata = metadata_of_rw(segment)?;
    if slot as usize >= METADATA_SLOTS {
        return None;
    }
    let (word, mask) = watchdog_position(metadata, slot);
    Some(WatchdogBit::new(word, mask, segment.clone()))
}

/// This process's metadata segment, the slots it has not handed out, and the
/// chunks that were handed out and have not come home.
struct MetadataStore {
    segment: Arc<OwnedSegment>,
    id: u16,
    /// First in, first out, as upstream's `available` queue is: a reclaimed slot
    /// goes to the back, so a stale descriptor meets a reused slot as late as it
    /// can, on top of the generation check that refuses it then.
    free: VecDeque<u16>,
    busy: Vec<BusyChunk>,
    /// The slots whose chunks this provider watches: upstream's validator list.
    /// A slot joins at allocation and leaves when it is reclaimed or when its
    /// chunk is invalidated, after which there is nothing left to watch.
    validating: BTreeSet<u16>,
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
            segment: Arc::new(segment),
            id,
            free,
            busy: Vec::new(),
            validating: BTreeSet::new(),
        })
    }

    /// One validation pass: upstream's validator tick. For every chunk this
    /// provider watches, clear its bit and read what it was; a bit that was not
    /// set means no holder confirmed since the last pass, so the chunk's header is
    /// marked invalidated and the provider stops watching it. Returns how many
    /// chunks were invalidated.
    ///
    /// The header is only MARKED. Reclaiming a chunk is the count's alone
    /// (`collect_garbage`), as upstream's default collection leaves it.
    fn validate(&mut self) -> usize {
        let metadata = metadata_of(self.segment.bytes())
            .expect("the segment was created at size_of::<Metadata>()");
        let mut invalidated = Vec::new();
        for &slot in &self.validating {
            let (word, mask) = watchdog_position(metadata, slot);
            let was = word.fetch_and(!mask, Ordering::SeqCst) & mask;
            if was == 0 {
                metadata.headers[slot as usize]
                    .watchdog_invalidated
                    .store(true, Ordering::Relaxed);
                invalidated.push(slot);
            }
        }
        for slot in &invalidated {
            self.validating.remove(slot);
        }
        invalidated.len()
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
            self.validating.remove(&chunk.slot);
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
    /// The owner's confirmation of its chunk's watchdog bit, kept up for as long
    /// as the handle lives and let go with it: upstream's buffer holds one the
    /// same way. After that only a receiver's confirmation keeps the chunk valid.
    _confirmed: Confirmed,
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
        // THE WATCHDOG, in upstream's order: the slot's bit is reset (a previous
        // use left whatever it left), the owner confirms at once, and only then
        // does the provider start validating, so the first validation finds a
        // confirmed bit and not an empty one.
        let bit = own_bit(&store.segment, slot);
        bit.validate();
        let confirmed = confirmator().add(bit);
        store.validating.insert(slot);
        Ok(Self {
            data: Some(data),
            len,
            metadata_id: store.id,
            slot,
            generation,
            _confirmed: confirmed,
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

/// The metadata segments this process has opened as a reader, by id, so a
/// receiver maps a provider's segment once and not once per sample: upstream
/// links a metadata segment the first time it sees it and keeps the mapping
/// (`commons/zenoh-shm/src/metadata/subscription.rs`).
fn peer_metadata_cache() -> &'static Mutex<HashMap<u64, Arc<PeerSegmentRw>>> {
    static CACHE: OnceLock<Mutex<HashMap<u64, Arc<PeerSegmentRw>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The provider's metadata segment named `id`, mapped WRITABLE (a release is a
/// write), from the cache when its entry is still the object the name names.
fn peer_metadata(id: u16) -> Option<Arc<PeerSegmentRw>> {
    let id = u64::from(id);
    let mut cache = peer_metadata_cache().lock().ok()?;
    if let Some(segment) = cache.get(&id) {
        if segment.is_current() {
            return Some(segment.clone());
        }
        // The provider is gone, or another process has made a segment under its
        // name: a mapping of the old object would read a dead header as live.
        cache.remove(&id);
    }
    let segment = Arc::new(PeerSegmentRw::open(id).ok()?);
    cache.insert(id, segment.clone());
    Some(segment)
}

/// Let go of cached mappings whose segment no longer exists, so a provider that
/// exited does not stay mapped and locked in this process until it does. Run by
/// the watchdog thread; a hold in use keeps its own reference to its mapping.
pub(crate) fn sweep_peer_metadata() {
    if let Ok(mut cache) = peer_metadata_cache().lock() {
        cache.retain(|_, segment| segment.is_current());
    }
}

/// One validation pass over what this process provides: the watchdog thread's
/// call into the provider.
pub(crate) fn validate_tick() {
    if let Ok(mut guard) = store().lock() {
        if let Some(store) = guard.as_mut() {
            store.validate();
        }
    }
}

/// A receiver's hold on one chunk: upstream's received `ShmBufInner`, as the
/// lifecycle of a buffer and not yet its bytes.
///
/// While it lives the chunk's watchdog bit is confirmed (the holder is alive),
/// and when it drops it gives back the reference the sender took for it. Both
/// are what upstream's buffer does, and holding the bytes of a delivered sample
/// without copying them is the same thing with the bytes added.
///
/// Linking a descriptor takes nothing from the chunk: the sender took the
/// reference when it serialized the descriptor, and a read takes none
/// (`commons/zenoh-shm/src/reader.rs` @
/// `// Read does not increment the reference count as it is assumed`).
pub struct ChunkHold {
    metadata: Arc<PeerSegmentRw>,
    descriptor: ShmDescriptor,
    /// Declared after `metadata` on purpose: the bit it confirms is in that
    /// mapping, and the confirmator keeps its own reference to the mapping, so
    /// either order is sound; this one only reads as the order they are made in.
    _confirmed: Option<Confirmed>,
}

impl ChunkHold {
    /// Link a received descriptor: open (or reuse) the provider's metadata
    /// segment, check that the header at the descriptor's slot is still of the
    /// descriptor's generation, and attach to the chunk's watchdog before doing
    /// anything else, as upstream's reader does ("attach to the watchdog before
    /// doing other things").
    ///
    /// `None` when the metadata segment cannot be opened, or when the slot's
    /// generation is not the descriptor's: that reference is not this receiver's
    /// to give back, so nothing is touched.
    pub fn link(descriptor: &ShmDescriptor) -> Option<Self> {
        let metadata = peer_metadata(descriptor.metadata_id)?;
        let header = metadata_of_rw(&metadata)?
            .headers
            .get(descriptor.metadata_index as usize)?;
        if header.generation.load(Ordering::SeqCst) != descriptor.generation {
            return None;
        }
        let confirmed =
            peer_bit(&metadata, descriptor.metadata_index).map(|bit| confirmator().add(bit));
        Some(Self {
            metadata,
            descriptor: *descriptor,
            _confirmed: confirmed,
        })
    }

    fn header(&self) -> Option<&ChunkHeader> {
        metadata_of_rw(&self.metadata)?
            .headers
            .get(self.descriptor.metadata_index as usize)
    }

    /// Whether the chunk is still the buffer the descriptor names and has not
    /// been invalidated: upstream's `is_valid`
    /// (`commons/zenoh-shm/src/lib.rs` @ `fn is_valid(&self) -> bool {`).
    pub fn is_valid(&self) -> bool {
        match self.header() {
            Some(header) => {
                !header.watchdog_invalidated.load(Ordering::SeqCst)
                    && header.generation.load(Ordering::SeqCst) == self.descriptor.generation
            }
            None => false,
        }
    }

    /// Copy the chunk's bytes out of the shared page (the bounded scoped copy
    /// into an owned buffer), or `None` when the chunk is not valid, names a
    /// protocol this node does not speak, claims more than its length, or its data
    /// segment will not open.
    pub fn read(&self) -> Option<Vec<u8>> {
        let header = self.header()?;
        if header.watchdog_invalidated.load(Ordering::Acquire)
            || header.protocol.load(Ordering::Relaxed) != POSIX_PROTOCOL_ID
        {
            return None;
        }
        let data_len = self.descriptor.data_len as usize;
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

impl Drop for ChunkHold {
    fn drop(&mut self) {
        if let Some(header) = self.header() {
            release_reference(header);
        }
    }
}

/// The reader-side resolver: the AP impl of the no_std [`ShmResolver`] seam.
///
/// Follows a descriptor as upstream's reader does: [`ChunkHold::link`] it, read
/// the bytes off the shared page into an owned buffer, and let the hold go.
#[derive(Debug, Clone, Copy, Default)]
pub struct PosixShmResolver;

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
        let hold = ChunkHold::link(descriptor)?;
        hold.read()
    }
}

/// Whether a descriptor's chunk has been invalidated by its provider's watchdog:
/// `Some(true)` once no holder confirmed it for a whole validation window,
/// `None` when the provider's metadata segment cannot be opened or the slot
/// holds another generation. A diagnostic, like [`reference_state`].
pub fn is_invalidated(descriptor: &ShmDescriptor) -> Option<bool> {
    let segment = PeerSegment::open(u64::from(descriptor.metadata_id)).ok()?;
    let header = metadata_of(segment.bytes())?
        .headers
        .get(descriptor.metadata_index as usize)?;
    if header.generation.load(Ordering::SeqCst) != descriptor.generation {
        return None;
    }
    Some(header.watchdog_invalidated.load(Ordering::SeqCst))
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

    /// A slot of a PRIVATE store, watched as an allocation watches it: the bit
    /// reset and the slot on the validator's list. A private store is not the
    /// process's, so the watchdog thread never validates it and a test drives the
    /// windows itself.
    fn watched_slot(store: &mut MetadataStore) -> u16 {
        let slot = store.free.pop_front().expect("a free slot");
        header_of(&store.segment, slot)
            .refcount
            .store(1, Ordering::SeqCst);
        own_bit(&store.segment, slot).validate();
        store.validating.insert(slot);
        slot
    }

    /// R3039 -- a chunk nobody confirmed for a whole window is invalidated, and the
    /// provider stops watching it. The first window is confirmed, the second is
    /// not: upstream's validator reads the bit and clears it, and finds it clear.
    #[test]
    fn a_provider_invalidates_a_chunk_nobody_confirmed_for_a_window() {
        let mut store = MetadataStore::create().expect("a private store");
        let slot = watched_slot(&mut store);

        own_bit(&store.segment, slot).confirm();
        assert_eq!(store.validate(), 0, "confirmed in the window, so valid");
        assert!(!header_of(&store.segment, slot)
            .watchdog_invalidated
            .load(Ordering::SeqCst));

        assert_eq!(store.validate(), 1, "nobody confirmed in the next window");
        assert!(header_of(&store.segment, slot)
            .watchdog_invalidated
            .load(Ordering::SeqCst));
        assert!(
            !store.validating.contains(&slot),
            "an invalidated chunk is not watched again"
        );
        assert_eq!(store.validate(), 0);
    }

    /// R3039 -- a chunk that is confirmed in every window is never invalidated,
    /// however many windows pass: confirming once per window is the whole of a
    /// holder's duty.
    #[test]
    fn a_chunk_confirmed_in_every_window_stays_valid() {
        let mut store = MetadataStore::create().expect("a private store");
        let slot = watched_slot(&mut store);
        let bit = own_bit(&store.segment, slot);
        for _ in 0..8 {
            bit.confirm();
            assert_eq!(store.validate(), 0);
        }
        assert!(!header_of(&store.segment, slot)
            .watchdog_invalidated
            .load(Ordering::SeqCst));
    }

    /// R3039 -- A RECEIVER'S HOLD IS WHAT KEEPS A CHUNK ITS PROVIDER NO LONGER
    /// HOLDS VALID, and letting go gives the reference back.
    ///
    /// The descriptor points into a private store, so the validation windows are
    /// this test's to drive. Linking confirms at once; the hold stays confirmed
    /// across windows by the confirmator's pass; and once it drops nothing
    /// confirms, so the provider invalidates the chunk, and the reference the
    /// sender took for it is back.
    #[test]
    fn a_hold_keeps_its_chunk_confirmed_until_it_lets_go_and_releases_on_drop() {
        let mut store = MetadataStore::create().expect("a private store");
        let slot = watched_slot(&mut store);
        // Through the segment's own handle, so the header is not a borrow of the
        // store the windows below need to drive mutably.
        let segment = store.segment.clone();
        let header = header_of(&segment, slot);
        header.protocol.store(POSIX_PROTOCOL_ID, Ordering::Relaxed);
        header.len.store(4, Ordering::Relaxed);
        // The owner is gone; the descriptor's reference is the only one.
        let descriptor = ShmDescriptor {
            data_len: 4,
            metadata_id: store.id,
            metadata_index: slot,
            generation: header.generation.load(Ordering::SeqCst),
        };
        // Nothing has confirmed since the slot was watched.

        let hold =
            ChunkHold::link(&descriptor).expect("the header is of the descriptor's generation");
        assert_eq!(store.validate(), 0, "linking confirmed before any tick");
        assert!(hold.is_valid());

        confirmator().tick();
        assert_eq!(
            store.validate(),
            0,
            "the pass confirms a held chunk each window"
        );
        confirmator().tick();
        assert_eq!(store.validate(), 0);
        assert_eq!(
            header.refcount.load(Ordering::SeqCst),
            1,
            "linking takes no reference"
        );

        drop(hold);
        assert_eq!(
            header.refcount.load(Ordering::SeqCst),
            0,
            "letting go gave the sender's reference back"
        );
        // The last pass may have left the bit set; the window after it cannot.
        // Each window is a real one, longer than the watchdog thread's confirm
        // period: a hold that left its bit tracked would be confirmed again by
        // that thread between the two validations, and back-to-back validations
        // would never give it the chance to.
        let mut invalidated = 0;
        for _ in 0..2 {
            std::thread::sleep(std::time::Duration::from_millis(120));
            invalidated += store.validate();
        }
        assert_eq!(invalidated, 1, "no one holds it, so no one confirmed");
        assert!(header.watchdog_invalidated.load(Ordering::SeqCst));
    }

    /// R3039 -- a hold on a header of ANOTHER generation links nothing and touches
    /// nothing: that reference is another buffer's.
    #[test]
    fn a_hold_of_the_wrong_generation_links_nothing() {
        let mut store = MetadataStore::create().expect("a private store");
        let slot = watched_slot(&mut store);
        let header = header_of(&store.segment, slot);
        let descriptor = ShmDescriptor {
            data_len: 4,
            metadata_id: store.id,
            metadata_index: slot,
            generation: header.generation.load(Ordering::SeqCst).wrapping_add(1),
        };
        assert!(ChunkHold::link(&descriptor).is_none());
        assert_eq!(
            header.refcount.load(Ordering::SeqCst),
            1,
            "no reference was touched"
        );
    }

    /// R3039 -- THE RUNNING WATCHDOG: a chunk its owner has let go of and no
    /// receiver holds is invalidated by the process's own watchdog thread, with no
    /// tick driven by the test. Only that the thread acts is asserted, with a long
    /// deadline, so a slow runner cannot fail it; what a window means is the
    /// private-store tests' to say.
    #[test]
    fn the_running_watchdog_invalidates_a_parked_chunk_nobody_holds() {
        let payload = ShmBackedPayload::alloc(4).expect("alloc");
        let descriptor = sent(&payload);
        drop(payload);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match is_invalidated(&descriptor) {
                Some(true) => break,
                Some(false) => {}
                None => panic!("the chunk was collected while a reference was outstanding"),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the watchdog never invalidated a chunk no one holds"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        // Give the reference back so the chunk can be collected.
        assert!(
            PosixShmResolver.resolve(&descriptor).is_none(),
            "invalidated, so refused"
        );
    }
}
