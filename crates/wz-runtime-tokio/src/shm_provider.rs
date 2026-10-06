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
//! # R3056 — a PROVIDER, and a pool
//!
//! Until this round a payload WAS a data segment: created for it, named by it, unlinked with
//! it. That gives a publisher that sends one buffer exactly what it needs and gives a program
//! that allocates a chunk out of a fixed-size pool once a second nothing at all, which is the
//! program upstream's own examples are. The lifecycle above is now the PROVIDER's
//! ([`ShmProvider`](crate::shm_provider::ShmProvider)), not the payload's, and the memory under it is a
//! [`ShmProviderBackend`](crate::shm_backend::ShmProviderBackend):
//!
//! * a backend allocates and frees chunks of its segments
//!   ([`crate::shm_posix_backend`] is the built-in pool);
//! * the provider draws a metadata slot for each chunk, writes the header a receiver follows,
//!   keeps the chunk on its busy list, and gives its memory back to the backend only when the
//!   reference count reads zero (`commons/zenoh-shm/src/api/provider/shm_provider.rs` @
//!   `fn garbage_collect_impl<const SAFE: bool>(&self) -> usize {`);
//! * a policy ([`AllocPolicy`](crate::shm_provider::AllocPolicy)) says what an allocation does when the backend cannot serve
//!   it: collect, defragment, take back the newest chunk held or not, or wait.
//!
//! [`ShmBackedPayload::alloc`](crate::shm_provider::ShmBackedPayload::alloc) is a provider whose pool is one payload, so everything above
//! still holds for it and nothing about its callers changed.
//!
//! A provider a program holds is collected when the program (or its policy) says so, as
//! upstream's is: a program that watches how much of a pool is in use must not have the
//! process quietly empty it. A provider whose last handle is gone is collected by the
//! process, because chunks it issued may be in flight and nobody else can take them home.
//!
//! # What this increment does NOT do yet
//!
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

use wz_session_core::extshm::{ShmDescriptor, ShmReservation, ShmResolver, ShmSendBuffer};
use wz_session_core::link::{RxBytes, RxStorage, ShmChunkView};

use crate::posix_shm::{next_candidate_id, OwnedSegment, PeerSegment, PeerSegmentRw};
use crate::shm_backend::{
    AllocError, AllocatedChunk, ChunkDescriptor, LayoutAllocError, LayoutError, MemoryLayout,
    PtrInSegment, ShmProviderBackend,
};
use crate::shm_clients::{ShmClientSet, ShmDataSegment};
use crate::shm_posix_backend::PosixShmProviderBackend;
use crate::shm_watchdog::{confirmator, Confirmed, WatchdogBit};

/// What the pool of a lone payload has beyond the payload: the room its allocator needs.
/// Talc claims about a kilobyte of its arena for its own bins and spends a few bytes of
/// header on every chunk, and a pool smaller than its bins cannot be made at all
/// (see [`crate::shm_posix_backend`]), so a pool for one chunk of `len` bytes is `len`
/// plus this, with room to spare.
const SINGLE_PAYLOAD_POOL_HEADROOM: usize = 4096;

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

/// A chunk its provider issued and has not taken back: the metadata slot that
/// describes it and where it lies, kept until every holder has let go
/// (`commons/zenoh-shm/src/api/provider/shm_provider.rs` @ `struct BusyChunk {`).
///
/// The descriptor is what the backend is handed back when the chunk comes home,
/// and it is held here and not read back out of the slot's header because a header
/// is shared memory a receiver can write, and the memory a backend frees must not
/// be whatever a stranger wrote there.
#[derive(Clone, Copy)]
struct BusyChunk {
    slot: u16,
    descriptor: ChunkDescriptor,
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

/// This process's metadata segment and the slots it has not handed out.
///
/// ONE per process, as upstream's `GLOBAL_METADATA_STORAGE` is: the slots are a
/// shared resource every provider of the process draws from, and a receiver maps
/// the segment once however many providers fill it. The chunks that were handed out
/// and have not come home are NOT here since R3056: they are each provider's own
/// (`ProviderCore::busy`), because only the provider that issued a chunk can give
/// its memory back to the backend that holds it.
struct MetadataStore {
    segment: Arc<OwnedSegment>,
    id: u16,
    /// First in, first out, as upstream's `available` queue is: a reclaimed slot
    /// goes to the back, so a stale descriptor meets a reused slot as late as it
    /// can, on top of the generation check that refuses it then.
    free: VecDeque<u16>,
    /// The slots whose chunks the providers of this process watch: upstream's
    /// validator list. A slot joins at allocation and leaves when it is reclaimed
    /// or when its chunk is invalidated, after which there is nothing left to watch.
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

    /// Make `slots` stale: advance each one's generation, which turns every
    /// descriptor still naming it into one a receiver refuses, and stop watching it.
    ///
    /// Done BEFORE the chunk's memory goes back to its backend (see
    /// [`ProviderCore::take_back`]), so a descriptor that outlived its chunk can never
    /// be followed into memory the backend has already handed to another chunk.
    fn make_stale(&mut self, slots: &[u16]) {
        for &slot in slots {
            header_of(&self.segment, slot)
                .generation
                .fetch_add(1, Ordering::SeqCst);
            self.validating.remove(&slot);
        }
    }

    /// Put `slots` on the back of the free queue, once their chunks are home.
    fn recycle(&mut self, slots: &[u16]) {
        self.free.extend(slots.iter().copied());
    }
}

/// This process's metadata segment if one has been made, without making it.
fn existing_metadata() -> Option<Arc<OwnedSegment>> {
    store()
        .lock()
        .ok()?
        .as_ref()
        .map(|store| store.segment.clone())
}

/// The process-wide store, created on first use. `None` inside means the
/// creation failed; it is retried on the next allocation.
fn store() -> &'static Mutex<Option<MetadataStore>> {
    static STORE: OnceLock<Mutex<Option<MetadataStore>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(None))
}

// ---------------------------------------------------------------------------
// the provider
// ---------------------------------------------------------------------------

/// What a provider keeps for the chunks it issued: its backend, the chunks not yet
/// taken back, and how many [`ShmProvider`] handles are alive.
///
/// Shared by the handles, by every payload it issued, and by the process-wide
/// registry (see [`registry`]), because the chunks outlive the handle on purpose:
/// a publisher that lets go of its payload the moment it has sent it, or that drops
/// its provider, leaves a descriptor in flight that a receiver will follow later, and
/// the memory it names must stay until that receiver has let go.
struct ProviderCore {
    backend: Arc<dyn ShmProviderBackend>,
    /// Upstream's `busy_list`: a chunk is on it from the moment it is issued until the
    /// provider takes it back.
    busy: Mutex<Vec<BusyChunk>>,
    /// The live [`ShmProvider`] handles. At zero the provider is an ORPHAN: nobody can
    /// ask it to collect, so the process does it, and it goes when it has nothing left
    /// to give back.
    handles: AtomicUsize,
}

impl ProviderCore {
    fn is_orphan(&self) -> bool {
        self.handles.load(Ordering::Acquire) == 0
    }

    fn busy(&self) -> std::sync::MutexGuard<'_, Vec<BusyChunk>> {
        // A panic while the list was held cannot leave it torn: every mutation is one
        // statement sequence with no `?` in it.
        self.busy.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Take back every chunk nobody holds and return the size of the largest: upstream's
    /// garbage collection (`commons/zenoh-shm/src/api/provider/shm_provider.rs` @
    /// `fn garbage_collect_impl<const SAFE: bool>(&self) -> usize {`).
    ///
    /// SAFE collection takes a chunk when its count reads zero and on nothing else. The
    /// unsafe form also takes one its watchdog invalidated, which is a chunk a holder may
    /// still be reading: the caller is the one who knows there is none.
    fn collect(&self, safe: bool) -> usize {
        let Some(metadata) = existing_metadata() else {
            return 0;
        };
        let mut due = Vec::new();
        {
            let mut busy = self.busy();
            let mut i = 0;
            while i < busy.len() {
                let header = header_of(&metadata, busy[i].slot);
                if header.refcount.load(Ordering::SeqCst) == 0
                    || (!safe && header.watchdog_invalidated.load(Ordering::SeqCst))
                {
                    due.push(busy.swap_remove(i));
                } else {
                    i += 1;
                }
            }
        }
        self.take_back(&due)
    }

    /// Take back the NEWEST chunk whether or not anybody holds it: upstream's
    /// `Deallocate` policy, which is unsafe by its own account. `false` when there is
    /// none.
    fn reclaim_newest(&self) -> bool {
        let Some(chunk) = self.busy().pop() else {
            return false;
        };
        self.take_back(&[chunk]);
        true
    }

    /// Give chunks back. In this order, and the order is the safety: their slots go
    /// stale first, so a descriptor that outlived its chunk is refused on the generation;
    /// then the memory goes back to the backend, which may hand it to another chunk at
    /// once; then the slots go back on the queue. Returns the size of the largest chunk.
    ///
    /// The backend is called with no lock of this module held, because a backend a host
    /// supplies may allocate a chunk of its own from inside `free`.
    fn take_back(&self, chunks: &[BusyChunk]) -> usize {
        if chunks.is_empty() {
            return 0;
        }
        let slots: Vec<u16> = chunks.iter().map(|chunk| chunk.slot).collect();
        if let Ok(mut guard) = store().lock() {
            if let Some(store) = guard.as_mut() {
                store.make_stale(&slots);
            }
        }
        let mut largest = 0;
        for chunk in chunks {
            self.backend.free(&chunk.descriptor);
            largest = largest.max(chunk.descriptor.len.get());
        }
        if let Ok(mut guard) = store().lock() {
            if let Some(store) = guard.as_mut() {
                store.recycle(&slots);
            }
        }
        largest
    }
}

/// Every provider of this process that is alive or still owes a chunk back.
///
/// A provider whose handle is gone but whose chunks are in flight must still be
/// collected, and by someone: this is how. It is swept when the watchdog thread ticks
/// and when anything allocates, and a provider leaves it when it is an orphan with
/// nothing on its busy list, which drops the backend and with it the segment.
fn registry() -> &'static Mutex<Vec<Arc<ProviderCore>>> {
    static REGISTRY: OnceLock<Mutex<Vec<Arc<ProviderCore>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

/// Collect every orphaned provider, and forget the ones that have nothing left.
///
/// Live providers are NOT touched: upstream collects when its caller asks (or its
/// policy does), and a program that watches how much a pool holds must not have the
/// process quietly empty it.
fn sweep_orphans() {
    // WEAK references, upgraded one at a time: a snapshot of strong ones would hold every
    // provider of the process alive for as long as the sweep runs, and a provider that
    // was the last holder of its segment could not unlink it while another thread swept.
    let snapshot: Vec<std::sync::Weak<ProviderCore>> = match registry().lock() {
        Ok(list) => list.iter().map(Arc::downgrade).collect(),
        Err(_) => return,
    };
    for core in &snapshot {
        if let Some(core) = core.upgrade() {
            if core.is_orphan() {
                core.collect(true);
            }
        }
    }
    forget_finished(None);
}

/// Take the providers that are orphans with nothing left to give back out of the
/// registry (all of them, or only `only`), and let go of them AFTER the registry's lock
/// is released.
///
/// Letting go of the last reference to a provider drops its backend, and a backend a host
/// supplies runs the host's code when it drops. That code may allocate a chunk, which sweeps,
/// which takes this lock: dropping under it would deadlock on a lock the same thread holds.
fn forget_finished(only: Option<&Arc<ProviderCore>>) {
    let finished: Vec<Arc<ProviderCore>> = {
        let Ok(mut list) = registry().lock() else {
            return;
        };
        let mut finished = Vec::new();
        let mut i = 0;
        while i < list.len() {
            let core = &list[i];
            let selected = match only {
                Some(only) => Arc::ptr_eq(only, core),
                None => true,
            };
            if selected && core.is_orphan() && core.busy().is_empty() {
                finished.push(list.swap_remove(i));
            } else {
                i += 1;
            }
        }
        finished
    };
    drop(finished);
}

/// Drop `core` from the registry if it is an orphan with nothing left to give back.
///
/// The one-provider-one-payload case ends here the moment its owner lets go and every
/// receiver already has, instead of waiting for the next sweep.
fn forget_if_finished(core: &Arc<ProviderCore>) {
    forget_finished(Some(core));
}

/// How an allocation reacts to a backend that cannot serve it: upstream's policies
/// (`commons/zenoh-shm/src/api/provider/shm_provider.rs` @ `pub struct JustAlloc;`,
/// `GarbageCollect`, `Defragment`, `Deallocate`, `BlockOn`), which compose.
///
/// A runtime value and not a type parameter, because the C ABI above this crate picks
/// its policy by which function the program called, and a program's call is a runtime
/// fact.
#[derive(Clone, Debug)]
pub enum AllocPolicy {
    /// Ask the backend once.
    JustAlloc,
    /// Ask `inner`; if that fails, collect, and if the collection returned a chunk at
    /// least as large as the request, ask `alt`. `safe` selects safe collection.
    GarbageCollect {
        /// The first attempt.
        inner: Box<AllocPolicy>,
        /// The attempt after a collection that freed enough.
        alt: Box<AllocPolicy>,
        /// Whether the collection takes only chunks nobody holds.
        safe: bool,
    },
    /// Ask `inner`; if the backend says it needs defragmenting and defragmenting
    /// yields a chunk big enough, ask `alt`.
    Defragment {
        /// The first attempt.
        inner: Box<AllocPolicy>,
        /// The attempt after a defragmentation that freed enough.
        alt: Box<AllocPolicy>,
    },
    /// Ask `inner`; if the backend cannot serve it, take back the newest chunk WHETHER
    /// OR NOT it is held, and ask again, up to `limit` times, then ask `alt`. Unsafe: the
    /// chunk it takes may be one a holder is reading.
    Deallocate {
        /// How many chunks to take back before giving up.
        limit: usize,
        /// The attempt each round.
        inner: Box<AllocPolicy>,
        /// The attempt after `limit` chunks were taken back.
        alt: Box<AllocPolicy>,
    },
    /// Ask `inner` until it succeeds or fails for a reason waiting cannot fix,
    /// sleeping a millisecond between attempts as upstream's does (it polls; nothing
    /// signals a release made by another process). It stops when the provider has no
    /// chunk outstanding, because then nothing could ever be released: upstream waits
    /// forever there, and this is the single point where this policy returns where
    /// upstream's does not.
    BlockOn(Box<AllocPolicy>),
}

impl AllocPolicy {
    /// `GarbageCollect` with safe collection.
    pub fn garbage_collect(inner: AllocPolicy, alt: AllocPolicy) -> Self {
        Self::GarbageCollect {
            inner: Box::new(inner),
            alt: Box::new(alt),
            safe: true,
        }
    }

    /// `Defragment`.
    pub fn defragment(inner: AllocPolicy, alt: AllocPolicy) -> Self {
        Self::Defragment {
            inner: Box::new(inner),
            alt: Box::new(alt),
        }
    }

    /// `Deallocate`.
    pub fn deallocate(limit: usize, inner: AllocPolicy, alt: AllocPolicy) -> Self {
        Self::Deallocate {
            limit,
            inner: Box::new(inner),
            alt: Box::new(alt),
        }
    }

    /// `BlockOn`.
    pub fn block_on(inner: AllocPolicy) -> Self {
        Self::BlockOn(Box::new(inner))
    }

    fn run(
        &self,
        layout: &MemoryLayout,
        core: &ProviderCore,
    ) -> Result<AllocatedChunk, AllocError> {
        match self {
            AllocPolicy::JustAlloc => core.backend.alloc(layout),
            AllocPolicy::GarbageCollect { inner, alt, safe } => {
                let result = inner.run(layout, core);
                if result.is_err() {
                    // Ask again only if the collection freed a chunk big enough to matter.
                    let collected = core.collect(*safe);
                    if collected >= layout.size().get() {
                        return alt.run(layout, core);
                    }
                }
                result
            }
            AllocPolicy::Defragment { inner, alt } => {
                let result = inner.run(layout, core);
                if let Err(AllocError::NeedDefragment) = result {
                    if core.backend.defragment() >= layout.size().get() {
                        return alt.run(layout, core);
                    }
                }
                result
            }
            AllocPolicy::Deallocate { limit, inner, alt } => {
                for _ in 0..*limit {
                    match inner.run(layout, core) {
                        res @ Err(AllocError::NeedDefragment | AllocError::OutOfMemory) => {
                            if !core.reclaim_newest() {
                                return res;
                            }
                        }
                        other => return other,
                    }
                }
                alt.run(layout, core)
            }
            AllocPolicy::BlockOn(inner) => loop {
                match inner.run(layout, core) {
                    res @ Err(AllocError::NeedDefragment | AllocError::OutOfMemory) => {
                        // THE ONE PLACE this differs from upstream's, which sleeps and asks
                        // again forever: with nothing on the provider's busy list there is
                        // no chunk whose release could ever make room, so waiting is a hang
                        // and not a wait (a request larger than the whole pool is the usual
                        // case). The refusal is returned instead. A chunk another process
                        // still holds IS on the list, so a wait that can end still waits.
                        if core.busy().is_empty() {
                            return res;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    other => return other,
                }
            },
        }
    }
}

/// A provider of shared-memory chunks: a backend, and the lifecycle of what it issued
/// (`commons/zenoh-shm/src/api/provider/shm_provider.rs` @
/// `pub struct ShmProvider<Backend> {`).
///
/// It draws a metadata slot for every chunk, watches it, and keeps the chunk on a busy
/// list until the reference count reads zero; only then does the memory go back to the
/// backend. A handle is cheap to clone. Dropping the last one does not end the provider:
/// chunks it issued stay valid until their holders let go, and the process collects them.
pub struct ShmProvider {
    core: Arc<ProviderCore>,
}

impl ShmProvider {
    /// A provider over `backend`.
    pub fn new(backend: Arc<dyn ShmProviderBackend>) -> Self {
        let core = Arc::new(ProviderCore {
            backend,
            busy: Mutex::new(Vec::new()),
            handles: AtomicUsize::new(1),
        });
        if let Ok(mut list) = registry().lock() {
            list.push(core.clone());
        }
        Self { core }
    }

    /// A provider over a new POSIX pool of `layout.size()` bytes: upstream's default
    /// backend.
    pub fn pool(layout: &MemoryLayout) -> io::Result<Self> {
        Ok(Self::new(Arc::new(PosixShmProviderBackend::new(layout)?)))
    }

    /// The protocol id of this provider's chunks.
    pub fn protocol_id(&self) -> u32 {
        self.core.backend.id()
    }

    /// `layout` as this provider's backend would serve it, or why it cannot.
    ///
    /// Whatever the backend refuses with, the provider answers
    /// [`LayoutError::ProviderIncompatibleLayout`]: the layout was well formed (the caller
    /// built it) and THIS provider cannot serve it, which is how upstream reports it
    /// (`commons/zenoh-shm/src/api/provider/shm_provider.rs` @
    /// `.map_err(|_| ZLayoutError::ProviderIncompatibleLayout)?;`), and what the real
    /// library's C ABI shows for a 32-byte-aligned request on a default provider.
    pub fn layout_for(&self, layout: MemoryLayout) -> Result<MemoryLayout, LayoutError> {
        self.core
            .backend
            .layout_for(layout)
            .map_err(|_| LayoutError::ProviderIncompatibleLayout)
    }

    /// Allocate a chunk for `layout` under `policy`.
    ///
    /// The layout is checked against the backend first, and the backend is asked for the
    /// layout it returned, which may be larger. The payload's length is the length that
    /// was asked for.
    pub fn alloc(
        &self,
        layout: MemoryLayout,
        policy: &AllocPolicy,
    ) -> Result<ShmBackedPayload, LayoutAllocError> {
        let backend_layout = self.layout_for(layout)?;
        // Anything else's orphaned chunks come home first, so a slot or a range one of
        // them was keeping is available to this request.
        sweep_orphans();
        let chunk = policy.run(&backend_layout, &self.core)?;
        ShmBackedPayload::issue(&self.core, chunk, layout.size().get()).map_err(Into::into)
    }

    /// Wrap a chunk that something else allocated out of this provider's backend,
    /// which has the length `len` or more: upstream's `map`, for a backend that pushes
    /// chunks rather than serving a request.
    pub fn map(&self, chunk: AllocatedChunk, len: usize) -> Result<ShmBackedPayload, AllocError> {
        if len == 0 || len > chunk.descriptor.len.get() || !self.core.backend.accepts(&chunk) {
            return Err(AllocError::Other);
        }
        ShmBackedPayload::issue(&self.core, chunk, len)
    }

    /// Take back every chunk nobody holds. The size of the largest, or 0.
    pub fn garbage_collect(&self) -> usize {
        self.core.collect(true)
    }

    /// As [`Self::garbage_collect`], but also takes a chunk the watchdog invalidated.
    ///
    /// # Safety
    /// No holder may be reading a chunk that has been invalidated.
    pub unsafe fn garbage_collect_unsafe(&self) -> usize {
        self.core.collect(false)
    }

    /// Defragment the backend. The size of the largest chunk now allocatable.
    pub fn defragment(&self) -> usize {
        self.core.backend.defragment()
    }

    /// Bytes the backend reports available.
    pub fn available(&self) -> usize {
        self.core.backend.available()
    }
}

impl Clone for ShmProvider {
    fn clone(&self) -> Self {
        self.core.handles.fetch_add(1, Ordering::AcqRel);
        Self {
            core: self.core.clone(),
        }
    }
}

impl Drop for ShmProvider {
    fn drop(&mut self) {
        if self.core.handles.fetch_sub(1, Ordering::AcqRel) == 1 {
            // The last handle: nobody can ask this provider to collect any more, so the
            // process takes over, and gets the first pass in at once.
            sweep_orphans();
        }
    }
}

/// An owner-side SHM-backed payload: a chunk of a provider's memory the application
/// writes its payload into, and the metadata slot that describes it to a receiver. The
/// payload is published by a descriptor instead of by bytes
/// ([`Self::wire_reference`] takes the reference that descriptor carries).
///
/// Dropping it releases the owner's own reference. The chunk is NOT taken back then
/// unless that was the last reference: a receiver that was sent the descriptor still
/// holds one, and the chunk stays until it lets go.
pub struct ShmBackedPayload {
    /// Where the bytes are in this process, with the segment that keeps them mapped:
    /// the chunk's memory stays valid for as long as this value does, whatever happens
    /// to its provider.
    data: PtrInSegment,
    len: usize,
    /// The process's metadata segment, held so the header is reachable without taking
    /// the store's lock.
    metadata: Arc<OwnedSegment>,
    metadata_id: u16,
    slot: u16,
    generation: u32,
    /// The provider that issued the chunk, to tell it when the owner lets go.
    core: Arc<ProviderCore>,
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
        self.payload.release_if_current();
    }
}

/// R3062 -- [`WireReference`] that OWNS its payload, for a message whose send outlives the
/// call that took the reference: a reply is staged by a queryable's handler and sent when the
/// handler's job drains, so the reservation travels with the staged reply and cannot borrow
/// from a stack frame. The same contract: the reference goes back unless [`ShmReservation::commit`]
/// says the frame left.
struct OwnedWireReference {
    payload: Arc<ShmBackedPayload>,
    committed: bool,
}

impl ShmReservation for OwnedWireReference {
    fn descriptor(&self) -> ShmDescriptor {
        self.payload.descriptor()
    }

    fn commit(mut self: Box<Self>) {
        self.committed = true;
    }
}

impl Drop for OwnedWireReference {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        self.payload.release_if_current();
    }
}

/// A chunk of this process's provider is a buffer a message can be sent from: the session core
/// sees the seam and never the segment.
impl ShmSendBuffer for ShmBackedPayload {
    fn bytes(&self) -> &[u8] {
        ShmBackedPayload::bytes(self)
    }

    fn protocol(&self) -> u32 {
        ShmBackedPayload::protocol(self)
    }

    fn receiver_view(&self) -> Option<RxBytes> {
        ShmBackedPayload::receiver_view(self)
    }

    fn reserve_for_receiver(self: Arc<Self>) -> Box<dyn ShmReservation> {
        self.take_reference();
        Box::new(OwnedWireReference {
            payload: self,
            committed: false,
        })
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
    /// Allocate a `len`-byte payload in a pool of its own: a new POSIX segment big enough
    /// for that one chunk and its allocator's overhead, the chunk, and a metadata slot
    /// whose header names it.
    ///
    /// This is a provider whose pool is one payload, which is what a publisher that sends
    /// one buffer wants and what this function has always been; a program that allocates
    /// many builds a [`ShmProvider`] and allocates from it. `len` must be non-zero —
    /// upstream's `data_len` is a `NonZeroUsize`, so a 0-byte descriptor is not one a
    /// receiver takes.
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
        let layout = MemoryLayout::of_size(len)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        // The pool is the chunk plus the room its allocator needs around it: talc claims
        // part of its arena for its own bins and spends a header on the chunk, so a pool
        // of exactly `len` bytes could not be made, let alone serve the chunk.
        let pool_size = len
            .checked_add(SINGLE_PAYLOAD_POOL_HEADROOM)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "an SHM payload is too large")
            })?;
        let pool = MemoryLayout::of_size(pool_size)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        // The handle goes out of scope at the end of this function and the provider
        // becomes an orphan holding one chunk, which is the point: the process collects it
        // when the owner and every receiver have let go.
        let provider = ShmProvider::pool(&pool)?;
        provider
            .alloc(layout, &AllocPolicy::JustAlloc)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    /// Wrap a chunk the backend allocated: draw its metadata slot, write the header a
    /// receiver follows, and put the chunk on the provider's busy list.
    ///
    /// On a failure the chunk goes back to the backend, so a refusal here never loses
    /// memory (upstream's own comment: "don't lose this chunk, it leaks at the backend").
    fn issue(
        core: &Arc<ProviderCore>,
        chunk: AllocatedChunk,
        len: usize,
    ) -> Result<Self, AllocError> {
        match Self::draw_slot(core, &chunk) {
            Ok(slot) => {
                core.busy().push(BusyChunk {
                    slot: slot.slot,
                    descriptor: chunk.descriptor,
                });
                Ok(Self {
                    data: chunk.data,
                    len,
                    metadata: slot.metadata,
                    metadata_id: slot.metadata_id,
                    slot: slot.slot,
                    generation: slot.generation,
                    core: core.clone(),
                    _confirmed: slot.confirmed,
                })
            }
            Err(e) => {
                core.backend.free(&chunk.descriptor);
                Err(e)
            }
        }
    }

    /// The slot half of [`Self::issue`].
    fn draw_slot(core: &ProviderCore, chunk: &AllocatedChunk) -> Result<DrawnSlot, AllocError> {
        let mut guard = store().lock().map_err(|_| AllocError::Other)?;
        if guard.is_none() {
            *guard = Some(MetadataStore::create().map_err(|_| AllocError::Other)?);
        }
        let store = guard.as_mut().expect("just filled");
        let slot = store.free.pop_front().ok_or(AllocError::Other)?;
        let header = header_of(&store.segment, slot);
        // The generation is NOT touched here: it advanced when this slot was
        // reclaimed, which is the moment every descriptor of its last use went
        // stale, and a descriptor of THIS use is stamped with the value read here.
        let generation = header.generation.load(Ordering::SeqCst);
        header.protocol.store(core.backend.id(), Ordering::Relaxed);
        header
            .segment
            .store(chunk.descriptor.segment, Ordering::Relaxed);
        header
            .chunk
            .store(chunk.descriptor.chunk, Ordering::Relaxed);
        header
            .len
            .store(chunk.descriptor.len.get(), Ordering::Relaxed);
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
        Ok(DrawnSlot {
            metadata: store.segment.clone(),
            metadata_id: store.id,
            slot,
            generation,
            confirmed,
        })
    }

    /// This payload's header in the metadata segment.
    fn header(&self) -> &ChunkHeader {
        header_of(&self.metadata, self.slot)
    }

    /// Give one reference back, but only while the slot is still this payload's: a slot
    /// that was made stale and recycled belongs to another chunk, whose count is not this
    /// payload's to touch (see the owner's `Drop`).
    fn release_if_current(&self) {
        let header = self.header();
        if header.generation.load(Ordering::SeqCst) == self.generation {
            release_reference(header);
        }
    }

    /// The bytes as a RECEIVER in this process is handed them: a range of the shared page that
    /// reports itself shared memory, holding a reference of its own that goes back when the
    /// last range of it drops.
    ///
    /// What a subscriber of the publishing session is owed, since upstream hands a local
    /// subscriber the buffer and not a copy of it (MEASURED against the real library: a
    /// same-session subscriber's `z_bytes_as_loaned_shm` succeeds). It is built by the path a
    /// remote receiver's payload takes, a descriptor sent and a reference resolved, so there
    /// is one implementation of "a receiver holds a chunk", and this owner stays unique only
    /// until that reference is given back.
    ///
    /// `None` when the descriptor cannot be resolved, in which case the reference taken for
    /// it has been returned and the caller falls back to the bytes.
    pub fn receiver_view(&self) -> Option<RxBytes> {
        let wire = self.wire_reference();
        let descriptor = wire.descriptor();
        wire.commit();
        PosixShmResolver.resolve_shared(&descriptor)
    }

    /// Whether this owner is the chunk's ONLY holder: no descriptor of it is in flight and
    /// no receiver holds one, which the slot's count reads as one. Upstream's `is_unique`
    /// (`commons/zenoh-shm/src/api/buffer/zshmmut.rs` @ `impl TryFrom<&mut zshm> for &mut zshmmut {`),
    /// the condition for a shared buffer to become writable again. A slot that has been made
    /// stale is not this payload's and is not unique.
    pub fn is_unique(&self) -> bool {
        let header = self.header();
        header.generation.load(Ordering::SeqCst) == self.generation
            && header.refcount.load(Ordering::SeqCst) == 1
    }

    /// The payload's length: what was asked for, which may be less than the chunk the
    /// backend set aside.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the payload is empty. It never is (a chunk is at least a byte), and the
    /// method exists for the lint that wants it beside `len`.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The address of the first byte, writable. Valid for [`Self::len`] bytes for as long
    /// as `self` lives.
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.data.ptr()
    }

    /// Copy `bytes` into the shared segment (truncated to the allocated `len`).
    pub fn write(&mut self, bytes: &[u8]) {
        let n = bytes.len().min(self.len);
        // SAFETY: the chunk is `len` bytes of live shared memory this payload owns, and
        // `bytes` is a Rust slice that cannot overlap it: the source is in this process's
        // heap or stack and the destination is a mapping.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.data.ptr(), n) };
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
        self.take_reference();
        WireReference {
            payload: self,
            committed: false,
        }
    }

    /// This chunk as a buffer a message can be sent from (R3062): the handle a staged reply
    /// carries, so the session core can send the descriptor, or the bytes, or hand a receiver of
    /// the same session the chunk, without naming this type. Cheap: a clone of the `Arc`.
    pub fn send_handle(self: &Arc<Self>) -> wz_session_core::extshm::ShmSendHandle {
        wz_session_core::extshm::ShmSendHandle::new(self.clone())
    }

    /// The increment both guards share: one reference for a receiver, which the guard that
    /// carries it gives back unless it is committed.
    fn take_reference(&self) {
        self.header().refcount.fetch_add(1, Ordering::SeqCst);
    }

    /// R3065 -- the shared-memory protocol this chunk belongs to: the id its provider's backend
    /// reports and its header carries, the one a receiver reads the chunk through. A peer whose
    /// reader has no client for it cannot resolve the descriptor, so the payload is sent as its
    /// bytes there (see `SessionLinkActions::shm_admits`).
    pub fn protocol(&self) -> u32 {
        self.core.backend.id()
    }

    /// The payload bytes in the shared segment — the source for the inline-bytes
    /// fallback when a session did NOT negotiate SHM (`publish_shm` then ships the
    /// bytes the ordinary way).
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: the chunk is `len` bytes of live shared memory this payload keeps mapped.
        // A receiver in another process may write it only by the conversion to a mutable
        // buffer that requires being the sole holder, which no holder is while this
        // payload's owner reference stands.
        unsafe { std::slice::from_raw_parts(self.data.ptr(), self.len) }
    }
}

/// What drawing a metadata slot for a chunk produced.
struct DrawnSlot {
    metadata: Arc<OwnedSegment>,
    metadata_id: u16,
    slot: u16,
    generation: u32,
    confirmed: Confirmed,
}

impl Drop for ShmBackedPayload {
    fn drop(&mut self) {
        // Give the owner's own reference back. Whether a receiver still holds one is the
        // count's to say, and the chunk stays on its provider's busy list either way: the
        // collection decides, and at zero it takes the chunk home.
        //
        // Only while the slot is still this payload's. The unsafe policy that takes back the
        // newest chunk whether or not it is held makes the slot stale and recycles it, and an
        // owner that lets go afterwards would otherwise decrement the count of whatever chunk
        // the slot has been given to since. Upstream's release has no such check and leaves it
        // to the policy's warning; costing one comparison removes the corruption.
        self.release_if_current();
        // A provider nobody can ask to collect is collected now, so a publisher that lets
        // go the moment it has sent gets its memory back when the receiver has let go too,
        // without waiting for the next allocation or the watchdog's sweep. A provider a
        // program still holds is collected when the program (or its policy) says so, as
        // upstream's is.
        if self.core.is_orphan() {
            self.core.collect(true);
            forget_if_finished(&self.core);
        }
    }
}

/// The metadata segments this process has opened as a reader, by id, so a
/// receiver maps a provider's segment once and not once per sample: upstream
/// links a metadata segment the first time it sees it and keeps the mapping
/// (`commons/zenoh-shm/src/metadata/subscription.rs` @
/// `pub fn link(&self, descriptor: &MetadataDescriptor) -> ZResult<OwnedMetadataDescriptor> {`).
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
    // A provider whose handle is gone is collected by the process, and this is the clock
    // that does it for a chunk whose receiver lets go after its owner has.
    sweep_orphans();
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
    /// R3065 -- the reader's clients, when it holds a set of its own. `None` is the default
    /// reader, which resolves POSIX alone and allocates nothing for the privilege.
    clients: Option<Arc<ShmClientSet>>,
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
        Self::link_with(descriptor, None)
    }

    /// R3065 -- [`Self::link`] for a reader that holds a set of clients: the chunk is mapped
    /// through the client its header's protocol names, and a protocol the set holds none for is
    /// refused, as it is by upstream's reader. Everything else is `link`'s.
    pub fn link_through(descriptor: &ShmDescriptor, clients: &Arc<ShmClientSet>) -> Option<Self> {
        Self::link_with(descriptor, Some(Arc::clone(clients)))
    }

    fn link_with(descriptor: &ShmDescriptor, clients: Option<Arc<ShmClientSet>>) -> Option<Self> {
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
            clients,
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

    /// The chunk's data segment, mapped, and where in it the chunk's bytes lie, or
    /// `None` when the chunk is not valid, names a protocol this node does not
    /// speak, claims more than its length, its data segment will not open, or the
    /// window does not lie inside the segment.
    fn window(&self) -> Option<(ChunkData, std::ops::Range<usize>)> {
        let header = self.header()?;
        if header.watchdog_invalidated.load(Ordering::Acquire) {
            return None;
        }
        let protocol = header.protocol.load(Ordering::Relaxed);
        let data_len = self.descriptor.data_len as usize;
        let chunk = header.chunk.load(Ordering::Relaxed) as usize;
        if data_len > header.len.load(Ordering::Relaxed) {
            return None;
        }
        let segment_id = header.segment.load(Ordering::Relaxed);
        // POSIX is the built-in client and keeps its own mapping, which also serves the writable
        // second mapping; a reader built without it cannot resolve POSIX memory at all.
        let resolves_posix = self
            .clients
            .as_ref()
            .map_or(true, |clients| clients.resolves_posix());
        if protocol == POSIX_PROTOCOL_ID && resolves_posix {
            let segment = u64::from(segment_id);
            let data = PeerSegment::open(segment).ok()?;
            let end = chunk.checked_add(data_len)?;
            data.bytes().get(chunk..end)?;
            return Some((ChunkData::Posix { data, segment }, chunk..end));
        }
        // Any other protocol is read through the client the reader holds for it, or refused when
        // it holds none. The default reader holds none, so it refuses every protocol but POSIX.
        let segment = self.clients.as_ref()?.mount(protocol, segment_id)?;
        let ptr = segment.map(u32::try_from(chunk).ok()?);
        if ptr.is_null() {
            return None;
        }
        Some((
            ChunkData::Foreign {
                _segment: segment,
                ptr,
                len: data_len,
            },
            0..data_len,
        ))
    }

    /// Whether this hold is the ONLY reference to the chunk: the count in the slot's
    /// header reads one, which is the reference the sender took for this receiver.
    /// The owner's own is given back when it lets go of the buffer, so a count of
    /// one means nobody else reads the chunk, and it is upstream's `is_unique`
    /// (`commons/zenoh-shm/src/api/buffer/zshmmut.rs` @
    /// `impl TryFrom<&mut zshm> for &mut zshmmut {`) read the same way, off the
    /// metadata slot.
    pub fn is_unique(&self) -> bool {
        match self.header() {
            Some(header) => {
                header.refcount.load(Ordering::SeqCst) == 1
                    && header.generation.load(Ordering::SeqCst) == self.descriptor.generation
            }
            None => false,
        }
    }

    /// Copy the chunk's bytes out of the shared page (the bounded scoped copy
    /// into an owned buffer), or `None` when the chunk has no readable window (see
    /// `window`).
    pub fn read(&self) -> Option<Vec<u8>> {
        let (data, window) = self.window()?;
        Some(data.bytes()[window].to_vec())
    }

    /// The chunk's bytes as they lie on the shared page, with this hold kept for as
    /// long as any range of them lives (R3049): the delivered payload IS the page,
    /// and the reference the sender took for this receiver goes back, and the
    /// watchdog bit stops being confirmed, when the last range drops and not before.
    ///
    /// Upstream's receiver is the same: its `ShmBuf` reads straight out of the
    /// mapped segment and gives the reference back in `Drop for ShmBufInner`.
    /// `None` when the chunk has no readable window, and then `self` drops here, so the
    /// reference goes back on that way out as it does for a copy.
    pub fn into_shared(self) -> Option<RxBytes> {
        let (data, window) = self.window()?;
        let len = window.len();
        let storage: Arc<dyn RxStorage> = Arc::new(SharedChunk {
            data,
            writable: OnceLock::new(),
            window,
            hold: self,
        });
        RxBytes::shared(storage, 0..len)
    }
}

/// The storage a received shared-memory payload is a range of: a chunk's data
/// segment, mapped, and the hold that keeps the chunk the sender's until the last
/// range of it drops.
///
/// The fields drop in the order they are declared and the order is the point: the
/// mappings go first, so nothing can read the page after the sender is free to
/// reuse it, and the hold goes last and gives the reference back.
struct SharedChunk {
    data: ChunkData,
    /// The POSIX segment mapped WRITABLE, made the first time a host asks for a pointer
    /// it may write through (R3052) and not before: a payload that is only read
    /// never needs it, and `None` is a segment that would not map writable. A chunk of a
    /// client's protocol has no second mapping: its client's pointer is the writable one.
    writable: OnceLock<Option<PeerSegmentRw>>,
    window: std::ops::Range<usize>,
    hold: ChunkHold,
}

/// R3065 -- where a received chunk's bytes are: a POSIX segment this module maps, or a segment a
/// CLIENT of another protocol attached.
enum ChunkData {
    /// The chunk's data segment mapped read-only, and its id, to map it a second time writable.
    Posix { data: PeerSegment, segment: u64 },
    /// The chunk at `ptr` in a segment the reader's client for the chunk's protocol attached. The
    /// segment is held for as long as the chunk is, which is what keeps `ptr` valid.
    Foreign {
        _segment: Arc<dyn ShmDataSegment>,
        ptr: *mut u8,
        len: usize,
    },
}

// SAFETY: `ptr` is an address inside `_segment`, which the value owns, and the client contract
// ([`ShmDataSegment::map`]) keeps it valid while the segment is alive. The bytes it names are
// shared memory read by any holder of the chunk, which is what the type is for.
unsafe impl Send for ChunkData {}
// SAFETY: as above; nothing in the value is mutated through a shared reference.
unsafe impl Sync for ChunkData {}

impl ChunkData {
    /// The bytes of the whole segment mapping for POSIX, and of the chunk alone for a client's.
    fn bytes(&self) -> &[u8] {
        match self {
            ChunkData::Posix { data, .. } => data.bytes(),
            // SAFETY: `ptr` names `len` bytes of `_segment`, which `self` holds alive; the length
            // is the descriptor's, which the header's own length bounds (`window` checked it).
            ChunkData::Foreign { ptr, len, .. } => unsafe {
                std::slice::from_raw_parts(*ptr as *const u8, *len)
            },
        }
    }
}

impl RxStorage for SharedChunk {
    fn as_slice(&self) -> &[u8] {
        &self.data.bytes()[self.window.clone()]
    }

    fn shm_chunk(&self) -> Option<&dyn ShmChunkView> {
        Some(self)
    }
}

impl ShmChunkView for SharedChunk {
    fn is_unique(&self) -> bool {
        self.hold.is_unique()
    }

    fn writable_ptr(&self) -> Option<*mut u8> {
        let segment = match &self.data {
            ChunkData::Posix { segment, .. } => *segment,
            // The client mapped the chunk through a pointer it owns the write side of.
            ChunkData::Foreign { ptr, .. } => return Some(*ptr),
        };
        let mapped = self
            .writable
            .get_or_init(|| PeerSegmentRw::open(segment).ok())
            .as_ref()?;
        if mapped.len() < self.window.end {
            return None;
        }
        // SAFETY: the window lies inside the mapping, as just checked.
        Some(unsafe { mapped.base().add(self.window.start) })
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
/// Follows a descriptor as upstream's reader does: [`ChunkHold::link`] it, then
/// either read the bytes off the shared page into an owned buffer and let the hold
/// go (`resolve`), or hand the bytes up where they lie and keep the hold until the
/// last range of them drops (`resolve_shared`, which is the path a delivered sample
/// takes, R3050).
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

    /// R3049 -- the bytes where they lie on the shared page, the reference given
    /// back when the last range of them drops (see [`ChunkHold::into_shared`]).
    fn resolve_shared(&self, descriptor: &ShmDescriptor) -> Option<RxBytes> {
        ChunkHold::link(descriptor)?.into_shared()
    }
}

/// Where a descriptor's chunk lies, as its own header names it: the data segment's id and
/// the chunk's offset in that segment, or `None` when the metadata segment cannot be opened
/// or the slot holds another generation.
///
/// A diagnostic, like [`reference_state`]: it reads what a PEER would read, so a witness
/// that two chunks share a pool is a fact in the shared header and not a claim of the
/// provider that made them.
pub fn chunk_position(descriptor: &ShmDescriptor) -> Option<(u32, u32)> {
    let segment = PeerSegment::open(u64::from(descriptor.metadata_id)).ok()?;
    let header = metadata_of(segment.bytes())?
        .headers
        .get(descriptor.metadata_index as usize)?;
    if header.generation.load(Ordering::SeqCst) != descriptor.generation {
        return None;
    }
    Some((
        header.segment.load(Ordering::SeqCst),
        header.chunk.load(Ordering::SeqCst),
    ))
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
            5 + SINGLE_PAYLOAD_POOL_HEADROOM,
            "the lone payload's pool is the payload plus its allocator's room"
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
        // Unlinked when the last holder of the pool lets go. Another test thread's sweep
        // may be holding the provider for the instant it takes to collect it, so this
        // waits a moment for the name to go and does not assert the instant.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while PeerSegment::open(data_id).is_ok() {
            assert!(
                std::time::Instant::now() < deadline,
                "the data segment was never unlinked once every holder had let go"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
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

    /// R3049 -- THE PAYLOAD IS THE PAGE. A resolved payload that is a copy cannot
    /// see what the owner writes into the segment afterwards, and one that is the
    /// page can, so the owner's later write is the witness that separates them:
    /// comparing the bytes it was handed with the bytes that were sent passes a
    /// copy too.
    #[test]
    fn a_resolved_payload_is_the_page_and_not_a_copy_of_it() {
        let mut payload = ShmBackedPayload::alloc(8).expect("alloc");
        payload.write(b"before!!");
        let descriptor = sent(&payload);

        let shared = PosixShmResolver
            .resolve_shared(&descriptor)
            .expect("resolve_shared");
        assert_eq!(shared.as_slice(), b"before!!");
        assert!(shared.is_shared(), "the bytes are a range of lent storage");

        payload.write(b"after!!!");
        assert_eq!(
            shared.as_slice(),
            b"after!!!",
            "the receiver reads the page itself, so the owner's later write shows"
        );
    }

    /// The view a receiver in this process is handed is the page, reports itself shared
    /// memory, and holds a reference of its own: the owner is not unique while the view is
    /// alive and is again once it drops. A view that gave its reference back early would
    /// let the owner write a page a subscriber is still reading, and one that never gave
    /// it back would keep the chunk out of its pool for good.
    #[test]
    fn a_receiver_view_holds_a_reference_until_it_drops() {
        let mut payload = ShmBackedPayload::alloc(8).expect("alloc");
        payload.write(b"in-place");
        assert!(payload.is_unique(), "the control: nothing else holds it");

        let view = payload.receiver_view().expect("a view of a live chunk");
        assert!(view.is_shared_memory(), "the view is the chunk, not a copy");
        assert_eq!(view.as_slice(), b"in-place");
        assert!(
            !payload.is_unique(),
            "the view is a holder, so the owner may not write"
        );

        let second = view.clone();
        drop(view);
        assert!(
            !payload.is_unique(),
            "a clone of the view still holds the reference"
        );
        drop(second);
        assert!(
            payload.is_unique(),
            "the last range letting go gave the reference back"
        );
    }

    /// R3049 -- the reference the sender took for this receiver is NOT given back
    /// when the payload is resolved: it goes back when the last range of the
    /// payload drops, however many ranges were taken of it. The count is read off
    /// the slot's own header, so a payload that gave it back early (a copy) reads
    /// 1 where this reads 2.
    #[test]
    fn the_reference_goes_back_when_the_last_range_of_a_shared_payload_drops() {
        let mut payload = ShmBackedPayload::alloc(4).expect("alloc");
        payload.write(b"held");
        let descriptor = sent(&payload);
        assert_eq!(reference_state(&descriptor), Some(ReferenceState::Held(2)));

        let shared = PosixShmResolver
            .resolve_shared(&descriptor)
            .expect("resolve_shared");
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Held(2)),
            "a resolve keeps the receiver's reference for as long as the bytes live"
        );

        let part = shared.subslice(0..2).expect("a range of the payload");
        drop(shared);
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Held(2)),
            "a range of the payload still holds the chunk after the payload is gone"
        );

        drop(part);
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Held(1)),
            "the last range dropped, so the receiver's reference is back and only the owner's is left"
        );
    }

    /// R3049 -- a read that fails after the descriptor is known to be this
    /// receiver's still gives the reference back, as a copy does: the way out of a
    /// failed shared read is the drop of the hold.
    #[test]
    fn a_shared_read_that_fails_gives_its_reference_back() {
        let mut payload = ShmBackedPayload::alloc(4).expect("alloc");
        payload.write(b"torn");
        let mut lies = sent(&payload);
        assert_eq!(reference_state(&lies), Some(ReferenceState::Held(2)));

        lies.data_len += 1_000_000;
        assert!(
            PosixShmResolver.resolve_shared(&lies).is_none(),
            "a length past the chunk's own is refused"
        );
        assert_eq!(
            reference_state(&lies),
            Some(ReferenceState::Held(1)),
            "and the reference the descriptor carried is not left raised"
        );
    }

    /// R3052 -- a payload that is the page SAYS so, and one that is a copy does not:
    /// a host's buffer plane reads this to tell the two apart, so the answer cannot
    /// be a property of the bytes.
    #[test]
    fn a_shared_payload_says_it_is_a_chunk_of_shared_memory_and_a_copy_does_not() {
        let mut payload = ShmBackedPayload::alloc(4).expect("alloc");
        payload.write(b"page");
        let descriptor = sent(&payload);

        let shared = PosixShmResolver
            .resolve_shared(&descriptor)
            .expect("resolve_shared");
        assert!(shared.is_shared_memory());
        assert!(
            !RxBytes::lend(b"page".to_vec()).is_shared_memory(),
            "lent bytes that are not a chunk are not shared memory"
        );
        assert!(
            !RxBytes::from(b"page".to_vec()).is_shared_memory(),
            "owned bytes are not shared memory"
        );
    }

    /// R3052 -- a chunk is UNIQUE while the owner has let go and only this receiver
    /// holds it, which is the condition upstream converts a received buffer to a
    /// mutable one on. The owner still holding its own reference reads the count
    /// at two, so the same payload is not unique until the owner drops it.
    #[test]
    fn a_received_chunk_is_unique_only_once_the_owner_has_let_go() {
        let mut payload = ShmBackedPayload::alloc(4).expect("alloc");
        payload.write(b"uniq");
        let descriptor = sent(&payload);
        let shared = PosixShmResolver
            .resolve_shared(&descriptor)
            .expect("resolve_shared");
        let view = shared.shm_chunk().expect("a shared-memory chunk");
        assert!(
            !view.is_unique(),
            "the owner still holds its reference and the receiver holds the other"
        );

        drop(payload);
        assert!(
            shared.shm_chunk().expect("a chunk").is_unique(),
            "the owner let go, so the receiver's reference is the only one"
        );
    }

    /// R3052 -- the pointer a unique chunk is written through is the PAGE: a write
    /// through it shows in what the payload reads, which is the second mapping of the
    /// segment, so the two mappings are the same memory and not a copy.
    #[test]
    fn a_write_through_the_writable_pointer_shows_in_the_payload() {
        let mut payload = ShmBackedPayload::alloc(4).expect("alloc");
        payload.write(b"abcd");
        let descriptor = sent(&payload);
        let shared = PosixShmResolver
            .resolve_shared(&descriptor)
            .expect("resolve_shared");
        drop(payload);

        let ptr = shared.shm_writable_ptr().expect("a writable mapping");
        // SAFETY: the chunk is unique (the owner dropped) and the pointer is valid
        // for the four bytes of the payload.
        unsafe { ptr.write(b'Z') };
        assert_eq!(shared.as_slice(), b"Zbcd");
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

    /// R3062 -- the reservation a message takes through the session core's sending seam is the
    /// owning twin of the wire reference, and has the same contract: it names the chunk's own
    /// descriptor, raises the count while it lives, gives the reference back when it drops without
    /// a commit, and leaves it with the receiver when it is committed. It owns its payload, so it
    /// outlives the handle it was taken from (a reply is sent after the handler returned).
    #[test]
    fn an_owned_reservation_is_returned_unless_it_is_committed() {
        let payload = Arc::new(ShmBackedPayload::alloc(2).expect("alloc"));
        let descriptor = payload.descriptor();

        let reservation = payload.send_handle().reserve_for_receiver();
        assert_eq!(reservation.descriptor(), descriptor);
        assert_eq!(reference_state(&descriptor), Some(ReferenceState::Held(2)));
        drop(reservation);
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Held(1)),
            "a frame that did not leave gives the receiver's reference back"
        );

        let reservation = payload.send_handle().reserve_for_receiver();
        reservation.commit();
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Held(2)),
            "a frame that left keeps it raised: the receiver releases it when it lets go"
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

    // -----------------------------------------------------------------------
    // R3056 -- the provider: many chunks out of one pool
    // -----------------------------------------------------------------------

    fn layout(size: usize) -> MemoryLayout {
        MemoryLayout::of_size(size).expect("a layout")
    }

    /// R3065 -- a backend that relabels a POSIX pool with a protocol of its own: its chunks lie
    /// where POSIX chunks lie and their headers say `id`, so only a client for `id` reads them.
    struct Relabelled {
        inner: PosixShmProviderBackend,
        id: u32,
    }

    impl ShmProviderBackend for Relabelled {
        fn id(&self) -> u32 {
            self.id
        }
        fn alloc(&self, layout: &MemoryLayout) -> Result<AllocatedChunk, AllocError> {
            self.inner.alloc(layout)
        }
        fn free(&self, chunk: &crate::shm_backend::ChunkDescriptor) {
            self.inner.free(chunk);
        }
        fn defragment(&self) -> usize {
            self.inner.defragment()
        }
        fn available(&self) -> usize {
            self.inner.available()
        }
        fn layout_for(&self, layout: MemoryLayout) -> Result<MemoryLayout, LayoutError> {
            self.inner.layout_for(layout)
        }
    }

    /// The client for [`Relabelled`]'s protocol: it attaches the POSIX segment by id, and counts.
    struct RelabelledClient {
        id: u32,
        attaches: AtomicUsize,
    }

    struct MappedSegment(PeerSegment);

    impl ShmDataSegment for MappedSegment {
        fn map(&self, chunk: u32) -> *mut u8 {
            self.0.bytes().as_ptr().wrapping_add(chunk as usize) as *mut u8
        }
    }

    impl crate::shm_clients::ShmDataClient for RelabelledClient {
        fn protocol(&self) -> u32 {
            self.id
        }
        fn attach(&self, segment: u32) -> Option<Arc<dyn ShmDataSegment>> {
            self.attaches.fetch_add(1, Ordering::SeqCst);
            let mapped = PeerSegment::open(u64::from(segment)).ok()?;
            Some(Arc::new(MappedSegment(mapped)))
        }
    }

    /// R3065 -- THE READER READS A CHUNK THROUGH THE CLIENT ITS HEADER'S PROTOCOL NAMES, and only
    /// that: the default reader refuses a protocol it holds no client for, a set that holds the
    /// client reads the chunk as bytes AND as the page itself, the segment is attached once for
    /// every buffer of it, and a set built without the built-in POSIX client cannot read POSIX.
    #[test]
    fn a_chunk_of_another_protocol_is_read_through_its_client_and_only_through_it() {
        use crate::shm_clients::{ShmClientResolver, ShmClientSet};

        const PROTOCOL: u32 = 100500;
        let provider = ShmProvider::new(Arc::new(Relabelled {
            inner: PosixShmProviderBackend::new(&layout(4096)).expect("a pool"),
            id: PROTOCOL,
        }));
        let chunk = |text: &[u8]| {
            let mut payload = provider
                .alloc(layout(64), &AllocPolicy::JustAlloc)
                .expect("a chunk of the relabelled pool");
            payload.write(text);
            let descriptor = sent(&payload);
            (payload, descriptor)
        };
        let client = Arc::new(RelabelledClient {
            id: PROTOCOL,
            attaches: AtomicUsize::new(0),
        });
        let with_client = Arc::new(
            ShmClientSet::new(
                true,
                [client.clone() as Arc<dyn crate::shm_clients::ShmDataClient>],
            )
            .expect("a client beside POSIX"),
        );
        let reader = ShmClientResolver::new(with_client);

        // The default reader holds no client for the protocol: it refuses, and gives the
        // reference back, as it does for a protocol it does not speak.
        let (_kept_a, refused) = chunk(b"refused by the default reader");
        assert!(
            PosixShmResolver.resolve(&refused).is_none(),
            "the default reader resolves POSIX alone"
        );

        // A set that holds the client reads the bytes ...
        let (_kept_b, copied) = chunk(b"read through the client");
        let copy = reader.resolve(&copied).expect("the client's protocol");
        assert_eq!(
            copy.len(),
            64,
            "the chunk is the 64 bytes that were allocated"
        );
        assert!(copy.starts_with(b"read through the client"));
        // ... and hands the page up where it lies, keeping the hold with it.
        let (_kept_c, shared) = chunk(b"the page itself");
        let bytes = reader.resolve_shared(&shared).expect("shared bytes");
        assert_eq!(bytes.as_slice().len(), 64);
        assert!(bytes.as_slice().starts_with(b"the page itself"));
        assert!(
            bytes.shm_chunk().is_some(),
            "a chunk of a client's protocol is delivered as a buffer of shared memory"
        );
        assert_eq!(
            client.attaches.load(Ordering::SeqCst),
            1,
            "the pool's one segment is attached once however many buffers are read from it"
        );

        // A set holding POSIX alone refuses the protocol it holds no client for.
        let (_kept_d, other) = chunk(b"no client for this");
        let posix_only = ShmClientResolver::new(Arc::new(ShmClientSet::posix_only()));
        assert!(posix_only.resolve(&other).is_none());

        // A set built WITHOUT the built-in POSIX client cannot read POSIX memory, and a set
        // with it can.
        let mut plain = ShmBackedPayload::alloc(5).expect("a POSIX chunk");
        plain.write(b"posix");
        let (posix_without, posix_with) = (sent(&plain), sent(&plain));
        let custom_only = ShmClientResolver::new(Arc::new(
            ShmClientSet::new(
                false,
                [client.clone() as Arc<dyn crate::shm_clients::ShmDataClient>],
            )
            .expect("a set without POSIX"),
        ));
        assert!(
            custom_only.resolve(&posix_without).is_none(),
            "a reader built without the default client set cannot read POSIX memory"
        );
        assert_eq!(
            reader.resolve(&posix_with).expect("POSIX is in the set"),
            b"posix"
        );
    }

    /// A chunk that fills a 4096-byte pool: the allocator spends about a kilobyte of the
    /// arena on its bins, so one chunk of this size is all a pool of that size serves (the
    /// real library gave the same for a default provider).
    const BIG: usize = 2048;

    /// Read the chunk offset and segment a descriptor's header names, the way a peer
    /// does: off the metadata segment.
    fn header_position(descriptor: &ShmDescriptor) -> (u32, u32) {
        let meta = PeerSegment::open(u64::from(descriptor.metadata_id)).expect("metadata segment");
        let header =
            &metadata_of(meta.bytes()).expect("view").headers[descriptor.metadata_index as usize];
        (
            header.segment.load(Ordering::Relaxed),
            header.chunk.load(Ordering::Relaxed),
        )
    }

    /// THE POINT OF A POOL: two chunks of one provider are two offsets of ONE segment,
    /// and each reads back its own bytes through the descriptor a peer would follow.
    #[test]
    fn two_chunks_of_one_provider_are_two_offsets_of_one_segment() {
        let provider = ShmProvider::pool(&layout(4096)).expect("a pool");
        let mut a = provider
            .alloc(layout(1024), &AllocPolicy::JustAlloc)
            .expect("first chunk");
        let mut b = provider
            .alloc(layout(1024), &AllocPolicy::JustAlloc)
            .expect("second chunk");
        a.write(&[0xA1; 1024]);
        b.write(&[0xB2; 1024]);

        let (da, db) = (sent(&a), sent(&b));
        let ((seg_a, off_a), (seg_b, off_b)) = (header_position(&da), header_position(&db));
        assert_eq!(seg_a, seg_b, "one pool is one segment");
        assert!(
            off_a.abs_diff(off_b) >= 1024,
            "two chunks of 1024 bytes cannot lie closer than that: {off_a} and {off_b}"
        );
        assert!(
            off_a > 0 && off_b > 0,
            "the allocator keeps its bins at the front, so no chunk starts at offset 0"
        );
        let read_a = PosixShmResolver.resolve(&da).expect("read a");
        let read_b = PosixShmResolver.resolve(&db).expect("read b");
        assert!(read_a.iter().all(|&byte| byte == 0xA1));
        assert!(read_b.iter().all(|&byte| byte == 0xB2));
    }

    /// A chunk goes back to the pool when its holders have let go AND the provider is asked
    /// to collect, and not before: a live provider is not emptied behind its program's back.
    #[test]
    fn a_live_provider_keeps_a_released_chunk_until_it_is_asked_to_collect() {
        let provider = ShmProvider::pool(&layout(4096)).expect("a pool");
        let first = provider
            .alloc(layout(BIG), &AllocPolicy::JustAlloc)
            .expect("the chunk that fills the pool");
        let descriptor = first.descriptor();
        drop(first);
        // Nobody holds it, but nobody has collected it either.
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Held(0)),
            "a live provider does not collect on its own"
        );
        assert!(
            provider
                .alloc(layout(BIG), &AllocPolicy::JustAlloc)
                .is_err(),
            "so the pool is still full"
        );
        assert_eq!(provider.garbage_collect(), BIG, "the collection frees it");
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Reclaimed),
            "and every descriptor of it is now stale"
        );
        assert!(provider.alloc(layout(BIG), &AllocPolicy::JustAlloc).is_ok());
    }

    /// A chunk a receiver still holds is NOT collected: its memory is not handed to anyone
    /// else, and it is collected after the receiver lets go.
    #[test]
    fn a_chunk_a_receiver_holds_is_not_given_to_another() {
        // Two chunks of 1024 fill the pool. One goes to a receiver, the other is let go.
        let provider = ShmProvider::pool(&layout(4096)).expect("a pool");
        let mut held = provider
            .alloc(layout(1024), &AllocPolicy::JustAlloc)
            .expect("the first chunk");
        let spare = provider
            .alloc(layout(1024), &AllocPolicy::JustAlloc)
            .expect("the second chunk");
        held.write(&[7u8; 1024]);
        let descriptor = sent(&held);
        drop(held);
        drop(spare);

        assert_eq!(
            provider.garbage_collect(),
            1024,
            "the spare chunk comes home and the one a receiver holds does not"
        );
        let reuse = provider
            .alloc(layout(1024), &AllocPolicy::JustAlloc)
            .expect("the spare chunk's room is served again");
        assert!(
            provider
                .alloc(layout(1024), &AllocPolicy::JustAlloc)
                .is_err(),
            "and the held chunk's room is NOT another chunk's"
        );
        assert!(PosixShmResolver.resolve(&descriptor).is_some());
        assert_eq!(provider.garbage_collect(), 1024, "now nobody holds it");
        assert!(provider
            .alloc(layout(1024), &AllocPolicy::JustAlloc)
            .is_ok());
        drop(reuse);
    }

    /// A layout the backend will not serve is the PROVIDER's incompatibility and not a malformed
    /// layout: a 32-byte-aligned request on a provider built at byte alignment is well formed
    /// and cannot be served, which the real library's C ABI reports as
    /// `PROVIDER_INCOMPATIBLE_LAYOUT` (read off it for exactly this request).
    #[test]
    fn a_layout_the_backend_will_not_serve_is_the_providers_incompatibility() {
        let provider = ShmProvider::pool(&layout(4096)).expect("a pool at byte alignment");
        let aligned = crate::shm_backend::AllocAlignment::new(5).expect("32 bytes");
        let request = MemoryLayout::new(64, aligned).expect("a well-formed layout");
        match provider.alloc(request, &AllocPolicy::JustAlloc) {
            Err(LayoutAllocError::Layout(LayoutError::ProviderIncompatibleLayout)) => {}
            Err(other) => panic!("a different refusal: {other}"),
            Ok(_) => panic!("a 32-byte-aligned request was served by a byte-aligned provider"),
        }
        assert_eq!(
            provider.layout_for(request),
            Err(LayoutError::ProviderIncompatibleLayout)
        );
    }

    /// A holder that died without releasing leaves its chunk with a count that never reaches
    /// zero, and the watchdog invalidates it. The safe collection, which takes a chunk on the
    /// count alone, leaves it, as upstream's does; only the unsafe one, whose caller promises
    /// nobody is reading, takes it home.
    #[test]
    fn only_the_unsafe_collection_takes_a_chunk_the_watchdog_invalidated() {
        let provider = ShmProvider::pool(&layout(4096)).expect("a pool");
        let payload = provider
            .alloc(layout(BIG), &AllocPolicy::JustAlloc)
            .expect("alloc");
        // A reference for a receiver that never reads it and never gives it back.
        let descriptor = sent(&payload);
        drop(payload);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while is_invalidated(&descriptor) != Some(true) {
            assert!(
                std::time::Instant::now() < deadline,
                "the watchdog never invalidated a chunk nobody confirmed"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(
            provider.garbage_collect(),
            0,
            "a safe collection leaves a chunk a holder may still be reading"
        );
        assert!(provider
            .alloc(layout(BIG), &AllocPolicy::JustAlloc)
            .is_err());
        // SAFETY: nothing reads this chunk: the one reference outstanding is a descriptor
        // this test took and never used.
        assert_eq!(unsafe { provider.garbage_collect_unsafe() }, BIG);
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Reclaimed)
        );
        assert!(provider.alloc(layout(BIG), &AllocPolicy::JustAlloc).is_ok());
    }

    /// A provider whose last handle is gone still owes its in-flight chunks to their
    /// receivers: the chunk stays readable, and the process takes it home when the receiver
    /// has let go.
    #[test]
    fn a_chunk_outlives_its_provider_handle_and_is_collected_by_the_process() {
        let provider = ShmProvider::pool(&layout(4096)).expect("a pool");
        let mut chunk = provider
            .alloc(layout(32), &AllocPolicy::JustAlloc)
            .expect("alloc");
        chunk.write(b"still here after the provider went");
        let descriptor = sent(&chunk);
        drop(provider);
        drop(chunk);

        assert_eq!(
            PosixShmResolver.resolve(&descriptor).as_deref(),
            Some(&b"still here after the provider went"[..][..32]),
            "a receiver that comes after both are gone reads it"
        );
        // The receiver let go; the next allocation anywhere sweeps the orphan.
        let _next = ShmBackedPayload::alloc(1).expect("alloc");
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Reclaimed),
            "the process collected a provider nobody could ask to"
        );
    }

    /// `GarbageCollect` retries an allocation after a collection that freed enough: a full
    /// pool whose only chunk was released serves the next request in one call.
    #[test]
    fn the_garbage_collecting_policy_serves_a_request_a_collection_makes_room_for() {
        let provider = ShmProvider::pool(&layout(4096)).expect("a pool");
        let full = provider
            .alloc(layout(BIG), &AllocPolicy::JustAlloc)
            .expect("fill it");
        drop(full);
        assert!(provider
            .alloc(layout(BIG), &AllocPolicy::JustAlloc)
            .is_err());
        let policy = AllocPolicy::garbage_collect(AllocPolicy::JustAlloc, AllocPolicy::JustAlloc);
        assert!(
            provider.alloc(layout(BIG), &policy).is_ok(),
            "the policy collected the released chunk and asked again"
        );
    }

    /// `Deallocate` takes back the newest chunk held or not: the unsafe way to make room.
    #[test]
    fn the_deallocating_policy_takes_back_a_chunk_even_while_it_is_held() {
        let provider = ShmProvider::pool(&layout(4096)).expect("a pool");
        let held = provider
            .alloc(layout(BIG), &AllocPolicy::JustAlloc)
            .expect("fill it");
        let descriptor = held.descriptor();
        assert!(held.is_unique(), "the control: the owner holds it alone");
        let policy = AllocPolicy::deallocate(1, AllocPolicy::JustAlloc, AllocPolicy::JustAlloc);
        let replacement = provider.alloc(layout(BIG), &policy).expect("made room");
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Reclaimed),
            "the held chunk's descriptor went stale"
        );
        assert!(
            !held.is_unique(),
            "a chunk taken back is not its owner's, and the slot may be another chunk's now"
        );
        // The slot is stale and may be recycled to another chunk; an owner that lets go
        // afterwards must not touch its count. Planted at 5, so a decrement is visible
        // where a count of zero (saturated) would hide it.
        held.header().refcount.store(5, Ordering::SeqCst);
        let header_of_held = held.header() as *const ChunkHeader;
        drop(held);
        // SAFETY: the metadata segment lives for the process, and the header is in it.
        let after = unsafe { (*header_of_held).refcount.load(Ordering::SeqCst) };
        assert_eq!(
            after, 5,
            "a stale owner decremented a count that is not its own"
        );
        drop(replacement);
    }

    /// `BlockOn` waits for room instead of failing, and gets it when another thread lets
    /// go and the policy's collection runs.
    #[test]
    fn the_blocking_policy_waits_for_a_chunk_to_be_released() {
        let provider = ShmProvider::pool(&layout(4096)).expect("a pool");
        let held = provider
            .alloc(layout(BIG), &AllocPolicy::JustAlloc)
            .expect("fill it");
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            drop(held);
        });
        let policy = AllocPolicy::block_on(AllocPolicy::garbage_collect(
            AllocPolicy::JustAlloc,
            AllocPolicy::JustAlloc,
        ));
        let waited = provider.alloc(layout(BIG), &policy);
        releaser.join().expect("releaser");
        assert!(waited.is_ok(), "it waited until the chunk was released");
    }

    /// `BlockOn` returns where waiting could never help: a request larger than the whole
    /// pool, with nothing outstanding, is refused and not waited on forever. Upstream waits
    /// forever there, and this is the one place the policy returns where upstream's does
    /// not. The test above is its control: with a chunk outstanding the same policy waits.
    ///
    /// A thread and a timeout stand in for the hang that a missing check would be, so that
    /// the failure is a red test and not a test run that never ends.
    #[test]
    fn the_blocking_policy_gives_up_when_nothing_could_ever_be_released() {
        let provider = ShmProvider::pool(&layout(4096)).expect("a pool");
        let policy = AllocPolicy::block_on(AllocPolicy::garbage_collect(
            AllocPolicy::JustAlloc,
            AllocPolicy::JustAlloc,
        ));
        let (answered, hears) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let refused = provider.alloc(layout(8192), &policy).is_err();
            let _ = answered.send(refused);
        });
        assert_eq!(
            hears.recv_timeout(std::time::Duration::from_secs(10)),
            Ok(true),
            "a request no release could ever make room for was waited on, or was served"
        );
    }

    /// `map` takes on a chunk something else produced, and refuses one this provider's
    /// backend could not have issued and one shorter than the length asked for: the provider
    /// hands the range back to its backend when it collects, and a range the backend never
    /// issued may corrupt it.
    #[test]
    fn a_mapped_chunk_must_be_one_the_backend_could_have_issued_and_long_enough() {
        let backend = Arc::new(PosixShmProviderBackend::new(&layout(4096)).expect("a pool"));
        let provider = ShmProvider::new(backend.clone());
        let elsewhere = PosixShmProviderBackend::new(&layout(4096)).expect("another pool");

        let own = backend.alloc(&layout(1024)).expect("a chunk of the pool");
        let mapped = provider
            .map(own, 512)
            .expect("the control: a chunk of this pool, mapped at a length it holds");
        assert_eq!(mapped.len(), 512);

        let own = backend.alloc(&layout(1024)).expect("a second chunk");
        assert!(
            matches!(provider.map(own, 1025), Err(AllocError::Other)),
            "a length beyond the chunk"
        );

        let foreign = elsewhere
            .alloc(&layout(1024))
            .expect("a chunk of another pool");
        assert!(
            matches!(provider.map(foreign, 512), Err(AllocError::Other)),
            "a chunk of a pool this provider does not own"
        );
    }

    /// An owner is UNIQUE while nothing else holds its chunk, which is what lets a buffer
    /// that was shared become writable again: a descriptor in flight, and a receiver that
    /// resolved it, each make it not unique.
    #[test]
    fn an_owner_is_unique_until_a_descriptor_of_its_chunk_is_held() {
        let mut payload = ShmBackedPayload::alloc(4).expect("alloc");
        payload.write(b"uniq");
        assert!(payload.is_unique(), "nothing else has been given the chunk");

        let descriptor = sent(&payload);
        assert!(
            !payload.is_unique(),
            "a descriptor is in flight and holds the second reference"
        );
        let shared = PosixShmResolver
            .resolve_shared(&descriptor)
            .expect("resolve_shared");
        assert!(!payload.is_unique(), "the receiver holds it");
        drop(shared);
        assert!(payload.is_unique(), "the receiver gave its reference back");
    }

    /// A layout the backend extends is allocated at the extended size, and the payload is the
    /// size that was asked for.
    #[test]
    fn a_payload_is_the_size_asked_for_in_a_chunk_the_backend_sized() {
        let alignment = crate::shm_backend::AllocAlignment::ALIGN_8_BYTES;
        let provider =
            ShmProvider::pool(&MemoryLayout::new(4096, alignment).unwrap()).expect("pool");
        let payload = provider
            .alloc(layout(10), &AllocPolicy::JustAlloc)
            .expect("alloc");
        assert_eq!(payload.len(), 10);
        let descriptor = payload.descriptor();
        assert_eq!(descriptor.data_len, 10);
        let meta = PeerSegment::open(u64::from(descriptor.metadata_id)).expect("metadata");
        let header =
            &metadata_of(meta.bytes()).expect("view").headers[descriptor.metadata_index as usize];
        assert_eq!(
            header.len.load(Ordering::Relaxed),
            16,
            "the header names the chunk the backend set aside, 10 rounded up to eight bytes"
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
