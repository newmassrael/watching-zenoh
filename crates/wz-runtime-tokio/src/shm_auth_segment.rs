// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The POSIX AUTH SEGMENT behind zenoh's SHM establishment challenge-response
//! (`session-extshm`) — the `std` half of the split whose wire format lives in
//! `wz_session_core::extshm`.
//!
//! ## Why a segment and not a token
//!
//! zenoh does not prove shared memory by exchanging a secret. Each peer creates
//! a real POSIX shm object holding a random challenge; answering with that
//! challenge demonstrates the answerer could `mmap` the object, which is the
//! only evidence that the two processes genuinely share memory rather than both
//! merely claiming to. A token exchange would pass between two hosts that share
//! nothing (`io/zenoh-transport/src/unicast/establishment/ext/shm/segment.rs`
//! @ `pub struct TXAuthSegment`; 1.10.0 split the old single
//! `ext/shm.rs` @ REMOVED into
//! `ext/shm/{mod,auth,handoff,segment}.rs` and moved the segment out of
//! `zenoh-shm`'s array type,
//! `commons/zenoh-shm/src/posix_shm/array.rs` @ `pub struct ArrayInSHM<ID, Elem, ElemIndex>`).
//!
//! ## The layout is a wire format
//!
//! A foreign zenohd opens this object and reads it as
//! `StructInSHM<AuthSegmentID, ShmTransportMetadata>` — one `#[repr(C)]` struct
//! at offset 0, with no header of its own:
//!
//! | byte | field | note |
//! |---|---|---|
//! | 0 | `id_count: u64` | count of the protocol ids that follow |
//! | 8 | `challenge: u64` | VERBATIM; see below |
//! | 16 | `version: u64` | `SHM_VERSION` = `2` |
//! | 24 | `protocols: [ProtocolID; 256]` | `u32` each; `POSIX_PROTOCOL_ID = 0` |
//! | 1048 | `shm_counters: [AtomicU32; 762 + 2048]` | the handoff counters |
//!
//! ## What R2240 moved, and why each half had to move
//!
//! Until 1.10.0 this was an `ArrayInSHM` of four `u64`s — `[len, !challenge,
//! version, protocols…]`, 32 bytes — and the challenge was stored BITWISE
//! NEGATED, which upstream's own comment justified as anti-probing between
//! versioned implementations. **1.10.0 stores it verbatim.** The three scalars
//! kept their byte offsets, so the change is invisible to an offset-by-offset
//! reading and shows up only as a peer whose echo never validates: a zenohd
//! reads byte 8, echoes what it finds, and this node compares it against the
//! un-negated value it holds.
//!
//! The version word moved 1 -> 2 in the same release, and upstream does NOT
//! check the peer's copy — `validate()` is only ever called on the LOCAL
//! segment (`establishment/ext/shm/auth.rs`, the two `self.inner.validate(..)`
//! calls). So this node's `version` is written for a wz peer and for a future
//! upstream that does look; what makes THIS node interoperate is that its
//! READER accepts `2`.
//!
//! The protocol list is not decoration. Upstream reads it after establishment
//! — `PartnerShmConfig::supports_protocol` in `common/shm/interop.rs` asks
//! `link_partner_segment.protocols().contains(&protocol)` before sending an SHM
//! buffer — so a segment that establishes with an empty list negotiates and
//! then carries nothing.
//!
//! The object NAME is equally a wire format: zenoh calls
//! `shm_open("{id}.zenoh", ..)` (`shm/unix.rs:256`), where `id` is the `u32`
//! rendered in DECIMAL. On Linux that is the file `/dev/shm/{id}.zenoh`, which
//! is what lets wz create and open one with ordinary file operations plus
//! `mmap` — the same mechanism `shm_open` itself provides.
//!
//! ## What is deliberately NOT mirrored
//!
//! zenoh takes a SHARED advisory lock (`flock`) on the object and treats an
//! exclusive lock elsewhere as an invalidated segment. wz takes the same shared
//! lock so a zenoh peer's own locking is unaffected, but wz never takes the
//! EXCLUSIVE lock upstream uses to invalidate — wz has no segment-recycling
//! pool for it to guard, and taking a lock it never releases meaningfully would
//! make wz's segments look invalid to a peer.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use wz_session_core::extshm::{
    decode_shm_descriptor, ShmAuthenticator, ShmHandoff, ShmTxHandoff, ShmTxTransaction,
    SHM_PRIORITY_BANDS,
};

use crate::shm_watchdog::Confirmed;

/// zenoh `SHM_VERSION` (`commons/zenoh-shm/src/version.rs`, the `SHM_VERSION`
/// constant). A peer whose segment carries a different value is treated as
/// "no SHM". R2240 moved it 1 -> 2 with the rest of the layout below.
const SHM_VERSION: u64 = 2;
/// zenoh `POSIX_PROTOCOL_ID` (`api/protocol_implementations/posix/protocol_id.rs`,
/// `pub const POSIX_PROTOCOL_ID: ProtocolID = 0`). `ProtocolID` is a `u32` in
/// 1.10.0, which is why the protocol slots below are four bytes and not eight.
const POSIX_PROTOCOL_ID: u32 = 0;

/// `u64` slot indices for the three scalar fields, which sit at the same byte
/// offsets in BOTH layouts — `id_count` 0, `challenge` 8, `version` 16.
const LEN_INDEX: usize = 0;
const CHALLENGE_INDEX: usize = 1;
const VERSION_INDEX: usize = 2;

/// Byte offset of `ShmTransportMetadata::protocols`, i.e. straight after the
/// three `u64` scalars.
const PROTOCOLS_OFFSET: usize = 3 * core::mem::size_of::<u64>();
/// `protocols: [ProtocolID; 256]`.
const PROTOCOL_SLOTS: usize = 256;
/// `shm_counters: [AtomicU32; 762 + 2048]`, restated as upstream spells the sum
/// so a reader can join the two halves to the declaration.
const COUNTER_SLOTS: usize = 762 + 2048;
/// Byte offset of `ShmTransportMetadata::shm_counters`: straight after the
/// protocol array, 1048 (the table in the module docs).
const COUNTERS_OFFSET: usize = PROTOCOLS_OFFSET + PROTOCOL_SLOTS * core::mem::size_of::<u32>();

/// The one protocol the segment of wz's DEFAULT reader advertises (R3065: a reader built from a
/// client storage lists that storage's protocols instead, see [`ShmAuthSegment::create_listing`]).
/// Written into `protocols[0]` with
/// `id_count = 1`; upstream's `PartnerShmConfig::supports_protocol`
/// (`common/shm/interop.rs`, `link_partner_segment.protocols().contains`) reads
/// it when it decides whether wz can be SENT an SHM buffer, so an empty list
/// would establish and then never carry anything.
const WZ_PROTOCOLS: [u32; 1] = [POSIX_PROTOCOL_ID];

/// `size_of::<ShmTransportMetadata>()`, derived from the field composition
/// rather than transcribed: 3 x u64 + 256 x u32 + 2810 x AtomicU32 = 12288, and
/// the struct is `#[repr(C)]` with an 8-byte alignment that the total already
/// satisfies, so there is no tail padding to account for.
const SEGMENT_BYTES: usize = PROTOCOLS_OFFSET
    + PROTOCOL_SLOTS * core::mem::size_of::<u32>()
    + COUNTER_SLOTS * core::mem::size_of::<u32>();

// R2862 — the id derivation (and its R2201 injectivity rationale), the object
// NAME, the mode and the shared advisory lock moved to `crate::posix_shm`, the
// one implementation every segment kind is made through. The payload provider's
// metadata and data segments share this namespace, so they share its counter.
#[cfg(test)]
use crate::posix_shm::candidate_id;
use crate::posix_shm::{next_candidate_id, OwnedSegment, PeerSegment, PeerSegmentRw};

/// This segment kind's `/dev/shm` path, for the tests that open one by hand.
#[cfg(test)]
fn auth_segment_path(segment_id: u32) -> std::path::PathBuf {
    crate::posix_shm::segment_path(u64::from(segment_id))
}

fn read_u64(map: &[u8], index: usize) -> Option<u64> {
    let start = index * core::mem::size_of::<u64>();
    let bytes: [u8; 8] = map.get(start..start + 8)?.try_into().ok()?;
    // Native endianness: the peer is on THIS host by construction (the whole
    // point of shared memory), and zenoh writes through a native `*mut u64`.
    Some(u64::from_ne_bytes(bytes))
}

fn write_u64(map: &mut [u8], index: usize, value: u64) {
    let start = index * core::mem::size_of::<u64>();
    map[start..start + 8].copy_from_slice(&value.to_ne_bytes());
}

/// Read one `ProtocolID` slot — a `u32` at a BYTE offset, because the protocol
/// array no longer shares the `u64` grid the three scalars sit on.
///
/// The establishment path must NOT REJECT a peer over its protocol list, because upstream does
/// not: `RXAuthSegment` is opened and its `challenge()` read with no validation at all, and the
/// list is consulted later, at send time, by `PartnerShmConfig::supports_protocol`. A reader
/// here that rejected a peer whose list it disliked would be stricter than the implementation it
/// has to interoperate with. It was test-only (the layout assertion) until R3065, which reads the
/// list the way upstream's sender does, to decide at send time whether a buffer goes out as its
/// descriptor or as its bytes ([`open_peer_protocols`]); a peer is still never refused for it.
fn read_u32_at(map: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = map.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_ne_bytes(bytes))
}

fn write_u32_at(map: &mut [u8], offset: usize, value: u32) {
    map[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

/// This node's own auth segment: created once at bring-up, unlinked on drop.
///
/// The [`OwnedSegment`] keeps the mapping and its shared lock alive and
/// unlinks the object when this drops, which is what bounds the lifetime of an
/// id a peer may still try to open (a peer that opens after the unlink gets
/// `None`, i.e. "no SHM", which is the correct outcome).
pub struct ShmAuthSegment {
    segment: OwnedSegment,
    challenge: u64,
    /// R3110 -- the counters of the segment nobody has leased, first in first out, as upstream's
    /// transmit segment keeps them (`io/zenoh-transport/src/unicast/establishment/ext/shm/segment.rs` @
    /// `available_shm_counters: Arc<std::sync::Mutex<VecDeque<ShmCounterID>>>,`).
    free_counters: Mutex<VecDeque<u16>>,
}

impl ShmAuthSegment {
    /// Create this node's segment with `challenge`, retrying on an id
    /// collision. `challenge` is the caller's random u64; it is stored VERBATIM
    /// per upstream — 1.5.0 negated it, 1.10.0 does not (R2240), and a peer
    /// reading the negated form echoes a value that can never validate.
    pub fn create(challenge: u64) -> io::Result<Self> {
        Self::create_listing(challenge, &WZ_PROTOCOLS)
    }

    /// R3065 -- [`Self::create`] listing `protocols`, the ones this node's READER can resolve,
    /// where `create` lists the one wz's default reader has (POSIX). The list is what a peer's
    /// sender reads to decide whether this node can be sent a buffer's descriptor, so it must be
    /// the reader's own and never a wider one: a protocol listed here that the reader cannot
    /// resolve is a descriptor dropped on arrival.
    ///
    /// `InvalidInput` when there are more ids than the segment has slots.
    pub fn create_listing(challenge: u64, protocols: &[u32]) -> io::Result<Self> {
        if protocols.len() > PROTOCOL_SLOTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} protocols do not fit an auth segment of {PROTOCOL_SLOTS} slots",
                    protocols.len()
                ),
            ));
        }
        let mut segment = OwnedSegment::create(SEGMENT_BYTES, || u64::from(next_candidate_id()))?;
        let map = segment.bytes_mut();
        write_u64(map, LEN_INDEX, protocols.len() as u64);
        // VERBATIM, per the module doc. 1.5.0 stored `!challenge` and 1.10.0
        // does not; a peer reading the inverted form echoes a value that can
        // never match.
        write_u64(map, CHALLENGE_INDEX, challenge);
        write_u64(map, VERSION_INDEX, SHM_VERSION);
        for (i, p) in protocols.iter().enumerate() {
            write_u32_at(map, PROTOCOLS_OFFSET + i * core::mem::size_of::<u32>(), *p);
        }
        segment.flush()?;
        Ok(Self {
            segment,
            challenge,
            free_counters: Mutex::new((0..COUNTER_SLOTS as u16).collect()),
        })
    }

    /// The counter `id` names, as an atomic every process that maps this object shares.
    ///
    /// # Panics
    ///
    /// When `id` is past the array; an id comes only from [`Self::lease_counters`].
    fn counter(&self, id: u16) -> &AtomicU32 {
        assert!(
            usize::from(id) < COUNTER_SLOTS,
            "counter {id} is past the {COUNTER_SLOTS} the segment holds"
        );
        // SAFETY: `id < COUNTER_SLOTS` and the mapping holds `SEGMENT_BYTES`, so the four bytes at
        // `COUNTERS_OFFSET + 4 * id` are inside it; the offset is a multiple of four from a
        // page-aligned base, so the pointer is aligned for an `AtomicU32`; and the mapping lives
        // as long as `self.segment`, which the returned borrow cannot outlive.
        unsafe {
            &*self
                .segment
                .base()
                .add(COUNTERS_OFFSET + usize::from(id) * core::mem::size_of::<u32>())
                .cast::<AtomicU32>()
        }
    }

    /// Lease one counter per priority band and zero them, as upstream's
    /// `ShmTXCounterLease::new` does (`io/zenoh-transport/src/unicast/establishment/ext/shm/segment.rs`
    /// @ `// Reset counter to 0 when lease is created`). `None` when fewer than a band's worth are
    /// free, which upstream reports as `No available SHM counters` and treats as no handoff.
    fn lease_counters(&self) -> Option<[u16; SHM_PRIORITY_BANDS]> {
        let mut free = self.free_counters.lock().unwrap_or_else(|e| e.into_inner());
        if free.len() < SHM_PRIORITY_BANDS {
            return None;
        }
        let mut ids = [0u16; SHM_PRIORITY_BANDS];
        for id in &mut ids {
            *id = free.pop_front()?;
            self.counter(*id).store(0, Ordering::SeqCst);
        }
        Some(ids)
    }

    /// Give leased counters back, to the FRONT of the free list, as upstream's lease does when it
    /// drops (`io/zenoh-transport/src/unicast/establishment/ext/shm/segment.rs` @
    /// `zlock!(self.segment.available_shm_counters).push_front(self.counter_index);`).
    fn return_counters(&self, ids: &[u16; SHM_PRIORITY_BANDS]) {
        let mut free = self.free_counters.lock().unwrap_or_else(|e| e.into_inner());
        for &id in ids.iter().rev() {
            free.push_front(id);
        }
    }

    /// This segment's id — the value that goes on the wire. The auth id is a
    /// `u32` on the wire, and `next_candidate_id` draws only `u32`s.
    pub fn id(&self) -> u32 {
        u32::try_from(self.segment.id()).expect("auth segment ids are drawn as u32")
    }

    /// The challenge a peer must echo back to prove it mapped this segment.
    pub fn challenge(&self) -> u64 {
        self.challenge
    }
}

/// Open a PEER's auth segment by id and read its challenge.
///
/// `None` — never an error — when the object does not exist, is too small, or
/// carries a different `SHM_VERSION`. zenoh treats every one of those as "this
/// peer does not do SHM with me" and continues the handshake
/// (`recv_init_ack` returns `Ok(None)`), so surfacing them as failures would
/// turn a benign mismatch into a dropped session.
pub fn open_peer_challenge(segment_id: u32) -> Option<u64> {
    let segment = PeerSegment::open(u64::from(segment_id)).ok()?;
    // Every field read is an 8-byte native load; a torn value fails the
    // comparison rather than being unsound.
    let map = segment.bytes();
    if map.len() < SEGMENT_BYTES {
        return None;
    }
    if read_u64(map, VERSION_INDEX)? != SHM_VERSION {
        return None;
    }
    // Verbatim, the mirror of `create`.
    read_u64(map, CHALLENGE_INDEX)
}

/// R3065 -- the protocol ids a PEER's auth segment lists: the shared-memory protocols its reader
/// has a client for, which is what decides whether this node may send it a descriptor
/// (upstream's `io/zenoh-transport/src/common/shm/interop.rs` @
/// `link_partner_segment.protocols().contains`, which `supports_protocol` answers from).
///
/// `None`, like [`open_peer_challenge`], when the object does not exist, is too small or carries
/// another `SHM_VERSION`, and also when the count it names is past the array: a list that cannot
/// be trusted is an UNKNOWN list, which the sender does not act on, and not an empty one, which
/// would withhold every descriptor from a peer that may take them.
pub fn open_peer_protocols(segment_id: u32) -> Option<Vec<u32>> {
    let segment = PeerSegment::open(u64::from(segment_id)).ok()?;
    let map = segment.bytes();
    if map.len() < SEGMENT_BYTES {
        return None;
    }
    if read_u64(map, VERSION_INDEX)? != SHM_VERSION {
        return None;
    }
    let count = usize::try_from(read_u64(map, LEN_INDEX)?).ok()?;
    if count > PROTOCOL_SLOTS {
        return None;
    }
    (0..count)
        .map(|i| read_u32_at(map, PROTOCOLS_OFFSET + i * core::mem::size_of::<u32>()))
        .collect()
}

/// R3040 -- a PEER's handoff counters, opened for writing: the means of telling a
/// zenoh sender that a shared-memory slice it sent has arrived.
///
/// The sender keeps a hard reference to every buffer it sends until the receiver
/// lowers one of the counters in the sender's auth segment, one counter per
/// priority, at the ids the sender named in its Open message
/// (`io/zenoh-transport/src/unicast/establishment/ext/shm/segment.rs` @
/// `pub fn counter_decrease(&self) {`). This holds that segment mapped WRITABLE,
/// where `open_peer_challenge` maps it read-only and lets it go, and the eight
/// ids, and `ShmHandoff::on_rx` lowers the one named for a message's priority.
///
/// The decrement SATURATES at zero where upstream's wraps. A counter that was
/// lowered below zero would read as four billion and be larger than the number of
/// buffers the sender holds for ever, which is a sender that never lets go of
/// anything again, so a mismatch between what was sent and what is acknowledged
/// must cost a missed acknowledgement and not the whole channel.
pub struct PeerHandoff {
    segment: PeerSegmentRw,
    ids: [u16; SHM_PRIORITY_BANDS],
}

impl PeerHandoff {
    /// Open the peer's auth segment `segment_id` for writing, with the counter
    /// ids it named for each priority.
    ///
    /// `None` when the segment cannot be opened, is too small, carries another
    /// `SHM_VERSION`, or when any id names a counter past the array: upstream
    /// refuses such an id when it builds its channel
    /// (`ShmRXCounterLease::new` @ `Invalid counter index`) and carries on without
    /// a handoff, which is the same outcome here.
    pub fn open(segment_id: u32, ids: &[u16; SHM_PRIORITY_BANDS]) -> Option<Self> {
        let segment = PeerSegmentRw::open(u64::from(segment_id)).ok()?;
        if segment.len() < SEGMENT_BYTES {
            return None;
        }
        // SAFETY: the mapping is at least `SEGMENT_BYTES` long, and `VERSION_INDEX`
        // names an 8-byte-aligned `u64` inside it (a page-aligned base plus 16); it
        // is read through an atomic load because the peer may write it.
        let version = unsafe {
            (*segment
                .base()
                .add(VERSION_INDEX * core::mem::size_of::<u64>())
                .cast::<AtomicU64>())
            .load(Ordering::Relaxed)
        };
        if version != SHM_VERSION {
            return None;
        }
        if ids.iter().any(|&id| usize::from(id) >= COUNTER_SLOTS) {
            return None;
        }
        Some(Self { segment, ids: *ids })
    }

    /// The counter `id` names. `id` was checked against the array at `open`.
    fn counter(&self, id: u16) -> &AtomicU32 {
        // SAFETY: `id < COUNTER_SLOTS` and the mapping holds `SEGMENT_BYTES`, so the
        // four bytes at `COUNTERS_OFFSET + 4 * id` are inside it; the offset is a
        // multiple of four from a page-aligned base, so the pointer is aligned for an
        // `AtomicU32`; and the mapping lives as long as `self.segment`, which the
        // returned borrow cannot outlive.
        unsafe {
            &*self
                .segment
                .base()
                .add(COUNTERS_OFFSET + usize::from(id) * core::mem::size_of::<u32>())
                .cast::<AtomicU32>()
        }
    }
}

impl ShmHandoff for PeerHandoff {
    fn on_rx(&self, band: usize) {
        // A band past the eight priorities holds no counter: nothing to lower.
        let Some(&id) = self.ids.get(band) else {
            return;
        };
        // Release, so the reads this node made of the buffer happen before the
        // sender sees that the buffer was acknowledged.
        let _ = self
            .counter(id)
            .fetch_update(Ordering::Release, Ordering::Relaxed, |n| n.checked_sub(1));
    }
}

/// What a node that SENDS shared memory keeps of one peer's counters (R3110), shared between the
/// handoff the session sends through and the poll that lets chunks go.
struct TxInner {
    segment: Arc<ShmAuthSegment>,
    /// The counter this node leased for each priority band, named in its Open messages.
    ids: [u16; SHM_PRIORITY_BANDS],
    /// For each band, the chunks sent and not yet acknowledged, oldest first, each kept confirmed
    /// by its entry. An entry is `None` for a slice whose chunk this node could not keep
    /// confirmed: the slice was counted, because the peer will lower the counter for it.
    queues: [Mutex<VecDeque<Option<Confirmed>>>; SHM_PRIORITY_BANDS],
}

impl TxInner {
    /// Let go of the oldest `queue.len() - counter` chunks of each band: the receiver has lowered
    /// the counter by one per slice it mapped, so the chunks beyond what the counter still counts
    /// are the acknowledged ones, as upstream's reactor computes it
    /// (`io/zenoh-transport/src/unicast/establishment/ext/shm/handoff.rs` @
    /// `let to_pop = self.handoffs_len.load(SeqCst) as isize - self.counter.counter() as isize;`).
    fn poll(&self) {
        for (band, queue) in self.queues.iter().enumerate() {
            let counter = self.segment.counter(self.ids[band]).load(Ordering::Relaxed) as usize;
            // Dropping a `Confirmed` takes the confirmator's lock, so the entries are taken out
            // under the queue's lock and dropped after it.
            let acknowledged: Vec<_> = {
                let mut queue = queue.lock().unwrap_or_else(|e| e.into_inner());
                let n = queue.len().saturating_sub(counter);
                queue.drain(..n).collect()
            };
            drop(acknowledged);
        }
    }
}

impl Drop for TxInner {
    fn drop(&mut self) {
        self.segment.return_counters(&self.ids);
    }
}

/// The transmit handoffs this process operates, so one thread can poll them all: upstream's
/// `GLOBAL_HANDOFF_REACTOR`. A handoff leaves when its session lets go of it.
fn tx_registry() -> &'static Mutex<Vec<Weak<TxInner>>> {
    static REGISTRY: OnceLock<Mutex<Vec<Weak<TxInner>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

/// One poll of every transmit handoff of the process: run by the watchdog thread on the validator's
/// clock, which is the interval upstream's reactor sleeps.
pub(crate) fn poll_tx_handoffs() {
    let live: Vec<Arc<TxInner>> = {
        let mut registry = tx_registry().lock().unwrap_or_else(|e| e.into_inner());
        registry.retain(|handoff| handoff.strong_count() > 0);
        registry.iter().filter_map(Weak::upgrade).collect()
    };
    for handoff in live {
        handoff.poll();
    }
}

/// This node's handoff as a SENDER: eight counters leased from its auth segment, one per priority
/// band, and the chunks it keeps confirmed against them (R3110).
pub struct PosixTxHandoff {
    inner: Arc<TxInner>,
}

impl PosixTxHandoff {
    /// Lease a band's worth of counters from `segment`. `None` when the segment has none to give.
    fn new(segment: Arc<ShmAuthSegment>) -> Option<Self> {
        let ids = segment.lease_counters()?;
        let inner = Arc::new(TxInner {
            segment,
            ids,
            queues: std::array::from_fn(|_| Mutex::new(VecDeque::new())),
        });
        tx_registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Arc::downgrade(&inner));
        Some(Self { inner })
    }
}

impl ShmTxHandoff for PosixTxHandoff {
    fn counters(&self) -> [u16; SHM_PRIORITY_BANDS] {
        self.inner.ids
    }

    fn reset(&self) {
        for (band, queue) in self.inner.queues.iter().enumerate() {
            let forgotten: Vec<_> = queue
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .drain(..)
                .collect();
            drop(forgotten);
            self.inner
                .segment
                .counter(self.inner.ids[band])
                .store(0, Ordering::SeqCst);
        }
    }

    fn begin(&self, band: usize) -> Box<dyn ShmTxTransaction> {
        Box::new(PosixTxTransaction {
            inner: Arc::clone(&self.inner),
            band: band.min(SHM_PRIORITY_BANDS - 1),
            held: Vec::new(),
            committed: false,
        })
    }
}

/// One message's slices, declared to the counter of its band and kept confirmed.
struct PosixTxTransaction {
    inner: Arc<TxInner>,
    band: usize,
    held: Vec<Option<Confirmed>>,
    committed: bool,
}

impl ShmTxTransaction for PosixTxTransaction {
    fn on_tx(&mut self, descriptor: &[u8]) {
        let confirmed = decode_shm_descriptor(descriptor)
            .and_then(|descriptor| crate::shm_provider::confirm_sent_chunk(&descriptor));
        self.inner
            .segment
            .counter(self.inner.ids[self.band])
            .fetch_add(1, Ordering::SeqCst);
        self.held.push(confirmed);
    }

    fn commit(mut self: Box<Self>) {
        self.committed = true;
        let held = std::mem::take(&mut self.held);
        self.inner.queues[self.band]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(held);
    }
}

impl Drop for PosixTxTransaction {
    fn drop(&mut self) {
        if !self.committed && !self.held.is_empty() {
            // The message did not leave: no peer will lower the counter for these slices.
            self.inner
                .segment
                .counter(self.inner.ids[self.band])
                .fetch_sub(self.held.len() as u32, Ordering::SeqCst);
        }
    }
}

/// The [`ShmAuthenticator`] a session is handed at bring-up: this node's own
/// segment plus the ability to open a peer's.
pub struct PosixShmAuthenticator {
    segment: Arc<ShmAuthSegment>,
    /// R3110 -- the counters this session leased as a sender, or `None` when the segment had none
    /// to give, which declares the counter block `Disabled`.
    tx: Option<Arc<PosixTxHandoff>>,
}

impl PosixShmAuthenticator {
    /// Create this node's auth segment with a fresh challenge.
    ///
    /// The challenge is drawn from the same `getrandom` source the rest of the
    /// AP uses for handshake nonces, not from a counter: it is the value a peer
    /// must not be able to guess without mapping the segment, so a predictable
    /// one would make the whole exchange decorative.
    pub fn new() -> io::Result<Self> {
        Self::with_protocols(&WZ_PROTOCOLS)
    }

    /// R3065 -- [`Self::new`] for a node whose reader resolves `protocols` and not POSIX alone.
    pub fn with_protocols(protocols: &[u32]) -> io::Result<Self> {
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| io::Error::other(format!("getrandom: {e}")))?;
        let segment = Arc::new(ShmAuthSegment::create_listing(
            u64::from_ne_bytes(bytes),
            protocols,
        )?);
        let tx = PosixTxHandoff::new(Arc::clone(&segment)).map(Arc::new);
        Ok(Self { segment, tx })
    }
}

impl ShmAuthenticator for PosixShmAuthenticator {
    fn local_segment_id(&self) -> u32 {
        self.segment.id()
    }

    fn local_challenge(&self) -> u64 {
        self.segment.challenge()
    }

    fn open_peer_challenge(&self, segment_id: u32) -> Option<u64> {
        open_peer_challenge(segment_id)
    }

    fn open_peer_protocols(&self, segment_id: u32) -> Option<Vec<u32>> {
        open_peer_protocols(segment_id)
    }

    fn open_peer_handoff(
        &self,
        peer_segment: u32,
        counters: &[u16; SHM_PRIORITY_BANDS],
    ) -> Option<Box<dyn ShmHandoff>> {
        PeerHandoff::open(peer_segment, counters)
            .map(|handoff| Box::new(handoff) as Box<dyn ShmHandoff>)
    }

    fn tx_handoff(&self) -> Option<Arc<dyn ShmTxHandoff>> {
        self.tx
            .as_ref()
            .map(|tx| Arc::clone(tx) as Arc<dyn ShmTxHandoff>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memmap2::MmapOptions;
    use std::fs::OpenOptions;

    /// How many consecutive counter values the injectivity witness walks.
    ///
    /// Not 2: the old form collided on every OTHER consecutive pair, so a
    /// two-draw window lands on the surviving half half the time and reports
    /// green on the defect. Any window of three already contains a colliding
    /// pair; 64 is far enough past that to make the failure a landslide
    /// (measured: 33 distinct of 64 for pid 17730) rather than an off-by-one a
    /// reader has to squint at.
    const ID_WALK: u32 = 64;

    /// R2201 (open-debt item 559) — DISTINCT counter values give DISTINCT ids.
    ///
    /// Over `candidate_id` rather than over `next_candidate_id`, and that is
    /// the whole design of this test. The atomic is process-global, so a test
    /// that drew from it would be measuring whichever values the other tests in
    /// this binary left it — under `--test-threads > 1` its draws are not
    /// consecutive at all, and non-consecutive draws MISS the defect (the old
    /// form separated `c` and `c + 2` perfectly well). A witness that a
    /// scheduler can turn green is not a witness.
    ///
    /// So the counter values are supplied here, the walk is TOTAL over them,
    /// and the verdict does not depend on what any other thread is doing.
    #[test]
    fn consecutive_counter_values_never_share_a_segment_id() {
        // Several pids because the collision's position depends on the parity
        // of `pid * K`: with one pid a reader cannot tell "injective" from
        // "this pid happens to start on the lucky side".
        for pid in [1u32, 2, 1234, 17730, 99999, u32::MAX] {
            let ids: Vec<u32> = (1..=ID_WALK).map(|c| candidate_id(pid, c)).collect();
            let distinct: std::collections::BTreeSet<u32> = ids.iter().copied().collect();
            assert_eq!(
                distinct.len(),
                ids.len(),
                "pid {pid}: {} of {} consecutive counter values share an id — \
                 a draw that follows an unlinked segment then reopens it",
                ids.len() - distinct.len(),
                ids.len()
            );
            // Never 0, and structurally so: the id names the file
            // `/dev/shm/<id>.zenoh`, and 0 is what an uninitialised value looks
            // like on the wire. Asserted beside injectivity because the two are
            // one rule here — the shift is what lets `| 1` buy "never 0"
            // without buying a collision with it.
            assert!(ids.iter().all(|&id| id != 0), "pid {pid}: an id was 0");
        }
    }

    /// The round trip through a REAL `/dev/shm` object: create, then re-open by
    /// id through the same path a foreign peer would use and recover the
    /// challenge. Real syscalls, not a mock — the layout only matters because a
    /// foreign process reads it, so a test that never touches the filesystem
    /// would pin nothing.
    #[test]
    fn a_created_segment_is_reopenable_by_id_and_yields_its_challenge() {
        let seg = ShmAuthSegment::create(0xDEAD_BEEF_CAFE_F00D).expect("create");
        assert!(auth_segment_path(seg.id()).is_file(), "lands in /dev/shm");
        assert_eq!(open_peer_challenge(seg.id()), Some(0xDEAD_BEEF_CAFE_F00D));

        let id = seg.id();
        drop(seg);
        assert_eq!(
            open_peer_challenge(id),
            None,
            "the segment is unlinked on drop, so a later open reads as no-SHM"
        );
    }

    /// The challenge is stored VERBATIM, as 1.10.0 stores it. Asserted on the
    /// RAW BYTES rather than through the accessor, because the accessor would
    /// pass either way if writer and reader agreed on a negation — and it is
    /// the raw bytes a zenohd reads.
    ///
    /// R2240 INVERTED this test rather than deleting it. Its old form asserted
    /// `!challenge` and was right for 1.5.0; the negated form is now the defect,
    /// and it is the one a zenohd cannot tell from a wrong peer.
    #[test]
    fn the_challenge_is_stored_verbatim_on_the_page() {
        let challenge = 0x0123_4567_89AB_CDEFu64;
        let seg = ShmAuthSegment::create(challenge).expect("create");
        let raw = std::fs::read(auth_segment_path(seg.id())).expect("read back");
        assert_eq!(raw.len(), SEGMENT_BYTES);
        assert_eq!(read_u64(&raw, CHALLENGE_INDEX), Some(challenge));
        assert_ne!(
            read_u64(&raw, CHALLENGE_INDEX),
            Some(!challenge),
            "storing it inverted is the 1.5.0 shape, and the bug this pins"
        );
    }

    /// The rest of the layout is what a foreign reader indexes into: the
    /// protocol COUNT at byte 0, the VERSION at byte 16, `POSIX_PROTOCOL_ID` as
    /// a `u32` at byte 24 — and the whole object exactly the size of upstream's
    /// struct, since `StructInSHM::create` allocates `size_of::<Elem>()` and
    /// dereferences the mapping as that type.
    #[test]
    fn the_struct_layout_matches_what_a_foreign_reader_dereferences() {
        let seg = ShmAuthSegment::create(1).expect("create");
        let raw = std::fs::read(auth_segment_path(seg.id())).expect("read back");
        assert_eq!(raw.len(), 12_288, "size_of::<ShmTransportMetadata>()");
        assert_eq!(raw.len(), SEGMENT_BYTES, "and the derivation agrees");
        assert_eq!(read_u64(&raw, LEN_INDEX), Some(1), "one protocol");
        assert_eq!(read_u64(&raw, VERSION_INDEX), Some(SHM_VERSION));
        assert_eq!(read_u32_at(&raw, PROTOCOLS_OFFSET), Some(POSIX_PROTOCOL_ID));
        // The slot AFTER the one wz declares must be zero, not a second id: a
        // reader takes `protocols[..id_count]`, so a stray non-zero here would
        // be invisible to us and meaningful to a peer that read a larger count.
        assert_eq!(read_u32_at(&raw, PROTOCOLS_OFFSET + 4), Some(0));
    }

    /// R3065 -- a peer's list is read back as the protocols its segment advertises, which for a
    /// segment this node made is the one protocol it declares. The read is of the OBJECT, the way
    /// a peer process reads it, so a list written by another implementation reads the same.
    #[test]
    fn a_peers_protocol_list_is_read_back_from_its_segment() {
        let seg = ShmAuthSegment::create(7).expect("create");
        assert_eq!(
            open_peer_protocols(seg.id()),
            Some(vec![POSIX_PROTOCOL_ID]),
            "the one protocol the segment declares"
        );
    }

    /// R3065 -- a segment lists the protocols it was created with, which is how a node whose
    /// reader has a client beyond POSIX is sent that protocol's descriptors, and refuses a list
    /// longer than its slots rather than writing past them.
    #[test]
    fn a_segment_lists_the_protocols_it_was_created_with() {
        let seg = ShmAuthSegment::create_listing(9, &[POSIX_PROTOCOL_ID, 100500]).expect("create");
        assert_eq!(
            open_peer_protocols(seg.id()),
            Some(vec![POSIX_PROTOCOL_ID, 100500]),
            "the ids, in the order given"
        );
        let too_many: Vec<u32> = (0..=PROTOCOL_SLOTS as u32).collect();
        assert_eq!(
            ShmAuthSegment::create_listing(9, &too_many)
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::InvalidInput),
            "a list longer than the array is refused, not truncated"
        );
    }

    /// R3065 -- a list that cannot be trusted is UNKNOWN, not empty: a version this node does
    /// not speak and a count past the array both read as `None`. An empty list would withhold
    /// every descriptor from a peer that may take them, where an unknown one leaves the send as
    /// it was.
    #[test]
    fn a_list_that_cannot_be_trusted_reads_as_unknown() {
        let seg = ShmAuthSegment::create(8).expect("create");
        let path = auth_segment_path(seg.id());
        {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            // SAFETY: same-process remap of a file this test owns.
            let mut map = unsafe { MmapOptions::new().map_mut(&file).unwrap() };
            write_u64(&mut map, LEN_INDEX, PROTOCOL_SLOTS as u64 + 1);
            map.flush().unwrap();
        }
        assert_eq!(
            open_peer_protocols(seg.id()),
            None,
            "a count past the array is a list this node does not read"
        );
        {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            // SAFETY: as above.
            let mut map = unsafe { MmapOptions::new().map_mut(&file).unwrap() };
            write_u64(&mut map, LEN_INDEX, 1);
            write_u64(&mut map, VERSION_INDEX, SHM_VERSION + 1);
            map.flush().unwrap();
        }
        assert_eq!(
            open_peer_protocols(seg.id()),
            None,
            "a segment of another version is not read, as its challenge is not"
        );
        assert_eq!(
            open_peer_protocols(u32::MAX),
            None,
            "a segment that does not exist is unknown"
        );
    }

    /// A version mismatch reads as "no SHM", not as an error — the arm that
    /// keeps a benign upgrade skew from dropping sessions.
    #[test]
    fn a_version_mismatch_reads_as_no_shm() {
        let seg = ShmAuthSegment::create(42).expect("create");
        let path = auth_segment_path(seg.id());
        {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            // SAFETY: same-process remap of a file this test owns.
            let mut map = unsafe { MmapOptions::new().map_mut(&file).unwrap() };
            write_u64(&mut map, VERSION_INDEX, SHM_VERSION + 1);
            map.flush().unwrap();
        }
        assert_eq!(open_peer_challenge(seg.id()), None);
    }

    /// An id nobody published reads as "no SHM" rather than panicking.
    #[test]
    fn an_unknown_segment_id_reads_as_no_shm() {
        assert_eq!(open_peer_challenge(0xFFFF_FFFE), None);
    }

    /// One counter id per band, distinct, so a handoff that lowered the wrong
    /// band's counter, or read the ids in the wrong order, cannot pass.
    const BAND_IDS: [u16; SHM_PRIORITY_BANDS] = [40, 41, 42, 43, 44, 45, 46, 47];

    /// Set a handoff counter of a segment this test owns, through the file, so
    /// the write is what a peer's own process would have made.
    fn set_counter(segment_id: u32, id: u16, value: u32) {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(auth_segment_path(segment_id))
            .unwrap();
        // SAFETY: same-process remap of a file this test owns.
        let mut map = unsafe { MmapOptions::new().map_mut(&file).unwrap() };
        write_u32_at(
            &mut map,
            COUNTERS_OFFSET + usize::from(id) * core::mem::size_of::<u32>(),
            value,
        );
        map.flush().unwrap();
    }

    /// Read a handoff counter of a segment, through the file and not through the
    /// handoff under test, so the assertion is on the bytes a peer would read.
    fn counter_of(segment_id: u32, id: u16) -> u32 {
        let raw = std::fs::read(auth_segment_path(segment_id)).expect("read back");
        read_u32_at(
            &raw,
            COUNTERS_OFFSET + usize::from(id) * core::mem::size_of::<u32>(),
        )
        .expect("inside the segment")
    }

    /// R3040 -- THE ACKNOWLEDGEMENT, on real shared-memory bytes: `on_rx(band)`
    /// lowers exactly the counter the peer named for that band by one, and no
    /// other. Every counter is set to 3, so a handoff that lowered a neighbour, or
    /// the wrong band's, shows as a 2 where a 3 must stay.
    #[test]
    fn a_handoff_lowers_exactly_the_counter_named_for_the_band() {
        let peer = ShmAuthSegment::create(1).expect("create the peer's segment");
        for id in BAND_IDS {
            set_counter(peer.id(), id, 3);
        }
        let handoff = PeerHandoff::open(peer.id(), &BAND_IDS).expect("open the handoff");

        handoff.on_rx(5);
        assert_eq!(counter_of(peer.id(), BAND_IDS[5]), 2, "band 5's counter");
        for (band, id) in BAND_IDS.into_iter().enumerate() {
            if band != 5 {
                assert_eq!(counter_of(peer.id(), id), 3, "band {band} was not touched");
            }
        }
        handoff.on_rx(2);
        handoff.on_rx(5);
        assert_eq!(counter_of(peer.id(), BAND_IDS[2]), 2);
        assert_eq!(counter_of(peer.id(), BAND_IDS[5]), 1);
    }

    /// R3040 -- a counter already at zero stays at zero. Upstream's decrement
    /// wraps, and a wrapped counter reads as four billion, so the sender would
    /// never again see fewer than it holds and would keep every buffer for ever.
    #[test]
    fn a_counter_at_zero_stays_at_zero() {
        let peer = ShmAuthSegment::create(1).expect("create the peer's segment");
        set_counter(peer.id(), BAND_IDS[5], 1);
        let handoff = PeerHandoff::open(peer.id(), &BAND_IDS).expect("open the handoff");
        for _ in 0..3 {
            handoff.on_rx(5);
        }
        assert_eq!(
            counter_of(peer.id(), BAND_IDS[5]),
            0,
            "one acknowledgement owed and three given: it stops at zero"
        );
    }

    /// R3040 -- a band past the eight priorities holds no counter, and lowers
    /// nothing, rather than indexing past the ids.
    #[test]
    fn a_band_past_the_priorities_lowers_nothing() {
        let peer = ShmAuthSegment::create(1).expect("create the peer's segment");
        for id in BAND_IDS {
            set_counter(peer.id(), id, 3);
        }
        let handoff = PeerHandoff::open(peer.id(), &BAND_IDS).expect("open the handoff");
        handoff.on_rx(SHM_PRIORITY_BANDS);
        handoff.on_rx(usize::MAX);
        for id in BAND_IDS {
            assert_eq!(counter_of(peer.id(), id), 3);
        }
    }

    /// R3040 -- a counter id past the array opens no handoff, as upstream's
    /// `ShmRXCounterLease::new` refuses it: an id from a peer is an index into
    /// memory this node writes, and one past the end is not written.
    #[test]
    fn a_counter_id_past_the_array_opens_no_handoff() {
        let peer = ShmAuthSegment::create(1).expect("create the peer's segment");
        let mut ids = BAND_IDS;
        ids[3] = COUNTER_SLOTS as u16;
        assert!(PeerHandoff::open(peer.id(), &ids).is_none());
        ids[3] = COUNTER_SLOTS as u16 - 1;
        assert!(
            PeerHandoff::open(peer.id(), &ids).is_some(),
            "the last counter is inside the array"
        );
    }

    /// R3040 -- a peer segment that is missing, or carries another version, opens
    /// no handoff: the same reading `open_peer_challenge` gives it, so a segment
    /// refused for the challenge is not written for the counters.
    #[test]
    fn a_missing_or_foreign_version_segment_opens_no_handoff() {
        assert!(PeerHandoff::open(0xFFFF_FFFE, &BAND_IDS).is_none());

        let peer = ShmAuthSegment::create(1).expect("create the peer's segment");
        {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(auth_segment_path(peer.id()))
                .unwrap();
            // SAFETY: same-process remap of a file this test owns.
            let mut map = unsafe { MmapOptions::new().map_mut(&file).unwrap() };
            write_u64(&mut map, VERSION_INDEX, SHM_VERSION + 1);
            map.flush().unwrap();
        }
        assert!(PeerHandoff::open(peer.id(), &BAND_IDS).is_none());
    }

    /// R3040 -- the authenticator the session is handed opens the handoff through
    /// the trait the establishment calls, and the object it returns is the one
    /// that lowers the counter.
    #[test]
    fn the_authenticator_opens_a_handoff_through_the_trait() {
        let peer = ShmAuthSegment::create(1).expect("create the peer's segment");
        set_counter(peer.id(), BAND_IDS[5], 2);
        let a = PosixShmAuthenticator::new().expect("authenticator");
        let handoff = a
            .open_peer_handoff(peer.id(), &BAND_IDS)
            .expect("the peer's counters open");
        handoff.on_rx(5);
        assert_eq!(counter_of(peer.id(), BAND_IDS[5]), 1);
    }

    /// The authenticator draws a challenge that is neither zero nor a counter
    /// value, and exposes the same pair its own segment holds.
    #[test]
    fn the_authenticator_publishes_its_own_segment() {
        let a = PosixShmAuthenticator::new().expect("authenticator");
        assert_eq!(
            a.open_peer_challenge(a.local_segment_id()),
            Some(a.local_challenge()),
            "its own segment is openable by its own id"
        );
        let b = PosixShmAuthenticator::new().expect("second authenticator");
        assert_ne!(a.local_segment_id(), b.local_segment_id(), "distinct ids");
        assert_ne!(
            a.local_challenge(),
            b.local_challenge(),
            "distinct challenges — a shared or counter-derived one would make \
             the exchange decorative"
        );
    }

    // ---- the node as a SENDER (R3110) ------------------------------------------------------

    /// A segment and a transmit handoff leased from it.
    fn a_handoff() -> (Arc<ShmAuthSegment>, PosixTxHandoff) {
        let segment = Arc::new(ShmAuthSegment::create(7).expect("create a segment"));
        let tx = PosixTxHandoff::new(Arc::clone(&segment)).expect("a band of counters is free");
        (segment, tx)
    }

    /// The serialized descriptor of a chunk a receiver is about to be sent: the reference is taken
    /// for it, as production takes it when it serializes the descriptor.
    fn sent_descriptor(
        payload: &crate::shm_provider::ShmBackedPayload,
    ) -> (wz_session_core::extshm::ShmDescriptor, Vec<u8>) {
        let wire = payload.wire_reference();
        let descriptor = wire.descriptor();
        wire.commit();
        let bytes = wz_session_core::extshm::encode_shm_descriptor(&descriptor);
        (descriptor, bytes)
    }

    /// A handoff leases one counter per band, each distinct and zero however it was left, and its
    /// counters are the next to be leased once it lets go of them.
    #[test]
    fn a_handoff_leases_a_band_of_distinct_zeroed_counters_and_returns_them() {
        let segment = Arc::new(ShmAuthSegment::create(7).expect("create a segment"));
        // Leave dirt in the counters a lease will draw, which a lease must zero.
        for id in 0..(2 * SHM_PRIORITY_BANDS as u16) {
            segment.counter(id).store(99, Ordering::SeqCst);
        }
        let first = PosixTxHandoff::new(Arc::clone(&segment)).expect("first lease");
        let second = PosixTxHandoff::new(Arc::clone(&segment)).expect("second lease");
        let (a, b) = (first.counters(), second.counters());
        let all: std::collections::BTreeSet<u16> = a.iter().chain(b.iter()).copied().collect();
        assert_eq!(all.len(), 2 * SHM_PRIORITY_BANDS, "no counter leased twice");
        assert!(
            a.iter()
                .chain(b.iter())
                .all(|&id| segment.counter(id).load(Ordering::SeqCst) == 0),
            "a lease zeroes what the last holder left"
        );

        drop(first);
        let third = PosixTxHandoff::new(Arc::clone(&segment)).expect("third lease");
        let mut reused = third.counters();
        let mut returned = a;
        reused.sort_unstable();
        returned.sort_unstable();
        assert_eq!(
            reused, returned,
            "the counters a handoff let go of are the next leased"
        );
    }

    /// The segment holds counters for 351 sessions of eight bands and no more: the 352nd is told
    /// there are none, which declares the counter block `Disabled`, and a lease that is let go of
    /// serves it.
    #[test]
    fn the_counters_serve_351_sessions_and_then_none() {
        let segment = Arc::new(ShmAuthSegment::create(7).expect("create a segment"));
        let mut held: Vec<PosixTxHandoff> = (0..COUNTER_SLOTS / SHM_PRIORITY_BANDS)
            .map(|_| PosixTxHandoff::new(Arc::clone(&segment)).expect("a band is free"))
            .collect();
        assert_eq!(held.len(), 351);
        assert!(
            PosixTxHandoff::new(Arc::clone(&segment)).is_none(),
            "the segment has no band left to lease"
        );
        held.pop();
        assert!(
            PosixTxHandoff::new(Arc::clone(&segment)).is_some(),
            "a session that ended gives its counters back"
        );
    }

    /// EVERY slice of a message that left is counted against its band's counter, a chunk this node
    /// can keep confirmed and one it cannot alike, and a peer that lowers the counter once per
    /// slice brings it back to zero: a slice that was sent and not counted would take a peer's
    /// decrement below zero.
    #[test]
    fn every_slice_is_counted_and_the_peers_acknowledgements_bring_it_back() {
        let (segment, tx) = a_handoff();
        let counter = segment.counter(tx.counters()[3]);
        let payload = crate::shm_provider::ShmBackedPayload::alloc(16).expect("alloc");
        let (_, chunk) = sent_descriptor(&payload);

        let mut transaction = tx.begin(3);
        transaction.on_tx(&chunk);
        // A descriptor that does not parse names no chunk to keep, and is still a slice sent.
        transaction.on_tx(&[0xff, 0xff]);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "both slices are declared"
        );
        transaction.commit();
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "committing counts nothing more"
        );
        assert_eq!(
            segment.counter(tx.counters()[2]).load(Ordering::SeqCst),
            0,
            "another band's counter is not touched"
        );

        counter.fetch_sub(2, Ordering::SeqCst);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    /// A message that did not leave is given back: nothing is counted against a peer that will
    /// never lower the counter for it, and nothing is kept confirmed.
    #[test]
    fn a_message_that_did_not_leave_is_given_back() {
        let (segment, tx) = a_handoff();
        let counter = segment.counter(tx.counters()[0]);
        let payload = crate::shm_provider::ShmBackedPayload::alloc(16).expect("alloc");
        let (_, chunk) = sent_descriptor(&payload);
        {
            let mut transaction = tx.begin(0);
            transaction.on_tx(&chunk);
            assert_eq!(counter.load(Ordering::SeqCst), 1);
            // Dropped without being committed: the send failed.
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "the count was given back"
        );
        assert!(
            tx.inner.queues[0].lock().expect("queue").is_empty(),
            "and nothing is kept for a message that never left"
        );
    }

    /// A new establishment is a new peer: what the last was owed is forgotten and the counters are
    /// zero again, so a count the last peer never lowered cannot hold this one's chunks.
    #[test]
    fn declaring_the_counters_again_forgets_what_the_last_peer_was_owed() {
        let (segment, tx) = a_handoff();
        let counter = segment.counter(tx.counters()[5]);
        let payload = crate::shm_provider::ShmBackedPayload::alloc(16).expect("alloc");
        let (_, chunk) = sent_descriptor(&payload);
        let mut transaction = tx.begin(5);
        transaction.on_tx(&chunk);
        transaction.commit();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(tx.inner.queues[5].lock().expect("queue").len(), 1);

        tx.reset();
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert!(tx.inner.queues[5].lock().expect("queue").is_empty());
    }

    /// THE POINT, on a real chunk and the real validator. Its owner lets go the moment it is sent;
    /// from then on only the sender's handoff keeps its watchdog bit confirmed. Four validator
    /// windows later it is still valid, because nobody has acknowledged it; once the peer lowers
    /// the counter and the poll runs it is let go of, and the validator invalidates it.
    #[test]
    fn a_chunk_stays_valid_until_the_peer_acknowledges_it_and_not_after() {
        let (segment, tx) = a_handoff();
        let payload = crate::shm_provider::ShmBackedPayload::alloc(16).expect("alloc");
        let (descriptor, chunk) = sent_descriptor(&payload);
        let mut transaction = tx.begin(3);
        transaction.on_tx(&chunk);
        transaction.commit();
        drop(payload);

        std::thread::sleep(std::time::Duration::from_millis(500));
        poll_tx_handoffs();
        assert_eq!(
            crate::shm_provider::is_invalidated(&descriptor),
            Some(false),
            "the sender let a chunk lapse that its peer had not yet acknowledged"
        );

        segment
            .counter(tx.counters()[3])
            .fetch_sub(1, Ordering::SeqCst);
        poll_tx_handoffs();
        let mut invalidated = false;
        for _ in 0..40 {
            if crate::shm_provider::is_invalidated(&descriptor) == Some(true) {
                invalidated = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(
            invalidated,
            "the confirmation outlived the acknowledgement: the chunk is still valid two seconds \
             after the peer lowered the counter"
        );
    }
}
