// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
//! rendered in DECIMAL. On Linux that is the file `/dev/shm/{id}.zenoh`.
//!
//! ## The segment is `zenoh-shm`'s
//!
//! The object is made and opened by `zenoh-shm`'s `StructInSHM`, the type upstream's own
//! transport makes it with, so its name, its mode, the shared advisory lock every holder takes and
//! the unlink by the last of them are upstream's and no copy of them lives in this crate
//! (`docs/shm-transport.md`, section 6).
use std::collections::VecDeque;
use std::io;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use wz_session_core::extshm::{
    decode_shm_descriptor, ShmAuthenticator, ShmDescriptor, ShmHandoff, ShmHandoffRefused,
    ShmTxHandoff, ShmTxTransaction, SHM_PRIORITY_BANDS,
};
use zenoh_shm::metadata::descriptor::MetadataDescriptor;
use zenoh_shm::posix_shm::struct_in_shm::StructInSHM;
use zenoh_shm::version::SHM_VERSION;
use zenoh_shm::{ShmBufHardRef, ShmBufInfo};

/// zenoh `POSIX_PROTOCOL_ID` (`api/protocol_implementations/posix/protocol_id.rs`,
/// `pub const POSIX_PROTOCOL_ID: ProtocolID = 0`). `ProtocolID` is a `u32` in
/// 1.10.0, which is why the protocol slots below are four bytes and not eight.
const POSIX_PROTOCOL_ID: u32 = 0;

/// `protocols: [ProtocolID; 256]`.
const PROTOCOL_SLOTS: usize = 256;
/// `shm_counters: [AtomicU32; 762 + 2048]`, restated as upstream spells the sum
/// so a reader can join the two halves to the declaration.
const COUNTER_SLOTS: usize = 762 + 2048;

/// The one protocol the segment of wz's DEFAULT reader advertises (a reader built from a client
/// storage lists that storage's protocols instead, see [`ShmAuthSegment::create_listing`]).
/// Upstream's `PartnerShmConfig::supports_protocol` (`common/shm/interop.rs`,
/// `link_partner_segment.protocols().contains`) reads it when it decides whether wz can be SENT
/// an SHM buffer, so an empty list would establish and then never carry anything.
const WZ_PROTOCOLS: [u32; 1] = [POSIX_PROTOCOL_ID];

/// The segment's layout, field for field upstream's
/// (`io/zenoh-transport/src/unicast/establishment/ext/shm/segment.rs` @
/// `struct ShmTransportMetadata {`): a foreign process dereferences the mapping as this type.
#[repr(C)]
struct ShmTransportMetadata {
    id_count: u64,
    challenge: u64,
    version: u64,
    protocols: [u32; PROTOCOL_SLOTS],
    shm_counters: [AtomicU32; COUNTER_SLOTS],
}

/// 3 x u64 + 256 x u32 + 2810 x AtomicU32 = 12288, at an 8-byte alignment the total already
/// satisfies: what a foreign reader maps.
const SEGMENT_BYTES: usize = 12_288;
const _: () = assert!(core::mem::size_of::<ShmTransportMetadata>() == SEGMENT_BYTES);

/// The object, as both its maker and a peer that opens it hold it.
type AuthObject = StructInSHM<u32, ShmTransportMetadata>;

/// This node's own auth segment: created once at bring-up, unlinked by the last holder.
///
/// A peer that opens it after the unlink gets `None`, i.e. "no SHM", which is the correct
/// outcome.
pub struct ShmAuthSegment {
    segment: AuthObject,
    challenge: u64,
    /// The counters of the segment nobody has leased, first in first out, as upstream's
    /// transmit segment keeps them (`io/zenoh-transport/src/unicast/establishment/ext/shm/segment.rs` @
    /// `available_shm_counters: Arc<std::sync::Mutex<VecDeque<ShmCounterID>>>,`).
    free_counters: Mutex<VecDeque<u16>>,
}

impl ShmAuthSegment {
    /// Create this node's segment with `challenge`. `challenge` is the caller's random u64; it
    /// is stored VERBATIM per upstream -- 1.5.0 negated it, 1.10.0 does not, and a peer reading
    /// the negated form echoes a value that can never validate.
    pub fn create(challenge: u64) -> io::Result<Self> {
        Self::create_listing(challenge, &WZ_PROTOCOLS)
    }

    /// [`Self::create`] listing `protocols`, the ones this node's READER can resolve, where
    /// `create` lists the one wz's default reader has (POSIX). The list is what a peer's sender
    /// reads to decide whether this node can be sent a buffer's descriptor, so it must be the
    /// reader's own and never a wider one: a protocol listed here that the reader cannot resolve
    /// is a descriptor dropped on arrival.
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
        let mut segment = AuthObject::create().map_err(|e| io::Error::other(e.to_string()))?;
        segment.id_count = protocols.len() as u64;
        segment.challenge = challenge;
        segment.version = SHM_VERSION;
        segment.protocols[..protocols.len()].copy_from_slice(protocols);
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
        &self.segment.shm_counters[usize::from(id)]
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

    /// This segment's id -- the value that goes on the wire.
    pub fn id(&self) -> u32 {
        self.segment.id()
    }

    /// The challenge a peer must echo back to prove it mapped this segment.
    pub fn challenge(&self) -> u64 {
        self.challenge
    }
}

/// A PEER's auth segment, opened as upstream opens it, when it carries the version this node
/// speaks. `None` -- never an error -- when the object does not exist, is too small for the
/// layout, or carries another `SHM_VERSION`.
fn open_peer(segment_id: u32) -> Option<AuthObject> {
    let segment = AuthObject::open(segment_id).ok()?;
    (segment.version == SHM_VERSION).then_some(segment)
}

/// Open a PEER's auth segment by id and read its challenge.
///
/// `None` when the object does not exist, is too small for the layout, or carries another
/// `SHM_VERSION`. zenoh treats every one of those
/// as "this peer does not do SHM with me" and continues the handshake (`recv_init_ack` returns
/// `Ok(None)`), so surfacing them as failures would turn a benign mismatch into a dropped session.
pub fn open_peer_challenge(segment_id: u32) -> Option<u64> {
    // Verbatim, the mirror of `create`.
    open_peer(segment_id).map(|segment| segment.challenge)
}

/// The protocol ids a PEER's auth segment lists: the shared-memory protocols its reader has a
/// client for, which is what decides whether this node may send it a descriptor (upstream's
/// `io/zenoh-transport/src/common/shm/interop.rs` @ `link_partner_segment.protocols().contains`,
/// which `supports_protocol` answers from).
///
/// `None`, like [`open_peer_challenge`], when the segment cannot be opened, and also when the
/// count it names is past the array: a list that cannot be trusted is an UNKNOWN list, which the
/// sender does not act on, and not an empty one, which would withhold every descriptor from a
/// peer that may take them. The establishment never refuses a peer for its list, because upstream
/// does not: the list is consulted at send time.
pub fn open_peer_protocols(segment_id: u32) -> Option<Vec<u32>> {
    let segment = open_peer(segment_id)?;
    let count = usize::try_from(segment.id_count).ok()?;
    (count <= PROTOCOL_SLOTS).then(|| segment.protocols[..count].to_vec())
}

/// A PEER's handoff counters, opened for writing: the means of telling a zenoh sender that a
/// shared-memory slice it sent has arrived.
///
/// The sender keeps a hard reference to every buffer it sends until the receiver lowers one of
/// the counters in the sender's auth segment, one counter per priority, at the ids the sender
/// named in its Open message (`io/zenoh-transport/src/unicast/establishment/ext/shm/segment.rs` @
/// `pub fn counter_decrease(&self) {`). This holds that segment mapped and the eight ids, and
/// `ShmHandoff::on_rx` lowers the one named for a message's priority.
///
/// The decrement SATURATES at zero where upstream's wraps. A counter that was lowered below zero
/// would read as four billion and be larger than the number of buffers the sender holds for ever,
/// which is a sender that never lets go of anything again, so a mismatch between what was sent and
/// what is acknowledged must cost a missed acknowledgement and not the whole channel.
pub struct PeerHandoff {
    segment: AuthObject,
    ids: [u16; SHM_PRIORITY_BANDS],
}

impl PeerHandoff {
    /// Open the peer's auth segment `segment_id` with the counter ids it named for each
    /// priority.
    ///
    /// `None` when the segment cannot be opened or carries another `SHM_VERSION`, or when any id names a
    /// counter past the array: upstream refuses such an id when it builds its channel
    /// (`ShmRXCounterLease::new` @ `Invalid counter index`) and carries on without a handoff,
    /// which is the same outcome here.
    pub fn open(segment_id: u32, ids: &[u16; SHM_PRIORITY_BANDS]) -> Option<Self> {
        let segment = open_peer(segment_id)?;
        if ids.iter().any(|&id| usize::from(id) >= COUNTER_SLOTS) {
            return None;
        }
        Some(Self { segment, ids: *ids })
    }

    /// The counter `id` names. `id` was checked against the array at `open`.
    fn counter(&self, id: u16) -> &AtomicU32 {
        &self.segment.shm_counters[usize::from(id)]
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

/// The hard reference of the chunk a sent descriptor names: what keeps the chunk confirmed until
/// its receiver acknowledges it, as upstream's handoff keeps the `ShmBufHardRef` of each buffer
/// it sends (`io/zenoh-transport/src/unicast/establishment/ext/shm/handoff.rs` @
/// `handoffs: lockfree::queue::Queue<Option<ShmBufHardRef>>,`). `None` when the descriptor does
/// not name a chunk this process can link, or one of another generation.
fn hard_ref_of(descriptor: &ShmDescriptor) -> Option<ShmBufHardRef> {
    let info = ShmBufInfo::new(
        NonZeroUsize::new(descriptor.data_len as usize)?,
        MetadataDescriptor {
            id: descriptor.metadata_id,
            index: descriptor.metadata_index,
        },
        descriptor.generation,
    );
    ShmBufHardRef::of_info(&info).ok()
}

/// What a node that SENDS shared memory keeps of one peer's counters, shared between the handoff
/// the session sends through and the poll that lets chunks go.
struct TxInner {
    segment: Arc<ShmAuthSegment>,
    /// The counter this node leased for each priority band, named in its Open messages.
    ids: [u16; SHM_PRIORITY_BANDS],
    /// For each band, the chunks sent and not yet acknowledged, oldest first, each kept confirmed
    /// by its entry. An entry is `None` for a slice whose chunk this node could not keep
    /// confirmed: the slice was counted, because the peer will lower the counter for it.
    queues: [Mutex<VecDeque<Option<ShmBufHardRef>>>; SHM_PRIORITY_BANDS],
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
            // Dropping a hard reference takes the confirmator's lock, so the entries are taken out
            // under the queue's lock and dropped after it.
            let acknowledged: Vec<_> = {
                let mut queue = queue.lock().unwrap_or_else(|e| e.into_inner());
                let n = queue.len().saturating_sub(counter);
                queue.drain(..n).collect()
            };
            drop(acknowledged);
        }
    }

    /// How many sent chunks this handoff keeps confirmed.
    fn holds(&self) -> usize {
        self.queues
            .iter()
            .map(|queue| {
                queue
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .filter(|entry| entry.is_some())
                    .count()
            })
            .sum()
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

/// The transmit handoffs alive now.
fn live_tx_handoffs() -> Vec<Arc<TxInner>> {
    let mut registry = tx_registry().lock().unwrap_or_else(|e| e.into_inner());
    registry.retain(|handoff| handoff.strong_count() > 0);
    registry.iter().filter_map(Weak::upgrade).collect()
}

/// One poll of every transmit handoff of the process: run by the reactor of `crate::shm_buffer`
/// on the validator's clock, which is the interval upstream's reactor sleeps.
pub(crate) fn poll_tx_handoffs() {
    for handoff in live_tx_handoffs() {
        handoff.poll();
    }
}

/// How many sent chunks the transmit handoffs of the process keep confirmed for receivers that
/// have not yet acknowledged them. A diagnostic: the witness that what a sender kept for a
/// receiver is let go of once the receiver acknowledges is this count returning to where it was.
pub fn tx_handoff_holds() -> usize {
    live_tx_handoffs()
        .iter()
        .map(|handoff| handoff.holds())
        .sum()
}

/// This node's handoff as a SENDER: eight counters leased from its auth segment, one per priority
/// band, and the chunks it keeps confirmed against them.
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
        crate::shm_buffer::start_reactor();
        Some(Self { inner })
    }
}

impl ShmTxHandoff for PosixTxHandoff {
    fn counters(&self) -> [u16; SHM_PRIORITY_BANDS] {
        self.inner.ids
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
    held: Vec<Option<ShmBufHardRef>>,
    committed: bool,
}

impl ShmTxTransaction for PosixTxTransaction {
    fn on_tx(&mut self, descriptor: &[u8]) {
        let confirmed = decode_shm_descriptor(descriptor).and_then(|d| hard_ref_of(&d));
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
        Ok(Self { segment })
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
    ) -> Result<Option<Box<dyn ShmHandoff>>, ShmHandoffRefused> {
        // A segment that cannot be mapped, or a counter outside its array, is zenoh's `Handoff
        // channel creation error`, which 1.10.2 answers by refusing the link.
        PeerHandoff::open(peer_segment, counters)
            .map(|handoff| Some(Box::new(handoff) as Box<dyn ShmHandoff>))
            .ok_or(ShmHandoffRefused)
    }

    /// R3122 -- a band of counters leased from this node's segment for ONE link, `None` when the
    /// segment has none left to give, which declares the counter block `Disabled`. The segment
    /// is the session's own, so the pool serves every link the session ever opens; the lease goes
    /// back when the link lets go of the handoff.
    fn lease_tx_handoff(&self) -> Option<Arc<dyn ShmTxHandoff>> {
        PosixTxHandoff::new(Arc::clone(&self.segment))
            .map(|tx| Arc::new(tx) as Arc<dyn ShmTxHandoff>)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use zenoh_shm::posix_shm::segment::Segment;

    /// The bytes of auth segment `id` as a foreign reader maps them, before any layout is laid on
    /// them.
    fn raw_bytes(id: u32) -> Vec<u8> {
        let segment = Segment::<u32>::open(id).expect("open the segment");
        // SAFETY: the mapping is `len` bytes long and lives until `segment` drops, after the copy.
        unsafe { std::slice::from_raw_parts(segment.as_ptr(), segment.len().get()) }.to_vec()
    }

    fn u64_at(raw: &[u8], offset: usize) -> u64 {
        u64::from_ne_bytes(raw[offset..offset + 8].try_into().expect("eight bytes"))
    }

    fn u32_at(raw: &[u8], offset: usize) -> u32 {
        u32::from_ne_bytes(raw[offset..offset + 4].try_into().expect("four bytes"))
    }

    /// A second mapping of auth segment `id`, through which a test writes what a peer's own process
    /// would.
    fn peer_mapping(id: u32) -> AuthObject {
        AuthObject::open(id).expect("open the segment")
    }

    /// The round trip through a REAL shared-memory object: create, then re-open by id through the
    /// path a foreign peer would use and recover the challenge.
    #[test]
    fn a_created_segment_is_reopenable_by_id_and_yields_its_challenge() {
        let seg = ShmAuthSegment::create(0xDEAD_BEEF_CAFE_F00D).expect("create");
        assert_eq!(open_peer_challenge(seg.id()), Some(0xDEAD_BEEF_CAFE_F00D));

        let id = seg.id();
        drop(seg);
        assert_eq!(
            open_peer_challenge(id),
            None,
            "the last holder unlinks the segment, so a later open reads as no-SHM"
        );
    }

    /// The challenge is stored VERBATIM, as 1.10.0 stores it. Asserted on the RAW BYTES rather
    /// than through the accessor, because the accessor would pass either way if writer and reader
    /// agreed on a negation, and it is the raw bytes a zenohd reads.
    #[test]
    fn the_challenge_is_stored_verbatim_on_the_page() {
        let challenge = 0x0123_4567_89AB_CDEFu64;
        let seg = ShmAuthSegment::create(challenge).expect("create");
        let raw = raw_bytes(seg.id());
        assert_eq!(u64_at(&raw, 8), challenge);
        assert_ne!(
            u64_at(&raw, 8),
            !challenge,
            "storing it inverted is the 1.5.0 shape, and the bug this pins"
        );
    }

    /// The rest of the layout is what a foreign reader indexes into: the protocol COUNT at byte 0,
    /// the VERSION at byte 16, `POSIX_PROTOCOL_ID` as a `u32` at byte 24, and the whole object
    /// exactly the size of upstream's struct.
    #[test]
    fn the_struct_layout_matches_what_a_foreign_reader_dereferences() {
        let seg = ShmAuthSegment::create(1).expect("create");
        let raw = raw_bytes(seg.id());
        assert!(
            raw.len() >= SEGMENT_BYTES,
            "size_of::<ShmTransportMetadata>()"
        );
        assert_eq!(u64_at(&raw, 0), 1, "one protocol");
        assert_eq!(u64_at(&raw, 16), SHM_VERSION);
        assert_eq!(u32_at(&raw, 24), POSIX_PROTOCOL_ID);
        // The slot AFTER the one wz declares must be zero, not a second id: a reader takes
        // `protocols[..id_count]`, so a stray non-zero here would be invisible to us and
        // meaningful to a peer that read a larger count.
        assert_eq!(u32_at(&raw, 28), 0);
        // The counters start at byte 1048, straight after the protocol array.
        seg.counter(0).store(0xABCD, Ordering::SeqCst);
        assert_eq!(u32_at(&raw_bytes(seg.id()), 1048), 0xABCD);
    }

    /// A peer's list is read back as the protocols its segment advertises, which for a segment
    /// this node made is the one protocol it declares.
    #[test]
    fn a_peers_protocol_list_is_read_back_from_its_segment() {
        let seg = ShmAuthSegment::create(7).expect("create");
        assert_eq!(
            open_peer_protocols(seg.id()),
            Some(vec![POSIX_PROTOCOL_ID]),
            "the one protocol the segment declares"
        );
    }

    /// A segment lists the protocols it was created with, and refuses a list longer than its slots
    /// rather than writing past them.
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

    /// A list that cannot be trusted is UNKNOWN, not empty: a version this node does not speak and
    /// a count past the array both read as `None`.
    #[test]
    fn a_list_that_cannot_be_trusted_reads_as_unknown() {
        let seg = ShmAuthSegment::create(8).expect("create");
        let mut peer = peer_mapping(seg.id());
        peer.id_count = PROTOCOL_SLOTS as u64 + 1;
        assert_eq!(
            open_peer_protocols(seg.id()),
            None,
            "a count past the array is a list this node does not read"
        );
        peer.id_count = 1;
        peer.version = SHM_VERSION + 1;
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

    /// A version mismatch reads as "no SHM", not as an error: the arm that keeps a benign upgrade
    /// skew from dropping sessions.
    #[test]
    fn a_version_mismatch_reads_as_no_shm() {
        let seg = ShmAuthSegment::create(42).expect("create");
        peer_mapping(seg.id()).version = SHM_VERSION + 1;
        assert_eq!(open_peer_challenge(seg.id()), None);
    }

    /// An id nobody published reads as "no SHM" rather than panicking.
    #[test]
    fn an_unknown_segment_id_reads_as_no_shm() {
        assert_eq!(open_peer_challenge(0xFFFF_FFFE), None);
    }

    /// One counter id per band, distinct, so a handoff that lowered the wrong band's counter, or
    /// read the ids in the wrong order, cannot pass.
    const BAND_IDS: [u16; SHM_PRIORITY_BANDS] = [40, 41, 42, 43, 44, 45, 46, 47];

    /// THE ACKNOWLEDGEMENT, on real shared-memory bytes: `on_rx(band)` lowers exactly the counter
    /// the peer named for that band by one, and no other.
    #[test]
    fn a_handoff_lowers_exactly_the_counter_named_for_the_band() {
        let peer = ShmAuthSegment::create(1).expect("create the peer's segment");
        for id in BAND_IDS {
            peer.counter(id).store(3, Ordering::SeqCst);
        }
        let handoff = PeerHandoff::open(peer.id(), &BAND_IDS).expect("open the handoff");

        handoff.on_rx(5);
        assert_eq!(
            peer.counter(BAND_IDS[5]).load(Ordering::SeqCst),
            2,
            "band 5's counter"
        );
        for (band, id) in BAND_IDS.into_iter().enumerate() {
            if band != 5 {
                assert_eq!(
                    peer.counter(id).load(Ordering::SeqCst),
                    3,
                    "band {band} was not touched"
                );
            }
        }
        handoff.on_rx(2);
        handoff.on_rx(5);
        assert_eq!(peer.counter(BAND_IDS[2]).load(Ordering::SeqCst), 2);
        assert_eq!(peer.counter(BAND_IDS[5]).load(Ordering::SeqCst), 1);
    }

    /// A counter already at zero stays at zero. Upstream's decrement wraps, and a wrapped counter
    /// reads as four billion, so the sender would keep every buffer for ever.
    #[test]
    fn a_counter_at_zero_stays_at_zero() {
        let peer = ShmAuthSegment::create(1).expect("create the peer's segment");
        peer.counter(BAND_IDS[5]).store(1, Ordering::SeqCst);
        let handoff = PeerHandoff::open(peer.id(), &BAND_IDS).expect("open the handoff");
        for _ in 0..3 {
            handoff.on_rx(5);
        }
        assert_eq!(
            peer.counter(BAND_IDS[5]).load(Ordering::SeqCst),
            0,
            "one acknowledgement owed and three given: it stops at zero"
        );
    }

    /// A band past the eight priorities holds no counter, and lowers nothing.
    #[test]
    fn a_band_past_the_priorities_lowers_nothing() {
        let peer = ShmAuthSegment::create(1).expect("create the peer's segment");
        for id in BAND_IDS {
            peer.counter(id).store(3, Ordering::SeqCst);
        }
        let handoff = PeerHandoff::open(peer.id(), &BAND_IDS).expect("open the handoff");
        handoff.on_rx(SHM_PRIORITY_BANDS);
        handoff.on_rx(usize::MAX);
        for id in BAND_IDS {
            assert_eq!(peer.counter(id).load(Ordering::SeqCst), 3);
        }
    }

    /// A counter id past the array opens no handoff, as upstream's `ShmRXCounterLease::new`
    /// refuses it: an id from a peer is an index into memory this node writes.
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

    /// A peer segment that is missing, or carries another version, opens no handoff: the same
    /// reading `open_peer_challenge` gives it.
    #[test]
    fn a_missing_or_foreign_version_segment_opens_no_handoff() {
        assert!(PeerHandoff::open(0xFFFF_FFFE, &BAND_IDS).is_none());

        let peer = ShmAuthSegment::create(1).expect("create the peer's segment");
        peer_mapping(peer.id()).version = SHM_VERSION + 1;
        assert!(PeerHandoff::open(peer.id(), &BAND_IDS).is_none());
    }

    /// The authenticator the session is handed opens the handoff through the trait the
    /// establishment calls, and the object it returns is the one that lowers the counter.
    #[test]
    fn the_authenticator_opens_a_handoff_through_the_trait() {
        let peer = ShmAuthSegment::create(1).expect("create the peer's segment");
        peer.counter(BAND_IDS[5]).store(2, Ordering::SeqCst);
        let a = PosixShmAuthenticator::new().expect("authenticator");
        let handoff = a
            .open_peer_handoff(peer.id(), &BAND_IDS)
            .expect("the peer's counters are not refused")
            .expect("the peer's counters open");
        handoff.on_rx(5);
        assert_eq!(peer.counter(BAND_IDS[5]).load(Ordering::SeqCst), 1);
    }

    /// zenoh 1.10.2 refuses the link on a `Handoff channel creation error`, so a segment this node
    /// cannot map answers `Err` and not "no handoff".
    #[test]
    fn counters_in_a_segment_that_cannot_be_mapped_are_refused() {
        let a = PosixShmAuthenticator::new().expect("authenticator");
        assert!(a.open_peer_handoff(u32::MAX - 1, &BAND_IDS).is_err());
    }

    /// The authenticator draws a challenge that is neither shared nor derived, and exposes the same
    /// pair its own segment holds.
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
            "distinct challenges: a shared or counter-derived one would make the exchange \
             decorative"
        );
    }

    // ---- the node as a SENDER ----------------------------------------------------------------

    /// A segment and a transmit handoff leased from it.
    fn a_handoff() -> (Arc<ShmAuthSegment>, PosixTxHandoff) {
        let segment = Arc::new(ShmAuthSegment::create(7).expect("create a segment"));
        let tx = PosixTxHandoff::new(Arc::clone(&segment)).expect("a band of counters is free");
        (segment, tx)
    }

    /// The serialized descriptor of a buffer a receiver is about to be sent: the reference is taken
    /// for it, as production takes it when it serializes the descriptor.
    fn sent_descriptor(
        buffer: &crate::shm_buffer::IssuedBuffer,
    ) -> (wz_session_core::extshm::ShmDescriptor, Vec<u8>) {
        let wire = buffer.wire_reference();
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
    /// there are none, and a lease that is let go of serves it.
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
    /// slice brings it back to zero.
    #[test]
    fn every_slice_is_counted_and_the_peers_acknowledgements_bring_it_back() {
        let (segment, tx) = a_handoff();
        let counter = segment.counter(tx.counters()[3]);
        let buffer = crate::shm_buffer::IssuedBuffer::alloc(16).expect("alloc");
        let (_, chunk) = sent_descriptor(&buffer);

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
            tx.inner.holds(),
            1,
            "the chunk that parsed is kept confirmed, the one that did not keeps nothing"
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
        let buffer = crate::shm_buffer::IssuedBuffer::alloc(16).expect("alloc");
        let (_, chunk) = sent_descriptor(&buffer);
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

    /// A handoff belongs to a link, and a link that lets go of it lets go of every chunk it kept
    /// and returns its counters to the segment: a count its peer never lowered cannot hold the
    /// chunks of a later peer, whose lease starts at zero.
    #[test]
    fn a_handoff_that_is_let_go_of_lets_go_of_what_it_kept_and_returns_its_counters() {
        let (segment, tx) = a_handoff();
        let ids = tx.counters();
        let buffer = crate::shm_buffer::IssuedBuffer::alloc(16).expect("alloc");
        let (_, chunk) = sent_descriptor(&buffer);
        let mut transaction = tx.begin(5);
        transaction.on_tx(&chunk);
        transaction.commit();
        assert_eq!(segment.counter(ids[5]).load(Ordering::SeqCst), 1);
        assert_eq!(tx.inner.queues[5].lock().expect("queue").len(), 1);

        // What the handoff kept lives in its inner state; when that is gone so is every entry of
        // its queues, each of which holds a chunk confirmed.
        let inner = Arc::downgrade(&tx.inner);
        drop(tx);
        assert!(
            inner.upgrade().is_none(),
            "nothing else holds what the handoff kept"
        );
        let later = PosixTxHandoff::new(Arc::clone(&segment)).expect("a band is free");
        assert_eq!(
            later.counters(),
            ids,
            "the counters it returned are leased next"
        );
        assert_eq!(
            segment.counter(ids[5]).load(Ordering::SeqCst),
            0,
            "and start at zero however the last peer left them"
        );
    }

    /// R3111 -- what a session declares in its OpenAck is decided by the link it will leave on,
    /// read off the driver: counters on a stream and none on a datagram link, whose lost message
    /// no peer would ever acknowledge. The same session, the same authenticator, only the kind of
    /// link differs.
    #[test]
    fn a_session_declares_counters_on_a_stream_link_and_none_on_a_datagram_link() {
        use wz_session_core::extshm::{
            decode_shm_open_ack_body, peer_shm_zbuf_body, ShmHandoffCounters,
        };
        use wz_session_core::link::LinkKind;

        for (kind, declares) in [(LinkKind::Tcp, true), (LinkKind::Udp, false)] {
            let (actions, _driver) = crate::test_fixtures::recording_actions_over(kind);
            actions.install_shm_auth(Box::new(
                PosixShmAuthenticator::new().expect("create an authenticator"),
            ));
            actions.set_shm_offer(true);
            actions.negotiate_shm_against_peer(true);
            let ack = actions
                .shm_send_open_ack()
                .expect("negotiated, so the acceptor acknowledges");
            let body = peer_shm_zbuf_body(core::slice::from_ref(&ack)).expect("a body");
            let counters = decode_shm_open_ack_body(body).expect("a counter block");
            assert_eq!(
                matches!(counters, ShmHandoffCounters::PerPriority(_)),
                declares,
                "a {kind:?} link declared {counters:?}"
            );
        }
    }

    /// R3122 -- a SECOND LINK of a session opening must leave alone the chunks the first link is
    /// still owed. Upstream's handoff belongs to a link (`LinkShmHandoffConfig` holds one
    /// transmit channel and one receive channel per link), so the second link's establishment
    /// leases counters of its own and the first keeps what it has. Before R3122 both links
    /// shared the session's one handoff, and the second link's Open message declared its
    /// counters again, which zeroed them and forgot what the first link was owed.
    #[cfg(feature = "transport-multilink")]
    #[test]
    fn a_second_link_opening_leaves_the_chunks_the_first_link_is_owed_alone() {
        use crate::multilink::{join_link, JoinOutcome};
        use crate::runtime_impl::TokioRuntime;
        use wz_runtime_core::Runtime;
        use wz_session_core::link::LinkKind;

        let (primary, _) = crate::test_fixtures::recording_actions_over(LinkKind::Tcp);
        let (secondary, _) = crate::test_fixtures::recording_actions_over(LinkKind::Tcp);
        let key = vec![0x0Au8, 0x0B, 0x0C, 0x0D];
        primary
            .core
            .fact_multilink_pubkey(|s| *s = Some(key.clone()));
        secondary.core.fact_multilink_pubkey(|s| *s = Some(key));
        let JoinOutcome::Joined(second_link) = join_link(&primary, &secondary, 2) else {
            panic!("the second link joins the shared core");
        };
        let authenticator = PosixShmAuthenticator::new().expect("create an authenticator");
        let segment = Arc::clone(&authenticator.segment);
        primary.install_shm_auth(Box::new(authenticator));
        primary.set_shm_offer(true);
        primary.negotiate_shm_against_peer(true);

        primary
            .shm_send_open_ack()
            .expect("the first link's Open declares the counters");
        let first = TokioRuntime::with_mutex_mut(&primary.link.shm_tx, |slot| slot.clone())
            .expect("the first link keeps the handoff its Open declared");
        let payload = crate::shm_buffer::IssuedBuffer::alloc(16).expect("alloc");
        let (_, chunk) = sent_descriptor(&payload);
        let mut transaction = first.begin(0);
        transaction.on_tx(&chunk);
        transaction.commit();
        let counter = segment.counter(first.counters()[0]);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "the chunk is owed by the first link's peer"
        );

        second_link
            .shm_send_open_ack()
            .expect("the second link's Open");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "and the second link's Open does not zero what the first link's peer was told of"
        );
        let second = TokioRuntime::with_mutex_mut(&second_link.link.shm_tx, |slot| slot.clone())
            .expect("the second link keeps a handoff of its own");
        assert_ne!(
            first.counters(),
            second.counters(),
            "with counters of its own, which the first link's peer does not lower"
        );
        assert_eq!(
            TokioRuntime::with_mutex_mut(&primary.link.shm_tx, |slot| slot
                .as_ref()
                .map(|kept| kept.counters())),
            Some(first.counters()),
            "while the first link still holds the counters its peer was told of"
        );
    }

    /// R3122 -- a link that sends an Open message again (a new establishment on it) keeps the new
    /// handoff and lets go of the old: its counters go back to the segment and what it kept is
    /// released, because the peer they were declared to is gone.
    #[test]
    fn a_link_that_opens_again_lets_go_of_the_handoff_it_kept() {
        use crate::runtime_impl::TokioRuntime;
        use wz_runtime_core::Runtime;
        use wz_session_core::link::LinkKind;

        let (actions, _) = crate::test_fixtures::recording_actions_over(LinkKind::Tcp);
        actions.install_shm_auth(Box::new(
            PosixShmAuthenticator::new().expect("create an authenticator"),
        ));
        actions.set_shm_offer(true);
        actions.negotiate_shm_against_peer(true);

        actions.shm_send_open_ack().expect("the first Open");
        let first = TokioRuntime::with_mutex_mut(&actions.link.shm_tx, |slot| slot.clone())
            .expect("the link keeps a handoff");
        let first_counters = first.counters();
        let watching_first = Arc::downgrade(&first);
        drop(first);
        assert!(
            watching_first.upgrade().is_some(),
            "the link still holds it"
        );

        actions.shm_send_open_ack().expect("the second Open");
        assert!(
            watching_first.upgrade().is_none(),
            "the second Open replaced it, and nothing else held it"
        );
        let second = TokioRuntime::with_mutex_mut(&actions.link.shm_tx, |slot| slot.clone())
            .expect("and the link keeps the new one");
        assert_ne!(
            second.counters(),
            first_counters,
            "which was leased while the old one was still held, so it has counters of its own"
        );
    }

    /// R3122 -- the links of a session may differ in reliability, and each declares by its own:
    /// a stream link keeps a handoff and a datagram link joined to the same session keeps none,
    /// where before R3122 the last Open message decided for both.
    #[cfg(feature = "transport-multilink")]
    #[test]
    fn the_links_of_a_session_declare_by_their_own_reliability() {
        use crate::multilink::{join_link, JoinOutcome};
        use crate::runtime_impl::TokioRuntime;
        use wz_runtime_core::Runtime;
        use wz_session_core::link::LinkKind;

        let (primary, _) = crate::test_fixtures::recording_actions_over(LinkKind::Tcp);
        let (secondary, _) = crate::test_fixtures::recording_actions_over(LinkKind::Udp);
        let key = vec![0x0Au8, 0x0B, 0x0C, 0x0D];
        primary
            .core
            .fact_multilink_pubkey(|s| *s = Some(key.clone()));
        secondary.core.fact_multilink_pubkey(|s| *s = Some(key));
        let JoinOutcome::Joined(datagram_link) = join_link(&primary, &secondary, 2) else {
            panic!("the second link joins the shared core");
        };
        primary.install_shm_auth(Box::new(
            PosixShmAuthenticator::new().expect("create an authenticator"),
        ));
        primary.set_shm_offer(true);
        primary.negotiate_shm_against_peer(true);

        primary.shm_send_open_ack().expect("the stream link's Open");
        datagram_link
            .shm_send_open_ack()
            .expect("the datagram link's Open");
        assert!(
            TokioRuntime::with_mutex_mut(&primary.link.shm_tx, |slot| slot.is_some()),
            "the stream link keeps a handoff"
        );
        assert!(
            TokioRuntime::with_mutex_mut(&datagram_link.link.shm_tx, |slot| slot.is_none()),
            "and the datagram link joined to the same session keeps none"
        );
    }

    /// R3122 -- THE TRANSACTION OPENS ON THE LINK THE MESSAGE LEAVES ON, through the real publish.
    /// One session holds a stream link and a datagram link; a reliable publish takes the stream
    /// link and counts its slice against that link's counters, and a best-effort publish takes the
    /// datagram link, which keeps no handoff, and counts against nothing: the counters the stream
    /// link's peer was told of are not touched by a message that never went to it.
    #[cfg(all(feature = "transport-multilink", feature = "codec-push"))]
    #[test]
    fn a_shared_memory_publish_is_counted_on_the_link_it_leaves_on() {
        use crate::multilink::{join_link, JoinOutcome};
        use crate::observer::ApplicationLayerObserver;
        use crate::runtime_impl::{TokioRuntime, TokioTime};
        use crate::session::{PublishOptions, TokioSession};
        use wz_runtime_core::Runtime;
        use wz_session_core::link::LinkKind;
        use wz_session_core::reliability::Reliability;

        let (stream, stream_driver) = crate::test_fixtures::recording_actions_over(LinkKind::Tcp);
        let (datagram, datagram_driver) =
            crate::test_fixtures::recording_actions_over(LinkKind::Udp);
        let key = vec![0x0Au8, 0x0B, 0x0C, 0x0D];
        stream
            .core
            .fact_multilink_pubkey(|s| *s = Some(key.clone()));
        datagram.core.fact_multilink_pubkey(|s| *s = Some(key));
        let JoinOutcome::Joined(datagram_link) = join_link(&stream, &datagram, 2) else {
            panic!("the datagram link joins the shared core");
        };
        stream.enter_established();
        datagram_link.enter_established();

        let authenticator = PosixShmAuthenticator::new().expect("create an authenticator");
        let segment = Arc::clone(&authenticator.segment);
        stream.install_shm_auth(Box::new(authenticator));
        stream.set_shm_offer(true);
        stream.negotiate_shm_against_peer(true);
        stream.shm_send_open_ack().expect("the stream link's Open");
        datagram_link
            .shm_send_open_ack()
            .expect("the datagram link's Open");
        let ids = TokioRuntime::with_mutex_mut(&stream.link.shm_tx, |slot| slot.clone())
            .expect("the stream link keeps a handoff")
            .counters();
        let owed = || -> u32 {
            ids.iter()
                .map(|&id| segment.counter(id).load(Ordering::SeqCst))
                .sum()
        };

        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let session = TokioSession::new(stream.clone(), observer, Arc::new(TokioTime::new()));
        let payload = crate::shm_buffer::IssuedBuffer::alloc(16).expect("alloc");

        session
            .publish_shm("home/stream", &payload, PublishOptions::default())
            .expect("a reliable publish");
        assert_eq!(stream_driver.frame_count(), 1, "it left on the stream link");
        assert_eq!(datagram_driver.frame_count(), 0);
        assert_eq!(owed(), 1, "and its slice is owed by the stream link's peer");

        session
            .publish_shm(
                "home/datagram",
                &payload,
                PublishOptions::default().with_reliability(Reliability::BestEffort),
            )
            .expect("a best-effort publish");
        assert_eq!(
            datagram_driver.frame_count(),
            1,
            "it left on the datagram link"
        );
        assert_eq!(stream_driver.frame_count(), 1);
        assert_eq!(
            owed(),
            1,
            "and is owed by nobody: the stream link's peer was never sent it"
        );
    }

    /// THE POINT, on a real chunk and the real validator. Its owner lets go the moment it is sent;
    /// from then on only the sender's handoff keeps the chunk confirmed. Validator windows later it
    /// is still valid, because nobody has acknowledged it; once the peer lowers the counter and the
    /// poll runs it is let go of, and the validator invalidates it.
    #[test]
    fn a_chunk_stays_valid_until_the_peer_acknowledges_it_and_not_after() {
        use zenoh_core::Wait;
        use zenoh_shm::api::provider::shm_provider::ShmProviderBuilder;

        let (segment, tx) = a_handoff();
        // The provider is the test's, so that the slot is not reclaimed and the invalidation can
        // be read after the owner has gone.
        let provider = Arc::new(
            ShmProviderBuilder::default_backend(1usize << 16)
                .wait()
                .expect("a provider"),
        );
        let allocated = provider.alloc(16usize).wait().expect("a buffer");
        let buffer = crate::shm_buffer::IssuedBuffer::new(
            allocated.into_inner(),
            Arc::clone(&provider) as Arc<dyn std::any::Any + Send + Sync>,
        );
        let (descriptor, chunk) = sent_descriptor(&buffer);
        let mut transaction = tx.begin(3);
        transaction.on_tx(&chunk);
        transaction.commit();
        drop(buffer);

        std::thread::sleep(std::time::Duration::from_millis(500));
        poll_tx_handoffs();
        assert_eq!(
            crate::shm_buffer::is_invalidated(&descriptor),
            Some(false),
            "the sender let a chunk lapse that its peer had not yet acknowledged"
        );

        segment
            .counter(tx.counters()[3])
            .fetch_sub(1, Ordering::SeqCst);
        poll_tx_handoffs();
        assert_eq!(tx.inner.holds(), 0, "the acknowledged chunk is let go of");
        let mut invalidated = false;
        for _ in 0..40 {
            if crate::shm_buffer::is_invalidated(&descriptor) == Some(true) {
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
