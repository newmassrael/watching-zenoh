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

use std::io;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use wz_session_core::extshm::{ShmAuthenticator, ShmHandoff, SHM_PRIORITY_BANDS};

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

/// The one protocol wz's segment advertises. Written into `protocols[0]` with
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
/// TEST-ONLY on purpose, and the reason is interop rather than tidiness: the
/// establishment path must NOT consult the peer's protocol list, because
/// upstream does not. `RXAuthSegment` is opened and its `challenge()` read with
/// no validation at all; the list is consulted later, at send time, by
/// `PartnerShmConfig::supports_protocol`. A reader here that rejected a peer
/// whose list it disliked would be stricter than the implementation it has to
/// interoperate with. What the slot IS for is the layout assertion, which is
/// where this is used.
#[cfg(test)]
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
}

impl ShmAuthSegment {
    /// Create this node's segment with `challenge`, retrying on an id
    /// collision. `challenge` is the caller's random u64; it is stored VERBATIM
    /// per upstream — 1.5.0 negated it, 1.10.0 does not (R2240), and a peer
    /// reading the negated form echoes a value that can never validate.
    pub fn create(challenge: u64) -> io::Result<Self> {
        let mut segment = OwnedSegment::create(SEGMENT_BYTES, || u64::from(next_candidate_id()))?;
        let map = segment.bytes_mut();
        write_u64(map, LEN_INDEX, WZ_PROTOCOLS.len() as u64);
        // VERBATIM, per the module doc. 1.5.0 stored `!challenge` and 1.10.0
        // does not; a peer reading the inverted form echoes a value that can
        // never match.
        write_u64(map, CHALLENGE_INDEX, challenge);
        write_u64(map, VERSION_INDEX, SHM_VERSION);
        for (i, p) in WZ_PROTOCOLS.iter().enumerate() {
            write_u32_at(map, PROTOCOLS_OFFSET + i * core::mem::size_of::<u32>(), *p);
        }
        segment.flush()?;
        Ok(Self { segment, challenge })
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

/// The [`ShmAuthenticator`] a session is handed at bring-up: this node's own
/// segment plus the ability to open a peer's.
pub struct PosixShmAuthenticator {
    segment: ShmAuthSegment,
}

impl PosixShmAuthenticator {
    /// Create this node's auth segment with a fresh challenge.
    ///
    /// The challenge is drawn from the same `getrandom` source the rest of the
    /// AP uses for handshake nonces, not from a counter: it is the value a peer
    /// must not be able to guess without mapping the segment, so a predictable
    /// one would make the whole exchange decorative.
    pub fn new() -> io::Result<Self> {
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| io::Error::other(format!("getrandom: {e}")))?;
        Ok(Self {
            segment: ShmAuthSegment::create(u64::from_ne_bytes(bytes))?,
        })
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

    fn open_peer_handoff(
        &self,
        peer_segment: u32,
        counters: &[u16; SHM_PRIORITY_BANDS],
    ) -> Option<Box<dyn ShmHandoff>> {
        PeerHandoff::open(peer_segment, counters)
            .map(|handoff| Box::new(handoff) as Box<dyn ShmHandoff>)
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
}
