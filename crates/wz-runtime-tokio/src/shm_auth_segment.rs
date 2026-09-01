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
//! @ `pub struct TXAuthSegment`; 1.10.0 split the old single `ext/shm.rs` into
//! `ext/shm/{mod,auth,handoff,segment}.rs` and moved the segment out of
//! `zenoh-shm`'s `posix_shm/array.rs`).
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

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use memmap2::{Mmap, MmapMut, MmapOptions};
use wz_session_core::extshm::ShmAuthenticator;

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

/// zenoh retries id allocation this many times before giving up
/// (`posix_shm/segment.rs:22` `SEGMENT_DEDICATE_TRIES`).
const SEGMENT_DEDICATE_TRIES: usize = 100;

/// Per-process candidate-id source. Collisions BETWEEN PROCESSES are caught by
/// `create_new` (`O_EXCL`) and retried, so this only needs to spread — the same
/// discipline as `shm_provider::next_candidate_id`, and deliberately NOT
/// `rand`, which this crate does not otherwise pull in on the SHM path.
///
/// ⚠ `create_new` does NOT cover a collision between two draws of THIS counter,
/// which is why [`candidate_id`] must be injective in `c`. Retry only helps
/// while the colliding id is still occupied; an id whose segment has just been
/// unlinked is free, and a second draw then lands on it legitimately. R2201
/// measured that window as a live red — see [`candidate_id`].
static AUTH_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

/// The candidate id for counter value `c` in process `pid` — the whole of the
/// derivation, as a pure function so its one load-bearing property can be
/// asserted over a range this test picks rather than over whatever draws it
/// happened to win from the atomic.
///
/// # The property, and what it cost to learn
///
/// INJECTIVE in `c`. Two different counter values must never produce the same
/// id, and until R2201 they did — half the time.
///
/// The old form was `pid.wrapping_mul(K).wrapping_add(c) | 1`, where the `| 1`
/// enforced "never 0" by flattening the low BIT. Writing `b = pid * K`, that
/// makes `(b + c) | 1 == (b + c + 1) | 1` whenever `b + c` is even, so every
/// other pair of CONSECUTIVE counter values collapsed onto one id. Measured
/// over the first 64 draws (`c` from 1, as the counter starts): 33 distinct ids
/// for pid 17730, 32 for pid 99999.
///
/// That is not absorbed by `create`'s retry loop. Retry answers "this id is
/// TAKEN"; it says nothing about an id that was taken a microsecond ago and has
/// since been unlinked. Two segments drawn back to back, the first dropped
/// before the second is created, land on the SAME `/dev/shm/<id>.zenoh` — and
/// a reader still holding the first id then reads the second segment's
/// challenge. Layer C1bn caught exactly that, hosted, as
/// `a_created_segment_is_reopenable_by_id_and_yields_its_challenge` reading
/// `Some(42)` where it required `None`: `42` is the challenge of the test
/// running beside it.
///
/// # Why the counter is SHIFTED rather than special-cased
///
/// "Never 0" is now structural instead of a correction. `c << 1` leaves bit 0
/// free for the `| 1`, so the OR carries no information away: every id is odd,
/// hence never 0, and distinct `c` still give distinct ids. Special-casing
/// (`if v == 0 { 1 }`) would keep the full 2^32 range but re-introduce one
/// collision pair — the values mapping to 0 and to 1 — and a rule with an
/// exception is what this function is being repaired FOR.
///
/// The trade, stated rather than hidden: the period is 2^31 draws, not 2^32,
/// and every id is odd. Both are irrelevant against a retry budget of
/// [`SEGMENT_DEDICATE_TRIES`] and a namespace shared with foreign nodes that
/// pick their ids independently.
fn candidate_id(pid: u32, c: u32) -> u32 {
    pid.wrapping_mul(0x9E37_79B1).wrapping_add(c << 1) | 1
}

fn next_candidate_id() -> u32 {
    candidate_id(
        std::process::id(),
        AUTH_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
    )
}

/// The `/dev/shm` path zenoh's `shm_open("{id}.zenoh", ..)` resolves to. This
/// name IS interop: a foreign peer opens exactly this string.
fn auth_segment_path(segment_id: u32) -> PathBuf {
    PathBuf::from(format!("/dev/shm/{segment_id}.zenoh"))
}

/// Take a SHARED advisory lock, as zenoh does on both create and open
/// (`shm/unix.rs`, `try_lock(FileLockMode::Shared)`). Shared locks coexist, so
/// this never blocks a zenoh peer holding its own; it exists so wz participates
/// in the same protocol rather than silently opting out of it.
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
/// Holding the `MmapMut` alive keeps the mapping valid; the FILE stays on
/// `/dev/shm` until [`Drop`] unlinks it, which is what bounds the lifetime of
/// an id a peer may still try to open (a peer that opens after the unlink gets
/// `None`, i.e. "no SHM", which is the correct outcome).
pub struct ShmAuthSegment {
    _map: MmapMut,
    segment_id: u32,
    challenge: u64,
    path: PathBuf,
    /// Kept so the shared advisory lock lives as long as the segment does —
    /// `flock` locks are released when the last fd for the open file closes.
    _file: File,
}

impl ShmAuthSegment {
    /// Create this node's segment with `challenge`, retrying on an id
    /// collision. `challenge` is the caller's random u64; it is stored VERBATIM
    /// per upstream — 1.5.0 negated it, 1.10.0 does not (R2240), and a peer
    /// reading the negated form echoes a value that can never validate.
    pub fn create(challenge: u64) -> io::Result<Self> {
        let mut last_err = None;
        for _ in 0..SEGMENT_DEDICATE_TRIES {
            let segment_id = next_candidate_id();
            let path = auth_segment_path(segment_id);
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                // 0600, matching zenoh's `Mode::S_IRUSR | Mode::S_IWUSR`. A
                // peer running as another user cannot open it, which is
                // upstream's posture and not something to widen here.
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => {
                    file.set_len(SEGMENT_BYTES as u64)?;
                    lock_shared(&file)?;
                    // SAFETY: the file was just created exclusively by this
                    // process; the mapping is the only writer.
                    let mut map = unsafe { MmapOptions::new().map_mut(&file)? };
                    write_u64(&mut map, LEN_INDEX, WZ_PROTOCOLS.len() as u64);
                    // VERBATIM, per the module doc. 1.5.0 stored `!challenge`
                    // and 1.10.0 does not; a peer reading the inverted form
                    // echoes a value that can never match.
                    write_u64(&mut map, CHALLENGE_INDEX, challenge);
                    write_u64(&mut map, VERSION_INDEX, SHM_VERSION);
                    for (i, p) in WZ_PROTOCOLS.iter().enumerate() {
                        write_u32_at(
                            &mut map,
                            PROTOCOLS_OFFSET + i * core::mem::size_of::<u32>(),
                            *p,
                        );
                    }
                    map.flush()?;
                    return Ok(Self {
                        _map: map,
                        segment_id,
                        challenge,
                        path,
                        _file: file,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last_err = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::other("could not dedicate a POSIX shm auth segment after 100 tries")
        }))
    }

    /// This segment's id — the value that goes on the wire.
    pub fn id(&self) -> u32 {
        self.segment_id
    }

    /// The challenge a peer must echo back to prove it mapped this segment.
    pub fn challenge(&self) -> u64 {
        self.challenge
    }
}

impl Drop for ShmAuthSegment {
    fn drop(&mut self) {
        // Best-effort unlink, matching zenoh's cleanup registration. A failure
        // here leaves a 32-byte file in /dev/shm; it is not worth panicking in
        // a drop, and a stale segment reads as "no SHM" to any peer.
        let _ = std::fs::remove_file(&self.path);
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
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(auth_segment_path(segment_id))
        .ok()?;
    lock_shared(&file).ok()?;
    // SAFETY: a read-only view of a peer-owned mapping. The peer may write it
    // concurrently, which is exactly the shared-memory contract; every field
    // read is an 8-byte native load, and a torn value fails the comparison
    // rather than being unsound.
    let map: Mmap = unsafe { MmapOptions::new().map(&file).ok()? };
    if map.len() < SEGMENT_BYTES {
        return None;
    }
    if read_u64(&map, VERSION_INDEX)? != SHM_VERSION {
        return None;
    }
    // Verbatim, the mirror of `create`.
    read_u64(&map, CHALLENGE_INDEX)
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
