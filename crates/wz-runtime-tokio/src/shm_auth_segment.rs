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
//! nothing (`commons/zenoh-shm/src/posix_shm/array.rs` `AuthSegment`,
//! `io/zenoh-transport/src/unicast/establishment/ext/shm.rs`).
//!
//! ## The layout is a wire format
//!
//! A foreign zenohd opens this object and reads it as
//! `ArrayInSHM<AuthSegmentID, AuthChallenge, usize>` — an array of `u64`:
//!
//! | index | field | note |
//! |---|---|---|
//! | 0 | `protocols.len()` | count of the trailing protocol ids |
//! | 1 | `!challenge` | INVERTED on purpose (see below) |
//! | 2 | `SHM_VERSION` | `1`; a mismatch means "no SHM", not an error |
//! | 3.. | `ProtocolID` each | `POSIX_PROTOCOL_ID = 0` |
//!
//! The challenge is stored BITWISE-NEGATED. Upstream's comment says why: "to
//! prevent SHM probing between new versioned SHM implementation and the old
//! one" — an older reader that does not know about the version word would find
//! a challenge that never matches instead of a plausible one. So the inversion
//! is load-bearing interop, not obfuscation, and both write and read apply it.
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

/// zenoh `SHM_VERSION` (`commons/zenoh-shm/src/version.rs:15`). A peer whose
/// segment carries a different value is treated as "no SHM".
const SHM_VERSION: u64 = 1;
/// zenoh `POSIX_PROTOCOL_ID` (`api/protocol_implementations/posix/protocol_id.rs:19`).
const POSIX_PROTOCOL_ID: u64 = 0;

/// Array indices, named as upstream names them (`ext/shm.rs:38-41`).
const LEN_INDEX: usize = 0;
const CHALLENGE_INDEX: usize = 1;
const VERSION_INDEX: usize = 2;
const ID_START_INDEX: usize = 3;

/// The one protocol wz's segment advertises, so the array is exactly four u64s.
const WZ_PROTOCOLS: [u64; 1] = [POSIX_PROTOCOL_ID];
const SEGMENT_ELEMS: usize = ID_START_INDEX + WZ_PROTOCOLS.len();
const SEGMENT_BYTES: usize = SEGMENT_ELEMS * core::mem::size_of::<u64>();

/// zenoh retries id allocation this many times before giving up
/// (`posix_shm/segment.rs:22` `SEGMENT_DEDICATE_TRIES`).
const SEGMENT_DEDICATE_TRIES: usize = 100;

/// Per-process candidate-id source. Collisions are caught by `create_new`
/// (`O_EXCL`) and retried, so this only needs to spread — the same discipline
/// as `shm_provider::next_candidate_id`, and deliberately NOT `rand`, which
/// this crate does not otherwise pull in on the SHM path.
static AUTH_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

fn next_candidate_id() -> u32 {
    let pid = std::process::id();
    let c = AUTH_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    // Never 0: a zero id renders as the file "0.zenoh", which is legal but is
    // also what an uninitialised value looks like on the wire.
    pid.wrapping_mul(0x9E37_79B1).wrapping_add(c) | 1
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
    /// collision. `challenge` is the caller's random u64; it is stored INVERTED
    /// per upstream.
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
                    // INVERTED, per the module doc.
                    write_u64(&mut map, CHALLENGE_INDEX, !challenge);
                    write_u64(&mut map, VERSION_INDEX, SHM_VERSION);
                    for (i, p) in WZ_PROTOCOLS.iter().enumerate() {
                        write_u64(&mut map, ID_START_INDEX + i, *p);
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
    // Un-invert, the mirror of `create`.
    Some(!read_u64(&map, CHALLENGE_INDEX)?)
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

    /// The challenge is stored BITWISE-NEGATED, as upstream stores it. Asserted
    /// on the RAW BYTES rather than through the accessor, because the accessor
    /// inverts on both sides and would pass either way — and it is the raw
    /// bytes a zenohd reads.
    #[test]
    fn the_challenge_is_stored_inverted_on_the_page() {
        let challenge = 0x0123_4567_89AB_CDEFu64;
        let seg = ShmAuthSegment::create(challenge).expect("create");
        let raw = std::fs::read(auth_segment_path(seg.id())).expect("read back");
        assert_eq!(raw.len(), SEGMENT_BYTES);
        assert_eq!(read_u64(&raw, CHALLENGE_INDEX), Some(!challenge));
        assert_ne!(
            read_u64(&raw, CHALLENGE_INDEX),
            Some(challenge),
            "storing it uninverted is the bug this pins"
        );
    }

    /// The rest of the layout is what a foreign reader indexes into: the
    /// protocol COUNT at 0, the VERSION at 2, and `POSIX_PROTOCOL_ID` at 3.
    #[test]
    fn the_array_layout_matches_what_a_foreign_reader_indexes() {
        let seg = ShmAuthSegment::create(1).expect("create");
        let raw = std::fs::read(auth_segment_path(seg.id())).expect("read back");
        assert_eq!(read_u64(&raw, LEN_INDEX), Some(1), "one protocol");
        assert_eq!(read_u64(&raw, VERSION_INDEX), Some(SHM_VERSION));
        assert_eq!(read_u64(&raw, ID_START_INDEX), Some(POSIX_PROTOCOL_ID));
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
