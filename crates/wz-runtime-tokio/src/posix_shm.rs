// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2862 (`transport-shm`) — the ONE implementation of a shared-memory
//! segment the way upstream makes one, for every segment wz creates or opens:
//! the auth segment of the establishment challenge, and the metadata and data
//! segments of an SHM payload.
//!
//! Upstream has one such type, `posix_shm::segment::Segment<ID>` over
//! `shm::SegmentImpl` (`commons/zenoh-shm/src/shm/mod.rs` @ `use windows as platform;`),
//! and every segment kind is a `Segment` of some id width. wz had the naming, the
//! shared advisory lock and the create-and-retry loop written inside the auth
//! segment, and a second, INCOMPATIBLE naming (`wz-shm-<hex>.wz`) inside the payload
//! provider — so a payload segment was one no zenoh peer could ever open. Everything
//! that is wire format about a segment lives here, in one file per platform that
//! upstream also splits by platform:
//!
//! * Unix (`unix`): a `/dev/shm/{id}.zenoh` file, mode 0600, under a shared,
//!   non-blocking `flock`, mapped with `mmap`;
//! * Windows (`windows`): a pagefile-backed named file mapping called `"{id}.zenoh"`.
//!
//! The id is decimal whatever its width, and the id source below is shared, so two
//! segment kinds in one process never hand out one id twice.

use std::sync::atomic::{AtomicU32, Ordering};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

pub use platform::{cleanup_orphaned_segments, OwnedSegment, PeerSegment, PeerSegmentRw};
#[cfg(unix)]
pub use unix::segment_path;

/// How many ids a create tries before giving up — upstream's
/// `SEGMENT_DEDICATE_TRIES` (`commons/zenoh-shm/src/posix_shm/segment.rs` @
/// `const SEGMENT_DEDICATE_TRIES: usize = 100;`).
pub const SEGMENT_DEDICATE_TRIES: usize = 100;

/// Per-process candidate-id source, ONE for every segment kind this process
/// makes. Collisions BETWEEN processes are caught by the create call refusing a
/// name that is taken (`O_EXCL` on Unix, `ERROR_ALREADY_EXISTS` on Windows) and
/// retried, so this only needs to spread. Moved here from the auth segment
/// in R2862: the payload provider's metadata and data segments share the same
/// namespace, and two counters would be two chances to hand out one id twice.
///
/// ⚠ A refused name does NOT cover a collision between two draws of THIS
/// counter, which is why [`candidate_id`] must be injective in `c`. Retry only
/// helps while the colliding id is still occupied; an id whose segment has just
/// been unlinked is free, and a second draw then lands on it legitimately.
static ID_COUNTER: AtomicU32 = AtomicU32::new(1);

/// The candidate id for counter value `c` in process `pid`, as a pure function
/// so its one load-bearing property can be asserted over a range a test picks.
///
/// INJECTIVE in `c` (R2201). The earlier form `pid * K + c | 1` flattened the
/// low bit, so every other pair of consecutive counter values collapsed onto
/// one id, and a reader still holding the first id then read the second
/// segment — Layer C1bn caught it hosted. `c << 1` leaves bit 0 free for the
/// `| 1`, so every id is odd (hence never 0) and distinct `c` give distinct
/// ids; the period is 2^31 draws, irrelevant against a retry budget of
/// [`SEGMENT_DEDICATE_TRIES`].
pub fn candidate_id(pid: u32, c: u32) -> u32 {
    pid.wrapping_mul(0x9E37_79B1).wrapping_add(c << 1) | 1
}

/// The next candidate id from this process's counter.
pub fn next_candidate_id() -> u32 {
    candidate_id(
        std::process::id(),
        ID_COUNTER.fetch_add(1, Ordering::Relaxed),
    )
}
