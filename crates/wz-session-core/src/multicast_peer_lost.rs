// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y784 / R311y787 — the multicast departure observer surface:
//! who left the group, and which of the two ways.
//!
//! These three types ride [`crate::driver_loop::IterationEvent`], which is
//! where they were first authored (R311y784) — but they cannot LIVE there.
//! `driver_loop` is `alloc`-gated (its outcome envelope carries `Vec`), while
//! the producer of every departure is the multicast Router in
//! `crate::multicast_dispatch`, which compiles on the no-alloc MCU profile
//! (`--no-default-features --features session-multicast,no_std`, run-ci Layer
//! G.12). An import of an `alloc`-gated module from an alloc-free one is an
//! E0432 on exactly that profile, and it is what R311y787 pays off.
//!
//! So the types live here, ungated and allocation-free — a fixed
//! [`OBSERVER_ZID_MAX`](crate::multicast_peer_lost::OBSERVER_ZID_MAX) byte
//! buffer and two field-less enum arms — and `driver_loop` re-exports them for
//! the alloc-side consumers that already name them through that path. The
//! split is the same one the crate already draws for
//! `crate::reassembly_dispatch`: the layer an MCU build keeps is the layer
//! that owns the type.
//!
//! The two dispatchers are named as code spans rather than intra-doc links
//! because both are feature-gated (`session-multicast` / `reassembly`) and so
//! do not exist in the default-feature rustdoc run Layer C1bz measures; the
//! constant is fully qualified because this module doc is merged with the
//! outer `///` on `pub mod multicast_peer_lost;` in `lib.rs`, and the merged
//! text resolves relative links against the CRATE ROOT.

/// The maximum length of a zenoh ZID, in bytes. The peer table keys on the
/// same bound (`multicast_dispatch`), and this is the ungated copy so the
/// observer surface below does not depend on `session-multicast`.
pub const OBSERVER_ZID_MAX: usize = 16;

/// R311y784 — a multicast group peer's identity, in the fixed `(bytes, len)`
/// form the peer table already keys on.
///
/// A value type rather than a borrow because it rides
/// [`crate::driver_loop::IterationEvent`], which is `Copy` by contract (one
/// observer callback fans the same event to several consumers without
/// reconstructing it), and because the peer it names is GONE by the time an
/// observer sees it — there is no slot left to borrow from. That is the whole
/// reason a departure has to carry its identity rather than a table index: the
/// index is already recycled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MulticastPeerId {
    bytes: [u8; OBSERVER_ZID_MAX],
    len: u8,
}

impl MulticastPeerId {
    /// Build from a wire zid, clamping to [`OBSERVER_ZID_MAX`] (a zenoh ZID is
    /// 1..=16 bytes, so a longer input is already malformed upstream).
    pub fn from_wire(zid: &[u8]) -> Self {
        let mut bytes = [0u8; OBSERVER_ZID_MAX];
        let len = core::cmp::min(zid.len(), OBSERVER_ZID_MAX);
        bytes[..len].copy_from_slice(&zid[..len]);
        Self {
            bytes,
            len: len as u8,
        }
    }

    /// The zid bytes as they appeared on the wire.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

/// R311y784 — why a multicast group peer left, surfaced on
/// [`crate::driver_loop::IterationEvent::MulticastPeerLost`].
///
/// The two arms are zenoh's two `del_peer` reasons, which is where the
/// distinction is load-bearing rather than decorative: an inbound Close is the
/// peer SAYING it left (`multicast/rx.rs:310-313`, forwarding the Close's own
/// reason byte), while a lease expiry is this node INFERRING it from silence
/// (`multicast/transport.rs:401`, hard-coded `close::reason::EXPIRED`). An
/// application that treats a graceful departure and an unreachable peer alike
/// cannot tell a clean shutdown from a dead link. zenoh-pico keeps them apart
/// the same way, by call site (`multicast/rx.c:513-536` vs
/// `multicast/lease.c:110-133`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MulticastPeerLostReason {
    /// The peer multicast a Close. Its own announcement, not an inference.
    Closed,
    /// The peer's lease elapsed with no inbound message. An inference from
    /// silence: the peer may be gone, partitioned, or merely wedged.
    LeaseExpired,
}

/// R311y784 — one peer's departure from the multicast group: who left and
/// which of the two ways.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MulticastPeerLost {
    /// The departing peer's zid, learned from the JOIN that admitted it.
    pub peer: MulticastPeerId,
    /// Announced departure vs inferred silence.
    pub reason: MulticastPeerLostReason,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R311y787 — the departure surface is usable with no allocator at all.
    /// The build-side half of this claim is run-ci Layer G.12 (the no-alloc
    /// MCU cross-compile that E0432'd for two rounds); this is the value-side
    /// half, and it is deliberately in THIS module rather than `driver_loop`
    /// so it is compiled by the same feature set the MCU profile selects.
    #[test]
    fn departure_round_trips_without_alloc() {
        let lost = MulticastPeerLost {
            peer: MulticastPeerId::from_wire(&[0xAA, 0xBB, 0xCC]),
            reason: MulticastPeerLostReason::Closed,
        };
        assert_eq!(lost.peer.as_slice(), &[0xAA, 0xBB, 0xCC]);
        assert_eq!(lost.reason, MulticastPeerLostReason::Closed);
        // `Copy` by contract — one observer callback fans the same event to
        // several consumers without reconstructing it.
        let fanned = lost;
        assert_eq!(fanned, lost);
    }

    /// An over-long zid is clamped, not panicked on: the wire is untrusted and
    /// a 17-byte ZID is already malformed upstream.
    #[test]
    fn over_long_zid_clamps_to_the_bound() {
        let id = MulticastPeerId::from_wire(&[0x11; OBSERVER_ZID_MAX + 4]);
        assert_eq!(id.as_slice().len(), OBSERVER_ZID_MAX);
        assert_eq!(id.as_slice(), &[0x11; OBSERVER_ZID_MAX]);
    }

    /// An absent zid (a peer evicted before its JOIN named it) is the empty
    /// slice, not a 16-byte run of zeroes — `multicast_dispatch::departure`
    /// builds exactly this for a slot with no recorded zid.
    #[test]
    fn absent_zid_is_empty_not_zero_padded() {
        let id = MulticastPeerId::from_wire(&[]);
        assert!(id.as_slice().is_empty());
    }
}
