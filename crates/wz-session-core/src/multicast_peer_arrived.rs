// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2728 (§5.21 `router-multicast-faces`) — the multicast ARRIVAL observer
//! surface: who joined the group, and in which role.
//!
//! The admitting twin of [`crate::multicast_peer_lost`], and it exists because
//! the group had only the departure half. R311y784 built the departure on the
//! argument that the dispatcher drove a peer's FSM to Expired, freed its slot,
//! and the application was never told. The ADMITTING side carried the same
//! silence and nobody had written it down: an application told that a peer LEFT
//! but never told that one ARRIVED cannot hold a membership view at all, since
//! the first event it can observe about any peer is that peer's removal.
//!
//! BOTH REFERENCES ANNOUNCE THE ADMISSION, and each does it in the new-entry
//! branch rather than on every beacon. zenoh hands the admitted peer to its
//! router, which mints a FACE for it and stamps the peer's zid onto that face
//! (`zenoh/src/net/routing/gateway.rs` @ `pub fn new_peer_multicast`), then
//! keeps it in the group's per-peer face list
//! (`zenoh/src/net/routing/gateway.rs` @ `mcast_faces.push(face.clone())`).
//! zenoh-pico fires its connectivity callback from the branch that allocates
//! the new peer entry
//! (`vendor/zenoh-pico/src/transport/multicast/rx.c` @
//! `_z_connectivity_peer_connected(`), with its `is_multicast` argument true.
//!
//! WHY THE ROLE RIDES ALONG. Upstream's arrival carries a whole `TransportPeer`
//! and the face it builds is classified by that peer's `whatami`. wz's group
//! learns the same field from the JOIN beacon and already stores it per slot,
//! so the event carries what the reference's face-builder consumes rather than
//! a zid a consumer would have to go back and re-look-up — and `Option` because
//! an unrecognized wire code is a peer whose role this node does not know, which
//! is a different fact from a peer that announced Client.
//!
//! The types live HERE for the same reason the departure types do, and the
//! reason is not cosmetic: they are allocation-free, while their PRODUCER is the
//! multicast Router in `multicast_dispatch` / `multicast_rx`, which compiles on
//! the no-alloc MCU profile where the `alloc`-gated `driver_loop` does not exist
//! at all. `driver_loop` re-exports them for the alloc-side consumers.
//!
//! (`multicast_dispatch`, `multicast_rx` and `driver_loop` are code spans rather
//! than intra-doc links: the first two are `session-multicast`-gated and the
//! third is `alloc`-gated, so none is present in the default-feature rustdoc run
//! Layer C1bz measures.)

use wz_codecs::whatami::WhatAmI;

use crate::multicast_peer_lost::MulticastPeerId;

/// R2728 — one peer's ADMISSION to the multicast group: who joined, and in
/// which role.
///
/// Fired ONCE per admission, from the branch that allocates the peer its slot —
/// never from the refresh a live peer's periodic beacon takes. That is the same
/// distinction both references draw by call site, and it is the one that makes
/// the event usable: a consumer that builds per-peer state on arrival must not
/// rebuild it every join interval.
///
/// `Copy`, like its departure twin, because it rides
/// `driver_loop::IterationEvent`, which is `Copy` by contract so one observer
/// callback can fan the same event to several consumers without reconstructing
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MulticastPeerArrived {
    /// The arriving peer's zid, as its JOIN announced it.
    pub peer: MulticastPeerId,
    /// The role the JOIN announced, or `None` when the wire code is one this
    /// node does not recognize. Carried because it is what upstream's
    /// face-builder classifies the new face by, and because "this node does not
    /// know the role" is a different fact from any role it does know.
    pub whatami: Option<WhatAmI>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multicast_peer_lost::OBSERVER_ZID_MAX;

    /// The arrival surface is usable with no allocator at all — the value-side
    /// half of the claim whose build-side half is the no-alloc MCU
    /// cross-compile (run-ci Layer G.12). Deliberately in THIS module rather
    /// than `driver_loop`, so it is compiled by the same feature set the MCU
    /// profile selects — the argument its departure twin already makes.
    #[test]
    fn arrival_round_trips_without_alloc() {
        let arrived = MulticastPeerArrived {
            peer: MulticastPeerId::from_wire(&[0xAA, 0xBB, 0xCC]),
            whatami: Some(WhatAmI::Router),
        };
        assert_eq!(arrived.peer.as_slice(), &[0xAA, 0xBB, 0xCC]);
        assert_eq!(arrived.whatami, Some(WhatAmI::Router));
        // `Copy` by contract — one observer callback fans the same event to
        // several consumers without reconstructing it.
        let fanned = arrived;
        assert_eq!(fanned, arrived);
    }

    /// An unrecognized wire role is `None`, which is NOT the same value as any
    /// role this node knows. Asserted because the field's whole reason for
    /// being an `Option` is that a consumer must be able to tell "the peer
    /// announced Client" from "this node could not read the announcement".
    #[test]
    fn an_unknown_role_is_distinguishable_from_every_known_one() {
        let unknown = MulticastPeerArrived {
            peer: MulticastPeerId::from_wire(&[0x01]),
            whatami: None,
        };
        for known in [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client] {
            assert_ne!(
                unknown.whatami,
                Some(known),
                "an unread role must not read as {known:?}",
            );
        }
    }

    /// An over-long zid is clamped rather than panicked on, the same contract
    /// the departure surface holds: the wire is untrusted and a 17-byte ZID is
    /// already malformed upstream.
    #[test]
    fn an_over_long_arriving_zid_clamps_to_the_bound() {
        let arrived = MulticastPeerArrived {
            peer: MulticastPeerId::from_wire(&[0x22; OBSERVER_ZID_MAX + 3]),
            whatami: None,
        };
        assert_eq!(arrived.peer.as_slice().len(), OBSERVER_ZID_MAX);
    }
}
