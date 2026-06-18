// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Linkstate-peer routing driver (P4 routing, step c3a) — the
//! [`FaceForwarder`] SEAM that connects the [`LinkstateNetwork`] topology
//! graph to the [`accept_loop`](crate::accept_loop) /
//! [`peer_loop`](crate::accept_loop::peer_loop) face lifecycle.
//!
//! Periodic flood lives on the SEAM (R311rf): the self-flood cadence is the
//! forwarder's own protocol obligation, exposed through
//! [`FaceForwarder::tick_period`] / [`FaceForwarder::tick`], so the
//! [`face_drive_loop`](crate::accept_loop) drives it for EVERY `peer_loop`
//! caller — not only a demo that hand-rolls a flood `select!`. (Before R311rf
//! the period lived in the demo's `run_peer`, so a non-demo caller held faces
//! but never converged.)
//!
//! [`LinkstateForwarder`] is a [`FaceForwarder`]: as peer faces come and
//! go it connects/disconnects them in the graph
//! ([`register`](FaceForwarder::register) / [`deregister`](FaceForwarder::deregister)),
//! and on each inbound iteration event it extracts an `OAM_LINKSTATE`
//! message and feeds the decoded `LinkStateList` to the graph ingest,
//! recomputing the spanning trees ([`forward`](FaceForwarder::forward)).
//! On `register` it also BOOTSTRAPS the new neighbour — immediately
//! advertising its own link-state to that face (zenoh `add_link`'s
//! send-on-new-link) so the neighbour converges at once, not at the next
//! periodic tick.
//!
//! Single-task model: like [`RoutingForwarder`](crate::routing_forward),
//! the whole loop is one `!Send` task, so the graph is held behind a plain
//! `Rc<RefCell<…>>` — no `Mutex`, no `Send` bound. Each handler borrows
//! the cell only for its own synchronous duration, never across an
//! `.await`.
//!
//! What is NOT here yet: using the computed spanning trees to forward DATA
//! (`tree_children_of` is exposed but unused — the c3c atom), and the
//! change-triggered-flood / `Details` optimisations. `routing-peer`-gated.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use sce_forge_runtime::codec::CodecError;
use wz_codecs::linkstate_list::LinkstateListOwned;
use wz_codecs::oam::OamOwned;
use wz_session_core::driver_loop::DriverLoopOutcome;
use wz_session_core::linkstate_oam::{
    build_linkstate_oam_owned, try_parse_linkstate_oam, LinkstateOam,
};
use wz_session_core::network_message::NetworkMessage;

use wz_routing_graph::{Changes, LinkId, LinkstateNetwork, Zid};

use crate::accept_loop::{FaceForwarder, FaceId};
use crate::session_glue::{IterationEvent, SessionLinkActions};

/// Re-export so the peer-loop caller (the demo) names the neighbour role by
/// the same const the graph + forwarder use, not a bare `0x02` literal.
pub use wz_routing_graph::WHATAMI_PEER;

/// Cadence the linkstate peer re-advertises its own link-state on
/// ([`FaceForwarder::tick`] → [`LinkstateForwarder::flood_self`]) — the
/// periodic refresh of the mesh exchange; sn-staleness on each receiver drops
/// a re-flood of unchanged topology. zenoh's link-state is event-driven (no
/// fixed timer); a fixed cadence is the wz simplification, with
/// change-triggered flooding the tracked optimisation. Driven from the seam
/// (via [`FaceForwarder::tick_period`]) so every `peer_loop` caller converges,
/// not only a demo's hand-rolled `select!`.
const LINKSTATE_FLOOD_PERIOD: Duration = Duration::from_millis(1000);

/// A [`FaceForwarder`] that maintains the [`LinkstateNetwork`] topology
/// graph from the face lifecycle + inbound `OAM_LINKSTATE` messages. The
/// linkstate-peer counterpart to the data-plane
/// [`RoutingForwarder`](crate::routing_forward).
/// Per-face state the forwarder keeps for each held face: the send seam to
/// flood TO the face and, once the face's routing identity (zid) is known, the
/// graph link it maps to for ingest. One [`FaceId`]-keyed map of these (rather
/// than two parallel `FaceId`-keyed maps) so the send seam and the graph link
/// cannot drift out of sync.
struct FaceState {
    /// The face's transport send seam (an `Arc` clone of its
    /// `SessionLinkActions`), so [`LinkstateForwarder::flood_self`] and the
    /// register-time bootstrap can push the local link-state out on it.
    actions: Arc<SessionLinkActions>,
    /// The graph link this face maps to, once its peer zid surfaced at
    /// register — an inbound list is ingested against it (its psid<->zid
    /// mappings resolve the list). `None` for a face held without a routing
    /// identity: no graph link, so nothing to ingest against and no bootstrap
    /// target.
    link: Option<LinkId>,
}

pub struct LinkstateForwarder {
    /// Shared single-task topology graph (`Rc<RefCell>`, not `Mutex`).
    net: Rc<RefCell<LinkstateNetwork>>,
    /// Held faces keyed by id — each carries its send seam and (once its zid
    /// is known) its graph link. The single source for both "who do I flood
    /// to" and "which graph link did this list arrive on".
    faces: RefCell<HashMap<FaceId, FaceState>>,
    /// Running total of link-state lists ingested — the control-plane work
    /// witness (the linkstate analogue of `RoutingForwarder::forwarded`).
    ingested: Cell<usize>,
}

impl LinkstateForwarder {
    /// A driver seeded with the local node (this peer's zid + whatami).
    pub fn new(self_zid: Zid, self_whatami: u8) -> Self {
        Self {
            net: Rc::new(RefCell::new(LinkstateNetwork::new(self_zid, self_whatami))),
            faces: RefCell::new(HashMap::new()),
            ingested: Cell::new(0),
        }
    }

    /// A decoded topology `LinkStateList` arrived on `face`: ingest it
    /// against that face's graph link and recompute the spanning trees.
    /// Returns what the ingest changed, so the caller can re-flood it onward
    /// ([`propagate`](Self::propagate)).
    pub fn on_inbound_linkstate(&self, face: FaceId, list: LinkstateListOwned) -> Changes {
        let link_id = match self.faces.borrow().get(&face).and_then(|s| s.link) {
            Some(id) => id,
            // a list from a face with no graph link (unknown / no zid) is dropped.
            None => return Changes::default(),
        };
        let mut net = self.net.borrow_mut();
        let changes = net.ingest_linkstate_list(link_id, list);
        net.compute_trees();
        drop(net);
        self.ingested.set(self.ingested.get() + 1);
        changes
    }

    /// Re-flood the nodes an ingest changed to every face EXCEPT (a) the one
    /// it arrived on and (b), per face, the node whose own state it is —
    /// zenoh `propagate_link_states` (`network.rs:636-678`, called at the
    /// receive tail `:804`; the per-node exclusion is `:663`
    /// `link.zid != self.graph[idx].zid` — a peer never receives its own
    /// link-state echoed back). This is what carries topology TRANSITIVELY
    /// across a multi-hop mesh: a node B learns from face A is advertised
    /// onward to face C. sn-staleness on each receiver drops a re-flood of
    /// unchanged state, so the propagation converges rather than storming.
    /// Returns the number of faces propagated to. (zenoh's
    /// full-state-for-new / links-only-for-updated `Details` split is the
    /// deferred optimisation; wz sends the changed nodes full-state.)
    pub fn propagate(&self, source: FaceId, changes: &Changes) -> Result<usize, CodecError> {
        if changes.updated.is_empty() {
            return Ok(0);
        }
        let net = self.net.borrow();
        let mut sent = 0;
        for (id, state) in self.faces.borrow().iter() {
            if *id == source {
                continue;
            }
            let actions = &state.actions;
            // Drop the node whose own state this is from the list sent to ITS
            // face (zenoh `network.rs:663`) — the per-face payload differs, so
            // each face gets its own built carrier.
            let peer_zid = actions.peer_zid();
            let to_send: Vec<Zid> = changes
                .updated
                .iter()
                .filter(|z| peer_zid.as_deref() != Some(z.as_slice()))
                .cloned()
                .collect();
            if to_send.is_empty() {
                continue;
            }
            let oam = build_linkstate_oam_owned(&net.build_linkstate_for(&to_send))?;
            if actions
                .send_network_message(NetworkMessage::Oam(oam), true, false)
                .is_ok()
            {
                sent += 1;
            }
        }
        Ok(sent)
    }

    /// Total link-state lists ingested so far — the control-plane witness.
    pub fn ingested(&self) -> usize {
        self.ingested.get()
    }

    /// Number of nodes in the topology graph (self + every learned peer) —
    /// the graph-state witness (the demo logs it at shutdown).
    pub fn node_count(&self) -> usize {
        self.net.borrow().node_count()
    }

    /// This peer's children in the spanning tree rooted at `source` — the
    /// faces to forward a message flooded along `source`'s tree to. The
    /// data-forwarding atom (c3b) reads this; exposed now as the graph
    /// query the driver owns.
    pub fn tree_children_of(&self, source: &Zid) -> Vec<Zid> {
        self.net.borrow().tree_children_of(source)
    }

    /// Build the `OAM_LINKSTATE` carrier for this peer's full current topology
    /// — the shared body of [`flood_self`](Self::flood_self) (one carrier
    /// re-wrapped per face) and the per-face [`flood_self_to`](Self::flood_self_to)
    /// bootstrap. The graph builds the full-topology `LinkStateList` (c3b
    /// [`LinkstateNetwork::build_linkstate_list`]); `build_linkstate_oam_owned`
    /// (c1) wraps it in the carrier. Mirrors zenoh `make_msg`.
    fn build_self_oam(&self) -> Result<OamOwned, CodecError> {
        let list = self.net.borrow().build_linkstate_list();
        build_linkstate_oam_owned(&list)
    }

    /// Flood THIS peer's own link-state to every held face — the TX seam
    /// (c3d). Each face's [`SessionLinkActions::send_network_message`] puts it
    /// on the wire (reliably — topology is control traffic). Returns the number
    /// of faces the message reached. Mirrors zenoh `make_msg` + `send_on_links`.
    /// The WHEN is the forwarder's own [`FaceForwarder::tick`] cadence (R311rf
    /// — on the seam, so every caller converges).
    pub fn flood_self(&self) -> Result<usize, CodecError> {
        // `NetworkMessage` is not `Clone`, but `OamOwned` is — build the
        // carrier once and re-wrap a clone per face.
        let oam = self.build_self_oam()?;
        let mut sent = 0;
        for state in self.faces.borrow().values() {
            // a per-face send failure (link gone mid-flood) is skipped, not
            // fatal to the rest of the flood — the face's own driver will
            // surface its teardown via deregister.
            let msg = NetworkMessage::Oam(oam.clone());
            if state.actions.send_network_message(msg, true, false).is_ok() {
                sent += 1;
            }
        }
        Ok(sent)
    }

    /// Advertise this peer's full link-state to ONE face — the register-time
    /// bootstrap (zenoh `add_link`'s "send all nodes linkstate on new link",
    /// `network.rs:932`) so a freshly-up neighbour converges immediately rather
    /// than waiting up to one flood period for the next periodic tick. Reuses
    /// the same full-topology carrier [`flood_self`](Self::flood_self) builds.
    fn flood_self_to(&self, actions: &SessionLinkActions) -> Result<(), CodecError> {
        let oam = self.build_self_oam()?;
        let _ = actions.send_network_message(NetworkMessage::Oam(oam), true, false);
        Ok(())
    }
}

impl FaceForwarder for LinkstateForwarder {
    fn register(&self, id: FaceId, actions: &Arc<SessionLinkActions>) {
        // Connect the face in the graph if its routing zid surfaced at the
        // handshake (R311qi). Without a zid there is no graph identity to key
        // on, so the face is held (its send seam kept) but not connected — it
        // cannot route topology, and there is nothing to bootstrap it with.
        // The real handshake whatami is not yet threaded onto the face (a
        // tracked deferral — spanning-tree forwarding is whatami-agnostic;
        // only gossip/autoconnect would need the true role), so a neighbour is
        // recorded as WHATAMI_PEER.
        let link = actions
            .peer_zid()
            .map(|peer_zid| self.net.borrow_mut().add_link(peer_zid, WHATAMI_PEER));
        self.faces.borrow_mut().insert(
            id,
            FaceState {
                actions: actions.clone(),
                link,
            },
        );
        // Bootstrap a real routing neighbour: immediately advertise our full
        // link-state to it (zenoh `add_link`'s send-on-new-link) so it
        // converges now, not at the next periodic tick. A held-without-identity
        // face (link == None) is not a routing peer, so it is not bootstrapped.
        if link.is_some() {
            let _ = self.flood_self_to(actions);
        }
    }

    fn deregister(&self, id: FaceId) {
        // Drop the face's state; if it had a graph link, disconnect it.
        if let Some(state) = self.faces.borrow_mut().remove(&id) {
            if let Some(link) = state.link {
                self.net.borrow_mut().remove_link(link);
            }
        }
    }

    fn tick_period(&self) -> Option<Duration> {
        // The linkstate peer's periodic self-flood cadence — a protocol
        // obligation, so the loop drives it for every caller (R311rf).
        Some(LINKSTATE_FLOOD_PERIOD)
    }

    fn tick(&self) {
        // Re-advertise our own link-state to every held face. A CodecError
        // building the carrier drops this tick (the next one retries) rather
        // than tearing down the loop; a per-face send failure is skipped.
        let _ = self.flood_self();
    }

    fn forward(&self, id: FaceId, event: IterationEvent<'_>) {
        let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event else {
            return;
        };
        for message in messages {
            if let NetworkMessage::Oam(oam) = message {
                match try_parse_linkstate_oam(oam) {
                    LinkstateOam::Decoded(list) => {
                        // ingest, then re-flood the changed nodes onward to
                        // the OTHER faces (transitive propagation).
                        let changes = self.on_inbound_linkstate(id, list);
                        let _ = self.propagate(id, &changes);
                    }
                    // a malformed OAM_LINKSTATE or a non-linkstate OAM is
                    // left alone (the generic OAM path / a logged drop).
                    LinkstateOam::Malformed(_) | LinkstateOam::NotLinkstate => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_impl::TokioRuntime;
    use crate::test_fixtures::{recording_actions, RecordingLinkDriver};
    use sce_forge_runtime::codec::SceBytes;
    use wz_codecs::linkstate::LinkstateOwned;
    use wz_codecs::linkstate_link::LinkstateLink;
    use wz_runtime_core::runtime::Runtime;

    fn zid(b: u8) -> Zid {
        vec![b, b, b, b]
    }

    /// A recording-actions face whose remote peer zid is `peer`, so `register`
    /// connects it in the graph — the production face-up path (a face with no
    /// zid is held but not graph-connected). Returns the sink so a test can
    /// assert the frames the face received.
    fn peer_face(peer: Zid) -> (Arc<SessionLinkActions>, Arc<RecordingLinkDriver>) {
        let (actions, sink) = recording_actions();
        TokioRuntime::with_mutex_mut(&actions.remote_peer_zid, |s| *s = Some(peer));
        (actions, sink)
    }

    /// A one-entry LinkStateList where the entry advertises its own zid.
    fn list_with_node(psid: u64, sn: u64, node: u8) -> LinkstateListOwned {
        LinkstateListOwned {
            num_link_states: 1,
            link_states: vec![LinkstateOwned {
                options: 0,
                psid,
                sn,
                zid_len: Some(4),
                zid: Some(SceBytes::from_slice(&zid(node)).unwrap()),
                whatami: Some(2),
                num_locators: None,
                locators: None,
                links_len: 0,
                links: Vec::<LinkstateLink>::new(),
                weights: None,
            }],
        }
    }

    #[test]
    fn face_up_connects_neighbour() {
        let fwd = LinkstateForwarder::new(zid(0x01), 2);
        let (face, _sink) = peer_face(zid(0xAA));
        fwd.register(FaceId(7), &face);
        // self + the neighbour node.
        assert_eq!(fwd.net.borrow().node_count(), 2);
    }

    #[test]
    fn inbound_linkstate_grows_the_graph_and_counts() {
        let fwd = LinkstateForwarder::new(zid(0x01), 2);
        let (face, _sink) = peer_face(zid(0xAA));
        fwd.register(FaceId(7), &face);
        // the neighbour A floods a list announcing a far node B.
        fwd.on_inbound_linkstate(FaceId(7), list_with_node(11, 5, 0xBB));
        assert_eq!(fwd.ingested(), 1);
        assert!(fwd.net.borrow().get_node(&zid(0xBB)).is_some());
    }

    #[test]
    fn inbound_from_unknown_face_is_dropped() {
        let fwd = LinkstateForwarder::new(zid(0x01), 2);
        // no face registered for id 9.
        fwd.on_inbound_linkstate(FaceId(9), list_with_node(11, 5, 0xBB));
        assert_eq!(fwd.ingested(), 0);
        assert!(fwd.net.borrow().get_node(&zid(0xBB)).is_none());
    }

    #[test]
    fn face_down_disconnects_neighbour() {
        let fwd = LinkstateForwarder::new(zid(0x01), 2);
        let (face, _sink) = peer_face(zid(0xAA));
        fwd.register(FaceId(7), &face);
        assert_eq!(fwd.net.borrow().node_count(), 2);
        fwd.deregister(FaceId(7));
        // the link mapping is gone; a later inbound on that face is dropped.
        fwd.on_inbound_linkstate(FaceId(7), list_with_node(11, 5, 0xBB));
        assert_eq!(fwd.ingested(), 0);
    }

    #[test]
    fn flood_self_sends_link_state_to_every_face() {
        // the TX seam: flood_self pushes the local link-state out on each
        // held face's send seam (the OAM landing as one frame per face).
        let fwd = LinkstateForwarder::new(zid(0x01), 2);
        let (face_a, sink_a) = recording_actions();
        let (face_b, sink_b) = recording_actions();
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);

        let sent = fwd.flood_self().expect("flood self");
        assert_eq!(sent, 2, "flooded both held faces");
        assert_eq!(sink_a.frame_count(), 1, "face A received the link-state");
        assert_eq!(sink_b.frame_count(), 1, "face B received the link-state");
    }

    #[test]
    fn deregister_stops_flooding_a_face() {
        let fwd = LinkstateForwarder::new(zid(0x01), 2);
        let (face_a, sink_a) = recording_actions();
        fwd.register(FaceId(0), &face_a);
        fwd.deregister(FaceId(0));
        let sent = fwd.flood_self().expect("flood self after deregister");
        assert_eq!(sent, 0, "the deregistered face is no longer flooded");
        assert_eq!(sink_a.frame_count(), 0);
    }

    #[test]
    fn propagate_re_floods_changed_nodes_to_other_faces() {
        // a change that arrived on face 0 is re-flooded to face 1, never
        // back to its source (transitive propagation; zenoh excludes src).
        let fwd = LinkstateForwarder::new(zid(0x0B), 2);
        let (source, source_sink) = recording_actions();
        let (other, other_sink) = recording_actions();
        fwd.register(FaceId(0), &source);
        fwd.register(FaceId(1), &other);

        // the self node is always in the graph, so it resolves in build.
        let changes = Changes {
            updated: vec![zid(0x0B)],
        };
        let sent = fwd.propagate(FaceId(0), &changes).expect("propagate");
        assert_eq!(sent, 1, "propagated to the other face only");
        assert_eq!(source_sink.frame_count(), 0, "not back to the source");
        assert_eq!(
            other_sink.frame_count(),
            1,
            "the other face got the re-flood"
        );
    }

    #[test]
    fn propagate_with_no_changes_sends_nothing() {
        let fwd = LinkstateForwarder::new(zid(0x0B), 2);
        let (other, other_sink) = recording_actions();
        fwd.register(FaceId(1), &other);
        let sent = fwd
            .propagate(FaceId(0), &Changes::default())
            .expect("propagate empty");
        assert_eq!(sent, 0, "an empty change set floods nothing");
        assert_eq!(other_sink.frame_count(), 0);
    }

    #[test]
    fn propagate_excludes_a_node_from_its_own_face() {
        // zenoh network.rs:663 — a peer never receives its OWN link-state
        // echoed. With faces to A (zid 0x0A) and C (zid 0x0C) held, a change
        // to A's state propagates to C but NOT back to A's own face.
        let fwd = LinkstateForwarder::new(zid(0x0B), 2);
        let (peer_a, sink_a) = peer_face(zid(0x0A));
        let (peer_c, sink_c) = peer_face(zid(0x0C));
        // register connects each face in the graph AND bootstraps it (a
        // face-up self-flood); reset the sinks after so the assertion counts
        // only the frames `propagate` emits.
        fwd.register(FaceId(1), &peer_a); // graph gains node 0x0A
        fwd.register(FaceId(2), &peer_c); // graph gains node 0x0C
        sink_a.reset();
        sink_c.reset();

        // A's state changed; source is an unregistered face so both A and C
        // are propagation candidates.
        let changes = Changes {
            updated: vec![zid(0x0A)],
        };
        fwd.propagate(FaceId(99), &changes).expect("propagate");
        assert_eq!(
            sink_a.frame_count(),
            0,
            "A's own state is not echoed back to A's face"
        );
        assert_eq!(sink_c.frame_count(), 1, "C receives A's changed state");
    }

    #[test]
    fn register_bootstraps_the_new_neighbour() {
        // R311rf — a face with a routing zid is bootstrapped on register:
        // the forwarder immediately advertises its own link-state to it, so a
        // freshly-up neighbour converges without waiting for the next tick.
        let fwd = LinkstateForwarder::new(zid(0x0B), 2);
        let (peer, sink) = peer_face(zid(0x0A));
        fwd.register(FaceId(1), &peer);
        assert_eq!(
            sink.frame_count(),
            1,
            "the new neighbour received the bootstrap link-state on register"
        );
    }

    #[test]
    fn register_without_zid_does_not_bootstrap() {
        // A face held without a routing identity (no zid) is not a graph
        // neighbour, so there is nothing to bootstrap it with.
        let fwd = LinkstateForwarder::new(zid(0x0B), 2);
        let (face, sink) = recording_actions();
        fwd.register(FaceId(1), &face);
        assert_eq!(
            sink.frame_count(),
            0,
            "a zid-less held face is not bootstrapped"
        );
    }
}
