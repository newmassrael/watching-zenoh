// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Linkstate-peer routing driver (P4 routing, step c3a) — the
//! [`FaceForwarder`] SEAM that connects the [`LinkstateNetwork`] topology
//! graph to the [`accept_loop`](crate::accept_loop) /
//! [`peer_loop`](crate::accept_loop::peer_loop) face lifecycle.
//!
//! IMPORTANT — not yet installed: [`LinkstateForwarder`] *implements* the
//! seam but no live loop passes it yet (every `peer_loop` call still uses
//! [`NoOpForwarder`](crate::accept_loop::NoOpForwarder), e.g. the demo's
//! `run_peer`). Installing it into `peer_loop` is the c3d atom; combined
//! with the absent self-link-state TX (below) the subsystem does not yet
//! exchange topology in production. So far this is unit-test-only.
//!
//! [`LinkstateForwarder`] is a [`FaceForwarder`]: as peer faces come and
//! go it connects/disconnects them in the graph
//! ([`register`](FaceForwarder::register) / [`deregister`](FaceForwarder::deregister)),
//! and on each inbound iteration event it extracts an `OAM_LINKSTATE`
//! message and feeds the decoded `LinkStateList` to the graph ingest,
//! recomputing the spanning trees ([`forward`](FaceForwarder::forward)).
//!
//! Single-task model: like [`RoutingForwarder`](crate::routing_forward),
//! the whole loop is one `!Send` task, so the graph is held behind a plain
//! `Rc<RefCell<…>>` — no `Mutex`, no `Send` bound. Each handler borrows
//! the cell only for its own synchronous duration, never across an
//! `.await`.
//!
//! What is NOT here yet: emitting self's own link-state on a timer
//! (`make_msg` send), `Changes`-driven gossip re-flooding, and using the
//! computed trees to forward DATA — those are the c3b+ atoms.
//! `routing-peer`-gated.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use sce_forge_runtime::codec::CodecError;
use wz_codecs::linkstate_list::LinkstateListOwned;
use wz_session_core::driver_loop::DriverLoopOutcome;
use wz_session_core::linkstate_oam::{
    build_linkstate_oam_owned, try_parse_linkstate_oam, LinkstateOam,
};
use wz_session_core::network_message::NetworkMessage;

use wz_routing_graph::{Changes, LinkId, LinkstateNetwork, Zid, WHATAMI_PEER};

use crate::accept_loop::{FaceForwarder, FaceId};
use crate::session_glue::{IterationEvent, SessionLinkActions};

/// A [`FaceForwarder`] that maintains the [`LinkstateNetwork`] topology
/// graph from the face lifecycle + inbound `OAM_LINKSTATE` messages. The
/// linkstate-peer counterpart to the data-plane
/// [`RoutingForwarder`](crate::routing_forward).
pub struct LinkstateForwarder {
    /// Shared single-task topology graph (`Rc<RefCell>`, not `Mutex`).
    net: Rc<RefCell<LinkstateNetwork>>,
    /// Face -> graph link id, so an inbound list is ingested against the
    /// link it arrived on (whose psid<->zid mappings resolve it).
    face_links: RefCell<HashMap<FaceId, LinkId>>,
    /// Face -> its transport send seam, so [`flood_self`](Self::flood_self)
    /// can push the local link-state out on every held face (the `Arc`
    /// clone of the face's `SessionLinkActions`, as `RoutingForwarder` keeps
    /// for the data plane).
    faces: RefCell<HashMap<FaceId, Arc<SessionLinkActions>>>,
    /// Running total of link-state lists ingested — the control-plane work
    /// witness (the linkstate analogue of `RoutingForwarder::forwarded`).
    ingested: Cell<usize>,
}

impl LinkstateForwarder {
    /// A driver seeded with the local node (this peer's zid + whatami).
    pub fn new(self_zid: Zid, self_whatami: u8) -> Self {
        Self {
            net: Rc::new(RefCell::new(LinkstateNetwork::new(self_zid, self_whatami))),
            face_links: RefCell::new(HashMap::new()),
            faces: RefCell::new(HashMap::new()),
            ingested: Cell::new(0),
        }
    }

    /// A peer face came up: connect it in the graph and remember its link id.
    pub fn on_face_up(&self, face: FaceId, peer_zid: Zid, peer_whatami: u8) {
        let link_id = self.net.borrow_mut().add_link(peer_zid, peer_whatami);
        self.face_links.borrow_mut().insert(face, link_id);
    }

    /// A peer face went down: disconnect it from the graph.
    pub fn on_face_down(&self, face: FaceId) {
        if let Some(link_id) = self.face_links.borrow_mut().remove(&face) {
            self.net.borrow_mut().remove_link(link_id);
        }
    }

    /// A decoded topology `LinkStateList` arrived on `face`: ingest it
    /// against that face's link and recompute the spanning trees. Returns
    /// what the ingest changed, so the caller can re-flood it onward
    /// ([`propagate`](Self::propagate)).
    pub fn on_inbound_linkstate(&self, face: FaceId, list: LinkstateListOwned) -> Changes {
        let link_id = match self.face_links.borrow().get(&face).copied() {
            Some(id) => id,
            // a list from a face with no graph link is dropped.
            None => return Changes::default(),
        };
        let mut net = self.net.borrow_mut();
        let changes = net.ingest_linkstate_list(link_id, list);
        net.compute_trees();
        drop(net);
        self.ingested.set(self.ingested.get() + 1);
        changes
    }

    /// Re-flood the nodes an ingest changed to every face EXCEPT the one it
    /// arrived on — zenoh `propagate_link_states` (`network.rs:636-678`,
    /// called at the tail of the receive path `:804`). This is what carries
    /// topology TRANSITIVELY across a >2-node mesh: a node B learns from face
    /// A is advertised onward to face C. The source is excluded (it sent the
    /// state); sn-staleness on each receiver drops a re-flood of unchanged
    /// state, so the propagation converges rather than storming. Returns the
    /// number of faces propagated to. (zenoh's full-state-for-new /
    /// links-only-for-updated `Details` split is the deferred optimisation;
    /// wz sends the changed nodes full-state.)
    pub fn propagate(&self, source: FaceId, changes: &Changes) -> Result<usize, CodecError> {
        if changes.updated.is_empty() {
            return Ok(0);
        }
        let oam = {
            let net = self.net.borrow();
            build_linkstate_oam_owned(&net.build_linkstate_for(&changes.updated))?
        };
        let mut sent = 0;
        for (id, actions) in self.faces.borrow().iter() {
            if *id == source {
                continue;
            }
            let msg = NetworkMessage::Oam(oam.clone());
            if actions.send_network_message(msg, true, false).is_ok() {
                sent += 1;
            }
        }
        Ok(sent)
    }

    /// Total link-state lists ingested so far — the control-plane witness.
    pub fn ingested(&self) -> usize {
        self.ingested.get()
    }

    /// This peer's children in the spanning tree rooted at `source` — the
    /// faces to forward a message flooded along `source`'s tree to. The
    /// data-forwarding atom (c3b) reads this; exposed now as the graph
    /// query the driver owns.
    pub fn tree_children_of(&self, source: &Zid) -> Vec<Zid> {
        self.net.borrow().tree_children_of(source)
    }

    /// Flood THIS peer's own link-state to every held face — the TX seam
    /// (c3d). The graph builds the full-topology `LinkStateList` (c3b
    /// [`LinkstateNetwork::build_linkstate_list`]); `build_linkstate_oam_owned`
    /// (c1) wraps it in the `OAM_LINKSTATE` carrier; each face's
    /// [`SessionLinkActions::send_network_message`] puts it on the wire
    /// (reliably — topology is control traffic). Returns the number of faces
    /// the message reached. Mirrors zenoh `make_msg` + `send_on_links`. The
    /// WHEN — a periodic timer / on a `Changes`-driven re-flood — is the
    /// caller's (the peer loop's) concern.
    pub fn flood_self(&self) -> Result<usize, CodecError> {
        let list = self.net.borrow().build_linkstate_list();
        // `NetworkMessage` is not `Clone`, but `OamOwned` is — build the
        // carrier once and re-wrap a clone per face.
        let oam = build_linkstate_oam_owned(&list)?;
        let mut sent = 0;
        for actions in self.faces.borrow().values() {
            // a per-face send failure (link gone mid-flood) is skipped, not
            // fatal to the rest of the flood — the face's own driver will
            // surface its teardown via deregister.
            let msg = NetworkMessage::Oam(oam.clone());
            if actions.send_network_message(msg, true, false).is_ok() {
                sent += 1;
            }
        }
        Ok(sent)
    }
}

impl FaceForwarder for LinkstateForwarder {
    fn register(&self, id: FaceId, actions: &Arc<SessionLinkActions>) {
        // Keep the face's send seam so flood_self can reach it.
        self.faces.borrow_mut().insert(id, actions.clone());
        // The peer's routing zid is read from the handshake at FaceUp
        // (R311qi). Without it there is no graph identity to key on, so the
        // face is held but not connected (it cannot route topology). The
        // peer-mesh is a mesh of peers; the real handshake whatami is not
        // yet threaded onto the face (a tracked deferral — spanning-tree
        // forwarding is whatami-agnostic; only gossip/autoconnect would
        // need the true role), so a neighbour is recorded as Peer.
        if let Some(peer_zid) = actions.peer_zid() {
            self.on_face_up(id, peer_zid, WHATAMI_PEER);
        }
    }

    fn deregister(&self, id: FaceId) {
        self.faces.borrow_mut().remove(&id);
        self.on_face_down(id);
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
    use crate::test_fixtures::recording_actions;
    use sce_forge_runtime::codec::SceBytes;
    use wz_codecs::linkstate::LinkstateOwned;
    use wz_codecs::linkstate_link::LinkstateLink;

    fn zid(b: u8) -> Zid {
        vec![b, b, b, b]
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
        fwd.on_face_up(FaceId(7), zid(0xAA), 2);
        // self + the neighbour node.
        assert_eq!(fwd.net.borrow().node_count(), 2);
    }

    #[test]
    fn inbound_linkstate_grows_the_graph_and_counts() {
        let fwd = LinkstateForwarder::new(zid(0x01), 2);
        fwd.on_face_up(FaceId(7), zid(0xAA), 2);
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
        fwd.on_face_up(FaceId(7), zid(0xAA), 2);
        assert_eq!(fwd.net.borrow().node_count(), 2);
        fwd.on_face_down(FaceId(7));
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
}
