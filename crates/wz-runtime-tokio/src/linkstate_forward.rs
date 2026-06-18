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

use wz_codecs::linkstate_list::LinkstateListOwned;
use wz_session_core::driver_loop::DriverLoopOutcome;
use wz_session_core::linkstate_oam::{try_parse_linkstate_oam, LinkstateOam};
use wz_session_core::network_message::NetworkMessage;

use wz_routing_graph::{LinkId, LinkstateNetwork, Zid, WHATAMI_PEER};

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
    /// against that face's link and recompute the spanning trees.
    pub fn on_inbound_linkstate(&self, face: FaceId, list: LinkstateListOwned) {
        let link_id = match self.face_links.borrow().get(&face).copied() {
            Some(id) => id,
            // a list from a face with no graph link is dropped.
            None => return,
        };
        let mut net = self.net.borrow_mut();
        net.ingest_linkstate_list(link_id, list);
        net.compute_trees();
        drop(net);
        self.ingested.set(self.ingested.get() + 1);
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
}

impl FaceForwarder for LinkstateForwarder {
    fn register(&self, id: FaceId, actions: &Arc<SessionLinkActions>) {
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
        self.on_face_down(id);
    }

    fn forward(&self, id: FaceId, event: IterationEvent<'_>) {
        let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event else {
            return;
        };
        for message in messages {
            if let NetworkMessage::Oam(oam) = message {
                match try_parse_linkstate_oam(oam) {
                    LinkstateOam::Decoded(list) => self.on_inbound_linkstate(id, list),
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
}
