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
//! Data forwarding (c3c): [`forward_push`](LinkstateForwarder::forward_push)
//! floods a received Push along the source's spanning tree
//! ([`tree_children_of`](wz_routing_graph::LinkstateNetwork::tree_children_of)),
//! and [`publish`](LinkstateForwarder::publish) originates one. What is NOT
//! here yet: subscription-filtered routing (zenoh forwards along
//! `directions[sub]` toward interested subscribers; wz floods every tree child
//! — the deferred c3c-3 step), and the change-triggered-flood / `Details`
//! optimisations. `routing-peer`-gated.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use sce_forge_runtime::codec::CodecError;
use wz_codecs::linkstate_list::LinkstateListOwned;
use wz_codecs::oam::OamOwned;
use wz_codecs::push::PushOwned;
use wz_session_core::driver_loop::DriverLoopOutcome;
use wz_session_core::linkstate_oam::{
    build_linkstate_oam_owned, try_parse_linkstate_oam, LinkstateOam,
};
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::push_build::build_push_literal;
use wz_session_core::push_routing_context::{read_push_source, set_push_source};

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
    /// Running total of data `Push` messages received on a face — the
    /// data-plane reception witness. A far peer's count rising above zero is
    /// the end-to-end proof that mesh data forwarding reached it (the data
    /// counterpart of `ingested`).
    data_seen: Cell<usize>,
}

impl LinkstateForwarder {
    /// A driver seeded with the local node (this peer's zid + whatami).
    pub fn new(self_zid: Zid, self_whatami: u8) -> Self {
        Self {
            net: Rc::new(RefCell::new(LinkstateNetwork::new(self_zid, self_whatami))),
            faces: RefCell::new(HashMap::new()),
            ingested: Cell::new(0),
            data_seen: Cell::new(0),
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
        // A clone of the graph handle so the per-face builder can borrow it
        // (the `Rc` is the cell; `fan_out` only holds the `faces` borrow).
        let net = self.net.clone();
        self.fan_out(true, |id, zid| {
            if id == source {
                return Ok(None);
            }
            // Drop the node whose own state this is from the list sent to ITS
            // face (zenoh `network.rs:663`) — the per-face payload differs, so
            // each face gets its own built carrier.
            let to_send: Vec<Zid> = changes
                .updated
                .iter()
                .filter(|z| zid != Some(z.as_slice()))
                .cloned()
                .collect();
            if to_send.is_empty() {
                return Ok(None);
            }
            let oam = build_linkstate_oam_owned(&net.borrow().build_linkstate_for(&to_send))?;
            Ok(Some(NetworkMessage::Oam(oam)))
        })
    }

    /// Total link-state lists ingested so far — the control-plane witness.
    pub fn ingested(&self) -> usize {
        self.ingested.get()
    }

    /// Total data `Push` messages received on a face so far — the data-plane
    /// reception witness. On a far peer this rising above zero proves mesh
    /// data forwarding reached it end to end.
    pub fn data_seen(&self) -> usize {
        self.data_seen.get()
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

    /// The single fan-out SSOT: send to each held face the message `build`
    /// produces for it, returning the count of faces that accepted one. The
    /// builder `build(face_id, peer_zid)` returns `Ok(Some(msg))` to send to
    /// that face, `Ok(None)` to skip it, or `Err` to abort the whole fan-out
    /// (a per-face build failure). This owns the parts every sender shares —
    /// borrow the `faces` set, iterate, read each peer zid, send, count, skip a
    /// per-face send failure — so `flood_self` / `propagate` / `forward_push` /
    /// `publish` each express ONLY their selection + carrier policy as the
    /// closure, never a re-hand-rolled face loop. Holds only the `faces` borrow;
    /// a builder may borrow the graph (a distinct cell).
    fn fan_out(
        &self,
        reliable: bool,
        mut build: impl FnMut(FaceId, Option<&[u8]>) -> Result<Option<NetworkMessage>, CodecError>,
    ) -> Result<usize, CodecError> {
        let mut sent = 0;
        for (id, state) in self.faces.borrow().iter() {
            let peer_zid = state.actions.peer_zid();
            if let Some(msg) = build(*id, peer_zid.as_deref())? {
                // a per-face send failure (link gone mid-fan-out) is skipped,
                // not fatal to the rest — the face's own driver surfaces its
                // teardown via deregister.
                if state
                    .actions
                    .send_network_message(msg, reliable, false)
                    .is_ok()
                {
                    sent += 1;
                }
            }
        }
        Ok(sent)
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
        self.fan_out(true, |_id, _zid| Ok(Some(NetworkMessage::Oam(oam.clone()))))
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

    /// Flood a data `Push` onward along the SOURCE's spanning tree (c3c-2) —
    /// the loop-free mesh data forward. The Push arrived on `inbound`; its
    /// `ext_nodeid` names the source the message floods FROM (zenoh's
    /// data-route tree root): `node_id == 0` means the inbound neighbour
    /// itself originated it, otherwise the node_id is the source's psid in the
    /// inbound link's space, resolved via that link's `psid -> zid` mapping.
    /// Self's CHILDREN in the source-rooted tree are the next hops, and the
    /// inbound face (self's parent toward the source) is excluded. Each
    /// outbound copy is re-stamped with THIS node's psid for the source (the
    /// same value for every face; each child remaps it via its own link, zenoh
    /// `get_local_context`).
    ///
    /// Loop-freedom — the honest scope: it holds WHEN every node computes the
    /// SAME tree for the source. They do once topology has converged, because
    /// every node runs the same Bellman-Ford over the same graph with the same
    /// deterministic (zid-symmetric) edge jitter — so the per-source tree is
    /// globally consistent and a flood descends it exactly once per node. Under
    /// TRANSIENT disagreement (mid-convergence / a flapping link) two nodes can
    /// briefly disagree on the tree, and there is NO message dedup (no
    /// per-source seen-set) or TTL to break a resulting duplicate/short loop —
    /// the convergence window self-heals it, but a persistently flapping mesh
    /// is unbounded. A `(source, sn)` seen-set is the tracked defence;
    /// subscription-filtered routing (zenoh forwards along `directions[sub]`
    /// toward interested subscribers rather than flooding every tree child) is
    /// the deferred c3c-3 step that also bounds the fan-out.
    fn forward_push(&self, inbound: FaceId, reliable: bool, push: &PushOwned) {
        // The inbound face's zid + graph link — the only state the source
        // resolution needs from the faces set, taken in a SCOPED borrow so the
        // `fan_out` below holds the only live `faces` borrow.
        let (inbound_zid, inbound_link) = {
            let faces = self.faces.borrow();
            match faces.get(&inbound) {
                Some(s) => (s.actions.peer_zid(), s.link),
                None => return,
            }
        };

        // Resolve the source (tree root) and this node's psid for it.
        let net = self.net.borrow();
        let source_zid: Zid = match read_push_source(push) {
            // self-originated by the inbound neighbour: it IS the source.
            0 => match inbound_zid.clone() {
                Some(z) => z,
                None => return,
            },
            // a transit message: node_id is the source's psid in the inbound
            // link's space; resolve it through that link's psid -> zid mapping.
            node_id => {
                let Some(link_id) = inbound_link else {
                    return;
                };
                match net
                    .get_link(link_id)
                    .and_then(|l| l.get_zid(node_id as u64))
                {
                    Some(z) => z.clone(),
                    None => return, // unknown source -> cannot place it in a tree
                }
            }
        };
        // Self can never be a TRANSIT source on a message arriving at us. Its
        // local psid is 0, which `set_push_source` encodes as the self-
        // originated sentinel — re-stamping a transit message to 0 would make
        // every downstream node mis-attribute the source to ITS inbound
        // neighbour. Drop such a (malformed / looped-back) message.
        if source_zid == *net.self_zid() {
            return;
        }
        let Some(out_node_id) = net.local_psid_of(&source_zid) else {
            return;
        };
        // The wire routing-context node_id is a u16 (zenoh `NodeIdType`); a psid
        // beyond that range cannot be represented, so DROP rather than silently
        // alias by truncation (a truncated psid would re-stamp a wrong / 0
        // source). Unreachable until a graph holds >65535 live nodes
        // (`remove_detached_nodes` pruning is a tracked deferral).
        let Ok(out_node_id) = u16::try_from(out_node_id) else {
            return;
        };
        let children = net.tree_children_of(&source_zid);
        drop(net);

        if children.is_empty() {
            return;
        }
        // `out_node_id` is the same for every face, so build the re-stamped
        // carrier once; fan_out clones it to each tree child.
        let mut carrier = push.clone();
        set_push_source(&mut carrier, out_node_id);

        // Forward to self's children in the source's tree — never to the inbound
        // face, nor back toward the source's own neighbour (a parallel link).
        let _ = self.fan_out(reliable, |id, zid| {
            if id == inbound {
                return Ok(None);
            }
            let Some(zid) = zid else {
                return Ok(None);
            };
            if inbound_zid.as_deref() == Some(zid) {
                return Ok(None);
            }
            if !children.iter().any(|c| c.as_slice() == zid) {
                return Ok(None);
            }
            Ok(Some(NetworkMessage::Push(Box::new(carrier.clone()))))
        });
    }

    /// Originate a data Put INTO the mesh from this node (a publishing peer) —
    /// build the carrier and flood it to self's CHILDREN in self's own
    /// spanning tree (this node is the source). `build_push_literal` emits no
    /// `ext_nodeid`, so the carrier is self-originated (node_id 0, zenoh
    /// DEFAULT) as built; each child resolves the source to this node (its
    /// inbound neighbour) and re-forwards via [`forward_push`](Self::forward_push).
    /// The publishing counterpart to `forward_push` (which re-forwards a
    /// RECEIVED Push). Returns the number of tree-child faces the Put reached.
    pub fn publish(&self, keyexpr: &str, payload: &[u8]) -> Result<usize, CodecError> {
        let push = build_push_literal(keyexpr, payload)?;
        let children = {
            let net = self.net.borrow();
            let self_zid = net.self_zid().clone();
            net.tree_children_of(&self_zid)
        };
        if children.is_empty() {
            return Ok(0);
        }
        self.fan_out(true, |_id, zid| {
            let to_child = match zid {
                Some(z) => children.iter().any(|c| c.as_slice() == z),
                None => false,
            };
            Ok(to_child.then(|| NetworkMessage::Push(Box::new(push.clone()))))
        })
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
        // Drop the face's state; if it had a graph link, disconnect it AND
        // recompute the spanning trees. Without the recompute, `forward_push` /
        // `publish` would keep routing along trees that still include the dead
        // link until the next inbound link-state happened to trigger a recompute
        // — a misroute window after every face loss. zenoh recomputes on
        // link-down too (`hat/linkstate_peer/mod.rs` `schedule_compute_trees`).
        if let Some(state) = self.faces.borrow_mut().remove(&id) {
            if let Some(link) = state.link {
                let mut net = self.net.borrow_mut();
                net.remove_link(link);
                net.compute_trees();
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
        let IterationEvent::Poll(DriverLoopOutcome::FramePayload {
            messages, reliable, ..
        }) = event
        else {
            return;
        };
        for message in messages {
            match message {
                NetworkMessage::Oam(oam) => match try_parse_linkstate_oam(oam) {
                    LinkstateOam::Decoded(list) => {
                        // ingest, then re-flood the changed nodes onward to
                        // the OTHER faces (transitive propagation).
                        let changes = self.on_inbound_linkstate(id, list);
                        let _ = self.propagate(id, &changes);
                    }
                    // a malformed OAM_LINKSTATE or a non-linkstate OAM is
                    // left alone (the generic OAM path / a logged drop).
                    LinkstateOam::Malformed(_) | LinkstateOam::NotLinkstate => {}
                },
                // c3c-2 — a data Push: count the reception (the data-plane
                // witness) then flood it onward along the SOURCE's spanning
                // tree (loop-free), excluding the inbound face.
                NetworkMessage::Push(push) => {
                    self.data_seen.set(self.data_seen.get() + 1);
                    self.forward_push(id, *reliable, push);
                }
                _ => {}
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

    /// A self-originated data Push (its routing-context node_id defaults to 0).
    fn data_push() -> PushOwned {
        use wz_session_core::push_build::build_push_literal;
        build_push_literal("demo/data", b"payload").expect("build push")
    }

    /// One LinkState entry (psid-space, with the psids it links to) — mirrors
    /// the wz-routing-graph test idiom for building a topology by ingest.
    fn entry(psid: u64, sn: u64, node: u8, links: &[u64]) -> LinkstateOwned {
        LinkstateOwned {
            options: 0,
            psid,
            sn,
            zid_len: Some(4),
            zid: Some(SceBytes::from_slice(&zid(node)).unwrap()),
            whatami: Some(2),
            num_locators: None,
            locators: None,
            links_len: links.len() as u64,
            links: links.iter().map(|&psid| LinkstateLink { psid }).collect(),
            weights: None,
        }
    }

    fn list(entries: Vec<LinkstateOwned>) -> LinkstateListOwned {
        LinkstateListOwned {
            num_link_states: entries.len() as u64,
            link_states: entries,
        }
    }

    /// Make `neighbour` (on `face`) advertise a single link back to self
    /// (`self_node`), which is what forms the mutual graph edge self<->
    /// neighbour. The self entry (psid 0) is carried only to teach the
    /// psid->zid mapping; its low sn keeps it stale so self's own links are
    /// not clobbered. The neighbour entry (psid 1) links to psid 0 = self.
    fn advertise_link_back(fwd: &LinkstateForwarder, face: FaceId, neighbour: u8, self_node: u8) {
        fwd.on_inbound_linkstate(
            face,
            list(vec![
                entry(0, 1, self_node, &[]),
                entry(1, 5, neighbour, &[0]),
            ]),
        );
    }

    /// Decode the routing-context `node_id` of the single forwarded Push in a
    /// recorded wire frame — proves the re-stamp landed ON THE WIRE (the Push
    /// codec carried the ext_nodeid), not merely that a frame went out.
    fn forwarded_source(frame: &[u8]) -> u16 {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let InboundFrame::Frame { payload, .. } =
            parse_inbound(frame).expect("parse forwarded frame")
        else {
            panic!("forwarded bytes are not a Frame");
        };
        let msgs = parse_frame_payload(&payload).expect("parse frame payload");
        match msgs.first() {
            Some(NetworkMessage::Push(p)) => read_push_source(p),
            other => panic!("expected a forwarded Push, got {other:?}"),
        }
    }

    #[test]
    fn forwards_a_push_along_the_source_tree_to_a_child() {
        // Line A - S(self) - B (A and B each link only to S). A Push
        // self-originated by neighbour A (node_id 0) floods along A's tree:
        // self's only child is B, so it reaches B and never goes back to A.
        let fwd = LinkstateForwarder::new(zid(0x05), 2); // self -> idx 0
        let (face_a, sink_a) = peer_face(zid(0x0A)); // -> idx 1
        let (face_b, sink_b) = peer_face(zid(0x0B)); // -> idx 2
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05); // edge S<->B
        sink_a.reset();
        sink_b.reset();

        fwd.forward_push(FaceId(0), true, &data_push());

        assert_eq!(sink_b.frame_count(), 1, "forwarded to the tree child B");
        assert_eq!(sink_a.frame_count(), 0, "never back toward the source A");
        // Re-stamped with THIS node's psid for the source A (its idx, 1).
        assert_eq!(forwarded_source(&sink_b.frame_bytes(0)), 1);
    }

    #[test]
    fn does_not_forward_a_push_to_a_face_outside_the_source_tree() {
        // self holds A (connected, edge S<->A) and B (held but never advertised
        // back, so it is an isolated node with no edge). A Push from A reaches
        // self only — B is not in A's spanning tree, so it gets nothing.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // only S<->A
        sink_a.reset();
        sink_b.reset();

        fwd.forward_push(FaceId(0), true, &data_push());
        assert_eq!(sink_a.frame_count(), 0, "not back toward the source");
        assert_eq!(
            sink_b.frame_count(),
            0,
            "B is not in A's tree -> no forward"
        );
    }

    #[test]
    fn forwards_a_transit_push_resolving_the_source_from_the_link_psid() {
        // Line S - A - B (B behind A), plus S - C. A Push arrives on A's face
        // carrying a NON-zero node_id = A's psid for B (a transit message, not
        // self-originated). Self resolves it via A's link psid->zid mapping to
        // source B, then floods along B's spanning tree: self's only child
        // there is C (A is B's child, not self's), so only C receives it —
        // re-stamped into SELF's psid space for B. The link mapping is taught by
        // a REAL ingest (A advertising its links), not a graph-internal poke.
        let fwd = LinkstateForwarder::new(zid(0x05), 2); // S -> idx 0
        let (face_a, sink_a) = peer_face(zid(0x0A)); // -> idx 1
        let (face_c, sink_c) = peer_face(zid(0x0C)); // -> idx 2
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        // A advertises links to self (psid 0) AND to B (psid 7); B links back to
        // A — forming edges S-A and A-B and teaching A's link that psid 7 = B
        // (the transit source). B is added as a node (idx 3).
        fwd.on_inbound_linkstate(
            FaceId(0),
            list(vec![
                entry(0, 1, 0x05, &[]),
                entry(1, 5, 0x0A, &[0, 7]),
                entry(7, 5, 0x0B, &[1]),
            ]),
        );
        advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05); // edge S-C
        sink_a.reset();
        sink_c.reset();

        let mut push = data_push();
        set_push_source(&mut push, 7); // node_id 7 = A's psid for B
        fwd.forward_push(FaceId(0), true, &push);

        assert_eq!(sink_c.frame_count(), 1, "C is self's child in B's tree");
        assert_eq!(sink_a.frame_count(), 0, "A is the inbound face (excluded)");
        // Re-stamped with self's psid for the RESOLVED source B (its idx, 3).
        assert_eq!(forwarded_source(&sink_c.frame_bytes(0)), 3);
    }

    #[test]
    fn publish_floods_self_originated_data_to_tree_children() {
        // self(S) publishes its OWN data: it is the source, so the Put floods
        // to self's children in self's tree (here the single neighbour A),
        // stamped self-originated (node_id 0).
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A
        sink_a.reset();

        let sent = fwd.publish("demo/data", b"v").expect("publish");
        assert_eq!(sent, 1, "flooded to the one tree child");
        assert_eq!(sink_a.frame_count(), 1, "A received the published Put");
        // self-originated -> node_id 0 on the wire (zenoh DEFAULT).
        assert_eq!(forwarded_source(&sink_a.frame_bytes(0)), 0);
    }

    #[test]
    fn forward_counts_received_data_pushes() {
        // The forward() seam counts every received data Push — the data-plane
        // reception witness a far peer logs to prove end-to-end delivery.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, _sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        assert_eq!(fwd.data_seen(), 0);

        let outcome = DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(data_push()))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&outcome));
        assert_eq!(fwd.data_seen(), 1, "one received data Push counted");
    }

    #[test]
    fn drops_a_transit_push_whose_source_resolves_to_self() {
        // R311rj — a neighbour stamps a node_id that maps (in OUR inbound link's
        // space) to OUR OWN zid: a malformed / looped-back message. Self can
        // never be a transit source on a message arriving at us, and re-stamping
        // it would hit local psid 0 = the self-originated sentinel (misroute).
        // forward_push must DROP it, not flood it to self's tree children.
        let fwd = LinkstateForwarder::new(zid(0x05), 2); // self
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        // A's link-state advertises SELF (0x05) under a non-zero psid 7 and
        // links A to it (forming edge S<->A); B links back normally (edge S<->B).
        fwd.on_inbound_linkstate(
            FaceId(0),
            list(vec![entry(7, 1, 0x05, &[]), entry(1, 5, 0x0A, &[7])]),
        );
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        sink_a.reset();
        sink_b.reset();

        let mut push = data_push();
        set_push_source(&mut push, 7); // resolves via A's link to self's zid
        fwd.forward_push(FaceId(0), true, &push);
        assert_eq!(sink_a.frame_count(), 0, "not echoed to the inbound face");
        assert_eq!(
            sink_b.frame_count(),
            0,
            "self-as-source is dropped, not flooded to self's tree children"
        );
    }

    #[test]
    fn drops_a_transit_push_with_an_unresolvable_source() {
        // A transit node_id with no entry in the inbound link's psid->zid map
        // cannot be placed in any tree — forward_push drops it (no misroute on
        // an attacker-supplied / pre-convergence bogus source).
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        sink_a.reset();
        sink_b.reset();

        let mut push = data_push();
        set_push_source(&mut push, 123); // not in A's link mapping
        fwd.forward_push(FaceId(0), true, &push);
        assert_eq!(sink_a.frame_count(), 0);
        assert_eq!(
            sink_b.frame_count(),
            0,
            "unresolvable source -> dropped, not forwarded"
        );
    }

    #[test]
    fn deregister_recomputes_trees_dropping_the_dead_link() {
        // R311rj — after a face drops, the spanning trees must drop paths
        // through the dead link so a SURVIVING face is no longer routed toward
        // the lost subtree (zenoh recomputes on link-down). Topology S-A, S-B,
        // A-C: in B's tree, self's child is A (the next hop toward A and C).
        // Dropping A's face must leave B's tree with NO child of self (A and C
        // become unreachable) — which only holds if deregister recomputed; a
        // stale tree would still name A.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, _sa) = peer_face(zid(0x0A));
        let (face_b, _sb) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        // A links to self (psid 0) and to C (psid 2); C links back to A — edges
        // S-A and A-C. B links back to self — edge S-B.
        fwd.on_inbound_linkstate(
            FaceId(0),
            list(vec![
                entry(0, 1, 0x05, &[]),
                entry(1, 5, 0x0A, &[0, 2]),
                entry(2, 5, 0x0C, &[1]),
            ]),
        );
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        assert_eq!(
            fwd.tree_children_of(&zid(0x0B)),
            vec![zid(0x0A)],
            "in B's tree self forwards toward A/C via child A"
        );

        fwd.deregister(FaceId(0));
        assert!(
            fwd.tree_children_of(&zid(0x0B)).is_empty(),
            "deregister recomputed: A/C left B's tree (a stale tree would keep A)"
        );
    }

    #[test]
    fn forwards_along_the_tree_not_the_cycle_edge_in_a_mesh() {
        // R311rl — loop-freedom on a CYCLIC mesh (the e2e only exercises a
        // line). Converged topology: triangle S-A-B (self S is linked to A and
        // B, and A-B are linked to each other) plus S-C. A Push from A floods
        // along A's spanning tree, in which B is A's DIRECT child (via the A-B
        // edge) while C is self's. So self forwards ONLY to its tree child C —
        // NOT across the S-B cycle edge — and the message cannot loop
        // S->B->A->S. The cycle edge is excluded because the (converged,
        // deterministic-jitter) tree is consistent and acyclic.
        let fwd = LinkstateForwarder::new(zid(0x05), 2); // S -> idx 0
        let (face_a, sink_a) = peer_face(zid(0x0A)); // -> idx 1
        let (face_b, sink_b) = peer_face(zid(0x0B)); // -> idx 2
        let (face_c, sink_c) = peer_face(zid(0x0C)); // -> idx 3
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        fwd.register(FaceId(2), &face_c);
        // A advertises links to S + B (authoritative); A-B closes the triangle.
        fwd.on_inbound_linkstate(
            FaceId(0),
            list(vec![
                entry(0, 1, 0x05, &[]),
                entry(1, 5, 0x0A, &[0, 2]),
                entry(2, 5, 0x0B, &[1]),
            ]),
        );
        // B advertises links to S + A (authoritative, higher sn so it is not
        // stale-gated); S and A are stale references for the psid mapping only.
        fwd.on_inbound_linkstate(
            FaceId(1),
            list(vec![
                entry(0, 1, 0x05, &[]),
                entry(2, 1, 0x0A, &[]),
                entry(1, 10, 0x0B, &[0, 2]),
            ]),
        );
        advertise_link_back(&fwd, FaceId(2), 0x0C, 0x05); // edge S-C
                                                          // C is self's child in A's tree; B is A's child (reached via A-B), so
                                                          // self does not forward toward B.
        assert_eq!(fwd.tree_children_of(&zid(0x0A)), vec![zid(0x0C)]);
        sink_a.reset();
        sink_b.reset();
        sink_c.reset();

        fwd.forward_push(FaceId(0), true, &data_push()); // Push from A (source A)
        assert_eq!(sink_c.frame_count(), 1, "forwarded to the tree child C");
        assert_eq!(sink_a.frame_count(), 0, "not back to the source A");
        assert_eq!(
            sink_b.frame_count(),
            0,
            "the S-B cycle edge is excluded by A's tree (B is A's child) — no loop"
        );
    }
}
