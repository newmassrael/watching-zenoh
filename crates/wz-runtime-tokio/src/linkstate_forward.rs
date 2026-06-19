// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Linkstate-peer routing driver (P4 routing, step c3a) — the
//! [`FaceForwarder`] SEAM that connects the [`LinkstateNetwork`] topology
//! graph to the [`accept_loop`](crate::accept_loop) /
//! [`peer_loop`](crate::accept_loop::peer_loop) face lifecycle.
//!
//! [`LinkstateForwarder`] is a [`FaceForwarder`]: as peer faces come and go it
//! connects/disconnects them in the graph
//! ([`register`](FaceForwarder::register) / [`deregister`](FaceForwarder::deregister)),
//! and on each inbound iteration event it extracts an `OAM_LINKSTATE` message,
//! feeds the decoded `LinkStateList` to the graph ingest, recomputes the spanning
//! trees, and re-floods the changed nodes onward ([`forward`](FaceForwarder::forward)).
//!
//! Topology flooding is EVENT-DRIVEN (D2b), like zenoh — which floods only on a
//! link change, with NO periodic keepalive. A self-link change (`register` gained
//! a link / `deregister` lost one, sn bumped) floods self's full link-state to
//! every held face at once: the new neighbour is bootstrapped with the full
//! topology AND the existing faces learn the change immediately. An inbound
//! change re-floods transitively via `forward`'s `propagate`. Reliable transport
//! (the mesh is TCP) delivers each flood, so the topology FLOOD needs no periodic
//! re-send — but the spanning-tree RECOMPUTE each change triggers IS coalesced on
//! a debounce timer (D2c, below), not run inline.
//!
//! Single-task model: like [`RoutingForwarder`](crate::routing_forward),
//! the whole loop is one `!Send` task, so the graph is held behind a plain
//! `Rc<RefCell<…>>` — no `Mutex`, no `Send` bound. Each handler borrows
//! the cell only for its own synchronous duration, never across an
//! `.await`.
//!
//! Data forwarding (c3c): [`forward_push`](LinkstateForwarder::forward_push)
//! re-forwards a received Push, and [`publish`](LinkstateForwarder::publish)
//! originates one — both subscription-FILTERED (c3c-3 atom4): the next hops are
//! [`directions_toward`](wz_routing_graph::LinkstateNetwork::directions_toward)
//! the INTERESTED subscribers, not every tree child, so a keyexpr no peer
//! subscribes to forwards nowhere. Subscription INTEREST propagates across the
//! mesh (c3c-3 atom3):
//! [`declare_subscription`](LinkstateForwarder::declare_subscription) floods a
//! sourced `DeclareSubscriber`, and
//! [`forward_subscription`](LinkstateForwarder::forward_subscription) registers
//! the source peer's interest + re-floods it, so each peer learns who is
//! interested in what ([`interested`](LinkstateForwarder::interested)), and a
//! tree-change re-advertises a subscription to its source tree's NEW children
//! (`pubsub_tree_change`, c3c-3 A2 + D2 children-delta). Each topology change
//! COALESCES its spanning-tree recompute on a debounce timer rather than
//! recomputing inline (c3c-3 D2c): the change handlers
//! ([`forward`](FaceForwarder::forward) / [`deregister`](FaceForwarder::deregister))
//! [`schedule_recompute`](LinkstateForwarder::schedule_recompute) and the
//! [`tick`](FaceForwarder::tick) flushes ONE
//! [`compute_trees`](wz_routing_graph::LinkstateNetwork::compute_trees) +
//! re-advertise per window, so a burst (a join flood, a flapping cascade)
//! collapses to a single recompute — zenoh's `TreesComputationWorker`
//! (`hat/linkstate_peer/mod.rs:122-157`), translated to wz's single-task actor:
//! a coalescing tick on the loop, not a separate task (zenoh needs a task only
//! because its tables are `Arc<RwLock>`-shared across many connection tasks; wz
//! is one `!Send` task). The window is the
//! [`with_trees_delay`](LinkstateForwarder::with_trees_delay) knob (default
//! 100ms = zenoh's `TREES_COMPUTATION_DELAY_MS`); it tunes the SPF-throttle
//! delay, NOT an on/off switch — the coalescing path is the single recompute
//! SSOT. Still deferred: the `Details` topology optimisation (a per-link delta
//! instead of the full-topology flood, D4), and alias / wildcard keyexprs (the
//! filter is literal-keyexpr exact-match, B1 / B2). `routing-peer`-gated.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use sce_forge_runtime::codec::CodecError;
use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant};
use wz_codecs::linkstate_list::LinkstateListOwned;
use wz_codecs::oam::OamOwned;
use wz_codecs::push::PushOwned;
use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};
use wz_session_core::declare_build::{
    build_declare_subscriber, build_undeclare_subscriber_with_keyexpr,
};
use wz_session_core::declare_ext_keyexpr::read_ext_keyexpr;
use wz_session_core::declare_routing_context::{read_declare_source, set_declare_source};
use wz_session_core::driver_loop::DriverLoopOutcome;
use wz_session_core::linkstate_oam::{
    build_linkstate_oam_owned, try_parse_linkstate_oam, LinkstateOam,
};
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::push_build::build_push_literal;
use wz_session_core::push_routing_context::{
    read_push_hoplimit, read_push_source, set_push_hoplimit, set_push_source,
};

use wz_routing_graph::{Changes, LinkId, LinkstateNetwork, Zid};

use crate::accept_loop::{FaceForwarder, FaceId};
use crate::linkstate_subs::LinkstatepeerSubs;
use crate::session_glue::{IterationEvent, SessionLinkActions};

/// Re-export so the peer-loop caller (the demo) names the neighbour role by
/// the same const the graph + forwarder use, not a bare `0x02` literal.
pub use wz_routing_graph::WHATAMI_PEER;

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
    /// The linkstate-peer subscription interest table (c3c-3 atom2): which
    /// peers are interested in which keyexpr, learned from sourced
    /// `DeclareSubscriber`s flooded across the mesh. The HAT-analogue interest
    /// state the data-route filter (atom4) reads to bound the Push fan-out to
    /// interested subtrees, INCLUDING this node's own subscription (registered
    /// under its own zid, zenoh-faithful — see [`LinkstatepeerSubs`]). The
    /// data-route filter reads the self-excluding
    /// [`interested_remote`](crate::linkstate_subs::LinkstatepeerSubs::interested_remote)
    /// view. `RefCell` by the same single-task contract as the graph — borrowed
    /// only for a handler's synchronous duration.
    subs: RefCell<LinkstatepeerSubs>,
    /// D2c — a spanning-tree recompute is pending (the coalescing flag). The
    /// topology-change handlers ([`forward`](FaceForwarder::forward)'s inbound
    /// link-state, [`deregister`](FaceForwarder::deregister)'s face loss) SET this
    /// instead of recomputing inline; the [`tick`](FaceForwarder::tick) flushes it
    /// ONCE per window, so a burst of changes collapses to a single
    /// `compute_trees` — zenoh's `TreesComputationWorker` debounce
    /// (`hat/linkstate_peer/mod.rs:122-157`). Setting an already-set flag is the
    /// coalesce (N changes -> 1 recompute). `Cell` by the single-task contract.
    trees_dirty: Cell<bool>,
    /// The coalescing window: how long topology changes accumulate before the
    /// tick flushes one recompute — the SPF-throttle delay (zenoh's
    /// `TREES_COMPUTATION_DELAY_MS`, default 100ms). The
    /// [`with_trees_delay`](Self::with_trees_delay) knob; zenoh fixes it at
    /// compile time, wz exposes it (an operator tunes the throttle, a test drives
    /// a short window) — it tunes the delay, it is NOT an on/off switch, since the
    /// coalescing path is the single, always-on recompute SSOT.
    trees_delay: Duration,
    /// Total spanning-tree recomputes flushed so far — the D2c coalescing witness
    /// (the count rises once per flushed window, not once per change, so a burst
    /// of N scheduled changes followed by one tick raises it by exactly 1).
    recomputes: Cell<usize>,
}

impl LinkstateForwarder {
    /// The default coalescing window — zenoh's `TREES_COMPUTATION_DELAY_MS`
    /// (`hat/mod.rs:56`). The SPF-throttle delay a [`new`](Self::new) forwarder
    /// uses unless [`with_trees_delay`](Self::with_trees_delay) overrides it.
    pub const DEFAULT_TREES_DELAY: Duration = Duration::from_millis(100);

    /// A driver seeded with the local node (this peer's zid + whatami), using the
    /// default [`DEFAULT_TREES_DELAY`](Self::DEFAULT_TREES_DELAY) recompute window.
    pub fn new(self_zid: Zid, self_whatami: u8) -> Self {
        Self::with_trees_delay(self_zid, self_whatami, Self::DEFAULT_TREES_DELAY)
    }

    /// As [`new`](Self::new), but with an explicit spanning-tree recompute
    /// coalescing window (the SPF-throttle delay D2c debounces topology changes
    /// by). A shorter window converges faster at the cost of more frequent
    /// recomputes under churn; a longer one coalesces a heavier burst. This tunes
    /// the single coalescing path — it does not turn coalescing off.
    pub fn with_trees_delay(self_zid: Zid, self_whatami: u8, trees_delay: Duration) -> Self {
        Self {
            net: Rc::new(RefCell::new(LinkstateNetwork::new(self_zid, self_whatami))),
            faces: RefCell::new(HashMap::new()),
            ingested: Cell::new(0),
            data_seen: Cell::new(0),
            subs: RefCell::new(LinkstatepeerSubs::new()),
            trees_dirty: Cell::new(false),
            trees_delay,
            recomputes: Cell::new(0),
        }
    }

    /// A decoded topology `LinkStateList` arrived on `face`: ingest it against
    /// that face's graph link. Returns the ingest `Changes` the caller re-floods
    /// onward ([`propagate`](Self::propagate)). Does NOT recompute the spanning
    /// trees — the recompute is COALESCED (D2c): the caller
    /// [`schedule_recompute`](Self::schedule_recompute)s and the
    /// [`tick`](FaceForwarder::tick) runs one
    /// [`compute_trees`](wz_routing_graph::LinkstateNetwork::compute_trees) per
    /// window, so a burst of inbound lists collapses to a single recompute. (The
    /// flood `Changes` fall out of the ingest itself and stay inline, exactly as
    /// zenoh floods link-states inline and only debounces the tree compute.)
    pub fn ingest_inbound_linkstate(&self, face: FaceId, list: LinkstateListOwned) -> Changes {
        let link_id = match self.faces.borrow().get(&face).and_then(|s| s.link) {
            Some(id) => id,
            // a list from a face with no graph link (unknown / no zid) is dropped.
            None => return Changes::default(),
        };
        let mut net = self.net.borrow_mut();
        let changes = net.ingest_linkstate_list(link_id, list);
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

    /// Total spanning-tree recomputes flushed so far (D2c) — the coalescing
    /// witness. A burst of scheduled topology changes followed by one
    /// [`tick`](FaceForwarder::tick) raises this by exactly 1, which is what a
    /// coalescing test asserts (N changes did not produce N recomputes).
    pub fn recomputes(&self) -> usize {
        self.recomputes.get()
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
    /// re-wrapped per face). The graph builds the full-topology `LinkStateList` (c3b
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

    /// Flood THIS peer's own (full) link-state to every held face — the TX seam
    /// (c3d). Each face's [`SessionLinkActions::send_network_message`] puts it
    /// on the wire (reliably — topology is control traffic). Returns the number
    /// of faces the message reached. Mirrors zenoh `make_msg` + `send_on_links`.
    /// The WHEN is EVENT-DRIVEN (D2b): [`register`](FaceForwarder::register) /
    /// [`deregister`](FaceForwarder::deregister) call it the instant self's own
    /// link-state changes (a link gained / lost, sn bumped), so the new face is
    /// bootstrapped with the full topology and the existing faces learn the change
    /// at once — no periodic tick (zenoh floods only on link change). The full
    /// topology rather than a per-link delta is the wz simplification (the Details
    /// split is D4); sn-staleness on each receiver drops the unchanged nodes.
    pub fn flood_self(&self) -> Result<usize, CodecError> {
        // `NetworkMessage` is not `Clone`, but `OamOwned` is — build the
        // carrier once and re-wrap a clone per face.
        let oam = self.build_self_oam()?;
        self.fan_out(true, |_id, _zid| Ok(Some(NetworkMessage::Oam(oam.clone()))))
    }

    /// Resolve a routing-context source `node_id` (carried by a Push or a
    /// sourced Declare arriving on `inbound`) to the SOURCE zid + THIS node's
    /// psid for it — the value to re-stamp outbound copies with. `node_id == 0`
    /// means the inbound neighbour itself originated it; a non-zero id is the
    /// source's psid in the inbound link's space, resolved via that link's
    /// `psid -> zid` mapping (zenoh `get_peer`). Returns `None` to DROP:
    /// - unknown source (no inbound zid / no link / unmapped psid → cannot
    ///   place it in any tree),
    /// - the source resolves to SELF: a malformed / looped-back message. Self's
    ///   local psid is 0, which `set_*_source` encodes as the self-originated
    ///   sentinel, so re-stamping it would make every downstream node
    ///   mis-attribute the source to ITS inbound neighbour,
    /// - the local psid exceeds the u16 routing-context range (zenoh
    ///   `NodeIdType`): DROP rather than silently alias by truncation.
    ///   Unreachable until a graph holds >65535 live nodes
    ///   (`remove_detached_nodes` pruning is a tracked deferral).
    ///
    /// The single SSOT shared by [`forward_push`](Self::forward_push) (data)
    /// and [`forward_subscription`](Self::forward_subscription) (a sourced
    /// subscription declaration): both flood along the SOURCE's tree, so both
    /// resolve the source — and the self-source / range guards — identically.
    fn resolve_source(
        &self,
        inbound_zid: Option<&Zid>,
        inbound_link: Option<LinkId>,
        node_id: u16,
    ) -> Option<(Zid, u16)> {
        let net = self.net.borrow();
        let source_zid: Zid = match node_id {
            0 => inbound_zid?.clone(),
            nid => net
                .get_link(inbound_link?)
                .and_then(|l| l.get_zid(nid as u64))?
                .clone(),
        };
        if source_zid == *net.self_zid() {
            return None;
        }
        let out_node_id = u16::try_from(net.local_psid_of(&source_zid)?).ok()?;
        Some((source_zid, out_node_id))
    }

    /// Flood a data `Push` onward along the SOURCE's spanning tree (c3c-2) —
    /// the loop-free mesh data forward. The Push arrived on `inbound`; its
    /// `ext_nodeid` names the source the message floods FROM (zenoh's
    /// data-route tree root), resolved by [`resolve_source`](Self::resolve_source):
    /// `node_id == 0` means the inbound neighbour itself originated it,
    /// otherwise the node_id is the source's psid in the inbound link's space.
    /// The next hops are self's children in the source-rooted tree that lead
    /// toward an INTERESTED subscriber — the data-route filter (c3c-3 atom4):
    /// [`directions_toward`](wz_routing_graph::LinkstateNetwork::directions_toward)
    /// over the keyexpr's interested-peer set
    /// ([`LinkstatepeerSubs`](crate::linkstate_subs::LinkstatepeerSubs)), NOT
    /// every tree child (the pre-atom4 broadcast). A keyexpr no peer subscribes
    /// to forwards nowhere (the any-interest gate). The inbound face (self's
    /// parent toward the source) is excluded, and each outbound copy is
    /// re-stamped with THIS node's psid for the source (the same value for every
    /// face; each child remaps it via its own link, zenoh `get_local_context`).
    ///
    /// Loop-freedom — two complementary layers:
    /// 1. STRUCTURAL (by construction, when converged): when every node computes
    ///    the SAME tree for the source — true once topology has converged, because
    ///    every node runs the same Bellman-Ford over the same graph with the same
    ///    deterministic (zid-symmetric) edge jitter — the per-source tree is
    ///    globally consistent and a flood descends it exactly once per node.
    /// 2. TRANSIENT BOUND (by construction, always): under mid-convergence / a
    ///    flapping link two nodes can briefly disagree on the tree, lapsing the
    ///    structural guarantee. The HOP-LIMIT (c3c-3 D1) bounds any resulting loop:
    ///    [`publish`](Self::publish) stamps a budget = `node_count`, each transit
    ///    hop decrements it, and a Push arriving with the budget exhausted is NOT
    ///    re-forwarded. A Push outliving `node_count` hops is provably looping (an
    ///    acyclic path visits <= `node_count` nodes), so the loop is cut after a
    ///    bounded hop count rather than circulating until convergence.
    ///
    /// The second layer is a DELIBERATE step beyond zenoh, whose data plane is
    /// structural-ONLY: zenoh `route_data` carries no seen-set / sequence / TTL,
    /// and transient loops self-heal on its ~100 ms tree recompute. The wz mesh is
    /// wz-only (zenoh-pico is client-only and never routes), so the hop-limit ext
    /// (id `0x0a`, non-mandatory) rides only mesh-internal wz<->wz forwards and is
    /// invisible to a client. The CONTROL plane (a sourced subscription flood)
    /// needs no hop-limit — it is bounded by the [`LinkstatepeerSubs`] register
    /// change-gate (re-flood only on a NEW interest), the state-convergent bound.
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

        // Resolve the source (tree root) + this node's psid for it via the
        // shared seam (forward_subscription resolves a sourced Declare the same
        // way; both flood along the source's tree).
        let Some((source_zid, out_node_id)) =
            self.resolve_source(inbound_zid.as_ref(), inbound_link, read_push_source(push))
        else {
            return;
        };
        // The data-route filter (c3c-3 atom4): forward only toward subtrees
        // that hold an interested subscriber — `directions_toward` over the
        // keyexpr's interested-peer set — not every tree child (the pre-atom4
        // broadcast). A keyexpr no peer subscribes to forwards nowhere.
        let Some(keyexpr) = push_keyexpr(push) else {
            return;
        };
        // The data-route filter excludes self (interested_remote): self is the
        // local sink (delivered by the session layer), not a mesh forward target.
        let self_zid = self.net.borrow().self_zid().clone();
        let interested = self.subs.borrow().interested_remote(keyexpr, &self_zid);
        if interested.is_empty() {
            return;
        }
        let children = self
            .net
            .borrow()
            .directions_toward(&source_zid, &interested);
        if children.is_empty() {
            return;
        }
        // Hop-limit (c3c-3 D1): a Push that has exhausted its forward budget is
        // NOT re-forwarded — the by-construction transient-convergence loop bound.
        // Absent = an un-stamped Push entering the mesh from a non-stamping origin;
        // treat it as a fresh budget (this node's node_count) so it is bounded from
        // this hop on. `hop <= 1` means the last unit of budget arrived here: this
        // node still received + locally delivered the data (counted in `forward`),
        // it just stops the onward flood — so a loop is cut after a bounded count.
        // NOTE the budget is each node's LOCAL `node_count`, not a global value:
        // the originator stamps ITS count and each transit only decrements, so a
        // stamped Push keeps its budget; an unstamped one is bounded by whatever
        // the FIRST stamping hop knows. Mid-convergence these counts can differ,
        // but any positive bound still cuts the loop — an under-count only cuts
        // earlier (safe: at worst a transient missed delivery, self-healed by the
        // 250ms re-publish), never under-bounds.
        let budget = self.net.borrow().node_count() as u16;
        let hop = read_push_hoplimit(push).unwrap_or(budget);
        if hop <= 1 {
            return;
        }
        // `out_node_id` is the same for every face, so build the re-stamped
        // carrier once; fan_out clones it to each interested child. The hop budget
        // is decremented on the outbound copy (the next hop sees `hop - 1`).
        let mut carrier = push.clone();
        set_push_source(&mut carrier, out_node_id);
        set_push_hoplimit(&mut carrier, hop - 1);

        // Forward to the interested children in the source's tree — never to the
        // inbound face, nor back toward the source's own neighbour (the shared
        // re-forward predicate).
        let _ = self.fan_out(reliable, |id, zid| {
            Ok(
                is_tree_forward_target(id, zid, inbound, inbound_zid.as_deref(), &children)
                    .then(|| NetworkMessage::Push(Box::new(carrier.clone()))),
            )
        });
    }

    /// Originate a data Put INTO the mesh from this node (a publishing peer) —
    /// build the carrier and flood it toward the INTERESTED subscribers in
    /// self's own spanning tree (this node is the source). The data-route
    /// filter (c3c-3 atom4): the next hops are
    /// [`directions_toward`](wz_routing_graph::LinkstateNetwork::directions_toward)
    /// the keyexpr's interested-peer set, not every tree child — a keyexpr no
    /// peer subscribes to publishes nowhere (returns `Ok(0)`).
    /// `build_push_literal` emits no `ext_nodeid`, so the carrier is
    /// self-originated (node_id 0, zenoh DEFAULT) as built; each child resolves
    /// the source to this node (its inbound neighbour) and re-forwards via
    /// [`forward_push`](Self::forward_push). The publishing counterpart to
    /// `forward_push` (which re-forwards a RECEIVED Push). Returns the number of
    /// interested-child faces the Put reached.
    pub fn publish(&self, keyexpr: &str, payload: &[u8]) -> Result<usize, CodecError> {
        let self_zid = self.net.borrow().self_zid().clone();
        // interested_remote excludes self: a key only self subscribes to has no
        // remote forward target (self is the local sink), so publish sends nowhere.
        let interested = self.subs.borrow().interested_remote(keyexpr, &self_zid);
        if interested.is_empty() {
            return Ok(0); // no remote subscriber for this keyexpr -> nothing to send
        }
        let mut push = build_push_literal(keyexpr, payload)?;
        // Stamp the hop-limit budget = node_count (c3c-3 D1, the transient-loop
        // bound): a Push descends an acyclic tree path of at most node_count-1
        // edges, so the budget is generous enough never to false-drop a legitimate
        // forward yet finite, so any copy that outlives node_count hops is provably
        // looping (pigeonhole) and is dropped at the exhausting hop's `forward_push`.
        set_push_hoplimit(&mut push, self.net.borrow().node_count() as u16);
        let children = self.net.borrow().directions_toward(&self_zid, &interested);
        if children.is_empty() {
            return Ok(0);
        }
        self.fan_out(true, |_id, zid| {
            Ok(zid
                .is_some_and(|z| is_child(&children, z))
                .then(|| NetworkMessage::Push(Box::new(push.clone()))))
        })
    }

    /// Originate a LOCAL subscription INTO the mesh: this node is interested in
    /// `keyexpr`, so flood a sourced `DeclareSubscriber` to self's CHILDREN in
    /// self's own spanning tree (this node is the source), stamped
    /// self-originated (node_id 0 — `build_declare_subscriber` emits no
    /// `ext_nodeid`). Each child registers self's interest and re-forwards via
    /// [`forward_subscription`](Self::forward_subscription). The control-plane
    /// (interest) counterpart to [`publish`](Self::publish) (data). Mirrors
    /// zenoh `declare_linkstatepeer_subscription` -> `propagate_sourced_subscription`
    /// with source = self. Returns the number of tree-child faces reached.
    ///
    /// Registers this node's OWN interest into the SINGLE [`subs`](Self#structfield.subs)
    /// set under its own zid — exactly as zenoh's `declare_simple_subscription`
    /// calls `register_linkstatepeer_subscription(.., tables.zid, ..)`. That is
    /// what lets the tree-change re-advertise re-flood it to peers that join LATER
    /// (the late-joiner convergence that makes this a ONE-TIME call, c3c-3 debt
    /// A2), iterated uniformly with remote subscriptions — no separate
    /// self-origination structure.
    pub fn declare_subscription(&self, keyexpr: &str) -> Result<usize, CodecError> {
        let self_zid = self.net.borrow().self_zid().clone();
        self.subs.borrow_mut().register(keyexpr, self_zid.clone());
        // node_id 0 = self-originated (build_declare_subscriber emits no ext_nodeid);
        // literal keyexpr (mapping id 0 + suffix, the wz MVP form).
        let declare = build_declare_subscriber(0, 0, Some(keyexpr))?;
        self.flood_to_tree_children(&self_zid, || {
            NetworkMessage::Declare(Box::new(declare.clone()))
        })
    }

    /// Originate a LOCAL subscription RETRACTION into the mesh: this node is no
    /// longer interested in `keyexpr`, so flood a sourced `UndeclareSubscriber`
    /// (the keyexpr carried in its `ext_keyexpr` extension, node_id 0 —
    /// self-originated) to self's CHILDREN in self's own spanning tree. Each
    /// child withdraws self's interest and re-forwards via
    /// [`forward_unsubscription`](Self::forward_unsubscription). The retraction
    /// counterpart to [`declare_subscription`](Self::declare_subscription), and
    /// the control-plane mirror of zenoh's
    /// `undeclare_linkstatepeer_subscription` -> `propagate_forget_sourced_subscription`
    /// with source = self. Returns the number of tree-child faces reached.
    /// Withdraws self from the [`subs`](Self#structfield.subs) set so the retracted
    /// keyexpr is no longer re-advertised on a tree change (a retraction, unlike a
    /// declaration, needs no late-joiner re-advertise — a peer that joins after
    /// never held the interest).
    pub fn undeclare_subscription(&self, keyexpr: &str) -> Result<usize, CodecError> {
        let self_zid = self.net.borrow().self_zid().clone();
        self.subs.borrow_mut().withdraw(keyexpr, &self_zid);
        let declare = build_undeclare_subscriber_with_keyexpr(keyexpr)?;
        self.flood_to_tree_children(&self_zid, || {
            NetworkMessage::Declare(Box::new(declare.clone()))
        })
    }

    /// Flood `msg` to self's CHILDREN in `root`'s spanning tree — the shared
    /// originate/proactively-re-advertise primitive (c3c-3 rem-1). Replaces the
    /// per-site `tree_children_of(root) -> fan_out(is_child)` block that
    /// [`declare_subscription`](Self::declare_subscription) and
    /// [`undeclare_subscription`](Self::undeclare_subscription) each expressed;
    /// only the carrier (`msg`) and the `root` differ. The full-subtree spread
    /// (every current child of `root`) — for a FRESH local declaration that no
    /// child has yet. (The tree-change re-advertise uses the NEW-children DELTA
    /// instead; see [`flood_to_children`](Self::flood_to_children).)
    fn flood_to_tree_children(
        &self,
        root: &Zid,
        build: impl Fn() -> NetworkMessage,
    ) -> Result<usize, CodecError> {
        let children = self.net.borrow().tree_children_of(root);
        self.flood_to_children(&children, build)
    }

    /// Flood `msg` to a GIVEN set of children — the lowest-level proactive
    /// origination SSOT (c3c-3 D2). No inbound exclusion: these are proactive
    /// originations toward children downstream of a source (zenoh
    /// `send_sourced_subscription_to_net_children(.., None, ..)`), never
    /// re-forwards of a received message (those use [`is_tree_forward_target`]).
    /// [`flood_to_tree_children`](Self::flood_to_tree_children) passes a source
    /// root's FULL child set (a fresh declaration); the tree-change re-advertise
    /// ([`re_advertise_subscriptions`](Self::re_advertise_subscriptions)) passes
    /// only the NEW-children delta (so an already-converged child is not
    /// re-sent). `build` mints a fresh carrier per child (`NetworkMessage` is not
    /// `Clone`; the caller clones the inner owned body). Returns the count
    /// reached.
    fn flood_to_children(
        &self,
        children: &[Zid],
        build: impl Fn() -> NetworkMessage,
    ) -> Result<usize, CodecError> {
        if children.is_empty() {
            return Ok(0);
        }
        self.fan_out(true, |_id, zid| {
            // `then(build)` would move `build` (called once per child); mint
            // lazily on the matching children only.
            Ok(if zid.is_some_and(|z| is_child(children, z)) {
                Some(build())
            } else {
                None
            })
        })
    }

    /// A sourced `DeclareSubscriber` arrived on `inbound`: register the SOURCE
    /// peer's interest in the declared keyexpr, and — only if this NEWLY
    /// learned it — re-flood the declaration onward along the SOURCE's spanning
    /// tree to self's tree children (excluding the inbound face), re-stamped
    /// with this node's psid for the source. The "only on new"
    /// ([`LinkstatepeerSubs::register`](crate::linkstate_subs::LinkstatepeerSubs::register)
    /// returning `true`) is the change-gate that bounds the flood: a peer that
    /// already knew the interest does not re-flood, so the declaration cannot
    /// loop. zenoh `register_linkstatepeer_subscription`'s `if !contains {
    /// insert; propagate }`. Resolves the source + re-stamp value through the
    /// shared [`resolve_source`](Self::resolve_source) seam, exactly as
    /// [`forward_push`](Self::forward_push) — the difference is the
    /// control-plane spread floods ALL tree children (zenoh
    /// `propagate_sourced_subscription` uses the tree `children`), not the
    /// data-plane interest-filtered directions.
    fn forward_subscription(&self, inbound: FaceId, reliable: bool, declare: &DeclareOwned) {
        // Only a DeclareSubscriber body carries mesh interest (and only the MVP
        // literal keyexpr form). A non-subscriber Declare / non-literal
        // wireexpr is left alone.
        let Some(keyexpr) = declare_subscriber_keyexpr(declare) else {
            return;
        };
        let (inbound_zid, inbound_link) = {
            let faces = self.faces.borrow();
            match faces.get(&inbound) {
                Some(s) => (s.actions.peer_zid(), s.link),
                None => return,
            }
        };
        let Some((source_zid, out_node_id)) = self.resolve_source(
            inbound_zid.as_ref(),
            inbound_link,
            read_declare_source(declare),
        ) else {
            return;
        };
        // Register the source's interest; re-flood ONLY on a new registration
        // (the loop-bounding change-gate). `register` borrows `keyexpr` (a view
        // into `declare`); the subsequent `declare.clone()` re-borrows after it
        // returns.
        if !self.subs.borrow_mut().register(keyexpr, source_zid.clone()) {
            return;
        }
        let children = self.net.borrow().tree_children_of(&source_zid);
        if children.is_empty() {
            return;
        }
        let mut carrier = declare.clone();
        set_declare_source(&mut carrier, out_node_id);
        // Re-flood to self's children in the source's tree — the same shared
        // re-forward predicate forward_push uses (excludes the inbound face and
        // the source's own neighbour); only the carrier differs.
        let _ = self.fan_out(reliable, |id, zid| {
            Ok(
                is_tree_forward_target(id, zid, inbound, inbound_zid.as_deref(), &children)
                    .then(|| NetworkMessage::Declare(Box::new(carrier.clone()))),
            )
        });
    }

    /// A sourced `UndeclareSubscriber` arrived on `inbound`: withdraw the SOURCE
    /// peer's interest in the retracted keyexpr (carried in the message's
    /// `ext_keyexpr` extension — sourced undeclares use no id, the keyexpr is the
    /// identity), and — only if this peer HELD that interest — re-flood the
    /// retraction onward along the SOURCE's spanning tree to self's tree children
    /// (excluding the inbound face), re-stamped with this node's psid for the
    /// source. The "only on held"
    /// ([`LinkstatepeerSubs::withdraw`](crate::linkstate_subs::LinkstatepeerSubs::withdraw)
    /// returning `true`) is the change-gate bounding the flood — the exact mirror
    /// of [`forward_subscription`](Self::forward_subscription)'s "only on new",
    /// so a retraction cannot loop. zenoh
    /// `forget_linkstatepeer_subscription` -> `unregister_peer_subscription` +
    /// `propagate_forget_sourced_subscription`. Resolves the source + re-stamp
    /// through the same shared [`resolve_source`](Self::resolve_source) seam the
    /// declare path uses.
    fn forward_unsubscription(&self, inbound: FaceId, reliable: bool, declare: &DeclareOwned) {
        // The retracted keyexpr rides the ext_keyexpr extension. A non-undeclare
        // body, or an absent / aliased keyexpr ext, is left alone (the same
        // literal-only MVP deferral as the declare side).
        let Some(keyexpr) = undeclare_subscriber_keyexpr(declare) else {
            return;
        };
        let (inbound_zid, inbound_link) = {
            let faces = self.faces.borrow();
            match faces.get(&inbound) {
                Some(s) => (s.actions.peer_zid(), s.link),
                None => return,
            }
        };
        let Some((source_zid, out_node_id)) = self.resolve_source(
            inbound_zid.as_ref(),
            inbound_link,
            read_declare_source(declare),
        ) else {
            return;
        };
        // Withdraw the source's interest; re-flood ONLY on a real removal (the
        // loop-bounding change-gate). `withdraw` borrows `keyexpr` (a view into
        // `declare`); the subsequent `declare.clone()` re-borrows after it
        // returns.
        if !self.subs.borrow_mut().withdraw(keyexpr, &source_zid) {
            return;
        }
        let children = self.net.borrow().tree_children_of(&source_zid);
        if children.is_empty() {
            return;
        }
        let mut carrier = declare.clone();
        set_declare_source(&mut carrier, out_node_id);
        // Re-flood to self's children in the source's tree — the same shared
        // re-forward predicate forward_subscription uses; only the carrier (an
        // UndeclareSubscriber) differs.
        let _ = self.fan_out(reliable, |id, zid| {
            Ok(
                is_tree_forward_target(id, zid, inbound, inbound_zid.as_deref(), &children)
                    .then(|| NetworkMessage::Declare(Box::new(carrier.clone()))),
            )
        });
    }

    /// Re-advertise known subscriptions to the NEW children a tree-recompute
    /// added — zenoh's `pubsub_tree_change` (`pubsub.rs:641-678`). Called after a
    /// [`compute_trees`](wz_routing_graph::LinkstateNetwork::compute_trees) on a
    /// topology change (an inbound link-state, or a face loss) with THAT
    /// recompute's per-tree new-children DELTA (`(source, [new child, ..])`). A
    /// subscription declared before a peer joined did not reach it; the recompute
    /// makes the joiner a NEW child of some source's tree, and re-flooding the
    /// source's `DeclareSubscriber` to that new child alone delivers the interest
    /// onto the new branch — without re-sending to children that already
    /// converged (c3c-3 D2; the prior version re-flooded to ALL current children
    /// and leaned on the receiver change-gate to dedup the redundant sends).
    ///
    /// Structure mirrors zenoh `pubsub_tree_change`: the OUTER loop is over the
    /// new-children delta (each source tree that grew), the INNER over the
    /// subscriptions sourced at that tree (`*sub == tree_id`); each match floods
    /// to the delta children via [`flood_to_children`](Self::flood_to_children).
    /// ONE delta covers both remote-relayed and self-originated subscriptions: a
    /// self-sourced pair resolves `local_psid_of(self) == 0`, so
    /// `set_declare_source(0)` leaves it self-originated — the same wire a direct
    /// `declare_subscription` emits — which is what lets a ONE-TIME
    /// `declare_subscription` converge to a late-joining peer without a per-tick
    /// re-declare. Loop-freedom is unchanged: the receiver's register change-gate
    /// still bounds any onward flood; the delta only narrows WHO is re-sent to.
    fn re_advertise_subscriptions(&self, new_children: &[(Zid, Vec<Zid>)]) {
        if new_children.is_empty() {
            return;
        }
        // Snapshot the (keyexpr, source) pairs so the table borrow is released
        // before the per-source graph borrow + fan_out below.
        let pairs = self.subs.borrow().subscriptions();
        for (source_zid, delta_children) in new_children {
            // this node's psid for the source (the re-stamp value; 0 for a
            // self-sourced subscription, leaving it self-originated). Scoped graph
            // borrow released before flood_to_children (which re-borrows).
            let out_node_id = match self
                .net
                .borrow()
                .local_psid_of(source_zid)
                .and_then(|p| u16::try_from(p).ok())
            {
                Some(n) => n,
                None => continue,
            };
            for (keyexpr, sub_source) in &pairs {
                if sub_source != source_zid {
                    continue;
                }
                let Ok(mut declare) = build_declare_subscriber(0, 0, Some(keyexpr)) else {
                    continue;
                };
                set_declare_source(&mut declare, out_node_id);
                let _ = self.flood_to_children(delta_children, || {
                    NetworkMessage::Declare(Box::new(declare.clone()))
                });
            }
        }
    }

    /// The single spanning-tree recompute path (D2c SSOT): recompute the trees
    /// and re-advertise known subscriptions to whatever new children the recompute
    /// produced. The [`tick`](FaceForwarder::tick) calls this once per coalescing
    /// window after [`schedule_recompute`](Self::schedule_recompute) marked a
    /// topology change pending — so EVERY production recompute funnels through
    /// here (zenoh's `TreesComputationWorker` body: `compute_trees` then
    /// `pubsub_tree_change`). The `compute_trees` borrow is released before
    /// `re_advertise_subscriptions` re-borrows.
    fn recompute_and_advertise(&self) {
        let new_children = self.net.borrow_mut().compute_trees();
        self.recomputes.set(self.recomputes.get() + 1);
        self.re_advertise_subscriptions(&new_children);
    }

    /// Mark a spanning-tree recompute pending (D2c) — the coalescing entry the
    /// topology-change handlers call instead of recomputing inline. The next
    /// [`tick`](FaceForwarder::tick) flushes it via
    /// [`recompute_and_advertise`](Self::recompute_and_advertise); setting an
    /// already-set flag coalesces (a burst of changes -> one recompute). Mirrors
    /// zenoh's `schedule_compute_trees` (`hat/linkstate_peer/mod.rs:178`), which
    /// likewise only enqueues — the worker does the compute.
    fn schedule_recompute(&self) {
        self.trees_dirty.set(true);
    }

    /// The peers interested in `keyexpr` — the subscription-filter input the
    /// data forward (atom4) feeds to
    /// [`directions_toward`](wz_routing_graph::LinkstateNetwork::directions_toward).
    /// Empty if no peer is interested. Exposed so a test (and the demo's
    /// shutdown summary) can observe the interest the mesh propagated.
    pub fn interested(&self, keyexpr: &str) -> Vec<Zid> {
        self.subs.borrow().interested(keyexpr)
    }
}

/// Whether `zid` is one of `children` — the tree next hops a fan-out targets.
/// The shared membership check the originate paths ([`publish`](LinkstateForwarder::publish)
/// / [`declare_subscription`](LinkstateForwarder::declare_subscription)) and
/// the re-forward paths ([`is_tree_forward_target`]) both build on.
fn is_child(children: &[Zid], zid: &[u8]) -> bool {
    children.iter().any(|c| c.as_slice() == zid)
}

/// Whether a face is a valid forward target when RE-FORWARDING along a source
/// tree: its `zid` is one of `children` (the next hops), it is NOT the inbound
/// face, and its zid is not the inbound neighbour's (a parallel link back
/// toward the source). The single selection predicate shared by
/// [`forward_push`](LinkstateForwarder::forward_push) (data, directions-filtered
/// `children`) and [`forward_subscription`](LinkstateForwarder::forward_subscription)
/// (control, all tree `children`) — only the carrier each wraps differs, so the
/// loop-exclusion mechanics live here once.
fn is_tree_forward_target(
    id: FaceId,
    zid: Option<&[u8]>,
    inbound: FaceId,
    inbound_zid: Option<&[u8]>,
    children: &[Zid],
) -> bool {
    let Some(zid) = zid else {
        return false;
    };
    id != inbound && inbound_zid != Some(zid) && is_child(children, zid)
}

/// Extract a literal keyexpr from a `WireexprOwned` — the wz MVP literal form
/// (`WireexprLocal { id: 0, suffix }`, what `push_build` / `declare_build`
/// emit), shared by the subscription ([`declare_subscriber_keyexpr`]) and data
/// ([`push_keyexpr`]) sides. Returns `None` for a non-literal wireexpr: an
/// aliased (`id != 0`) keyexpr needs a peer keyexpr-mapping table to resolve —
/// the alias-aware superset is `wz_session_core::wireexpr_resolve::resolve_wireexpr`
/// (the routing-routes HAT's path); the linkstate-peer HAT is literal-only in
/// the MVP (keyexpr-mapping + wildcard intersection are tracked deferrals).
fn literal_keyexpr(wireexpr: &WireexprOwned) -> Option<&str> {
    match &wireexpr.body {
        WireexprOwnedVariant::WireexprLocal(w) if w.id == 0 => w.suffix.as_deref(),
        _ => None,
    }
}

/// The literal keyexpr a `DeclareSubscriber` declares interest in — `None` for
/// a non-subscriber Declare body or a non-literal keyexpr.
fn declare_subscriber_keyexpr(declare: &DeclareOwned) -> Option<&str> {
    match &declare.body {
        DeclareOwnedVariant::CodecZenohDeclSubscriber(sub) => literal_keyexpr(&sub.keyexpr),
        _ => None,
    }
}

/// The literal keyexpr a sourced `UndeclareSubscriber` retracts — read from its
/// `ext_keyexpr` extension (a sourced undeclare carries no id, so the keyexpr is
/// the subscription identity). `None` for a non-undeclare-subscriber body or an
/// absent / aliased keyexpr ext (the literal-only MVP deferral, the retraction
/// twin of [`declare_subscriber_keyexpr`]).
fn undeclare_subscriber_keyexpr(declare: &DeclareOwned) -> Option<&str> {
    match &declare.body {
        DeclareOwnedVariant::CodecZenohUndeclSubscriber(u) => {
            read_ext_keyexpr(u.extensions.as_ref())
        }
        _ => None,
    }
}

/// The literal keyexpr a data `Push` carries — the key the data-route filter
/// (c3c-3 atom4) looks the interested-peer set up by. `None` for a non-literal
/// keyexpr.
fn push_keyexpr(push: &PushOwned) -> Option<&str> {
    literal_keyexpr(&push.keyexpr)
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
        // Self gained a routing link (its own link-state changed, sn bumped):
        // flood self's updated full link-state to EVERY held face — the new face is
        // bootstrapped with the full topology, and existing faces learn the new
        // neighbour NOW rather than at a periodic tick. zenoh `add_link` floods the
        // updated self link-state to existing links + full state to the new link
        // (`network.rs:862-903`); wz floods the full topology to all (the Details
        // delta split is D4). Event-driven, so the mesh needs no periodic re-flood
        // (D2b — the periodic tick is gone). A held-without-identity face (link ==
        // None) is not a routing peer and did not change self's link-state, so it
        // triggers no flood.
        if link.is_some() {
            let _ = self.flood_self();
        }
    }

    fn deregister(&self, id: FaceId) {
        // Drop the face's state; if it had a graph link, disconnect it (inline —
        // the dead edge must leave the graph at once) and SCHEDULE a recompute.
        // The recompute purges the trees that still include the dead link; until
        // the next tick flushes it, `forward_push` / `publish` may route along a
        // stale tree, but the dead face is already gone from `faces`, so a send
        // toward it simply drops (self-heal) — the same bounded window zenoh
        // accepts by debouncing link-down too (`hat/linkstate_peer/mod.rs`
        // `schedule_compute_trees`, the link-down path). The recompute's
        // re-advertise is deferred with it (D2c).
        let dropped_link = if let Some(state) = self.faces.borrow_mut().remove(&id) {
            // Purge the departed peer's subscription interest — zenoh's
            // `pubsub_remove_node` on link-down (`hat/linkstate_peer/mod.rs`).
            // Without this a gone subscriber's interest lingers in the table,
            // keeping the publisher's any-interest gate spuriously armed (the
            // data route self-heals via unreachability, but the table leaks).
            if let Some(zid) = state.actions.peer_zid() {
                self.subs.borrow_mut().remove_peer(&zid);
            }
            if let Some(link) = state.link {
                self.net.borrow_mut().remove_link(link);
                true
            } else {
                false
            }
        } else {
            false
        };
        if dropped_link {
            // D2b — self LOST a routing link (its own link-state changed, sn
            // bumped): flood self's updated full link-state to the surviving faces
            // IMMEDIATELY (zenoh `remove_link`'s `send_on_links`,
            // `network.rs:936-962`), so they drop the dead link from their topology
            // NOW. The flood is a wire event on the link change and stays inline;
            // only the spanning-tree recompute it triggers is coalesced (D2c).
            let _ = self.flood_self();
            // D2c — coalesce the recompute (and its re-advertise) onto the tick,
            // exactly as the inbound forward() path does. The recompute matters for
            // more than purging the dead link: under non-uniform edge weights (e.g.
            // a zenohd peer's `transport_weights` ingested into the graph) dropping
            // a link can REMOVE a cheaper detour and RE-HOME a node so it becomes
            // self's NEW child in some root's tree — self is then the only node that
            // can deliver that root's interest to it, so the flushed
            // re_advertise_subscriptions must run (R311sg). zenoh feeds the
            // link-down delta into `pubsub_tree_change` unconditionally; the
            // uniform-weight common case shrinks self's children with no re-home, so
            // the flushed delta is empty and the re-advertise no-ops.
            self.schedule_recompute();
        }
    }

    // D2c — the coalescing recompute seam. Topology FLOODING stays event-driven
    // (register / deregister flood self's changed link-state immediately,
    // `propagate` re-floods inbound changes), exactly like zenoh — the mesh has NO
    // periodic WIRE traffic. But the spanning-tree RECOMPUTE each change triggers
    // is debounced: the handlers `schedule_recompute` (set the dirty flag) and the
    // tick flushes ONE recompute per window, coalescing a burst into a single
    // `compute_trees` (zenoh's `TreesComputationWorker`). This is the single-task
    // actor translation of zenoh's worker task: the loop's tick drives the flush
    // rather than a separate task, because `forward` runs INSIDE the per-face drive
    // future (`accept_loop.rs`), so the loop's only regular re-entry point is this
    // timer. The tick is a cheap local poll (one `Cell` read) when nothing
    // accumulated — it sends nothing on the wire unless a real topology change is
    // pending, so D2b's no-periodic-wire-traffic property holds.
    fn tick_period(&self) -> Option<Duration> {
        Some(self.trees_delay)
    }

    fn tick(&self) {
        // Flush a coalesced recompute, if one accumulated since the last tick.
        // `replace(false)` reads-and-clears in one step: an idle window leaves the
        // flag false and this is a no-op poll; a window with >=1 scheduled change
        // runs exactly one `compute_trees` + re-advertise for the whole burst.
        if self.trees_dirty.replace(false) {
            self.recompute_and_advertise();
        }
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
                        // Ingest, then re-flood the changed nodes onward to the
                        // OTHER faces (transitive propagation) — both inline, as
                        // zenoh floods link-states inline.
                        let changes = self.ingest_inbound_linkstate(id, list);
                        let _ = self.propagate(id, &changes);
                        // c3c-3 D2c — coalesce the spanning-tree recompute (and its
                        // pubsub_tree_change re-advertise to new children) onto the
                        // tick instead of recomputing inline: a burst of inbound
                        // lists (a join flood) collapses to one compute_trees. The
                        // re-advertise the recompute drives is what delivers a known
                        // subscription to a peer that joined since the declaration
                        // (A2 + D2 children-delta), now flushed by the tick.
                        self.schedule_recompute();
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
                // c3c-3 — a sourced subscription declaration: a
                // DeclareSubscriber registers the source peer's interest, an
                // UndeclareSubscriber (c3c-3 debt A1) withdraws it; both then
                // re-flood along the source's tree on a real change.
                NetworkMessage::Declare(declare) => match &declare.body {
                    DeclareOwnedVariant::CodecZenohUndeclSubscriber(_) => {
                        self.forward_unsubscription(id, *reliable, declare);
                    }
                    _ => self.forward_subscription(id, *reliable, declare),
                },
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
        fwd.ingest_inbound_linkstate(FaceId(7), list_with_node(11, 5, 0xBB));
        assert_eq!(fwd.ingested(), 1);
        assert!(fwd.net.borrow().get_node(&zid(0xBB)).is_some());
    }

    #[test]
    fn inbound_from_unknown_face_is_dropped() {
        let fwd = LinkstateForwarder::new(zid(0x01), 2);
        // no face registered for id 9.
        fwd.ingest_inbound_linkstate(FaceId(9), list_with_node(11, 5, 0xBB));
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
        fwd.ingest_inbound_linkstate(FaceId(7), list_with_node(11, 5, 0xBB));
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
    fn register_event_floods_self_to_existing_faces() {
        // D2b — when a NEW routing face registers, self's own link-state changed
        // (it gained a neighbour, sn bumped), so self floods the update to the
        // EXISTING faces at once (event-driven), not at a periodic tick. A is held
        // (a routing peer, so its zid connects it); B then registers, and A
        // receives self's updated link-state immediately.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        sink_a.reset(); // ignore A's own register-time bootstrap
        let (face_b, _sb) = peer_face(zid(0x0B));
        fwd.register(FaceId(1), &face_b); // self gains a link -> floods existing A
        assert_eq!(
            sink_a.frame_count(),
            1,
            "the existing face A learns self's new neighbour B at once (event-driven)"
        );
    }

    #[test]
    fn deregister_event_floods_self_to_surviving_faces() {
        // D2b — when a routing face drops, self's own link-state changed (it lost a
        // neighbour, sn bumped), so self floods the update to the SURVIVING faces at
        // once, so they drop the dead link from their topology now (zenoh
        // remove_link's send_on_links) rather than at a periodic tick.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, _sb) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        sink_a.reset(); // ignore the register-time floods
        fwd.deregister(FaceId(1)); // B drops -> floods surviving A
        assert_eq!(
            sink_a.frame_count(),
            1,
            "the surviving face A learns self lost B at once (event-driven)"
        );
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
    /// Ingests the list, then runs the recompute synchronously and returns its
    /// new-children delta — D2c defers the recompute to the tick in production, so
    /// a unit test forces it here to get the deterministic delta a re-advertise
    /// test threads into `re_advertise_subscriptions` (callers that only need the
    /// edge formed + trees computed ignore the return).
    fn advertise_link_back(
        fwd: &LinkstateForwarder,
        face: FaceId,
        neighbour: u8,
        self_node: u8,
    ) -> Vec<(Zid, Vec<Zid>)> {
        fwd.ingest_inbound_linkstate(
            face,
            list(vec![
                entry(0, 1, self_node, &[]),
                entry(1, 5, neighbour, &[0]),
            ]),
        );
        fwd.net.borrow_mut().compute_trees()
    }

    /// Register (via the real sourced-declare path) that the peer on `face` is
    /// interested in `keyexpr` — a sourced `DeclareSubscriber` the neighbour
    /// sent (node_id 0 = that neighbour is the source). The data-route filter
    /// (c3c-3 atom4) forwards a Push only toward such interested peers, so the
    /// forwarding tests establish interest first. A caller resets sinks
    /// afterwards to drop the registration's own re-flood.
    fn declare_interest(fwd: &LinkstateForwarder, face: FaceId, keyexpr: &str) {
        let declare = build_declare_subscriber(0, 0, Some(keyexpr)).expect("build sub");
        fwd.forward_subscription(face, true, &declare);
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

    /// Decode the routing-context `node_id` of the single forwarded Declare in a
    /// recorded wire frame — the control-plane twin of [`forwarded_source`],
    /// proving the re-stamp landed ON THE WIRE for a sourced (Un)DeclareSubscriber.
    fn forwarded_declare_source(frame: &[u8]) -> u16 {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let InboundFrame::Frame { payload, .. } =
            parse_inbound(frame).expect("parse forwarded frame")
        else {
            panic!("forwarded bytes are not a Frame");
        };
        let msgs = parse_frame_payload(&payload).expect("parse frame payload");
        match msgs.first() {
            Some(NetworkMessage::Declare(d)) => read_declare_source(d),
            other => panic!("expected a forwarded Declare, got {other:?}"),
        }
    }

    #[test]
    fn forwards_a_push_along_the_source_tree_to_a_child() {
        // Line A - S(self) - B (A and B each link only to S). B subscribes to
        // the Push's keyexpr. A Push self-originated by neighbour A (node_id 0)
        // floods along A's tree toward the interested subscriber B: self's only
        // child toward B is B, so it reaches B and never goes back to A.
        let fwd = LinkstateForwarder::new(zid(0x05), 2); // self -> idx 0
        let (face_a, sink_a) = peer_face(zid(0x0A)); // -> idx 1
        let (face_b, sink_b) = peer_face(zid(0x0B)); // -> idx 2
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05); // edge S<->B
        declare_interest(&fwd, FaceId(1), "demo/data"); // B subscribes
        sink_a.reset();
        sink_b.reset();

        fwd.forward_push(FaceId(0), true, &data_push());

        assert_eq!(
            sink_b.frame_count(),
            1,
            "forwarded to the interested child B"
        );
        assert_eq!(sink_a.frame_count(), 0, "never back toward the source A");
        // Re-stamped with THIS node's psid for the source A (its idx, 1).
        assert_eq!(forwarded_source(&sink_b.frame_bytes(0)), 1);
    }

    #[test]
    fn does_not_forward_a_push_to_a_face_outside_the_source_tree() {
        // self holds A (connected, edge S<->A) and B (held but never advertised
        // back, so it is an isolated node with no edge). B subscribes, yet a
        // Push from A still does not reach it: B is not in A's spanning tree, so
        // `directions_toward` finds no hop toward it (interest alone is not
        // enough — the subscriber must be reachable in the source's tree).
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // only S<->A
        declare_interest(&fwd, FaceId(1), "demo/data"); // B subscribes (but isolated)
        sink_a.reset();
        sink_b.reset();

        fwd.forward_push(FaceId(0), true, &data_push());
        assert_eq!(sink_a.frame_count(), 0, "not back toward the source");
        assert_eq!(
            sink_b.frame_count(),
            0,
            "B is interested but not in A's tree -> no hop, no forward"
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
        fwd.ingest_inbound_linkstate(
            FaceId(0),
            list(vec![
                entry(0, 1, 0x05, &[]),
                entry(1, 5, 0x0A, &[0, 7]),
                entry(7, 5, 0x0B, &[1]),
            ]),
        );
        advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05); // edge S-C
        declare_interest(&fwd, FaceId(1), "demo/data"); // C subscribes
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
    fn forward_subscription_resolves_a_transit_source_from_the_link_psid() {
        // The CONTROL-plane twin of the transit-Push test (rem-2 coverage): a
        // sourced DeclareSubscriber arrives on A's face with a NON-zero node_id =
        // A's psid for B (a transit declaration, not A self-originated). Self
        // resolves it via A's link psid->zid map to source B (NOT the inbound
        // neighbour A), registers B's interest, then re-floods along B's spanning
        // tree to self's child C (A is B's child, excluded as inbound) — re-stamped
        // into self's psid for B. Exercises the shared resolve_source seam with a
        // non-zero id on the Declare path, where the prior subscription tests only
        // used node_id 0.
        let fwd = LinkstateForwarder::new(zid(0x05), 2); // S -> idx 0
        let (face_a, sink_a) = peer_face(zid(0x0A)); // -> idx 1
        let (face_c, sink_c) = peer_face(zid(0x0C)); // -> idx 2
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        fwd.ingest_inbound_linkstate(
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

        let mut declare = build_declare_subscriber(0, 0, Some("demo/sub")).expect("build");
        set_declare_source(&mut declare, 7); // node_id 7 = A's psid for B
        fwd.forward_subscription(FaceId(0), true, &declare);

        assert_eq!(
            fwd.interested("demo/sub"),
            vec![zid(0x0B)],
            "registered the RESOLVED transit source B, not the inbound neighbour A",
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "re-flooded to self's child C in B's tree"
        );
        assert_eq!(sink_a.frame_count(), 0, "A is the inbound face (excluded)");
        // Re-stamped with self's psid for the resolved source B (its idx, 3).
        assert_eq!(forwarded_declare_source(&sink_c.frame_bytes(0)), 3);
    }

    #[test]
    fn publish_sends_self_originated_data_to_an_interested_tree_child() {
        // self(S) publishes its OWN data toward an interested subscriber: A
        // subscribes, so the Put reaches A (self's child toward A in self's
        // tree), stamped self-originated (node_id 0).
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A
        declare_interest(&fwd, FaceId(0), "demo/data"); // A subscribes
        sink_a.reset();

        let sent = fwd.publish("demo/data", b"v").expect("publish");
        assert_eq!(sent, 1, "sent to the one interested tree child");
        assert_eq!(sink_a.frame_count(), 1, "A received the published Put");
        // self-originated -> node_id 0 on the wire (zenoh DEFAULT).
        assert_eq!(forwarded_source(&sink_a.frame_bytes(0)), 0);
    }

    #[test]
    fn publish_to_an_unsubscribed_keyexpr_sends_nothing() {
        // The any-interest gate on the publish path: with no subscriber for the
        // keyexpr, originating a Put reaches no face (and allocates no carrier).
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        sink_a.reset();

        let sent = fwd.publish("demo/data", b"v").expect("publish");
        assert_eq!(sent, 0, "no subscriber -> nothing sent");
        assert_eq!(sink_a.frame_count(), 0, "A receives no unsubscribed data");
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
        fwd.ingest_inbound_linkstate(
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

    /// Decode the hop-limit (remaining forward budget) of the single forwarded
    /// Push in a recorded wire frame — proves the budget landed ON THE WIRE (the
    /// wz-proprietary `0x0a` ext survived the codec), the c3c-3 D1 twin of
    /// [`forwarded_source`]. `None` when the forwarded Push carried no hop ext.
    fn forwarded_hoplimit(frame: &[u8]) -> Option<u16> {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let InboundFrame::Frame { payload, .. } =
            parse_inbound(frame).expect("parse forwarded frame")
        else {
            panic!("forwarded bytes are not a Frame");
        };
        let msgs = parse_frame_payload(&payload).expect("parse frame payload");
        match msgs.first() {
            Some(NetworkMessage::Push(p)) => read_push_hoplimit(p),
            other => panic!("expected a forwarded Push, got {other:?}"),
        }
    }

    /// Whether a recorded wire frame carries a `Declare` — used to tell a
    /// SUBSCRIPTION re-advertise (a sourced DeclareSubscriber) apart from a
    /// TOPOLOGY flood (an OAM_LINKSTATE), since after D2b both can reach a face.
    fn frame_has_declare(frame: &[u8]) -> bool {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let InboundFrame::Frame { payload, .. } =
            parse_inbound(frame).expect("parse forwarded frame")
        else {
            panic!("forwarded bytes are not a Frame");
        };
        parse_frame_payload(&payload)
            .expect("parse frame payload")
            .iter()
            .any(|m| matches!(m, NetworkMessage::Declare(_)))
    }

    #[test]
    fn publish_stamps_the_hop_limit_budget_as_node_count() {
        // c3c-3 D1 — a published Put carries a hop-limit budget = node_count (the
        // transient-loop bound). With self + A in the graph, node_count is 2, so
        // the Put A receives is stamped with budget 2.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A (2 nodes)
        declare_interest(&fwd, FaceId(0), "demo/data");
        sink_a.reset();
        assert_eq!(fwd.node_count(), 2);

        fwd.publish("demo/data", b"v").expect("publish");
        assert_eq!(sink_a.frame_count(), 1);
        assert_eq!(
            forwarded_hoplimit(&sink_a.frame_bytes(0)),
            Some(2),
            "published Put stamped with hop budget = node_count",
        );
    }

    #[test]
    fn forward_push_decrements_the_hop_limit() {
        // c3c-3 D1 — a transit forward decrements the budget by one (the next hop
        // sees one less). Line A - S - B, B subscribes; a Push from A arrives with
        // hop 5 and is re-forwarded to B with hop 4.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(1), "demo/data");
        sink_a.reset();
        sink_b.reset();

        let mut push = data_push();
        set_push_hoplimit(&mut push, 5);
        fwd.forward_push(FaceId(0), true, &push);
        assert_eq!(sink_b.frame_count(), 1, "forwarded to the interested child");
        assert_eq!(
            forwarded_hoplimit(&sink_b.frame_bytes(0)),
            Some(4),
            "the outbound copy carries hop - 1",
        );
    }

    #[test]
    fn forward_push_drops_an_exhausted_hop_budget() {
        // c3c-3 D1 — the loop bound: a Push arriving with its budget exhausted
        // (hop 1, the last unit) is NOT re-forwarded, even though B is an
        // interested child in the source's tree. This is what cuts a transient
        // convergence loop after a bounded number of hops.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(1), "demo/data");
        sink_a.reset();
        sink_b.reset();

        let mut push = data_push();
        set_push_hoplimit(&mut push, 1); // budget exhausted
        fwd.forward_push(FaceId(0), true, &push);
        assert_eq!(
            sink_b.frame_count(),
            0,
            "an exhausted hop budget is not re-forwarded (the loop bound)",
        );
        assert_eq!(sink_a.frame_count(), 0, "nor back toward the source");
    }

    #[test]
    fn forward_push_bounds_an_unstamped_push_from_node_count() {
        // c3c-3 D1 — an un-stamped Push (no hop ext, e.g. entering from a
        // non-stamping origin) is treated as a fresh budget = this node's
        // node_count, then decremented, so it is bounded from its first mesh hop.
        // Line A - S - B (3 nodes), B subscribes; an un-stamped Push from A is
        // forwarded to B with hop = node_count - 1 = 2.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(1), "demo/data");
        sink_a.reset();
        sink_b.reset();
        assert_eq!(fwd.node_count(), 3);

        let push = data_push(); // carries no hop ext
        assert_eq!(read_push_hoplimit(&push), None, "un-stamped");
        fwd.forward_push(FaceId(0), true, &push);
        assert_eq!(sink_b.frame_count(), 1);
        assert_eq!(
            forwarded_hoplimit(&sink_b.frame_bytes(0)),
            Some(2),
            "absent hop treated as node_count budget, then decremented",
        );
    }

    #[test]
    fn the_hop_limit_bounds_a_circulating_push_to_its_budget() {
        // R311sg — D1's loop bound exercised as an ACTUAL multi-hop circulation
        // (the prior hop tests only checked single-hop stamp/decrement/drop). A
        // Push is forwarded, the decremented hop is taken off the forwarded copy
        // and RE-INJECTED (as a circulating message would re-enter the node a hop
        // later), and the round repeats. The forward count is BOUNDED by the
        // initial budget — proving a transient loop terminates by construction
        // rather than circulating forever. Line C(source) - S - A; A subscribes,
        // so each round forwards toward A and decrements the budget.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A)); // interested child
        let (face_c, _sc) = peer_face(zid(0x0C)); // inbound source neighbour
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05);
        declare_interest(&fwd, FaceId(0), "demo/data"); // A interested
        sink_a.reset();

        // Start with a budget LARGER than node_count (3) so the bound is the hop
        // budget, not the graph size — a circulating message keeps its budget.
        let mut hop = 8u16;
        let mut forwards = 0u16;
        loop {
            let before = sink_a.frame_count();
            let mut push = data_push();
            set_push_source(&mut push, 0); // self-originated from the inbound C
            set_push_hoplimit(&mut push, hop);
            fwd.forward_push(FaceId(1), true, &push); // inbound = C (the source)
            if sink_a.frame_count() == before {
                break; // forward_push dropped it — the budget is exhausted
            }
            forwards += 1;
            hop = forwarded_hoplimit(&sink_a.frame_bytes(sink_a.frame_count() - 1))
                .expect("the forwarded copy carries the decremented budget");
            assert!(
                forwards <= 8,
                "a circulating Push must not forward unboundedly"
            );
        }
        // Budget 8 forwards at most 7 times (hop 8->7->...->2 each forward, then
        // the round that receives hop=1 drops). The loop is CUT, never infinite.
        assert_eq!(
            forwards, 7,
            "the circulating Push was bounded to budget-1 hops, then dropped"
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
        fwd.ingest_inbound_linkstate(
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
        // D2c — deregister SCHEDULES the recompute, it no longer runs it inline, so
        // B's tree is still the stale cached one (names A) until the tick flushes
        // the recompute (remove_link drops the edge but leaves the `trees` cache).
        assert_eq!(
            fwd.tree_children_of(&zid(0x0B)),
            vec![zid(0x0A)],
            "deregister deferred the recompute: B's tree still names A pre-tick"
        );
        fwd.tick(); // flush the coalesced recompute
        assert!(
            fwd.tree_children_of(&zid(0x0B)).is_empty(),
            "the tick recomputed: A/C left B's tree (a stale tree would keep A)"
        );
    }

    #[test]
    fn forwards_along_the_tree_not_the_cycle_edge_in_a_mesh() {
        // R311rl — loop-freedom on a CYCLIC mesh (the e2e only exercises a
        // line). Converged topology: triangle S-A-B (self S is linked to A and
        // B, and A-B are linked to each other) plus S-C. BOTH B and C subscribe.
        // A Push from A floods along A's spanning tree, in which B is A's DIRECT
        // child (via the A-B edge) while C is self's. So even though B is
        // interested, the route toward B runs S->A (B is A's child), and A is
        // the inbound face (excluded) — self forwards ONLY to its tree child C,
        // NEVER across the S-B cycle edge, so the message cannot loop S->B->A->S.
        // The cycle edge is excluded because the (converged, deterministic-
        // jitter) tree is consistent and acyclic — interest does not override it.
        let fwd = LinkstateForwarder::new(zid(0x05), 2); // S -> idx 0
        let (face_a, sink_a) = peer_face(zid(0x0A)); // -> idx 1
        let (face_b, sink_b) = peer_face(zid(0x0B)); // -> idx 2
        let (face_c, sink_c) = peer_face(zid(0x0C)); // -> idx 3
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        fwd.register(FaceId(2), &face_c);
        // A advertises links to S + B (authoritative); A-B closes the triangle.
        fwd.ingest_inbound_linkstate(
            FaceId(0),
            list(vec![
                entry(0, 1, 0x05, &[]),
                entry(1, 5, 0x0A, &[0, 2]),
                entry(2, 5, 0x0B, &[1]),
            ]),
        );
        // B advertises links to S + A (authoritative, higher sn so it is not
        // stale-gated); S and A are stale references for the psid mapping only.
        fwd.ingest_inbound_linkstate(
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
        declare_interest(&fwd, FaceId(1), "demo/data"); // B subscribes
        declare_interest(&fwd, FaceId(2), "demo/data"); // C subscribes
        sink_a.reset();
        sink_b.reset();
        sink_c.reset();

        fwd.forward_push(FaceId(0), true, &data_push()); // Push from A (source A)
        assert_eq!(
            sink_c.frame_count(),
            1,
            "forwarded to the interested child C"
        );
        assert_eq!(sink_a.frame_count(), 0, "not back to the source A");
        assert_eq!(
            sink_b.frame_count(),
            0,
            "interested B is reached via A (inbound, excluded); the S-B cycle \
             edge is never used — no loop"
        );
    }

    // ── c3c-3 atom4: subscription-filtered data route ────────────────

    #[test]
    fn forward_push_to_the_interested_subtree_only() {
        // S has neighbours A, B, C (a star). A Push from A floods along A's
        // tree, where B and C are both self's children. Only B subscribes, so
        // the filter forwards to B ALONE — never to the uninterested C (the
        // pre-atom4 broadcast would have hit both). This is the point of c3c-3.
        let fwd = LinkstateForwarder::new(zid(0x05), 2); // S
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        let (face_c, sink_c) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        fwd.register(FaceId(2), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S-A
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05); // edge S-B
        advertise_link_back(&fwd, FaceId(2), 0x0C, 0x05); // edge S-C
        declare_interest(&fwd, FaceId(1), "demo/data"); // only B subscribes
        sink_a.reset();
        sink_b.reset();
        sink_c.reset();

        fwd.forward_push(FaceId(0), true, &data_push());
        assert_eq!(
            sink_b.frame_count(),
            1,
            "forwarded to the interested child B"
        );
        assert_eq!(sink_c.frame_count(), 0, "NOT to the uninterested child C");
        assert_eq!(sink_a.frame_count(), 0, "not back to the source A");
    }

    #[test]
    fn forward_push_with_no_interest_forwards_nothing() {
        // The any-interest gate: a Push whose keyexpr no peer subscribes to is
        // not forwarded at all (the pre-atom4 broadcast would have flooded B).
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        sink_a.reset();
        sink_b.reset();

        fwd.forward_push(FaceId(0), true, &data_push());
        assert_eq!(sink_b.frame_count(), 0, "no subscriber -> no forward");
        assert_eq!(sink_a.frame_count(), 0, "not back to the source either");
    }

    #[test]
    fn forward_push_to_two_interested_subtrees() {
        // R311rv review coverage — multi-direction fan-out at the forward level
        // (the graph unit covers the split; this proves forward_push honours
        // it). S has neighbours A, B, C; a Push from A has B and C both as self's
        // children. BOTH subscribe -> the filter forwards to BOTH.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        let (face_c, sink_c) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        fwd.register(FaceId(2), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        advertise_link_back(&fwd, FaceId(2), 0x0C, 0x05);
        declare_interest(&fwd, FaceId(1), "demo/data");
        declare_interest(&fwd, FaceId(2), "demo/data");
        sink_a.reset();
        sink_b.reset();
        sink_c.reset();

        fwd.forward_push(FaceId(0), true, &data_push());
        assert_eq!(sink_b.frame_count(), 1, "B (interested subtree) forwarded");
        assert_eq!(sink_c.frame_count(), 1, "C (interested subtree) forwarded");
        assert_eq!(sink_a.frame_count(), 0, "not back to the source A");
    }

    #[test]
    fn forward_push_routes_by_keyexpr() {
        // R311rv review coverage — keyexpr-keyed routing through the real
        // forward path (the registry unit covers key isolation; this proves the
        // forward filter honours it). B subscribes demo/a, C subscribes demo/b;
        // a Push for demo/a reaches only B.
        use wz_session_core::push_build::build_push_literal;
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        let (face_c, sink_c) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        fwd.register(FaceId(2), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        advertise_link_back(&fwd, FaceId(2), 0x0C, 0x05);
        declare_interest(&fwd, FaceId(1), "demo/a");
        declare_interest(&fwd, FaceId(2), "demo/b");
        sink_a.reset();
        sink_b.reset();
        sink_c.reset();

        let push = build_push_literal("demo/a", b"payload").expect("push demo/a");
        fwd.forward_push(FaceId(0), true, &push);
        assert_eq!(sink_b.frame_count(), 1, "B subscribed demo/a -> receives");
        assert_eq!(
            sink_c.frame_count(),
            0,
            "C subscribed demo/b -> not a demo/a destination"
        );
    }

    #[test]
    fn forward_push_does_not_echo_to_an_interested_source() {
        // R311rv review coverage — the source A is ALSO a subscriber, plus B is
        // the far subscriber. A Push from A must reach B but NOT echo back to A:
        // A's own interest resolves to the upstream (inbound) direction, which
        // the inbound-face exclusion drops.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(0), "demo/data"); // A (the source) subscribes
        declare_interest(&fwd, FaceId(1), "demo/data"); // B subscribes
        sink_a.reset();
        sink_b.reset();

        fwd.forward_push(FaceId(0), true, &data_push());
        assert_eq!(sink_b.frame_count(), 1, "B (far subscriber) receives");
        assert_eq!(
            sink_a.frame_count(),
            0,
            "A is source/inbound: its own interest routes upstream, excluded"
        );
    }

    #[test]
    fn deregister_purges_the_departed_peers_interest() {
        // R311rt review remediation — a subscriber's interest must not outlive
        // its face. A declares interest, then its face deregisters: the table
        // must drop A so the publisher's any-interest gate is no longer armed
        // for it (zenoh pubsub_remove_node on link-down). Before the fix the
        // interest leaked (the route self-healed via unreachability, but the
        // table kept the stale entry).
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, _sa) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        declare_interest(&fwd, FaceId(0), "demo/data");
        assert_eq!(
            fwd.interested("demo/data"),
            vec![zid(0x0A)],
            "A's interest registered"
        );

        fwd.deregister(FaceId(0));
        assert!(
            fwd.interested("demo/data").is_empty(),
            "deregister purged A's interest (no stale subscriber left armed)"
        );
    }

    // ── c3c-3 atom3b-ii: subscription declaration propagation ────────

    #[test]
    fn declare_subscription_floods_to_tree_children() {
        // self(S) declares its OWN interest: floods a sourced DeclareSubscriber
        // to self's children in self's tree (here the single neighbour A).
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A
        sink_a.reset();

        let sent = fwd.declare_subscription("demo/sub").expect("declare");
        assert_eq!(sent, 1, "flooded to the one tree child");
        assert_eq!(
            sink_a.frame_count(),
            1,
            "A received the subscription declaration"
        );
    }

    #[test]
    fn forward_subscription_registers_source_and_re_floods_along_the_tree() {
        // Line A - S(self) - C. A's sourced DeclareSubscriber (node_id 0) floods
        // along A's tree: self registers A's interest, then re-floods to its
        // tree child C — never back to the inbound source A.
        let fwd = LinkstateForwarder::new(zid(0x05), 2); // self S
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_c, sink_c) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A
        advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05); // edge S<->C
        sink_a.reset();
        sink_c.reset();

        let declare = build_declare_subscriber(0, 0, Some("demo/sub")).expect("build");
        fwd.forward_subscription(FaceId(0), true, &declare);

        assert_eq!(
            fwd.interested("demo/sub"),
            vec![zid(0x0A)],
            "self learned A is interested in demo/sub"
        );
        assert_eq!(sink_c.frame_count(), 1, "re-flooded to the tree child C");
        assert_eq!(sink_a.frame_count(), 0, "not back to the inbound source A");
    }

    #[test]
    fn forward_subscription_does_not_re_flood_a_known_interest() {
        // The change-gate: a duplicate DeclareSubscriber for an interest already
        // registered does NOT re-flood (zenoh's `if !contains`), so a converged
        // mesh cannot loop the declaration.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, _sa) = peer_face(zid(0x0A));
        let (face_c, sink_c) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05);

        let declare = build_declare_subscriber(0, 0, Some("demo/sub")).expect("build");
        fwd.forward_subscription(FaceId(0), true, &declare); // first: register + flood
        sink_c.reset();
        fwd.forward_subscription(FaceId(0), true, &declare); // duplicate: gated

        assert_eq!(
            fwd.interested("demo/sub"),
            vec![zid(0x0A)],
            "interest recorded exactly once"
        );
        assert_eq!(
            sink_c.frame_count(),
            0,
            "a known interest is not re-flooded"
        );
    }

    #[test]
    fn forward_dispatches_a_declare_subscriber_to_the_registry() {
        // The forward() seam routes a NetworkMessage::Declare to
        // forward_subscription — the inbound-iteration path the peer loop drives.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, _sa) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);

        let declare = build_declare_subscriber(0, 0, Some("demo/sub")).expect("build");
        let outcome = DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Declare(Box::new(declare))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&outcome));
        assert_eq!(
            fwd.interested("demo/sub"),
            vec![zid(0x0A)],
            "the Declare arm registered A's interest"
        );
    }

    // ── c3c-3 debt A1: subscription RETRACTION propagation ───────────

    #[test]
    fn undeclare_subscription_floods_to_tree_children() {
        // self(S) retracts its OWN interest: floods a sourced UndeclareSubscriber
        // to self's children in self's tree (the single neighbour A) — the
        // retraction twin of declare_subscription.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A
        sink_a.reset();

        let sent = fwd.undeclare_subscription("demo/sub").expect("undeclare");
        assert_eq!(sent, 1, "flooded the retraction to the one tree child");
        assert_eq!(
            sink_a.frame_count(),
            1,
            "A received the subscription retraction"
        );
    }

    #[test]
    fn forward_unsubscription_withdraws_source_and_re_floods_along_the_tree() {
        // Line A - S(self) - C. A first declares interest, then retracts it: the
        // sourced UndeclareSubscriber (node_id 0) floods along A's tree — self
        // withdraws A's interest, then re-floods to its tree child C, never back
        // to the inbound source A.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_c, sink_c) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A
        advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05); // edge S<->C
        declare_interest(&fwd, FaceId(0), "demo/sub"); // A is interested
        assert_eq!(fwd.interested("demo/sub"), vec![zid(0x0A)], "A registered");
        sink_a.reset();
        sink_c.reset();

        let undeclare =
            build_undeclare_subscriber_with_keyexpr("demo/sub").expect("build undeclare");
        fwd.forward_unsubscription(FaceId(0), true, &undeclare);

        assert!(
            fwd.interested("demo/sub").is_empty(),
            "self withdrew A's interest"
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "re-flooded the retraction to the tree child C"
        );
        assert_eq!(sink_a.frame_count(), 0, "not back to the inbound source A");
    }

    #[test]
    fn forward_unsubscription_does_not_re_flood_an_unknown_interest() {
        // The change-gate: an UndeclareSubscriber for an interest never held does
        // NOT withdraw or re-flood (the mirror of zenoh's `if contains`), so a
        // retraction cannot loop on a converged mesh.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, _sa) = peer_face(zid(0x0A));
        let (face_c, sink_c) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05);
        sink_c.reset();

        let undeclare = build_undeclare_subscriber_with_keyexpr("demo/sub").expect("build");
        fwd.forward_unsubscription(FaceId(0), true, &undeclare); // never registered

        assert_eq!(
            sink_c.frame_count(),
            0,
            "an unknown interest's retraction is not re-flooded"
        );
    }

    #[test]
    fn forward_dispatches_an_undeclare_subscriber_to_withdraw() {
        // The forward() seam routes a NetworkMessage::Declare(UndeclareSubscriber)
        // to forward_unsubscription — the inbound-iteration retract path, distinct
        // from the DeclareSubscriber register path.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, _sa) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        declare_interest(&fwd, FaceId(0), "demo/sub"); // A is interested
        assert_eq!(fwd.interested("demo/sub"), vec![zid(0x0A)], "A registered");

        let undeclare = build_undeclare_subscriber_with_keyexpr("demo/sub").expect("build");
        let outcome = DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Declare(Box::new(undeclare))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&outcome));
        assert!(
            fwd.interested("demo/sub").is_empty(),
            "the UndeclareSubscriber arm withdrew A's interest"
        );
    }

    // ── c3c-3 debt A2: pubsub_tree_change re-advertise ───────────────

    #[test]
    fn re_advertise_reaches_a_child_that_joined_after_the_declaration() {
        // A subscribes when S has no other neighbour, so the declaration floods
        // nowhere (S has no child in A's tree yet). C then joins; on the
        // recompute S re-advertises A's subscription to the newly-arrived child C
        // — the late-joiner convergence pubsub_tree_change provides, the reason a
        // ONE-TIME declare suffices (no per-tick re-declare).
        let fwd = LinkstateForwarder::new(zid(0x05), 2); // self S
        let (face_a, _sa) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A only
        declare_interest(&fwd, FaceId(0), "demo/sub"); // A interested; no child -> nowhere

        // C joins now: S<->C edge makes C a child of S in A's tree. The join's
        // recompute delta names C as a new child of A's tree (the one
        // forward()'s hook threads into re_advertise).
        let (face_c, sink_c) = peer_face(zid(0x0C));
        fwd.register(FaceId(1), &face_c);
        let new_children = advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05);
        sink_c.reset(); // ignore any join-time frames

        fwd.re_advertise_subscriptions(&new_children); // what forward()'s hook runs
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the late-joining child C learns A's earlier subscription via re-advertise"
        );
    }

    #[test]
    fn re_advertise_reaches_a_child_that_joined_after_self_declared() {
        // The origination half: self S declares its OWN subscription with no
        // neighbour (floods nowhere). C then joins as S's child; on the recompute
        // S re-advertises its own declaration to C — what lets self's ONE-TIME
        // declare_subscription reach a late-joining peer. self's interest lives in
        // the SAME subs set under its own zid (zenoh-faithful), so the single
        // re_advertise loop re-floods it (local_psid_of(self) == 0 -> node_id 0).
        let fwd = LinkstateForwarder::new(zid(0x05), 2); // self S
        fwd.declare_subscription("demo/self")
            .expect("declare own sub"); // no faces

        let (face_c, sink_c) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &face_c);
        // S<->C; C is a new child of S's own tree -> the delta names it.
        let new_children = advertise_link_back(&fwd, FaceId(0), 0x0C, 0x05);
        sink_c.reset();

        fwd.re_advertise_subscriptions(&new_children);
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the late-joining child C learns self's earlier own subscription"
        );
    }

    #[test]
    fn re_advertise_with_no_subscriptions_sends_nothing() {
        // The any-interest guard: with no known subscription there is nothing to
        // re-advertise, so a tree recompute floods nothing.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_c, sink_c) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        let new_children = advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05);
        sink_a.reset();
        sink_c.reset();

        // A non-empty delta, but with no known subscription there is nothing to
        // re-advertise to the new children.
        fwd.re_advertise_subscriptions(&new_children);
        assert_eq!(sink_a.frame_count(), 0, "nothing re-advertised to A");
        assert_eq!(sink_c.frame_count(), 0, "nothing re-advertised to C");
    }

    #[test]
    fn re_advertise_floods_only_the_new_child_not_an_existing_one() {
        // c3c-3 D2 — the delta optimisation: when a tree gains a child, the
        // re-advertise reaches ONLY that new child, not the children that already
        // converged. self S declares demo/x with B as its sole child (B gets it).
        // D then joins as a second child of S; the recompute delta is just [D], so
        // re-advertise sends demo/x to D ALONE — B is not re-sent.
        let fwd = LinkstateForwarder::new(zid(0x05), 2); // self S
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0B, 0x05); // S<->B
        fwd.declare_subscription("demo/x").expect("declare"); // floods to B

        let (face_d, sink_d) = peer_face(zid(0x0D));
        fwd.register(FaceId(1), &face_d);
        let new_children = advertise_link_back(&fwd, FaceId(1), 0x0D, 0x05); // S<->D
        sink_b.reset();
        sink_d.reset();

        fwd.re_advertise_subscriptions(&new_children);
        assert_eq!(sink_d.frame_count(), 1, "the NEW child D learns demo/x");
        assert_eq!(
            sink_b.frame_count(),
            0,
            "the already-converged child B is NOT re-sent (the delta narrows it out)"
        );
    }

    // ── c3c-3 rem-1: single interest set, self excluded from the data route ──

    #[test]
    fn publish_routes_to_remote_subscribers_excluding_self() {
        // self S subscribes to demo/k (registered under its OWN zid in the single
        // set) AND a remote child A subscribes. publish forwards to A only — self
        // is the local sink (delivered by the session layer), excluded from the
        // mesh route by interested_remote, yet still a member of the set.
        let fwd = LinkstateForwarder::new(zid(0x05), 2); // self S
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A
        fwd.declare_subscription("demo/k").expect("self declares"); // self in the set
        declare_interest(&fwd, FaceId(0), "demo/k"); // remote A in the set
        assert!(
            fwd.interested("demo/k").contains(&zid(0x05)),
            "self is a member of the single interest set",
        );
        sink_a.reset();

        let sent = fwd.publish("demo/k", b"v").expect("publish");
        assert_eq!(sent, 1, "published to the one remote subscriber A");
        assert_eq!(sink_a.frame_count(), 1, "A received the data");
    }

    #[test]
    fn publish_to_a_self_only_subscription_has_no_remote_target() {
        // A key only THIS node subscribes to yields no remote forward direction
        // (interested_remote drops self), so publish sends nowhere over the mesh.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        fwd.declare_subscription("demo/k").expect("self declares"); // only self
        sink_a.reset();

        let sent = fwd.publish("demo/k", b"v").expect("publish");
        assert_eq!(
            sent, 0,
            "a self-only subscription has no remote forward target"
        );
        assert_eq!(
            sink_a.frame_count(),
            0,
            "A (not a subscriber) received nothing"
        );
    }

    // ── c3c-3 rem-2: the re_advertise HOOK fires through forward()/deregister ──

    #[test]
    fn forward_hook_re_advertises_to_a_new_child_on_an_inbound_change() {
        // Drives the FULL forward() path (not re_advertise directly): A subscribes
        // when S has no other neighbour, so the declare floods nowhere (S has no
        // child in A's tree yet). C registers, and an inbound OAM_LINKSTATE on C's
        // face establishing the S<->C edge makes C a NEW child of A's tree —
        // forward()'s hook threads the recompute's new-children delta into
        // re_advertise, delivering A's subscription to the new child C. Verifies
        // the call site fires on a real delta (the direct re_advertise unit tests
        // bypass forward()). The OAM is on C's own face, so `propagate` excludes C
        // (a node never receives its own state echoed), leaving exactly the one
        // re-advertised Declare for C to count.
        let fwd = LinkstateForwarder::new(zid(0x05), 2); // S
        let (face_a, _sa) = peer_face(zid(0x0A));
        let (face_c, sink_c) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A
        declare_interest(&fwd, FaceId(0), "demo/sub"); // A subscribes; S has no child yet
        fwd.register(FaceId(1), &face_c); // C joins (graph gains the S<->C link)
        sink_c.reset(); // ignore C's register-time bootstrap

        // Inbound OAM on C's face: C advertises its link back to S, so the
        // recompute makes C a NEW child of A's tree. options 0x03 = OPT_P (zid) |
        // OPT_W (whatami): the entries are ENCODED into the OAM and decoded back
        // through forward(), so (unlike the direct-ingest `entry` helper's
        // options 0) the flags must match the carried optional fields for the
        // codec round-trip to succeed.
        let join = list(vec![
            LinkstateOwned {
                options: 0x03,
                ..entry(0, 1, 0x05, &[])
            },
            LinkstateOwned {
                options: 0x03,
                ..entry(1, 5, 0x0C, &[0])
            },
        ]);
        let oam = build_linkstate_oam_owned(&join).expect("build oam");
        let outcome = DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Oam(oam)],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(1), IterationEvent::Poll(&outcome));
        // D2c — forward() SCHEDULES the recompute (and its re-advertise); nothing
        // reaches C until the tick flushes it (the inbound OAM is on C's own face,
        // so `propagate` excludes C, leaving zero frames pre-tick).
        assert_eq!(
            sink_c.frame_count(),
            0,
            "forward() deferred the re-advertise: C has no Declare pre-tick",
        );
        fwd.tick(); // flush the coalesced recompute
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the tick's recompute re-advertised A's subscription to the NEW child C",
        );
    }

    #[test]
    fn deregister_does_not_re_advertise_the_subscription_to_a_survivor() {
        // c3c-3 D2 + R311sg — the delta on a face loss in the UNIFORM-WEIGHT case
        // (every wz-originated edge has the default weight): dropping a leaf shrinks
        // self's tree children with NO re-homing, so the recompute's new-children
        // delta is empty and the surviving child is NOT re-advertised the
        // subscription. deregister DOES feed the delta to re_advertise (no longer
        // the retracted "provably empty" short-circuit — a re-home under non-uniform
        // weights CAN add a child, see deregister re_advertise wiring), but here the
        // delta is empty so it no-ops. S has edges to A, B, C; A subscribes, so its
        // declare reached children B and C. Dropping B's face SCHEDULES a recompute
        // (D2c) the tick flushes; it adds no new child. C DOES receive the D2b
        // topology flood (an OAM, so it learns the dead link) — but NO Declare.
        let fwd = LinkstateForwarder::new(zid(0x05), 2); // S
        let (face_a, _sa) = peer_face(zid(0x0A));
        let (face_b, _sb) = peer_face(zid(0x0B));
        let (face_c, sink_c) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        fwd.register(FaceId(2), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05); // edge S<->B
        advertise_link_back(&fwd, FaceId(2), 0x0C, 0x05); // edge S<->C
        declare_interest(&fwd, FaceId(0), "demo/sub"); // A subscribes (children B, C)
        sink_c.reset();

        fwd.deregister(FaceId(1)); // B drops -> schedules a recompute (D2c)
        fwd.tick(); // flush it: uniform weights -> empty delta -> no re-advertise
        let any_declare =
            (0..sink_c.frame_count()).any(|i| frame_has_declare(&sink_c.frame_bytes(i)));
        assert!(
            !any_declare,
            "no new child appeared, so the flushed recompute re-advertises nothing \
             to the surviving C (it receives the D2b topology OAM flood, but no \
             Declare)",
        );
    }

    // ── c3c-3 D2c: coalesced spanning-tree recompute (debounce) ──────

    #[test]
    fn tick_with_no_scheduled_change_does_not_recompute() {
        // The coalescing tick is a cheap poll: with nothing scheduled it runs no
        // compute_trees (the recompute witness stays 0), so an idle mesh does no
        // recompute work per tick — D2b's no-periodic-work property, preserved.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        assert_eq!(fwd.recomputes(), 0);
        fwd.tick();
        fwd.tick();
        assert_eq!(
            fwd.recomputes(),
            0,
            "an idle tick is a no-op, not a recompute"
        );
    }

    #[test]
    fn a_burst_of_scheduled_changes_coalesces_into_one_recompute() {
        // D2c — several topology changes between ticks collapse to ONE recompute:
        // each change sets the dirty flag, the tick flushes it once. Two inbound
        // link-states (a join flood) with no tick between them, then one tick ->
        // recomputes() rises by exactly 1, not 2 (the burst coalesced). This is
        // exactly what the forward() OAM arm drives in production (ingest +
        // schedule_recompute), exercised directly here for the count.
        let fwd = LinkstateForwarder::new(zid(0x05), 2);
        let (face_a, _sa) = peer_face(zid(0x0A));
        let (face_b, _sb) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        fwd.ingest_inbound_linkstate(FaceId(0), list_with_node(11, 5, 0xAA));
        fwd.schedule_recompute();
        fwd.ingest_inbound_linkstate(FaceId(1), list_with_node(12, 5, 0xBB));
        fwd.schedule_recompute();
        assert_eq!(
            fwd.recomputes(),
            0,
            "nothing recomputed inline (both deferred)"
        );

        fwd.tick();
        assert_eq!(
            fwd.recomputes(),
            1,
            "the burst coalesced into ONE recompute"
        );

        fwd.tick();
        assert_eq!(fwd.recomputes(), 1, "a second idle tick adds no recompute");
    }

    #[test]
    fn with_trees_delay_sets_the_tick_cadence() {
        // The recompute window is the with_trees_delay knob (the SPF-throttle
        // delay), surfaced as the loop's tick cadence. Default and override both
        // arm the tick — the coalescing path is always on; the knob TUNES the
        // window, it is not an on/off switch.
        let default = LinkstateForwarder::new(zid(0x05), 2);
        assert_eq!(
            default.tick_period(),
            Some(LinkstateForwarder::DEFAULT_TREES_DELAY)
        );
        let tuned = LinkstateForwarder::with_trees_delay(zid(0x05), 2, Duration::from_millis(5));
        assert_eq!(tuned.tick_period(), Some(Duration::from_millis(5)));
    }
}
