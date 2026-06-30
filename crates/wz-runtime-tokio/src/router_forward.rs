// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Router-hat forwarder (P4 §5.21, slice 1a — DUAL-mesh TOPOLOGY STATE).
//!
//! [`RouterForwarder`] is the 4th [`FaceForwarder`](crate::accept_loop::FaceForwarder),
//! the wz port of zenoh's `hat/router` routing strategy. Where the
//! single-net [`LinkstateForwarder`](crate::linkstate_forward) ports
//! `hat/linkstate_peer` (ONE [`LinkstateNetwork`] graph), the router maintains
//! TWO graphs — `routers_net` (the Router-tier mesh) and `linkstatepeers_net`
//! (the Peer-tier mesh) — exactly as zenoh's `HatTables` keeps `routers_net`
//! and `linkstatepeers_net` side by side (`hat/router/mod.rs:174-175`). The
//! local node is a `WhatAmI::Router` present in BOTH graphs (zenoh's local
//! `tables.zid` appears in each net), so both are constructed with
//! [`WhatAmI::Router`].
//!
//! ## Why a 4th typed forwarder, not a `Box<dyn Any>` hat
//!
//! zenoh erases its per-HAT state behind three `Box<dyn Any>` slots
//! (`Tables.hat` / `FaceState.hat` / `Resource.context.hat`) so one dispatcher
//! skeleton serves the client / p2p-peer / linkstate-peer / router HATs. wz's
//! [`FaceForwarder`](crate::accept_loop::FaceForwarder) trait is the same
//! multi-hat seam expressed without type erasure: each forwarder owns TYPED
//! self-state, and the run-mode selects the concrete forwarder. The router is
//! the fourth such type alongside `NoOpForwarder`, `RoutingForwarder`, and
//! `LinkstateForwarder`.
//!
//! ## Slice boundary (1a = topology STATE)
//!
//! This slice is the CONTROL-PLANE TOPOLOGY half, mirroring how the peer
//! lineage shipped graph state (register/deregister + OAM ingest) before the
//! data plane, and how `routing-router` (accept-and-hold) shipped before
//! `routing-routes` (forwarding):
//!
//! - `register` / `deregister` classify a face into a tier by its handshake
//!   [`WhatAmI`] (zenoh's `match face.whatami` at
//!   `new_transport_unicast_face`, `hat/router/mod.rs:424-438`): a Router face
//!   joins `routers_net`, a Peer face joins `linkstatepeers_net`, a Client (or
//!   a face whose routing zid never surfaced) is HELD without a graph link.
//! - `forward` ingests an inbound `OAM_LINKSTATE` into the INBOUND face's
//!   tier-net, re-floods the changed nodes onward, and coalesces the
//!   spanning-tree recompute onto the [`tick`](FaceForwarder::tick) (D2c), per
//!   net.
//! - The flood is **TIER-SCOPED**: a `routers_net` change reaches only Router
//!   faces, a `linkstatepeers_net` change only Peer faces. The two graphs
//!   live in independent psid spaces, so cross-injecting one net's link-state
//!   onto the other net's faces would corrupt their topology — zenoh gets this
//!   for free because each `Network` floods over its OWN link set
//!   (`send_on_links`); wz keeps one `faces` map, so the flood filters on the
//!   per-face tier it records here.
//!
//! ## Deferred to later slices (named, not silently dropped)
//!
//! - **Dual-tier Declare INGEST** — populating `router_subs` / `linkstatepeer_subs`
//!   (and the queryable twins) from sourced `DeclareSubscriber` /
//!   `DeclareQueryable`, plus zenoh's **cross-tier bubble** (a peer/client
//!   declaration re-injected into the router tier under the local zid, and the
//!   reverse) — slice 1b. The tier tables exist here (so the struct + the
//!   `deregister` purge are stable) but are populated by 1b.
//! - **The simple/client subscription store** (zenoh's per-`Resource`
//!   `session_ctxs`, the leaf-subscriber input) — folded into 1b with the
//!   bubble.
//! - **Route COMPUTE + master-election** — `compute_data_route` /
//!   `compute_query_route`, the source-dimensioned route cache, `elect_router`
//!   consistent-hash ingress/egress filtering, and `shared_nodes`
//!   maintenance — the COMPUTE slice. A data `Push` is COUNTED here (the
//!   reception witness) but not yet routed; a `Request` / `Response` is
//!   left alone.
//! - **Gossip / autoconnect / interceptors / pending-query GC** — the
//!   per-net policy knobs the `LinkstateForwarder` carries; added as the
//!   router gains the corresponding plane.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use sce_forge_runtime::codec::CodecError;

use wz_codecs::linkstate_list::LinkstateListOwned;
use wz_routing_graph::{Changes, LinkId, LinkstateNetwork, WhatAmI, Zid};
use wz_session_core::driver_loop::DriverLoopOutcome;
use wz_session_core::linkstate_oam::{
    build_linkstate_oam_owned, try_parse_linkstate_oam, LinkstateOam,
};
use wz_session_core::network_message::NetworkMessage;

use crate::accept_loop::{FaceForwarder, FaceId};
use crate::linkstate_forward::{peer_whatami_routing, peer_zid_routing};
use crate::linkstate_interest::LinkstatepeerInterest;
use crate::session_glue::{IterationEvent, SessionLinkActions};
use wz_session_core::queryable_info::QueryableInfo;

/// Which of a router's two link-state meshes a face belongs to — the routing
/// classification of its handshake [`WhatAmI`] role. zenoh partitions faces by
/// `match face.whatami` at `add_link` (`hat/router/mod.rs:424-438`): a Router
/// joins `routers_net`, a Peer joins `linkstatepeers_net`, a Client joins
/// neither (it is a leaf, not a transit node). [`FaceTier::Client`] therefore
/// has no graph; such a face is HELD (its send seam kept) but routes no
/// topology.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FaceTier {
    Routers,
    LinkstatePeers,
    Client,
}

/// The routing tier of a handshake role. The wz `FaceForwarder` analogue of
/// zenoh's `new_transport_unicast_face` whatami branch
/// (`hat/router/mod.rs:424-438`): wz ports the FULL-linkstate peer model (there
/// is no `p2p_peer` hat), so a Peer always classifies to the linkstate-peer
/// tier — never to the simple tier zenoh's default `peer_to_peer` config would
/// use.
fn tier_of(whatami: WhatAmI) -> FaceTier {
    match whatami {
        WhatAmI::Router => FaceTier::Routers,
        WhatAmI::Peer => FaceTier::LinkstatePeers,
        WhatAmI::Client => FaceTier::Client,
    }
}

/// Per-face state the router keeps for each held face: the send seam to flood
/// TO it, the tier (which net it joined) it was classified into at register,
/// and — once its routing zid surfaced — the graph link in that net. The tier
/// is recorded at register so every later flood / purge targets the SAME net
/// the face joined, without re-deriving it from the (possibly since-changed)
/// handshake.
struct RouterFaceState {
    actions: Arc<SessionLinkActions>,
    tier: FaceTier,
    /// The graph link in the face's tier-net, or `None` for a held face (a
    /// Client, or a Router/Peer whose routing zid never surfaced).
    link: Option<LinkId>,
}

/// A [`FaceForwarder`] that maintains zenoh's DUAL router meshes — `routers_net`
/// (Router-tier) and `linkstatepeers_net` (Peer-tier) — from the face lifecycle
/// and inbound `OAM_LINKSTATE` topology. The router counterpart to the
/// single-net [`LinkstateForwarder`](crate::linkstate_forward). Slice 1a owns
/// the topology STATE; see the module docs for the deferred slices.
pub struct RouterForwarder {
    /// The Router-tier link-state graph (zenoh `HatTables.routers_net`).
    /// `Rc<RefCell>`, single-task, like every forwarder graph.
    routers_net: Rc<RefCell<LinkstateNetwork>>,
    /// The Peer-tier link-state graph (zenoh `HatTables.linkstatepeers_net`).
    /// Unconditionally present (wz ports the full-linkstate peer model — no
    /// p2p-peer hat — so the peer net is never the `Option::None` zenoh uses
    /// for its default `peer_to_peer` config).
    linkstatepeers_net: Rc<RefCell<LinkstateNetwork>>,
    /// Held faces keyed by id, each carrying its send seam, its tier, and (once
    /// its zid is known) its graph link. One id-keyed map across BOTH tiers
    /// (the `RouterFaceState.tier` says which net), so the flood can scope to a
    /// single net by filtering this map.
    faces: RefCell<HashMap<FaceId, RouterFaceState>>,
    /// Router-tier subscription interest (zenoh `HatTables.router_subs`).
    /// Present so the struct + the `deregister` purge are stable; POPULATED by
    /// the Declare-INGEST slice (1b).
    router_subs: RefCell<LinkstatepeerInterest<()>>,
    /// Peer-tier subscription interest (zenoh `HatTables.linkstatepeer_subs`).
    /// Populated by slice 1b.
    linkstatepeer_subs: RefCell<LinkstatepeerInterest<()>>,
    /// Router-tier queryable interest (zenoh `HatTables.router_qabls`).
    /// Populated by slice 1b.
    router_qabls: RefCell<LinkstatepeerInterest<QueryableInfo>>,
    /// Peer-tier queryable interest (zenoh `HatTables.linkstatepeer_qabls`).
    /// Populated by slice 1b.
    linkstatepeer_qabls: RefCell<LinkstatepeerInterest<QueryableInfo>>,
    /// Running total of link-state lists ingested across both nets — the
    /// control-plane work witness (the router twin of
    /// `LinkstateForwarder::ingested`).
    ingested: Cell<usize>,
    /// Running total of data `Push` messages received — the data-plane
    /// reception witness. The route fan-out that consumes it is the COMPUTE
    /// slice; this slice only counts.
    data_seen: Cell<usize>,
    /// A `routers_net` spanning-tree recompute is pending (D2c coalescing flag).
    /// zenoh runs a SEPARATE `TreesComputationWorker` per net; wz coalesces both
    /// nets onto the one [`tick`](FaceForwarder::tick) cadence the trait seam
    /// offers, with one dirty flag per net (a functional-equivalent
    /// simplification of the two independent debounce workers).
    trees_dirty_routers: Cell<bool>,
    /// A `linkstatepeers_net` spanning-tree recompute is pending (D2c).
    trees_dirty_peers: Cell<bool>,
    /// Total spanning-tree recomputes flushed across both nets — the D2c
    /// coalescing witness (rises once per flushed net per tick window).
    recomputes: Cell<usize>,
    /// The coalescing window the [`tick_period`](FaceForwarder::tick_period)
    /// reports — zenoh's `TREES_COMPUTATION_DELAY_MS`, shared with the
    /// linkstate forwarder's default.
    trees_delay: Duration,
}

impl RouterForwarder {
    /// The SPF-throttle coalescing window — the SAME default the single-net
    /// [`LinkstateForwarder`](crate::linkstate_forward::LinkstateForwarder)
    /// uses (zenoh's `TREES_COMPUTATION_DELAY_MS`), referenced rather than
    /// re-literal-ed so the two forwarders share one source of the value.
    pub const DEFAULT_TREES_DELAY: Duration =
        crate::linkstate_forward::LinkstateForwarder::DEFAULT_TREES_DELAY;

    /// A router driver seeded with the local node (`self_zid`). Self is a
    /// `WhatAmI::Router` in BOTH meshes, so both nets are constructed with
    /// [`WhatAmI::Router`].
    pub fn new(self_zid: Zid) -> Self {
        Self {
            routers_net: Rc::new(RefCell::new(LinkstateNetwork::new(
                self_zid,
                WhatAmI::Router,
            ))),
            linkstatepeers_net: Rc::new(RefCell::new(LinkstateNetwork::new(
                self_zid,
                WhatAmI::Router,
            ))),
            faces: RefCell::new(HashMap::new()),
            router_subs: RefCell::new(LinkstatepeerInterest::new()),
            linkstatepeer_subs: RefCell::new(LinkstatepeerInterest::new()),
            router_qabls: RefCell::new(LinkstatepeerInterest::new()),
            linkstatepeer_qabls: RefCell::new(LinkstatepeerInterest::new()),
            ingested: Cell::new(0),
            data_seen: Cell::new(0),
            trees_dirty_routers: Cell::new(false),
            trees_dirty_peers: Cell::new(false),
            recomputes: Cell::new(0),
            trees_delay: Self::DEFAULT_TREES_DELAY,
        }
    }

    /// The graph + coalescing flag for a tier, or `None` for
    /// [`FaceTier::Client`] (a client is a leaf, in no mesh). The single
    /// classifier `register` / `deregister` / `forward` route a face's work
    /// through, so the routers-vs-peers selection lives in ONE place.
    fn plane(&self, tier: FaceTier) -> Option<(&Rc<RefCell<LinkstateNetwork>>, &Cell<bool>)> {
        match tier {
            FaceTier::Routers => Some((&self.routers_net, &self.trees_dirty_routers)),
            FaceTier::LinkstatePeers => Some((&self.linkstatepeers_net, &self.trees_dirty_peers)),
            FaceTier::Client => None,
        }
    }

    /// Send to each held face of `tier` the message `build` produces for it,
    /// returning the count of faces that accepted one — the TIER-SCOPED fan-out
    /// SSOT. The `state.tier == tier` gate is the load-bearing router property
    /// (the module docs' CRITICAL note): a `routers_net` flood reaches only
    /// Router faces and a `linkstatepeers_net` flood only Peer faces, so the two
    /// nets' psid spaces never cross-inject. The single-net
    /// [`LinkstateForwarder`](crate::linkstate_forward) gates on a `gossip_target`
    /// role matcher instead, which CANNOT separate the router's two nets
    /// (`default_gossip_target(Router) == default_gossip_target(Peer)`), hence
    /// the router's own per-tier fan-out. Holds only the `faces` borrow; a
    /// builder may borrow a graph (a distinct cell). (Egress access control is
    /// deferred with the interceptor plane.)
    fn fan_out_tier(
        &self,
        tier: FaceTier,
        reliable: bool,
        mut build: impl FnMut(FaceId, Option<Zid>) -> Result<Option<NetworkMessage>, CodecError>,
    ) -> Result<usize, CodecError> {
        let mut sent = 0;
        for (id, state) in self.faces.borrow().iter() {
            if state.tier != tier {
                continue;
            }
            let peer_zid = peer_zid_routing(&state.actions);
            if let Some(msg) = build(*id, peer_zid)? {
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

    /// Flood self's GAINED-link event within `tier`'s net (the
    /// [`register`](FaceForwarder::register) path), the per-net mirror of
    /// [`LinkstateForwarder::register`]'s `flood_link_added`: the NEW face is
    /// bootstrapped with `net`'s FULL topology; every EXISTING face OF THE SAME
    /// TIER gets the minimal delta (the `[neighbour zid-only, self links-only]`
    /// pair when the neighbour is new to the graph, else just self's
    /// links-only); a parallel link to the same neighbour zid is skipped (it
    /// learns the change on its own bootstrap). Reliable (topology is control
    /// traffic).
    fn flood_link_added_tier(
        &self,
        new_face: FaceId,
        tier: FaceTier,
        net: &Rc<RefCell<LinkstateNetwork>>,
        neighbour: &Zid,
        neighbour_was_new: bool,
    ) -> Result<usize, CodecError> {
        let full = build_linkstate_oam_owned(&net.borrow().build_linkstate_list())?;
        let delta = {
            let n = net.borrow();
            let list = if neighbour_was_new {
                n.build_link_added_delta(neighbour)
            } else {
                n.build_self_links_delta()
            };
            build_linkstate_oam_owned(&list)?
        };
        self.fan_out_tier(tier, true, |id, zid| {
            if id == new_face {
                return Ok(Some(NetworkMessage::Oam(full.clone())));
            }
            if zid == Some(*neighbour) {
                return Ok(None);
            }
            Ok(Some(NetworkMessage::Oam(delta.clone())))
        })
    }

    /// Flood self's LOST-link event within `tier`'s net (the
    /// [`deregister`](FaceForwarder::deregister) path) — the per-net mirror of
    /// `flood_self_links_changed`: send the 1-entry `[self links-only]` delta to
    /// every surviving face of the tier so they drop the dead link from their
    /// topology at once (each receiver's own detached-node prune handles the
    /// rest). Reliable.
    fn flood_self_links_changed_tier(
        &self,
        tier: FaceTier,
        net: &Rc<RefCell<LinkstateNetwork>>,
    ) -> Result<usize, CodecError> {
        let oam = build_linkstate_oam_owned(&net.borrow().build_self_links_delta())?;
        self.fan_out_tier(tier, true, |_id, _zid| {
            Ok(Some(NetworkMessage::Oam(oam.clone())))
        })
    }

    /// Ingest a decoded `LinkStateList` that arrived on `face` against that
    /// face's link in `net` (its tier-net), returning the `Changes` the caller
    /// re-floods. The per-net mirror of `ingest_inbound_linkstate`; the
    /// spanning-tree recompute is COALESCED (D2c), not run here. (Autoconnect
    /// discovery is deferred with the gossip plane.)
    fn ingest_inbound_linkstate_tier(
        &self,
        face: FaceId,
        net: &Rc<RefCell<LinkstateNetwork>>,
        list: LinkstateListOwned,
    ) -> Changes {
        let link_id = match self.faces.borrow().get(&face).and_then(|s| s.link) {
            Some(id) => id,
            None => {
                log::debug!(
                    "dropping linkstate from face {} with no graph link (no routing zid)",
                    face.0
                );
                return Changes::default();
            }
        };
        let changes = net.borrow_mut().ingest_linkstate_list(link_id, list);
        self.ingested.set(self.ingested.get() + 1);
        changes
    }

    /// Re-flood the nodes an ingest changed to every OTHER face of `tier`
    /// (excluding the inbound face and, per face, the node whose own state it
    /// is) — the per-net, tier-scoped mirror of `propagate`. This carries
    /// topology transitively across a multi-hop mesh WITHIN one tier; the
    /// inter-tier bridge (a node learned on one net advertised onto the other)
    /// is the COMPUTE slice's cross-tier concern, not a within-net re-flood.
    fn propagate_tier(
        &self,
        source: FaceId,
        tier: FaceTier,
        net: &Rc<RefCell<LinkstateNetwork>>,
        changes: &Changes,
    ) -> Result<usize, CodecError> {
        if changes.new.is_empty() && changes.updated.is_empty() {
            return Ok(0);
        }
        self.fan_out_tier(tier, true, |id, zid| {
            if id == source {
                return Ok(None);
            }
            let keep = |z: &&Zid| zid != Some(**z);
            let new: Vec<Zid> = changes.new.iter().filter(keep).cloned().collect();
            let updated: Vec<Zid> = changes.updated.iter().filter(keep).cloned().collect();
            if new.is_empty() && updated.is_empty() {
                return Ok(None);
            }
            let oam =
                build_linkstate_oam_owned(&net.borrow().build_linkstate_split(&new, &updated))?;
            Ok(Some(NetworkMessage::Oam(oam)))
        })
    }

    /// Purge every node in `removed` from BOTH interest tables OF `tier` — the
    /// per-tier mirror of `purge_detached_interest`, called on a link-down (the
    /// `remove_link` detached set) and on an ingest that detached nodes. A gone
    /// node's interest must not keep a route gate spuriously armed. The tables
    /// are empty until slice 1b populates them, so this is a structural no-op
    /// now; it is wired here so 1b adds INGEST without re-touching `deregister`
    /// / `forward`. No-op for [`FaceTier::Client`] (no tier tables).
    fn purge_detached_interest_tier(&self, tier: FaceTier, removed: &[Zid]) {
        if removed.is_empty() {
            return;
        }
        let (subs, qabls) = match tier {
            FaceTier::Routers => (&self.router_subs, &self.router_qabls),
            FaceTier::LinkstatePeers => (&self.linkstatepeer_subs, &self.linkstatepeer_qabls),
            FaceTier::Client => return,
        };
        let mut subs = subs.borrow_mut();
        let mut qabls = qabls.borrow_mut();
        for zid in removed {
            subs.remove_peer(zid);
            qabls.remove_peer(zid);
        }
    }
}

impl FaceForwarder for RouterForwarder {
    fn register(&self, id: FaceId, actions: &Arc<SessionLinkActions>) {
        // Classify the face by its handshake role (zenoh's
        // `new_transport_unicast_face` whatami branch): a Router/Peer face with
        // a routing zid joins the matching net; a Client face — or one whose
        // zid never surfaced — is HELD without a graph link (it routes nothing).
        let whatami = peer_whatami_routing(actions);
        let tier = tier_of(whatami);
        let added = match self.plane(tier) {
            Some((net, _dirty)) => peer_zid_routing(actions).map(|neighbour| {
                let mut net = net.borrow_mut();
                // Whether this neighbour is NEW to the GRAPH (not merely a new
                // face): a second link to a known peer re-advertises only self's
                // links — zenoh add_link's `new` flag. Queried before add_link,
                // under the one borrow.
                let neighbour_was_new = net.get_node(&neighbour).is_none();
                let link = net.add_link(neighbour, whatami);
                (link, neighbour, neighbour_was_new)
            }),
            // Client tier: held with no net (a leaf, not a transit node).
            None => None,
        };
        self.faces.borrow_mut().insert(
            id,
            RouterFaceState {
                actions: actions.clone(),
                tier,
                link: added.map(|(link, _, _)| link),
            },
        );
        // Self gained a routing link in this tier's net (its link-state changed):
        // bootstrap the new face + delta the existing same-tier faces NOW
        // (event-driven), and SCHEDULE that net's recompute (coalesced onto the
        // tick). A held-without-identity face changed no link-state, so it
        // triggers no flood.
        if let Some((_, neighbour, neighbour_was_new)) = added {
            if let Some((net, dirty)) = self.plane(tier) {
                let _ = self.flood_link_added_tier(id, tier, net, &neighbour, neighbour_was_new);
                dirty.set(true);
            }
        }
    }

    fn deregister(&self, id: FaceId) {
        let Some(state) = self.faces.borrow_mut().remove(&id) else {
            return;
        };
        let tier = state.tier;
        let Some(link) = state.link else {
            // A held-without-identity face (Client, or no routing zid) changed
            // no link-state; nothing to disconnect or re-flood.
            return;
        };
        let Some((net, dirty)) = self.plane(tier) else {
            return;
        };
        // Drop the dead edge from the tier's graph; GC-prune detaches it
        // returns, and purge each pruned node's interest from THAT tier's
        // tables (a neighbour still reachable via another face keeps its
        // interest — only the genuinely detached set is purged).
        let removed = net.borrow_mut().remove_link(link);
        self.purge_detached_interest_tier(tier, &removed);
        // Self LOST a link in this tier: flood its updated links-only entry to
        // the surviving same-tier faces, and coalesce the recompute onto the
        // tick.
        let _ = self.flood_self_links_changed_tier(tier, net);
        dirty.set(true);
    }

    /// `Some(self.trees_delay)`: the router DOES tick — it flushes the coalesced
    /// per-net spanning-tree recomputes (D2c). Without this override the trait
    /// default `None` would never arm the timer and [`tick`](Self::tick) would
    /// be dead.
    fn tick_period(&self) -> Option<Duration> {
        Some(self.trees_delay)
    }

    fn tick(&self) {
        // Flush each net's coalesced recompute, if one accumulated. zenoh runs
        // two independent debounce workers; wz coalesces both onto this one tick
        // (two dirty flags, one flush pass) — functionally equivalent. Slice 1a
        // recomputes the trees but does NOT re-advertise interest to new tree
        // children (the re-advertise + cross-tier bubble is slice 1b), so the
        // new-children delta is discarded here.
        if self.trees_dirty_routers.replace(false) {
            let _ = self.routers_net.borrow_mut().compute_trees();
            self.recomputes.set(self.recomputes.get() + 1);
        }
        if self.trees_dirty_peers.replace(false) {
            let _ = self.linkstatepeers_net.borrow_mut().compute_trees();
            self.recomputes.set(self.recomputes.get() + 1);
        }
    }

    /// `true`: both meshes key the self-edge on the peer zid (a
    /// [`LinkstateNetwork`] property), so the router must hold AT MOST ONE face
    /// per zid — two faces to one peer would give a net two links for one zid,
    /// and either teardown's `remove_link` (keyed on zid) would prune the
    /// still-live peer. The loop enforces it by dropping a redundant second
    /// face at establishment (zenoh's one-transport-per-zid). A Client face
    /// without a surfaced zid is simply never deduped — consistent.
    fn dedups_faces_by_zid(&self) -> bool {
        true
    }

    fn forward(&self, id: FaceId, event: IterationEvent<'_>) {
        let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event else {
            return;
        };
        // The inbound face's tier selects which net topology ingests into and
        // which faces a re-flood reaches. Read once; the borrow is released
        // before the per-message work re-borrows `faces`.
        let tier = {
            let faces = self.faces.borrow();
            match faces.get(&id) {
                Some(s) => s.tier,
                None => return,
            }
        };
        for message in messages {
            match message {
                // A topology link-state: ingest into the INBOUND tier's net,
                // re-flood the changed nodes onward to the SAME tier, purge the
                // interest of any detached node, and coalesce that net's
                // recompute. A Client face has no net, so it carries no topology.
                NetworkMessage::Oam(oam) => {
                    if let Some((net, dirty)) = self.plane(tier) {
                        match try_parse_linkstate_oam(oam) {
                            LinkstateOam::Decoded(list) => {
                                let changes = self.ingest_inbound_linkstate_tier(id, net, list);
                                let _ = self.propagate_tier(id, tier, net, &changes);
                                self.purge_detached_interest_tier(tier, &changes.removed);
                                dirty.set(true);
                            }
                            LinkstateOam::Malformed(_) | LinkstateOam::NotLinkstate => {}
                        }
                    }
                }
                // A data Push: count the reception (the data-plane witness). The
                // tree fan-out + cross-net data route is the COMPUTE slice; this
                // slice routes nothing (the count-only deferral, pinned by a
                // test asserting no face received it).
                NetworkMessage::Push(_) => {
                    self.data_seen.set(self.data_seen.get() + 1);
                }
                // Declare INGEST (dual-tier interest + cross-tier bubble) is
                // slice 1b; the Request/Response query plane is the COMPUTE
                // slice. Left alone here.
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
        Zid::from_slice(&[b, b, b, b])
    }

    /// A recording-actions face whose remote peer zid is `peer` and whose
    /// handshake whatami is the 2-bit INIT wire form `wire_whatami`
    /// (Router=0b00, Peer=0b01, Client=0b10), so `register` classifies it into
    /// the matching tier. Returns the sink so a test can assert the frames the
    /// face received.
    fn face(peer: Zid, wire_whatami: u8) -> (Arc<SessionLinkActions>, Arc<RecordingLinkDriver>) {
        let (actions, sink) = recording_actions();
        TokioRuntime::with_mutex_mut(&actions.remote_peer_zid, |s| {
            *s = Some(peer.as_slice().to_vec())
        });
        TokioRuntime::with_mutex_mut(&actions.peer_whatami, |s| *s = Some(wire_whatami));
        (actions, sink)
    }

    const WIRE_ROUTER: u8 = 0b00;
    const WIRE_PEER: u8 = 0b01;
    const WIRE_CLIENT: u8 = 0b10;

    /// One LinkState entry (psid-space, with the psids it links to). Unlike the
    /// linkstate forwarder's direct-ingest `entry` (which can leave `options`
    /// 0), this one is encoded into an OAM ZBuf and decoded back, so `options`
    /// MUST flag the present optional fields: `OPT_P` (zid) | `OPT_W` (whatami).
    /// Otherwise the encoder writes the zid bytes the decoder then skips, and
    /// the OAM parses as `Malformed`.
    fn entry(psid: u64, sn: u64, node: u8, links: &[u64]) -> LinkstateOwned {
        const OPT_P: u8 = 0x01; // zid present (wz_routing_graph OPT_P)
        const OPT_W: u8 = 0x02; // whatami present (wz_routing_graph OPT_W)
        LinkstateOwned {
            options: OPT_P | OPT_W,
            psid,
            sn,
            zid_len: Some(4),
            zid: Some(SceBytes::from_slice(zid(node).as_slice()).unwrap()),
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

    /// Drive `forward` with a single inbound message on `face`.
    fn forward_one(fwd: &RouterForwarder, face: FaceId, message: NetworkMessage) {
        let outcome = DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: vec![message],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(face, IterationEvent::Poll(&outcome));
    }

    /// Ingest (through `forward`) on `face` a 3-entry flood that DISCOVERS a
    /// distant `node` reachable self <-> `neighbour` <-> `node` — the proven
    /// discovery shape (mirrors the linkstate forwarder's `discover_distant`).
    fn discover_via(
        fwd: &RouterForwarder,
        face: FaceId,
        self_z: u8,
        neighbour: u8,
        node: u8,
        psid_node: u64,
        sn: u64,
    ) {
        let oam = build_linkstate_oam_owned(&list(vec![
            entry(0, 1, self_z, &[]),                 // self mapping (stale-gated)
            entry(psid_node, sn, node, &[1]),         // the distant node -> neighbour
            entry(1, sn, neighbour, &[0, psid_node]), // neighbour -> self + node
        ]))
        .expect("build oam");
        forward_one(fwd, face, NetworkMessage::Oam(oam));
    }

    #[test]
    fn register_router_face_lands_in_routers_net() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sink) = face(zid(0xAA), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        // self + 0xAA in routers_net; only self in linkstatepeers_net.
        assert_eq!(fwd.routers_net.borrow().node_count(), 2);
        assert!(fwd.routers_net.borrow().get_node(&zid(0xAA)).is_some());
        assert_eq!(fwd.linkstatepeers_net.borrow().node_count(), 1);
        assert_eq!(fwd.faces.borrow()[&FaceId(0)].tier, FaceTier::Routers);
    }

    #[test]
    fn register_peer_face_lands_in_peers_net() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (b, _sink) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &b);
        assert_eq!(fwd.linkstatepeers_net.borrow().node_count(), 2);
        assert!(fwd
            .linkstatepeers_net
            .borrow()
            .get_node(&zid(0xBB))
            .is_some());
        assert_eq!(fwd.routers_net.borrow().node_count(), 1);
        assert_eq!(
            fwd.faces.borrow()[&FaceId(0)].tier,
            FaceTier::LinkstatePeers
        );
    }

    #[test]
    fn register_client_face_is_held_with_no_net() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (c, _sink) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &c);
        // A client is a leaf: held in `faces` but in neither mesh.
        assert!(fwd.faces.borrow().contains_key(&FaceId(0)));
        assert_eq!(fwd.faces.borrow()[&FaceId(0)].tier, FaceTier::Client);
        assert_eq!(fwd.faces.borrow()[&FaceId(0)].link, None);
        assert_eq!(fwd.routers_net.borrow().node_count(), 1);
        assert_eq!(fwd.linkstatepeers_net.borrow().node_count(), 1);
    }

    #[test]
    fn register_router_face_without_zid_is_held_without_a_link() {
        let fwd = RouterForwarder::new(zid(0x01));
        // A router-role face whose routing zid never surfaced: tier Routers, but
        // held without a graph link (the `added == None` path).
        let (actions, _sink) = recording_actions();
        TokioRuntime::with_mutex_mut(&actions.peer_whatami, |s| *s = Some(WIRE_ROUTER));
        fwd.register(FaceId(0), &actions);
        assert_eq!(fwd.faces.borrow()[&FaceId(0)].tier, FaceTier::Routers);
        assert_eq!(fwd.faces.borrow()[&FaceId(0)].link, None);
        assert_eq!(
            fwd.routers_net.borrow().node_count(),
            1,
            "no neighbour added"
        );
    }

    #[test]
    fn oam_ingest_routes_to_the_inbound_tier_net() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sink) = face(zid(0xAA), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        assert_eq!(fwd.routers_net.borrow().node_count(), 2); // self + 0xAA
                                                              // A flood on the ROUTER face discovers 0xDD into the routers tier only.
        discover_via(&fwd, FaceId(0), 0x01, 0xAA, 0xDD, 3, 5);
        assert_eq!(fwd.ingested.get(), 1, "the OAM was ingested");
        assert_eq!(
            fwd.routers_net.borrow().node_count(),
            3,
            "0xDD discovered in the routers tier (self + 0xAA + 0xDD)"
        );
        assert_eq!(
            fwd.linkstatepeers_net.borrow().node_count(),
            1,
            "the peers tier is untouched by a routers-tier flood"
        );
    }

    #[test]
    fn flood_is_tier_scoped() {
        // The CRITICAL property: a routers_net flood reaches only Router faces,
        // never a Peer face (the two nets never cross-inject).
        let fwd = RouterForwarder::new(zid(0x01));
        let (a_r, sink_r) = face(zid(0xAA), WIRE_ROUTER);
        let (a_p, sink_p) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &a_r);
        fwd.register(FaceId(1), &a_p);
        sink_r.reset();
        sink_p.reset();
        // A SECOND router joins -> floods the routers tier (the existing router
        // face sees self's link delta; the peer face must see nothing).
        let (a_r2, _sink_r2) = face(zid(0xCC), WIRE_ROUTER);
        fwd.register(FaceId(2), &a_r2);
        assert!(
            sink_r.frame_count() > 0,
            "the existing router face sees the routers_net flood"
        );
        assert_eq!(
            sink_p.frame_count(),
            0,
            "the peer face is NOT cross-injected with a routers_net flood"
        );
    }

    #[test]
    fn tick_coalesces_both_nets_independently() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (a_r, _s1) = face(zid(0xAA), WIRE_ROUTER);
        let (a_p, _s2) = face(zid(0xBB), WIRE_PEER);
        // Each register schedules its net's recompute (D2c dirty flag).
        fwd.register(FaceId(0), &a_r);
        fwd.register(FaceId(1), &a_p);
        assert_eq!(
            fwd.recomputes.get(),
            0,
            "register only SCHEDULES, never recomputes inline"
        );
        assert!(fwd.trees_dirty_routers.get());
        assert!(fwd.trees_dirty_peers.get());
        fwd.tick();
        // Both nets had a pending change -> one recompute each, flags cleared.
        assert_eq!(fwd.recomputes.get(), 2);
        assert!(!fwd.trees_dirty_routers.get());
        assert!(!fwd.trees_dirty_peers.get());
        // An idle tick is a no-op poll.
        fwd.tick();
        assert_eq!(fwd.recomputes.get(), 2, "an idle window adds no recompute");
    }

    #[test]
    fn push_is_counted_not_routed() {
        // The count-only deferral: a Push raises the reception witness but is
        // routed NOWHERE this slice (pinned: no other face receives it).
        let fwd = RouterForwarder::new(zid(0x01));
        let (a_r, sink_r) = face(zid(0xAA), WIRE_ROUTER);
        let (a_p, sink_p) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &a_r);
        fwd.register(FaceId(1), &a_p);
        sink_r.reset();
        sink_p.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push)));
        assert_eq!(fwd.data_seen.get(), 1, "the Push is counted");
        assert_eq!(
            sink_r.frame_count(),
            0,
            "not routed back to the inbound face"
        );
        assert_eq!(
            sink_p.frame_count(),
            0,
            "not routed to any other face (no route compute yet)"
        );
    }

    #[test]
    fn deregister_removes_the_link_from_its_tier_net() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sink) = face(zid(0xAA), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        assert_eq!(fwd.routers_net.borrow().node_count(), 2);
        fwd.deregister(FaceId(0));
        assert!(!fwd.faces.borrow().contains_key(&FaceId(0)), "face dropped");
        assert!(
            fwd.routers_net.borrow().get_node(&zid(0xAA)).is_none(),
            "the departed neighbour's link is removed from routers_net"
        );
    }

    #[test]
    fn dedups_faces_by_zid_is_true() {
        let fwd = RouterForwarder::new(zid(0x01));
        assert!(
            fwd.dedups_faces_by_zid(),
            "a dual-mesh router keys topology on zid, so one face per zid"
        );
    }

    #[test]
    fn propagate_floods_same_tier_only() {
        // The OAM re-flood (`propagate_tier`) reaches OTHER same-tier faces but
        // never the other net's faces — the load-bearing multi-hop path, proven
        // tier-scoped (the single-face OAM test above never reaches a 2nd face).
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sa) = face(zid(0xAA), WIRE_ROUTER); // source router
        let (b, sink_b) = face(zid(0xBB), WIRE_ROUTER); // same-tier router (target)
        let (p, sink_p) = face(zid(0xCC), WIRE_PEER); // peer (must NOT receive)
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &b);
        fwd.register(FaceId(2), &p);
        sink_b.reset();
        sink_p.reset();
        // An OAM on A discovers a distant node -> propagated to the other router
        // (B, not the source), never to the peer face.
        discover_via(&fwd, FaceId(0), 0x01, 0xAA, 0xDD, 3, 5);
        assert!(
            sink_b.frame_count() > 0,
            "the other router face receives the propagated topology delta"
        );
        assert_eq!(
            sink_p.frame_count(),
            0,
            "the peer face is NOT reached by a routers-tier propagate"
        );
    }

    #[test]
    fn oam_on_a_peer_face_routes_to_the_peers_tier() {
        // The reverse direction of `oam_ingest_routes_to_the_inbound_tier_net`:
        // an OAM on a PEER face ingests into linkstatepeers_net, not routers_net.
        let fwd = RouterForwarder::new(zid(0x01));
        let (p, _sink) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &p);
        assert_eq!(fwd.linkstatepeers_net.borrow().node_count(), 2); // self + 0xBB
        discover_via(&fwd, FaceId(0), 0x01, 0xBB, 0xEE, 3, 5);
        assert_eq!(fwd.ingested.get(), 1);
        assert_eq!(
            fwd.linkstatepeers_net.borrow().node_count(),
            3,
            "0xEE discovered in the peers tier (self + 0xBB + 0xEE)"
        );
        assert_eq!(
            fwd.routers_net.borrow().node_count(),
            1,
            "the routers tier is untouched by a peers-tier flood"
        );
    }

    #[test]
    fn deregister_floods_only_the_surviving_same_tier() {
        // A departing router floods its lost-link delta to the surviving router
        // face only — the peer face is never reached (deregister flood is
        // tier-scoped, like the register flood).
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sa) = face(zid(0xAA), WIRE_ROUTER);
        let (b, sink_b) = face(zid(0xBB), WIRE_ROUTER);
        let (p, sink_p) = face(zid(0xCC), WIRE_PEER);
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &b);
        fwd.register(FaceId(2), &p);
        sink_b.reset();
        sink_p.reset();
        fwd.deregister(FaceId(0));
        assert!(
            sink_b.frame_count() > 0,
            "the surviving router face sees the lost-link delta"
        );
        assert_eq!(
            sink_p.frame_count(),
            0,
            "the peer face is NOT reached by a routers-tier deregister flood"
        );
    }

    #[test]
    fn register_relink_to_an_oam_known_node_does_not_duplicate() {
        // A node first learned via OAM, then reached by a DIRECT face: the
        // `neighbour_was_new == false` arm of `flood_link_added_tier` (the
        // build_self_links_delta path). The node must not be duplicated in the
        // graph, and the new direct face is still bootstrapped with the topology.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sa) = face(zid(0xAA), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        discover_via(&fwd, FaceId(0), 0x01, 0xAA, 0xDD, 3, 5);
        assert_eq!(fwd.routers_net.borrow().node_count(), 3); // self + AA + DD (via OAM)
        let (d, sink_d) = face(zid(0xDD), WIRE_ROUTER);
        fwd.register(FaceId(1), &d);
        assert_eq!(
            fwd.routers_net.borrow().node_count(),
            3,
            "0xDD was already a graph node via OAM; the direct link adds no node"
        );
        assert!(
            sink_d.frame_count() > 0,
            "the new direct face is bootstrapped with the routers topology"
        );
    }
}
