// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Router-hat forwarder (P4 §5.21 — DUAL-mesh STATE + declare INGEST (1a-1c) +
//! within-tier data route + tick re-advertise (C1)).
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
//! ## Slice 1a (topology STATE)
//!
//! This is the CONTROL-PLANE TOPOLOGY half, mirroring how the peer
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
//! ## Slices 1b + 1c (declare INGEST) — landed
//!
//! `forward` ingests a sourced `DeclareSubscriber` into the INBOUND face's tier
//! subs table (`router_subs` for a Router face, `linkstatepeer_subs` for a Peer
//! face), keyed by the resolve-source-resolved SOURCE zid, and — only on a real
//! change — re-floods a clean literal declaration WITHIN THAT TIER to the
//! source's spanning-tree children (the per-tier analogue of
//! [`LinkstateForwarder`]'s `forward_subscription`). `UndeclareSubscriber`
//! withdraws + re-floods the retraction the same way; a `DeclKexpr` / `UndeclKexpr`
//! records the link-local keyexpr alias so an aliased declaration resolves.
//!
//! The **cross-tier bubble** is NOT stored here. zenoh STORES the local zid into
//! the other tier's set when a cross-tier source exists; wz instead DERIVES that
//! at route-compute time from the native tier tables (the COMPUTE slice's
//! `cross_tier_self_source(ke, tier)`), the same "filter / project on read"
//! normalization [`LinkstatepeerInterest`] already uses for the self-exclusion.
//! Storing it is behaviorally equivalent (a stored set == natives ∪ {self}
//! whenever the other tier has a native) but would force zenoh's four
//! reverse-forget teardown sites; deriving makes that drift
//! unrepresentable-by-construction (R311y109 design panel). So the ingest stores
//! ONLY natives, which its own readers (`purge_detached_interest_tier`, future
//! interest-broker) want anyway.
//!
//! Slice 1c adds the QUERYABLE twin (`DeclareQueryable` → `router_qabls` /
//! `linkstatepeer_qabls`), keyed by source with VALUE = the declared
//! [`QueryableInfo`] (a NEW peer OR a changed info re-floods — the value-diff
//! gate), the re-flood carrying that info downstream. Its cross-tier bubble is a
//! MERGED info in zenoh (`local_router_qabl_info` / `local_peer_qabl_info`,
//! `complete = OR`, `distance = min`); like the sub bubble it is DERIVED at
//! compute from the NATIVE qabls, not stored. `UndeclareQueryable` stays deferred
//! (the wz-codecs body carries no keyexpr ext — the face-down purge is the safety
//! net until a codec atom adds it, as the sibling documents).
//!
//! ## Slice C1 (within-tier data route + tick re-advertise) — landed
//!
//! `forward` ROUTES a data `Push` WITHIN its inbound tier's mesh
//! ([`forward_push_tier`](RouterForwarder::forward_push_tier), the shared
//! [`compute_push_forward`] core on the tier's `(net, subs)` fanned out
//! tier-scoped) — a peer-sourced Push to peer-mesh subs, a router-sourced one to
//! router-mesh subs (zenoh's master-gate-free route blocks). The
//! [`tick`](FaceForwarder::tick) RE-ADVERTISES each tier's NATIVE subs + qabls to
//! the new tree children a recompute adds (the shared
//! [`re_advertise_interest_into`] per net). A `Push` is still COUNTED (the
//! reception witness); a Client-tier Push (no mesh) stays count-only.
//!
//! ## Slice C2 (client cross-tier subscription advertisement) — landed
//!
//! A CLIENT-face `DeclareSubscriber` lands in the per-face
//! [`client_subs`](RouterForwarder#structfield.client_subs) leaf store, and the
//! router ADVERTISES self's now-derived cross-tier interest into BOTH meshes — a
//! self-sourced `DeclareSubscriber` (node_id 0) flooded to self's tree children
//! ([`advertise_self_cross_tier_sub`](RouterForwarder::advertise_self_cross_tier_sub)),
//! re-derived on the tick for late-joining children
//! ([`re_advertise_self_cross_tier`](RouterForwarder::re_advertise_self_cross_tier))
//! — so a mesh publisher routes the keyexpr toward this router. This is
//! `cross_tier_self_source` in its client form (the single-router-meaningful
//! contributor; a router's `router_subs` is empty until routers federate).
//! DERIVE-not-STORE: `client_subs` is the SSOT, self is NOT registered in the tier
//! tables, and the derived self-source drives the ADVERTISEMENT / re-advertise
//! path ONLY — never a data forward-target set (which stays self-excluded). A
//! client face-down purges `client_subs` BEFORE `deregister`'s linkless
//! early-return (OBLIGATION 1) and withdraws any advertisement it was the last
//! client of.
//!
//! ## Slice C3 (cross-tier client data delivery) — landed
//!
//! A data `Push` is now DELIVERED to the CLIENT faces subscribing its keyexpr
//! ([`deliver_to_client_subscribers`](RouterForwarder::deliver_to_client_subscribers)),
//! re-literalized to the resolved keyexpr — CLOSING the advertise-then-blackhole:
//! a Push attracted toward this router by C2's client advertisement now reaches
//! the subscribing client. It runs for a Push from ANY source (excluding the
//! inbound face), so it covers mesh→client AND client→client. A client-sourced
//! Push reaching the MESH (client→peer, a self-sourced re-injection) and LOCAL
//! self-hosted delivery (a pure router hosts none) remain deferred.
//!
//! ## Deferred to later slices (named, not silently dropped)
//!
//! - **The client→mesh publish + router↔router federation + master-election** —
//!   C3 delivers mesh→client and client→client; a CLIENT-sourced Push reaching the
//!   MESH subs (client→peer, a self-sourced re-injection / publish) is the
//!   remaining client direction. The router↔router cross-tier DATA bridge (a Push
//!   from one tier delivered to the OTHER tier's subs) is MULTI-ROUTER, so it
//!   couples with `elect_router` (`shared_nodes` for the route master vs
//!   `get_router_links` per-peer — a real asymmetry) + the source-dimensioned
//!   route cache. A cross-tier data bridge MUST fail-fast fence `shared_nodes <= 1`
//!   until the election lands, else a 2nd router double-delivers. (The C2
//!   advertisement is NOT master-gated — every router advertises its own clients'
//!   interest.)
//! - **The client QABL store + `compute_query_route`** (`Request` / `Response`) —
//!   the query-plane twin of C2 (a client `DeclareQueryable` + its cross-tier
//!   advertisement carrying the merged `QueryableInfo`) plus the query route.
//! - **Gossip / autoconnect / interceptors / pending-query GC** — the
//!   per-net policy knobs the `LinkstateForwarder` carries; added as the
//!   router gains the corresponding plane. NOTE (impl-panel R311y113): the
//!   tier-scoped [`fan_out_tier`](RouterForwarder::fan_out_tier) applies NEITHER
//!   the egress-ACL `admit_outbound` gate NOR the `interceptor_dropped` witness
//!   the single-net `fan_out` applies, so a within-tier Push forward + the tick
//!   re-advertise reach a tree child a §5.16 egress-deny would drop. Silent in
//!   any config with no ACL wired (the router has no interceptor plane yet); this
//!   is the router↔single-net data-path parity obligation for the interceptor
//!   slice — the ONE place the router route is not yet at single-net parity.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use sce_forge_runtime::codec::CodecError;

use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant};
use wz_codecs::linkstate_list::LinkstateListOwned;
use wz_codecs::push::PushOwned;
use wz_codecs::wireexpr::WireexprOwned;
use wz_routing_graph::{Changes, LinkId, LinkstateNetwork, WhatAmI, Zid};
use wz_session_core::declare_build::{
    build_declare_subscriber, build_undeclare_subscriber_with_keyexpr,
};
use wz_session_core::declare_ext_keyexpr::resolve_ext_keyexpr;
use wz_session_core::declare_routing_context::{read_declare_source, set_declare_source};
use wz_session_core::driver_loop::DriverLoopOutcome;
use wz_session_core::keyexpr_match::keyexpr_intersects_target;
use wz_session_core::linkstate_oam::{
    build_linkstate_oam_owned, try_parse_linkstate_oam, LinkstateOam,
};
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::push_build::reliteralize_push;
use wz_session_core::wireexpr_resolve::resolve_wireexpr;

use crate::accept_loop::{FaceForwarder, FaceId};
use crate::linkstate_forward::{
    absorb_keyexpr_into, build_declare_queryable_with_info, compute_push_forward,
    declare_queryable_wireexpr, declare_subscriber_wireexpr, is_tree_forward_target,
    peer_whatami_routing, peer_zid_routing, re_advertise_interest_into, resolve_source_in,
};
use crate::linkstate_interest::LinkstatepeerInterest;
use crate::session_glue::{IterationEvent, SessionLinkActions};
use wz_session_core::queryable_info::{read_queryable_info, QueryableInfo};

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
    /// Per-face keyexpr-alias table (1b): a `DeclKexpr` maps `id -> resolved
    /// keyexpr` here so a later aliased `DeclareSubscriber` on this link resolves
    /// to a literal. Link-local (each link negotiates its own aliases), the same
    /// shape as [`LinkstateForwarder`]'s `FaceState.keyexpr_table`
    /// (`hashbrown` to match `resolve_wireexpr`'s table type).
    keyexpr_table: hashbrown::HashMap<u64, String>,
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
    /// POPULATED by the subscription-INGEST slice (1b, this round): NATIVE
    /// Router sources keyed by their zid. The cross-tier self-bubble is NOT
    /// stored — it is DERIVED at route-compute from the native tables.
    router_subs: RefCell<LinkstatepeerInterest<()>>,
    /// Peer-tier subscription interest (zenoh `HatTables.linkstatepeer_subs`).
    /// Populated by slice 1b (native Peer sources keyed by zid).
    linkstatepeer_subs: RefCell<LinkstatepeerInterest<()>>,
    /// Router-tier queryable interest (zenoh `HatTables.router_qabls`).
    /// POPULATED by the queryable-INGEST slice (1c, this round): NATIVE Router
    /// queryable sources keyed by zid, VALUE = their declared `QueryableInfo`.
    /// The cross-tier self-bubble (a MERGED info in zenoh) is DERIVED at compute.
    router_qabls: RefCell<LinkstatepeerInterest<QueryableInfo>>,
    /// Peer-tier queryable interest (zenoh `HatTables.linkstatepeer_qabls`).
    /// Populated by slice 1c (native Peer queryable sources keyed by zid).
    linkstatepeer_qabls: RefCell<LinkstatepeerInterest<QueryableInfo>>,
    /// Per-CLIENT-face subscription store (C2) — zenoh's per-`Resource`
    /// `session_ctxs` leaf input, keyed by the client's [`FaceId`] (a Client face
    /// is HELD with no mesh, so its interest cannot live in a Zid-keyed tier
    /// table). This is the SSOT contributor to `cross_tier_self_source`: a client
    /// subscribing `K` makes SELF a virtual sub-source that is ADVERTISED into the
    /// meshes (a self-sourced `DeclareSubscriber` flooded to self's tree children,
    /// self NOT stored in the tier tables — derive-not-store), so a mesh publisher
    /// routes `K` toward this router. FaceId-keyed leaf state, so
    /// [`deregister`](FaceForwarder::deregister) MUST purge it BEFORE its linkless
    /// early-return (OBLIGATION 1). The cross-tier DATA delivery to these clients
    /// is a later slice; C2 is the ADVERTISEMENT half.
    client_subs: RefCell<HashMap<FaceId, HashSet<String>>>,
    /// Running total of link-state lists ingested across both nets — the
    /// control-plane work witness (the router twin of
    /// `LinkstateForwarder::ingested`).
    ingested: Cell<usize>,
    /// Running total of data `Push` messages received — the data-plane
    /// reception witness, raised on EVERY inbound Push (including a Client-tier
    /// one that routes nowhere within-tier). The WITHIN-tier fan-out that also
    /// consumes it is [`forward_push_tier`](RouterForwarder::forward_push_tier)
    /// (C1); the cross-tier bridge is a later slice (C2).
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
            client_subs: RefCell::new(HashMap::new()),
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
    /// node's interest must not keep a route gate spuriously armed. The subs
    /// tables are populated by 1b (this round) and the qabls tables by 1c; the
    /// purge covers BOTH so neither slice re-touches `deregister` / `forward`.
    /// No bubble teardown is needed: the cross-tier self-bubble is never stored
    /// (derived at compute), so a departed node leaves only its native entries —
    /// which this removes. No-op for [`FaceTier::Client`] (no tier tables).
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

    /// The subscription interest table for `tier`, or `None` for
    /// [`FaceTier::Client`] (the leaf/simple store is slice 1d).
    fn subs_table(&self, tier: FaceTier) -> Option<&RefCell<LinkstatepeerInterest<()>>> {
        match tier {
            FaceTier::Routers => Some(&self.router_subs),
            FaceTier::LinkstatePeers => Some(&self.linkstatepeer_subs),
            FaceTier::Client => None,
        }
    }

    /// The queryable interest table for `tier` (the query-plane twin of
    /// [`subs_table`](Self::subs_table)), or `None` for [`FaceTier::Client`].
    fn qabls_table(
        &self,
        tier: FaceTier,
    ) -> Option<&RefCell<LinkstatepeerInterest<QueryableInfo>>> {
        match tier {
            FaceTier::Routers => Some(&self.router_qabls),
            FaceTier::LinkstatePeers => Some(&self.linkstatepeer_qabls),
            FaceTier::Client => None,
        }
    }

    /// Record (or drop) a link-local keyexpr alias from a sourced `DeclKexpr` /
    /// `UndeclKexpr` on `face` (1b) — a thin `&self.faces`-borrow around the
    /// shared [`absorb_keyexpr_into`] SSOT (R311y111), which both forwarders use.
    /// Link-local: each link negotiates its own aliases (not re-flooded).
    fn absorb_keyexpr_declaration(&self, face: FaceId, declare: &DeclareOwned) {
        let mut faces = self.faces.borrow_mut();
        let Some(state) = faces.get_mut(&face) else {
            return;
        };
        absorb_keyexpr_into(&mut state.keyexpr_table, declare);
    }

    /// The SSOT for a sourced interest declaration (subscriber `V = ()` /
    /// queryable `V = QueryableInfo`) — the router twin of
    /// [`LinkstateForwarder`]'s `forward_interest_declaration`. Register the
    /// resolved SOURCE's interest (value `V`) in the inbound tier's `table`, and
    /// — only on a real change (the value-diff gate: a NEW peer OR a CHANGED
    /// value) — re-flood a clean declaration WITHIN that tier via `build`
    /// (re-stamped with this node's psid for the source). The cross-tier bubble
    /// is NOT stored (derived at compute). Only the wireexpr extractor, the
    /// `table`, the `value`, and the carrier `build` differ between the two
    /// planes; this holds everything they share (the alias-resolve +
    /// source-resolve + change-gate + re-flood), so neither plane re-hand-rolls
    /// it (the sibling factored the identical `V`-generic).
    #[allow(clippy::too_many_arguments)]
    fn ingest_interest<V: PartialEq>(
        &self,
        inbound: FaceId,
        tier: FaceTier,
        reliable: bool,
        declare: &DeclareOwned,
        wireexpr: &WireexprOwned,
        table: &RefCell<LinkstatepeerInterest<V>>,
        value: V,
        build: impl Fn(&str) -> Result<DeclareOwned, CodecError>,
    ) {
        let Some((net, _dirty)) = self.plane(tier) else {
            return; // Client tier: no net -> slice 1d (caller also guards on the table).
        };
        // Resolve the keyexpr against the inbound face's alias table + read its
        // zid / link, in one scoped borrow (an unresolvable alias drops it).
        let (inbound_zid, inbound_link, keyexpr) = {
            let faces = self.faces.borrow();
            let Some(s) = faces.get(&inbound) else {
                return;
            };
            let Some(keyexpr) = resolve_wireexpr(&wireexpr.body, &s.keyexpr_table) else {
                return;
            };
            (peer_zid_routing(&s.actions), s.link, keyexpr)
        };
        let Some((source_zid, out_node_id)) = resolve_source_in(
            &net.borrow(),
            inbound_zid,
            inbound_link,
            read_declare_source(declare),
        ) else {
            return;
        };
        // Register the SOURCE's native interest; re-flood ONLY on a real change
        // (the value-diff gate -- a new peer OR a changed value).
        if !table.borrow_mut().register(&keyexpr, source_zid, value) {
            return;
        }
        self.reflood_declaration(
            inbound,
            tier,
            net,
            source_zid,
            inbound_zid,
            out_node_id,
            reliable,
            &keyexpr,
            build,
        );
    }

    /// Ingest a sourced `DeclareSubscriber` (1b) — the `V = ()` case of
    /// [`ingest_interest`](Self::ingest_interest): register the SOURCE in the
    /// inbound tier's `subs` table (Router face -> `router_subs`, Peer face ->
    /// `linkstatepeer_subs`) + within-tier re-flood. A Client face (no tier
    /// table) is slice 1d.
    fn ingest_subscription(
        &self,
        inbound: FaceId,
        tier: FaceTier,
        reliable: bool,
        declare: &DeclareOwned,
    ) {
        let Some(wireexpr) = declare_subscriber_wireexpr(declare) else {
            return;
        };
        let Some(subs) = self.subs_table(tier) else {
            return; // Client tier -> slice 1d.
        };
        self.ingest_interest(inbound, tier, reliable, declare, wireexpr, subs, (), |ke| {
            build_declare_subscriber(0, 0, Some(ke))
        });
    }

    /// A sourced `UndeclareSubscriber` (1b): withdraw the SOURCE peer's interest
    /// from the INBOUND tier's subs table (the keyexpr rides the `ext_keyexpr`
    /// extension) and — only on a real removal — re-flood the retraction WITHIN
    /// that tier. The mirror of [`LinkstateForwarder`]'s `forward_unsubscription`;
    /// no bubble teardown (none is stored). A face-down purge is already covered
    /// by [`purge_detached_interest_tier`](Self::purge_detached_interest_tier).
    fn withdraw_subscription(
        &self,
        inbound: FaceId,
        tier: FaceTier,
        reliable: bool,
        declare: &DeclareOwned,
    ) {
        let exts = match &declare.body {
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(u) => u.extensions.as_ref(),
            _ => return,
        };
        let Some((net, _dirty)) = self.plane(tier) else {
            return;
        };
        let Some(subs) = self.subs_table(tier) else {
            return;
        };
        let (inbound_zid, inbound_link, keyexpr) = {
            let faces = self.faces.borrow();
            let Some(s) = faces.get(&inbound) else {
                return;
            };
            let Some(keyexpr) = resolve_ext_keyexpr(exts, &s.keyexpr_table) else {
                return;
            };
            (peer_zid_routing(&s.actions), s.link, keyexpr)
        };
        let Some((source_zid, out_node_id)) = resolve_source_in(
            &net.borrow(),
            inbound_zid,
            inbound_link,
            read_declare_source(declare),
        ) else {
            return;
        };
        if !subs.borrow_mut().withdraw(&keyexpr, &source_zid) {
            return;
        }
        self.reflood_declaration(
            inbound,
            tier,
            net,
            source_zid,
            inbound_zid,
            out_node_id,
            reliable,
            &keyexpr,
            build_undeclare_subscriber_with_keyexpr,
        );
    }

    /// Ingest a sourced `DeclareQueryable` (1c) — the query-plane twin of
    /// [`ingest_subscription`](Self::ingest_subscription). Register the SOURCE's
    /// queryable interest (VALUE = its declared [`QueryableInfo`], read off the
    /// DeclQueryable ext chain) in the INBOUND tier's qabls table, and — only on
    /// a real change (a NEW peer OR a CHANGED `QueryableInfo`, the value-diff
    /// gate) — re-flood a clean declaration CARRYING that info within the tier so
    /// a multi-hop relay learns the queryable's completeness. Like the sub
    /// bubble, the cross-tier bubble (a MERGED `local_*_qabl_info` in zenoh) is
    /// DERIVED at compute, not stored. `UndeclareQueryable` is deferred: the
    /// wz-codecs body carries no keyexpr ext (id only), so per-keyexpr retraction
    /// needs a codec extension first — the whole-peer face-down purge is the
    /// safety net until then (the same gap the sibling documents).
    fn ingest_queryable(
        &self,
        inbound: FaceId,
        tier: FaceTier,
        reliable: bool,
        declare: &DeclareOwned,
    ) {
        let Some(wireexpr) = declare_queryable_wireexpr(declare) else {
            return;
        };
        let Some(qabls) = self.qabls_table(tier) else {
            return; // Client tier -> slice 1d.
        };
        // The declared QueryableInfo (complete / distance) rides the DeclQueryable
        // body's ext chain; absent ext = zenoh DEFAULT (incomplete).
        let info = match &declare.body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(dq) => {
                read_queryable_info(dq.extensions.as_ref())
            }
            _ => QueryableInfo::DEFAULT,
        };
        // CARRY the source's QueryableInfo downstream on the re-flood (info is Copy).
        self.ingest_interest(
            inbound,
            tier,
            reliable,
            declare,
            wireexpr,
            qabls,
            info,
            move |ke| build_declare_queryable_with_info(ke, info),
        );
    }

    /// Re-flood a clean sourced declaration WITHIN `tier` to the source's
    /// spanning-tree children (excluding the inbound face + the source's own
    /// neighbour) — the per-tier re-forward shared by the subscribe + unsubscribe
    /// paths (only the `build` carrier differs). This is the within-net
    /// control-plane spread (the per-tier mirror of `forward_interest_declaration`'s
    /// re-flood tail); the CROSS-tier spread is derived at compute, not done here.
    /// `out_node_id` re-stamps the source's psid; the carrier is rebuilt as a
    /// LITERAL (id 0), the same B1b normalize the topology + data planes use.
    #[allow(clippy::too_many_arguments)]
    fn reflood_declaration(
        &self,
        inbound: FaceId,
        tier: FaceTier,
        net: &Rc<RefCell<LinkstateNetwork>>,
        source_zid: Zid,
        inbound_zid: Option<Zid>,
        out_node_id: u16,
        reliable: bool,
        keyexpr: &str,
        build: impl Fn(&str) -> Result<DeclareOwned, CodecError>,
    ) {
        let children = net.borrow().tree_children_of(&source_zid);
        if children.is_empty() {
            return;
        }
        let Ok(mut carrier) = build(keyexpr) else {
            return;
        };
        set_declare_source(&mut carrier, out_node_id);
        let _ = self.fan_out_tier(tier, reliable, |id, zid| {
            Ok(
                is_tree_forward_target(id, zid, inbound, inbound_zid, &children)
                    .then(|| NetworkMessage::Declare(Box::new(carrier.clone()))),
            )
        });
    }

    /// Route a data `Push` WITHIN its inbound tier's mesh (C1) — the router twin
    /// of [`LinkstateForwarder::forward_push`], calling the shared
    /// [`compute_push_forward`] core on the INBOUND tier's `(net, subs)` and
    /// fanning the result out tier-scoped. This is the WITHIN-TIER half only: it
    /// maps to zenoh's non-cross-tier route blocks — a peer-sourced Push to
    /// peer-mesh subs, a router-sourced Push to router-mesh subs, both
    /// master-gate-free in `compute_data_route`. The CROSS-tier bridge (the
    /// derived self-bubble), local-client delivery, and master-election are later
    /// slices (C2/C3/C4). A [`FaceTier::Client`] Push has no mesh to route within,
    /// so it is only counted (the reception witness in [`forward`]). A drop
    /// (unresolvable source / no interested subscriber / hop-exhausted) is silent,
    /// as in the single-net path.
    fn forward_push_tier(&self, inbound: FaceId, tier: FaceTier, reliable: bool, push: &PushOwned) {
        let Some((net, _dirty)) = self.plane(tier) else {
            return; // Client tier: no mesh -> within-tier routes nowhere (C2/C3).
        };
        let Some(subs) = self.subs_table(tier) else {
            return;
        };
        // Resolve the keyexpr against the inbound face's alias table + read its
        // zid / link in one scoped borrow (an unresolvable alias drops the Push).
        let (inbound_zid, inbound_link, keyexpr) = {
            let faces = self.faces.borrow();
            let Some(s) = faces.get(&inbound) else {
                return;
            };
            let Some(keyexpr) = resolve_wireexpr(&push.keyexpr.body, &s.keyexpr_table) else {
                return;
            };
            (peer_zid_routing(&s.actions), s.link, keyexpr)
        };
        let Some((carrier, children)) =
            compute_push_forward(net, subs, inbound_zid, inbound_link, push, &keyexpr)
        else {
            return;
        };
        let _ = self.fan_out_tier(tier, reliable, |id, zid| {
            Ok(
                is_tree_forward_target(id, zid, inbound, inbound_zid, &children)
                    .then(|| NetworkMessage::Push(Box::new(carrier.clone()))),
            )
        });
    }

    /// Deliver a data `Push` to the CLIENT faces subscribing its keyexpr (C3) —
    /// the cross-tier data half that CLOSES the advertise-then-blackhole: a Push
    /// attracted toward this router by C2's client advertisement is now DELIVERED
    /// to the subscribing client(s), re-literalized to the resolved keyexpr (a
    /// client leaf shares no alias table). Runs for a Push from ANY source (a mesh
    /// peer OR a client), excluding the inbound face, so it covers mesh->client AND
    /// client->client. A client-sourced Push reaching the MESH (client->peer, a
    /// self-sourced re-injection) is a later slice; LOCAL self-hosted delivery is
    /// deferred (a pure router hosts no subscribers — that is the combined-node
    /// seam). Routes through the [`fan_out_tier`](Self::fan_out_tier) egress SSOT
    /// (`FaceTier::Client`) like every other router send, so it inherits the
    /// interceptor / egress-ACL gate once that plane lands on the seam (the y113
    /// obligation) rather than being a separate retrofit site.
    fn deliver_to_client_subscribers(&self, inbound: FaceId, reliable: bool, push: &PushOwned) {
        if self.client_subs.borrow().is_empty() {
            return;
        }
        // Resolve the keyexpr against the INBOUND face's alias table (a client leaf
        // stores the literal, so an aliased inbound must resolve to compare).
        let keyexpr = {
            let faces = self.faces.borrow();
            let Some(s) = faces.get(&inbound) else {
                return;
            };
            match resolve_wireexpr(&push.keyexpr.body, &s.keyexpr_table) {
                Some(k) => k,
                None => return,
            }
        };
        // Re-literalize once (payload / encoding / attachment preserved, literal
        // keyexpr for the client leaf); the fan-out clones it per matching client.
        let Ok(carrier) = reliteralize_push(push, &keyexpr) else {
            return;
        };
        // Deliver to each Client-tier face subscribing a keyexpr that INTERSECTS
        // the published K, excluding the inbound face (never echo a client's own
        // Push back to it). Wildcard-aware via the SAME `keyexpr_intersects_target`
        // SSOT the mesh data route reads through `interested_remote` — a client
        // subscribing `demo/**` must receive a `demo/data` Push, NOT just an exact
        // `demo/data` sub (exact `HashSet::contains` would silently blackhole every
        // wildcard client sub, re-opening the very gap C3 closes).
        let target_chunks: Vec<&str> = keyexpr.split('/').collect();
        let _ = self.fan_out_tier(FaceTier::Client, reliable, |id, _zid| {
            if id == inbound {
                return Ok(None);
            }
            let deliver = self.client_subs.borrow().get(&id).is_some_and(|keys| {
                keys.iter()
                    .any(|sub| keyexpr_intersects_target(sub, &target_chunks))
            });
            Ok(deliver.then(|| NetworkMessage::Push(Box::new(carrier.clone()))))
        });
    }

    /// Recompute `tier`'s spanning trees and re-advertise its NATIVE subscription
    /// and queryable interest to whatever NEW children the recompute produced
    /// (C1) — the per-tier mirror of [`LinkstateForwarder`]'s
    /// `recompute_and_advertise`, so a declaration made before a peer joined
    /// converges onto the new branch. Both tables re-advertise through the shared
    /// [`re_advertise_interest_into`] core bound to THIS tier's net (its psid
    /// space) and flooded tier-scoped. NATIVES ONLY: the cross-tier self-bubble
    /// is DERIVED at compute (C2), a distinct self-sourced declaration, so it
    /// re-advertises on its own path.
    fn recompute_and_advertise_tier(&self, tier: FaceTier) {
        let Some((net, _dirty)) = self.plane(tier) else {
            return;
        };
        let new_children = net.borrow_mut().compute_trees();
        self.recomputes.set(self.recomputes.get() + 1);
        if new_children.is_empty() {
            return;
        }
        if let Some(subs) = self.subs_table(tier) {
            re_advertise_interest_into(
                net,
                subs,
                &new_children,
                |ke, _: &()| build_declare_subscriber(0, 0, Some(ke)),
                |children, declare| self.flood_delta_tier(tier, children, declare),
            );
        }
        if let Some(qabls) = self.qabls_table(tier) {
            re_advertise_interest_into(
                net,
                qabls,
                &new_children,
                |ke, info: &QueryableInfo| build_declare_queryable_with_info(ke, *info),
                |children, declare| self.flood_delta_tier(tier, children, declare),
            );
        }
        // C2: also re-advertise self's DERIVED cross-tier subs (from client_subs)
        // to self's NEW tree children — the derive's OBLIGATION-2 re-advertise feed
        // (a distinct self-sourced declaration), so a late-joining mesh node learns
        // to route toward this router for a keyexpr a local client subscribes.
        self.re_advertise_self_cross_tier(tier, &new_children);
    }

    /// Flood a re-advertised declaration to a tree-recompute's NEW children within
    /// `tier` — the per-tier analogue of [`LinkstateForwarder`]'s
    /// `flood_to_children`. No inbound face to exclude: self is the re-advertise
    /// source, and the delta already names exactly the newly-gained children.
    fn flood_delta_tier(&self, tier: FaceTier, children: &[Zid], declare: &DeclareOwned) {
        let _ = self.fan_out_tier(tier, true, |_id, zid| {
            Ok(zid
                .filter(|z| children.contains(z))
                .map(|_| NetworkMessage::Declare(Box::new(declare.clone()))))
        });
    }

    /// Ingest a CLIENT-face `DeclareSubscriber` (C2) into the per-face
    /// [`client_subs`](Self#structfield.client_subs) store and — when it is the
    /// FIRST client interested in the keyexpr — ADVERTISE self's now-derived
    /// cross-tier interest into the meshes. The mesh-face declare path
    /// ([`ingest_subscription`](Self::ingest_subscription)) drops a Client-tier
    /// declare (no tier table); this is where the leaf input lands instead.
    fn ingest_client_subscription(&self, inbound: FaceId, declare: &DeclareOwned) {
        let Some(wireexpr) = declare_subscriber_wireexpr(declare) else {
            return;
        };
        let keyexpr = {
            let faces = self.faces.borrow();
            let Some(s) = faces.get(&inbound) else {
                return;
            };
            match resolve_wireexpr(&wireexpr.body, &s.keyexpr_table) {
                Some(k) => k,
                None => return,
            }
        };
        // The derive-level change gate: ADVERTISE only when this is the FIRST
        // client interested in `keyexpr` (the derive flips false -> true).
        let already = self.any_client_subscribes(&keyexpr);
        let inserted = self
            .client_subs
            .borrow_mut()
            .entry(inbound)
            .or_default()
            .insert(keyexpr.clone());
        if inserted && !already {
            self.advertise_self_cross_tier_sub(&keyexpr);
        }
    }

    /// Withdraw a CLIENT-face `UndeclareSubscriber` (C2) from
    /// [`client_subs`](Self#structfield.client_subs); when it removed the LAST
    /// client interested in the keyexpr, withdraw self's cross-tier advertisement.
    fn withdraw_client_subscription(&self, inbound: FaceId, declare: &DeclareOwned) {
        let exts = match &declare.body {
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(u) => u.extensions.as_ref(),
            _ => return,
        };
        let keyexpr = {
            let faces = self.faces.borrow();
            let Some(s) = faces.get(&inbound) else {
                return;
            };
            match resolve_ext_keyexpr(exts, &s.keyexpr_table) {
                Some(k) => k,
                None => return,
            }
        };
        let removed = {
            let mut store = self.client_subs.borrow_mut();
            let removed = store
                .get_mut(&inbound)
                .is_some_and(|set| set.remove(&keyexpr));
            // Prune an emptied set (the same prune discipline
            // [`LinkstatepeerInterest::withdraw`] uses), so a client that
            // unsubscribes everything does not defeat the `is_empty()` delivery
            // fast-path with a lingering empty entry.
            if store.get(&inbound).is_some_and(|set| set.is_empty()) {
                store.remove(&inbound);
            }
            removed
        };
        if removed && !self.any_client_subscribes(&keyexpr) {
            self.withdraw_self_cross_tier_sub(&keyexpr);
        }
    }

    /// Whether ANY client face currently subscribes `keyexpr` — the C2 derive read
    /// (`cross_tier_self_source` for the subscription plane). Self is a virtual
    /// sub-source in the meshes IFF this is true (or, once federation lands, the
    /// OTHER tier holds a native — always empty in a single router).
    fn any_client_subscribes(&self, keyexpr: &str) -> bool {
        self.client_subs
            .borrow()
            .values()
            .any(|set| set.contains(keyexpr))
    }

    /// The deduped set of keyexprs some client subscribes — self's DERIVED
    /// cross-tier sub-sources, re-advertised to a tier's NEW tree children on the
    /// tick ([`re_advertise_self_cross_tier`](Self::re_advertise_self_cross_tier)).
    fn derived_cross_tier_subs(&self) -> Vec<String> {
        let mut set: HashSet<String> = HashSet::new();
        for keys in self.client_subs.borrow().values() {
            set.extend(keys.iter().cloned());
        }
        set.into_iter().collect()
    }

    /// Flood self's cross-tier subscription ADVERTISEMENT for `keyexpr` into BOTH
    /// meshes — a self-sourced `DeclareSubscriber` (node_id 0) to self's tree
    /// children in each net, so a mesh publisher routes `keyexpr` toward this
    /// router. DERIVE-not-STORE: self is NOT registered in the tier tables; the
    /// [`client_subs`](Self#structfield.client_subs) store is the SSOT and the
    /// advertisement is re-derived on the tick for late-joining children. The
    /// router-mesh flood is a no-op in a single router (no router tree children)
    /// but keeps the two tiers symmetric for when routers federate.
    fn advertise_self_cross_tier_sub(&self, keyexpr: &str) {
        for tier in [FaceTier::Routers, FaceTier::LinkstatePeers] {
            self.flood_self_sourced(tier, keyexpr, |ke| build_declare_subscriber(0, 0, Some(ke)));
        }
    }

    /// Flood self's cross-tier WITHDRAWAL for `keyexpr` into BOTH meshes — the
    /// undeclare twin of
    /// [`advertise_self_cross_tier_sub`](Self::advertise_self_cross_tier_sub).
    fn withdraw_self_cross_tier_sub(&self, keyexpr: &str) {
        for tier in [FaceTier::Routers, FaceTier::LinkstatePeers] {
            self.flood_self_sourced(tier, keyexpr, build_undeclare_subscriber_with_keyexpr);
        }
    }

    /// Flood a self-sourced declaration for `keyexpr` (node_id 0) to self's tree
    /// children in `tier`'s net — the immediate advertisement/withdrawal seam.
    /// Mirrors [`LinkstateForwarder`]'s `declare_subscription` flood, but keyed on
    /// the DERIVED client interest, not a stored self-native.
    fn flood_self_sourced(
        &self,
        tier: FaceTier,
        keyexpr: &str,
        build: impl Fn(&str) -> Result<DeclareOwned, CodecError>,
    ) {
        let Some((net, _dirty)) = self.plane(tier) else {
            return;
        };
        let children = {
            let n = net.borrow();
            let self_zid = *n.self_zid();
            n.tree_children_of(&self_zid)
        };
        if children.is_empty() {
            return;
        }
        let Ok(declare) = build(keyexpr) else {
            return;
        };
        self.flood_delta_tier(tier, &children, &declare);
    }

    /// Re-advertise self's DERIVED cross-tier subscriptions to the tier's NEW tree
    /// children a recompute added (C2) — self is the source, so the flood targets
    /// the delta children of SELF's tree in this net. The tick counterpart of the
    /// immediate [`advertise_self_cross_tier_sub`](Self::advertise_self_cross_tier_sub),
    /// the OBLIGATION-2 feed of the re-advertise path with the DERIVED (not stored)
    /// self-source — distinct from the native re-advertise (native = real peer
    /// source; derived = self, node_id 0).
    fn re_advertise_self_cross_tier(&self, tier: FaceTier, new_children: &[(Zid, Vec<Zid>)]) {
        let Some((net, _dirty)) = self.plane(tier) else {
            return;
        };
        let self_zid = *net.borrow().self_zid();
        let Some((_, self_delta)) = new_children.iter().find(|(src, _)| *src == self_zid) else {
            return;
        };
        if self_delta.is_empty() {
            return;
        }
        for keyexpr in self.derived_cross_tier_subs() {
            let Ok(declare) = build_declare_subscriber(0, 0, Some(&keyexpr)) else {
                continue;
            };
            self.flood_delta_tier(tier, self_delta, &declare);
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
            Some((net, _dirty)) => {
                // OBLIGATION-3 self-zid parity: a face whose routing zid IS self's
                // own zid (a self-connect) is HELD without a link. Adding it would
                // insert a self entry into `node.links` that `make_link_state` then
                // emits as a spurious self-loop link (psid 0) onto the wire, plus
                // an sn bump real peers ingest — `rebuild_edges`'s `idx2 != idx1`
                // guard skips the petgraph self-EDGE but does NOT scrub that
                // `node.links` entry, so the self-loop still floods. zenoh relies
                // on its transport manager never handing `add_link` a
                // self-transport; wz guards it here (mirror in `LinkstateForwarder`).
                let self_zid = *net.borrow().self_zid();
                peer_zid_routing(actions)
                    .filter(|neighbour| *neighbour != self_zid)
                    .map(|neighbour| {
                        let mut net = net.borrow_mut();
                        // Whether this neighbour is NEW to the GRAPH (not merely a
                        // new face): a second link to a known peer re-advertises
                        // only self's links — zenoh add_link's `new` flag. Queried
                        // before add_link, under the one borrow.
                        let neighbour_was_new = net.get_node(&neighbour).is_none();
                        let link = net.add_link(neighbour, whatami);
                        (link, neighbour, neighbour_was_new)
                    })
            }
            // Client tier: held with no net (a leaf, not a transit node).
            None => None,
        };
        self.faces.borrow_mut().insert(
            id,
            RouterFaceState {
                actions: actions.clone(),
                tier,
                link: added.map(|(link, _, _)| link),
                keyexpr_table: hashbrown::HashMap::new(),
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
        // OBLIGATION-1: purge the FaceId-keyed client sub store BEFORE the linkless
        // early-return below (a Client face is `link == None`), withdrawing self's
        // cross-tier advertisement for any keyexpr this was the LAST client of.
        // Mirrors the sibling's `pending.remove_face`-first ordering; a Client face
        // is skipped by the peer/router fan-out (its tier), so flooding before its
        // `faces` entry is dropped is harmless.
        let departed = self.client_subs.borrow_mut().remove(&id);
        if let Some(keys) = departed {
            for keyexpr in keys {
                if !self.any_client_subscribes(&keyexpr) {
                    self.withdraw_self_cross_tier_sub(&keyexpr);
                }
            }
        }
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
        // Flush each net's coalesced recompute, if one accumulated, and
        // re-advertise that tier's NATIVE interest to whatever new tree children
        // the recompute produced (C1) — zenoh runs two independent debounce
        // workers; wz coalesces both onto this one tick (two dirty flags), each
        // flushing its OWN net. This fixes the prior slice's discard-the-delta
        // tick. The cross-tier self-bubble re-advertise is C2 (a distinct
        // self-sourced declaration on its own path).
        if self.trees_dirty_routers.replace(false) {
            self.recompute_and_advertise_tier(FaceTier::Routers);
        }
        if self.trees_dirty_peers.replace(false) {
            self.recompute_and_advertise_tier(FaceTier::LinkstatePeers);
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
        let IterationEvent::Poll(DriverLoopOutcome::FramePayload {
            messages, reliable, ..
        }) = event
        else {
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
                // A data Push: count the reception (the data-plane witness), then
                // route it WITHIN the inbound tier's mesh (C1, `forward_push_tier`
                // — a peer-sourced Push to peer-mesh subs, a router-sourced one to
                // router-mesh subs). The CROSS-tier bridge + local-client delivery
                // + master-election are later slices (C2/C3/C4); a Client-tier
                // Push has no mesh to route within, so it stays count-only.
                NetworkMessage::Push(push) => {
                    self.data_seen.set(self.data_seen.get() + 1);
                    self.forward_push_tier(id, tier, *reliable, push);
                    self.deliver_to_client_subscribers(id, *reliable, push);
                }
                // A declaration: ingest a DeclareSubscriber (1b) / DeclareQueryable
                // (1c) into the inbound tier's subs/qabls table + re-flood within
                // that tier; a keyexpr-alias declaration records the link-local
                // alias for resolution. A Client-face declare is slice 1d, the
                // cross-tier bubble is derived at compute, and the Request/Response
                // query plane is the COMPUTE slice.
                NetworkMessage::Declare(declare) => match &declare.body {
                    DeclareOwnedVariant::CodecZenohDeclKexpr(_)
                    | DeclareOwnedVariant::CodecZenohUndeclKexpr(_) => {
                        self.absorb_keyexpr_declaration(id, declare);
                    }
                    DeclareOwnedVariant::CodecZenohDeclSubscriber(_) => {
                        if tier == FaceTier::Client {
                            self.ingest_client_subscription(id, declare);
                        } else {
                            self.ingest_subscription(id, tier, *reliable, declare);
                        }
                    }
                    DeclareOwnedVariant::CodecZenohUndeclSubscriber(_) => {
                        if tier == FaceTier::Client {
                            self.withdraw_client_subscription(id, declare);
                        } else {
                            self.withdraw_subscription(id, tier, *reliable, declare);
                        }
                    }
                    DeclareOwnedVariant::CodecZenohDeclQueryable(_) => {
                        self.ingest_queryable(id, tier, *reliable, declare);
                    }
                    // UndeclareQueryable: deferred (the wz-codecs body carries no
                    // keyexpr ext -> per-keyexpr retraction needs a codec atom
                    // first; the face-down purge is the safety net, as the sibling
                    // documents). Dropped explicitly so it is NOT mis-routed.
                    DeclareOwnedVariant::CodecZenohUndeclQueryable(_) => {}
                    _ => {}
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

    /// Make `neighbour` (on `face`) advertise a link back to self, forming the
    /// mutual graph edge (mirror of the linkstate `advertise_link_back`). Fed
    /// through `forward`; the caller `tick()`s to flush the coalesced recompute.
    fn advertise_link_back(
        fwd: &RouterForwarder,
        face: FaceId,
        self_z: u8,
        neighbour: u8,
        sn: u64,
    ) {
        let oam = build_linkstate_oam_owned(&list(vec![
            entry(0, 1, self_z, &[]),      // self mapping (stale-gated)
            entry(1, sn, neighbour, &[0]), // neighbour -> self
        ]))
        .expect("build oam");
        forward_one(fwd, face, NetworkMessage::Oam(oam));
    }

    /// A literal `DeclareSubscriber` for `keyexpr` (id 0, no ext_nodeid — the
    /// inbound neighbour is the source).
    fn declare_sub(keyexpr: &str) -> NetworkMessage {
        NetworkMessage::Declare(Box::new(
            build_declare_subscriber(0, 0, Some(keyexpr)).expect("build declare"),
        ))
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
    fn push_to_an_unsubscribed_keyexpr_is_counted_but_not_routed() {
        // A Push on a keyexpr no in-tier peer subscribes to raises the reception
        // witness but forwards NOWHERE — `compute_push_forward` drops on the empty
        // interested set (the same drop the single-net path takes).
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
            "not routed to any face (no subscriber for the keyexpr)"
        );
    }

    #[test]
    fn push_routes_within_the_inbound_tier_only() {
        // A peer-sourced Push routes to peer-tier subscribers along the SOURCE's
        // tree (the within-tier data route, C1) — and NOT to a router-tier
        // subscriber of the SAME keyexpr (the cross-tier bridge is C2).
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER); // peer source
        let (c, sink_c) = face(zid(0xCC), WIRE_PEER); // peer subscriber (tree child)
        let (r, sink_r) = face(zid(0xDD), WIRE_ROUTER); // router-tier subscriber
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        fwd.register(FaceId(2), &r);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5); // peer edge self<->A
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5); // peer edge self<->C
        advertise_link_back(&fwd, FaceId(2), 0x01, 0xDD, 5); // router edge self<->R
        fwd.tick(); // compute both nets' spanning trees
        forward_one(&fwd, FaceId(1), declare_sub("demo/data")); // C (peer) subscribes
        forward_one(&fwd, FaceId(2), declare_sub("demo/data")); // R (router) subscribes
        sink_a.reset();
        sink_c.reset();
        sink_r.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push)));
        assert_eq!(fwd.data_seen.get(), 1, "the Push is counted");
        assert_eq!(
            sink_c.frame_count(),
            1,
            "routed to the peer-tier subscriber C along A's tree"
        );
        assert_eq!(sink_a.frame_count(), 0, "not back to the inbound source A");
        assert_eq!(
            sink_r.frame_count(),
            0,
            "NOT to the router-tier subscriber (cross-tier bridge is C2)"
        );
    }

    #[test]
    fn tick_re_advertises_a_native_sub_to_a_late_joining_child() {
        // A subscription learned before a peer joined converges onto the new tree
        // child when the tick recompute adds it — the per-tier re-advertise (C1),
        // fixing the prior slice's discard-the-new-children tick.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sa) = face(zid(0xAA), WIRE_PEER); // the sub's source
        let (c, sink_c) = face(zid(0xCC), WIRE_PEER); // joins AFTER the declare
        fwd.register(FaceId(0), &a);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_sub("demo/late")); // A subscribes; no C yet
        assert_eq!(
            fwd.linkstatepeer_subs.borrow().interested("demo/late"),
            vec![zid(0xAA)],
            "self learned A's interest before C joined"
        );
        // C joins + forms its edge, becoming a NEW child of A's tree.
        fwd.register(FaceId(1), &c);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 6);
        sink_c.reset();
        fwd.tick(); // recompute peers_net -> C is a new child -> re-advertise to it
        assert_eq!(
            sink_c.frame_count(),
            1,
            "A's subscription re-advertised to the late-joining child C"
        );
    }

    #[test]
    fn tick_re_advertises_a_native_queryable_to_a_late_joining_child() {
        // The queryable twin of the subscription re-advertise (C1): a queryable
        // learned before a peer joined converges onto the new tree child — the
        // SECOND table `recompute_and_advertise_tier` walks, pinned so the qabls
        // half of the tick re-advertise is not left composed-untested.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sa) = face(zid(0xAA), WIRE_PEER); // the queryable's source
        let (c, sink_c) = face(zid(0xCC), WIRE_PEER); // joins AFTER the declare
        fwd.register(FaceId(0), &a);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", true)); // A declares; no C
        assert_eq!(
            fwd.linkstatepeer_qabls.borrow().interested("demo/q"),
            vec![zid(0xAA)],
            "self learned A's queryable before C joined"
        );
        fwd.register(FaceId(1), &c);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 6);
        sink_c.reset();
        fwd.tick(); // recompute peers_net -> C new child -> re-advertise the qabl
        assert_eq!(
            sink_c.frame_count(),
            1,
            "A's queryable re-advertised to the late-joining child C"
        );
    }

    #[test]
    fn register_self_zid_face_is_held_without_a_link() {
        // OBLIGATION-3 self-zid parity: a face whose routing zid IS self's own zid
        // is HELD without a graph link — no self-loop is added to the net and no
        // spurious self-loop link-state is flooded.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0x01), WIRE_PEER); // routing zid == self
        fwd.register(FaceId(0), &a);
        let faces = fwd.faces.borrow();
        let st = faces.get(&FaceId(0)).expect("the face is still held");
        assert_eq!(
            st.link, None,
            "but with no graph link (self-connect guarded)"
        );
        assert_eq!(
            fwd.linkstatepeers_net.borrow().node_count(),
            1,
            "no self-loop neighbour added to the peer net (only self)"
        );
        assert_eq!(
            sink_a.frame_count(),
            0,
            "no self-loop link-state flooded to the face"
        );
    }

    #[test]
    fn push_routes_within_the_router_tier() {
        // The router-tier twin of the peer-tier data route (C1): a router-sourced
        // Push routes to router-mesh subscribers along the SOURCE's tree — and NOT
        // to a peer-tier subscriber of the same keyexpr (cross-tier isolation, the
        // router->peer direction).
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_ROUTER); // router source
        let (c, sink_c) = face(zid(0xCC), WIRE_ROUTER); // router subscriber (tree child)
        let (p, sink_p) = face(zid(0xDD), WIRE_PEER); // peer-tier subscriber
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        fwd.register(FaceId(2), &p);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5); // router edge self<->A
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5); // router edge self<->C
        advertise_link_back(&fwd, FaceId(2), 0x01, 0xDD, 5); // peer edge self<->P
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_sub("demo/data")); // C (router) subscribes
        forward_one(&fwd, FaceId(2), declare_sub("demo/data")); // P (peer) subscribes
        sink_a.reset();
        sink_c.reset();
        sink_p.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push)));
        assert_eq!(fwd.data_seen.get(), 1, "the Push is counted");
        assert_eq!(
            sink_c.frame_count(),
            1,
            "routed to the router-tier subscriber C along A's tree"
        );
        assert_eq!(sink_a.frame_count(), 0, "not back to the inbound source A");
        assert_eq!(
            sink_p.frame_count(),
            0,
            "NOT to the peer-tier subscriber (cross-tier bridge is C2)"
        );
    }

    #[test]
    fn client_face_push_is_counted_but_not_routed() {
        // A Push on a Client face (no mesh) is COUNTED (the reception witness) but
        // routes nowhere within-tier — `forward_push_tier`'s no-plane early-return.
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, sink_client) = face(zid(0xAA), WIRE_CLIENT);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &client);
        fwd.register(FaceId(1), &p);
        sink_client.reset();
        sink_p.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push)));
        assert_eq!(fwd.data_seen.get(), 1, "the Client Push is counted");
        assert_eq!(
            sink_client.frame_count(),
            0,
            "not routed back to the inbound face"
        );
        assert_eq!(
            sink_p.frame_count(),
            0,
            "a Client-tier Push has no mesh to route within"
        );
    }

    #[test]
    fn deregister_of_a_linkless_face_is_clean() {
        // A held-without-link face (a Client here) deregisters cleanly: removed
        // from `faces`, neither net touched, no panic — it hits the linkless
        // early-return with its FaceId-keyed state already dropped by the top
        // `faces.remove` (OBLIGATION-1's ordering, pinned for the linkless arm).
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, _sc) = face(zid(0xAA), WIRE_CLIENT);
        fwd.register(FaceId(0), &client);
        assert!(
            fwd.faces.borrow().contains_key(&FaceId(0)),
            "held before deregister"
        );
        fwd.deregister(FaceId(0));
        assert!(
            !fwd.faces.borrow().contains_key(&FaceId(0)),
            "removed on deregister"
        );
        assert_eq!(
            fwd.routers_net.borrow().node_count(),
            1,
            "routers_net untouched (only self)"
        );
        assert_eq!(
            fwd.linkstatepeers_net.borrow().node_count(),
            1,
            "peers_net untouched (only self)"
        );
    }

    /// A literal `UndeclareSubscriber` carrying `keyexpr` in its ext_keyexpr.
    fn undeclare_sub(keyexpr: &str) -> NetworkMessage {
        NetworkMessage::Declare(Box::new(
            build_undeclare_subscriber_with_keyexpr(keyexpr).expect("build undeclare"),
        ))
    }

    #[test]
    fn client_sub_advertises_self_interest_to_the_peer_mesh() {
        // A CLIENT subscribing K makes the router ADVERTISE self's cross-tier
        // interest into the peer mesh (a self-sourced DeclareSubscriber to a peer
        // tree child), so a peer publisher routes K toward this router (C2). Self
        // is NOT stored in the tier table (derive-not-store).
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, _cs) = face(zid(0xAA), WIRE_CLIENT);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER); // a peer tree child
        fwd.register(FaceId(0), &client);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5); // peer edge self<->P
        fwd.tick(); // compute the peer tree (P is self's child)
        sink_p.reset();
        forward_one(&fwd, FaceId(0), declare_sub("demo/data")); // client subscribes
        assert_eq!(
            sink_p.frame_count(),
            1,
            "self advertised its cross-tier interest to the peer child P"
        );
        assert!(
            fwd.linkstatepeer_subs
                .borrow()
                .interested("demo/data")
                .is_empty(),
            "derive-not-store: self is NOT registered in the peer subs table"
        );
    }

    #[test]
    fn a_second_client_for_the_same_keyexpr_does_not_re_advertise() {
        // The derive change-gate: self advertises only on the FIRST client for K.
        let fwd = RouterForwarder::new(zid(0x01));
        let (c1, _) = face(zid(0xAA), WIRE_CLIENT);
        let (c2, _) = face(zid(0xCC), WIRE_CLIENT);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &c1);
        fwd.register(FaceId(1), &c2);
        fwd.register(FaceId(2), &p);
        advertise_link_back(&fwd, FaceId(2), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_sub("demo/data")); // first client -> advertise
        sink_p.reset();
        forward_one(&fwd, FaceId(1), declare_sub("demo/data")); // second client -> gated
        assert_eq!(
            sink_p.frame_count(),
            0,
            "a second client for the same keyexpr does not re-advertise (derive gate)"
        );
    }

    #[test]
    fn last_client_undeclare_withdraws_the_advertisement() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, _) = face(zid(0xAA), WIRE_CLIENT);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &client);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_sub("demo/data"));
        sink_p.reset();
        forward_one(&fwd, FaceId(0), undeclare_sub("demo/data")); // last client withdraws
        assert_eq!(
            sink_p.frame_count(),
            1,
            "self withdrew its cross-tier advertisement from the peer mesh"
        );
    }

    #[test]
    fn client_face_down_purges_and_withdraws_before_the_linkless_early_return() {
        // OBLIGATION-1: a Client face-down (link == None) purges its FaceId-keyed
        // client sub store BEFORE the linkless early-return AND withdraws the
        // advertisement it was the last client of.
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, _) = face(zid(0xAA), WIRE_CLIENT);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &client);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_sub("demo/data"));
        sink_p.reset();
        fwd.deregister(FaceId(0)); // client down -> purge + withdraw
        assert_eq!(
            sink_p.frame_count(),
            1,
            "the client face-down withdrew its advertisement"
        );
        assert!(
            fwd.client_subs.borrow().get(&FaceId(0)).is_none(),
            "the client sub store was purged"
        );
    }

    #[test]
    fn tick_re_advertises_the_derived_self_sub_to_a_late_joining_peer() {
        // The DERIVED self cross-tier sub (not a stored native) converges onto a
        // peer that joins AFTER the client declared — OBLIGATION-2's re-advertise
        // feed of the derived self-source.
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, _) = face(zid(0xAA), WIRE_CLIENT);
        fwd.register(FaceId(0), &client);
        forward_one(&fwd, FaceId(0), declare_sub("demo/data")); // client subscribes; no peer yet
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER); // joins LATER
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 6);
        sink_p.reset();
        fwd.tick(); // recompute -> P is a new self-child -> re-advertise the derived sub
        assert_eq!(
            sink_p.frame_count(),
            1,
            "the derived self cross-tier sub re-advertised to the late-joining peer"
        );
    }

    #[test]
    fn partial_client_deregister_keeps_the_advertisement() {
        // Two clients subscribe the SAME keyexpr; one leaving does NOT withdraw
        // (the other still holds K) — only the LAST client's departure withdraws.
        // The derive gate on the withdraw side, distinct from a naive per-face
        // withdraw (the composition case the single-client tests skip).
        let fwd = RouterForwarder::new(zid(0x01));
        let (c1, _) = face(zid(0xAA), WIRE_CLIENT);
        let (c2, _) = face(zid(0xCC), WIRE_CLIENT);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &c1);
        fwd.register(FaceId(1), &c2);
        fwd.register(FaceId(2), &p);
        advertise_link_back(&fwd, FaceId(2), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_sub("demo/data")); // c1 -> advertise
        forward_one(&fwd, FaceId(1), declare_sub("demo/data")); // c2 (same K) -> gated
        sink_p.reset();
        fwd.deregister(FaceId(0)); // c1 down -> c2 still holds K -> NO withdraw
        assert_eq!(
            sink_p.frame_count(),
            0,
            "no withdraw while another client still subscribes K"
        );
        fwd.deregister(FaceId(1)); // c2 down -> last client for K -> withdraw
        assert_eq!(
            sink_p.frame_count(),
            1,
            "withdrawn once the last client for K departs"
        );
    }

    #[test]
    fn aliased_client_sub_advertises_via_the_face_table() {
        // A client's ALIASED DeclareSubscriber (via a prior DeclKexpr) resolves to
        // the literal in client_subs and advertises it cross-tier; a literal
        // undeclare of the resolved keyexpr withdraws — the alias round-trip on the
        // client path (the class y106b/y107b asymmetries lived in).
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, _cs) = face(zid(0xAA), WIRE_CLIENT);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &client);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        let kexpr = NetworkMessage::Declare(Box::new(
            wz_session_core::declare_build::build_declare_kexpr(7, "demo/aliased").expect("kexpr"),
        ));
        forward_one(&fwd, FaceId(0), kexpr);
        sink_p.reset();
        let aliased = NetworkMessage::Declare(Box::new(
            build_declare_subscriber(0, 7, None).expect("aliased sub"),
        ));
        forward_one(&fwd, FaceId(0), aliased);
        assert_eq!(
            sink_p.frame_count(),
            1,
            "the aliased client sub resolved via the face table + advertised to the peer"
        );
        sink_p.reset();
        forward_one(&fwd, FaceId(0), undeclare_sub("demo/aliased")); // literal undeclare of the resolved ke
        assert_eq!(
            sink_p.frame_count(),
            1,
            "withdrawn when the (aliased) client sub is undeclared"
        );
    }

    #[test]
    fn client_undeclare_without_prior_sub_is_silent() {
        // A client UndeclareSubscriber for a keyexpr it never subscribed floods no
        // withdrawal (the derive gate: nothing was removed, so nothing withdraws).
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, _cs) = face(zid(0xAA), WIRE_CLIENT);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &client);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        sink_p.reset();
        forward_one(&fwd, FaceId(0), undeclare_sub("never/subscribed"));
        assert_eq!(
            sink_p.frame_count(),
            0,
            "an undeclare with no prior client sub floods no withdrawal"
        );
    }

    #[test]
    fn a_peer_push_is_delivered_to_a_subscribing_client() {
        // C3 CLOSES the advertise-then-blackhole: a peer's Push for K reaches the
        // CLIENT subscribing K (the delivery C2's advertisement attracted).
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, sink_client) = face(zid(0xAA), WIRE_CLIENT);
        let (p, _sp) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &client);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_sub("demo/data")); // client subscribes K
        sink_client.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(1), NetworkMessage::Push(Box::new(push))); // peer publishes K
        assert_eq!(
            sink_client.frame_count(),
            1,
            "the peer Push was delivered to the subscribing client"
        );
    }

    #[test]
    fn a_client_push_reaches_another_client_but_not_the_sender() {
        // client -> client delivery, with the inbound (publishing) client excluded.
        let fwd = RouterForwarder::new(zid(0x01));
        let (c1, sink_c1) = face(zid(0xAA), WIRE_CLIENT); // publisher
        let (c2, sink_c2) = face(zid(0xCC), WIRE_CLIENT); // subscriber
        fwd.register(FaceId(0), &c1);
        fwd.register(FaceId(1), &c2);
        forward_one(&fwd, FaceId(1), declare_sub("demo/data")); // c2 subscribes
        sink_c1.reset();
        sink_c2.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push))); // c1 publishes
        assert_eq!(
            sink_c2.frame_count(),
            1,
            "delivered to the subscribing client c2"
        );
        assert_eq!(
            sink_c1.frame_count(),
            0,
            "not echoed back to the publishing client c1"
        );
    }

    #[test]
    fn a_push_is_not_delivered_to_a_client_that_did_not_subscribe_the_keyexpr() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, sink_client) = face(zid(0xAA), WIRE_CLIENT);
        let (p, _sp) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &client);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_sub("demo/subscribed"));
        sink_client.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/other", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(1), NetworkMessage::Push(Box::new(push))); // a different keyexpr
        assert_eq!(
            sink_client.frame_count(),
            0,
            "a client is not delivered a keyexpr it did not subscribe"
        );
    }

    #[test]
    fn a_wildcard_client_sub_receives_an_intersecting_concrete_push() {
        // A client subscribing `demo/**` MUST receive a `demo/data` Push — the
        // wildcard-intersection match (exact string equality would blackhole every
        // wildcard client sub, re-opening the gap C3 closes).
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, sink_client) = face(zid(0xAA), WIRE_CLIENT);
        let (p, _sp) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &client);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_sub("demo/**")); // wildcard sub
        sink_client.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(1), NetworkMessage::Push(Box::new(push)));
        assert_eq!(
            sink_client.frame_count(),
            1,
            "the wildcard client sub received the intersecting concrete Push"
        );
    }

    #[test]
    fn a_push_reaches_all_clients_subscribing_the_keyexpr() {
        // The multi-target delivery loop: two clients subscribing K both receive.
        let fwd = RouterForwarder::new(zid(0x01));
        let (c1, sink_c1) = face(zid(0xAA), WIRE_CLIENT);
        let (c2, sink_c2) = face(zid(0xCC), WIRE_CLIENT);
        let (p, _sp) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &c1);
        fwd.register(FaceId(1), &c2);
        fwd.register(FaceId(2), &p);
        advertise_link_back(&fwd, FaceId(2), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_sub("demo/data"));
        forward_one(&fwd, FaceId(1), declare_sub("demo/data"));
        sink_c1.reset();
        sink_c2.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(2), NetworkMessage::Push(Box::new(push)));
        assert_eq!(sink_c1.frame_count(), 1, "delivered to client c1");
        assert_eq!(sink_c2.frame_count(), 1, "delivered to client c2");
    }

    #[test]
    fn a_peer_push_reaches_both_a_peer_subscriber_and_a_client_subscriber() {
        // forward_push_tier (mesh) and deliver_to_client_subscribers (client)
        // COMPOSE: a peer's Push reaches BOTH a peer-mesh subscriber and a client.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sa) = face(zid(0xAA), WIRE_PEER); // source peer
        let (peer_sub, sink_peer) = face(zid(0xCC), WIRE_PEER); // peer subscriber (tree child)
        let (client, sink_client) = face(zid(0xDD), WIRE_CLIENT); // client subscriber
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &peer_sub);
        fwd.register(FaceId(2), &client);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_sub("demo/data")); // peer_sub subscribes (mesh)
        forward_one(&fwd, FaceId(2), declare_sub("demo/data")); // client subscribes
        sink_peer.reset();
        sink_client.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push))); // peer A publishes
        assert_eq!(
            sink_peer.frame_count(),
            1,
            "the peer-mesh subscriber got it (within-tier route)"
        );
        assert_eq!(
            sink_client.frame_count(),
            1,
            "the client subscriber got it (client delivery)"
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

    // ── slice 1b: subscription dual-tier INGEST ──────────────────────────

    #[test]
    fn router_face_declare_lands_in_router_subs_only() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sink) = face(zid(0xAA), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        forward_one(&fwd, FaceId(0), declare_sub("demo/data"));
        assert_eq!(
            fwd.router_subs.borrow().interested("demo/data"),
            vec![zid(0xAA)],
            "the router-face source is registered in router_subs"
        );
        assert!(
            fwd.linkstatepeer_subs
                .borrow()
                .interested("demo/data")
                .is_empty(),
            "no native peer entry, and the cross-tier bubble is NOT stored"
        );
    }

    #[test]
    fn peer_face_declare_lands_in_linkstatepeer_subs_only() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (b, _sink) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &b);
        forward_one(&fwd, FaceId(0), declare_sub("demo/data"));
        assert_eq!(
            fwd.linkstatepeer_subs.borrow().interested("demo/data"),
            vec![zid(0xBB)],
        );
        assert!(fwd.router_subs.borrow().interested("demo/data").is_empty());
    }

    #[test]
    fn client_face_declare_is_not_ingested() {
        // A Client face has no tier table (the leaf/simple store is slice 1d):
        // its declare registers nothing in either mesh tier.
        let fwd = RouterForwarder::new(zid(0x01));
        let (c, _sink) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &c);
        forward_one(&fwd, FaceId(0), declare_sub("demo/data"));
        assert!(fwd.router_subs.borrow().interested("demo/data").is_empty());
        assert!(fwd
            .linkstatepeer_subs
            .borrow()
            .interested("demo/data")
            .is_empty());
    }

    #[test]
    fn undeclare_withdraws_from_the_inbound_tier() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sink) = face(zid(0xAA), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        forward_one(&fwd, FaceId(0), declare_sub("demo/data"));
        assert_eq!(
            fwd.router_subs.borrow().interested("demo/data"),
            vec![zid(0xAA)]
        );
        let undecl = NetworkMessage::Declare(Box::new(
            build_undeclare_subscriber_with_keyexpr("demo/data").expect("undecl"),
        ));
        forward_one(&fwd, FaceId(0), undecl);
        assert!(
            fwd.router_subs.borrow().interested("demo/data").is_empty(),
            "the source's interest is withdrawn"
        );
    }

    #[test]
    fn face_down_purges_the_declared_interest() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sink) = face(zid(0xAA), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        forward_one(&fwd, FaceId(0), declare_sub("demo/data"));
        assert_eq!(
            fwd.router_subs.borrow().interested("demo/data"),
            vec![zid(0xAA)]
        );
        fwd.deregister(FaceId(0));
        assert!(
            fwd.router_subs.borrow().interested("demo/data").is_empty(),
            "the departed source's interest is purged (no bubble to leak)"
        );
    }

    // ── slice 1c: queryable dual-tier INGEST ─────────────────────────────

    /// A `DeclareQueryable` for `keyexpr` carrying a `QueryableInfo` (id 0, no
    /// ext_nodeid — the inbound neighbour is the source).
    fn declare_qabl(keyexpr: &str, complete: bool) -> NetworkMessage {
        NetworkMessage::Declare(Box::new(
            build_declare_queryable_with_info(
                keyexpr,
                QueryableInfo {
                    complete,
                    distance: 0,
                },
            )
            .expect("build queryable"),
        ))
    }

    #[test]
    fn router_face_queryable_lands_in_router_qabls_only() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sink) = face(zid(0xAA), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", true));
        assert_eq!(
            fwd.router_qabls.borrow().interested("demo/q"),
            vec![zid(0xAA)],
            "the router-face source is registered in router_qabls"
        );
        assert!(
            fwd.linkstatepeer_qabls
                .borrow()
                .interested("demo/q")
                .is_empty(),
            "no native peer entry, and the cross-tier bubble is NOT stored"
        );
        // The subscription plane is untouched by a queryable declare.
        assert!(fwd.router_subs.borrow().interested("demo/q").is_empty());
    }

    #[test]
    fn peer_face_queryable_lands_in_linkstatepeer_qabls_only() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (b, _sink) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &b);
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", false));
        assert_eq!(
            fwd.linkstatepeer_qabls.borrow().interested("demo/q"),
            vec![zid(0xBB)]
        );
        assert!(fwd.router_qabls.borrow().interested("demo/q").is_empty());
    }

    #[test]
    fn queryable_value_diff_gate_re_floods_on_complete_flip() {
        // The queryable-specific VALUE-DIFF gate: a new queryable re-floods, a
        // redundant re-declare does not, but a completeness flip DOES (so a
        // storage finishing its load re-propagates). Tier-scoped (peer untouched).
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sa) = face(zid(0xAA), WIRE_ROUTER);
        let (c, sink_c) = face(zid(0xCC), WIRE_ROUTER);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        fwd.register(FaceId(2), &p);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick();
        sink_c.reset();
        sink_p.reset();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", false)); // new -> re-flood
        assert_eq!(
            sink_c.frame_count(),
            1,
            "a new queryable re-floods to the child"
        );
        sink_c.reset();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", false)); // same -> gated
        assert_eq!(
            sink_c.frame_count(),
            0,
            "the same QueryableInfo does not re-flood"
        );
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", true)); // complete flip
        assert_eq!(
            sink_c.frame_count(),
            1,
            "a complete:false->true flip re-floods (the value-diff gate)"
        );
        assert_eq!(
            sink_p.frame_count(),
            0,
            "the peer tier is never reached by a routers-tier queryable re-flood"
        );
    }

    #[test]
    fn face_down_purges_the_declared_queryable() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sink) = face(zid(0xAA), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", true));
        assert_eq!(
            fwd.router_qabls.borrow().interested("demo/q"),
            vec![zid(0xAA)]
        );
        fwd.deregister(FaceId(0));
        assert!(
            fwd.router_qabls.borrow().interested("demo/q").is_empty(),
            "the departed queryable source is purged (the 1a purge covers qabls)"
        );
    }

    #[test]
    fn client_face_queryable_is_not_ingested() {
        // A Client face has no tier table (slice 1d): its queryable declare
        // registers nothing in either mesh tier.
        let fwd = RouterForwarder::new(zid(0x01));
        let (c, _sink) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &c);
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", true));
        assert!(fwd.router_qabls.borrow().interested("demo/q").is_empty());
        assert!(fwd
            .linkstatepeer_qabls
            .borrow()
            .interested("demo/q")
            .is_empty());
    }

    /// The `QueryableInfo` carried on the single forwarded DeclareQueryable in a
    /// re-flooded frame — decoded through the production `read_queryable_info`
    /// SSOT (mirror of the sibling's `forwarded_declare_queryable_info`).
    fn forwarded_qabl_info(frame: &[u8]) -> QueryableInfo {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let InboundFrame::Frame { payload, .. } =
            parse_inbound(frame).expect("parse forwarded frame")
        else {
            panic!("forwarded bytes are not a Frame");
        };
        let msgs = parse_frame_payload(&payload).expect("parse frame payload");
        match msgs.first() {
            Some(NetworkMessage::Declare(d)) => match &d.body {
                DeclareOwnedVariant::CodecZenohDeclQueryable(q) => {
                    read_queryable_info(q.extensions.as_ref())
                }
                _ => panic!("forwarded Declare is not a DeclareQueryable"),
            },
            other => panic!("expected a forwarded Declare, got {other:?}"),
        }
    }

    #[test]
    fn queryable_re_flood_carries_the_source_completeness() {
        // The 1c-distinctive behavior: the re-flooded DeclareQueryable CARRIES the
        // source's QueryableInfo (not DEFAULT, not the subscriber carrier) — so a
        // multi-hop relay learns the queryable's completeness. Content-checked,
        // not just frame-counted.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sa) = face(zid(0xAA), WIRE_ROUTER);
        let (c, sink_c) = face(zid(0xCC), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick();
        sink_c.reset();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", true));
        assert_eq!(sink_c.frame_count(), 1, "re-flooded to the tree child");
        assert!(
            forwarded_qabl_info(&sink_c.frame_bytes(0)).complete,
            "the re-flood carries the source's complete=true QueryableInfo"
        );
    }

    #[test]
    fn undeclare_queryable_is_inert() {
        // UndeclareQueryable is deferred (the wz-codecs body carries no keyexpr
        // ext): a declared queryable SURVIVES an UndeclareQueryable (unlike an
        // UndeclareSubscriber, which withdraws). Pins the no-op arm.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sink) = face(zid(0xAA), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", true));
        assert_eq!(
            fwd.router_qabls.borrow().interested("demo/q"),
            vec![zid(0xAA)]
        );
        forward_one(
            &fwd,
            FaceId(0),
            NetworkMessage::Declare(Box::new(
                wz_session_core::declare_build::build_undeclare_queryable(0),
            )),
        );
        assert_eq!(
            fwd.router_qabls.borrow().interested("demo/q"),
            vec![zid(0xAA)],
            "UndeclareQueryable is inert (deferred codec gap) — the queryable survives"
        );
    }

    #[test]
    fn declare_re_floods_within_the_tier_only() {
        // A sourced DeclareSubscriber floods along the SOURCE's tree WITHIN its
        // tier: register the source + re-flood to the tree child, never back to
        // the inbound source, never to the other tier.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_ROUTER); // source
        let (c, sink_c) = face(zid(0xCC), WIRE_ROUTER); // same-tier tree child
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER); // other tier
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        fwd.register(FaceId(2), &p);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5); // edge self<->A
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5); // edge self<->C
        fwd.tick(); // compute the spanning trees
        sink_a.reset();
        sink_c.reset();
        sink_p.reset();
        forward_one(&fwd, FaceId(0), declare_sub("demo/sub"));
        assert_eq!(
            fwd.router_subs.borrow().interested("demo/sub"),
            vec![zid(0xAA)],
            "self learned A is interested"
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "re-flooded to the same-tier tree child C"
        );
        assert_eq!(sink_a.frame_count(), 0, "not back to the inbound source A");
        assert_eq!(sink_p.frame_count(), 0, "not to the peer tier");
    }

    #[test]
    fn duplicate_declare_does_not_re_flood() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sa) = face(zid(0xAA), WIRE_ROUTER);
        let (c, sink_c) = face(zid(0xCC), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_sub("demo/sub")); // first: re-floods
        sink_c.reset();
        forward_one(&fwd, FaceId(0), declare_sub("demo/sub")); // duplicate: gated
        assert_eq!(
            sink_c.frame_count(),
            0,
            "a re-declare of a known interest does not re-flood (the change-gate)"
        );
    }

    #[test]
    fn aliased_declare_resolves_via_the_face_table() {
        // A DeclKexpr maps an alias id on the link; a later aliased
        // DeclareSubscriber resolves through the face's keyexpr_table to the
        // literal (the alias-absorb path).
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sink) = face(zid(0xAA), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        let kexpr = NetworkMessage::Declare(Box::new(
            wz_session_core::declare_build::build_declare_kexpr(7, "demo/aliased").expect("kexpr"),
        ));
        forward_one(&fwd, FaceId(0), kexpr);
        let aliased = NetworkMessage::Declare(Box::new(
            build_declare_subscriber(0, 7, None).expect("aliased sub"),
        ));
        forward_one(&fwd, FaceId(0), aliased);
        assert_eq!(
            fwd.router_subs.borrow().interested("demo/aliased"),
            vec![zid(0xAA)],
            "the aliased declare resolved to the literal via the face table"
        );
    }

    #[test]
    fn transit_source_declare_keys_on_the_resolved_zid() {
        // A declare with a NON-zero node_id resolves via the inbound link's psid
        // map to the TRANSIT source (0xBB), not the inbound neighbour (0xAA) — the
        // resolve_source_in non-zero branch on the declare path.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sink) = face(zid(0xAA), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        discover_via(&fwd, FaceId(0), 0x01, 0xAA, 0xBB, 7, 5); // psid 7 = 0xBB on A's link
        let mut decl = build_declare_subscriber(0, 0, Some("demo/sub")).expect("build");
        set_declare_source(&mut decl, 7); // node_id 7 = A's psid for B
        forward_one(&fwd, FaceId(0), NetworkMessage::Declare(Box::new(decl)));
        assert_eq!(
            fwd.router_subs.borrow().interested("demo/sub"),
            vec![zid(0xBB)],
            "keyed on the resolved transit source B, not the inbound neighbour A"
        );
    }

    #[test]
    fn undeclare_re_floods_within_the_tier() {
        // The retraction re-flood: after a declare re-floods to the tree child,
        // an UndeclareSubscriber withdraws AND re-floods the retraction to the
        // same child, never back to the inbound source.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_ROUTER);
        let (c, sink_c) = face(zid(0xCC), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_sub("demo/sub")); // register + re-flood
        sink_a.reset();
        sink_c.reset();
        let undecl = NetworkMessage::Declare(Box::new(
            build_undeclare_subscriber_with_keyexpr("demo/sub").expect("undecl"),
        ));
        forward_one(&fwd, FaceId(0), undecl);
        assert!(
            fwd.router_subs.borrow().interested("demo/sub").is_empty(),
            "the source's interest is withdrawn"
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the retraction re-flooded to the tree child C"
        );
        assert_eq!(sink_a.frame_count(), 0, "not back to the inbound source A");
    }

    #[test]
    fn peer_declare_re_floods_within_the_peers_tier() {
        // The peer-tier twin of `declare_re_floods_within_the_tier_only`: the
        // re-flood machinery is tier-generic (a peer declare floods the peers
        // tree, never the router tier).
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER); // source (peer)
        let (c, sink_c) = face(zid(0xCC), WIRE_PEER); // same-tier tree child
        let (r, sink_r) = face(zid(0xBB), WIRE_ROUTER); // other tier
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        fwd.register(FaceId(2), &r);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick();
        sink_a.reset();
        sink_c.reset();
        sink_r.reset();
        forward_one(&fwd, FaceId(0), declare_sub("demo/sub"));
        assert_eq!(
            fwd.linkstatepeer_subs.borrow().interested("demo/sub"),
            vec![zid(0xAA)]
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "re-flooded to the peer-tier tree child"
        );
        assert_eq!(sink_r.frame_count(), 0, "not to the router tier");
    }

    #[test]
    fn unknown_keyexpr_undeclare_is_a_noop() {
        // An UndeclareSubscriber for a never-declared keyexpr: withdraw returns
        // false -> no re-flood, no panic (the change-gate).
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        sink_a.reset();
        let undecl = NetworkMessage::Declare(Box::new(
            build_undeclare_subscriber_with_keyexpr("never/declared").expect("undecl"),
        ));
        forward_one(&fwd, FaceId(0), undecl);
        assert!(fwd
            .router_subs
            .borrow()
            .interested("never/declared")
            .is_empty());
    }

    #[test]
    fn undeclkexpr_removes_the_alias() {
        // After an UndeclKexpr removes the alias, a later aliased declare
        // referencing that id no longer resolves and is not registered.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sink) = face(zid(0xAA), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        forward_one(
            &fwd,
            FaceId(0),
            NetworkMessage::Declare(Box::new(
                wz_session_core::declare_build::build_declare_kexpr(7, "demo/aliased")
                    .expect("kexpr"),
            )),
        );
        forward_one(
            &fwd,
            FaceId(0),
            NetworkMessage::Declare(Box::new(
                wz_session_core::declare_build::build_undeclare_kexpr(7),
            )),
        );
        forward_one(
            &fwd,
            FaceId(0),
            NetworkMessage::Declare(Box::new(
                build_declare_subscriber(0, 7, None).expect("aliased"),
            )),
        );
        assert!(
            fwd.router_subs
                .borrow()
                .interested("demo/aliased")
                .is_empty(),
            "the alias was removed, so the aliased declare did not resolve"
        );
    }
}
