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
//! compute from the NATIVE qabls, not stored. A per-keyexpr `UndeclareQueryable`
//! withdraws a queryable interest via its `ext_wire_expr` extension (parity with
//! the sub plane now that the codec models the ext); the face-down purge remains
//! the safety net for a departed peer that sends no retraction.
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
//! ([`advertise_client_cross_tier_sub`](RouterForwarder::advertise_client_cross_tier_sub)),
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
//! ## Slice C3a (cross-tier client data delivery) — landed
//!
//! A data `Push` is DELIVERED to the CLIENT faces subscribing its keyexpr
//! ([`deliver_to_client_subscribers`](RouterForwarder::deliver_to_client_subscribers)),
//! re-literalized to the resolved keyexpr — CLOSING the advertise-then-blackhole:
//! a Push attracted toward this router by C2's client advertisement now reaches
//! the subscribing client. It runs for a Push from ANY source (excluding the
//! inbound face), so it covers mesh→client AND client→client.
//!
//! ## Slice C3b (client→mesh publish) — landed
//!
//! A CLIENT-sourced `Push` is RE-INJECTED into BOTH meshes as a SELF-sourced
//! publish ([`publish_client_push_into_meshes`](RouterForwarder::publish_client_push_into_meshes)),
//! so it reaches subscribing MESH peers (the client→peer direction, not just
//! other clients). A client is a leaf below exactly one router, so self is the
//! unique origin node in each net; this mirrors [`LinkstateForwarder::publish`]
//! via the shared [`compute_self_publish_forward`] core (self tree-root, node_id
//! 0, fresh per-net hop budget) — self-origination, NOT the transit re-forward
//! (a client zid is no mesh node, so `resolve_source_in` would drop it). Faithful
//! to zenoh's `route_data`: the peer-net publish leg is NOT master-gated for a
//! non-router source (zenoh block 2), while the router-net leg IS master-gated
//! (block 1) — C4 landed that gate (below). LOCAL self-hosted delivery (a pure
//! router hosts no subscribers) stays deferred.
//!
//! ## Slice C4 (router↔router federation + master-election) — landed
//!
//! A data `Push` on ONE mesh is BRIDGED to the OTHER mesh's subscribers when self
//! is the elected route master
//! ([`bridge_push_cross_mesh`](RouterForwarder::bridge_push_cross_mesh)) — a
//! self-origination into the target net via [`compute_self_publish_forward`], the
//! zenoh `compute_data_route` cross-tier legs (blocks 1 & 2 for a non-native
//! source, `hat/router/pubsub.rs:1291`/`:1307`). The master is elected per-keyexpr
//! by HRW ([`elect_router`], a port of zenoh `Hat::elect_router`,
//! `hat/router/mod.rs:245`) over the SHARED nodes — the routers present in BOTH
//! meshes ([`shared_nodes`](RouterForwarder::shared_nodes), zenoh
//! `network.rs:1197`), DERIVED per call (no stored field, the R311y109
//! derive-not-store idiom). Self is a node of both meshes, so a single-router
//! topology has `shared_nodes = {self}` ⇒ self is always master ⇒ the C4 gates are
//! no-ops (behavior-preserving). Election makes exactly ONE router bridge the two
//! meshes, so C4 ALSO master-gates the two other non-native legs that would
//! otherwise double-deliver once routers federate: C3a local client delivery
//! ([`deliver_to_client_subscribers`](RouterForwarder::deliver_to_client_subscribers),
//! zenoh block 3, `master || source == Router`) and C3b's router-net publish leg
//! (block 1). Cross-mesh loop-freedom rests on the election agreement (the
//! self-origination resets the per-net hop budget), NOT the hop budget.
//!
//! ## Slice C5b (query-route FORWARD half — the Request) — landed
//!
//! An inbound `Request` (a Query) is ROUTED
//! ([`route_request`](RouterForwarder::route_request)) through the router's full
//! zenoh `compute_query_route` (`hat/router/queries.rs:1426`) +
//! `compute_final_route` (`dispatcher/queries.rs:205`) — the query-plane twin of
//! [`route_push`](RouterForwarder::route_push). The SAME 3-block master-gated
//! structure (routers_net qabls / linkstatepeers_net qabls / client queryables),
//! reusing C4's [`is_master`](RouterForwarder::is_master), with the within-tier +
//! cross-mesh + client legs split exactly as the data plane's `forward_push_tier`
//! / `bridge_push_cross_mesh` / `deliver_to_client_subscribers` /
//! `publish_client_push_into_meshes`. A CLIENT-face `DeclareQueryable` lands in the
//! per-face [`client_qabls`](RouterForwarder#structfield.client_qabls) store
//! ([`ingest_client_queryable`](RouterForwarder::ingest_client_queryable)); the
//! query route reads its `complete` / `distance`.
//!
//! The one query-specific twist over the data plane is the `QueryTarget` dispatch,
//! whose **BestMatching is GLOBAL** (zenoh `compute_final_route` picks the FIRST
//! complete queryable in the union route sorted by SELF-relative distance,
//! `queries.rs:1520`): the C5a per-net `compute_query_directions` does NOT compose
//! for it, so the router picks the min over each net's per-net nearest complete
//! (`select_best_matching`, min-of-mins == global-min) and the client candidates at
//! distance 1 ([`best_query_winner`](RouterForwarder::best_query_winner)). `All` /
//! `AllComplete` DO compose per tier (union of per-tier `all_query_directions` /
//! `complete_query_directions` + client faces). Each forwarded Request ALLOCATES a
//! [`PendingQueries`](crate::linkstate_pending::PendingQueries) return entry (the
//! reverse Response route is C5c, below); an EMPTY route prompts a `ResponseFinal`
//! to the querier. [`deregister`](FaceForwarder::deregister) purges `client_qabls`
//! + the pending entries keyed by the departed face BEFORE its linkless
//! early-return (OBLIGATION 1).
//!
//! ## Slice C5c (query-route RESPONSE half — the reply return) — landed
//!
//! A queryable's `Response` / `ResponseFinal` is routed BACK toward the querier
//! via the pending table — the reverse of C5b's per-face allocate, mirroring the
//! single-net [`LinkstateForwarder`]'s proven return path:
//! [`forward_response`](RouterForwarder::forward_response) peeks (more replies may
//! follow) and [`forward_response_final`](RouterForwarder::forward_response_final)
//! takes — freeing that BRANCH; the closing final propagates upstream only from
//! the fan's LAST branch (the last-out gate, zenoh `finalize_pending_query`'s
//! `Arc::into_inner`) — each rewriting the `request_id` back to the recorded
//! upstream rid and unicasting to the recorded inbound face — a MESH face
//! (transit) or a CLIENT face (a local querier), the tier-agnostic
//! [`send_to_face`](RouterForwarder::send_to_face). The
//! [`tick`](FaceForwarder::tick) additionally sweeps the pending table for
//! branches past their deadline
//! ([`reap_timed_out_queries`](RouterForwarder::reap_timed_out_queries), zenoh's
//! `QueryCleanup`): a synthesized `Err("Timeout")` reply per reaped branch + the
//! closing `ResponseFinal` for a `last` branch, so a queryable that crashes
//! without a final on a still-up face cannot hang a `get()` forever.
//!
//! ## Slices A2a + A2b + A3 (FEDERATION cross-tier bubble + client qabl) — landed
//!
//! The cross-tier self-advertisement now derives from the OTHER tier's NATIVES,
//! not just from `client_subs` (C2). A ROUTER-native sub advertises self's
//! interest into the PEER mesh, a PEER-native sub into the ROUTER mesh — zenoh's
//! `register_router_subscription` / `declare_linkstatepeer_subscription`
//! cross-registration (`pubsub.rs:248-250`/`:296-297`), NOT master-gated (every
//! router advertises; only the DELIVERY bridge is master-gated). One per-target
//! derive SSOT ([`self_advertises_sub_into`](RouterForwarder::self_advertises_sub_into)
//! = client ∪ opposite-mesh native) feeds the immediate advertise (the flip
//! false->true on ingest), the tick re-advertise
//! ([`derived_cross_tier_subs_into`](RouterForwarder::derived_cross_tier_subs_into)),
//! and — as its exact negation — the withdraw. The withdraw is centralized in
//! [`purge_detached_interest_tier`](RouterForwarder::purge_detached_interest_tier),
//! the shared choke point for BOTH the local face-down deregister AND the remote
//! Oam-ingest detach, so a departed native's stale advertisement is retracted on
//! either path (the R311y107b lifecycle-asymmetry class). This is LATENT in a
//! single router (`router_subs` empty, the router-mesh flood no-op) and
//! unit-tested by injecting a native directly; the E2E black-hole proof (a peer
//! publisher actually routing toward the router-native's interest) needs the
//! 2-router ACTIVATION harness (below). The QUERYABLE twin landed in A2b: a
//! native qabl advertises its MERGED [`QueryableInfo`] (`complete = OR` /
//! `distance = min`, [`derived_cross_tier_qabl_info`](RouterForwarder::derived_cross_tier_qabl_info))
//! into the opposite mesh; a partial removal DOWNGRADES via a re-advertised
//! `DeclareQueryable`, and the full retraction (last contributor leaves) floods an
//! `UndeclareQueryable` carrying the keyexpr in its `ext_wire_expr` extension
//! ([`withdraw_native_cross_tier_qabl`](RouterForwarder::withdraw_native_cross_tier_qabl)) —
//! parity with the sub plane now that the codec models the ext.
//!
//! A3 adds the CLIENT-queryable cross-tier advertisement (the query twin of C2's
//! [`advertise_client_cross_tier_sub`](RouterForwarder::advertise_client_cross_tier_sub)):
//! a client `DeclareQueryable` makes self flood a self-sourced `DeclareQueryable`
//! carrying the merged info into BOTH meshes (a client is in neither), so a REMOTE
//! mesh querier steers toward the client's queryable
//! ([`advertise_client_cross_tier_qabl`](RouterForwarder::advertise_client_cross_tier_qabl)).
//! It reuses [`derived_cross_tier_qabl_info`](RouterForwarder::derived_cross_tier_qabl_info)
//! (which already folds `client_qabls`), so A3 is a trigger-only add; a client
//! face-down re-advertises the downgraded merge. What remains for the query plane
//! is the E2E remote-querier steer, with the 2-router ACTIVATION harness.
//!
//! ## Deferred to later slices (named, not silently dropped)
//!
//! - **Per-peer ingress/egress master filter + source-dimensioned route cache
//!   (C4 tail)** — zenoh ALSO elects a master per-peer over
//!   `get_router_links(face.zid)` in its `ingress_filter`/`egress_filter`
//!   (`hat/router/mod.rs:793`/`:815`), a DIFFERENT candidate set than the global
//!   `shared_nodes` route master — a real asymmetry. wz has no interceptor
//!   ingress/egress plane yet, so C4 implements the global route master only; the
//!   per-peer filter + `router_peers_failover_brokering` (off by default in zenoh)
//!   land with the interceptor slice. The source-dimensioned route cache is a
//!   data-path optimization (wz computes routes inline today) deferred with it.
//! - **Native-other-tier cross bubble — the ROUTER-NATIVE / non-master corner
//!   (mechanism landed A2a/A2b; peer-native E2E landed A4; router-native E2E
//!   UNIT-only)** — the canonical R311y120 black-hole is: a peer-source Push into a
//!   NON-MASTER router whose only subscriber is a ROUTER-NATIVE sub behind the
//!   elected master, with no same-tier native relay — without the
//!   cross-tier-native advertisement the non-master never attracts the Push toward
//!   a router that can bridge it. A2a closed the subscription-plane mechanism and
//!   A2b the queryable-plane twin (self advertises a router-native's interest into
//!   the peer mesh, and vice versa), unit-tested by direct native injection. A4
//!   (R311y128) then proved the PEER-NATIVE direction E2E over real transport (a
//!   `--peer` subscriber behind another router; the A2a `linkstatepeer_subs ->
//!   router-mesh` half + the sole-master bridge). What stays UNIT-only is the
//!   ROUTER-NATIVE direction (`router_subs -> peer-mesh`) AND the non-master-attract
//!   corner: both are UNDRIVABLE by the OBSERVE-only demo router — `router_subs` is
//!   populated only by another router ORIGINATING a native declare (the demo router
//!   originates nothing), and 2 routers make each the sole master of its own domain
//!   (`shared_nodes` = {self}), so a non-master needs 3+ routers sharing both
//!   meshes. Their E2E proof waits on a router that hosts/relays natives (or a
//!   3-router harness); the DIRECT-injection unit tests
//!   (`advertise_native_cross_tier_sub` / `push_bridges_cross_mesh_only_when_master`)
//!   cover the mechanism meanwhile. (The client-behind-a-router variant was already
//!   rescued by C2.)
//! - **Gossip / autoconnect / interceptors** — the per-net policy knobs the
//!   `LinkstateForwarder` carries; added as the router gains the corresponding
//!   plane. (The pending-query GC — the timeout sweep — landed with C5c above.)
//!   NOTE (impl-panel R311y113): NEITHER the tier-scoped
//!   [`fan_out_tier`](RouterForwarder::fan_out_tier) NOR the single-target
//!   [`send_to_face`](RouterForwarder::send_to_face) applies the egress-ACL
//!   `admit_outbound` gate or the `interceptor_dropped` witness the single-net
//!   `fan_out` applies, so a within-tier Push forward, the tick re-advertise, and
//!   the query Request/Response sends reach a face a §5.16 egress-deny would
//!   drop. Silent in any config with no ACL wired (the router has no interceptor
//!   plane yet); these two egress helpers are the router↔single-net data-path
//!   parity obligation for the interceptor slice.

use std::cell::{Cell, RefCell};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::Hasher;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sce_forge_runtime::codec::CodecError;

use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant};
use wz_codecs::interest::InterestOwned;
use wz_codecs::linkstate_list::LinkstateListOwned;
use wz_codecs::push::PushOwned;
use wz_codecs::wireexpr::WireexprOwned;
// R311wt-mc slice 1 — the EGRESS-only multicast group plane
// (`router-multicast-faces`). Gated on `transport-multicast` (the existing §5.1
// atom that makes `MulticastTxItem` + the drive loop available); the reserved
// `router-multicast-faces` atom stays cfg-site-free until a run-mode wires
// `attach_mcast_group` (a later slice, the reserved→active flip).
#[cfg(feature = "transport-multicast")]
use tokio::sync::mpsc::UnboundedSender;
use wz_routing_graph::{Changes, LinkId, LinkstateNetwork, WhatAmI, Zid};
use wz_session_core::declare_build::{
    build_declare_final_reply, build_declare_queryable_reply,
    build_declare_queryable_reply_with_id, build_declare_queryable_with_id_info,
    build_declare_subscriber, build_declare_subscriber_reply,
    build_declare_subscriber_reply_with_id, build_undeclare_queryable,
    build_undeclare_queryable_with_keyexpr, build_undeclare_subscriber,
    build_undeclare_subscriber_with_keyexpr,
};
#[cfg(feature = "routing-token-tables")]
use wz_session_core::declare_build::{
    build_declare_token, build_declare_token_reply, build_declare_token_reply_with_id,
    build_undeclare_token, build_undeclare_token_with_keyexpr,
};
use wz_session_core::declare_ext_keyexpr::resolve_ext_keyexpr;
use wz_session_core::declare_routing_context::{read_declare_source, set_declare_source};
use wz_session_core::driver_loop::DriverLoopOutcome;
use wz_session_core::keyexpr_match::{keyexpr_includes_target, keyexpr_intersects_target};
use wz_session_core::linkstate_oam::{
    build_linkstate_oam_owned, try_parse_linkstate_oam, LinkstateOam,
};
#[cfg(feature = "transport-multicast")]
use wz_session_core::multicast_tx::MulticastTxItem;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::push_build::reliteralize_push;
use wz_session_core::push_routing_context::set_push_source;
use wz_session_core::qos::Priority;
use wz_session_core::query::{QueryReply, QueryResponder};
use wz_session_core::wireexpr_resolve::{resolve_wireexpr, wireexpr_is_empty};
use wz_session_core::zid_hex::zid_to_zenoh_hex;

use crate::accept_loop::{FaceForwarder, FaceId};
use crate::future_interest::{FutureQablStore, FutureSubStore};
use crate::interceptor::{
    InterceptorChain, InterceptorConfig, InterceptorContext, InterceptorFlow,
};
#[cfg(feature = "routing-token-tables")]
use crate::linkstate_forward::declare_token_wireexpr;
use crate::linkstate_forward::{
    absorb_keyexpr_into, all_query_directions, build_declare_queryable_with_info,
    complete_query_directions, compute_push_forward, compute_self_publish_forward,
    declare_queryable_wireexpr, declare_subscriber_wireexpr, emit_current_interest_replies,
    is_tree_forward_target, peer_whatami_routing, peer_zid_routing, re_advertise_interest_into,
    resolve_governed_keyexpr, resolve_source_in, select_best_matching,
    synthesize_drained_fan_finals, synthesize_expired_query_returns, LocalQueryHandler,
    LocalQueryView, LocalQueryable,
};
use crate::linkstate_interest::LinkstatepeerInterest;
use crate::linkstate_pending::{PendingQueries, QueryFan};
use crate::session_glue::{IterationEvent, SessionLinkActions};
use wz_codecs::ext_entry::ExtEntryOwned;
use wz_codecs::request::RequestOwned;
use wz_codecs::response::ResponseOwned;
use wz_codecs::response_final::ResponseFinalOwned;
use wz_session_core::link::LinkSubject;
use wz_session_core::query_mode::QueryTarget;
use wz_session_core::queryable_info::{read_queryable_info, QueryableInfo};
use wz_session_core::request_build::set_request_keyexpr_literal;
use wz_session_core::request_routing_context::{
    read_request_source, read_request_target, read_request_timeout_ms, set_request_source,
};
use wz_session_core::response_build::set_response_keyexpr_literal;

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

/// Elect the master router for `keyexpr` among `candidates` by Highest-Random-
/// Weight (rendezvous) hashing — a faithful port of zenoh `Hat::elect_router`
/// (`hat/router/mod.rs:245`): a std `DefaultHasher` is fed each keyexpr byte
/// then each candidate zid wire byte ([`Zid::as_slice`] == zenoh
/// `to_le_bytes()[..size]`), and the highest-hash candidate wins; an empty
/// candidate set elects `self_zid` (zenoh's `routers.next() == None` arm). A tie
/// resolves to the earlier candidate, matching zenoh's strict `>` accumulation.
///
/// `DefaultHasher` is seedless SipHash-1-3, so every router computes the SAME
/// hash for a given (keyexpr, zid) pair — all routers therefore agree on the one
/// master, which is what makes exactly one router bridge the two meshes
/// (cross-mesh loop-freedom rests on this agreement, not on the hop budget,
/// which [`compute_self_publish_forward`] RESETS at each origination). The
/// byte-feed order matches zenoh's so a wz router elects the same master as a
/// zenohd router sharing the mesh (cross-impl federation).
fn elect_router<'a>(
    self_zid: &Zid,
    keyexpr: &str,
    candidates: impl Iterator<Item = &'a Zid>,
) -> Zid {
    let hash = |z: &Zid| {
        let mut h = DefaultHasher::new();
        for b in keyexpr.as_bytes() {
            h.write_u8(*b);
        }
        for b in z.as_slice() {
            h.write_u8(*b);
        }
        h.finish()
    };
    let mut best: Option<(u64, Zid)> = None;
    for z in candidates {
        let hz = hash(z);
        let replace = match best {
            Some((bh, _)) => hz > bh, // strict '>' => the earlier candidate wins a tie
            None => true,
        };
        if replace {
            best = Some((hz, *z));
        }
    }
    best.map_or(*self_zid, |(_, z)| z)
}

/// One mesh tier's query-route parameters, resolved by
/// [`RouterForwarder::mesh_query_block`] — zenoh `compute_query_route`'s block-1
/// (routers_net) / block-2 (linkstatepeers_net) AFTER the master gate + source
/// selection (`hat/router/queries.rs:1465-1497`). Carries the tree ROOT to route
/// the Query along, the `node_id` to stamp on the outbound Request, and the inbound
/// neighbour to exclude in THIS net.
struct MeshQueryBlock {
    /// Which mesh this block routes into (its faces + qabls table).
    tier: FaceTier,
    /// The tree root: the QUERIER's zid for the within-tier leg (route along the
    /// querier's tree), or SELF for a cross-tier self-originated leg.
    source_zid: Zid,
    /// The `ext_nodeid` to stamp on the outbound Request: the querier's psid
    /// (`out_node_id`) for the within-tier leg, or `0` (self-origination,
    /// omit-on-DEFAULT) for a cross leg — the query twin of the data plane's
    /// within-tier vs [`compute_self_publish_forward`] cross stamp.
    source_psid: u16,
    /// The inbound neighbour to exclude in this net — the querier's own neighbour
    /// on the within leg (never route a Query back at its source), or `None` for a
    /// cross leg (the inbound face is no node of this net).
    inbound_for_net: Option<Zid>,
}

/// The GLOBAL-BestMatching winner — the single globally-nearest COMPLETE queryable
/// across BOTH meshes + clients (zenoh `compute_final_route`'s first complete in
/// the distance-sorted union route, `dispatcher/queries.rs:243`).
enum BestQueryWinner {
    /// A mesh queryable: the index into the router's live `MeshQueryBlock`s + the
    /// tree hop toward it.
    Mesh(usize, Zid),
    /// A client-hosted queryable: the client face to forward the Query to.
    Client(FaceId),
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

/// One EGRESS-only multicast group face — the wz analog of a zenoh
/// `mcast_groups` entry (`dispatcher/tables.rs:79`) whose primitives is a
/// `McastMux` (`mux.rs:245`). Holds the outbound sender of a multicast drive
/// loop ([`multicast_glue::drive_multicast_session`](crate::multicast_glue));
/// the router enqueues a [`MulticastTxItem::Push`] and the (SEPARATE-task) loop
/// mints the group channel SN + frames it through the `multicast_tx` SSOT, so
/// this `!Send` forwarder only needs a `Send` sender (no single-task fold — that
/// is the INGRESS milestone). A group is a broadcast SINK: no zid, no ingress,
/// never a delivery-lookup key (zenoh's per-peer `DummyPrimitives` ingress face
/// lives in the separate `mcast_faces` plane, deferred).
#[cfg(feature = "transport-multicast")]
struct McastGroup {
    tx: UnboundedSender<MulticastTxItem>,
}

/// The synthetic FaceId for the single multicast INGRESS face (the deferred
/// `mcast_faces` plane's first slice, I1). A group ingress is folded under ONE
/// face rather than zenoh's per-peer `mcast_faces` (per-peer is the deferred I3
/// milestone). Drawn from the TOP of the u64 range so it can never alias a
/// unicast FaceId, which the accept loop assigns densely from 0
/// (`accept_loop.rs` `next_id`). It is deliberately NOT inserted into
/// [`faces`](RouterForwarder#structfield.faces): a mcast ingress has no send seam
/// and no graph link (zenoh's per-peer `DummyPrimitives` ingress face analog,
/// `router.rs:229`), so [`resolve_inbound_keyexpr`](RouterForwarder::resolve_inbound_keyexpr)
/// special-cases it against an empty alias table (literal-only).
#[cfg(feature = "transport-multicast")]
const MCAST_INGRESS_FACE: FaceId = FaceId(u64::MAX);

/// A read-only, `Rc`-backed handle to one of a [`RouterForwarder`]'s two
/// link-state graphs, exposing ONLY the adminspace render seam (§5.23
/// `adminspace-router-linkstate`): the GraphViz DOT and the `route_successors`
/// enumeration, each zid rendered to the zenoh `ZenohId` Display hex an admin
/// client expects ([`zid_to_zenoh_hex`]). Handed to the router's admin-queryable
/// handler so it renders LIVE per GET (no per-tick snapshot buffer) WITHOUT
/// leaking a `borrow_mut` handle that could mutate routing state — the wz-fit
/// resolution of the render-accessor-vs-Rc-clone question (a router net is
/// already `Rc<RefCell<..>>`, unlike the peer's owned-snapshot `subscriptions()`).
pub struct LinkstateNetView(Rc<RefCell<LinkstateNetwork>>);

impl LinkstateNetView {
    /// The graph as GraphViz DOT with zenoh-hex node labels — the wz mirror of
    /// zenoh `info(..)` = `net.dot()` (`net/runtime/adminspace.rs:753,773`). The
    /// zid formatter is injected because `dot_with` (in the lower `wz-routing-
    /// graph` crate) cannot reach the [`zid_to_zenoh_hex`] SSOT itself.
    pub fn dot(&self) -> String {
        self.0.borrow().dot_with(|z| zid_to_zenoh_hex(z.as_slice()))
    }

    /// Every `(source, destination, successor)` triple, each zid in zenoh-hex —
    /// the wz mirror of zenoh `route_successors()` (`net/protocol/network.rs:
    /// 1187`). Rendered from THIS net (the router adminspace uses `routers_net`
    /// for the `route/successor` legs, zenoh `hat/router/mod.rs:910`).
    pub fn route_successors_hex(&self) -> Vec<(String, String, String)> {
        self.0
            .borrow()
            .route_successors()
            .into_iter()
            .map(|(s, d, h)| {
                (
                    zid_to_zenoh_hex(s.as_slice()),
                    zid_to_zenoh_hex(d.as_slice()),
                    zid_to_zenoh_hex(h.as_slice()),
                )
            })
            .collect()
    }
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
    /// EGRESS-only multicast group faces (zenoh `Tables.mcast_groups`,
    /// `dispatcher/tables.rs:79`) — a SEPARATE collection from `faces`, mirroring
    /// zenoh's separate `mcast_groups` Vec (the egress polymorphism is WHICH
    /// collection a face lives in, not a `dyn EPrimitives`). A routed `Push` is
    /// broadcast to every group UNCONDITIONALLY at the [`route_push`](Self::route_push)
    /// tail — zenoh's flat append (`hat/router/pubsub.rs:1334`) sits OUTSIDE the
    /// sub-gated graph walk, so a Put with zero matched local subs still reaches
    /// the group. Empty until a run-mode [`attach_mcast_group`](Self::attach_mcast_group)s
    /// a drive loop's sender (the reserved→active wiring, a later slice).
    #[cfg(feature = "transport-multicast")]
    mcast_groups: RefCell<Vec<McastGroup>>,
    /// The OTHER on-group ROUTER member zids for the attached multicast group —
    /// the Designated-Router (DR) election candidate set (I3b loop-safe
    /// federation). Learned from the group's JOIN beacons (whatami=Router) and
    /// relayed live from the ingress drive loop via
    /// [`set_mcast_group_members`](Self::set_mcast_group_members). Empty ⇒ this is
    /// the sole on-group router ⇒ it is trivially the DR for every keyexpr
    /// ([`is_group_dr`](Self::is_group_dr) returns true, so group egress +
    /// mcast-ingress federation stay unconditional as before — the single-router /
    /// egress-only case). Gated on `router-multicast-faces` (NOT the broader
    /// `transport-multicast` that gates `mcast_groups`): an egress-only build
    /// never runs the ingress drive loop that populates it, so the field + gate
    /// are elided there and egress stays unconditional (the shipped behavior).
    #[cfg(feature = "router-multicast-faces")]
    mcast_group_members: RefCell<Vec<Zid>>,
    /// The DEDUPED keyexpr set the attached multicast group's SUBSCRIBERS declared
    /// (§5.21 sub plane, S2), relayed live from the ingress drive loop via
    /// [`set_mcast_group_subs`](Self::set_mcast_group_subs). A THIRD self-advertise
    /// contributor alongside local client subs and opposite-mesh natives
    /// ([`self_advertises_sub_into`](Self::self_advertises_sub_into)): while a
    /// keyexpr is in this set, self advertises interest in it into BOTH meshes (a
    /// self-sourced `DeclareSubscriber`, exactly as a local client sub does — zenoh
    /// registers a `mcast_faces` Client-face sub under the router's OWN zid,
    /// `pubsub.rs:245`), so a mesh-side publisher routes matching Puts toward this
    /// router and they reach the on-group subscriber via the unconditional group
    /// egress. Kept as a DISTINCT set (not merged into `client_subs`) because the
    /// group-sub lifecycle differs — it is withdrawn on async lease-evict, relayed
    /// as a wholesale REPLACE from the dispatch SSOT, not on a synchronous unicast
    /// UndeclareSubscriber. Empty (and elided) without `router-multicast-faces`.
    #[cfg(feature = "router-multicast-faces")]
    group_subs: RefCell<HashSet<String>>,
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
    /// Router-tier liveliness-TOKEN interest (zenoh `HatTables.router_tokens`).
    /// The TOKEN TWIN of `router_subs` — a source-zid set with NO value payload
    /// (tokens carry no info, unlike `QueryableInfo`), so `V = ()` exactly like
    /// the sub plane. Populated by the token-INGEST slice: NATIVE Router token
    /// sources keyed by their zid; within-tier re-flood (slice-1) + the cross-tier
    /// self-bubble (slice-2) + read by the token-INTEREST current dump (slice-4).
    #[cfg(feature = "routing-token-tables")]
    router_tokens: RefCell<LinkstatepeerInterest<()>>,
    /// Peer-tier liveliness-TOKEN interest (zenoh `HatTables.linkstatepeer_tokens`).
    /// The token twin of `linkstatepeer_subs` (native Peer token sources by zid).
    #[cfg(feature = "routing-token-tables")]
    linkstatepeer_tokens: RefCell<LinkstatepeerInterest<()>>,
    /// Per-CLIENT-face liveliness-TOKEN store (slice-3) — the token twin of
    /// [`client_subs`](Self#structfield.client_subs), but keyed the way zenoh's
    /// `face_hat.remote_tokens: HashMap<TokenId, Arc<Resource>>` is
    /// (`hat/router/token.rs:303`): the client's DECL ID -> the resolved keyexpr,
    /// NOT a lossy keyexpr set. RATIONALE: a real client (incl wz's own —
    /// `session_actions.rs::send_undeclare_token` -> `build_undeclare_token(id)`)
    /// gracefully retracts a token with an ID-KEYED `UndeclareToken(id, ext=null)`
    /// carrying NO keyexpr on the wire; only an id map can resolve that retraction
    /// (zenoh `forget_simple_token` removes by id, token.rs:276). Keeping the id
    /// also gives correct per-token refcount when two tokens share a keyexpr.
    /// A Client face is HELD with no mesh, so — like `client_subs` — this leaf
    /// state MUST be purged by [`deregister`](FaceForwarder::deregister) BEFORE its
    /// linkless early-return (OBLIGATION 1). The cross-tier ADVERTISEMENT of a
    /// client-held token into BOTH meshes is
    /// [`advertise_client_cross_tier_token`](Self::advertise_client_cross_tier_token)
    /// (derive-not-store: self is never stored in a mesh token table).
    /// SLICE-4 OBLIGATION: because a client token is derive-not-store (kept OUT of
    /// the mesh tables), `declare_token_interest`'s CURRENT-state replay must FOLD
    /// `client_tokens` (excluding the requester) — the twin of `dump_interest_subs`
    /// folding `client_subs` — else a client-sourced token is invisible to a
    /// token-interest reader on this router.
    #[cfg(feature = "routing-token-tables")]
    client_tokens: RefCell<HashMap<FaceId, HashMap<u64, String>>>,
    /// Per-CLIENT-face subscription store (C2) — zenoh's per-`Resource`
    /// `session_ctxs` leaf input, keyed by the client's [`FaceId`] (a Client face
    /// is HELD with no mesh, so its interest cannot live in a Zid-keyed tier
    /// table). This is the SSOT contributor to `cross_tier_self_source`: a client
    /// subscribing `K` makes SELF a virtual sub-source that is ADVERTISED into the
    /// meshes (a self-sourced `DeclareSubscriber` flooded to self's tree children,
    /// self NOT stored in the tier tables — derive-not-store), so a mesh publisher
    /// routes `K` toward this router. FaceId-keyed leaf state, so
    /// [`deregister`](FaceForwarder::deregister) MUST purge it BEFORE its linkless
    /// early-return (OBLIGATION 1). C2 is the ADVERTISEMENT half; the cross-tier
    /// DATA delivery TO these clients is C3a
    /// ([`deliver_to_client_subscribers`](RouterForwarder::deliver_to_client_subscribers)).
    ///
    /// CARRIED FOLLOW-UP (id-map): still KEYEXPR-keyed, so a client's ID-ONLY graceful
    /// `UndeclareSubscriber` (no `ext_keyexpr`) no-ops in `withdraw_client_subscription` ->
    /// stale until face-down. The wz-PEER client-sub/qabl planes were converted to id-keyed
    /// at R311y178 (and `client_tokens` above at slice-3); the router client_subs/client_qabls
    /// are the remaining keyexpr-keyed holdouts — the symmetric id-map fix is a named follow-up.
    client_subs: RefCell<HashMap<FaceId, HashSet<String>>>,
    /// Per-CLIENT-face QUERYABLE store (C5b) — the query-plane twin of
    /// [`client_subs`](Self#structfield.client_subs): zenoh's per-`Resource`
    /// `session_ctxs[..].qabl` leaf input, keyed by the client's [`FaceId`] and, per
    /// hosted keyexpr, the declared [`QueryableInfo`] (`complete` / `distance`) the
    /// query route reads. A Client face is HELD with no mesh, so a client-hosted
    /// queryable cannot live in a Zid-keyed tier table (`router_qabls` /
    /// `linkstatepeer_qabls`); it lands here instead. [`route_request`](Self::route_request)
    /// routes a Request TOWARD these client queryables (zenoh `compute_query_route`
    /// block 3, `hat/router/queries.rs:1499`, gated `master || source == Router`);
    /// their completeness feeds the GLOBAL BestMatching at distance 1. FaceId-keyed
    /// leaf state, so [`deregister`](FaceForwarder::deregister) MUST purge it BEFORE
    /// its linkless early-return (OBLIGATION 1), like `client_subs`. A3 landed the
    /// cross-tier ADVERTISEMENT of these queryables into BOTH meshes (the query-plane
    /// twin of C2's `advertise_client_cross_tier_sub`, so a REMOTE mesh querier routes
    /// toward this router):
    /// [`advertise_client_cross_tier_qabl`](Self::advertise_client_cross_tier_qabl) on
    /// ingest, and a downgrade re-advertise on face-down. This store is also a
    /// contributor to the merged
    /// [`derived_cross_tier_qabl_info`](Self::derived_cross_tier_qabl_info).
    ///
    /// CARRIED FOLLOW-UP (id-map): still KEYEXPR-keyed, so a client's ID-ONLY graceful
    /// `UndeclareQueryable` no-ops in `withdraw_client_queryable` -> stale until face-down.
    /// The symmetric id-map fix (the wz-peer planes got it at R311y178) is a named follow-up.
    client_qabls: RefCell<HashMap<FaceId, HashMap<String, QueryableInfo>>>,
    /// Queryables HOSTED BY THIS ROUTER (§5.23 `adminspace-router-linkstate`) —
    /// e.g. the built-in admin queryable on `@/<self-zid>/router/**`. The
    /// router-idiom `derive-not-store` analogue of the peer
    /// [`LinkstateForwarder`]'s `local_queryables`: the store FEEDS the cross-tier
    /// derive ([`derived_cross_tier_qabl_info`](Self::derived_cross_tier_qabl_info)
    /// / [`derived_cross_tier_qabls_into`](Self::derived_cross_tier_qabls_into)), so
    /// a self-hosted queryable advertises into BOTH meshes + re-advertises to
    /// late-joining tree children UNIFORMLY with `client_qabls` and the multicast
    /// group-sub aggregate (the proven self-sourced-into-derive precedents). A GET
    /// whose only match is a self-hosted queryable self-dispatches to its handler
    /// at the [`route_request`](Self::route_request) empty-route tail (self is
    /// excluded from the routing targets). Always compiled (like `client_qabls`);
    /// the `adminspace-router-linkstate` cfg gates only the demo registration + the
    /// session-core answerer, so an unused registry is a harmless empty no-op.
    local_queryables: RefCell<Vec<LocalQueryable>>,
    /// FUTURE-mode subscriber-interest store (R311y146) — which CLIENT faces
    /// declared a FUTURE (`f()`) subscriber `Interest`, and which
    /// `DeclareSubscriber`s wz has pushed back to them (zenoh's per-`FaceState`
    /// `remote_interests` + `face_hat.local_subs`). The CURRENT half of the
    /// handshake is [`respond_to_interest`](Self::respond_to_interest)'s dump; this
    /// is the FUTURE half: a subscriber learned LATER
    /// ([`ingest_subscription`](Self::ingest_subscription) /
    /// [`ingest_client_subscription`](Self::ingest_client_subscription)) is
    /// proactively pushed via [`push_future_subscription`](Self::push_future_subscription)
    /// so a pub-BEFORE-sub publisher's write-filter deactivates. FaceId-keyed leaf
    /// state, so [`deregister`](FaceForwarder::deregister) MUST purge it BEFORE its
    /// linkless early-return (OBLIGATION 1), like `client_subs`. SUBS plane only
    /// (the QABL future-push is the value-aware [`future_qabls`](Self#structfield.future_qabls)).
    future_subs: RefCell<FutureSubStore>,
    /// The QUERYABLE-plane FUTURE store (R311y150) — the value-aware twin of
    /// [`future_subs`](Self#structfield.future_subs): a queryable learned LATER
    /// ([`ingest_queryable`](Self::ingest_queryable) /
    /// [`ingest_client_queryable`](Self::ingest_client_queryable)) is proactively
    /// pushed via [`push_future_queryable`](Self::push_future_queryable) so a
    /// querier-BEFORE-queryable querier's write-filter deactivates, and a
    /// completeness flip re-pushes the same id. Same OBLIGATION-1 purge as
    /// `future_subs`.
    future_qabls: RefCell<FutureQablStore>,
    /// §5.21 routing-token-tables (slice-4) — the liveliness-TOKEN FUTURE store,
    /// the token twin of [`future_subs`](Self#structfield.future_subs) (both
    /// `FutureInterestStore<()>` — tokens carry no value). A CLIENT face's FUTURE
    /// (`f()`) TOKEN interest is stored here so a token learned LATER
    /// ([`ingest_token`](Self::ingest_token) / [`ingest_client_token`](Self::ingest_client_token))
    /// is proactively pushed via [`push_future_token`](Self::push_future_token). The
    /// CURRENT dump ([`dump_interest_tokens`](Self::dump_interest_tokens)) is the
    /// FIRST reader of the token tables — it makes the slice-1/2/3 bubble observable.
    /// Same OBLIGATION-1 purge as `future_subs`. The withdraw->notify twin of
    /// `undeclare_push_subs` — [`undeclare_push_token`](Self::undeclare_push_token) —
    /// is WIRED (slice-5) at all 5 token-removal sites (graceful mesh/client withdraw,
    /// ungraceful detach, id-reuse displacement, client face-down), so a future-push
    /// reader IS told a token withdrew: the liveliness stale-live residual is CLOSED.
    #[cfg(feature = "routing-token-tables")]
    future_tokens: RefCell<FutureSubStore>,
    /// The pending-query return table (C5b) — one entry per outbound Request,
    /// keyed by the out face + a per-face local qid, recording where the matching
    /// `Response` / `ResponseFinal` routes back (the querier's inbound face + rid).
    /// [`route_request`](Self::route_request) ALLOCATES an entry per forwarded
    /// Request; the reverse Response route (peek/take) + the timeout sweep are C5c.
    /// The standalone [`PendingQueries`] struct is reused verbatim (the same one the
    /// single-net [`LinkstateForwarder`](crate::linkstate_forward) holds).
    pending: RefCell<PendingQueries>,
    /// Running total of `Request` (Query) messages received — the query-plane
    /// reception witness, the query twin of
    /// [`data_seen`](Self#structfield.data_seen).
    queries_seen: Cell<usize>,
    /// The per-query timeout (zenoh `queries_default_timeout`, 10s) — how long a
    /// forwarded Query's pending return entry lives before the C5c tick sweep
    /// abandons it. [`route_request`](Self::route_request) stamps each allocated
    /// entry with [`now`](Self::now)` + this`. `Cell` (it is `Copy`, set through a
    /// `&self` config seam), the same knob the single-net forwarder carries.
    query_timeout: Cell<Duration>,
    /// Count of pending queries reaped by the timeout sweep (C5c) — the GC
    /// witness, the router twin of the single-net forwarder's `timed_out`. Rises
    /// once per abandoned BRANCH (a queryable that never sent its `ResponseFinal`
    /// on a still-up face; a 2-branch fan expiring counts 2); `0` on a healthy
    /// mesh where every branch finalizes.
    timed_out: Cell<usize>,
    /// Running total of link-state lists ingested across both nets — the
    /// control-plane work witness (the router twin of
    /// `LinkstateForwarder::ingested`).
    ingested: Cell<usize>,
    /// Running total of data `Push` messages received — the data-plane
    /// reception witness, raised ONCE on EVERY inbound Push before it is routed.
    /// The WITHIN-tier mesh fan-out that consumes it is
    /// [`forward_push_tier`](RouterForwarder::forward_push_tier) (C1); a Client-tier
    /// Push (no within-tier mesh) instead reaches subscribing clients (C3a) and is
    /// re-injected into the meshes (C3b,
    /// [`publish_client_push_into_meshes`](RouterForwarder::publish_client_push_into_meshes)),
    /// and, when self is the route master, BRIDGED to the other mesh (C4,
    /// [`bridge_push_cross_mesh`](RouterForwarder::bridge_push_cross_mesh)).
    data_seen: Cell<usize>,
    /// C4 double-delivery guard witness: the number of local-client deliveries a
    /// NON-master router DEFERRED (block-3 master gate) — the peer/client-source
    /// copy suppressed in favour of the master's bridged router-source copy. A
    /// POSITIVE observable that self was non-master for a keyexpr its client
    /// subscribes AND correctly deferred; the guard is otherwise E2E-invisible (a
    /// correct guard delivers the client zero peer-source copies, same as a
    /// black-hole — only the counter distinguishes "suppressed a duplicate" from
    /// "never had one").
    deferred_client_delivery: Cell<usize>,
    /// I3c loop-safety witnesses (mcast-ingress DR plane). `mcast_ingress_federated`
    /// / `_suppressed` count the two arms of the per-keyexpr DR gate at
    /// [`route_push`](Self::route_push): federated when this router is the group DR
    /// for the keyexpr, suppressed when it is not. The two-router e2e proof asserts
    /// exactly ONE of two group-sharing routers federates a keyexpr (single bridge
    /// = loop-free by construction). `mcast_member_peak` is the high-water on-group
    /// ROUTER member count relayed via
    /// [`set_mcast_group_members`](Self::set_mcast_group_members) — a non-zero peak
    /// witnesses that the JOIN->router_member_zids->relay->set chain ran e2e (the
    /// leg the I3b unit tests inject past).
    #[cfg(feature = "router-multicast-faces")]
    mcast_ingress_federated: Cell<usize>,
    #[cfg(feature = "router-multicast-faces")]
    mcast_ingress_suppressed: Cell<usize>,
    #[cfg(feature = "router-multicast-faces")]
    mcast_member_peak: Cell<usize>,
    /// §5.21 sub plane (S2/S3) — high-water count of DISTINCT on-group subscriber
    /// keyexprs this router has advertised into the unicast mesh via
    /// [`set_mcast_group_subs`](Self::set_mcast_group_subs). A non-zero peak
    /// witnesses that the group-sub INGEST -> relay -> mesh-advertise chain ran e2e
    /// (a cross-impl reachability test gates a mesh-side PUBLISHER on this, proving
    /// the router holds + advertised the on-group subscriber's interest before the
    /// Put — the sub-plane twin of the I3b `mcast_member_peak` barrier).
    #[cfg(feature = "router-multicast-faces")]
    group_subs_advertised_peak: Cell<usize>,
    /// Running total of unsolicited FUTURE `DeclareSubscriber` pushes emitted by
    /// [`push_future_subscription`](Self::push_future_subscription) — the y146
    /// proactive-push witness. Rises once per CLIENT face actually told a
    /// newly-learned subscription (a pub-before-sub publisher's write-filter
    /// deactivation cause). A reverse-data e2e where the publisher declares
    /// BEFORE any subscriber asserts this to distinguish the FUTURE push from a
    /// raced CURRENT interest dump (which logs nothing either) — without it the
    /// two paths are separable only by timing.
    future_pushes: Cell<usize>,
    /// Running total of unsolicited FUTURE `DeclareQueryable` pushes emitted by
    /// [`push_future_queryable`](Self::push_future_queryable) — the R311y150
    /// query-plane proactive-push witness (twin of
    /// [`future_pushes`](Self#structfield.future_pushes)). Rises once per CLIENT
    /// face told a newly-learned OR completeness-flipped queryable.
    future_qabl_pushes: Cell<usize>,
    /// §5.21 routing-token-tables (slice-4) — running total of unsolicited FUTURE
    /// `DeclareToken` pushes emitted by [`push_future_token`](Self::push_future_token),
    /// the token twin of [`future_pushes`](Self#structfield.future_pushes). Rises once
    /// per CLIENT face told a newly-learned token; the proactive-push witness a test
    /// asserts to separate the FUTURE push from a raced CURRENT dump.
    #[cfg(feature = "routing-token-tables")]
    future_token_pushes: Cell<usize>,
    /// §5.16 access-control INGRESS interceptor chain — consulted at the top of
    /// [`forward`](FaceForwarder::forward) before the kind-dispatch, the router twin
    /// of [`LinkstateForwarder`](crate::linkstate_forward)'s `ingress_interceptors`.
    /// Empty (admits everything) until [`set_interceptors`](Self::set_interceptors).
    ingress_interceptors: RefCell<InterceptorChain>,
    /// §5.16 access-control EGRESS interceptor chain — consulted per outbound
    /// message in [`fan_out_tier`](Self::fan_out_tier) + [`send_to_face`](Self::send_to_face),
    /// the router twin of the single-net `egress_interceptors`. This closes the
    /// y113 obligation: the router's egress helpers now carry the same
    /// `admit_outbound` gate the single-net `fan_out` has (the one router↔single-net
    /// data-path parity gap).
    egress_interceptors: RefCell<InterceptorChain>,
    /// Count of messages ANY interceptor dropped on either flow — the router twin
    /// of the single-net `interceptor_dropped` witness (a coarse per-node count, not
    /// per-interceptor). `0` in any config with no ACL wired.
    interceptor_dropped: Cell<usize>,
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
    /// The monotonic clock the pending-query deadlines are stamped from (C5b) and
    /// reaped against (C5c) — [`Box`]ed so a deterministic test injects a
    /// controllable `base + offset` closure via [`with_clock`](Self::with_clock),
    /// exactly as the single-net [`LinkstateForwarder`](crate::linkstate_forward)
    /// does. Production is `Instant::now`.
    clock: Box<dyn Fn() -> Instant>,
    /// R311y450 — THIS router's §5.18 wall-clock HLC, the source of the
    /// forward-path timestamp [`route_push`](Self::route_push) applies. A distinct
    /// axis from `clock` above (that one is the opaque MONOTONIC clock for query
    /// deadlines; this one is a wall-clock NTP64 that reaches the wire).
    ///
    /// This is the role that STAMPS. zenoh ships `timestamping.enabled:
    /// { router: true, peer: false, client: false }`
    /// (`DEFAULT_CONFIG.json5:206`) and this forwarder is a `WhatAmI::Router` in
    /// both meshes by construction, so — unlike the linkstate-peer forwarder,
    /// whose clock is `None` under the same default — a `time-hlc` build of this
    /// forwarder really does add timestamps to un-timestamped Puts it relays.
    /// That makes the forward stamp FOREIGN-OBSERVABLE here: a pico subscriber
    /// prints `with timestamp:` for a Put that entered this router bare.
    node_hlc: crate::node_clock::NodeHlc,
}

impl RouterForwarder {
    /// The SPF-throttle coalescing window — the SAME default the single-net
    /// [`LinkstateForwarder`](crate::linkstate_forward::LinkstateForwarder)
    /// uses (zenoh's `TREES_COMPUTATION_DELAY_MS`), referenced rather than
    /// re-literal-ed so the two forwarders share one source of the value.
    pub const DEFAULT_TREES_DELAY: Duration =
        crate::linkstate_forward::LinkstateForwarder::DEFAULT_TREES_DELAY;

    /// The default per-query timeout — zenoh's `queries_default_timeout` (10s),
    /// referenced from the single-net forwarder so the two share ONE source of the
    /// value. A forwarded Query's pending return entry is abandoned this long after
    /// it is recorded if no `ResponseFinal` routes back (the C5c tick sweep). A
    /// deploy overrides via [`set_query_timeout`](Self::set_query_timeout).
    pub const DEFAULT_QUERY_TIMEOUT: Duration =
        crate::linkstate_forward::LinkstateForwarder::DEFAULT_QUERY_TIMEOUT;

    /// A router driver seeded with the local node (`self_zid`), using the
    /// production `Instant::now` clock. Self is a `WhatAmI::Router` in BOTH meshes,
    /// so both nets are constructed with [`WhatAmI::Router`].
    pub fn new(self_zid: Zid) -> Self {
        Self::with_clock(self_zid, Box::new(Instant::now))
    }

    /// As [`new`](Self::new), but with an INJECTED monotonic clock — the dependency
    /// injection a deterministic pending-query-timeout test uses to advance "now"
    /// across a deadline (the router twin of
    /// [`LinkstateForwarder::with_clock`](crate::linkstate_forward::LinkstateForwarder::with_clock)).
    pub fn with_clock(self_zid: Zid, clock: Box<dyn Fn() -> Instant>) -> Self {
        Self {
            routers_net: Rc::new(RefCell::new(LinkstateNetwork::new(
                self_zid,
                WhatAmI::Router,
            ))),
            linkstatepeers_net: Rc::new(RefCell::new(LinkstateNetwork::new(
                self_zid,
                WhatAmI::Router,
            ))),
            // R311y450 — this router's §5.18 clock, over the SAME `WhatAmI::Router`
            // both nets above are seeded with, so the timestamping gate cannot
            // disagree with the role. Router is the one role zenoh's shipped map
            // enables, which is why the stamp is live on this forwarder.
            node_hlc: crate::node_clock::NodeHlc::for_node(
                self_zid.as_slice(),
                WhatAmI::Router,
                crate::node_clock::TimestampingEnabled::default(),
            ),
            faces: RefCell::new(HashMap::new()),
            #[cfg(feature = "transport-multicast")]
            mcast_groups: RefCell::new(Vec::new()),
            #[cfg(feature = "router-multicast-faces")]
            mcast_group_members: RefCell::new(Vec::new()),
            #[cfg(feature = "router-multicast-faces")]
            group_subs: RefCell::new(HashSet::new()),
            router_subs: RefCell::new(LinkstatepeerInterest::new()),
            linkstatepeer_subs: RefCell::new(LinkstatepeerInterest::new()),
            router_qabls: RefCell::new(LinkstatepeerInterest::new()),
            linkstatepeer_qabls: RefCell::new(LinkstatepeerInterest::new()),
            #[cfg(feature = "routing-token-tables")]
            router_tokens: RefCell::new(LinkstatepeerInterest::new()),
            #[cfg(feature = "routing-token-tables")]
            linkstatepeer_tokens: RefCell::new(LinkstatepeerInterest::new()),
            #[cfg(feature = "routing-token-tables")]
            client_tokens: RefCell::new(HashMap::new()),
            client_subs: RefCell::new(HashMap::new()),
            client_qabls: RefCell::new(HashMap::new()),
            local_queryables: RefCell::new(Vec::new()),
            future_subs: RefCell::new(FutureSubStore::new()),
            future_qabls: RefCell::new(FutureQablStore::new()),
            #[cfg(feature = "routing-token-tables")]
            future_tokens: RefCell::new(FutureSubStore::new()),
            pending: RefCell::new(PendingQueries::new()),
            queries_seen: Cell::new(0),
            query_timeout: Cell::new(Self::DEFAULT_QUERY_TIMEOUT),
            timed_out: Cell::new(0),
            ingested: Cell::new(0),
            data_seen: Cell::new(0),
            deferred_client_delivery: Cell::new(0),
            #[cfg(feature = "router-multicast-faces")]
            mcast_ingress_federated: Cell::new(0),
            #[cfg(feature = "router-multicast-faces")]
            mcast_ingress_suppressed: Cell::new(0),
            #[cfg(feature = "router-multicast-faces")]
            mcast_member_peak: Cell::new(0),
            #[cfg(feature = "router-multicast-faces")]
            group_subs_advertised_peak: Cell::new(0),
            future_pushes: Cell::new(0),
            future_qabl_pushes: Cell::new(0),
            #[cfg(feature = "routing-token-tables")]
            future_token_pushes: Cell::new(0),
            ingress_interceptors: RefCell::new(InterceptorChain::new()),
            egress_interceptors: RefCell::new(InterceptorChain::new()),
            interceptor_dropped: Cell::new(0),
            trees_dirty_routers: Cell::new(false),
            trees_dirty_peers: Cell::new(false),
            recomputes: Cell::new(0),
            trees_delay: Self::DEFAULT_TREES_DELAY,
            clock,
        }
    }

    /// Override the per-query timeout (zenoh's `queries_default_timeout`) — the
    /// same `&self` config seam the single-net forwarder exposes. Takes effect on
    /// the NEXT [`route_request`](Self::route_request); already-recorded deadlines
    /// are not retroactively changed.
    pub fn set_query_timeout(&self, timeout: Duration) {
        self.query_timeout.set(timeout);
    }

    /// Number of nodes in the ROUTER-tier graph (self + every learned Router) —
    /// the `routers_net` state witness. The dual-tier router twin of
    /// [`LinkstateForwarder::node_count`](crate::linkstate_forward::LinkstateForwarder::node_count);
    /// exposed as its own method (not a `(usize, usize)` tuple with the peer
    /// count) so each mirrors the field it reads and a caller cannot transpose
    /// them. A single-router topology (no Router faces) reads 1 (self alone).
    pub fn routers_net_node_count(&self) -> usize {
        self.routers_net.borrow().node_count()
    }

    /// Number of nodes in the PEER-tier graph (self + every learned Peer) — the
    /// `linkstatepeers_net` state witness, the sibling of
    /// [`routers_net_node_count`](Self::routers_net_node_count). A router serving
    /// N connected peers reads `1 + N` once converged (the E2E convergence
    /// witness the ACTIVATION harness asserts on).
    pub fn linkstatepeers_net_node_count(&self) -> usize {
        self.linkstatepeers_net.borrow().node_count()
    }

    /// Total link-state lists ingested across both nets — the control-plane
    /// convergence witness (name-matched to
    /// [`LinkstateForwarder::ingested`](crate::linkstate_forward::LinkstateForwarder::ingested)).
    /// Rising above zero proves this router ingested a neighbour's link-state
    /// flood, i.e. topology converged over the wire (not merely that a face is
    /// held).
    pub fn ingested(&self) -> usize {
        self.ingested.get()
    }

    /// Total data `Push` messages received across all faces — the data-plane
    /// TRANSIT witness (name-matched to
    /// [`LinkstateForwarder::data_seen`](crate::linkstate_forward::LinkstateForwarder::data_seen)).
    /// Raised once at the `Push` dispatch arm, immediately before
    /// [`route_push`](Self::route_push) routes it — on EVERY inbound Push, so a
    /// pure router that hosts no subscription still counts a Push it forwarded —
    /// the "delivery went THROUGH this router" proof the ACTIVATION harness
    /// asserts on.
    pub fn data_seen(&self) -> usize {
        self.data_seen.get()
    }

    /// C4 double-delivery guard witness — the number of local-client deliveries a
    /// NON-master router deferred (block-3 master gate). `> 0` proves self was
    /// non-master for a keyexpr its client subscribes and SUPPRESSED the duplicate
    /// peer/client-source copy (the master's bridged router-source copy is what
    /// delivers, exactly once). The non-master-corner E2E asserts this positive
    /// observable — a broken guard leaves it at 0 (and double-delivers the client).
    pub fn deferred_client_delivery_seen(&self) -> usize {
        self.deferred_client_delivery.get()
    }

    /// I3c — count of mcast-ingress Pushes this router FEDERATED into the mesh as
    /// the group DR (the loop-safety witness: exactly one of two group-sharing
    /// routers federates a given keyexpr).
    #[cfg(feature = "router-multicast-faces")]
    pub fn mcast_ingress_federated(&self) -> usize {
        self.mcast_ingress_federated.get()
    }

    /// I3c — count of mcast-ingress Pushes this router SUPPRESSED (it was NOT the
    /// group DR): the non-DR arm of the same per-keyexpr election.
    #[cfg(feature = "router-multicast-faces")]
    pub fn mcast_ingress_suppressed(&self) -> usize {
        self.mcast_ingress_suppressed.get()
    }

    /// I3c — high-water on-group ROUTER member count (the DR election candidate set
    /// relayed from the multicast ingress loop). `>= 1` witnesses that the
    /// JOIN->router_member_zids->relay->set_mcast_group_members chain ran e2e.
    #[cfg(feature = "router-multicast-faces")]
    pub fn mcast_member_peak(&self) -> usize {
        self.mcast_member_peak.get()
    }

    /// §5.21 sub plane (S2/S3) — high-water count of on-group subscriber keyexprs
    /// advertised into the unicast mesh. `>= 1` witnesses that the group-sub
    /// INGEST->relay->mesh-advertise chain ran e2e (the reachability barrier a
    /// mesh-side publisher gates on before publishing).
    #[cfg(feature = "router-multicast-faces")]
    pub fn group_subs_advertised_peak(&self) -> usize {
        self.group_subs_advertised_peak.get()
    }

    /// Total `Request(Query)` messages received across all faces — the query-plane
    /// TRANSIT witness (the query twin of [`data_seen`](Self::data_seen)). Raised
    /// once at the `Request` dispatch arm, immediately before
    /// [`route_request`](Self::route_request) routes it — on EVERY inbound Query, so a
    /// pure router that hosts no local queryable still counts a Query it forwarded.
    /// The 2-router query-federation e2e asserts this on BOTH routers to pin the
    /// query's cross-mesh transit from the routers' own logs (not topology alone).
    pub fn queries_seen(&self) -> usize {
        self.queries_seen.get()
    }

    /// Total unsolicited FUTURE `DeclareSubscriber` pushes emitted — the y146
    /// proactive-push witness ([`future_pushes`](Self#structfield.future_pushes)).
    /// A `>0` value proves this router told at least one CLIENT face a
    /// subscription it learned AFTER that face's FUTURE interest, the sole wz
    /// cause of a pub-before-sub publisher's write-filter deactivation. The
    /// FUTURE-mode reverse-data e2e asserts it to prove the push fired, not a
    /// raced CURRENT dump.
    pub fn future_pushes_seen(&self) -> usize {
        self.future_pushes.get()
    }

    /// Total unsolicited FUTURE `DeclareQueryable` pushes emitted — the R311y150
    /// query-plane proactive-push witness
    /// ([`future_qabl_pushes`](Self#structfield.future_qabl_pushes)). A `>0` value
    /// proves this router told a CLIENT face a queryable it learned AFTER that
    /// face's FUTURE interest (or a completeness flip), the sole wz cause of a
    /// querier-before-queryable querier's write-filter deactivation. Surfaced by
    /// `wz-ap-demo`'s `run_router_hat` as `router-hat: pushed a future queryable`
    /// (R311y156), consumed by the querier-before-queryable cross-impl legs 7 & 8 of
    /// `wz_router_hat_zenohd_interop` — the query twin of the sub
    /// [`future_pushes_seen`](Self::future_pushes_seen) witness / leg 5.
    pub fn future_qabl_pushes_seen(&self) -> usize {
        self.future_qabl_pushes.get()
    }

    /// §5.21 routing-token-tables (slice-4) — total unsolicited FUTURE
    /// `DeclareToken` pushes emitted ([`future_token_pushes`](Self#structfield.future_token_pushes)),
    /// the token twin of [`future_pushes_seen`](Self::future_pushes_seen). A `>0`
    /// value proves this router told a CLIENT face a liveliness token it learned
    /// AFTER that face's FUTURE token interest — the witness a test asserts to
    /// separate the FUTURE push from a raced CURRENT dump.
    #[cfg(feature = "routing-token-tables")]
    pub fn future_token_pushes_seen(&self) -> usize {
        self.future_token_pushes.get()
    }

    /// Total distinct queryable interests this router currently holds across all
    /// tiers — client-hosted ([`client_qabls`](Self#structfield.client_qabls)) +
    /// mesh-native (`router_qabls` + `linkstatepeer_qabls`). The query-plane
    /// READINESS witness the ACTIVATION query e2e gates the issuer spawn on: a `>0`
    /// value proves R ingested a queryable's `DeclareQueryable` BEFORE the issuer
    /// fires its one-shot query, making that e2e a barrier rather than a race.
    pub fn queryables_seen(&self) -> usize {
        let client: usize = self.client_qabls.borrow().values().map(|m| m.len()).sum();
        let router = self.router_qabls.borrow().count();
        let peer = self.linkstatepeer_qabls.borrow().count();
        client + router + peer
    }

    /// Total distinct client-hosted subscriptions this router currently holds
    /// ([`client_subs`](Self#structfield.client_subs)). The data-plane READINESS
    /// witness — the twin of [`queryables_seen`](Self::queryables_seen): a `>0` value
    /// proves R installed a client's `DeclareSubscriber` in `client_subs`, letting a
    /// data e2e gate a publisher spawn on a router-CONFIRMED subscription rather than
    /// racing declare-propagation with a Put burst.
    pub fn client_subs_seen(&self) -> usize {
        self.client_subs.borrow().values().map(|s| s.len()).sum()
    }

    /// Total mesh-native subscriptions this router currently holds
    /// (`router_subs` + `linkstatepeer_subs`) — the REVERSE-data READINESS
    /// witness, the mesh twin of [`client_subs_seen`](Self::client_subs_seen). A
    /// `>0` value proves R has INGESTED a peer router's (e.g. zenohd's)
    /// `DeclareSubscriber` off the mesh, letting a reverse-data e2e (publisher
    /// behind THIS router -> subscriber behind the peer) gate the publisher spawn
    /// on a router-CONFIRMED remote subscription. Required because a pico
    /// publisher's write-filter deactivates only once wz answers its Interest with
    /// a matching sub — which needs wz to already hold that sub HERE; an empty
    /// CURRENT dump leaves the filter active and the puts never reach the wire.
    pub fn mesh_subs_seen(&self) -> usize {
        let router = self.router_subs.borrow().count();
        let peer = self.linkstatepeer_subs.borrow().count();
        router + peer
    }

    /// Install the full §5.16 interceptor configuration — the router twin of
    /// [`LinkstateForwarder::set_interceptors`](crate::linkstate_forward::LinkstateForwarder::set_interceptors).
    /// Builds BOTH the ingress and egress chains from ONE [`InterceptorConfig`] in
    /// zenoh's fixed factory order; a later call REPLACES both (no accumulation), so
    /// a re-config is idempotent. Empty config -> both chains empty -> every message
    /// admitted (the default). Denials are counted by
    /// [`interceptor_dropped`](Self::interceptor_dropped).
    pub fn set_interceptors(&self, config: InterceptorConfig) {
        *self.ingress_interceptors.borrow_mut() = config.build_chain(InterceptorFlow::Ingress);
        *self.egress_interceptors.borrow_mut() = config.build_chain(InterceptorFlow::Egress);
    }

    /// The number of messages ANY interceptor has dropped so far (ACL denial on
    /// either flow) — the router twin of the single-net drop witness.
    pub fn interceptor_dropped(&self) -> usize {
        self.interceptor_dropped.get()
    }

    /// Whether the INGRESS chain admits this inbound `msg` arriving on face `id` —
    /// the router twin of
    /// [`LinkstateForwarder::admit_inbound`](crate::linkstate_forward::LinkstateForwarder).
    /// Consulted at the top of [`forward`](FaceForwarder::forward) ahead of the
    /// kind-dispatch. Empty chain (no ACL) admits without touching the face table.
    fn admit_inbound(&self, id: FaceId, msg: &NetworkMessage) -> bool {
        let chain = self.ingress_interceptors.borrow();
        if chain.is_empty() {
            return true;
        }
        let faces = self.faces.borrow();
        let Some(face) = faces.get(&id) else {
            return true; // an unknown face has no relay path anyway
        };
        chain.admit(&RouterFaceContext { face }, msg)
    }

    /// Whether the EGRESS chain admits sending `msg` to the face whose `state` the
    /// caller already holds — the router twin of the single-net `admit_outbound`.
    /// Takes the already-borrowed `state` (not a `FaceId`) because the egress seams
    /// ([`fan_out_tier`](Self::fan_out_tier)) hold the `faces` borrow across the
    /// per-face loop. Empty chain admits without building a context.
    fn admit_outbound(&self, state: &RouterFaceState, msg: &NetworkMessage) -> bool {
        let chain = self.egress_interceptors.borrow();
        if chain.is_empty() {
            return true;
        }
        chain.admit(&RouterFaceContext { face: state }, msg)
    }

    /// The current instant from the injected clock — the single read site the
    /// pending-query deadline stamp ([`route_request`](Self::route_request)) and
    /// the C5c timeout sweep will share, so an injected test clock governs both.
    fn now(&self) -> Instant {
        (self.clock)()
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
        build: impl FnMut(FaceId, Option<Zid>) -> Result<Option<NetworkMessage>, CodecError>,
    ) -> Result<usize, CodecError> {
        // R311y224 — the DEFAULT-priority, non-express tier fan-out: every
        // control-plane caller (flood_*_tier / declare re-floods / the client-egress
        // `deliver_to_client_subscribers`) routes through here byte-identically to the
        // prior hard-coded `send_network_message(msg, reliable, false)`. The
        // band-carrying transit callers go to `fan_out_tier_qos` directly:
        // `forward_push_tier` (a within-tier re-forward) and `self_publish_into_tier`
        // (the cross-mesh bridge + client->mesh re-inject), both preserving the
        // received `FramePayload.priority` — the router twin of the peer plane's
        // `fan_out` / `fan_out_qos` split (R311y220/y221).
        self.fan_out_tier_qos(tier, reliable, Priority::DEFAULT, false, build)
    }

    /// R311y224 — the priority-carrying tier fan-out: identical to
    /// [`Self::fan_out_tier`] except each admitted per-face send routes `priority` +
    /// `express` through [`send_network_message_qos`](wz_session_core::session_actions)
    /// so an aggregated QoS multilink mesh peer pins the fan-out onto the
    /// priority-band link (`select_link`) and re-encodes ext_qos = the band.
    /// [`Self::fan_out_tier`] is the `(Priority::DEFAULT, express = false)`
    /// specialization every control-plane caller takes. TRANSIT PRESERVATION
    /// (R311y224): the router-tier re-forwards route through here on the received
    /// band — [`forward_push_tier`](Self::forward_push_tier) (within-tier) plus
    /// [`self_publish_into_tier`](Self::self_publish_into_tier) (the C4 cross-mesh
    /// bridge + the C3b client->mesh re-inject) — so a band survives a router relay
    /// hop end-to-end. The router twin of the peer plane's `forward_push` ->
    /// `fan_out_qos` (R311y221), and the zenoh `route_data` `ext_qos` copy
    /// (`net/routing/dispatcher/pubsub.rs`) restricted to the priority sub-field wz
    /// decodes. DEFAULT under a non-QoS session (the `dispatch_push` clamp), so
    /// byte-identical to the prior `fan_out_tier` on every non-QoS transit. R311y225
    /// extended the same preservation to the CLIENT-face egress
    /// [`deliver_to_client_subscribers`](Self::deliver_to_client_subscribers) (this
    /// plane + the peer plane's twin), so a QoS-negotiated client observes the band too
    /// (a pico client, which negotiates no unicast ext_qos, keeps DEFAULT). RESIDUAL
    /// (still DEFAULT, named honestly): `broadcast_to_mcast_groups` (the multicast
    /// plane is a structural 2-channel, no per-priority conduit) and the QUERY-plane
    /// client egress (a Response to a client querier -- a separate, uniformly-DEFAULT
    /// plane).
    fn fan_out_tier_qos(
        &self,
        tier: FaceTier,
        reliable: bool,
        priority: Priority,
        express: bool,
        mut build: impl FnMut(FaceId, Option<Zid>) -> Result<Option<NetworkMessage>, CodecError>,
    ) -> Result<usize, CodecError> {
        let mut sent = 0;
        for (id, state) in self.faces.borrow().iter() {
            if state.tier != tier {
                continue;
            }
            let peer_zid = peer_zid_routing(&state.actions);
            if let Some(msg) = build(*id, peer_zid)? {
                // §5.16 EGRESS access control (y113): gate the built message by the
                // DESTINATION face's subject before it leaves — a denied outbound is
                // dropped for THIS face (not sent, not counted) and witnessed. The
                // router twin of `LinkstateForwarder::fan_out`'s `admit_outbound`
                // gate; empty chain (no ACL) is a no-op fast path.
                if !self.admit_outbound(state, &msg) {
                    self.interceptor_dropped
                        .set(self.interceptor_dropped.get() + 1);
                    continue;
                }
                if state
                    .actions
                    .send_network_message_qos(msg, reliable, express, priority)
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
    /// tables are populated by 1b and the qabls tables by 1c; the purge covers
    /// BOTH so neither slice re-touches `deregister` / `forward`.
    ///
    /// This is the SHARED CHOKE POINT for a native removal — its two callers are
    /// `deregister` (a local face-down) AND the `forward` Oam-ingest detach (a
    /// REMOTE topology node dropping out, `changes.removed`). So the FEDERATION
    /// cross-tier withdrawal (R311y125) lives HERE, not in `deregister`: if a
    /// departed native was the LAST source for a keyexpr in this tier, self's
    /// advertisement of it into the OPPOSITE mesh must be withdrawn (the flip
    /// true->false), and centralizing it covers BOTH remove paths by construction
    /// (the y107b lifecycle-asymmetry class — a remote detach is the path most
    /// likely to be missed). No-op for [`FaceTier::Client`] (no tier tables). The
    /// self-bubble itself is never stored (derive-not-store); only the WIRE
    /// advertisement needs the explicit retraction.
    fn purge_detached_interest_tier(&self, tier: FaceTier, removed: &[Zid]) {
        if removed.is_empty() {
            return;
        }
        let (subs, qabls) = match tier {
            FaceTier::Routers => (&self.router_subs, &self.router_qabls),
            FaceTier::LinkstatePeers => (&self.linkstatepeer_subs, &self.linkstatepeer_qabls),
            FaceTier::Client => return,
        };
        // Collect the sub + qabl keyexprs the departed natives held, so the
        // cross-tier advertisement they contributed to is re-evaluated AFTER the
        // removal (the borrows must be dropped before the withdraw/re-advertise,
        // which re-read the tables).
        let mut affected_sub_keys: HashSet<String> = HashSet::new();
        let mut affected_qabl_keys: HashSet<String> = HashSet::new();
        {
            let mut subs = subs.borrow_mut();
            let mut qabls = qabls.borrow_mut();
            for zid in removed {
                affected_sub_keys.extend(subs.remove_peer_keys(zid));
                affected_qabl_keys.extend(qabls.remove_peer_keys(zid));
            }
        }
        // §5.21 routing-token-tables — drain the departed natives' token entries,
        // then (slice-2) withdraw self's CROSS-TIER advertisement for any keyexpr
        // whose LAST native source just left — the token twin of the subs/qabls
        // withdraw loops above (minus the client `undeclare_push`). tier is
        // Routers|LinkstatePeers here (Client returned early), so `tokens_table` is
        // `Some`. The drained keys are collected INSIDE the scoped `borrow_mut` and
        // the withdraw runs AFTER it drops — `withdraw_native_cross_tier_token`
        // re-reads the same table via `source_count`, so withdrawing under the live
        // borrow_mut would RefCell-panic (mirrors the subs/qabls collect-then-act
        // shape at the top of this fn).
        #[cfg(feature = "routing-token-tables")]
        if let Some(tokens) = self.tokens_table(tier) {
            let mut affected_token_keys: HashSet<String> = HashSet::new();
            {
                let mut tokens = tokens.borrow_mut();
                for zid in removed {
                    affected_token_keys.extend(tokens.remove_peer_keys(zid));
                }
            }
            for keyexpr in affected_token_keys {
                self.withdraw_native_cross_tier_token(tier, &keyexpr);
                // slice-5: the ungraceful node-detach twin of the graceful withdraw's
                // notify (the token half of zenoh token_remove_node's
                // propagate_forget_simple_token, the R311y152 detach-push for tokens).
                self.undeclare_push_token(&keyexpr);
            }
        }
        // R311y152 — the UNGRACEFUL detach now fires the undeclare-push too (this
        // was the "benign NAMED deferral" the R311y151 residual left OFF here): a
        // native departing via face-down / link-down / topology-detach un-backs a
        // co-attached CLIENT publisher's/querier's pushed reply ke exactly as a
        // graceful UndeclareSubscriber/Queryable does, so the SAME
        // undeclare_push_subs/qabls seam re-arms its pico write-filter here — zenoh's
        // node-removal forget-to-simple-face `propagate_forget_simple_subscription`,
        // reached on a node drop (router hat via `unregister_router_subscription`,
        // hat/router/pubsub.rs:568; linkstate_peer hat via `unregister_peer_subscription`,
        // hat/linkstate_peer/pubsub.rs:482), and the `queries_remove_node` twin.
        // The two per-keyexpr retraction actions are co-located: the cross-tier mesh
        // WITHDRAW (opposite-mesh wire advertisement) and the client undeclare-push
        // (client-face pushed declarations) are DISJOINT and order-free. still_backed
        // (any_sub/qabl_matches) is the post-removal GLOBAL existence fold, so a reply
        // ke a surviving tier / client still backs is NOT undeclared. The undeclare
        // fires INSIDE this choke point because BOTH router callers hold NO
        // `self.faces` borrow (deregister's let-else; the Oam-ingest arm of `forward`);
        // the peer twin defers it PAST its if-let, which does hold that borrow.
        //
        // Cross-tier qabl withdraw (A2b): a partial removal that leaves a contributor
        // DOWNGRADES via a re-declared DeclareQueryable; a full removal floods an
        // explicit UndeclareQueryable retraction (expressible via the ext_wire_expr
        // codec).
        //
        // Case (c) — the qabl completeness-DOWNGRADE on a PARTIAL withdrawal toward the
        // CLIENT querier (a native leaves but the reply ke stays backed at a now-lower
        // folded completeness) — is CLOSED (R311y153): undeclare_push_qabls fires BOTH
        // the full-undeclare AND the value-aware downgrade re-push here, matching zenoh's
        // ROUTER hat register_router_queryable-via-local_router_qabl_info re-declare on
        // partial node-removal (hat/router/queries.rs:930-940). See undeclare_push_qabls.
        // Pre-existing + benign (named, not introduced here): any_sub/qabl_matches fold
        // with NO destination-face exclusion (vs zenoh loop-2's remote_*_subs(&m, &face)),
        // so a client that both publishes AND subscribes a ke keeps its OWN filter OFF
        // after the other backer detaches (over-deliver, never a spurious undeclare) — a
        // property of the reused graceful seam.
        for keyexpr in affected_sub_keys {
            self.withdraw_native_cross_tier_sub(tier, &keyexpr);
            self.undeclare_push_subs(&keyexpr);
        }
        for keyexpr in affected_qabl_keys {
            self.withdraw_native_cross_tier_qabl(tier, &keyexpr);
            self.undeclare_push_qabls(&keyexpr);
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

    /// The liveliness-token interest table for `tier`, or `None` for
    /// [`FaceTier::Client`] (a client token lands in `client_tokens`, never in a
    /// Zid-keyed mesh tier table — derive-not-store) — the token twin of
    /// [`subs_table`](Self::subs_table). Tokens carry no value,
    /// so both tiers are `LinkstatepeerInterest<()>`, identical to the sub plane.
    #[cfg(feature = "routing-token-tables")]
    fn tokens_table(&self, tier: FaceTier) -> Option<&RefCell<LinkstatepeerInterest<()>>> {
        match tier {
            FaceTier::Routers => Some(&self.router_tokens),
            FaceTier::LinkstatePeers => Some(&self.linkstatepeer_tokens),
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
    ///
    /// Returns `Some(resolved_keyexpr)` IFF it registered a REAL change (and thus
    /// re-flooded) — the signal the caller uses to decide the CROSS-tier
    /// advertisement (R311y125): a native that first appears for a keyexpr may
    /// flip self's cross-tier advertise-into-the-opposite-mesh state. `None` on
    /// any drop (client tier / unresolvable / no change).
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
    ) -> Option<String> {
        let (net, _dirty) = self.plane(tier)?; // Client tier: no net -> slice 1d.
                                               // Resolve the keyexpr against the inbound face's alias table + read its
                                               // zid / link, in one scoped borrow (an unresolvable alias drops it).
        let (inbound_zid, inbound_link, keyexpr) = {
            let faces = self.faces.borrow();
            let s = faces.get(&inbound)?;
            let keyexpr = resolve_wireexpr(&wireexpr.body, &s.keyexpr_table)?;
            (peer_zid_routing(&s.actions), s.link, keyexpr)
        };
        let (source_zid, out_node_id) = resolve_source_in(
            &net.borrow(),
            inbound_zid,
            inbound_link,
            read_declare_source(declare),
        )?;
        // Register the SOURCE's native interest; re-flood ONLY on a real change
        // (the value-diff gate -- a new peer OR a changed value).
        if !table.borrow_mut().register(&keyexpr, source_zid, value) {
            return None;
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
        Some(keyexpr)
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
        let changed =
            self.ingest_interest(inbound, tier, reliable, declare, wireexpr, subs, (), |ke| {
                build_declare_subscriber(0, 0, Some(ke))
            });
        log::debug!(
            "router forward: mesh sub ingest on face {inbound:?} tier {tier:?} -> {}",
            match &changed {
                Some(ke) => format!("REGISTERED {ke:?}"),
                None => "not registered (unresolvable / no-change)".to_string(),
            }
        );
        // FEDERATION cross-tier bubble (R311y125): a NATIVE sub for `ke` in this
        // tier makes self ADVERTISE `ke` into the OPPOSITE mesh (a router-native
        // -> peer mesh; a peer-native -> router mesh) so a publisher on that mesh
        // routes toward self, which then bridges cross-tier (C4). zenoh's
        // register_router_subscription / declare_linkstatepeer_subscription
        // cross-register self into the opposite tier here (pubsub.rs:248-250 /
        // :296-297) — NOT master-gated (every router advertises; only the delivery
        // bridge is gated). Fires on the flip false->true only.
        if let Some(ke) = changed {
            self.advertise_native_cross_tier_sub(tier, &ke);
            // FUTURE-mode push: a mesh sub just became known -> declare it to any
            // CLIENT face whose stored FUTURE interest matches (the pub-before-sub
            // close). Never echoed to `inbound` (a mesh face is not a future holder,
            // but the guard is faithful).
            self.push_future_subscription(&ke, inbound);
        }
    }

    /// Ingest a sourced `DeclareToken` (§5.21 routing-token-tables) — the
    /// liveliness-token twin of
    /// [`ingest_subscription`](Self::ingest_subscription): register the SOURCE
    /// in the inbound tier's `tokens` table (Router face -> `router_tokens`,
    /// Peer face -> `linkstatepeer_tokens`) + within-tier re-flood, carrier
    /// `build_declare_token(0, 0, Some(ke))` (id 0 = sourced, keyexpr inline —
    /// the identical convention `build_declare_subscriber(0, 0, Some(ke))` uses).
    ///
    /// Calls the shared [`ingest_interest`](Self::ingest_interest) core DIRECTLY,
    /// NOT via the `ingest_subscription` wrapper; the CROSS-TIER advertise
    /// ([`advertise_native_cross_tier_token`](Self::advertise_native_cross_tier_token),
    /// slice-2) AND the FUTURE push
    /// ([`push_future_token`](Self::push_future_token), slice-4 — declares the newly
    /// learned token to any CLIENT face with a matching stored token interest) are
    /// both invoked on the register flip in the tail here. A Client-tier `DeclareToken`
    /// no longer reaches here: `forward()` routes it to
    /// [`ingest_client_token`](Self::ingest_client_token) (slice-3), so the
    /// `tokens_table` `None` guard below is defensive-only.
    /// The retraction counterpart is
    /// [`withdraw_token`](Self::withdraw_token): a peer router's graceful sourced
    /// `UndeclareToken` (`{id:0, ext_wire_expr}`) withdraws by keyexpr (the
    /// `UndeclToken` codec now carries the ext chain), and the face-down
    /// [`purge_detached_interest_tier`](Self::purge_detached_interest_tier) drains
    /// a departed source's tokens on an ungraceful departure.
    #[cfg(feature = "routing-token-tables")]
    fn ingest_token(
        &self,
        inbound: FaceId,
        tier: FaceTier,
        reliable: bool,
        declare: &DeclareOwned,
    ) {
        let Some(wireexpr) = declare_token_wireexpr(declare) else {
            return;
        };
        let Some(tokens) = self.tokens_table(tier) else {
            return; // Client tier: forward() routes it to the client-token plane.
        };
        let changed = self.ingest_interest(
            inbound,
            tier,
            reliable,
            declare,
            wireexpr,
            tokens,
            (),
            |ke| build_declare_token(0, 0, Some(ke)),
        );
        log::debug!(
            "router forward: mesh token ingest on face {inbound:?} tier {tier:?} -> {}",
            match &changed {
                Some(ke) => format!("REGISTERED {ke:?}"),
                None => "not registered (unresolvable / no-change)".to_string(),
            }
        );
        // Cross-tier PROPAGATION (slice-2): a NATIVE token for `ke` in this tier
        // makes self ADVERTISE it into the OPPOSITE mesh (the token twin of
        // ingest_subscription's advertise_native_cross_tier_sub tail). Fires on the
        // register flip false->true only (ingest_interest returns Some).
        if let Some(ke) = changed {
            self.advertise_native_cross_tier_token(tier, &ke);
            // FUTURE-mode push (slice-4): a mesh token just became known -> declare it
            // to any CLIENT face whose stored FUTURE token interest matches (mirror of
            // ingest_subscription's push_future_subscription). Never echoed to inbound.
            self.push_future_token(&ke, inbound);
        }
    }

    /// Withdraw a sourced `UndeclareToken` (§5.21 routing-token-tables) — the
    /// liveliness-token twin of [`withdraw_subscription`](Self::withdraw_subscription)
    /// and the removal counterpart of [`ingest_token`](Self::ingest_token). The
    /// retracted keyexpr rides the `ext_wire_expr` extension chain (now that the
    /// `UndeclToken` codec models it); resolve it, withdraw the SOURCE from the
    /// inbound tier's token table, and within-tier re-flood a clean sourced
    /// retraction via `build_undeclare_token_with_keyexpr`. Reuses the shared
    /// [`withdraw_interest`](Self::withdraw_interest) core DIRECTLY (like
    /// ingest_token reuses ingest_interest); on a REAL removal it captures the
    /// returned keyexpr and withdraws the CROSS-TIER advertisement
    /// ([`withdraw_native_cross_tier_token`](Self::withdraw_native_cross_tier_token),
    /// slice-2 — the negation of ingest_token's advertise) when the LAST native
    /// source left. An id-keyed simple `UndeclareToken` (the RAII drop's form, no
    /// ext) resolves no keyexpr and is a no-op — the router source-routes tokens
    /// by keyexpr, never by id.
    #[cfg(feature = "routing-token-tables")]
    fn withdraw_token(
        &self,
        inbound: FaceId,
        tier: FaceTier,
        reliable: bool,
        declare: &DeclareOwned,
    ) {
        let exts = match &declare.body {
            DeclareOwnedVariant::CodecZenohUndeclToken(u) => u.extensions.as_ref(),
            _ => return,
        };
        let Some(tokens) = self.tokens_table(tier) else {
            return; // Client tier: forward() routes it to the client-token plane.
        };
        // Cross-tier PROPAGATION (slice-2): withdraw_interest returns Some(ke) on a
        // REAL removal; if that was the LAST native token source, withdraw self's
        // cross-tier advertisement into the opposite mesh (the flip true->false —
        // the negation of ingest_token's advertise). Mirror of withdraw_subscription
        // minus undeclare_push (a client-push concern).
        if let Some(keyexpr) = self.withdraw_interest(
            inbound,
            tier,
            reliable,
            declare,
            exts,
            tokens,
            build_undeclare_token_with_keyexpr,
        ) {
            self.withdraw_native_cross_tier_token(tier, &keyexpr);
            // slice-5 withdraw->notify: the mesh token is gone from the table, so a
            // future-push reader whose pushed reply ke lost its LAST backer is told it
            // withdrew (mirror of withdraw_subscription's undeclare_push_subs).
            self.undeclare_push_token(&keyexpr);
        }
    }

    /// Respond to an inbound `Interest` solicitation — the zenoh-1.x
    /// interest-declaration handshake. A pico publisher/querier keeps a
    /// WRITE-FILTER that drops its own put/get LOCALLY until the router answers
    /// its declare-Interest with a matching `Declare(Sub/Qabl)`; wz previously
    /// DROPPED the Interest (`_ => {}`), which is exactly why a pico publisher
    /// behind wz never puts data on the wire (the reverse-data path). This is the
    /// CURRENT-mode reply (`hat/router/interests.rs::declare_interest` +
    /// `declare_{sub,qabl}_interest`): per matching REMOTE declaration wz holds, a
    /// `Declare(Sub)` / `Declare(Qabl)` stamped with the soliciting `interest_id`,
    /// then ONE terminating `Declare(DeclFinal)`. FUTURE (`f()`): a CLIENT face's
    /// SUBSCRIBER interest is additionally STORED
    /// ([`future_subs`](Self#structfield.future_subs)) so a sub learned LATER is
    /// pushed ([`push_future_subscription`](Self::push_future_subscription)) — the
    /// pub-before-sub close (R311y146); an `Interest(Final)` tears the stored
    /// interest down. A body-less Final gets no wire reply. The current dump is
    /// tier-agnostic — routers answer
    /// interests from any tier — the faithful zenoh behavior.
    fn respond_to_interest(&self, inbound: FaceId, interest: &InterestOwned) {
        // Interest(Final) (`!c && !f`): a client CANCELLING a prior interest. pico
        // sends one on every publisher/querier drop (`net/primitives.c:
        // _z_remove_interest`, client-gated), so the stored FUTURE interest for
        // this `interest_id` must be dropped (else it leaks + keeps pushing to a
        // publisher whose write-filter is gone). No reply (a Final carries no body).
        if !interest.c() && !interest.f() {
            // The interest_id lives in ONE plane's store per option bit set (su() /
            // qu() / to() — a single interest MAY set several); removing from all is
            // safe (a plane that never stored this id no-ops).
            self.future_subs
                .borrow_mut()
                .remove_interest(inbound, interest.interest_id);
            self.future_qabls
                .borrow_mut()
                .remove_interest(inbound, interest.interest_id);
            #[cfg(feature = "routing-token-tables")]
            self.future_tokens
                .borrow_mut()
                .remove_interest(inbound, interest.interest_id);
            return;
        }
        let Some(body) = interest.body.as_ref() else {
            return; // a C||F interest always carries a body (the C||F decode gate).
        };
        let interest_id = interest.interest_id;
        // Resolve the RESTRICTED target keyexpr against the inbound face's alias
        // table in ONE scoped borrow (`None` => match-all, deferred; pico always
        // sets RESTRICTED). An unresolvable alias still terminates the interest so
        // the peer is not left waiting.
        let target: Option<String> = {
            let faces = self.faces.borrow();
            let Some(s) = faces.get(&inbound) else {
                return;
            };
            if body.r() {
                match body
                    .keyexpr
                    .as_ref()
                    .and_then(|w| resolve_wireexpr(&w.body, &s.keyexpr_table))
                {
                    Some(ke) => Some(ke),
                    None => {
                        // A CURRENT interest is still terminated so the peer is not
                        // left waiting; a FUTURE-only interest has no snapshot to
                        // close (nothing was stored — the alias was unresolvable).
                        if interest.c() {
                            self.send_one_to_face(
                                inbound,
                                NetworkMessage::Declare(Box::new(build_declare_final_reply(
                                    interest_id,
                                ))),
                            );
                        }
                        return;
                    }
                }
            } else {
                None
            }
        };
        let aggregate = body.ag();
        // FUTURE (`f()`) half: STORE the subscriber interest so a matching sub
        // learned LATER is pushed to this face (the pub-before-sub close). CLIENT
        // faces only — zenoh pushes future subs to `whatami==Client` faces
        // (`propagate_simple_subscription_to`); peers/routers converge via proactive
        // link-state, not interest-push. SUBS plane only (`su()`); match-all (target
        // None) is not stored (current-dump parity). The QABL future-push is the
        // parallel `store_future_qabl` block below (R311y150); match-all stays a
        // separate deferred unit.
        let store_future = interest.f() && body.su() && self.is_client_face(inbound);
        if store_future {
            if let Some(t) = target.as_deref() {
                self.future_subs.borrow_mut().store_interest(
                    inbound,
                    interest_id,
                    t.to_owned(),
                    aggregate,
                );
            }
        }
        // The QUERYABLE-plane twin (R311y150): store a FUTURE queryable interest so a
        // queryable learned LATER is pushed to this querier (the querier-before-
        // queryable close), and a completeness flip re-pushes (value-aware). Same
        // CLIENT-only + literal-target gate as the sub plane.
        let store_future_qabl = interest.f() && body.qu() && self.is_client_face(inbound);
        if store_future_qabl {
            if let Some(t) = target.as_deref() {
                self.future_qabls.borrow_mut().store_interest(
                    inbound,
                    interest_id,
                    t.to_owned(),
                    aggregate,
                );
            }
        }
        // §5.21 routing-token-tables (slice-4): STORE a FUTURE liveliness-TOKEN
        // interest so a token learned LATER is pushed to this face (the token twin of
        // the sub/qabl future store). CLIENT-only + literal-target, same gate — the
        // full-net token replay is client-directed (zenoh declare_token_interest:1001).
        #[cfg(feature = "routing-token-tables")]
        let store_future_token = interest.f() && body.to() && self.is_client_face(inbound);
        #[cfg(feature = "routing-token-tables")]
        if store_future_token {
            if let Some(t) = target.as_deref() {
                self.future_tokens.borrow_mut().store_interest(
                    inbound,
                    interest_id,
                    t.to_owned(),
                    aggregate,
                );
            }
        }
        // CURRENT (`c()`) half: dump the matching declarations wz holds + the single
        // terminating DeclareFinal (sent regardless of dump size — 0 matches keeps
        // the peer's write-filter armed = "no subscriber yet", correct). A
        // FUTURE-only interest (no `c()`) gets neither — an ongoing subscription has
        // no current snapshot to close.
        if interest.c() {
            let self_zid = *self.routers_net.borrow().self_zid();
            if body.su() {
                self.dump_interest_subs(
                    inbound,
                    target.as_deref(),
                    aggregate,
                    &self_zid,
                    interest_id,
                    store_future,
                );
            }
            if body.qu() {
                self.dump_interest_qabls(
                    inbound,
                    target.as_deref(),
                    aggregate,
                    &self_zid,
                    interest_id,
                    store_future_qabl,
                );
            }
            // §5.21 routing-token-tables (slice-4): the CURRENT liveliness-TOKEN dump —
            // the FIRST reader of the token tables (makes the slice-1/2/3 bubble
            // observable). CLIENT-GATED, UNLIKE the sub/qabl dumps above: zenoh
            // `declare_token_interest` (token.rs:1001) gates the token replay on
            // `Client || (Peer && !full_net)`, and wz is full-net (peers land in
            // `linkstatepeer_tokens`), so it reduces to CLIENT-ONLY (`declare_sub_interest`
            // is bare `if mode.current()`). A peer's token Interest(current) gets only the
            // DeclareFinal below — peers learn tokens via the linkstate flood, not replay.
            #[cfg(feature = "routing-token-tables")]
            if body.to() && self.is_client_face(inbound) {
                self.dump_interest_tokens(
                    inbound,
                    target.as_deref(),
                    aggregate,
                    &self_zid,
                    interest_id,
                    store_future_token,
                );
            }
            self.send_one_to_face(
                inbound,
                NetworkMessage::Declare(Box::new(build_declare_final_reply(interest_id))),
            );
        }
    }

    /// Whether `face` is a held CLIENT face — the tier gate for STORING a FUTURE
    /// subscriber interest (zenoh pushes future declarations to `whatami==Client`
    /// faces only). A vanished face is not a client.
    fn is_client_face(&self, face: FaceId) -> bool {
        self.faces
            .borrow()
            .get(&face)
            .is_some_and(|s| s.tier == FaceTier::Client)
    }

    /// The CURRENT-dump SUBSCRIBER leg of [`respond_to_interest`]: reply with the
    /// REMOTE subscriptions matching the interest target. Sources both meshes
    /// (`router_subs` + `linkstatepeer_subs`, excluding SELF — zenoh's `*r !=
    /// tables.zid`) plus the client leaf subs (excluding the requesting face). For
    /// an AGGREGATE interest, ONE reply keyed on the INTEREST's keyexpr (pico
    /// matches an aggregate interest's replies by keyexpr EQUALITY, so a concrete
    /// sub keyexpr would silently fail to match); else one reply per distinct
    /// matching sub keyexpr. Keyexprs are collected OWNED before any send, so no
    /// interest-table borrow is held across the egress.
    fn dump_interest_subs(
        &self,
        inbound: FaceId,
        target: Option<&str>,
        aggregate: bool,
        self_zid: &Zid,
        interest_id: u64,
        future: bool,
    ) {
        let Some(target) = target else {
            return; // match-all deferred; the caller's DeclareFinal still closes the interest.
        };
        let mut per_ke: HashMap<String, ()> = HashMap::new();
        for table in [&self.router_subs, &self.linkstatepeer_subs] {
            for (ke, _zid, ()) in table.borrow().matching_entries(target, Some(self_zid)) {
                per_ke.insert(ke.to_string(), ());
            }
        }
        let target_chunks: Vec<&str> = target.split('/').collect();
        for (face, keys) in self.client_subs.borrow().iter() {
            if *face == inbound {
                continue; // never advertise a face its own subscription
            }
            for k in keys {
                if keyexpr_intersects_target(k, &target_chunks) {
                    per_ke.insert(k.clone(), ());
                }
            }
        }
        emit_current_interest_replies(
            interest_id,
            target,
            aggregate,
            per_ke,
            |a, _b| a,
            // For a FUTURE (C+F) interest the current reply carries a NON-ZERO id
            // interned per (face, reply ke) (zenoh `make_sub_id`'s `mode.future()`
            // branch seeds `local_subs`), so the id can be REUSED on a redundant
            // re-declare and the later FUTURE push of the same ke dedups. A
            // CURRENT-only interest keeps id 0 (`make_sub_id` = 0 for non-future).
            |id, ke, ()| {
                if future {
                    let sub_id =
                        self.future_subs
                            .borrow_mut()
                            .intern_current_reply(inbound, ke, ());
                    build_declare_subscriber_reply_with_id(id, sub_id, ke)
                } else {
                    build_declare_subscriber_reply(id, ke)
                }
            },
            |msg| self.send_one_to_face(inbound, msg),
        );
    }

    /// The CURRENT-dump QUERYABLE leg of [`respond_to_interest`] — the query-plane
    /// twin of [`dump_interest_subs`] with one addition: each reply carries the
    /// MERGED [`QueryableInfo`] (complete = OR, distance = min — zenoh's
    /// `local_qabl_info` fold) of the matched queryables. A
    /// `Z_QUERY_TARGET_ALL_COMPLETE` querier's write-filter deactivates ONLY on a
    /// reply with `complete = true`, so the completeness must be folded, not
    /// dropped to DEFAULT. Aggregate => one reply (all matched infos merged) keyed
    /// on the interest ke; else one per distinct keyexpr (each keyexpr's sources
    /// pre-merged).
    fn dump_interest_qabls(
        &self,
        inbound: FaceId,
        target: Option<&str>,
        aggregate: bool,
        self_zid: &Zid,
        interest_id: u64,
        future: bool,
    ) {
        let Some(target) = target else {
            return;
        };
        let mut per_ke: HashMap<String, QueryableInfo> = HashMap::new();
        for table in [&self.router_qabls, &self.linkstatepeer_qabls] {
            for (ke, _zid, info) in table.borrow().matching_entries(target, Some(self_zid)) {
                per_ke
                    .entry(ke.to_string())
                    .and_modify(|e| *e = e.merge(*info))
                    .or_insert(*info);
            }
        }
        let target_chunks: Vec<&str> = target.split('/').collect();
        for (face, m) in self.client_qabls.borrow().iter() {
            if *face == inbound {
                continue;
            }
            for (k, info) in m {
                if keyexpr_intersects_target(k, &target_chunks) {
                    per_ke
                        .entry(k.clone())
                        .and_modify(|e| *e = e.merge(*info))
                        .or_insert(*info);
                }
            }
        }
        emit_current_interest_replies(
            interest_id,
            target,
            aggregate,
            per_ke,
            |a, b| a.merge(b),
            // A FUTURE (C+F) interest's current reply carries a NON-ZERO id interned
            // per (face, reply ke) with the FOLDED info seeded, so the id is REUSED
            // and a later completeness flip re-pushes the SAME target (HOLE 3: the
            // seed id must match the wire id, mirror of the sub future branch). A
            // CURRENT-only interest keeps id 0.
            |id, ke, info| {
                if future {
                    let qabl_id = self
                        .future_qabls
                        .borrow_mut()
                        .intern_current_reply(inbound, ke, info);
                    build_declare_queryable_reply_with_id(id, qabl_id, ke, info)
                } else {
                    build_declare_queryable_reply(id, ke, info)
                }
            },
            |msg| self.send_one_to_face(inbound, msg),
        );
    }

    /// §5.21 routing-token-tables (slice-4) — the CURRENT-dump liveliness-TOKEN leg
    /// of [`respond_to_interest`], the FIRST reader of the token tables (makes the
    /// slice-1/2/3 bubble observable). The token twin of [`dump_interest_subs`]
    /// (tokens carry no value → no merge). Folds the REMOTE tokens matching the
    /// interest target: both mesh tiers (`router_tokens` + `linkstatepeer_tokens`,
    /// excluding SELF — zenoh's `*r != tables.zid`) ∪ the CLIENT leaf tokens
    /// (`client_tokens`, excluding the requesting face — the SLICE-4 OBLIGATION from
    /// the `client_tokens` field doc that makes a client-sourced derive-not-store
    /// token observable). CLIENT-gated by the caller (zenoh `declare_token_interest`
    /// is client-only). Uses the ungated `declare_build` token reply builders (routed
    /// through the shared `stamp_interest_reply` I-flag SSOT), NOT
    /// `declare::local_token::build_token_reply` (which is behind `liveliness-token` —
    /// the router token plane must not pull that feature). A FUTURE (C+F) interest
    /// interns a non-zero id (reused on the later FUTURE push, so it dedups — zenoh
    /// `make_token_id`'s future branch); a CURRENT-only interest keeps id 0.
    #[cfg(feature = "routing-token-tables")]
    fn dump_interest_tokens(
        &self,
        inbound: FaceId,
        target: Option<&str>,
        aggregate: bool,
        self_zid: &Zid,
        interest_id: u64,
        future: bool,
    ) {
        let Some(target) = target else {
            return; // match-all deferred; the caller's DeclareFinal still closes it.
        };
        let mut per_ke: HashMap<String, ()> = HashMap::new();
        for table in [&self.router_tokens, &self.linkstatepeer_tokens] {
            for (ke, _zid, ()) in table.borrow().matching_entries(target, Some(self_zid)) {
                per_ke.insert(ke.to_string(), ());
            }
        }
        let target_chunks: Vec<&str> = target.split('/').collect();
        for (face, ids) in self.client_tokens.borrow().iter() {
            if *face == inbound {
                continue; // never replay a face its own token
            }
            for k in ids.values() {
                if keyexpr_intersects_target(k, &target_chunks) {
                    per_ke.insert(k.clone(), ());
                }
            }
        }
        emit_current_interest_replies(
            interest_id,
            target,
            aggregate,
            per_ke,
            |a, _b| a,
            // A FUTURE (C+F) interest's current reply carries a NON-ZERO id interned
            // per (face, reply ke) so it is REUSED on the later FUTURE push and dedups
            // (mirror of the sub future branch); a CURRENT-only interest keeps id 0.
            |id, ke, ()| {
                if future {
                    let token_id =
                        self.future_tokens
                            .borrow_mut()
                            .intern_current_reply(inbound, ke, ());
                    build_declare_token_reply_with_id(id, token_id, ke)
                } else {
                    build_declare_token_reply(id, ke)
                }
            },
            |msg| self.send_one_to_face(inbound, msg),
        );
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
        let Some(subs) = self.subs_table(tier) else {
            return;
        };
        // FEDERATION cross-tier bubble (R311y125): on a real removal, if that was
        // the LAST native source for `keyexpr` in this tier (and no client covers
        // it), withdraw self's advertisement into the opposite mesh (flip
        // true->false). The shared withdraw returns the resolved keyexpr on a real
        // change, exactly as `ingest_interest` returns it for the advertise side.
        if let Some(keyexpr) = self.withdraw_interest(
            inbound,
            tier,
            reliable,
            declare,
            exts,
            subs,
            build_undeclare_subscriber_with_keyexpr,
        ) {
            self.withdraw_native_cross_tier_sub(tier, &keyexpr);
            // R311y151 undeclare-push: the mesh sub is gone from the table, so if a
            // waiting publisher's pushed reply ke has now lost its LAST backer,
            // re-arm its write-filter with an UndeclareSubscriber + clear `pushed`.
            self.undeclare_push_subs(&keyexpr);
        }
    }

    /// The SSOT for a sourced interest WITHDRAWAL (subscriber `V = ()` / queryable
    /// `V = QueryableInfo`) — the router twin of
    /// [`LinkstateForwarder`]'s `forward_interest_withdrawal`, and the removal
    /// counterpart of [`ingest_interest`](Self::ingest_interest). Withdraw the
    /// resolved SOURCE's interest from the inbound tier's `table` (the retracted
    /// keyexpr rides `exts` = the body's `ext_wire_expr` chain) and — only on a
    /// real removal — re-flood a clean sourced retraction WITHIN that tier via
    /// `build` (re-stamped with this node's psid for the source). Returns
    /// `Some(resolved keyexpr)` IFF it removed a REAL interest (the signal the
    /// caller uses to recompute the CROSS-tier advertisement, mirroring
    /// `ingest_interest`'s change-signal); `None` on any drop (client tier /
    /// unresolvable / not held). The cross-tier bubble is NOT done here (it differs
    /// per plane: presence for subs, merged-info for qabls) — the caller owns it.
    #[allow(clippy::too_many_arguments)]
    fn withdraw_interest<V>(
        &self,
        inbound: FaceId,
        tier: FaceTier,
        reliable: bool,
        declare: &DeclareOwned,
        exts: Option<&Vec<ExtEntryOwned>>,
        table: &RefCell<LinkstatepeerInterest<V>>,
        build: impl Fn(&str) -> Result<DeclareOwned, CodecError>,
    ) -> Option<String> {
        let (net, _dirty) = self.plane(tier)?;
        let (inbound_zid, inbound_link, keyexpr) = {
            let faces = self.faces.borrow();
            let s = faces.get(&inbound)?;
            let keyexpr = resolve_ext_keyexpr(exts, &s.keyexpr_table)?;
            (peer_zid_routing(&s.actions), s.link, keyexpr)
        };
        let (source_zid, out_node_id) = resolve_source_in(
            &net.borrow(),
            inbound_zid,
            inbound_link,
            read_declare_source(declare),
        )?;
        if !table.borrow_mut().withdraw(&keyexpr, &source_zid) {
            return None;
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
        Some(keyexpr)
    }

    /// Ingest a sourced `DeclareQueryable` (1c) — the query-plane twin of
    /// [`ingest_subscription`](Self::ingest_subscription). Register the SOURCE's
    /// queryable interest (VALUE = its declared [`QueryableInfo`], read off the
    /// DeclQueryable ext chain) in the INBOUND tier's qabls table, and — only on
    /// a real change (a NEW peer OR a CHANGED `QueryableInfo`, the value-diff
    /// gate) — re-flood a clean declaration CARRYING that info within the tier so
    /// a multi-hop relay learns the queryable's completeness. Like the sub
    /// bubble, the cross-tier bubble (a MERGED `local_*_qabl_info` in zenoh) is
    /// DERIVED at compute (A2b), not stored. The removal twin is
    /// [`withdraw_queryable`](Self::withdraw_queryable): a per-keyexpr
    /// `UndeclareQueryable` withdraws via its `ext_wire_expr` extension, and the
    /// whole-peer face-down purge stays the safety net for a departed peer.
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
        let changed = self.ingest_interest(
            inbound,
            tier,
            reliable,
            declare,
            wireexpr,
            qabls,
            info,
            move |ke| build_declare_queryable_with_info(ke, info),
        );
        // FEDERATION cross-tier bubble (A2b): a NATIVE qabl makes self ADVERTISE
        // its MERGED QueryableInfo into the OPPOSITE mesh (the query twin of the
        // sub advertise) so a REMOTE querier routes toward self. The advertise is
        // done AFTER `ingest_interest` registered the native (so the merge INCLUDES
        // the triggering native — the register-before-merge fidelity order), and
        // fires on any real change (a new native OR a changed info re-declares the
        // recomputed merge — an upgrade or downgrade).
        if let Some(ke) = changed {
            self.advertise_native_cross_tier_qabl(tier, &ke);
            // FUTURE-push (R311y150): a queryable learned off the mesh is proactively
            // pushed to any CLIENT face whose FUTURE querier-interest matches, with
            // the RE-FOLDED merged info — the query twin of the mesh-sub future push.
            self.push_future_queryable(&ke, inbound);
        }
    }

    /// A sourced `UndeclareQueryable` — the query-plane twin of
    /// [`withdraw_subscription`](Self::withdraw_subscription): withdraw the SOURCE
    /// peer's interest from the INBOUND tier's qabls table (the keyexpr rides the
    /// `ext_wire_expr` extension) and — only on a real removal — re-flood the
    /// retraction WITHIN that tier, then recompute self's cross-tier advertisement.
    /// Before the `UndeclareQueryable` codec modeled the keyexpr ext this arm was a
    /// no-op (the face-down purge was the only qabl teardown); it now mirrors the
    /// sub retraction. A face-down purge is still covered by
    /// [`purge_detached_interest_tier`](Self::purge_detached_interest_tier).
    fn withdraw_queryable(
        &self,
        inbound: FaceId,
        tier: FaceTier,
        reliable: bool,
        declare: &DeclareOwned,
    ) {
        let exts = match &declare.body {
            DeclareOwnedVariant::CodecZenohUndeclQueryable(u) => u.extensions.as_ref(),
            _ => return,
        };
        let Some(qabls) = self.qabls_table(tier) else {
            return;
        };
        // FEDERATION cross-tier bubble (A2b): on a real removal, recompute self's
        // advertisement into the opposite mesh — a downgrade if a contributor
        // remains, or a full `UndeclareQueryable` retraction if the merge is now
        // `None`. Shares the withdraw SSOT with the sub plane (only the table,
        // carrier, and this cross-tier step differ), the query twin of the
        // `ingest_queryable`/`ingest_subscription` split over `ingest_interest`.
        if let Some(keyexpr) = self.withdraw_interest(
            inbound,
            tier,
            reliable,
            declare,
            exts,
            qabls,
            build_undeclare_queryable_with_keyexpr,
        ) {
            self.withdraw_native_cross_tier_qabl(tier, &keyexpr);
            // R311y151 undeclare-push (query twin): a waiting querier whose pushed
            // reply ke lost its LAST backing queryable is re-armed with an
            // UndeclareQueryable + `pushed` cleared.
            self.undeclare_push_qabls(&keyexpr);
        }
    }

    /// A NATIVE qabl for `keyexpr` in `native_tier` just left (undeclare or
    /// face-down purge): recompute self's cross-tier advertisement into the
    /// OPPOSITE mesh — the value-bearing query twin of
    /// [`withdraw_native_cross_tier_sub`](Self::withdraw_native_cross_tier_sub). If
    /// a contributor remains (an opposite-mesh native or a client qabl), re-advertise
    /// the DOWNGRADED merged [`QueryableInfo`]; if NONE remains, flood a full
    /// `UndeclareQueryable` retraction. The `None` arm is what the `ext_wire_expr`
    /// codec atom made expressible (previously a no-op ⇒ a stale remote advertisement
    /// lingering until self-down). Centralized so BOTH the undeclare and the
    /// (local + Oam-detach) purge paths route through it.
    fn withdraw_native_cross_tier_qabl(&self, native_tier: FaceTier, keyexpr: &str) {
        let Some(target) = Self::opposite_mesh(native_tier) else {
            return;
        };
        match self.derived_cross_tier_qabl_info(target, keyexpr) {
            Some(info) => self.flood_self_sourced(target, keyexpr, move |ke| {
                build_declare_queryable_with_info(ke, info)
            }),
            None => {
                self.flood_self_sourced(target, keyexpr, build_undeclare_queryable_with_keyexpr)
            }
        }
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

    /// Route an inbound data `Push` through the router's full zenoh
    /// `compute_data_route` structure (`hat/router/pubsub.rs:1215`): resolve the
    /// keyexpr and elect the per-keyexpr route master ONCE, then apply the three
    /// route blocks —
    /// - blocks 1 & 2, the two meshes' subs: the WITHIN-tier transit
    ///   ([`forward_push_tier`](Self::forward_push_tier), master-gate-free) plus
    ///   the master-gated CROSS-mesh bridge
    ///   ([`bridge_push_cross_mesh`](Self::bridge_push_cross_mesh));
    /// - block 3, the local CLIENT faces
    ///   ([`deliver_to_client_subscribers`](Self::deliver_to_client_subscribers),
    ///   gated `master || source == Router`);
    /// - and, for a CLIENT-sourced Push, the self-sourced mesh re-injection
    ///   ([`publish_client_push_into_meshes`](Self::publish_client_push_into_meshes),
    ///   router leg master-gated, peer leg ungated).
    ///
    /// The master decision ([`is_master`](Self::is_master)) is a no-op in a
    /// single-router topology (`shared_nodes` = `{self}` ⇒ self always wins the
    /// election ⇒ `master == true`), so every gate below reduces to the pre-C4
    /// behavior and the single-router tests are unchanged. An unresolvable
    /// inbound alias drops the whole Push (each leg would independently drop it).
    fn route_push(
        &self,
        inbound: FaceId,
        tier: FaceTier,
        reliable: bool,
        priority: Priority,
        push: &PushOwned,
        inbound_is_mcast: bool,
    ) {
        let Some(keyexpr) = self.resolve_inbound_keyexpr(inbound, push) else {
            return;
        };
        // R311y450 — the §5.18 forward-path stamp, applied ONCE here, before ANY
        // of the four blocks below fans out. zenoh stamps at a single point
        // (`treat_timestamp!` at `dispatcher/pubsub.rs:328`) and hands the one
        // stamped `msg` to every out-face in `route`, so a Put that fans to two
        // meshes plus three client faces carries ONE timestamp, not five. Every
        // block below therefore takes the stamped `push`.
        //
        // Deliberately NOT inside `compute_push_forward`: `forward_push_tier`
        // calls that core once PER TIER-NET, so a stamp there would give the
        // router-mesh leg and the peer-mesh leg of one Put different timestamps.
        //
        // One divergence, stated: zenoh stamps INSIDE `if !route.is_empty()`,
        // after computing the route, whereas this is before the blocks that
        // compute theirs. So a Put with no interested route still advances this
        // node's logical counter. That is HLC-internal — a counter advance is not
        // wire-visible, and the counter is monotonic either way — and hoisting the
        // stamp is what buys the single-timestamp guarantee across four
        // independently-routed blocks.
        let stamped;
        let push = if self.node_hlc.is_stamping() {
            let mut carrier = push.clone();
            self.node_hlc.treat_timestamp(&mut carrier);
            stamped = carrier;
            &stamped
        } else {
            push
        };
        let master = self.is_master(&keyexpr);
        // Blocks 1 & 2 — within-tier transit (ungated, the resolved-source route).
        // R311y224/y225 — the received band is threaded through EVERY unicast pubsub
        // re-forward this Push fans out to: the within-tier transit + the master-gated
        // cross-mesh bridge (y224, below) AND the CLIENT-face egress (y225, block 3),
        // so a relayed Put keeps its priority end-to-end. The mcast-group egress
        // (broadcast_to_mcast_groups) is the one remaining DEFAULT wire egress — the
        // 2-channel mcast plane has no per-priority conduit (residual, not inert).
        self.forward_push_tier(inbound, tier, reliable, priority, push);
        // Blocks 1 & 2 — the master-gated cross-mesh bridge (a received-frame transit
        // re-injected into the other mesh; preserves the band).
        self.bridge_push_cross_mesh(tier, reliable, priority, push, &keyexpr, master);
        // Block 3 — local client delivery (master || source == Router). R311y225 —
        // now PRESERVES the received band on the client-face egress (was the y224
        // DEFAULT residual); a QoS-negotiated client observes the mesh legs' band.
        self.deliver_to_client_subscribers(
            inbound, tier, reliable, priority, push, &keyexpr, master,
        );
        // Client-sourced mesh re-injection (peer leg ungated, router leg master).
        // A multicast INGRESS Push (I3b) federates into the mesh ONLY when this
        // router is the Designated Router (DR) for its keyexpr: `is_group_dr`
        // elects exactly one on-group router (seedless HRW over the group's ROUTER
        // members U self), so a group-ingress Put crosses into the mesh via a
        // SINGLE bridge. That is what makes the two-wz-routers-sharing-a-group case
        // loop-free — the non-DR routers deliver the Put to their LOCAL subs only
        // (the I1 behavior) and never re-inject, and the DR's group-egress gate
        // (`broadcast_to_mcast_groups`) runs the SAME election, so no mesh-received
        // copy is re-egressed to the group. A non-mcast (unicast client) source
        // always federates, unchanged. Zenoh leaves this topology undefended — its
        // `egress_filter` both-multicast deny keys on the IMMEDIATE face, so a
        // mesh-hop copy re-egresses and loops; the DR election is the wz superset.
        // Bounded transient: during JOIN/lease convergence two routers can briefly
        // both bridge (self-healing; the two-router cross-impl e2e proof is I3c).
        if tier == FaceTier::Client {
            // `federate` is the pre-I3c condition, computed ONCE (behavior-identical:
            // `!inbound_is_mcast || DR`; `mcast_ingress_may_federate` is `false`
            // without `router-multicast-faces`, so a mcast-ingress never federates —
            // the I1 behavior). The I3c witnesses only COUNT the two mcast-ingress
            // arms; they change no routing.
            let federate = !inbound_is_mcast || self.mcast_ingress_may_federate(&keyexpr);
            #[cfg(feature = "router-multicast-faces")]
            if inbound_is_mcast {
                if federate {
                    self.mcast_ingress_federated
                        .set(self.mcast_ingress_federated.get() + 1);
                } else {
                    self.mcast_ingress_suppressed
                        .set(self.mcast_ingress_suppressed.get() + 1);
                }
            }
            if federate {
                self.publish_client_push_into_meshes(reliable, priority, push, &keyexpr, master);
            }
        }
        // EGRESS to any attached multicast group — UNCONDITIONAL, OUTSIDE the
        // sub-gated fan-out above (zenoh's flat `mcast_groups` append,
        // `hat/router/pubsub.rs:1334`): a Put with zero matched local subs still
        // reaches the group. The resolved `keyexpr` is threaded so the egress
        // reliteralizes an aliased id-only push (the group shares no alias table).
        // `inbound_is_mcast` is the echo guard (zenoh `egress_filter` both-multicast
        // deny, `hat/router/mod.rs:812`): a Push that ARRIVED on the multicast
        // ingress face is NOT re-broadcast to a group — `false` on the unicast path
        // here, `true` on the [`route_mcast_ingress`](Self::route_mcast_ingress) path.
        #[cfg(feature = "transport-multicast")]
        self.broadcast_to_mcast_groups(
            reliable,
            priority,
            push,
            &keyexpr,
            inbound_is_mcast,
            tier != FaceTier::Client,
        );
    }

    /// Attach a multicast drive loop's outbound sender as an EGRESS group face
    /// (the wz analog of zenoh `Router::new_transport_multicast`, `router.rs:181`,
    /// pushing a `McastMux` face into `mcast_groups`). A routed `Push` is
    /// thereafter broadcast to this group. The sender is `Send` + `Clone`, so the
    /// drive loop stays a SEPARATE task from this `!Send` forwarder — the EGRESS
    /// half needs no single-task fold (that is the INGRESS milestone). Called by
    /// the router+multicast run-mode (a later slice); until then the plane is empty.
    #[cfg(feature = "transport-multicast")]
    pub fn attach_mcast_group(&self, tx: UnboundedSender<MulticastTxItem>) {
        self.mcast_groups.borrow_mut().push(McastGroup { tx });
    }

    /// Broadcast a routed `Push` to every attached multicast group. UNCONDITIONAL
    /// by design (zenoh appends `mcast_groups` to every data route outside the
    /// graph walk, `hat/router/pubsub.rs:1334`), so it must NOT be folded into the
    /// sub-gated [`self_publish_into_tier`](Self::self_publish_into_tier) /
    /// [`forward_push_tier`](Self::forward_push_tier) (which drop when no local sub
    /// matched). Echo guard (zenoh `egress_filter`, `hat/router/mod.rs:813`): a
    /// Push whose source is itself a multicast face is NOT re-broadcast to a group
    /// (`inbound_is_mcast` ⇒ return; mcast→mcast is the both-multicast deny). The
    /// group sink only ENQUEUES a [`MulticastTxItem::Push`]; the drive loop mints
    /// the group channel SN + frames it (the `multicast_tx` SSOT), so egress here
    /// never mints an SN (double-mint would desync the group ring). The routed push
    /// is RE-LITERALIZED against the resolved `keyexpr` first (a group leaf shares
    /// no expr-id alias table — an aliased id-only push would be a group blackhole),
    /// mirroring the client-leaf / mesh egress legs.
    #[cfg(feature = "transport-multicast")]
    fn broadcast_to_mcast_groups(
        &self,
        reliable: bool,
        priority: Priority,
        push: &PushOwned,
        keyexpr: &str,
        inbound_is_mcast: bool,
        source_is_mesh: bool,
    ) {
        if inbound_is_mcast {
            return;
        }
        // `source_is_mesh` gates the I3b Designated-Router egress below, which is
        // `router-multicast-faces`-only; a `transport-multicast` egress-only build
        // (no ingress plane / DR election) has no use for it, so consume it here to
        // avoid an unused-variable error under `-D warnings` (run-ci Layer C1ay).
        #[cfg(not(feature = "router-multicast-faces"))]
        let _ = source_is_mesh;
        // I3b Designated-Router gate — applied ONLY to MESH-sourced Puts
        // (`source_is_mesh`), NEVER to a local unicast client's produce. A mcast
        // group is a shared broadcast medium, so a router must always egress its
        // OWN local clients' Puts to it (it is their bridge) — local-client egress
        // is unconditional. A MESH-received Put is the loop-relevant one: the
        // two-router-shared-group echo is a mesh-hop copy of a mcast-ingress Put a
        // non-DR would otherwise re-egress. The per-keyexpr HRW DR election
        // (agreed by all on-group routers) lets exactly ONE router relay mesh
        // traffic to the group — closing that loop AND de-duplicating the
        // mesh→group bridge to the DR. Empty member set (single on-group router /
        // egress-only build) ⇒ self is the DR ⇒ unconditional (the shipped
        // behavior; also `#[cfg]`-elided without `router-multicast-faces`).
        //
        // Why NOT DR-gate local-client egress (the limit-(b) decision, R311y200 sub
        // plane): a router is its OWN clients' bridge to the group, so it must always
        // egress their Puts unconditionally. DR-gating local egress would BLACKHOLE
        // under asymmetric / transient membership (the producer suppresses its local
        // egress while the DR has not converged / never advertised the sub) — strictly
        // LESS robust than zenoh, which never DR-gates and tolerates the duplicate. The
        // residual is limit (b): a bounded, loop-safe DUPLICATE when two mesh-peered
        // routers share a group (producer's local egress + the DR's mesh re-egress).
        // Its safe elimination is effectively-once via (origin,SN)/HLC egress dedup —
        // a routing-wide QoS follow-up, NOT the naive local-egress DR-gate. (Pre-S2
        // this cited "group subs not yet propagated"; S2/R311y200 propagates them, but
        // the bridge-your-own-clients reason is independent and stands.)
        //
        // CAVEAT (single-group): one member set covers all attached groups;
        // `run_router_hat` attaches exactly one, so this is exact. A future second
        // `attach_mcast_group` with distinct membership needs a per-group set.
        // CAVEAT (trust): the DR candidate pool comes from unauthenticated
        // multicast JOINs (whatami=Router) — a LAN attacker advertising Router can
        // win the HRW and blackhole those keyexprs. Same LAN-trust boundary the
        // rest of the unauthenticated multicast plane already assumes.
        #[cfg(feature = "router-multicast-faces")]
        if source_is_mesh && !self.is_group_dr(keyexpr) {
            return;
        }
        let groups = self.mcast_groups.borrow();
        if groups.is_empty() {
            return;
        }
        // Re-literalize ONCE against the `route_push`-resolved `keyexpr`: a
        // multicast group is a downstream link with NO shared expr-id alias table
        // (a group leaf never saw the inbound face's `DeclKexpr`), so an ALIASED
        // (id-only) inbound push would egress an unresolvable wireexpr — a group
        // blackhole. Every sibling egress leg to a no-shared-table downstream
        // reliteralizes for the same reason (`deliver_to_client_subscribers`,
        // `compute_self_publish_forward`); a literal push is forwarded verbatim.
        let Ok(carrier) = reliteralize_push(push, keyexpr) else {
            return;
        };
        for group in groups.iter() {
            // Fire-and-forget: a dropped receiver = a dead multicast link, the
            // same contract the drive loop's own reply backing carries.
            let _ = group.tx.send(MulticastTxItem::Push {
                push: Box::new(carrier.clone()),
                reliable,
                // R311y227 — the received routing band (the inbound frame's decoded
                // priority) egresses to the group on its own conduit when the group
                // negotiated is_qos; `multicast_tx_emit` clamps it back to DEFAULT
                // on a non-qos group (byte-identical). This closes the "mcast-egress
                // band" residual: a QoS client's prioritized Put reaches the group
                // at its band, not DEFAULT.
                priority,
            });
        }
    }

    /// Whether SELF is the Designated Router (DR) that bridges the multicast
    /// group ↔ the unicast mesh for `keyexpr` — the I3b loop-safety election.
    /// Reuses the seedless-SipHash HRW [`elect_router`] (the same primitive
    /// [`is_master`](Self::is_master) uses) over the on-group ROUTER members ∪
    /// self, keyed on the resolved literal keyexpr (zenoh's per-keyexpr master
    /// granularity). Determinism ⇒ every on-group router agrees on the ONE bridge
    /// for a keyexpr, so exactly one federates a group-ingress Push into the mesh
    /// and exactly one egresses a mesh/local Put to the group — loop-free by
    /// construction for the two-router-shared-group topology zenoh's
    /// `WhatAmI::Client` "Quick hack" leaves undefended (`router.rs:226`; zenoh's
    /// `egress_filter` both-multicast deny keys on the immediate face, so a
    /// mesh-hop-federated copy re-egresses and loops). Empty members ⇒ self is the
    /// SOLE candidate (self is always chained in) ⇒ `elect_router` returns
    /// `self_zid` ⇒ self is the DR (the single-router / egress-only case,
    /// unchanged). DERIVED per call (no
    /// stored verdict), like `is_master` — it can never drift from the live
    /// member set.
    #[cfg(feature = "router-multicast-faces")]
    fn is_group_dr(&self, keyexpr: &str) -> bool {
        let self_zid = *self.routers_net.borrow().self_zid();
        let members = self.mcast_group_members.borrow();
        elect_router(
            &self_zid,
            keyexpr,
            members.iter().chain(core::iter::once(&self_zid)),
        ) == self_zid
    }

    /// Whether a multicast-INGRESS Push may be federated into the unicast mesh —
    /// the I3b Designated-Router gate on the mcast-ingress -> mesh leg. Only the
    /// elected DR for `keyexpr` federates a group-ingress Push, so exactly one
    /// on-group router bridges the group into the mesh (loop-free even when two wz
    /// routers share the group and are mesh-peered). Without `router-multicast-faces`
    /// there is no ingress plane / DR election, so this is always `false` and the
    /// `!inbound_is_mcast` gate alone stands (a mcast-ingress Push reaches LOCAL
    /// subscribers only, the I1 behavior).
    #[cfg(feature = "router-multicast-faces")]
    fn mcast_ingress_may_federate(&self, keyexpr: &str) -> bool {
        self.is_group_dr(keyexpr)
    }
    #[cfg(not(feature = "router-multicast-faces"))]
    fn mcast_ingress_may_federate(&self, _keyexpr: &str) -> bool {
        false
    }

    /// Resolve a `Push`'s wire keyexpr against the inbound face's alias table —
    /// the scoped-borrow head [`route_push`](Self::route_push) runs ONCE to elect
    /// the master and feed the client-delivery / bridge / publish legs the literal
    /// keyexpr. (The within-tier [`forward_push_tier`](Self::forward_push_tier)
    /// resolves again in its own borrow, since it also needs the inbound zid/link
    /// there; `resolve_wireexpr` is pure, so the two resolutions are identical.)
    /// `None` = the face is gone or the alias id is unknown (drop the Push).
    fn resolve_inbound_keyexpr(&self, inbound: FaceId, push: &PushOwned) -> Option<String> {
        // The multicast INGRESS sentinel face carries NO per-peer alias table (I1
        // single group-ingress face, literal-only): resolve against an EMPTY table
        // — a literal (id==0) push yields its suffix; an aliased id-only push
        // yields None and is dropped (per-peer alias tracking is the deferred I3
        // milestone). The sentinel is not in `faces`, so this branch precedes the
        // faces lookup below (which would otherwise return None and drop it).
        #[cfg(feature = "transport-multicast")]
        if inbound == MCAST_INGRESS_FACE {
            return resolve_wireexpr(&push.keyexpr.body, &hashbrown::HashMap::new());
        }
        let faces = self.faces.borrow();
        let s = faces.get(&inbound)?;
        resolve_wireexpr(&push.keyexpr.body, &s.keyexpr_table)
    }

    /// Whether SELF is the elected route master for `keyexpr` — the zenoh
    /// `compute_data_route` master decision (`hat/router/pubsub.rs:1284`): master
    /// IFF self wins the HRW election ([`elect_router`]) over the SHARED nodes
    /// (routers present in BOTH meshes, [`shared_nodes`](Self::shared_nodes)).
    /// `shared_nodes` ALWAYS contains self (seeded in both nets), so a
    /// single-router topology ⇒ `shared = {self}` ⇒ self wins ⇒ `master = true`,
    /// making every C4 gate a no-op (the pre-C4 single-router behavior and its
    /// tests are unchanged).
    ///
    /// DERIVED per call — no stored `shared_nodes` field, hence no
    /// topology-teardown obligation on `deregister` (the wz derive-not-store
    /// idiom, R311y109). This also matches zenoh, which recomputes `shared_nodes`
    /// synchronously at every topology event (`mod.rs:385..724`) rather than
    /// lazily; deriving at read time is the wz equivalent that additionally can
    /// never drift from the live graph.
    fn is_master(&self, keyexpr: &str) -> bool {
        let self_zid = *self.routers_net.borrow().self_zid();
        let shared = self.shared_nodes();
        elect_router(&self_zid, keyexpr, shared.iter()) == self_zid
    }

    /// The routers present in BOTH link-state meshes — zenoh `shared_nodes`
    /// (`network.rs:1197`), the candidate set for the route-master election. A
    /// pure zid intersection of the two nets' node sets (no whatami /
    /// reachability filter, exactly as zenoh); self is a node in both (seeded at
    /// each net's construction), so the result is never empty. DERIVED on demand
    /// from the current graphs (the derive-not-store idiom): a router leaving
    /// either mesh simply drops out of the next call's intersection, with no
    /// incremental teardown to order against `deregister`.
    fn shared_nodes(&self) -> Vec<Zid> {
        let routers: HashSet<Zid> = self.routers_net.borrow().node_zids().collect();
        let mut shared: Vec<Zid> = self
            .linkstatepeers_net
            .borrow()
            .node_zids()
            .filter(|z| routers.contains(z))
            .collect();
        // Sort for a DETERMINISTIC election tie-break across routers: `node_zids`
        // iterates a std `HashMap` (`RandomState` order), so an unsorted candidate
        // set would let two wz routers break an HRW tie differently and disagree on
        // the master. A tie needs a 2^-64 SipHash collision (zenoh carries the same
        // exposure via its own graph order), and [`elect_router`] picks the MAX
        // hash, so sorting is election-neutral for every non-colliding keyexpr while
        // removing even that residual divergence — every wz router elects the same
        // master from the same shared set.
        shared.sort_unstable();
        shared
    }

    /// Bridge a MESH-sourced data `Push` across to the OTHER mesh (C4) — the
    /// master-gated CROSS-tier half of zenoh `compute_data_route` (the
    /// non-native-tier legs of blocks 1 & 2, `pubsub.rs:1291`/`:1307`): when self
    /// is the elected route master for `keyexpr`, a PEER-sourced Push is
    /// re-injected into the ROUTER mesh's subs, and a ROUTER-sourced Push into
    /// the PEER mesh's subs. The within-tier legs are
    /// [`forward_push_tier`](Self::forward_push_tier) (ungated); a
    /// [`FaceTier::Client`] inbound has no mesh source (its mesh path is
    /// [`publish_client_push_into_meshes`](Self::publish_client_push_into_meshes)),
    /// so it never bridges here.
    ///
    /// The cross leg is a SELF-origination
    /// ([`compute_self_publish_forward`] — self as tree root, node_id 0) exactly
    /// as zenoh stamps `router_source` / `peer_source` = self's net index for a
    /// non-native source (`pubsub.rs:1295`/`:1311`), NOT the transit
    /// [`compute_push_forward`] (which would DROP the source: the peer/router
    /// origin is not a node of the OTHER net). Master-gated so only the single
    /// HRW-elected router bridges: in a federated 2-router mesh a cross-mesh Push
    /// is delivered exactly once, and the bridged (now router-source) copy is not
    /// re-bridged by the other router (it is not master). Routes through
    /// [`fan_out_tier`](Self::fan_out_tier) so it inherits the future
    /// interceptor / egress-ACL gate (the y113 obligation).
    fn bridge_push_cross_mesh(
        &self,
        inbound_tier: FaceTier,
        reliable: bool,
        priority: Priority,
        push: &PushOwned,
        keyexpr: &str,
        master: bool,
    ) {
        if !master {
            return; // only the elected master bridges (double-delivery / loop guard)
        }
        let target_tier = match inbound_tier {
            FaceTier::LinkstatePeers => FaceTier::Routers,
            FaceTier::Routers => FaceTier::LinkstatePeers,
            FaceTier::Client => return, // a client's mesh path is C3b, not a bridge
        };
        // The cross leg re-injects the RECEIVED mesh frame into the target mesh (self
        // tree root, node_id 0) via the shared self-publish-into-tier seam, PRESERVING
        // the received band (R311y224) — a mesh source can be QoS-negotiated, so the
        // bridged copy must carry the same priority the within-tier copy does.
        self.self_publish_into_tier(target_tier, reliable, priority, push, keyexpr);
    }

    /// Route a data `Push` WITHIN its inbound tier's mesh (C1) — the router twin
    /// of [`LinkstateForwarder::forward_push`], calling the shared
    /// [`compute_push_forward`] core on the INBOUND tier's `(net, subs)` and
    /// fanning the result out tier-scoped. This is the WITHIN-TIER half only: it
    /// maps to zenoh's non-cross-tier route blocks — a peer-sourced Push to
    /// peer-mesh subs, a router-sourced Push to router-mesh subs, both
    /// master-gate-free in `compute_data_route`. The CROSS-tier bridge
    /// ([`bridge_push_cross_mesh`](Self::bridge_push_cross_mesh), C4), local-client
    /// delivery ([`deliver_to_client_subscribers`](Self::deliver_to_client_subscribers),
    /// C3a), and master-election ([`is_master`](Self::is_master), C4) are the OTHER
    /// [`route_push`](Self::route_push) legs, now landed. A [`FaceTier::Client`] Push
    /// has no mesh to route within,
    /// so it is only counted (the reception witness in [`forward`]). A drop
    /// (unresolvable source / no interested subscriber / hop-exhausted) is silent,
    /// as in the single-net path.
    fn forward_push_tier(
        &self,
        inbound: FaceId,
        tier: FaceTier,
        reliable: bool,
        priority: Priority,
        push: &PushOwned,
    ) {
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
        // R311y224 — preserve the received band on the within-tier transit
        // re-forward: route through `fan_out_tier_qos` on the frame's `priority`
        // (express stays false — a FramePayload carries no express bit), so an
        // aggregated QoS multilink mesh peer pins the relay onto the band link. The
        // router twin of the peer plane's `forward_push` (R311y221). DEFAULT under a
        // non-QoS session (the `dispatch_push` clamp).
        let _ = self.fan_out_tier_qos(tier, reliable, priority, false, |id, zid| {
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
    /// client leaf shares no alias table). Excludes the inbound face, so it covers
    /// mesh->client AND client->client. Zenoh block-3 MASTER-GATED
    /// (`pubsub.rs:1323`, `master || source == Router`): a Push from a
    /// Peer/Client source is delivered only when self is the route master
    /// (`master`), so a NON-master router defers to the copy the master bridges
    /// back as a ROUTER source — else a client on a non-master would get the Push
    /// twice. A Router-source Push (the bridged copy) is always delivered. In a
    /// single-router topology `master` is always true, so this is unconditional as
    /// before. A client-sourced Push reaching the MESH (client->peer, a
    /// self-sourced re-injection) is the SIBLING C3b path
    /// ([`publish_client_push_into_meshes`](Self::publish_client_push_into_meshes));
    /// LOCAL self-hosted delivery stays deferred (a pure router hosts no
    /// subscribers — that is the combined-node seam). Routes through the
    /// [`fan_out_tier`](Self::fan_out_tier) egress SSOT
    /// (`FaceTier::Client`) like every other router send, so it inherits the
    /// interceptor / egress-ACL gate once that plane lands on the seam (the y113
    /// obligation) rather than being a separate retrofit site.
    // R311y225 added the `priority` band arg (client-egress band preservation),
    // crossing the 7-arg lint; the args are the irreducible routing context
    // (source, tier, reliability, band, payload, keyexpr, master-gate).
    #[allow(clippy::too_many_arguments)]
    fn deliver_to_client_subscribers(
        &self,
        inbound: FaceId,
        inbound_tier: FaceTier,
        reliable: bool,
        priority: Priority,
        push: &PushOwned,
        keyexpr: &str,
        master: bool,
    ) {
        // Block-3 master gate (zenoh pubsub.rs:1323, `master || source == Router`):
        // a NON-master router defers its local client delivery to the copy the
        // master bridges back as a ROUTER source, so a client subscribing on a
        // non-master router is NOT delivered its own Peer/Client-source copy (which
        // it would then ALSO receive as the bridged router-source copy = a double
        // delivery). Single-router => master => unconditional, as before C4.
        if inbound_tier != FaceTier::Routers && !master {
            // C4 double-delivery guard fired: a non-master router defers this
            // peer/client-source client delivery (the master's bridged
            // router-source copy delivers instead). Count it — but only when a
            // client sub exists, so the witness reflects a delivery actually
            // suppressed, not a vacuous defer on a router hosting no clients.
            if !self.client_subs.borrow().is_empty() {
                self.deferred_client_delivery
                    .set(self.deferred_client_delivery.get() + 1);
            }
            return;
        }
        if self.client_subs.borrow().is_empty() {
            return;
        }
        // Re-literalize once (payload / encoding / attachment preserved, literal
        // keyexpr for the client leaf); the fan-out clones it per matching client.
        // `keyexpr` is resolved once by the [`route_push`](Self::route_push) head.
        let Ok(mut carrier) = reliteralize_push(push, keyexpr) else {
            return;
        };
        // A client subscriber is a LEAF, not a routing-graph node: reset the Push's
        // routing source node-id to 0 (set_push_source(_, 0) omits the ext, zenoh's
        // omit-on-DEFAULT). reliteralize_push PRESERVES the inbound push's ext_nodeid;
        // a Peer/Router-source (or bridged-master) Push carries a NON-ZERO source, and
        // forwarding it to a client (e.g. a pico z_sub) is a protocol violation the
        // client rejects by CLOSING its transport (its Push decoder has no case for the
        // mandatory ext_nodeid id 0x03). Faithful to zenoh pubsub.rs (a client-sub
        // data-route direction node-id is NodeId::default()=0). The DATA-plane twin of
        // the R311y179 forward_request_to_client_queryables source-reset fix.
        set_push_source(&mut carrier, 0);
        // Deliver to each Client-tier face subscribing a keyexpr that INTERSECTS
        // the published K, excluding the inbound face (never echo a client's own
        // Push back to it). Wildcard-aware via the SAME `keyexpr_intersects_target`
        // SSOT the mesh data route reads through `interested_remote` — a client
        // subscribing `demo/**` must receive a `demo/data` Push, NOT just an exact
        // `demo/data` sub (exact `HashSet::contains` would silently blackhole every
        // wildcard client sub, re-opening the very gap C3 closes).
        let target_chunks: Vec<&str> = keyexpr.split('/').collect();
        // R311y225 — preserve the received band on the CLIENT-face egress (the y224
        // residual): route through `fan_out_tier_qos` on the frame's `priority`, so a
        // QoS-negotiated client observes the same band the mesh legs carry (zenoh
        // `route_data` copies `ext_qos` onto client-face egress the same as any egress,
        // pubsub.rs). DEFAULT under a non-QoS session; a pico client negotiates no
        // unicast ext_qos so it stays DEFAULT. (The QUERY-plane client egress -- a
        // Response to a client querier -- is a separate, uniformly-DEFAULT plane, out
        // of scope here.)
        let _ = self.fan_out_tier_qos(FaceTier::Client, reliable, priority, false, |id, _zid| {
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

    /// Re-inject a CLIENT-sourced data `Push` into BOTH meshes as a SELF-sourced
    /// publish (C3b) — the remaining client data direction, CLOSING the
    /// client->peer blackhole: a client's Put now reaches subscribing MESH peers,
    /// not just other clients ([`deliver_to_client_subscribers`], C3a). A client
    /// is a leaf below exactly ONE router, so SELF is the unique origin node in
    /// each net; this mirrors [`LinkstateForwarder::publish`] via the shared
    /// [`compute_self_publish_forward`] core (self as tree root, node_id 0, fresh
    /// per-net hop budget) — NOT the transit [`compute_push_forward`], which
    /// would DROP a client source (the client zid is not a mesh node, so
    /// `resolve_source_in` finds no psid for it). `reliteralize_push` preserves
    /// the client sample's encoding/attachment/timestamp/qos (a RE-injected
    /// sample, unlike `publish`'s fresh `build_push_literal`). Precondition: the
    /// dispatch calls this ONLY for a [`FaceTier::Client`] inbound Push — a
    /// mesh-sourced Push is routed within-tier by [`forward_push_tier`] and its
    /// cross-tier (mesh->other-mesh) bridge is the master-gated C4 slice, NOT this
    /// self-origination (calling it for a mesh source would self-source re-inject
    /// = a loop). Routes through the [`fan_out_tier`](Self::fan_out_tier) egress
    /// SSOT so it inherits the future interceptor/egress-ACL gate (the y113
    /// obligation) rather than being a separate retrofit site. `reliable` follows
    /// the inbound frame (per-message data reliability), unlike `publish`'s
    /// hard-coded `true` (a fresh local produce).
    fn publish_client_push_into_meshes(
        &self,
        reliable: bool,
        priority: Priority,
        push: &PushOwned,
        keyexpr: &str,
        master: bool,
    ) {
        // `keyexpr` is the literal already resolved against the inbound (client)
        // face's alias table by the [`route_push`](Self::route_push) head — a
        // downstream mesh peer shares no alias table, so the re-injection carries
        // the literal.
        for tier in [FaceTier::Routers, FaceTier::LinkstatePeers] {
            // Zenoh route_data for a CLIENT (non-router) source: the ROUTER-net leg
            // (block 1, `pubsub.rs:1291`) requires `master`, while the PEER-net leg
            // (block 2, `pubsub.rs:1307`) is UNgated for a non-router source. A
            // non-master router that skips its router leg lets the single elected
            // master be the sole injector, so a router-net subscriber reachable via
            // two masters receives the Put exactly once. Single-router => master =>
            // both legs fire, as before C4. (Zenoh also inserts `mcast_groups` faces
            // at `pubsub.rs:1334` -- an unbuilt wz plane, deferred with multicast.)
            if tier == FaceTier::Routers && !master {
                continue;
            }
            self.self_publish_into_tier(tier, reliable, priority, push, keyexpr);
        }
    }

    /// Self-originate a data `Push` into ONE mesh tier — the shared seam for both
    /// self-sourced re-injections: the C4 cross-mesh
    /// [`bridge_push_cross_mesh`](Self::bridge_push_cross_mesh) (a mesh-source Push
    /// re-injected into the OTHER tier) and the C3b
    /// [`publish_client_push_into_meshes`](Self::publish_client_push_into_meshes) (a
    /// client-source Push into both tiers). Runs the shared
    /// [`compute_self_publish_forward`] core (self tree root, node_id 0) on the
    /// tier's `(net, subs)` and fans the result out through the
    /// [`fan_out_tier`](Self::fan_out_tier) egress SSOT. The CALLER owns the
    /// master-gating + tier selection (bridge = the one opposite tier when master;
    /// publish = both tiers, router leg master-gated); this seam is the gate-free
    /// plumbing they shared verbatim. A drop (no interested sub / no tree child /
    /// build err) is silent.
    fn self_publish_into_tier(
        &self,
        tier: FaceTier,
        reliable: bool,
        priority: Priority,
        push: &PushOwned,
        keyexpr: &str,
    ) {
        let Some((net, _)) = self.plane(tier) else {
            return;
        };
        let Some(subs) = self.subs_table(tier) else {
            return;
        };
        let carrier_children =
            compute_self_publish_forward(net, subs, keyexpr, || reliteralize_push(push, keyexpr));
        let Ok(Some((carrier, children))) = carrier_children else {
            return; // no interested mesh sub / no tree direction / build err
        };
        // R311y224 — preserve the received band on the cross-mesh / client->mesh
        // re-inject: this seam RELITERALIZES a RECEIVED frame (`reliteralize_push`),
        // so it is a transit re-forward of a banded sample (NOT a fresh produce like
        // `publish` / the peer `publish_qos`), and the band survives the tier bridge.
        // The `node_id 0` tree-root is a routing-graph fact (the source zid is not a
        // node in the TARGET net), not a QoS-provenance reset. zenoh `route_data`
        // copies `ext_qos` across the cross-HAT federation the same as any egress.
        // DEFAULT under a non-QoS session. The band is threaded UNCONDITIONALLY, so the
        // C3b client->mesh re-inject preserves whatever band the client frame carried
        // (a pico client negotiates no unicast ext_qos, so that band is typically
        // DEFAULT — but the seam does not rely on it).
        let _ = self.fan_out_tier_qos(tier, reliable, priority, false, |_id, zid| {
            Ok(zid
                .filter(|z| children.contains(z))
                .map(|_| NetworkMessage::Push(Box::new(carrier.clone()))))
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
        // §5.21 routing-token-tables (slice-2) — re-advertise the native tokens to
        // the tier's NEW tree children too, so a late-joining child converges on
        // the within-tier token bubble (closes the slice-1 register-only gap where
        // an ingested native token was never re-advertised to a late joiner).
        #[cfg(feature = "routing-token-tables")]
        if let Some(tokens) = self.tokens_table(tier) {
            re_advertise_interest_into(
                net,
                tokens,
                &new_children,
                |ke, _: &()| build_declare_token(0, 0, Some(ke)),
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
        // client interested in `keyexpr` (the client half of the derive flips
        // false -> true). Per-target-tier: a mesh an opposite-tier native already
        // advertises is skipped (R311y125 — no redundant flood).
        let already = self.any_client_subscribes(&keyexpr);
        let inserted = self
            .client_subs
            .borrow_mut()
            .entry(inbound)
            .or_default()
            .insert(keyexpr.clone());
        if inserted {
            if !already {
                self.advertise_client_cross_tier_sub(&keyexpr);
            }
            // FUTURE-mode push: a new client sub -> declare it to any OTHER client
            // face whose stored FUTURE interest matches (client-to-client via this
            // router). Fires even when `already` (a co-client subscribes): the push
            // dedups per interest-holder via the pushed registry, so a holder the
            // earlier sub already covered is a no-op. `inbound` (the source) is
            // never echoed.
            self.push_future_subscription(&keyexpr, inbound);
        }
    }

    /// Emit the unsolicited FUTURE `DeclareSubscriber` pushes a newly-learned
    /// subscription `new_ke` (sourced at `origin`) triggers: one per CLIENT face
    /// whose stored FUTURE interest matches and has not yet been told this reply ke
    /// (zenoh `propagate_simple_subscription_to`). The push carries the interned
    /// non-zero decl id, `interest_id: None`, no `I` flag — an unsolicited declare,
    /// NOT an interest reply. `origin` is never pushed (no self-echo).
    fn push_future_subscription(&self, new_ke: &str, origin: FaceId) {
        let pushes = self
            .future_subs
            .borrow_mut()
            .pushes_for_new(new_ke, Some(origin), |_, _| ());
        for (face, reply_ke, id, ()) in pushes {
            match build_declare_subscriber(id, 0, Some(&reply_ke)) {
                Ok(decl) => {
                    self.send_one_to_face(face, NetworkMessage::Declare(Box::new(decl)));
                    self.future_pushes.set(self.future_pushes.get() + 1);
                }
                Err(e) => log::warn!(
                    "router forward: future sub push build failed for {reply_ke:?}: {e:?}"
                ),
            }
        }
    }

    /// §5.21 routing-token-tables (slice-4) — emit the unsolicited FUTURE
    /// `DeclareToken` pushes a newly-learned token `new_ke` (sourced at `origin`)
    /// triggers: one per CLIENT face whose stored FUTURE token interest matches and
    /// has not yet been told this ke (zenoh `propagate_simple_token`). The token twin
    /// of [`push_future_subscription`](Self::push_future_subscription); the push
    /// carries the interned non-zero decl id, `interest_id: None`, no `I` flag — an
    /// unsolicited declare. `origin` is never pushed (no self-echo). The self-delivery
    /// guard `|| dst.zid == tables.zid` (zenoh `propagate_simple_token_to:98`, the
    /// token-only disjunct absent from the sub guard) targets the router's own
    /// co-located local-session face; wz's forwarder has NO self-session face (external
    /// transport faces only, and `future_tokens` stores CLIENT faces only), so the
    /// guard is a faithful NO-OP here — if wz later co-locates a session on the router
    /// node, this push must NOT exclude a face whose zid == self's zid.
    #[cfg(feature = "routing-token-tables")]
    fn push_future_token(&self, new_ke: &str, origin: FaceId) {
        let pushes =
            self.future_tokens
                .borrow_mut()
                .pushes_for_new(new_ke, Some(origin), |_, _| ());
        for (face, reply_ke, id, ()) in pushes {
            match build_declare_token(id, 0, Some(&reply_ke)) {
                Ok(decl) => {
                    self.send_one_to_face(face, NetworkMessage::Declare(Box::new(decl)));
                    self.future_token_pushes
                        .set(self.future_token_pushes.get() + 1);
                }
                Err(e) => log::warn!(
                    "router forward: future token push build failed for {reply_ke:?}: {e:?}"
                ),
            }
        }
    }

    /// The MERGED [`QueryableInfo`] the querier on `exclude_face` interested in `ke`
    /// would see — the OR of `complete` (min of `distance`) over EVERY queryable wz
    /// holds that intersects `ke` (`router_qabls` + `linkstatepeer_qabls` excluding
    /// self, plus `client_qabls` EXCLUDING the destination face) — the value a FUTURE
    /// qabl push/re-push MUST carry: a single source's raw info would DOWNGRADE an
    /// aggregate reply (`merge` is OR-complete) and re-arm an ALL_COMPLETE filter.
    /// Excluding `exclude_face` keeps the CURRENT-dump seed
    /// ([`dump_interest_qabls`](Self::dump_interest_qabls), which inlines the SAME fold
    /// excluding the requesting `inbound`), the ingest push, and the R311y153
    /// downgrade re-push all like-for-like, so the stored value never drifts.
    ///
    /// DIVERGENCE from zenoh (benign, source-verified): zenoh's `local_qabl_info(res,
    /// dst_face)` excludes the dst's own contribution only CONDITIONALLY — for a CLIENT
    /// dst it FOLDS IN the dst's own queryable (hat/router/queries.rs:175-177, the
    /// `face.whatami != Peer` disjunct), keeping that client's filter OFF via the fold.
    /// wz excludes `exclude_face` UNCONDITIONALLY. The OUTCOME is nonetheless equivalent
    /// for a co-hosted COMPLETE queryable: that scenario requires pico
    /// `Z_FEATURE_LOCAL_QUERYABLE`, which registers the local queryable as a
    /// `local_target` (zenoh-pico `net/filtering.c` `_z_write_filter_ctx_update_state`:
    /// the filter is ACTIVE only when `targets == NULL && local_targets == 0`), so the
    /// co-hosted queryable keeps the write-filter OFF independent of what wz declares —
    /// no black-hole. Different mechanism (pico `local_targets` vs zenoh fold-in), same
    /// outcome (filter stays OFF, the querier's get flows to the local answerer).
    fn merged_qabl_info(&self, ke: &str, self_zid: &Zid, exclude_face: FaceId) -> QueryableInfo {
        let mut merged: Option<QueryableInfo> = None;
        let mut fold = |info: QueryableInfo| {
            merged = Some(match merged {
                Some(m) => m.merge(info),
                None => info,
            });
        };
        for table in [&self.router_qabls, &self.linkstatepeer_qabls] {
            for (_ke, _zid, info) in table.borrow().matching_entries(ke, Some(self_zid)) {
                fold(*info);
            }
        }
        let ke_chunks: Vec<&str> = ke.split('/').collect();
        for (face, m) in self.client_qabls.borrow().iter() {
            if *face == exclude_face {
                continue; // don't fold the destination querier's own queryable
            }
            for (k, info) in m {
                if keyexpr_intersects_target(k, &ke_chunks) {
                    fold(*info);
                }
            }
        }
        merged.unwrap_or(QueryableInfo::DEFAULT)
    }

    /// Emit the unsolicited FUTURE `DeclareQueryable` pushes a newly-learned
    /// queryable `new_ke` (sourced at `origin`) triggers — the query-plane twin of
    /// [`push_future_subscription`](Self::push_future_subscription). Each push
    /// carries the RE-FOLDED merged [`QueryableInfo`] for its reply ke
    /// ([`merged_qabl_info`](Self::merged_qabl_info)), so an aggregate reply folds
    /// the whole target and a completeness flip `false -> true` re-declares the SAME
    /// interned id (pico updates the `(decl_id, peer)` write-filter target in place).
    /// `origin` is never pushed (no self-echo).
    fn push_future_queryable(&self, new_ke: &str, origin: FaceId) {
        let self_zid = *self.routers_net.borrow().self_zid();
        let pushes = self.future_qabls.borrow_mut().pushes_for_new(
            new_ke,
            Some(origin),
            |reply_ke, dest| self.merged_qabl_info(reply_ke, &self_zid, dest),
        );
        for (face, reply_ke, id, info) in pushes {
            match build_declare_queryable_with_id_info(id, &reply_ke, info) {
                Ok(decl) => {
                    self.send_one_to_face(face, NetworkMessage::Declare(Box::new(decl)));
                    self.future_qabl_pushes
                        .set(self.future_qabl_pushes.get() + 1);
                }
                Err(e) => log::warn!(
                    "router forward: future qabl push build failed for {reply_ke:?}: {e:?}"
                ),
            }
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
        if removed {
            if !self.any_client_subscribes(&keyexpr) {
                self.withdraw_client_cross_tier_sub(&keyexpr);
            }
            // R311y151 undeclare-push: this client sub is gone; re-arm any waiting
            // publisher whose pushed reply ke lost its last backer.
            self.undeclare_push_subs(&keyexpr);
        }
    }

    /// Whether ANY client face currently subscribes `keyexpr` — the CLIENT half of
    /// the cross-tier advertise derive (the C2 contributor). The full predicate is
    /// [`self_advertises_sub_into`](Self::self_advertises_sub_into): self is a
    /// virtual sub-source in a mesh IFF this is true OR the OPPOSITE mesh holds a
    /// native for `keyexpr` (the A2a federation contributor). Client-agnostic to
    /// tier — a client subscribing feeds BOTH meshes.
    fn any_client_subscribes(&self, keyexpr: &str) -> bool {
        self.client_subs
            .borrow()
            .values()
            .any(|set| set.contains(keyexpr))
    }

    /// Whether ANY subscription wz still holds INTERSECTS `ke` — the "still backed"
    /// existence predicate the R311y151 undeclare-push consults AFTER a withdrawal to
    /// decide whether a pushed reply ke has lost its LAST backer (`false` => undeclare
    /// and re-arm the filter). Folds GLOBALLY (no self/dest-face exclusion): the
    /// current dump's "backed" is `matching_entries` non-empty or an intersecting
    /// client sub, so a per-destination exclusion here would spuriously undeclare a
    /// reply ke still backed by a co-hosted or self sub.
    fn any_sub_matches(&self, ke: &str) -> bool {
        for table in [&self.router_subs, &self.linkstatepeer_subs] {
            if !table.borrow().matching_entries(ke, None).is_empty() {
                return true;
            }
        }
        let chunks: Vec<&str> = ke.split('/').collect();
        self.client_subs
            .borrow()
            .values()
            .any(|set| set.iter().any(|k| keyexpr_intersects_target(k, &chunks)))
    }

    /// The queryable twin of [`any_sub_matches`](Self::any_sub_matches). An EXISTENCE
    /// check, NOT [`merged_qabl_info`](Self::merged_qabl_info) (which folds to
    /// `QueryableInfo::DEFAULT` on zero matches — a value read would report "backed"
    /// even when no queryable exists and suppress every undeclare).
    fn any_qabl_matches(&self, ke: &str) -> bool {
        for table in [&self.router_qabls, &self.linkstatepeer_qabls] {
            if !table.borrow().matching_entries(ke, None).is_empty() {
                return true;
            }
        }
        let chunks: Vec<&str> = ke.split('/').collect();
        self.client_qabls
            .borrow()
            .values()
            .any(|m| m.keys().any(|k| keyexpr_intersects_target(k, &chunks)))
    }

    /// Emit the R311y151 UNDECLARE pushes a withdrawn SUBSCRIPTION `withdrawn_ke`
    /// triggers: for each CLIENT face whose pushed reply ke is now UN-backed, an
    /// unsolicited `UndeclareSubscriber(id)` (interest_id None) that re-arms the pico
    /// publisher's write-filter, clearing the stale `pushed` entry so a later
    /// re-declaration re-pushes (the residual the y146/y150 store documented). Run
    /// AFTER the withdrawn sub is removed from its table so `any_sub_matches` is
    /// post-withdrawal.
    fn undeclare_push_subs(&self, withdrawn_ke: &str) {
        let forgets = self
            .future_subs
            .borrow_mut()
            .forgets_for_withdrawn(withdrawn_ke, |rk| self.any_sub_matches(rk));
        for (face, _reply_ke, id) in forgets {
            self.send_one_to_face(
                face,
                NetworkMessage::Declare(Box::new(build_undeclare_subscriber(id))),
            );
        }
    }

    /// The queryable twin of [`undeclare_push_subs`](Self::undeclare_push_subs). TWO
    /// halves, both fired here so every caller (graceful native / client undeclare +
    /// the detach choke point) gets both:
    /// - `forgets_for_withdrawn` -> `UndeclareQueryable(id)` for each reply ke now
    ///   FULLY un-backed (its last backer gone) — R311y151/y152.
    /// - `re_pushes_for_withdrawn` -> a re-declared `DeclareQueryable(id, ke,
    ///   DOWNGRADED info)` for each STILL-backed reply ke whose FOLDED completeness
    ///   dropped (case c, R311y153), so an ALL_COMPLETE querier's filter re-arms. The
    ///   client-facing twin of zenoh's `register_router_queryable(local_router_qabl_info)`
    ///   partial-removal re-declare — reached from a graceful undeclare via
    ///   `undeclare_simple_queryable` (hat/router/queries.rs:808-809) and from a
    ///   node-removal via `queries_remove_node` (:930-940); both route through the same
    ///   `propagate_simple_queryable` value-diff gate (:255). Uses the SAME
    ///   `merged_qabl_info` fold `push_future_queryable` uses (excludes self + dest).
    ///
    /// Run AFTER the withdrawn qabl left its table (both folds are post-withdrawal).
    /// `forgets` runs FIRST so `re_pushes` only re-folds the SURVIVORS — no reply ke is
    /// both undeclared and re-pushed (forgets removes the fully-unbacked from `pushed`;
    /// re_pushes scans what remains). Both store calls read `self.*_qabls` (distinct
    /// RefCells from `future_qabls`) via their closures — the proven `pushes_for_new`
    /// borrow shape.
    fn undeclare_push_qabls(&self, withdrawn_ke: &str) {
        let self_zid = *self.routers_net.borrow().self_zid();
        let (forgets, re_pushes) = {
            let mut store = self.future_qabls.borrow_mut();
            let forgets = store.forgets_for_withdrawn(withdrawn_ke, |rk| self.any_qabl_matches(rk));
            let re_pushes = store.re_pushes_for_withdrawn(withdrawn_ke, |rk, dest| {
                self.merged_qabl_info(rk, &self_zid, dest)
            });
            (forgets, re_pushes)
        };
        for (face, _reply_ke, id) in forgets {
            self.send_one_to_face(
                face,
                NetworkMessage::Declare(Box::new(build_undeclare_queryable(id))),
            );
        }
        for (face, reply_ke, id, info) in re_pushes {
            match build_declare_queryable_with_id_info(id, &reply_ke, info) {
                Ok(decl) => self.send_one_to_face(face, NetworkMessage::Declare(Box::new(decl))),
                Err(e) => log::warn!(
                    "router forward: qabl downgrade re-push build failed for {reply_ke:?}: {e:?}"
                ),
            }
        }
    }

    /// The mesh a NATIVE in `tier` advertises its cross-tier interest INTO — the
    /// OPPOSITE mesh (a `Routers` native attracts publishers on the `LinkstatePeers`
    /// mesh and vice versa), or `None` for [`FaceTier::Client`] (a client is in no
    /// mesh; its advertisement targets BOTH meshes, handled by the caller loop).
    fn opposite_mesh(tier: FaceTier) -> Option<FaceTier> {
        match tier {
            FaceTier::Routers => Some(FaceTier::LinkstatePeers),
            FaceTier::LinkstatePeers => Some(FaceTier::Routers),
            FaceTier::Client => None,
        }
    }

    /// Whether self SHOULD advertise interest in `keyexpr` into `target` mesh —
    /// the per-target-tier cross-tier-bubble derive SSOT (R311y125), read by the
    /// immediate advertise (client + native ingest), the tick re-advertise, and —
    /// as its exact NEGATION — the withdraw decision. Self attracts INTO a mesh
    /// when it can DELIVER `keyexpr` to a subscriber that is NOT on that mesh: a
    /// CLIENT sub (delivered by C3a) OR an OPPOSITE-mesh NATIVE (delivered by the
    /// master-gated cross-mesh bridge, C4). This is exactly zenoh's contributor
    /// set for the cross-registration — register_router_subscription cross-registers
    /// self into the PEER tier for a router-native (or client) sub (pubsub.rs:248-250),
    /// declare_linkstatepeer_subscription into the ROUTER tier for a peer-native
    /// (:296-297). DERIVE-not-STORE: the native is read from the OPPOSITE mesh's
    /// table (`contributor_subs_source_count`), self is never stored. NOT
    /// master-gated (every router advertises; only the DELIVERY bridge is gated).
    fn self_advertises_sub_into(&self, target: FaceTier, keyexpr: &str) -> bool {
        self.any_client_subscribes(keyexpr)
            || self.group_subscribes(keyexpr)
            || self.contributor_subs_source_count(target, keyexpr) > 0
    }

    /// Whether a multicast-group SUBSCRIBER holds `keyexpr` — the THIRD
    /// self-advertise contributor (§5.21 sub plane, S2), alongside local client
    /// subs and opposite-mesh natives. A group sub makes self advertise interest
    /// into the mesh exactly as a local client sub does (zenoh treats a
    /// `mcast_faces` Client-face sub as a router-owned sub). Without
    /// `router-multicast-faces` there is no ingress plane / group-sub relay, so this
    /// is always `false` and `self_advertises_sub_into` reduces to the pre-sub-plane
    /// client-|-native derive (byte-identical for non-router / egress-only builds).
    #[cfg(feature = "router-multicast-faces")]
    fn group_subscribes(&self, keyexpr: &str) -> bool {
        self.group_subs.borrow().contains(keyexpr)
    }
    #[cfg(not(feature = "router-multicast-faces"))]
    fn group_subscribes(&self, _keyexpr: &str) -> bool {
        false
    }

    /// The number of OPPOSITE-mesh NATIVE sub sources for the EXACT `keyexpr` that
    /// make self advertise into `target` — the native half of
    /// [`self_advertises_sub_into`](Self::self_advertises_sub_into). For
    /// `target = LinkstatePeers` this reads `router_subs`; for `target = Routers`,
    /// `linkstatepeer_subs`. `0` for a `Client` target (unused — clients are not a
    /// mesh) and when the opposite table has no exact-`keyexpr` source.
    fn contributor_subs_source_count(&self, target: FaceTier, keyexpr: &str) -> usize {
        Self::opposite_mesh(target)
            .and_then(|src| self.subs_table(src))
            .map_or(0, |t| t.borrow().source_count(keyexpr))
    }

    /// The keyexprs self should advertise into `target` mesh — client subs ∪ the
    /// OPPOSITE mesh's native subs, deduped. The set form of
    /// [`self_advertises_sub_into`](Self::self_advertises_sub_into) (a `K` is in
    /// this set IFF that predicate holds for `(target, K)` — same two sources), fed
    /// to the tick re-advertise
    /// ([`re_advertise_self_cross_tier`](Self::re_advertise_self_cross_tier)) for
    /// late-joining children.
    fn derived_cross_tier_subs_into(&self, target: FaceTier) -> Vec<String> {
        let mut set: HashSet<String> = HashSet::new();
        for keys in self.client_subs.borrow().values() {
            set.extend(keys.iter().cloned());
        }
        // §5.21 sub plane (S2) — the group-subscriber aggregate is a third source
        // in the tick re-advertise (a late-joining tree child converges on self's
        // cross-tier bubble for a group sub too, exactly as for a client sub).
        #[cfg(feature = "router-multicast-faces")]
        for keyexpr in self.group_subs.borrow().iter() {
            set.insert(keyexpr.clone());
        }
        if let Some(table) = Self::opposite_mesh(target).and_then(|src| self.subs_table(src)) {
            for (keyexpr, _peer, ()) in table.borrow().entries() {
                set.insert(keyexpr);
            }
        }
        set.into_iter().collect()
    }

    /// The keyexprs self should advertise a cross-tier token for into `target` mesh
    /// — CLIENT-held tokens ∪ the OPPOSITE mesh's native tokens, deduped. The exact
    /// token twin of
    /// [`derived_cross_tier_subs_into`](Self::derived_cross_tier_subs_into) (slice-3
    /// added the `client_tokens` fold — the set form of
    /// [`self_advertises_token_into`](Self::self_advertises_token_into)); fed to the
    /// tick re-advertise
    /// ([`re_advertise_self_cross_tier`](Self::re_advertise_self_cross_tier)) so a
    /// late-joining tree child converges on self's cross-tier token bubble.
    #[cfg(feature = "routing-token-tables")]
    fn derived_cross_tier_tokens_into(&self, target: FaceTier) -> Vec<String> {
        let mut set: HashSet<String> = HashSet::new();
        for ids in self.client_tokens.borrow().values() {
            set.extend(ids.values().cloned());
        }
        if let Some(table) = Self::opposite_mesh(target).and_then(|src| self.tokens_table(src)) {
            for (keyexpr, _peer, ()) in table.borrow().entries() {
                set.insert(keyexpr);
            }
        }
        set.into_iter().collect()
    }

    /// A CLIENT sub for `keyexpr` just appeared (the FIRST client for it): flood
    /// self's cross-tier ADVERTISEMENT into each mesh the client newly flips ON —
    /// a self-sourced `DeclareSubscriber` (node_id 0) to self's tree children, so
    /// a publisher on that mesh routes `keyexpr` toward this router. Skips a mesh
    /// an OPPOSITE-mesh native already advertises (the derive was already true for
    /// that target — no redundant flood). DERIVE-not-STORE: self is NOT stored;
    /// the advertisement is re-derived on the tick for late joiners. A single
    /// router has no router tree children, so the router-mesh flood is a no-op.
    fn advertise_client_cross_tier_sub(&self, keyexpr: &str) {
        // A group sub (§5.21 sub plane, S2) is a THIRD self-advertise contributor
        // that already flooded BOTH meshes, so the first client is NOT the false->true
        // flip edge — skip to preserve the flood-only-on-flip invariant (the mirror of
        // `advertise_group_cross_tier_sub`'s `!any_client_subscribes` early-out; the
        // withdraw side already negates the full 3-contributor derive). No-op without
        // `router-multicast-faces` (the `group_subscribes` cfg stub is `false`).
        if self.group_subscribes(keyexpr) {
            return;
        }
        for target in [FaceTier::Routers, FaceTier::LinkstatePeers] {
            // Flip false->true for this target IFF no native already covers it
            // (before this client, self_advertises_sub_into(target) == native-only,
            // since it was the first client).
            if self.contributor_subs_source_count(target, keyexpr) == 0 {
                self.flood_self_sourced(target, keyexpr, |ke| {
                    build_declare_subscriber(0, 0, Some(ke))
                });
            }
        }
    }

    /// The LAST client for `keyexpr` just left: flood self's cross-tier WITHDRAWAL
    /// into each mesh no OPPOSITE-mesh native still holds — the exact negation of
    /// [`advertise_client_cross_tier_sub`](Self::advertise_client_cross_tier_sub).
    /// A mesh whose opposite-tier native still holds `keyexpr` keeps the
    /// advertisement (else a native's interest would be silently retracted — the
    /// R311y120 black-hole).
    fn withdraw_client_cross_tier_sub(&self, keyexpr: &str) {
        // Caller has already removed the client (last-client case ⇒
        // `any_client_subscribes` false), so withdraw from each mesh self NO
        // LONGER advertises into — the exact NEGATION of the advertise predicate
        // (a mesh whose opposite-tier native still holds `keyexpr` keeps it).
        for target in [FaceTier::Routers, FaceTier::LinkstatePeers] {
            if !self.self_advertises_sub_into(target, keyexpr) {
                self.flood_self_sourced(target, keyexpr, build_undeclare_subscriber_with_keyexpr);
            }
        }
    }

    /// A group SUBSCRIBER keyexpr just appeared in the aggregate (§5.21 sub plane,
    /// S2): flood self's cross-tier ADVERTISEMENT into each mesh nothing else
    /// already covers — a self-sourced `DeclareSubscriber` (node_id 0), so a
    /// mesh-side publisher routes `keyexpr` toward this router and it reaches the
    /// on-group subscriber via the unconditional group egress. The group-sub twin of
    /// [`advertise_client_cross_tier_sub`](Self::advertise_client_cross_tier_sub);
    /// it additionally skips a keyexpr a local CLIENT already advertises (a group
    /// sub is not necessarily the FIRST contributor, unlike the first-client case).
    /// Called from [`set_mcast_group_subs`](Self::set_mcast_group_subs) on the
    /// aggregate's false->true edge for `keyexpr`.
    #[cfg(feature = "router-multicast-faces")]
    fn advertise_group_cross_tier_sub(&self, keyexpr: &str) {
        if self.any_client_subscribes(keyexpr) {
            return; // a local client already advertises the bubble into both meshes.
        }
        for target in [FaceTier::Routers, FaceTier::LinkstatePeers] {
            if self.contributor_subs_source_count(target, keyexpr) == 0 {
                self.flood_self_sourced(target, keyexpr, |ke| {
                    build_declare_subscriber(0, 0, Some(ke))
                });
            }
        }
    }

    /// A group SUBSCRIBER keyexpr just left the aggregate (§5.21 sub plane, S2):
    /// flood self's cross-tier WITHDRAWAL into each mesh self NO LONGER advertises
    /// into — the exact negation of
    /// [`advertise_group_cross_tier_sub`](Self::advertise_group_cross_tier_sub),
    /// reusing [`self_advertises_sub_into`](Self::self_advertises_sub_into) (which
    /// now excludes the just-removed group sub) so a mesh whose client or native
    /// still holds `keyexpr` keeps the advertisement (the R311y120 black-hole
    /// guard). Called from [`set_mcast_group_subs`](Self::set_mcast_group_subs)
    /// AFTER `keyexpr` is removed from `group_subs`.
    #[cfg(feature = "router-multicast-faces")]
    fn withdraw_group_cross_tier_sub(&self, keyexpr: &str) {
        for target in [FaceTier::Routers, FaceTier::LinkstatePeers] {
            if !self.self_advertises_sub_into(target, keyexpr) {
                self.flood_self_sourced(target, keyexpr, build_undeclare_subscriber_with_keyexpr);
            }
        }
    }

    /// A NATIVE sub for `keyexpr` in `native_tier` just registered: flood self's
    /// cross-tier ADVERTISEMENT into the OPPOSITE mesh IFF it flipped that mesh's
    /// derive false->true — i.e. this is the SOLE native source for the exact
    /// `keyexpr` (`source_count == 1` after register) AND no client already covers
    /// it. The federation half of the R311y120 fix: a router-native attracts peer
    /// publishers toward self (which bridges cross-tier, C4). NOT master-gated.
    fn advertise_native_cross_tier_sub(&self, native_tier: FaceTier, keyexpr: &str) {
        let Some(target) = Self::opposite_mesh(native_tier) else {
            return; // a client native has no mesh (unreachable: client subs != natives)
        };
        let sole = self
            .subs_table(native_tier)
            .is_some_and(|t| t.borrow().source_count(keyexpr) == 1);
        // `!group_subscribes` keeps the flip-edge invariant when a §5.21 group sub
        // (S2) already advertised `keyexpr` into `target` (else a redundant flood);
        // the withdraw side already negates the full 3-contributor derive. No-op
        // without `router-multicast-faces` (the `group_subscribes` cfg stub is `false`).
        if sole && !self.any_client_subscribes(keyexpr) && !self.group_subscribes(keyexpr) {
            self.flood_self_sourced(target, keyexpr, |ke| {
                build_declare_subscriber(0, 0, Some(ke))
            });
        }
    }

    /// A NATIVE sub for `keyexpr` in `native_tier` just left (undeclare or
    /// face-down purge): flood self's cross-tier WITHDRAWAL into the OPPOSITE mesh
    /// IFF it flipped that mesh's derive true->false — i.e. NO native source for
    /// the exact `keyexpr` remains (`source_count == 0` after removal) AND no client
    /// covers it. The exact negation of
    /// [`advertise_native_cross_tier_sub`](Self::advertise_native_cross_tier_sub);
    /// centralized so BOTH the undeclare and the (local + Oam-detach) purge paths
    /// route through it (R311y125 lifecycle-symmetry).
    fn withdraw_native_cross_tier_sub(&self, native_tier: FaceTier, keyexpr: &str) {
        let Some(target) = Self::opposite_mesh(native_tier) else {
            return;
        };
        // The exact negation of the advertise predicate: after this native left,
        // self no longer advertises `keyexpr` into `target` IFF no native source
        // remains in `native_tier` (the `target` contributor) AND no client covers
        // it — `!self_advertises_sub_into(target, keyexpr)`.
        if !self.self_advertises_sub_into(target, keyexpr) {
            self.flood_self_sourced(target, keyexpr, build_undeclare_subscriber_with_keyexpr);
        }
    }

    /// §5.21 routing-token-tables (slice-2, slice-3 gate) — the liveliness-token
    /// twin of
    /// [`advertise_native_cross_tier_sub`](Self::advertise_native_cross_tier_sub):
    /// a NATIVE token for `keyexpr` in `native_tier` makes self ADVERTISE it into
    /// the OPPOSITE mesh (a self-sourced `DeclareToken` to self's tree children
    /// there), so a token-interested face on that mesh learns self holds it. Fires
    /// on the false->true flip ONLY — this is the SOLE native source (`source_count
    /// == 1` after register) AND no client already covers the target (slice-3 added
    /// the `!any_client_holds_token` term SYMMETRICALLY with the withdraw negation;
    /// mirrors `advertise_native_cross_tier_sub`). Tokens carry no value, so unlike
    /// the qabl twin there is no merge. DERIVE-not-STORE: self is NOT stored in the
    /// opposite token table (`flood_self_sourced` floods self's tree children only).
    #[cfg(feature = "routing-token-tables")]
    fn advertise_native_cross_tier_token(&self, native_tier: FaceTier, keyexpr: &str) {
        let Some(target) = Self::opposite_mesh(native_tier) else {
            return; // a client native has no mesh (its bubble is client_tokens')
        };
        let sole = self
            .tokens_table(native_tier)
            .is_some_and(|t| t.borrow().source_count(keyexpr) == 1);
        if sole && !self.any_client_holds_token(keyexpr) {
            self.flood_self_sourced(target, keyexpr, |ke| build_declare_token(0, 0, Some(ke)));
        }
    }

    /// A NATIVE token for `keyexpr` in `native_tier` just left (retraction or
    /// face-down purge): flood self's cross-tier WITHDRAWAL into the OPPOSITE mesh
    /// IFF it flipped that mesh's advertise true->false — the EXACT negation of
    /// [`advertise_native_cross_tier_token`](Self::advertise_native_cross_tier_token):
    /// self no longer advertises `keyexpr` into `target` IFF NO native source
    /// remains in `native_tier` AND no client holds it
    /// (`!self_advertises_token_into`; slice-3 added the client term SYMMETRICALLY —
    /// a native withdraw while a client still holds `keyexpr` MUST keep the
    /// advertisement, else the client's interest is silently retracted, the R311y120
    /// black-hole). Mirrors `withdraw_native_cross_tier_sub`. Centralized so BOTH
    /// the graceful retraction and the (local + Oam-detach) purge paths route
    /// through it (the R311y125 lifecycle-symmetry class).
    #[cfg(feature = "routing-token-tables")]
    fn withdraw_native_cross_tier_token(&self, native_tier: FaceTier, keyexpr: &str) {
        let Some(target) = Self::opposite_mesh(native_tier) else {
            return;
        };
        // The exact negation of the advertise predicate: after this native left,
        // self no longer advertises `keyexpr` into `target` IFF no native source
        // remains in `native_tier` (the `target` contributor) AND no client holds
        // it — `!self_advertises_token_into(target, keyexpr)`.
        if !self.self_advertises_token_into(target, keyexpr) {
            self.flood_self_sourced(target, keyexpr, build_undeclare_token_with_keyexpr);
        }
    }

    // ── §5.21 routing-token-tables (slice-3): CLIENT/simple liveliness-TOKEN plane ──

    /// Ingest a CLIENT-face `DeclareToken` (slice-3) into the per-face
    /// [`client_tokens`](Self#structfield.client_tokens) store (keyed by the
    /// client's DECL ID -> keyexpr, the zenoh `remote_tokens` twin) and — when it
    /// is the FIRST client holding the keyexpr — ADVERTISE self's now-derived
    /// cross-tier interest into BOTH meshes. The token twin of
    /// [`ingest_client_subscription`](Self::ingest_client_subscription); the
    /// mesh-face path ([`ingest_token`](Self::ingest_token)) drops a Client-tier
    /// declare (no tier table), so the leaf input lands here instead. The
    /// FUTURE push to a CLIENT face with a matching stored token interest is
    /// [`push_future_token`](Self::push_future_token) (slice-4, wired in the tail);
    /// the self-delivery guard is a no-op in the forwarder (see that method).
    #[cfg(feature = "routing-token-tables")]
    fn ingest_client_token(&self, inbound: FaceId, declare: &DeclareOwned) {
        let (decl_id, wireexpr) = match &declare.body {
            DeclareOwnedVariant::CodecZenohDeclToken(t) => (t.id, &t.keyexpr),
            _ => return,
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
        // The derive-level change gate: ADVERTISE only when this is the FIRST client
        // holding `keyexpr` (the client half of the cross-tier derive flips
        // false->true). A re-declare of an already-held keyexpr (same or a new id)
        // does not re-flood. Insert in a scoped borrow, THEN advertise after it drops
        // (advertise reads only the mesh token tables, but keep the discipline).
        let already = self.any_client_holds_token(&keyexpr);
        let displaced = self
            .client_tokens
            .borrow_mut()
            .entry(inbound)
            .or_default()
            .insert(decl_id, keyexpr.clone());
        if !already {
            self.advertise_client_cross_tier_token(&keyexpr);
        }
        // FUTURE-mode push (slice-4): declare this token to any CLIENT face whose
        // stored FUTURE token interest matches (mirror of ingest_client_subscription's
        // push_future_subscription). Skip a redundant same-id/same-ke re-declare
        // (pushes_for_new dedups anyway, but match the sub `if inserted` discipline).
        if displaced.as_deref() != Some(keyexpr.as_str()) {
            self.push_future_token(&keyexpr, inbound);
        }
        // Defensive: an id RE-USED for a DIFFERENT keyexpr without an intervening
        // undeclare silently displaced its old mapping (conforming clients — wz's own
        // + pico — allocate monotonic ids and undeclare first, so this is unreachable
        // in practice; the id-map makes it detectable where the keyexpr-set sub twin
        // could not). Retract the displaced keyexpr's cross-tier advertisement if this
        // was its last holder, so a liveliness token never leaks stale-live.
        if let Some(old) = displaced {
            if old != keyexpr {
                if !self.any_client_holds_token(&old) {
                    self.withdraw_client_cross_tier_token(&old);
                }
                // slice-5: the displaced old keyexpr also owes a reader-notify — the
                // 5th token-removal path (id-reuse), which has NO sub mirror (client_subs
                // is a HashSet that cannot displace), so the "3 sub sites" enumeration
                // misses it. Closes the same stale-live residual as the other sites.
                self.undeclare_push_token(&old);
            }
        }
    }

    /// Withdraw a CLIENT-face `UndeclareToken` (slice-3) from
    /// [`client_tokens`](Self#structfield.client_tokens); when it removed the LAST
    /// client holding the keyexpr, withdraw self's cross-tier advertisement. The
    /// token twin of [`withdraw_client_subscription`](Self::withdraw_client_subscription).
    /// A Client-tier `UndeclareToken` is ID-KEYED (`build_undeclare_token(id)`, no
    /// ext — the form wz's own liveliness `Drop` and pico emit), so the retracted
    /// keyexpr is resolved BY ID (zenoh `forget_simple_token` id-first,
    /// `hat/client/token.rs:276`), NOT by an `ext_wire_expr` the client never sends.
    /// The sourced (`id == 0`, ext) form is a MESH peer's and routes through
    /// [`withdraw_token`](Self::withdraw_token) instead.
    #[cfg(feature = "routing-token-tables")]
    fn withdraw_client_token(&self, inbound: FaceId, declare: &DeclareOwned) {
        let decl_id = match &declare.body {
            DeclareOwnedVariant::CodecZenohUndeclToken(u) => u.id,
            _ => return,
        };
        let keyexpr = {
            let mut store = self.client_tokens.borrow_mut();
            let removed = store.get_mut(&inbound).and_then(|ids| ids.remove(&decl_id));
            // Prune an emptied per-face map (the same discipline
            // `withdraw_client_subscription` uses), so a client that drops every
            // token does not linger in the derive/late-joiner fold.
            if store.get(&inbound).is_some_and(|ids| ids.is_empty()) {
                store.remove(&inbound);
            }
            removed
        };
        let Some(keyexpr) = keyexpr else {
            return; // unknown id (never ingested / already gone) — nothing to withdraw
        };
        if !self.any_client_holds_token(&keyexpr) {
            self.withdraw_client_cross_tier_token(&keyexpr);
        }
        // slice-5 withdraw->notify (unconditional on a real removal, like
        // withdraw_client_subscription): a future-push reader whose pushed reply ke is
        // now un-backed is told the token withdrew. The internal `any_token_matches`
        // gate keeps a ke another token still backs from being spuriously undeclared.
        self.undeclare_push_token(&keyexpr);
    }

    /// Whether ANY client face currently holds a liveliness token for `keyexpr` —
    /// the CLIENT half of the cross-tier advertise derive, the token twin of
    /// [`any_client_subscribes`](Self::any_client_subscribes). Client-agnostic to
    /// tier: a client-held token feeds BOTH meshes. The full predicate is
    /// [`self_advertises_token_into`](Self::self_advertises_token_into).
    #[cfg(feature = "routing-token-tables")]
    fn any_client_holds_token(&self, keyexpr: &str) -> bool {
        self.client_tokens
            .borrow()
            .values()
            .any(|ids| ids.values().any(|k| k == keyexpr))
    }

    /// A CLIENT token for `keyexpr` just appeared (the FIRST client for it): flood
    /// self's cross-tier ADVERTISEMENT into each mesh the client newly flips ON — a
    /// self-sourced `DeclareToken` (node_id 0) to self's tree children, so a
    /// token-interested face on that mesh learns self holds it. Skips a mesh an
    /// OPPOSITE-mesh native already advertises (no redundant flood). DERIVE-not-STORE:
    /// self is NOT stored in either mesh token table; the advertisement is
    /// re-derived on the tick for late joiners. The token twin of
    /// [`advertise_client_cross_tier_sub`](Self::advertise_client_cross_tier_sub).
    #[cfg(feature = "routing-token-tables")]
    fn advertise_client_cross_tier_token(&self, keyexpr: &str) {
        for target in [FaceTier::Routers, FaceTier::LinkstatePeers] {
            if self.contributor_tokens_source_count(target, keyexpr) == 0 {
                self.flood_self_sourced(target, keyexpr, |ke| build_declare_token(0, 0, Some(ke)));
            }
        }
    }

    /// The LAST client for `keyexpr` just left: flood self's cross-tier WITHDRAWAL
    /// into each mesh no OPPOSITE-mesh native still holds — the exact negation of
    /// [`advertise_client_cross_tier_token`](Self::advertise_client_cross_tier_token).
    /// A mesh whose opposite-tier native still holds `keyexpr` keeps the
    /// advertisement (else a native's interest would be silently retracted — the
    /// R311y120 black-hole). The token twin of
    /// [`withdraw_client_cross_tier_sub`](Self::withdraw_client_cross_tier_sub).
    #[cfg(feature = "routing-token-tables")]
    fn withdraw_client_cross_tier_token(&self, keyexpr: &str) {
        for target in [FaceTier::Routers, FaceTier::LinkstatePeers] {
            if !self.self_advertises_token_into(target, keyexpr) {
                self.flood_self_sourced(target, keyexpr, build_undeclare_token_with_keyexpr);
            }
        }
    }

    /// Whether self SHOULD advertise a liveliness token for `keyexpr` into `target`
    /// mesh — the per-target cross-tier-bubble derive SSOT, the token twin of
    /// [`self_advertises_sub_into`](Self::self_advertises_sub_into). True when a
    /// CLIENT holds `keyexpr` OR an OPPOSITE-mesh NATIVE token sources it. Read by
    /// the client withdraw and — as its exact NEGATION — the native withdraw gate,
    /// keeping the two gates symmetric (no one-sided silent retraction).
    #[cfg(feature = "routing-token-tables")]
    fn self_advertises_token_into(&self, target: FaceTier, keyexpr: &str) -> bool {
        self.any_client_holds_token(keyexpr)
            || self.contributor_tokens_source_count(target, keyexpr) > 0
    }

    /// The number of OPPOSITE-mesh NATIVE token sources for the EXACT `keyexpr` that
    /// make self advertise into `target` — the native half of
    /// [`self_advertises_token_into`](Self::self_advertises_token_into), the token
    /// twin of [`contributor_subs_source_count`](Self::contributor_subs_source_count).
    /// For `target = LinkstatePeers` this reads `router_tokens`; for
    /// `target = Routers`, `linkstatepeer_tokens`. `0` for a `Client` target.
    #[cfg(feature = "routing-token-tables")]
    fn contributor_tokens_source_count(&self, target: FaceTier, keyexpr: &str) -> usize {
        Self::opposite_mesh(target)
            .and_then(|src| self.tokens_table(src))
            .map_or(0, |t| t.borrow().source_count(keyexpr))
    }

    // ── §5.21 routing-token-tables (slice-5): topology-reconcile withdraw->notify ──

    /// Whether ANY liveliness token wz still holds INTERSECTS `ke` — the token twin of
    /// [`any_sub_matches`](Self::any_sub_matches), the post-withdrawal "still backed"
    /// existence check [`undeclare_push_token`](Self::undeclare_push_token) consults.
    /// Folds GLOBALLY (no face/self exclusion): both mesh tiers via
    /// `matching_entries(ke, None)` ∪ the client leaf tokens (any inner-map VALUE
    /// intersecting `ke`) — a per-face exclusion here would spuriously undeclare a
    /// reply ke a co-hosted or mesh token still backs. DERIVE-not-STORE means self is
    /// never in the mesh tables, so `None` (no self-zid filter) is correct.
    #[cfg(feature = "routing-token-tables")]
    fn any_token_matches(&self, ke: &str) -> bool {
        for table in [&self.router_tokens, &self.linkstatepeer_tokens] {
            if !table.borrow().matching_entries(ke, None).is_empty() {
                return true;
            }
        }
        let chunks: Vec<&str> = ke.split('/').collect();
        self.client_tokens
            .borrow()
            .values()
            .any(|ids| ids.values().any(|k| keyexpr_intersects_target(k, &chunks)))
    }

    /// Emit the withdraw->reader UNDECLARE pushes a withdrawn TOKEN `withdrawn_ke`
    /// triggers — the token twin of [`undeclare_push_subs`](Self::undeclare_push_subs)
    /// (slice-5, the withdraw half of zenoh `propagate_forget_simple_token` — its ARM 1,
    /// the `pushed`/`local_tokens` faces; the interested-but-never-declared arm 2 is
    /// omitted, symmetric with `undeclare_push_subs`, and unreachable in wz's flow — a
    /// face interested in a ke wz holds is always interned into `pushed` first): for each
    /// CLIENT face whose pushed reply ke is now UN-backed
    /// ([`any_token_matches`](Self::any_token_matches) false), an unsolicited id-keyed
    /// `UndeclareToken(id)` (interest_id None) that retracts the earlier FUTURE-push and
    /// clears the stale `pushed` entry. For a LIVELINESS token this closes the
    /// stale-live residual (a reader told a token appeared is now told it withdrew).
    /// INVARIANT: run AFTER the withdrawn token left its table / store, so
    /// `any_token_matches` reflects the post-withdrawal state (a ke still backed by
    /// ANOTHER token must NOT be undeclared). Borrow-safe: `future_tokens.borrow_mut()`
    /// with the closure reading the DISTINCT token-table RefCells (the
    /// `undeclare_push_subs` shape).
    #[cfg(feature = "routing-token-tables")]
    fn undeclare_push_token(&self, withdrawn_ke: &str) {
        let forgets = self
            .future_tokens
            .borrow_mut()
            .forgets_for_withdrawn(withdrawn_ke, |rk| self.any_token_matches(rk));
        for (face, _reply_ke, id) in forgets {
            self.send_one_to_face(
                face,
                NetworkMessage::Declare(Box::new(build_undeclare_token(id))),
            );
        }
    }

    /// The MERGED [`QueryableInfo`] self advertises for `keyexpr` into `target`
    /// mesh, or `None` if NO contributor — the value-bearing qabl twin of
    /// [`self_advertises_sub_into`](Self::self_advertises_sub_into) (A2b). Folds the
    /// contributors: the OPPOSITE-mesh NATIVE qabls for the exact `keyexpr` ∪ the
    /// CLIENT qabls for it, via [`QueryableInfo::merge`] (`complete = OR`,
    /// `distance = min`) — zenoh's `local_*_qabl_info` (`queries.rs:67-133`).
    /// `Option`-seeded from the first contributor (NEVER `DEFAULT` — its distance 0
    /// would collapse the `min`). Self is never a source (derive-not-store), so no
    /// self-exclusion is needed. The advertised `distance` is DISTINCT from the
    /// query-ROUTE distance (`net.distances`, `best_query_winner`) — this rides the
    /// DeclareQueryable ext for UPSTREAM propagation only. (The client-qabl fold is
    /// already wired so ACTIVATION-3 adds only the client-declare TRIGGER, not a
    /// derive change.)
    fn derived_cross_tier_qabl_info(
        &self,
        target: FaceTier,
        keyexpr: &str,
    ) -> Option<QueryableInfo> {
        let mut acc: Option<QueryableInfo> = None;
        if let Some(table) = Self::opposite_mesh(target).and_then(|src| self.qabls_table(src)) {
            for info in table.borrow().values_for(keyexpr) {
                acc = Some(acc.map_or(info, |a| a.merge(info)));
            }
        }
        for qabls in self.client_qabls.borrow().values() {
            if let Some(info) = qabls.get(keyexpr) {
                acc = Some(acc.map_or(*info, |a| a.merge(*info)));
            }
        }
        // §5.23 adminspace-router-linkstate — a queryable HOSTED BY THIS router
        // (e.g. `@/<self-zid>/router/**`) is a third self-sourced contributor,
        // folded here EXACTLY like `client_qabls` (a self-host is a leaf in
        // neither mesh) so it advertises + re-advertises through the same derive.
        for lq in self.local_queryables.borrow().iter() {
            if lq.keyexpr == keyexpr {
                let info = QueryableInfo::local(lq.complete);
                acc = Some(acc.map_or(info, |a| a.merge(info)));
            }
        }
        acc
    }

    /// The keyexprs self should advertise a merged queryable for into `target`
    /// mesh — the OPPOSITE mesh's native qabls ∪ the client qabls, deduped. The set
    /// form of [`derived_cross_tier_qabl_info`](Self::derived_cross_tier_qabl_info)
    /// (a `K` is in this set IFF that returns `Some`), fed to the tick re-advertise
    /// for late-joining children (the qabl twin of `derived_cross_tier_subs_into`).
    fn derived_cross_tier_qabls_into(&self, target: FaceTier) -> Vec<String> {
        let mut set: HashSet<String> = HashSet::new();
        if let Some(table) = Self::opposite_mesh(target).and_then(|src| self.qabls_table(src)) {
            for (keyexpr, _peer, _info) in table.borrow().entries() {
                set.insert(keyexpr);
            }
        }
        for qabls in self.client_qabls.borrow().values() {
            set.extend(qabls.keys().cloned());
        }
        // §5.23 adminspace-router-linkstate — self-hosted queryables join the set
        // (the twin of the `client_qabls` fold above), so `re_advertise_self_cross_
        // tier` re-advertises them to late-joining tree children for FREE — the
        // single change that lets a router that registered its admin queryable at
        // startup still be reached by a peer/router that joins the mesh later.
        for lq in self.local_queryables.borrow().iter() {
            set.insert(lq.keyexpr.clone());
        }
        set.into_iter().collect()
    }

    /// A NATIVE qabl for `keyexpr` in `native_tier` just registered, or its merged
    /// value changed (A2b): (re-)advertise self's MERGED cross-tier `QueryableInfo`
    /// into the OPPOSITE mesh — a self-sourced `DeclareQueryable` (node_id 0)
    /// carrying the fold. Fires on any real change (upgrade OR downgrade): zenoh
    /// re-declares `local_*_qabl_info` whenever it changes, and the downstream
    /// value-diff gate absorbs a re-declare of the SAME value. NOT master-gated.
    /// This is the ADVERTISE (register / value-change) path, where a contributor
    /// always exists (the triggering native was just registered), so the `None` arm
    /// below is unreachable from `ingest_queryable` and kept only as a safe guard.
    /// The FULL retraction (last contributor leaves ⇒ merged `None`) is handled by
    /// [`withdraw_native_cross_tier_qabl`](Self::withdraw_native_cross_tier_qabl),
    /// which floods an `UndeclareQueryable` carrying the keyexpr in `ext_wire_expr`
    /// (declare.rs:520-522, parity with the sub plane) — no longer the self-down-only
    /// staleness the codec deferral once left. A partial removal that leaves a
    /// contributor DOWNGRADES via a re-advertised `DeclareQueryable`.
    fn advertise_native_cross_tier_qabl(&self, native_tier: FaceTier, keyexpr: &str) {
        let Some(target) = Self::opposite_mesh(native_tier) else {
            return;
        };
        let Some(info) = self.derived_cross_tier_qabl_info(target, keyexpr) else {
            return; // no contributor (unreachable from the register path; safe guard)
        };
        self.flood_self_sourced(target, keyexpr, move |ke| {
            build_declare_queryable_with_info(ke, info)
        });
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

    /// Re-advertise self's DERIVED cross-tier subscriptions AND queryables to the
    /// tier's NEW tree children a recompute added — self is the source, so the
    /// flood targets the delta children of SELF's tree in this net. The tick
    /// counterpart of the immediate
    /// [`advertise_client_cross_tier_sub`](Self::advertise_client_cross_tier_sub) /
    /// [`advertise_native_cross_tier_qabl`](Self::advertise_native_cross_tier_qabl),
    /// the OBLIGATION-2 feed of the re-advertise path with the DERIVED (not stored)
    /// self-source (node_id 0) — so a late-joining child converges on self's full
    /// cross-tier bubble (both planes). The qabl re-advertise carries the MERGED
    /// info (`derived_cross_tier_qabl_info`), the same value the immediate advertise
    /// floods.
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
        for keyexpr in self.derived_cross_tier_subs_into(tier) {
            let Ok(declare) = build_declare_subscriber(0, 0, Some(&keyexpr)) else {
                continue;
            };
            self.flood_delta_tier(tier, self_delta, &declare);
        }
        for keyexpr in self.derived_cross_tier_qabls_into(tier) {
            let Some(info) = self.derived_cross_tier_qabl_info(tier, &keyexpr) else {
                continue;
            };
            let Ok(declare) = build_declare_queryable_with_info(&keyexpr, info) else {
                continue;
            };
            self.flood_delta_tier(tier, self_delta, &declare);
        }
        // §5.21 routing-token-tables (slice-2) — the cross-tier token bubble's
        // late-joiner feed (the token twin of the subs loop above): re-advertise
        // self's derived cross-tier tokens to self's NEW tree children.
        #[cfg(feature = "routing-token-tables")]
        for keyexpr in self.derived_cross_tier_tokens_into(tier) {
            let Ok(declare) = build_declare_token(0, 0, Some(&keyexpr)) else {
                continue;
            };
            self.flood_delta_tier(tier, self_delta, &declare);
        }
    }

    /// Ingest a CLIENT-face `DeclareQueryable` (C5b) into the per-face
    /// [`client_qabls`](Self#structfield.client_qabls) store — the query-plane twin
    /// of [`ingest_client_subscription`](Self::ingest_client_subscription). The
    /// mesh-face declare path ([`ingest_queryable`](Self::ingest_queryable)) drops a
    /// Client-tier declare (no Zid-keyed tier table); a client-hosted queryable
    /// lands here instead, keyed by the client face + its declared
    /// [`QueryableInfo`] (the query route reads `complete` / `distance`), and — A3
    /// — ADVERTISES self's cross-tier merged queryable into BOTH meshes so a REMOTE
    /// mesh querier routes toward this router (the query-plane twin of C2's
    /// [`advertise_client_cross_tier_sub`](Self::advertise_client_cross_tier_sub)).
    /// A client is a leaf in NEITHER mesh, so it steers both (unlike a native,
    /// which steers only the opposite mesh). The advertised value is the MERGED
    /// [`QueryableInfo`] ([`derived_cross_tier_qabl_info`](Self::derived_cross_tier_qabl_info),
    /// which already folds `client_qabls` — the A2b seam), so A3 is a trigger-only
    /// add over the A2b machinery. Fires only on a real change (a new client
    /// queryable OR a changed info) so a redundant re-declare does not re-flood.
    fn ingest_client_queryable(&self, inbound: FaceId, declare: &DeclareOwned) {
        let Some(wireexpr) = declare_queryable_wireexpr(declare) else {
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
        // The declared QueryableInfo rides the DeclQueryable ext chain; absent =
        // zenoh DEFAULT (incomplete), the same read `ingest_queryable` does.
        let info = match &declare.body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(dq) => {
                read_queryable_info(dq.extensions.as_ref())
            }
            _ => QueryableInfo::DEFAULT,
        };
        // The change gate (mirrors the native value-diff): re-advertise only on a
        // NEW keyexpr for this face OR a CHANGED info — `insert` returns the prior
        // value, so `Some(prev) if prev == info` is the redundant re-declare.
        let prev = self
            .client_qabls
            .borrow_mut()
            .entry(inbound)
            .or_default()
            .insert(keyexpr.clone(), info);
        if prev != Some(info) {
            self.advertise_client_cross_tier_qabl(&keyexpr);
            // FUTURE-push (R311y150): a client queryable is proactively pushed to
            // ANOTHER client face whose FUTURE querier-interest matches (the value-
            // aware site — `prev` carried the old info, so a completeness flip
            // re-pushes the recomputed merge). `inbound` (the queryable's own face)
            // is never self-echoed.
            self.push_future_queryable(&keyexpr, inbound);
        }
    }

    /// Flood self's cross-tier queryable ADVERTISEMENT for `keyexpr` into BOTH
    /// meshes (A3) — a self-sourced `DeclareQueryable` (node_id 0) carrying the
    /// MERGED [`QueryableInfo`] ([`derived_cross_tier_qabl_info`](Self::derived_cross_tier_qabl_info)),
    /// so a REMOTE querier on either mesh routes `keyexpr` toward this router. The
    /// client-qabl twin of [`advertise_native_cross_tier_qabl`](Self::advertise_native_cross_tier_qabl),
    /// but into BOTH meshes (a client is in neither). This is the ADVERTISE
    /// (register / value-change) path; the client face-down / undeclare REMOVAL
    /// path is [`withdraw_client_cross_tier_qabl`](Self::withdraw_client_cross_tier_qabl)
    /// (downgrade if a contributor remains, else a full `UndeclareQueryable`
    /// retraction). NOT master-gated.
    fn advertise_client_cross_tier_qabl(&self, keyexpr: &str) {
        self.advertise_cross_tier_qabl_both_meshes(keyexpr);
    }

    /// Flood self's MERGED cross-tier queryable advertisement for `keyexpr` into
    /// BOTH meshes — the shared both-meshes flood for a self-sourced queryable that
    /// is a leaf in NEITHER mesh (a client qabl OR a self-hosted admin queryable).
    /// The merged [`QueryableInfo`] ([`derived_cross_tier_qabl_info`](Self::derived_cross_tier_qabl_info))
    /// already folds every self source, so both callers reuse this one flood.
    fn advertise_cross_tier_qabl_both_meshes(&self, keyexpr: &str) {
        for target in [FaceTier::Routers, FaceTier::LinkstatePeers] {
            let Some(info) = self.derived_cross_tier_qabl_info(target, keyexpr) else {
                continue;
            };
            self.flood_self_sourced(target, keyexpr, move |ke| {
                build_declare_queryable_with_info(ke, info)
            });
        }
    }

    /// Register a queryable HOSTED BY THIS router (§5.23 `adminspace-router-
    /// linkstate`) — the router twin of the peer
    /// [`LinkstateForwarder::register_local_queryable`](crate::linkstate_forward::LinkstateForwarder::register_local_queryable).
    /// Stores the handler in [`local_queryables`](Self#structfield.local_queryables)
    /// (so a matching GET self-dispatches at the `route_request` empty-route tail)
    /// AND advertises the self-hosted queryable into BOTH meshes — a self-host is a
    /// leaf in neither mesh (the `client_qabls` case), so a REMOTE router/peer
    /// routes a matching GET toward this router, and a peer/router joining LATER
    /// converges via `re_advertise_self_cross_tier` (the `local_queryables` fold in
    /// [`derived_cross_tier_qabls_into`](Self::derived_cross_tier_qabls_into)). The
    /// merged advertise already sees the just-pushed entry (registry mutated
    /// first). `complete = true` for the admin queryable (it fully answers its own
    /// `@/<zid>/router/**` subtree).
    pub fn register_local_queryable(
        &self,
        keyexpr: &str,
        complete: bool,
        handler: LocalQueryHandler,
    ) {
        self.local_queryables.borrow_mut().push(LocalQueryable {
            keyexpr: keyexpr.to_string(),
            complete,
            handler: Rc::new(RefCell::new(handler)),
        });
        self.advertise_cross_tier_qabl_both_meshes(keyexpr);
    }

    /// A read-only [`LinkstateNetView`] over the ROUTER-tier graph (`routers_net`)
    /// — the adminspace host's DOT + `route/successor` render seam (§5.23).
    pub fn routers_net_view(&self) -> LinkstateNetView {
        LinkstateNetView(Rc::clone(&self.routers_net))
    }

    /// A read-only [`LinkstateNetView`] over the PEER-tier graph
    /// (`linkstatepeers_net`) — the adminspace host's `linkstate/peers` render seam.
    pub fn peers_net_view(&self) -> LinkstateNetView {
        LinkstateNetView(Rc::clone(&self.linkstatepeers_net))
    }

    /// Self-dispatch a routed GET whose only match is a queryable HOSTED BY THIS
    /// router (§5.23 `adminspace-router-linkstate`) — the router twin of the peer's
    /// `dispatch_local_queryables`, reached from the [`route_request`](Self::route_request)
    /// empty-route tail (self is excluded from the routing targets, so a GET
    /// matching only a self-hosted queryable — e.g. `@/<self-zid>/router/**` —
    /// arrives with `forwarded == 0`). Snapshots the matching handlers under a
    /// SHORT borrow, DROPS it, then invokes each borrow-free (the re-entrancy
    /// discipline the peer documents), accumulating replies via the SAME
    /// `QueryResponder` / `QueryReply::into_response` SSOT the wire queryable path
    /// uses, and emits them + the closing `ResponseFinal` (rid = the querier's) to
    /// `inbound`. The admin handler renders topology data + replies and NEVER
    /// self-queries, so — UNLIKE the peer — no self-query redelivery/`DeferredQuery`
    /// path is needed. Returns `true` iff a local queryable matched (the caller
    /// then skips the bare empty-route final). The reply's rid = the inbound
    /// Request's rid, which at a transit router IS the qid it stamped on the
    /// forward hop, so multi-hop route-back (`forward_response`) resolves it with
    /// no new pending state here.
    fn dispatch_router_local_queryables(
        &self,
        inbound: FaceId,
        reliable: bool,
        request: &RequestOwned,
        keyexpr: &str,
    ) -> bool {
        let query_chunks: Vec<&str> = keyexpr.split('/').collect();
        let target = read_request_target(request);
        let matched: Vec<Rc<RefCell<LocalQueryHandler>>> = {
            let locals = self.local_queryables.borrow();
            locals
                .iter()
                .filter(|lq| keyexpr_intersects_target(&lq.keyexpr, &query_chunks))
                .filter(|lq| !matches!(target, Some(QueryTarget::AllComplete)) || lq.complete)
                .map(|lq| Rc::clone(&lq.handler))
                .collect()
        };
        if matched.is_empty() {
            return false;
        }
        let view = LocalQueryView {
            keyexpr,
            rid: request.rid,
        };
        let mut replies: Vec<QueryReply> = Vec::new();
        {
            let mut responder = QueryResponder::new(request.rid, keyexpr.to_string(), &mut replies);
            for handler in &matched {
                // The self-hosted admin handler renders net data + replies; it never
                // re-queries its own keyexpr, so try_borrow_mut always succeeds and
                // no self-query redelivery (the peer's DeferredQuery path) is needed.
                if let Ok(mut h) = handler.try_borrow_mut() {
                    (**h)(&view, &mut responder);
                }
            }
        }
        for reply in replies {
            if let Ok(resp) = reply.into_response() {
                self.send_to_face(inbound, reliable, || {
                    NetworkMessage::Response(Box::new(resp.clone()))
                });
            }
        }
        let final_msg = wz_session_core::response_final_build::build_response_final(request.rid);
        self.send_to_face(inbound, reliable, || {
            NetworkMessage::ResponseFinal(final_msg.clone())
        });
        true
    }

    /// Withdraw a CLIENT-face `UndeclareQueryable` (the query twin of
    /// [`withdraw_client_subscription`](Self::withdraw_client_subscription)) from
    /// [`client_qabls`](Self#structfield.client_qabls); when it removed the client's
    /// entry, recompute self's cross-tier advertisement into BOTH meshes.
    fn withdraw_client_queryable(&self, inbound: FaceId, declare: &DeclareOwned) {
        let exts = match &declare.body {
            DeclareOwnedVariant::CodecZenohUndeclQueryable(u) => u.extensions.as_ref(),
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
            let mut store = self.client_qabls.borrow_mut();
            let removed = store
                .get_mut(&inbound)
                .is_some_and(|m| m.remove(&keyexpr).is_some());
            // Prune an emptied map (the same discipline withdraw_client_subscription
            // uses) so an emptied face does not linger in client_qabls.
            if store.get(&inbound).is_some_and(|m| m.is_empty()) {
                store.remove(&inbound);
            }
            removed
        };
        if removed {
            self.withdraw_client_cross_tier_qabl(&keyexpr);
            // R311y151 undeclare-push (query twin): re-arm any waiting querier whose
            // pushed reply ke lost its last backing queryable.
            self.undeclare_push_qabls(&keyexpr);
        }
    }

    /// Recompute self's cross-tier queryable advertisement into BOTH meshes after a
    /// client qabl left — the query twin of
    /// [`withdraw_client_cross_tier_sub`](Self::withdraw_client_cross_tier_sub) and
    /// the removal counterpart of
    /// [`advertise_client_cross_tier_qabl`](Self::advertise_client_cross_tier_qabl).
    /// Per mesh: re-advertise the DOWNGRADED merge if a contributor remains, else
    /// flood a full `UndeclareQueryable` retraction (the `None` arm the ext_wire_expr
    /// codec atom made expressible).
    fn withdraw_client_cross_tier_qabl(&self, keyexpr: &str) {
        for target in [FaceTier::Routers, FaceTier::LinkstatePeers] {
            match self.derived_cross_tier_qabl_info(target, keyexpr) {
                Some(info) => self.flood_self_sourced(target, keyexpr, move |ke| {
                    build_declare_queryable_with_info(ke, info)
                }),
                None => {
                    self.flood_self_sourced(target, keyexpr, build_undeclare_queryable_with_keyexpr)
                }
            }
        }
    }

    /// Route an inbound `Request` (a Query) through the router's full zenoh
    /// `compute_query_route` (`hat/router/queries.rs:1426`) + `compute_final_route`
    /// (`dispatcher/queries.rs:205`) — the FORWARD (Request) half of the query
    /// route (C5b), the query-plane twin of [`route_push`](Self::route_push).
    ///
    /// Structure (mirroring the data plane's `route_push` legs, but the Query flows
    /// TOWARD queryables and the three blocks are UNIFIED by a GLOBAL BestMatching):
    /// - Blocks 1 & 2 — the two meshes' qabls: a WITHIN-tier leg (the inbound
    ///   tier's own net, master-gate-free, stamped with the querier's psid) and a
    ///   master-gated CROSS-mesh leg (self-originated, node_id 0), exactly the
    ///   `forward_push_tier` + `bridge_push_cross_mesh` split
    ///   ([`mesh_query_block`](Self::mesh_query_block) computes each).
    /// - Block 3 — the local CLIENT queryables
    ///   ([`forward_request_to_clients`](Self::forward_request_to_clients) /
    ///   [`first_complete_client`](Self::first_complete_client)), gated
    ///   `master || source == Router`.
    /// - A CLIENT-sourced Query self-injects into BOTH meshes (both legs cross;
    ///   peer ungated, router master-gated), the query twin of C3b — falls out of
    ///   the same block gates (a client inbound has no within leg).
    ///
    /// The `QueryTarget` dispatch (the wire DEFAULT — an absent ext_target — is
    /// BestMatching): `All` fans to every matching queryable, `AllComplete` to every
    /// COMPLETE one, BestMatching to the SINGLE globally-nearest complete one
    /// ([`best_query_winner`](Self::best_query_winner)) with an All fallback. Each
    /// forwarded Request ALLOCATES a pending-return entry so the reverse Response
    /// route (C5c) finds its way back. An EMPTY route prompts a `ResponseFinal` to
    /// the querier so its `get()` terminates at once (a pure router hosts no local
    /// self-queryable to dispatch — a deferred combined-node seam). Single-router
    /// topologies elect self, so every master gate is a no-op.
    fn route_request(
        &self,
        inbound: FaceId,
        tier: FaceTier,
        reliable: bool,
        request: &RequestOwned,
    ) {
        // Resolve the query keyexpr + the inbound face's zid/link in one scoped
        // borrow (released before any send re-borrows `faces`).
        let resolved = {
            let faces = self.faces.borrow();
            let Some(s) = faces.get(&inbound) else {
                return; // the inbound face is gone: nothing to reply to
            };
            resolve_wireexpr(&request.keyexpr.body, &s.keyexpr_table)
                .map(|keyexpr| (peer_zid_routing(&s.actions), s.link, keyexpr))
        };
        let (inbound_zid, inbound_link, keyexpr) = match resolved {
            Some(t) => t,
            None => {
                // An unresolvable keyexpr alias cannot be routed, but the querier
                // must still TERMINATE — zenoh route_query sends a ResponseFinal on
                // an unknown scope (dispatcher/queries.rs:575), not a silent drop
                // that would hang the get() until its own timeout.
                let final_msg =
                    wz_session_core::response_final_build::build_response_final(request.rid);
                self.send_to_face(inbound, reliable, || {
                    NetworkMessage::ResponseFinal(final_msg.clone())
                });
                return;
            }
        };
        // A mesh-tier inbound resolves its querier source in the inbound net. An
        // UNRESOLVABLE source (a transit Query naming a psid this node has not
        // learned yet) drops ONLY the within-tier leg — like `route_push`, whose
        // `compute_push_forward` returns `None` for the within leg while
        // `bridge_push_cross_mesh` + the client delivery still run — NOT the whole
        // route: the cross-mesh + client legs are self-originated (they route along
        // self's tree, not the querier's) so they still fire, and an empty TOTAL
        // route prompts the final below (zenoh's other blocks use `net.idx`, not the
        // querier source, so they are unaffected by an unmapped source). A Client
        // inbound has no mesh source (both mesh legs are self-originated cross legs).
        let within = match self.plane(tier) {
            Some((net, _)) => resolve_source_in(
                &net.borrow(),
                inbound_zid,
                inbound_link,
                read_request_source(request),
            ),
            None => None,
        };
        let self_zid = *self.routers_net.borrow().self_zid();
        let master = self.is_master(&keyexpr);
        // The two mesh blocks, gated + source-selected per compute_query_route; a
        // gated-off block is omitted. Block 3 (clients) gate is `master || src ==
        // Router`, the same as block 1's.
        let blocks: Vec<MeshQueryBlock> = [FaceTier::Routers, FaceTier::LinkstatePeers]
            .into_iter()
            .filter_map(|bt| self.mesh_query_block(bt, tier, master, within, inbound_zid, self_zid))
            .collect();
        let client_gate = master || tier == FaceTier::Routers;
        // ONE shared fan target for this logical Query — every branch's pending
        // entry Rc-shares it, so the closing final aggregates LAST-OUT across all
        // the legs below (mesh tiers + clients): zenoh's one `Arc<Query>` cloned
        // per branch of `compute_final_route`.
        let fan = QueryFan::new(inbound, request.rid);
        // The per-branch deadline — the Query's own carried ext_timeout when
        // present, else this relay's configured default: zenoh route_query's
        // `ext_timeout.unwrap_or(queries_default_timeout)`
        // (dispatcher/queries.rs:514), honored at EVERY relay hop.
        let deadline = self.now()
            + read_request_timeout_ms(request)
                .map(Duration::from_millis)
                .unwrap_or_else(|| self.query_timeout.get());

        let forwarded = match read_request_target(request) {
            // BestMatching (wire default): the SINGLE globally-nearest COMPLETE
            // queryable; fall back to All (every matching one) when none is
            // complete.
            None => match self.best_query_winner(&blocks, client_gate, inbound, &keyexpr, self_zid)
            {
                Some(BestQueryWinner::Mesh(bi, hop)) => self.forward_request_to_tier(
                    &blocks[bi],
                    reliable,
                    inbound,
                    &[hop],
                    request,
                    &keyexpr,
                    &fan,
                    deadline,
                ),
                Some(BestQueryWinner::Client(face)) => self
                    .forward_request_to_face(face, 0, reliable, request, &keyexpr, &fan, deadline),
                None => self.forward_request_all(
                    &blocks,
                    client_gate,
                    false,
                    reliable,
                    inbound,
                    request,
                    &keyexpr,
                    &fan,
                    deadline,
                    self_zid,
                ),
            },
            Some(QueryTarget::All) => self.forward_request_all(
                &blocks,
                client_gate,
                false,
                reliable,
                inbound,
                request,
                &keyexpr,
                &fan,
                deadline,
                self_zid,
            ),
            Some(QueryTarget::AllComplete) => self.forward_request_all(
                &blocks,
                client_gate,
                true,
                reliable,
                inbound,
                request,
                &keyexpr,
                &fan,
                deadline,
                self_zid,
            ),
        };

        if forwarded == 0 {
            // §5.23 adminspace-router-linkstate — a GET whose only match is a
            // queryable HOSTED BY THIS router (self is excluded from the routing
            // targets, so a self-hosted admin GET `@/<self-zid>/router/**` reaches
            // the empty-route tail) self-dispatches to its handler, replying +
            // emitting its own closing Final. Mirrors the peer's
            // `finish_unrouted_request`. A non-admin empty route falls through.
            if self.dispatch_router_local_queryables(inbound, reliable, request, &keyexpr) {
                return;
            }
            // zenoh route_query EMPTY route: no queryable matched, so PROMPT a
            // ResponseFinal back to the querier (its get() terminates at once). No
            // pending entry (nothing is awaited).
            let final_msg =
                wz_session_core::response_final_build::build_response_final(request.rid);
            self.send_to_face(inbound, reliable, || {
                NetworkMessage::ResponseFinal(final_msg.clone())
            });
        }
    }

    /// The per-mesh-tier query-route parameters for a Request whose inbound source
    /// role is `src_tier` — zenoh `compute_query_route`'s block-1 / block-2 gate +
    /// source selection (`hat/router/queries.rs:1465-1497`). `None` when the block
    /// is master-gated OFF; else a [`MeshQueryBlock`]:
    /// - the block's OWN tier is the source's tier (within-tier leg): route along
    ///   the QUERIER's tree, stamp its psid, exclude the real inbound neighbour —
    ///   always allowed (the gate reduces to true), zenoh `router_source = source`.
    /// - a CROSS tier: route along SELF's tree (self-origination, node_id 0), no
    ///   inbound exclusion (the inbound face is no node of this net) — zenoh's
    ///   `router_source = net.idx`; master-GATED (only the elected master bridges a
    ///   Query across meshes, the query twin of `bridge_push_cross_mesh`).
    fn mesh_query_block(
        &self,
        block_tier: FaceTier,
        src_tier: FaceTier,
        master: bool,
        within: Option<(Zid, u16)>,
        inbound_zid: Option<Zid>,
        self_zid: Zid,
    ) -> Option<MeshQueryBlock> {
        // The block gates: block 1 (routers_net) `master || src == Router`; block 2
        // (linkstatepeers_net) `master || src != Router`.
        let gated_on = match block_tier {
            FaceTier::Routers => master || src_tier == FaceTier::Routers,
            FaceTier::LinkstatePeers => master || src_tier != FaceTier::Routers,
            FaceTier::Client => return None,
        };
        if !gated_on {
            return None;
        }
        if src_tier == block_tier {
            // Within-tier: route along the querier's tree (its resolved source +
            // psid), excluding its own inbound neighbour. `within` is `None` when
            // the mesh source was UNRESOLVABLE (a transit Query naming a psid this
            // node has not learned) — the `?` short-circuit here IS the
            // within-leg-only drop: this block is omitted while the cross-tier +
            // client legs (self-originated, no querier source) still route, the
            // route_push / zenoh per-block degrade parity.
            let (source_zid, out_node_id) = within?;
            Some(MeshQueryBlock {
                tier: block_tier,
                source_zid,
                source_psid: out_node_id,
                inbound_for_net: inbound_zid,
            })
        } else {
            // Cross-tier: self-origination into this mesh (self tree root, node_id
            // 0), no inbound exclusion.
            Some(MeshQueryBlock {
                tier: block_tier,
                source_zid: self_zid,
                source_psid: 0,
                inbound_for_net: None,
            })
        }
    }

    /// The GLOBAL BestMatching winner (zenoh `compute_final_route`'s BestMatching,
    /// `dispatcher/queries.rs:243`): the globally-nearest COMPLETE queryable across
    /// both meshes + clients, or `None` when none is complete (the caller then
    /// falls back to All). zenoh sorts the union route by SELF-relative distance and
    /// takes the first complete; wz picks the min over each net's per-net nearest
    /// complete ([`select_best_matching`], min-of-mins == global-min) and the client
    /// candidates at distance 1. A distance TIE keeps the EARLIER block (routers
    /// before peers before clients), matching zenoh's stable-sorted B1/B2/B3 order.
    fn best_query_winner(
        &self,
        blocks: &[MeshQueryBlock],
        client_gate: bool,
        inbound: FaceId,
        keyexpr: &str,
        self_zid: Zid,
    ) -> Option<BestQueryWinner> {
        let mut best: Option<(u16, BestQueryWinner)> = None;
        for (bi, block) in blocks.iter().enumerate() {
            let Some((net, _)) = self.plane(block.tier) else {
                continue;
            };
            let Some(qabls) = self.qabls_table(block.tier) else {
                continue;
            };
            if let Some((dist, hop)) = select_best_matching(
                &net.borrow(),
                qabls,
                keyexpr,
                &block.source_zid,
                &self_zid,
                block.inbound_for_net,
            ) {
                // Truncate the jittered graph distance to u16, exactly as zenoh
                // stamps `distance: net.distances[qabl_idx] as u16`
                // (`hat/router/queries.rs:1107`): the per-net `select_best_matching`
                // picks the truly-nearest by the full f64 (jitter breaks a same-cost
                // tie deterministically WITHIN a net), but the CROSS-block compare
                // must be on the same integer scale zenoh sorts by. With the DEFAULT
                // link weight (100, matching zenoh's `DEFAULT_LINK_WEIGHT`) a 1-hop
                // mesh queryable is ~100 and a client is 1, so a client wins by
                // distance; an advertised weight-1 link CAN tie a client at u16 1,
                // and the mesh block (fed first) then wins — zenoh's insertion
                // order (B1/B2 before B3) breaks the same tie the same way. The
                // truncation's other load-bearing role is cross-net MESH-vs-MESH
                // ties: a router-net 100.6 and a peer-net 100.3 both → u16 100, and
                // the strict `<` + routers-first order then breaks that tie exactly
                // as zenoh's stable B1/B2/B3 sort does.
                Self::consider_best(&mut best, dist as u16, BestQueryWinner::Mesh(bi, hop));
            }
        }
        if client_gate {
            if let Some(face) = self.first_complete_client(inbound, keyexpr) {
                // A client-hosted queryable is a directly-attached leaf: distance 1
                // (zenoh `compute_query_route` block 3's `distance: 1`).
                Self::consider_best(&mut best, 1, BestQueryWinner::Client(face));
            }
        }
        best.map(|(_, winner)| winner)
    }

    /// Keep `winner` as the running best IFF it is strictly NEARER (fewer hops) than
    /// the current best — strict `<` so an equal-distance later candidate does NOT
    /// displace the earlier one (the router/peer/client block order is the zenoh
    /// stable-sort tie break, so the caller must feed candidates in that order).
    fn consider_best(
        best: &mut Option<(u16, BestQueryWinner)>,
        dist: u16,
        winner: BestQueryWinner,
    ) {
        if best.as_ref().map_or(true, |(bd, _)| dist < *bd) {
            *best = Some((dist, winner));
        }
    }

    /// The first client face (other than `inbound`) hosting a queryable COMPLETE
    /// for `keyexpr` — the client candidate for the GLOBAL BestMatching (distance 1,
    /// zenoh `compute_query_route` block 3's `distance: 1`,
    /// `hat/router/queries.rs:1512`). "Complete for the query" is the declared
    /// `complete` AND the declaration keyexpr INCLUDING the full query keyexpr — the
    /// same test [`complete_for_query_peers`] applies to a mesh queryable.
    fn first_complete_client(&self, inbound: FaceId, keyexpr: &str) -> Option<FaceId> {
        let query_chunks: Vec<&str> = keyexpr.split('/').collect();
        self.client_qabls
            .borrow()
            .iter()
            .filter(|(id, _)| **id != inbound)
            .find(|(_, qabls)| {
                qabls.iter().any(|(decl, info)| {
                    info.complete && keyexpr_includes_target(decl, &query_chunks)
                })
            })
            .map(|(id, _)| *id)
    }

    /// Route the Query to EVERY matching queryable (`QueryTarget::All`, and the
    /// BestMatching fallback) or every COMPLETE one (`QueryTarget::AllComplete`,
    /// `complete_only`) — zenoh `compute_final_route`'s All / AllComplete
    /// (`dispatcher/queries.rs:215`/`:228`) fanned across the gated mesh blocks + the
    /// client block. Returns the total faces forwarded to (the empty-route witness
    /// [`route_request`](Self::route_request) sums to decide the prompt final).
    #[allow(clippy::too_many_arguments)]
    fn forward_request_all(
        &self,
        blocks: &[MeshQueryBlock],
        client_gate: bool,
        complete_only: bool,
        reliable: bool,
        inbound: FaceId,
        request: &RequestOwned,
        keyexpr: &str,
        fan: &Rc<QueryFan>,
        deadline: Instant,
        self_zid: Zid,
    ) -> usize {
        let mut forwarded = 0;
        for block in blocks {
            let Some((net, _)) = self.plane(block.tier) else {
                continue;
            };
            let Some(qabls) = self.qabls_table(block.tier) else {
                continue;
            };
            // Compute the tree hops under the net borrow, then release it before the
            // fan-out (which re-borrows `faces` + allocates pending).
            let hops = {
                let n = net.borrow();
                if complete_only {
                    complete_query_directions(&n, qabls, keyexpr, &block.source_zid, &self_zid)
                } else {
                    all_query_directions(&n, qabls, keyexpr, &block.source_zid, &self_zid)
                }
            };
            forwarded += self.forward_request_to_tier(
                block, reliable, inbound, &hops, request, keyexpr, fan, deadline,
            );
        }
        if client_gate {
            forwarded += self.forward_request_to_clients(
                complete_only,
                reliable,
                inbound,
                request,
                keyexpr,
                fan,
                deadline,
            );
        }
        forwarded
    }

    /// Forward the Query to every face of `block.tier` that
    /// [`is_tree_forward_target`] selects for `hops`, ALLOCATING a fresh
    /// pending-return qid per outbound face (so the reverse Response route, C5c,
    /// finds its way back) stamped as that Request's rid. The Request is re-stamped
    /// with the block's `source_psid` (the querier tree for the within leg, `0`
    /// self-origination for a cross leg) and B1-normalized to a literal keyexpr (a
    /// downstream child shares no inbound alias table). Returns the faces forwarded
    /// to; the per-face qid is why each face gets its OWN carrier.
    #[allow(clippy::too_many_arguments)]
    fn forward_request_to_tier(
        &self,
        block: &MeshQueryBlock,
        reliable: bool,
        inbound: FaceId,
        hops: &[Zid],
        request: &RequestOwned,
        keyexpr: &str,
        fan: &Rc<QueryFan>,
        deadline: Instant,
    ) -> usize {
        if hops.is_empty() {
            return 0;
        }
        let mut template = request.clone();
        set_request_source(&mut template, block.source_psid);
        if set_request_keyexpr_literal(&mut template, keyexpr).is_err() {
            return 0;
        }
        let mut forwarded = 0;
        let _ = self.fan_out_tier(block.tier, reliable, |id, zid| {
            if !is_tree_forward_target(id, zid, inbound, block.inbound_for_net, hops) {
                return Ok(None);
            }
            let qid = self.pending.borrow_mut().allocate(id, fan, deadline);
            let mut carrier = template.clone();
            carrier.rid = qid;
            forwarded += 1;
            Ok(Some(NetworkMessage::Request(Box::new(carrier))))
        });
        forwarded
    }

    /// Forward the Query to CLIENT faces hosting a matching queryable — zenoh
    /// `compute_query_route` block 3 fanned (`hat/router/queries.rs:1499`): every
    /// client (other than `inbound`) whose stored queryable INTERSECTS the query
    /// (`complete_only == false`, `QueryTarget::All`) or is COMPLETE-for-the-query
    /// (`complete_only == true`, `QueryTarget::AllComplete`), allocating a
    /// pending-return qid per client face. Self-origination stamp (`source_psid ==
    /// 0`, zenoh `NodeId::default()` for a client leaf). Returns the client faces
    /// forwarded to.
    #[allow(clippy::too_many_arguments)]
    fn forward_request_to_clients(
        &self,
        complete_only: bool,
        reliable: bool,
        inbound: FaceId,
        request: &RequestOwned,
        keyexpr: &str,
        fan: &Rc<QueryFan>,
        deadline: Instant,
    ) -> usize {
        let mut template = request.clone();
        set_request_source(&mut template, 0);
        if set_request_keyexpr_literal(&mut template, keyexpr).is_err() {
            return 0;
        }
        let query_chunks: Vec<&str> = keyexpr.split('/').collect();
        let mut forwarded = 0;
        let _ = self.fan_out_tier(FaceTier::Client, reliable, |id, _zid| {
            if id == inbound {
                return Ok(None);
            }
            let qualifies = self.client_qabls.borrow().get(&id).is_some_and(|qabls| {
                qabls.iter().any(|(decl, info)| {
                    if complete_only {
                        info.complete && keyexpr_includes_target(decl, &query_chunks)
                    } else {
                        keyexpr_intersects_target(decl, &query_chunks)
                    }
                })
            });
            if !qualifies {
                return Ok(None);
            }
            let qid = self.pending.borrow_mut().allocate(id, fan, deadline);
            let mut carrier = template.clone();
            carrier.rid = qid;
            forwarded += 1;
            Ok(Some(NetworkMessage::Request(Box::new(carrier))))
        });
        forwarded
    }

    /// Forward the Query to ONE specific face — the single-target send the GLOBAL
    /// BestMatching CLIENT winner uses (a client-hosted queryable is a leaf, not a
    /// tree hop toward which [`forward_request_to_tier`](Self::forward_request_to_tier)
    /// fans). Allocates the pending-return qid keyed by that face + stamps it as the
    /// Request's rid; re-stamps `source_psid` (0 for a client) + a literal keyexpr.
    /// Returns 1 when the face is live (a route was taken), else 0 (a vanished
    /// winner is no route — the caller prompts the empty-route final).
    #[allow(clippy::too_many_arguments)]
    fn forward_request_to_face(
        &self,
        out_face: FaceId,
        source_psid: u16,
        reliable: bool,
        request: &RequestOwned,
        keyexpr: &str,
        fan: &Rc<QueryFan>,
        deadline: Instant,
    ) -> usize {
        if !self.faces.borrow().contains_key(&out_face) {
            return 0;
        }
        let mut carrier = request.clone();
        set_request_source(&mut carrier, source_psid);
        if set_request_keyexpr_literal(&mut carrier, keyexpr).is_err() {
            return 0;
        }
        let qid = self.pending.borrow_mut().allocate(out_face, fan, deadline);
        carrier.rid = qid;
        self.send_to_face(out_face, reliable, || {
            NetworkMessage::Request(Box::new(carrier.clone()))
        });
        1
    }

    /// A `Response` (a queryable's reply to a routed Query) arrived on `inbound`:
    /// route it BACK toward the querier via the pending-query table (C5c) — the
    /// reverse of [`route_request`](Self::route_request)'s allocate, the router
    /// twin of [`LinkstateForwarder::forward_response`]. The response's
    /// `request_id` is the local qid THIS router stamped on the Request it
    /// forwarded out `inbound`; look it up ([`PendingQueries::peek`], NOT taking —
    /// more replies may follow), rewrite the `request_id` back to the recorded
    /// upstream rid, B1-normalize the reply keyexpr to a literal, and unicast it to
    /// the recorded inbound face. The return face may be a MESH face (a transit
    /// reply) or a CLIENT face (the querier is a local client) — the tier-agnostic
    /// [`send_to_face`](Self::send_to_face) covers both. zenoh
    /// `route_send_response` (`dispatcher/queries.rs`): look up
    /// `face.pending_queries`, rewrite `rid = query.src_qid`, send to
    /// `query.src_face`. An unknown qid (finalized / timed out / never sent) drops
    /// silently.
    fn forward_response(&self, inbound: FaceId, reliable: bool, response: &ResponseOwned) {
        // Resolve the reply keyexpr against the inbound (forward-outbound) face's
        // alias table — scoped borrow (an unresolvable alias drops the Response;
        // the closing final still terminates the querier). A keyexpr-LESS reply
        // (the EMPTY wireexpr — a downstream relay's synthesized timeout Err,
        // zenoh WireExpr::empty()) is passed THROUGH unresolved with only the
        // rid rewritten, as zenoh route_send_response forwards a reply with no
        // keyexpr resolution at all (dispatcher/queries.rs:595-635) — resolving
        // it would drop the explicit Err the querier is owed.
        let keyexpr = if wireexpr_is_empty(&response.keyexpr.body) {
            None
        } else {
            let faces = self.faces.borrow();
            let Some(s) = faces.get(&inbound) else {
                return;
            };
            match resolve_wireexpr(&response.keyexpr.body, &s.keyexpr_table) {
                Some(k) => Some(k),
                None => return,
            }
        };
        let Some((orig_face, orig_rid)) = self.pending.borrow().peek(inbound, response.request_id)
        else {
            return;
        };
        let mut carrier = response.clone();
        carrier.request_id = orig_rid;
        if let Some(ke) = &keyexpr {
            if set_response_keyexpr_literal(&mut carrier, ke).is_err() {
                return;
            }
        }
        self.send_to_face(orig_face, reliable, || {
            NetworkMessage::Response(Box::new(carrier.clone()))
        });
    }

    /// A `ResponseFinal` (a queryable's end-of-replies marker) arrived on
    /// `inbound`: FREE this branch's pending entry and — only when it was the
    /// fan's LAST live branch — route the closing final BACK toward the querier
    /// (C5c), the [`PendingQueries::take`] twin of
    /// [`forward_response`](Self::forward_response)'s peek, the router twin of
    /// [`LinkstateForwarder::forward_response_final`]. A Query the router fanned
    /// to several queryables (`QueryTarget::All` / `AllComplete` / BestMatching's
    /// fall-back — across BOTH mesh tiers and clients) must close upstream exactly
    /// ONCE, after ALL branches finalize: a NON-last final is ABSORBED (the
    /// querier still awaits the other branches' replies) — zenoh's
    /// `Arc::into_inner` gate in `finalize_pending_query`
    /// (`dispatcher/queries.rs:670`), which propagates `ResponseFinal { rid:
    /// query.src_qid }` to `query.src_face` only on the LAST branch's removal.
    /// The forwarded final is rewritten to the recorded upstream rid and unicast
    /// to the recorded inbound face (a ResponseFinal carries no keyexpr, so no B1
    /// normalize). An unknown qid drops silently.
    fn forward_response_final(
        &self,
        inbound: FaceId,
        reliable: bool,
        response_final: &ResponseFinalOwned,
    ) {
        // TAKE the branch — frees the entry; `last` is the fan's last-out gate.
        let Some((orig_face, orig_rid, last)) = self
            .pending
            .borrow_mut()
            .take(inbound, response_final.request_id)
        else {
            return;
        };
        if !last {
            return; // other branches of the fan still answering: absorb
        }
        let mut carrier = response_final.clone();
        carrier.request_id = orig_rid;
        self.send_to_face(orig_face, reliable, || {
            NetworkMessage::ResponseFinal(carrier.clone())
        });
    }

    /// Reap pending query BRANCHES past their deadline (C5c) — the router twin
    /// of [`LinkstateForwarder::reap_timed_out_queries`], the wz form of zenoh's
    /// per-branch `QueryCleanup::run` (`dispatcher/queries.rs:305-349`). The
    /// [`tick`](FaceForwarder::tick) calls this each coalescing window: sweep the
    /// pending table ([`PendingQueries::expired`]) for branches whose
    /// `ResponseFinal` never arrived on a still-up face and route the synthesized
    /// timeout messages back via the shared [`synthesize_expired_query_returns`]
    /// core: an `Err("Timeout")` reply per reaped BRANCH (zenoh runs one
    /// `QueryCleanup` per branch, each sending an Err) and the closing
    /// `ResponseFinal` only for a `last` branch (the fan's last-out gate — a
    /// sibling branch still answering must not have its query closed by this
    /// branch's timeout). The final is the load-bearing part (it terminates the
    /// querier's `get()`); the Err gives an explicit timeout error rather than a
    /// silent empty result — and a relaying wz hop passes the empty-keyexpr Err
    /// THROUGH (`forward_response`'s `wireexpr_is_empty` arm), so both reach a
    /// multi-hop querier. The `expired` borrow is released before the per-entry
    /// send re-borrows the faces table.
    fn reap_timed_out_queries(&self) {
        let reaped = self.pending.borrow_mut().expired(self.now());
        if reaped.is_empty() {
            return;
        }
        self.timed_out.set(self.timed_out.get() + reaped.len());
        synthesize_expired_query_returns(&reaped, |face, msg| self.send_one_to_face(face, msg));
    }

    /// Total live pending query branches — the pending-table witness the shutdown
    /// summary (and a test) reads; the router twin of
    /// [`LinkstateForwarder::pending_len`].
    pub fn pending_len(&self) -> usize {
        self.pending.borrow().len()
    }

    /// Total pending query BRANCHES reaped by the timeout sweep (a 2-branch fan
    /// expiring counts 2) — the GC witness; the router twin of
    /// [`LinkstateForwarder::pending_timed_out`].
    pub fn pending_timed_out(&self) -> usize {
        self.timed_out.get()
    }

    /// Send ONE built message to a specific face, ANY tier — the router's
    /// single-target egress (the prompt empty-route ResponseFinal + the GLOBAL
    /// BestMatching client winner + the C5c Response return). Tier-agnostic (unlike
    /// the tier-scoped [`fan_out_tier`](Self::fan_out_tier)): a return / prompt
    /// target may be a mesh face OR a client face. Returns whether the face existed
    /// and accepted the message. (Egress access control is deferred with the
    /// interceptor plane, like `fan_out_tier` — the y113 obligation.)
    fn send_to_face(
        &self,
        target: FaceId,
        reliable: bool,
        mut build: impl FnMut() -> NetworkMessage,
    ) -> bool {
        let faces = self.faces.borrow();
        let Some(state) = faces.get(&target) else {
            return false;
        };
        let msg = build();
        // §5.16 EGRESS access control (y113): gate the single-target send (a query
        // Response / ResponseFinal / prompt final) by the destination's subject —
        // a denied reply is dropped and witnessed, not returned. The other egress
        // seam beside `fan_out_tier`.
        if !self.admit_outbound(state, &msg) {
            self.interceptor_dropped
                .set(self.interceptor_dropped.get() + 1);
            return false;
        }
        state
            .actions
            .send_network_message(msg, reliable, false)
            .is_ok()
    }

    /// [`send_to_face`](Self::send_to_face) for an already-BUILT owned message —
    /// the adapter the shared synthesis cores ([`synthesize_expired_query_returns`]
    /// / [`synthesize_drained_fan_finals`]) hand their per-send `NetworkMessage`
    /// to (`NetworkMessage` is not `Clone`; the one-shot `Option` take feeds the
    /// at-most-once builder — the target face is looked up exactly once).
    fn send_one_to_face(&self, face: FaceId, msg: NetworkMessage) {
        let mut carrier = Some(msg);
        self.send_to_face(face, true, || {
            carrier.take().expect("send_one_to_face builds once")
        });
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
        // OBLIGATION-1: purge ALL FaceId-keyed leaf state BEFORE the linkless
        // early-return below (a Client face is `link == None`, so it never reaches
        // the graph teardown). (a) the pending-query return table entries keyed by
        // this face as their OUT face (C5b) — mirrors the sibling forwarder's
        // `pending.remove_face`-first deregister; entries on OTHER faces that point
        // back to this one as their inbound target self-heal at send / timeout. (b)
        // this face's hosted client queryables (C5b) — and, since A3 advertises a
        // client queryable cross-tier, recompute self's advertisement per departed
        // keyexpr via the withdraw seam (a DOWNGRADE if another contributor remains;
        // a full `UndeclareQueryable` retraction if none — now expressible via the
        // ext_wire_expr codec), mirroring the client sub withdraw.
        //
        // A fan whose LAST answering branch died with this face is DRAINED: its
        // querier is owed the closing ResponseFinal NOW (zenoh
        // `finalize_pending_queries` on face teardown, final only — no Err), else
        // its get() waits out its own timeout. A drained fan whose querier IS the
        // departed face has nobody left to notify (skipped).
        let drained = self.pending.borrow_mut().remove_face(&id);
        synthesize_drained_fan_finals(&drained, id, |face, msg| self.send_one_to_face(face, msg));
        let departed_qabls = self.client_qabls.borrow_mut().remove(&id);
        if let Some(qabls) = departed_qabls {
            for keyexpr in qabls.into_keys() {
                self.withdraw_client_cross_tier_qabl(&keyexpr);
            }
        }
        // Purge the FaceId-keyed client sub store, withdrawing self's cross-tier
        // advertisement for any keyexpr this was the LAST client of. A Client face
        // is skipped by the peer/router fan-out (its tier), so flooding before its
        // `faces` entry is dropped is harmless.
        let departed = self.client_subs.borrow_mut().remove(&id);
        if let Some(keys) = departed {
            for keyexpr in keys {
                if !self.any_client_subscribes(&keyexpr) {
                    self.withdraw_client_cross_tier_sub(&keyexpr);
                }
            }
        }
        // §5.21 routing-token-tables (slice-3) — purge the FaceId-keyed CLIENT
        // liveliness-token store too, withdrawing self's cross-tier advertisement
        // for any keyexpr this was the LAST client of (the token twin of the
        // client_subs purge above; the single client-token purge site — a Client
        // face is link==None so it never reaches the Oam-detach graph teardown).
        // `remove` is bound to a `let` so the borrow_mut drops BEFORE the loop reads
        // `any_client_holds_token`; the keyexprs are deduped (a face may hold one
        // keyexpr under several decl ids) so the withdraw fires once.
        // Purge this face's client tokens + withdraw self's cross-tier advertisement
        // for any keyexpr it was the LAST client of. The departed keyexprs are HOISTED
        // so the slice-5 reader-notify can run AFTER `future_tokens.purge_face` below
        // (which removes the departed face, so it is not self-notified).
        #[cfg(feature = "routing-token-tables")]
        let departed_token_keys: Vec<String> = {
            let departed_tokens = self.client_tokens.borrow_mut().remove(&id);
            match departed_tokens {
                Some(ids) => {
                    let keyexprs: HashSet<String> = ids.into_values().collect();
                    for keyexpr in &keyexprs {
                        if !self.any_client_holds_token(keyexpr) {
                            self.withdraw_client_cross_tier_token(keyexpr);
                        }
                    }
                    keyexprs.into_iter().collect()
                }
                None => Vec::new(),
            }
        };
        // Purge this face's FUTURE-mode interest + pushed-declaration state
        // (OBLIGATION 1, alongside client_subs/client_qabls): a client face is
        // `link == None` so it never reaches the graph teardown below. The DEPARTED
        // face owes itself no undeclare (pico clears its own write-filter targets on
        // the transport drop, filtering.c CONNECTION_DROPPED); the SURVIVING readers of
        // this face's tokens ARE owed one — the slice-5 loop below (subs leave this a
        // benign over-deliver gap; a liveliness token's stale-live is not benign, so
        // tokens close it — zenoh close_face retracts on face-down for BOTH planes,
        // mod.rs:498/541).
        self.future_subs.borrow_mut().purge_face(id);
        self.future_qabls.borrow_mut().purge_face(id);
        // §5.21 routing-token-tables (slice-4): the token FUTURE store is client leaf
        // state too — purge it alongside future_subs/future_qabls (OBLIGATION 1).
        #[cfg(feature = "routing-token-tables")]
        self.future_tokens.borrow_mut().purge_face(id);
        // §5.21 slice-5: NOW notify the surviving future-push readers (future_tokens no
        // longer holds the departed face). Runs before the `link == None` early-return
        // so a Client face is covered.
        #[cfg(feature = "routing-token-tables")]
        for keyexpr in departed_token_keys {
            self.undeclare_push_token(&keyexpr);
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
        // Reap pending queries whose ResponseFinal never arrived on a still-up
        // face (zenoh's per-query QueryCleanup timeout) on the same coalescing
        // cadence (C5c) — a cheap empty sweep when nothing timed out, exactly as
        // the sibling forwarder's tick.
        self.reap_timed_out_queries();
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

    /// Route a Push RECEIVED on the multicast INGRESS face (the single
    /// group-ingress face) to the router's LOCAL unicast (client) subscribers AND
    /// — iff self is the group Designated Router for the Push's keyexpr (I3b) —
    /// federate it into the unicast linkstate mesh. Classified Client-tier like
    /// zenoh's mcast peer (`WhatAmI::Client`, `new_peer_multicast` router.rs:226).
    /// The echo guard keeps it OFF every multicast group (`inbound_is_mcast = true`
    /// — zenoh both-multicast deny, `hat/router/mod.rs:812`). Mesh federation is
    /// gated by the per-keyexpr HRW Designated-Router election
    /// ([`mcast_ingress_may_federate`](Self::mcast_ingress_may_federate) →
    /// [`is_group_dr`](Self::is_group_dr)): exactly one on-group router federates a
    /// given keyexpr, so two group-sharing mesh-peered routers cannot echo-loop
    /// (the two-router-shared-group topology zenoh's `WhatAmI::Client` "Quick hack"
    /// leaves undefended). Aliases are resolved to literal UPSTREAM in the dispatch
    /// SSOT (I3a), so this face sees a literal Push; a still-aliased id-only push
    /// (the single ingress face carries no per-peer alias table) is dropped by
    /// [`resolve_inbound_keyexpr`](Self::resolve_inbound_keyexpr). The synthetic
    /// [`MCAST_INGRESS_FACE`] id is disjoint from the dense unicast range, so the
    /// Client-tier fan-out's source self-skip (`id == inbound`) excludes no real
    /// subscriber.
    #[cfg(feature = "transport-multicast")]
    fn route_mcast_ingress(&self, priority: Priority, reliable: bool, push: &PushOwned) {
        // R311y227 — a multicast-received Push re-injects at the priority its frame
        // carried (the decoded ext_qos band surfaced by `multicast_rx`; DEFAULT on
        // a non-qos group). The mesh federation + local-client delivery then ride
        // that band via `route_push`, closing the ingress half of the
        // "mcast-egress band" residual (the egress half is `broadcast_to_mcast_groups`).
        self.route_push(
            MCAST_INGRESS_FACE,
            FaceTier::Client,
            reliable,
            priority,
            push,
            true,
        );
    }

    /// Replace the on-group ROUTER member set (the I3b Designated-Router election
    /// candidates) with the live view the router-hat's multicast INGRESS loop
    /// relays from its `MulticastDispatcher` (per-peer JOIN `whatami`). Called on
    /// every group membership change (a router JOIN admit / lease evict) via the
    /// accept loop's `Step::McastMembers` arm. `self` is an implicit candidate
    /// added at election time, so the relayed slice carries only the OTHER
    /// on-group routers. The `FaceForwarder` default is a no-op — only the router
    /// (with a multicast ingress plane) tracks group membership.
    #[cfg(feature = "router-multicast-faces")]
    fn set_mcast_group_members(&self, members: &[Vec<u8>]) {
        // The relay carries RAW zid bytes (keeping `wz-routing-graph` off the
        // accept-loop channel + trait); convert to `Zid` here — the router build
        // links the routing graph. A malformed zid (never from a wz JOIN) drops.
        let mut slot = self.mcast_group_members.borrow_mut();
        slot.clear();
        slot.extend(
            members
                .iter()
                .filter_map(|b| Zid::try_from(b.as_slice()).ok()),
        );
        // I3c witness: high-water on-group ROUTER member count. A non-zero peak
        // means this router saw a peer router on the group (the relay chain ran).
        self.mcast_member_peak
            .set(self.mcast_member_peak.get().max(slot.len()));
    }

    /// Replace the group-SUBSCRIBER keyexpr aggregate with the live deduped view the
    /// router-hat's ingress loop relays (§5.21 sub plane, S2), diffing old-vs-new to
    /// advertise the group's interest into the unicast mesh on a keyexpr's
    /// false->true edge and withdraw it on true->false. A wholesale REPLACE (like
    /// [`set_mcast_group_members`](Self::set_mcast_group_members)'s clear+extend) so
    /// the forwarder snapshot can never drift from the dispatch SSOT
    /// ([`MulticastDispatcher::group_sub_keyexprs`], the derive-not-store union).
    /// The new set is committed BEFORE the diff walk so the withdraw predicate
    /// ([`self_advertises_sub_into`](Self::self_advertises_sub_into)) sees the
    /// post-removal state (a removed keyexpr no longer counts its own group sub, so
    /// it withdraws iff no client / native still holds it). The `FaceForwarder`
    /// default is a no-op — only the router advertises a group's interest.
    #[cfg(feature = "router-multicast-faces")]
    fn set_mcast_group_subs(&self, subs: &[String]) {
        let new: HashSet<String> = subs.iter().cloned().collect();
        // Diff against the current set, then COMMIT the new set (move — no clone),
        // so `withdraw_group_cross_tier_sub`'s `self_advertises_sub_into` check sees
        // the removed keyexpr already gone from `group_subs`.
        let (added, removed) = {
            let old = self.group_subs.borrow();
            let added: Vec<String> = new.difference(&old).cloned().collect();
            let removed: Vec<String> = old.difference(&new).cloned().collect();
            (added, removed)
        };
        *self.group_subs.borrow_mut() = new;
        // S3 reachability witness: high-water of DISTINCT group subs advertised, so a
        // cross-impl test can gate a mesh-side publisher on this router provably
        // holding + advertising the on-group subscriber's interest.
        let live = self.group_subs.borrow().len();
        self.group_subs_advertised_peak
            .set(self.group_subs_advertised_peak.get().max(live));
        for keyexpr in &added {
            self.advertise_group_cross_tier_sub(keyexpr);
        }
        for keyexpr in &removed {
            self.withdraw_group_cross_tier_sub(keyexpr);
        }
    }

    fn forward(&self, id: FaceId, event: IterationEvent<'_>) {
        let IterationEvent::Poll(DriverLoopOutcome::FramePayload {
            messages,
            reliable,
            priority,
            ..
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
                None => {
                    log::debug!(
                        "router forward: DROP {} inbound message(s) from unregistered face {id:?}",
                        messages.len()
                    );
                    return;
                }
            }
        };
        for message in messages {
            log::debug!(
                "router forward: face {id:?} tier {tier:?} inbound {}",
                match message {
                    NetworkMessage::Oam(_) => "Oam".to_string(),
                    NetworkMessage::Push(_) => "Push".to_string(),
                    NetworkMessage::Declare(d) => match &d.body {
                        DeclareOwnedVariant::CodecZenohDeclSubscriber(_) => "Declare(Sub)",
                        DeclareOwnedVariant::CodecZenohUndeclSubscriber(_) => "Undeclare(Sub)",
                        DeclareOwnedVariant::CodecZenohDeclKexpr(_) => "Declare(Kexpr)",
                        DeclareOwnedVariant::CodecZenohUndeclKexpr(_) => "Undeclare(Kexpr)",
                        DeclareOwnedVariant::CodecZenohDeclQueryable(_) => "Declare(Qabl)",
                        DeclareOwnedVariant::CodecZenohUndeclQueryable(_) => "Undeclare(Qabl)",
                        _ => "Declare(other)",
                    }
                    .to_string(),
                    NetworkMessage::Request(_) => "Request".to_string(),
                    NetworkMessage::Response(_) => "Response".to_string(),
                    NetworkMessage::ResponseFinal(_) => "ResponseFinal".to_string(),
                    NetworkMessage::Interest(_) => "Interest".to_string(),
                    NetworkMessage::Unknown { mid, body } =>
                        format!("Unknown{{mid=0x{mid:02x}, len={}}}", body.len()),
                    #[allow(unreachable_patterns)]
                    _ => "other".to_string(),
                }
            );
            // §5.16 INGRESS access control (y113): consult the ingress chain ONCE
            // here, ahead of the kind-dispatch — a denied message is dropped (not
            // counted as received Push/Query, not routed) and witnessed. The router
            // twin of `LinkstateForwarder::forward`'s admit_inbound gate; the
            // empty-chain fast path (no ACL) is a single predicate read.
            if !self.admit_inbound(id, message) {
                self.interceptor_dropped
                    .set(self.interceptor_dropped.get() + 1);
                continue;
            }
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
                // route it through [`route_push`](Self::route_push), the router's
                // full zenoh `compute_data_route` (pubsub.rs:1215) — within-tier
                // transit (C1) + the master-gated cross-mesh federation bridge (C4)
                // + local client delivery (C3a) + the client->mesh re-injection
                // (C3b). The keyexpr resolution + master election run ONCE at the
                // head; single-router topologies elect self, so every master gate is
                // a no-op and the behavior is the pre-C4 route.
                NetworkMessage::Push(push) => {
                    self.data_seen.set(self.data_seen.get() + 1);
                    self.route_push(id, tier, *reliable, *priority, push, false);
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
                        if tier == FaceTier::Client {
                            self.ingest_client_queryable(id, declare);
                        } else {
                            self.ingest_queryable(id, tier, *reliable, declare);
                        }
                    }
                    // UndeclareQueryable: the query twin of the UndeclareSubscriber
                    // arm above. The keyexpr rides the `ext_wire_expr` extension (now
                    // that the wz-codecs body models the ext chain), so the retraction
                    // withdraws the source's queryable interest per-keyexpr — the
                    // face-down purge stays the safety net for a departed peer.
                    DeclareOwnedVariant::CodecZenohUndeclQueryable(_) => {
                        if tier == FaceTier::Client {
                            self.withdraw_client_queryable(id, declare);
                        } else {
                            self.withdraw_queryable(id, tier, *reliable, declare);
                        }
                    }
                    // §5.21 routing-token-tables — a DeclareToken: a MESH face
                    // (Router -> router_tokens, Peer -> linkstatepeer_tokens)
                    // registers + re-floods within its tier (slice-1/2); a CLIENT
                    // face lands the leaf in `client_tokens` + advertises self's
                    // cross-tier interest into BOTH meshes (slice-3). Its retraction
                    // is the UndeclareToken arm below.
                    #[cfg(feature = "routing-token-tables")]
                    DeclareOwnedVariant::CodecZenohDeclToken(_) => {
                        if tier == FaceTier::Client {
                            self.ingest_client_token(id, declare);
                        } else {
                            self.ingest_token(id, tier, *reliable, declare);
                        }
                    }
                    // An UndeclareToken retracts a token: a MESH source's SOURCED
                    // ({id:0, ext_wire_expr}) form routes to withdraw_token (slice-2,
                    // by keyexpr); a CLIENT's ID-KEYED form routes to
                    // withdraw_client_token (slice-3, by decl id).
                    #[cfg(feature = "routing-token-tables")]
                    DeclareOwnedVariant::CodecZenohUndeclToken(_) => {
                        if tier == FaceTier::Client {
                            self.withdraw_client_token(id, declare);
                        } else {
                            self.withdraw_token(id, tier, *reliable, declare);
                        }
                    }
                    _ => {}
                },
                // A Query Request: count the reception (the query-plane witness),
                // then route it through [`route_request`](Self::route_request) — the
                // router's full zenoh compute_query_route (3-block master-gated +
                // GLOBAL BestMatching over both meshes + clients, C5b).
                NetworkMessage::Request(request) => {
                    self.queries_seen.set(self.queries_seen.get() + 1);
                    self.route_request(id, tier, *reliable, request);
                }
                // A queryable's reply: route it BACK toward the querier via the
                // pending table (C5c) — peek on a Response (more replies may
                // follow); take on the ResponseFinal frees that BRANCH, and the
                // final propagates upstream only from the fan's LAST branch.
                NetworkMessage::Response(response) => {
                    self.forward_response(id, *reliable, response);
                }
                NetworkMessage::ResponseFinal(response_final) => {
                    self.forward_response_final(id, *reliable, response_final);
                }
                // An Interest solicitation (the zenoh-1.x interest-declaration
                // handshake). Reply with the matching CURRENT declarations wz
                // holds + a DeclareFinal so the soliciting peer's write-filter (a
                // pico publisher/querier drops its own data LOCALLY until it learns
                // a matching remote declaration) deactivates. Previously dropped
                // (`_ => {}`), which black-holed the reverse-data path.
                NetworkMessage::Interest(interest) => {
                    self.respond_to_interest(id, interest);
                }
                _ => {}
            }
        }
    }
}

/// The per-message [`InterceptorContext`] for one router face — the router twin of
/// [`LinkstateForwarder`](crate::linkstate_forward)'s `FaceContext`. Borrows the
/// face's state so an enforcer reads the subject (the peer's routing zid) and
/// resolves a governed message's keyexpr against that face's link-local alias
/// table. Serves BOTH flows: the inbound face for ingress, the destination face
/// for egress (the subject is the peer on the other end of the link either way).
struct RouterFaceContext<'a> {
    face: &'a RouterFaceState,
}

impl InterceptorContext for RouterFaceContext<'_> {
    fn subject(&self) -> Option<Zid> {
        peer_zid_routing(&self.face.actions)
    }

    // R311y453 — the §5.16 link-derived subject, off the driver this face already
    // holds. Same one-liner as the single-net twin: both forwarders read the
    // subject from the same place, so the two cannot drift.
    fn link_subject(&self) -> Option<&LinkSubject> {
        self.face.actions.link_subject()
    }

    fn full_keyexpr(&self, msg: &NetworkMessage) -> Option<String> {
        // Delegates to the shared SSOT (the single-net FaceContext delegates to the
        // same free fn), alias-resolved against THIS face's table — one
        // governed-kind match for both forwarders.
        resolve_governed_keyexpr(msg, &self.face.keyexpr_table)
    }
}

/// The production [`InterceptorSink`](crate::interceptor::InterceptorSink) impl for
/// the router — the typed config SSOT drives the live forwarder through this seam
/// (parity with [`LinkstateForwarder`](crate::linkstate_forward)). Delegates to the
/// inherent [`set_interceptors`](RouterForwarder::set_interceptors).
impl crate::interceptor::InterceptorSink for RouterForwarder {
    fn set_interceptors(&self, config: crate::interceptor::InterceptorConfig) {
        RouterForwarder::set_interceptors(self, config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_impl::TokioRuntime;
    use crate::test_fixtures::{recording_actions, RecordingLinkDriver};
    use sce_forge_runtime::codec::SceBytes;
    #[cfg(feature = "access-acl")]
    use wz_access_control::{
        AclConfig, AclFlow, AclMessage, AclPolicy, AclRule, Permission, SubjectSelector,
    };
    use wz_codecs::linkstate::LinkstateOwned;
    use wz_codecs::linkstate_link::LinkstateLink;
    use wz_codecs::wireexpr::WireexprOwnedVariant;
    use wz_codecs::wireexpr_local::WireexprLocalOwned;
    use wz_runtime_core::runtime::Runtime;
    use wz_session_core::push_routing_context::{read_push_hoplimit, read_push_source};

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

    /// Drive `forward` with a single inbound message on `face` (reliable).
    fn forward_one(fwd: &RouterForwarder, face: FaceId, message: NetworkMessage) {
        forward_one_reliability(fwd, face, message, true);
    }

    /// [`forward_one`] with an explicit reliability channel — so a test can drive
    /// a BEST-EFFORT (reliable=false) inbound frame and assert the router
    /// propagates the channel onward (C3b threads the inbound `reliable` into the
    /// mesh fan, unlike `publish`'s hard-coded reliable).
    fn forward_one_reliability(
        fwd: &RouterForwarder,
        face: FaceId,
        message: NetworkMessage,
        reliable: bool,
    ) {
        forward_one_priority(fwd, face, message, reliable, Priority::DEFAULT);
    }

    /// [`forward_one_reliability`] with an explicit priority BAND — so a
    /// transport-qos test can drive a banded inbound frame and assert the router
    /// PRESERVES it on transit (R311y224). `forward_one_reliability` delegates here
    /// with `Priority::DEFAULT`, so this helper always has a non-gated caller (no
    /// dead-code under the plain `routing-router-hat` clippy arm).
    fn forward_one_priority(
        fwd: &RouterForwarder,
        face: FaceId,
        message: NetworkMessage,
        reliable: bool,
        priority: Priority,
    ) {
        let outcome = DriverLoopOutcome::FramePayload {
            priority,
            reliable,
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
    fn push_peer_source_routes_within_tier_and_bridges_to_router_as_master() {
        // A peer-sourced Push routes to peer-tier subscribers along the SOURCE's
        // tree (the within-tier data route, C1) AND is bridged to a router-tier
        // subscriber of the SAME keyexpr (the cross-mesh federation bridge, C4).
        // In this single-router topology `shared_nodes = {self}`, so self wins the
        // election and IS the route master, exactly as zenoh `compute_data_route`
        // fires block 1 (router_subs) for a peer source when `master`
        // (pubsub.rs:1291). A non-master router suppresses this bridge — see
        // `push_non_master_suppresses_cross_mesh_bridge`.
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
            1,
            "bridged to the router-tier subscriber (self is master in single-router)"
        );
    }

    #[cfg(feature = "transport-qos")]
    #[test]
    fn route_push_preserves_the_received_band_on_transit() {
        // R311y224 — the router twin of the peer plane's
        // `forward_push_preserves_the_received_band_on_transit`. A RealTime Put from
        // peer source A, driven through the FULL `forward` dispatch, must reach BOTH
        // the within-tier peer subscriber C (`forward_push_tier`) AND the cross-mesh
        // router subscriber R (`bridge_push_cross_mesh` -> `self_publish_into_tier`)
        // still banded RealTime — proving the FramePayload destructure -> route_push
        // band threading across both MESH-directed re-forwards, not just a leaf
        // fan-out. C and R must be QoS-negotiated, else the per-face send clamps every
        // Frame to DEFAULT (`dispatch_push`) and the band cannot be observed.
        use crate::session_glue::{parse_inbound, InboundFrame};
        fn egress_band(frame: &[u8]) -> Priority {
            let InboundFrame::Frame { priority, .. } =
                parse_inbound(frame).expect("parse forwarded frame")
            else {
                panic!("forwarded bytes are not a Frame");
            };
            priority
        }

        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sink_a) = face(zid(0xAA), WIRE_PEER); // peer source
        let (c, sink_c) = face(zid(0xCC), WIRE_PEER); // peer subscriber (within-tier child)
        let (r, sink_r) = face(zid(0xDD), WIRE_ROUTER); // router subscriber (cross-mesh bridge)
        c.set_qos_offer(true);
        r.set_qos_offer(true);
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        fwd.register(FaceId(2), &r);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5); // peer edge self<->A
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5); // peer edge self<->C
        advertise_link_back(&fwd, FaceId(2), 0x01, 0xDD, 5); // router edge self<->R
        fwd.tick(); // compute both nets' spanning trees
        forward_one(&fwd, FaceId(1), declare_sub("demo/data")); // C (peer) subscribes
        forward_one(&fwd, FaceId(2), declare_sub("demo/data")); // R (router) subscribes

        // A RealTime Put from A: preserved on BOTH the within-tier relay to C and the
        // master-gated cross-mesh bridge to R.
        sink_c.reset();
        sink_r.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one_priority(
            &fwd,
            FaceId(0),
            NetworkMessage::Push(Box::new(push)),
            true,
            Priority::RealTime,
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "relayed to the within-tier child C"
        );
        assert_eq!(
            egress_band(&sink_c.frame_bytes(0)),
            Priority::RealTime,
            "within-tier transit PRESERVES the received band — not re-clamped to DEFAULT"
        );
        assert_eq!(
            sink_r.frame_count(),
            1,
            "bridged to the router subscriber R"
        );
        assert_eq!(
            egress_band(&sink_r.frame_bytes(0)),
            Priority::RealTime,
            "cross-mesh bridge PRESERVES the received band — not re-clamped to DEFAULT"
        );

        // Negative control: a DEFAULT transit stays DEFAULT on both legs
        // (byte-identical to the pre-y224 `fan_out_tier` path).
        sink_c.reset();
        sink_r.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one_priority(
            &fwd,
            FaceId(0),
            NetworkMessage::Push(Box::new(push)),
            true,
            Priority::DEFAULT,
        );
        assert_eq!(
            egress_band(&sink_c.frame_bytes(0)),
            Priority::DEFAULT,
            "a DEFAULT within-tier transit stays DEFAULT"
        );
        assert_eq!(
            egress_band(&sink_r.frame_bytes(0)),
            Priority::DEFAULT,
            "a DEFAULT cross-mesh bridge stays DEFAULT"
        );
    }

    /// An `AclPolicy` that DENIES `Put` on `keyexpr` for `flow`, allow-default —
    /// the router twin of the single-net `deny_put_policy`, parameterised on the
    /// flow so a test can gate ingress vs egress.
    #[cfg(feature = "access-acl")]
    fn deny_put_policy(keyexpr: &str, flow: AclFlow) -> AclPolicy {
        AclPolicy::new(AclConfig {
            default_permission: Permission::Allow,
            rules: vec![AclRule {
                subject: SubjectSelector::Any,
                key_exprs: vec![keyexpr.to_owned()],
                messages: vec![AclMessage::Put],
                flow,
                permission: Permission::Deny,
            }],
        })
    }

    /// The within-tier demo topology (peer source A + peer subscriber C, a tree
    /// child of self) with C subscribed to `demo/data` and both sinks reset —
    /// ready for a Put from A that routes A -> self -> C within the peer tier.
    #[cfg(feature = "access-acl")]
    fn peer_source_and_subscriber() -> (
        RouterForwarder,
        Arc<RecordingLinkDriver>,
        Arc<RecordingLinkDriver>,
    ) {
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER); // peer source
        let (c, sink_c) = face(zid(0xCC), WIRE_PEER); // peer subscriber (tree child)
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_sub("demo/data")); // C subscribes
        sink_a.reset();
        sink_c.reset();
        (fwd, sink_a, sink_c)
    }

    #[cfg(feature = "access-acl")]
    #[test]
    fn an_ingress_acl_deny_drops_a_push_before_route() {
        // With self configured to DENY demo/** on INGRESS, a Put from A is dropped
        // at the top of forward(): not counted as received data, not routed to the
        // interested child C, and witnessed. The router twin of the single-net
        // an_acl_deny_drops_an_inbound_put_before_relay.
        let (fwd, _sink_a, sink_c) = peer_source_and_subscriber();
        fwd.set_interceptors(InterceptorConfig {
            acl: Some(deny_put_policy("demo/**", AclFlow::Ingress)),
            ..Default::default()
        });
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push)));
        assert_eq!(fwd.interceptor_dropped(), 1, "the denied Put is witnessed");
        assert_eq!(
            fwd.data_seen(),
            0,
            "a denied ingress Put is not counted as received"
        );
        assert_eq!(
            sink_c.frame_count(),
            0,
            "a denied ingress Put is not routed to C"
        );
    }

    #[cfg(feature = "access-acl")]
    #[test]
    fn an_egress_acl_deny_drops_the_within_tier_relay() {
        // The y113 obligation: with self configured to DENY demo/** on EGRESS, a Put
        // from A is ADMITTED on ingress (counted, routed) but its within-tier relay
        // to the subscriber C is dropped at fan_out_tier's admit_outbound gate and
        // witnessed — the router↔single-net egress parity the fan_out gate closes.
        let (fwd, _sink_a, sink_c) = peer_source_and_subscriber();
        fwd.set_interceptors(InterceptorConfig {
            acl: Some(deny_put_policy("demo/**", AclFlow::Egress)),
            ..Default::default()
        });
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push)));
        assert_eq!(
            fwd.data_seen(),
            1,
            "the Put is admitted on ingress and counted"
        );
        assert_eq!(
            sink_c.frame_count(),
            0,
            "the egress relay to C is dropped by the ACL"
        );
        assert_eq!(
            fwd.interceptor_dropped(),
            1,
            "the dropped egress relay is witnessed"
        );
    }

    #[cfg(feature = "access-acl")]
    #[test]
    fn an_egress_acl_allow_relays_a_non_denied_push() {
        // Selective, not blanket: the EGRESS deny targets a DIFFERENT subtree
        // (admin/**), so the demo/data relay reaches C exactly as without an ACL —
        // proving the gate is a filter, not a block.
        let (fwd, _sink_a, sink_c) = peer_source_and_subscriber();
        fwd.set_interceptors(InterceptorConfig {
            acl: Some(deny_put_policy("admin/**", AclFlow::Egress)),
            ..Default::default()
        });
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push)));
        assert_eq!(fwd.data_seen(), 1, "the Put is counted");
        assert_eq!(sink_c.frame_count(), 1, "a non-denied Put relays to C");
        assert_eq!(fwd.interceptor_dropped(), 0, "nothing dropped");
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
    fn push_router_source_routes_within_tier_and_bridges_to_peer_as_master() {
        // The router-tier twin (C1 within-tier + C4 bridge): a router-sourced Push
        // routes to router-mesh subscribers along the SOURCE's tree AND is bridged
        // to a peer-tier subscriber of the same keyexpr (the router->peer cross-mesh
        // direction). Single-router `shared_nodes = {self}` => self is master, so
        // zenoh block 2 (linkstatepeer_subs) fires for a router source when `master`
        // (pubsub.rs:1307).
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
            1,
            "bridged to the peer-tier subscriber (self is master in single-router)"
        );
    }

    #[test]
    fn elect_router_is_deterministic_max_hash() {
        // The HRW election is a pure, order-INDEPENDENT MAX over the candidate
        // hashes, deterministic across calls (seedless SipHash), with an empty
        // candidate set electing self — a faithful port of zenoh `elect_router`
        // (hat/router/mod.rs:245).
        let s = zid(0x01);
        let a = zid(0x02);
        let b = zid(0x03);
        // Empty candidates -> self (zenoh's `routers.next() == None` arm).
        assert_eq!(elect_router(&s, "demo/x", std::iter::empty::<&Zid>()), s);
        // Order-independent (a real MAX, not first/last seen): {a,b} == {b,a}.
        let ab = elect_router(&s, "demo/x", [a, b].iter());
        let ba = elect_router(&s, "demo/x", [b, a].iter());
        assert_eq!(ab, ba, "HRW is order-independent (picks the max hash)");
        assert!(ab == a || ab == b, "the winner is one of the candidates");
        assert_eq!(
            elect_router(&s, "demo/x", [a, b].iter()),
            ab,
            "deterministic across calls"
        );
        // The keyexpr participates in the hash (the winner is ke-dependent).
        let flips = (0..256)
            .map(|i| format!("demo/k{i}"))
            .any(|k| elect_router(&s, &k, [a, b].iter()) != ab);
        assert!(flips, "the keyexpr participates in the hash");
    }

    #[test]
    fn shared_nodes_is_the_two_mesh_router_intersection() {
        // shared_nodes = the routers present in BOTH meshes (zenoh
        // `network.rs:1197`): self (seeded in both nets) plus a router R2 reachable
        // in the router mesh (a direct router link) AND the peer mesh (a
        // peer-linkstate node behind A). A peer-only node is excluded.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sa) = face(zid(0xAA), WIRE_PEER); // a peer-only node
        let (r, _sr) = face(zid(0x02), WIRE_ROUTER); // R2, the shared router
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &r);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0x02, 5); // R2 -> routers_net
        discover_via(&fwd, FaceId(0), 0x01, 0xAA, 0x02, 7, 5); // R2 -> linkstatepeers_net (behind A)
        fwd.tick();
        let mut shared = fwd.shared_nodes();
        shared.sort();
        assert_eq!(
            shared,
            vec![zid(0x01), zid(0x02)],
            "self + R2 are shared across both meshes"
        );
        assert!(
            !shared.contains(&zid(0xAA)),
            "a peer-only node is NOT in the shared set"
        );
    }

    #[test]
    fn push_bridges_cross_mesh_only_when_master() {
        // C4 federation: a PEER-source Push is bridged into the ROUTER mesh to a
        // router-mesh subscriber ONLY when self is the elected route master. With
        // two routers shared across both meshes (`shared_nodes = {self, R2}`), the
        // HRW election makes self master for some keyexprs and R2 master for others;
        // self bridges only its own, so exactly ONE router bridges (no
        // double-delivery, cross-mesh loop-freedom).
        let self_z = zid(0x01);
        let r2 = zid(0x02);
        let shared = [self_z, r2];
        let ke_master = (0..256)
            .map(|i| format!("demo/m{i}"))
            .find(|k| elect_router(&self_z, k, shared.iter()) == self_z)
            .expect("some ke elects self");
        let ke_other = (0..256)
            .map(|i| format!("demo/o{i}"))
            .find(|k| elect_router(&self_z, k, shared.iter()) == r2)
            .expect("some ke elects R2");

        // Build the federated topology (R2 shared across both meshes, R2 subscribing
        // `ke` on its router face), publish a peer-source Push, and return
        // (router-face hits, shared_nodes len).
        let run = |ke: &str| -> (usize, usize) {
            let fwd = RouterForwarder::new(self_z);
            let (a, _sa) = face(zid(0xAA), WIRE_PEER); // peer publisher + R2 discovery neighbour
            let (r, sink_r) = face(r2, WIRE_ROUTER); // the other router R2 (subscriber)
            fwd.register(FaceId(0), &a);
            fwd.register(FaceId(1), &r);
            advertise_link_back(&fwd, FaceId(1), 0x01, 0x02, 5); // R2 -> routers_net
            discover_via(&fwd, FaceId(0), 0x01, 0xAA, 0x02, 7, 5); // R2 -> linkstatepeers_net
            fwd.tick();
            forward_one(&fwd, FaceId(1), declare_sub(ke)); // R2 subscribes on its router face
            sink_r.reset();
            let push =
                wz_session_core::push_build::build_push_literal(ke, b"payload").expect("push");
            forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push)));
            (sink_r.frame_count(), fwd.shared_nodes().len())
        };

        let (master_hits, shared_len) = run(&ke_master);
        assert_eq!(shared_len, 2, "self + R2 are shared across both meshes");
        assert_eq!(
            master_hits, 1,
            "master bridges the peer-source Push to the router-mesh sub"
        );
        let (other_hits, _) = run(&ke_other);
        assert_eq!(
            other_hits, 0,
            "a non-master suppresses the cross-mesh bridge"
        );
    }

    #[test]
    fn local_client_delivery_deferred_on_non_master() {
        // BLOCKER-2 double-delivery regression (zenoh block-3 gate, pubsub.rs:1323):
        // a client on a NON-master router must NOT be delivered its own peer-source
        // copy — it would ALSO receive the copy the master bridges back as a ROUTER
        // source, i.e. the Push twice. The non-master DEFERS; the router-source
        // (bridged) copy is what actually delivers, exactly once.
        let self_z = zid(0x01);
        let r2 = zid(0x02);
        let shared = [self_z, r2];
        let ke_other = (0..256)
            .map(|i| format!("demo/o{i}"))
            .find(|k| elect_router(&self_z, k, shared.iter()) == r2)
            .expect("some ke elects R2 (self non-master)");

        let fwd = RouterForwarder::new(self_z);
        let (a, _sa) = face(zid(0xAA), WIRE_PEER); // peer publisher + R2 discovery neighbour
        let (r, _sr) = face(r2, WIRE_ROUTER); // the shared router
        let (cb, sink_cb) = face(zid(0xCC), WIRE_CLIENT); // local client subscriber
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &r);
        fwd.register(FaceId(2), &cb);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0x02, 5); // R2 -> routers_net
        discover_via(&fwd, FaceId(0), 0x01, 0xAA, 0x02, 7, 5); // R2 -> linkstatepeers_net
        fwd.tick();
        forward_one(&fwd, FaceId(2), declare_sub(&ke_other)); // Cb subscribes
        assert_eq!(fwd.shared_nodes().len(), 2, "federated: self + R2 shared");
        assert!(
            !fwd.is_master(&ke_other),
            "self is NOT the elected master for this ke"
        );
        sink_cb.reset();

        // The peer-source copy: a non-master DEFERS its local client delivery.
        let p1 = wz_session_core::push_build::build_push_literal(&ke_other, b"x").expect("push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(p1)));
        assert_eq!(
            sink_cb.frame_count(),
            0,
            "non-master defers the peer-source copy (no double delivery)"
        );

        // The router-source (bridged-back) copy: delivered (source == Router ungated).
        let p2 = wz_session_core::push_build::build_push_literal(&ke_other, b"x").expect("push");
        forward_one(&fwd, FaceId(1), NetworkMessage::Push(Box::new(p2)));
        assert_eq!(
            sink_cb.frame_count(),
            1,
            "the bridged router-source copy delivers exactly once"
        );
    }

    #[cfg(feature = "transport-qos")]
    #[test]
    fn deliver_to_client_subscribers_preserves_the_received_band() {
        // R311y225 — the router CLIENT-face egress preserves the received band (the
        // y224 residual): a RealTime mesh Put reaches a QoS-negotiated CLIENT
        // subscriber still banded RealTime, driven through the full `forward` ->
        // route_push dispatch. Single-router => self is master => the block-3 client
        // delivery is unconditional. The client must `set_qos_offer(true)`, else the
        // per-face send clamps every Frame to DEFAULT (`dispatch_push`).
        use crate::session_glue::{parse_inbound, InboundFrame};
        fn egress_band(frame: &[u8]) -> Priority {
            let InboundFrame::Frame { priority, .. } =
                parse_inbound(frame).expect("parse forwarded frame")
            else {
                panic!("forwarded bytes are not a Frame");
            };
            priority
        }

        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sa) = face(zid(0xAA), WIRE_PEER); // the mesh Push source
        let (cb, sink_cb) = face(zid(0xCC), WIRE_CLIENT); // the client subscriber
        cb.set_qos_offer(true);
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &cb);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_sub("demo/**")); // the client subscribes

        // RealTime mesh Put -> the client sub, still RealTime.
        sink_cb.reset();
        forward_one_priority(
            &fwd,
            FaceId(0),
            NetworkMessage::Push(Box::new(
                wz_session_core::push_build::build_push_literal("demo/data", b"payload")
                    .expect("build push"),
            )),
            true,
            Priority::RealTime,
        );
        assert_eq!(sink_cb.frame_count(), 1, "delivered to the client sub");
        assert_eq!(
            egress_band(&sink_cb.frame_bytes(0)),
            Priority::RealTime,
            "router client-face egress PRESERVES the received band — not re-clamped"
        );

        // Negative control: a DEFAULT client egress stays DEFAULT.
        sink_cb.reset();
        forward_one_priority(
            &fwd,
            FaceId(0),
            NetworkMessage::Push(Box::new(
                wz_session_core::push_build::build_push_literal("demo/data", b"payload")
                    .expect("build push"),
            )),
            true,
            Priority::DEFAULT,
        );
        assert_eq!(
            egress_band(&sink_cb.frame_bytes(0)),
            Priority::DEFAULT,
            "a DEFAULT client egress stays DEFAULT"
        );
    }

    #[test]
    fn client_push_router_leg_is_master_gated_peer_leg_ungated() {
        // C4 re-gate of C3b (client->mesh re-injection): a CLIENT-sourced Push's
        // ROUTER-net leg requires `master` (zenoh block 1, pubsub.rs:1291) while its
        // PEER-net leg is UNgated for a non-router source (block 2, :1307). A
        // non-master injects only the peer leg, so the elected master is the sole
        // router-net injector (no double-injection to a router-net sub).
        let self_z = zid(0x01);
        let r2 = zid(0x02);
        let shared = [self_z, r2];
        let ke_other = (0..256)
            .map(|i| format!("demo/o{i}"))
            .find(|k| elect_router(&self_z, k, shared.iter()) == r2)
            .expect("some ke elects R2 (self non-master)");

        let fwd = RouterForwarder::new(self_z);
        let (p, sink_p) = face(zid(0xAA), WIRE_PEER); // peer-net subscriber + R2 discovery neighbour
        let (r, sink_r) = face(r2, WIRE_ROUTER); // router-net subscriber (R2)
        let (cpub, _sc) = face(zid(0xCC), WIRE_CLIENT); // client publisher
        fwd.register(FaceId(0), &p);
        fwd.register(FaceId(1), &r);
        fwd.register(FaceId(2), &cpub);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0x02, 5); // R2 -> routers_net
        discover_via(&fwd, FaceId(0), 0x01, 0xAA, 0x02, 7, 5); // R2 -> linkstatepeers_net
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_sub(&ke_other)); // P subscribes (peer leg target)
        forward_one(&fwd, FaceId(1), declare_sub(&ke_other)); // R2 subscribes (router leg target)
        assert!(!fwd.is_master(&ke_other), "self is NOT master for this ke");
        sink_p.reset();
        sink_r.reset();
        let push = wz_session_core::push_build::build_push_literal(&ke_other, b"z").expect("push");
        forward_one(&fwd, FaceId(2), NetworkMessage::Push(Box::new(push))); // client publishes
        assert_eq!(
            sink_p.frame_count(),
            1,
            "the peer-net leg is ungated for a client source (delivered)"
        );
        assert_eq!(
            sink_r.frame_count(),
            0,
            "the router-net leg is master-gated (a non-master suppresses it)"
        );
    }

    /// R311y197 (I3b slice 3) — the Designated Router FEDERATES a multicast-ingress
    /// Push into the unicast mesh. With an empty member set self is the DR for
    /// every keyexpr, so `route_mcast_ingress` now re-injects the group-ingress
    /// Push into the peer mesh (the ungated peer leg) and the peer-mesh subscriber
    /// receives it. Before I3b `route_push` skipped the client->mesh re-injection
    /// for a mcast-ingress source (the bare `!inbound_is_mcast` gate) and the peer
    /// sub got nothing. (Local client delivery is the separate I1 path,
    /// `mcast_ingress_literal_push_delivers_to_a_client_subscriber`.)
    #[cfg(feature = "router-multicast-faces")]
    #[test]
    fn mcast_ingress_federates_into_mesh_when_dr() {
        let self_z = zid(0x01);
        let fwd = RouterForwarder::new(self_z);
        let (p, sink_p) = face(zid(0xAA), WIRE_PEER); // peer-mesh subscriber + neighbour
        let (r, _sink_r) = face(zid(0x02), WIRE_ROUTER); // router-net node (topology)
        fwd.register(FaceId(0), &p);
        fwd.register(FaceId(1), &r);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0x02, 5);
        discover_via(&fwd, FaceId(0), 0x01, 0xAA, 0x02, 7, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_sub("demo/data")); // P subscribes
        sink_p.reset();
        // Empty member set => self is the DR for every keyexpr => federation ON.
        fwd.set_mcast_group_members(&[]);

        let push =
            wz_session_core::push_build::build_push_literal("demo/data", b"z").expect("push");
        fwd.route_mcast_ingress(Priority::DEFAULT, true, &push);

        assert_eq!(
            sink_p.frame_count(),
            1,
            "the DR federates a mcast-ingress Push into the peer mesh (I3b flip)"
        );
    }

    /// R311y197 (I3b slice 3) — a NON-DR on-group router does NOT federate a
    /// multicast-ingress Push into the mesh (it delivers to LOCAL subs only, the
    /// I1 behavior). With a group member that out-hashes self for the keyexpr, the
    /// OTHER router is the DR; self must not re-inject, or two routers both bridge
    /// the group into the mesh and echo-loop. Same mesh setup as the DR test — the
    /// ONLY difference is the group member set — so the peer sub receiving nothing
    /// isolates the DR gate.
    #[cfg(feature = "router-multicast-faces")]
    #[test]
    fn mcast_ingress_not_federated_when_not_dr() {
        let self_z = zid(0x01);
        let fwd = RouterForwarder::new(self_z);
        let (p, sink_p) = face(zid(0xAA), WIRE_PEER);
        let (r, _sink_r) = face(zid(0x02), WIRE_ROUTER);
        fwd.register(FaceId(0), &p);
        fwd.register(FaceId(1), &r);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0x02, 5);
        discover_via(&fwd, FaceId(0), 0x01, 0xAA, 0x02, 7, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_sub("demo/data"));
        sink_p.reset();
        // A group member (NOT necessarily a mesh node) that beats self in the HRW
        // for this keyexpr => self is NOT the DR => federation SUPPRESSED.
        let winner = (2u8..=255)
            .map(zid)
            .find(|c| elect_router(&self_z, "demo/data", [self_z, *c].iter()) == *c)
            .expect("some zid out-hashes self for the keyexpr");
        fwd.set_mcast_group_members(&[winner.as_slice().to_vec()]);

        let push =
            wz_session_core::push_build::build_push_literal("demo/data", b"z").expect("push");
        fwd.route_mcast_ingress(Priority::DEFAULT, true, &push);

        assert_eq!(
            sink_p.frame_count(),
            0,
            "a non-DR router does NOT federate mcast ingress into the mesh (loop-safety)"
        );
    }

    #[test]
    fn reverse_data_a_foreign_router_client_sub_is_delivered_a_wz_client_push() {
        // Cross-impl REVERSE-data reproduction, wz-side + deterministic: a
        // subscriber behind a FOREIGN router (zenohd) publishes its interest onto
        // wz's router-tier mesh, then a wz LOCAL client publishes that keyexpr — wz
        // must forward the Put out the router face toward zenohd. This is the ②
        // reverse direction (pub@wz -> sub@zenohd), the mirror of the y140-forward
        // leg, and it pins the ENTIRE wz-side path: declaration INGEST + client-pub
        // DELIVERY.
        //
        // Direct-read of zenoh 49c8a53 settles the wire the prior spike could not:
        // zenohd's OWN client sub is sourced at `tables.zid` (declare_simple_ ->
        // register_router_subscription, pubsub.rs:337), whose net index is ALWAYS 0
        // (Network::new adds self FIRST, network.rs:156), and the flood stamps
        // `ext_nodeid = tree_sid.index()` (pubsub.rs:210). So it arrives at wz as a
        // node_id-0 sourced DeclareSubscriber on the router face — the direct
        // neighbour IS the source — NOT a transit non-zero node_id. (psid ==
        // NodeIndex, make_link_state:328, so wz's link `mappings` and zenohd's
        // ext_nodeid share one numbering.) In a pure router-tier topology zenohd is
        // in routers_net ONLY, so `shared_nodes = {self}` and wz elects itself
        // master (is_master true) => the client-push router leg (C3b block 1,
        // publish_client_push_into_meshes) is NOT suppressed. A GREEN here redirects
        // the remaining reverse-data gap OFF the wz side and onto zenohd's egress /
        // wire form; a RED pins a wz bug.
        let fwd = RouterForwarder::new(zid(0x01));
        let (zenohd, sink_zenohd) = face(zid(0xAA), WIRE_ROUTER); // the foreign router
        let (cpub, _sc) = face(zid(0xCC), WIRE_CLIENT); // a wz local client publisher
        fwd.register(FaceId(0), &zenohd);
        fwd.register(FaceId(1), &cpub);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5); // mutual routers_net edge + tree
        fwd.tick();
        // zenohd's own client subscribes -> reaches wz as a node_id-0 sourced
        // declare (zenohd, the direct neighbour, IS the source).
        forward_one(&fwd, FaceId(0), declare_sub("demo/data"));
        assert_eq!(
            fwd.router_subs.borrow().interested("demo/data"),
            vec![zid(0xAA)],
            "the foreign router's client sub registers the peer in router_subs"
        );
        assert!(
            fwd.is_master("demo/data"),
            "pure router-tier topology: shared_nodes = {{self}} => self is master"
        );
        sink_zenohd.reset();
        // A wz local client publishes the keyexpr zenohd subscribed.
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(1), NetworkMessage::Push(Box::new(push)));
        assert_eq!(
            sink_zenohd.frame_count(),
            1,
            "the wz client's Put is forwarded out the router face toward zenohd (reverse data)"
        );
    }

    #[test]
    fn reverse_data_faithful_zenohd_wire_aliased_compound_wildcard_sub() {
        // The EXACT zenohd 49c8a53 wire for a `demo/**` client-sub propagated to a
        // router peer, captured by direct `RUST_LOG=zenoh=trace` on zenohd's
        // egress toward the wz router link:
        //   DeclareKeyExpr   { id: 3, wire_expr: scope:0, suffix:"demo" }   // map 3 -> "demo"
        //   DeclareSubscriber{ id: 0, wire_expr: scope:3, suffix:"/**", node_id:0 }
        // i.e. a COMPOUND aliased keyexpr — a mapped PREFIX ("demo") + a literal
        // suffix ("/**") — sourced at zenohd's self node-index (0). The prior
        // sibling test used a LITERAL exact keyexpr; wz's `aliased_declare_...`
        // test uses a FULL-keyexpr alias with an EMPTY suffix. This is the
        // untested middle: prefix-alias + non-empty-suffix, then a WILDCARD
        // delivery match ("demo/**" sub vs a "demo/key" pub, not the exact-literal
        // match the first test used). This is the faithful reverse-data repro.
        let fwd = RouterForwarder::new(zid(0x01));
        let (zenohd, sink_zenohd) = face(zid(0xAA), WIRE_ROUTER);
        let (cpub, _sc) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &zenohd);
        fwd.register(FaceId(1), &cpub);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        fwd.tick();
        // zenohd maps id 3 -> "demo" on its link, then subscribes "demo" + "/**".
        forward_one(
            &fwd,
            FaceId(0),
            NetworkMessage::Declare(Box::new(
                wz_session_core::declare_build::build_declare_kexpr(3, "demo").expect("kexpr"),
            )),
        );
        forward_one(
            &fwd,
            FaceId(0),
            NetworkMessage::Declare(Box::new(
                build_declare_subscriber(0, 3, Some("/**")).expect("compound aliased sub"),
            )),
        );
        assert_eq!(
            fwd.router_subs.borrow().interested("demo/**"),
            vec![zid(0xAA)],
            "the compound aliased (prefix 'demo' + suffix '/**') sub registers 'demo/**'"
        );
        sink_zenohd.reset();
        // A wz client publishes demo/key — a WILDCARD match vs the demo/** sub.
        let push = wz_session_core::push_build::build_push_literal("demo/key", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(1), NetworkMessage::Push(Box::new(push)));
        assert_eq!(
            sink_zenohd.frame_count(),
            1,
            "the wz client's demo/key Put is forwarded to the demo/** router \
             subscriber (reverse data, wildcard match)"
        );
    }

    /// A CURRENT-mode `Interest` restricted to `keyexpr` (mapping id 0 + literal
    /// suffix), for SUBSCRIBERS and/or QUERYABLES, optionally AGGREGATE — the
    /// write-filter interest a zenoh(-pico) publisher/querier emits. Outer header
    /// `N_MID_INTEREST (0x19) | C (0x20)`; body `SU|QU | R(0x10) | N(0x20) |
    /// M(0x40) | [A(0x80)]`.
    #[allow(clippy::too_many_arguments)]
    fn interest_with_mode(
        interest_id: u64,
        keyexpr: &str,
        current: bool,
        future: bool,
        su: bool,
        qu: bool,
        aggregate: bool,
    ) -> NetworkMessage {
        let outer = 0x19 | (if current { 0x20 } else { 0 }) | (if future { 0x40 } else { 0 });
        let body_header = (if su { 0x02 } else { 0 })
            | (if qu { 0x04 } else { 0 })
            | 0x10
            | 0x20
            | 0x40
            | (if aggregate { 0x80 } else { 0 });
        NetworkMessage::Interest(InterestOwned {
            header: outer,
            interest_id,
            body: Some(wz_codecs::interest_body::InterestBodyOwned {
                header: body_header,
                keyexpr: Some(WireexprOwned {
                    body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                        id: 0,
                        suffix_len: Some(keyexpr.len() as u64),
                        suffix: Some(
                            sce_forge_runtime::codec::SceString::from_view(keyexpr)
                                .expect("interest keyexpr fits the SceString capacity"),
                        ),
                    }),
                }),
            }),
            extensions: None,
        })
    }

    /// The common CURRENT-only interest (C set, F clear).
    fn interest_msg(
        interest_id: u64,
        keyexpr: &str,
        su: bool,
        qu: bool,
        aggregate: bool,
    ) -> NetworkMessage {
        interest_with_mode(interest_id, keyexpr, true, false, su, qu, aggregate)
    }

    /// Decode the FIRST message of a recorded frame as a `DeclareOwned` (the
    /// interest-reply twin of [`forwarded_push`]).
    fn forwarded_declare(frame: &[u8]) -> DeclareOwned {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let InboundFrame::Frame { payload, .. } =
            parse_inbound(frame).expect("parse forwarded frame")
        else {
            panic!("forwarded bytes are not a Frame");
        };
        let msgs = parse_frame_payload(&payload).expect("parse frame payload");
        match msgs.into_iter().next() {
            Some(NetworkMessage::Declare(d)) => *d,
            other => panic!("expected a forwarded Declare, got {other:?}"),
        }
    }

    #[test]
    fn interest_current_subscribers_replies_with_the_matching_sub_then_final() {
        // The reverse-data fix: a pico publisher's CURRENT write-filter interest
        // (SUBSCRIBERS, RESTRICTED demo/key, AGGREGATE) is answered with the
        // matching REMOTE sub wz holds (zenohd's demo/**) + a DeclareFinal, so the
        // publisher's filter deactivates and it puts data on the wire.
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER); // the zenohd analog
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT); // the pico publisher (requester)
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(&fwd, FaceId(0), declare_sub("demo/**")); // zenohd's sub -> router_subs
        assert_eq!(
            fwd.router_subs.borrow().interested("demo/**"),
            vec![zid(0xAA)]
        );
        sink_c.reset();
        forward_one(
            &fwd,
            FaceId(1),
            interest_msg(7, "demo/key", true, false, true),
        );
        assert_eq!(
            sink_c.frame_count(),
            2,
            "one DeclareSubscriber reply + one terminating DeclareFinal"
        );
        // Reply 0: DeclareSubscriber, interest_id echoed, keyed on the INTEREST ke
        // demo/key — NOT the sub's demo/** (INVARIANT: pico matches an aggregate
        // interest's replies by keyexpr EQUALITY, so demo/** would silently fail).
        let reply = forwarded_declare(&sink_c.frame_bytes(0));
        assert_eq!(reply.interest_id, Some(7), "reply echoes the interest id");
        match &reply.body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => match &d.keyexpr.body {
                WireexprOwnedVariant::WireexprLocal(w) => assert_eq!(
                    w.suffix.as_deref(),
                    Some("demo/key"),
                    "aggregate reply is keyed on the interest keyexpr, not demo/**"
                ),
                _ => panic!("reply keyexpr must be literal"),
            },
            other => panic!("expected a DeclSubscriber reply, got {other:?}"),
        }
        // Reply 1: the terminating DeclareFinal, interest_id echoed.
        let fin = forwarded_declare(&sink_c.frame_bytes(1));
        assert_eq!(fin.interest_id, Some(7));
        assert!(matches!(
            fin.body,
            DeclareOwnedVariant::CodecZenohDeclFinal(_)
        ));
    }

    #[test]
    fn future_interest_pushes_a_later_mesh_sub_to_the_client_publisher() {
        // The pub-before-sub close (R311y146): a CLIENT publisher solicits a C+F
        // SUBSCRIBERS interest for demo/key while NO matching sub exists -> an empty
        // current dump, only a DeclareFinal, its write-filter stays armed. A MESH
        // sub for demo/** is learned LATER -> wz PROACTIVELY pushes an UNSOLICITED
        // DeclareSubscriber to the publisher (non-zero id, keyed on the AGGREGATE
        // interest ke, interest_id None) so its filter deactivates. This proves the
        // wz push MECHANISM; the actual filter-deactivation lives in a pico binary
        // (Layer Z, deferred) — a wz face has no write-filter to observe.
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER); // the LATER mesh sub source
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT); // the pico publisher
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        // 1) C+F interest, no matching sub yet -> ONLY a DeclareFinal (stored, not
        //    answered inline).
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(7, "demo/key", true, true, true, false, true),
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "empty current dump -> only the terminating DeclareFinal"
        );
        assert!(matches!(
            forwarded_declare(&sink_c.frame_bytes(0)).body,
            DeclareOwnedVariant::CodecZenohDeclFinal(_)
        ));
        sink_c.reset();
        // 2) A mesh sub for demo/** is learned LATER -> the FUTURE push fires.
        forward_one(&fwd, FaceId(0), declare_sub("demo/**"));
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the later mesh sub is pushed to the waiting client publisher"
        );
        let push = forwarded_declare(&sink_c.frame_bytes(0));
        assert_eq!(
            push.interest_id, None,
            "an unsolicited FUTURE push carries no interest_id / no I flag"
        );
        match &push.body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => {
                assert_ne!(
                    d.id, 0,
                    "a future push carries a non-zero decl id (make_sub_id)"
                );
                match &d.keyexpr.body {
                    WireexprOwnedVariant::WireexprLocal(w) => assert_eq!(
                        w.suffix.as_deref(),
                        Some("demo/key"),
                        "the aggregate push is keyed on the INTEREST ke, not demo/**"
                    ),
                    _ => panic!("push keyexpr must be literal"),
                }
            }
            other => panic!("expected a DeclSubscriber push, got {other:?}"),
        }
        // 3a) A redundant re-declare of the SAME sub does NOT re-push — register's
        //     no-change gate stops it BEFORE the push path (the push never runs).
        sink_c.reset();
        forward_one(&fwd, FaceId(0), declare_sub("demo/**"));
        assert_eq!(
            sink_c.frame_count(),
            0,
            "a redundant re-declare is not re-pushed"
        );
        // 3b) A DISTINCT sub keyexpr (demo/*) that registers as a NEW source but maps
        //     to the SAME aggregate reply ke (demo/key) IS reached by the push path,
        //     yet the pushed-registry dedup suppresses it (the filter is already off).
        forward_one(&fwd, FaceId(0), declare_sub("demo/*"));
        assert_eq!(
            sink_c.frame_count(),
            0,
            "a second distinct sub under the same aggregate ke is deduped by the pushed registry"
        );
    }

    #[test]
    fn future_qabl_interest_pushes_a_later_mesh_qabl_to_the_client_querier() {
        // The querier-before-queryable close (R311y150, the query-plane twin of the
        // pub-before-sub push): a CLIENT querier solicits a C+F QUERYABLES interest
        // for demo/key while NO matching queryable exists -> empty current dump, only
        // a DeclareFinal. A MESH qabl for demo/** (complete) is learned LATER -> wz
        // PROACTIVELY pushes an unsolicited DeclareQueryable (non-zero id, aggregate
        // ke, interest_id None) carrying the FOLDED completeness so an ALL_COMPLETE
        // querier's write-filter deactivates.
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER); // the LATER mesh qabl source
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT); // the pico querier
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(7, "demo/key", true, true, false, true, true),
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "empty current dump -> only the terminating DeclareFinal"
        );
        assert!(matches!(
            forwarded_declare(&sink_c.frame_bytes(0)).body,
            DeclareOwnedVariant::CodecZenohDeclFinal(_)
        ));
        sink_c.reset();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/**", true));
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the later mesh qabl is pushed to the waiting client querier"
        );
        let push = forwarded_declare(&sink_c.frame_bytes(0));
        assert_eq!(
            push.interest_id, None,
            "an unsolicited FUTURE push carries no interest_id / no I flag"
        );
        match &push.body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => {
                assert_ne!(d.id, 0, "a future qabl push carries a non-zero decl id");
                match &d.keyexpr.body {
                    WireexprOwnedVariant::WireexprLocal(w) => assert_eq!(
                        w.suffix.as_deref(),
                        Some("demo/key"),
                        "the aggregate push is keyed on the INTEREST ke, not demo/**"
                    ),
                    _ => panic!("push keyexpr must be literal"),
                }
                assert!(
                    read_queryable_info(d.extensions.as_ref()).complete,
                    "the folded completeness (complete=true) rides the push"
                );
            }
            _ => panic!("expected a DeclareQueryable future push"),
        }
    }

    #[test]
    fn future_qabl_complete_flip_re_pushes_the_same_id() {
        // The value-aware re-push the y146 sub store cannot have (subs carry no
        // value): a mesh qabl arrives INCOMPLETE -> pushed complete=false; the SAME
        // source later re-declares it COMPLETE -> a value-diff re-push carrying the
        // SAME decl id with complete=true (so pico updates the (decl_id, peer)
        // write-filter target in place and a Z_QUERY_TARGET_ALL_COMPLETE querier's
        // filter, which deactivates only on complete=true, is released). A raw
        // single-source push would instead DOWNGRADE and black-hole.
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER);
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(7, "demo/key", true, true, false, true, true),
        );
        sink_c.reset();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/**", false));
        assert_eq!(sink_c.frame_count(), 1, "the incomplete qabl is pushed");
        let first_id = match &forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => {
                assert!(
                    !read_queryable_info(d.extensions.as_ref()).complete,
                    "the first push carries complete=false"
                );
                d.id
            }
            _ => panic!("expected a DeclareQueryable"),
        };
        sink_c.reset();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/**", true));
        assert_eq!(sink_c.frame_count(), 1, "the completeness flip re-pushes");
        match &forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => {
                assert_eq!(
                    d.id, first_id,
                    "the re-push reuses the SAME decl id (pico updates the target in place)"
                );
                assert!(
                    read_queryable_info(d.extensions.as_ref()).complete,
                    "the re-push carries complete=true"
                );
            }
            _ => panic!("expected a DeclareQueryable re-push"),
        }
        sink_c.reset();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/**", true));
        assert_eq!(
            sink_c.frame_count(),
            0,
            "a redundant re-declare (still complete=true) is not re-pushed"
        );
    }

    #[test]
    fn withdrawing_the_last_backing_sub_undeclares_and_lets_a_re_declare_re_push() {
        // R311y151 undeclare-push: after a pub-before-sub push (a mesh sub learned +
        // pushed to the waiting client publisher), WITHDRAWING that mesh sub (its
        // last backer gone) pushes an UndeclareSubscriber carrying the SAME id so the
        // publisher's write-filter RE-ARMS, and clears `pushed` so a later re-declared
        // sub re-pushes (the residual y146/y150 documented).
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER);
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(7, "demo/key", true, true, true, false, true),
        );
        sink_c.reset();
        forward_one(&fwd, FaceId(0), declare_sub("demo/**"));
        assert_eq!(sink_c.frame_count(), 1, "the mesh sub is pushed");
        let pushed_id = match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => d.id,
            _ => panic!("expected a DeclareSubscriber push"),
        };
        assert_ne!(pushed_id, 0);
        sink_c.reset();
        // Withdraw the mesh sub -> UndeclareSubscriber(pushed_id) to the publisher.
        forward_one(&fwd, FaceId(0), undeclare_sub("demo/**"));
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the withdrawal of the last backer undeclares to the waiting publisher"
        );
        match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(u) => assert_eq!(
                u.id, pushed_id,
                "the undeclare carries the pushed decl id (pico keys its filter on it)"
            ),
            _ => panic!("expected an UndeclareSubscriber"),
        }
        sink_c.reset();
        // A re-declared mesh sub RE-pushes (the pushed entry was cleared, not stale).
        forward_one(&fwd, FaceId(0), declare_sub("demo/**"));
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the reappearing sub re-pushes after the undeclare cleared the registry"
        );
        assert!(matches!(
            forwarded_declare(&sink_c.frame_bytes(0)).body,
            DeclareOwnedVariant::CodecZenohDeclSubscriber(_)
        ));
    }

    #[test]
    fn withdrawal_while_another_sub_still_backs_does_not_undeclare() {
        // The aggregate multi-backer case: two mesh subs (demo/a, demo/b) both back
        // the aggregate demo/key push; withdrawing demo/a leaves demo/b backing, so
        // NO undeclare fires (the publisher's filter stays correctly OFF).
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER);
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(7, "demo/key", true, true, true, false, true),
        );
        // BOTH subs INTERSECT the interest target demo/key, so both back the
        // aggregate reply ke (demo/**` matches demo/key; demo/key is exact). The
        // FIRST push happens on demo/**; the second dedups (same aggregate reply ke).
        forward_one(&fwd, FaceId(0), declare_sub("demo/**"));
        sink_c.reset();
        forward_one(&fwd, FaceId(0), declare_sub("demo/key"));
        assert_eq!(
            sink_c.frame_count(),
            0,
            "a second backer under the same aggregate reply ke needs no new push"
        );
        // Withdraw ONE backer -> the reply ke is STILL backed by demo/key -> NO
        // undeclare (the publisher's filter stays correctly OFF).
        forward_one(&fwd, FaceId(0), undeclare_sub("demo/**"));
        assert_eq!(
            sink_c.frame_count(),
            0,
            "demo/key still backs the aggregate reply ke -> no undeclare"
        );
        // Withdraw the LAST backer -> now un-backed -> the undeclare fires.
        forward_one(&fwd, FaceId(0), undeclare_sub("demo/key"));
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the LAST backer's withdrawal undeclares (the filter re-arms)"
        );
        assert!(matches!(
            forwarded_declare(&sink_c.frame_bytes(0)).body,
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(_)
        ));
    }

    #[test]
    fn withdrawing_the_backing_qabl_undeclares_to_the_waiting_querier() {
        // R311y151 query twin: a mesh queryable was pushed to a waiting client
        // querier; withdrawing it (last backer gone) pushes an UndeclareQueryable
        // carrying the SAME id so the querier's write-filter RE-ARMS + clears
        // `pushed`, and a re-declared queryable re-pushes.
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER);
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(7, "demo/key", true, true, false, true, true),
        );
        sink_c.reset();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/**", true));
        assert_eq!(sink_c.frame_count(), 1, "the mesh qabl is pushed");
        let pushed_id = match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => d.id,
            _ => panic!("expected a DeclareQueryable push"),
        };
        assert_ne!(pushed_id, 0);
        sink_c.reset();
        forward_one(&fwd, FaceId(0), undeclare_qabl("demo/**"));
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the withdrawal of the last backing qabl undeclares to the waiting querier"
        );
        match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohUndeclQueryable(u) => {
                assert_eq!(u.id, pushed_id, "the undeclare carries the pushed qabl id")
            }
            _ => panic!("expected an UndeclareQueryable"),
        }
        sink_c.reset();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/**", true));
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the reappearing qabl re-pushes after the undeclare cleared the registry"
        );
        assert!(matches!(
            forwarded_declare(&sink_c.frame_bytes(0)).body,
            DeclareOwnedVariant::CodecZenohDeclQueryable(_)
        ));
    }

    #[test]
    fn native_detach_undeclares_to_the_waiting_publisher() {
        // gap (a) / R311y152: the UNGRACEFUL twin of
        // withdrawing_the_last_backing_sub... . A mesh native that BACKED a
        // co-attached publisher's pushed reply ke goes DOWN (face-down / link-down),
        // so the detach choke point (purge_detached_interest_tier) must fire the
        // undeclare-push exactly as the graceful UndeclareSubscriber path does —
        // zenoh's pubsub_remove_node -> propagate_forget_simple_subscription. Before
        // R311y152 the detach path removed the mesh backing but left the publisher's
        // write-filter OFF forever (the "benign NAMED deferral").
        let fwd = RouterForwarder::new(zid(0x01));
        let (native, _ns) = face(zid(0xBB), WIRE_PEER); // the backing mesh native
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT); // the waiting publisher
        fwd.register(FaceId(0), &native);
        fwd.register(FaceId(1), &client);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(7, "demo/key", true, true, true, false, true),
        );
        sink_c.reset();
        forward_one(&fwd, FaceId(0), declare_sub("demo/**")); // learned -> pushed
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the mesh sub is pushed to the waiting publisher"
        );
        let pushed_id = match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => d.id,
            _ => panic!("expected a DeclareSubscriber push"),
        };
        assert_ne!(pushed_id, 0);
        sink_c.reset();
        fwd.deregister(FaceId(0)); // the backing native's face goes DOWN (ungraceful)
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the detach undeclares to the waiting publisher (the write-filter re-arms)"
        );
        match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(u) => assert_eq!(
                u.id, pushed_id,
                "the detach undeclare carries the pushed decl id (pico keys its filter on it)"
            ),
            _ => panic!("expected an UndeclareSubscriber on detach"),
        }
    }

    #[test]
    fn native_detach_undeclares_to_the_waiting_querier() {
        // gap (a) query twin: the backing mesh queryable's face goes DOWN -> the
        // detach choke point undeclares to the waiting querier (its ALL_COMPLETE
        // filter re-arms), mirroring zenoh queries_remove_node ->
        // propagate_forget_simple_queryable (full un-backing).
        let fwd = RouterForwarder::new(zid(0x01));
        let (native, _ns) = face(zid(0xBB), WIRE_PEER);
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &native);
        fwd.register(FaceId(1), &client);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(7, "demo/key", true, true, false, true, true),
        );
        sink_c.reset();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/**", true));
        assert_eq!(sink_c.frame_count(), 1, "the mesh qabl is pushed");
        let pushed_id = match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => d.id,
            _ => panic!("expected a DeclareQueryable push"),
        };
        sink_c.reset();
        fwd.deregister(FaceId(0));
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the detach undeclares to the waiting querier"
        );
        match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohUndeclQueryable(u) => {
                assert_eq!(
                    u.id, pushed_id,
                    "the detach undeclare carries the pushed qabl id"
                )
            }
            _ => panic!("expected an UndeclareQueryable on detach"),
        }
    }

    #[test]
    fn native_detach_keeps_a_reply_ke_a_client_still_backs() {
        // gap (a) still-backed guard: a mesh native AND a co-attached client both
        // back the publisher's pushed reply ke. The native detaches, but the client
        // sub still backs it -> NO undeclare (the global existence fold any_sub_matches
        // sees the surviving client sub), so the filter correctly stays OFF.
        let fwd = RouterForwarder::new(zid(0x01));
        let (native, _ns) = face(zid(0xBB), WIRE_PEER); // backing mesh native
        let (pubc, sink_p) = face(zid(0xCC), WIRE_CLIENT); // the waiting publisher
        let (subc, _ss) = face(zid(0xDD), WIRE_CLIENT); // a co-attached client subscriber
        fwd.register(FaceId(0), &native);
        fwd.register(FaceId(1), &pubc);
        fwd.register(FaceId(2), &subc);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(7, "demo/key", true, true, true, false, true),
        );
        sink_p.reset(); // clear the empty-dump DeclareFinal
        forward_one(&fwd, FaceId(0), declare_sub("demo/**")); // native backs + pushes
        assert_eq!(
            sink_p.frame_count(),
            1,
            "the mesh sub is pushed to the publisher (guards against a vacuous negative)"
        );
        forward_one(&fwd, FaceId(2), declare_sub("demo/key")); // client also backs (dedups)
        sink_p.reset();
        fwd.deregister(FaceId(0)); // the native detaches, but the client sub remains
        assert_eq!(
            sink_p.frame_count(),
            0,
            "a reply ke still backed by a surviving client sub is NOT undeclared on detach"
        );
    }

    #[test]
    fn remote_oam_detach_undeclares_to_the_waiting_publisher() {
        // gap (a) via the OTHER detach entry point: a topology Oam-ingest detach
        // (changes.removed), not a local face-down. A router-native sub is sourced
        // from a DISTANT router Rd learned via neighbour A; a co-attached client
        // publisher was pushed that sub. When an Oam drops A's link to Rd, Rd
        // detaches and purge_detached_interest_tier(tier, &changes.removed) — the
        // SAME choke point the link-down uses — fires the undeclare-push. Guards
        // that the Oam-ingest call site (which runs inside forward's message loop)
        // holds no self.faces borrow across the undeclare fan_out.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _as) = face(zid(0xAA), WIRE_ROUTER); // router neighbour
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT); // the waiting publisher
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &client);
        discover_via(&fwd, FaceId(0), 0x01, 0xAA, 0xBB, 7, 5); // Rd(0xBB) via A, psid 7
        fwd.tick();
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(7, "demo/key", true, true, true, false, true),
        );
        sink_c.reset(); // clear the empty-dump DeclareFinal
                        // A router-native sub for demo/** sourced from the DISTANT router Rd (node_id 7).
        let mut decl = build_declare_subscriber(0, 0, Some("demo/**")).expect("build");
        set_declare_source(&mut decl, 7);
        forward_one(&fwd, FaceId(0), NetworkMessage::Declare(Box::new(decl)));
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the distant-router sub is pushed to the waiting publisher"
        );
        let pushed_id = match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => d.id,
            _ => panic!("expected a DeclareSubscriber push"),
        };
        sink_c.reset();
        // A now links ONLY to self (drops Rd), higher sn -> Rd unreachable -> the
        // ingest detaches it -> the shared choke point fires the undeclare-push.
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 6);
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the Oam-detach of the distant-router sub undeclares to the waiting publisher"
        );
        match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(u) => {
                assert_eq!(
                    u.id, pushed_id,
                    "the Oam-detach undeclare carries the pushed decl id"
                )
            }
            _ => panic!("expected an UndeclareSubscriber on Oam-detach"),
        }
    }

    #[test]
    fn partial_qabl_withdrawal_downgrades_the_waiting_querier_same_id() {
        // gap (c) / R311y153: two mesh qabls (complete + incomplete) back the aggregate
        // reply demo/key; complete=true is pushed to an ALL_COMPLETE querier. When the
        // complete one WITHDRAWS, demo/key STAYS backed (incomplete) -> NOT an undeclare
        // (forgets_for_withdrawn's any_qabl_matches is true), but a RE-PUSH of the
        // DOWNGRADED complete=false carrying the SAME id, so the querier's ALL_COMPLETE
        // filter re-arms. The client-facing twin of zenoh's register_router_queryable(
        // local_router_qabl_info) partial-removal re-declare (hat/router/queries.rs:930-940).
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER);
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(7, "demo/key", true, true, false, true, true),
        );
        sink_c.reset(); // clear the empty-dump DeclareFinal
        forward_one(&fwd, FaceId(0), declare_qabl("demo/**", true)); // complete backer -> push
        assert_eq!(sink_c.frame_count(), 1, "the complete qabl is pushed");
        let pushed_id = match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => d.id,
            _ => panic!("expected a DeclareQueryable push"),
        };
        assert!(
            forwarded_qabl_info(&sink_c.frame_bytes(0)).complete,
            "pushed complete=true"
        );
        sink_c.reset();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/key", false)); // incomplete co-backer
        assert_eq!(
            sink_c.frame_count(),
            0,
            "folded still complete=true -> dedup, no re-push"
        );
        sink_c.reset();
        forward_one(&fwd, FaceId(0), undeclare_qabl("demo/**")); // the complete backer withdraws
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the DOWNGRADE re-pushes (not an undeclare — demo/key still backs it)"
        );
        match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => {
                assert_eq!(d.id, pushed_id, "same interned id, re-declared in place")
            }
            other => panic!("expected a downgrade DeclareQueryable, got {other:?}"),
        }
        assert!(
            !forwarded_qabl_info(&sink_c.frame_bytes(0)).complete,
            "carries the folded complete=false"
        );
    }

    #[test]
    fn downgrade_re_push_excludes_the_queriers_own_co_hosted_queryable() {
        // gap (c) Q1 exclusion edge (the CRUX the DESIGN panel split on, arbitrated by
        // pico source): the querier F co-hosts its OWN complete queryable AND a REMOTE
        // complete backer exists. The remote withdraws. any_qabl_matches("demo/key") is
        // still TRUE (F's own qabl, no exclusion) so it is NOT undeclared; but the
        // re-fold merged_qabl_info EXCLUDES F's own -> DEFAULT(complete=false) re-push.
        // wz's exclude_face is UNCONDITIONAL (zenoh folds a client dst's own qabl IN,
        // hat/router/queries.rs:175-177); the outcome is still safe because pico tracks
        // the co-hosted queryable as a `local_target` that keeps F's write-filter OFF
        // independent of this re-push (zenoh-pico net/filtering.c). This guards that the
        // re-push flows through the same dest-exclusion as the ingest push (no drift).
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER);
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(7, "demo/key", true, true, false, true, true),
        );
        forward_one(&fwd, FaceId(1), declare_qabl("demo/**", true)); // F co-hosts its OWN complete qabl
        sink_c.reset();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/**", true)); // REMOTE complete backer -> push
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the remote complete qabl is pushed"
        );
        let pushed_id = match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => d.id,
            _ => panic!("expected a DeclareQueryable push"),
        };
        assert!(
            forwarded_qabl_info(&sink_c.frame_bytes(0)).complete,
            "pushed complete=true (F's own qabl is excluded, so the remote's true stands)"
        );
        sink_c.reset();
        forward_one(&fwd, FaceId(0), undeclare_qabl("demo/**")); // the REMOTE backer withdraws
        assert_eq!(
            sink_c.frame_count(),
            1,
            "still backed by F's OWN qabl (not undeclared) -> DOWNGRADE re-push to DEFAULT"
        );
        match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => {
                assert_eq!(d.id, pushed_id, "same interned id")
            }
            other => panic!("expected a downgrade DeclareQueryable, got {other:?}"),
        }
        assert!(
            !forwarded_qabl_info(&sink_c.frame_bytes(0)).complete,
            "F's own co-hosted qabl is EXCLUDED from the re-fold -> complete=false"
        );
    }

    #[test]
    fn native_detach_downgrades_the_waiting_querier() {
        // gap (c) via the DETACH path (not graceful undeclare): the detach choke point
        // purge_detached_interest_tier -> undeclare_push_qabls must ALSO fire the
        // downgrade re-push. A complete mesh qabl (0xBB) + an incomplete client co-backer
        // both back the aggregate reply demo/key; complete=true is pushed to the querier.
        // 0xBB's face goes DOWN -> demo/key stays backed (client incomplete) -> DOWNGRADE
        // re-push complete=false, same id.
        let fwd = RouterForwarder::new(zid(0x01));
        let (native, _ns) = face(zid(0xBB), WIRE_PEER); // complete backer, detaches
        let (querier, sink_q) = face(zid(0xCC), WIRE_CLIENT); // the ALL_COMPLETE querier
        let (cobacker, _cs) = face(zid(0xDD), WIRE_CLIENT); // incomplete co-backer, survives
        fwd.register(FaceId(0), &native);
        fwd.register(FaceId(1), &querier);
        fwd.register(FaceId(2), &cobacker);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(7, "demo/key", true, true, false, true, true),
        );
        forward_one(&fwd, FaceId(2), declare_qabl("demo/key", false)); // client incomplete co-backer
        sink_q.reset();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/**", true)); // mesh complete -> re-push true
        assert_eq!(sink_q.frame_count(), 1, "the complete fold is pushed");
        let pushed_id = match forwarded_declare(&sink_q.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => d.id,
            _ => panic!("expected a DeclareQueryable push"),
        };
        assert!(forwarded_qabl_info(&sink_q.frame_bytes(0)).complete);
        sink_q.reset();
        fwd.deregister(FaceId(0)); // the complete mesh backer's face goes DOWN (detach)
        assert_eq!(
            sink_q.frame_count(),
            1,
            "the DETACH downgrades (client co-backer still backs demo/key)"
        );
        match forwarded_declare(&sink_q.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => {
                assert_eq!(d.id, pushed_id, "same id, re-declared in place on detach")
            }
            other => panic!("expected a downgrade DeclareQueryable on detach, got {other:?}"),
        }
        assert!(
            !forwarded_qabl_info(&sink_q.frame_bytes(0)).complete,
            "the detach re-push carries complete=false"
        );
    }

    #[test]
    fn seeded_qabl_downgrades_on_partial_withdrawal_same_id() {
        // gap (c) F3 (test-rigor coverage): the qabl EXISTS at interest time, so the
        // CURRENT-dump SEED (dump_interest_qabls -> intern_current_reply) sets `pushed`,
        // NOT a future push. A later partial withdrawal must downgrade the SEEDED id —
        // pinning that the current-dump seed fold and the re-push fold (both
        // merged_qabl_info) AGREE (no drift; the F3 the IMPL panel flagged).
        let fwd = RouterForwarder::new(zid(0x01));
        let (native, _ns) = face(zid(0xAA), WIRE_ROUTER);
        let (querier, sink_q) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &native);
        fwd.register(FaceId(1), &querier);
        // Both qabls exist BEFORE the interest (folded aggregate = complete=true).
        forward_one(&fwd, FaceId(0), declare_qabl("demo/**", true)); // complete
        forward_one(&fwd, FaceId(0), declare_qabl("demo/key", false)); // incomplete co-backer
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(7, "demo/key", true, true, false, true, true),
        );
        // The current dump: one aggregate DeclareQueryable(complete=true) + a DeclareFinal.
        assert_eq!(sink_q.frame_count(), 2, "current dump reply + DeclareFinal");
        let seeded_id = match forwarded_declare(&sink_q.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => d.id,
            other => panic!("expected the seeded DeclareQueryable first, got {other:?}"),
        };
        assert!(
            forwarded_qabl_info(&sink_q.frame_bytes(0)).complete,
            "the current-dump seed folds to complete=true"
        );
        sink_q.reset();
        forward_one(&fwd, FaceId(0), undeclare_qabl("demo/**")); // the complete backer withdraws
        assert_eq!(
            sink_q.frame_count(),
            1,
            "the SEEDED id downgrades on the partial withdrawal"
        );
        match forwarded_declare(&sink_q.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => assert_eq!(
                d.id, seeded_id,
                "the downgrade reuses the SEEDED id — seed and re-push folds agree"
            ),
            other => panic!("expected a downgrade DeclareQueryable, got {other:?}"),
        }
        assert!(
            !forwarded_qabl_info(&sink_q.frame_bytes(0)).complete,
            "downgraded to complete=false"
        );
    }

    #[test]
    fn future_interest_final_stops_further_pushes() {
        // pico sends an Interest(Final) when a publisher drops (net/primitives.c
        // _z_remove_interest, client-gated); wz must FORGET the stored FUTURE
        // interest so a later sub is no longer pushed to a gone publisher.
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER);
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        // Store the future interest, then CANCEL it with an Interest(Final)
        // (C=0,F=0) carrying the same interest_id.
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(7, "demo/key", true, true, true, false, true),
        );
        sink_c.reset();
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(7, "demo/key", false, false, false, false, false),
        );
        assert_eq!(
            sink_c.frame_count(),
            0,
            "an Interest(Final) gets no wire reply"
        );
        // A later matching mesh sub must NOT be pushed — the interest is gone.
        forward_one(&fwd, FaceId(0), declare_sub("demo/**"));
        assert_eq!(
            sink_c.frame_count(),
            0,
            "no push after the future interest was torn down"
        );
    }

    #[test]
    fn future_interest_pushes_a_later_client_sub_to_another_client() {
        // Client-to-client via the router (the client-ingest push site): publisher A
        // declares a C+F interest; a SECOND client B declares a matching subscriber
        // -> A is pushed. A subscriber declared by the interest HOLDER itself is NOT
        // echoed back to it (the only non-moot origin-skip case).
        let fwd = RouterForwarder::new(zid(0x01));
        let (pub_a, sink_a) = face(zid(0xAA), WIRE_CLIENT); // publisher A = interest holder
        let (sub_b, _sb) = face(zid(0xBB), WIRE_CLIENT); // subscriber B
        fwd.register(FaceId(0), &pub_a);
        fwd.register(FaceId(1), &sub_b);
        forward_one(
            &fwd,
            FaceId(0),
            interest_with_mode(7, "demo/key", true, true, true, false, true),
        );
        assert_eq!(sink_a.frame_count(), 1, "empty dump -> only a DeclareFinal");
        sink_a.reset();
        // B (a client) declares a matching subscriber -> A is pushed.
        forward_one(&fwd, FaceId(1), declare_sub("demo/**"));
        assert_eq!(
            sink_a.frame_count(),
            1,
            "the later client-B sub is pushed to publisher A"
        );
        let push = forwarded_declare(&sink_a.frame_bytes(0));
        assert_eq!(push.interest_id, None);
        match &push.body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => {
                assert_ne!(d.id, 0, "the push carries a non-zero decl id")
            }
            other => panic!("expected a DeclSubscriber push, got {other:?}"),
        }
        // The interest holder A subscribing its OWN matching keyexpr is NOT echoed
        // back to A (origin-skip).
        sink_a.reset();
        forward_one(&fwd, FaceId(0), declare_sub("demo/*"));
        assert_eq!(
            sink_a.frame_count(),
            0,
            "a sub from the interest holder is not echoed back to it"
        );
    }

    #[test]
    fn future_interest_current_dump_seeds_a_non_zero_id_and_dedups_the_later_push() {
        // When a matching sub EXISTS at C+F interest time, the current-dump reply
        // carries a NON-ZERO interned id (make_sub_id semantics) AND seeds the pushed
        // registry so a later re-learn of the same aggregate ke does not
        // double-declare. This is the only test that exercises
        // build_declare_subscriber_reply_with_id + the seed->dedup path E2E.
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER);
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(&fwd, FaceId(0), declare_sub("demo/**")); // a sub EXISTS at interest time
        sink_c.reset();
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(7, "demo/key", true, true, true, false, true),
        );
        assert_eq!(
            sink_c.frame_count(),
            2,
            "one DeclareSubscriber reply + the DeclareFinal"
        );
        let reply = forwarded_declare(&sink_c.frame_bytes(0));
        assert_eq!(
            reply.interest_id,
            Some(7),
            "a current reply is interest-stamped"
        );
        match &reply.body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => assert_ne!(
                d.id, 0,
                "a C+F (future) current reply carries a non-zero interned id, not 0"
            ),
            other => panic!("expected a DeclSubscriber reply, got {other:?}"),
        }
        // A re-learn of the SAME aggregate reply ke (via a distinct sub) is deduped
        // by the seed -> no second declare.
        sink_c.reset();
        forward_one(&fwd, FaceId(0), declare_sub("demo/*"));
        assert_eq!(
            sink_c.frame_count(),
            0,
            "the current-dump seed dedups the later matching push"
        );
    }

    #[test]
    fn deregister_purges_the_future_interest() {
        // A client face going down purges its stored future interest (OBLIGATION 1),
        // so a later matching sub is neither pushed nor a panic on a gone face.
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER);
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(7, "demo/key", true, true, true, false, true),
        );
        fwd.deregister(FaceId(1)); // the publisher's face drops
        sink_c.reset();
        forward_one(&fwd, FaceId(0), declare_sub("demo/**"));
        assert_eq!(
            sink_c.frame_count(),
            0,
            "a purged (face-down) interest holder is not pushed to"
        );
    }

    #[test]
    fn interest_with_no_matching_sub_replies_only_a_final() {
        // A CURRENT interest whose keyexpr no sub matches: wz still terminates it
        // with a DeclareFinal (0 subs => the filter stays active = "no subscriber
        // yet", correct) — but dumps nothing.
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER);
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(&fwd, FaceId(0), declare_sub("demo/**"));
        sink_c.reset();
        forward_one(
            &fwd,
            FaceId(1),
            interest_msg(3, "other/key", true, false, true),
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "no matching sub -> only the terminating DeclareFinal"
        );
        let fin = forwarded_declare(&sink_c.frame_bytes(0));
        assert_eq!(fin.interest_id, Some(3));
        assert!(matches!(
            fin.body,
            DeclareOwnedVariant::CodecZenohDeclFinal(_)
        ));
    }

    #[test]
    fn interest_excludes_the_requesting_faces_own_client_sub() {
        // A client that both subscribes AND publishes: its own sub must NOT be
        // echoed back as a matching remote sub (zenoh's face.id exclusion).
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &client);
        forward_one(&fwd, FaceId(0), declare_sub("demo/**")); // the requester's OWN sub (client tier)
        sink_c.reset();
        forward_one(
            &fwd,
            FaceId(0),
            interest_msg(5, "demo/key", true, false, true),
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the requester's own sub is excluded -> only the DeclareFinal"
        );
        assert!(matches!(
            forwarded_declare(&sink_c.frame_bytes(0)).body,
            DeclareOwnedVariant::CodecZenohDeclFinal(_)
        ));
    }

    #[test]
    fn interest_non_aggregate_replies_per_matching_sub_keyexpr() {
        // A non-AGGREGATE interest: one reply per matching sub, keyed on the sub's
        // OWN keyexpr (demo/**), not the interest ke.
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER);
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(&fwd, FaceId(0), declare_sub("demo/**"));
        sink_c.reset();
        forward_one(
            &fwd,
            FaceId(1),
            interest_msg(9, "demo/key", true, false, false),
        );
        assert_eq!(
            sink_c.frame_count(),
            2,
            "one per-sub reply + the DeclareFinal"
        );
        match &forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => match &d.keyexpr.body {
                WireexprOwnedVariant::WireexprLocal(w) => assert_eq!(
                    w.suffix.as_deref(),
                    Some("demo/**"),
                    "non-aggregate reply is keyed on the sub's own keyexpr"
                ),
                _ => panic!("literal keyexpr expected"),
            },
            other => panic!("expected a DeclSubscriber reply, got {other:?}"),
        }
    }

    #[test]
    fn interest_queryables_reply_carries_the_merged_complete_bit() {
        // The query-plane twin: a QUERYABLES interest is answered with a
        // DeclareQueryable carrying the merged completeness (a complete queryable
        // -> reply complete=true, which a Z_QUERY_TARGET_ALL_COMPLETE querier's
        // filter requires).
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER);
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(&fwd, FaceId(0), declare_qabl("demo/**", true)); // a COMPLETE queryable
        sink_c.reset();
        forward_one(
            &fwd,
            FaceId(1),
            interest_msg(4, "demo/key", false, true, true),
        );
        assert_eq!(
            sink_c.frame_count(),
            2,
            "one DeclareQueryable reply + one DeclareFinal"
        );
        assert_eq!(
            forwarded_declare(&sink_c.frame_bytes(0)).interest_id,
            Some(4)
        );
        // Decode the QueryableInfo off the ext chain and assert complete == true,
        // NOT merely `extensions.is_some()`: a Z_QUERY_TARGET_ALL_COMPLETE querier's
        // write-filter deactivates only on complete=true, and once distance
        // handling grows a non-zero value an `is_some()`-only check would pass on a
        // `complete=false` reply (a silent write-filter regression).
        assert_eq!(
            forwarded_qabl_info(&sink_c.frame_bytes(0)),
            QueryableInfo {
                complete: true,
                distance: 0
            },
            "the reply carries the complete=true bit on the wire"
        );
    }

    #[test]
    fn interest_queryables_aggregate_reply_merges_completeness_across_sources() {
        // The MERGE path (the round's headline): TWO sources for the SAME keyexpr,
        // one incomplete + one complete, fold to complete=true in the aggregate
        // reply (zenoh's local_qabl_info OR). The prior test has a single source,
        // so it cannot exercise the fold.
        let fwd = RouterForwarder::new(zid(0x01));
        let (ra, _sa) = face(zid(0xAA), WIRE_ROUTER);
        let (rb, _sb) = face(zid(0xEE), WIRE_ROUTER);
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &ra);
        fwd.register(FaceId(1), &rb);
        fwd.register(FaceId(2), &client);
        forward_one(&fwd, FaceId(0), declare_qabl("demo/**", false)); // source A: incomplete
        forward_one(&fwd, FaceId(1), declare_qabl("demo/**", true)); // source B: complete
        sink_c.reset();
        forward_one(
            &fwd,
            FaceId(2),
            interest_msg(6, "demo/key", false, true, true),
        );
        assert_eq!(
            sink_c.frame_count(),
            2,
            "one MERGED DeclareQueryable reply + one DeclareFinal"
        );
        assert!(
            forwarded_qabl_info(&sink_c.frame_bytes(0)).complete,
            "the aggregate reply folds complete=false||true -> true across the two \
             sources"
        );
    }

    #[test]
    fn interest_future_only_and_final_get_no_reply() {
        // A pure-Future (C=0,F=1) and a body-less Final (C=0,F=0) interest each emit
        // ZERO immediate reply frames (no current dump, no Final). Since R311y146 a
        // future-only interest is STORED for a later push and a Final TEARS DOWN a
        // stored interest — both without a wire reply; this test locks that
        // no-immediate-reply property.
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER);
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(&fwd, FaceId(0), declare_sub("demo/**"));
        sink_c.reset();
        // Pure-Future interest (F set, C clear) — no CURRENT dump, no reply.
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(1, "demo/key", false, true, true, false, true),
        );
        assert_eq!(
            sink_c.frame_count(),
            0,
            "a pure-Future interest gets no immediate CURRENT reply (it is stored)"
        );
        // Body-less Final interest (C=0, F=0).
        forward_one(
            &fwd,
            FaceId(1),
            NetworkMessage::Interest(InterestOwned {
                header: 0x19, // N_MID_INTEREST, no C/F
                interest_id: 2,
                body: None,
                extensions: None,
            }),
        );
        assert_eq!(
            sink_c.frame_count(),
            0,
            "a body-less Final interest gets no reply"
        );
    }

    #[test]
    fn interest_with_no_entity_options_replies_only_a_final() {
        // A CURRENT interest targeting neither SUBSCRIBERS nor QUERYABLES (e.g.
        // KEYEXPRS-only): no dump, just the terminating DeclareFinal.
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER);
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(&fwd, FaceId(0), declare_sub("demo/**"));
        sink_c.reset();
        forward_one(
            &fwd,
            FaceId(1),
            interest_msg(8, "demo/key", false, false, true),
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "no S/Q options -> only the terminating DeclareFinal"
        );
        assert!(matches!(
            forwarded_declare(&sink_c.frame_bytes(0)).body,
            DeclareOwnedVariant::CodecZenohDeclFinal(_)
        ));
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
    fn a_peer_sourced_push_delivered_to_a_client_subscriber_carries_source_zero() {
        // Regression guard for the Push-plane client-delivery fidelity fix (the router
        // twin of the linkstate guard + the R311y179 forward_request_to_clients
        // source-reset): a Push delivered to a co-attached CLIENT subscriber must carry
        // routing source 0 -- a client is a LEAF, not a graph node. reliteralize_push
        // PRESERVES the inbound push's ext_nodeid; a Peer/Router-source (or bridged
        // master) Push carries a NON-ZERO source that a real client (a pico z_sub)
        // rejects by CLOSING its transport (its Push decoder mandatory-rejects the
        // ext_nodeid id 0x03). Pre-fix the client carrier leaked the source verbatim.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sa) = face(zid(0xAA), WIRE_PEER); // source peer
        let (client, sink_client) = face(zid(0xDD), WIRE_CLIENT); // client subscriber
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5); // psid 5 = peer A
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_sub("demo/**")); // client subscribes
        sink_client.reset();
        let mut push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        wz_session_core::push_routing_context::set_push_source(&mut push, 5); // NON-ZERO peer source
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push)));
        assert_eq!(
            sink_client.frame_count(),
            1,
            "the client subscriber received the peer-sourced push"
        );
        assert_eq!(
            wz_session_core::push_routing_context::read_push_source(&forwarded_push(
                &sink_client.frame_bytes(0)
            )),
            0,
            "the Push delivered to a CLIENT subscriber must carry routing source 0 (a \
             client is not a graph node); leaking the non-zero source closes a real \
             pico client's transport"
        );
    }

    /// Decode the first forwarded `Push` in a recorded wire frame (the C3b twin
    /// of the linkstate `forwarded_hoplimit`), so a test can assert the
    /// re-injected carrier's self-source node_id + hop budget landed ON THE WIRE.
    fn forwarded_push(frame: &[u8]) -> PushOwned {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let InboundFrame::Frame { payload, .. } =
            parse_inbound(frame).expect("parse forwarded frame")
        else {
            panic!("forwarded bytes are not a Frame");
        };
        let msgs = parse_frame_payload(&payload).expect("parse frame payload");
        match msgs.first() {
            Some(NetworkMessage::Push(p)) => (**p).clone(),
            other => panic!("expected a forwarded Push, got {other:?}"),
        }
    }

    #[test]
    fn a_client_push_reaches_a_subscribing_mesh_peer() {
        // C3b: a CLIENT publishes K; a peer-mesh subscriber of K receives it via
        // the self-sourced re-injection (the client->peer direction, blackholed
        // pre-C3b -- forward_push_tier no-ops for a Client inbound).
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, _sc) = face(zid(0xAA), WIRE_CLIENT); // publishing client
        let (peer_sub, sink_peer) = face(zid(0xBB), WIRE_PEER); // peer subscriber (tree child)
        fwd.register(FaceId(0), &client);
        fwd.register(FaceId(1), &peer_sub);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_sub("demo/data")); // peer subscribes (mesh)
        sink_peer.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push))); // client publishes
        assert_eq!(
            sink_peer.frame_count(),
            1,
            "the peer-mesh subscriber received the client's re-injected Push (C3b)"
        );
    }

    #[test]
    fn a_client_push_is_re_injected_self_sourced_with_a_fresh_hop_budget() {
        // The re-injected carrier is SELF-sourced (node_id 0, ext removed) and
        // carries a FRESH hop budget = the tier net's node_count (self + peer = 2)
        // -- the `publish` shape, NOT a transit re-forward. Proven ON THE WIRE.
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, _sc) = face(zid(0xAA), WIRE_CLIENT);
        let (peer_sub, sink_peer) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &client);
        fwd.register(FaceId(1), &peer_sub);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_sub("demo/data"));
        sink_peer.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push)));
        let p = forwarded_push(&sink_peer.frame_bytes(0));
        assert_eq!(
            read_push_source(&p),
            0,
            "self-sourced: node_id 0 (the ext is removed, zenoh omit-on-DEFAULT)"
        );
        assert_eq!(
            read_push_hoplimit(&p),
            Some(2),
            "fresh hop budget = linkstatepeers_net node_count (self + the peer)"
        );
    }

    #[test]
    fn a_client_push_reaches_a_mesh_peer_and_another_client_but_not_the_publisher() {
        // C3b (mesh) + C3a (client) COMPOSE for a CLIENT source, disjoint fan: the
        // peer via publish_client_push_into_meshes, client c2 via
        // deliver_to_client_subscribers, and c1 (the source) excluded from BOTH --
        // no echo to the publisher.
        let fwd = RouterForwarder::new(zid(0x01));
        let (c1, sink_c1) = face(zid(0xAA), WIRE_CLIENT); // publishing client
        let (c2, sink_c2) = face(zid(0xCC), WIRE_CLIENT); // client subscriber
        let (peer_sub, sink_peer) = face(zid(0xBB), WIRE_PEER); // peer subscriber
        fwd.register(FaceId(0), &c1);
        fwd.register(FaceId(1), &c2);
        fwd.register(FaceId(2), &peer_sub);
        advertise_link_back(&fwd, FaceId(2), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_sub("demo/data")); // c2 subscribes (client)
        forward_one(&fwd, FaceId(2), declare_sub("demo/data")); // peer subscribes (mesh)
        sink_c1.reset();
        sink_c2.reset();
        sink_peer.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push))); // c1 publishes
        assert_eq!(sink_peer.frame_count(), 1, "the mesh peer got it (C3b)");
        assert_eq!(sink_c2.frame_count(), 1, "the other client got it (C3a)");
        assert_eq!(
            sink_c1.frame_count(),
            0,
            "the publishing client is NOT echoed its own Push"
        );
    }

    #[test]
    fn a_client_push_with_no_mesh_subscriber_is_not_re_injected() {
        // interested_remote empty on both meshes -> compute_self_publish_forward
        // returns None -> nothing floods (mirrors publish's Ok(0)).
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, _sc) = face(zid(0xAA), WIRE_CLIENT);
        let (peer, sink_peer) = face(zid(0xBB), WIRE_PEER); // a peer, NOT subscribing
        fwd.register(FaceId(0), &client);
        fwd.register(FaceId(1), &peer);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        sink_peer.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push)));
        assert_eq!(
            sink_peer.frame_count(),
            0,
            "no mesh subscriber -> the client Push is not re-injected into the mesh"
        );
    }

    #[test]
    fn a_wildcard_mesh_peer_sub_receives_a_client_concrete_push() {
        // C3b's mesh injection is wildcard-aware via the interested_remote SSOT
        // (the same match the mesh data route uses): a peer subscribing `demo/**`
        // receives a CLIENT's `demo/data` push, not just an exact `demo/data` sub.
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, _sc) = face(zid(0xAA), WIRE_CLIENT);
        let (peer_sub, sink_peer) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &client);
        fwd.register(FaceId(1), &peer_sub);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_sub("demo/**")); // wildcard mesh sub
        sink_peer.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push)));
        assert_eq!(
            sink_peer.frame_count(),
            1,
            "the wildcard mesh peer sub received the intersecting concrete client Push"
        );
    }

    #[test]
    fn a_client_push_reaches_subscribers_on_both_meshes() {
        // C3b floods BOTH nets: a directly-attached subscribing ROUTER (routers_net
        // leg) AND a subscribing PEER (linkstatepeers_net leg) both receive a
        // CLIENT's push, while a non-subscribing router gets nothing. The only test
        // that drives the Routers leg to a NON-empty result (single-master,
        // shared_nodes <= 1) -- a wrong subs_table/net in the Routers iteration
        // would slip past every peer-only C3b test. (router_subs is NOT empty here:
        // a directly-attached subscribing router populates it.)
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, _sc) = face(zid(0xAA), WIRE_CLIENT); // publishing client
        let (peer_sub, sink_peer) = face(zid(0xCC), WIRE_PEER); // peer subscriber
        let (router_sub, sink_router) = face(zid(0xDD), WIRE_ROUTER); // router subscriber
        let (router_bare, sink_bare) = face(zid(0xEE), WIRE_ROUTER); // NON-subscribing router
        fwd.register(FaceId(0), &client);
        fwd.register(FaceId(1), &peer_sub);
        fwd.register(FaceId(2), &router_sub);
        fwd.register(FaceId(3), &router_bare);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5); // peer edge self<->CC
        advertise_link_back(&fwd, FaceId(2), 0x01, 0xDD, 5); // router edge self<->DD
        advertise_link_back(&fwd, FaceId(3), 0x01, 0xEE, 5); // router edge self<->EE
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_sub("demo/data")); // peer subscribes (peers_net)
        forward_one(&fwd, FaceId(2), declare_sub("demo/data")); // router subscribes (routers_net)
        sink_peer.reset();
        sink_router.reset();
        sink_bare.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push))); // client publishes
        assert_eq!(
            sink_peer.frame_count(),
            1,
            "the peers_net leg delivered to the subscribing peer"
        );
        assert_eq!(
            sink_router.frame_count(),
            1,
            "the routers_net leg delivered to the directly-attached subscribing router"
        );
        assert_eq!(
            sink_bare.frame_count(),
            0,
            "the non-subscribing router got nothing (route filtered by interest)"
        );
    }

    #[test]
    fn a_client_push_relays_to_a_distant_mesh_subscriber_via_an_intermediate() {
        // The self-source route to a 2-HOP subscriber flows to the INTERMEDIATE
        // tree child, not the destination directly: directions_toward(self,
        // {distant}) returns the neighbour. Exercises the relay class no 1-hop fan
        // covers -- the router's wiring of directions_toward into the mesh fan.
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, _sc) = face(zid(0xAA), WIRE_CLIENT); // publishing client
        let (peer, sink_peer) = face(zid(0xBB), WIRE_PEER); // the INTERMEDIATE neighbour
        fwd.register(FaceId(0), &client);
        fwd.register(FaceId(1), &peer);
        // Discover a distant node 0xDD reachable self <-> 0xBB <-> 0xDD (psid 7 =
        // 0xDD on the peer link); the flood also carries 0xBB -> self, so the tree
        // computes without a separate advertise_link_back.
        discover_via(&fwd, FaceId(1), 0x01, 0xBB, 0xDD, 7, 5);
        fwd.tick();
        // The distant node 0xDD subscribes demo/data (a sourced DeclareSubscriber
        // whose node_id 7 resolves via the inbound link's psid map to 0xDD).
        let mut decl = build_declare_subscriber(0, 0, Some("demo/data")).expect("build");
        set_declare_source(&mut decl, 7);
        forward_one(&fwd, FaceId(1), NetworkMessage::Declare(Box::new(decl)));
        assert_eq!(
            fwd.linkstatepeer_subs.borrow().interested("demo/data"),
            vec![zid(0xDD)],
            "the distant node 0xDD's interest is registered (2 hops away)"
        );
        sink_peer.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push))); // client publishes
        assert_eq!(
            sink_peer.frame_count(),
            1,
            "relayed to the INTERMEDIATE peer 0xBB (0xDD has no local face) -- \
             directions_toward returned the neighbour, not the destination"
        );
    }

    #[test]
    fn a_best_effort_client_push_is_re_injected_best_effort() {
        // C3b threads the INBOUND frame's `reliable` into the mesh fan (unlike
        // publish's hard-coded reliable): a best-effort client Push re-injects
        // best-effort. The one behaviour where C3b diverges from `publish`.
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, _sc) = face(zid(0xAA), WIRE_CLIENT);
        let (peer_sub, sink_peer) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &client);
        fwd.register(FaceId(1), &peer_sub);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_sub("demo/data"));
        sink_peer.reset();
        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        // Drive the client Push on the BEST-EFFORT channel.
        forward_one_reliability(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push)), false);
        assert_eq!(sink_peer.frame_count(), 1, "delivered to the mesh peer");
        assert_eq!(
            sink_peer.frame_reliability(0),
            crate::Reliability::BestEffort,
            "the re-injected Push carries the inbound best-effort channel, not a \
             hard-coded reliable"
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
    fn router_native_sub_advertises_into_the_peer_mesh() {
        // FEDERATION (R311y125): a ROUTER-native sub makes self ADVERTISE that
        // keyexpr into the PEER mesh (a self-sourced DeclareSubscriber to a peer
        // tree child), so a peer publisher routes toward self (which bridges
        // cross-tier, C4). The within-tier router reflood has no router child, so
        // only the cross-tier advertise reaches the peer child. Derive-not-store:
        // self is NOT registered in the peer subs table.
        let fwd = RouterForwarder::new(zid(0x01));
        let (r, _rs) = face(zid(0xAA), WIRE_ROUTER); // the router-native source
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER); // a peer tree child
        fwd.register(FaceId(0), &r);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5); // self<->P peer edge
        fwd.tick();
        sink_p.reset();
        forward_one(&fwd, FaceId(0), declare_sub("demo/data")); // router-native sub
        assert_eq!(
            sink_p.frame_count(),
            1,
            "a router-native sub advertised self's cross-tier interest to the peer mesh"
        );
        assert!(
            fwd.linkstatepeer_subs
                .borrow()
                .interested("demo/data")
                .is_empty(),
            "derive-not-store: self is NOT stored in the peer subs table"
        );
    }

    #[test]
    fn peer_native_sub_advertises_into_the_router_mesh() {
        // The mirror direction: a PEER-native sub advertises into the ROUTER mesh
        // (a router tree child observes the self-sourced DeclareSubscriber).
        let fwd = RouterForwarder::new(zid(0x01));
        let (pn, _ps) = face(zid(0xBB), WIRE_PEER); // the peer-native source
        let (rc, sink_rc) = face(zid(0xCC), WIRE_ROUTER); // a router tree child
        fwd.register(FaceId(0), &pn);
        fwd.register(FaceId(1), &rc);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5); // self<->Rc router edge
        fwd.tick();
        sink_rc.reset();
        forward_one(&fwd, FaceId(0), declare_sub("demo/data")); // peer-native sub
        assert_eq!(
            sink_rc.frame_count(),
            1,
            "a peer-native sub advertised self's cross-tier interest to the router mesh"
        );
    }

    #[test]
    fn native_sub_advertise_is_gated_when_a_client_already_covers_it() {
        // The per-tier derive gate: a client subscribing K already advertised into
        // BOTH meshes, so a router-native for the SAME K does NOT re-advertise into
        // the peer mesh (no redundant flood — the flip was already true).
        let fwd = RouterForwarder::new(zid(0x01));
        let (c, _cs) = face(zid(0xAA), WIRE_CLIENT);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER);
        let (r, _rs) = face(zid(0xDD), WIRE_ROUTER);
        fwd.register(FaceId(0), &c);
        fwd.register(FaceId(1), &p);
        fwd.register(FaceId(2), &r);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_sub("demo/data")); // client -> advertise into peer
        sink_p.reset();
        forward_one(&fwd, FaceId(2), declare_sub("demo/data")); // router-native, client covers it
        assert_eq!(
            sink_p.frame_count(),
            0,
            "a native does not re-advertise a keyexpr a client already covers"
        );
    }

    #[test]
    fn native_sub_face_down_withdraws_the_cross_tier_advertisement() {
        // Lifecycle-symmetry (R311y125): a peer-native's face going down purges it
        // (through purge_detached_interest_tier — the SHARED choke point that also
        // covers the remote Oam-detach path :2597) and, since it was the LAST
        // source, WITHDRAWS self's advertisement from the router mesh.
        let fwd = RouterForwarder::new(zid(0x01));
        let (pn, _ps) = face(zid(0xBB), WIRE_PEER); // the peer-native source
        let (rc, sink_rc) = face(zid(0xCC), WIRE_ROUTER); // a router tree child
        fwd.register(FaceId(0), &pn);
        fwd.register(FaceId(1), &rc);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_sub("demo/data")); // advertise into router mesh
        sink_rc.reset();
        fwd.deregister(FaceId(0)); // the peer-native's face goes down
        assert_eq!(
            sink_rc.frame_count(),
            1,
            "the departed native's last source withdrew self's cross-tier advertisement"
        );
    }

    #[test]
    fn remote_oam_detach_withdraws_the_cross_tier_advertisement() {
        // The y107b-class REMOTE path (distinct from the local face-down above): a
        // router-native sub is sourced from a DISTANT router Rd learned via the
        // neighbour A. When a topology Oam drops A's link to Rd, Rd becomes
        // unreachable (`changes.removed`) and `purge_detached_interest_tier` — the
        // SHARED choke point — withdraws self's peer-mesh advertisement, exactly as
        // the local face-down does. Directly exercises the Oam-ingest purge call
        // site (the local path is covered by the test above).
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _as) = face(zid(0xAA), WIRE_ROUTER); // router neighbour
        let (p, sink_p) = face(zid(0xEE), WIRE_PEER); // peer tree child (advertise target)
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xEE, 5); // self<->P peer edge
        discover_via(&fwd, FaceId(0), 0x01, 0xAA, 0xBB, 7, 5); // Rd(0xBB) via A, psid 7
        fwd.tick();
        // A router-native sub for K sourced from the DISTANT router Rd (node_id 7).
        let mut decl = build_declare_subscriber(0, 0, Some("demo/data")).expect("build");
        set_declare_source(&mut decl, 7);
        forward_one(&fwd, FaceId(0), NetworkMessage::Declare(Box::new(decl)));
        assert_eq!(
            fwd.router_subs.borrow().interested("demo/data"),
            vec![zid(0xBB)],
            "the router-native is sourced from the distant router Rd"
        );
        sink_p.reset();
        // A topology Oam: A now links ONLY to self (drops Rd), higher sn — so Rd
        // becomes unreachable, the ingest detaches it, and the shared purge choke
        // point withdraws self's advertisement into the peer mesh.
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 6);
        assert_eq!(
            sink_p.frame_count(),
            1,
            "the remote Oam-detach of the distant router-native withdrew the advertisement"
        );
    }

    #[test]
    fn client_undeclare_keeps_the_advertisement_a_native_still_backs() {
        // The R311y120 black-hole GUARD: a client and a peer-native both cover K.
        // The peer-native advertises into the router mesh; the client adds the peer
        // mesh (router mesh is already covered, so the client does not re-advertise
        // it). When the client undeclares, the router-mesh advertisement MUST stay
        // (the native still backs it) — only the client-only peer-mesh advertise is
        // withdrawn. Withdrawing the native-backed one would black-hole the native.
        let fwd = RouterForwarder::new(zid(0x01));
        let (pn, _ps) = face(zid(0xBB), WIRE_PEER); // peer-native source + peer child
        let (rc, sink_rc) = face(zid(0xCC), WIRE_ROUTER); // router child
        let (c, _cs) = face(zid(0xAA), WIRE_CLIENT); // client
        fwd.register(FaceId(0), &pn);
        fwd.register(FaceId(1), &rc);
        fwd.register(FaceId(2), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xBB, 5); // self<->Pn peer edge
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 6); // self<->Rc router edge
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_sub("demo/data")); // peer-native -> router advertise
        forward_one(&fwd, FaceId(2), declare_sub("demo/data")); // client -> peer advertise (router gated)
        sink_rc.reset();
        forward_one(&fwd, FaceId(2), undeclare_sub("demo/data")); // last client leaves
        assert_eq!(
            sink_rc.frame_count(),
            0,
            "the native-backed router-mesh advertisement is NOT withdrawn when the client leaves"
        );
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

    // ── §5.21 routing-token-tables (slice-1): liveliness-TOKEN dual-tier INGEST ──

    /// A sourced `DeclareToken` for `keyexpr` (id 0 = sourced, keyexpr inline —
    /// the liveliness-token twin of [`declare_sub`]).
    #[cfg(feature = "routing-token-tables")]
    fn declare_token_msg(keyexpr: &str) -> NetworkMessage {
        NetworkMessage::Declare(Box::new(
            build_declare_token(0, 0, Some(keyexpr)).expect("build declare token"),
        ))
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn router_face_token_lands_in_router_tokens_only() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sink) = face(zid(0xAA), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data"));
        assert_eq!(
            fwd.router_tokens.borrow().interested("live/data"),
            vec![zid(0xAA)],
            "the router-face token source is registered in router_tokens"
        );
        assert!(
            fwd.linkstatepeer_tokens
                .borrow()
                .interested("live/data")
                .is_empty(),
            "no native peer token entry (derive-not-store; this is a Router-tier source)"
        );
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn peer_face_token_lands_in_linkstatepeer_tokens_only() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (b, _sink) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &b);
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data"));
        assert_eq!(
            fwd.linkstatepeer_tokens.borrow().interested("live/data"),
            vec![zid(0xBB)],
        );
        assert!(fwd
            .router_tokens
            .borrow()
            .interested("live/data")
            .is_empty());
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn client_face_token_is_not_ingested_into_a_mesh_tier() {
        // DERIVE-not-STORE: a client-face token lands in `client_tokens` (slice-3),
        // never in either Zid-keyed mesh tier table. (slice-1 dropped it entirely;
        // slice-3 lands the leaf in client_tokens + advertises cross-tier — but self
        // is still never stored as a mesh source.)
        let fwd = RouterForwarder::new(zid(0x01));
        let (c, _sink) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &c);
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data"));
        assert!(
            fwd.router_tokens
                .borrow()
                .interested("live/data")
                .is_empty()
                && fwd
                    .linkstatepeer_tokens
                    .borrow()
                    .interested("live/data")
                    .is_empty(),
            "a client-face token is not stored in either mesh tier (derive-not-store)"
        );
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn token_declare_re_floods_within_the_tier_only() {
        // The token twin of `declare_re_floods_within_the_tier_only`: a sourced
        // DeclareToken floods along the SOURCE's tree WITHIN its tier — to the
        // same-tier tree child, never back to the inbound source, never to the
        // other tier.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_ROUTER); // source
        let (c, sink_c) = face(zid(0xCC), WIRE_ROUTER); // same-tier tree child
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER); // other tier
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        fwd.register(FaceId(2), &p);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick();
        sink_a.reset();
        sink_c.reset();
        sink_p.reset();
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data"));
        assert_eq!(
            fwd.router_tokens.borrow().interested("live/data"),
            vec![zid(0xAA)],
            "self learned A's token"
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "re-flooded to the same-tier tree child C"
        );
        assert_eq!(sink_a.frame_count(), 0, "not back to the inbound source A");
        assert_eq!(sink_p.frame_count(), 0, "not to the peer tier");
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn duplicate_token_does_not_re_flood() {
        // The change-gate: a re-declared token from a KNOWN source is a no-op
        // (`register` returns false), so it does NOT re-flood a second time.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sa) = face(zid(0xAA), WIRE_ROUTER);
        let (c, sink_c) = face(zid(0xCC), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data")); // first: re-floods
        sink_c.reset();
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data")); // duplicate: gated
        assert_eq!(
            sink_c.frame_count(),
            0,
            "a re-declare of a known token does not re-flood (the change-gate)"
        );
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn token_face_down_is_purged() {
        // The face-down safety net (the ADJUST-2 purge extension): a departed
        // native token source is drained from `router_tokens` on an UNGRACEFUL
        // departure (a graceful retraction rides the sourced UndeclareToken arm).
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sink) = face(zid(0xAA), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data"));
        assert_eq!(
            fwd.router_tokens.borrow().interested("live/data"),
            vec![zid(0xAA)]
        );
        fwd.deregister(FaceId(0));
        assert!(
            fwd.router_tokens
                .borrow()
                .interested("live/data")
                .is_empty(),
            "the departed token source is purged (no leak in the register-only slice)"
        );
    }

    /// A SOURCED `UndeclareToken` retracting `keyexpr` (id 0, keyexpr in the
    /// ext_wire_expr chain — decodable now that the UndeclToken codec models the
    /// ext). The token twin of the `build_undeclare_subscriber_with_keyexpr` msg.
    #[cfg(feature = "routing-token-tables")]
    fn undeclare_token_msg(keyexpr: &str) -> NetworkMessage {
        NetworkMessage::Declare(Box::new(
            build_undeclare_token_with_keyexpr(keyexpr).expect("build undeclare token"),
        ))
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn undeclare_token_withdraws_from_the_inbound_tier() {
        // The codec round's native withdraw: a sourced UndeclareToken (keyexpr in
        // the ext) drains the source from router_tokens. Proves the forward()
        // UndeclareToken arm + withdraw_token + the regenerated ext codec.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sink) = face(zid(0xAA), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data"));
        assert_eq!(
            fwd.router_tokens.borrow().interested("live/data"),
            vec![zid(0xAA)]
        );
        forward_one(&fwd, FaceId(0), undeclare_token_msg("live/data"));
        assert!(
            fwd.router_tokens
                .borrow()
                .interested("live/data")
                .is_empty(),
            "the sourced UndeclareToken withdrew the token source"
        );
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn undeclare_token_re_floods_within_the_tier() {
        // The retraction re-flood: after a DeclareToken re-floods to the tree
        // child, a sourced UndeclareToken withdraws AND re-floods the retraction
        // to the same child, never back to the inbound source. Proves the reflood
        // carrier build_undeclare_token_with_keyexpr.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_ROUTER);
        let (c, sink_c) = face(zid(0xCC), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data")); // register + re-flood
        sink_a.reset();
        sink_c.reset();
        forward_one(&fwd, FaceId(0), undeclare_token_msg("live/data"));
        assert!(
            fwd.router_tokens
                .borrow()
                .interested("live/data")
                .is_empty(),
            "the token source is withdrawn"
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the retraction re-flooded to the tree child C"
        );
        assert_eq!(sink_a.frame_count(), 0, "not back to the inbound source A");
    }

    // ── §5.21 routing-token-tables (slice-2): token CROSS-TIER PROPAGATION ──

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn router_native_token_advertises_into_the_peer_mesh() {
        // A ROUTER-native token makes self ADVERTISE that keyexpr into the PEER mesh
        // (a self-sourced DeclareToken to a peer tree child) — the token twin of
        // router_native_sub_advertises_into_the_peer_mesh. Derive-not-store: self is
        // NOT registered in the peer tokens table.
        let fwd = RouterForwarder::new(zid(0x01));
        let (r, _rs) = face(zid(0xAA), WIRE_ROUTER); // the router-native source
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER); // a peer tree child
        fwd.register(FaceId(0), &r);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5); // self<->P peer edge
        fwd.tick();
        sink_p.reset();
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data")); // router-native token
        assert_eq!(
            sink_p.frame_count(),
            1,
            "a router-native token advertised self's cross-tier interest to the peer mesh"
        );
        assert!(
            fwd.linkstatepeer_tokens
                .borrow()
                .interested("live/data")
                .is_empty(),
            "derive-not-store: self is NOT stored in the peer tokens table"
        );
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn peer_native_token_advertises_into_the_router_mesh() {
        // The mirror direction: a PEER-native token advertises into the ROUTER mesh.
        let fwd = RouterForwarder::new(zid(0x01));
        let (pn, _ps) = face(zid(0xBB), WIRE_PEER); // the peer-native source
        let (rc, sink_rc) = face(zid(0xCC), WIRE_ROUTER); // a router tree child
        fwd.register(FaceId(0), &pn);
        fwd.register(FaceId(1), &rc);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick();
        sink_rc.reset();
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data"));
        assert_eq!(
            sink_rc.frame_count(),
            1,
            "a peer-native token advertised into the router mesh"
        );
        assert!(
            fwd.router_tokens
                .borrow()
                .interested("live/data")
                .is_empty(),
            "derive-not-store: self is NOT stored in the router tokens table"
        );
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn native_token_face_down_withdraws_the_cross_tier_advertisement() {
        // Lifecycle-symmetry: a peer-native token's face going down purges it
        // (through purge_detached_interest_tier — the shared choke point that also
        // covers the remote Oam-detach) and, since it was the LAST source, WITHDRAWS
        // self's cross-tier advertisement from the router mesh. The token twin of
        // native_sub_face_down_withdraws_the_cross_tier_advertisement — proves the
        // slice-2 purge cross-tier withdraw (scoped-drain then withdraw-after-drop).
        let fwd = RouterForwarder::new(zid(0x01));
        let (pn, _ps) = face(zid(0xBB), WIRE_PEER);
        let (rc, sink_rc) = face(zid(0xCC), WIRE_ROUTER);
        fwd.register(FaceId(0), &pn);
        fwd.register(FaceId(1), &rc);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data")); // advertise into router mesh
        sink_rc.reset();
        fwd.deregister(FaceId(0)); // the peer-native's face goes down
        assert_eq!(
            sink_rc.frame_count(),
            1,
            "the departed native's last token source withdrew self's cross-tier advertisement"
        );
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn native_token_undeclare_withdraws_the_cross_tier_advertisement() {
        // The GRACEFUL path (vs the face-down purge above): a sourced UndeclareToken
        // for the LAST native source withdraws self's cross-tier advertisement, via
        // withdraw_token capturing the withdraw_interest change signal.
        let fwd = RouterForwarder::new(zid(0x01));
        let (r, _rs) = face(zid(0xAA), WIRE_ROUTER);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &r);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data")); // advertise into peer mesh
        sink_p.reset();
        forward_one(&fwd, FaceId(0), undeclare_token_msg("live/data"));
        assert_eq!(
            sink_p.frame_count(),
            1,
            "the graceful retraction of the last source withdrew the cross-tier advertisement"
        );
    }

    // ── §5.21 routing-token-tables (slice-3): CLIENT/simple token plane ──

    /// A CLIENT-face `DeclareToken` for `keyexpr` carrying a NON-ZERO decl `id`
    /// (a client declares its token by id, unlike the sourced id-0 mesh form); the
    /// router stores `id -> keyexpr` in `client_tokens` for id-keyed retraction.
    #[cfg(feature = "routing-token-tables")]
    fn declare_client_token_msg(id: u64, keyexpr: &str) -> NetworkMessage {
        NetworkMessage::Declare(Box::new(
            build_declare_token(id, 0, Some(keyexpr)).expect("build client declare token"),
        ))
    }

    /// A CLIENT-face ID-KEYED `UndeclareToken(id)` with NO ext — the form wz's own
    /// liveliness `Drop` (`send_undeclare_token` -> `build_undeclare_token(id)`) and
    /// pico emit. Resolved BY ID, not by an `ext_wire_expr` the client never sends.
    #[cfg(feature = "routing-token-tables")]
    fn undeclare_client_token_msg(id: u64) -> NetworkMessage {
        NetworkMessage::Declare(Box::new(
            wz_session_core::declare_build::build_undeclare_token(id),
        ))
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn client_face_token_lands_in_client_tokens() {
        // A CLIENT-face DeclareToken lands in client_tokens (id -> keyexpr), NOT in
        // either mesh tier table (derive-not-store). slice-1's mesh ingest dropped a
        // Client-tier token; slice-3 lands the leaf here instead.
        let fwd = RouterForwarder::new(zid(0x01));
        let (c, _cs) = face(zid(0xAA), WIRE_CLIENT);
        fwd.register(FaceId(0), &c);
        forward_one(&fwd, FaceId(0), declare_client_token_msg(7, "live/data"));
        assert!(
            fwd.any_client_holds_token("live/data"),
            "the client-face token is registered in client_tokens"
        );
        assert!(
            fwd.router_tokens
                .borrow()
                .interested("live/data")
                .is_empty()
                && fwd
                    .linkstatepeer_tokens
                    .borrow()
                    .interested("live/data")
                    .is_empty(),
            "derive-not-store: a client token is NOT stored in either mesh tier table"
        );
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn client_token_advertises_into_both_meshes() {
        // A CLIENT token steers BOTH meshes (unlike a native, which steers only the
        // opposite): a self-sourced DeclareToken floods to the router AND peer tree
        // children. The token twin of the client-sub cross-tier advertise.
        let fwd = RouterForwarder::new(zid(0x01));
        let (c, _cs) = face(zid(0xAA), WIRE_CLIENT);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER);
        let (r, sink_r) = face(zid(0xCC), WIRE_ROUTER);
        fwd.register(FaceId(0), &c);
        fwd.register(FaceId(1), &p);
        fwd.register(FaceId(2), &r);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5); // self<->P peer edge
        advertise_link_back(&fwd, FaceId(2), 0x01, 0xCC, 5); // self<->R router edge
        fwd.tick();
        sink_p.reset();
        sink_r.reset();
        forward_one(&fwd, FaceId(0), declare_client_token_msg(7, "live/data"));
        assert_eq!(
            sink_p.frame_count(),
            1,
            "the client token advertised self's cross-tier interest into the peer mesh"
        );
        assert_eq!(
            sink_r.frame_count(),
            1,
            "the client token advertised self's cross-tier interest into the router mesh"
        );
        assert!(
            fwd.router_tokens
                .borrow()
                .interested("live/data")
                .is_empty()
                && fwd
                    .linkstatepeer_tokens
                    .borrow()
                    .interested("live/data")
                    .is_empty(),
            "derive-not-store: self is NOT stored in either mesh token table"
        );
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn client_token_id_keyed_undeclare_retracts_cross_tier() {
        // The [mirror-verifies-template] guard: a real client (incl wz's own) retracts
        // its token with an ID-KEYED UndeclareToken(id) carrying NO keyexpr. A naive
        // resolve_ext_keyexpr mirror (as the sibling sub plane uses) would no-op on the
        // null ext and leave the liveliness token stale-live until face-down — a
        // NON-retraction black-hole; the id-map resolves the retraction by id (zenoh
        // forget_simple_token id-first). Assert BOTH the store removal AND the
        // cross-tier withdrawal flood fire.
        let fwd = RouterForwarder::new(zid(0x01));
        let (c, _cs) = face(zid(0xAA), WIRE_CLIENT);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &c);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_client_token_msg(7, "live/data"));
        sink_p.reset();
        forward_one(&fwd, FaceId(0), undeclare_client_token_msg(7)); // id-keyed, no ext
        assert!(
            !fwd.any_client_holds_token("live/data"),
            "the id-keyed client undeclare removed the token from client_tokens (by id)"
        );
        assert_eq!(
            sink_p.frame_count(),
            1,
            "the last client's token retraction withdrew self's cross-tier advertisement"
        );
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn client_token_face_down_purges_and_withdraws() {
        // A client face going down purges client_tokens (OBLIGATION 1, before the
        // linkless early-return) and withdraws self's cross-tier advertisement for any
        // keyexpr it was the LAST client of. Token twin of the client-sub face-down.
        let fwd = RouterForwarder::new(zid(0x01));
        let (c, _cs) = face(zid(0xAA), WIRE_CLIENT);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &c);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_client_token_msg(7, "live/data"));
        sink_p.reset();
        fwd.deregister(FaceId(0)); // client down
        assert!(
            !fwd.any_client_holds_token("live/data"),
            "the client token store was purged on face-down"
        );
        assert_eq!(
            sink_p.frame_count(),
            1,
            "face-down withdrew self's cross-tier token advertisement"
        );
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn native_token_advertise_is_gated_when_a_client_already_holds_it() {
        // The gate-symmetry ADVERTISE half: a client holding K already advertised into
        // BOTH meshes, so a router-native token for the SAME K does NOT re-advertise
        // into the peer mesh (the flip was already true — no redundant flood). Token
        // twin of native_sub_advertise_is_gated_when_a_client_already_covers_it.
        let fwd = RouterForwarder::new(zid(0x01));
        let (c, _cs) = face(zid(0xAA), WIRE_CLIENT);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER);
        let (r, _rs) = face(zid(0xDD), WIRE_ROUTER);
        fwd.register(FaceId(0), &c);
        fwd.register(FaceId(1), &p);
        fwd.register(FaceId(2), &r);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_client_token_msg(7, "live/data")); // client -> both meshes
        sink_p.reset();
        forward_one(&fwd, FaceId(2), declare_token_msg("live/data")); // router-native, client covers it
        assert_eq!(
            sink_p.frame_count(),
            0,
            "a native does not re-advertise a token a client already holds"
        );
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn client_token_undeclare_keeps_advertisement_a_native_still_backs() {
        // The R311y120 black-hole GUARD, client-withdraw side (token twin of
        // client_undeclare_keeps_the_advertisement_a_native_still_backs): a client and
        // a peer-native both hold K. The peer-native advertises into the router mesh;
        // the client adds the peer mesh (router already covered). When the CLIENT
        // undeclares, the router-mesh advertisement MUST stay (the native still backs
        // it) — withdrawing it would black-hole the native.
        let fwd = RouterForwarder::new(zid(0x01));
        let (pn, _ps) = face(zid(0xBB), WIRE_PEER); // peer-native source + peer child
        let (rc, sink_rc) = face(zid(0xCC), WIRE_ROUTER); // router child
        let (c, _cs) = face(zid(0xAA), WIRE_CLIENT); // client
        fwd.register(FaceId(0), &pn);
        fwd.register(FaceId(1), &rc);
        fwd.register(FaceId(2), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xBB, 5); // self<->Pn peer edge
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 6); // self<->Rc router edge
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data")); // peer-native -> router advertise
        forward_one(&fwd, FaceId(2), declare_client_token_msg(7, "live/data")); // client -> peer (router gated)
        sink_rc.reset();
        forward_one(&fwd, FaceId(2), undeclare_client_token_msg(7)); // last client leaves
        assert_eq!(
            sink_rc.frame_count(),
            0,
            "the native-backed router-mesh token advertisement is NOT withdrawn when the client leaves"
        );
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn native_token_undeclare_keeps_advertisement_a_client_still_holds() {
        // The R311y120 black-hole GUARD, NATIVE-withdraw side (the gate-symmetry fix's
        // load-bearing case): a peer-native advertises K into the router mesh (it is
        // first). Then a client declares K (router mesh already covered). When the
        // peer-native gracefully undeclares while the client STILL holds K, the
        // router-mesh advertisement MUST stay (the client now backs it) — the withdraw
        // gate's !any_client_holds_token term suppresses the flood. The OLD gate
        // (source_count==0 only) would black-hole the client's token.
        let fwd = RouterForwarder::new(zid(0x01));
        let (pn, _ps) = face(zid(0xBB), WIRE_PEER); // peer-native + peer child
        let (rc, sink_rc) = face(zid(0xCC), WIRE_ROUTER); // router child
        let (c, _cs) = face(zid(0xAA), WIRE_CLIENT); // client
        fwd.register(FaceId(0), &pn);
        fwd.register(FaceId(1), &rc);
        fwd.register(FaceId(2), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xBB, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 6);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data")); // peer-native -> router advertise
        forward_one(&fwd, FaceId(2), declare_client_token_msg(7, "live/data")); // client (router gated)
        sink_rc.reset();
        forward_one(&fwd, FaceId(0), undeclare_token_msg("live/data")); // native gracefully leaves
        assert_eq!(
            sink_rc.frame_count(),
            0,
            "the client-backed router-mesh advertisement is NOT withdrawn when the native leaves"
        );
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn client_token_re_advertised_to_a_late_joining_peer() {
        // The DERIVED self cross-tier token converges onto a peer that joins AFTER the
        // client declared the token — the tick re-advertise reads
        // derived_cross_tier_tokens_into (slice-3 taught it to fold client_tokens).
        // Token twin of tick_re_advertises_the_derived_self_sub_to_a_late_joining_peer.
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, _) = face(zid(0xAA), WIRE_CLIENT);
        fwd.register(FaceId(0), &client);
        forward_one(&fwd, FaceId(0), declare_client_token_msg(7, "live/data")); // no peer yet
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER); // joins LATER
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 6);
        sink_p.reset();
        fwd.tick(); // recompute -> P is a new self-child -> re-advertise the derived token
        assert_eq!(
            sink_p.frame_count(),
            1,
            "the derived self cross-tier token re-advertised to the late-joining peer"
        );
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn partial_client_token_deregister_keeps_the_advertisement() {
        // Two clients hold the SAME keyexpr token; one leaving does NOT withdraw (the
        // other still holds K) — only the LAST client's departure withdraws. The
        // refcount half of the derive (the id-map gives correct per-token refcount),
        // token twin of partial_client_deregister_keeps_the_advertisement.
        let fwd = RouterForwarder::new(zid(0x01));
        let (c1, _) = face(zid(0xAA), WIRE_CLIENT);
        let (c2, _) = face(zid(0xCC), WIRE_CLIENT);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &c1);
        fwd.register(FaceId(1), &c2);
        fwd.register(FaceId(2), &p);
        advertise_link_back(&fwd, FaceId(2), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_client_token_msg(7, "live/data")); // c1 -> advertise
        forward_one(&fwd, FaceId(1), declare_client_token_msg(9, "live/data")); // c2 (same K) -> gated
        sink_p.reset();
        fwd.deregister(FaceId(0)); // c1 down -> c2 still holds K -> NO withdraw
        assert_eq!(
            sink_p.frame_count(),
            0,
            "a client leaving does not withdraw a token another client still holds"
        );
    }

    // ── §5.21 routing-token-tables (slice-4): token INTEREST (the FIRST reader) ──

    /// A liveliness-TOKEN `Interest` restricted to `keyexpr` (the TOKENS option bit
    /// 0x08), current/future selectable — the token twin of [`interest_with_mode`].
    #[cfg(feature = "routing-token-tables")]
    fn token_interest_msg(
        interest_id: u64,
        keyexpr: &str,
        current: bool,
        future: bool,
        aggregate: bool,
    ) -> NetworkMessage {
        let outer = 0x19 | (if current { 0x20 } else { 0 }) | (if future { 0x40 } else { 0 });
        let body_header = 0x08 | 0x10 | 0x20 | 0x40 | (if aggregate { 0x80 } else { 0 });
        NetworkMessage::Interest(InterestOwned {
            header: outer,
            interest_id,
            body: Some(wz_codecs::interest_body::InterestBodyOwned {
                header: body_header,
                keyexpr: Some(WireexprOwned {
                    body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                        id: 0,
                        suffix_len: Some(keyexpr.len() as u64),
                        suffix: Some(
                            sce_forge_runtime::codec::SceString::from_view(keyexpr)
                                .expect("interest keyexpr fits the SceString capacity"),
                        ),
                    }),
                }),
            }),
            extensions: None,
        })
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn token_current_interest_replies_with_a_mesh_token() {
        // The FIRST reader: a client's CURRENT token interest is answered with the
        // matching REMOTE mesh token wz holds + a DeclareFinal — the slice-1/2 bubble
        // is now observable.
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER); // mesh token source
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT); // requester
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data")); // -> router_tokens
        sink_c.reset();
        forward_one(
            &fwd,
            FaceId(1),
            token_interest_msg(7, "live/data", true, false, false),
        );
        assert_eq!(
            sink_c.frame_count(),
            2,
            "one DeclareToken reply + one terminating DeclareFinal"
        );
        let reply = forwarded_declare(&sink_c.frame_bytes(0));
        assert_eq!(reply.interest_id, Some(7), "reply echoes the interest id");
        assert!(
            matches!(reply.body, DeclareOwnedVariant::CodecZenohDeclToken(_)),
            "the mesh token is replayed as a DeclareToken"
        );
        assert!(matches!(
            forwarded_declare(&sink_c.frame_bytes(1)).body,
            DeclareOwnedVariant::CodecZenohDeclFinal(_)
        ));
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn token_current_interest_replies_with_a_client_token() {
        // THE slice-4 obligation: a client-sourced token (derive-not-store, kept OUT of
        // the mesh tables) is folded into the current dump, so ANOTHER client's token
        // interest SEES it. Without the client_tokens fold this token is invisible.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sa) = face(zid(0xAA), WIRE_CLIENT); // token holder
        let (b, sink_b) = face(zid(0xBB), WIRE_CLIENT); // requester
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &b);
        forward_one(&fwd, FaceId(0), declare_client_token_msg(7, "live/data"));
        sink_b.reset();
        forward_one(
            &fwd,
            FaceId(1),
            token_interest_msg(9, "live/data", true, false, false),
        );
        assert_eq!(
            sink_b.frame_count(),
            2,
            "the client-sourced token replay + DeclareFinal"
        );
        assert!(
            matches!(
                forwarded_declare(&sink_b.frame_bytes(0)).body,
                DeclareOwnedVariant::CodecZenohDeclToken(_)
            ),
            "a client-sourced token is observable to another client's interest (the fold)"
        );
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn token_current_interest_excludes_the_requesters_own_token() {
        // A face is never replayed its OWN token (parity with the sub dump's
        // requester-exclusion): the sole holder's own interest gets only a DeclareFinal.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_CLIENT);
        fwd.register(FaceId(0), &a);
        forward_one(&fwd, FaceId(0), declare_client_token_msg(7, "live/data"));
        sink_a.reset();
        forward_one(
            &fwd,
            FaceId(0),
            token_interest_msg(9, "live/data", true, false, false),
        );
        assert_eq!(
            sink_a.frame_count(),
            1,
            "only the DeclareFinal (the requester's own token is excluded)"
        );
        assert!(matches!(
            forwarded_declare(&sink_a.frame_bytes(0)).body,
            DeclareOwnedVariant::CodecZenohDeclFinal(_)
        ));
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn token_current_interest_from_a_peer_gets_only_the_final() {
        // The CLIENT-GATE delta (zenoh declare_token_interest is client-only, UNLIKE
        // the ungated sub dump): a PEER-tier face's CURRENT token interest gets NO token
        // dump even when a mesh token matches — only the DeclareFinal. Peers learn tokens
        // via the linkstate flood, not interest replay.
        let fwd = RouterForwarder::new(zid(0x01));
        let (src, _ss) = face(zid(0xAA), WIRE_ROUTER); // mesh token source
        let (peer, sink_p) = face(zid(0xBB), WIRE_PEER); // a PEER requester
        fwd.register(FaceId(0), &src);
        fwd.register(FaceId(1), &peer);
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data")); // -> router_tokens
        sink_p.reset();
        forward_one(
            &fwd,
            FaceId(1),
            token_interest_msg(7, "live/data", true, false, false),
        );
        assert_eq!(
            sink_p.frame_count(),
            1,
            "a peer's token interest gets ONLY the DeclareFinal (the client-gate)"
        );
        assert!(matches!(
            forwarded_declare(&sink_p.frame_bytes(0)).body,
            DeclareOwnedVariant::CodecZenohDeclFinal(_)
        ));
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn future_token_interest_pushes_a_later_token() {
        // The FUTURE push witness: a client's C+F token interest for live/data (nothing
        // held yet) gets an empty dump; a mesh token learned LATER is proactively pushed
        // (future_token_pushes rises), the token twin of the sub future push.
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER); // the LATER mesh token source
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(
            &fwd,
            FaceId(1),
            token_interest_msg(7, "live/data", true, true, false),
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "empty current dump -> only the terminating DeclareFinal"
        );
        sink_c.reset();
        assert_eq!(fwd.future_token_pushes_seen(), 0);
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data")); // learned LATER
        assert_eq!(
            fwd.future_token_pushes_seen(),
            1,
            "the later token was proactively pushed to the future-interested client"
        );
        assert!(
            matches!(
                forwarded_declare(&sink_c.frame_bytes(0)).body,
                DeclareOwnedVariant::CodecZenohDeclToken(_)
            ),
            "the client got an unsolicited DeclareToken"
        );
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn token_interest_final_tears_down_the_future_token_interest() {
        // An Interest(Final) removes the stored FUTURE token interest, so a later token
        // is NOT pushed (parity with the sub Final teardown; else it leaks + keeps
        // pushing to a face whose write-filter is gone).
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER);
        let (client, _sc) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(
            &fwd,
            FaceId(1),
            token_interest_msg(7, "live/data", true, true, false),
        ); // store the future interest
        forward_one(
            &fwd,
            FaceId(1),
            token_interest_msg(7, "live/data", false, false, false),
        ); // Interest(Final) -> teardown
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data")); // learned AFTER teardown
        assert_eq!(
            fwd.future_token_pushes_seen(),
            0,
            "the torn-down future token interest is no longer pushed"
        );
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn aggregate_token_interest_replies_once_keyed_on_the_interest_ke() {
        // An AGGREGATE token interest for a wildcard gets ONE reply keyed on the INTEREST
        // keyexpr (pico matches aggregate replies by keyexpr EQUALITY), not one per
        // matched token — parity with the aggregate sub dump.
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER);
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(&fwd, FaceId(0), declare_token_msg("demo/a"));
        forward_one(&fwd, FaceId(0), declare_token_msg("demo/b"));
        sink_c.reset();
        forward_one(
            &fwd,
            FaceId(1),
            token_interest_msg(7, "demo/**", true, false, true),
        );
        assert_eq!(
            sink_c.frame_count(),
            2,
            "ONE aggregate DeclareToken reply + DeclareFinal"
        );
        match &forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclToken(d) => match &d.keyexpr.body {
                WireexprOwnedVariant::WireexprLocal(w) => assert_eq!(
                    w.suffix.as_deref(),
                    Some("demo/**"),
                    "aggregate reply is keyed on the interest keyexpr, not demo/a|demo/b"
                ),
                _ => panic!("reply keyexpr must be literal"),
            },
            other => panic!("expected a DeclToken reply, got {other:?}"),
        }
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn client_token_id_reuse_for_a_new_keyexpr_retracts_the_old() {
        // Defensive (IMPL-panel nit): a client re-uses decl id 7 for a DIFFERENT
        // keyexpr with no intervening undeclare. The displaced old keyexpr, if held by
        // no other client, has its cross-tier advertisement retracted — no stale-live
        // liveliness leak. (Conforming clients never trigger this: monotonic ids +
        // undeclare-first; the id-map makes it detectable where the sub set could not.)
        let fwd = RouterForwarder::new(zid(0x01));
        let (c, _cs) = face(zid(0xAA), WIRE_CLIENT);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &c);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_client_token_msg(7, "live/a")); // id 7 -> live/a
        sink_p.reset();
        forward_one(&fwd, FaceId(0), declare_client_token_msg(7, "live/b")); // id 7 REUSED -> live/b
        assert!(
            !fwd.any_client_holds_token("live/a"),
            "the displaced old keyexpr is no longer held"
        );
        assert!(
            fwd.any_client_holds_token("live/b"),
            "the new keyexpr under the reused id is held"
        );
        assert_eq!(
            sink_p.frame_count(),
            2,
            "the reused id advertised the new keyexpr AND retracted the displaced old one"
        );
    }

    // ── §5.21 routing-token-tables (slice-5): topology reconcile withdraw->notify ──

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn mesh_token_withdraw_undeclares_to_a_pushed_reader() {
        // slice-5: a future-push reader told a MESH token appeared is told it withdrew
        // on a graceful UndeclareToken (the token twin of the sub undeclare-push).
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER); // mesh token source
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT); // future reader
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(
            &fwd,
            FaceId(1),
            token_interest_msg(7, "live/data", true, true, false),
        );
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data")); // -> pushed to the client
        assert!(
            fwd.future_token_pushes_seen() >= 1,
            "the token was future-pushed"
        );
        sink_c.reset();
        forward_one(&fwd, FaceId(0), undeclare_token_msg("live/data")); // graceful mesh withdraw
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the reader is notified the token withdrew"
        );
        assert!(matches!(
            forwarded_declare(&sink_c.frame_bytes(0)).body,
            DeclareOwnedVariant::CodecZenohUndeclToken(_)
        ));
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn client_token_withdraw_undeclares_to_a_pushed_reader() {
        // slice-5: a client A's token pushed to reader B; A's graceful id-keyed
        // UndeclareToken retracts it to B.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sa) = face(zid(0xAA), WIRE_CLIENT); // token holder
        let (b, sink_b) = face(zid(0xBB), WIRE_CLIENT); // future reader
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &b);
        forward_one(
            &fwd,
            FaceId(1),
            token_interest_msg(7, "live/data", true, true, false),
        );
        forward_one(&fwd, FaceId(0), declare_client_token_msg(9, "live/data")); // -> pushed to B
        assert!(fwd.future_token_pushes_seen() >= 1);
        sink_b.reset();
        forward_one(&fwd, FaceId(0), undeclare_client_token_msg(9)); // A withdraws (id-keyed)
        assert_eq!(sink_b.frame_count(), 1, "reader B told A's token withdrew");
        assert!(matches!(
            forwarded_declare(&sink_b.frame_bytes(0)).body,
            DeclareOwnedVariant::CodecZenohUndeclToken(_)
        ));
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn token_node_detach_undeclares_to_a_pushed_reader() {
        // slice-5: the UNGRACEFUL path — the mesh token source's face goes down, the
        // detach purge notifies the future-push reader (a Client face gets no
        // link-state, so the only frame it sees is the UndeclareToken).
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER); // mesh source (will detach)
        let (client, sink_c) = face(zid(0xCC), WIRE_CLIENT); // reader
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &client);
        forward_one(
            &fwd,
            FaceId(1),
            token_interest_msg(7, "live/data", true, true, false),
        );
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data"));
        assert!(fwd.future_token_pushes_seen() >= 1);
        sink_c.reset();
        fwd.deregister(FaceId(0)); // the mesh source face goes down (ungraceful)
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the reader told the detached node's token withdrew"
        );
        assert!(matches!(
            forwarded_declare(&sink_c.frame_bytes(0)).body,
            DeclareOwnedVariant::CodecZenohUndeclToken(_)
        ));
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn client_face_down_undeclares_its_token_to_a_pushed_reader() {
        // slice-5 the LIVELINESS 4th site (subs do NOT do this; a token's stale-live is
        // not benign): client A's token pushed to reader B; A's client FACE going down
        // retracts A's token to B (zenoh close_face -> undeclare_simple_token ->
        // propagate_forget). Load-bearing for liveliness correctness.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sa) = face(zid(0xAA), WIRE_CLIENT); // token holder (faces down)
        let (b, sink_b) = face(zid(0xBB), WIRE_CLIENT); // reader
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &b);
        forward_one(
            &fwd,
            FaceId(1),
            token_interest_msg(7, "live/data", true, true, false),
        );
        forward_one(&fwd, FaceId(0), declare_client_token_msg(9, "live/data")); // -> pushed to B
        assert!(fwd.future_token_pushes_seen() >= 1);
        sink_b.reset();
        fwd.deregister(FaceId(0)); // A's client face goes down
        assert_eq!(
            sink_b.frame_count(),
            1,
            "reader B told A's token withdrew on A's face-down (liveliness)"
        );
        assert!(matches!(
            forwarded_declare(&sink_b.frame_bytes(0)).body,
            DeclareOwnedVariant::CodecZenohUndeclToken(_)
        ));
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn undeclare_push_token_suppressed_while_another_backer_holds() {
        // slice-5 the any_token_matches gate: two tokens back K (a mesh source + a
        // client); one withdrawing does NOT undeclare to the reader (K still backed).
        let fwd = RouterForwarder::new(zid(0x01));
        let (router, _sr) = face(zid(0xAA), WIRE_ROUTER); // mesh backer
        let (a, _sa) = face(zid(0xBB), WIRE_CLIENT); // client backer (withdraws)
        let (b, sink_b) = face(zid(0xCC), WIRE_CLIENT); // reader
        fwd.register(FaceId(0), &router);
        fwd.register(FaceId(1), &a);
        fwd.register(FaceId(2), &b);
        forward_one(
            &fwd,
            FaceId(2),
            token_interest_msg(7, "live/data", true, true, false),
        );
        forward_one(&fwd, FaceId(0), declare_token_msg("live/data")); // mesh backer -> pushed to B
        forward_one(&fwd, FaceId(1), declare_client_token_msg(9, "live/data")); // client backer (dedup push)
        sink_b.reset();
        forward_one(&fwd, FaceId(1), undeclare_client_token_msg(9)); // the client backer withdraws
        assert_eq!(
            sink_b.frame_count(),
            0,
            "the reader is NOT told (K still backed by the mesh source)"
        );
    }

    #[cfg(feature = "routing-token-tables")]
    #[test]
    fn client_token_id_reuse_undeclares_the_displaced_to_a_reader() {
        // slice-5 the 5th removal path (id-reuse, no sub mirror): A holds live/a under
        // id 9 (pushed to reader B), then REUSES id 9 for live/b -> B is told live/a
        // (now displaced + unbacked) withdrew.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sa) = face(zid(0xAA), WIRE_CLIENT); // holder (id-reuse)
        let (b, sink_b) = face(zid(0xBB), WIRE_CLIENT); // reader of live/a
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &b);
        forward_one(
            &fwd,
            FaceId(1),
            token_interest_msg(7, "live/a", true, true, false),
        );
        forward_one(&fwd, FaceId(0), declare_client_token_msg(9, "live/a")); // id9 -> live/a, pushed to B
        assert!(fwd.future_token_pushes_seen() >= 1);
        sink_b.reset();
        forward_one(&fwd, FaceId(0), declare_client_token_msg(9, "live/b")); // id9 REUSED -> live/b
        assert_eq!(
            sink_b.frame_count(),
            1,
            "reader B told the displaced live/a withdrew"
        );
        assert!(matches!(
            forwarded_declare(&sink_b.frame_bytes(0)).body,
            DeclareOwnedVariant::CodecZenohUndeclToken(_)
        ));
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

    fn undeclare_qabl(keyexpr: &str) -> NetworkMessage {
        NetworkMessage::Declare(Box::new(
            build_undeclare_queryable_with_keyexpr(keyexpr).expect("build undeclare qabl"),
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
    fn router_native_qabl_advertises_merged_info_into_the_peer_mesh() {
        // FEDERATION query plane (A2b): a ROUTER-native queryable makes self
        // ADVERTISE its MERGED QueryableInfo into the PEER mesh (a self-sourced
        // DeclareQueryable carrying the info), so a REMOTE mesh querier routes
        // toward self. Content-checked: the advertised complete flag is the
        // native's.
        let fwd = RouterForwarder::new(zid(0x01));
        let (r, _rs) = face(zid(0xAA), WIRE_ROUTER); // the router-native qabl source
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER); // a peer tree child
        fwd.register(FaceId(0), &r);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        sink_p.reset();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", true));
        assert_eq!(
            sink_p.frame_count(),
            1,
            "a router-native queryable advertised its merged info into the peer mesh"
        );
        assert!(
            forwarded_qabl_info(&sink_p.frame_bytes(0)).complete,
            "the cross-tier advertisement carries the native's complete=true"
        );
        assert!(
            fwd.linkstatepeer_qabls
                .borrow()
                .interested("demo/q")
                .is_empty(),
            "derive-not-store: self is NOT stored in the peer qabls table"
        );
    }

    #[test]
    fn native_qabl_undeclare_retracts_the_cross_tier_advertisement() {
        // The debt-closure witness for the NATIVE path (withdraw_native_cross_tier_qabl
        // None arm): a router-native queryable advertised into the peer mesh, then
        // retracted, floods a full UndeclareQueryable into that mesh once the last
        // contributor leaves — the frame-level proof that the cross-tier advertisement
        // no longer lingers until self-down (the closed codec gap).
        let fwd = RouterForwarder::new(zid(0x01));
        let (r, _rs) = face(zid(0xAA), WIRE_ROUTER); // the router-native qabl source
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER); // a peer tree child
        fwd.register(FaceId(0), &r);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", true)); // advertise into peer mesh
        sink_p.reset();
        forward_one(
            &fwd,
            FaceId(0),
            NetworkMessage::Declare(Box::new(
                build_undeclare_queryable_with_keyexpr("demo/q").expect("undecl"),
            )),
        );
        assert!(
            fwd.router_qabls.borrow().interested("demo/q").is_empty(),
            "the native queryable interest is withdrawn"
        );
        assert_eq!(
            sink_p.frame_count(),
            1,
            "the last contributor left ⇒ a single cross-tier retraction into the peer mesh"
        );
        assert_eq!(
            forwarded_undecl_queryable_keyexpr(&sink_p.frame_bytes(0)),
            "demo/q",
            "the peer mesh receives the UndeclareQueryable retraction (None arm)"
        );
    }

    #[test]
    fn native_qabl_advertise_merges_completeness_across_sources() {
        // Two router-native queryables for the same K — one incomplete, one
        // complete — merge to complete=true (QueryableInfo::merge OR), and the
        // second declare re-advertises the upgraded merged info into the peer mesh.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _as) = face(zid(0xAA), WIRE_ROUTER);
        let (b, _bs) = face(zid(0xCC), WIRE_ROUTER);
        let (p, sink_p) = face(zid(0xEE), WIRE_PEER);
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &b);
        fwd.register(FaceId(2), &p);
        advertise_link_back(&fwd, FaceId(2), 0x01, 0xEE, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", false)); // A: incomplete
        sink_p.reset();
        forward_one(&fwd, FaceId(1), declare_qabl("demo/q", true)); // B: complete
        assert_eq!(sink_p.frame_count(), 1, "the merge upgrade re-advertised");
        assert!(
            forwarded_qabl_info(&sink_p.frame_bytes(0)).complete,
            "the merged info is complete (A incomplete OR B complete)"
        );
    }

    #[test]
    fn native_qabl_partial_removal_re_advertises_the_downgraded_info() {
        // Panel-flagged (A2b): a face-down that removes ONE of several native
        // queryables must RE-ADVERTISE the DOWNGRADED merged info (a Declare
        // update), not withdraw — the qabl-specific complication over subs. A
        // (complete) + B (incomplete) merge to complete=true; when A goes down, the
        // merge downgrades to complete=false and self re-advertises it.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _as) = face(zid(0xAA), WIRE_ROUTER); // complete
        let (b, _bs) = face(zid(0xCC), WIRE_ROUTER); // incomplete
        let (p, sink_p) = face(zid(0xEE), WIRE_PEER);
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &b);
        fwd.register(FaceId(2), &p);
        advertise_link_back(&fwd, FaceId(2), 0x01, 0xEE, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", true)); // A complete
        forward_one(&fwd, FaceId(1), declare_qabl("demo/q", false)); // B incomplete
        sink_p.reset();
        fwd.deregister(FaceId(0)); // the COMPLETE queryable's face goes down
        assert_eq!(
            sink_p.frame_count(),
            1,
            "the partial removal re-advertised the downgraded merged info"
        );
        assert!(
            !forwarded_qabl_info(&sink_p.frame_bytes(0)).complete,
            "the merged info downgraded to incomplete (only B remains)"
        );
    }

    #[test]
    fn client_qabl_advertises_into_both_meshes() {
        // A3: a CLIENT queryable is in NEITHER mesh, so it ADVERTISES self's merged
        // queryable into BOTH — a router tree child AND a peer tree child each
        // receive the self-sourced DeclareQueryable carrying the client's info.
        let fwd = RouterForwarder::new(zid(0x01));
        let (c, _cs) = face(zid(0xAA), WIRE_CLIENT); // the client queryable source
        let (rc, sink_rc) = face(zid(0xCC), WIRE_ROUTER); // a router tree child
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER); // a peer tree child
        fwd.register(FaceId(0), &c);
        fwd.register(FaceId(1), &rc);
        fwd.register(FaceId(2), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5); // self<->Rc router edge
        advertise_link_back(&fwd, FaceId(2), 0x01, 0xBB, 6); // self<->P peer edge
        fwd.tick();
        sink_rc.reset();
        sink_p.reset();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", true)); // client queryable
        assert_eq!(sink_rc.frame_count(), 1, "advertised into the router mesh");
        assert_eq!(sink_p.frame_count(), 1, "advertised into the peer mesh");
        assert!(
            forwarded_qabl_info(&sink_rc.frame_bytes(0)).complete
                && forwarded_qabl_info(&sink_p.frame_bytes(0)).complete,
            "both meshes carry the client's complete=true"
        );
        assert!(
            fwd.router_qabls.borrow().interested("demo/q").is_empty()
                && fwd
                    .linkstatepeer_qabls
                    .borrow()
                    .interested("demo/q")
                    .is_empty(),
            "derive-not-store: self is NOT stored in either qabls table"
        );
    }

    #[test]
    fn client_qabl_face_down_re_advertises_the_downgrade() {
        // A client queryable (complete) + a router-native queryable (incomplete)
        // for K both feed the PEER-mesh advertisement, merging to complete=true.
        // When the client face goes down, the peer-mesh advertisement re-declares
        // with the router-native's info alone — complete=FALSE (the downgrade), NOT
        // a full withdraw (a contributor remains).
        let fwd = RouterForwarder::new(zid(0x01));
        let (c, _cs) = face(zid(0xAA), WIRE_CLIENT); // client, complete
        let (r, _rs) = face(zid(0xCC), WIRE_ROUTER); // router-native, incomplete
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER); // peer tree child (target)
        fwd.register(FaceId(0), &c);
        fwd.register(FaceId(1), &r);
        fwd.register(FaceId(2), &p);
        advertise_link_back(&fwd, FaceId(2), 0x01, 0xBB, 5); // self<->P peer edge
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_qabl("demo/q", false)); // router-native incomplete
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", true)); // client complete
        sink_p.reset();
        fwd.deregister(FaceId(0)); // the client (complete) goes down
        assert_eq!(
            sink_p.frame_count(),
            1,
            "the client face-down re-advertised the downgraded merge into the peer mesh"
        );
        assert!(
            !forwarded_qabl_info(&sink_p.frame_bytes(0)).complete,
            "the merge downgraded to incomplete (only the router-native remains)"
        );
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
    fn client_face_queryable_lands_in_the_client_store_not_a_mesh_tier() {
        // C5b: a Client face's DeclareQueryable is NOT registered in either mesh
        // tier (a Client is no mesh node) — it lands in the per-face `client_qabls`
        // leaf store instead, keyed by the client face + its declared QueryableInfo.
        let fwd = RouterForwarder::new(zid(0x01));
        let (c, _sink) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &c);
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", true));
        assert!(
            fwd.router_qabls.borrow().interested("demo/q").is_empty(),
            "not in the router tier"
        );
        assert!(
            fwd.linkstatepeer_qabls
                .borrow()
                .interested("demo/q")
                .is_empty(),
            "not in the peer tier"
        );
        let store = fwd.client_qabls.borrow();
        let hosted = store
            .get(&FaceId(0))
            .expect("the client's queryable is stored");
        assert_eq!(
            hosted.get("demo/q"),
            Some(&QueryableInfo {
                complete: true,
                distance: 0,
            }),
            "with its declared completeness"
        );
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

    /// The keyexpr a forwarded `Declare(UndeclareQueryable)` retracts, read off its
    /// `ext_wire_expr` extension — the retraction twin of [`forwarded_qabl_info`].
    fn forwarded_undecl_queryable_keyexpr(frame: &[u8]) -> String {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let InboundFrame::Frame { payload, .. } =
            parse_inbound(frame).expect("parse forwarded frame")
        else {
            panic!("forwarded bytes are not a Frame");
        };
        let msgs = parse_frame_payload(&payload).expect("parse frame payload");
        match msgs.first() {
            Some(NetworkMessage::Declare(d)) => match &d.body {
                DeclareOwnedVariant::CodecZenohUndeclQueryable(u) => {
                    wz_session_core::declare_ext_keyexpr::read_ext_keyexpr(u.extensions.as_ref())
                        .expect("undecl queryable carries an ext_keyexpr")
                        .to_string()
                }
                _ => panic!("forwarded Declare is not an UndeclareQueryable"),
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
    fn an_id_only_undeclare_queryable_does_not_withdraw_a_sourced_interest() {
        // An id-only (no-ext) UndeclareQueryable carries no keyexpr, so it cannot
        // identify a sourced keyexpr-keyed mesh interest: withdraw_queryable resolves
        // no keyexpr and no-ops. A declared queryable SURVIVES it (only the
        // keyexpr-carrying form below, or a face-down purge, withdraws it).
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
            "an id-only UndeclareQueryable carries no keyexpr — the interest survives"
        );
    }

    #[test]
    fn undeclare_queryable_withdraws_from_the_inbound_tier() {
        // The query twin of undeclare_withdraws_from_the_inbound_tier: a sourced
        // keyexpr-carrying UndeclareQueryable withdraws the source's queryable
        // interest from the inbound tier (now that the ext_wire_expr codec carries
        // the keyexpr identity).
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, _sink) = face(zid(0xAA), WIRE_ROUTER);
        fwd.register(FaceId(0), &a);
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", true));
        assert_eq!(
            fwd.router_qabls.borrow().interested("demo/q"),
            vec![zid(0xAA)]
        );
        let undecl = NetworkMessage::Declare(Box::new(
            build_undeclare_queryable_with_keyexpr("demo/q").expect("undecl"),
        ));
        forward_one(&fwd, FaceId(0), undecl);
        assert!(
            fwd.router_qabls.borrow().interested("demo/q").is_empty(),
            "the source's queryable interest is withdrawn"
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

    // ── C5b: router query-route FORWARD half (the Request) ──

    /// The single forwarded Request decoded from a recorded wire frame — so a test
    /// can assert its re-stamped routing source landed ON THE WIRE (the router twin
    /// of the sibling forwarder's `forwarded_request`).
    fn forwarded_request(frame: &[u8]) -> RequestOwned {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let InboundFrame::Frame { payload, .. } =
            parse_inbound(frame).expect("parse forwarded frame")
        else {
            panic!("forwarded bytes are not a Frame");
        };
        let msgs = parse_frame_payload(&payload).expect("parse frame payload");
        match msgs.into_iter().next() {
            Some(NetworkMessage::Request(r)) => *r,
            other => panic!("expected a forwarded Request, got {other:?}"),
        }
    }

    /// The `request_id` of the single ResponseFinal recorded on a sink — the
    /// empty-route prompt final routed back to the querier.
    fn forwarded_response_final_rid(frame: &[u8]) -> u64 {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let InboundFrame::Frame { payload, .. } = parse_inbound(frame).expect("parse frame") else {
            panic!("not a Frame");
        };
        let msgs = parse_frame_payload(&payload).expect("parse payload");
        match msgs.into_iter().next() {
            Some(NetworkMessage::ResponseFinal(rf)) => rf.request_id,
            other => panic!("expected a ResponseFinal, got {other:?}"),
        }
    }

    /// A BestMatching (wire-default) Request for `keyexpr`, self-sourced (no
    /// ext_nodeid — the inbound neighbour is the querier), rid `rid`.
    fn request_best(rid: u64, keyexpr: &str) -> NetworkMessage {
        NetworkMessage::Request(Box::new(
            wz_session_core::request_build::build_request_query(rid, 0, Some(keyexpr))
                .expect("build request"),
        ))
    }

    /// A Request for `keyexpr` with an explicit [`QueryTarget`], self-sourced.
    fn request_with_target(rid: u64, keyexpr: &str, target: QueryTarget) -> NetworkMessage {
        NetworkMessage::Request(Box::new(
            wz_session_core::request_build::build_request_query_with_target(
                rid,
                0,
                Some(keyexpr),
                target,
            )
            .expect("build request"),
        ))
    }

    #[test]
    fn a_peer_request_routes_within_tier_to_a_peer_queryable() {
        // The query twin of push_peer_source_routes_within_tier: a peer-sourced
        // Query for demo/q routes along the querier's tree to the peer-tier
        // queryable C (the WITHIN-tier query route), not back to the inbound A, and
        // ALLOCATES a pending-return entry with a remapped qid.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER); // querier
        let (c, sink_c) = face(zid(0xCC), WIRE_PEER); // queryable
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_qabl("demo/q", true)); // C hosts the queryable
        sink_a.reset();
        sink_c.reset();
        forward_one(&fwd, FaceId(0), request_best(42, "demo/q"));
        assert_eq!(fwd.queries_seen.get(), 1, "the Request is counted");
        assert_eq!(
            sink_c.frame_count(),
            1,
            "routed to the peer-tier queryable C"
        );
        assert_eq!(sink_a.frame_count(), 0, "not back to the inbound querier A");
        assert_eq!(
            fwd.pending.borrow().len(),
            1,
            "a pending-return entry was allocated for the forwarded Request"
        );
        let fwd_req = forwarded_request(&sink_c.frame_bytes(0));
        assert_ne!(fwd_req.rid, 42, "rid REMAPPED to a per-face local qid");
    }

    #[test]
    fn a_peer_request_bridges_cross_mesh_to_a_router_queryable_as_master() {
        // A peer-sourced Query with NO peer-tier queryable but a ROUTER-tier one is
        // bridged across meshes (block 1, master-gated) as a SELF-origination
        // (node_id 0). Single-router => self is master => the bridge fires.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER); // peer querier
        let (r, sink_r) = face(zid(0xDD), WIRE_ROUTER); // router-tier queryable
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &r);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xDD, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_qabl("demo/q", true)); // R hosts the queryable
        sink_a.reset();
        sink_r.reset();
        forward_one(&fwd, FaceId(0), request_best(7, "demo/q"));
        assert_eq!(
            sink_r.frame_count(),
            1,
            "bridged to the router-tier queryable (self is master in single-router)"
        );
        assert_eq!(sink_a.frame_count(), 0, "not back to the peer querier");
        let fwd_req = forwarded_request(&sink_r.frame_bytes(0));
        assert_eq!(
            read_request_source(&fwd_req),
            0,
            "the cross-mesh bridge is a self-origination (node_id 0)"
        );
    }

    #[test]
    fn a_peer_request_reaches_a_client_hosted_queryable() {
        // The query twin of a_peer_push_is_delivered_to_a_subscribing_client: a
        // peer's Query reaches the CLIENT hosting the queryable (block 3,
        // master || src == Router — single-router master).
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, sink_client) = face(zid(0xAA), WIRE_CLIENT);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &client);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", true)); // client hosts it
        sink_client.reset();
        sink_p.reset();
        forward_one(&fwd, FaceId(1), request_best(9, "demo/q")); // peer queries
        assert_eq!(
            sink_client.frame_count(),
            1,
            "the peer Query reached the client-hosted queryable"
        );
        assert_eq!(
            fwd.pending.borrow().len(),
            1,
            "a pending entry keyed by the client face"
        );
    }

    #[test]
    fn a_client_request_reaches_a_mesh_queryable() {
        // The query twin of a_client_push_reaches_a_subscribing_mesh_peer: a
        // CLIENT's Query self-injects into the peer mesh toward a peer queryable
        // (the peer leg is ungated for a client source), stamped self-originated.
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, sink_client) = face(zid(0xAA), WIRE_CLIENT);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER); // peer queryable
        fwd.register(FaceId(0), &client);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_qabl("demo/q", true)); // peer hosts it
        sink_client.reset();
        sink_p.reset();
        forward_one(&fwd, FaceId(0), request_best(3, "demo/q")); // client queries
        assert_eq!(
            sink_p.frame_count(),
            1,
            "the client Query self-injected to the peer queryable"
        );
        let fwd_req = forwarded_request(&sink_p.frame_bytes(0));
        assert_eq!(
            read_request_source(&fwd_req),
            0,
            "self-originated into the mesh (node_id 0)"
        );
    }

    #[test]
    fn best_matching_prefers_a_local_client_over_a_mesh_queryable() {
        // GLOBAL BestMatching (the query-specific twist): with a COMPLETE peer
        // queryable AND a COMPLETE client queryable BOTH matching demo/q,
        // BestMatching routes to EXACTLY ONE — the LOCAL CLIENT, whose distance is
        // 1 versus the mesh queryable's per-hop link weight (~100, zenoh's default),
        // exactly as zenoh prefers a directly-attached session queryable
        // (`compute_query_route` block 3 stamps `distance: 1`, mesh qabls stamp
        // `net.distances[..] as u16`). This proves the cross-block global min (a
        // client can beat a mesh candidate) AND single-winner (not the All fan-out).
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER); // querier
        let (c, sink_c) = face(zid(0xCC), WIRE_PEER); // complete peer queryable (~100)
        let (client, sink_client) = face(zid(0xEE), WIRE_CLIENT); // complete client (distance 1)
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        fwd.register(FaceId(2), &client);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_qabl("demo/q", true)); // peer C complete
        forward_one(&fwd, FaceId(2), declare_qabl("demo/q", true)); // client complete
        sink_a.reset();
        sink_c.reset();
        sink_client.reset();
        forward_one(&fwd, FaceId(0), request_best(11, "demo/q"));
        assert_eq!(
            sink_client.frame_count(),
            1,
            "the nearer LOCAL client queryable (distance 1) wins over the mesh (~100)"
        );
        assert_eq!(
            sink_c.frame_count(),
            0,
            "BestMatching routes to ONE, not the mesh queryable too"
        );
        assert_eq!(
            fwd.pending.borrow().len(),
            1,
            "one pending entry for the single winner"
        );
    }

    #[test]
    fn best_matching_falls_back_to_all_when_no_queryable_is_complete() {
        // BestMatching with only INCOMPLETE matching queryables finds no complete
        // one and falls back to QueryTarget::All — fan out to BOTH.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER); // querier
        let (b, sink_b) = face(zid(0xBB), WIRE_PEER); // incomplete queryable
        let (c, sink_c) = face(zid(0xCC), WIRE_PEER); // incomplete queryable
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &b);
        fwd.register(FaceId(2), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        advertise_link_back(&fwd, FaceId(2), 0x01, 0xCC, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_qabl("demo/q", false));
        forward_one(&fwd, FaceId(2), declare_qabl("demo/q", false));
        sink_a.reset();
        sink_b.reset();
        sink_c.reset();
        forward_one(&fwd, FaceId(0), request_best(13, "demo/q"));
        assert_eq!(sink_b.frame_count(), 1, "fell back to All: B reached");
        assert_eq!(sink_c.frame_count(), 1, "fell back to All: C reached");
        assert_eq!(sink_a.frame_count(), 0, "never the inbound querier");
    }

    #[test]
    fn all_complete_skips_an_incomplete_queryable() {
        // QueryTarget::AllComplete fans out to EVERY complete queryable only — the
        // incomplete one is skipped even though it matches.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER); // querier
        let (b, sink_b) = face(zid(0xBB), WIRE_PEER); // COMPLETE
        let (c, sink_c) = face(zid(0xCC), WIRE_PEER); // incomplete
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &b);
        fwd.register(FaceId(2), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        advertise_link_back(&fwd, FaceId(2), 0x01, 0xCC, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_qabl("demo/q", true)); // complete
        forward_one(&fwd, FaceId(2), declare_qabl("demo/q", false)); // incomplete
        sink_a.reset();
        sink_b.reset();
        sink_c.reset();
        forward_one(
            &fwd,
            FaceId(0),
            request_with_target(15, "demo/q", QueryTarget::AllComplete),
        );
        assert_eq!(sink_b.frame_count(), 1, "the complete queryable is reached");
        assert_eq!(
            sink_c.frame_count(),
            0,
            "the incomplete queryable is skipped"
        );
    }

    #[test]
    fn all_target_fans_out_even_to_incomplete_queryables() {
        // QueryTarget::All fans out to EVERY matching queryable regardless of
        // completeness (unlike AllComplete + BestMatching).
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER);
        let (b, sink_b) = face(zid(0xBB), WIRE_PEER);
        let (c, sink_c) = face(zid(0xCC), WIRE_PEER);
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &b);
        fwd.register(FaceId(2), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        advertise_link_back(&fwd, FaceId(2), 0x01, 0xCC, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_qabl("demo/q", true)); // complete
        forward_one(&fwd, FaceId(2), declare_qabl("demo/q", false)); // incomplete
        sink_a.reset();
        sink_b.reset();
        sink_c.reset();
        forward_one(
            &fwd,
            FaceId(0),
            request_with_target(17, "demo/q", QueryTarget::All),
        );
        assert_eq!(sink_b.frame_count(), 1, "the complete queryable is reached");
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the incomplete one is ALSO reached (All)"
        );
    }

    #[test]
    fn an_unmatched_request_prompts_a_response_final_to_the_querier() {
        // zenoh route_query EMPTY route: a Query no queryable matches PROMPTS a
        // ResponseFinal back to the querier (its get() terminates at once) — no
        // pending entry is recorded.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER);
        fwd.register(FaceId(0), &a);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        fwd.tick();
        sink_a.reset();
        forward_one(&fwd, FaceId(0), request_best(21, "demo/unmatched"));
        assert_eq!(
            sink_a.frame_count(),
            1,
            "a single frame back to the querier"
        );
        assert_eq!(
            forwarded_response_final_rid(&sink_a.frame_bytes(0)),
            21,
            "the prompt ResponseFinal carries the querier's rid"
        );
        assert!(
            fwd.pending.borrow().is_empty(),
            "no pending entry for an empty route (nothing is awaited)"
        );
    }

    #[test]
    fn deregister_purges_client_qabls_and_pending_before_the_linkless_early_return() {
        // OBLIGATION-1: a Client face is linkless, so its FaceId-keyed leaf state
        // (its hosted queryables + the pending-return entries keyed by it) MUST be
        // purged BEFORE deregister's linkless early-return. A peer Query routed to
        // the client's queryable leaves a pending entry keyed by the client face;
        // deregistering the client drops both.
        let fwd = RouterForwarder::new(zid(0x01));
        let (client, _sc) = face(zid(0xAA), WIRE_CLIENT);
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER);
        fwd.register(FaceId(0), &client);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(0), declare_qabl("demo/q", true)); // client hosts it
        forward_one(&fwd, FaceId(1), request_best(31, "demo/q")); // peer queries -> routed to client
        assert_eq!(
            fwd.pending.borrow().len(),
            1,
            "a pending entry keyed by the client face"
        );
        assert!(
            fwd.client_qabls.borrow().contains_key(&FaceId(0)),
            "the client's queryable is stored"
        );
        sink_p.reset();
        fwd.deregister(FaceId(0)); // the client face goes down (linkless)
        assert!(
            !fwd.client_qabls.borrow().contains_key(&FaceId(0)),
            "client_qabls purged on face-down (OBLIGATION 1)"
        );
        assert!(
            fwd.pending.borrow().is_empty(),
            "the pending entry keyed by the departed client face is purged (OBLIGATION 1)"
        );
        // The face-down produces TWO frames to the peer querier/mesh-child:
        //  [0] the DRAINED fan's closing final (its only answering branch died —
        //      zenoh finalize_pending_queries; carries the querier's rid), then
        //  [1] the cross-tier qabl RETRACTION — self's last client queryable for
        //      "demo/q" departed, so self floods an UndeclareQueryable to the peer
        //      mesh (the debt closure: previously a no-op ⇒ staleness until self-down).
        assert_eq!(
            sink_p.frame_count(),
            2,
            "the closing final + the cross-tier qabl retraction"
        );
        assert_eq!(
            forwarded_response_final_rid(&sink_p.frame_bytes(0)),
            31,
            "the closing final carries the querier's original rid"
        );
        assert_eq!(
            forwarded_undecl_queryable_keyexpr(&sink_p.frame_bytes(1)),
            "demo/q",
            "the cross-tier advertisement for the departed client queryable is retracted"
        );
    }

    #[test]
    fn a_peer_request_bridges_cross_mesh_to_a_router_queryable_only_when_master() {
        // The query twin of push_bridges_cross_mesh_only_when_master: a peer-source
        // Query is bridged into the ROUTER mesh toward a router-tier queryable ONLY
        // when self is the elected route master (block-1 gate). With two shared
        // routers, self bridges only the keyexprs it wins the HRW election for, so
        // exactly one router bridges each Query (no double-query).
        let self_z = zid(0x01);
        let r2 = zid(0x02);
        let shared = [self_z, r2];
        let ke_master = (0..256)
            .map(|i| format!("demo/m{i}"))
            .find(|k| elect_router(&self_z, k, shared.iter()) == self_z)
            .expect("some ke elects self");
        let ke_other = (0..256)
            .map(|i| format!("demo/o{i}"))
            .find(|k| elect_router(&self_z, k, shared.iter()) == r2)
            .expect("some ke elects R2");
        let run = |ke: &str| -> (usize, usize) {
            let fwd = RouterForwarder::new(self_z);
            let (a, _sa) = face(zid(0xAA), WIRE_PEER); // peer querier + R2 discovery neighbour
            let (r, sink_r) = face(r2, WIRE_ROUTER); // the other router R2 (hosts a queryable)
            fwd.register(FaceId(0), &a);
            fwd.register(FaceId(1), &r);
            advertise_link_back(&fwd, FaceId(1), 0x01, 0x02, 5); // R2 -> routers_net
            discover_via(&fwd, FaceId(0), 0x01, 0xAA, 0x02, 7, 5); // R2 -> linkstatepeers_net
            fwd.tick();
            forward_one(&fwd, FaceId(1), declare_qabl(ke, true)); // R2 hosts a complete queryable
            sink_r.reset();
            forward_one(&fwd, FaceId(0), request_best(50, ke)); // peer queries
            (sink_r.frame_count(), fwd.shared_nodes().len())
        };
        let (master_hits, shared_len) = run(&ke_master);
        assert_eq!(shared_len, 2, "self + R2 are shared across both meshes");
        assert_eq!(
            master_hits, 1,
            "master bridges the peer-source Query to the router queryable"
        );
        let (other_hits, _) = run(&ke_other);
        assert_eq!(
            other_hits, 0,
            "a non-master suppresses the cross-mesh query bridge"
        );
    }

    #[test]
    fn client_query_delivery_deferred_on_a_non_master() {
        // The query twin of local_client_delivery_deferred_on_non_master (zenoh
        // block-3 gate): a peer-source Query for a keyexpr this router is NOT master
        // for must NOT reach the local client queryable — it defers to the master's
        // router-source query (else the client is queried twice). A ROUTER-source
        // Query (the bridged-back copy) IS delivered (src == Router, ungated).
        let self_z = zid(0x01);
        let r2 = zid(0x02);
        let shared = [self_z, r2];
        let ke_other = (0..256)
            .map(|i| format!("demo/o{i}"))
            .find(|k| elect_router(&self_z, k, shared.iter()) == r2)
            .expect("some ke elects R2 (self non-master)");
        let fwd = RouterForwarder::new(self_z);
        let (a, _sa) = face(zid(0xAA), WIRE_PEER); // peer querier + R2 discovery neighbour
        let (r, _sr) = face(r2, WIRE_ROUTER); // the shared router
        let (client, sink_client) = face(zid(0xCC), WIRE_CLIENT); // local client queryable
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &r);
        fwd.register(FaceId(2), &client);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0x02, 5); // R2 -> routers_net
        discover_via(&fwd, FaceId(0), 0x01, 0xAA, 0x02, 7, 5); // R2 -> linkstatepeers_net
        fwd.tick();
        forward_one(&fwd, FaceId(2), declare_qabl(&ke_other, true)); // client hosts a queryable
        assert_eq!(fwd.shared_nodes().len(), 2, "federated: self + R2 shared");
        assert!(
            !fwd.is_master(&ke_other),
            "self is NOT the elected master for this ke"
        );
        sink_client.reset();
        // Peer-source Query: a non-master DEFERS its local client query.
        forward_one(&fwd, FaceId(0), request_best(60, &ke_other));
        assert_eq!(
            sink_client.frame_count(),
            0,
            "non-master defers the peer-source client query (no double query)"
        );
        // Router-source Query (the bridged-back copy): delivered (src == Router).
        forward_one(&fwd, FaceId(1), request_best(61, &ke_other));
        assert_eq!(
            sink_client.frame_count(),
            1,
            "the router-source Query reaches the client queryable exactly once"
        );
    }

    #[test]
    fn all_target_routes_to_a_matching_wildcard_client_queryable() {
        // forward_request_to_clients (block-3 client fan) under QueryTarget::All:
        // a client hosting a `demo/**` queryable is queried by a `demo/data` Query
        // via the INTERSECTS predicate (wildcard-aware, the same SSOT the C3a client
        // data delivery uses) — the client-fan path BestMatching's single-winner
        // route never exercises.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER); // querier
        let (client, sink_client) = face(zid(0xCC), WIRE_CLIENT); // wildcard queryable host
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_qabl("demo/**", false)); // wildcard, incomplete
        sink_a.reset();
        sink_client.reset();
        forward_one(
            &fwd,
            FaceId(0),
            request_with_target(70, "demo/data", QueryTarget::All),
        );
        assert_eq!(
            sink_client.frame_count(),
            1,
            "the demo/** client queryable is queried by a demo/data All-target query"
        );
    }

    #[test]
    fn all_complete_routes_to_a_complete_wildcard_client_queryable() {
        // forward_request_to_clients under QueryTarget::AllComplete: a COMPLETE
        // `demo/**` client queryable is queried by a `demo/data` Query (the
        // `complete && includes` branch); an INCOMPLETE one is skipped.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER); // querier
        let (cc, sink_cc) = face(zid(0xCC), WIRE_CLIENT); // complete wildcard queryable
        let (cd, sink_cd) = face(zid(0xDD), WIRE_CLIENT); // incomplete wildcard queryable
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &cc);
        fwd.register(FaceId(2), &cd);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_qabl("demo/**", true)); // complete
        forward_one(&fwd, FaceId(2), declare_qabl("demo/**", false)); // incomplete
        sink_a.reset();
        sink_cc.reset();
        sink_cd.reset();
        forward_one(
            &fwd,
            FaceId(0),
            request_with_target(72, "demo/data", QueryTarget::AllComplete),
        );
        assert_eq!(
            sink_cc.frame_count(),
            1,
            "the complete client queryable is queried"
        );
        assert_eq!(sink_cd.frame_count(), 0, "the incomplete one is skipped");
    }

    #[test]
    fn an_unresolvable_keyexpr_alias_prompts_a_response_final() {
        // A Query whose aliased keyexpr id is unknown on the inbound face cannot be
        // routed, but the querier is TERMINATED with a prompt ResponseFinal (zenoh
        // route_query "unknown scope") rather than black-holed until its own timeout.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER);
        fwd.register(FaceId(0), &a);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        fwd.tick();
        sink_a.reset();
        // An aliased wireexpr (mapping id 9, no suffix) with no prior DeclKexpr for 9.
        let request = NetworkMessage::Request(Box::new(
            wz_session_core::request_build::build_request_query(80, 9, None)
                .expect("build request"),
        ));
        forward_one(&fwd, FaceId(0), request);
        assert_eq!(
            sink_a.frame_count(),
            1,
            "the querier is terminated with a final"
        );
        assert_eq!(
            forwarded_response_final_rid(&sink_a.frame_bytes(0)),
            80,
            "the prompt ResponseFinal carries the querier's rid"
        );
        assert!(
            fwd.pending.borrow().is_empty(),
            "no pending entry (nothing routed)"
        );
    }

    #[test]
    fn an_unresolvable_source_still_routes_the_client_and_cross_legs() {
        // The SMELL-1 fix: an unresolvable mesh SOURCE (a transit Query naming a psid
        // this node has not learned) drops ONLY the within-tier leg — the client
        // block (self-originated, master-gated) STILL routes, exactly as route_push
        // keeps its cross-mesh + client legs when the within-tier compute drops. So a
        // local client queryable is reached and the querier is NOT black-holed.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER); // peer querier
        let (client, sink_client) = face(zid(0xCC), WIRE_CLIENT); // local client queryable
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_qabl("demo/q", true)); // client hosts it
        sink_a.reset();
        sink_client.reset();
        // A Request whose ext_nodeid psid (99) is NOT mapped on A's link -> the
        // source resolves to None -> the within-tier peer leg is dropped.
        let mut req = wz_session_core::request_build::build_request_query(90, 0, Some("demo/q"))
            .expect("build request");
        set_request_source(&mut req, 99);
        forward_one(&fwd, FaceId(0), NetworkMessage::Request(Box::new(req)));
        assert_eq!(
            sink_client.frame_count(),
            1,
            "the client queryable is still reached despite the unresolvable source"
        );
        assert_eq!(
            sink_a.frame_count(),
            0,
            "not black-holed with a spurious final: the route was non-empty"
        );
    }

    // ── C5c: router query-route RESPONSE half (the reply return) ──

    /// The single forwarded Response decoded from a recorded wire frame — so a
    /// test can assert the rewritten `request_id` landed ON THE WIRE.
    fn forwarded_response(frame: &[u8]) -> wz_codecs::response::ResponseOwned {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let InboundFrame::Frame { payload, .. } = parse_inbound(frame).expect("parse frame") else {
            panic!("not a Frame");
        };
        let msgs = parse_frame_payload(&payload).expect("parse payload");
        match msgs.into_iter().next() {
            Some(NetworkMessage::Response(r)) => *r,
            other => panic!("expected a forwarded Response, got {other:?}"),
        }
    }

    #[test]
    fn a_reply_routes_back_to_the_querier_and_the_final_frees_the_entry() {
        // The full within-tier query lifecycle through the router (the twin of the
        // sibling's a_query_routes_to_a_queryable_and_the_reply_routes_back): a
        // peer querier A's Query routes to the peer queryable C with a REMAPPED
        // qid; C's Response + ResponseFinal route BACK to A with the request_id
        // rewritten to A's original rid; the final frees the entry; a straggler
        // Response after the final drops (the entry is gone). All through the
        // `forward` dispatch, so the new Response/ResponseFinal arms are covered.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER); // querier
        let (c, sink_c) = face(zid(0xCC), WIRE_PEER); // queryable
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_qabl("demo/q", true));
        sink_a.reset();
        sink_c.reset();

        forward_one(&fwd, FaceId(0), request_best(99, "demo/q"));
        let qid = forwarded_request(&sink_c.frame_bytes(0)).rid;
        assert_eq!(fwd.pending.borrow().len(), 1, "one pending entry recorded");

        // C replies: the Response routes back to A, rid rewritten, entry kept.
        let response =
            wz_session_core::response_build::build_response_reply_literal(qid, "demo/q", b"hi")
                .expect("build response");
        forward_one(
            &fwd,
            FaceId(1),
            NetworkMessage::Response(Box::new(response)),
        );
        assert_eq!(sink_a.frame_count(), 1, "the Reply routed back to A");
        assert_eq!(
            forwarded_response(&sink_a.frame_bytes(0)).request_id,
            99,
            "request_id rewritten back to the querier's rid"
        );
        assert_eq!(
            fwd.pending.borrow().len(),
            1,
            "a Response (not final) keeps the entry"
        );

        // C finalizes: the final routes back AND frees the entry.
        let rf = wz_session_core::response_final_build::build_response_final(qid);
        forward_one(&fwd, FaceId(1), NetworkMessage::ResponseFinal(rf));
        assert_eq!(sink_a.frame_count(), 2, "the final routed back to A too");
        assert_eq!(
            forwarded_response_final_rid(&sink_a.frame_bytes(1)),
            99,
            "the final's request_id rewritten back to the querier's rid"
        );
        assert!(fwd.pending.borrow().is_empty(), "the final freed the entry");

        // A straggler Response after the final: the entry is gone, drops silently.
        let straggler =
            wz_session_core::response_build::build_response_reply_literal(qid, "demo/q", b"late")
                .expect("build response");
        forward_one(
            &fwd,
            FaceId(1),
            NetworkMessage::Response(Box::new(straggler)),
        );
        assert_eq!(sink_a.frame_count(), 2, "a post-final Response drops");
    }

    #[test]
    fn a_client_queryable_reply_routes_back_to_a_mesh_querier() {
        // The CROSS-TIER return path (router-distinctive): a peer querier's Query
        // routed to a CLIENT-hosted queryable (C5b block 3); the client's Response
        // + ResponseFinal route back to the PEER querier — the return face and the
        // reply face are in DIFFERENT tiers, the tier-agnostic send_to_face.
        let fwd = RouterForwarder::new(zid(0x01));
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER); // mesh querier
        let (client, sink_client) = face(zid(0xAA), WIRE_CLIENT); // queryable host
        fwd.register(FaceId(0), &p);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_qabl("demo/q", true));
        sink_p.reset();
        sink_client.reset();

        forward_one(&fwd, FaceId(0), request_best(33, "demo/q"));
        assert_eq!(sink_client.frame_count(), 1, "the Query reached the client");
        let qid = forwarded_request(&sink_client.frame_bytes(0)).rid;

        let response =
            wz_session_core::response_build::build_response_reply_literal(qid, "demo/q", b"v")
                .expect("build response");
        forward_one(
            &fwd,
            FaceId(1),
            NetworkMessage::Response(Box::new(response)),
        );
        let rf = wz_session_core::response_final_build::build_response_final(qid);
        forward_one(&fwd, FaceId(1), NetworkMessage::ResponseFinal(rf));
        assert_eq!(
            sink_p.frame_count(),
            2,
            "the client's Reply + final routed back to the mesh querier"
        );
        assert_eq!(
            forwarded_response(&sink_p.frame_bytes(0)).request_id,
            33,
            "the reply carries the querier's original rid"
        );
        assert_eq!(
            forwarded_response_final_rid(&sink_p.frame_bytes(1)),
            33,
            "so does the closing final"
        );
        assert!(fwd.pending.borrow().is_empty(), "the final freed the entry");
    }

    #[test]
    fn an_unknown_response_qid_drops_without_routing() {
        // A Response carrying a qid this router never allocated has no pending
        // entry — it drops silently (no panic, nothing routed).
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER);
        let (c, _sc) = face(zid(0xCC), WIRE_PEER);
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick();
        sink_a.reset();
        let response =
            wz_session_core::response_build::build_response_reply_literal(42, "demo/q", b"x")
                .expect("build response");
        forward_one(
            &fwd,
            FaceId(1),
            NetworkMessage::Response(Box::new(response)),
        );
        let rf = wz_session_core::response_final_build::build_response_final(42);
        forward_one(&fwd, FaceId(1), NetworkMessage::ResponseFinal(rf));
        assert_eq!(sink_a.frame_count(), 0, "an unknown qid routes nowhere");
        assert!(fwd.pending.borrow().is_empty(), "and records nothing");
    }

    #[test]
    fn a_timed_out_query_synthesizes_err_and_final_to_the_querier() {
        // The C5c timeout sweep (zenoh QueryCleanup): a routed Query whose
        // ResponseFinal never arrives is reaped at — not before — its deadline by
        // the tick, which synthesizes an Err("Timeout") Response + the closing
        // ResponseFinal back to the querier (rid rewritten), freeing the entry.
        // Deterministic via the injected clock (base + controllable offset).
        let base = Instant::now();
        let offset = Rc::new(Cell::new(Duration::ZERO));
        let offset_clock = offset.clone();
        let fwd =
            RouterForwarder::with_clock(zid(0x01), Box::new(move || base + offset_clock.get()));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER); // querier
        let (c, sink_c) = face(zid(0xCC), WIRE_PEER); // queryable (never replies)
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick(); // flush the topology recomputes so later ticks only reap
        forward_one(&fwd, FaceId(1), declare_qabl("demo/q", true));
        sink_a.reset();
        sink_c.reset();

        forward_one(&fwd, FaceId(0), request_best(77, "demo/q"));
        assert_eq!(fwd.pending.borrow().len(), 1, "the query is pending");

        // BEFORE the deadline: the sweep reaps nothing.
        offset.set(RouterForwarder::DEFAULT_QUERY_TIMEOUT - Duration::from_millis(1));
        fwd.tick();
        assert_eq!(fwd.timed_out.get(), 0, "not reaped before the deadline");
        assert_eq!(fwd.pending.borrow().len(), 1, "still pending");
        assert_eq!(sink_a.frame_count(), 0, "nothing synthesized yet");

        // AT/PAST the deadline: reaped — the querier gets the Err + the final.
        offset.set(RouterForwarder::DEFAULT_QUERY_TIMEOUT);
        fwd.tick();
        assert_eq!(fwd.timed_out.get(), 1, "one query reaped at its deadline");
        assert!(fwd.pending.borrow().is_empty(), "the entry is freed");
        assert_eq!(
            sink_a.frame_count(),
            2,
            "the querier received the Err reply + the closing final"
        );
        assert_eq!(
            forwarded_response(&sink_a.frame_bytes(0)).request_id,
            77,
            "the Err reply carries the querier's rid"
        );
        assert_eq!(
            forwarded_response_final_rid(&sink_a.frame_bytes(1)),
            77,
            "the closing final carries the querier's rid"
        );
    }

    #[test]
    fn a_fanned_query_closes_upstream_only_after_the_last_branch_finalizes() {
        // The fan-aggregation last-out gate (zenoh Arc::into_inner in
        // finalize_pending_query): a Query fanned to TWO queryables (BestMatching
        // falls back to All — both incomplete) must close upstream exactly ONCE,
        // after BOTH branches finalize. The first branch's final is ABSORBED; a
        // reply from the still-open second branch STILL routes; the second final
        // closes the fan with a single upstream final.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER); // querier
        let (b, sink_b) = face(zid(0xBB), WIRE_PEER); // queryable 1 (incomplete)
        let (c, sink_c) = face(zid(0xCC), WIRE_PEER); // queryable 2 (incomplete)
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &b);
        fwd.register(FaceId(2), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        advertise_link_back(&fwd, FaceId(2), 0x01, 0xCC, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_qabl("demo/q", false));
        forward_one(&fwd, FaceId(2), declare_qabl("demo/q", false));
        sink_a.reset();
        sink_b.reset();
        sink_c.reset();

        forward_one(&fwd, FaceId(0), request_best(91, "demo/q"));
        assert_eq!(fwd.pending_len(), 2, "two branches pending (B and C)");
        let qid_b = forwarded_request(&sink_b.frame_bytes(0)).rid;
        let qid_c = forwarded_request(&sink_c.frame_bytes(0)).rid;

        // B finalizes FIRST: absorbed (C is still answering) — no upstream final.
        let rf_b = wz_session_core::response_final_build::build_response_final(qid_b);
        forward_one(&fwd, FaceId(1), NetworkMessage::ResponseFinal(rf_b));
        assert_eq!(
            sink_a.frame_count(),
            0,
            "the FIRST branch's final is absorbed (the fan is still open)"
        );
        assert_eq!(fwd.pending_len(), 1, "B's branch freed, C's remains");

        // C's reply AFTER B's final still routes (the fan is open).
        let response =
            wz_session_core::response_build::build_response_reply_literal(qid_c, "demo/q", b"hi")
                .expect("build response");
        forward_one(
            &fwd,
            FaceId(2),
            NetworkMessage::Response(Box::new(response)),
        );
        assert_eq!(sink_a.frame_count(), 1, "C's reply routed back to A");
        assert_eq!(forwarded_response(&sink_a.frame_bytes(0)).request_id, 91);

        // C finalizes LAST: the fan closes with exactly ONE upstream final.
        let rf_c = wz_session_core::response_final_build::build_response_final(qid_c);
        forward_one(&fwd, FaceId(2), NetworkMessage::ResponseFinal(rf_c));
        assert_eq!(
            sink_a.frame_count(),
            2,
            "exactly one upstream final, after the LAST branch"
        );
        assert_eq!(
            forwarded_response_final_rid(&sink_a.frame_bytes(1)),
            91,
            "carrying the querier's rid"
        );
        assert!(fwd.pending.borrow().is_empty(), "the fan is fully freed");
    }

    #[test]
    fn a_branch_face_down_drains_the_fan_and_finalizes_the_querier() {
        // The face-down half of the last-out gate (zenoh finalize_pending_queries):
        // a fan of two branches loses ONE queryable face — the fan stays open (the
        // other branch still answers); losing the OTHER closes it with the drained
        // final. The querier is a CLIENT face, so the mesh link-state floods the
        // deregisters trigger never pollute its sink.
        let fwd = RouterForwarder::new(zid(0x01));
        let (cq, sink_cq) = face(zid(0xEE), WIRE_CLIENT); // client querier
        let (b, _sb) = face(zid(0xBB), WIRE_PEER); // queryable 1 (incomplete)
        let (c, _sc) = face(zid(0xCC), WIRE_PEER); // queryable 2 (incomplete)
        fwd.register(FaceId(0), &cq);
        fwd.register(FaceId(1), &b);
        fwd.register(FaceId(2), &c);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        advertise_link_back(&fwd, FaceId(2), 0x01, 0xCC, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_qabl("demo/q", false));
        forward_one(&fwd, FaceId(2), declare_qabl("demo/q", false));
        sink_cq.reset();

        forward_one(&fwd, FaceId(0), request_best(41, "demo/q")); // client queries
        assert_eq!(fwd.pending_len(), 2, "fanned to both mesh queryables");

        fwd.deregister(FaceId(1)); // B dies: the fan survives on C
        assert_eq!(
            sink_cq.frame_count(),
            0,
            "no final while the other branch still answers"
        );
        assert_eq!(fwd.pending_len(), 1, "B's branch dropped, C's remains");

        fwd.deregister(FaceId(2)); // C dies: the fan is DRAINED
        assert_eq!(
            sink_cq.frame_count(),
            1,
            "the drained fan's querier received the closing final"
        );
        assert_eq!(
            forwarded_response_final_rid(&sink_cq.frame_bytes(0)),
            41,
            "carrying the querier's original rid"
        );
        assert!(fwd.pending.borrow().is_empty());
    }

    #[test]
    fn a_mesh_queryable_reply_routes_back_to_a_client_querier() {
        // The CLIENT-querier return face (the other direction of the cross-tier
        // return): a CLIENT's Query routed to a COMPLETE peer queryable
        // (BestMatching); the peer's Response + final route back to the CLIENT
        // face, rid-rewritten — the return face is a client leaf, the reply face a
        // mesh face.
        let fwd = RouterForwarder::new(zid(0x01));
        let (cq, sink_cq) = face(zid(0xEE), WIRE_CLIENT); // client querier
        let (p, sink_p) = face(zid(0xBB), WIRE_PEER); // complete peer queryable
        fwd.register(FaceId(0), &cq);
        fwd.register(FaceId(1), &p);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xBB, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_qabl("demo/q", true));
        sink_cq.reset();
        sink_p.reset();

        forward_one(&fwd, FaceId(0), request_best(51, "demo/q")); // client queries
        assert_eq!(sink_p.frame_count(), 1, "routed to the peer queryable");
        let qid = forwarded_request(&sink_p.frame_bytes(0)).rid;

        let response =
            wz_session_core::response_build::build_response_reply_literal(qid, "demo/q", b"v")
                .expect("build response");
        forward_one(
            &fwd,
            FaceId(1),
            NetworkMessage::Response(Box::new(response)),
        );
        let rf = wz_session_core::response_final_build::build_response_final(qid);
        forward_one(&fwd, FaceId(1), NetworkMessage::ResponseFinal(rf));
        assert_eq!(
            sink_cq.frame_count(),
            2,
            "the reply + final reached the CLIENT querier"
        );
        assert_eq!(
            forwarded_response(&sink_cq.frame_bytes(0)).request_id,
            51,
            "the reply carries the client's original rid"
        );
        assert_eq!(
            forwarded_response_final_rid(&sink_cq.frame_bytes(1)),
            51,
            "so does the closing final"
        );
    }

    #[test]
    fn an_ext_timeout_overrides_the_relay_default_deadline() {
        // zenoh route_query arms the pending deadline from the Query's OWN
        // carried ext_timeout (`ext_timeout.unwrap_or(queries_default_timeout)`,
        // dispatcher/queries.rs:514) — the router must honor it, not its 10s
        // knob: a 5ms ext on an un-answered query is reaped at 5ms.
        let base = Instant::now();
        let offset = Rc::new(Cell::new(Duration::ZERO));
        let offset_clock = offset.clone();
        let fwd =
            RouterForwarder::with_clock(zid(0x01), Box::new(move || base + offset_clock.get()));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER); // querier
        let (c, _sc) = face(zid(0xCC), WIRE_PEER); // queryable (never replies)
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick(); // flush the topology recomputes so later ticks only reap
        forward_one(&fwd, FaceId(1), declare_qabl("demo/q", true));
        sink_a.reset();
        let request = NetworkMessage::Request(Box::new(
            wz_session_core::request_build::build_request_query_with_timeout_ms(
                90,
                0,
                Some("demo/q"),
                5,
            )
            .expect("build request"),
        ));
        forward_one(&fwd, FaceId(0), request);
        assert_eq!(fwd.pending_len(), 1, "the branch is pending");
        offset.set(Duration::from_millis(4));
        fwd.tick();
        assert_eq!(
            fwd.pending_timed_out(),
            0,
            "not reaped before the ext deadline"
        );
        offset.set(Duration::from_millis(5));
        fwd.tick();
        assert_eq!(
            fwd.pending_timed_out(),
            1,
            "reaped AT the Query's own 5ms ext_timeout, not the 10s default"
        );
        assert_eq!(
            sink_a.frame_count(),
            2,
            "the querier received the Err + the closing final"
        );
    }

    #[test]
    fn an_empty_keyexpr_err_reply_is_relayed_not_dropped() {
        // The multi-hop timeout-Err path: a DOWNSTREAM relay's synthesized
        // Err("Timeout") carries the EMPTY wireexpr (zenoh WireExpr::empty()).
        // The router must pass it THROUGH with only the rid rewritten (zenoh
        // route_send_response does no keyexpr resolution), not drop it at
        // resolve_wireexpr.
        let fwd = RouterForwarder::new(zid(0x01));
        let (a, sink_a) = face(zid(0xAA), WIRE_PEER); // querier
        let (c, sink_c) = face(zid(0xCC), WIRE_PEER); // queryable
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xAA, 5);
        advertise_link_back(&fwd, FaceId(1), 0x01, 0xCC, 5);
        fwd.tick();
        forward_one(&fwd, FaceId(1), declare_qabl("demo/q", true));
        sink_a.reset();
        sink_c.reset();
        forward_one(&fwd, FaceId(0), request_best(95, "demo/q"));
        let qid = forwarded_request(&sink_c.frame_bytes(0)).rid;
        let err = wz_session_core::response_build::build_response_err_empty(qid, b"Timeout")
            .expect("build err");
        forward_one(&fwd, FaceId(1), NetworkMessage::Response(Box::new(err)));
        assert_eq!(
            sink_a.frame_count(),
            1,
            "the empty-keyexpr Err was RELAYED to the querier, not dropped"
        );
        assert_eq!(
            forwarded_response(&sink_a.frame_bytes(0)).request_id,
            95,
            "with the rid rewritten to the querier's"
        );
    }

    /// R311wt-mc slice 1 — the EGRESS-only multicast group plane: an attached
    /// group receives a routed Put as a `MulticastTxItem::Push` (carrying the
    /// reliable flag), and the echo guard suppresses a multicast-sourced Push
    /// (zenoh's both-multicast egress deny, `hat/router/mod.rs:813`). The
    /// broadcast is UNCONDITIONAL — no subscriber is registered here, yet the
    /// group still receives it (zenoh's flat append, `pubsub.rs:1334`).
    #[cfg(feature = "transport-multicast")]
    #[test]
    fn mcast_group_receives_routed_push_and_echo_guards() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        fwd.attach_mcast_group(tx);
        let push =
            wz_session_core::push_build::build_push_literal("demo/data", b"payload").expect("push");

        // A Put whose source is NOT a multicast face broadcasts to the group,
        // UNCONDITIONALLY (no matching sub is registered on this forwarder).
        fwd.broadcast_to_mcast_groups(true, Priority::DEFAULT, &push, "demo/data", false, false);
        let item = rx.try_recv().expect("the routed Put reached the group");
        assert!(
            matches!(item, MulticastTxItem::Push { reliable: true, .. }),
            "broadcast as a reliable MulticastTxItem::Push"
        );

        // Echo guard: a Push whose source IS a multicast face is not re-broadcast.
        fwd.broadcast_to_mcast_groups(true, Priority::DEFAULT, &push, "demo/data", true, false);
        assert!(
            rx.try_recv().is_err(),
            "a multicast-sourced Push must not echo back to a group"
        );
    }

    /// R311y188 — router-multicast-faces slice 3: a REAL routed Push (driven
    /// through `forward` -> `route_push`, not a direct `broadcast_to_mcast_groups`
    /// call as slice 1's unit did) reaches an attached multicast group at the
    /// `route_push` tail — UNCONDITIONALLY, with no subscriber registered for the
    /// keyexpr (zenoh's flat `mcast_groups` append outside the sub-gated walk,
    /// `hat/router/pubsub.rs:1334`). This closes the forwarder->sender half of the
    /// egress composition; the sender->group socket half is the Layer M loopback
    /// e2e `router_egress_helper_reaches_group_subscriber`.
    #[cfg(feature = "transport-multicast")]
    #[test]
    fn routed_push_broadcasts_to_attached_mcast_group() {
        let fwd = RouterForwarder::new(zid(0x01));
        // A peer inbound face so `route_push` resolves the inbound keyexpr (it
        // early-returns on an unregistered face); NO subscriber is registered, so
        // the sub-gated fan-out drops — only the unconditional group broadcast fires.
        let (a_p, _sink_p) = face(zid(0xAA), WIRE_PEER);
        fwd.register(FaceId(0), &a_p);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        fwd.attach_mcast_group(tx);

        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push)));

        let item = rx
            .try_recv()
            .expect("the routed Push reached the group via the route_push tail");
        let MulticastTxItem::Push { push, reliable, .. } = item else {
            panic!("expected a MulticastTxItem::Push");
        };
        assert!(reliable, "broadcast on the reliable channel");
        // The group leaf shares NO alias table, so resolve the egressed keyexpr
        // against an EMPTY table (the leaf's view): a literal push forwards verbatim
        // and stays resolvable — a wrong/stale keyexpr would fail this.
        let empty: hashbrown::HashMap<u64, String> = hashbrown::HashMap::new();
        assert_eq!(
            resolve_wireexpr(&push.keyexpr.body, &empty).as_deref(),
            Some("demo/data"),
            "the group receives a resolvable literal keyexpr"
        );
    }

    /// R311y189 — the reliteralization guard the literal-only tests structurally
    /// missed (IMPL-review CONFIRMED): a router forwards an ALIASED (id-only) inbound
    /// push to a multicast group. A group leaf shares NO expr-id alias table with the
    /// router, so the egress MUST re-literalize — an aliased id would otherwise be an
    /// unresolvable blackhole (the same reason every sibling egress leg literalizes,
    /// `deliver_to_client_subscribers` / `compute_self_publish_forward`). Modeled by
    /// resolving the egressed keyexpr against an EMPTY table (the leaf's view): it
    /// must be the literal "demo/data", NOT the aliased id 7.
    #[cfg(feature = "transport-multicast")]
    #[test]
    fn aliased_routed_push_is_reliteralized_for_the_mcast_group() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (a_p, _sink_p) = face(zid(0xAA), WIRE_PEER);
        fwd.register(FaceId(0), &a_p);
        // The inbound face declares an expr-id alias 7 -> "demo/data" (the wire's
        // bandwidth-efficient shape), populating the face's keyexpr_table.
        let kexpr = NetworkMessage::Declare(Box::new(
            wz_session_core::declare_build::build_declare_kexpr(7, "demo/data").expect("kexpr"),
        ));
        forward_one(&fwd, FaceId(0), kexpr);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        fwd.attach_mcast_group(tx);

        // A pure-aliased push (id 7, no suffix): route_push resolves it via the face
        // table, and the egress must re-literalize before enqueuing to the group.
        let aliased =
            wz_session_core::push_build::build_push_aliased(7, None, b"payload").expect("aliased");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(aliased)));

        let item = rx
            .try_recv()
            .expect("the aliased routed Push reached the group");
        let MulticastTxItem::Push { push, .. } = item else {
            panic!("expected a MulticastTxItem::Push");
        };
        // The group leaf has NO alias table: resolve against an empty one. The
        // aliased id 7 would resolve to None (blackhole); the reliteralized literal
        // resolves to "demo/data".
        let empty: hashbrown::HashMap<u64, String> = hashbrown::HashMap::new();
        assert_eq!(
            resolve_wireexpr(&push.keyexpr.body, &empty).as_deref(),
            Some("demo/data"),
            "the mcast egress must re-literalize the aliased push (id 7 -> literal) \
             or a group leaf with no alias table blackholes it"
        );
    }

    /// R311y197 (I3b slice 1) — the Designated-Router egress gate is a NO-OP for
    /// the sole on-group router: an empty member set elects `self_zid`
    /// (`elect_router`'s empty-candidate arm) ⇒ self is the DR ⇒ group egress is
    /// unconditional, exactly the shipped single-router / egress-only behavior.
    #[cfg(feature = "router-multicast-faces")]
    #[test]
    fn mcast_egress_unconditional_when_sole_on_group_router() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (a_p, _sink_p) = face(zid(0xAA), WIRE_PEER);
        fwd.register(FaceId(0), &a_p);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        fwd.attach_mcast_group(tx);
        // An explicit empty relay is equivalent to never relaying: no other
        // on-group router ⇒ self is the DR for every keyexpr.
        fwd.set_mcast_group_members(&[]);

        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push)));

        assert!(
            rx.try_recv().is_ok(),
            "the sole on-group router is the DR ⇒ egress is unconditional"
        );
    }

    /// R311y197 (I3b slice 1) — a NON-DR on-group router SUPPRESSES its group
    /// egress. With a second on-group router whose zid out-hashes self for the
    /// keyexpr, all on-group routers agree that the OTHER router is the DR, so
    /// self must not egress — otherwise two routers both egress the same Put to
    /// the group (double egress / the seed of the two-router re-egress loop).
    #[cfg(feature = "router-multicast-faces")]
    #[test]
    fn mcast_egress_suppressed_for_non_dr() {
        let self_zid = zid(0x01);
        let fwd = RouterForwarder::new(self_zid);
        let (a_p, _sink_p) = face(zid(0xAA), WIRE_PEER);
        fwd.register(FaceId(0), &a_p);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        fwd.attach_mcast_group(tx);

        // HRW is ~uniform, so some zid always out-hashes self for the keyexpr.
        let key = "demo/data";
        let winner = (2u8..=255)
            .map(zid)
            .find(|cand| elect_router(&self_zid, key, [self_zid, *cand].iter()) == *cand)
            .expect("some zid out-hashes self for the keyexpr");
        fwd.set_mcast_group_members(&[winner.as_slice().to_vec()]);

        let push =
            wz_session_core::push_build::build_push_literal(key, b"payload").expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push)));

        assert!(
            rx.try_recv().is_err(),
            "a non-DR on-group router suppresses group egress (I3b loop-safety)"
        );
    }

    /// R311y197 (I3b slice 1) — the gate is a per-keyexpr ELECTION, not a blanket
    /// "any other member ⇒ suppress": with a member that LOSES the HRW to self,
    /// self is the elected DR and egresses normally even though the member set is
    /// non-empty.
    #[cfg(feature = "router-multicast-faces")]
    #[test]
    fn mcast_egress_fires_for_the_dr_with_members_present() {
        let self_zid = zid(0x01);
        let fwd = RouterForwarder::new(self_zid);
        let (a_p, _sink_p) = face(zid(0xAA), WIRE_PEER);
        fwd.register(FaceId(0), &a_p);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        fwd.attach_mcast_group(tx);

        let key = "demo/data";
        let loser = (2u8..=255)
            .map(zid)
            .find(|cand| elect_router(&self_zid, key, [self_zid, *cand].iter()) == self_zid)
            .expect("some zid loses to self for the keyexpr");
        fwd.set_mcast_group_members(&[loser.as_slice().to_vec()]);

        let push =
            wz_session_core::push_build::build_push_literal(key, b"payload").expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push)));

        assert!(
            rx.try_recv().is_ok(),
            "self is the elected DR (member loses the HRW) ⇒ egress fires"
        );
    }

    /// R311y197 (I3b) — a NON-DR router still egresses its OWN local unicast
    /// client's Put to the group: the DR gate applies ONLY to mesh-sourced Puts
    /// (`source_is_mesh`), never to local produce. Without this a client on a
    /// non-DR router would be STARVED from the group (the mesh is sub-gated, so
    /// the DR never receives the Put to relay it — IMPL Lens-C). Client inbound
    /// ⇒ tier=Client ⇒ source_is_mesh=false ⇒ unconditional egress.
    #[cfg(feature = "router-multicast-faces")]
    #[test]
    fn mcast_local_client_egress_is_not_dr_gated() {
        let self_zid = zid(0x01);
        let fwd = RouterForwarder::new(self_zid);
        let (cli, _sink) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &cli);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        fwd.attach_mcast_group(tx);

        // A member that out-hashes self ⇒ self is NOT the DR for the keyexpr.
        let key = "demo/data";
        let winner = (2u8..=255)
            .map(zid)
            .find(|cand| elect_router(&self_zid, key, [self_zid, *cand].iter()) == *cand)
            .expect("some zid out-hashes self for the keyexpr");
        fwd.set_mcast_group_members(&[winner.as_slice().to_vec()]);

        let push =
            wz_session_core::push_build::build_push_literal(key, b"payload").expect("build push");
        forward_one(&fwd, FaceId(0), NetworkMessage::Push(Box::new(push)));

        assert!(
            rx.try_recv().is_ok(),
            "a non-DR router MUST still egress its OWN local client's Put to the group \
             (DR gate is mesh-sourced-only; else the client starves)"
        );
    }

    /// §5.21 router-multicast-faces (sub plane, S2) — a group SUBSCRIBER keyexpr
    /// relayed via `set_mcast_group_subs` is ADVERTISED into the unicast mesh as a
    /// self-sourced `DeclareSubscriber` (so a mesh-side publisher routes matching
    /// Puts toward this router and they reach the on-group subscriber — the
    /// cross-router reachability limit (a) resolved); removing the last group sub
    /// floods the WITHDRAWAL. The wz analog of zenoh registering a `mcast_faces`
    /// Client-face sub under the router's own zid (`pubsub.rs:245`).
    #[cfg(feature = "router-multicast-faces")]
    #[test]
    fn mcast_group_sub_advertises_and_withdraws_into_mesh() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (c, sink_c) = face(zid(0xCC), WIRE_PEER); // a linkstatepeer tree child
        fwd.register(FaceId(0), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xCC, 5);
        fwd.tick();
        sink_c.reset();

        fwd.set_mcast_group_subs(&["demo/data".to_string()]);
        assert_eq!(
            sink_c.frame_count(),
            1,
            "a group sub is advertised into the mesh (self-sourced sub to the child)"
        );
        match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(_) => {}
            other => panic!("expected a DeclareSubscriber advertisement, got {other:?}"),
        }
        sink_c.reset();

        fwd.set_mcast_group_subs(&[]);
        assert_eq!(
            sink_c.frame_count(),
            1,
            "removing the last group sub withdraws the advertisement from the mesh"
        );
        match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(_) => {}
            other => panic!("expected an UndeclareSubscriber withdrawal, got {other:?}"),
        }
    }

    /// §5.21 sub plane (S2) — a group sub is the THIRD `self_advertises_sub_into`
    /// contributor (alongside local client subs and opposite-mesh natives) AND folds
    /// into the tick re-advertise SSOT (`derived_cross_tier_subs_into`) so a late
    /// joiner converges on the group's bubble. Derive-level pin of the fold.
    #[cfg(feature = "router-multicast-faces")]
    #[test]
    fn mcast_group_sub_folds_into_self_advertise_derive() {
        let fwd = RouterForwarder::new(zid(0x01));
        assert!(!fwd.self_advertises_sub_into(FaceTier::LinkstatePeers, "demo/k"));
        fwd.set_mcast_group_subs(&["demo/k".to_string()]);
        assert!(
            fwd.self_advertises_sub_into(FaceTier::LinkstatePeers, "demo/k"),
            "a group sub makes self advertise interest (the third contributor)"
        );
        assert!(
            fwd.derived_cross_tier_subs_into(FaceTier::LinkstatePeers)
                .contains(&"demo/k".to_string()),
            "the tick re-advertise SSOT includes the group sub (late-joiner convergence)"
        );
        fwd.set_mcast_group_subs(&[]);
        assert!(
            !fwd.self_advertises_sub_into(FaceTier::LinkstatePeers, "demo/k"),
            "removing the group sub clears the derive (no client / native holds it)"
        );
    }

    /// §5.23 adminspace-router-linkstate — a self-hosted admin queryable is a
    /// self-sourced contributor to the cross-tier qabl derive (the query-plane
    /// twin of the group_subs sub-plane fold above): registering it must make it
    /// advertise into BOTH meshes AND fold into the tick re-advertise SSOT
    /// (`derived_cross_tier_qabls_into`) so a router/peer joining LATER converges
    /// on it. This is the fast, derive-level pin of the CROSS-NODE fold the
    /// `--ignored` Layer E7c e2e proves over the wire (a `cargo test --lib` guard
    /// against a regression that removes the `local_queryables` fold).
    #[test]
    fn local_queryable_folds_into_the_cross_tier_qabl_derive() {
        use wz_session_core::query_sink::{QueryView, ReplyOut};
        let fwd = RouterForwarder::new(zid(0x01));
        let key = "@/self/router/**";
        // Before registration: neither the derive set nor the merged info holds it.
        for tier in [FaceTier::Routers, FaceTier::LinkstatePeers] {
            assert!(!fwd
                .derived_cross_tier_qabls_into(tier)
                .contains(&key.to_string()));
            assert!(fwd.derived_cross_tier_qabl_info(tier, key).is_none());
        }
        let handler: LocalQueryHandler = Box::new(|_v: &dyn QueryView, _o: &mut dyn ReplyOut| {});
        fwd.register_local_queryable(key, true, handler);
        // After: BOTH meshes carry it in the re-advertise SSOT + the merged info
        // (the fold; without it a startup-registered admin qabl is unreachable by a
        // late joiner).
        for tier in [FaceTier::Routers, FaceTier::LinkstatePeers] {
            assert!(
                fwd.derived_cross_tier_qabls_into(tier)
                    .contains(&key.to_string()),
                "the self-hosted admin qabl folds into the {tier:?} re-advertise SSOT"
            );
            assert!(
                fwd.derived_cross_tier_qabl_info(tier, key).is_some(),
                "the {tier:?} derived merged info includes the self-hosted qabl"
            );
        }
    }

    /// §5.21 sub plane (S2) — union-refcount with a local client: a client sub AND a
    /// group sub for the same keyexpr; removing the group sub must NOT withdraw the
    /// mesh advertisement while the client still holds it (the R311y120 black-hole
    /// guard — `withdraw_group_cross_tier_sub` reuses `self_advertises_sub_into`).
    #[cfg(feature = "router-multicast-faces")]
    #[test]
    fn mcast_group_sub_union_refcounts_with_a_local_client() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (cli, _s) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &cli);
        forward_one(&fwd, FaceId(0), declare_sub("demo/k")); // a local client sub
        assert!(fwd.any_client_subscribes("demo/k"));
        fwd.set_mcast_group_subs(&["demo/k".to_string()]);
        fwd.set_mcast_group_subs(&[]); // group sub leaves; client still holds it
        assert!(
            fwd.self_advertises_sub_into(FaceTier::LinkstatePeers, "demo/k"),
            "a client sub keeps the advertisement after the group sub leaves (no black-hole)"
        );
    }

    /// §5.21 sub plane (S2) — re-relaying the SAME group-sub aggregate is a no-op
    /// (the diff is empty), so an unchanged set never re-floods the mesh.
    #[cfg(feature = "router-multicast-faces")]
    #[test]
    fn mcast_group_sub_reset_is_idempotent() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (c, sink_c) = face(zid(0xCC), WIRE_PEER);
        fwd.register(FaceId(0), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xCC, 5);
        fwd.tick();
        fwd.set_mcast_group_subs(&["demo/k".to_string()]);
        sink_c.reset();
        fwd.set_mcast_group_subs(&["demo/k".to_string()]);
        assert_eq!(
            sink_c.frame_count(),
            0,
            "an unchanged group-sub set does not re-advertise"
        );
    }

    /// §5.21 sub plane (S2) — flip-edge invariant across contributor classes: a group
    /// sub advertises a keyexpr into the mesh; a LATER local client for the SAME
    /// keyexpr must NOT re-flood (group is already the `true` contributor, so the
    /// client is not the false->true edge). Regression for the IMPL-review should-fix
    /// (`advertise_client_cross_tier_sub` now skips when `group_subscribes`).
    #[cfg(feature = "router-multicast-faces")]
    #[test]
    fn mcast_group_sub_advertise_is_flip_edge_idempotent_with_a_later_client() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (c, sink_c) = face(zid(0xCC), WIRE_PEER); // a linkstatepeer flood target
        fwd.register(FaceId(0), &c);
        advertise_link_back(&fwd, FaceId(0), 0x01, 0xCC, 5);
        fwd.tick();
        let (cli, _s) = face(zid(0xDD), WIRE_CLIENT);
        fwd.register(FaceId(1), &cli);

        fwd.set_mcast_group_subs(&["demo/k".to_string()]); // group advertises (1 frame to C)
        sink_c.reset();
        forward_one(&fwd, FaceId(1), declare_sub("demo/k")); // a LATER client for the same K
        assert_eq!(
            sink_c.frame_count(),
            0,
            "a later client for an already-group-advertised keyexpr does not re-flood"
        );
    }

    /// R311y194 — router-multicast-faces INGRESS slice (I1): a LITERAL Push
    /// received on the multicast ingress face routes to a unicast (client) leaf
    /// subscriber via `route_mcast_ingress` — the wz analog of zenoh routing a
    /// `new_peer_multicast` DeMux ingress to local subs (`router.rs:213`). The
    /// synthetic `MCAST_INGRESS_FACE` id is disjoint from the client's FaceId, so
    /// the Client-tier source self-skip excludes no real subscriber.
    #[cfg(feature = "transport-multicast")]
    #[test]
    fn mcast_ingress_literal_push_delivers_to_a_client_subscriber() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (cb, sink_cb) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &cb);
        forward_one(&fwd, FaceId(0), declare_sub("demo/data"));
        sink_cb.reset();

        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        fwd.route_mcast_ingress(Priority::DEFAULT, true, &push);

        assert_eq!(
            sink_cb.frame_count(),
            1,
            "a literal mcast-ingress Push delivers once to the matching client sub"
        );
    }

    /// R311y194 — echo guard (zenoh both-multicast deny, `hat/router/mod.rs:812`):
    /// a Push RECEIVED on the multicast ingress face is NOT re-broadcast to an
    /// attached multicast group (mcast->mcast is denied), so `route_mcast_ingress`
    /// threads `inbound_is_mcast = true` into the group-broadcast tail.
    #[cfg(feature = "transport-multicast")]
    #[test]
    fn mcast_ingress_push_is_echo_guarded_off_the_groups() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        fwd.attach_mcast_group(tx);

        let push = wz_session_core::push_build::build_push_literal("demo/data", b"payload")
            .expect("build push");
        fwd.route_mcast_ingress(Priority::DEFAULT, true, &push);

        assert!(
            rx.try_recv().is_err(),
            "a multicast-ingress Push must not echo back out to a multicast group"
        );
    }

    /// R311y194 — I1 is LITERAL-ONLY: an ALIASED (id-only) Push received on the
    /// single group-ingress face has NO per-peer alias table on the router (the
    /// deferred I3 per-peer `mcast_faces` plane), so `resolve_inbound_keyexpr`
    /// resolves the sentinel against an EMPTY table -> None -> the Push is dropped
    /// (never mis-resolved against a colliding peer expr-id). The literal test
    /// above DOES deliver through the same entry, so this pins the aliased-drop,
    /// not a dead entry.
    #[cfg(feature = "transport-multicast")]
    #[test]
    fn mcast_ingress_drops_an_aliased_id_only_push() {
        let fwd = RouterForwarder::new(zid(0x01));
        let (cb, sink_cb) = face(zid(0xCC), WIRE_CLIENT);
        fwd.register(FaceId(0), &cb);
        forward_one(&fwd, FaceId(0), declare_sub("demo/data"));
        sink_cb.reset();

        // An aliased push (id 7, no suffix): the sentinel ingress face has no alias
        // table, so it resolves to None and is dropped (no delivery).
        let aliased =
            wz_session_core::push_build::build_push_aliased(7, None, b"payload").expect("aliased");
        fwd.route_mcast_ingress(Priority::DEFAULT, true, &aliased);

        assert_eq!(
            sink_cb.frame_count(),
            0,
            "an aliased id-only mcast-ingress Push has no per-peer alias table (I1) \
             and is dropped, not mis-delivered"
        );
    }
}
