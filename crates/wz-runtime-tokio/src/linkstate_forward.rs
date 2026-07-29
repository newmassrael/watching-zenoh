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
//! link change, with NO periodic keepalive. A self-link change floods the zenoh
//! MINIMAL DELTA (D4), not the full topology: on `register` the NEW face is
//! bootstrapped with the full topology while EXISTING faces get only a 2-entry
//! `[neighbour zid-only, self links-only]` delta ([`flood_link_added`](LinkstateForwarder::flood_link_added));
//! on `deregister` every surviving face gets a 1-entry `[self links-only]` delta
//! ([`flood_self_links_changed`](LinkstateForwarder::flood_self_links_changed)).
//! An inbound change re-floods transitively via `forward`'s `propagate`. Reliable transport
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
//! SSOT. Data-plane keyexpr ALIASES are resolved (c3c-3 B1): a peer's sourced
//! `Declare(DeclKexpr)` records `id -> keyexpr` in the inbound face's link-local
//! table ([`absorb_keyexpr_declaration`](LinkstateForwarder::absorb_keyexpr_declaration)),
//! a `Push` carrying that alias is resolved via the shared `resolve_wireexpr`
//! SSOT, and the forward NORMALIZES the keyexpr to a literal so the downstream
//! link (which does not share the inbound link's alias table) can resolve it.
//! The CONTROL plane resolves aliases too (c3c-3 B1b): a `DeclareSubscriber` /
//! `UndeclareSubscriber` whose keyexpr (or `ext_keyexpr`) is aliased is resolved
//! against the inbound face's table and re-flooded NORMALIZED to a literal, so
//! the data and control planes share the alias machinery. Normalize-to-literal
//! is a deliberate DIVERGENCE from zenoh, which re-aliases per outbound face
//! (`Resource::decl_key`); wz keeps no outbound alias table, so it always emits
//! literals (the cost is wire verbosity, not correctness). Still deferred: the
//! `Details` topology optimisation (D4) and wildcard keyexpr intersection (the
//! filter is exact-match, B2). `routing-peer`-gated.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sce_forge_runtime::codec::CodecError;
use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant};
use wz_codecs::ext_entry::ExtEntryOwned;
use wz_codecs::interest::InterestOwned;
use wz_codecs::linkstate_list::LinkstateListOwned;
use wz_codecs::oam::OamOwned;
use wz_codecs::push::{PushOwned, PushOwnedVariant};
use wz_codecs::request::RequestOwned;
use wz_codecs::response::ResponseOwned;
use wz_codecs::response_final::ResponseFinalOwned;
use wz_codecs::wireexpr::WireexprOwned;
use wz_session_core::declare_build::{
    build_declare_final_reply, build_declare_queryable, build_declare_queryable_reply,
    build_declare_queryable_reply_with_id, build_declare_queryable_with_id_info,
    build_declare_subscriber, build_declare_subscriber_reply,
    build_declare_subscriber_reply_with_id, build_undeclare_queryable,
    build_undeclare_queryable_with_keyexpr, build_undeclare_subscriber,
    build_undeclare_subscriber_with_keyexpr, set_declare_queryable_info,
};
use wz_session_core::declare_ext_keyexpr::resolve_ext_keyexpr;
use wz_session_core::declare_routing_context::{read_declare_source, set_declare_source};
use wz_session_core::driver_loop::DriverLoopOutcome;
use wz_session_core::keyexpr_match::{
    keyexpr_includes_target, keyexpr_intersects_target, keyexpr_pattern_matches,
};
use wz_session_core::linkstate_oam::{
    build_linkstate_oam_owned, try_parse_linkstate_oam, LinkstateOam,
};
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::push_build::{
    build_push_literal, build_push_literal_with_meta, reliteralize_push, set_push_keyexpr_literal,
};
use wz_session_core::push_routing_context::{
    read_push_hoplimit, read_push_source, set_push_hoplimit, set_push_source,
};
// R311y220 — the QoS priority band the forwarder's `fan_out_qos` / `publish_qos`
// twins thread down to `SessionLinkActions::send_network_message_qos`. Ungated: the
// base `fan_out` / `publish` delegators reference `Priority::DEFAULT` unconditionally
// (this whole module is `#[cfg(feature = "routing-peer")]`, which force-pulls
// `codec-push`, so the referenced symbol is always live — never an unused import).
use wz_session_core::qos::Priority;
use wz_session_core::query::{QueryReply, QueryResponder};
use wz_session_core::query_mode::QueryTarget;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::queryable_info::QueryableInfo;
use wz_session_core::reliability::Reliability;
use wz_session_core::request_build::set_request_keyexpr_literal;
use wz_session_core::request_routing_context::{
    read_request_source, read_request_target, read_request_timeout_ms, set_request_source,
};
use wz_session_core::response_build::set_response_keyexpr_literal;
use wz_session_core::sample::Sample;
use wz_session_core::sample_kind::SampleKind;
use wz_session_core::sink::{BorrowedSample, SampleView};
use wz_session_core::wireexpr_resolve::{resolve_wireexpr, wireexpr_is_empty};

use wz_routing_graph::{Changes, LinkId, LinkstateNetwork};

use crate::accept_loop::{DialIntent, DialIntentReceiver, DialIntentSender, FaceForwarder, FaceId};
use crate::future_interest::{FutureQablStore, FutureSubStore};
use crate::interceptor::{InterceptorChain, InterceptorContext, InterceptorFlow};
use crate::linkstate_interest::LinkstatepeerInterest;
use crate::linkstate_pending::{ExpiredQuery, PendingQueries, QueryFan};
use crate::session_glue::{IterationEvent, SessionLinkActions};

/// Re-export `Zid`, the typed [`WhatAmI`] role, and the gossip
/// [`AutoConnect`] policy so the peer-loop caller (the demo) names them by the
/// same SSOT type (defined in `wz-codecs` / the graph), not a bare byte. A deploy
/// opting into autoconnect builds its policy from [`default_autoconnect_matcher`]
/// (this module) + these re-exports, so the `router|peer` matcher is never
/// re-typed at the call site.
pub use wz_routing_graph::{AutoConnect, AutoConnectStrategy, WhatAmI, Zid};
// R311tt — re-export the §5.16 access-control policy-construction surface
// beside `set_interceptors`, so a deploy builds an `AclPolicy` from one facade
// path (`wz::runtime_tokio::linkstate_forward::{AclPolicy, ..}`) — the same
// convenience the AutoConnect re-export above gives the autoconnect opt-in.
// Gated on `access-acl` (the enforcer + its engine compile only with it).
#[cfg(feature = "access-acl")]
pub use wz_access_control::{
    AclConfig, AclFlow, AclMessage, AclPolicy, AclRule, Permission, SubjectSelector,
};
// R311tw — the downsampling rule type, re-exported beside the other rule types
// so a deploy builds it from the same facade path as the ACL types above.
#[cfg(feature = "access-downsampling")]
pub use crate::interceptor::downsampling::DownsamplingRule;
// R311tx — the low-pass (per-key payload-size limit) rule type, re-exported
// beside the other rule types (the §5.16 access-quota realization).
#[cfg(feature = "access-quota")]
pub use crate::interceptor::low_pass::LowPassRule;
// R311ty — the combined interceptor configuration, the single funnel a deploy
// fills and installs via `set_interceptors` (the wz mirror of zenoh's
// interceptor_factories(config)). Re-exported beside the rule types above so a
// deploy builds the whole pipeline from one facade path.
pub use crate::interceptor::InterceptorConfig;
// The gossip-target role set lives in the codec layer beside `WhatAmI`; the
// forwarder consumes it to gate which faces a link-state flood reaches.
use wz_codecs::whatami::WhatAmIMatcher;

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
    /// `SessionLinkActions`), so the event-driven self-floods
    /// ([`LinkstateForwarder::flood_link_added`] / `flood_self_links_changed`)
    /// and the register-time bootstrap can push the local link-state out on it.
    actions: Arc<SessionLinkActions>,
    /// The graph link this face maps to, once its peer zid surfaced at
    /// register — an inbound list is ingested against it (its psid<->zid
    /// mappings resolve the list). `None` for a face held without a routing
    /// identity: no graph link, so nothing to ingest against and no bootstrap
    /// target.
    link: Option<LinkId>,
    /// This face's link-local keyexpr-alias table (c3c-3 B1): `id -> literal
    /// keyexpr`, populated from sourced `Declare(DeclKexpr)` messages the peer
    /// sent on THIS link and consulted (via the shared
    /// [`resolve_wireexpr`](wz_session_core::wireexpr_resolve::resolve_wireexpr)
    /// SSOT) to resolve an aliased keyexpr a later `Push` / `DeclareSubscriber`
    /// carries. Per-face because keyexpr aliasing is a per-transport negotiation
    /// in zenoh (`hashbrown` to match `resolve_wireexpr`'s table type).
    keyexpr_table: hashbrown::HashMap<u64, String>,
}

/// The default gossip target for a node of role `whatami` — zenoh's
/// `scouting.gossip.target` per-local-whatami default
/// (`commons/zenoh-config/src/defaults.rs`): a ROUTER or PEER gossips its
/// link-state to routers and peers (`router|peer`); a CLIENT gossips to nobody
/// (the empty set — a client floods no link-state). The
/// [`LinkstateForwarder::new`] seed for its own role; a deploy config-sources a
/// different set via [`LinkstateForwarder::set_gossip_target`].
const fn default_gossip_target(whatami: WhatAmI) -> WhatAmIMatcher {
    match whatami {
        WhatAmI::Router | WhatAmI::Peer => WhatAmIMatcher::empty().router().peer(),
        WhatAmI::Client => WhatAmIMatcher::empty(),
    }
}

/// The default gossip-AUTOCONNECT matcher for a node of role `whatami` — zenoh's
/// `scouting.gossip.autoconnect` per-local default
/// (`commons/zenoh-config/src/defaults.rs`), the SIBLING of
/// [`default_gossip_target`] and DELIBERATELY a different profile: a PEER
/// autoconnects to discovered routers and peers (`router|peer`), but a ROUTER
/// autoconnects to NOBODY (the empty set — routers are reached via configured
/// links, not gossip-dialed), as does a CLIENT. The role-correct matcher a
/// deploy passes to [`AutoConnect::new`] when it opts a node into autoconnect, so
/// the `router|peer` literal is never re-hardcoded at the (role-blind) call site
/// — a router that hardcoded `router|peer` would wrongly dial discovered peers.
pub const fn default_autoconnect_matcher(whatami: WhatAmI) -> WhatAmIMatcher {
    match whatami {
        WhatAmI::Peer => WhatAmIMatcher::empty().router().peer(),
        WhatAmI::Router | WhatAmI::Client => WhatAmIMatcher::empty(),
    }
}

/// The interest table + the per-peer value to register into it, bundled for the
/// shared [`forward_interest_declaration`](LinkstateForwarder::forward_interest_declaration)
/// seam: the table's `V` ties the value's type (subs pass `((), &subs)`,
/// queryables pass `(info, &qabls)`), and the bundle keeps the seam within the
/// argument budget (a param-object, the R311lw precedent, not a `#[allow]`).
struct InterestRegistration<'t, V> {
    table: &'t RefCell<LinkstatepeerInterest<V>>,
    value: V,
}

/// The id-keyed co-attached CLIENT-queryable store ([`client_qabls`](LinkstateForwarder#structfield.client_qabls)):
/// per client `FaceId`, the client's declaration `id -> (keyexpr, QueryableInfo)` so an
/// id-only `UndeclareQueryable` resolves the (ke, info) by id (R311y178 id-map).
type ClientQabls = HashMap<FaceId, HashMap<u64, (String, QueryableInfo)>>;

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
    /// Total unsolicited FUTURE `DeclareSubscriber` pushes emitted (R311y158) — a
    /// NEW subscription told to a CLIENT face whose stored FUTURE interest predated
    /// it ([`push_future_subscription`](Self::push_future_subscription)), the
    /// peer-tier twin of the router's `future_pushes`. The sole wz cause of a
    /// pub-before-sub publisher's write-filter deactivation; surfaced by `run_peer`
    /// as the peer-mode analogue of the router-hat `pushed a future subscriber`
    /// witness (the peer-mode cross-impl e2e that consumes it is a named follow-up).
    future_pushes: Cell<usize>,
    /// Total unsolicited FUTURE `DeclareQueryable` pushes emitted (R311y158) — the
    /// query-plane twin ([`push_future_queryable`](Self::push_future_queryable)),
    /// the peer-tier analogue of the router's `future_qabl_pushes`.
    future_qabl_pushes: Cell<usize>,
    /// The linkstate-peer subscription interest table (c3c-3 atom2): which
    /// peers are interested in which keyexpr, learned from sourced
    /// `DeclareSubscriber`s flooded across the mesh. The HAT-analogue interest
    /// state the data-route filter (atom4) reads to bound the Push fan-out to
    /// interested subtrees, INCLUDING this node's own subscription (registered
    /// under its own zid, zenoh-faithful — see [`LinkstatepeerInterest`]). The
    /// data-route filter reads the self-excluding
    /// [`interested_remote`](crate::linkstate_interest::LinkstatepeerInterest::interested_remote)
    /// view. `RefCell` by the same single-task contract as the graph — borrowed
    /// only for a handler's synchronous duration.
    subs: RefCell<LinkstatepeerInterest<()>>,
    /// Co-attached CLIENT subscriptions (R311y163 / D4) — per-client-face leaf
    /// store, the peer-tier twin of the router's
    /// [`client_subs`](crate::router_forward::RouterForwarder). A CLIENT is a leaf
    /// (zenoh `session_ctxs`), never a link-state graph node, so its interest
    /// cannot live in the zid-keyed [`subs`](Self#structfield.subs) tier table; it
    /// is held here FaceId-keyed for (a) local delivery of a matching Push
    /// ([`deliver_to_client_subscribers`](Self::deliver_to_client_subscribers), C3a)
    /// and (b) the face-down / graceful-undeclare withdraw. The MESH advertisement
    /// of a client sub rides `subs` under SELF's zid (self-sourced, exactly as
    /// zenoh's `register_linkstatepeer_subscription(.., tables.zid)`), UNION-refcounted
    /// with any self-native local sub on the same keyexpr so the last source's
    /// departure — client OR self-native — is what withdraws + floods the forget
    /// ([`withdraw_mesh_sub_if_unbacked`](Self::withdraw_mesh_sub_if_unbacked)).
    ///
    /// ID-KEYED (`declaration id -> keyexpr`, R311y178) — the token-plane shape (zenoh
    /// `face_hat.remote_subs` id-keyed, `forget_simple_subscription` removes BY ID,
    /// linkstate_peer/pubsub.rs). A real client's graceful `UndeclareSubscriber` is
    /// ID-ONLY (`send_undeclare_subscriber(id)`, no `ext_keyexpr`), so
    /// [`withdraw_client_subscription`](Self::withdraw_client_subscription) resolves the
    /// keyexpr BY ID (was a keyexpr-set that no-op'd an id-only undeclare -> stale until
    /// face-down). Per-FaceId namespace, so two clients may reuse an id.
    client_subs: RefCell<HashMap<FaceId, HashMap<u64, String>>>,
    /// The linkstate-peer QUERYABLE interest table — the query-plane twin of
    /// [`subs`](Self#structfield.subs), learned from sourced `DeclareQueryable`s
    /// flooded across the mesh (zenoh's per-`Resource` `linkstatepeer_qabls`,
    /// `hat/linkstate_peer/mod.rs:517`). The SAME generic
    /// [`LinkstatepeerInterest`] type, a SEPARATE instance: subscriptions bound a
    /// Push fan-out, queryables bound a Query fan-out (the Request routing that
    /// reads this lands in the next atom). Populated by
    /// [`forward_queryable`](Self::forward_queryable); a peer's interest is
    /// purged whole on its face-down (`purge_detached_interest`). `RefCell` by
    /// the same single-task contract as `subs`.
    qabls: RefCell<LinkstatepeerInterest<QueryableInfo>>,
    /// Co-attached CLIENT queryables HOSTED by this peer (the query-plane twin of
    /// [`client_subs`](Self#structfield.client_subs)) — per-client-face
    /// `keyexpr -> QueryableInfo`. A CLIENT is a leaf (zenoh `session_ctxs`), never
    /// a graph node, so its DeclareQueryable cannot ride the zid-keyed
    /// [`qabls`](Self#structfield.qabls) tier table under its OWN zid
    /// (`resolve_source` finds no psid → the declare is dropped). It is held here for
    /// (a) local query DELIVERY — a routed Query matching it is fanned to the client
    /// face + a pending return entry allocated
    /// ([`forward_request_to_client_queryables`](Self::forward_request_to_client_queryables))
    /// — and (b) the face-down / graceful-undeclare withdraw. The MESH ADVERTISEMENT
    /// rides `qabls` under SELF's zid (self-sourced, exactly as zenoh's
    /// `register_linkstatepeer_queryable(.., tables.zid)`), carrying the MERGED
    /// [`QueryableInfo`] over every self-source
    /// ([`derived_self_qabl_info`](Self::derived_self_qabl_info)) — so a second
    /// complete co-host UPGRADES the advert and a contributor's departure DOWNGRADES
    /// it ([`withdraw_mesh_qabl_if_unbacked`](Self::withdraw_mesh_qabl_if_unbacked)),
    /// the qabl-specific refinement over the sub union-refcount (subs carry no info).
    /// ID-KEYED (`declaration id -> (keyexpr, QueryableInfo)`, R311y178) — the token-plane
    /// shape (zenoh `face_hat.remote_qabls` id-keyed, `forget_simple_queryable` removes BY
    /// ID, linkstate_peer/queries.rs). A real client's graceful `UndeclareQueryable` is
    /// ID-ONLY (`send_undeclare_queryable(id)`, no `ext_keyexpr`), so
    /// [`withdraw_client_queryable`](Self::withdraw_client_queryable) resolves the keyexpr
    /// BY ID (was keyexpr-keyed -> an id-only undeclare no-op'd -> stale until face-down).
    /// The value carries the `QueryableInfo` so a face declaring the SAME ke under two ids
    /// folds BOTH infos in [`derived_self_qabl_info`](Self::derived_self_qabl_info) (the
    /// keyexpr-keyed map structurally overwrote — one slot per ke). Per-FaceId namespace.
    /// The wz-peer client-sub + client-qabl planes are now BOTH id-keyed; the ROUTER
    /// (`router_forward.rs` client_subs/client_qabls) still carries the keyexpr-keyed gap
    /// as a named symmetric follow-up (its client_tokens was already id-keyed at slice-3).
    client_qabls: RefCell<ClientQabls>,
    /// FUTURE-mode subscriber-interest store (R311y146) — which CLIENT faces
    /// declared a FUTURE (`f()`) subscriber `Interest`, and which
    /// `DeclareSubscriber`s this peer has pushed back to them (zenoh's per-`FaceState`
    /// `remote_interests` + `face_hat.local_subs`). The CURRENT half of the
    /// handshake is [`respond_to_interest`](Self::respond_to_interest)'s dump; this
    /// is the FUTURE half: a subscriber learned LATER — from the mesh
    /// ([`forward_subscription`](Self::forward_subscription)) or this node's own
    /// local declaration ([`declare_subscription`](Self::declare_subscription)) — is
    /// proactively pushed via [`push_future_subscription`](Self::push_future_subscription)
    /// so a pub-BEFORE-sub client publisher's write-filter deactivates. FaceId-keyed
    /// leaf state, purged UNCONDITIONALLY in
    /// [`deregister`](FaceForwarder::deregister) (a client face has `link == None`,
    /// mirroring the router's OBLIGATION-1). SUBS plane only (the QABL future-push is
    /// the value-aware [`future_qabls`](Self#structfield.future_qabls) below).
    future_subs: RefCell<FutureSubStore>,
    /// The QUERYABLE-plane FUTURE store (R311y150) — the value-aware twin of
    /// [`future_subs`](Self#structfield.future_subs): a queryable learned LATER
    /// (self-local [`declare_queryable`](Self::declare_queryable) or mesh
    /// [`forward_queryable`](Self::forward_queryable)) is proactively pushed via
    /// [`push_future_queryable`](Self::push_future_queryable) so a querier-BEFORE-
    /// queryable querier's write-filter deactivates, and a completeness flip
    /// re-pushes the same id. Same OBLIGATION-1 purge as `future_subs`.
    future_qabls: RefCell<FutureQablStore>,
    /// The pending-query RETURN table (query-routing atom 3): the
    /// per-outbound-face `out qid -> (inbound face, inbound rid)` map that routes
    /// a routed Query's `Response` / `ResponseFinal` BACK to the querier — the wz
    /// analogue of zenoh's per-`FaceState` `pending_queries`.
    /// [`forward_request`](Self::forward_request) allocates a qid + records a
    /// mapping per outbound face; [`forward_response`](Self::forward_response)
    /// peeks it and [`forward_response_final`](Self::forward_response_final) takes
    /// (frees) it; `deregister` drops a departed face's entries. `RefCell` by the
    /// same single-task contract as the interest tables.
    pending: RefCell<PendingQueries>,
    /// R311y44 (§5.23 Phase 2a) — queryables HOSTED BY THIS NODE with a
    /// reply-producing handler (distinct from [`qabls`](Self#structfield.qabls),
    /// which only tracks remote interest for ROUTING). A routed Query whose only
    /// match is one of these reaches the empty-route branch of
    /// [`forward_request`](Self::forward_request) (self is excluded from query
    /// routing) and is dispatched to the matching handler, whose replies unwind
    /// back to the querier via the existing return path. `RefCell` (the handler is
    /// `FnMut`) by the same single-task contract; no `Send` (the handler may
    /// capture an `Rc` — the §5.23 combined node's shared `WzConfig` in Phase 2b).
    local_queryables: RefCell<Vec<LocalQueryable>>,
    /// R311y46 (§5.23 Phase 3a) — subscribers HOSTED BY THIS NODE with a handler:
    /// the Push-plane twin of [`local_queryables`](Self#structfield.local_queryables).
    /// A Put matching one is delivered to its handler at the Push ingress (in
    /// ADDITION to the remote fan-out — [`forward_push`](Self::forward_push) excludes
    /// self, so this is the local-delivery seam). `RefCell` (the handler is `FnMut`)
    /// by the same single-task contract; no `Send` (a handler may capture an `Rc` —
    /// the §5.23 config-write handler's shared `WzConfig` in Phase 3b).
    local_subscribers: RefCell<Vec<LocalSubscriber>>,
    /// #3-c (R311y167) — the bounded self-echo redelivery queue for
    /// [`dispatch_local_subscribers`](Self::dispatch_local_subscribers). A
    /// `LocalSubscriber` is a SYNCHRONOUS `FnMut` — zenoh's *callback* subscriber,
    /// which re-enters itself on a self-echo and recurses to a stack overflow. When
    /// a handler, mid-fire, re-drives a matching Put to ITSELF, `try_borrow_mut`
    /// cannot re-enter the busy handler; instead of DROPPING the sample (the y156
    /// skip) this queues the busy handler's `Rc` + an OWNED copy and REDELIVERS at
    /// the outermost [`forward`](FaceForwarder::forward) exit — making the
    /// synchronous callback subscriber behave like zenoh's DEFAULT (channel)
    /// handler, whose `sender.send` decouples the self-put into a queue drained on
    /// the receiver's next poll (handlers/mod.rs:38-41 + handlers/fifo.rs:57-66),
    /// never a silent drop. Overflow is drop-OLDEST past
    /// [`SELF_ECHO_QUEUE_CAP`](Self::SELF_ECHO_QUEUE_CAP) (a RingChannel,
    /// handlers/ring.rs) — the default FifoChannel BLOCKS when full, but
    /// backpressure is impossible single-task (the drainer IS the enqueuer's task,
    /// so blocking self-deadlocks), so drop-oldest is the forced faithful bound.
    /// This is the single-task twin of the Session-tier
    /// [`DeferredListenerCell`](wz_session_core::deferred_fire::DeferredListenerCell)
    /// (which cannot serve here: it requires `Send` + `Arc<Mutex>` + an `R: Runtime`;
    /// this forwarder is non-`Send` `Rc`/`RefCell`, single-task, un-parameterized).
    /// Purged on [`undeclare_subscription`](Self::undeclare_subscription) so a queued
    /// echo for a retracted handler is not redelivered. `RefCell` / no `Send` by the
    /// single-task contract (it holds the non-`Send` handler `Rc`).
    sub_redelivery: RefCell<VecDeque<(Rc<RefCell<LocalSubscriberHandler>>, Sample)>>,
    /// #3-c QUERY half (R311y168) — the query-plane twin of
    /// [`sub_redelivery`](Self#structfield.sub_redelivery): deferred self-queries (a
    /// queryable that re-queried its OWN ke while answering, so `try_borrow_mut`
    /// found it busy). The busy handler(s) + the query return context (rid / keyexpr
    /// / inbound face / reliability) are held here with the closing `ResponseFinal`
    /// SUPPRESSED, and redelivered at the outermost
    /// [`forward`](FaceForwarder::forward) exit -- reply-before-final preserved (the
    /// query plane cannot emit the Final eagerly the way the fire-and-forget sub
    /// plane can, or the querier discards the redelivered reply -- zenoh removes the
    /// query on ResponseFinal, session.rs:3023). Bounded drop-oldest by
    /// [`SELF_ECHO_QUEUE_CAP`](Self::SELF_ECHO_QUEUE_CAP); purged of a retracted
    /// queryable's handler on [`undeclare_queryable`](Self::undeclare_queryable) (the
    /// record survives so the Final still terminates the querier). `RefCell` / no
    /// `Send`, single-task.
    query_redelivery: RefCell<VecDeque<DeferredQuery>>,
    /// #3-c (R311y167) — re-entrancy depth of
    /// [`forward`](FaceForwarder::forward). The self-echo drain runs only at the
    /// OUTERMOST `forward` (depth 1, BEFORE the decrement), so a handler re-driving
    /// a Put from inside its callback — or from inside the drain — re-enters at
    /// depth >= 2 and does not re-trigger the drain. `Cell` by the single-task
    /// contract.
    forward_depth: Cell<u32>,
    /// R311y219b (transport-multilink) — joined aggregated link FaceId -> the
    /// session's PRIMARY registered FaceId. A second+ physical link aggregated onto
    /// a peer's session (`join_link`) is not `register`ed as its own face, so its
    /// inbound reaches [`forward`](FaceForwarder::forward) tagged with its own id,
    /// which is absent from [`faces`](Self#structfield.faces). [`forward`] resolves
    /// that id through this map to the primary BEFORE the delivery gates
    /// (`forward_push` / `dispatch_local_subscribers` early-return on
    /// `faces.get(inbound)=None`), so the aggregate presents ONE logical face to
    /// routing (the faithful zenoh model: an aggregated transport is one FaceState) —
    /// closing the joined-face delivery gap. Populated by
    /// [`register_joined`](FaceForwarder::register_joined) at the loop's JOIN,
    /// cleared by [`deregister_joined`](FaceForwarder::deregister_joined) on the
    /// joined link's death.
    joined_faces: RefCell<HashMap<FaceId, FaceId>>,
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
    /// The set of neighbour roles this peer gossips its link-state to (zenoh's
    /// `gossip_target`). A face whose handshake `whatami` is outside this set is
    /// skipped by every link-state flood ([`fan_out`](Self::fan_out)'s gossip
    /// gate), exactly like zenoh's per-target `send_on_link`
    /// (`hat/p2p_peer/gossip.rs:238-252`). Seeded per THIS node's role via
    /// [`default_gossip_target`] (the zenoh `scouting.gossip.target` default: a
    /// router or peer gossips to `router|peer`, a client to nobody) and
    /// config-sourceable by a deploy through [`set_gossip_target`](Self::set_gossip_target).
    /// `Cell` because the matcher is `Copy` and set through `&self`, like the
    /// other policy knobs.
    gossip_target: Cell<WhatAmIMatcher>,
    /// The gossip autoconnect policy (zenoh `AutoConnect`): whether a peer this
    /// node DISCOVERS off a gossip flood should be dialed (the role matcher + zid
    /// tie-break). Default [`AutoConnect::disabled`] — an empty matcher, so the
    /// ingest emit gate is always false and a default driver produces no
    /// dial-intents (the signature-stable prior behaviour). A deploy opts in via
    /// [`enable_autoconnect`](Self::enable_autoconnect). `Cell` because the policy
    /// is `Copy` and set once at setup through `&self`, like the other knobs.
    autoconnect: Cell<AutoConnect>,
    /// The sending end of the dial-intent channel, installed by
    /// [`enable_autoconnect`](Self::enable_autoconnect). `None` until autoconnect
    /// is enabled — the ingest emit is then a no-op. The accept loop holds the
    /// matching [`DialIntentReceiver`] and turns each intent into an outbound dial
    /// (A5c).
    dial_tx: RefCell<Option<DialIntentSender>>,

    /// R311tt — the §5.16 access-control INGRESS interceptor chain, consulted
    /// once per inbound message at the top of [`forward`](Self::forward), ahead
    /// of the kind-dispatch (the mesh-RELAY admission point). EMPTY by default =
    /// access control disabled (zenoh `AclConfig.enabled = false`, every message
    /// admitted); a deploy installs the chain via
    /// [`set_interceptors`](Self::set_interceptors). `RefCell` because the chain
    /// is set through a `&self` config seam, the same shape as the other knobs.
    ingress_interceptors: RefCell<InterceptorChain>,
    /// R311tv — the §5.16 access-control EGRESS interceptor chain, consulted per
    /// OUTBOUND message in [`fan_out`](Self::fan_out) keyed by the DESTINATION
    /// face's subject — the wz analogue of zenoh's `EgressAclEnforcer` in the
    /// `Mux`, the twin of the ingress chain. EMPTY by default. It is what gates
    /// this node's OWN originations (a `publish` never crosses `forward`, only
    /// `fan_out`), so ingress alone could not cover them.
    egress_interceptors: RefCell<InterceptorChain>,
    /// R311tt — count of messages ANY interceptor dropped, on either flow: an ACL
    /// denial, a downsampling rate-limit, or a low-pass size-cap — the shared
    /// interceptor-drop witness, the drop twin of
    /// [`data_seen`](Self#structfield.data_seen) the e2e/unit tests assert against.
    /// (zenoh keeps a per-interceptor stat; wz collapses to one count — a coarser
    /// witness, since the chain's `admit` returns a single bool and does not
    /// attribute the drop to a specific interceptor.)
    interceptor_dropped: Cell<usize>,
    /// The per-query timeout — how long a forwarded Query's pending return entry
    /// lives before [`tick`](FaceForwarder::tick) abandons it (zenoh's
    /// `queries_default_timeout`, default 10s). `forward_request` stamps each
    /// allocated entry with `Instant::now() + this`; the tick sweep reaps any
    /// past its deadline. `Cell` because it is `Copy` and set through a `&self`
    /// config seam, like the other policy knobs.
    query_timeout: Cell<Duration>,
    /// Count of pending query BRANCHES reaped by the timeout sweep — the GC
    /// witness, the timeout twin of [`recomputes`](Self#structfield.recomputes).
    /// Rises once per abandoned branch (a queryable that never sent its
    /// `ResponseFinal` on a still-up face; a 2-branch fan expiring counts 2);
    /// `0` on a healthy mesh where every branch finalizes.
    timed_out: Cell<usize>,
    /// The monotonic clock the pending-query deadlines are stamped + reaped
    /// against — `Instant::now` in production ([`new`](Self::new) /
    /// [`with_trees_delay`](Self::with_trees_delay)), injectable via
    /// [`with_clock`](Self::with_clock) so a deterministic test can advance "now"
    /// and assert a query is reaped AT — not before — its deadline. (`Instant` is
    /// opaque, so a fake clock returns `base + offset`; the base cancels in every
    /// deadline comparison, leaving the offset as the controllable virtual time.)
    clock: Box<dyn Fn() -> Instant>,
    /// R311y450 — THIS node's §5.18 wall-clock HLC, the source of the forward-path
    /// timestamp [`forward_push`](Self::forward_push) applies. A DIFFERENT axis
    /// from `clock` above, which is the opaque MONOTONIC clock for query
    /// deadlines: this one is a wall-clock NTP64 that goes on the wire, and the
    /// two are deliberately not the same value (`wz-runtime-core`'s `TimeSource`
    /// excludes the wall clock for exactly that reason).
    ///
    /// Built once from this peer's `self_zid` + `self_whatami` against zenoh's
    /// shipped `timestamping.enabled` map, so on a `WhatAmI::Peer` — the only role
    /// this forwarder is constructed with today — it holds NO clock and the
    /// forward path is byte-identical to the pre-R311y450 wire. That is parity,
    /// not an omission: zenoh ships `enabled: { router: true, peer: false,
    /// client: false }`, so a peer that stamped would diverge from upstream in the
    /// direction a foreign subscriber can see.
    node_hlc: crate::node_clock::NodeHlc,
}

/// R311y44 (§5.23 Phase 2a) — the heap handler backing a [`LocalQueryable`]: the
/// SAME `FnMut(&dyn QueryView, &mut dyn ReplyOut)` shape the Session-level
/// `declare_queryable` uses (`query_sink::BoxedQueryFn`), MINUS the `Send +
/// 'static` bound — the forwarder is single-task, so a handler may capture an
/// `Rc` (Phase 2b's shared `WzConfig`). Factored to a `type` per
/// `clippy::type_complexity` (the two nested trait-object args), as `query_sink`
/// does for its `Send` variant.
pub(crate) type LocalQueryHandler = Box<dyn FnMut(&dyn QueryView, &mut dyn ReplyOut)>;

/// R311y44 (§5.23 Phase 2a) — a queryable HOSTED BY THIS NODE: its declared
/// keyexpr + completeness + the reply-producing handler. A self-targeted Query is
/// dispatched to the matching handler(s). `pub(crate)` so the [`RouterForwarder`]
/// (`router_forward.rs`) reuses the SAME type for its own self-host store (§5.23
/// adminspace-router-linkstate) rather than duplicating it.
pub(crate) struct LocalQueryable {
    pub(crate) keyexpr: String,
    pub(crate) complete: bool,
    /// `Rc<RefCell<…>>` so [`dispatch_local_queryables`](LinkstateForwarder::dispatch_local_queryables)
    /// can clone the handle out under a short borrow, drop the `local_queryables`
    /// borrow, and only THEN invoke — a handler may re-entrantly register /
    /// undeclare a local queryable (incl. self-undeclare) without panicking the
    /// outer `RefCell`. See that method's re-entrancy contract.
    pub(crate) handler: Rc<RefCell<LocalQueryHandler>>,
}

/// #3-c QUERY half (R311y168) — a self-query DEFERRED for redelivery: the busy
/// queryable handler(s) that could not answer inline (mid-fire on the stack) plus
/// the return context needed to emit their replies + the HELD closing
/// `ResponseFinal` at the outermost `forward` exit. The query twin of the
/// sub-plane's `(handler, Sample)` queue entry, carrying the extra query context
/// (rid / keyexpr / face) the Final-hold needs (a query, unlike a fire-and-forget
/// Put, has a return path + a terminating Final).
struct DeferredQuery {
    handlers: Vec<Rc<RefCell<LocalQueryHandler>>>,
    rid: u64,
    keyexpr: String,
    inbound: FaceId,
    reliable: bool,
}

/// R311y46 (§5.23 Phase 3a) — the heap handler backing a [`LocalSubscriber`]:
/// `FnMut(&dyn SampleView)` (the SAME view a Session subscriber callback reads),
/// MINUS `Send` — the forwarder is single-task, so a handler may capture an `Rc`
/// (Phase 3b's shared `WzConfig`). Factored to a `type` per
/// `clippy::type_complexity`, as `LocalQueryHandler` is.
type LocalSubscriberHandler = Box<dyn FnMut(&dyn SampleView)>;

/// R311y46 (§5.23 Phase 3a) — a subscriber HOSTED BY THIS NODE: its declared
/// keyexpr (a PATTERN) + the handler. A Put whose concrete key the pattern matches
/// is delivered to the handler (the Push-plane twin of [`LocalQueryable`]).
struct LocalSubscriber {
    keyexpr: String,
    /// `Rc<RefCell<…>>` — the Push-plane twin of [`LocalQueryable`]'s handler:
    /// [`dispatch_local_subscribers`](LinkstateForwarder::dispatch_local_subscribers)
    /// clones the handle out under a short borrow, drops the `local_subscribers`
    /// borrow, then invokes, so a handler may re-entrantly register / undeclare a
    /// local subscriber (incl. self-undeclare) without a `RefCell` panic.
    handler: Rc<RefCell<LocalSubscriberHandler>>,
}

/// A minimal [`QueryView`] over a routed Request's resolved fields, for
/// dispatching to a local queryable handler. Parameters / attachment are not
/// threaded in Phase 2a (the §5.23 admin handler reads only the keyexpr); a
/// future handler that needs them adds the plumbing. `is_local` / `source_info`
/// fall through to the trait defaults (wire origin, no source info).
pub(crate) struct LocalQueryView<'a> {
    pub(crate) keyexpr: &'a str,
    pub(crate) rid: u64,
}

impl QueryView for LocalQueryView<'_> {
    fn keyexpr(&self) -> &str {
        self.keyexpr
    }
    fn parameters(&self) -> Option<&[u8]> {
        None
    }
    fn attachment(&self) -> Option<&[u8]> {
        None
    }
    fn rid(&self) -> u64 {
        self.rid
    }
}

impl LinkstateForwarder {
    /// The default coalescing window — zenoh's `TREES_COMPUTATION_DELAY_MS`
    /// (`hat/mod.rs:56`). The SPF-throttle delay a [`new`](Self::new) forwarder
    /// uses unless [`with_trees_delay`](Self::with_trees_delay) overrides it.
    pub const DEFAULT_TREES_DELAY: Duration = Duration::from_millis(100);

    /// The default per-query timeout — zenoh's `queries_default_timeout`
    /// (`commons/zenoh-config/src/defaults.rs`, 10000ms). A forwarded Query's
    /// pending return entry is abandoned this long after it is recorded if no
    /// `ResponseFinal` has routed back. A deploy overrides via
    /// [`set_query_timeout`](Self::set_query_timeout).
    pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_millis(10_000);

    /// A driver seeded with the local node (this peer's zid + whatami), using the
    /// default [`DEFAULT_TREES_DELAY`](Self::DEFAULT_TREES_DELAY) recompute window.
    pub fn new(self_zid: Zid, self_whatami: WhatAmI) -> Self {
        Self::with_trees_delay(self_zid, self_whatami, Self::DEFAULT_TREES_DELAY)
    }

    /// As [`new`](Self::new), but with an explicit spanning-tree recompute
    /// coalescing window (the SPF-throttle delay D2c debounces topology changes
    /// by). A shorter window converges faster at the cost of more frequent
    /// recomputes under churn; a longer one coalesces a heavier burst. This tunes
    /// the single coalescing path — it does not turn coalescing off.
    pub fn with_trees_delay(self_zid: Zid, self_whatami: WhatAmI, trees_delay: Duration) -> Self {
        Self::build(self_zid, self_whatami, trees_delay, Box::new(Instant::now))
    }

    /// Construct with an INJECTED monotonic clock (dependency injection for
    /// deterministic pending-query-timeout tests) and the default recompute
    /// window. Production uses [`new`](Self::new) (the `Instant::now` clock); a
    /// test passes a controllable `base + offset` closure to advance "now" across
    /// a deadline and prove a query is reaped at — not before — its deadline.
    pub fn with_clock(
        self_zid: Zid,
        self_whatami: WhatAmI,
        clock: Box<dyn Fn() -> Instant>,
    ) -> Self {
        Self::build(self_zid, self_whatami, Self::DEFAULT_TREES_DELAY, clock)
    }

    /// The inner constructor every public constructor funnels through, so the
    /// field initialiser lives ONCE (only the recompute delay + the clock vary).
    fn build(
        self_zid: Zid,
        self_whatami: WhatAmI,
        trees_delay: Duration,
        clock: Box<dyn Fn() -> Instant>,
    ) -> Self {
        Self {
            net: Rc::new(RefCell::new(LinkstateNetwork::new(self_zid, self_whatami))),
            // R311y450 — this node's §5.18 clock, derived from the SAME identity
            // and role the net above is seeded with, so the timestamping gate can
            // never disagree with the role this forwarder actually plays.
            node_hlc: crate::node_clock::NodeHlc::for_node(
                self_zid.as_slice(),
                self_whatami,
                crate::node_clock::TimestampingEnabled::default(),
            ),
            faces: RefCell::new(HashMap::new()),
            ingested: Cell::new(0),
            data_seen: Cell::new(0),
            future_pushes: Cell::new(0),
            future_qabl_pushes: Cell::new(0),
            subs: RefCell::new(LinkstatepeerInterest::new()),
            client_subs: RefCell::new(HashMap::new()),
            qabls: RefCell::new(LinkstatepeerInterest::new()),
            client_qabls: RefCell::new(HashMap::new()),
            future_subs: RefCell::new(FutureSubStore::new()),
            future_qabls: RefCell::new(FutureQablStore::new()),
            pending: RefCell::new(PendingQueries::new()),
            local_queryables: RefCell::new(Vec::new()),
            local_subscribers: RefCell::new(Vec::new()),
            sub_redelivery: RefCell::new(VecDeque::new()),
            query_redelivery: RefCell::new(VecDeque::new()),
            forward_depth: Cell::new(0),
            joined_faces: RefCell::new(HashMap::new()),
            trees_dirty: Cell::new(false),
            trees_delay,
            recomputes: Cell::new(0),
            // The gossip target default for THIS node's role (zenoh's per-local
            // `scouting.gossip.target`): router|peer for a router/peer, empty for
            // a client. A deploy overrides via `set_gossip_target`.
            gossip_target: Cell::new(default_gossip_target(self_whatami)),
            // autoconnect off by default (an empty matcher) -> the ingest emit
            // gate is always false, so a default driver produces no dial-intents.
            autoconnect: Cell::new(AutoConnect::disabled(self_zid)),
            dial_tx: RefCell::new(None),
            // Access control off by default (an empty chain) — every inbound
            // message admitted, exactly as zenoh's `AclConfig.enabled = false`.
            ingress_interceptors: RefCell::new(InterceptorChain::new()),
            egress_interceptors: RefCell::new(InterceptorChain::new()),
            interceptor_dropped: Cell::new(0),
            query_timeout: Cell::new(Self::DEFAULT_QUERY_TIMEOUT),
            timed_out: Cell::new(0),
            clock,
        }
    }

    /// Advertise self's dial locators (its listen addresses) — they ride every
    /// FULL flood self originates, so a neighbour learns where to reach this
    /// peer (the discovery data a gossip/autoconnect consumer dials). The driver
    /// sets this ONCE at startup, before the first face registers, so self's
    /// very first flood already carries them. Signature-stable: a driver that
    /// never calls this advertises no locators (the prior behaviour exactly).
    pub fn set_self_locators(&self, locators: Vec<String>) {
        self.net.borrow_mut().set_self_locators(locators);
    }

    /// Override the per-query timeout (zenoh's `queries_default_timeout`) — how
    /// long a forwarded Query's pending return entry lives before the tick sweep
    /// abandons it. The [`with_trees_delay`](Self::with_trees_delay) /
    /// [`new`](Self::new) default is
    /// [`DEFAULT_QUERY_TIMEOUT`](Self::DEFAULT_QUERY_TIMEOUT) (10s); a deploy
    /// tunes it, a test drives a short (or zero) window. Set through `&self` like
    /// the other policy knobs; takes effect on the NEXT `forward_request`
    /// (already-recorded deadlines are not retroactively changed).
    pub fn set_query_timeout(&self, timeout: Duration) {
        self.query_timeout.set(timeout);
    }

    /// The current instant from the injected clock — the SINGLE read site the
    /// pending-query deadline stamp ([`forward_request`](Self::forward_request))
    /// and the timeout sweep ([`reap_timed_out_queries`](Self::reap_timed_out_queries))
    /// share, so an injected test clock governs both halves of the deadline check.
    fn now(&self) -> Instant {
        (self.clock)()
    }

    /// Override the gossip target — the set of neighbour roles this node floods
    /// its link-state to (zenoh's `scouting.gossip.target`). The
    /// [`new`](Self::new) default is [`default_gossip_target`] for this node's
    /// role; a deploy config-sources a different set here (e.g. a router that
    /// gossips only to routers). The config seam symmetric to the other policy
    /// knobs ([`enable_autoconnect`](Self::enable_autoconnect),
    /// [`LinkstateNetwork::set_gossip_multihop`](wz_routing_graph::LinkstateNetwork::set_gossip_multihop));
    /// a driver that never calls it keeps the per-role default.
    pub fn set_gossip_target(&self, target: WhatAmIMatcher) {
        self.gossip_target.set(target);
    }

    /// Select the PEER ROUTING MODE this node participates in — zenoh
    /// `routing.peer.mode`, which is a SUBSYSTEM-wide setting ("needs to be set
    /// to the same value in all peers and routers of the subsystem",
    /// `DEFAULT_CONFIG.json5`). `true` (the [`new`](Self::new) default) is
    /// `"linkstate"`; `false` is zenoh's own default, `"peer_to_peer"` gossip.
    ///
    /// R311y431 — it governs BOTH halves at once, deliberately: the graph's
    /// ingest ([`LinkstateNetwork::set_full_linkstate`](wz_routing_graph::LinkstateNetwork::set_full_linkstate))
    /// and the re-flood shape [`propagate`](Self::propagate) builds. Setting one
    /// without the other would produce a node that learns like a gossip peer and
    /// advertises like a linkstate one, so there is one seam and it moves both.
    pub fn set_full_linkstate(&self, enabled: bool) {
        self.net.borrow_mut().set_full_linkstate(enabled);
    }

    /// Enable gossip autoconnect: install `policy` and return the receiving end
    /// of the dial-intent channel. From now on each peer the topology ingest
    /// DISCOVERS (a `changes.new` node that advertised locators) whose role + zid
    /// the policy admits ([`AutoConnect::should_autoconnect`]) is emitted as a
    /// [`DialIntent`]; the accept loop drains the returned [`DialIntentReceiver`]
    /// and opens an outbound dial (A5c). Call ONCE at setup, before the drive
    /// loop starts; a driver that never calls this keeps the prior behaviour (no
    /// autoconnect, an empty matcher). zenoh's gossip holds the same policy and
    /// dials inline (`hat/p2p_peer/gossip.rs:444`); wz routes the dial back to its
    /// single drive task over this channel instead of spawning it.
    pub fn enable_autoconnect(&self, policy: AutoConnect) -> DialIntentReceiver {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.autoconnect.set(policy);
        *self.dial_tx.borrow_mut() = Some(tx);
        rx
    }

    /// Install the full §5.16 interceptor configuration — the SINGLE config seam,
    /// symmetric to [`set_gossip_target`](Self::set_gossip_target) /
    /// [`enable_autoconnect`](Self::enable_autoconnect). The wz mirror of zenoh's
    /// `interceptor_factories(config)` (`net/routing/interceptor/mod.rs:122`): it
    /// builds BOTH the ingress and the egress chain from `config` via
    /// [`InterceptorConfig::build_chain`], in zenoh's FIXED factory order
    /// (downsampling, then access-control, then low-pass), so the pipeline order
    /// is deterministic regardless of which features the deploy enables.
    ///
    /// REPLACES both chains rather than appending, so it is idempotent — calling
    /// it twice does not duplicate interceptors. This closes the R311tx-review
    /// footgun of three independent append-only setters (a re-call duplicated an
    /// interceptor, and the cross-setter order was unspecified): a deploy now
    /// fills one [`InterceptorConfig`] and installs it ONCE at setup, exactly as
    /// zenoh reads one `Config` once. An empty config leaves both chains empty
    /// (access control disabled — every message admitted, zenoh
    /// `AclConfig.enabled = false`). A denied / rate-limited / oversized message
    /// is dropped and witnessed by
    /// [`interceptor_dropped`](Self::interceptor_dropped).
    pub fn set_interceptors(&self, config: InterceptorConfig) {
        *self.ingress_interceptors.borrow_mut() = config.build_chain(InterceptorFlow::Ingress);
        *self.egress_interceptors.borrow_mut() = config.build_chain(InterceptorFlow::Egress);
    }

    /// The number of messages ANY interceptor has dropped so far (ACL denial,
    /// downsampling rate-limit, or low-pass size-cap; ingress or egress) — the
    /// drop twin of [`data_seen`](Self::data_seen). A pure witness (zero on a
    /// healthy unrestricted mesh); the e2e/unit tests assert it.
    pub fn interceptor_dropped(&self) -> usize {
        self.interceptor_dropped.get()
    }

    /// Whether the INGRESS chain admits this inbound `msg` arriving on face `id`.
    /// The fast path: an empty chain (no ACL configured) admits without touching
    /// the face table. Otherwise it builds the per-message [`FaceContext`] off
    /// that face's state (subject zid + alias table) and runs the chain. The
    /// single seam consulted at the top of [`forward`](Self::forward), ahead of
    /// the kind-dispatch — never an inline `if deny` per message arm.
    fn admit_inbound(&self, id: FaceId, msg: &NetworkMessage) -> bool {
        let chain = self.ingress_interceptors.borrow();
        if chain.is_empty() {
            return true;
        }
        let faces = self.faces.borrow();
        // An unknown face has no relay path anyway; admit (nothing to gate).
        let Some(face) = faces.get(&id) else {
            return true;
        };
        chain.admit(&FaceContext { face }, msg)
    }

    /// Whether the EGRESS chain admits sending `msg` to the face whose `state`
    /// the caller already holds (the destination subject is that face's zid).
    /// The fast path: an empty chain admits without building a context.
    /// Consulted per outbound message in [`fan_out`](Self::fan_out) — the wz
    /// `Mux`-side twin of [`admit_inbound`](Self::admit_inbound). Takes the
    /// already-borrowed `state` (not a `FaceId`) because `fan_out` holds the
    /// `faces` borrow across the per-face loop.
    fn admit_outbound(&self, state: &FaceState, msg: &NetworkMessage) -> bool {
        let chain = self.egress_interceptors.borrow();
        if chain.is_empty() {
            return true;
        }
        chain.admit(&FaceContext { face: state }, msg)
    }
}

/// Resolve the GOVERNED keyexpr a §5.16 ACL enforcer gates for `msg`, alias-aware
/// against `keyexpr_table` — the SSOT both forwarders' `InterceptorContext::full_keyexpr`
/// delegate to (one governed-kind match, not one per forwarder). Push / Request /
/// Response carry the keyexpr inline; a DeclareSubscriber / DeclareQueryable carries
/// it in the declaration body; any other kind (UndeclareSubscriber / alias
/// declaration / keyless ResponseFinal / Oam) carries no governed keyexpr, so the
/// enforcer admits it (`None`). Adding a new governed kind is a ONE-place edit here.
pub(crate) fn resolve_governed_keyexpr(
    msg: &NetworkMessage,
    keyexpr_table: &hashbrown::HashMap<u64, String>,
) -> Option<String> {
    match msg {
        NetworkMessage::Push(p) => resolve_wireexpr(&p.keyexpr.body, keyexpr_table),
        NetworkMessage::Request(r) => resolve_wireexpr(&r.keyexpr.body, keyexpr_table),
        NetworkMessage::Response(r) => resolve_wireexpr(&r.keyexpr.body, keyexpr_table),
        NetworkMessage::Declare(d) => declare_subscriber_wireexpr(d)
            .or_else(|| declare_queryable_wireexpr(d))
            .and_then(|we| resolve_wireexpr(&we.body, keyexpr_table)),
        _ => None,
    }
}

/// The per-message [`InterceptorContext`] for one face — borrows that face's
/// state so an enforcer can read the subject (the peer's routing zid) and
/// resolve a message keyexpr against the face's link-local alias table. Serves
/// BOTH directions: the inbound face for ingress, the destination face for
/// egress (the subject is the peer on the other end of the link either way). The
/// wz analogue of the per-transport state zenoh's enforcer bakes in at
/// `new_transport_unicast`; here it is built per message off the already-held
/// face state (an `O(1)` field read, not a re-derivation — the per-face cache
/// zenoh keeps is the deferred optimisation that the per-keyexpr decision cache
/// would land beside).
struct FaceContext<'a> {
    face: &'a FaceState,
}

impl InterceptorContext for FaceContext<'_> {
    fn subject(&self) -> Option<Zid> {
        peer_zid_routing(&self.face.actions)
    }

    fn full_keyexpr(&self, msg: &NetworkMessage) -> Option<String> {
        // The governed-kind resolution is the shared SSOT (the router twin
        // delegates to the same free fn), alias-resolved against THIS face's table.
        resolve_governed_keyexpr(msg, &self.face.keyexpr_table)
    }
}

/// R311y43 — the production [`InterceptorSink`] impl: the typed `WzConfig` SSOT
/// drives the live forwarder through this seam (decoupled from the concrete
/// type, for the §5.23 combined node). Delegates to the inherent
/// [`set_interceptors`](LinkstateForwarder::set_interceptors) — the path form
/// resolves to the inherent method (inherent shadows trait), so this is plain
/// delegation, not recursion.
impl crate::interceptor::InterceptorSink for LinkstateForwarder {
    fn set_interceptors(&self, config: crate::interceptor::InterceptorConfig) {
        LinkstateForwarder::set_interceptors(self, config)
    }
}

impl LinkstateForwarder {
    /// R311y219b — map a JOINED aggregated link's own FaceId to the session's PRIMARY
    /// registered face (via [`joined_faces`](Self#structfield.joined_faces)); returns
    /// `id` unchanged for a primary / single-link / non-aggregating face (absent from
    /// the map). Called once at the top of [`forward`](FaceForwarder::forward) so the
    /// joined link's inbound is served against the primary's face table.
    fn resolve_joined_face(&self, id: FaceId) -> FaceId {
        self.joined_faces.borrow().get(&id).copied().unwrap_or(id)
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
            // a list from a face with no graph link (held but no routing zid at
            // the handshake) is dropped — surface it (E2) so the topology not
            // converging over such a face is diagnosable.
            None => {
                log::debug!(
                    "dropping linkstate from face {} with no graph link (no routing zid)",
                    face.0
                );
                return Changes::default();
            }
        };
        let mut net = self.net.borrow_mut();
        let changes = net.ingest_linkstate_list(link_id, list);
        // Discovery: a node seen for the first time that advertised dial locators
        // is a freshly-DISCOVERED peer. Two things happen per such peer:
        //   1. log where it is reachable (`debug!`, not `info!`: it fires for
        //      every new peer in any multi-peer mesh, so it is per-peer-noisy
        //      operational detail, not a steady-state event);
        //   2. (A5b) if the autoconnect policy admits it, emit a `DialIntent` the
        //      accept loop turns into an outbound dial (A5c). Gated exactly as
        //      zenoh's gossip (`hat/p2p_peer/gossip.rs:444`): the role + zid
        //      tie-break (`should_autoconnect`) AND advertised locators. With
        //      autoconnect disabled (the default, empty matcher) the gate is
        //      always false, so this stays log-only — the prior behaviour.
        let autoconnect = self.autoconnect.get();
        for zid in &changes.new {
            let Some(locators) = net.node_locators(zid) else {
                continue;
            };
            log::debug!("discovered peer {zid} reachable at {locators:?}");
            // A `None` whatami (a node whose role has not surfaced) cannot pass
            // the role matcher, so it is never a dial candidate.
            let Some(whatami) = net.get_node(zid).and_then(|n| n.whatami) else {
                continue;
            };
            if autoconnect.should_autoconnect(*zid, whatami) {
                if let Some(tx) = self.dial_tx.borrow().as_ref() {
                    // The unbounded send never blocks this sync ingest; an Err
                    // means the receiver (the loop) is gone (shutdown), so the
                    // intent is simply dropped.
                    let _ = tx.send(DialIntent {
                        zid: zid.as_slice().to_vec(),
                        locators: locators.to_vec(),
                    });
                }
            }
        }
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
    /// Returns the number of faces propagated to. zenoh's D4 `Details` split is
    /// honoured: `changes.new` nodes (first full state seen) re-flood FULL
    /// (zid + links), `changes.updated` nodes (already-mapped re-advertisers)
    /// re-flood LINKS-ONLY (no zid — the receiver resolves it from the psid it
    /// learned when the node was new). Both halves ride ONE list per face so
    /// they arrive atomically (zenoh `network.rs:643-644`: send all states at
    /// once to avoid premature node deletion on the other side).
    ///
    /// Source-face handling is zenoh's, and it is ASYMMETRIC between the two
    /// halves (`network.rs:659-666`): `new` nodes ride back out on the SOURCE
    /// link too, and only the `updated` half is withheld from it
    /// (`:661` `link.zid != src`).
    ///
    /// R311y431 — wz used to drop the source face ENTIRELY, on the rationale that
    /// "every node it would echo back was advertised BY that source, so the echo
    /// is redundant". That rationale is wrong, and a real zenohd said so: PSID
    /// SPACE IS PER-SENDER. The source advertised the node under ITS OWN psid
    /// numbering, which tells it nothing about the psid THIS node will use for
    /// that same node in its own later floods. Suppressing the echo means the
    /// source never learns our psid for it, so the next self-advertisement
    /// referencing that psid in `links` is unresolvable — zenohd rejects the edge
    /// with `Received LinkState from <zid> with unknown link mapping <psid>`
    /// (zenoh `network.rs:527-539`), which is exactly what a three-node
    /// wz/zenohd/zenohd linkstate mesh produced. Nor does sn-staleness make it
    /// moot: the psid->zid mapping is installed in `convert_to_local_link_states`
    /// BEFORE the sn gate can drop the entry, so the echo does its job even when
    /// the state itself is stale.
    pub fn propagate(&self, source: FaceId, changes: &Changes) -> Result<usize, CodecError> {
        if changes.new.is_empty() && changes.updated.is_empty() {
            return Ok(0);
        }
        // A clone of the graph handle so the per-face builder can borrow it
        // (the `Rc` is the cell; `fan_out` only holds the `faces` borrow).
        let net = self.net.clone();
        // GOSSIP (`peer_to_peer`) re-flood — zenoh `network.rs:594-602`. A
        // different SHAPE, not a narrowed one: one `NodeOnly` entry (zid +
        // locators, no links) per changed node, admitted only when
        // `gossip_reflood_admits` says so (without multihop a gossip node relays
        // its DIRECT neighbours only). The source face is NOT excluded here
        // either — zenoh's filter is `|link| link.zid != ls.zid`, the per-node
        // exclusion alone.
        if !net.borrow().full_linkstate() {
            return self.fan_out(true, Some(self.gossip_target.get()), |_id, zid| {
                let net_ref = net.borrow();
                let nodes: Vec<Zid> = changes
                    .new
                    .iter()
                    .chain(changes.updated.iter())
                    .filter(|z| zid != Some(**z))
                    .filter(|z| net_ref.gossip_reflood_admits(z))
                    .cloned()
                    .collect();
                if nodes.is_empty() {
                    return Ok(None);
                }
                let oam = build_linkstate_oam_owned(&net_ref.build_linkstate_gossip(&nodes))?;
                Ok(Some(NetworkMessage::Oam(oam)))
            });
        }
        self.fan_out(true, Some(self.gossip_target.get()), |id, zid| {
            // Drop the node whose own state this is from the list sent to ITS
            // face (zenoh `network.rs:663`) — the per-face payload differs, so
            // each face gets its own built carrier.
            let keep = |z: &&Zid| zid != Some(**z);
            let new: Vec<Zid> = changes.new.iter().filter(keep).cloned().collect();
            // The source face gets the `new` half (above) but NOT the `updated`
            // half — zenoh `network.rs:661`.
            let updated: Vec<Zid> = if id == source {
                Vec::new()
            } else {
                changes.updated.iter().filter(keep).cloned().collect()
            };
            if new.is_empty() && updated.is_empty() {
                return Ok(None);
            }
            let oam =
                build_linkstate_oam_owned(&net.borrow().build_linkstate_split(&new, &updated))?;
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

    /// Total unsolicited FUTURE `DeclareSubscriber` pushes emitted (R311y158) — the
    /// peer-tier twin of the router's `future_pushes_seen`. A `>0` value proves this
    /// peer told a CLIENT face a subscription it learned AFTER that face's FUTURE
    /// interest (`push_future_subscription`), the sole wz cause of a pub-before-sub
    /// publisher's write-filter deactivation.
    pub fn future_pushes_seen(&self) -> usize {
        self.future_pushes.get()
    }

    /// Total co-attached CLIENT subscriptions currently held (R311y163 / D4) — the
    /// data-plane READINESS witness, the peer-tier twin of the router's
    /// `client_subs_seen`. A `>0` value proves this peer installed a client's
    /// `DeclareSubscriber` in [`client_subs`](Self#structfield.client_subs) (and
    /// advertised it into the mesh under self's zid), the barrier a co-attached
    /// cross-impl e2e gates on before driving data.
    pub fn client_subs_seen(&self) -> usize {
        self.client_subs.borrow().values().map(|s| s.len()).sum()
    }

    /// Total co-attached CLIENT queryables currently hosted (the query-plane twin of
    /// [`client_subs_seen`](Self::client_subs_seen)) — the READINESS witness a
    /// co-attached cross-impl e2e gates on before driving a query. A `>0` value proves
    /// this peer installed a client's `DeclareQueryable` in
    /// [`client_qabls`](Self#structfield.client_qabls) and advertised it into the mesh
    /// under self's zid.
    pub fn client_qabls_seen(&self) -> usize {
        self.client_qabls.borrow().values().map(|q| q.len()).sum()
    }

    /// Total unsolicited FUTURE `DeclareQueryable` pushes emitted (R311y158) — the
    /// query-plane twin (`push_future_queryable`), the peer-tier analogue of the
    /// router's `future_qabl_pushes_seen`.
    pub fn future_qabl_pushes_seen(&self) -> usize {
        self.future_qabl_pushes.get()
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

    /// Number of edges (MUTUAL links) in the topology graph. An edge exists
    /// only when BOTH endpoints advertise a link to each other
    /// ([`rebuild_edges`](wz_routing_graph::LinkstateNetwork) forms the edge
    /// solely on `graph[dest].links.contains_key(self)`), so a bare
    /// `add_link` (register) — which records self's outbound link but not the
    /// neighbour's reciprocal one — yields NO edge until an inbound
    /// link-state carrying the neighbour's link back to self is ingested. It
    /// is therefore the discriminator between a full-linkstate peer flood
    /// (self-entry carries `links={self}` → reciprocal edge) and a gossip
    /// (`peer_to_peer`) peer flood (self-entry `links:false` → node only, no
    /// edge): both bump [`ingested`](Self::ingested), only the linkstate one
    /// bumps this. The demo samples its high-water at each tick.
    pub fn edge_count(&self) -> usize {
        self.net.borrow().edge_count()
    }

    /// This peer's children in the spanning tree rooted at `source` — the
    /// faces to forward a message flooded along `source`'s tree to. The
    /// data-forwarding atom (c3b) reads this; exposed now as the graph
    /// query the driver owns.
    pub fn tree_children_of(&self, source: &Zid) -> Vec<Zid> {
        self.net.borrow().tree_children_of(source)
    }

    /// Build the `OAM_LINKSTATE` carrier for this peer's full current topology
    /// — the new-face bootstrap body of [`flood_link_added`](Self::flood_link_added)
    /// (one carrier re-wrapped per new face). The graph builds the full-topology `LinkStateList` (c3b
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
    /// per-face send failure — so `flood_link_added` / `flood_self_links_changed`
    /// / `propagate` / `forward_push` / `publish` each express ONLY their
    /// selection + carrier policy as the closure, never a re-hand-rolled face
    /// loop. Holds only the `faces` borrow;
    /// a builder may borrow the graph (a distinct cell).
    /// `gossip_gate` is the per-target whatami gate: a link-state gossip flood
    /// passes `Some(self.gossip_target.get())` so a face whose role is outside the
    /// gossip target (a `client`) is skipped entirely — zenoh's per-target
    /// `send_on_link` (`hat/p2p_peer/gossip.rs:241`). A data-plane fan-out
    /// passes `None`: its selectivity is the tree/interest filter in the builder,
    /// not the role gate, so it must reach every held face the builder selects.
    /// Taken by value — the matcher is a `Copy` one-byte bitset, so the caller
    /// reads the `Cell` once and the gate needs no borrow.
    fn fan_out(
        &self,
        reliable: bool,
        gossip_gate: Option<WhatAmIMatcher>,
        build: impl FnMut(FaceId, Option<Zid>) -> Result<Option<NetworkMessage>, CodecError>,
    ) -> Result<usize, CodecError> {
        // R311y220 — the DEFAULT-priority, non-express fan-out: every control-plane
        // caller (flood_link_added / flood_self_links_changed / propagate / publish /
        // ...) routes through here byte-identically to the prior hard-coded
        // `send_network_message(msg, reliable, false)`. The band-carrying callers go
        // to `fan_out_qos` directly: `publish_qos` (an origin send) and, R311y221,
        // `forward_push` (a transit re-forward preserving the received band).
        self.fan_out_qos(reliable, Priority::DEFAULT, false, gossip_gate, build)
    }

    /// R311y220 — the priority-carrying fan-out that holds the shared body: identical
    /// to [`Self::fan_out`] except each admitted per-face send routes `priority` +
    /// `express` through [`send_network_message_qos`](wz_session_core::session_actions)
    /// so an aggregated QoS multilink session pins the fan-out onto the priority-band
    /// link (`select_link`). [`Self::fan_out`] is the `(Priority::DEFAULT,
    /// express = false)` specialization that every control-plane caller takes;
    /// `publish_qos` (an origin send) and `forward_push` (a transit re-forward,
    /// R311y221) are the callers that pass a non-DEFAULT band. TRANSIT PRESERVATION
    /// (R311y221): a NON-origin re-forward on THIS (mesh / linkstate-peer) plane now
    /// routes through `fan_out_qos` on the received `FramePayload.priority`, so the
    /// band survives a relay hop end-to-end — the mirror of zenoh `route_data`
    /// copying `msg.ext_qos` onto egress (`net/routing/dispatcher/pubsub.rs`),
    /// restricted to the priority sub-field wz decodes (express / congestion-control
    /// are not carried on `FramePayload`). R311y224 added the router twin
    /// (`RouterForwarder::fan_out_tier_qos`) so the router-tier re-forward
    /// (`forward_push_tier` + the cross-mesh bridge) and the switchboard
    /// `RouteTable::forward_push` preserve a transit band too; R311y225 extended it to
    /// the CLIENT-face egress (`deliver_to_client_subscribers`) and the client->mesh
    /// re-inject (`reinject_client_push`) on this plane. The remaining DEFAULT data
    /// egresses are the multicast plane (a structural 2-channel, no per-priority
    /// conduit) and the query plane (Request/Response, uniformly DEFAULT).
    fn fan_out_qos(
        &self,
        reliable: bool,
        priority: Priority,
        express: bool,
        gossip_gate: Option<WhatAmIMatcher>,
        mut build: impl FnMut(FaceId, Option<Zid>) -> Result<Option<NetworkMessage>, CodecError>,
    ) -> Result<usize, CodecError> {
        let mut sent = 0;
        for (id, state) in self.faces.borrow().iter() {
            // Gossip floods reach only faces whose handshake whatami is in the
            // gossip target; an out-of-target face (a client) is skipped before
            // a carrier is even built for it. Data fan-outs pass no gate.
            if let Some(target) = gossip_gate {
                if !target.matches(peer_whatami_routing(&state.actions)) {
                    continue;
                }
            }
            // Convert the session-layer peer zid (Vec<u8>) to the routing Zid at
            // this single boundary, so every fan-out builder works in Zid terms
            // (Copy, Eq) rather than re-deriving it from raw bytes per call. The
            // handshake supplies a trusted, canonical zid, so the infallible
            // from_slice is the right ctor (a wire zid would use try_from).
            let peer_zid = peer_zid_routing(&state.actions);
            if let Some(msg) = build(*id, peer_zid)? {
                // R311tv — §5.16 EGRESS access control: gate the built message by
                // the DESTINATION face's subject before it leaves. A denied
                // outbound is dropped for THIS face (not sent, not counted) and
                // witnessed — the wz `Mux`-side enforcement that also covers this
                // node's own originations (a `publish` reaches only `fan_out`).
                if !self.admit_outbound(state, &msg) {
                    self.interceptor_dropped
                        .set(self.interceptor_dropped.get() + 1);
                    continue;
                }
                // a per-face send failure (link gone mid-fan-out) is skipped,
                // not fatal to the rest — the face's own driver surfaces its
                // teardown via deregister.
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

    /// Flood self's GAINED-link event (the [`register`](FaceForwarder::register)
    /// path) — the D4-faithful counterpart of zenoh `add_link`
    /// (`network.rs:861-932`). The WHEN is EVENT-DRIVEN (D2b): register calls this
    /// the instant self gains a neighbour (sn bumped), so there is no periodic
    /// tick. The WHAT is now a DELTA, not the full topology:
    /// - the NEW face is bootstrapped with the FULL topology (every node, full
    ///   state — zenoh's "send all nodes linkstate on new link");
    /// - every EXISTING face gets only the minimal delta zenoh sends on its
    ///   existing links: the 2-entry `[neighbour zid-only, self links-only]` list
    ///   when the neighbour is NEW to the graph
    ///   ([`build_link_added_delta`](wz_routing_graph::LinkstateNetwork::build_link_added_delta)),
    ///   or just self's links-only entry when the neighbour was already known (a
    ///   second link to it).
    ///
    /// sn-staleness on each receiver drops the unchanged nodes a full re-flood
    /// would carry, so the delta is the same convergence with far less wire churn
    /// — this closes the SELF-event half of D4 (the receive-side
    /// [`propagate`](Self::propagate) half landed in sm). Reliable (topology is
    /// control traffic); returns the count of faces reached.
    fn flood_link_added(
        &self,
        new_face: FaceId,
        neighbour: &Zid,
        neighbour_was_new: bool,
    ) -> Result<usize, CodecError> {
        // Build each shape once (NetworkMessage is not Clone, OamOwned is —
        // re-wrap a clone per face).
        let full = self.build_self_oam()?;
        let delta = {
            let net = self.net.borrow();
            // zenoh's condition is `new || (!full_linkstate && !gossip_multihop)`
            // (`network.rs:867`, and the gossip twin at `p2p_peer/gossip.rs:519`
            // where the `full_linkstate` term is absent because that Network is
            // always gossip). So in GOSSIP mode the 2-entry form is unconditional:
            // a gossip receiver has no other way to learn our psid for this
            // neighbour, since the gossip re-flood only relays DIRECT neighbours
            // and this one was not ours yet when its announcement arrived. Sending
            // the 1-entry form there leaves the psid in self's `links` dangling
            // and the peer rejects that edge (`unknown link mapping`), which is
            // what a stock zenohd router did until R311y431.
            let introduce_neighbour = neighbour_was_new || !net.full_linkstate();
            let list = if introduce_neighbour {
                net.build_link_added_delta(neighbour)
            } else {
                net.build_self_links_delta()
            };
            build_linkstate_oam_owned(&list)?
        };
        self.fan_out(true, Some(self.gossip_target.get()), |id, zid| {
            if id == new_face {
                // the new link is bootstrapped with the FULL topology.
                return Ok(Some(NetworkMessage::Oam(full.clone())));
            }
            if zid == Some(*neighbour) {
                // Another link carrying the SAME neighbour zid (a relink to a peer
                // already held on a different face): zenoh excludes EVERY link with
                // `link.zid == zid` from the existing-links delta (`network.rs:864`),
                // since that peer learns self's change on its own new face's full
                // bootstrap. Skip it (otherwise it gets a redundant — if idempotent
                // — self-links frame).
                return Ok(None);
            }
            Ok(Some(NetworkMessage::Oam(delta.clone())))
        })
    }

    /// Flood self's LOST-link event (the [`deregister`](FaceForwarder::deregister)
    /// path) — zenoh `remove_link`'s `send_on_links` of self's updated links-only
    /// entry (`network.rs:952-962`). Sends the 1-entry `[self links-only]` delta
    /// to every surviving face so they drop the dead link from their topology at
    /// once; each receiver's own `remove_detached_nodes` prunes the now-detached
    /// nodes (self stops referencing them), so no node-removal entries are needed,
    /// and the links-only form (no zid) suffices since every survivor already
    /// mapped self. Reliable; returns the count of faces reached.
    fn flood_self_links_changed(&self) -> Result<usize, CodecError> {
        let oam = build_linkstate_oam_owned(&self.net.borrow().build_self_links_delta())?;
        self.fan_out(true, Some(self.gossip_target.get()), |_id, _zid| {
            Ok(Some(NetworkMessage::Oam(oam.clone())))
        })
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
    ///   Unreachable until a graph holds >65535 live nodes (and
    ///   `remove_detached_nodes` GC-prunes nodes that leave, bounding the
    ///   live set to the reachable mesh).
    ///
    /// The single SSOT shared by [`forward_push`](Self::forward_push) (data)
    /// and [`forward_subscription`](Self::forward_subscription) (a sourced
    /// subscription declaration): both flood along the SOURCE's tree, so both
    /// resolve the source — and the self-source / range guards — identically.
    fn resolve_source(
        &self,
        inbound_zid: Option<Zid>,
        inbound_link: Option<LinkId>,
        node_id: u16,
    ) -> Option<(Zid, u16)> {
        // R311y109 — the resolution reads ONLY the net, so the body lives as the
        // free `resolve_source_in` (SSOT) that RouterForwarder also calls per
        // tier-net; this method is the LinkstateForwarder-side thin delegate.
        resolve_source_in(&self.net.borrow(), inbound_zid, inbound_link, node_id)
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
    /// ([`LinkstatepeerInterest`](crate::linkstate_interest::LinkstatepeerInterest)), NOT
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
    /// needs no hop-limit — it is bounded by the [`LinkstatepeerInterest`] register
    /// change-gate (re-flood only on a NEW interest), the state-convergent bound.
    fn forward_push(&self, inbound: FaceId, reliable: bool, priority: Priority, push: &PushOwned) {
        // R311y450 — the §5.18 forward-path stamp, applied ONCE here, at the head,
        // before anything fans out. zenoh does the same at ONE point
        // (`treat_timestamp!` at `dispatcher/pubsub.rs:328`) and then fans the one
        // stamped `msg` to every leg of `route`.
        //
        // NOT inside `compute_push_forward` below, even though that is where the
        // carrier is already cloned and mutated (`set_push_source` /
        // `set_push_hoplimit`) and where the `interested.is_empty()` early-out
        // mirrors zenoh's `if !route.is_empty()`. That core is called PER TIER-NET
        // by `RouterForwarder` (`router_forward.rs`'s `forward_push_tier`), so a
        // stamp there would mint a DIFFERENT timestamp for each mesh leg of one
        // Put — the opposite of what zenoh's single stamp point guarantees.
        //
        // No-op on this forwarder's production role: `WhatAmI::Peer` does not
        // timestamp under zenoh's shipped map, so `node_hlc` holds no clock and
        // the borrow below is skipped entirely.
        let stamped;
        let push = if self.node_hlc.is_stamping() {
            let mut carrier = push.clone();
            self.node_hlc.treat_timestamp(&mut carrier);
            stamped = carrier;
            &stamped
        } else {
            push
        };
        // The inbound face's zid + graph link (source resolution) AND the Push's
        // keyexpr resolved against THIS face's link-local alias table (c3c-3 B1) —
        // taken in one SCOPED borrow so the `fan_out` below holds the only live
        // `faces` borrow. An aliased keyexpr (id != 0) the peer never declared on
        // this link is unresolvable and drops the Push (the same drop a missing
        // literal got); id == 0 resolves to the suffix verbatim.
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

        // The route CORE (source-resolve → self-excluded interest → tree
        // directions → hop-limit → literal-normalize) is the shared free
        // [`compute_push_forward`] RouterForwarder also calls per tier-net
        // (R311y112). The fan-out stays here — this forwarder's gossip-gated +
        // egress-ACL `fan_out` — over the returned (carrier, children).
        let Some((carrier, children)) = compute_push_forward(
            &self.net,
            &self.subs,
            inbound_zid,
            inbound_link,
            push,
            &keyexpr,
        ) else {
            return;
        };

        // Forward to the interested children in the source's tree — never to the
        // inbound face, nor back toward the source's own neighbour (the shared
        // re-forward predicate). R311y221 — route through `fan_out_qos` on the
        // frame's received `priority` (express stays false — a FramePayload carries
        // no express bit), so an aggregated QoS multilink relay pins the re-forward
        // onto the band link (`select_link`) and re-encodes ext_qos = the received
        // band. DEFAULT under a non-QoS session (the `dispatch_push` clamp), so this
        // is byte-identical to the prior `fan_out` on every non-QoS transit.
        let _ = self.fan_out_qos(reliable, priority, false, None, |id, zid| {
            Ok(
                is_tree_forward_target(id, zid, inbound, inbound_zid, &children)
                    .then(|| NetworkMessage::Push(Box::new(carrier.clone()))),
            )
        });
    }

    /// A routed Query (`Request`) arrived on `inbound`: relay it toward the
    /// matching QUERYABLES along the QUERIER's spanning tree — the query-plane
    /// twin of [`forward_push`](Self::forward_push) (data toward subscribers).
    /// Resolves the source (querier, tree root) from the Request's
    /// routing-context node_id ([`read_request_source`]) exactly as forward_push
    /// resolves a Push's source, reads the queryable interest
    /// [`qabls`](Self#structfield.qabls) `interested_remote` for the keyexpr, and
    /// routes toward those queryables' subtrees via
    /// [`directions_toward`](wz_routing_graph::LinkstateNetwork::directions_toward).
    /// A keyexpr no peer offers a queryable for routes nowhere. zenoh
    /// `route_query` -> `compute_query_route` over the linkstate trees.
    ///
    /// The Request is relayed with its `rid` REMAPPED per outbound branch (a
    /// fresh local qid + a pending entry against the query's shared
    /// [`QueryFan`]), so a `Response` / `ResponseFinal` routes back via
    /// [`forward_response`](Self::forward_response) /
    /// [`forward_response_final`](Self::forward_response_final). No hop-limit:
    /// zenoh bounds a Query by the per-query timeout (the pending deadline +
    /// tick sweep), not a hop count, and a converged source tree is acyclic
    /// (the transient-recompute loop window is what the timeout closes). A
    /// Query that routes NOWHERE — unresolvable keyexpr, empty route, or a
    /// route whose directions match no live face — TERMINATES the querier with
    /// a local dispatch attempt + a prompt `ResponseFinal`
    /// ([`finish_unrouted_request`](Self::finish_unrouted_request)), zenoh
    /// `route_query`'s unknown-scope / empty-route finals.
    fn forward_request(&self, inbound: FaceId, reliable: bool, request: &RequestOwned) {
        // The inbound face's zid + graph link AND the RESOLVED keyexpr, one
        // scoped borrow (released before any send re-borrows `faces`).
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
                // must still TERMINATE — zenoh route_query sends a ResponseFinal
                // on an unknown scope (dispatcher/queries.rs:575), not a silent
                // drop that would hang the get() until its own timeout (the
                // router twin's y121 behavior, backported).
                let final_msg =
                    wz_session_core::response_final_build::build_response_final(request.rid);
                self.send_to_face(inbound, reliable, || {
                    NetworkMessage::ResponseFinal(final_msg.clone())
                });
                return;
            }
        };
        // Resolve the source (querier, tree root) + this node's psid for it — the
        // SAME shared seam forward_push uses; a routed Query floods along the
        // querier's tree, not the relaying neighbour's.
        //
        // R311y166 — a CLIENT querier is a LEAF (no graph node since the R311y163
        // register Client-tier branch), so the shared `resolve_source` finds no psid
        // and would DROP its Query. Route it with SELF as the query tree root
        // (out_node_id 0) — the query twin of the D4b client-Push re-inject
        // ([`reinject_client_push`](Self::reinject_client_push)) and zenoh
        // `compute_query_route`'s `self.idx` for a `WhatAmI::Client` source. Without
        // this a client's adminspace / mesh GET never routes (its only local match,
        // e.g. `@/<zid>/peer/config`, reaches the self-dispatch `finish_unrouted_request`
        // branch below only once the source resolves).
        let (source_zid, out_node_id) = if self.is_client_face(inbound) {
            (*self.net.borrow().self_zid(), 0)
        } else {
            let Some(resolved) =
                self.resolve_source(inbound_zid, inbound_link, read_request_source(request))
            else {
                return;
            };
            resolved
        };
        // The query-route candidate set (zenoh compute_final_route): the single zenoh
        // route folds MESH queryables (graph distance) AND co-attached CLIENT queryables
        // (session_ctxs, distance 1) into one set, then applies the QueryTarget. wz
        // computes the two sides separately and selects per target. The wire DEFAULT
        // (absent ext_target) is BestMatching. UNCONDITIONAL — the single-net peer has no
        // master election (zenoh linkstate_peer compute_query_route has no elect_router).
        let target = read_request_target(request);
        let query_chunks: Vec<&str> = keyexpr.split('/').collect();
        // Co-attached CLIENT queryables matching this query — distance-1 candidates, the
        // query twin of deliver_to_client_subscribers. The querier's OWN face is never a
        // target (no routing a query back to its source). `complete` = declared complete
        // AND the declaration keyexpr INCLUDES the query (zenoh's `complete && includes`);
        // a plain INTERSECT is the BestMatching/All match. Wildcard-aware via the SAME
        // keyexpr_intersects_target / keyexpr_includes_target SSOTs the mesh + local dispatch use.
        let client_candidates: Vec<(FaceId, bool)> = {
            let cq = self.client_qabls.borrow();
            let mut candidates = Vec::new();
            for (&face, qabls) in cq.iter() {
                if face == inbound {
                    continue;
                }
                let mut intersects = false;
                let mut complete = false;
                for (decl, info) in qabls.values() {
                    if keyexpr_intersects_target(decl, &query_chunks) {
                        intersects = true;
                        if info.complete && keyexpr_includes_target(decl, &query_chunks) {
                            complete = true;
                            break;
                        }
                    }
                }
                let matches = match target {
                    Some(QueryTarget::AllComplete) => complete,
                    _ => intersects,
                };
                if matches {
                    candidates.push((face, complete));
                }
            }
            candidates
        };
        // Select the mesh directions + client faces per QueryTarget. A client queryable is
        // distance 1: for BestMatching a COMPLETE client is the nearest-complete winner (it
        // suppresses the >= distance-1 mesh best); with no complete client the mesh's own
        // complete-best stands, and if NOTHING is complete anywhere the All-fallback fans
        // mesh + clients together (zenoh compute_final_route's distance-sorted
        // first-complete, else all).
        let self_zid = *self.net.borrow().self_zid();
        let (children, client_targets): (Vec<Zid>, Vec<FaceId>) = match target {
            None => {
                if let Some(face) = client_candidates.iter().find(|(_, c)| *c).map(|(f, _)| *f) {
                    // A distance-1 COMPLETE client wins BestMatching over any mesh best.
                    (Vec::new(), vec![face])
                } else {
                    let net = self.net.borrow();
                    match select_best_matching(
                        &net,
                        &self.qabls,
                        &keyexpr,
                        &source_zid,
                        &self_zid,
                        inbound_zid,
                    ) {
                        // A complete mesh queryable is the nearest-complete winner.
                        Some((_distance, hop)) => (vec![hop], Vec::new()),
                        // Nothing complete anywhere -> the All fallback: mesh + all clients.
                        None => (
                            all_query_directions(
                                &net,
                                &self.qabls,
                                &keyexpr,
                                &source_zid,
                                &self_zid,
                            ),
                            client_candidates.iter().map(|(f, _)| *f).collect(),
                        ),
                    }
                }
            }
            // All / AllComplete: fan to every mesh direction AND every matching client
            // (client_candidates is already AllComplete-filtered above).
            Some(QueryTarget::All) | Some(QueryTarget::AllComplete) => (
                compute_query_directions(
                    &self.net,
                    &self.qabls,
                    &keyexpr,
                    target,
                    &source_zid,
                    inbound_zid,
                ),
                client_candidates.iter().map(|(f, _)| *f).collect(),
            ),
        };
        // zenoh route_query EMPTY route: no mesh direction AND no co-attached client
        // queryable -> try the self-hosted local queryables (the SYNCHRONOUS
        // dispatch_local_queryables self-final path, e.g. an admin GET), else a prompt
        // empty-route ResponseFinal so the querier's get() terminates. A client-qabl match
        // takes the async fan path below, so the sync local dispatch runs ONLY when there
        // is zero async branch (a client qabl on the SAME ke as a self-hosted queryable
        // would suppress the local dispatch — no worse than the pre-existing local-vs-mesh
        // gap, and self-hosted admin kes are zid-unique so it does not arise in practice).
        if children.is_empty() && client_targets.is_empty() {
            self.finish_unrouted_request(inbound, reliable, request, &keyexpr);
            return;
        }
        // out_node_id + the literal keyexpr are the same for every outbound branch, so build
        // the re-stamped TEMPLATE once; the per-branch step swaps in a freshly allocated qid.
        // NORMALIZE the forwarded keyexpr to a literal (B1).
        let mut template = request.clone();
        set_request_source(&mut template, out_node_id);
        if set_request_keyexpr_literal(&mut template, &keyexpr).is_err() {
            return;
        }
        // ONE shared fan target for this logical Query — every MESH and CLIENT branch's
        // pending entry Rc-shares it, so the fan's closing final aggregates last-out across
        // both legs (zenoh's one Arc<Query> cloned per branch).
        let fan = QueryFan::new(inbound, request.rid);
        // The deadline each pending entry is abandoned at if no ResponseFinal routes back
        // (the Query's own ext_timeout, else this relay's default); the tick sweep reaps it.
        let deadline = self.now()
            + read_request_timeout_ms(request)
                .map(Duration::from_millis)
                .unwrap_or_else(|| self.query_timeout.get());
        let mut forwarded = 0usize;
        // MESH branches: allocate a fresh local qid PER tree-forward child + stamp it as the
        // outbound Request's rid, so its Response/ResponseFinal routes back via
        // forward_response/_final. The per-face qid is why each child gets its OWN carrier.
        let _ = self.fan_out(reliable, None, |id, zid| {
            if !is_tree_forward_target(id, zid, inbound, inbound_zid, &children) {
                return Ok(None);
            }
            let qid = self.pending.borrow_mut().allocate(id, &fan, deadline);
            let mut carrier = template.clone();
            carrier.rid = qid;
            forwarded += 1;
            Ok(Some(NetworkMessage::Request(Box::new(carrier))))
        });
        // CLIENT-qabl branches: forward the Request to each matching co-attached client
        // face, allocating a pending return entry sharing the SAME fan — so the client's
        // Reply routes back via forward_response and the closing final aggregates last-out
        // across mesh AND client branches (the query twin of deliver_to_client_subscribers).
        forwarded += self.forward_request_to_client_queryables(
            &fan,
            deadline,
            &template,
            reliable,
            &client_targets,
        );
        // A non-empty candidate set can still forward to ZERO live faces (a stale tree, or
        // the only direction pointing back at the querier); apply the SAME termination
        // guarantee here so the querier never hangs.
        if forwarded == 0 {
            self.finish_unrouted_request(inbound, reliable, request, &keyexpr);
        }
    }

    /// Forward a routed Query to each matching co-attached CLIENT queryable face — the
    /// query twin of [`deliver_to_client_subscribers`](Self::deliver_to_client_subscribers)
    /// (and the router's `forward_request_to_clients`). Each client face gets its OWN
    /// carrier with a freshly allocated pending qid that Rc-shares the caller's `fan`, so
    /// the client's Reply routes back via [`forward_response`](Self::forward_response) and
    /// the closing final aggregates last-out with the mesh branches. UNCONDITIONAL (no
    /// master gate — the single-net peer). Returns the count forwarded.
    fn forward_request_to_client_queryables(
        &self,
        fan: &Rc<QueryFan>,
        deadline: Instant,
        template: &RequestOwned,
        reliable: bool,
        client_faces: &[FaceId],
    ) -> usize {
        let mut forwarded = 0usize;
        for &face in client_faces {
            let qid = self.pending.borrow_mut().allocate(face, fan, deadline);
            let mut carrier = template.clone();
            // A client queryable is a LEAF, not a routing-graph node: reset the Query's
            // routing source node-id to 0 (mirror of the router's forward_request_to_clients,
            // router_forward.rs:4174 + forward_request_to_face "0 for a client"). The shared
            // `template` carries the MESH query tree root (out_node_id, forward_request:1559)
            // for the mesh branches; forwarding that NON-ZERO routing source to a client (e.g.
            // a pico z_queryable) is a protocol violation the client rejects by CLOSING its
            // transport — surfaced by the peer qabl cross-impl leg (the green y177 units missed
            // it because an in-process test face ignores the source ext). For a client-sourced
            // query out_node_id is already 0, so this is a no-op there.
            set_request_source(&mut carrier, 0);
            carrier.rid = qid;
            self.send_to_face(face, reliable, || {
                NetworkMessage::Request(Box::new(carrier.clone()))
            });
            forwarded += 1;
        }
        forwarded
    }

    /// Terminate a Query that routed NOWHERE — the shared unrouted tail of
    /// [`forward_request`](Self::forward_request) (empty directions, or
    /// directions matching no live face): try the LOCAL self-hosted queryables
    /// (R311y44 — a routed Query whose only match is hosted by this node lands
    /// here, e.g. every admin GET; a local match emits its replies + the closing
    /// final), else send the prompt empty-route `ResponseFinal` so the querier's
    /// `get()` terminates immediately (zenoh `route_query`,
    /// `dispatcher/queries.rs:518-530`). No pending entry is recorded (nothing
    /// is awaited).
    fn finish_unrouted_request(
        &self,
        inbound: FaceId,
        reliable: bool,
        request: &RequestOwned,
        keyexpr: &str,
    ) {
        if self.dispatch_local_queryables(
            inbound,
            reliable,
            request,
            keyexpr,
            read_request_target(request),
        ) {
            return;
        }
        let final_msg = wz_session_core::response_final_build::build_response_final(request.rid);
        self.send_to_face(inbound, reliable, || {
            NetworkMessage::ResponseFinal(final_msg.clone())
        });
    }

    /// A `Response` (a queryable's reply to a routed Query) arrived on `inbound`:
    /// route it BACK toward the querier via the pending-query table — the reverse
    /// of the forward hop. The response's `request_id` is the local qid THIS relay
    /// stamped on the outbound Request it forwarded out `inbound`; look it up
    /// ([`peek`](PendingQueries::peek), NOT taking — more replies may follow),
    /// rewrite the `request_id` back to the recorded upstream rid, B1-normalize the
    /// reply keyexpr to a literal, and unicast it to the recorded inbound face.
    /// zenoh `route_send_response` (`dispatcher/queries.rs`): look up
    /// `face.pending_queries`, rewrite `rid = query.src_qid`, send to
    /// `query.src_face`. An unknown qid (no pending query — finalized / timed out /
    /// never sent) drops silently.
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
        // The return target for the qid this Response carries on the inbound face.
        let Some((orig_face, orig_rid)) = self.pending.borrow().peek(inbound, response.request_id)
        else {
            return;
        };
        // Rewrite the request_id back to the upstream rid + normalize a carried
        // keyexpr, then unicast to the single upstream face (the pending table IS
        // the return route — a back-hop, not a tree fan-out).
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
    /// fan's LAST live branch — route the closing final BACK toward the querier,
    /// the [`take`](PendingQueries::take) twin of
    /// [`forward_response`](Self::forward_response)'s peek. A Query fanned to
    /// several queryables (`QueryTarget::All` / the BestMatching fall-back) must
    /// close upstream exactly ONCE, after ALL branches finalize — a NON-last
    /// final is ABSORBED (the querier still awaits the other branches' replies),
    /// exactly zenoh's `Arc::into_inner` gate in `finalize_pending_query`
    /// (`dispatcher/queries.rs:670`): only the removal that drops the last
    /// `Arc<Query>` reference sends `ResponseFinal { rid: query.src_qid }` to
    /// `query.src_face`. The forwarded final is rewritten to the recorded
    /// upstream rid and unicast to the recorded inbound face (a ResponseFinal
    /// carries no keyexpr, so no B1 normalize). An unknown qid drops silently.
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
        // R311y220 — the DEFAULT-priority origination: delegate to `publish_qos` so a
        // plain publish stays byte-identical to the prior `fan_out(true, None, ..)`
        // (Priority::DEFAULT = Data, in the LOW band; express = false).
        self.publish_qos(keyexpr, payload, Priority::DEFAULT, false)
    }

    /// R311y220 — the priority-carrying origination twin of [`Self::publish`] (the
    /// demo-reachability path the `--express-high` / `--low` flags drive).
    /// R311y226 — the self-sourced carrier now carries the priority on BOTH wire
    /// halves of the publisher dual-write (zenoh `resolve_put` + conduit select; pico
    /// `_z_n_qos_make`): the per-message Push qos ext (so a subscriber reads it via
    /// `Sample::priority()` — the app-observable band) AND, downstream via
    /// `dispatch_network_message`, the Frame `ext_qos` conduit + `select_link` routing
    /// key. On a QoS-negotiated aggregated multilink session the frame band pins the
    /// Put onto the priority-band link; on any non-QoS / single-link session the frame
    /// half is byte-identical to `publish` (the `is_qos()` clamp forces the effective
    /// conduit priority back to DEFAULT) while the qos ext still rides the wire so the
    /// app sees the band. A DEFAULT publish emits no qos ext (encoder suppression),
    /// staying wire-identical. Transit re-forwards preserve the frame band
    /// (R311y221-y225) and the per-message qos ext (clone-based re-literalize).
    pub fn publish_qos(
        &self,
        keyexpr: &str,
        payload: &[u8],
        priority: Priority,
        express: bool,
    ) -> Result<usize, CodecError> {
        // The self-originate route CORE (shared with the router's client->mesh
        // re-injection, R311y112 core-extract discipline): self is the tree root,
        // the returned carrier is self-sourced (node_id 0) + fresh-budget stamped
        // (node_count). R311y226 — the FRESH carrier now carries the per-message Push
        // qos ext (priority + express) so a subscriber reads the band via
        // `Sample::priority()`. congestion is Drop (publish_qos exposes no congestion
        // knob — a wz-side setter is a follow-up).
        let qos = wz_session_core::sample::QosLevel::from_parts(
            priority,
            wz_session_core::qos::CongestionControl::Drop,
            express,
        );
        let Some((push, children)) =
            compute_self_publish_forward(&self.net, &self.subs, keyexpr, || {
                // A DEFAULT band carries no metadata: skip the meta bundle and emit
                // the stripped baseline (byte-identical to a plain `publish`). The
                // encoder `build_push_outer_extensions` suppresses a DEFAULT ext
                // anyway — it stays the correctness SSOT; this is the allocation
                // fast-path that also keeps the two builders producing identical
                // bytes for a DEFAULT publish.
                if qos == wz_session_core::sample::QosLevel::DEFAULT {
                    build_push_literal(keyexpr, payload)
                } else {
                    build_push_literal_with_meta(
                        keyexpr,
                        payload,
                        &wz_session_core::metadata::PushMetadata {
                            qos: Some(qos),
                            ..Default::default()
                        },
                    )
                }
            })?
        else {
            return Ok(0); // no remote subscriber / no tree direction -> nothing to send
        };
        self.fan_out_qos(true, priority, express, None, |_id, zid| {
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
        let self_zid = *self.net.borrow().self_zid();
        let registered = self.subs.borrow_mut().register(keyexpr, self_zid, ());
        // node_id 0 = self-originated (build_declare_subscriber emits no ext_nodeid);
        // literal keyexpr (mapping id 0 + suffix, the wz MVP form).
        let declare = build_declare_subscriber(0, 0, Some(keyexpr))?;
        // FUTURE-mode push: a NEW local subscriber -> declare it to any CLIENT face
        // whose stored FUTURE interest matches (a co-attached publisher's
        // write-filter learns THIS node's own subscriber). No inbound face (origin
        // None); only on a genuinely new registration.
        if registered {
            self.push_future_subscription(keyexpr, None);
        }
        self.flood_to_tree_children(&self_zid, || {
            NetworkMessage::Declare(Box::new(declare.clone()))
        })
    }

    /// Group an interest table's entries by keyexpr into `(keyexpr, source-zid-hex
    /// list)` — the WHOLE-TABLE materialization the admin `subscriber`/`queryable`
    /// introspection replies from. This mirrors zenoh's `get_subscriptions` /
    /// `get_queryables`, which enumerate EVERY known declaration tagged by its source
    /// (`net/routing/hat/mod.rs:211`), NOT only this node's own — a peer that has
    /// learned a remote subscription lists it too. Each keyexpr's source zids become
    /// the `peers` bucket of the admin `Sources` body (a peer-tier linkstate interest
    /// table's sources are peers; the self-declared entry is registered under this
    /// node's own zid). A fresh owned snapshot per call (the caller re-materializes it
    /// each app-tick), never a retained side-table.
    #[cfg(feature = "adminspace-introspection-handlers")]
    fn group_interest_sources<V: Clone>(
        table: &LinkstatepeerInterest<V>,
    ) -> Vec<(String, Vec<String>)> {
        let mut by_key: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for (ke, zid, _) in table.entries() {
            by_key
                .entry(ke)
                .or_default()
                .push(wz_session_core::zid_hex::zid_to_zenoh_hex(zid.as_slice()));
        }
        by_key.into_iter().collect()
    }

    /// The declared subscribers this node knows (`@/<zid>/<whatami>/subscriber/**`
    /// admin introspection, §5.23) — every keyexpr in the [`subs`](Self#structfield.subs)
    /// interest table paired with the hex zids that declared it. See
    /// [`group_interest_sources`](Self::group_interest_sources) for the whole-table /
    /// Sources rationale.
    #[cfg(feature = "adminspace-introspection-handlers")]
    pub fn subscriptions(&self) -> Vec<(String, Vec<String>)> {
        Self::group_interest_sources(&self.subs.borrow())
    }

    /// The declared queryables this node knows (`@/<zid>/<whatami>/queryable/**` admin
    /// introspection, §5.23) — the [`qabls`](Self#structfield.qabls) twin of
    /// [`subscriptions`](Self::subscriptions). The queryable body is the SAME `Sources`
    /// struct zenoh serializes (`get_queryables`, `hat/mod.rs:252`), NOT the
    /// per-declaration `QueryableInfoType`.
    #[cfg(feature = "adminspace-introspection-handlers")]
    pub fn queryables(&self) -> Vec<(String, Vec<String>)> {
        Self::group_interest_sources(&self.qabls.borrow())
    }

    /// Emit the unsolicited FUTURE `DeclareSubscriber` pushes a newly-learned
    /// subscription `new_ke` (sourced at `origin`, `None` for this node's own local
    /// subscriber) triggers: one per CLIENT face whose stored FUTURE interest
    /// matches and has not yet been told this reply ke (zenoh
    /// `propagate_simple_subscription_to`). The push carries the interned non-zero
    /// decl id, `interest_id: None`, no `I` flag — an unsolicited declare, NOT an
    /// interest reply. `origin` is never pushed (no self-echo).
    fn push_future_subscription(&self, new_ke: &str, origin: Option<FaceId>) {
        let pushes = self
            .future_subs
            .borrow_mut()
            .pushes_for_new(new_ke, origin, |_, _| ());
        for (face, reply_ke, id, ()) in pushes {
            match build_declare_subscriber(id, 0, Some(&reply_ke)) {
                Ok(decl) => {
                    self.send_one_to_face(face, NetworkMessage::Declare(Box::new(decl)));
                    self.future_pushes.set(self.future_pushes.get() + 1);
                }
                Err(e) => {
                    log::warn!("peer forward: future sub push build failed for {reply_ke:?}: {e:?}")
                }
            }
        }
    }

    /// The MERGED [`QueryableInfo`] a querier interested in `ke` would see — the OR
    /// of `complete` (min `distance`) over every queryable in `self.qabls` that
    /// intersects `ke` (self-local declares register there under `self_zid`, so they
    /// fold in — the SAME single-set fold [`dump_interest_qabls`](Self::dump_interest_qabls)
    /// uses). The value a FUTURE qabl push MUST carry (a single source's raw info
    /// would downgrade an aggregate reply and re-arm an ALL_COMPLETE filter). Folds
    /// `qabls` GLOBALLY — a co-attached client queryable folds in through the SELF's-zid
    /// aggregate slot ([`derived_self_qabl_info`](Self::derived_self_qabl_info) merged it
    /// there on ingest), so the pushed value already reflects the client-qabl plane; the
    /// querier's OWN-queryable exclusion is by the push-recipient `origin` arg of
    /// [`push_future_queryable`](Self::push_future_queryable) (a self-query-and-host
    /// querier's own qabl folding into the value it sees is a benign minor over-include —
    /// a named merged_qabl_info-exclude refinement, not a black-hole).
    fn merged_qabl_info(&self, ke: &str) -> QueryableInfo {
        let mut merged: Option<QueryableInfo> = None;
        for (_ke, _zid, info) in self.qabls.borrow().matching_entries(ke, None) {
            merged = Some(match merged {
                Some(m) => m.merge(*info),
                None => *info,
            });
        }
        merged.unwrap_or(QueryableInfo::DEFAULT)
    }

    /// Emit the unsolicited FUTURE `DeclareQueryable` pushes a newly-learned
    /// queryable `new_ke` (sourced at `origin`, `None` for self-local) triggers — the
    /// query-plane twin of [`push_future_subscription`](Self::push_future_subscription).
    /// Each push carries the RE-FOLDED merged [`QueryableInfo`] for its reply ke
    /// ([`merged_qabl_info`](Self::merged_qabl_info)), so a completeness flip re-
    /// declares the SAME interned id. `origin` is never pushed (no self-echo).
    /// Increments [`future_qabl_pushes`](Self#structfield.future_qabl_pushes) per
    /// emitted push (R311y158, the peer-tier observability parity with the router);
    /// the peer-mode cross-impl e2e that consumes the `run_peer` witness is a named
    /// follow-up.
    fn push_future_queryable(&self, new_ke: &str, origin: Option<FaceId>) {
        let pushes =
            self.future_qabls
                .borrow_mut()
                .pushes_for_new(new_ke, origin, |reply_ke, _dest| {
                    // Folds `self.qabls` GLOBALLY; a co-attached client queryable folds in
                    // via SELF's-zid aggregate slot (merged there on ingest), so the pushed
                    // value reflects the client-qabl plane. The `origin` push-recipient
                    // exclusion (above) already suppresses echoing a declarer its own
                    // queryable; a per-`_dest` merged-info exclusion is the named refinement.
                    self.merged_qabl_info(reply_ke)
                });
        for (face, reply_ke, id, info) in pushes {
            match build_declare_queryable_with_id_info(id, &reply_ke, info) {
                Ok(decl) => {
                    self.send_one_to_face(face, NetworkMessage::Declare(Box::new(decl)));
                    self.future_qabl_pushes
                        .set(self.future_qabl_pushes.get() + 1);
                }
                Err(e) => {
                    log::warn!(
                        "peer forward: future qabl push build failed for {reply_ke:?}: {e:?}"
                    )
                }
            }
        }
    }

    /// Whether ANY subscription/queryable wz still holds INTERSECTS `ke` — the
    /// "still backed" existence predicates the R311y151 undeclare-push consults AFTER
    /// a withdrawal (`false` => the pushed reply ke lost its LAST backer, so undeclare
    /// and re-arm the filter). Fold GLOBALLY (`None` exclusion) so a self-local decl
    /// under `self_zid` still counts as backing. Existence, NOT `merged_qabl_info`
    /// (which folds to DEFAULT on zero matches).
    fn any_sub_matches(&self, ke: &str) -> bool {
        !self.subs.borrow().matching_entries(ke, None).is_empty()
    }

    fn any_qabl_matches(&self, ke: &str) -> bool {
        !self.qabls.borrow().matching_entries(ke, None).is_empty()
    }

    /// Emit the R311y151 UNDECLARE pushes a withdrawn SUBSCRIPTION `withdrawn_ke`
    /// triggers — one `UndeclareSubscriber(id)` per CLIENT face whose pushed reply ke
    /// is now un-backed, clearing the stale `pushed` entry so the pico write-filter
    /// re-arms. Run AFTER the sub is removed from `self.subs`. Counterless (like the
    /// peer push).
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

    /// The queryable twin of [`undeclare_push_subs`](Self::undeclare_push_subs). Two
    /// halves: `forgets_for_withdrawn` -> `UndeclareQueryable(id)` for each FULLY
    /// un-backed reply ke (y151/y152), and `re_pushes_for_withdrawn` -> a re-declared
    /// `DeclareQueryable(id, ke, DOWNGRADED info)` for each STILL-backed reply ke whose
    /// FOLDED completeness dropped (case c, R311y153) so an ALL_COMPLETE querier re-arms.
    /// The peer folds `self.qabls` GLOBALLY ([`merged_qabl_info`](Self::merged_qabl_info),
    /// no exclusion — a co-attached client queryable folds in via SELF's-zid aggregate).
    /// `forgets` runs FIRST so `re_pushes` re-folds only survivors.
    ///
    /// SUPERSET over zenoh (intentional, north-star superset-not-mirror): zenoh's
    /// linkstate_peer hat `queries_remove_node` is FULL-UNDECLARE-ONLY — no partial
    /// downgrade re-declare (hat/linkstate_peer/queries.rs `unregister_linkstatepeer_queryable`
    /// fires `propagate_forget_simple_queryable` only when the qabl set empties; contrast
    /// the ROUTER hat's re-declare arm at hat/router/queries.rs:930-940). Wiring the
    /// downgrade re-push into the peer closes the same ALL_COMPLETE-downgrade hole the
    /// linkstate_peer hat leaves open — a valid CLIENT-directed re-declare pico handles
    /// via drop-first + conditional-readd (`net/filtering.c`), never sent to a real peer.
    fn undeclare_push_qabls(&self, withdrawn_ke: &str) {
        let (forgets, re_pushes) = {
            let mut store = self.future_qabls.borrow_mut();
            let forgets = store.forgets_for_withdrawn(withdrawn_ke, |rk| self.any_qabl_matches(rk));
            let re_pushes =
                store.re_pushes_for_withdrawn(withdrawn_ke, |rk, _dest| self.merged_qabl_info(rk));
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
                    "peer forward: qabl downgrade re-push build failed for {reply_ke:?}: {e:?}"
                ),
            }
        }
    }

    /// Originate a LOCAL queryable INTO the mesh: this node offers a queryable for
    /// `keyexpr` with the given `complete` flag (the BestMatching input — `true` =
    /// this node can FULLY answer the keyexpr, e.g. a storage holding the whole
    /// key space), so register self's queryable in
    /// [`qabls`](Self#structfield.qabls) under its OWN zid and flood a sourced
    /// `DeclareQueryable` — CARRYING the `QueryableInfo`
    /// ([`set_declare_queryable_info`]) — to self's CHILDREN in self's own
    /// spanning tree (this node is the source, node_id 0). Each child registers
    /// self's queryable (with completeness) via
    /// [`forward_queryable`](Self::forward_queryable) and re-floods. The
    /// query-plane counterpart to [`declare_subscription`](Self::declare_subscription)
    /// (subs) and the SELF-origination twin of
    /// [`forward_queryable`](Self::forward_queryable) (which re-floods a RECEIVED
    /// declaration). Mirrors zenoh `declare_queryable` ->
    /// `declare_linkstatepeer_queryable` -> `propagate_sourced_queryable` with
    /// source = self and the local `QueryableInfo`. Returns the number of
    /// tree-child faces reached.
    ///
    /// `complete: false` is the DEFAULT `QueryableInfo`, which
    /// [`set_declare_queryable_info`] OMITS (no ext, byte-identical to the no-info
    /// wire — zenoh's omit-on-DEFAULT); only a `complete` queryable adds the ext
    /// that drives a downstream relay's BestMatching select
    /// (the BestMatching arm of [`compute_query_directions`]).
    pub fn declare_queryable(&self, keyexpr: &str, complete: bool) -> Result<usize, CodecError> {
        let self_zid = *self.net.borrow().self_zid();
        // The local QueryableInfo (distance 0 — the SSOT local-declaration
        // convention). The downstream re-flood carries this verbatim (R311uq, no
        // per-hop increment); BestMatching reads the GRAPH distance, not this
        // carried value.
        let info = QueryableInfo::local(complete);
        // Register self's OWN queryable under its own zid — as zenoh's
        // declare_simple_queryable registers under tables.zid — so the tree-change
        // re-advertise re-floods it to peers that join LATER, iterated uniformly
        // with remote queryables (the late-joiner convergence, like
        // declare_subscription). The single (ke, self_zid) slot OVERWRITES, so advertise
        // the MERGED info over ALL of this node's sources (self-native + co-attached
        // client queryables, [`derived_self_qabl_info`](Self::derived_self_qabl_info)) —
        // else this self-native declare would CLOBBER a coexisting client queryable's
        // completeness (and vice-versa). This declare's own source is not yet in
        // `local_queryables` (register_local_queryable pushes AFTER), so fold `info` in
        // explicitly; with no other source the merge is just `info` (behavior-preserving).
        // INVARIANT: a self-hosted queryable MUST be declared via `register_local_queryable`
        // (which records it in `local_queryables` so a LATER re-derive sees it). A BARE
        // `declare_queryable` — never tracked in `local_queryables` — coexisting with a
        // client queryable on the same ke would be invisible to `derived_self_qabl_info`
        // and could be clobbered by the client's re-derive; the sole in-tree caller is
        // `register_local_queryable`, so this stays a documented constraint, not a live gap.
        let advert = self
            .derived_self_qabl_info(keyexpr)
            .map_or(info, |d| d.merge(info));
        self.qabls.borrow_mut().register(keyexpr, self_zid, advert);
        // FUTURE-push (R311y150): a self-local queryable is proactively pushed to any
        // CLIENT face whose FUTURE querier-interest matches (origin None = no inbound
        // face), with the RE-FOLDED merged info; the store dedups a redundant
        // re-declare and re-pushes only a completeness flip.
        // The retraction twin [`undeclare_queryable`](Self::undeclare_queryable) exists
        // (R311y154): it drops the `local_queryables` reply handler, re-arms any waiting
        // client querier, and (via `withdraw_mesh_qabl_if_unbacked`) downgrades or fully
        // withdraws the mesh advert depending on the surviving sources.
        self.push_future_queryable(keyexpr, None);
        // node_id 0 = self-originated; the merged completeness rides the body ext
        // (omitted when DEFAULT/incomplete — the byte-identical no-info wire).
        let mut declare = build_declare_queryable(0, 0, Some(keyexpr))?;
        set_declare_queryable_info(&mut declare, advert);
        self.flood_to_tree_children(&self_zid, || {
            NetworkMessage::Declare(Box::new(declare.clone()))
        })
    }

    /// R311y44 (§5.23 Phase 2a) — host a LOCAL queryable WITH a reply-producing
    /// `handler` on this node. Reuses [`declare_queryable`](Self::declare_queryable)
    /// for the interest-registration + flood (so upstream peers route Queries
    /// toward this node), then stores the handler. A routed Query whose only match
    /// is this node is dispatched to the handler in
    /// [`forward_request`](Self::forward_request)'s empty-route branch. Returns the
    /// declare flood reach (tree-child faces), like `declare_queryable`.
    pub fn register_local_queryable(
        &self,
        keyexpr: &str,
        complete: bool,
        handler: LocalQueryHandler,
    ) -> Result<usize, CodecError> {
        let reached = self.declare_queryable(keyexpr, complete)?;
        // Wrap the caller's `Box<dyn FnMut>` in the shared `Rc<RefCell<…>>` cell here
        // (INTERNAL — the pub `handler: LocalQueryHandler` signature is unchanged) so
        // dispatch can invoke it with the `local_queryables` borrow released.
        self.local_queryables.borrow_mut().push(LocalQueryable {
            keyexpr: keyexpr.to_string(),
            complete,
            handler: Rc::new(RefCell::new(handler)),
        });
        Ok(reached)
    }

    /// R311y46 (§5.23 Phase 3a) — host a LOCAL subscriber WITH a `handler` on this
    /// node. Reuses [`declare_subscription`](Self::declare_subscription) for the
    /// interest flood (so upstream peers route matching Puts toward this node),
    /// then stores the handler. A Put whose concrete key matches the declared
    /// pattern is delivered to the handler at the Push ingress
    /// ([`dispatch_local_subscribers`](Self::dispatch_local_subscribers)), in
    /// ADDITION to the remote fan-out. Returns the declare flood reach.
    pub fn register_local_subscriber(
        &self,
        keyexpr: &str,
        handler: LocalSubscriberHandler,
    ) -> Result<usize, CodecError> {
        let reached = self.declare_subscription(keyexpr)?;
        // Wrap in the shared `Rc<RefCell<…>>` cell here (INTERNAL — the pub
        // `handler: LocalSubscriberHandler` signature is unchanged), the twin of
        // register_local_queryable, so dispatch invokes with the borrow released.
        self.local_subscribers.borrow_mut().push(LocalSubscriber {
            keyexpr: keyexpr.to_string(),
            handler: Rc::new(RefCell::new(handler)),
        });
        Ok(reached)
    }

    /// R311y44 — dispatch a routed Query to any LOCAL queryable hosting a matching
    /// keyexpr, emitting the handler's replies + a closing `ResponseFinal` back on
    /// the inbound face (`rid` = the querier's inbound rid; the existing per-hop
    /// return path unwinds it). Returns `true` iff at least one local queryable
    /// matched (so the caller skips the bare empty-route `ResponseFinal`).
    ///
    /// Re-entrancy contract (R311y156, collect-drop-invoke): matching handlers are
    /// cloned out (`Rc<RefCell<…>>`) under a SHORT `borrow()` of `local_queryables`;
    /// the borrow is DROPPED before any handler runs, and each is invoked via
    /// `try_borrow_mut`. So a handler may re-entrantly `register_local_queryable` /
    /// `undeclare_queryable` (both `borrow_mut` `local_queryables`) — including
    /// undeclaring ITSELF — without panicking: a re-entrant register lands after the
    /// snapshot (excluded from THIS query, zenoh's "declared after the query"
    /// semantics); a re-entrant undeclare drops the Vec's `Rc` while the snapshot
    /// clone keeps the mid-fire handler alive. This mirrors zenoh's lock-free
    /// callback delivery (`route_query` drops `rtables` before `send_request`;
    /// `handle_query` drops the session read guard before `cb.call`). The self-query
    /// case: a handler that, mid-answer, re-queries ITS OWN ke re-enters this dispatch
    /// where `try_borrow_mut` finds it busy; R311y168 DEFERS the busy handler + HOLDS
    /// this query's `ResponseFinal` into `query_redelivery` and redelivers off-stack at
    /// the outermost `forward` exit
    /// ([`drain_query_redelivery`](Self::drain_query_redelivery)) -- reply-before-final
    /// preserved (an eager Final would make the querier discard the redelivered reply,
    /// zenoh removing the query on ResponseFinal, session.rs:3023). `send_to_face`
    /// (which borrows `faces`) still runs AFTER, on the drained `replies`.
    ///
    /// Cost: the snapshot `Vec` allocates ONLY on ≥1 local match (Rust `Vec` is lazy,
    /// so a no-match relay pays nothing); the alloc is inherent to dropping the borrow
    /// before invoke. A `SmallVec<[_; 1]>` / SingleOrVec inline form (zenoh's
    /// `SingleOrVec`, session.rs) is a re-openable micro-opt if per-delivery alloc ever
    /// profiles hot — not warranted now (off the mesh fan-out hot path).
    fn dispatch_local_queryables(
        &self,
        inbound: FaceId,
        reliable: bool,
        request: &RequestOwned,
        keyexpr: &str,
        target: Option<QueryTarget>,
    ) -> bool {
        let query_chunks: Vec<&str> = keyexpr.split('/').collect();
        let view = LocalQueryView {
            keyexpr,
            rid: request.rid,
        };
        // Accumulate via the SAME Session-side `QueryResponder` + `QueryReply`
        // currency the wire queryable path uses, and map each reply to a Response
        // through the ONE `QueryReply::into_response` builder — so Put / keyed /
        // encoded / stamped / attached / Err replies are all handled identically,
        // with no parallel reply accumulator (SSOT).
        // Snapshot the matching handlers under a SHORT borrow, then DROP it so the
        // invoke runs borrow-free (the re-entrancy contract above). A queryable
        // answers a query whose keyexpr its declaration INTERSECTS (zenoh's
        // `decl.intersects(query)`); under AllComplete only COMPLETE queryables answer.
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
        let mut replies: Vec<QueryReply> = Vec::new();
        let mut deferred: Vec<Rc<RefCell<LocalQueryHandler>>> = Vec::new();
        {
            let mut responder = QueryResponder::new(request.rid, keyexpr.to_string(), &mut replies);
            for handler in &matched {
                match handler.try_borrow_mut() {
                    Ok(mut h) => (**h)(&view, &mut responder),
                    // #3-c QUERY half (R311y168) — a BUSY queryable is mid-answer and
                    // has re-queried ITS OWN ke (self-query). Skipping it AND emitting
                    // the Final eagerly (the y156 behavior) would DROP its answer:
                    // zenoh removes the query on ResponseFinal (session.rs:3023), then
                    // discards a late reply (:2807). DEFER the busy handler + HOLD this
                    // query's Final for redelivery at the outermost forward exit.
                    Err(_) => deferred.push(Rc::clone(handler)),
                }
            }
        }
        // Emit the free handlers' replies now — order-agnostic (a query fan-out has
        // no reply order); ONLY the closing ResponseFinal must come last. Routed
        // through send_to_face so egress ACL applies, as the bare final does.
        self.emit_query_responses(inbound, reliable, replies);
        if deferred.is_empty() {
            // No self-query: emit the closing ResponseFinal now — the querier is one
            // hop away (rid = its own inbound rid); upstream hops unwind via the
            // existing forward_response path (the y44 behavior, unchanged).
            self.emit_query_final(inbound, reliable, request.rid);
        } else {
            // Self-query: queue the busy handler(s) + this query's return context with
            // the Final SUPPRESSED; drain_query_redelivery (outermost forward exit)
            // fires them off-stack and emits reply-before-final. Bounded drop-oldest
            // (RingChannel) by SELF_ECHO_QUEUE_CAP, like the sub-plane sub_redelivery.
            self.enqueue_deferred_query(DeferredQuery {
                handlers: deferred,
                rid: request.rid,
                keyexpr: keyexpr.to_string(),
                inbound,
                reliable,
            });
        }
        true
    }

    /// #3-c QUERY half (R311y168) — emit a queryable's accumulated replies as
    /// `Response` messages on the querier's `inbound` face, each mapped through the
    /// ONE `QueryReply::into_response` SSOT builder (so Put / keyed / encoded /
    /// stamped / attached / Err replies are handled identically). Factored from
    /// [`dispatch_local_queryables`](Self::dispatch_local_queryables) so the deferred
    /// self-query redelivery ([`drain_query_redelivery`](Self::drain_query_redelivery))
    /// reuses the exact same emission.
    fn emit_query_responses(&self, inbound: FaceId, reliable: bool, replies: Vec<QueryReply>) {
        for reply in replies {
            let Ok(resp) = reply.into_response() else {
                continue;
            };
            self.send_to_face(inbound, reliable, || {
                NetworkMessage::Response(Box::new(resp.clone()))
            });
        }
    }

    /// #3-c QUERY half (R311y168) — emit the closing `ResponseFinal` (rid = the
    /// querier's) that terminates a query. HELD BACK when a self-query defers a busy
    /// queryable (an eager Final would make the querier discard the redelivered reply
    /// -- zenoh removes the query on ResponseFinal, session.rs:3023), then emitted
    /// once by [`drain_query_redelivery`](Self::drain_query_redelivery) after the
    /// deferred handlers answer.
    fn emit_query_final(&self, inbound: FaceId, reliable: bool, rid: u64) {
        let final_msg = wz_session_core::response_final_build::build_response_final(rid);
        self.send_to_face(inbound, reliable, || {
            NetworkMessage::ResponseFinal(final_msg.clone())
        });
    }

    /// #3-c QUERY half (R311y168) — queue a deferred self-query, bounded drop-oldest
    /// (RingChannel) at [`SELF_ECHO_QUEUE_CAP`](Self::SELF_ECHO_QUEUE_CAP) -- the query
    /// twin of the sub-plane `sub_redelivery` cap in
    /// [`enqueue_self_echo`](Self::enqueue_self_echo). UNLIKE a dropped fire-and-forget
    /// Sample, a dropped `DeferredQuery` carries a HELD `ResponseFinal` a querier
    /// awaits, so on eviction we EMIT that Final (an empty answer) rather than strand
    /// the evicted querier to its get() timeout -- the query terminator drop-oldest
    /// would otherwise swallow (only a pathological > CAP-deferred-in-one-tick
    /// self-querier evicts). The evicted Final is emitted OUTSIDE the `query_redelivery`
    /// borrow (send_to_face borrows `faces`, not `query_redelivery`).
    fn enqueue_deferred_query(&self, dq: DeferredQuery) {
        let evicted = {
            let mut q = self.query_redelivery.borrow_mut();
            let evicted = if q.len() >= Self::SELF_ECHO_QUEUE_CAP {
                q.pop_front()
            } else {
                None
            };
            q.push_back(dq);
            evicted
        };
        if let Some(ev) = evicted {
            self.emit_query_final(ev.inbound, ev.reliable, ev.rid);
        }
    }

    /// #3-c QUERY half (R311y168) — redeliver deferred self-queries to their
    /// (now-unwound) queryables: the query twin of
    /// [`drain_sub_redelivery`](Self::drain_sub_redelivery), run at the outermost
    /// [`forward`](FaceForwarder::forward) exit off the handler stack. For each
    /// deferred query, fire its (now-free) handlers into a fresh `QueryResponder`,
    /// emit the replies, THEN the one closing `ResponseFinal` that was held -- so the
    /// querier observes reply-before-final. Bounded to
    /// [`SELF_ECHO_QUEUE_CAP`](Self::SELF_ECHO_QUEUE_CAP) per call: an unconditional
    /// self-querier re-enqueues (drop-oldest capped) and spins across ticks, never a
    /// hang or stack overflow. A queryable retracted after deferral is purged from the
    /// record's handler set (undeclare_queryable) but the Final STILL emits (an empty
    /// answer), so the querier's get() terminates instead of hanging. NB (the sub twin's
    /// caveat, sharpened for queries): a handler that PANICS mid-drain unwinds past the
    /// `forward_depth` decrement and disables the drain, stranding queued Finals -- their
    /// queriers then time out (a query's Final is a terminator, not a droppable sample).
    /// Same non-panic-safe class as `drain_sub_redelivery`; a single-task panic poisons
    /// the drive task regardless, so an `FnMut` handler must not panic.
    fn drain_query_redelivery(&self) {
        let mut budget = Self::SELF_ECHO_QUEUE_CAP;
        while budget > 0 {
            let Some(dq) = self.query_redelivery.borrow_mut().pop_front() else {
                break;
            };
            budget -= 1;
            let view = LocalQueryView {
                keyexpr: &dq.keyexpr,
                rid: dq.rid,
            };
            let mut replies: Vec<QueryReply> = Vec::new();
            {
                let mut responder = QueryResponder::new(dq.rid, dq.keyexpr.clone(), &mut replies);
                for handler in &dq.handlers {
                    if let Ok(mut h) = handler.try_borrow_mut() {
                        (**h)(&view, &mut responder);
                    }
                }
            }
            self.emit_query_responses(dq.inbound, dq.reliable, replies);
            self.emit_query_final(dq.inbound, dq.reliable, dq.rid);
        }
    }

    /// R311y46 (§5.23 Phase 3a) — deliver a Put to any LOCAL subscriber whose
    /// declared keyexpr PATTERN matches the Put's concrete key, firing each handler
    /// with a [`SampleView`]. Called UNCONDITIONALLY after
    /// [`forward_push`](Self::forward_push) at the Push ingress: a Put delivers to
    /// BOTH the remote interested subtrees (`forward_push`, which excludes self) AND
    /// any locally-hosted subscriber (here) — no double-delivery, since forward_push
    /// excludes self. A Del body (the non-`MsgPut` variant) is NOT delivered this
    /// round; a `MsgPut` payload is delivered RAW — a body-level SHM descriptor, if
    /// present, is delivered un-decoded (descriptor decoding is a deferred layer;
    /// the §5.23 config-write is a plain Put).
    ///
    /// Re-entrancy contract (R311y156, collect-drop-invoke): the twin of
    /// [`dispatch_local_queryables`](Self::dispatch_local_queryables) — matching
    /// handlers are cloned out (`Rc<RefCell<…>>`) under a SHORT `borrow()`, the
    /// borrow is DROPPED, then each is invoked via `try_borrow_mut`. So a handler
    /// may re-entrantly `register_local_subscriber` / `undeclare_subscription`
    /// (incl. self-undeclare) without a `RefCell` panic (a re-entrant register is
    /// excluded from THIS Put's snapshot; a re-entrant undeclare drops the Vec's
    /// `Rc` while the snapshot clone keeps the mid-fire handler alive). A handler
    /// that synchronously re-delivers to ITSELF (publishes to its own pattern) finds
    /// `try_borrow_mut` busy; R311y167 QUEUES the owned self-echo sample
    /// ([`enqueue_self_echo`](Self::enqueue_self_echo)) and redelivers it off-stack at
    /// the outermost `forward` exit
    /// ([`drain_sub_redelivery`](Self::drain_sub_redelivery)) -- faithful to zenoh's
    /// default channel handler, not a drop.
    fn dispatch_local_subscribers(&self, inbound: FaceId, reliable: bool, push: &PushOwned) {
        // Resolve the Put keyexpr against the inbound face's alias table (as
        // forward_push does); an unresolvable alias is dropped.
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
        // The MsgPut payload, delivered raw. A non-Put body (MsgDel) is skipped;
        // a body-level SHM descriptor is delivered un-decoded (a deferred layer).
        let payload: &[u8] = match &push.body {
            PushOwnedVariant::CodecZenohMsgPut(put) => put.payload.as_slice(),
            _ => return,
        };
        let sample = BorrowedSample {
            keyexpr: &keyexpr,
            payload,
            kind: SampleKind::Put,
            reliability: if reliable {
                Reliability::Reliable
            } else {
                Reliability::BestEffort
            },
        };
        // Snapshot every LOCAL subscriber whose declared keyexpr (a PATTERN) matches
        // the concrete Put key (the R227 subscriber-side match) under a SHORT borrow,
        // drop it, then fire — so a handler may re-enter the registry (contract above).
        let matched: Vec<Rc<RefCell<LocalSubscriberHandler>>> = {
            let locals = self.local_subscribers.borrow();
            locals
                .iter()
                .filter(|sub| {
                    let pattern_chunks: Vec<&str> = sub.keyexpr.split('/').collect();
                    keyexpr_pattern_matches(&pattern_chunks, &keyexpr)
                })
                .map(|sub| Rc::clone(&sub.handler))
                .collect()
        };
        for handler in &matched {
            match handler.try_borrow_mut() {
                Ok(mut h) => (**h)(&sample),
                // #3-c (R311y167) — the handler is BUSY: it re-entered THIS dispatch
                // for its OWN pattern (self-echo). Don't DROP the sample (the y156
                // skip); queue the busy handler's `Rc` + an OWNED copy for redelivery
                // at the outermost `forward` exit — faithful to zenoh's FifoChannel
                // requeue (handlers/fifo.rs:57-66), which never drops a self-echo.
                // (The queryable twin still drops, pending its own round: it emits
                // ResponseFinal eagerly, so redelivery there needs the
                // Reply-before-Final hold — the deferred #3-c query half.)
                Err(_) => self.enqueue_self_echo(handler, &sample),
            }
        }
    }

    /// #3-c (R311y167) — the self-echo redelivery queue capacity + per-`forward`
    /// drain budget, mirroring zenoh's default reception channel size
    /// (`API_DATA_RECEPTION_CHANNEL_SIZE = 256`, api/session.rs:118). The queue is
    /// drop-OLDEST past the cap (a RingChannel, api/handlers/ring.rs) so an
    /// unconditional self-republisher spins with bounded memory, never an unbounded
    /// queue — zenoh bounds memory / backpressure, never the loop itself.
    const SELF_ECHO_QUEUE_CAP: usize = 256;

    /// #3-c (R311y167) — queue a self-echo sample for redelivery. Called by
    /// [`dispatch_local_subscribers`](Self::dispatch_local_subscribers) when a
    /// matching handler is BUSY (it re-entered the dispatch for its own pattern, so
    /// `try_borrow_mut` fails). Materializes an OWNED [`Sample`] (the borrowed view
    /// cannot outlive the dispatch frame) and pushes it with the busy handler's
    /// `Rc`; drop-OLDEST past [`SELF_ECHO_QUEUE_CAP`](Self::SELF_ECHO_QUEUE_CAP)
    /// (RingChannel semantics) bounds an unconditional self-republisher.
    fn enqueue_self_echo(
        &self,
        handler: &Rc<RefCell<LocalSubscriberHandler>>,
        view: &dyn SampleView,
    ) {
        let mut q = self.sub_redelivery.borrow_mut();
        if q.len() >= Self::SELF_ECHO_QUEUE_CAP {
            q.pop_front(); // drop-oldest (RingChannel), never grow unbounded
        }
        q.push_back((Rc::clone(handler), Sample::from_view(view)));
    }

    /// #3-c (R311y167) — redeliver queued self-echo samples to their (now-unwound)
    /// handlers. Run ONCE at the outermost [`forward`](FaceForwarder::forward) exit,
    /// off the handler stack — mirroring zenoh's receiver-side channel drain running
    /// on its own task, not nested in the publish call. Bounded to
    /// [`SELF_ECHO_QUEUE_CAP`](Self::SELF_ECHO_QUEUE_CAP) deliveries per call: a
    /// handler that self-echoes AGAIN during redelivery re-enqueues (drop-oldest
    /// capped), so an unconditional self-republisher spins across `forward` ticks
    /// with bounded per-tick work + bounded memory, never a synchronous hang or a
    /// stack overflow. An over-budget remainder (only a pathological
    /// unconditional-republisher exceeds the per-call budget) rides the NEXT
    /// `forward`, so on a quiescent forwarder the last such echo waits for an
    /// unrelated future Push. NB: a handler that PANICS unwinds past the
    /// `forward_depth` decrement and disables the drain — the file's other counters
    /// (`data_seen`, `recomputes`) are equally non-panic-safe, and a single-task
    /// panic poisons the drive task regardless, so an `FnMut` handler must not panic.
    fn drain_sub_redelivery(&self) {
        let mut budget = Self::SELF_ECHO_QUEUE_CAP;
        while budget > 0 {
            let Some((handler, sample)) = self.sub_redelivery.borrow_mut().pop_front() else {
                break;
            };
            budget -= 1;
            // Off-stack now (redelivery runs after the dispatch unwound), so
            // `try_borrow_mut` succeeds; a still-busy handler (a deeper nested
            // `forward` mid-flight) is skipped this pass, the cap bounding it.
            // Bind the borrow to a local so its `RefMut` drops before the owned
            // `handler` (an inline `if let` scrutinee temporary would outlive
            // `handler` at the loop-body scope end — E0597).
            let delivery = handler.try_borrow_mut();
            if let Ok(mut h) = delivery {
                (**h)(&sample as &dyn SampleView);
            }
        }
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
        // Drop the self-hosted subscriber handler FIRST (the inverse of
        // register_local_subscriber) so a RETRACTED local subscriber STOPS receiving
        // — R311y154 closed this pre-existing residual symmetrically with
        // undeclare_queryable's local_queryables drop (dispatch_local_subscribers
        // would otherwise keep delivering) — and so the union check below sees it gone.
        // R311y167 (#3-c) — collect the retracted handlers' `Rc`s and PURGE any
        // self-echo already queued for them from `sub_redelivery`: else the
        // outermost `forward` drain would redeliver to a retracted subscriber
        // (extending the in-flight window past this "stops receiving" contract), and
        // an `Rc`-capturing handler would leak via the undrained queued clone.
        let mut retracted: Vec<Rc<RefCell<LocalSubscriberHandler>>> = Vec::new();
        self.local_subscribers.borrow_mut().retain(|ls| {
            if ls.keyexpr == keyexpr {
                retracted.push(Rc::clone(&ls.handler));
                false
            } else {
                true
            }
        });
        if !retracted.is_empty() {
            self.sub_redelivery
                .borrow_mut()
                .retain(|(h, _)| !retracted.iter().any(|r| Rc::ptr_eq(h, r)));
        }
        // R311y163 (D4) — UNION-gated withdraw: the peer now co-hosts CLIENT subs on
        // the SAME (ke, self_zid) mesh-advertise slot, so an unconditional withdraw
        // would blackhole a surviving co-attached client subscriber. Only the LAST
        // source's departure (no other local sub AND no client sub for `keyexpr`)
        // withdraws `subs` + floods the sourced UndeclareSubscriber + re-arms any
        // waiting future-push backer.
        self.withdraw_mesh_sub_if_unbacked(keyexpr)
    }

    /// R311y163 (D4) — is the inbound face a CLIENT (a leaf, not a mesh peer)? Read
    /// from the face's handshake WhatAmI (`peer_whatami_routing`), the SAME role
    /// source [`respond_to_interest`](Self::respond_to_interest) gates its
    /// future-interest store on — NOT the graph (a client is held without a graph
    /// node). A gone face is not a client.
    fn is_client_face(&self, id: FaceId) -> bool {
        self.faces
            .borrow()
            .get(&id)
            .is_some_and(|s| peer_whatami_routing(&s.actions) == WhatAmI::Client)
    }

    /// R311y163 (D4) — does any co-attached CLIENT face subscribe EXACTLY `keyexpr`?
    /// The client half of the mesh-advertise union refcount (the self-native half is
    /// [`local_subscribers`](Self#structfield.local_subscribers)). Exact-string,
    /// matching the per-ke `subs` slot the advertisement keys on.
    fn any_client_subscribes(&self, keyexpr: &str) -> bool {
        self.client_subs
            .borrow()
            .values()
            .any(|ids| ids.values().any(|ke| ke == keyexpr))
    }

    /// R311y163 (D4) — does any self-native local subscriber hold EXACTLY `keyexpr`?
    /// The self-native half of the mesh-advertise union refcount.
    fn any_local_subscriber(&self, keyexpr: &str) -> bool {
        self.local_subscribers
            .borrow()
            .iter()
            .any(|ls| ls.keyexpr == keyexpr)
    }

    /// R311y163 (D4) — withdraw the SELF-sourced mesh advertisement for `keyexpr`
    /// IFF no source still backs it: neither a self-native local subscriber
    /// ([`any_local_subscriber`](Self::any_local_subscriber)) nor a co-attached
    /// client sub ([`any_client_subscribes`](Self::any_client_subscribes)). On the
    /// union's 1->0 transition it withdraws self from `subs` (so a tree change no
    /// longer re-advertises the retracted ke), re-arms any waiting future-push
    /// backer (`undeclare_push_subs`), and floods the sourced UndeclareSubscriber to
    /// self's tree children. Shared by the self-native `undeclare_subscription` and
    /// the client withdraw / face-down paths; the caller removes ITS OWN source (the
    /// local-sub handler or the `client_subs` entry) BEFORE calling.
    fn withdraw_mesh_sub_if_unbacked(&self, keyexpr: &str) -> Result<usize, CodecError> {
        if self.any_local_subscriber(keyexpr) || self.any_client_subscribes(keyexpr) {
            return Ok(0); // still backed by another source — keep the advertisement
        }
        let self_zid = *self.net.borrow().self_zid();
        let removed = self.subs.borrow_mut().withdraw(keyexpr, &self_zid);
        if removed {
            // R311y151 undeclare-push: the last backer of this ke is gone; re-arm any
            // waiting CLIENT publisher whose pushed reply ke lost its last backer.
            self.undeclare_push_subs(keyexpr);
        }
        let declare = build_undeclare_subscriber_with_keyexpr(keyexpr)?;
        self.flood_to_tree_children(&self_zid, || {
            NetworkMessage::Declare(Box::new(declare.clone()))
        })
    }

    /// The MERGED [`QueryableInfo`] this peer advertises under SELF's zid for
    /// `keyexpr` — the OR of `complete` (min `distance`) over every SELF source: a
    /// self-native local queryable
    /// ([`local_queryables`](Self#structfield.local_queryables)) and a co-attached
    /// client queryable ([`client_qabls`](Self#structfield.client_qabls)) declaring
    /// EXACTLY `keyexpr`. `None` = no self source (the advert must be withdrawn).
    /// zenoh `local_peer_qabl_info` (`hat/linkstate_peer/queries.rs:67`): folds ONLY
    /// the peer's OWN sources (session_ctxs), NOT the remote-peer `linkstatepeer_qabls`
    /// and — single-net — NO cross-tier / `failover_brokering`. Deliberately NOT
    /// [`merged_qabl_info`](Self::merged_qabl_info), which folds `qabls` GLOBALLY
    /// (remote peers + self's own output slot) for the FUTURE-push value — folding
    /// that here would pollute the advert with a remote's completeness. Exact-string
    /// keying matches the per-ke `qabls` slot the advertisement registers under; seed
    /// from the FIRST source (`Option`), never [`DEFAULT`](QueryableInfo::DEFAULT)
    /// (whose `distance == 0` collapses the `min`).
    fn derived_self_qabl_info(&self, keyexpr: &str) -> Option<QueryableInfo> {
        let mut acc: Option<QueryableInfo> = None;
        for lq in self.local_queryables.borrow().iter() {
            if lq.keyexpr == keyexpr {
                let info = QueryableInfo::local(lq.complete);
                acc = Some(acc.map_or(info, |a| a.merge(info)));
            }
        }
        for ids in self.client_qabls.borrow().values() {
            for (ke, info) in ids.values() {
                if ke == keyexpr {
                    acc = Some(acc.map_or(*info, |a| a.merge(*info)));
                }
            }
        }
        acc
    }

    /// Withdraw-or-DOWNGRADE the SELF-sourced mesh advertisement for `keyexpr` after a
    /// source was removed — the qabl twin of
    /// [`withdraw_mesh_sub_if_unbacked`](Self::withdraw_mesh_sub_if_unbacked), with the
    /// info-carrying refinement subs lack (a queryable advertises a `QueryableInfo`; a
    /// subscription is presence-only). Re-derives the merged info over the SURVIVING
    /// self sources ([`derived_self_qabl_info`](Self::derived_self_qabl_info)):
    /// - `Some(merged)` — a source still backs `keyexpr`: RE-ADVERTISE a
    ///   `DeclareQueryable` carrying the (possibly DOWNGRADED) merged info — the
    ///   `register` value-diff gate suppresses a no-op re-flood — and re-arm any waiting
    ///   client querier whose folded completeness dropped
    ///   ([`undeclare_push_qabls`](Self::undeclare_push_qabls)). zenoh
    ///   `undeclare_simple_queryable`'s "contributors remain" arm
    ///   (`hat/linkstate_peer/queries.rs:559-569`).
    /// - `None` — the last source is gone: WITHDRAW self from `qabls`, re-arm the
    ///   filter, and flood the sourced `UndeclareQueryable`.
    ///
    /// The self-native [`undeclare_queryable`](Self::undeclare_queryable) and the client
    /// withdraw / face-down paths share this seam; the caller removes ITS OWN source
    /// (the `local_queryables` handler or the `client_qabls` entry) BEFORE calling.
    fn withdraw_mesh_qabl_if_unbacked(&self, keyexpr: &str) -> Result<usize, CodecError> {
        let self_zid = *self.net.borrow().self_zid();
        match self.derived_self_qabl_info(keyexpr) {
            Some(merged) => {
                let changed = self.qabls.borrow_mut().register(keyexpr, self_zid, merged);
                if !changed {
                    return Ok(0); // the surviving sources already advertise this info
                }
                // A completeness downgrade must re-arm ALL_COMPLETE queriers whose
                // pushed reply ke folded lower; the ke is still backed, so no forget.
                self.undeclare_push_qabls(keyexpr);
                let mut declare = build_declare_queryable(0, 0, Some(keyexpr))?;
                set_declare_queryable_info(&mut declare, merged);
                self.flood_to_tree_children(&self_zid, || {
                    NetworkMessage::Declare(Box::new(declare.clone()))
                })
            }
            None => {
                let removed = self.qabls.borrow_mut().withdraw(keyexpr, &self_zid);
                if removed {
                    self.undeclare_push_qabls(keyexpr);
                }
                let declare = build_undeclare_queryable_with_keyexpr(keyexpr)?;
                self.flood_to_tree_children(&self_zid, || {
                    NetworkMessage::Declare(Box::new(declare.clone()))
                })
            }
        }
    }

    /// R311y163 (D4) — ingest a co-attached CLIENT's `DeclareSubscriber`. A CLIENT is
    /// a leaf (never a graph node), so its interest cannot ride the zid-keyed `subs`
    /// tier table under its OWN zid (`resolve_source_in` would find no psid); instead
    /// it is (a) recorded in [`client_subs`](Self#structfield.client_subs)
    /// FaceId-keyed for local delivery + face-down purge, and (b) advertised into the
    /// mesh under SELF's zid — exactly as zenoh `declare_simple_subscription`
    /// re-sources a client sub under `tables.zid`. The mesh advertise is
    /// UNION-refcounted with any self-native local sub on the same ke: the sourced
    /// `DeclareSubscriber` + future-push fire only on the union's 0->1 transition
    /// (`subs.register`'s `true` return), so a second backer neither re-floods nor
    /// re-pushes.
    fn ingest_client_subscription(&self, inbound: FaceId, declare: &DeclareOwned) {
        // Read the DeclareSubscriber's declaration id + resolve its keyexpr against ITS
        // face alias table (c3c-3 B1b) in one scoped borrow; an unresolvable alias drops
        // it. The id keys the store so an id-only UndeclareSubscriber can resolve the ke.
        let (decl_id, keyexpr) = {
            let (decl_id, wireexpr) = match &declare.body {
                DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => (d.id, &d.keyexpr),
                _ => return,
            };
            let faces = self.faces.borrow();
            let Some(s) = faces.get(&inbound) else {
                return;
            };
            match resolve_wireexpr(&wireexpr.body, &s.keyexpr_table) {
                Some(ke) => (decl_id, ke),
                None => return,
            }
        };
        // Record the leaf sub id -> ke, capturing any keyexpr this id previously mapped
        // (an id RE-USED for a new ke without an intervening undeclare — displacement).
        let displaced = self
            .client_subs
            .borrow_mut()
            .entry(inbound)
            .or_default()
            .insert(decl_id, keyexpr.clone());
        // Advertise into the mesh under SELF's zid. `register` returns `true` only on the
        // union 0->1 transition (no self-native sub and no OTHER client/id already holds
        // this ke) — gate the future-push + sourced flood on it so a duplicate (same id
        // same ke, or a second holder) stays silent (the ke is already advertised).
        let self_zid = *self.net.borrow().self_zid();
        let registered = self.subs.borrow_mut().register(&keyexpr, self_zid, ());
        if registered {
            // A NEW subscriber (to this node) -> tell any co-attached CLIENT publisher
            // whose stored FUTURE interest matches (pub-before-sub write-filter close).
            // `origin = Some(inbound)` EXCLUDES the subscribing client itself, so a
            // client that pubs+subs the same ke is never echoed its OWN sub (which
            // would open its write-filter against a phantom self-subscriber) — zenoh
            // `src_face != dst_face`, mirror of the router's
            // `push_future_subscription(_, inbound)`. (Self-native `declare_subscription`
            // passes None because SELF has no face to exclude.)
            self.push_future_subscription(&keyexpr, Some(inbound));
            match build_declare_subscriber(0, 0, Some(&keyexpr)) {
                Ok(flood) => {
                    let _ = self.flood_to_tree_children(&self_zid, || {
                        NetworkMessage::Declare(Box::new(flood.clone()))
                    });
                }
                Err(e) => {
                    log::warn!("peer: client sub advertise build failed for {keyexpr:?}: {e:?}");
                }
            }
        }
        // id-reuse displacement: if this id previously mapped a DIFFERENT ke, that old ke
        // lost this backer -> withdraw its self-sourced advert if it was the LAST holder
        // (self-gated by withdraw_mesh_sub_if_unbacked's union check). Unreachable for
        // conforming clients (monotonic ids + undeclare-first); the id-map makes it
        // detectable where the keyexpr-set twin structurally could not.
        if let Some(old) = displaced {
            if old != keyexpr {
                let _ = self.withdraw_mesh_sub_if_unbacked(&old);
            }
        }
    }

    /// R311y163 (D4) / R311y178 (id-map) — withdraw a co-attached CLIENT's subscription on
    /// its graceful `UndeclareSubscriber`. A client's undeclare is ID-ONLY
    /// (`build_undeclare_subscriber(id)`, no `ext_keyexpr` — the form wz's own
    /// `send_undeclare_subscriber` + pico emit), so the retracted keyexpr is resolved BY
    /// ID from [`client_subs`](Self#structfield.client_subs) (zenoh `forget_simple_subscription`
    /// id-first), NOT by an ext the client never sends (the prior keyexpr-keyed resolve
    /// NO-OP'd, leaving the advert stale until face-down). Then (union-gated) withdraws the
    /// mesh advertisement if this was the ke's last backer. The mesh-sourced form (id 0 +
    /// ext) is a peer's and routes through [`forward_unsubscription`](Self::forward_unsubscription)
    /// instead. The face-down path ([`deregister`](FaceForwarder::deregister)) drains every
    /// id the departing client held through the same
    /// [`withdraw_mesh_sub_if_unbacked`](Self::withdraw_mesh_sub_if_unbacked) seam.
    fn withdraw_client_subscription(&self, inbound: FaceId, declare: &DeclareOwned) {
        let decl_id = match &declare.body {
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(u) => u.id,
            _ => return,
        };
        let keyexpr = {
            let mut cs = self.client_subs.borrow_mut();
            let removed = cs.get_mut(&inbound).and_then(|ids| ids.remove(&decl_id));
            if cs.get(&inbound).is_some_and(|ids| ids.is_empty()) {
                cs.remove(&inbound);
            }
            removed
        };
        let Some(keyexpr) = keyexpr else {
            return; // unknown id (never ingested / already gone) — nothing to withdraw
        };
        let _ = self.withdraw_mesh_sub_if_unbacked(&keyexpr);
    }

    /// Ingest a co-attached CLIENT's `DeclareQueryable` (the query-plane twin of
    /// [`ingest_client_subscription`](Self::ingest_client_subscription)). A CLIENT is a
    /// leaf, so its queryable cannot ride the zid-keyed [`qabls`](Self#structfield.qabls)
    /// under its OWN zid (`resolve_source` finds no psid → drop); it is (a) recorded in
    /// [`client_qabls`](Self#structfield.client_qabls) FaceId-keyed for local query
    /// DELIVERY + face-down purge, and (b) advertised into the mesh under SELF's zid —
    /// exactly as zenoh `declare_simple_queryable` re-sources under `tables.zid`. Unlike
    /// the sub twin (presence-only), the advert carries the MERGED
    /// [`QueryableInfo`](Self::derived_self_qabl_info) over every self source, so a second
    /// complete co-host UPGRADES it; the sourced flood + future-push fire only when the
    /// merged advert CHANGES (`register`'s value-diff gate), so a redundant re-declare
    /// stays silent.
    fn ingest_client_queryable(&self, inbound: FaceId, declare: &DeclareOwned) {
        // Read the DeclareQueryable's declaration id + QueryableInfo + resolve its keyexpr
        // in one scoped borrow (against ITS face alias table); unresolvable -> drop. The id
        // keys the store so an id-only UndeclareQueryable can resolve the (ke, info).
        let (decl_id, keyexpr, info) = {
            // The declared completeness rides the DeclQueryable body ext chain; absent ext
            // = zenoh DEFAULT (incomplete), the SAME read `forward_queryable` does.
            let (decl_id, wireexpr, info) = match &declare.body {
                DeclareOwnedVariant::CodecZenohDeclQueryable(dq) => (
                    dq.id,
                    &dq.keyexpr,
                    wz_session_core::queryable_info::read_queryable_info(dq.extensions.as_ref()),
                ),
                _ => return,
            };
            let faces = self.faces.borrow();
            let Some(s) = faces.get(&inbound) else {
                return;
            };
            let Some(keyexpr) = resolve_wireexpr(&wireexpr.body, &s.keyexpr_table) else {
                return;
            };
            (decl_id, keyexpr, info)
        };
        // Record id -> (ke, info), capturing any (ke, info) this id previously mapped (an id
        // RE-USED for a new ke/info without an intervening undeclare — displacement).
        let displaced = self
            .client_qabls
            .borrow_mut()
            .entry(inbound)
            .or_default()
            .insert(decl_id, (keyexpr.clone(), info));
        // Advertise the MERGED info under SELF's zid; `register` returns `true` only when
        // the merged advert changed (a new ke, or an UPGRADE from a second complete
        // co-host) — gate the future-push + sourced flood on it so a duplicate (same id
        // same ke+info) stays silent. `derived_self_qabl_info` is `Some` (this id inserted).
        let self_zid = *self.net.borrow().self_zid();
        let merged = self.derived_self_qabl_info(&keyexpr).unwrap_or(info);
        let registered = self.qabls.borrow_mut().register(&keyexpr, self_zid, merged);
        if registered {
            // A NEW/UPGRADED queryable (to this node) -> tell any co-attached CLIENT
            // querier whose stored FUTURE interest matches (querier-before-queryable
            // write-filter close). `origin = Some(inbound)` excludes the declaring client
            // itself, mirror of `ingest_client_subscription`.
            self.push_future_queryable(&keyexpr, Some(inbound));
            let mut declare = match build_declare_queryable(0, 0, Some(&keyexpr)) {
                Ok(d) => d,
                Err(e) => {
                    log::warn!("peer: client qabl advertise build failed for {keyexpr:?}: {e:?}");
                    return;
                }
            };
            set_declare_queryable_info(&mut declare, merged);
            let _ = self.flood_to_tree_children(&self_zid, || {
                NetworkMessage::Declare(Box::new(declare.clone()))
            });
        }
        // id-reuse displacement: an id re-declared for a DIFFERENT ke -> the old ke lost
        // this backer -> downgrade/withdraw its self-sourced advert (self-gated by the
        // re-derive in withdraw_mesh_qabl_if_unbacked). Unreachable for conforming clients
        // (monotonic ids + undeclare-first); the id-map makes it detectable.
        if let Some((old_ke, _)) = displaced {
            if old_ke != keyexpr {
                let _ = self.withdraw_mesh_qabl_if_unbacked(&old_ke);
            }
        }
    }

    /// R311y178 (id-map) — withdraw a co-attached CLIENT's queryable on its graceful
    /// `UndeclareQueryable`. A client's undeclare is ID-ONLY (`build_undeclare_queryable(id)`,
    /// no `ext_keyexpr`), so the retracted keyexpr is resolved BY ID from
    /// [`client_qabls`](Self#structfield.client_qabls) (zenoh `forget_simple_queryable`
    /// id-first), NOT by an ext the client never sends (the prior keyexpr-keyed resolve
    /// NO-OP'd on an id-only undeclare -> stale advert until face-down). Then (via the
    /// shared [`withdraw_mesh_qabl_if_unbacked`](Self::withdraw_mesh_qabl_if_unbacked) seam)
    /// DOWNGRADES the mesh advert if another source remains, or fully withdraws it if this
    /// was the last. The query-plane twin of
    /// [`withdraw_client_subscription`](Self::withdraw_client_subscription).
    fn withdraw_client_queryable(&self, inbound: FaceId, declare: &DeclareOwned) {
        let decl_id = match &declare.body {
            DeclareOwnedVariant::CodecZenohUndeclQueryable(u) => u.id,
            _ => return,
        };
        let keyexpr = {
            let mut cq = self.client_qabls.borrow_mut();
            let removed = cq.get_mut(&inbound).and_then(|ids| ids.remove(&decl_id));
            if cq.get(&inbound).is_some_and(|ids| ids.is_empty()) {
                cq.remove(&inbound);
            }
            removed
        };
        let Some((keyexpr, _)) = keyexpr else {
            return; // unknown id (never ingested / already gone) — nothing to withdraw
        };
        let _ = self.withdraw_mesh_qabl_if_unbacked(&keyexpr);
    }

    /// R311y163 (D4 / C3a) — deliver a received data `Push` to co-attached CLIENT
    /// subscribers whose stored keyexpr wildcard-INTERSECTS the published key, the
    /// peer-tier twin of `RouterForwarder::deliver_to_client_subscribers`.
    /// UNCONDITIONAL: the single-net peer has no master election / cross-mesh bridge
    /// (zenoh `linkstate_peer::compute_data_route` has no `elect_router` gate). The
    /// sample is re-literalized ONCE (payload / encoding / attachment / timestamp /
    /// qos preserved) and the inbound face is excluded (never echo a client's own
    /// Push back). Wildcard-aware via the SAME `keyexpr_intersects_target` SSOT the
    /// mesh route reads (over the id-keyed store's ke VALUES) — an exact string match
    /// would blackhole every `demo/**` client sub receiving a `demo/data` Push.
    fn deliver_to_client_subscribers(
        &self,
        inbound: FaceId,
        reliable: bool,
        priority: Priority,
        push: &PushOwned,
    ) {
        if self.client_subs.borrow().is_empty() {
            return;
        }
        // Resolve the Push key against the INBOUND face's alias table (c3c-3 B1) in a
        // scoped borrow, then re-literalize once; the fan-out clones the carrier per
        // matching client.
        let keyexpr = {
            let faces = self.faces.borrow();
            let Some(s) = faces.get(&inbound) else {
                return;
            };
            match resolve_wireexpr(&push.keyexpr.body, &s.keyexpr_table) {
                Some(ke) => ke,
                None => return,
            }
        };
        let Ok(mut carrier) = reliteralize_push(push, &keyexpr) else {
            return;
        };
        // A client subscriber is a LEAF, not a routing-graph node: reset the Push's
        // routing source node-id to 0 (set_push_source(_, 0) omits the ext, zenoh's
        // omit-on-DEFAULT). reliteralize_push PRESERVES the inbound push's ext_nodeid;
        // at a 3+ hop TRANSIT node that source is NON-ZERO (compute_push_forward stamps
        // out_node_id), and forwarding it to a client (e.g. a pico z_sub) is a protocol
        // violation the client rejects by CLOSING its transport (its Push decoder has no
        // case for the mandatory ext_nodeid id 0x03). Faithful to zenoh linkstate_peer
        // pubsub.rs (a client-sub data-route direction node-id is NodeId::default()=0).
        // The DATA-plane twin of the R311y179 forward_request_to_client_queryables fix.
        set_push_source(&mut carrier, 0);
        let target_chunks: Vec<&str> = keyexpr.split('/').collect();
        // R311y225 — preserve the received band on the CLIENT-face egress (the y224
        // residual): route through `fan_out_qos` on the frame's `priority` so a
        // QoS-negotiated client observes the same band the mesh transit carries (zenoh
        // `route_data` copies `ext_qos` onto client-face egress the same as any egress).
        // DEFAULT under a non-QoS session; a pico client negotiates no unicast ext_qos
        // so it stays DEFAULT. The peer-tier twin of the router's y225 client egress.
        let _ = self.fan_out_qos(reliable, priority, false, None, |id, _zid| {
            if id == inbound {
                return Ok(None);
            }
            let deliver = self.client_subs.borrow().get(&id).is_some_and(|ids| {
                ids.values()
                    .any(|sub| keyexpr_intersects_target(sub, &target_chunks))
            });
            Ok(deliver.then(|| NetworkMessage::Push(Box::new(carrier.clone()))))
        });
    }

    /// R311y164 (D4b / C3b) — re-inject a co-attached CLIENT publisher's `Push` into
    /// the mesh as a SELF-sourced publish, the client DATA direction (BLOCKER-2, the
    /// twin of D4a's client SUB advertise). A CLIENT is a leaf (no graph node), so
    /// the transit [`forward_push`](Self::forward_push) drops it
    /// ([`compute_push_forward`] -> [`resolve_source_in`] finds no psid for a
    /// non-graph client); this re-sources it under SELF's zid via
    /// [`compute_self_publish_forward`] (self as tree root, node_id 0, fresh hop
    /// budget), preserving the client sample's encoding / attachment / timestamp /
    /// qos with [`reliteralize_push`] (NOT `build_push_literal`, which mints a FRESH
    /// sample and loses that metadata). UNCONDITIONAL — the router's
    /// `publish_client_push_into_meshes` peer leg is itself ungated and the single-net
    /// peer has no master election (zenoh `linkstate_peer::compute_data_route` has no
    /// `elect_router` gate). Mirrors zenoh routing a `source_type == Client` push over
    /// `linkstatepeer_subs` with self as the tree root.
    fn reinject_client_push(
        &self,
        inbound: FaceId,
        reliable: bool,
        priority: Priority,
        push: &PushOwned,
    ) {
        // Resolve the client Push key against ITS face alias table (c3c-3 B1), once.
        let keyexpr = {
            let faces = self.faces.borrow();
            let Some(s) = faces.get(&inbound) else {
                return;
            };
            match resolve_wireexpr(&push.keyexpr.body, &s.keyexpr_table) {
                Some(ke) => ke,
                None => return,
            }
        };
        let computed = match compute_self_publish_forward(&self.net, &self.subs, &keyexpr, || {
            reliteralize_push(push, &keyexpr)
        }) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("peer: client push re-inject build failed for {keyexpr:?}: {e:?}");
                return;
            }
        };
        let Some((carrier, children)) = computed else {
            return; // no remote subscriber / no tree direction -> nothing to re-inject
        };
        // R311y225 — preserve the received band on the client->mesh re-inject: this
        // re-forwards a RECEIVED client frame into the mesh (reliteralize_push), so it
        // carries the client's band through `fan_out_qos`, the peer-tier twin of the
        // router's already-threaded `publish_client_push_into_meshes` (y224). A pico
        // client sends DEFAULT (no unicast ext_qos); a QoS wz client's band survives.
        let _ = self.fan_out_qos(reliable, priority, false, None, |_id, zid| {
            Ok(zid
                .is_some_and(|z| is_child(&children, z))
                .then(|| NetworkMessage::Push(Box::new(carrier.clone()))))
        });
    }

    /// Retract self's LOCAL queryable for `keyexpr` (R311y154, gap b) — the inverse of
    /// [`declare_queryable`](Self::declare_queryable) and the qabl twin of
    /// [`undeclare_subscription`](Self::undeclare_subscription). Withdraw self's own
    /// declaration from [`qabls`](Self#structfield.qabls), re-arm any waiting CLIENT
    /// querier (`undeclare_push_qabls`), and flood the sourced forget to tree children —
    /// zenoh's `undeclare_linkstatepeer_queryable` (`hat/linkstate_peer/queries.rs:516`)
    /// -> `unregister_linkstatepeer_queryable` (`propagate_forget_simple_queryable`, :512)
    /// + `propagate_forget_sourced_queryable` (:525). Returns the mesh flood reach.
    ///
    /// The `undeclare_push_qabls` re-arm fires BOTH the full-undeclare AND — via
    /// `re_pushes_for_withdrawn` — the y153 completeness-DOWNGRADE re-push; the latter is
    /// an intentional SUPERSET over zenoh's linkstate_peer hat (full-undeclare-only, no
    /// partial re-declare), per that method's doc.
    pub fn undeclare_queryable(&self, keyexpr: &str) -> Result<usize, CodecError> {
        // Drop the self-hosted reply handler (the inverse of register_local_queryable) so a
        // RETRACTED queryable STOPS answering, not just stops being routed to — else
        // dispatch_local_queryables keeps replying on the empty-route branch (zenoh drops
        // the callback with the declaration). Keyed by keyexpr (the wz declare/undeclare
        // API is keyexpr-based); symmetric with undeclare_subscription's local_subscribers
        // drop (R311y154 closed the identical pre-existing residual on both planes).
        let mut retracted: Vec<Rc<RefCell<LocalQueryHandler>>> = Vec::new();
        self.local_queryables.borrow_mut().retain(|lq| {
            if lq.keyexpr == keyexpr {
                retracted.push(Rc::clone(&lq.handler));
                false
            } else {
                true
            }
        });
        // #3-c QUERY half (R311y168) — purge the retracted queryable's handler from
        // any DEFERRED self-query (query_redelivery). The DeferredQuery record
        // SURVIVES (its Final must still emit so a querier awaiting the deferred
        // answer terminates rather than hanging); only the retracted handler is
        // removed from that query's answer set (an empty-handler record then emits
        // just the Final).
        if !retracted.is_empty() {
            for dq in self.query_redelivery.borrow_mut().iter_mut() {
                dq.handlers
                    .retain(|h| !retracted.iter().any(|r| Rc::ptr_eq(h, r)));
            }
        }
        // Withdraw-or-DOWNGRADE the self-sourced mesh advert through the shared
        // union-refcount seam: a co-attached CLIENT queryable still hosting this ke
        // DOWNGRADES the advert (re-declared with the surviving merged info) rather than
        // fully retracting it (which would black-hole the client's queryable); only the
        // LAST source's departure withdraws self from `qabls`, floods the sourced
        // UndeclareQueryable, and re-arms waiting queriers (full-undeclare and the y153
        // completeness downgrade). Mirrors how undeclare_subscription routes through
        // withdraw_mesh_sub_if_unbacked (R311y163), with the qabl-specific info downgrade
        // (subs are presence-only). A never-registered ke with no client backer floods an
        // idempotent UndeclareQueryable (the None arm), preserving the prior behavior.
        self.withdraw_mesh_qabl_if_unbacked(keyexpr)
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
        self.fan_out(true, None, |_id, zid| {
            // `then(build)` would move `build` (called once per child); mint
            // lazily on the matching children only.
            Ok(if zid.is_some_and(|z| is_child(children, z)) {
                Some(build())
            } else {
                None
            })
        })
    }

    /// A sourced `DeclareSubscriber` arrived on `inbound`: the subscriber-plane
    /// thin wrapper over [`forward_interest_declaration`](Self::forward_interest_declaration).
    /// Supplies the subscriber body extractor, the subscription interest table
    /// ([`subs`](Self#structfield.subs)) and the `DeclareSubscriber` carrier
    /// builder; the shared helper does the source-resolve + register-gate +
    /// re-flood. zenoh `register_linkstatepeer_subscription`.
    fn forward_subscription(&self, inbound: FaceId, reliable: bool, declare: &DeclareOwned) {
        // Only a DeclareSubscriber body carries mesh interest. Its keyexpr may be
        // aliased (c3c-3 B1b) — resolved by the shared helper against the inbound
        // face's table.
        let Some(wireexpr) = declare_subscriber_wireexpr(declare) else {
            return;
        };
        // Subscriptions carry no per-peer value (V = ()); the value-diff gate
        // reduces to new-peer for subs.
        let registered = self.forward_interest_declaration(
            inbound,
            reliable,
            declare,
            wireexpr,
            InterestRegistration {
                table: &self.subs,
                value: (),
            },
            |ke| build_declare_subscriber(0, 0, Some(ke)),
        );
        // FUTURE-mode push: a mesh sub just became known -> declare it to any CLIENT
        // face whose stored FUTURE interest matches (pub-before-sub close). `inbound`
        // (the mesh source) is never echoed.
        if let Some(ke) = registered {
            self.push_future_subscription(&ke, Some(inbound));
        }
    }

    /// A sourced `DeclareQueryable` arrived on `inbound`: the queryable-plane
    /// twin of [`forward_subscription`](Self::forward_subscription) — same shared
    /// [`forward_interest_declaration`](Self::forward_interest_declaration), only
    /// the body extractor ([`declare_queryable_wireexpr`]), the interest table
    /// ([`qabls`](Self#structfield.qabls)) and the `DeclareQueryable` carrier
    /// builder ([`build_declare_queryable`]) differ. zenoh
    /// `register_linkstatepeer_queryable` (`queries.rs`). Registers the source
    /// peer's queryable interest and re-floods along the source's tree on a NEW
    /// registration; the Request routing that consumes `qabls` lands in the next
    /// atom.
    fn forward_queryable(&self, inbound: FaceId, reliable: bool, declare: &DeclareOwned) {
        let Some(wireexpr) = declare_queryable_wireexpr(declare) else {
            return;
        };
        // The declared QueryableInfo (complete / distance) rides the DeclQueryable
        // BODY's ext chain (R311ui/uj); read it so the qabls store records the
        // peer's completeness — the value the value-diff gate compares and that
        // BestMatching (atom 3) reads. Absent ext = zenoh DEFAULT (incomplete).
        let info = match &declare.body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(dq) => {
                wz_session_core::queryable_info::read_queryable_info(dq.extensions.as_ref())
            }
            _ => wz_session_core::queryable_info::QueryableInfo::DEFAULT,
        };
        let registered = self.forward_interest_declaration(
            inbound,
            reliable,
            declare,
            wireexpr,
            InterestRegistration {
                table: &self.qabls,
                value: info,
            },
            // Carry the source's QueryableInfo DOWNSTREAM on the re-flood so a
            // multi-hop relay learns its completeness (R311uq) — the same SSOT
            // mint re_advertise_queryables uses. `info` is Copy, captured by the
            // Fn closure.
            move |ke| build_declare_queryable_with_info(ke, info),
        );
        // FUTURE-push (R311y150): a mesh queryable learned off the tree is
        // proactively pushed to any CLIENT face whose FUTURE querier-interest
        // matches, with the RE-FOLDED merged info — closing the y146 residual (the
        // registered ke was previously discarded). Fires on a NEW registration OR a
        // value-diff (a completeness flip re-declares the same interned id).
        if let Some(ke) = registered {
            self.push_future_queryable(&ke, Some(inbound));
        }
    }

    /// The shared sourced-interest-declaration re-flood, SSOT for both the
    /// subscriber ([`forward_subscription`](Self::forward_subscription)) and the
    /// queryable ([`forward_queryable`](Self::forward_queryable)) planes: register
    /// the SOURCE peer's interest in the declared keyexpr in `table`, and — only
    /// if this NEWLY learned it — re-flood a CLEAN sourced literal declaration
    /// onward along the SOURCE's spanning tree to self's tree children (excluding
    /// the inbound face), re-stamped with this node's psid for the source. The
    /// "only on new" ([`LinkstatepeerInterest::register`](crate::linkstate_interest::LinkstatepeerInterest::register)
    /// returning `true`) is the change-gate that bounds the flood: a peer that
    /// already knew the interest does not re-flood, so the declaration cannot
    /// loop. zenoh `register_linkstatepeer_{subscription,queryable}`'s `if
    /// !contains { insert; propagate }`. Resolves the source + re-stamp value
    /// through the shared [`resolve_source`](Self::resolve_source) seam, exactly
    /// as [`forward_push`](Self::forward_push) — the difference is the
    /// control-plane spread floods ALL tree children (zenoh
    /// `propagate_sourced_{subscription,queryable}` uses the tree `children`), not
    /// the data-plane interest-filtered directions. `table` is the
    /// subscriber/queryable interest instance; `build` mints the per-flow carrier
    /// (`DeclareSubscriber` / `DeclareQueryable`) from the resolved LITERAL
    /// keyexpr (B1b normalize — a downstream link does not share this link's alias
    /// table, so it must see a literal; a sourced re-flood carries no id, id 0,
    /// the keyexpr being the identity).
    ///
    /// Handles interest DECLARATIONS (new interest) only — withdrawals route
    /// through the symmetric [`forward_interest_withdrawal`](Self::forward_interest_withdrawal)
    /// SSOT (subscriber retraction via `UndeclareSubscriber`, queryable retraction
    /// via `UndeclareQueryable`; both carry the retracted keyexpr in the
    /// `ext_wire_expr` extension).
    fn forward_interest_declaration<V: PartialEq>(
        &self,
        inbound: FaceId,
        reliable: bool,
        declare: &DeclareOwned,
        wireexpr: &WireexprOwned,
        reg: InterestRegistration<V>,
        build: impl Fn(&str) -> Result<DeclareOwned, CodecError>,
    ) -> Option<String> {
        // The inbound face's zid + graph link AND the RESOLVED keyexpr, in one
        // scoped borrow (an unresolvable alias drops the declaration).
        let (inbound_zid, inbound_link, keyexpr) = {
            let faces = self.faces.borrow();
            let s = faces.get(&inbound)?;
            let keyexpr = resolve_wireexpr(&wireexpr.body, &s.keyexpr_table)?;
            (peer_zid_routing(&s.actions), s.link, keyexpr)
        };
        let (source_zid, out_node_id) =
            self.resolve_source(inbound_zid, inbound_link, read_declare_source(declare))?;
        // Register the resolved interest with its declared value; re-flood ONLY
        // on a real change — a new peer OR a changed value (the loop-bounding
        // value-diff change-gate, R311ul).
        if !reg
            .table
            .borrow_mut()
            .register(&keyexpr, source_zid, reg.value)
        {
            return None;
        }
        // Re-flood a CLEAN sourced literal declaration to self's children in the
        // source's tree (B1b normalize — a downstream link does not share this
        // link's alias table, so it must see a literal; a sourced re-flood carries
        // no id, id 0, the keyexpr being the identity). Independent of the caller's
        // FUTURE push: a peer with no tree children still returns the registered ke
        // so a co-attached client's future interest is served.
        let children = self.net.borrow().tree_children_of(&source_zid);
        if !children.is_empty() {
            if let Ok(mut carrier) = build(keyexpr.as_str()) {
                set_declare_source(&mut carrier, out_node_id);
                // The same shared re-forward predicate forward_push uses (excludes
                // the inbound face and the source's own neighbour); only the carrier
                // differs.
                let _ = self.fan_out(reliable, None, |id, zid| {
                    Ok(
                        is_tree_forward_target(id, zid, inbound, inbound_zid, &children)
                            .then(|| NetworkMessage::Declare(Box::new(carrier.clone()))),
                    )
                });
            }
        }
        Some(keyexpr)
    }

    /// A sourced `UndeclareSubscriber` arrived on `inbound`: withdraw the SOURCE
    /// peer's interest in the retracted keyexpr (carried in the message's
    /// `ext_keyexpr` extension — sourced undeclares use no id, the keyexpr is the
    /// identity), and — only if this peer HELD that interest — re-flood the
    /// retraction onward along the SOURCE's spanning tree to self's tree children
    /// (excluding the inbound face), re-stamped with this node's psid for the
    /// source. The "only on held"
    /// ([`LinkstatepeerInterest::withdraw`](crate::linkstate_interest::LinkstatepeerInterest::withdraw)
    /// returning `true`) is the change-gate bounding the flood — the exact mirror
    /// of [`forward_subscription`](Self::forward_subscription)'s "only on new",
    /// so a retraction cannot loop. zenoh
    /// `forget_linkstatepeer_subscription` -> `unregister_peer_subscription` +
    /// `propagate_forget_sourced_subscription`. Resolves the source + re-stamp
    /// through the same shared [`resolve_source`](Self::resolve_source) seam the
    /// declare path uses.
    fn forward_unsubscription(&self, inbound: FaceId, reliable: bool, declare: &DeclareOwned) {
        // The retracted keyexpr rides the ext_keyexpr extension. The forward()
        // dispatch guarantees an UndeclareSubscriber body here.
        let exts = match &declare.body {
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(u) => u.extensions.as_ref(),
            _ => return,
        };
        if let Some(keyexpr) = self.forward_interest_withdrawal(
            inbound,
            reliable,
            declare,
            exts,
            &self.subs,
            build_undeclare_subscriber_with_keyexpr,
        ) {
            // R311y151 undeclare-push: the mesh sub is gone; re-arm any waiting
            // publisher whose pushed reply ke lost its last backer.
            self.undeclare_push_subs(&keyexpr);
        }
    }

    /// A sourced `UndeclareQueryable` arrived on `inbound`: the query-plane twin
    /// of [`forward_unsubscription`](Self::forward_unsubscription) — same shared
    /// [`forward_interest_withdrawal`](Self::forward_interest_withdrawal), only the
    /// body extractor, the interest table ([`qabls`](Self#structfield.qabls)) and
    /// the `UndeclareQueryable` carrier builder differ. The retracted keyexpr rides
    /// the `ext_wire_expr` extension (the codec parity with `UndeclareSubscriber`);
    /// before that codec atom this was a no-op (the id-only body carried no
    /// keyexpr). zenoh `forget_linkstatepeer_queryable` (`queries.rs`).
    fn forward_queryable_undeclare(&self, inbound: FaceId, reliable: bool, declare: &DeclareOwned) {
        let exts = match &declare.body {
            DeclareOwnedVariant::CodecZenohUndeclQueryable(u) => u.extensions.as_ref(),
            _ => return,
        };
        if let Some(keyexpr) = self.forward_interest_withdrawal(
            inbound,
            reliable,
            declare,
            exts,
            &self.qabls,
            build_undeclare_queryable_with_keyexpr,
        ) {
            // R311y151 undeclare-push (query twin): re-arm any waiting querier whose
            // pushed reply ke lost its last backing queryable.
            self.undeclare_push_qabls(&keyexpr);
        }
    }

    /// The shared sourced-interest-WITHDRAWAL re-flood, SSOT for both the
    /// subscriber ([`forward_unsubscription`](Self::forward_unsubscription)) and
    /// the queryable ([`forward_queryable_undeclare`](Self::forward_queryable_undeclare))
    /// planes — the withdrawal twin of
    /// [`forward_interest_declaration`](Self::forward_interest_declaration).
    /// Withdraw the SOURCE peer's interest in the retracted keyexpr (carried in the
    /// message's `ext_wire_expr` extension, which may be aliased [c3c-3 B1b] —
    /// resolved against the inbound face's table; sourced undeclares use no id, the
    /// keyexpr is the identity), and — only if this peer HELD that interest —
    /// re-flood a CLEAN sourced literal retraction onward along the SOURCE's
    /// spanning tree to self's tree children (excluding the inbound face),
    /// re-stamped with this node's psid for the source. The "only on held"
    /// ([`LinkstatepeerInterest::withdraw`](crate::linkstate_interest::LinkstatepeerInterest::withdraw)
    /// returning `true`) is the change-gate bounding the flood — the exact mirror
    /// of the declare side's "only on new", so a retraction cannot loop. zenoh
    /// `forget_linkstatepeer_{subscription,queryable}`. `exts` is the body's
    /// extension chain (extracted by the caller from its body-specific variant);
    /// `table` selects the subscriber/queryable interest instance; `build` mints
    /// the per-flow `Undeclare*` carrier from the resolved LITERAL keyexpr (id 0).
    /// Returns the resolved keyexpr on a REAL removal (`None` on an unresolvable
    /// alias / unknown source / no-op withdraw), so the caller can fire the
    /// R311y151 undeclare-push forget for that keyexpr — the withdraw twin of
    /// [`forward_interest_declaration`](Self::forward_interest_declaration)'s
    /// `Option<String>`. The re-flood below is best-effort; a real removal returns
    /// `Some(keyexpr)` whether or not there were tree children to re-flood to.
    fn forward_interest_withdrawal<V>(
        &self,
        inbound: FaceId,
        reliable: bool,
        declare: &DeclareOwned,
        exts: Option<&Vec<ExtEntryOwned>>,
        table: &RefCell<LinkstatepeerInterest<V>>,
        build: impl Fn(&str) -> Result<DeclareOwned, CodecError>,
    ) -> Option<String> {
        let (inbound_zid, inbound_link, keyexpr) = {
            let faces = self.faces.borrow();
            let s = faces.get(&inbound)?;
            let keyexpr = resolve_ext_keyexpr(exts, &s.keyexpr_table)?;
            (peer_zid_routing(&s.actions), s.link, keyexpr)
        };
        let (source_zid, out_node_id) =
            self.resolve_source(inbound_zid, inbound_link, read_declare_source(declare))?;
        // Withdraw the resolved interest; re-flood ONLY on a real removal (the
        // loop-bounding change-gate).
        if !table.borrow_mut().withdraw(&keyexpr, &source_zid) {
            return None;
        }
        // A real removal — re-flood a CLEAN sourced literal retraction to self's
        // children in the source's tree (B1b normalize, uniform with the declare
        // side): the downstream link withdraws by the resolved literal, a sourced
        // retraction carries no id. Best-effort; the removal (and thus the caller's
        // undeclare-push forget) stands regardless.
        let children = self.net.borrow().tree_children_of(&source_zid);
        if !children.is_empty() {
            if let Ok(mut carrier) = build(keyexpr.as_str()) {
                set_declare_source(&mut carrier, out_node_id);
                let _ = self.fan_out(reliable, None, |id, zid| {
                    Ok(
                        is_tree_forward_target(id, zid, inbound, inbound_zid, &children)
                            .then(|| NetworkMessage::Declare(Box::new(carrier.clone()))),
                    )
                });
            }
        }
        Some(keyexpr)
    }

    /// Re-advertise known SUBSCRIPTIONS to the NEW children a tree-recompute
    /// added — zenoh's `pubsub_tree_change` (`pubsub.rs:641-678`). The
    /// subscriber-plane thin wrapper over
    /// [`re_advertise_interest`](Self::re_advertise_interest).
    fn re_advertise_subscriptions(&self, new_children: &[(Zid, Vec<Zid>)]) {
        // Subscriptions carry no per-peer value (V = ()): ignore it in the mint.
        self.re_advertise_interest(new_children, &self.subs, |ke, _value| {
            build_declare_subscriber(0, 0, Some(ke))
        });
    }

    /// Re-advertise known QUERYABLES to the NEW children a tree-recompute added —
    /// zenoh's `queries_tree_change` (`queries.rs:663-697`), the query-plane twin
    /// of [`re_advertise_subscriptions`](Self::re_advertise_subscriptions). Same
    /// delta + same [`re_advertise_interest`](Self::re_advertise_interest) seam;
    /// only the interest table (`qabls`) and the `DeclareQueryable` carrier
    /// differ, so a queryable declared before a peer joined converges onto the new
    /// branch exactly as a subscription does.
    fn re_advertise_queryables(&self, new_children: &[(Zid, Vec<Zid>)]) {
        // CARRY the per-peer QueryableInfo so the late-joining branch learns the
        // queryable's completeness (R311uq) — the same SSOT mint forward_queryable
        // re-floods with.
        self.re_advertise_interest(new_children, &self.qabls, |ke, info| {
            build_declare_queryable_with_info(ke, *info)
        });
    }

    /// The shared tree-change re-advertise, SSOT for both the subscriber
    /// ([`re_advertise_subscriptions`](Self::re_advertise_subscriptions)) and the
    /// queryable ([`re_advertise_queryables`](Self::re_advertise_queryables))
    /// planes. Called after a
    /// [`compute_trees`](wz_routing_graph::LinkstateNetwork::compute_trees) on a
    /// topology change (an inbound link-state, or a face loss) with THAT
    /// recompute's per-tree new-children DELTA (`(source, [new child, ..])`). A
    /// declaration made before a peer joined did not reach it; the recompute
    /// makes the joiner a NEW child of some source's tree, and re-flooding the
    /// source's declaration to that new child alone delivers the interest
    /// onto the new branch — without re-sending to children that already
    /// converged (c3c-3 D2; the prior version re-flooded to ALL current children
    /// and leaned on the receiver change-gate to dedup the redundant sends).
    ///
    /// Structure mirrors zenoh `pubsub_tree_change` / `queries_tree_change`: the
    /// OUTER loop is over the new-children delta (each source tree that grew), the
    /// INNER over the declarations sourced at that tree (`*src == tree_id`); each
    /// match floods to the delta children via
    /// [`flood_to_children`](Self::flood_to_children). ONE delta covers both
    /// remote-relayed and self-originated declarations: a self-sourced pair
    /// resolves `local_psid_of(self) == 0`, so `set_declare_source(0)` leaves it
    /// self-originated — the same wire a direct `declare_*` emits — which is what
    /// lets a ONE-TIME `declare_*` converge to a late-joining peer without a
    /// per-tick re-declare. Loop-freedom is unchanged: the receiver's register
    /// change-gate still bounds any onward flood; the delta only narrows WHO is
    /// re-sent to. `table` selects the subscriber/queryable interest instance;
    /// `build` mints the per-flow carrier from the literal keyexpr.
    fn re_advertise_interest<V: Clone>(
        &self,
        new_children: &[(Zid, Vec<Zid>)],
        table: &RefCell<LinkstatepeerInterest<V>>,
        build: impl Fn(&str, &V) -> Result<DeclareOwned, CodecError>,
    ) {
        // The delta walk + per-source re-stamp is the shared free
        // [`re_advertise_interest_into`] RouterForwarder also calls per tier-net
        // (R311y112); one net here, so pass `self.net`. This forwarder floods via
        // `flood_to_children` (its gossip-gated + egress-ACL `fan_out`).
        re_advertise_interest_into(
            &self.net,
            table,
            new_children,
            build,
            |children, declare| {
                let _ = self.flood_to_children(children, || {
                    NetworkMessage::Declare(Box::new(declare.clone()))
                });
            },
        );
    }

    /// The single spanning-tree recompute path (D2c SSOT): recompute the trees
    /// and re-advertise known subscriptions AND queryables to whatever new
    /// children the recompute produced. The [`tick`](FaceForwarder::tick) calls
    /// this once per coalescing window after
    /// [`schedule_recompute`](Self::schedule_recompute) marked a topology change
    /// pending — so EVERY production recompute funnels through here (zenoh's
    /// `TreesComputationWorker` body: `compute_trees` then `pubsub_tree_change` +
    /// `queries_tree_change`). The `compute_trees` borrow is released before the
    /// re-advertise re-borrows.
    fn recompute_and_advertise(&self) {
        let new_children = self.net.borrow_mut().compute_trees();
        self.recomputes.set(self.recomputes.get() + 1);
        self.re_advertise_subscriptions(&new_children);
        self.re_advertise_queryables(&new_children);
    }

    /// Unicast a message to the single face `face` — a back-hop on the
    /// pending-query RETURN route, NOT a tree fan-out. The reply path
    /// ([`forward_response`](Self::forward_response) /
    /// [`forward_response_final`](Self::forward_response_final)) and the timeout
    /// sweep ([`reap_timed_out_queries`](Self::reap_timed_out_queries)) all route
    /// ONE message back to ONE recorded inbound face — this is the single seam
    /// they share, the broadcast [`fan_out`](Self::fan_out) gated to the one
    /// target so the egress ACL + drop-witness still apply. `build` is the
    /// per-send message constructor (NetworkMessage is not `Clone`, so the carrier
    /// is built for the matching face).
    fn send_to_face(
        &self,
        face: FaceId,
        reliable: bool,
        mut build: impl FnMut() -> NetworkMessage,
    ) {
        let _ = self.fan_out(reliable, None, |id, _zid| Ok((id == face).then(&mut build)));
    }

    /// [`send_to_face`](Self::send_to_face) for an already-BUILT owned message —
    /// the adapter the shared synthesis cores ([`synthesize_expired_query_returns`]
    /// / [`synthesize_drained_fan_finals`]) hand their per-send `NetworkMessage`
    /// to (`NetworkMessage` is not `Clone`, so the one-shot `Option` take feeds
    /// the at-most-once builder — `fan_out` matches `face` at most once).
    fn send_one_to_face(&self, face: FaceId, msg: NetworkMessage) {
        let mut carrier = Some(msg);
        self.send_to_face(face, true, || {
            carrier.take().expect("send_one_to_face builds once")
        });
    }

    /// Answer an inbound `Interest` solicitation from a CLIENT face — the peer
    /// twin of
    /// [`RouterForwarder::respond_to_interest`](crate::router_forward::RouterForwarder),
    /// and the reverse-data write-filter handshake for a pico publisher/querier
    /// attached to THIS peer (not a router). A zenoh(-pico) publisher keeps a
    /// write-filter that drops its own put/get LOCALLY until it learns a matching
    /// remote declaration; this reply is that declaration. CURRENT (`c()`) is
    /// answered by the dump below; FUTURE (`f()`) stores the client's SUBSCRIBER
    /// interest ([`future_subs`](Self#structfield.future_subs)) so a sub learned
    /// LATER is pushed
    /// ([`push_future_subscription`](Self::push_future_subscription)) — the
    /// pub-before-sub close (R311y146); an `Interest(Final)` tears the stored
    /// interest down.
    ///
    /// FAITHFUL to zenoh's `linkstate_peer` HAT, which answers a CURRENT interest
    /// ONLY from a CLIENT face (the `declare_sub_interest` / `declare_qabl_interest`
    /// gate `mode.current() && face.whatami == WhatAmI::Client` in
    /// `hat/linkstate_peer/pubsub.rs` + `queries.rs`) — a mesh peer/router learns
    /// declarations by proactive link-state flooding, never by soliciting. The
    /// terminating `DeclareFinal`
    /// is still sent for EVERY current interest (incl a non-client one) so the
    /// soliciting side's handshake completes; only the declaration dump is
    /// client-gated. 0 matches => no `Declare`, the filter stays active ("no
    /// subscriber yet"), which is correct.
    ///
    /// SCOPE (named — not silent): the CURRENT dump AND the FUTURE push surface the
    /// MESH declarations + this node's SELF-LOCAL declarations (both keyed by a
    /// graph zid in [`subs`](Self#structfield.subs) / `qabls`, plus a self-local
    /// [`declare_subscription`](Self::declare_subscription) push). The FUTURE push
    /// (R311y146) CLOSES the pub-before-sub hole for the SUBSCRIBER plane: a
    /// publisher soliciting before any matching sub gets an empty dump, but a sub
    /// appearing LATER now pushes an unsolicited `DeclareSubscriber` that
    /// deactivates its write-filter. Formerly-open item (1) — a subscription
    /// declared by ANOTHER client attached to THIS peer — was CLOSED by R311y163
    /// (D4): the peer now keeps a per-face [`client_subs`](Self#structfield.client_subs)
    /// store and re-sources a co-attached client's sub under SELF's zid in
    /// [`subs`](Self#structfield.subs)
    /// ([`ingest_client_subscription`](Self::ingest_client_subscription)), so the
    /// CURRENT dump (which excludes only the requester's OWN zid) surfaces it to a
    /// co-attached client publisher — the two-clients-on-one-peer case is now
    /// covered. One deferred unit remains, named: (2) the QUERYABLE future-push and
    /// the undeclare-push (a sub DISAPPEARING) are separate deferred units.
    fn respond_to_interest(&self, inbound: FaceId, interest: &InterestOwned) {
        // Interest(Final) (`!c && !f`): a client CANCELLING a prior interest. pico
        // sends one on every publisher/querier drop (`net/primitives.c:
        // _z_remove_interest`, client-gated), so drop the stored FUTURE interest for
        // this `interest_id` (else it leaks + keeps pushing to a gone publisher). No
        // reply (a Final carries no body).
        if !interest.c() && !interest.f() {
            // The interest_id lives in exactly ONE plane's store (su() XOR qu());
            // removing from both is safe (the other no-ops).
            self.future_subs
                .borrow_mut()
                .remove_interest(inbound, interest.interest_id);
            self.future_qabls
                .borrow_mut()
                .remove_interest(inbound, interest.interest_id);
            return;
        }
        let Some(body) = interest.body.as_ref() else {
            return; // a C||F interest always carries a body (the C||F decode gate).
        };
        let interest_id = interest.interest_id;
        // Resolve the RESTRICTED target keyexpr, the requesting face's ROLE, and
        // its zid in ONE scoped borrow. An unresolvable alias still terminates the
        // interest so the peer is not left waiting; a body-less RESTRICTED (`None`
        // target) => match-all, deferred (pico always sets RESTRICTED, like the
        // router).
        let (target, requester_zid, is_client) = {
            let faces = self.faces.borrow();
            let Some(s) = faces.get(&inbound) else {
                return;
            };
            let is_client = peer_whatami_routing(&s.actions) == WhatAmI::Client;
            let requester_zid = peer_zid_routing(&s.actions);
            let target: Option<String> = if body.r() {
                match body
                    .keyexpr
                    .as_ref()
                    .and_then(|w| resolve_wireexpr(&w.body, &s.keyexpr_table))
                {
                    Some(ke) => Some(ke),
                    None => {
                        // A CURRENT interest is still terminated so the peer is not
                        // left waiting; a FUTURE-only interest has no snapshot to
                        // close (nothing stored — the alias was unresolvable).
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
            };
            (target, requester_zid, is_client)
        };
        let aggregate = body.ag();
        // FUTURE (`f()`) half: STORE the subscriber interest so a matching sub
        // learned LATER (mesh or self-local) is pushed to this face — the
        // pub-before-sub close. CLIENT faces only (zenoh pushes future subs to
        // `whatami==Client` faces); SUBS plane only (`su()`); match-all (target
        // None) is not stored (current-dump parity).
        let store_future = interest.f() && body.su() && is_client;
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
        // queryable learned LATER (mesh or self-local) is pushed to this querier, and
        // a completeness flip re-pushes (value-aware). Same CLIENT-only + literal gate.
        let store_future_qabl = interest.f() && body.qu() && is_client;
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
        // CURRENT (`c()`) half: the client-only dump + the DeclareFinal (sent for
        // ANY current interest, even a non-client one — its write-filter still needs
        // the terminator). A FUTURE-only interest gets neither.
        if interest.c() {
            if is_client {
                if body.su() {
                    self.dump_interest_subs(
                        inbound,
                        target.as_deref(),
                        aggregate,
                        requester_zid.as_ref(),
                        interest_id,
                        store_future,
                    );
                }
                if body.qu() {
                    self.dump_interest_qabls(
                        inbound,
                        target.as_deref(),
                        aggregate,
                        requester_zid.as_ref(),
                        interest_id,
                        store_future_qabl,
                    );
                }
            }
            self.send_one_to_face(
                inbound,
                NetworkMessage::Declare(Box::new(build_declare_final_reply(interest_id))),
            );
        }
    }

    /// The CURRENT-dump SUBSCRIBER leg of [`respond_to_interest`]: reply with the
    /// subscriptions in this peer's SINGLE [`subs`](Self#structfield.subs) set
    /// matching the interest target, EXCLUDING the requesting face's own zid
    /// (`exclude`). Every OTHER source counts — incl this node's own LOCAL
    /// subscriber (registered under `self_zid` by
    /// [`declare_subscription`](Self::declare_subscription), zenoh's
    /// `remote_simple_subs` which includes self's local face) AND remote mesh
    /// peers (zenoh's `remote_linkstatepeer_subs`). The aggregate-vs-explicit
    /// reply shape is the shared [`emit_current_interest_replies`] SSOT. Keyexprs
    /// are gathered OWNED before the egress so no `subs` borrow crosses the send.
    fn dump_interest_subs(
        &self,
        inbound: FaceId,
        target: Option<&str>,
        aggregate: bool,
        exclude: Option<&Zid>,
        interest_id: u64,
        future: bool,
    ) {
        let Some(target) = target else {
            return; // match-all deferred; the caller's DeclareFinal still closes it.
        };
        let mut per_ke: HashMap<String, ()> = HashMap::new();
        for (ke, _zid, ()) in self.subs.borrow().matching_entries(target, exclude) {
            per_ke.insert(ke.to_string(), ());
        }
        emit_current_interest_replies(
            interest_id,
            target,
            aggregate,
            per_ke,
            |a, _b| a,
            // A FUTURE (C+F) interest's current reply carries a NON-ZERO id interned
            // per (face, reply ke) (zenoh `make_sub_id`'s `mode.future()` branch),
            // seeding the pushed registry so the later FUTURE push of the same ke
            // dedups; a CURRENT-only interest keeps id 0.
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
    /// twin of [`dump_interest_subs`](Self::dump_interest_subs), each reply
    /// carrying the MERGED [`QueryableInfo`] (complete = OR, distance = min —
    /// zenoh's `local_qabl_info` fold) of the matched queryables so a
    /// `Z_QUERY_TARGET_ALL_COMPLETE` querier's write-filter (which deactivates
    /// ONLY on a `complete = true` reply) sees the true completeness. Same
    /// single-set source + requester-zid exclusion as the sub leg; same shared
    /// [`emit_current_interest_replies`] reply shape.
    fn dump_interest_qabls(
        &self,
        inbound: FaceId,
        target: Option<&str>,
        aggregate: bool,
        exclude: Option<&Zid>,
        interest_id: u64,
        future: bool,
    ) {
        let Some(target) = target else {
            return;
        };
        let mut per_ke: HashMap<String, QueryableInfo> = HashMap::new();
        for (ke, _zid, info) in self.qabls.borrow().matching_entries(target, exclude) {
            per_ke
                .entry(ke.to_string())
                .and_modify(|e| *e = e.merge(*info))
                .or_insert(*info);
        }
        emit_current_interest_replies(
            interest_id,
            target,
            aggregate,
            per_ke,
            |a, b| a.merge(b),
            // A FUTURE (C+F) interest's current reply carries a NON-ZERO id interned
            // per (face, reply ke) with the FOLDED info, so the id is REUSED and a
            // later completeness flip re-pushes the SAME target (mirror of the sub
            // future branch). A CURRENT-only interest keeps id 0.
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

    /// Reap pending query BRANCHES past their deadline — the wz form of zenoh's
    /// per-branch `QueryCleanup::run` (`dispatcher/queries.rs:305-349`). The
    /// [`tick`](FaceForwarder::tick) calls this each coalescing window: it sweeps
    /// the pending table ([`expired`](PendingQueries::expired)) for branches
    /// whose `ResponseFinal` never arrived on a still-up face and routes the
    /// synthesized timeout messages back via the shared
    /// [`synthesize_expired_query_returns`] core: an `Err("Timeout")` reply per
    /// reaped BRANCH (zenoh runs one `QueryCleanup` per branch, each sending an
    /// Err) and the closing `ResponseFinal` only for a `last` branch (the fan's
    /// last-out gate — a sibling branch still answering must not have its query
    /// closed by this branch's timeout). The final is the load-bearing part (it
    /// terminates the querier's `get()`); the Err gives an explicit timeout
    /// error rather than a silent empty result. The `expired` borrow is released
    /// before the per-entry [`fan_out`](Self::fan_out) re-borrows the faces
    /// table.
    fn reap_timed_out_queries(&self) {
        let reaped = self.pending.borrow_mut().expired(self.now());
        if reaped.is_empty() {
            return;
        }
        self.timed_out.set(self.timed_out.get() + reaped.len());
        synthesize_expired_query_returns(&reaped, |face, msg| self.send_one_to_face(face, msg));
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

    /// Record (or drop) a peer keyexpr alias from a sourced `Declare` on `face`
    /// (c3c-3 B1): a `DeclKexpr` maps `id -> resolved keyexpr` into THAT face's
    /// link-local [`keyexpr_table`](FaceState::keyexpr_table), an `UndeclKexpr`
    /// removes it. The declared base may itself reference an earlier alias on the
    /// same link, so it is resolved against the table before recording (the
    /// routing-routes HAT's `absorb_declare`, `pubsub.rs`; zenoh-pico
    /// `_z_session_recv_declaration`). Link-local: NOT re-flooded onward — each
    /// link negotiates its own aliases (zenoh declares keyexprs hop-by-hop, never
    /// across the mesh), so the forwarder records the alias for RESOLUTION and
    /// re-expresses the keyexpr to a literal when it forwards the carrying message.
    fn absorb_keyexpr_declaration(&self, face: FaceId, declare: &DeclareOwned) {
        let mut faces = self.faces.borrow_mut();
        let Some(state) = faces.get_mut(&face) else {
            return;
        };
        absorb_keyexpr_into(&mut state.keyexpr_table, declare);
    }

    /// The peers interested in `keyexpr` — the subscription-filter input the
    /// data forward (atom4) feeds to
    /// [`directions_toward`](wz_routing_graph::LinkstateNetwork::directions_toward).
    /// Empty if no peer is interested. Exposed so a test (and the demo's
    /// shutdown summary) can observe the interest the mesh propagated.
    pub fn interested(&self, keyexpr: &str) -> Vec<Zid> {
        self.subs.borrow().interested(keyexpr)
    }

    /// The peers with a QUERYABLE interested in `keyexpr` — the public-observer
    /// twin of [`interested`](Self::interested), and the input the Request route
    /// will feed to `directions_toward`. Empty if no peer declared a matching
    /// queryable. `pub` symmetric with `interested` (itself pub for the demo's
    /// shutdown summary): the current readers are this module's tests, and the
    /// Request-routing / demo-summary atom adds the production consumer.
    pub fn interested_queryables(&self, keyexpr: &str) -> Vec<Zid> {
        self.qabls.borrow().interested(keyexpr)
    }

    /// The number of live pending-query return entries across every face — the
    /// query-routing work witness (atom 3). Rises as `forward_request` records a
    /// return mapping per outbound face, falls as each `ResponseFinal` (a
    /// face-down purge, or a timeout sweep) frees one. Exposed so a test (and the
    /// timeout sweep) can observe the pending-query state.
    pub fn pending_len(&self) -> usize {
        self.pending.borrow().len()
    }

    /// The number of pending query BRANCHES the timeout sweep has reaped — the
    /// GC witness ([`reap_timed_out_queries`](Self::reap_timed_out_queries)),
    /// rising once per branch abandoned for want of a `ResponseFinal` on a
    /// still-up face (a 2-branch fan expiring counts 2). `0` on a healthy mesh;
    /// a test drives a short timeout to exercise it.
    pub fn pending_timed_out(&self) -> usize {
        self.timed_out.get()
    }

    /// Purge every node in `removed` from BOTH the subscription AND queryable
    /// interest tables — the single SSOT for zenoh's
    /// `pubsub_remove_node` + `queries_remove_node`-over-a-removed-set action,
    /// called from BOTH prune sites: a link-down (`deregister`, the
    /// `remove_link` detached set) and an ingest that detached nodes (`forward`,
    /// `changes.removed`). A gone node's interest must not keep a publisher's /
    /// querier's route gate spuriously armed. No-op for an empty set.
    ///
    /// R311y152 — this also fires the UNGRACEFUL detach undeclare-push (the peer
    /// twin of the router's `purge_detached_interest_tier`): a native leaving
    /// un-backs a co-attached CLIENT publisher's/querier's pushed reply ke exactly
    /// as a graceful `Undeclare` does, so `undeclare_push_subs/qabls` re-arm its pico
    /// write-filter here — zenoh's `pubsub_remove_node` ->
    /// `propagate_forget_simple_subscription` (and the `queries_remove_node` twin).
    /// The `subs`/`qabls` `borrow_mut`s are dropped BEFORE the undeclare loops, which
    /// re-borrow `self.subs`/`qabls` (`any_sub/qabl_matches`) and `self.faces`
    /// (`fan_out`); `deregister` hoists its own `self.faces` borrow so this runs with
    /// it free. `still_backed` is the post-removal GLOBAL fold, so a reply ke a
    /// surviving decl still backs is NOT undeclared. (Peer-specific, R311y163/D4:
    /// `any_sub_matches` folds `self.subs`, which now INCLUDES a co-attached client's
    /// sub re-sourced under SELF's zid
    /// ([`ingest_client_subscription`](Self::ingest_client_subscription)), so
    /// `still_backed` counts it — a mesh-sub detach no longer spuriously re-arms a
    /// co-attached client PUBLISHER's filter while a co-attached client SUBSCRIBER
    /// still wants the ke, and that subscriber IS served by
    /// [`deliver_to_client_subscribers`](Self::deliver_to_client_subscribers). The
    /// former two-clients-on-one-peer under-deliver gap is CLOSED.) Case c (the qabl completeness
    /// DOWNGRADE on a partial withdrawal) is CLOSED (R311y153):
    /// [`undeclare_push_qabls`](Self::undeclare_push_qabls) fires the value-aware
    /// downgrade re-push here too (a SUPERSET over zenoh's full-undeclare-only
    /// linkstate_peer hat).
    fn purge_detached_interest(&self, removed: &[Zid]) {
        if removed.is_empty() {
            return;
        }
        // Remove the departed natives from both tables, COLLECTING the affected
        // keyexprs (`remove_peer_keys`, the value-carrying twin of `remove_peer`) so
        // the undeclare-push below re-arms per un-backed reply ke. Scoped so the
        // `borrow_mut`s drop before the undeclare loops (which re-borrow the tables +
        // `self.faces`). A `Vec` (not the router's `HashSet`) is fine: a ke backed by
        // two removed zids appears twice, but undeclare_push is idempotent (the first
        // clears `pushed`, the second no-ops) — the peer set feeds ONLY the undeclare,
        // whereas the router set also feeds the cross-tier withdraw and dedups there.
        let (affected_subs, affected_qabls) = {
            let mut subs = self.subs.borrow_mut();
            let mut qabls = self.qabls.borrow_mut();
            let mut affected_subs: Vec<String> = Vec::new();
            let mut affected_qabls: Vec<String> = Vec::new();
            for zid in removed {
                affected_subs.extend(subs.remove_peer_keys(zid));
                affected_qabls.extend(qabls.remove_peer_keys(zid));
            }
            (affected_subs, affected_qabls)
        };
        for keyexpr in affected_subs {
            self.undeclare_push_subs(&keyexpr);
        }
        for keyexpr in affected_qabls {
            self.undeclare_push_qabls(&keyexpr);
        }
    }
}

/// Emit the CURRENT-mode interest reply set from a per-keyexpr candidate map —
/// the shared SSOT of the four `dump_interest_{subs,qabls}` legs across BOTH
/// forwarders (the router's dual mesh tables + client leaf; this peer's single
/// mesh set). The caller GATHERS its plane-specific `per_ke` (each keyexpr
/// already folded to ONE value `V` — `()` for subs, a merged
/// [`QueryableInfo`](wz_session_core::queryable_info::QueryableInfo) for qabls);
/// this fn owns only the aggregate-vs-explicit reply shape, identical for every
/// plane:
/// - AGGREGATE => ONE `Declare` keyed on the INTEREST keyexpr `target`, carrying
///   the `merge`-fold of every candidate value. pico matches an aggregate
///   interest's replies by keyexpr EQUALITY, so a concrete sub keyexpr would
///   silently fail to match — the reply MUST carry the interest keyexpr.
/// - explicit => one `Declare` per distinct candidate keyexpr, sorted for a
///   deterministic wire order, each carrying its own pre-folded value.
///
/// Empty `per_ke` => nothing sent (the caller's terminating `DeclareFinal` still
/// closes the interest; 0 matches keeps the soliciting peer's write-filter active
/// = "no subscriber yet", correct). `send` is the caller's single-message egress
/// (`send_one_to_face(inbound, _)`); a `build` error drops that ONE reply and
/// never panics. `V` is `Copy`-free — values move through `into_values` /
/// `into_iter`.
pub(crate) fn emit_current_interest_replies<V>(
    interest_id: u64,
    target: &str,
    aggregate: bool,
    per_ke: HashMap<String, V>,
    merge: impl Fn(V, V) -> V,
    build: impl Fn(u64, &str, V) -> Result<DeclareOwned, CodecError>,
    mut send: impl FnMut(NetworkMessage),
) {
    if per_ke.is_empty() {
        return;
    }
    if aggregate {
        let merged = per_ke
            .into_values()
            .reduce(merge)
            .expect("per_ke checked non-empty above");
        if let Ok(decl) = build(interest_id, target, merged) {
            send(NetworkMessage::Declare(Box::new(decl)));
        }
    } else {
        let mut entries: Vec<(String, V)> = per_ke.into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (ke, value) in entries {
            if let Ok(decl) = build(interest_id, &ke, value) {
                send(NetworkMessage::Declare(Box::new(decl)));
            }
        }
    }
}

/// This face's remote peer zid as the routing [`Zid`], or `None` if the
/// handshake did not surface one OR surfaced a non-conformant one — the SINGLE
/// session(`Vec<u8>`) -> routing(`Zid`) boundary every flood / forward path
/// reads through. The peer zid is captured verbatim from the peer's INIT body
/// (`SessionLinkActions::peer_zid`), so it is UNTRUSTED wire data: validate it
/// with the same `Zid::try_from` the linkstate ingest uses (rejecting an empty /
/// all-zero zid) rather than the infallible `from_slice`, so a non-conformant
/// peer cannot enter the graph as a zero-identity node. A face whose zid is
/// absent / rejected is held WITHOUT a routing identity (it routes nothing),
/// exactly like a zid-less face. The conversion lives here (the driver), keeping
/// `SessionLinkActions` (session-core, `#![no_std]`, routing-agnostic) free of
/// the routing `Zid` type.
pub(crate) fn peer_zid_routing(actions: &SessionLinkActions) -> Option<Zid> {
    actions
        .peer_zid()
        .and_then(|bytes| Zid::try_from(bytes).ok())
}

/// The neighbour's [`WhatAmI`] role for [`add_link`](LinkstateNetwork::add_link),
/// derived from the handshake (R311td "F1"). Mirrors [`peer_zid_routing`]: the
/// raw wire datum lives in routing-agnostic session-core, and the routing
/// interpretation (the 2-bit wire role -> the typed role via
/// [`WhatAmI::from_wire`], the SSOT decode in `wz-codecs`) lives here at the
/// driver boundary. The two fall-back cases are kept DISTINCT (not collapsed
/// into one silent default):
/// - role ABSENT (`None`): a face registered before the INIT exchange populated
///   the slot — silently the peer-mesh default [`WhatAmI::Peer`] (legitimate).
/// - role NON-CONFORMING (the reserved wire pattern): `log::warn!` then default
///   to [`WhatAmI::Peer`], matching the ingest path's warn-on-invalid-whatami
///   (`wz-routing-graph` `process_linkstates`) so a protocol violation is logged
///   on both paths, not swallowed silently here.
///
/// An all-peer deployment hits neither branch (wire Peer -> Peer), so it is
/// behaviour-unchanged.
pub(crate) fn peer_whatami_routing(actions: &SessionLinkActions) -> WhatAmI {
    match actions.peer_whatami_wire() {
        None => WhatAmI::Peer,
        Some(wire) => WhatAmI::from_wire(wire).unwrap_or_else(|| {
            log::warn!("face handshake whatami wire={wire} non-conforming; recording as peer");
            WhatAmI::Peer
        }),
    }
}

/// Resolve a sourced message's routing-context `node_id` against `net` to the
/// (source zid, this node's out-psid for it) pair — the SSOT for both
/// [`LinkstateForwarder::resolve_source`] AND
/// [`RouterForwarder`](crate::router_forward)'s per-tier resolution (R311y109).
/// The resolution reads ONLY the net (no faces / interest tables), so it is a
/// free fn over `&LinkstateNetwork` both forwarders share rather than a method.
/// `node_id == 0` means the inbound neighbour itself originated it; a non-zero id
/// is the source's psid in the inbound link's space. Returns `None` to DROP: an
/// unknown source (no inbound zid / no link / unmapped psid), the source
/// resolving to SELF (a looped-back message — self's local psid 0 is the
/// self-originated sentinel), or a local psid past the u16 routing-context range.
pub(crate) fn resolve_source_in(
    net: &LinkstateNetwork,
    inbound_zid: Option<Zid>,
    inbound_link: Option<LinkId>,
    node_id: u16,
) -> Option<(Zid, u16)> {
    let source_zid: Zid = match node_id {
        0 => inbound_zid?,
        nid => match inbound_link
            .and_then(|l| net.get_link(l))
            .and_then(|l| l.get_zid(nid as u64))
        {
            Some(zid) => *zid,
            // The message names a source psid the inbound link never mapped
            // (an out-of-order flood, or a link that dropped the mapping): the
            // message is dropped. Surface it (E2) so a non-forwarding route is
            // diagnosable.
            None => {
                log::debug!(
                    "dropping a sourced message: unresolvable source psid {nid} \
                     on the inbound link"
                );
                return None;
            }
        },
    };
    if source_zid == *net.self_zid() {
        return None;
    }
    let out_node_id = u16::try_from(net.local_psid_of(&source_zid)?).ok()?;
    Some((source_zid, out_node_id))
}

/// Compute the data-`Push` re-forward for ONE link-state mesh: given the tier's
/// `net` + subscription `subs` and a Push already resolved against the inbound
/// link's alias table (`keyexpr`), return the re-stamped carrier + the
/// interested tree children to fan it out to — or `None` to DROP. The pure route
/// CORE shared by [`LinkstateForwarder::forward_push`] (its ONE net) and
/// [`RouterForwarder`](crate::router_forward)'s per-tier data route (each of its
/// TWO nets), so the loop-freedom bound (the hop-limit) + the literal normalize
/// live in ONE place, not a per-forwarder copy that could drift (R311y112).
///
/// Reads ONLY `net` + `subs` — no faces, no fan-out: the caller resolves the
/// inbound face in its own borrow (it owns a `RouterFaceState` vs a `FaceState`)
/// and fans the returned `(carrier, children)` out through its tier-appropriate
/// seam, exactly as [`resolve_source_in`] splits the net-only resolution from
/// the face-owning caller. Drops (→ `None`) on an unresolvable source, a keyexpr
/// no remote peer subscribes to (the self-excluded [`LinkstatepeerInterest::interested_remote`]
/// view — the self-bubble is the local sink, never a data forward target), an
/// empty tree direction, an exhausted hop budget (`hop <= 1`), or a carrier the
/// literal-normalize rejects.
pub(crate) fn compute_push_forward(
    net: &RefCell<LinkstateNetwork>,
    subs: &RefCell<LinkstatepeerInterest<()>>,
    inbound_zid: Option<Zid>,
    inbound_link: Option<LinkId>,
    push: &PushOwned,
    keyexpr: &str,
) -> Option<(PushOwned, Vec<Zid>)> {
    let net = net.borrow();
    // Resolve the source (tree root) + this node's psid for it — the same seam a
    // sourced Declare uses; both flood along the source's tree.
    let (source_zid, out_node_id) =
        resolve_source_in(&net, inbound_zid, inbound_link, read_push_source(push))?;
    // The data-route filter: forward only toward subtrees that hold an
    // interested subscriber, excluding self (interested_remote) — self is the
    // local sink, delivered by the session layer, not a mesh forward target.
    let self_zid = *net.self_zid();
    let interested = subs.borrow().interested_remote(keyexpr, &self_zid);
    if interested.is_empty() {
        return None;
    }
    let children = net.directions_toward(&source_zid, &interested);
    if children.is_empty() {
        return None;
    }
    // Hop-limit (c3c-3 D1): a Push that has exhausted its forward budget is NOT
    // re-forwarded — the by-construction transient-convergence loop bound. Absent
    // = an un-stamped Push from a non-stamping origin; treat it as a fresh budget
    // (this node's node_count). `hop <= 1` = the last unit arrived here: the node
    // still received + locally delivered the data, it just stops the onward flood.
    let budget = net.node_count() as u16;
    let hop = read_push_hoplimit(push).unwrap_or(budget);
    if hop <= 1 {
        return None;
    }
    // Re-stamp the source psid + decrement the budget, and NORMALIZE the keyexpr
    // to a literal (a downstream child does not share this inbound link's alias
    // table, so an aliased id would be unresolvable there; wz keeps no outbound
    // alias table, so it always emits id == 0) — the same B1 normalize inline.
    let mut carrier = push.clone();
    set_push_source(&mut carrier, out_node_id);
    set_push_hoplimit(&mut carrier, hop - 1);
    set_push_keyexpr_literal(&mut carrier, keyexpr).ok()?;
    Some((carrier, children))
}

/// Compute the self-ORIGINATED data-`Push` forward for ONE link-state mesh:
/// treat SELF as the tree root (a node PUBLISHING its own data — or, for the
/// router, a leaf CLIENT's data re-injected as self-sourced) and return the
/// self-sourced carrier + the interested tree children to fan it out to, or
/// `Ok(None)` to send nowhere. The ORIGINATE twin of [`compute_push_forward`]
/// (the transit RE-forward core): there the source is a resolved REMOTE node and
/// the hop budget is DECREMENTED; here the source is SELF (`node_id 0` —
/// [`set_push_source`]`(_, 0)` REMOVES the ext, zenoh's omit-on-DEFAULT) with a
/// FRESH budget (`node_count`). Genuinely distinct route semantics (originate vs
/// re-forward), kept as TWO cores exactly as the codebase keeps
/// [`LinkstateForwarder::publish`] separate from
/// [`forward_push`](LinkstateForwarder::forward_push).
///
/// Shared by [`LinkstateForwarder::publish`] (`build = build_push_literal`, a
/// FRESH local sample) and [`RouterForwarder`](crate::router_forward)'s
/// client->mesh re-injection (`build = reliteralize_push`, a RECEIVED client
/// sample whose encoding/attachment/timestamp/qos MUST survive) — so the two
/// drift-prone invariants (the `node_count` loop budget + the `node_id 0`
/// self-stamp) live in ONE place, not a per-caller copy (R311y112 core-extract
/// discipline). Reads ONLY `net` + `subs` (no faces, no fan-out): the caller
/// fans the returned `(carrier, children)` through its own tier-appropriate
/// egress seam. Drops (→ `Ok(None)`) on a keyexpr no remote peer subscribes to
/// (the self-excluded [`LinkstatepeerInterest::interested_remote`] view — the
/// self-bubble is the local sink, never a data forward target) or an empty tree
/// direction; a `build` codec failure propagates as `Err`.
pub(crate) fn compute_self_publish_forward(
    net: &RefCell<LinkstateNetwork>,
    subs: &RefCell<LinkstatepeerInterest<()>>,
    keyexpr: &str,
    build: impl FnOnce() -> Result<PushOwned, CodecError>,
) -> Result<Option<(PushOwned, Vec<Zid>)>, CodecError> {
    // Borrow the net once for the whole route compute (the `compute_push_forward`
    // idiom); `subs` is a distinct cell borrowed as a temp, and `build` touches
    // neither, so the single held borrow is safe.
    let net = net.borrow();
    let self_zid = *net.self_zid();
    let interested = subs.borrow().interested_remote(keyexpr, &self_zid);
    if interested.is_empty() {
        return Ok(None);
    }
    let children = net.directions_toward(&self_zid, &interested);
    if children.is_empty() {
        return Ok(None);
    }
    let mut carrier = build()?;
    // Self-originated: node_id 0 removes the ext_nodeid, so a downstream hop
    // resolves the source to THIS node (its inbound neighbour) and floods along
    // self's tree. Fresh hop budget = node_count (the by-construction
    // transient-loop bound), the same stamp `compute_push_forward` decrements.
    set_push_source(&mut carrier, 0);
    set_push_hoplimit(&mut carrier, net.node_count() as u16);
    Ok(Some((carrier, children)))
}

/// Synthesize the querier-ward TIMEOUT messages for a reaped pending sweep —
/// the shared per-branch core both forwarders' `reap_timed_out_queries` call
/// with their own single-target send seam, so the zenoh `QueryCleanup::run`
/// semantics (`dispatcher/queries.rs:305-349`) live ONCE: an `Err("Timeout")`
/// reply per reaped BRANCH (zenoh runs one cleanup task per branch, each
/// sending an Err; a build error skips the Err — the final is the load-bearing
/// part) and the closing `ResponseFinal` only for a `last` branch (the fan's
/// last-out gate, zenoh `finalize_pending_query`'s `Arc::into_inner`). Both
/// carry the recorded upstream rid toward the recorded inbound face.
///
/// Multi-hop note: an intermediate wz relay PASSES the empty-keyexpr Err
/// through unresolved (`forward_response`'s `wireexpr_is_empty` arm, matching
/// zenoh `route_send_response`'s no-resolution forward), so the explicit Err
/// reaches the querier across relays, as does the final.
pub(crate) fn synthesize_expired_query_returns(
    reaped: &[ExpiredQuery],
    mut send: impl FnMut(FaceId, NetworkMessage),
) {
    for eq in reaped {
        if let Ok(err_msg) =
            wz_session_core::response_build::build_response_err_empty(eq.inbound_rid, b"Timeout")
        {
            send(eq.inbound, NetworkMessage::Response(Box::new(err_msg)));
        }
        if !eq.last {
            continue;
        }
        let final_msg = wz_session_core::response_final_build::build_response_final(eq.inbound_rid);
        send(eq.inbound, NetworkMessage::ResponseFinal(final_msg));
    }
}

/// Synthesize the closing `ResponseFinal` for each fan a face-down DRAINED —
/// the shared core both forwarders' `deregister` call after
/// [`PendingQueries::remove_face`], so the zenoh `finalize_pending_queries`
/// semantics (face teardown drains through the last-out gate, FINAL only — no
/// Err) live ONCE. A drained fan whose querier IS the `departed` face has
/// nobody left to notify (skipped); the others get the final that terminates
/// their `get()` instead of waiting out their own timeout.
pub(crate) fn synthesize_drained_fan_finals(
    drained: &[(FaceId, u64)],
    departed: FaceId,
    mut send: impl FnMut(FaceId, NetworkMessage),
) {
    for &(querier, rid) in drained {
        if querier == departed {
            continue;
        }
        let final_msg = wz_session_core::response_final_build::build_response_final(rid);
        send(querier, NetworkMessage::ResponseFinal(final_msg));
    }
}

/// Compute the query-route DIRECTIONS (the queryable-ward tree children) for a
/// Request in ONE link-state mesh — the shared query-route CORE, the query twin
/// of [`compute_push_forward`], so [`LinkstateForwarder::forward_request`] (its
/// ONE net) and the pending router query slice (C5b, each of its TWO tier nets)
/// reuse the SAME BestMatching / All / AllComplete logic, not a per-forwarder
/// copy. Reads
/// ONLY `net` + `qabls` (borrowing `net` ONCE for the whole compute); the caller
/// owns the faces, the pending-query allocation, and the fan-out. `target` is the
/// Request's carried `QueryTarget` (the wire DEFAULT, an absent ext, is `None` =
/// BestMatching). Returns the tree hops to forward toward — empty = route nowhere
/// (no matching queryable, or only a self-hosted / inbound-ward one the caller
/// handles).
pub(crate) fn compute_query_directions(
    net: &RefCell<LinkstateNetwork>,
    qabls: &RefCell<LinkstatepeerInterest<QueryableInfo>>,
    keyexpr: &str,
    target: Option<QueryTarget>,
    source_zid: &Zid,
    inbound_zid: Option<Zid>,
) -> Vec<Zid> {
    let net = net.borrow();
    let self_zid = *net.self_zid();
    match target {
        // BestMatching (wire default): the SINGLE nearest COMPLETE queryable, else
        // fall back to QueryTarget::All (fan out to every matching one).
        None => {
            match select_best_matching(&net, qabls, keyexpr, source_zid, &self_zid, inbound_zid) {
                // The single net discards the distance (the router keeps it to
                // rank the global-nearest across both meshes, C5b).
                Some((_distance, hop)) => vec![hop],
                None => all_query_directions(&net, qabls, keyexpr, source_zid, &self_zid),
            }
        }
        // QueryTarget::All: every matching queryable's subtree direction.
        Some(QueryTarget::All) => all_query_directions(&net, qabls, keyexpr, source_zid, &self_zid),
        // QueryTarget::AllComplete: every COMPLETE matching queryable's subtree
        // direction (the complete-for-query filter, FANNED OUT — not narrowed to
        // the nearest, unlike BestMatching).
        Some(QueryTarget::AllComplete) => {
            complete_query_directions(&net, qabls, keyexpr, source_zid, &self_zid)
        }
    }
}

/// zenoh `QueryTarget::BestMatching` (`dispatcher/queries.rs:243-266`): pick the
/// SINGLE nearest COMPLETE queryable for `keyexpr` and return `(graph distance,
/// tree direction)` — the next-hop neighbour toward it in the SOURCE's tree PLUS
/// the self-relative graph distance used to rank it — or `None` when no complete
/// queryable matches (the single-net [`compute_query_directions`] then falls back
/// to `QueryTarget::All`). "Nearest" is the GRAPH distance from THIS node to the
/// queryable peer (zenoh's `insert_target_for_qabls` reads `net.distances[qabl_idx]`,
/// `queries.rs:1107`, NOT the carried declaration distance). The inbound direction
/// is excluded, and an unreachable peer contributes nothing. A distance TIE breaks
/// by the candidate scan order (`HashMap` iteration, unspecified — same as zenoh);
/// harmless, every equal-distance complete queryable fully answers the query.
///
/// The distance is RETURNED (not discarded) because it is SELF-relative — the hop
/// count from THIS node to the queryable, comparable ACROSS the router's two
/// meshes. The router's GLOBAL BestMatching (`RouterForwarder::route_request`,
/// C5b) picks the global-nearest complete queryable as the min over each net's
/// per-net nearest (min-of-mins == global-min), and per-net client candidates at
/// distance 1 (zenoh `compute_final_route` finds the FIRST complete in the
/// distance-sorted union route, `queries.rs:1520`). The single-net peer caller
/// discards the distance.
pub(crate) fn select_best_matching(
    net: &LinkstateNetwork,
    qabls: &RefCell<LinkstatepeerInterest<QueryableInfo>>,
    keyexpr: &str,
    source_zid: &Zid,
    self_zid: &Zid,
    inbound_zid: Option<Zid>,
) -> Option<(f64, Zid)> {
    complete_for_query_peers(qabls, keyexpr, self_zid)
        .into_iter()
        .filter_map(|peer| {
            // The tree direction toward the peer + its graph distance. Skip the
            // inbound direction (no routing a Query back at its source) and any
            // unreachable peer.
            let hop = net.next_hop(source_zid, &peer)?;
            if inbound_zid == Some(hop) {
                return None;
            }
            Some((net.distance_to(&peer)?, hop))
        })
        .min_by(|(a, _), (b, _)| a.total_cmp(b))
}

/// The peers offering a queryable COMPLETE for `keyexpr` — declared complete AND
/// whose declaration keyexpr INCLUDES the full query keyexpr (zenoh's `complete
/// && qabl_info.complete`, `hat/linkstate_peer/queries.rs:723`), excluding self.
/// The shared candidate set for BestMatching (pick the nearest) AND AllComplete
/// (route to every one). A peer matching via several declarations may appear more
/// than once — harmless: BestMatching's min-distance and AllComplete's
/// `directions_toward` both dedup downstream.
fn complete_for_query_peers(
    qabls: &RefCell<LinkstatepeerInterest<QueryableInfo>>,
    keyexpr: &str,
    self_zid: &Zid,
) -> Vec<Zid> {
    let query_chunks: Vec<&str> = keyexpr.split('/').collect();
    qabls
        .borrow()
        .matching_entries(keyexpr, Some(self_zid))
        .into_iter()
        .filter_map(|(decl, peer, info)| {
            (info.complete && keyexpr_includes_target(decl, &query_chunks)).then_some(peer)
        })
        .collect()
}

/// The tree directions (next-hop neighbours) toward EVERY queryable matching
/// `keyexpr` in the SOURCE's tree — `QueryTarget::All` (`dispatcher/queries.rs:215`),
/// and the BestMatching fallback when no queryable is complete.
/// `directions_toward` dedups to one hop per subtree; the inbound-face exclusion
/// is the fan_out's `is_tree_forward_target`. `pub(crate)` so the router composes
/// it per-tier for its `QueryTarget::All` route (C5b).
pub(crate) fn all_query_directions(
    net: &LinkstateNetwork,
    qabls: &RefCell<LinkstatepeerInterest<QueryableInfo>>,
    keyexpr: &str,
    source_zid: &Zid,
    self_zid: &Zid,
) -> Vec<Zid> {
    let interested = qabls.borrow().interested_remote(keyexpr, self_zid);
    net.directions_toward(source_zid, &interested)
}

/// The tree directions toward every COMPLETE-for-`keyexpr` queryable —
/// `QueryTarget::AllComplete` (`dispatcher/queries.rs:228`): the complete-for-query
/// filter FANNED OUT (every complete one), not narrowed to the nearest as
/// BestMatching does. `directions_toward` dedups to one hop per subtree; the
/// inbound-face exclusion is the fan_out's predicate. `pub(crate)` so the router
/// composes it per-tier for its `QueryTarget::AllComplete` route (C5b).
pub(crate) fn complete_query_directions(
    net: &LinkstateNetwork,
    qabls: &RefCell<LinkstatepeerInterest<QueryableInfo>>,
    keyexpr: &str,
    source_zid: &Zid,
    self_zid: &Zid,
) -> Vec<Zid> {
    let peers = complete_for_query_peers(qabls, keyexpr, self_zid);
    net.directions_toward(source_zid, &peers)
}

/// Re-advertise the interest in `table` to the NEW tree children a recompute
/// added, for ONE mesh — the tree-change re-flood CORE shared by
/// [`LinkstateForwarder::re_advertise_interest`] (its ONE net) and
/// [`RouterForwarder`](crate::router_forward)'s per-tier tick (each of its TWO
/// nets). The single-net caller hard-bound the net + the flood; here BOTH are
/// parameters, so the router stamps `out_node_id` in the CORRECT tier's psid
/// space (routers_net for `router_subs`, linkstatepeers_net for
/// `linkstatepeer_subs`) rather than injecting a wrong-net psid, and floods via
/// its tier-scoped fan-out (R311y112). `build` mints the per-entry carrier from
/// the literal keyexpr + value (`V = ()` subs / `QueryableInfo` qabls);
/// `flood(children, declare)` sends it to the delta children. Structure is
/// unchanged from the single-net original: outer over the new-children delta,
/// inner over the declarations sourced at that tree (`*src == tree_id`), each
/// re-stamped for the source (`local_psid_of(self) == 0` leaves a self-sourced
/// declaration self-originated).
pub(crate) fn re_advertise_interest_into<V: Clone>(
    net: &RefCell<LinkstateNetwork>,
    table: &RefCell<LinkstatepeerInterest<V>>,
    new_children: &[(Zid, Vec<Zid>)],
    build: impl Fn(&str, &V) -> Result<DeclareOwned, CodecError>,
    mut flood: impl FnMut(&[Zid], &DeclareOwned),
) {
    if new_children.is_empty() {
        return;
    }
    // Snapshot the (keyexpr, source, value) entries so the table borrow is
    // released before the per-source net borrow + flood below.
    let pairs = table.borrow().entries();
    for (source_zid, delta_children) in new_children {
        // this node's psid for the source (the re-stamp value). Scoped net
        // borrow released before flood (which re-borrows via the caller's seam).
        let out_node_id = match net
            .borrow()
            .local_psid_of(source_zid)
            .and_then(|p| u16::try_from(p).ok())
        {
            Some(n) => n,
            None => continue,
        };
        for (keyexpr, decl_source, value) in &pairs {
            if decl_source != source_zid {
                continue;
            }
            let Ok(mut declare) = build(keyexpr, value) else {
                continue;
            };
            set_declare_source(&mut declare, out_node_id);
            flood(delta_children, &declare);
        }
    }
}

/// Record (or drop) a link-local keyexpr alias from a `DeclKexpr` / `UndeclKexpr`
/// into `table` — the SSOT shared by BOTH forwarders' `absorb_keyexpr_declaration`
/// (R311y111). The declared base may reference an earlier alias on the same link,
/// so it is resolved against `table` before recording; an unknown-alias declare
/// is dropped. Link-local: each link negotiates its own aliases (not re-flooded).
/// Only the two keyexpr-declaration bodies reach here; a defensive no-op otherwise.
// R311y196 — the keyexpr-absorb SSOT moved to `wz-session-core` so the no_std
// multicast per-peer ingress plane (§5.21 router-multicast-faces I3a) and the
// unicast router faces share ONE definition. Re-exported here so every existing
// `absorb_keyexpr_into(..)` call site in this module is unchanged.
pub(crate) use wz_session_core::wireexpr_resolve::absorb_keyexpr_into;

/// Whether `zid` is one of `children` — the tree next hops a fan-out targets.
/// The shared membership check the originate paths ([`publish`](LinkstateForwarder::publish)
/// / [`declare_subscription`](LinkstateForwarder::declare_subscription)) and
/// the re-forward paths ([`is_tree_forward_target`]) both build on.
fn is_child(children: &[Zid], zid: Zid) -> bool {
    children.contains(&zid)
}

/// Build a literal sourced `DeclareQueryable` CARRYING the `QueryableInfo` — the
/// SSOT carrier mint shared by BOTH queryable re-flood paths
/// ([`forward_queryable`](LinkstateForwarder::forward_queryable)'s inbound
/// re-flood AND
/// [`re_advertise_queryables`](LinkstateForwarder::re_advertise_queryables)'
/// tree-change re-flood), so a queryable's completeness propagates DOWNSTREAM
/// identically on either path — what makes MULTI-HOP BestMatching work (a relay
/// N hops from the queryable learns its completeness, then routes by the GRAPH
/// distance to it). zenoh `propagate_sourced_queryable` re-floods the registered
/// `QueryableInfo` VERBATIM — NO per-hop distance increment (BestMatching reads
/// `net.distances`, not the carried distance). DEFAULT / incomplete omits the
/// ext (byte-identical to the prior clean re-flood).
pub(crate) fn build_declare_queryable_with_info(
    keyexpr: &str,
    info: QueryableInfo,
) -> Result<DeclareOwned, CodecError> {
    let mut declare = build_declare_queryable(0, 0, Some(keyexpr))?;
    set_declare_queryable_info(&mut declare, info);
    Ok(declare)
}

/// Whether a face is a valid forward target when RE-FORWARDING along a source
/// tree: its `zid` is one of `children` (the next hops), it is NOT the inbound
/// face, and its zid is not the inbound neighbour's (a parallel link back
/// toward the source). The single selection predicate shared by every
/// tree-re-forward path — [`forward_push`](LinkstateForwarder::forward_push)
/// (data, directions-filtered `children`),
/// [`forward_subscription`](LinkstateForwarder::forward_subscription) /
/// [`forward_unsubscription`](LinkstateForwarder::forward_unsubscription) /
/// [`forward_interest_declaration`](LinkstateForwarder::forward_interest_declaration)
/// (control, all tree `children`), and
/// [`forward_request`](LinkstateForwarder::forward_request) (the query route) —
/// only the carrier each wraps differs, so the loop-exclusion mechanics live
/// here once.
pub(crate) fn is_tree_forward_target(
    id: FaceId,
    zid: Option<Zid>,
    inbound: FaceId,
    inbound_zid: Option<Zid>,
    children: &[Zid],
) -> bool {
    let Some(zid) = zid else {
        return false;
    };
    id != inbound && inbound_zid != Some(zid) && is_child(children, zid)
}

/// The keyexpr `Wireexpr` a `DeclareSubscriber` declares interest in — `None` for
/// a non-subscriber Declare body. Returns the raw `Wireexpr` (literal OR aliased)
/// so the caller resolves it against the inbound face's alias table (B1b), rather
/// than a pre-resolved literal string.
pub(crate) fn declare_subscriber_wireexpr(declare: &DeclareOwned) -> Option<&WireexprOwned> {
    match &declare.body {
        DeclareOwnedVariant::CodecZenohDeclSubscriber(sub) => Some(&sub.keyexpr),
        _ => None,
    }
}

/// The keyexpr `Wireexpr` a `DeclareQueryable` declares interest in — `None` for
/// a non-queryable Declare body. The query-plane twin of
/// [`declare_subscriber_wireexpr`]; returns the raw `Wireexpr` (literal OR
/// aliased) so the caller resolves it against the inbound face's alias table
/// (B1b), exactly as the subscriber side.
pub(crate) fn declare_queryable_wireexpr(declare: &DeclareOwned) -> Option<&WireexprOwned> {
    match &declare.body {
        DeclareOwnedVariant::CodecZenohDeclQueryable(q) => Some(&q.keyexpr),
        _ => None,
    }
}

/// The keyexpr `Wireexpr` a `DeclareToken` declares a liveliness token for —
/// `None` for a non-token Declare body. The liveliness-token twin of
/// [`declare_subscriber_wireexpr`]; the `DeclareToken` carries its keyexpr
/// inline (like `DeclareSubscriber`), returned raw (literal OR aliased) so the
/// caller resolves it against the inbound face's alias table (B1b).
#[cfg(feature = "routing-token-tables")]
pub(crate) fn declare_token_wireexpr(declare: &DeclareOwned) -> Option<&WireexprOwned> {
    match &declare.body {
        DeclareOwnedVariant::CodecZenohDeclToken(t) => Some(&t.keyexpr),
        _ => None,
    }
}

impl FaceForwarder for LinkstateForwarder {
    fn register(&self, id: FaceId, actions: &Arc<SessionLinkActions>) {
        // Connect the face in the graph if its routing zid surfaced at the
        // handshake (R311qi). Without a zid there is no graph identity to key
        // on, so the face is held (its send seam kept) but not connected — it
        // cannot route topology, and there is nothing to bootstrap it with.
        // R311td ("F1") — the neighbour's real handshake WhatAmI is now threaded
        // onto the face: `peer_whatami_routing` maps the wire role captured at the
        // INIT exchange to the graph's API-form byte (absent / non-conforming ->
        // WhatAmI::Peer, the peer-mesh default). Spanning-tree forwarding stays
        // whatami-agnostic, so this is behaviour-neutral for an all-peer mesh; it
        // is the gossip-policy / autoconnect prerequisite (those gate per the
        // target's true role).
        // OBLIGATION-3 self-zid parity: a face whose routing zid IS self's own
        // zid (a self-connect) is HELD without a link — adding it would insert a
        // self entry into `node.links` that `make_link_state` then emits as a
        // spurious self-loop link (psid 0) onto the wire, plus an sn bump real
        // peers ingest — `rebuild_edges`'s `idx2 != idx1` guard skips the petgraph
        // self-EDGE but does NOT scrub that `node.links` entry, so the self-loop
        // still floods. zenoh relies on its transport manager never handing
        // `add_link` a self-transport; wz guards it here (mirror in
        // `RouterForwarder::register`).
        let self_zid = *self.net.borrow().self_zid();
        let neighbour_whatami = peer_whatami_routing(actions);
        let added = peer_zid_routing(actions)
            .filter(|neighbour| *neighbour != self_zid)
            // R311y163 (D4) — a CLIENT face is a LEAF (zenoh `session_ctxs`), never a
            // link-state graph node: held with its send seam (the `faces` insert
            // below) but NOT `add_link`'d, so it neither inflates `node_count` (the
            // hop budget) nor floods a spurious one-directional self->client link
            // mesh-wide via `make_link_state`. Mirrors `RouterForwarder::register`'s
            // Client-tier `None` arm and the OBLIGATION-3 self-zid parity guard above.
            // A co-attached client's subscription rides `subs` under SELF's zid
            // instead ([`ingest_client_subscription`](Self::ingest_client_subscription)).
            .filter(|_| neighbour_whatami != WhatAmI::Client)
            .map(|neighbour| {
                let mut net = self.net.borrow_mut();
                // Whether this neighbour is NEW to the GRAPH (not merely a new
                // face): a second link to an already-known peer re-advertises only
                // self's links, not the neighbour again — zenoh add_link's `new`
                // flag (`network.rs:826`). Queried before add_link, under the one
                // borrow.
                let neighbour_was_new = net.get_node(&neighbour).is_none();
                let link_id = net.add_link(neighbour, neighbour_whatami);
                (link_id, neighbour, neighbour_was_new)
            });
        self.faces.borrow_mut().insert(
            id,
            FaceState {
                actions: actions.clone(),
                link: added.map(|(link_id, _, _)| link_id),
                keyexpr_table: hashbrown::HashMap::new(),
            },
        );
        // Self gained a routing link (its own link-state changed, sn bumped): the
        // NEW face is bootstrapped with the full topology and the EXISTING faces
        // learn the change NOW (event-driven), via the minimal D4 delta —
        // `flood_link_added` (zenoh `add_link`, `network.rs:861-932`: full on the
        // new link, a 2-entry delta on existing links). D2b — no periodic
        // re-flood. A held-without-identity face (added == None) is not a routing
        // peer and did not change self's link-state, so it triggers no flood.
        if let Some((_, neighbour, neighbour_was_new)) = added {
            let _ = self.flood_link_added(id, &neighbour, neighbour_was_new);
            // Self gained a link, so its spanning trees changed: SCHEDULE a
            // recompute (D2c coalesces it onto the tick), mirroring zenoh's
            // schedule_compute_trees on link-up (`hat/linkstate_peer/mod.rs:275`).
            // Without it self's local trees would stay stale until the neighbour's
            // reciprocal inbound flood happened to trigger a recompute — a bounded
            // transient drop window toward a destination reachable only via the new
            // neighbour. Scheduling here closes it without waiting for the reply.
            self.schedule_recompute();
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
        //
        // atom 3 — drop this face's pending-query return entries (it is keyed by
        // FaceId, not the graph link, so EVERY face-down purges it, whether or not
        // the face had a routing identity): a Response can never be routed toward
        // (or expected back from) a dead face. zenoh tears down a face's
        // `pending_queries` on close the same way (`finalize_pending_queries`),
        // and — through the same last-out gate — sends the closing ResponseFinal
        // to each querier whose fan this face-down DRAINED (its last answering
        // branch died), so the querier's get() terminates instead of waiting out
        // its own timeout. A drained fan whose querier IS the departed face has
        // nobody left to notify (skipped).
        let drained = self.pending.borrow_mut().remove_face(&id);
        synthesize_drained_fan_finals(&drained, id, |face, msg| self.send_one_to_face(face, msg));
        // Purge this face's FUTURE-mode interest + pushed-declaration state
        // UNCONDITIONALLY, before the graph teardown below (a client face is
        // `link == None`, so it never reaches that branch) — the peer's analogue of
        // the router's OBLIGATION-1 client-leaf purge. pico clears its own
        // write-filter targets on the transport drop (filtering.c
        // CONNECTION_DROPPED), so no undeclare is owed.
        self.future_subs.borrow_mut().purge_face(id);
        self.future_qabls.borrow_mut().purge_face(id);
        // R311y163 (D4) — purge this face's co-attached CLIENT subscriptions (leaf
        // store) UNCONDITIONALLY, before the graph teardown below, and for each
        // keyexpr it was the LAST source of (no surviving client or self-native
        // local sub) withdraw the self-sourced mesh advertisement + flood the
        // forget. The removed set is HOISTED out of the loop scrutinee (edition
        // 2021 keeps a `borrow_mut()` temporary alive across the loop; the withdraw
        // below re-borrows `client_subs` via `any_client_subscribes`) — the same
        // hoist discipline as the face removal below.
        let departed_client_subs = self
            .client_subs
            .borrow_mut()
            .remove(&id)
            .unwrap_or_default();
        // Dedup the kes (a client may hold ONE ke under several ids) so the withdraw +
        // forget flood fires ONCE per unique ke, not once per id (the old keyexpr-SET
        // deduped structurally; the id-map must dedup here). BTreeSet = deterministic.
        for keyexpr in departed_client_subs
            .into_values()
            .collect::<std::collections::BTreeSet<_>>()
        {
            let _ = self.withdraw_mesh_sub_if_unbacked(&keyexpr);
        }
        // Query-plane twin of the client-sub purge above: drain this face's co-attached
        // CLIENT queryables and, for each ke, downgrade-or-withdraw the self-sourced mesh
        // advert (a surviving self-native / other-client source DOWNGRADES the merged
        // info; the LAST source's departure withdraws self + floods the forget). Same
        // hoist discipline — withdraw_mesh_qabl_if_unbacked re-borrows client_qabls via
        // derived_self_qabl_info.
        let departed_client_qabls = self
            .client_qabls
            .borrow_mut()
            .remove(&id)
            .unwrap_or_default();
        // Dedup the kes (same ke under several ids) so the downgrade-or-withdraw fires
        // ONCE per unique ke, not once per id (the keyexpr-map twin deduped structurally).
        for keyexpr in departed_client_qabls
            .into_values()
            .map(|(ke, _info)| ke)
            .collect::<std::collections::BTreeSet<_>>()
        {
            let _ = self.withdraw_mesh_qabl_if_unbacked(&keyexpr);
        }
        // R311y152 — hoist the face removal OUT of the `if let` scrutinee so its
        // `RefMut` on `self.faces` drops at THIS `;`. Edition 2021 keeps a scrutinee
        // temporary alive across the whole `if let` block, and
        // `purge_detached_interest` below now fires the undeclare-push, whose fan_out
        // re-borrows `self.faces` (`undeclare_push_subs` -> `send_one_to_face` ->
        // `fan_out`); the hoist frees that borrow before the choke point runs (the
        // router's `deregister` is already `let-else`, so it needs no such hoist).
        let removed_face = self.faces.borrow_mut().remove(&id);
        let dropped_link = if let Some(state) = removed_face {
            if let Some(link) = state.link {
                // remove_link drops the self<->neighbour edge and GC-prunes every
                // node the link's loss DETACHED from the mesh (zenoh remove_link ->
                // remove_detached_nodes, network.rs:948). Purge each pruned node's
                // subscription interest — zenoh's `pubsub_remove_node` per removed
                // node on link-down (`hat/linkstate_peer/mod.rs:378-387`). Without
                // it a gone subscriber's interest lingers, keeping a publisher's
                // any-interest gate spuriously armed. The departed neighbour is
                // itself in the pruned set when it had no other path, so this both
                // subsumes AND corrects the former unconditional peer purge: a
                // neighbour still reachable via another face KEEPS its interest (it
                // is still a valid subscriber, reached via the surviving path), as
                // in zenoh — only the genuinely detached set is purged.
                let removed = self.net.borrow_mut().remove_link(link);
                self.purge_detached_interest(&removed);
                true
            } else {
                false
            }
        } else {
            false
        };
        if dropped_link {
            // D2b — self LOST a routing link (its own link-state changed, sn
            // bumped): flood self's updated LINKS-ONLY entry to the surviving faces
            // IMMEDIATELY (zenoh `remove_link`'s `send_on_links` of one
            // links-only self entry, `network.rs:952-962`), so they drop the dead
            // link from their topology NOW (the D4 self-flood delta — no full
            // topology, no node-removal entries; each receiver prunes the detached
            // nodes itself). The flood is a wire event on the link change and stays
            // inline; only the spanning-tree recompute it triggers is coalesced (D2c).
            let _ = self.flood_self_links_changed();
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
        // Reap pending queries whose `ResponseFinal` never arrived on a still-up
        // face (zenoh's per-query `QueryCleanup` timeout) on the same coalescing
        // cadence — a cheap empty sweep when nothing timed out.
        self.reap_timed_out_queries();
    }

    /// The linkstate peer's topology graph keys the self-edge on the peer zid, so
    /// it must hold AT MOST ONE face per zid: two faces to one peer would give the
    /// graph two links for one zid, and either face's teardown `remove_link`
    /// (keyed on zid) would prune the still-live peer. The loop enforces it by
    /// dropping a redundant second face at establishment — the wz analog of
    /// zenoh's one-transport-per-zid (`init_transport_unicast`).
    fn dedups_faces_by_zid(&self) -> bool {
        true
    }

    /// R311y219b — record a joined aggregated link's id -> the session's PRIMARY
    /// registered face, so [`forward`](Self::forward) resolves the joined link's
    /// inbound onto the primary's face table (one logical face per aggregate). No
    /// self-flood / graph change: the joined link is NOT a new routing neighbour
    /// (the primary already IS the graph link to this peer), only a second physical
    /// carrier for the same session.
    fn register_joined(&self, joined_id: FaceId, primary_id: FaceId) {
        self.joined_faces.borrow_mut().insert(joined_id, primary_id);
    }

    /// R311y219b — the joined link died: forget its id -> primary mapping.
    fn deregister_joined(&self, joined_id: FaceId) {
        self.joined_faces.borrow_mut().remove(&joined_id);
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
        // R311y219b (transport-multilink) — resolve a JOINED aggregated link's own
        // FaceId to the session's PRIMARY registered face BEFORE any delivery / route
        // / ACL logic below, so the joined link's data + control are served against
        // the primary's face table (`faces`, keyexpr aliases, graph link, ACL
        // subject) — the aggregate is ONE logical face (the faithful zenoh model),
        // and no Put/Declare on the secondary link is dropped at the
        // `faces.get(inbound)=None` gate. Identity (no-op) for a primary / single-
        // link face (absent from `joined_faces`); the raw physical id is preserved
        // for observation-only forwarders, which never populate the map. INVARIANT:
        // merging both links' inbound into the primary's ONE `keyexpr_table` cannot
        // collide because a faithful peer mints DeclareKeyexpr mapping ids per-SESSION
        // (both links share one session), not per-link; literal keyexprs (id 0) are
        // table-independent regardless.
        let id = self.resolve_joined_face(id);
        // #3-c (R311y167) — track re-entrancy so the self-echo drain runs ONCE, at
        // the outermost `forward`. A local subscriber handler that re-drives a Put
        // to itself calls back into `forward` (this same method) at depth >= 2,
        // where `dispatch_local_subscribers` enqueues the busy-handler self-echo;
        // the outermost call drains it after the message loop (below).
        let outermost = self.forward_depth.get() == 0;
        self.forward_depth.set(self.forward_depth.get() + 1);
        for message in messages {
            // R311tt — §5.16 access control: consult the interceptor chain ONCE
            // here, ahead of the kind-dispatch (the relay-admission point). A
            // denied message is dropped — not counted as received data, not
            // forwarded — and witnessed by `interceptor_dropped`. The empty-chain fast
            // path (no ACL configured) makes this a single predicate read.
            if !self.admit_inbound(id, message) {
                self.interceptor_dropped
                    .set(self.interceptor_dropped.get() + 1);
                continue;
            }
            match message {
                NetworkMessage::Oam(oam) => match try_parse_linkstate_oam(oam) {
                    LinkstateOam::Decoded(list) => {
                        // Ingest, then re-flood the changed nodes onward to the
                        // OTHER faces (transitive propagation) — both inline, as
                        // zenoh floods link-states inline.
                        let changes = self.ingest_inbound_linkstate(id, list);
                        let _ = self.propagate(id, &changes);
                        // c3c-3 D3 — purge the subscription interest of every node
                        // the ingest detached from the mesh (the same
                        // pubsub_remove_node action as the link-down path,
                        // handle_oam hat/linkstate_peer/mod.rs:418-422).
                        self.purge_detached_interest(&changes.removed);
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
                    // R311y221 — preserve the received band on the transit
                    // re-forward: a relay hop re-emits on the SAME priority the
                    // frame arrived with (the priority sub-field of the ext_qos
                    // zenoh route_data copies onto egress, pubsub.rs), instead of
                    // re-clamping to DEFAULT.
                    self.forward_push(id, *reliable, *priority, push);
                    // R311y46 (§5.23 Phase 3a) — local-delivery: a Put matching a
                    // LOCALLY-hosted subscriber fires its handler. forward_push
                    // excludes self, so this is the self/local-delivery seam (in
                    // addition to the remote fan-out), not a double-delivery.
                    self.dispatch_local_subscribers(id, *reliable, push);
                    // R311y163 (D4 / C3a) — deliver to co-attached CLIENT
                    // subscribers whose keyexpr intersects this Push. Fires for a
                    // MESH-sourced Push (a peer's data reaching a co-attached client
                    // sub) AND a CLIENT-sourced Push (client A -> co-attached client
                    // B); the inbound face is excluded, and a mesh face is never in
                    // `client_subs`, so this neither echoes nor double-delivers.
                    self.deliver_to_client_subscribers(id, *reliable, *priority, push);
                    // R311y164 (D4b / C3b) — re-inject a co-attached CLIENT
                    // publisher's Push into the mesh as SELF-sourced (the transit
                    // `forward_push` above drops a client source, which is not a graph
                    // node). Gated on `is_client_face` so a MESH-sourced Push is NOT
                    // self-re-sourced — it rides `forward_push`'s transit re-forward.
                    if self.is_client_face(id) {
                        self.reinject_client_push(id, *reliable, *priority, push);
                    }
                }
                // c3c-3 — a sourced subscription declaration: a
                // DeclareSubscriber registers the source peer's interest, an
                // UndeclareSubscriber (c3c-3 debt A1) withdraws it; both then
                // re-flood along the source's tree on a real change.
                NetworkMessage::Declare(declare) => match &declare.body {
                    // c3c-3 B1 — a peer keyexpr alias declaration: record/drop it
                    // in the INBOUND face's link-local table (not re-flooded; each
                    // link negotiates its own aliases).
                    DeclareOwnedVariant::CodecZenohDeclKexpr(_)
                    | DeclareOwnedVariant::CodecZenohUndeclKexpr(_) => {
                        self.absorb_keyexpr_declaration(id, declare);
                    }
                    DeclareOwnedVariant::CodecZenohUndeclSubscriber(_) => {
                        // R311y163 (D4) — a CLIENT's graceful UndeclareSubscriber
                        // withdraws its leaf sub (union-gated mesh forget on the last
                        // source's departure); a MESH source's retraction withdraws
                        // its interest + re-floods along its tree.
                        if self.is_client_face(id) {
                            self.withdraw_client_subscription(id, declare);
                        } else {
                            self.forward_unsubscription(id, *reliable, declare);
                        }
                    }
                    // The query-plane twin of the subscriber declare: a sourced
                    // DeclareQueryable registers the source peer's queryable
                    // interest and re-floods along the source's tree, exactly as
                    // forward_subscription does for subscriptions (zenoh
                    // `declare_linkstatepeer_queryable`, `queries.rs`). Without
                    // this explicit arm it fell to the `_` subscriber catch-all
                    // and was silently dropped (its body is not a subscriber).
                    DeclareOwnedVariant::CodecZenohDeclQueryable(_) => {
                        // A CLIENT's DeclareQueryable is INGESTED as a co-attached leaf
                        // queryable (hosted in `client_qabls` + advertised into the mesh
                        // under SELF's zid); a MESH source's registers its interest +
                        // re-floods along its tree (the query twin of the DeclareSubscriber
                        // fork below).
                        if self.is_client_face(id) {
                            self.ingest_client_queryable(id, declare);
                        } else {
                            self.forward_queryable(id, *reliable, declare);
                        }
                    }
                    // UndeclareQueryable: the query-plane twin of the
                    // UndeclareSubscriber arm above. A sourced mesh retraction
                    // identifies the queryable by its keyexpr (id == 0), carried in
                    // the `ext_wire_expr` extension — now that the wz-codecs
                    // `UndeclQueryable` body models the ext chain (parity with
                    // `UndeclSubscriber` + zenoh
                    // `commons/zenoh-protocol/src/network/declare.rs:520-523`),
                    // `forward_queryable_undeclare` reads the keyexpr and withdraws
                    // the source's queryable interest (the whole-peer face-down
                    // purge stays the safety net for a departed peer). An id-only
                    // (no-ext) body carries no keyexpr and is a no-op inside the
                    // shared withdrawal — matched EXPLICITLY so it is not mis-routed
                    // to the subscriber catch-all below (its body is not a sub).
                    DeclareOwnedVariant::CodecZenohUndeclQueryable(_) => {
                        // A CLIENT's UndeclareQueryable withdraws its hosted queryable
                        // (downgrade-or-retract the self advert via the shared seam); a
                        // MESH source's withdraws its interest + re-floods (the query twin
                        // of the UndeclSubscriber fork above). A client undeclare is ID-ONLY
                        // (no ext_keyexpr); withdraw_client_queryable resolves the ke BY ID
                        // (R311y178 id-map — was a no-op that left the advert stale).
                        if self.is_client_face(id) {
                            self.withdraw_client_queryable(id, declare);
                        } else {
                            self.forward_queryable_undeclare(id, *reliable, declare);
                        }
                    }
                    // A DeclareSubscriber (the subscriber catch-all): a CLIENT's is
                    // INGESTED as a co-attached leaf sub (R311y163 / D4 — recorded in
                    // `client_subs` + advertised into the mesh under SELF's zid); a
                    // MESH source's registers its interest + re-floods along its tree.
                    _ => {
                        if self.is_client_face(id) {
                            self.ingest_client_subscription(id, declare);
                        } else {
                            self.forward_subscription(id, *reliable, declare);
                        }
                    }
                },
                // A routed Query: relay it toward the matching queryables along
                // the querier's tree (the query-plane twin of the data Push),
                // recording a pending-query return entry per outbound face.
                NetworkMessage::Request(request) => {
                    self.forward_request(id, *reliable, request);
                }
                // A queryable's Reply: route it BACK toward the querier via the
                // pending-query table (atom 3) — the reverse of the forward hop.
                NetworkMessage::Response(response) => {
                    self.forward_response(id, *reliable, response);
                }
                // The end-of-replies marker: free this BRANCH's pending entry;
                // the final routes back only when it was the fan's LAST branch
                // (the last-out gate).
                NetworkMessage::ResponseFinal(response_final) => {
                    self.forward_response_final(id, *reliable, response_final);
                }
                // A client's Interest solicitation (the zenoh-1.x write-filter
                // handshake): answer a CLIENT face with the CURRENT declarations
                // this peer holds + a DeclareFinal, so a pico publisher/querier
                // behind THIS peer deactivates its write-filter WHEN wz holds a
                // matching mesh or self-local declaration (the same reverse-data
                // black-hole the router-hat closed in R311y141 — the peer
                // forwarder previously DROPPED the Interest here, `_ => {}`). Mesh
                // peers/routers solicit nothing (proactive link-state flood), so
                // respond_to_interest gates the declaration dump on
                // `whatami == Client`. See its doc for the scope (CURRENT-only;
                // mesh + self-local, not a co-attached client's sub).
                NetworkMessage::Interest(interest) => {
                    self.respond_to_interest(id, interest);
                }
                _ => {}
            }
        }
        // #3-c (R311y167) — redeliver queued self-echoes at the outermost `forward`,
        // WHILE still at depth 1 (BEFORE the decrement) so a handler re-driving a Put
        // during redelivery re-enters at depth 2 and does NOT re-trigger the drain
        // (its `outermost` is false). Bounded per call (`SELF_ECHO_QUEUE_CAP`); any
        // still-queued remainder rides the next `forward`, spreading work across
        // ticks like zenoh's receiver-side channel drain.
        if outermost {
            self.drain_sub_redelivery();
            self.drain_query_redelivery();
        }
        self.forward_depth.set(self.forward_depth.get() - 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_impl::TokioRuntime;
    use crate::test_fixtures::{recording_actions, RecordingLinkDriver};
    use sce_forge_runtime::codec::{SceBytes, SceString};
    #[cfg(feature = "access-acl")]
    use wz_access_control::{AclConfig, AclMessage, AclRule, Permission, SubjectSelector};
    use wz_codecs::linkstate::LinkstateOwned;
    use wz_codecs::linkstate_link::LinkstateLink;
    use wz_codecs::locator::LocatorOwned;
    use wz_codecs::wireexpr::WireexprOwnedVariant;
    use wz_routing_graph::AutoConnectStrategy;
    use wz_runtime_core::runtime::Runtime;

    fn zid(b: u8) -> Zid {
        Zid::from_slice(&[b, b, b, b])
    }

    /// A recording-actions face whose remote peer zid is `peer`, so `register`
    /// connects it in the graph — the production face-up path (a face with no
    /// zid is held but not graph-connected). Returns the sink so a test can
    /// assert the frames the face received.
    fn peer_face(peer: Zid) -> (Arc<SessionLinkActions>, Arc<RecordingLinkDriver>) {
        let (actions, sink) = recording_actions();
        // the session-layer peer_zid is raw bytes (Vec<u8>); the driver maps it
        // to a routing `Zid` on register, so a test sets the raw form here.
        TokioRuntime::with_mutex_mut(&actions.remote_peer_zid, |s| {
            *s = Some(peer.as_slice().to_vec())
        });
        (actions, sink)
    }

    /// A peer face (as [`peer_face`]) that additionally records the remote's
    /// WhatAmI as the raw 2-bit INIT wire form, so a test can assert the role
    /// `register` threads into the graph (R311td "F1").
    fn peer_face_whatami(
        peer: Zid,
        wire_whatami: u8,
    ) -> (Arc<SessionLinkActions>, Arc<RecordingLinkDriver>) {
        let (actions, sink) = peer_face(peer);
        TokioRuntime::with_mutex_mut(&actions.peer_whatami, |s| *s = Some(wire_whatami));
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
                zid: Some(SceBytes::from_slice(zid(node).as_slice()).unwrap()),
                whatami: Some(2),
                num_locators: None,
                locators: None,
                links_len: 0,
                links: Vec::<LinkstateLink>::new(),
                weights: None,
            }],
        }
    }

    /// Ingest on the registered neighbour 0xAA's face (`FaceId(0)`) a 3-entry
    /// flood that DISCOVERS a distant peer `node` (role `whatami_api`, advertising
    /// `locs`): reachable `self_z` <-> 0xAA <-> `node`, so it survives the
    /// detached-node prune and surfaces as a `changes.new` discovery the
    /// autoconnect emit keys on. `node`'s own FULL entry is listed FIRST (the
    /// natural new-before-linker flood shape — the role gate then reads its
    /// whatami; the graph also recovers a placeholder's whatami on the update
    /// path, so this order is for clarity, not correctness). psid 0 = self (a
    /// stale, low-sn entry that only teaches the psid->zid mapping), psid 1 =
    /// 0xAA, `psid_node` = the discovered node.
    fn discover_distant(
        fwd: &LinkstateForwarder,
        self_z: u8,
        node: u8,
        whatami_api: u8,
        locs: &[&str],
        psid_node: u64,
        sn: u64,
    ) {
        let mut node_entry = entry(psid_node, sn, node, &[1]); // node -> 0xAA (psid 1)
        node_entry.whatami = Some(whatami_api);
        node_entry.num_locators = Some(locs.len() as u64);
        node_entry.locators = Some(
            locs.iter()
                .map(|s| LocatorOwned {
                    locator_len: s.len() as u64,
                    locator: SceString::from_view(s).unwrap(),
                })
                .collect(),
        );
        fwd.ingest_inbound_linkstate(
            FaceId(0),
            list(vec![
                entry(0, 1, self_z, &[]),            // self mapping (stale-gated)
                node_entry,                          // the distant node FIRST
                entry(1, sn, 0xAA, &[0, psid_node]), // 0xAA -> self(0) + node
            ]),
        );
    }

    /// The zenoh peer default autoconnect matcher (router|peer), under the
    /// strategy a test picks. The policy's own zid must equal the driver's self
    /// zid for the `GreaterZid` tie-break to compare against the right operand.
    fn autoconnect_policy(self_zid: Zid, strategy: AutoConnectStrategy) -> AutoConnect {
        AutoConnect::new(self_zid, WhatAmIMatcher::empty().router().peer(), strategy)
    }

    #[test]
    fn autoconnect_emits_a_dial_intent_for_an_admitted_discovered_peer() {
        // A5b: with autoconnect enabled (router|peer, Always), a peer the ingest
        // discovers (a `changes.new` node advertising locators + a peer role) is
        // emitted as a dial-intent carrying its zid + locators.
        let fwd = LinkstateForwarder::new(zid(0x01), WhatAmI::Peer);
        let mut rx =
            fwd.enable_autoconnect(autoconnect_policy(zid(0x01), AutoConnectStrategy::Always));
        let (face, _sink) = peer_face(zid(0xAA));
        fwd.register(FaceId(0), &face);
        // 0xBB is a 2-hop peer relayed by 0xAA: new, role peer, with a locator.
        discover_distant(
            &fwd,
            0x01,
            0xBB,
            WhatAmI::Peer.to_api(),
            &["tcp/10.0.0.187:7447"],
            3,
            5,
        );
        let intent = rx
            .try_recv()
            .expect("a dial-intent for the discovered peer");
        assert_eq!(intent.zid, zid(0xBB).as_slice().to_vec());
        assert_eq!(intent.locators, vec!["tcp/10.0.0.187:7447".to_string()]);
        assert!(
            rx.try_recv().is_err(),
            "exactly one intent for one new peer"
        );
    }

    #[test]
    fn a_disabled_policy_emits_no_intent_even_with_the_channel_wired() {
        // The signature-stable default: a disabled policy (empty matcher) never
        // dials, even for an admitted-role peer with locators and a live channel.
        let fwd = LinkstateForwarder::new(zid(0x01), WhatAmI::Peer);
        let mut rx = fwd.enable_autoconnect(AutoConnect::disabled(zid(0x01)));
        let (face, _sink) = peer_face(zid(0xAA));
        fwd.register(FaceId(0), &face);
        discover_distant(
            &fwd,
            0x01,
            0xBB,
            WhatAmI::Peer.to_api(),
            &["tcp/10.0.0.187:7447"],
            3,
            5,
        );
        assert!(rx.try_recv().is_err(), "a disabled policy never dials");
    }

    #[test]
    fn a_role_unadmitted_discovered_peer_emits_no_intent() {
        // The channel is wired and the policy enabled, but the discovered peer's
        // role (client) is outside the router|peer matcher -> no dial-intent.
        let fwd = LinkstateForwarder::new(zid(0x01), WhatAmI::Peer);
        let mut rx =
            fwd.enable_autoconnect(autoconnect_policy(zid(0x01), AutoConnectStrategy::Always));
        let (face, _sink) = peer_face(zid(0xAA));
        fwd.register(FaceId(0), &face);
        // 0xCC is discovered with a CLIENT role (api byte 4) + a locator.
        discover_distant(
            &fwd,
            0x01,
            0xCC,
            WhatAmI::Client.to_api(),
            &["tcp/10.0.0.204:7447"],
            3,
            5,
        );
        assert!(rx.try_recv().is_err(), "a client is not a dial candidate");
    }

    #[test]
    fn greater_zid_strategy_emits_only_when_self_zid_is_greater() {
        // GreaterZid double-dial avoidance, observed through the emit: self 0x05
        // dials a discovered LESSER-zid peer (0x03) but defers on a GREATER one
        // (0x09) -- so a mutually-discovering pair has exactly one dialer.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let mut rx = fwd.enable_autoconnect(autoconnect_policy(
            zid(0x05),
            AutoConnectStrategy::GreaterZid,
        ));
        let (face, _sink) = peer_face(zid(0xAA));
        fwd.register(FaceId(0), &face);
        discover_distant(
            &fwd,
            0x05,
            0x03,
            WhatAmI::Peer.to_api(),
            &["tcp/10.0.0.3:7447"],
            3,
            5,
        );
        assert!(
            rx.try_recv().is_ok(),
            "greater self zid dials the lesser-zid peer"
        );
        // A second discovery (distinct psid 4 / higher sn) of a GREATER-zid peer.
        discover_distant(
            &fwd,
            0x05,
            0x09,
            WhatAmI::Peer.to_api(),
            &["tcp/10.0.0.9:7447"],
            4,
            6,
        );
        assert!(
            rx.try_recv().is_err(),
            "lesser self zid defers to the greater-zid peer"
        );
    }

    #[test]
    fn face_up_connects_neighbour() {
        let fwd = LinkstateForwarder::new(zid(0x01), WhatAmI::Peer);
        let (face, _sink) = peer_face(zid(0xAA));
        fwd.register(FaceId(7), &face);
        // self + the neighbour node.
        assert_eq!(fwd.net.borrow().node_count(), 2);
    }

    // (the wire<->role mapping itself is tested at its SSOT home, `wz-codecs`
    // `whatami` — the driver no longer owns a conversion fn to test.)

    #[test]
    fn register_threads_real_handshake_whatami() {
        // R311td "F1": a ROUTER/PEER neighbour's real role (not a hardcoded peer)
        // lands on its graph node — the gossip-policy/autoconnect prerequisite.
        // R311y163 (D4, diagnose-first for the register Client-tier branch): a CLIENT
        // is a LEAF, held WITHOUT a graph node (never `add_link`'d), so its role is
        // read from the face, never the graph. This CLIENT half FAILED before D4
        // (`get_node(0xBB)` was `Some`, a ghost isolated vertex).
        let fwd = LinkstateForwarder::new(zid(0x01), WhatAmI::Peer);
        let (router, _r) = peer_face_whatami(zid(0xAA), 0); // wire 0 = Router
        let (client, _c) = peer_face_whatami(zid(0xBB), 2); // wire 2 = Client
        fwd.register(FaceId(1), &router);
        fwd.register(FaceId(2), &client);
        assert_eq!(
            fwd.net.borrow().get_node(&zid(0xAA)).unwrap().whatami,
            Some(WhatAmI::Router)
        );
        assert!(
            fwd.net.borrow().get_node(&zid(0xBB)).is_none(),
            "a client is a leaf face, never a link-state graph node (D4)"
        );
        assert!(
            fwd.faces
                .borrow()
                .get(&FaceId(2))
                .is_some_and(|s| s.link.is_none()),
            "the client face is HELD (its send seam kept) without a graph link"
        );
    }

    #[test]
    fn register_without_handshake_whatami_falls_back_to_peer() {
        // A face whose handshake role never surfaced (the pre-F1 path / a peer
        // mesh) keeps the WhatAmI::Peer default, so an all-peer deployment is
        // behaviour-unchanged by F1.
        let fwd = LinkstateForwarder::new(zid(0x01), WhatAmI::Peer);
        let (face, _sink) = peer_face(zid(0xAA)); // no whatami slot set
        fwd.register(FaceId(7), &face);
        assert_eq!(
            fwd.net.borrow().get_node(&zid(0xAA)).unwrap().whatami,
            Some(WhatAmI::Peer)
        );
    }

    // The full risky chain through the REAL handshake (not a poked slot): a wire
    // InitSyn -> handle_inbound (captures the raw 2-bit wire role) -> register
    // (whatami_from_wire maps wire->API) -> Node.whatami holds the API-form role.
    // Closes the gap between the session-core slot-capture test and the slot->node
    // tests above; gated on the Init codec that the capture path needs.
    #[cfg(feature = "codec-init-body")]
    #[test]
    fn register_records_whatami_end_to_end_through_handle_inbound() {
        let fwd = LinkstateForwarder::new(zid(0x01), WhatAmI::Peer);
        let (actions, _sink) = recording_actions();
        let initsyn = vec![
            0x40 | 0x01, // FLAG_T_INIT_S | T_MID_INIT
            0x05,
            0x30, // version, cbyte (whatami Router wire 0, zid_len 4)
            0xAA,
            0xAA,
            0xAA,
            0xAA, // zid -> zid(0xAA)
            0x00,
            0x00,
            0x00, // sn_res, batch_size
        ];
        actions.handle_inbound(&initsyn).expect("InitSyn parses");
        fwd.register(FaceId(7), &actions);
        assert_eq!(
            fwd.net.borrow().get_node(&zid(0xAA)).unwrap().whatami,
            Some(WhatAmI::Router),
            "a router peer's INIT role is captured and recorded end-to-end"
        );
    }

    #[test]
    fn inbound_linkstate_grows_the_graph_and_counts() {
        let fwd = LinkstateForwarder::new(zid(0x01), WhatAmI::Peer);
        let (face, _sink) = peer_face(zid(0xAA));
        fwd.register(FaceId(7), &face);
        // The neighbour A floods a consistent list: A (psid 1) advertises self
        // (psid 0) and a far node B (psid 2). B is reachable THROUGH A, so the
        // reachability prune (D3) keeps it — a B announced with no advertiser
        // leading back to self would be pruned as detached.
        fwd.ingest_inbound_linkstate(
            FaceId(7),
            list(vec![
                entry(0, 1, 0x01, &[]),
                entry(1, 5, 0xAA, &[0, 2]),
                entry(2, 5, 0xBB, &[1]),
            ]),
        );
        assert_eq!(fwd.ingested(), 1);
        assert!(fwd.net.borrow().get_node(&zid(0xBB)).is_some());
    }

    #[test]
    fn inbound_from_unknown_face_is_dropped() {
        let fwd = LinkstateForwarder::new(zid(0x01), WhatAmI::Peer);
        // no face registered for id 9.
        fwd.ingest_inbound_linkstate(FaceId(9), list_with_node(11, 5, 0xBB));
        assert_eq!(fwd.ingested(), 0);
        assert!(fwd.net.borrow().get_node(&zid(0xBB)).is_none());
    }

    #[test]
    fn face_down_disconnects_neighbour() {
        let fwd = LinkstateForwarder::new(zid(0x01), WhatAmI::Peer);
        let (face, _sink) = peer_face(zid(0xAA));
        fwd.register(FaceId(7), &face);
        assert_eq!(fwd.net.borrow().node_count(), 2);
        fwd.deregister(FaceId(7));
        // the link mapping is gone; a later inbound on that face is dropped.
        fwd.ingest_inbound_linkstate(FaceId(7), list_with_node(11, 5, 0xBB));
        assert_eq!(fwd.ingested(), 0);
    }

    #[test]
    fn flood_self_links_changed_sends_to_every_face() {
        // the TX seam fan-out: a self link-state delta reaches every held face's
        // send seam (the OAM landing as one frame per face).
        let fwd = LinkstateForwarder::new(zid(0x01), WhatAmI::Peer);
        let (face_a, sink_a) = recording_actions();
        let (face_b, sink_b) = recording_actions();
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);

        let sent = fwd.flood_self_links_changed().expect("flood self");
        assert_eq!(sent, 2, "flooded both held faces");
        assert_eq!(sink_a.frame_count(), 1, "face A received the link-state");
        assert_eq!(sink_b.frame_count(), 1, "face B received the link-state");
    }

    #[test]
    fn gossip_skips_a_client_face_but_reaches_a_peer() {
        // zenoh's per-target gossip gate (`send_on_link`): a peer gossips its
        // link-state to router|peer faces only, so a CLIENT face is skipped
        // entirely while a PEER face receives it. An all-peer deployment hits the
        // peer arm for every face, so the gate is behaviour-neutral there.
        let fwd = LinkstateForwarder::new(zid(0x01), WhatAmI::Peer);
        let (peer, peer_sink) = peer_face_whatami(zid(0xAA), 1); // wire 1 = Peer
        let (client, client_sink) = peer_face_whatami(zid(0xBB), 2); // wire 2 = Client
        fwd.register(FaceId(0), &peer);
        fwd.register(FaceId(1), &client);

        let sent = fwd.flood_self_links_changed().expect("flood self");
        assert_eq!(
            sent, 1,
            "only the peer face is in the gossip target (router|peer)"
        );
        assert!(
            peer_sink.frame_count() >= 1,
            "the peer face received the link-state"
        );
        assert_eq!(
            client_sink.frame_count(),
            0,
            "a client face never receives gossip (the router|peer target excludes it)"
        );
    }

    #[test]
    fn default_gossip_target_is_per_local_whatami() {
        // zenoh scouting.gossip.target default: a router or peer gossips to
        // router|peer; a client gossips to nobody (the empty set).
        let rp = WhatAmIMatcher::empty().router().peer();
        assert_eq!(default_gossip_target(WhatAmI::Router), rp);
        assert_eq!(default_gossip_target(WhatAmI::Peer), rp);
        assert_eq!(
            default_gossip_target(WhatAmI::Client),
            WhatAmIMatcher::empty(),
            "a client floods no link-state"
        );
    }

    #[test]
    fn default_autoconnect_matcher_is_per_local_whatami_and_differs_from_target() {
        // zenoh scouting.gossip.autoconnect default: a PEER autoconnects to
        // router|peer, but a ROUTER and a CLIENT autoconnect to NOBODY -- the
        // deliberate asymmetry vs gossip.target (where a router DOES gossip to
        // router|peer). A router that reused the target matcher here would wrongly
        // dial discovered peers; the twin keeps the two profiles distinct.
        let rp = WhatAmIMatcher::empty().router().peer();
        assert_eq!(default_autoconnect_matcher(WhatAmI::Peer), rp);
        assert_eq!(
            default_autoconnect_matcher(WhatAmI::Router),
            WhatAmIMatcher::empty(),
            "a router autoconnects to nobody (unlike its gossip TARGET)"
        );
        assert_eq!(
            default_autoconnect_matcher(WhatAmI::Client),
            WhatAmIMatcher::empty()
        );
        // The router profiles differ between the two defaults -- the bug the twin
        // prevents.
        assert_ne!(
            default_autoconnect_matcher(WhatAmI::Router),
            default_gossip_target(WhatAmI::Router)
        );
    }

    #[test]
    fn set_gossip_target_overrides_the_flood_gate() {
        // The config seam: the per-role default (a peer local -> router|peer)
        // floods a peer face; after set_gossip_target(empty) the same face is
        // gated out, the override a deploy uses to source the target per its
        // local whatami.
        let fwd = LinkstateForwarder::new(zid(0x01), WhatAmI::Peer);
        let (peer, peer_sink) = peer_face_whatami(zid(0xAA), 1); // wire 1 = Peer
        fwd.register(FaceId(0), &peer);
        fwd.set_gossip_target(WhatAmIMatcher::empty());
        // Clear the register-time flood (sent under the default target) so the
        // next flood isolates the override's effect.
        peer_sink.reset();
        let sent = fwd.flood_self_links_changed().expect("flood self");
        assert_eq!(sent, 0, "the empty gossip target gates out every face");
        assert_eq!(
            peer_sink.frame_count(),
            0,
            "the peer face received no gossip under the empty target"
        );
    }

    #[test]
    fn deregister_stops_flooding_a_face() {
        let fwd = LinkstateForwarder::new(zid(0x01), WhatAmI::Peer);
        let (face_a, sink_a) = recording_actions();
        fwd.register(FaceId(0), &face_a);
        fwd.deregister(FaceId(0));
        let sent = fwd
            .flood_self_links_changed()
            .expect("flood self after deregister");
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
        // D4 self-flood delta: A gets the MINIMAL 2-entry delta [B zid-only, self
        // links-only], NOT the full topology (which would also re-send A itself).
        let states = propagated_link_states(&sink_a.frame_bytes(0));
        assert_eq!(
            states.len(),
            2,
            "the delta is [neighbour B, self] -- A's own entry is NOT re-sent"
        );
        assert!(
            states[0].zid.is_some(),
            "B is announced zid-only (zid present)"
        );
        assert_eq!(
            states[0].links_len, 0,
            "B's entry carries no links (zid-only)"
        );
        assert!(
            states[1].zid.is_none(),
            "self is links-only (zid omitted) in the delta"
        );
    }

    #[test]
    fn register_relink_to_known_peer_floods_self_links_only() {
        // The was_new == false branch (zenoh add_link's `new` flag, network.rs:826):
        // a SECOND link to an ALREADY-KNOWN peer does NOT re-announce the neighbour
        // -- existing faces get only self's links-only entry, not the 2-entry
        // [neighbour, self] delta. (Each add_link mints a new link id but the graph
        // node is shared, so the second register sees the peer already present.)
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A)); // an existing witness
        let (face_b0, sink_b0) = peer_face(zid(0x0B)); // B's first link
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b0); // B is NEW to the graph here
        sink_a.reset();
        sink_b0.reset();
        let (face_b1, _b1) = peer_face(zid(0x0B)); // a SECOND link to the same B
        fwd.register(FaceId(2), &face_b1); // B already known -> not re-announced
        let states = propagated_link_states(&sink_a.frame_bytes(0));
        assert_eq!(
            states.len(),
            1,
            "a known-peer relink re-sends only self's links, no neighbour entry"
        );
        assert!(states[0].zid.is_none(), "self links-only (zid omitted)");
        // zenoh excludes EVERY link with link.zid == neighbour from the delta
        // (network.rs:864): B's FIRST face must get nothing (it learns self's
        // change on the new face's full bootstrap), not a redundant self-links frame.
        assert_eq!(
            sink_b0.frame_count(),
            0,
            "B's other link (same zid) is excluded from the relink delta"
        );
    }

    #[test]
    fn deregister_event_floods_self_to_surviving_faces() {
        // D2b — when a routing face drops, self's own link-state changed (it lost a
        // neighbour, sn bumped), so self floods the update to the SURVIVING faces at
        // once, so they drop the dead link from their topology now (zenoh
        // remove_link's send_on_links) rather than at a periodic tick.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
        // D4 self-flood delta: A gets the MINIMAL 1-entry [self links-only] delta,
        // NOT the full topology (which would re-send self + A). A's own
        // remove_detached_nodes prunes the now-gone B.
        let states = propagated_link_states(&sink_a.frame_bytes(0));
        assert_eq!(states.len(), 1, "remove_link delta is self's entry alone");
        assert!(states[0].zid.is_none(), "self is links-only (zid omitted)");
    }

    #[test]
    fn propagate_re_floods_changed_nodes_to_other_faces() {
        // an UPDATED node that arrived on face 0 is re-flooded to face 1, never
        // back to its source (transitive propagation; zenoh `network.rs:661`
        // excludes src for the `updated` half). The `new` half is NOT excluded
        // there — see `propagate_sends_new_nodes_back_to_the_source_face`.
        let fwd = LinkstateForwarder::new(zid(0x0B), WhatAmI::Peer);
        let (source, source_sink) = recording_actions();
        let (other, other_sink) = recording_actions();
        fwd.register(FaceId(0), &source);
        fwd.register(FaceId(1), &other);

        // the self node is always in the graph, so it resolves in build.
        let changes = Changes {
            updated: vec![zid(0x0B)],
            ..Default::default()
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
        let fwd = LinkstateForwarder::new(zid(0x0B), WhatAmI::Peer);
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
        let fwd = LinkstateForwarder::new(zid(0x0B), WhatAmI::Peer);
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
            ..Default::default()
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
    fn propagate_sends_new_nodes_back_to_the_source_face() {
        // R311y431 — zenoh `network.rs:659-666` withholds ONLY the `updated`
        // half from the source link (`:661` `link.zid != src`); `new` nodes ride
        // back out on it. The reason is not politeness, it is addressing: PSID
        // SPACE IS PER-SENDER, so the source advertised that node under ITS
        // numbering and still has no idea which psid WE will use for it. Without
        // this echo, our next self-entry that lists the node in `links` is
        // unresolvable on the source, and a real zenohd rejects that edge with
        // `unknown link mapping` (zenoh `network.rs:527-539`).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (source, source_sink) = peer_face(zid(0x0A));
        let (other, other_sink) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &source); // graph gains 0x0A
        fwd.register(FaceId(1), &other); // graph gains 0x0C
        source_sink.reset();
        other_sink.reset();

        // 0x0C is NEW and self (0x05) is UPDATED, both arriving on face 0.
        let changes = Changes {
            new: vec![zid(0x0C)],
            updated: vec![zid(0x05)],
            ..Default::default()
        };
        fwd.propagate(FaceId(0), &changes).expect("propagate");

        assert_eq!(
            source_sink.frame_count(),
            1,
            "the NEW node must ride back out on the source face"
        );
        let to_source = propagated_link_states(&source_sink.frame_bytes(0));
        assert_eq!(
            to_source.len(),
            1,
            "the source gets the new half ALONE — the updated half is withheld"
        );
        assert!(
            to_source[0].zid.is_some(),
            "the echoed new node must carry its zid; a links-only echo would \
             teach the source nothing about our psid numbering"
        );

        // The per-node exclusion still holds on the other face: C never receives
        // its own state, so it gets the updated half only.
        let to_other = propagated_link_states(&other_sink.frame_bytes(0));
        assert_eq!(to_other.len(), 1, "C gets the updated half only");
        assert!(
            to_other[0].zid.is_none(),
            "an updated node re-floods links-only"
        );
    }

    #[test]
    fn propagate_re_floods_new_full_and_updated_links_only() {
        // c3c-3 D4 — propagate must route `changes.new` into the FULL slot and
        // `changes.updated` into the LINKS-ONLY slot, in ONE list per face. The
        // face to a NON-involved peer (C) receives both halves; decoding its
        // frame proves the split landed on the wire (new keeps its zid, updated
        // omits it) and was not swapped.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (peer_a, _sa) = peer_face(zid(0x0A));
        let (peer_b, _sb) = peer_face(zid(0x0B));
        let (peer_c, sink_c) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &peer_a); // graph gains 0x0A
        fwd.register(FaceId(1), &peer_b); // graph gains 0x0B
        fwd.register(FaceId(2), &peer_c); // graph gains 0x0C
        sink_c.reset();

        // 0x0A is NEW (full), 0x0B is UPDATED (links-only). Source is an
        // unregistered face so C is not excluded.
        let changes = Changes {
            new: vec![zid(0x0A)],
            updated: vec![zid(0x0B)],
            ..Default::default()
        };
        fwd.propagate(FaceId(99), &changes).expect("propagate");

        let states = propagated_link_states(&sink_c.frame_bytes(0));
        assert_eq!(
            states.len(),
            2,
            "C's list carries both the new and updated node"
        );
        // new nodes are listed first (build_linkstate_split): full state.
        assert!(states[0].zid.is_some(), "the NEW node (0x0A) keeps its zid");
        assert_eq!(states[0].options & 0x01, 0x01, "NEW sets the P flag");
        // updated node second: links-only, no zid.
        assert!(
            states[1].zid.is_none(),
            "the UPDATED node (0x0B) omits its zid"
        );
        assert_eq!(states[1].options & 0x01, 0, "UPDATED clears the P flag");
    }

    #[test]
    fn register_bootstraps_the_new_neighbour() {
        // R311rf — a face with a routing zid is bootstrapped on register:
        // the forwarder immediately advertises its own link-state to it, so a
        // freshly-up neighbour converges without waiting for the next tick.
        let fwd = LinkstateForwarder::new(zid(0x0B), WhatAmI::Peer);
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
        let fwd = LinkstateForwarder::new(zid(0x0B), WhatAmI::Peer);
        let (face, sink) = recording_actions();
        fwd.register(FaceId(1), &face);
        assert_eq!(
            sink.frame_count(),
            0,
            "a zid-less held face is not bootstrapped"
        );
    }

    #[test]
    fn register_self_zid_face_is_held_without_a_link() {
        // OBLIGATION-3 self-zid parity (mirrors RouterForwarder): a face whose
        // routing zid IS self's own zid is HELD without a graph link — adding it
        // would flood a spurious self-loop (psid 0) + sn bump; the guard drops it
        // to the held-without-link branch, so no self-loop is advertised.
        let fwd = LinkstateForwarder::new(zid(0x01), WhatAmI::Peer);
        let (face, sink) = peer_face(zid(0x01)); // routing zid == self
        fwd.register(FaceId(1), &face);
        assert_eq!(
            sink.frame_count(),
            0,
            "a self-connect face is not bootstrapped (held without a link)"
        );
        assert_eq!(
            fwd.net.borrow().node_count(),
            1,
            "no self-loop neighbour added to the net (only self)"
        );
    }

    // ── R311y163 (D4) — the peer's co-attached CLIENT data plane ─────────────

    /// Feed a co-attached CLIENT's `DeclareSubscriber` through the dispatch seam
    /// (`forward`), so the is_client branch routes it to `ingest_client_subscription`
    /// (NOT the mesh `forward_subscription`). The `face` must be registered with a
    /// Client WhatAmI (`peer_face_whatami(_, 2)`).
    fn client_declare_sub(fwd: &LinkstateForwarder, face: FaceId, id: u64, keyexpr: &str) {
        let declare = build_declare_subscriber(id, 0, Some(keyexpr)).expect("build sub");
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Declare(Box::new(declare))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(face, IterationEvent::Poll(&outcome));
    }

    /// Feed a client's graceful `UndeclareSubscriber` — ID-ONLY
    /// (`build_undeclare_subscriber(id)`, no ext_keyexpr, the form a real wz/pico client
    /// sends), so the withdraw resolves the ke by id (the R311y178 id-map).
    fn client_undeclare_sub(fwd: &LinkstateForwarder, face: FaceId, id: u64) {
        let declare = build_undeclare_subscriber(id);
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Declare(Box::new(declare))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(face, IterationEvent::Poll(&outcome));
    }

    #[test]
    fn a_client_sub_registers_under_self_and_advertises_to_a_mesh_child() {
        // D4 / BLOCKER-1 fix (FAILS before D4: a client sub was mis-registered under
        // the client's own zid and never re-flooded). A pico-style CLIENT of this
        // peer declares a sub; it lands in `client_subs` AND is advertised into the
        // mesh under SELF's zid, so a mesh child learns to route matching data back.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (peer_b, sink_b) = peer_face(zid(0x0B)); // a real mesh child
        let (client, _c) = peer_face_whatami(zid(0x0C), 2); // a CLIENT leaf
        fwd.register(FaceId(0), &peer_b);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0B, 0x05); // edge S<->B
        sink_b.reset();

        client_declare_sub(&fwd, FaceId(1), 1, "demo/**");

        assert_eq!(
            fwd.client_subs_seen(),
            1,
            "the client sub is installed in client_subs"
        );
        assert!(
            fwd.interested("demo/**").contains(&zid(0x05)),
            "the client sub is advertised into the mesh under SELF's zid"
        );
        assert_eq!(
            sink_b.frame_count(),
            1,
            "the mesh child learns the sub (a self-sourced DeclareSubscriber)"
        );
        assert_eq!(
            forwarded_declare_keyexpr(&sink_b.frame_bytes(0)).as_deref(),
            Some("demo/**")
        );
    }

    #[test]
    fn a_client_push_is_delivered_to_a_co_attached_client_subscriber() {
        // D4 / C3a (FAILS before D4: the peer had no client delivery). A MESH Push
        // reaches a co-attached CLIENT subscriber whose WILDCARD sub intersects the
        // published key — the peer-tier deliver_to_client_subscribers.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (peer_a, _sink_a) = peer_face(zid(0x0A)); // the mesh Push source
        let (client_sub, sink_sub) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &peer_a);
        fwd.register(FaceId(1), &client_sub);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A
        client_declare_sub(&fwd, FaceId(1), 1, "demo/**");
        sink_sub.reset();

        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(data_push()))], // demo/data
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&outcome));

        assert_eq!(
            sink_sub.frame_count(),
            1,
            "the co-attached client sub (demo/**) receives the mesh Push demo/data (C3a)"
        );
        assert_eq!(
            forwarded_keyexpr(&sink_sub.frame_bytes(0)).as_deref(),
            Some("demo/data"),
            "delivered with the published literal key (reliteralized)"
        );
    }

    #[test]
    fn a_departing_client_purges_client_subs_and_withdraws_the_advertisement() {
        // D4 (FAILS before D4: deregister had no client_subs purge). A client face
        // going down purges its subs AND — as the last backer — withdraws the mesh
        // advertisement (a sourced UndeclareSubscriber to the mesh child).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (peer_b, sink_b) = peer_face(zid(0x0B));
        let (client, _c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &peer_b);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0B, 0x05);
        client_declare_sub(&fwd, FaceId(1), 1, "demo/**");
        assert_eq!(fwd.client_subs_seen(), 1);
        sink_b.reset();

        fwd.deregister(FaceId(1));

        assert_eq!(
            fwd.client_subs_seen(),
            0,
            "the departed client's subs are purged from client_subs"
        );
        assert!(
            !fwd.interested("demo/**").contains(&zid(0x05)),
            "the last backer's departure withdraws the mesh advertisement"
        );
        assert_eq!(
            sink_b.frame_count(),
            1,
            "the mesh child receives the sourced UndeclareSubscriber"
        );
    }

    #[test]
    fn a_graceful_undeclare_from_a_client_withdraws_the_advertisement() {
        // D4 — the graceful (UndeclareSubscriber) twin of the face-down purge: a
        // client explicitly retracts; as the last backer, the mesh advertisement is
        // withdrawn + the forget floods to the mesh child.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (peer_b, sink_b) = peer_face(zid(0x0B));
        let (client, _c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &peer_b);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0B, 0x05);
        client_declare_sub(&fwd, FaceId(1), 1, "demo/**");
        assert_eq!(fwd.client_subs_seen(), 1);
        sink_b.reset();

        client_undeclare_sub(&fwd, FaceId(1), 1);

        assert_eq!(fwd.client_subs_seen(), 0, "the client sub is withdrawn");
        assert!(
            !fwd.interested("demo/**").contains(&zid(0x05)),
            "the last backer's retraction withdraws the mesh advertisement"
        );
        assert_eq!(
            sink_b.frame_count(),
            1,
            "the mesh child receives the sourced UndeclareSubscriber"
        );
    }

    #[test]
    fn a_self_native_undeclare_keeps_a_surviving_client_subscribers_advertisement() {
        // D4 union-refcount — the decisive BLACKHOLE guard. This peer co-hosts BOTH a
        // self-native local sub AND a co-attached CLIENT sub on the SAME keyexpr,
        // collapsed onto one (ke, self_zid) advertise slot. The self-native undeclare
        // must NOT withdraw the shared advertisement while the client still backs it;
        // only the LAST backer's departure withdraws + floods the forget.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (peer_b, sink_b) = peer_face(zid(0x0B));
        let (client, _c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &peer_b);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0B, 0x05);
        fwd.declare_subscription("demo/**")
            .expect("self-native sub"); // source 1
        client_declare_sub(&fwd, FaceId(1), 1, "demo/**"); // source 2 (same ke, one slot)
        sink_b.reset();

        // The self-native source retracts while the client still subscribes.
        fwd.undeclare_subscription("demo/**")
            .expect("self-native undeclare");
        assert_eq!(
            sink_b.frame_count(),
            0,
            "a surviving client sub keeps the shared advertise — NO withdraw flood (blackhole guard)"
        );
        assert!(
            fwd.interested("demo/**").contains(&zid(0x05)),
            "the mesh advertisement survives while the client still backs it"
        );

        // Now the LAST backer (the client) departs -> the withdraw finally floods.
        fwd.deregister(FaceId(1));
        assert_eq!(
            sink_b.frame_count(),
            1,
            "the last backer's departure withdraws the shared advertisement"
        );
        assert!(!fwd.interested("demo/**").contains(&zid(0x05)));
    }

    #[test]
    fn two_clients_on_the_same_ke_share_one_advertise_and_survive_one_departure() {
        // D4 union-refcount among CLIENTS: two client faces subscribe the SAME ke ->
        // ONE mesh advertise (the 2nd ingest is SILENT, `subs.register` false); one
        // client departing KEEPS the advertise (the other still backs it via
        // `any_client_subscribes`); only the LAST backer's departure withdraws it.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (peer_b, sink_b) = peer_face(zid(0x0B));
        let (client1, _c1) = peer_face_whatami(zid(0x0C), 2);
        let (client2, _c2) = peer_face_whatami(zid(0x0D), 2);
        fwd.register(FaceId(0), &peer_b);
        fwd.register(FaceId(1), &client1);
        fwd.register(FaceId(2), &client2);
        advertise_link_back(&fwd, FaceId(0), 0x0B, 0x05);
        client_declare_sub(&fwd, FaceId(1), 1, "demo/**"); // first backer -> advertise
        sink_b.reset();
        client_declare_sub(&fwd, FaceId(2), 1, "demo/**"); // second backer -> SILENT

        assert_eq!(fwd.client_subs_seen(), 2, "both client subs recorded");
        assert_eq!(
            sink_b.frame_count(),
            0,
            "the second client on the same ke does NOT re-flood the advertise"
        );

        // client1 departs -> client2 still backs demo/** -> the advertise SURVIVES.
        fwd.deregister(FaceId(1));
        assert!(
            fwd.interested("demo/**").contains(&zid(0x05)),
            "a surviving client keeps the shared advertise"
        );
        assert_eq!(
            sink_b.frame_count(),
            0,
            "one of two client backers departing does not withdraw"
        );

        // client2 (the LAST backer) departs -> the advertise is withdrawn + flooded.
        fwd.deregister(FaceId(2));
        assert!(!fwd.interested("demo/**").contains(&zid(0x05)));
        assert_eq!(
            sink_b.frame_count(),
            1,
            "the last backer's departure withdraws the shared advertise"
        );
    }

    #[test]
    fn an_id_reused_for_a_new_ke_displaces_and_retracts_the_old_client_sub_advert() {
        // R311y178 id-map displacement: a client RE-USES declaration id 1 for a DIFFERENT
        // ke WITHOUT an intervening undeclare -> the old ke's advert is retracted (it was
        // the last holder) + the new ke advertised. The keyexpr-SET twin structurally could
        // not detect this (one id maps one ke); the id-map makes it detectable, mirror of
        // the token plane's ingest_client_token displacement.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (peer_b, _sb) = peer_face(zid(0x0B));
        let (client, _c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &peer_b);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0B, 0x05);
        client_declare_sub(&fwd, FaceId(1), 1, "demo/a");
        assert!(
            fwd.interested("demo/a").contains(&zid(0x05)),
            "demo/a advertised under self"
        );

        // Re-use id 1 for demo/b (no undeclare of demo/a first).
        client_declare_sub(&fwd, FaceId(1), 1, "demo/b");

        assert!(
            fwd.interested("demo/b").contains(&zid(0x05)),
            "demo/b now advertised (the new mapping for id 1)"
        );
        assert!(
            !fwd.interested("demo/a").contains(&zid(0x05)),
            "demo/a's advert was RETRACTED — id 1 no longer maps it (displacement)"
        );
        assert_eq!(fwd.client_subs_seen(), 1, "id 1 holds exactly one ke");
    }

    #[test]
    fn an_id_reused_for_a_new_ke_displaces_and_retracts_the_old_client_qabl_advert() {
        // R311y178 id-map displacement, QABL plane (the info-carrying twin — the retract
        // re-derives the merged QueryableInfo): a client RE-USES declaration id 1 for a
        // DIFFERENT ke without an undeclare -> the old ke's advert is retracted (last
        // holder) + the new ke advertised.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (peer_b, _sb) = peer_face(zid(0x0B));
        let (client, _c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &peer_b);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0B, 0x05);
        client_declare_qabl(&fwd, FaceId(1), 1, "demo/a", true);
        assert!(
            fwd.interested_queryables("demo/a").contains(&zid(0x05)),
            "demo/a advertised under self"
        );

        // Re-use id 1 for demo/b (no undeclare of demo/a first).
        client_declare_qabl(&fwd, FaceId(1), 1, "demo/b", true);

        assert!(
            fwd.interested_queryables("demo/b").contains(&zid(0x05)),
            "demo/b now advertised (the new mapping for id 1)"
        );
        assert!(
            !fwd.interested_queryables("demo/a").contains(&zid(0x05)),
            "demo/a's advert was RETRACTED — id 1 no longer maps it (displacement)"
        );
        assert_eq!(fwd.client_qabls_seen(), 1, "id 1 holds exactly one qabl");
    }

    #[test]
    fn a_client_that_pubs_and_subs_the_same_ke_is_not_echoed_its_own_sub() {
        // D4 self-echo guard (FAILS with origin=None): a co-attached CLIENT that
        // holds a FUTURE publish-interest on demo/key AND then subscribes demo/key
        // must NOT be pushed its OWN DeclareSubscriber back (which would open its
        // write-filter against a phantom self-subscriber). `ingest_client_subscription`
        // passes `origin = Some(inbound)`, excluding the subscribing client — zenoh
        // `src_face != dst_face` / the router's `push_future_subscription(_, inbound)`.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (mesh, _sm) = peer_face(zid(0x0A));
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &mesh);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        // The client solicits a C+F SUBSCRIBERS interest on demo/key (pub-before-sub),
        // no matching sub yet -> only a DeclareFinal; it now holds a FUTURE interest.
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(8, "demo/key", true, true, true, false, true),
        );
        sink_c.reset();

        // The SAME client now declares a subscriber on demo/key.
        client_declare_sub(&fwd, FaceId(1), 1, "demo/key");

        assert_eq!(
            fwd.future_pushes_seen(),
            0,
            "the subscribing client is NOT pushed its own sub (origin exclusion)"
        );
        assert_eq!(
            sink_c.frame_count(),
            0,
            "no self-echo of the client's own DeclareSubscriber back to it"
        );
    }

    #[test]
    fn a_client_push_re_injects_into_the_mesh_as_self_sourced() {
        // D4b / C3b (FAILS before D4b: the transit forward_push drops a client-sourced
        // Push -- a client is not a graph node). A co-attached CLIENT publisher's Put
        // is re-injected into the mesh as SELF-sourced (node_id 0), so a subscribing
        // MESH peer receives it.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (peer_b, sink_b) = peer_face(zid(0x0B)); // a subscribing mesh peer
        let (client_pub, _cp) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &peer_b);
        fwd.register(FaceId(1), &client_pub);
        advertise_link_back(&fwd, FaceId(0), 0x0B, 0x05); // edge S<->B
        declare_interest(&fwd, FaceId(0), "demo/data"); // the MESH peer B subscribes
        sink_b.reset();

        // The client publishes demo/data via the Push dispatch.
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(data_push()))], // demo/data
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(1), IterationEvent::Poll(&outcome));

        assert_eq!(
            sink_b.frame_count(),
            1,
            "the client Put is re-injected to the subscribing mesh peer (C3b)"
        );
        assert_eq!(
            forwarded_source(&sink_b.frame_bytes(0)),
            0,
            "re-injected as SELF-sourced (routing-context node_id 0)"
        );
        assert_eq!(
            forwarded_keyexpr(&sink_b.frame_bytes(0)).as_deref(),
            Some("demo/data")
        );
    }

    #[test]
    fn a_client_push_reaches_both_a_co_attached_client_sub_and_a_mesh_sub() {
        // D4a C3a + D4b C3b COMPOSE: a CLIENT publisher's Put reaches BOTH a
        // co-attached CLIENT subscriber (local delivery) AND a subscribing MESH peer
        // (re-injected self-sourced) from the one dispatch.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (peer_b, sink_b) = peer_face(zid(0x0B)); // mesh subscriber
        let (client_pub, _cp) = peer_face_whatami(zid(0x0C), 2);
        let (client_sub, sink_cs) = peer_face_whatami(zid(0x0D), 2);
        fwd.register(FaceId(0), &peer_b);
        fwd.register(FaceId(1), &client_pub);
        fwd.register(FaceId(2), &client_sub);
        advertise_link_back(&fwd, FaceId(0), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(0), "demo/data"); // MESH peer B subscribes
        client_declare_sub(&fwd, FaceId(2), 1, "demo/**"); // co-attached client D subscribes
        sink_b.reset();
        sink_cs.reset();

        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(data_push()))], // demo/data from client C
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(1), IterationEvent::Poll(&outcome));

        assert_eq!(
            sink_cs.frame_count(),
            1,
            "the co-attached client subscriber receives it (C3a)"
        );
        assert_eq!(
            sink_b.frame_count(),
            1,
            "the subscribing mesh peer receives it re-injected (C3b)"
        );
        assert_eq!(
            forwarded_source(&sink_b.frame_bytes(0)),
            0,
            "the mesh copy is SELF-sourced"
        );
    }

    #[cfg(feature = "transport-qos")]
    #[test]
    fn deliver_to_client_subscribers_preserves_the_received_band() {
        // R311y225 — the peer CLIENT-face egress preserves the received band (the
        // y224 residual): a RealTime mesh Put reaches a co-attached QoS-negotiated
        // CLIENT subscriber still banded RealTime, driven through the full `forward`
        // dispatch. The client must `set_qos_offer(true)`, else the per-face send
        // clamps every Frame to DEFAULT (`dispatch_push`) and the band is unobservable.
        // Source is a MESH face so only `deliver_to_client_subscribers` fires (a client
        // source would ALSO trigger `reinject_client_push` — a different sink anyway).
        use crate::session_glue::{parse_inbound, InboundFrame};
        fn egress_band(frame: &[u8]) -> Priority {
            let InboundFrame::Frame { priority, .. } =
                parse_inbound(frame).expect("parse forwarded frame")
            else {
                panic!("forwarded bytes are not a Frame");
            };
            priority
        }

        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (peer_a, _sink_a) = peer_face(zid(0x0A)); // the mesh Push source
        let (client_sub, sink_sub) = peer_face_whatami(zid(0x0C), 2);
        client_sub.set_qos_offer(true);
        fwd.register(FaceId(0), &peer_a);
        fwd.register(FaceId(1), &client_sub);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        client_declare_sub(&fwd, FaceId(1), 1, "demo/**");

        // RealTime mesh Put -> the co-attached client sub, still RealTime.
        sink_sub.reset();
        let outcome = DriverLoopOutcome::FramePayload {
            priority: Priority::RealTime,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(data_push()))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&outcome));
        assert_eq!(sink_sub.frame_count(), 1, "delivered to the client sub");
        assert_eq!(
            egress_band(&sink_sub.frame_bytes(0)),
            Priority::RealTime,
            "client-face egress PRESERVES the received band — not re-clamped to DEFAULT"
        );

        // Negative control: a DEFAULT client egress stays DEFAULT.
        sink_sub.reset();
        let outcome = DriverLoopOutcome::FramePayload {
            priority: Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(data_push()))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&outcome));
        assert_eq!(
            egress_band(&sink_sub.frame_bytes(0)),
            Priority::DEFAULT,
            "a DEFAULT client egress stays DEFAULT"
        );
    }

    #[cfg(feature = "transport-qos")]
    #[test]
    fn reinject_client_push_preserves_the_received_band() {
        // R311y225 — the peer client->mesh re-inject preserves the received band: a
        // RealTime Put from a co-attached CLIENT publisher reaches a subscribing
        // QoS-negotiated MESH peer still banded RealTime (the peer twin of the
        // router's `publish_client_push_into_meshes`, y224 — restoring the symmetry
        // the y224 ledger flagged). Driven through the full `forward` dispatch.
        use crate::session_glue::{parse_inbound, InboundFrame};
        fn egress_band(frame: &[u8]) -> Priority {
            let InboundFrame::Frame { priority, .. } =
                parse_inbound(frame).expect("parse forwarded frame")
            else {
                panic!("forwarded bytes are not a Frame");
            };
            priority
        }

        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (peer_b, sink_b) = peer_face(zid(0x0B)); // the mesh subscriber
        let (client_pub, _cp) = peer_face_whatami(zid(0x0C), 2); // the client publisher
        peer_b.set_qos_offer(true);
        fwd.register(FaceId(0), &peer_b);
        fwd.register(FaceId(1), &client_pub);
        advertise_link_back(&fwd, FaceId(0), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(0), "demo/data"); // the mesh peer B subscribes

        // RealTime client Put -> re-injected to the subscribing mesh peer, still RealTime.
        sink_b.reset();
        let outcome = DriverLoopOutcome::FramePayload {
            priority: Priority::RealTime,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(data_push()))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(1), IterationEvent::Poll(&outcome));
        assert_eq!(sink_b.frame_count(), 1, "re-injected to the mesh sub");
        assert_eq!(
            egress_band(&sink_b.frame_bytes(0)),
            Priority::RealTime,
            "client->mesh re-inject PRESERVES the received band"
        );

        // Negative control: DEFAULT stays DEFAULT.
        sink_b.reset();
        let outcome = DriverLoopOutcome::FramePayload {
            priority: Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(data_push()))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(1), IterationEvent::Poll(&outcome));
        assert_eq!(
            egress_band(&sink_b.frame_bytes(0)),
            Priority::DEFAULT,
            "a DEFAULT re-inject stays DEFAULT"
        );
    }

    /// A self-originated data Push (its routing-context node_id defaults to 0).
    fn data_push() -> PushOwned {
        use wz_session_core::push_build::build_push_literal;
        build_push_literal("demo/data", b"payload").expect("build push")
    }

    // ── peer client-QUERYABLE hosting plane (the query-plane twin of D4a) ─────────

    /// Feed a co-attached CLIENT's `DeclareQueryable` (with its declared completeness)
    /// through the dispatch seam so the is_client branch routes it to
    /// `ingest_client_queryable` (NOT the mesh `forward_queryable`).
    fn client_declare_qabl(
        fwd: &LinkstateForwarder,
        face: FaceId,
        id: u64,
        keyexpr: &str,
        complete: bool,
    ) {
        let mut declare = build_declare_queryable(id, 0, Some(keyexpr)).expect("build qabl");
        wz_session_core::declare_build::set_declare_queryable_info(
            &mut declare,
            wz_session_core::queryable_info::QueryableInfo {
                complete,
                distance: 0,
            },
        );
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Declare(Box::new(declare))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(face, IterationEvent::Poll(&outcome));
    }

    /// Feed a client's graceful `UndeclareQueryable` — ID-ONLY
    /// (`build_undeclare_queryable(id)`, no ext_keyexpr, the form a real wz/pico client
    /// sends), so the withdraw resolves the ke by id (the R311y178 id-map).
    fn client_undeclare_qabl(fwd: &LinkstateForwarder, face: FaceId, id: u64) {
        let declare = build_undeclare_queryable(id);
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Declare(Box::new(declare))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(face, IterationEvent::Poll(&outcome));
    }

    #[test]
    fn a_client_qabl_registers_under_self_and_advertises_to_a_mesh_child() {
        // U1 (FAILS before this build: a client DeclareQueryable was dropped in
        // resolve_source — a client is not a graph node). A CLIENT of this peer declares
        // a queryable; it lands in `client_qabls` AND is advertised into the mesh under
        // SELF's zid carrying its QueryableInfo, so a mesh child routes matching queries here.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (peer_b, sink_b) = peer_face(zid(0x0B)); // a real mesh child
        let (client, _c) = peer_face_whatami(zid(0x0C), 2); // a CLIENT leaf
        fwd.register(FaceId(0), &peer_b);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0B, 0x05); // edge S<->B
        sink_b.reset();

        client_declare_qabl(&fwd, FaceId(1), 1, "demo/q", true);

        assert_eq!(
            fwd.client_qabls_seen(),
            1,
            "the client queryable is installed in client_qabls"
        );
        assert!(
            fwd.interested_queryables("demo/q").contains(&zid(0x05)),
            "the client queryable is advertised into the mesh under SELF's zid"
        );
        assert_eq!(
            forwarded_declare_queryable_keyexpr(&sink_b.frame_bytes(0)).as_deref(),
            Some("demo/q"),
            "the mesh child learns the queryable (a self-sourced DeclareQueryable)"
        );
        assert!(
            forwarded_declare_queryable_info(&sink_b.frame_bytes(0)).complete,
            "the advertised info carries the declared completeness"
        );
    }

    #[test]
    fn a_query_is_forwarded_to_a_co_attached_client_queryable_and_the_reply_returns() {
        // U2 composed delivery (FAILS before this build: a client queryable was never
        // hosted, so the query routed nowhere and the querier got only a bare final). A
        // co-attached CLIENT queryable answers a routed Query: the Query is forwarded to
        // the client face (a pending return entry allocated) and its Reply routes back to
        // the querier via the reused forward_response path.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (querier, sink_q) = peer_face_whatami(zid(0x0A), 2); // a CLIENT querier
        let (queryable, sink_qa) = peer_face_whatami(zid(0x0C), 2); // a CLIENT queryable
        fwd.register(FaceId(0), &querier);
        fwd.register(FaceId(1), &queryable);
        client_declare_qabl(&fwd, FaceId(1), 1, "demo/q", true);
        sink_q.reset();
        sink_qa.reset();

        let request = wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);

        assert_eq!(
            sink_qa.frame_count(),
            1,
            "the Query is forwarded to the co-attached client queryable"
        );
        let forwarded = forwarded_request(&sink_qa.frame_bytes(0));
        // The client answers with the pending qid this relay stamped.
        let reply = wz_session_core::response_build::build_response_reply_literal(
            forwarded.rid,
            "demo/q",
            b"client-reply",
        )
        .expect("build reply");
        fwd.forward_response(FaceId(1), true, &reply);

        assert_eq!(
            sink_q.frame_count(),
            1,
            "the client queryable's Reply routes back to the querier"
        );
        assert_eq!(
            forwarded_response(&sink_q.frame_bytes(0)).request_id,
            99,
            "the Reply carries the querier's own rid"
        );
    }

    #[test]
    fn a_mesh_sourced_query_to_a_client_queryable_carries_routing_source_zero() {
        // Regression guard for the peer qabl cross-impl fidelity fix: the Request
        // forwarded to a co-attached CLIENT queryable must carry routing source node-id
        // 0 — a client is a LEAF, not a graph node. `forward_request` stamps a SHARED
        // template with the query tree root (out_node_id, NON-ZERO for a MESH-sourced
        // query) for the mesh branches; reusing that verbatim for the client branch
        // ships a non-zero routing source that a real client (a pico z_queryable)
        // rejects by CLOSING its transport (surfaced by wz_peer_qabl_pico_interop).
        // The U2 test above uses a CLIENT querier (out_node_id 0), so it cannot catch
        // this — here the querier is a MESH face with a link-back edge, so the source
        // resolves NON-ZERO and the client branch's reset-to-0 is load-bearing.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // S
        let (querier, sink_q) = peer_face(zid(0x0A)); // a MESH querier (non-zero source)
        let (queryable, sink_qa) = peer_face_whatami(zid(0x0C), 2); // a CLIENT queryable
        fwd.register(FaceId(0), &querier);
        fwd.register(FaceId(1), &queryable);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S-A: source resolves non-zero
        client_declare_qabl(&fwd, FaceId(1), 1, "demo/q", true);
        sink_q.reset();
        sink_qa.reset();

        let request = wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);

        assert_eq!(
            sink_qa.frame_count(),
            1,
            "the mesh-sourced Query is forwarded to the co-attached client queryable"
        );
        let forwarded = forwarded_request(&sink_qa.frame_bytes(0));
        assert_eq!(
            read_request_source(&forwarded),
            0,
            "the Request forwarded to a CLIENT queryable must carry routing source 0 (a \
             client is not a graph node); reusing the mesh template's non-zero tree-root \
             source is what closed a real pico client's transport"
        );
    }

    #[test]
    fn a_complete_client_queryable_wins_bestmatching_over_a_coexisting_mesh_queryable() {
        // U2b — the black-hole the forward_request restructure fixes. A CLIENT hosts a
        // COMPLETE queryable for a ke a remote MESH peer ALSO offers. Before the restructure
        // the mesh direction made `children` non-empty, so the query fanned only to the mesh
        // and the co-hosted client was BLACK-HOLED (the empty-route tail never ran). Now the
        // distance-1 complete client WINS BestMatching and the mesh best is suppressed.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (querier, _sq) = peer_face_whatami(zid(0x0A), 2); // a CLIENT querier
        let (mesh_b, sink_b) = peer_face(zid(0x0B)); // a mesh peer that ALSO hosts demo/q
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2); // the co-hosted client queryable
        fwd.register(FaceId(0), &querier);
        fwd.register(FaceId(1), &mesh_b);
        fwd.register(FaceId(2), &client);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05); // edge S<->B
        declare_queryable_complete(&fwd, FaceId(1), "demo/q", 0, true); // B's mesh qabl
        client_declare_qabl(&fwd, FaceId(2), 1, "demo/q", true); // C's client qabl
        sink_b.reset();
        sink_c.reset();

        let request = wz_session_core::request_build::build_request_query(7, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);

        assert_eq!(
            sink_c.frame_count(),
            1,
            "the distance-1 complete client queryable receives the Query (NOT black-holed)"
        );
        assert_eq!(
            sink_b.frame_count(),
            0,
            "the farther mesh queryable is suppressed — the nearer complete client wins BestMatching"
        );
    }

    #[test]
    fn two_client_queryables_on_the_same_ke_advertise_the_merged_completeness() {
        // U3 upgrade-merge — the qabl-specific refinement over the sub union-refcount
        // (subs carry no info). Client A declares INCOMPLETE demo/q (advert incomplete),
        // then client B declares COMPLETE demo/q: the self-sourced advert is UPGRADED to
        // complete (the OR merge over both self sources).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (peer_x, sink_x) = peer_face(zid(0x0B)); // a mesh child
        let (client_a, _ca) = peer_face_whatami(zid(0x0C), 2);
        let (client_b, _cb) = peer_face_whatami(zid(0x0D), 2);
        fwd.register(FaceId(0), &peer_x);
        fwd.register(FaceId(1), &client_a);
        fwd.register(FaceId(2), &client_b);
        advertise_link_back(&fwd, FaceId(0), 0x0B, 0x05);
        sink_x.reset(); // ignore the link-state OAM from advertise_link_back

        client_declare_qabl(&fwd, FaceId(1), 1, "demo/q", false); // incomplete
        assert!(
            !forwarded_declare_queryable_info(&sink_x.frame_bytes(0)).complete,
            "the first (incomplete) client advertises incomplete"
        );
        sink_x.reset();

        client_declare_qabl(&fwd, FaceId(2), 1, "demo/q", true); // complete -> UPGRADE
        assert_eq!(
            sink_x.frame_count(),
            1,
            "the completeness UPGRADE re-advertises (value-diff gate fired)"
        );
        assert!(
            forwarded_declare_queryable_info(&sink_x.frame_bytes(0)).complete,
            "the merged advert is now COMPLETE (the OR over both client contributors)"
        );
    }

    #[test]
    fn a_partial_client_queryable_withdrawal_downgrades_the_advertisement() {
        // U4 downgrade — one of two contributors leaves: the advert is RE-DECLARED with the
        // surviving (lower) merged info, NOT fully undeclared (which would black-hole the
        // survivor). Client A INCOMPLETE + client B COMPLETE -> advert complete; B withdraws
        // -> advert DOWNGRADES to incomplete (a DeclareQueryable, not an UndeclareQueryable).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (peer_x, sink_x) = peer_face(zid(0x0B));
        let (client_a, _ca) = peer_face_whatami(zid(0x0C), 2);
        let (client_b, _cb) = peer_face_whatami(zid(0x0D), 2);
        fwd.register(FaceId(0), &peer_x);
        fwd.register(FaceId(1), &client_a);
        fwd.register(FaceId(2), &client_b);
        advertise_link_back(&fwd, FaceId(0), 0x0B, 0x05);
        client_declare_qabl(&fwd, FaceId(1), 1, "demo/q", false);
        client_declare_qabl(&fwd, FaceId(2), 1, "demo/q", true);
        sink_x.reset();

        client_undeclare_qabl(&fwd, FaceId(2), 1); // the COMPLETE contributor leaves

        assert!(
            fwd.interested_queryables("demo/q").contains(&zid(0x05)),
            "the advert survives (client A still hosts demo/q)"
        );
        assert_eq!(
            forwarded_declare_queryable_keyexpr(&sink_x.frame_bytes(0)).as_deref(),
            Some("demo/q"),
            "a DOWNGRADED DeclareQueryable is re-flooded (not an UndeclareQueryable)"
        );
        assert!(
            !forwarded_declare_queryable_info(&sink_x.frame_bytes(0)).complete,
            "the downgraded advert dropped completeness back to incomplete"
        );
    }

    #[test]
    fn a_departing_client_purges_client_qabls_and_withdraws_the_advertisement() {
        // U5 / U7 (FAILS before this build: deregister had no client_qabls purge). A client
        // face going down purges its hosted queryables AND — as the last backer — withdraws
        // the mesh advertisement (a sourced UndeclareQueryable to the mesh child).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (peer_b, sink_b) = peer_face(zid(0x0B));
        let (client, _c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &peer_b);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0B, 0x05);
        client_declare_qabl(&fwd, FaceId(1), 1, "demo/q", true);
        assert_eq!(fwd.client_qabls_seen(), 1);
        sink_b.reset();

        fwd.deregister(FaceId(1));

        assert_eq!(
            fwd.client_qabls_seen(),
            0,
            "the departed client's queryables are purged from client_qabls"
        );
        assert!(
            !fwd.interested_queryables("demo/q").contains(&zid(0x05)),
            "the last backer's departure withdraws the mesh advertisement"
        );
        assert_eq!(
            forwarded_undeclare_queryable_keyexpr(&sink_b.frame_bytes(0)).as_deref(),
            Some("demo/q"),
            "the mesh child learns the forget (a sourced UndeclareQueryable)"
        );
    }

    #[test]
    fn a_self_native_undeclare_keeps_a_surviving_client_queryables_advertisement() {
        // U6 shared-slot rewire — the self-native undeclare_queryable and the client
        // queryable share the SINGLE (ke, self_zid) advert slot. A self-native
        // local_queryable + a client queryable on the SAME ke: retracting the self-native
        // one must DOWNGRADE-not-nuke (the client's advert survives), proving
        // undeclare_queryable routes through withdraw_mesh_qabl_if_unbacked (before this
        // build it unconditionally withdrew self + would black-hole the client).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (peer_b, _sb) = peer_face(zid(0x0B));
        let (client, _c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &peer_b);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0B, 0x05);
        fwd.register_local_queryable(
            "demo/q",
            true,
            Box::new(|_v: &dyn QueryView, out: &mut dyn ReplyOut| out.reply(b"local")),
        )
        .expect("register local queryable");
        client_declare_qabl(&fwd, FaceId(1), 1, "demo/q", true);

        fwd.undeclare_queryable("demo/q")
            .expect("undeclare self-native");

        assert!(
            fwd.interested_queryables("demo/q").contains(&zid(0x05)),
            "the client queryable's advert SURVIVES the self-native retraction (downgrade, not nuke)"
        );
        assert_eq!(
            fwd.client_qabls_seen(),
            1,
            "the client queryable is still hosted"
        );
    }

    /// One LinkState entry (psid-space, with the psids it links to) — mirrors
    /// the wz-routing-graph test idiom for building a topology by ingest.
    fn entry(psid: u64, sn: u64, node: u8, links: &[u64]) -> LinkstateOwned {
        LinkstateOwned {
            options: 0,
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

    /// R311y226 — decode the per-message outer qos ext off a captured
    /// egress frame's Push (the decode primitive). `None` when the Push
    /// carries no qos ext (a plain / DEFAULT-suppressed publish), so a
    /// caller can witness ABSENCE, not merely a DEFAULT read. Decoding
    /// the full outer chain also proves the qos(0x01) ext coexists with
    /// the self-origin source(0x03) + hoplimit(0x0a) stamps uncorrupted.
    /// Gated on the same qos-byte subset as its only callers (the R311y226
    /// tests) so a routing-peer build WITHOUT the qos-byte features does
    /// not carry it as dead code (Layer C1ba's ML_DEPLOY_FEATURES combo).
    #[cfg(feature = "pubsub-qos")]
    fn forwarded_qos(frame: &[u8]) -> Option<wz_session_core::sample::QosLevel> {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let InboundFrame::Frame { payload, .. } =
            parse_inbound(frame).expect("parse forwarded frame")
        else {
            panic!("forwarded bytes are not a Frame");
        };
        let msgs = parse_frame_payload(&payload).expect("parse frame payload");
        let Some(NetworkMessage::Push(p)) = msgs.first() else {
            panic!("expected a forwarded Push");
        };
        wz_session_core::sample::extract_qos(p.extensions.as_deref().unwrap_or(&[]))
    }

    /// R311y226 — project a captured egress frame's per-message qos ext
    /// onto a `Sample` and read the app-observable priority exactly as
    /// the production RX path does (extract_qos -> Sample::priority()).
    /// `Priority::DEFAULT` when the Push carries no qos ext. Gated with
    /// [`forwarded_qos`] on the qos-byte subset (its only callers are the
    /// R311y226 tests).
    #[cfg(feature = "pubsub-qos")]
    fn forwarded_priority(frame: &[u8]) -> wz_session_core::qos::Priority {
        let mut sample = wz_session_core::sample::Sample::new_put("k", Vec::<u8>::new());
        if let Some(q) = forwarded_qos(frame) {
            sample = sample.with_qos(q);
        }
        sample.priority()
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

    /// The LITERAL keyexpr of the single forwarded Push in a recorded wire frame,
    /// or `None` if that Push's keyexpr is still aliased (id != 0). Proves the B1
    /// normalize landed ON THE WIRE — a downstream link sees a literal.
    fn forwarded_keyexpr(frame: &[u8]) -> Option<String> {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let InboundFrame::Frame { payload, .. } =
            parse_inbound(frame).expect("parse forwarded frame")
        else {
            panic!("forwarded bytes are not a Frame");
        };
        let msgs = parse_frame_payload(&payload).expect("parse frame payload");
        match msgs.first() {
            Some(NetworkMessage::Push(p)) => match &p.keyexpr.body {
                WireexprOwnedVariant::WireexprLocal(w) if w.id == 0 => {
                    w.suffix.as_deref().map(str::to_string)
                }
                _ => None,
            },
            other => panic!("expected a forwarded Push, got {other:?}"),
        }
    }

    /// The LITERAL keyexpr of the single forwarded DeclareSubscriber in a frame,
    /// or `None` if aliased — the control-plane twin of [`forwarded_keyexpr`]
    /// (B1b), proving the re-flooded subscription was normalized to a literal.
    fn forwarded_declare_keyexpr(frame: &[u8]) -> Option<String> {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let InboundFrame::Frame { payload, .. } =
            parse_inbound(frame).expect("parse forwarded frame")
        else {
            panic!("forwarded bytes are not a Frame");
        };
        let msgs = parse_frame_payload(&payload).expect("parse frame payload");
        match msgs.first() {
            Some(NetworkMessage::Declare(d)) => match &d.body {
                DeclareOwnedVariant::CodecZenohDeclSubscriber(sub) => match &sub.keyexpr.body {
                    WireexprOwnedVariant::WireexprLocal(w) if w.id == 0 => {
                        w.suffix.as_deref().map(str::to_string)
                    }
                    _ => None,
                },
                _ => None,
            },
            other => panic!("expected a forwarded Declare, got {other:?}"),
        }
    }

    /// Decode the FIRST message of a recorded frame as a `DeclareOwned` (the
    /// full-body twin of [`forwarded_declare_keyexpr`], for asserting the reply
    /// VARIANT + echoed interest_id of an interest answer).
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

    /// An `Interest` with the C/F/SUBSCRIBERS/QUERYABLES/AGGREGATE bits a test
    /// picks, RESTRICTED to a literal `keyexpr` (mapping id 0) — the wz peer's
    /// test twin of the router's interest builder.
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
                    body: WireexprOwnedVariant::WireexprLocal(
                        wz_codecs::wireexpr_local::WireexprLocalOwned {
                            id: 0,
                            suffix_len: Some(keyexpr.len() as u64),
                            suffix: Some(
                                sce_forge_runtime::codec::SceString::from_view(keyexpr)
                                    .expect("interest keyexpr fits the SceString capacity"),
                            ),
                        },
                    ),
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

    /// Wrap ONE message as a reliable inbound frame poll and drive `forward` — the
    /// interest-answer test driver (the peer twin of the router's `forward_one`).
    fn forward_one(fwd: &LinkstateForwarder, face: FaceId, msg: NetworkMessage) {
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![msg],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(face, IterationEvent::Poll(&outcome));
    }

    #[test]
    fn peer_answers_a_client_interest_with_the_matching_mesh_sub_then_final() {
        // B-c reverse-data fix for the PEER forwarder: a pico publisher attached to
        // a wz PEER (not a router) solicits with a CURRENT interest (SUBSCRIBERS,
        // RESTRICTED demo/key, AGGREGATE); the peer answers with the matching mesh
        // subscription it holds (a neighbour's demo/**) + a DeclareFinal, so the
        // publisher's write-filter deactivates. This is what the `_ => {}` gap
        // black-holed before B-c.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (mesh, _sm) = peer_face(zid(0x0A)); // a mesh neighbour that subscribes
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2); // wire 2 = Client, the requester
        fwd.register(FaceId(0), &mesh);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A
        declare_interest(&fwd, FaceId(0), "demo/**"); // A subscribes -> subs
        assert_eq!(fwd.subs.borrow().interested("demo/**"), vec![zid(0x0A)]);
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
        // Reply 0: DeclareSubscriber keyed on the INTEREST ke demo/key (aggregate —
        // pico matches by keyexpr EQUALITY, so demo/** would silently fail).
        let reply = forwarded_declare(&sink_c.frame_bytes(0));
        assert_eq!(reply.interest_id, Some(7));
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
        let fin = forwarded_declare(&sink_c.frame_bytes(1));
        assert_eq!(fin.interest_id, Some(7));
        assert!(matches!(
            fin.body,
            DeclareOwnedVariant::CodecZenohDeclFinal(_)
        ));
    }

    #[test]
    fn peer_interest_with_no_matching_sub_replies_only_a_final() {
        // A CURRENT interest whose keyexpr no sub matches: the peer still
        // terminates it with a DeclareFinal (0 subs => the filter stays active =
        // "no subscriber yet"), but dumps nothing.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (mesh, _sm) = peer_face(zid(0x0A));
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &mesh);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        declare_interest(&fwd, FaceId(0), "demo/**");
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
        assert!(matches!(
            forwarded_declare(&sink_c.frame_bytes(0)).body,
            DeclareOwnedVariant::CodecZenohDeclFinal(_)
        ));
    }

    #[test]
    fn peer_ignores_a_non_client_interest_but_still_sends_a_final() {
        // FAITHFUL to zenoh linkstate_peer (`mode.current() && face.whatami ==
        // Client`): only a CLIENT face's CURRENT interest is answered with
        // declarations — a mesh peer/router learns by proactive flooding. A
        // non-client interest still gets the terminating DeclareFinal so its
        // handshake completes, but NO declaration dump even though a sub matches.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (mesh, _sm) = peer_face(zid(0x0A));
        let (peer_req, sink_p) = peer_face(zid(0x0B)); // no whatami -> defaults to Peer
        fwd.register(FaceId(0), &mesh);
        fwd.register(FaceId(1), &peer_req);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        declare_interest(&fwd, FaceId(0), "demo/**"); // a matching sub DOES exist
        sink_p.reset();
        forward_one(
            &fwd,
            FaceId(1),
            interest_msg(9, "demo/key", true, false, true),
        );
        assert_eq!(
            sink_p.frame_count(),
            1,
            "a peer-face interest gets only the DeclareFinal, no declaration dump"
        );
        assert!(matches!(
            forwarded_declare(&sink_p.frame_bytes(0)).body,
            DeclareOwnedVariant::CodecZenohDeclFinal(_)
        ));
    }

    #[test]
    fn peer_answers_a_client_interest_from_its_own_local_subscriber() {
        // The peer INCLUDES self's own local subscription in the reply — self_zid
        // is NOT excluded (zenoh's `remote_simple_subs` counts self's local face),
        // unlike the router which derives self separately. A pico publisher whose
        // only matching subscriber is the wz peer ITSELF must still deactivate its
        // filter. Only the requesting face's OWN zid is excluded.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &client);
        fwd.declare_subscription("demo/**").expect("self local sub"); // under self_zid 0x05
        assert_eq!(fwd.subs.borrow().interested("demo/**"), vec![zid(0x05)]);
        sink_c.reset();
        forward_one(
            &fwd,
            FaceId(0),
            interest_msg(4, "demo/key", true, false, true),
        );
        assert_eq!(
            sink_c.frame_count(),
            2,
            "self's local sub IS advertised (self_zid not excluded) + a DeclareFinal"
        );
        assert!(matches!(
            forwarded_declare(&sink_c.frame_bytes(0)).body,
            DeclareOwnedVariant::CodecZenohDeclSubscriber(_)
        ));
        assert!(matches!(
            forwarded_declare(&sink_c.frame_bytes(1)).body,
            DeclareOwnedVariant::CodecZenohDeclFinal(_)
        ));
    }

    #[test]
    fn peer_answers_a_client_queryable_interest_with_a_declare_queryable() {
        // The QUERYABLE leg (qu bit): a client's CURRENT interest is answered with
        // a DeclareQueryable for the matching mesh queryable + a DeclareFinal, so a
        // pico QUERIER's write-filter deactivates. The merged-completeness fold is
        // the shared `emit_current_interest_replies` SSOT (router-tested); here we
        // prove the peer's qu() leg routes to a DeclareQueryable carrier.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (mesh, _sm) = peer_face(zid(0x0A));
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &mesh);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        declare_queryable_complete(&fwd, FaceId(0), "demo/**", 0, true); // a COMPLETE mesh qabl
        sink_c.reset();
        forward_one(
            &fwd,
            FaceId(1),
            interest_msg(6, "demo/key", false, true, true),
        ); // qu, not su
        assert_eq!(
            sink_c.frame_count(),
            2,
            "one DeclareQueryable reply + one DeclareFinal"
        );
        let reply = forwarded_declare(&sink_c.frame_bytes(0));
        assert_eq!(reply.interest_id, Some(6));
        assert!(
            matches!(reply.body, DeclareOwnedVariant::CodecZenohDeclQueryable(_)),
            "the qu() leg replies with a DeclareQueryable, not a subscriber"
        );
        assert!(matches!(
            forwarded_declare(&sink_c.frame_bytes(1)).body,
            DeclareOwnedVariant::CodecZenohDeclFinal(_)
        ));
    }

    #[test]
    fn peer_future_only_interest_gets_no_reply() {
        // A pure-FUTURE interest (C clear, F set) emits NO immediate wire reply —
        // not even a DeclareFinal (zenoh sends the Final only on `mode.current()`),
        // even when a matching sub already exists. Since R311y146 the interest is
        // STORED (so a sub learned LATER is pushed — see the future_interest store
        // tests + wz_router_future_sub_push E2E); this test locks the
        // no-spurious-immediate-reply property that storage must not break.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (mesh, _sm) = peer_face(zid(0x0A));
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &mesh);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        declare_interest(&fwd, FaceId(0), "demo/**"); // a matching sub exists
        sink_c.reset();
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(8, "demo/key", false, true, true, false, true),
        );
        assert_eq!(
            sink_c.frame_count(),
            0,
            "a future-only interest gets NO immediate reply (not even a Final); \
             it is stored, not answered inline"
        );
    }

    #[test]
    fn peer_future_interest_pushes_a_later_mesh_sub_to_the_client_publisher() {
        // The pub-before-sub close on the peer (R311y146): a CLIENT publisher
        // solicits a C+F SUBSCRIBERS interest for demo/key while NO matching sub
        // exists -> only a DeclareFinal. A MESH sub for demo/** is learned LATER ->
        // the peer proactively pushes an unsolicited DeclareSubscriber (non-zero id,
        // keyed on the aggregate interest ke, interest_id None) to the publisher.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (mesh, _sm) = peer_face(zid(0x0A));
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &mesh);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        // 1) C+F interest, no matching sub yet -> only the DeclareFinal.
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(8, "demo/key", true, true, true, false, true),
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "empty current dump -> only a DeclareFinal"
        );
        assert!(matches!(
            forwarded_declare(&sink_c.frame_bytes(0)).body,
            DeclareOwnedVariant::CodecZenohDeclFinal(_)
        ));
        assert_eq!(
            fwd.future_pushes_seen(),
            0,
            "no future push yet (the interest found an empty current dump)"
        );
        sink_c.reset();
        // 2) a mesh sub for demo/** is learned LATER -> the FUTURE push fires.
        declare_interest(&fwd, FaceId(0), "demo/**");
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the later mesh sub is pushed to the waiting client publisher"
        );
        let push = forwarded_declare(&sink_c.frame_bytes(0));
        assert_eq!(
            push.interest_id, None,
            "unsolicited FUTURE push carries no interest_id"
        );
        match &push.body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => {
                assert_ne!(d.id, 0, "a future push carries a non-zero decl id")
            }
            other => panic!("expected a DeclSubscriber push, got {other:?}"),
        }
        assert_eq!(
            forwarded_declare_keyexpr(&sink_c.frame_bytes(0)).as_deref(),
            Some("demo/key"),
            "the aggregate push is keyed on the INTEREST ke"
        );
        assert_eq!(
            fwd.future_pushes_seen(),
            1,
            "the future push bumped the peer future_pushes counter (R311y158)"
        );
    }

    #[test]
    fn peer_future_interest_pushes_a_self_local_sub_to_the_client_publisher() {
        // The self-local push: a client publisher declares a C+F interest, then
        // THIS peer declares its OWN local subscriber matching it -> the publisher
        // is pushed the peer's subscriber (declare_subscription's future push, origin
        // None). Exercises the peer path that has no inbound face.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(1), &client);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(8, "demo/key", true, true, true, false, true),
        );
        sink_c.reset();
        // This node declares a LOCAL subscriber matching the interest.
        fwd.declare_subscription("demo/**")
            .expect("declare local subscriber");
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the self-local subscriber is pushed to the client publisher"
        );
        let push = forwarded_declare(&sink_c.frame_bytes(0));
        assert_eq!(push.interest_id, None);
        assert!(matches!(
            push.body,
            DeclareOwnedVariant::CodecZenohDeclSubscriber(_)
        ));
        assert_eq!(
            forwarded_declare_keyexpr(&sink_c.frame_bytes(0)).as_deref(),
            Some("demo/key"),
        );
    }

    #[test]
    fn peer_future_qabl_interest_pushes_a_self_local_qabl_to_the_client_querier() {
        // The self-local qabl push (R311y150, query-plane twin): a client querier
        // declares a C+F QUERYABLES interest, then THIS peer declares its OWN local
        // queryable matching it -> the querier is pushed the peer's queryable
        // (declare_queryable's future push, origin None) carrying its completeness.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(1), &client);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(8, "demo/key", true, true, false, true, true),
        );
        sink_c.reset();
        fwd.declare_queryable("demo/**", true)
            .expect("declare local queryable");
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the self-local queryable is pushed to the client querier"
        );
        let push = forwarded_declare(&sink_c.frame_bytes(0));
        assert_eq!(push.interest_id, None);
        match &push.body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => {
                assert_ne!(d.id, 0, "a future qabl push carries a non-zero decl id");
                assert!(
                    wz_session_core::queryable_info::read_queryable_info(d.extensions.as_ref())
                        .complete,
                    "the peer's complete=true rides the push"
                );
                match &d.keyexpr.body {
                    WireexprOwnedVariant::WireexprLocal(w) => assert_eq!(
                        w.suffix.as_deref(),
                        Some("demo/key"),
                        "the aggregate push is keyed on the INTEREST ke"
                    ),
                    _ => panic!("push keyexpr must be literal"),
                }
            }
            _ => panic!("expected a DeclareQueryable future push"),
        }
        assert_eq!(
            fwd.future_qabl_pushes_seen(),
            1,
            "the future qabl push bumped the peer future_qabl_pushes counter (R311y158)"
        );
    }

    #[test]
    fn peer_withdrawing_the_self_local_sub_undeclares_to_the_client_publisher() {
        // R311y151 peer undeclare-push: a self-local sub was pushed to a waiting
        // client publisher; `undeclare_subscription` re-arms the publisher's
        // write-filter with an UndeclareSubscriber carrying the SAME id + clears
        // `pushed`. (The mesh path via forward_unsubscription is structurally the
        // twin — both fire the forget after the removal.)
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(1), &client);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(8, "demo/key", true, true, true, false, true),
        );
        sink_c.reset();
        fwd.declare_subscription("demo/**")
            .expect("declare local subscriber");
        assert_eq!(sink_c.frame_count(), 1, "the self-local sub is pushed");
        let pushed_id = match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => d.id,
            _ => panic!("expected a DeclareSubscriber push"),
        };
        assert_ne!(pushed_id, 0);
        sink_c.reset();
        fwd.undeclare_subscription("demo/**")
            .expect("undeclare local subscriber");
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the withdrawal undeclares to the waiting client publisher"
        );
        match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(u) => {
                assert_eq!(u.id, pushed_id, "the undeclare carries the pushed decl id")
            }
            _ => panic!("expected an UndeclareSubscriber"),
        }
    }

    #[test]
    fn peer_link_down_undeclares_to_the_client_publisher() {
        // gap (a) / R311y152 — the CRITICAL peer regression guard: a MESH sub backing
        // a co-attached client publisher's pushed reply ke goes DOWN via a LINK-DOWN
        // (deregister -> remove_link -> purge_detached_interest), NOT a graceful
        // Undeclare. The detach choke point must fire the undeclare-push so the
        // publisher's write-filter re-arms — AND must not panic. The link-down path
        // is the one that exercises the deregister `self.faces` borrow scope (the
        // Oam-ingest detach path holds no such borrow), so a test on the Oam path
        // alone would pass while link-down panics in production.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (mesh, _sm) = peer_face(zid(0x0A));
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &mesh);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(8, "demo/key", true, true, true, false, true),
        );
        sink_c.reset();
        declare_interest(&fwd, FaceId(0), "demo/**"); // mesh sub learned -> pushed
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the mesh sub is pushed to the waiting client publisher"
        );
        let pushed_id = match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => d.id,
            _ => panic!("expected a DeclareSubscriber push"),
        };
        assert_ne!(pushed_id, 0);
        sink_c.reset();
        fwd.deregister(FaceId(0)); // the backing mesh face goes DOWN (link-down)
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the link-down undeclares to the waiting publisher (the write-filter re-arms)"
        );
        match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(u) => assert_eq!(
                u.id, pushed_id,
                "the link-down undeclare carries the pushed decl id"
            ),
            _ => panic!("expected an UndeclareSubscriber on link-down"),
        }
    }

    #[test]
    fn peer_oam_ingest_detach_undeclares_to_the_client_publisher() {
        // gap (a) / R311y152 — the OAM-INGEST twin of
        // `peer_link_down_undeclares_to_the_client_publisher`, covering the SECOND
        // prune site that funnels through the SAME `purge_detached_interest` choke
        // point. Here the MESH sub backing a co-attached client publisher's pushed
        // reply ke detaches NOT by a local link-down (`deregister`) but by a TOPOLOGY
        // change learned over the wire: a relay's linkstate OAM drops the last edge
        // reaching the backing node, so `forward`'s `changes.removed` prunes it and
        // fires the undeclare-push at the ingest site (linkstate_forward.rs `forward`,
        // `purge_detached_interest(&changes.removed)`). The backing node (0x0B) is
        // 2-hop — reachable ONLY via relay 0x0A — so ONLY an OAM ingest, never a
        // `deregister`, can detach it. The link-down site is already guarded (that
        // test exercises the harder `deregister` `self.faces` borrow scope); this
        // proves the choke point is genuinely shared, not link-down-only.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (relay, _sr) = peer_face(zid(0x0A));
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &relay);
        fwd.register(FaceId(1), &client);
        // 0x0B is a 2-hop node reachable ONLY via relay 0x0A (psid 7 in 0x0A's link
        // space), so it can be detached by an OAM topology change but never by a
        // face-local `deregister`.
        fwd.ingest_inbound_linkstate(
            FaceId(0),
            list(vec![
                entry(0, 1, 0x05, &[]),
                entry(1, 5, 0x0A, &[0, 7]),
                entry(7, 5, 0x0B, &[1]),
            ]),
        );
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(8, "demo/key", true, true, true, false, true),
        );
        sink_c.reset();
        // 0x0B (the transit source, psid 7) declares demo/** -> backs the client
        // publisher's demo/key -> pushed to the waiting publisher.
        let mut declare = build_declare_subscriber(0, 0, Some("demo/**")).expect("build sub");
        set_declare_source(&mut declare, 7); // node_id 7 = 0x0B via relay 0x0A
        fwd.forward_subscription(FaceId(0), true, &declare);
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the 2-hop mesh sub is pushed to the waiting client publisher"
        );
        let pushed_id = match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => d.id,
            _ => panic!("expected a DeclareSubscriber push"),
        };
        assert_ne!(pushed_id, 0);
        sink_c.reset();
        // Relay 0x0A sends an updated linkstate OVER THE WIRE (through `forward`'s OAM
        // ingest, options 0x03 so the zid/whatami round-trip through the codec) that
        // drops its edge to 0x0B (higher sn supersedes the sn-5 entry): 0x0B loses its
        // only path and detaches -> changes.removed = [0x0B] -> purge_detached_interest
        // fires the undeclare-push here, exactly as the link-down site does.
        let detach = list(vec![
            LinkstateOwned {
                options: 0x03,
                ..entry(0, 2, 0x05, &[])
            },
            LinkstateOwned {
                options: 0x03,
                ..entry(1, 6, 0x0A, &[0])
            },
        ]);
        let oam = build_linkstate_oam_owned(&detach).expect("build detach oam");
        forward_one(&fwd, FaceId(0), NetworkMessage::Oam(oam));
        assert!(
            fwd.net.borrow().get_node(&zid(0x0B)).is_none(),
            "the OAM ingest detached 0x0B (its only path, via 0x0A, is gone)"
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the OAM-ingest detach undeclares to the waiting publisher (the SAME \
             purge_detached_interest choke point the link-down site uses)"
        );
        match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(u) => assert_eq!(
                u.id, pushed_id,
                "the OAM-ingest undeclare carries the pushed decl id"
            ),
            _ => panic!("expected an UndeclareSubscriber on the OAM-ingest detach"),
        }
    }

    #[test]
    fn peer_oam_ingest_detach_undeclares_to_the_client_querier() {
        // The query twin of `peer_oam_ingest_detach_undeclares_to_the_client_publisher`:
        // a 2-hop mesh QUERYABLE backing a co-attached client querier detaches via an
        // OAM topology change (not a `deregister`), and the SAME purge_detached_interest
        // choke point fires `undeclare_push_qabls` (the `affected_qabls` branch) so the
        // querier's write-filter re-arms. 0x0B is the sole backer of demo/key, so its
        // detach is a FULL undeclare (not the y153 partial-withdrawal downgrade).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (relay, _sr) = peer_face(zid(0x0A));
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &relay);
        fwd.register(FaceId(1), &client);
        fwd.ingest_inbound_linkstate(
            FaceId(0),
            list(vec![
                entry(0, 1, 0x05, &[]),
                entry(1, 5, 0x0A, &[0, 7]),
                entry(7, 5, 0x0B, &[1]),
            ]),
        );
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(8, "demo/key", true, true, false, true, true),
        );
        sink_c.reset();
        // 0x0B (transit, psid 7) declares a COMPLETE queryable demo/** -> backs the
        // querier's demo/key -> pushed.
        declare_queryable_complete(&fwd, FaceId(0), "demo/**", 7, true);
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the 2-hop mesh qabl is pushed to the waiting client querier"
        );
        let pushed_id = match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => d.id,
            _ => panic!("expected a DeclareQueryable push"),
        };
        assert_ne!(pushed_id, 0);
        sink_c.reset();
        let detach = list(vec![
            LinkstateOwned {
                options: 0x03,
                ..entry(0, 2, 0x05, &[])
            },
            LinkstateOwned {
                options: 0x03,
                ..entry(1, 6, 0x0A, &[0])
            },
        ]);
        let oam = build_linkstate_oam_owned(&detach).expect("build detach oam");
        forward_one(&fwd, FaceId(0), NetworkMessage::Oam(oam));
        assert!(
            fwd.net.borrow().get_node(&zid(0x0B)).is_none(),
            "the OAM ingest detached 0x0B"
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the OAM-ingest detach undeclares to the waiting querier"
        );
        match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohUndeclQueryable(u) => assert_eq!(
                u.id, pushed_id,
                "the OAM-ingest undeclare carries the pushed qabl id"
            ),
            _ => panic!("expected an UndeclareQueryable on the OAM-ingest detach"),
        }
    }

    #[test]
    fn peer_link_down_undeclares_to_the_client_querier() {
        // gap (a) query twin on the peer: a MESH queryable backing a co-attached
        // client querier's pushed reply ke goes DOWN via a LINK-DOWN -> the detach
        // choke point undeclares to the querier (its write-filter re-arms), through
        // the same undeclare_push_qabls seam + hoisted-borrow path as the sub twin.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (mesh, _sm) = peer_face(zid(0x0A));
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &mesh);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(8, "demo/key", true, true, false, true, true),
        );
        sink_c.reset();
        declare_queryable_interest(&fwd, FaceId(0), "demo/**"); // mesh qabl -> pushed
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the mesh qabl is pushed to the querier"
        );
        let pushed_id = match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => d.id,
            _ => panic!("expected a DeclareQueryable push"),
        };
        assert_ne!(pushed_id, 0);
        sink_c.reset();
        fwd.deregister(FaceId(0)); // the backing mesh qabl's face goes DOWN
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the link-down undeclares to the waiting querier"
        );
        match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohUndeclQueryable(u) => {
                assert_eq!(
                    u.id, pushed_id,
                    "the link-down undeclare carries the pushed qabl id"
                )
            }
            _ => panic!("expected an UndeclareQueryable on link-down"),
        }
    }

    #[test]
    fn peer_partial_qabl_withdrawal_downgrades_the_client_querier_same_id() {
        // gap (c) / R311y153 on the peer (a SUPERSET over zenoh's full-undeclare-only
        // linkstate_peer hat): a COMPLETE mesh qabl (0x0A) and an INCOMPLETE one (0x0B)
        // both back the aggregate reply demo/key; complete=true is pushed to an
        // ALL_COMPLETE client querier. 0x0A's link drops (detach), but 0x0B still backs
        // demo/key -> NOT an undeclare, a RE-PUSH of the DOWNGRADED complete=false with
        // the SAME id. 0x0B keeps its OWN link so it survives 0x0A's detach.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (mesh_c, _sc) = peer_face(zid(0x0A)); // complete backer, will detach
        let (mesh_i, _si) = peer_face(zid(0x0B)); // incomplete co-backer, survives
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &mesh_c);
        fwd.register(FaceId(2), &mesh_i);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(2), 0x0B, 0x05); // 0x0B's own link -> survives 0x0A detach
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(8, "demo/key", true, true, false, true, true),
        );
        sink_c.reset();
        declare_queryable_complete(&fwd, FaceId(0), "demo/**", 0, true); // complete -> push
        assert_eq!(sink_c.frame_count(), 1, "the complete qabl is pushed");
        let pushed_id = match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => d.id,
            _ => panic!("expected a DeclareQueryable push"),
        };
        assert!(
            wz_session_core::queryable_info::read_queryable_info(
                match &forwarded_declare(&sink_c.frame_bytes(0)).body {
                    DeclareOwnedVariant::CodecZenohDeclQueryable(d) => d.extensions.as_ref(),
                    _ => None,
                }
            )
            .complete,
            "pushed complete=true"
        );
        declare_queryable_complete(&fwd, FaceId(2), "demo/key", 0, false); // incomplete co-backer
        sink_c.reset();
        fwd.deregister(FaceId(0)); // the complete backer's link drops (detach)
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the DOWNGRADE re-pushes (demo/key still backed by 0x0B)"
        );
        let re = forwarded_declare(&sink_c.frame_bytes(0));
        match &re.body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => {
                assert_eq!(d.id, pushed_id, "same interned id, re-declared in place");
                assert!(
                    !wz_session_core::queryable_info::read_queryable_info(d.extensions.as_ref())
                        .complete,
                    "carries the folded complete=false"
                );
            }
            other => panic!("expected a downgrade DeclareQueryable, got {other:?}"),
        }
    }

    #[test]
    fn peer_future_interest_final_stops_further_pushes() {
        // The peer's Interest(Final) teardown (mirror of the router's): a Final
        // removes the stored interest so a later mesh sub is not pushed to a gone
        // publisher.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (mesh, _sm) = peer_face(zid(0x0A));
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &mesh);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(8, "demo/key", true, true, true, false, true),
        );
        sink_c.reset();
        // Interest(Final) (C=0,F=0) cancels the stored interest.
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(8, "demo/key", false, false, false, false, false),
        );
        assert_eq!(
            sink_c.frame_count(),
            0,
            "an Interest(Final) gets no wire reply"
        );
        // A later matching mesh sub must NOT be pushed.
        declare_interest(&fwd, FaceId(0), "demo/**");
        assert_eq!(
            sink_c.frame_count(),
            0,
            "no push after the future interest was torn down"
        );
    }

    #[test]
    fn peer_non_aggregate_interest_replies_per_matching_sub_keyexpr() {
        // A non-AGGREGATE interest: one DeclareSubscriber per matching sub keyexpr
        // (the shared emit's explicit branch, sorted ascending), each keyed on the
        // SUB's OWN keyexpr, + a terminating DeclareFinal.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (mesh, _sm) = peer_face(zid(0x0A));
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(0), &mesh);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        declare_interest(&fwd, FaceId(0), "demo/a"); // two distinct mesh subs
        declare_interest(&fwd, FaceId(0), "demo/b");
        sink_c.reset();
        forward_one(
            &fwd,
            FaceId(1),
            interest_msg(2, "demo/**", true, false, false),
        );
        assert_eq!(
            sink_c.frame_count(),
            3,
            "one reply per matching sub (demo/a, demo/b) + a DeclareFinal"
        );
        let ke_of = |frame: &[u8]| match &forwarded_declare(frame).body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => match &d.keyexpr.body {
                WireexprOwnedVariant::WireexprLocal(w) => w.suffix.as_deref().map(str::to_string),
                _ => None,
            },
            other => panic!("expected a DeclSubscriber reply, got {other:?}"),
        };
        assert_eq!(
            (ke_of(&sink_c.frame_bytes(0)), ke_of(&sink_c.frame_bytes(1))),
            (Some("demo/a".to_string()), Some("demo/b".to_string())),
            "non-aggregate replies are keyed per-sub, sorted ascending",
        );
        assert!(matches!(
            forwarded_declare(&sink_c.frame_bytes(2)).body,
            DeclareOwnedVariant::CodecZenohDeclFinal(_)
        ));
    }

    /// The LITERAL keyexpr of the single forwarded UndeclareSubscriber's
    /// `ext_keyexpr` in a frame, or `None` if absent / still aliased — proves the
    /// B1b undeclare normalize landed on the wire (the retraction twin of
    /// [`forwarded_declare_keyexpr`]).
    fn forwarded_undeclare_keyexpr(frame: &[u8]) -> Option<String> {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let InboundFrame::Frame { payload, .. } =
            parse_inbound(frame).expect("parse forwarded frame")
        else {
            panic!("forwarded bytes are not a Frame");
        };
        let msgs = parse_frame_payload(&payload).expect("parse frame payload");
        match msgs.first() {
            Some(NetworkMessage::Declare(d)) => match &d.body {
                DeclareOwnedVariant::CodecZenohUndeclSubscriber(u) => {
                    wz_session_core::declare_ext_keyexpr::read_ext_keyexpr(u.extensions.as_ref())
                        .map(str::to_string)
                }
                _ => None,
            },
            other => panic!("expected a forwarded Declare, got {other:?}"),
        }
    }

    /// The LITERAL keyexpr of the single forwarded `UndeclareQueryable`'s
    /// `ext_wire_expr` in a frame — the query-plane twin of
    /// [`forwarded_undeclare_keyexpr`], proving the B1b retraction normalize
    /// landed on the wire for the queryable plane.
    fn forwarded_undeclare_queryable_keyexpr(frame: &[u8]) -> Option<String> {
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
                        .map(str::to_string)
                }
                _ => None,
            },
            other => panic!("expected a forwarded Declare, got {other:?}"),
        }
    }

    /// Decode the `LinkStateList` entries of a propagated OAM frame — the D4
    /// witness that the per-face re-flood carried the right `Details` split on
    /// the wire (a `new` node full, an `updated` node links-only).
    fn propagated_link_states(frame: &[u8]) -> Vec<wz_codecs::linkstate::LinkstateOwned> {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let InboundFrame::Frame { payload, .. } =
            parse_inbound(frame).expect("parse forwarded frame")
        else {
            panic!("forwarded bytes are not a Frame");
        };
        let msgs = parse_frame_payload(&payload).expect("parse frame payload");
        match msgs.first() {
            Some(NetworkMessage::Oam(oam)) => match try_parse_linkstate_oam(oam) {
                LinkstateOam::Decoded(list) => list.link_states,
                other => panic!("OAM did not decode as a link-state list: {other:?}"),
            },
            other => panic!("expected a propagated OAM, got {other:?}"),
        }
    }

    /// A PURE-ALIASED sourced `UndeclareSubscriber` whose `ext_keyexpr` references
    /// mapping `id` (no per-message suffix) — there is no aliased-undeclare
    /// builder (wz originates only literals), so a B1b test hand-builds the ext by
    /// reusing a literal undeclare scaffold and swapping in an aliased ZBuf body.
    fn aliased_undeclare(id: u8) -> DeclareOwned {
        use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
        use wz_codecs::ext_zbuf::ExtZbufOwned;
        let mut declare =
            wz_session_core::declare_build::build_undeclare_subscriber_with_keyexpr("x")
                .expect("build undeclare scaffold");
        let DeclareOwnedVariant::CodecZenohUndeclSubscriber(u) = &mut declare.body else {
            unreachable!("scaffold is an UndeclareSubscriber");
        };
        // ext_keyexpr ZBuf body [inner_header 0x02 (local, no suffix), VLE(id)] ->
        // resolves to table[id] (B1b). ext header 0x5f = id 0x0f | M 0x10 | ZBuf 0x40.
        let body: Vec<u8> = vec![0x02u8, id];
        u.extensions = Some(vec![ExtEntryOwned {
            header: 0x5f,
            body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                value_len: body.len() as u64,
                value: SceBytes::from_slice(&body).unwrap(),
            }),
        }]);
        declare
    }

    /// The query-plane twin of [`aliased_undeclare`]: a PURE-ALIASED sourced
    /// `UndeclareQueryable` whose `ext_wire_expr` references mapping `id` (no
    /// per-message suffix), hand-built by swapping an aliased ZBuf body into a
    /// literal scaffold (wz originates only literals).
    fn aliased_undeclare_queryable(id: u8) -> DeclareOwned {
        use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
        use wz_codecs::ext_zbuf::ExtZbufOwned;
        let mut declare =
            wz_session_core::declare_build::build_undeclare_queryable_with_keyexpr("x")
                .expect("build undeclare scaffold");
        let DeclareOwnedVariant::CodecZenohUndeclQueryable(u) = &mut declare.body else {
            unreachable!("scaffold is an UndeclareQueryable");
        };
        let body: Vec<u8> = vec![0x02u8, id];
        u.extensions = Some(vec![ExtEntryOwned {
            header: 0x5f,
            body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                value_len: body.len() as u64,
                value: SceBytes::from_slice(&body).unwrap(),
            }),
        }]);
        declare
    }

    // ── c3c-3 B1: data-plane keyexpr alias resolution (DeclKexpr) ────

    #[test]
    fn an_aliased_push_resolves_via_the_face_table_and_forwards_a_literal() {
        // Line A - S(self) - B; B subscribes to "demo/data" (literal). A first
        // declares a keyexpr alias (id 7 -> "demo/data") on its link, then sends a
        // PURE-ALIASED Push (id 7, no suffix). self resolves the alias via A's
        // link-local table, matches B's interest, and forwards toward B — but
        // NORMALIZED to a literal (id 0), since B's link does not share A's alias
        // table (c3c-3 B1).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05); // edge S<->B
        declare_interest(&fwd, FaceId(1), "demo/data"); // B subscribes (literal)
        let decl = wz_session_core::declare_build::build_declare_kexpr(7, "demo/data")
            .expect("build decl kexpr");
        fwd.absorb_keyexpr_declaration(FaceId(0), &decl);
        sink_a.reset();
        sink_b.reset();

        let aliased = wz_session_core::push_build::build_push_aliased(7, None, b"v")
            .expect("build aliased push");
        fwd.forward_push(
            FaceId(0),
            true,
            wz_session_core::qos::Priority::DEFAULT,
            &aliased,
        );

        assert_eq!(
            sink_b.frame_count(),
            1,
            "the aliased Push resolved and forwarded to the interested child B"
        );
        assert_eq!(sink_a.frame_count(), 0, "never back toward the source A");
        assert_eq!(
            forwarded_keyexpr(&sink_b.frame_bytes(0)),
            Some("demo/data".to_string()),
            "the forwarded keyexpr is normalized to a literal (B's link has no alias)",
        );
    }

    #[test]
    fn an_undeclared_alias_no_longer_resolves_so_the_push_drops() {
        // After the alias is retracted (UndeclKexpr), a Push still carrying it is
        // unresolvable and dropped — the table entry is gone.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sa) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(1), "demo/data");
        let decl = wz_session_core::declare_build::build_declare_kexpr(7, "demo/data")
            .expect("build decl kexpr");
        fwd.absorb_keyexpr_declaration(FaceId(0), &decl);
        let undecl = wz_session_core::declare_build::build_undeclare_kexpr(7);
        fwd.absorb_keyexpr_declaration(FaceId(0), &undecl);
        sink_b.reset();

        let aliased = wz_session_core::push_build::build_push_aliased(7, None, b"v")
            .expect("build aliased push");
        fwd.forward_push(
            FaceId(0),
            true,
            wz_session_core::qos::Priority::DEFAULT,
            &aliased,
        );
        assert_eq!(
            sink_b.frame_count(),
            0,
            "the retracted alias no longer resolves -> Push dropped"
        );
    }

    #[test]
    fn an_unknown_alias_push_is_dropped() {
        // A Push carrying an alias the peer never declared on this link is
        // unresolvable -> dropped (no misroute on a pre-declaration / bogus id).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sa) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(1), "demo/data");
        sink_b.reset();

        let aliased = wz_session_core::push_build::build_push_aliased(9, None, b"v")
            .expect("build aliased push"); // id 9 never declared on this link
        fwd.forward_push(
            FaceId(0),
            true,
            wz_session_core::qos::Priority::DEFAULT,
            &aliased,
        );
        assert_eq!(
            sink_b.frame_count(),
            0,
            "unknown alias -> dropped, not forwarded"
        );
    }

    #[test]
    fn an_aliased_push_with_a_per_message_suffix_resolves_to_the_composed_literal() {
        // m1 — the composed-alias path: A declares 7 -> "demo" (a prefix), then
        // sends a Push aliased 7 WITH a per-message suffix "/data". self resolves
        // it to "demo" + "/data" = "demo/data" via the table, matches B's interest,
        // and forwards the COMPOSED literal (proving the suffix survives normalize).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(1), "demo/data"); // B subscribes to the composed literal
        let decl =
            wz_session_core::declare_build::build_declare_kexpr(7, "demo").expect("decl kexpr");
        fwd.absorb_keyexpr_declaration(FaceId(0), &decl);
        sink_a.reset();
        sink_b.reset();

        let aliased = wz_session_core::push_build::build_push_aliased(7, Some("/data"), b"v")
            .expect("build composed-aliased push");
        fwd.forward_push(
            FaceId(0),
            true,
            wz_session_core::qos::Priority::DEFAULT,
            &aliased,
        );

        assert_eq!(
            sink_b.frame_count(),
            1,
            "the composed alias resolved and forwarded to B"
        );
        assert_eq!(
            forwarded_keyexpr(&sink_b.frame_bytes(0)),
            Some("demo/data".to_string()),
            "the per-message suffix survived: table[7] + suffix = demo + /data",
        );
    }

    // ── c3c-3 B1b: control-plane keyexpr alias resolution ────────────

    #[test]
    fn an_aliased_subscription_resolves_and_re_floods_a_literal() {
        // A declares alias 7 -> "demo/sub" on its link, then subscribes with a
        // PURE-ALIASED DeclareSubscriber (mapping id 7, no suffix). self resolves
        // it via A's table, registers the RESOLVED literal interest, and re-floods
        // a LITERAL declare to its child B (B1b, the control-plane twin of B1a's
        // forward_push normalize).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sa) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05); // edge S<->B (child)
        let decl = wz_session_core::declare_build::build_declare_kexpr(7, "demo/sub")
            .expect("build decl kexpr");
        fwd.absorb_keyexpr_declaration(FaceId(0), &decl);
        sink_b.reset();

        let aliased_sub = wz_session_core::declare_build::build_declare_subscriber(0, 7, None)
            .expect("build aliased declare subscriber");
        fwd.forward_subscription(FaceId(0), true, &aliased_sub);

        assert_eq!(
            fwd.interested("demo/sub"),
            vec![zid(0x0A)],
            "the aliased subscription resolved to the literal and registered A's interest",
        );
        assert_eq!(
            sink_b.frame_count(),
            1,
            "re-flooded the subscription to the child B"
        );
        assert_eq!(
            forwarded_declare_keyexpr(&sink_b.frame_bytes(0)),
            Some("demo/sub".to_string()),
            "the re-flooded DeclareSubscriber keyexpr is normalized to a literal",
        );
    }

    #[test]
    fn an_aliased_unsubscription_resolves_and_withdraws_the_interest() {
        // Symmetry: an aliased subscribe must be cleanly undoable by an aliased
        // unsubscribe. A aliases 7 -> "demo/sub", subscribes (aliased), then sends
        // a PURE-ALIASED UndeclareSubscriber (ext_keyexpr id 7). self resolves the
        // ext alias via A's table and withdraws the resolved literal interest.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sa) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        let decl = wz_session_core::declare_build::build_declare_kexpr(7, "demo/sub")
            .expect("build decl kexpr");
        fwd.absorb_keyexpr_declaration(FaceId(0), &decl);
        let aliased_sub = wz_session_core::declare_build::build_declare_subscriber(0, 7, None)
            .expect("build aliased declare subscriber");
        fwd.forward_subscription(FaceId(0), true, &aliased_sub);
        assert_eq!(
            fwd.interested("demo/sub"),
            vec![zid(0x0A)],
            "interest registered before the unsubscribe"
        );
        sink_b.reset(); // ignore the subscribe re-flood

        fwd.forward_unsubscription(FaceId(0), true, &aliased_undeclare(7));
        assert!(
            fwd.interested("demo/sub").is_empty(),
            "the aliased unsubscription resolved the ext alias and withdrew the interest",
        );
        // M2 — the retraction re-floods to the child B NORMALIZED to a literal
        // ext_keyexpr (B's link has no alias table), the withdrawal twin of the
        // subscribe-side literal re-flood assertion.
        assert_eq!(
            sink_b.frame_count(),
            1,
            "the retraction re-flooded to the child B"
        );
        assert_eq!(
            forwarded_undeclare_keyexpr(&sink_b.frame_bytes(0)),
            Some("demo/sub".to_string()),
            "the re-flooded UndeclareSubscriber ext_keyexpr is normalized to a literal",
        );
    }

    #[test]
    fn an_aliased_queryable_undeclare_resolves_and_withdraws_the_interest() {
        // Query-plane parity with an_aliased_unsubscription_...: an aliased queryable
        // declare must be cleanly undoable by an aliased UndeclareQueryable. A aliases
        // 7 -> "demo/q", declares (aliased), then sends a PURE-ALIASED
        // UndeclareQueryable (ext_keyexpr id 7). self resolves the ext alias via A's
        // table (the SAME resolve seam the sub twin uses, exercised for the qabl
        // plane) and withdraws the resolved literal interest, re-flooding a literal.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sa) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        let decl = wz_session_core::declare_build::build_declare_kexpr(7, "demo/q")
            .expect("build decl kexpr");
        fwd.absorb_keyexpr_declaration(FaceId(0), &decl);
        let aliased_qabl = wz_session_core::declare_build::build_declare_queryable(0, 7, None)
            .expect("build aliased declare queryable");
        fwd.forward_queryable(FaceId(0), true, &aliased_qabl);
        assert_eq!(
            fwd.interested_queryables("demo/q"),
            vec![zid(0x0A)],
            "queryable interest registered before the undeclare"
        );
        sink_b.reset(); // ignore the declare re-flood

        fwd.forward_queryable_undeclare(FaceId(0), true, &aliased_undeclare_queryable(7));
        assert!(
            fwd.interested_queryables("demo/q").is_empty(),
            "the aliased UndeclareQueryable resolved the ext alias and withdrew the interest",
        );
        assert_eq!(
            sink_b.frame_count(),
            1,
            "the retraction re-flooded to the child B"
        );
        assert_eq!(
            forwarded_undeclare_queryable_keyexpr(&sink_b.frame_bytes(0)),
            Some("demo/q".to_string()),
            "the re-flooded UndeclareQueryable ext_keyexpr is normalized to a literal",
        );
    }

    #[test]
    fn forwards_a_push_along_the_source_tree_to_a_child() {
        // Line A - S(self) - B (A and B each link only to S). B subscribes to
        // the Push's keyexpr. A Push self-originated by neighbour A (node_id 0)
        // floods along A's tree toward the interested subscriber B: self's only
        // child toward B is B, so it reaches B and never goes back to A.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // self -> idx 0
        let (face_a, sink_a) = peer_face(zid(0x0A)); // -> idx 1
        let (face_b, sink_b) = peer_face(zid(0x0B)); // -> idx 2
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05); // edge S<->B
        declare_interest(&fwd, FaceId(1), "demo/data"); // B subscribes
        sink_a.reset();
        sink_b.reset();

        fwd.forward_push(
            FaceId(0),
            true,
            wz_session_core::qos::Priority::DEFAULT,
            &data_push(),
        );

        assert_eq!(
            sink_b.frame_count(),
            1,
            "forwarded to the interested child B"
        );
        assert_eq!(sink_a.frame_count(), 0, "never back toward the source A");
        // Re-stamped with THIS node's psid for the source A (its idx, 1).
        assert_eq!(forwarded_source(&sink_b.frame_bytes(0)), 1);
        // m2 — the LITERAL path's keyexpr is byte-faithful through the B1
        // normalize (a literal in -> the same literal out, not corrupted).
        assert_eq!(
            forwarded_keyexpr(&sink_b.frame_bytes(0)),
            Some("demo/data".to_string()),
            "the literal keyexpr survives the forward unchanged",
        );
    }

    #[test]
    fn does_not_forward_a_push_to_a_face_outside_the_source_tree() {
        // self holds A (connected, edge S<->A) and B (held but never advertised
        // back, so it is an isolated node with no edge). B subscribes, yet a
        // Push from A still does not reach it: B is not in A's spanning tree, so
        // `directions_toward` finds no hop toward it (interest alone is not
        // enough — the subscriber must be reachable in the source's tree).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // only S<->A
        declare_interest(&fwd, FaceId(1), "demo/data"); // B subscribes (but isolated)
        sink_a.reset();
        sink_b.reset();

        fwd.forward_push(
            FaceId(0),
            true,
            wz_session_core::qos::Priority::DEFAULT,
            &data_push(),
        );
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // S -> idx 0
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
        fwd.forward_push(
            FaceId(0),
            true,
            wz_session_core::qos::Priority::DEFAULT,
            &push,
        );

        assert_eq!(sink_c.frame_count(), 1, "C is self's child in B's tree");
        assert_eq!(sink_a.frame_count(), 0, "A is the inbound face (excluded)");
        // Re-stamped with self's psid for the RESOLVED source B (its idx, 3).
        assert_eq!(forwarded_source(&sink_c.frame_bytes(0)), 3);
    }

    #[test]
    fn a_transit_sourced_push_delivered_to_a_client_subscriber_carries_source_zero() {
        // Regression guard for the Push-plane client-delivery fidelity fix (the DATA
        // twin of a_mesh_sourced_query_to_a_client_queryable_carries_routing_source_zero):
        // a Push delivered to a co-attached CLIENT subscriber must carry routing source 0
        // -- a client is a LEAF, not a graph node. reliteralize_push PRESERVES the inbound
        // push's ext_nodeid; at a TRANSIT node the inbound push carries a NON-ZERO mesh
        // source, and forwarding that to a client (e.g. a pico z_sub) is a protocol
        // violation the client rejects by CLOSING its transport. The mesh re-forward
        // branch above correctly RE-STAMPS a non-zero source (idx 3); ONLY the
        // client-delivery branch resets to 0.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // S -> idx 0
        let (face_a, sink_a) = peer_face(zid(0x0A)); // mesh transit neighbour -> idx 1
        let (client_sub, sink_cs) = peer_face_whatami(zid(0x0D), 2); // a CLIENT subscriber
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &client_sub);
        // A teaches self that psid 7 = B (a transit source two hops out).
        fwd.ingest_inbound_linkstate(
            FaceId(0),
            list(vec![
                entry(0, 1, 0x05, &[]),
                entry(1, 5, 0x0A, &[0, 7]),
                entry(7, 5, 0x0B, &[1]),
            ]),
        );
        client_declare_sub(&fwd, FaceId(1), 1, "demo/**"); // co-attached client subscribes
        sink_a.reset();
        sink_cs.reset();

        let mut push = data_push(); // demo/data
        set_push_source(&mut push, 7); // NON-ZERO transit source (A's psid for B)
                                       // Feed via forward() (not forward_push, the mesh-only leg) so the Push arm's
                                       // deliver_to_client_subscribers branch (linkstate_forward.rs:4841) runs.
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(push))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&outcome));

        assert_eq!(
            sink_cs.frame_count(),
            1,
            "the co-attached client subscriber receives the transit-sourced push"
        );
        assert_eq!(
            forwarded_source(&sink_cs.frame_bytes(0)),
            0,
            "the Push delivered to a CLIENT subscriber must carry routing source 0 (a \
             client is not a graph node); leaking the non-zero transit source closes a \
             real pico client's transport"
        );
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // S -> idx 0
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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

    // Gated on the same qos-byte subset as the emit/decode path
    // (build_push_outer_extensions / extract_qos): off-subset the ext is
    // neither emitted nor decoded, so the RealTime assertion would not hold.
    #[cfg(feature = "pubsub-qos")]
    #[test]
    fn publish_qos_emits_per_message_qos_ext_observable_as_sample_priority() {
        // R311y226 — a prioritized publish stamps the per-message Push qos ext
        // so a subscriber reads the band via Sample::priority(); a plain
        // (DEFAULT) publish emits no qos ext (wire-identity preserved). This is
        // the app-observable half of the publisher dual-write (the frame band
        // is the orthogonal transport half).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        declare_interest(&fwd, FaceId(0), "demo/data");

        // Prioritized: RealTime rides the wire and is app-observable, while the
        // self-origin source(0) + hoplimit stamps stay intact on the same chain.
        sink_a.reset();
        let sent = fwd
            .publish_qos(
                "demo/data",
                b"v",
                wz_session_core::qos::Priority::RealTime,
                true,
            )
            .expect("publish_qos");
        assert_eq!(sent, 1, "reached the one interested child");
        assert_eq!(sink_a.frame_count(), 1);
        assert_eq!(
            forwarded_priority(&sink_a.frame_bytes(0)),
            wz_session_core::qos::Priority::RealTime,
            "subscriber must observe the published RealTime band via Sample::priority()"
        );
        assert_eq!(
            forwarded_source(&sink_a.frame_bytes(0)),
            0,
            "self-origin source stamp intact alongside the qos ext"
        );

        // Plain publish (DEFAULT) -> the qos ext is SUPPRESSED (ABSENT on the
        // wire), not merely decoded as DEFAULT — asserting absence proves
        // wire-identity, where a `== DEFAULT` read would also pass on a
        // present raw-0x05 ext.
        sink_a.reset();
        fwd.publish("demo/data", b"v").expect("publish");
        assert_eq!(sink_a.frame_count(), 1);
        assert!(
            forwarded_qos(&sink_a.frame_bytes(0)).is_none(),
            "a plain publish carries NO qos ext (DEFAULT suppression, wire-identity)"
        );
    }

    #[test]
    fn publish_to_an_unsubscribed_keyexpr_sends_nothing() {
        // The any-interest gate on the publish path: with no subscriber for the
        // keyexpr, originating a Put reaches no face (and allocates no carrier).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        assert_eq!(fwd.data_seen(), 0);

        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(data_push()))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&outcome));
        assert_eq!(fwd.data_seen(), 1, "one received data Push counted");
    }

    // ── R311tt: §5.16 access control — ingress Put relay enforcement ──────

    /// Build an allow-default policy with one ingress-Put deny rule on
    /// `deny_keyexpr`, applied to every peer — the smallest real ACL.
    #[cfg(feature = "access-acl")]
    fn deny_put_policy(deny_keyexpr: &str) -> AclPolicy {
        AclPolicy::new(AclConfig {
            default_permission: Permission::Allow,
            rules: vec![AclRule {
                subject: SubjectSelector::Any,
                key_exprs: vec![deny_keyexpr.to_owned()],
                messages: vec![AclMessage::Put],
                flow: AclFlow::Ingress,
                permission: Permission::Deny,
            }],
        })
    }

    #[cfg(feature = "access-acl")]
    #[test]
    fn an_acl_deny_drops_an_inbound_put_before_relay() {
        // Line A - S(self) - B; B subscribes demo/data. With S configured to DENY
        // `demo/**` on ingress, a Put from A on demo/data is dropped at S: not
        // counted as received data, not relayed to the interested child B, and
        // witnessed by interceptor_dropped. The relay-admission point the forward() seam
        // gates (zenoh's IngressAclEnforcer over the mesh path).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05); // edge S<->B
        declare_interest(&fwd, FaceId(1), "demo/data"); // B subscribes
        sink_a.reset();
        sink_b.reset();
        fwd.set_interceptors(InterceptorConfig {
            acl: Some(deny_put_policy("demo/**")),
            ..Default::default()
        });

        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(data_push()))], // demo/data
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&outcome));

        assert_eq!(fwd.interceptor_dropped(), 1, "the denied Put is witnessed");
        assert_eq!(
            fwd.data_seen(),
            0,
            "a denied Put is not counted as received data"
        );
        assert_eq!(
            sink_b.frame_count(),
            0,
            "a denied Put is not relayed to the interested child"
        );
    }

    #[cfg(feature = "access-acl")]
    #[test]
    fn an_acl_allow_lets_an_inbound_put_relay() {
        // The same topology, but the deny rule targets a DIFFERENT subtree
        // (`admin/**`); the demo/data Put is admitted and relays to B exactly as
        // without ACL — proving the gate is selective, not a blanket block.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(1), "demo/data");
        sink_a.reset();
        sink_b.reset();
        fwd.set_interceptors(InterceptorConfig {
            acl: Some(deny_put_policy("admin/**")), // denies admin, not demo
            ..Default::default()
        });

        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(data_push()))], // demo/data
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&outcome));

        assert_eq!(
            fwd.interceptor_dropped(),
            0,
            "demo/data is not denied by an admin/** rule"
        );
        assert_eq!(fwd.data_seen(), 1, "the admitted Put is counted");
        assert_eq!(
            sink_b.frame_count(),
            1,
            "the admitted Put relays to the interested child"
        );
    }

    /// R311y219b — the JOINED-FACE DELIVERY fix: a Put arriving on an aggregated
    /// (joined) link's OWN FaceId — which is never `register`ed, since the joined
    /// link shares the session's primary face — is DROPPED at the `faces.get`
    /// delivery gate UNTIL [`register_joined`](FaceForwarder::register_joined) maps
    /// it to the primary. This is the gap y219's priority routing first exposes (a
    /// non-DEFAULT priority Put deliberately rides the secondary link). FaceId(0) is
    /// the registered primary; FaceId(1) is the joined secondary. Direct, RED-before
    /// / GREEN-after-`register_joined` proof of the resolve at `forward`'s top.
    #[test]
    fn joined_link_inbound_delivers_to_primary_face_local_subscriber_after_register_joined() {
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (primary, _sink) = peer_face(zid(0x0A));
        // Only the PRIMARY link is registered (the aggregate's one logical face);
        // the joined FaceId(1) is deliberately never `register`ed.
        fwd.register(FaceId(0), &primary);
        let delivered: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        {
            let d = delivered.clone();
            fwd.register_local_subscriber(
                "demo/data",
                Box::new(move |s: &dyn SampleView| d.borrow_mut().push(s.keyexpr().to_string())),
            )
            .expect("register the local subscriber");
        }
        let put = || DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(data_push()))], // demo/data
            has_ext: false,
            extensions: Vec::new(),
        };

        // BEFORE register_joined: a Put on the un-mapped joined FaceId(1) hits
        // `faces.get(1) == None` and is DROPPED before delivery (the pre-fix gap).
        fwd.forward(FaceId(1), IterationEvent::Poll(&put()));
        assert!(
            delivered.borrow().is_empty(),
            "an un-mapped joined-link Put is dropped at the delivery gate (the gap)"
        );

        // AFTER register_joined(1 -> 0): the SAME Put resolves to the primary face
        // and is delivered to the local subscriber (the fix).
        fwd.register_joined(FaceId(1), FaceId(0));
        fwd.forward(FaceId(1), IterationEvent::Poll(&put()));
        assert_eq!(
            delivered.borrow().as_slice(),
            &["demo/data".to_string()],
            "the joined-link Put is delivered to the primary face's subscriber after register_joined"
        );

        // deregister_joined drops the mapping -> the gate drops it again (no stale
        // mis-resolve after the joined link dies).
        fwd.deregister_joined(FaceId(1));
        delivered.borrow_mut().clear();
        fwd.forward(FaceId(1), IterationEvent::Poll(&put()));
        assert!(
            delivered.borrow().is_empty(),
            "after deregister_joined the mapping is gone -> the joined-link Put drops again"
        );
    }

    // R311y39 — config-DRIVEN proof: a typed `WzConfig` mutation re-installs the
    // interceptor chain on the LIVE forwarder, so the admit/deny verdict flips at
    // runtime. The ON arm proves the drive; the inert arm (below) proves the
    // `config-mutate-runtime` toggle is load-bearing (OFF = stored-but-not-applied).
    #[cfg(all(feature = "config-mutate-runtime", feature = "access-acl"))]
    #[test]
    fn wzconfig_reconfigure_drives_the_live_forwarder() {
        use crate::config::WzConfig;
        // Line A - S(self) - B; B subscribes demo/data.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(1), "demo/data");

        // An empty (admit-all) typed config installed at setup — same seam the
        // runtime reconfigure re-uses.
        let mut config = WzConfig::new();
        config.install_interceptors(&fwd);
        sink_a.reset();
        sink_b.reset();

        let put = || DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(data_push()))], // demo/data
            has_ext: false,
            extensions: Vec::new(),
        };

        // Phase 1 — no rule yet: the Put is admitted + relayed to B.
        fwd.forward(FaceId(0), IterationEvent::Poll(&put()));
        assert_eq!(fwd.data_seen(), 1, "phase 1: admitted before any rule");
        assert_eq!(fwd.interceptor_dropped(), 0, "phase 1: nothing dropped");
        assert_eq!(sink_b.frame_count(), 1, "phase 1: relayed to the child");

        // RUNTIME RECONFIGURE — mutate the typed config to DENY demo/**; under
        // config-mutate-runtime the live forwarder is re-driven.
        config.reconfigure_interceptors(
            InterceptorConfig {
                acl: Some(deny_put_policy("demo/**")),
                ..Default::default()
            },
            &fwd,
        );

        // Phase 2 — the SAME Put is now DROPPED (the live verdict flipped).
        sink_b.reset();
        fwd.forward(FaceId(0), IterationEvent::Poll(&put()));
        assert_eq!(
            fwd.interceptor_dropped(),
            1,
            "phase 2: denied after the LIVE reconfigure"
        );
        assert_eq!(
            fwd.data_seen(),
            1,
            "phase 2: a denied Put is not counted as received data"
        );
        assert_eq!(
            sink_b.frame_count(),
            0,
            "phase 2: not relayed after the live reconfigure"
        );
    }

    // R311y48 (§5.23 Phase 3b) — the config-WRITE merge pattern the demo's
    // adminspace handler drives: a partial write (set only the ACL slice) reads the
    // LIVE interceptor config via `WzConfig::interceptors()`, clones it, swaps the
    // one slice, and reconfigures the WHOLE — so the getter is the read leg of a
    // read-modify-write that never drops the unrelated interceptors. Here the
    // pre-write config already denies an UNRELATED key (`other/**`); the
    // config-write swaps the ACL to deny `demo/**`; the forwarder's verdict flips
    // to drop demo/data, proving the getter + clone-merge-reapply round-trips.
    #[cfg(all(feature = "config-mutate-runtime", feature = "access-acl"))]
    #[test]
    fn wzconfig_interceptors_getter_backs_the_config_write_merge() {
        use crate::config::WzConfig;
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(1), "demo/data");

        // Pre-write config denies an UNRELATED key; demo/data is admitted.
        let mut config = WzConfig::new().with_interceptors(InterceptorConfig {
            acl: Some(deny_put_policy("other/**")),
            ..Default::default()
        });
        config.install_interceptors(&fwd);
        sink_a.reset();
        sink_b.reset();

        let put = || DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(data_push()))], // demo/data
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&put()));
        assert_eq!(
            fwd.data_seen(),
            1,
            "pre-write: demo/data admitted (only other/** denied)"
        );

        // CONFIG-WRITE merge: read the live config via the getter, clone, swap
        // ONLY the ACL slice, reconfigure the whole — the demo handler's pattern.
        let mut merged = config.interceptors().clone();
        merged.acl = Some(deny_put_policy("demo/**"));
        config.reconfigure_interceptors(merged, &fwd);

        sink_b.reset();
        fwd.forward(FaceId(0), IterationEvent::Poll(&put()));
        assert_eq!(
            fwd.interceptor_dropped(),
            1,
            "post-write: demo/data denied after the getter-clone-merge-reapply"
        );
        assert_eq!(
            sink_b.frame_count(),
            0,
            "post-write: not relayed after the config-write merge"
        );
    }

    // R311y49 (§5.23) — the admin config GET is now OBSERVABLE under a runtime
    // reconfigure: to_admin_json's acl_deny array is [] before any ACL, then
    // carries the denied keyexpr after a config-write deny -> the read path
    // witnesses the flip (the counterpart to the data-plane drop), closing the
    // y45 read-at-open caveat on the READ path. Needs config-mutate-runtime (the
    // reconfigure is the live drive) + access-acl (the ACL slice exists).
    #[cfg(all(feature = "config-mutate-runtime", feature = "access-acl"))]
    #[test]
    fn wzconfig_to_admin_json_reflects_a_reconfigure() {
        use crate::config::WzConfig;
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let mut config = WzConfig::new();
        config.install_interceptors(&fwd);
        // Before any ACL: the deny list is empty (GET shows nothing denied).
        assert!(
            config.to_admin_json().contains(r#""acl_deny":[]"#),
            "pre-reconfigure admin JSON should carry an empty acl_deny: {}",
            config.to_admin_json()
        );
        // A config-write deny reconfigure -> the denied keyexpr now appears in
        // the GET view (observable on the SAME instance the forwarder drives).
        config.reconfigure_interceptors(
            InterceptorConfig {
                acl: Some(deny_put_policy("demo/**")),
                ..Default::default()
            },
            &fwd,
        );
        assert!(
            config.to_admin_json().contains(r#""acl_deny":["demo/**"]"#),
            "post-reconfigure admin JSON should carry the denied keyexpr: {}",
            config.to_admin_json()
        );
    }

    // R311y43 — §5.23 combined-node FOUNDATION proof (binding level): ONE WzConfig
    // BINDING both DRIVES the live forwarder (the deny verdict flips, as in the
    // test above) AND serves the admin read-at-open view (`to_admin_json`) — the
    // same `config` value backs both surfaces. This is the in-process foundation for
    // the §5.23 combined node; the NODE-level / wire composition (a routing peer
    // answering its own admin GET off this instance) is the deferred Phase-2 step
    // (the forwarder self-query dispatch bridge). The read assertion checks the
    // CONCRETE JSON (falsifiable on the serialization contract), not a
    // from_init_params self-comparison. R311y49 — the ACL is now in `to_admin_json`
    // (the `acl_deny` array), so the read view OBSERVES the SAME reconfigure that
    // drove the forwarder above: the binding's two surfaces stay mutually
    // consistent (a strengthening of the one-binding proof), while the
    // handshake-fixed read-at-open fields (batch/lease/whatami) stay invariant.
    #[cfg(all(feature = "config-mutate-runtime", feature = "access-acl"))]
    #[test]
    fn wzconfig_one_instance_drives_forwarder_and_serves_admin_read() {
        use crate::config::WzConfig;
        use wz_runtime_tokio_test_support::fixture_session_init_params;

        // Line A - S(self) - B; B subscribes demo/data (same topology as above).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(1), "demo/data");

        // ONE typed config, populated from the handshake params (so to_admin_json
        // carries real read-at-open values) + an empty admit-all interceptor set.
        let params = fixture_session_init_params();
        let mut config =
            WzConfig::from_init_params(&params).with_interceptors(InterceptorConfig::default());
        config.install_interceptors(&fwd);
        sink_a.reset();
        sink_b.reset();

        let put = || DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(data_push()))], // demo/data
            has_ext: false,
            extensions: Vec::new(),
        };

        // DRIVE surface — admit, then (after a deny reconfigure on the SAME
        // instance) drop: the live verdict flips.
        fwd.forward(FaceId(0), IterationEvent::Poll(&put()));
        assert_eq!(fwd.data_seen(), 1, "admitted before any rule");
        config.reconfigure_interceptors(
            InterceptorConfig {
                acl: Some(deny_put_policy("demo/**")),
                ..Default::default()
            },
            &fwd,
        );
        sink_b.reset();
        fwd.forward(FaceId(0), IterationEvent::Poll(&put()));
        assert_eq!(
            fwd.interceptor_dropped(),
            1,
            "denied after the live reconfigure"
        );
        assert_eq!(
            sink_b.frame_count(),
            0,
            "not relayed after the live reconfigure"
        );

        // READ surface — the SAME `config` binding that just drove the forwarder
        // serves the admin JSON. Assert the CONCRETE expected string (falsifiable:
        // catches key-order / whatami-string / numeric-format drift), NOT a
        // from_init_params self-comparison. R311y49 — the JSON leads with
        // `acl_deny:["demo/**"]`, the SAME deny the reconfigure above drove into
        // the forwarder. R311y54 — `acl_rules` now carries the FULL rule (the
        // `deny_put_policy` single Ingress Put deny on `demo/**`, subject any), the
        // detail complement to the deny summary: one binding, both surfaces,
        // mutually consistent. The fixture params resolve to batch_size 0 ->
        // effective 65535, lease_ms 10000, whatami Peer -> "peer".
        assert_eq!(
            config.to_admin_json(),
            r#"{"acl_default":"allow","acl_deny":["demo/**"],"acl_rules":[{"flow":"ingress","key_exprs":["demo/**"],"messages":["put"],"permission":"deny","subject":"any"}],"batch_size":65535,"lease_ms":10000,"whatami":"peer"}"#,
            "one binding: the config that drove the forwarder's deny also SHOWS it \
             in the admin read view (acl_default + acl_deny summary + acl_rules detail)"
        );
    }

    #[cfg(all(not(feature = "config-mutate-runtime"), feature = "access-acl"))]
    #[test]
    fn wzconfig_reconfigure_is_inert_without_config_mutate_runtime() {
        use crate::config::WzConfig;
        // Same topology; WITHOUT config-mutate-runtime the reconfigure stores the
        // new typed value (the introspection SSOT updates) but does NOT re-drive
        // the forwarder — the deny never takes effect (the inert-mirror arm).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(1), "demo/data");

        let mut config = WzConfig::new();
        config.install_interceptors(&fwd);
        sink_a.reset();
        sink_b.reset();

        let put = || DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(data_push()))],
            has_ext: false,
            extensions: Vec::new(),
        };

        fwd.forward(FaceId(0), IterationEvent::Poll(&put()));
        // Store a DENY rule, but with the feature OFF it is not re-applied.
        config.reconfigure_interceptors(
            InterceptorConfig {
                acl: Some(deny_put_policy("demo/**")),
                ..Default::default()
            },
            &fwd,
        );
        fwd.forward(FaceId(0), IterationEvent::Poll(&put()));

        assert_eq!(
            fwd.interceptor_dropped(),
            0,
            "inert: the deny never takes effect without config-mutate-runtime"
        );
        assert_eq!(fwd.data_seen(), 2, "inert: both Puts admitted");
        assert_eq!(sink_b.frame_count(), 2, "inert: both Puts relayed");
    }

    #[cfg(feature = "access-acl")]
    #[test]
    fn an_acl_deny_drops_an_inbound_declare_subscriber() {
        // Control-plane enforcement: S denies DeclareSubscriber on `admin/**`. A
        // sourced DeclareSubscriber from A on admin/sub is dropped at S — the
        // source's interest is NOT registered (so it never attracts a Push) and
        // it is witnessed by interceptor_dropped. A declaration on an unrelated keyexpr
        // still registers, proving the gate is action- and keyexpr-selective.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sa) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        fwd.set_interceptors(InterceptorConfig {
            acl: Some(AclPolicy::new(AclConfig {
                default_permission: Permission::Allow,
                rules: vec![AclRule {
                    subject: SubjectSelector::Any,
                    key_exprs: vec!["admin/**".to_owned()],
                    messages: vec![AclMessage::DeclareSubscriber],
                    flow: AclFlow::Ingress,
                    permission: Permission::Deny,
                }],
            })),
            ..Default::default()
        });

        let denied = build_declare_subscriber(0, 0, Some("admin/sub")).expect("build");
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Declare(Box::new(denied))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&outcome));
        assert_eq!(
            fwd.interceptor_dropped(),
            1,
            "the denied DeclareSubscriber is witnessed"
        );
        assert!(
            fwd.interested("admin/sub").is_empty(),
            "a denied subscription is not registered"
        );

        // An allowed keyexpr registers as usual (no extra deny).
        let allowed = build_declare_subscriber(0, 0, Some("demo/sub")).expect("build");
        let outcome2 = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Declare(Box::new(allowed))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&outcome2));
        assert_eq!(
            fwd.interested("demo/sub"),
            vec![zid(0x0A)],
            "an allowed subscription registers"
        );
        assert_eq!(
            fwd.interceptor_dropped(),
            1,
            "the allowed declaration adds no deny"
        );
    }

    #[cfg(feature = "access-acl")]
    #[test]
    fn an_acl_deny_drops_an_inbound_declare_queryable() {
        // §5.16 query ACL (R311ud) — the query-plane twin of
        // an_acl_deny_drops_an_inbound_declare_subscriber: S denies
        // DeclareQueryable on admin/**. A sourced DeclareQueryable from A on
        // admin/q is dropped at S — the source's queryable interest is NOT
        // registered (so a Query never routes toward it) and it is witnessed by
        // interceptor_dropped. A queryable on an unrelated keyexpr still registers.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sa) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        fwd.set_interceptors(InterceptorConfig {
            acl: Some(AclPolicy::new(AclConfig {
                default_permission: Permission::Allow,
                rules: vec![AclRule {
                    subject: SubjectSelector::Any,
                    key_exprs: vec!["admin/**".to_owned()],
                    messages: vec![AclMessage::DeclareQueryable],
                    flow: AclFlow::Ingress,
                    permission: Permission::Deny,
                }],
            })),
            ..Default::default()
        });

        let denied = build_declare_queryable(0, 0, Some("admin/q")).expect("build");
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Declare(Box::new(denied))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&outcome));
        assert_eq!(
            fwd.interceptor_dropped(),
            1,
            "the denied DeclareQueryable is witnessed"
        );
        assert!(
            fwd.interested_queryables("admin/q").is_empty(),
            "a denied queryable is not registered"
        );

        // An allowed keyexpr registers the queryable as usual.
        let allowed = build_declare_queryable(0, 0, Some("demo/q")).expect("build");
        let outcome2 = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Declare(Box::new(allowed))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&outcome2));
        assert_eq!(
            fwd.interested_queryables("demo/q"),
            vec![zid(0x0A)],
            "an allowed queryable registers"
        );
        assert_eq!(
            fwd.interceptor_dropped(),
            1,
            "the allowed declaration adds no deny"
        );
    }

    #[cfg(feature = "access-acl")]
    #[test]
    fn an_acl_deny_drops_an_inbound_query_before_routing() {
        // §5.16 query ACL (R311ud) — the routed-Query gate. C holds queryables for
        // admin/q AND demo/q; S denies the Query action on admin/**. A Query from
        // A on admin/q is dropped at S (witnessed, NOT routed to C, no pending
        // entry recorded), while a Query on demo/q is admitted and routed — the
        // gate is action- and keyexpr-selective.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // S
        let (face_a, sink_a) = peer_face(zid(0x0A)); // querier, FaceId 0
        let (face_c, sink_c) = peer_face(zid(0x0C)); // queryable, FaceId 1
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05);
        // Register C's queryables directly (bypassing admit — this isolates the
        // QUERY gate; the DeclareQueryable gate is the prior test).
        declare_queryable_interest(&fwd, FaceId(1), "admin/q");
        declare_queryable_interest(&fwd, FaceId(1), "demo/q");
        fwd.set_interceptors(InterceptorConfig {
            acl: Some(AclPolicy::new(AclConfig {
                default_permission: Permission::Allow,
                rules: vec![AclRule {
                    subject: SubjectSelector::Any,
                    key_exprs: vec!["admin/**".to_owned()],
                    messages: vec![AclMessage::Query],
                    flow: AclFlow::Ingress,
                    permission: Permission::Deny,
                }],
            })),
            ..Default::default()
        });
        sink_a.reset();
        sink_c.reset();

        // A Query on the DENIED keyexpr is dropped before routing.
        let denied = wz_session_core::request_build::build_request_query(7, 0, Some("admin/q"))
            .expect("build");
        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&DriverLoopOutcome::FramePayload {
                priority: wz_session_core::qos::Priority::DEFAULT,
                reliable: true,
                sn: 0,
                messages: vec![NetworkMessage::Request(Box::new(denied))],
                has_ext: false,
                extensions: Vec::new(),
            }),
        );
        assert_eq!(
            fwd.interceptor_dropped(),
            1,
            "the denied Query is witnessed"
        );
        assert_eq!(sink_c.frame_count(), 0, "a denied Query is not routed");
        assert_eq!(fwd.pending_len(), 0, "and records no pending return entry");

        // A Query on an ALLOWED keyexpr is routed toward the queryable.
        let allowed = wz_session_core::request_build::build_request_query(8, 0, Some("demo/q"))
            .expect("build");
        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&DriverLoopOutcome::FramePayload {
                priority: wz_session_core::qos::Priority::DEFAULT,
                reliable: true,
                sn: 0,
                messages: vec![NetworkMessage::Request(Box::new(allowed))],
                has_ext: false,
                extensions: Vec::new(),
            }),
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "an allowed Query routes to the queryable"
        );
        assert_eq!(fwd.pending_len(), 1, "and records a pending return entry");
        assert_eq!(
            fwd.interceptor_dropped(),
            1,
            "the allowed Query adds no deny"
        );
    }

    #[cfg(feature = "access-acl")]
    #[test]
    fn an_egress_acl_deny_blocks_a_relayed_reply() {
        // §5.16 query ACL EGRESS (R311ud) — the reply-relay gate (the Reply twin
        // of an_egress_acl_deny_blocks_a_relay_but_not_reception). S relays a Query
        // to a queryable (recording a pending return entry), then DENIES Reply on
        // demo/** egress: the queryable's Response is received but NOT relayed back
        // to the querier (the egress gate drops it, witnessed); the pending entry
        // SURVIVES (peek, not consumed — only a ResponseFinal frees it).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // S
        let (face_a, sink_a) = peer_face(zid(0x0A)); // querier, FaceId 0
        let (face_c, sink_c) = peer_face(zid(0x0C)); // queryable, FaceId 1
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05);
        declare_queryable_interest(&fwd, FaceId(1), "demo/q");
        sink_a.reset();
        sink_c.reset(); // drop the setup topology frames so frame 0 is the Query

        // Forward a Query to C (no ACL yet) -> records a pending entry + a qid.
        let query =
            wz_session_core::request_build::build_request_query(7, 0, Some("demo/q")).expect("q");
        fwd.forward_request(FaceId(0), true, &query);
        let qid = forwarded_request(&sink_c.frame_bytes(0)).rid;
        sink_a.reset();
        sink_c.reset();

        // Now DENY Reply on demo/** EGRESS.
        fwd.set_interceptors(InterceptorConfig {
            acl: Some(AclPolicy::new(AclConfig {
                default_permission: Permission::Allow,
                rules: vec![AclRule {
                    subject: SubjectSelector::Any,
                    key_exprs: vec!["demo/**".to_owned()],
                    messages: vec![AclMessage::Reply],
                    flow: AclFlow::Egress,
                    permission: Permission::Deny,
                }],
            })),
            ..Default::default()
        });

        // C replies; the Response would route back to A, but egress denies it.
        let response =
            wz_session_core::response_build::build_response_reply_literal(qid, "demo/q", b"hi")
                .expect("reply");
        fwd.forward_response(FaceId(1), true, &response);
        assert_eq!(
            sink_a.frame_count(),
            0,
            "the denied Reply is NOT relayed back to the querier"
        );
        assert_eq!(
            fwd.interceptor_dropped(),
            1,
            "the egress Reply deny is witnessed"
        );
        assert_eq!(
            fwd.pending_len(),
            1,
            "the pending entry survives (a Reply peeks, only a final frees)"
        );
    }

    #[cfg(feature = "access-acl")]
    #[test]
    fn an_egress_acl_deny_blocks_a_relay_but_not_reception() {
        // Egress enforcement — the gap ingress cannot close. S ALLOWS ingress but
        // DENIES egress on demo/**: a Put from A on demo/data is RECEIVED at S
        // (admitted at ingress, counted) yet NOT relayed to the interested child
        // B (egress denies sending it out the B face), and the egress drop is
        // witnessed. Egress gates what THIS node SENDS, keyed by the destination.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05); // edge S<->B
        declare_interest(&fwd, FaceId(1), "demo/data"); // B subscribes
        sink_a.reset();
        sink_b.reset();
        fwd.set_interceptors(InterceptorConfig {
            acl: Some(AclPolicy::new(AclConfig {
                default_permission: Permission::Allow,
                rules: vec![AclRule {
                    subject: SubjectSelector::Any,
                    key_exprs: vec!["demo/**".to_owned()],
                    messages: vec![AclMessage::Put],
                    flow: AclFlow::Egress, // egress only — ingress is allowed
                    permission: Permission::Deny,
                }],
            })),
            ..Default::default()
        });

        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(data_push()))], // demo/data
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&outcome));

        assert_eq!(fwd.data_seen(), 1, "the Put is received (ingress allows)");
        assert_eq!(
            sink_b.frame_count(),
            0,
            "egress denies the relay out to the interested child"
        );
        assert_eq!(fwd.interceptor_dropped(), 1, "the egress drop is witnessed");
    }

    #[cfg(all(feature = "access-acl", feature = "access-downsampling"))]
    #[test]
    fn downsampling_composes_with_acl_on_the_interceptor_chain() {
        // The chain runs BOTH a (permissive) ACL enforcer and a downsampler —
        // proving it is genuinely composable. Topology A-S-B, B subscribes
        // demo/data. Two back-to-back Puts on demo/data: the first is admitted
        // (relays to B); the second (microseconds later, well inside the 1s
        // interval) is rate-limited by the downsampler. Downsampling runs on BOTH
        // flows (zenoh default), so the second is dropped at INGRESS — it is not
        // even counted as received — while the ACL admits both.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(1), "demo/data");
        sink_a.reset();
        sink_b.reset();
        fwd.set_interceptors(InterceptorConfig {
            acl: Some(AclPolicy::new(AclConfig::allow_all())), // present but permissive
            downsampling: vec![DownsamplingRule {
                key_exprs: vec!["demo/**".to_owned()],
                min_interval: std::time::Duration::from_secs(1),
            }],
            ..Default::default()
        });

        let mk = || DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(data_push()))], // demo/data
            has_ext: false,
            extensions: Vec::new(),
        };
        let o1 = mk();
        fwd.forward(FaceId(0), IterationEvent::Poll(&o1));
        let o2 = mk();
        fwd.forward(FaceId(0), IterationEvent::Poll(&o2));

        assert_eq!(
            fwd.data_seen(),
            1,
            "only the first is counted; the second is dropped at ingress"
        );
        assert_eq!(
            sink_b.frame_count(),
            1,
            "the first relayed; the second is rate-limited by the downsampler"
        );
        assert_eq!(
            fwd.interceptor_dropped(),
            1,
            "the downsampling drop is witnessed"
        );
    }

    #[cfg(all(feature = "access-acl", feature = "access-downsampling"))]
    #[test]
    fn downsampling_precedes_the_acl_and_accounts_a_denied_message() {
        // Locks the FIXED zenoh factory order (downsampling BEFORE access-control,
        // `interceptor_factories` mod.rs:133-134) — observable because the chain's
        // `admit` short-circuits (`all`) and the downsampler records its rate timer
        // only on the messages IT admits. S denies `demo/secret` (ingress Put) but
        // rate-limits all of `demo/**` at 1s; B subscribes demo/data.
        //
        // Two back-to-back Puts from A: (1) demo/secret — the downsampler runs
        // FIRST, admits it and stamps the demo/** rule timer, THEN the ACL denies
        // it; (2) demo/data (allowed by the ACL) arrives inside the 1s interval, so
        // the downsampler — already stamped by the denied demo/secret — drops it
        // before the ACL is even consulted. Net: the allowed demo/data is rate-
        // limited BECAUSE the denied demo/secret consumed the rule's budget, which
        // is zenoh-faithful (zenoh's downsampler likewise stamps a message its ACL
        // later denies). Under the old ACL-first order demo/secret would short-
        // circuit at the ACL, the downsampler would never see it, and demo/data
        // would be the first message it saw — and would relay. So this asserts the
        // new ordering, not the old.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(1), "demo/data");
        sink_a.reset();
        sink_b.reset();
        fwd.set_interceptors(InterceptorConfig {
            acl: Some(AclPolicy::new(AclConfig {
                default_permission: Permission::Allow,
                rules: vec![AclRule {
                    subject: SubjectSelector::Any,
                    key_exprs: vec!["demo/secret".to_owned()],
                    messages: vec![AclMessage::Put],
                    flow: AclFlow::Ingress,
                    permission: Permission::Deny,
                }],
            })),
            downsampling: vec![DownsamplingRule {
                key_exprs: vec!["demo/**".to_owned()],
                min_interval: std::time::Duration::from_secs(1),
            }],
            ..Default::default()
        });

        // (1) demo/secret — downsampler stamps the rule timer, ACL then denies.
        let secret = build_push_literal("demo/secret", b"x").expect("build");
        let o1 = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(secret))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&o1));

        // (2) demo/data — allowed by the ACL, but inside the interval the timer the
        // denied demo/secret already stamped causes the downsampler to drop it.
        let o2 = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(data_push()))], // demo/data
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&o2));

        assert_eq!(
            fwd.data_seen(),
            0,
            "demo/data is rate-limited: the denied demo/secret already consumed the \
             demo/** rule budget (downsampling ran before the ACL, zenoh order)"
        );
        assert_eq!(
            sink_b.frame_count(),
            0,
            "so nothing relays to the interested child"
        );
        assert_eq!(
            fwd.interceptor_dropped(),
            2,
            "two drops: demo/secret by the ACL, demo/data by the downsampler"
        );
    }

    #[cfg(feature = "access-quota")]
    #[test]
    fn low_pass_drops_an_oversized_put_on_a_governed_keyexpr() {
        // The §5.16 access-quota realization (a per-key payload-size cap). S caps
        // demo/** payloads at 8 bytes. Low-pass runs on BOTH flows (zenoh default),
        // so a 32-byte Put from A on demo/data is dropped at INGRESS — not counted,
        // not relayed to the interested child B — and witnessed; a small Put still
        // flows through and relays.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(1), "demo/data");
        sink_a.reset();
        sink_b.reset();
        fwd.set_interceptors(InterceptorConfig {
            low_pass: vec![LowPassRule {
                key_exprs: vec!["demo/**".to_owned()],
                max_payload_size: 8,
            }],
            ..Default::default()
        });

        let big = build_push_literal("demo/data", &[0u8; 32]).expect("build");
        let o1 = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(big))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&o1));
        assert_eq!(
            fwd.data_seen(),
            0,
            "the oversized Put is dropped at ingress, not even counted"
        );
        assert_eq!(sink_b.frame_count(), 0, "and not relayed");
        assert_eq!(
            fwd.interceptor_dropped(),
            1,
            "the low-pass drop is witnessed"
        );

        // A small Put (under the limit) still relays.
        let small = build_push_literal("demo/data", b"hi").expect("build"); // 2 bytes
        let o2 = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(small))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&o2));
        assert_eq!(sink_b.frame_count(), 1, "a Put under the limit relays");
        assert_eq!(fwd.interceptor_dropped(), 1, "the small Put adds no drop");
    }

    #[test]
    fn drops_a_transit_push_whose_source_resolves_to_self() {
        // R311rj — a neighbour stamps a node_id that maps (in OUR inbound link's
        // space) to OUR OWN zid: a malformed / looped-back message. Self can
        // never be a transit source on a message arriving at us, and re-stamping
        // it would hit local psid 0 = the self-originated sentinel (misroute).
        // forward_push must DROP it, not flood it to self's tree children.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // self
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
        fwd.forward_push(
            FaceId(0),
            true,
            wz_session_core::qos::Priority::DEFAULT,
            &push,
        );
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
        fwd.forward_push(
            FaceId(0),
            true,
            wz_session_core::qos::Priority::DEFAULT,
            &push,
        );
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
        fwd.forward_push(
            FaceId(0),
            true,
            wz_session_core::qos::Priority::DEFAULT,
            &push,
        );
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
        fwd.forward_push(
            FaceId(0),
            true,
            wz_session_core::qos::Priority::DEFAULT,
            &push,
        );
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
        fwd.forward_push(
            FaceId(0),
            true,
            wz_session_core::qos::Priority::DEFAULT,
            &push,
        );
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
            fwd.forward_push(
                FaceId(1),
                true,
                wz_session_core::qos::Priority::DEFAULT,
                &push,
            ); // inbound = C (the source)
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
        let recomputes_before = fwd.recomputes();

        fwd.deregister(FaceId(0));
        // D3 — remove_link prunes A INLINE (dropping S-A detaches A, and C
        // transitively, since both are reachable only through the dead link),
        // and purges any interest they held (zenoh remove_link ->
        // remove_detached_nodes + pubsub_remove_node).
        assert!(
            fwd.net.borrow().get_node(&zid(0x0A)).is_none(),
            "A is pruned the moment its link drops"
        );
        assert!(
            fwd.net.borrow().get_node(&zid(0x0C)).is_none(),
            "C is pruned transitively (only reachable via A)"
        );
        // D2c — the tree RECOMPUTE is still deferred (only the prune is inline):
        // the recompute counter has not advanced until the tick flushes it.
        assert_eq!(
            fwd.recomputes(),
            recomputes_before,
            "deregister scheduled but did not run the recompute"
        );
        fwd.tick(); // flush the coalesced recompute
        assert_eq!(
            fwd.recomputes(),
            recomputes_before + 1,
            "the tick ran exactly one coalesced recompute"
        );
        assert!(
            fwd.tree_children_of(&zid(0x0B)).is_empty(),
            "after the recompute B's tree has no child of self (A/C are gone)"
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // S -> idx 0
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

        fwd.forward_push(
            FaceId(0),
            true,
            wz_session_core::qos::Priority::DEFAULT,
            &data_push(),
        ); // Push from A (source A)
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // S
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

        fwd.forward_push(
            FaceId(0),
            true,
            wz_session_core::qos::Priority::DEFAULT,
            &data_push(),
        );
        assert_eq!(
            sink_b.frame_count(),
            1,
            "forwarded to the interested child B"
        );
        assert_eq!(sink_c.frame_count(), 0, "NOT to the uninterested child C");
        assert_eq!(sink_a.frame_count(), 0, "not back to the source A");
    }

    /// R311y221 — a relay hop preserves the band the frame arrived with: S relays
    /// a Push from A to the interested child B through `forward_push`, and with B
    /// QoS-negotiated the egress frame carries `ext_qos` = the RECEIVED band, not a
    /// DEFAULT re-clamp (the faithful mirror of zenoh's `route_data` copying
    /// `msg.ext_qos` onto egress, `net/routing/dispatcher/pubsub.rs`). Before the
    /// y221 fix the transit routed through the DEFAULT `fan_out`, so the RealTime
    /// assertion below would read DEFAULT and fail.
    #[cfg(feature = "transport-qos")]
    #[test]
    fn forward_push_preserves_the_received_band_on_transit() {
        use crate::session_glue::{parse_inbound, InboundFrame};

        // Decode the band off a forwarded frame (the RX projection wz decodes
        // feature-agnostically from `ext_qos`, `inbound.rs`).
        fn egress_band(frame: &[u8]) -> Priority {
            let InboundFrame::Frame { priority, .. } =
                parse_inbound(frame).expect("parse forwarded frame")
            else {
                panic!("forwarded bytes are not a Frame");
            };
            priority
        }

        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // S (relay)
        let (face_a, _sink_a) = peer_face(zid(0x0A)); // source
        let (face_b, sink_b) = peer_face(zid(0x0B)); // interested child
                                                     // B must be QoS-negotiated, else the per-face send clamps every
                                                     // Frame to DEFAULT (`dispatch_push`) and the band cannot be observed.
        face_b.set_qos_offer(true);
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S-A
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05); // edge S-B
        declare_interest(&fwd, FaceId(1), "demo/data");

        // A RealTime Put relayed through S must reach B still banded RealTime.
        sink_b.reset();
        fwd.forward_push(FaceId(0), true, Priority::RealTime, &data_push());
        assert_eq!(sink_b.frame_count(), 1, "relayed to the interested child B");
        assert_eq!(
            egress_band(&sink_b.frame_bytes(0)),
            Priority::RealTime,
            "transit PRESERVES the received band — not re-clamped to DEFAULT"
        );

        // Negative control: a DEFAULT transit stays DEFAULT (byte-identical to the
        // pre-y221 `fan_out` path).
        sink_b.reset();
        fwd.forward_push(FaceId(0), true, Priority::DEFAULT, &data_push());
        assert_eq!(
            sink_b.frame_count(),
            1,
            "the DEFAULT transit still relays to B"
        );
        assert_eq!(
            egress_band(&sink_b.frame_bytes(0)),
            Priority::DEFAULT,
            "a DEFAULT transit stays DEFAULT"
        );
    }

    #[cfg(feature = "pubsub-qos")]
    #[test]
    fn forward_push_preserves_the_per_message_qos_ext_on_transit() {
        // R311y226 — a transit re-forward (reliteralize_push, clone-based) must
        // preserve the RECEIVED Push's per-message qos ext, so a downstream
        // subscriber reads the ORIGINAL publisher's band via Sample::priority().
        // This is DISTINCT from the frame conduit band (covered by
        // forward_push_preserves_the_received_band_on_transit): the per-message
        // ext rides the Push payload and is not subject to the is_qos() frame
        // clamp, so B needs no qos negotiation to observe it.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(1), "demo/data");

        // A received Put carrying a per-message qos ext (RealTime).
        let received = build_push_literal_with_meta(
            "demo/data",
            b"payload",
            &wz_session_core::metadata::PushMetadata {
                qos: Some(wz_session_core::sample::QosLevel::from_parts(
                    wz_session_core::qos::Priority::RealTime,
                    wz_session_core::qos::CongestionControl::Drop,
                    false,
                )),
                ..Default::default()
            },
        )
        .expect("build received push with qos ext");

        sink_b.reset();
        fwd.forward_push(
            FaceId(0),
            true,
            wz_session_core::qos::Priority::DEFAULT,
            &received,
        );
        assert_eq!(sink_b.frame_count(), 1, "relayed to the interested child B");
        assert_eq!(
            forwarded_priority(&sink_b.frame_bytes(0)),
            wz_session_core::qos::Priority::RealTime,
            "transit preserves the received per-message qos ext (Sample::priority)"
        );
    }

    #[test]
    fn forward_push_with_no_interest_forwards_nothing() {
        // The any-interest gate: a Push whose keyexpr no peer subscribes to is
        // not forwarded at all (the pre-atom4 broadcast would have flooded B).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        sink_a.reset();
        sink_b.reset();

        fwd.forward_push(
            FaceId(0),
            true,
            wz_session_core::qos::Priority::DEFAULT,
            &data_push(),
        );
        assert_eq!(sink_b.frame_count(), 0, "no subscriber -> no forward");
        assert_eq!(sink_a.frame_count(), 0, "not back to the source either");
    }

    #[test]
    fn forward_push_to_two_interested_subtrees() {
        // R311rv review coverage — multi-direction fan-out at the forward level
        // (the graph unit covers the split; this proves forward_push honours
        // it). S has neighbours A, B, C; a Push from A has B and C both as self's
        // children. BOTH subscribe -> the filter forwards to BOTH.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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

        fwd.forward_push(
            FaceId(0),
            true,
            wz_session_core::qos::Priority::DEFAULT,
            &data_push(),
        );
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
        fwd.forward_push(
            FaceId(0),
            true,
            wz_session_core::qos::Priority::DEFAULT,
            &push,
        );
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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

        fwd.forward_push(
            FaceId(0),
            true,
            wz_session_core::qos::Priority::DEFAULT,
            &data_push(),
        );
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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

    #[test]
    fn deregister_keeps_a_still_reachable_peers_interest() {
        // The correctness boundary D3 corrects: a face going down must purge a
        // subscriber's interest ONLY if that subscriber LEFT the mesh. Here A is
        // reachable by two paths — the direct face S-A and the relay path S-C-A —
        // so dropping the direct S-A face leaves A still reachable via C. A is
        // therefore NOT pruned and its interest MUST survive (self still forwards
        // toward A, now via C). zenoh purges only remove_link's detached set; the
        // former unconditional peer purge wrongly dropped a still-reachable peer.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sa) = peer_face(zid(0x0A));
        let (face_c, _sc) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        // A advertises self back (edge S-A). C advertises self AND A, giving A a
        // second path S-C-A (edges S-C and C-A).
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        fwd.ingest_inbound_linkstate(
            FaceId(1),
            list(vec![
                entry(0, 1, 0x05, &[]),
                entry(1, 5, 0x0C, &[0, 2]), // C -> S, A
                entry(2, 5, 0x0A, &[0, 1]), // A -> S, C
            ]),
        );
        declare_interest(&fwd, FaceId(0), "demo/data"); // A subscribes
        assert_eq!(
            fwd.interested("demo/data"),
            vec![zid(0x0A)],
            "A's interest registered"
        );

        fwd.deregister(FaceId(0)); // drop the DIRECT S-A face
        assert!(
            fwd.net.borrow().get_node(&zid(0x0A)).is_some(),
            "A is still reachable via C, so it is NOT pruned"
        );
        assert_eq!(
            fwd.interested("demo/data"),
            vec![zid(0x0A)],
            "A's interest survives — it is still a reachable subscriber (via C)"
        );
    }

    // ── c3c-3 atom3b-ii: subscription declaration propagation ────────

    #[test]
    fn declare_subscription_floods_to_tree_children() {
        // self(S) declares its OWN interest: floods a sourced DeclareSubscriber
        // to self's children in self's tree (here the single neighbour A).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // self S
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sa) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);

        let declare = build_declare_subscriber(0, 0, Some("demo/sub")).expect("build");
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sa) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        declare_interest(&fwd, FaceId(0), "demo/sub"); // A is interested
        assert_eq!(fwd.interested("demo/sub"), vec![zid(0x0A)], "A registered");

        let undeclare = build_undeclare_subscriber_with_keyexpr("demo/sub").expect("build");
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // self S
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // self S
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // self S
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // self S
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // S
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
            priority: wz_session_core::qos::Priority::DEFAULT,
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // S
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
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
        let default = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        assert_eq!(
            default.tick_period(),
            Some(LinkstateForwarder::DEFAULT_TREES_DELAY)
        );
        let tuned = LinkstateForwarder::with_trees_delay(
            zid(0x05),
            WhatAmI::Peer,
            Duration::from_millis(5),
        );
        assert_eq!(tuned.tick_period(), Some(Duration::from_millis(5)));
    }

    // ── §5.15/§5.16 query routing atom 1: queryable interest propagation ──

    /// Send a sourced `DeclareQueryable` for `keyexpr` into the forwarder on
    /// `face` — the queryable-plane twin of [`declare_interest`].
    fn declare_queryable_interest(fwd: &LinkstateForwarder, face: FaceId, keyexpr: &str) {
        let declare = build_declare_queryable(0, 0, Some(keyexpr)).expect("build qabl");
        fwd.forward_queryable(face, true, &declare);
    }

    /// Declare a queryable for `keyexpr` from the peer reached by `source_node_id`
    /// on `face` (node_id 0 = the direct neighbour IS the source; non-zero = a
    /// transit source resolved through the face's psid table, as in
    /// forward_queryable_floods_to_tree_children_and_registers), carrying a
    /// QueryableInfo with the given `complete` flag — the BestMatching input
    /// (atom 3) that [`declare_queryable_interest`]'s DEFAULT (incomplete) form
    /// omits.
    fn declare_queryable_complete(
        fwd: &LinkstateForwarder,
        face: FaceId,
        keyexpr: &str,
        source_node_id: u16,
        complete: bool,
    ) {
        let mut declare = build_declare_queryable(0, 0, Some(keyexpr)).expect("build qabl");
        if source_node_id != 0 {
            set_declare_source(&mut declare, source_node_id);
        }
        wz_session_core::declare_build::set_declare_queryable_info(
            &mut declare,
            wz_session_core::queryable_info::QueryableInfo {
                complete,
                distance: 0,
            },
        );
        fwd.forward_queryable(face, true, &declare);
    }

    /// The LITERAL keyexpr of the single forwarded DeclareQueryable in a frame,
    /// or `None` if it is not a DeclareQueryable / is still aliased — the
    /// query-plane twin of [`forwarded_declare_keyexpr`], proving the re-flooded
    /// queryable was normalized to a literal AND that a QUERYABLE (not a
    /// subscriber) carrier went on the wire.
    fn forwarded_declare_queryable_keyexpr(frame: &[u8]) -> Option<String> {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let InboundFrame::Frame { payload, .. } =
            parse_inbound(frame).expect("parse forwarded frame")
        else {
            panic!("forwarded bytes are not a Frame");
        };
        let msgs = parse_frame_payload(&payload).expect("parse frame payload");
        match msgs.first() {
            Some(NetworkMessage::Declare(d)) => match &d.body {
                DeclareOwnedVariant::CodecZenohDeclQueryable(q) => match &q.keyexpr.body {
                    WireexprOwnedVariant::WireexprLocal(w) if w.id == 0 => {
                        w.suffix.as_deref().map(str::to_string)
                    }
                    _ => None,
                },
                _ => None,
            },
            other => panic!("expected a forwarded Declare, got {other:?}"),
        }
    }

    /// The QueryableInfo carried on the single forwarded DeclareQueryable in a
    /// frame — the BestMatching completeness the producer / re-flood stamped (atom
    /// 4). Reads the body ext through the production read_queryable_info SSOT, so
    /// an OMITTED ext decodes to the DEFAULT (incomplete) QueryableInfo.
    fn forwarded_declare_queryable_info(
        frame: &[u8],
    ) -> wz_session_core::queryable_info::QueryableInfo {
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
                    wz_session_core::queryable_info::read_queryable_info(q.extensions.as_ref())
                }
                _ => panic!("forwarded Declare is not a DeclareQueryable"),
            },
            other => panic!("expected a forwarded Declare, got {other:?}"),
        }
    }

    /// Parse the single forwarded DeclareQueryable in a frame back into an owned
    /// Declare — for an e2e hand-off where one forwarder's flooded declaration is
    /// fed into another forwarder's forward_queryable (atom 4 producer -> relay).
    fn parse_forwarded_declare(frame: &[u8]) -> DeclareOwned {
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
    fn forward_queryable_floods_to_tree_children_and_registers() {
        // The query-plane twin of
        // forward_subscription_resolves_a_transit_source_from_the_link_psid: a
        // sourced DeclareQueryable arrives on A's face with a NON-zero node_id =
        // A's psid for B (a transit declaration). Self resolves it to source B,
        // registers B's QUERYABLE interest, re-floods along B's tree to child C
        // re-stamped — AND the wire carrier is a DeclareQueryable, not a
        // DeclareSubscriber. The subscription plane stays empty (separate tables).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // S -> idx 0
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_c, sink_c) = peer_face(zid(0x0C));
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

        let mut declare = build_declare_queryable(0, 0, Some("demo/q")).expect("build");
        set_declare_source(&mut declare, 7); // node_id 7 = A's psid for B
        fwd.forward_queryable(FaceId(0), true, &declare);

        assert_eq!(
            fwd.interested_queryables("demo/q"),
            vec![zid(0x0B)],
            "registered the RESOLVED transit source B's queryable, not neighbour A",
        );
        assert!(
            fwd.interested("demo/q").is_empty(),
            "the SUBSCRIPTION plane is untouched — separate interest tables",
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "re-flooded to self's child C in B's tree"
        );
        assert_eq!(sink_a.frame_count(), 0, "A is the inbound face (excluded)");
        assert_eq!(
            forwarded_declare_source(&sink_c.frame_bytes(0)),
            3,
            "re-stamped with self's psid for the resolved source B (its idx, 3)"
        );
        assert_eq!(
            forwarded_declare_queryable_keyexpr(&sink_c.frame_bytes(0)).as_deref(),
            Some("demo/q"),
            "the wire carrier is a literal DeclareQueryable (not a subscriber)",
        );
    }

    #[test]
    fn forward_queryable_stores_completeness_and_re_floods_only_on_a_value_change() {
        // R311ul: forward_queryable READS the QueryableInfo from the
        // DeclareQueryable body + stores it per-(key,peer), and the value-diff
        // change-gate re-floods on a CHANGE (a complete flip) but not on a
        // redundant re-declare. Observable via the re-flood to the tree child: an
        // ingest that IGNORED the info would not detect the complete flip and so
        // would NOT re-flood at step 3 — the test would fail.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A)); // source-side (A = the source)
        let (face_c, sink_c) = peer_face(zid(0x0C)); // re-flood child
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S-A
        advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05); // edge S-C
        sink_a.reset();
        sink_c.reset();

        // A DeclareQueryable from A (node_id 0 = A-originated) carrying a
        // QueryableInfo with the given `complete` flag.
        let declare_with = |complete: bool| {
            let mut d = build_declare_queryable(0, 0, Some("demo/q")).expect("build");
            wz_session_core::declare_build::set_declare_queryable_info(
                &mut d,
                wz_session_core::queryable_info::QueryableInfo {
                    complete,
                    distance: 0,
                },
            );
            d
        };

        // 1) First declare (complete) -> registered + re-flooded to child C.
        fwd.forward_queryable(FaceId(0), true, &declare_with(true));
        assert_eq!(
            sink_c.frame_count(),
            1,
            "a new queryable re-floods to the child"
        );
        sink_c.reset();

        // 2) Redundant re-declare of the SAME complete value -> NO re-flood.
        fwd.forward_queryable(FaceId(0), true, &declare_with(true));
        assert_eq!(
            sink_c.frame_count(),
            0,
            "an unchanged re-declare does not re-flood (value-diff gate)"
        );

        // 3) complete flips true -> false: a real value change -> re-flood (proves
        //    the ingest READ the per-peer info; a DEFAULT-only ingest sees no
        //    change here and would not re-flood).
        fwd.forward_queryable(FaceId(0), true, &declare_with(false));
        assert_eq!(
            sink_c.frame_count(),
            1,
            "a complete-flag flip re-floods (the value-diff gate fired)"
        );
    }

    #[test]
    fn forward_queryable_re_floods_the_completeness_downstream() {
        // R311uq — the multi-hop carry: forward_queryable re-floods the source's
        // QueryableInfo (not a clean declaration) to its tree child, so a relay N
        // hops from the queryable learns its completeness and can route to it by
        // GRAPH distance. S receives a COMPLETE DeclareQueryable sourced at B
        // (transit via A), re-floods to child C — the carrier must carry
        // complete=true (a clean re-flood would lose it, and C's BestMatching
        // would fall back to All).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_c, sink_c) = peer_face(zid(0x0C));
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
        advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05);
        sink_a.reset();
        sink_c.reset();

        // A COMPLETE DeclareQueryable sourced at B (node_id 7 = A's psid for B).
        let mut declare = build_declare_queryable(0, 0, Some("demo/q")).expect("build");
        set_declare_source(&mut declare, 7);
        wz_session_core::declare_build::set_declare_queryable_info(
            &mut declare,
            wz_session_core::queryable_info::QueryableInfo {
                complete: true,
                distance: 0,
            },
        );
        fwd.forward_queryable(FaceId(0), true, &declare);

        assert_eq!(sink_c.frame_count(), 1, "re-flooded to child C in B's tree");
        assert!(
            forwarded_declare_queryable_info(&sink_c.frame_bytes(0)).complete,
            "the re-flooded DeclareQueryable carries the source's complete=true downstream",
        );
    }

    #[test]
    fn re_advertise_queryables_reaches_a_late_joining_child() {
        // The query-plane twin of
        // re_advertise_reaches_a_child_that_joined_after_the_declaration: a
        // queryable declared before a peer joined converges onto the new branch
        // exactly as a subscription does (zenoh queries_tree_change).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sa) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A only
        declare_queryable_interest(&fwd, FaceId(0), "demo/q"); // A's qabl; no child -> nowhere

        let (face_c, sink_c) = peer_face(zid(0x0C));
        fwd.register(FaceId(1), &face_c);
        let new_children = advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05);
        sink_c.reset(); // ignore any join-time frames

        fwd.re_advertise_queryables(&new_children);
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the late-joining child C learns A's earlier queryable via re-advertise",
        );
        assert_eq!(
            forwarded_declare_queryable_keyexpr(&sink_c.frame_bytes(0)).as_deref(),
            Some("demo/q"),
            "re-advertised as a literal DeclareQueryable",
        );
    }

    #[test]
    fn re_advertise_queryables_carries_completeness_to_a_late_joiner() {
        // R311uq — the tree-change re-advertise also CARRIES the QueryableInfo, so
        // a late-joining branch learns a complete queryable's completeness (not a
        // clean re-flood). A declares a COMPLETE queryable before C joins; the
        // re-advertise to C must carry complete=true.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sa) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A only
        declare_queryable_complete(&fwd, FaceId(0), "demo/q", 0, true); // A's COMPLETE qabl

        let (face_c, sink_c) = peer_face(zid(0x0C));
        fwd.register(FaceId(1), &face_c);
        let new_children = advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05);
        sink_c.reset(); // ignore any join-time frames

        fwd.re_advertise_queryables(&new_children);
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the late-joining child C learns A's earlier queryable via re-advertise",
        );
        assert!(
            forwarded_declare_queryable_info(&sink_c.frame_bytes(0)).complete,
            "the re-advertised DeclareQueryable carries complete=true (multi-hop carry)",
        );
    }

    #[test]
    fn deregister_purges_the_departed_peers_queryable_interest() {
        // The query-plane twin of deregister_purges_the_departed_peers_interest:
        // a queryable's interest must not outlive its face (zenoh
        // queries_remove_node on link-down). This face-down purge is the safety
        // net for a DEPARTED peer (which sends no retraction) — it complements the
        // per-keyexpr UndeclareQueryable withdrawal (now live via the ext_wire_expr
        // codec) that handles an undeclare-while-connected.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sa) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        declare_queryable_interest(&fwd, FaceId(0), "demo/q");
        assert_eq!(
            fwd.interested_queryables("demo/q"),
            vec![zid(0x0A)],
            "A's queryable interest registered",
        );

        fwd.deregister(FaceId(0));
        assert!(
            fwd.interested_queryables("demo/q").is_empty(),
            "deregister purged A's queryable interest",
        );
    }

    #[test]
    fn a_queryable_and_a_subscription_on_one_key_are_tracked_independently() {
        // The two interest planes share ONE generic table type but are SEPARATE
        // instances: the same peer declaring BOTH a subscription and a queryable
        // on the same keyexpr lands in both tables without cross-contamination,
        // and a face-down purge clears both.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sa) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);

        declare_interest(&fwd, FaceId(0), "demo/k"); // A subscribes
        declare_queryable_interest(&fwd, FaceId(0), "demo/k"); // A also has a queryable
        assert_eq!(fwd.interested("demo/k"), vec![zid(0x0A)], "sub plane has A");
        assert_eq!(
            fwd.interested_queryables("demo/k"),
            vec![zid(0x0A)],
            "qabl plane independently has A",
        );

        fwd.deregister(FaceId(0));
        assert!(fwd.interested("demo/k").is_empty(), "sub plane purged");
        assert!(
            fwd.interested_queryables("demo/k").is_empty(),
            "qabl plane purged too",
        );
    }

    #[test]
    fn an_id_only_undeclare_queryable_does_not_withdraw_a_sourced_interest() {
        // An id-only (no-ext) UndeclareQueryable — the LOCAL-registry retraction
        // form (build_undeclare_queryable(id)) — carries no keyexpr, so it cannot
        // identify a sourced keyexpr-keyed mesh interest: forward_queryable_undeclare
        // resolves no keyexpr and no-ops. So A's mesh queryable interest SURVIVES an
        // id-only body (only the keyexpr-carrying form below, or a face-down purge,
        // withdraws it), and the body is NOT mis-routed to the subscriber catch-all.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sa) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        declare_queryable_interest(&fwd, FaceId(0), "demo/q");
        assert_eq!(
            fwd.interested_queryables("demo/q"),
            vec![zid(0x0A)],
            "A's queryable interest registered",
        );

        // Feed an id-only (no-ext) UndeclareQueryable through the forward() dispatch.
        let undecl = wz_session_core::declare_build::build_undeclare_queryable(7);
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Declare(Box::new(undecl))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&outcome));

        assert_eq!(
            fwd.interested_queryables("demo/q"),
            vec![zid(0x0A)],
            "an id-only UndeclareQueryable carries no keyexpr — the interest survives",
        );
        assert!(
            fwd.interested("demo/q").is_empty(),
            "and it was NOT mis-routed into the subscriber table",
        );
    }

    #[test]
    fn forward_queryable_undeclare_withdraws_source_and_re_floods_along_the_tree() {
        // The query-plane twin of
        // forward_unsubscription_withdraws_source_and_re_floods_along_the_tree:
        // Line A - S(self) - C. A declares a queryable then retracts it via a
        // sourced keyexpr-carrying UndeclareQueryable (node_id 0) — self withdraws
        // A's queryable interest, then re-floods the retraction to its tree child
        // C, never back to the inbound source A.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_c, sink_c) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S<->A
        advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05); // edge S<->C
        declare_queryable_interest(&fwd, FaceId(0), "demo/q"); // A has a queryable
        assert_eq!(
            fwd.interested_queryables("demo/q"),
            vec![zid(0x0A)],
            "A registered"
        );
        sink_a.reset();
        sink_c.reset();

        let undeclare = build_undeclare_queryable_with_keyexpr("demo/q").expect("build undeclare");
        fwd.forward_queryable_undeclare(FaceId(0), true, &undeclare);

        assert!(
            fwd.interested_queryables("demo/q").is_empty(),
            "self withdrew A's queryable interest"
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "re-flooded the retraction to the tree child C"
        );
        assert_eq!(sink_a.frame_count(), 0, "not back to the inbound source A");
    }

    // ── §5.15 query routing atom 2b: Request routing toward queryables ──

    /// The single forwarded Request decoded from a recorded wire frame — so a
    /// test can assert its re-stamped routing source, verbatim rid, and the
    /// B1-normalized literal keyexpr all landed ON THE WIRE.
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

    #[test]
    fn forward_request_resolves_a_transit_source_and_routes_to_a_queryable() {
        // The query-plane twin of forward_push_to_the_interested_subtree_only +
        // the transit-source resolution: C declares a queryable for demo/q, then a
        // routed Query for demo/q arrives on A's face sourced at B (node_id 7 =
        // A's psid for B, the querier). Self resolves the source to B, reads the
        // QUERYABLE interest (qabls), and routes along B's tree to C (which holds
        // the queryable), re-stamped into self's psid for B — fed through the
        // forward() dispatch so the Request arm is covered too. The carrier is a
        // Request with a literal keyexpr and the rid REMAPPED to a fresh local
        // qid recorded in the pending return table (atom 3).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // S -> idx 0
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
                                                          // C declares a queryable for demo/q (sourced from C, FaceId(1)'s peer).
        declare_queryable_interest(&fwd, FaceId(1), "demo/q");
        sink_a.reset();
        sink_c.reset();

        let mut request =
            wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
                .expect("build request");
        set_request_source(&mut request, 7); // node_id 7 = A's psid for B (the querier)
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Request(Box::new(request))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(0), IterationEvent::Poll(&outcome));

        assert_eq!(
            sink_c.frame_count(),
            1,
            "routed to C (which holds the queryable) in B's tree"
        );
        assert_eq!(sink_a.frame_count(), 0, "A is the inbound face (excluded)");
        let fwd_req = forwarded_request(&sink_c.frame_bytes(0));
        assert_ne!(
            fwd_req.rid, 99,
            "rid REMAPPED to a local qid (atom 3 — not the querier's 99)"
        );
        assert_eq!(
            fwd.pending_len(),
            1,
            "a pending-query return entry was recorded for the forwarded Request"
        );
        assert_eq!(
            read_request_source(&fwd_req),
            3,
            "re-stamped into self's psid for the resolved source B (its idx, 3)"
        );
        match &fwd_req.keyexpr.body {
            WireexprOwnedVariant::WireexprLocal(w) if w.id == 0 => {
                assert_eq!(
                    w.suffix.as_deref(),
                    Some("demo/q"),
                    "B1-normalized to a literal keyexpr"
                );
            }
            _ => panic!("expected a literal keyexpr on the forwarded Request"),
        }
        // The N (suffix-present, 0x20) header bit MUST be set in sync with the
        // literal keyexpr — a clear N with a suffix-bearing wireexpr offset-shifts
        // the peer's decode of the Query body (set_request_keyexpr_literal).
        assert_eq!(
            fwd_req.header & 0x20,
            0x20,
            "the N bit is set for the normalized literal keyexpr"
        );
    }

    #[test]
    fn forward_request_fans_out_to_every_matching_queryable() {
        // QueryTarget::All FALLBACK (atom 3): B and C each declare a DEFAULT
        // (incomplete) queryable for demo/q, so BestMatching finds no COMPLETE
        // queryable and falls back to QueryTarget::All — fan out toward ALL
        // matching queryable directions. S has neighbours A, B, C; a Request from
        // A has B and C both as self's children, so it relays to BOTH (the
        // query-plane twin of forward_push_to_two_interested_subtrees). The
        // complete-queryable narrowing is exercised by
        // forward_request_best_matching_* below.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        let (face_c, sink_c) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        fwd.register(FaceId(2), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        advertise_link_back(&fwd, FaceId(2), 0x0C, 0x05);
        declare_queryable_interest(&fwd, FaceId(1), "demo/q"); // B has a queryable
        declare_queryable_interest(&fwd, FaceId(2), "demo/q"); // and so does C
        sink_a.reset();
        sink_b.reset();
        sink_c.reset();

        let request = wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);
        assert_eq!(sink_b.frame_count(), 1, "relayed to queryable B");
        assert_eq!(sink_c.frame_count(), 1, "relayed to queryable C");
        assert_eq!(sink_a.frame_count(), 0, "not back to the source A");
    }

    #[test]
    fn forward_request_dispatches_self_hosted_local_queryable() {
        // §5.23 Phase 2a: S hosts a LOCAL queryable for demo/q with a reply
        // handler. A routed Query for demo/q from face A finds NO remote queryable
        // (self is excluded from query routing), reaches forward_request's
        // empty-route branch, and is dispatched to the local handler — whose Reply
        // + closing ResponseFinal unwind back to the querier on face A. (The reply
        // PAYLOAD content is exercised end-to-end by the Phase-2b admin GET.)
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S-A (querier)
        fwd.register_local_queryable(
            "demo/q",
            true,
            Box::new(|_view: &dyn QueryView, out: &mut dyn ReplyOut| out.reply(b"local-reply")),
        )
        .expect("register local queryable");
        sink_a.reset(); // drop the declare flood to A

        let request = wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);

        // The querier face received the Reply + the closing final (no other face).
        assert_eq!(
            sink_a.frame_count(),
            2,
            "self-dispatch sent a Reply + a ResponseFinal back to the querier"
        );
        // Frame 0 — the Reply, carrying the querier's rid (a DIRECT self-reply uses
        // the inbound rid, no qid remap) under the queryable's keyexpr.
        let resp = forwarded_response(&sink_a.frame_bytes(0));
        assert_eq!(resp.request_id, 99, "reply carries the querier's rid");
        match &resp.keyexpr.body {
            WireexprOwnedVariant::WireexprLocal(w) if w.id == 0 => {
                assert_eq!(w.suffix.as_deref(), Some("demo/q"), "reply keyed to demo/q");
            }
            _ => panic!("expected a literal-keyexpr Reply"),
        }
        // Frame 1 — the closing ResponseFinal, same rid.
        let final_msg = forwarded_response_final(&sink_a.frame_bytes(1));
        assert_eq!(final_msg.request_id, 99, "final carries the querier's rid");
        // A direct self-reply awaits nothing — no pending return entry recorded.
        assert_eq!(
            fwd.pending_len(),
            0,
            "self-dispatch records no pending return entry"
        );
    }

    #[test]
    fn forward_request_from_a_client_querier_dispatches_a_self_hosted_local_queryable() {
        // R311y166 (FAILS before the fix): a CLIENT querier has no graph node since the
        // R311y163 register Client-tier branch, so forward_request's shared
        // resolve_source found no psid and DROPPED its Query (the wz_peer_adminspace_config
        // e2e regression). A client's routed Query for a self-hosted local queryable is
        // now routed with SELF as the tree root, reaches the self-dispatch branch, and
        // the local handler's Reply + closing final unwind back to the client — the query
        // twin of the D4b client-Push re-inject.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2); // a CLIENT querier (held, no graph node)
        fwd.register(FaceId(0), &client);
        fwd.register_local_queryable(
            "demo/q",
            true,
            Box::new(|_view: &dyn QueryView, out: &mut dyn ReplyOut| out.reply(b"local-reply")),
        )
        .expect("register local queryable");
        sink_c.reset();

        let request = wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);

        assert_eq!(
            sink_c.frame_count(),
            2,
            "the client querier received a Reply + a ResponseFinal (self-dispatch)"
        );
        let resp = forwarded_response(&sink_c.frame_bytes(0));
        assert_eq!(
            resp.request_id, 99,
            "reply carries the client querier's rid"
        );
        let final_msg = forwarded_response_final(&sink_c.frame_bytes(1));
        assert_eq!(
            final_msg.request_id, 99,
            "final carries the client querier's rid"
        );
    }

    #[test]
    fn forward_request_no_local_queryable_match_sends_only_the_bare_final() {
        // The negative: with a local queryable for demo/q registered, a Query for a
        // DIFFERENT key (other/q) does NOT match it — so the empty-route branch
        // falls through to the prompt bare ResponseFinal (no spurious Reply),
        // preserving the prior empty-route behaviour.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        fwd.register_local_queryable(
            "demo/q",
            true,
            Box::new(|_v: &dyn QueryView, out: &mut dyn ReplyOut| out.reply(b"x")),
        )
        .expect("register local queryable");
        sink_a.reset();

        let request = wz_session_core::request_build::build_request_query(7, 0, Some("other/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);

        assert_eq!(
            sink_a.frame_count(),
            1,
            "no local match: only the bare empty-route ResponseFinal"
        );
        let final_msg = forwarded_response_final(&sink_a.frame_bytes(0));
        assert_eq!(
            final_msg.request_id, 7,
            "the bare final carries the querier's rid"
        );
    }

    #[test]
    fn peer_undeclare_self_local_qabl_re_arms_the_client_querier() {
        // gap (b) / R311y154: a self-local queryable pushed to a waiting client querier;
        // undeclare_queryable re-arms the querier's write-filter with UndeclareQueryable
        // (same id) — the qabl twin of peer_withdrawing_the_self_local_sub....
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(1), &client);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(8, "demo/key", true, true, false, true, true),
        );
        sink_c.reset();
        fwd.declare_queryable("demo/**", true).expect("declare");
        assert_eq!(sink_c.frame_count(), 1, "the self-local qabl is pushed");
        let pushed_id = match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => d.id,
            _ => panic!("expected a DeclareQueryable push"),
        };
        assert_ne!(pushed_id, 0);
        sink_c.reset();
        fwd.undeclare_queryable("demo/**").expect("undeclare");
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the retraction undeclares to the waiting querier"
        );
        match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohUndeclQueryable(u) => {
                assert_eq!(u.id, pushed_id, "the undeclare carries the pushed qabl id")
            }
            _ => panic!("expected an UndeclareQueryable"),
        }
    }

    #[test]
    fn peer_undeclare_self_local_qabl_floods_the_mesh_forget() {
        // undeclare_queryable floods a sourced UndeclareQueryable to tree children
        // (zenoh propagate_forget_sourced_queryable).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // A is S's tree child
        fwd.declare_queryable("demo/q", false).expect("declare");
        sink_a.reset();
        let reached = fwd.undeclare_queryable("demo/q").expect("undeclare");
        assert_eq!(reached, 1, "the forget floods to the one tree child A");
        assert!(matches!(
            forwarded_declare(&sink_a.frame_bytes(0)).body,
            DeclareOwnedVariant::CodecZenohUndeclQueryable(_)
        ));
    }

    #[test]
    fn peer_undeclare_self_local_qabl_downgrades_a_still_backed_querier() {
        // gap (b) x case (c): a self-local COMPLETE qabl + a MESH INCOMPLETE one both back
        // the aggregate reply demo/key; complete=true is pushed. undeclare_queryable removes
        // self's complete backer but 0x0B still backs demo/key -> DOWNGRADE re-push
        // complete=false (same id), NOT an undeclare — the y153 machinery via the new path.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (mesh_i, _si) = peer_face(zid(0x0B)); // incomplete co-backer, survives
        let (client, sink_c) = peer_face_whatami(zid(0x0C), 2);
        fwd.register(FaceId(2), &mesh_i);
        fwd.register(FaceId(1), &client);
        advertise_link_back(&fwd, FaceId(2), 0x0B, 0x05);
        forward_one(
            &fwd,
            FaceId(1),
            interest_with_mode(8, "demo/key", true, true, false, true, true),
        );
        declare_queryable_complete(&fwd, FaceId(2), "demo/key", 0, false); // mesh incomplete co-backer
        sink_c.reset();
        fwd.declare_queryable("demo/**", true).expect("declare"); // self complete -> complete=true pushed
        let pushed_id = match forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => d.id,
            _ => panic!("expected a DeclareQueryable push"),
        };
        sink_c.reset();
        fwd.undeclare_queryable("demo/**").expect("undeclare"); // self's complete backer gone; 0x0B remains
        assert_eq!(
            sink_c.frame_count(),
            1,
            "DOWNGRADE re-push (demo/key still backed by 0x0B)"
        );
        match &forwarded_declare(&sink_c.frame_bytes(0)).body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => {
                assert_eq!(d.id, pushed_id, "same interned id, re-declared in place");
                assert!(
                    !wz_session_core::queryable_info::read_queryable_info(d.extensions.as_ref())
                        .complete,
                    "downgraded to complete=false"
                );
            }
            other => panic!("expected a downgrade DeclareQueryable, got {other:?}"),
        }
    }

    #[test]
    fn peer_undeclare_queryable_stops_the_local_reply_handler() {
        // R311y154: undeclare_queryable is the INVERSE of register_local_queryable — it
        // drops the reply handler so a RETRACTED queryable STOPS answering (zenoh drops the
        // callback with the declaration). Without the local_queryables drop, a Query on the
        // empty-route branch would still hit the handler (dispatch_local_queryables) and
        // reply — a "retraction that keeps answering".
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        fwd.register_local_queryable(
            "demo/q",
            true,
            Box::new(|_v: &dyn QueryView, out: &mut dyn ReplyOut| out.reply(b"local-reply")),
        )
        .expect("register local queryable");
        fwd.undeclare_queryable("demo/q").expect("undeclare");
        sink_a.reset();
        let request = wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);
        assert_eq!(
            sink_a.frame_count(),
            1,
            "the retracted queryable no longer answers: only the bare final (a live handler \
             would add a Reply = 2 frames)"
        );
        assert_eq!(
            forwarded_response_final(&sink_a.frame_bytes(0)).request_id,
            99,
            "the bare empty-route final carries the querier's rid"
        );
    }

    #[test]
    fn peer_undeclare_subscription_stops_the_local_subscriber() {
        // R311y154 symmetric: undeclare_subscription is the INVERSE of
        // register_local_subscriber — it drops the handler so a retracted local subscriber
        // STOPS receiving. This closes the identical pre-existing local-handler residual
        // the qabl twin exposed; fixed on BOTH planes to preserve the twin symmetry.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        let fired = std::rc::Rc::new(std::cell::Cell::new(false));
        let f = fired.clone();
        fwd.register_local_subscriber(
            "demo/data",
            Box::new(move |_s: &dyn SampleView| f.set(true)),
        )
        .expect("register local subscriber");
        fwd.undeclare_subscription("demo/data").expect("undeclare");
        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&push_outcome("demo/data", b"p")),
        );
        assert!(
            !fired.get(),
            "the retracted local subscriber no longer receives the Put"
        );
    }

    #[test]
    fn forward_request_self_dispatch_replies_under_the_handler_keyexpr_with_encoding() {
        // The Phase-2b PRODUCTION path: a handler that answers a WILDCARD query by
        // replying under a CONCRETE keyexpr DIFFERENT from the query keyexpr,
        // carrying an encoding — exactly what the §5.23 admin handler does (it
        // answers an `@/<zid>/**` GET via `reply_keyed_encoded(config_key, json,
        // APPLICATION_JSON)`). Proves the keyed + encoded reply arm routes the
        // reply under the HANDLER's own key (not the query wildcard) back to the
        // querier — so the handler's chosen reply data reaches the querier.
        use wz_session_core::sample::EncodingHint;
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        fwd.register_local_queryable(
            "admin/**",
            true,
            Box::new(|_v: &dyn QueryView, out: &mut dyn ReplyOut| {
                out.reply_keyed_encoded(
                    "admin/config",
                    b"{\"k\":1}",
                    Some(&EncodingHint::APPLICATION_JSON),
                )
            }),
        )
        .expect("register local queryable");
        sink_a.reset();

        let request = wz_session_core::request_build::build_request_query(5, 0, Some("admin/**"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);

        assert_eq!(sink_a.frame_count(), 2, "a keyed reply + the closing final");
        let resp = forwarded_response(&sink_a.frame_bytes(0));
        assert_eq!(resp.request_id, 5, "reply carries the querier's rid");
        // The reply is keyed to the handler's OWN concrete key, NOT the wildcard
        // query keyexpr — the reply_keyed_encoded path.
        match &resp.keyexpr.body {
            WireexprOwnedVariant::WireexprLocal(w) if w.id == 0 => {
                assert_eq!(
                    w.suffix.as_deref(),
                    Some("admin/config"),
                    "reply keyed to the handler's concrete key, not the query wildcard"
                );
            }
            _ => panic!("expected a literal-keyexpr Reply"),
        }
    }

    #[test]
    fn forward_request_allcomplete_skips_an_incomplete_local_queryable() {
        // The AllComplete filter: a local queryable registered INCOMPLETE
        // (complete=false) is NOT dispatched for a QueryTarget::AllComplete query
        // (only complete queryables answer AllComplete), so the empty-route branch
        // falls through to the bare ResponseFinal — no spurious reply.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        fwd.register_local_queryable(
            "demo/q",
            false, // INCOMPLETE
            Box::new(|_v: &dyn QueryView, out: &mut dyn ReplyOut| out.reply(b"x")),
        )
        .expect("register local queryable");
        sink_a.reset();

        let request =
            wz_session_core::request_build::RequestQueryBuilder::new(8, 0, Some("demo/q"))
                .request_target(QueryTarget::AllComplete)
                .build()
                .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);

        assert_eq!(
            sink_a.frame_count(),
            1,
            "AllComplete skips the incomplete local queryable: only the bare final"
        );
        let final_msg = forwarded_response_final(&sink_a.frame_bytes(0));
        assert_eq!(
            final_msg.request_id, 8,
            "the bare final carries the querier's rid"
        );
    }

    // R311y46 (§5.23 Phase 3a) — drive a Put into the forwarder and capture what a
    // LOCALLY-hosted subscriber's handler received.
    fn push_outcome(keyexpr: &str, payload: &[u8]) -> DriverLoopOutcome {
        let push =
            wz_session_core::push_build::build_push_literal(keyexpr, payload).expect("build push");
        DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(push))],
            has_ext: false,
            extensions: Vec::new(),
        }
    }

    // #3-c QUERY half — drive a routed Query through the full `forward` message
    // loop (so the depth-guarded self-query drain runs), the Request twin of
    // `push_outcome`.
    fn request_outcome(rid: u64, keyexpr: &str) -> DriverLoopOutcome {
        let request = wz_session_core::request_build::build_request_query(rid, 0, Some(keyexpr))
            .expect("build request");
        DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Request(Box::new(request))],
            has_ext: false,
            extensions: Vec::new(),
        }
    }

    #[test]
    fn query_self_reentrant_queryable_redelivers_the_self_query() {
        // #3-c QUERY half (R311y168) — the query twin of the sub-plane self-echo fix.
        // A queryable handler QH that, while answering a query, RE-QUERIES its own
        // keyexpr (self-query) hits a busy try_borrow_mut in the inner
        // dispatch_local_queryables; the y44/y156 code skipped it AND emitted the
        // inner query's ResponseFinal EAGERLY (dropping QH's answer -- zenoh removes
        // the query on ResponseFinal, session.rs:3023, then discards a late reply,
        // :2807). Faithful redelivery DEFERS the busy QH + HOLDS the inner Final, then
        // at the outermost forward exit fires QH for the deferred self-query and emits
        // its reply + the one closing Final. QH must fire TWICE (outer + redelivered
        // self-query). Driven through forward (NOT forward_request) so the
        // depth-guarded drain runs. Diagnose-first: pre-fix QH fires ONCE.
        let fwd = std::rc::Rc::new(LinkstateForwarder::new(zid(0x05), WhatAmI::Peer));
        let (face_a, _sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        let fires = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let weak = std::rc::Rc::downgrade(&fwd);
        let queried = std::cell::Cell::new(false);
        let fc = fires.clone();
        fwd.register_local_queryable(
            "demo/**",
            true,
            Box::new(move |_v: &dyn QueryView, out: &mut dyn ReplyOut| {
                fc.set(fc.get() + 1);
                out.reply(b"R");
                if !queried.replace(true) {
                    if let Some(fwd) = weak.upgrade() {
                        fwd.forward(
                            FaceId(0),
                            IterationEvent::Poll(&request_outcome(77, "demo/q")),
                        );
                    }
                }
            }),
        )
        .expect("register self-querying QH");

        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&request_outcome(99, "demo/q")),
        );
        assert_eq!(
            fires.get(),
            2,
            "QH answered the outer query AND the redelivered self-query (not dropped)"
        );
    }

    #[test]
    fn deferred_self_query_emits_reply_before_final() {
        // #3-c QUERY half (R311y168) — the CORE correctness property: a deferred
        // self-query's reply must precede its closing ResponseFinal on the wire (else
        // the querier discards the redelivered reply). QH answers the outer query
        // (rid 99: reply, final) inline, self-queries (rid 77) deferring itself; at the
        // outermost forward exit the drain emits the rid-77 reply THEN its final.
        let fwd = std::rc::Rc::new(LinkstateForwarder::new(zid(0x05), WhatAmI::Peer));
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        let weak = std::rc::Rc::downgrade(&fwd);
        let queried = std::cell::Cell::new(false);
        fwd.register_local_queryable(
            "demo/**",
            true,
            Box::new(move |_v: &dyn QueryView, out: &mut dyn ReplyOut| {
                out.reply(b"R");
                if !queried.replace(true) {
                    if let Some(fwd) = weak.upgrade() {
                        fwd.forward(
                            FaceId(0),
                            IterationEvent::Poll(&request_outcome(77, "demo/q")),
                        );
                    }
                }
            }),
        )
        .expect("register self-querying QH");
        sink_a.reset(); // drop the declare flood to A

        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&request_outcome(99, "demo/q")),
        );
        // Outer 99 (reply, final) inline, THEN the deferred 77 (reply, final) at drain.
        assert_eq!(
            sink_a.frame_count(),
            4,
            "reply+final for the outer AND the deferred self-query"
        );
        assert_eq!(forwarded_response(&sink_a.frame_bytes(0)).request_id, 99);
        assert_eq!(
            forwarded_response_final(&sink_a.frame_bytes(1)).request_id,
            99
        );
        assert_eq!(
            forwarded_response(&sink_a.frame_bytes(2)).request_id,
            77,
            "the deferred self-query's REPLY is emitted first"
        );
        assert_eq!(
            forwarded_response_final(&sink_a.frame_bytes(3)).request_id,
            77,
            "the deferred self-query's FINAL comes AFTER its reply (the hold worked)"
        );
    }

    #[test]
    fn query_self_reentrant_redelivery_is_bounded_and_terminates() {
        // #3-c QUERY half (R311y168) — an UNCONDITIONAL self-querier (QH re-queries
        // its own ke on EVERY answer) is REDELIVERED but BOUNDED by the drain budget
        // (SELF_ECHO_QUEUE_CAP), so the outer forward TERMINATES with QH fired a
        // bounded number of times — no hang / stack overflow (the query twin of the
        // sub-plane bound).
        let fwd = std::rc::Rc::new(LinkstateForwarder::new(zid(0x05), WhatAmI::Peer));
        let (face_a, _sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        let fires = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let weak = std::rc::Rc::downgrade(&fwd);
        let fc = fires.clone();
        fwd.register_local_queryable(
            "demo/**",
            true,
            Box::new(move |_v: &dyn QueryView, out: &mut dyn ReplyOut| {
                fc.set(fc.get() + 1);
                out.reply(b"R");
                if let Some(fwd) = weak.upgrade() {
                    fwd.forward(
                        FaceId(0),
                        IterationEvent::Poll(&request_outcome(77, "demo/q")),
                    );
                }
            }),
        )
        .expect("register unconditional self-querying QH");

        // A single outer Query must TERMINATE (no unbounded recursion / hang).
        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&request_outcome(99, "demo/q")),
        );
        let n = fires.get();
        assert!(n > 1, "the self-query is REDELIVERED (QH fired {n} times)");
        assert!(
            n <= LinkstateForwarder::SELF_ECHO_QUEUE_CAP as u32 + 1,
            "redelivery is BOUNDED by the per-forward drain budget (QH fired {n} times)"
        );
    }

    #[test]
    fn undeclare_queryable_purges_a_deferred_self_query() {
        // #3-c QUERY half (R311y168) — QH self-queries (deferring itself) THEN
        // undeclares itself in the same answer: the deferred handler is purged from
        // the DeferredQuery, so QH is NOT redelivered (fires ONCE). The record
        // survives with an empty handler set so the closing ResponseFinal still emits
        // (an empty answer) — the self-querier's get() terminates rather than hanging.
        let fwd = std::rc::Rc::new(LinkstateForwarder::new(zid(0x05), WhatAmI::Peer));
        let (face_a, _sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        let fires = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let weak = std::rc::Rc::downgrade(&fwd);
        let queried = std::cell::Cell::new(false);
        let fc = fires.clone();
        fwd.register_local_queryable(
            "demo/**",
            true,
            Box::new(move |_v: &dyn QueryView, out: &mut dyn ReplyOut| {
                fc.set(fc.get() + 1);
                out.reply(b"R");
                if !queried.replace(true) {
                    if let Some(fwd) = weak.upgrade() {
                        fwd.forward(
                            FaceId(0),
                            IterationEvent::Poll(&request_outcome(77, "demo/q")),
                        );
                        let _ = fwd.undeclare_queryable("demo/**");
                    }
                }
            }),
        )
        .expect("register self-querying-then-undeclaring QH");

        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&request_outcome(99, "demo/q")),
        );
        assert_eq!(
            fires.get(),
            1,
            "the retracted queryable is not redelivered for its deferred self-query"
        );
    }

    #[test]
    fn forward_push_dispatches_self_hosted_local_subscriber() {
        // §5.23 Phase 3a: S hosts a LOCAL subscriber for demo/data with a handler.
        // A Put for demo/data arriving on face A is delivered to the handler (the
        // self/local-delivery seam — forward_push excludes self).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        let recorded = std::rc::Rc::new(std::cell::RefCell::new(Vec::<(String, Vec<u8>)>::new()));
        let rec = recorded.clone();
        fwd.register_local_subscriber(
            "demo/data",
            Box::new(move |s: &dyn SampleView| {
                rec.borrow_mut()
                    .push((s.keyexpr().to_string(), s.payload().to_vec()));
            }),
        )
        .expect("register local subscriber");

        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&push_outcome("demo/data", b"payload")),
        );

        let got = recorded.borrow();
        assert_eq!(got.len(), 1, "the local subscriber handler fired once");
        assert_eq!(got[0].0, "demo/data", "handler saw the resolved keyexpr");
        assert_eq!(got[0].1, b"payload", "handler saw the Put payload");
    }

    #[test]
    fn forward_push_no_local_subscriber_match_does_not_fire() {
        // The negative: a Put for a key the local subscriber does NOT cover does
        // not fire its handler.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        let fired = std::rc::Rc::new(std::cell::Cell::new(false));
        let f = fired.clone();
        fwd.register_local_subscriber(
            "demo/data",
            Box::new(move |_s: &dyn SampleView| f.set(true)),
        )
        .expect("register local subscriber");

        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&push_outcome("other/data", b"x")),
        );

        assert!(
            !fired.get(),
            "a non-matching Put does not fire the local handler"
        );
    }

    #[test]
    fn forward_push_local_subscriber_pattern_matches() {
        // A PATTERN subscriber (demo/**) is delivered a concrete Put (demo/data) —
        // the subscriber keyexpr is the pattern, the Put key concrete.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        let recorded = std::rc::Rc::new(std::cell::RefCell::new(Vec::<String>::new()));
        let rec = recorded.clone();
        fwd.register_local_subscriber(
            "demo/**",
            Box::new(move |s: &dyn SampleView| rec.borrow_mut().push(s.keyexpr().to_string())),
        )
        .expect("register local subscriber");

        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&push_outcome("demo/data", b"p")),
        );

        let got = recorded.borrow();
        assert_eq!(
            got.len(),
            1,
            "the demo/** subscriber matched the demo/data Put"
        );
        assert_eq!(got[0], "demo/data");
    }

    #[test]
    fn forward_push_delivers_to_remote_and_local_subscriber_without_double() {
        // The no-double-delivery invariant: a key BOTH a REMOTE peer (B) and SELF
        // subscribe to. A Put from A fans out to B ONCE (forward_push, which excludes
        // self) AND fires the LOCAL handler ONCE (dispatch_local_subscribers, a
        // separate registry) — disjoint recipients, no double-delivery.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A)); // source
        let (face_b, sink_b) = peer_face(zid(0x0B)); // REMOTE subscriber
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(1), "demo/data"); // B subscribes (remote)
        let fired = std::rc::Rc::new(std::cell::Cell::new(0usize));
        let f = fired.clone();
        fwd.register_local_subscriber("demo/data", Box::new(move |_s| f.set(f.get() + 1)))
            .expect("register local subscriber"); // self subscribes (local)
        sink_a.reset();
        sink_b.reset(); // drop the declare floods

        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&push_outcome("demo/data", b"payload")),
        );

        assert_eq!(
            sink_b.frame_count(),
            1,
            "remote subscriber B got the Put exactly once"
        );
        assert_eq!(fired.get(), 1, "the local handler fired exactly once");
        assert_eq!(sink_a.frame_count(), 0, "not echoed back to the source A");
    }

    #[test]
    fn dispatch_reentrant_register_local_subscriber_is_safe_and_snapshot_excludes_it() {
        // R311y156 re-entrancy contract (subscriber plane): a local subscriber
        // handler that re-entrantly REGISTERS another matching local subscriber must
        // not panic the `local_subscribers` RefCell (the collect-drop-invoke drops
        // the Vec borrow before the handler runs), and the newly-registered handler
        // is EXCLUDED from the in-flight Put (snapshot = zenoh's "declared after this
        // sample"). The pre-y156 `borrow_mut`-across-handler would panic on the
        // re-entrant register.
        let fwd = std::rc::Rc::new(LinkstateForwarder::new(zid(0x05), WhatAmI::Peer));
        let (face_a, _sa) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        let fires = std::rc::Rc::new(std::cell::RefCell::new(Vec::<&'static str>::new()));
        let weak = std::rc::Rc::downgrade(&fwd);
        let fires_a = fires.clone();
        let fires_b = fires.clone();
        let once = std::cell::Cell::new(false);
        fwd.register_local_subscriber(
            "demo/**",
            Box::new(move |_s: &dyn SampleView| {
                fires_a.borrow_mut().push("A");
                if !once.replace(true) {
                    if let Some(fwd) = weak.upgrade() {
                        let fb = fires_b.clone();
                        let _ = fwd.register_local_subscriber(
                            "demo/**",
                            Box::new(move |_s: &dyn SampleView| fb.borrow_mut().push("B")),
                        );
                    }
                }
            }),
        )
        .expect("register A");

        // Put 1: snapshot = [A]. A fires (records "A") and re-entrantly registers B;
        // B is NOT in this snapshot, so it is excluded from Put 1 (and no panic).
        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&push_outcome("demo/data", b"p1")),
        );
        assert_eq!(
            *fires.borrow(),
            vec!["A"],
            "re-entrant register did not panic; B excluded from the in-flight Put"
        );

        // Put 2: snapshot = [A, B] -> both fire (B is now in the registry).
        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&push_outcome("demo/data", b"p2")),
        );
        assert_eq!(
            *fires.borrow(),
            vec!["A", "A", "B"],
            "the re-entrantly-registered B fires on the NEXT Put"
        );
    }

    #[test]
    fn dispatch_reentrant_self_undeclare_local_subscriber_is_safe() {
        // R311y156 (subscriber plane): a handler that undeclares ITSELF during
        // dispatch must not panic — the snapshot `Rc` keeps the mid-fire handler
        // alive while `undeclare_subscription`'s `retain` drops the Vec entry — and
        // after the self-undeclare it no longer fires.
        let fwd = std::rc::Rc::new(LinkstateForwarder::new(zid(0x05), WhatAmI::Peer));
        let (face_a, _sa) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        let fires = std::rc::Rc::new(std::cell::Cell::new(0usize));
        let weak = std::rc::Rc::downgrade(&fwd);
        let f = fires.clone();
        fwd.register_local_subscriber(
            "demo/**",
            Box::new(move |_s: &dyn SampleView| {
                f.set(f.get() + 1);
                if let Some(fwd) = weak.upgrade() {
                    let _ = fwd.undeclare_subscription("demo/**"); // self-undeclare mid-fire
                }
            }),
        )
        .expect("register self-undeclaring subscriber");

        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&push_outcome("demo/data", b"p1")),
        );
        assert_eq!(
            fires.get(),
            1,
            "fired once; the self-undeclare did not panic"
        );
        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&push_outcome("demo/data", b"p2")),
        );
        assert_eq!(
            fires.get(),
            1,
            "the self-undeclared subscriber no longer fires"
        );
    }

    #[test]
    fn dispatch_reentrant_register_local_queryable_is_safe_and_snapshot_excludes_it() {
        // R311y156 (queryable plane, the twin of the subscriber register test): a
        // local queryable handler that re-entrantly registers another matching
        // queryable must not panic `local_queryables`, and the new one is excluded
        // from the in-flight Query (snapshot).
        let fwd = std::rc::Rc::new(LinkstateForwarder::new(zid(0x05), WhatAmI::Peer));
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        let replies = std::rc::Rc::new(std::cell::Cell::new(0usize));
        let weak = std::rc::Rc::downgrade(&fwd);
        let ra = replies.clone();
        let rb = replies.clone();
        let once = std::cell::Cell::new(false);
        fwd.register_local_queryable(
            "demo/q",
            true,
            Box::new(move |_v: &dyn QueryView, out: &mut dyn ReplyOut| {
                ra.set(ra.get() + 1);
                out.reply(b"A");
                if !once.replace(true) {
                    if let Some(fwd) = weak.upgrade() {
                        let rb2 = rb.clone();
                        let _ = fwd.register_local_queryable(
                            "demo/q",
                            true,
                            Box::new(move |_v: &dyn QueryView, out: &mut dyn ReplyOut| {
                                rb2.set(rb2.get() + 1);
                                out.reply(b"B");
                            }),
                        );
                    }
                }
            }),
        )
        .expect("register A");
        sink_a.reset();

        let request = wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);
        assert_eq!(
            replies.get(),
            1,
            "Query 1: only A dispatched (B excluded from the snapshot); no panic"
        );

        let request2 = wz_session_core::request_build::build_request_query(100, 0, Some("demo/q"))
            .expect("build request 2");
        fwd.forward_request(FaceId(0), true, &request2);
        assert_eq!(
            replies.get(),
            3,
            "Query 2: A + B both dispatch (1 + 2 = 3 total invocations)"
        );
    }

    #[test]
    fn dispatch_reentrant_self_undeclare_local_queryable_is_safe() {
        // R311y156 (queryable plane): a handler that undeclares ITSELF during
        // dispatch must not panic; its reply for THIS query is still emitted (already
        // accumulated in `replies`), and it no longer answers the NEXT query.
        let fwd = std::rc::Rc::new(LinkstateForwarder::new(zid(0x05), WhatAmI::Peer));
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        let replies = std::rc::Rc::new(std::cell::Cell::new(0usize));
        let weak = std::rc::Rc::downgrade(&fwd);
        let r = replies.clone();
        fwd.register_local_queryable(
            "demo/q",
            true,
            Box::new(move |_v: &dyn QueryView, out: &mut dyn ReplyOut| {
                r.set(r.get() + 1);
                out.reply(b"A");
                if let Some(fwd) = weak.upgrade() {
                    let _ = fwd.undeclare_queryable("demo/q"); // self-undeclare mid-fire
                }
            }),
        )
        .expect("register self-undeclaring queryable");
        sink_a.reset();

        let request = wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);
        assert_eq!(
            replies.get(),
            1,
            "answered once; the self-undeclare did not panic"
        );
        // Query 2: the queryable is gone -> no local dispatch (the empty-route final
        // is sent instead; the handler count stays 1).
        let request2 = wz_session_core::request_build::build_request_query(100, 0, Some("demo/q"))
            .expect("build request 2");
        fwd.forward_request(FaceId(0), true, &request2);
        assert_eq!(
            replies.get(),
            1,
            "the self-undeclared queryable no longer answers"
        );
    }

    #[test]
    fn dispatch_self_reentrant_subscriber_redelivery_is_bounded_and_terminates() {
        // #3-c (R311y167) — the loop-safety guard, superseding the y156
        // skipped-not-looped contract: an UNCONDITIONAL self-echoer (A re-drives a
        // matching Put on EVERY fire) is now REDELIVERED (not dropped), but the
        // per-`forward` drain budget (`SELF_ECHO_QUEUE_CAP`) caps deliveries so the
        // call TERMINATES with A fired a BOUNDED number of times — zenoh's
        // RingChannel spins with bounded memory rather than a synchronous hang or a
        // stack overflow (zenoh does not prevent the loop, only bounds it; a failed
        // y156 skip would instead recurse unboundedly and overflow). A SECOND plain
        // subscriber B pins that the inner dispatch genuinely ran.
        let fwd = std::rc::Rc::new(LinkstateForwarder::new(zid(0x05), WhatAmI::Peer));
        let (face_a, _sa) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        let fires = std::rc::Rc::new(std::cell::RefCell::new(Vec::<&'static str>::new()));
        let weak = std::rc::Rc::downgrade(&fwd);
        let fa = fires.clone();
        // A: on EVERY fire, re-drive one matching Put (unconditional self-echo).
        fwd.register_local_subscriber(
            "demo/**",
            Box::new(move |_s: &dyn SampleView| {
                fa.borrow_mut().push("A");
                if let Some(fwd) = weak.upgrade() {
                    fwd.forward(
                        FaceId(0),
                        IterationEvent::Poll(&push_outcome("demo/data", b"inner")),
                    );
                }
            }),
        )
        .expect("register self-echoing A");
        // B: a plain matching subscriber that just records "B".
        let fb = fires.clone();
        fwd.register_local_subscriber(
            "demo/**",
            Box::new(move |_s: &dyn SampleView| fb.borrow_mut().push("B")),
        )
        .expect("register B");

        // A single outer Put must TERMINATE (no unbounded recursion / hang).
        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&push_outcome("demo/data", b"outer")),
        );
        let a_count = fires.borrow().iter().filter(|&&x| x == "A").count();
        // Redelivery happened (A fired past the single outer delivery) AND it is
        // bounded by the drain budget (+1 for the outer, non-drained delivery).
        assert!(
            a_count > 1,
            "the self-echo is REDELIVERED, not dropped (A fired {a_count} times)"
        );
        assert!(
            a_count <= LinkstateForwarder::SELF_ECHO_QUEUE_CAP + 1,
            "redelivery is BOUNDED by the per-forward drain budget (A fired {a_count} times)"
        );
        assert!(
            fires.borrow().contains(&"B"),
            "the inner dispatch genuinely ran (B fired)"
        );
    }

    #[test]
    fn dispatch_self_reentrant_subscriber_redelivers_a_single_self_echo() {
        // #3-c (faithful self-echo redelivery) — the FIX target for the y156 drop.
        // A handler A that re-delivers to ITSELF (re-drives one matching Put from
        // inside its own callback) must have that self-echo REDELIVERED after the
        // dispatch unwinds — mirroring zenoh's default FifoChannel, whose
        // `sender.send` requeues the self-put for the receiver's next drain
        // (handlers/fifo.rs:57-66), NOT dropped as the y156 `try_borrow_mut` skip
        // does. A self-echoes exactly ONCE (a `Cell` guard) so redelivery is
        // bounded and terminates: A must fire TWICE (outer Put + the redelivered
        // self-echo). Diagnose-first: pre-fix this asserts A fires ONCE (self-echo
        // dropped) and FAILS.
        let fwd = std::rc::Rc::new(LinkstateForwarder::new(zid(0x05), WhatAmI::Peer));
        let (face_a, _sa) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        let fires = std::rc::Rc::new(std::cell::RefCell::new(Vec::<&'static str>::new()));
        let weak = std::rc::Rc::downgrade(&fwd);
        let echoed = std::cell::Cell::new(false);
        let fa = fires.clone();
        fwd.register_local_subscriber(
            "demo/**",
            Box::new(move |_s: &dyn SampleView| {
                fa.borrow_mut().push("A");
                if !echoed.replace(true) {
                    if let Some(fwd) = weak.upgrade() {
                        fwd.forward(
                            FaceId(0),
                            IterationEvent::Poll(&push_outcome("demo/data", b"inner")),
                        );
                    }
                }
            }),
        )
        .expect("register self-echoing A");

        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&push_outcome("demo/data", b"outer")),
        );
        assert_eq!(
            *fires.borrow(),
            vec!["A", "A"],
            "A's single self-echo is REDELIVERED after the dispatch unwinds, not dropped"
        );
    }

    #[test]
    fn undeclare_purges_a_pending_self_echo() {
        // #3-c (R311y167) — a self-echo already QUEUED for a handler that then
        // UNDECLARES itself in the same tick must NOT be redelivered: undeclare
        // purges the handler's `sub_redelivery` entries, honoring the y154/y163
        // "undeclare stops delivering" contract (and closing the `Rc`-capture leak
        // window). A re-drives one matching Put (enqueuing a self-echo) THEN
        // undeclares itself; the outermost drain finds nothing -> A fires ONCE.
        let fwd = std::rc::Rc::new(LinkstateForwarder::new(zid(0x05), WhatAmI::Peer));
        let (face_a, _sa) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        let fires = std::rc::Rc::new(std::cell::RefCell::new(Vec::<&'static str>::new()));
        let weak = std::rc::Rc::downgrade(&fwd);
        let echoed = std::cell::Cell::new(false);
        let fa = fires.clone();
        fwd.register_local_subscriber(
            "demo/**",
            Box::new(move |_s: &dyn SampleView| {
                fa.borrow_mut().push("A");
                if !echoed.replace(true) {
                    if let Some(fwd) = weak.upgrade() {
                        // Enqueue a self-echo (A is busy on this stack) ...
                        fwd.forward(
                            FaceId(0),
                            IterationEvent::Poll(&push_outcome("demo/data", b"inner")),
                        );
                        // ... then retract self: the queued self-echo must be purged.
                        let _ = fwd.undeclare_subscription("demo/**");
                    }
                }
            }),
        )
        .expect("register self-echoing-then-undeclaring A");

        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&push_outcome("demo/data", b"outer")),
        );
        assert_eq!(
            *fires.borrow(),
            vec!["A"],
            "the pending self-echo is purged on undeclare — A is not redelivered"
        );
    }

    #[test]
    fn dispatch_sibling_undeclare_during_dispatch_still_fires_the_peer() {
        // R311y156 — snapshot-Rc liveness (subscriber plane): a handler A that
        // undeclares a DIFFERENT, not-yet-fired handler B during dispatch must NOT
        // cancel B's in-flight delivery — the snapshot holds B's `Rc`, so B STILL
        // fires THIS Put (zenoh's "a sample already being delivered is not un-delivered
        // by a concurrent undeclare"), and B is gone from the NEXT Put. This isolates
        // the snapshot-`Rc` liveness guarantee: the self-undeclare tests only show a
        // handler surviving its OWN stack frame (trivially alive because it is running).
        let fwd = std::rc::Rc::new(LinkstateForwarder::new(zid(0x05), WhatAmI::Peer));
        let (face_a, _sa) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        let fires = std::rc::Rc::new(std::cell::RefCell::new(Vec::<&'static str>::new()));
        let weak = std::rc::Rc::downgrade(&fwd);
        // A (registered FIRST, pattern "demo/**"): on fire, undeclare the sibling B once.
        let fa = fires.clone();
        let once = std::cell::Cell::new(false);
        fwd.register_local_subscriber(
            "demo/**",
            Box::new(move |_s: &dyn SampleView| {
                fa.borrow_mut().push("A");
                if !once.replace(true) {
                    if let Some(fwd) = weak.upgrade() {
                        let _ = fwd.undeclare_subscription("demo/key"); // drop sibling B
                    }
                }
            }),
        )
        .expect("register A");
        // B (registered SECOND, exact "demo/key"): also matches the Put demo/key.
        let fb = fires.clone();
        fwd.register_local_subscriber(
            "demo/key",
            Box::new(move |_s: &dyn SampleView| fb.borrow_mut().push("B")),
        )
        .expect("register B");

        // Put 1: snapshot = [A, B]. A fires ("A") and undeclares B; B is ALREADY in the
        // snapshot, so it STILL fires this Put ("B") — a concurrent undeclare does not
        // cancel an in-flight delivery.
        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&push_outcome("demo/key", b"p1")),
        );
        assert_eq!(
            *fires.borrow(),
            vec!["A", "B"],
            "the sibling B, undeclared mid-dispatch, still fires THIS Put (snapshot Rc)"
        );
        // Put 2: B is gone -> only A fires.
        fwd.forward(
            FaceId(0),
            IterationEvent::Poll(&push_outcome("demo/key", b"p2")),
        );
        assert_eq!(
            *fires.borrow(),
            vec!["A", "B", "A"],
            "B is gone from the NEXT Put; only A fires"
        );
    }

    #[test]
    fn forward_request_best_matching_routes_only_to_the_complete_queryable() {
        // QueryTarget::BestMatching (atom 3): when a COMPLETE queryable exists the
        // Query routes to that ONE queryable, NOT the All fan-out. B declares a
        // COMPLETE queryable for demo/q, C an INCOMPLETE one (both self's
        // children, equal distance). BestMatching selects B alone; C — matching
        // but incomplete — is not a target. Contrast
        // forward_request_fans_out_to_every_matching_queryable, where both are
        // incomplete and the All fallback reaches BOTH.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        let (face_c, sink_c) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        fwd.register(FaceId(2), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        advertise_link_back(&fwd, FaceId(2), 0x0C, 0x05);
        declare_queryable_complete(&fwd, FaceId(1), "demo/q", 0, true); // B complete
        declare_queryable_complete(&fwd, FaceId(2), "demo/q", 0, false); // C incomplete
        sink_a.reset();
        sink_b.reset();
        sink_c.reset();

        let request = wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);
        assert_eq!(
            sink_b.frame_count(),
            1,
            "BestMatching routes to the COMPLETE queryable B",
        );
        assert_eq!(
            sink_c.frame_count(),
            0,
            "the incomplete queryable C is not a BestMatching target",
        );
        assert_eq!(sink_a.frame_count(), 0, "not back to the source A");
        assert_eq!(
            fwd.pending_len(),
            1,
            "a single pending-query return entry for the one selected target",
        );
    }

    #[test]
    fn forward_request_best_matching_prefers_the_nearer_of_two_complete_queryables() {
        // QueryTarget::BestMatching distance order (atom 3): among COMPLETE
        // queryables, the GRAPH-nearest one wins (zenoh sorts the route by
        // net.distances then takes the first complete). B is a direct neighbour
        // (distance 1); E sits behind D (distance 2). BOTH declare a COMPLETE
        // queryable for demo/q. A Request from A routes to B alone — never to D
        // (the direction toward the farther E).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // S -> idx 0
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        let (face_d, sink_d) = peer_face(zid(0x0D));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        fwd.register(FaceId(2), &face_d);
        // A and B are direct neighbours (distance 1); E sits behind D (distance 2).
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S-A
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05); // edge S-B
        fwd.ingest_inbound_linkstate(
            FaceId(2),
            list(vec![
                entry(0, 1, 0x05, &[]),     // self psid 0 -> teaches psid->zid
                entry(1, 5, 0x0D, &[0, 7]), // D links to self(0) and E(psid 7) -> edge S-D
                entry(7, 5, 0x0E, &[1]),    // E links to D(psid 1) -> E at distance 2
            ]),
        );
        fwd.net.borrow_mut().compute_trees();
        // B (distance 1) and E (distance 2, sourced via D's psid 7) both declare a
        // COMPLETE queryable for demo/q.
        declare_queryable_complete(&fwd, FaceId(1), "demo/q", 0, true); // B, direct source
        declare_queryable_complete(&fwd, FaceId(2), "demo/q", 7, true); // E, transit via D
        sink_a.reset();
        sink_b.reset();
        sink_d.reset();

        let request = wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);
        assert_eq!(
            sink_b.frame_count(),
            1,
            "routed to the NEAREST complete queryable B (distance 1)",
        );
        assert_eq!(
            sink_d.frame_count(),
            0,
            "the farther complete queryable E (distance 2, via D) is not selected",
        );
        assert_eq!(sink_a.frame_count(), 0, "not back to the source A");
    }

    #[test]
    fn declare_queryable_floods_completeness_and_registers_self() {
        // atom 4 producer: declare_queryable(keyexpr, complete) registers self's
        // OWN queryable AND floods a sourced DeclareQueryable CARRYING the
        // completeness to tree children — the wire input a downstream relay's
        // BestMatching select reads. A complete declaration stamps the ext; an
        // incomplete one OMITS it (DEFAULT, the byte-identical no-info wire).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S-A (A is S's child)
        sink_a.reset();

        // 1) A COMPLETE queryable: self registered + the flood carries complete=true.
        let reached = fwd.declare_queryable("demo/q", true).expect("declare");
        assert_eq!(reached, 1, "flooded to the one tree child A");
        assert_eq!(
            fwd.interested_queryables("demo/q"),
            vec![zid(0x05)],
            "self's OWN queryable is registered under its own zid",
        );
        assert_eq!(
            forwarded_declare_queryable_keyexpr(&sink_a.frame_bytes(0)).as_deref(),
            Some("demo/q"),
            "the carrier is a literal DeclareQueryable",
        );
        assert!(
            forwarded_declare_queryable_info(&sink_a.frame_bytes(0)).complete,
            "the flooded DeclareQueryable carries complete=true",
        );
        sink_a.reset();

        // 2) An INCOMPLETE queryable on a fresh key: the flood OMITS the ext
        //    (DEFAULT QueryableInfo) — the byte-identical no-info wire.
        fwd.declare_queryable("demo/r", false).expect("declare");
        assert!(
            !forwarded_declare_queryable_info(&sink_a.frame_bytes(0)).complete,
            "an incomplete queryable floods the DEFAULT (omitted) QueryableInfo",
        );
    }

    #[test]
    fn a_declared_complete_queryable_is_best_matching_selected_by_a_relay() {
        // atom 4 e2e (producer -> relay -> BestMatching select): the producer C
        // declares a COMPLETE queryable via declare_queryable; its flooded frame,
        // fed into relay S's forward_queryable, makes S store C's completeness, so
        // a Query from A at S BestMatching-selects C (not an All fan-out). Ties the
        // producer API (atom 4) to the select (atom 3) over the real wire.
        //
        // Producer C (0x0C) with one child link to the relay S (0x05).
        let producer = LinkstateForwarder::new(zid(0x0C), WhatAmI::Peer);
        let (c_to_s, c_sink) = peer_face(zid(0x05));
        producer.register(FaceId(0), &c_to_s);
        advertise_link_back(&producer, FaceId(0), 0x05, 0x0C); // S is C's tree child
        c_sink.reset();
        let reached = producer.declare_queryable("demo/q", true).expect("declare");
        assert_eq!(reached, 1, "C floods its complete queryable toward S");
        let c_declare = parse_forwarded_declare(&c_sink.frame_bytes(0));

        // Relay S (0x05) with the querier A (0x0A) and the producer C (0x0C).
        let relay = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (s_to_a, a_sink) = peer_face(zid(0x0A));
        let (s_to_c, s_c_sink) = peer_face(zid(0x0C));
        relay.register(FaceId(0), &s_to_a);
        relay.register(FaceId(1), &s_to_c);
        advertise_link_back(&relay, FaceId(0), 0x0A, 0x05); // S-A
        advertise_link_back(&relay, FaceId(1), 0x0C, 0x05); // S-C
                                                            // S ingests C's flooded complete queryable (node_id 0 -> source = neighbour C).
        relay.forward_queryable(FaceId(1), true, &c_declare);
        a_sink.reset();
        s_c_sink.reset();

        let request = wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
            .expect("build request");
        relay.forward_request(FaceId(0), true, &request);
        assert_eq!(
            s_c_sink.frame_count(),
            1,
            "the Query BestMatching-routes to the COMPLETE queryable at C",
        );
        assert_eq!(a_sink.frame_count(), 0, "not back to the querier A");
    }

    #[test]
    fn forward_request_all_target_fans_out_even_with_a_complete_queryable() {
        // QueryTarget::All (atom 4b): an EXPLICIT All target (Request ext_target)
        // fans out to EVERY matching queryable — it is NOT narrowed to the nearest
        // complete one. B complete + C incomplete, both children: an All query
        // reaches BOTH (contrast
        // forward_request_best_matching_routes_only_to_the_complete_queryable,
        // where the BestMatching wire default picks only B).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        let (face_c, sink_c) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        fwd.register(FaceId(2), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        advertise_link_back(&fwd, FaceId(2), 0x0C, 0x05);
        declare_queryable_complete(&fwd, FaceId(1), "demo/q", 0, true); // B complete
        declare_queryable_complete(&fwd, FaceId(2), "demo/q", 0, false); // C incomplete
        sink_a.reset();
        sink_b.reset();
        sink_c.reset();

        let request = wz_session_core::request_build::build_request_query_with_target(
            99,
            0,
            Some("demo/q"),
            QueryTarget::All,
        )
        .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);
        assert_eq!(
            sink_b.frame_count(),
            1,
            "All reaches the complete queryable B"
        );
        assert_eq!(
            sink_c.frame_count(),
            1,
            "All reaches the incomplete queryable C too (not narrowed)",
        );
        assert_eq!(sink_a.frame_count(), 0, "not back to the source A");
    }

    #[test]
    fn forward_request_all_complete_target_fans_out_to_complete_queryables_only() {
        // QueryTarget::AllComplete (atom 4b): fan out to EVERY COMPLETE queryable
        // (not narrowed to the nearest like BestMatching) but NOT the incomplete
        // ones. B + C complete, D incomplete (all self's children): an AllComplete
        // query reaches B and C, never D.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        let (face_c, sink_c) = peer_face(zid(0x0C));
        let (face_d, sink_d) = peer_face(zid(0x0D));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        fwd.register(FaceId(2), &face_c);
        fwd.register(FaceId(3), &face_d);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        advertise_link_back(&fwd, FaceId(2), 0x0C, 0x05);
        advertise_link_back(&fwd, FaceId(3), 0x0D, 0x05);
        declare_queryable_complete(&fwd, FaceId(1), "demo/q", 0, true); // B complete
        declare_queryable_complete(&fwd, FaceId(2), "demo/q", 0, true); // C complete
        declare_queryable_complete(&fwd, FaceId(3), "demo/q", 0, false); // D incomplete
        sink_a.reset();
        sink_b.reset();
        sink_c.reset();
        sink_d.reset();

        let request = wz_session_core::request_build::build_request_query_with_target(
            99,
            0,
            Some("demo/q"),
            QueryTarget::AllComplete,
        )
        .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);
        assert_eq!(sink_b.frame_count(), 1, "AllComplete reaches complete B");
        assert_eq!(sink_c.frame_count(), 1, "AllComplete reaches complete C");
        assert_eq!(
            sink_d.frame_count(),
            0,
            "AllComplete excludes the incomplete queryable D",
        );
        assert_eq!(sink_a.frame_count(), 0, "not back to the source A");
    }

    #[test]
    fn forward_request_with_no_queryable_sends_a_prompt_final_to_the_querier() {
        // zenoh route_query EMPTY route (R311uv, dispatcher/queries.rs:518-530): a
        // Request whose keyexpr no peer offers a queryable for is not RELAYED — but
        // the relay sends a prompt ResponseFinal straight back to the querier so
        // its get() terminates immediately instead of waiting out its own timeout.
        // No pending entry is recorded (nothing is awaited).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        sink_a.reset();
        sink_b.reset();

        let request = wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);
        assert_eq!(
            sink_b.frame_count(),
            0,
            "no queryable -> not relayed onward"
        );
        assert_eq!(
            sink_a.frame_count(),
            1,
            "a prompt ResponseFinal routed back to the querier A",
        );
        assert_eq!(
            forwarded_response_final(&sink_a.frame_bytes(0)).request_id,
            99,
            "the prompt final carries the querier's rid",
        );
        assert_eq!(
            fwd.pending_len(),
            0,
            "no pending entry recorded — nothing is awaited on an empty route",
        );
    }

    #[test]
    fn forward_request_all_complete_with_no_complete_queryable_sends_a_prompt_final() {
        // The empty-route final for the case uo's AllComplete widened (R311uv): a
        // matching queryable EXISTS but is INCOMPLETE, so an AllComplete query has
        // no target — the relay sends a prompt ResponseFinal back rather than
        // leaving the querier to time out. (A default BestMatching query here would
        // instead fall back to All and reach the incomplete B; only AllComplete
        // empties the route.)
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        declare_queryable_complete(&fwd, FaceId(1), "demo/q", 0, false); // B INCOMPLETE
        sink_a.reset();
        sink_b.reset();

        let request = wz_session_core::request_build::build_request_query_with_target(
            99,
            0,
            Some("demo/q"),
            QueryTarget::AllComplete,
        )
        .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);
        assert_eq!(
            sink_b.frame_count(),
            0,
            "no COMPLETE queryable -> AllComplete relays nowhere",
        );
        assert_eq!(
            sink_a.frame_count(),
            1,
            "a prompt ResponseFinal back to the querier A",
        );
        assert_eq!(
            forwarded_response_final(&sink_a.frame_bytes(0)).request_id,
            99,
            "the prompt final carries the querier's rid",
        );
    }

    #[test]
    fn a_subscriber_does_not_attract_a_routed_query() {
        // The query route reads qabls, NOT subs: a peer that only SUBSCRIBES to
        // the keyexpr is not a query target (the planes are separate). B
        // subscribes to demo/q but offers no queryable -> the Request routes
        // nowhere, even though a Push for demo/q WOULD reach B.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_b, sink_b) = peer_face(zid(0x0B));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        declare_interest(&fwd, FaceId(1), "demo/q"); // B SUBSCRIBES (not a queryable)
        sink_a.reset();
        sink_b.reset();

        let request = wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);
        assert_eq!(
            sink_b.frame_count(),
            0,
            "a subscriber is not a query target (qabls is read, not subs)"
        );
    }

    // ── §5.15 query routing atom 3: the Reply RETURN path ──

    /// The single forwarded Response decoded from a recorded wire frame.
    fn forwarded_response(frame: &[u8]) -> ResponseOwned {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let InboundFrame::Frame { payload, .. } =
            parse_inbound(frame).expect("parse forwarded frame")
        else {
            panic!("forwarded bytes are not a Frame");
        };
        let msgs = parse_frame_payload(&payload).expect("parse frame payload");
        match msgs.into_iter().next() {
            Some(NetworkMessage::Response(r)) => *r,
            other => panic!("expected a forwarded Response, got {other:?}"),
        }
    }

    /// The single forwarded ResponseFinal decoded from a recorded wire frame.
    fn forwarded_response_final(frame: &[u8]) -> ResponseFinalOwned {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let InboundFrame::Frame { payload, .. } =
            parse_inbound(frame).expect("parse forwarded frame")
        else {
            panic!("forwarded bytes are not a Frame");
        };
        let msgs = parse_frame_payload(&payload).expect("parse frame payload");
        match msgs.into_iter().next() {
            Some(NetworkMessage::ResponseFinal(rf)) => rf,
            other => panic!("expected a forwarded ResponseFinal, got {other:?}"),
        }
    }

    #[test]
    fn a_query_routes_to_a_queryable_and_the_reply_routes_back() {
        // The full query lifecycle through one relay S: A (querier side) — S — C
        // (queryable side). A's Query routes to C with a REMAPPED qid + a recorded
        // pending entry; C's Response + ResponseFinal route BACK to A with the
        // request_id rewritten to A's original rid; the final frees the entry.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // S
        let (face_a, sink_a) = peer_face(zid(0x0A)); // querier side, FaceId 0
        let (face_c, sink_c) = peer_face(zid(0x0C)); // queryable side, FaceId 1
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05); // edge S-A
        advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05); // edge S-C
        declare_queryable_interest(&fwd, FaceId(1), "demo/q"); // C holds the queryable
        sink_a.reset();
        sink_c.reset();

        // 1) A routed Query from A (rid 99) routes to C, REMAPPED to a local qid +
        //    a recorded pending return entry.
        let request = wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the Query reached the queryable side C"
        );
        let qid = forwarded_request(&sink_c.frame_bytes(0)).rid;
        assert_ne!(
            qid, 99,
            "the rid was REMAPPED to a local qid (not carried verbatim)"
        );
        assert_eq!(
            fwd.pending_len(),
            1,
            "one pending-query return entry recorded"
        );

        // 2) C replies with a Response carrying that qid -> routes back to A, the
        //    request_id rewritten to 99 (A's rid); the entry SURVIVES (more replies
        //    may follow).
        let response =
            wz_session_core::response_build::build_response_reply_literal(qid, "demo/q", b"hi")
                .expect("build response");
        fwd.forward_response(FaceId(1), true, &response);
        assert_eq!(
            sink_a.frame_count(),
            1,
            "the Reply routed back to querier side A"
        );
        assert_eq!(
            forwarded_response(&sink_a.frame_bytes(0)).request_id,
            99,
            "the response request_id rewritten back to the querier's rid"
        );
        assert_eq!(
            fwd.pending_len(),
            1,
            "a Response (not final) keeps the entry"
        );

        // 3) C sends a ResponseFinal -> routes back AND frees the entry.
        let rf = wz_session_core::response_final_build::build_response_final(qid);
        fwd.forward_response_final(FaceId(1), true, &rf);
        assert_eq!(sink_a.frame_count(), 2, "the final routed back to A too");
        assert_eq!(
            forwarded_response_final(&sink_a.frame_bytes(1)).request_id,
            99,
            "the final's request_id rewritten back to the querier's rid"
        );
        assert_eq!(fwd.pending_len(), 0, "the final freed the pending entry");
    }

    #[test]
    fn an_unknown_response_qid_drops_without_routing() {
        // A Response carrying a qid this relay never allocated has no pending entry
        // -> it drops silently (no panic, nothing routed).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        let (face_c, _sc) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05);
        sink_a.reset();

        let response =
            wz_session_core::response_build::build_response_reply_literal(42, "demo/q", b"x")
                .expect("build response");
        fwd.forward_response(FaceId(1), true, &response);
        assert_eq!(sink_a.frame_count(), 0, "an unknown qid routes nowhere");
        assert_eq!(fwd.pending_len(), 0, "and records nothing");
    }

    #[test]
    fn a_fanned_query_closes_upstream_only_after_the_last_branch_finalizes() {
        // The fan-aggregation last-out gate (zenoh's one Arc<Query> per fan +
        // Arc::into_inner in finalize_pending_query): a Query fanned to TWO
        // queryables (B and C, both DEFAULT/incomplete -> BestMatching falls back
        // to All) closes upstream exactly ONCE, after BOTH branches finalize. The
        // first final is ABSORBED, a reply from the still-open branch STILL
        // routes, the last final propagates.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A)); // querier
        let (face_b, sink_b) = peer_face(zid(0x0B)); // queryable 1
        let (face_c, sink_c) = peer_face(zid(0x0C)); // queryable 2
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_b);
        fwd.register(FaceId(2), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0B, 0x05);
        advertise_link_back(&fwd, FaceId(2), 0x0C, 0x05);
        declare_queryable_interest(&fwd, FaceId(1), "demo/q");
        declare_queryable_interest(&fwd, FaceId(2), "demo/q");
        sink_a.reset();
        sink_b.reset();
        sink_c.reset();

        let request = wz_session_core::request_build::build_request_query(91, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);
        assert_eq!(fwd.pending_len(), 2, "two branches pending (B and C)");
        let qid_b = forwarded_request(&sink_b.frame_bytes(0)).rid;
        let qid_c = forwarded_request(&sink_c.frame_bytes(0)).rid;

        // B finalizes FIRST: absorbed — no upstream final while C still answers.
        let rf_b = wz_session_core::response_final_build::build_response_final(qid_b);
        fwd.forward_response_final(FaceId(1), true, &rf_b);
        assert_eq!(
            sink_a.frame_count(),
            0,
            "the first branch's final is absorbed (the fan is still open)"
        );
        assert_eq!(fwd.pending_len(), 1, "B's branch freed, C's remains");

        // C's reply AFTER B's final still routes back.
        let response =
            wz_session_core::response_build::build_response_reply_literal(qid_c, "demo/q", b"hi")
                .expect("build response");
        fwd.forward_response(FaceId(2), true, &response);
        assert_eq!(sink_a.frame_count(), 1, "C's reply routed back to A");
        assert_eq!(forwarded_response(&sink_a.frame_bytes(0)).request_id, 91);

        // C finalizes LAST: exactly one upstream final closes the fan.
        let rf_c = wz_session_core::response_final_build::build_response_final(qid_c);
        fwd.forward_response_final(FaceId(2), true, &rf_c);
        assert_eq!(
            sink_a.frame_count(),
            2,
            "exactly one upstream final, after the LAST branch"
        );
        assert_eq!(
            forwarded_response_final(&sink_a.frame_bytes(1)).request_id,
            91,
            "carrying the querier's rid"
        );
        assert_eq!(fwd.pending_len(), 0, "the fan is fully freed");
    }

    #[test]
    fn an_unresolvable_keyexpr_alias_prompts_a_response_final() {
        // A Query whose aliased keyexpr id is unknown on the inbound face cannot
        // be routed, but the querier is TERMINATED with a prompt ResponseFinal
        // (zenoh route_query's unknown-scope final) rather than silently dropped
        // to hang until its own timeout — the router twin's behavior, backported.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        sink_a.reset();
        // An aliased wireexpr (mapping id 9, no suffix) with no prior DeclKexpr.
        let request = wz_session_core::request_build::build_request_query(80, 9, None)
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);
        assert_eq!(sink_a.frame_count(), 1, "the querier is terminated");
        assert_eq!(
            forwarded_response_final(&sink_a.frame_bytes(0)).request_id,
            80,
            "the prompt final carries the querier's rid"
        );
        assert_eq!(fwd.pending_len(), 0, "nothing was routed or awaited");
    }

    #[test]
    fn a_query_whose_only_direction_is_the_querier_side_prompts_a_final() {
        // The effective-empty-route termination: the only matching queryable is
        // the QUERIER's own peer, so the (non-empty) direction set resolves back
        // toward the inbound side, which the tree-target predicate excludes —
        // ZERO live fan targets. Previously total silence (no pending entry, so
        // not even the timeout could rescue the querier); now the unrouted tail
        // terminates it with the prompt final, zenoh's route.is_empty() guarantee
        // expressed at wz's face-matching fan.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A));
        fwd.register(FaceId(0), &face_a);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        declare_queryable_interest(&fwd, FaceId(0), "demo/q"); // A itself holds it
        sink_a.reset();
        let request = wz_session_core::request_build::build_request_query(81, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);
        assert_eq!(fwd.pending_len(), 0, "no branch was forwarded");
        assert_eq!(
            sink_a.frame_count(),
            1,
            "the querier received the prompt final instead of silence"
        );
        assert_eq!(
            forwarded_response_final(&sink_a.frame_bytes(0)).request_id,
            81,
            "carrying the querier's rid"
        );
    }

    #[test]
    fn an_ext_timeout_overrides_the_relay_default_deadline() {
        // zenoh route_query arms the pending deadline from the Query's OWN
        // carried ext_timeout (`ext_timeout.unwrap_or(queries_default_timeout)`,
        // dispatcher/queries.rs:514) — a relay must honor it, not its 10s knob.
        // A 5ms ext on an un-answered query is reaped at 5ms (the default would
        // not reap for 10s).
        let base = Instant::now();
        let offset = Rc::new(Cell::new(Duration::ZERO));
        let offset_clock = offset.clone();
        let fwd = LinkstateForwarder::with_clock(
            zid(0x05),
            WhatAmI::Peer,
            Box::new(move || base + offset_clock.get()),
        );
        let (face_a, sink_a) = peer_face(zid(0x0A)); // querier side
        let (face_c, _sc) = peer_face(zid(0x0C)); // queryable side (never replies)
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05);
        declare_queryable_interest(&fwd, FaceId(1), "demo/q");
        fwd.tick(); // flush the topology recompute so later ticks only reap
        sink_a.reset();
        let request = wz_session_core::request_build::build_request_query_with_timeout_ms(
            90,
            0,
            Some("demo/q"),
            5,
        )
        .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);
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
        // This relay must pass it THROUGH with only the rid rewritten — zenoh
        // route_send_response does no keyexpr resolution — not drop it at
        // resolve_wireexpr (which returns None for the empty form).
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, sink_a) = peer_face(zid(0x0A)); // querier side
        let (face_c, sink_c) = peer_face(zid(0x0C)); // queryable side
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05);
        declare_queryable_interest(&fwd, FaceId(1), "demo/q");
        sink_a.reset();
        sink_c.reset();
        let request = wz_session_core::request_build::build_request_query(95, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);
        let qid = forwarded_request(&sink_c.frame_bytes(0)).rid;
        // The downstream hop times out ITS branch and synthesizes the Err — the
        // exact wire shape the reap emits — which arrives here as a Response.
        let err = wz_session_core::response_build::build_response_err_empty(qid, b"Timeout")
            .expect("build err");
        fwd.forward_response(FaceId(1), true, &err);
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

    #[test]
    fn deregister_drops_a_faces_pending_queries() {
        // A face going down must drop its pending-query return entries, so a Reply
        // is never expected back from (or routed toward) a dead face.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer);
        let (face_a, _sa) = peer_face(zid(0x0A));
        let (face_c, _sc) = peer_face(zid(0x0C));
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05);
        declare_queryable_interest(&fwd, FaceId(1), "demo/q");

        let request = wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request); // records pending on FaceId(1)
        assert_eq!(
            fwd.pending_len(),
            1,
            "a pending entry recorded on the out face"
        );

        fwd.deregister(FaceId(1)); // the queryable-side face goes down
        assert_eq!(
            fwd.pending_len(),
            0,
            "deregister purged the departed face's pending queries"
        );
    }

    #[test]
    fn a_pending_query_times_out_and_finalizes_back_to_the_querier() {
        // A queryable that never sends its ResponseFinal on a STILL-UP face must
        // not leak the relay's pending entry: the tick sweep abandons it after the
        // query timeout and routes a synthesized ResponseFinal back to the querier
        // (zenoh's per-query QueryCleanup -> finalize_pending_query). Same A — S —
        // C shape as the happy-path reply test, but C stays silent.
        let fwd = LinkstateForwarder::new(zid(0x05), WhatAmI::Peer); // S
        let (face_a, sink_a) = peer_face(zid(0x0A)); // querier side, FaceId 0
        let (face_c, sink_c) = peer_face(zid(0x0C)); // queryable side, FaceId 1
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05);
        declare_queryable_interest(&fwd, FaceId(1), "demo/q");
        // Flush the setup recompute first, so the LATER sweeping tick emits ONLY
        // the timeout final (not a re-advertise from a pending topology change).
        fwd.tick();
        sink_a.reset();
        sink_c.reset();

        // A zero timeout makes the entry forward_request records expire at once —
        // the next tick reaps it. (Set before forward_request: the deadline is
        // stamped at allocate time, not at sweep time.)
        fwd.set_query_timeout(Duration::ZERO);
        let request = wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request);
        assert_eq!(
            sink_c.frame_count(),
            1,
            "the Query reached the queryable side C"
        );
        assert_eq!(fwd.pending_len(), 1, "one pending return entry recorded");
        assert_eq!(fwd.pending_timed_out(), 0, "nothing reaped yet");
        // Clear the queryable-side sink so the post-sweep assertion isolates what
        // the TIMEOUT routed (the forwarded Query already sits in sink_c).
        sink_c.reset();

        // C never replies. The tick sweep reaps the expired entry and routes two
        // messages back to the querier side A (FaceId 0), exactly zenoh
        // QueryCleanup::run: an Err("Timeout") reply THEN the closing
        // ResponseFinal, both with the request_id rewritten to A's original 99.
        fwd.tick();
        assert_eq!(fwd.pending_len(), 0, "the timeout freed the pending entry");
        assert_eq!(fwd.pending_timed_out(), 1, "one query reaped by the sweep");
        assert_eq!(
            sink_a.frame_count(),
            2,
            "an Err(Timeout) reply + the closing final routed back to A"
        );
        // Frame 0: the Err("Timeout") reply, rid rewritten to 99.
        let err = forwarded_response(&sink_a.frame_bytes(0));
        assert_eq!(
            err.request_id, 99,
            "the timeout Err carries the querier's rid"
        );
        match &err.body {
            wz_codecs::response::ResponseOwnedVariant::CodecZenohErr(e) => {
                assert_eq!(
                    e.payload.as_slice(),
                    b"Timeout",
                    "the timeout reply body is the Timeout marker"
                );
            }
            other => panic!("expected an Err(Timeout) reply, got {other:?}"),
        }
        // Frame 1: the closing final, rid rewritten to 99.
        assert_eq!(
            forwarded_response_final(&sink_a.frame_bytes(1)).request_id,
            99,
            "the synthesized final carries the querier's rid"
        );
        assert_eq!(
            sink_c.frame_count(),
            0,
            "nothing routed toward the silent queryable"
        );
    }

    #[test]
    fn a_pending_query_is_reaped_only_after_its_non_zero_deadline_passes() {
        // R311us — the clock-injection twin of the zero-timeout reap test: with a
        // NON-ZERO timeout and an INJECTED clock, a pending query survives a sweep
        // BEFORE its deadline and is reaped only once "now" reaches it. The
        // zero-timeout test can only prove "reaped immediately"; this pins the
        // deadline ARITHMETIC — reaped AT, not before. The fake clock returns
        // `base + offset`; advancing `offset` is the controllable virtual time.
        let base = Instant::now();
        let offset = Rc::new(Cell::new(Duration::ZERO));
        let offset_clock = offset.clone();
        let fwd = LinkstateForwarder::with_clock(
            zid(0x05),
            WhatAmI::Peer,
            Box::new(move || base + offset_clock.get()),
        );
        let (face_a, sink_a) = peer_face(zid(0x0A)); // querier side
        let (face_c, sink_c) = peer_face(zid(0x0C)); // queryable side
        fwd.register(FaceId(0), &face_a);
        fwd.register(FaceId(1), &face_c);
        advertise_link_back(&fwd, FaceId(0), 0x0A, 0x05);
        advertise_link_back(&fwd, FaceId(1), 0x0C, 0x05);
        declare_queryable_interest(&fwd, FaceId(1), "demo/q");
        sink_a.reset();
        sink_c.reset();

        let timeout = Duration::from_millis(100);
        fwd.set_query_timeout(timeout);
        let request = wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
            .expect("build request");
        fwd.forward_request(FaceId(0), true, &request); // deadline = base + 0 + 100ms
        assert_eq!(fwd.pending_len(), 1, "one pending return entry recorded");

        // Just BEFORE the deadline: the sweep does NOT reap it.
        offset.set(timeout - Duration::from_millis(1));
        fwd.reap_timed_out_queries();
        assert_eq!(
            fwd.pending_len(),
            1,
            "not yet past the deadline -> survives"
        );
        assert_eq!(
            fwd.pending_timed_out(),
            0,
            "nothing reaped before the deadline"
        );
        assert_eq!(
            sink_a.frame_count(),
            0,
            "no premature timeout final to the querier",
        );

        // AT the deadline: reaped, and the Err(Timeout) + closing final route to A.
        offset.set(timeout);
        fwd.reap_timed_out_queries();
        assert_eq!(fwd.pending_len(), 0, "reaped once now reached the deadline");
        assert_eq!(fwd.pending_timed_out(), 1, "one query reaped by the sweep");
        assert_eq!(
            sink_a.frame_count(),
            2,
            "the Err(Timeout) reply + the closing final routed back to A",
        );
    }

    /// Feed an already-decoded [`NetworkMessage`] into `fwd` on `face` as one
    /// inbound frame — the shuttle primitive for the two-relay e2e: one relay's
    /// recorded wire frame is decoded and replayed into the next relay's real
    /// `forward()` inbound path (decode + dispatch), exercising the full hop.
    fn feed_message(fwd: &LinkstateForwarder, face: FaceId, msg: NetworkMessage) {
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![msg],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(face, IterationEvent::Poll(&outcome));
    }

    #[test]
    fn a_query_routes_across_two_relays_and_the_reply_unwinds_both_hops() {
        // The TWO-INSTANCE composition the single-relay tests cannot cover: a
        // query crosses A — S1 — S2 — C through two independent LinkstateForwarder
        // instances, the qid remapped AT EACH hop (S1 allocates qid_a, S2 allocates
        // qid_b keyed on qid_a), and the Reply + ResponseFinal unwind back through
        // BOTH pending tables (qid_b -> qid_a -> A's rid 99). Frames are shuttled
        // relay-to-relay through the real wire-decode + forward() inbound path.
        let s1 = LinkstateForwarder::new(zid(0x01), WhatAmI::Peer);
        let s2 = LinkstateForwarder::new(zid(0x02), WhatAmI::Peer);
        // S1 faces: 0 = A (querier side), 1 = S2.
        let (a_face, a_sink) = peer_face(zid(0x0A));
        let (s2_on_s1, s1_to_s2) = peer_face(zid(0x02));
        s1.register(FaceId(0), &a_face);
        s1.register(FaceId(1), &s2_on_s1);
        // S2 faces: 0 = S1, 1 = C (queryable side).
        let (s1_on_s2, s2_to_s1) = peer_face(zid(0x01));
        let (c_face, c_sink) = peer_face(zid(0x0C));
        s2.register(FaceId(0), &s1_on_s2);
        s2.register(FaceId(1), &c_face);

        // Topology A-S1-S2-C on each relay (line: a unique path to C from any
        // source). S1 learns A direct (FaceId0) + the S2-C chain (FaceId1); S2
        // learns C direct (FaceId1) + the S1-A chain (FaceId0).
        advertise_link_back(&s1, FaceId(0), 0x0A, 0x01);
        s1.ingest_inbound_linkstate(
            FaceId(1),
            list(vec![
                entry(0, 1, 0x01, &[]),
                entry(1, 5, 0x02, &[0, 2]),
                entry(2, 5, 0x0C, &[1]),
            ]),
        );
        s1.net.borrow_mut().compute_trees();
        advertise_link_back(&s2, FaceId(1), 0x0C, 0x02);
        s2.ingest_inbound_linkstate(
            FaceId(0),
            list(vec![
                entry(0, 1, 0x02, &[]),
                entry(1, 5, 0x01, &[0, 2]),
                entry(2, 5, 0x0A, &[1]),
            ]),
        );
        s2.net.borrow_mut().compute_trees();
        // C's queryable, registered on S2 (direct) and on S1 (learned via S2): both
        // relays must route the query toward the queryable direction.
        declare_queryable_interest(&s2, FaceId(1), "demo/q");
        declare_queryable_interest(&s1, FaceId(1), "demo/q");
        a_sink.reset();
        s1_to_s2.reset();
        s2_to_s1.reset();
        c_sink.reset();

        // 1) A's Query (rid 99) into S1 -> forwarded to S2 with a remapped qid_a.
        let request = wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
            .expect("build request");
        feed_message(&s1, FaceId(0), NetworkMessage::Request(Box::new(request)));
        assert_eq!(s1_to_s2.frame_count(), 1, "S1 forwarded the Query to S2");
        let req_s2 = forwarded_request(&s1_to_s2.frame_bytes(0));
        let qid_a = req_s2.rid;
        assert_ne!(qid_a, 99, "S1 remapped the rid to its own local qid_a");
        assert_eq!(s1.pending_len(), 1, "S1 recorded one pending entry");

        // 2) S1's forwarded Query into S2 -> forwarded to C with a remapped qid_b.
        feed_message(&s2, FaceId(0), NetworkMessage::Request(Box::new(req_s2)));
        assert_eq!(s2_to_s1.frame_count(), 0, "S2 does not echo back to S1");
        assert_eq!(c_sink.frame_count(), 1, "S2 forwarded the Query on to C");
        let req_c = forwarded_request(&c_sink.frame_bytes(0));
        let qid_b = req_c.rid;
        // qid_a and qid_b are INDEPENDENT per-(relay, face) counters, so both
        // legitimately start at 1 — the remap is per-relay STATE (each relay maps
        // its own qid back to the rid it received), not a distinct value. The proof
        // it composed is the reply unwinding below (qid_b -> qid_a -> 99).
        assert_eq!(s2.pending_len(), 1, "S2 recorded its own pending entry");

        // 3) C's Reply (carrying qid_b) into S2 -> back to S1 with request_id qid_a.
        let reply =
            wz_session_core::response_build::build_response_reply_literal(qid_b, "demo/q", b"hi")
                .expect("build reply");
        feed_message(&s2, FaceId(1), NetworkMessage::Response(Box::new(reply)));
        assert_eq!(
            s2_to_s1.frame_count(),
            1,
            "S2 routed the Reply back toward S1"
        );
        let resp_s1 = forwarded_response(&s2_to_s1.frame_bytes(0));
        assert_eq!(
            resp_s1.request_id, qid_a,
            "S2 rewrote request_id back to qid_a"
        );

        // 4) S1's relayed Reply into S1 -> back to A with request_id 99.
        feed_message(&s1, FaceId(1), NetworkMessage::Response(Box::new(resp_s1)));
        assert_eq!(a_sink.frame_count(), 1, "the Reply reached the querier A");
        assert_eq!(
            forwarded_response(&a_sink.frame_bytes(0)).request_id,
            99,
            "S1 rewrote request_id back to A's original 99 — the reply unwound both hops"
        );
        // Both pending entries survive a Reply (more replies may follow).
        assert_eq!(s2.pending_len(), 1, "S2 keeps its entry past a Reply");
        assert_eq!(s1.pending_len(), 1, "S1 keeps its entry past a Reply");

        // 5) C's ResponseFinal (qid_b) -> S2 (frees) -> S1 (frees) -> A (rid 99).
        let rf = wz_session_core::response_final_build::build_response_final(qid_b);
        feed_message(&s2, FaceId(1), NetworkMessage::ResponseFinal(rf));
        assert_eq!(s2.pending_len(), 0, "the final freed S2's entry");
        let final_s1 = forwarded_response_final(&s2_to_s1.frame_bytes(1));
        assert_eq!(final_s1.request_id, qid_a, "S2 rewrote the final to qid_a");
        feed_message(&s1, FaceId(1), NetworkMessage::ResponseFinal(final_s1));
        assert_eq!(s1.pending_len(), 0, "the final freed S1's entry too");
        assert_eq!(
            forwarded_response_final(&a_sink.frame_bytes(1)).request_id,
            99,
            "the closing final reached A with the querier's rid",
        );
    }

    #[test]
    fn a_complete_queryable_propagates_two_hops_and_best_matching_routes_to_it() {
        // Multi-hop BestMatching e2e (R311uu — closes the uq coverage gap that had
        // only a single-relay select test + propagation UNIT tests): a COMPLETE
        // queryable at C, declared on S2, PROPAGATES its completeness to S1 (TWO
        // hops away) via the real re-flood frame (the uq downstream carry); S1 then
        // BestMatching-routes a default Query toward C by GRAPH distance, across
        // two independent LinkstateForwarder instances. Topology A — S1 — S2 — C.
        let s1 = LinkstateForwarder::new(zid(0x01), WhatAmI::Peer);
        let s2 = LinkstateForwarder::new(zid(0x02), WhatAmI::Peer);
        let (a_face, a_sink) = peer_face(zid(0x0A));
        let (s2_on_s1, s1_to_s2) = peer_face(zid(0x02));
        s1.register(FaceId(0), &a_face);
        s1.register(FaceId(1), &s2_on_s1);
        let (s1_on_s2, s2_to_s1) = peer_face(zid(0x01));
        let (c_face, c_sink) = peer_face(zid(0x0C));
        s2.register(FaceId(0), &s1_on_s2);
        s2.register(FaceId(1), &c_face);
        // The same A-S1-S2-C line each relay sees in the reply-unwind e2e.
        advertise_link_back(&s1, FaceId(0), 0x0A, 0x01);
        s1.ingest_inbound_linkstate(
            FaceId(1),
            list(vec![
                entry(0, 1, 0x01, &[]),
                entry(1, 5, 0x02, &[0, 2]),
                entry(2, 5, 0x0C, &[1]),
            ]),
        );
        s1.net.borrow_mut().compute_trees();
        advertise_link_back(&s2, FaceId(1), 0x0C, 0x02);
        s2.ingest_inbound_linkstate(
            FaceId(0),
            list(vec![
                entry(0, 1, 0x02, &[]),
                entry(1, 5, 0x01, &[0, 2]),
                entry(2, 5, 0x0A, &[1]),
            ]),
        );
        s2.net.borrow_mut().compute_trees();
        a_sink.reset();
        s1_to_s2.reset();
        s2_to_s1.reset();
        c_sink.reset();

        // 1) C declares a COMPLETE queryable on S2 (node_id 0 = C is S2's direct
        //    neighbour). S2 stores C's completeness AND re-floods a CARRYING
        //    DeclareQueryable toward its tree child S1 (the uq downstream carry).
        declare_queryable_complete(&s2, FaceId(1), "demo/q", 0, true);
        assert_eq!(
            s2_to_s1.frame_count(),
            1,
            "S2 re-floods C's queryable toward its child S1",
        );
        assert!(
            forwarded_declare_queryable_info(&s2_to_s1.frame_bytes(0)).complete,
            "S2's re-flood CARRIES C's complete=true downstream to S1 (the uq carry)",
        );

        // 2) Feed S2's re-flood into S1 (the real inbound handler): S1 — TWO hops
        //    from C — learns C is complete, registered back under the origin C.
        let reflood = parse_forwarded_declare(&s2_to_s1.frame_bytes(0));
        s1.forward_queryable(FaceId(1), true, &reflood);
        assert_eq!(
            s1.interested_queryables("demo/q"),
            vec![zid(0x0C)],
            "S1 registered C's queryable, resolved back to the origin C two hops away",
        );
        a_sink.reset();
        s1_to_s2.reset();

        // 3) A's default (BestMatching) Query into S1: S1 knows C is COMPLETE at
        //    GRAPH distance 2, so it BestMatching-routes toward C (direction S2) —
        //    the multi-hop select, not an All fan-out.
        let request = wz_session_core::request_build::build_request_query(99, 0, Some("demo/q"))
            .expect("build request");
        feed_message(&s1, FaceId(0), NetworkMessage::Request(Box::new(request)));
        assert_eq!(
            s1_to_s2.frame_count(),
            1,
            "S1 BestMatching-routes the Query toward C (nearest complete, 2 hops via S2)",
        );
        assert_eq!(a_sink.frame_count(), 0, "not routed back to the querier A");
        assert_eq!(s1.pending_len(), 1, "S1 recorded a pending return entry");
    }
}
