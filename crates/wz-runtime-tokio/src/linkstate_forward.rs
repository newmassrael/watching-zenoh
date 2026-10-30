// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The link-state routing cores the region-hat forwarder
//! ([`RouterForwarder`](crate::router_forward)) is built from, and the surface a
//! deploy names them by.
//!
//! This module held the single-net peer forwarder until open-debt item 751 step 7
//! (`docs/peer-region-hats.md`): a peer node is now the region-hat forwarder at node
//! mode Peer, and what is left here is what that forwarder, and the code around it,
//! reads without owning a forwarder's state:
//!
//! - the pure ROUTE CORES over one link-state net and its interest tables (the data
//!   route and the client leg of it, the query route and its target selection, the
//!   re-forward and the originate cores, the tree re-advertise), which take the net
//!   and the tables as arguments and answer a route, so that a hat of any region
//!   computes with them what a mesh node computes;
//! - the SYNTHESIS of the messages a reaped or drained query owes its querier;
//! - the read-only handle to a graph ([`NetHandle`], [`LinkstateNetView`]);
//! - the re-exports a deploy builds its policy and its configuration from
//!   (`wz::runtime_tokio::linkstate_forward::{AutoConnect, TransportWeight, AclPolicy, ..}`).
//!
//! `routing-router-hat`-gated: the cores have no caller without the forwarder.
//!
//! The name stays. What is here is still the forwarding cores over a link-state net, and
//! `wz::runtime_tokio::linkstate_forward::{..}` is the path a deploy names its policy and its
//! configuration by, so a rename would move a public path to say what the module's doc already
//! says (item 751 step 7c-2 left the name for that reason).

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;

use sce_forge_runtime::codec::CodecError;
use wz_codecs::declare::DeclareOwned;
use wz_session_core::declare_build::{build_declare_queryable, set_declare_queryable_info};
use wz_session_core::declare_routing_context::set_declare_source;
use wz_session_core::keyexpr_match::{keyexpr_includes_target, keyexpr_intersects_target};
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::push_build::set_push_keyexpr_literal;
use wz_session_core::push_routing_context::{
    read_push_hoplimit, read_push_source, set_push_hoplimit, set_push_source,
};
use wz_session_core::queryable_info::QueryableInfo;
use wz_session_core::wire::PushOwned;
use wz_session_core::wireexpr_resolve::wireexpr_names_a_declaration;

use wz_routing_graph::{LinkId, LinkstateNetwork, Versioned};

use crate::accept_loop::FaceId;
use crate::interceptor::InterceptorKind;
use crate::linkstate_interest::LinkstatepeerInterest;
use crate::linkstate_pending::{ExpiredQuery, QueryReturn};
use crate::route_cache::{RouteCache, RouteInputs};
use crate::session_glue::SessionLinkActions;

/// Re-export `Zid`, the typed [`WhatAmI`] role, and the gossip
/// [`AutoConnect`] policy so the peer-loop caller (the demo) names them by the
/// same SSOT type (defined in `wz-codecs` / the graph), not a bare byte. A deploy
/// opting into autoconnect builds its policy from [`default_autoconnect_matcher`]
/// (this module) + these re-exports, so the `router|peer` matcher is never
/// re-typed at the call site.
/// R2141 — [`AutoConnectStrategies`] and [`WhatAmIMatcher`] join them, because
/// the multicast plane's policy is built from a CONFIG rather than from a fixed
/// per-role default: `scouting/multicast/autoconnect` names its own matcher and
/// `_strategy` its own per-target table, and a caller that could not name those
/// two types would have to re-type them at the call site — which is the drift
/// this re-export exists to prevent.
pub use wz_codecs::whatami::WhatAmIMatcher;
pub use wz_routing_graph::{AutoConnect, AutoConnectStrategies, AutoConnectStrategy, WhatAmI, Zid};
// R2633 — the CONFIGURED link-weight surface, re-exported for the same reason
// and gated by the same feature: `wz-routing-graph` is an OPTIONAL dependency
// pulled by `routing-peer`, so these types exist exactly where this module does.
// A deploy that weights its router links names them on one path
// (`wz::runtime_tokio::linkstate_forward::{TransportWeight, link_weights_from_config}`)
// rather than re-typing the row shape at the call site. `zenoh_config`
// re-exports the same three for the CONFIG-FILE half, which needs its own
// feature; a build with the router hat and no config reader reaches them here.
pub use wz_routing_graph::{link_weights_from_config, DuplicateLinkWeight, TransportWeight};
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
// R311y452 adds `DownsamplingMessage` (a rule now names the message KINDS it
// throttles) and `interval_from_freq` (zenoh configures the rate as a FREQUENCY
// in Hertz, so a deploy speaking upstream's unit needs the mapping from the same
// facade path rather than re-deriving `1/freq` at the call site).
#[cfg(feature = "access-downsampling")]
pub use crate::interceptor::downsampling::{
    interval_from_freq, DownsamplingMessage, DownsamplingRule,
};
// R311tx — the low-pass (per-key message-size limit) rule type, re-exported
// beside the other rule types (the §5.16 access-quota realization). R311y451
// adds `LowPassMessage`: a rule now names the message KINDS it sizes, so a
// deploy needs the kind vocabulary from the same facade path as the rule.
#[cfg(feature = "access-quota")]
pub use crate::interceptor::low_pass::{LowPassMessage, LowPassRule};
// R311ty — the combined interceptor configuration, the single funnel a deploy
// fills and installs via `set_interceptors` (the wz mirror of zenoh's
// interceptor_factories(config)). Re-exported beside the rule types above so a
// deploy builds the whole pipeline from one facade path.
pub use crate::interceptor::InterceptorConfig;
// R311y451 — the flow descriptor, re-exported beside the config it is now part
// OF: a low-pass rule names the flows it applies to, so a deploy that builds a
// rule needs the flow vocabulary from the same facade path. Unconditional (the
// seam lives under `routing-peer`, not under an `access-*` knob).
pub use crate::interceptor::InterceptorFlow;
// R311y453 — the §5.16 SUBJECT vocabulary, re-exported beside the rule types: a
// deploy that narrows a rule by `link_protocols` needs the link-protocol names,
// and it must spell them the way upstream's config does (`from_config_str`).
pub use wz_session_core::link::{InterceptorLink, LinkSubject};

/// The default gossip-AUTOCONNECT matcher for a node of role `whatami` — zenoh's
/// `scouting.gossip.autoconnect` per-local default
/// (`commons/zenoh-config/src/defaults.rs`), DELIBERATELY a different profile from
/// the gossip target: a PEER autoconnects to discovered routers and peers
/// (`router|peer`), but a ROUTER autoconnects to NOBODY (the empty set — routers
/// are reached via configured links, not gossip-dialed), as does a CLIENT. The
/// role-correct matcher a deploy passes to [`AutoConnect::new`] when it opts a
/// node into autoconnect, so the `router|peer` literal is never re-hardcoded at
/// the (role-blind) call site — a router that hardcoded `router|peer` would
/// wrongly dial discovered peers.
pub const fn default_autoconnect_matcher(whatami: WhatAmI) -> WhatAmIMatcher {
    match whatami {
        WhatAmI::Peer => WhatAmIMatcher::empty().router().peer(),
        WhatAmI::Router | WhatAmI::Client => WhatAmIMatcher::empty(),
    }
}

/// A read-only, `Rc`-backed handle to a link-state graph, exposing ONLY the
/// adminspace render seam (§5.23 `adminspace-router-linkstate`): the GraphViz
/// DOT and the `route_successors` enumeration, each zid rendered to the zenoh
/// `ZenohId` Display hex an admin client expects. Handed to an admin-queryable
/// handler so it renders LIVE per GET (no per-tick snapshot buffer) WITHOUT
/// leaking a `borrow_mut` handle that could mutate routing state.
///
/// R2684 — it lives HERE, with `routing-peer`, rather than in the router hat
/// where it was written. The graph it views belongs to the peer tier, so a
/// plain linkstate peer owned the data while the handle that renders it sat
/// behind `routing-router-hat` — which is the whole of why `linkstate/peers`
/// could be served only from a router. `router_forward` re-exports it, so every
/// path that already named it is unchanged.
///
/// Gated on `adminspace-router-linkstate` because that is what the seam IS —
/// the render half of the admin linkstate legs, with no other consumer. Left
/// ungated it goes dead in every build serving no adminspace, and
/// `pub(crate) fn new` then trips `-D dead-code`; the diagnostic axis found
/// exactly that while probing an unrelated feature. Making the constructor
/// `pub` would also have silenced it — `pub` items draw no dead-code warning —
/// and that is the wrong repair twice: it hides the fact, and it lets a
/// consumer mint a view over a graph it obtained some other way.
#[cfg(feature = "adminspace-router-linkstate")]
pub struct LinkstateNetView<N = Arc<dyn NetHandle + Send + Sync>>(N);

/// A topology graph, read through whatever holds it: a single-task `Rc<RefCell<_>>`, a
/// lock, or the router's tables, where the graph is a field of a hat and a handle names the
/// region. What a view or a node-locator reads a graph through, so that neither knows how it is
/// held. The method takes a closure and not a guard because a guard would have to name the
/// holder's lock type.
pub trait NetHandle {
    /// Run `f` over the graph, holding it for as long as `f` runs.
    fn with_net(&self, f: &mut dyn FnMut(&LinkstateNetwork));
}

impl NetHandle for RefCell<LinkstateNetwork> {
    fn with_net(&self, f: &mut dyn FnMut(&LinkstateNetwork)) {
        f(&self.borrow())
    }
}

impl NetHandle for crate::sync::PlainRwLock<LinkstateNetwork> {
    fn with_net(&self, f: &mut dyn FnMut(&LinkstateNetwork)) {
        f(&self.read())
    }
}

impl<T: NetHandle + ?Sized> NetHandle for Rc<T> {
    fn with_net(&self, f: &mut dyn FnMut(&LinkstateNetwork)) {
        (**self).with_net(f)
    }
}

impl<T: NetHandle + ?Sized> NetHandle for Arc<T> {
    fn with_net(&self, f: &mut dyn FnMut(&LinkstateNetwork)) {
        (**self).with_net(f)
    }
}

/// `f` over the graph `net` holds, answering what `f` answers.
#[cfg(any(
    feature = "adminspace-router-linkstate",
    all(
        feature = "session-close-ingress",
        feature = "routing-peer",
        feature = "routing-accept",
        feature = "router-connect-reconcile",
        feature = "transport-link-tcp",
        feature = "transport-unicast"
    )
))]
pub(crate) fn read_net<R>(
    net: &(impl NetHandle + ?Sized),
    f: impl FnOnce(&LinkstateNetwork) -> R,
) -> R {
    let mut f = Some(f);
    let mut out = None;
    net.with_net(&mut |graph| {
        if let Some(f) = f.take() {
            out = Some(f(graph));
        }
    });
    out.expect("a graph handle runs the closure it is given")
}

#[cfg(feature = "adminspace-router-linkstate")]
impl<N: NetHandle> LinkstateNetView<N> {
    /// Wrap a shared graph in the render seam. `pub(crate)` rather than `pub`:
    /// the handle is a VIEW a forwarder hands out, never something a consumer
    /// mints over a graph it obtained some other way — which is the property
    /// that keeps the write lock from escaping.
    ///
    /// How the graph is held is the forwarder's: the router's is a [`NetHandle`] over its tables
    /// (the default).
    pub(crate) fn new(net: N) -> Self {
        Self(net)
    }

    /// The graph as GraphViz DOT with zenoh-hex node labels — the wz mirror of
    /// zenoh `info(..)` = `net.dot()` (`net/runtime/adminspace.rs:753,773`). The
    /// zid formatter is injected because `dot_with` (in the lower `wz-routing-
    /// graph` crate) cannot reach the `zid_to_zenoh_hex` SSOT itself.
    pub fn dot(&self) -> String {
        read_net(&self.0, |net| {
            net.dot_with(|z| wz_session_core::zid_hex::zid_to_zenoh_hex(z.as_slice()))
        })
    }

    /// Every `(source, destination, successor)` triple, each zid in zenoh-hex —
    /// the wz mirror of zenoh `route_successors()` (`net/protocol/network.rs:
    /// 1187`). Rendered from THIS net (the router adminspace uses `routers_net`
    /// for the `route/successor` legs, zenoh
    /// `zenoh/src/net/routing/hat/router/mod.rs` @ `fn route_successors`).
    pub fn route_successors_hex(&self) -> Vec<(String, String, String)> {
        read_net(&self.0, |net| {
            net.route_successors()
                .into_iter()
                .map(|(s, d, h)| {
                    (
                        wz_session_core::zid_hex::zid_to_zenoh_hex(s.as_slice()),
                        wz_session_core::zid_hex::zid_to_zenoh_hex(d.as_slice()),
                        wz_session_core::zid_hex::zid_to_zenoh_hex(h.as_slice()),
                    )
                })
                .collect()
        })
    }
}

/// R2371 (`transport-stats`) — charge ONE interceptor drop to the face's own
/// session counters, on the counter upstream puts that reason on.
///
/// # The mapping is upstream's, and it is not onto
///
/// `commons/zenoh-stats/src/stats.rs` @ `ReasonLabel::Downsampling` is the whole
/// set of interceptor reasons upstream counts: downsampling (messages) and
/// low-pass (messages AND bytes). An ACL denial has no counter there, so
/// [`InterceptorKind::AccessControl`] charges nothing here. That asymmetry is
/// deliberate — inventing a `wz_acl_dropped` counter would export a number no
/// zenoh dashboard reads, and folding an ACL denial into the downsampler's
/// counter would make a rate-limit graph move on a policy change. The forwarder's
/// own `interceptor_dropped` witness still counts every drop including this one,
/// which is where an ACL denial remains visible.
///
/// # Why the message is re-classified here
///
/// The byte figure `low_pass_dropped_bytes` wants is the PAYLOAD size, which is
/// exactly what [`wz_session_core::network_message::stats_class`] already
/// derives for the network counters. Deriving it once, in one place, is what
/// keeps a dropped Put's bytes measured the same way as a delivered Put's.
#[cfg(feature = "transport-stats")]
pub(crate) fn charge_interceptor_drop(
    actions: &SessionLinkActions,
    msg: &NetworkMessage,
    kind: InterceptorKind,
    flow: InterceptorFlow,
) {
    use wz_session_core::stats::StatDrop;
    let reason = match kind {
        InterceptorKind::Downsampling => StatDrop::Downsampling,
        InterceptorKind::LowPass => StatDrop::LowPass,
        // No upstream counter; see this function's docs. The QoS overwrite drops nothing, so
        // no verdict names it; it is here because the match is exhaustive.
        InterceptorKind::AccessControl | InterceptorKind::QosOverwrite => return,
    };
    // The peer's alias space is not reachable from here either (the face table
    // holds it, but a dropped message's SPACE moves no counter this function
    // charges — only the kind and the byte count do), so the resolver is empty
    // for the same stated reason the RX walk's is.
    let class = wz_session_core::network_message::stats_class(msg, |_id| None);
    let pl_bytes = class.payload.map_or(0, |p| p.pl_bytes);
    match flow {
        InterceptorFlow::Ingress => actions.stats.inc_rx_drop(reason, 1, pl_bytes),
        InterceptorFlow::Egress => actions.stats.inc_tx_drop(reason, 1, pl_bytes),
    }
}

/// The `transport-stats`-off twin: an interceptor drop still moves the
/// forwarder's own witness, and nothing else. Kept as a real function rather
/// than a `cfg` at each of the two call sites so the two flows cannot drift.
#[cfg(not(feature = "transport-stats"))]
pub(crate) fn charge_interceptor_drop(
    _actions: &SessionLinkActions,
    _msg: &NetworkMessage,
    _kind: InterceptorKind,
    _flow: InterceptorFlow,
) {
}

/// R2702 — the governed-keyexpr resolver and the three `Declare` keyexpr
/// readers MOVED to [`crate::interceptor::keyexpr`], and this re-export is how
/// every caller keeps its unqualified name. They were the only thing tying the
/// §5.16 seam to a routing build: nothing else under `interceptor/` names a
/// routing type, but its enforcer's resolver lived HERE, so `pub mod
/// interceptor` had to be `routing-peer`-gated. A forwarder is a CONSUMER of
/// that seam, so importing from it adds no edge — the old direction pointed from
/// the seam INTO one of its consumers.
pub(crate) use crate::interceptor::keyexpr::{
    declare_queryable_wireexpr, declare_subscriber_wireexpr, resolve_governed_keyexpr,
};

/// Emit the CURRENT-mode interest reply set from a per-keyexpr candidate map —
/// the shared SSOT of the `dump_interest_{subs,qabls}` legs of every hat. The
/// caller GATHERS its plane-specific `per_ke` (each keyexpr already folded to ONE
/// value `V` — `()` for subs, a merged
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
    mut build: impl FnMut(u64, &str, V) -> Result<DeclareOwned, CodecError>,
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

/// R2702 — the two peer-identity readers MOVED to [`crate::peer_identity`], and
/// this re-export is how every caller keeps its unqualified name. Both have two
/// consumers with different lifetimes — routing keys its graph on the zid, the
/// §5.16 enforcer reads both as subject axes — and while they lived here the
/// enforcer could only exist in a routing build. See that module for why the
/// conversion is host-side at all.
pub(crate) use crate::peer_identity::{peer_acl_username, peer_zid_routing};

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
/// (source zid, this node's out-psid for it) pair — the SSOT for
/// [`RouterForwarder`](crate::router_forward)'s per-tier resolution (R311y109).
/// The resolution reads ONLY the net (no faces / interest tables), so it is a
/// free fn over `&LinkstateNetwork` rather than a method.
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
    let source_zid = resolve_source_zid_in(net, inbound_zid, inbound_link, node_id)?;
    let out_node_id = u16::try_from(net.local_psid_of(&source_zid)?).ok()?;
    Some((source_zid, out_node_id))
}

/// R2893 (open-debt item 751, rule 8d) — the SOURCE half of
/// [`resolve_source_in`] alone: who originated a message, which the pin reads
/// off the inbound link without consulting its graph
/// (`zenoh/src/net/routing/hat/peer/mod.rs` @ `fn remote_node_id_to_zid`).
/// The psid [`resolve_source_in`] adds is what self stamps when it RELAYS
/// the message, and a single-hop gossip `Network` holds no node for a
/// neighbour until that neighbour announces itself, so asking for both would
/// drop a peer's first declaration in a region that never relays it anyway.
pub(crate) fn resolve_source_zid_in(
    net: &LinkstateNetwork,
    inbound_zid: Option<Zid>,
    inbound_link: Option<LinkId>,
    node_id: u16,
) -> Option<Zid> {
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
    Some(source_zid)
}

/// R2908 — the data-route cache of one (graph, subscription table) pair: per
/// keyexpr and source, this node's tree children toward the remote
/// subscribers. Each hat keeps one per mesh it routes over.
pub(crate) type DataRoutes = RouteCache<Arc<[Zid]>>;

/// A data forward: the carrier to send and the tree children to send it to,
/// the second a route [`DataRoutes`] may be serving.
pub(crate) type DataForward = (PushOwned, Arc<[Zid]>);

/// R2910 — a route cache together with the node's test of whether a keyexpr
/// names a routing resource: what every cached route is asked through.
///
/// Upstream keeps ONE resource tree per node, and every hat's route cache
/// hangs off it, so a keyexpr declared in any region is a resource for every
/// hat (`zenoh/src/net/routing/dispatcher/resource.rs` @ `pub(crate) hats: RegionMap<HatResourceContext>,`).
/// R2908 asked each table alone, which a router measured wrong at once: a
/// keyexpr only the peer mesh declared was recomputed on every query in the
/// router mesh. So the test is the FORWARDER's, over all of its tables, and a
/// cache cannot be reached without it.
#[derive(Clone, Copy)]
pub(crate) struct Cached<'a, R> {
    /// The cache routes are served from and kept in.
    pub(crate) routes: &'a R,
    /// Whether a keyexpr is declared anywhere on this node.
    pub(crate) names_a_resource: &'a dyn Fn(&str) -> bool,
}

/// R2908 — the data route from `source` for `keyexpr`: this node's children
/// on `source`'s tree toward every REMOTE subscriber (self is the local sink,
/// never a mesh target), served from the cache while neither table changed
/// (upstream's `get_hat_data_route`,
/// `zenoh/src/net/routing/dispatcher/pubsub.rs` @ `fn get_hat_data_route(`).
///
/// A route is kept when the expression is a resource: `wire` (the message
/// named it by a declared id) or the node's own test. Anything else is
/// computed and not kept.
fn data_route(
    net: &LinkstateNetwork,
    subs: &LinkstatepeerInterest<()>,
    cached: Cached<'_, DataRoutes>,
    source: &Zid,
    keyexpr: &str,
    wire: bool,
) -> Arc<[Zid]> {
    let inputs = RouteInputs {
        net: net.route_version(),
        table: subs.version(),
    };
    let resource = || wire || (cached.names_a_resource)(keyexpr);
    cached
        .routes
        .get_or_compute(inputs, source, keyexpr, resource, || {
            let interested = subs.interested_remote(keyexpr, net.self_zid());
            net.directions_toward(source, &interested).into()
        })
}

/// R2909 — the CLIENT faces a node holds, each with its subscribers by decl
/// id: the leaf-face store every broker hat keeps. Versioned for the reason the
/// mesh tables are, the client leg of a data route is cached against it, and
/// indexed and change-logged so that a change retires only the routes its key
/// reaches (see [`crate::client_sub_store`]).
pub(crate) use crate::client_sub_store::ClientSubStore;

/// R2909 — the client-leg route cache of one [`ClientSubStore`]: per keyexpr,
/// the client faces subscribing to it. Keyed by `()` rather than a source,
/// because every source reaches the same leaf faces; the inbound face is
/// excluded at send time, as upstream excludes the source face when it walks
/// a route rather than when it computes one.
pub(crate) type ClientRoutes = RouteCache<Arc<[FaceId]>, ()>;

/// R2909 — the client leg of the data route for `keyexpr`: every held client
/// face with a subscriber whose keyexpr intersects it, in face order, served
/// from `routes` while the store is unchanged. Upstream computes the client
/// faces into the same route as the mesh directions
/// (`zenoh/src/net/routing/hat/router/pubsub.rs` @ `fn insert_faces_for_subs`
/// reads the resource's `session_ctxs`); wz keeps them as a second route
/// because they are sent a differently stamped carrier (source 0).
///
/// `wire` and the resource test as [`data_route`] takes them.
pub(crate) fn client_route(
    store: &ClientSubStore,
    cached: Cached<'_, ClientRoutes>,
    keyexpr: &str,
    wire: bool,
) -> Arc<[FaceId]> {
    // A store holding no client has no client leg; a router keeps one per
    // leaf region, most of them empty, and none of those is worth a route.
    if store.is_empty() {
        return Arc::from([]);
    }
    let inputs = RouteInputs {
        net: 0,
        table: store.version(),
    };
    // A change of the store retires the routes of the keys it intersects and keeps
    // the rest, instead of every route in the cache: a client that joins or leaves
    // costs the keys it subscribes, not the keys in use.
    cached.routes.refresh(
        inputs,
        |since, visit| store.changed_since(since, visit),
        |changed, cached_key| {
            let target: Vec<&str> = cached_key.split('/').collect();
            keyexpr_intersects_target(changed, &target)
        },
    );
    let resource = || wire || (cached.names_a_resource)(keyexpr);
    cached
        .routes
        .get_or_compute(inputs, &(), keyexpr, resource, || {
            store.faces_intersecting(keyexpr).into()
        })
}

/// R2911 — the CLIENT faces a node holds, each with its queryables by decl id
/// and the `QueryableInfo` each declared: the query twin of [`ClientSubStore`],
/// kept by every broker hat and [`Versioned`] for the same reason.
pub(crate) type ClientQablStore = Versioned<HashMap<FaceId, HashMap<u64, (String, QueryableInfo)>>>;

/// R2911 — one client face that can answer a query: the leaf twin of
/// [`QueryCandidate`]. A client is directly attached, so there is no hop and
/// its distance is the pin's constant 1
/// (`zenoh/src/net/routing/hat/router/queries.rs` @ `fn compute_query_route`,
/// block 3); what varies is whether it is complete for the query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientQueryable {
    /// The client face.
    pub(crate) face: FaceId,
    /// Some queryable of the face is declared complete AND its keyexpr
    /// includes the whole queried keyexpr.
    pub(crate) complete: bool,
}

/// R2911 — the client-leg query-route cache of one [`ClientQablStore`], per
/// keyexpr, keyed by `()` for the reason [`ClientRoutes`] is.
pub(crate) type ClientQueryRoutes = RouteCache<Arc<[ClientQueryable]>, ()>;

/// R2911 — the client faces able to answer a query for `keyexpr`: every held
/// client with a queryable intersecting it, in face order, served while the
/// store is unchanged. The querier's own face and the query target are
/// applied by the caller, as upstream applies both to a cached route per
/// query. `wire` and the resource test as [`data_route`] takes them.
pub(crate) fn client_query_route(
    store: &ClientQablStore,
    cached: Cached<'_, ClientQueryRoutes>,
    keyexpr: &str,
    wire: bool,
) -> Arc<[ClientQueryable]> {
    if store.is_empty() {
        return Arc::from([]);
    }
    let inputs = RouteInputs {
        net: 0,
        table: store.version(),
    };
    let resource = || wire || (cached.names_a_resource)(keyexpr);
    cached
        .routes
        .get_or_compute(inputs, &(), keyexpr, resource, || {
            let query_chunks: Vec<&str> = keyexpr.split('/').collect();
            let mut out: Vec<ClientQueryable> = store
                .iter()
                .filter(|(_, ids)| {
                    ids.values()
                        .any(|(decl, _)| keyexpr_intersects_target(decl, &query_chunks))
                })
                .map(|(face, ids)| ClientQueryable {
                    face: *face,
                    complete: ids.values().any(|(decl, info)| {
                        info.complete && keyexpr_includes_target(decl, &query_chunks)
                    }),
                })
                .collect();
            out.sort_unstable_by_key(|c| c.face);
            out.into()
        })
}

/// Compute the data-`Push` re-forward for ONE link-state mesh: given the tier's
/// `net` + subscription `subs` and a Push already resolved against the inbound
/// link's alias table (`keyexpr`), return the re-stamped carrier + the
/// interested tree children to fan it out to — or `None` to DROP. The pure route
/// CORE of [`RouterForwarder`](crate::router_forward)'s per-tier data route (each
/// of its nets), so the loop-freedom bound (the hop-limit) + the literal normalize
/// live in ONE place (R311y112).
///
/// Reads ONLY `net` + `subs` — no faces, no fan-out: the caller resolves the
/// inbound face in its own borrow and fans the returned `(carrier, children)` out
/// through its tier-appropriate seam, exactly as [`resolve_source_in`] splits the
/// net-only resolution from the face-owning caller. Drops (→ `None`) on an
/// unresolvable source, a keyexpr no remote peer subscribes to (the self-excluded
/// [`LinkstatepeerInterest::interested_remote`] view — the self-bubble is the
/// local sink, never a data forward target), an empty tree direction, an
/// exhausted hop budget (`hop <= 1`), or a carrier the literal-normalize rejects.
pub(crate) fn compute_push_forward(
    net: &LinkstateNetwork,
    subs: &LinkstatepeerInterest<()>,
    cached: Cached<'_, DataRoutes>,
    inbound_zid: Option<Zid>,
    inbound_link: Option<LinkId>,
    push: &PushOwned,
    keyexpr: &str,
) -> Option<DataForward> {
    // Resolve the source (tree root) + this node's psid for it — the same seam a
    // sourced Declare uses; both flood along the source's tree.
    let (source_zid, out_node_id) =
        resolve_source_in(net, inbound_zid, inbound_link, read_push_source(push))?;
    // R2908 — the route from this source, served from the cache while neither
    // table it reads has changed (upstream's `get_data_route`).
    let wire = wireexpr_names_a_declaration(&push.keyexpr.body);
    let children = data_route(net, subs, cached, &source_zid, keyexpr, wire);
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
/// re-forward), kept as TWO cores.
///
/// Shared by the node's own publish (`build = build_push_literal`, a FRESH local
/// sample) and [`RouterForwarder`](crate::router_forward)'s client->mesh
/// re-injection (`build = reliteralize_push`, a RECEIVED client sample whose
/// encoding/attachment/timestamp/qos MUST survive) — so the two drift-prone
/// invariants (the `node_count` loop budget + the `node_id 0` self-stamp) live in
/// ONE place, not a per-caller copy (R311y112 core-extract discipline). Reads
/// ONLY `net` + `subs` (no faces, no fan-out): the caller fans the returned
/// `(carrier, children)` through its own tier-appropriate egress seam. Drops (→
/// `Ok(None)`) on a keyexpr no remote peer subscribes to (the self-excluded
/// [`LinkstatepeerInterest::interested_remote`] view — the self-bubble is the
/// local sink, never a data forward target) or an empty tree direction; a `build`
/// codec failure propagates as `Err`.
///
/// R2901 (open-debt item 828) — unless `to_gateways`: then a keyexpr no remote
/// peer subscribes to still yields the carrier, with an empty child set,
/// because the caller owes it to its gateway faces whatever the subscription
/// table says. The router passes `false` and keeps the contract above unchanged.
pub(crate) fn compute_self_publish_forward(
    net: &LinkstateNetwork,
    subs: &LinkstatepeerInterest<()>,
    cached: Cached<'_, DataRoutes>,
    keyexpr: &str,
    wire: bool,
    to_gateways: bool,
    build: impl FnOnce() -> Result<PushOwned, CodecError>,
) -> Result<Option<DataForward>, CodecError> {
    let self_zid = *net.self_zid();
    // R2236 (open-debt item 588) found that a gossip subsystem's edgeless graph
    // gave every self-originated Push zero directions, and answered it HERE.
    // R2811 moved that answer into the graph (`LinkstateNetwork::next_hop`),
    // because the query plane asked the same graph and kept the defect: in
    // gossip mode a direct neighbour is self's own next hop, so this is now the
    // one call for both modes.
    // R2908 — self is the source here, so this is the transit route's cache
    // keyed at self's own zid.
    let children = data_route(net, subs, cached, &self_zid, keyexpr, wire);
    if children.is_empty() && !to_gateways {
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
/// the shared per-branch core a forwarder's `reap_timed_out_queries` calls
/// with its own single-target send seam, so the zenoh `QueryCleanup::run`
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
    zid_of: impl Fn(FaceId) -> Option<Zid>,
    mut send: impl FnMut(FaceId, NetworkMessage),
) {
    for eq in reaped {
        // R2906 — the timeout Err goes back through the SAME relay step as any
        // answerer's reply, as upstream's `QueryCleanup::run` hands its Err to
        // `route_send_response`: the step is what stamps the querier's rid and
        // QoS, so the Err is built at the branch's own qid and relayed.
        // R2912 — naming the face that never answered as its responder, as
        // upstream does. Upstream sends no Err at all once that face is gone
        // (`if let Some(mut face) = self.face.upgrade()`); a departed face's
        // branches are drained at its deregister, so an unnamed face here is
        // that same case and gets no Err, while a LAST branch still closes the
        // querier below rather than leaving it waiting.
        let err_msg = zid_of(eq.out_face).and_then(|zid| {
            wz_session_core::response_build::build_response_timeout_err(eq.qid, zid.as_ref())
                .and_then(|err| {
                    wz_session_core::response_build::relay_response(
                        &err, eq.to.rid, eq.to.qos, None,
                    )
                })
                .ok()
        });
        if let Some(err_msg) = err_msg {
            send(eq.to.face, NetworkMessage::Response(Box::new(err_msg)));
        }
        if !eq.last {
            continue;
        }
        let final_msg =
            wz_session_core::response_final_build::build_response_final(eq.to.rid, eq.to.qos);
        send(eq.to.face, NetworkMessage::ResponseFinal(final_msg));
    }
}

/// Synthesize the closing `ResponseFinal` for each fan a face-down DRAINED —
/// the shared core a forwarder's `deregister` calls after
/// [`PendingQueries::remove_face`](crate::linkstate_pending::PendingQueries::remove_face),
/// so the zenoh `finalize_pending_queries` semantics (face teardown drains
/// through the last-out gate, FINAL only — no Err) live ONCE. A drained fan whose
/// querier IS the `departed` face has nobody left to notify (skipped); the others
/// get the final that terminates their `get()` instead of waiting out their own
/// timeout.
pub(crate) fn synthesize_drained_fan_finals(
    drained: &[QueryReturn],
    departed: FaceId,
    mut send: impl FnMut(FaceId, NetworkMessage),
) {
    for to in drained {
        if to.face == departed {
            continue;
        }
        let final_msg = wz_session_core::response_final_build::build_response_final(to.rid, to.qos);
        send(to.face, NetworkMessage::ResponseFinal(final_msg));
    }
}

/// R2910 — one mesh queryable a query from some source can reach: the
/// neighbour on the source's tree toward it, its graph distance from THIS node
/// (`None` when unreachable by distance), and whether it is complete for the
/// queried keyexpr. The wz form of upstream's `QueryTargetQabl`
/// (`zenoh/src/net/routing/dispatcher/resource.rs` @ `pub(crate) struct QueryTargetQabl {`),
/// narrowed to what a mesh leg needs.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct QueryCandidate {
    /// The queryable's node.
    pub(crate) peer: Zid,
    /// The next hop toward it on the source's tree.
    pub(crate) hop: Zid,
    /// Its graph distance from this node.
    pub(crate) distance: Option<f64>,
    /// Declared complete AND its declaration includes the whole queried keyexpr.
    pub(crate) complete: bool,
}

/// R2910 — the query-route cache of one (graph, queryable table) pair: per
/// keyexpr and source, the [`QueryCandidate`]s, in peer order. The target is
/// applied per query to what this serves, as upstream caches a
/// `QueryTargetQablSet` and runs `compute_final_route` on it each time.
pub(crate) type QueryRoutes = RouteCache<Arc<[QueryCandidate]>>;

/// R2910 — the mesh queryables a query from `source` for `keyexpr` can reach,
/// served from `routes` while neither table changed (upstream's
/// `zenoh/src/net/routing/dispatcher/queries.rs` @ `fn get_query_route(`).
/// Self is excluded (its own queryables answer through the local path), and a
/// peer with no next hop on the source's tree is left out, as
/// `directions_toward` left it out. `wire` and the resource test as
/// [`data_route`] takes them.
pub(crate) fn query_candidates(
    net: &LinkstateNetwork,
    qabls: &LinkstatepeerInterest<QueryableInfo>,
    cached: Cached<'_, QueryRoutes>,
    source: &Zid,
    keyexpr: &str,
    wire: bool,
) -> Arc<[QueryCandidate]> {
    let inputs = RouteInputs {
        net: net.route_version(),
        table: qabls.version(),
    };
    let resource = || wire || (cached.names_a_resource)(keyexpr);
    cached
        .routes
        .get_or_compute(inputs, source, keyexpr, resource, || {
            let self_zid = net.self_zid();
            let query_chunks: Vec<&str> = keyexpr.split('/').collect();
            let mut complete: HashSet<Zid> = HashSet::new();
            for (decl, peer, info) in qabls.matching_entries(keyexpr, Some(self_zid)) {
                if info.complete && keyexpr_includes_target(decl, &query_chunks) {
                    complete.insert(peer);
                }
            }
            let mut peers = qabls.interested_remote(keyexpr, self_zid);
            peers.sort_unstable();
            peers
                .into_iter()
                .filter_map(|peer| {
                    Some(QueryCandidate {
                        peer,
                        hop: net.next_hop(source, &peer)?,
                        distance: net.distance_to(&peer),
                        complete: complete.contains(&peer),
                    })
                })
                .collect()
        })
}

/// zenoh `QueryTarget::BestMatching` (`dispatcher/queries.rs:243-266`): pick the
/// SINGLE nearest COMPLETE queryable for `keyexpr` and return `(graph distance,
/// tree direction)` — the next-hop neighbour toward it in the SOURCE's tree PLUS
/// the self-relative graph distance used to rank it — or `None` when no complete
/// queryable matches (the caller then falls back to `QueryTarget::All`).
/// "Nearest" is the GRAPH distance from THIS node to the queryable peer (zenoh's
/// `insert_target_for_qabls` reads `net.distances[qabl_idx]`, `queries.rs:1107`,
/// NOT the carried declaration distance). The inbound direction is excluded, and
/// an unreachable peer contributes nothing. A distance TIE breaks by candidate
/// order, which R2910 made the peer order of [`query_candidates`] (it was a
/// `HashMap` walk); every equal-distance complete queryable fully answers the
/// query, so only determinism rests on it.
///
/// The pin runs this once for each region's hat and merges the picks
/// (`zenoh/src/net/routing/dispatcher/queries.rs` @ `for dst in rtables.hats.regions() {`),
/// so the router calls it once for each mesh region.
pub(crate) fn select_best_matching(
    candidates: &[QueryCandidate],
    inbound_zid: Option<Zid>,
    admits: impl Fn(&Zid) -> bool,
) -> Option<(f64, Zid)> {
    candidates
        .iter()
        .filter(|c| c.complete)
        .filter_map(|c| {
            // Skip the inbound direction (no routing a Query back at its
            // source); an unreachable peer has no hop and is not a candidate.
            let hop = c.hop;
            if inbound_zid == Some(hop) {
                return None;
            }
            // R2880 (open-debt item 751, step 6) — and a direction the caller's
            // egress filter refuses, BEFORE the nearest is picked: the pin filters
            // the route and then takes its first complete queryable
            // (`zenoh/src/net/routing/dispatcher/queries.rs` @ `.resolve(tables)`),
            // so a refused nearest falls through to the next, not to nothing.
            if !admits(&hop) {
                return None;
            }
            Some((c.distance?, hop))
        })
        .min_by(|(a, _), (b, _)| a.total_cmp(b))
}

/// The distinct next hops of `candidates`, first-seen order: what
/// `directions_toward` returned for the same peers, one hop per subtree.
fn distinct_hops<'a>(candidates: impl Iterator<Item = &'a QueryCandidate>) -> Vec<Zid> {
    let mut hops: Vec<Zid> = Vec::new();
    for c in candidates {
        if !hops.contains(&c.hop) {
            hops.push(c.hop);
        }
    }
    hops
}

/// The tree directions (next-hop neighbours) toward EVERY queryable matching
/// the query — `QueryTarget::All` (`dispatcher/queries.rs:215`), and the
/// BestMatching fallback when no queryable is complete. One hop per subtree;
/// the inbound-face exclusion is the fan_out's `is_tree_forward_target`.
/// `pub(crate)` so the router composes it per-tier for its `QueryTarget::All`
/// route (C5b).
pub(crate) fn all_query_directions(candidates: &[QueryCandidate]) -> Vec<Zid> {
    distinct_hops(candidates.iter())
}

/// The tree directions toward every queryable COMPLETE for the query —
/// `QueryTarget::AllComplete` (`dispatcher/queries.rs:228`): declared complete
/// AND its declaration includes the whole queried keyexpr (zenoh's `complete
/// && qabl_info.complete`, `zenoh/src/net/routing/hat/peer/queries.rs`
/// @ `fn compute_query_route`), FANNED OUT rather than narrowed to the nearest
/// as BestMatching does. `pub(crate)` so the router composes it per-tier for
/// its `QueryTarget::AllComplete` route (C5b).
pub(crate) fn complete_query_directions(candidates: &[QueryCandidate]) -> Vec<Zid> {
    distinct_hops(candidates.iter().filter(|c| c.complete))
}

/// Re-advertise the interest in `table` to the NEW tree children a recompute
/// added, for ONE mesh — the tree-change re-flood CORE of
/// [`RouterForwarder`](crate::router_forward)'s per-tier tick (each of its
/// nets). BOTH the net and the flood are parameters, so the router stamps
/// `out_node_id` in the CORRECT tier's psid space (routers_net for
/// `router_subs`, linkstatepeers_net for `linkstatepeer_subs`) rather than
/// injecting a wrong-net psid, and floods via its tier-scoped fan-out (R311y112).
/// `build` mints the per-entry carrier from the literal keyexpr + value (`V = ()`
/// subs / `QueryableInfo` qabls); `flood(children, declare)` sends it to the delta
/// children. Outer over the new-children delta, inner over the declarations
/// sourced at that tree (`*src == tree_id`), each re-stamped for the source
/// (`local_psid_of(self) == 0` leaves a self-sourced declaration self-originated).
pub(crate) fn re_advertise_interest_into<V: Clone>(
    psid_of: impl Fn(&Zid) -> Option<u16>,
    pairs: Vec<(String, Zid, V)>,
    new_children: &[(Zid, Vec<Zid>)],
    build: impl Fn(&str, &V) -> Result<DeclareOwned, CodecError>,
    mut flood: impl FnMut(&[Zid], &DeclareOwned),
) {
    if new_children.is_empty() {
        return;
    }
    // `pairs` is the snapshot of the (keyexpr, source, value) entries and `psid_of` this node's
    // psid for a source: both are read by the caller, so that neither the table nor the graph is
    // held while `flood` runs.
    for (source_zid, delta_children) in new_children {
        // this node's psid for the source (the re-stamp value).
        let Some(out_node_id) = psid_of(source_zid) else {
            continue;
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
/// into `table` — the SSOT shared by every forwarder's `absorb_keyexpr_declaration`
/// (R311y111). The declared base may reference an earlier alias on the same link,
/// so it is resolved against `table` before recording; an unknown-alias declare
/// is dropped. Link-local: each link negotiates its own aliases (not re-flooded).
/// Only the two keyexpr-declaration bodies reach here; a defensive no-op otherwise.
// R311y196 — the keyexpr-absorb SSOT moved to `wz-session-core` so the no_std
// multicast per-peer ingress plane (§5.21 router-multicast-faces I3a) and the
// unicast router faces share ONE definition. Re-exported here so every existing
// `absorb_keyexpr_into(..)` call site is unchanged.
pub(crate) use wz_session_core::wireexpr_resolve::absorb_keyexpr_into;

/// Whether `zid` is one of `children` — the tree next hops a fan-out targets.
/// The membership check [`is_tree_forward_target`] builds on.
fn is_child(children: &[Zid], zid: Zid) -> bool {
    children.contains(&zid)
}

/// Build a literal sourced `DeclareQueryable` CARRYING the `QueryableInfo` — the
/// SSOT carrier mint shared by BOTH queryable re-flood paths (the inbound
/// re-flood and the tree-change re-flood), so a queryable's completeness
/// propagates DOWNSTREAM identically on either path — what makes MULTI-HOP
/// BestMatching work (a relay N hops from the queryable learns its completeness,
/// then routes by the GRAPH distance to it). zenoh `propagate_sourced_queryable`
/// re-floods the registered `QueryableInfo` VERBATIM — NO per-hop distance
/// increment (BestMatching reads `net.distances`, not the carried distance).
/// DEFAULT / incomplete omits the ext (byte-identical to the prior clean re-flood).
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
/// tree-re-forward path (data, control and the query route) — only the carrier
/// each wraps differs, so the loop-exclusion mechanics live here once.
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
