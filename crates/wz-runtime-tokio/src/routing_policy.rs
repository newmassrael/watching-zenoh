// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The types a deploy states its routing policy and configuration in: the node's identity and
//! role (`Zid`, `WhatAmI`), the autoconnect policy with its role matcher, per-target strategies
//! and per-role default, the configured link weights, and the interceptor configuration with the
//! rule, flow and subject types it is built from.
//!
//! Each type is defined by the crate that owns it (`wz-routing-graph`, `wz-codecs`,
//! `wz-access-control`, `wz-session-core`, this crate's `interceptor`) and re-exported here, so a
//! deploy builds its whole policy from one path, `wz::runtime_tokio::routing_policy`, and never
//! re-types a matcher or a row shape at the call site.
//!
//! Public and kept apart from the route cores the forwarder computes with (`linkstate_routes`,
//! crate-private). The two shared one module, named for the single-net peer forwarder it held
//! until open-debt item 751 step 7 (`docs/peer-region-hats.md`); that forwarder no longer exists,
//! and one module held two concerns under a name that said neither: a surface a deploy names, and
//! cores the crate keeps to itself. Each now has a module named for what it holds, with the
//! visibility its users need.
//!
//! Gated on `routing-router-hat`, the forwarder a deploy hands this policy to.

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
// pulled by `routing-peer`, which `routing-router-hat` pulls, so these types exist
// wherever this module does.
// A deploy that weights its router links names them on one path
// (`wz::runtime_tokio::routing_policy::{TransportWeight, link_weights_from_config}`)
// rather than re-typing the row shape at the call site. `zenoh_config`
// re-exports the same three for the CONFIG-FILE half, which needs its own
// feature; a build with the router hat and no config reader reaches them here.
pub use wz_routing_graph::{link_weights_from_config, DuplicateLinkWeight, TransportWeight};
// R311tt — re-export the §5.16 access-control policy-construction surface
// beside `set_interceptors`, so a deploy builds an `AclPolicy` from one facade
// path (`wz::runtime_tokio::routing_policy::{AclPolicy, ..}`) — the same
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The per-role autoconnect default: a peer dials the routers and peers it discovers, a
    /// router and a client dial nobody they discover. Turned red by a role arm of
    /// `default_autoconnect_matcher` that answers another matcher, as a router given
    /// `router|peer` would dial every peer it hears of.
    #[test]
    fn the_autoconnect_default_dials_discovered_nodes_only_from_a_peer() {
        assert_eq!(
            default_autoconnect_matcher(WhatAmI::Peer),
            WhatAmIMatcher::empty().router().peer()
        );
        assert_eq!(
            default_autoconnect_matcher(WhatAmI::Router),
            WhatAmIMatcher::empty()
        );
        assert_eq!(
            default_autoconnect_matcher(WhatAmI::Client),
            WhatAmIMatcher::empty()
        );
    }
}
