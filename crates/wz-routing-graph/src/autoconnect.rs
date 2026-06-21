// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The zenoh gossip **autoconnect** policy — when a peer that has just
//! DISCOVERED another node (learned its zid + locators off a gossip flood)
//! should dial it. The wz mirror of zenoh `net/common.rs` `AutoConnect`.
//!
//! Two gates, both consulted by [`AutoConnect::should_autoconnect`]:
//!
//! - a role [`WhatAmIMatcher`] — only a discovered node whose handshake role is
//!   in the set is a dial candidate (zenoh's per-local-whatami
//!   `scouting.gossip.autoconnect`: a peer defaults to `router|peer`, a router /
//!   client to the empty set);
//! - an [`AutoConnectStrategy`] zid tie-break — `GreaterZid` makes only the
//!   greater-zid end dial, so two peers that discover each other do not BOTH
//!   open a redundant connection (the double-dial the discovery seam must
//!   avoid).
//!
//! WHERE IT LIVES. zenoh defines `AutoConnect` in `net/common.rs` (a leaf
//! shared module, sibling to the `network.rs` topology graph) and only the
//! gossip HAT (`hat/p2p_peer/gossip.rs`) HOLDS an instance as a field. wz keeps
//! the same split: the type lives here, in the routing-graph crate — the lowest
//! crate that has both [`Zid`](crate::Zid) (for the zid tie-break) and
//! [`WhatAmIMatcher`] (for the role gate) — and the runtime driver
//! (`linkstate_forward`, the gossip-HAT analog) will hold an `AutoConnect`
//! field that feeds its dial decision. This atom is the policy VOCABULARY; the
//! discovery→dial wiring that calls [`should_autoconnect`](AutoConnect::should_autoconnect)
//! is a later atom.
//!
//! SIMPLIFICATION vs zenoh. zenoh sources the matcher and strategy from the
//! scouting config, layered as `ModeDependent<TargetDependentValue<..>>` (per
//! LOCAL whatami, then per TARGET whatami). wz has no config layer, so it stores
//! one [`WhatAmIMatcher`] and one [`AutoConnectStrategy`] directly — the same
//! deliberate flattening [`WhatAmIMatcher`] makes against zenoh's `NonZeroU8`
//! niche and the driver's `gossip_target` const makes against `ModeDependent`.
//! `should_autoconnect` keeps the identical semantics for the single-strategy
//! case (which is every default deploy: zenoh's per-target strategy default is
//! `Unique(Always)`).

use wz_codecs::whatami::{WhatAmI, WhatAmIMatcher};

use crate::Zid;

/// How a discovering node decides whether to be the side that dials, when both
/// ends may have discovered each other. zenoh `AutoConnectStrategy`
/// (`zenoh-config`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AutoConnectStrategy {
    /// Always dial a matcher-admitted discovered node. Both ends may dial,
    /// producing a redundant connection the transport layer then closes — the
    /// simplest policy, and zenoh's default.
    #[default]
    Always,
    /// Dial only when self's zid is GREATER than the target's. If both ends use
    /// this strategy, exactly one dials — the double-dial avoidance. zenoh
    /// documents its one hazard: if the greater-zid node cannot reach the lesser
    /// (e.g. a private IP), no connection forms, because the lesser-zid end —
    /// the only one that could reach across — declines to dial.
    GreaterZid,
}

/// The autoconnect gate a gossip-discovering peer consults before dialing a
/// node it just learned about: a role [`WhatAmIMatcher`] AND an
/// [`AutoConnectStrategy`] zid tie-break, carrying the local zid the tie-break
/// compares against. Mirrors zenoh `net/common.rs` `AutoConnect`.
///
/// `Copy`, like zenoh's — a cheap policy value the driver clones into each dial
/// decision, not shared state.
#[derive(Debug, Clone, Copy)]
pub struct AutoConnect {
    /// This node's own zid — the left operand of the [`AutoConnectStrategy::GreaterZid`]
    /// comparison.
    zid: Zid,
    matcher: WhatAmIMatcher,
    strategy: AutoConnectStrategy,
}

impl AutoConnect {
    /// An autoconnect policy for a node with `zid`, admitting the target roles
    /// in `matcher` under `strategy`. zenoh sources `matcher` / `strategy` from
    /// the scouting config per local whatami; wz passes them directly (no config
    /// layer) — the flattening this module documents.
    pub fn new(zid: Zid, matcher: WhatAmIMatcher, strategy: AutoConnectStrategy) -> Self {
        Self {
            zid,
            matcher,
            strategy,
        }
    }

    /// A disabled policy for a node with `zid`: an empty matcher, so
    /// [`is_enabled`](Self::is_enabled) is false and
    /// [`should_autoconnect`](Self::should_autoconnect) never fires. zenoh
    /// `AutoConnect::disabled` (which uses a default zid, irrelevant under an
    /// empty matcher); wz threads self's real zid so the value is honest even
    /// while disabled. The signature-stable default for a deploy that does not
    /// gossip-autoconnect — the current behaviour, before any dial wiring.
    pub fn disabled(zid: Zid) -> Self {
        Self {
            zid,
            matcher: WhatAmIMatcher::empty(),
            strategy: AutoConnectStrategy::default(),
        }
    }

    /// The role set this policy admits as dial candidates. zenoh
    /// `AutoConnect::matcher`.
    pub fn matcher(&self) -> WhatAmIMatcher {
        self.matcher
    }

    /// Whether autoconnect is enabled at all — a non-empty matcher. zenoh
    /// `AutoConnect::is_enabled`. A disabled policy is `false`; the discovery
    /// seam can skip the dial path entirely for it.
    pub fn is_enabled(&self) -> bool {
        !self.matcher.is_empty()
    }

    /// Whether self should dial the discovered node `to` of role `what`: its
    /// role is admitted by the matcher AND the strategy tie-break passes. zenoh
    /// `AutoConnect::should_autoconnect` (`net/common.rs:65`). The `GreaterZid`
    /// arm — `self.zid > to` — is the double-dial avoidance: of a mutually
    /// discovering pair, only the greater-zid end dials.
    pub fn should_autoconnect(&self, to: Zid, what: WhatAmI) -> bool {
        self.matcher.matches(what)
            && match self.strategy {
                AutoConnectStrategy::Always => true,
                AutoConnectStrategy::GreaterZid => self.zid > to,
            }
    }
}

#[cfg(test)]
mod tests {
    use super::{AutoConnect, AutoConnectStrategy};
    use crate::Zid;
    use wz_codecs::whatami::{WhatAmI, WhatAmIMatcher};

    /// A canonical single-byte zid — enough to exercise the derived `Ord` the
    /// `GreaterZid` tie-break leans on (`zid(0x02) > zid(0x01)`).
    fn zid(b: u8) -> Zid {
        Zid::from_slice(&[b])
    }

    /// The zenoh peer default: gossip-autoconnect to routers and peers, never to
    /// clients.
    fn router_or_peer() -> WhatAmIMatcher {
        WhatAmIMatcher::empty().router().peer()
    }

    #[test]
    fn disabled_never_enables_or_autoconnects() {
        let ac = AutoConnect::disabled(zid(0x05));
        assert!(!ac.is_enabled());
        assert!(ac.matcher().is_empty());
        // No role, neither greater nor lesser, is ever a dial candidate.
        for to in [zid(0x01), zid(0x05), zid(0x09)] {
            for what in [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client] {
                assert!(!ac.should_autoconnect(to, what));
            }
        }
    }

    #[test]
    fn always_strategy_dials_any_admitted_role_regardless_of_zid() {
        let ac = AutoConnect::new(zid(0x05), router_or_peer(), AutoConnectStrategy::Always);
        assert!(ac.is_enabled());
        // Admitted roles dial whether the target's zid is lesser, equal, or
        // greater than self's — Always ignores the zid entirely.
        for to in [zid(0x01), zid(0x05), zid(0x09)] {
            assert!(ac.should_autoconnect(to, WhatAmI::Router));
            assert!(ac.should_autoconnect(to, WhatAmI::Peer));
        }
    }

    #[test]
    fn matcher_gate_excludes_unadmitted_roles_under_either_strategy() {
        // A client is outside the peer default matcher: never a dial candidate,
        // even under Always and even with the most favourable (lesser) zid.
        for strategy in [AutoConnectStrategy::Always, AutoConnectStrategy::GreaterZid] {
            let ac = AutoConnect::new(zid(0xff), router_or_peer(), strategy);
            assert!(!ac.should_autoconnect(zid(0x01), WhatAmI::Client));
        }
    }

    #[test]
    fn greater_zid_strategy_dials_only_the_strictly_greater_end() {
        let me = zid(0x05);
        let ac = AutoConnect::new(me, router_or_peer(), AutoConnectStrategy::GreaterZid);
        // Strictly greater self zid -> dial; lesser or equal -> do not.
        assert!(ac.should_autoconnect(zid(0x01), WhatAmI::Peer));
        assert!(!ac.should_autoconnect(zid(0x09), WhatAmI::Peer));
        assert!(
            !ac.should_autoconnect(me, WhatAmI::Peer),
            "equal zid must not dial — `>` is strict"
        );
    }

    #[test]
    fn greater_zid_pair_has_exactly_one_dialer() {
        // Two peers that discover each other, both on GreaterZid: exactly one
        // dials — the double-dial avoidance. Roles admit each other (peer<->peer).
        let (lo, hi) = (zid(0x03), zid(0x07));
        let low = AutoConnect::new(lo, router_or_peer(), AutoConnectStrategy::GreaterZid);
        let high = AutoConnect::new(hi, router_or_peer(), AutoConnectStrategy::GreaterZid);
        assert!(
            high.should_autoconnect(lo, WhatAmI::Peer),
            "greater-zid end dials"
        );
        assert!(
            !low.should_autoconnect(hi, WhatAmI::Peer),
            "lesser-zid end declines"
        );
        // Exactly one of the two sides dials.
        assert_ne!(
            high.should_autoconnect(lo, WhatAmI::Peer),
            low.should_autoconnect(hi, WhatAmI::Peer)
        );
    }
}
