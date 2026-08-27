// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! shared module, sibling to the `network.rs` topology graph); the instance is a
//! field of the gossip-side topology graph `Network` itself
//! (`hat/p2p_peer/gossip.rs:101`), which is also where the gate + dial fire
//! (`should_autoconnect` then `connect_peer`, inside the graph's ingest). wz
//! keeps the type here, in the routing-graph crate — the lowest crate that has
//! both [`Zid`](crate::Zid) (for the zid tie-break) and [`WhatAmIMatcher`] (for
//! the role gate) — while the runtime driver (`linkstate_forward`) holds the
//! `AutoConnect` field and applies the gate at emit. wz splits the gate
//! (forwarder, sync) from the dial (accept-loop, async) over a channel because
//! its sync ingest cannot open an outbound link; zenoh keeps both in the graph
//! ingest.
//!
//! # R2141 — the flattening this module used to document is GONE
//!
//! Until this round the doc here said wz "has no config layer, so it stores one
//! [`WhatAmIMatcher`] and one [`AutoConnectStrategy`] directly", called that a
//! deliberate simplification, and justified it by noting the semantics stay
//! "identical for the single-strategy case (which is every default deploy)".
//! Both halves were true when written, and the second is what made the first
//! safe: zenoh's per-target strategy default IS `Unique(Always)`.
//!
//! wz now HAS a config layer for these keys — `scouting/multicast/autoconnect`
//! and `scouting/multicast/autoconnect_strategy`, read by `wz-runtime-tokio`'s
//! `zenoh_config` — and the moment a document can spell
//! `autoconnect_strategy: { to_router: "always", to_peer: "greater-zid" }` the
//! default stops being the only case. Upstream types that value
//! `ModeDependentValue<TargetDependentValue<AutoConnectStrategy>>`
//! (`commons/zenoh-config/src/mode_dependent.rs`), and its two layers resolve at
//! DIFFERENT times — which is why exactly one of them can be flattened away:
//!
//! * MODE dependence resolves at CONSTRUCTION — `.get(self_whatami)` in zenoh's
//!   `AutoConnect::multicast` / `::gossip` (`net/common.rs`), against the LOCAL
//!   node's role, which is fixed for the process. [`AutoConnect::new`] takes the
//!   already-resolved matcher and strategy, so that layer stays outside this
//!   type exactly as it always did.
//! * TARGET dependence resolves at USE — `self.strategy.get(what)` inside
//!   `should_autoconnect`, against the DISCOVERED node's role, which differs per
//!   Hello. That layer has to survive INSIDE the policy value, and
//!   [`AutoConnectStrategies`] is it.
//!
//! [`AutoConnect::new`] keeps its signature and wraps the single strategy in
//! [`AutoConnectStrategies::Unique`], so every pre-R2141 caller behaves
//! identically; [`AutoConnect::with_strategies`] is the target-dependent
//! constructor the config reader uses.

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

impl AutoConnectStrategy {
    /// Every variant, so a sweep over the spellings cannot miss one the enum
    /// grew. Declaration order, default first.
    pub const ALL: &'static [Self] = &[Self::Always, Self::GreaterZid];

    /// The spelling a zenoh config file and this workspace's flags both use —
    /// upstream's `#[serde(rename_all = "kebab-case")]` on `AutoConnectStrategy`
    /// (`commons/zenoh-config/src/lib.rs`), hence `greater-zid` and not
    /// `greater_zid`.
    ///
    /// R2141 — this exists so the spelling has ONE home. Before this round both
    /// directions were written out by hand at call sites that cannot see each
    /// other (`wz-ap-demo`'s `--autoconnect-strategy` parse and its usage text),
    /// and the config reader was about to become a third. `zenoh_config` already
    /// matches the `mode:` key against `WhatAmI::to_str` "so the two directions
    /// cannot disagree about a spelling"; this is that idiom, for this enum.
    pub const fn to_config_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::GreaterZid => "greater-zid",
        }
    }

    /// The inverse of [`to_config_str`](Self::to_config_str), matched against it
    /// rather than against a second literal table. `None` for anything outside
    /// the set: a value the operator mistyped is not a strategy, and defaulting
    /// it would silently run a tie-break nobody asked for.
    pub fn from_config_str(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|s| s.to_config_str() == name)
    }
}

/// The tie-break a policy applies, per TARGET role — the wz mirror of zenoh's
/// `TargetDependentValue<AutoConnectStrategy>`
/// (`commons/zenoh-config/src/mode_dependent.rs`), which is what
/// `scouting/{multicast,gossip}/autoconnect_strategy` resolves to once the
/// node's own mode has selected its row.
///
/// [`Unique`](Self::Unique) is one strategy for every target and is what a
/// default deploy carries (upstream's `defaults.rs` resolves both
/// `autoconnect_strategy` keys to `Unique(Always)`).
/// [`PerTarget`](Self::PerTarget) is the table spelling
/// `{ to_router: "always", to_peer: "greater-zid" }` — the shape wz could not
/// represent at all before R2141, which is the finding that turned item 223 from
/// a wiring round into a design one.
///
/// WHICH KEYS THIS ANSWERS. Upstream spells this table twice — once per
/// discovery plane — as `scouting.multicast.autoconnect_strategy` and
/// `scouting.gossip.autoconnect_strategy`. wz's config reader honours the
/// multicast one and does not yet read the gossip one, so the gossip key is
/// carried in `UNHONOURED_READER_GAP` rather than among the keys wz cannot act
/// on: the capability is HERE, and what is missing is the reader. R2150 added
/// this sentence because that classification was asserted only in the reader's
/// own doc, which made it a claim with no witness at the capability.
///
/// A target with no entry falls back to [`AutoConnectStrategy::default`], NOT to
/// "do not dial": upstream reads it as
/// `self.strategy.get(what).copied().unwrap_or_default()`, so an unnamed target
/// gets `Always`. The role matcher is what decides whether a target is a
/// candidate at all; this only decides the tie-break once it already is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AutoConnectStrategies {
    /// One strategy for every admitted target — zenoh
    /// `TargetDependentValue::Unique`.
    Unique(AutoConnectStrategy),
    /// A strategy per target role, each optional — zenoh
    /// `TargetDependentValue::Dependent(TargetValues { .. })`, whose three
    /// fields are `to_router` / `to_peer` / `to_client`. The `to_` prefix is
    /// upstream's `serde_with::with_prefix!`, and it is what keeps this table
    /// unambiguous against the `{ router, peer, client }` MODE table one level
    /// up.
    PerTarget {
        /// The tie-break for a discovered ROUTER.
        to_router: Option<AutoConnectStrategy>,
        /// The tie-break for a discovered PEER.
        to_peer: Option<AutoConnectStrategy>,
        /// The tie-break for a discovered CLIENT.
        to_client: Option<AutoConnectStrategy>,
    },
}

impl Default for AutoConnectStrategies {
    /// `Unique(Always)` — the value upstream's own defaults resolve to.
    fn default() -> Self {
        Self::Unique(AutoConnectStrategy::default())
    }
}

impl AutoConnectStrategies {
    /// An empty per-target table: every target falls back to the default. The
    /// starting point a config reader fills in field by field.
    pub const fn per_target() -> Self {
        Self::PerTarget {
            to_router: None,
            to_peer: None,
            to_client: None,
        }
    }

    /// The strategy for a discovered node of role `target`. zenoh
    /// `TargetDependentValue::get(whatami)` followed by the
    /// `.copied().unwrap_or_default()` its `should_autoconnect` call site
    /// applies; the fallback is folded in here so no caller can forget it.
    pub fn get(self, target: WhatAmI) -> AutoConnectStrategy {
        match self {
            Self::Unique(s) => s,
            Self::PerTarget {
                to_router,
                to_peer,
                to_client,
            } => match target {
                WhatAmI::Router => to_router,
                WhatAmI::Peer => to_peer,
                WhatAmI::Client => to_client,
            }
            .unwrap_or_default(),
        }
    }

    /// Whether this value names a different strategy for different targets — the
    /// shape a single [`AutoConnectStrategy`] could NOT have carried.
    ///
    /// DERIVED from [`get`](Self::get) rather than from the variant, because a
    /// `PerTarget` whose entries all agree (or are all absent) is not
    /// target-dependent in EFFECT, and reporting it as such would overstate what
    /// the operator's file asked for.
    pub fn is_target_dependent(self) -> bool {
        let first = self.get(WhatAmI::Router);
        [WhatAmI::Peer, WhatAmI::Client]
            .into_iter()
            .any(|w| self.get(w) != first)
    }

    /// The flag / report spelling: a bare `always`, or a
    /// `to_router=always,to_peer=greater-zid` list naming only the targets the
    /// table actually sets.
    ///
    /// An EMPTY `PerTarget` renders as its effective single value rather than as
    /// an empty string, because an empty string is not a value
    /// [`from_config_str`](Self::from_config_str) parses back — and the round
    /// trip is what the flag path depends on.
    pub fn to_config_str(self) -> String {
        match self {
            Self::Unique(s) => String::from(s.to_config_str()),
            Self::PerTarget {
                to_router,
                to_peer,
                to_client,
            } => {
                let parts: Vec<String> = [
                    (WhatAmI::Router, to_router),
                    (WhatAmI::Peer, to_peer),
                    (WhatAmI::Client, to_client),
                ]
                .into_iter()
                .filter_map(|(target, set)| {
                    set.map(|s| format!("to_{}={}", target.to_str(), s.to_config_str()))
                })
                .collect();
                if parts.is_empty() {
                    return String::from(AutoConnectStrategy::default().to_config_str());
                }
                parts.join(",")
            }
        }
    }

    /// Parse the spelling [`to_config_str`](Self::to_config_str) renders.
    ///
    /// A bare strategy name is [`Unique`](Self::Unique); a comma-separated list
    /// of `to_<role>=<strategy>` is [`PerTarget`](Self::PerTarget). The two are
    /// told apart by the `=`, which is the same KIND of discriminator upstream
    /// uses one level up, where a map's field NAMES tell a mode table from a
    /// target table (`mode_dependent.rs`).
    ///
    /// Every failure is NAMED. A strategy this enum does not have, a target that
    /// is not one of the three roles, an entry with no `=`, and a target named
    /// twice are each their own error: an operator whose file was refused has to
    /// be able to tell WHICH word was wrong, and a parser answering "invalid"
    /// would send them back to the whole line.
    pub fn from_config_str(spec: &str) -> Result<Self, AutoConnectStrategiesError> {
        if !spec.contains('=') {
            return AutoConnectStrategy::from_config_str(spec)
                .map(Self::Unique)
                .ok_or(AutoConnectStrategiesError::UnknownStrategy);
        }
        let mut to_router = None;
        let mut to_peer = None;
        let mut to_client = None;
        for entry in spec.split(',') {
            let Some((target, name)) = entry.split_once('=') else {
                return Err(AutoConnectStrategiesError::NotAnEntry);
            };
            let Some(role) = target.strip_prefix("to_") else {
                return Err(AutoConnectStrategiesError::UnknownTarget);
            };
            let Some(role) = [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client]
                .into_iter()
                .find(|w| w.to_str() == role)
            else {
                return Err(AutoConnectStrategiesError::UnknownTarget);
            };
            let strategy = AutoConnectStrategy::from_config_str(name)
                .ok_or(AutoConnectStrategiesError::UnknownStrategy)?;
            let slot = match role {
                WhatAmI::Router => &mut to_router,
                WhatAmI::Peer => &mut to_peer,
                WhatAmI::Client => &mut to_client,
            };
            if slot.is_some() {
                return Err(AutoConnectStrategiesError::RepeatedTarget);
            }
            *slot = Some(strategy);
        }
        Ok(Self::PerTarget {
            to_router,
            to_peer,
            to_client,
        })
    }
}

/// Why a `to_<role>=<strategy>` spec was refused. Each arm is a DIFFERENT word
/// in the operator's line, so the caller can say which one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoConnectStrategiesError {
    /// A comma-separated entry with no `=` in it.
    NotAnEntry,
    /// The left side is not `to_router` / `to_peer` / `to_client`.
    UnknownTarget,
    /// The right side is not a strategy this enum has.
    UnknownStrategy,
    /// The same target appears twice, so one of the two values would be lost.
    RepeatedTarget,
}

impl core::fmt::Display for AutoConnectStrategiesError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotAnEntry => "expects `to_<role>=<strategy>` entries separated by commas",
            Self::UnknownTarget => {
                "names a target that is not `to_router`, `to_peer` or `to_client`"
            }
            Self::UnknownStrategy => "names a strategy that is not `always` or `greater-zid`",
            Self::RepeatedTarget => "names the same target twice",
        })
    }
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
    /// R2141 — the TARGET-dependent tie-break, so one policy can carry
    /// `{ to_router: "always", to_peer: "greater-zid" }`. Was a single
    /// [`AutoConnectStrategy`]; the module doc says why the flattening had to go.
    strategy: AutoConnectStrategies,
}

impl AutoConnect {
    /// An autoconnect policy for a node with `zid`, admitting the target roles
    /// in `matcher` under ONE `strategy` for every target — zenoh's
    /// `TargetDependentValue::Unique` arm, and what a default deploy carries.
    ///
    /// The mode layer stays outside: zenoh resolves `matcher` / `strategy` from
    /// the scouting config per LOCAL whatami before building the policy, and so
    /// does wz's config reader. [`with_strategies`](Self::with_strategies) is the
    /// constructor for the per-TARGET table, which cannot be resolved early
    /// because its selector is the discovered node's role.
    pub fn new(zid: Zid, matcher: WhatAmIMatcher, strategy: AutoConnectStrategy) -> Self {
        Self::with_strategies(zid, matcher, AutoConnectStrategies::Unique(strategy))
    }

    /// R2141 — the TARGET-DEPENDENT constructor: a tie-break per discovered
    /// role, which is what `scouting/{multicast,gossip}/autoconnect_strategy` can
    /// spell and what [`new`](Self::new) cannot express.
    ///
    /// [`new`](Self::new) is kept rather than replaced, and not only for source
    /// compatibility: a deploy that means one tie-break for everything should not
    /// have to write a table, and upstream's own `Unique` arm exists for exactly
    /// that.
    pub fn with_strategies(
        zid: Zid,
        matcher: WhatAmIMatcher,
        strategy: AutoConnectStrategies,
    ) -> Self {
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
            strategy: AutoConnectStrategies::default(),
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
    /// R2141 — the tie-break is SELECTED by the target's role before it is
    /// applied (`self.strategy.get(what)`, upstream's
    /// `TargetDependentValue::get`). Before this round there was one strategy and
    /// nothing to select, which is exactly the config shape wz could not honour.
    pub fn should_autoconnect(&self, to: Zid, what: WhatAmI) -> bool {
        self.matcher.matches(what)
            && match self.strategy.get(what) {
                AutoConnectStrategy::Always => true,
                AutoConnectStrategy::GreaterZid => self.zid > to,
            }
    }

    /// The per-target tie-break table this policy applies. zenoh has no accessor
    /// for it (its field is private and read only by `should_autoconnect`); wz
    /// exposes it so a deploy can REPORT the policy a config resolved into,
    /// which is the R311y845 discipline — a banner naming what was actually
    /// installed rather than what the default is.
    pub fn strategies(&self) -> AutoConnectStrategies {
        self.strategy
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AutoConnect, AutoConnectStrategies, AutoConnectStrategiesError, AutoConnectStrategy,
    };
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

    // ── R2141 — the target-dependent tie-break (open-debt item 223) ──

    /// ONE policy applies DIFFERENT tie-breaks to a discovered router and a
    /// discovered peer.
    ///
    /// THE ROUND'S CENTRAL CLAIM. Item 223 asserts honouring
    /// `scouting/multicast/autoconnect_strategy` is "a wiring round, not a
    /// design one, because wz already has `AutoConnect`". The value that key
    /// takes is `TargetDependentValue<AutoConnectStrategy>`, whose selector is
    /// the DISCOVERED node's role — so `{ to_router: "always", to_peer:
    /// "greater-zid" }` needs the table to survive inside the policy. It could
    /// not: the field was one [`AutoConnectStrategy`], and this test was
    /// UNWRITEABLE before the type changed.
    ///
    /// The fixture is the one that discriminates. Self's zid is the LESSER, so
    /// `GreaterZid` must decline; both targets are admitted by the same matcher,
    /// so the matcher cannot be what separates them; and the two verdicts differ
    /// only because the STRATEGY differs per target. A policy that ignored the
    /// table and used any single strategy answers both alike and fails here.
    #[test]
    fn one_policy_applies_a_different_tie_break_to_each_target_role() {
        let me = zid(0x03);
        let greater = zid(0x09);
        let ac = AutoConnect::with_strategies(
            me,
            router_or_peer(),
            AutoConnectStrategies::PerTarget {
                to_router: Some(AutoConnectStrategy::Always),
                to_peer: Some(AutoConnectStrategy::GreaterZid),
                to_client: None,
            },
        );
        assert!(
            ac.should_autoconnect(greater, WhatAmI::Router),
            "`to_router: always` dials a greater-zid ROUTER"
        );
        assert!(
            !ac.should_autoconnect(greater, WhatAmI::Peer),
            "`to_peer: greater-zid` declines the same greater-zid PEER, from the \
             same policy and the same matcher — the verdict that no single \
             strategy can produce"
        );
        assert!(
            ac.strategies().is_target_dependent(),
            "the policy must REPORT itself as target-dependent, so a deploy \
             banner can say so"
        );
    }

    /// A target the table leaves unnamed falls back to the DEFAULT strategy, not
    /// to "do not dial" — upstream's `.copied().unwrap_or_default()`.
    ///
    /// The direction matters: reading an absent entry as a refusal would make a
    /// file that names only `to_peer` silently stop dialling routers, which is a
    /// topology change the operator never wrote.
    #[test]
    fn an_unnamed_target_falls_back_to_the_default_strategy_not_to_a_refusal() {
        let table = AutoConnectStrategies::PerTarget {
            to_router: None,
            to_peer: Some(AutoConnectStrategy::GreaterZid),
            to_client: None,
        };
        assert_eq!(table.get(WhatAmI::Router), AutoConnectStrategy::default());
        assert_eq!(table.get(WhatAmI::Client), AutoConnectStrategy::default());
        assert_eq!(table.get(WhatAmI::Peer), AutoConnectStrategy::GreaterZid);

        // And the fallback is a DIAL, because the default is `Always`: self's zid
        // is the lesser here, so a `GreaterZid` fallback would refuse.
        let ac = AutoConnect::with_strategies(zid(0x03), router_or_peer(), table);
        assert!(ac.should_autoconnect(zid(0x09), WhatAmI::Router));
        assert!(!ac.should_autoconnect(zid(0x09), WhatAmI::Peer));

        // An EMPTY table is every target at the default, and is NOT reported as
        // target-dependent: nothing about it differs per target.
        let empty = AutoConnectStrategies::per_target();
        for w in [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client] {
            assert_eq!(empty.get(w), AutoConnectStrategy::default());
        }
        assert!(!empty.is_target_dependent());
        // Nor is a table whose entries AGREE — `is_target_dependent` is derived
        // from the verdicts, not from the variant.
        assert!(!AutoConnectStrategies::PerTarget {
            to_router: Some(AutoConnectStrategy::GreaterZid),
            to_peer: Some(AutoConnectStrategy::GreaterZid),
            to_client: Some(AutoConnectStrategy::GreaterZid),
        }
        .is_target_dependent());
    }

    /// `new` is exactly `with_strategies(Unique(..))` — every pre-R2141 caller
    /// keeps its behaviour.
    ///
    /// Swept over BOTH strategies and every (target role, relative zid) pair
    /// rather than spot-checked, because "the old constructor still means what
    /// it meant" is the compatibility claim the whole change rests on.
    #[test]
    fn the_single_strategy_constructor_is_the_unique_arm_for_every_target() {
        for strategy in AutoConnectStrategy::ALL.iter().copied() {
            let flat = AutoConnect::new(zid(0x05), router_or_peer(), strategy);
            let wrapped = AutoConnect::with_strategies(
                zid(0x05),
                router_or_peer(),
                AutoConnectStrategies::Unique(strategy),
            );
            assert_eq!(flat.strategies(), AutoConnectStrategies::Unique(strategy));
            assert!(!flat.strategies().is_target_dependent());
            for to in [zid(0x01), zid(0x05), zid(0x09)] {
                for what in [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client] {
                    assert_eq!(
                        flat.should_autoconnect(to, what),
                        wrapped.should_autoconnect(to, what),
                        "{strategy:?} {what:?}"
                    );
                }
            }
        }
    }

    /// The flag spelling round-trips, and the population is DERIVED from
    /// `AutoConnectStrategy::ALL` so a third variant cannot arrive untested.
    ///
    /// The argv path depends on this exactly: the config reader resolves a value,
    /// the expansion renders it into `--scout-autoconnect-strategy`, and `main`
    /// parses it back. A spelling that did not survive that trip would be a key
    /// reported as applied and reaching a different policy.
    #[test]
    fn every_strategy_spelling_round_trips_through_the_flag_form() {
        assert!(
            !AutoConnectStrategy::ALL.is_empty(),
            "an empty population is green for the wrong reason"
        );
        for s in AutoConnectStrategy::ALL.iter().copied() {
            assert_eq!(
                AutoConnectStrategy::from_config_str(s.to_config_str()),
                Some(s)
            );
            let unique = AutoConnectStrategies::Unique(s);
            assert_eq!(
                AutoConnectStrategies::from_config_str(&unique.to_config_str()),
                Ok(unique)
            );
        }
        // Every per-target combination, INCLUDING the absent entries, over the
        // full cross product rather than one hand-picked table.
        let opts: Vec<Option<AutoConnectStrategy>> = core::iter::once(None)
            .chain(AutoConnectStrategy::ALL.iter().copied().map(Some))
            .collect();
        let mut seen = 0usize;
        for to_router in &opts {
            for to_peer in &opts {
                for to_client in &opts {
                    let table = AutoConnectStrategies::PerTarget {
                        to_router: *to_router,
                        to_peer: *to_peer,
                        to_client: *to_client,
                    };
                    let spelled = table.to_config_str();
                    let back = AutoConnectStrategies::from_config_str(&spelled)
                        .unwrap_or_else(|e| panic!("{spelled} did not parse back: {e}"));
                    // The all-absent table renders as its effective single value,
                    // so it comes back as `Unique(default)` rather than as an
                    // empty table — equal in EVERY verdict, which is the property
                    // that matters and the one asserted.
                    for w in [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client] {
                        assert_eq!(table.get(w), back.get(w), "{spelled} at {w:?}");
                    }
                    seen += 1;
                }
            }
        }
        assert_eq!(seen, opts.len().pow(3), "the cross product was not swept");
    }

    /// A mistyped spec is refused, and the refusal NAMES which word was wrong.
    #[test]
    fn a_mistyped_strategy_spec_is_refused_by_the_word_that_is_wrong() {
        for (spec, want) in [
            ("sometimes", AutoConnectStrategiesError::UnknownStrategy),
            (
                "to_peer=sometimes",
                AutoConnectStrategiesError::UnknownStrategy,
            ),
            (
                "to_router=always,peer",
                AutoConnectStrategiesError::NotAnEntry,
            ),
            (
                "to_gateway=always",
                AutoConnectStrategiesError::UnknownTarget,
            ),
            ("router=always", AutoConnectStrategiesError::UnknownTarget),
            (
                "to_peer=always,to_peer=greater-zid",
                AutoConnectStrategiesError::RepeatedTarget,
            ),
        ] {
            assert_eq!(
                AutoConnectStrategies::from_config_str(spec),
                Err(want),
                "{spec}"
            );
            // The sentence an operator reads is non-empty and distinct per arm.
            assert!(!want.to_string().is_empty());
        }
    }
}
