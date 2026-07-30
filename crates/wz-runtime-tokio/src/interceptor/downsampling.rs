// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The §5.16 downsampling (rate-limit) interceptor — the QoS sibling of the ACL
//! enforcer on the composable [`InterceptorChain`](super::InterceptorChain), the
//! wz mirror of zenoh `net/routing/interceptor/downsampling.rs`. It proves the
//! chain is genuinely composable: a SECOND, different kind of interceptor runs
//! beside the ACL enforcer, neither aware of the other.
//!
//! A message of a governed [`kind`](DownsamplingRule::messages), on a governed
//! [`flow`](DownsamplingRule::flows), whose keyexpr a rule governs is admitted at
//! most once per the rule's minimum interval — a later one arriving sooner is
//! dropped (the wz analogue of zenoh's `intercept` comparing `Instant::now() -
//! latest_message_timestamp >= threshold`, `downsampling.rs:242`). The timer is
//! PER RULE, shared by every concrete keyexpr the rule governs (zenoh keys its
//! state by rule id — `HashMap<usize, Timestate>` — not per concrete keyexpr), so
//! the state is bounded by `rules.len()`, not by the set of seen keyexprs. A rule
//! matches a message keyexpr by INTERSECTION (zenoh `intersecting_keys`), NOT the
//! rule⊇msg inclusion the ACL and the low-pass use — the two predicates agree on
//! a concrete (wildcard-free) Put keyexpr but diverge on a wildcard one, so the
//! faithful predicate is the one zenoh applies. The control plane (declarations,
//! `ResponseFinal`, OAM) is never throttled.
//!
//! # What a rule governs (R311y452)
//!
//! A rule carries the axes zenoh's `DownsamplingItemConf` +
//! `DownsamplingRuleConf` carry and wz can resolve: `key_exprs`, the interval,
//! the [`messages`](DownsamplingRule::messages) set and the
//! [`flows`](DownsamplingRule::flows) set. Before R311y452 wz had only the first
//! two, which made three divergences from zenoh 1.5.0 that a foreign peer could
//! drive:
//!
//! 1. **Only a Push was throttled, always.** zenoh throttles Push, Query AND
//!    Reply, selected per configuration item by a required non-empty `messages`
//!    list (`downsampling.rs:168-215`, `zenoh-config/src/lib.rs:108-114`). wz
//!    hardcoded the Push arm, so it both MISSED the query plane and could not be
//!    narrowed OFF the data plane.
//! 2. **Both flows were always installed.** zenoh installs a separate ingress /
//!    egress downsampler and only for the flows the item lists, defaulting to
//!    both (`downsampling.rs:76-79`, `:133-152`); a flow no rule governs gets no
//!    interceptor at all.
//! 3. **A drop-everything rule was unrepresentable.** zenoh's unit is a FREQUENCY
//!    in Hertz, and `freq == 0.0` is the special case that leaves the threshold
//!    at `Duration::MAX` WITHOUT the shift-back that makes the first message due
//!    (`:291-298`) — so a zero-frequency rule drops even the first message. wz's
//!    interval always admitted the first. [`interval_from_freq`] closes both
//!    halves: the Hz→interval mapping and the drop-all sentinel.
//!
//! # Deliberate omissions, with their reasons
//!
//! - **`interfaces` / `link_protocols` subject scoping** (zenoh `:90-116`). zenoh
//!   narrows an item to the NIC name and link protocol of the transport the
//!   message arrived on; wz's `FaceState` carries neither, and
//!   `BoxedLinkDriver` (`wz-session-core/src/link.rs:63-81`) exposes no locator
//!   or protocol accessor to derive them from. It is ONE seam serving all three
//!   interceptors — the ACL subject axis, this downsampler and the low-pass — so
//!   it belongs to a round that builds that seam, not to a third of a port inside
//!   one atom's module. Same disposition, same reason, as R311y451 recorded for
//!   `access-quota`.
//! - **Rule `id` uniqueness validation** (zenoh `:48-54`). As in the low-pass, the
//!   `id` has NO other consumer — a grep of `.id` across zenoh's `downsampling.rs`
//!   shows the single read at `:50`, inside the uniqueness check itself. Porting
//!   it would add a field whose only function is to validate its own uniqueness.
//! - **`compute_keyexpr_cache`** (zenoh `:222-230`) — a per-face memoization of
//!   the matched rule id, not a semantic. wz has no per-face keyexpr cache seam to
//!   hang it on; the rule lookup is a linear scan of the rule list.
//! - **The one-shot INFO log flag** (zenoh `:218-219`, `:246-248`). wz witnesses
//!   drops with the `LinkstateForwarder::interceptor_dropped` counter, which is
//!   what the cross-impl leg reads; a rate-limited log line is not a semantic.
//!
//! # Established by read, NOT a residual
//!
//! zenoh installs no downsampler on a multicast transport at all
//! (`new_transport_multicast` / `new_peer_multicast` both return `None`,
//! `:156-165`). wz consults the chain only from the per-FACE unicast admission
//! points (`linkstate_forward.rs:883-908`, `router_forward.rs:1233-1255`); the
//! multicast ingress path (`route_mcast_ingress`) never reaches `admit`. The two
//! agree, so this is not a gap.

use std::cell::Cell;
use std::time::{Duration, Instant};

use wz_session_core::keyexpr_match::keyexpr_intersects_target;
use wz_session_core::network_message::NetworkMessage;

use super::{Interceptor, InterceptorContext, InterceptorFlow};

/// Which message KIND a downsampling rule throttles — the wz mirror of zenoh
/// `DownsamplingMessage` (`zenoh-config/src/lib.rs:108-114`), the `messages`
/// selector. zenoh dispatches at the NETWORK-BODY level (`downsampling.rs:205-215`),
/// one kind per body, which is why this enum is coarser than the low-pass's
/// [`LowPassMessage`](super::low_pass::LowPassMessage): the low-pass mirrors an
/// upstream that matches the inner body variant, this mirrors one that does not.
/// The asymmetry is upstream's, and porting each faithfully reproduces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownsamplingMessage {
    /// A data `Push` — zenoh `NetworkBodyMut::Push(_)`.
    Push,
    /// A `Request` — zenoh `NetworkBodyMut::Request(_)`. zenoh's `RequestBody`
    /// has only a `Query` arm, so upstream's `Request(_)` IS a query; wz's codec
    /// can also route a Put / Del as a Request, and those take this same arm
    /// because the arm zenoh writes is body-blind. (The sibling low-pass splits
    /// them out, because the upstream IT mirrors matches on the body.)
    Query,
    /// A `Response` (a query reply) — zenoh `NetworkBodyMut::Response(_)`.
    Reply,
}

impl DownsamplingMessage {
    /// Every kind — what a "rate-limit this keyexpr" deploy knob means, and what
    /// zenoh's required non-empty `messages` list would have to spell out to
    /// govern the whole message surface.
    pub const ALL: [DownsamplingMessage; 3] = [
        DownsamplingMessage::Push,
        DownsamplingMessage::Query,
        DownsamplingMessage::Reply,
    ];
}

/// Nanoseconds per second — zenoh's `NANOS_PER_SEC` (`downsampling.rs:280`),
/// the constant of the Hz→interval mapping.
const NANOS_PER_SEC: f64 = 1_000_000_000.0;

/// A downsampling rule — a message of a governed [`kind`](Self::messages), on a
/// governed [`flow`](Self::flows), whose keyexpr one of
/// [`key_exprs`](Self::key_exprs) INTERSECTS (zenoh `intersecting_keys`) is
/// admitted at most once per [`min_interval`](Self::min_interval), across ALL the
/// concrete keyexprs the rule governs (one shared timer). zenoh's
/// `DownsamplingRuleConf` plus the item-level selectors its `DownsamplingItemConf`
/// carries — wz puts them per RULE, which is a superset: an item's shared set is
/// expressed by repeating it on each of its rules.
#[derive(Debug, Clone)]
pub struct DownsamplingRule {
    /// The rule keyexprs (literals or `*`/`**` patterns); a message keyexpr they
    /// INTERSECT is governed by this rule's rate limit.
    pub key_exprs: Vec<String>,
    /// The minimum interval between two admitted messages governed by this rule;
    /// one arriving sooner is dropped. [`Duration::MAX`] is the DROP-ALL rule
    /// (zenoh's `freq == 0.0`), which drops even the first message — build it
    /// with [`interval_from_freq`].
    pub min_interval: Duration,
    /// Which message kinds this rule throttles. zenoh's `messages` is a REQUIRED
    /// non-empty list, so there is no "all kinds" default to inherit — a rule
    /// governing everything spells out [`DownsamplingMessage::ALL`].
    pub messages: Vec<DownsamplingMessage>,
    /// Which flows this rule applies to. zenoh's `flows` is optional and defaults
    /// to BOTH (`downsampling.rs:76-79`); wz makes the resolved set explicit on
    /// the rule so the per-flow interceptor can filter on it.
    pub flows: Vec<InterceptorFlow>,
}

/// The minimum interval for a maximum frequency in Hertz — zenoh's
/// `Duration::from_nanos((1. / rule.freq * NANOS_PER_SEC) as u64)`
/// (`downsampling.rs:294-298`), including its two edges:
///
/// - `freq == 0.0` maps to [`Duration::MAX`], the DROP-ALL rule. zenoh reaches
///   the same behaviour a different way — it leaves `threshold` at
///   `Duration::MAX` and, crucially, SKIPS the `latest_message_timestamp -=
///   threshold` shift that makes the first message due — so even the first
///   message fails `now - latest >= MAX`. wz encodes that state in the interval
///   itself rather than in a seeded instant, which keeps
///   [`admit_at`](DownsamplingInterceptor::admit_at) a pure function of the clock
///   it is handed (zenoh's form would need an `Instant::now()` at construction)
///   and avoids the `Instant - Duration::MAX` underflow that shift would be.
/// - a NEGATIVE or non-finite frequency saturates the `as u64` cast to `0`, i.e.
///   no throttling — the same value zenoh's identical cast produces. Mirrored
///   rather than rejected: the config surface is upstream's, not wz's to tighten.
pub fn interval_from_freq(freq: f64) -> Duration {
    if freq == 0.0 {
        return Duration::MAX;
    }
    Duration::from_nanos((1. / freq * NANOS_PER_SEC) as u64)
}

/// A rule plus its single last-admitted instant — the wz analogue of zenoh's
/// per-rule `Timestate` entry (`HashMap<usize, Timestate>` keyed by rule id).
/// `Cell` because [`Interceptor::intercept`] takes `&self` (`Instant` is `Copy`).
struct RuleState {
    rule: DownsamplingRule,
    last_admitted: Cell<Option<Instant>>,
}

/// The downsampling interceptor for ONE flow — holds the rules that apply to that
/// flow, each with ONE last-admitted instant (per-rule state, bounded by
/// `rules.len()`; nothing grows with the set of seen keyexprs). zenoh builds a
/// separate ingress / egress `DownsamplingInterceptor`, each with its OWN
/// `ke_state` (`downsampling.rs:133-152`), which is why the flow is resolved once
/// at construction and the timers do not straddle the two directions.
///
/// R311y452 — that per-flow independence carries NO test, deliberately. It is
/// structurally guaranteed and therefore untestable here:
/// [`InterceptorConfig::build_chain`](super::InterceptorConfig::build_chain) is
/// called once per flow (`linkstate_forward.rs:865-866`) and each call
/// constructs fresh [`Cell`]s, so there is no shared state for a leak to travel
/// through. That was CHECKED, not assumed — a candidate test was written and
/// then removed after no damage to either this module or `build_chain` could
/// red it. zenoh needs its `Arc<Mutex<HashMap<usize, Timestate>>>` because its
/// factory hands the rule set to two interceptors; wz's config-to-chain shape
/// does not.
pub struct DownsamplingInterceptor {
    rules: Vec<RuleState>,
}

impl DownsamplingInterceptor {
    /// The interceptor enforcing the subset of `rules` that applies to `flow`, or
    /// `None` when none does — the wz analogue of zenoh's
    /// `self.flows.<flow>.then(|| ...)` (`downsampling.rs:133-152`), which
    /// installs no interceptor on a flow no rule governs.
    pub fn for_flow(rules: &[DownsamplingRule], flow: InterceptorFlow) -> Option<Self> {
        let rules: Vec<RuleState> = rules
            .iter()
            .filter(|r| r.flows.contains(&flow))
            .map(|rule| RuleState {
                rule: rule.clone(),
                last_admitted: Cell::new(None),
            })
            .collect();
        (!rules.is_empty()).then_some(Self { rules })
    }

    /// Whether to admit a `message` of the given kind on `keyexpr` at time `now` —
    /// the testable rate core (`intercept` calls it with `Instant::now()`).
    /// Admits (and records the instant) when no rule governs the (kind, keyexpr)
    /// pair, or the governing rule's interval has elapsed since the last message
    /// IT admitted; otherwise drops. The FIRST rule whose keyexpr INTERSECTS the
    /// message decides (zenoh takes `intersecting_keys(ke).next()`,
    /// `downsampling.rs:224` — the first match, NOT the low-pass's minimum across
    /// matches).
    fn admit_at(&self, now: Instant, message: DownsamplingMessage, keyexpr: &str) -> bool {
        let target_chunks: Vec<&str> = keyexpr.split('/').collect();
        let Some(state) = self
            .rules
            .iter()
            .filter(|s| s.rule.messages.contains(&message))
            .find(|s| {
                s.rule
                    .key_exprs
                    .iter()
                    .any(|ke| keyexpr_intersects_target(ke, &target_chunks))
            })
        else {
            return true; // ungoverned (kind, keyexpr) — never rate-limited
        };
        match state.last_admitted.get() {
            // The DROP-ALL rule (zenoh `freq == 0.0`): zenoh withholds the
            // shift-back that makes the first message due, so the first is
            // dropped too. Every LATER message is covered by the arm below, in
            // which no real elapsed time can reach `Duration::MAX`.
            None if state.rule.min_interval == Duration::MAX => false,
            Some(prev) if now.saturating_duration_since(prev) < state.rule.min_interval => false,
            _ => {
                state.last_admitted.set(Some(now));
                true
            }
        }
    }
}

/// Classify `msg` into the kind a downsampling rule selects on, or `None` for a
/// kind zenoh never throttles — the wz mirror of `is_msg_filtered`'s match over
/// `NetworkBodyMut` (`downsampling.rs:205-215`), where `ResponseFinal`,
/// `Interest`, `Declare` and `OAM` are hard `false` arms.
///
/// The dispatch is at the NETWORK-BODY level, exactly as upstream writes it: a
/// `Request` is a [`Query`](DownsamplingMessage::Query) whatever body it carries.
/// That deliberately differs from the sibling low-pass, which splits a
/// `Request(Put)` out as a Put — because the upstream low-pass matches on the
/// inner body and this upstream does not. Two adapters, two upstreams, two
/// granularities; the asymmetry is ported, not invented.
fn message_kind(msg: &NetworkMessage) -> Option<DownsamplingMessage> {
    match msg {
        NetworkMessage::Push(_) => Some(DownsamplingMessage::Push),
        NetworkMessage::Request(_) => Some(DownsamplingMessage::Query),
        NetworkMessage::Response(_) => Some(DownsamplingMessage::Reply),
        _ => None,
    }
}

impl Interceptor for DownsamplingInterceptor {
    fn intercept(&self, ctx: &dyn InterceptorContext, msg: &NetworkMessage) -> bool {
        // A kind zenoh does not throttle is admitted (its `false` arms).
        let Some(message) = message_kind(msg) else {
            return true;
        };
        let Some(keyexpr) = ctx.full_keyexpr(msg) else {
            return true;
        };
        self.admit_at(Instant::now(), message, &keyexpr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rule governing every kind on both flows — what the deploy knob builds.
    fn rule(key_exprs: &[&str], min_interval: Duration) -> DownsamplingRule {
        DownsamplingRule {
            key_exprs: key_exprs.iter().map(|k| (*k).to_owned()).collect(),
            min_interval,
            messages: DownsamplingMessage::ALL.to_vec(),
            flows: InterceptorFlow::ALL.to_vec(),
        }
    }

    fn ingress(rules: Vec<DownsamplingRule>) -> DownsamplingInterceptor {
        DownsamplingInterceptor::for_flow(&rules, InterceptorFlow::Ingress)
            .expect("both-flow rules apply to ingress")
    }

    #[test]
    fn rate_limits_a_governed_keyexpr_by_the_minimum_interval() {
        let ds = ingress(vec![rule(&["demo/**"], Duration::from_millis(100))]);
        let t0 = Instant::now();
        let push = |at: Duration, ke| ds.admit_at(t0 + at, DownsamplingMessage::Push, ke);
        assert!(push(Duration::ZERO, "demo/data"), "first is admitted");
        assert!(
            !push(Duration::from_millis(40), "demo/data"),
            "within the interval -> dropped"
        );
        assert!(
            !push(Duration::from_millis(99), "demo/data"),
            "still within the interval -> dropped"
        );
        assert!(
            push(Duration::from_millis(100), "demo/data"),
            "the interval elapsed -> admitted again"
        );
        // An ungoverned keyexpr is never rate-limited.
        assert!(push(Duration::ZERO, "other/x"));
        assert!(push(Duration::ZERO, "other/x"));
    }

    #[test]
    fn concrete_keyexprs_under_one_rule_share_the_rule_timer() {
        // demo/a and demo/b both match `demo/**`; they SHARE the rule's single
        // timer (zenoh keys state by rule id, not per concrete keyexpr), so a
        // demo/b right after a demo/a is rate-limited by the same rule.
        let ds = ingress(vec![rule(&["demo/**"], Duration::from_millis(100))]);
        let t0 = Instant::now();
        assert!(
            ds.admit_at(t0, DownsamplingMessage::Push, "demo/a"),
            "first under the rule is admitted"
        );
        assert!(
            !ds.admit_at(
                t0 + Duration::from_millis(10),
                DownsamplingMessage::Push,
                "demo/b"
            ),
            "demo/b shares the rule timer with demo/a -> dropped"
        );
    }

    /// R311y452 — a rule's `messages` set scopes it to the kinds it lists; a kind
    /// outside the set is never throttled on the same keyexpr (zenoh selects the
    /// body arm against the item's `DownsamplingFilters`,
    /// `downsampling.rs:205-215`). The pre-y452 code throttled Push and ONLY
    /// Push, unconditionally — so this reds both if the selector is ignored and
    /// if the query plane is left unreachable.
    #[test]
    fn a_rule_governs_only_the_kinds_it_lists() {
        let query_only = ingress(vec![DownsamplingRule {
            key_exprs: vec!["demo/**".to_owned()],
            min_interval: Duration::from_millis(100),
            messages: vec![DownsamplingMessage::Query],
            flows: InterceptorFlow::ALL.to_vec(),
        }]);
        let t0 = Instant::now();
        // The query plane IS governed — a second query inside the interval drops.
        assert!(query_only.admit_at(t0, DownsamplingMessage::Query, "demo/q"));
        assert!(
            !query_only.admit_at(
                t0 + Duration::from_millis(10),
                DownsamplingMessage::Query,
                "demo/q"
            ),
            "Query is in the rule's messages set -> rate-limited"
        );
        // ... and the kinds it does NOT list are unlimited on that same keyexpr,
        // however fast they arrive.
        for ungoverned in [DownsamplingMessage::Push, DownsamplingMessage::Reply] {
            assert!(query_only.admit_at(t0, ungoverned, "demo/q"));
            assert!(
                query_only.admit_at(t0, ungoverned, "demo/q"),
                "{ungoverned:?} is not in the rule's messages set -> never throttled"
            );
        }
    }

    /// R311y452 — a rule's `flows` set scopes it to one direction, and a flow no
    /// rule governs installs NO interceptor at all (zenoh's
    /// `self.flows.<flow>.then(...)`, `downsampling.rs:133-152`). The pre-y452
    /// code installed the downsampler on both flows unconditionally.
    #[test]
    fn a_flow_no_rule_governs_installs_no_interceptor() {
        let ingress_only = vec![DownsamplingRule {
            key_exprs: vec!["demo/**".to_owned()],
            min_interval: Duration::from_millis(100),
            messages: DownsamplingMessage::ALL.to_vec(),
            flows: vec![InterceptorFlow::Ingress],
        }];
        let on_ingress = DownsamplingInterceptor::for_flow(&ingress_only, InterceptorFlow::Ingress)
            .expect("the ingress-scoped rule applies to ingress");
        let t0 = Instant::now();
        assert!(on_ingress.admit_at(t0, DownsamplingMessage::Push, "demo/x"));
        assert!(
            !on_ingress.admit_at(
                t0 + Duration::from_millis(10),
                DownsamplingMessage::Push,
                "demo/x"
            ),
            "the ingress rule throttles an ingress Push"
        );
        assert!(
            DownsamplingInterceptor::for_flow(&ingress_only, InterceptorFlow::Egress).is_none(),
            "no rule governs egress -> no egress interceptor is installed"
        );
    }

    /// R311y452 — the Hz→interval mapping is zenoh's, including the `freq == 0.0`
    /// DROP-ALL edge and the saturating cast on a negative frequency.
    #[test]
    fn the_frequency_maps_to_zenohs_interval() {
        assert_eq!(interval_from_freq(2.0), Duration::from_millis(500));
        assert_eq!(interval_from_freq(1.0), Duration::from_secs(1));
        assert_eq!(interval_from_freq(1000.0), Duration::from_millis(1));
        assert_eq!(
            interval_from_freq(0.0),
            Duration::MAX,
            "zero frequency is the drop-all rule, not an unthrottled one"
        );
        assert_eq!(
            interval_from_freq(-1.0),
            Duration::ZERO,
            "a negative frequency saturates zenoh's `as u64` cast to 0"
        );
    }

    /// R311y452 — a `freq == 0.0` rule drops EVERY message, the first included.
    /// This is the half that is easy to get wrong: an interval-based port admits
    /// the first message because it has no previous one to compare against, while
    /// zenoh withholds the shift-back that would make it due (`:291-298`).
    #[test]
    fn a_zero_frequency_rule_drops_even_the_first_message() {
        let ds = ingress(vec![rule(&["demo/**"], interval_from_freq(0.0))]);
        let t0 = Instant::now();
        assert!(
            !ds.admit_at(t0, DownsamplingMessage::Push, "demo/x"),
            "the FIRST message under a zero-frequency rule is already dropped"
        );
        assert!(
            !ds.admit_at(
                t0 + Duration::from_secs(3600),
                DownsamplingMessage::Push,
                "demo/x"
            ),
            "and no elapsed time ever makes one due"
        );
        // The rule still scopes to its keyexprs — drop-all is not deny-all.
        assert!(ds.admit_at(t0, DownsamplingMessage::Push, "other/x"));
    }

    /// The kind classification is bound to real built messages, so a codec arm
    /// rename reds here. zenoh dispatches on the network body — a `Request` is a
    /// Query whatever it carries — and `Declare` / `ResponseFinal` / OAM are the
    /// hard `false` arms (`downsampling.rs:205-215`).
    #[test]
    fn message_kind_classifies_the_bodies_zenoh_throttles() {
        use wz_session_core::push_build::build_push_literal;
        use wz_session_core::request_build::build_request_query;
        use wz_session_core::response_build::build_response_reply_literal;

        let push = NetworkMessage::Push(Box::new(
            build_push_literal("demo/x", b"1234").expect("build put"),
        ));
        assert_eq!(message_kind(&push), Some(DownsamplingMessage::Push));

        let query = NetworkMessage::Request(Box::new(
            build_request_query(1, 0, Some("demo/q")).expect("build query"),
        ));
        assert_eq!(message_kind(&query), Some(DownsamplingMessage::Query));

        let reply = NetworkMessage::Response(Box::new(
            build_response_reply_literal(1, "demo/q", b"abc").expect("build reply"),
        ));
        assert_eq!(message_kind(&reply), Some(DownsamplingMessage::Reply));

        let declare = NetworkMessage::Declare(Box::new(
            wz_session_core::declare_build::build_declare_queryable(0, 0, Some("demo/q"))
                .expect("build decl queryable"),
        ));
        assert_eq!(
            message_kind(&declare),
            None,
            "the control plane is never throttled"
        );
    }
}
