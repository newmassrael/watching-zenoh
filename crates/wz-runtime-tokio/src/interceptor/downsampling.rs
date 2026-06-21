// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The §5.16 downsampling (rate-limit) interceptor — the QoS sibling of the ACL
//! enforcer on the composable [`InterceptorChain`](super::InterceptorChain), the
//! wz mirror of zenoh `net/routing/interceptor/downsampling.rs`. It proves the
//! chain is genuinely composable: a SECOND, different kind of interceptor runs
//! beside the ACL enforcer, neither aware of the other.
//!
//! A data Push whose keyexpr a rule governs is admitted at most once per the
//! rule's minimum interval — a later one arriving sooner is dropped (the wz
//! analogue of zenoh's `intercept` comparing `Instant::now() -
//! latest_message_timestamp >= threshold`). The timer is PER RULE, shared by
//! every concrete keyexpr the rule governs (zenoh keys its state by rule id —
//! `HashMap<usize, Timestate>` — not per concrete keyexpr), so the state is
//! bounded by `rules.len()`, not by the set of seen keyexprs. A rule matches a
//! message keyexpr by INTERSECTION (zenoh `intersecting_keys`), NOT the rule⊇msg
//! inclusion the ACL uses — the two predicates agree on a concrete (wildcard-free)
//! Put keyexpr but diverge on a wildcard one, so the faithful predicate is the
//! one zenoh applies. The control plane (declarations, OAM) is never throttled.

use std::cell::Cell;
use std::time::{Duration, Instant};

use wz_session_core::keyexpr_match::keyexpr_intersects_target;
use wz_session_core::network_message::NetworkMessage;

use super::{Interceptor, InterceptorContext};

/// A downsampling rule — a data Push whose keyexpr one of [`key_exprs`](Self::key_exprs)
/// INTERSECTS (zenoh `intersecting_keys`) is admitted at most once per
/// [`min_interval`](Self::min_interval), across ALL the concrete keyexprs the
/// rule governs (one shared timer). zenoh's `DownsamplingRuleConf`.
#[derive(Debug, Clone)]
pub struct DownsamplingRule {
    /// The rule keyexprs (literals or `*`/`**` patterns); a message keyexpr they
    /// INTERSECT is governed by this rule's rate limit.
    pub key_exprs: Vec<String>,
    /// The minimum interval between two admitted messages governed by this rule;
    /// one arriving sooner is dropped.
    pub min_interval: Duration,
}

/// A rule plus its single last-admitted instant — the wz analogue of zenoh's
/// per-rule `Timestate` entry (`HashMap<usize, Timestate>` keyed by rule id).
/// `Cell` because [`Interceptor::intercept`] takes `&self` (`Instant` is `Copy`).
struct RuleState {
    rule: DownsamplingRule,
    last_admitted: Cell<Option<Instant>>,
}

/// The downsampling interceptor — holds the rules, each with ONE last-admitted
/// instant (per-rule state, bounded by `rules.len()`; nothing grows with the set
/// of seen keyexprs). Installed on BOTH flows (zenoh downsampling defaults to
/// ingress + egress).
pub struct DownsamplingInterceptor {
    rules: Vec<RuleState>,
}

impl DownsamplingInterceptor {
    /// An interceptor enforcing `rules`.
    pub fn new(rules: Vec<DownsamplingRule>) -> Self {
        Self {
            rules: rules
                .into_iter()
                .map(|rule| RuleState {
                    rule,
                    last_admitted: Cell::new(None),
                })
                .collect(),
        }
    }

    /// Whether to admit a message on `keyexpr` at time `now` — the testable rate
    /// core (`intercept` calls it with `Instant::now()`). Admits (and records the
    /// instant) when no rule governs the keyexpr, or the governing rule's interval
    /// has elapsed since the last message IT admitted; otherwise drops. The FIRST
    /// rule whose keyexpr INTERSECTS the message decides (the rule-global timer).
    fn admit_at(&self, now: Instant, keyexpr: &str) -> bool {
        let target_chunks: Vec<&str> = keyexpr.split('/').collect();
        let Some(state) = self.rules.iter().find(|s| {
            s.rule
                .key_exprs
                .iter()
                .any(|ke| keyexpr_intersects_target(ke, &target_chunks))
        }) else {
            return true; // ungoverned keyexpr — never rate-limited
        };
        match state.last_admitted.get() {
            Some(prev) if now.saturating_duration_since(prev) < state.rule.min_interval => false,
            _ => {
                state.last_admitted.set(Some(now));
                true
            }
        }
    }
}

impl Interceptor for DownsamplingInterceptor {
    fn intercept(&self, ctx: &dyn InterceptorContext, msg: &NetworkMessage) -> bool {
        // Only a data Push is rate-limited; the control plane is never throttled.
        if !matches!(msg, NetworkMessage::Push(_)) {
            return true;
        }
        let Some(keyexpr) = ctx.full_keyexpr(msg) else {
            return true;
        };
        self.admit_at(Instant::now(), &keyexpr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limits_a_governed_keyexpr_by_the_minimum_interval() {
        let ds = DownsamplingInterceptor::new(vec![DownsamplingRule {
            key_exprs: vec!["demo/**".to_owned()],
            min_interval: Duration::from_millis(100),
        }]);
        let t0 = Instant::now();
        assert!(ds.admit_at(t0, "demo/data"), "first is admitted");
        assert!(
            !ds.admit_at(t0 + Duration::from_millis(40), "demo/data"),
            "within the interval -> dropped"
        );
        assert!(
            !ds.admit_at(t0 + Duration::from_millis(99), "demo/data"),
            "still within the interval -> dropped"
        );
        assert!(
            ds.admit_at(t0 + Duration::from_millis(100), "demo/data"),
            "the interval elapsed -> admitted again"
        );
        // An ungoverned keyexpr is never rate-limited.
        assert!(ds.admit_at(t0, "other/x"));
        assert!(ds.admit_at(t0, "other/x"));
    }

    #[test]
    fn concrete_keyexprs_under_one_rule_share_the_rule_timer() {
        // demo/a and demo/b both match `demo/**`; they SHARE the rule's single
        // timer (zenoh keys state by rule id, not per concrete keyexpr), so a
        // demo/b right after a demo/a is rate-limited by the same rule.
        let ds = DownsamplingInterceptor::new(vec![DownsamplingRule {
            key_exprs: vec!["demo/**".to_owned()],
            min_interval: Duration::from_millis(100),
        }]);
        let t0 = Instant::now();
        assert!(
            ds.admit_at(t0, "demo/a"),
            "first under the rule is admitted"
        );
        assert!(
            !ds.admit_at(t0 + Duration::from_millis(10), "demo/b"),
            "demo/b shares the rule timer with demo/a -> dropped"
        );
    }
}
