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
//! latest_message_timestamp >= threshold`). The interval is tracked per CONCRETE
//! message keyexpr (so `demo/a` and `demo/b` under one `demo/**` rule rate-limit
//! independently — faithful to zenoh's per-`Resource` `latest_message_timestamp`).
//! The control plane (declarations, OAM) is never throttled.

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use wz_session_core::keyexpr_match::keyexpr_includes_target;
use wz_session_core::network_message::NetworkMessage;

use super::{Interceptor, InterceptorContext};

/// A downsampling rule — a data Push whose keyexpr one of [`key_exprs`](Self::key_exprs)
/// INCLUDES (`rule ⊇ msg`, the same directional matcher the ACL uses) is admitted
/// at most once per [`min_interval`](Self::min_interval). zenoh's
/// `DownsamplingRuleConf` (`key_expr` + `freq` → an interval threshold).
#[derive(Debug, Clone)]
pub struct DownsamplingRule {
    /// The rule keyexprs (literals or `*`/`**` patterns); a message keyexpr they
    /// INCLUDE is governed by this rule's rate limit.
    pub key_exprs: Vec<String>,
    /// The minimum interval between two admitted messages on the same concrete
    /// keyexpr — a third arriving sooner is dropped.
    pub min_interval: Duration,
}

/// The downsampling interceptor — holds the rules and the per-concrete-keyexpr
/// last-admitted timestamps. Installed on the EGRESS chain (zenoh downsamples on
/// egress by default).
pub struct DownsamplingInterceptor {
    rules: Vec<DownsamplingRule>,
    /// The last-admitted instant per CONCRETE message keyexpr (interior-mutable
    /// because [`Interceptor::intercept`] takes `&self`). The map grows with the
    /// set of distinct governed keyexprs — bounded in practice by a deploy's
    /// keyexpr set; a GC bound is a tracked follow-up (zenoh bounds it via the
    /// resource tree's lifecycle).
    last_admitted: RefCell<HashMap<String, Instant>>,
}

impl DownsamplingInterceptor {
    /// An interceptor enforcing `rules`.
    pub fn new(rules: Vec<DownsamplingRule>) -> Self {
        Self {
            rules,
            last_admitted: RefCell::new(HashMap::new()),
        }
    }

    /// Whether to admit a message on `keyexpr` at time `now` — the testable rate
    /// core (`intercept` calls it with `Instant::now()`). Admits (and records the
    /// instant) when no rule governs the keyexpr, or the governing rule's
    /// interval has elapsed since the last admitted message on that exact
    /// keyexpr; otherwise drops.
    fn admit_at(&self, now: Instant, keyexpr: &str) -> bool {
        let target_chunks: Vec<&str> = keyexpr.split('/').collect();
        let Some(rule) = self.rules.iter().find(|r| {
            r.key_exprs
                .iter()
                .any(|ke| keyexpr_includes_target(ke, &target_chunks))
        }) else {
            return true; // ungoverned keyexpr — never rate-limited
        };
        let mut last = self.last_admitted.borrow_mut();
        match last.get(keyexpr) {
            Some(&prev) if now.saturating_duration_since(prev) < rule.min_interval => false,
            _ => {
                last.insert(keyexpr.to_owned(), now);
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
    fn concrete_keyexprs_under_one_rule_are_tracked_independently() {
        // demo/a and demo/b both match `demo/**`, but each has its own timer —
        // faithful to zenoh's per-Resource latest_message_timestamp.
        let ds = DownsamplingInterceptor::new(vec![DownsamplingRule {
            key_exprs: vec!["demo/**".to_owned()],
            min_interval: Duration::from_millis(100),
        }]);
        let t0 = Instant::now();
        assert!(ds.admit_at(t0, "demo/a"));
        assert!(ds.admit_at(t0, "demo/b"), "demo/b is independent of demo/a");
        assert!(
            !ds.admit_at(t0 + Duration::from_millis(10), "demo/a"),
            "demo/a is rate-limited"
        );
        assert!(
            !ds.admit_at(t0 + Duration::from_millis(10), "demo/b"),
            "demo/b is rate-limited"
        );
    }
}
