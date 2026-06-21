// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The §5.16 low-pass (per-key payload-size limit) interceptor — the wz mirror
//! of zenoh `net/routing/interceptor/low_pass.rs`, and the faithful realization
//! of the `access-quota` inventory feature.
//!
//! HONEST mapping note. The `access-quota` catalog entry reads "per-key quota
//! accounting", but zenoh has NO cumulative quota-accounting interceptor — only
//! `low_pass`, a per-key payload-SIZE limit (a Put whose payload exceeds the
//! limit for its keyexpr is dropped). A cumulative byte/message accounting quota
//! would be an INVENTION, which the port-don't-invent rule forbids; so "quota"
//! is realized as zenoh's actual per-key limit: a payload-size cap. The
//! interceptor is STATELESS (a pure size comparison — no clock, no per-keyexpr
//! state, unlike the downsampler), and is the THIRD interceptor kind on the
//! composable chain beside the ACL enforcer and the downsampler.
//!
//! Only a Put carries a sized payload, so only a Put is limited; a Del / the
//! control plane carry no governed payload and are admitted.

use wz_codecs::push::PushOwnedVariant;
use wz_session_core::keyexpr_match::keyexpr_includes_target;
use wz_session_core::network_message::NetworkMessage;

use super::{Interceptor, InterceptorContext};

/// A low-pass rule — a Put whose keyexpr one of [`key_exprs`](Self::key_exprs)
/// INCLUDES (`rule ⊇ msg`, the same directional matcher the ACL uses) is dropped
/// when its payload exceeds [`max_payload_size`](Self::max_payload_size) bytes.
/// zenoh's `LowPassFilterConf` (`key_exprs` + `size_limit`).
#[derive(Debug, Clone)]
pub struct LowPassRule {
    /// The rule keyexprs (literals or `*`/`**` patterns); a message keyexpr they
    /// INCLUDE is governed by this rule's size limit.
    pub key_exprs: Vec<String>,
    /// The maximum admitted Put payload size in bytes; a larger one is dropped.
    pub max_payload_size: usize,
}

/// The low-pass interceptor — holds the rules; stateless (the decision is a pure
/// `(payload size, keyexpr)` comparison). Installed on BOTH flows (zenoh low_pass
/// defaults to ingress + egress), the size-limit sibling of the downsampler.
pub struct LowPassInterceptor {
    rules: Vec<LowPassRule>,
}

impl LowPassInterceptor {
    /// An interceptor enforcing `rules`.
    pub fn new(rules: Vec<LowPassRule>) -> Self {
        Self { rules }
    }

    /// Whether to admit a Put of `size` bytes on `keyexpr` — the testable core
    /// (`intercept` extracts the size + keyexpr and calls it). Admits when no
    /// rule governs the keyexpr, or the message fits the governing rule's limit;
    /// drops a payload larger than the limit. The FIRST matching rule decides
    /// (mirroring zenoh's per-keyexpr `get_max_allowed_message_size`).
    fn admit_size(&self, size: usize, keyexpr: &str) -> bool {
        let target_chunks: Vec<&str> = keyexpr.split('/').collect();
        for rule in &self.rules {
            if rule
                .key_exprs
                .iter()
                .any(|ke| keyexpr_includes_target(ke, &target_chunks))
            {
                return size <= rule.max_payload_size;
            }
        }
        true // ungoverned keyexpr — never size-limited
    }
}

impl Interceptor for LowPassInterceptor {
    fn intercept(&self, ctx: &dyn InterceptorContext, msg: &NetworkMessage) -> bool {
        // Only a Put carries a sized payload; a Del / control plane is admitted.
        let NetworkMessage::Push(p) = msg else {
            return true;
        };
        let PushOwnedVariant::CodecZenohMsgPut(put) = &p.body else {
            return true;
        };
        let Some(keyexpr) = ctx.full_keyexpr(msg) else {
            return true;
        };
        // Measure the ACTUAL payload bytes (zenoh reads `put.payload.len()`), not
        // the producer-supplied `payload_len` wire field. DIVERGENCE: zenoh also
        // adds the attachment size to the budget; wz accounts only the payload
        // (the data-plane attachment rides the Push ext-chain and is not summed
        // here — a tracked fidelity gap, not a soundness hole).
        self.admit_size(put.payload.as_slice().len(), &keyexpr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_a_put_whose_payload_exceeds_the_limit() {
        let lp = LowPassInterceptor::new(vec![LowPassRule {
            key_exprs: vec!["demo/**".to_owned()],
            max_payload_size: 16,
        }]);
        assert!(lp.admit_size(0, "demo/data"), "empty fits");
        assert!(lp.admit_size(16, "demo/data"), "exactly the limit fits");
        assert!(
            !lp.admit_size(17, "demo/data"),
            "one over the limit is dropped"
        );
        assert!(!lp.admit_size(1024, "demo/data"), "well over is dropped");
        // An ungoverned keyexpr is never size-limited.
        assert!(lp.admit_size(1 << 20, "other/x"), "no rule -> admitted");
    }

    #[test]
    fn the_first_matching_rule_decides() {
        let lp = LowPassInterceptor::new(vec![
            LowPassRule {
                key_exprs: vec!["demo/small/**".to_owned()],
                max_payload_size: 4,
            },
            LowPassRule {
                key_exprs: vec!["demo/**".to_owned()],
                max_payload_size: 64,
            },
        ]);
        // demo/small/x matches the first (tighter) rule.
        assert!(
            !lp.admit_size(8, "demo/small/x"),
            "tight rule applies first"
        );
        // demo/big matches only the second (looser) rule.
        assert!(lp.admit_size(8, "demo/big"), "looser rule admits 8 bytes");
        assert!(!lp.admit_size(65, "demo/big"), "but not over its 64 limit");
    }
}
