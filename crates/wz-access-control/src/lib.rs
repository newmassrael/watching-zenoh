// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The §5.16 access-control ACL policy kernel — the PURE decision engine, the
//! wz mirror of zenoh `net/routing/interceptor/authorization.rs`
//! (`PolicyEnforcer::policy_decision_point`) plus the `zenoh-config`
//! `AclConfig` shape it is built from.
//!
//! # What this is (and is not)
//!
//! This crate is ONLY the policy decision function:
//! `(subject zid, flow, action, keyexpr) -> Permission`. It holds no message
//! types, no transport state, no async — a published key is a `&str`, a subject
//! is a [`Zid`]. That separation is deliberate and mirrors zenoh's own split:
//! `authorization.rs` (this crate) is the pure engine; `access_control.rs`
//! (the wz interceptor enforcer ADAPTER, in wz-runtime-tokio) is what matches
//! on `NetworkMessage` bodies and calls this engine; `interceptor/mod.rs` (the
//! wz interceptor SEAM, also in wz-runtime-tokio) is the composable chain that
//! runs the adapter at the face message boundary. The seam + adapter reference
//! the codec message types, so they CANNOT live here — exactly why zenoh keeps
//! `authorization.rs` free of `NetworkMessage`.
//!
//! # SSOT reuse, not invention
//!
//! - The subject is the routing [`Zid`] (wz-routing-graph), the same identity
//!   the routing layer keys on — not a parallel id type. zenoh's full subject
//!   (`SubjectProperty<{interface,cert_cn,username,link,zid}>`) is reduced here
//!   to the auth-free [`SubjectSelector`] (`Any` | `Zid`); the cert/username
//!   subjects need transport authentication and arrive with the extauth
//!   features (§5.16 `access-extauth-*`).
//! - Keyexpr rule matching uses
//!   [`keyexpr_includes_target`](wz_session_core::keyexpr_match::keyexpr_includes_target):
//!   a rule keyexpr must INCLUDE the message keyexpr (`rule ⊇ msg`), the
//!   directional predicate zenoh's `policy_decision_point` applies via
//!   `deny.nodes_including(key_expr)` / `allow.nodes_including(key_expr)`. This
//!   is NOT the symmetric intersection the pub/sub route filter uses — the two
//!   diverge (rule `home/*` does not include `home/**`, yet they intersect), so
//!   reusing the route filter's matcher here would be a silent ACL defect.
//!
//! # Decision semantics (faithful to zenoh `policy_decision_point`)
//!
//! For a request `(subject, flow, action, keyexpr)`:
//!
//! 1. No rules at all → the configured [`AclConfig::default_permission`].
//! 2. A DENY rule that applies (same flow, subject matches, action listed, some
//!    rule keyexpr includes the message keyexpr) → [`Permission::Deny`]
//!    (deny wins, checked first).
//! 3. Otherwise, if the default is [`Permission::Allow`] → `Allow`.
//! 4. Otherwise (default `Deny`), an applicable ALLOW rule → `Allow`, else
//!    `Deny`.
//!
//! # Container note (perf, not semantics)
//!
//! zenoh folds rule keyexprs into a `KeBoxTree` for sublinear `nodes_including`
//! lookup; this engine keeps an `O(rules)` linear scan — the same correct
//! linear posture wz's interest matcher takes (`linkstate_interest`), with the
//! tree a tracked perf follow-up. The decision PRECEDENCE (deny-first, then
//! default, then allow) is the faithful part and is independent of the
//! container.

use wz_routing_graph::Zid;
use wz_session_core::keyexpr_match::keyexpr_includes_target;

/// Allow or deny — zenoh-config `Permission`. The verdict of every rule and the
/// workspace default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    /// The request is permitted.
    Allow,
    /// The request is blocked.
    Deny,
}

/// The flow a rule (and a request) applies to — zenoh `InterceptorFlow`.
/// Ingress is a message arriving INTO this node across a face; egress is a
/// message this node SENDS out a face. The first atom enforces
/// [`Ingress`](AclFlow::Ingress); egress is wired with the egress seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AclFlow {
    /// A message received from a face.
    Ingress,
    /// A message sent to a face.
    Egress,
}

/// The action a rule restricts — zenoh `AclMessage`. Covers the actions a
/// routing peer's inbound seam processes: the data-plane [`Put`](AclMessage::Put)
/// / [`Delete`](AclMessage::Delete) (a Push body) and the control-plane
/// [`DeclareSubscriber`](AclMessage::DeclareSubscriber). The rest of zenoh's set
/// (`Query`, `Reply`, `DeclareQueryable`, the liveliness actions) arrive as the
/// enforcer adapter gains each message-kind arm — a non-breaking enum extension,
/// since [`AclPolicy::decision`] is generic over the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AclMessage {
    /// A data Push with a `Put` payload.
    Put,
    /// A data Push with a `Del` payload (a tombstone / key removal).
    Delete,
    /// A subscription interest declaration crossing the mesh — denying it stops
    /// a peer from registering interest in the keyexpr (zenoh
    /// `AclMessage::DeclareSubscriber`).
    DeclareSubscriber,
}

/// Which subject a rule applies to — the auth-free subset of zenoh's
/// `SubjectProperty`. [`Any`](SubjectSelector::Any) is zenoh's `Wildcard` (the
/// rule applies to every peer); [`Zid`](SubjectSelector::Zid) is `Exactly(zid)`
/// (only that peer). The interface / cert-common-name / username / link-protocol
/// subjects need transport authentication and are deferred to the §5.16
/// `access-extauth-*` features.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubjectSelector {
    /// Matches every peer (zenoh `SubjectProperty::Wildcard`).
    Any,
    /// Matches only the peer with this routing identity (zenoh
    /// `SubjectProperty::Exactly`).
    Zid(Zid),
}

impl SubjectSelector {
    /// Whether this selector matches the request's subject zid.
    #[inline]
    fn matches(&self, subject: &Zid) -> bool {
        match self {
            SubjectSelector::Any => true,
            SubjectSelector::Zid(z) => z == subject,
        }
    }
}

/// One access-control rule — zenoh `AclConfigRule` expanded to a single
/// subject. A rule APPLIES to a request when the flows match, the subject
/// selector matches, the action is in [`messages`](AclRule::messages), and at
/// least one of [`key_exprs`](AclRule::key_exprs) INCLUDES the message keyexpr.
#[derive(Debug, Clone)]
pub struct AclRule {
    /// Which peer this rule governs.
    pub subject: SubjectSelector,
    /// The rule keyexprs (literals or `*`/`**` patterns). A rule matches when
    /// any one of these INCLUDES the message keyexpr (`rule ⊇ msg`).
    pub key_exprs: Vec<String>,
    /// The actions this rule restricts.
    pub messages: Vec<AclMessage>,
    /// The flow this rule applies to.
    pub flow: AclFlow,
    /// The verdict when the rule applies.
    pub permission: Permission,
}

/// The access-control configuration — the wz mirror of `zenoh-config`'s
/// `AclConfig`, the SINGLE construction shape every policy source funnels
/// through (the programmatic demo builder today; a `deploy.yaml` loader later
/// — both produce this struct, so there is one construction path, exactly as
/// zenoh has one `PolicyEnforcer::init(&AclConfig)`).
#[derive(Debug, Clone)]
pub struct AclConfig {
    /// The verdict when no rule applies (zenoh `default_permission`).
    pub default_permission: Permission,
    /// The ordered rule set.
    pub rules: Vec<AclRule>,
}

impl AclConfig {
    /// A default-deny configuration with no rules — every request denied. The
    /// strictest base a deploy adds allow-rules onto.
    pub fn deny_all() -> Self {
        Self {
            default_permission: Permission::Deny,
            rules: Vec::new(),
        }
    }

    /// A default-allow configuration with no rules — every request allowed. The
    /// base a deploy adds deny-rules onto (the common "open mesh with a few
    /// forbidden keyexprs" shape).
    pub fn allow_all() -> Self {
        Self {
            default_permission: Permission::Allow,
            rules: Vec::new(),
        }
    }
}

/// The compiled policy — the wz mirror of zenoh's `PolicyEnforcer`. Holds the
/// immutable rule set; the per-face resolved subject and the message-kind
/// dispatch live in the interceptor enforcer adapter (wz-runtime-tokio), which
/// shares this policy as an `Arc` across faces exactly as zenoh shares one
/// `Arc<PolicyEnforcer>` across its per-transport enforcers.
#[derive(Debug, Clone)]
pub struct AclPolicy {
    config: AclConfig,
}

impl AclPolicy {
    /// Compile a policy from its configuration.
    pub fn new(config: AclConfig) -> Self {
        Self { config }
    }

    /// The configured default verdict — exposed so a caller can distinguish a
    /// configured-but-default-allow policy from "no policy".
    pub fn default_permission(&self) -> Permission {
        self.config.default_permission
    }

    /// The verdict for a request — the wz port of zenoh
    /// `PolicyEnforcer::policy_decision_point` (deny-first, then default, then
    /// allow). `keyexpr` is the message's key expression; it is split once here
    /// and each rule keyexpr is tested for INCLUSION of it via the
    /// [`keyexpr_includes_target`] SSOT.
    pub fn decision(
        &self,
        subject: &Zid,
        flow: AclFlow,
        action: AclMessage,
        keyexpr: &str,
    ) -> Permission {
        if self.config.rules.is_empty() {
            return self.config.default_permission;
        }
        // Split the message keyexpr ONCE; each rule keyexpr is then tested for
        // `rule ⊇ msg` against these chunks (the directional ACL predicate).
        let target_chunks: Vec<&str> = keyexpr.split('/').collect();
        let applies = |rule: &AclRule| -> bool {
            rule.flow == flow
                && rule.subject.matches(subject)
                && rule.messages.contains(&action)
                && rule
                    .key_exprs
                    .iter()
                    .any(|ke| keyexpr_includes_target(ke, &target_chunks))
        };
        // Deny wins, checked first (zenoh `deny.nodes_including(..).any(..)`).
        if self
            .config
            .rules
            .iter()
            .any(|r| r.permission == Permission::Deny && applies(r))
        {
            return Permission::Deny;
        }
        // No deny matched: a default-allow policy permits without consulting the
        // allow rules (they only narrow a default-deny).
        if self.config.default_permission == Permission::Allow {
            return Permission::Allow;
        }
        // Default-deny: permit only on an explicit allow match.
        if self
            .config
            .rules
            .iter()
            .any(|r| r.permission == Permission::Allow && applies(r))
        {
            return Permission::Allow;
        }
        Permission::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zid(b: &[u8]) -> Zid {
        Zid::from_slice(b)
    }

    fn deny_rule(subject: SubjectSelector, ke: &str) -> AclRule {
        AclRule {
            subject,
            key_exprs: vec![ke.to_owned()],
            messages: vec![AclMessage::Put],
            flow: AclFlow::Ingress,
            permission: Permission::Deny,
        }
    }

    fn allow_rule(subject: SubjectSelector, ke: &str) -> AclRule {
        AclRule {
            permission: Permission::Allow,
            ..deny_rule(subject, ke)
        }
    }

    #[test]
    fn no_rules_returns_the_default_permission() {
        let z = zid(&[1]);
        assert_eq!(
            AclPolicy::new(AclConfig::allow_all()).decision(
                &z,
                AclFlow::Ingress,
                AclMessage::Put,
                "x/y"
            ),
            Permission::Allow
        );
        assert_eq!(
            AclPolicy::new(AclConfig::deny_all()).decision(
                &z,
                AclFlow::Ingress,
                AclMessage::Put,
                "x/y"
            ),
            Permission::Deny
        );
    }

    #[test]
    fn deny_rule_blocks_a_matching_keyexpr_on_an_allow_default() {
        let z = zid(&[1]);
        let policy = AclPolicy::new(AclConfig {
            default_permission: Permission::Allow,
            rules: vec![deny_rule(SubjectSelector::Any, "admin/**")],
        });
        // Denied: the deny rule's `admin/**` includes `admin/cfg`.
        assert_eq!(
            policy.decision(&z, AclFlow::Ingress, AclMessage::Put, "admin/cfg"),
            Permission::Deny
        );
        // Allowed: outside the deny keyexpr, the allow default carries it.
        assert_eq!(
            policy.decision(&z, AclFlow::Ingress, AclMessage::Put, "demo/data"),
            Permission::Allow
        );
    }

    #[test]
    fn allow_rule_admits_a_matching_keyexpr_on_a_deny_default() {
        let z = zid(&[1]);
        let policy = AclPolicy::new(AclConfig {
            default_permission: Permission::Deny,
            rules: vec![allow_rule(SubjectSelector::Any, "metrics/**")],
        });
        assert_eq!(
            policy.decision(&z, AclFlow::Ingress, AclMessage::Put, "metrics/cpu"),
            Permission::Allow
        );
        // Default-deny carries everything the allow rule does not cover.
        assert_eq!(
            policy.decision(&z, AclFlow::Ingress, AclMessage::Put, "admin/cfg"),
            Permission::Deny
        );
    }

    #[test]
    fn deny_wins_over_an_overlapping_allow() {
        let z = zid(&[1]);
        let policy = AclPolicy::new(AclConfig {
            default_permission: Permission::Deny,
            rules: vec![
                allow_rule(SubjectSelector::Any, "secret/**"),
                deny_rule(SubjectSelector::Any, "secret/key"),
            ],
        });
        // Both rules apply to `secret/key`; deny wins.
        assert_eq!(
            policy.decision(&z, AclFlow::Ingress, AclMessage::Put, "secret/key"),
            Permission::Deny
        );
        // Only the allow applies here.
        assert_eq!(
            policy.decision(&z, AclFlow::Ingress, AclMessage::Put, "secret/pub"),
            Permission::Allow
        );
    }

    #[test]
    fn a_zid_subject_rule_only_governs_that_peer() {
        let denied = zid(&[0xAA]);
        let other = zid(&[0xBB]);
        let policy = AclPolicy::new(AclConfig {
            default_permission: Permission::Allow,
            rules: vec![deny_rule(SubjectSelector::Zid(denied), "admin/**")],
        });
        // The named peer is denied admin/**.
        assert_eq!(
            policy.decision(&denied, AclFlow::Ingress, AclMessage::Put, "admin/cfg"),
            Permission::Deny
        );
        // Another peer is not governed by that rule -> allow default.
        assert_eq!(
            policy.decision(&other, AclFlow::Ingress, AclMessage::Put, "admin/cfg"),
            Permission::Allow
        );
    }

    #[test]
    fn a_rule_does_not_apply_across_flows() {
        let z = zid(&[1]);
        let policy = AclPolicy::new(AclConfig {
            default_permission: Permission::Allow,
            rules: vec![deny_rule(SubjectSelector::Any, "admin/**")],
        });
        // The deny rule is Ingress-flow; an Egress request is not governed by it.
        assert_eq!(
            policy.decision(&z, AclFlow::Egress, AclMessage::Put, "admin/cfg"),
            Permission::Allow
        );
    }

    #[test]
    fn a_rule_only_governs_its_listed_actions() {
        let z = zid(&[1]);
        // A rule listing Delete + DeclareSubscriber (but NOT Put) governs those
        // two actions and leaves Put to the allow default — the engine is
        // action-generic, so the new actions flow through the same decision.
        let policy = AclPolicy::new(AclConfig {
            default_permission: Permission::Allow,
            rules: vec![AclRule {
                subject: SubjectSelector::Any,
                key_exprs: vec!["admin/**".to_owned()],
                messages: vec![AclMessage::Delete, AclMessage::DeclareSubscriber],
                flow: AclFlow::Ingress,
                permission: Permission::Deny,
            }],
        });
        assert_eq!(
            policy.decision(&z, AclFlow::Ingress, AclMessage::Delete, "admin/cfg"),
            Permission::Deny
        );
        assert_eq!(
            policy.decision(
                &z,
                AclFlow::Ingress,
                AclMessage::DeclareSubscriber,
                "admin/cfg"
            ),
            Permission::Deny
        );
        // Put is not in the rule's action set -> allow default carries it.
        assert_eq!(
            policy.decision(&z, AclFlow::Ingress, AclMessage::Put, "admin/cfg"),
            Permission::Allow
        );
    }
}
