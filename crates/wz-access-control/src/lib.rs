// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//!   [`keyexpr_includes_target`]:
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
use wz_session_core::link::{InterceptorLink, LinkSubject};

/// Allow or deny — zenoh-config `Permission`. The verdict of every rule and the
/// workspace default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    /// The request is permitted.
    Allow,
    /// The request is blocked.
    Deny,
}

impl Permission {
    /// The lowercase wire/admin string (zenoh-config `Permission` rendering) — the
    /// SSOT for the admin config-GET view (`acl_default` / `acl_rules.permission`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::Allow => "allow",
            Permission::Deny => "deny",
        }
    }
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

impl AclFlow {
    /// The lowercase wire/admin string for the config-GET `acl_rules.flow` view.
    pub fn as_str(&self) -> &'static str {
        match self {
            AclFlow::Ingress => "ingress",
            AclFlow::Egress => "egress",
        }
    }
}

/// The action a rule restricts — zenoh `AclMessage`, and as of R311y458 the
/// SAME NINE actions in the same order (`zenoh-config/src/lib.rs:354-364`):
/// the data plane ([`Put`](AclMessage::Put) / [`Delete`](AclMessage::Delete)),
/// the query plane ([`Query`](AclMessage::Query) / [`Reply`](AclMessage::Reply)
/// / [`DeclareQueryable`](AclMessage::DeclareQueryable)), the subscription
/// control plane ([`DeclareSubscriber`](AclMessage::DeclareSubscriber)), and the
/// three liveliness actions. An action governs BOTH the declare and the
/// undeclare of its kind, exactly as zenoh reuses one action for the pair.
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
    /// A routed query (a `Request` carrying a `Query`) — denying it stops a peer
    /// from querying the keyexpr across the mesh (zenoh `AclMessage::Query`).
    Query,
    /// A queryable interest declaration crossing the mesh — denying it stops a
    /// peer from registering a queryable for the keyexpr, the query-plane twin of
    /// [`DeclareSubscriber`](AclMessage::DeclareSubscriber) (zenoh
    /// `AclMessage::DeclareQueryable`).
    DeclareQueryable,
    /// A query reply (a `Response`, Reply or Err) — denying it stops a peer from
    /// answering a query on the keyexpr (zenoh `AclMessage::Reply`).
    Reply,
    /// A liveliness token declaration — denying it stops a peer from asserting
    /// liveliness on the keyexpr (zenoh `AclMessage::LivelinessToken`). Governs
    /// the `UndeclareToken` too.
    LivelinessToken,
    /// A liveliness SUBSCRIPTION — a token-carrying `Interest` whose mode
    /// includes FUTURE, i.e. a peer registering for the token stream (zenoh
    /// `AclMessage::DeclareLivelinessSubscriber`).
    DeclareLivelinessSubscriber,
    /// A one-shot liveliness GET — a token-carrying `Interest` whose mode is
    /// CURRENT only, i.e. a snapshot of the alive matching tokens (zenoh
    /// `AclMessage::LivelinessQuery`). Separate from
    /// [`DeclareLivelinessSubscriber`](AclMessage::DeclareLivelinessSubscriber)
    /// because zenoh splits the Interest arms on mode, not on the token flag.
    LivelinessQuery,
}

impl AclMessage {
    /// The lowercase wire/admin string (mirrors zenoh `AclMessage` names) for the
    /// config-GET `acl_rules.messages` view.
    pub fn as_str(&self) -> &'static str {
        match self {
            AclMessage::Put => "put",
            AclMessage::Delete => "delete",
            AclMessage::DeclareSubscriber => "declare_subscriber",
            AclMessage::Query => "query",
            AclMessage::DeclareQueryable => "declare_queryable",
            AclMessage::Reply => "reply",
            AclMessage::LivelinessToken => "liveliness_token",
            AclMessage::DeclareLivelinessSubscriber => "declare_liveliness_subscriber",
            AclMessage::LivelinessQuery => "liveliness_query",
        }
    }
}

/// Which subject a rule applies to — the auth-free subset of zenoh's
/// `SubjectProperty`. [`Any`](SubjectSelector::Any) is zenoh's `Wildcard` (the
/// rule applies to every peer); [`Zid`](SubjectSelector::Zid) is `Exactly(zid)`
/// (only that peer). The link-protocol and interface subjects are NOT here: they
/// narrow a rule rather than name a peer, so R311y453 put them on
/// [`AclRule`](AclRule#structfield.link_protocols) instead. What remains absent
/// from zenoh's `SubjectProperty` set is the cert-common-name and the username
/// (`interceptor/authorization.rs:40-45`), both of which need transport
/// authentication — deferred to the §5.16 `access-extauth-*` features.
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
    /// R311y453 — the LINK-PROTOCOL subject axis: the rule governs only a face
    /// whose transport speaks one of these. EMPTY means the rule does not narrow
    /// by protocol, which is zenoh's `link_protocols: None`
    /// (`zenoh-config/src/lib.rs:134`).
    ///
    /// FAIL-CLOSED on an indeterminate subject — see
    /// [`LinkSubject::opt_matches_protocols`].
    pub link_protocols: Vec<InterceptorLink>,
    /// R311y453 — the NIC-NAME subject axis: the rule governs only a face whose
    /// link sits on one of these interfaces. EMPTY means the rule does not narrow
    /// by interface (zenoh's `interfaces: None`).
    ///
    /// FAIL-CLOSED on an indeterminate subject, and a link RESOLVED to no NIC (a
    /// unix socket, pipe, serial, vsock) is a definite non-match — see
    /// [`LinkSubject::opt_matches_interfaces`].
    pub interfaces: Vec<String>,
    /// The verdict when the rule applies.
    pub permission: Permission,
}

impl AclRule {
    /// R311y453 — whether this rule's LINK subject axes admit `subject`, i.e.
    /// whether the rule governs the face the message arrived on at all.
    ///
    /// Both axes must pass, and an axis left EMPTY does not narrow. Kept beside
    /// the rule rather than in the enforcer so the three §5.16 interceptors
    /// cannot drift on the policy: the downsampler and the low-pass call the same
    /// two [`LinkSubject`] matchers.
    pub fn governs_link(&self, subject: Option<&LinkSubject>) -> bool {
        LinkSubject::opt_matches_protocols(subject, &self.link_protocols)
            && LinkSubject::opt_matches_interfaces(subject, &self.interfaces)
    }
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

// WHICH KEYS THIS ANSWERS. Upstream configures the same engine under
// `access_control/default_permission`, `access_control/rules`,
// `access_control/subjects`, `access_control/policies` and
// `access_control/enabled`. wz's config reader honours none of them, so all five
// are carried in `UNHONOURED_READER_GAP` — the engine is HERE, and what is
// missing is the reader. Three shape notes the reader will have to bridge:
// upstream names subjects and rules and then JOINS them under `policies`, while
// an `AclRule` here carries its subject axes inline; `enabled` has no switch to
// build, because a peer with no policy installed already enforces nothing; and
// a `subjects` entry reaches THREE of upstream's five axes here — `subject`
// (zid), `link_protocols` and `interfaces` — so `cert_common_names` and
// `usernames` are the two a reader cannot bridge, which is what the
// `access-acl` catalog atom's reason has said since R311y453.
// R2151 (open-debt item 540) moved the five and added this comment:
// until then the classification lived only in the reader's own doc, which made
// it a claim with no witness at the capability.

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

    /// R311y54 — the ordered rule set, for the admin config-GET FULL per-rule dump
    /// (`acl_rules`): each rule's subject / flow / messages / permission / key_exprs.
    /// The detail complement to [`Self::deny_key_exprs`] (the denied-keyexpr
    /// summary); allow rules + the subject/flow/message detail appear only here.
    pub fn rules(&self) -> &[AclRule] {
        &self.config.rules
    }

    /// R311y49 — the keyexprs appearing in at least one DENY rule, sorted and
    /// deduplicated: the admin-introspection summary of "what this policy forbids".
    /// It is the GET-observable surface of a runtime ACL reconfigure — a config
    /// write that adds or changes a deny rule changes THIS list, so the admin
    /// config GET observes the change (the read-path counterpart to the data-plane
    /// drop). A SUMMARY, not the full per-rule dump: the subject / message-kind /
    /// flow of each rule are elided (a detailed rule view is a deferred richer
    /// admin layer); two different rules denying the same keyexpr collapse to one
    /// entry. Allow rules never appear here.
    pub fn deny_key_exprs(&self) -> Vec<String> {
        let mut keys: Vec<String> = self
            .config
            .rules
            .iter()
            .filter(|r| r.permission == Permission::Deny)
            .flat_map(|r| r.key_exprs.iter().cloned())
            .collect();
        keys.sort();
        keys.dedup();
        keys
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
        link: Option<&LinkSubject>,
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
                // R311y453 — the LINK subject axes, checked beside the zid
                // subject: zenoh decides these in the interceptor FACTORY (it
                // simply does not install the interceptor on a non-matching
                // transport); wz has one chain for every face, so the same
                // narrowing happens per rule, here.
                && rule.governs_link(link)
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
            link_protocols: Vec::new(),
            interfaces: Vec::new(),
        }
    }

    fn allow_rule(subject: SubjectSelector, ke: &str) -> AclRule {
        AclRule {
            permission: Permission::Allow,
            ..deny_rule(subject, ke)
        }
    }

    #[test]
    fn deny_key_exprs_collects_sorted_deduped_deny_keys_only() {
        // R311y49 — the admin-introspection summary: only DENY rules' keyexprs,
        // sorted + deduped; allow rules and the rule's subject/message/flow elided.
        let policy = AclPolicy::new(AclConfig {
            default_permission: Permission::Allow,
            rules: vec![
                deny_rule(SubjectSelector::Any, "mesh/data"),
                allow_rule(SubjectSelector::Any, "metrics/**"), // allow: excluded
                deny_rule(SubjectSelector::Any, "admin/**"),
                deny_rule(SubjectSelector::Any, "mesh/data"), // dup: collapsed
            ],
        });
        assert_eq!(
            policy.deny_key_exprs(),
            vec!["admin/**".to_owned(), "mesh/data".to_owned()]
        );
        // No rules at all -> empty (a default-allow open policy forbids nothing).
        assert!(AclPolicy::new(AclConfig::allow_all())
            .deny_key_exprs()
            .is_empty());
    }

    #[test]
    fn enum_as_str_maps_match_zenoh_names() {
        // R311y54 — the wire/admin-string SSOT used by the config-GET acl_rules dump.
        assert_eq!(Permission::Allow.as_str(), "allow");
        assert_eq!(Permission::Deny.as_str(), "deny");
        assert_eq!(AclFlow::Ingress.as_str(), "ingress");
        assert_eq!(AclFlow::Egress.as_str(), "egress");
        assert_eq!(AclMessage::Put.as_str(), "put");
        assert_eq!(AclMessage::Delete.as_str(), "delete");
        assert_eq!(AclMessage::DeclareSubscriber.as_str(), "declare_subscriber");
        assert_eq!(AclMessage::Query.as_str(), "query");
        assert_eq!(AclMessage::DeclareQueryable.as_str(), "declare_queryable");
        assert_eq!(AclMessage::Reply.as_str(), "reply");
    }

    #[test]
    fn rules_accessor_returns_the_ordered_rule_set() {
        // R311y54 — the full per-rule dump source (the detail complement to
        // deny_key_exprs): preserves order, includes allow rules + every field.
        let policy = AclPolicy::new(AclConfig {
            default_permission: Permission::Allow,
            rules: vec![
                deny_rule(SubjectSelector::Any, "mesh/data"),
                allow_rule(SubjectSelector::Zid(zid(&[1, 2])), "metrics/**"),
            ],
        });
        let rules = policy.rules();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].permission, Permission::Deny);
        assert_eq!(rules[1].permission, Permission::Allow);
        assert_eq!(rules[1].subject, SubjectSelector::Zid(zid(&[1, 2])));
        assert!(AclPolicy::new(AclConfig::allow_all()).rules().is_empty());
    }

    #[test]
    fn no_rules_returns_the_default_permission() {
        let z = zid(&[1]);
        assert_eq!(
            AclPolicy::new(AclConfig::allow_all()).decision(
                &z,
                AclFlow::Ingress,
                AclMessage::Put,
                "x/y",
                None
            ),
            Permission::Allow
        );
        assert_eq!(
            AclPolicy::new(AclConfig::deny_all()).decision(
                &z,
                AclFlow::Ingress,
                AclMessage::Put,
                "x/y",
                None
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
            policy.decision(&z, AclFlow::Ingress, AclMessage::Put, "admin/cfg", None),
            Permission::Deny
        );
        // Allowed: outside the deny keyexpr, the allow default carries it.
        assert_eq!(
            policy.decision(&z, AclFlow::Ingress, AclMessage::Put, "demo/data", None),
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
            policy.decision(&z, AclFlow::Ingress, AclMessage::Put, "metrics/cpu", None),
            Permission::Allow
        );
        // Default-deny carries everything the allow rule does not cover.
        assert_eq!(
            policy.decision(&z, AclFlow::Ingress, AclMessage::Put, "admin/cfg", None),
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
            policy.decision(&z, AclFlow::Ingress, AclMessage::Put, "secret/key", None),
            Permission::Deny
        );
        // Only the allow applies here.
        assert_eq!(
            policy.decision(&z, AclFlow::Ingress, AclMessage::Put, "secret/pub", None),
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
            policy.decision(
                &denied,
                AclFlow::Ingress,
                AclMessage::Put,
                "admin/cfg",
                None
            ),
            Permission::Deny
        );
        // Another peer is not governed by that rule -> allow default.
        assert_eq!(
            policy.decision(&other, AclFlow::Ingress, AclMessage::Put, "admin/cfg", None),
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
            policy.decision(&z, AclFlow::Egress, AclMessage::Put, "admin/cfg", None),
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
                link_protocols: Vec::new(),
                interfaces: Vec::new(),
            }],
        });
        assert_eq!(
            policy.decision(&z, AclFlow::Ingress, AclMessage::Delete, "admin/cfg", None),
            Permission::Deny
        );
        assert_eq!(
            policy.decision(
                &z,
                AclFlow::Ingress,
                AclMessage::DeclareSubscriber,
                "admin/cfg",
                None
            ),
            Permission::Deny
        );
        // Put is not in the rule's action set -> allow default carries it.
        assert_eq!(
            policy.decision(&z, AclFlow::Ingress, AclMessage::Put, "admin/cfg", None),
            Permission::Allow
        );
    }
}
