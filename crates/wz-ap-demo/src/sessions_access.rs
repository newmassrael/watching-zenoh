// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `access` key of a `--sessions` session: the §5.16 policy a multicast group is held to.
//!
//! Upstream installs no interceptor on a multicast transport, so a policy written for a node's
//! unicast sessions leaves its groups alone. wz can govern a group (the `access-acl-multicast`
//! build feature), and this key is how a document asks for it:
//!
//! ```text
//! { name: "group", mode: "peer", transport: "multicast",
//!   group: { endpoint: "udp/224.0.0.224:7446#iface=eth0" },
//!   access: { acl_deny: "admin/**",          // the `--acl-deny` policy: this key, both flows
//!             govern_multicast: true } }     // optional, false when left out
//! ```
//!
//! * `acl_deny` is the key expression `--acl-deny` takes, with the same meaning: denied on every
//!   message plane, in both flows, for every subject.
//! * `govern_multicast: true` makes the group obey it. `false`, or no such key, installs the policy
//!   and leaves the group alone, which is upstream's behaviour and the default.
//! * Only a multicast-transport session takes the block. A unicast session of this demo is driven
//!   through its open link and not through a policy-carrying session object, so a block there
//!   would be read and never applied, which is refused rather than ignored.
//!
//! The validator the other keys are held to knows nothing of this one, so the key is taken out
//! before the shared rules run (see [`crate::sessions_driver::without_local_keys`]) and judged
//! here.

use wz::runtime_tokio::json5::Json5Value;

use crate::sessions::{as_str, field, has, key_set, Refusal};

/// The keys the `access` block takes.
const ACCESS_KEYS: &[&str] = &["acl_deny", "govern_multicast"];

/// The deny-policy SSOT: the allow-default ACL that denies one key expression across the data AND
/// query planes, in both flows, for every subject (the smallest real ACL).
///
/// ONE definition for every way this demo states such a policy: `--acl-deny` at startup, the
/// runtime config-write drain (`@/<zid>/peer/config/acl-deny`), and a `--sessions` group's
/// `access.acl_deny`. The rule set is therefore not duplicated across them, and a message kind
/// the enforcer learns to govern is added here once.
///
/// A rule per FLOW (a rule carries a single flow): the key is denied on ingress (a neighbour
/// cannot push, subscribe, query, declare a queryable or reply on it through this node) and on
/// egress (this node never relays it out, nor originates it toward a peer).
#[cfg(any(feature = "access-acl-multicast", feature = "routing-peer"))]
pub(crate) fn deny_policy(deny_keyexpr: &str) -> wz::runtime_tokio::interceptor::AclPolicy {
    use wz::runtime_tokio::interceptor::{
        AclConfig, AclFlow, AclMessage, AclPolicy, AclRule, Permission, SubjectSelector,
    };
    let deny_rule = |flow| AclRule {
        subject: SubjectSelector::Any,
        key_exprs: vec![deny_keyexpr.to_owned()],
        messages: vec![
            AclMessage::Put,
            AclMessage::Delete,
            AclMessage::DeclareSubscriber,
            // The query plane (R311ud): denying K also blocks querying it, declaring a queryable
            // for it, and replying on it.
            AclMessage::Query,
            AclMessage::DeclareQueryable,
            AclMessage::Reply,
            // R311y458 — the liveliness plane, so a deny means what it says: a peer denied K
            // cannot assert liveliness on it, nor register for its token stream, nor snapshot it.
            AclMessage::LivelinessToken,
            AclMessage::DeclareLivelinessSubscriber,
            AclMessage::LivelinessQuery,
        ],
        flow,
        permission: Permission::Deny,
        link_protocols: Vec::new(),
        interfaces: Vec::new(),
        usernames: Vec::new(),
        cert_common_names: Vec::new(),
    };
    AclPolicy::new(AclConfig {
        default_permission: Permission::Allow,
        rules: vec![deny_rule(AclFlow::Ingress), deny_rule(AclFlow::Egress)],
    })
}

/// What a session's `access` block asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccessSpec {
    /// The key expression denied everywhere, as `--acl-deny` takes it.
    pub(crate) acl_deny: String,
    /// Whether the group is held to the policy.
    pub(crate) govern_multicast: bool,
}

/// Every refusal the `access` keys of a document earn, by key path.
pub(crate) fn access_refusals(doc: &Json5Value) -> Vec<Refusal> {
    let mut out = Vec::new();
    let Json5Value::Object(top) = doc else {
        return out;
    };
    let Some(Json5Value::Array(sessions)) = field(top, "sessions") else {
        return out;
    };
    for (i, session) in sessions.iter().enumerate() {
        let Json5Value::Object(entries) = session else {
            continue;
        };
        if !has(entries, "access") {
            continue;
        }
        let path = format!("sessions[{i}].access");
        if field(entries, "transport").and_then(as_str) != Some("multicast") {
            out.push(Refusal::new(
                path,
                "only a multicast session takes an access block; a unicast session of this \
                 demo is not driven through a policy, so the block would never apply",
            ));
            continue;
        }
        block_refusals(&path, field(entries, "access"), &mut out);
    }
    out
}

fn block_refusals(path: &str, block: Option<&Json5Value>, out: &mut Vec<Refusal>) {
    let Some(Json5Value::Object(access)) = block else {
        out.push(Refusal::new(path, "must be a mapping"));
        return;
    };
    for key in key_set(access) {
        if !ACCESS_KEYS.contains(&key) {
            out.push(Refusal::new(format!("{path}.{key}"), "unknown key"));
        }
    }
    match field(access, "acl_deny").and_then(as_str) {
        Some(key) if !key.is_empty() && !key.chars().any(char::is_whitespace) => {}
        _ => out.push(Refusal::new(
            format!("{path}.acl_deny"),
            "required: the key expression to deny, with no whitespace in it",
        )),
    }
    if has(access, "govern_multicast")
        && !matches!(field(access, "govern_multicast"), Some(Json5Value::Bool(_)))
    {
        out.push(Refusal::new(
            format!("{path}.govern_multicast"),
            "must be true or false",
        ));
    }
}

/// The access a session asks for, or `None` when its document has no block. Only called for a
/// document the rules and [`access_refusals`] passed.
pub(crate) fn access_of(session: &[(String, Json5Value)]) -> Option<AccessSpec> {
    let Some(Json5Value::Object(access)) = field(session, "access") else {
        return None;
    };
    Some(AccessSpec {
        acl_deny: field(access, "acl_deny")
            .and_then(as_str)
            .unwrap_or_default()
            .to_string(),
        govern_multicast: matches!(
            field(access, "govern_multicast"),
            Some(Json5Value::Bool(true))
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::read_sessions_document;

    fn group_with(block: &str) -> String {
        format!(
            r#"{{ sessions: [ {{ name: "g", mode: "peer", transport: "multicast",
                group: {{ endpoint: "udp/224.0.0.224:7446" }}, access: {block} }} ] }}"#
        )
    }

    fn refused(text: &str) -> Vec<String> {
        read_sessions_document(text)
            .expect_err("refused")
            .iter()
            .map(|r| r.to_string())
            .collect()
    }

    /// The block a document wrote reads into the policy it names, and `govern_multicast` left
    /// out is `false`: the default is upstream's.
    #[test]
    fn an_access_block_reads_into_the_policy_it_names() {
        let plan = read_sessions_document(&group_with(
            r#"{ acl_deny: "admin/**", govern_multicast: true }"#,
        ))
        .expect("passes");
        assert_eq!(
            plan.sessions[0].access,
            Some(AccessSpec {
                acl_deny: "admin/**".into(),
                govern_multicast: true,
            })
        );
        let bare =
            read_sessions_document(&group_with(r#"{ acl_deny: "admin/**" }"#)).expect("passes");
        assert_eq!(
            bare.sessions[0].access,
            Some(AccessSpec {
                acl_deny: "admin/**".into(),
                govern_multicast: false,
            })
        );
    }

    /// No block, no access: a session that asks for nothing is as it was.
    #[test]
    fn a_session_without_a_block_has_no_access() {
        let plan = read_sessions_document(
            r#"{ sessions: [ { name: "g", mode: "peer", transport: "multicast",
                group: { endpoint: "udp/224.0.0.224:7446" } } ] }"#,
        )
        .expect("passes");
        assert_eq!(plan.sessions[0].access, None);
    }

    /// Each way a block is wrong is refused by the key path that is wrong.
    #[test]
    fn a_wrong_block_is_refused_by_its_key_path() {
        for (block, path) in [
            ("{}", "sessions[0].access.acl_deny"),
            (r#"{ acl_deny: "" }"#, "sessions[0].access.acl_deny"),
            (r#"{ acl_deny: "a b" }"#, "sessions[0].access.acl_deny"),
            (r#"{ acl_deny: 3 }"#, "sessions[0].access.acl_deny"),
            (
                r#"{ acl_deny: "a/**", govern_multicast: "yes" }"#,
                "sessions[0].access.govern_multicast",
            ),
            (
                r#"{ acl_deny: "a/**", extra: 1 }"#,
                "sessions[0].access.extra",
            ),
            ("[]", "sessions[0].access"),
        ] {
            let why = refused(&group_with(block));
            assert!(
                why.iter().any(|r| r.starts_with(path)),
                "{block} must be refused at {path}, got {why:?}"
            );
        }
    }

    /// A unicast session takes no block: it would be read and never applied.
    #[test]
    fn a_unicast_session_takes_no_access_block() {
        let why = refused(
            r#"{ sessions: [ { name: "a", mode: "peer", transport: "unicast",
                listen: { endpoints: ["tcp/127.0.0.1:0"] },
                access: { acl_deny: "admin/**" } } ] }"#,
        );
        assert!(
            why.iter().any(|r| r.starts_with("sessions[0].access")),
            "{why:?}"
        );
    }
}
