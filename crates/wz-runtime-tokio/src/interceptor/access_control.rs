// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The ACL enforcer ADAPTER — the wz mirror of zenoh
//! `net/routing/interceptor/access_control.rs` (`IngressAclEnforcer` /
//! `EgressAclEnforcer`). It is the bridge between the codec [`NetworkMessage`]
//! and the pure [`wz_access_control`] policy engine: it dispatches on the
//! message KIND (a single `match`, mirroring zenoh's match over
//! `NetworkBodyMut`), maps the kind to an [`AclMessage`] action, resolves the
//! subject + keyexpr off the [`InterceptorContext`], and asks the policy for a
//! verdict.
//!
//! Governed actions: the data-plane `Put` / `Del` (a Push or a write-Request
//! body), the query plane `Query` (a Request's Query body) / `Reply` (a
//! Response) / `DeclareQueryable`, and the control plane `DeclareSubscriber`.
//! Every other kind — the rest of the `Declare` family, the keyless
//! `ResponseFinal`, the liveliness messages — is admitted here and gains its own
//! arm as the action set grows. Because the per-kind dispatch is a `match`,
//! adding an action is a new arm, not a new check site.

use wz_access_control::{AclFlow, AclMessage, AclPolicy, Permission};
use wz_codecs::declare::DeclareOwnedVariant;
use wz_codecs::push::PushOwnedVariant;
use wz_codecs::request::RequestOwnedVariant;
use wz_session_core::network_message::NetworkMessage;

use super::{Interceptor, InterceptorContext};

/// An access-control enforcer for one flow — the wz mirror of zenoh's
/// `IngressAclEnforcer` / `EgressAclEnforcer`. Holds the (shared) compiled
/// [`AclPolicy`] and the flow it enforces. A policy install creates one per
/// flow (an ingress enforcer consulted at the forwarder's inbound seam, an
/// egress one at the outbound `fan_out`), both sharing the same rule set.
pub struct AclInterceptor {
    policy: AclPolicy,
    flow: AclFlow,
}

impl AclInterceptor {
    /// An enforcer applying `policy` to the given `flow`.
    pub fn new(policy: AclPolicy, flow: AclFlow) -> Self {
        Self { policy, flow }
    }
}

/// The ACL action a message represents, or `None` for a kind this enforcer does
/// not govern (which is then admitted). The wz analogue of zenoh's
/// per-`NetworkBody` dispatch in `access_control.rs::intercept`: a Push / Request
/// maps to [`Put`](AclMessage::Put) / [`Delete`](AclMessage::Delete) /
/// [`Query`](AclMessage::Query) on its body, a Response to
/// [`Reply`](AclMessage::Reply), a `DeclareSubscriber` /  `DeclareQueryable` to
/// [`DeclareSubscriber`](AclMessage::DeclareSubscriber) /
/// [`DeclareQueryable`](AclMessage::DeclareQueryable). An UndeclareSubscriber /
/// keyexpr-alias declaration, the keyless `ResponseFinal`, and the liveliness
/// kinds are not governed, so they return `None` and admit.
fn acl_action(msg: &NetworkMessage) -> Option<AclMessage> {
    match msg {
        NetworkMessage::Push(p) => match &p.body {
            PushOwnedVariant::CodecZenohMsgPut(_) => Some(AclMessage::Put),
            PushOwnedVariant::CodecZenohMsgDel(_) => Some(AclMessage::Delete),
            _ => None,
        },
        // A routed Request maps by its body, the same as a Push: a Query body is
        // the query plane (governed as `Query`); a Put / Del body is a write
        // routed via the request mechanism (governed as the data-plane action).
        NetworkMessage::Request(r) => match &r.body {
            RequestOwnedVariant::CodecZenohQuery(_) => Some(AclMessage::Query),
            RequestOwnedVariant::CodecZenohMsgPut(_) => Some(AclMessage::Put),
            RequestOwnedVariant::CodecZenohMsgDel(_) => Some(AclMessage::Delete),
            _ => None,
        },
        // A query reply (a `Response`, Reply or Err body) — both bodies are a
        // `Reply` action. This arm does NOT cover the end-marker:
        // [`ResponseFinal`](NetworkMessage::ResponseFinal) is its own
        // `NetworkMessage` variant (`wz_session_core::network_message`), not a
        // `Response` body, so it exits at the `_ => None` arm below and never
        // reaches the keyexpr branch at all — the same place zenoh puts it
        // (an explicitly unfiltered arm beside `Interest` and `OAM`,
        // net/routing/interceptor/access_control.rs:615-617 / :922-924).
        NetworkMessage::Response(_) => Some(AclMessage::Reply),
        NetworkMessage::Declare(d)
            if matches!(d.body, DeclareOwnedVariant::CodecZenohDeclSubscriber(_)) =>
        {
            Some(AclMessage::DeclareSubscriber)
        }
        NetworkMessage::Declare(d)
            if matches!(d.body, DeclareOwnedVariant::CodecZenohDeclQueryable(_)) =>
        {
            Some(AclMessage::DeclareQueryable)
        }
        _ => None,
    }
}

impl Interceptor for AclInterceptor {
    fn intercept(&self, ctx: &dyn InterceptorContext, msg: &NetworkMessage) -> bool {
        // A kind this atom does not govern is admitted (zenoh's unmatched arms).
        let Some(action) = acl_action(msg) else {
            return true;
        };
        // No resolved subject -> admit: the enforcer cannot attribute the
        // message to a peer, so it does not block it (zenoh skips a transport
        // with no matched subject).
        let Some(subject) = ctx.subject() else {
            return true;
        };
        // A GOVERNED kind whose keyexpr does not resolve -> DENY. The enforcer
        // cannot decide a rule it cannot name a keyexpr for, and fail-open is the
        // wrong default for the one place that says no: zenoh takes the same
        // branch in ALL 22 of its governed arms
        // (`let Some(keyexpr) = ctx.full_keyexpr(msg) else { return false };`,
        // net/routing/interceptor/access_control.rs:386-600, ingress + egress).
        // Two message shapes reach this branch, and zenoh denies both: an
        // UNDECLARED expr-id (`resolve_wireexpr` misses the face's alias table)
        // and the EMPTY wireexpr a synthesized timeout `Err` carries (zenoh
        // `WireExpr::empty()`, dispatcher/queries.rs:317 — its `full_keyexpr`
        // composes the root prefix `""` and `KeyExpr::new("")` then fails on the
        // empty chunk, so the Response arm returns false). So an installed ACL
        // dropping the timeout `Err` is upstream behaviour, not a wz regression;
        // the querier still terminates on its own timeout.
        let Some(keyexpr) = ctx.full_keyexpr(msg) else {
            return false;
        };
        self.policy
            .decision(&subject, self.flow, action, &keyexpr, ctx.link_subject())
            == Permission::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashbrown::HashMap;
    use wz_access_control::{AclConfig, AclRule, SubjectSelector};
    use wz_routing_graph::Zid;
    use wz_session_core::push_build::{
        build_push_aliased, build_push_del_literal, build_push_literal,
    };

    /// A context that hands back a fixed subject and resolves the message keyexpr
    /// through the PRODUCTION SSOT — the same
    /// [`resolve_governed_keyexpr`](crate::linkstate_forward::resolve_governed_keyexpr)
    /// both forwarders' real `FaceContext::full_keyexpr` delegates to — against
    /// `aliases`, this fixture's stand-in for a face's link-local alias table. It
    /// resolves what production resolves, so an "undeclared expr-id" and a keyless
    /// `Err` are the production shapes here, not mock-only ones (the earlier
    /// hand-written Push-only body could not have expressed either).
    struct MockCtx {
        subject: Option<Zid>,
        aliases: HashMap<u64, String>,
    }

    impl MockCtx {
        /// A context attributing every message to `subject`, with an EMPTY alias
        /// table — the literal id-0 keyexprs the fixtures build resolve verbatim,
        /// and any aliased one is by construction undeclared.
        fn with_subject(subject: Option<Zid>) -> Self {
            Self {
                subject,
                aliases: HashMap::new(),
            }
        }
    }

    impl InterceptorContext for MockCtx {
        fn subject(&self) -> Option<Zid> {
            self.subject
        }
        fn full_keyexpr(&self, msg: &NetworkMessage) -> Option<String> {
            crate::linkstate_forward::resolve_governed_keyexpr(msg, &self.aliases)
        }
    }

    fn deny_admin_policy() -> AclPolicy {
        AclPolicy::new(AclConfig {
            default_permission: Permission::Allow,
            rules: vec![AclRule {
                subject: SubjectSelector::Any,
                key_exprs: vec!["admin/**".to_owned()],
                messages: vec![
                    AclMessage::Put,
                    AclMessage::Delete,
                    AclMessage::DeclareSubscriber,
                ],
                flow: AclFlow::Ingress,
                permission: Permission::Deny,
                link_protocols: Vec::new(),
                interfaces: Vec::new(),
            }],
        })
    }

    #[test]
    fn acl_action_maps_the_query_plane() {
        // R311ud — the query-plane action mapping: a Request(Query) -> Query, a
        // Response -> Reply, a DeclareQueryable -> DeclareQueryable. The
        // Request(Put|Del)-body -> Put|Delete arms are the faithful zenoh
        // body-dispatch (and gate a Request-carried write rather than admit it),
        // but wz emits only Request(Query) today, so they are not exercised here.
        use wz_session_core::declare_build::build_declare_queryable;
        use wz_session_core::request_build::build_request_query;
        use wz_session_core::response_build::build_response_reply_literal;

        let query = NetworkMessage::Request(Box::new(
            build_request_query(1, 0, Some("demo/q")).expect("build query"),
        ));
        assert_eq!(acl_action(&query), Some(AclMessage::Query));

        let reply = NetworkMessage::Response(Box::new(
            build_response_reply_literal(1, "demo/q", b"x").expect("build reply"),
        ));
        assert_eq!(acl_action(&reply), Some(AclMessage::Reply));

        let decl_qabl = NetworkMessage::Declare(Box::new(
            build_declare_queryable(0, 0, Some("demo/q")).expect("build decl queryable"),
        ));
        assert_eq!(acl_action(&decl_qabl), Some(AclMessage::DeclareQueryable));
    }

    #[test]
    fn a_denied_put_is_dropped() {
        let acl = AclInterceptor::new(deny_admin_policy(), AclFlow::Ingress);
        let ctx = MockCtx::with_subject(Some(Zid::from_slice(&[0x0A])));
        let put = NetworkMessage::Push(Box::new(
            build_push_literal("admin/secret", b"x").expect("build"),
        ));
        assert!(!acl.intercept(&ctx, &put), "admin/secret Put is denied");
    }

    #[test]
    fn an_admitted_put_passes() {
        let acl = AclInterceptor::new(deny_admin_policy(), AclFlow::Ingress);
        let ctx = MockCtx::with_subject(Some(Zid::from_slice(&[0x0A])));
        let put = NetworkMessage::Push(Box::new(
            build_push_literal("demo/data", b"x").expect("build"),
        ));
        assert!(acl.intercept(&ctx, &put), "demo/data Put is admitted");
    }

    #[test]
    fn a_del_on_a_denied_keyexpr_is_denied() {
        // Del is a governed action (maps to AclMessage::Delete); a Del on the
        // denied keyexpr is dropped just like a Put.
        let acl = AclInterceptor::new(deny_admin_policy(), AclFlow::Ingress);
        let ctx = MockCtx::with_subject(Some(Zid::from_slice(&[0x0A])));
        let del = NetworkMessage::Push(Box::new(
            build_push_del_literal("admin/secret").expect("build"),
        ));
        assert!(!acl.intercept(&ctx, &del), "admin/secret Del is denied");
    }

    #[test]
    fn a_message_with_no_subject_is_admitted() {
        let acl = AclInterceptor::new(deny_admin_policy(), AclFlow::Ingress);
        let ctx = MockCtx::with_subject(None);
        let put = NetworkMessage::Push(Box::new(
            build_push_literal("admin/secret", b"x").expect("build"),
        ));
        assert!(
            acl.intercept(&ctx, &put),
            "an unattributable message is admitted, not blocked"
        );
    }

    /// A Put aliased to `mapping_id`, with the fixed `/data` suffix — the one
    /// message shape the three alias legs below vary the TABLE around, so the
    /// only difference between them is whether (and to what) the id is declared.
    fn aliased_put(mapping_id: u64) -> NetworkMessage {
        NetworkMessage::Push(Box::new(
            build_push_aliased(mapping_id, Some("/data"), b"x").expect("build aliased push"),
        ))
    }

    #[test]
    fn an_undeclared_expr_id_is_denied() {
        // The fail-OPEN close. A governed Put naming an expr-id the face never
        // declared has no resolvable keyexpr, so no rule can be evaluated for it;
        // wz used to ADMIT it, where zenoh denies in all 22 governed arms.
        // DISCRIMINATING: the policy defaults to ALLOW and its only rule covers
        // `admin/**`, so the unresolvable-keyexpr branch is the ONLY thing that
        // can deny here — restoring `intercept`'s `return true` fails this and
        // nothing else in the file.
        let acl = AclInterceptor::new(deny_admin_policy(), AclFlow::Ingress);
        let ctx = MockCtx::with_subject(Some(Zid::from_slice(&[0x0A])));
        let put = aliased_put(7);
        assert_eq!(
            acl_action(&put),
            Some(AclMessage::Put),
            "precondition: the message IS governed, so it reaches the keyexpr branch",
        );
        assert_eq!(
            ctx.full_keyexpr(&put),
            None,
            "precondition: expr-id 7 is absent from the alias table",
        );
        assert!(
            !acl.intercept(&ctx, &put),
            "an undeclared expr-id is denied"
        );
    }

    #[test]
    fn the_same_alias_admits_once_declared() {
        // The PAIR to the leg above: the deny is about a resolution FAILURE, not
        // about aliased messages. Declaring 7 -> `demo` makes the identical Put
        // resolve to `demo/data`, which the default-Allow policy admits.
        let acl = AclInterceptor::new(deny_admin_policy(), AclFlow::Ingress);
        let mut aliases = HashMap::new();
        aliases.insert(7u64, "demo".to_owned());
        let ctx = MockCtx {
            subject: Some(Zid::from_slice(&[0x0A])),
            aliases,
        };
        let put = aliased_put(7);
        assert_eq!(
            ctx.full_keyexpr(&put).as_deref(),
            Some("demo/data"),
            "the declared prefix composes with the message suffix",
        );
        assert!(
            acl.intercept(&ctx, &put),
            "a declared alias resolves and allows"
        );
    }

    #[test]
    fn a_declared_alias_into_the_denied_space_is_denied_by_the_rule() {
        // The third leg of the same triple: a RESOLVED keyexpr actually reaches
        // the policy. Declaring 7 -> `admin` composes `admin/data`, which the
        // `admin/**` rule denies — so the alias path feeds the rule engine, and
        // the deny in the first leg is not simply "aliased messages fail".
        let acl = AclInterceptor::new(deny_admin_policy(), AclFlow::Ingress);
        let mut aliases = HashMap::new();
        aliases.insert(7u64, "admin".to_owned());
        let ctx = MockCtx {
            subject: Some(Zid::from_slice(&[0x0A])),
            aliases,
        };
        let put = aliased_put(7);
        assert_eq!(ctx.full_keyexpr(&put).as_deref(), Some("admin/data"));
        assert!(
            !acl.intercept(&ctx, &put),
            "a declared alias resolving into admin/** is denied by the rule"
        );
    }

    #[test]
    fn the_empty_keyexpr_timeout_err_is_denied() {
        // The OTHER shape that reaches the unresolvable branch, and the one wz
        // message an installed ACL now drops that it used to pass: the synthesized
        // timeout `Err` carries the EMPTY wireexpr (zenoh `WireExpr::empty()`),
        // which resolves to nothing. zenoh denies it too — its `full_keyexpr`
        // composes the root prefix "" and `KeyExpr::new("")` fails on the empty
        // chunk, so the governed Response arm returns false.
        use wz_session_core::response_build::build_response_err_empty;

        let acl = AclInterceptor::new(deny_admin_policy(), AclFlow::Ingress);
        let ctx = MockCtx::with_subject(Some(Zid::from_slice(&[0x0A])));
        let err = NetworkMessage::Response(Box::new(
            build_response_err_empty(42, b"Timeout").expect("build empty err"),
        ));
        assert_eq!(
            acl_action(&err),
            Some(AclMessage::Reply),
            "precondition: an Err body is a governed Reply",
        );
        assert_eq!(
            ctx.full_keyexpr(&err),
            None,
            "precondition: the empty wireexpr resolves to nothing",
        );
        assert!(
            !acl.intercept(&ctx, &err),
            "the empty-keyexpr timeout Err is denied, as in zenoh"
        );
    }

    #[test]
    fn a_response_final_admits_via_the_action_arm_not_the_keyexpr_one() {
        // The end-marker is keyless AND ungoverned, and WHICH branch admits it is
        // the load-bearing part: `ResponseFinal` is its own `NetworkMessage`
        // variant, so `acl_action` returns None and `intercept` admits BEFORE
        // asking for a keyexpr. Were it ever folded into the governed `Response`
        // arm, it would now hit the deny branch and every query end-marker would
        // drop — this test is what reds first if that happens.
        let acl = AclInterceptor::new(deny_admin_policy(), AclFlow::Ingress);
        let ctx = MockCtx::with_subject(Some(Zid::from_slice(&[0x0A])));
        let fin = NetworkMessage::ResponseFinal(
            wz_session_core::response_final_build::build_response_final(42),
        );
        assert_eq!(
            acl_action(&fin),
            None,
            "ResponseFinal is ungoverned at the ACTION arm",
        );
        assert_eq!(
            ctx.full_keyexpr(&fin),
            None,
            "and it has no keyexpr, so admitting cannot be coming from there",
        );
        assert!(
            acl.intercept(&ctx, &fin),
            "the end-marker admits despite having no keyexpr"
        );
    }
}
