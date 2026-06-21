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
//! Governed actions: the data-plane `Put` / `Del` (a Push body) and the
//! control-plane `DeclareSubscriber`. Every other kind — the rest of the
//! `Declare` family, `Query` / `Reply`, the liveliness messages — is admitted
//! here and gains its own arm as the action set grows. Because the per-kind
//! dispatch is a `match`, adding an action is a new arm, not a new check site.

use wz_access_control::{AclFlow, AclMessage, AclPolicy, Permission};
use wz_codecs::declare::DeclareOwnedVariant;
use wz_codecs::push::PushOwnedVariant;
use wz_session_core::network_message::NetworkMessage;

use super::{Interceptor, InterceptorContext};

/// An access-control enforcer for one flow — the wz mirror of zenoh's
/// `IngressAclEnforcer` / `EgressAclEnforcer`. Holds the (shared) compiled
/// [`AclPolicy`] and the flow it enforces. The first atom installs one of these
/// with [`AclFlow::Ingress`].
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
/// per-`NetworkBody` dispatch in `access_control.rs::intercept`: a Push maps to
/// [`Put`](AclMessage::Put) / [`Delete`](AclMessage::Delete) on its body, and a
/// `DeclareSubscriber` maps to [`DeclareSubscriber`](AclMessage::DeclareSubscriber);
/// an UndeclareSubscriber / keyexpr-alias declaration, `Query` / `Reply`, and the
/// liveliness kinds are not governed yet, so they return `None` and admit.
fn acl_action(msg: &NetworkMessage) -> Option<AclMessage> {
    match msg {
        NetworkMessage::Push(p) => match &p.body {
            PushOwnedVariant::CodecZenohMsgPut(_) => Some(AclMessage::Put),
            PushOwnedVariant::CodecZenohMsgDel(_) => Some(AclMessage::Delete),
            _ => None,
        },
        NetworkMessage::Declare(d)
            if matches!(d.body, DeclareOwnedVariant::CodecZenohDeclSubscriber(_)) =>
        {
            Some(AclMessage::DeclareSubscriber)
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
        // An unresolvable keyexpr (an undeclared alias) would drop in routing
        // anyway; admit and let the routing path handle it.
        let Some(keyexpr) = ctx.full_keyexpr(msg) else {
            return true;
        };
        self.policy.decision(&subject, self.flow, action, &keyexpr) == Permission::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashbrown::HashMap;
    use wz_access_control::{AclConfig, AclRule, SubjectSelector};
    use wz_routing_graph::Zid;
    use wz_session_core::push_build::{build_push_del_literal, build_push_literal};
    use wz_session_core::wireexpr_resolve::resolve_wireexpr;

    /// A context that hands back a fixed subject and resolves a Push keyexpr
    /// through the SAME [`resolve_wireexpr`] SSOT the forwarder's real
    /// `IngressContext` uses (an empty alias table — the test pushes are literal
    /// id-0 keyexprs).
    struct MockCtx {
        subject: Option<Zid>,
    }

    impl InterceptorContext for MockCtx {
        fn subject(&self) -> Option<Zid> {
            self.subject
        }
        fn full_keyexpr(&self, msg: &NetworkMessage) -> Option<String> {
            match msg {
                NetworkMessage::Push(p) => resolve_wireexpr(&p.keyexpr.body, &HashMap::new()),
                _ => None,
            }
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
            }],
        })
    }

    #[test]
    fn a_denied_put_is_dropped() {
        let acl = AclInterceptor::new(deny_admin_policy(), AclFlow::Ingress);
        let ctx = MockCtx {
            subject: Some(Zid::from_slice(&[0x0A])),
        };
        let put = NetworkMessage::Push(Box::new(
            build_push_literal("admin/secret", b"x").expect("build"),
        ));
        assert!(!acl.intercept(&ctx, &put), "admin/secret Put is denied");
    }

    #[test]
    fn an_admitted_put_passes() {
        let acl = AclInterceptor::new(deny_admin_policy(), AclFlow::Ingress);
        let ctx = MockCtx {
            subject: Some(Zid::from_slice(&[0x0A])),
        };
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
        let ctx = MockCtx {
            subject: Some(Zid::from_slice(&[0x0A])),
        };
        let del = NetworkMessage::Push(Box::new(
            build_push_del_literal("admin/secret").expect("build"),
        ));
        assert!(!acl.intercept(&ctx, &del), "admin/secret Del is denied");
    }

    #[test]
    fn a_message_with_no_subject_is_admitted() {
        let acl = AclInterceptor::new(deny_admin_policy(), AclFlow::Ingress);
        let ctx = MockCtx { subject: None };
        let put = NetworkMessage::Push(Box::new(
            build_push_literal("admin/secret", b"x").expect("build"),
        ));
        assert!(
            acl.intercept(&ctx, &put),
            "an unattributable message is admitted, not blocked"
        );
    }
}
