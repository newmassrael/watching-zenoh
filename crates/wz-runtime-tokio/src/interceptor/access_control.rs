// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! Governed actions, and as of R311y458 the SAME set zenoh governs: the
//! data-plane `Put` / `Del` (a Push or a write-Request body), the query plane
//! `Query` (a Request's Query body) / `Reply` (a Response) / `DeclareQueryable`,
//! the subscription plane `DeclareSubscriber`, and the liveliness plane
//! (`LivelinessToken`, plus a token-carrying `Interest` split on MODE into
//! `LivelinessQuery` and `DeclareLivelinessSubscriber`). Each (un)declare pair
//! shares ONE action, as upstream. What stays ungoverned — a keyexpr-alias
//! (un)declaration, `DeclareFinal`, the keyless `ResponseFinal`, an `Oam`, a
//! non-token or `Final` Interest — is ungoverned in zenoh too, in its
//! explicitly-unfiltered arms. Because the per-kind dispatch is a `match`,
//! adding an action is a new arm, not a new check site.

use std::any::Any;

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

/// One governed message kind's verdict inputs: the [`AclMessage`] a rule is
/// evaluated for, plus whether the kind is an UNDECLARE — the one bit the
/// unresolvable-keyexpr branch needs, because zenoh treats an undeclare
/// differently there and only on ingress (see [`AclInterceptor::intercept`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GovernedAction {
    action: AclMessage,
    undeclare: bool,
}

impl GovernedAction {
    /// A governed DECLARE-side (or data / query plane) kind.
    const fn decl(action: AclMessage) -> Self {
        Self {
            action,
            undeclare: false,
        }
    }

    /// A governed UNDECLARE kind, evaluated under the SAME action as its
    /// declaration — zenoh reuses one `AclMessage` for the pair rather than
    /// adding an undeclare action.
    const fn undecl(action: AclMessage) -> Self {
        Self {
            action,
            undeclare: true,
        }
    }
}

/// The ACL action a message represents, or `None` for a kind this enforcer does
/// not govern (which is then admitted). The wz analogue of zenoh's
/// per-`NetworkBody` dispatch in `access_control.rs::intercept`, and as of
/// R311y458 the same governed SET: the data plane (Push / write-Request bodies),
/// the query plane (Request(Query), Response, Declare/UndeclareQueryable), the
/// subscription plane (Declare/UndeclareSubscriber), and the liveliness plane
/// (Declare/UndeclareToken, plus a token-carrying `Interest` split on MODE).
///
/// Ungoverned, and therefore admitted at this arm before a keyexpr is ever
/// asked for: a keyexpr-alias (un)declaration, `DeclareFinal`, the keyless
/// `ResponseFinal`, an `Oam`, and any Interest that does not carry the token
/// flag — including the `Final` terminator, which zenoh also leaves unfiltered
/// (`access_control.rs:593-599` on ingress) because routing rejects it if the
/// Interest it closes was denied.
fn acl_action(msg: &NetworkMessage) -> Option<GovernedAction> {
    match msg {
        NetworkMessage::Push(p) => match &p.body {
            PushOwnedVariant::CodecZenohMsgPut(_) => Some(GovernedAction::decl(AclMessage::Put)),
            PushOwnedVariant::CodecZenohMsgDel(_) => Some(GovernedAction::decl(AclMessage::Delete)),
            _ => None,
        },
        // A routed Request maps by its body, the same as a Push: a Query body is
        // the query plane (governed as `Query`); a Put / Del body is a write
        // routed via the request mechanism (governed as the data-plane action).
        //
        // R311y458 CORRECTION — the Put / Del arms are NOT a zenoh mirror, as the
        // prose here used to imply. zenoh's `RequestBody` has exactly one variant,
        // `Query` (`zenoh-protocol/src/zenoh/mod.rs:79-81`), so its enforcer has
        // no Request-write arm to mirror. The wz codec's `RequestOwnedVariant`
        // does carry Put / Del, so these arms are a deliberate SUPERSET on the
        // deny side: a body zenoh's protocol cannot express is governed rather
        // than silently admitted if one ever arrives.
        NetworkMessage::Request(r) => match &r.body {
            RequestOwnedVariant::CodecZenohQuery(_) => {
                Some(GovernedAction::decl(AclMessage::Query))
            }
            RequestOwnedVariant::CodecZenohMsgPut(_) => Some(GovernedAction::decl(AclMessage::Put)),
            RequestOwnedVariant::CodecZenohMsgDel(_) => {
                Some(GovernedAction::decl(AclMessage::Delete))
            }
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
        NetworkMessage::Response(_) => Some(GovernedAction::decl(AclMessage::Reply)),
        // The six governed declaration bodies, each (un)declare pair sharing one
        // action exactly as zenoh pairs them (`access_control.rs:451-554`).
        NetworkMessage::Declare(d) => match &d.body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(_) => {
                Some(GovernedAction::decl(AclMessage::DeclareSubscriber))
            }
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(_) => {
                Some(GovernedAction::undecl(AclMessage::DeclareSubscriber))
            }
            DeclareOwnedVariant::CodecZenohDeclQueryable(_) => {
                Some(GovernedAction::decl(AclMessage::DeclareQueryable))
            }
            DeclareOwnedVariant::CodecZenohUndeclQueryable(_) => {
                Some(GovernedAction::undecl(AclMessage::DeclareQueryable))
            }
            DeclareOwnedVariant::CodecZenohDeclToken(_) => {
                Some(GovernedAction::decl(AclMessage::LivelinessToken))
            }
            DeclareOwnedVariant::CodecZenohUndeclToken(_) => {
                Some(GovernedAction::undecl(AclMessage::LivelinessToken))
            }
            _ => None,
        },
        // A TOKEN-carrying Interest, split on MODE and not on the flag: zenoh
        // gives CURRENT-only its own action (a one-shot liveliness GET) and
        // FUTURE / CURRENT+FUTURE another (registering for the token stream) —
        // `access_control.rs:557-591`. The mode lives in the outer header's C / F
        // bits (`zenoh-codec network/interest.rs:53-58`: Final 0b00, Current
        // 0b01, Future 0b10, CurrentFuture 0b11), the token flag in the body's
        // `to` bit. A Final Interest has NO body at all, so it takes the
        // no-token exit and is admitted here, which is zenoh's unfiltered arm.
        NetworkMessage::Interest(i) => {
            if !i.body.as_ref().is_some_and(|b| b.to()) {
                return None;
            }
            match (i.c(), i.f()) {
                (true, false) => Some(GovernedAction::decl(AclMessage::LivelinessQuery)),
                (_, true) => Some(GovernedAction::decl(
                    AclMessage::DeclareLivelinessSubscriber,
                )),
                (false, false) => None,
            }
        }
        _ => None,
    }
}

impl Interceptor for AclInterceptor {
    fn intercept(&self, ctx: &dyn InterceptorContext, msg: &NetworkMessage) -> bool {
        // A kind this atom does not govern is admitted (zenoh's unmatched arms).
        let Some(governed) = acl_action(msg) else {
            return true;
        };
        // No resolved subject -> the POLICY decides, not this function
        // (open-debt item 655, R2347). Until then the enforcer returned `true`
        // here, and that early exit was reachable by a peer's own choice: the zid
        // is captured verbatim from its INIT body
        // (`wz-session-core` `session_actions.rs:3836`, `:3872`, `:3879`) and
        // nothing on the way to the slot validates it, so a peer sending an
        // all-zero zid made `peer_zid_routing` answer `None` and exempted itself
        // from every rule -- a wildcard `SubjectSelector::Any` deny included.
        // `AclPolicy::decision` now takes the `Option`, where `Any` still matches
        // and a zid-targeted rule does not; a request matching no rule lands on
        // the configured default, which is where upstream's own
        // no-matched-subject path lands
        // (`zenoh/src/net/routing/interceptor/access_control.rs`
        // @ `let mut decision = policy_enforcer.default_permission`).
        let subject = ctx.subject();
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
        //
        // R311y458 — the ONE exception, and it is zenoh's, not a wz softening: an
        // INGRESS UNDECLARE admits instead. zenoh routes exactly those three arms
        // through `cached_result_or_action_undecl`, whose `None` keyexpr answers
        // `Permission::Allow` (:159-166), because an undeclare carries its
        // keyexpr only in the OPTIONAL `ext_wire_expr` and a peer that omits it
        // has its undeclare rejected by routing anyway if the matching
        // declaration was denied (:472-478). EGRESS has no such arm — there the
        // keyexpr is required and a miss denies (:762-776) — so the asymmetry is
        // keyed on the flow this enforcer was built for, which is why it lives
        // here and not in the resolver.
        let Some(keyexpr) = ctx.full_keyexpr(msg) else {
            return governed.undeclare && self.flow == AclFlow::Ingress;
        };
        self.policy.decision(
            subject.as_ref(),
            self.flow,
            governed.action,
            &keyexpr,
            ctx.link_subject(),
        ) == Permission::Allow
    }

    /// R311y508 (`routing-interceptor-hotreload`) — precompute this face's
    /// verdict for `keyexpr` under EVERY governed action, the wz mirror of
    /// zenoh's per-keyexpr `Cache` of per-`AclMessage` permissions
    /// (`net/routing/interceptor/access_control.rs:339-368` ingress, `:624`
    /// egress). Every input the policy reads other than the action is
    /// face-derived (subject, link subject) or the keyexpr itself, so the whole
    /// verdict table factors through (face, keyexpr) — which is what makes the
    /// ACL cacheable at all, and what a rate limiter is not.
    ///
    /// A face with no resolved subject caches NOTHING rather than caching its
    /// verdict: the subject can be resolved later on the same face, and the
    /// cached row would then outlive the reason for it. That is the one case
    /// where a cheap-looking cache would change a verdict instead of just saving
    /// work — and R2347 sharpened it rather than retiring it. Before item 655 the
    /// uncached verdict for such a face was a constant admit, so the row skipped
    /// here was only ever "true"; now [`AclPolicy::decision`] gives that face a
    /// REAL verdict off the wildcard rules, so the row would be a real answer to
    /// a question whose inputs are still in flux. Declining to cache is the same
    /// decision for a stronger reason.
    fn compute_keyexpr_cache(
        &self,
        ctx: &dyn InterceptorContext,
        keyexpr: &str,
    ) -> Option<Box<dyn Any>> {
        let subject = ctx.subject()?;
        let link = ctx.link_subject();
        let allow = |action: AclMessage| {
            self.policy
                .decision(Some(&subject), self.flow, action, keyexpr, link)
                == Permission::Allow
        };
        Some(Box::new(AclKeyexprCache {
            put: allow(AclMessage::Put),
            delete: allow(AclMessage::Delete),
            query: allow(AclMessage::Query),
            reply: allow(AclMessage::Reply),
            declare_subscriber: allow(AclMessage::DeclareSubscriber),
            declare_queryable: allow(AclMessage::DeclareQueryable),
            liveliness_token: allow(AclMessage::LivelinessToken),
            liveliness_query: allow(AclMessage::LivelinessQuery),
            declare_liveliness_subscriber: allow(AclMessage::DeclareLivelinessSubscriber),
        }))
    }

    /// The cached twin of [`Self::intercept`]. It MUST answer identically — the
    /// cache is an optimisation, never a semantic — so the two branches that do
    /// not factor through (face, keyexpr) are taken here exactly as they are
    /// there: an ungoverned kind admits, and a governed kind whose keyexpr does
    /// not resolve takes the undeclare-on-ingress branch. Only the final policy
    /// lookup is served from the table.
    fn intercept_cached(
        &self,
        ctx: &dyn InterceptorContext,
        msg: &NetworkMessage,
        cache: Option<&dyn Any>,
    ) -> bool {
        let Some(cached) = cache.and_then(|c| c.downcast_ref::<AclKeyexprCache>()) else {
            return self.intercept(ctx, msg);
        };
        let Some(governed) = acl_action(msg) else {
            return true;
        };
        // The cache is only ever built for a face WITH a subject
        // (`compute_keyexpr_cache` returns None otherwise), so reaching here
        // means the subject was resolved when it was built. Re-reading it would
        // be the message-derived read the cache contract forbids.
        if ctx.full_keyexpr(msg).is_none() {
            return governed.undeclare && self.flow == AclFlow::Ingress;
        }
        cached.allows(governed.action)
    }
}

/// R311y508 — one face's precomputed ACL verdicts for one keyexpr: the whole
/// governed action set, since the policy reads nothing else per message. The wz
/// analogue of zenoh's per-keyexpr `Cache` struct, which likewise carries one
/// field per `AclMessage` rather than a map — the action set is closed and
/// small, so a field read beats a hash.
struct AclKeyexprCache {
    put: bool,
    delete: bool,
    query: bool,
    reply: bool,
    declare_subscriber: bool,
    declare_queryable: bool,
    liveliness_token: bool,
    liveliness_query: bool,
    declare_liveliness_subscriber: bool,
}

impl AclKeyexprCache {
    /// The cached verdict for `action`. Exhaustive on purpose: a new
    /// [`AclMessage`] variant must fail to compile here rather than silently
    /// pick a neighbouring action's answer.
    fn allows(&self, action: AclMessage) -> bool {
        match action {
            AclMessage::Put => self.put,
            AclMessage::Delete => self.delete,
            AclMessage::Query => self.query,
            AclMessage::Reply => self.reply,
            AclMessage::DeclareSubscriber => self.declare_subscriber,
            AclMessage::DeclareQueryable => self.declare_queryable,
            AclMessage::LivelinessToken => self.liveliness_token,
            AclMessage::LivelinessQuery => self.liveliness_query,
            AclMessage::DeclareLivelinessSubscriber => self.declare_liveliness_subscriber,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashbrown::HashMap;
    use wz_access_control::{AclConfig, AclRule, SubjectSelector};
    use wz_routing_graph::Zid;
    use wz_session_core::declare_build::{
        build_declare_token, build_undeclare_subscriber, build_undeclare_subscriber_with_keyexpr,
        build_undeclare_token_with_keyexpr,
    };
    use wz_session_core::interest_build::{
        build_interest_final, build_interest_liveliness_get, build_interest_liveliness_subscriber,
    };
    use wz_session_core::link::{InterceptorLink, LinkSubject};
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
        /// R2347 (open-debt 655) — the LINK subject this face reports. It exists
        /// because item 655's fifth clause names the link axes as collateral of
        /// the same early exit: `link_protocols` / `interfaces` are read INSIDE
        /// `AclPolicy::decision`, so an enforcer that returned before calling it
        /// left them as unreachable as the zid axis. Leaving this at `None` (the
        /// trait default) cannot show that, because `None` matches every
        /// narrowed rule — the axis would look reached whether or not it was.
        link: Option<LinkSubject>,
    }

    impl MockCtx {
        /// A context attributing every message to `subject`, with an EMPTY alias
        /// table — the literal id-0 keyexprs the fixtures build resolve verbatim,
        /// and any aliased one is by construction undeclared.
        fn with_subject(subject: Option<Zid>) -> Self {
            Self {
                subject,
                aliases: HashMap::new(),
                link: None,
            }
        }

        /// The same context, reporting a RESOLVED link protocol — the one input
        /// shape that can tell "the link axis was evaluated" from "the link axis
        /// was skipped".
        fn with_link_protocol(subject: Option<Zid>, protocol: InterceptorLink) -> Self {
            Self {
                subject,
                aliases: HashMap::new(),
                link: Some(LinkSubject {
                    protocol: Some(protocol),
                    interfaces: None,
                }),
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
        fn link_subject(&self) -> Option<&LinkSubject> {
            self.link.as_ref()
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
        // Request(Put|Del)-body -> Put|Delete arms gate a Request-carried write
        // rather than admit it, but wz emits only Request(Query) today, so they
        // are not exercised here. R311y458 CORRECTION: they are a wz SUPERSET,
        // not the "faithful zenoh body-dispatch" this comment used to claim --
        // zenoh's RequestBody has only a Query variant.
        use wz_session_core::declare_build::build_declare_queryable;
        use wz_session_core::request_build::build_request_query;
        use wz_session_core::response_build::build_response_reply_literal;

        let query = NetworkMessage::Request(Box::new(
            build_request_query(1, 0, Some("demo/q")).expect("build query"),
        ));
        assert_eq!(
            acl_action(&query),
            Some(GovernedAction::decl(AclMessage::Query))
        );

        let reply = NetworkMessage::Response(Box::new(
            build_response_reply_literal(1, "demo/q", b"x").expect("build reply"),
        ));
        assert_eq!(
            acl_action(&reply),
            Some(GovernedAction::decl(AclMessage::Reply))
        );

        let decl_qabl = NetworkMessage::Declare(Box::new(
            build_declare_queryable(0, 0, Some("demo/q")).expect("build decl queryable"),
        ));
        assert_eq!(
            acl_action(&decl_qabl),
            Some(GovernedAction::decl(AclMessage::DeclareQueryable))
        );
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

    /// OPEN-DEBT 655 (R2347) — the enforcer-level twin of the router-level
    /// `a_malformed_zid_no_longer_escapes_the_egress_acl`. Until R2347 this
    /// asserted the opposite ("an unattributable message is admitted, not
    /// blocked"), and that sentence was the defect: `deny_admin_policy`'s rule is
    /// `SubjectSelector::Any`, so it never needed a subject to decide, yet the
    /// enforcer returned before reading it.
    #[test]
    fn a_message_with_no_subject_is_governed_by_a_wildcard_rule() {
        let acl = AclInterceptor::new(deny_admin_policy(), AclFlow::Ingress);
        let ctx = MockCtx::with_subject(None);
        let put = NetworkMessage::Push(Box::new(
            build_push_literal("admin/secret", b"x").expect("build"),
        ));
        assert!(
            !acl.intercept(&ctx, &put),
            "a rule that does not name a peer denies a message it cannot attribute"
        );
        // The control: the same unattributable face on a keyexpr the rule does
        // NOT cover is still admitted by the allow default. Without this, the
        // assertion above is equally explained by denying everything subjectless.
        let benign = NetworkMessage::Push(Box::new(
            build_push_literal("demo/data", b"x").expect("build"),
        ));
        assert!(
            acl.intercept(&ctx, &benign),
            "outside the rule, the allow default still carries an unattributable message"
        );
    }

    /// OPEN-DEBT 655 clause 5, the OTHER half (R2347) — the LINK axes were
    /// collateral of the same early exit, and closing the item means showing
    /// they are reached now, not only the zid axis.
    ///
    /// `link_protocols` / `interfaces` are read inside `AclPolicy::decision`, so
    /// an enforcer that returned `true` before calling it skipped them for every
    /// unattributable face — a rule narrowed to TCP could not stop a peer that
    /// had made itself unattributable, whatever it was speaking. The item said
    /// so and nothing measured it.
    ///
    /// Both directions are asserted, because one alone proves nothing: a rule
    /// narrowed to the protocol the face SPEAKS must deny it, and the same rule
    /// narrowed to a protocol it does not speak must NOT apply — which is what
    /// separates "the axis was evaluated" from "the axis was ignored and the
    /// rule matched on its other fields".
    #[test]
    fn an_unattributable_face_is_still_narrowed_by_the_link_axis() {
        let admin_deny_over = |protocol: InterceptorLink| {
            AclInterceptor::new(
                AclPolicy::new(AclConfig {
                    default_permission: Permission::Allow,
                    rules: vec![AclRule {
                        subject: SubjectSelector::Any,
                        key_exprs: vec!["admin/**".to_owned()],
                        messages: vec![AclMessage::Put],
                        flow: AclFlow::Ingress,
                        permission: Permission::Deny,
                        link_protocols: vec![protocol],
                        interfaces: Vec::new(),
                    }],
                }),
                AclFlow::Ingress,
            )
        };
        // The face speaks TCP and has NO resolved subject.
        let ctx = MockCtx::with_link_protocol(None, InterceptorLink::Tcp);
        let put = || {
            NetworkMessage::Push(Box::new(
                build_push_literal("admin/secret", b"x").expect("build"),
            ))
        };
        assert!(
            !admin_deny_over(InterceptorLink::Tcp).intercept(&ctx, &put()),
            "a rule narrowed to the protocol this face speaks reaches it, even \
             though the face has no attributable zid"
        );
        assert!(
            admin_deny_over(InterceptorLink::Udp).intercept(&ctx, &put()),
            "and a rule narrowed to a protocol it does NOT speak leaves it to \
             the allow default -- so the deny above is the link axis deciding, \
             not the keyexpr and action matching on their own"
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
            Some(GovernedAction::decl(AclMessage::Put)),
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
            link: None,
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
            link: None,
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
            Some(GovernedAction::decl(AclMessage::Reply)),
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

    /// The R311y458 policy: `admin/**` denied for the SIX actions this round
    /// added arms for, so a test can tell "denied by the rule" from "denied by
    /// the unresolvable-keyexpr branch" — the rule only ever fires on a keyexpr
    /// that RESOLVED.
    fn deny_admin_liveliness_policy() -> AclPolicy {
        AclPolicy::new(AclConfig {
            default_permission: Permission::Allow,
            rules: vec![AclRule {
                subject: SubjectSelector::Any,
                key_exprs: vec!["admin/**".to_owned()],
                messages: vec![
                    AclMessage::DeclareSubscriber,
                    AclMessage::DeclareQueryable,
                    AclMessage::LivelinessToken,
                    AclMessage::LivelinessQuery,
                    AclMessage::DeclareLivelinessSubscriber,
                ],
                flow: AclFlow::Ingress,
                permission: Permission::Deny,
                link_protocols: Vec::new(),
                interfaces: Vec::new(),
            }],
        })
    }

    #[test]
    fn an_undeclare_carrying_the_ext_keyexpr_is_judged_by_the_rule() {
        // UndeclareSubscriber is now GOVERNED, under the SAME action as its
        // declaration (zenoh reuses `DeclareSubscriber` for the pair). The
        // keyexpr is not inline — it rides the optional `ext_wire_expr`, so this
        // also proves the enforcer reads that extension and feeds it to the
        // policy. Both arms of the pair, so the deny is attributable to the rule.
        let acl = AclInterceptor::new(deny_admin_liveliness_policy(), AclFlow::Ingress);
        let ctx = MockCtx::with_subject(Some(Zid::from_slice(&[0x0A])));

        let denied = build_undeclare_subscriber_with_keyexpr("admin/secret").expect("build");
        let denied = NetworkMessage::Declare(Box::new(denied));
        assert_eq!(
            acl_action(&denied),
            Some(GovernedAction::undecl(AclMessage::DeclareSubscriber)),
            "precondition: an undeclare is governed under its declaration's action",
        );
        assert_eq!(
            ctx.full_keyexpr(&denied).as_deref(),
            Some("admin/secret"),
            "precondition: the ext_wire_expr is what supplies the keyexpr",
        );
        assert!(
            !acl.intercept(&ctx, &denied),
            "admin/** undeclare is denied"
        );

        let allowed = build_undeclare_subscriber_with_keyexpr("demo/data").expect("build");
        let allowed = NetworkMessage::Declare(Box::new(allowed));
        assert!(
            acl.intercept(&ctx, &allowed),
            "the same kind on an allowed keyexpr passes, so the deny is the RULE"
        );
    }

    #[test]
    fn an_ingress_undeclare_without_the_ext_keyexpr_admits() {
        // zenoh's DELIBERATE asymmetry, and the one exception to R311y457's
        // deny-on-unresolvable: an id-only undeclare carries no keyexpr at all,
        // and on INGRESS zenoh routes it through cached_result_or_action_undecl,
        // whose None arm answers Allow (:159-166). Routing rejects it anyway if
        // the declaration it retracts was denied.
        let acl = AclInterceptor::new(deny_admin_liveliness_policy(), AclFlow::Ingress);
        let ctx = MockCtx::with_subject(Some(Zid::from_slice(&[0x0A])));
        let undecl = NetworkMessage::Declare(Box::new(build_undeclare_subscriber(7)));
        assert_eq!(
            acl_action(&undecl),
            Some(GovernedAction::undecl(AclMessage::DeclareSubscriber)),
            "precondition: it IS governed, so it reaches the keyexpr branch",
        );
        assert_eq!(
            ctx.full_keyexpr(&undecl),
            None,
            "precondition: an id-only undeclare has no ext_wire_expr to resolve",
        );
        assert!(
            acl.intercept(&ctx, &undecl),
            "an ingress undeclare with no ext_wire_expr admits"
        );
    }

    #[test]
    fn an_egress_undeclare_without_the_ext_keyexpr_is_denied() {
        // The PAIR that makes the asymmetry real rather than a blanket softening
        // of R311y457: the SAME message through an EGRESS enforcer is denied,
        // because zenoh's egress undeclare arms take the ordinary
        // `else { return false }` (:762-776) and require the keyexpr. Only the
        // flow differs between this test and the one above.
        let acl = AclInterceptor::new(deny_admin_liveliness_policy(), AclFlow::Egress);
        let ctx = MockCtx::with_subject(Some(Zid::from_slice(&[0x0A])));
        let undecl = NetworkMessage::Declare(Box::new(build_undeclare_subscriber(7)));
        assert!(
            !acl.intercept(&ctx, &undecl),
            "an egress undeclare with no ext_wire_expr is denied"
        );
    }

    #[test]
    fn a_liveliness_token_declaration_is_governed() {
        // DeclareToken carries its keyexpr INLINE (like DeclareSubscriber) and is
        // governed as LivelinessToken; its undeclare shares the action.
        let acl = AclInterceptor::new(deny_admin_liveliness_policy(), AclFlow::Ingress);
        let ctx = MockCtx::with_subject(Some(Zid::from_slice(&[0x0A])));

        let denied = NetworkMessage::Declare(Box::new(
            build_declare_token(1, 0, Some("admin/secret")).expect("build decl token"),
        ));
        assert_eq!(
            acl_action(&denied),
            Some(GovernedAction::decl(AclMessage::LivelinessToken)),
        );
        assert!(!acl.intercept(&ctx, &denied), "admin/** token is denied");

        let allowed = NetworkMessage::Declare(Box::new(
            build_declare_token(1, 0, Some("demo/alive")).expect("build decl token"),
        ));
        assert!(
            acl.intercept(&ctx, &allowed),
            "demo/alive token is admitted"
        );

        let undecl = build_undeclare_token_with_keyexpr("admin/secret").expect("build");
        let undecl = NetworkMessage::Declare(Box::new(undecl));
        assert_eq!(
            acl_action(&undecl),
            Some(GovernedAction::undecl(AclMessage::LivelinessToken)),
            "the undeclare shares the declaration's action",
        );
        assert!(!acl.intercept(&ctx, &undecl), "admin/** untoken is denied");
    }

    #[test]
    fn a_token_interest_maps_on_its_mode_and_an_untokened_one_is_ungoverned() {
        // zenoh splits the Interest arms on MODE, not on the token flag: CURRENT
        // alone is a one-shot liveliness GET (LivelinessQuery), anything with
        // FUTURE is registering for the stream (DeclareLivelinessSubscriber), and
        // Final is unfiltered. The mode lives in the outer C / F header bits, so
        // this also pins that wz reads them from the right byte.
        let get = NetworkMessage::Interest(
            build_interest_liveliness_get(1, 0, Some("demo/alive")).expect("build get"),
        );
        assert_eq!(
            acl_action(&get),
            Some(GovernedAction::decl(AclMessage::LivelinessQuery)),
            "CURRENT-only is the one-shot GET",
        );

        let sub = NetworkMessage::Interest(
            build_interest_liveliness_subscriber(1, false, 0, Some("demo/alive"))
                .expect("build sub"),
        );
        assert_eq!(
            acl_action(&sub),
            Some(GovernedAction::decl(
                AclMessage::DeclareLivelinessSubscriber
            )),
            "FUTURE is the subscription",
        );

        let sub_hist = NetworkMessage::Interest(
            build_interest_liveliness_subscriber(1, true, 0, Some("demo/alive"))
                .expect("build sub"),
        );
        assert_eq!(
            acl_action(&sub_hist),
            Some(GovernedAction::decl(
                AclMessage::DeclareLivelinessSubscriber
            )),
            "CURRENT+FUTURE is still the subscription, not the GET",
        );

        let fin = NetworkMessage::Interest(build_interest_final(1));
        assert_eq!(
            acl_action(&fin),
            None,
            "the Final terminator is unfiltered, as in zenoh",
        );

        // The TOKEN flag is load-bearing on its own, separately from the mode: an
        // Interest that carries a keyexpr body but NOT the token bit is zenoh's
        // catch-all `Interest(_)` unfiltered arm. wz has no builder for one (all
        // three interest builders are liveliness), so this takes the FUTURE
        // subscription above and clears the body's `to` bit — same message,
        // one bit different — and asserts that precondition before the claim.
        let NetworkMessage::Interest(mut untokened) = NetworkMessage::Interest(
            build_interest_liveliness_subscriber(1, false, 0, Some("demo/alive"))
                .expect("build sub"),
        ) else {
            unreachable!("built as an Interest")
        };
        let body = untokened
            .body
            .as_mut()
            .expect("a FUTURE interest has a body");
        body.header &= !0x08;
        assert!(!body.to(), "precondition: the TOKENS bit is now clear");
        let untokened = NetworkMessage::Interest(untokened);
        assert_eq!(
            acl_action(&untokened),
            None,
            "a non-token Interest is ungoverned even though it carries a keyexpr",
        );
    }

    #[test]
    fn a_liveliness_get_on_a_denied_keyexpr_is_dropped() {
        // The Interest arm end-to-end, not just its mapping: the keyexpr comes
        // from the Interest BODY (which zenoh writes only for a non-Final mode),
        // so this proves the resolver reaches it and the rule adjudicates.
        let acl = AclInterceptor::new(deny_admin_liveliness_policy(), AclFlow::Ingress);
        let ctx = MockCtx::with_subject(Some(Zid::from_slice(&[0x0A])));
        let denied = NetworkMessage::Interest(
            build_interest_liveliness_get(1, 0, Some("admin/secret")).expect("build get"),
        );
        assert_eq!(
            ctx.full_keyexpr(&denied).as_deref(),
            Some("admin/secret"),
            "precondition: the keyexpr is read out of the Interest body",
        );
        assert!(
            !acl.intercept(&ctx, &denied),
            "admin/** liveliness GET denied"
        );

        let allowed = NetworkMessage::Interest(
            build_interest_liveliness_get(1, 0, Some("demo/alive")).expect("build get"),
        );
        assert!(
            acl.intercept(&ctx, &allowed),
            "demo/alive liveliness GET is admitted"
        );
    }

    /// R311y508 — THE CACHE CONTRACT: a cached answer must equal the answer
    /// [`AclInterceptor::intercept`] would have given. The cache is an
    /// optimisation, and the moment the two disagree it is a second, divergent
    /// policy engine instead.
    ///
    /// Every branch of `intercept` is represented, because the ones that do NOT
    /// factor through (face, keyexpr) are exactly where a cache is easy to get
    /// wrong: a denied Put, an admitted Put, an admitted Delete under a rule that
    /// denies it elsewhere, an UNGOVERNED kind that must never consult the table,
    /// and an ALIASED keyexpr the face never declared — which is denied on this
    /// flow and must stay denied rather than pick up a neighbouring cached
    /// verdict. The equality is asserted per message, so a failure names the
    /// shape that diverged.
    #[test]
    fn a_cached_verdict_equals_the_direct_one_on_every_branch() {
        let acl = AclInterceptor::new(deny_admin_policy(), AclFlow::Ingress);
        let ctx = MockCtx::with_subject(Some(Zid::from_slice(&[0x0A])));

        let cases: Vec<(&str, NetworkMessage)> = vec![
            (
                "denied put",
                NetworkMessage::Push(Box::new(
                    build_push_literal("admin/secret", b"x").expect("build push"),
                )),
            ),
            (
                "admitted put",
                NetworkMessage::Push(Box::new(
                    build_push_literal("demo/data", b"x").expect("build push"),
                )),
            ),
            (
                "denied delete",
                NetworkMessage::Push(Box::new(
                    build_push_del_literal("admin/secret").expect("build del"),
                )),
            ),
            (
                "ungoverned interest final",
                NetworkMessage::Interest(build_interest_final(1)),
            ),
            (
                "governed token declare",
                NetworkMessage::Declare(Box::new(
                    build_declare_token(1, 0, Some("admin/tok")).expect("build token"),
                )),
            ),
            (
                "undeclared alias",
                NetworkMessage::Push(Box::new(
                    build_push_aliased(7, Some(""), b"x").expect("build aliased push"),
                )),
            ),
        ];

        for (name, msg) in &cases {
            // The cache is computed per (face, keyexpr), so each message gets the
            // table for ITS keyexpr — which is how the forwarder keys it. A message
            // whose keyexpr does not resolve has no table, exactly as in production.
            let cache = ctx
                .full_keyexpr(msg)
                .and_then(|ke| acl.compute_keyexpr_cache(&ctx, &ke));
            assert_eq!(
                acl.intercept_cached(&ctx, msg, cache.as_deref()),
                acl.intercept(&ctx, msg),
                "cached and direct verdicts diverged for: {name}"
            );
        }
    }

    /// R311y508 — a face with NO resolved subject must cache nothing. The subject
    /// can resolve later on the same face, and a table computed while it was
    /// unknown would then outlive the verdict it was built under. This is the
    /// one input that is face-derived but NOT stable for the life of the face.
    ///
    /// R2347 (open-debt 655) kept the rule and rewrote its second half. The
    /// uncached verdict for such a face used to be a constant admit, so "no
    /// cache" and "admitted anyway" were the same observation; now the fallback
    /// runs the real policy, and what this pins is that the two paths AGREE —
    /// which is the actual cache contract, and is what the old wording could not
    /// distinguish from the enforcer simply not looking.
    #[test]
    fn a_subjectless_face_computes_no_cache() {
        let acl = AclInterceptor::new(deny_admin_policy(), AclFlow::Ingress);
        let ctx = MockCtx::with_subject(None);
        assert!(
            acl.compute_keyexpr_cache(&ctx, "admin/secret").is_none(),
            "no subject -> no cached verdict table"
        );
        let msg = NetworkMessage::Push(Box::new(
            build_push_literal("admin/secret", b"x").expect("build push"),
        ));
        assert!(
            !acl.intercept_cached(&ctx, &msg, None),
            "the cache-miss fallback is the direct path, which now denies this"
        );
        assert_eq!(
            acl.intercept_cached(&ctx, &msg, None),
            acl.intercept(&ctx, &msg),
            "cached and direct verdicts agree for a face that caches nothing"
        );
    }
}
