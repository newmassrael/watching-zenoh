// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Which keyexpr a §5.16 enforcer governs for a given message — the resolver
//! every [`InterceptorContext::full_keyexpr`](super::InterceptorContext::full_keyexpr)
//! implementation delegates to, and the readers that find a `Declare`'s keyexpr
//! in whichever field its body carries it.
//!
//! R2702 — these lived in `linkstate_forward.rs` until this round, and the move
//! is the point rather than tidying. The §5.16 module was gated
//! `#[cfg(feature = "routing-peer")]`, and this was the ONLY thing making that
//! gate true: nothing else under `interceptor/` names a routing type, but the
//! enforcer's own keyexpr resolver sat inside a routing module, so the seam
//! could not compile without one. `access-acl`'s residual has said for many
//! rounds that wz "gates the whole engine behind a routing build" while upstream
//! installs its interceptors with no mode branch
//! (`zenoh/src/net/routing/dispatcher/tables.rs` @ `interceptors: interceptor_factories(config)?`);
//! this file is where that stopped being true.
//!
//! The dependency direction is the one that was wrong before, not a new one. A
//! forwarder is a CONSUMER of the §5.16 seam — it holds the chains, builds them
//! and implements [`InterceptorSink`](super::InterceptorSink) — so a forwarder
//! importing the seam's resolver adds no edge, while the seam importing the
//! forwarder's was an edge from a thing to one of its own consumers.

use hashbrown::HashMap;

use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant};
use wz_codecs::wireexpr::WireexprOwned;
use wz_session_core::declare_ext_keyexpr::resolve_ext_keyexpr;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::wireexpr_resolve::resolve_wireexpr;

/// Resolve the GOVERNED keyexpr a §5.16 ACL enforcer gates for `msg`, alias-aware
/// against `keyexpr_table` — the SSOT every `InterceptorContext::full_keyexpr`
/// delegates to (one governed-kind match, not one per context). Push / Request /
/// Response carry the keyexpr inline; a Declare resolves through
/// [`declare_governed_keyexpr`]; an `Interest` carries it in its (mode != Final)
/// body; any other kind — an alias declaration, the keyless `ResponseFinal`, an
/// `Oam` — carries no governed keyexpr and answers `None`.
///
/// `None` is NOT an admit verdict: an ungoverned kind admits because
/// [`acl_action`](super::access_control) returns no action for it,
/// BEFORE the enforcer asks for a keyexpr at all — a governed kind that lands
/// here on `None` (an undeclared expr-id, or the empty wireexpr of a synthesized
/// timeout `Err`) is DENIED, as in every governed zenoh arm. The ONE exception is
/// an INGRESS undeclare, which zenoh deliberately admits when its `ext_wire_expr`
/// is unset; the enforcer owns that asymmetry, not this resolver, because it
/// depends on the flow. Adding a new governed kind is a ONE-place edit here.
pub(crate) fn resolve_governed_keyexpr(
    msg: &NetworkMessage,
    keyexpr_table: &HashMap<u64, String>,
) -> Option<String> {
    match msg {
        NetworkMessage::Push(p) => resolve_wireexpr(&p.keyexpr.body, keyexpr_table),
        NetworkMessage::Request(r) => resolve_wireexpr(&r.keyexpr.body, keyexpr_table),
        NetworkMessage::Response(r) => resolve_wireexpr(&r.keyexpr.body, keyexpr_table),
        NetworkMessage::Declare(d) => declare_governed_keyexpr(d, keyexpr_table),
        // An Interest carries its keyexpr in the body zenoh writes only when the
        // mode is not Final (`zenoh-codec network/interest.rs:69-73`), so a Final
        // Interest answers `None` here — and is ungoverned at the action arm, the
        // same place zenoh leaves it unfiltered.
        NetworkMessage::Interest(i) => i
            .body
            .as_ref()
            .and_then(|b| b.keyexpr.as_ref())
            .and_then(|we| resolve_wireexpr(&we.body, keyexpr_table)),
        _ => None,
    }
}

/// The governed keyexpr of a `Declare`, alias-resolved — the Declare half of
/// [`resolve_governed_keyexpr`], split out because the six governed declaration
/// bodies carry their keyexpr in TWO different places.
///
/// `DeclareSubscriber` / `DeclareQueryable` / `DeclareToken` carry it INLINE. The
/// three undeclares carry only `{ id }` on the wire, so zenoh puts the keyexpr in
/// the optional `ext_wire_expr` extension (`UndeclareSubscriber { id,
/// ext_wire_expr }`) — read here through the same
/// [`resolve_ext_keyexpr`](wz_session_core::declare_ext_keyexpr::resolve_ext_keyexpr)
/// SSOT the forwarders' undeclare ingest already uses. An undeclare whose peer
/// omitted that extension answers `None`, which is not a resolution FAILURE but
/// an absent field: on ingress the enforcer admits it (zenoh's deliberate
/// asymmetry, `access_control.rs:472-485`), on egress it denies (`:762-776`).
fn declare_governed_keyexpr(
    declare: &DeclareOwned,
    keyexpr_table: &HashMap<u64, String>,
) -> Option<String> {
    if let Some(we) = declare_subscriber_wireexpr(declare)
        .or_else(|| declare_queryable_wireexpr(declare))
        .or_else(|| declare_token_wireexpr(declare))
    {
        return resolve_wireexpr(&we.body, keyexpr_table);
    }
    let exts = match &declare.body {
        DeclareOwnedVariant::CodecZenohUndeclSubscriber(u) => u.extensions.as_ref(),
        DeclareOwnedVariant::CodecZenohUndeclQueryable(u) => u.extensions.as_ref(),
        DeclareOwnedVariant::CodecZenohUndeclToken(u) => u.extensions.as_ref(),
        _ => return None,
    };
    resolve_ext_keyexpr(exts, keyexpr_table)
}

/// The keyexpr `Wireexpr` a `DeclareSubscriber` declares interest in — `None` for
/// a non-subscriber Declare body. Returns the raw `Wireexpr` (literal OR aliased)
/// so the caller resolves it against the inbound face's alias table (B1b), rather
/// than a pre-resolved literal string.
pub(crate) fn declare_subscriber_wireexpr(declare: &DeclareOwned) -> Option<&WireexprOwned> {
    match &declare.body {
        DeclareOwnedVariant::CodecZenohDeclSubscriber(sub) => Some(&sub.keyexpr),
        _ => None,
    }
}

/// The keyexpr `Wireexpr` a `DeclareQueryable` declares interest in — `None` for
/// a non-queryable Declare body. The query-plane twin of
/// [`declare_subscriber_wireexpr`]; returns the raw `Wireexpr` (literal OR
/// aliased) so the caller resolves it against the inbound face's alias table
/// (B1b), exactly as the subscriber side.
pub(crate) fn declare_queryable_wireexpr(declare: &DeclareOwned) -> Option<&WireexprOwned> {
    match &declare.body {
        DeclareOwnedVariant::CodecZenohDeclQueryable(q) => Some(&q.keyexpr),
        _ => None,
    }
}

/// The keyexpr `Wireexpr` a `DeclareToken` declares a liveliness token for —
/// `None` for a non-token Declare body. The liveliness-token twin of
/// [`declare_subscriber_wireexpr`]; the `DeclareToken` carries its keyexpr
/// inline (like `DeclareSubscriber`), returned raw (literal OR aliased) so the
/// caller resolves it against the inbound face's alias table (B1b).
///
/// R311y458 dropped the `routing-token-tables` gate: [`resolve_governed_keyexpr`]
/// calls it on every build that compiles this module, so it is no longer dead
/// code without that feature and gating it would only cfg the §5.16 liveliness
/// arms out of builds that do enforce them.
pub(crate) fn declare_token_wireexpr(declare: &DeclareOwned) -> Option<&WireexprOwned> {
    match &declare.body {
        DeclareOwnedVariant::CodecZenohDeclToken(t) => Some(&t.keyexpr),
        _ => None,
    }
}
