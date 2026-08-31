// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.21 routing-namespace — the per-participant keyexpr namespace decorator,
//! the wz mirror of zenoh's `net/routing/namespace.rs` `Namespace` (egress) +
//! `ENamespace` (ingress) `Primitives`/`EPrimitives` decorator pair.
//!
//! A session configured with a non-wild `namespace` prefix publishes/declares
//! and receives keyexprs RELATIVE to that prefix: the application names bare
//! keyexprs (`foo/bar`) and the namespace (`myns`) is applied transparently —
//! `myns/foo/bar` on the wire, `foo/bar` to the app. zenoh installs the
//! decorator on the SESSION's own face at open (`api/session.rs:689-696`); wz
//! has no single `Primitives` trait, so the two halves are applied at the
//! participant's local-origin / local-delivery boundaries instead (see
//! [`apply_egress`] / [`NamespaceIngress`]). EGRESS is structurally safe against
//! the router forwarder: a relay is emitted through the shared
//! `SessionLinkActions::send_network_message` floor DIRECTLY, below the
//! per-participant egress seams, so it is never re-namespaced. INGRESS, however,
//! strips BEFORE the drive loop's `on_event` (which feeds the forwarder), so a
//! namespaced FORWARDING face would relay the already-stripped (relative)
//! keyexpr — i.e. the real safety invariant is that a namespaced face is NEVER a
//! forwarder face: `set_namespace` is reachable only from the client-open
//! helpers, and the router/peer face path never installs a namespace. Wiring the
//! multihat router (a future atom) must re-examine this strip-vs-forward ordering
//! before that invariant can be lifted.
//!
//! ## Egress ([`apply_egress`], the `Namespace` mirror)
//! Prepend the namespace to a LITERAL (`id == 0`) keyexpr, and to a
//! `DeclareKeyExpr` alias DEFINITION (always — the namespace must be baked into
//! the alias). An ALIASED (`id != 0`) non-`DeclareKeyExpr` use passes through:
//! its alias was already namespaced when its `DeclareKeyExpr` was sent. Mirrors
//! `handle_namespace_egress` (`namespace.rs:45-56`) +
//! `handle_declare_egress` (`namespace.rs:58-80`). `ResponseFinal` / undeclare-
//! keyexpr are left untouched, exactly as zenoh.
//!
//! ## Ingress ([`NamespaceIngress`], the `ENamespace` mirror — STATEFUL)
//! Strip the namespace from a literal inbound keyexpr; DROP a message whose
//! keyexpr is not under the namespace. Statefully (per zenoh `ENamespace`):
//! - `blocked_{subscribers,queryables,tokens,interests}` — the id of a DROPPED
//!   `Declare*` is remembered so its later id-only `Undeclare*` (wz undeclare
//!   bodies carry NO keyexpr) is also dropped, instead of leaking a phantom
//!   undeclare for an entity the local registry never saw declared.
//! - `incomplete` — a `DeclareKeyExpr` whose definition does not (yet) match
//!   the namespace is stored by id; a later aliased reference to it is
//!   reconstructed (`head + suffix`) and re-validated, and its `UndeclareKeyExpr`
//!   is correlated. Mirrors `incomplete_ingress_keyexpr_declarations`
//!   (`namespace.rs:127,150-188`).
//!
//! ## Mapping (Local/Nonlocal ↔ Sender/Receiver)
//! wz's wireexpr locality is the wire's `M` bit (`declare_build.rs:382-388`):
//! `WireexprLocal` (M=1) = rooted in the SENDER's own table = zenoh
//! `Mapping::Sender` (=1); `WireexprNonlocal` (M=0) = rooted in the receiver's
//! table = zenoh `Mapping::Receiver` (=0). The ingress strip-once branch keys
//! off this exactly as zenoh `handle_namespace_ingress` (`namespace.rs:150-188`):
//! a Receiver(Nonlocal)-mapped alias references OUR (already-relative) table and
//! passes through unstripped; only a Sender(Local)-mapped alias consults the
//! `incomplete` reconstruction path.
//!
//! @verbatim is treated as ordinary throughout (the [`crate::keyexpr_prefix`]
//! strip is @-blind, consistent with the rest of the wz keyexpr stack).

use alloc::string::{String, ToString as _};

use hashbrown::{HashMap, HashSet};
use sce_forge_runtime::codec::CodecError;

use crate::driver_loop::DriverLoopOutcome;
use crate::keyexpr_prefix::{strip_nonwild_prefix, OwnedNonWildKeyExpr};
use crate::network_message::NetworkMessage;
use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};

/// The Interest outer-header `C` (Current) / `F` (Future) mode bits
/// (`interest_build.rs:43-44`). `Final` is `C == 0 && F == 0` — no enum exists,
/// so the mode is read off these bits.
const INTEREST_C: u8 = 0x20;
const INTEREST_F: u8 = 0x40;

/// R2220 — the interest BODY header's `M` bit: the wireexpr mapping the sender
/// used, `1` = Local (Sender-mapped). `interest_body.scxml` declares it
/// (`<sce:flag name="M" bit="6"/>`) and zenoh-pico's `_z_interest_encode` sets
/// it from `_z_wireexpr_is_local`; it is read here because the generated decoder
/// does not dispatch the wireexpr variant on it — see
/// [`NamespaceIngress::strip_mapped`].
///
/// Distinct byte from [`INTEREST_C`] / [`INTEREST_F`], which are the OUTER
/// interest header's mode bits. Same numeric value as `INTEREST_F` and a
/// different field: naming it separately is what stops the two being confused.
const INTEREST_BODY_M: u8 = 0x40;

/// Read `(id, suffix)` from a wireexpr regardless of Local/Nonlocal arm.
fn id_suffix(we: &WireexprOwned) -> (u64, Option<&str>) {
    match &we.body {
        WireexprOwnedVariant::WireexprLocal(a) => (a.id, a.suffix.as_deref()),
        WireexprOwnedVariant::WireexprNonlocal(a) => (a.id, a.suffix.as_deref()),
    }
}

/// `true` iff the wireexpr is Sender-mapped (Local arm, M=1). Receiver-mapped
/// (Nonlocal, M=0) references the receiver's own already-relative table.
fn is_sender_mapped(we: &WireexprOwned) -> bool {
    matches!(&we.body, WireexprOwnedVariant::WireexprLocal(_))
}

/// Overwrite a wireexpr to the LITERAL `suffix` (id forced to 0), keeping its
/// Local/Nonlocal arm. The keyexpr's suffix was already PRESENT (we only ever
/// rewrite a keyexpr that carried a literal suffix), so no owning-message
/// suffix-presence flag needs touching.
fn set_literal_suffix(we: &mut WireexprOwned, suffix: String) -> Result<(), CodecError> {
    let sce = crate::codec_owned::owned_string::<128>(&suffix)?;
    let len = suffix.len() as u64;
    match &mut we.body {
        WireexprOwnedVariant::WireexprLocal(a) => {
            a.id = 0;
            a.suffix_len = Some(len);
            a.suffix = Some(sce);
        }
        WireexprOwnedVariant::WireexprNonlocal(a) => {
            a.id = 0;
            a.suffix_len = Some(len);
            a.suffix = Some(sce);
        }
    }
    Ok(())
}

// ─────────────────────────── Egress (Namespace) ───────────────────────────

/// Apply the namespace prefix to an OUTBOUND message originated by this
/// participant — the `Namespace` egress decorator. Idempotent-safe: only a
/// literal (`id == 0`) keyexpr or a `DeclareKeyExpr` definition is rewritten;
/// an aliased use passes through unchanged.
pub fn apply_egress(ns: &OwnedNonWildKeyExpr, msg: &mut NetworkMessage) -> Result<(), CodecError> {
    match msg {
        #[cfg(feature = "codec-push")]
        NetworkMessage::Push(p) => apply_egress_push(ns, p)?,
        #[cfg(feature = "codec-request")]
        NetworkMessage::Request(r) => {
            if let Some(new) = literal_prefix(ns, &r.keyexpr) {
                crate::request_build::set_request_keyexpr_literal(r, &new)?;
            }
        }
        #[cfg(feature = "codec-response")]
        NetworkMessage::Response(r) => apply_egress_response(ns, r)?,
        NetworkMessage::Interest(i) => apply_egress_interest(ns, i)?,
        #[cfg(feature = "codec-declare")]
        NetworkMessage::Declare(d) => apply_egress_declare(ns, d)?,
        // R2220 — the no-keyexpr messages, named rather than caught. `Oam` is a
        // control envelope upstream's `Primitives` has no method for at all;
        // `ResponseFinal` is a bare request-id and upstream leaves it
        // undecorated on purpose (`send_response_final` forwards untouched,
        // zenoh `net/routing/namespace.rs:111-113`); `Unknown` is a MID this
        // build cannot decode, so it holds bytes and no field to reach. Written
        // out so a new `NetworkMessage` variant is a COMPILE ERROR here rather
        // than a message that quietly leaves undecorated.
        #[cfg(feature = "codec-response-final")]
        NetworkMessage::ResponseFinal(_) => {}
        NetworkMessage::Oam(_) => {}
        NetworkMessage::Unknown { .. } => {}
    }
    Ok(())
}

/// The Push (`z_put` / `z_del`) egress rule — the SSOT for the
/// `NetworkMessage::Push` arm of [`apply_egress`] AND the multicast TX-item
/// dispatcher ([`apply_egress_multicast_item`]), which decorates the boxed
/// `Push` of a [`MulticastTxItem`](crate::multicast_tx::MulticastTxItem) at the
/// AP multicast drive loop's outbound chokepoint. Prefixes a LITERAL push
/// keyexpr; an aliased one (already namespaced at its declaration) passes
/// through. zenoh decorates `send_push` (`net/routing/namespace.rs:96`).
#[cfg(feature = "codec-push")]
pub fn apply_egress_push(
    ns: &OwnedNonWildKeyExpr,
    p: &mut wz_codecs::push::PushOwned,
) -> Result<(), CodecError> {
    if let Some(new) = literal_prefix(ns, &p.keyexpr) {
        crate::push_build::set_push_keyexpr_literal(p, &new)?;
    }
    Ok(())
}

/// The Response (query-reply) egress rule — the single SSOT for the
/// `NetworkMessage::Response` arm of [`apply_egress`] AND the dedicated reply
/// emit path ([`crate::session_actions`]'s `send_response`). Query replies do
/// NOT traverse the `send_network_message` floor (they flush through a separate
/// `dispatch_response` seam), so the decorator must hook there too; factoring
/// the rule here keeps both call sites byte-identical. zenoh decorates
/// `send_response` (`net/routing/namespace.rs:106-109`).
#[cfg(feature = "codec-response")]
pub fn apply_egress_response(
    ns: &OwnedNonWildKeyExpr,
    r: &mut wz_codecs::response::ResponseOwned,
) -> Result<(), CodecError> {
    if let Some(new) = literal_prefix(ns, &r.keyexpr) {
        crate::response_build::set_response_keyexpr_literal(r, &new)?;
    }
    Ok(())
}

/// The Interest egress rule — the SSOT for the `NetworkMessage::Interest` arm of
/// [`apply_egress`] AND the reconnect declaration replay
/// ([`crate::session_actions`]'s `replay_*`), which re-emits cached liveliness
/// interests via a direct `dispatch_interest` that bypasses the
/// `send_network_message` egress arm. Prefixes a LITERAL interest keyexpr; an
/// aliased one (already namespaced at its declaration) or a keyexpr-less
/// interest is left untouched.
pub fn apply_egress_interest(
    ns: &OwnedNonWildKeyExpr,
    i: &mut wz_codecs::interest::InterestOwned,
) -> Result<(), CodecError> {
    if let Some(we) = i.body.as_mut().and_then(|b| b.keyexpr.as_mut()) {
        if let Some(new) = literal_prefix(ns, we) {
            set_literal_suffix(we, new)?;
        }
    }
    Ok(())
}

/// The literal-prefix egress rule: `Some(<ns>/<suffix>)` when the keyexpr is a
/// literal (`id == 0`), else `None` (an aliased use already carries the
/// namespace from its declaration). zenoh `handle_namespace_egress(.., false)`.
fn literal_prefix(ns: &OwnedNonWildKeyExpr, we: &WireexprOwned) -> Option<String> {
    let (id, suffix) = id_suffix(we);
    if id == 0 {
        Some(ns.prepend(suffix.unwrap_or("")))
    } else {
        None
    }
}

/// The Declare egress rule — the SSOT for the `NetworkMessage::Declare` arm of
/// [`apply_egress`] AND the reconnect declaration replay
/// ([`crate::session_actions`]'s `replay_*`), which re-emits cached declares via
/// a direct `dispatch_declare` that bypasses the `send_network_message` egress
/// arm (the cache holds the BARE keyexpr, so the replayed declare must be
/// re-decorated here). zenoh `handle_declare_egress`.
#[cfg(feature = "codec-declare")]
pub fn apply_egress_declare(
    ns: &OwnedNonWildKeyExpr,
    d: &mut wz_codecs::declare::DeclareOwned,
) -> Result<(), CodecError> {
    use wz_codecs::declare::DeclareOwnedVariant as DV;
    match &mut d.body {
        // DeclareKeyExpr definition: ALWAYS prepend (new_keyexpr_declare=true) —
        // the namespace must be baked into the alias so every later aliased use
        // is already relative. wz's DeclKexpr definition is a literal (id==0,
        // declare_build.rs:402-404), so forcing id=0 in set_literal_suffix is a
        // no-op on the real shape.
        DV::CodecZenohDeclKexpr(m) => {
            let (_id, suffix) = id_suffix(&m.keyexpr);
            let new = ns.prepend(suffix.unwrap_or(""));
            set_literal_suffix(&mut m.keyexpr, new)?;
        }
        DV::CodecZenohDeclSubscriber(m) => {
            if let Some(new) = literal_prefix(ns, &m.keyexpr) {
                set_literal_suffix(&mut m.keyexpr, new)?;
            }
        }
        DV::CodecZenohDeclQueryable(m) => {
            if let Some(new) = literal_prefix(ns, &m.keyexpr) {
                set_literal_suffix(&mut m.keyexpr, new)?;
            }
        }
        DV::CodecZenohDeclToken(m) => {
            if let Some(new) = literal_prefix(ns, &m.keyexpr) {
                set_literal_suffix(&mut m.keyexpr, new)?;
            }
        }
        // R2220 — THE ONE ARM UPSTREAM HAS THAT THIS MATCH DID NOT. zenoh
        // decorates the retracted keyexpr a SOURCED `UndeclareQueryable` carries
        // in its `ext_wire_expr`
        // (`handle_namespace_egress(&mut m.ext_wire_expr.wire_expr, false)`,
        // zenoh `net/routing/namespace.rs:71-73`), and this match reached it
        // through a `_ => {}` whose comment said "Undeclares carry only an id
        // (no keyexpr)". That sentence is FALSE of this tree: three builders
        // put a LITERAL keyexpr in exactly this extension
        // (`declare_build::build_undeclare_{subscriber,queryable,token}_with_keyexpr`).
        DV::CodecZenohUndeclQueryable(m) => {
            // Read then write: `read_ext_keyexpr` borrows out of the extension
            // it is about to be replaced in.
            let literal = crate::declare_ext_keyexpr::read_ext_keyexpr(m.extensions.as_ref())
                .map(String::from);
            if let (Some(literal), Some(exts)) = (literal, m.extensions.as_mut()) {
                let prefixed = ns.prepend(&literal);
                crate::declare_ext_keyexpr::set_ext_keyexpr_literal(exts, &prefixed)?;
            }
        }
        // ⚠ THE ASYMMETRY IS UPSTREAM'S, and these arms are written out rather
        // than folded into a catch-all so that reading it is unavoidable.
        // `UndeclareSubscriber` and `UndeclareToken` carry the same
        // `ext_wire_expr` field upstream does, and upstream decorates NEITHER —
        // `DeclareBody::UndeclareSubscriber(_) => {}` and
        // `DeclareBody::UndeclareToken(_) => {}` (`namespace.rs:67, 79`), beside
        // the queryable arm that does. Matching it is not an endorsement: a
        // drop-in replacement is judged on the bytes it puts on the wire, and
        // decorating here would hand a stock zenoh peer a keyexpr its own
        // `ENamespace` does not strip (that ingress reads no extension at all).
        DV::CodecZenohUndeclSubscriber(_) | DV::CodecZenohUndeclToken(_) => {}
        // No keyexpr anywhere in the body: `UndeclareKeyExpr` is an id
        // (`namespace.rs:65`), `DeclareFinal` is empty (`:80`), and `Default` is
        // a MID this build does not name, which by definition has no field this
        // decorator could reach.
        DV::CodecZenohUndeclKexpr(_) | DV::CodecZenohDeclFinal(_) | DV::Default { .. } => {}
    }
    Ok(())
}

/// §5.21 routing-namespace — the MULTICAST egress decorator: apply the
/// namespace to one queued [`MulticastTxItem`](crate::multicast_tx::MulticastTxItem)
/// at the AP multicast drive loop's SINGLE outbound chokepoint (the
/// `outbound`-channel dequeue). Every multicast TX item is LOCAL-ORIGIN — the
/// publish `Push` and the reply-plane `Response` / `ResponseFinal` /
/// `DeclareReply` all funnel through the one outbound channel, and there is NO
/// relay path onto it (multicast is handshake-free with no multihat forwarder
/// TODAY) — so decorating at the dequeue is safe, UNLIKE unicast which must
/// decorate ABOVE the shared `send_network_message` floor to avoid
/// re-namespacing a router relay ([`apply_egress`] doc; the floor-below relay
/// is the unicast invariant). INVARIANT for the future `router-hat-multihat`
/// atom: when a multicast forwarder is added, a relayed (non-local-origin) item
/// must NOT be re-namespaced here — re-examine this seam (decorate-above, or tag
/// relays) before relaying through the decorated dequeue. The `match` below is
/// EXHAUSTIVE (no `_ =>`) so a new relay/alias-carrying `MulticastTxItem` variant
/// forces that review at compile time.
///
/// Dispatches each variant to the EXISTING per-message egress rule SSOT (zero
/// rule duplication): Push -> [`apply_egress_push`], Response ->
/// [`apply_egress_response`], DeclareReply -> [`apply_egress_declare`]
/// (`liveliness-token` implies `codec-declare`, so the declare egress is always
/// available here). `ResponseFinal` carries no keyexpr — left untouched, exactly
/// as zenoh leaves `send_response_final` undecorated (`namespace.rs:111-113`).
#[cfg(all(
    feature = "session-multicast",
    feature = "codec-frame",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
pub fn apply_egress_multicast_item(
    ns: &OwnedNonWildKeyExpr,
    item: &mut crate::multicast_tx::MulticastTxItem,
) -> Result<(), CodecError> {
    use crate::multicast_tx::MulticastTxItem as Item;
    match item {
        #[cfg(feature = "codec-push")]
        Item::Push { push, .. } => apply_egress_push(ns, push)?,
        #[cfg(feature = "codec-response")]
        Item::Response { response } => apply_egress_response(ns, response)?,
        // ResponseFinal is a bare request-id with no keyexpr — nothing to
        // namespace (zenoh leaves send_response_final undecorated).
        #[cfg(feature = "codec-response-final")]
        Item::ResponseFinal { .. } => {}
        #[cfg(feature = "liveliness-token")]
        Item::DeclareReply { declare } => apply_egress_declare(ns, declare)?,
    }
    Ok(())
}

// ───────────────────────── Ingress (ENamespace) ──────────────────────────

/// Stateful per-participant namespace INGRESS decorator — the `ENamespace`
/// mirror. Strips the namespace from inbound keyexprs and drops messages not
/// under the namespace, correlating id-only undeclares against the declares it
/// dropped. One instance per session (the same lifetime as the session's
/// `peer_keyexpr_table`); not `Clone` (it owns mutation-correlation state).
#[derive(Debug)]
pub struct NamespaceIngress {
    namespace: OwnedNonWildKeyExpr,
    // The Declare* blocked-id sets are consumed only by `declare_ingress`, so
    // they are `codec-declare`-gated — a namespace build without the declare
    // plane (e.g. a pure-pubsub data path) carries no dead correlation state.
    #[cfg(feature = "codec-declare")]
    blocked_subscribers: HashSet<u64>,
    #[cfg(feature = "codec-declare")]
    blocked_queryables: HashSet<u64>,
    #[cfg(feature = "codec-declare")]
    blocked_tokens: HashSet<u64>,
    // Interest correlation is always compiled (Interest is the unconditional
    // `NetworkMessage` variant).
    blocked_interests: HashSet<u64>,
    /// keyexpr-id → the unmatched literal of a `DeclareKeyExpr` whose definition
    /// did not match the namespace (zenoh `incomplete_ingress_keyexpr_declarations`).
    /// Read by the aliased-reference reconstruction path in [`Self::strip`]
    /// (always compiled); populated only by a `DeclareKeyExpr` definition
    /// (`codec-declare`).
    incomplete: HashMap<u64, String>,
}

impl NamespaceIngress {
    /// Build the ingress decorator for `namespace`.
    pub fn new(namespace: OwnedNonWildKeyExpr) -> Self {
        Self {
            namespace,
            #[cfg(feature = "codec-declare")]
            blocked_subscribers: HashSet::new(),
            #[cfg(feature = "codec-declare")]
            blocked_queryables: HashSet::new(),
            #[cfg(feature = "codec-declare")]
            blocked_tokens: HashSet::new(),
            blocked_interests: HashSet::new(),
            incomplete: HashMap::new(),
        }
    }

    /// Clear the per-peer CORRELATION state (the `blocked_*` id sets + the
    /// `incomplete` alias map) while KEEPING the namespace prefix. Called on a
    /// peer-IDENTITY reset that is NOT a full teardown: a unicast transport
    /// reopen ([`crate::session_actions`]'s `reset_for_reopen`) or a multicast
    /// re-JOIN to a known address with a NEW zid. After such a reset the remote
    /// re-handshakes with EMPTY declaration tables + a RESTARTED id space
    /// (handshake-scoped, exactly like the RX SN gate), so a stale `blocked_*`
    /// entry must not survive to swallow a re-declared entity's id-only
    /// `Undeclare*` (the multicast re-JOIN / unicast reopen twin of the
    /// `evict()` reset — the lifecycle gap the R311y107 session review found).
    /// The namespace itself is THIS node's config and is preserved.
    pub fn reset(&mut self) {
        #[cfg(feature = "codec-declare")]
        {
            self.blocked_subscribers.clear();
            self.blocked_queryables.clear();
            self.blocked_tokens.clear();
        }
        self.blocked_interests.clear();
        self.incomplete.clear();
    }

    /// Apply the ingress transform to an INBOUND message destined for this
    /// participant's local registries. Returns `false` when the message must be
    /// DROPPED (its keyexpr is not under the namespace, or it undeclares a
    /// previously-dropped declaration); the caller then skips local dispatch.
    pub fn apply(&mut self, msg: &mut NetworkMessage) -> bool {
        match msg {
            #[cfg(feature = "codec-push")]
            NetworkMessage::Push(p) => self.strip(&mut p.keyexpr, None),
            #[cfg(feature = "codec-request")]
            NetworkMessage::Request(r) => self.strip(&mut r.keyexpr, None),
            #[cfg(feature = "codec-response")]
            NetworkMessage::Response(r) => self.strip(&mut r.keyexpr, None),
            NetworkMessage::Interest(i) => self.interest_ingress(i),
            #[cfg(feature = "codec-declare")]
            NetworkMessage::Declare(d) => self.declare_ingress(d),
            // R2220 — named, not caught, for [`apply_egress`]'s reason. Upstream
            // forwards `send_response_final` unstripped (zenoh
            // `net/routing/namespace.rs:279-281`), has no `EPrimitives` method
            // for `Oam` at all, and cannot see an `Unknown` MID. A new
            // `NetworkMessage` variant must be adjudicated here rather than
            // admitted by default — an admitted message is one this decorator
            // let past the namespace.
            #[cfg(feature = "codec-response-final")]
            NetworkMessage::ResponseFinal(_) => true,
            NetworkMessage::Oam(_) => true,
            NetworkMessage::Unknown { .. } => true,
        }
    }

    /// The core `handle_namespace_ingress` (`namespace.rs:150-188`): strip the
    /// namespace from one keyexpr in place, returning whether the message is
    /// kept. `decl_id` is `Some` only for a `DeclareKeyExpr` DEFINITION (so a
    /// non-matching definition is parked in `incomplete` by that id).
    fn strip(&mut self, we: &mut WireexprOwned, decl_id: Option<u64>) -> bool {
        let sender = is_sender_mapped(we);
        self.strip_mapped(we, decl_id, sender)
    }

    /// [`Self::strip`] with the MAPPING supplied by the caller instead of read
    /// off the decoded variant.
    ///
    /// R2220 — this parameter exists because for ONE message the variant is not
    /// the truth. `out/wz-codecs/interest_body.rs:66` decodes the interest
    /// keyexpr as `Wireexpr::decode(cursor, .., 0x1u8)` — the variant tag is a
    /// LITERAL `Local`, where the six sibling codecs pass `(header >> 6) & 0x1`,
    /// their `M` bit. So every inbound interest keyexpr read back as
    /// Sender-mapped whatever the wire said, and upstream's first ingress rule —
    /// `if scope != EMPTY_EXPR_ID && mapping == Mapping::Receiver { return true }`
    /// (zenoh `net/routing/namespace.rs:149-151`) — was UNREACHABLE for
    /// interests.
    ///
    /// The bit is not lost, only unread: `M` is bit 6 of the interest body's own
    /// header, and [`WireexprLocal`](wz_codecs::wireexpr_local::WireexprLocalOwned)
    /// and its Nonlocal twin decode the SAME three fields from the SAME bytes
    /// (`out/wz-codecs/wireexpr_local.rs:45-70` against
    /// `wireexpr_nonlocal.rs`), so the mis-tagged variant corrupts no value — it
    /// only forgets which table the id belongs to. Reading `M` here recovers
    /// exactly that, with no change to the pinned codegen.
    fn strip_mapped(&mut self, we: &mut WireexprOwned, decl_id: Option<u64>, sender: bool) -> bool {
        let (id, suffix_opt) = id_suffix(we);
        // id != 0, Receiver(Nonlocal): an alias in OUR own table, already in
        // relative (stripped) form — pass through without re-stripping.
        if id != 0 && !sender {
            return true;
        }
        if id != 0 {
            // id != 0, Sender(Local): an optimized reference into the peer's
            // table. If the peer's defining DeclareKeyExpr was parked
            // (non-matching), reconstruct head+suffix and re-validate; otherwise
            // it was stripped at its definition, so the relative form passes.
            let suffix = suffix_opt.unwrap_or("");
            let Some(head) = self.incomplete.get(&id) else {
                return true;
            };
            if suffix.is_empty() {
                return false;
            }
            let mut combined = head.clone();
            combined.push_str(suffix);
            if set_literal_suffix(we, combined).is_err() {
                return false;
            }
            return self.strip(we, None);
        }
        // id == 0: a literal keyexpr — strip the namespace prefix.
        let key = suffix_opt.unwrap_or("");
        match strip_nonwild_prefix(key, self.namespace.as_nonwild()) {
            // A non-empty stripped tail is the relative keyexpr to deliver.
            Some(tail) if !tail.is_empty() => {
                let tail = tail.to_string();
                set_literal_suffix(we, tail).is_ok()
            }
            // An empty tail means the inbound keyexpr was the namespace plus a
            // trailing '/' (non-canonical) — drop rather than write back an
            // invalid empty keyexpr. wz does not validate inbound keyexpr
            // canonicity at decode (zenoh does, so its `ENamespace` never reaches
            // here); this is the wz robustness backstop. It is a malformed match,
            // not a namespace MISS, so it is never parked in `incomplete`.
            Some(_) => false,
            None => {
                // Not under the namespace. A non-matching DeclareKeyExpr
                // definition (Sender-mapped) is parked so later references to it
                // can be reconstructed; everything else is simply dropped.
                if let (Some(mid), true) = (decl_id, sender) {
                    self.incomplete.insert(mid, key.to_string());
                }
                false
            }
        }
    }

    /// `handle_declare_ingress` (`namespace.rs:190-226`). A `Declare*` whose
    /// keyexpr is out of namespace is dropped AND its id recorded in the
    /// matching blocked set, so the later id-only `Undeclare*` (wz undeclare
    /// bodies carry no keyexpr) is correlated and dropped too.
    #[cfg(feature = "codec-declare")]
    fn declare_ingress(&mut self, d: &mut wz_codecs::declare::DeclareOwned) -> bool {
        use wz_codecs::declare::DeclareOwnedVariant as DV;
        match &mut d.body {
            DV::CodecZenohDeclKexpr(m) => self.strip(&mut m.keyexpr, Some(m.id)),
            // A parked (non-matching) DeclareKeyExpr's undeclare is dropped; one
            // that was stripped (not in `incomplete`) forwards. zenoh:
            // `remove(&id).is_none()`.
            DV::CodecZenohUndeclKexpr(m) => self.incomplete.remove(&m.id).is_none(),
            DV::CodecZenohDeclSubscriber(m) => {
                let id = m.id;
                if self.strip(&mut m.keyexpr, None) {
                    true
                } else {
                    self.blocked_subscribers.insert(id);
                    false
                }
            }
            DV::CodecZenohUndeclSubscriber(m) => !self.blocked_subscribers.remove(&m.id),
            DV::CodecZenohDeclQueryable(m) => {
                let id = m.id;
                if self.strip(&mut m.keyexpr, None) {
                    true
                } else {
                    self.blocked_queryables.insert(id);
                    false
                }
            }
            DV::CodecZenohUndeclQueryable(m) => !self.blocked_queryables.remove(&m.id),
            DV::CodecZenohDeclToken(m) => {
                let id = m.id;
                if self.strip(&mut m.keyexpr, None) {
                    true
                } else {
                    self.blocked_tokens.insert(id);
                    false
                }
            }
            DV::CodecZenohUndeclToken(m) => !self.blocked_tokens.remove(&m.id),
            // No keyexpr and no correlation: upstream admits both
            // (`DeclareBody::DeclareFinal(_) => true`, zenoh
            // `net/routing/namespace.rs:225`). `Default` is a MID this build
            // cannot name, so there is nothing to strip and nothing to block —
            // it is admitted for the same reason, and written out rather than
            // caught so a new sub-MID has to be adjudicated here.
            DV::CodecZenohDeclFinal(_) | DV::Default { .. } => true,
        }
    }

    /// `handle_interest_ingress` (`namespace.rs:228-242`). `Final` (C=0 && F=0,
    /// no keyexpr) correlates against `blocked_interests`; a non-final interest
    /// with a keyexpr strips+blocks; one without a keyexpr passes.
    ///
    /// R2220 — THE MAPPING IS READ FROM THE BODY HEADER, and the clause that
    /// used to stand here recorded why it could not be. That clause called this
    /// a "CODEC LIMITATION (not a logic gap)": the interest-keyexpr decoder
    /// hardcodes the wireexpr variant tag to Local, so every inbound interest
    /// keyexpr read back Sender-mapped and upstream's Receiver pass-through was
    /// unreachable. It also said closing it "needs the interest_body codegen to
    /// decode `M` (a separate codec atom)". That last part is FALSE, and the
    /// measurement is one line: `M` is bit 6 of the body's OWN header
    /// (`interest_body.scxml` declares `<sce:flag name="M" bit="6"/>`, and the
    /// generated `InterestBodyOwned` keeps that byte), so the bit the decoder
    /// declined to dispatch on is still in the struct this method holds. The
    /// two wireexpr arms decode identical fields from identical bytes, so the
    /// mis-tagged variant loses the mapping and nothing else. Reading it here
    /// makes [`Self::strip_mapped`]'s Receiver arm reachable for interests, with
    /// no change to the pinned `out/**` codegen.
    fn interest_ingress(&mut self, i: &mut wz_codecs::interest::InterestOwned) -> bool {
        let is_final = (i.header & INTEREST_C) == 0 && (i.header & INTEREST_F) == 0;
        if is_final {
            return !self.blocked_interests.remove(&i.interest_id);
        }
        let id = i.interest_id;
        // Read before the mutable borrow of the same body below.
        // A `match`, not `is_none_or`: that method is stable since 1.82 and this
        // workspace's MSRV is 1.81 (`crates/Cargo.toml`), which
        // `clippy::incompatible-msrv` enforces on this lane.
        let sender = match i.body.as_ref() {
            Some(b) => (b.header & INTEREST_BODY_M) != 0,
            // No body means no keyexpr, so the mapping is never consulted; this
            // is the value the decoded variant would have reported anyway.
            None => true,
        };
        match i.body.as_mut().and_then(|b| b.keyexpr.as_mut()) {
            Some(we) => {
                if self.strip_mapped(we, None, sender) {
                    true
                } else {
                    self.blocked_interests.insert(id);
                    false
                }
            }
            None => true,
        }
    }
}

/// Apply the stateful ingress decorator to one driver-loop outcome in place.
/// For a `FramePayload` batch, strip + drop each decoded message BEFORE the
/// observer fan-out; `retain_mut` preserves batch order, which the stateful
/// blocked-id / incomplete-alias correlation in [`NamespaceIngress::apply`]
/// depends on. Non-`FramePayload` outcomes (FSM advance, KeepAlive, parse
/// error, link-lost, an un-reassembled fragment) carry no application keyexpr
/// and pass through untouched. The single integration seam between the
/// decorator and the driver loop: the AP `drive_session_until_terminal` calls
/// it on the direct outcome, `report_outcome_reassembling` on the reassembled
/// completion (the two distinct owned-outcome mint points).
pub fn strip_outcome(ing: &mut NamespaceIngress, outcome: &mut DriverLoopOutcome) {
    if let DriverLoopOutcome::FramePayload { messages, .. } = outcome {
        messages.retain_mut(|m| ing.apply(m));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wireexpr_build::literal_wireexpr;
    use alloc::format;
    use wz_codecs::wireexpr_local::WireexprLocalOwned;
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocalOwned;

    fn ns(s: &str) -> OwnedNonWildKeyExpr {
        OwnedNonWildKeyExpr::new(s).unwrap()
    }

    fn literal(s: &str) -> WireexprOwned {
        literal_wireexpr(s).unwrap()
    }

    /// Sender(Local)-mapped aliased wireexpr: id != 0, M=1.
    fn aliased_sender(id: u64, suffix: Option<&str>) -> WireexprOwned {
        WireexprOwned {
            body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                id,
                suffix_len: suffix.map(|s| s.len() as u64),
                suffix: suffix.map(|s| crate::codec_owned::owned_string::<128>(s).unwrap()),
            }),
        }
    }

    /// Receiver(Nonlocal)-mapped aliased wireexpr: id != 0, M=0.
    fn aliased_receiver(id: u64, suffix: Option<&str>) -> WireexprOwned {
        WireexprOwned {
            body: WireexprOwnedVariant::WireexprNonlocal(WireexprNonlocalOwned {
                id,
                suffix_len: suffix.map(|s| s.len() as u64),
                suffix: suffix.map(|s| crate::codec_owned::owned_string::<128>(s).unwrap()),
            }),
        }
    }

    fn suffix_of(we: &WireexprOwned) -> Option<String> {
        id_suffix(we).1.map(str::to_string)
    }

    #[test]
    fn egress_literal_prefix() {
        let n = ns("myns");
        let we = literal("foo/bar");
        assert_eq!(literal_prefix(&n, &we), Some("myns/foo/bar".to_string()));
        // aliased (id!=0) -> not prefixed on egress.
        assert_eq!(literal_prefix(&n, &aliased_sender(5, Some("x"))), None);
    }

    #[test]
    fn ingress_strip_literal() {
        let mut ing = NamespaceIngress::new(ns("myns"));
        let mut we = literal("myns/foo/bar");
        assert!(ing.strip(&mut we, None));
        assert_eq!(suffix_of(&we), Some("foo/bar".to_string()));
    }

    #[test]
    fn ingress_drop_out_of_namespace() {
        let mut ing = NamespaceIngress::new(ns("myns"));
        let mut we = literal("other/foo");
        assert!(!ing.strip(&mut we, None)); // dropped
    }

    #[test]
    fn ingress_strip_wild_target() {
        // A peer's wild subscription declaration under the namespace.
        let mut ing = NamespaceIngress::new(ns("myns"));
        let mut we = literal("myns/**");
        assert!(ing.strip(&mut we, None));
        assert_eq!(suffix_of(&we), Some("**".to_string()));
    }

    #[test]
    fn ingress_receiver_alias_passes_through() {
        // id!=0 Receiver(Nonlocal): our own already-relative alias -> untouched.
        let mut ing = NamespaceIngress::new(ns("myns"));
        let mut we = aliased_receiver(7, Some("x"));
        assert!(ing.strip(&mut we, None));
        assert_eq!(id_suffix(&we), (7, Some("x")));
    }

    #[test]
    fn ingress_sender_alias_not_parked_passes() {
        // id!=0 Sender(Local) with no incomplete entry: it was stripped at its
        // (matching) DeclareKeyExpr definition, so the relative form passes.
        let mut ing = NamespaceIngress::new(ns("myns"));
        let mut we = aliased_sender(9, Some("x"));
        assert!(ing.strip(&mut we, None));
    }

    #[cfg(feature = "codec-declare")]
    #[test]
    fn ingress_blocked_undeclare_correlation() {
        use alloc::boxed::Box;
        use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant as DV};
        let mut ing = NamespaceIngress::new(ns("myns"));
        let decl_sub = |id, ke| {
            NetworkMessage::Declare(Box::new(DeclareOwned {
                header: 0,
                interest_id: None,
                extensions: None,
                body: DV::CodecZenohDeclSubscriber(
                    wz_codecs::decl_subscriber::DeclSubscriberOwned {
                        header: 0,
                        id,
                        keyexpr: literal(ke),
                        extensions: None,
                    },
                ),
            }))
        };
        // DeclareSubscriber id=3 out-of-namespace -> dropped + id blocked.
        assert!(!ing.apply(&mut decl_sub(3, "other/foo")));
        assert!(ing.blocked_subscribers.contains(&3));
        // The id-only UndeclareSubscriber(id=3) must ALSO be dropped (no phantom
        // undeclare leaked to a registry that never saw the declare).
        let mut undecl = NetworkMessage::Declare(Box::new(DeclareOwned {
            header: 0,
            interest_id: None,
            extensions: None,
            body: DV::CodecZenohUndeclSubscriber(
                wz_codecs::undecl_subscriber::UndeclSubscriberOwned {
                    header: 0,
                    id: 3,
                    extensions: None,
                },
            ),
        }));
        assert!(!ing.apply(&mut undecl));
        assert!(!ing.blocked_subscribers.contains(&3)); // consumed
                                                        // A matching DeclareSubscriber id=4 strips + passes (not blocked).
        assert!(ing.apply(&mut decl_sub(4, "myns/foo")));
        assert!(!ing.blocked_subscribers.contains(&4));
    }

    /// R311y107b — `reset()` clears the blocked-id / incomplete CORRELATION while
    /// keeping the namespace: a blocked id is forgotten (so its later undeclare
    /// SURVIVES rather than being consumed), yet an in-namespace declare still
    /// strips. The kernel proof behind the unicast `reset_for_reopen` + multicast
    /// re-JOIN identity-reset paths (the session-review lifecycle-gap fix).
    #[cfg(feature = "codec-declare")]
    #[test]
    fn reset_clears_blocked_ids_keeps_namespace() {
        use alloc::boxed::Box;
        use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant as DV};
        let mut ing = NamespaceIngress::new(ns("myns"));
        let decl_sub = |id, ke| {
            NetworkMessage::Declare(Box::new(DeclareOwned {
                header: 0,
                interest_id: None,
                extensions: None,
                body: DV::CodecZenohDeclSubscriber(
                    wz_codecs::decl_subscriber::DeclSubscriberOwned {
                        header: 0,
                        id,
                        keyexpr: literal(ke),
                        extensions: None,
                    },
                ),
            }))
        };
        // Block id=3 (out-of-namespace declare dropped + id remembered).
        assert!(!ing.apply(&mut decl_sub(3, "other/foo")));
        assert!(ing.blocked_subscribers.contains(&3));
        // reset() forgets the correlation (identity reset, namespace preserved).
        ing.reset();
        assert!(ing.blocked_subscribers.is_empty());
        assert!(ing.incomplete.is_empty());
        // The id-3 undeclare now SURVIVES (no stale block to consume it) — the
        // re-handshaked peer's re-declared id is not swallowed.
        let mut undecl = NetworkMessage::Declare(Box::new(DeclareOwned {
            header: 0,
            interest_id: None,
            extensions: None,
            body: DV::CodecZenohUndeclSubscriber(
                wz_codecs::undecl_subscriber::UndeclSubscriberOwned {
                    header: 0,
                    id: 3,
                    extensions: None,
                },
            ),
        }));
        assert!(ing.apply(&mut undecl));
        // The namespace PREFIX survives: an in-namespace declare still strips+passes.
        assert!(ing.apply(&mut decl_sub(4, "myns/foo")));
    }

    #[test]
    fn ingress_incomplete_reconstruct() {
        // DeclareKeyExpr id=5 defines alias "my" (shorter than namespace "myns")
        // -> parked. A later Sender alias (id=5, suffix="ns/zenoh/pub")
        // reconstructs "my"+"ns/zenoh/pub" = "myns/zenoh/pub" -> strip ->
        // "zenoh/pub".
        let mut ing = NamespaceIngress::new(ns("myns"));
        let mut defn = literal("my");
        assert!(!ing.strip(&mut defn, Some(5))); // parked (doesn't match yet)
        assert_eq!(ing.incomplete.get(&5).map(String::as_str), Some("my"));
        let mut us = aliased_sender(5, Some("ns/zenoh/pub"));
        assert!(ing.strip(&mut us, None));
        assert_eq!(suffix_of(&us), Some("zenoh/pub".to_string()));
    }

    #[test]
    fn egress_ingress_roundtrip() {
        let n = ns("myns");
        let mut ing = NamespaceIngress::new(ns("myns"));
        for ke in ["foo/bar", "a/b/c"] {
            let mut we = literal(ke);
            let new = literal_prefix(&n, &we).unwrap();
            set_literal_suffix(&mut we, new).unwrap();
            assert_eq!(suffix_of(&we), Some(format!("myns/{ke}")));
            assert!(ing.strip(&mut we, None));
            assert_eq!(suffix_of(&we), Some(ke.to_string()));
        }
    }

    fn interest(header: u8, id: u64, ke: Option<&str>) -> NetworkMessage {
        NetworkMessage::Interest(wz_codecs::interest::InterestOwned {
            header,
            interest_id: id,
            body: ke.map(|k| wz_codecs::interest_body::InterestBodyOwned {
                header: 0,
                keyexpr: Some(literal(k)),
            }),
            extensions: None,
        })
    }

    fn interest_ke(msg: &NetworkMessage) -> Option<String> {
        match msg {
            NetworkMessage::Interest(i) => i
                .body
                .as_ref()
                .and_then(|b| b.keyexpr.as_ref())
                .map(|w| id_suffix(w).1.unwrap_or("").to_string()),
            _ => None,
        }
    }

    // ─── apply_egress dispatch ───

    #[test]
    fn egress_interest_prepends_keyexpr() {
        // non-final interest (C set) with a literal keyexpr -> prefixed.
        let mut msg = interest(INTEREST_C, 1, Some("foo/bar"));
        apply_egress(&ns("myns"), &mut msg).unwrap();
        assert_eq!(interest_ke(&msg), Some("myns/foo/bar".to_string()));
    }

    #[cfg(feature = "codec-push")]
    #[test]
    fn egress_push_prepends_keyexpr() {
        let mut msg = NetworkMessage::Push(alloc::boxed::Box::new(
            crate::push_build::build_push_literal("foo/bar", b"v").unwrap(),
        ));
        apply_egress(&ns("myns"), &mut msg).unwrap();
        let NetworkMessage::Push(p) = &msg else {
            panic!("not a push")
        };
        assert_eq!(suffix_of(&p.keyexpr), Some("myns/foo/bar".to_string()));
    }

    // ─── multicast egress item dispatch ───

    /// R311y107 — the MULTICAST egress item dispatcher prefixes a `Push`'s
    /// literal keyexpr (via the extracted [`apply_egress_push`] SSOT, shared
    /// with the `NetworkMessage::Push` arm of [`apply_egress`]). The reply-plane
    /// variants route through the same `apply_egress_response`/`_declare` SSOTs
    /// already covered above; `ResponseFinal` carries no keyexpr.
    #[cfg(all(
        feature = "session-multicast",
        feature = "codec-frame",
        feature = "codec-push"
    ))]
    #[test]
    fn egress_multicast_item_prefixes_push() {
        use crate::multicast_tx::MulticastTxItem;
        let n = ns("myns");
        let mut item = MulticastTxItem::Push {
            push: alloc::boxed::Box::new(
                crate::push_build::build_push_literal("foo/bar", b"v").unwrap(),
            ),
            reliable: true,
            priority: crate::qos::Priority::DEFAULT,
        };
        apply_egress_multicast_item(&n, &mut item).unwrap();
        let MulticastTxItem::Push { push, .. } = &item else {
            panic!("not a push")
        };
        assert_eq!(suffix_of(&push.keyexpr), Some("myns/foo/bar".to_string()));
    }

    #[cfg(feature = "codec-declare")]
    #[test]
    fn egress_declare_kexpr_subscriber_and_aliased() {
        use alloc::boxed::Box;
        use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant as DV};
        let n = ns("myns");
        let wrap = |body| {
            NetworkMessage::Declare(Box::new(DeclareOwned {
                header: 0,
                interest_id: None,
                extensions: None,
                body,
            }))
        };
        let body_ke = |msg: &NetworkMessage| -> WireexprOwned {
            let NetworkMessage::Declare(d) = msg else {
                panic!()
            };
            match &d.body {
                DV::CodecZenohDeclKexpr(m) => m.keyexpr.clone(),
                DV::CodecZenohDeclSubscriber(m) => m.keyexpr.clone(),
                _ => panic!(),
            }
        };
        // DeclareKeyExpr definition: ALWAYS prefixed.
        let mut k = wrap(DV::CodecZenohDeclKexpr(
            wz_codecs::decl_kexpr::DeclKexprOwned {
                header: 0,
                id: 9,
                keyexpr: literal("foo"),
                extensions: None,
            },
        ));
        apply_egress(&n, &mut k).unwrap();
        assert_eq!(suffix_of(&body_ke(&k)), Some("myns/foo".to_string()));
        // DeclareSubscriber literal (id==0): prefixed.
        let mut s = wrap(DV::CodecZenohDeclSubscriber(
            wz_codecs::decl_subscriber::DeclSubscriberOwned {
                header: 0,
                id: 1,
                keyexpr: literal("bar"),
                extensions: None,
            },
        ));
        apply_egress(&n, &mut s).unwrap();
        assert_eq!(suffix_of(&body_ke(&s)), Some("myns/bar".to_string()));
        // Aliased DeclareSubscriber (id!=0): NOT prefixed (alias already namespaced).
        let mut a = wrap(DV::CodecZenohDeclSubscriber(
            wz_codecs::decl_subscriber::DeclSubscriberOwned {
                header: 0,
                id: 2,
                keyexpr: aliased_sender(7, Some("baz")),
                extensions: None,
            },
        ));
        apply_egress(&n, &mut a).unwrap();
        assert_eq!(id_suffix(&body_ke(&a)), (7, Some("baz")));
    }

    // ─── interest ingress ───

    #[test]
    fn ingress_interest_final_correlates_blocked() {
        let mut ing = NamespaceIngress::new(ns("myns"));
        // non-final interest with an out-of-namespace keyexpr -> drop + block id.
        assert!(!ing.apply(&mut interest(INTEREST_C, 8, Some("other/x"))));
        assert!(ing.blocked_interests.contains(&8));
        // Final (C=0,F=0) for id 8 -> dropped (was blocked) + consumed.
        assert!(!ing.apply(&mut interest(0, 8, None)));
        assert!(!ing.blocked_interests.contains(&8));
    }

    #[test]
    fn ingress_interest_nonfinal_strip_and_passthrough() {
        let mut ing = NamespaceIngress::new(ns("myns"));
        // non-final with in-namespace keyexpr -> strip + pass.
        let mut ok = interest(INTEREST_C, 1, Some("myns/foo"));
        assert!(ing.apply(&mut ok));
        assert_eq!(interest_ke(&ok), Some("foo".to_string()));
        // non-final with NO keyexpr -> pass untouched.
        assert!(ing.apply(&mut interest(INTEREST_C, 2, None)));
        // Final id never blocked -> pass (remove() = false -> !false = true).
        assert!(ing.apply(&mut interest(0, 99, None)));
    }

    // ─── ingress drop edges ───

    #[test]
    fn ingress_empty_tail_dropped_not_parked() {
        // "myns/" (trailing slash, non-canonical) strips to "" -> dropped, and
        // because it is a malformed match (not a namespace MISS) it is NOT parked.
        let mut ing = NamespaceIngress::new(ns("myns"));
        let mut we = literal("myns/");
        assert!(!ing.strip(&mut we, Some(5)));
        assert!(ing.incomplete.is_empty());
    }

    #[test]
    fn ingress_empty_suffix_aliased_drop() {
        // A parked alias referenced with an EMPTY suffix cannot be reconstructed
        // -> drop (zenoh namespace.rs:160).
        let mut ing = NamespaceIngress::new(ns("myns"));
        let mut defn = literal("my");
        assert!(!ing.strip(&mut defn, Some(5))); // parked
        assert!(!ing.strip(&mut aliased_sender(5, None), None));
    }

    #[cfg(feature = "codec-declare")]
    #[test]
    fn ingress_undecl_kexpr_correlation() {
        use alloc::boxed::Box;
        use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant as DV};
        let mut ing = NamespaceIngress::new(ns("myns"));
        // park id=5 via a non-matching DeclareKeyExpr definition ("my" < "myns").
        assert!(!ing.strip(&mut literal("my"), Some(5)));
        let undecl = |id| {
            NetworkMessage::Declare(Box::new(DeclareOwned {
                header: 0,
                interest_id: None,
                extensions: None,
                body: DV::CodecZenohUndeclKexpr(wz_codecs::undecl_kexpr::UndeclKexprOwned {
                    header: 0,
                    id,
                    extensions: None,
                }),
            }))
        };
        // UndeclareKeyExpr id=5 was parked -> dropped (remove = Some -> is_none() false).
        assert!(!ing.apply(&mut undecl(5)));
        assert!(ing.incomplete.is_empty());
        // UndeclareKeyExpr id=99 never parked -> forwarded.
        assert!(ing.apply(&mut undecl(99)));
    }

    #[cfg(feature = "codec-declare")]
    #[test]
    fn ingress_queryable_token_block_correlation() {
        use alloc::boxed::Box;
        use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant as DV};
        let mut ing = NamespaceIngress::new(ns("myns"));
        let wrap = |body| {
            NetworkMessage::Declare(Box::new(DeclareOwned {
                header: 0,
                interest_id: None,
                extensions: None,
                body,
            }))
        };
        // DeclareQueryable out-of-namespace -> drop + block; its undeclare -> drop.
        assert!(!ing.apply(&mut wrap(DV::CodecZenohDeclQueryable(
            wz_codecs::decl_queryable::DeclQueryableOwned {
                header: 0,
                id: 1,
                keyexpr: literal("other/q"),
                extensions: None,
            },
        ))));
        assert!(ing.blocked_queryables.contains(&1));
        assert!(!ing.apply(&mut wrap(DV::CodecZenohUndeclQueryable(
            wz_codecs::undecl_queryable::UndeclQueryableOwned {
                header: 0,
                id: 1,
                extensions: None,
            },
        ))));
        assert!(!ing.blocked_queryables.contains(&1));
        // DeclareToken out-of-namespace -> drop + block; its undeclare -> drop.
        assert!(!ing.apply(&mut wrap(DV::CodecZenohDeclToken(
            wz_codecs::decl_token::DeclTokenOwned {
                header: 0,
                id: 2,
                keyexpr: literal("other/t"),
                extensions: None,
            },
        ))));
        assert!(ing.blocked_tokens.contains(&2));
        assert!(!ing.apply(&mut wrap(DV::CodecZenohUndeclToken(
            wz_codecs::undecl_token::UndeclTokenOwned {
                header: 0,
                id: 2,
                extensions: None,
            },
        ))));
        assert!(!ing.blocked_tokens.contains(&2));
        // A matching DeclareQueryable strips + passes (not blocked).
        assert!(ing.apply(&mut wrap(DV::CodecZenohDeclQueryable(
            wz_codecs::decl_queryable::DeclQueryableOwned {
                header: 0,
                id: 3,
                keyexpr: literal("myns/q"),
                extensions: None,
            },
        ))));
        assert!(!ing.blocked_queryables.contains(&3));
    }

    // ─── R2220: the per-message-type diff's two findings ───

    /// Upstream's ONE `handle_declare_egress` arm this decorator did not have:
    /// the keyexpr a SOURCED `UndeclareQueryable` retracts rides an extension,
    /// and zenoh prefixes it
    /// (`handle_namespace_egress(&mut m.ext_wire_expr.wire_expr, false)`,
    /// `net/routing/namespace.rs:71-73`).
    #[test]
    fn a_sourced_undeclare_queryables_ext_keyexpr_is_decorated() {
        use crate::declare_ext_keyexpr::read_ext_keyexpr;
        use wz_codecs::declare::DeclareOwnedVariant as DV;
        let n = ns("myns");
        let mut d = crate::declare_build::build_undeclare_queryable_with_keyexpr("demo/q")
            .expect("build the sourced retraction");
        apply_egress_declare(&n, &mut d).expect("egress");
        let DV::CodecZenohUndeclQueryable(m) = &d.body else {
            panic!("the builder produced the wrong variant");
        };
        assert_eq!(
            read_ext_keyexpr(m.extensions.as_ref()),
            Some("myns/demo/q"),
            "the retracted keyexpr must leave under the namespace, as upstream's does"
        );
    }

    /// THE CONTROL, and it pins an asymmetry rather than a symmetry. Upstream
    /// carries the same `ext_wire_expr` field on `UndeclareSubscriber` and
    /// `UndeclareToken` and decorates NEITHER (`namespace.rs:67, 79`), so wz
    /// must not either — the wire is what a drop-in is judged on. Without this
    /// arm, "decorate every ext" would pass the test above and put a keyexpr on
    /// the wire that a stock zenoh peer's `ENamespace` never strips.
    ///
    /// It also names what it did NOT vary: the same namespace, the same builder
    /// shape, the same literal — only the retracted ENTITY differs.
    #[test]
    fn the_subscriber_and_token_ext_keyexprs_are_left_alone_as_upstream_leaves_them() {
        use crate::declare_ext_keyexpr::read_ext_keyexpr;
        use wz_codecs::declare::DeclareOwnedVariant as DV;
        let n = ns("myns");

        let mut sub = crate::declare_build::build_undeclare_subscriber_with_keyexpr("demo/s")
            .expect("build the sourced subscriber retraction");
        apply_egress_declare(&n, &mut sub).expect("egress");
        let DV::CodecZenohUndeclSubscriber(m) = &sub.body else {
            panic!("the builder produced the wrong variant");
        };
        assert_eq!(read_ext_keyexpr(m.extensions.as_ref()), Some("demo/s"));

        let mut token = crate::declare_build::build_undeclare_token_with_keyexpr("demo/t")
            .expect("build the sourced token retraction");
        apply_egress_declare(&n, &mut token).expect("egress");
        let DV::CodecZenohUndeclToken(m) = &token.body else {
            panic!("the builder produced the wrong variant");
        };
        assert_eq!(read_ext_keyexpr(m.extensions.as_ref()), Some("demo/t"));
    }

    /// An interest whose keyexpr is an alias in OUR OWN table (`M = 0`,
    /// Receiver-mapped) is passed through untouched — upstream's first ingress
    /// rule, `if scope != EMPTY_EXPR_ID && mapping == Mapping::Receiver { return
    /// true }` (`net/routing/namespace.rs:149-151`).
    ///
    /// THE DISCRIMINATOR is the second arm: the SAME alias id, the same suffix,
    /// the same parked declaration — only `M` differs — must take the
    /// `incomplete` reconstruction instead and come out rewritten. Before R2220
    /// both arms took the second path, because the generated decoder tags every
    /// interest keyexpr `Local`; a run that only checked the first arm would
    /// have passed then too, since a parked-id MISS also returns `true`. The
    /// collision is therefore the whole point of parking id 7 first.
    #[test]
    fn an_interest_alias_is_read_by_its_own_mapping_bit_not_by_the_decoded_variant() {
        fn interest_with(body_header: u8, we: WireexprOwned) -> NetworkMessage {
            NetworkMessage::Interest(wz_codecs::interest::InterestOwned {
                header: INTEREST_C,
                interest_id: 1,
                body: Some(wz_codecs::interest_body::InterestBodyOwned {
                    header: body_header,
                    keyexpr: Some(we),
                }),
                extensions: None,
            })
        }

        // Receiver-mapped (M = 0): passed through, and the keyexpr is UNCHANGED.
        let mut ing = NamespaceIngress::new(ns("myns"));
        let mut defn = literal("my");
        assert!(!ing.strip(&mut defn, Some(7)), "the definition is parked");
        let mut recv = interest_with(0, aliased_receiver(7, Some("ns/x")));
        assert!(
            ing.apply(&mut recv),
            "a Receiver alias is upstream's early true"
        );
        assert_eq!(
            interest_ke(&recv),
            Some("ns/x".to_string()),
            "an alias in our own table is not rewritten"
        );

        // Sender-mapped (M = 1): the parked head is prepended and stripped, so
        // the SAME id on the SAME parked declaration comes out as "x".
        let mut ing = NamespaceIngress::new(ns("myns"));
        let mut defn = literal("my");
        assert!(!ing.strip(&mut defn, Some(7)));
        let mut send = interest_with(INTEREST_BODY_M, aliased_sender(7, Some("ns/x")));
        assert!(ing.apply(&mut send));
        assert_eq!(
            interest_ke(&send),
            Some("x".to_string()),
            "a Sender alias resolves through `incomplete` and is stripped"
        );
    }
}
