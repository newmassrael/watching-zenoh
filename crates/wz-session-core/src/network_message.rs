// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R74 / R311di-11 — Application-layer envelope batch inside a
//! `Frame.payload` carrier.
//!
//! `Frame.payload` models `Vec<NetworkMessage>` per
//! `docs/wire-spec-subset.md` §4 (the Established-session payload
//! carrier; zenoh-pico maps it to `_z_network_message_t`). Each
//! record starts with a header byte where bits 0..4 carry the network
//! MID and bits 5..7 carry per-MID flags + the shared Z bit. The full
//! network-MID set is 7 wide (PUSH 0x1D, REQUEST 0x1C, RESPONSE 0x1B,
//! RESPONSE_FINAL 0x1A, DECLARE 0x1E, INTEREST 0x19, OAM 0x1F per
//! `vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/network.h:33-39`).
//!
//! Each variant body (Request / Push / Response / ResponseFinal /
//! Declare) is cfg-gated on the matching `codec-*` feature so a
//! handshake-only deploy that turns off body codecs elides the unused
//! decode paths from the runtime. `Oam`, `Interest`, and `Unknown`
//! remain unconditional because the underlying codec modules are
//! always present in wz-codecs (no `codec-oam` / `codec-interest`
//! feature exists).

#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-request",
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-declare",
    )
))]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(all(feature = "codec-frame", feature = "alloc"))]
use sce_forge_runtime::codec::CodecError;
// The owned walks (`alloc`) and the walks that lend a record where its payload lies.
#[cfg(all(
    feature = "codec-frame",
    any(
        feature = "alloc",
        test,
        feature = "session-unicast",
        feature = "session-multicast"
    )
))]
use sce_forge_runtime::codec::SceCursor;

// Only the lifetime-free `*Owned` mirrors are imported at module level —
// they are what `NetworkMessage` stores. The borrowed `Foo<'a>` decode
// views are referenced by fully-qualified path inside the codec-frame
// gated `parse_frame_payload` (their only use), so no borrowed import
// needs cfg-gating against the body-codec feature matrix.
#[cfg(all(feature = "alloc", feature = "codec-declare"))]
use wz_codecs::declare::DeclareOwned;
#[cfg(feature = "alloc")]
use wz_codecs::interest::InterestOwned;
#[cfg(feature = "alloc")]
use wz_codecs::oam::OamOwned;
#[cfg(all(feature = "alloc", feature = "codec-push"))]
use wz_codecs::push::PushOwned;
#[cfg(all(feature = "alloc", feature = "codec-request"))]
use wz_codecs::request::RequestOwned;
#[cfg(all(feature = "alloc", feature = "codec-response"))]
use wz_codecs::response::ResponseOwned;
#[cfg(all(feature = "alloc", feature = "codec-response-final"))]
use wz_codecs::response_final::ResponseFinalOwned;

/// R3011 (open-debt item 850) — the storage profile of the DATA-PLANE messages
/// a receive path hands up: `Push`, `Request` and `Response`.
///
/// On an AP build ([`rx-shared-bytes`](crate::rx_profile)) it is
/// [`RxShared`](crate::rx_profile::RxShared), whose byte fields are ranges of the
/// frame the message was decoded from, so a received payload is the frame's own
/// bytes and a deep clone of the message is a reference count. On every other
/// build it is the SCE default, which is exactly what these variants held before
/// there was a choice: the MCU profiles are Arc-free by construction and keep
/// the owned form.
///
/// The control-plane variants (`Declare`, `Interest`, `Oam`, `ResponseFinal`)
/// stay on the default: their byte fields are a few bytes of extension, not a
/// payload, and a second profile there would only make every helper that reads
/// both a generic one.
#[cfg(feature = "rx-shared-bytes")]
pub type WireStorage = crate::rx_profile::RxShared;
/// See the `rx-shared-bytes` form of this alias.
#[cfg(not(feature = "rx-shared-bytes"))]
pub type WireStorage = sce_forge_runtime::codec::DefaultStorage;

/// What a decode projects its messages out of: the frame, when there is one to
/// share, and nothing on a build that has no sharing to do.
#[cfg(all(
    feature = "alloc",
    feature = "codec-frame",
    feature = "rx-shared-bytes"
))]
type Origin<'a> = Option<&'a crate::link::RxBytes>;
#[cfg(all(
    feature = "alloc",
    feature = "codec-frame",
    not(feature = "rx-shared-bytes")
))]
type Origin<'a> = core::marker::PhantomData<&'a ()>;

/// No origin to share: the walk copies, as every walk did before there was one.
#[cfg(all(
    feature = "alloc",
    feature = "codec-frame",
    feature = "rx-shared-bytes"
))]
const NO_ORIGIN: Origin<'static> = None;
#[cfg(all(
    feature = "alloc",
    feature = "codec-frame",
    not(feature = "rx-shared-bytes")
))]
const NO_ORIGIN: Origin<'static> = core::marker::PhantomData;

/// Project a borrowed view into its owned message at [`WireStorage`], sharing
/// `origin` when there is one and copying when there is not.
///
/// A macro, not a function: the projection is a method of each generated codec
/// (`try_into_owned_in_origin` is generic over the profile and takes the
/// profile's own origin type), there are seven of them, and a function would
/// have to be generic over all seven. The `None` arm is a COPY, the behaviour
/// of every caller before the origin existed.
///
/// Defined only where a data codec exists to project: the three call sites are
/// the `Push`, `Request` and `Response` arms, and a build with none of them has
/// no use for the macro (an unused definition is a `-D warnings` error).
#[cfg(all(
    feature = "alloc",
    feature = "codec-frame",
    feature = "rx-shared-bytes",
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response"
    )
))]
macro_rules! own_wire {
    ($view:expr, $origin:expr) => {
        match $origin {
            Some(origin) => $view.try_into_owned_in_origin::<WireStorage>(origin)?,
            None => $view.try_into_owned_in::<WireStorage>()?,
        }
    };
}
#[cfg(all(
    feature = "alloc",
    feature = "codec-frame",
    not(feature = "rx-shared-bytes"),
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response"
    )
))]
macro_rules! own_wire {
    ($view:expr, $origin:expr) => {{
        let _: Origin<'_> = $origin;
        $view.try_into_owned_in::<WireStorage>()?
    }};
}

/// R311dl — re-export the wire-spec MID constants from the
/// wz-codecs single-source-of-truth home. Callsite references
/// (`wire_const::N_MID_REQUEST` etc.) below keep their existing
/// shape; the constants themselves are defined in
/// [`wz_codecs::wire_const`].
#[cfg(all(
    feature = "codec-frame",
    any(
        feature = "alloc",
        all(
            feature = "session-slot",
            any(
                test,
                feature = "session-unicast",
                all(feature = "session-multicast", not(feature = "alloc"))
            )
        )
    )
))]
use wz_codecs::wire_const;

/// R74 — one application-layer message inside a `Frame.payload` batch.
///
/// See the module docstring for the wire-shape rationale and per-
/// variant cfg gating policy. `#[derive(Debug)]` derives transitively
/// over wz-codecs codec structs — those carry the category-uniform
/// `Debug + Clone + PartialEq` derive set per
/// `sce-build::forge::rust_derive_policy::RustDeriveCategory::CodecStruct`
/// SSOT (SCE 14ff5e36d).
///
/// The heap profile's message: each variant owns its decoded record (boxed, and
/// the unknown record's bytes in a `Vec`). The per-session slot profile has no
/// such value: it reads every record where its frame lies (`RecordForm::LentControl`)
/// and hands the lent view over.
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub enum NetworkMessage {
    /// Network MID `_Z_MID_N_REQUEST` (0x1C). Carries a query / put /
    /// del wrapped in a Wireexpr + request-id envelope with response
    /// correlation. Decoded via `wz_codecs::request::Request`. The
    /// `Box` keeps the enum variant size small — `Request` carries
    /// `Wireexpr` + a `RequestVariant` whose arms hold MsgPut / MsgDel
    /// / Query structs, making the inline form much larger than the
    /// `Unknown` variant.
    #[cfg(feature = "codec-request")]
    Request(Box<RequestOwned<WireStorage>>),
    /// R90 — Network MID `_Z_MID_N_PUSH` (0x1D). Pub/sub data
    /// carrier wrapping a put / del inner body — same envelope
    /// shape as `Request` minus the rid field. The `Box` mirrors
    /// the `Request` variant's size-balancing rationale.
    #[cfg(feature = "codec-push")]
    Push(Box<PushOwned<WireStorage>>),
    /// R91 — Network MID `_Z_MID_N_RESPONSE_FINAL` (0x1A). Pure
    /// correlation marker that closes a Request's reply stream;
    /// payload is header + request_id VLE only (no embed, no
    /// inner body). Inlined (no `Box`) because the struct is
    /// small — just three integer fields plus an optional ext
    /// vec.
    #[cfg(feature = "codec-response-final")]
    ResponseFinal(ResponseFinalOwned),
    /// R92 — Network MID `_Z_MID_N_OAM` (0x1F). Diagnostic /
    /// control-plane envelope; header (mid+enc+Z) + VLE id +
    /// optional ext-chain + body variant on `header.enc` (UNIT
    /// / ZINT / ZBUF inner codec). The body variant arms hold
    /// `ExtUnit` / `ExtZint` / `ExtZbuf` — small enough to inline
    /// like `ResponseFinal`.
    Oam(OamOwned),
    /// R93/R94 — Network MID `_Z_MID_N_INTEREST` (0x19).
    /// Declarations discovery / liveliness subscriber registration
    /// envelope; header (mid+C+F+Z) + VLE interest_id + (C||F)-gated
    /// inner body + Z-gated ext-chain. R94 closed the body via the
    /// interest_body sub-codec (body_flags byte + R-gated wireexpr).
    /// Inlined (no `Box`) because the struct is small — header byte
    /// + u64 + optional body + optional ext vec.
    Interest(InterestOwned),
    /// R97 — Network MID `_Z_MID_N_RESPONSE` (0x1B). Query reply
    /// carrier wrapping a reply (0x04) or err (0x05) inner body
    /// dispatched via peek-byte on the inner MID bit-range. Same
    /// envelope shape as `Request` minus the body kind set. The
    /// `Box` keeps the enum variant size small — `Response`
    /// carries `Wireexpr` + `ResponseVariant` whose arms hold
    /// Reply / Err structs, making the inline form larger than
    /// the `Unknown` variant (mirrors the Request sizing
    /// rationale).
    #[cfg(feature = "codec-response")]
    Response(Box<ResponseOwned<WireStorage>>),
    /// R110/R115 — Network MID `_Z_MID_N_DECLARE` (0x1E). Declarations
    /// envelope wrapping one of the nine sub-MID inner bodies
    /// (DECL_KEXPR / DECL_SUBSCRIBER / DECL_QUERYABLE / DECL_TOKEN /
    /// UNDECL_KEXPR / UNDECL_SUBSCRIBER / UNDECL_QUERYABLE /
    /// UNDECL_TOKEN / DECL_FINAL) dispatched via peek-byte on the
    /// inner header MID. R110a-e closed the wz-side authoring chain
    /// and the byte-equiv Layer 3 wire-interop vs zenoh-pico
    /// `_z_declare_encode`; R115 wires the inbound dispatch so a
    /// peer-emitted DECLARE record surfaces here. The `Box` mirrors
    /// the `Request`/`Push`/`Response` sizing rationale — `Declare`
    /// carries an optional interest_id + ext vec + the inner
    /// `DeclareVariant` whose arms hold the nine sub-body structs,
    /// making the inline form much larger than `Unknown`.
    #[cfg(feature = "codec-declare")]
    Declare(Box<DeclareOwned>),
    /// Header byte's MID falls outside the
    /// {REQUEST, PUSH, RESPONSE_FINAL, OAM, INTEREST, RESPONSE, DECLARE}
    /// subset wz-codecs has authored envelope coverage for. `body`
    /// carries the rest of the payload bytes (header byte included)
    /// verbatim so a future per-MID decoder can re-parse without
    /// losing data; the parse stops here to avoid mis-cursor-advancing
    /// across an unknown body length.
    Unknown { mid: u8, body: Vec<u8> },
}

#[cfg(feature = "alloc")]
impl NetworkMessage {
    /// The word the documents print for this message: the dissection's
    /// `MessageName` word for each decoded arm, and `Unknown` for a MID this
    /// build has no envelope for, which is the word the transport walker gives
    /// a transport MID it does not know. Exhaustive, so an arm added later
    /// names itself or fails to compile.
    pub const fn name(&self) -> &'static str {
        match self {
            #[cfg(feature = "codec-request")]
            Self::Request(_) => "Request",
            #[cfg(feature = "codec-push")]
            Self::Push(_) => "Push",
            #[cfg(feature = "codec-response-final")]
            Self::ResponseFinal(_) => "ResponseFinal",
            Self::Oam(_) => "Oam",
            Self::Interest(_) => "Interest",
            #[cfg(feature = "codec-response")]
            Self::Response(_) => "Response",
            #[cfg(feature = "codec-declare")]
            Self::Declare(_) => "Declare",
            Self::Unknown { .. } => "Unknown",
        }
    }
}

/// The verdict on one chain, or
/// [`ExtAdmission::Admissible`](crate::ext_admit::ExtAdmission::Admissible) for a
/// message that has none.
// The union of its callers: the owned message (`alloc`), the Declare and Push
// verdicts, the Response read where its frame lies (`response_view_admission`,
// whose verdict the owned message shares), and the views read where a slot
// profile's frame lies. The Request verdict is `alloc`'s alone, so it adds
// nothing. Each item below is gated on the union of ITS callers, because the
// workspace builds with warnings denied: an item wider than its callers is dead
// code in a build that has none, and a caller wider than the item has no callee.
#[cfg(any(
    feature = "alloc",
    feature = "codec-declare",
    feature = "codec-push",
    all(
        feature = "codec-frame",
        feature = "codec-response",
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    ),
    all(
        feature = "codec-frame",
        feature = "session-slot",
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    )
))]
fn judge_chain<E: crate::ext_view::ExtEntryView>(
    carrier: crate::ext_admit::ExtCarrier,
    extensions: Option<&[E]>,
) -> crate::ext_admit::ExtAdmission {
    judge_headers(
        carrier,
        extensions.map(|chain| chain.iter().map(|e| e.header())),
    )
}

/// [`judge_chain`] over the header bytes a chain yields, held or walked where its frame lies: the
/// verdict reads the headers and nothing else of an entry.
// [`judge_chain`]'s union, which it serves, and the Request read where its frame
// lies (`request_view_admission`), which walks its chains and calls this alone.
#[cfg(any(
    feature = "alloc",
    feature = "codec-declare",
    feature = "codec-push",
    all(
        feature = "codec-frame",
        any(feature = "codec-request", feature = "codec-response"),
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    ),
    all(
        feature = "codec-frame",
        feature = "session-slot",
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    )
))]
fn judge_headers(
    carrier: crate::ext_admit::ExtCarrier,
    headers: Option<impl Iterator<Item = u8>>,
) -> crate::ext_admit::ExtAdmission {
    headers.map_or(crate::ext_admit::ExtAdmission::Admissible, |headers| {
        crate::ext_admit::judge_ext_chain(carrier, headers)
    })
}

/// `first` unless it is admissible, and then `next()`: the
/// chains of a message are read in the order upstream reads them, the envelope's
/// before the body's, and the first offender is the one reported.
// Only the messages that carry a body have a second chain to read.
#[allow(dead_code)]
fn then_judge(
    first: crate::ext_admit::ExtAdmission,
    next: impl FnOnce() -> crate::ext_admit::ExtAdmission,
) -> crate::ext_admit::ExtAdmission {
    match first {
        crate::ext_admit::ExtAdmission::Admissible => next(),
        other => other,
    }
}

#[cfg(feature = "alloc")]
impl NetworkMessage {
    /// What a conforming PARTICIPANT must do with this message's extension
    /// chains:
    /// [`ExtAdmission::UnknownMandatory`](crate::ext_admit::ExtAdmission::UnknownMandatory)
    /// means the message, or the body
    /// it carries, has an extension with the M bit set that the message does not
    /// define, and upstream refuses the whole message for it
    /// (`commons/zenoh-codec/src/common/extension.rs` @ `if u.is_mandatory() {`).
    ///
    /// The network and zenoh-body counterpart of
    /// [`crate::inbound::InboundFrame::ext_admission`], and for the same reason a
    /// predicate beside the decode and not a refusal inside it: a capture must
    /// still SEE a message that carries an extension nobody here implements. The
    /// participant seam is `drive`'s dispatch, which turns it into a framing
    /// error. `Unknown` answers
    /// [`ExtAdmission::Unjudged`](crate::ext_admit::ExtAdmission::Unjudged): this
    /// build cannot
    /// name the message, so it has no space to judge it against.
    pub fn ext_admission(&self) -> crate::ext_admit::ExtAdmission {
        // Which of these a build uses depends on the codecs it selects.
        #[allow(unused_imports)]
        use crate::ext_admit::{
            ExtAdmission, ExtCarrier as C, NetworkEnvelope as N, ZenohBody as Z,
        };
        match self {
            #[cfg(feature = "codec-request")]
            Self::Request(request) => {
                use wz_codecs::request::RequestOwnedVariant as B;
                let body = match &request.body {
                    B::CodecZenohMsgPut(put) => RequestBodyChain::Put(put.extensions.as_deref()),
                    B::CodecZenohMsgDel(del) => RequestBodyChain::Del(del.extensions.as_deref()),
                    B::CodecZenohQuery(query) | B::Default { body: query, .. } => {
                        RequestBodyChain::Query(query.extensions.as_deref())
                    }
                };
                judge_request_chains(request.extensions.as_deref(), body)
            }
            #[cfg(feature = "codec-push")]
            Self::Push(push) => {
                use wz_codecs::push::PushOwnedVariant as B;
                let (body, chain) = match &push.body {
                    B::CodecZenohMsgPut(put) | B::Default { body: put, .. } => {
                        (Z::Put, put.extensions.as_deref())
                    }
                    B::CodecZenohMsgDel(del) => (Z::Del, del.extensions.as_deref()),
                };
                judge_push_chains(push.extensions.as_deref(), body, chain)
            }
            #[cfg(feature = "codec-response")]
            Self::Response(response) => {
                use wz_codecs::reply::ReplyOwnedVariant as R;
                use wz_codecs::response::ResponseOwnedVariant as B;
                let body = match &response.body {
                    B::CodecZenohReply(reply) | B::Default { body: reply, .. } => {
                        let (data, chain) = match &reply.body {
                            R::CodecZenohMsgPut(put) | R::Default { body: put, .. } => {
                                (Z::Put, put.extensions.as_deref())
                            }
                            R::CodecZenohMsgDel(del) => (Z::Del, del.extensions.as_deref()),
                        };
                        ResponseBodyChain::Reply {
                            reply: reply.extensions.as_deref(),
                            data,
                            chain,
                        }
                    }
                    B::CodecZenohErr(err) => ResponseBodyChain::Err(err.extensions.as_deref()),
                };
                judge_response_chains(response.extensions.as_deref(), body)
            }
            #[cfg(feature = "codec-response-final")]
            Self::ResponseFinal(done) => {
                judge_chain(C::Network(N::ResponseFinal), done.extensions.as_deref())
            }
            Self::Oam(oam) => judge_chain(C::Network(N::Oam), oam.extensions.as_deref()),
            Self::Interest(interest) => {
                judge_chain(C::Network(N::Interest), interest.extensions.as_deref())
            }
            #[cfg(feature = "codec-declare")]
            Self::Declare(declare) => {
                use crate::ext_admit::DeclarationKind as K;
                use wz_codecs::declare::DeclareOwnedVariant as B;
                let (kind, chain) = match &declare.body {
                    B::CodecZenohDeclKexpr(d) => (K::KeyExpr, d.extensions.as_deref()),
                    B::CodecZenohUndeclKexpr(d) => (K::UndeclKeyExpr, d.extensions.as_deref()),
                    B::CodecZenohDeclSubscriber(d) => (K::Subscriber, d.extensions.as_deref()),
                    B::CodecZenohUndeclSubscriber(d) => {
                        (K::UndeclSubscriber, d.extensions.as_deref())
                    }
                    B::CodecZenohDeclQueryable(d) => (K::Queryable, d.extensions.as_deref()),
                    B::CodecZenohUndeclQueryable(d) => {
                        (K::UndeclQueryable, d.extensions.as_deref())
                    }
                    B::CodecZenohDeclToken(d) => (K::Token, d.extensions.as_deref()),
                    B::CodecZenohUndeclToken(d) => (K::UndeclToken, d.extensions.as_deref()),
                    B::CodecZenohDeclFinal(d) | B::Default { body: d, .. } => {
                        (K::Final, d.extensions.as_deref())
                    }
                };
                judge_declare_chains(declare.extensions.as_deref(), kind, chain)
            }
            Self::Unknown { .. } => ExtAdmission::Unjudged,
        }
    }
}

/// The verdict on a Declare: its own chain, then the chain of the declaration it
/// carries (`kind`). One rule for the owned message
/// ([`NetworkMessage::ext_admission`]) and the Declare read where its frame lies
/// (`declare_view_admission`), so the receive path that delivers a Declare
/// without copying it refuses exactly what the one that copies it does.
#[cfg(feature = "codec-declare")]
fn judge_declare_chains<E: crate::ext_view::ExtEntryView>(
    outer: Option<&[E]>,
    kind: crate::ext_admit::DeclarationKind,
    chain: Option<&[E]>,
) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::{ExtCarrier as C, NetworkEnvelope as N};
    then_judge(judge_chain(C::Network(N::Declare), outer), || {
        judge_chain(C::Declaration(kind), chain)
    })
}

/// [`NetworkMessage::ext_admission`] for a Declare read where its frame lies.
#[cfg(all(
    feature = "codec-frame",
    feature = "codec-declare",
    feature = "session-slot",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
fn declare_view_admission(
    declare: &wz_codecs::declare::Declare<'_>,
) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::DeclarationKind as K;
    use wz_codecs::declare::DeclareVariant as B;
    let (kind, chain) = match &declare.body {
        B::CodecZenohDeclKexpr(d) => (K::KeyExpr, d.extensions.as_deref()),
        B::CodecZenohUndeclKexpr(d) => (K::UndeclKeyExpr, d.extensions.as_deref()),
        B::CodecZenohDeclSubscriber(d) => (K::Subscriber, d.extensions.as_deref()),
        B::CodecZenohUndeclSubscriber(d) => (K::UndeclSubscriber, d.extensions.as_deref()),
        B::CodecZenohDeclQueryable(d) => (K::Queryable, d.extensions.as_deref()),
        B::CodecZenohUndeclQueryable(d) => (K::UndeclQueryable, d.extensions.as_deref()),
        B::CodecZenohDeclToken(d) => (K::Token, d.extensions.as_deref()),
        B::CodecZenohUndeclToken(d) => (K::UndeclToken, d.extensions.as_deref()),
        B::CodecZenohDeclFinal(d) | B::Default { body: d, .. } => {
            (K::Final, d.extensions.as_deref())
        }
    };
    judge_declare_chains(declare.extensions.as_deref(), kind, chain)
}

/// [`NetworkMessage::ext_admission`] for an Interest read where its frame lies.
#[cfg(all(
    feature = "codec-frame",
    feature = "session-slot",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
fn interest_view_admission(
    interest: &wz_codecs::interest::Interest<'_>,
) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::{ExtCarrier as C, NetworkEnvelope as N};
    judge_chain(C::Network(N::Interest), interest.extensions.as_deref())
}

/// [`NetworkMessage::ext_admission`] for a ResponseFinal read where its frame
/// lies.
#[cfg(all(
    feature = "codec-frame",
    feature = "codec-response-final",
    feature = "session-slot",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
fn response_final_view_admission(
    response_final: &wz_codecs::response_final::ResponseFinal<'_>,
) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::{ExtCarrier as C, NetworkEnvelope as N};
    judge_chain(
        C::Network(N::ResponseFinal),
        response_final.extensions.as_deref(),
    )
}

/// [`NetworkMessage::ext_admission`] for an Oam read where its frame lies.
#[cfg(all(
    feature = "codec-frame",
    feature = "session-slot",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
fn oam_view_admission(oam: &wz_codecs::oam::Oam<'_>) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::{ExtCarrier as C, NetworkEnvelope as N};
    judge_chain(C::Network(N::Oam), oam.extensions.as_deref())
}

/// The verdict on a Push: its own chain, then the chain of the body it carries
/// (`body`). One rule for the owned message ([`NetworkMessage::ext_admission`])
/// and the Push read where its frame lies (`push_view_admission`), so the
/// receive path that delivers a Push without copying it refuses exactly what the
/// one that copies it does.
#[cfg(feature = "codec-push")]
fn judge_push_chains<E: crate::ext_view::ExtEntryView>(
    outer: Option<&[E]>,
    body: crate::ext_admit::ZenohBody,
    body_chain: Option<&[E]>,
) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::{ExtCarrier as C, NetworkEnvelope as N};
    then_judge(judge_chain(C::Network(N::Push), outer), || {
        judge_chain(C::Zenoh(body), body_chain)
    })
}

/// [`NetworkMessage::ext_admission`] for a Push read where its frame lies.
#[cfg(all(
    feature = "codec-frame",
    feature = "codec-push",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
fn push_view_admission(push: &wz_codecs::push::Push<'_>) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::ZenohBody as Z;
    use wz_codecs::push::PushVariant as B;
    let (body, chain) = match &push.body {
        B::CodecZenohMsgPut(put) | B::Default { body: put, .. } => {
            (Z::Put, put.extensions.as_deref())
        }
        B::CodecZenohMsgDel(del) => (Z::Del, del.extensions.as_deref()),
    };
    judge_push_chains(push.extensions.as_deref(), body, chain)
}

/// The chain a Request's body carries, for [`judge_request_chains`]: a Put's or a
/// Del's (generic entries, `E`) or a Query's (the Query's own entries, `Q`). The owned message's;
/// the Request read where its frame lies walks its chains (`request_view_admission`).
#[cfg(all(feature = "alloc", feature = "codec-request"))]
enum RequestBodyChain<'c, E, Q> {
    Put(Option<&'c [E]>),
    Del(Option<&'c [E]>),
    Query(Option<&'c [Q]>),
}

/// The verdict on a Request: its own chain, then its body's. The same order
/// `request_view_admission` judges the Request read where its frame lies in, over chains it
/// walks and does not hold.
#[cfg(all(feature = "alloc", feature = "codec-request"))]
fn judge_request_chains<E: crate::ext_view::ExtEntryView, Q: crate::ext_view::ExtEntryView>(
    outer: Option<&[E]>,
    body: RequestBodyChain<'_, E, Q>,
) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::{ExtCarrier as C, NetworkEnvelope as N, ZenohBody as Z};
    then_judge(judge_chain(C::Network(N::Request), outer), || match body {
        RequestBodyChain::Put(chain) => judge_chain(C::Zenoh(Z::Put), chain),
        RequestBodyChain::Del(chain) => judge_chain(C::Zenoh(Z::Del), chain),
        RequestBodyChain::Query(chain) => judge_chain(C::Zenoh(Z::Query), chain),
    })
}

/// The chains a Response's body carries, for [`judge_response_chains`]: a
/// Reply's own and its data body's (a Put's or a Del's), or an Err's.
#[cfg(all(
    feature = "codec-response",
    any(
        feature = "alloc",
        all(
            feature = "codec-frame",
            any(
                test,
                feature = "session-unicast",
                all(feature = "session-multicast", not(feature = "alloc"))
            )
        )
    )
))]
enum ResponseBodyChain<'c, E> {
    Reply {
        reply: Option<&'c [E]>,
        data: crate::ext_admit::ZenohBody,
        chain: Option<&'c [E]>,
    },
    Err(Option<&'c [E]>),
}

/// The verdict on a Response: its own chain, then its body's, a Reply's own
/// before its data's. One rule for the owned message and the Response read
/// where its frame lies (`response_view_admission`).
#[cfg(all(
    feature = "codec-response",
    any(
        feature = "alloc",
        all(
            feature = "codec-frame",
            any(
                test,
                feature = "session-unicast",
                all(feature = "session-multicast", not(feature = "alloc"))
            )
        )
    )
))]
fn judge_response_chains<E: crate::ext_view::ExtEntryView>(
    outer: Option<&[E]>,
    body: ResponseBodyChain<'_, E>,
) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::{ExtCarrier as C, NetworkEnvelope as N, ZenohBody as Z};
    then_judge(judge_chain(C::Network(N::Response), outer), || match body {
        ResponseBodyChain::Reply { reply, data, chain } => {
            then_judge(judge_chain(C::Zenoh(Z::Reply), reply), || {
                judge_chain(C::Zenoh(data), chain)
            })
        }
        ResponseBodyChain::Err(chain) => judge_chain(C::Zenoh(Z::Err), chain),
    })
}

/// [`NetworkMessage::ext_admission`] for a Request read where its frame lies.
#[cfg(all(
    feature = "codec-frame",
    feature = "codec-request",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
fn request_view_admission(
    request: &wz_codecs::request::RequestView<'_>,
) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::{ExtCarrier as C, NetworkEnvelope as N, ZenohBody as Z};
    use crate::ext_view::walked;
    use wz_codecs::request::RequestViewVariant as B;
    // The rule of [`judge_request_chains`] -- the envelope's chain, then the body's -- over chains
    // that are walked where the frame lies and not held, so no entry is decoded into a slot.
    then_judge(
        judge_headers(
            C::Network(N::Request),
            request
                .extensions
                .as_ref()
                .map(|chain| walked(Some(chain)).map(|e| e.header)),
        ),
        || match &request.body {
            B::CodecZenohMsgPut(put) => judge_headers(
                C::Zenoh(Z::Put),
                put.extensions
                    .as_ref()
                    .map(|chain| walked(Some(chain)).map(|e| e.header)),
            ),
            B::CodecZenohMsgDel(del) => judge_headers(
                C::Zenoh(Z::Del),
                del.extensions
                    .as_ref()
                    .map(|chain| walked(Some(chain)).map(|e| e.header)),
            ),
            B::CodecZenohQuery(query) | B::Default { body: query, .. } => judge_headers(
                C::Zenoh(Z::Query),
                query
                    .extensions
                    .as_ref()
                    .map(|chain| walked(Some(chain)).map(|e| e.header)),
            ),
        },
    )
}

/// [`NetworkMessage::ext_admission`] for a Response read where its frame lies.
#[cfg(all(
    feature = "codec-frame",
    feature = "codec-response",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
fn response_view_admission(
    response: &wz_codecs::response::Response<'_>,
) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::ZenohBody as Z;
    use wz_codecs::reply::ReplyVariant as R;
    use wz_codecs::response::ResponseVariant as B;
    let body = match &response.body {
        B::CodecZenohReply(reply) | B::Default { body: reply, .. } => {
            let (data, chain) = match &reply.body {
                R::CodecZenohMsgPut(put) | R::Default { body: put, .. } => {
                    (Z::Put, put.extensions.as_deref())
                }
                R::CodecZenohMsgDel(del) => (Z::Del, del.extensions.as_deref()),
            };
            ResponseBodyChain::Reply {
                reply: reply.extensions.as_deref(),
                data,
                chain,
            }
        }
        B::CodecZenohErr(err) => ResponseBodyChain::Err(err.extensions.as_deref()),
    };
    judge_response_chains(response.extensions.as_deref(), body)
}

/// The batch a participant may act on: `messages` itself, or the refusal of the
/// first message whose chains a conforming participant must refuse the whole batch
/// for ([`NetworkMessage::ext_admission`]). Out of line: it is called from each
/// receive path of a decoded batch, none of which holds anything to judge one
/// with.
///
/// The decode itself reads such a batch, so a capture sees it; this is the one
/// place a participant stops it.
#[cfg(feature = "alloc")]
#[inline(never)]
pub fn refuse_unknown_mandatory_ext(
    messages: Vec<NetworkMessage>,
) -> Result<Vec<NetworkMessage>, crate::parse_error::InboundParseError> {
    match first_unknown_mandatory_ext(&messages) {
        Some(refusal) => Err(refusal),
        None => Ok(messages),
    }
}

/// The refusal [`refuse_unknown_mandatory_ext`] makes of `messages`, or `None`
/// when a participant may act on every one of them.
#[cfg(feature = "alloc")]
fn first_unknown_mandatory_ext(
    messages: &[NetworkMessage],
) -> Option<crate::parse_error::InboundParseError> {
    messages
        .iter()
        .find_map(|message| match message.ext_admission() {
            crate::ext_admit::ExtAdmission::UnknownMandatory { eid } => {
                Some(crate::parse_error::InboundParseError::UnknownMandatoryExt { eid })
            }
            _ => None,
        })
}

/// R74 — decode a `Frame.payload` byte slice into the in-order batch
/// of network messages it carries.
///
/// Loop shape: peek the cursor's next byte, mask to `mid = byte & 0x1F`,
/// dispatch to the matching envelope decoder. On `N_MID_REQUEST` calls
/// `Request::decode` which re-reads the header byte itself (peek-byte
/// primitive per RFC §5.B Y3 atomic 2b-ii) so no double-consumption.
/// On any other MID, absorbs the remaining bytes as `Unknown { mid,
/// body }` and terminates the batch loop — see
/// [`NetworkMessage::Unknown`] for the rationale.
///
/// An empty `bytes` slice returns `Ok(vec![])` (an empty batch is a
/// valid Frame.payload — the transport envelope is fine, no
/// application-layer records).
///
/// Codec errors propagate as `CodecError`. The caller is responsible
/// for deciding whether to surface them as a transport-FSM
/// `FramingError` (current `poll_and_dispatch_one` behavior, since the
/// transport envelope already parsed but the application-layer batch
/// is malformed) or to log and continue with the partially-decoded
/// batch.
///
/// R311g — gated on `codec-frame`. The only caller is the
/// `InboundFrame::Frame` arm in `poll_and_dispatch_one` (also
/// codec-frame-gated), so a codec-frame-OFF build never reaches a
/// caller; cfg-gating the definition itself elides ~80 lines of
/// dispatch + the `NetworkMessage` decoders for every body codec
/// without leaving an orphan public symbol. Individual match arms
/// inside this function carry their own per-body cfg
/// (`N_MID_PUSH` under `codec-push`, etc.).
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
pub fn parse_frame_payload(bytes: &[u8]) -> Result<Vec<NetworkMessage>, CodecError> {
    parse_batch(bytes, NO_ORIGIN)
}

/// [`parse_frame_payload`] over a frame that can be shared: each decoded
/// message's byte fields are ranges of `origin` (on an AP build) rather than
/// copies out of it. The decode runs over `origin`'s own bytes, which is what
/// makes a slice of them recognisable as part of `origin`; handing in a copy of
/// the frame would decode correctly and share nothing.
///
/// Off `rx-shared-bytes` there is nothing to share, and this is
/// [`parse_frame_payload`] over the same bytes.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
pub fn parse_frame_payload_in(
    origin: &crate::link::RxBytes,
) -> Result<Vec<NetworkMessage>, CodecError> {
    #[cfg(feature = "rx-shared-bytes")]
    {
        parse_batch(origin.as_slice(), Some(origin))
    }
    #[cfg(not(feature = "rx-shared-bytes"))]
    {
        parse_batch(origin.as_slice(), NO_ORIGIN)
    }
}

/// [`parse_frame_payload`] for a batch that exists only as a BORROWED slice,
/// which is the one shape a completed reassembly chain has: its bytes are a slot
/// of the reassembler, reused the moment the completion returns, so nothing
/// decoded out of it may keep pointing there.
///
/// On an AP build the batch is copied ONCE into a buffer that can be shared
/// (see [`RxBytes::lend`](crate::link::RxBytes::lend)) and walked from there, so
/// each message holds a range of that one copy; the per-message copies the walk
/// used to make are the same bytes, so the total moved is unchanged. That is
/// also why this is not a policy of [`parse_frame_payload`] itself: a caller
/// whose bytes are already a frame has a copy to save and should call
/// [`parse_frame_payload_in`] instead. Off `rx-shared-bytes` there is nothing to
/// share, a lent copy would be a second copy for nothing, and this is
/// [`parse_frame_payload`] over the same bytes.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
pub fn parse_frame_payload_lending(bytes: &[u8]) -> Result<Vec<NetworkMessage>, CodecError> {
    #[cfg(feature = "rx-shared-bytes")]
    {
        parse_frame_payload_in(&crate::link::RxBytes::lend(bytes.to_vec()))
    }
    #[cfg(not(feature = "rx-shared-bytes"))]
    {
        parse_frame_payload(bytes)
    }
}

#[cfg(all(feature = "alloc", feature = "codec-frame"))]
fn parse_batch(bytes: &[u8], origin: Origin<'_>) -> Result<Vec<NetworkMessage>, CodecError> {
    let mut messages = Vec::new();
    let mut cursor = SceCursor::new(bytes);
    while cursor.remaining() > 0 {
        // R311y578 — the per-MID dispatch moved to `decode_one_record`, the
        // SSOT this strict walk and the best-effort walk share. Behaviour
        // here is unchanged: `Ok(None)` (no envelope decoder for the MID)
        // absorbs the tail as `Unknown` and terminates, a codec error
        // propagates and fails the whole batch.
        if !decode_one_record(&mut cursor, &mut messages, origin)? {
            absorb_unknown(&mut cursor, &mut messages)?;
            break;
        }
    }
    Ok(messages)
}

/// The record at the cursor has a MID this build has no envelope decoder for,
/// so its length is unknowable: take the rest of the payload, header byte
/// included, as one [`NetworkMessage::Unknown`]. The caller stops walking.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
fn absorb_unknown(cursor: &mut SceCursor<'_>, out: &mut impl RecordOut) -> Result<(), CodecError> {
    let mid = cursor.peek_slice(1)?[0] & 0x1F;
    let rem = cursor.remaining();
    let body = cursor.peek_slice(rem)?.to_vec();
    cursor.advance(rem)?;
    out.put(NetworkMessage::Unknown { mid, body })
}

/// The one-record buffer of the record-at-a-time walk
/// ([`try_for_each_record`], the receive path `drive::dispatch_datagram`): each
/// record is decoded into it, handed over, and cleared before the next.
///
/// A `Vec` on every build but `bounded-heapless`, where it is a `heapless::Vec`
/// of one that lives inside the value that holds it, so a session pump placed in
/// a `static` carries its record buffer with it and the walk takes nothing from
/// a heap to begin. Make one with [`new_record_buf`], the only spelling that does
/// not name the backing.
#[cfg(all(
    feature = "codec-frame",
    feature = "alloc",
    not(feature = "bounded-heapless")
))]
pub type RecordBuf = Vec<NetworkMessage>;
/// See the growable form of this alias.
#[cfg(all(
    feature = "codec-frame",
    feature = "alloc",
    feature = "bounded-heapless"
))]
pub type RecordBuf = heapless::Vec<NetworkMessage, 1>;

/// The record buffer of a build with no allocator: nothing. Such a build has no
/// owned message to decode a record into (`NetworkMessage` is the heap profile's),
/// so the walk reads every record where it lies and the buffer is a marker the
/// walk and the pump that holds it still pass around, one value of no size.
#[cfg(all(feature = "codec-frame", not(feature = "alloc")))]
#[derive(Debug, Default)]
pub struct RecordBuf;

#[cfg(all(feature = "codec-frame", not(feature = "alloc")))]
impl RecordBuf {
    /// Empty the buffer: it holds nothing, so there is nothing to do.
    pub fn clear(&mut self) {}
}

/// An empty [`RecordBuf`]. The growable form reserves its one slot here, once,
/// so a walk that decodes an owned record never grows it.
#[cfg(feature = "codec-frame")]
pub fn new_record_buf() -> RecordBuf {
    #[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
    {
        Vec::with_capacity(1)
    }
    #[cfg(all(feature = "alloc", feature = "bounded-heapless"))]
    {
        heapless::Vec::new()
    }
    #[cfg(not(feature = "alloc"))]
    {
        RecordBuf
    }
}

/// Where a decode puts the message it has projected: the batch decode's `Vec`
/// and the walk's [`RecordBuf`] are both this, so the per-MID decoder is written
/// once. A full output is a refusal the decoder returns, never a drop: the walk
/// empties its one-record buffer before every decode, so the refusal is only
/// reachable by a caller that did not.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
trait RecordOut {
    fn put(&mut self, message: NetworkMessage) -> Result<(), CodecError>;
}

#[cfg(all(feature = "alloc", feature = "codec-frame"))]
impl RecordOut for Vec<NetworkMessage> {
    // Inline: this is `Vec::push` as it was written at each call site, and the
    // decoder's code size is a measured quantity (see `decode_one_record`).
    #[inline(always)]
    fn put(&mut self, message: NetworkMessage) -> Result<(), CodecError> {
        self.push(message);
        Ok(())
    }
}

#[cfg(all(
    feature = "alloc",
    feature = "codec-frame",
    feature = "bounded-heapless"
))]
impl<const N: usize> RecordOut for heapless::Vec<NetworkMessage, N> {
    #[inline(always)]
    fn put(&mut self, message: NetworkMessage) -> Result<(), CodecError> {
        self.push(message).map_err(|_| CodecError::TooManyElements)
    }
}

/// Walk a `Frame.payload` one record at a time: decode the next record into
/// `record` (emptied first), judge it as [`refuse_unknown_mandatory_ext`]
/// judges a batch, and hand it to `each` before the following one is decoded.
///
/// The participant walk of a receive path that dispatches each record as it is
/// decoded (`drive::dispatch_datagram`): what it holds at any moment is one
/// record, however many the peer put in the frame, where [`parse_frame_payload`]
/// holds all of them at once in a list whose length the peer chose. zenoh-pico
/// receives a frame the same way, decoding and handling one network message at
/// a time (`src/transport/unicast/rx.c` @
/// `// Handle all the zenoh message, one by one`).
///
/// The records it hands over are the ones [`parse_frame_payload`] decodes, in
/// the same order, by the same per-MID decoder. What differs is the failure: a
/// record that does not decode, or that carries an extension a participant
/// must refuse, ends the walk with that error AFTER the records before it were
/// handed over, as pico's loop returns from the middle of a frame; the batch
/// decode refuses the whole frame before any record is acted on. An unknown
/// MID is absorbed with the rest of the payload into one
/// [`NetworkMessage::Unknown`], handed over, and ends the walk, as in the batch
/// decode.
///
/// How the walk hands a record over ([`WalkedRecord`]). With
/// [`RecordForm::Lent`], a Push, a Request and a Response are not projected into
/// their owned messages at all: each is decoded where the payload lies and lent
/// for the call, so nothing of it is copied (ARCHITECTURE section 9.2). Every
/// other record is the build's [`WireStorage`] copy of the payload's bytes either
/// way, and so is every record with [`RecordForm::Owned`]: the payload need only
/// outlive the walk.
#[cfg(all(
    feature = "codec-frame",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecordForm {
    /// Every record is decoded into its owned message.
    #[cfg(feature = "alloc")]
    Owned,
    /// A Push, a Request and a Response are decoded where the payload lies and
    /// lent.
    #[cfg(all(
        feature = "alloc",
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response"
        )
    ))]
    Lent,
    /// The slot profile's form: EVERY record is decoded where the payload lies
    /// and lent, the control kinds (a Declare, an Interest, a ResponseFinal) beside
    /// the data kinds, and nothing is projected into an owned message at all. A
    /// record this build reads no further (an Oam, which has no consumer, or a
    /// MID it has no decoder for, whose length is unknowable) is judged where
    /// that is possible and skipped, so the walk allocates nothing whatever the
    /// peer put in the frame ([`WalkedRecord::Skipped`]).
    #[cfg(feature = "session-slot")]
    LentControl,
}

/// One record the walk hands over: the one owned message in the caller's
/// buffer, or a record read where the payload lies ([`RecordForm::Lent`],
/// [`RecordForm::LentControl`]).
///
/// Read by the unicast receive path; a test build without it reads only the
/// kinds its own tests walk.
#[cfg(all(
    feature = "codec-frame",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[cfg_attr(
    not(any(
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )),
    allow(dead_code)
)]
pub(crate) enum WalkedRecord<'r> {
    /// The record's owned message, the one entry of the buffer.
    #[cfg(feature = "alloc")]
    Owned(&'r mut RecordBuf),
    /// A Push decoded where the payload lies, valid for the call.
    #[cfg(feature = "codec-push")]
    Push(&'r wz_codecs::push::Push<'r>),
    /// A Request read where the payload lies, valid for the call: its view, which holds its extension
    /// chains as the bytes they occupy and not as entries (the eager record is 1.8 KB).
    #[cfg(feature = "codec-request")]
    Request(&'r wz_codecs::request::RequestView<'r>),
    /// A Response decoded where the payload lies, valid for the call.
    #[cfg(feature = "codec-response")]
    Response(&'r wz_codecs::response::Response<'r>),
    /// A Declare decoded where the payload lies, valid for the call
    /// ([`RecordForm::LentControl`]).
    #[cfg(all(feature = "session-slot", feature = "codec-declare"))]
    Declare(&'r wz_codecs::declare::Declare<'r>),
    /// A ResponseFinal decoded where the payload lies, valid for the call
    /// ([`RecordForm::LentControl`]).
    #[cfg(all(feature = "session-slot", feature = "codec-response-final"))]
    ResponseFinal(&'r wz_codecs::response_final::ResponseFinal<'r>),
    /// An Interest decoded where the payload lies, valid for the call
    /// ([`RecordForm::LentControl`]).
    #[cfg(feature = "session-slot")]
    Interest(&'r wz_codecs::interest::Interest<'r>),
    /// A record the walk read and judged and no consumer reads further: an Oam, or
    /// the tail of a payload that opens with a MID this build has no decoder for
    /// (the walk ends there, as the owned walk's `Unknown` ends it)
    /// ([`RecordForm::LentControl`]). It carries nothing: the point of handing it
    /// over is that the walk counts it as a record, as it counts the owned
    /// `Oam` and `Unknown` it replaces.
    #[cfg(feature = "session-slot")]
    Skipped,
}

/// The records are copies of the payload's bytes (the build's [`WireStorage`])
/// except one lent under [`RecordForm::Lent`], which is the payload's own
/// bytes. Either way the payload need only outlive the walk.
///
/// A lent record is judged by the same rule as an owned one
/// (`judge_push_chains`, `judge_request_chains`, `judge_response_chains`), so an
/// extension a participant must refuse ends the walk at the same record on both
/// forms.
#[cfg(all(feature = "codec-frame", test))]
pub(crate) fn for_each_record(
    payload: &[u8],
    record: &mut RecordBuf,
    form: RecordForm,
    mut each: impl FnMut(WalkedRecord<'_>),
) -> Result<(), crate::parse_error::InboundParseError> {
    try_for_each_record(payload, record, form, |one| {
        each(one);
        Ok(())
    })
}

/// [`for_each_record`] whose consumer may END the walk: an `Err` from `each`
/// stops it after that record, and is the walk's answer. What a receive path
/// needs when handing a record over can itself fail (the owned extension chain
/// of the `Frame` it came in, made only when an owned record needs it).
#[cfg(all(
    feature = "codec-frame",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
pub(crate) fn try_for_each_record(
    payload: &[u8],
    record: &mut RecordBuf,
    form: RecordForm,
    mut each: impl FnMut(WalkedRecord<'_>) -> Result<(), crate::parse_error::InboundParseError>,
) -> Result<(), crate::parse_error::InboundParseError> {
    // Without a lendable codec there is nothing to lend, and every form is owned.
    #[cfg(not(any(
        all(
            feature = "alloc",
            any(
                feature = "codec-push",
                feature = "codec-request",
                feature = "codec-response"
            )
        ),
        feature = "session-slot"
    )))]
    let _ = form;
    let mut cursor = SceCursor::new(payload);
    while cursor.remaining() > 0 {
        record.clear();
        // The slot profile's form lends every kind, so there is no owned decode
        // left for the rest of the loop to do on its behalf.
        #[cfg(all(feature = "session-slot", feature = "alloc"))]
        if form == RecordForm::LentControl {
            match lend_any_record(&mut cursor, &mut each)? {
                Walk::Continue => continue,
                Walk::End => break,
            }
        }
        // A build with no allocator has the one form and no owned message to decode a
        // record into: this is the whole walk.
        #[cfg(not(feature = "alloc"))]
        {
            let RecordForm::LentControl = form;
            match lend_any_record(&mut cursor, &mut each)? {
                Walk::Continue => continue,
                Walk::End => break,
            }
        }
        #[cfg(feature = "alloc")]
        {
            use crate::parse_error::InboundParseError;
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-request",
                feature = "codec-response"
            ))]
            if form == RecordForm::Lent {
                let mid = cursor.peek_slice(1).map_err(InboundParseError::Codec)?[0] & 0x1F;
                if lend_record(mid, &mut cursor, &mut each)? {
                    continue;
                }
            }
            let known = decode_one_record(&mut cursor, record, NO_ORIGIN)
                .map_err(InboundParseError::Codec)?;
            if !known {
                absorb_unknown(&mut cursor, record).map_err(InboundParseError::Codec)?;
            }
            if let Some(refusal) = first_unknown_mandatory_ext(record) {
                record.clear();
                return Err(refusal);
            }
            if let Err(stop) = each(WalkedRecord::Owned(record)) {
                record.clear();
                return Err(stop);
            }
            if !known {
                break;
            }
        }
    }
    record.clear();
    Ok(())
}

/// The lent half of [`try_for_each_record`]: when the record at the cursor is of
/// a kind the walk lends (`mid`), decode it where the payload lies, judge it by
/// the owned rule, hand it to `each`, and answer `true`; `false` for any other
/// kind, which the caller decodes owned.
///
/// Each kind is decoded in a function of its own, never inlined: a decoded
/// Request or Response is a wide value (inline extension chains), and kept out of
/// line it occupies the stack only while that one record is handed over, not
/// for the whole walk.
#[cfg(all(
    feature = "alloc",
    feature = "codec-frame",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    ),
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response"
    )
))]
fn lend_record(
    mid: u8,
    cursor: &mut SceCursor<'_>,
    each: &mut impl FnMut(WalkedRecord<'_>) -> Result<(), crate::parse_error::InboundParseError>,
) -> Result<bool, crate::parse_error::InboundParseError> {
    match mid {
        #[cfg(feature = "codec-push")]
        wire_const::N_MID_PUSH => lend_push(cursor, each).map(|()| true),
        #[cfg(feature = "codec-request")]
        wire_const::N_MID_REQUEST => lend_request(cursor, each).map(|()| true),
        #[cfg(feature = "codec-response")]
        wire_const::N_MID_RESPONSE => lend_response(cursor, each).map(|()| true),
        _ => Ok(false),
    }
}

/// The refusal a lent record's admission makes, as the owned walk makes it.
#[cfg(all(
    feature = "codec-frame",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    ),
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "session-slot"
    )
))]
fn admit_lent(
    admission: crate::ext_admit::ExtAdmission,
) -> Result<(), crate::parse_error::InboundParseError> {
    match admission {
        crate::ext_admit::ExtAdmission::UnknownMandatory { eid } => {
            Err(crate::parse_error::InboundParseError::UnknownMandatoryExt { eid })
        }
        _ => Ok(()),
    }
}

#[cfg(all(
    feature = "codec-frame",
    feature = "codec-push",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[inline(never)]
fn lend_push(
    cursor: &mut SceCursor<'_>,
    each: &mut impl FnMut(WalkedRecord<'_>) -> Result<(), crate::parse_error::InboundParseError>,
) -> Result<(), crate::parse_error::InboundParseError> {
    let push = wz_codecs::push::Push::decode(cursor)
        .map_err(crate::parse_error::InboundParseError::Codec)?;
    admit_lent(push_view_admission(&push))?;
    each(WalkedRecord::Push(&push))
}

#[cfg(all(
    feature = "codec-frame",
    feature = "codec-request",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[inline(never)]
fn lend_request(
    cursor: &mut SceCursor<'_>,
    each: &mut impl FnMut(WalkedRecord<'_>) -> Result<(), crate::parse_error::InboundParseError>,
) -> Result<(), crate::parse_error::InboundParseError> {
    // The record is read as its view: a few words and the bytes its chains occupy, where the eager
    // record is over a kilobyte (its extension vectors are inline, sized for their declared
    // maximum). `decode` refuses what `Request::decode` refuses, with the same error, so the
    // walk of a chain afterwards cannot fail. It is decoded into the binding that lends it.
    //
    // A view is INVARIANT in the lifetime of the bytes it was read from (its lists hold functions
    // that take a cursor over them), so it cannot be lent for the call while it is read from a
    // cursor of the caller's lifetime. It is read from a cursor of its own over what remains, which
    // lasts as long as the call, and the caller's cursor then moves past what it consumed.
    let rest = cursor
        .peek_slice(cursor.remaining())
        .map_err(crate::parse_error::InboundParseError::Codec)?;
    let mut own = SceCursor::new(rest);
    let mut request = wz_codecs::request::RequestView::default();
    wz_codecs::request::RequestView::decode_into(&mut own, &mut request)
        .map_err(crate::parse_error::InboundParseError::Codec)?;
    cursor
        .advance(rest.len() - own.remaining())
        .map_err(crate::parse_error::InboundParseError::Codec)?;
    admit_lent(request_view_admission(&request))?;
    each(WalkedRecord::Request(&request))
}

#[cfg(all(
    feature = "codec-frame",
    feature = "codec-response",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[inline(never)]
fn lend_response(
    cursor: &mut SceCursor<'_>,
    each: &mut impl FnMut(WalkedRecord<'_>) -> Result<(), crate::parse_error::InboundParseError>,
) -> Result<(), crate::parse_error::InboundParseError> {
    let mut response = wz_codecs::response::Response::default();
    wz_codecs::response::Response::decode_into(cursor, &mut response)
        .map_err(crate::parse_error::InboundParseError::Codec)?;
    admit_lent(response_view_admission(&response))?;
    each(WalkedRecord::Response(&response))
}

/// Whether the walk goes on after a lent record: the record was one of a run
/// (`Continue`), or it was the tail of the payload and the walk ends (`End`).
#[cfg(all(
    feature = "codec-frame",
    feature = "session-slot",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
enum Walk {
    Continue,
    End,
}

/// The slot profile's walk of ONE record ([`RecordForm::LentControl`]): decode the
/// record at the cursor where the payload lies, judge it by the owned rule, and
/// hand it over, whatever kind it is.
///
/// The kinds this build has a decoder for are lent as their own variant of
/// [`WalkedRecord`]; an Oam is judged and handed over as
/// [`WalkedRecord::Skipped`] (nothing reads an Oam's body); and a MID this build
/// has no decoder for, whose length is unknowable, takes the rest of the payload
/// as one skipped record and ends the walk, as the owned walk's `Unknown` does.
/// A kind whose codec is not selected is that last case, as it is in the owned
/// walk.
#[cfg(all(
    feature = "codec-frame",
    feature = "session-slot",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
fn lend_any_record(
    cursor: &mut SceCursor<'_>,
    each: &mut impl FnMut(WalkedRecord<'_>) -> Result<(), crate::parse_error::InboundParseError>,
) -> Result<Walk, crate::parse_error::InboundParseError> {
    let mid = cursor
        .peek_slice(1)
        .map_err(crate::parse_error::InboundParseError::Codec)?[0]
        & 0x1F;
    match mid {
        #[cfg(feature = "codec-push")]
        wire_const::N_MID_PUSH => lend_push(cursor, each).map(|()| Walk::Continue),
        #[cfg(feature = "codec-request")]
        wire_const::N_MID_REQUEST => lend_request(cursor, each).map(|()| Walk::Continue),
        #[cfg(feature = "codec-response")]
        wire_const::N_MID_RESPONSE => lend_response(cursor, each).map(|()| Walk::Continue),
        #[cfg(feature = "codec-declare")]
        wire_const::N_MID_DECLARE => lend_declare(cursor, each).map(|()| Walk::Continue),
        #[cfg(feature = "codec-response-final")]
        wire_const::N_MID_RESPONSE_FINAL => {
            lend_response_final(cursor, each).map(|()| Walk::Continue)
        }
        wire_const::N_MID_INTEREST => lend_interest(cursor, each).map(|()| Walk::Continue),
        wire_const::N_MID_OAM => lend_oam(cursor, each).map(|()| Walk::Continue),
        _ => lend_unknown(cursor, each),
    }
}

#[cfg(all(
    feature = "codec-frame",
    feature = "codec-declare",
    feature = "session-slot",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[inline(never)]
fn lend_declare(
    cursor: &mut SceCursor<'_>,
    each: &mut impl FnMut(WalkedRecord<'_>) -> Result<(), crate::parse_error::InboundParseError>,
) -> Result<(), crate::parse_error::InboundParseError> {
    let declare = wz_codecs::declare::Declare::decode(cursor)
        .map_err(crate::parse_error::InboundParseError::Codec)?;
    admit_lent(declare_view_admission(&declare))?;
    each(WalkedRecord::Declare(&declare))
}

#[cfg(all(
    feature = "codec-frame",
    feature = "codec-response-final",
    feature = "session-slot",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[inline(never)]
fn lend_response_final(
    cursor: &mut SceCursor<'_>,
    each: &mut impl FnMut(WalkedRecord<'_>) -> Result<(), crate::parse_error::InboundParseError>,
) -> Result<(), crate::parse_error::InboundParseError> {
    let response_final = wz_codecs::response_final::ResponseFinal::decode(cursor)
        .map_err(crate::parse_error::InboundParseError::Codec)?;
    admit_lent(response_final_view_admission(&response_final))?;
    each(WalkedRecord::ResponseFinal(&response_final))
}

#[cfg(all(
    feature = "codec-frame",
    feature = "session-slot",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[inline(never)]
fn lend_interest(
    cursor: &mut SceCursor<'_>,
    each: &mut impl FnMut(WalkedRecord<'_>) -> Result<(), crate::parse_error::InboundParseError>,
) -> Result<(), crate::parse_error::InboundParseError> {
    let interest = wz_codecs::interest::Interest::decode(cursor)
        .map_err(crate::parse_error::InboundParseError::Codec)?;
    admit_lent(interest_view_admission(&interest))?;
    each(WalkedRecord::Interest(&interest))
}

#[cfg(all(
    feature = "codec-frame",
    feature = "session-slot",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[inline(never)]
fn lend_oam(
    cursor: &mut SceCursor<'_>,
    each: &mut impl FnMut(WalkedRecord<'_>) -> Result<(), crate::parse_error::InboundParseError>,
) -> Result<(), crate::parse_error::InboundParseError> {
    let oam = wz_codecs::oam::Oam::decode(cursor)
        .map_err(crate::parse_error::InboundParseError::Codec)?;
    admit_lent(oam_view_admission(&oam))?;
    each(WalkedRecord::Skipped)
}

/// The tail of a payload that opens with a MID this build has no decoder for: its
/// length is unknowable, so the rest of the payload is one skipped record and the
/// walk ends.
#[cfg(all(
    feature = "codec-frame",
    feature = "session-slot",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
fn lend_unknown(
    cursor: &mut SceCursor<'_>,
    each: &mut impl FnMut(WalkedRecord<'_>) -> Result<(), crate::parse_error::InboundParseError>,
) -> Result<Walk, crate::parse_error::InboundParseError> {
    let rest = cursor.remaining();
    cursor
        .advance(rest)
        .map_err(crate::parse_error::InboundParseError::Codec)?;
    each(WalkedRecord::Skipped).map(|()| Walk::End)
}

/// R311y578 — why a batch parse stopped short of the payload's end.
///
/// A batch is a run of self-delimiting records with no per-record length
/// prefix, so the ONLY way to find record N+1 is to have fully decoded
/// record N. Once that fails there is nothing to resynchronise against:
/// halting is correct, and the deliverable is saying WHERE and WHY.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchHalt {
    /// A network MID this build has no envelope decoder for. Its body
    /// length is unknowable, so the remaining bytes were absorbed into a
    /// trailing [`NetworkMessage::Unknown`] and the walk stopped. Not
    /// necessarily corruption: it is also what a peer speaking a MID
    /// outside this build's `codec-*` selection looks like.
    UnknownMid {
        /// The masked MID (`header & 0x1F`).
        mid: u8,
        /// Byte offset of that header within the payload.
        offset: usize,
    },
    /// A record's decoder failed. Everything before `offset` decoded
    /// cleanly and is in [`BatchParse::messages`]; from `offset` on the
    /// payload is unparsed.
    ///
    /// [`sce_forge_runtime::codec::CodecError::NeedMoreBytes`] here is the
    /// ordinary shape of a TRUNCATED capture (a snaplen cut, a flow whose
    /// tail was never captured), which is why the error value is carried
    /// rather than flattened to a bool.
    CodecError {
        /// Byte offset of the failing record's header within the payload.
        offset: usize,
        /// The decoder's own error.
        error: CodecError,
    },
}

/// R311y578 — the outcome of a BEST-EFFORT batch parse.
///
/// [`parse_frame_payload`] is the PARTICIPANT contract: a record it cannot
/// decode is a framing error on a session it owns, so the whole batch
/// fails and the transport tears down. That is the right answer when an
/// unparsable frame means the two ends have lost sync.
///
/// An OBSERVER owns nothing. Its batch may contain a MID this build was
/// not compiled with, a record from a protocol revision it predates, or a
/// tail the capture truncated — and in every one of those cases the
/// records it COULD read are still real, still in order, and still worth
/// more than the `Err` that discards them.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
#[derive(Debug)]
pub struct BatchParse {
    /// Every record decoded before the walk stopped, in wire order.
    pub messages: Vec<NetworkMessage>,
    /// R311y641 (§1.1n) — `(offset, len)` within this payload for each entry of
    /// [`Self::messages`], same index, same order.
    ///
    /// THE WALK ALREADY COMPUTED THIS AND KEPT IT ONLY FOR FAILURES. `offset`
    /// is recomputed from the cursor on every iteration and, until this round,
    /// was carried into [`BatchHalt`] and discarded for every record that
    /// SUCCEEDED. So a batch reported where it stopped and never where anything
    /// in it was, and a consumer holding a record could not point at the bytes
    /// it came from.
    ///
    /// A parallel `Vec` rather than a field on `NetworkMessage`, because the
    /// span is a fact about this PARSE and not about the message: the same
    /// message re-encoded elsewhere sits at a different offset, and putting it
    /// on the value would let a copy carry a coordinate that no longer refers to
    /// anything. Pushed in lockstep in the ONE loop below, with
    /// [`Self::span_of`] as the sanctioned paired read.
    pub spans: Vec<(usize, usize)>,
    /// `None` when the whole payload decoded; otherwise where and why the
    /// walk stopped.
    pub halt: Option<BatchHalt>,
    /// Bytes from the halt offset to the end of the payload — `0` when
    /// the walk consumed everything. Carried separately from `offset`
    /// because a consumer reporting "N bytes unparsed" should not have to
    /// hold the payload to compute it.
    pub unparsed_bytes: usize,
}

#[cfg(all(feature = "alloc", feature = "codec-frame"))]
impl BatchParse {
    /// `true` when the entire payload decoded with no halt — the shape a
    /// participant's strict parse also accepts.
    pub fn is_complete(&self) -> bool {
        self.halt.is_none()
    }

    /// R311y641 (§1.1n) — `(offset, len)` of the `i`th message within the
    /// payload this batch was parsed from.
    ///
    /// `None` only when `i` is out of range. The two vectors are pushed
    /// together in `parse_frame_payload_best_effort` and a lookup that fell
    /// through would mean they had desynced, which is the one failure a
    /// parallel vector can have — so it answers `None` rather than indexing.
    pub fn span_of(&self, i: usize) -> Option<(usize, usize)> {
        self.spans.get(i).copied()
    }

    /// Every record with the bytes it came from, in wire order.
    pub fn records(&self) -> impl Iterator<Item = (&NetworkMessage, Option<(usize, usize)>)> {
        self.messages
            .iter()
            .enumerate()
            .map(|(i, m)| (m, self.span_of(i)))
    }
}

/// R311y578 — decode a `Frame.payload` BEST-EFFORT: keep every record that
/// decodes and report where the walk stopped, instead of failing the whole
/// batch.
///
/// The record loop is [`parse_frame_payload`]'s, deliberately: the two
/// contracts differ only in what they do at the seam where a record cannot
/// be decoded, and duplicating the seven-arm MID dispatch to express that
/// would put the codec selection in two places that could drift. This
/// function owns the loop and the halt bookkeeping; the strict entry point
/// stays byte-for-byte the caller-visible contract it always was.
///
/// Never returns `Err`. An empty payload is `messages = []`, `halt = None`
/// — a valid empty batch, exactly as in the strict parse.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
pub fn parse_frame_payload_best_effort(bytes: &[u8]) -> BatchParse {
    parse_payload_best_effort(bytes, usize::MAX)
}

/// Decode the single network record carried by a lowlatency framing unit.
/// Trailing bytes are reported, never treated as another batched message.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
pub fn parse_lowlatency_payload_best_effort(bytes: &[u8]) -> BatchParse {
    parse_payload_best_effort(bytes, 1)
}

#[cfg(all(feature = "alloc", feature = "codec-frame"))]
fn parse_payload_best_effort(bytes: &[u8], max_records: usize) -> BatchParse {
    let total = bytes.len();
    let mut messages = Vec::new();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut cursor = SceCursor::new(bytes);
    let mut halt = None;
    while cursor.remaining() > 0 {
        // The offset is recomputed per record rather than tracked, so it
        // cannot drift from the cursor the decoders actually advance.
        let offset = total - cursor.remaining();
        if messages.len() == max_records {
            halt = Some(BatchHalt::CodecError {
                offset,
                error: CodecError::TooManyElements,
            });
            break;
        }
        // R311y641 — how many records this step appends is the decoder's
        // business, not this loop's, so the spans are filled by DELTA rather
        // than by assuming one. A step that pushed two would otherwise leave the
        // vectors one apart for the rest of the walk.
        let before = messages.len();
        match decode_one_record(&mut cursor, &mut messages, NO_ORIGIN) {
            Ok(true) => {
                let len = (total - cursor.remaining()) - offset;
                spans.resize(before, (0, 0));
                for _ in before..messages.len() {
                    spans.push((offset, len));
                }
            }
            Ok(false) => {
                // An unknown MID: absorb the rest verbatim (the strict
                // parse's own behaviour) and stop, since the record's
                // length is unknowable and there is nothing to resync on.
                let mid = bytes[offset] & 0x1F;
                let rem = cursor.remaining();
                let body = bytes[offset..].to_vec();
                // `advance` past a slice the cursor already reports as
                // remaining cannot fail; the outcome is checked anyway so
                // a future cursor change cannot silently desync the walk.
                if cursor.advance(rem).is_err() {
                    halt = Some(BatchHalt::CodecError {
                        offset,
                        error: CodecError::NeedMoreBytes,
                    });
                    break;
                }
                messages.push(NetworkMessage::Unknown { mid, body });
                // The absorbed remainder IS this record's extent: the strict
                // parse treats an unknown MID as consuming the rest, so the
                // span says so rather than leaving the one record a reader most
                // wants to locate without a coordinate.
                spans.push((offset, rem));
                halt = Some(BatchHalt::UnknownMid { mid, offset });
                break;
            }
            Err(error) => {
                halt = Some(BatchHalt::CodecError { offset, error });
                break;
            }
        }
    }
    let unparsed_bytes = match halt {
        Some(BatchHalt::UnknownMid { offset, .. }) | Some(BatchHalt::CodecError { offset, .. }) => {
            total - offset
        }
        None => 0,
    };
    // Every path that appends a message appends its span, so this holds by
    // construction; it is asserted because a parallel vector's one failure mode
    // is silent and a later arm could reintroduce it.
    debug_assert_eq!(messages.len(), spans.len());
    BatchParse {
        messages,
        spans,
        halt,
        unparsed_bytes,
    }
}

/// Decode ONE record at the cursor and PUSH it onto `out`. `Ok(false)` means
/// the MID has no envelope decoder in this build — the caller decides whether
/// that is a terminating `Unknown` absorb (both parsers) or something else.
///
/// The single MID-dispatch SSOT: adding a `codec-*` feature adds an arm
/// here and both the strict and the best-effort walk gain it together.
///
/// R311y580 — pushes through `out` rather than returning
/// `Option<NetworkMessage>` by value, and that is a FOOTPRINT decision with a
/// measured number behind it. `NetworkMessage` is a wide enum (its largest
/// variants are boxed precisely because of that); returning one through an
/// extra `Option` layer, out of a function, and into a `Vec::push` gave the
/// thumbv7m multicast artifact +748 B in `parse_frame_payload` alone at
/// `opt-level=s` — the whole of Layer Q's +868 regression, per-symbol ELF
/// diff of `e8af0d92` against `8fd6c25c`. The SSOT the extraction bought is
/// worth keeping; the extra move was not, and the out-param keeps both.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
fn decode_one_record(
    cursor: &mut SceCursor<'_>,
    out: &mut impl RecordOut,
    origin: Origin<'_>,
) -> Result<bool, CodecError> {
    let header = cursor.peek_slice(1)?[0];
    let mid = header & 0x1F;
    // Only the three data-plane arms project through the origin; on a build with
    // none of them this is the one parameter nothing reads.
    #[cfg(not(any(
        feature = "codec-request",
        feature = "codec-push",
        feature = "codec-response"
    )))]
    let _ = origin;
    match mid {
        #[cfg(feature = "codec-request")]
        wire_const::N_MID_REQUEST => {
            let req = wz_codecs::request::Request::decode(cursor)?;
            out.put(NetworkMessage::Request(Box::new(own_wire!(req, origin))))?;
        }
        #[cfg(feature = "codec-push")]
        wire_const::N_MID_PUSH => {
            let push = wz_codecs::push::Push::decode(cursor)?;
            out.put(NetworkMessage::Push(Box::new(own_wire!(push, origin))))?;
        }
        #[cfg(feature = "codec-response-final")]
        wire_const::N_MID_RESPONSE_FINAL => {
            let rf = wz_codecs::response_final::ResponseFinal::decode(cursor)?;
            out.put(NetworkMessage::ResponseFinal(rf.try_into_owned()?))?;
        }
        wire_const::N_MID_OAM => {
            let oam = wz_codecs::oam::Oam::decode(cursor)?;
            out.put(NetworkMessage::Oam(oam.try_into_owned()?))?;
        }
        wire_const::N_MID_INTEREST => {
            let interest = wz_codecs::interest::Interest::decode(cursor)?;
            out.put(NetworkMessage::Interest(interest.try_into_owned()?))?;
        }
        #[cfg(feature = "codec-response")]
        wire_const::N_MID_RESPONSE => {
            let resp = wz_codecs::response::Response::decode(cursor)?;
            out.put(NetworkMessage::Response(Box::new(own_wire!(resp, origin))))?;
        }
        #[cfg(feature = "codec-declare")]
        wire_const::N_MID_DECLARE => {
            let decl = wz_codecs::declare::Declare::decode(cursor)?;
            out.put(NetworkMessage::Declare(Box::new(decl.try_into_owned()?)))?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

// ── R311y582 — A1: a chain that never terminated must not reach a consumer.
//    A rule that is merely PRESENT proves nothing, so each leg damages one
//    thing and is paired with the control that leaves it green.
//
//    R311y589 — the check no longer lives in `crate::ext_chain`: SCE landed
//    `on-overflow="reject"` on the entry-flag path (`ec3b032984`) and the
//    GENERATED decode refuses now, so wz's compensating seam was deleted. These
//    tests were deliberately NOT deleted with it. They assert the CONTRACT —
//    what a wz participant must never act on — and the contract outlives
//    whichever layer enforces it; that they still pass with the seam gone is
//    the measurement that the codec took the work over, rather than an
//    inspection of the emit. ──
#[cfg(all(test, feature = "codec-frame", feature = "codec-push"))]
mod chain_saturation_tests {
    use super::*;

    /// A `Push` whose keyexpr is a bare id and whose body is a `MsgPut`
    /// carrying `ext_count` unit extensions and a three-byte payload.
    ///
    /// The terminating extension's id is 3 on purpose: its header byte is
    /// then `0x03`, a plausible VLE that the codec will read as `payload_len`
    /// if the chain saturates — so an unguarded parse SUCCEEDS with the wrong
    /// answer instead of failing. A fixture whose overflow byte was
    /// implausible would prove only that the codec noticed a truncated read.
    ///
    /// The leading extensions' ids start at 5, not 1. Id 2 is the shared-memory
    /// marker, and a Put whose chain carries it lays its payload out as slices,
    /// so a chain of ids 1, 2, 3 reads the payload as a slice count and the
    /// fixture would fail for a reason that is not the one under test. The
    /// terminating id stays 3: it is the plausible byte the control relies on.
    fn push_with_put_exts(ext_count: usize) -> Vec<u8> {
        let mut wire = alloc::vec![wire_const::N_MID_PUSH, 0x01];
        // MsgPut header: MID 0x01 plus Z, since the chain is present.
        wire.push(0x01 | 0x80);
        for i in 1..ext_count {
            wire.push(0x80 | (4 + i as u8));
        }
        wire.push(0x03);
        wire.extend_from_slice(&[0x03, 0xAA, 0xBB, 0xCC]);
        wire
    }

    /// THE CONTROL. Four extensions is exactly the cap, and the chain
    /// terminates on its own, so nothing is refused and the payload is the
    /// one on the wire. Without this leg the reject below could be produced
    /// by a check that fires on every chain.
    #[test]
    fn a_chain_that_terminates_at_the_cap_is_accepted_with_the_right_payload() {
        let wire = push_with_put_exts(crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH);
        let msgs = parse_frame_payload(&wire).expect("a terminated chain must parse");
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            NetworkMessage::Push(p) => match &p.body {
                wz_codecs::push::PushOwnedVariant::CodecZenohMsgPut(put) => {
                    assert_eq!(
                        crate::put_payload::inline_bytes(put),
                        Some(&[0xAAu8, 0xBB, 0xCC][..])
                    );
                    assert_eq!(
                        put.extensions.as_ref().map_or(0, |e| e.len()),
                        crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH
                    );
                }
                other => panic!("expected a Put body, got {other:?}"),
            },
            other => panic!("expected a Push, got {other:?}"),
        }
    }

    /// THE FIRING LEG. One more extension than the cap, and the generated
    /// decode would return `Ok` with a payload of `[0x03, 0xAA, 0xBB]`. The
    /// seam refuses instead — and refuses on the NESTED chain, which is the
    /// one that costs a payload; the `Push`'s own chain is absent here.
    #[test]
    fn a_chain_past_the_cap_is_refused_at_the_dispatch_seam() {
        let wire = push_with_put_exts(crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH + 1);
        assert_eq!(
            parse_frame_payload(&wire).unwrap_err(),
            CodecError::TlvChainOverflow,
            "the dispatch accepted a message whose inner chain never terminated"
        );
    }

    /// An observer keeps what it read and reports where it stopped, rather
    /// than losing the batch — G4's contract, which A1 must not undo. The
    /// leading clean record survives; the saturated one does not become a
    /// decoded message.
    #[test]
    fn the_best_effort_walk_halts_on_it_without_losing_the_earlier_record() {
        let mut wire = wz_codecs::oam::Oam {
            id: 7,
            ..Default::default()
        }
        .encode_to_vec();
        wire.extend_from_slice(&push_with_put_exts(
            crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH + 1,
        ));

        let best = parse_frame_payload_best_effort(&wire);
        assert_eq!(best.messages.len(), 1, "the clean OAM record is kept");
        assert!(
            !best.is_complete(),
            "the saturated record must halt the walk"
        );
        assert!(best
            .messages
            .iter()
            .all(|m| !matches!(m, NetworkMessage::Push(_))));
    }
}

/// R2371 (`transport-stats`) — classify ONE network message for the counters:
/// which medium carried it, and which of upstream's four payload cells (if any)
/// it charges.
///
/// # Why a free function over the typed message, and not a `match` at the seams
///
/// The two counting seams — the TX chokepoint and the RX frame-payload walk —
/// see the same seven-MID enum, so one classifier serves both and the two
/// directions cannot drift into disagreeing about what a `Push(Del)` is. The
/// population is the ENUM: a new [`NetworkMessage`] variant makes the `match`
/// below non-exhaustive and the crate stops compiling, which is what keeps a new
/// message kind from silently counting as nothing.
///
/// # The four cells, and what falls outside them
///
/// Upstream's payload labels cover exactly `put` / `del` / `query` / `reply`
/// (`commons/zenoh-stats/src/stats.rs` @ `MessageLabel::Put`, whose `Reply` and
/// `ReplyErr` arms both fold onto `reply`). A `Push` or a `Request` carries a
/// Put or a Del; a `Request` may instead carry a Query; a `Response` carries a
/// Reply or an Err, and both are `reply`. Everything else — `Declare`,
/// `Interest`, `Oam`, `ResponseFinal`, `Unknown` — is control plane: it counts
/// toward `n_msgs` and toward no payload cell, which is upstream's shape and not
/// an omission.
///
/// # `pl_bytes` is the PAYLOAD, not the envelope
///
/// The wire seam already counts encoded bytes as `bytes`. This counts what
/// upstream's `pl_bytes` counts — the body's own payload — so a Del (a
/// tombstone, no payload field at all) and a Query with no parameters both
/// charge zero bytes against a non-zero message count, exactly as upstream's
/// histogram does.
///
/// # `resolve_alias` and the SPACE axis
///
/// The admin/user split is a property of the LITERAL key expression, and a
/// Wireexpr on the wire may be an ALIAS (`id != 0`) into the declaring side's id
/// space. `resolve_alias` is how the caller lends whichever space it owns: the
/// TX seam passes the session's own outbound mapping table, which is exactly the
/// space its own `id`s name, so an outbound aliased admin expression classifies
/// correctly.
///
/// An alias the resolver cannot resolve falls to
/// [`StatSpace::User`](crate::stats::StatSpace::User) — see
/// [`of_keyexpr`](crate::stats::StatSpace::of_keyexpr). Fully qualified because
/// this module does not import the axis enums: an unqualified link here is
/// exactly the shape that cost R2371 its first push. That is a DECIDED default
/// rather than an
/// oversight — it is `stats_space_of`'s `None` arm, and R2372 measured that NO
/// TEST PINS IT (open-debt 662: R2371's prose named
/// `an_unresolvable_alias_counts_as_user`, which exists in no file, and this
/// module carries no test module at all). The reasoning: the peer's id
/// space lives on the face (the forwarder's per-face table), not on the session,
/// so the inbound seam has no table to consult, and counting an unknown
/// expression as admin would move ADMIN traffic counts on nothing more than an
/// alias being used.
#[cfg(feature = "transport-stats")]
pub fn stats_class<F>(msg: &NetworkMessage, resolve_alias: F) -> crate::stats::NetworkStatsClass
where
    F: Fn(u64) -> Option<alloc::string::String>,
{
    use crate::stats::{MessageLabel, NetworkStatsClass};
    // The three arms below are `resolve_alias`'s ONLY consumers and each is
    // cfg-gated, so a build with all three off leaves the parameter genuinely
    // unused and this crate's `-D warnings` refuses to compile. That build is
    // not hypothetical: this crate's default set is `alloc` + the keyexpr
    // matchers, so `--features transport-stats` alone reaches it, which is
    // exactly the command Layer C1ak's first count guard runs.
    // The union is the one `stats_space_of` already declares rather than a
    // second list of the same three names, and binding it here keeps
    // `unused_variables` live for every other name in this function.
    #[cfg(not(any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response"
    )))]
    let _ = &resolve_alias;
    match msg {
        #[cfg(feature = "codec-push")]
        NetworkMessage::Push(p) => push_stats_class(p, resolve_alias),
        #[cfg(feature = "codec-request")]
        NetworkMessage::Request(r) => request_stats_class(r, resolve_alias),
        #[cfg(feature = "codec-response")]
        NetworkMessage::Response(r) => response_stats_class(r, resolve_alias),
        // Control plane: `n_msgs` and nothing else. Listed rather than caught by
        // a wildcard so a NEW network MID has to be classified here on purpose.
        #[cfg(feature = "codec-response-final")]
        NetworkMessage::ResponseFinal(_) => NetworkStatsClass::control(MessageLabel::ResponseFinal),
        #[cfg(feature = "codec-declare")]
        NetworkMessage::Declare(_) => NetworkStatsClass::control(MessageLabel::Declare),
        NetworkMessage::Oam(_) => NetworkStatsClass::control(MessageLabel::Oam),
        NetworkMessage::Interest(_) => NetworkStatsClass::control(MessageLabel::Interest),
        // A body this build has no codec for; see `NetworkStatsClass::undecoded`.
        NetworkMessage::Unknown { .. } => NetworkStatsClass::undecoded(),
    }
}

/// R2825 — a received message's OWN priority band, read off its `ext_qos`:
/// the `priority` label the stats registry files it under
/// (`zenoh/src/net/routing/dispatcher/stats.rs` @ `fn priority(&self) -> Priority;`).
///
/// It is the band the message CARRIES, not the one the frame that brought it
/// was on — upstream reads the message, and a non-QoS session carries every
/// band in DEFAULT frames. Absent `ext_qos` is `Priority::DEFAULT`, as
/// upstream's decoder leaves it. An undecoded body has no extension to read.
#[cfg(feature = "transport-stats")]
pub fn network_message_priority(msg: &NetworkMessage) -> crate::qos::Priority {
    use crate::declare_ext_qos as qos;
    match msg {
        #[cfg(feature = "codec-push")]
        NetworkMessage::Push(p) => qos::read_push_qos(p).priority(),
        #[cfg(feature = "codec-request")]
        NetworkMessage::Request(r) => qos::read_request_qos(r).priority(),
        #[cfg(feature = "codec-response")]
        NetworkMessage::Response(r) => qos::read_response_qos(r).priority(),
        #[cfg(feature = "codec-response-final")]
        NetworkMessage::ResponseFinal(f) => qos::read_response_final_qos(f).priority(),
        #[cfg(feature = "codec-declare")]
        NetworkMessage::Declare(d) => qos::read_declare_qos(d).priority(),
        NetworkMessage::Oam(o) => qos::read_oam_qos(o).priority(),
        NetworkMessage::Interest(i) => qos::read_interest_qos(i).priority(),
        NetworkMessage::Unknown { .. } => crate::qos::Priority::DEFAULT,
    }
}

/// The SPACE of a Wireexpr, resolving an alias through the caller's id space.
/// See [`stats_class`]'s note on `resolve_alias`.
#[cfg(all(
    feature = "transport-stats",
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response"
    )
))]
fn stats_space_of<F>(
    keyexpr: &crate::wire::parts::WireexprOwned,
    resolve_alias: &F,
) -> crate::stats::StatSpace
where
    F: Fn(u64) -> Option<alloc::string::String>,
{
    use wz_codecs::wireexpr::WireexprOwnedVariant as V;
    let (id, suffix) = match &keyexpr.body {
        V::WireexprNonlocal(b) => (b.id, b.suffix.as_deref()),
        V::WireexprLocal(b) => (b.id, b.suffix.as_deref()),
    };
    if id == 0 {
        // Fully literal: the suffix IS the whole expression.
        return crate::stats::StatSpace::of_keyexpr(suffix.unwrap_or_default());
    }
    match resolve_alias(id) {
        Some(prefix) => crate::stats::StatSpace::of_keyexpr(&prefix),
        None => crate::stats::StatSpace::User,
    }
}

/// Fold a classified body into a class, selecting the `shm` medium when the
/// body's extension chain carries the SHM descriptor marker — the wz twin of
/// upstream's `labels.shm`.
#[cfg(all(
    feature = "transport-stats",
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response"
    )
))]
fn stats_data_class<E: crate::ext_view::ExtEntryView>(
    kind: crate::stats::MessageLabel,
    message: crate::stats::StatMessage,
    space: crate::stats::StatSpace,
    pl_bytes: usize,
    extensions: Option<&[E]>,
) -> crate::stats::NetworkStatsClass {
    stats_class_marked(
        kind,
        message,
        space,
        pl_bytes,
        extensions,
        crate::ext_header::body_ext_id::SHM | crate::ext_header::EXT_FLAG_M,
    )
}

/// [`stats_data_class`] for a body whose shared-memory marker is not a `Put`'s:
/// the marker is named by its identity (its header without the chain flag), so
/// that the Query, whose marker is another extension at another id, is held to
/// its own (R3045). Before it a Query that carried the marker could not be
/// decoded at all, so there was no class to get wrong.
#[cfg(all(
    feature = "transport-stats",
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response"
    )
))]
fn stats_class_marked<E: crate::ext_view::ExtEntryView>(
    kind: crate::stats::MessageLabel,
    message: crate::stats::StatMessage,
    space: crate::stats::StatSpace,
    pl_bytes: usize,
    _extensions: Option<&[E]>,
    _marker: u8,
) -> crate::stats::NetworkStatsClass {
    let class = crate::stats::NetworkStatsClass::net(kind, message, space, pl_bytes);
    #[cfg(feature = "transport-shm")]
    if _extensions.is_some_and(|exts| crate::unit_ext::chain_has_ext_eid(exts, _marker)) {
        return class.on_shm();
    }
    class
}

/// The value length of the first ZBUF extension of identity `eid` in
/// `extensions`, or `0`. The extension is told by its identity
/// ([`crate::ext_header::body_eid`]), as upstream tells it, so an extension of
/// the same id that is mandatory is another extension and is not sized.
#[cfg(all(
    feature = "transport-stats",
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response"
    )
))]
fn zbuf_ext_len<E: crate::ext_view::ExtEntryView>(extensions: Option<&[E]>, eid: u8) -> usize {
    crate::ext_view::find_by_eid(extensions.unwrap_or_default(), eid)
        .and_then(|ext| ext.plain_zbuf())
        .map_or(0, <[u8]>::len)
}

/// R2825 (open-debt item 820) — a data body's payload SIZE as upstream counts
/// it: the payload plus the ATTACHMENT, per carrier
/// (`commons/zenoh-protocol/src/network/push.rs` @ `PushBody::Del(d) => d.ext_attachment.as_ref().map_or(0, |a| a.buffer.len()),`).
/// A `Put` is its payload and its attachment, a `Del` its attachment alone.
/// Before R2825 the attachment was left out and a Del counted `0`.
#[cfg(all(
    feature = "transport-stats",
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response"
    )
))]
fn put_payload_size(put: &crate::wire::parts::MsgPutOwned) -> usize {
    crate::put_payload::payload_len(put)
        + zbuf_ext_len(
            put.extensions.as_deref(),
            crate::ext_header::body_eid::PUT_ATTACHMENT,
        )
}

/// See [`put_payload_size`].
#[cfg(all(
    feature = "transport-stats",
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response"
    )
))]
fn del_payload_size(extensions: Option<&[crate::wire::parts::ExtEntryOwned]>) -> usize {
    zbuf_ext_len(extensions, crate::ext_header::body_eid::DEL_ATTACHMENT)
}

/// [`stats_class`] for a `Push` body — the pub-sub data plane. Shared by the TX
/// chokepoint (which holds the typed body, not the enum) and the RX walk.
#[cfg(all(feature = "transport-stats", feature = "codec-push"))]
pub fn push_stats_class<F>(
    push: &crate::wire::PushOwned,
    resolve_alias: F,
) -> crate::stats::NetworkStatsClass
where
    F: Fn(u64) -> Option<alloc::string::String>,
{
    use crate::stats::{MessageLabel, StatMessage};
    use wz_codecs::push::PushOwnedVariant as V;
    let space = stats_space_of(&push.keyexpr, &resolve_alias);
    match &push.body {
        V::CodecZenohMsgPut(b) | V::Default { body: b, .. } => stats_data_class(
            MessageLabel::Put,
            StatMessage::Put,
            space,
            put_payload_size(b),
            b.extensions.as_deref(),
        ),
        V::CodecZenohMsgDel(b) => stats_data_class(
            MessageLabel::Del,
            StatMessage::Del,
            space,
            del_payload_size(b.extensions.as_deref()),
            b.extensions.as_deref(),
        ),
    }
}

/// [`stats_class`] for a `Request` body — a Put, a Del, or a Query.
#[cfg(all(feature = "transport-stats", feature = "codec-request"))]
pub fn request_stats_class<F>(
    request: &crate::wire::RequestOwned,
    resolve_alias: F,
) -> crate::stats::NetworkStatsClass
where
    F: Fn(u64) -> Option<alloc::string::String>,
{
    use crate::stats::{MessageLabel, StatMessage};
    use wz_codecs::request::RequestOwnedVariant as V;
    let space = stats_space_of(&request.keyexpr, &resolve_alias);
    // Every Request is a `query` to the registry whatever its body: upstream
    // labels by the network message, and its `Request` arm names one kind
    // (`commons/zenoh-stats/src/labels.rs` @ `NetworkBodyRef::Request(_) => MessageLabel::Query,`).
    match &request.body {
        V::CodecZenohMsgPut(b) => stats_data_class(
            MessageLabel::Query,
            StatMessage::Put,
            space,
            put_payload_size(b),
            b.extensions.as_deref(),
        ),
        V::CodecZenohMsgDel(b) => stats_data_class(
            MessageLabel::Query,
            StatMessage::Del,
            space,
            del_payload_size(b.extensions.as_deref()),
            b.extensions.as_deref(),
        ),
        // The marker that precedes a Query's value is its own extension, not a
        // Put's (`ext_header::body_ext_id::QUERY_SHM`), and upstream's `is_shm`
        // for a Request reads it off the Query's value body.
        V::CodecZenohQuery(b) | V::Default { body: b, .. } => stats_class_marked(
            MessageLabel::Query,
            StatMessage::Query,
            space,
            query_payload_size(b.extensions.as_deref()),
            b.extensions.as_deref(),
            crate::ext_header::body_ext_id::QUERY_SHM,
        ),
    }
}

/// R2825 (open-debt item 820) — a Query's payload SIZE as upstream counts it:
/// the VALUE its body extension carries, without the encoding in front of it,
/// plus its attachment
/// (`commons/zenoh-protocol/src/network/request.rs` @ `+ q.ext_attachment.as_ref().map_or(0, |a| a.buffer.len())`).
/// Before R2825 this counted the selector PARAMETERS, which upstream never
/// counts: a `get` with parameters and no value reported bytes where upstream
/// reports none.
#[cfg(all(feature = "transport-stats", feature = "codec-request"))]
fn query_payload_size(extensions: Option<&[crate::wire::parts::QueryExtEntryOwned]>) -> usize {
    crate::ext_view::query_value_payload_len(extensions.unwrap_or_default())
        + zbuf_ext_len(extensions, crate::ext_header::body_eid::QUERY_ATTACHMENT)
}

/// [`stats_class`] for a `Response` body. Reply and Err BOTH fold onto
/// upstream's `reply` cell, which is upstream's own `MessageLabel::Reply |
/// MessageLabel::ReplyErr` arm rather than a wz simplification.
#[cfg(all(feature = "transport-stats", feature = "codec-response"))]
pub fn response_stats_class<F>(
    response: &crate::wire::ResponseOwned,
    resolve_alias: F,
) -> crate::stats::NetworkStatsClass
where
    F: Fn(u64) -> Option<alloc::string::String>,
{
    use crate::stats::{MessageLabel, StatMessage};
    use wz_codecs::response::ResponseOwnedVariant as V;
    let space = stats_space_of(&response.keyexpr, &resolve_alias);
    match &response.body {
        V::CodecZenohReply(b) | V::Default { body: b, .. } => {
            use wz_codecs::reply::ReplyOwnedVariant as RV;
            match &b.body {
                // A reply's body IS a push body upstream, so it is sized as one
                // (`commons/zenoh-protocol/src/network/response.rs` @ `ReplyBody::Del(d) => d.ext_attachment.as_ref().map_or(0, |a| a.buffer.len()),`).
                RV::CodecZenohMsgPut(p) | RV::Default { body: p, .. } => stats_data_class(
                    MessageLabel::Reply,
                    StatMessage::Reply,
                    space,
                    put_payload_size(p),
                    p.extensions.as_deref(),
                ),
                RV::CodecZenohMsgDel(d) => stats_data_class(
                    MessageLabel::Reply,
                    StatMessage::Reply,
                    space,
                    del_payload_size(d.extensions.as_deref()),
                    d.extensions.as_deref(),
                ),
            }
        }
        // The JSON schema folds an Err onto `reply`; the registry does not.
        V::CodecZenohErr(b) => stats_data_class(
            MessageLabel::ReplyErr,
            StatMessage::Reply,
            space,
            b.payload_len as usize,
            b.extensions.as_deref(),
        ),
    }
}

// ── R311y578 — G4: the batch parse is best-effort for an OBSERVER while
//    staying strict for a PARTICIPANT. The fixtures are OAM records
//    (`N_MID_OAM = 0x1F`), whose codec is ungated in wz-codecs, so the
//    contract is pinned in every build that has `codec-frame` at all
//    rather than only in the lanes that select a body codec. ──
// The record-at-a-time walk against the batch decode it must agree with, and
// the one place it is meant to differ: a failure ends it AFTER the records
// before it were handed over.
#[cfg(all(test, feature = "codec-frame"))]
mod record_walk_tests {
    use super::*;
    use alloc::vec;

    fn oam_record(id: u64) -> Vec<u8> {
        wz_codecs::oam::Oam {
            id,
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// What `for_each_record` hands over, one entry per call: the OAM id, or
    /// the MID of an absorbed unknown record. Also checks every call carries
    /// exactly one record.
    fn walk(
        payload: &[u8],
    ) -> (
        Vec<(char, u64)>,
        Result<(), crate::parse_error::InboundParseError>,
    ) {
        let mut record = new_record_buf();
        let mut seen = Vec::new();
        let result = for_each_record(payload, &mut record, RecordForm::Owned, |one| {
            // Without a lendable codec the owned form is the only one there is.
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-request",
                feature = "codec-response",
                feature = "session-slot"
            ))]
            let WalkedRecord::Owned(one) = one
            else {
                panic!("an owned walk lends nothing");
            };
            #[cfg(not(any(
                feature = "codec-push",
                feature = "codec-request",
                feature = "codec-response",
                feature = "session-slot"
            )))]
            let WalkedRecord::Owned(one) = one;
            assert_eq!(one.len(), 1, "one record per call");
            seen.push(match &one[0] {
                NetworkMessage::Oam(o) => ('o', o.id),
                NetworkMessage::Unknown { mid, .. } => ('u', u64::from(*mid)),
                other => panic!("unexpected record {other:?}"),
            });
        });
        assert!(record.is_empty(), "the buffer is handed back empty");
        (seen, result)
    }

    #[test]
    fn the_walk_hands_over_what_the_batch_decode_reads_in_order() {
        let payload = [oam_record(1), oam_record(2), oam_record(3)].concat();
        let batch: Vec<u64> = parse_frame_payload(&payload)
            .expect("the batch decodes")
            .iter()
            .map(|m| match m {
                NetworkMessage::Oam(o) => o.id,
                other => panic!("unexpected record {other:?}"),
            })
            .collect();
        let (seen, result) = walk(&payload);
        assert!(result.is_ok());
        assert_eq!(batch, vec![1, 2, 3]);
        assert_eq!(seen, vec![('o', 1), ('o', 2), ('o', 3)]);
        // An empty payload is a frame of no records: nothing handed over.
        assert_eq!(walk(&[]), (vec![], Ok(())));
    }

    #[test]
    fn a_record_that_does_not_decode_ends_the_walk_after_the_ones_before_it() {
        // The second record is an OAM header with its id cut off.
        let mut payload = oam_record(7);
        payload.push(wire_const::N_MID_OAM);
        assert!(
            parse_frame_payload(&payload).is_err(),
            "the batch decode refuses the whole frame"
        );
        let (seen, result) = walk(&payload);
        assert_eq!(seen, vec![('o', 7)], "the record before it was handed over");
        assert!(
            matches!(result, Err(crate::parse_error::InboundParseError::Codec(_))),
            "then the walk ends with the decode error: {result:?}"
        );
    }

    /// Exhaustion of the pump's record buffer, case R5 of the pool design. The
    /// buffer holds ONE record whatever the peer put in the frame: a frame of many
    /// records goes through it one record at a time, so what a peer sends cannot
    /// fill it.
    #[test]
    fn a_frame_of_many_records_goes_through_the_one_record_buffer_one_at_a_time() {
        const RECORDS: u64 = 64;
        let payload: Vec<u8> = (0..RECORDS).flat_map(oam_record).collect();
        assert_eq!(
            new_record_buf().capacity(),
            1,
            "the buffer holds one record, however many a frame carries"
        );
        let (seen, result) = walk(&payload);
        assert!(result.is_ok());
        assert_eq!(seen.len(), RECORDS as usize, "every record was handed over");
        assert_eq!(seen.last(), Some(&('o', RECORDS - 1)), "in wire order");
    }

    /// The other half: a caller that does NOT hand the buffer back (the walk
    /// clears it before every decode, so only a caller that decodes past it can
    /// meet this) is refused the next record as `TooManyElements`, an explicit
    /// error, and the record the buffer holds is kept. On the fixed backing the
    /// buffer cannot grow, so there is nothing else it could do.
    #[cfg(feature = "bounded-heapless")]
    #[test]
    fn a_record_buffer_that_is_full_refuses_the_next_record_and_keeps_its_own() {
        let payload = [oam_record(1), oam_record(2)].concat();
        let mut cursor = SceCursor::new(&payload);
        let mut record = new_record_buf();
        assert!(matches!(
            decode_one_record(&mut cursor, &mut record, NO_ORIGIN),
            Ok(true)
        ));
        assert_eq!(record.len(), 1, "the buffer is full");
        assert!(
            matches!(
                decode_one_record(&mut cursor, &mut record, NO_ORIGIN),
                Err(CodecError::TooManyElements)
            ),
            "the second record has nowhere to go"
        );
        assert_eq!(record.len(), 1, "a refusal grows nothing");
        match &record[0] {
            NetworkMessage::Oam(oam) => assert_eq!(oam.id, 1, "and keeps the record it held"),
            other => panic!("unexpected record {other:?}"),
        }
    }

    /// A Push record as a peer sends it, on `key`.
    #[cfg(feature = "codec-push")]
    fn push_record(key: &str) -> Vec<u8> {
        crate::push_build::build_push_literal(key, b"v")
            .expect("build")
            .try_as_borrowed()
            .expect("a view")
            .encode_to_vec()
    }

    /// The lent walk hands a Push over where the payload lies and every other
    /// record owned, in wire order; the owned walk hands the same records owned.
    #[cfg(feature = "codec-push")]
    #[test]
    fn the_lent_walk_lends_each_push_and_owns_the_rest_in_order() {
        let payload = [push_record("a/1"), oam_record(2), push_record("a/3")].concat();
        let mut record = new_record_buf();
        let mut seen: Vec<(char, alloc::string::String)> = Vec::new();
        let result = for_each_record(&payload, &mut record, RecordForm::Lent, |one| match one {
            WalkedRecord::Push(push) => {
                let (_, suffix) = crate::wireexpr_resolve::id_and_suffix_view(&push.keyexpr.body);
                seen.push(('p', suffix.expect("a key").into()));
            }
            WalkedRecord::Owned(one) => match &one[0] {
                NetworkMessage::Oam(o) => seen.push(('o', alloc::format!("{}", o.id))),
                other => panic!("only the OAM is owned: {other:?}"),
            },
            #[allow(unreachable_patterns)]
            _ => panic!("only Pushes and an OAM were encoded"),
        });
        assert!(result.is_ok());
        assert_eq!(
            seen,
            vec![('p', "a/1".into()), ('o', "2".into()), ('p', "a/3".into())]
        );
        // The owned walk owns all three, the Pushes included.
        let mut owned = 0;
        let result = for_each_record(&payload, &mut record, RecordForm::Owned, |one| match one {
            WalkedRecord::Owned(_) => owned += 1,
            _ => panic!("an owned walk lends nothing"),
        });
        assert!(result.is_ok());
        assert_eq!(owned, 3);
    }

    /// The slot profile's walk ([`RecordForm::LentControl`]): every kind this
    /// build decodes is lent where the payload lies, and what no consumer reads is
    /// skipped, so the walk builds no owned message at all.
    #[cfg(all(
        feature = "session-slot",
        feature = "codec-declare",
        feature = "declare-final",
        feature = "codec-response-final"
    ))]
    mod control {
        use super::*;
        use crate::declare_build::{build_declare_final, build_declare_subscriber};
        use crate::interest_build::build_interest_subscribers;
        use crate::parse_error::InboundParseError;
        use wz_codecs::declare::DeclareVariant;
        use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
        use wz_codecs::ext_unit::ExtUnit;

        fn declare_bytes(declare: &wz_codecs::declare::DeclareOwned) -> Vec<u8> {
            declare.try_as_borrowed().expect("a view").encode_to_vec()
        }

        fn interest_bytes(interest: &wz_codecs::interest::InterestOwned) -> Vec<u8> {
            interest.try_as_borrowed().expect("a view").encode_to_vec()
        }

        fn response_final_bytes(done: &wz_codecs::response_final::ResponseFinalOwned) -> Vec<u8> {
            done.try_as_borrowed().expect("a view").encode_to_vec()
        }

        /// A DeclSubscriber of `id` on a literal keyexpr.
        fn subscriber(id: u64) -> Vec<u8> {
            declare_bytes(&build_declare_subscriber(id, 0, Some("a/b")).expect("build"))
        }

        /// A mandatory unit extension no message defines: upstream refuses a
        /// message that carries one.
        fn mandatory_unknown() -> ExtEntryOwned {
            ExtEntryOwned {
                header: 0x1e,
                body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
            }
        }

        /// What the walk handed over, one tag per call: the kind and an id that
        /// names the record.
        fn tag(one: WalkedRecord<'_>) -> (char, u64) {
            match one {
                WalkedRecord::Declare(d) => match &d.body {
                    DeclareVariant::CodecZenohDeclSubscriber(s) => ('s', s.id),
                    DeclareVariant::CodecZenohDeclFinal(_) => ('f', 0),
                    other => panic!("an unexpected declaration {other:?}"),
                },
                WalkedRecord::Interest(i) => ('i', i.interest_id),
                WalkedRecord::ResponseFinal(r) => ('r', r.request_id),
                WalkedRecord::Skipped => ('-', 0),
                WalkedRecord::Owned(_) => panic!("the control walk owns nothing"),
                #[allow(unreachable_patterns)]
                _ => panic!("a kind this test did not encode"),
            }
        }

        fn walk(
            payload: &[u8],
            form: RecordForm,
        ) -> (Vec<(char, u64)>, Result<(), InboundParseError>) {
            let mut record = new_record_buf();
            let mut seen = Vec::new();
            let result = for_each_record(payload, &mut record, form, |one| match one {
                WalkedRecord::Owned(one) => {
                    // The owned walk's own records, tagged the same way so the two
                    // walks can be compared.
                    seen.push(match &one[0] {
                        NetworkMessage::Declare(d) => match &d.body {
                            wz_codecs::declare::DeclareOwnedVariant::CodecZenohDeclSubscriber(
                                s,
                            ) => ('s', s.id),
                            wz_codecs::declare::DeclareOwnedVariant::CodecZenohDeclFinal(_) => {
                                ('f', 0)
                            }
                            other => panic!("an unexpected declaration {other:?}"),
                        },
                        NetworkMessage::Interest(i) => ('i', i.interest_id),
                        NetworkMessage::ResponseFinal(r) => ('r', r.request_id),
                        NetworkMessage::Oam(_) | NetworkMessage::Unknown { .. } => ('-', 0),
                        // The data kinds, in a build that selects their codecs.
                        #[allow(unreachable_patterns)]
                        other => panic!("an unexpected record {other:?}"),
                    });
                }
                other => seen.push(tag(other)),
            });
            (seen, result)
        }

        /// One payload of every kind, in an order that interleaves them.
        fn every_kind() -> Vec<u8> {
            [
                subscriber(7),
                interest_bytes(
                    &build_interest_subscribers(9, true, true, 0, Some("a/**")).expect("build"),
                ),
                response_final_bytes(&crate::response_final_build::build_response_final(
                    5,
                    crate::sample::QosLevel::default(),
                )),
                oam_record(2),
                declare_bytes(&build_declare_final()),
            ]
            .concat()
        }

        #[test]
        fn the_control_walk_lends_every_kind_in_wire_order_and_owns_nothing() {
            let payload = every_kind();
            let (lent, result) = walk(&payload, RecordForm::LentControl);
            assert!(result.is_ok());
            assert_eq!(
                lent,
                vec![('s', 7), ('i', 9), ('r', 5), ('-', 0), ('f', 0)],
                "(kind, id) of each record, an Oam skipped"
            );
            // The owned walk reads the same records in the same order, so the lent
            // one is not a different reading.
            let (owned, result) = walk(&payload, RecordForm::Owned);
            assert!(result.is_ok());
            assert_eq!(owned, lent, "the owned walk reads the same records");
        }

        #[test]
        fn an_unknown_mid_is_skipped_and_ends_the_walk_as_the_owned_walk_ends() {
            // 0x15 is a network MID no codec here decodes; whatever follows it is
            // part of its unknowable body.
            let payload = [subscriber(7), alloc::vec![0x15, 0x01, 0x02], subscriber(8)].concat();
            let (lent, result) = walk(&payload, RecordForm::LentControl);
            assert!(result.is_ok());
            assert_eq!(
                lent,
                vec![('s', 7), ('-', 0)],
                "the tail is one skipped record"
            );
            let (owned, result) = walk(&payload, RecordForm::Owned);
            assert!(result.is_ok());
            assert_eq!(owned, lent, "the owned walk ends where the lent one does");
        }

        #[test]
        fn a_record_that_does_not_decode_ends_the_control_walk_after_the_ones_before_it() {
            let mut payload = subscriber(7);
            payload.push(wire_const::N_MID_DECLARE);
            let (lent, result) = walk(&payload, RecordForm::LentControl);
            assert_eq!(lent, vec![('s', 7)], "the record before it was handed over");
            assert!(
                matches!(result, Err(InboundParseError::Codec(_))),
                "then the walk ends with the decode error: {result:?}"
            );
            let (owned, owned_result) = walk(&payload, RecordForm::Owned);
            assert_eq!(
                (owned, owned_result),
                (lent, result),
                "as the owned walk does"
            );
        }

        /// A mandatory extension nobody defines refuses the message on every kind,
        /// on the lent walk exactly as on the owned one: the same error, after the
        /// same records.
        #[test]
        fn a_mandatory_extension_nobody_defines_refuses_each_control_kind_as_the_owned_walk_does() {
            let before = subscriber(1);
            let declare = {
                let mut d = build_declare_final();
                d.extensions = Some(alloc::vec![mandatory_unknown()]);
                declare_bytes(&d)
            };
            let interest = {
                let mut i = build_interest_subscribers(3, true, true, 0, Some("k")).expect("build");
                i.extensions = Some(alloc::vec![mandatory_unknown()]);
                i.header |= wire_const::FLAG_N_Z;
                interest_bytes(&i)
            };
            let response_final = {
                let mut done = crate::response_final_build::build_response_final(
                    4,
                    crate::sample::QosLevel::default(),
                );
                done.extensions = Some(alloc::vec![mandatory_unknown()]);
                done.header |= wire_const::FLAG_N_Z;
                response_final_bytes(&done)
            };
            let oam = {
                use wz_codecs::ext_entry::{ExtEntry, ExtEntryVariant};
                let mut chain = sce_forge_runtime::heapless::Vec::new();
                let _ = chain.push(ExtEntry {
                    header: 0x1e,
                    body: ExtEntryVariant::CodecZenohExtUnit(ExtUnit::default()),
                });
                wz_codecs::oam::Oam {
                    header: wire_const::N_MID_OAM | wire_const::FLAG_N_Z,
                    id: 6,
                    extensions: Some(chain),
                    ..Default::default()
                }
                .encode_to_vec()
            };
            for (name, bad) in [
                ("declare", declare),
                ("interest", interest),
                ("response final", response_final),
                ("oam", oam),
            ] {
                let payload = [before.clone(), bad].concat();
                let (lent, lent_result) = walk(&payload, RecordForm::LentControl);
                let (owned, owned_result) = walk(&payload, RecordForm::Owned);
                assert_eq!(
                    lent,
                    vec![('s', 1)],
                    "{name}: the record before it was handed over"
                );
                assert!(
                    matches!(
                        lent_result,
                        Err(InboundParseError::UnknownMandatoryExt { .. })
                    ),
                    "{name}: the lent walk refuses: {lent_result:?}"
                );
                assert_eq!(
                    (owned, owned_result),
                    (lent, lent_result),
                    "{name}: the owned walk refuses alike"
                );
            }
        }
    }

    /// A Push whose own chain carries an unknown MANDATORY extension ends the
    /// walk at that record with the same refusal on both forms, after the
    /// records before it.
    #[cfg(feature = "codec-push")]
    #[test]
    fn a_push_a_participant_must_refuse_ends_both_walks_at_the_same_record() {
        let plain = push_record("a/1");
        let built = crate::push_build::build_push_literal("a/2", b"v").expect("build");
        let mut refused = built.try_as_borrowed().expect("a view");
        // Id 0xF, mandatory (0x10), unit encoding: defined by no network message.
        let mut chain = sce_forge_runtime::heapless::Vec::new();
        let _ = chain.push(wz_codecs::ext_entry::ExtEntry {
            header: 0x10 | 0x0F,
            body: wz_codecs::ext_entry::ExtEntryVariant::CodecZenohExtUnit(Default::default()),
        });
        refused.extensions = Some(chain);
        refused.header |= 0x80;
        let payload = [plain, refused.encode_to_vec(), push_record("a/3")].concat();
        let walk = |form| {
            let mut record = new_record_buf();
            let mut handed = 0;
            let result = for_each_record(&payload, &mut record, form, |_| handed += 1);
            (handed, alloc::format!("{result:?}"))
        };
        let lent = walk(RecordForm::Lent);
        assert_eq!(lent.0, 1, "the record before it was handed over");
        assert!(lent.1.contains("UnknownMandatoryExt"), "{}", lent.1);
        assert_eq!(lent, walk(RecordForm::Owned), "the owned walk stops alike");
    }

    /// The lent walk lends a Request and a Response where the payload lies and
    /// owns the rest, in wire order, and the owned walk owns all of them; a
    /// Request or a Response a participant must refuse ends both walks at the
    /// same record, after the records before it.
    #[cfg(all(feature = "codec-request", feature = "codec-response"))]
    #[test]
    fn the_lent_walk_lends_requests_and_responses_and_refuses_them_alike() {
        let request = crate::request_build::RequestQueryBuilder::new(3, 0, Some("q/1"))
            .build()
            .expect("build");
        let response = crate::response_build::ResponseReplyBuilder::new(3, 0, Some("q/1"), b"v")
            .build()
            .expect("build");
        let rq = request.try_as_borrowed().expect("a view").encode_to_vec();
        let rs = response.try_as_borrowed().expect("a view").encode_to_vec();
        let payload = [rq.clone(), oam_record(2), rs.clone()].concat();
        let mut record = new_record_buf();
        let mut seen: Vec<char> = Vec::new();
        let result = for_each_record(&payload, &mut record, RecordForm::Lent, |one| match one {
            WalkedRecord::Request(request) => {
                assert_eq!(request.rid, 3);
                seen.push('q');
            }
            WalkedRecord::Response(response) => {
                assert_eq!(response.request_id, 3);
                seen.push('r');
            }
            WalkedRecord::Owned(one) => match &one[0] {
                NetworkMessage::Oam(_) => seen.push('o'),
                other => panic!("only the OAM is owned: {other:?}"),
            },
            #[allow(unreachable_patterns)]
            _ => panic!("no Push was encoded"),
        });
        assert!(result.is_ok());
        assert_eq!(seen, vec!['q', 'o', 'r']);
        let mut owned = 0;
        let result = for_each_record(&payload, &mut record, RecordForm::Owned, |one| match one {
            WalkedRecord::Owned(_) => owned += 1,
            _ => panic!("an owned walk lends nothing"),
        });
        assert!(result.is_ok());
        assert_eq!(owned, 3);

        // Id 0xF, mandatory (0x10), unit encoding: defined by no network message.
        let unknown = || {
            let mut chain = sce_forge_runtime::heapless::Vec::new();
            let _ = chain.push(wz_codecs::ext_entry::ExtEntry {
                header: 0x10 | 0x0F,
                body: wz_codecs::ext_entry::ExtEntryVariant::CodecZenohExtUnit(Default::default()),
            });
            chain
        };
        let mut bad_request = request.try_as_borrowed().expect("a view");
        bad_request.extensions = Some(unknown());
        bad_request.header |= 0x80;
        let mut bad_response = response.try_as_borrowed().expect("a view");
        bad_response.extensions = Some(unknown());
        bad_response.header |= 0x80;
        for bad in [bad_request.encode_to_vec(), bad_response.encode_to_vec()] {
            let payload = [rq.clone(), bad, rs.clone()].concat();
            let walk = |form| {
                let mut record = new_record_buf();
                let mut handed = 0;
                let result = for_each_record(&payload, &mut record, form, |_| handed += 1);
                (handed, alloc::format!("{result:?}"))
            };
            let lent = walk(RecordForm::Lent);
            assert_eq!(lent.0, 1, "the record before it was handed over");
            assert!(lent.1.contains("UnknownMandatoryExt"), "{}", lent.1);
            assert_eq!(lent, walk(RecordForm::Owned), "the owned walk stops alike");
        }
    }

    #[test]
    fn an_unknown_mid_is_handed_over_with_the_rest_and_ends_the_walk() {
        // MID 0x01 has no envelope decoder: its length is unknowable, so it
        // and the OAM after it are one absorbed record, as in the batch decode.
        let payload = [oam_record(4), vec![0x01, 0xAB], oam_record(5)].concat();
        let (seen, result) = walk(&payload);
        assert!(result.is_ok());
        assert_eq!(seen, vec![('o', 4), ('u', 1)]);
        let batch = parse_frame_payload(&payload).expect("the batch decodes");
        assert!(
            matches!(&batch[1], NetworkMessage::Unknown { mid: 1, body } if body.len() == payload.len() - oam_record(4).len()),
            "the batch decode absorbs the same tail: {batch:?}"
        );
    }
}

#[cfg(all(test, feature = "codec-frame"))]
mod best_effort_batch_tests {
    use super::*;
    use alloc::vec;

    /// One encoded OAM record. `Oam::default()`'s header carries its own
    /// wire MID (`0x1F`), so the fixture is a real record through the real
    /// encoder rather than a hand-typed byte string.
    fn oam_record(id: u64) -> Vec<u8> {
        wz_codecs::oam::Oam {
            id,
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn oam_ids(messages: &[NetworkMessage]) -> Vec<u64> {
        messages
            .iter()
            .filter_map(|m| match m {
                NetworkMessage::Oam(o) => Some(o.id),
                _ => None,
            })
            .collect()
    }

    /// A clean batch: both parsers agree, and the best-effort one reports
    /// no halt. Without this the halt assertions below could be satisfied
    /// by a parser that always halts.
    #[test]
    fn a_clean_batch_parses_identically_under_both_contracts() {
        let mut wire = oam_record(7);
        wire.extend_from_slice(&oam_record(8));

        let strict = parse_frame_payload(&wire).expect("clean batch");
        let best = parse_frame_payload_best_effort(&wire);

        assert_eq!(oam_ids(&strict), vec![7, 8]);
        assert_eq!(oam_ids(&best.messages), vec![7, 8]);
        assert!(best.is_complete(), "no halt on a clean batch");
        assert_eq!(best.halt, None);
        assert_eq!(best.unparsed_bytes, 0);
    }

    /// An empty payload is a valid EMPTY batch under both contracts — not
    /// a halt. A dissector that reported "unparsed" here would flag every
    /// keepalive-shaped frame.
    #[test]
    fn an_empty_payload_is_a_complete_empty_batch() {
        let best = parse_frame_payload_best_effort(&[]);
        assert!(best.messages.is_empty());
        assert!(best.is_complete());
        assert_eq!(best.unparsed_bytes, 0);
    }

    /// THE CASE G4 EXISTS FOR. A truncated trailing record makes the
    /// strict parse discard the whole batch — correct for a participant,
    /// for which a half-record means the two ends lost sync. An observer
    /// reading a capture whose tail was cut still has the earlier records,
    /// and they are exactly as real as they were.
    ///
    /// The two arms run over the SAME bytes, so the difference is the
    /// contract and nothing else.
    #[test]
    fn a_truncated_tail_loses_the_whole_batch_strictly_and_keeps_the_prefix_best_effort() {
        let first = oam_record(7);
        let second = oam_record(8);
        let mut wire = first.clone();
        // Keep only the second record's header byte: enough to dispatch on
        // the MID, not enough to decode the body.
        wire.push(second[0]);

        // Participant: everything is lost.
        assert!(
            parse_frame_payload(&wire).is_err(),
            "the strict contract fails the whole batch on a truncated record"
        );

        // Observer: the readable prefix survives, with a typed marker for
        // where the payload stopped being readable.
        let best = parse_frame_payload_best_effort(&wire);
        assert_eq!(
            oam_ids(&best.messages),
            vec![7],
            "the record that DID decode is kept"
        );
        assert!(!best.is_complete());
        match best.halt {
            Some(BatchHalt::CodecError { offset, error }) => {
                assert_eq!(
                    offset,
                    first.len(),
                    "the halt points at the failing record's own header, not at the \
                     cursor's high-water mark"
                );
                assert_eq!(
                    error,
                    CodecError::NeedMoreBytes,
                    "a truncated capture is NeedMoreBytes, which is why the error \
                     value is carried rather than flattened to a bool"
                );
            }
            other => panic!("expected a CodecError halt, got {other:?}"),
        }
        assert_eq!(best.unparsed_bytes, 1, "the lone header byte is unparsed");
    }

    /// An unknown MID mid-batch: both contracts absorb the tail as
    /// `Unknown` and stop (its length is unknowable, so there is nothing
    /// to resynchronise on), but only the best-effort one says WHERE.
    ///
    /// `0x00` is outside the seven-wide network MID set on purpose — the
    /// authored catalog covers all seven, so a meaningful Unknown fixture
    /// has to be synthetic.
    #[test]
    fn an_unknown_mid_halts_with_its_offset_under_both_contracts() {
        let first = oam_record(7);
        let mut wire = first.clone();
        wire.extend_from_slice(&[0x00, 0xAB, 0xCD]);

        let strict = parse_frame_payload(&wire).expect("unknown MID absorbs, not errors");
        assert_eq!(oam_ids(&strict), vec![7]);
        assert!(matches!(
            strict.last(),
            Some(NetworkMessage::Unknown { mid: 0x00, .. })
        ));

        let best = parse_frame_payload_best_effort(&wire);
        assert_eq!(oam_ids(&best.messages), vec![7]);
        match best.messages.last() {
            Some(NetworkMessage::Unknown { mid, body }) => {
                assert_eq!(*mid, 0x00);
                assert_eq!(
                    body.as_slice(),
                    &[0x00, 0xAB, 0xCD],
                    "the absorbed body starts AT the unknown header, not after it"
                );
            }
            other => panic!("expected a trailing Unknown, got {other:?}"),
        }
        assert_eq!(
            best.halt,
            Some(BatchHalt::UnknownMid {
                mid: 0x00,
                offset: first.len()
            })
        );
        assert_eq!(best.unparsed_bytes, 3);
    }

    /// The two walks share ONE per-MID dispatch (`decode_one_record`), so
    /// a build's codec selection cannot differ between them. Asserted over
    /// a batch of every record kind this build decodes: the strict and
    /// best-effort message sequences must be identical whenever the strict
    /// parse succeeds at all.
    #[test]
    fn both_walks_decode_the_same_records() {
        let mut wire = Vec::new();
        for id in 0..4u64 {
            wire.extend_from_slice(&oam_record(id));
        }
        let strict = parse_frame_payload(&wire).expect("clean batch");
        let best = parse_frame_payload_best_effort(&wire);
        assert_eq!(oam_ids(&strict), oam_ids(&best.messages));
        assert_eq!(strict.len(), best.messages.len());
        assert!(best.is_complete());
    }
}

// ── R311y804 — the Z-flagged DECLARATION-BODY ext chain, and why every
//    assertion below is about the SECOND record.
//
//    Each declaration body carries a `Z` bit at header bit 7 meaning "an
//    extension chain follows", and both upstreams consume it unconditionally:
//    zenoh loops `extension::skip` / `skip_all` per body
//    (zenoh-codec/src/network/declare.rs — :319 DeclareKeyExpr, :377
//    UndeclareKeyExpr, :452 DeclareSubscriber, :826 DeclareToken, :255 Final),
//    and pico calls `_z_msg_ext_skip_non_mandatories` / `_z_msg_ext_decode_iter`
//    at the same five sites (src/protocol/codec/declarations.c:181-191,
//    :192-200, :259-267, :301-309, :314-321). wz consumed it on the four bodies
//    that carry an ext of their OWN (the queryable info, the sourced
//    `ext_keyexpr`) and on none of these five.
//
//    A test that only asserts the Z-flagged record itself decodes proves
//    NOTHING — the old decoder returned `Ok` too, having simply stopped early.
//    What the unconsumed bytes cost is the REST OF THE BATCH: a batch is a run
//    of self-delimiting records with no per-record length prefix (see
//    `BatchHalt`'s header above), so record N+1 is found only by having fully
//    decoded record N. Each test therefore puts a second, ordinary
//    `Declare(UndeclKexpr id = 42)` after the Z-flagged one and asserts THAT
//    survives. Before this round every one of them read the ext header byte
//    `0x21` as a network MID (`0x21 & 0x1F == 0x01`, which is no N_MID),
//    absorbed the remainder as `Unknown`, and lost the second record.
//
//    The fixtures are hand-assembled bytes on purpose: wz's own builders write
//    Z=0 on all five bodies, as do both upstreams' 1.5.0 writers, so an
//    encode-then-decode round trip could not reach the arm under test. These
//    bytes are what a peer with one extension more than this revision knows
//    about puts on the wire. ──
#[cfg(all(test, feature = "codec-frame", feature = "codec-declare"))]
mod declare_body_ext_chain_tests {
    use super::*;

    /// A terminal ZINT extension: id 1, `enc = ZINT` (`0b01 << 5`), no `M`, no
    /// `Z` — so the chain ends here — carrying VLE(42).
    const TERMINAL_ZINT_EXT: [u8; 2] = [0x21, 0x2A];

    /// The mapping id of the record every test appends AFTER the Z-flagged one.
    const SENTINEL_ID: u64 = 42;

    /// That record: a plain `Declare(UndeclKexpr)`, two bytes of body, no flags,
    /// nothing shared with the record before it — so decoding it back out with
    /// the right id is not something a desynchronised cursor produces.
    fn sentinel_record() -> Vec<u8> {
        alloc::vec![wire_const::N_MID_DECLARE, 0x01, SENTINEL_ID as u8]
    }

    /// `[Declare(<z_flagged_body>), Declare(UndeclKexpr 42)]`.
    fn batch_after(z_flagged_body: &[u8]) -> Vec<u8> {
        let mut wire = alloc::vec![wire_const::N_MID_DECLARE];
        wire.extend_from_slice(z_flagged_body);
        wire.extend_from_slice(&sentinel_record());
        wire
    }

    /// The shared assertion: two records came back, and the SECOND is the
    /// sentinel with its id intact.
    fn assert_sentinel_survived(wire: &[u8], what: &str) -> Vec<NetworkMessage> {
        let msgs = parse_frame_payload(wire)
            .unwrap_or_else(|e| panic!("{what}: the batch must parse, got {e:?}"));
        assert_eq!(
            msgs.len(),
            2,
            "{what}: the Z-flagged body swallowed the record after it"
        );
        match &msgs[1] {
            NetworkMessage::Declare(d) => match &d.body {
                wz_codecs::declare::DeclareOwnedVariant::CodecZenohUndeclKexpr(u) => {
                    assert_eq!(
                        u.id, SENTINEL_ID,
                        "{what}: the second record decoded at the wrong offset"
                    );
                }
                other => panic!("{what}: expected the sentinel UndeclKexpr, got {other:?}"),
            },
            other => panic!("{what}: expected a Declare, got {other:?}"),
        }
        msgs
    }

    /// DeclSubscriber, and the one fixture with a MULTI-entry chain: the first
    /// entry sets its own `Z` (0x80) so the loop must run twice. A decoder that
    /// consumed exactly one entry fails here while passing every single-entry
    /// sibling below.
    #[test]
    fn a_z_flagged_decl_subscriber_does_not_swallow_the_next_record() {
        let body = alloc::vec![
            0x02 | 0x80, // DeclSubscriber MID 0x02 | Z
            0x07,        // subscriber id
            0x00,        // wireexpr mapping id (N=0, so no suffix)
            0xA1,        // ext id 1, ZINT, Z set -> one more follows
            0x2A,        // VLE(42)
            0x22,        // ext id 2, ZINT, terminal
            0x07,        // VLE(7)
        ];
        let msgs = assert_sentinel_survived(&batch_after(&body), "decl_subscriber");
        match &msgs[0] {
            NetworkMessage::Declare(d) => match &d.body {
                wz_codecs::declare::DeclareOwnedVariant::CodecZenohDeclSubscriber(s) => {
                    assert_eq!(
                        s.extensions.as_ref().map_or(0, |e| e.len()),
                        2,
                        "both chain entries must be held, not skipped"
                    );
                }
                other => panic!("expected a DeclSubscriber, got {other:?}"),
            },
            other => panic!("expected a Declare, got {other:?}"),
        }
    }

    #[test]
    fn a_z_flagged_decl_token_does_not_swallow_the_next_record() {
        let mut body = alloc::vec![
            0x06 | 0x80, // DeclToken MID 0x06 | Z
            0x09,        // token id
            0x00,        // wireexpr mapping id (N=0)
        ];
        body.extend_from_slice(&TERMINAL_ZINT_EXT);
        assert_sentinel_survived(&batch_after(&body), "decl_token");
    }

    /// DeclKexpr is the sharper of the two bodies that did not model bit 7 at
    /// all — the flag was absent from `decl_kexpr.scxml`, so there was no `z()`
    /// accessor to have ignored.
    #[test]
    // R311y806 — the `<MID> | 0x80` spelling is what makes this group of hand-
    // assembled fixtures readable: each names its declaration MID and then sets
    // bit 7. DeclKexpr's MID is 0x00, so clippy reads the OR as an identity and
    // asks for a bare `0x80` — which would leave this the one fixture in the
    // group that does not say which body it is. The lint is right about the
    // arithmetic and wrong about the intent, so it is silenced HERE rather than
    // the byte being collapsed. R311y804 shipped this and the `--all-features`
    // clippy lane (C1bf) reddened on it hosted.
    #[allow(clippy::identity_op)]
    fn a_z_flagged_decl_kexpr_does_not_swallow_the_next_record() {
        let mut body = alloc::vec![
            0x00 | 0x80, // DeclKexpr MID 0x00 | Z (N=0)
            0x03,        // mapping id
            0x00,        // wireexpr mapping id
        ];
        body.extend_from_slice(&TERMINAL_ZINT_EXT);
        assert_sentinel_survived(&batch_after(&body), "decl_kexpr");
    }

    /// UndeclKexpr had the `Z` flag declared with no chain behind it, which is
    /// the shape that reads as deliberate and is not: its three Undecl_*
    /// siblings all consume a chain because their SOURCED form rides one, and
    /// this body has no ext of its own to have prompted the same work.
    #[test]
    fn a_z_flagged_undecl_kexpr_does_not_swallow_the_next_record() {
        let mut body = alloc::vec![
            0x01 | 0x80, // UndeclKexpr MID 0x01 | Z
            0x05,        // mapping id
        ];
        body.extend_from_slice(&TERMINAL_ZINT_EXT);
        assert_sentinel_survived(&batch_after(&body), "undecl_kexpr");
    }

    #[test]
    fn a_z_flagged_decl_final_does_not_swallow_the_next_record() {
        let mut body = alloc::vec![0x1A | 0x80]; // DeclFinal MID 0x1A | Z
        body.extend_from_slice(&TERMINAL_ZINT_EXT);
        assert_sentinel_survived(&batch_after(&body), "decl_final");
    }

    /// An UNKNOWN declaration MID with a chain, decoded through the `DeclFinal`
    /// catch-all arm. wz ABSORBS an unknown declaration where both upstreams
    /// reject the whole message, so wz is the implementation for which
    /// consuming the chain changes an outcome rather than tidying one.
    #[test]
    fn an_unknown_declaration_kind_with_a_chain_does_not_swallow_the_next_record() {
        // MID 0x0B is in no `declare::id::*` upstream and no wz arm.
        let mut body = alloc::vec![0x0B | 0x80];
        body.extend_from_slice(&TERMINAL_ZINT_EXT);
        assert_sentinel_survived(&batch_after(&body), "unknown declaration kind");
    }

    /// wz HOLDS the chain where both upstreams DISCARD it (zenoh's `skip`,
    /// pico's `skip_non_mandatories`), so a decoded body re-encodes to the bytes
    /// it came from. That is a superset of upstream behaviour, and it separates
    /// "the chain is consumed" from "the chain is modelled" — a skip-only
    /// decoder passes every test above and fails this one.
    #[test]
    fn a_decoded_z_flagged_body_re_encodes_to_the_bytes_it_came_from() {
        use sce_forge_runtime::codec::SceCursor;
        let wire = alloc::vec![
            wire_const::N_MID_DECLARE,
            0x02 | 0x80, // DeclSubscriber | Z
            0x07,
            0x00,
            0x21,
            0x2A,
        ];
        let mut cursor = SceCursor::new(&wire);
        let decoded = wz_codecs::declare::Declare::decode(&mut cursor).expect("decode");
        assert_eq!(
            cursor.remaining(),
            0,
            "the decode left the extension bytes on the cursor"
        );
        assert_eq!(decoded.encode_to_vec(), wire);
    }
}

// ── R2825 (open-debt item 820) — payload SIZE is upstream's `payload_size()`:
//    the payload plus the attachment, a Del its attachment alone, a Query the
//    value in its body extension without the encoding, never its parameters. ──
#[cfg(all(
    test,
    feature = "transport-stats",
    feature = "codec-push",
    feature = "codec-request"
))]
mod payload_size_tests {
    use super::*;
    use crate::ext_header::body_ext_id;
    use crate::wire::parts::{ExtEntryOwned, ExtEntryOwnedVariant, ExtZbufOwned, MsgPutOwned};
    use crate::wire::wire_bytes as owned_bytes;

    /// A ZBUF extension `id` carrying `value` — the shape an attachment and a
    /// query value both have on the wire (`ENC_ZBUF` in the header's high bits).
    fn zbuf_ext(id: u8, value: &[u8]) -> ExtEntryOwned {
        ExtEntryOwned {
            header: 0x40 | id,
            body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                value_len: value.len() as u64,
                value: owned_bytes(value).expect("alloc profile"),
            }),
        }
    }

    /// An inline Put of twelve payload bytes carrying `exts` in its chain.
    fn twelve_byte_put_with(exts: alloc::vec::Vec<ExtEntryOwned>) -> MsgPutOwned {
        let mut put: MsgPutOwned =
            crate::put_payload::inline(b"twelve bytes").expect("a literal put");
        for ext in exts {
            put.extensions
                .get_or_insert_with(Default::default)
                .push(ext);
        }
        put
    }

    #[test]
    fn a_put_counts_its_payload_and_its_attachment() {
        let with = twelve_byte_put_with(alloc::vec![zbuf_ext(
            body_ext_id::PUT_ATTACHMENT,
            b"attached"
        )]);
        assert_eq!(put_payload_size(&with), 12 + 8);
        assert_eq!(put_payload_size(&twelve_byte_put_with(alloc::vec![])), 12);
        // The Del's id on a Put body is not the Put's attachment.
        let wrong = twelve_byte_put_with(alloc::vec![zbuf_ext(
            body_ext_id::DEL_ATTACHMENT,
            b"attached"
        )]);
        assert_eq!(put_payload_size(&wrong), 12);
    }

    #[test]
    fn a_del_counts_its_attachment_alone() {
        let exts = alloc::vec![zbuf_ext(body_ext_id::DEL_ATTACHMENT, b"four")];
        assert_eq!(del_payload_size(Some(&exts)), 4);
        assert_eq!(del_payload_size(None), 0);
    }

    /// A Query's size is its VALUE's payload — the encoding in front of it is
    /// not counted — plus its attachment. Parameters are not an extension and
    /// cannot reach this function at all, which is the point.
    #[test]
    fn a_query_counts_its_value_payload_and_attachment_not_its_encoding() {
        let encoding = crate::encoding::encoding_from_mime("text/plain;utf-8");
        let mut value = encoding.to_codec().encode_to_vec();
        let encoding_len = value.len();
        value.extend_from_slice(b"value!");
        let exts: alloc::vec::Vec<_> = [
            zbuf_ext(body_ext_id::QUERY_BODY, &value),
            zbuf_ext(body_ext_id::QUERY_ATTACHMENT, b"xyz"),
        ]
        .into_iter()
        .map(crate::ext_view::query_ext_from_generic)
        .collect();
        assert!(
            encoding_len > 1,
            "the encoding really occupies bytes to leave out"
        );
        assert_eq!(query_payload_size(Some(&exts)), 6 + 3);
        assert_eq!(query_payload_size(None), 0);
    }

    /// The classifier a Push goes through uses these sizes: a literal Put with
    /// an attachment appended classifies at payload + attachment.
    #[test]
    fn the_push_classifier_sizes_with_the_attachment() {
        use wz_codecs::push::PushOwnedVariant as V;
        let mut push = crate::push_build::build_push_literal("demo/size", b"twelve bytes")
            .expect("build a literal put");
        match &mut push.body {
            V::CodecZenohMsgPut(b) | V::Default { body: b, .. } => {
                b.extensions
                    .get_or_insert_with(Default::default)
                    .push(zbuf_ext(body_ext_id::PUT_ATTACHMENT, b"attached"));
            }
            V::CodecZenohMsgDel(_) => unreachable!("a literal put"),
        }
        let class = push_stats_class(&push, |_| None);
        assert_eq!(class.kind, Some(crate::stats::MessageLabel::Put));
        assert_eq!(class.payload.map(|p| p.pl_bytes), Some(12 + 8));
    }
}

// ── R3011 (open-debt item 850) — the receive walk can SHARE the frame it decodes
//    from. The pin's origin seam is only worth having if a decoded payload really
//    is a range of the frame: `subrange_of` is address-based, so a walk over a COPY
//    of the frame would decode correctly and share nothing, and no value-level
//    assertion would notice. These tests read the ADDRESS. ──
#[cfg(all(test, feature = "rx-shared-bytes", feature = "codec-push"))]
mod shared_decode_tests {
    use super::*;
    use crate::link::RxBytes;
    use wz_codecs_test_support::TestWire;

    const PAYLOAD: &[u8] = b"shared-payload";

    /// The batch a Frame would carry: one literal Put.
    fn batch() -> Vec<u8> {
        crate::push_build::build_push_literal("demo/x", PAYLOAD)
            .expect("build a literal put")
            .wire()
    }

    fn push_payload(message: &NetworkMessage) -> &[u8] {
        let NetworkMessage::Push(push) = message else {
            panic!("the batch is one Push, got {message:?}");
        };
        let crate::wire::PushOwnedVariant::CodecZenohMsgPut(put) = &push.body else {
            panic!("a literal put carries a Put body");
        };
        crate::put_payload::inline_bytes(put).expect("an inline Put")
    }

    fn lies_within(whole: &[u8], part: &[u8]) -> bool {
        whole.as_ptr_range().contains(&part.as_ptr())
    }

    /// Whether the message's payload is a range of lent storage rather than
    /// bytes it owns: what `RxSharedBytes::is_shared` answers.
    fn payload_is_lent(message: &NetworkMessage) -> bool {
        let NetworkMessage::Push(push) = message else {
            panic!("the batch is Pushes, got {message:?}");
        };
        let crate::wire::PushOwnedVariant::CodecZenohMsgPut(put) = &push.body else {
            panic!("a literal put carries a Put body");
        };
        put.payload.as_ref().expect("an inline Put").is_shared()
    }

    /// A completed reassembly chain is a BORROWED slice, a slot the reassembler
    /// reuses the moment the completion returns, so what is decoded out of it
    /// must not point there. It is copied once into a lent buffer and every
    /// message is a range of that one copy: the payloads are lent (and not
    /// owned, as the copying walk's are), lie outside the borrowed bytes, and
    /// survive the slot being overwritten.
    #[test]
    fn a_batch_that_is_only_a_slice_is_decoded_into_one_copy_the_messages_share() {
        let mut slot = batch();
        slot.extend_from_slice(&batch());
        let messages = parse_frame_payload_lending(&slot).expect("the batch parses");
        assert_eq!(messages.len(), 2);
        for message in &messages {
            assert!(payload_is_lent(message), "a range of the one lent copy");
            assert!(
                !lies_within(&slot, push_payload(message)),
                "a copy of its own, not a slice of the slot it was reassembled in"
            );
        }
        slot.fill(0);
        for message in &messages {
            assert_eq!(
                push_payload(message),
                PAYLOAD,
                "the slot is reused; the messages must not notice"
            );
        }
        // The control: the copying walk over the same slice owns each payload.
        let copied = parse_frame_payload(&batch()).expect("the batch parses");
        assert!(
            !payload_is_lent(&copied[0]),
            "the copying walk's payload is owned"
        );
    }

    /// The discriminator: a lent frame decodes to a payload that sits INSIDE the
    /// frame's own bytes, and the message holds the storage, so the frame handle
    /// can go while the payload stays readable. Replacing the origin with `None`
    /// in `parse_frame_payload_in` copies the payload out and reds the address
    /// check.
    #[test]
    fn a_walk_over_a_lent_frame_decodes_its_payload_as_a_range_of_that_frame() {
        let frame = RxBytes::lend(batch());
        assert!(frame.is_shared(), "the premise: this frame is lent storage");
        let messages = parse_frame_payload_in(&frame).expect("the batch parses");
        assert_eq!(messages.len(), 1);
        assert_eq!(push_payload(&messages[0]), PAYLOAD);
        assert!(
            lies_within(frame.as_slice(), push_payload(&messages[0])),
            "the payload must be a range of the frame, not a copy of it"
        );
        drop(frame);
        assert_eq!(
            push_payload(&messages[0]),
            PAYLOAD,
            "the message keeps the storage alive after the frame handle is gone"
        );
    }

    /// The control: the copying walk over the same bytes puts the payload
    /// OUTSIDE them. Without this, the address check above could pass for a
    /// reason that has nothing to do with sharing.
    #[test]
    fn the_copying_walk_over_the_same_bytes_does_not_share_them() {
        let bytes = batch();
        let messages = parse_frame_payload(&bytes).expect("the batch parses");
        assert_eq!(push_payload(&messages[0]), PAYLOAD);
        assert!(
            !lies_within(&bytes, push_payload(&messages[0])),
            "the copying walk owns its payload"
        );
    }

    /// An OWNED frame has no storage to share, so its sub-ranges are copies: the
    /// cost the owned arm always had, stated so a change to it is a decision.
    #[test]
    fn a_walk_over_an_owned_frame_copies_because_there_is_nothing_to_share() {
        let frame = RxBytes::from(batch());
        assert!(!frame.is_shared(), "the premise: this frame is owned");
        let messages = parse_frame_payload_in(&frame).expect("the batch parses");
        assert_eq!(push_payload(&messages[0]), PAYLOAD);
        assert!(!lies_within(frame.as_slice(), push_payload(&messages[0])));
    }

    /// The Response arm is projected through the same macro with its own call
    /// site, so it is witnessed on its own: a Reply's Put payload is a range of
    /// the lent frame too.
    #[cfg(feature = "codec-response")]
    #[test]
    fn a_reply_put_payload_is_a_range_of_the_lent_frame() {
        let bytes = crate::response_build::build_response_reply_literal(7, "demo/q", PAYLOAD)
            .expect("build a literal reply")
            .wire();
        let frame = RxBytes::lend(bytes);
        let messages = parse_frame_payload_in(&frame).expect("the batch parses");
        let NetworkMessage::Response(response) = &messages[0] else {
            panic!("the batch is one Response, got {:?}", messages[0]);
        };
        let crate::wire::ResponseOwnedVariant::CodecZenohReply(reply) = &response.body else {
            panic!("a literal reply carries a Reply body");
        };
        let crate::wire::parts::ReplyOwnedVariant::CodecZenohMsgPut(put) = &reply.body else {
            panic!("a literal reply carries a Put");
        };
        let payload = crate::put_payload::inline_bytes(put).expect("an inline Put");
        assert_eq!(payload, PAYLOAD);
        assert!(lies_within(frame.as_slice(), payload));
    }
}

// The statistics classifier sizes an attachment by the extension upstream counts
// as the attachment, which is told by its identity and not by the id field
// (`commons/zenoh-codec/src/zenoh/put.rs` @ `Ok(match iext::eid(ext) {`).
#[cfg(all(
    test,
    feature = "transport-stats",
    feature = "alloc",
    feature = "attachment-bytes",
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response"
    )
))]
mod attachment_identity_tests {
    use super::*;
    use crate::ext_header::{body_eid, lookalike_headers};

    #[test]
    fn an_extension_of_the_attachments_id_is_not_sized_as_the_attachment() {
        let entry = |header: u8| {
            let mut e = crate::attachment::encode_attachment_ext::<crate::wire::WireStorage>(
                crate::attachment::ATTACHMENT_EXT_ID_QUERY,
                &[0xAB; 3],
            )
            .unwrap();
            e.header = header;
            e
        };
        assert_eq!(
            zbuf_ext_len(
                Some(&[entry(body_eid::QUERY_ATTACHMENT)][..]),
                body_eid::QUERY_ATTACHMENT
            ),
            3
        );
        for header in lookalike_headers(body_eid::QUERY_ATTACHMENT).filter(|h| (h >> 5) & 3 == 2) {
            assert_eq!(
                zbuf_ext_len(Some(&[entry(header)][..]), body_eid::QUERY_ATTACHMENT),
                0,
                "{header:#04x} shares only the id with the attachment"
            );
        }
    }
}

// The mandatory-extension rule for the network messages and the zenoh bodies:
// every header a chain entry can have, on every chain, against the extensions
// upstream's reader of that message defines. A message whose chain holds an
// extension its reader does not define, with the M bit set, is refused whole
// (`commons/zenoh-codec/src/common/extension.rs` @ `if u.is_mandatory() {`), and
// one with the M bit clear is skipped. The extension is told by its identity,
// the header without the chain flag, so a defined id in another shape is another
// extension.
#[cfg(all(
    test,
    feature = "codec-push",
    feature = "codec-request",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "codec-declare",
    feature = "declare-final"
))]
mod mandatory_extension_rule_tests {
    use super::*;
    use crate::ext_admit::ExtAdmission;
    use crate::wire::WireStorage;
    use sce_forge_runtime::codec::{CodecStorage, SceByteBuf};
    use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
    use wz_codecs::ext_unit::ExtUnit;
    use wz_codecs::ext_zbuf::ExtZbufOwned;
    use wz_codecs::ext_zint::ExtZint;

    /// Every header a chain entry can have without the chain flag, with the
    /// reserved encoding left out: it has no body shape to build.
    fn headers() -> impl Iterator<Item = u8> {
        (0u8..0x80).filter(|h| (h >> 5) & 3 != 3)
    }

    /// One generic entry with `header` and the body its encoding needs.
    fn entry<S: CodecStorage>(header: u8) -> ExtEntryOwned<S> {
        let body = match (header >> 5) & 3 {
            0 => ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
            1 => ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint { value: 0 }),
            _ => ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                value_len: 0,
                value: <S::Bytes<32> as SceByteBuf>::from_slice(&[]).expect("an empty body"),
            }),
        };
        ExtEntryOwned { header, body }
    }

    /// One Query-chain entry: the generic one moved into the Query's own kind.
    fn query_entry(header: u8) -> crate::wire::parts::QueryExtEntryOwned {
        crate::ext_view::query_ext_from_generic(entry::<WireStorage>(header))
    }

    /// The verdict upstream's reader gives a chain of this one entry: refused when
    /// it is mandatory and the message does not define it.
    fn expected(defined_mandatory: &[u8], header: u8) -> ExtAdmission {
        if header & crate::ext_header::EXT_FLAG_M != 0 && !defined_mandatory.contains(&header) {
            ExtAdmission::UnknownMandatory { eid: header }
        } else {
            ExtAdmission::Admissible
        }
    }

    /// Runs every header through `place`, which puts it on one chain of one
    /// message, and checks the verdict against `defined_mandatory`.
    fn every_header(name: &str, defined_mandatory: &[u8], place: impl Fn(u8) -> NetworkMessage) {
        for header in headers() {
            assert_eq!(
                place(header).ext_admission(),
                expected(defined_mandatory, header),
                "{name}: {header:#04x}"
            );
        }
    }

    /// The node id (`zextz64!(0x3, true)`) and the target (`zextz64!(0x4, true)`).
    const NODE_ID: u8 = 0x33;
    const TARGET: u8 = 0x34;
    /// The wire expression (`zextzbuf!(0x0f, true)`).
    const WIRE_EXPR: u8 = 0x5F;
    /// The shared-memory marker of a `Put` and an `Err` (`zextunit!(0x2, true)`),
    /// defined for a build that reads it: upstream compiles its reader arm only
    /// with `shared-memory`, and wz reads it only with `transport-shm`.
    const SHM: &[u8] = if cfg!(feature = "transport-shm") {
        &[0x12]
    } else {
        &[]
    };

    fn push(place: impl Fn(&mut crate::wire::PushOwned, u8)) -> impl Fn(u8) -> NetworkMessage {
        move |header| {
            let mut push = crate::push_build::build_push_literal("k", b"v").unwrap();
            place(&mut push, header);
            NetworkMessage::Push(Box::new(push))
        }
    }

    #[test]
    fn a_push_defines_the_node_id_and_its_put_the_shm_marker() {
        every_header(
            "push envelope",
            &[NODE_ID],
            push(|p, h| p.extensions = Some(alloc::vec![entry(h)])),
        );
        every_header(
            "push put body",
            SHM,
            push(|p, h| match &mut p.body {
                crate::wire::PushOwnedVariant::CodecZenohMsgPut(put) => {
                    put.extensions = Some(alloc::vec![entry(h)]);
                }
                other => panic!("a literal push carries a Put, got {other:?}"),
            }),
        );
    }

    #[test]
    fn a_push_del_defines_no_mandatory_extension() {
        every_header("push del body", &[], |header| {
            let mut push = crate::push_build::build_push_del_literal("k").unwrap();
            match &mut push.body {
                crate::wire::PushOwnedVariant::CodecZenohMsgDel(del) => {
                    del.extensions = Some(alloc::vec![entry(header)]);
                }
                other => panic!("a literal del carries a Del, got {other:?}"),
            }
            NetworkMessage::Push(Box::new(push))
        });
    }

    #[test]
    fn a_request_defines_the_node_id_and_the_target_and_its_query_nothing() {
        let request = || crate::request_build::build_request_query(1, 0, Some("k")).unwrap();
        every_header("request envelope", &[NODE_ID, TARGET], |header| {
            let mut request = request();
            request.extensions = Some(alloc::vec![entry(header)]);
            NetworkMessage::Request(Box::new(request))
        });
        every_header("request query body", &[], |header| {
            let mut request = request();
            match &mut request.body {
                crate::wire::RequestOwnedVariant::CodecZenohQuery(query) => {
                    query.extensions = Some(alloc::vec![query_entry(header)]);
                }
                other => panic!("a query request carries a Query, got {other:?}"),
            }
            NetworkMessage::Request(Box::new(request))
        });
    }

    #[test]
    fn a_response_defines_nothing_mandatory_and_its_reply_put_and_err_the_shm_marker() {
        let reply = || crate::response_build::build_response_reply_literal(1, "k", b"v").unwrap();
        every_header("response envelope", &[], |header| {
            let mut response = reply();
            response.extensions = Some(alloc::vec![entry(header)]);
            NetworkMessage::Response(Box::new(response))
        });
        every_header("reply envelope", &[], |header| {
            let mut response = reply();
            match &mut response.body {
                crate::wire::ResponseOwnedVariant::CodecZenohReply(reply) => {
                    reply.extensions = Some(alloc::vec![entry(header)]);
                }
                other => panic!("a reply carries a Reply, got {other:?}"),
            }
            NetworkMessage::Response(Box::new(response))
        });
        every_header("reply put body", SHM, |header| {
            let mut response = reply();
            match &mut response.body {
                crate::wire::ResponseOwnedVariant::CodecZenohReply(reply) => {
                    match &mut reply.body {
                        crate::wire::parts::ReplyOwnedVariant::CodecZenohMsgPut(put) => {
                            put.extensions = Some(alloc::vec![entry(header)]);
                        }
                        other => panic!("a literal reply carries a Put, got {other:?}"),
                    }
                }
                other => panic!("a reply carries a Reply, got {other:?}"),
            }
            NetworkMessage::Response(Box::new(response))
        });
        every_header("err body", SHM, |header| {
            let mut response =
                crate::response_build::build_response_err_literal(1, "k", b"e").unwrap();
            match &mut response.body {
                crate::wire::ResponseOwnedVariant::CodecZenohErr(err) => {
                    err.extensions = Some(alloc::vec![entry(header)]);
                }
                other => panic!("an err response carries an Err, got {other:?}"),
            }
            NetworkMessage::Response(Box::new(response))
        });
    }

    #[test]
    fn the_small_envelopes_define_what_upstream_declares() {
        every_header("response final", &[], |header| {
            let mut done = crate::response_final_build::build_response_final(
                1,
                crate::sample::QosLevel::DEFAULT,
            );
            done.extensions = Some(alloc::vec![entry(header)]);
            NetworkMessage::ResponseFinal(done)
        });
        every_header("oam", &[], |header| {
            let mut oam = wz_codecs::oam::Oam::default().try_into_owned().unwrap();
            oam.extensions = Some(alloc::vec![entry(header)]);
            NetworkMessage::Oam(oam)
        });
        every_header("interest", &[NODE_ID], |header| {
            let mut interest = crate::interest_build::build_interest_final(1);
            interest.extensions = Some(alloc::vec![entry(header)]);
            NetworkMessage::Interest(interest)
        });
    }

    #[test]
    fn a_declare_defines_the_node_id_and_only_an_undeclare_the_wire_expression() {
        every_header("declare envelope", &[NODE_ID], |header| {
            let mut declare = crate::declare_build::build_declare_final();
            declare.extensions = Some(alloc::vec![entry(header)]);
            NetworkMessage::Declare(Box::new(declare))
        });
        every_header("undeclare subscriber", &[WIRE_EXPR], |header| {
            let mut declare = crate::declare_build::build_undeclare_subscriber(1);
            match &mut declare.body {
                wz_codecs::declare::DeclareOwnedVariant::CodecZenohUndeclSubscriber(d) => {
                    d.extensions = Some(alloc::vec![entry(header)]);
                }
                other => panic!("an undeclare carries its body, got {other:?}"),
            }
            NetworkMessage::Declare(Box::new(declare))
        });
        every_header("declare subscriber", &[], |header| {
            let mut declare =
                crate::declare_build::build_declare_subscriber(1, 0, Some("k")).unwrap();
            match &mut declare.body {
                wz_codecs::declare::DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => {
                    d.extensions = Some(alloc::vec![entry(header)]);
                }
                other => panic!("a declare carries its body, got {other:?}"),
            }
            NetworkMessage::Declare(Box::new(declare))
        });
    }

    /// The decode reads such a batch, so a capture sees it, and the participant
    /// seam refuses it whole, as it refuses a batch that does not decode. That is
    /// wz's rule for every batch it cannot act on, and it is narrower than
    /// upstream's by the messages BEFORE the offender: upstream's frame reader
    /// hands those on one at a time (`io/zenoh-transport/src/unicast/universal/rx.rs`
    /// @ `for mut msg in frame {`) and then fails the rest of the batch
    /// (`.map_err(|_| zerror!("{}: decoding error", link.link))?;` in the same
    /// file). The difference is the same for both causes and is not this rule's.
    #[test]
    fn a_batch_with_a_mandatory_look_alike_decodes_and_is_refused_by_the_participant() {
        // A Push whose Put carries the node-id look-alike `0x23` (optional) and
        // one carrying `0x13` (a mandatory unit, defined by no one).
        let wire_of = |header: u8| {
            let mut push = crate::push_build::build_push_literal("k", b"v").unwrap();
            match &mut push.body {
                crate::wire::PushOwnedVariant::CodecZenohMsgPut(put) => {
                    put.extensions = Some(alloc::vec![entry(header)]);
                    put.header |= 0x80;
                }
                _ => unreachable!(),
            }
            use wz_codecs_test_support::TestWire as _;
            push.wire()
        };
        let optional = wire_of(0x03);
        let parsed = parse_frame_payload(&optional).expect("the optional one decodes");
        assert!(refuse_unknown_mandatory_ext(parsed).is_ok());
        let mandatory = wire_of(0x13);
        let parsed = parse_frame_payload(&mandatory).expect("the decode reads the mandatory one");
        assert_eq!(
            refuse_unknown_mandatory_ext(parsed).unwrap_err(),
            crate::parse_error::InboundParseError::UnknownMandatoryExt { eid: 0x13 }
        );
    }
}
