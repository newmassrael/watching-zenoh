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

// Not every build reads a held chain here: the arms that do are gated on the body codecs.
#[cfg(feature = "storage-profile")]
#[allow(unused_imports)]
use crate::held_list::HeldList;
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
use crate::transport_profile::owned::DeclareOwned;
#[cfg(feature = "alloc")]
use crate::transport_profile::owned::InterestOwned;
#[cfg(feature = "alloc")]
use crate::transport_profile::owned::OamOwned;
#[cfg(all(feature = "alloc", feature = "codec-response-final"))]
use crate::transport_profile::owned::ResponseFinalOwned;
#[cfg(all(feature = "alloc", feature = "codec-push"))]
use wz_codecs::push::PushOwned;
#[cfg(all(feature = "alloc", feature = "codec-request"))]
use wz_codecs::request::RequestOwned;
#[cfg(all(feature = "alloc", feature = "codec-response"))]
use wz_codecs::response::ResponseOwned;

/// R3011 (open-debt item 850) — the storage profile of the DATA-PLANE messages
/// a receive path hands up: `Push`, `Request` and `Response`.
///
/// On an AP build ([`rx-shared-bytes`](crate::rx_profile)) it is
/// [`RxShared`](crate::rx_profile::RxShared), whose byte fields are ranges of the
/// frame the message was decoded from, so a received payload is the frame's own
/// bytes and a deep clone of the message is a reference count. On another build
/// with an allocator it is the heap, and on a build without one it is the node's
/// deployment ([`wz_codecs::node::Node`]): the MCU profiles are Arc-free by
/// construction and keep the owned form, inline at what the node stores. Never
/// `Inline`, the SCE default without an allocator, which holds each field at the
/// protocol's bound (a payload's is a `u32` length) and so in no array a node
/// can give it.
///
/// The control-plane variants (`Declare`, `Interest`, `Oam`, `ResponseFinal`)
/// are on [`TransportStorage`](crate::transport_profile::TransportStorage), the
/// heap where the build allocates and the node's deployment where it does not
/// ([`crate::transport_profile::owned`]): their byte fields are a few bytes of
/// extension, not a payload, and a second profile there would only make every
/// helper that reads both a generic one.
#[cfg(feature = "rx-shared-bytes")]
pub type WireStorage = crate::rx_profile::RxShared;
/// See the `rx-shared-bytes` form of this alias.
#[cfg(all(feature = "alloc", not(feature = "rx-shared-bytes")))]
pub type WireStorage = sce_forge_runtime::codec::Heap;
/// See the `rx-shared-bytes` form of this alias.
#[cfg(not(feature = "alloc"))]
pub type WireStorage = wz_codecs::node::Node;

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
            feature = "rx-lent-control",
            // Named by the arms of the pull's `lend_next`, each of which is a kind the build reads.
            any(
                feature = "codec-request",
                all(feature = "codec-push", feature = "rx-push"),
                all(feature = "codec-response", feature = "rx-response"),
                all(feature = "codec-response-final", feature = "rx-response"),
                feature = "rx-control"
            ),
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

/// A [`NetworkMessage`] borrowed: each variant's record by reference. What a reader that only
/// reads a message takes (an interceptor, the egress gate), so a message its sender holds by
/// value, or as its record alone, is read where it is and never boxed to be asked of.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, Copy)]
pub enum MessageRef<'a> {
    /// A `Request`.
    #[cfg(feature = "codec-request")]
    Request(&'a RequestOwned<WireStorage>),
    /// A `Push`.
    #[cfg(feature = "codec-push")]
    Push(&'a PushOwned<WireStorage>),
    /// A `ResponseFinal`.
    #[cfg(feature = "codec-response-final")]
    ResponseFinal(&'a ResponseFinalOwned),
    /// An `Oam`.
    Oam(&'a OamOwned),
    /// An `Interest`.
    Interest(&'a InterestOwned),
    /// A `Response`.
    #[cfg(feature = "codec-response")]
    Response(&'a ResponseOwned<WireStorage>),
    /// A `Declare`.
    #[cfg(feature = "codec-declare")]
    Declare(&'a DeclareOwned),
    /// A message of an id with no decoder, as [`NetworkMessage::Unknown`] holds it.
    Unknown {
        /// Its id.
        mid: u8,
        /// Its bytes.
        body: &'a [u8],
    },
}

#[cfg(feature = "alloc")]
impl NetworkMessage {
    /// The message borrowed ([`MessageRef`]).
    pub fn view(&self) -> MessageRef<'_> {
        match self {
            #[cfg(feature = "codec-request")]
            Self::Request(request) => MessageRef::Request(request),
            #[cfg(feature = "codec-push")]
            Self::Push(push) => MessageRef::Push(push),
            #[cfg(feature = "codec-response-final")]
            Self::ResponseFinal(response_final) => MessageRef::ResponseFinal(response_final),
            Self::Oam(oam) => MessageRef::Oam(oam),
            Self::Interest(interest) => MessageRef::Interest(interest),
            #[cfg(feature = "codec-response")]
            Self::Response(response) => MessageRef::Response(response),
            #[cfg(feature = "codec-declare")]
            Self::Declare(declare) => MessageRef::Declare(declare),
            Self::Unknown { mid, body } => MessageRef::Unknown { mid: *mid, body },
        }
    }
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
// The union of its callers: the owned message (`alloc`), the Declare verdict,
// the Response read where its frame lies (`response_view_admission`,
// whose verdict the owned message shares), and the views read where a slot
// profile's frame lies. The Request verdict is `alloc`'s alone, so it adds
// nothing. Each item below is gated on the union of ITS callers, because the
// workspace builds with warnings denied: an item wider than its callers is dead
// code in a build that has none, and a caller wider than the item has no callee.
//
// A node reads only the kinds it asked for (`rx-push`, `rx-response`, `rx-control`), so on a build
// with no allocator each verdict is a caller when its selector is on.
#[cfg(any(
    feature = "alloc",
    all(feature = "codec-declare", feature = "rx-control"),
    all(
        feature = "codec-frame",
        feature = "codec-response",
        feature = "rx-response",
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    ),
    all(
        feature = "codec-frame",
        feature = "rx-lent-control",
        any(feature = "rx-control", feature = "rx-response"),
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
    judge_entries(carrier, extensions.map(|chain| chain.iter()))
}

/// [`judge_chain`] over the entries a chain yields, held or walked where its frame lies: each
/// entry's header and the body of each extension the message declares
/// ([`crate::ext_admit::judge_ext_entries`]), so the held, the lent and the walked forms of a
/// message refuse the same chains.
// [`judge_chain`]'s union, which it serves and which holds the Put verdict's
// (`judge_put_chain`) and the Response read where its frame lies
// (`response_view_admission`), and the Request read where its frame lies
// (`request_view_admission`), which walks its chains and calls this alone.
#[cfg(any(
    feature = "alloc",
    all(feature = "codec-declare", feature = "rx-control"),
    all(feature = "codec-push", feature = "rx-push"),
    all(
        feature = "codec-frame",
        any(
            feature = "codec-request",
            all(feature = "codec-response", feature = "rx-response")
        ),
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    ),
    all(
        feature = "codec-frame",
        feature = "rx-lent-control",
        any(feature = "rx-control", feature = "rx-response"),
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    )
))]
fn judge_entries<I>(
    carrier: crate::ext_admit::ExtCarrier,
    entries: Option<I>,
) -> crate::ext_admit::ExtAdmission
where
    I: IntoIterator,
    I::Item: crate::ext_view::ExtEntryView,
{
    entries.map_or(crate::ext_admit::ExtAdmission::Admissible, |entries| {
        crate::ext_admit::judge_ext_entries(carrier, entries)
    })
}

/// `first` unless it is admissible, and then `next()`: the
/// chains of a message are read in the order upstream reads them, the envelope's
/// before the body's, and the first offender is the one reported.
// The union of its callers: the messages that carry a body, which have a second chain to read
// (the Declare, Push, Request and Response verdicts, and the Request and Response read where
// their frame lies).
#[cfg(any(
    all(
        feature = "codec-declare",
        any(feature = "alloc", feature = "rx-control")
    ),
    all(feature = "codec-push", any(feature = "alloc", feature = "rx-push")),
    all(
        feature = "alloc",
        any(feature = "codec-request", feature = "codec-response")
    ),
    all(
        feature = "codec-frame",
        any(
            feature = "codec-request",
            all(feature = "codec-response", feature = "rx-response")
        ),
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    )
))]
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
    /// (`commons/zenoh-codec/src/common/extension.rs` @ `if u.is_mandatory() {`);
    /// [`ExtAdmission::MalformedExt`](crate::ext_admit::ExtAdmission::MalformedExt)
    /// means one of them carries an extension the message declares whose body that
    /// extension's reader refuses, which upstream's decoder refuses the whole message
    /// for as well ([`crate::ext_admit::judge_ext_entries`]).
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
                    #[cfg(feature = "request-put-del")]
                    B::CodecZenohMsgPut(put) => RequestBodyChain::Put(judge_put_chain(put)),
                    #[cfg(feature = "request-put-del")]
                    B::CodecZenohMsgDel(del) => RequestBodyChain::Del(del.extensions.entries()),
                    B::CodecZenohQuery(query) | B::Default { body: query, .. } => {
                        RequestBodyChain::Query(query.extensions.entries())
                    }
                    // This build does not name a Put or a Del body, so it has no space to judge
                    // one against. The codec may still build the arms (another crate of the
                    // graph asked for `wz-codecs/request-put-del`); without them this is
                    // unreachable.
                    #[cfg(not(feature = "request-put-del"))]
                    #[allow(unreachable_patterns)]
                    _ => return ExtAdmission::Unjudged,
                };
                judge_request_chains(request.extensions.entries(), body)
            }
            #[cfg(feature = "codec-push")]
            Self::Push(push) => {
                use wz_codecs::push::PushOwnedVariant as B;
                judge_push_chains(push.extensions.entries(), || match &push.body {
                    B::CodecZenohMsgPut(put) | B::Default { body: put, .. } => judge_put_chain(put),
                    B::CodecZenohMsgDel(del) => {
                        judge_chain(C::Zenoh(Z::Del), del.extensions.entries())
                    }
                })
            }
            #[cfg(feature = "codec-response")]
            Self::Response(response) => {
                use wz_codecs::reply::ReplyOwnedVariant as R;
                use wz_codecs::response::ResponseOwnedVariant as B;
                let body = match &response.body {
                    B::CodecZenohReply(reply) | B::Default { body: reply, .. } => {
                        let data = match &reply.body {
                            R::CodecZenohMsgPut(put) | R::Default { body: put, .. } => {
                                judge_put_chain(put)
                            }
                            R::CodecZenohMsgDel(del) => {
                                judge_chain(C::Zenoh(Z::Del), del.extensions.entries())
                            }
                        };
                        ResponseBodyChain::Reply {
                            reply: reply.extensions.entries(),
                            data,
                        }
                    }
                    B::CodecZenohErr(err) => ResponseBodyChain::Err(err.extensions.entries()),
                };
                judge_response_chains(response.extensions.entries(), body)
            }
            #[cfg(feature = "codec-response-final")]
            Self::ResponseFinal(done) => {
                judge_chain(C::Network(N::ResponseFinal), done.extensions.entries())
            }
            Self::Oam(oam) => judge_chain(C::Network(N::Oam), oam.extensions.entries()),
            Self::Interest(interest) => {
                judge_chain(C::Network(N::Interest), interest.extensions.entries())
            }
            #[cfg(feature = "codec-declare")]
            Self::Declare(declare) => {
                use crate::ext_admit::DeclarationKind as K;
                use wz_codecs::declare::DeclareOwnedVariant as B;
                let (kind, chain) = match &declare.body {
                    B::CodecZenohDeclKexpr(d) => (K::KeyExpr, d.extensions.entries()),
                    B::CodecZenohUndeclKexpr(d) => (K::UndeclKeyExpr, d.extensions.entries()),
                    B::CodecZenohDeclSubscriber(d) => (K::Subscriber, d.extensions.entries()),
                    B::CodecZenohUndeclSubscriber(d) => {
                        (K::UndeclSubscriber, d.extensions.entries())
                    }
                    B::CodecZenohDeclQueryable(d) => (K::Queryable, d.extensions.entries()),
                    B::CodecZenohUndeclQueryable(d) => (K::UndeclQueryable, d.extensions.entries()),
                    B::CodecZenohDeclToken(d) => (K::Token, d.extensions.entries()),
                    B::CodecZenohUndeclToken(d) => (K::UndeclToken, d.extensions.entries()),
                    B::CodecZenohDeclFinal(d) | B::Default { body: d, .. } => {
                        (K::Final, d.extensions.entries())
                    }
                };
                judge_declare_chains(declare.extensions.entries(), kind, chain)
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
#[cfg(all(
    feature = "codec-declare",
    any(feature = "alloc", feature = "rx-control")
))]
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
    feature = "rx-control",
    feature = "rx-lent-control",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
fn declare_view_admission(
    declare: &wz_codecs::lent::Declare<'_>,
) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::DeclarationKind as K;
    use wz_codecs::lent::DeclareVariant as B;
    let (kind, chain) = match &declare.body {
        B::CodecZenohDeclKexpr(d) => (K::KeyExpr, d.extensions.entries()),
        B::CodecZenohUndeclKexpr(d) => (K::UndeclKeyExpr, d.extensions.entries()),
        B::CodecZenohDeclSubscriber(d) => (K::Subscriber, d.extensions.entries()),
        B::CodecZenohUndeclSubscriber(d) => (K::UndeclSubscriber, d.extensions.entries()),
        B::CodecZenohDeclQueryable(d) => (K::Queryable, d.extensions.entries()),
        B::CodecZenohUndeclQueryable(d) => (K::UndeclQueryable, d.extensions.entries()),
        B::CodecZenohDeclToken(d) => (K::Token, d.extensions.entries()),
        B::CodecZenohUndeclToken(d) => (K::UndeclToken, d.extensions.entries()),
        B::CodecZenohDeclFinal(d) | B::Default { body: d, .. } => {
            (K::Final, d.extensions.entries())
        }
    };
    judge_declare_chains(declare.extensions.entries(), kind, chain)
}

/// [`NetworkMessage::ext_admission`] for an Interest read where its frame lies.
#[cfg(all(
    feature = "codec-frame",
    feature = "rx-control",
    feature = "rx-lent-control",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
fn interest_view_admission(
    interest: &wz_codecs::lent::Interest<'_>,
) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::{ExtCarrier as C, NetworkEnvelope as N};
    judge_chain(C::Network(N::Interest), interest.extensions.entries())
}

/// [`NetworkMessage::ext_admission`] for a ResponseFinal read where its frame
/// lies.
#[cfg(all(
    feature = "codec-frame",
    feature = "codec-response-final",
    feature = "rx-response",
    feature = "rx-lent-control",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
fn response_final_view_admission(
    response_final: &wz_codecs::lent::ResponseFinal<'_>,
) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::{ExtCarrier as C, NetworkEnvelope as N};
    judge_chain(
        C::Network(N::ResponseFinal),
        response_final.extensions.entries(),
    )
}

/// [`NetworkMessage::ext_admission`] for an Oam read where its frame lies.
#[cfg(all(
    feature = "codec-frame",
    feature = "rx-control",
    feature = "rx-lent-control",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
fn oam_view_admission(oam: &wz_codecs::lent::Oam<'_>) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::{ExtCarrier as C, NetworkEnvelope as N};
    judge_chain(C::Network(N::Oam), oam.extensions.entries())
}

/// The verdict on a Push: its own chain, then the chain of the body it carries
/// (`body`). The owned message's ([`NetworkMessage::ext_admission`]); the Push read
/// where its frame lies keeps the same rule over the chains it reads (`push_read`), so the
/// receive path that delivers a Push without copying it refuses exactly what the one that
/// copies it does.
#[cfg(all(feature = "codec-push", feature = "alloc"))]
fn judge_push_chains<E: crate::ext_view::ExtEntryView>(
    outer: Option<&[E]>,
    body: impl FnOnce() -> crate::ext_admit::ExtAdmission,
) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::{ExtCarrier as C, NetworkEnvelope as N};
    then_judge(judge_chain(C::Network(N::Push), outer), body)
}

/// The verdict on the chain of a Put body, its shared-memory marker included at the
/// place it stands: a Put holds the marker as a place among its entries and not as
/// one of them, so the chain is judged by the entries it writes, the marker among them
/// ([`crate::put_payload::chain_entries`]). The Push, the Reply and the Request
/// that carry a Put all judge it here.
// The union of its callers: the owned message's Push, Response and (with `request-put-del`)
// Request. A Put read where its frame lies is judged by `judge_put_view`.
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        all(feature = "codec-request", feature = "request-put-del")
    )
))]
fn judge_put_chain<S: wz_codecs::msg_put::MsgPutStorage>(
    put: &wz_codecs::msg_put::MsgPutOwned<S>,
) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::{ExtCarrier as C, ZenohBody as Z};
    judge_entries(C::Zenoh(Z::Put), crate::put_payload::chain_entries(put))
}

/// The verdict on the chain of a Put read as its view, its shared-memory marker included at the
/// place it stands: the rule of `judge_put_chain` over the chain walked where the frame lies. The
/// Request read where its frame lies judges the Put it carries here; the Push reader judges its
/// Put's chain as it reads it (`push_read`), and its tests hold that verdict to this one.
#[cfg(all(
    feature = "codec-frame",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    ),
    any(
        all(feature = "codec-request", feature = "request-put-del"),
        all(
            test,
            feature = "codec-push",
            any(feature = "alloc", feature = "rx-push")
        )
    )
))]
fn judge_put_view(put: &wz_codecs::msg_put::MsgPutView<'_>) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::{ExtCarrier as C, ZenohBody as Z};
    // A Put holds its shared-memory marker as a place among its entries, so the walk yields the
    // marker at that place, as `judge_put_chain` reads a held Put.
    judge_entries(
        C::Zenoh(Z::Put),
        crate::put_payload::view_chain(put).map(|(rest, place)| {
            use crate::put_payload::ChainEntry;
            let entries = sce_forge_runtime::codec::Entries::entries(rest);
            let at = place.unwrap_or(usize::MAX);
            entries
                .clone()
                .take(at)
                .map(ChainEntry::Entry)
                .chain(place.map(|_| ChainEntry::Marker))
                .chain(entries.skip(at).map(ChainEntry::Entry))
        }),
    )
}

/// The chain a Request's body carries, for [`judge_request_chains`]: a Put's, already judged
/// ([`judge_put_chain`], which reads its shared-memory marker at its place), a Del's (generic
/// entries, `E`) or a Query's (the Query's own entries, `Q`). The owned message's; the Request
/// read where its frame lies walks its chains (`request_view_admission`).
///
/// The Put and Del are the arms of the `request-put-del` feature (zenoh takes only a Query as a
/// request body, zenoh-pico all three). Without it the generic `E` would name no field, so
/// `Never` holds it; it cannot be built, because it holds an `Infallible`.
#[cfg(all(feature = "alloc", feature = "codec-request"))]
enum RequestBodyChain<'c, E, Q> {
    #[cfg(feature = "request-put-del")]
    Put(crate::ext_admit::ExtAdmission),
    #[cfg(feature = "request-put-del")]
    Del(Option<&'c [E]>),
    Query(Option<&'c [Q]>),
    #[cfg(not(feature = "request-put-del"))]
    #[allow(dead_code)]
    Never(
        core::marker::PhantomData<&'c [E]>,
        core::convert::Infallible,
    ),
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
        #[cfg(feature = "request-put-del")]
        RequestBodyChain::Put(verdict) => verdict,
        #[cfg(feature = "request-put-del")]
        RequestBodyChain::Del(chain) => judge_chain(C::Zenoh(Z::Del), chain),
        RequestBodyChain::Query(chain) => judge_chain(C::Zenoh(Z::Query), chain),
        #[cfg(not(feature = "request-put-del"))]
        RequestBodyChain::Never(_, never) => match never {},
    })
}

/// The chains a Response's body carries, for [`judge_response_chains`]: a
/// Reply's own and its data body's (a Put's or a Del's), or an Err's.
///
/// The owned message's only: a Response read where its frame lies walks its chains
/// (`response_view_admission`) and holds none.
#[cfg(all(feature = "alloc", feature = "codec-response"))]
enum ResponseBodyChain<'c, E> {
    /// A Reply's own chain, and the verdict on its data body's: a Put's is judged by
    /// [`judge_put_chain`], which reads its shared-memory marker at its place.
    Reply {
        reply: Option<&'c [E]>,
        data: crate::ext_admit::ExtAdmission,
    },
    Err(Option<&'c [E]>),
}

/// The verdict on a Response: its own chain, then its body's, a Reply's own
/// before its data's. The rule of the owned message, which the Response read
/// where its frame lies keeps over chains it walks (`response_view_admission`).
#[cfg(all(feature = "alloc", feature = "codec-response"))]
fn judge_response_chains<E: crate::ext_view::ExtEntryView>(
    outer: Option<&[E]>,
    body: ResponseBodyChain<'_, E>,
) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::{ExtCarrier as C, NetworkEnvelope as N, ZenohBody as Z};
    then_judge(judge_chain(C::Network(N::Response), outer), || match body {
        ResponseBodyChain::Reply { reply, data } => {
            then_judge(judge_chain(C::Zenoh(Z::Reply), reply), || data)
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
        judge_entries(
            C::Network(N::Request),
            request.extensions.as_ref().map(|chain| walked(Some(chain))),
        ),
        || match &request.body {
            #[cfg(feature = "request-put-del")]
            B::CodecZenohMsgPut(put) => judge_put_view(put),
            #[cfg(feature = "request-put-del")]
            B::CodecZenohMsgDel(del) => judge_entries(
                C::Zenoh(Z::Del),
                del.extensions.as_ref().map(|chain| walked(Some(chain))),
            ),
            B::CodecZenohQuery(query) | B::Default { body: query, .. } => judge_entries(
                C::Zenoh(Z::Query),
                query.extensions.as_ref().map(|chain| walked(Some(chain))),
            ),
            // As in `ext_admission`: a Put or Del body this build does not name is not judged.
            #[cfg(not(feature = "request-put-del"))]
            #[allow(unreachable_patterns)]
            _ => crate::ext_admit::ExtAdmission::Unjudged,
        },
    )
}

/// [`NetworkMessage::ext_admission`] for a Response read where its frame lies.
#[cfg(all(
    feature = "codec-frame",
    feature = "codec-response",
    any(
        all(
            feature = "alloc",
            any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
        ),
        feature = "rx-response"
    ),
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
fn response_view_admission(
    response: &wz_codecs::response::ResponseView<'_>,
) -> crate::ext_admit::ExtAdmission {
    use crate::ext_admit::{ExtCarrier as C, NetworkEnvelope as N, ZenohBody as Z};
    use crate::ext_view::walked;
    use wz_codecs::reply::ReplyViewVariant as R;
    use wz_codecs::response::ResponseViewVariant as B;
    // The rule of [`judge_response_chains`] -- the envelope's chain, then a Reply's own before
    // its data's, or an Err's -- over chains that are walked where the frame lies and not held,
    // so no entry is decoded into a slot.
    then_judge(
        judge_entries(
            C::Network(N::Response),
            response
                .extensions
                .as_ref()
                .map(|chain| walked(Some(chain))),
        ),
        || match &response.body {
            B::CodecZenohReply(reply) | B::Default { body: reply, .. } => then_judge(
                judge_entries(
                    C::Zenoh(Z::Reply),
                    reply.extensions.as_ref().map(|chain| walked(Some(chain))),
                ),
                || match &reply.body {
                    // A Put holds its shared-memory marker as a place among its entries, so the
                    // walk yields the marker at that place, as `judge_put_chain` reads a held
                    // Put.
                    R::CodecZenohMsgPut(put) | R::Default { body: put, .. } => judge_entries(
                        C::Zenoh(Z::Put),
                        crate::put_payload::view_chain(put).map(|(rest, place)| {
                            use crate::put_payload::ChainEntry;
                            let entries = sce_forge_runtime::codec::Entries::entries(rest);
                            let at = place.unwrap_or(usize::MAX);
                            entries
                                .clone()
                                .take(at)
                                .map(ChainEntry::Entry)
                                .chain(place.map(|_| ChainEntry::Marker))
                                .chain(entries.skip(at).map(ChainEntry::Entry))
                        }),
                    ),
                    R::CodecZenohMsgDel(del) => judge_entries(
                        C::Zenoh(Z::Del),
                        del.extensions.as_ref().map(|chain| walked(Some(chain))),
                    ),
                },
            ),
            B::CodecZenohErr(err) => judge_entries(
                C::Zenoh(Z::Err),
                err.extensions.as_ref().map(|chain| walked(Some(chain))),
            ),
        },
    )
}

/// What upstream sends on of `message` when it routes it: the message its decoder made, which
/// holds exactly the extensions the message (or a body it carries) declares, each once, with the
/// value of the last entry the chain carried of it, and the entries a zenoh body carries of an
/// extension it does not declare. `None` when the router sends `message` on as it came, which is
/// nearly every message.
///
/// Upstream's decoders assign each entry an extension's arm meets to the one field that extension
/// has, so a repeated extension is held as its last entry
/// ([`crate::ext_view::last_by_eid`]), and its encoders write each field once
/// (`commons/zenoh-codec/src/network/push.rs` @ `if let Some(ts) = ext_tstamp.as_ref() {`): a
/// router that forwards a chain carrying an extension twice sends the extension once. An entry of
/// an extension the network envelope or a declaration does not declare is read and let go
/// (`commons/zenoh-codec/src/common/extension.rs` @
/// `let (_, has_ext): (ZExtUnknown, bool) = read_inner(&mut *reader, s, header)?;`, reached from
/// each envelope's reader as `commons/zenoh-codec/src/network/push.rs` @
/// `has_ext = extension::skip(reader, "Push", ext)?;`), so upstream's router forwards none of it.
/// A zenoh body keeps each such entry instead
/// (`commons/zenoh-codec/src/zenoh/put.rs` @ `ext_unknown.push(u);`), and upstream forwards it
/// as it came, a repeated one as often as it came.
///
/// A wz router forwards what upstream's does. A relay that copies bytes it cannot interpret
/// forwards claims it never judged, and the preset's routers do not carry them, so a mesh that
/// mixes the two behaves the same whichever router a message crosses. A mandatory extension the
/// message does not declare is not a case here: the participant refuses the whole message before
/// it is routed ([`crate::ext_admit::ExtAdmission::UnknownMandatory`]). An extension wz itself
/// declares on a kind, the mesh hop limit of a Push, is routed as a declared one. wz holds a
/// chain as it came and its egress writes what it holds, so the router makes this message of the
/// one it received before it routes it, and every way a routed message leaves (a mesh face, a
/// client's carrier, a group) sends it. Which entries go is one rule, `routing_drops_at`.
///
/// A Query's value is one extension upstream reads from two entries, the shared-memory marker and
/// the value after it (`commons/zenoh-codec/src/zenoh/query.rs` @
/// `ext::QueryBodyType::SID | ext::QueryBodyType::VID => {`): the last value is kept with the
/// marker before it, when it has one, and every other value and marker is dropped.
#[cfg(feature = "alloc")]
pub fn as_routed(message: &NetworkMessage) -> Option<NetworkMessage> {
    // Which of these a build uses depends on the codecs it selects.
    #[allow(unused_imports)]
    use crate::ext_admit::{
        DeclarationKind as K, ExtCarrier as C, NetworkEnvelope as N, ZenohBody as Z,
    };
    use crate::held_list::HeldList;
    match message {
        #[cfg(feature = "codec-request")]
        NetworkMessage::Request(request) => {
            request_as_routed(request).map(|r| NetworkMessage::Request(Box::new(r)))
        }
        #[cfg(feature = "codec-push")]
        NetworkMessage::Push(push) => {
            push_as_routed(push).map(|p| NetworkMessage::Push(Box::new(p)))
        }
        #[cfg(feature = "codec-response")]
        NetworkMessage::Response(response) => {
            use wz_codecs::reply::ReplyOwnedVariant as R;
            use wz_codecs::response::ResponseOwnedVariant as B;
            let body = match &response.body {
                B::CodecZenohReply(reply) | B::Default { body: reply, .. } => {
                    routing_drops(C::Zenoh(Z::Reply), reply.extensions.entries())
                        || match &reply.body {
                            R::CodecZenohMsgPut(put) | R::Default { body: put, .. } => {
                                put_routing_drops(put)
                            }
                            R::CodecZenohMsgDel(del) => {
                                routing_drops(C::Zenoh(Z::Del), del.extensions.entries())
                            }
                        }
                }
                B::CodecZenohErr(err) => routing_drops(C::Zenoh(Z::Err), err.extensions.entries()),
            };
            if !body && !routing_drops(C::Network(N::Response), response.extensions.entries()) {
                return None;
            }
            let mut response = response.clone();
            drop_for_routing(
                C::Network(N::Response),
                &mut response.header,
                &mut response.extensions,
            )
            .ok()?;
            match &mut response.body {
                B::CodecZenohReply(reply) | B::Default { body: reply, .. } => {
                    drop_for_routing(C::Zenoh(Z::Reply), &mut reply.header, &mut reply.extensions)
                        .ok()?;
                    match &mut reply.body {
                        R::CodecZenohMsgPut(put) | R::Default { body: put, .. } => {
                            drop_for_routing_put(put).ok()?
                        }
                        R::CodecZenohMsgDel(del) => {
                            drop_for_routing(C::Zenoh(Z::Del), &mut del.header, &mut del.extensions)
                                .ok()?
                        }
                    }
                }
                B::CodecZenohErr(err) => {
                    drop_for_routing(C::Zenoh(Z::Err), &mut err.header, &mut err.extensions).ok()?
                }
            }
            Some(NetworkMessage::Response(response))
        }
        #[cfg(feature = "codec-response-final")]
        NetworkMessage::ResponseFinal(done) => {
            if !routing_drops(C::Network(N::ResponseFinal), done.extensions.entries()) {
                return None;
            }
            let mut done = done.clone();
            drop_for_routing(
                C::Network(N::ResponseFinal),
                &mut done.header,
                &mut done.extensions,
            )
            .ok()?;
            Some(NetworkMessage::ResponseFinal(done))
        }
        NetworkMessage::Oam(oam) => {
            if !routing_drops(C::Network(N::Oam), oam.extensions.entries()) {
                return None;
            }
            let mut oam = oam.clone();
            drop_for_routing(C::Network(N::Oam), &mut oam.header, &mut oam.extensions).ok()?;
            Some(NetworkMessage::Oam(oam))
        }
        NetworkMessage::Interest(interest) => {
            if !routing_drops(C::Network(N::Interest), interest.extensions.entries()) {
                return None;
            }
            let mut interest = interest.clone();
            drop_for_routing(
                C::Network(N::Interest),
                &mut interest.header,
                &mut interest.extensions,
            )
            .ok()?;
            Some(NetworkMessage::Interest(interest))
        }
        #[cfg(feature = "codec-declare")]
        NetworkMessage::Declare(declare) => {
            use wz_codecs::declare::DeclareOwnedVariant as B;
            let body = match &declare.body {
                B::CodecZenohDeclKexpr(d) => {
                    routing_drops(C::Declaration(K::KeyExpr), d.extensions.entries())
                }
                B::CodecZenohUndeclKexpr(d) => {
                    routing_drops(C::Declaration(K::UndeclKeyExpr), d.extensions.entries())
                }
                B::CodecZenohDeclSubscriber(d) => {
                    routing_drops(C::Declaration(K::Subscriber), d.extensions.entries())
                }
                B::CodecZenohUndeclSubscriber(d) => {
                    routing_drops(C::Declaration(K::UndeclSubscriber), d.extensions.entries())
                }
                B::CodecZenohDeclQueryable(d) => {
                    routing_drops(C::Declaration(K::Queryable), d.extensions.entries())
                }
                B::CodecZenohUndeclQueryable(d) => {
                    routing_drops(C::Declaration(K::UndeclQueryable), d.extensions.entries())
                }
                B::CodecZenohDeclToken(d) => {
                    routing_drops(C::Declaration(K::Token), d.extensions.entries())
                }
                B::CodecZenohUndeclToken(d) => {
                    routing_drops(C::Declaration(K::UndeclToken), d.extensions.entries())
                }
                B::CodecZenohDeclFinal(d) | B::Default { body: d, .. } => {
                    routing_drops(C::Declaration(K::Final), d.extensions.entries())
                }
            };
            if !body && !routing_drops(C::Network(N::Declare), declare.extensions.entries()) {
                return None;
            }
            let mut declare = declare.clone();
            drop_for_routing(
                C::Network(N::Declare),
                &mut declare.header,
                &mut declare.extensions,
            )
            .ok()?;
            match &mut declare.body {
                B::CodecZenohDeclKexpr(d) => {
                    drop_for_routing(C::Declaration(K::KeyExpr), &mut d.header, &mut d.extensions)
                        .ok()?
                }
                B::CodecZenohUndeclKexpr(d) => drop_for_routing(
                    C::Declaration(K::UndeclKeyExpr),
                    &mut d.header,
                    &mut d.extensions,
                )
                .ok()?,
                B::CodecZenohDeclSubscriber(d) => drop_for_routing(
                    C::Declaration(K::Subscriber),
                    &mut d.header,
                    &mut d.extensions,
                )
                .ok()?,
                B::CodecZenohUndeclSubscriber(d) => drop_for_routing(
                    C::Declaration(K::UndeclSubscriber),
                    &mut d.header,
                    &mut d.extensions,
                )
                .ok()?,
                B::CodecZenohDeclQueryable(d) => drop_for_routing(
                    C::Declaration(K::Queryable),
                    &mut d.header,
                    &mut d.extensions,
                )
                .ok()?,
                B::CodecZenohUndeclQueryable(d) => drop_for_routing(
                    C::Declaration(K::UndeclQueryable),
                    &mut d.header,
                    &mut d.extensions,
                )
                .ok()?,
                B::CodecZenohDeclToken(d) => {
                    drop_for_routing(C::Declaration(K::Token), &mut d.header, &mut d.extensions)
                        .ok()?
                }
                B::CodecZenohUndeclToken(d) => drop_for_routing(
                    C::Declaration(K::UndeclToken),
                    &mut d.header,
                    &mut d.extensions,
                )
                .ok()?,
                B::CodecZenohDeclFinal(d) | B::Default { body: d, .. } => {
                    drop_for_routing(C::Declaration(K::Final), &mut d.header, &mut d.extensions)
                        .ok()?
                }
            }
            Some(NetworkMessage::Declare(declare))
        }
        NetworkMessage::Unknown { .. } => None,
    }
}

/// [`as_routed`] for a Request: the message a router routes of the one it received, or `None`
/// when the router sends it on as it came. Its own function for the router's multicast ingress,
/// which is handed a Request and not a [`NetworkMessage`].
#[cfg(all(feature = "alloc", feature = "codec-request"))]
pub fn request_as_routed(request: &RequestOwned<WireStorage>) -> Option<RequestOwned<WireStorage>> {
    use crate::ext_admit::{ExtCarrier as C, NetworkEnvelope as N, ZenohBody as Z};
    use crate::held_list::HeldList;
    use wz_codecs::request::RequestOwnedVariant as B;
    let body = match &request.body {
        #[cfg(feature = "request-put-del")]
        B::CodecZenohMsgPut(put) => put_routing_drops(put),
        #[cfg(feature = "request-put-del")]
        B::CodecZenohMsgDel(del) => routing_drops(C::Zenoh(Z::Del), del.extensions.entries()),
        B::CodecZenohQuery(query) | B::Default { body: query, .. } => {
            routing_drops(C::Zenoh(Z::Query), query.extensions.entries())
        }
        #[cfg(not(feature = "request-put-del"))]
        #[allow(unreachable_patterns)]
        _ => false,
    };
    if !body && !routing_drops(C::Network(N::Request), request.extensions.entries()) {
        return None;
    }
    let mut request = request.clone();
    drop_for_routing(
        C::Network(N::Request),
        &mut request.header,
        &mut request.extensions,
    )
    .ok()?;
    match &mut request.body {
        #[cfg(feature = "request-put-del")]
        B::CodecZenohMsgPut(put) => drop_for_routing_put(put).ok()?,
        #[cfg(feature = "request-put-del")]
        B::CodecZenohMsgDel(del) => {
            drop_for_routing(C::Zenoh(Z::Del), &mut del.header, &mut del.extensions).ok()?
        }
        B::CodecZenohQuery(query) | B::Default { body: query, .. } => {
            drop_for_routing_query(query).ok()?
        }
        #[cfg(not(feature = "request-put-del"))]
        #[allow(unreachable_patterns)]
        _ => {}
    }
    Some(request)
}

/// [`as_routed`] for a Push, for the router's multicast ingress as `request_as_routed` (with
/// `codec-request`) is for a Request.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
pub fn push_as_routed(push: &PushOwned<WireStorage>) -> Option<PushOwned<WireStorage>> {
    use crate::ext_admit::{ExtCarrier as C, NetworkEnvelope as N, ZenohBody as Z};
    use crate::held_list::HeldList;
    use wz_codecs::push::PushOwnedVariant as B;
    let body = match &push.body {
        B::CodecZenohMsgPut(put) | B::Default { body: put, .. } => put_routing_drops(put),
        B::CodecZenohMsgDel(del) => routing_drops(C::Zenoh(Z::Del), del.extensions.entries()),
    };
    if !body && !routing_drops(C::Network(N::Push), push.extensions.entries()) {
        return None;
    }
    let mut push = push.clone();
    drop_for_routing(C::Network(N::Push), &mut push.header, &mut push.extensions).ok()?;
    match &mut push.body {
        B::CodecZenohMsgPut(put) | B::Default { body: put, .. } => {
            drop_for_routing_put(put).ok()?
        }
        B::CodecZenohMsgDel(del) => {
            drop_for_routing(C::Zenoh(Z::Del), &mut del.header, &mut del.extensions).ok()?
        }
    }
    Some(push)
}

/// Whether a router drops an entry of `chain`, a chain of the message `carrier` names
/// ([`routing_drops_at`]).
#[cfg(feature = "alloc")]
fn routing_drops<E: crate::ext_view::ExtEntryView>(
    carrier: crate::ext_admit::ExtCarrier,
    chain: Option<&[E]>,
) -> bool {
    let (Some(chain), Some(declared)) = (chain, crate::ext_admit::declared_identities(carrier))
    else {
        return false;
    };
    (0..chain.len()).any(|at| routing_drops_at(carrier, chain, at, declared))
}

/// Whether a router drops the entry at `at` of `chain`, a chain of the message `carrier` names,
/// whose reader declares `declared`: the one rule [`as_routed`] makes every routed chain by.
///
/// An entry of a declared extension, upstream's or wz's own ([`wz_declared`]), is dropped when a
/// later entry carries the extension again, since upstream's decoder holds the later one in its
/// place. An entry of an extension the carrier does not declare is dropped from a network
/// envelope and from a declaration, whose readers skip it, and kept on a zenoh body, whose
/// readers hold it (`commons/zenoh-codec/src/zenoh/put.rs` @ `ext_unknown.push(u);`).
#[cfg(feature = "alloc")]
fn routing_drops_at<E: crate::ext_view::ExtEntryView>(
    carrier: crate::ext_admit::ExtCarrier,
    chain: &[E],
    at: usize,
    declared: &[u8],
) -> bool {
    chain.get(at).is_some_and(|entry| {
        let eid = entry.eid();
        if declared.contains(&eid) || wz_declared(carrier).contains(&eid) {
            chain
                .iter()
                .skip(at.saturating_add(1))
                .any(|later| later.eid() == eid)
        } else {
            !matches!(carrier, crate::ext_admit::ExtCarrier::Zenoh(_))
        }
    })
}

/// The extensions wz declares on the message `carrier` names beyond upstream's: the mesh hop
/// limit of a Push ([`crate::push_routing_context::HOPLIMIT_EXT_HEADER`]), which each node of a
/// wz mesh reads and counts down, so a router that dropped it would hand the next hop a fresh
/// budget and lift the bound it keeps on a loop.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
fn wz_declared(carrier: crate::ext_admit::ExtCarrier) -> &'static [u8] {
    use crate::ext_admit::{ExtCarrier as C, NetworkEnvelope as N};
    if carrier == C::Network(N::Push) {
        &[crate::push_routing_context::HOPLIMIT_EXT_HEADER]
    } else {
        &[]
    }
}

/// The extensions wz declares on the message `carrier` names beyond upstream's: none in a build
/// that carries no Push.
#[cfg(all(feature = "alloc", not(feature = "codec-push")))]
fn wz_declared(_carrier: crate::ext_admit::ExtCarrier) -> &'static [u8] {
    &[]
}

/// Drop from `list` each entry a router drops ([`routing_drops_at`]), keeping the order of the
/// rest.
#[cfg(feature = "alloc")]
fn retain_routed<E: crate::ext_view::ExtEntryView>(
    carrier: crate::ext_admit::ExtCarrier,
    list: &mut Vec<E>,
    declared: &[u8],
) {
    let entries: &[E] = list;
    let dropped: Vec<bool> = (0..entries.len())
        .map(|at| routing_drops_at(carrier, entries, at, declared))
        .collect();
    let mut dropped = dropped.into_iter();
    list.retain(|_| !dropped.next().unwrap_or(false));
}

/// [`retain_routed`] on the chain a message holds of the generic entry, its chain flags set again
/// for the entries that are left and the message's `header` flag set to whether any is. A chain
/// of extensions the carrier does not declare alone is left empty, and the message is routed with
/// none.
#[cfg(feature = "alloc")]
fn drop_for_routing<
    S: wz_codecs::ext_entry::ExtEntryStorage,
    const MAX: usize,
    const MIN: usize,
>(
    carrier: crate::ext_admit::ExtCarrier,
    header: &mut u8,
    chain: &mut Option<
        sce_forge_runtime::codec::Bounded<Vec<wz_codecs::ext_entry::ExtEntryOwned<S>>, MAX, MIN>,
    >,
) -> Result<(), sce_forge_runtime::codec::CodecError> {
    let Some(declared) = crate::ext_admit::declared_identities(carrier) else {
        return Ok(());
    };
    crate::held_list::edit_chain(chain, |list| {
        if let Some(list) = list {
            retain_routed(carrier, list, declared);
            crate::ext_nodeid::apply_chain_z_bits(list);
        }
    })?;
    crate::ext_nodeid::sync_header_z(header, chain.is_some());
    Ok(())
}

/// Whether a router drops an entry of a Put's chain ([`routing_drops_at`]). The shared-memory
/// marker is a place of the chain and cannot be repeated.
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        all(feature = "codec-request", feature = "request-put-del")
    )
))]
fn put_routing_drops<S: wz_codecs::msg_put::MsgPutStorage>(
    put: &wz_codecs::msg_put::MsgPutOwned<S>,
) -> bool {
    use crate::ext_admit::{ExtCarrier as C, ZenohBody as Z};
    routing_drops(C::Zenoh(Z::Put), Some(crate::put_payload::chain(put)))
}

/// [`drop_for_routing`] for a Put's chain, the shared-memory marker kept at its place.
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        all(feature = "codec-request", feature = "request-put-del")
    )
))]
fn drop_for_routing_put<S: wz_codecs::msg_put::MsgPutStorage>(
    put: &mut wz_codecs::msg_put::MsgPutOwned<S>,
) -> Result<(), sce_forge_runtime::codec::CodecError> {
    use crate::ext_admit::{ExtCarrier as C, ZenohBody as Z};
    use crate::put_payload::ChainEntry;
    use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
    let Some(declared) = crate::ext_admit::declared_identities(C::Zenoh(Z::Put)) else {
        return Ok(());
    };
    // The whole chain, the marker an entry at its place, as `set_chain` takes it back.
    let mut entries: Vec<ExtEntryOwned<S>> = crate::put_payload::chain_entries(put)
        .map(|walk| {
            walk.map(|entry| match entry {
                ChainEntry::Marker => ExtEntryOwned {
                    header: crate::put_payload::marker_header(),
                    body: ExtEntryOwnedVariant::CodecZenohExtUnit(
                        wz_codecs::ext_unit::ExtUnit::default(),
                    ),
                },
                ChainEntry::Entry(entry) => entry.clone(),
            })
            .collect()
        })
        .unwrap_or_default();
    retain_routed(C::Zenoh(Z::Put), &mut entries, declared);
    crate::ext_nodeid::apply_chain_z_bits(&mut entries);
    crate::put_payload::set_chain(put, entries)
}

/// [`drop_for_routing`] for a Query's chain, whose value is the marker and the entry after it.
#[cfg(all(feature = "alloc", feature = "codec-request"))]
fn drop_for_routing_query(
    query: &mut crate::wire::parts::QueryOwned,
) -> Result<(), sce_forge_runtime::codec::CodecError> {
    use crate::ext_admit::{ExtCarrier as C, ZenohBody as Z};
    use crate::ext_header::body_eid::{QUERY_SHM, QUERY_VALUE};
    use crate::ext_header::EXT_FLAG_Z;
    use crate::ext_view::ExtEntryView;
    let Some(declared) = crate::ext_admit::declared_identities(C::Zenoh(Z::Query)) else {
        return Ok(());
    };
    let Some(lawful) = query.extensions.take() else {
        return Ok(());
    };
    let mut chain = lawful.into_parts().1.into_inner();
    let value = crate::ext_view::last_index_by_eid(&chain, QUERY_VALUE);
    let marker = value
        .and_then(|at| at.checked_sub(1))
        .filter(|at| chain.get(*at).is_some_and(|entry| entry.eid() == QUERY_SHM));
    let dropped: Vec<bool> = (0..chain.len())
        .map(|at| match chain.get(at).map(ExtEntryView::eid) {
            Some(QUERY_VALUE) => Some(at) != value,
            Some(QUERY_SHM) => Some(at) != marker,
            _ => routing_drops_at(C::Zenoh(Z::Query), &chain, at, declared),
        })
        .collect();
    let mut dropped = dropped.into_iter();
    chain.retain(|_| !dropped.next().unwrap_or(false));
    let last = chain.len().saturating_sub(1);
    for (at, entry) in chain.iter_mut().enumerate() {
        entry.header = if at == last {
            entry.header & !EXT_FLAG_Z
        } else {
            entry.header | EXT_FLAG_Z
        };
    }
    query.extensions = Some(crate::held_list::lawful(crate::held_list::held(chain)?)?);
    Ok(())
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
    parse_batch(bytes, NO_ORIGIN, false).map(|(messages, _)| messages)
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
    let parsed = parse_batch(origin.as_slice(), Some(origin), false);
    #[cfg(not(feature = "rx-shared-bytes"))]
    let parsed = parse_batch(origin.as_slice(), NO_ORIGIN, false);
    parsed.map(|(messages, _)| messages)
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

/// The batch a participant may act on: what [`parse_frame_payload_in`] decodes, or the refusal of
/// the first message whose chains a conforming participant must refuse the whole batch for, judged
/// in the same pass as the decode. A Push is judged as its chains are read; any other message by
/// its own verdict ([`NetworkMessage::ext_admission`]). A batch that does not decode is refused
/// with its codec error, ahead of any refusal of the rule.
///
/// The decode itself reads such a batch, so a capture sees it; this is the one place a
/// participant stops it.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
pub fn admit_frame_payload_in(
    origin: &crate::link::RxBytes,
) -> Result<Vec<NetworkMessage>, crate::parse_error::InboundParseError> {
    #[cfg(feature = "rx-shared-bytes")]
    let parsed = parse_batch(origin.as_slice(), Some(origin), true);
    #[cfg(not(feature = "rx-shared-bytes"))]
    let parsed = parse_batch(origin.as_slice(), NO_ORIGIN, true);
    admitted(parsed)
}

/// [`admit_frame_payload_in`] for a batch that exists only as a borrowed slice, as
/// [`parse_frame_payload_lending`] is [`parse_frame_payload_in`] for one.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
pub fn admit_frame_payload_lending(
    bytes: &[u8],
) -> Result<Vec<NetworkMessage>, crate::parse_error::InboundParseError> {
    #[cfg(feature = "rx-shared-bytes")]
    {
        admit_frame_payload_in(&crate::link::RxBytes::lend(bytes.to_vec()))
    }
    #[cfg(not(feature = "rx-shared-bytes"))]
    {
        admitted(parse_batch(bytes, NO_ORIGIN, true))
    }
}

/// What a participant acts on of a judged batch ([`parse_batch`]): the codec's error first, then
/// the rule's refusal, then the messages.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
fn admitted(
    parsed: Result<
        (
            Vec<NetworkMessage>,
            Option<crate::parse_error::InboundParseError>,
        ),
        CodecError,
    >,
) -> Result<Vec<NetworkMessage>, crate::parse_error::InboundParseError> {
    match parsed {
        Ok((messages, None)) => Ok(messages),
        Ok((_, Some(refusal))) => Err(refusal),
        Err(error) => Err(crate::parse_error::InboundParseError::Codec(error)),
    }
}

/// The messages of a batch, and with `judge` the refusal of the mandatory-extension rule of the
/// first of them a participant must refuse, by the verdict each decode returns.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
fn parse_batch(
    bytes: &[u8],
    origin: Origin<'_>,
    judge: bool,
) -> Result<
    (
        Vec<NetworkMessage>,
        Option<crate::parse_error::InboundParseError>,
    ),
    CodecError,
> {
    let mut messages = Vec::new();
    let mut refusal = None;
    let mut cursor = SceCursor::new(bytes);
    while cursor.remaining() > 0 {
        // R311y578 — the per-MID dispatch moved to `decode_one_record`, the
        // SSOT this strict walk and the best-effort walk share. Behaviour
        // here is unchanged: `Ok(None)` (no envelope decoder for the MID)
        // absorbs the tail as `Unknown` and terminates, a codec error
        // propagates and fails the whole batch.
        let decoded = decode_one_record(&mut cursor, &mut messages, origin)?;
        if decoded == Decoded::Unknown {
            absorb_unknown(&mut cursor, &mut messages)?;
            break;
        }
        if judge && refusal.is_none() {
            refusal = decoded.refusal(messages.last());
        }
    }
    Ok((messages, refusal))
}

/// The record at the cursor has a MID this build has no envelope decoder for,
/// so its length is unknowable: take the rest of the payload, header byte
/// included, as one [`NetworkMessage::Unknown`]. The caller stops walking.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
fn absorb_unknown(cursor: &mut SceCursor<'_>, out: &mut impl RecordOut) -> Result<(), CodecError> {
    let mid = cursor
        .peek_slice(1)?
        .first()
        .copied()
        .ok_or(CodecError::NeedMoreBytes)?
        & 0x1F;
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
    all(
        feature = "alloc",
        any(
            test,
            not(feature = "rx-lent-control"),
            feature = "transport-stats",
            feature = "routing-namespace"
        )
    ),
    not(feature = "bounded-heapless")
))]
pub type RecordBuf = Vec<NetworkMessage>;
/// See the growable form of this alias.
#[cfg(all(
    feature = "codec-frame",
    all(
        feature = "alloc",
        any(
            test,
            not(feature = "rx-lent-control"),
            feature = "transport-stats",
            feature = "routing-namespace"
        )
    ),
    feature = "bounded-heapless"
))]
pub type RecordBuf = heapless::Vec<NetworkMessage, 1>;

/// The record buffer of a build whose walk decodes no record into an owned message:
/// nothing. A build with no allocator has no owned message (`NetworkMessage` is the
/// heap profile's), and a heap build that lends every record (`rx-lent-control`, with
/// no owned reader kept for the counters of `transport-stats` or the strip of
/// `routing-namespace`) never puts one here (its walk has the one form that lends
/// every kind), so the walk reads every record where it lies and the buffer is a marker the
/// walk and the pump that holds it still pass around, one value of no size. A list of
/// owned messages there would link their drop for a list that is always empty.
#[cfg(all(
    feature = "codec-frame",
    not(all(
        feature = "alloc",
        any(
            test,
            not(feature = "rx-lent-control"),
            feature = "transport-stats",
            feature = "routing-namespace"
        )
    ))
))]
#[derive(Debug, Default)]
pub struct RecordBuf;

#[cfg(all(
    feature = "codec-frame",
    not(all(
        feature = "alloc",
        any(
            test,
            not(feature = "rx-lent-control"),
            feature = "transport-stats",
            feature = "routing-namespace"
        )
    ))
))]
impl RecordBuf {
    /// Empty the buffer: it holds nothing, so there is nothing to do.
    pub fn clear(&mut self) {}
}

/// An empty [`RecordBuf`]. The growable form reserves its one slot here, once,
/// so a walk that decodes an owned record never grows it.
#[cfg(feature = "codec-frame")]
pub fn new_record_buf() -> RecordBuf {
    #[cfg(all(
        all(
            feature = "alloc",
            any(
                test,
                not(feature = "rx-lent-control"),
                feature = "transport-stats",
                feature = "routing-namespace"
            )
        ),
        not(feature = "bounded-heapless")
    ))]
    {
        Vec::with_capacity(1)
    }
    #[cfg(all(
        all(
            feature = "alloc",
            any(
                test,
                not(feature = "rx-lent-control"),
                feature = "transport-stats",
                feature = "routing-namespace"
            )
        ),
        feature = "bounded-heapless"
    ))]
    {
        heapless::Vec::new()
    }
    #[cfg(not(all(
        feature = "alloc",
        any(
            test,
            not(feature = "rx-lent-control"),
            feature = "transport-stats",
            feature = "routing-namespace"
        )
    )))]
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
/// `record` (emptied first), judge it as [`admit_frame_payload_in`] judges a
/// batch, and hand it to `each` before the following one is decoded.
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
    /// Every record is decoded into its owned message: the form of a build that has no record to
    /// lend (no `rx-lent-control` and no lendable codec), of a message rejoined from fragments
    /// whose namespace is stripped off its owned outcome (`reassembly` with
    /// `routing-namespace`), and of the tests. Any other build lends what it can, and has no use
    /// for it.
    #[cfg(all(
        feature = "alloc",
        any(
            test,
            all(
                not(feature = "rx-lent-control"),
                not(any(
                    feature = "codec-push",
                    feature = "codec-request",
                    feature = "codec-response"
                ))
            ),
            all(feature = "reassembly", feature = "routing-namespace")
        )
    ))]
    Owned,
    /// A Push, a Request and a Response are decoded where the payload lies and
    /// lent.
    #[cfg(all(
        all(
            feature = "alloc",
            any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
        ),
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response"
        )
    ))]
    Lent,
    /// The form of a build that lends its control records (`rx-lent-control`,
    /// which the slot profile selects): EVERY record is decoded where the payload
    /// lies and lent, the control kinds (a Declare, an Interest, a ResponseFinal)
    /// beside the data kinds, and nothing is projected into an owned message at all. A
    /// record this build reads no further (an Oam, which has no consumer, or a
    /// MID it has no decoder for, whose length is unknowable) is judged where
    /// that is possible and skipped, so the walk allocates nothing whatever the
    /// peer put in the frame ([`WalkedRecord::Skipped`]).
    #[cfg(feature = "rx-lent-control")]
    LentControl,
}

/// A Push as the receive path's reader read it where its frame lies: the codec's view, and what the
/// delivery reads of its chains, picked out as the reader decoded each entry ([`PushExts`]), so
/// the delivery reads no chain of it again.
// Built by the walks that lend a Push and read by the delivery of a lent Push (`pubsub`'s
// `in_place`); a build without both reads nothing of it.
#[cfg(feature = "codec-push")]
#[cfg_attr(
    not(all(
        any(
            all(
                feature = "alloc",
                any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
            ),
            feature = "rx-push"
        ),
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        ),
        feature = "storage-profile",
        any(feature = "pubsub-put", feature = "pubsub-delete")
    )),
    allow(dead_code)
)]
#[derive(Debug, Default)]
pub(crate) struct PushRead<'f> {
    /// The record as the codec's view: its key, its body and its chains as the bytes they occupy.
    pub(crate) view: wz_codecs::push::PushView<'f>,
    /// What the delivery reads of its chains.
    pub(crate) exts: PushExts<'f>,
}

/// The extensions of a Push its delivery reads, each the LAST entry of its identity in its chain,
/// as [`crate::ext_view::last_of_each_in`] picks it out of a walk of the chain: the QoS and
/// whether a timestamp stack is carried, of the Push's own chain; the attachment (of the identity
/// of the body that carries it) and the source info, of its body's. Each is kept by a build whose
/// delivery reads it.
#[cfg(feature = "codec-push")]
#[cfg_attr(
    not(all(
        any(
            all(
                feature = "alloc",
                any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
            ),
            feature = "rx-push"
        ),
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        ),
        feature = "storage-profile",
        any(feature = "pubsub-put", feature = "pubsub-delete")
    )),
    allow(dead_code)
)]
#[derive(Debug, Default)]
pub(crate) struct PushExts<'f> {
    /// The QoS entry of the Push's own chain.
    #[cfg(feature = "pubsub-qos")]
    pub(crate) qos: Option<wz_codecs::ext_entry::ExtEntryView<'f>>,
    /// Whether the Push's own chain carries a timestamp stack.
    #[cfg(feature = "pubsub-ts-stack")]
    pub(crate) ts_stack: bool,
    /// The attachment entry of the body's chain, of the Put's identity on a Put and the Del's on
    /// a Del.
    #[cfg(feature = "pubsub-attachment")]
    pub(crate) attachment: Option<wz_codecs::ext_entry::ExtEntryView<'f>>,
    /// The source-info entry of the body's chain.
    #[cfg(feature = "pubsub-source-info")]
    pub(crate) source_info: Option<wz_codecs::ext_entry::ExtEntryView<'f>>,
    /// The frame the entries lie in, which a build that keeps none of them names here alone.
    _frame: core::marker::PhantomData<&'f [u8]>,
}

/// One record the walk hands over: the one owned message in the caller's
/// buffer, or a record read where the payload lies ([`RecordForm::Lent`],
/// [`RecordForm::LentControl`]).
///
/// Two lifetimes, because the codec's lent messages are invariant in the bytes
/// they are read from: `'r` is the record's own borrow, the walk's local binding
/// lent for the one call, and `'f` is the frame's, the payload the record's keys,
/// bytes and text lie in. A record is lent for less than its frame lives.
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
pub(crate) enum WalkedRecord<'r, 'f> {
    /// Never made: it holds the lifetimes in a build that reads no kind of record (a slot profile
    /// with no `rx-*` and no request codec), where no other variant does.
    #[allow(dead_code)]
    Never(
        core::convert::Infallible,
        core::marker::PhantomData<(&'r (), &'f ())>,
    ),
    /// The record's owned message, the one entry of the buffer.
    #[cfg(all(
        feature = "alloc",
        any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
    ))]
    Owned(&'r mut RecordBuf),
    /// A Push read where the payload lies, valid for the call: its view, which holds its extension
    /// chains as the bytes they occupy and not as entries, so it is a few words however long a
    /// chain the protocol lets a peer send, and the extensions its delivery reads, picked out as
    /// they were decoded. A chain longer than the node stores inline is lent like any other, on a
    /// build with no allocator too (the slot profile): the protocol bounds a chain by nothing and
    /// upstream reads it whole, as a lent Request's is read.
    #[cfg(all(
        feature = "codec-push",
        any(
            all(
                feature = "alloc",
                any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
            ),
            feature = "rx-push"
        )
    ))]
    Push(&'r PushRead<'f>),
    /// A Request read where the payload lies, valid for the call: its view, which holds its extension
    /// chains as the bytes they occupy and not as entries (the eager record is 1.8 KB).
    #[cfg(feature = "codec-request")]
    Request(&'r wz_codecs::request::RequestView<'f>),
    /// A Response decoded where the payload lies, valid for the call.
    #[cfg(all(
        feature = "codec-response",
        any(
            all(
                feature = "alloc",
                any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
            ),
            feature = "rx-response"
        )
    ))]
    Response(&'r wz_codecs::response::ResponseView<'f>),
    /// A Declare decoded where the payload lies, valid for the call
    /// ([`RecordForm::LentControl`]).
    #[cfg(all(
        feature = "rx-lent-control",
        feature = "codec-declare",
        feature = "rx-control"
    ))]
    Declare(&'r wz_codecs::lent::Declare<'f>),
    /// A ResponseFinal decoded where the payload lies, valid for the call
    /// ([`RecordForm::LentControl`]).
    #[cfg(all(
        feature = "rx-lent-control",
        feature = "codec-response-final",
        feature = "rx-response"
    ))]
    ResponseFinal(&'r wz_codecs::lent::ResponseFinal<'f>),
    /// An Interest decoded where the payload lies, valid for the call
    /// ([`RecordForm::LentControl`]).
    #[cfg(all(feature = "rx-lent-control", feature = "rx-control"))]
    Interest(&'r wz_codecs::lent::Interest<'f>),
    /// An Oam decoded where the payload lies, valid for the call
    /// ([`RecordForm::LentControl`]), in a build with the transport counters: no consumer reads
    /// it further, and it is handed over as itself so the counters read the band it carries, as
    /// they read the owned Oam's. A build without them hands it over as [`Self::Skipped`].
    #[cfg(all(
        feature = "rx-lent-control",
        feature = "rx-control",
        feature = "transport-stats",
        feature = "alloc"
    ))]
    Oam(&'r wz_codecs::lent::Oam<'f>),
    /// A record the walk read and no consumer reads further: the tail of a payload
    /// that opens with a MID this build has no decoder for (the walk ends there, as
    /// the owned walk's `Unknown` ends it) ([`RecordForm::LentControl`]). It carries
    /// nothing: the point of handing it over is that the walk counts it as a record,
    /// as it counts the owned `Unknown` it replaces.
    #[cfg(feature = "rx-lent-control")]
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
// Read by the walk tests, each of which needs records to lend and a heap to keep what it saw.
#[cfg(all(
    feature = "codec-frame",
    test,
    feature = "alloc",
    any(
        feature = "codec-push",
        all(feature = "codec-request", feature = "codec-response"),
        all(
            feature = "rx-lent-control",
            feature = "rx-control",
            feature = "rx-response",
            feature = "codec-declare",
            feature = "declare-final",
            feature = "codec-response-final"
        )
    )
))]
pub(crate) fn for_each_record<'f>(
    payload: &'f [u8],
    record: &mut RecordBuf,
    form: RecordForm,
    mut each: impl FnMut(WalkedRecord<'_, 'f>),
) -> Result<(), crate::parse_error::InboundParseError> {
    try_for_each_record(payload, record, form, |one| {
        each(one);
        Ok(())
    })
    .map(|_| ())
}

/// Whether `mid` names a TRANSPORT message (OAM, INIT, OPEN, CLOSE, KEEPALIVE, FRAME, FRAGMENT
/// or JOIN) and not a network one. A Frame's records are network messages, and the next
/// transport message of a batch (a second Frame header: the sender puts a message of the other
/// reliability behind one) begins where the last record ends. The walk of a Frame stops there
/// and leaves what follows to the reader of the batch.
// Gated by its readers: the record walk (`walk_records`, a unicast session's or an allocator-free
// group's), and with an allocator the best-effort walk, which the heap profile's frame and the
// dissector reach through it or beside it.
#[cfg(all(
    feature = "codec-frame",
    any(
        test,
        feature = "alloc",
        feature = "session-unicast",
        feature = "session-multicast"
    )
))]
pub(crate) fn is_transport_mid(mid: u8) -> bool {
    mid <= wz_codecs::wire_const::T_MID_JOIN
}

/// [`for_each_record`] whose consumer may END the walk: an `Err` from `each`
/// stops it after that record, and is the walk's answer. What a receive path
/// needs when handing a record over can itself fail (the owned extension chain
/// of the `Frame` it came in, made only when an owned record needs it).
// Its test readers are the record walk's, which are the heap profile's (`record_walk_tests`).
#[cfg(all(
    feature = "codec-frame",
    any(all(test, feature = "alloc"), feature = "session-unicast")
))]
pub(crate) fn try_for_each_record<'f>(
    payload: &'f [u8],
    record: &mut RecordBuf,
    form: RecordForm,
    mut each: impl FnMut(WalkedRecord<'_, 'f>) -> Result<(), crate::parse_error::InboundParseError>,
) -> Result<usize, crate::parse_error::InboundParseError> {
    try_for_each_record_while(
        payload,
        record,
        form,
        |one| each(one).map(|()| true),
        #[cfg(all(feature = "transport-stats", feature = "alloc"))]
        &mut |_: &RecordClass<'_>| {},
    )
    .map(|(read, _)| read)
}

/// [`try_for_each_record`] whose consumer says, as it takes each record, whether it takes
/// another: `Ok(false)` ends the walk before the next record. How far the walk read, and
/// whether it ended so, with records of the payload still unread. What a receive path asks whose
/// consumer may have no room for another record.
///
/// A build with the transport counters (`transport-stats`) hands `counted` each record it lends,
/// as the owned message the same bytes decode to: the counters classify a message by reading the
/// owned form, and so a lent record is counted as the same record walked owned is, and how a
/// record is received does not depend on whether the build counts it. An owned record is not
/// handed to `counted`: its consumer counts it from the owned message it is handed.
#[cfg(all(
    feature = "codec-frame",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
pub(crate) fn try_for_each_record_while<'f>(
    payload: &'f [u8],
    record: &mut RecordBuf,
    form: RecordForm,
    mut each: impl FnMut(WalkedRecord<'_, 'f>) -> Result<bool, crate::parse_error::InboundParseError>,
    #[cfg(all(feature = "transport-stats", feature = "alloc"))] counted: &mut dyn FnMut(
        &RecordClass<'_>,
    ),
) -> Result<(usize, bool), crate::parse_error::InboundParseError> {
    // A record the walk lends is counted by its class, read off the record as it was decoded; an
    // owned record is counted by the consumer it is handed to.
    #[cfg(all(feature = "transport-stats", feature = "alloc"))]
    let mut each = |one: WalkedRecord<'_, 'f>| {
        if let Some(class) = RecordClass::of_lent(&one) {
            counted(&class);
        }
        each(one)
    };
    walk_records(payload, record, form, &mut each)
}

/// What a record walk hands each record to, and what ends the walk: `Ok(false)` before the
/// next record, `Err` as the walk's answer. A trait
/// of its own rather than `dyn FnMut`: a closure made a `dyn FnMut` has a `call_once` shim in
/// its vtable beside `call_mut`, and the shim is a second copy of the closure's body. This
/// trait's vtable holds the one method, so the consumer's body is compiled once.
#[cfg(all(
    feature = "codec-frame",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
trait EachRecord<'f> {
    /// Take `one`, and say whether the walk hands another; an `Err` ends the walk after it and
    /// is the walk's answer.
    fn take_record(
        &mut self,
        one: WalkedRecord<'_, 'f>,
    ) -> Result<bool, crate::parse_error::InboundParseError>;
}

#[cfg(all(
    feature = "codec-frame",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
impl<'f, F> EachRecord<'f> for F
where
    F: FnMut(WalkedRecord<'_, 'f>) -> Result<bool, crate::parse_error::InboundParseError>,
{
    fn take_record(
        &mut self,
        one: WalkedRecord<'_, 'f>,
    ) -> Result<bool, crate::parse_error::InboundParseError> {
        self(one)
    }
}

/// The walk of [`try_for_each_record_while`], with the consumer behind a trait object: the pull of
/// the payload's records (`pull::hand_records`) on the form that lends every kind, and the walk
/// that owns or lends by kind on the others.
// One body for every consumer: generic over it, the walk and each kind's reader (and the codec's
// decode of that kind) were compiled again for each closure, and in the crate of each generic
// caller as well, while what differs between consumers is only the call that hands a record over.
// Out of line so that a caller's crate does not take a copy of it back.
#[cfg(all(
    feature = "codec-frame",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[inline(never)]
fn walk_records<'f>(
    payload: &'f [u8],
    record: &mut RecordBuf,
    form: RecordForm,
    each: &mut dyn EachRecord<'f>,
) -> Result<(usize, bool), crate::parse_error::InboundParseError> {
    match form {
        #[cfg(feature = "rx-lent-control")]
        RecordForm::LentControl => {
            record.clear();
            pull::hand_records(payload, each)
        }
        #[cfg(all(
            feature = "alloc",
            any(
                test,
                all(
                    not(feature = "rx-lent-control"),
                    not(any(
                        feature = "codec-push",
                        feature = "codec-request",
                        feature = "codec-response"
                    ))
                ),
                all(feature = "reassembly", feature = "routing-namespace")
            )
        ))]
        RecordForm::Owned => walk_kept_records(payload, record, form, each),
        #[cfg(all(
            all(
                feature = "alloc",
                any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
            ),
            any(
                feature = "codec-push",
                feature = "codec-request",
                feature = "codec-response"
            )
        ))]
        RecordForm::Lent => walk_kept_records(payload, record, form, each),
    }
}

/// The walk of the forms that keep a record they do not lend as its owned message
/// ([`RecordForm::Owned`], [`RecordForm::Lent`]).
#[cfg(all(
    feature = "codec-frame",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    ),
    any(
        all(
            feature = "alloc",
            any(
                test,
                all(
                    not(feature = "rx-lent-control"),
                    not(any(
                        feature = "codec-push",
                        feature = "codec-request",
                        feature = "codec-response"
                    ))
                ),
                all(feature = "reassembly", feature = "routing-namespace")
            )
        ),
        all(
            all(
                feature = "alloc",
                any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
            ),
            any(
                feature = "codec-push",
                feature = "codec-request",
                feature = "codec-response"
            )
        )
    )
))]
fn walk_kept_records<'f>(
    payload: &'f [u8],
    record: &mut RecordBuf,
    form: RecordForm,
    each: &mut dyn EachRecord<'f>,
) -> Result<(usize, bool), crate::parse_error::InboundParseError> {
    use crate::parse_error::InboundParseError;
    let mut stopped = false;
    // What the consumer said when it took the last record: whether it takes another.
    let mut go_on = true;
    // Without a lendable codec there is nothing to lend, and every form is owned.
    #[cfg(not(all(
        all(
            feature = "alloc",
            any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
        ),
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response"
        )
    )))]
    let _ = form;
    let mut cursor = SceCursor::new(payload);
    while cursor.remaining() > 0 {
        // The one read of the record's id, which every reader below is handed.
        let mid = cursor.peek_u8().map_err(InboundParseError::Codec)? & 0x1F;
        // A transport message is not a record of this frame: the walk ends before it, and the
        // caller, who is told how far the walk got, goes on from there.
        if is_transport_mid(mid) {
            break;
        }
        if !go_on {
            stopped = true;
            break;
        }
        #[cfg(all(
            all(
                feature = "alloc",
                any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
            ),
            any(
                feature = "codec-push",
                feature = "codec-request",
                feature = "codec-response"
            )
        ))]
        if form == RecordForm::Lent {
            if let Some(more) = lend_record(mid, &mut cursor, each)? {
                go_on = more;
                continue;
            }
        }
        // Only an owned record is decoded into the buffer, so only it clears it first.
        record.clear();
        let decoded =
            decode_one_record(&mut cursor, record, NO_ORIGIN).map_err(InboundParseError::Codec)?;
        if decoded == Decoded::Unknown {
            absorb_unknown(&mut cursor, record).map_err(InboundParseError::Codec)?;
        }
        if let Some(refusal) = decoded.refusal(record.last()) {
            record.clear();
            return Err(refusal);
        }
        match each.take_record(WalkedRecord::Owned(record)) {
            Ok(more) => go_on = more,
            Err(stop) => {
                record.clear();
                return Err(stop);
            }
        }
        if decoded == Decoded::Unknown {
            break;
        }
    }
    record.clear();
    // How much of the payload the walk read: all of it, or up to the transport message that
    // ended it, or up to the record the consumer took no more after.
    Ok((payload.len().saturating_sub(cursor.remaining()), stopped))
}

/// The pull of a payload's records on the form that lends every kind.
#[cfg(all(
    feature = "codec-frame",
    feature = "rx-lent-control",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
mod pull;

/// The lent half of [`try_for_each_record`]: when the record at the cursor is of
/// a kind the walk lends (`mid`), decode it where the payload lies, judge it by
/// the owned rule, hand it to `each`, and answer what `each` said of taking another;
/// `None` for any other kind, which the caller decodes owned.
///
/// Each kind is decoded in a function of its own, never inlined: a decoded
/// Request or Response is a wide value (inline extension chains), and kept out of
/// line it occupies the stack only while that one record is handed over, not
/// for the whole walk.
#[cfg(all(
    all(
        feature = "alloc",
        any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
    ),
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
fn lend_record<'f>(
    mid: u8,
    cursor: &mut SceCursor<'f>,
    each: &mut dyn EachRecord<'f>,
) -> Result<Option<bool>, crate::parse_error::InboundParseError> {
    match mid {
        #[cfg(all(
            feature = "codec-push",
            any(
                all(
                    feature = "alloc",
                    any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
                ),
                feature = "rx-push"
            )
        ))]
        wire_const::N_MID_PUSH => lend_push(cursor, each).map(Some),
        #[cfg(feature = "codec-request")]
        wire_const::N_MID_REQUEST => lend_request(cursor, each).map(Some),
        #[cfg(all(
            feature = "codec-response",
            any(
                all(
                    feature = "alloc",
                    any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
                ),
                feature = "rx-response"
            )
        ))]
        wire_const::N_MID_RESPONSE => lend_response(cursor, each).map(Some),
        _ => Ok(None),
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
    // The union of its callers, the lent readers of each kind.
    any(
        all(
            feature = "codec-push",
            any(
                all(
                    feature = "alloc",
                    any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
                ),
                feature = "rx-push"
            )
        ),
        feature = "codec-request",
        all(
            feature = "codec-response",
            any(
                all(
                    feature = "alloc",
                    any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
                ),
                feature = "rx-response"
            )
        ),
        all(
            feature = "codec-response-final",
            feature = "rx-response",
            feature = "rx-lent-control"
        ),
        all(feature = "rx-control", feature = "rx-lent-control")
    )
))]
fn admit_lent(
    admission: crate::ext_admit::ExtAdmission,
) -> Result<(), crate::parse_error::InboundParseError> {
    match admission.refusal() {
        Some(refusal) => Err(refusal),
        None => Ok(()),
    }
}

/// The reader of a Push: on the walks that lend one (`lend_push`), and on the owned parse
/// (`decode_one_record`), which a build with an allocator has.
#[cfg(all(
    feature = "codec-frame",
    feature = "codec-push",
    any(
        feature = "alloc",
        all(
            feature = "rx-push",
            any(test, feature = "session-unicast", feature = "session-multicast")
        )
    )
))]
pub(crate) mod push_read;

// Each kind is read by a function of its own, never inlined, into a binding its caller holds: a
// decoded record is a wide value (inline extension chains), and kept out of line its decode
// occupies the stack only while that one record is read. Each reader refuses what the owned
// decode of its kind refuses, with the same error, and judges the record by the owned rule.

#[cfg(all(
    feature = "codec-frame",
    feature = "codec-push",
    any(
        all(
            feature = "alloc",
            any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
        ),
        feature = "rx-push"
    ),
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[inline(never)]
fn read_push<'f>(
    cursor: &mut SceCursor<'f>,
    push: &mut PushRead<'f>,
) -> Result<(), crate::parse_error::InboundParseError> {
    // Read as its view: a few words and the bytes its chains occupy. The lent record held each
    // chain inline at the node's capacity, so it was filled from a template of that size for every
    // record and refused a chain past it, which the protocol bounds by nothing. The reader judges
    // the chains as it reads them, and keeps the entries the delivery reads as it decodes them.
    let PushRead { view, exts } = push;
    *exts = PushExts::default();
    let admission = push_read::read_push_view(cursor, view, exts)
        .map_err(crate::parse_error::InboundParseError::Codec)?;
    admit_lent(admission)
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
fn read_request<'f>(
    cursor: &mut SceCursor<'f>,
    request: &mut wz_codecs::request::RequestView<'f>,
) -> Result<(), crate::parse_error::InboundParseError> {
    // Read as its view, where the eager record is over a kilobyte (its extension vectors are
    // inline, sized for their declared maximum), so the walk of a chain afterwards cannot fail.
    wz_codecs::request::RequestView::decode_into(cursor, request)
        .map_err(crate::parse_error::InboundParseError::Codec)?;
    admit_lent(request_view_admission(request))
}

#[cfg(all(
    feature = "codec-frame",
    feature = "codec-response",
    any(
        all(
            feature = "alloc",
            any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
        ),
        feature = "rx-response"
    ),
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[inline(never)]
fn read_response<'f>(
    cursor: &mut SceCursor<'f>,
    response: &mut wz_codecs::response::ResponseView<'f>,
) -> Result<(), crate::parse_error::InboundParseError> {
    wz_codecs::response::ResponseView::decode_into(cursor, response)
        .map_err(crate::parse_error::InboundParseError::Codec)?;
    admit_lent(response_view_admission(response))
}

#[cfg(all(
    feature = "codec-frame",
    feature = "codec-response-final",
    feature = "rx-response",
    feature = "rx-lent-control",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[inline(never)]
fn read_response_final<'f>(
    cursor: &mut SceCursor<'f>,
    response_final: &mut wz_codecs::lent::ResponseFinal<'f>,
) -> Result<(), crate::parse_error::InboundParseError> {
    wz_codecs::lent::ResponseFinal::decode_into(cursor, response_final)
        .map_err(crate::parse_error::InboundParseError::Codec)?;
    admit_lent(response_final_view_admission(response_final))
}

#[cfg(all(
    feature = "codec-frame",
    feature = "codec-declare",
    feature = "rx-control",
    feature = "rx-lent-control",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[inline(never)]
fn read_declare<'f>(
    cursor: &mut SceCursor<'f>,
    declare: &mut wz_codecs::lent::Declare<'f>,
) -> Result<(), crate::parse_error::InboundParseError> {
    // Into the caller's binding: `Declare::decode` builds a default, decodes into it, and returns
    // it by value, which is a copy of the largest message a record can be.
    wz_codecs::lent::Declare::decode_into(cursor, declare)
        .map_err(crate::parse_error::InboundParseError::Codec)?;
    admit_lent(declare_view_admission(declare))
}

#[cfg(all(
    feature = "codec-frame",
    feature = "rx-control",
    feature = "rx-lent-control",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[inline(never)]
fn read_interest<'f>(
    cursor: &mut SceCursor<'f>,
    interest: &mut wz_codecs::lent::Interest<'f>,
) -> Result<(), crate::parse_error::InboundParseError> {
    wz_codecs::lent::Interest::decode_into(cursor, interest)
        .map_err(crate::parse_error::InboundParseError::Codec)?;
    admit_lent(interest_view_admission(interest))
}

#[cfg(all(
    feature = "codec-frame",
    feature = "rx-control",
    feature = "rx-lent-control",
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[inline(never)]
fn read_oam<'f>(
    cursor: &mut SceCursor<'f>,
    oam: &mut wz_codecs::lent::Oam<'f>,
) -> Result<(), crate::parse_error::InboundParseError> {
    wz_codecs::lent::Oam::decode_into(cursor, oam)
        .map_err(crate::parse_error::InboundParseError::Codec)?;
    admit_lent(oam_view_admission(oam))
}

// The kinds the walk that keeps its other records lends ([`RecordForm::Lent`]), each into a binding
// of its own frame, held only while its record is handed over.

#[cfg(all(
    feature = "codec-frame",
    feature = "codec-push",
    all(
        feature = "alloc",
        any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
    ),
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[inline(never)]
fn lend_push<'f>(
    cursor: &mut SceCursor<'f>,
    each: &mut dyn EachRecord<'f>,
) -> Result<bool, crate::parse_error::InboundParseError> {
    let mut push = PushRead::<'f>::default();
    read_push(cursor, &mut push)?;
    each.take_record(WalkedRecord::Push(&push))
}

#[cfg(all(
    feature = "codec-frame",
    feature = "codec-request",
    all(
        feature = "alloc",
        any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
    ),
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[inline(never)]
fn lend_request<'f>(
    cursor: &mut SceCursor<'f>,
    each: &mut dyn EachRecord<'f>,
) -> Result<bool, crate::parse_error::InboundParseError> {
    let mut request = wz_codecs::request::RequestView::<'f>::default();
    read_request(cursor, &mut request)?;
    each.take_record(WalkedRecord::Request(&request))
}

#[cfg(all(
    feature = "codec-frame",
    feature = "codec-response",
    all(
        feature = "alloc",
        any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
    ),
    any(
        test,
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[inline(never)]
fn lend_response<'f>(
    cursor: &mut SceCursor<'f>,
    each: &mut dyn EachRecord<'f>,
) -> Result<bool, crate::parse_error::InboundParseError> {
    let mut response = wz_codecs::response::ResponseView::<'f>::default();
    read_response(cursor, &mut response)?;
    each.take_record(WalkedRecord::Response(&response))
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

#[cfg(all(feature = "alloc", feature = "codec-frame"))]
impl BatchHalt {
    /// Where in the payload the walk stopped: the byte everything from on is
    /// unparsed.
    pub const fn offset(&self) -> usize {
        match self {
            Self::UnknownMid { offset, .. } | Self::CodecError { offset, .. } => *offset,
        }
    }
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
    /// Where the next transport message of the batch begins in the payload,
    /// when the walk of a `Frame`'s payload ended at one; `None` when its
    /// records reach the end of the payload, or the walk halted.
    ///
    /// A `Frame` is read as the tail of its unit, and a sender puts a message
    /// of the other reliability into an open batch behind a second `Frame`
    /// header. The records of this `Frame` end before that header, and the
    /// bytes from it on are the next transport message, which the reader of the
    /// batch reads: they are neither records of this `Frame` nor unparsed, so
    /// the batch is complete and [`Self::unparsed_bytes`] does not count them.
    pub next_message_at: Option<usize>,
}

#[cfg(all(feature = "alloc", feature = "codec-frame"))]
impl BatchParse {
    /// `true` when the entire payload decoded with no halt — the shape a
    /// participant's strict parse also accepts.
    pub fn is_complete(&self) -> bool {
        self.halt.is_none()
    }

    /// Whether upstream's batch reader fails the batch these records of a
    /// `Frame` were read from ([`parse_frame_payload_best_effort`]).
    ///
    /// Upstream's `Frame` reader rewinds to a record that does not decode as a
    /// network message and ends the `Frame` there
    /// (`commons/zenoh-codec/src/transport/frame.rs` @ `reader.rewind(mark);`),
    /// and the batch's loop reads the bytes from that record on as a transport
    /// message, failing the whole batch when they are not one
    /// (`io/zenoh-transport/src/unicast/universal/rx.rs` @
    /// `.map_err(|_| zerror!("{}: decoding error", link.link))?;`). A transport
    /// id ends this walk before it halts ([`Self::next_message_at`]), so every
    /// halt stands at a byte no transport message begins with:
    ///
    /// - a record that failed to decode fails the batch;
    /// - an id in neither the transport nor the network space (`0x08` to
    ///   `0x18`) is refused by both of upstream's dispatches
    ///   (`commons/zenoh-codec/src/network/mod.rs` @
    ///   `_ => return Err(DidntRead),`) and fails the batch;
    /// - a network id this build has no decoder for is a limit of the build's
    ///   `codec-*` selection and not of the bytes, which upstream decodes, so
    ///   it does not.
    pub fn fails_the_frames_batch(&self) -> bool {
        match &self.halt {
            None => false,
            Some(BatchHalt::CodecError { .. }) => true,
            Some(BatchHalt::UnknownMid { mid, .. }) => !wz_codecs::wire_const::is_wire_front(*mid),
        }
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
///
/// `bytes` is the `Frame`'s payload as the tail of its unit, so the walk ends
/// before a transport message ([`BatchParse::next_message_at`]), as the record
/// walk of a participant does: upstream's `Frame` reader rewinds the message it
/// cannot read as a network one and the batch's loop reads it as a transport
/// message (`commons/zenoh-codec/src/transport/frame.rs` @ `reader.rewind(mark);`,
/// `io/zenoh-transport/src/unicast/universal/rx.rs` @ `while !batch.is_empty() {`).
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
pub fn parse_frame_payload_best_effort(bytes: &[u8]) -> BatchParse {
    parse_payload_best_effort(bytes, usize::MAX, RecordsEnd::AtTransportMessage)
}

/// Decode, best-effort, the bytes a completed fragment chain joined. They are
/// network messages and nothing else (upstream decodes a network message out of
/// them, `io/zenoh-transport/src/common/defragmentation.rs` @
/// `pub(crate) fn defragment`), so a transport MID among them is a record this
/// walk cannot read, and halts it as any unknown MID does.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
pub fn parse_reassembled_payload_best_effort(bytes: &[u8]) -> BatchParse {
    parse_payload_best_effort(bytes, usize::MAX, RecordsEnd::AtPayloadEnd)
}

/// Decode the single network record carried by a lowlatency framing unit.
/// Trailing bytes are reported, never treated as another batched message.
///
/// The unit is a KeepAlive, a Close or one network message
/// (`commons/zenoh-codec/src/transport/mod.rs` @
/// `id::KEEP_ALIVE => TransportBodyLowLatency::KeepAlive(codec.read(&mut *reader)?),`),
/// told apart by the masked id; its document would be a variant whose default
/// arm is the network message dispatch, which stays by hand until a document
/// can refuse an unknown id (SCE ADR 0100, not yet in the pinned language).
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
pub fn parse_lowlatency_payload_best_effort(bytes: &[u8]) -> BatchParse {
    parse_payload_best_effort(bytes, 1, RecordsEnd::AtPayloadEnd)
}

/// Where a best-effort walk's records may end before a halt.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum RecordsEnd {
    /// At the payload's end only: the bytes are network messages and nothing else.
    AtPayloadEnd,
    /// At a transport message too: the bytes are a `Frame`'s payload read as the tail of its
    /// unit, which ends where the batch's next transport message begins.
    AtTransportMessage,
}

#[cfg(all(feature = "alloc", feature = "codec-frame"))]
fn parse_payload_best_effort(bytes: &[u8], max_records: usize, end: RecordsEnd) -> BatchParse {
    let total = bytes.len();
    let mut messages = Vec::new();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut cursor = SceCursor::new(bytes);
    let mut halt = None;
    let mut next_message_at = None;
    while cursor.remaining() > 0 {
        // The offset is recomputed per record rather than tracked, so it
        // cannot drift from the cursor the decoders actually advance.
        // The cursor runs over `bytes`, so what it has left is at most their length.
        let offset = total.saturating_sub(cursor.remaining());
        let rest = bytes.get(offset..).unwrap_or_default();
        let header = rest.first().copied().unwrap_or_default();
        if end == RecordsEnd::AtTransportMessage && is_transport_mid(header & 0x1F) {
            next_message_at = Some(offset);
            break;
        }
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
            Ok(Decoded::Unknown) => {
                // An unknown MID: absorb the rest verbatim (the strict
                // parse's own behaviour) and stop, since the record's
                // length is unknowable and there is nothing to resync on.
                let mid = header & 0x1F;
                let rem = cursor.remaining();
                let body = rest.to_vec();
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
            // A message, judged or not: a capture judges nothing.
            Ok(_) => {
                let len = total
                    .saturating_sub(cursor.remaining())
                    .saturating_sub(offset);
                spans.resize(before, (0, 0));
                for _ in before..messages.len() {
                    spans.push((offset, len));
                }
            }
            Err(error) => {
                halt = Some(BatchHalt::CodecError { offset, error });
                break;
            }
        }
    }
    let unparsed_bytes = match halt {
        Some(BatchHalt::UnknownMid { offset, .. }) | Some(BatchHalt::CodecError { offset, .. }) => {
            total.saturating_sub(offset)
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
        next_message_at,
    }
}

/// The lent form of a record at the heap's capacity: its lists grow, and its bytes are the
/// frame's. The owned parse reads each record in it (`wz_codecs::lent` holds the lists inline at
/// the deployment's capacity, which a node with no allocator must).
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
type LentHeap<'f> = sce_forge_runtime::codec::Lent<'f, WireStorage>;

/// What [`decode_one_record`] made of the record at the cursor.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decoded {
    /// A MID this build has no envelope decoder for: nothing was read or put.
    Unknown,
    /// One message, put, whose chains the decode judged as it read them: the verdict the
    /// mandatory-extension rule gives it, which a participant uses rather than walking the
    /// chains of the owned message again.
    #[cfg(feature = "codec-push")]
    Judged(crate::ext_admit::ExtAdmission),
    /// One message, put, whose decode judged nothing: its verdict is its own
    /// ([`NetworkMessage::ext_admission`]).
    Unjudged,
}

#[cfg(all(feature = "alloc", feature = "codec-frame"))]
impl Decoded {
    /// The refusal the rule makes of the message the decode put, `put`, or `None` when a
    /// participant may act on it.
    fn refusal(
        self,
        put: Option<&NetworkMessage>,
    ) -> Option<crate::parse_error::InboundParseError> {
        match self {
            Self::Unknown => None,
            #[cfg(feature = "codec-push")]
            Self::Judged(verdict) => verdict.refusal(),
            Self::Unjudged => put.and_then(|message| message.ext_admission().refusal()),
        }
    }
}

/// Decode ONE record at the cursor and PUSH it onto `out`, and say what it was
/// ([`Decoded`]). `Decoded::Unknown` means the MID has no envelope decoder in this
/// build — the caller decides whether that is a terminating `Unknown` absorb (both
/// parsers) or something else.
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
) -> Result<Decoded, CodecError> {
    let header = cursor
        .peek_slice(1)?
        .first()
        .copied()
        .ok_or(CodecError::NeedMoreBytes)?;
    let mid = header & 0x1F;
    // The dispatch by the masked id stays here and not in a document: upstream
    // refuses an id it does not know (`commons/zenoh-codec/src/network/mod.rs` @
    // `impl<W> WCodec<&NetworkMessage, &mut W> for Zenoh080`), which a variant
    // that reaches an arm for every tag cannot state. Masked dispatch with that
    // refusal is what SCE ADR 0100 proposes, not yet in the pinned language.
    //
    // Only the three data-plane arms project through the origin; on a build with
    // none of them this is the one parameter nothing reads.
    #[cfg(not(any(
        feature = "codec-request",
        feature = "codec-push",
        feature = "codec-response"
    )))]
    let _ = origin;
    match mid {
        // Each record is read in the lent form at the HEAP's capacity (`LentHeap`: its lists grow,
        // its bytes are the frame's), and not at the node's (`wz_codecs::lent`, the lists inline at
        // the deployment's capacity, eight extensions to a chain): the protocol bounds a chain by
        // nothing, so a participant with an allocator reads any length, as upstream does.
        #[cfg(feature = "codec-request")]
        wire_const::N_MID_REQUEST => {
            let req = wz_codecs::request::RequestIn::<LentHeap<'_>>::decode(cursor)?;
            out.put(NetworkMessage::Request(Box::new(own_wire!(req, origin))))?;
        }
        // A Push is read by the one reader every walk reads it with (`push_read`), which judges
        // its chains as it reads them and builds each entry into the record at the heap's capacity
        // as it decodes it; the owned message is projected from that record. The verdict goes back
        // with it.
        #[cfg(feature = "codec-push")]
        wire_const::N_MID_PUSH => {
            let mut push = wz_codecs::push::PushIn::<LentHeap<'_>>::default();
            let verdict = push_read::read_push_owned(cursor, &mut push)?;
            out.put(NetworkMessage::Push(Box::new(own_wire!(push, origin))))?;
            return Ok(Decoded::Judged(verdict));
        }
        #[cfg(feature = "codec-response-final")]
        wire_const::N_MID_RESPONSE_FINAL => {
            let rf = wz_codecs::response_final::ResponseFinalIn::<LentHeap<'_>>::decode(cursor)?;
            out.put(NetworkMessage::ResponseFinal(
                rf.try_into_owned_in::<crate::transport_profile::TransportStorage>()?,
            ))?;
        }
        wire_const::N_MID_OAM => {
            let oam = wz_codecs::oam::OamIn::<LentHeap<'_>>::decode(cursor)?;
            out.put(NetworkMessage::Oam(
                oam.try_into_owned_in::<crate::transport_profile::TransportStorage>()?,
            ))?;
        }
        wire_const::N_MID_INTEREST => {
            let interest = wz_codecs::interest::InterestIn::<LentHeap<'_>>::decode(cursor)?;
            out.put(NetworkMessage::Interest(
                interest.try_into_owned_in::<crate::transport_profile::TransportStorage>()?,
            ))?;
        }
        #[cfg(feature = "codec-response")]
        wire_const::N_MID_RESPONSE => {
            let resp = wz_codecs::response::ResponseIn::<LentHeap<'_>>::decode(cursor)?;
            out.put(NetworkMessage::Response(Box::new(own_wire!(resp, origin))))?;
        }
        #[cfg(feature = "codec-declare")]
        wire_const::N_MID_DECLARE => {
            let decl = wz_codecs::declare::DeclareIn::<LentHeap<'_>>::decode(cursor)?;
            out.put(NetworkMessage::Declare(Box::new(
                decl.try_into_owned_in::<crate::transport_profile::TransportStorage>()?,
            )))?;
        }
        _ => return Ok(Decoded::Unknown),
    }
    Ok(Decoded::Unjudged)
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
#[cfg(all(
    test,
    feature = "alloc",
    feature = "codec-frame",
    feature = "codec-push"
))]
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
            // An id in 4 to 11, whatever the count: the encoding and mandatory bits stay clear.
            wire.push(0x80 | (4 + (i % 8) as u8));
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
                        crate::put_payload::chain(put).len(),
                        crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH
                    );
                }
                other => panic!("expected a Put body, got {other:?}"),
            },
            other => panic!("expected a Push, got {other:?}"),
        }
    }

    /// THE PAST-THE-CAP LEG. More extensions than a node stores of a chain.
    /// The protocol bounds the chain by nothing, and a participant with an
    /// allocator reads any length, as upstream does: the owned parse reads each
    /// record in the lent form at the HEAP's capacity (`LentHeap`), where it
    /// read it at the node's (`wz_codecs::lent`, eight entries) and refused the
    /// ninth as storage (`CapacityExceeded`). The payload after the chain is
    /// the one on the wire, on the NESTED chain, which is the one that costs a
    /// payload; the `Push`'s own chain is absent here.
    #[test]
    fn a_chain_past_what_a_node_stores_is_read_whole_with_an_allocator() {
        for count in [
            crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH + 1,
            40,
            300,
            5_000,
        ] {
            let wire = push_with_put_exts(count);
            let msgs = parse_frame_payload(&wire).expect("a terminated chain must parse");
            assert_eq!(msgs.len(), 1);
            match &msgs[0] {
                NetworkMessage::Push(p) => match &p.body {
                    wz_codecs::push::PushOwnedVariant::CodecZenohMsgPut(put) => {
                        assert_eq!(
                            crate::put_payload::inline_bytes(put),
                            Some(&[0xAAu8, 0xBB, 0xCC][..]),
                            "{count} extensions"
                        );
                        assert_eq!(crate::put_payload::chain(put).len(), count);
                    }
                    other => panic!("expected a Put body, got {other:?}"),
                },
                other => panic!("expected a Push, got {other:?}"),
            }
        }
    }

    /// The chain headers (the shared-memory marker's at its place) and the
    /// inline payload of the Put a Push record carries.
    fn put_reading(msg: &NetworkMessage) -> (Vec<u8>, Option<Vec<u8>>) {
        match msg {
            NetworkMessage::Push(p) => match &p.body {
                wz_codecs::push::PushOwnedVariant::CodecZenohMsgPut(put) => (
                    crate::put_payload::chain_headers(put).map_or_else(Vec::new, |h| h.collect()),
                    crate::put_payload::inline_bytes(put).map(<[u8]>::to_vec),
                ),
                other => panic!("expected a Put body, got {other:?}"),
            },
            other => panic!("expected a Push, got {other:?}"),
        }
    }

    /// The chain headers and the inline payload of the Put a lent Push carries, read where the
    /// frame lies: [`put_reading`] of its view. The fixtures carry no shared-memory marker.
    fn put_view_reading(push: &wz_codecs::push::PushView<'_>) -> (Vec<u8>, Option<Vec<u8>>) {
        match &push.body {
            wz_codecs::push::PushViewVariant::CodecZenohMsgPut(put) => (
                crate::put_payload::view_chain(put).map_or_else(Vec::new, |(rest, place)| {
                    assert_eq!(place, None, "the fixtures carry no marker");
                    sce_forge_runtime::codec::Entries::entries(rest)
                        .map(|e| e.header)
                        .collect()
                }),
                match &put.extensions_has_0x12 {
                    wz_codecs::msg_put::MsgPutExtensionsHas0x12::NotHas0x12 { payload, .. } => {
                        Some(payload.into_inner().to_vec())
                    }
                    _ => None,
                },
            ),
            other => panic!("expected a Put body, got {other:?}"),
        }
    }

    /// THE LENT WALK PAST THE CAP. The receive path lends a Push as its view,
    /// which holds a chain as the bytes it occupies, so a Push with more
    /// extensions than a node stores of a chain is lent like any other, read
    /// whole as the batch decode reads it, and the walk goes on from its end.
    /// Turned red by a lent form that holds the chain at the node's capacity,
    /// which hands the long Push over owned.
    #[test]
    fn the_lent_walk_lends_a_push_past_what_a_node_stores_and_goes_on_after_it() {
        let depth = crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH;
        for count in [depth + 1, 32, 300] {
            let wire = [
                push_with_put_exts(depth),
                push_with_put_exts(count),
                push_with_put_exts(depth),
            ]
            .concat();
            let batch = parse_frame_payload(&wire).expect("the batch decode reads all three");
            assert_eq!(batch.len(), 3);
            let expected = put_reading(&batch[1]);
            assert_eq!(expected.0.len(), count, "the batch decode reads it whole");
            assert_eq!(expected.1.as_deref(), Some(&[0xAAu8, 0xBB, 0xCC][..]));
            let mut record = new_record_buf();
            let mut seen: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();
            let result = for_each_record(&wire, &mut record, RecordForm::Lent, |one| match one {
                WalkedRecord::Push(push) => seen.push(put_view_reading(&push.view)),
                #[allow(unreachable_patterns)]
                _ => panic!("only Pushes were encoded, and each is lent"),
            });
            assert!(result.is_ok(), "{count} extensions: {result:?}");
            assert_eq!(seen.len(), 3, "{count} extensions");
            assert_eq!(seen[1].0.len(), count, "read whole where it lies");
            assert_eq!(seen[1].1, expected.1, "{count} extensions");
            assert_eq!(seen[2].0.len(), depth, "the walk goes on after it");
        }
    }

    /// A walk that lends hands each Push over as the view the codec decodes it to, and goes on
    /// where the codec's cursor goes on: a frame of Puts with and without the QoS extension, with
    /// a suffix and in either mapping, around a Put with a chain of its own, each lent record equal
    /// to the codec's decode of the same bytes in turn.
    #[test]
    fn the_lent_walk_hands_each_push_over_as_the_codec_reads_it() {
        let ours = [0x9du8, 3, 0x21, 0x1a, 0x01, 3, b'a', b'b', b'c'];
        let theirs = [0xddu8, 5, 0x21, 0x05, 0x01, 1, b'x'];
        let suffixed = [0x7du8, 5, 2, b'a', b'b', 0x01, 0];
        let declined = push_with_put_exts(2);
        let wire = [
            &ours[..],
            &declined[..],
            &theirs[..],
            &suffixed[..],
            &ours[..],
        ]
        .concat();
        let mut expected = Vec::new();
        let mut cursor = sce_forge_runtime::codec::SceCursor::new(&wire);
        while cursor.remaining() > 0 {
            expected.push(
                wz_codecs::push::PushView::decode(&mut cursor)
                    .expect("the codec reads each record"),
            );
        }
        assert_eq!(expected.len(), 5);
        let mut record = new_record_buf();
        let mut seen = Vec::new();
        let result = for_each_record(&wire, &mut record, RecordForm::Lent, |one| {
            if let WalkedRecord::Push(push) = one {
                seen.push(push.view.clone());
            } else {
                panic!("only Pushes were encoded, and each is lent");
            }
        });
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(seen, expected);
    }

    /// The slot profile's walk holds no owned form of a record, and lends a Push
    /// past what a node stores of a chain as it lends any other: the view reads
    /// the chain where it lies. Turned red by a lent form that holds the chain
    /// at the node's capacity, which refuses the second Push.
    #[cfg(all(feature = "rx-lent-control", feature = "rx-push"))]
    #[test]
    fn the_slot_walk_lends_a_push_past_what_a_node_stores() {
        let depth = crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH;
        let wire = [push_with_put_exts(depth), push_with_put_exts(depth + 1)].concat();
        let mut record = new_record_buf();
        let mut chains: Vec<usize> = Vec::new();
        let result = for_each_record(&wire, &mut record, RecordForm::LentControl, |one| {
            if let WalkedRecord::Push(push) = one {
                chains.push(put_view_reading(&push.view).0.len());
            }
        });
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(chains, [depth, depth + 1]);
    }

    /// An observer keeps what it read and reports where it stopped, rather
    /// than losing the batch — G4's contract, which A1 must not undo. The
    /// leading clean record survives; the record the frame ends inside does
    /// not become a decoded message.
    #[test]
    fn the_best_effort_walk_halts_on_a_cut_record_without_losing_the_earlier_one() {
        let mut wire = wz_codecs::lent::Oam {
            id: 7,
            ..Default::default()
        }
        .encode_to_vec();
        let mut push = push_with_put_exts(crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH + 1);
        // The frame ends inside the payload that follows the chain.
        push.truncate(push.len() - 2);
        wire.extend_from_slice(&push);

        let best = parse_frame_payload_best_effort(&wire);
        assert_eq!(best.messages.len(), 1, "the clean OAM record is kept");
        assert!(!best.is_complete(), "the cut record must halt the walk");
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
/// oversight — it is `stats_space_of`'s `None` arm, pinned by this module's
/// `an_unresolvable_alias_counts_as_user`. The reasoning: the peer's id
/// space lives on the face (the forwarder's per-face table), not on the session,
/// so the inbound seam has no table to consult, and counting an unknown
/// expression as admin would move ADMIN traffic counts on nothing more than an
/// alias being used.
#[cfg(feature = "transport-stats")]
pub fn stats_class<F>(msg: &NetworkMessage, resolve_alias: F) -> crate::stats::NetworkStatsClass
where
    F: Fn(crate::wire_id::ExprId) -> Option<alloc::string::String>,
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
    F: Fn(crate::wire_id::ExprId) -> Option<alloc::string::String>,
{
    use wz_codecs::wireexpr::WireexprOwnedVariant as V;
    let (id, suffix) = match &keyexpr.body {
        V::WireexprNonlocal(b) => (b.id, b.suffix.as_ref()),
        V::WireexprLocal(b) => (b.id, b.suffix.as_ref()),
    };
    stats_space_of_key(id, suffix.map(|s| s.as_text().into_inner()), resolve_alias)
}

/// [`stats_space_of`] for a key given as its parts, the mapping `id` and the `suffix`: the one
/// rule both an owned Wireexpr and a key a sender holds as borrowed parts are classified by.
#[cfg(all(
    feature = "transport-stats",
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response"
    )
))]
fn stats_space_of_key<F>(
    id: crate::wire_id::ExprId,
    suffix: Option<&str>,
    resolve_alias: &F,
) -> crate::stats::StatSpace
where
    F: Fn(crate::wire_id::ExprId) -> Option<alloc::string::String>,
{
    if id == 0 {
        // Fully literal: the suffix IS the whole expression.
        return crate::stats::StatSpace::of_keyexpr(suffix.unwrap_or_default());
    }
    match resolve_alias(id) {
        Some(prefix) => crate::stats::StatSpace::of_keyexpr(&prefix),
        None => crate::stats::StatSpace::User,
    }
}

/// The key expression a data message addresses, an alias resolved through the caller's id space
/// as [`stats_class`] resolves one: what the session's `stats/filters` are matched against. `None`
/// for a message with no key expression, and for an alias the space does not hold, which counts
/// under no filter as it counts in the user space.
#[cfg(feature = "transport-stats")]
pub fn stats_keyexpr<F>(msg: &NetworkMessage, resolve_alias: F) -> Option<alloc::string::String>
where
    F: Fn(crate::wire_id::ExprId) -> Option<alloc::string::String>,
{
    #[cfg(not(any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response"
    )))]
    let _ = &resolve_alias;
    match msg {
        #[cfg(feature = "codec-push")]
        NetworkMessage::Push(p) => stats_keyexpr_of_wireexpr(&p.keyexpr, &resolve_alias),
        #[cfg(feature = "codec-request")]
        NetworkMessage::Request(r) => stats_keyexpr_of_wireexpr(&r.keyexpr, &resolve_alias),
        #[cfg(feature = "codec-response")]
        NetworkMessage::Response(r) => stats_keyexpr_of_wireexpr(&r.keyexpr, &resolve_alias),
        _ => None,
    }
}

/// [`stats_keyexpr`] for a Wireexpr a sender holds.
#[cfg(all(
    feature = "transport-stats",
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response"
    )
))]
pub fn stats_keyexpr_of_wireexpr<F>(
    keyexpr: &crate::wire::parts::WireexprOwned,
    resolve_alias: &F,
) -> Option<alloc::string::String>
where
    F: Fn(crate::wire_id::ExprId) -> Option<alloc::string::String>,
{
    use wz_codecs::wireexpr::WireexprOwnedVariant as V;
    let (id, suffix) = match &keyexpr.body {
        V::WireexprNonlocal(b) => (b.id, b.suffix.as_ref()),
        V::WireexprLocal(b) => (b.id, b.suffix.as_ref()),
    };
    stats_keyexpr_of_key(id, suffix.map(|s| s.as_text().into_inner()), resolve_alias)
}

/// [`stats_keyexpr`] for a key given as its parts, the mapping `id` and the `suffix`: the literal
/// when `id` is 0, else the alias's key with the suffix after it.
#[cfg(feature = "transport-stats")]
pub fn stats_keyexpr_of_key<F>(
    id: crate::wire_id::ExprId,
    suffix: Option<&str>,
    resolve_alias: &F,
) -> Option<alloc::string::String>
where
    F: Fn(crate::wire_id::ExprId) -> Option<alloc::string::String>,
{
    if id == 0 {
        return suffix.map(alloc::string::String::from);
    }
    let mut keyexpr = resolve_alias(id)?;
    if let Some(suffix) = suffix {
        keyexpr.push_str(suffix);
    }
    Some(keyexpr)
}

/// [`push_stats_class`] for a plain `Put` a sender holds as borrowed parts (the key's mapping
/// `id` and `suffix`, and a payload of `pl_bytes`), with no owned message to read: a plain Put
/// has no attachment and no shared-memory marker, so its class is the one
/// [`push_stats_class`] gives the owned message of the same parts.
#[cfg(all(feature = "transport-stats", feature = "codec-push"))]
pub fn plain_put_stats_class<F>(
    id: crate::wire_id::ExprId,
    suffix: Option<&str>,
    pl_bytes: usize,
    resolve_alias: F,
) -> crate::stats::NetworkStatsClass
where
    F: Fn(crate::wire_id::ExprId) -> Option<alloc::string::String>,
{
    use crate::stats::{MessageLabel, NetworkStatsClass, StatMessage};
    NetworkStatsClass::net(
        MessageLabel::Put,
        StatMessage::Put,
        stats_space_of_key(id, suffix, &resolve_alias),
        pl_bytes,
    )
}

/// [`plain_put_stats_class`] for a sender that holds the key's whole text: the space is the
/// key's own, as a literal key's is, whatever declaration names the key on the wire, so no alias
/// is resolved to classify it.
#[cfg(all(feature = "transport-stats", feature = "codec-push"))]
pub fn named_put_stats_class(keyexpr: &str, pl_bytes: usize) -> crate::stats::NetworkStatsClass {
    use crate::stats::{MessageLabel, NetworkStatsClass, StatMessage, StatSpace};
    NetworkStatsClass::net(
        MessageLabel::Put,
        StatMessage::Put,
        StatSpace::of_keyexpr(keyexpr),
        pl_bytes,
    )
}

/// [`push_stats_class`] for a Put or a Del a sender writes from its parts (the key's mapping `id`
/// and `suffix`, the payload's length and the attachment's), with no owned message to read: the
/// class [`push_stats_class`] gives the owned Push of the same parts, whose Del is sized by its
/// attachment alone.
#[cfg(all(feature = "transport-stats", feature = "codec-push"))]
pub fn publication_stats_class<F>(
    id: crate::wire_id::ExprId,
    suffix: Option<&str>,
    kind: crate::sample::SampleKind,
    payload: usize,
    attachment: usize,
    resolve_alias: F,
) -> crate::stats::NetworkStatsClass
where
    F: Fn(crate::wire_id::ExprId) -> Option<alloc::string::String>,
{
    use crate::sample::SampleKind;
    use crate::stats::{MessageLabel, NetworkStatsClass, StatMessage};
    let space = stats_space_of_key(id, suffix, &resolve_alias);
    match kind {
        SampleKind::Put => NetworkStatsClass::net(
            MessageLabel::Put,
            StatMessage::Put,
            space,
            payload.saturating_add(attachment),
        ),
        SampleKind::Del => {
            NetworkStatsClass::net(MessageLabel::Del, StatMessage::Del, space, attachment)
        }
    }
}

/// [`request_stats_class`] for a get a sender writes from its parts, with no owned `Request` to
/// read: the class the owned `Request` of the same parts is given
/// ([`crate::query_parts::GetParts::owned_request`]), its payload what the writer writes of the
/// query's value and its attachment.
#[cfg(all(feature = "transport-stats", feature = "codec-request"))]
pub fn get_stats_class<F>(
    writer: &crate::lent_request::RequestWriter<'_>,
    resolve_alias: F,
) -> crate::stats::NetworkStatsClass
where
    F: Fn(crate::wire_id::ExprId) -> Option<alloc::string::String>,
{
    use crate::stats::{MessageLabel, NetworkStatsClass, StatMessage};
    let key = writer.parts().key;
    NetworkStatsClass::net(
        MessageLabel::Query,
        StatMessage::Query,
        stats_space_of_key(key.id(), key.suffix(), &resolve_alias),
        writer.payload_len(),
    )
}

/// [`response_stats_class`] for a reply a sender writes from its parts, with no owned `Response` to
/// read: a reply by its payload and the attachment the build writes, a Del by its attachment
/// alone, an Err by its payload, each in the space of the literal key the reply is stamped with. A
/// buffer of shared memory is written as its bytes, and is counted so.
#[cfg(all(feature = "transport-stats", feature = "codec-response"))]
pub fn reply_parts_stats_class(
    parts: &crate::reply_stage::ReplyParts<'_>,
) -> crate::stats::NetworkStatsClass {
    use crate::reply_stage::{PartsBody, PartsKind};
    use crate::stats::{MessageLabel, NetworkStatsClass, StatMessage, StatSpace};
    let space = StatSpace::of_keyexpr(parts.keyexpr);
    match &parts.kind {
        PartsKind::Reply {
            body, attachment, ..
        } => {
            #[cfg(feature = "pubsub-attachment")]
            let attachment = attachment.map_or(0, <[u8]>::len);
            #[cfg(not(feature = "pubsub-attachment"))]
            let attachment = {
                let _ = attachment;
                0
            };
            let payload = match body {
                PartsBody::Put(bytes) => bytes.len(),
                PartsBody::Del => 0,
                #[cfg(feature = "transport-shm")]
                PartsBody::Shared(handle) => handle.bytes().len(),
            };
            NetworkStatsClass::net(
                MessageLabel::Reply,
                StatMessage::Reply,
                space,
                payload.saturating_add(attachment),
            )
        }
        #[cfg(feature = "query-reply-err")]
        PartsKind::Err { payload, .. } => NetworkStatsClass::net(
            MessageLabel::ReplyErr,
            StatMessage::Reply,
            space,
            payload.len(),
        ),
    }
}

/// Fold a classified body into a class, selecting the `shm` medium when the
/// body's extension chain carries the SHM descriptor marker — the wz twin of
/// upstream's `labels.shm`.
#[cfg(all(
    feature = "transport-stats",
    any(
        feature = "codec-push",
        all(feature = "codec-request", feature = "request-put-del"),
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

/// The value length of the ZBUF extension of identity `eid` in `extensions`,
/// the last entry of it as every reader picks one
/// ([`crate::ext_view::last_by_eid`]), or `0`. The extension is told by its identity
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
    crate::ext_view::last_by_eid(extensions.unwrap_or_default(), eid)
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
        all(feature = "codec-request", feature = "request-put-del"),
        feature = "codec-response"
    )
))]
fn put_payload_size<S: wz_codecs::msg_put::MsgPutStorage>(
    put: &wz_codecs::msg_put::MsgPutOwned<S>,
) -> usize {
    crate::put_payload::payload_len(put).saturating_add(zbuf_ext_len(
        Some(crate::put_payload::chain(put)),
        crate::ext_header::body_eid::PUT_ATTACHMENT,
    ))
}

/// See [`put_payload_size`].
#[cfg(all(
    feature = "transport-stats",
    any(
        feature = "codec-push",
        all(feature = "codec-request", feature = "request-put-del"),
        feature = "codec-response"
    )
))]
fn del_payload_size(extensions: Option<&[crate::wire::parts::ExtEntryOwned]>) -> usize {
    zbuf_ext_len(extensions, crate::ext_header::body_eid::DEL_ATTACHMENT)
}

/// [`stats_data_class`] for a `Put` body. A Put's shared-memory marker is the
/// layout it carries ([`crate::put_payload::is_sliced`]) rather than one of the
/// chain entries [`crate::put_payload::chain`] yields, so the `shm` medium is
/// read from the layout.
#[cfg(all(
    feature = "transport-stats",
    any(
        feature = "codec-push",
        all(feature = "codec-request", feature = "request-put-del"),
        feature = "codec-response"
    )
))]
fn put_stats_class<S: wz_codecs::msg_put::MsgPutStorage>(
    kind: crate::stats::MessageLabel,
    message: crate::stats::StatMessage,
    space: crate::stats::StatSpace,
    put: &wz_codecs::msg_put::MsgPutOwned<S>,
) -> crate::stats::NetworkStatsClass {
    let class = stats_data_class(
        kind,
        message,
        space,
        put_payload_size(put),
        Some(crate::put_payload::chain(put)),
    );
    #[cfg(feature = "transport-shm")]
    if crate::put_payload::is_sliced(put) {
        return class.on_shm();
    }
    class
}

/// [`stats_class`] for a `Push` body — the pub-sub data plane. Shared by the TX
/// chokepoint (which holds the typed body, not the enum) and the RX walk.
#[cfg(all(feature = "transport-stats", feature = "codec-push"))]
pub fn push_stats_class<F>(
    push: &crate::wire::PushOwned,
    resolve_alias: F,
) -> crate::stats::NetworkStatsClass
where
    F: Fn(crate::wire_id::ExprId) -> Option<alloc::string::String>,
{
    push_body_stats_class(push, stats_space_of(&push.keyexpr, &resolve_alias))
}

/// [`push_stats_class`] for `push` sent under the literal key `keyexpr` in place of the key it
/// names: the class of the Put a router delivers to a leaf, read off the Put it received, whose key
/// named an alias of the face it came from that no session it is sent on holds.
#[cfg(all(feature = "transport-stats", feature = "codec-push"))]
pub fn push_stats_class_under(
    push: &crate::wire::PushOwned,
    keyexpr: &str,
) -> crate::stats::NetworkStatsClass {
    push_body_stats_class(push, crate::stats::StatSpace::of_keyexpr(keyexpr))
}

/// The class of `push`'s body, its key expression read into `space`. Inlined into both callers,
/// so that [`push_stats_class`] is one body in a build that never classifies a Put under another
/// key, which is every build without a router.
#[cfg(all(feature = "transport-stats", feature = "codec-push"))]
#[inline(always)]
fn push_body_stats_class(
    push: &crate::wire::PushOwned,
    space: crate::stats::StatSpace,
) -> crate::stats::NetworkStatsClass {
    use crate::stats::{MessageLabel, StatMessage};
    use wz_codecs::push::PushOwnedVariant as V;
    match &push.body {
        V::CodecZenohMsgPut(b) | V::Default { body: b, .. } => {
            put_stats_class(MessageLabel::Put, StatMessage::Put, space, b)
        }
        V::CodecZenohMsgDel(b) => stats_data_class(
            MessageLabel::Del,
            StatMessage::Del,
            space,
            del_payload_size(b.extensions.entries()),
            b.extensions.entries(),
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
    F: Fn(crate::wire_id::ExprId) -> Option<alloc::string::String>,
{
    use crate::stats::{MessageLabel, StatMessage};
    use wz_codecs::request::RequestOwnedVariant as V;
    let space = stats_space_of(&request.keyexpr, &resolve_alias);
    // Every Request is a `query` to the registry whatever its body: upstream
    // labels by the network message, and its `Request` arm names one kind
    // (`commons/zenoh-stats/src/labels.rs` @ `NetworkBodyRef::Request(_) => MessageLabel::Query,`).
    let query = match &request.body {
        #[cfg(feature = "request-put-del")]
        V::CodecZenohMsgPut(b) => {
            return put_stats_class(MessageLabel::Query, StatMessage::Put, space, b);
        }
        #[cfg(feature = "request-put-del")]
        V::CodecZenohMsgDel(b) => {
            return stats_data_class(
                MessageLabel::Query,
                StatMessage::Del,
                space,
                del_payload_size(b.extensions.entries()),
                b.extensions.entries(),
            );
        }
        V::CodecZenohQuery(b) => b,
        // An unknown tag carries a Query's body. Anything else is a Put or a Del arm the codec
        // builds for another crate of the graph where this build names neither, so it has no
        // class here; the binding keeps the match exhaustive whichever arms the codec has.
        other => {
            let V::Default { body, .. } = other else {
                return crate::stats::NetworkStatsClass::undecoded();
            };
            body
        }
    };
    // The marker that precedes a Query's value is its own extension, not a
    // Put's (`ext_header::body_ext_id::QUERY_SHM`), and upstream's `is_shm`
    // for a Request reads it off the Query's value body.
    stats_class_marked(
        MessageLabel::Query,
        StatMessage::Query,
        space,
        query_payload_size(query.extensions.entries()),
        query.extensions.entries(),
        crate::ext_header::body_ext_id::QUERY_SHM,
    )
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
    crate::ext_view::query_value_payload_len(extensions.unwrap_or_default()).saturating_add(
        zbuf_ext_len(extensions, crate::ext_header::body_eid::QUERY_ATTACHMENT),
    )
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
    F: Fn(crate::wire_id::ExprId) -> Option<alloc::string::String>,
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
                RV::CodecZenohMsgPut(p) | RV::Default { body: p, .. } => {
                    put_stats_class(MessageLabel::Reply, StatMessage::Reply, space, p)
                }
                RV::CodecZenohMsgDel(d) => stats_data_class(
                    MessageLabel::Reply,
                    StatMessage::Reply,
                    space,
                    del_payload_size(d.extensions.entries()),
                    d.extensions.entries(),
                ),
            }
        }
        // The JSON schema folds an Err onto `reply`; the registry does not.
        V::CodecZenohErr(b) => stats_data_class(
            MessageLabel::ReplyErr,
            StatMessage::Reply,
            space,
            b.payload_len as usize,
            b.extensions.entries(),
        ),
    }
}

/// What the transport counters read of one received record: its class, the band it carries and
/// the key it names. A record the walk lends is read here, off the record as the walk decoded it
/// ([`Self::of_lent`]); an owned record is read off its message ([`stats_class`],
/// [`network_message_priority`], [`stats_keyexpr`]) by the same rules, so a record counts the
/// same whichever form the build received it in, and counting a lent record decodes nothing
/// again and allocates nothing.
#[cfg(all(
    feature = "transport-stats",
    feature = "alloc",
    all(
        feature = "codec-frame",
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    )
))]
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RecordClass<'k> {
    pub(crate) class: crate::stats::NetworkStatsClass,
    pub(crate) priority: crate::qos::Priority,
    /// The key's mapping id and suffix, for a data record; `None` for a control record.
    key: Option<(crate::wire_id::ExprId, Option<&'k str>)>,
}

#[cfg(all(
    feature = "transport-stats",
    feature = "alloc",
    all(
        feature = "codec-frame",
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    )
))]
impl<'k> RecordClass<'k> {
    /// The key expression the record addresses, an alias resolved through no space, as
    /// [`stats_keyexpr`] resolves the owned message's: what the session's `stats/filters` are
    /// matched against.
    pub(crate) fn keyexpr(&self) -> Option<alloc::string::String> {
        let (id, suffix) = self.key?;
        stats_keyexpr_of_key(id, suffix, &|_id| None)
    }

    /// A control record of `label`, its band read off its chain.
    #[cfg(any(
        all(feature = "rx-lent-control", feature = "rx-control"),
        all(
            feature = "rx-lent-control",
            feature = "codec-response-final",
            feature = "rx-response"
        )
    ))]
    fn control<E: crate::ext_view::ExtEntryView>(
        label: crate::stats::MessageLabel,
        extensions: impl IntoIterator<Item = E>,
    ) -> Self {
        Self {
            class: crate::stats::NetworkStatsClass::control(label),
            priority: crate::declare_ext_qos::read_qos_of(extensions).priority(),
            key: None,
        }
    }

    /// The class of a record the walk lent, `None` for one it hands owned.
    pub(crate) fn of_lent(one: &WalkedRecord<'_, 'k>) -> Option<Self> {
        match one {
            WalkedRecord::Never(never, _) => match *never {},
            #[cfg(all(
                feature = "alloc",
                any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
            ))]
            WalkedRecord::Owned(_) => None,
            #[cfg(all(
                feature = "codec-push",
                any(
                    all(
                        feature = "alloc",
                        any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
                    ),
                    feature = "rx-push"
                )
            ))]
            WalkedRecord::Push(push) => Some(lent_push_class(&push.view)),
            #[cfg(feature = "codec-request")]
            WalkedRecord::Request(request) => Some(lent_request_class(request)),
            #[cfg(all(
                feature = "codec-response",
                any(
                    all(
                        feature = "alloc",
                        any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
                    ),
                    feature = "rx-response"
                )
            ))]
            WalkedRecord::Response(response) => Some(lent_response_class(response)),
            #[cfg(all(
                feature = "rx-lent-control",
                feature = "codec-declare",
                feature = "rx-control"
            ))]
            WalkedRecord::Declare(declare) => Some(Self::control(
                crate::stats::MessageLabel::Declare,
                declare
                    .extensions
                    .as_ref()
                    .map_or(&[][..], |chain| {
                        sce_forge_runtime::codec::SceList::as_slice(chain.inner())
                    })
                    .iter(),
            )),
            #[cfg(all(
                feature = "rx-lent-control",
                feature = "codec-response-final",
                feature = "rx-response"
            ))]
            WalkedRecord::ResponseFinal(response_final) => Some(Self::control(
                crate::stats::MessageLabel::ResponseFinal,
                response_final
                    .extensions
                    .as_ref()
                    .map_or(&[][..], |chain| {
                        sce_forge_runtime::codec::SceList::as_slice(chain.inner())
                    })
                    .iter(),
            )),
            #[cfg(all(feature = "rx-lent-control", feature = "rx-control"))]
            WalkedRecord::Interest(interest) => Some(Self::control(
                crate::stats::MessageLabel::Interest,
                interest
                    .extensions
                    .as_ref()
                    .map_or(&[][..], |chain| {
                        sce_forge_runtime::codec::SceList::as_slice(chain.inner())
                    })
                    .iter(),
            )),
            #[cfg(all(
                feature = "rx-lent-control",
                feature = "rx-control",
                feature = "transport-stats",
                feature = "alloc"
            ))]
            WalkedRecord::Oam(oam) => Some(Self::control(
                crate::stats::MessageLabel::Oam,
                oam.extensions
                    .as_ref()
                    .map_or(&[][..], |chain| {
                        sce_forge_runtime::codec::SceList::as_slice(chain.inner())
                    })
                    .iter(),
            )),
            // A MID this build has no decoder for: the owned walk's `Unknown`, which carries no
            // extension to read a band off.
            #[cfg(feature = "rx-lent-control")]
            WalkedRecord::Skipped => Some(Self {
                class: crate::stats::NetworkStatsClass::undecoded(),
                priority: crate::qos::Priority::DEFAULT,
                key: None,
            }),
        }
    }
}

/// The length of the plain ZBuf body of the first entry of `extensions` whose identity is `eid`,
/// or `0`: [`zbuf_ext_len`] over the entries a chain yields.
#[cfg(any(
    all(
        feature = "transport-stats",
        feature = "alloc",
        all(
            feature = "codec-frame",
            any(
                test,
                feature = "session-unicast",
                all(feature = "session-multicast", not(feature = "alloc"))
            )
        ),
        all(
            feature = "codec-push",
            any(
                all(
                    feature = "alloc",
                    any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
                ),
                feature = "rx-push"
            )
        )
    ),
    all(
        feature = "transport-stats",
        feature = "alloc",
        all(
            feature = "codec-frame",
            any(
                test,
                feature = "session-unicast",
                all(feature = "session-multicast", not(feature = "alloc"))
            )
        ),
        feature = "codec-request"
    ),
    all(
        feature = "transport-stats",
        feature = "alloc",
        all(
            feature = "codec-frame",
            any(
                test,
                feature = "session-unicast",
                all(feature = "session-multicast", not(feature = "alloc"))
            )
        ),
        all(
            feature = "codec-response",
            any(
                all(
                    feature = "alloc",
                    any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
                ),
                feature = "rx-response"
            )
        )
    )
))]
fn zbuf_ext_len_in<E: crate::ext_view::ExtEntryView>(
    extensions: impl IntoIterator<Item = E>,
    eid: u8,
) -> usize {
    crate::ext_view::last_by_eid_in(extensions, eid)
        .and_then(|ext| ext.plain_zbuf().map(<[u8]>::len))
        .unwrap_or(0)
}

/// [`stats_class_marked`] over the entries a chain yields: the `shm` medium when one of them is
/// the marker `marker` names.
#[cfg(any(
    all(
        feature = "transport-stats",
        feature = "alloc",
        all(
            feature = "codec-frame",
            any(
                test,
                feature = "session-unicast",
                all(feature = "session-multicast", not(feature = "alloc"))
            )
        ),
        all(
            feature = "codec-push",
            any(
                all(
                    feature = "alloc",
                    any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
                ),
                feature = "rx-push"
            )
        )
    ),
    all(
        feature = "transport-stats",
        feature = "alloc",
        all(
            feature = "codec-frame",
            any(
                test,
                feature = "session-unicast",
                all(feature = "session-multicast", not(feature = "alloc"))
            )
        ),
        feature = "codec-request"
    ),
    all(
        feature = "transport-stats",
        feature = "alloc",
        all(
            feature = "codec-frame",
            any(
                test,
                feature = "session-unicast",
                all(feature = "session-multicast", not(feature = "alloc"))
            )
        ),
        all(
            feature = "codec-response",
            any(
                all(
                    feature = "alloc",
                    any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
                ),
                feature = "rx-response"
            )
        )
    )
))]
fn stats_class_marked_in<E: crate::ext_view::ExtEntryView>(
    kind: crate::stats::MessageLabel,
    message: crate::stats::StatMessage,
    space: crate::stats::StatSpace,
    pl_bytes: usize,
    _extensions: impl IntoIterator<Item = E>,
    _marker: u8,
) -> crate::stats::NetworkStatsClass {
    let class = crate::stats::NetworkStatsClass::net(kind, message, space, pl_bytes);
    #[cfg(feature = "transport-shm")]
    {
        let want = crate::ext_header::ext_eid(_marker);
        if _extensions
            .into_iter()
            .any(|ext| crate::ext_header::ext_eid(ext.header()) == want)
        {
            return class.on_shm();
        }
    }
    class
}

/// The marker a Put's and a Del's chain carries before a shared-memory body.
#[cfg(any(
    all(
        feature = "transport-stats",
        feature = "alloc",
        all(
            feature = "codec-frame",
            any(
                test,
                feature = "session-unicast",
                all(feature = "session-multicast", not(feature = "alloc"))
            )
        ),
        all(
            feature = "codec-push",
            any(
                all(
                    feature = "alloc",
                    any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
                ),
                feature = "rx-push"
            )
        )
    ),
    any(
        all(
            feature = "transport-stats",
            feature = "alloc",
            all(
                feature = "codec-frame",
                any(
                    test,
                    feature = "session-unicast",
                    all(feature = "session-multicast", not(feature = "alloc"))
                )
            ),
            all(
                feature = "codec-response",
                any(
                    all(
                        feature = "alloc",
                        any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
                    ),
                    feature = "rx-response"
                )
            )
        ),
        all(
            all(
                feature = "transport-stats",
                feature = "alloc",
                all(
                    feature = "codec-frame",
                    any(
                        test,
                        feature = "session-unicast",
                        all(feature = "session-multicast", not(feature = "alloc"))
                    )
                ),
                feature = "codec-request"
            ),
            feature = "request-put-del"
        )
    )
))]
const DATA_SHM_MARKER: u8 = crate::ext_header::body_ext_id::SHM | crate::ext_header::EXT_FLAG_M;

/// The class of a lent Push: [`push_stats_class`]'s rules, read off the record where it lies.
#[cfg(all(
    feature = "transport-stats",
    feature = "alloc",
    all(
        feature = "codec-frame",
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    ),
    all(
        feature = "codec-push",
        any(
            all(
                feature = "alloc",
                any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
            ),
            feature = "rx-push"
        )
    )
))]
fn lent_push_class<'f>(push: &wz_codecs::push::PushView<'f>) -> RecordClass<'f> {
    use crate::stats::{MessageLabel, StatMessage};
    use wz_codecs::push::PushViewVariant as V;
    let (id, suffix, _) = crate::wireexpr_resolve::id_suffix_and_space_viewed(&push.keyexpr.body);
    let space = stats_space_of_key(id, suffix, &|_id| None);
    let class = match &push.body {
        V::CodecZenohMsgPut(put) | V::Default { body: put, .. } => {
            put_view_class(MessageLabel::Put, StatMessage::Put, space, put)
        }
        V::CodecZenohMsgDel(del) => del_view_class(MessageLabel::Del, StatMessage::Del, space, del),
    };
    RecordClass {
        class,
        priority: crate::declare_ext_qos::read_qos_of(crate::ext_view::walked(
            push.extensions.as_ref(),
        ))
        .priority(),
        key: Some((id, suffix)),
    }
}

/// The class of a Put read as its view: [`put_stats_class`]'s rules, the payload inline or as its
/// slices, and the attachment beside it.
#[cfg(any(
    all(
        feature = "transport-stats",
        feature = "alloc",
        all(
            feature = "codec-frame",
            any(
                test,
                feature = "session-unicast",
                all(feature = "session-multicast", not(feature = "alloc"))
            )
        ),
        all(
            feature = "codec-response",
            any(
                all(
                    feature = "alloc",
                    any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
                ),
                feature = "rx-response"
            )
        )
    ),
    all(
        all(
            feature = "transport-stats",
            feature = "alloc",
            all(
                feature = "codec-frame",
                any(
                    test,
                    feature = "session-unicast",
                    all(feature = "session-multicast", not(feature = "alloc"))
                )
            ),
            feature = "codec-request"
        ),
        feature = "request-put-del"
    ),
    all(
        feature = "transport-stats",
        feature = "alloc",
        all(
            feature = "codec-frame",
            any(
                test,
                feature = "session-unicast",
                all(feature = "session-multicast", not(feature = "alloc"))
            )
        ),
        all(
            feature = "codec-push",
            any(
                all(
                    feature = "alloc",
                    any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
                ),
                feature = "rx-push"
            )
        )
    ),
))]
fn put_view_class(
    kind: crate::stats::MessageLabel,
    message: crate::stats::StatMessage,
    space: crate::stats::StatSpace,
    put: &wz_codecs::msg_put::MsgPutView<'_>,
) -> crate::stats::NetworkStatsClass {
    use wz_codecs::msg_put::MsgPutExtensionsHas0x12 as Layout;
    let (payload, sliced) = match &put.extensions_has_0x12 {
        Layout::NotHas0x12 { payload, .. } => (payload.into_inner().len(), false),
        Layout::Has0x12 { slices, .. } => (
            slices
                .inner()
                .iter()
                .map(|slice| crate::put_payload::slice_len(&slice))
                .sum(),
            true,
        ),
    };
    let entries = || {
        crate::put_payload::view_chain(put)
            .map(|(rest, _)| sce_forge_runtime::codec::Entries::entries(rest))
            .into_iter()
            .flatten()
    };
    let class = stats_class_marked_in(
        kind,
        message,
        space,
        payload.saturating_add(zbuf_ext_len_in(
            entries(),
            crate::ext_header::body_eid::PUT_ATTACHMENT,
        )),
        entries(),
        DATA_SHM_MARKER,
    );
    #[cfg(feature = "transport-shm")]
    if sliced {
        return class.on_shm();
    }
    let _ = sliced;
    class
}

/// The class of a Del read as its view: its attachment is its size.
#[cfg(any(
    all(
        feature = "transport-stats",
        feature = "alloc",
        all(
            feature = "codec-frame",
            any(
                test,
                feature = "session-unicast",
                all(feature = "session-multicast", not(feature = "alloc"))
            )
        ),
        all(
            feature = "codec-response",
            any(
                all(
                    feature = "alloc",
                    any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
                ),
                feature = "rx-response"
            )
        )
    ),
    all(
        all(
            feature = "transport-stats",
            feature = "alloc",
            all(
                feature = "codec-frame",
                any(
                    test,
                    feature = "session-unicast",
                    all(feature = "session-multicast", not(feature = "alloc"))
                )
            ),
            feature = "codec-request"
        ),
        feature = "request-put-del"
    ),
    all(
        feature = "transport-stats",
        feature = "alloc",
        all(
            feature = "codec-frame",
            any(
                test,
                feature = "session-unicast",
                all(feature = "session-multicast", not(feature = "alloc"))
            )
        ),
        all(
            feature = "codec-push",
            any(
                all(
                    feature = "alloc",
                    any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
                ),
                feature = "rx-push"
            )
        )
    ),
))]
fn del_view_class(
    kind: crate::stats::MessageLabel,
    message: crate::stats::StatMessage,
    space: crate::stats::StatSpace,
    del: &wz_codecs::msg_del::MsgDelView<'_>,
) -> crate::stats::NetworkStatsClass {
    let entries = || crate::ext_view::walked(del.extensions.as_ref());
    stats_class_marked_in(
        kind,
        message,
        space,
        zbuf_ext_len_in(entries(), crate::ext_header::body_eid::DEL_ATTACHMENT),
        entries(),
        DATA_SHM_MARKER,
    )
}

/// The class of a lent Request: [`request_stats_class`]'s rules, read off its view.
#[cfg(all(
    feature = "transport-stats",
    feature = "alloc",
    all(
        feature = "codec-frame",
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    ),
    feature = "codec-request"
))]
fn lent_request_class<'f>(request: &wz_codecs::request::RequestView<'f>) -> RecordClass<'f> {
    let (id, suffix, _) =
        crate::wireexpr_resolve::id_suffix_and_space_viewed(&request.keyexpr.body);
    let space = stats_space_of_key(id, suffix, &|_id| None);
    RecordClass {
        class: request_body_class(&request.body, space),
        priority: crate::declare_ext_qos::read_qos_of(crate::ext_view::walked(
            request.extensions.as_ref(),
        ))
        .priority(),
        key: Some((id, suffix)),
    }
}

/// The class of a Request's body read as its view. Every Request is a `query` to the registry,
/// whatever its body, as [`request_stats_class`] files it.
#[cfg(all(
    feature = "transport-stats",
    feature = "alloc",
    all(
        feature = "codec-frame",
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    ),
    feature = "codec-request"
))]
fn request_body_class(
    body: &wz_codecs::request::RequestViewVariant<'_>,
    space: crate::stats::StatSpace,
) -> crate::stats::NetworkStatsClass {
    #[cfg(feature = "request-put-del")]
    use crate::stats::{MessageLabel, StatMessage};
    use wz_codecs::request::RequestViewVariant as V;
    let query = match body {
        #[cfg(feature = "request-put-del")]
        V::CodecZenohMsgPut(put) => {
            return put_view_class(MessageLabel::Query, StatMessage::Put, space, put);
        }
        #[cfg(feature = "request-put-del")]
        V::CodecZenohMsgDel(del) => {
            return del_view_class(MessageLabel::Query, StatMessage::Del, space, del);
        }
        V::CodecZenohQuery(query) => query,
        // As in `request_stats_class`: an unknown tag carries a Query's body, and a Put or a Del
        // arm this build does not name has no class.
        other => {
            let V::Default { body: query, .. } = other else {
                return crate::stats::NetworkStatsClass::undecoded();
            };
            query
        }
    };
    query_view_class(space, query)
}

/// The class of a Query read as its view: its value without the encoding in front of it, inline
/// or as its slices, and its attachment, as [`query_payload_size`] sizes the owned one.
#[cfg(all(
    feature = "transport-stats",
    feature = "alloc",
    all(
        feature = "codec-frame",
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    ),
    feature = "codec-request"
))]
fn query_view_class(
    space: crate::stats::StatSpace,
    query: &wz_codecs::query::QueryView<'_>,
) -> crate::stats::NetworkStatsClass {
    use crate::stats::{MessageLabel, StatMessage};
    use wz_codecs::query_ext_entry::QueryExtEntryViewVariant;
    use wz_codecs::query_value_zbuf::QueryValueZbufAfterShm;
    let entries = || crate::ext_view::walked(query.extensions.as_deref());
    let value =
        crate::ext_view::last_by_eid_in(entries(), crate::ext_header::body_eid::QUERY_VALUE)
            .map_or(0, |ext| match &ext.body {
                QueryExtEntryViewVariant::CodecZenohQueryValueZbuf(zbuf) => match &zbuf.after_shm {
                    QueryValueZbufAfterShm::NotAfterShm { value } => {
                        crate::encoding::split_value_body(value.into_inner())
                            .map_or(0, |(_, payload)| payload.len())
                    }
                    QueryValueZbufAfterShm::AfterShm { slices, .. } => slices
                        .inner()
                        .iter()
                        .map(|slice| crate::put_payload::slice_len(&slice))
                        .sum(),
                },
                _ => 0,
            });
    stats_class_marked_in(
        MessageLabel::Query,
        StatMessage::Query,
        space,
        value.saturating_add(zbuf_ext_len_in(
            entries(),
            crate::ext_header::body_eid::QUERY_ATTACHMENT,
        )),
        entries(),
        crate::ext_header::body_ext_id::QUERY_SHM,
    )
}

/// The class of a lent Response: [`response_stats_class`]'s rules, read off its view.
#[cfg(all(
    feature = "transport-stats",
    feature = "alloc",
    all(
        feature = "codec-frame",
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    ),
    all(
        feature = "codec-response",
        any(
            all(
                feature = "alloc",
                any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
            ),
            feature = "rx-response"
        )
    )
))]
fn lent_response_class<'f>(response: &wz_codecs::response::ResponseView<'f>) -> RecordClass<'f> {
    use crate::stats::{MessageLabel, StatMessage};
    use wz_codecs::reply::ReplyViewVariant as RV;
    use wz_codecs::response::ResponseViewVariant as V;
    let (id, suffix, _) =
        crate::wireexpr_resolve::id_suffix_and_space_viewed(&response.keyexpr.body);
    let space = stats_space_of_key(id, suffix, &|_id| None);
    let class = match &response.body {
        V::CodecZenohReply(reply) | V::Default { body: reply, .. } => match &reply.body {
            RV::CodecZenohMsgPut(put) | RV::Default { body: put, .. } => {
                put_view_class(MessageLabel::Reply, StatMessage::Reply, space, put)
            }
            RV::CodecZenohMsgDel(del) => {
                del_view_class(MessageLabel::Reply, StatMessage::Reply, space, del)
            }
        },
        V::CodecZenohErr(err) => stats_class_marked_in(
            MessageLabel::ReplyErr,
            StatMessage::Reply,
            space,
            err.payload_len as usize,
            crate::ext_view::walked(err.extensions.as_ref()),
            DATA_SHM_MARKER,
        ),
    };
    RecordClass {
        class,
        priority: crate::declare_ext_qos::read_qos_of(crate::ext_view::walked(
            response.extensions.as_ref(),
        ))
        .priority(),
        key: Some((id, suffix)),
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
#[cfg(all(test, feature = "alloc", feature = "codec-frame"))]
mod record_walk_tests {
    use super::*;
    use alloc::vec;

    fn oam_record(id: u64) -> Vec<u8> {
        wz_codecs::lent::Oam {
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
        let (seen, result) = walk_read(payload);
        (seen, result.map(|_| ()))
    }

    /// [`walk`], with how much of the payload the walk read.
    fn walk_read(
        payload: &[u8],
    ) -> (
        Vec<(char, u64)>,
        Result<usize, crate::parse_error::InboundParseError>,
    ) {
        let mut record = new_record_buf();
        let mut seen = Vec::new();
        let result = try_for_each_record(payload, &mut record, RecordForm::Owned, |one| {
            // Without a lendable codec the owned form is the only one there is.
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-request",
                feature = "codec-response",
                feature = "rx-lent-control"
            ))]
            let WalkedRecord::Owned(one) = one
            else {
                panic!("an owned walk lends nothing");
            };
            #[cfg(not(any(
                feature = "codec-push",
                feature = "codec-request",
                feature = "codec-response",
                feature = "rx-lent-control"
            )))]
            let WalkedRecord::Owned(one) = one;
            assert_eq!(one.len(), 1, "one record per call");
            seen.push(match &one[0] {
                NetworkMessage::Oam(o) => ('o', o.id),
                NetworkMessage::Unknown { mid, .. } => ('u', u64::from(*mid)),
                other => panic!("unexpected record {other:?}"),
            });
            Ok(())
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
            Ok(Decoded::Unjudged)
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

    /// A consumer that takes no more ends the walk before the next record: the walk says it
    /// stopped with records unread and how far it read, on the owned form and the lent one. The
    /// control takes another each time and reads the payload whole. Turned red by a walk that
    /// reads on past the record its consumer took no more after.
    #[cfg(feature = "codec-push")]
    #[test]
    fn the_walk_ends_after_the_record_its_consumer_takes_no_more_after() {
        let first = push_record("a/1");
        let payload = [first.clone(), push_record("a/2")].concat();
        for form in [RecordForm::Owned, RecordForm::Lent] {
            let mut record = new_record_buf();
            let mut taken = 0usize;
            let result = try_for_each_record_while(
                &payload,
                &mut record,
                form,
                |_| {
                    taken += 1;
                    Ok(false)
                },
                #[cfg(all(feature = "transport-stats", feature = "alloc"))]
                &mut |_: &RecordClass<'_>| {},
            );
            assert_eq!(result.ok(), Some((first.len(), true)), "{form:?}");
            assert_eq!(taken, 1, "{form:?}");
        }
        let mut record = new_record_buf();
        let result = try_for_each_record_while(
            &payload,
            &mut record,
            RecordForm::Lent,
            |_| Ok(true),
            #[cfg(all(feature = "transport-stats", feature = "alloc"))]
            &mut |_: &RecordClass<'_>| {},
        );
        assert_eq!(result.ok(), Some((payload.len(), false)));
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
                let (_, suffix, _) =
                    crate::wireexpr_resolve::id_suffix_and_space_viewed(&push.view.keyexpr.body);
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

    /// A build with the transport counters counts each record the walk lends by its class, read off
    /// the record as the walk decoded it, and the class is the one the owned message of the same
    /// bytes is counted by: the class, the band and the key read the same for one batch walked lent
    /// and walked owned, so the counters do not depend on the form the build receives in. The
    /// batch holds two Pushes and an Oam, and with their codecs a Query on a band of its own, a
    /// Reply with an attachment and an Err.
    #[cfg(all(feature = "transport-stats", feature = "codec-push"))]
    #[test]
    fn a_lent_record_is_counted_as_the_same_record_walked_owned() {
        type Counted = (
            crate::stats::NetworkStatsClass,
            crate::qos::Priority,
            Option<alloc::string::String>,
        );
        let mut records = vec![push_record("a/1"), oam_record(2), push_record("a/3")];
        #[cfg(feature = "codec-request")]
        records.push(
            crate::request_build::RequestQueryBuilder::new(
                12,
                crate::wire_key::WireKey::literal("q/1").expect("a literal key"),
            )
            .request_qos(0x0D)
            .build()
            .expect("build")
            .try_as_borrowed()
            .expect("a view")
            .encode_to_vec(),
        );
        #[cfg(feature = "codec-response")]
        {
            records.push(
                crate::response_build::ResponseReplyBuilder::new(
                    9,
                    crate::wire_key::WireKey::literal("r/1").expect("a literal key"),
                    b"reply",
                )
                .attachment(b"att")
                .build()
                .expect("build")
                .try_as_borrowed()
                .expect("a view")
                .encode_to_vec(),
            );
            records.push(
                crate::response_build::ResponseErrBuilder::new(
                    9,
                    crate::wire_key::WireKey::literal("r/2").expect("a literal key"),
                    b"oops",
                )
                .build()
                .expect("build")
                .try_as_borrowed()
                .expect("a view")
                .encode_to_vec(),
            );
        }
        let payload = records.concat();
        let counted = |form: RecordForm| -> (Vec<Counted>, usize) {
            let seen = core::cell::RefCell::new(Vec::new());
            let lent = core::cell::Cell::new(0);
            let mut record = new_record_buf();
            let result = try_for_each_record_while(
                &payload,
                &mut record,
                form,
                |one| {
                    if let WalkedRecord::Owned(owned) = one {
                        for message in owned.iter() {
                            seen.borrow_mut().push((
                                stats_class(message, |_id| None),
                                network_message_priority(message),
                                stats_keyexpr(message, |_id| None),
                            ));
                        }
                    }
                    Ok(true)
                },
                &mut |class: &RecordClass<'_>| {
                    lent.set(lent.get() + 1);
                    seen.borrow_mut()
                        .push((class.class, class.priority, class.keyexpr()));
                },
            );
            assert!(result.is_ok());
            (seen.into_inner(), lent.get())
        };
        let (owned, none_lent) = counted(RecordForm::Owned);
        assert_eq!(
            owned.len(),
            records.len(),
            "the owned walk counts every record it owns"
        );
        assert_eq!(none_lent, 0, "an owned walk lends nothing to count");
        let (lent, lent_count) = counted(RecordForm::Lent);
        assert_eq!(
            lent_count,
            records.len() - 1,
            "every record but the Oam was lent and counted by its class"
        );
        assert_eq!(
            lent, owned,
            "a lent batch counts as the same batch walked owned"
        );
        // The form that lends every kind lends the Oam too, and counts its band as the owned walk.
        #[cfg(all(
            feature = "rx-lent-control",
            feature = "rx-control",
            feature = "rx-push",
            feature = "rx-response"
        ))]
        {
            let (all_lent, every) = counted(RecordForm::LentControl);
            assert_eq!(every, records.len(), "every record was lent");
            assert_eq!(all_lent, owned, "and counts as the batch walked owned");
        }
    }

    /// The slot profile's walk ([`RecordForm::LentControl`]): every kind this
    /// build decodes is lent where the payload lies, and what no consumer reads is
    /// skipped, so the walk builds no owned message at all.
    // The walk lends a Declare and an Interest only with `rx-control` and a ResponseFinal only with
    // `rx-response`; without them it skips the kind, and the walk this compares has nothing to lend.
    #[cfg(all(
        feature = "rx-lent-control",
        feature = "rx-control",
        feature = "rx-response",
        feature = "codec-declare",
        feature = "declare-final",
        feature = "codec-response-final"
    ))]
    mod control {
        use super::*;
        use crate::declare_build::{build_declare_final, build_declare_subscriber};
        use crate::interest_build::build_interest_subscribers;
        use crate::parse_error::InboundParseError;
        use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
        use wz_codecs::ext_unit::ExtUnit;
        use wz_codecs::lent::DeclareVariant;

        fn declare_bytes(declare: &crate::transport_profile::owned::DeclareOwned) -> Vec<u8> {
            declare.try_as_borrowed().expect("a view").encode_to_vec()
        }

        fn interest_bytes(interest: &crate::transport_profile::owned::InterestOwned) -> Vec<u8> {
            interest.try_as_borrowed().expect("a view").encode_to_vec()
        }

        fn response_final_bytes(
            done: &crate::transport_profile::owned::ResponseFinalOwned,
        ) -> Vec<u8> {
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
        fn tag(one: WalkedRecord<'_, '_>) -> (char, u64) {
            match one {
                WalkedRecord::Declare(d) => match &d.body {
                    DeclareVariant::CodecZenohDeclSubscriber(s) => ('s', s.id),
                    DeclareVariant::CodecZenohDeclFinal(_) => ('f', 0),
                    other => panic!("an unexpected declaration {other:?}"),
                },
                WalkedRecord::Interest(i) => ('i', i.interest_id),
                WalkedRecord::ResponseFinal(r) => ('r', u64::from(r.request_id)),
                WalkedRecord::Skipped => ('-', 0),
                #[cfg(all(feature = "rx-control", feature = "transport-stats", feature = "alloc"))]
                WalkedRecord::Oam(_) => ('-', 0),
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
                        NetworkMessage::ResponseFinal(r) => ('r', u64::from(r.request_id)),
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

        /// The pull reads each record where it lies as it reads its kind, and hands over what the
        /// control walk hands over, in the same order; it stops before a transport message, having
        /// read the bytes up to it, and says no record is left. Turned red by a pull that reads into
        /// the transport message, or one that says a record is left where a transport message is.
        #[test]
        fn the_pull_hands_over_what_the_control_walk_does_and_stops_before_a_transport_message() {
            let records = every_kind();
            // A KeepAlive behind the records: a transport message, the batch's to read.
            let payload = [records.clone(), alloc::vec![wire_const::T_MID_KEEP_ALIVE]].concat();
            let mut seen = Vec::new();
            let mut each = |walked: WalkedRecord<'_, '_>| -> Result<bool, InboundParseError> {
                seen.push(tag(walked));
                Ok(true)
            };
            let read = pull::hand_records(&payload, &mut each);
            assert_eq!(
                read.ok(),
                Some((records.len(), false)),
                "up to the KeepAlive"
            );
            let (walked, result) = walk(&payload, RecordForm::LentControl);
            assert!(result.is_ok());
            assert_eq!(seen, walked, "the walk hands over what the pull reads");
        }

        /// A consumer that takes no more ends the pull after the record it took: the pull says how
        /// far it read, and that a record is left when one is, and not when a transport message
        /// follows. Turned red by a pull that reads the next record before it asks the consumer, or
        /// says a record is left where none is.
        #[test]
        fn a_consumer_that_takes_no_more_ends_the_pull_after_its_record() {
            let first = subscriber(7);
            let mut taken = Vec::new();
            let mut once = |walked: WalkedRecord<'_, '_>| -> Result<bool, InboundParseError> {
                taken.push(tag(walked));
                Ok(false)
            };
            let two = [first.clone(), subscriber(8)].concat();
            assert_eq!(
                pull::hand_records(&two, &mut once).ok(),
                Some((first.len(), true)),
                "the second record is left"
            );
            let behind = [first.clone(), alloc::vec![wire_const::T_MID_KEEP_ALIVE]].concat();
            assert_eq!(
                pull::hand_records(&behind, &mut once).ok(),
                Some((first.len(), false)),
                "a transport message is no record"
            );
            assert_eq!(taken, vec![('s', 7), ('s', 7)], "one record each time");
        }

        /// A record that does not decode ends the pull with its error, after the records before it
        /// were handed over. Turned red by a pull that reads on after it.
        #[test]
        fn a_record_that_does_not_decode_ends_the_pull_with_its_error() {
            let mut broken = subscriber(7);
            broken.push(wire_const::N_MID_DECLARE);
            let mut seen = Vec::new();
            let mut each = |walked: WalkedRecord<'_, '_>| -> Result<bool, InboundParseError> {
                seen.push(tag(walked));
                Ok(true)
            };
            let read = pull::hand_records(&broken, &mut each);
            assert!(
                matches!(read, Err(InboundParseError::Codec(_))),
                "the decode error: {read:?}"
            );
            assert_eq!(seen, vec![('s', 7)], "the record before it was handed over");
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
                d.extensions = Some(crate::held_list::one_entry(mandatory_unknown()));
                declare_bytes(&d)
            };
            let interest = {
                let mut i = build_interest_subscribers(3, true, true, 0, Some("k")).expect("build");
                i.extensions = Some(crate::held_list::one_entry(mandatory_unknown()));
                i.header |= wire_const::FLAG_N_Z;
                interest_bytes(&i)
            };
            let response_final = {
                let mut done = crate::response_final_build::build_response_final(
                    4,
                    crate::sample::QosLevel::default(),
                );
                done.extensions = Some(crate::held_list::one_entry(mandatory_unknown()));
                done.header |= wire_const::FLAG_N_Z;
                response_final_bytes(&done)
            };
            let oam = {
                use wz_codecs::lent::{ExtEntry, ExtEntryVariant};
                let mut chain = sce_forge_runtime::heapless::Vec::new();
                let _ = chain.push(ExtEntry {
                    header: 0x1e,
                    body: ExtEntryVariant::CodecZenohExtUnit(ExtUnit::default()),
                });
                wz_codecs::lent::Oam {
                    header: wire_const::N_MID_OAM | wire_const::FLAG_N_Z,
                    id: 6,
                    extensions: Some(wz_codecs::Bounded::new(chain).expect("one entry of eight")),
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
        // The entry takes the profile of the borrowed Push it goes into.
        refused.extensions = Some(crate::held_list::one_entry(
            wz_codecs::ext_entry::ExtEntryIn {
                header: 0x10 | 0x0F,
                body: wz_codecs::ext_entry::ExtEntryVariantIn::CodecZenohExtUnit(Default::default()),
            },
        ));
        refused.header |= 0x80;
        let refused = refused.encode_to_vec();
        let payload = [plain, refused, push_record("a/3")].concat();
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
        let request = crate::request_build::RequestQueryBuilder::new(
            3,
            crate::wire_key::WireKey::literal("q/1").expect("a literal key"),
        )
        .build()
        .expect("build");
        let response = crate::response_build::ResponseReplyBuilder::new(
            3,
            crate::wire_key::WireKey::literal("q/1").expect("a literal key"),
            b"v",
        )
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
        // The entry takes the profile of the borrowed message it goes into.
        let unknown = || wz_codecs::ext_entry::ExtEntryIn {
            header: 0x10 | 0x0F,
            body: wz_codecs::ext_entry::ExtEntryVariantIn::CodecZenohExtUnit(Default::default()),
        };
        let mut bad_request = request.try_as_borrowed().expect("a view");
        bad_request.extensions = Some(crate::held_list::one_entry(unknown()));
        bad_request.header |= 0x80;
        let mut bad_response = response.try_as_borrowed().expect("a view");
        bad_response.extensions = Some(crate::held_list::one_entry(unknown()));
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
        // MID 0x18 is neither a network MID nor a transport one and has no envelope decoder: its
        // length is unknowable, so it and the OAM after it are one absorbed record, as in the
        // batch decode.
        let payload = [oam_record(4), vec![0x18, 0xAB], oam_record(5)].concat();
        let (seen, result) = walk(&payload);
        assert!(result.is_ok());
        assert_eq!(seen, vec![('o', 4), ('u', 0x18)]);
        let batch = parse_frame_payload(&payload).expect("the batch decodes");
        assert!(
            matches!(&batch[1], NetworkMessage::Unknown { mid: 0x18, body } if body.len() == payload.len() - oam_record(4).len()),
            "the batch decode absorbs the same tail: {batch:?}"
        );
    }

    /// A transport message is not a record of the frame: the walk ends before it, hands over
    /// nothing for it, and says how far it read, so the caller goes on from there. This is the
    /// batch of a sender that puts a message of the other reliability behind a second Frame
    /// header.
    #[test]
    fn a_transport_mid_ends_the_walk_before_it_and_the_walk_says_where() {
        let first = oam_record(4);
        for transport in [0x00_u8, 0x01, 0x04, 0x05, 0x06, 0x07] {
            let payload = [first.clone(), vec![transport, 0x00], oam_record(5)].concat();
            let (seen, read) = walk_read(&payload);
            assert_eq!(seen, vec![('o', 4)], "transport id {transport}");
            assert_eq!(read, Ok(first.len()), "up to the header and no further");
        }
        // A payload that opens with one has no record of its own.
        let (seen, read) = walk_read(&[0x05, 0x00]);
        assert_eq!(seen, vec![]);
        assert_eq!(read, Ok(0));
        // Without one, the walk reads to the end.
        let payload = [first.clone(), oam_record(5)].concat();
        let (seen, read) = walk_read(&payload);
        assert_eq!(seen, vec![('o', 4), ('o', 5)]);
        assert_eq!(read, Ok(payload.len()));
    }
}

#[cfg(all(test, feature = "alloc", feature = "codec-frame"))]
mod best_effort_batch_tests {
    use super::*;
    use alloc::vec;

    /// One encoded OAM record. `Oam::default()`'s header carries its own
    /// wire MID (`0x1F`), so the fixture is a real record through the real
    /// encoder rather than a hand-typed byte string.
    fn oam_record(id: u64) -> Vec<u8> {
        wz_codecs::lent::Oam {
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
    /// `0x18` is outside the seven-wide network MID set on purpose — the
    /// authored catalog covers all seven, so a meaningful Unknown fixture
    /// has to be synthetic. It is outside the transport MIDs (`0x00..=0x07`)
    /// too: one of those ends a `Frame`'s records instead.
    #[test]
    fn an_unknown_mid_halts_with_its_offset_under_both_contracts() {
        let first = oam_record(7);
        let mut wire = first.clone();
        wire.extend_from_slice(&[0x18, 0xAB, 0xCD]);

        let strict = parse_frame_payload(&wire).expect("unknown MID absorbs, not errors");
        assert_eq!(oam_ids(&strict), vec![7]);
        assert!(matches!(
            strict.last(),
            Some(NetworkMessage::Unknown { mid: 0x18, .. })
        ));

        let best = parse_frame_payload_best_effort(&wire);
        assert_eq!(oam_ids(&best.messages), vec![7]);
        match best.messages.last() {
            Some(NetworkMessage::Unknown { mid, body }) => {
                assert_eq!(*mid, 0x18);
                assert_eq!(
                    body.as_slice(),
                    &[0x18, 0xAB, 0xCD],
                    "the absorbed body starts AT the unknown header, not after it"
                );
            }
            other => panic!("expected a trailing Unknown, got {other:?}"),
        }
        assert_eq!(
            best.halt,
            Some(BatchHalt::UnknownMid {
                mid: 0x18,
                offset: first.len()
            })
        );
        assert_eq!(best.unparsed_bytes, 3);
        assert_eq!(best.next_message_at, None);
    }

    /// A batch whose sender put a message of the other reliability behind a
    /// second `Frame` header: the first `Frame`'s payload, read as the tail of
    /// the unit, holds its own records and then that header. The best-effort
    /// walk ends the records before it and says where it begins; nothing is
    /// absorbed, nothing is unparsed, and the batch is complete.
    #[test]
    fn a_second_frame_header_ends_the_records_of_the_first() {
        let first = [oam_record(7), oam_record(8)].concat();
        // A best-effort `Frame` header (`R` clear, no extensions) with sn 3, and one record.
        let second = [
            vec![wz_codecs::wire_const::T_MID_FRAME, 0x03],
            oam_record(9),
        ]
        .concat();
        let wire = [first.clone(), second].concat();

        let best = parse_frame_payload_best_effort(&wire);
        assert_eq!(oam_ids(&best.messages), vec![7, 8]);
        assert_eq!(best.next_message_at, Some(first.len()));
        assert!(best.is_complete(), "a transport message is no halt");
        assert_eq!(best.unparsed_bytes, 0);
        assert!(
            !best
                .messages
                .iter()
                .any(|m| matches!(m, NetworkMessage::Unknown { .. })),
            "the next transport message is not absorbed as an unknown record"
        );
        let (seven, eight) = (oam_record(7).len(), oam_record(8).len());
        assert_eq!(best.spans, vec![(0, seven), (seven, eight)]);
    }

    /// WHAT FAILS A FRAME'S BATCH, as upstream's batch reader reads it: a
    /// record that does not decode, and an id of neither space. A network id
    /// this build has no decoder for does not (upstream decodes it), nor does
    /// a second `Frame` header, which ends the records and is read as the next
    /// message.
    #[test]
    fn only_a_failed_record_or_an_id_of_neither_space_fails_a_frames_batch() {
        for mid in 0u8..32 {
            let absorbed = BatchParse {
                messages: vec![],
                spans: vec![],
                halt: Some(BatchHalt::UnknownMid { mid, offset: 0 }),
                unparsed_bytes: 1,
                next_message_at: None,
            };
            let of_neither_space = (0x08..=0x18).contains(&mid);
            assert_eq!(
                absorbed.fails_the_frames_batch(),
                of_neither_space,
                "mid {mid:#04x}"
            );
        }
        let first = oam_record(7);
        assert!(!parse_frame_payload_best_effort(&first).fails_the_frames_batch());
        let truncated = [first.clone(), vec![oam_record(8)[0]]].concat();
        assert!(parse_frame_payload_best_effort(&truncated).fails_the_frames_batch());
        let unknown = [first.clone(), vec![0x18, 0xAB]].concat();
        assert!(parse_frame_payload_best_effort(&unknown).fails_the_frames_batch());
        let second_frame = [
            first,
            vec![wz_codecs::wire_const::T_MID_FRAME, 0x03],
            oam_record(9),
        ]
        .concat();
        assert!(!parse_frame_payload_best_effort(&second_frame).fails_the_frames_batch());
    }

    /// Every transport MID ends a `Frame`'s records, the first byte of a
    /// payload included, and no network MID does.
    #[test]
    fn every_transport_mid_and_no_network_mid_ends_a_frames_records() {
        for mid in 0u8..32 {
            let best = parse_frame_payload_best_effort(&[mid]);
            if mid <= wz_codecs::wire_const::T_MID_JOIN {
                assert_eq!(best.next_message_at, Some(0), "mid {mid:#04x}");
                assert!(best.messages.is_empty(), "mid {mid:#04x}");
            } else {
                assert_eq!(best.next_message_at, None, "mid {mid:#04x}");
            }
        }
    }

    /// The bytes of a joined fragment chain are network messages only, as
    /// upstream decodes them: a transport MID there is an unknown record that
    /// halts the walk, and not the end of a `Frame`.
    #[test]
    fn a_transport_mid_in_a_reassembled_payload_halts_as_an_unknown_record() {
        let first = oam_record(7);
        let wire = [
            first.clone(),
            vec![wz_codecs::wire_const::T_MID_FRAME, 0x03],
            oam_record(9),
        ]
        .concat();
        let joined = parse_reassembled_payload_best_effort(&wire);
        assert_eq!(oam_ids(&joined.messages), vec![7]);
        assert_eq!(joined.next_message_at, None);
        assert_eq!(
            joined.halt,
            Some(BatchHalt::UnknownMid {
                mid: wz_codecs::wire_const::T_MID_FRAME,
                offset: first.len()
            })
        );
        assert_eq!(joined.unparsed_bytes, wire.len() - first.len());
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
#[cfg(all(
    test,
    feature = "alloc",
    feature = "codec-frame",
    feature = "codec-declare"
))]
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
        let decoded = wz_codecs::lent::Declare::decode(&mut cursor).expect("decode");
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
        crate::put_payload::set_chain(&mut put, exts).expect("within the bound");
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
        let mut value = encoding
            .to_codec()
            .expect("a MIME encoding's schema is within its bound")
            .encode_to_vec();
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
                let mut entries = crate::put_payload::chain(b).to_vec();
                entries.push(zbuf_ext(body_ext_id::PUT_ATTACHMENT, b"attached"));
                crate::put_payload::set_chain(b, entries).expect("within the bound");
            }
            V::CodecZenohMsgDel(_) => unreachable!("a literal put"),
        }
        let class = push_stats_class(&push, |_| None);
        assert_eq!(class.kind, Some(crate::stats::MessageLabel::Put));
        assert_eq!(class.payload.map(|p| p.pl_bytes), Some(12 + 8));
    }

    /// A Put whose sender holds the key's whole text classifies as the literal Put of that key,
    /// in the user space and the admin space, whatever declaration names the key on the wire.
    #[test]
    fn a_named_put_classifies_as_the_literal_put_of_its_key() {
        for key in ["demo/plain", "@/admin/key", "@/router/abc/tail"] {
            assert_eq!(
                named_put_stats_class(key, 13),
                plain_put_stats_class(0, Some(key), 13, |_| None),
                "{key}"
            );
        }
        assert_ne!(
            named_put_stats_class("@/router/abc", 13),
            named_put_stats_class("demo/declared", 13),
            "the admin space is told from the user space by the text"
        );
    }

    /// A plain Put a sender holds as borrowed parts classifies as the owned message of the same
    /// parts does: literal and aliased, user and admin space, an alias resolved or not.
    #[test]
    fn a_plain_put_classifies_as_its_owned_message_does() {
        let resolve = |id: crate::wire_id::ExprId| match id {
            7 => Some(alloc::string::String::from("@/router/abc")),
            8 => Some(alloc::string::String::from("demo/declared")),
            _ => None,
        };
        let cases: [(crate::wire_id::ExprId, Option<&str>); 6] = [
            (0, Some("demo/plain")),
            (0, Some("@/admin/key")),
            (7, None),
            (8, Some("/tail")),
            (9, None),
            (8, None),
        ];
        for (id, suffix) in cases {
            let value = b"payload bytes";
            let owned = if id == 0 {
                crate::push_build::build_push_literal(suffix.unwrap_or_default(), value)
            } else {
                crate::push_build::build_push_aliased(id, suffix, value)
            }
            .expect("build a put");
            assert_eq!(
                plain_put_stats_class(id, suffix, value.len(), resolve),
                push_stats_class(&owned, resolve),
                "the key ({id}, {suffix:?})"
            );
        }
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
        let wz_codecs::msg_put::MsgPutExtensionsHas0x12::NotHas0x12 { payload, .. } =
            &put.extensions_has_0x12
        else {
            panic!("an inline Put");
        };
        payload.is_shared()
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
        let bytes = crate::response_build::build_response_reply(
            7,
            crate::wire_key::WireKey::literal("demo/q").expect("a literal key"),
            PAYLOAD,
        )
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

    /// A Query that carries its attachment twice is sized by the last, the one upstream's decoder
    /// keeps (`commons/zenoh-codec/src/zenoh/query.rs` @ `ext_attachment = Some(a);`) and whose
    /// length its statistics count, held and walked alike.
    #[test]
    fn a_repeated_attachment_is_sized_by_its_last_entry() {
        let entry = |bytes: &[u8]| {
            crate::attachment::encode_attachment_ext::<crate::wire::WireStorage>(
                crate::attachment::ATTACHMENT_EXT_ID_QUERY,
                bytes,
            )
            .unwrap()
        };
        let chain = [entry(&[0xAB; 3]), entry(&[0xCD; 5])];
        assert_eq!(
            zbuf_ext_len(Some(&chain[..]), body_eid::QUERY_ATTACHMENT),
            5
        );
        assert_eq!(zbuf_ext_len_in(chain.iter(), body_eid::QUERY_ATTACHMENT), 5);
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
    use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant, ExtEntryStorage};
    use wz_codecs::ext_unit::ExtUnit;
    use wz_codecs::ext_zbuf::ExtZbufOwned;
    use wz_codecs::ext_zint::ExtZint;

    /// Every header a chain entry can have without the chain flag, with the
    /// reserved encoding left out: it has no body shape to build.
    fn headers() -> impl Iterator<Item = u8> {
        (0u8..0x80).filter(|h| (h >> 5) & 3 != 3)
    }

    /// One generic entry with `header` and the body its encoding needs. These tests judge the
    /// mandatory-extension rule, so the body of an identity some message declares is one every
    /// reader of that identity reads (the readers' well-formed cases in `ext_admit`): the
    /// verdict then turns on the header alone. Every other identity carries the empty body.
    fn entry<S: ExtEntryStorage>(header: u8) -> ExtEntryOwned<S>
    where
        <S as sce_forge_runtime::codec::HoldsBytes<wz_codecs::ext_zbuf::ExtZbufValueField>>::Bytes:
            wz_codecs::SceByteBuf,
    {
        let zbuf: &[u8] = match header {
            // A timestamp: a time, an id length of 1, an id that is not zero.
            0x42 => &[0x05, 0x01, 0x01],
            // A responder (zid length, zid, entity id) and a Query's value (an encoding
            // with no schema, then the payload): these bytes are both.
            0x43 => &[0x00, 0x01, 0x07],
            // A source info: a zid, an entity id and a sequence number.
            0x41 => &[0x00, 0x01, 0x02, 0x03],
            // A timestamp stack: flags that are not zero, then one interception.
            0x47 => &[0x01, 0x01, 0x02, 0x01, 0xAA],
            // An undeclaration's key: a scope and a UTF-8 suffix.
            0x5F => &[0x01, 0x00, b'a'],
            _ => &[],
        };
        let body = match (header >> 5) & 3 {
            0 => ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
            1 => ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint { value: 0 }),
            _ => ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                value_len: zbuf.len() as u64,
                value: crate::codec_owned::owned_bytes(zbuf).expect("a short body fits"),
            }),
        };
        ExtEntryOwned { header, body }
    }

    /// One Query-chain entry: the generic one moved into the Query's own kind.
    fn query_entry(header: u8) -> crate::wire::parts::QueryExtEntryOwned {
        crate::ext_view::query_ext_from_generic(entry::<WireStorage>(header))
    }

    /// `put` with its chain the one entry `header`, in the layout that entry requires: a Put
    /// holds the shared-memory marker's identity only in the sliced layout, so the marker
    /// makes `put` a sliced Put and every other header leaves it inline.
    fn put_with_one_entry(put: &mut crate::wire::parts::MsgPutOwned, header: u8) {
        use crate::ext_header::ext_eid;
        if ext_eid(header) == ext_eid(crate::put_payload::marker_header()) {
            *put = crate::put_payload::shm(&[0x01]).expect("one slice fits");
        }
        crate::put_payload::set_chain(put, [entry(header)]).expect("one entry fits either layout");
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
            push(|p, h| p.extensions = Some(crate::held_list::one_entry(entry(h)))),
        );
        every_header(
            "push put body",
            SHM,
            push(|p, h| match &mut p.body {
                crate::wire::PushOwnedVariant::CodecZenohMsgPut(put) => put_with_one_entry(put, h),
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
                    del.extensions = Some(crate::held_list::one_entry(entry(header)));
                }
                other => panic!("a literal del carries a Del, got {other:?}"),
            }
            NetworkMessage::Push(Box::new(push))
        });
    }

    #[test]
    fn a_request_defines_the_node_id_and_the_target_and_its_query_nothing() {
        let request = || {
            crate::request_build::build_request_query(
                1,
                crate::wire_key::WireKey::literal("k").expect("a literal key"),
            )
            .unwrap()
        };
        every_header("request envelope", &[NODE_ID, TARGET], |header| {
            let mut request = request();
            request.extensions = Some(crate::held_list::one_entry(entry(header)));
            NetworkMessage::Request(Box::new(request))
        });
        every_header("request query body", &[], |header| {
            let mut request = request();
            match &mut request.body {
                crate::wire::RequestOwnedVariant::CodecZenohQuery(query) => {
                    query.extensions = Some(
                        crate::held_list::lawful(crate::held_list::one_entry(query_entry(header)))
                            .expect("a chain of one entry follows its law"),
                    );
                }
                other => panic!("a query request carries a Query, got {other:?}"),
            }
            NetworkMessage::Request(Box::new(request))
        });
    }

    #[test]
    fn a_response_defines_nothing_mandatory_and_its_reply_put_and_err_the_shm_marker() {
        let reply = || {
            crate::response_build::build_response_reply(
                1,
                crate::wire_key::WireKey::literal("k").expect("a literal key"),
                b"v",
            )
            .unwrap()
        };
        every_header("response envelope", &[], |header| {
            let mut response = reply();
            response.extensions = Some(crate::held_list::one_entry(entry(header)));
            NetworkMessage::Response(Box::new(response))
        });
        every_header("reply envelope", &[], |header| {
            let mut response = reply();
            match &mut response.body {
                crate::wire::ResponseOwnedVariant::CodecZenohReply(reply) => {
                    reply.extensions = Some(crate::held_list::one_entry(entry(header)));
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
                            put_with_one_entry(put, header);
                        }
                        other => panic!("a literal reply carries a Put, got {other:?}"),
                    }
                }
                other => panic!("a reply carries a Reply, got {other:?}"),
            }
            NetworkMessage::Response(Box::new(response))
        });
        every_header("err body", SHM, |header| {
            let mut response = crate::response_build::build_response_err(
                1,
                crate::wire_key::WireKey::literal("k").expect("a literal key"),
                b"e",
            )
            .unwrap();
            match &mut response.body {
                crate::wire::ResponseOwnedVariant::CodecZenohErr(err) => {
                    err.extensions = Some(crate::held_list::one_entry(entry(header)));
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
            done.extensions = Some(crate::held_list::one_entry(entry(header)));
            NetworkMessage::ResponseFinal(done)
        });
        every_header("oam", &[], |header| {
            let mut oam = wz_codecs::lent::Oam::default()
                .try_into_owned_in::<crate::transport_profile::TransportStorage>()
                .unwrap();
            oam.extensions = Some(crate::held_list::one_entry(entry(header)));
            NetworkMessage::Oam(oam)
        });
        every_header("interest", &[NODE_ID], |header| {
            let mut interest = crate::interest_build::build_interest_final(1);
            interest.extensions = Some(crate::held_list::one_entry(entry(header)));
            NetworkMessage::Interest(interest)
        });
    }

    #[test]
    fn a_declare_defines_the_node_id_and_only_an_undeclare_the_wire_expression() {
        every_header("declare envelope", &[NODE_ID], |header| {
            let mut declare = crate::declare_build::build_declare_final();
            declare.extensions = Some(crate::held_list::one_entry(entry(header)));
            NetworkMessage::Declare(Box::new(declare))
        });
        every_header("undeclare subscriber", &[WIRE_EXPR], |header| {
            let mut declare = crate::declare_build::build_undeclare_subscriber(1);
            match &mut declare.body {
                wz_codecs::declare::DeclareOwnedVariant::CodecZenohUndeclSubscriber(d) => {
                    d.extensions = Some(crate::held_list::one_entry(entry(header)));
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
                    d.extensions = Some(crate::held_list::one_entry(entry(header)));
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
                    // Neither header is the shared-memory marker, so the Put stays inline;
                    // the setter sets the body header's `Z` bit with the chain.
                    crate::put_payload::set_chain(put, [entry(header)]).expect("one entry fits");
                }
                _ => unreachable!(),
            }
            use wz_codecs_test_support::TestWire as _;
            push.wire()
        };
        let optional = wire_of(0x03);
        parse_frame_payload(&optional).expect("the optional one decodes");
        assert!(admit_frame_payload_lending(&optional).is_ok());
        let mandatory = wire_of(0x13);
        parse_frame_payload(&mandatory).expect("the decode reads the mandatory one");
        assert_eq!(
            admit_frame_payload_lending(&mandatory).unwrap_err(),
            crate::parse_error::InboundParseError::UnknownMandatoryExt { eid: 0x13 }
        );
        // The verdict is the first offender's, judged as the batch is read, and a batch that does
        // not decode is refused for that, whatever the rule says of a message before the damage.
        let both = [&optional[..], &mandatory[..], &optional[..]].concat();
        assert_eq!(
            admit_frame_payload_lending(&both).unwrap_err(),
            crate::parse_error::InboundParseError::UnknownMandatoryExt { eid: 0x13 }
        );
        let cut = [&mandatory[..], &optional[..optional.len() - 1]].concat();
        assert!(matches!(
            admit_frame_payload_lending(&cut),
            Err(crate::parse_error::InboundParseError::Codec(_))
        ));
    }
}

// The space a key expression is counted in, as `stats_class` classifies it. The
// module's name avoids the words of the `--lib` filters the count guards select
// by, so adding it moves none of them.
#[cfg(all(
    test,
    feature = "transport-stats",
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response"
    )
))]
mod alias_space_tests {
    use super::stats_space_of_key;
    use crate::stats::StatSpace;
    use crate::wire_id::ExprId;
    use alloc::string::String;

    /// An alias the caller's id space cannot resolve counts in the USER space,
    /// whatever its suffix says: the inbound seam holds no table of the peer's
    /// ids, and counting an unknown expression as admin would move admin counts
    /// on nothing more than an alias being used.
    #[test]
    fn an_unresolvable_alias_counts_as_user() {
        let unknown = |_: ExprId| -> Option<String> { None };
        assert_eq!(stats_space_of_key(7, None, &unknown), StatSpace::User);
        assert_eq!(
            stats_space_of_key(7, Some("@/abc/session"), &unknown),
            StatSpace::User
        );
    }

    /// The controls: an alias the space resolves is classified by what it names,
    /// and a literal key by itself. Without them the case above would also pass
    /// a classifier that counted everything as user.
    #[test]
    fn a_resolved_alias_and_a_literal_key_are_classified_by_their_text() {
        let admin = |_: ExprId| -> Option<String> { Some(String::from("@/abc")) };
        assert_eq!(
            stats_space_of_key(7, Some("/session"), &admin),
            StatSpace::Admin
        );
        let unknown = |_: ExprId| -> Option<String> { None };
        assert_eq!(
            stats_space_of_key(0, Some("@/abc/session"), &unknown),
            StatSpace::Admin
        );
        assert_eq!(
            stats_space_of_key(0, Some("demo/x"), &unknown),
            StatSpace::User
        );
    }
}

// A chain that carries one extension twice is read as upstream reads it, on every network
// message and every body it carries whose extension wz reads. Each of upstream's decoders assigns
// the entry an extension's arm meets, so a later entry replaces an earlier one: the chain reads as
// the chain of its last entry alone, and no decoder refuses the repetition or keeps the first
// (`crate::ext_view::last_by_eid`, which cites each decoder). Every test reads the chain held, as
// the heap receive path holds it, and walked where its frame lies, as the in-place and the slot
// receive paths read it, and holds each reading to the reading of the last entry alone and away
// from that of the first.
#[cfg(all(
    test,
    feature = "alloc",
    feature = "storage-profile",
    feature = "codec-push",
    feature = "codec-request",
    feature = "codec-response",
    feature = "codec-declare"
))]
mod repeated_extension_tests {
    use super::{parse_frame_payload, NetworkMessage};
    use crate::ext_header::body_eid::{DEL_ATTACHMENT, QUERY_ATTACHMENT, QUERY_VALUE, SOURCE_INFO};
    use crate::ext_header::network_eid::{QOS, RESPONDER};
    use crate::ext_nodeid::{read_z64_of, NODEID_EXT_HEADER as NODE_ID};
    use crate::ext_view::walked;
    use crate::held_list::HeldList;
    use crate::wire::WireStorage;
    use alloc::vec::Vec;
    use sce_forge_runtime::codec::{Bounded, SceCursor};
    use wz_codecs::ext_entry::{
        ExtEntryFrom, ExtEntryOwned, ExtEntryOwnedVariant, ExtEntryStorage,
    };
    use wz_codecs::ext_zbuf::{ExtZbufOwned, ExtZbufValueField};
    use wz_codecs::ext_zint::ExtZint;
    use wz_codecs_test_support::TestWire as _;

    /// A z64 entry of `header` holding `value`.
    fn z64<S: ExtEntryStorage>(header: u8, value: u64) -> ExtEntryOwned<S> {
        ExtEntryOwned {
            header,
            body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint { value }),
        }
    }

    /// A ZBuf entry of `header` holding `bytes`.
    fn zbuf<S: for<'x> ExtEntryFrom<'x>>(header: u8, bytes: &[u8]) -> ExtEntryOwned<S> {
        let value = Bounded::new(bytes)
            .expect("a test value is within the protocol's bound")
            .store::<S, ExtZbufValueField>()
            .expect("the heap holds a test value");
        ExtEntryOwned {
            header,
            body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                value_len: bytes.len() as u64,
                value,
            }),
        }
    }

    /// A chain of `entries`, in order, as a message holds it; the encoder sets each entry's
    /// chain flag.
    fn chain<E>(entries: Vec<E>) -> Bounded<Vec<E>, { usize::MAX }, 1> {
        crate::held_list::held(entries).expect("a chain of a few entries is within its bound")
    }

    /// The body of a source-info extension naming the two-byte zid `[0xA0, n]`, entity `n` and
    /// sequence number `n`.
    fn source_info(n: u8) -> Vec<u8> {
        crate::source_info_ext::encode_source_info_ext_body(&[0xA0, n], u32::from(n), u32::from(n))
            .expect("a two-byte zid is a zid")
    }

    /// `both` is the reading of the chain that carries the extension twice, `last` and `first`
    /// the readings of each of its entries alone.
    #[track_caller]
    fn assert_reads_last<T: PartialEq + core::fmt::Debug>(what: &str, both: T, last: T, first: T) {
        assert_ne!(last, first, "{what}: the two entries must read apart");
        assert_eq!(
            both, last,
            "{what}: a repeated extension is read by its last entry"
        );
    }

    /// The Push (`commons/zenoh-codec/src/network/push.rs` @ `ext_qos = q;` and
    /// `ext_nodeid = nid;`) and the Del it carries (`commons/zenoh-codec/src/zenoh/del.rs` @
    /// `ext_sinfo = Some(s);` and `ext_attachment = Some(a);`).
    #[test]
    fn a_push_and_its_del_read_a_repeated_extension_by_its_last_entry() {
        let (sinfo_first, sinfo_last) = (source_info(1), source_info(2));
        let mut push = crate::push_build::build_push_del_literal("k").expect("a literal del");
        push.extensions = Some(chain(alloc::vec![
            z64(QOS, 5),
            z64(NODE_ID, 7),
            z64(QOS, 2),
            z64(NODE_ID, 9),
        ]));
        crate::ext_nodeid::sync_header_z(&mut push.header, true);
        match &mut push.body {
            crate::wire::PushOwnedVariant::CodecZenohMsgDel(del) => {
                del.extensions = Some(chain(alloc::vec![
                    zbuf(SOURCE_INFO, &sinfo_first),
                    zbuf(DEL_ATTACHMENT, b"first"),
                    zbuf(SOURCE_INFO, &sinfo_last),
                    zbuf(DEL_ATTACHMENT, b"last"),
                ]));
                crate::ext_nodeid::sync_header_z(&mut del.header, true);
            }
            _ => panic!("a literal del carries a Del"),
        }
        let wire = push.wire();
        let messages = parse_frame_payload(&wire).expect("the Push decodes");
        let [NetworkMessage::Push(held)] = messages.as_slice() else {
            panic!("the wire is one Push");
        };
        let view = wz_codecs::push::PushView::decode(&mut SceCursor::new(&wire))
            .expect("the Push decodes where it lies");

        let envelope = HeldList::entries(&held.extensions).expect("the Push holds its chain");
        let (qos_last, qos_first) = (z64::<WireStorage>(QOS, 2), z64::<WireStorage>(QOS, 5));
        let alone_qos = |e: &ExtEntryOwned<WireStorage>| crate::sample::extract_qos_in([e]);
        for both in [
            crate::sample::extract_qos_in(envelope),
            crate::sample::extract_qos_in(walked(view.extensions.as_ref())),
        ] {
            assert_reads_last(
                "push qos",
                both,
                alone_qos(&qos_last),
                alone_qos(&qos_first),
            );
        }
        for both in [
            read_z64_of(envelope, NODE_ID),
            read_z64_of(walked(view.extensions.as_ref()), NODE_ID),
        ] {
            assert_reads_last("push node id", both, Some(9), Some(7));
        }
        assert_eq!(
            crate::ext_nodeid::read_source(held.extensions.as_deref()),
            9
        );

        let held_del = match &held.body {
            crate::wire::PushOwnedVariant::CodecZenohMsgDel(del) => {
                HeldList::entries(&del.extensions).expect("the Del holds its chain")
            }
            _ => panic!("the Push carries a Del"),
        };
        let walked_del = || {
            walked(match &view.body {
                wz_codecs::push::PushViewVariant::CodecZenohMsgDel(del) => del.extensions.as_ref(),
                _ => panic!("the Push carries a Del"),
            })
        };
        let sinfo = |bytes: &[u8]| {
            crate::sample::extract_source_info(&[zbuf::<WireStorage>(SOURCE_INFO, bytes)])
        };
        for both in [
            crate::sample::extract_source_info(held_del),
            crate::sample::extract_source_info_in(walked_del()),
        ] {
            assert_reads_last(
                "del source info",
                both,
                sinfo(&sinfo_last),
                sinfo(&sinfo_first),
            );
        }
        #[cfg(feature = "attachment-bytes")]
        {
            use crate::attachment::ATTACHMENT_EXT_ID_DEL as DEL;
            use crate::attachment::{decode_attachment_ext, decode_attachment_ext_in};
            for both in [
                decode_attachment_ext(held_del, DEL),
                decode_attachment_ext_in(walked_del(), DEL),
            ] {
                assert_reads_last(
                    "del attachment",
                    both,
                    Some(&b"last"[..]),
                    Some(&b"first"[..]),
                );
            }
        }
    }

    /// The Put a Push carries (`commons/zenoh-codec/src/zenoh/put.rs` @ `*ext_sinfo = Some(s);`
    /// and `*ext_attachment = Some(a);`), whose chain the payload's layout holds.
    #[test]
    fn a_put_reads_a_repeated_extension_by_its_last_entry() {
        let (sinfo_first, sinfo_last) = (source_info(1), source_info(2));
        let mut push = crate::push_build::build_push_literal("k", b"v").expect("a literal put");
        match &mut push.body {
            crate::wire::PushOwnedVariant::CodecZenohMsgPut(put) => {
                crate::put_payload::set_chain(
                    put,
                    [
                        zbuf(SOURCE_INFO, &sinfo_first),
                        zbuf(crate::ext_header::body_eid::PUT_ATTACHMENT, b"first"),
                        zbuf(SOURCE_INFO, &sinfo_last),
                        zbuf(crate::ext_header::body_eid::PUT_ATTACHMENT, b"last"),
                    ],
                )
                .expect("an inline Put holds a chain of four entries");
            }
            _ => panic!("a literal put carries a Put"),
        }
        let wire = push.wire();
        let messages = parse_frame_payload(&wire).expect("the Push decodes");
        let [NetworkMessage::Push(held)] = messages.as_slice() else {
            panic!("the wire is one Push");
        };
        let view = wz_codecs::push::PushView::decode(&mut SceCursor::new(&wire))
            .expect("the Push decodes where it lies");
        let held_put = match &held.body {
            crate::wire::PushOwnedVariant::CodecZenohMsgPut(put) => crate::put_payload::chain(put),
            _ => panic!("the Push carries a Put"),
        };
        let walked_put = || {
            let wz_codecs::push::PushViewVariant::CodecZenohMsgPut(put) = &view.body else {
                panic!("the Push carries a Put");
            };
            crate::put_payload::view_chain(put)
                .map(|(rest, _)| sce_forge_runtime::codec::Entries::entries(rest))
                .into_iter()
                .flatten()
        };
        let sinfo = |bytes: &[u8]| {
            crate::sample::extract_source_info(&[zbuf::<WireStorage>(SOURCE_INFO, bytes)])
        };
        for both in [
            crate::sample::extract_source_info(held_put),
            crate::sample::extract_source_info_in(walked_put()),
        ] {
            assert_reads_last(
                "put source info",
                both,
                sinfo(&sinfo_last),
                sinfo(&sinfo_first),
            );
        }
        #[cfg(feature = "attachment-bytes")]
        {
            use crate::attachment::ATTACHMENT_EXT_ID_PUSH as PUT;
            use crate::attachment::{decode_attachment_ext, decode_attachment_ext_in};
            for both in [
                decode_attachment_ext(held_put, PUT),
                decode_attachment_ext_in(walked_put(), PUT),
            ] {
                assert_reads_last(
                    "put attachment",
                    both,
                    Some(&b"last"[..]),
                    Some(&b"first"[..]),
                );
            }
        }
    }

    /// The Request (`commons/zenoh-codec/src/network/request.rs` @ `ext_qos = q;`,
    /// `ext_nodeid = nid;`, `ext_target = rt;` and `ext_timeout = Some(`) and the Query it carries
    /// (`commons/zenoh-codec/src/zenoh/query.rs` @ `ext_sinfo = Some(s);`, `ext_body = Some(s);`
    /// and `ext_attachment = Some(a);`).
    #[test]
    fn a_request_and_its_query_read_a_repeated_extension_by_its_last_entry() {
        use crate::query_mode::TARGET_EXT_HEADER as TARGET;
        use crate::request_routing_context::TIMEOUT_EXT_HEADER as TIMEOUT;
        let (sinfo_first, sinfo_last) = (source_info(1), source_info(2));
        // A value is its encoding (0: none, no schema) and its payload.
        let (value_first, value_last) = ([0x00, b'a'], [0x00, b'b', b'b']);
        let mut request = crate::request_build::build_request_query(
            1,
            crate::wire_key::WireKey::literal("k").expect("a literal key"),
        )
        .expect("a query request");
        request.extensions = Some(chain(alloc::vec![
            z64(QOS, 5),
            z64(TARGET, 1),
            z64(TIMEOUT, 100),
            z64(NODE_ID, 7),
            z64(QOS, 2),
            z64(TARGET, 2),
            z64(TIMEOUT, 200),
            z64(NODE_ID, 9),
        ]));
        crate::ext_nodeid::sync_header_z(&mut request.header, true);
        let entry = |header: u8, bytes: &[u8]| {
            crate::ext_view::query_ext_from_generic(zbuf::<WireStorage>(header, bytes))
        };
        match &mut request.body {
            crate::wire::RequestOwnedVariant::CodecZenohQuery(query) => {
                query.extensions = Some(
                    crate::held_list::lawful(chain(alloc::vec![
                        entry(SOURCE_INFO, &sinfo_first),
                        entry(QUERY_VALUE, &value_first),
                        entry(QUERY_ATTACHMENT, b"first"),
                        entry(SOURCE_INFO, &sinfo_last),
                        entry(QUERY_VALUE, &value_last),
                        entry(QUERY_ATTACHMENT, b"last"),
                    ]))
                    .expect("a chain with no shared-memory marker follows its law"),
                );
                crate::ext_nodeid::sync_header_z(&mut query.header, true);
            }
            _ => panic!("a query request carries a Query"),
        }
        let wire = request.wire();
        let messages = parse_frame_payload(&wire).expect("the Request decodes");
        let [NetworkMessage::Request(held)] = messages.as_slice() else {
            panic!("the wire is one Request");
        };
        let view = wz_codecs::request::RequestView::decode(&mut SceCursor::new(&wire))
            .expect("the Request decodes where it lies");

        let envelope = HeldList::entries(&held.extensions).expect("the Request holds its chain");
        let alone = |header: u8, value: u64| [z64::<WireStorage>(header, value)];
        for both in [
            crate::declare_ext_qos::read_qos_of(envelope),
            crate::declare_ext_qos::read_qos_of(walked(view.extensions.as_ref())),
        ] {
            assert_reads_last(
                "request qos",
                both,
                crate::declare_ext_qos::read_qos_of(alone(QOS, 2)),
                crate::declare_ext_qos::read_qos_of(alone(QOS, 5)),
            );
        }
        for both in [
            crate::request_routing_context::read_target_of(envelope),
            crate::request_routing_context::read_target_of(walked(view.extensions.as_ref())),
        ] {
            assert_reads_last(
                "request target",
                both,
                crate::request_routing_context::read_target_of(alone(TARGET, 2)),
                crate::request_routing_context::read_target_of(alone(TARGET, 1)),
            );
        }
        assert_eq!(
            crate::request_routing_context::read_request_target(held),
            crate::request_routing_context::read_target_of(alone(TARGET, 2))
        );
        // The in-place receive path reads the target and the QoS in one walk.
        assert_eq!(
            crate::ext_nodeid::read_two_z64_of(walked(view.extensions.as_ref()), TARGET, QOS),
            (Some(2), Some(2))
        );
        for both in [
            read_z64_of(envelope, TIMEOUT),
            read_z64_of(walked(view.extensions.as_ref()), TIMEOUT),
        ] {
            assert_reads_last("request timeout", both, Some(200), Some(100));
        }
        assert_eq!(
            crate::request_routing_context::read_request_timeout_ms(held),
            Some(200)
        );
        for both in [
            read_z64_of(envelope, NODE_ID),
            read_z64_of(walked(view.extensions.as_ref()), NODE_ID),
        ] {
            assert_reads_last("request node id", both, Some(9), Some(7));
        }

        let held_query = match &held.body {
            crate::wire::RequestOwnedVariant::CodecZenohQuery(query) => {
                HeldList::entries(&query.extensions).expect("the Query holds its chain")
            }
            _ => panic!("the Request carries a Query"),
        };
        let walked_query = || {
            walked(match &view.body {
                wz_codecs::request::RequestViewVariant::CodecZenohQuery(query) => {
                    query.extensions.as_deref()
                }
                _ => panic!("the Request carries a Query"),
            })
        };
        let sinfo = |bytes: &[u8]| crate::sample::extract_source_info(&[entry(SOURCE_INFO, bytes)]);
        for both in [
            crate::sample::extract_source_info(held_query),
            crate::sample::extract_source_info_in(walked_query()),
        ] {
            assert_reads_last(
                "query source info",
                both,
                sinfo(&sinfo_last),
                sinfo(&sinfo_first),
            );
        }
        assert_reads_last(
            "query value length",
            crate::ext_view::query_value_payload_len(held_query),
            2,
            1,
        );
        #[cfg(feature = "query-value")]
        {
            use crate::query_value_ext::{decode_query_value_ext, decode_query_value_ext_in};
            for both in [
                decode_query_value_ext(held_query).map(|(_, payload)| payload),
                decode_query_value_ext_in(walked_query()).map(|(_, payload)| payload),
            ] {
                assert_reads_last("query value", both, Some(&b"bb"[..]), Some(&b"a"[..]));
            }
        }
        #[cfg(feature = "attachment-bytes")]
        {
            use crate::attachment::ATTACHMENT_EXT_ID_QUERY as QUERY;
            use crate::attachment::{decode_attachment_ext, decode_attachment_ext_in};
            for both in [
                decode_attachment_ext(held_query, QUERY),
                decode_attachment_ext_in(walked_query(), QUERY),
            ] {
                assert_reads_last(
                    "query attachment",
                    both,
                    Some(&b"last"[..]),
                    Some(&b"first"[..]),
                );
            }
        }
    }

    /// The Response (`commons/zenoh-codec/src/network/response.rs` @ `ext_qos = q;` and
    /// `ext_respid = Some(t);`) and the Err it carries (`commons/zenoh-codec/src/zenoh/err.rs` @
    /// `ext_sinfo = Some(s);`).
    #[test]
    fn a_response_and_its_err_read_a_repeated_extension_by_its_last_entry() {
        let (sinfo_first, sinfo_last) = (source_info(1), source_info(2));
        // The responder: the zid's length less one in the high nibble, the zid, the entity id.
        let (responder_first, responder_last) = ([0x10, 0xCA, 0xFE, 0x03], [0x00, 0xAB, 0x07]);
        let mut response = crate::response_build::build_response_err(
            1,
            crate::wire_key::WireKey::literal("k").expect("a literal key"),
            b"e",
        )
        .expect("an err response");
        response.extensions = Some(chain(alloc::vec![
            zbuf(RESPONDER, &responder_first),
            z64(QOS, 5),
            zbuf(RESPONDER, &responder_last),
            z64(QOS, 2),
        ]));
        crate::ext_nodeid::sync_header_z(&mut response.header, true);
        match &mut response.body {
            crate::wire::ResponseOwnedVariant::CodecZenohErr(err) => {
                err.extensions = Some(chain(alloc::vec![
                    zbuf(SOURCE_INFO, &sinfo_first),
                    zbuf(SOURCE_INFO, &sinfo_last),
                ]));
                crate::ext_nodeid::sync_header_z(&mut err.header, true);
            }
            _ => panic!("an err response carries an Err"),
        }
        let wire = response.wire();
        let messages = parse_frame_payload(&wire).expect("the Response decodes");
        let [NetworkMessage::Response(held)] = messages.as_slice() else {
            panic!("the wire is one Response");
        };
        let view = wz_codecs::response::ResponseView::decode(&mut SceCursor::new(&wire))
            .expect("the Response decodes where it lies");

        let envelope = HeldList::entries(&held.extensions).expect("the Response holds its chain");
        for both in [
            crate::reply::response_responder(envelope),
            crate::reply::response_responder(walked(view.extensions.as_ref())),
        ] {
            assert_reads_last(
                "response responder",
                both,
                Some((&[0xAB][..], 7)),
                Some((&[0xCA, 0xFE][..], 3)),
            );
        }
        let (qos_last, qos_first) = (z64::<WireStorage>(QOS, 2), z64::<WireStorage>(QOS, 5));
        let alone_qos = |e: &ExtEntryOwned<WireStorage>| crate::sample::extract_qos_in([e]);
        for both in [
            crate::sample::extract_qos_in(envelope),
            crate::sample::extract_qos_in(walked(view.extensions.as_ref())),
        ] {
            assert_reads_last(
                "response qos",
                both,
                alone_qos(&qos_last),
                alone_qos(&qos_first),
            );
        }

        let held_err = match &held.body {
            crate::wire::ResponseOwnedVariant::CodecZenohErr(err) => {
                HeldList::entries(&err.extensions).expect("the Err holds its chain")
            }
            _ => panic!("the Response carries an Err"),
        };
        let walked_err = walked(match &view.body {
            wz_codecs::response::ResponseViewVariant::CodecZenohErr(err) => err.extensions.as_ref(),
            _ => panic!("the Response carries an Err"),
        });
        let sinfo = |bytes: &[u8]| {
            crate::sample::extract_source_info(&[zbuf::<WireStorage>(SOURCE_INFO, bytes)])
        };
        for both in [
            crate::sample::extract_source_info(held_err),
            crate::sample::extract_source_info_in(walked_err),
        ] {
            assert_reads_last(
                "err source info",
                both,
                sinfo(&sinfo_last),
                sinfo(&sinfo_first),
            );
        }
    }

    /// The Declare (`commons/zenoh-codec/src/network/declare.rs` @ `ext_qos = q;` and
    /// `ext_nodeid = nid;`), the undeclaration's wire expression (the same file @
    /// `ext_wire_expr = we;`) and a queryable's info (the same file @ `ext_info = i;`).
    #[test]
    fn a_declare_and_its_bodies_read_a_repeated_extension_by_its_last_entry() {
        let mut undeclare = crate::declare_build::build_undeclare_subscriber(1);
        undeclare.extensions = Some(chain(alloc::vec![
            z64(QOS, 5),
            z64(NODE_ID, 7),
            z64(QOS, 2),
            z64(NODE_ID, 9),
        ]));
        crate::ext_nodeid::sync_header_z(&mut undeclare.header, true);
        match &mut undeclare.body {
            wz_codecs::declare::DeclareOwnedVariant::CodecZenohUndeclSubscriber(d) => {
                d.extensions = Some(chain(alloc::vec![
                    crate::declare_ext_keyexpr::build_ext_keyexpr("first")
                        .expect("a literal keyexpr"),
                    crate::declare_ext_keyexpr::build_ext_keyexpr("last")
                        .expect("a literal keyexpr"),
                ]));
                crate::ext_nodeid::sync_header_z(&mut d.header, true);
            }
            _ => panic!("an undeclaration carries its body"),
        }
        let wire = undeclare.wire();
        let messages = parse_frame_payload(&wire).expect("the Declare decodes");
        let [NetworkMessage::Declare(held)] = messages.as_slice() else {
            panic!("the wire is one Declare");
        };
        let view = wz_codecs::declare::DeclareView::decode(&mut SceCursor::new(&wire))
            .expect("the Declare decodes where it lies");

        let envelope = HeldList::entries(&held.extensions).expect("the Declare holds its chain");
        let alone_qos =
            |value: u64| crate::declare_ext_qos::read_qos_of(&[z64::<WireStorage>(QOS, value)]);
        for both in [
            crate::declare_ext_qos::read_qos_of(envelope),
            crate::declare_ext_qos::read_qos_of(walked(view.extensions.as_ref())),
        ] {
            assert_reads_last("declare qos", both, alone_qos(2), alone_qos(5));
        }
        for both in [
            read_z64_of(envelope, NODE_ID),
            read_z64_of(walked(view.extensions.as_ref()), NODE_ID),
        ] {
            assert_reads_last("declare node id", both, Some(9), Some(7));
        }
        let wire_expr = match &held.body {
            wz_codecs::declare::DeclareOwnedVariant::CodecZenohUndeclSubscriber(d) => {
                crate::declare_ext_keyexpr::read_ext_keyexpr(d.extensions.as_deref())
            }
            _ => panic!("the Declare carries the undeclaration"),
        };
        assert_reads_last(
            "undeclaration wire expression",
            wire_expr,
            Some("last"),
            Some("first"),
        );

        let mut queryable = crate::declare_build::build_declare_queryable(1, 0, Some("k"))
            .expect("a literal queryable");
        let info = crate::queryable_info::QUERYABLE_INFO_EXT_HEADER;
        let (info_first, info_last) = (0x01, 0x0300);
        match &mut queryable.body {
            wz_codecs::declare::DeclareOwnedVariant::CodecZenohDeclQueryable(d) => {
                d.extensions = Some(chain(alloc::vec![
                    z64(info, info_first),
                    z64(info, info_last),
                ]));
                crate::ext_nodeid::sync_header_z(&mut d.header, true);
            }
            _ => panic!("a queryable declaration carries its body"),
        }
        let wire = queryable.wire();
        let messages = parse_frame_payload(&wire).expect("the Declare decodes");
        let [NetworkMessage::Declare(held)] = messages.as_slice() else {
            panic!("the wire is one Declare");
        };
        let read = match &held.body {
            wz_codecs::declare::DeclareOwnedVariant::CodecZenohDeclQueryable(d) => {
                crate::queryable_info::read_queryable_info_in(HeldList::entries(&d.extensions))
            }
            _ => panic!("the Declare carries the queryable"),
        };
        let alone = |value: u64| {
            crate::queryable_info::read_queryable_info_in(Some(
                &[z64::<WireStorage>(info, value)][..],
            ))
        };
        assert_reads_last("queryable info", read, alone(info_last), alone(info_first));
    }

    /// The Interest (`commons/zenoh-codec/src/network/interest.rs` @ `ext_qos = q;` and
    /// `ext_nodeid = nid;`).
    #[test]
    fn an_interest_reads_a_repeated_extension_by_its_last_entry() {
        let mut interest = crate::interest_build::build_interest_final(1);
        interest.extensions = Some(chain(alloc::vec![
            z64(QOS, 5),
            z64(NODE_ID, 7),
            z64(QOS, 2),
            z64(NODE_ID, 9),
        ]));
        crate::ext_nodeid::sync_header_z(&mut interest.header, true);
        let wire = interest.wire();
        let messages = parse_frame_payload(&wire).expect("the Interest decodes");
        let [NetworkMessage::Interest(held)] = messages.as_slice() else {
            panic!("the wire is one Interest");
        };
        let view = wz_codecs::interest::InterestView::decode(&mut SceCursor::new(&wire))
            .expect("the Interest decodes where it lies");
        let envelope = HeldList::entries(&held.extensions).expect("the Interest holds its chain");
        let alone_qos =
            |value: u64| crate::declare_ext_qos::read_qos_of(&[z64::<WireStorage>(QOS, value)]);
        for both in [
            crate::declare_ext_qos::read_qos_of(envelope),
            crate::declare_ext_qos::read_qos_of(walked(view.extensions.as_ref())),
        ] {
            assert_reads_last("interest qos", both, alone_qos(2), alone_qos(5));
        }
        for both in [
            read_z64_of(envelope, NODE_ID),
            read_z64_of(walked(view.extensions.as_ref()), NODE_ID),
        ] {
            assert_reads_last("interest node id", both, Some(9), Some(7));
        }
    }

    /// A message's readings a participant may act on: the batch decode held and judged as a batch,
    /// and the record walk that lends each record where its frame lies and the one that owns it.
    fn refusals(wire: &[u8]) -> [Result<(), crate::parse_error::InboundParseError>; 3] {
        use super::{for_each_record, new_record_buf, RecordForm};
        let held = parse_frame_payload(wire)
            .expect("the record decodes")
            .iter()
            .find_map(|message| message.ext_admission().refusal())
            .map_or(Ok(()), Err);
        let walk = |form| {
            let mut record = new_record_buf();
            let mut handed = 0usize;
            let result = for_each_record(wire, &mut record, form, |_| handed += 1);
            assert!(
                result.is_ok() || handed == 0,
                "a refused record is not handed over"
            );
            result
        };
        [held, walk(RecordForm::Lent), walk(RecordForm::Owned)]
    }

    /// A declared extension whose LAST entry its reader refuses refuses the whole message on every
    /// reading, where it was read as absent: upstream reads each entry with the extension's reader
    /// and propagates what that reader refuses (`commons/zenoh-codec/src/network/push.rs` @
    /// `let (t, ext): (ext::TimestampType, bool) = eodec.read(&mut *reader)?;`,
    /// `commons/zenoh-codec/src/network/request.rs` @ `_ => return Err(DidntRead),`,
    /// `commons/zenoh-codec/src/zenoh/mod.rs` @ `let sn: u32 = self.codec.read(&mut *reader)?;`).
    /// The same message with that entry well formed is admitted on every reading.
    #[test]
    fn a_malformed_last_entry_refuses_the_message_on_every_reading() {
        use crate::ext_header::ext_eid;
        use crate::parse_error::InboundParseError::MalformedExt;
        use crate::query_mode::TARGET_EXT_HEADER as TARGET;
        // `pub type Timestamp = zextzbuf!(0x2, false);`
        const TIMESTAMP: u8 = 0x42;
        // A timestamp is a time, the length of an id and the id; an id of zero is no id.
        let (stamp_good, stamp_zero) = ([0x05, 0x01, 0x01], [0x05, 0x01, 0x00]);
        let push = |last: &[u8]| {
            let mut push = crate::push_build::build_push_del_literal("k").expect("a literal del");
            push.extensions = Some(chain(alloc::vec![
                zbuf(TIMESTAMP, &stamp_good),
                zbuf(TIMESTAMP, last),
            ]));
            crate::ext_nodeid::sync_header_z(&mut push.header, true);
            push.wire()
        };
        // A Request's target is 0, 1 or 2.
        let request = |last: u64| {
            let mut request = crate::request_build::build_request_query(
                1,
                crate::wire_key::WireKey::literal("k").expect("a literal key"),
            )
            .expect("a query request");
            request.extensions = Some(chain(alloc::vec![z64(TARGET, 1), z64(TARGET, last)]));
            crate::ext_nodeid::sync_header_z(&mut request.header, true);
            request.wire()
        };
        // A source info is a zid, an entity id and a sequence number; one cut short has none.
        let sinfo_good = source_info(2);
        let sinfo_cut = &sinfo_good[..sinfo_good.len() - 1];
        let response = |last: &[u8]| {
            let mut response = crate::response_build::build_response_err(
                1,
                crate::wire_key::WireKey::literal("k").expect("a literal key"),
                b"e",
            )
            .expect("an err response");
            match &mut response.body {
                crate::wire::ResponseOwnedVariant::CodecZenohErr(err) => {
                    err.extensions = Some(chain(alloc::vec![
                        zbuf(SOURCE_INFO, &source_info(1)),
                        zbuf(SOURCE_INFO, last),
                    ]));
                    crate::ext_nodeid::sync_header_z(&mut err.header, true);
                }
                _ => panic!("an err response carries an Err"),
            }
            response.wire()
        };
        let cases = [
            (
                "push timestamp",
                push(&stamp_good),
                push(&stamp_zero),
                TIMESTAMP,
            ),
            ("request target", request(2), request(3), ext_eid(TARGET)),
            (
                "err source info",
                response(&sinfo_good),
                response(sinfo_cut),
                SOURCE_INFO,
            ),
        ];
        for (what, good, bad, eid) in cases {
            assert_eq!(
                refusals(&good),
                [Ok(()); 3],
                "{what}: the well-formed control"
            );
            assert_eq!(refusals(&bad), [Err(MalformedExt { eid }); 3], "{what}");
        }
    }

    /// The shape of a chain as its readers see it: each entry's identity and body, in order, the
    /// chain flag aside.
    fn shape<E: crate::ext_view::ExtEntryView>(
        entries: &[E],
    ) -> Vec<(u8, Option<Vec<u8>>, Option<u64>)> {
        entries
            .iter()
            .map(|e| (e.eid(), e.plain_zbuf().map(<[u8]>::to_vec), e.zint()))
            .collect()
    }

    /// What a router routes of a message whose chains repeat a declared extension is the message
    /// upstream's decoder makes of it (`super::as_routed`): each declared extension
    /// once, as its last entry, the order of the rest kept. An extension a body does not declare
    /// is kept as often as it came, as upstream's body decoder keeps each
    /// (`commons/zenoh-codec/src/zenoh/del.rs` @ `ext_unknown.push(u);`), and a Query's value
    /// is its last. A message that repeats nothing is routed as it came.
    #[test]
    fn a_routed_message_holds_a_repeated_declared_extension_once_as_its_last_entry() {
        use super::as_routed;
        use crate::ext_header::body_eid::PUT_ATTACHMENT;
        // A ZBuf of id 0xA, which no Del declares.
        const UNKNOWN: u8 = 0x4A;
        let decoded = |wire: Vec<u8>| {
            let mut messages = parse_frame_payload(&wire).expect("the record decodes");
            assert_eq!(messages.len(), 1);
            messages.remove(0)
        };
        let (sinfo_first, sinfo_last) = (source_info(1), source_info(2));

        let mut push = crate::push_build::build_push_del_literal("k").expect("a literal del");
        push.extensions = Some(chain(alloc::vec![
            z64(QOS, 5),
            z64(NODE_ID, 7),
            z64(QOS, 2)
        ]));
        crate::ext_nodeid::sync_header_z(&mut push.header, true);
        match &mut push.body {
            crate::wire::PushOwnedVariant::CodecZenohMsgDel(del) => {
                del.extensions = Some(chain(alloc::vec![
                    zbuf(SOURCE_INFO, &sinfo_first),
                    zbuf(UNKNOWN, b"u1"),
                    zbuf(DEL_ATTACHMENT, b"first"),
                    zbuf(SOURCE_INFO, &sinfo_last),
                    zbuf(UNKNOWN, b"u2"),
                    zbuf(DEL_ATTACHMENT, b"last"),
                ]));
                crate::ext_nodeid::sync_header_z(&mut del.header, true);
            }
            _ => panic!("a literal del carries a Del"),
        }
        let Some(NetworkMessage::Push(routed)) = as_routed(&decoded(push.wire())) else {
            panic!("a Push that repeats an extension is routed as another Push");
        };
        let envelope: [ExtEntryOwned<WireStorage>; 2] = [z64(NODE_ID, 7), z64(QOS, 2)];
        assert_eq!(
            shape(routed.extensions.entries().expect("a chain")),
            shape(&envelope)
        );
        let body: [ExtEntryOwned<WireStorage>; 4] = [
            zbuf(UNKNOWN, b"u1"),
            zbuf(SOURCE_INFO, &sinfo_last),
            zbuf(UNKNOWN, b"u2"),
            zbuf(DEL_ATTACHMENT, b"last"),
        ];
        match &routed.body {
            crate::wire::PushOwnedVariant::CodecZenohMsgDel(del) => {
                assert_eq!(
                    shape(del.extensions.entries().expect("a chain")),
                    shape(&body)
                )
            }
            _ => panic!("the routed Push carries the Del"),
        }
        let again = decoded(routed.wire());
        assert!(
            as_routed(&again).is_none(),
            "the routed Push encodes, decodes and repeats nothing"
        );

        let mut put = crate::push_build::build_push_literal("k", b"v").expect("a literal put");
        match &mut put.body {
            crate::wire::PushOwnedVariant::CodecZenohMsgPut(p) => crate::put_payload::set_chain(
                p,
                [
                    zbuf(PUT_ATTACHMENT, b"first"),
                    zbuf(PUT_ATTACHMENT, b"last"),
                ],
            )
            .expect("two entries are within the bound"),
            _ => panic!("a literal put carries a Put"),
        }
        let Some(NetworkMessage::Push(routed)) = as_routed(&decoded(put.wire())) else {
            panic!("a Put that repeats its attachment is routed as another Push");
        };
        let attachment: [ExtEntryOwned<WireStorage>; 1] = [zbuf(PUT_ATTACHMENT, b"last")];
        match &routed.body {
            crate::wire::PushOwnedVariant::CodecZenohMsgPut(p) => {
                assert_eq!(shape(crate::put_payload::chain(p)), shape(&attachment))
            }
            _ => panic!("the routed Push carries the Put"),
        }

        let entry = |header: u8, bytes: &[u8]| {
            crate::ext_view::query_ext_from_generic(zbuf::<WireStorage>(header, bytes))
        };
        let mut request = crate::request_build::build_request_query(
            1,
            crate::wire_key::WireKey::literal("k").expect("a literal key"),
        )
        .expect("a query request");
        request.extensions = Some(chain(alloc::vec![z64(QOS, 5), z64(QOS, 2)]));
        crate::ext_nodeid::sync_header_z(&mut request.header, true);
        match &mut request.body {
            crate::wire::RequestOwnedVariant::CodecZenohQuery(query) => {
                query.extensions = Some(
                    crate::held_list::lawful(chain(alloc::vec![
                        entry(SOURCE_INFO, &sinfo_first),
                        entry(QUERY_VALUE, &[0x00, b'a']),
                        entry(QUERY_ATTACHMENT, b"a"),
                        entry(QUERY_VALUE, &[0x00, b'b']),
                    ]))
                    .expect("a chain with no shared-memory marker follows its law"),
                );
                crate::ext_nodeid::sync_header_z(&mut query.header, true);
            }
            _ => panic!("a query request carries a Query"),
        }
        let Some(NetworkMessage::Request(routed)) = as_routed(&decoded(request.wire())) else {
            panic!("a Request that repeats an extension is routed as another Request");
        };
        let qos: [ExtEntryOwned<WireStorage>; 1] = [z64(QOS, 2)];
        assert_eq!(
            shape(routed.extensions.entries().expect("a chain")),
            shape(&qos)
        );
        let query = [
            entry(SOURCE_INFO, &sinfo_first),
            entry(QUERY_ATTACHMENT, b"a"),
            entry(QUERY_VALUE, &[0x00, b'b']),
        ];
        match &routed.body {
            crate::wire::RequestOwnedVariant::CodecZenohQuery(q) => {
                assert_eq!(
                    shape(q.extensions.entries().expect("a chain")),
                    shape(&query)
                )
            }
            _ => panic!("the routed Request carries the Query"),
        }

        let plain = crate::push_build::build_push_literal("k", b"v").expect("a literal put");
        assert!(
            as_routed(&decoded(plain.wire())).is_none(),
            "a message that repeats nothing is routed as it came"
        );
    }

    /// An extension of id 0xB, a z64 and not mandatory, which no network envelope, declaration or
    /// zenoh body declares, upstream or wz.
    const UNDECLARED: u8 = 0x2B;

    /// The one message `wire` holds, as the receive path holds it.
    fn one_message(wire: &[u8]) -> NetworkMessage {
        let mut messages = parse_frame_payload(wire).expect("the record decodes");
        assert_eq!(messages.len(), 1, "the wire is one message");
        messages.remove(0)
    }

    /// A router forwards exactly the extensions a message's kind declares
    /// (`super::as_routed`): on a Push, a Request, a Response, a Declare and its declaration and
    /// an Interest, an entry of an extension the envelope or the declaration does not declare is
    /// dropped and the declared one beside it is kept, as upstream's readers skip the one and
    /// read the other (`commons/zenoh-codec/src/network/push.rs` @
    /// `has_ext = extension::skip(reader, "Push", ext)?;`). An undeclared entry a zenoh body
    /// carries is kept, as upstream's body readers hold it. Each routed message encodes, decodes
    /// and is then routed as it came. Turned red by `routing_drops_at` keeping an undeclared
    /// entry on an envelope or a declaration, or dropping one on a zenoh body.
    #[test]
    fn a_routed_message_carries_only_the_extensions_its_kind_declares() {
        use super::as_routed;

        let mut push = crate::push_build::build_push_literal("k", b"v").expect("a literal put");
        push.extensions = Some(chain(alloc::vec![z64(UNDECLARED, 1), z64(QOS, 2)]));
        crate::ext_nodeid::sync_header_z(&mut push.header, true);
        match &mut push.body {
            crate::wire::PushOwnedVariant::CodecZenohMsgPut(p) => {
                crate::put_payload::set_chain(p, [z64(UNDECLARED, 3)])
                    .expect("one entry is within the bound")
            }
            _ => panic!("a literal put carries a Put"),
        }
        let Some(NetworkMessage::Push(routed)) = as_routed(&one_message(&push.wire())) else {
            panic!("a Push carrying an undeclared extension is routed as another Push");
        };
        let qos: [ExtEntryOwned<WireStorage>; 1] = [z64(QOS, 2)];
        assert_eq!(
            shape(routed.extensions.entries().expect("a chain")),
            shape(&qos),
            "push: the declared QoS alone"
        );
        let kept: [ExtEntryOwned<WireStorage>; 1] = [z64(UNDECLARED, 3)];
        match &routed.body {
            crate::wire::PushOwnedVariant::CodecZenohMsgPut(p) => assert_eq!(
                shape(crate::put_payload::chain(p)),
                shape(&kept),
                "push: the Put keeps the entry it does not declare"
            ),
            _ => panic!("the routed Push carries the Put"),
        }
        assert!(
            as_routed(&one_message(&routed.wire())).is_none(),
            "push: the routed message is routed as it came"
        );

        let mut request = crate::request_build::build_request_query(
            1,
            crate::wire_key::WireKey::literal("k").expect("a literal key"),
        )
        .expect("a query request");
        request.extensions = Some(chain(alloc::vec![z64(QOS, 2), z64(UNDECLARED, 1)]));
        crate::ext_nodeid::sync_header_z(&mut request.header, true);
        let Some(NetworkMessage::Request(routed)) = as_routed(&one_message(&request.wire())) else {
            panic!("a Request carrying an undeclared extension is routed as another Request");
        };
        assert_eq!(
            shape(routed.extensions.entries().expect("a chain")),
            shape(&qos),
            "request: the declared QoS alone"
        );
        assert!(
            as_routed(&one_message(&routed.wire())).is_none(),
            "request: the routed message is routed as it came"
        );

        let responder = [0x00, 0xAB, 0x07];
        let mut response = crate::response_build::build_response_err(
            1,
            crate::wire_key::WireKey::literal("k").expect("a literal key"),
            b"e",
        )
        .expect("an err response");
        response.extensions = Some(chain(alloc::vec![
            z64(UNDECLARED, 1),
            zbuf(RESPONDER, &responder),
        ]));
        crate::ext_nodeid::sync_header_z(&mut response.header, true);
        match &mut response.body {
            crate::wire::ResponseOwnedVariant::CodecZenohErr(err) => {
                err.extensions = Some(chain(alloc::vec![z64(UNDECLARED, 4)]));
                crate::ext_nodeid::sync_header_z(&mut err.header, true);
            }
            _ => panic!("an err response carries an Err"),
        }
        let Some(NetworkMessage::Response(routed)) = as_routed(&one_message(&response.wire()))
        else {
            panic!("a Response carrying an undeclared extension is routed as another Response");
        };
        let responder_alone: [ExtEntryOwned<WireStorage>; 1] = [zbuf(RESPONDER, &responder)];
        assert_eq!(
            shape(routed.extensions.entries().expect("a chain")),
            shape(&responder_alone),
            "response: the declared responder alone"
        );
        let err_kept: [ExtEntryOwned<WireStorage>; 1] = [z64(UNDECLARED, 4)];
        match &routed.body {
            crate::wire::ResponseOwnedVariant::CodecZenohErr(err) => assert_eq!(
                shape(err.extensions.entries().expect("a chain")),
                shape(&err_kept),
                "response: the Err keeps the entry it does not declare"
            ),
            _ => panic!("the routed Response carries the Err"),
        }
        assert!(
            as_routed(&one_message(&routed.wire())).is_none(),
            "response: the routed message is routed as it came"
        );

        let mut undeclare = crate::declare_build::build_undeclare_subscriber(1);
        undeclare.extensions = Some(chain(alloc::vec![z64(UNDECLARED, 1), z64(NODE_ID, 7)]));
        crate::ext_nodeid::sync_header_z(&mut undeclare.header, true);
        match &mut undeclare.body {
            wz_codecs::declare::DeclareOwnedVariant::CodecZenohUndeclSubscriber(d) => {
                d.extensions = Some(chain(alloc::vec![
                    crate::declare_ext_keyexpr::build_ext_keyexpr("k").expect("a literal keyexpr"),
                    z64(UNDECLARED, 2),
                ]));
                crate::ext_nodeid::sync_header_z(&mut d.header, true);
            }
            _ => panic!("an undeclaration carries its body"),
        }
        let Some(NetworkMessage::Declare(routed)) = as_routed(&one_message(&undeclare.wire()))
        else {
            panic!("a Declare carrying an undeclared extension is routed as another Declare");
        };
        let node_id: [ExtEntryOwned<WireStorage>; 1] = [z64(NODE_ID, 7)];
        assert_eq!(
            shape(routed.extensions.entries().expect("a chain")),
            shape(&node_id),
            "declare: the declared node id alone"
        );
        let wire_expr =
            [crate::declare_ext_keyexpr::build_ext_keyexpr("k").expect("a literal keyexpr")];
        match &routed.body {
            wz_codecs::declare::DeclareOwnedVariant::CodecZenohUndeclSubscriber(d) => {
                assert_eq!(
                    shape(d.extensions.entries().expect("a chain")),
                    shape(&wire_expr),
                    "declare: the undeclaration keeps its declared wire expression alone"
                )
            }
            _ => panic!("the routed Declare carries the undeclaration"),
        }
        assert!(
            as_routed(&one_message(&routed.wire())).is_none(),
            "declare: the routed message is routed as it came"
        );

        let mut interest = crate::interest_build::build_interest_final(1);
        interest.extensions = Some(chain(alloc::vec![z64(QOS, 2), z64(UNDECLARED, 1)]));
        crate::ext_nodeid::sync_header_z(&mut interest.header, true);
        let Some(NetworkMessage::Interest(routed)) = as_routed(&one_message(&interest.wire()))
        else {
            panic!("an Interest carrying an undeclared extension is routed as another Interest");
        };
        assert_eq!(
            shape(routed.extensions.entries().expect("a chain")),
            shape(&qos),
            "interest: the declared QoS alone"
        );
        assert!(
            as_routed(&one_message(&routed.wire())).is_none(),
            "interest: the routed message is routed as it came"
        );
    }

    /// The mesh hop limit is an extension wz declares on a Push, so a router routes it as a
    /// declared one: kept beside the declared QoS while the undeclared entry is dropped, and held
    /// once, as its last entry, when the chain repeats it. Turned red by `wz_declared` leaving the
    /// hop limit out, which hands the next node of a mesh a fresh budget.
    #[test]
    fn a_routed_push_keeps_the_mesh_hop_limit_wz_declares() {
        use crate::push_routing_context::{read_push_hoplimit, HOPLIMIT_EXT_HEADER};
        let mut push = crate::push_build::build_push_literal("k", b"v").expect("a literal put");
        push.extensions = Some(chain(alloc::vec![
            z64(HOPLIMIT_EXT_HEADER, 4),
            z64(UNDECLARED, 1),
            z64(QOS, 2),
            z64(HOPLIMIT_EXT_HEADER, 3),
        ]));
        crate::ext_nodeid::sync_header_z(&mut push.header, true);
        let Some(NetworkMessage::Push(routed)) = super::as_routed(&one_message(&push.wire()))
        else {
            panic!("a Push carrying an undeclared extension is routed as another Push");
        };
        let expected: [ExtEntryOwned<WireStorage>; 2] = [z64(QOS, 2), z64(HOPLIMIT_EXT_HEADER, 3)];
        assert_eq!(
            shape(routed.extensions.entries().expect("a chain")),
            shape(&expected),
            "the QoS and the last hop limit, the undeclared entry gone"
        );
        assert_eq!(read_push_hoplimit(&routed), Some(3));
    }

    /// A chain that carries only extensions its message does not declare is routed as no chain,
    /// and the message's extension flag says so: a declaration that declares none and an Interest
    /// each leave with no extension, encode, and decode with none. Turned red by
    /// `drop_for_routing` leaving the header's extension flag set over an emptied chain, or by
    /// `routing_drops_at` keeping the entry.
    #[test]
    fn a_chain_of_undeclared_extensions_alone_is_routed_as_no_chain() {
        use super::as_routed;
        use crate::ext_nodeid::MESSAGE_FLAG_Z;

        let mut subscriber = crate::declare_build::build_declare_subscriber(1, 0, Some("k"))
            .expect("a literal subscriber");
        match &mut subscriber.body {
            wz_codecs::declare::DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => {
                d.extensions = Some(chain(alloc::vec![z64(UNDECLARED, 2)]));
                crate::ext_nodeid::sync_header_z(&mut d.header, true);
            }
            _ => panic!("a subscriber declaration carries its body"),
        }
        let Some(NetworkMessage::Declare(routed)) = as_routed(&one_message(&subscriber.wire()))
        else {
            panic!("a declaration carrying an undeclared extension is routed as another Declare");
        };
        match &routed.body {
            wz_codecs::declare::DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => {
                assert!(
                    d.extensions.is_none(),
                    "the declaration leaves with no chain"
                );
                assert_eq!(d.header & MESSAGE_FLAG_Z, 0, "and says it carries none");
            }
            _ => panic!("the routed Declare carries the declaration"),
        }
        let NetworkMessage::Declare(again) = one_message(&routed.wire()) else {
            panic!("the routed Declare decodes as a Declare");
        };
        match &again.body {
            wz_codecs::declare::DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => {
                assert!(
                    d.extensions.is_none(),
                    "the declaration decodes with no chain"
                )
            }
            _ => panic!("the decoded Declare carries the declaration"),
        }

        let mut interest = crate::interest_build::build_interest_final(1);
        interest.extensions = Some(chain(alloc::vec![z64(UNDECLARED, 1)]));
        crate::ext_nodeid::sync_header_z(&mut interest.header, true);
        let Some(NetworkMessage::Interest(routed)) = as_routed(&one_message(&interest.wire()))
        else {
            panic!("an Interest carrying an undeclared extension is routed as another Interest");
        };
        assert!(
            routed.extensions.is_none(),
            "the Interest leaves with no chain"
        );
        assert_eq!(
            routed.header & MESSAGE_FLAG_Z,
            0,
            "and says it carries none"
        );
        let NetworkMessage::Interest(again) = one_message(&routed.wire()) else {
            panic!("the routed Interest decodes as an Interest");
        };
        assert!(
            again.extensions.is_none(),
            "the Interest decodes with no chain"
        );
    }

    /// A message whose only undeclared entry rides a zenoh body is routed as it came: the body
    /// keeps the entry, and nothing else is dropped. Turned red by `routing_drops_at` dropping an
    /// entry a zenoh body does not declare.
    #[test]
    fn an_undeclared_extension_on_a_zenoh_body_alone_is_routed_as_it_came() {
        let mut push = crate::push_build::build_push_literal("k", b"v").expect("a literal put");
        match &mut push.body {
            crate::wire::PushOwnedVariant::CodecZenohMsgPut(p) => {
                crate::put_payload::set_chain(p, [z64(UNDECLARED, 3)])
                    .expect("one entry is within the bound")
            }
            _ => panic!("a literal put carries a Put"),
        }
        assert!(
            super::as_routed(&one_message(&push.wire())).is_none(),
            "a Put's undeclared entry is forwarded as it came"
        );
    }
}
