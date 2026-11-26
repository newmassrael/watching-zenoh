// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ARCHITECTURE section 9.2 -- a Response delivered where its frame lies.
//!
//! The fixed-memory MCU profile's receive path (`drive::dispatch_datagram`,
//! `wz-runtime-coop`'s `rx-in-place`) decodes a Response record over the
//! datagram the link lends and hands it over as
//! [`IterationEvent::InPlace`](crate::driver_loop::IterationEvent::InPlace)
//! instead of projecting it into a boxed owned message. This module is the
//! pending-get side of that: the keyexpr is resolved without a `String`
//! ([`resolve_wireexpr_viewed_held`]), the payload, the encodings and the attachment
//! are read where they lie (the Response is read as its view, a few words and the
//! bytes its chains occupy, so the walk holds no kilobyte-sized record on the
//! stack), and every pending get on the reply's rid, or the one entry the rid names in a
//! table whose ids each name one ([`ReplyRegistry::reply_to_one`]), is handed
//! a [`ReplyView`] over those bytes ([`LentReply`]) through the same matcher
//! the owned path fires through (`ReplyRegistry::fire_replies_for`). A reply
//! sink's contract was already a view borrowed for the call, so no sink
//! changes; one that keeps the reply copies it
//! ([`InboundReply::from_view`](super::InboundReply::from_view)).
//!
//! What it delivers is what [`ReplyRegistry::dispatch_response`] delivers for
//! the owned projection of the same record, field for field: the keyexpr by the
//! same resolution rule, the kind, the payload, the two encodings, and under the
//! same features the attachment, the source info and the timestamp. The
//! timestamp hint owns a heap field (a zid vector), so it is built only when a
//! sink asks for it.
//!
//! Two replies are not represented lent and take the owned projection instead:
//! a Put whose payload is a list of slices (read through the shared-memory
//! un-swap, or dropped without it, on the owned path), and a reply whose resolved
//! keyexpr is longer than [`KeyexprBuf`], which only the fixed bounded backing
//! refuses. Each is still delivered, as the copying path delivers it.

#[cfg(feature = "alloc")]
use core::cell::OnceCell;

#[cfg(any(
    feature = "pubsub-put",
    feature = "pubsub-delete",
    feature = "query-reply"
))]
use wz_codecs::reply::ReplyViewVariant;
use wz_codecs::response::{ResponseView, ResponseViewVariant};
// The view's own timestamp and encoding: they hold their lists inline, where the lent record's
// (`wz_codecs::lent`) are sized for the deployment's node.
use wz_codecs::timestamp::Timestamp;

use super::{Reach, ReplyRegistry};
use crate::bounded::Storage;
use crate::driver_loop::OwedToProjection;
use crate::ext_view::walked;
#[cfg(any(
    feature = "pubsub-put",
    feature = "pubsub-delete",
    feature = "query-reply"
))]
use crate::ext_view::ExtEntryBytes;
use crate::reply_sink::{ReplyKind, ReplySink, ReplyView};
use crate::sample::SourceInfo;
#[cfg(feature = "alloc")]
use crate::sample::TimestampHint;
use crate::wireexpr_resolve::{
    resolve_wireexpr_viewed_held, KeyexprBuf, KeyexprPastBound, MappingSpaces,
};

/// The reply a Response read in place is delivered as: every field a range of
/// the frame or a value read off it, valid for the delivery call.
///
/// `'r` is the delivery's borrow of the decoded record; `'f` is the frame's, in
/// which the codec's lent timestamp is invariant.
pub struct LentReply<'r, 'f> {
    rid: crate::wire_id::RequestId,
    keyexpr: &'r str,
    /// The key of the session's key arena `keyexpr` is the whole text of, when it is one.
    held: Option<&'r crate::key_arena::KeyRef>,
    kind: ReplyKind,
    payload: &'r [u8],
    err_encoding: Option<(u32, Option<&'r [u8]>)>,
    put_encoding: Option<(u32, Option<&'r [u8]>)>,
    attachment: Option<&'r [u8]>,
    source_info: Option<SourceInfo>,
    timestamp: Option<&'r Timestamp<'f>>,
    // The node and the entity the Response names as its responder, and the quality of
    // service it was sent at, both read off the Response's own chain.
    responder: Option<(&'r [u8], u32)>,
    qos: Option<crate::sample::QosLevel>,
    // The owned hint a sink asks for by `timestamp`, built on the first ask; a build with no
    // allocator reads the stamp as `timestamp_parts`.
    #[cfg(feature = "alloc")]
    timestamp_hint: OnceCell<TimestampHint>,
}

impl ReplyView for LentReply<'_, '_> {
    fn rid(&self) -> crate::wire_id::RequestId {
        self.rid
    }
    fn keyexpr(&self) -> &str {
        self.keyexpr
    }
    fn keyexpr_held(&self) -> Option<&crate::key_arena::KeyRef> {
        self.held
    }
    fn kind(&self) -> ReplyKind {
        self.kind
    }
    fn payload(&self) -> &[u8] {
        self.payload
    }
    fn err_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
        self.err_encoding
    }
    fn attachment(&self) -> Option<&[u8]> {
        self.attachment
    }
    fn put_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
        self.put_encoding
    }
    fn source_info(&self) -> Option<&SourceInfo> {
        self.source_info.as_ref()
    }
    #[cfg(feature = "alloc")]
    fn timestamp(&self) -> Option<&TimestampHint> {
        let ts = self.timestamp?;
        // The codec holds the id within the sixteen bytes a zenoh id has, so every byte is kept.
        crate::once_built::get_or_build(&self.timestamp_hint, || TimestampHint {
            time: ts.time,
            zid: crate::sample::TimestampZid::new(ts.zid.into_inner()).unwrap_or_default(),
        })
    }
    fn timestamp_parts(&self) -> Option<crate::reply_stage::TimestampParts<'_>> {
        self.timestamp.map(|ts| crate::reply_stage::TimestampParts {
            time: ts.time,
            zid: ts.zid.into_inner(),
        })
    }
    fn responder(&self) -> Option<(&[u8], u32)> {
        self.responder
    }
    fn qos(&self) -> Option<crate::sample::QosLevel> {
        self.qos
    }
    // A Response is read in place only off a link, so it was routed to this node.
    #[cfg(feature = "pubsub-ts-stack")]
    fn routed(&self) -> bool {
        true
    }
    // `payload_shared` and `attachment_shared` keep their `None` defaults: the
    // bytes are the link's, lent for the call, and a sink that keeps them copies
    // them.
}

/// The body-level fields of a reply read in place, before the keyexpr is known:
/// what `dispatch_response`'s body match projects, on the lent form. The
/// lifetimes are [`LentReply`]'s.
struct LentBody<'r, 'f> {
    kind: ReplyKind,
    payload: &'r [u8],
    err_encoding: Option<(u32, Option<&'r [u8]>)>,
    put_encoding: Option<(u32, Option<&'r [u8]>)>,
    attachment: Option<&'r [u8]>,
    source_info: Option<SourceInfo>,
    timestamp: Option<&'r Timestamp<'f>>,
}

/// Why a Response read in place is delivered through its owned projection
/// instead.
enum Fallback {
    /// A Put reply whose payload is a list of slices.
    #[cfg(any(feature = "pubsub-put", feature = "query-reply"))]
    Sliced,
    /// Its keyexpr does not fit the bounded buffer.
    KeyexprPastBound,
    /// It carries a timestamp stack, which the delivering node adds to: the stack is an owned
    /// value the lent form has none of.
    #[cfg(feature = "pubsub-ts-stack")]
    Instrumented,
}

/// The source info of a reply body's chain, under the gate the owned path
/// reads it under (`reply-source-info`).
#[cfg(any(
    feature = "pubsub-put",
    feature = "pubsub-delete",
    feature = "query-reply"
))]
fn lent_source_info<'c, T: ExtEntryBytes<'c>>(
    exts: impl IntoIterator<Item = T>,
) -> Option<SourceInfo> {
    #[cfg(feature = "reply-source-info")]
    {
        crate::sample::extract_source_info_in(exts)
    }
    #[cfg(not(feature = "reply-source-info"))]
    {
        let _ = exts;
        None
    }
}

/// Which body an attachment is read off: each has its own extension id.
#[cfg(any(
    feature = "pubsub-put",
    feature = "pubsub-delete",
    feature = "query-reply"
))]
#[derive(Clone, Copy)]
enum AttachmentOf {
    #[cfg(any(feature = "pubsub-put", feature = "query-reply"))]
    Put,
    #[cfg(any(feature = "pubsub-delete", feature = "query-reply"))]
    Del,
}

#[cfg(any(
    feature = "pubsub-put",
    feature = "pubsub-delete",
    feature = "query-reply"
))]
impl AttachmentOf {
    /// The identity of the body's attachment extension.
    const fn eid(self) -> u8 {
        match self {
            #[cfg(any(feature = "pubsub-put", feature = "query-reply"))]
            Self::Put => crate::ext_header::body_eid::PUT_ATTACHMENT,
            #[cfg(any(feature = "pubsub-delete", feature = "query-reply"))]
            Self::Del => crate::ext_header::body_eid::DEL_ATTACHMENT,
        }
    }
}

/// The attachment and the source info of a reply body's chain, each under the gate the owned path
/// reads it under, both read in ONE walk of the chain: a chain read where its frame lies decodes
/// every entry again at every walk. A build that reads neither walks nothing.
#[cfg(any(
    feature = "pubsub-put",
    feature = "pubsub-delete",
    feature = "query-reply"
))]
fn lent_chain_fields<'c, T: ExtEntryBytes<'c>>(
    exts: impl IntoIterator<Item = T>,
    of: AttachmentOf,
) -> (Option<&'c [u8]>, Option<SourceInfo>) {
    let eids = [of.eid(), crate::ext_header::body_eid::SOURCE_INFO];
    let [attachment, source_info] = if cfg!(any(
        feature = "pubsub-attachment",
        feature = "reply-source-info"
    )) {
        crate::ext_view::last_of_each_in(exts, eids)
    } else {
        [None, None]
    };
    (
        lent_attachment(attachment, of),
        lent_source_info(source_info),
    )
}

/// The attachment of a reply body's chain, under the gate the owned path reads
/// it under (`pubsub-attachment`), at that body's own id.
#[cfg(any(
    feature = "pubsub-put",
    feature = "pubsub-delete",
    feature = "query-reply"
))]
fn lent_attachment<'c, T: ExtEntryBytes<'c>>(
    exts: impl IntoIterator<Item = T>,
    of: AttachmentOf,
) -> Option<&'c [u8]> {
    #[cfg(feature = "pubsub-attachment")]
    {
        let ext_id = match of {
            #[cfg(any(feature = "pubsub-put", feature = "query-reply"))]
            AttachmentOf::Put => crate::attachment::ATTACHMENT_EXT_ID_PUSH,
            #[cfg(any(feature = "pubsub-delete", feature = "query-reply"))]
            AttachmentOf::Del => crate::attachment::ATTACHMENT_EXT_ID_DEL,
        };
        crate::attachment::decode_attachment_ext_in(exts, ext_id)
    }
    #[cfg(not(feature = "pubsub-attachment"))]
    {
        let _ = (exts, of);
        None
    }
}

/// The inline timestamp of a reply body, under the gate the owned path reads it
/// under (`pubsub-timestamp`).
#[cfg(any(
    feature = "pubsub-put",
    feature = "pubsub-delete",
    feature = "query-reply"
))]
fn lent_timestamp<'r, 'f>(ts: Option<&'r Timestamp<'f>>) -> Option<&'r Timestamp<'f>> {
    #[cfg(feature = "pubsub-timestamp")]
    {
        ts
    }
    #[cfg(not(feature = "pubsub-timestamp"))]
    {
        let _ = ts;
        None
    }
}

/// An encoding read where its frame lies, as the id word and the schema bytes a lent reply
/// carries.
fn encoding_parts<'r>(encoding: &wz_codecs::encoding::Encoding<'r>) -> (u32, Option<&'r [u8]>) {
    (
        encoding.packed_id,
        encoding.schema.map(|schema| schema.into_inner()),
    )
}

/// The body of `response` as a lent reply delivers it, `Ok(None)` for a body
/// the owned path drops too (an unknown body tag, or a kind this build does not
/// deliver), and the fallback for a Put whose payload is sliced.
///
/// The Response is read as its view, and the body's chain is walked where it lies, once for the
/// attachment and the source info together, each read off the entry found as the held chain is
/// read: the bytes they hand out stay in the frame.
fn lent_body<'r, 'f>(response: &'r ResponseView<'f>) -> Result<Option<LentBody<'r, 'f>>, Fallback> {
    match &response.body {
        ResponseViewVariant::CodecZenohReply(reply) => match &reply.body {
            #[cfg(any(feature = "pubsub-put", feature = "query-reply"))]
            ReplyViewVariant::CodecZenohMsgPut(put) => {
                let wz_codecs::msg_put::MsgPutExtensionsHas0x12::NotHas0x12 { payload, .. } =
                    &put.extensions_has_0x12
                else {
                    return Err(Fallback::Sliced);
                };
                // The whole chain of an inline Put: it carries no shared-memory marker.
                let (attachment, source_info) = lent_chain_fields(
                    crate::ext_view::walked_from(
                        crate::put_payload::view_chain(put)
                            .map(|(rest, _)| sce_forge_runtime::codec::Entries::entries(rest)),
                    ),
                    AttachmentOf::Put,
                );
                Ok(Some(LentBody {
                    kind: ReplyKind::Put,
                    payload: payload.into_inner(),
                    err_encoding: None,
                    #[cfg(feature = "pubsub-encoding")]
                    put_encoding: put.encoding.as_ref().map(encoding_parts),
                    #[cfg(not(feature = "pubsub-encoding"))]
                    put_encoding: None,
                    attachment,
                    source_info,
                    timestamp: lent_timestamp(put.timestamp.as_ref()),
                }))
            }
            #[cfg(any(feature = "pubsub-delete", feature = "query-reply"))]
            ReplyViewVariant::CodecZenohMsgDel(del) => {
                let (attachment, source_info) =
                    lent_chain_fields(walked(del.extensions.as_ref()), AttachmentOf::Del);
                Ok(Some(LentBody {
                    kind: ReplyKind::Del,
                    payload: &[],
                    err_encoding: None,
                    put_encoding: None,
                    attachment,
                    source_info,
                    timestamp: lent_timestamp(del.timestamp.as_ref()),
                }))
            }
            // An unknown inner body tag, or a kind this build does not deliver:
            // dropped, as the owned path drops it.
            _ => Ok(None),
        },
        ResponseViewVariant::CodecZenohErr(err) => Ok(Some(LentBody {
            kind: ReplyKind::Err,
            payload: err.payload.into_inner(),
            err_encoding: err.encoding.as_ref().map(encoding_parts),
            put_encoding: None,
            attachment: None,
            source_info: None,
            timestamp: None,
        })),
        ResponseViewVariant::Default { .. } => Ok(None),
    }
}

impl<C: ReplySink, P: Storage> ReplyRegistry<C, P> {
    /// Deliver a Response the in-place receive path lent: the pending-get side
    /// of [`IterationEvent::InPlace`](crate::driver_loop::IterationEvent::InPlace).
    /// See the module docs for what it delivers and what it hands to the owned
    /// projection.
    pub(super) fn dispatch_response_in_place<PS: Storage, OS: Storage>(
        &mut self,
        response: &ResponseView<'_>,
        spaces: MappingSpaces<'_, PS, OS>,
        reach: Reach,
    ) {
        match self.deliver_lent(response, spaces, reach) {
            Ok(()) => {}
            #[cfg(all(
                feature = "alloc",
                not(feature = "rx-lent-only"),
                any(feature = "pubsub-put", feature = "query-reply")
            ))]
            Err(Fallback::Sliced) => self.dispatch_owned_projection(response, spaces, reach),
            #[cfg(all(feature = "alloc", not(feature = "rx-lent-only")))]
            Err(Fallback::KeyexprPastBound) => {
                self.dispatch_owned_projection(response, spaces, reach)
            }
            #[cfg(all(feature = "pubsub-ts-stack", not(feature = "rx-lent-only")))]
            Err(Fallback::Instrumented) => self.dispatch_owned_projection(response, spaces, reach),
            // With no allocator, or in a build that lends only (`rx-lent-only`), there is no
            // owned projection to fall back on: a reply the lent form cannot represent is
            // dropped, and the pending get it answers ends by its own timeout, as it does for a
            // reply that never came.
            #[cfg(any(not(feature = "alloc"), feature = "rx-lent-only"))]
            Err(_) => {
                let _ = (spaces, reach);
            }
        }
    }

    /// The lent delivery itself: nothing on the heap for a reply whose keyexpr
    /// fits, short of a timestamp hint a sink asks for.
    fn deliver_lent<PS: Storage, OS: Storage>(
        &mut self,
        response: &ResponseView<'_>,
        spaces: MappingSpaces<'_, PS, OS>,
        reach: Reach,
    ) -> Result<(), Fallback> {
        let mut room = ReplyRoom::default();
        if let Some(reply) = lent_reply(response, spaces, &mut room)? {
            self.fire_to(&reply, reach);
        }
        Ok(())
    }

    /// The fallback: the owned projection of `response`, delivered by the path
    /// the copying receive takes ([`Self::dispatch_response`]), so a reply the
    /// lent form cannot represent is delivered exactly as it always was. Heap
    /// profile only.
    #[cfg(all(feature = "alloc", not(feature = "rx-lent-only")))]
    fn dispatch_owned_projection<PS: Storage, OS: Storage>(
        &mut self,
        response: &ResponseView<'_>,
        spaces: MappingSpaces<'_, PS, OS>,
        reach: Reach,
    ) {
        if let Some(inbound) = self.project_response(response, spaces) {
            self.fire_to(&inbound, reach);
        }
    }

    /// The owned projection of `response`, which the lent form does not represent
    /// ([`OwedToProjection`]): the reply the copying receive delivers for it, owned, for a
    /// caller that hands it to the pending gets itself. `None` for one the projection drops, and
    /// for every one in a build that lends only (`rx-lent-only`).
    #[cfg(feature = "alloc")]
    pub fn project_response<PS: Storage, OS: Storage>(
        &mut self,
        response: &ResponseView<'_>,
        spaces: MappingSpaces<'_, PS, OS>,
    ) -> Option<super::InboundReply> {
        #[cfg(not(feature = "rx-lent-only"))]
        {
            // The wire profile is unbounded (`Heap`, or the AP's shared frame
            // ranges), so this projection cannot refuse a decoded Response. The
            // view is first filled into the codec's own record (the heap profile has the stack
            // for its kilobyte, and this is the path of a Response the lent form cannot hold), and
            // that record consumes itself into the owned one.
            let mut record = wz_codecs::lent::Response::default();
            response.into_builder(&mut record).ok()?;
            let owned = record
                .try_into_owned_in::<crate::wire::WireStorage>()
                .ok()?;
            self.inbound_reply(&owned, spaces, None)
        }
        #[cfg(feature = "rx-lent-only")]
        {
            let _ = (response, spaces);
            None
        }
    }
}

/// Where a lent reply's key is composed when it is not one text of the peer's tables: the
/// caller's, held for as long as it holds the reply ([`lend_response`]).
pub struct ReplyRoom {
    composed: KeyexprBuf,
}

impl Default for ReplyRoom {
    fn default() -> Self {
        Self {
            composed: KeyexprBuf::new(),
        }
    }
}

/// A Response the in-place receive path lent, read for a caller that hands its reply to the
/// pending gets itself ([`lend_response`]): the reply, over the frame, the peer's tables and the
/// caller's room; `None` for a Response the owned path drops too (an unknown body, a kind this
/// build does not deliver, a key no space holds) and, in a build with no owned projection to fall
/// back on, for one the lent form does not represent; [`OwedToProjection`] for one the lent form
/// does not represent, which its owned projection delivers (`ReplyRegistry::project_response`).
pub type LentResponse<'r, 'f> = Result<Option<LentReply<'r, 'f>>, OwedToProjection>;

/// Read `response` into the reply its pending gets are handed, over its frame, the peer's tables
/// `spaces` names and `room`, for a caller that hands it to them itself: what
/// [`ReplyRegistry::dispatch_borrowed`] is then handed is what the registry's own dispatch of the
/// same record hands its sinks, field for field.
pub fn lend_response<'r, 'f, PS: Storage, OS: Storage>(
    response: &'r ResponseView<'f>,
    spaces: MappingSpaces<'r, PS, OS>,
    room: &'r mut ReplyRoom,
) -> LentResponse<'r, 'f> {
    match lent_reply(response, spaces, room) {
        Ok(reply) => Ok(reply),
        #[cfg(all(feature = "alloc", not(feature = "rx-lent-only")))]
        Err(_) => Err(OwedToProjection),
        // No owned projection to fall back on: dropped, as the registry's own dispatch drops it.
        #[cfg(any(not(feature = "alloc"), feature = "rx-lent-only"))]
        Err(_) => Ok(None),
    }
}

/// `response` read into the reply its pending gets are handed, over its frame, the peer's tables
/// `spaces` names and `room`, where its key is composed when it is not one text of those
/// tables; `Ok(None)` for one the owned path drops too, and the fallback for one the lent form
/// does not represent.
fn lent_reply<'r, 'f, PS: Storage, OS: Storage>(
    response: &'r ResponseView<'f>,
    spaces: MappingSpaces<'r, PS, OS>,
    room: &'r mut ReplyRoom,
) -> Result<Option<LentReply<'r, 'f>>, Fallback> {
    let Some(body) = lent_body(response)? else {
        return Ok(None);
    };
    // The Response's own chain is walked where it lies, once for every field that reads it.
    use crate::ext_header::network_eid::{QOS, RESPONDER};
    #[cfg(feature = "pubsub-ts-stack")]
    let [responder, qos, stack] = crate::ext_view::last_of_each_in(
        walked(response.extensions.as_ref()),
        [
            RESPONDER,
            QOS,
            crate::ext_header::ext_eid(crate::ts_stack::TS_STACK_EXT_HEADER),
        ],
    );
    #[cfg(not(feature = "pubsub-ts-stack"))]
    let [responder, qos] =
        crate::ext_view::last_of_each_in(walked(response.extensions.as_ref()), [RESPONDER, QOS]);
    // A Response the nodes record on is delivered with a stack of its own to add to.
    #[cfg(feature = "pubsub-ts-stack")]
    if stack.is_some() {
        return Err(Fallback::Instrumented);
    }
    let (keyexpr, held) =
        match resolve_wireexpr_viewed_held(&response.keyexpr.body, spaces, &mut room.composed) {
            Ok(Some(resolved)) => resolved,
            // An error reply is not about a key: a node that expires a query it forwarded
            // (upstream's routing does) sends its `Timeout` with no key expression at all, and
            // the error is what the asker is waiting on. It is delivered with none, as the owned
            // path delivers it.
            Ok(None) if body.kind == crate::reply_sink::ReplyKind::Err => ("", None),
            // An id the space does not hold: dropped, as the owned path drops
            // it. A sliced Put never reaches here, so there are no shared-memory
            // slices to settle.
            Ok(None) => return Ok(None),
            Err(KeyexprPastBound) => return Err(Fallback::KeyexprPastBound),
        };
    Ok(Some(LentReply {
        rid: response.request_id,
        keyexpr,
        held,
        kind: body.kind,
        payload: body.payload,
        err_encoding: body.err_encoding,
        put_encoding: body.put_encoding,
        attachment: body.attachment,
        source_info: body.source_info,
        timestamp: body.timestamp,
        responder: super::response_responder(responder),
        qos: crate::sample::extract_qos_in(qos),
        #[cfg(feature = "alloc")]
        timestamp_hint: OnceCell::new(),
    }))
}

// The lent delivery against the owned one on the same wire record: every field
// a sink can read through `ReplyView` must be the same, for every body kind, a
// keyexpr through either id space, one routing cannot place, and one past the
// bounded buffer (the fallback). The allocation count of the path is the lwIP
// harness's (`wz-session-lwip/tests/rx_frame_allocations.rs`).
#[cfg(all(test, feature = "query-reply"))]
mod tests {
    use super::*;
    use crate::driver_loop::{InPlaceRecord, IterationEvent};
    use crate::network_message::{parse_frame_payload, NetworkMessage};
    use crate::response_build::{ResponseErrBuilder, ResponseReplyBuilder};
    use crate::sample::EncodingHint;
    use alloc::string::String;
    use alloc::vec::Vec;
    use hashbrown::HashMap;
    use sce_forge_runtime::codec::SceCursor;
    use std::sync::{Arc, Mutex};

    const RID: crate::wire_id::RequestId = 9;

    /// Everything a sink can read through the view, as owned values.
    #[derive(Debug, Clone, PartialEq)]
    struct Seen {
        rid: crate::wire_id::RequestId,
        keyexpr: String,
        kind: ReplyKind,
        payload: Vec<u8>,
        err_encoding: Option<(u32, Option<Vec<u8>>)>,
        put_encoding: Option<(u32, Option<Vec<u8>>)>,
        attachment: Option<Vec<u8>>,
        source_info: Option<SourceInfo>,
        timestamp: Option<TimestampHint>,
        responder: Option<(Vec<u8>, u32)>,
        qos: Option<crate::sample::QosLevel>,
        #[cfg(feature = "pubsub-ts-stack")]
        ts_stack: Option<crate::ts_stack::TsStack>,
        #[cfg(feature = "pubsub-ts-stack")]
        routed: bool,
    }

    fn seen(view: &dyn ReplyView) -> Seen {
        Seen {
            rid: view.rid(),
            keyexpr: String::from(view.keyexpr()),
            kind: view.kind(),
            payload: view.payload().to_vec(),
            err_encoding: view
                .err_encoding()
                .map(|(id, s)| (id, s.map(<[u8]>::to_vec))),
            put_encoding: view
                .put_encoding()
                .map(|(id, s)| (id, s.map(<[u8]>::to_vec))),
            attachment: view.attachment().map(<[u8]>::to_vec),
            source_info: view.source_info().cloned(),
            timestamp: view
                .timestamp_parts()
                .map(|stamp| TimestampHint::new(stamp.time, stamp.zid).unwrap()),
            responder: view.responder().map(|(zid, eid)| (zid.to_vec(), eid)),
            qos: view.qos(),
            #[cfg(feature = "pubsub-ts-stack")]
            ts_stack: view.ts_stack().cloned(),
            #[cfg(feature = "pubsub-ts-stack")]
            routed: view.routed(),
        }
    }

    type Registry = super::ReplyRegistry<
        crate::reply_sink::ConsolidatingSink<crate::reply_sink::BoxedReplySink>,
    >;

    fn recording() -> (Registry, Arc<Mutex<Vec<Seen>>>) {
        let mut registry = Registry::new();
        let log = Arc::new(Mutex::new(Vec::new()));
        let into = log.clone();
        registry
            .register(
                RID,
                1,
                None,
                crate::reply_acceptance::ReplyAcceptance::Any,
                move |view| into.lock().expect("not poisoned").push(seen(view)),
                |_| {},
            )
            .expect("no quota is stated on this table");
        (registry, log)
    }

    /// The peer's id space: one alias, and one whose expansion together with a
    /// suffix is past the bounded keyexpr buffer.
    fn peer() -> HashMap<u64, String> {
        let mut peer = HashMap::new();
        peer.insert(5, String::from("demo/mapped"));
        peer.insert(6, "x".repeat(crate::caps::MAX_KEYEXPR_BYTES));
        peer
    }

    /// What the owned path and the lent path deliver for the same wire record.
    fn both(response: &crate::wire::ResponseOwned) -> (Vec<Seen>, Vec<Seen>) {
        let wire = response
            .try_as_borrowed()
            .expect("a borrowed view")
            .encode_to_vec();
        let peer = peer();
        let (mut owned, owned_log) = recording();
        let messages = parse_frame_payload(&wire).expect("the record decodes");
        assert!(matches!(messages.as_slice(), [NetworkMessage::Response(_)]));
        owned.dispatch_messages(&messages, &peer);
        let (mut lent, lent_log) = recording();
        let decoded = ResponseView::decode(&mut SceCursor::new(&wire)).expect("the record decodes");
        lent.dispatch_iteration_event(
            IterationEvent::InPlace(InPlaceRecord::response_of_frame(
                &decoded,
                true,
                0,
                crate::qos::Priority::DEFAULT,
            )),
            &peer,
        );
        let owned_seen = owned_log.lock().expect("not poisoned").clone();
        let lent_seen = lent_log.lock().expect("not poisoned").clone();
        (owned_seen, lent_seen)
    }

    /// A reply read for a caller that hands it to the pending gets itself is what the registry's
    /// own dispatch hands them, field for field, through the same matcher; its key composed in the
    /// caller's room when it is a peer's id with a suffix; and a key no space holds reads nothing.
    #[test]
    fn a_reply_lent_to_its_caller_is_what_the_registry_hands_its_sinks() {
        let peer = peer();
        let mapped = ResponseReplyBuilder::new(
            RID,
            crate::wire_key::WireKey::from_parts(5, Some("/deeper")).expect("a key"),
            b"composed",
        )
        .build()
        .expect("build");
        let unknown = ResponseReplyBuilder::new(
            RID,
            crate::wire_key::WireKey::from_parts(77, None).expect("a key"),
            b"nowhere",
        )
        .build()
        .expect("build");
        let (owned, _) = both(&mapped);
        assert_eq!(owned.len(), 1, "CONTROL: the owned path delivers it");
        let wire = mapped
            .try_as_borrowed()
            .expect("a borrowed view")
            .encode_to_vec();
        let decoded = ResponseView::decode(&mut SceCursor::new(&wire)).expect("the record decodes");
        let mut room = ReplyRoom::default();
        let Ok(Some(reply)) = lend_response(&decoded, MappingSpaces::from(&peer), &mut room) else {
            panic!("a reply lent where it lies");
        };
        let (mut registry, log) = recording();
        assert_eq!(registry.dispatch_borrowed(&reply), 1);
        assert_eq!(*log.lock().expect("not poisoned"), owned);
        let wire = unknown
            .try_as_borrowed()
            .expect("a borrowed view")
            .encode_to_vec();
        let decoded = ResponseView::decode(&mut SceCursor::new(&wire)).expect("the record decodes");
        let mut room = ReplyRoom::default();
        assert!(matches!(
            lend_response(&decoded, MappingSpaces::from(&peer), &mut room),
            Ok(None)
        ));
    }

    /// A Response that carries a timestamp stack is delivered with it, as one routed to this node:
    /// the lent form has no stack of its own for the nodes to add to, so it takes the owned path,
    /// for a reply and for an error alike.
    #[cfg(feature = "pubsub-ts-stack")]
    #[test]
    fn an_instrumented_response_is_delivered_with_its_stack_on_both_paths() {
        use crate::ts_stack::{point, TsStack};

        let mut stack = TsStack::new(point::SEND | point::RECEIVE);
        stack.record(point::SEND, alloc::vec![5, 6], false);
        for response in [
            ResponseReplyBuilder::new(
                RID,
                crate::wire_key::WireKey::literal("demo/a").expect("a literal key"),
                b"v",
            )
            .ts_stack(&stack)
            .build()
            .expect("build"),
            ResponseErrBuilder::new(
                RID,
                crate::wire_key::WireKey::literal("demo/b").expect("a literal key"),
                b"oops",
            )
            .ts_stack(&stack)
            .qos(crate::sample::QosLevel::from_raw(0b0001_1010))
            .responder(&[0xCA, 0xFE], 3)
            .build()
            .expect("build"),
        ] {
            let (owned, lent) = both(&response);
            #[cfg(not(feature = "rx-lent-only"))]
            assert_eq!(lent, owned, "the lent path is the owned one");
            // A build that lends only refuses it where it lies.
            #[cfg(feature = "rx-lent-only")]
            assert!(lent.is_empty(), "refused where it lies: {lent:?}");
            assert_eq!(owned.len(), 1);
            assert_eq!(owned[0].ts_stack.as_ref(), Some(&stack));
            assert!(owned[0].routed, "it came in over a link");
        }
        // One that carries none is delivered with none, and as routed all the same.
        let plain = ResponseReplyBuilder::new(
            RID,
            crate::wire_key::WireKey::literal("demo/a").expect("a literal key"),
            b"v",
        )
        .build()
        .expect("build");
        let (owned, lent) = both(&plain);
        assert_eq!(lent, owned);
        assert_eq!(owned[0].ts_stack, None);
        assert!(owned[0].routed);
    }

    #[test]
    fn every_reply_kind_is_delivered_lent_as_the_owned_path_delivers_it() {
        let info = SourceInfo::new(&[1, 2, 3, 4], 7, 11);
        let stamp = TimestampHint::new(0x1234_5678, &[9, 8, 7]).unwrap();
        let schema = EncodingHint {
            packed_id: 0x0B,
            schema: Some(b"text".to_vec()),
        };
        let cases = [
            ResponseReplyBuilder::new(
                RID,
                crate::wire_key::WireKey::literal("demo/a").expect("a literal key"),
                b"plain",
            )
            .build()
            .expect("build"),
            ResponseReplyBuilder::new(
                RID,
                crate::wire_key::WireKey::literal("demo/b").expect("a literal key"),
                b"full",
            )
            .encoding(&schema)
            .timestamp(&stamp)
            .attachment(b"att")
            .source_info(&info)
            .build()
            .expect("build"),
            ResponseReplyBuilder::new(
                RID,
                crate::wire_key::WireKey::literal("demo/c").expect("a literal key"),
                b"",
            )
            .reply_del()
            .attachment(b"del-att")
            .timestamp(&stamp)
            .source_info(&info)
            .build()
            .expect("build"),
            ResponseErrBuilder::new(
                RID,
                crate::wire_key::WireKey::literal("demo/d").expect("a literal key"),
                b"oops",
            )
            .encoding(0x0D, Some(&b"why"[..]))
            .build()
            .expect("build"),
            // Through the peer's alias, with and without a suffix.
            ResponseReplyBuilder::new(
                RID,
                crate::wire_key::WireKey::from_parts(5, None).expect("a key"),
                b"mapped",
            )
            .build()
            .expect("build"),
            ResponseReplyBuilder::new(
                RID,
                crate::wire_key::WireKey::from_parts(5, Some("/more")).expect("a key"),
                b"composed",
            )
            .build()
            .expect("build"),
            // The envelope's own fields: who answered, and the QoS it was sent at, on a
            // reply, a delete and an error alike.
            ResponseReplyBuilder::new(
                RID,
                crate::wire_key::WireKey::literal("demo/e").expect("a literal key"),
                b"named",
            )
            .responder(&[0xCA, 0xFE, 0xBA, 0xBE], 300)
            .qos(crate::sample::QosLevel::from_raw(0b0001_1010))
            .build()
            .expect("build"),
            ResponseReplyBuilder::new(
                RID,
                crate::wire_key::WireKey::literal("demo/f").expect("a literal key"),
                b"",
            )
            .reply_del()
            .responder(&[0x11; 16], 1)
            .build()
            .expect("build"),
            ResponseErrBuilder::new(
                RID,
                crate::wire_key::WireKey::literal("demo/g").expect("a literal key"),
                b"nope",
            )
            .responder(&[0x22], u32::MAX)
            .qos(crate::sample::QosLevel::from_raw(0b0000_0011))
            .build()
            .expect("build"),
            // An error is not about a key, so it is delivered whether it names none (the
            // `Timeout` that upstream's routing sends for a query it forwarded) or one the peer
            // never declared.
            crate::response_build::build_response_err_empty(RID, b"Timeout").expect("build"),
            ResponseErrBuilder::new(
                RID,
                crate::wire_key::WireKey::from_parts(77, None).expect("a key"),
                b"unplaced",
            )
            .build()
            .expect("build"),
            // An id the peer never declared: nothing is delivered.
            ResponseReplyBuilder::new(
                RID,
                crate::wire_key::WireKey::from_parts(77, None).expect("a key"),
                b"lost",
            )
            .build()
            .expect("build"),
            // Past the bounded buffer: the fixed backing falls back to the
            // owned projection, which delivers it.
            ResponseReplyBuilder::new(
                RID,
                crate::wire_key::WireKey::from_parts(6, Some("/tail")).expect("a key"),
                b"long",
            )
            .build()
            .expect("build"),
        ];
        let mut delivered = 0;
        for (i, response) in cases.iter().enumerate() {
            let (owned, lent) = both(response);
            // A build that lends only refuses, where it lies, the last case on the fixed backing,
            // which cannot compose its key; it delivers every other case lent.
            let refused = cfg!(feature = "rx-lent-only")
                && crate::bounded::ENFORCES_CAPACITY
                && i == cases.len() - 1;
            if refused {
                assert!(lent.is_empty(), "case {i}: {lent:?}");
            } else {
                assert_eq!(lent, owned, "case {i}");
            }
            delivered += owned.len();
        }
        assert_eq!(delivered, cases.len() - 1, "every case but the lost one");
    }

    #[test]
    fn an_error_that_names_no_key_is_delivered_with_none_on_either_path() {
        let timeout =
            crate::response_build::build_response_err_empty(RID, b"Timeout").expect("build");
        let (owned, lent) = both(&timeout);
        for seen in [&owned, &lent] {
            assert_eq!(seen.len(), 1);
            assert_eq!(
                (
                    seen[0].kind,
                    seen[0].keyexpr.as_str(),
                    seen[0].payload.as_slice()
                ),
                (ReplyKind::Err, "", b"Timeout".as_slice())
            );
        }
    }

    #[test]
    fn a_reply_shows_who_answered_and_the_qos_it_was_sent_at_on_either_path() {
        let named = ResponseReplyBuilder::new(
            RID,
            crate::wire_key::WireKey::literal("demo/e").expect("a literal key"),
            b"named",
        )
        .responder(&[0xCA, 0xFE, 0xBA, 0xBE], 300)
        .qos(crate::sample::QosLevel::from_raw(0b0001_1010))
        .build()
        .expect("build");
        let (owned, lent) = both(&named);
        for seen in [&owned, &lent] {
            assert_eq!(
                seen[0].responder,
                Some((alloc::vec![0xCA, 0xFE, 0xBA, 0xBE], 300))
            );
            assert_eq!(
                seen[0].qos,
                Some(crate::sample::QosLevel::from_raw(0b0001_1010))
            );
        }
        // A Response that names neither shows neither.
        let bare = ResponseReplyBuilder::new(
            RID,
            crate::wire_key::WireKey::literal("demo/h").expect("a literal key"),
            b"bare",
        )
        .build()
        .expect("build");
        let (owned, lent) = both(&bare);
        for seen in [&owned, &lent] {
            assert_eq!((seen[0].responder.clone(), seen[0].qos), (None, None));
        }
    }

    /// A reply whose body's chain carries its attachment and its source info twice each, in a
    /// Response whose own chain carries the responder and the QoS twice each, is delivered lent
    /// with the last entry of each, as the owned path delivers it, each chain walked once. Turned
    /// red by a walk that keeps the first entry of an identity, or by an identity the one walk
    /// asks for that names another extension.
    #[cfg(all(feature = "pubsub-attachment", feature = "reply-source-info"))]
    #[test]
    fn a_replys_repeated_extensions_are_delivered_lent_by_their_last_entries() {
        use crate::ext_header::network_eid::{QOS, RESPONDER};
        use crate::wire::WireStorage;
        use sce_forge_runtime::codec::Bounded;
        use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
        use wz_codecs::ext_zbuf::{ExtZbufOwned, ExtZbufValueField};
        use wz_codecs::ext_zint::ExtZint;

        let zbuf = |header: u8, bytes: &[u8]| {
            let value = Bounded::new(bytes)
                .expect("a test value is within the protocol's bound")
                .store::<WireStorage, ExtZbufValueField>()
                .expect("the heap holds a test value");
            ExtEntryOwned::<WireStorage> {
                header,
                body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                    value_len: bytes.len() as u64,
                    value,
                }),
            }
        };
        let z64 = |header: u8, value: u64| ExtEntryOwned::<WireStorage> {
            header,
            body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint { value }),
        };
        let source_info = |n: u8| {
            crate::source_info_ext::encode_source_info_ext_entry::<WireStorage>(
                &[0xA0, n],
                u32::from(n),
                u32::from(n),
            )
            .expect("a two-byte zid is a zid")
        };
        let attachment = |bytes: &[u8]| {
            crate::attachment::encode_attachment_ext::<WireStorage>(
                crate::attachment::ATTACHMENT_EXT_ID_PUSH,
                bytes,
            )
            .expect("the heap holds it")
        };
        let mut response = ResponseReplyBuilder::new(
            RID,
            crate::wire_key::WireKey::literal("demo/repeated").expect("a literal key"),
            b"v",
        )
        .build()
        .expect("build");
        // The responder: the zid's length less one in the high nibble, the zid, the entity id.
        response.extensions = Some(
            crate::held_list::held(alloc::vec![
                zbuf(RESPONDER, &[0x10, 0xCA, 0xFE, 0x03]),
                z64(QOS, 5),
                zbuf(RESPONDER, &[0x00, 0xAB, 0x07]),
                z64(QOS, 2),
            ])
            .expect("a chain of four entries is within its bound"),
        );
        crate::ext_nodeid::sync_header_z(&mut response.header, true);
        match &mut response.body {
            crate::wire::ResponseOwnedVariant::CodecZenohReply(reply) => match &mut reply.body {
                wz_codecs::reply::ReplyOwnedVariant::CodecZenohMsgPut(put) => {
                    crate::put_payload::set_chain(
                        put,
                        [
                            source_info(1),
                            attachment(b"first"),
                            source_info(2),
                            attachment(b"last"),
                        ],
                    )
                    .expect("an inline Put holds a chain of four entries");
                }
                _ => panic!("a reply built with a payload carries a Put"),
            },
            _ => panic!("a reply response carries a Reply"),
        }
        let (owned, lent) = both(&response);
        assert_eq!(lent, owned, "the lent delivery is the owned one");
        let [seen] = lent.as_slice() else {
            panic!("one reply delivered: {lent:?}");
        };
        assert_eq!(seen.attachment.as_deref(), Some(&b"last"[..]));
        assert_eq!(seen.source_info, Some(SourceInfo::new(&[0xA0, 2], 2, 2)));
        assert_eq!(seen.responder, Some((alloc::vec![0xAB], 7)));
        assert_eq!(seen.qos, Some(crate::sample::QosLevel::from_raw(2)));
    }
}
