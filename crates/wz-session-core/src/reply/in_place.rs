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
//! ([`resolve_wireexpr_view`]), the payload, the encodings and the attachment
//! are read where they lie, and every pending get on the reply's rid is handed
//! a [`ReplyView`] over those bytes ([`LentReply`]) through the same matcher
//! the owned path fires through ([`ReplyRegistry::fire_replies_for`]). A reply
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

use wz_codecs::response::{Response, ResponseVariant};
use wz_codecs::timestamp::Timestamp;

use super::ReplyRegistry;
use crate::reply_sink::{ReplyKind, ReplySink, ReplyView};
use crate::sample::SourceInfo;
#[cfg(feature = "alloc")]
use crate::sample::TimestampHint;
use crate::wireexpr_resolve::{resolve_wireexpr_view, KeyexprBuf, KeyexprPastBound, MappingSpaces};

/// The reply a Response read in place is delivered as: every field a range of
/// the frame or a value read off it, valid for the delivery call.
struct LentReply<'r> {
    rid: u64,
    keyexpr: &'r str,
    kind: ReplyKind,
    payload: &'r [u8],
    err_encoding: Option<(u32, Option<&'r str>)>,
    put_encoding: Option<(u32, Option<&'r str>)>,
    attachment: Option<&'r [u8]>,
    source_info: Option<SourceInfo>,
    timestamp: Option<&'r Timestamp<'r>>,
    // The owned hint a sink asks for by `timestamp`, built on the first ask: it owns a
    // heap field, so a build with no allocator reads the stamp as `timestamp_parts`.
    #[cfg(feature = "alloc")]
    timestamp_hint: OnceCell<TimestampHint>,
}

impl ReplyView for LentReply<'_> {
    fn rid(&self) -> u64 {
        self.rid
    }
    fn keyexpr(&self) -> &str {
        self.keyexpr
    }
    fn kind(&self) -> ReplyKind {
        self.kind
    }
    fn payload(&self) -> &[u8] {
        self.payload
    }
    fn err_encoding(&self) -> Option<(u32, Option<&str>)> {
        self.err_encoding
    }
    fn attachment(&self) -> Option<&[u8]> {
        self.attachment
    }
    fn put_encoding(&self) -> Option<(u32, Option<&str>)> {
        self.put_encoding
    }
    fn source_info(&self) -> Option<&SourceInfo> {
        self.source_info.as_ref()
    }
    #[cfg(feature = "alloc")]
    fn timestamp(&self) -> Option<&TimestampHint> {
        let ts = self.timestamp?;
        Some(
            self.timestamp_hint
                .get_or_init(|| TimestampHint::from_view(ts)),
        )
    }
    fn timestamp_parts(&self) -> Option<crate::reply_stage::TimestampParts<'_>> {
        self.timestamp.map(|ts| crate::reply_stage::TimestampParts {
            time: ts.time,
            zid: ts.zid,
        })
    }
    // `payload_shared` and `attachment_shared` keep their `None` defaults: the
    // bytes are the link's, lent for the call, and a sink that keeps them copies
    // them.
}

/// The body-level fields of a reply read in place, before the keyexpr is known:
/// what `dispatch_response`'s body match projects, on the lent form.
struct LentBody<'r> {
    kind: ReplyKind,
    payload: &'r [u8],
    err_encoding: Option<(u32, Option<&'r str>)>,
    put_encoding: Option<(u32, Option<&'r str>)>,
    attachment: Option<&'r [u8]>,
    source_info: Option<SourceInfo>,
    timestamp: Option<&'r Timestamp<'r>>,
}

/// Why a Response read in place is delivered through its owned projection
/// instead.
enum Fallback {
    /// A Put reply whose payload is a list of slices.
    #[cfg(any(feature = "pubsub-put", feature = "query-reply"))]
    Sliced,
    /// Its keyexpr does not fit the bounded buffer.
    KeyexprPastBound,
}

/// The source info of a reply body's chain, under the gate the owned path
/// reads it under (`reply-source-info`).
#[cfg(any(
    feature = "pubsub-put",
    feature = "pubsub-delete",
    feature = "query-reply"
))]
fn lent_source_info(exts: &[wz_codecs::ext_entry::ExtEntry<'_>]) -> Option<SourceInfo> {
    #[cfg(feature = "reply-source-info")]
    {
        crate::sample::extract_source_info(exts)
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

/// The attachment of a reply body's chain, under the gate the owned path reads
/// it under (`pubsub-attachment`), at that body's own id.
#[cfg(any(
    feature = "pubsub-put",
    feature = "pubsub-delete",
    feature = "query-reply"
))]
fn lent_attachment<'r>(
    exts: &'r [wz_codecs::ext_entry::ExtEntry<'r>],
    of: AttachmentOf,
) -> Option<&'r [u8]> {
    #[cfg(feature = "pubsub-attachment")]
    {
        let ext_id = match of {
            #[cfg(any(feature = "pubsub-put", feature = "query-reply"))]
            AttachmentOf::Put => crate::attachment::ATTACHMENT_EXT_ID_PUSH,
            #[cfg(any(feature = "pubsub-delete", feature = "query-reply"))]
            AttachmentOf::Del => crate::attachment::ATTACHMENT_EXT_ID_DEL,
        };
        crate::attachment::decode_attachment_ext(exts, ext_id)
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
fn lent_timestamp<'r>(ts: Option<&'r Timestamp<'r>>) -> Option<&'r Timestamp<'r>> {
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

/// The body of `response` as a lent reply delivers it, `Ok(None)` for a body
/// the owned path drops too (an unknown body tag, or a kind this build does not
/// deliver), and the fallback for a Put whose payload is sliced.
fn lent_body<'r>(response: &'r Response<'r>) -> Result<Option<LentBody<'r>>, Fallback> {
    match &response.body {
        ResponseVariant::CodecZenohReply(reply) => match &reply.body {
            #[cfg(any(feature = "pubsub-put", feature = "query-reply"))]
            wz_codecs::reply::ReplyVariant::CodecZenohMsgPut(put) => {
                if put.slices.is_some() {
                    return Err(Fallback::Sliced);
                }
                let exts: &[wz_codecs::ext_entry::ExtEntry<'r>] =
                    put.extensions.as_deref().unwrap_or(&[]);
                Ok(Some(LentBody {
                    kind: ReplyKind::Put,
                    // A Put with neither layout populated is an empty inline
                    // payload, as `put_payload::layout` reads it.
                    payload: put.payload.unwrap_or(&[]),
                    err_encoding: None,
                    #[cfg(feature = "pubsub-encoding")]
                    put_encoding: put.encoding.as_ref().map(|e| (e.packed_id, e.schema)),
                    #[cfg(not(feature = "pubsub-encoding"))]
                    put_encoding: None,
                    attachment: lent_attachment(exts, AttachmentOf::Put),
                    source_info: lent_source_info(exts),
                    timestamp: lent_timestamp(put.timestamp.as_ref()),
                }))
            }
            #[cfg(any(feature = "pubsub-delete", feature = "query-reply"))]
            wz_codecs::reply::ReplyVariant::CodecZenohMsgDel(del) => {
                let exts: &[wz_codecs::ext_entry::ExtEntry<'r>] =
                    del.extensions.as_deref().unwrap_or(&[]);
                Ok(Some(LentBody {
                    kind: ReplyKind::Del,
                    payload: &[],
                    err_encoding: None,
                    put_encoding: None,
                    attachment: lent_attachment(exts, AttachmentOf::Del),
                    source_info: lent_source_info(exts),
                    timestamp: lent_timestamp(del.timestamp.as_ref()),
                }))
            }
            // An unknown inner body tag, or a kind this build does not deliver:
            // dropped, as the owned path drops it.
            _ => Ok(None),
        },
        ResponseVariant::CodecZenohErr(err) => Ok(Some(LentBody {
            kind: ReplyKind::Err,
            payload: err.payload,
            err_encoding: err.encoding.as_ref().map(|e| (e.packed_id, e.schema)),
            put_encoding: None,
            attachment: None,
            source_info: None,
            timestamp: None,
        })),
        ResponseVariant::Default { .. } => Ok(None),
    }
}

impl<C: ReplySink, const N: usize> ReplyRegistry<C, N> {
    /// Deliver a Response the in-place receive path lent: the pending-get side
    /// of [`IterationEvent::InPlace`](crate::driver_loop::IterationEvent::InPlace).
    /// See the module docs for what it delivers and what it hands to the owned
    /// projection.
    pub(super) fn dispatch_response_in_place(
        &mut self,
        response: &Response<'_>,
        spaces: MappingSpaces<'_>,
    ) {
        match self.deliver_lent(response, spaces) {
            Ok(()) => {}
            #[cfg(all(
                feature = "alloc",
                any(feature = "pubsub-put", feature = "query-reply")
            ))]
            Err(Fallback::Sliced) => self.dispatch_owned_projection(response, spaces),
            #[cfg(feature = "alloc")]
            Err(Fallback::KeyexprPastBound) => self.dispatch_owned_projection(response, spaces),
            // With no allocator there is no owned projection to fall back on: a reply the
            // lent form cannot represent is dropped, and the pending get it answers
            // ends by its own timeout, as it does for a reply that never came.
            #[cfg(not(feature = "alloc"))]
            Err(_) => {
                let _ = spaces;
            }
        }
    }

    /// The lent delivery itself: nothing on the heap for a reply whose keyexpr
    /// fits, short of a timestamp hint a sink asks for.
    fn deliver_lent(
        &mut self,
        response: &Response<'_>,
        spaces: MappingSpaces<'_>,
    ) -> Result<(), Fallback> {
        let Some(body) = lent_body(response)? else {
            return Ok(());
        };
        let mut composed = KeyexprBuf::new();
        let keyexpr = match resolve_wireexpr_view(&response.keyexpr.body, spaces, &mut composed) {
            Ok(Some(keyexpr)) => keyexpr,
            // An id the space does not hold: dropped, as the owned path drops
            // it. A sliced Put never reaches here, so there are no shared-memory
            // slices to settle.
            Ok(None) => return Ok(()),
            Err(KeyexprPastBound) => return Err(Fallback::KeyexprPastBound),
        };
        let reply = LentReply {
            rid: response.request_id,
            keyexpr,
            kind: body.kind,
            payload: body.payload,
            err_encoding: body.err_encoding,
            put_encoding: body.put_encoding,
            attachment: body.attachment,
            source_info: body.source_info,
            timestamp: body.timestamp,
            #[cfg(feature = "alloc")]
            timestamp_hint: OnceCell::new(),
        };
        self.fire_replies_for(&reply);
        Ok(())
    }

    /// The fallback: the owned projection of `response`, delivered by the path
    /// the copying receive takes ([`Self::dispatch_response`]), so a reply the
    /// lent form cannot represent is delivered exactly as it always was. Heap
    /// profile only.
    #[cfg(feature = "alloc")]
    fn dispatch_owned_projection(&mut self, response: &Response<'_>, spaces: MappingSpaces<'_>) {
        // The wire profile is unbounded (`Heap`, or the AP's shared frame
        // ranges), so this projection cannot refuse a decoded Response. It
        // consumes its view; the clone is of the view, not of the bytes.
        if let Ok(owned) = response
            .clone()
            .try_into_owned_in::<crate::wire::WireStorage>()
        {
            self.dispatch_response(&owned, spaces);
        }
    }
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

    const RID: u64 = 9;

    /// Everything a sink can read through the view, as owned values.
    #[derive(Debug, Clone, PartialEq)]
    struct Seen {
        rid: u64,
        keyexpr: String,
        kind: ReplyKind,
        payload: Vec<u8>,
        err_encoding: Option<(u32, Option<String>)>,
        put_encoding: Option<(u32, Option<String>)>,
        attachment: Option<Vec<u8>>,
        source_info: Option<SourceInfo>,
        timestamp: Option<TimestampHint>,
    }

    fn seen(view: &dyn ReplyView) -> Seen {
        Seen {
            rid: view.rid(),
            keyexpr: String::from(view.keyexpr()),
            kind: view.kind(),
            payload: view.payload().to_vec(),
            err_encoding: view.err_encoding().map(|(id, s)| (id, s.map(String::from))),
            put_encoding: view.put_encoding().map(|(id, s)| (id, s.map(String::from))),
            attachment: view.attachment().map(<[u8]>::to_vec),
            source_info: view.source_info().cloned(),
            timestamp: view.timestamp().cloned(),
        }
    }

    type Registry = super::ReplyRegistry<
        crate::reply_sink::ConsolidatingSink<crate::reply_sink::BoxedReplySink>,
    >;

    fn recording() -> (Registry, Arc<Mutex<Vec<Seen>>>) {
        let mut registry = Registry::new();
        let log = Arc::new(Mutex::new(Vec::new()));
        let into = log.clone();
        registry.register(
            RID,
            1,
            None,
            crate::reply_acceptance::ReplyAcceptance::Any,
            move |view| into.lock().expect("not poisoned").push(seen(view)),
            |_| {},
        );
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
        let decoded = Response::decode(&mut SceCursor::new(&wire)).expect("the record decodes");
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

    #[test]
    fn every_reply_kind_is_delivered_lent_as_the_owned_path_delivers_it() {
        let info = SourceInfo::new(&[1, 2, 3, 4], 7, 11);
        let stamp = TimestampHint {
            time: 0x1234_5678,
            zid: alloc::vec![9, 8, 7],
        };
        let schema = EncodingHint {
            packed_id: 0x0B,
            schema: Some(String::from("text")),
        };
        let cases = [
            ResponseReplyBuilder::new(RID, 0, Some("demo/a"), b"plain")
                .build()
                .expect("build"),
            ResponseReplyBuilder::new(RID, 0, Some("demo/b"), b"full")
                .encoding(&schema)
                .timestamp(&stamp)
                .attachment(b"att")
                .source_info(&info)
                .build()
                .expect("build"),
            ResponseReplyBuilder::new(RID, 0, Some("demo/c"), b"")
                .reply_del()
                .attachment(b"del-att")
                .timestamp(&stamp)
                .source_info(&info)
                .build()
                .expect("build"),
            ResponseErrBuilder::new(RID, 0, Some("demo/d"), b"oops")
                .encoding(0x0D, Some("why"))
                .build()
                .expect("build"),
            // Through the peer's alias, with and without a suffix.
            ResponseReplyBuilder::new(RID, 5, None, b"mapped")
                .build()
                .expect("build"),
            ResponseReplyBuilder::new(RID, 5, Some("/more"), b"composed")
                .build()
                .expect("build"),
            // An id the peer never declared: nothing is delivered.
            ResponseReplyBuilder::new(RID, 77, None, b"lost")
                .build()
                .expect("build"),
            // Past the bounded buffer: the fixed backing falls back to the
            // owned projection, which delivers it.
            ResponseReplyBuilder::new(RID, 6, Some("/tail"), b"long")
                .build()
                .expect("build"),
        ];
        let mut delivered = 0;
        for (i, response) in cases.iter().enumerate() {
            let (owned, lent) = both(response);
            assert_eq!(lent, owned, "case {i}");
            delivered += owned.len();
        }
        assert_eq!(delivered, cases.len() - 1, "every case but the lost one");
    }
}
