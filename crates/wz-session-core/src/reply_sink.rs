// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Reply-delivery seam (`ReplyView` accessor contract + `ReplySink`
//! trait + the `alloc`-only `BoxedReplySink` closure adapter) for the
//! application-layer reply registry (the z_get requester side).
//!
//! Model B (statechart-event) callback architecture, the response-plane
//! sibling of the data-plane [`crate::sink`] seam: the reply registry
//! routes each inbound `Response(Reply|Err)` (and the terminal
//! `ResponseFinal`) for a pending z_get through a Dependency-Inversion
//! seam rather than a hard-coded `Box<dyn FnMut(&InboundReply)>` +
//! `Box<dyn FnMut(u64)>` pair, so one registry implementation backs both
//! profiles (ARCHITECTURE.md §2.4 static-first, dynamic-opt-in):
//!
//! - **AP / `alloc` on** — [`BoxedReplySink`] wraps the `on_reply` +
//!   `on_final` heap closures; the registry stores a homogeneous
//!   `BoxedReplySink` per pending, type-erasing arbitrary capturing
//!   closures via the heap (the dynamic-opt-in side).
//! - **MCU / `alloc` off** — the consumer (a hand-written app, or the
//!   SCE-Mesh / wz-standalone switchboard generator) supplies a closed
//!   `enum` whose variants route to codegen'd Worker producers /
//!   statechart ingress; each variant impls [`ReplySink`] with no heap.
//!   wz ships only the trait + the AP adapter; the no-heap sink is the
//!   consumer's (generated or hand-written) type.
//!
//! **Delivery currency = [`ReplyView`], an accessor *contract*, not a
//! data type** — the same shape as [`crate::sink::SampleView`]. The owned
//! [`crate::reply::InboundReply`] (AP retention form) `impl`s `ReplyView`,
//! so the registry trait depends on one read contract (DIP + ISP) rather
//! than re-projecting into a third reply struct. [`on_reply`] takes
//! `&dyn ReplyView` — a borrowed fat pointer, no heap and no copy — so
//! the dispatch site passes its native reply directly. The reply seam
//! carries no output contract (unlike the queryable [`crate::query_sink`]
//! seam's `ReplyOut`): `on_reply` only consumes, it emits nothing.
//!
//! `on_final` carries the bare `rid` (`u64`, `Copy`) — a scalar tag, no
//! view needed; it fires once when the matching `ResponseFinal` arrives
//! and the registry auto-removes the pending entry.

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

/// Put / Del / Err discriminant of an inbound reply body. The response-
/// plane analogue of [`crate::sample_kind::SampleKind`], extended with
/// the `Err` arm the `Response.Err` reply carries. `Copy`; the
/// payload-bearing owned form is [`crate::reply::InboundReplyBody`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReplyKind {
    /// Successful data reply (`MsgPut` inner body) — payload bytes valid.
    #[default]
    Put,
    /// Delete-keyexpr reply (`MsgDel` inner body) — no payload bytes.
    Del,
    /// Error reply (`Response.Err` arm) — payload is the error blob, and
    /// [`ReplyView::err_encoding`] may carry the encoding hint.
    Err,
}

/// Read-only accessor contract for an inbound reply handed to a
/// [`ReplySink`] via [`ReplySink::on_reply`]. This is the delivery
/// currency (passed as `&dyn ReplyView`); a contract rather than a new
/// data representation (see the [module docs](self)), so the owned
/// [`crate::reply::InboundReply`] and the loose [`BorrowedReply`] each
/// `impl` it instead of being re-projected into a third struct. Object-
/// safe; the impls return borrows tied to the source, so delivery stays
/// heap-free and copy-free.
///
/// `rid` / `keyexpr` / `kind` / `payload` are unconditional plain types.
/// `payload` is empty for a [`ReplyKind::Del`]. `err_encoding` is
/// meaningful only for [`ReplyKind::Err`] (it mirrors the wire
/// `Encoding { packed_id, schema }` minus the redundant `schema_len`) and
/// returns `None` for Put / Del.
pub trait ReplyView {
    /// Echo of the inbound `Response.request_id` — the rid the z_get
    /// caller used when registering.
    fn rid(&self) -> u64;
    /// Resolved keyexpr literal the reply is bound to.
    fn keyexpr(&self) -> &str;
    /// Put / Del / Err discriminant.
    fn kind(&self) -> ReplyKind;
    /// Payload bytes. Empty for a Del reply; the error blob for an Err.
    fn payload(&self) -> &[u8];
    /// Encoding hint carried by an Err reply (`packed_id` + optional
    /// `schema`), or `None` for Put / Del.
    fn err_encoding(&self) -> Option<(u32, Option<&str>)>;
    /// A8b — opaque attachment carried by a Put reply on its inner
    /// `MsgPut` body extension (push-body ext id 0x03 — the receive twin
    /// of the A8a emit seam), or `None` for Del / Err or a Put with no
    /// attachment. What a storage aligner reads its serialized
    /// `AlignmentReply` off an inbound reply. Default `None` so impls
    /// predating the attachment seam stay valid.
    fn attachment(&self) -> Option<&[u8]> {
        None
    }
    /// A8b — value encoding carried by a Put reply (`packed_id` + optional
    /// `schema`), or `None` for Del / Err or a Put with no encoding. The
    /// Put-arm twin of [`Self::err_encoding`]; what a querier reconstructs
    /// a stored value's encoding from (the aligner's
    /// `RetrievedValue.encoding`). Default `None`.
    fn put_encoding(&self) -> Option<(u32, Option<&str>)> {
        None
    }
    /// R311y78 — the source identity `(zid, eid, sn)` a Put reply carried on
    /// its inner-body source_info ext (id 0x01), or `None` for Del / Err or a
    /// Put with no source_info. The receive twin of the producer emit seam
    /// (R311y74-y76): what an `ext-pubsub-advanced-subscriber` re-keys /
    /// reorders a recovered (retransmitted) sample by — a recovery GET reply
    /// carries the original sample's identity so it lands in the right
    /// per-source stream. Default `None` so impls predating the seam stay
    /// valid. `alloc`-gated (the [`crate::sample::SourceInfo`] type lives in
    /// the `alloc`-gated `sample` module), mirroring [`crate::query_sink::QueryView::source_info`].
    #[cfg(feature = "alloc")]
    fn source_info(&self) -> Option<&crate::sample::SourceInfo> {
        None
    }
}

/// A [`ReplyView`] over loose borrowed fields — the canonical impl for a
/// reply not backed by an owned [`crate::reply::InboundReply`] (a local /
/// loopback synthesised reply, and the seam's own tests). One `ReplyView`
/// impl among several; not the delivery currency itself (that is
/// `&dyn ReplyView`).
pub struct BorrowedReply<'a> {
    /// Echo of the inbound request id.
    pub rid: u64,
    /// Resolved keyexpr literal.
    pub keyexpr: &'a str,
    /// Put / Del / Err discriminant.
    pub kind: ReplyKind,
    /// Payload bytes. Empty for a Del reply.
    pub payload: &'a [u8],
    /// Encoding hint for an Err reply, if any.
    pub err_encoding: Option<(u32, Option<&'a str>)>,
    /// A8b — attachment carried by a Put reply (the inner-MsgPut push-body ext
    /// id 0x03), or `None`. Carried so a synthesised [`BorrowedReply`] is a
    /// FULL [`ReplyView`] — i.e. `InboundReply::from_view` is lossless for a
    /// `BorrowedReply` source too, not only the wire `InboundReply` (the A8c
    /// session-review gap).
    pub attachment: Option<&'a [u8]>,
    /// A8b — value encoding carried by a Put reply (`packed_id` + schema), or
    /// `None`. The Put-arm twin of [`Self::err_encoding`].
    pub put_encoding: Option<(u32, Option<&'a str>)>,
}

impl ReplyView for BorrowedReply<'_> {
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
            .as_ref()
            .map(|(id, schema)| (*id, schema.as_deref()))
    }
    fn attachment(&self) -> Option<&[u8]> {
        self.attachment
    }
    fn put_encoding(&self) -> Option<(u32, Option<&str>)> {
        self.put_encoding
            .as_ref()
            .map(|(id, schema)| (*id, schema.as_deref()))
    }
}

/// Reply-delivery sink: the Dependency-Inversion seam a pending z_get
/// dispatches its inbound replies + terminal final through. See the
/// [module docs](self) for the AP ([`BoxedReplySink`]) vs MCU (consumer-
/// supplied closed `enum`) backing contract.
///
/// The two methods mirror the per-rid `(on_reply, on_final)` pairing the
/// registry stores: [`on_reply`](Self::on_reply) fires once per inbound
/// `Response(Reply|Err)` (many per pending, zenoh-pico "many Reply"
/// semantics); [`on_final`](Self::on_final) fires exactly once when the
/// matching `ResponseFinal` arrives, after which the registry auto-
/// removes the pending entry.
pub trait ReplySink {
    /// Deliver one inbound reply. The [`ReplyView`] is borrowed for the
    /// duration of the call only.
    fn on_reply(&mut self, reply: &dyn ReplyView);
    /// Signal the terminal `ResponseFinal` for `rid`. Fires once; the
    /// pending entry is removed by the registry afterwards.
    fn on_final(&mut self, rid: u64);
}

/// Heap reply-closure type backing [`BoxedReplySink`]. Factored to a
/// `type` per `clippy::type_complexity` — the nested `&dyn ReplyView`
/// trait object pushes the inline `Box<dyn FnMut(...)>` over the
/// complexity threshold.
#[cfg(feature = "alloc")]
type BoxedReplyFn = Box<dyn FnMut(&dyn ReplyView) + Send + 'static>;

/// Heap final-closure type backing [`BoxedReplySink`].
#[cfg(feature = "alloc")]
type BoxedFinalFn = Box<dyn FnMut(u64) + Send + 'static>;

/// AP / `alloc`-profile adapter: wraps the `on_reply` + `on_final`
/// capturing closures in heap `Box`es, type-erasing them so a registry
/// stores a homogeneous `BoxedReplySink` per pending (the dynamic-opt-in
/// side, ARCHITECTURE.md §2.4). No MCU counterpart — the no-heap profile
/// uses a consumer-supplied closed `enum` instead.
#[cfg(feature = "alloc")]
pub struct BoxedReplySink {
    reply_fn: BoxedReplyFn,
    final_fn: BoxedFinalFn,
}

#[cfg(feature = "alloc")]
impl BoxedReplySink {
    /// Wrap the `on_reply` + `on_final` capturing closures as a heap-
    /// stored sink. Mirrors the registry's `register(rid, on_reply,
    /// on_final)` pairing.
    pub fn new(
        on_reply: impl FnMut(&dyn ReplyView) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> Self {
        Self {
            reply_fn: Box::new(on_reply),
            final_fn: Box::new(on_final),
        }
    }
}

#[cfg(feature = "alloc")]
impl ReplySink for BoxedReplySink {
    fn on_reply(&mut self, reply: &dyn ReplyView) {
        (self.reply_fn)(reply)
    }
    fn on_final(&mut self, rid: u64) {
        (self.final_fn)(rid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A no-heap concrete reply sink: the shape an MCU consumer `enum`
    // variant takes. Reads the inbound reply through `ReplyView` and
    // counts terminal finals with no `Box`, so it compiles + runs on
    // both the `alloc` and no-`alloc` profiles.
    #[derive(Default)]
    struct CountingReplySink {
        replies: u32,
        finals: u32,
        last_rid: u64,
        last_kind: ReplyKind,
        last_len: usize,
        last_final_rid: u64,
    }

    impl ReplySink for CountingReplySink {
        fn on_reply(&mut self, reply: &dyn ReplyView) {
            self.replies += 1;
            self.last_rid = reply.rid();
            self.last_kind = reply.kind();
            self.last_len = reply.payload().len();
        }
        fn on_final(&mut self, rid: u64) {
            self.finals += 1;
            self.last_final_rid = rid;
        }
    }

    #[test]
    fn concrete_reply_sink_reads_through_view_and_counts_final() {
        let mut sink = CountingReplySink::default();
        sink.on_reply(&BorrowedReply {
            rid: 7,
            keyexpr: "robot/state",
            kind: ReplyKind::Put,
            payload: b"21.5",
            err_encoding: None,
            attachment: None,
            put_encoding: None,
        });
        sink.on_reply(&BorrowedReply {
            rid: 7,
            keyexpr: "robot/state",
            kind: ReplyKind::Del,
            payload: b"",
            err_encoding: None,
            attachment: None,
            put_encoding: None,
        });
        sink.on_final(7);

        assert_eq!(sink.replies, 2);
        assert_eq!(sink.finals, 1);
        assert_eq!(sink.last_rid, 7);
        assert_eq!(sink.last_kind, ReplyKind::Del);
        assert_eq!(sink.last_len, 0);
        assert_eq!(sink.last_final_rid, 7);
    }

    #[test]
    fn err_reply_view_surfaces_encoding_through_contract() {
        let view = BorrowedReply {
            rid: 3,
            keyexpr: "svc/q",
            kind: ReplyKind::Err,
            payload: b"boom",
            err_encoding: Some((4, Some("text/plain"))),
            attachment: None,
            put_encoding: None,
        };
        assert_eq!(view.kind(), ReplyKind::Err);
        assert_eq!(view.payload(), b"boom");
        assert_eq!(view.err_encoding(), Some((4, Some("text/plain"))));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn boxed_reply_sink_dispatches_to_captured_closures() {
        use std::string::{String, ToString};
        use std::sync::{Arc, Mutex};
        use std::vec::Vec;

        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let finals: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_cb = Arc::clone(&seen);
        let finals_cb = Arc::clone(&finals);

        let mut sink = BoxedReplySink::new(
            move |reply: &dyn ReplyView| {
                seen_cb.lock().unwrap().push(reply.keyexpr().to_string());
            },
            move |rid: u64| {
                finals_cb.lock().unwrap().push(rid);
            },
        );

        sink.on_reply(&BorrowedReply {
            rid: 1,
            keyexpr: "a/b",
            kind: ReplyKind::Put,
            payload: b"x",
            err_encoding: None,
            attachment: None,
            put_encoding: None,
        });
        sink.on_reply(&BorrowedReply {
            rid: 1,
            keyexpr: "c/d",
            kind: ReplyKind::Put,
            payload: b"y",
            err_encoding: None,
            attachment: None,
            put_encoding: None,
        });
        sink.on_final(1);

        let got = seen.lock().unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], "a/b");
        assert_eq!(got[1], "c/d");
        assert_eq!(*finals.lock().unwrap(), std::vec![1]);
    }
}
