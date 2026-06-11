// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Query-dispatch seam (`QueryView` inbound accessor contract +
//! `ReplyOut` outbound emit contract + `QuerySink` trait + the
//! `alloc`-only `BoxedQuerySink` closure adapter) for the
//! application-layer queryable registry.
//!
//! Model B (statechart-event) callback architecture, the
//! request/response sibling of the one-way data-plane [`crate::sink`]
//! seam: a queryable registry dispatches a matched inbound query
//! through a Dependency-Inversion seam rather than a hard-coded
//! `Box<dyn FnMut(..)>` over the wire-codec query types, so one registry
//! implementation backs both profiles (ARCHITECTURE.md §2.4 static-first,
//! dynamic-opt-in):
//!
//! - **AP / `alloc` on** — [`BoxedQuerySink`] wraps a heap closure; the
//!   registry stores a homogeneous `BoxedQuerySink`, type-erasing
//!   arbitrary capturing handlers via the heap (the dynamic-opt-in side).
//! - **MCU / `alloc` off** — the consumer (a hand-written app, or the
//!   SCE-Mesh / wz-standalone switchboard generator) supplies a closed
//!   `enum` whose variants route to codegen'd Worker producers /
//!   statechart `on_query` ingress; each variant impls [`QuerySink`] with
//!   no heap. wz ships only the traits + the AP adapter; the no-heap sink
//!   is the consumer's (generated or hand-written) type.
//!
//! **Two narrow contracts (DIP + ISP), not the wire-codec types.**
//! Unlike the data-plane sink, a queryable handler also *emits*: it reads
//! the inbound query through [`QueryView`] and writes zero or more
//! replies back through the injected [`ReplyOut`] output contract (the
//! §3-a "hard case" — the HAL-injection output side, §4.10 trampoline
//! precedent). Both are passed by borrowed trait object
//! (`&dyn QueryView`, `&mut dyn ReplyOut`) so dispatch stays heap-free
//! and copy-free and the handler depends on the two contracts rather
//! than on `wz_codecs::query::Query` / the alloc-bound
//! `crate::query::QueryResponder`. On the wire-dispatch path the reply
//! accumulator [`crate::query::QueryResponder`] `impl`s [`ReplyOut`]
//! directly and the dispatch builds a [`BorrowedQuery`] for the inbound
//! [`QueryView`], so no intermediate wrapper sits on the seam.

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

/// Read-only accessor contract for an inbound query handed to a
/// [`QuerySink`]. The query side of the delivery currency (passed as
/// `&dyn QueryView`); a contract rather than a new data representation,
/// so the dispatch's [`BorrowedQuery`] and any borrowed link-runtime
/// query each `impl` it instead of being re-projected into a third
/// struct (DIP + ISP).
///
/// All four accessors are unconditional plain types — every profile
/// reads the resolved keyexpr, the optional URL-style parameters, the
/// optional attachment blob, and the correlation request id. The returns
/// borrow from the dispatcher's per-callback stack frame; a handler that
/// retains the data past the call must copy it explicitly.
pub trait QueryView {
    /// Resolved keyexpr literal (peer DECLARE table lookup already
    /// applied). Always non-empty — an un-resolvable keyexpr drops the
    /// dispatch before the handler is reached.
    fn keyexpr(&self) -> &str;
    /// Raw parameters bytes (URL-style query string). `None` when the
    /// inbound query carries no parameters segment.
    fn parameters(&self) -> Option<&[u8]>;
    /// Attachment payload extracted from the Query ext-chain. `None` when
    /// no attachment ext is present.
    fn attachment(&self) -> Option<&[u8]>;
    /// Source-info record extracted from the Query ext-chain (querier
    /// identity: zid / eid / sn). `None` when no source-info ext is
    /// present or `query-source-info` is off. Default impl returns `None`
    /// so `QueryView` impls that predate this accessor stay valid.
    /// `alloc`-only (the `SourceInfo` type lives in the `alloc`-gated
    /// `sample` module); mirrors `SampleView`'s metadata accessors.
    #[cfg(feature = "alloc")]
    fn source_info(&self) -> Option<&crate::sample::SourceInfo> {
        None
    }
    /// Request id from the outer `Request.rid` envelope (correlation key
    /// for the matching reply chain).
    fn rid(&self) -> u64;
    /// R311li — `true` when the query originated in-process (the
    /// requester is this same session's `query` loopback branch), so a
    /// reply must route back into the local reply registry rather than
    /// onto the wire. Mirrors zenoh-pico's `_z_query_t._is_local`.
    /// Default `false` (wire origin) so `QueryView` impls that predate
    /// this accessor stay valid.
    fn is_local(&self) -> bool {
        false
    }
}

/// Outbound emit contract a [`QuerySink`] writes replies through. The
/// output half of the §3-a queryable seam, injected as `&mut dyn
/// ReplyOut` so the no-`alloc` MCU handler stays decoupled from the
/// alloc-bound `crate::query::QueryResponder`. Object-safe; the
/// concrete `crate::query::QueryResponder` (the reply accumulator)
/// `impl`s it on the wire-dispatch path.
///
/// The emit surface mirrors `QueryResponder`'s reply-staging methods.
/// `reply` / `reply_del` / `reply_err` accumulate per-call reply records;
/// `with_responder` / `clear_responder` set the responder identity
/// stamped onto every subsequent emit, and [`Self::responder`] reads it
/// back. [`Self::reply_err`] stays in the contract unconditionally
/// (signature stability); a build without the Err-reply feature lowers
/// the concrete impl to a no-op rather than dropping the method.
pub trait ReplyOut {
    /// Emit a Put-form data reply with the given payload bytes.
    fn reply(&mut self, payload: &[u8]);
    /// Emit a Del-form reply (the queryable signals deletion at the
    /// keyexpr).
    fn reply_del(&mut self);
    /// Emit an Err-form reply carrying an optional encoding id + schema.
    fn reply_err(&mut self, encoding_id: Option<u32>, schema: Option<&str>, payload: &[u8]);
    /// Attach a responder identity (`zid` + entity id) to every
    /// subsequent [`Self::reply`] / [`Self::reply_del`] /
    /// [`Self::reply_err`] call.
    fn with_responder(&mut self, zid: &[u8], eid: u32);
    /// Clear the responder identity set via [`Self::with_responder`].
    fn clear_responder(&mut self);
    /// Current responder identity (read-only view), or `None` when no
    /// identity is attached.
    fn responder(&self) -> Option<(&[u8], u32)>;
}

/// Query-dispatch sink: the Dependency-Inversion seam a queryable
/// registry dispatches matched inbound queries through. See the [module
/// docs](self) for the AP ([`BoxedQuerySink`]) vs MCU (consumer-supplied
/// closed `enum`) backing contract.
pub trait QuerySink {
    /// Handle one matched inbound query. Read the query through `query`
    /// and emit any replies through `out`; both are borrowed for the
    /// duration of the call only.
    fn handle(&mut self, query: &dyn QueryView, out: &mut dyn ReplyOut);
}

/// A [`QueryView`] over loose borrowed fields — the canonical impl for a
/// query not backed by an owned projection (a local / loopback
/// synthesised query, and the seam's own tests). One `QueryView` impl
/// among several; not the delivery currency itself (that is
/// `&dyn QueryView`).
pub struct BorrowedQuery<'a> {
    /// Resolved keyexpr literal.
    pub keyexpr: &'a str,
    /// Raw parameters bytes (URL-style query string), if any.
    pub parameters: Option<&'a [u8]>,
    /// Attachment payload, if any.
    pub attachment: Option<&'a [u8]>,
    /// Source-info record (querier identity), if any. Borrowed — the
    /// dispatcher decodes the ext once into a local that outlives the
    /// per-queryable fan and lends it, matching the other fields' borrow
    /// shape (no per-match clone). `alloc`-only — the `SourceInfo` type
    /// lives in the `alloc`-gated `sample` module.
    #[cfg(feature = "alloc")]
    pub source_info: Option<&'a crate::sample::SourceInfo>,
    /// Request id (correlation key).
    pub rid: u64,
    /// R311li — in-process loopback origin marker (see
    /// [`QueryView::is_local`]). `false` for wire dispatch.
    pub is_local: bool,
}

impl QueryView for BorrowedQuery<'_> {
    fn keyexpr(&self) -> &str {
        self.keyexpr
    }
    fn parameters(&self) -> Option<&[u8]> {
        self.parameters
    }
    fn attachment(&self) -> Option<&[u8]> {
        self.attachment
    }
    #[cfg(feature = "alloc")]
    fn source_info(&self) -> Option<&crate::sample::SourceInfo> {
        self.source_info
    }
    fn rid(&self) -> u64 {
        self.rid
    }
    fn is_local(&self) -> bool {
        self.is_local
    }
}

/// Heap handler type backing [`BoxedQuerySink`]. Factored to a `type` per
/// `clippy::type_complexity` — the two nested trait-object arguments push
/// the inline `Box<dyn FnMut(...)>` over the complexity threshold.
#[cfg(feature = "alloc")]
type BoxedQueryFn = Box<dyn FnMut(&dyn QueryView, &mut dyn ReplyOut) + Send + 'static>;

/// AP / `alloc`-profile adapter: wraps an arbitrary capturing handler in
/// a heap `Box`, type-erasing it so a registry stores a homogeneous
/// `BoxedQuerySink` list of differently-captured handlers (the
/// dynamic-opt-in side, ARCHITECTURE.md §2.4). No MCU counterpart — the
/// no-heap profile uses a consumer-supplied closed `enum` instead.
#[cfg(feature = "alloc")]
pub struct BoxedQuerySink {
    inner: BoxedQueryFn,
}

#[cfg(feature = "alloc")]
impl BoxedQuerySink {
    /// Wrap a capturing handler as a heap-stored query sink.
    pub fn new(handler: impl FnMut(&dyn QueryView, &mut dyn ReplyOut) + Send + 'static) -> Self {
        Self {
            inner: Box::new(handler),
        }
    }
}

#[cfg(feature = "alloc")]
impl QuerySink for BoxedQuerySink {
    fn handle(&mut self, query: &dyn QueryView, out: &mut dyn ReplyOut) {
        (self.inner)(query, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A no-heap concrete reply sink: the shape an MCU consumer takes for
    // the output side. Stores a fixed responder buffer so it impls the
    // full `ReplyOut` contract (including `responder()`) without a heap.
    #[derive(Default)]
    struct CountingReplyOut {
        replies: u32,
        dels: u32,
        errs: u32,
        last_len: usize,
        zid_buf: [u8; 16],
        zid_len: usize,
        eid: u32,
        responder_set: bool,
    }

    impl ReplyOut for CountingReplyOut {
        fn reply(&mut self, payload: &[u8]) {
            self.replies += 1;
            self.last_len = payload.len();
        }
        fn reply_del(&mut self) {
            self.dels += 1;
        }
        fn reply_err(&mut self, _encoding_id: Option<u32>, _schema: Option<&str>, payload: &[u8]) {
            self.errs += 1;
            self.last_len = payload.len();
        }
        fn with_responder(&mut self, zid: &[u8], eid: u32) {
            let n = zid.len().min(self.zid_buf.len());
            self.zid_buf[..n].copy_from_slice(&zid[..n]);
            self.zid_len = n;
            self.eid = eid;
            self.responder_set = true;
        }
        fn clear_responder(&mut self) {
            self.responder_set = false;
            self.zid_len = 0;
        }
        fn responder(&self) -> Option<(&[u8], u32)> {
            if self.responder_set {
                Some((&self.zid_buf[..self.zid_len], self.eid))
            } else {
                None
            }
        }
    }

    // A no-heap concrete query sink: the shape an MCU consumer `enum`
    // variant takes. Reads the inbound query through `QueryView` and
    // emits through `ReplyOut` with no `Box`, so it compiles + runs on
    // both the `alloc` and no-`alloc` profiles.
    #[derive(Default)]
    struct EchoQuerySink {
        calls: u32,
        last_key_len: usize,
        last_rid: u64,
        last_param_len: Option<usize>,
    }

    impl QuerySink for EchoQuerySink {
        fn handle(&mut self, query: &dyn QueryView, out: &mut dyn ReplyOut) {
            self.calls += 1;
            self.last_key_len = query.keyexpr().len();
            self.last_rid = query.rid();
            self.last_param_len = query.parameters().map(|p| p.len());
            out.reply(b"ok");
        }
    }

    #[test]
    fn concrete_query_sink_reads_view_and_emits_through_reply_out() {
        let mut sink = EchoQuerySink::default();
        let mut out = CountingReplyOut::default();
        sink.handle(
            &BorrowedQuery {
                keyexpr: "robot/**",
                parameters: Some(b"p=1"),
                attachment: None,
                source_info: None,
                rid: 42,
                is_local: false,
            },
            &mut out,
        );
        assert_eq!(sink.calls, 1);
        assert_eq!(sink.last_key_len, 8);
        assert_eq!(sink.last_rid, 42);
        assert_eq!(sink.last_param_len, Some(3));
        assert_eq!(out.replies, 1);
        assert_eq!(out.last_len, 2);
    }

    #[test]
    fn reply_out_contract_covers_del_err_and_responder_roundtrip() {
        let mut out = CountingReplyOut::default();
        assert_eq!(out.responder(), None);

        out.with_responder(b"node-7", 3);
        assert_eq!(out.responder(), Some((&b"node-7"[..], 3)));

        out.reply_del();
        out.reply_err(Some(1), Some("text/plain"), b"boom");
        assert_eq!(out.dels, 1);
        assert_eq!(out.errs, 1);
        assert_eq!(out.last_len, 4);

        out.clear_responder();
        assert_eq!(out.responder(), None);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn boxed_query_sink_dispatches_to_captured_handler() {
        use std::string::{String, ToString};
        use std::sync::{Arc, Mutex};
        use std::vec::Vec;

        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_cb = Arc::clone(&seen);
        let mut sink = BoxedQuerySink::new(move |q: &dyn QueryView, out: &mut dyn ReplyOut| {
            seen_cb.lock().unwrap().push(q.keyexpr().to_string());
            out.reply(b"r");
        });

        let mut out = CountingReplyOut::default();
        sink.handle(
            &BorrowedQuery {
                keyexpr: "a/b",
                parameters: None,
                attachment: None,
                source_info: None,
                rid: 1,
                is_local: false,
            },
            &mut out,
        );
        sink.handle(
            &BorrowedQuery {
                keyexpr: "c/d",
                parameters: Some(b"x=2"),
                attachment: Some(b"att"),
                source_info: None,
                rid: 2,
                is_local: false,
            },
            &mut out,
        );

        let got = seen.lock().unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], "a/b");
        assert_eq!(got[1], "c/d");
        assert_eq!(out.replies, 2);
    }
}
