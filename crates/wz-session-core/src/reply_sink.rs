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
    /// R311y321 — the inline body timestamp (`MsgPut` / `MsgDel` T-flag
    /// `_Z_FLAG_Z_*_T`) a Put or Del reply carried, or `None` for Err, for a
    /// reply that carried none, or when `pubsub-timestamp` is off (the decode
    /// is gated on both the wire and loopback legs).
    ///
    /// What a `Latest` / `Monotonic` consolidating querier orders versions by.
    /// Without it consolidation is not undefined but SILENTLY LOSSY: an absent
    /// stamp reads as 0 and pico's `0 <= 0` comparison drops the sample.
    ///
    /// Default `None` so impls predating the seam stay valid. `alloc`-gated —
    /// [`crate::sample::TimestampHint`] lives in the `alloc`-gated `sample`
    /// module — exactly like [`Self::source_info`].
    #[cfg(feature = "alloc")]
    fn timestamp(&self) -> Option<&crate::sample::TimestampHint> {
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

/// R311y321 — is `new` at least as recent as `cached`, by the ordering zenoh
/// consolidates with?
///
/// zenoh compares `Option<uhlc::Timestamp>` with `>=` (api/session.rs, the
/// Monotonic + Auto/Latest arms). `uhlc::Timestamp` derives `Ord` over its
/// fields IN ORDER — `time: NTP64` then `id: ID` (uhlc timestamp.rs) — so the
/// rule is lexicographic `(time, zid)`, and `Option`'s own ordering puts `None`
/// BELOW every `Some`. Both halves matter: a stamped reply always beats an
/// unstamped one, and two replies stamped at the same instant by different
/// sources still have a deterministic winner rather than an arrival-order race.
///
/// NAMED DIVERGENCE — pico compares `msg->_commons._timestamp.time <=
/// pen_rep->_tstamp.time` (`vendor/zenoh-pico/src/session/query.c:145`): the
/// TIME WORD ONLY, and it drops on a tie, so pico keeps the FIRST arrival among
/// equal stamps while zenoh keeps the LAST. wz follows zenoh: its order is
/// total, so the delivered reply does not depend on which peer answered first.
/// The tie is also where "no timestamps at all" lands (both read as `None`),
/// which is why the choice is not academic — an unstamped keyexpr consolidates
/// to the LAST reply here and to the FIRST under pico.
#[cfg(feature = "alloc")]
fn reply_ts_at_least(
    new: Option<&crate::sample::TimestampHint>,
    cached: Option<&crate::sample::TimestampHint>,
) -> bool {
    match (new, cached) {
        // Option ordering: None < Some(_). An unstamped reply never displaces a
        // stamped one; two unstamped replies tie, and a tie keeps the newer.
        (None, None) => true,
        (None, Some(_)) => false,
        (Some(_), None) => true,
        (Some(n), Some(c)) => (n.time, n.zid.as_slice()) >= (c.time, c.zid.as_slice()),
    }
}

/// R311y321 — reception-side reply consolidation as a DECORATOR over any
/// [`ReplySink`], the apply-half of the `query-consolidation` atom.
///
/// Before y321 wz emitted the `Q_C` wire ext and applied NOTHING on receive, so
/// `with_consolidation(Latest)` was a no-op. That was a live break on the
/// zenoh-pico C API's DEFAULT path, not a corner case: `z_get_options_default`
/// sets `Z_CONSOLIDATION_MODE_AUTO` (`vendor/zenoh-pico/src/api/api.c:1725` ->
/// `:462` -> `:446`), and `wz-capi-pico`'s `get_options` resolves AUTO to LATEST
/// exactly as pico does and calls `with_consolidation(Latest)`. Every default
/// `z_get()` through wz therefore delivered every reply where pico delivers one
/// per keyexpr.
///
/// A DECORATOR rather than a `Pending` cache field: the registry's pending entry
/// stays byte-identical, so the no-alloc profile pays zero for a feature it
/// cannot compose (`ConsolidatingSink` is `alloc`-gated; an MCU build supplies
/// its own closed-`enum` sink and never sees this type). It rides the existing
/// DIP seam — the registry is generic over `C: ReplySink`, so wrapping is a type
/// substitution, not a new code path in the registry.
///
/// Mode semantics, each anchored by direct read of BOTH upstreams:
///
/// - **None** — forward every reply immediately; no cache. zenoh and pico agree
///   (`api/session.rs` `ConsolidationMode::None`; `query.c:179` fires whenever
///   the mode is not LATEST).
/// - **Monotonic** — forward a reply only when it is at least as recent as the
///   last one forwarded for its keyexpr; drop stale/out-of-order arrivals.
///   **This is zenoh's semantic and it DIVERGES from pico**, which computes the
///   same staleness check but then fires the callback regardless (`query.c:179`
///   gates on `!= LATEST`, so `drop` suppresses only pico's cache, never its
///   callback — pico's Monotonic is observably identical to None). wz honours
///   the mode: a Monotonic that cannot suppress anything is a mode in name only.
///   `wz-capi-pico` keeps the pico-faithful behaviour on the C ABI so a relinked
///   pico app does not change behaviour; that mapping names the gap at its own
///   seam.
/// - **Latest** — forward NOTHING during the query; keep the most recent reply
///   per keyexpr and flush the whole cache on the terminal final. zenoh and pico
///   agree on the shape (`api/session.rs:3025-3029` flushes at `nb_final == 0`;
///   `query.c:239-246` flushes at finalize); they differ only in the tie-break,
///   see [`reply_ts_at_least`].
///
/// The cache holds owned [`crate::reply::InboundReply`] values for BOTH caching
/// modes, matching zenoh (`query.replies` is allocated for every mode but None,
/// `api/session.rs:2295`, and its Monotonic arm inserts the full reply). pico
/// stores only the keyexpr + stamp under Monotonic — an MCU memory economy, not
/// a semantic difference, and moot here because this type is AP-only.
#[cfg(feature = "alloc")]
pub struct ConsolidatingSink<S: ReplySink> {
    inner: S,
    mode: crate::query_mode::ConsolidationMode,
    /// Most-recent reply per keyexpr. Empty for `None` (never populated), so a
    /// non-consolidating pending pays one empty `HashMap` — no allocation until
    /// the first insert.
    cache: hashbrown::HashMap<alloc::string::String, crate::reply::InboundReply>,
}

#[cfg(feature = "alloc")]
impl<S: ReplySink> ConsolidatingSink<S> {
    /// Wrap `inner` with `mode`. `ConsolidationMode::None` is a pure
    /// passthrough — the wrapper is installed on EVERY pending so the registry's
    /// `C` stays one type, and a non-consolidating z_get must therefore behave
    /// exactly as it did before this type existed.
    pub fn new(mode: crate::query_mode::ConsolidationMode, inner: S) -> Self {
        Self {
            inner,
            mode,
            cache: hashbrown::HashMap::new(),
        }
    }

    /// Wrap `inner` in passthrough mode — the constructor every non-z_get
    /// registration path uses (liveliness, the aligner's own plumbing), so their
    /// call sites keep their signatures and their behaviour.
    pub fn passthrough(inner: S) -> Self {
        Self::new(crate::query_mode::ConsolidationMode::None, inner)
    }

    /// Would `reply` displace what is cached for its keyexpr? `true` when
    /// nothing is cached yet, or when the arrival is at least as recent.
    fn displaces_cached(&self, reply: &dyn ReplyView) -> bool {
        match self.cache.get(reply.keyexpr()) {
            None => true,
            Some(cached) => reply_ts_at_least(reply.timestamp(), cached.timestamp()),
        }
    }

    fn cache_reply(&mut self, reply: &dyn ReplyView) {
        self.cache.insert(
            alloc::string::String::from(reply.keyexpr()),
            crate::reply::InboundReply::from_view(reply),
        );
    }
}

#[cfg(feature = "alloc")]
impl<S: ReplySink> ReplySink for ConsolidatingSink<S> {
    fn on_reply(&mut self, reply: &dyn ReplyView) {
        use crate::query_mode::ConsolidationMode;
        match self.mode {
            ConsolidationMode::None => self.inner.on_reply(reply),
            ConsolidationMode::Monotonic => {
                // zenoh's arm: cache AND forward when this is not stale; drop
                // outright when it is. An Err reply carries no keyexpr-versioned
                // body, but it still keys by keyexpr and stamps as `None`, so it
                // ties with an unstamped Put and is forwarded — matching zenoh,
                // which runs every reply through the same match.
                if self.displaces_cached(reply) {
                    self.cache_reply(reply);
                    self.inner.on_reply(reply);
                }
            }
            ConsolidationMode::Latest => {
                // Cache only. The flush happens in `on_final` — this is why a
                // Latest z_get that never receives its final delivers nothing,
                // exactly as zenoh (whose timeout path flushes explicitly).
                if self.displaces_cached(reply) {
                    self.cache_reply(reply);
                }
            }
        }
    }

    fn on_final(&mut self, rid: u64) {
        if self.mode == crate::query_mode::ConsolidationMode::Latest {
            // Drain BEFORE the inner final so the consumer sees every reply
            // ahead of the terminal signal — the ordering zenoh produces
            // (api/session.rs:3025-3029 flushes, then closes the query) and the
            // one the Reply-before-Final contract already requires everywhere
            // else in this crate.
            for (_, reply) in self.cache.drain() {
                self.inner.on_reply(&reply);
            }
        }
        self.inner.on_final(rid);
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

/// R311y321 — the `ConsolidatingSink` contract, mode by mode.
///
/// These build `InboundReply` values rather than `BorrowedReply` ones because
/// consolidation orders by TIMESTAMP and `BorrowedReply` has no timestamp field
/// (it rides the trait default `None`, as it already does for `source_info`), so
/// it cannot express the input this seam keys on. `InboundReply` is the owned
/// retention form the wire path produces, which is what a real pending sees.
#[cfg(test)]
#[cfg(feature = "alloc")]
mod consolidating_sink_tests {
    use super::*;
    use crate::query_mode::ConsolidationMode;
    use crate::reply::{InboundReply, InboundReplyBody};
    use crate::sample::TimestampHint;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;

    /// Records what actually reached the consumer, in order.
    #[derive(Default)]
    struct Recorder {
        delivered: Vec<(String, Vec<u8>)>,
        finals: Vec<u64>,
    }

    impl ReplySink for &mut Recorder {
        fn on_reply(&mut self, reply: &dyn ReplyView) {
            self.delivered
                .push((reply.keyexpr().to_string(), reply.payload().to_vec()));
        }
        fn on_final(&mut self, rid: u64) {
            self.finals.push(rid);
        }
    }

    fn ts(time: u64) -> TimestampHint {
        TimestampHint {
            time,
            zid: alloc::vec![0x01],
        }
    }

    fn put(keyexpr: &str, payload: &[u8], timestamp: Option<TimestampHint>) -> InboundReply {
        InboundReply {
            rid: 1,
            keyexpr_literal: keyexpr.to_string(),
            body: InboundReplyBody::Put {
                payload: payload.to_vec(),
                attachment: None,
                encoding: None,
                source_info: None,
                timestamp,
            },
        }
    }

    /// `None` is the pre-y321 behaviour and the wrapper is installed on EVERY
    /// pending, so this is the regression guard for every non-consolidating
    /// z_get in the tree: forward each reply immediately, in arrival order.
    #[test]
    fn none_forwards_every_reply_immediately() {
        let mut rec = Recorder::default();
        {
            let mut sink = ConsolidatingSink::new(ConsolidationMode::None, &mut rec);
            sink.on_reply(&put("a/b", b"v1", Some(ts(10))));
            sink.on_reply(&put("a/b", b"v2", Some(ts(20))));
            sink.on_final(1);
        }
        assert_eq!(
            rec.delivered,
            alloc::vec![
                ("a/b".to_string(), b"v1".to_vec()),
                ("a/b".to_string(), b"v2".to_vec())
            ],
            "None must not consolidate: both replies, in arrival order"
        );
        assert_eq!(rec.finals, alloc::vec![1]);
    }

    /// THE pico-AP break this whole increment exists to close. pico's
    /// `z_get_options_default` is AUTO, `wz-capi-pico` resolves that to LATEST,
    /// and before y321 wz delivered BOTH replies where pico delivers one.
    #[test]
    fn latest_delivers_one_per_keyexpr_and_only_at_final() {
        let mut rec = Recorder::default();
        {
            let mut sink = ConsolidatingSink::new(ConsolidationMode::Latest, &mut rec);
            sink.on_reply(&put("a/b", b"old", Some(ts(10))));
            sink.on_reply(&put("a/b", b"new", Some(ts(20))));
            assert!(
                sink.inner.delivered.is_empty(),
                "Latest delivers NOTHING before the final — it cannot know which is last"
            );
            sink.on_final(1);
        }
        assert_eq!(
            rec.delivered,
            alloc::vec![("a/b".to_string(), b"new".to_vec())],
            "one reply per keyexpr, the newest by timestamp"
        );
        assert_eq!(rec.finals, alloc::vec![1], "the final still fires, after");
    }

    /// Distinct keyexprs are distinct versions — consolidation is per-keyexpr,
    /// not per-query. A wildcard GET over N keys must still see N replies.
    #[test]
    fn latest_keeps_one_per_distinct_keyexpr() {
        let mut rec = Recorder::default();
        {
            let mut sink = ConsolidatingSink::new(ConsolidationMode::Latest, &mut rec);
            sink.on_reply(&put("a/1", b"x", Some(ts(10))));
            sink.on_reply(&put("a/2", b"y", Some(ts(10))));
            sink.on_final(1);
        }
        let mut got: Vec<String> = rec.delivered.iter().map(|(k, _)| k.clone()).collect();
        got.sort();
        assert_eq!(got, alloc::vec!["a/1".to_string(), "a/2".to_string()]);
    }

    /// An out-of-order arrival must not displace a newer cached version.
    #[test]
    fn latest_ignores_a_stale_out_of_order_arrival() {
        let mut rec = Recorder::default();
        {
            let mut sink = ConsolidatingSink::new(ConsolidationMode::Latest, &mut rec);
            sink.on_reply(&put("a/b", b"new", Some(ts(20))));
            sink.on_reply(&put("a/b", b"old", Some(ts(10))));
            sink.on_final(1);
        }
        assert_eq!(
            rec.delivered,
            alloc::vec![("a/b".to_string(), b"new".to_vec())],
            "the ts=10 arrival is stale and must not overwrite ts=20"
        );
    }

    /// Monotonic = zenoh's semantic (R311y321 owner decision): forward as they
    /// arrive, but SUPPRESS a stale one. NAMED DIVERGENCE from pico, whose
    /// Monotonic fires every reply (`query.c:179`) and is thus identical to
    /// None; `wz-capi-pico` keeps pico's behaviour on the C ABI.
    #[test]
    fn monotonic_forwards_immediately_and_suppresses_only_the_stale() {
        let mut rec = Recorder::default();
        {
            let mut sink = ConsolidatingSink::new(ConsolidationMode::Monotonic, &mut rec);
            sink.on_reply(&put("a/b", b"v1", Some(ts(10))));
            assert_eq!(
                sink.inner.delivered.len(),
                1,
                "Monotonic forwards immediately — it does not wait for the final"
            );
            sink.on_reply(&put("a/b", b"stale", Some(ts(5))));
            sink.on_reply(&put("a/b", b"v2", Some(ts(20))));
            sink.on_final(1);
        }
        assert_eq!(
            rec.delivered,
            alloc::vec![
                ("a/b".to_string(), b"v1".to_vec()),
                ("a/b".to_string(), b"v2".to_vec())
            ],
            "the ts=5 arrival is stale and must be dropped; v1 and v2 pass"
        );
    }

    /// The tie rule, which is where "no timestamps at all" lands: zenoh's `>=`
    /// keeps the LAST arrival, pico's `<=`-drop keeps the FIRST. wz follows
    /// zenoh — this test pins that divergence so it cannot drift silently.
    #[test]
    fn latest_unstamped_replies_tie_and_the_last_arrival_wins() {
        let mut rec = Recorder::default();
        {
            let mut sink = ConsolidatingSink::new(ConsolidationMode::Latest, &mut rec);
            sink.on_reply(&put("a/b", b"first", None));
            sink.on_reply(&put("a/b", b"second", None));
            sink.on_final(1);
        }
        assert_eq!(
            rec.delivered,
            alloc::vec![("a/b".to_string(), b"second".to_vec())],
            "zenoh's >= keeps the last arrival on a tie; pico would keep `first`"
        );
    }

    /// A stamped reply always beats an unstamped one, in both directions —
    /// `Option`'s `None < Some` ordering, which zenoh gets for free by comparing
    /// `Option<Timestamp>` and wz reproduces in `reply_ts_at_least`.
    #[test]
    fn stamped_beats_unstamped_regardless_of_arrival_order() {
        for (first, second, want) in [
            (
                (b"un".as_slice(), None),
                (b"st".as_slice(), Some(ts(1))),
                "st",
            ),
            (
                (b"st".as_slice(), Some(ts(1))),
                (b"un".as_slice(), None),
                "st",
            ),
        ] {
            let mut rec = Recorder::default();
            {
                let mut sink = ConsolidatingSink::new(ConsolidationMode::Latest, &mut rec);
                sink.on_reply(&put("a/b", first.0, first.1));
                sink.on_reply(&put("a/b", second.0, second.1));
                sink.on_final(1);
            }
            assert_eq!(
                rec.delivered,
                alloc::vec![("a/b".to_string(), want.as_bytes().to_vec())],
                "the stamped reply must win"
            );
        }
    }
}
