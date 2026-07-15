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
    /// id 0x03), or `None`. Carried so `InboundReply::from_view` preserves the
    /// attachment for a `BorrowedReply` source too, not only for the wire
    /// `InboundReply` (the A8c session-review gap).
    ///
    /// R311y321 — SCOPE CORRECTION. This used to claim the attachment field made
    /// a synthesised `BorrowedReply` "a FULL `ReplyView`", i.e. `from_view`
    /// lossless. It never was: `BorrowedReply` has no `source_info` field
    /// either, so it rides `ReplyView`'s `None` default and `from_view` has
    /// silently dropped source_info from this source since R311y78. y321 widened
    /// the same hole with `timestamp`. The honest statement is per-field, and
    /// the two missing ones are named here rather than left for the next round
    /// to trip over: **`from_view` is lossless for `rid` / `keyexpr` / `kind` /
    /// `payload` / `err_encoding` / `attachment` / `put_encoding`, and LOSSY for
    /// `source_info` and `timestamp`.**
    ///
    /// Both absentees are `alloc`-gated types (`sample::SourceInfo`,
    /// `sample::TimestampHint`) while this struct is ungated, so adding them
    /// means `#[cfg]`-gated fields and a cfg at every construction site — which
    /// is why neither was added. Nothing consolidates a `BorrowedReply` today
    /// (its two production sites are `declare::liveliness_get`, which carries no
    /// side-bands and owns its own pending table, and the aligner's test
    /// module), so this is latent. It stops being latent the moment a
    /// `BorrowedReply` reaches a `ConsolidatingSink`: consolidation ORDERS BY
    /// timestamp, and every such reply would read as unstamped.
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
    /// R311y323 — the pending for `rid` EXPIRED: its deadline passed before a
    /// terminal `ResponseFinal` arrived. Fires instead of a bare
    /// [`on_final`](Self::on_final), exactly once, and the registry removes the
    /// entry afterwards.
    ///
    /// Why the seam needs a THIRD event rather than the sweep just calling
    /// `on_final`: zenoh does not close a timed-out query silently — it
    /// synthesizes an error reply so the caller can TELL a timeout from a peer's
    /// normal completion (`api/session.rs`, the z_get timeout task and its
    /// liveliness twin both call back `Err(ReplyError::new("Timeout",
    /// Encoding::ZENOH_STRING))`). Before y323 wz fired a bare `on_final` and a
    /// caller could not distinguish the two.
    ///
    /// The DEFAULT is the whole contract for a sink that holds no state:
    /// synthesize the error, then the final. It is correct as-written for every
    /// existing impl — the AP closure adapter, an MCU closed `enum`, the
    /// liveliness get registry's sinks — which is why this is a defaulted method
    /// and not a breaking addition.
    ///
    /// [`ConsolidatingSink`] overrides it because ORDER is observable: zenoh
    /// flushes a `Latest` cache BEFORE the timeout error (data first, then the
    /// reason the stream stopped). The default's `on_reply` -> `on_final`
    /// sequence would emit the error FIRST and the cached data after it, and a
    /// caller that treats an error as terminal would lose the data.
    fn on_timeout(&mut self, rid: u64) {
        self.on_reply(&timeout_reply(rid));
        self.on_final(rid);
    }
}

/// R311y323 — the synthetic `Err("Timeout")` reply a sweep delivers for an
/// expired pending. The wz form of zenoh's `Reply { result:
/// Err(ReplyError::new("Timeout", Encoding::ZENOH_STRING)) }`.
///
/// - `payload` = `Timeout`, the same ASCII bytes zenoh passes as the
///   `ReplyError` payload.
/// - `err_encoding` = `Some((2, None))`. zenoh's `Encoding::ZENOH_STRING` is
///   `{ id: 1, schema: None }` (api/encoding.rs) and pico agrees (`id 1`); wz's
///   wire form packs that as `id << 1 | schema_bit`, so no-schema `zenoh/string`
///   is `packed_id == 2`. The low bit is the schema flag per
///   [`crate::sample::EncodingHint::packed_id`].
/// - `keyexpr` = `""`. There is no key: zenoh's `ReplyError` carries NO keyexpr
///   field at all, and the registry could not supply one anyway — a `Pending`
///   holds `rid` / `remaining_finals` / `deadline_ms` / `sink` and never saw the
///   query's keyexpr. The empty literal is the honest encoding of "absent", not
///   a placeholder to be filled in later.
///
/// Ungated and no-alloc-safe (a `BorrowedReply` over `'static` literals), so the
/// MCU profile gets the same timeout signal as AP.
pub fn timeout_reply(rid: u64) -> BorrowedReply<'static> {
    BorrowedReply {
        rid,
        keyexpr: "",
        kind: ReplyKind::Err,
        payload: b"Timeout",
        err_encoding: Some((2, None)),
        attachment: None,
        put_encoding: None,
    }
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

    /// R311y323 — deliver and clear the `Latest` cache. The ONE place that
    /// decides a flush is due, shared by the normal-final path
    /// ([`ReplySink::on_final`]) and the timeout path
    /// ([`ReplySink::on_timeout`]) so they cannot drift apart on the `Latest`
    /// condition. A no-op in every other mode — `Monotonic` and `None` forward
    /// as they arrive and the cache (if any) is only a staleness record, never a
    /// delivery backlog.
    fn flush_latest(&mut self) {
        if self.mode == crate::query_mode::ConsolidationMode::Latest {
            for (_, reply) in self.cache.drain() {
                self.inner.on_reply(&reply);
            }
        }
    }
}

#[cfg(feature = "alloc")]
impl<S: ReplySink> ReplySink for ConsolidatingSink<S> {
    fn on_reply(&mut self, reply: &dyn ReplyView) {
        use crate::query_mode::ConsolidationMode;
        // An Err reply is NEVER consolidated — forwarded immediately, in every
        // mode, and never cached.
        //
        // This is zenoh's shape, and zenoh expresses it STRUCTURALLY rather than
        // as a rule: its consolidation match lives entirely inside
        // `send_response`'s `ResponseBody::Reply` arm, while `ResponseBody::Err`
        // is a DISJOINT arm that calls `callback.call(new_reply)` directly
        // (api/session.rs, the two arms of the payload match). It could not
        // consolidate an Err even if it wanted to: `Reply.result`'s `Err` variant
        // is a bare `ReplyError { payload, encoding }` with NO keyexpr, and the
        // consolidation arms key the cache on `result.unwrap().key_expr` — which
        // is unreachable for an Err by construction.
        //
        // wz cannot borrow that structure: `InboundReply` gives EVERY arm a
        // `keyexpr_literal` (the wire dispatcher resolves it before the body
        // match), so an Err arrives here fully cache-able and the type system
        // does not stop it. The guard has to be explicit.
        //
        // R311y321 review — the first cut of this method had no guard and
        // reasoned, wrongly, that an Err "ties with an unstamped Put and is
        // forwarded — matching zenoh, which runs every reply through the same
        // match". zenoh does not run every reply through the same match, and the
        // consequences were data loss on the default pico path in BOTH
        // directions: against a stamped Put the Err failed `displaces_cached` and
        // was silently swallowed; against an unstamped Put it won the tie and
        // EVICTED the good reply. The comment was the artifact that hid it — it
        // argued from the tie rule and never checked the upstream arm split.
        if reply.kind() == ReplyKind::Err {
            self.inner.on_reply(reply);
            return;
        }
        match self.mode {
            ConsolidationMode::None => self.inner.on_reply(reply),
            ConsolidationMode::Monotonic => {
                // zenoh's arm: cache AND forward when this is not stale; drop
                // outright when it is.
                if self.displaces_cached(reply) {
                    self.cache_reply(reply);
                    self.inner.on_reply(reply);
                }
            }
            ConsolidationMode::Latest => {
                // Cache only; the flush happens at the end, via `flush_latest` —
                // reached from `on_final` on the normal path and from
                // `on_timeout` on the expired one.
                //
                // R311y323 review — this said the timeout path was covered "for
                // free" because the sweep fired `on_final`. That was true when it
                // was written and is now the reasoning `on_timeout`'s override
                // exists to REFUTE: the sweep fires `on_timeout`, and taking the
                // free ride (the trait default's `on_reply` -> `on_final`) would
                // emit the Timeout error BEFORE the flush. zenoh flushes first.
                // A comment describing a bug as a convenience is how the y321 Err
                // bug shipped; see the override.
                if self.displaces_cached(reply) {
                    self.cache_reply(reply);
                }
            }
        }
    }

    /// R311y323 — zenoh's timeout ORDER, which the default `on_timeout` cannot
    /// produce: flush the `Latest` cache FIRST, then the synthetic
    /// `Err("Timeout")`, then the final.
    ///
    /// zenoh's timeout task does exactly this — remove the query, `if
    /// reception_mode == Latest` replay the cached replies, then call back the
    /// error (`api/session.rs`). Reaching it through the default would invert
    /// the first two: `on_reply(err)` forwards immediately (the Err guard), and
    /// only the following `on_final` drains — so the caller would see the
    /// timeout error and THEN the data it had already earned.
    ///
    /// The `Latest` check is not duplicated here; `flush_latest` owns it, so the
    /// normal-final path and this one cannot disagree about when a flush is due.
    fn on_timeout(&mut self, rid: u64) {
        self.flush_latest();
        self.inner.on_reply(&timeout_reply(rid));
        self.inner.on_final(rid);
    }

    fn on_final(&mut self, rid: u64) {
        // Drain BEFORE the inner final so the consumer sees every reply ahead of
        // the terminal signal — the ordering zenoh produces (it flushes, then
        // closes the query) and the one the Reply-before-Final contract already
        // requires everywhere else in this crate.
        self.flush_latest();
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

    /// R311y323 review — the DEFAULT `on_timeout` on the NO-ALLOC profile.
    ///
    /// `timeout_reply`'s doc justifies its design as "ungated and no-alloc-safe
    /// ... so the MCU profile gets the same timeout signal as AP", but y323's
    /// only default-`on_timeout` test lived in `consolidating_sink_tests`, which
    /// is `#[cfg(feature = "alloc")]` — so the profile the design claim is ABOUT
    /// had zero coverage of it. This module is the ungated one (its
    /// `CountingReplySink` exists precisely to run on both profiles), so the
    /// claim is tested where it is made.
    #[test]
    fn default_on_timeout_synthesizes_the_error_on_the_no_alloc_profile() {
        let mut sink = CountingReplySink::default();
        sink.on_timeout(11);
        assert_eq!(sink.replies, 1, "the default must synthesize one reply");
        assert_eq!(sink.last_kind, ReplyKind::Err);
        assert_eq!(sink.last_len, b"Timeout".len());
        assert_eq!(sink.last_rid, 11);
        assert_eq!(sink.finals, 1, "and then the final");
        assert_eq!(sink.last_final_rid, 11);
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

    fn err(keyexpr: &str, payload: &[u8]) -> InboundReply {
        InboundReply {
            rid: 1,
            keyexpr_literal: keyexpr.to_string(),
            body: InboundReplyBody::Err {
                encoding: None,
                payload: payload.to_vec(),
            },
        }
    }

    /// R311y321 review — an Err reply must NEVER be consolidated. zenoh handles
    /// Err in a DISJOINT arm of `send_response` that calls the callback directly;
    /// its consolidation match is unreachable for an Err by construction (an
    /// `Err` result has no keyexpr to key the cache on). wz gives every arm a
    /// keyexpr, so nothing stops an Err from entering the cache but an explicit
    /// guard.
    ///
    /// Without the guard this loses data in BOTH directions, on the DEFAULT pico
    /// path (AUTO -> LATEST): against a stamped Put the Err fails
    /// `displaces_cached` and vanishes; against an unstamped Put it wins the tie
    /// and evicts the good reply. The first cut of `on_reply` had no guard and no
    /// Err test — the absent test is why it shipped.
    #[test]
    fn err_is_never_consolidated_in_any_mode() {
        for mode in [
            ConsolidationMode::None,
            ConsolidationMode::Monotonic,
            ConsolidationMode::Latest,
        ] {
            // (a) a STAMPED Put already cached must not swallow the Err.
            let mut rec = Recorder::default();
            {
                let mut sink = ConsolidatingSink::new(mode, &mut rec);
                sink.on_reply(&put("a/b", b"data", Some(ts(10))));
                sink.on_reply(&err("a/b", b"boom"));
                sink.on_final(1);
            }
            let payloads: Vec<Vec<u8>> = rec.delivered.iter().map(|(_, p)| p.clone()).collect();
            assert!(
                payloads.contains(&b"boom".to_vec()),
                "{mode:?}: the Err was swallowed by a stamped cached Put"
            );
            assert!(
                payloads.contains(&b"data".to_vec()),
                "{mode:?}: the Put was lost"
            );

            // (b) an UNSTAMPED Put must not be evicted by the Err's tie.
            let mut rec = Recorder::default();
            {
                let mut sink = ConsolidatingSink::new(mode, &mut rec);
                sink.on_reply(&put("a/b", b"data", None));
                sink.on_reply(&err("a/b", b"boom"));
                sink.on_final(1);
            }
            let payloads: Vec<Vec<u8>> = rec.delivered.iter().map(|(_, p)| p.clone()).collect();
            assert!(
                payloads.contains(&b"boom".to_vec()),
                "{mode:?}: the Err was lost"
            );
            assert!(
                payloads.contains(&b"data".to_vec()),
                "{mode:?}: the Err EVICTED an unstamped Put"
            );
        }
    }

    /// The Err guard must not become a consolidation bypass for its keyexpr: two
    /// Errs on one key are BOTH forwarded (zenoh forwards each as it lands), and
    /// an Err must not poison the cache slot a later Put needs.
    #[test]
    fn err_neither_caches_nor_blocks_a_later_put() {
        let mut rec = Recorder::default();
        {
            let mut sink = ConsolidatingSink::new(ConsolidationMode::Latest, &mut rec);
            sink.on_reply(&err("a/b", b"e1"));
            sink.on_reply(&err("a/b", b"e2"));
            sink.on_reply(&put("a/b", b"data", Some(ts(10))));
            sink.on_final(1);
        }
        let payloads: Vec<Vec<u8>> = rec.delivered.iter().map(|(_, p)| p.clone()).collect();
        assert_eq!(
            payloads,
            alloc::vec![b"e1".to_vec(), b"e2".to_vec(), b"data".to_vec()],
            "both Errs forward immediately; the Put still consolidates and flushes"
        );
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

    /// R311y323 — the timeout ORDER, and it is the whole reason `on_timeout`
    /// exists as a seam method instead of the sweep calling `on_reply` then
    /// `on_final`. zenoh flushes the `Latest` cache and THEN synthesizes the
    /// error (data first, then the reason the stream stopped). The default
    /// `on_timeout` would invert it — the Err guard forwards immediately, and
    /// only the following `on_final` drains — so a caller that treats an error
    /// as terminal would lose data it had already earned.
    #[test]
    fn timeout_flushes_latest_before_the_error_then_finals() {
        let mut rec = Recorder::default();
        {
            let mut sink = ConsolidatingSink::new(ConsolidationMode::Latest, &mut rec);
            sink.on_reply(&put("a/b", b"old", Some(ts(10))));
            sink.on_reply(&put("a/b", b"new", Some(ts(20))));
            assert!(
                sink.inner.delivered.is_empty(),
                "Latest holds until the end"
            );
            sink.on_timeout(1);
        }
        assert_eq!(
            rec.delivered,
            alloc::vec![
                ("a/b".to_string(), b"new".to_vec()),
                (String::new(), b"Timeout".to_vec()),
            ],
            "the cached data must arrive BEFORE the Timeout error, not after"
        );
        assert_eq!(rec.finals, alloc::vec![1], "the final still fires, last");
    }

    /// A timed-out query must be DISTINGUISHABLE from a peer's normal
    /// completion. Before y323 both fired a bare `on_final` and a caller could
    /// not tell them apart — that was `query-timeout`'s booked residual.
    #[test]
    fn timeout_is_distinguishable_from_a_normal_final() {
        // normal completion: no synthetic reply, just the final
        let mut normal = Recorder::default();
        {
            let mut sink = ConsolidatingSink::new(ConsolidationMode::None, &mut normal);
            sink.on_final(7);
        }
        assert!(
            normal.delivered.is_empty(),
            "a normal final synthesizes nothing"
        );
        assert_eq!(normal.finals, alloc::vec![7]);

        // timeout: an Err("Timeout") precedes the final
        let mut timed = Recorder::default();
        {
            let mut sink = ConsolidatingSink::new(ConsolidationMode::None, &mut timed);
            sink.on_timeout(7);
        }
        assert_eq!(
            timed.delivered,
            alloc::vec![(String::new(), b"Timeout".to_vec())],
            "a timeout must announce itself"
        );
        assert_eq!(timed.finals, alloc::vec![7]);
    }

    /// R311y323 — the DEFAULT `on_timeout`, which is what the LIVELINESS get
    /// registry's sinks and every MCU closed-`enum` sink take.
    /// [`ConsolidatingSink`] OVERRIDES `on_timeout`, so every other test in this
    /// module exercises the override and proves NOTHING about the default.
    ///
    /// This test exists because falsification caught its absence: neutering the
    /// trait default to a bare `on_final` left all 12 other tests GREEN. The
    /// liveliness leg would have shipped with no timeout signal and no test
    /// would have said so — the same shape as the y321 Err bug, whose fixture
    /// set (`fn put`) never built the arm that broke.
    #[test]
    fn default_on_timeout_synthesizes_the_error_then_finals() {
        let mut rec = Recorder::default();
        {
            // A plain sink: no ConsolidatingSink wrapper, so this is the trait's
            // own default body.
            let mut plain = &mut rec;
            plain.on_timeout(9);
        }
        assert_eq!(
            rec.delivered,
            alloc::vec![(String::new(), b"Timeout".to_vec())],
            "the default must synthesize Err(Timeout) before the final"
        );
        assert_eq!(rec.finals, alloc::vec![9]);
    }

    /// The synthetic reply's SHAPE, pinned against zenoh's
    /// `ReplyError::new("Timeout", Encoding::ZENOH_STRING)`. The encoding is the
    /// half most likely to rot: zenoh's ZENOH_STRING is `{id: 1, schema: None}`
    /// and wz packs `id << 1 | schema_bit`, so no-schema is `packed_id == 2` —
    /// a bare `1` here would silently mean "id 0, schema follows".
    #[test]
    fn timeout_reply_matches_zenoh_replyerror_shape() {
        let r = timeout_reply(42);
        assert_eq!(r.rid(), 42);
        assert_eq!(r.kind(), ReplyKind::Err);
        assert_eq!(r.payload(), b"Timeout");
        assert_eq!(r.err_encoding(), Some((2, None)), "zenoh/string, no schema");
        assert_eq!(r.keyexpr(), "", "zenoh's ReplyError carries no keyexpr");
        assert_eq!(r.timestamp(), None);
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
