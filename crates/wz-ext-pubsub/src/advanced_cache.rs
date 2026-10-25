// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y69 — `ext-pubsub-advanced-cache` (§5.25): the publisher-side
//! sample ring + the answer a cache queryable gives to `_sn` / `_max` /
//! `_time` recovery and history selectors out of it.
//!
//! The wz mirror of zenoh-ext `advanced_cache.rs`: an advanced publisher
//! retains its last `max_samples` published samples in a FIFO ring and
//! exposes them through a queryable on `<key_expr>/@adv/pub/<zid>/...`. A
//! late-joining or gap-detecting subscriber recovers missed samples by
//! `get`-ing that queryable with an `_sn=START..END` (sequence-number
//! range) and/or `_max=N` selector; the cache replies the matching ring
//! samples (zenoh advanced_cache.rs:209-346).
//!
//! What is here is the ring and the answer, which no runtime owns. The queryable that carries
//! the answer to a peer is the host's (`AdvancedCache` of the tokio runtime on a runtime
//! session, the plane of a C session on its own key table), and so is the clock: the answer
//! reads "now" through a function the host gives it.
//!
//! ## Reply-side `source_info` (R311y75 seam + R311y76 cache emit)
//!
//! zenoh replies the cached `Sample` whole, so each reply carries the
//! original `SourceInfo` and a subscriber re-keys it by its sequence
//! number. wz now mirrors this: each [`CachedSample`] stores the full
//! [`SourceInfo`] (R311y76), and `answer_from_ring` replies it via
//! [`ReplyOut::reply_keyed_sourced`] (R311y75), which threads the
//! `(zid, eid, sn)` onto the inner Put-body source_info ext (id 0x01).
//! The wire EMISSION is gated `reply-source-info` at the codec: OFF (the
//! default for `ext-pubsub-advanced-cache` alone) the recovery reply is
//! source_info-free (pico-faithful), and the
//! `ext-pubsub-advanced-recovery` composition turns it on.
//!
//! ## `_time` time-range filter (R311y98)
//!
//! zenoh's cache applies a `_time` time-range filter in both query branches
//! (zenoh-ext advanced_cache.rs:264-272, :308-316): a sample is replied only
//! if its timestamp falls in the query's `_time` range. wz mirrors this —
//! `answer_from_ring` parses the `_time` selector ([`TimeRange::parse`])
//! and drops out-of-range samples. The "now" the relative `now(-age)` bounds
//! resolve against is the NTP64 word the host's clock function answers at query
//! time (the same wall-clock base the publisher stamps each cached sample with),
//! so the filter lives on the ANSWERER side and works for a publisher-only node
//! serving a remote history subscriber. Every form zenoh's grammar accepts is
//! resolved (`now(±d)`, an absolute RFC3339 bound, the `[t;duration]` form; see
//! [`crate::time_range`]); a value zenoh's parser rejects is no range at all, so
//! every sample replies, as upstream does.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use wz_session_core::qos::{CongestionControl, Priority};
use wz_session_core::query_sink::{QueryView, ReplyMeta, ReplyOut};
use wz_session_core::sample::{EncodingHint, QosLevel, SampleKind, SourceInfo, TimestampHint};

use crate::time_range::{ntp64_to_system_time, TimeRange};

/// One sample retained in the cache ring for recovery / history replies.
/// `source_info` carries the sample's `(zid, eid, sn)`; the `_sn` range
/// filter reads `sn` from it (`None` for a timestamp / no-sequencing
/// publisher, which an `_sn` query then never matches — only time/`_max`
/// queries do), and a recovery reply re-stamps the whole identity.
#[derive(Clone, Debug)]
pub struct CachedSample {
    /// The concrete keyexpr the sample was published under (each reply
    /// carries its own key, the `reply ⊆ query` contract).
    pub keyexpr: String,
    /// Put payload bytes.
    pub payload: Vec<u8>,
    /// The sample's source identity `(zid, eid, sn)`, or `None` under
    /// timestamp / no sequencing (a publisher that stamps no `SourceInfo`).
    /// The `_sn` range filter reads `sn` from it, and a recovery reply
    /// re-stamps it ([`ReplyOut::reply_keyed_sourced`]) so a subscriber
    /// re-keys / reorders the retransmitted sample — zenoh caches the whole
    /// `Sample` with its `SourceInfo`, so the cached source identity ==
    /// the wire's. The SSOT for the sample's source: the publisher builds
    /// ONE `SourceInfo` for both the wire publish and this cache entry.
    pub source_info: Option<SourceInfo>,
    /// The sample's timestamp (the publisher stamps every cached put), used
    /// to order replies and stamp them back ([`ReplyOut::reply_keyed_sourced`]).
    pub timestamp: TimestampHint,
    /// R311y561 — whether the retained sample was a PUT or a DELETE.
    ///
    /// zenoh caches the whole `Sample`, and a `Sample` carries its kind, so a
    /// cached Del replays as a Del. Before this field wz's ring was Put-only by
    /// construction and `AdvancedPublisher::delete` therefore skipped the cache
    /// entirely — replaying a Del as a Put would RESURRECT a deleted key on a
    /// recovering subscriber, which is strictly worse than losing the
    /// retraction. With the kind stored, `answer_from_ring` dispatches the
    /// reply arm ([`ReplyOut::reply_keyed_sourced`] vs
    /// [`ReplyOut::reply_keyed_del_sourced`]) and deletes are retained like any
    /// other sample.
    pub kind: SampleKind,
    /// R311y562 — the sample's value ENCODING, replayed on recovery.
    ///
    /// zenoh caches the whole `Sample`, and a `Sample` carries its encoding, so
    /// a recovered sample renders exactly as the live one did. Before this
    /// field the ring retained no encoding and `answer_from_ring` passed a
    /// hard-coded `None`, so every recovered sample arrived with the peer's
    /// DEFAULT encoding regardless of what was published — a silent content-type
    /// corruption on exactly the samples a subscriber could not compare against
    /// the original, because it never received the original.
    ///
    /// `None` is the honest absence (a publish that set no encoding), which is
    /// distinct from "we forgot to keep it" only because this field exists.
    pub encoding: Option<EncodingHint>,
    /// R311y562 — the sample's ATTACHMENT side-band, replayed on recovery.
    ///
    /// Put-only, like the wire (`_z_push_body_encode` gates `has_attachment` on
    /// `_is_put`, `vendor/zenoh-pico/src/protocol/codec/message.c:263`), so a
    /// cached Del carries `None` by construction rather than by accident. The
    /// same reasoning as [`Self::encoding`]: an application that puts its
    /// routing metadata in the attachment lost all of it on every recovered
    /// sample.
    pub attachment: Option<Vec<u8>>,
    /// Whatever the sample keeps alive for as long as the ring holds it — see
    /// [`Retained`].
    pub retained: Option<Retained>,
    /// R3063 -- the sample's payload when it is a buffer of shared memory, KEPT AS THE BUFFER.
    ///
    /// zenoh caches the whole `Sample`, and a `Sample` whose payload lies in shared memory
    /// holds a reference to that buffer, so the chunk stays allocated while the ring holds the
    /// sample and a recovery reply sends the descriptor again
    /// (`zenoh-ext/src/advanced_cache.rs` @ `SampleBuilder::from(sample.clone())` replies the
    /// cached sample as it is). A copy of the bytes would be a recovered sample the
    /// real library would have delivered as shared memory arriving as bytes, and a second copy of
    /// what the buffer exists to avoid copying. When this is `Some`, [`Self::payload`] is EMPTY
    /// and the bytes are read through [`Self::bytes`].
    #[cfg(feature = "transport-shm")]
    pub shared: Option<wz_session_core::extshm::ShmSendHandle>,
}

/// What a cached sample keeps alive, dropped when the sample leaves the ring.
///
/// zenoh-pico's cached sample holds a reference to the key it was published on
/// (`vendor/zenoh-pico/src/net/sample.c` @
/// `_Z_RETURN_IF_ERR(_z_declared_keyexpr_copy(&dst->keyexpr, key));`), so a key
/// the publisher declared stays declared until its last cached sample is
/// evicted or the cache is freed, and that is observable: the peer is told the
/// key is gone only then. The ring is runtime-neutral and knows nothing of a
/// declaration, so it holds the reference as an opaque owner and a host that has
/// something to keep passes it in through [`CachedSample::keeping`].
#[derive(Clone)]
pub struct Retained {
    /// Held for its drop alone, which is why it is never read.
    _owner: Arc<dyn Send + Sync>,
}

impl Retained {
    /// Keep `owner` alive.
    pub fn new(owner: Arc<dyn Send + Sync>) -> Self {
        Self { _owner: owner }
    }
}

impl std::fmt::Debug for Retained {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Retained")
    }
}

impl CachedSample {
    /// R311y562 — a cached sample carrying no value metadata.
    ///
    /// Exists so that adding a retained field is a change to THIS function
    /// rather than to every construction site. The two fields this round added
    /// (`encoding`, `attachment`) broke ten struct literals, all of them test
    /// fixtures that never cared about the new fields — which is the signal
    /// that spelling every field at every site was the wrong shape. Callers
    /// that DO care chain [`Self::with_encoding`] / [`Self::with_attachment`].
    pub fn new(
        keyexpr: impl Into<String>,
        payload: Vec<u8>,
        source_info: Option<SourceInfo>,
        timestamp: TimestampHint,
        kind: SampleKind,
    ) -> Self {
        Self {
            keyexpr: keyexpr.into(),
            payload,
            source_info,
            timestamp,
            kind,
            encoding: None,
            attachment: None,
            retained: None,
            #[cfg(feature = "transport-shm")]
            shared: None,
        }
    }

    /// R3063 -- keep the sample's payload as the buffer of shared memory it is (see
    /// [`Self::shared`]). The `payload` given to [`Self::new`] is then not kept: pass an empty
    /// vector there, and read the bytes through [`Self::bytes`].
    #[cfg(feature = "transport-shm")]
    pub fn with_shared(mut self, shared: Option<wz_session_core::extshm::ShmSendHandle>) -> Self {
        self.shared = shared;
        self
    }

    /// The sample's payload bytes: the buffer's when it is one, the vector's otherwise.
    pub fn bytes(&self) -> &[u8] {
        #[cfg(feature = "transport-shm")]
        if let Some(shared) = &self.shared {
            return shared.bytes();
        }
        &self.payload
    }

    /// Keep `owner` alive for as long as the ring holds this sample — see
    /// [`Retained`].
    pub fn keeping(mut self, owner: Option<Retained>) -> Self {
        self.retained = owner;
        self
    }

    /// Retain the sample's value encoding, replayed on recovery.
    pub fn with_encoding(mut self, encoding: Option<EncodingHint>) -> Self {
        self.encoding = encoding;
        self
    }

    /// Retain the sample's attachment side-band, replayed on recovery.
    /// Put-only on the wire; a Del keeps `None`.
    pub fn with_attachment(mut self, attachment: Option<Vec<u8>>) -> Self {
        self.attachment = attachment;
        self
    }
}

/// R2596 — the QoS a cache stamps on EVERY reply it makes, overriding the
/// query's own. wz's mirror of zenoh-ext's
/// `zenoh-ext/src/advanced_cache.rs` @ `pub struct RepliesConfig {`.
///
/// An override rather than an inheritance, and that is upstream's shape in all
/// three references: zenoh-ext applies `congestion_control` / `priority` /
/// `is_express` to every cache reply through a `SampleBuilder`, and zenoh-pico
/// stores the same three on the cache and sets `z_query_reply_options_t` from
/// them per reply (`vendor/zenoh-pico/src/collections/advanced_cache.c`). A
/// cache answers out of a bounded ring on its own terms; what the querier asked
/// for governs its OTHER replies, not these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepliesConfig {
    /// The band cache replies ride.
    pub priority: Priority,
    /// What a congested link does with one.
    pub congestion_control: CongestionControl,
    /// Skip batching: lower latency, lower throughput.
    pub is_express: bool,
}

impl Default for RepliesConfig {
    /// `Data` / `Block` / not express — zenoh-ext's
    /// `impl Default for RepliesConfig`.
    ///
    /// ⚠ THE TWO C ABIs DEFAULT DIFFERENTLY, measured rather than assumed:
    /// zenoh-c's `ze_advanced_publisher_cache_options_default` answers
    /// `congestion_control = Drop` (read out of the real `libzenohc.so`), and
    /// zenoh-pico's writes `z_internal_congestion_control_default_push()`,
    /// which is Drop as well. So this default belongs to the RUST surface, and
    /// each C ABI keeps its own upstream's — a single shared default would
    /// quietly break one of the two.
    fn default() -> Self {
        Self {
            priority: Priority::DEFAULT,
            congestion_control: CongestionControl::Block,
            is_express: false,
        }
    }
}

impl RepliesConfig {
    /// The packed QoS byte this config puts on a reply.
    fn qos(&self) -> QosLevel {
        QosLevel::from_parts(self.priority, self.congestion_control, self.is_express)
    }
}

/// How many samples the cache retains, and how it answers. Mirror of zenoh-ext
/// `CacheConfig` (advanced_cache.rs:88-100); default 1 sample.
#[derive(Clone, Copy, Debug)]
pub struct CacheConfig {
    /// Ring depth: the cache keeps at most this many most-recent samples.
    pub max_samples: usize,
    /// R2596 — the QoS every reply out of this cache carries. Upstream's
    /// `CacheConfig` carries exactly these two knobs and no others.
    pub replies_config: RepliesConfig,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_samples: 1,
            replies_config: RepliesConfig::default(),
        }
    }
}

/// The shared ring an advanced publisher feeds and the cache queryable answers from.
type CacheRing = Arc<Mutex<VecDeque<CachedSample>>>;

/// The retained samples and the answer a cache queryable gives out of them —
/// everything an advanced cache is except the queryable that carries the answer
/// to a peer.
///
/// Split out of the session-bound cache because the queryable is the one part of a
/// cache whose declaration depends on WHERE the publisher lives: on a runtime
/// session it is a plain queryable, and on a C session it is declared on the
/// session's own key table and announced per peer. The ring and its answer are
/// the same on both, so they are one type and the host brings only the
/// declaration (`AdvancedPublisherPlane::declare_cache_queryable` of the runtime).
///
/// Cloning shares the ring: the publisher feeds it and the queryable's handler
/// reads it, and both hold one of these.
#[derive(Clone)]
pub struct CacheStore {
    ring: CacheRing,
    max_samples: usize,
    /// R2596 — copied into the answering handler beside the ring: the reply QoS
    /// is a property of the CACHE, so it is fixed at construction exactly as
    /// `max_samples` is, not read per query.
    replies_config: RepliesConfig,
}

impl CacheStore {
    /// An empty ring of `config`'s depth.
    pub fn new(config: CacheConfig) -> Self {
        Self {
            ring: Arc::new(Mutex::new(VecDeque::new())),
            max_samples: config.max_samples,
            replies_config: config.replies_config,
        }
    }

    /// The handler a cache queryable answers with: each inbound `get` is
    /// filtered on the `_sn` range + `_max` cap parsed from its selector and
    /// replied with the matching samples, timestamp-stamped, oldest-first.
    ///
    /// `now` answers the host's wall clock as an NTP64 word, read once per query: the "now" of
    /// the `_time` age filter, from the same base the publisher stamps samples with. The ring
    /// reads no clock of its own.
    pub fn query_handler(
        &self,
        now: impl Fn() -> u64 + Send + 'static,
    ) -> impl FnMut(&dyn QueryView, &mut dyn ReplyOut) + Send + 'static {
        let ring = Arc::clone(&self.ring);
        let replies_config = self.replies_config;
        move |view: &dyn QueryView, out: &mut dyn ReplyOut| {
            let guard = ring.lock().expect("advanced cache ring mutex poisoned");
            answer_from_ring(&guard, view, out, now(), replies_config);
        }
    }

    /// Push a freshly published sample into the ring, evicting the oldest
    /// when the depth bound is reached (zenoh advanced_cache.rs:368-377).
    ///
    /// Uses `if` (evict at most one) rather than `while` (evict until under
    /// budget): each push adds exactly one, so for any `max_samples >= 1` the
    /// two are equivalent — but `while` infinite-loops on the degenerate
    /// `max_samples == 0` (`0 >= 0` stays true while `pop_front()` on the empty
    /// ring never reduces `len`), hanging the thread WITH the ring mutex held.
    /// `if` matches zenoh and bounds a 0-depth cache at one retained sample.
    ///
    /// The evicted sample is dropped AFTER the ring's lock is released: what it
    /// [retains](Retained) may re-enter the session as it goes (a key's
    /// retraction does), and this mutex is not reentrant.
    pub fn cache_sample(&self, sample: CachedSample) {
        let evicted = {
            let mut ring = self
                .ring
                .lock()
                .expect("advanced cache ring mutex poisoned");
            let evicted = if ring.len() >= self.max_samples {
                ring.pop_front()
            } else {
                None
            };
            ring.push_back(sample);
            evicted
        };
        drop(evicted);
    }

    /// Number of samples currently retained (test / introspection seam).
    pub fn len(&self) -> usize {
        self.ring
            .lock()
            .expect("advanced cache ring mutex poisoned")
            .len()
    }

    /// True when the ring holds no samples.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Answer one inbound query from the ring: filter by the `_sn` range +
/// `_max` cap, reply matching samples oldest-first (each under its own
/// concrete keyexpr + timestamp).
fn answer_from_ring(
    ring: &VecDeque<CachedSample>,
    view: &dyn QueryView,
    out: &mut dyn ReplyOut,
    now_ntp64: u64,
    replies_config: RepliesConfig,
) {
    let params = view.parameters();
    let sn_range = param_value(params, "_sn").map(parse_sn_range);
    let max = param_value(params, "_max").and_then(|v| v.parse::<usize>().ok());
    // R311y98 — the `_time` age filter (zenoh advanced_cache.rs:264-272). A
    // history GET carries `_time=[now(-age)..]`; only samples whose timestamp
    // lies in the range are replied. Absent, or a value zenoh's own parser
    // rejects, leaves this `None` = unfiltered, which is what upstream does with
    // a range it cannot read.
    let time_range = param_value(params, "_time")
        .and_then(TimeRange::parse)
        .map(|r| r.resolve_at(ntp64_to_system_time(now_ntp64)));

    let mut matched: Vec<&CachedSample> = ring
        .iter()
        .filter(|s| sample_matches_sn(s.source_info.as_ref().map(|si| si.sn), sn_range))
        .filter(|s| sample_matches_time(s.timestamp.time, time_range))
        .collect();

    // `_max`: keep the newest `m` (the ring tail), still replied oldest-first.
    if let Some(m) = max {
        if matched.len() > m {
            matched = matched.split_off(matched.len() - m);
        }
    }

    for s in matched {
        // Both arms carry the sample's source_info (the inner-body ext id 0x01)
        // so a recovery subscriber re-keys / reorders it. The emission is gated
        // `reply-source-info` at the codec (default OFF = the recovery reply is
        // source_info-free, i.e. advanced-cache without the advanced-recovery
        // composition); the cache passes it unconditionally.
        //
        // R311y561 — the KIND decides the arm. zenoh replies the cached `Sample`
        // whole, so a cached DELETE comes back as a Del reply; replaying it on
        // the Put arm would resurrect the deleted key on the recovering
        // subscriber. The `_sn` / `_max` / `_time` filters above are
        // kind-agnostic on purpose: a Del occupies its sequence number exactly
        // like a Put, so excluding it from a range would re-introduce the
        // apparent gap the shared counter exists to avoid.
        //
        // R311y562 — the reply now carries the sample's ENCODING and
        // ATTACHMENT too, through the one [`ReplyMeta`] seam. Both were
        // previously dropped: the Put arm passed a literal `None` encoding and
        // no arm had an attachment slot alongside a timestamp, so a recovered
        // sample arrived stripped of both. The Del arm carries neither, and
        // that is the wire's rule rather than a leftover — see
        // [`ReplyOut::reply_keyed_del_meta`].
        // R2596 — `replies_config` OVERRIDES the query's QoS on every reply,
        // both arms, which is what upstream's `SampleBuilder` chain and pico's
        // `z_query_reply_options_t` each do. Set on the shared `meta` so the
        // Put and Del arms cannot drift.
        let meta = ReplyMeta::new()
            .with_timestamp(Some(&s.timestamp))
            .with_source_info(s.source_info.as_ref())
            .with_qos(Some(replies_config.qos()));
        // R3063 -- a sample cached as a buffer of shared memory is replied AS the buffer, so a
        // recovering subscriber that can map the segment is sent the descriptor again, as
        // upstream's cache replies the sample it holds. The bytes argument is the buffer's own
        // either way, for a sink that cannot stage one.
        #[cfg(feature = "transport-shm")]
        let meta = meta.with_shared(s.shared.as_ref());
        let staged = match s.kind {
            SampleKind::Put => out.reply_keyed_meta(
                &s.keyexpr,
                s.bytes(),
                meta.with_encoding(s.encoding.as_ref())
                    .with_attachment(s.attachment.as_deref()),
            ),
            SampleKind::Del => out.reply_keyed_del_meta(&s.keyexpr, meta),
        };
        // A refused sample is warned about and the replay goes on to the
        // next, as upstream's does (`zenoh-ext/src/advanced_cache.rs`
        // @ `Error replying to query`).
        if let Err(e) = staged {
            log::warn!("AdvancedCache{{}} Error replying to query: {}", e);
        }
    }
}

/// Extract a `key=value` selector value from the raw query parameter bytes
/// (`_sn=10..20;_max=5;_anyke`). `None` when absent or non-UTF-8.
///
/// R311y442 — the split lives in [`wz_session_core::selector_params`] now, and
/// the separator it uses is `;` rather than the `&` this function hand-wrote. The
/// old spelling read a real zenoh subscriber's multi-parameter selector as ONE
/// parameter with a corrupted value, so `_max` failed to parse and `_time` was
/// invisible: both filters dropped, silently, in the over-return direction.
///
/// That consequence is REASONED, not witnessed: the only foreign advanced
/// subscriber available (`z_advanced_sub`) hardcodes `HistoryConfig::default()`
/// and therefore sends no `key=value` parameter at all, so no leg in the tree
/// exercises this side of the dialect. See the module docs of
/// `wz_advanced_pubsub_zenoh_ext_interop.rs`.
///
/// Review follow-up: the dialect moved OUT of this crate, because a copy that
/// lives next to one consumer is not a single source of truth — the same `&` bug
/// was still live in `wz-rest/src/bridge.rs` one crate away.
fn param_value<'a>(params: Option<&'a [u8]>, key: &str) -> Option<&'a str> {
    let s = core::str::from_utf8(params?).ok()?;
    wz_session_core::selector_params::param_value(s, key)
}

/// Parse an `_sn` range string into inclusive `(lo, hi)` bounds, mirroring
/// zenoh's `decode_range` (advanced_cache.rs:191-207): `"a..b"` →
/// `(Some(a), Some(b))`, `"a.."` → `(Some(a), None)`, `"..b"` →
/// `(None, Some(b))`, `".."` → `(None, None)`, a bare `"a"` →
/// `(Some(a), Some(a))`; an unparseable side is unbounded (`None`).
fn parse_sn_range(val: &str) -> (Option<u32>, Option<u32>) {
    match val.split_once("..") {
        Some((lo, hi)) => (lo.parse().ok(), hi.parse().ok()),
        None => {
            let v = val.parse().ok();
            (v, v)
        }
    }
}

/// Whether a ring sample's `source_sn` satisfies the parsed `_sn` range.
/// No `_sn` param, or an unbounded `..` range, matches every sample;
/// a bounded range requires a present `source_sn` inside it.
fn sample_matches_sn(sample_sn: Option<u32>, range: Option<(Option<u32>, Option<u32>)>) -> bool {
    match range {
        None | Some((None, None)) => true,
        Some((lo, hi)) => match sample_sn {
            None => false,
            Some(sn) => lo.map_or(true, |l| sn >= l) && hi.map_or(true, |h| sn <= h),
        },
    }
}

/// Whether a sample's NTP64 timestamp satisfies the resolved `_time` range.
/// No range (absent, or a value zenoh's parser rejects) matches every sample.
fn sample_matches_time(sample_time: u64, range: Option<TimeRange<SystemTime>>) -> bool {
    range.map_or(true, |r| r.contains_ntp64(sample_time))
}

#[cfg(test)]
mod tests;
