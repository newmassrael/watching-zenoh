// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y69 — `ext-pubsub-advanced-cache` (§5.25): the publisher-side
//! sample ring + the queryable that answers `_sn` / `_max` recovery and
//! history selectors from it.
//!
//! The wz mirror of zenoh-ext `advanced_cache.rs`: an `AdvancedPublisher`
//! retains its last `max_samples` published samples in a FIFO ring and
//! exposes them through a queryable on `<key_expr>/@adv/pub/<zid>/...`. A
//! late-joining or gap-detecting subscriber recovers missed samples by
//! `get`-ing that queryable with an `_sn=START..END` (sequence-number
//! range) and/or `_max=N` selector; the cache replies the matching ring
//! samples (zenoh advanced_cache.rs:209-346).
//!
//! ## Reply-side `source_info` (R311y75 seam + R311y76 cache emit)
//!
//! zenoh replies the cached `Sample` whole, so each reply carries the
//! original `SourceInfo` and a subscriber re-keys it by its sequence
//! number. wz now mirrors this: each [`CachedSample`] stores the full
//! [`SourceInfo`] (R311y76), and [`answer_from_ring`] replies it via
//! [`ReplyOut::reply_keyed_sourced`] (R311y75), which threads the
//! `(zid, eid, sn)` onto the inner Put-body source_info ext (id 0x01).
//! The wire EMISSION is gated `reply-source-info` at the codec: OFF (the
//! default for `ext-pubsub-advanced-cache` alone) the recovery reply is
//! source_info-free (pico-faithful), and the
//! `ext-pubsub-advanced-recovery` composition turns it on. The remaining
//! CONSUMER side — surfacing the recovered reply's source_info on the
//! subscriber so it re-keys / reorders — lands with the subscriber
//! reorder buffer (advanced-recovery piece #3, each seam paired with its
//! consumer).
//!
//! ## `_time` time-range filter (R311y98)
//!
//! zenoh's cache applies a `_time` time-range filter in both query branches
//! (zenoh-ext advanced_cache.rs:264-272, :308-316): a sample is replied only
//! if its timestamp falls in the query's `_time` range. wz now mirrors this —
//! [`answer_from_ring`] parses the `_time` selector ([`parse_time_range_ntp64`])
//! and drops out-of-range samples. The "now" the relative `now(-age)` bounds
//! resolve against is [`crate::timestamp_source::wall_clock_ntp64`] read at
//! query time (the same NTP64 wall-clock base the publisher stamps each cached
//! sample with), so the filter lives on the ANSWERER side and works for a
//! publisher-only node serving a remote history subscriber — it does NOT
//! require `ext-pubsub-advanced-history` on the cache's node. The `_time`
//! selector is emitted by the startup HISTORY query (`max_age` ->
//! `_time=[now(-age)..]`, the advanced-subscriber side). A `_time` form wz does
//! not parse (an absolute RFC3339 bound, or the `[t;duration]` form) leaves the
//! range unresolved = unfiltered, so an exotic zenoh-peer form degrades to the
//! prior over-return rather than wrongly dropping samples (a documented, narrow
//! interop divergence; the wz↔wz `now(±duration)` form filters exactly).

use std::collections::VecDeque;
use std::ops::Bound;
use std::sync::{Arc, Mutex};

use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;
use wz_session_core::ntp64::Ntp64;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::sample::{SampleKind, SourceInfo, TimestampHint};

use crate::session::{Queryable, QueryableError, QueryableOptions, Session, Unicast};
use crate::session_glue::SessionLinkActions;

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
    /// retraction. With the kind stored, [`answer_from_ring`] dispatches the
    /// reply arm ([`ReplyOut::reply_keyed_sourced`] vs
    /// [`ReplyOut::reply_keyed_del_sourced`]) and deletes are retained like any
    /// other sample.
    pub kind: SampleKind,
}

/// How many samples the cache retains. Mirror of zenoh-ext `CacheConfig`
/// (advanced_cache.rs:88-100); default 1.
#[derive(Clone, Copy, Debug)]
pub struct CacheConfig {
    /// Ring depth: the cache keeps at most this many most-recent samples.
    pub max_samples: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self { max_samples: 1 }
    }
}

/// The shared ring an [`crate::advanced_publisher::AdvancedPublisher`]
/// feeds and the cache queryable answers from.
type CacheRing = Arc<Mutex<VecDeque<CachedSample>>>;

/// A live advanced cache bound to a [`Session`]: owns the sample ring +
/// the answering [`Queryable`]. Dropping it undeclares the queryable
/// (RAII).
pub struct AdvancedCache<R: SessionRuntime, T: TimeSource> {
    ring: CacheRing,
    max_samples: usize,
    _queryable: Queryable<R, T>,
}

impl<R, T> AdvancedCache<R, T>
where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    /// Declare the cache queryable on `queryable_keyexpr` (the publisher's
    /// `<key_expr>/@adv/pub/...` suffix). The queryable answers each inbound
    /// `get` by filtering the ring on the `_sn` range + `_max` cap parsed
    /// from the query selector and replying the matching samples
    /// timestamp-stamped, oldest-first.
    pub fn declare(
        session: &Session<R, T, Unicast>,
        queryable_keyexpr: impl Into<String>,
        config: CacheConfig,
    ) -> Result<Self, QueryableError> {
        let ring: CacheRing = Arc::new(Mutex::new(VecDeque::new()));
        let query_ring = Arc::clone(&ring);
        // The cache is the authoritative answerer for its `@adv` suffix, so
        // the queryable is COMPLETE (zenoh declares the cache queryable as a
        // normal queryable; recovery/history gets target it directly).
        let queryable = session.declare_queryable(
            queryable_keyexpr,
            QueryableOptions::default().with_complete(true),
            move |view: &dyn QueryView, out: &mut dyn ReplyOut| {
                let guard = query_ring
                    .lock()
                    .expect("advanced cache ring mutex poisoned");
                // "now" for the `_time` age filter, read at query time from the
                // same NTP64 wall-clock base the publisher stamps samples with.
                let now = crate::timestamp_source::wall_clock_ntp64();
                answer_from_ring(&guard, view, out, now);
            },
        )?;
        Ok(Self {
            ring,
            max_samples: config.max_samples,
            _queryable: queryable,
        })
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
    pub fn cache_sample(&self, sample: CachedSample) {
        let mut ring = self
            .ring
            .lock()
            .expect("advanced cache ring mutex poisoned");
        if ring.len() >= self.max_samples {
            ring.pop_front();
        }
        ring.push_back(sample);
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
) {
    let params = view.parameters();
    let sn_range = param_value(params, "_sn").map(parse_sn_range);
    let max = param_value(params, "_max").and_then(|v| v.parse::<usize>().ok());
    // R311y98 — the `_time` age filter (zenoh advanced_cache.rs:264-272). A
    // history GET carries `_time=[now(-age)..]`; only samples whose timestamp
    // lies in the range are replied. Absent OR an unparseable form (absolute
    // RFC3339, the `[t;dur]` form) leaves this `None` = unfiltered (the
    // documented over-return), so wz never wrongly drops on a form it cannot
    // resolve while the wz↔wz `now(±duration)` form filters exactly.
    let time_range =
        param_value(params, "_time").and_then(|v| parse_time_range_ntp64(v, now_ntp64));

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
        match s.kind {
            SampleKind::Put => out.reply_keyed_sourced(
                &s.keyexpr,
                &s.payload,
                None,
                &s.timestamp,
                s.source_info.as_ref(),
            ),
            SampleKind::Del => {
                out.reply_keyed_del_sourced(&s.keyexpr, &s.timestamp, s.source_info.as_ref())
            }
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

/// One NTP64 second = `2^32` in the `(unix_secs << 32) | fraction` word, so a
/// duration in seconds scales to the NTP64 magnitude by `secs * 2^32`. The
/// `f64` view of the [`Ntp64::FRAC_PER_SEC`] magnitude SSOT, for the
/// `now(±duration)` offset arithmetic below.
const NTP64_SECOND: f64 = Ntp64::FRAC_PER_SEC as f64;

/// Whether a sample's NTP64 timestamp satisfies the parsed `_time` range.
/// No range (absent or unparseable `_time`) matches every sample.
fn sample_matches_time(sample_time: u64, range: Option<(Bound<u64>, Bound<u64>)>) -> bool {
    match range {
        None => true,
        Some((lo, hi)) => {
            let lo_ok = match lo {
                Bound::Included(l) => sample_time >= l,
                Bound::Excluded(l) => sample_time > l,
                Bound::Unbounded => true,
            };
            let hi_ok = match hi {
                Bound::Included(h) => sample_time <= h,
                Bound::Excluded(h) => sample_time < h,
                Bound::Unbounded => true,
            };
            lo_ok && hi_ok
        }
    }
}

/// Parse a `_time` time-range selector into resolved inclusive/exclusive NTP64
/// bounds, mirroring zenoh's `TimeRange<TimeExpr>` grammar (zenoh-util
/// time_range.rs:158-211): `[`/`]` opens an inclusive/exclusive start, `]`/`[`
/// closes an inclusive/exclusive end, `start..end` are the two bounds (empty =
/// unbounded). Returns `None` (= unfiltered, the documented over-return) for
/// any form wz does not resolve to a wall-clock instant: an absolute RFC3339
/// bound or the `[start;duration]` form. The wz history query only ever emits
/// `[now(-age)..]`, so wz↔wz filters exactly.
fn parse_time_range_ntp64(val: &str, now_ntp64: u64) -> Option<(Bound<u64>, Bound<u64>)> {
    let bytes = val.as_bytes();
    if bytes.len() < 4 {
        return None;
    }
    let incl_start = match bytes[0] {
        b'[' => true,
        b']' => false,
        _ => return None,
    };
    let incl_end = match bytes[bytes.len() - 1] {
        b']' => true,
        b'[' => false,
        _ => return None,
    };
    let inner = &val[1..val.len() - 1];
    // Only the `start..end` form (the `[start;duration]` form -> None/unfiltered).
    let (start, end) = inner.split_once("..")?;
    Some((
        parse_time_bound_ntp64(start, incl_start, now_ntp64)?,
        parse_time_bound_ntp64(end, incl_end, now_ntp64)?,
    ))
}

/// Resolve one `_time` bound: empty = unbounded, else a `now(±duration)`
/// instant carried into an inclusive/exclusive bound.
fn parse_time_bound_ntp64(s: &str, inclusive: bool, now_ntp64: u64) -> Option<Bound<u64>> {
    if s.is_empty() {
        return Some(Bound::Unbounded);
    }
    let t = parse_now_expr_ntp64(s, now_ntp64)?;
    Some(if inclusive {
        Bound::Included(t)
    } else {
        Bound::Excluded(t)
    })
}

/// Resolve a `now(±duration)` / `now()` expression to an NTP64 instant against
/// `now_ntp64`, mirroring zenoh's `TimeExpr::Now` (time_range.rs:344-356). An
/// absolute (RFC3339) time returns `None` — wz does not carry an absolute
/// wall-clock parser here, so such a bound leaves the range unfiltered.
fn parse_now_expr_ntp64(s: &str, now_ntp64: u64) -> Option<u64> {
    let inner = s.strip_prefix("now(")?.strip_suffix(')')?;
    if inner.is_empty() {
        return Some(now_ntp64);
    }
    let (negative, dur) = match inner.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, inner),
    };
    let secs = parse_duration_secs(dur)?;
    // Resolve the offset in UNSIGNED NTP64 space (saturating). An `i64` cast of
    // `now_ntp64` would wrap NEGATIVE once unix seconds reach 2^31 (year 2038,
    // `secs << 32 >= 2^63`): an upper `now()` bound would then collapse to 0 and
    // WRONGLY DROP every sample. `now_ntp64` is `(unix_secs << 32) | frac`
    // (~7.6e18 today, not the ~9.2e18 i64 ceiling); the offset is `secs * 2^32`
    // (f64-exact for realistic durations, `as u64` saturating beyond that).
    let offset = (secs * NTP64_SECOND) as u64;
    Some(if negative {
        now_ntp64.saturating_sub(offset)
    } else {
        now_ntp64.saturating_add(offset)
    })
}

/// Parse a zenoh duration literal to seconds, mirroring zenoh-util
/// `parse_duration` (time_range.rs): a bare `<f64>` is seconds; the suffixes
/// `u` (micros), `ms` (millis), `s`, `m` (minutes), `h`, `d`, `w` scale it.
fn parse_duration_secs(s: &str) -> Option<f64> {
    let bytes = s.as_bytes();
    let n = bytes.len();
    if n == 0 {
        return None;
    }
    match bytes[n - 1] {
        b'u' => s[..n - 1].parse::<f64>().ok().map(|u| u * 1e-6),
        b's' => {
            if n >= 2 && bytes[n - 2] == b'm' {
                s[..n - 2].parse::<f64>().ok().map(|ms| ms * 1e-3)
            } else {
                s[..n - 1].parse::<f64>().ok()
            }
        }
        b'm' => s[..n - 1].parse::<f64>().ok().map(|m| m * 60.0),
        b'h' => s[..n - 1].parse::<f64>().ok().map(|h| h * 3600.0),
        b'd' => s[..n - 1].parse::<f64>().ok().map(|d| d * 86_400.0),
        b'w' => s[..n - 1].parse::<f64>().ok().map(|w| w * 604_800.0),
        _ => s.parse::<f64>().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use wz_session_core::sample::EncodingHint;

    /// Shared `ReplyOut` recorder for the `answer_from_ring` integration
    /// tests: captures each reply's `(keyexpr, payload)` and its source
    /// identity `(zid_prefix, eid, sn)` (or `None`).
    ///
    /// R311y561 — `arms` records which reply ARM each emission took, in emit
    /// order, and `dels` the Del arm's own `(keyexpr, timestamp, source_info)`.
    /// Without `arms` a Del replayed on the Put arm (the pre-y561 behaviour, and
    /// the resurrect-a-deleted-key bug) is INVISIBLE to a recorder that only
    /// collects `(keyexpr, payload)` — a cached Del carries an empty payload, so
    /// it would land in `keyed` as `("demo/k", vec![])` and read as a legitimate
    /// empty Put.
    /// A recorded source identity `(zid_prefix, eid, sn)`, or `None` when the
    /// reply carried none.
    type RecSource = Option<(Vec<u8>, u32, u32)>;
    /// One Del-arm emission: `(keyexpr, timestamp, source_info)`.
    type RecDel = (String, u64, RecSource);

    #[derive(Default)]
    struct Rec {
        keyed: Vec<(String, Vec<u8>)>,
        sourced: Vec<RecSource>,
        arms: Vec<&'static str>,
        dels: Vec<RecDel>,
    }
    impl ReplyOut for Rec {
        fn reply(&mut self, payload: &[u8]) {
            self.keyed.push((String::new(), payload.to_vec()));
            self.arms.push("put");
        }
        fn reply_keyed_sourced(
            &mut self,
            keyexpr: &str,
            payload: &[u8],
            _encoding: Option<&EncodingHint>,
            _timestamp: &TimestampHint,
            source_info: Option<&SourceInfo>,
        ) {
            self.keyed.push((keyexpr.to_string(), payload.to_vec()));
            self.sourced
                .push(source_info.map(|si| (si.zid_prefix().to_vec(), si.eid, si.sn)));
            self.arms.push("put");
        }
        fn reply_keyed_del_sourced(
            &mut self,
            keyexpr: &str,
            timestamp: &TimestampHint,
            source_info: Option<&SourceInfo>,
        ) {
            self.dels.push((
                keyexpr.to_string(),
                timestamp.time,
                source_info.map(|si| (si.zid_prefix().to_vec(), si.eid, si.sn)),
            ));
            self.arms.push("del");
        }
        fn reply_del(&mut self) {
            self.arms.push("bare-del");
        }
        fn reply_err(&mut self, _: Option<u32>, _: Option<&str>, _: &[u8]) {}
        fn with_responder(&mut self, _: &[u8], _: u32) {}
        fn clear_responder(&mut self) {}
        fn responder(&self) -> Option<(&[u8], u32)> {
            None
        }
    }

    /// R311y442 REWROTE this test, and the old expectation is the diagnosis: it
    /// fed `_sn=10..20&_max=5` and asserted BOTH keys came back, certifying the
    /// `&` dialect as the cache's contract. The querier side joined on `&` too,
    /// so wz agreed with wz and neither agreed with upstream. The fixture here is
    /// now the byte string a real zenoh advanced subscriber sends — `;`-separated
    /// and terminated by the bare `_anyke` flag.
    #[test]
    fn param_value_extracts_selectors() {
        let zenoh_shaped = b"_sn=10..20;_max=5;_anyke";
        assert_eq!(param_value(Some(zenoh_shaped), "_sn"), Some("10..20"));
        assert_eq!(param_value(Some(zenoh_shaped), "_max"), Some("5"));
        assert_eq!(param_value(Some(b"_sn=10..20"), "_max"), None);
        assert_eq!(param_value(None, "_sn"), None);
    }

    #[test]
    fn parse_sn_range_mirrors_decode_range() {
        assert_eq!(parse_sn_range("10..20"), (Some(10), Some(20)));
        assert_eq!(parse_sn_range("10.."), (Some(10), None));
        assert_eq!(parse_sn_range("..20"), (None, Some(20)));
        assert_eq!(parse_sn_range(".."), (None, None));
        assert_eq!(parse_sn_range("7"), (Some(7), Some(7)));
    }

    /// Integration over `answer_from_ring`: a populated ring + a synthetic
    /// query exercise the `_sn` filter, the `_max` cap, and the
    /// timestamp-stamped reply fan together.
    #[test]
    fn answer_from_ring_filters_and_replies() {
        use wz_session_core::query_sink::BorrowedQuery;

        let mut ring = VecDeque::new();
        for sn in 0..3u32 {
            ring.push_back(CachedSample {
                keyexpr: "demo/k".to_string(),
                payload: vec![sn as u8],
                source_info: Some(SourceInfo::new(&[0x07], 9, sn)),
                timestamp: TimestampHint {
                    time: 100 + sn as u64,
                    zid: vec![1],
                },
                kind: SampleKind::Put,
            });
        }
        let q = |params: Option<&'static [u8]>| BorrowedQuery {
            keyexpr: "demo/k",
            parameters: params,
            attachment: None,
            source_info: None,
            payload: None,
            encoding: None,
            rid: 0,
            is_local: true,
        };

        // `_sn=1..` → sn 1 and 2, oldest-first. (No `_time` param, so the
        // `now` argument is irrelevant here — passed `0`.)
        let mut out = Rec::default();
        answer_from_ring(&ring, &q(Some(b"_sn=1..")), &mut out, 0);
        assert_eq!(
            out.keyed,
            vec![
                ("demo/k".to_string(), vec![1]),
                ("demo/k".to_string(), vec![2])
            ]
        );

        // `_max=1` → only the newest (sn 2).
        let mut out = Rec::default();
        answer_from_ring(&ring, &q(Some(b"_max=1")), &mut out, 0);
        assert_eq!(out.keyed, vec![("demo/k".to_string(), vec![2])]);

        // No params → all three, each carrying its source_info (zid, eid, sn)
        // so a recovery subscriber can re-key / reorder the retransmissions.
        let mut out = Rec::default();
        answer_from_ring(&ring, &q(None), &mut out, 0);
        assert_eq!(out.keyed.len(), 3);
        assert_eq!(
            out.sourced,
            vec![
                Some((vec![0x07], 9, 0)),
                Some((vec![0x07], 9, 1)),
                Some((vec![0x07], 9, 2)),
            ],
            "each recovery reply carries the cached sample's source_info",
        );
    }

    /// R311y561 — a cached DELETE replays on the Del arm, under its own key,
    /// carrying its timestamp and its `(zid, eid, sn)`.
    ///
    /// The assertion that carries the weight is `arms`, not the payloads: a Del
    /// replayed on the Put arm emits `("demo/k", vec![])`, which a
    /// payload-only recorder cannot tell from a legitimate empty Put — and that
    /// mistake is exactly the one that resurrects a deleted key on the
    /// recovering subscriber. Point the reply arm at `reply_keyed_sourced`
    /// unconditionally (the pre-y561 shape) and this test fails on `arms` while
    /// `keyed` still looks plausible.
    ///
    /// The kind-agnostic `_sn` filter is asserted too: the Del occupies sn 1
    /// like any other sample, so `_sn=1..` starts AT it. Excluding deletes from
    /// the range would re-open the apparent gap the shared sn counter exists to
    /// close.
    #[test]
    fn cached_delete_replays_on_the_del_arm() {
        use wz_session_core::query_sink::BorrowedQuery;

        // sn 0 Put, sn 1 DEL, sn 2 Put — one mixed stream from one publisher.
        let mut ring = VecDeque::new();
        for sn in 0..3u32 {
            let kind = if sn == 1 {
                SampleKind::Del
            } else {
                SampleKind::Put
            };
            ring.push_back(CachedSample {
                keyexpr: "demo/k".to_string(),
                payload: if kind == SampleKind::Del {
                    Vec::new()
                } else {
                    vec![sn as u8]
                },
                source_info: Some(SourceInfo::new(&[0x07], 9, sn)),
                timestamp: TimestampHint {
                    time: 100 + sn as u64,
                    zid: vec![1],
                },
                kind,
            });
        }
        let q = |params: Option<&'static [u8]>| BorrowedQuery {
            keyexpr: "demo/k",
            parameters: params,
            attachment: None,
            source_info: None,
            payload: None,
            encoding: None,
            rid: 0,
            is_local: true,
        };

        let mut out = Rec::default();
        answer_from_ring(&ring, &q(None), &mut out, 0);

        assert_eq!(
            out.arms,
            vec!["put", "del", "put"],
            "the retained kind decides the reply arm, in ring order"
        );
        assert_eq!(
            out.keyed,
            vec![
                ("demo/k".to_string(), vec![0]),
                ("demo/k".to_string(), vec![2])
            ],
            "only the two Puts carry a payload; the Del never reaches the Put arm"
        );
        assert_eq!(
            out.dels,
            vec![("demo/k".to_string(), 101, Some((vec![0x07], 9, 1)))],
            "the Del reply carries its own concrete key, its timestamp, and its \
             (zid, eid, sn) — the identity the subscriber re-keys it by"
        );

        // The `_sn` range is kind-agnostic: `_sn=1..` starts at the DELETE.
        let mut out = Rec::default();
        answer_from_ring(&ring, &q(Some(b"_sn=1..")), &mut out, 0);
        assert_eq!(
            out.arms,
            vec!["del", "put"],
            "a Del occupies its sequence number like any other sample, so a \
             recovery range starting at it replays it"
        );

        // ... and so is `_max`, which counts the Del as one of the newest.
        let mut out = Rec::default();
        answer_from_ring(&ring, &q(Some(b"_max=2")), &mut out, 0);
        assert_eq!(out.arms, vec!["del", "put"], "_max counts the Del");
    }

    #[test]
    fn sn_filter_includes_and_excludes() {
        // No range → all (incl un-sequenced).
        assert!(sample_matches_sn(Some(5), None));
        assert!(sample_matches_sn(None, None));
        // Unbounded `..` → all.
        assert!(sample_matches_sn(Some(5), Some((None, None))));
        // Open upper (`10..`): recovery's main form.
        assert!(sample_matches_sn(Some(10), Some((Some(10), None))));
        assert!(!sample_matches_sn(Some(9), Some((Some(10), None))));
        // Closed range.
        assert!(sample_matches_sn(Some(15), Some((Some(10), Some(20)))));
        assert!(!sample_matches_sn(Some(21), Some((Some(10), Some(20)))));
        // Bounded range needs a present sn.
        assert!(!sample_matches_sn(None, Some((Some(10), None))));
    }

    #[test]
    fn parse_duration_units_match_zenoh() {
        assert_eq!(parse_duration_secs("30"), Some(30.0)); // bare = seconds
        assert_eq!(parse_duration_secs("30s"), Some(30.0));
        assert_eq!(parse_duration_secs("500ms"), Some(0.5));
        assert_eq!(parse_duration_secs("2m"), Some(120.0));
        assert_eq!(parse_duration_secs("1h"), Some(3600.0));
        assert_eq!(parse_duration_secs("1d"), Some(86_400.0));
        assert_eq!(parse_duration_secs("1w"), Some(604_800.0));
        assert_eq!(parse_duration_secs("1000u"), Some(1e-3)); // 1000us = 1ms
        assert_eq!(parse_duration_secs("xs"), None);
        assert_eq!(parse_duration_secs(""), None);
    }

    #[test]
    fn parse_time_range_resolves_now_relative_bounds() {
        let now = 1_000u64 << 32; // NTP64 = 1000 wall-clock seconds
                                  // `[now(-30s)..]` -> [970s, unbounded) — the wz history-query form.
        assert_eq!(
            parse_time_range_ntp64("[now(-30s)..]", now),
            Some((Bound::Included(970u64 << 32), Bound::Unbounded))
        );
        // `[now()..]` -> [1000s, unbounded).
        assert_eq!(
            parse_time_range_ntp64("[now()..]", now),
            Some((Bound::Included(now), Bound::Unbounded))
        );
        // Closed, exclusive both ends: `]now(-2m)..now(-1m)[`.
        assert_eq!(
            parse_time_range_ntp64("]now(-2m)..now(-1m)[", now),
            Some((Bound::Excluded(880u64 << 32), Bound::Excluded(940u64 << 32)))
        );
        // A `now(-age)` that underflows clamps at 0 (never wraps).
        assert_eq!(
            parse_time_range_ntp64("[now(-2000s)..]", now),
            Some((Bound::Included(0), Bound::Unbounded))
        );
        // Unparseable / exotic forms -> None (= unfiltered over-return):
        // an absolute RFC3339 bound, the `[t;dur]` form, and a malformed bracket.
        assert_eq!(
            parse_time_range_ntp64("[2024-01-01T00:00:00Z..]", now),
            None
        );
        assert_eq!(parse_time_range_ntp64("[now();1h]", now), None);
        assert_eq!(parse_time_range_ntp64("now(-30s)", now), None);
    }

    /// R311y99 (20th-trigger review MED) regression: resolving the `now(±dur)`
    /// offset must not cast `now_ntp64` through `i64`. Once unix seconds reach
    /// 2^31 (year 2038) the NTP64 word is `>= 2^63`, so an `i64` cast wraps
    /// NEGATIVE — an UPPER `now()` bound would then collapse to `Included(0)`
    /// and the filter would WRONGLY DROP every sample. Unsigned saturating
    /// resolution keeps the bound a large positive value.
    #[test]
    fn parse_time_range_survives_post_2038_now_word() {
        let now = 1u64 << 63; // unix_secs = 2^31 (year 2038); now word >= 2^63
        let one_hour = 3600u64 << 32;
        // `[..now(-1h)]`: an upper-bounded "older than 1h" window. The end must
        // stay just below `now`, NOT collapse to 0 (the pre-fix i64-wrap bug).
        let r = parse_time_range_ntp64("[..now(-1h)]", now).expect("parses");
        assert_eq!(r, (Bound::Unbounded, Bound::Included(now - one_hour)));
        // A 2h-old sample is inside `[.., now-1h]` — pre-fix (end==0) it was
        // wrongly dropped; post-fix it passes.
        assert!(sample_matches_time(now - 2 * one_hour, Some(r)));
        // A 1-minute-old sample is NEWER than the now-1h cutoff -> excluded.
        assert!(!sample_matches_time(now - (60u64 << 32), Some(r)));
    }

    #[test]
    fn time_filter_includes_and_excludes() {
        let threshold = 70u64 << 32; // = now(100s) - 30s
                                     // No range -> all.
        assert!(sample_matches_time(60u64 << 32, None));
        // [70s, unbounded): 80s in, 60s out, 70s in (inclusive).
        let r = Some((Bound::Included(threshold), Bound::Unbounded));
        assert!(sample_matches_time(80u64 << 32, r));
        assert!(sample_matches_time(threshold, r));
        assert!(!sample_matches_time(60u64 << 32, r));
        // Exclusive lower bound drops the boundary sample.
        let rex = Some((Bound::Excluded(threshold), Bound::Unbounded));
        assert!(!sample_matches_time(threshold, rex));
    }

    /// Integration: `answer_from_ring` actually applies the `_time` filter in
    /// its reply chain. A ring spanning three wall-clock seconds + a
    /// `_time=[now(-30s)..]` query (now = 100s) replies only the samples newer
    /// than 70s, oldest-first.
    #[test]
    fn answer_from_ring_applies_time_filter() {
        use wz_session_core::query_sink::BorrowedQuery;

        let now = 100u64 << 32;
        let mut ring = VecDeque::new();
        for (i, secs) in [60u64, 80, 100].into_iter().enumerate() {
            ring.push_back(CachedSample {
                keyexpr: "demo/k".to_string(),
                payload: vec![i as u8],
                source_info: Some(SourceInfo::new(&[0x07], 9, i as u32)),
                timestamp: TimestampHint {
                    time: secs << 32,
                    zid: vec![1],
                },
                kind: SampleKind::Put,
            });
        }
        let q = BorrowedQuery {
            keyexpr: "demo/k",
            parameters: Some(b"_time=[now(-30s)..]"),
            attachment: None,
            source_info: None,
            payload: None,
            encoding: None,
            rid: 0,
            is_local: true,
        };
        let mut out = Rec::default();
        answer_from_ring(&ring, &q, &mut out, now);
        // threshold = 70s -> the 80s (payload 1) + 100s (payload 2) samples;
        // the 60s (payload 0) sample is dropped.
        assert_eq!(
            out.keyed,
            vec![
                ("demo/k".to_string(), vec![1]),
                ("demo/k".to_string(), vec![2]),
            ],
            "the _time filter drops the out-of-range sample"
        );
    }
}
