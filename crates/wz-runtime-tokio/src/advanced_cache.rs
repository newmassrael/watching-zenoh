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
//! ## Reply-side `source_info` gap (deferred to `advanced-recovery`)
//!
//! zenoh replies the cached `Sample` whole, so each reply carries the
//! original `SourceInfo` and a subscriber re-keys it by `source_sn`. The
//! wz reply seam ([`ReplyOut`]) carries keyexpr + payload + encoding +
//! timestamp but NOT `source_info`, so the cache replies are
//! timestamp-stamped ([`ReplyOut::reply_keyed_stamped`]) here. The
//! `source_sn`-on-reply that a sequenced subscriber needs to re-key
//! recovered samples is a `ReplyOut` / `Response`-codec extension built
//! WITH its consumer in the `ext-pubsub-advanced-recovery` round (each
//! seam-extension paired with its consumer). The cache already FILTERS
//! by `source_sn` (it stores the publisher-stamped sn per sample), so the
//! query side is faithful today; only the reply carry-back waits.
//!
//! ## `_time` time-range filter (deferred to advanced-history)
//!
//! zenoh's cache also applies a `_time` time-range filter in both query
//! branches (zenoh-ext advanced_cache.rs:264-272, :308-316). wz parses
//! only `_sn` + `_max` here; a `_time` selector is currently IGNORED (the
//! cache returns time-unfiltered samples). This is consumer-paired: the
//! `_time` selector is emitted by the startup HISTORY query
//! (`age`/`max_age` -> `_time=[now-age,..]`), so `_time` filtering lands
//! WITH `ext-pubsub-advanced-history`. Until then a wz cache answering a
//! zenoh `AdvancedSubscriber`'s age-bounded history query over-returns
//! (a documented interop divergence, not silent).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::sample::TimestampHint;

use crate::session::{Queryable, QueryableError, QueryableOptions, Session, Unicast};
use crate::session_glue::SessionLinkActions;

/// One sample retained in the cache ring for recovery / history replies.
/// `source_sn` is the publisher-stamped sequence number used by the `_sn`
/// range filter (`None` for a timestamp-sequenced publisher, which an
/// `_sn` query then never matches — only time/`_max` queries do).
#[derive(Clone, Debug)]
pub struct CachedSample {
    /// The concrete keyexpr the sample was published under (each reply
    /// carries its own key, the `reply ⊆ query` contract).
    pub keyexpr: String,
    /// Put payload bytes.
    pub payload: Vec<u8>,
    /// Publisher-stamped sequence number, or `None` under timestamp
    /// sequencing.
    pub source_sn: Option<u32>,
    /// The sample's timestamp (the publisher stamps every cached put), used
    /// to order replies and stamp them back ([`ReplyOut::reply_keyed_stamped`]).
    pub timestamp: TimestampHint,
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
                answer_from_ring(&guard, view, out);
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
    pub fn cache_sample(&self, sample: CachedSample) {
        let mut ring = self
            .ring
            .lock()
            .expect("advanced cache ring mutex poisoned");
        while ring.len() >= self.max_samples {
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
fn answer_from_ring(ring: &VecDeque<CachedSample>, view: &dyn QueryView, out: &mut dyn ReplyOut) {
    let params = view.parameters();
    let sn_range = param_value(params, "_sn").map(parse_sn_range);
    let max = param_value(params, "_max").and_then(|v| v.parse::<usize>().ok());

    let mut matched: Vec<&CachedSample> = ring
        .iter()
        .filter(|s| sample_matches_sn(s.source_sn, sn_range))
        .collect();

    // `_max`: keep the newest `m` (the ring tail), still replied oldest-first.
    if let Some(m) = max {
        if matched.len() > m {
            matched = matched.split_off(matched.len() - m);
        }
    }

    for s in matched {
        out.reply_keyed_stamped(&s.keyexpr, &s.payload, None, &s.timestamp);
    }
}

/// Extract a `key=value` selector value from the raw URL-style query
/// parameter bytes (`_sn=10..20&_max=5`). `None` when absent or non-UTF-8.
fn param_value<'a>(params: Option<&'a [u8]>, key: &str) -> Option<&'a str> {
    let s = core::str::from_utf8(params?).ok()?;
    s.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then_some(v)
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn param_value_extracts_selectors() {
        assert_eq!(
            param_value(Some(b"_sn=10..20&_max=5"), "_sn"),
            Some("10..20")
        );
        assert_eq!(param_value(Some(b"_sn=10..20&_max=5"), "_max"), Some("5"));
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
        use wz_session_core::sample::EncodingHint;

        #[derive(Default)]
        struct Rec {
            keyed: Vec<(String, Vec<u8>)>,
        }
        impl ReplyOut for Rec {
            fn reply(&mut self, payload: &[u8]) {
                self.keyed.push((String::new(), payload.to_vec()));
            }
            fn reply_keyed_stamped(
                &mut self,
                keyexpr: &str,
                payload: &[u8],
                _encoding: Option<&EncodingHint>,
                _timestamp: &TimestampHint,
            ) {
                self.keyed.push((keyexpr.to_string(), payload.to_vec()));
            }
            fn reply_del(&mut self) {}
            fn reply_err(&mut self, _: Option<u32>, _: Option<&str>, _: &[u8]) {}
            fn with_responder(&mut self, _: &[u8], _: u32) {}
            fn clear_responder(&mut self) {}
            fn responder(&self) -> Option<(&[u8], u32)> {
                None
            }
        }

        let mut ring = VecDeque::new();
        for sn in 0..3u32 {
            ring.push_back(CachedSample {
                keyexpr: "demo/k".to_string(),
                payload: vec![sn as u8],
                source_sn: Some(sn),
                timestamp: TimestampHint {
                    time: 100 + sn as u64,
                    zid: vec![1],
                },
            });
        }
        let q = |params: Option<&'static [u8]>| BorrowedQuery {
            keyexpr: "demo/k",
            parameters: params,
            attachment: None,
            source_info: None,
            rid: 0,
            is_local: true,
        };

        // `_sn=1..` → sn 1 and 2, oldest-first.
        let mut out = Rec::default();
        answer_from_ring(&ring, &q(Some(b"_sn=1..")), &mut out);
        assert_eq!(
            out.keyed,
            vec![
                ("demo/k".to_string(), vec![1]),
                ("demo/k".to_string(), vec![2])
            ]
        );

        // `_max=1` → only the newest (sn 2).
        let mut out = Rec::default();
        answer_from_ring(&ring, &q(Some(b"_max=1")), &mut out);
        assert_eq!(out.keyed, vec![("demo/k".to_string(), vec![2])]);

        // No params → all three.
        let mut out = Rec::default();
        answer_from_ring(&ring, &q(None), &mut out);
        assert_eq!(out.keyed.len(), 3);
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
}
