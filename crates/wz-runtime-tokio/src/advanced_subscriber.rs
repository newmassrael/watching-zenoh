// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y70 — `ext-pubsub-advanced-subscriber` (§5.25): the per-source
//! ordering / de-duplication subscriber that consumes the `SourceInfo`
//! sequence numbers an [`crate::advanced_publisher::AdvancedPublisher`]
//! stamps.
//!
//! The wz mirror of zenoh-ext `advanced_subscriber.rs`'s `handle_sample`
//! state machine (advanced_subscriber.rs:476-566). It wraps a plain
//! subscriber and tracks, per source, the last in-order delivered marker:
//!
//! - **Sequenced** (the sample carries `SourceInfo(zid, eid, sn)`): keyed
//!   by `(zid, eid)`. `sn == last + 1` delivers in order; `sn > last + 1`
//!   is a forward GAP — it fires a [`Miss`] callback (`nb = sn - last - 1`)
//!   then delivers and advances (the no-retransmission path); `sn <= last`
//!   is a duplicate / out-of-order-late sample and is DROPPED.
//! - **No sequenced source-id**: delivered immediately, no de-duplication.
//!
//! The TIMESTAMPED de-duplication path (a `Sequencing::Timestamp`
//! publisher's samples, keyed by the timestamp id) is DEFERRED to the
//! round that composes + tests a Timestamp-mode publisher. Its ordering
//! primitive — `wz_session_core::sample::timestamp_strictly_newer` — is now
//! a shared SSOT (R311y73 lifted it out of the storage-backend-gated
//! `storage_state` so this ext-pubsub atom can consume it WITHOUT pulling
//! storage), so the path is unblocked: when built it imports that fn. This
//! round builds the SEQUENCED path the `SequenceNumber` publisher (the
//! R311y69 default) produces.
//!
//! ## Scope vs zenoh (the reorder buffer is deferred to advanced-recovery)
//!
//! zenoh's `handle_sample` also BUFFERS a forward gap into a
//! `pending_samples` BTreeMap when retransmission is on, to be back-filled
//! by a recovery query, and buffers during a startup history query. Both
//! the buffer and its drainers (`deliver_and_flush`, the recovery `get`,
//! the history gating) are only FUNCTIONAL once
//! `ext-pubsub-advanced-recovery` / `-advanced-history` compose their
//! query machinery — without a drainer a buffered sample would never be
//! delivered. So this round builds the faithful SUBSET (retransmission
//! off: gap -> Miss + deliver): the per-source `last_delivered` tracking,
//! in-order delivery, gap detection, and duplicate drop. The reorder
//! buffer + the `retransmission` flag land in the recovery round WITH the
//! query that drains them (each structure built with its consumer — the
//! same sequencing as the R311y69 cache reply-seam deferral).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;
use wz_session_core::sample::Sample;
use wz_session_core::sink::SampleView;

use crate::session::{Session, SubscribeError, SubscribeOptions, Subscriber, Unicast};
use crate::session_glue::SessionLinkActions;

/// A detected gap in a sequenced source's stream: `nb` samples between the
/// last in-order delivery and the just-received `sn` were missed. Mirror
/// of zenoh-ext `Miss` (advanced_subscriber.rs:1409-1427); `source` is
/// split into the `(zid, eid)` the wz `SourceInfo` carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Miss {
    /// The missing source's zenoh id (the meaningful `zid_prefix` bytes).
    pub source_zid: Vec<u8>,
    /// The missing source's entity id.
    pub source_eid: u32,
    /// How many samples were skipped (`sn - last_delivered - 1`).
    pub nb: u32,
}

/// Per-source last-in-order-delivered tracking + the user callbacks.
/// Behind an `Arc<Mutex>` because the session may fire the subscriber
/// callback from different worker threads (the storage-service idiom).
struct State {
    /// `(zid, eid)` -> last in-order delivered sequence number.
    sequenced: HashMap<(Vec<u8>, u32), u32>,
    on_sample: Box<dyn FnMut(Sample) + Send>,
    on_miss: Box<dyn FnMut(Miss) + Send>,
}

impl State {
    /// The zenoh `handle_sample` state machine (retransmission-off subset).
    fn handle(&mut self, view: &dyn SampleView) {
        if let Some(source_info) = view.source_info() {
            let key = (source_info.zid_prefix().to_vec(), source_info.eid);
            let sn = source_info.sn;
            match self.sequenced.get(&key).copied() {
                // First sample from this source: deliver, record.
                None => {
                    (self.on_sample)(Sample::from_view(view));
                    self.sequenced.insert(key, sn);
                }
                // In order: deliver, advance.
                Some(last) if sn == last.wrapping_add(1) => {
                    (self.on_sample)(Sample::from_view(view));
                    self.sequenced.insert(key, sn);
                }
                // Forward gap (no retransmission): report the miss, deliver,
                // advance past it (zenoh advanced_subscriber.rs:521-535).
                Some(last) if sn > last => {
                    (self.on_miss)(Miss {
                        source_zid: key.0.clone(),
                        source_eid: key.1,
                        nb: sn - last - 1,
                    });
                    (self.on_sample)(Sample::from_view(view));
                    self.sequenced.insert(key, sn);
                }
                // `sn <= last`: duplicate / out-of-order-late — drop.
                Some(_) => {}
            }
        } else {
            // No sequenced source-id: deliver, no de-duplication (the
            // timestamped-dedup path is deferred — see the module docs).
            (self.on_sample)(Sample::from_view(view));
        }
    }
}

/// A live advanced subscriber bound to a [`Session`]: owns the wrapped
/// plain [`Subscriber`] (RAII: dropping it undeclares) whose callback runs
/// the per-source ordering / de-duplication state machine.
pub struct AdvancedSubscriber<R: SessionRuntime = crate::runtime_impl::TokioRuntime> {
    _subscriber: Subscriber<R>,
}

impl<R: SessionRuntime> AdvancedSubscriber<R> {
    /// Declare an advanced subscriber on `keyexpr`. `on_sample` receives
    /// each in-order / de-duplicated [`Sample`]; `on_miss` receives a
    /// [`Miss`] for every detected forward gap on a sequenced source.
    pub fn declare<T, OnSample, OnMiss>(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        on_sample: OnSample,
        on_miss: OnMiss,
    ) -> Result<Self, SubscribeError>
    where
        T: TimeSource + 'static,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        SessionLinkActions<R, T>: Send + Sync + 'static,
        OnSample: FnMut(Sample) + Send + 'static,
        OnMiss: FnMut(Miss) + Send + 'static,
    {
        let state = Arc::new(Mutex::new(State {
            sequenced: HashMap::new(),
            on_sample: Box::new(on_sample),
            on_miss: Box::new(on_miss),
        }));
        let cb_state = Arc::clone(&state);
        let subscriber = session.declare_subscriber(
            keyexpr,
            SubscribeOptions::default(),
            move |view: &dyn SampleView| {
                cb_state
                    .lock()
                    .expect("advanced subscriber state mutex poisoned")
                    .handle(view);
            },
        )?;
        Ok(Self {
            _subscriber: subscriber,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::observer::ApplicationLayerObserver;
    use crate::runtime_impl::TokioTime;
    use crate::session::{PublishOptions, TokioSession};
    use wz_session_core::locality::Locality;
    use wz_session_core::sample::SourceInfo;

    /// Drive the subscriber with one controlled sequence number under a
    /// fixed synthetic source identity. These are STATE-MACHINE unit tests:
    /// they inject specific sns (incl a deliberate gap + a duplicate) that a
    /// real, always-incrementing `AdvancedPublisher` cannot produce, so they
    /// synthesize the wire `SourceInfo` directly. The zid value is arbitrary
    /// — SessionLocal loopback applies NO self-echo dedup (that is gated
    /// `if is_remote` only, pubsub.rs; proven by
    /// `pubsub::tests::local_publish_ignores_own_zid_dedup`), so own-vs-remote
    /// zid is irrelevant here. The genuine producer->consumer link is the
    /// separate composed test (`composed_advanced_publisher_to_subscriber_*`).
    fn put_sequenced(session: &TokioSession, sn: u32) -> usize {
        session
            .publish(
                "demo/data",
                &[sn as u8],
                PublishOptions::put()
                    .with_locality(Locality::SessionLocal)
                    .with_source_info(SourceInfo::new(&[0x02], 7, sn)),
            )
            .expect("loopback sequenced publish")
    }

    /// State-machine unit test (synthetic source, controlled sns): a source
    /// feeds 0,1, then 3 (a gap at 2), then a duplicate 1. The advanced
    /// subscriber must deliver 0,1,3 in order, fire one Miss(nb=1) on the
    /// 1->3 gap, and DROP the duplicate.
    #[test]
    fn sequenced_in_order_gap_miss_and_dedup() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let delivered = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let misses = Arc::new(Mutex::new(Vec::<Miss>::new()));
        let d = Arc::clone(&delivered);
        let m = Arc::clone(&misses);
        let _sub = AdvancedSubscriber::declare(
            &session,
            "demo/data",
            move |sample: Sample| d.lock().unwrap().push(sample.payload.clone()),
            move |miss: Miss| m.lock().unwrap().push(miss),
        )
        .expect("advanced subscriber declares against the test link");

        put_sequenced(&session, 0);
        put_sequenced(&session, 1);
        put_sequenced(&session, 3); // gap: 2 was missed
        put_sequenced(&session, 1); // duplicate / old

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![vec![0u8], vec![1u8], vec![3u8]],
            "0,1,3 delivered in order; the duplicate 1 dropped"
        );
        let got_misses = misses.lock().unwrap().clone();
        assert_eq!(
            got_misses,
            vec![Miss {
                source_zid: vec![0x02],
                source_eid: 7,
                nb: 1,
            }],
            "one miss reported for the single skipped sample (sn 2)"
        );
    }

    /// A NEW source's first sample always delivers (no last marker yet),
    /// and a second source is tracked independently.
    #[test]
    fn distinct_sources_track_independently() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let delivered = Arc::new(Mutex::new(Vec::<(u32, u8)>::new()));
        let d = Arc::clone(&delivered);
        let _sub = AdvancedSubscriber::declare(
            &session,
            "demo/data",
            move |sample: Sample| {
                let eid = sample.source_info.as_ref().map(|s| s.eid).unwrap_or(0);
                d.lock().unwrap().push((eid, sample.payload[0]));
            },
            |_miss: Miss| {},
        )
        .expect("advanced subscriber declares");

        // Source eid=7 sends sn 0; source eid=8 sends sn 5 (its first — no
        // gap reported, a new source has no last marker).
        let send = |eid: u32, sn: u32, v: u8| {
            session
                .publish(
                    "demo/data",
                    &[v],
                    PublishOptions::put()
                        .with_locality(Locality::SessionLocal)
                        .with_source_info(SourceInfo::new(&[0x02], eid, sn)),
                )
                .expect("publish");
        };
        send(7, 0, 0xA0);
        send(8, 5, 0xB0);
        send(7, 1, 0xA1);

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![(7, 0xA0), (8, 0xB0), (7, 0xA1)],
            "each source's stream is ordered independently; eid=8's first sn=5 delivers with no miss"
        );
    }

    /// Composed producer->consumer e2e — the HIGH-priority fix from the
    /// R311y70 session review (the prior tests exercised each half in
    /// isolation; this co-compiles BOTH atoms and proves the seqnum
    /// producer/consumer contract that is the atom's whole point). A REAL
    /// `AdvancedPublisher` (its own zid + `SequenceNumber` sequencing) feeds
    /// a REAL `AdvancedSubscriber` on one session over the loopback
    /// (`Locality::Any` -> the local subscriber fires; session-API loopback,
    /// no wire codec). A contiguous 0,1,2 publish must deliver 0,1,2 in
    /// order with zero misses.
    #[cfg(all(
        feature = "ext-pubsub-advanced-publisher",
        feature = "pubsub-allow-loop"
    ))]
    #[test]
    fn composed_advanced_publisher_to_subscriber_in_order() {
        use crate::advanced_cache::CacheConfig;
        use crate::advanced_publisher::{AdvancedPublisher, AdvancedPublisherOptions, Sequencing};

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let misses = Arc::new(Mutex::new(0usize));
        let d = Arc::clone(&delivered);
        let m = Arc::clone(&misses);
        let _sub = AdvancedSubscriber::declare(
            &session,
            "demo/data",
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
            move |_miss: Miss| *m.lock().unwrap() += 1,
        )
        .expect("advanced subscriber declares");

        // A REAL publisher with its OWN zid (its genuine identity) +
        // SequenceNumber sequencing; default Locality::Any -> the loopback
        // leg fires the local subscriber (own-zid loopback delivers — no
        // self-echo dedup on the loopback path).
        let publisher = AdvancedPublisher::declare(
            &session,
            "demo/data",
            AdvancedPublisherOptions {
                sequencing: Sequencing::SequenceNumber,
                cache: Some(CacheConfig { max_samples: 8 }),
                publisher_detection: true,
            },
            vec![0x09],
        )
        .expect("advanced publisher declares");

        for v in 0u8..3 {
            publisher.put(&[v]).expect("advanced put");
        }

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0u8, 1, 2],
            "the real publisher's incrementing seqnums delivered in order by the real subscriber"
        );
        assert_eq!(
            *misses.lock().unwrap(),
            0,
            "a contiguous 0,1,2 stream has no gaps -> no Miss"
        );
    }
}
