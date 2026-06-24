// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311uy — the storage service DRIVER (§5.11 storage domain, atom 3/4):
//! the AP-side runtime binding that turns the runtime-agnostic storage
//! kernel into a live service on a [`Session`].
//!
//! [`wz_session_core::storage_backend`] (atom 1) is the pluggable store and
//! [`wz_session_core::storage_state::StorageState`] (atom 2) is the
//! newer-wins gate + query-match logic — both pure no_std. This module is
//! their tokio binding: a [`StorageService`] declares a [`Subscriber`] on
//! the storage keyexpr (to capture inbound Put / Delete samples into the
//! gate) and a COMPLETE [`Queryable`] on the same keyexpr (to answer
//! queries from the stored set), holding both handles and a shared
//! `Arc<Mutex<StorageState>>` across the session lifetime.
//!
//! ## zenoh anchor
//!
//! Mirrors zenoh 1.5.0 `StorageService`
//! (`plugins/zenoh-plugin-storage-manager/src/storages_mgt/service.rs`):
//! `declare_subscriber` (service.rs:142-148) + `declare_queryable`
//! `.complete(..)` (service.rs:151-162), and the select loop's two arms
//! (service.rs:170-208): a received sample routes to `process_sample`
//! (here the gate's [`StorageState::apply_sample`]) and a received query
//! routes to `reply_query` (here the gate's [`StorageState::answer_into`]).
//! Both are runtime-agnostic kernel methods (no async / no Session), so a
//! future MCU storage driver reuses the same capture/answer mapping; this
//! module is the thin tokio binding that locks the shared state and
//! delegates. wz's callback-driven observer replaces zenoh's explicit
//! `tokio::select!` — the subscriber / queryable registries fire the two
//! closures, so the "loop" is the session's own drive loop.
//!
//! ## Fallback timestamp (the §5.18 seam)
//!
//! zenoh stamps an un-timestamped sample with the session HLC
//! (`sample.timestamp().cloned().unwrap_or(session.new_timestamp())`,
//! service.rs:182) so newer-wins always has a timestamp. wz routes the same
//! fallback through the §5.18 timestamp-source seam
//! ([`crate::timestamp_source::FallbackStamp`]), built over the storage's
//! `local_zid`. The stamp is the same NTP64 word shape a real publisher's
//! timestamp carries, so a fallback stamp is directly comparable to a real
//! one. This is the deliberate fix for the prior monotonic-counter design,
//! which produced tiny counter values (1, 2, …) that any real NTP64
//! (~10^18) dominated: under newer-wins a single real-timestamped Put then
//! made every subsequent un-timestamped Put lose as Outdated — silent data
//! loss in a mixed-publisher deployment. A wall-clock-magnitude stamp
//! competes fairly by time instead.
//!
//! The source the seam selects (R311xt):
//! - `time-hlc` OFF (default): the bare
//!   [`wall_clock_ntp64`](crate::timestamp_source::wall_clock_ntp64) SSOT. Not
//!   guaranteed monotonic across NTP adjustments, and two un-timestamped
//!   Puts within one fraction-tick collide (same `(time, zid)`, the later
//!   one Replaces).
//! - `time-hlc` ON: an `uhlc::HLC` over that same wall clock — its logical
//!   counter removes both limits (successive stamps strictly increase even
//!   within one physical instant).
//!
//! A sample that DOES carry a timestamp always uses it, so a
//! timestamped-publisher deployment is unaffected by the source choice.
//!
//! ## NON-goals (this atom)
//!
//! Reply-side value timestamps (the reply carries the payload, not the
//! stored version — a get returns the latest value, and the querier does
//! not yet read a per-reply timestamp), the cross-process e2e against a
//! foreign `z_get` (a follow-up `wz-e2e-*` binary over the shared harness,
//! the wz-e2e-queryable pattern), tombstone GC / wildcard-update
//! overriding / `strip_prefix` (the deferred kernel follow-ups named in
//! [`wz_session_core::storage_state`]).

use std::sync::{Arc, Mutex};

use wz_session_core::query_sink::{QueryView, ReplyOut};
// The fallback stamp is now produced by `timestamp_source::FallbackStamp`
// (the §5.18 source seam); `TimestampHint` is referenced directly only by
// the tests below.
#[cfg(test)]
use wz_session_core::sample::TimestampHint;
use wz_session_core::sink::SampleView;
use wz_session_core::storage_backend::{MemoryStorage, StorageBackend};
use wz_session_core::storage_state::StorageState;

use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;

use crate::session::{
    Queryable, QueryableError, QueryableOptions, Session, SubscribeError, SubscribeOptions,
    Subscriber, Unicast,
};
use crate::session_glue::SessionLinkActions;

/// Shared, lockable storage gate over a backend `B`. The subscriber
/// callback locks it to write (capture Put / Delete) and the queryable
/// callback locks it to read (answer a query); `Arc` because the two
/// callbacks each own a clone, `Mutex` because the session may fire them
/// from different worker threads.
type SharedState<B> = Arc<Mutex<StorageState<B>>>;

/// A live storage service bound to a [`Session`]: owns the capture
/// [`Subscriber`], the answering [`Queryable`], and the shared
/// [`StorageState`] over a backend `B` (defaulting to the in-memory
/// `History::Latest` [`MemoryStorage`]). Dropping it undeclares both (the
/// handles' RAII `Drop`), tearing the storage down.
pub struct StorageService<R: SessionRuntime, T: TimeSource, B: StorageBackend = MemoryStorage> {
    state: SharedState<B>,
    // Held for their RAII lifetime: dropping a handle undeclares the
    // subscriber / queryable. The service is the storage's lifetime owner.
    _subscriber: Subscriber<R>,
    _queryable: Queryable<R, T>,
}

impl<R, T, B> StorageService<R, T, B>
where
    R: SessionRuntime,
    T: TimeSource + 'static,
    B: StorageBackend + Send + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    /// Declare a storage on `keyexpr` over `session` backed by an explicit
    /// `backend`: a capture subscriber plus a complete queryable. The
    /// generic form — pass [`MemoryStorage`] for `History::Latest` (or the
    /// [`declare`](StorageService::declare) shorthand) or a
    /// `History::All` backend (`storage-history`'s `HistoryStorage`) for a
    /// version-keeping storage. `local_zid` is the storage's identity for
    /// stamping un-timestamped samples (the fallback `zid`; see the
    /// module-level fallback note) — must be non-empty.
    ///
    /// The queryable is declared COMPLETE
    /// ([`QueryableOptions::with_complete`]): a storage is an authoritative
    /// answerer for its keyexpr, the BestMatching producer signal a router
    /// routes a get to (the query-routing track).
    pub fn declare_with_backend(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        local_zid: Vec<u8>,
        backend: B,
    ) -> Result<Self, StorageServiceError> {
        if local_zid.is_empty() {
            return Err(StorageServiceError::InvalidZid);
        }
        let keyexpr: String = keyexpr.into();
        let state: SharedState<B> = Arc::new(Mutex::new(StorageState::new(backend)));

        // Capture leg: each inbound sample locks the gate and applies it,
        // stamping a fallback wall-clock NTP64 timestamp when the sample
        // carries none (the §5.18 seam) — comparable to a real publisher
        // timestamp, so newer-wins competes fairly (see the module note).
        let sub_state = Arc::clone(&state);
        // The §5.18 timestamp-source seam: with `time-hlc` on, an
        // un-timestamped sample is stamped by the HLC (a logical counter +
        // monotonicity over the wall clock); off, by the bare
        // `wall_clock_ntp64` SSOT. Built once over the storage identity and
        // shared by the (possibly multi-threaded) capture callback.
        let stamper = crate::timestamp_source::FallbackStamp::new(local_zid);
        let subscriber = session.declare_subscriber(
            keyexpr.clone(),
            SubscribeOptions::default(),
            move |view: &dyn SampleView| {
                let mut guard = sub_state.lock().expect("storage state mutex poisoned");
                guard.apply_sample(view, || stamper.stamp());
            },
        )?;

        // Answer leg: each inbound query locks the gate and replies the
        // matching stored entries, each under its own concrete keyexpr.
        let query_state = Arc::clone(&state);
        let queryable = session.declare_queryable(
            keyexpr,
            QueryableOptions::default().with_complete(true),
            move |view: &dyn QueryView, out: &mut dyn ReplyOut| {
                let guard = query_state.lock().expect("storage state mutex poisoned");
                guard.answer_into(view, out);
            },
        )?;

        Ok(Self {
            state,
            _subscriber: subscriber,
            _queryable: queryable,
        })
    }

    /// Read the stored state under the lock — the inspection seam for
    /// tests / admin surfaces (e.g. count stored keys, read a value)
    /// without exposing the `Arc<Mutex<..>>` internals.
    pub fn with_state<F, O>(&self, f: F) -> O
    where
        F: FnOnce(&StorageState<B>) -> O,
    {
        let guard = self.state.lock().expect("storage state mutex poisoned");
        f(&guard)
    }

    /// Clone the shared `Arc<Mutex<StorageState>>` so the replication digest
    /// driver ([`crate::storage_replication_service`]) can digest the SAME
    /// live stored data this storage captures. The replication seam: a
    /// replica's published digest must reflect its storage's actual state, so
    /// the digest publisher and the capture/answer service share one gate
    /// rather than maintaining a second copy.
    #[cfg(feature = "storage-replication")]
    pub fn shared_state(&self) -> Arc<Mutex<StorageState<B>>> {
        Arc::clone(&self.state)
    }
}

impl<R, T> StorageService<R, T, MemoryStorage>
where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    /// Declare an in-memory `History::Latest` storage — the common shape
    /// (newer-wins, one value per key). Shorthand for
    /// [`declare_with_backend`](StorageService::declare_with_backend) with
    /// a fresh [`MemoryStorage`].
    pub fn declare(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        local_zid: Vec<u8>,
    ) -> Result<Self, StorageServiceError> {
        Self::declare_with_backend(session, keyexpr, local_zid, MemoryStorage::new())
    }
}

/// Why a [`StorageService::declare`] failed: a rejected subscriber or
/// queryable declaration, or an invalid `local_zid`.
#[derive(Debug)]
pub enum StorageServiceError {
    /// The capture subscriber declaration was rejected (e.g. the outbound
    /// keyexpr failed the pico-safety gate, or the transport rejected the
    /// announce).
    Subscribe(SubscribeError),
    /// The answering queryable declaration was rejected (e.g.
    /// `query-queryable` is disabled, or the announce was rejected).
    Queryable(QueryableError),
    /// `local_zid` was empty (the fallback timestamp needs a non-empty
    /// identity for its newer-wins zid tiebreak).
    InvalidZid,
}

impl From<SubscribeError> for StorageServiceError {
    fn from(e: SubscribeError) -> Self {
        StorageServiceError::Subscribe(e)
    }
}

impl From<QueryableError> for StorageServiceError {
    fn from(e: QueryableError) -> Self {
        StorageServiceError::Queryable(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::query_sink::BorrowedQuery;
    use wz_session_core::sample::Sample;
    use wz_session_core::storage_backend::StorageInsertionResult;

    fn ts(time: u64, zid: u8) -> TimestampHint {
        TimestampHint {
            time,
            zid: vec![zid],
        }
    }

    fn fresh() -> StorageState<MemoryStorage> {
        StorageState::new(MemoryStorage::new())
    }

    // A recording ReplyOut: captures (keyexpr, payload) per reply so a
    // test can assert the per-key fan. Uses the default `reply` for the
    // bound-keyexpr path and the override `reply_keyed` for the per-key
    // path.
    #[derive(Default)]
    struct RecordingReplyOut {
        keyed: Vec<(String, Vec<u8>)>,
        // (keyexpr, encoding.packed_id, timestamp.time, payload) for each
        // stamped reply — the full metadata the driver emits per version.
        stamped: Vec<(String, Option<u32>, u64, Vec<u8>)>,
    }
    impl ReplyOut for RecordingReplyOut {
        fn reply(&mut self, payload: &[u8]) {
            self.keyed.push((String::new(), payload.to_vec()));
        }
        fn reply_keyed(&mut self, keyexpr: &str, payload: &[u8]) {
            self.keyed.push((keyexpr.to_string(), payload.to_vec()));
        }
        fn reply_keyed_stamped(
            &mut self,
            keyexpr: &str,
            payload: &[u8],
            encoding: Option<&wz_session_core::sample::EncodingHint>,
            timestamp: &TimestampHint,
        ) {
            // Keep `keyed` populated (per-key fan assertions) AND record the
            // full metadata separately (per-version encoding + timestamp).
            self.keyed.push((keyexpr.to_string(), payload.to_vec()));
            self.stamped.push((
                keyexpr.to_string(),
                encoding.map(|e| e.packed_id),
                timestamp.time,
                payload.to_vec(),
            ));
        }
        fn reply_del(&mut self) {}
        fn reply_err(&mut self, _encoding_id: Option<u32>, _schema: Option<&str>, _payload: &[u8]) {
        }
        fn with_responder(&mut self, _zid: &[u8], _eid: u32) {}
        fn clear_responder(&mut self) {}
        fn responder(&self) -> Option<(&[u8], u32)> {
            None
        }
    }

    fn query(keyexpr: &str) -> BorrowedQuery<'_> {
        BorrowedQuery {
            keyexpr,
            parameters: None,
            attachment: None,
            source_info: None,
            rid: 1,
            is_local: false,
        }
    }

    #[test]
    fn apply_sample_put_uses_the_carried_timestamp_not_the_fallback() {
        let mut state = fresh();
        let sample = Sample::new_put("demo/a", vec![1, 2, 3]).with_timestamp(ts(10, 1));
        state.apply_sample(&sample, || {
            panic!("fallback must not run for a stamped sample")
        });
        let stored = state.get("demo/a").expect("stored after put");
        assert_eq!(stored.payload, vec![1, 2, 3]);
        assert_eq!(stored.timestamp, ts(10, 1));
    }

    #[test]
    fn apply_sample_put_without_timestamp_uses_the_fallback() {
        let mut state = fresh();
        let sample = Sample::new_put("demo/a", vec![9]);
        state.apply_sample(&sample, || ts(7, 9));
        let stored = state.get("demo/a").expect("stored after put");
        assert_eq!(
            stored.timestamp,
            ts(7, 9),
            "the fallback stamp versions the value"
        );
    }

    #[test]
    fn apply_sample_del_removes_through_the_gate() {
        let mut state = fresh();
        state.apply_sample(
            &Sample::new_put("demo/a", vec![1]).with_timestamp(ts(10, 1)),
            || unreachable!(),
        );
        state.apply_sample(
            &Sample::new_del("demo/a").with_timestamp(ts(20, 1)),
            || unreachable!(),
        );
        assert!(state.get("demo/a").is_none(), "del removed the value");
    }

    #[test]
    fn apply_sample_routes_outdated_through_the_gate() {
        // A second put with an older timestamp is dropped by the gate; the
        // driver does not bypass newer-wins.
        let mut state = fresh();
        state.apply_sample(
            &Sample::new_put("demo/a", vec![9]).with_timestamp(ts(100, 1)),
            || unreachable!(),
        );
        state.apply_sample(
            &Sample::new_put("demo/a", vec![1]).with_timestamp(ts(1, 1)),
            || unreachable!(),
        );
        assert_eq!(
            state.get("demo/a").unwrap().payload,
            vec![9],
            "outdated put dropped"
        );
        assert_eq!(
            state.get("demo/a").unwrap().timestamp,
            ts(100, 1),
            "newer value retained"
        );
    }

    #[test]
    fn answer_query_wildcard_replies_each_matching_key_under_its_own_keyexpr() {
        let mut state = fresh();
        assert_eq!(
            state.process_put("demo/a", vec![1], None, ts(10, 1)),
            StorageInsertionResult::Inserted
        );
        state.process_put("demo/b", vec![2], None, ts(10, 1));
        state.process_put("other/c", vec![3], None, ts(10, 1));

        let mut out = RecordingReplyOut::default();
        state.answer_into(&query("demo/*"), &mut out);

        let mut got = out.keyed;
        got.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            got,
            vec![
                (String::from("demo/a"), vec![1]),
                (String::from("demo/b"), vec![2]),
            ],
            "each reply carries its own concrete keyexpr; other/c is not matched"
        );
    }

    #[test]
    fn answer_query_exact_key_replies_the_single_value() {
        let mut state = fresh();
        state.process_put("demo/a", vec![42], None, ts(10, 1));
        let mut out = RecordingReplyOut::default();
        state.answer_into(&query("demo/a"), &mut out);
        assert_eq!(out.keyed, vec![(String::from("demo/a"), vec![42])]);
    }

    #[test]
    fn answer_query_does_not_reply_a_deleted_key() {
        let mut state = fresh();
        state.process_put("demo/a", vec![1], None, ts(10, 1));
        state.process_delete("demo/a", ts(20, 1));
        let mut out = RecordingReplyOut::default();
        state.answer_into(&query("demo/**"), &mut out);
        assert!(out.keyed.is_empty(), "a deleted key is not replied");
    }

    // A REAL live-session test of the driver wiring (not just the kernel
    // methods): build a session, declare an actual StorageService (the
    // routed declare_subscriber + complete queryable), then a loopback
    // publish must reach the capture subscriber and land in the store,
    // observed through `with_state`. Exercises StorageService::declare, the
    // Arc<Mutex> shared state, the capture closure, and with_state — the
    // session-wiring the free-function tests above cannot cover. Mirrors
    // `session::tests::declared_subscriber_fires_on_loopback_publish`.
    #[cfg(all(feature = "declare-subscriber", feature = "pubsub-allow-loop"))]
    #[test]
    fn declared_storage_captures_a_loopback_publish_observed_via_with_state() {
        use crate::observer::ApplicationLayerObserver;
        use crate::runtime_impl::TokioTime;
        use crate::session::{PublishOptions, TokioSession};
        use wz_session_core::locality::Locality;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let storage = StorageService::declare(&session, "demo/**", vec![0x01])
            .expect("storage declare succeeds against the test link");

        let fired = session
            .publish(
                "demo/a",
                b"v1",
                PublishOptions::put().with_locality(Locality::SessionLocal),
            )
            .expect("loopback publish");
        assert_eq!(fired, 1, "the storage's capture subscriber fired once");

        storage.with_state(|st| {
            assert_eq!(
                st.get("demo/a").map(|d| d.payload.clone()),
                Some(b"v1".to_vec()),
                "the declared storage captured the loopback publish into the store"
            );
        });
    }

    // The History::All driver path needs the storage-history backend.
    #[cfg(feature = "storage-history")]
    mod history {
        use super::*;
        use wz_session_core::storage_history::HistoryStorage;

        #[test]
        fn answer_query_replies_every_version_of_a_history_all_key() {
            let mut state = StorageState::new(HistoryStorage::new());
            // Three versions of one key (an older one arrives out of order).
            state.apply_sample(
                &Sample::new_put("demo/a", vec![3]).with_timestamp(ts(30, 1)),
                || unreachable!(),
            );
            state.apply_sample(
                &Sample::new_put("demo/a", vec![1]).with_timestamp(ts(10, 1)),
                || unreachable!(),
            );
            state.apply_sample(
                &Sample::new_put("demo/a", vec![2]).with_timestamp(ts(20, 1)),
                || unreachable!(),
            );

            let mut out = RecordingReplyOut::default();
            state.answer_into(&query("demo/a"), &mut out);
            // All three versions replied, each under the concrete key,
            // ordered by timestamp (the backend keeps them sorted).
            assert_eq!(
                out.keyed,
                vec![
                    (String::from("demo/a"), vec![1]),
                    (String::from("demo/a"), vec![2]),
                    (String::from("demo/a"), vec![3]),
                ],
                "History::All replies every version, not just the latest"
            );
        }

        #[test]
        fn answer_query_stamps_each_version_with_its_value_encoding_and_timestamp() {
            use wz_session_core::sample::EncodingHint;
            // Each version reply carries the timestamp that orders it AND the
            // stored value's encoding, so a querier gets the value back
            // exactly as published (zenoh .encoding(..).timestamp(..)).
            let mut state = StorageState::new(HistoryStorage::new());
            state.apply_sample(
                &Sample::new_put("demo/a", vec![1])
                    .with_timestamp(ts(10, 1))
                    .with_encoding(EncodingHint {
                        packed_id: 4,
                        schema: None,
                    }),
                || unreachable!(),
            );
            state.apply_sample(
                &Sample::new_put("demo/a", vec![2]).with_timestamp(ts(20, 1)),
                || unreachable!(),
            );

            let mut out = RecordingReplyOut::default();
            state.answer_into(&query("demo/a"), &mut out);
            assert_eq!(
                out.stamped,
                vec![
                    // v1 carried encoding 4 + ts 10; v2 no encoding + ts 20.
                    (String::from("demo/a"), Some(4), 10, vec![1]),
                    (String::from("demo/a"), None, 20, vec![2]),
                ],
                "each version reply carries its own encoding + timestamp, in order"
            );
        }
    }
}
