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
use wz_session_core::storage_config::StorageConfig;
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

/// R311y59 (§5.24 `storage-mgr-complete-flag`) — resolve the storage queryable's
/// COMPLETE bit. Under the cfg the configured value drives it (a storage may be
/// declared partial / non-authoritative); with the gate compiled out the queryable
/// is always COMPLETE (the pre-y59 behavior — a storage is the authoritative
/// answerer for its keyexpr). The library-resident per-call gate, the storage twin
/// of the adminspace `admin_write_permit` idiom; [`StorageService::declare_with_backend`]
/// feeds the result to [`QueryableOptions::with_complete`].
#[cfg(feature = "storage-mgr-complete-flag")]
fn storage_queryable_complete(configured: bool) -> bool {
    configured
}
#[cfg(not(feature = "storage-mgr-complete-flag"))]
fn storage_queryable_complete(configured: bool) -> bool {
    let _ = configured;
    true
}

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
    /// Declare a storage on `session` from a [`StorageConfig`], backed by an
    /// explicit `backend`: a capture subscriber plus a queryable. The config
    /// supplies the storage's `key_expr` (the keyexpr it captures + answers
    /// on), `complete` flag, and `strip_prefix` (R311y61 — the mount-relative
    /// key transform). The config's `name` / `volume_id` / `garbage_collection`
    /// are the storage MANAGER's concern and are NOT read here. The generic
    /// form — pass [`MemoryStorage`] for `History::Latest` (or the
    /// [`declare`](StorageService::declare) shorthand), a `History::All`
    /// backend (`storage-history`'s `HistoryStorage`), or a volume-created
    /// `Box<dyn StorageBackend + Send>`
    /// ([`crate::storage_service`] composition). `local_zid` is the storage's
    /// identity for stamping un-timestamped samples (the fallback `zid`; see
    /// the module-level fallback note) — must be non-empty.
    ///
    /// The queryable is declared COMPLETE
    /// ([`QueryableOptions::with_complete`]) when `config.complete` is `true`: a
    /// storage is then an authoritative answerer for its keyexpr, the
    /// BestMatching producer signal a router routes a get to (the query-routing
    /// track). R311y59 — under `storage-mgr-complete-flag` a `false`
    /// `config.complete` declares a PARTIAL storage (zenoh
    /// `StorageConfig.complete`); with that gate off the value is ignored and
    /// the queryable is always complete (the pre-y59 behavior). R311y61 —
    /// `complete` now flows from the config, retiring the prior standalone
    /// `complete` parameter.
    pub fn declare_with_backend(
        session: &Session<R, T, Unicast>,
        config: &StorageConfig,
        local_zid: Vec<u8>,
        backend: B,
    ) -> Result<Self, StorageServiceError> {
        if local_zid.is_empty() {
            return Err(StorageServiceError::InvalidZid);
        }
        let keyexpr: String = config.key_expr.clone();
        // The newer-wins gate over the backend, with the config's `strip_prefix`
        // applied to the live capture + query key path (R311y61): a stored key
        // is held RELATIVE to the mount point, and restored to its full keyexpr
        // on a query reply. Without the `storage-mgr-strip-prefix` feature the
        // prefix is ignored and keys are stored verbatim.
        #[cfg(feature = "storage-mgr-strip-prefix")]
        let state: SharedState<B> = Arc::new(Mutex::new(StorageState::with_strip_prefix(
            backend,
            config.strip_prefix.clone(),
        )));
        #[cfg(not(feature = "storage-mgr-strip-prefix"))]
        let state: SharedState<B> = Arc::new(Mutex::new(StorageState::new(backend)));

        // Capture leg: each inbound sample locks the gate and applies it,
        // stamping a fallback wall-clock NTP64 timestamp when the sample
        // carries none (the §5.18 seam) — comparable to a real publisher
        // timestamp, so newer-wins competes fairly (see the module note).
        let sub_state = Arc::clone(&state);
        // The §5.18 timestamp-source seam: with `time-hlc` on AND this node's
        // role timestamping, an un-timestamped sample is stamped by the NODE's
        // HLC (a logical counter + monotonicity over the wall clock); otherwise
        // by the bare `wall_clock_ntp64` SSOT. Built once over the storage
        // identity and shared by the (possibly multi-threaded) capture callback.
        //
        // R311y450 — the clock is BORROWED from the session, not built here.
        // This site and `advanced_publisher`'s each used to construct one from
        // the same node zid, which put two HLCs with one `uhlc::ID` and separate
        // `last_time` on any `time-hlc,ext-pubsub-advanced-publisher` build.
        // Matches how zenoh's own storage plugin reaches the clock — through the
        // session (`Session::new_timestamp()`, `zenoh/src/api/session.rs:833`,
        // used at `plugins/zenoh-plugin-storage-manager/src/storages_mgt/service.rs:182`).
        let stamper =
            crate::timestamp_source::FallbackStamp::new(local_zid, session.node_hlc().clone());
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
            QueryableOptions::default().with_complete(storage_queryable_complete(config.complete)),
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

    /// Clone the shared `Arc<Mutex<StorageState>>` so an external periodic
    /// driver can act on the SAME live stored data this storage captures — the
    /// digest publisher ([`crate::storage_replication_service`], which must
    /// digest the actual state) and the garbage collector
    /// ([`crate::storage_gc_service`], R311wt slice 4, which sweeps the same
    /// wildcard registries). One shared gate rather than a second copy. Widened
    /// from `storage-replication` to also cover `storage-mgr-garbage-collection`
    /// (the GC driver is caller-spawned over this Arc, mirroring the digest
    /// publisher — StorageService itself does not own the timer).
    #[cfg(any(
        feature = "storage-replication",
        feature = "storage-mgr-garbage-collection"
    ))]
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
    /// Declare an in-memory `History::Latest` storage from a [`StorageConfig`]
    /// — the common shape (newer-wins, one value per key). Shorthand for
    /// [`declare_with_backend`](StorageService::declare_with_backend) with
    /// a fresh [`MemoryStorage`]; `complete` / `strip_prefix` flow from the
    /// config exactly as the generic form.
    pub fn declare(
        session: &Session<R, T, Unicast>,
        config: &StorageConfig,
        local_zid: Vec<u8>,
    ) -> Result<Self, StorageServiceError> {
        Self::declare_with_backend(session, config, local_zid, MemoryStorage::new())
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

    #[test]
    fn queryable_complete_resolves_per_gate() {
        // R311y59 — the storage-mgr-complete-flag gate (the storage twin of the
        // adminspace admin_write_permit idiom): under the cfg the configured value
        // drives the queryable's COMPLETE bit; with the gate compiled out the
        // queryable is always complete (the pre-y59 authoritative behavior).
        #[cfg(feature = "storage-mgr-complete-flag")]
        {
            assert!(storage_queryable_complete(true));
            assert!(
                !storage_queryable_complete(false),
                "a PARTIAL storage is declarable under the gate"
            );
        }
        #[cfg(not(feature = "storage-mgr-complete-flag"))]
        {
            assert!(storage_queryable_complete(true));
            assert!(
                storage_queryable_complete(false),
                "gate elided -> always complete"
            );
        }
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
            payload: None,
            encoding: None,
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
        let stored = state.get(Some("demo/a")).expect("stored after put");
        assert_eq!(stored.payload, vec![1, 2, 3]);
        assert_eq!(stored.timestamp, ts(10, 1));
    }

    #[test]
    fn apply_sample_put_without_timestamp_uses_the_fallback() {
        let mut state = fresh();
        let sample = Sample::new_put("demo/a", vec![9]);
        state.apply_sample(&sample, || ts(7, 9));
        let stored = state.get(Some("demo/a")).expect("stored after put");
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
        assert!(state.get(Some("demo/a")).is_none(), "del removed the value");
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
            state.get(Some("demo/a")).unwrap().payload,
            vec![9],
            "outdated put dropped"
        );
        assert_eq!(
            state.get(Some("demo/a")).unwrap().timestamp,
            ts(100, 1),
            "newer value retained"
        );
    }

    #[test]
    fn answer_query_wildcard_replies_each_matching_key_under_its_own_keyexpr() {
        let mut state = fresh();
        assert_eq!(
            state.process_put(Some("demo/a"), vec![1], None, ts(10, 1)),
            StorageInsertionResult::Inserted
        );
        state.process_put(Some("demo/b"), vec![2], None, ts(10, 1));
        state.process_put(Some("other/c"), vec![3], None, ts(10, 1));

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
        state.process_put(Some("demo/a"), vec![42], None, ts(10, 1));
        let mut out = RecordingReplyOut::default();
        state.answer_into(&query("demo/a"), &mut out);
        assert_eq!(out.keyed, vec![(String::from("demo/a"), vec![42])]);
    }

    #[test]
    fn answer_query_does_not_reply_a_deleted_key() {
        let mut state = fresh();
        state.process_put(Some("demo/a"), vec![1], None, ts(10, 1));
        state.process_delete(Some("demo/a"), ts(20, 1));
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

        let storage = StorageService::declare(
            &session,
            &StorageConfig::new("demo", "demo/**", "mem"),
            vec![0x01],
        )
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
                st.get(Some("demo/a")).map(|d| d.payload.clone()),
                Some(b"v1".to_vec()),
                "the declared storage captured the loopback publish into the store"
            );
        });
    }

    // R311y61 — the §5.24 COMPOSITION proof: a strip-configured StorageConfig
    // drives a LIVE StorageService over a Volume-created backend, end to end. A
    // loopback publish UNDER the mount is captured into the backend under the
    // STRIPPED (relative) key, and a query RESTORES the full keyexpr on the
    // reply — proving Volume(create_storage) + StorageConfig(key_expr / complete
    // / strip_prefix) + the live capture/answer service COMPOSE (closing the
    // §5.24 "atoms built but unwired into a live storage path" gap). Gated on
    // `storage-mgr-strip-prefix`: without it `declare_with_backend` ignores the
    // prefix and the storage would hold the full key.
    #[cfg(all(
        feature = "declare-subscriber",
        feature = "pubsub-allow-loop",
        feature = "storage-mgr-strip-prefix"
    ))]
    #[test]
    fn strip_configured_storage_captures_stripped_and_restores_on_query() {
        use crate::observer::ApplicationLayerObserver;
        use crate::reply_sink::ReplyView;
        use crate::runtime_impl::TokioTime;
        use crate::session::{PublishOptions, QueryOptions, TokioSession};
        use wz_session_core::locality::Locality;
        use wz_session_core::storage_volume::{MemoryVolume, Volume};

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        // A storage mounted at home/kitchen, holding keys RELATIVE to it.
        let mut config = StorageConfig::new("kitchen", "home/kitchen/**", "mem");
        config.strip_prefix = Some("home/kitchen".into());

        // The backend comes from a Volume (create_storage), wiring the §5.24
        // factory into the live service.
        let backend = MemoryVolume
            .create_storage(&config)
            .expect("in-memory volume create");
        let storage = StorageService::declare_with_backend(&session, &config, vec![0x01], backend)
            .expect("strip-configured storage declares against the test link");

        // A loopback publish UNDER the mount fires the capture subscriber.
        let fired = session
            .publish(
                "home/kitchen/temp",
                b"v1",
                PublishOptions::put().with_locality(Locality::SessionLocal),
            )
            .expect("loopback publish");
        assert_eq!(fired, 1, "the storage's capture subscriber fired once");

        // CAPTURE leg (kept): the value is stored under the RELATIVE (stripped)
        // key on the live path, never under the full keyexpr.
        storage.with_state(|st| {
            assert_eq!(
                st.get(Some("temp")).map(|d| d.payload.clone()),
                Some(b"v1".to_vec()),
                "the live capture stored the key RELATIVE to the mount"
            );
            assert!(
                st.get(Some("home/kitchen/temp")).is_none(),
                "the full keyexpr is not a stored key under strip"
            );
        });

        // RESTORE leg (over the LIVE path): a real loopback GET drives the
        // declared queryable's callback inline (SessionLocal locality), which
        // runs the gate's answer_into + strip restore. The recorded reply must
        // carry the RESTORED full keyexpr `home/kitchen/temp` with payload v1 —
        // proving the queryable -> answer_into -> restore wiring, not just the
        // kernel method. The recorder is Arc<Mutex<..>> because the on_reply
        // closure is `Send + 'static`.
        let replies = Arc::new(Mutex::new(Vec::<(String, Vec<u8>)>::new()));
        let rec = Arc::clone(&replies);
        session
            .query(
                "home/kitchen/*",
                QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
                move |reply: &dyn ReplyView| {
                    rec.lock()
                        .expect("reply recorder poisoned")
                        .push((reply.keyexpr().to_string(), reply.payload().to_vec()));
                },
                |_rid| {},
            )
            .expect("loopback query fires the declared queryable inline");

        let got = replies.lock().expect("reply recorder poisoned").clone();
        assert_eq!(
            got,
            vec![(String::from("home/kitchen/temp"), b"v1".to_vec())],
            "the live loopback query restores the full keyexpr from the stored relative key"
        );
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
