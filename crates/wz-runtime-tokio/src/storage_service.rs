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
//! (here [`apply_sample`] -> the gate's `process_put` / `process_delete`)
//! and a received query routes to `reply_query` (here [`answer_query`] ->
//! the gate's `matching_entries`, replied per key). wz's callback-driven
//! observer replaces zenoh's explicit `tokio::select!` — the subscriber /
//! queryable registries fire the two closures, so the "loop" is the
//! session's own drive loop, not a private one.
//!
//! ## Fallback timestamp (the §5.18 seam)
//!
//! zenoh stamps an un-timestamped sample with the session HLC
//! (`sample.timestamp().cloned().unwrap_or(session.new_timestamp())`,
//! service.rs:182) so newer-wins always has a timestamp. wz's HLC / time
//! sources are still reserved (§5.18), so this driver stamps an
//! un-timestamped sample with a MONOTONIC arrival counter under a fixed
//! `local_zid`. That gives a deterministic newer-wins order *among
//! un-timestamped samples* (arrival order). The honest limit: a
//! fallback-stamped sample's counter time is not comparable to a real
//! NTP64 timestamp, so a storage facing a MIX of timestamped and
//! un-timestamped publishers needs a real HLC to order them coherently —
//! the §5.18 atom. A sample that DOES carry a timestamp always uses it, so
//! a timestamped-publisher deployment is already fully coherent.
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
use wz_session_core::sample::TimestampHint;
use wz_session_core::sample_kind::SampleKind;
use wz_session_core::sink::SampleView;
use wz_session_core::storage_backend::MemoryStorage;
use wz_session_core::storage_state::StorageState;

use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;

use crate::session::{
    Queryable, QueryableError, QueryableOptions, Session, SubscribeError, SubscribeOptions,
    Subscriber, Unicast,
};
use crate::session_glue::SessionLinkActions;

/// Shared, lockable storage gate. The subscriber callback locks it to
/// write (capture Put / Delete) and the queryable callback locks it to
/// read (answer a query); `Arc` because the two callbacks each own a
/// clone, `Mutex` because the session may fire them from different worker
/// threads.
type SharedState = Arc<Mutex<StorageState<MemoryStorage>>>;

/// Apply one inbound sample to the gate: a Put is stored / a Del removes,
/// both through the newer-wins gate (an outdated mutation is dropped by
/// the gate). An un-timestamped sample is stamped via `fallback` (called
/// at most once, only when the sample carries no timestamp). Free function
/// so the capture logic is unit-testable without a live session — the
/// subscriber closure is a thin lock-then-call wrapper over this.
fn apply_sample(
    state: &mut StorageState<MemoryStorage>,
    view: &dyn SampleView,
    fallback: impl FnOnce() -> TimestampHint,
) {
    let timestamp = view.timestamp().cloned().unwrap_or_else(fallback);
    match view.kind() {
        SampleKind::Put => {
            let encoding = view.encoding().cloned();
            state.process_put(view.keyexpr(), view.payload().to_vec(), encoding, timestamp);
        }
        SampleKind::Del => {
            state.process_delete(view.keyexpr(), timestamp);
        }
    }
}

/// Answer one inbound query from the stored set: reply every live entry
/// whose key intersects the query keyexpr, each stamped with its OWN
/// concrete keyexpr via [`ReplyOut::reply_keyed`] (so a wildcard get
/// returns per-key replies, not the wildcard). The terminating
/// ResponseFinal is scheduled by the queryable dispatch path, not here.
/// Free function for the same unit-testability reason as [`apply_sample`].
fn answer_query(state: &StorageState<MemoryStorage>, view: &dyn QueryView, out: &mut dyn ReplyOut) {
    for (key, data) in state.matching_entries(view.keyexpr()) {
        out.reply_keyed(&key, &data.payload);
    }
}

/// A live storage service bound to a [`Session`]: owns the capture
/// [`Subscriber`], the answering [`Queryable`], and the shared
/// [`StorageState`]. Dropping it undeclares both (the handles' RAII
/// `Drop`), tearing the storage down.
pub struct StorageService<R: SessionRuntime, T: TimeSource> {
    state: SharedState,
    // Held for their RAII lifetime: dropping a handle undeclares the
    // subscriber / queryable. The service is the storage's lifetime owner.
    _subscriber: Subscriber<R>,
    _queryable: Queryable<R, T>,
}

impl<R, T> StorageService<R, T>
where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    /// Declare a storage on `keyexpr` over `session`: a capture subscriber
    /// plus a complete queryable backed by an in-memory store. `local_zid`
    /// is the storage's identity for stamping un-timestamped samples (the
    /// fallback `zid`; see the module-level fallback note) — must be
    /// non-empty.
    ///
    /// The queryable is declared COMPLETE
    /// ([`QueryableOptions::with_complete`]): a storage is an authoritative
    /// answerer for its keyexpr, the BestMatching producer signal a router
    /// routes a get to (the query-routing track).
    pub fn declare(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        local_zid: Vec<u8>,
    ) -> Result<Self, StorageServiceError> {
        if local_zid.is_empty() {
            return Err(StorageServiceError::InvalidZid);
        }
        let keyexpr: String = keyexpr.into();
        let state: SharedState = Arc::new(Mutex::new(StorageState::new(MemoryStorage::new())));

        // Capture leg: each inbound sample locks the gate and applies it,
        // stamping a fallback monotonic timestamp when the sample carries
        // none (the §5.18 seam).
        let sub_state = Arc::clone(&state);
        let mut fallback_counter: u64 = 0;
        let fallback_zid = local_zid;
        let subscriber = session.declare_subscriber(
            keyexpr.clone(),
            SubscribeOptions::default(),
            move |view: &dyn SampleView| {
                let mut guard = sub_state.lock().expect("storage state mutex poisoned");
                apply_sample(&mut guard, view, || {
                    fallback_counter += 1;
                    TimestampHint {
                        time: fallback_counter,
                        zid: fallback_zid.clone(),
                    }
                });
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
                answer_query(&guard, view, out);
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
        F: FnOnce(&StorageState<MemoryStorage>) -> O,
    {
        let guard = self.state.lock().expect("storage state mutex poisoned");
        f(&guard)
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
    }
    impl ReplyOut for RecordingReplyOut {
        fn reply(&mut self, payload: &[u8]) {
            self.keyed.push((String::new(), payload.to_vec()));
        }
        fn reply_keyed(&mut self, keyexpr: &str, payload: &[u8]) {
            self.keyed.push((keyexpr.to_string(), payload.to_vec()));
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
        apply_sample(&mut state, &sample, || {
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
        apply_sample(&mut state, &sample, || ts(7, 9));
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
        apply_sample(
            &mut state,
            &Sample::new_put("demo/a", vec![1]).with_timestamp(ts(10, 1)),
            || unreachable!(),
        );
        apply_sample(
            &mut state,
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
        apply_sample(
            &mut state,
            &Sample::new_put("demo/a", vec![9]).with_timestamp(ts(100, 1)),
            || unreachable!(),
        );
        apply_sample(
            &mut state,
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
        answer_query(&state, &query("demo/*"), &mut out);

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
        answer_query(&state, &query("demo/a"), &mut out);
        assert_eq!(out.keyed, vec![(String::from("demo/a"), vec![42])]);
    }

    #[test]
    fn answer_query_does_not_reply_a_deleted_key() {
        let mut state = fresh();
        state.process_put("demo/a", vec![1], None, ts(10, 1));
        state.process_delete("demo/a", ts(20, 1));
        let mut out = RecordingReplyOut::default();
        answer_query(&state, &query("demo/**"), &mut out);
        assert!(out.keyed.is_empty(), "a deleted key is not replied");
    }
}
