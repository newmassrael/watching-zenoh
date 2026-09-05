// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311wt slice 4 — the storage garbage-collection DRIVER (§5.24
//! `storage-mgr-garbage-collection`): the AP-side tokio binding that
//! periodically sweeps stale entries out of a storage's wildcard-update
//! registries.
//!
//! The no_std kernel
//! ([`StorageState::collect_garbage`](wz_session_core::storage_state::StorageState::collect_garbage))
//! owns the age math (remove every registered wildcard Put / Delete older than
//! `now - lifespan`); this module is its tokio timer glue. A
//! [`GarbageCollector`] spawns a task that, every
//! `config.garbage_collection.period`, locks the shared
//! [`crate::storage_service::StorageService`] state (via
//! [`StorageService::shared_state`](crate::storage_service::StorageService::shared_state))
//! and calls `collect_garbage(wall_clock_ntp64(), lifespan)`. Dropping the
//! collector aborts the task (RAII teardown), so its lifetime is the handle's
//! lifetime — the caller MUST hold the returned handle for the storage's
//! lifetime (a dropped handle stops collecting). This mirrors the
//! [`DigestPublisher`](crate::storage_replication_service::DigestPublisher)
//! caller-driven periodic-driver pattern; the [`StorageService`] itself does
//! not own the timer.
//!
//! ## zenoh anchor
//!
//! Mirrors zenoh 1.5.0 `GarbageCollectionEvent`
//! (`plugins/zenoh-plugin-storage-manager/src/storages_mgt/service.rs:661-713`):
//! a `TimedEvent::periodic(config.period, ...)` that removes wildcard-registry
//! entries with `timestamp.get_time() < now - lifespan`.
//!
//! ## Clock split (deliberate, each correct for its role)
//!
//! - the PERIOD uses the session's monotonic-ms [`TimeSource::sleep`] — an
//!   interval must not wobble on an NTP step (same as `DigestPublisher`);
//! - the CUTOFF `now` uses the wall-clock NTP64 SSOT
//!   ([`wall_clock_ntp64`](crate::timestamp_source::wall_clock_ntp64)) — a
//!   registry entry's age is measured against its wall-clock stamp, not a
//!   monotonic instant (whose epoch is unspecified). zenoh splits them the same
//!   way (`config.period` timer vs `SystemTime::now()` cutoff).
//!
//! ## Mutex-poison policy
//!
//! A poisoned state mutex makes this sweep a no-op for the tick and retries on
//! the next one (`if let Ok(mut g) = state.lock()`), matching the loop's
//! best-effort philosophy — a missed sweep only defers memory reclamation, and
//! `retain` is safe from any consistent state. This DIFFERS deliberately from
//! `DigestPublisher`'s `.expect("… poisoned")`: a dropped digest is a
//! correctness signal a peer must not miss, whereas a deferred GC is benign.

use std::sync::{Arc, Mutex};

use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;
use wz_session_core::storage_backend::StorageBackend;
use wz_session_core::storage_config::GarbageCollectionConfig;
use wz_session_core::storage_state::StorageState;

use crate::session::{Session, Unicast};
use crate::session_glue::SessionLinkActions;
use crate::timestamp_source::wall_clock_ntp64;

/// A running garbage collector bound to a [`Session`]: a spawned task that
/// sweeps this storage's wildcard-update registries every
/// `config.garbage_collection.period`. Dropping it aborts the task (RAII
/// teardown), so the collector's lifetime is the handle's lifetime — hold it
/// for as long as the storage should be GC'd.
pub struct GarbageCollector {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for GarbageCollector {
    fn drop(&mut self) {
        // The spawned loop is detached; abort it so a dropped collector does not
        // keep sweeping a torn-down storage.
        self.task.abort();
    }
}

impl GarbageCollector {
    /// Spawn the periodic garbage collector. `state` is shared with the
    /// [`StorageService`](crate::storage_service::StorageService) (pass
    /// [`StorageService::shared_state`](crate::storage_service::StorageService::shared_state)),
    /// so the sweep acts on the live registries. The loop sleeps
    /// `gc.period` then sweeps entries older than `gc.lifespan`. The kernel
    /// [`StorageState::collect_garbage`](wz_session_core::storage_state::StorageState::collect_garbage)
    /// is the deterministically tested body; this is the thin timer glue over it.
    ///
    /// The caller MUST keep the returned handle alive for the storage's lifetime
    /// — dropping it aborts the sweep task.
    pub fn spawn<R, T, B>(
        session: &Session<R, T, Unicast>,
        state: Arc<Mutex<StorageState<B>>>,
        gc: GarbageCollectionConfig,
        storage_name: &str,
    ) -> Self
    where
        R: SessionRuntime + 'static,
        T: TimeSource + Send + Sync + 'static,
        B: StorageBackend + Send + 'static,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        SessionLinkActions<R, T>: Send + Sync + 'static,
        Session<R, T, Unicast>: Clone + Send + 'static,
    {
        let clock = Arc::clone(session.clock());
        // The period as whole ms, floored at 1ms. `as_millis()` truncates, so a
        // sub-millisecond period (or `Duration::ZERO`) would be `0` → `sleep(0)`
        // returns Ready without yielding → the loop hot-spins, starving the
        // runtime (a current_thread executor would hang) and hammering the state
        // lock. The `.max(1)` guarantees the loop yields every tick. `u128 -> u64`
        // narrowing saturates (impossible for any realistic period).
        let period_ms = u64::try_from(gc.period.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let lifespan = gc.lifespan;
        let label = storage_name.to_string();
        // The APPLICATION subsystem, as for the replication publisher and for
        // the same reason: upstream's storage plugin names none
        // (`plugins/zenoh-plugin-storage-manager`), so wz makes the inherited
        // tier explicit. zenoh's nearest named analogue is the ext GC loop,
        // `ZRuntime::Application.spawn(gc_task(..))`
        // (`zenoh-ext/src/advanced_subscriber.rs`
        // @ `ZRuntime::Application.spawn(gc_task(`), which is this same
        // shape — a periodic sweep over retained state.
        let task = crate::runtime_pool::WzRuntime::Application.spawn(async move {
            loop {
                // PERIOD: monotonic ms sleep (interval, held OUTSIDE the lock).
                clock.sleep(period_ms).await;
                // CUTOFF: wall-clock NTP64 now (the entries' stamp basis). A
                // poisoned mutex defers this sweep to the next tick.
                //
                // R311y503 — the sweep's POSITIVE EDGE is logged, and it is the
                // only thing outside this process that can tell a wired collector
                // from an unwired one. `collect_garbage` is a `retain`: it returns
                // nothing and a swept registry looks exactly like a registry that
                // never held anything. So the lens is read either side of the
                // sweep and a line is emitted only when entries were actually
                // REMOVED -- never per tick, which would fire on an idle storage
                // and witness the timer rather than the collection.
                if let Ok(mut guard) = state.lock() {
                    let (puts_before, dels_before) = guard.wildcard_registry_lens();
                    guard.collect_garbage(wall_clock_ntp64(), lifespan);
                    let (puts_after, dels_after) = guard.wildcard_registry_lens();
                    let swept = (puts_before - puts_after) + (dels_before - dels_after);
                    if swept > 0 {
                        log::info!(
                            "wz storage '{label}': garbage collected {swept} stale \
                             wildcard-update entr{} (puts {puts_before}->{puts_after}, \
                             deletes {dels_before}->{dels_after})",
                            if swept == 1 { "y" } else { "ies" }
                        );
                    }
                }
            }
        });
        Self { task }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::ApplicationLayerObserver;
    use crate::runtime_impl::TokioTime;
    use crate::session::TokioSession;
    use crate::storage_service::StorageService;
    use core::time::Duration;
    use wz_session_core::sample::{Sample, TimestampHint};
    use wz_session_core::storage_backend::MemoryStorage;
    use wz_session_core::storage_config::{GarbageCollectionConfig, StorageConfig};

    fn session() -> TokioSession {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        TokioSession::new(actions, observer, clock)
    }

    // A wildcard-delete registered on the shared state at a fixed past NTP64
    // instant (10 s after the epoch — decades stale versus wall-clock now).
    fn register_stale_wildcard(state: &Arc<Mutex<StorageState<MemoryStorage>>>) {
        let mut g = state.lock().unwrap();
        g.apply_sample(
            &Sample::new_del("demo/**").with_timestamp(TimestampHint {
                time: 10u64 << 32,
                zid: vec![0x01],
            }),
            || unreachable!(),
        );
        assert_eq!(
            g.wildcard_registry_lens(),
            (0, 1),
            "one wildcard-delete registered"
        );
    }

    #[tokio::test]
    async fn spawned_collector_sweeps_a_stale_registry_entry() {
        let session = session();
        let storage = StorageService::declare(
            &session,
            &StorageConfig::new("demo", "demo/**", "mem"),
            vec![0x01],
        )
        .expect("storage declares");
        let state = storage.shared_state();
        register_stale_wildcard(&state);

        // Short period, zero lifespan: the first tick's wall-clock cutoff is
        // decades after the entry's 10 s stamp, so it is collected.
        let gc = GarbageCollectionConfig {
            period: Duration::from_millis(10),
            lifespan: Duration::from_secs(0),
        };
        let _collector = GarbageCollector::spawn(&session, Arc::clone(&state), gc, "test");

        // Wait a few periods for at least one sweep.
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            if state.lock().unwrap().wildcard_registry_lens() == (0, 0) {
                return; // swept
            }
        }
        panic!("the collector did not sweep the stale entry within the timeout");
    }

    #[tokio::test]
    async fn a_within_lifespan_entry_is_retained_proving_lifespan_is_threaded() {
        // The driver must thread `gc.lifespan` through: an entry stamped ≈now
        // with a 1h lifespan is NOT stale, so no tick collects it. A mutant
        // driver that dropped `gc.lifespan` (hardcoding 0) would collect it and
        // fail — the sweep test alone (lifespan=0) cannot catch that.
        let session = session();
        let storage = StorageService::declare(
            &session,
            &StorageConfig::new("demo", "demo/**", "mem"),
            vec![0x01],
        )
        .expect("storage declares");
        let state = storage.shared_state();
        // Register a wildcard-delete stamped at the CURRENT wall clock (fresh).
        {
            let mut g = state.lock().unwrap();
            g.apply_sample(
                &Sample::new_del("demo/**").with_timestamp(TimestampHint {
                    time: wall_clock_ntp64(),
                    zid: vec![0x01],
                }),
                || unreachable!(),
            );
            assert_eq!(g.wildcard_registry_lens(), (0, 1));
        }
        let gc = GarbageCollectionConfig {
            period: Duration::from_millis(10),
            lifespan: Duration::from_secs(3600), // 1 hour: the entry is in-window
        };
        let _collector = GarbageCollector::spawn(&session, Arc::clone(&state), gc, "test");
        // Let several sweeps run; the fresh entry must survive them all.
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(
            state.lock().unwrap().wildcard_registry_lens(),
            (0, 1),
            "a within-lifespan entry is retained (the driver threads gc.lifespan)"
        );
    }

    #[tokio::test]
    async fn dropping_the_collector_aborts_the_sweep_task() {
        let session = session();
        let storage = StorageService::declare(
            &session,
            &StorageConfig::new("demo", "demo/**", "mem"),
            vec![0x01],
        )
        .expect("storage declares");
        let state = storage.shared_state();

        let gc = GarbageCollectionConfig {
            period: Duration::from_millis(10),
            lifespan: Duration::from_secs(0),
        };
        let collector = GarbageCollector::spawn(&session, Arc::clone(&state), gc, "test");
        let handle = collector.task.abort_handle();
        drop(collector); // Drop aborts the task (RAII teardown).
                         // `abort()` schedules cancellation; yield so the runtime
                         // processes it, then confirm the task is gone.
        for _ in 0..50 {
            if handle.is_finished() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("dropping the collector did not abort the sweep task");
    }
}
