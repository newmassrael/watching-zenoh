// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Round 311vm — the storage-replication DRIVER, digest publisher half
//! (§5.11 storage domain, replication 6/N): the AP-side tokio binding that
//! periodically publishes this storage's replication Digest so peer replicas
//! can detect divergence.
//!
//! The no_std kernel ([`wz_session_core::storage_replication`]) produces and
//! compares digests; this module is its tokio binding. A
//! [`DigestPublisher`] spawns a task that, every `config.interval_ms`, builds
//! the storage's current [`Digest`](wz_session_core::storage_replication::Digest)
//! ([`StorageState::replication_digest`](wz_session_core::storage_state::StorageState::replication_digest)),
//! encodes it ([`wire::encode`](wz_session_core::storage_replication::wire::encode)),
//! and publishes it on the digest keyexpr. It shares the live
//! [`crate::storage_service::StorageService`] state (via
//! [`StorageService::shared_state`](crate::storage_service::StorageService::shared_state)),
//! so the digest reflects the actual stored data. Dropping the publisher
//! aborts the task (RAII teardown).
//!
//! ## zenoh anchor
//!
//! Mirrors zenoh 1.5.0 `Replication::spawn_digest_publisher`
//! (`plugins/zenoh-plugin-storage-manager/src/replication/core.rs:125-274`):
//! the per-interval loop computes the digest off the replication log and
//! `zenoh_session.put`s it (core.rs:217-257). The keyexpr is the
//! `digest_key_expr_formatter` `@-digest/${zid}/${hash_configuration}`
//! (core.rs:45-48), filled with the replica zid and the configuration
//! fingerprint (core.rs:136-148).
//!
//! ## Deliberate divergences (each documented)
//!
//! - **No propagation-delay pre-sleep or random jitter.** zenoh sleeps
//!   `propagation_delay` before each compute (to catch in-transit pubs) and
//!   adds `0..interval/3` random jitter (to de-correlate a fleet's
//!   publications, core.rs:198-237). Both are mesh-tuning, not correctness;
//!   wz publishes on a plain interval tick. They are a later tuning atom
//!   (and randomness needs a seeded source in this deterministic kernel).
//! - **Recompute, not an incremental log.** The digest is rebuilt from the
//!   storage snapshot each tick (the kernel
//!   [`StorageState::replication_digest`](wz_session_core::storage_state::StorageState::replication_digest)
//!   divergence note), so there is no `latest_updates` swap (core.rs:212-215).

use std::sync::{Arc, Mutex};

use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;
use wz_session_core::storage_backend::StorageBackend;
use wz_session_core::storage_replication::{wire, ReplicationConfig};
use wz_session_core::storage_state::StorageState;

use crate::session::{PublishError, PublishOptions, Session, Unicast};
use crate::session_glue::SessionLinkActions;
use crate::storage_service::wall_clock_ntp64;

/// The keyexpr a replica publishes its Digest on:
/// `@-digest/<zid-hex>/<config-fp>`. zenoh `digest_key_expr_formatter`
/// `@-digest/${zid:*}/${hash_configuration:*}` (core.rs:45-48), filled with
/// the replica zid and the configuration fingerprint (core.rs:136-148). wz
/// formats the zid as lowercase hex of its bytes and the fingerprint as the
/// `u64`'s decimal `Display` (matching zenoh's keformat substitution of the
/// `Fingerprint` it `Deref`s to `u64`).
pub fn digest_keyexpr(config: &ReplicationConfig, local_zid: &[u8]) -> String {
    let zid_hex: String = local_zid.iter().map(|b| format!("{b:02x}")).collect();
    format!("@-digest/{}/{}", zid_hex, config.fingerprint().value())
}

/// Builds the `(keyexpr, encoded-digest-bytes)` a publication carries, given
/// the wall-clock NTP64 `now` (injected so the build is deterministically
/// testable). The Hot-era upper bound is the current interval,
/// `config.classify(now).0` (zenoh `last_elapsed_interval`,
/// configuration.rs:116-126). Pure over the shared state: no Session, no
/// clock — the testable core of [`publish_digest_once`].
fn digest_frame<B: StorageBackend>(
    state: &Arc<Mutex<StorageState<B>>>,
    config: &ReplicationConfig,
    local_zid: &[u8],
    now: u64,
) -> (String, Vec<u8>) {
    let hot_upper = config.classify(now).0;
    let digest = {
        let guard = state.lock().expect("storage state mutex poisoned");
        guard.replication_digest(config, hot_upper)
    };
    (digest_keyexpr(config, local_zid), wire::encode(&digest))
}

/// Builds and publishes this storage's Digest once on the digest keyexpr,
/// `now` taken from the wall clock. `PublishOptions::put()` is
/// `Locality::Any`, so the digest reaches remote replicas (a replica ignores
/// its own copy via the Remote-only digest subscriber, the R7 atom). Returns
/// how many subscribers the publish reached. zenoh per-interval
/// `zenoh_session.put(digest_key, ..)` (core.rs:244-257).
fn publish_digest_once<R, T, B>(
    state: &Arc<Mutex<StorageState<B>>>,
    session: &Session<R, T, Unicast>,
    config: &ReplicationConfig,
    local_zid: &[u8],
) -> Result<usize, PublishError>
where
    R: SessionRuntime,
    T: TimeSource,
    B: StorageBackend,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    let (keyexpr, bytes) = digest_frame(state, config, local_zid, wall_clock_ntp64());
    session.publish(&keyexpr, &bytes, PublishOptions::put())
}

/// A running digest publisher bound to a [`Session`]: a spawned task that
/// republishes this storage's Digest every `config.interval_ms`. Dropping it
/// aborts the task (RAII teardown), so the publisher's lifetime is the
/// handle's lifetime.
pub struct DigestPublisher {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for DigestPublisher {
    fn drop(&mut self) {
        // The spawned loop is detached; abort it so a dropped publisher does
        // not keep emitting digests for a torn-down storage.
        self.task.abort();
    }
}

impl DigestPublisher {
    /// Spawn the periodic digest publisher. `state` is shared with the
    /// [`StorageService`](crate::storage_service::StorageService) (pass
    /// [`StorageService::shared_state`](crate::storage_service::StorageService::shared_state)),
    /// so the published digest reflects the live stored data. The loop sleeps
    /// `config.interval_ms` then publishes (zenoh `spawn_digest_publisher`
    /// loop, core.rs:202-272). The publish body is the deterministically
    /// tested [`publish_digest_once`]; this is the thin timer glue over it.
    pub fn spawn<R, T, B>(
        session: &Session<R, T, Unicast>,
        state: Arc<Mutex<StorageState<B>>>,
        config: ReplicationConfig,
        local_zid: Vec<u8>,
    ) -> Self
    where
        R: SessionRuntime + 'static,
        T: TimeSource + Send + Sync + 'static,
        B: StorageBackend + Send + 'static,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        SessionLinkActions<R, T>: Send + Sync + 'static,
        Session<R, T, Unicast>: Clone + Send + 'static,
    {
        let session = session.clone();
        let clock = Arc::clone(session.clock());
        let interval_ms = config.interval_ms();
        let task = tokio::spawn(async move {
            loop {
                clock.sleep(interval_ms).await;
                // A publish error (e.g. a torn-down link) is non-fatal to the
                // loop — the next tick republishes the full current digest.
                let _ = publish_digest_once(&state, &session, &config, &local_zid);
            }
        });
        Self { task }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::storage_backend::MemoryStorage;
    use wz_session_core::storage_replication::wire;

    fn cfg() -> ReplicationConfig {
        // Short interval so the spawn loop's first tick is fast in tests; the
        // values otherwise mirror zenoh defaults.
        ReplicationConfig::new("demo/**", None, 20, 5, 6, 30, 250)
    }

    fn put_state(now: u64) -> Arc<Mutex<StorageState<MemoryStorage>>> {
        use wz_session_core::sample::TimestampHint;
        let mut st = StorageState::new(MemoryStorage::new());
        st.process_put(
            "demo/a",
            vec![1, 2, 3],
            None,
            TimestampHint {
                time: now,
                zid: vec![0x01],
            },
        );
        Arc::new(Mutex::new(st))
    }

    #[test]
    fn digest_keyexpr_is_zenoh_formatted() {
        let config = cfg();
        let ke = digest_keyexpr(&config, &[0x01, 0xab]);
        assert_eq!(
            ke,
            format!("@-digest/01ab/{}", config.fingerprint().value())
        );
    }

    #[test]
    fn digest_frame_carries_the_current_digest_and_keyexpr() {
        let config = cfg();
        let zid = vec![0x01];
        let now = wall_clock_ntp64();
        let state = put_state(now);

        let (keyexpr, bytes) = digest_frame(&state, &config, &zid, now);

        assert_eq!(keyexpr, digest_keyexpr(&config, &zid));
        // The bytes decode to exactly the state's digest at this hot bound.
        let hot_upper = config.classify(now).0;
        let expected = state.lock().unwrap().replication_digest(&config, hot_upper);
        assert_eq!(wire::decode(&bytes), Ok(expected));
        // The put landed, so the digest is non-empty.
        let decoded = wire::decode(&bytes).unwrap();
        assert_eq!(decoded.configuration_fingerprint(), config.fingerprint());
        assert!(
            !decoded.hot_era_fingerprints().is_empty()
                || decoded.cold_era_fingerprint() != Default::default()
                || !decoded.warm_era_fingerprints().is_empty(),
            "a stored key produces a non-empty digest"
        );
    }

    // A REAL live-session test: spawn the publisher against a session and a
    // loopback subscriber on the digest keyexpr; the loop must publish a
    // decodable digest carrying this replica's configuration fingerprint.
    // Exercises spawn -> clock.sleep -> publish_digest_once -> keyexpr ->
    // wire payload -> a subscriber, plus the RAII abort on drop.
    #[cfg(all(feature = "declare-subscriber", feature = "pubsub-allow-loop"))]
    #[tokio::test]
    async fn spawned_publisher_emits_a_decodable_digest() {
        use crate::observer::ApplicationLayerObserver;
        use crate::runtime_impl::TokioTime;
        use crate::session::{SubscribeOptions, TokioSession};
        use std::time::Duration;
        use wz_session_core::sink::SampleView;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let config = cfg();
        let zid = vec![0x01];
        let state = put_state(wall_clock_ntp64());

        // Loopback subscriber on the exact digest keyexpr, recording payloads.
        let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let rx = Arc::clone(&received);
        let ke = digest_keyexpr(&config, &zid);
        let _sub = session
            .declare_subscriber(
                ke,
                SubscribeOptions::default(),
                move |v: &dyn SampleView| {
                    rx.lock().unwrap().push(v.payload().to_vec());
                },
            )
            .expect("digest keyexpr subscriber declares");

        let publisher = DigestPublisher::spawn(&session, state, config.clone(), zid);

        // Wait (generously, vs the 20ms interval) for the first digest.
        let bytes = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(b) = received.lock().unwrap().first().cloned() {
                    break b;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("a digest is published within 5s of spawning");

        let digest = wire::decode(&bytes).expect("the published payload decodes as a Digest");
        assert_eq!(digest.configuration_fingerprint(), config.fingerprint());

        drop(publisher); // RAII abort the loop.
    }
}
