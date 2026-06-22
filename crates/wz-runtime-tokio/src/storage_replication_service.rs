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
use wz_session_core::locality::Locality;
use wz_session_core::sink::SampleView;
use wz_session_core::storage_backend::StorageBackend;
use wz_session_core::storage_replication::{wire, zid_to_zenoh_hex, DigestDiff, ReplicationConfig};
use wz_session_core::storage_state::StorageState;

use crate::session::{
    PublishError, PublishOptions, Session, SubscribeError, SubscribeOptions, Subscriber, Unicast,
};
use crate::session_glue::SessionLinkActions;
use crate::storage_service::wall_clock_ntp64;

/// The keyexpr a replica publishes its Digest on:
/// `@-digest/<zid-hex>/<config-fp>`. zenoh `digest_key_expr_formatter`
/// `@-digest/${zid:*}/${hash_configuration:*}` (core.rs:45-48), filled with
/// the replica zid and the configuration fingerprint (core.rs:136-148).
///
/// Both components go through zenoh's `keformat` `set<S: Display>` (key_expr
/// `format/mod.rs:487-493`), i.e. each is rendered via its [`Display`]: the zid
/// as zenoh's `ZenohId` Display (the
/// [`zid_to_zenoh_hex`](wz_session_core::storage_replication::zid_to_zenoh_hex)
/// SSOT — LE id read as a `u128`, big-endian hex, one leading zero stripped,
/// NOT a naive per-byte hex) and the fingerprint as the `u64`'s decimal
/// `Display` (`Fingerprint` `Deref`s to `u64`). Using the shared SSOT keeps
/// this byte-identical to a real zenoh's keyexpr and consistent with the
/// aligner's `AlignmentReply::Discovery` zid encoding.
pub fn digest_keyexpr(config: &ReplicationConfig, local_zid: &[u8]) -> String {
    format!(
        "@-digest/{}/{}",
        zid_to_zenoh_hex(local_zid),
        config.fingerprint().value()
    )
}

/// Extract the `<zid-hex>` component from a digest keyexpr
/// `@-digest/<zid-hex>/<config-fp>` — the inverse of [`digest_keyexpr`]'s zid
/// slot. The subscriber identifies the diverging peer from this (the Digest
/// payload carries no zid; only the keyexpr does), so the aligner can target
/// that peer's aligner queryable. Returns `None` for a keyexpr that is not a
/// well-formed digest keyexpr (wrong prefix, missing/empty component, or a
/// trailing segment). zenoh `digest_key_expr_formatter::parse` (core.rs:333);
/// wz's keyexprs are plain `/`-delimited, so a split suffices.
pub fn digest_keyexpr_zid_hex(keyexpr: &str) -> Option<&str> {
    let (zid_hex, fp) = keyexpr.strip_prefix("@-digest/")?.split_once('/')?;
    if zid_hex.is_empty() || fp.is_empty() || fp.contains('/') {
        return None;
    }
    Some(zid_hex)
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

/// The keyexpr a replica subscribes to for peer Digests:
/// `@-digest/*/<config-fp>` — any source zid (`*`) but this replica's OWN
/// configuration fingerprint, so only compatibly-configured replicas' digests
/// are received. zenoh digest subscriber keyexpr (core.rs:294-298).
pub fn digest_subscribe_keyexpr(config: &ReplicationConfig) -> String {
    format!("@-digest/*/{}", config.fingerprint().value())
}

/// Process one received peer Digest: decode it, build the local digest at
/// `now`, diff them, and hand any divergence to `on_diff` along with the peer's
/// zid hex (`peer_zid_hex`, parsed from the digest keyexpr) so the aligner can
/// target that peer. zenoh's `spawn_digest_subscriber` per-sample body
/// (core.rs:331-399) up to the point it queries the aligner — wz produces the
/// [`DigestDiff`] + peer identity (the typed aligner handoff). A payload that
/// fails to decode, or a peer on an incompatible configuration
/// ([`Digest::diff`](wz_session_core::storage_replication::Digest::diff) returns
/// `None` on a config-fingerprint mismatch), is ignored — never fatal. Pure
/// over the shared state: the deterministically tested core of the subscriber.
fn handle_peer_digest<B: StorageBackend>(
    state: &Arc<Mutex<StorageState<B>>>,
    config: &ReplicationConfig,
    peer_zid_hex: &str,
    peer_bytes: &[u8],
    now: u64,
    on_diff: &mut dyn FnMut(&str, DigestDiff),
) {
    let peer = match wire::decode(peer_bytes) {
        Ok(peer) => peer,
        Err(_) => return,
    };
    let hot_upper = config.classify(now).0;
    let local = {
        let guard = state.lock().expect("storage state mutex poisoned");
        guard.replication_digest(config, hot_upper)
    };
    if let Some(diff) = local.diff(peer) {
        on_diff(peer_zid_hex, diff);
    }
}

/// A live peer-digest subscriber bound to a [`Session`]: receives peer Digests
/// on `@-digest/*/<config-fp>` and, for each, hands a [`DigestDiff`] (plus the
/// diverging peer's zid hex, parsed from the digest keyexpr) to the caller's
/// `on_diff` callback whenever this replica diverges from the peer. The callback
/// is the **aligner handoff seam**: this track produces the `(peer_zid_hex,
/// DigestDiff)`; the aligner's `spawn_digest_aligner` (the `storage-aligner`
/// driver) consumes it to pull the diverging entries from that peer. Dropping it
/// undeclares the subscriber (RAII).
///
/// The subscriber uses [`Locality::Remote`] so a replica does not process its
/// OWN published digest (zenoh `allowed_origin(Locality::Remote)`,
/// core.rs:310-317).
pub struct DigestSubscriber<R: SessionRuntime> {
    _subscriber: Subscriber<R>,
}

impl<R: SessionRuntime> DigestSubscriber<R> {
    /// Declare the peer-digest subscriber. `state` is shared with the
    /// [`StorageService`](crate::storage_service::StorageService) (pass its
    /// `shared_state()`), so the local digest each diff compares against
    /// reflects the live stored data. `on_diff` is invoked once per received
    /// peer digest that diverges from this replica, with the peer's zid hex
    /// (from the digest keyexpr) and the [`DigestDiff`].
    pub fn declare<T, B>(
        session: &Session<R, T, Unicast>,
        state: Arc<Mutex<StorageState<B>>>,
        config: ReplicationConfig,
        mut on_diff: impl FnMut(&str, DigestDiff) + Send + 'static,
    ) -> Result<Self, SubscribeError>
    where
        T: TimeSource + 'static,
        B: StorageBackend + Send + 'static,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        SessionLinkActions<R, T>: Send + Sync + 'static,
    {
        let subscriber = session.declare_subscriber(
            digest_subscribe_keyexpr(&config),
            SubscribeOptions::default().with_allowed_origin(Locality::Remote),
            move |view: &dyn SampleView| {
                // The peer zid is the digest keyexpr's <zid-hex> component (the
                // Digest payload carries no zid); skip a sample whose keyexpr
                // does not parse as a digest keyexpr.
                if let Some(peer_zid_hex) = digest_keyexpr_zid_hex(view.keyexpr()) {
                    handle_peer_digest(
                        &state,
                        &config,
                        peer_zid_hex,
                        view.payload(),
                        wall_clock_ntp64(),
                        &mut on_diff,
                    );
                }
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

    fn state_with(keys: &[&str], now: u64) -> StorageState<MemoryStorage> {
        use wz_session_core::sample::TimestampHint;
        let mut st = StorageState::new(MemoryStorage::new());
        for (i, key) in keys.iter().enumerate() {
            st.process_put(
                key,
                vec![i as u8],
                None,
                TimestampHint {
                    time: now,
                    zid: vec![0x01],
                },
            );
        }
        st
    }

    #[test]
    fn digest_subscribe_keyexpr_is_zenoh_formatted() {
        let config = cfg();
        assert_eq!(
            digest_subscribe_keyexpr(&config),
            format!("@-digest/*/{}", config.fingerprint().value())
        );
    }

    #[test]
    fn handle_peer_digest_reports_a_divergent_peer() {
        let now = wall_clock_ntp64();
        let config = cfg();
        let hot_upper = config.classify(now).0;
        let local = state_with(&["demo/a"], now);
        // The peer holds an extra key -> the local replica diverges from it.
        let peer = state_with(&["demo/a", "demo/b"], now);
        let peer_bytes = wire::encode(&peer.replication_digest(&config, hot_upper));

        let expected = local
            .replication_digest(&config, hot_upper)
            .diff(peer.replication_digest(&config, hot_upper));
        assert!(expected.is_some(), "peer has an extra key -> a diff exists");

        let arc = Arc::new(Mutex::new(local));
        let mut got = None;
        let mut got_zid = String::new();
        handle_peer_digest(&arc, &config, "ab01", &peer_bytes, now, &mut |zid, d| {
            got_zid = zid.to_string();
            got = Some(d);
        });
        assert_eq!(got, expected);
        assert_eq!(
            got_zid, "ab01",
            "the peer zid hex threads through to on_diff"
        );
    }

    #[test]
    fn handle_peer_digest_ignores_an_identical_peer() {
        let now = wall_clock_ntp64();
        let config = cfg();
        let hot_upper = config.classify(now).0;
        let local = state_with(&["demo/a"], now);
        let peer_bytes = wire::encode(&local.replication_digest(&config, hot_upper));

        let arc = Arc::new(Mutex::new(local));
        let mut called = false;
        handle_peer_digest(&arc, &config, "ab01", &peer_bytes, now, &mut |_zid, _| {
            called = true
        });
        assert!(!called, "an identical peer produces no diff");
    }

    #[test]
    fn handle_peer_digest_ignores_a_corrupt_payload() {
        let config = cfg();
        let arc = Arc::new(Mutex::new(state_with(&["demo/a"], wall_clock_ntp64())));
        let mut called = false;
        handle_peer_digest(
            &arc,
            &config,
            "ab01",
            &[0xff, 0x00, 0x01],
            wall_clock_ntp64(),
            &mut |_zid, _| called = true,
        );
        assert!(!called, "a corrupt digest payload is ignored, not fatal");
    }

    #[test]
    fn handle_peer_digest_ignores_an_incompatible_config_peer() {
        let now = wall_clock_ntp64();
        let local_config = cfg();
        // A peer on a different key_expr -> a different config fingerprint, so
        // Digest::diff short-circuits to None and the peer is ignored.
        let peer_config = ReplicationConfig::new("other/**", None, 20, 5, 6, 30, 250);
        let hot_upper = peer_config.classify(now).0;
        let peer_bytes =
            wire::encode(&state_with(&["x/y"], now).replication_digest(&peer_config, hot_upper));

        let arc = Arc::new(Mutex::new(state_with(&["demo/a"], now)));
        let mut called = false;
        handle_peer_digest(
            &arc,
            &local_config,
            "ab01",
            &peer_bytes,
            now,
            &mut |_zid, _| called = true,
        );
        assert!(
            !called,
            "a peer on an incompatible configuration is ignored (config-fp mismatch)"
        );
    }

    // A live-session test that the peer-digest subscriber declares against a
    // real session on the @-digest/*/<fp> keyexpr (Remote-only). The
    // cross-session firing (a remote peer's digest -> diff -> on_diff) needs a
    // TWO-INSTANCE e2e: the subscriber is Remote-only, so a single-session
    // loopback (which is SessionLocal-origin) cannot exercise it by
    // construction. Here the decode/diff/observer core is covered by the
    // handle_peer_digest unit tests above; the live two-replica exchange rides
    // the storage-aligner track's e2e (it also needs the aligner to converge).
    #[cfg(feature = "declare-subscriber")]
    #[test]
    fn digest_subscriber_declares_on_the_subscribe_keyexpr() {
        use crate::observer::ApplicationLayerObserver;
        use crate::runtime_impl::TokioTime;
        use crate::session::TokioSession;
        use crate::storage_service::StorageService;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let storage =
            StorageService::declare(&session, "demo/**", vec![0x01]).expect("storage declares");
        let config = cfg();
        let sub =
            DigestSubscriber::declare(&session, storage.shared_state(), config, |_zid, _diff| {});
        assert!(
            sub.is_ok(),
            "the peer-digest subscriber declares on @-digest/*/<fp>"
        );
    }

    #[test]
    fn digest_keyexpr_zid_hex_extracts_the_peer_zid() {
        let config = cfg();
        // Round-trip: a published digest keyexpr parses back to the same zid hex
        // (the zid renders via ZenohId Display: [0x01, 0xab] -> "ab01").
        let ke = digest_keyexpr(&config, &[0x01, 0xab]);
        assert_eq!(digest_keyexpr_zid_hex(&ke), Some("ab01"));
        // Malformed keyexprs are rejected.
        assert_eq!(digest_keyexpr_zid_hex("@-digest/ab01"), None, "missing fp");
        assert_eq!(digest_keyexpr_zid_hex("foo/ab01/9"), None, "wrong prefix");
        assert_eq!(digest_keyexpr_zid_hex("@-digest//9"), None, "empty zid");
        assert_eq!(
            digest_keyexpr_zid_hex("@-digest/ab01/9/x"),
            None,
            "trailing segment"
        );
    }

    #[test]
    fn digest_keyexpr_is_zenoh_formatted() {
        let config = cfg();
        // The zid renders via zenoh's ZenohId Display (LE -> u128 -> big-endian
        // hex), so [0x01, 0xab] -> u128 0xab01 -> "ab01" -- NOT a per-byte
        // "01ab". This is what a real zenoh keformat produces.
        let ke = digest_keyexpr(&config, &[0x01, 0xab]);
        assert_eq!(
            ke,
            format!("@-digest/ab01/{}", config.fingerprint().value())
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
        use crate::session::TokioSession;
        use std::time::Duration;

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
