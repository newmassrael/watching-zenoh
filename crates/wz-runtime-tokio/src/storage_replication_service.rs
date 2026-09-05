// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! ## The publication schedule
//!
//! R311y829 — the loop is upstream's, not a plain tick: it aligns to the
//! fleet's shared interval boundaries before its first publication, waits the
//! configured `propagation_delay` before reading the store, jitters the put by
//! `0..interval/3` to de-correlate a fleet, and subtracts the cycle's own work
//! from the closing sleep so the PERIOD stays `interval_ms`
//! (core.rs:161-272). The arithmetic is four pure functions on
//! [`ReplicationConfig`] (`alignment_delay_ms`, `propagation_delay_ms`,
//! `publication_delay_ms`, `post_publication_delay_ms`) so the schedule is
//! testable without a wall clock; this module supplies only the clock reads.
//! The jitter draws come from
//! [`JitterSequence`](wz_session_core::storage_replication::JitterSequence),
//! seeded per replica from its zid — see that type for why de-correlation
//! does not want the entropy port.
//!
//! ## Deliberate divergences (each documented)
//!
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
use wz_session_core::storage_replication::{
    wire, zid_to_zenoh_hex, DigestDiff, JitterSequence, ReplicationConfig,
};
use wz_session_core::storage_state::StorageState;

use crate::session::{
    PublishOptions, Session, SubscribeError, SubscribeOptions, Subscriber, Unicast,
};
use crate::session_glue::SessionLinkActions;
use crate::timestamp_source::{wall_clock_ntp64, wall_clock_unix_ms};

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
    // The zid chunk must be canonical lowercase hex -- exactly what
    // [`zid_to_zenoh_hex`] always emits, so a legit peer never fails this -- and
    // the fp a single non-empty chunk. Rejecting a non-hex zid is
    // defense-in-depth: a crafted/non-conformant peer keyexpr like
    // `@-digest/a$*/<fp>` would otherwise splice a keyexpr WILDCARD into the
    // aligner query keyexpr [`aligner_keyexpr_for_hex`], fanning a targeted
    // `Diff` pull (and this replica's DigestDiff) out to many replicas instead
    // of the one diverging peer.
    if fp.is_empty()
        || fp.contains('/')
        || zid_hex.is_empty()
        || !zid_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    Some(zid_hex)
}

/// Builds the `(keyexpr, encoded-digest-bytes)` a publication carries, given
/// the wall-clock NTP64 `now` (injected so the build is deterministically
/// testable). The Hot-era upper bound is the current interval,
/// `config.classify(now).0` (zenoh `last_elapsed_interval`,
/// configuration.rs:116-126). Pure over the shared state: no Session, no
/// clock — the testable core of the publication cycle, which
/// [`DigestPublisher::spawn`] puts on the wire with `PublishOptions::put()`
/// (`Locality::Any`, so a digest reaches remote replicas; a replica ignores
/// its own copy via the Remote-only digest subscriber, the R7 atom — zenoh
/// `zenoh_session.put(digest_key, ..)`, core.rs:244-257).
fn digest_frame<B: StorageBackend>(
    state: &Arc<Mutex<StorageState<B>>>,
    config: &ReplicationConfig,
    local_zid: &[u8],
    now: u64,
) -> (String, Vec<u8>) {
    let hot_upper = config.classify(now).0;
    let digest = {
        // `mut` since R2354: the digest is read off the storage's maintained
        // replication log, and the first call under a configuration seeds it.
        let mut guard = state.lock().expect("storage state mutex poisoned");
        guard.replication_digest(config, hot_upper)
    };
    (digest_keyexpr(config, local_zid), wire::encode(&digest))
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
    /// so the published digest reflects the live stored data. The loop is
    /// zenoh's `spawn_digest_publisher` (core.rs:161-272) — see the module's
    /// "publication schedule" note for the four sleeps it is built from. The
    /// frame body is the deterministically tested [`digest_frame`]; this is
    /// the timer glue over it.
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
        let task = tokio::spawn(async move {
            // Align to the interval boundaries the whole fleet shares, rather
            // than to whenever this process happened to start (zenoh
            // core.rs:161-191). Read once, before the loop: from here on the
            // period is maintained by the closing sleep below, so the schedule
            // never re-reads a clock that could have been stepped.
            clock
                .sleep(config.alignment_delay_ms(wall_clock_unix_ms()))
                .await;

            let mut jitter = JitterSequence::for_replica(&local_zid);
            loop {
                // Measured on the SAME timeline the sleeps below run on, which
                // is what makes the closing subtraction mean anything.
                let cycle_start = clock.now_monotonic_ms();

                // Wait out the configured propagation delay BEFORE reading the
                // store, so publications still in transit toward this node have
                // landed and the digest describes a settled interval
                // (core.rs:203-209). This is the parameter that
                // [`ReplicationConfig`] has always hashed into the
                // configuration fingerprint that gates digest exchange.
                clock.sleep(config.propagation_delay_ms()).await;

                let (keyexpr, bytes) =
                    digest_frame(&state, &config, &local_zid, wall_clock_ntp64());

                // The JITTER sits between the build and the put, as upstream's
                // does (core.rs:234-243): it de-correlates when the fleet
                // TRANSMITS, while the digest still describes the moment the
                // propagation window closed. Jittering before the build would
                // move the observation instead.
                clock
                    .sleep(config.publication_delay_ms(jitter.next_draw()))
                    .await;

                // A publish error (e.g. a torn-down link) is non-fatal to the
                // loop — the next cycle republishes the full current digest.
                let _ = session.publish(&keyexpr, &bytes, PublishOptions::put());

                // Close the cycle so the PERIOD is interval_ms: the cycle's own
                // work is subtracted, not added on top (core.rs:262-272).
                // `None` = the cycle overran an interval, where upstream warns
                // and re-enters immediately; re-entering is the honest
                // response, since sleeping would push the drift further.
                let elapsed = clock.now_monotonic_ms().saturating_sub(cycle_start);
                if let Some(rest) = config.post_publication_delay_ms(elapsed) {
                    clock.sleep(rest).await;
                }
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
        // `mut` since R2354 — see [`digest_frame`].
        let mut guard = state.lock().expect("storage state mutex poisoned");
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
            Some("demo/a"),
            vec![1, 2, 3],
            None,
            TimestampHint {
                time: now,
                zid: vec![0x01],
            },
        )
        .unwrap();
        Arc::new(Mutex::new(st))
    }

    fn state_with(keys: &[&str], now: u64) -> StorageState<MemoryStorage> {
        use wz_session_core::sample::TimestampHint;
        let mut st = StorageState::new(MemoryStorage::new());
        for (i, key) in keys.iter().enumerate() {
            st.process_put(
                Some(key),
                vec![i as u8],
                None,
                TimestampHint {
                    time: now,
                    zid: vec![0x01],
                },
            )
            .unwrap();
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
        let mut local = state_with(&["demo/a"], now);
        // The peer holds an extra key -> the local replica diverges from it.
        let mut peer = state_with(&["demo/a", "demo/b"], now);
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
        let mut local = state_with(&["demo/a"], now);
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
        use wz_session_core::storage_config::StorageConfig;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let storage = StorageService::declare(
            &session,
            &StorageConfig::new("demo", "demo/**", "mem"),
            vec![0x01],
        )
        .expect("storage declares");
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
        // Defense-in-depth: a non-hex zid chunk (a crafted/non-conformant peer
        // splicing a keyexpr wildcard) is rejected so it cannot become a
        // wildcard aligner query keyexpr.
        assert_eq!(
            digest_keyexpr_zid_hex("@-digest/a$*/9"),
            None,
            "wildcard zid chunk rejected"
        );
        assert_eq!(
            digest_keyexpr_zid_hex("@-digest/**/9"),
            None,
            "wildcard zid chunk rejected"
        );
        assert_eq!(
            digest_keyexpr_zid_hex("@-digest/ZZ/9"),
            None,
            "non-hex zid rejected"
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
    // Exercises spawn -> the publication cycle -> digest_frame -> keyexpr ->
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

    /// Records, in the publisher's own virtual clock, the millisecond offset
    /// from spawn of the first `count` digests a `config`-configured publisher
    /// emits.
    ///
    /// The instant is taken INSIDE the subscriber callback, at the exact
    /// virtual moment the digest lands, so an offset is never conflated with
    /// the granularity of a poll. The wait is a `Notify` rather than a poll
    /// sleep: under `start_paused` the runtime auto-advances to the earliest
    /// pending deadline, so with no poll timer of our own the clock jumps
    /// straight to the publisher's next wake — the offsets are exact, not
    /// rounded to a polling period. Returning FEWER than `count` offsets is a
    /// distinct failure from a wrong offset, and the callers assert the length
    /// before the values.
    #[cfg(all(feature = "declare-subscriber", feature = "pubsub-allow-loop"))]
    async fn publication_offsets_ms(config: &ReplicationConfig, count: usize) -> Vec<u64> {
        use crate::observer::ApplicationLayerObserver;
        use crate::runtime_impl::TokioTime;
        use crate::session::TokioSession;
        use std::time::Duration;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let zid = vec![0x01];
        let state = put_state(wall_clock_ntp64());

        let spawned_at = tokio::time::Instant::now();
        let offsets: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let landed = Arc::new(tokio::sync::Notify::new());

        let rx = Arc::clone(&offsets);
        let tx = Arc::clone(&landed);
        let _sub = session
            .declare_subscriber(
                digest_keyexpr(config, &zid),
                SubscribeOptions::default(),
                move |_v: &dyn SampleView| {
                    let dt = tokio::time::Instant::now().duration_since(spawned_at);
                    rx.lock().unwrap().push(dt.as_millis() as u64);
                    // `notify_one` stores a permit, so a digest that lands
                    // while nobody is parked is not lost — the waiter wakes on
                    // the stored permit and re-reads the length.
                    tx.notify_one();
                },
            )
            .expect("digest keyexpr subscriber declares");

        let publisher = DigestPublisher::spawn(&session, state, config.clone(), zid);

        // Virtual time, so this budget costs no wall-clock; it is the
        // fail-loud bound for a publisher that stopped emitting, not a race.
        let _ = tokio::time::timeout(Duration::from_secs(600), async {
            loop {
                if offsets.lock().unwrap().len() >= count {
                    return;
                }
                landed.notified().await;
            }
        })
        .await;

        drop(publisher); // RAII abort before reading, so the vector is stable.
        let out = offsets.lock().unwrap().clone();
        out
    }

    /// R311y829 — the residual this round pays off, with its own CONTROL in
    /// the same test.
    ///
    /// [`ReplicationConfig`] has always carried `propagation_delay_ms` and
    /// hashed it into the configuration fingerprint that gates digest exchange
    /// (zenoh `configuration.rs:72`), while the publisher never read it: the
    /// loop was a plain `interval_ms` tick, so this measured `[20, 40]` before
    /// the fix — identical to a replica configured with no delay at all.
    ///
    /// The zero-delay half is what makes the green mean something: "the first
    /// digest is late" would also be true of a publisher that is simply slow,
    /// or of a dead observation window. Two configurations differing ONLY in
    /// this parameter must land in disjoint windows.
    #[cfg(all(feature = "declare-subscriber", feature = "pubsub-allow-loop"))]
    #[tokio::test(start_paused = true)]
    async fn the_publisher_waits_the_configured_propagation_delay() {
        // interval 20ms, propagation delay 250ms — an order of magnitude
        // LARGER than the interval, so honouring it cannot be mistaken for
        // tick jitter.
        let delayed = cfg();
        assert_eq!(delayed.interval_ms(), 20);
        assert_eq!(delayed.propagation_delay_ms(), 250);
        let prompt = ReplicationConfig::new("demo/**", None, 20, 5, 6, 30, 0);

        let delayed_offsets = publication_offsets_ms(&delayed, 1).await;
        let prompt_offsets = publication_offsets_ms(&prompt, 1).await;
        assert_eq!(delayed_offsets.len(), 1, "{delayed_offsets:?}");
        assert_eq!(prompt_offsets.len(), 1, "{prompt_offsets:?}");

        // The first digest lands at `alignment + propagation + jitter`, and
        // the two outer terms are bounded by the config rather than known
        // exactly: the alignment is `interval - (unix_ms % interval)` on the
        // real wall clock, so 1..=20, and the jitter is `0..interval/3`, so
        // 0..=5. The two windows below are therefore [251, 275] and [1, 25] —
        // disjoint, which is the whole point.
        let window = |base: u64| (base + 1)..=(base + 20 + 5);

        assert!(
            window(250).contains(&delayed_offsets[0]),
            "the 250ms propagation delay precedes the first digest: {} not in \
             {:?}",
            delayed_offsets[0],
            window(250)
        );
        assert!(
            window(0).contains(&prompt_offsets[0]),
            "CONTROL — with no configured delay the same publisher emits \
             within one interval: {} not in {:?}",
            prompt_offsets[0],
            window(0)
        );
    }

    /// R311y829 — the publication PERIOD is `interval_ms`, not `interval_ms`
    /// plus however long the cycle's own work took.
    ///
    /// zenoh subtracts the elapsed cycle from the closing sleep
    /// (core.rs:262-272); without that subtraction a replica configured for a
    /// 1s interval publishes every 1.1s here, and the drift compounds for the
    /// life of the session. The propagation delay is deliberately non-zero so
    /// the cycle has real work to absorb — with a zero-work cycle the
    /// compensated and uncompensated schedules are indistinguishable, which
    /// is exactly the measurement this test must not make.
    ///
    /// The span is measured over TEN cycles rather than one because the
    /// jitter re-randomises the transmit instant inside each cycle: one
    /// interval is `1000 + (jₙ − jₙ₋₁)`, which at ±332ms overlaps an
    /// uncompensated cycle and would decide nothing. Over ten, the jitter
    /// difference is still one draw wide while the drift has accumulated ten
    /// times over. Measured: dropping the subtraction spans 12651ms here,
    /// since an uncompensated period is `interval + propagation + jitter`
    /// rather than `interval`.
    #[cfg(all(feature = "declare-subscriber", feature = "pubsub-allow-loop"))]
    #[tokio::test(start_paused = true)]
    async fn the_publication_period_absorbs_the_cycles_own_work() {
        // 100ms propagation + at most 333ms jitter fits inside the 1s
        // interval, so every cycle has something to subtract and none of them
        // overruns.
        let config = ReplicationConfig::new("demo/**", None, 1_000, 5, 6, 30, 100);
        let jitter_bound = config.max_publication_delay_ms();
        assert_eq!(jitter_bound, 333);

        let offsets = publication_offsets_ms(&config, 11).await;

        assert_eq!(
            offsets.len(),
            11,
            "eleven digests are observed: {offsets:?}"
        );
        let span = offsets[10] - offsets[0];
        assert!(
            span.abs_diff(10_000) < jitter_bound,
            "ten cycles span ten intervals, whatever each cycle spent on its \
             propagation wait and jitter: {span} is not within {jitter_bound} \
             of 10000 (dropping the subtraction measured 12651 here, eight \
             jitter-widths away). offsets: {offsets:?}"
        );
    }
}
