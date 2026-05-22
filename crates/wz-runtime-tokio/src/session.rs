// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R228 — application-level [`Session`] bundle.
//!
//! [`Session`] owns the outbound action handle ([`SessionLinkActions`])
//! and a shared reference to the inbound observer
//! ([`ApplicationLayerObserver`]) so a single [`Session::publish`] call
//! routes through both the wire-side codec and the in-process
//! subscriber loopback. Mirrors zenoh-pico's `_z_session_t`, which
//! similarly owns both the transport handle and the local subscription
//! table (`vendor/zenoh-pico/include/zenoh-pico/net/session.h` 172,
//! `vendor/zenoh-pico/src/net/primitives.c::_z_write` 170-205 fans the
//! outbound publish across `allows_remote()` / `allows_local()` from a
//! single entry point).
//!
//! ## Scope (R228 minimum-viable)
//!
//! * [`Session::publish`] handles literal-keyexpr Put + Del. Aliased
//!   (`mapping_id != 0`) publish is an R229 carry — the symmetric
//!   counterpart to [`crate::session_glue::SessionLinkActions::send_push_aliased`]
//!   will land as `publish_aliased` once a use case surfaces.
//! * [`PublishOptions`] carries the three load-bearing knobs
//!   (`allowed_destination`, `reliability`, `kind`). The remaining
//!   five [`crate::sample::Sample`] body fields (`qos`, `attachment`,
//!   `timestamp`, `encoding`, `source_info`) are R229+ carries —
//!   the wire path's `send_push_literal` currently does not accept
//!   them either, so propagating them through `Session::publish`
//!   would surface an asymmetry between the wire branch (loses the
//!   metadata) and the loopback branch (preserves it).
//! * `Session` is a NEW public surface introduced in parallel with
//!   the legacy direct-`SessionLinkActions` + direct-`ApplicationLayerObserver`
//!   pattern that `wz-ap-demo` and the integration suite still use.
//!   R230+ carry: migrate `wz-ap-demo` to `Session` and route every
//!   subscriber registration through `Session::observer().lock()`
//!   instead of directly on `observer.subscribers`.
//!
//! ## Locking discipline
//!
//! The observer is wrapped in [`std::sync::Mutex`] (not
//! [`tokio::sync::Mutex`]) because the loopback branch runs the
//! subscriber callbacks synchronously — exactly the semantic of a
//! locally-published Sample under zenoh-pico's
//! `_z_session_deliver_push_locally`
//! (`vendor/zenoh-pico/src/session/loopback.c` 70-100) which fires
//! the subscription callbacks in-line under the session lock. A
//! `tokio::sync::Mutex` would force `publish` to be `async`, which
//! would in turn force callers to be `async`, propagating a
//! coloring change for no measurable benefit — the lock window is
//! the time it takes to walk the subscriber table once.
//!
//! ## Wire / loopback symmetry today (R228) vs zenoh-pico
//!
//! zenoh-pico's `_z_write` constructs the same [`crate::sample::Sample`]-
//! shaped record once and routes both branches off the same record.
//! wz at R228 constructs the wire-side `Push` via the legacy
//! `send_push_literal` / `send_push_del_literal` builders AND
//! constructs the loopback-side `Sample` via the `new_put` / `new_del`
//! builder — two separate constructions. R229+ candidate: unify the
//! construction so both branches read the same source struct (an
//! intermediate `PublishRecord` that the wire side encodes and the
//! loopback side projects to `Sample`).

use std::sync::{Arc, Mutex};

use crate::locality::Locality;
use crate::observer::ApplicationLayerObserver;
use crate::sample::{Reliability, Sample, SampleKind};
use crate::session_glue::SessionLinkActions;

/// Options bundle for [`Session::publish`]. Carries the locality
/// routing predicate (`allowed_destination`), the reliability hint
/// for the wire frame and the loopback `Sample.reliability` field,
/// and the [`SampleKind`] discriminator that selects Put vs Del
/// dispatch.
///
/// Construct via [`PublishOptions::put`] / [`PublishOptions::del`]
/// plus optional `with_*` setters; defaults to a Put publish that
/// fans both branches (`Locality::Any`) with `Reliability::Reliable`
/// matching zenoh-pico's `Z_RELIABILITY_DEFAULT`.
///
/// Future-additive: this struct is `#[non_exhaustive]` so R229+ can
/// add metadata fields (`qos`, `attachment`, `timestamp`, `encoding`,
/// `source_info`) without breaking external callers when the wire-side
/// `send_push_literal` learns to accept them. Construct through the
/// builder API rather than struct-literal so the future-additive
/// contract holds.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PublishOptions {
    /// Publisher-side locality predicate (zenoh-pico
    /// `allowed_destination` parameter to `_z_write`). `Any` routes
    /// to both wire and loopback branches; `Remote` to wire only;
    /// `SessionLocal` to loopback only. Default: `Any`.
    pub allowed_destination: Locality,
    /// Link-layer reliability hint propagated to (a) the wire frame's
    /// reliable-flag (zenoh-pico `FLAG_T_FRAME_R`) and (b) the
    /// loopback `Sample.reliability` field. Default: `Reliable`.
    pub reliability: Reliability,
    /// Sample discriminator. `Put` carries the caller payload; `Del`
    /// carries an empty payload (the keyexpr is the entire payload).
    /// Default: `Put`.
    pub kind: SampleKind,
}

impl Default for PublishOptions {
    fn default() -> Self {
        Self {
            allowed_destination: Locality::default(),
            reliability: Reliability::default(),
            kind: SampleKind::Put,
        }
    }
}

impl PublishOptions {
    /// Default Put-kind options: `allowed_destination = Any`,
    /// `reliability = Reliable`.
    pub fn put() -> Self {
        Self::default()
    }

    /// Default Del-kind options: `allowed_destination = Any`,
    /// `reliability = Reliable`, `kind = Del`. The payload argument
    /// to [`Session::publish`] is ignored for Del kind (zenoh-pico
    /// `_z_n_msg_make_push_del` does not carry payload).
    pub fn del() -> Self {
        Self {
            kind: SampleKind::Del,
            ..Self::default()
        }
    }

    /// Pin the publisher-side locality predicate.
    pub fn with_locality(mut self, locality: Locality) -> Self {
        self.allowed_destination = locality;
        self
    }

    /// Pin the reliability hint.
    pub fn with_reliability(mut self, reliability: Reliability) -> Self {
        self.reliability = reliability;
        self
    }

    /// Pin the Sample kind.
    pub fn with_kind(mut self, kind: SampleKind) -> Self {
        self.kind = kind;
        self
    }

    /// Translate [`Reliability`] into the bool flag the legacy
    /// `send_push_*` outbound API expects (it predates the typed
    /// enum). Exposed inside the crate so [`Session::publish`] does
    /// the conversion in exactly one place.
    fn reliable_bool(&self) -> bool {
        matches!(self.reliability, Reliability::Reliable)
    }
}

/// Application-level session bundle. Owns the outbound action handle
/// plus a shared reference to the inbound observer so a single call
/// to [`Session::publish`] routes both branches per the
/// `allowed_destination` predicate on [`PublishOptions`].
///
/// See module-level docs for the wire / loopback symmetry contract,
/// the locking discipline, and the R228 → R229+ carry map.
pub struct Session {
    /// Outbound action handle. Cloned `Arc` — multiple `Session`s
    /// can share the same actions if the application binds several
    /// publish surfaces to the same physical session.
    actions: Arc<SessionLinkActions>,
    /// Inbound observer wrapped in [`Mutex`] so [`Session::publish`]'s
    /// loopback branch can borrow the subscriber registry through
    /// the same handle the main dispatch loop uses.
    observer: Arc<Mutex<ApplicationLayerObserver>>,
}

impl Session {
    /// Construct a new session bundle from existing handles.
    /// `actions` typically comes from
    /// [`SessionLinkActions::new`](crate::session_glue::SessionLinkActions::new);
    /// `observer` is a freshly-wrapped
    /// [`ApplicationLayerObserver::new`](crate::observer::ApplicationLayerObserver::new).
    pub fn new(
        actions: Arc<SessionLinkActions>,
        observer: Arc<Mutex<ApplicationLayerObserver>>,
    ) -> Self {
        Self { actions, observer }
    }

    /// Borrow the outbound action handle. Useful when the caller
    /// needs to invoke non-publish methods like `send_declare_*` or
    /// `send_request_query` directly on the actions surface.
    pub fn actions(&self) -> &Arc<SessionLinkActions> {
        &self.actions
    }

    /// Borrow the observer handle. Application code registers
    /// callbacks on the contained registries through this — typically
    /// `session.observer().lock().unwrap().subscribers.register(...)`.
    pub fn observer(&self) -> &Arc<Mutex<ApplicationLayerObserver>> {
        &self.observer
    }

    /// Publish a literal-keyexpr Sample. Routes both branches per
    /// `opts.allowed_destination`:
    ///
    /// * [`Locality::allows_remote`] → wire send via
    ///   [`SessionLinkActions::send_push_literal`] (Put) or
    ///   [`SessionLinkActions::send_push_del_literal`] (Del). The
    ///   `payload` is ignored on Del kind.
    /// * [`Locality::allows_local`] → loopback dispatch via
    ///   [`crate::pubsub::SubscriberRegistry::local_publish`] with a
    ///   newly-built [`Sample`] carrying `keyexpr` / `payload` /
    ///   `opts.kind` / `opts.reliability` (R228 scope) and default
    ///   `None` for `qos` / `attachment` / `timestamp` / `encoding` /
    ///   `source_info` (R229+ carries).
    ///
    /// Returns the number of subscriber callbacks the loopback branch
    /// fired (0 if `allows_local()` is false OR no subscribers match
    /// the keyexpr). Wire-branch outcomes are not reported through
    /// this return value — fire-and-forget per
    /// [`SessionLinkActions::send_push_literal`]'s shape.
    ///
    /// Mirrors zenoh-pico's `_z_write` `vendor/zenoh-pico/src/net/primitives.c`
    /// 170-205: wire branch under `allows_remote()`, loopback branch
    /// under `allows_local()`. Both branches run when
    /// `Locality::Any` (the default) and the publisher's intent is
    /// "fan to every receiver, in-process and remote".
    pub fn publish(
        &self,
        keyexpr: &str,
        payload: &[u8],
        opts: PublishOptions,
    ) -> usize {
        let reliable = opts.reliable_bool();
        if opts.allowed_destination.allows_remote() {
            match opts.kind {
                SampleKind::Put => {
                    self.actions.send_push_literal(keyexpr, payload, reliable);
                }
                SampleKind::Del => {
                    self.actions.send_push_del_literal(keyexpr, reliable);
                }
            }
        }
        if opts.allowed_destination.allows_local() {
            let sample = match opts.kind {
                SampleKind::Put => {
                    Sample::new_put(keyexpr, payload.to_vec())
                        .with_reliability(opts.reliability)
                }
                SampleKind::Del => {
                    Sample::new_del(keyexpr).with_reliability(opts.reliability)
                }
            };
            self.observer
                .lock()
                .expect("Session observer mutex poisoned — a subscriber callback panicked")
                .subscribers
                .local_publish(&sample)
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::ApplicationLayerObserver;
    use crate::session_glue::{BoxedLinkDriver, SessionInitParams, SigningKey};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Captures every outbound wire send so tests can assert wire
    /// branch fires only when `allows_remote()` holds. Mirrors the
    /// `RecordingDriver` shape already used by session_glue tests.
    struct RecordingDriver {
        frames: Mutex<Vec<(Vec<u8>, Reliability)>>,
    }

    impl RecordingDriver {
        fn new() -> Self {
            Self {
                frames: Mutex::new(Vec::new()),
            }
        }

        fn frame_count(&self) -> usize {
            self.frames.lock().unwrap().len()
        }

        fn frame_reliability(&self, idx: usize) -> Reliability {
            self.frames.lock().unwrap()[idx].1
        }
    }

    impl BoxedLinkDriver for RecordingDriver {
        fn send_blocking(&self, bytes: &[u8], r: Reliability) {
            self.frames.lock().unwrap().push((bytes.to_vec(), r));
        }
        fn open_blocking(&self) {}
        fn close_blocking(&self) {}
    }

    fn fixture_params() -> SessionInitParams {
        SessionInitParams {
            version: 0x09,
            whatami: 0x02,
            zid: vec![0x01, 0x02, 0x03, 0x04],
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 65535,
            lease: 10_000,
            lease_in_seconds: false,
            initial_sn: 1,
            cookie: Vec::new(),
            cookie_signing_key: SigningKey::new(vec![0xAB; 32])
                .expect("32-byte demo key satisfies the >=32 invariant"),
        }
    }

    /// Convenience constructor that returns a (Session,
    /// driver_handle) pair so tests can assert against both the
    /// outbound wire branch (via the driver) and the loopback branch
    /// (via the observer borrowed off the session).
    fn build_session() -> (Session, Arc<RecordingDriver>) {
        let driver = Arc::new(RecordingDriver::new());
        let actions = SessionLinkActions::new(driver.clone(), fixture_params());
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        (Session::new(actions, observer), driver)
    }

    #[test]
    fn publish_options_default_is_put_any_reliable() {
        let opts = PublishOptions::default();
        assert_eq!(opts.kind, SampleKind::Put);
        assert_eq!(opts.allowed_destination, Locality::Any);
        assert_eq!(opts.reliability, Reliability::Reliable);
    }

    #[test]
    fn publish_options_put_and_del_constructors() {
        let put = PublishOptions::put();
        assert_eq!(put.kind, SampleKind::Put);
        let del = PublishOptions::del();
        assert_eq!(del.kind, SampleKind::Del);
    }

    #[test]
    fn publish_options_with_setters_chain() {
        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_reliability(Reliability::BestEffort)
            .with_kind(SampleKind::Del);
        assert_eq!(opts.allowed_destination, Locality::SessionLocal);
        assert_eq!(opts.reliability, Reliability::BestEffort);
        assert_eq!(opts.kind, SampleKind::Del);
    }

    #[test]
    fn publish_locality_any_fires_wire_and_loopback() {
        let (session, driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        let fired = session.publish("home/temp", b"22.5", PublishOptions::put());
        assert_eq!(fired, 1, "Locality::Any fires loopback subscriber");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(
            driver.frame_count(),
            1,
            "Locality::Any also fires wire branch (one frame on the driver)"
        );
    }

    #[test]
    fn publish_locality_remote_fires_wire_only() {
        let (session, driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        let opts = PublishOptions::put().with_locality(Locality::Remote);
        let fired = session.publish("home/temp", b"22.5", opts);
        assert_eq!(
            fired, 0,
            "Locality::Remote suppresses loopback branch entirely"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert_eq!(
            driver.frame_count(),
            1,
            "wire branch still fires under allows_remote()"
        );
    }

    #[test]
    fn publish_locality_session_local_fires_loopback_only() {
        let (session, driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
        let fired = session.publish("home/temp", b"22.5", opts);
        assert_eq!(fired, 1, "loopback branch fires the Any-default subscriber");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(
            driver.frame_count(),
            0,
            "wire branch is suppressed under Locality::SessionLocal"
        );
    }

    #[test]
    fn publish_loopback_sample_carries_options_reliability_and_kind() {
        let (session, _driver) = build_session();
        let captured = Arc::new(Mutex::new(None::<Sample>));
        let captured_clone = captured.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |sample| {
                *captured_clone.lock().unwrap() = Some(sample.clone());
            });

        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_reliability(Reliability::BestEffort);
        let fired = session.publish("home/temp", b"22.5", opts);
        assert_eq!(fired, 1);
        let observed = captured.lock().unwrap().clone().expect("callback fired");
        assert_eq!(observed.keyexpr, "home/temp");
        assert_eq!(observed.kind, SampleKind::Put);
        assert_eq!(observed.payload, b"22.5");
        assert_eq!(
            observed.reliability,
            Reliability::BestEffort,
            "PublishOptions.reliability propagates into Sample.reliability"
        );
    }

    #[test]
    fn publish_del_kind_routes_to_del_loopback_with_empty_payload() {
        let (session, _driver) = build_session();
        let captured = Arc::new(Mutex::new(None::<(SampleKind, Vec<u8>)>));
        let captured_clone = captured.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |sample| {
                *captured_clone.lock().unwrap() =
                    Some((sample.kind, sample.payload.clone()));
            });

        let opts = PublishOptions::del().with_locality(Locality::SessionLocal);
        // Payload argument is ignored for Del kind — the Sample observed
        // by the subscriber carries an empty payload regardless.
        let fired = session.publish("home/temp", b"ignored", opts);
        assert_eq!(fired, 1);
        let (kind, payload) = captured.lock().unwrap().clone().expect("fired");
        assert_eq!(kind, SampleKind::Del);
        assert!(payload.is_empty(), "Del Sample carries no payload");
    }

    #[test]
    fn publish_reliability_propagates_to_wire_frame_flag() {
        let (session, driver) = build_session();
        let opts = PublishOptions::put()
            .with_locality(Locality::Remote)
            .with_reliability(Reliability::BestEffort);
        session.publish("home/temp", b"x", opts);
        assert_eq!(driver.frame_count(), 1);
        assert_eq!(
            driver.frame_reliability(0),
            Reliability::BestEffort,
            "PublishOptions.reliability sets the wire-frame reliability hint"
        );

        let opts = PublishOptions::put()
            .with_locality(Locality::Remote)
            .with_reliability(Reliability::Reliable);
        session.publish("home/temp", b"x", opts);
        assert_eq!(driver.frame_count(), 2);
        assert_eq!(driver.frame_reliability(1), Reliability::Reliable);
    }

    #[test]
    fn publish_with_no_subscribers_returns_zero_on_loopback() {
        let (session, _driver) = build_session();
        let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
        let fired = session.publish("home/temp", b"x", opts);
        assert_eq!(
            fired, 0,
            "empty registry yields zero fired subscribers without panic"
        );
    }

    #[test]
    fn publish_locality_remote_only_returns_zero_even_with_matching_subscriber() {
        let (session, _driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        let opts = PublishOptions::put().with_locality(Locality::Remote);
        let fired = session.publish("home/temp", b"x", opts);
        assert_eq!(
            fired, 0,
            "Locality::Remote never enters the loopback branch, so fired count is always 0"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn publish_returns_multi_subscriber_fired_count() {
        let (session, _driver) = build_session();
        let hits_a = Arc::new(AtomicUsize::new(0));
        let hits_b = Arc::new(AtomicUsize::new(0));
        {
            let clone = hits_a.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register("home/temp", move |_sample| {
                    clone.fetch_add(1, Ordering::SeqCst);
                });
        }
        {
            let clone = hits_b.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register("home/*", move |_sample| {
                    clone.fetch_add(1, Ordering::SeqCst);
                });
        }

        let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
        let fired = session.publish("home/temp", b"22.5", opts);
        assert_eq!(fired, 2, "both matching subscribers fire on loopback");
        assert_eq!(hits_a.load(Ordering::SeqCst), 1);
        assert_eq!(hits_b.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn publish_locality_session_local_skips_remote_subscribers() {
        // Mixed locality on the same keyexpr — Session::publish with
        // SessionLocal routes only to loopback (no wire), and only
        // SessionLocal + Any subscribers fire on that branch. The
        // Remote subscriber is silent because its allows_local() is
        // false.
        let (session, driver) = build_session();
        let any_hits = Arc::new(AtomicUsize::new(0));
        let local_hits = Arc::new(AtomicUsize::new(0));
        let remote_hits = Arc::new(AtomicUsize::new(0));
        {
            let clone = any_hits.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register_with_locality("home/temp", Locality::Any, move |_sample| {
                    clone.fetch_add(1, Ordering::SeqCst);
                });
        }
        {
            let clone = local_hits.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register_with_locality(
                    "home/temp",
                    Locality::SessionLocal,
                    move |_sample| {
                        clone.fetch_add(1, Ordering::SeqCst);
                    },
                );
        }
        {
            let clone = remote_hits.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register_with_locality(
                    "home/temp",
                    Locality::Remote,
                    move |_sample| {
                        clone.fetch_add(1, Ordering::SeqCst);
                    },
                );
        }

        let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
        let fired = session.publish("home/temp", b"22.5", opts);
        assert_eq!(
            fired, 2,
            "Session::publish(SessionLocal) fires Any + SessionLocal, suppresses Remote"
        );
        assert_eq!(any_hits.load(Ordering::SeqCst), 1);
        assert_eq!(local_hits.load(Ordering::SeqCst), 1);
        assert_eq!(remote_hits.load(Ordering::SeqCst), 0);
        assert_eq!(
            driver.frame_count(),
            0,
            "Locality::SessionLocal suppresses the wire branch"
        );
    }
}
