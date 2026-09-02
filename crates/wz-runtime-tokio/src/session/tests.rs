// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311jg — Session behavioural test suite, extracted verbatim from the
//! former monolithic session.rs into the `session::tests` child module
//! so the production decomposition keeps mod.rs to the Session core.

use super::*;
use crate::observer::ApplicationLayerObserver;
#[cfg(all(feature = "query-get", feature = "query-queryable"))]
use crate::reply::InboundReplyBody;
#[cfg(all(feature = "query-get", feature = "query-queryable"))]
use crate::reply_sink::ReplyKind;
use crate::runtime_impl::TokioTime;
use crate::test_fixtures::{recording_actions, recording_actions_with_params, RecordingLinkDriver};
use portable_atomic::{AtomicUsize, Ordering};
use wz_runtime_core::TimeSource;
use wz_runtime_tokio_test_support::fixture_session_init_params;

/// R283 test helper — force the session-FSM `Established` stamp
/// without driving the full handshake. The production path
/// populates `established_at` via the `record_established_at` Lua
/// action wired to `Established.onentry` in
/// `session_fsm_unicast.scxml`; pure-Rust unit tests skip the
/// SCXML driver and stamp the field directly. Mirror of any
/// other test fixture that needs to bypass FSM driving (e.g. the
/// keyexpr mapping is populated via `send_declare_keyexpr` rather
/// than driving the peer's `DeclKexpr` inbound).
fn mark_session_established(session: &TokioSession) {
    // R311nf — `actions()` is now infallible on `TokioSession` (= `Session<_,_,Unicast>`).
    *session
        .actions()
        .link
        .established_at
        .lock()
        .expect("established_at poisoned in test fixture") =
        Some(session.actions().clock.now_monotonic_ms());
}

/// Convenience constructor that returns a (Session,
/// driver_handle) pair so tests can assert against both the
/// outbound wire branch (via the driver) and the loopback branch
/// (via the observer borrowed off the session). The driver +
/// `SessionInitParams` come from the crate-local `test_fixtures`
/// SSOT (`recording_actions()`); the former local `RecordingDriver`
/// + `fixture_params` duplicate was folded into it.
fn build_session() -> (TokioSession, Arc<RecordingLinkDriver>) {
    let (actions, driver) = recording_actions();
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    // R311cw — Session::new takes `Arc<T>` clock; R311nf — `TokioSession` alias.
    let clock = Arc::new(TokioTime::new());
    (TokioSession::new(actions, observer, clock), driver)
}

/// R311y836 — `QueryOptions::get()` for a test whose SUBJECT IS NOT
/// CONSOLIDATION, and which therefore needs replies delivered one by one, in
/// arrival order, as they land.
///
/// y836 made the unnamed mode resolve to `Latest` (`zenoh/src/api/session.rs:2250`),
/// and `Latest` is defined as holding samples back to emit one set at the end —
/// "Holds back samples to only send the set of samples that had the highest
/// timestamp for their key" (`commons/zenoh-protocol/src/zenoh/query.rs:37`). So
/// under the default a reply is no longer observable INLINE, and the flush order
/// is the cache's rather than the wire's. Four locality / aliasing tests and the
/// `_anyke` acceptance test asserted exactly those two things while proving
/// something else entirely; MEASURED, they read `left: 0 / right: 1` on
/// "loopback reply fires inline" and `left: [out, in] / right: [in, out]` on
/// arrival order. Neither is a property zenoh's DEFAULT get has, so the trigger
/// was wrong, not the claim — the claims survive verbatim under an explicit
/// `None`.
///
/// Assigned as the FIELD, not through the `query-consolidation`-gated setter,
/// for the reason `advanced_publisher::tests::adv_recovery_get_options` states:
/// the setter's gate would change WHICH LANES RUN THESE TESTS for a reason
/// orthogonal to what they prove. With the feature off the field is inert
/// (`effective_consolidation` hard-returns `None`).
///
/// R311y837 — the gate GAINED `query-queryable`, which is the cfg all five of
/// its callers already carry. `query-get` alone was too wide: the C1j
/// `zget-reply-only` subset composes `query-get` WITHOUT `query-queryable`, so
/// the helper had no caller there and the lane failed to BUILD under
/// `-D warnings` — hosted-only, because no local lane composes that subset.
/// A private test helper inherits its callers' cfg or it is dead somewhere.
#[cfg(all(feature = "query-get", feature = "query-queryable"))]
fn get_opts_in_arrival_order() -> QueryOptions {
    QueryOptions {
        consolidation: Some(wz_session_core::query_mode::ConsolidationMode::None),
        ..QueryOptions::get()
    }
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

#[cfg(all(feature = "codec-push", feature = "pubsub-allow-loop"))]
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

    let fired = session
        .publish("home/temp", b"22.5", PublishOptions::put())
        .unwrap();
    assert_eq!(fired, 1, "Locality::Any fires loopback subscriber");
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_eq!(
        driver.frame_count(),
        1,
        "Locality::Any also fires wire branch (one frame on the driver)"
    );
}

#[cfg(feature = "codec-push")]
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
    let fired = session.publish("home/temp", b"22.5", opts).unwrap();
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

#[cfg(feature = "pubsub-allow-loop")]
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
    let fired = session.publish("home/temp", b"22.5", opts).unwrap();
    assert_eq!(fired, 1, "loopback branch fires the Any-default subscriber");
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_eq!(
        driver.frame_count(),
        0,
        "wire branch is suppressed under Locality::SessionLocal"
    );
}

// R311hy — pubsub-allow-loop NEG / isolation. The POS twins
// (publish_locality_session_local_fires_loopback_only +
// publish_aliased_locality_session_local_fires_loopback_only) are
// cfg-gated ON `pubsub-allow-loop`, so they run only in the all-on
// default build; with the feature OFF nothing otherwise proves the
// loopback branch actually elides. `pubsub-allow-loop` is OFF in every
// C1j consumer-plane subset (none compose it), so these guards run
// there. Contract (Session::publish / publish_aliased
// `#[cfg(not(pubsub-allow-loop))]` arm at session.rs ~1043 / ~1149): a
// SessionLocal publish must short-circuit to Ok(0) and NEVER invoke
// the registered subscriber callback — a regression that silently
// un-gated the loopback would fire it. Two guards because publish and
// publish_aliased are distinct cfg sites.
#[cfg(not(feature = "pubsub-allow-loop"))]
#[test]
fn publish_session_local_does_not_fire_loopback_when_allow_loop_off() {
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
    let fired = session.publish("home/temp", b"22.5", opts).unwrap();
    assert_eq!(
        fired, 0,
        "pubsub-allow-loop OFF: SessionLocal publish must short-circuit to Ok(0)"
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "pubsub-allow-loop OFF: the loopback subscriber callback must not fire"
    );
    assert_eq!(
        driver.frame_count(),
        0,
        "SessionLocal suppresses the wire branch regardless of allow-loop"
    );
}

#[cfg(not(feature = "pubsub-allow-loop"))]
#[test]
fn publish_aliased_session_local_does_not_fire_loopback_when_allow_loop_off() {
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
    let fired = session
        .publish_aliased(7, None, "home/temp", b"22.5", opts)
        .unwrap();
    assert_eq!(
        fired, 0,
        "pubsub-allow-loop OFF: aliased SessionLocal publish short-circuits to Ok(0)"
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "pubsub-allow-loop OFF: the aliased loopback callback must not fire"
    );
    assert_eq!(driver.frame_count(), 0);
}

#[cfg(feature = "pubsub-allow-loop")]
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
            *captured_clone.lock().unwrap() = Some(Sample::from_view(sample));
        });

    let opts = PublishOptions::put()
        .with_locality(Locality::SessionLocal)
        .with_reliability(Reliability::BestEffort);
    let fired = session.publish("home/temp", b"22.5", opts).unwrap();
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

#[cfg(feature = "pubsub-allow-loop")]
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
            *captured_clone.lock().unwrap() = Some((sample.kind(), sample.payload().to_vec()));
        });

    let opts = PublishOptions::del().with_locality(Locality::SessionLocal);
    // Payload argument is ignored for Del kind — the Sample observed
    // by the subscriber carries an empty payload regardless.
    let fired = session.publish("home/temp", b"ignored", opts).unwrap();
    assert_eq!(fired, 1);
    let (kind, payload) = captured.lock().unwrap().clone().expect("fired");
    assert_eq!(kind, SampleKind::Del);
    assert!(payload.is_empty(), "Del Sample carries no payload");
}

#[cfg(feature = "codec-push")]
#[test]
fn publish_reliability_propagates_to_wire_frame_flag() {
    let (session, driver) = build_session();
    let opts = PublishOptions::put()
        .with_locality(Locality::Remote)
        .with_reliability(Reliability::BestEffort);
    session.publish("home/temp", b"x", opts).unwrap();
    assert_eq!(driver.frame_count(), 1);
    assert_eq!(
        driver.frame_reliability(0),
        Reliability::BestEffort,
        "PublishOptions.reliability sets the wire-frame reliability hint"
    );

    let opts = PublishOptions::put()
        .with_locality(Locality::Remote)
        .with_reliability(Reliability::Reliable);
    session.publish("home/temp", b"x", opts).unwrap();
    assert_eq!(driver.frame_count(), 2);
    assert_eq!(driver.frame_reliability(1), Reliability::Reliable);
}

#[test]
fn publish_with_no_subscribers_returns_zero_on_loopback() {
    let (session, _driver) = build_session();
    let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
    let fired = session.publish("home/temp", b"x", opts).unwrap();
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
    let fired = session.publish("home/temp", b"x", opts).unwrap();
    assert_eq!(
        fired, 0,
        "Locality::Remote never enters the loopback branch, so fired count is always 0"
    );
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "pubsub-allow-loop")]
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
    let fired = session.publish("home/temp", b"22.5", opts).unwrap();
    assert_eq!(fired, 2, "both matching subscribers fire on loopback");
    assert_eq!(hits_a.load(Ordering::SeqCst), 1);
    assert_eq!(hits_b.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "pubsub-allow-loop")]
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
            .register_with_locality("home/temp", Locality::SessionLocal, move |_sample| {
                clone.fetch_add(1, Ordering::SeqCst);
            });
    }
    {
        let clone = remote_hits.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register_with_locality("home/temp", Locality::Remote, move |_sample| {
                clone.fetch_add(1, Ordering::SeqCst);
            });
    }

    let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
    let fired = session.publish("home/temp", b"22.5", opts).unwrap();
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

// ── R229 publish_aliased (mapping-id keyexpr) ──

#[cfg(all(feature = "codec-push", feature = "pubsub-allow-loop"))]
#[test]
fn publish_aliased_locality_any_fires_wire_and_loopback() {
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

    // Caller has previously (in prod) called send_declare_keyexpr(7,
    // "home/temp"); the loopback_keyexpr argument restates that
    // resolved form so loopback fires on "home/temp" even though
    // the wire side carries only mapping_id = 7.
    let fired = session
        .publish_aliased(7, None, "home/temp", b"22.5", PublishOptions::put())
        .unwrap();
    assert_eq!(fired, 1, "loopback fires on resolved literal");
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_eq!(
        driver.frame_count(),
        1,
        "wire branch emits one aliased Push frame"
    );
}

#[cfg(feature = "codec-push")]
#[test]
fn publish_aliased_locality_remote_fires_wire_only() {
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
    let fired = session
        .publish_aliased(7, None, "home/temp", b"22.5", opts)
        .unwrap();
    assert_eq!(fired, 0);
    assert_eq!(counter.load(Ordering::SeqCst), 0);
    assert_eq!(driver.frame_count(), 1);
}

#[cfg(feature = "pubsub-allow-loop")]
#[test]
fn publish_aliased_locality_session_local_fires_loopback_only() {
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
    let fired = session
        .publish_aliased(7, None, "home/temp", b"22.5", opts)
        .unwrap();
    assert_eq!(fired, 1);
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_eq!(
        driver.frame_count(),
        0,
        "SessionLocal suppresses the wire-aliased branch"
    );
}

#[cfg(all(feature = "codec-push", feature = "pubsub-allow-loop"))]
#[test]
fn publish_aliased_del_kind_routes_to_del_aliased_with_empty_payload() {
    let (session, driver) = build_session();
    let captured = Arc::new(Mutex::new(None::<(SampleKind, Vec<u8>, String)>));
    let captured_clone = captured.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .subscribers
        .register("home/temp", move |sample| {
            *captured_clone.lock().unwrap() = Some((
                sample.kind(),
                sample.payload().to_vec(),
                sample.keyexpr().to_string(),
            ));
        });

    let opts = PublishOptions::del();
    let fired = session
        .publish_aliased(7, None, "home/temp", b"ignored", opts)
        .unwrap();
    assert_eq!(fired, 1);
    let (kind, payload, keyexpr) = captured.lock().unwrap().clone().expect("fired");
    assert_eq!(kind, SampleKind::Del);
    assert!(payload.is_empty(), "Del Sample carries no payload");
    assert_eq!(keyexpr, "home/temp", "loopback uses resolved literal");
    assert_eq!(driver.frame_count(), 1, "send_push_del_aliased fired once");
}

#[cfg(all(feature = "codec-push", feature = "pubsub-allow-loop"))]
#[test]
fn publish_aliased_reliability_propagates_to_wire_and_sample() {
    let (session, driver) = build_session();
    let captured = Arc::new(Mutex::new(None::<Reliability>));
    let captured_clone = captured.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .subscribers
        .register("home/temp", move |sample| {
            *captured_clone.lock().unwrap() = Some(sample.reliability());
        });

    let opts = PublishOptions::put().with_reliability(Reliability::BestEffort);
    let fired = session
        .publish_aliased(7, None, "home/temp", b"x", opts)
        .unwrap();
    assert_eq!(fired, 1);
    assert_eq!(
        *captured.lock().unwrap(),
        Some(Reliability::BestEffort),
        "Sample.reliability mirrors opts.reliability"
    );
    assert_eq!(driver.frame_count(), 1);
    assert_eq!(
        driver.frame_reliability(0),
        Reliability::BestEffort,
        "wire-frame reliability mirrors opts.reliability"
    );
}

#[cfg(all(feature = "codec-push", feature = "pubsub-allow-loop"))]
#[test]
fn publish_aliased_inline_suffix_passes_through_to_wire() {
    // The wire builder appends the inline suffix to the
    // mapping-id-prefixed Push; the loopback branch uses
    // `loopback_keyexpr` verbatim and does not auto-concatenate.
    // This test pins the contract: caller is responsible for the
    // loopback literal even when an inline suffix is present.
    let (session, driver) = build_session();
    let captured = Arc::new(Mutex::new(None::<String>));
    let captured_clone = captured.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .subscribers
        .register("home/temp/kitchen", move |sample| {
            *captured_clone.lock().unwrap() = Some(sample.keyexpr().to_string());
        });

    let fired = session
        .publish_aliased(
            7,
            Some("/kitchen"),
            "home/temp/kitchen",
            b"x",
            PublishOptions::put(),
        )
        .unwrap();
    assert_eq!(fired, 1);
    assert_eq!(
        *captured.lock().unwrap(),
        Some(String::from("home/temp/kitchen")),
        "loopback keyexpr is the caller-resolved literal"
    );
    assert_eq!(driver.frame_count(), 1, "wire send fires once");
}

#[test]
fn publish_aliased_returns_zero_with_no_loopback_subscriber() {
    let (session, driver) = build_session();
    let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
    let fired = session
        .publish_aliased(7, None, "home/temp", b"x", opts)
        .unwrap();
    assert_eq!(fired, 0, "empty registry yields zero fired callbacks");
    assert_eq!(
        driver.frame_count(),
        0,
        "SessionLocal locality still suppresses wire branch"
    );
}

#[cfg(feature = "pubsub-allow-loop")]
#[test]
fn publish_aliased_loopback_independent_of_wire_keyexpr_form() {
    // Pathological-but-instructive contract assertion: the
    // loopback_keyexpr argument is structurally independent of the
    // (mapping_id, inline_suffix) wire-side pair. Production
    // callers will pass the matching resolved form, but the
    // mechanism does not enforce equivalence — that responsibility
    // sits with the caller per the documented precondition.
    let (session, _driver) = build_session();
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = counter.clone();
    session.observer().lock().unwrap().subscribers.register(
        "intentionally_decoupled",
        move |_sample| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        },
    );

    let fired = session
        .publish_aliased(
            42,
            Some("/whatever"),
            "intentionally_decoupled",
            b"x",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        )
        .unwrap();
    assert_eq!(
        fired, 1,
        "loopback fires on the caller-asserted literal regardless of the wire pair"
    );
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "pubsub-allow-loop")]
#[test]
fn publish_aliased_mixed_locality_isolation_matches_publish_literal() {
    // Symmetric to publish_locality_session_local_skips_remote_subscribers:
    // mixed Any + SessionLocal + Remote subscribers on the loopback
    // literal, publish_aliased with SessionLocal fires Any +
    // SessionLocal, suppresses Remote, no wire frame.
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
            .register_with_locality("home/temp", Locality::Any, move |_s| {
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
            .register_with_locality("home/temp", Locality::SessionLocal, move |_s| {
                clone.fetch_add(1, Ordering::SeqCst);
            });
    }
    {
        let clone = remote_hits.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register_with_locality("home/temp", Locality::Remote, move |_s| {
                clone.fetch_add(1, Ordering::SeqCst);
            });
    }

    let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
    let fired = session
        .publish_aliased(7, None, "home/temp", b"x", opts)
        .unwrap();
    assert_eq!(fired, 2);
    assert_eq!(any_hits.load(Ordering::SeqCst), 1);
    assert_eq!(local_hits.load(Ordering::SeqCst), 1);
    assert_eq!(remote_hits.load(Ordering::SeqCst), 0);
    assert_eq!(driver.frame_count(), 0);
}

// ── R231 own_zid forwarding ──

#[test]
fn set_own_zid_forwards_to_subscriber_registry() {
    // Session::set_own_zid is a thin forwarder onto
    // observer.subscribers.set_own_zid. This pins the wiring so a
    // future refactor that splits the observer mutex or renames
    // the subscriber field surfaces here as a compile / runtime
    // error rather than silently disabling the dedup.
    //
    // R236 — `Session::new` now auto-wires own_zid from
    // `actions.params.zid`, so a fresh `build_session()` already
    // carries the fixture zid. Clear it before exercising the
    // forwarder so this test targets `set_own_zid`'s explicit
    // path rather than measuring the constructor's auto-install.
    let (session, _driver) = build_session();
    session.clear_own_zid();
    assert!(
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .own_zid()
            .is_none(),
        "post-clear session has no own_zid installed"
    );

    let zid = vec![0x01, 0x02, 0x03, 0x04];
    assert!(session.set_own_zid(zid.clone()));
    assert_eq!(
        session.observer().lock().unwrap().subscribers.own_zid(),
        Some(&zid[..])
    );
}

#[test]
fn set_own_zid_rejects_invalid_length_without_mutating_registry() {
    // Length-0 and length-17 inputs must be rejected (return
    // false) AND must not mutate the registry's slot. Silent
    // accept of length 0 would store an empty own_zid that
    // could match an empty source_info.zid_prefix() — breaking
    // the cautious-default contract from the registry layer.
    let (session, _driver) = build_session();
    let initial = vec![0x42];
    assert!(session.set_own_zid(initial.clone()));

    assert!(!session.set_own_zid(vec![]));
    assert_eq!(
        session.observer().lock().unwrap().subscribers.own_zid(),
        Some(&initial[..]),
        "rejected length-0 install must not mutate previously-installed zid"
    );

    assert!(!session.set_own_zid(vec![0u8; 17]));
    assert_eq!(
        session.observer().lock().unwrap().subscribers.own_zid(),
        Some(&initial[..]),
        "rejected length-17 install must not mutate previously-installed zid"
    );
}

#[test]
fn clear_own_zid_forwards_to_subscriber_registry() {
    let (session, _driver) = build_session();
    assert!(session.set_own_zid(vec![0x09, 0x08, 0x07, 0x06]));
    assert!(session
        .observer()
        .lock()
        .unwrap()
        .subscribers
        .own_zid()
        .is_some());

    session.clear_own_zid();
    assert!(
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .own_zid()
            .is_none(),
        "Session::clear_own_zid must forward the release down to the registry"
    );
}

// ── R311y739 Session::new auto-wire of OUR keyexpr id space ──

/// Build an `IterationEvent`-shaped inbound Push whose keyexpr is an `M=0`
/// (`Mapping::Receiver`) alias — an id that names OUR space. This is the exact
/// wire shape a zenoh peer emits once we have declared a keyexpr, because
/// `get_best_key` prefers `ctx.remote_expr_id` and stamps it `Mapping::Receiver`
/// (`zenoh/src/net/routing/dispatcher/resource.rs:625`).
#[cfg(all(feature = "codec-push", feature = "declare-keyexpr"))]
fn inbound_push_aliased_in_our_space(
    mapping_id: u64,
    payload: &[u8],
) -> wz_session_core::driver_loop::DriverLoopOutcome {
    let push = wz_codecs::push::Push {
        keyexpr: wz_codecs::wireexpr::Wireexpr {
            body: wz_codecs::wireexpr::WireexprVariant::WireexprNonlocal(
                wz_codecs::wireexpr_nonlocal::WireexprNonlocal {
                    id: mapping_id,
                    suffix_len: None,
                    suffix: None,
                },
            ),
        },
        body: wz_codecs::push::PushVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
            payload,
            ..Default::default()
        }),
        ..wz_codecs::push::Push::default()
    }
    .try_into_owned()
    .expect("fixture Push is representable");
    wz_session_core::driver_loop::DriverLoopOutcome::FramePayload {
        priority: wz_session_core::qos::Priority::DEFAULT,
        reliable: true,
        sn: 0,
        messages: vec![wz_session_core::network_message::NetworkMessage::Push(
            Box::new(push),
        )],
        has_ext: false,
        extensions: Vec::new(),
    }
}

/// R311y739 — THE WIRING PROOF, and it is deliberately end-to-end rather than a
/// field read: `Session::new` installs the actions bundle as our id space, a
/// later `send_declare_keyexpr` writes into that same bundle, and an inbound
/// `M=0` alias for the declared id fires the subscriber.
///
/// Wired is not driven. An assertion that the slot is `Some(..)` would pass
/// against an install of the WRONG object, against a table that never fills,
/// and against a resolver that ignores the install. Firing the callback is the
/// claim that all three hold at once.
///
/// Before R311y739 this Push was dropped: the registry held only the peer's
/// space and an `M=0` alias resolved to `None`.
#[cfg(all(
    feature = "codec-push",
    feature = "declare-keyexpr",
    feature = "pubsub-put"
))]
#[test]
fn an_inbound_alias_in_our_own_space_fires_a_subscriber_after_session_new() {
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");

    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    let _sub = session.declare_subscriber("home/temp", SubscribeOptions::default(), move |_| {
        fired_cb.fetch_add(1, Ordering::SeqCst);
    });

    let outcome = inbound_push_aliased_in_our_space(7, b"22.5");
    session.dispatch_iteration_event(crate::session_glue::IterationEvent::Poll(&outcome));

    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "an M=0 alias for an id THIS session declared must resolve to \
         `home/temp` and fire -- `Session::new` wires our id space, and \
         `send_declare_keyexpr` fills it",
    );
}

/// ANTI-VACUITY twin. Releasing the install restores the pre-R311y739 refusal,
/// so the test above is measuring the INSTALL rather than some unconditional
/// resolution. The declaration and the subscriber are identical; only the
/// install differs.
#[cfg(all(
    feature = "codec-push",
    feature = "declare-keyexpr",
    feature = "pubsub-put"
))]
#[test]
fn the_same_alias_fires_nobody_once_our_space_is_released() {
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");
    session.clear_own_mapping_space();

    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    let _sub = session.declare_subscriber("home/temp", SubscribeOptions::default(), move |_| {
        fired_cb.fetch_add(1, Ordering::SeqCst);
    });

    let outcome = inbound_push_aliased_in_our_space(7, b"22.5");
    session.dispatch_iteration_event(crate::session_glue::IterationEvent::Poll(&outcome));

    assert_eq!(
        fired.load(Ordering::SeqCst),
        0,
        "with no own space the alias resolves nothing -- this is what every \
         such Push did before R311y739",
    );
}

/// R311y739 — the install tracks the table's RETRACTIONS, because it is the
/// table itself and not a copy of it. `send_undeclare_kexpr` prunes the entry
/// and the very next inbound alias for that id stops resolving.
///
/// This is the assertion a mirrored `HashMap` inside the registry would fail:
/// it would have been filled at declare time and never told about the prune.
#[cfg(all(
    feature = "codec-push",
    feature = "declare-keyexpr",
    feature = "declare-undeclare",
    feature = "pubsub-put"
))]
#[test]
fn an_undeclared_alias_stops_resolving_without_a_second_install() {
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");

    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    let _sub = session.declare_subscriber("home/temp", SubscribeOptions::default(), move |_| {
        fired_cb.fetch_add(1, Ordering::SeqCst);
    });

    let outcome = inbound_push_aliased_in_our_space(7, b"22.5");
    session.dispatch_iteration_event(crate::session_glue::IterationEvent::Poll(&outcome));
    assert_eq!(fired.load(Ordering::SeqCst), 1, "resolves while declared");

    session.actions().send_undeclare_kexpr(7);
    session.dispatch_iteration_event(crate::session_glue::IterationEvent::Poll(&outcome));
    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "after the retraction the same alias must resolve nothing -- the \
         registry reads the live table, never a snapshot of it",
    );
}

// ── R236 Session::new auto-wire from SessionInitParams.zid ──

#[test]
fn session_new_auto_wires_set_own_zid_from_params() {
    // R236 — Session::new forwards `actions.params.zid` into the
    // subscriber registry's own_zid slot at construction time so
    // the application is shielded by the R231 self-echo dedup
    // guard without an explicit hook against the FSM
    // open-handshake completion event. Mirrors zenoh-pico's
    // `_z_session_init` which stamps `_local_zid` at session
    // creation (vendor/zenoh-pico/src/session/session.c).
    let (session, _driver) = build_session();
    // The `fixture_session_init_params()` SSOT seeds zid = [0x01; 4];
    // this test only pins that whatever zid the params carry is the
    // one auto-wired into the registry, not a specific byte pattern.
    let fixture_zid: Vec<u8> = vec![0x01; 4];
    assert_eq!(
        session.observer().lock().unwrap().subscribers.own_zid(),
        Some(&fixture_zid[..]),
        "Session::new auto-wires own_zid from SessionInitParams.zid"
    );
}

#[test]
fn session_new_with_empty_zid_skips_auto_wire() {
    // R236 — empty zid in SessionInitParams (test fixtures or a
    // pre-handshake placeholder) results in no auto-install. The
    // registry stays in its pre-R231 default state, dedup is
    // disabled, and every wire-arrived Push fires its matching
    // subscribers (the safe default that preserves
    // backwards-compatible behavior for callers who never opt
    // into dedup).
    let mut params = fixture_session_init_params();
    params.zid = Vec::new();
    let (actions, _driver) = recording_actions_with_params(params);
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    // R311cw — Session::new gained third `clock: Arc<T>` argument.
    let clock = Arc::new(TokioTime::new());
    // R311da — Session::new lifted to the R-generic block; the
    // explicit `TokioSession` alias name pins R = TokioRuntime so
    // type inference resolves through the observer parameter's
    // concrete `Arc<std::sync::Mutex<...>>` shape.
    let session = TokioSession::new(actions, observer, clock);
    assert!(
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .own_zid()
            .is_none(),
        "Session::new with empty params.zid leaves own_zid uninstalled"
    );
}

#[test]
fn session_new_with_overlength_zid_silently_skips_auto_wire() {
    // R236 — params.zid.len() > 16 violates the wire-form
    // `_z_id_t` range (transport.h: zid_len ∈ 1..=16).
    // `set_own_zid`'s internal range check rejects the install
    // (returns false) and the constructor swallows the
    // rejection — no panic, no log noise at construction
    // boundary. The registry stays uninstalled; the application
    // can still call `set_own_zid` later with a valid zid to
    // opt into dedup.
    let mut params = fixture_session_init_params();
    params.zid = vec![0u8; 17];
    let (actions, _driver) = recording_actions_with_params(params);
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    // R311cw — Session::new gained third `clock: Arc<T>` argument.
    let clock = Arc::new(TokioTime::new());
    // R311da — Session::new lifted to the R-generic block; the
    // explicit `TokioSession` alias name pins R = TokioRuntime so
    // type inference resolves through the observer parameter's
    // concrete `Arc<std::sync::Mutex<...>>` shape.
    let session = TokioSession::new(actions, observer, clock);
    assert!(
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .own_zid()
            .is_none(),
        "Session::new with len-17 params.zid silently skips auto-wire"
    );
}

// ── R232 PublishOptions metadata propagation ──

/// Capture every sample fired through the loopback path so the
/// metadata-propagation tests can assert against the projected
/// Sample without racing the subscriber callback.
fn record_loopback_samples(session: &TokioSession, pattern: &str) -> Arc<Mutex<Vec<Sample>>> {
    let captured = Arc::new(Mutex::new(Vec::<Sample>::new()));
    let captured_clone = captured.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .subscribers
        .register(pattern, move |s| {
            captured_clone.lock().unwrap().push(Sample::from_view(s));
        });
    captured
}

#[cfg(all(
    feature = "pubsub-attachment",
    feature = "pubsub-timestamp",
    feature = "pubsub-encoding",
    feature = "pubsub-source-info",
    feature = "pubsub-qos"
))]
#[test]
fn publish_options_with_metadata_setters_chain() {
    // Builder ergonomics: every R232 with_* setter is chainable
    // and pins exactly the field it names, leaving the other
    // four metadata slots untouched.
    let opts = PublishOptions::put()
        .with_timestamp(TimestampHint {
            time: 0x1122_3344_5566_7788,
            zid: vec![0xAA, 0xBB],
        })
        .with_encoding(EncodingHint {
            packed_id: 13,
            schema: Some("application/json".into()),
        })
        .with_source_info(SourceInfo::new(&[0x01, 0x02, 0x03, 0x04], 7, 42))
        .with_attachment(b"meta".to_vec())
        .with_qos(QosLevel::from_raw(0b0001_1010));
    let ts = opts.timestamp.as_ref().unwrap();
    assert_eq!(ts.time, 0x1122_3344_5566_7788);
    assert_eq!(ts.zid, vec![0xAA, 0xBB]);
    let enc = opts.encoding.as_ref().unwrap();
    assert_eq!(enc.packed_id, 13);
    assert_eq!(enc.schema.as_deref(), Some("application/json"));
    let si = opts.source_info.as_ref().unwrap();
    assert_eq!(si.zid_len, 4);
    assert_eq!(si.eid, 7);
    assert_eq!(si.sn, 42);
    assert_eq!(opts.attachment.as_deref(), Some(&b"meta"[..]));
    assert_eq!(opts.qos.unwrap().raw, 0b0001_1010);
}

// R311y308 — the loopback gate NEG. Each metadata field is written through the
// PUB FIELD, deliberately bypassing the gated `with_*` setter that does not
// exist in this subset (`#[non_exhaustive]` blocks struct-literal construction,
// NOT field assignment — that is the exact back door y308 closed). Before y308
// `build_loopback_sample` copied all five fields ungated, so each assertion
// below was `Some(..)` in a build that never composed the feature, falsifying
// the manifest's "Feature-off: nothing is set nor written". The wire leg always
// dropped them; this was loopback-only, process-local.
//
// Each arm is `not(feature)`-gated, so it only compiles in a subset that omits
// that feature — Layer C1bj drives those subsets. Without such a lane these
// tests never build and the gate would be unproven [[a skip is green]].
// R311y309 — the WIRE-METADATA gate NEG, the sibling of the loopback NEGs
// below. `push_metadata` is what the remote leg hands to the Push builder, and
// `PushMetadata::is_express` reads its `qos` UNGATED, feeding the
// transport-batching drain — so before y309 a pub-field `qos` write in a
// `pubsub-qos`-off build produced no wire QoS byte yet still changed the Frame
// count and SN sequence. Asserting on `push_metadata()` pins the gate at the
// producer, which is where the leak was.
#[cfg(all(feature = "codec-push", not(feature = "pubsub-qos")))]
#[test]
fn push_metadata_drops_qos_when_feature_off() {
    let mut opts = PublishOptions::put();
    // the express bit (1 << 4) — the sub-field with a transport-visible effect
    opts.qos = Some(crate::sample::QosLevel::from_raw(1 << 4));
    let meta = opts.push_metadata();
    assert!(
        meta.qos.is_none(),
        "pubsub-qos off: a pub-field-written qos must not reach PushMetadata"
    );
    assert!(
        !meta.is_express(),
        "pubsub-qos off: the express bit must not drive the transport-batching drain"
    );
}

#[cfg(all(feature = "pubsub-allow-loop", not(feature = "pubsub-timestamp")))]
#[test]
fn loopback_drops_timestamp_when_feature_off() {
    let mut opts = PublishOptions::put();
    opts.timestamp = Some(crate::sample::TimestampHint {
        time: 0x1122_3344_5566_7788,
        zid: vec![0xAA],
    });
    let s = super::publish_common::build_loopback_sample("k", b"v", &opts);
    assert!(
        s.timestamp.is_none(),
        "pubsub-timestamp off: a pub-field-written timestamp must not reach the loopback Sample"
    );
}

#[cfg(all(feature = "pubsub-allow-loop", not(feature = "pubsub-encoding")))]
#[test]
fn loopback_drops_encoding_when_feature_off() {
    let mut opts = PublishOptions::put();
    opts.encoding = Some(crate::sample::EncodingHint {
        packed_id: 13,
        schema: Some("application/json".into()),
    });
    let s = super::publish_common::build_loopback_sample("k", b"v", &opts);
    assert!(
        s.encoding.is_none(),
        "pubsub-encoding off: a pub-field-written encoding must not reach the loopback Sample"
    );
}

#[cfg(all(feature = "pubsub-allow-loop", not(feature = "pubsub-source-info")))]
#[test]
fn loopback_drops_source_info_when_feature_off() {
    let mut opts = PublishOptions::put();
    opts.source_info = Some(crate::sample::SourceInfo::new(
        &[0x01, 0x02, 0x03, 0x04],
        7,
        42,
    ));
    let s = super::publish_common::build_loopback_sample("k", b"v", &opts);
    assert!(
        s.source_info.is_none(),
        "pubsub-source-info off: a pub-field-written source_info must not reach the loopback Sample"
    );
}

#[cfg(all(feature = "pubsub-allow-loop", not(feature = "pubsub-attachment")))]
#[test]
fn loopback_drops_attachment_when_feature_off() {
    let mut opts = PublishOptions::put();
    opts.attachment = Some(b"meta".to_vec());
    let s = super::publish_common::build_loopback_sample("k", b"v", &opts);
    assert!(
        s.attachment.is_none(),
        "pubsub-attachment off: a pub-field-written attachment must not reach the loopback Sample"
    );
}

#[cfg(all(feature = "pubsub-allow-loop", not(feature = "pubsub-qos")))]
#[test]
fn loopback_drops_qos_when_feature_off() {
    let mut opts = PublishOptions::put();
    opts.qos = Some(crate::sample::QosLevel::from_raw(0b0001_1010));
    let s = super::publish_common::build_loopback_sample("k", b"v", &opts);
    assert!(
        s.qos.is_none(),
        "pubsub-qos off: a pub-field-written qos must not reach the loopback Sample"
    );
}

#[cfg(all(feature = "pubsub-allow-loop", feature = "pubsub-timestamp"))]
#[test]
fn publish_loopback_propagates_timestamp_to_sample() {
    let (session, _driver) = build_session();
    let captured = record_loopback_samples(&session, "home/temp");

    let opts = PublishOptions::put()
        .with_locality(Locality::SessionLocal)
        .with_timestamp(TimestampHint {
            time: 0xDEAD_BEEF,
            zid: vec![1, 2, 3],
        });
    let fired = session.publish("home/temp", b"22.5", opts).unwrap();
    assert_eq!(fired, 1);

    let s = captured.lock().unwrap();
    let ts = s[0].timestamp.as_ref().unwrap();
    assert_eq!(ts.time, 0xDEAD_BEEF);
    assert_eq!(ts.zid, vec![1, 2, 3]);
}

#[cfg(all(feature = "pubsub-allow-loop", feature = "pubsub-encoding"))]
#[test]
fn publish_loopback_propagates_encoding_to_put_sample() {
    let (session, _driver) = build_session();
    let captured = record_loopback_samples(&session, "home/temp");

    let opts = PublishOptions::put()
        .with_locality(Locality::SessionLocal)
        .with_encoding(EncodingHint {
            packed_id: 5,
            schema: Some("text/plain".into()),
        });
    session.publish("home/temp", b"22.5", opts).unwrap();

    let s = captured.lock().unwrap();
    let enc = s[0].encoding.as_ref().unwrap();
    assert_eq!(enc.packed_id, 5);
    assert_eq!(enc.schema.as_deref(), Some("text/plain"));
}

#[cfg(all(feature = "pubsub-allow-loop", feature = "pubsub-encoding"))]
#[test]
fn publish_loopback_omits_encoding_for_del_kind_even_when_opts_supplied() {
    // Mirror zenoh-pico's wire constraint: _z_msg_del_t has no
    // encoding field. The wire-arrival dispatch projects Del with
    // encoding=None unconditionally; the loopback path must
    // match so caller code that mistakenly attaches encoding to
    // a Del publish sees the same projection on either origin.
    let (session, _driver) = build_session();
    let captured = record_loopback_samples(&session, "home/temp");

    let opts = PublishOptions::del()
        .with_locality(Locality::SessionLocal)
        .with_encoding(EncodingHint {
            packed_id: 5,
            schema: None,
        });
    session.publish("home/temp", b"", opts).unwrap();

    let s = captured.lock().unwrap();
    assert_eq!(s[0].kind, SampleKind::Del);
    assert!(
        s[0].encoding.is_none(),
        "Del kind must drop encoding on loopback to mirror wire-arrival projection"
    );
}

#[cfg(all(feature = "pubsub-allow-loop", feature = "pubsub-source-info"))]
#[test]
fn publish_loopback_propagates_source_info_to_sample() {
    let (session, _driver) = build_session();
    let captured = record_loopback_samples(&session, "home/temp");

    let si = SourceInfo::new(&[0xDE, 0xAD, 0xBE, 0xEF], 7, 42);
    let opts = PublishOptions::put()
        .with_locality(Locality::SessionLocal)
        .with_source_info(si.clone());
    session.publish("home/temp", b"22.5", opts).unwrap();

    let s = captured.lock().unwrap();
    let got = s[0].source_info.as_ref().unwrap();
    assert_eq!(got.zid_len, 4);
    assert_eq!(got.zid_prefix(), &[0xDE, 0xAD, 0xBE, 0xEF][..]);
    assert_eq!(got.eid, 7);
    assert_eq!(got.sn, 42);
}

#[cfg(all(feature = "pubsub-allow-loop", feature = "pubsub-attachment"))]
#[test]
fn publish_loopback_propagates_attachment_to_sample() {
    let (session, _driver) = build_session();
    let captured = record_loopback_samples(&session, "home/temp");

    let opts = PublishOptions::put()
        .with_locality(Locality::SessionLocal)
        .with_attachment(b"attach-payload".to_vec());
    session.publish("home/temp", b"22.5", opts).unwrap();

    let s = captured.lock().unwrap();
    assert_eq!(s[0].attachment.as_deref(), Some(&b"attach-payload"[..]));
}

#[cfg(all(feature = "pubsub-allow-loop", feature = "pubsub-qos"))]
#[test]
fn publish_loopback_propagates_qos_to_sample() {
    let (session, _driver) = build_session();
    let captured = record_loopback_samples(&session, "home/temp");

    let opts = PublishOptions::put()
        .with_locality(Locality::SessionLocal)
        .with_qos(QosLevel::from_raw(0b0001_1010));
    session.publish("home/temp", b"22.5", opts).unwrap();

    let s = captured.lock().unwrap();
    assert_eq!(s[0].qos.unwrap().raw, 0b0001_1010);
    assert!(
        s[0].qos.unwrap().is_express(),
        "raw bit 4 set must surface through is_express()"
    );
}

// ── R311y-item3 typed PublishOptions::with_priority (two-input unification) ──

/// R311y-item3 — `with_priority` sets the priority sub-field of the SINGLE
/// `qos` source: `priority_band()` reads it back as the transport conduit band
/// AND the same byte is what the app observes via `Sample.priority`, so the two
/// former inputs cannot diverge. Also pins the bit-preservation contract (only
/// the low-3-bit priority field is rewritten; congestion + express survive).
#[cfg(feature = "pubsub-qos")]
#[test]
fn publish_options_with_priority_is_single_source_band() {
    use wz_session_core::qos::{CongestionControl, Priority};

    // No QoS attached -> DEFAULT conduit band (byte-identical to a pre-QoS send).
    assert_eq!(PublishOptions::put().priority_band(), Priority::DEFAULT);

    // with_priority drives BOTH the derived conduit band AND the observable byte.
    let hi = PublishOptions::put().with_priority(Priority::InteractiveHigh);
    assert_eq!(hi.priority_band(), Priority::InteractiveHigh);
    assert_eq!(hi.qos.unwrap().priority(), Priority::InteractiveHigh);

    // with_priority PRESERVES congestion (bit 3) + express (bit 4) from a prior
    // with_qos; it rewrites only the low-3-bit priority sub-field.
    let merged = PublishOptions::put()
        .with_qos(QosLevel::from_parts(
            Priority::Data,
            CongestionControl::Block,
            true,
        ))
        .with_priority(Priority::RealTime);
    let q = merged.qos.unwrap();
    assert_eq!(q.priority(), Priority::RealTime, "priority overwritten");
    assert!(q.is_express(), "express bit (4) preserved");
    assert_eq!(
        q.raw & (1 << 3),
        1 << 3,
        "congestion nodrop bit (3) preserved"
    );
    assert_eq!(merged.priority_band(), Priority::RealTime);
}

/// R311y255 — the typed congestion / express knobs are the siblings
/// `with_priority` had been missing. Before y255 both bits rode the wire and were
/// foreign-proven (R311y242, a real zenoh-pico subscriber decodes them), but had
/// NO typed entry point: setting `Block` meant hand-assembling the whole byte via
/// `with_qos(QosLevel::from_parts(..))`, which forces the caller to restate the
/// priority and express they did not want to touch. This pins the fix: each knob
/// merges ONLY its own sub-field, the three compose in any order, and the
/// untouched sub-fields fall back to the wire-DEFAULT byte (0x05 = Data / Drop /
/// no-express) rather than a zeroed `Control` byte.
#[cfg(feature = "pubsub-qos")]
#[test]
fn publish_options_typed_qos_knobs_merge_independently() {
    use wz_session_core::qos::{CongestionControl, Priority};

    // A lone congestion knob: nodrop set, and the sub-fields the caller did NOT
    // touch come from the wire DEFAULT (Data priority, no express) — NOT from a
    // zeroed byte, which would silently demote the publish to Control priority.
    let blocked = PublishOptions::put().with_congestion_control(CongestionControl::Block);
    let q = blocked.qos.unwrap();
    assert_eq!(q.congestion(), CongestionControl::Block);
    assert_eq!(
        q.priority(),
        Priority::DEFAULT,
        "untouched priority = DEFAULT"
    );
    assert!(!q.is_express(), "untouched express = DEFAULT (clear)");
    assert_eq!(q.raw, QosLevel::DEFAULT.raw | (1 << 3));

    // A lone express knob, same contract.
    let express = PublishOptions::put().with_express(true);
    let q = express.qos.unwrap();
    assert!(q.is_express());
    assert_eq!(q.priority(), Priority::DEFAULT);
    assert_eq!(q.congestion(), CongestionControl::Drop);

    // All three chained: each lands in its own sub-field, none clobbers another,
    // and the result equals the one-shot from_parts packing.
    let all = PublishOptions::put()
        .with_priority(Priority::RealTime)
        .with_congestion_control(CongestionControl::Block)
        .with_express(true);
    let q = all.qos.unwrap();
    assert_eq!(
        q,
        QosLevel::from_parts(Priority::RealTime, CongestionControl::Block, true),
        "chained typed knobs == the one-shot packed byte"
    );
    // The conduit band still derives from the same single source.
    assert_eq!(all.priority_band(), Priority::RealTime);

    // Order independence: the knobs commute.
    let reordered = PublishOptions::put()
        .with_express(true)
        .with_congestion_control(CongestionControl::Block)
        .with_priority(Priority::RealTime);
    assert_eq!(reordered.qos.unwrap(), q);
}

/// R311y-item3 — the OBSERVABLE half of the unification: the same `qos` byte the
/// conduit band derives from (via `priority_band`) also surfaces on the loopback
/// `Sample.priority`. This `SessionLocal` publish exercises ONLY the loopback leg
/// (the conduit leg is proven by
/// `publish_with_priority_routes_multicast_conduit_band`); together they show one
/// `with_priority` feeds both legs from a single source.
#[cfg(all(feature = "pubsub-allow-loop", feature = "pubsub-qos"))]
#[test]
fn publish_with_priority_propagates_band_to_loopback_sample() {
    use wz_session_core::qos::Priority;
    let (session, _driver) = build_session();
    let captured = record_loopback_samples(&session, "home/temp");

    let opts = PublishOptions::put()
        .with_locality(Locality::SessionLocal)
        .with_priority(Priority::InteractiveHigh);
    session.publish("home/temp", b"22.5", opts).unwrap();

    let s = captured.lock().unwrap();
    assert_eq!(
        s[0].qos.unwrap().priority(),
        Priority::InteractiveHigh,
        "with_priority surfaces as Sample.priority on the loopback leg",
    );
}

/// R311y-item3 — under `pubsub-qos` (R311y314: said `pubsub-priority`, the
/// pre-y307 name; the cfg below has always been the merged gate), `publish_qos`
/// FOLDS its explicit band
/// into the single `opts.qos` source (was band-agnostic on the loopback leg
/// pre-item3, the y232 stopgap), so the loopback Sample now OBSERVES the band.
/// This `SessionLocal` publish proves the observable half of the fold; the
/// conduit half follows because the fold delegates to `publish` (conduit proven
/// by `publish_with_priority_routes_multicast_conduit_band`). Closes the
/// two-source smell — `with_qos(low)` + `publish_qos(high)` can no longer desync.
#[cfg(all(feature = "pubsub-allow-loop", feature = "pubsub-qos"))]
#[test]
fn publish_qos_folds_band_into_observable_sample() {
    use wz_session_core::qos::Priority;
    let (session, _driver) = build_session();
    let captured = record_loopback_samples(&session, "home/temp");

    let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
    session
        .publish_qos("home/temp", b"22.5", opts, Priority::InteractiveHigh)
        .unwrap();

    let s = captured.lock().unwrap();
    assert_eq!(
        s[0].qos.unwrap().priority(),
        Priority::InteractiveHigh,
        "publish_qos folds the explicit band into the observable Sample.priority",
    );
}

#[cfg(all(
    feature = "pubsub-allow-loop",
    feature = "pubsub-attachment",
    feature = "pubsub-timestamp",
    feature = "pubsub-encoding",
    feature = "pubsub-source-info",
    feature = "pubsub-qos"
))]
#[test]
fn publish_loopback_propagates_all_metadata_in_one_chain() {
    // Composition: every R232 metadata field set together must
    // surface together on the projected Sample, in the same
    // shape the wire-arrival dispatcher produces. Mirrors what a
    // production caller does on a metadata-rich publish.
    let (session, _driver) = build_session();
    let captured = record_loopback_samples(&session, "home/temp");

    let opts = PublishOptions::put()
        .with_locality(Locality::SessionLocal)
        .with_reliability(Reliability::BestEffort)
        .with_timestamp(TimestampHint {
            time: 0x0102_0304,
            zid: vec![0x11],
        })
        .with_encoding(EncodingHint {
            packed_id: 9,
            schema: None,
        })
        .with_source_info(SourceInfo::new(&[0xAA, 0xBB], 1, 2))
        .with_attachment(vec![0xCC, 0xDD])
        .with_qos(QosLevel::from_raw(0x10));
    session.publish("home/temp", b"payload", opts).unwrap();

    let s = captured.lock().unwrap();
    let got = &s[0];
    assert_eq!(got.keyexpr, "home/temp");
    assert_eq!(got.kind, SampleKind::Put);
    assert_eq!(got.payload, b"payload");
    assert_eq!(got.reliability, Reliability::BestEffort);
    assert_eq!(got.timestamp.as_ref().unwrap().time, 0x0102_0304);
    assert_eq!(got.encoding.as_ref().unwrap().packed_id, 9);
    assert_eq!(got.source_info.as_ref().unwrap().eid, 1);
    assert_eq!(got.attachment.as_deref(), Some(&[0xCC, 0xDD][..]));
    assert_eq!(got.qos.unwrap().raw, 0x10);
}

// ── R311y818 — the PUBLISH-side auto-stamp (zenoh `Session::resolve_put`) ──
//
// zenoh resolves the effective timestamp ONCE, at the head of `resolve_put`,
// before either branch runs:
//
//     let timestamp = timestamp.or_else(|| self.runtime.new_timestamp());
//     // zenoh/src/api/session.rs:2129
//
// and `Runtime::new_timestamp` (`net/runtime/mod.rs:296-297`) is
// `self.state.hlc.as_ref().map(|hlc| hlc.new_timestamp())` — so the whole
// behaviour is ROLE-GATED through the node's `Option<Arc<HLC>>`. The one
// resolved value then feeds BOTH the wire `PushBody::Put`/`Del` and the
// session-local `DataInfo.timestamp` (`:2152`, `:2193`).

/// A STAMPING node: the deterministic fixture params with `whatami = Router`,
/// the one role zenoh's shipped `timestamping.enabled` map turns on
/// (`DEFAULT_CONFIG.json5:206`, mirrored by
/// [`TimestampingEnabled::default`](crate::node_clock::TimestampingEnabled::default)).
///
/// `build_session`'s fixture is a `Peer`, which is the NON-stamping half — it
/// is used verbatim as this group's paired negative, so the role gate is
/// witnessed rather than assumed. The zid is distinctive so a wire-byte
/// assertion can tell the stamp's identity apart from the payload.
#[cfg(all(
    feature = "time-hlc",
    feature = "pubsub-timestamp",
    feature = "pubsub-allow-loop"
))]
fn build_router_session() -> (TokioSession, Arc<RecordingLinkDriver>) {
    let mut params = fixture_session_init_params();
    params.whatami = wz_codecs::whatami::WhatAmI::Router;
    params.zid = vec![0xD1, 0xD2, 0xD3, 0xD4];
    let (actions, driver) = recording_actions_with_params(params);
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let clock = Arc::new(TokioTime::new());
    (TokioSession::new(actions, observer, clock), driver)
}

#[cfg(all(
    feature = "time-hlc",
    feature = "pubsub-timestamp",
    feature = "pubsub-allow-loop"
))]
#[test]
fn auto_stamp_fills_an_absent_timestamp_from_the_node_clock() {
    // The headline: a publish that names no timestamp leaves a STAMPING node
    // carrying one, minted off that node's own clock.
    let (session, _driver) = build_router_session();
    let captured = record_loopback_samples(&session, "home/temp");

    session
        .publish(
            "home/temp",
            b"22.5",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        )
        .unwrap();

    let s = captured.lock().unwrap();
    let ts = s[0].timestamp.as_ref().expect(
        "a stamping node fills the absent timestamp itself — zenoh \
         `timestamp.or_else(|| self.runtime.new_timestamp())`, api/session.rs:2129",
    );
    assert_eq!(
        ts.zid,
        vec![0xD1, 0xD2, 0xD3, 0xD4],
        "the minted stamp carries THIS node's zid (the HLC's uhlc::ID IS the node zid)",
    );
}

#[cfg(all(
    feature = "time-hlc",
    feature = "pubsub-timestamp",
    feature = "pubsub-allow-loop"
))]
#[test]
fn auto_stamp_keeps_the_callers_timestamp() {
    // `or_else`, not `Some(..)`: a caller-supplied timestamp is authoritative.
    // Without this the advanced publisher's own stamp — which it sets on every
    // put so a recovery reply re-stamps the identical identity — would be
    // overwritten on the way out.
    let (session, _driver) = build_router_session();
    let captured = record_loopback_samples(&session, "home/temp");

    session
        .publish(
            "home/temp",
            b"22.5",
            PublishOptions::put()
                .with_locality(Locality::SessionLocal)
                .with_timestamp(TimestampHint {
                    time: 0x0102_0304,
                    zid: vec![0x11],
                }),
        )
        .unwrap();

    let s = captured.lock().unwrap();
    let ts = s[0].timestamp.as_ref().unwrap();
    assert_eq!(ts.time, 0x0102_0304, "the caller's time word survives");
    assert_eq!(ts.zid, vec![0x11], "and so does the caller's identity");
}

#[cfg(all(
    feature = "time-hlc",
    feature = "pubsub-timestamp",
    feature = "pubsub-allow-loop"
))]
#[test]
fn auto_stamp_is_absent_on_a_non_stamping_role() {
    // The ROLE GATE, and the reason this is a paired negative rather than a
    // remark: zenoh's shipped map is `{ router: true, peer: false, client:
    // false }`, so a peer that auto-stamped would diverge from upstream in the
    // direction an over-eager implementation produces. `build_session`'s
    // fixture is a `Peer`.
    let (session, _driver) = build_session();
    let captured = record_loopback_samples(&session, "home/temp");

    session
        .publish(
            "home/temp",
            b"22.5",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        )
        .unwrap();

    let s = captured.lock().unwrap();
    assert!(
        s[0].timestamp.is_none(),
        "a peer-role node holds no clock, so an un-timestamped publish stays bare \
         (zenoh `Runtime::new_timestamp` returns None without an HLC)",
    );
}

#[cfg(all(
    feature = "time-hlc",
    feature = "pubsub-timestamp",
    feature = "pubsub-allow-loop"
))]
#[test]
fn auto_stamp_successive_publishes_strictly_increase() {
    // What makes this the HLC rather than a wall-clock read: two publishes
    // inside one physical instant still order, via the logical counter in the
    // low `uhlc::CSIZE` bits.
    let (session, _driver) = build_router_session();
    let captured = record_loopback_samples(&session, "home/temp");

    let opts = || PublishOptions::put().with_locality(Locality::SessionLocal);
    session.publish("home/temp", b"a", opts()).unwrap();
    session.publish("home/temp", b"b", opts()).unwrap();

    let s = captured.lock().unwrap();
    let first = s[0].timestamp.as_ref().unwrap().time;
    let second = s[1].timestamp.as_ref().unwrap().time;
    assert!(
        second > first,
        "two publishes in one instant must still order: {second} !> {first}",
    );
}

#[cfg(all(
    feature = "time-hlc",
    feature = "pubsub-timestamp",
    feature = "pubsub-allow-loop",
    feature = "codec-push"
))]
#[test]
fn auto_stamp_reaches_both_legs_as_one_value() {
    // ONE resolved value, both legs — zenoh binds `timestamp` once and hands
    // the same binding to `PushBody::Put` and to `DataInfo`. Stamping each leg
    // separately would mint two different times for one publish, which no
    // observer could reconcile.
    let (session, driver) = build_router_session();
    let captured = record_loopback_samples(&session, "home/temp");

    // `Locality::Any` — both legs fire off this single call.
    session
        .publish("home/temp", b"22.5", PublishOptions::put())
        .unwrap();

    let s = captured.lock().unwrap();
    let ts = s[0].timestamp.clone().expect("loopback leg is stamped");

    // Rebuild the Push the wire leg must have emitted, using the stamp the
    // LOOPBACK leg reported. If the two legs minted separately, these bytes
    // are not in the frame.
    let meta = wz_session_core::metadata::PushMetadata {
        timestamp: Some(ts),
        ..Default::default()
    };
    let expected =
        wz_session_core::push_build::build_push_literal_with_meta("home/temp", b"22.5", &meta)
            .expect("fixture keyexpr and payload fit the bounded codec");
    let expected_bytes = expected
        .try_as_borrowed()
        .expect("owned Push re-borrows")
        .encode_to_vec();

    let frame = driver.frame_bytes(0);
    assert!(
        frame
            .windows(expected_bytes.len())
            .any(|w| w == expected_bytes),
        "the emitted frame must carry the SAME stamp the loopback leg reported",
    );
}

#[cfg(all(
    feature = "time-hlc",
    feature = "pubsub-timestamp",
    feature = "pubsub-allow-loop",
    feature = "pubsub-delete"
))]
#[test]
fn auto_stamp_covers_the_delete_arm() {
    // zenoh binds the timestamp BEFORE the `match kind`, so both `PushBody::Put`
    // and `PushBody::Del` receive it (`api/session.rs:2133` / `:2151`). A Del
    // carries no payload, so its timestamp is the only ordering information a
    // storage has to resolve it against a concurrent Put.
    let (session, _driver) = build_router_session();
    let captured = record_loopback_samples(&session, "home/temp");

    session
        .publish(
            "home/temp",
            &[],
            PublishOptions::del().with_locality(Locality::SessionLocal),
        )
        .unwrap();

    let s = captured.lock().unwrap();
    assert_eq!(s[0].kind, SampleKind::Del);
    assert!(
        s[0].timestamp.is_some(),
        "the Del arm is stamped by the same resolved value the Put arm gets",
    );
}

#[cfg(all(
    feature = "time-hlc",
    feature = "pubsub-timestamp",
    feature = "pubsub-allow-loop",
    feature = "codec-declare",
    feature = "codec-push",
    feature = "declare-keyexpr"
))]
#[test]
fn auto_stamp_covers_the_aliased_publish_body() {
    // wz splits zenoh's single `resolve_put` into a LITERAL body and an
    // ALIASED one (zenoh resolves the wire_expr inside the one function, so it
    // has no such split). A seam installed on only the literal body would leave
    // every `Publisher` declared through the keyexpr table publishing bare —
    // which is the shape a `PublisherAliased` handle takes.
    let (session, _driver) = build_router_session();
    let captured = record_loopback_samples(&session, "home/temp");

    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");
    session
        .publish_aliased_auto(7, None, b"22.5", PublishOptions::put())
        .expect("declared mapping resolves cleanly");

    let s = captured.lock().unwrap();
    let ts = s[0]
        .timestamp
        .as_ref()
        .expect("the aliased publish body resolves the timestamp too");
    assert_eq!(ts.zid, vec![0xD1, 0xD2, 0xD3, 0xD4]);
}

// ── R234 publish_aliased_auto (outbound mapping table) ──

#[cfg(all(
    feature = "codec-declare",
    feature = "codec-push",
    feature = "declare-keyexpr",
    feature = "pubsub-allow-loop"
))]
#[test]
fn publish_aliased_auto_resolves_loopback_from_outbound_table() {
    let (session, driver) = build_session();
    let captured = record_loopback_samples(&session, "home/temp");

    // Declare 7 → "home/temp", then publish_aliased_auto without
    // restating the literal — the table lookup feeds loopback.
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");
    let fired = session
        .publish_aliased_auto(7, None, b"22.5", PublishOptions::put())
        .expect("declared mapping resolves cleanly");
    assert_eq!(fired, 1, "loopback fires on resolved literal");

    let s = captured.lock().unwrap();
    assert_eq!(s[0].keyexpr, "home/temp");
    // Wire branch fired too: declare frame + push frame = 2.
    assert_eq!(
        driver.frame_count(),
        2,
        "declare frame then aliased push frame on the wire"
    );
}

#[cfg(all(
    feature = "codec-declare",
    feature = "codec-push",
    feature = "declare-keyexpr",
    feature = "pubsub-allow-loop"
))]
#[test]
fn publish_aliased_auto_composes_inline_suffix_with_table_base() {
    // Composition rule: declared prefix + inline_suffix forms the
    // loopback literal. Mirrors the manual publish_aliased path
    // where the caller would have asserted the composition by
    // hand.
    let (session, _driver) = build_session();
    let captured = record_loopback_samples(&session, "home/**");

    session
        .actions()
        .send_declare_keyexpr(7, "home")
        .expect("hardcoded canonical literal keyexpr");
    let fired = session
        .publish_aliased_auto(7, Some("/temp/kitchen"), b"22.5", PublishOptions::put())
        .expect("declared mapping resolves");
    assert_eq!(fired, 1);

    let s = captured.lock().unwrap();
    assert_eq!(s[0].keyexpr, "home/temp/kitchen");
}

#[test]
fn publish_aliased_auto_returns_unknown_mapping_when_never_declared() {
    // Mapping id 42 was never declared on this session. The
    // typed error path fires; neither wire nor loopback emit.
    let (session, driver) = build_session();
    let captured = record_loopback_samples(&session, "home/**");

    let err = session
        .publish_aliased_auto(42, None, b"x", PublishOptions::put())
        .expect_err("undeclared mapping must error out");
    assert_eq!(err, PublishAliasError::UnknownMapping(42));

    assert!(
        captured.lock().unwrap().is_empty(),
        "loopback must not fire on the error path"
    );
    assert_eq!(
        driver.frame_count(),
        0,
        "wire must not emit on the error path"
    );
}

#[cfg(all(
    feature = "codec-declare",
    feature = "codec-push",
    feature = "declare-keyexpr",
    feature = "declare-undeclare",
    feature = "pubsub-allow-loop"
))]
#[test]
fn publish_aliased_auto_returns_unknown_mapping_after_undeclare() {
    // The error path fires whether the id was never declared OR
    // was declared and then retracted. Both share the same
    // "table lookup returned None" failure mode.
    let (session, _driver) = build_session();

    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");
    // First publish OK.
    session
        .publish_aliased_auto(7, None, b"a", PublishOptions::put())
        .expect("first publish succeeds after declare");

    // Retract the mapping.
    session.actions().send_undeclare_kexpr(7);

    // Second publish fails typed.
    let err = session
        .publish_aliased_auto(7, None, b"b", PublishOptions::put())
        .expect_err("retracted mapping must error out");
    assert_eq!(err, PublishAliasError::UnknownMapping(7));
}

#[test]
fn publish_aliased_auto_error_display_names_the_violating_id() {
    // Display impl must surface the id so a logged error line is
    // diagnosable without reflection.
    let err = PublishAliasError::UnknownMapping(123);
    let s = err.to_string();
    assert!(
        s.contains("123"),
        "error message must contain the mapping id"
    );
    assert!(
        s.contains("send_declare_keyexpr"),
        "error message hints at the remediation API"
    );
}

#[cfg(all(
    feature = "pubsub-allow-loop",
    feature = "pubsub-attachment",
    feature = "pubsub-timestamp"
))]
#[test]
fn publish_aliased_loopback_propagates_metadata_to_sample() {
    // Parity check: publish_aliased's loopback branch shares the
    // same build_loopback_sample helper as publish, so metadata
    // must flow identically. This pins the shared-helper contract
    // — a future refactor that splits the helper or re-implements
    // either path independently surfaces here.
    let (session, _driver) = build_session();
    let captured = record_loopback_samples(&session, "home/temp");

    let opts = PublishOptions::put()
        .with_locality(Locality::SessionLocal)
        .with_timestamp(TimestampHint {
            time: 0xAABB_CCDD,
            zid: vec![0x42],
        })
        .with_attachment(b"aliased-meta".to_vec());
    let fired = session
        .publish_aliased(7, None, "home/temp", b"x", opts)
        .unwrap();
    assert_eq!(fired, 1);

    let s = captured.lock().unwrap();
    assert_eq!(s[0].timestamp.as_ref().unwrap().time, 0xAABB_CCDD);
    assert_eq!(s[0].attachment.as_deref(), Some(&b"aliased-meta"[..]));
}

// ── R239 QueryOptions + Session::query ──

#[test]
fn query_options_default_is_any_locality_unset_metadata() {
    let opts = QueryOptions::default();
    assert_eq!(opts.allowed_destination, Locality::Any);
    assert!(opts.target.is_none());
    assert!(opts.consolidation.is_none());
    assert!(opts.payload.is_none());
    assert!(opts.encoding.is_none());
    assert!(opts.attachment.is_none());
    assert_eq!(opts.timeout_ms, 0);
}

#[test]
fn query_options_get_constructor_matches_default() {
    let get = QueryOptions::get();
    let dflt = QueryOptions::default();
    assert_eq!(get.allowed_destination, dflt.allowed_destination);
    assert_eq!(get.target, dflt.target);
    assert_eq!(get.consolidation, dflt.consolidation);
}

#[cfg(all(
    feature = "query-attachment",
    feature = "query-consolidation",
    feature = "query-get",
    feature = "query-target",
    feature = "query-timeout"
))]
#[test]
fn query_options_with_setters_chain() {
    let opts = QueryOptions::get()
        .with_allowed_destination(Locality::SessionLocal)
        .with_target(QueryTarget::All)
        .with_consolidation(ConsolidationMode::Latest)
        .with_payload(b"q-payload".to_vec())
        .with_attachment(b"q-attach".to_vec())
        .with_timeout_ms(5_000);
    assert_eq!(opts.allowed_destination, Locality::SessionLocal);
    assert_eq!(opts.target, Some(QueryTarget::All));
    assert_eq!(opts.consolidation, Some(ConsolidationMode::Latest));
    assert_eq!(opts.payload.as_deref(), Some(&b"q-payload"[..]));
    assert_eq!(opts.attachment.as_deref(), Some(&b"q-attach"[..]));
    assert_eq!(opts.timeout_ms, 5_000);
}

#[cfg(feature = "query-get")]
#[test]
fn query_options_expected_finals_matches_locality() {
    assert_eq!(
        QueryOptions::default()
            .with_allowed_destination(Locality::Any)
            .expected_finals(),
        2,
        "Locality::Any expects loopback final + peer final"
    );
    assert_eq!(
        QueryOptions::default()
            .with_allowed_destination(Locality::Remote)
            .expected_finals(),
        1,
        "Locality::Remote expects peer final only"
    );
    assert_eq!(
        QueryOptions::default()
            .with_allowed_destination(Locality::SessionLocal)
            .expected_finals(),
        1,
        "Locality::SessionLocal expects loopback final only"
    );
}

#[cfg(all(feature = "query-get", feature = "query-queryable"))]
#[test]
fn query_locality_session_local_fires_loopback_only_and_completes_inline() {
    let (session, driver) = build_session();
    let reply_count = Arc::new(AtomicUsize::new(0));
    let final_count = Arc::new(AtomicUsize::new(0));

    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("home/temp", |_query, responder| {
            responder.reply(b"22.5");
        });

    let r = reply_count.clone();
    let f = final_count.clone();
    let _handle = session.query(
        "home/temp",
        QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
        move |reply| {
            r.fetch_add(1, Ordering::SeqCst);
            assert_eq!(reply.keyexpr(), "home/temp");
            assert_eq!(reply.kind(), ReplyKind::Put);
            assert_eq!(reply.payload(), b"22.5");
        },
        move |_rid| {
            f.fetch_add(1, Ordering::SeqCst);
        },
    );

    assert_eq!(
        reply_count.load(Ordering::SeqCst),
        1,
        "loopback reply fires inline"
    );
    assert_eq!(
        final_count.load(Ordering::SeqCst),
        1,
        "SessionLocal final completes inline"
    );
    assert_eq!(
        driver.frame_count(),
        0,
        "SessionLocal must NOT touch the wire"
    );
    assert!(
        session.observer().lock().unwrap().replies.is_empty(),
        "expected_finals=1 closes the pending entry on the loopback final"
    );
}

/// R311fq — a SessionLocal get with NO matching local queryable
/// still finalises inline with zero replies. This guards the
/// invariant the `query-get` / `query-queryable` decoupling relies
/// on: the synthetic loopback Final (`deliver_local_final`) lives
/// OUTSIDE the `#[cfg(feature = "query-queryable")]` queryable-fan
/// block, so a wire-only getter (query-queryable compiled out)
/// finalises a SessionLocal get rather than hanging on a Final that
/// never fires. Registering no queryable here reproduces the
/// zero-reply shape a query-queryable-OFF build always exhibits;
/// the OFF-build behavioural twin is the isolated `wz-e2e-zget`
/// binary (Layer E2, 0 query-queryable nodes) — a query-queryable-
/// OFF UNIT run is blocked until the test-support dev-dep stops
/// force-enabling default features (the C1j isolation carry).
#[cfg(feature = "query-get")]
#[test]
fn query_session_local_with_no_queryable_finalises_inline_with_zero_replies() {
    let (session, driver) = build_session();
    let reply_count = Arc::new(AtomicUsize::new(0));
    let final_count = Arc::new(AtomicUsize::new(0));

    let r = reply_count.clone();
    let f = final_count.clone();
    let _handle = session.query(
        "home/temp",
        QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
        move |_reply| {
            r.fetch_add(1, Ordering::SeqCst);
        },
        move |_rid| {
            f.fetch_add(1, Ordering::SeqCst);
        },
    );

    assert_eq!(
        reply_count.load(Ordering::SeqCst),
        0,
        "no registered queryable ⇒ zero loopback replies"
    );
    assert_eq!(
        final_count.load(Ordering::SeqCst),
        1,
        "synthetic loopback final still fires inline (deliver_local_final \
             is outside the query-queryable cfg gate)"
    );
    assert_eq!(
        driver.frame_count(),
        0,
        "SessionLocal must NOT touch the wire"
    );
    assert!(
        session.observer().lock().unwrap().replies.is_empty(),
        "expected_finals=1 closes the pending entry on the loopback final"
    );
}

#[cfg(all(feature = "query-get", feature = "query-queryable"))]
#[test]
fn query_locality_remote_fires_wire_only_and_keeps_pending_until_wire_final() {
    let (session, driver) = build_session();
    let reply_count = Arc::new(AtomicUsize::new(0));
    let final_count = Arc::new(AtomicUsize::new(0));

    // Local queryable that would fire on a loopback round must
    // stay dormant on Locality::Remote — verifies the loopback
    // branch is entirely skipped.
    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("home/temp", |_q, responder| {
            responder.reply(b"loopback-should-not-fire");
        });

    let r = reply_count.clone();
    let f = final_count.clone();
    let _handle = session.query(
        "home/temp",
        QueryOptions::get().with_allowed_destination(Locality::Remote),
        move |_reply| {
            r.fetch_add(1, Ordering::SeqCst);
        },
        move |_rid| {
            f.fetch_add(1, Ordering::SeqCst);
        },
    );

    assert_eq!(
        reply_count.load(Ordering::SeqCst),
        0,
        "Remote suppresses loopback"
    );
    assert_eq!(
        final_count.load(Ordering::SeqCst),
        0,
        "wire Final has not arrived yet"
    );
    assert_eq!(
        driver.frame_count(),
        1,
        "wire Request(Query) frame on the driver"
    );
    assert_eq!(
        session.observer().lock().unwrap().replies.len(),
        1,
        "pending entry preserved waiting for the peer's Final"
    );
}

#[cfg(all(
    feature = "codec-response-final",
    feature = "query-get",
    feature = "query-queryable"
))]
#[test]
fn query_locality_any_fires_both_branches_and_waits_for_wire_final() {
    let (session, driver) = build_session();
    let reply_count = Arc::new(AtomicUsize::new(0));
    let final_count = Arc::new(AtomicUsize::new(0));

    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("home/temp", |_q, responder| {
            responder.reply(b"22.5");
        });

    let r = reply_count.clone();
    let f = final_count.clone();
    let _handle = session.query(
        "home/temp",
        get_opts_in_arrival_order(),
        // Any (default)
        move |_reply| {
            r.fetch_add(1, Ordering::SeqCst);
        },
        move |_rid| {
            f.fetch_add(1, Ordering::SeqCst);
        },
    );

    // Inline observations:
    assert_eq!(
        reply_count.load(Ordering::SeqCst),
        1,
        "loopback reply fires inline"
    );
    assert_eq!(
        final_count.load(Ordering::SeqCst),
        0,
        "Locality::Any on_final must wait for the wire Final too (expected_finals=2)"
    );
    assert_eq!(
        driver.frame_count(),
        1,
        "wire branch dispatched one Request(Query)"
    );
    assert_eq!(
        session.observer().lock().unwrap().replies.len(),
        1,
        "pending entry preserved waiting for the remaining wire Final"
    );

    // Simulate the peer's ResponseFinal — the second of the two
    // expected finals — and observe on_final fire then.
    use wz_codecs::response_final::ResponseFinal;
    let mut observer = session.observer().lock().unwrap();
    let response_final = ResponseFinal {
        request_id: 0,
        ..ResponseFinal::default()
    }
    .try_into_owned()
    .unwrap();
    observer.replies.dispatch_response_final(&response_final);
    drop(observer);
    // R311lg — the deferred reply sink STAGES the on_final fire; a raw
    // registry dispatch (bypassing the Session dispatch SSOT) must
    // pair with a drain, per the F-6 drain-discipline contract.
    session.drain_deferred_fires();

    assert_eq!(
        final_count.load(Ordering::SeqCst),
        1,
        "second Final closes the chain"
    );
    assert!(
        session.observer().lock().unwrap().replies.is_empty(),
        "pending entry dropped after the closing Final"
    );
}

#[cfg(feature = "query-get")]
#[test]
fn query_handle_carries_rid_zero_for_first_call_then_monotonic() {
    let (session, _driver) = build_session();
    let h0 = session
        .query(
            "k",
            QueryOptions::get().with_allowed_destination(Locality::Remote),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");
    let h1 = session
        .query(
            "k",
            QueryOptions::get().with_allowed_destination(Locality::Remote),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");
    assert_eq!(h0.rid(), 0);
    assert_eq!(
        h1.rid(),
        1,
        "alloc_next_request_id increments monotonically"
    );
}

#[cfg(all(feature = "query-get", feature = "query-queryable"))]
#[test]
fn query_loopback_propagates_del_body() {
    let (session, _driver) = build_session();
    let captured: Arc<Mutex<Option<InboundReply>>> = Arc::new(Mutex::new(None));
    let cap_cb = captured.clone();

    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("clear/me", |_q, responder| {
            responder.reply_del();
        });

    session
        .query(
            "clear/me",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |reply| {
                *cap_cb.lock().unwrap() = Some(InboundReply::from_view(reply));
            },
            |_| {},
        )
        .expect("query-get feature is ON in this test build");

    let got = captured
        .lock()
        .unwrap()
        .clone()
        .expect("on_reply must fire");
    assert_eq!(
        got.body,
        InboundReplyBody::Del {
            // R311y769 — the Del arm gained an attachment slot; this loopback
            // reply sets none, so `None` is the assertion and not a placeholder.
            attachment: None,
            source_info: None,
            timestamp: None,
        }
    );
    assert_eq!(got.keyexpr_literal, "clear/me");
}

#[cfg(all(
    feature = "query-get",
    feature = "query-queryable",
    feature = "query-reply-err"
))]
#[test]
fn query_loopback_propagates_err_body_with_encoding_tuple() {
    let (session, _driver) = build_session();
    let captured: Arc<Mutex<Option<InboundReply>>> = Arc::new(Mutex::new(None));
    let cap_cb = captured.clone();

    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("error/path", |_q, responder| {
            responder.reply_err(Some(4), Some("schema_v1"), b"oops");
        });

    session
        .query(
            "error/path",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |reply| {
                *cap_cb.lock().unwrap() = Some(InboundReply::from_view(reply));
            },
            |_| {},
        )
        .expect("query-get feature is ON in this test build");

    let got = captured
        .lock()
        .unwrap()
        .clone()
        .expect("on_reply must fire");
    assert_eq!(got.keyexpr_literal, "error/path");
    match &got.body {
        InboundReplyBody::Err { encoding, payload } => {
            assert_eq!(*encoding, Some((4, Some("schema_v1".to_string()))));
            assert_eq!(payload, b"oops");
        }
        other => panic!("expected Err, got {other:?}"),
    }
}

#[cfg(all(feature = "query-get", feature = "query-queryable"))]
#[test]
fn query_with_no_matching_queryable_completes_loopback_with_zero_replies() {
    let (session, _driver) = build_session();
    let reply_count = Arc::new(AtomicUsize::new(0));
    let final_count = Arc::new(AtomicUsize::new(0));

    // Register a queryable on a different keyexpr; the query's
    // pattern won't match → zero replies, but the loopback's
    // synthetic Final still closes the SessionLocal pending entry.
    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("home/humidity", |_q, responder| {
            responder.reply(b"99");
        });

    let r = reply_count.clone();
    let f = final_count.clone();
    session
        .query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |_| {
                r.fetch_add(1, Ordering::SeqCst);
            },
            move |_| {
                f.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("query-get feature is ON in this test build");

    assert_eq!(reply_count.load(Ordering::SeqCst), 0);
    assert_eq!(
        final_count.load(Ordering::SeqCst),
        1,
        "loopback Final still fires even when no queryable matched"
    );
    assert!(session.observer().lock().unwrap().replies.is_empty());
}

#[cfg(all(feature = "query-get", feature = "query-queryable"))]
#[test]
fn query_session_local_skips_remote_only_queryable() {
    // A Locality::Remote-only queryable must NOT fire on a
    // Locality::SessionLocal query (loopback path uses
    // allows_local() — Remote returns false). Mirrors the
    // publish-side suppression pattern at the queryable side.
    let (session, _driver) = build_session();
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register_with_locality("home/temp", Locality::Remote, move |_q, _responder| {
            fired_cb.fetch_add(1, Ordering::SeqCst);
        });

    let reply_count = Arc::new(AtomicUsize::new(0));
    let final_count = Arc::new(AtomicUsize::new(0));
    let r = reply_count.clone();
    let f = final_count.clone();
    session
        .query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |_| {
                r.fetch_add(1, Ordering::SeqCst);
            },
            move |_| {
                f.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("query-get feature is ON in this test build");

    assert_eq!(
        fired.load(Ordering::SeqCst),
        0,
        "Remote-only queryable must skip loopback"
    );
    assert_eq!(reply_count.load(Ordering::SeqCst), 0);
    assert_eq!(
        final_count.load(Ordering::SeqCst),
        1,
        "loopback Final still fires"
    );
}

#[cfg(all(feature = "query-get", feature = "query-queryable"))]
#[test]
fn query_session_local_with_session_local_queryable_fires() {
    // SessionLocal queryable on SessionLocal query: both
    // allows_local() — must fire. Verifies the loopback path is
    // not accidentally gated on allows_remote().
    let (session, _driver) = build_session();
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register_with_locality("home/temp", Locality::SessionLocal, move |_q, responder| {
            fired_cb.fetch_add(1, Ordering::SeqCst);
            responder.reply(b"22.5");
        });

    let reply_count = Arc::new(AtomicUsize::new(0));
    let r = reply_count.clone();
    session
        .query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |_| {
                r.fetch_add(1, Ordering::SeqCst);
            },
            |_| {},
        )
        .expect("query-get feature is ON in this test build");

    assert_eq!(fired.load(Ordering::SeqCst), 1);
    assert_eq!(reply_count.load(Ordering::SeqCst), 1);
}

#[cfg(all(
    feature = "query-get",
    feature = "query-queryable",
    feature = "query-target"
))]
#[test]
fn query_allcomplete_target_loopback_fires_only_complete_queryable() {
    // The R311y321 loopback residual, closed at the runtime boundary:
    // `Session::query` forwards the GET's `target` into `local_query`, so an
    // `AllComplete` self-get reaches only the COMPLETE SessionLocal queryable —
    // the responder-side operand (`register_sink(.., complete=true, ..)`, the
    // same call `declare_queryable` makes with `options.complete`) meeting the
    // requester-side operand (`with_target(AllComplete)`) on one host. The
    // `All` arm is the anti-vacuity twin: it proves the skip was conditional on
    // the target, not an unconditional drop of the incomplete queryable.
    let (session, _driver) = build_session();
    let complete_hits = Arc::new(AtomicUsize::new(0));
    let incomplete_hits = Arc::new(AtomicUsize::new(0));

    let c = complete_hits.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register_sink(
            "home/temp",
            Locality::SessionLocal,
            /*complete=*/ true,
            wz_session_core::query_sink::BoxedQuerySink::new(move |_q, responder| {
                c.fetch_add(1, Ordering::SeqCst);
                responder.reply(b"complete");
            }),
        )
        .expect("register on the alloc backing never exceeds declared capacity");
    let ic = incomplete_hits.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register_with_locality("home/temp", Locality::SessionLocal, move |_q, responder| {
            ic.fetch_add(1, Ordering::SeqCst);
            responder.reply(b"incomplete");
        });

    // AllComplete self-get: only the complete queryable fires.
    session
        .query(
            "home/temp",
            QueryOptions::get()
                .with_allowed_destination(Locality::SessionLocal)
                .with_target(QueryTarget::AllComplete),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");
    assert_eq!(
        complete_hits.load(Ordering::SeqCst),
        1,
        "AllComplete self-get fires the complete queryable"
    );
    assert_eq!(
        incomplete_hits.load(Ordering::SeqCst),
        0,
        "AllComplete self-get skips the incomplete queryable through Session::query"
    );

    // Anti-vacuity twin: All self-get fires BOTH.
    session
        .query(
            "home/temp",
            QueryOptions::get()
                .with_allowed_destination(Locality::SessionLocal)
                .with_target(QueryTarget::All),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");
    assert_eq!(complete_hits.load(Ordering::SeqCst), 2);
    assert_eq!(
        incomplete_hits.load(Ordering::SeqCst),
        1,
        "All self-get reaches both — the incomplete queryable is not unconditionally dropped"
    );
}

#[cfg(all(
    feature = "query-get",
    feature = "query-queryable",
    feature = "adminspace-core"
))]
#[test]
fn declare_adminspace_answers_root_get_with_local_data_json() {
    // §5.23 adminspace-core e2e: declare_adminspace registers the
    // `@/<zid>/<whatami>/**` built-in queryable; a local GET on the root key
    // returns the `local_data` JSON as `application/json`. The wz mirror of a
    // zenoh admin GET against `local_data` (adminspace.rs:561).
    use wz_session_core::zid_hex::zid_to_zenoh_hex;

    let (session, _driver) = build_session();
    let zid_hex = zid_to_zenoh_hex(&session.actions().params.zid);
    let whatami = session.actions().params.whatami.to_str();
    let root = format!("@/{zid_hex}/{whatami}");

    let _admin = session
        .declare_adminspace("0.9.9", vec!["tcp/127.0.0.1:7447".to_string()])
        .expect("adminspace-core ON in this build");

    let payload = Arc::new(Mutex::new(Option::<Vec<u8>>::None));
    let enc = Arc::new(Mutex::new(Option::<(u32, Option<String>)>::None));
    let p = payload.clone();
    let e = enc.clone();
    session
        .query(
            &root,
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |reply| {
                *p.lock().unwrap() = Some(reply.payload().to_vec());
                *e.lock().unwrap() = reply
                    .put_encoding()
                    .map(|(id, s)| (id, s.map(str::to_string)));
            },
            |_| {},
        )
        .expect("query-get ON in this build");

    let got = payload.lock().unwrap().clone().expect("admin GET replied");
    // build_session has no connected peer -> sessions:[]; the embedder-supplied
    // version + locator are reflected verbatim. R311y237 — the `plugins` field is
    // `null` without `adminspace-plugins-handlers`, `{}` with it (the Session host's
    // `compiled_plugins` reports subsystems as `Loaded`, and surface A lists STARTED
    // plugins only, so the started object is empty here).
    #[cfg(not(feature = "adminspace-plugins-handlers"))]
    let plugins_tok = "null";
    #[cfg(feature = "adminspace-plugins-handlers")]
    let plugins_tok = "{}";
    let expected = format!(
        r#"{{"locators":["tcp/127.0.0.1:7447"],"metadata":null,"plugins":{plugins_tok},"sessions":[],"version":"0.9.9","zid":"{zid_hex}"}}"#
    );
    assert_eq!(String::from_utf8(got).unwrap(), expected);
    // application/json: zenoh encoding id 5 -> wz packed_id 10 (id << 1), no schema.
    assert_eq!(*enc.lock().unwrap(), Some((10, None)));
}

#[cfg(all(
    feature = "query-get",
    feature = "query-queryable",
    feature = "adminspace-core"
))]
#[test]
fn declare_adminspace_leaves_sub_path_get_for_layered_handlers() {
    // A sub-path GET with NO matching handler gets no reply. `.../subscriber/foo`
    // (the introspection-handlers atom is not built) reaches the `/**` queryable
    // but intersects neither the root nor any built handler key, so the dispatch
    // emits nothing — left for the layered §5.23 handler atoms. (A `.../metrics`
    // GET, by contrast, DOES reply once adminspace-metrics is built — see
    // declare_adminspace_metrics_get_returns_openmetrics_text.)
    let (session, _driver) = build_session();
    let zid_hex = wz_session_core::zid_hex::zid_to_zenoh_hex(&session.actions().params.zid);
    let whatami = session.actions().params.whatami.to_str();

    let _admin = session
        .declare_adminspace("0.9.9", Vec::new())
        .expect("adminspace-core ON in this build");

    let replies = Arc::new(AtomicUsize::new(0));
    let finals = Arc::new(AtomicUsize::new(0));
    let r = replies.clone();
    let f = finals.clone();
    session
        .query(
            &format!("@/{zid_hex}/{whatami}/subscriber/foo"),
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |_| {
                r.fetch_add(1, Ordering::SeqCst);
            },
            move |_| {
                f.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("query-get ON in this build");

    assert_eq!(
        replies.load(Ordering::SeqCst),
        0,
        "core must not answer a sub-path admin GET with no handler"
    );
    assert_eq!(
        finals.load(Ordering::SeqCst),
        1,
        "loopback Final still fires"
    );
}

#[cfg(all(
    feature = "query-get",
    feature = "query-queryable",
    feature = "adminspace-core"
))]
#[test]
fn declare_adminspace_config_get_returns_typed_config_json() {
    // R311y40 §5.23 config-read: a GET on @/<zid>/<whatami>/config returns the
    // typed WzConfig read-at-open mirror as application/json -- the "admin surface
    // READS config" leg. BEYOND-ZENOH (R311y42): zenoh's config/** is a write-only
    // subscriber (no read GET); wz ADDS this typed read. build_session's default
    // SessionInitParams drive the values, so `expected` is computed the same way
    // the handler serializes them: the assertion proves the GET -> handler ->
    // typed-config-JSON wiring + the application/json content-type.
    use wz_session_core::zid_hex::zid_to_zenoh_hex;
    let (session, _driver) = build_session();
    let zid_hex = zid_to_zenoh_hex(&session.actions().params.zid);
    let whatami = session.actions().params.whatami.to_str();
    let config_key = format!("@/{zid_hex}/{whatami}/config");
    let expected =
        crate::config::WzConfig::from_init_params(&session.actions().params).to_admin_json();

    let _admin = session
        .declare_adminspace("0.9.9", Vec::new())
        .expect("adminspace-core ON in this build");

    let payload = Arc::new(Mutex::new(Option::<Vec<u8>>::None));
    let enc = Arc::new(Mutex::new(Option::<(u32, Option<String>)>::None));
    let p = payload.clone();
    let e = enc.clone();
    session
        .query(
            &config_key,
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |reply| {
                *p.lock().unwrap() = Some(reply.payload().to_vec());
                *e.lock().unwrap() = reply
                    .put_encoding()
                    .map(|(id, s)| (id, s.map(str::to_string)));
            },
            |_| {},
        )
        .expect("query-get ON in this build");

    let got = payload.lock().unwrap().clone().expect("config GET replied");
    assert_eq!(String::from_utf8(got).unwrap(), expected);
    // application/json: zenoh encoding id 5 -> wz packed_id 10 (id << 1), no schema.
    assert_eq!(*enc.lock().unwrap(), Some((10, None)));
}

#[cfg(all(feature = "query-get", feature = "adminspace-metrics"))]
#[test]
fn declare_adminspace_metrics_get_returns_openmetrics_text() {
    // §5.23 adminspace-metrics: a GET on @/<zid>/<whatami>/metrics fires the
    // metrics dispatch branch and replies the OpenMetrics build-info body as
    // text/plain (the wz mirror of zenoh's metrics handler, adminspace.rs:706).
    use wz_session_core::zid_hex::zid_to_zenoh_hex;

    let (session, _driver) = build_session();
    let zid_hex = zid_to_zenoh_hex(&session.actions().params.zid);
    let whatami = session.actions().params.whatami.to_str();
    let metrics_ke = format!("@/{zid_hex}/{whatami}/metrics");

    let _admin = session
        .declare_adminspace("0.9.9", Vec::new())
        .expect("adminspace-core ON in this build");

    let payload = Arc::new(Mutex::new(Option::<Vec<u8>>::None));
    let enc = Arc::new(Mutex::new(Option::<(u32, Option<String>)>::None));
    let p = payload.clone();
    let e = enc.clone();
    session
        .query(
            &metrics_ke,
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |reply| {
                *p.lock().unwrap() = Some(reply.payload().to_vec());
                *e.lock().unwrap() = reply
                    .put_encoding()
                    .map(|(id, s)| (id, s.map(str::to_string)));
            },
            |_| {},
        )
        .expect("query-get ON in this build");

    let got = String::from_utf8(payload.lock().unwrap().clone().expect("metrics replied")).unwrap();
    assert_eq!(
        got,
        "# HELP zenoh_build Information about zenoh.\n\
         # TYPE zenoh_build gauge\n\
         zenoh_build{version=\"0.9.9\"} 1\n"
    );
    // text/plain = zenoh encoding id 4 -> wz packed_id 8 (id << 1), no schema.
    assert_eq!(*enc.lock().unwrap(), Some((8, None)));
}

#[cfg(all(feature = "query-get", feature = "adminspace-metrics"))]
#[test]
fn declare_adminspace_wildcard_get_fires_local_data_and_metrics() {
    // A @/<zid>/<whatami>/** wildcard GET intersects the root key, the `/config`
    // key (R311y40), AND the metrics key -> three replies, the faithful zenoh
    // multi-handler fan-out (adminspace.rs:499-503 fires every handler whose key
    // intersects).
    use wz_session_core::zid_hex::zid_to_zenoh_hex;

    let (session, _driver) = build_session();
    let zid_hex = zid_to_zenoh_hex(&session.actions().params.zid);
    let whatami = session.actions().params.whatami.to_str();
    let wild = format!("@/{zid_hex}/{whatami}/**");
    let root = format!("@/{zid_hex}/{whatami}");
    let config = format!("@/{zid_hex}/{whatami}/config");
    let metrics = format!("@/{zid_hex}/{whatami}/metrics");

    let _admin = session
        .declare_adminspace("0.9.9", Vec::new())
        .expect("adminspace-core ON in this build");

    let replies = Arc::new(Mutex::new(Vec::<String>::new()));
    let r = replies.clone();
    session
        .query(
            &wild,
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |reply| {
                r.lock().unwrap().push(reply.keyexpr().to_string());
            },
            |_| {},
        )
        .expect("query-get ON in this build");

    let keys = replies.lock().unwrap().clone();
    assert!(keys.contains(&root), "local_data reply present: {keys:?}");
    assert!(keys.contains(&config), "config reply present: {keys:?}");
    assert!(keys.contains(&metrics), "metrics reply present: {keys:?}");

    // R311y630 — the FAN-OUT is stated as a shape rather than as the literal
    // `3` that stood here, because that literal was right for every feature
    // combination CI runs and WRONG for `--all-features`, which no lane runs:
    // `adminspace-plugins-handlers` registers one `@/<zid>/<whatami>/plugins/<id>`
    // key per STARTED plugin, and a build with the storage manager compiled in
    // starts one, so the wildcard intersects four keys there.
    //
    // Stronger than the literal rather than weaker: it still catches a handler
    // that stopped firing (the three assertions above), it still catches a
    // DUPLICATE reply, and it additionally catches a key nobody expected —
    // which the literal count could only report as an unexplained number.
    let plugin_prefix = format!("@/{zid_hex}/{whatami}/plugins/");
    let unexpected: Vec<&String> = keys
        .iter()
        .filter(|k| ![&root, &config, &metrics].contains(k) && !k.starts_with(&plugin_prefix))
        .collect();
    assert!(
        unexpected.is_empty(),
        "the wildcard fired a handler this test does not describe: {unexpected:?}"
    );
    let mut sorted = keys.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        keys.len(),
        "every intersecting handler replies exactly once: {keys:?}"
    );
}

#[cfg(all(feature = "query-get", feature = "adminspace-read"))]
#[test]
fn declare_adminspace_read_false_denies_get_with_final_only() {
    // §5.23 adminspace-read: with permissions.read=false the admin queryable
    // answers NOTHING — the querier receives only the terminating Final, the wz
    // mirror of zenoh's bare ResponseFinal on a read-permission deny
    // (adminspace.rs:457-467).
    use wz_session_core::adminspace::AdminSpacePermissions;
    use wz_session_core::zid_hex::zid_to_zenoh_hex;

    let (session, _driver) = build_session();
    let zid_hex = zid_to_zenoh_hex(&session.actions().params.zid);
    let whatami = session.actions().params.whatami.to_str();
    let root = format!("@/{zid_hex}/{whatami}");

    let _admin = session
        .declare_adminspace_with_permissions(
            "0.9.9",
            Vec::new(),
            AdminSpacePermissions {
                read: false,
                ..Default::default()
            },
        )
        .expect("adminspace-core ON in this build");

    let replies = Arc::new(AtomicUsize::new(0));
    let finals = Arc::new(AtomicUsize::new(0));
    let r = replies.clone();
    let f = finals.clone();
    session
        .query(
            &root,
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |_| {
                r.fetch_add(1, Ordering::SeqCst);
            },
            move |_| {
                f.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("query-get ON in this build");

    assert_eq!(
        replies.load(Ordering::SeqCst),
        0,
        "read=false denies the admin GET (no local_data, no metrics)"
    );
    assert_eq!(
        finals.load(Ordering::SeqCst),
        1,
        "the terminating Final still fires on a denied GET"
    );
}

#[cfg(all(feature = "query-get", feature = "adminspace-read"))]
#[test]
fn declare_adminspace_live_permit_source_flips_the_gate_at_runtime() {
    // §5.23 adminspace-read LIVE permit: the gate is re-read on EVERY GET, so a
    // permit change takes effect on the next request against the SAME queryable.
    //
    // This is the divergence the atom recorded: wz resolved the permit once at
    // declare time and captured it in the handler closure, where zenoh takes the
    // runtime-config lock inside its admin `send_request` and re-reads
    // `conf.adminspace.permissions().read` per request
    // (`net/runtime/adminspace.rs:456-457`) — which is why a runtime config change,
    // including one performed by upstream's own admin `config/**` PUT, flips
    // upstream's gate and could not flip wz's.
    //
    // BOTH directions are driven on one queryable. A grant->deny-only assertion
    // would pass against a handler that had simply been rebuilt with a new constant,
    // and would say nothing about deny->grant; the three phases pin that the SOURCE
    // is what decides, not the declare call.
    use wz_session_core::adminspace::AdminSpacePermissions;
    use wz_session_core::zid_hex::zid_to_zenoh_hex;

    let (session, _driver) = build_session();
    let zid_hex = zid_to_zenoh_hex(&session.actions().params.zid);
    let whatami = session.actions().params.whatami.to_str();
    let root = format!("@/{zid_hex}/{whatami}");

    // The live permit cell — the test's stand-in for the shared `WzConfig` a
    // production host holds (`WzConfig::admin_permissions`).
    let permits = Arc::new(Mutex::new(AdminSpacePermissions::default()));
    let source = permits.clone();
    let _admin = session
        .declare_adminspace_with_permissions_source("0.9.9", Vec::new(), move || {
            *source.lock().unwrap()
        })
        .expect("adminspace-core ON in this build");

    // One GET, returning (replies, finals) — the same loopback probe three times.
    let get = || {
        let replies = Arc::new(AtomicUsize::new(0));
        let finals = Arc::new(AtomicUsize::new(0));
        let r = replies.clone();
        let f = finals.clone();
        session
            .query(
                &root,
                QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
                move |_| {
                    r.fetch_add(1, Ordering::SeqCst);
                },
                move |_| {
                    f.fetch_add(1, Ordering::SeqCst);
                },
            )
            .expect("query-get ON in this build");
        (
            replies.load(Ordering::SeqCst),
            finals.load(Ordering::SeqCst),
        )
    };

    // Phase 1 — the default permit (zenoh `PermissionsConf` read=true) serves.
    assert_eq!(get(), (1, 1), "default read=true serves the admin GET");

    // Phase 2 — revoke at runtime. No re-declare: the SAME queryable, same handler.
    permits.lock().unwrap().read = false;
    assert_eq!(
        get(),
        (0, 1),
        "a runtime revoke denies the very next GET (only the terminating Final)"
    );

    // Phase 3 — re-grant. The gate must open again; a latch that only ever closes
    // would satisfy phases 1-2 and fail here.
    permits.lock().unwrap().read = true;
    assert_eq!(get(), (1, 1), "a runtime re-grant serves again");
}

#[cfg(all(feature = "query-get", feature = "query-queryable"))]
#[test]
fn query_locality_remote_alone_skips_local_queryable() {
    // A local Locality::Any queryable does fire on its own
    // session's Remote-only query? NO — the loopback branch is
    // gated on opts.allowed_destination.allows_local(); Remote
    // sets that to false. Mirrors the publish-side
    // publish_locality_remote_fires_wire_only invariant for the
    // queryable side.
    let (session, driver) = build_session();
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("home/temp", move |_q, responder| {
            fired_cb.fetch_add(1, Ordering::SeqCst);
            responder.reply(b"22.5");
        });

    let reply_count = Arc::new(AtomicUsize::new(0));
    let r = reply_count.clone();
    session
        .query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::Remote),
            move |_| {
                r.fetch_add(1, Ordering::SeqCst);
            },
            |_| {},
        )
        .expect("query-get feature is ON in this test build");

    assert_eq!(
        fired.load(Ordering::SeqCst),
        0,
        "Remote query does NOT trigger local queryable through the loopback branch"
    );
    assert_eq!(reply_count.load(Ordering::SeqCst), 0);
    assert_eq!(driver.frame_count(), 1, "wire branch sent");
}

#[test]
fn alloc_next_request_id_increments_and_starts_at_zero() {
    let (actions, _driver) = recording_actions();
    assert_eq!(actions.alloc_next_request_id(), 0);
    assert_eq!(actions.alloc_next_request_id(), 1);
    assert_eq!(actions.alloc_next_request_id(), 2);
}

// ── R240 wire-side QueryOptions propagation ──

#[cfg(all(
    feature = "query-attachment",
    feature = "query-consolidation",
    feature = "query-get",
    feature = "query-target",
    feature = "query-timeout"
))]
#[cfg(feature = "query-attachment")]
#[test]
fn query_options_query_metadata_extracts_wire_fields() {
    // R240 — QueryOptions::query_metadata must surface the
    // wire-propagatable subset (target / consolidation /
    // attachment / timeout_ms). R311y250 — payload / encoding now
    // thread too: they collapse into the single QueryMetadata::value
    // wire unit (encoding, payload) that build_request_query_with_meta
    // stamps onto RequestQueryBuilder::query_value (the Q_B / Q_E value
    // ext 0x03; codec landed R311y248). The population is ungated so
    // this (no-query-value gate) test still observes the collapse.
    let opts = QueryOptions::get()
        .with_target(QueryTarget::AllComplete)
        .with_consolidation(ConsolidationMode::Monotonic)
        .with_attachment(b"q-att".to_vec())
        .with_timeout_ms(5_000)
        .with_payload(b"q-value-payload".to_vec())
        .with_encoding(EncodingHint {
            packed_id: 1,
            schema: None,
        });
    let meta = opts.query_metadata();
    assert_eq!(meta.target, Some(QueryTarget::AllComplete));
    assert_eq!(meta.consolidation, Some(ConsolidationMode::Monotonic));
    assert_eq!(meta.attachment.as_deref(), Some(&b"q-att"[..]));
    assert_eq!(meta.timeout_ms, 5_000);
    assert_eq!(
        meta.value,
        Some((
            EncodingHint {
                packed_id: 1,
                schema: None,
            },
            b"q-value-payload".to_vec(),
        )),
        "payload + encoding collapse into the QueryMetadata::value unit",
    );
}

/// R311y551 — the other half of the request-QoS seam: `QueryOptions` ->
/// `query_metadata()` -> the Request bytes. `wz-capi-c`'s
/// `a_get_options_qos_trio_reaches_the_query_options_and_the_wire` and
/// `wz-capi-pico`'s twin both end at `QueryOptions.qos`, which is where this
/// picks up, so the two ABIs' option structs are joined to the wire without a
/// gap.
///
/// Three separate claims, because they fail independently:
/// (1) the three per-field setters MERGE rather than overwrite — a
/// `with_express` that reset the byte would silently discard the priority set
/// one line earlier, and a test that set only one field could never see it;
/// (2) the merged byte survives `query_metadata()`;
/// (3) it reaches the wire identically to a hand-built builder chain.
#[cfg(all(feature = "query-get", feature = "codec-request"))]
#[test]
fn query_options_qos_reaches_the_request_wire() {
    use wz_codecs_test_support::TestWire;
    use wz_session_core::qos::{CongestionControl, Priority};

    let opts = QueryOptions::get()
        .with_priority(Priority::InteractiveHigh)
        .with_congestion_control(CongestionControl::Block)
        .with_express(true);

    // (1) All three survive each other.
    let qos = opts.qos.expect("the setters populate the slot");
    assert_eq!(qos.priority(), Priority::InteractiveHigh, "priority merged");
    assert_eq!(
        qos.congestion(),
        CongestionControl::Block,
        "congestion merged"
    );
    assert!(qos.is_express(), "express merged");

    // (2) The byte survives the metadata derivation.
    let meta = opts.query_metadata();
    assert_eq!(meta.qos, Some(qos), "query_metadata carries the QoS byte");

    // (3) And it lands on the wire where a direct builder chain puts it.
    let wire =
        wz_session_core::request_build::build_request_query_with_meta(7, 0, Some("q/qos"), &meta)
            .expect("request build")
            .wire();
    let expected = wz_session_core::request_build::build_request_query_with_meta(
        7,
        0,
        Some("q/qos"),
        &wz_session_core::metadata::QueryMetadata {
            qos: Some(qos),
            ..meta.clone()
        },
    )
    .expect("reference build")
    .wire();
    assert_eq!(wire, expected);

    // The reference arm above shares `meta`, so it cannot discriminate on its
    // own — assert the QoS ext is actually PRESENT by diffing against the same
    // query with the slot cleared. Without this the equality would hold on a
    // build that dropped the QoS everywhere.
    let without = wz_session_core::request_build::build_request_query_with_meta(
        7,
        0,
        Some("q/qos"),
        &wz_session_core::metadata::QueryMetadata {
            qos: None,
            ..meta.clone()
        },
    )
    .expect("no-qos build")
    .wire();
    assert_ne!(
        wire, without,
        "the QoS byte must CHANGE the Request bytes; equality here would mean \
         the slot never reached the encoder and claim (3) proved nothing",
    );
}

// R311y326 — the `is_empty()` verdict for default options is now
// build-dependent: with `query-timeout` ON, default options resolve the
// timeout to `DEFAULT_QUERY_TIMEOUT_MS` (matching pico/zenoh, neither of which
// has an empty-timeout default), so the metadata is NOT empty. With the atom
// OFF the accessor still yields 0 and the metadata stays empty. Two lanes, two
// tests, so the assertion matches the build it runs on rather than passing only
// by coincidence on the one subset that omits query-timeout.
#[cfg(all(feature = "query-get", not(feature = "query-timeout")))]
#[test]
fn query_options_default_query_metadata_is_empty() {
    let meta = QueryOptions::default().query_metadata();
    assert!(
        meta.is_empty(),
        "with query-timeout OFF, default options produce empty wire metadata"
    );
}

#[cfg(all(feature = "query-get", feature = "query-timeout"))]
#[test]
fn query_options_default_query_metadata_carries_default_timeout() {
    let meta = QueryOptions::default().query_metadata();
    assert_eq!(
        meta.timeout_ms, DEFAULT_QUERY_TIMEOUT_MS,
        "default options resolve the 0 sentinel to the platform default timeout"
    );
    assert!(
        !meta.is_empty(),
        "a default query now carries the timeout ext, so the metadata is non-empty"
    );
}

#[cfg(all(feature = "query-get", not(feature = "query-timeout")))]
#[test]
fn query_wire_branch_with_empty_meta_emits_no_meta_fast_path_frame() {
    // With query-timeout OFF, Session::query with default options
    // (Locality::Any, no metadata) MUST take the no-meta fast path → wire
    // frame is byte-identical to a standalone send_request_query call.
    // Pins the R240 short-circuit invariant at the Session level.
    let (session, driver) = build_session();
    session
        .query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::Remote),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");
    let session_frame = driver.frame_bytes(0);

    // Mirror the call against an independent recording driver +
    // SessionLinkActions, using the bare no-metadata API, and
    // assert byte parity. The `recording_actions()` SSOT seeds both
    // sides from the same `fixture_session_init_params()`, so the
    // outbound Frame SN starts from the same initial_sn; the
    // alloc_next_request_id counter also starts at 0 so the
    // request_id matches.
    let (actions2, driver2) = recording_actions();
    let rid = actions2.alloc_next_request_id();
    actions2
        .send_request_query(rid, 0, Some("home/temp"))
        .unwrap();
    let baseline = driver2.frame_bytes(0);

    assert_eq!(
        session_frame, baseline,
        "Session::query with default options must produce byte-stable parity"
    );
}

// R311y326 — with query-timeout ON, a default query no longer takes the
// no-meta fast path: it resolves the 0 sentinel to DEFAULT_QUERY_TIMEOUT_MS and
// carries the timeout ext, matching pico's z_get (which rewrites 0->default
// before encoding) and zenoh (which always emits ext_timeout). Two independent
// build_session() instances seed identically from fixture_session_init_params,
// so a default query and an explicit with_timeout_ms(DEFAULT) query produce
// byte-identical frames; both differ from the bare no-ext baseline.
#[cfg(all(feature = "query-get", feature = "query-timeout"))]
#[test]
fn query_wire_branch_default_carries_the_default_timeout_ext() {
    let (session, driver) = build_session();
    session
        .query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::Remote),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");
    let default_frame = driver.frame_bytes(0);

    let (session2, driver2) = build_session();
    session2
        .query(
            "home/temp",
            QueryOptions::get()
                .with_allowed_destination(Locality::Remote)
                .with_timeout_ms(DEFAULT_QUERY_TIMEOUT_MS),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");
    let explicit_frame = driver2.frame_bytes(0);

    assert_eq!(
        default_frame, explicit_frame,
        "a default query must resolve to exactly the platform default timeout on the wire"
    );

    // And it must NOT be the bare no-ext frame — the ext is genuinely present.
    let (actions3, driver3) = recording_actions();
    let rid = actions3.alloc_next_request_id();
    actions3
        .send_request_query(rid, 0, Some("home/temp"))
        .unwrap();
    let bare = driver3.frame_bytes(0);
    assert_ne!(
        default_frame, bare,
        "a default query on a query-timeout build must carry the timeout ext, not the bare frame"
    );
}

// R311y326 — expected Request bytes for a Session::query wire assertion, with
// the default-timeout resolution mirrored. A query now resolves `timeout_ms == 0`
// to `DEFAULT_QUERY_TIMEOUT_MS` (matching pico/zenoh), so the single-knob
// convenience builders (which carry no timeout) no longer appear verbatim in the
// recorded frame — the trailing timeout ext lengthens the request and flips the
// preceding ext's continuation bit. Build the expected via
// `build_request_query_with_meta` carrying the knob under test AND the effective
// timeout, so it matches on query-timeout ON (ext present) and OFF (ext absent,
// short-circuiting to the same bytes as the bare builder per the R240 invariant).
#[cfg(all(test, feature = "query-get"))]
fn expected_query_request_bytes(
    mapping_id: u64,
    keyexpr: Option<&str>,
    #[allow(unused_mut)] mut meta: wz_session_core::metadata::QueryMetadata,
) -> Vec<u8> {
    #[cfg(feature = "query-timeout")]
    if meta.timeout_ms == 0 {
        meta.timeout_ms = DEFAULT_QUERY_TIMEOUT_MS;
    }
    // R311y837 — the consolidation is the SECOND resolved default this helper
    // back-fills, and it is here for the reason the timeout is: `Session::query`
    // now TRANSMITS the mode it resolves (zenoh's `Auto -> Latest`,
    // `api/session.rs:2316`), so a bare builder carrying no mode stopped
    // producing the bytes the query path emits. Every caller's load-bearing
    // claim — "my knob reached the wire" — is unchanged; only the envelope it
    // sits in grew, exactly as it grew when the timeout ext landed.
    //
    // Resolved through the production SSOT and from the SAME `parameters` the
    // outbound Query carries, so the `_time` carve-out is honoured without this
    // helper restating a rule that lives in one place.
    #[cfg(feature = "query-consolidation")]
    if meta.consolidation.is_none() {
        let params = meta
            .parameters
            .as_deref()
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .unwrap_or("");
        meta.consolidation =
            Some(wz_session_core::query_mode::ConsolidationMode::resolve_auto(None, params));
    }
    wz_session_core::request_build::build_request_query_with_meta(0, mapping_id, keyexpr, &meta)
        .unwrap()
        .try_as_borrowed()
        .expect("test: <=N exts by construction")
        .encode_to_vec()
}

#[cfg(all(
    feature = "codec-request",
    feature = "query-get",
    feature = "query-target"
))]
#[test]
fn query_wire_branch_with_target_threads_target_through_with_meta() {
    // QueryOptions::with_target lands on the outbound Request via
    // the with-meta path. Pins the R240 Session-level integration
    // between QueryOptions.target → QueryMetadata.target →
    // RequestQueryBuilder::request_target.
    let (session, driver) = build_session();
    session
        .query(
            "home/temp",
            QueryOptions::get()
                .with_allowed_destination(Locality::Remote)
                .with_target(QueryTarget::AllComplete),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");

    // Re-encode an equivalent standalone Request with target=All (plus the
    // default timeout the query path now resolves) and assert the wire bytes
    // appear verbatim in the recorded frame.
    let standalone_bytes = expected_query_request_bytes(
        0,
        Some("home/temp"),
        wz_session_core::metadata::QueryMetadata {
            target: Some(QueryTarget::AllComplete),
            ..Default::default()
        },
    );
    let frame = driver.frame_bytes(0);
    assert!(
        frame
            .windows(standalone_bytes.len())
            .any(|w| w == standalone_bytes),
        "Session::query wire frame must contain with-target Request bytes"
    );
}

#[cfg(all(feature = "query-get", feature = "query-attachment"))]
#[test]
fn query_wire_branch_with_attachment_threads_attachment_through_with_meta() {
    let (session, driver) = build_session();
    session
        .query(
            "home/temp",
            QueryOptions::get()
                .with_allowed_destination(Locality::Remote)
                .with_attachment(b"q-att".to_vec()),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");

    let standalone_bytes = expected_query_request_bytes(
        0,
        Some("home/temp"),
        wz_session_core::metadata::QueryMetadata {
            attachment: Some(b"q-att".to_vec()),
            ..Default::default()
        },
    );
    let frame = driver.frame_bytes(0);
    assert!(
        frame
            .windows(standalone_bytes.len())
            .any(|w| w == standalone_bytes),
        "wire frame must contain with-attachment Request bytes"
    );
}

#[cfg(all(
    feature = "codec-request",
    feature = "query-consolidation",
    feature = "query-get"
))]
#[test]
fn query_wire_branch_with_consolidation_threads_consolidation_through_with_meta() {
    let (session, driver) = build_session();
    session
        .query(
            "home/temp",
            QueryOptions::get()
                .with_allowed_destination(Locality::Remote)
                .with_consolidation(ConsolidationMode::Latest),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");

    let standalone_bytes = expected_query_request_bytes(
        0,
        Some("home/temp"),
        wz_session_core::metadata::QueryMetadata {
            consolidation: Some(ConsolidationMode::Latest),
            ..Default::default()
        },
    );
    let frame = driver.frame_bytes(0);
    assert!(
        frame
            .windows(standalone_bytes.len())
            .any(|w| w == standalone_bytes),
        "wire frame must contain with-consolidation Request bytes"
    );
}

/// R311y837 — the UNNAMED get now puts zenoh's resolved `Latest` ON THE WIRE,
/// where until this round it put nothing at all.
///
/// The expectation is built with the mode NAMED LITERALLY rather than through
/// the helper's back-fill, which is what keeps the assertion from being
/// circular: `expected_query_request_bytes` resolves an absent mode the same way
/// production does, so a version of this test that passed `Default::default()`
/// would agree with production no matter which mode either of them chose.
///
/// The value is anchored outside this crate. `Latest` is what a stock zenohd was
/// MEASURED writing for a get that names no mode
/// (`wz-integration-tests/tests/query_consolidation_wire_byte_divergence.rs`,
/// which relays that byte off a real router's wire); this test is the unit-level
/// sentry for the same fact, so a refactor reds here without needing a zenohd.
#[cfg(all(
    feature = "codec-request",
    feature = "query-consolidation",
    feature = "query-get"
))]
#[test]
fn query_wire_branch_default_transmits_the_resolved_latest_mode() {
    let (session, driver) = build_session();
    session
        .query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::Remote),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");

    let standalone_bytes = expected_query_request_bytes(
        0,
        Some("home/temp"),
        wz_session_core::metadata::QueryMetadata {
            consolidation: Some(ConsolidationMode::Latest),
            ..Default::default()
        },
    );
    let frame = driver.frame_bytes(0);
    assert!(
        frame
            .windows(standalone_bytes.len())
            .any(|w| w == standalone_bytes),
        "a get naming no mode must transmit the RESOLVED Latest, as zenoh does \
         (`api/session.rs:2316`); wz elided this field until R311y837"
    );
}

/// R311y837 — the `_time` carve-out reaches THE WIRE, not just the local sink.
///
/// R311y836 gave the carve-out a unit and an e2e, both about what the getter
/// consolidates LOCALLY, because the mode was not transmitted at all. Now that
/// it is, "an unnamed get under a `_time` range resolves to None" is a claim
/// about a byte a peer reads, and this is the test that says so. Mode named
/// literally, for the anti-circularity reason its sibling above states.
#[cfg(all(
    feature = "codec-request",
    feature = "query-consolidation",
    feature = "query-get",
    feature = "query-selector-parameters"
))]
#[test]
fn query_wire_branch_time_range_transmits_none_rather_than_latest() {
    let (session, driver) = build_session();
    session
        .query(
            "home/temp",
            QueryOptions::get()
                .with_allowed_destination(Locality::Remote)
                .with_parameters(b"_time=[now(-1h)..now()]".to_vec()),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");

    let standalone_bytes = expected_query_request_bytes(
        0,
        Some("home/temp"),
        wz_session_core::metadata::QueryMetadata {
            consolidation: Some(ConsolidationMode::None),
            parameters: Some(b"_time=[now(-1h)..now()]".to_vec()),
            ..Default::default()
        },
    );
    let frame = driver.frame_bytes(0);
    assert!(
        frame
            .windows(standalone_bytes.len())
            .any(|w| w == standalone_bytes),
        "a get carrying a `_time` range must transmit None, not Latest — both \
         upstreams key the carve-out on the parameter's PRESENCE"
    );
}

/// R311hu — NEG / isolation coverage for the query send-side
/// metadata gate, the symmetric analog of the pubsub C1d
/// metadata-OFF lane. A subset that composes `query-get` WITHOUT
/// `query-target` (the C1j `zget-reply-only` subset) cfg's out the
/// POS `..._threads_target_through_with_meta` test above, so nothing
/// otherwise proves `QueryOptions::with_target` actually elides. This
/// guard pins the signature-stable no-op (R311o): with the feature
/// off, calling `with_target` must leave the outbound frame
/// byte-identical to the bare no-metadata baseline (no Q_T flag /
/// target ext on the wire). A regression that silently un-gated the
/// setter — making the field always-on — would break this parity.
// R311y326 — `not(query-timeout)` is load-bearing, not incidental: this guard
// compares against the BARE no-metadata baseline, and a default query only
// produces bare bytes when query-timeout is also off. With query-timeout ON the
// default resolves a 10s timeout ext, so the frame is bare+timeout, not bare.
// Without this clause the guard fails on the valid query-get+query-timeout,
// query-target-off combo (e.g. a future ext-pubsub-advanced-recovery test lane)
// for a reason unrelated to what it guards.
#[cfg(all(
    feature = "query-get",
    not(feature = "query-target"),
    not(feature = "query-timeout")
))]
#[test]
fn query_with_target_is_silent_noop_when_query_target_feature_disabled() {
    let (session, driver) = build_session();
    session
        .query(
            "home/temp",
            QueryOptions::get()
                .with_allowed_destination(Locality::Remote)
                .with_target(QueryTarget::AllComplete),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");
    let session_frame = driver.frame_bytes(0);

    // Baseline: the bare no-metadata send_request_query path, the
    // same construction the empty-meta fast-path test pins.
    let (actions2, driver2) = recording_actions();
    let rid = actions2.alloc_next_request_id();
    actions2
        .send_request_query(rid, 0, Some("home/temp"))
        .unwrap();
    let baseline = driver2.frame_bytes(0);

    assert_eq!(
        session_frame, baseline,
        "with query-target OFF, with_target() must be a no-op: the wire \
             frame must equal the bare no-metadata baseline (no Q_T on the wire)"
    );
}

/// R311y317 — the guard above pins the SETTER; this one pins the FIELD.
/// `QueryOptions.target` is a `pub` field, and `#[non_exhaustive]` blocks
/// only struct-literal construction, not assignment onto a
/// `QueryOptions::get()` value — so an external caller reaches the same slot
/// without ever calling the gated `with_target`. Every downstream hop is
/// ungated: `query_metadata()` copies the field, and session-core's
/// `build_request_query_with_meta` threads it through `request_target`
/// (session-core cannot gate it — `query-target` is not one of its features,
/// unlike query-value / -source-info / -attachment / -selector-parameters,
/// whose threading IS cfg-gated there).
///
/// So the runtime layer is the LAST hop that knows this feature exists, and
/// the wire is the consequence: this is the emit-path shape R311y315 closed
/// for `QueryResponder::send_err`, not the read-surface shape R311y316 ruled
/// benign for `BorrowedQuery`.
// R311y326 — `not(query-timeout)`: bare-baseline comparison, valid only when a
// default query emits no timeout ext (see the sibling silent-noop guard above).
#[cfg(all(
    feature = "query-get",
    not(feature = "query-target"),
    not(feature = "query-timeout")
))]
#[test]
fn query_target_pub_field_cannot_bypass_the_query_target_gate() {
    let (session, driver) = build_session();
    let mut opts = QueryOptions::get().with_allowed_destination(Locality::Remote);
    // NOT with_target() — the gated setter is deliberately not called.
    opts.target = Some(QueryTarget::AllComplete);
    session
        .query("home/temp", opts, |_| {}, |_| {})
        .expect("query-get feature is ON in this test build");
    let session_frame = driver.frame_bytes(0);

    let (actions2, driver2) = recording_actions();
    let rid = actions2.alloc_next_request_id();
    actions2
        .send_request_query(rid, 0, Some("home/temp"))
        .unwrap();
    let baseline = driver2.frame_bytes(0);

    assert_eq!(
        session_frame, baseline,
        "with query-target OFF, assigning the pub `target` field must not \
             reach the wire: no build without the atom may emit Q_T"
    );
}

/// R311y334 — the LOOPBACK twin of the wire guard above. When R311y334 wired
/// `queryable.complete` into the loopback dispatch, the local leg had to read
/// the GATED `effective_target()`, NOT the raw `opts.target` pub field. With
/// `query-target` OFF a pub-field write of `Some(AllComplete)` (the same
/// R311y317 bypass the wire guard blocks) must NOT re-arm the completeness
/// filter on the local leg: a build that cannot EMIT a target must not SELECT on
/// one either. Both SessionLocal queryables — complete and incomplete — must
/// fire, exactly as with no target. This is the guard that would have caught the
/// review-found bug (loopback fed `opts.target`, skipping the incomplete
/// queryable in a query-target-OFF build).
///
/// R311y336 — HOSTED in Layer C1bk, the feature-gates job's query pub-field row
/// (`ci.yml` -> `run-ci.sh --layer C1bk`), beside the wire twin it mirrors. That
/// subset composes `query-queryable` DIRECTLY and omits `query-target`, and its
/// `--list` SET pin names this guard, so a rename or a cfg elision fails the
/// lane red rather than passing as zero tests. (The pre-y336 text here claimed
/// an `adminspace-core, query-get` "feature-gates row"; that was wrong twice
/// over — the lane it named was Layer C1an, which is local-only and appears in
/// no workflow, and y336 removed that stopgap when C1bk took the guard.)
#[cfg(all(
    feature = "query-get",
    feature = "query-queryable",
    not(feature = "query-target")
))]
#[test]
fn loopback_target_pub_field_cannot_bypass_the_query_target_gate() {
    let (session, _driver) = build_session();
    let complete_hits = Arc::new(AtomicUsize::new(0));
    let incomplete_hits = Arc::new(AtomicUsize::new(0));

    let c = complete_hits.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register_sink(
            "home/temp",
            Locality::SessionLocal,
            /*complete=*/ true,
            wz_session_core::query_sink::BoxedQuerySink::new(move |_q, responder| {
                c.fetch_add(1, Ordering::SeqCst);
                responder.reply(b"complete");
            }),
        )
        .expect("register on the alloc backing never exceeds declared capacity");
    let ic = incomplete_hits.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register_with_locality("home/temp", Locality::SessionLocal, move |_q, responder| {
            ic.fetch_add(1, Ordering::SeqCst);
            responder.reply(b"incomplete");
        });

    let mut opts = QueryOptions::get().with_allowed_destination(Locality::SessionLocal);
    // Pub-field bypass — with_target() is a no-op when query-target is OFF, so
    // the raw field is the only injection path, exactly the R311y317 attack.
    opts.target = Some(QueryTarget::AllComplete);
    session
        .query("home/temp", opts, |_| {}, |_| {})
        .expect("query-get feature is ON in this test build");

    // query-target OFF => effective_target() == None => the loopback applies NO
    // completeness filter => BOTH queryables fire, despite the pub-field target.
    assert_eq!(
        complete_hits.load(Ordering::SeqCst),
        1,
        "complete queryable fires on the loopback"
    );
    assert_eq!(
        incomplete_hits.load(Ordering::SeqCst),
        1,
        "incomplete queryable STILL fires: a query-target-OFF build must not \
             select on a pub-field target injected past the gate"
    );
}

/// R311hu — NEG / isolation counterpart for `query-consolidation`
/// (see the `query-target` guard above for the rationale). With the
/// feature off, `QueryOptions::with_consolidation` is a
/// signature-stable no-op: the Q_C flag and its consolidation byte
/// must be absent, so the outbound frame must equal the bare
/// no-metadata baseline.
// R311y326 — `not(query-timeout)`: bare-baseline comparison, valid only when a
// default query emits no timeout ext (see the query-target silent-noop guard).
#[cfg(all(
    feature = "query-get",
    not(feature = "query-consolidation"),
    not(feature = "query-timeout")
))]
#[test]
fn query_with_consolidation_is_silent_noop_when_query_consolidation_feature_disabled() {
    let (session, driver) = build_session();
    session
        .query(
            "home/temp",
            QueryOptions::get()
                .with_allowed_destination(Locality::Remote)
                .with_consolidation(ConsolidationMode::Latest),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");
    let session_frame = driver.frame_bytes(0);

    let (actions2, driver2) = recording_actions();
    let rid = actions2.alloc_next_request_id();
    actions2
        .send_request_query(rid, 0, Some("home/temp"))
        .unwrap();
    let baseline = driver2.frame_bytes(0);

    assert_eq!(
        session_frame, baseline,
        "with query-consolidation OFF, with_consolidation() must be a \
             no-op: the wire frame must equal the bare no-metadata baseline \
             (no Q_C on the wire)"
    );
}

/// R311hv — NEG / isolation counterpart for `query-timeout` (see the
/// `query-target` guard above for the shared rationale). Unlike
/// target / consolidation, `query-timeout` drives TWO observables off
/// a single gate: the outbound Request-level timeout ext
/// (`send_request_query_with_meta`'s `meta.timeout_ms != 0` branch)
/// AND the local `ReplyRegistry` deadline (`Session::query` computes
/// `deadline_ms` from the same `opts.timeout_ms` the wire branch
/// reads). The single gate is the `with_timeout_ms` setter (R311o,
/// signature-stable): with the feature off it leaves `timeout_ms` at
/// the `0` "never-expire" sentinel, so the `!= 0` wire branch and the
/// `(opts.timeout_ms > 0).then(..)` deadline elide together. Pinning
/// the outbound frame to the bare no-metadata baseline therefore
/// guards both effects at once — a regression that silently un-gated
/// the setter would push the field above zero, emitting the timeout
/// ext (this assertion fails) and arming a spurious deadline. No
/// separate sweep harness is needed: the sentinel the wire branch
/// reads is the same one the deadline reads, so one wire-parity
/// assertion is the complete guard.
#[cfg(all(feature = "query-get", not(feature = "query-timeout")))]
#[test]
fn query_with_timeout_ms_is_silent_noop_when_query_timeout_feature_disabled() {
    let (session, driver) = build_session();
    session
        .query(
            "home/temp",
            QueryOptions::get()
                .with_allowed_destination(Locality::Remote)
                .with_timeout_ms(1_000),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");
    let session_frame = driver.frame_bytes(0);

    // Baseline: the bare no-metadata send_request_query path, the
    // same construction the target / consolidation guards pin.
    let (actions2, driver2) = recording_actions();
    let rid = actions2.alloc_next_request_id();
    actions2
        .send_request_query(rid, 0, Some("home/temp"))
        .unwrap();
    let baseline = driver2.frame_bytes(0);

    assert_eq!(
        session_frame, baseline,
        "with query-timeout OFF, with_timeout_ms() must be a no-op: the \
             wire frame must equal the bare no-metadata baseline (no timeout \
             ext on the wire) and no local deadline is armed"
    );
}

/// R311y317 — field-path twin of the guard above (see
/// `query_target_pub_field_cannot_bypass_the_query_target_gate` for why the
/// setter guard does not cover this): `QueryOptions.timeout_ms` is a `pub`
/// field, so a caller reaches the slot without the gated `with_timeout_ms`.
#[cfg(all(feature = "query-get", not(feature = "query-timeout")))]
#[test]
fn query_timeout_pub_field_cannot_bypass_the_query_timeout_gate() {
    let (session, driver) = build_session();
    let mut opts = QueryOptions::get().with_allowed_destination(Locality::Remote);
    // NOT with_timeout_ms() — the gated setter is deliberately not called.
    opts.timeout_ms = 1_000;
    session
        .query("home/temp", opts, |_| {}, |_| {})
        .expect("query-get feature is ON in this test build");
    let session_frame = driver.frame_bytes(0);

    let (actions2, driver2) = recording_actions();
    let rid = actions2.alloc_next_request_id();
    actions2
        .send_request_query(rid, 0, Some("home/temp"))
        .unwrap();
    let baseline = driver2.frame_bytes(0);

    assert_eq!(
        session_frame, baseline,
        "with query-timeout OFF, assigning the pub `timeout_ms` field must \
             not reach the wire: no build without the atom may emit the \
             timeout ext"
    );

    // The SECOND observable, and the reason this atom needs a gated accessor
    // rather than a gate at the wire threading: `Session::query` computes
    // `deadline_ms` straight off `opts.timeout_ms`, never touching
    // `query_metadata()`. A wire-only fix leaves this armed and the assertion
    // above still passes — so the wire check alone cannot guard this atom.
    assert_eq!(
        session.next_reply_deadline_ms(),
        None,
        "with query-timeout OFF, the pub-field write must not arm the local \
             ReplyRegistry deadline either"
    );
}

/// R311y317 — field-path twin for `query-consolidation` (see
/// `query_target_pub_field_cannot_bypass_the_query_target_gate`).
// R311y326 — `not(query-timeout)`: bare-baseline comparison, valid only when a
// default query emits no timeout ext (see the query-target silent-noop guard).
#[cfg(all(
    feature = "query-get",
    not(feature = "query-consolidation"),
    not(feature = "query-timeout")
))]
#[test]
fn query_consolidation_pub_field_cannot_bypass_the_gate() {
    let (session, driver) = build_session();
    let mut opts = QueryOptions::get().with_allowed_destination(Locality::Remote);
    // NOT with_consolidation() — the gated setter is deliberately not called.
    opts.consolidation = Some(ConsolidationMode::Latest);
    session
        .query("home/temp", opts, |_| {}, |_| {})
        .expect("query-get feature is ON in this test build");
    let session_frame = driver.frame_bytes(0);

    let (actions2, driver2) = recording_actions();
    let rid = actions2.alloc_next_request_id();
    actions2
        .send_request_query(rid, 0, Some("home/temp"))
        .unwrap();
    let baseline = driver2.frame_bytes(0);

    assert_eq!(
        session_frame, baseline,
        "with query-consolidation OFF, assigning the pub `consolidation` \
             field must not reach the wire: no build without the atom may \
             emit Q_C"
    );
}

#[cfg(all(feature = "query-get", feature = "query-attachment"))]
#[test]
fn query_session_local_with_any_metadata_skips_wire_branch_entirely() {
    // R240 invariance: even with non-empty QueryMetadata, a
    // Locality::SessionLocal query MUST NOT touch the wire. The
    // meta extraction happens regardless but the actions surface
    // is never invoked.
    let (session, driver) = build_session();
    session
        .query(
            "home/temp",
            QueryOptions::get()
                .with_allowed_destination(Locality::SessionLocal)
                .with_target(QueryTarget::All)
                .with_attachment(b"q-att".to_vec())
                .with_timeout_ms(1_000),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");
    assert_eq!(
        driver.frame_count(),
        0,
        "SessionLocal must skip the wire branch regardless of metadata"
    );
}

// ── R241 query_aliased + query_aliased_auto ──

#[cfg(all(feature = "query-get", feature = "query-queryable"))]
#[test]
fn query_aliased_locality_session_local_fires_loopback_only() {
    let (session, driver) = build_session();
    let reply_count = Arc::new(AtomicUsize::new(0));
    let final_count = Arc::new(AtomicUsize::new(0));

    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("home/temp", |_q, responder| {
            responder.reply(b"22.5");
        });

    let r = reply_count.clone();
    let f = final_count.clone();
    session
        .query_aliased(
            7,
            None,
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |_reply| {
                r.fetch_add(1, Ordering::SeqCst);
            },
            move |_rid| {
                f.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("query-get feature is ON in this test build");

    assert_eq!(reply_count.load(Ordering::SeqCst), 1);
    assert_eq!(final_count.load(Ordering::SeqCst), 1);
    assert_eq!(driver.frame_count(), 0, "SessionLocal skips wire");
}

#[cfg(feature = "query-get")]
#[test]
fn query_aliased_locality_remote_fires_wire_with_mapping_id() {
    let (session, driver) = build_session();
    session
        .query_aliased(
            7,
            None,
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::Remote),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");
    assert_eq!(driver.frame_count(), 1, "wire frame emitted");

    // Verify the recorded frame carries the (mapping_id=7, suffix=None) aliased
    // pair. A default query now resolves the platform timeout, so the expected
    // bytes carry it too (on a query-timeout build); on an OFF build the empty
    // meta short-circuits to the bare build_request_query bytes.
    let standalone_bytes =
        expected_query_request_bytes(7, None, wz_session_core::metadata::QueryMetadata::default());
    let frame = driver.frame_bytes(0);
    assert!(
        frame
            .windows(standalone_bytes.len())
            .any(|w| w == standalone_bytes),
        "wire frame must encode the (mapping_id=7, suffix=None) aliased pair"
    );
}

#[cfg(all(feature = "query-get", feature = "query-queryable"))]
#[test]
fn query_aliased_locality_any_fires_both_branches() {
    let (session, driver) = build_session();
    let reply_count = Arc::new(AtomicUsize::new(0));
    let final_count = Arc::new(AtomicUsize::new(0));
    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("home/temp", |_q, responder| {
            responder.reply(b"22.5");
        });

    let r = reply_count.clone();
    let f = final_count.clone();
    session
        .query_aliased(
            7,
            None,
            "home/temp",
            get_opts_in_arrival_order(),
            // Any
            move |_| {
                r.fetch_add(1, Ordering::SeqCst);
            },
            move |_| {
                f.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("query-get feature is ON in this test build");

    assert_eq!(reply_count.load(Ordering::SeqCst), 1, "loopback fires");
    assert_eq!(
        final_count.load(Ordering::SeqCst),
        0,
        "Any expects 2 finals; only loopback final has fired so far"
    );
    assert_eq!(driver.frame_count(), 1, "wire branch also fires");
}

#[cfg(all(feature = "query-get", feature = "query-queryable"))]
#[test]
fn query_aliased_inline_suffix_passes_through_to_wire_and_loopback() {
    let (session, driver) = build_session();
    let captured: Arc<Mutex<Option<InboundReply>>> = Arc::new(Mutex::new(None));
    let cap_cb = captured.clone();

    // Local queryable matches the COMPOSITE literal (the
    // loopback path uses loopback_keyexpr verbatim).
    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("home/temp/kitchen", |_q, responder| {
            responder.reply(b"21.0");
        });

    session
        .query_aliased(
            7,
            Some("/kitchen"),
            "home/temp/kitchen",
            get_opts_in_arrival_order(),
            move |reply| {
                *cap_cb.lock().unwrap() = Some(InboundReply::from_view(reply));
            },
            |_| {},
        )
        .expect("query-get feature is ON in this test build");

    let got = captured
        .lock()
        .unwrap()
        .clone()
        .expect("loopback reply fired");
    assert_eq!(got.keyexpr_literal, "home/temp/kitchen");
    assert_eq!(
        driver.frame_count(),
        1,
        "wire branch sent the composite pair"
    );
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "query-get",
    feature = "query-queryable"
))]
#[test]
fn query_aliased_auto_resolves_loopback_from_outbound_mapping_table() {
    let (session, driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");

    let captured: Arc<Mutex<Option<InboundReply>>> = Arc::new(Mutex::new(None));
    let cap_cb = captured.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("home/temp", |_q, responder| {
            responder.reply(b"22.5");
        });

    let handle = session
        .query_aliased_auto(
            7,
            None,
            get_opts_in_arrival_order(),
            move |reply| {
                *cap_cb.lock().unwrap() = Some(InboundReply::from_view(reply));
            },
            |_| {},
        )
        .expect("declared mapping resolves");

    assert_eq!(handle.rid(), 0, "first auto-resolved query gets rid=0");
    let got = captured
        .lock()
        .unwrap()
        .clone()
        .expect("loopback reply fired");
    assert_eq!(got.keyexpr_literal, "home/temp");
    // 2 wire frames: one DeclKexpr, one Request(Query).
    assert_eq!(driver.frame_count(), 2);
}

#[cfg(all(feature = "query-get", feature = "query-queryable"))]
#[test]
fn query_aliased_auto_unknown_mapping_returns_err_and_skips_both_branches() {
    let (session, driver) = build_session();
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("home/temp", move |_q, _r| {
            fired_cb.fetch_add(1, Ordering::SeqCst);
        });

    let err = session.query_aliased_auto(99, None, QueryOptions::get(), |_| {}, |_| {});
    assert_eq!(err, Err(QueryAliasError::UnknownMapping(99)));
    assert_eq!(fired.load(Ordering::SeqCst), 0, "loopback skipped on err");
    assert_eq!(driver.frame_count(), 0, "wire skipped on err");
    assert!(
        session.observer().lock().unwrap().replies.is_empty(),
        "no pending entry on err"
    );
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "query-get",
    feature = "query-queryable"
))]
#[test]
fn query_aliased_auto_with_inline_suffix_concatenates_for_loopback() {
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");

    let captured: Arc<Mutex<Option<InboundReply>>> = Arc::new(Mutex::new(None));
    let cap_cb = captured.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("home/temp/kitchen", |_q, responder| {
            responder.reply(b"21.0");
        });

    session
        .query_aliased_auto(
            7,
            Some("/kitchen"),
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |reply| {
                *cap_cb.lock().unwrap() = Some(InboundReply::from_view(reply));
            },
            |_| {},
        )
        .expect("declared mapping resolves");

    let got = captured
        .lock()
        .unwrap()
        .clone()
        .expect("composite literal matched");
    assert_eq!(got.keyexpr_literal, "home/temp/kitchen");
}

#[cfg(all(feature = "query-get", feature = "query-attachment"))]
#[test]
fn query_aliased_with_meta_threads_attachment_through_wire() {
    let (session, driver) = build_session();
    session
        .query_aliased(
            7,
            None,
            "home/temp",
            QueryOptions::get()
                .with_allowed_destination(Locality::Remote)
                .with_attachment(b"q-att".to_vec()),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");

    let standalone_bytes = expected_query_request_bytes(
        7,
        None,
        wz_session_core::metadata::QueryMetadata {
            attachment: Some(b"q-att".to_vec()),
            ..Default::default()
        },
    );
    let frame = driver.frame_bytes(0);
    assert!(
        frame
            .windows(standalone_bytes.len())
            .any(|w| w == standalone_bytes),
        "aliased + with-meta routing must thread attachment onto wire"
    );
}

#[test]
fn query_alias_error_display_message_hints_remediation() {
    let err = QueryAliasError::UnknownMapping(42);
    let msg = format!("{err}");
    assert!(
        msg.contains("42"),
        "error message includes the offending id"
    );
    assert!(
        msg.contains("send_declare_keyexpr"),
        "error message hints at the remediation API"
    );
}

// ── R242 Querier (z_querier_t mirror) ──

#[test]
fn declare_querier_returns_handle_with_keyexpr_and_options() {
    let (session, _driver) = build_session();
    let opts = QueryOptions::get()
        .with_target(QueryTarget::All)
        .with_consolidation(ConsolidationMode::Latest)
        .with_timeout_ms(5_000);
    let querier = session.declare_querier("home/temp", opts.clone());
    assert_eq!(querier.keyexpr(), "home/temp");
    assert_eq!(querier.options().target, opts.target);
    assert_eq!(querier.options().consolidation, opts.consolidation);
    assert_eq!(querier.options().timeout_ms, opts.timeout_ms);
}

#[test]
fn declare_querier_does_not_emit_wire_frame_at_declare_time() {
    // The querier "declaration" is purely a caller-side
    // aggregation; the Query side has no peer-side state to
    // register (unlike DeclareSubscriber / DeclareQueryable).
    let (session, driver) = build_session();
    let _querier = session.declare_querier("home/temp", QueryOptions::get());
    assert_eq!(
        driver.frame_count(),
        0,
        "declare_querier is a no-op on the wire"
    );
}

#[cfg(all(feature = "query-get", feature = "query-queryable"))]
#[test]
fn querier_get_fires_loopback_through_session_query_session_local() {
    let (session, driver) = build_session();
    let reply_count = Arc::new(AtomicUsize::new(0));
    let final_count = Arc::new(AtomicUsize::new(0));

    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("home/temp", |_q, responder| {
            responder.reply(b"22.5");
        });

    let querier = session.declare_querier(
        "home/temp",
        QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
    );
    let r = reply_count.clone();
    let f = final_count.clone();
    querier
        .get(
            move |_| {
                r.fetch_add(1, Ordering::SeqCst);
            },
            move |_| {
                f.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("query-get feature is ON in this test build");

    assert_eq!(reply_count.load(Ordering::SeqCst), 1);
    assert_eq!(final_count.load(Ordering::SeqCst), 1);
    assert_eq!(driver.frame_count(), 0, "SessionLocal skips wire");
}

#[cfg(feature = "query-get")]
#[test]
fn querier_get_called_twice_allocates_independent_rids() {
    let (session, _driver) = build_session();
    let querier = session.declare_querier(
        "home/temp",
        QueryOptions::get().with_allowed_destination(Locality::Remote),
    );
    let h0 = querier
        .get(|_| {}, |_| {})
        .expect("query-get feature is ON in this test build");
    let h1 = querier
        .get(|_| {}, |_| {})
        .expect("query-get feature is ON in this test build");
    assert_eq!(h0.rid(), 0);
    assert_eq!(
        h1.rid(),
        1,
        "successive querier.get() calls get monotonic rids"
    );
    assert_eq!(
        session.observer().lock().unwrap().replies.len(),
        2,
        "both pending entries preserved (Locality::Remote awaits wire Final)"
    );
}

#[cfg(all(
    feature = "codec-request",
    feature = "query-get",
    feature = "query-target"
))]
#[test]
fn querier_get_threads_target_option_into_wire() {
    // Single-knob verification: declare with target=All, observe
    // the wire frame containing the with-target Request encoding.
    // (Multi-knob composite verify lives in R240's
    // send_request_query_with_meta tests — we don't duplicate it
    // here; the contract this test pins is "Querier::get really
    // does thread its declare-time options through to
    // Session::query and onward to the wire".)
    let (session, driver) = build_session();
    let querier = session.declare_querier(
        "home/temp",
        QueryOptions::get()
            .with_allowed_destination(Locality::Remote)
            .with_target(QueryTarget::All),
    );
    querier
        .get(|_| {}, |_| {})
        .expect("query-get feature is ON in this test build");

    let standalone_bytes = expected_query_request_bytes(
        0,
        Some("home/temp"),
        wz_session_core::metadata::QueryMetadata {
            target: Some(QueryTarget::All),
            ..Default::default()
        },
    );
    let frame = driver.frame_bytes(0);
    assert!(
        frame
            .windows(standalone_bytes.len())
            .any(|w| w == standalone_bytes),
        "Querier::get must thread declare-time target option into the wire frame"
    );
}

#[cfg(feature = "query-get")]
#[test]
fn querier_clone_shares_session_and_options() {
    let (session, _driver) = build_session();
    let querier = session.declare_querier("home/temp", QueryOptions::get());
    let clone = querier.clone();
    assert_eq!(clone.keyexpr(), querier.keyexpr());
    assert_eq!(
        clone.options().allowed_destination,
        querier.options().allowed_destination
    );
    // Both clones can issue independent gets — verify by emitting
    // through both and checking the pending count.
    let q1 = querier
        .clone()
        .get(|_| {}, |_| {})
        .expect("query-get feature is ON in this test build");
    let q2 = clone
        .get(|_| {}, |_| {})
        .expect("query-get feature is ON in this test build");
    assert_eq!(q1.rid(), 0);
    assert_eq!(q2.rid(), 1, "clones share the same rid allocator");
}

// ── R288 Querier::get_matching_status ──

/// Local construction helper for inbound `DeclQueryable` /
/// `UndeclQueryable` records that exercise the
/// `remote_queryables` registry from session.rs tests. Returns a
/// ready `DeclareVariant` body from a single keyexpr literal —
/// distinct ergonomics from the `wz-session-core-test-support`
/// record builders (those return the unwrapped `DeclQueryable`
/// and take a separate `mapping_id`), so the 1-arg wrapper stays
/// inline here rather than threading the lower-level builders.
#[cfg(feature = "declare-queryable")]
fn make_decl_queryable(id: u64, keyexpr_literal: &str) -> wz_codecs::declare::DeclareOwnedVariant {
    use wz_codecs::decl_queryable::DeclQueryable;
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_local::WireexprLocal;
    let suffix_len = Some(keyexpr_literal.len() as u64);
    let keyexpr = Wireexpr {
        body: WireexprVariant::WireexprLocal(WireexprLocal {
            id: 0,
            suffix_len,
            suffix: Some(keyexpr_literal),
        }),
    };
    // Build the borrowed variant then deep-copy into the owned
    // mirror that `dispatch_declare` now takes.
    wz_codecs::declare::DeclareVariant::CodecZenohDeclQueryable(DeclQueryable {
        id,
        keyexpr,
        ..DeclQueryable::default()
    })
    .try_into_owned()
    .unwrap()
}

#[cfg(feature = "declare-queryable")]
fn make_undecl_queryable(id: u64) -> wz_codecs::declare::DeclareOwnedVariant {
    use wz_codecs::undecl_queryable::UndeclQueryable;
    wz_codecs::declare::DeclareVariant::CodecZenohUndeclQueryable(UndeclQueryable {
        id,
        ..UndeclQueryable::default()
    })
    .try_into_owned()
    .unwrap()
}

#[test]
fn querier_get_matching_status_false_on_fresh_session_with_no_peers() {
    let (session, _driver) = build_session();
    let querier = session.declare_querier("home/temp", QueryOptions::get());
    assert_eq!(
        querier.get_matching_status(),
        MatchingStatus { matching: false },
        "no peer DeclQueryable dispatched yet — matching is false"
    );
}

#[cfg(feature = "declare-queryable")]
#[test]
fn querier_get_matching_status_true_after_peer_decl_with_matching_keyexpr() {
    use hashbrown::HashMap;
    let (session, _driver) = build_session();
    let querier = session.declare_querier("home/temp", QueryOptions::get());
    // Drive a DeclQueryable into the registry directly (no FSM
    // dispatch needed for this assertion — the registry's
    // dispatch_declare is the contract surface).
    session
        .observer()
        .lock()
        .unwrap()
        .remote_queryables
        .dispatch_declare(&make_decl_queryable(42, "home/temp"), &HashMap::new());
    assert_eq!(
        querier.get_matching_status(),
        MatchingStatus { matching: true },
        "peer DeclQueryable for the literal keyexpr — matching is true"
    );
}

#[cfg(feature = "declare-queryable")]
#[test]
fn querier_get_matching_status_true_when_peer_pattern_covers_querier_literal() {
    use hashbrown::HashMap;
    let (session, _driver) = build_session();
    let querier = session.declare_querier("home/temp", QueryOptions::get());
    session
        .observer()
        .lock()
        .unwrap()
        .remote_queryables
        .dispatch_declare(&make_decl_queryable(43, "home/**"), &HashMap::new());
    assert_eq!(
        querier.get_matching_status(),
        MatchingStatus { matching: true },
        "peer pattern home/** covers the literal home/temp — matching is true"
    );
}

#[cfg(feature = "declare-queryable")]
#[test]
fn querier_get_matching_status_true_when_querier_pattern_covers_peer_literal() {
    use hashbrown::HashMap;
    let (session, _driver) = build_session();
    let querier = session.declare_querier("home/**", QueryOptions::get());
    session
        .observer()
        .lock()
        .unwrap()
        .remote_queryables
        .dispatch_declare(&make_decl_queryable(44, "home/door"), &HashMap::new());
    assert_eq!(
        querier.get_matching_status(),
        MatchingStatus { matching: true },
        "querier pattern home/** covers peer literal home/door — matching is true"
    );
}

#[cfg(feature = "declare-queryable")]
#[test]
fn querier_get_matching_status_false_after_peer_undeclare() {
    use hashbrown::HashMap;
    let (session, _driver) = build_session();
    let querier = session.declare_querier("home/temp", QueryOptions::get());
    session
        .observer()
        .lock()
        .unwrap()
        .remote_queryables
        .dispatch_declare(&make_decl_queryable(45, "home/temp"), &HashMap::new());
    assert_eq!(
        querier.get_matching_status(),
        MatchingStatus { matching: true }
    );
    // Peer retracts the queryable.
    session
        .observer()
        .lock()
        .unwrap()
        .remote_queryables
        .dispatch_declare(&make_undecl_queryable(45), &HashMap::new());
    assert_eq!(
        querier.get_matching_status(),
        MatchingStatus { matching: false },
        "post-UndeclQueryable — matching falls back to false"
    );
}

#[cfg(feature = "declare-queryable")]
#[test]
fn querier_get_matching_status_false_with_non_matching_peer_keyexpr() {
    use hashbrown::HashMap;
    let (session, _driver) = build_session();
    let querier = session.declare_querier("home/temp", QueryOptions::get());
    session
        .observer()
        .lock()
        .unwrap()
        .remote_queryables
        .dispatch_declare(&make_decl_queryable(46, "other/foo"), &HashMap::new());
    assert_eq!(
        querier.get_matching_status(),
        MatchingStatus { matching: false },
        "peer keyexpr does not intersect querier keyexpr — matching is false"
    );
}

#[cfg(feature = "declare-queryable")]
#[test]
fn querier_get_matching_status_true_when_any_of_many_peer_decls_matches() {
    use hashbrown::HashMap;
    let (session, _driver) = build_session();
    let querier = session.declare_querier("home/temp", QueryOptions::get());
    let mut obs = session.observer().lock().unwrap();
    obs.remote_queryables
        .dispatch_declare(&make_decl_queryable(50, "other/foo"), &HashMap::new());
    obs.remote_queryables
        .dispatch_declare(&make_decl_queryable(51, "home/temp"), &HashMap::new());
    obs.remote_queryables
        .dispatch_declare(&make_decl_queryable(52, "a/b/c"), &HashMap::new());
    assert_eq!(obs.remote_queryables.declared_count(), 3);
    drop(obs);
    assert_eq!(
        querier.get_matching_status(),
        MatchingStatus { matching: true },
        "any one matching peer decl suffices — matching is true"
    );
}

#[cfg(feature = "declare-queryable")]
#[test]
fn querier_clone_shares_matching_status_view() {
    use hashbrown::HashMap;
    let (session, _driver) = build_session();
    let querier = session.declare_querier("home/temp", QueryOptions::get());
    let querier_clone = querier.clone();
    assert_eq!(
        querier.get_matching_status(),
        MatchingStatus { matching: false }
    );
    assert_eq!(
        querier_clone.get_matching_status(),
        MatchingStatus { matching: false }
    );
    session
        .observer()
        .lock()
        .unwrap()
        .remote_queryables
        .dispatch_declare(&make_decl_queryable(60, "home/temp"), &HashMap::new());
    // Both clones observe the same registry membership change.
    assert_eq!(
        querier.get_matching_status(),
        MatchingStatus { matching: true }
    );
    assert_eq!(
        querier_clone.get_matching_status(),
        MatchingStatus { matching: true }
    );
}

// ── R243 QuerierAliased ──

#[test]
fn declare_querier_aliased_returns_handle_with_mapping_id_and_options() {
    let (session, _driver) = build_session();
    let opts = QueryOptions::get().with_target(QueryTarget::All);
    let qa = session.declare_querier_aliased(7, Some("/kitchen"), opts.clone());
    assert_eq!(qa.mapping_id(), 7);
    assert_eq!(qa.inline_suffix(), Some("/kitchen"));
    assert_eq!(qa.options().target, opts.target);
}

#[test]
fn declare_querier_aliased_does_not_emit_wire_frame() {
    let (session, driver) = build_session();
    let _qa = session.declare_querier_aliased(7, None, QueryOptions::get());
    assert_eq!(
        driver.frame_count(),
        0,
        "declare_querier_aliased is a no-op on the wire"
    );
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "query-get",
    feature = "query-queryable"
))]
#[test]
fn querier_aliased_get_resolves_loopback_through_outbound_mapping_table() {
    let (session, driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");

    let captured: Arc<Mutex<Option<InboundReply>>> = Arc::new(Mutex::new(None));
    let cap_cb = captured.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("home/temp", |_q, responder| {
            responder.reply(b"22.5");
        });

    let qa = session.declare_querier_aliased(
        7,
        None,
        QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
    );
    let handle = qa
        .get(
            move |reply| {
                *cap_cb.lock().unwrap() = Some(InboundReply::from_view(reply));
            },
            |_| {},
        )
        .expect("declared mapping resolves");

    assert_eq!(handle.rid(), 0);
    let got = captured.lock().unwrap().clone().expect("loopback fired");
    assert_eq!(got.keyexpr_literal, "home/temp");
    assert_eq!(
        driver.frame_count(),
        1,
        "DeclKexpr frame only (SessionLocal skips Query wire)"
    );
}

#[cfg(all(feature = "query-get", feature = "query-queryable"))]
#[test]
fn querier_aliased_get_unknown_mapping_returns_err_and_skips_both_branches() {
    let (session, driver) = build_session();
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("home/temp", move |_q, _r| {
            fired_cb.fetch_add(1, Ordering::SeqCst);
        });

    let qa = session.declare_querier_aliased(99, None, QueryOptions::get());
    let err = qa.get(|_| {}, |_| {});
    assert_eq!(err, Err(QueryAliasError::UnknownMapping(99)));
    assert_eq!(fired.load(Ordering::SeqCst), 0);
    assert_eq!(driver.frame_count(), 0);
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "query-get",
    feature = "query-queryable"
))]
#[test]
fn querier_aliased_get_threads_inline_suffix_into_composite_literal() {
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");

    let captured: Arc<Mutex<Option<InboundReply>>> = Arc::new(Mutex::new(None));
    let cap_cb = captured.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("home/temp/kitchen", |_q, responder| {
            responder.reply(b"21.0");
        });

    let qa = session.declare_querier_aliased(
        7,
        Some("/kitchen"),
        QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
    );
    qa.get(
        move |reply| {
            *cap_cb.lock().unwrap() = Some(InboundReply::from_view(reply));
        },
        |_| {},
    )
    .expect("declared mapping resolves");

    let got = captured
        .lock()
        .unwrap()
        .clone()
        .expect("composite literal matched");
    assert_eq!(got.keyexpr_literal, "home/temp/kitchen");
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "query-get"
))]
#[test]
fn querier_aliased_get_twice_allocates_independent_rids() {
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");
    let qa = session.declare_querier_aliased(
        7,
        None,
        QueryOptions::get().with_allowed_destination(Locality::Remote),
    );
    let h0 = qa.get(|_| {}, |_| {}).unwrap();
    let h1 = qa.get(|_| {}, |_| {}).unwrap();
    assert_eq!(h0.rid(), 0);
    assert_eq!(h1.rid(), 1);
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "query-get"
))]
#[test]
fn querier_aliased_clone_shares_session_and_options() {
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");
    let qa = session.declare_querier_aliased(
        7,
        None,
        QueryOptions::get().with_allowed_destination(Locality::Remote),
    );
    let clone = qa.clone();
    assert_eq!(clone.mapping_id(), qa.mapping_id());
    assert_eq!(clone.inline_suffix(), qa.inline_suffix());
    let h0 = qa.get(|_| {}, |_| {}).unwrap();
    let h1 = clone.get(|_| {}, |_| {}).unwrap();
    assert_eq!(h0.rid(), 0);
    assert_eq!(h1.rid(), 1, "clones share the same rid allocator");
}

// ── R289 QuerierAliased::get_matching_status ──

#[test]
fn querier_aliased_get_matching_status_returns_err_on_unknown_mapping() {
    let (session, _driver) = build_session();
    // No send_declare_keyexpr for id=88 — mapping is unknown.
    let qa = session.declare_querier_aliased(88, None, QueryOptions::get());
    assert_eq!(
        qa.get_matching_status(),
        Err(QueryAliasError::UnknownMapping(88)),
        "unresolvable mapping surfaces as QueryAliasError::UnknownMapping"
    );
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "declare-queryable"
))]
#[test]
fn querier_aliased_get_matching_status_false_after_declare_with_no_peer() {
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");
    let qa = session.declare_querier_aliased(7, None, QueryOptions::get());
    assert_eq!(
        qa.get_matching_status(),
        Ok(MatchingStatus { matching: false }),
        "mapping resolved but no peer DeclQueryable — matching is false"
    );
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "declare-queryable"
))]
#[test]
fn querier_aliased_get_matching_status_true_when_peer_decl_matches_base_literal() {
    use hashbrown::HashMap;
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");
    let qa = session.declare_querier_aliased(7, None, QueryOptions::get());
    session
        .observer()
        .lock()
        .unwrap()
        .remote_queryables
        .dispatch_declare(&make_decl_queryable(70, "home/temp"), &HashMap::new());
    assert_eq!(
        qa.get_matching_status(),
        Ok(MatchingStatus { matching: true }),
        "base mapping resolves to home/temp; peer DeclQueryable on home/temp matches"
    );
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "declare-queryable"
))]
#[test]
fn querier_aliased_get_matching_status_threads_inline_suffix_into_consult() {
    use hashbrown::HashMap;
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");
    // QuerierAliased with inline_suffix produces effective
    // keyexpr "home/temp/kitchen"; peer DeclQueryable on
    // "home/**" should match via the peer-pattern asymmetric
    // arm.
    let qa = session.declare_querier_aliased(7, Some("/kitchen"), QueryOptions::get());
    session
        .observer()
        .lock()
        .unwrap()
        .remote_queryables
        .dispatch_declare(&make_decl_queryable(71, "home/**"), &HashMap::new());
    assert_eq!(
        qa.get_matching_status(),
        Ok(MatchingStatus { matching: true }),
        "inline_suffix-composed effective keyexpr matches peer pattern home/**"
    );

    // Peer pattern home/door/** does NOT cover home/temp/kitchen
    // — verify the inline_suffix actually narrows the consult
    // (a literal-without-suffix consult against "home/door/**"
    // also fails to match home/temp, but the composed
    // home/temp/kitchen + home/door/** case is the more
    // diagnostic one).
    session
        .observer()
        .lock()
        .unwrap()
        .remote_queryables
        .dispatch_declare(&make_undecl_queryable(71), &HashMap::new());
    session
        .observer()
        .lock()
        .unwrap()
        .remote_queryables
        .dispatch_declare(&make_decl_queryable(72, "home/door/**"), &HashMap::new());
    assert_eq!(
        qa.get_matching_status(),
        Ok(MatchingStatus { matching: false }),
        "peer pattern home/door/** does not cover effective home/temp/kitchen"
    );
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "declare-queryable",
    feature = "declare-undeclare"
))]
#[test]
fn querier_aliased_get_matching_status_false_after_undeclared_mapping_drop() {
    use hashbrown::HashMap;
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");
    let qa = session.declare_querier_aliased(7, None, QueryOptions::get());
    session
        .observer()
        .lock()
        .unwrap()
        .remote_queryables
        .dispatch_declare(&make_decl_queryable(73, "home/temp"), &HashMap::new());
    assert_eq!(
        qa.get_matching_status(),
        Ok(MatchingStatus { matching: true })
    );
    // Local-side retracts the keyexpr mapping — subsequent
    // get_matching_status surfaces UnknownMapping just like
    // QuerierAliased::get does.
    session.actions().send_undeclare_kexpr(7);
    assert_eq!(
        qa.get_matching_status(),
        Err(QueryAliasError::UnknownMapping(7)),
        "post-undeclare_kexpr — mapping unresolvable, surfaces UnknownMapping"
    );
}

// ── R244 Publisher + PublisherAliased ──

#[test]
fn declare_publisher_returns_handle_with_keyexpr_and_options() {
    let (session, _driver) = build_session();
    let opts = PublishOptions::put()
        .with_locality(Locality::SessionLocal)
        .with_reliability(Reliability::BestEffort);
    let pubr = session.declare_publisher("home/temp", opts.clone());
    assert_eq!(pubr.keyexpr(), "home/temp");
    assert_eq!(pubr.options().allowed_destination, opts.allowed_destination);
    assert_eq!(pubr.options().reliability, opts.reliability);
}

#[test]
fn declare_publisher_does_not_emit_wire_frame() {
    let (session, driver) = build_session();
    let _pubr = session.declare_publisher("home/temp", PublishOptions::put());
    assert_eq!(
        driver.frame_count(),
        0,
        "declare_publisher is a no-op on the wire"
    );
}

#[cfg(feature = "pubsub-allow-loop")]
#[test]
fn publisher_put_fires_loopback_subscriber() {
    let (session, _driver) = build_session();
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .subscribers
        .register("home/temp", move |_sample| {
            fired_cb.fetch_add(1, Ordering::SeqCst);
        });

    let pubr = session.declare_publisher(
        "home/temp",
        PublishOptions::put().with_locality(Locality::SessionLocal),
    );
    let count = pubr.put(b"22.5").unwrap();
    assert_eq!(count, 1);
    assert_eq!(fired.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "pubsub-allow-loop")]
#[test]
fn publisher_delete_routes_to_del_kind_and_drops_payload() {
    let (session, _driver) = build_session();
    let kind_seen: Arc<Mutex<Option<SampleKind>>> = Arc::new(Mutex::new(None));
    let kind_cb = kind_seen.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .subscribers
        .register("clear/me", move |sample| {
            *kind_cb.lock().unwrap() = Some(sample.kind());
        });

    let pubr = session.declare_publisher(
        "clear/me",
        PublishOptions::put().with_locality(Locality::SessionLocal),
    );
    pubr.delete().unwrap();
    assert_eq!(*kind_seen.lock().unwrap(), Some(SampleKind::Del));
}

#[cfg(feature = "codec-push")]
#[test]
fn publisher_clone_shares_session_and_driver() {
    let (session, driver) = build_session();
    let pubr = session.declare_publisher(
        "home/temp",
        PublishOptions::put().with_locality(Locality::Remote),
    );
    let clone = pubr.clone();
    assert_eq!(clone.keyexpr(), pubr.keyexpr());
    pubr.put(b"a").unwrap();
    clone.put(b"b").unwrap();
    assert_eq!(driver.frame_count(), 2, "both clones share the wire driver");
}

#[test]
fn declare_publisher_aliased_returns_handle_with_mapping_id_and_options() {
    let (session, _driver) = build_session();
    let opts = PublishOptions::put().with_reliability(Reliability::BestEffort);
    let pa = session.declare_publisher_aliased(7, Some("/kitchen"), opts.clone());
    assert_eq!(pa.mapping_id(), 7);
    assert_eq!(pa.inline_suffix(), Some("/kitchen"));
    assert_eq!(pa.options().reliability, opts.reliability);
}

#[test]
fn declare_publisher_aliased_does_not_emit_wire_frame() {
    let (session, driver) = build_session();
    let _pa = session.declare_publisher_aliased(7, None, PublishOptions::put());
    assert_eq!(driver.frame_count(), 0);
}

#[cfg(all(
    feature = "codec-declare",
    feature = "codec-push",
    feature = "declare-keyexpr",
    feature = "pubsub-allow-loop"
))]
#[test]
fn publisher_aliased_put_resolves_loopback_through_outbound_table() {
    let (session, driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");

    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .subscribers
        .register("home/temp", move |_sample| {
            fired_cb.fetch_add(1, Ordering::SeqCst);
        });

    let pa = session.declare_publisher_aliased(
        7,
        None,
        PublishOptions::put().with_locality(Locality::SessionLocal),
    );
    let count = pa.put(b"22.5").expect("declared mapping resolves");
    assert_eq!(count, 1);
    assert_eq!(fired.load(Ordering::SeqCst), 1);
    assert_eq!(
        driver.frame_count(),
        1,
        "DeclKexpr only (SessionLocal skips Push wire)"
    );
}

#[test]
fn publisher_aliased_unknown_mapping_returns_err_and_skips_both_branches() {
    let (session, driver) = build_session();
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .subscribers
        .register("home/temp", move |_| {
            fired_cb.fetch_add(1, Ordering::SeqCst);
        });

    let pa = session.declare_publisher_aliased(99, None, PublishOptions::put());
    let err = pa.put(b"x");
    assert_eq!(err, Err(PublishAliasError::UnknownMapping(99)));
    assert_eq!(fired.load(Ordering::SeqCst), 0);
    assert_eq!(driver.frame_count(), 0);
}

#[cfg(all(
    feature = "codec-declare",
    feature = "codec-push",
    feature = "declare-keyexpr",
    feature = "pubsub-allow-loop"
))]
#[test]
fn publisher_aliased_delete_routes_to_del_kind() {
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "clear/me")
        .expect("hardcoded canonical literal keyexpr");
    let kind_seen: Arc<Mutex<Option<SampleKind>>> = Arc::new(Mutex::new(None));
    let kind_cb = kind_seen.clone();
    session
        .observer()
        .lock()
        .unwrap()
        .subscribers
        .register("clear/me", move |sample| {
            *kind_cb.lock().unwrap() = Some(sample.kind());
        });

    let pa = session.declare_publisher_aliased(
        7,
        None,
        PublishOptions::put().with_locality(Locality::SessionLocal),
    );
    pa.delete().expect("declared mapping resolves");
    assert_eq!(*kind_seen.lock().unwrap(), Some(SampleKind::Del));
}

// ── R290 Publisher / PublisherAliased::get_matching_status ──

/// R290 — local DeclSubscriber / UndeclSubscriber constructors
/// for session.rs tests. Mirror of the R288 make_decl_queryable /
/// make_undecl_queryable helpers; returns a ready `DeclareVariant`
/// body from a single keyexpr literal, distinct ergonomics from
/// the `wz-session-core-test-support` record builders.
#[cfg(feature = "declare-subscriber")]
fn make_decl_subscriber(id: u64, keyexpr_literal: &str) -> wz_codecs::declare::DeclareOwnedVariant {
    use wz_codecs::decl_subscriber::DeclSubscriber;
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_local::WireexprLocal;
    let suffix_len = Some(keyexpr_literal.len() as u64);
    let keyexpr = Wireexpr {
        body: WireexprVariant::WireexprLocal(WireexprLocal {
            id: 0,
            suffix_len,
            suffix: Some(keyexpr_literal),
        }),
    };
    wz_codecs::declare::DeclareVariant::CodecZenohDeclSubscriber(DeclSubscriber {
        id,
        keyexpr,
        ..DeclSubscriber::default()
    })
    .try_into_owned()
    .unwrap()
}

#[cfg(feature = "declare-subscriber")]
fn make_undecl_subscriber(id: u64) -> wz_codecs::declare::DeclareOwnedVariant {
    use wz_codecs::undecl_subscriber::UndeclSubscriber;
    wz_codecs::declare::DeclareVariant::CodecZenohUndeclSubscriber(UndeclSubscriber {
        id,
        ..UndeclSubscriber::default()
    })
    .try_into_owned()
    .unwrap()
}

#[test]
fn publisher_get_matching_status_false_on_fresh_session_with_no_peers() {
    let (session, _driver) = build_session();
    let publisher = session.declare_publisher("home/temp", PublishOptions::put());
    assert_eq!(
        publisher.get_matching_status(),
        MatchingStatus { matching: false },
        "no peer DeclSubscriber dispatched yet — matching is false"
    );
}

#[cfg(feature = "declare-subscriber")]
#[test]
fn publisher_get_matching_status_true_after_peer_decl_with_matching_keyexpr() {
    use hashbrown::HashMap;
    let (session, _driver) = build_session();
    let publisher = session.declare_publisher("home/temp", PublishOptions::put());
    session
        .observer()
        .lock()
        .unwrap()
        .remote_subscribers
        .dispatch_declare(&make_decl_subscriber(42, "home/temp"), &HashMap::new());
    assert_eq!(
        publisher.get_matching_status(),
        MatchingStatus { matching: true },
        "peer DeclSubscriber for the literal keyexpr — matching is true"
    );
}

#[cfg(feature = "declare-subscriber")]
#[test]
fn publisher_get_matching_status_true_when_peer_pattern_covers_publisher_literal() {
    use hashbrown::HashMap;
    let (session, _driver) = build_session();
    let publisher = session.declare_publisher("home/temp", PublishOptions::put());
    session
        .observer()
        .lock()
        .unwrap()
        .remote_subscribers
        .dispatch_declare(&make_decl_subscriber(43, "home/**"), &HashMap::new());
    assert_eq!(
        publisher.get_matching_status(),
        MatchingStatus { matching: true },
        "peer pattern home/** covers the literal home/temp — matching is true"
    );
}

// ── R311y788 — the SESSION-LOCAL half of matching status. Until this
// round `get_matching_status` consulted the remote registry only, so a
// publisher whose only subscriber sat on its own session reported false
// while its own `put` delivered to that subscriber.

#[cfg(all(feature = "declare-subscriber", feature = "pubsub-allow-loop"))]
#[test]
fn publisher_get_matching_status_true_for_a_session_local_subscriber() {
    use crate::session::subscriber::SubscribeOptions;
    let (session, _driver) = build_session();
    let publisher = session.declare_publisher("home/temp", PublishOptions::put());
    assert_eq!(
        publisher.get_matching_status(),
        MatchingStatus { matching: false },
        "nothing declared anywhere yet"
    );
    let _sub = session.declare_subscriber("home/temp", SubscribeOptions::default(), move |_| {});
    assert_eq!(
        publisher.get_matching_status(),
        MatchingStatus { matching: true },
        "a subscriber on THIS session is a matching target — no peer involved"
    );
}

#[cfg(all(feature = "declare-subscriber", feature = "pubsub-allow-loop"))]
#[test]
fn publisher_get_matching_status_ignores_local_when_destination_is_remote() {
    // The DISCRIMINATOR for reading the publisher's locality: same local
    // subscriber, same keyexpr, and a publisher that has declared it will
    // never deliver locally. pico gates its local count on `allow_local`
    // (`vendor/zenoh-pico/src/net/filtering.c:66`).
    use crate::session::subscriber::SubscribeOptions;
    use wz_session_core::locality::Locality;
    let (session, _driver) = build_session();
    let publisher = session.declare_publisher(
        "home/temp",
        PublishOptions::put().with_locality(Locality::Remote),
    );
    let _sub = session.declare_subscriber("home/temp", SubscribeOptions::default(), move |_| {});
    assert_eq!(
        publisher.get_matching_status(),
        MatchingStatus { matching: false },
        "a Remote-destination publisher does not count its own session's subscriber"
    );
}

#[cfg(all(feature = "declare-subscriber", feature = "pubsub-allow-loop"))]
#[test]
fn publisher_get_matching_status_ignores_a_remote_only_local_subscriber() {
    // The other side of the same gate: the SUBSCRIBER refuses local
    // origins, so it is not a target for its own session's publisher even
    // though the keyexprs intersect.
    use crate::session::subscriber::SubscribeOptions;
    use wz_session_core::locality::Locality;
    let (session, _driver) = build_session();
    let publisher = session.declare_publisher("home/temp", PublishOptions::put());
    let _sub = session.declare_subscriber(
        "home/temp",
        SubscribeOptions::default().with_allowed_origin(Locality::Remote),
        move |_| {},
    );
    assert_eq!(
        publisher.get_matching_status(),
        MatchingStatus { matching: false },
        "a Remote-origin subscriber is not reached by a local publish, so it does not match"
    );
}

#[cfg(all(feature = "declare-subscriber", feature = "pubsub-allow-loop"))]
#[test]
fn publisher_get_matching_status_false_again_after_the_local_subscriber_drops() {
    use crate::session::subscriber::SubscribeOptions;
    let (session, _driver) = build_session();
    let publisher = session.declare_publisher("home/temp", PublishOptions::put());
    {
        let _sub =
            session.declare_subscriber("home/temp", SubscribeOptions::default(), move |_| {});
        assert_eq!(
            publisher.get_matching_status(),
            MatchingStatus { matching: true }
        );
    }
    assert_eq!(
        publisher.get_matching_status(),
        MatchingStatus { matching: false },
        "the subscriber's RAII drop unregisters it and the verdict follows"
    );
}

#[cfg(feature = "declare-subscriber")]
#[test]
fn publisher_get_matching_status_false_after_peer_undeclare() {
    use hashbrown::HashMap;
    let (session, _driver) = build_session();
    let publisher = session.declare_publisher("home/temp", PublishOptions::put());
    session
        .observer()
        .lock()
        .unwrap()
        .remote_subscribers
        .dispatch_declare(&make_decl_subscriber(45, "home/temp"), &HashMap::new());
    assert_eq!(
        publisher.get_matching_status(),
        MatchingStatus { matching: true }
    );
    session
        .observer()
        .lock()
        .unwrap()
        .remote_subscribers
        .dispatch_declare(&make_undecl_subscriber(45), &HashMap::new());
    assert_eq!(
        publisher.get_matching_status(),
        MatchingStatus { matching: false },
        "post-UndeclSubscriber — matching falls back to false"
    );
}

#[cfg(feature = "declare-subscriber")]
#[test]
fn publisher_get_matching_status_false_with_non_matching_peer_keyexpr() {
    use hashbrown::HashMap;
    let (session, _driver) = build_session();
    let publisher = session.declare_publisher("home/temp", PublishOptions::put());
    session
        .observer()
        .lock()
        .unwrap()
        .remote_subscribers
        .dispatch_declare(&make_decl_subscriber(46, "other/foo"), &HashMap::new());
    assert_eq!(
        publisher.get_matching_status(),
        MatchingStatus { matching: false }
    );
}

// ── R311y797 — the SESSION-LOCAL half and the TARGET on the QUERIER
// plane. Until this round `Querier::get_matching_status` consulted the
// remote registry only and never read the target, so a querier whose only
// queryable sat on its own session reported false while its own `get` was
// answered by it, and an AllComplete querier was told `true` by responders
// that could not answer it alone.

#[cfg(feature = "query-queryable")]
#[test]
fn querier_get_matching_status_true_for_a_session_local_queryable() {
    let (session, _driver) = build_session();
    let querier = session.declare_querier("home/temp", QueryOptions::get());
    assert_eq!(
        querier.get_matching_status(),
        MatchingStatus { matching: false },
        "nothing declared anywhere yet"
    );
    let _q = session
        .declare_queryable("home/temp", QueryableOptions::default(), |_q, _r| {})
        .expect("query-queryable is on in this lane");
    assert_eq!(
        querier.get_matching_status(),
        MatchingStatus { matching: true },
        "a queryable on THIS session answers this querier — no peer involved"
    );
}

#[cfg(feature = "query-queryable")]
#[test]
fn querier_get_matching_status_false_again_after_the_local_queryable_drops() {
    let (session, _driver) = build_session();
    let querier = session.declare_querier("home/temp", QueryOptions::get());
    {
        let _q = session
            .declare_queryable("home/temp", QueryableOptions::default(), |_q, _r| {})
            .expect("query-queryable is on in this lane");
        assert_eq!(
            querier.get_matching_status(),
            MatchingStatus { matching: true }
        );
    }
    assert_eq!(
        querier.get_matching_status(),
        MatchingStatus { matching: false },
        "the queryable's RAII drop unregisters it and the verdict follows"
    );
}

#[cfg(feature = "query-queryable")]
#[test]
fn querier_get_matching_status_ignores_local_when_destination_is_remote() {
    // The DISCRIMINATOR for reading the querier's own locality: same local
    // queryable, same keyexpr, and a querier that has declared it will
    // never be answered locally.
    use wz_session_core::locality::Locality;
    let (session, _driver) = build_session();
    let querier = session.declare_querier(
        "home/temp",
        QueryOptions::get().with_allowed_destination(Locality::Remote),
    );
    let _q = session
        .declare_queryable("home/temp", QueryableOptions::default(), |_q, _r| {})
        .expect("query-queryable is on in this lane");
    assert_eq!(
        querier.get_matching_status(),
        MatchingStatus { matching: false },
        "a Remote-destination querier does not count its own session's queryable"
    );
}

#[cfg(feature = "query-queryable")]
#[test]
fn querier_get_matching_status_ignores_a_remote_only_local_queryable() {
    // The other side of the same gate: the QUERYABLE refuses local
    // origins, so it is not reached by its own session's querier even
    // though the keyexprs are identical.
    use wz_session_core::locality::Locality;
    let (session, _driver) = build_session();
    let querier = session.declare_querier("home/temp", QueryOptions::get());
    let _q = session
        .declare_queryable(
            "home/temp",
            QueryableOptions::default().with_allowed_origin(Locality::Remote),
            |_q, _r| {},
        )
        .expect("query-queryable is on in this lane");
    assert_eq!(
        querier.get_matching_status(),
        MatchingStatus { matching: false },
        "a Remote-origin queryable is not reached by a loopback query, so it does not match"
    );
}

/// A `Locality::SessionLocal` querier is not answered by a PEER, so a
/// peer's DeclQueryable must not flip its verdict. The `Locality::Any`
/// twin over the identical fixture is the discriminator.
#[cfg(feature = "declare-queryable")]
#[test]
fn querier_get_matching_status_ignores_a_peer_when_destination_is_session_local() {
    use hashbrown::HashMap;
    use wz_session_core::locality::Locality;
    let (session, _driver) = build_session();
    let local_only = session.declare_querier(
        "home/temp",
        QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
    );
    let anywhere = session.declare_querier("home/temp", QueryOptions::get());
    session
        .observer()
        .lock()
        .unwrap()
        .remote_queryables
        .dispatch_declare(&make_decl_queryable(90, "home/temp"), &HashMap::new());
    assert_eq!(
        anywhere.get_matching_status(),
        MatchingStatus { matching: true },
        "the peer declaration DID land — the fixture is live"
    );
    assert_eq!(
        local_only.get_matching_status(),
        MatchingStatus { matching: false },
        "a SessionLocal querier never reaches a peer, so no peer \
         declaration can make it match"
    );
}

/// `AllComplete` restricts the LOCAL half to queryables that declared
/// themselves complete. Both arms register the same keyexpr and the same
/// target, differing only in `QueryableOptions::complete`, so a poll that
/// ignored the flag would report them identically.
#[cfg(all(feature = "query-queryable", feature = "query-target"))]
#[test]
fn querier_get_matching_status_under_all_complete_needs_a_complete_local_queryable() {
    use wz_session_core::query_mode::QueryTarget;
    let (session, _driver) = build_session();
    let querier = session.declare_querier(
        "home/temp",
        QueryOptions::get().with_target(QueryTarget::AllComplete),
    );
    let incomplete = session
        .declare_queryable(
            "home/temp",
            QueryableOptions::default().with_complete(false),
            |_q, _r| {},
        )
        .expect("query-queryable is on in this lane");
    assert_eq!(
        querier.get_matching_status(),
        MatchingStatus { matching: false },
        "an AllComplete querier is not answered by an INCOMPLETE queryable"
    );
    drop(incomplete);

    let _complete = session
        .declare_queryable(
            "home/temp",
            QueryableOptions::default().with_complete(true),
            |_q, _r| {},
        )
        .expect("query-queryable is on in this lane");
    assert_eq!(
        querier.get_matching_status(),
        MatchingStatus { matching: true },
        "the same declaration marked COMPLETE does answer it"
    );
}

/// `AllComplete` also switches the keyexpr test from intersection to
/// INCLUSION. `home/*/temp` intersects `home/**` without including it, so
/// only the target distinguishes the two queriers here — same registry,
/// same complete queryable.
#[cfg(all(
    feature = "query-queryable",
    feature = "query-target",
    feature = "keyexpr-includes"
))]
#[test]
fn querier_get_matching_status_under_all_complete_demands_inclusion() {
    use wz_session_core::query_mode::QueryTarget;
    let (session, _driver) = build_session();
    let _q = session
        .declare_queryable(
            "home/*/temp",
            QueryableOptions::default().with_complete(true),
            |_q, _r| {},
        )
        .expect("query-queryable is on in this lane");

    let best_matching = session.declare_querier("home/**", QueryOptions::get());
    let all_complete = session.declare_querier(
        "home/**",
        QueryOptions::get().with_target(QueryTarget::AllComplete),
    );
    assert_eq!(
        best_matching.get_matching_status(),
        MatchingStatus { matching: true },
        "the two patterns intersect at `home/a/temp`"
    );
    assert_eq!(
        all_complete.get_matching_status(),
        MatchingStatus { matching: false },
        "`home/*/temp` does not INCLUDE `home/**`, so it cannot answer \
         the whole question alone"
    );
}

#[test]
fn publisher_aliased_get_matching_status_returns_err_on_unknown_mapping() {
    let (session, _driver) = build_session();
    let pa = session.declare_publisher_aliased(88, None, PublishOptions::put());
    assert_eq!(
        pa.get_matching_status(),
        Err(PublishAliasError::UnknownMapping(88)),
        "unresolvable mapping surfaces as PublishAliasError::UnknownMapping"
    );
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "declare-subscriber"
))]
#[test]
fn publisher_aliased_get_matching_status_threads_inline_suffix_into_consult() {
    use hashbrown::HashMap;
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");
    let pa = session.declare_publisher_aliased(7, Some("/kitchen"), PublishOptions::put());
    session
        .observer()
        .lock()
        .unwrap()
        .remote_subscribers
        .dispatch_declare(&make_decl_subscriber(71, "home/**"), &HashMap::new());
    assert_eq!(
        pa.get_matching_status(),
        Ok(MatchingStatus { matching: true }),
        "inline_suffix-composed effective keyexpr matches peer pattern home/**"
    );
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "declare-subscriber",
    feature = "declare-undeclare"
))]
#[test]
fn publisher_aliased_get_matching_status_false_after_undeclared_mapping_drop() {
    use hashbrown::HashMap;
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");
    let pa = session.declare_publisher_aliased(7, None, PublishOptions::put());
    session
        .observer()
        .lock()
        .unwrap()
        .remote_subscribers
        .dispatch_declare(&make_decl_subscriber(73, "home/temp"), &HashMap::new());
    assert_eq!(
        pa.get_matching_status(),
        Ok(MatchingStatus { matching: true })
    );
    session.actions().send_undeclare_kexpr(7);
    assert_eq!(
        pa.get_matching_status(),
        Err(PublishAliasError::UnknownMapping(7)),
        "post-undeclare_kexpr — mapping unresolvable, surfaces UnknownMapping"
    );
}

// ── R245 Subscriber + SubscribeOptions + declare_subscriber{_aliased} ──

#[test]
fn subscribe_options_default_is_any_locality() {
    let opts = SubscribeOptions::default();
    assert_eq!(opts.allowed_origin, Locality::Any);
}

#[test]
fn subscribe_options_with_allowed_origin_pins_locality() {
    let opts = SubscribeOptions::new().with_allowed_origin(Locality::SessionLocal);
    assert_eq!(opts.allowed_origin, Locality::SessionLocal);
}

#[test]
fn declare_subscriber_returns_handle_with_keyexpr_and_options() {
    let (session, _driver) = build_session();
    let sub = session
        .declare_subscriber(
            "home/temp",
            SubscribeOptions::new().with_allowed_origin(Locality::SessionLocal),
            |_sample| {},
        )
        .expect("session-local declare is infallible (no outbound keyexpr)");
    assert_eq!(sub.keyexpr(), "home/temp");
    assert_eq!(sub.options().allowed_origin, Locality::SessionLocal);
}

#[test]
fn declare_subscriber_session_local_does_not_emit_wire_frame() {
    // R311ou — pico parity (`_z_register_subscriber`, primitives.c:235): a
    // SessionLocal subscriber registers locally only; `allowed_origin` does not
    // allow remote, so NO `Declare(DeclSubscriber)` is announced. (This is the
    // surviving half of the old `declare_subscriber_does_not_emit_wire_frame` —
    // the wire-no-op is now the session-local case, not the default.)
    let (session, driver) = build_session();
    let _sub = session
        .declare_subscriber(
            "home/temp",
            SubscribeOptions::new().with_allowed_origin(Locality::SessionLocal),
            |_| {},
        )
        .expect("session-local declare emits nothing and cannot fail the outbound gate");
    assert_eq!(
        driver.frame_count(),
        0,
        "a SessionLocal subscriber is loopback-only and emits no wire frame"
    );
}

#[cfg(feature = "declare-subscriber")]
#[test]
fn declare_subscriber_remote_emits_one_reliable_decl_subscriber() {
    // R311ou — pico parity: a remote-locality subscriber (default `Any`)
    // announces itself to the router with exactly one reliable
    // `Declare(DeclSubscriber)` so the router routes matching Pushes back. This
    // falsifies the prior R311or "router-mode subscriber out of scope" finding;
    // verified end-to-end against zenohd (Layer Z interop). The DeclSubscriber
    // byte shape is pinned at the builder level
    // (`build_declare_subscriber_emits_zenoh_pico_compatible_wire_bytes`).
    let (session, driver) = build_session();
    let sub = session
        .declare_subscriber("home/temp", SubscribeOptions::default(), |_| {})
        .expect("remote declare against the test link succeeds");
    assert_eq!(
        driver.frame_count(),
        1,
        "a remote-locality subscriber emits exactly one Declare(DeclSubscriber)"
    );
    assert_eq!(
        driver.frame_reliability(0),
        Reliability::Reliable,
        "Declare frames travel on the reliable channel (SN-window ordering)"
    );
    // R311ou — the wire subscriber id IS the local SubscriptionId (one entity
    // id, pico `_z_get_entity_id` parity). Forget the handle so its Drop
    // retraction does not add a second frame (the retract path is the dedicated
    // test below).
    let _ = sub.id();
    std::mem::forget(sub);
}

/// R311y342 NEG — the OFF twin of the routed-announce test above, and the
/// guard `announce_subscriber`'s own doc was owed. That doc claims: "On a
/// build without the `declare-subscriber` codec, `Ok(None)` — the local
/// subscriber stays valid for loopback / directly-connected delivery; only
/// the router announce is elided." Both halves of that sentence were
/// unguarded — the arm returns the SAME `Ok(None)` a legitimate
/// session-local subscriber gets, so a regression that turned the announce
/// into a silent no-op ON a `declare-subscriber` build would look identical
/// from the caller's side. R311hw/R311hx: a compile proof does not prove the
/// signature-stable surface BEHAVES when the feature is off.
///
/// Asserted after Drop as well: the retraction half is elided too, so the
/// whole handle lifecycle is wire-silent rather than just its construction.
#[cfg(not(feature = "declare-subscriber"))]
#[test]
fn declare_subscriber_stays_local_and_emits_nothing_when_feature_off() {
    let (session, driver) = build_session();
    let sub = session
        .declare_subscriber("home/temp", SubscribeOptions::default(), |_| {})
        .expect("the local subscriber stays constructible with the atom off");
    assert_eq!(
        driver.frame_count(),
        0,
        "declare-subscriber off must elide the router announce — no Declare reaches the wire"
    );
    drop(sub);
    assert_eq!(
        driver.frame_count(),
        0,
        "the elided announce must not leave a retraction behind either"
    );
}

#[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
#[test]
fn routed_subscriber_drop_emits_undecl_subscriber() {
    // R311ou — RAII retraction: dropping a routed subscriber emits the matching
    // `Declare(UndeclSubscriber)` so the router stops routing (pico
    // `_z_undeclare_subscriber`, primitives.c:300-307).
    let (session, driver) = build_session();
    {
        let _sub = session
            .declare_subscriber("home/temp", SubscribeOptions::default(), |_| {})
            .expect("remote declare against the test link succeeds");
        assert_eq!(
            driver.frame_count(),
            1,
            "declare emits DeclSubscriber before scope end"
        );
    }
    assert_eq!(
        driver.frame_count(),
        2,
        "Subscriber Drop emits the matching UndeclSubscriber (RAII retract)"
    );
}

/// R2290 (open-debt item 626) — build a session whose link driver reports, per
/// emitted frame, whether the observer mutex was free at that instant.
///
/// Gated as the union of the two tests below, for the reason the fixture it
/// calls carries the same union: a `--no-default-features` subset that
/// compiles neither test must not see this as dead code under `-D warnings`.
#[cfg(any(
    all(feature = "declare-subscriber", feature = "declare-undeclare"),
    feature = "liveliness-token"
))]
fn build_probing_session() -> (
    TokioSession,
    Arc<crate::test_fixtures::ObserverProbeLinkDriver>,
) {
    let (actions, driver) = crate::test_fixtures::probing_actions();
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let clock = Arc::new(TokioTime::new());
    (TokioSession::new(actions, observer, clock), driver)
}

/// R2290 (open-debt item 626) — the SUBSCRIBER plane's half of "a wire
/// retraction and the local retirement it belongs to are ONE transition".
///
/// The window between them is not theoretical: the drive thread drains the
/// staged interest-response chain under this very mutex and resolves each
/// staged reply against `observer.subscribers`, so a drain landing in the
/// window announced a subscription whose `UndeclSubscriber` had already gone
/// out. Measured before the fix as a 1-2% `wz-capi-pico::matching_multiface`
/// failure delivering `[true, false, true, false]`; 0 in 300 after it.
///
/// The probe is deterministic where that leg is statistical: a same-thread
/// `try_lock` reports `WouldBlock`, so `false` here means the emitting thread
/// held the observer — which is exactly what denies the drain the window.
#[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
#[test]
fn a_routed_subscribers_wire_retract_is_emitted_under_the_observer_lock() {
    let (session, driver) = build_probing_session();
    let sub = session
        .declare_subscriber("home/temp", SubscribeOptions::default(), |_| {})
        .expect("remote declare against the test link succeeds");
    // Armed AFTER the declare so the population is the retract frame alone.
    driver.arm(session.observer().clone());
    drop(sub);

    assert_eq!(
        driver.lockable_flags(),
        vec![false],
        "exactly one frame (the UndeclSubscriber) must leave while armed, and \
         it must leave with the observer mutex HELD — `true` means the retract \
         was emitted outside the acquisition that retires the subscription, \
         which is the window a concurrent interest drain re-announces into, \
         and an empty vec means no retract was emitted at all"
    );
}

/// R2290 (open-debt item 626) — the LIVELINESS-TOKEN plane's half of the same
/// property, and the reason it is here at all: the population was derived from
/// the DRAIN, not from the handle that was caught. `drain_declare_replies`
/// resolves staged replies against exactly two tables — `subscribers` and
/// `local_tokens` — so exactly two handles retire an entity a staged reply can
/// still announce, and both had the same emit-then-retire shape.
#[cfg(feature = "liveliness-token")]
#[test]
fn a_liveliness_tokens_wire_retract_is_emitted_under_the_observer_lock() {
    let (session, driver) = build_probing_session();
    let token = session
        .declare_token("group1/wz", LivelinessOptions::new())
        .expect("token declare against the test link succeeds");
    driver.arm(session.observer().clone());
    drop(token);

    assert_eq!(
        driver.lockable_flags(),
        vec![false],
        "exactly one frame (the UndeclToken) must leave while armed, and it \
         must leave with the observer mutex HELD — see the subscriber twin"
    );
}

#[cfg(feature = "declare-subscriber")]
#[test]
fn declare_subscriber_invalid_keyexpr_rejects_and_rolls_back_local_registration() {
    // R311ou — pico parity (`_z_register_subscriber`, primitives.c:243): when
    // the wire `Declare(DeclSubscriber)` emit is suppressed by the R300 outbound
    // pico-safety gate, the just-registered LOCAL subscriber is rolled back, so a
    // rejected declare leaves NO orphan subscriber in the registry. "**/c/*" is
    // the R299 bug-#3 family pattern (`**` + non-`*` chunk + `*`-shape chunk) the
    // gate rejects (`keyexpr_canon::check_outbound_keyexpr_pico_safe`).
    let (session, driver) = build_session();
    let result = session.declare_subscriber("**/c/*", SubscribeOptions::default(), |_| {});
    assert!(
        matches!(result, Err(SubscribeError::InvalidKeyexpr(_))),
        "the bug-#3 keyexpr is rejected by the R300 outbound gate, not declared"
    );
    assert_eq!(
        driver.frame_count(),
        0,
        "a gate-rejected declare emits no wire frame (the reject is pre-send)"
    );
    let registered = session.observer().lock().unwrap().subscribers.len();
    assert_eq!(
        registered, 0,
        "pico-parity rollback: the rejected declare left no orphan local subscriber"
    );
}

#[cfg(all(feature = "declare-subscriber", feature = "pubsub-allow-loop"))]
#[test]
fn declared_subscriber_fires_on_loopback_publish() {
    let (session, _driver) = build_session();
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    let _sub = session
        .declare_subscriber("home/temp", SubscribeOptions::default(), move |_sample| {
            fired_cb.fetch_add(1, Ordering::SeqCst);
        })
        .expect("remote declare against the test link succeeds");

    session
        .publish(
            "home/temp",
            b"22.5",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        )
        .unwrap();
    assert_eq!(fired.load(Ordering::SeqCst), 1);
}

#[cfg(all(feature = "codec-push", feature = "pubsub-allow-loop"))]
#[test]
fn subscriber_drop_auto_unregisters() {
    let (session, _driver) = build_session();
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    {
        let _sub = session
            .declare_subscriber("home/temp", SubscribeOptions::default(), move |_| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            })
            .expect("remote declare against the test link succeeds");
        // First publish fires.
        session
            .publish(
                "home/temp",
                b"21.0",
                PublishOptions::put().with_locality(Locality::SessionLocal),
            )
            .unwrap();
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    } // Subscriber drops here -> auto-unregister
      // Second publish must NOT fire — the callback is gone.
    session
        .publish(
            "home/temp",
            b"22.0",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        )
        .unwrap();
    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "Drop auto-unregistered the callback"
    );
}

#[test]
fn subscriber_undeclare_returns_true_and_skips_drop() {
    let (session, _driver) = build_session();
    let sub = session
        .declare_subscriber("home/temp", SubscribeOptions::default(), |_| {})
        .expect("remote declare against the test link succeeds");
    let removed = sub.undeclare();
    assert!(removed, "first undeclare returns true");
    // Empty registry: subsequent publish fires no callback (no panic).
    session
        .publish(
            "home/temp",
            b"22.0",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        )
        .unwrap();
}

#[test]
fn declare_subscriber_with_locality_remote_skips_loopback_publish() {
    let (session, _driver) = build_session();
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    let _sub = session
        .declare_subscriber(
            "home/temp",
            SubscribeOptions::new().with_allowed_origin(Locality::Remote),
            move |_| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("remote declare against the test link succeeds");

    session
        .publish(
            "home/temp",
            b"22.5",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        )
        .unwrap();
    assert_eq!(
        fired.load(Ordering::SeqCst),
        0,
        "Remote-only subscriber must NOT fire on loopback publish"
    );
}

#[cfg(all(
    feature = "codec-declare",
    feature = "codec-push",
    feature = "declare-keyexpr",
    feature = "declare-subscriber",
    feature = "pubsub-allow-loop"
))]
#[test]
fn declare_subscriber_aliased_resolves_literal_at_declare_time() {
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");

    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    let sub = session
        .declare_subscriber_aliased(7, None, SubscribeOptions::default(), move |_| {
            fired_cb.fetch_add(1, Ordering::SeqCst);
        })
        .expect("declared mapping resolves");
    assert_eq!(
        sub.keyexpr(),
        "home/temp",
        "resolved literal stored on handle"
    );

    session
        .publish(
            "home/temp",
            b"22.5",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        )
        .unwrap();
    assert_eq!(fired.load(Ordering::SeqCst), 1);
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "declare-subscriber"
))]
#[test]
fn declare_subscriber_aliased_with_inline_suffix_composes_literal() {
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");
    let sub = session
        .declare_subscriber_aliased(7, Some("/kitchen"), SubscribeOptions::default(), |_| {})
        .expect("declared mapping resolves");
    assert_eq!(sub.keyexpr(), "home/temp/kitchen");
}

#[test]
fn declare_subscriber_aliased_unknown_mapping_returns_err() {
    let (session, _driver) = build_session();
    let err = session.declare_subscriber_aliased(99, None, SubscribeOptions::default(), |_| {});
    assert!(
        matches!(err, Err(SubscribeAliasError::UnknownMapping(99))),
        "expected Err(UnknownMapping(99))"
    );
    // Registry stays empty.
    assert_eq!(
        session.observer().lock().unwrap().subscribers.len(),
        0,
        "no subscriber registered on declare failure"
    );
}

#[cfg(all(
    feature = "codec-declare",
    feature = "codec-push",
    feature = "declare-keyexpr",
    feature = "declare-subscriber",
    feature = "declare-undeclare",
    feature = "pubsub-allow-loop"
))]
#[test]
fn declare_subscriber_aliased_survives_mapping_retract_after_declare() {
    // Mapping resolved at declare time; later send_undeclare_kexpr
    // must not affect the already-registered subscriber (zenoh-pico
    // _z_register_subscription mirror: resolution happens once).
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    let _sub = session
        .declare_subscriber_aliased(7, None, SubscribeOptions::default(), move |_| {
            fired_cb.fetch_add(1, Ordering::SeqCst);
        })
        .expect("declared mapping resolves");

    // Retract the mapping.
    session.actions().send_undeclare_kexpr(7);

    // Publish on the literal — subscriber still fires (already
    // registered against the resolved literal).
    session
        .publish(
            "home/temp",
            b"22.5",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        )
        .unwrap();
    assert_eq!(fired.load(Ordering::SeqCst), 1);
}

#[test]
fn subscribe_alias_error_display_message_hints_remediation() {
    let err = SubscribeAliasError::UnknownMapping(42);
    let msg = format!("{err}");
    assert!(msg.contains("42"));
    assert!(msg.contains("send_declare_keyexpr"));
}

// ── R311y331 query-get OFF-arm NEG trio ──
//
// `Session::query{,_aliased,_aliased_auto}` are the atom's whole initiator
// surface and all three carry a `not(query-get)` arm returning
// `QueryAliasError::FeatureDisabled`. Until now those three arms were the ONLY
// `not(feature = "query-get")` sites in the tree and ZERO tests carried that
// gate — the atom's OFF behaviour was compile-checked and never run, which is
// what held `query-get` at PARTIAL in R311y330.
//
// The standard is this repo's, not an imported one: `session_glue.rs:1445-1452`
// (R311hw / R311hx) rules that a footprint/compile proof "does NOT prove the
// consumer-side signature-stable emit path BEHAVES correctly when off", and each
// guard must pin BOTH the typed `Err` AND `frame_count()`. Seven sibling atoms
// (transport-batching / declare-keyexpr / declare-queryable / declare-subscriber
// / declare-token / declare-interest / codec-push) already run their OFF guards
// on the `queryable-only` subset — the very lane where query-get is off. These
// three close that asymmetry; they need no new lane, they ride that row.
//
// Frame count is asserted as a DELTA, not `== 0`: `build_session()`'s set-up is
// free to emit, and pinning an absolute would make the guard a hostage to it.

#[cfg(not(feature = "query-get"))]
#[test]
fn query_rejects_typed_and_emits_nothing_when_query_get_off() {
    let (session, driver) = build_session();
    let before = driver.frame_count();

    let r = session.query("home/temp", QueryOptions::get(), |_| {}, |_| {});

    assert!(
        matches!(r, Err(QueryAliasError::FeatureDisabled)),
        "query-get off must reject typed, not silently no-op",
    );
    assert_eq!(
        driver.frame_count(),
        before,
        "a rejected get must put NO Request(Query) on the wire",
    );
}

#[cfg(not(feature = "query-get"))]
#[test]
fn query_aliased_rejects_typed_and_emits_nothing_when_query_get_off() {
    let (session, driver) = build_session();
    let before = driver.frame_count();

    let r = session.query_aliased(7, None, "home/temp", QueryOptions::get(), |_| {}, |_| {});

    assert!(
        matches!(r, Err(QueryAliasError::FeatureDisabled)),
        "query-get off must reject the aliased get typed",
    );
    assert_eq!(
        driver.frame_count(),
        before,
        "a rejected aliased get must put NO Request(Query) on the wire",
    );
}

#[cfg(not(feature = "query-get"))]
#[test]
fn query_aliased_auto_rejects_typed_and_emits_nothing_when_query_get_off() {
    let (session, driver) = build_session();
    let before = driver.frame_count();

    let r = session.query_aliased_auto(7, None, QueryOptions::get(), |_| {}, |_| {});

    assert!(
        matches!(r, Err(QueryAliasError::FeatureDisabled)),
        "query-get off must reject the auto-aliased get typed",
    );
    assert_eq!(
        driver.frame_count(),
        before,
        "a rejected auto-aliased get must put NO Request(Query) on the wire",
    );
}

// ── R246 Queryable + QueryableOptions + declare_queryable{,_aliased} ──

/// R311y330 NEG — the `query-queryable` drop proof the atom never had.
///
/// Until now the atom's OFF arms (`mod.rs` `not(query-queryable)`: the two
/// `FeatureDisabled` rejects + the loopback-fan elision) were only ever
/// COMPILED — by C1h / C4b / C1g and by the hosted E2 `wz-e2e-zget` binary —
/// and the OFF *behaviour* rested on that e2e alone. `tests.rs` said so itself,
/// on `query_session_local_with_no_queryable_finalises_inline_with_zero_replies`
/// below: "a query-queryable-OFF UNIT run is blocked until the test-support
/// dev-dep stops force-enabling default features (the C1j isolation carry)".
///
/// That carry is STALE, measured not argued: the textbook fix already landed —
/// this file's fixtures come from the crate-LOCAL `crate::test_fixtures`
/// (`:15`), and the only sibling import (`fixture_session_init_params`, `:18`)
/// returns a shared `wz-session-core` type that is safe across the dev-dep
/// cycle. `cargo test -p wz-runtime-tokio --no-default-features --features
/// <C1j's zget-reply-only row>` compiles and runs 126 unit tests with
/// `query-queryable` OFF. Nothing was blocking the proof but the note claiming
/// it was blocked.
///
/// Pins BOTH halves of the contract, because the reject alone is the weaker
/// claim: the surface stays signature-stable and rejects typed, AND it emits
/// NO wire frame — an OFF build must not announce a queryable it cannot serve.
/// R311g1 NEG shape, same as `remote_subscriber_listener_rejects_typed_when_
/// feature_off`.
#[cfg(not(feature = "query-queryable"))]
#[test]
fn declare_queryable_rejects_typed_and_emits_nothing_when_feature_off() {
    let (session, driver) = build_session();
    let before = driver.frame_count();

    let r = session.declare_queryable("home/temp", QueryableOptions::default(), |_, _| {});

    assert!(
        matches!(r, Err(QueryableError::FeatureDisabled)),
        "query-queryable off must reject typed, not silently no-op",
    );
    assert_eq!(
        driver.frame_count(),
        before,
        "a rejected declare must announce NOTHING on the wire",
    );
}

/// R311y330 NEG — the aliased twin of
/// `declare_queryable_rejects_typed_and_emits_nothing_when_feature_off`.
/// Its own OFF arm is a separate `not(query-queryable)` site with a separate
/// error type, so it needs its own guard: a sibling covered by its neighbour's
/// proof is exactly the asymmetry this round's predecessor (R311y329) was spent
/// paying off.
#[cfg(not(feature = "query-queryable"))]
#[test]
fn declare_queryable_aliased_rejects_typed_and_emits_nothing_when_feature_off() {
    let (session, driver) = build_session();
    let before = driver.frame_count();

    let r = session.declare_queryable_aliased(7, None, QueryableOptions::default(), |_, _| {});

    assert!(
        matches!(r, Err(QueryableAliasError::FeatureDisabled)),
        "query-queryable off must reject the aliased declare typed",
    );
    assert_eq!(
        driver.frame_count(),
        before,
        "a rejected aliased declare must announce NOTHING on the wire",
    );
}

#[test]
fn queryable_options_default_is_any_locality() {
    let opts = QueryableOptions::default();
    assert_eq!(opts.allowed_origin, Locality::Any);
}

#[test]
fn queryable_options_with_allowed_origin_pins_locality() {
    let opts = QueryableOptions::new().with_allowed_origin(Locality::SessionLocal);
    assert_eq!(opts.allowed_origin, Locality::SessionLocal);
}

#[test]
fn queryable_options_with_complete_pins_completeness() {
    // R311up — the BestMatching producer signal. Default is incomplete; the
    // builder pins it and composes with the locality builder.
    assert!(
        !QueryableOptions::new().complete,
        "default queryable is incomplete"
    );
    let opts = QueryableOptions::new()
        .with_allowed_origin(Locality::Remote)
        .with_complete(true);
    assert!(opts.complete, "with_complete pins the flag");
    assert_eq!(
        opts.allowed_origin,
        Locality::Remote,
        "the two builders compose"
    );
}

#[cfg(feature = "query-queryable")]
#[test]
fn declare_queryable_returns_handle_with_keyexpr_and_options() {
    let (session, _driver) = build_session();
    let q = session
        .declare_queryable(
            "home/temp",
            QueryableOptions::new().with_allowed_origin(Locality::SessionLocal),
            |_query, _responder| {},
        )
        .expect("query-queryable feature is ON in this test build");
    assert_eq!(q.keyexpr(), "home/temp");
    assert_eq!(q.options().allowed_origin, Locality::SessionLocal);
}

/// R311y330 — was UNGATED and discarded the declare's `Result`, so on a
/// `query-queryable`-OFF build (C1j's `zget-reply-only` row) the reject at
/// `mod.rs`'s `not(query-queryable)` arm emitted nothing, `frame_count()` was
/// 0, and this passed VACUOUSLY while no queryable existed at all. Its own
/// sibling twelve lines up already carried the fix
/// (`declare_queryable_returns_handle_with_keyexpr_and_options`: gate +
/// `.expect("... is ON in this test build")`) — the same
/// rule-applied-to-X-not-Y asymmetry R311y329 was spent paying off. Gated and
/// `.expect`ed now, so the claim binds to a queryable that was really declared.
/// R311y342 NEG — the `declare-queryable`-OFF twin, and the guard
/// `announce_queryable`'s silent `Ok(None)` arm was owed. Note the cfg: it
/// needs `query-queryable` ON (the fn lives behind it) and
/// `declare-queryable` OFF — the C1j `queryable-only` row. Without this, the
/// announce could regress to a no-op ON a declare-queryable build and look
/// identical to a legitimate session-local queryable from the caller's side.
/// The sibling twelve lines down records a VACUOUS pass of exactly this
/// class, which is why the `.expect` and the post-Drop assert are both here.
#[cfg(all(feature = "query-queryable", not(feature = "declare-queryable")))]
#[test]
fn declare_queryable_stays_local_and_emits_nothing_when_declare_queryable_off() {
    let (session, driver) = build_session();
    let q = session
        .declare_queryable("home/temp", QueryableOptions::default(), |_, _| {})
        .expect("the local queryable stays constructible with the announce atom off");
    assert_eq!(
        driver.frame_count(),
        0,
        "declare-queryable off must elide the announce — no Declare reaches the wire"
    );
    drop(q);
    assert_eq!(
        driver.frame_count(),
        0,
        "the elided announce must not leave a retraction behind either"
    );
}

#[cfg(feature = "query-queryable")]
#[test]
fn declare_queryable_session_local_does_not_emit_wire_frame() {
    // R311ow — pico parity (`_z_register_queryable`, primitives.c:348): a
    // SessionLocal queryable registers locally only; `allowed_origin` does not
    // allow remote, so NO `Declare(DeclQueryable)` is announced. (This is the
    // surviving half of the old `declare_queryable_does_not_emit_wire_frame` —
    // the wire-no-op is now the session-local case, not the default.)
    let (session, driver) = build_session();
    let _q = session
        .declare_queryable(
            "home/temp",
            QueryableOptions::new().with_allowed_origin(Locality::SessionLocal),
            |_q, _r| {},
        )
        .expect("query-queryable feature is ON in this test build");
    assert_eq!(
        driver.frame_count(),
        0,
        "a SessionLocal queryable is loopback-only and emits no wire frame"
    );
}

#[cfg(all(feature = "query-queryable", feature = "declare-queryable"))]
#[test]
fn declare_queryable_remote_emits_one_reliable_decl_queryable() {
    // R311ow — pico parity: a remote-locality queryable (default `Any`)
    // announces itself to the router with exactly one reliable
    // `Declare(DeclQueryable)` so the router routes matching Query requests
    // here. The DeclQueryable byte shape is pinned at the builder level
    // (`build_declare_queryable_emits_zenoh_pico_compatible_wire_bytes`).
    let (session, driver) = build_session();
    let q = session
        .declare_queryable("home/temp", QueryableOptions::default(), |_q, _r| {})
        .expect("remote declare against the test link succeeds");
    assert_eq!(
        driver.frame_count(),
        1,
        "a remote-locality queryable emits exactly one Declare(DeclQueryable)"
    );
    assert_eq!(
        driver.frame_reliability(0),
        Reliability::Reliable,
        "Declare frames travel on the reliable channel (SN-window ordering)"
    );
    // R311ow — the wire queryable id IS the local QueryableId (one entity id,
    // pico `_z_get_entity_id` parity). Forget the handle so its Drop retraction
    // does not add a second frame (the retract path is the dedicated test below).
    let _ = q.id();
    std::mem::forget(q);
}

#[cfg(all(
    feature = "query-queryable",
    feature = "declare-queryable",
    feature = "declare-undeclare"
))]
#[test]
fn routed_queryable_drop_emits_undecl_queryable() {
    // R311ow — RAII retraction: dropping a routed queryable emits the matching
    // `Declare(UndeclQueryable)` so the router stops routing (pico
    // `_z_undeclare_queryable`, primitives.c:404-417).
    let (session, driver) = build_session();
    {
        let _q = session
            .declare_queryable("home/temp", QueryableOptions::default(), |_q, _r| {})
            .expect("remote declare against the test link succeeds");
        assert_eq!(
            driver.frame_count(),
            1,
            "declare emits DeclQueryable before scope end"
        );
    }
    assert_eq!(
        driver.frame_count(),
        2,
        "Queryable Drop emits the matching UndeclQueryable (RAII retract)"
    );
}

#[cfg(all(feature = "query-queryable", feature = "declare-queryable"))]
#[test]
fn declare_queryable_invalid_keyexpr_rejects_and_rolls_back_local_registration() {
    // R311ow — pico parity (`_z_register_queryable`, primitives.c:359): when the
    // wire `Declare(DeclQueryable)` emit is suppressed by the R300 outbound
    // pico-safety gate, the just-registered LOCAL queryable is rolled back, so a
    // rejected declare leaves NO orphan queryable in the registry. "**/c/*" is
    // the R299 bug-#3 family pattern (`**` + non-`*` chunk + `*`-shape chunk) the
    // gate rejects (`keyexpr_canon::check_outbound_keyexpr_pico_safe`).
    let (session, driver) = build_session();
    let result = session.declare_queryable("**/c/*", QueryableOptions::default(), |_q, _r| {});
    assert!(
        matches!(result, Err(QueryableError::InvalidKeyexpr(_))),
        "the bug-#3 keyexpr is rejected by the R300 outbound gate, not declared"
    );
    assert_eq!(
        driver.frame_count(),
        0,
        "a gate-rejected declare emits no wire frame (the reject is pre-send)"
    );
    let registered = session.observer().lock().unwrap().queryables.len();
    assert_eq!(
        registered, 0,
        "pico-parity rollback: the rejected declare left no orphan local queryable"
    );
}

#[cfg(all(
    feature = "declare-queryable",
    feature = "query-get",
    feature = "query-queryable"
))]
#[test]
fn declared_queryable_fires_on_loopback_query() {
    let (session, _driver) = build_session();
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    let _q = session.declare_queryable(
        "home/temp",
        QueryableOptions::default(),
        move |_query, responder| {
            fired_cb.fetch_add(1, Ordering::SeqCst);
            responder.reply(b"22.5");
        },
    );

    let replies = Arc::new(AtomicUsize::new(0));
    let r = replies.clone();
    session
        .query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |_reply| {
                r.fetch_add(1, Ordering::SeqCst);
            },
            |_| {},
        )
        .expect("query-get feature is ON in this test build");

    assert_eq!(fired.load(Ordering::SeqCst), 1);
    assert_eq!(replies.load(Ordering::SeqCst), 1);
}

/// R311y252 — a SessionLocal query fans the loopback queryable with the SAME
/// Query-body surface a wire queryable observes: selector `parameters` (Q_P)
/// PLUS the value (ext 0x03) / source_info (ext 0x01) / attachment (ext 0x05)
/// ext chain. Before y252 `build_loopback_query` carried only `parameters`, so
/// a loopback queryable's `attachment()` / `source_info()` / `payload()` /
/// `encoding()` accessors all returned `None` even when the querier set them
/// (they surfaced correctly only on the wire path). `build_loopback_query` now
/// reuses the wire SSOT (`build_request_query_with_meta`) Query body, so both
/// origins carry the identical ext chain.
#[cfg(all(
    feature = "query-get",
    feature = "query-queryable",
    feature = "query-value",
    feature = "query-source-info",
    feature = "query-attachment",
    feature = "query-selector-parameters"
))]
#[test]
fn loopback_query_surfaces_body_metadata_to_queryable() {
    type Captured = (
        Option<Vec<u8>>,             // parameters
        Option<Vec<u8>>,             // attachment
        Option<(Vec<u8>, u32, u32)>, // source_info (zid, eid, sn)
        Option<Vec<u8>>,             // value payload
        Option<u32>,                 // value encoding packed_id
    );
    let (session, _driver) = build_session();
    let captured: Arc<Mutex<Option<Captured>>> = Arc::new(Mutex::new(None));
    let cap = captured.clone();
    let _q = session
        .declare_queryable(
            "home/temp",
            QueryableOptions::default(),
            move |query: &dyn QueryView, responder: &mut dyn ReplyOut| {
                let si = query
                    .source_info()
                    .map(|s| (s.zid_prefix().to_vec(), s.eid, s.sn));
                *cap.lock().unwrap() = Some((
                    query.parameters().map(<[u8]>::to_vec),
                    query.attachment().map(<[u8]>::to_vec),
                    si,
                    query.payload().map(<[u8]>::to_vec),
                    query.encoding().map(|e| e.packed_id),
                ));
                responder.reply(b"ok");
            },
        )
        .expect("query-queryable feature is ON in this test build");

    session
        .query(
            "home/temp",
            QueryOptions::get()
                .with_allowed_destination(Locality::SessionLocal)
                .with_parameters(b"_max=3".to_vec())
                .with_attachment(b"q-att".to_vec())
                .with_source_info(SourceInfo::new(&[0xDE, 0xAD, 0xBE, 0xEF], 7, 42))
                .with_payload(b"q-value".to_vec())
                .with_encoding(EncodingHint {
                    // zenoh encoding id 5 (application/json) -> wz packed_id 10
                    // (id << 1, no schema).
                    packed_id: 10,
                    schema: None,
                }),
            |_reply| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");

    let got = captured.lock().unwrap();
    let (params, att, si, payload, enc) = got.as_ref().expect("loopback queryable fired");
    assert_eq!(
        params.as_deref(),
        Some(&b"_max=3"[..]),
        "loopback surfaces selector parameters (already true pre-y252)"
    );
    assert_eq!(
        att.as_deref(),
        Some(&b"q-att"[..]),
        "R311y252 — loopback now surfaces the query attachment"
    );
    let (zid, eid, sn) = si
        .as_ref()
        .expect("R311y252 — loopback surfaces source_info");
    assert_eq!(zid.as_slice(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(*eid, 7);
    assert_eq!(*sn, 42);
    assert_eq!(
        payload.as_deref(),
        Some(&b"q-value"[..]),
        "R311y252 — loopback surfaces the value payload"
    );
    assert_eq!(
        *enc,
        Some(10),
        "R311y252 — loopback surfaces the value encoding"
    );
}

#[cfg(all(feature = "query-get", feature = "query-queryable"))]
#[test]
fn queryable_drop_auto_unregisters() {
    let (session, _driver) = build_session();
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    {
        let _q = session.declare_queryable(
            "home/temp",
            QueryableOptions::default(),
            move |_q, responder| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
                responder.reply(b"22.5");
            },
        );
        session
            .query(
                "home/temp",
                QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
                |_| {},
                |_| {},
            )
            .expect("query-get feature is ON in this test build");
        assert_eq!(fired.load(Ordering::SeqCst), 1, "first query fires");
    } // Drop unregisters

    // Second query: no queryable matches.
    session
        .query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");
    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "Drop auto-unregistered the queryable"
    );
}

#[cfg(feature = "query-queryable")]
#[test]
fn queryable_undeclare_returns_true_and_skips_drop() {
    let (session, _driver) = build_session();
    let q = session
        .declare_queryable("home/temp", QueryableOptions::default(), |_q, _r| {})
        .expect("query-queryable feature is ON in this test build");
    assert!(q.undeclare(), "first undeclare returns true");
}

/// R311y330 — the gate gained `query-queryable` and the declare gained its
/// `.expect`. It was `query-get`-only and discarded the `Result`, so on a
/// `query-queryable`-OFF build no queryable was ever registered, `fired` was
/// trivially 0, and the locality predicate this test exists to pin went
/// UNEXERCISED while reporting green. The body already `.expect`ed the sibling
/// feature (`query-get`, on the `query` call below) — the asymmetry was inside
/// one function.
#[cfg(all(feature = "query-get", feature = "query-queryable"))]
#[test]
fn declare_queryable_with_locality_remote_skips_loopback_query() {
    let (session, _driver) = build_session();
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    let _q = session
        .declare_queryable(
            "home/temp",
            QueryableOptions::new().with_allowed_origin(Locality::Remote),
            move |_q, _r| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("query-queryable feature is ON in this test build");

    session
        .query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");
    assert_eq!(
        fired.load(Ordering::SeqCst),
        0,
        "Remote-only queryable must NOT fire on loopback query"
    );
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "query-get",
    feature = "query-queryable"
))]
#[test]
fn declare_queryable_aliased_resolves_literal_at_declare_time() {
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    let q = session
        .declare_queryable_aliased(
            7,
            None,
            QueryableOptions::default(),
            move |_q, responder| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
                responder.reply(b"22.5");
            },
        )
        .expect("declared mapping resolves");
    assert_eq!(q.keyexpr(), "home/temp");

    session
        .query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            |_| {},
            |_| {},
        )
        .expect("query-get feature is ON in this test build");
    assert_eq!(fired.load(Ordering::SeqCst), 1);
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "query-queryable"
))]
#[test]
fn declare_queryable_aliased_with_inline_suffix_composes_literal() {
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");
    let q = session
        .declare_queryable_aliased(
            7,
            Some("/kitchen"),
            QueryableOptions::default(),
            |_q, _r| {},
        )
        .expect("declared mapping resolves");
    assert_eq!(q.keyexpr(), "home/temp/kitchen");
}

#[cfg(feature = "query-queryable")]
#[test]
fn declare_queryable_aliased_unknown_mapping_returns_err() {
    let (session, _driver) = build_session();
    let err = session.declare_queryable_aliased(99, None, QueryableOptions::default(), |_q, _r| {});
    assert!(matches!(err, Err(QueryableAliasError::UnknownMapping(99))));
    assert_eq!(
        session.observer().lock().unwrap().queryables.len(),
        0,
        "no queryable registered on declare failure"
    );
}

#[test]
fn queryable_alias_error_display_message_hints_remediation() {
    let err = QueryableAliasError::UnknownMapping(42);
    let msg = format!("{err}");
    assert!(msg.contains("42"));
    assert!(msg.contains("send_declare_keyexpr"));
}

// ── R248 LivelinessToken + LivelinessOptions + declare_token{,_aliased} ──

#[test]
fn liveliness_options_default_is_constructible() {
    // Empty options today (mirror zenoh-pico
    // z_liveliness_token_options_t::__dummy placeholder). The
    // contract is that both ::default() and ::new() construct
    // without arguments and are interchangeable; future fields
    // arrive via with_* setters per the R245/R246 pattern.
    let a = LivelinessOptions::default();
    let b = LivelinessOptions::new();
    // Empty struct → fmt::Debug round-trip is the cheapest
    // equivalence proxy without deriving PartialEq.
    assert_eq!(format!("{a:?}"), format!("{b:?}"));
}

#[cfg(feature = "liveliness-token")]
#[test]
fn declare_token_returns_handle_with_keyexpr_and_id_zero() {
    let (session, _driver) = build_session();
    let token = session
        .declare_token("liveliness/devA", LivelinessOptions::default())
        .expect("hardcoded canonical literal keyexpr");
    assert_eq!(
        token.id(),
        0,
        "first allocation returns id=0 per zenoh-pico convention"
    );
    assert_eq!(token.keyexpr(), "liveliness/devA");
    // Options accessor — empty struct just confirms the borrow shape.
    let _: &LivelinessOptions = token.options();
}

#[cfg(feature = "liveliness-token")]
#[test]
fn declare_token_emits_exactly_one_reliable_wire_frame() {
    let (session, driver) = build_session();
    let _token = session
        .declare_token("liveliness/devA", LivelinessOptions::default())
        .expect("hardcoded canonical literal keyexpr");
    assert_eq!(
        driver.frame_count(),
        1,
        "declare emits one outbound Declare(DeclToken)"
    );
    assert_eq!(
        driver.frame_reliability(0),
        Reliability::Reliable,
        "Declare frames travel on the reliable channel per send_declare_token contract",
    );
    // Hold the handle until end-of-scope; the drop is exercised in
    // a dedicated test below.
    std::mem::forget(_token);
}

#[cfg(feature = "liveliness-token")]
#[test]
fn declare_token_wire_frame_contains_decl_token_bytes() {
    use crate::session_glue::build_declare_token;
    let (session, driver) = build_session();
    let _token = session
        .declare_token("liveliness/devA", LivelinessOptions::default())
        .expect("hardcoded canonical literal keyexpr");

    let expected = build_declare_token(0, /*mapping_id=*/ 0, Some("liveliness/devA"))
        .unwrap()
        .try_as_borrowed()
        .expect("test: <=N exts by construction")
        .encode_to_vec();
    let frame = driver.frame_bytes(0);
    assert!(
        frame.windows(expected.len()).any(|w| w == expected),
        "Session::declare_token wire frame must contain the build_declare_token byte stream"
    );
    // Cancel drop emit — wire-shape test does not care about the
    // retraction path.
    std::mem::forget(_token);
}

#[cfg(feature = "liveliness-token")]
#[test]
fn declare_token_assigns_monotonic_ids_per_session() {
    let (session, _driver) = build_session();
    let t0 = session
        .declare_token("liveliness/x", LivelinessOptions::default())
        .expect("hardcoded canonical literal keyexpr");
    let t1 = session
        .declare_token("liveliness/y", LivelinessOptions::default())
        .expect("hardcoded canonical literal keyexpr");
    let t2 = session
        .declare_token("liveliness/z", LivelinessOptions::default())
        .expect("hardcoded canonical literal keyexpr");
    assert_eq!((t0.id(), t1.id(), t2.id()), (0, 1, 2));
    // Avoid drop wire emits in this counter-only test.
    std::mem::forget(t0);
    std::mem::forget(t1);
    std::mem::forget(t2);
}

#[cfg(feature = "liveliness-token")]
#[test]
fn liveliness_token_drop_emits_undeclare_wire_frame() {
    let (session, driver) = build_session();
    {
        let _token = session
            .declare_token("liveliness/devA", LivelinessOptions::default())
            .expect("hardcoded canonical literal keyexpr");
        assert_eq!(driver.frame_count(), 1, "declare emit before scope end");
    }
    assert_eq!(
        driver.frame_count(),
        2,
        "Drop must emit Declare(UndeclToken) so peer liveliness subscribers see DELETE"
    );
    assert_eq!(driver.frame_reliability(1), Reliability::Reliable);
}

#[cfg(feature = "liveliness-token")]
#[test]
fn liveliness_token_drop_wire_frame_contains_undecl_token_bytes() {
    use crate::session_glue::build_undeclare_token;
    let (session, driver) = build_session();
    {
        let _token = session
            .declare_token("liveliness/devA", LivelinessOptions::default())
            .expect("hardcoded canonical literal keyexpr");
        // Token id 0 was just allocated; drop will retract it.
    }
    let expected = build_undeclare_token(0)
        .try_as_borrowed()
        .expect("test: <=N exts by construction")
        .encode_to_vec();
    let frame = driver.frame_bytes(1);
    assert!(
        frame.windows(expected.len()).any(|w| w == expected),
        "Drop must emit a Declare(UndeclToken) carrying the allocated token_id"
    );
}

#[cfg(feature = "liveliness-token")]
#[test]
fn liveliness_token_undeclare_consumes_handle_and_does_not_double_emit() {
    let (session, driver) = build_session();
    let token = session
        .declare_token("liveliness/devA", LivelinessOptions::default())
        .expect("hardcoded canonical literal keyexpr");
    assert_eq!(driver.frame_count(), 1);
    token.undeclare();
    assert_eq!(
        driver.frame_count(),
        2,
        "explicit undeclare emits the retraction"
    );
    // R311lo — after undeclare(self) the handle's disarm flag is
    // cleared, so the end-of-scope Drop runs the teardown but finds it
    // disarmed and emits nothing (the owned fields are freed rather
    // than mem::forget-leaked) — frame_count stays at 2.
    assert_eq!(
        driver.frame_count(),
        2,
        "consumed handle must not emit a duplicate UndeclToken via Drop",
    );
}

/// R311lo — `undeclare()` must FREE the handle (drop its owned fields)
/// rather than `mem::forget`-leak them. The handle holds a `Session`
/// clone, so every leaked handle permanently inflates the session's
/// `observer` Arc strong-count; an explicit undeclare on a long-running
/// app would accumulate one leaked Session clone (+ keyexpr String + the
/// deferred cell Arc) per call. The disarm-flag teardown lets the
/// natural Drop free those fields, so the count returns to baseline.
/// Pre-R311lo (`mem::forget(self)`) this assertion would fail: the count
/// would stay at base+1.
#[test]
fn subscriber_undeclare_frees_session_clone_no_leak() {
    let (session, _driver) = build_session();
    let base = Arc::strong_count(session.observer());
    let sub = session
        .declare_subscriber("home/temp", SubscribeOptions::default(), |_| {})
        .expect("remote declare against the test link succeeds");
    assert!(
        Arc::strong_count(session.observer()) > base,
        "the handle holds a Session clone (observer Arc count rises)",
    );
    sub.undeclare();
    assert_eq!(
        Arc::strong_count(session.observer()),
        base,
        "undeclare must free the handle's Session clone (no mem::forget leak)",
    );
}

/// R311lo — same no-leak guard on the [`Queryable`] undeclare path.
#[cfg(feature = "query-queryable")]
#[test]
fn queryable_undeclare_frees_session_clone_no_leak() {
    let (session, _driver) = build_session();
    let base = Arc::strong_count(session.observer());
    let q = session
        .declare_queryable("home/temp", QueryableOptions::default(), |_q, _r| {})
        .expect("query-queryable feature is ON in this test build");
    assert!(
        Arc::strong_count(session.observer()) > base,
        "the handle holds a Session clone (observer Arc count rises)",
    );
    q.undeclare();
    assert_eq!(
        Arc::strong_count(session.observer()),
        base,
        "undeclare must free the handle's Session clone (no mem::forget leak)",
    );
}

/// R311lo — same no-leak guard on the [`LivelinessToken`] undeclare
/// path (the wire-emitting handle family). The `does_not_double_emit`
/// test above guards the "exactly one UndeclToken" behaviour; this one
/// guards that the consumed handle's owned fields are freed.
#[cfg(feature = "liveliness-token")]
#[test]
fn liveliness_token_undeclare_frees_session_clone_no_leak() {
    let (session, _driver) = build_session();
    let base = Arc::strong_count(session.observer());
    let token = session
        .declare_token("liveliness/devA", LivelinessOptions::default())
        .expect("hardcoded canonical literal keyexpr");
    assert!(
        Arc::strong_count(session.observer()) > base,
        "the handle holds a Session clone (observer Arc count rises)",
    );
    token.undeclare();
    assert_eq!(
        Arc::strong_count(session.observer()),
        base,
        "undeclare must free the handle's Session clone (no mem::forget leak)",
    );
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "liveliness-token"
))]
#[test]
fn declare_token_aliased_resolves_literal_at_declare_time() {
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "liveliness/dev7")
        .expect("hardcoded canonical literal keyexpr");
    let token = session
        .declare_token_aliased(7, None, LivelinessOptions::default())
        .expect("declared mapping resolves");
    assert_eq!(
        token.keyexpr(),
        "liveliness/dev7",
        "aliased declare stores the resolved literal on the handle for introspection",
    );
    std::mem::forget(token);
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "liveliness-token"
))]
#[test]
fn declare_token_aliased_with_inline_suffix_composes_literal() {
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "liveliness/dev7")
        .expect("hardcoded canonical literal keyexpr");
    let token = session
        .declare_token_aliased(7, Some("/sensor"), LivelinessOptions::default())
        .expect("declared mapping resolves");
    assert_eq!(token.keyexpr(), "liveliness/dev7/sensor");
    std::mem::forget(token);
}

#[cfg(feature = "liveliness-token")]
#[test]
fn declare_token_aliased_unknown_mapping_returns_err_without_wire_emit() {
    let (session, driver) = build_session();
    let err = session.declare_token_aliased(99, None, LivelinessOptions::default());
    assert!(
        matches!(err, Err(LivelinessAliasError::UnknownMapping(99))),
        "expected Err(UnknownMapping(99))",
    );
    assert_eq!(
        driver.frame_count(),
        0,
        "no wire emit on unknown-mapping early-return path",
    );
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "liveliness-token"
))]
#[test]
fn declare_token_aliased_wire_frame_uses_alias_form() {
    // Aliased declare emits the bandwidth-efficient alias-form
    // wire (Declare(DeclToken) with WireexprLocal { id=mapping_id,
    // suffix }), matching zenoh-pico's
    // _z_declared_keyexpr_alias_to_wire behaviour when the caller
    // hands a previously-declared keyexpr to
    // z_liveliness_declare_token.
    use crate::session_glue::build_declare_token;
    let (session, driver) = build_session();
    // Send the keyexpr declare so the mapping table holds (7 ->
    // "liveliness/dev7"); first wire frame is this Declare(DeclKexpr).
    session
        .actions()
        .send_declare_keyexpr(7, "liveliness/dev7")
        .expect("hardcoded canonical literal keyexpr");
    let baseline_frames = driver.frame_count();

    let _token = session
        .declare_token_aliased(7, Some("/sensor"), LivelinessOptions::default())
        .expect("declared mapping resolves");

    assert_eq!(
        driver.frame_count(),
        baseline_frames + 1,
        "aliased declare emits exactly one Declare(DeclToken) frame",
    );
    let expected = build_declare_token(
        /*token_id=*/ 0,
        /*mapping_id=*/ 7,
        Some("/sensor"),
    )
    .unwrap()
    .try_as_borrowed()
    .expect("test: <=N exts by construction")
    .encode_to_vec();
    let token_frame = driver.frame_bytes(baseline_frames);
    assert!(
        token_frame.windows(expected.len()).any(|w| w == expected),
        "wire frame must carry alias-form DeclToken bytes (mapping_id=7, suffix=/sensor)",
    );
    std::mem::forget(_token);
}

#[test]
fn liveliness_alias_error_display_message_hints_remediation() {
    let err = LivelinessAliasError::UnknownMapping(42);
    let msg = format!("{err}");
    assert!(msg.contains("42"));
    assert!(msg.contains("send_declare_keyexpr"));
}

// ── R282 declare_liveliness_subscriber_aliased — mirrors the
// R245 declare_subscriber_aliased and R248 declare_token_aliased
// test patterns: resolve-at-declare-time, alias-form wire emit,
// mapping-retract survival, and error-shape Display. ───────────

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "liveliness-subscriber"
))]
#[test]
fn declare_liveliness_subscriber_aliased_resolves_literal_at_declare_time() {
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "liveliness/dev7")
        .expect("hardcoded canonical literal keyexpr");
    mark_session_established(&session);
    let sub = session
        .declare_liveliness_subscriber_aliased(
            7,
            None,
            LivelinessSubscriberOptions::default(),
            |_| {},
        )
        .expect("declared mapping resolves");
    assert_eq!(
        sub.keyexpr(),
        "liveliness/dev7",
        "aliased declare stores the resolved literal on the handle for introspection",
    );
    // Slot is keyed by the freshly-allocated interest id and stores
    // the resolved literal for inbound DeclToken matching.
    assert_eq!(
        session
            .observer()
            .lock()
            .unwrap()
            .liveliness_subscribers
            .keyexpr(sub.interest_id()),
        Some("liveliness/dev7"),
        "slot stores resolved literal for keyexpr-pattern matching",
    );
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "liveliness-subscriber"
))]
#[test]
fn declare_liveliness_subscriber_aliased_with_inline_suffix_composes_literal() {
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "liveliness/dev7")
        .expect("hardcoded canonical literal keyexpr");
    mark_session_established(&session);
    let sub = session
        .declare_liveliness_subscriber_aliased(
            7,
            Some("/sensor"),
            LivelinessSubscriberOptions::default(),
            |_| {},
        )
        .expect("declared mapping resolves");
    assert_eq!(sub.keyexpr(), "liveliness/dev7/sensor");
    assert_eq!(
        session
            .observer()
            .lock()
            .unwrap()
            .liveliness_subscribers
            .keyexpr(sub.interest_id()),
        Some("liveliness/dev7/sensor"),
    );
}

#[cfg(feature = "liveliness-subscriber")]
#[test]
fn declare_liveliness_subscriber_aliased_unknown_mapping_returns_err_without_wire_emit() {
    let (session, driver) = build_session();
    let err = session.declare_liveliness_subscriber_aliased(
        99,
        None,
        LivelinessSubscriberOptions::default(),
        |_| {},
    );
    assert!(
        matches!(err, Err(LivelinessSubscriberAliasError::UnknownMapping(99))),
        "expected Err(UnknownMapping(99))",
    );
    assert_eq!(
        driver.frame_count(),
        0,
        "no wire emit on unknown-mapping early-return path",
    );
    assert_eq!(
        session
            .observer()
            .lock()
            .unwrap()
            .liveliness_subscribers
            .slot_count(),
        0,
        "no slot registered on declare failure",
    );
}

/// R311ll (Finding B) — a wire-emit FAILURE on the literal
/// `declare_liveliness_subscriber` must roll the slot back, not leave a
/// keyexpr-matched orphan firing the callback for a subscription the
/// caller got no handle to retract. The slot is registered BEFORE the
/// emit (the inbound-DeclToken race guard), so a failed emit takes the
/// rollback path: kill the deferred cell + unregister. Sibling of the
/// unknown-mapping test above but on the register-THEN-fail path, not
/// the never-register early return. The RECONNECTING
/// transport-availability gate is the deterministic failure trigger (no
/// oversized-keyexpr fragility).
#[cfg(feature = "liveliness-subscriber")]
#[test]
fn declare_liveliness_subscriber_rolls_back_slot_on_wire_emit_failure() {
    let (session, driver) = build_session();
    // Flip the pub transport-availability flag off so the next wire emit
    // returns Err(TransportUnavailable) at the F2 gate, before any encode
    // or driver write.
    *session.actions().link.transport_available.lock().unwrap() = false;
    let result = session.declare_liveliness_subscriber(
        "live/**",
        LivelinessSubscriberOptions::default(),
        |_| {},
    );
    assert!(result.is_err(), "wire-emit failure must surface as Err");
    assert_eq!(
        session
            .observer()
            .lock()
            .unwrap()
            .liveliness_subscribers
            .slot_count(),
        0,
        "a failed declare must leave NO orphan slot (Finding B rollback)",
    );
    assert_eq!(driver.frame_count(), 0, "gated emit leaves no wire bytes");
}

/// R311ll (Finding B) — the `liveliness_get` rollback is unregister-only
/// (a get correlates by FRESH interest_id, so no reply can stage in the
/// register->send window). A failed wire emit must still drop the pending
/// entry, else it leaks — or a deadline'd entry fires a spurious sweep
/// `on_final` for a get the caller never received a success from.
#[cfg(feature = "liveliness-get")]
#[test]
fn liveliness_get_rolls_back_pending_on_wire_emit_failure() {
    let (session, driver) = build_session();
    // liveliness_get enforces the Established gate; satisfy it, THEN fail
    // the emit at the transport-availability gate.
    mark_session_established(&session);
    *session.actions().link.transport_available.lock().unwrap() = false;
    let result = session.liveliness_get("live/**", LivelinessGetOptions::default(), |_| {}, |_| {});
    assert!(result.is_err(), "wire-emit failure must surface as Err");
    assert_eq!(
        session.observer().lock().unwrap().liveliness_gets.len(),
        0,
        "a failed get must leave NO orphan pending entry (Finding B)",
    );
    assert_eq!(driver.frame_count(), 0, "gated emit leaves no wire bytes");
}

/// R311ln (Finding B sibling) — a wire-emit FAILURE on `Session::query`
/// must roll the pending entry back, not leave it as a deadline-sweep
/// orphan firing `on_final` for a query the caller got an `Err` from.
/// R311ln reordered the wire emit BEFORE the loopback fan (zenoh-pico
/// `_z_query` parity), so a failed emit takes the unregister-only
/// rollback path with no loopback delivered — the rid is FRESH so no
/// solicited reply can correlate before the send and `unregister`
/// alone drops the sink + its deferred cell. The transport-availability
/// gate is the deterministic failure trigger (no oversized-keyexpr
/// fragility); `Locality::Any` (the default) routes the wire branch so
/// the emit is attempted.
#[cfg(feature = "query-get")]
#[test]
fn query_rolls_back_pending_on_wire_emit_failure() {
    let (session, driver) = build_session();
    *session.actions().link.transport_available.lock().unwrap() = false;
    let result = session.query("home/temp", QueryOptions::get(), |_| {}, |_| {});
    assert!(result.is_err(), "wire-emit failure must surface as Err");
    assert_eq!(
        session.observer().lock().unwrap().replies.len(),
        0,
        "a failed query must leave NO orphan pending entry (Finding B rollback)",
    );
    assert_eq!(driver.frame_count(), 0, "gated emit leaves no wire bytes");
}

/// R311ln (Finding B sibling) — same unregister-only rollback for the
/// aliased z_get surface. `mapping_id = 1` is the caller-asserted alias
/// form (non-zero); the wire branch routes by (mapping_id,
/// inline_suffix) so the gated emit fails before any loopback fan, and
/// the pending entry rolls back with no orphan.
#[cfg(feature = "query-get")]
#[test]
fn query_aliased_rolls_back_pending_on_wire_emit_failure() {
    let (session, driver) = build_session();
    *session.actions().link.transport_available.lock().unwrap() = false;
    let result = session.query_aliased(1, None, "home/temp", QueryOptions::get(), |_| {}, |_| {});
    assert!(result.is_err(), "wire-emit failure must surface as Err");
    assert_eq!(
        session.observer().lock().unwrap().replies.len(),
        0,
        "a failed aliased query must leave NO orphan pending entry (Finding B)",
    );
    assert_eq!(driver.frame_count(), 0, "gated emit leaves no wire bytes");
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "liveliness-subscriber"
))]
#[test]
fn declare_liveliness_subscriber_aliased_wire_frame_uses_alias_form() {
    // Aliased declare emits the bandwidth-efficient alias-form
    // wire (Interest with WireexprLocal { id=mapping_id,
    // suffix }), matching zenoh-pico's
    // _z_n_interest_encode behaviour when the caller hands a
    // previously-declared keyexpr to z_liveliness_declare_subscriber.
    use crate::session_glue::build_interest_liveliness_subscriber;
    let (session, driver) = build_session();
    // Install the keyexpr mapping (7 -> "liveliness/dev7"); first
    // wire frame is this Declare(DeclKexpr).
    session
        .actions()
        .send_declare_keyexpr(7, "liveliness/dev7")
        .expect("hardcoded canonical literal keyexpr");
    mark_session_established(&session);
    let baseline_frames = driver.frame_count();

    let _sub = session
        .declare_liveliness_subscriber_aliased(
            7,
            Some("/sensor"),
            LivelinessSubscriberOptions::default(),
            |_| {},
        )
        .expect("declared mapping resolves");

    assert_eq!(
        driver.frame_count(),
        baseline_frames + 1,
        "aliased declare emits exactly one Interest frame",
    );
    let expected = build_interest_liveliness_subscriber(
        /*interest_id=*/ 0,
        /*history=*/ false,
        /*mapping_id=*/ 7,
        Some("/sensor"),
    )
    .unwrap()
    .try_as_borrowed()
    .expect("test: <=N exts by construction")
    .encode_to_vec();
    let interest_frame = driver.frame_bytes(baseline_frames);
    assert!(
        interest_frame
            .windows(expected.len())
            .any(|w| w == expected),
        "wire frame must carry alias-form Interest bytes (mapping_id=7, suffix=/sensor)",
    );
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "liveliness-subscriber"
))]
#[test]
fn declare_liveliness_subscriber_aliased_survives_mapping_retract_after_declare() {
    // Mapping resolved at declare time; later send_undeclare_kexpr
    // must not affect the already-registered slot (R245 one-shot
    // resolution contract). The slot still holds the resolved
    // literal, matching is unaffected.
    let (session, _driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "liveliness/dev7")
        .expect("hardcoded canonical literal keyexpr");
    mark_session_established(&session);
    let sub = session
        .declare_liveliness_subscriber_aliased(
            7,
            None,
            LivelinessSubscriberOptions::default(),
            |_| {},
        )
        .expect("declared mapping resolves");
    let interest_id = sub.interest_id();

    // Retract the mapping.
    session.actions().send_undeclare_kexpr(7);

    // Slot still keyed against the resolved literal.
    assert_eq!(
        session
            .observer()
            .lock()
            .unwrap()
            .liveliness_subscribers
            .keyexpr(interest_id),
        Some("liveliness/dev7"),
        "slot survives mapping retract — resolution is one-shot at declare time",
    );
}

// ── R283 Established gate — pre-Established declines, ordering
// rule (UnknownMapping precedes NotEstablished), and predicate
// behavior. ────────────────────────────────────────────────────

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-keyexpr",
    feature = "liveliness-subscriber"
))]
#[test]
fn declare_liveliness_subscriber_aliased_pre_established_returns_err_without_wire_emit() {
    // Session-FSM has not yet entered Established. The Interest
    // would be emitted into a mid-handshake session; the peer's
    // remote-interests table is empty so the frame would be
    // silently discarded. R283 surfaces the bug at the API
    // boundary instead.
    let (session, driver) = build_session();
    session
        .actions()
        .send_declare_keyexpr(7, "liveliness/dev7")
        .expect("hardcoded canonical literal keyexpr");
    let baseline_frames = driver.frame_count();
    // NOTE: NO mark_session_established(&session) — that's the
    // condition under test.
    let err = session.declare_liveliness_subscriber_aliased(
        7,
        None,
        LivelinessSubscriberOptions::default(),
        |_| {},
    );
    assert!(
        matches!(err, Err(LivelinessSubscriberAliasError::NotEstablished)),
        "expected Err(NotEstablished) when session is mid-handshake",
    );
    assert_eq!(
        driver.frame_count(),
        baseline_frames,
        "no wire emit on pre-Established early-return path",
    );
    assert_eq!(
        session
            .observer()
            .lock()
            .unwrap()
            .liveliness_subscribers
            .slot_count(),
        0,
        "no slot registered when the Established gate refuses the declare",
    );
}

#[cfg(feature = "liveliness-subscriber")]
#[test]
fn declare_liveliness_subscriber_aliased_unknown_mapping_takes_precedence_over_not_established() {
    // Pin the variant ordering: when the session is pre-Established
    // AND the mapping is unknown, the caller sees UnknownMapping
    // (the bug-class error) — not NotEstablished (the transient
    // state). Retrying post-Established with the same bad mapping
    // would still fail; surfacing UnknownMapping first short-
    // circuits the futile retry loop.
    let (session, driver) = build_session();
    // No send_declare_keyexpr — mapping 99 is genuinely unknown.
    // No mark_session_established — Established is also false.
    let err = session.declare_liveliness_subscriber_aliased(
        99,
        None,
        LivelinessSubscriberOptions::default(),
        |_| {},
    );
    assert!(
        matches!(err, Err(LivelinessSubscriberAliasError::UnknownMapping(99))),
        "unknown mapping must precede the NotEstablished gate",
    );
    assert_eq!(driver.frame_count(), 0, "no wire emit");
}

#[test]
fn is_established_predicate_flips_after_record_established_at() {
    // The Session::is_established proxy reads the same field the
    // record_established_at Lua action sets at Established.onentry.
    // A freshly-built session is mid-handshake (established_at =
    // None); the test fixture flips the field to verify the
    // predicate tracks it.
    let (session, _driver) = build_session();
    assert!(
        !session.is_established(),
        "freshly-built session is pre-Established (no record_established_at fired)",
    );
    assert!(
        !session.actions().is_established(),
        "Session::is_established proxy reads the same source",
    );
    mark_session_established(&session);
    assert!(
        session.is_established(),
        "post record_established_at, is_established() is true",
    );
    assert!(
        session.actions().is_established(),
        "actions-layer predicate flips in lockstep",
    );
}

#[test]
fn liveliness_subscriber_alias_error_display_message_hints_remediation() {
    // R282 UnknownMapping variant.
    let err = LivelinessSubscriberAliasError::UnknownMapping(42);
    let msg = format!("{err}");
    assert!(msg.contains("42"));
    assert!(msg.contains("send_declare_keyexpr"));

    // R283 NotEstablished variant.
    let err = LivelinessSubscriberAliasError::NotEstablished;
    let msg = format!("{err}");
    assert!(msg.contains("not yet Established"));
    assert!(msg.contains("is_established"));
}

#[cfg(feature = "liveliness-token")]
#[test]
fn liveliness_token_id_counter_independent_of_request_id() {
    // Token id space is a separate AtomicU64 from the request id
    // counter (R239) — declaring a token before any query must
    // still start the token counter at 0 regardless of how many
    // request ids were burned, and vice versa. This pins the
    // independent-counter invariant documented on
    // SessionLinkActions::next_outbound_token_id.
    let (session, _driver) = build_session();
    // Burn three request ids first.
    let r0 = session.actions().alloc_next_request_id();
    let r1 = session.actions().alloc_next_request_id();
    let r2 = session.actions().alloc_next_request_id();
    assert_eq!((r0, r1, r2), (0, 1, 2));
    // Token allocation still starts from 0.
    let t = session
        .declare_token("liveliness/x", LivelinessOptions::default())
        .expect("hardcoded canonical literal keyexpr");
    assert_eq!(
        t.id(),
        0,
        "token id counter independent from request id counter"
    );
    std::mem::forget(t);
}

// ── R311kh Publisher/Querier::declare_matching_listener ──

/// The publisher listener fires on transitions only: silent at
/// registration, `true` when a matching remote subscriber declares,
/// `false` when it undeclares, silent on a non-matching declare, and
/// silent after `undeclare()` — driven through the production
/// `dispatch_declare` path the drive loop runs. R311kz — each dispatch
/// is paired with `drain_deferred_fires()`, the production drive-loop
/// shape (the registry sink only stages; the drain runs the callback
/// outside the observer lock).
#[cfg(all(feature = "session-matching", feature = "declare-subscriber"))]
#[test]
fn publisher_matching_listener_fires_on_transitions_only() {
    use hashbrown::HashMap;
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();
    let pubr = session.declare_publisher("home/temp", PublishOptions::put());
    let log: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
    let log_cb = log.clone();
    let listener = pubr
        .declare_matching_listener(move |s| log_cb.lock().unwrap().push(s.matching))
        .expect("session-matching is on in this lane");
    assert!(
        log.lock().unwrap().is_empty(),
        "registration on a session with NO matching subscriber is silent \
         (pico fires the `true` arm only)"
    );

    let dispatch = |body: &wz_codecs::declare::DeclareOwnedVariant| {
        session
            .observer()
            .lock()
            .unwrap()
            .remote_subscribers
            .dispatch_declare(body, &HashMap::new());
        // R311kz — observer lock dropped; run the staged fires.
        session.drain_deferred_fires();
    };

    dispatch(&make_decl_subscriber(1, "garage/door"));
    assert!(
        log.lock().unwrap().is_empty(),
        "non-matching remote subscriber is silent"
    );

    dispatch(&make_decl_subscriber(2, "home/temp"));
    assert_eq!(*log.lock().unwrap(), vec![true], "flip false -> true");
    assert_eq!(
        pubr.get_matching_status(),
        MatchingStatus { matching: true },
        "poll agrees with the callback verdict"
    );

    dispatch(&make_undecl_subscriber(2));
    assert_eq!(
        *log.lock().unwrap(),
        vec![true, false],
        "flip true -> false"
    );

    assert!(listener.undeclare(), "undeclare removes the watch");
    dispatch(&make_decl_subscriber(3, "home/temp"));
    assert_eq!(
        *log.lock().unwrap(),
        vec![true, false],
        "no fire after undeclare"
    );
}

/// Registering a listener when a matching remote subscriber is ALREADY
/// declared DELIVERS `true` before the call returns — pico's
/// `_z_write_filter_ctx_add_callback` fire-before-insert
/// (`vendor/zenoh-pico/src/net/filtering.c:341-357`).
///
/// This is the SESSION-tier half of the fix and it is a separate test on
/// purpose. `MatchingWatchList::register`'s own unit test proves the registry
/// FIRES; it cannot prove the application is TOLD, because the Session tier
/// installs a deferred sink that only STAGES onto `session.fires`. Between the
/// two lies exactly the seam that has bitten this tree before: a stage that
/// nothing drains reaches the application as silence, and reads as "the
/// feature does not work" while every registry test stays green. So the
/// assertion here is made WITHOUT any `dispatch` / `drain_deferred_fires` of
/// the test's own — if `declare_matching_listener` did not drain on return,
/// the log would be empty at this point.
///
/// The ordering — subscriber declared FIRST, listener registered SECOND — is
/// what makes it the already-matching case, and it is the ordinary one for a
/// publisher joining an established session.
#[cfg(all(feature = "session-matching", feature = "declare-subscriber"))]
#[test]
fn publisher_matching_listener_delivers_true_at_registration_when_already_matching() {
    use hashbrown::HashMap;
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();

    // A matching remote subscriber declares BEFORE any listener exists.
    session
        .observer()
        .lock()
        .unwrap()
        .remote_subscribers
        .dispatch_declare(&make_decl_subscriber(7, "home/temp"), &HashMap::new());
    session.drain_deferred_fires();

    let pubr = session.declare_publisher("home/temp", PublishOptions::put());
    assert_eq!(
        pubr.get_matching_status(),
        MatchingStatus { matching: true },
        "precondition: the publisher IS already matching"
    );

    let log: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
    let log_cb = log.clone();
    let listener = pubr
        .declare_matching_listener(move |s| log_cb.lock().unwrap().push(s.matching))
        .expect("session-matching is on in this lane");

    assert_eq!(
        *log.lock().unwrap(),
        vec![true],
        "an already-matching registration must have DELIVERED `true` by the \
         time it returned; an empty log here means the fire was staged and \
         never drained"
    );

    // And the watch is seeded, so the next flip is the real `false` — not a
    // duplicate `true`.
    session
        .observer()
        .lock()
        .unwrap()
        .remote_subscribers
        .dispatch_declare(&make_undecl_subscriber(7), &HashMap::new());
    session.drain_deferred_fires();
    assert_eq!(*log.lock().unwrap(), vec![true, false]);
    assert!(listener.undeclare());
}

/// Q-side mirror of the registration-fire: an already-matching QUERIER is told
/// at registration too, so the pub/query halves cannot drift apart.
#[cfg(all(feature = "session-matching", feature = "declare-queryable"))]
#[test]
fn querier_matching_listener_delivers_true_at_registration_when_already_matching() {
    use hashbrown::HashMap;
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();
    session
        .observer()
        .lock()
        .unwrap()
        .remote_queryables
        .dispatch_declare(&make_decl_queryable(9, "home/**"), &HashMap::new());
    session.drain_deferred_fires();

    let querier = session.declare_querier("home/temp", QueryOptions::get());
    assert_eq!(
        querier.get_matching_status(),
        MatchingStatus { matching: true },
        "precondition: the querier IS already matching"
    );

    let log: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
    let log_cb = log.clone();
    let listener = querier
        .declare_matching_listener(move |s| log_cb.lock().unwrap().push(s.matching))
        .expect("session-matching is on in this lane");
    assert_eq!(
        *log.lock().unwrap(),
        vec![true],
        "already-matching querier registration must DELIVER `true`"
    );
    assert!(listener.undeclare());
}

/// Q-side mirror: the querier listener watches the remote QUERYABLE set.
#[cfg(all(feature = "session-matching", feature = "declare-queryable"))]
#[test]
fn querier_matching_listener_fires_on_remote_queryable_transitions() {
    use hashbrown::HashMap;
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();
    let querier = session.declare_querier("home/temp", QueryOptions::get());
    let log: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
    let log_cb = log.clone();
    let listener = querier
        .declare_matching_listener(move |s| log_cb.lock().unwrap().push(s.matching))
        .expect("session-matching is on in this lane");

    session
        .observer()
        .lock()
        .unwrap()
        .remote_queryables
        .dispatch_declare(&make_decl_queryable(7, "home/temp"), &HashMap::new());
    session.drain_deferred_fires();
    assert_eq!(*log.lock().unwrap(), vec![true]);

    session
        .observer()
        .lock()
        .unwrap()
        .remote_queryables
        .dispatch_declare(&make_undecl_queryable(7), &HashMap::new());
    session.drain_deferred_fires();
    assert_eq!(*log.lock().unwrap(), vec![true, false]);

    assert!(listener.undeclare());
}

// ── R311y797 — the WATCH must answer what the POLL answers ────────────
//
// These live at the session tier deliberately, and R311y788's own damage
// probe is the reason: a registry-only test cannot see the delivery seam
// (removing the deferred-fire drain left all four registry unit tests
// green and reddened only the session-tier one).

/// A LOCAL queryable declared after the listener flips the watch. Before
/// this round the querier's watch stood on the remote registry alone, so
/// declaring a queryable on the same session fired nothing at all.
#[cfg(all(feature = "session-matching", feature = "query-queryable"))]
#[test]
fn querier_matching_listener_fires_when_a_local_queryable_is_declared() {
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();
    let querier = session.declare_querier("home/temp", QueryOptions::get());
    let log: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
    let log_cb = log.clone();
    let listener = querier
        .declare_matching_listener(move |s| log_cb.lock().unwrap().push(s.matching))
        .expect("session-matching is on in this lane");
    assert!(
        log.lock().unwrap().is_empty(),
        "registration on a session with NO queryable anywhere is silent"
    );

    let queryable = session
        .declare_queryable("home/temp", QueryableOptions::default(), |_q, _r| {})
        .expect("query-queryable is on in this lane");
    session.drain_deferred_fires();
    assert_eq!(
        *log.lock().unwrap(),
        vec![true],
        "a queryable on THIS session flips the watch, exactly as it flips \
         the poll"
    );

    drop(queryable);
    session.drain_deferred_fires();
    assert_eq!(
        *log.lock().unwrap(),
        vec![true, false],
        "and its undeclare flips it back"
    );
    assert!(listener.undeclare());
}

/// Registration SEEDS from both halves, so a listener created while a
/// local queryable already answers fires `true` immediately — the same
/// verdict the poll reports at that instant. A seed that read only the
/// remote registry would stay silent here and then disagree with the poll
/// for the life of the listener.
#[cfg(all(feature = "session-matching", feature = "query-queryable"))]
#[test]
fn querier_matching_listener_registration_seeds_from_the_local_half_too() {
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();
    let _q = session
        .declare_queryable("home/temp", QueryableOptions::default(), |_q, _r| {})
        .expect("query-queryable is on in this lane");
    let querier = session.declare_querier("home/temp", QueryOptions::get());
    assert_eq!(
        querier.get_matching_status(),
        MatchingStatus { matching: true },
        "precondition: the poll already says true"
    );

    let log: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
    let log_cb = log.clone();
    let listener = querier
        .declare_matching_listener(move |s| log_cb.lock().unwrap().push(s.matching))
        .expect("session-matching is on in this lane");
    assert_eq!(
        *log.lock().unwrap(),
        vec![true],
        "an already-matching registration must DELIVER `true`, and the \
         local queryable is the only thing making it match"
    );
    assert!(listener.undeclare());
}

/// The watch keeps applying the querier's TARGET, not just its keyexpr.
/// Registered by an `AllComplete` querier, it stays silent while only an
/// INCOMPLETE local queryable exists and fires when a complete one
/// arrives — the flip a keyexpr-only watch key would have delivered on
/// the first declaration.
#[cfg(all(
    feature = "session-matching",
    feature = "query-queryable",
    feature = "query-target"
))]
#[test]
fn querier_matching_listener_keeps_applying_the_all_complete_target() {
    use std::sync::{Arc, Mutex};
    use wz_session_core::query_mode::QueryTarget;

    let (session, _driver) = build_session();
    let querier = session.declare_querier(
        "home/temp",
        QueryOptions::get().with_target(QueryTarget::AllComplete),
    );
    let log: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
    let log_cb = log.clone();
    let listener = querier
        .declare_matching_listener(move |s| log_cb.lock().unwrap().push(s.matching))
        .expect("session-matching is on in this lane");

    let incomplete = session
        .declare_queryable(
            "home/temp",
            QueryableOptions::default().with_complete(false),
            |_q, _r| {},
        )
        .expect("query-queryable is on in this lane");
    session.drain_deferred_fires();
    assert!(
        log.lock().unwrap().is_empty(),
        "an incomplete queryable does not satisfy an AllComplete watch"
    );
    drop(incomplete);
    session.drain_deferred_fires();

    let _complete = session
        .declare_queryable(
            "home/temp",
            QueryableOptions::default().with_complete(true),
            |_q, _r| {},
        )
        .expect("query-queryable is on in this lane");
    session.drain_deferred_fires();
    assert_eq!(
        *log.lock().unwrap(),
        vec![true],
        "the complete queryable flips it exactly once"
    );
    assert!(listener.undeclare());
}

/// The SESSION-LOCAL half reaches the watch on the PRODUCTION INBOUND
/// path, not only at registration and on local declares. A peer's
/// UndeclQueryable arriving through the observer fan must not flip a
/// watch that a session-local queryable is holding `true`.
///
/// Driven through `Session::dispatch_iteration_event` deliberately: the
/// registry's own `dispatch_declare` passes a `false` local half by
/// contract, so a test that used it would prove nothing about the fan —
/// and the fan is the only thing that runs in production.
#[cfg(all(
    feature = "session-matching",
    feature = "query-queryable",
    feature = "declare-queryable"
))]
#[test]
fn an_inbound_peer_undeclare_does_not_flip_a_watch_a_local_queryable_holds() {
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();
    let _local = session
        .declare_queryable("home/temp", QueryableOptions::default(), |_q, _r| {})
        .expect("query-queryable is on in this lane");
    let querier = session.declare_querier("home/temp", QueryOptions::get());
    let log: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
    let log_cb = log.clone();
    let listener = querier
        .declare_matching_listener(move |s| log_cb.lock().unwrap().push(s.matching))
        .expect("session-matching is on in this lane");
    assert_eq!(
        *log.lock().unwrap(),
        vec![true],
        "the local queryable already answers, so registration fires true"
    );

    let fan = |body: wz_codecs::declare::DeclareOwnedVariant| {
        let declare = wz_codecs::declare::DeclareOwned {
            header: 0,
            interest_id: None,
            extensions: None,
            body,
        };
        let outcome = wz_session_core::driver_loop::DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![wz_session_core::network_message::NetworkMessage::Declare(
                Box::new(declare),
            )],
            has_ext: false,
            extensions: Vec::new(),
        };
        session.dispatch_iteration_event(crate::session_glue::IterationEvent::Poll(&outcome));
    };

    fan(make_decl_queryable(50, "home/temp"));
    fan(make_undecl_queryable(50));
    assert_eq!(
        *log.lock().unwrap(),
        vec![true],
        "the peer came and went, but the LOCAL queryable still answers — \
         a fan that dropped the local half would have fired `false` here"
    );

    drop(_local);
    session.drain_deferred_fires();
    assert_eq!(
        *log.lock().unwrap(),
        vec![true, false],
        "only when the local half goes too does the verdict flip"
    );
    assert!(listener.undeclare());
}

/// R311y797 — the PUBLISHER-plane defect this round found while building
/// the querier twin: R311y788 gated the poll on the publisher's
/// `allowed_destination` but the WATCH stored only a keyexpr, so every
/// re-evaluation answered as if the locality were `Any`.
///
/// A `Locality::SessionLocal` publisher polls `false` on a purely remote
/// subscriber; its listener must agree. The disagreement is what this
/// pins, so the assertion is on BOTH surfaces at the same instant.
#[cfg(all(feature = "session-matching", feature = "declare-subscriber"))]
#[test]
fn a_session_local_publishers_watch_agrees_with_its_poll_about_a_peer() {
    use hashbrown::HashMap;
    use std::sync::{Arc, Mutex};
    use wz_session_core::locality::Locality;

    let (session, _driver) = build_session();
    let pubr = session.declare_publisher(
        "home/temp",
        PublishOptions::put().with_locality(Locality::SessionLocal),
    );
    let log: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
    let log_cb = log.clone();
    let listener = pubr
        .declare_matching_listener(move |s| log_cb.lock().unwrap().push(s.matching))
        .expect("session-matching is on in this lane");

    session
        .observer()
        .lock()
        .unwrap()
        .remote_subscribers
        .dispatch_declare(&make_decl_subscriber(97, "home/temp"), &HashMap::new());
    session.drain_deferred_fires();

    assert_eq!(
        pubr.get_matching_status(),
        MatchingStatus { matching: false },
        "a SessionLocal publisher never reaches a peer, so the poll is false"
    );
    assert!(
        log.lock().unwrap().is_empty(),
        "and the WATCH must say the same thing — before this round it \
         fired `true` here while the poll said false"
    );
    assert!(listener.undeclare());
}

/// The anti-vacuity twin of the test above: the identical fixture with a
/// `Locality::Any` publisher DOES fire, so the silence there is the
/// locality gate and not a broken dispatch.
#[cfg(all(feature = "session-matching", feature = "declare-subscriber"))]
#[test]
fn an_any_locality_publishers_watch_still_fires_on_the_same_peer() {
    use hashbrown::HashMap;
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();
    let pubr = session.declare_publisher("home/temp", PublishOptions::put());
    let log: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
    let log_cb = log.clone();
    let listener = pubr
        .declare_matching_listener(move |s| log_cb.lock().unwrap().push(s.matching))
        .expect("session-matching is on in this lane");

    session
        .observer()
        .lock()
        .unwrap()
        .remote_subscribers
        .dispatch_declare(&make_decl_subscriber(98, "home/temp"), &HashMap::new());
    session.drain_deferred_fires();

    assert_eq!(
        pubr.get_matching_status(),
        MatchingStatus { matching: true }
    );
    assert_eq!(*log.lock().unwrap(), vec![true]);
    assert!(listener.undeclare());
}

// ── R311y771 the matching listener ASKS for what it watches ──

/// R311y771 THE DISCRIMINATOR at the session tier. A publisher's matching
/// listener now puts an `Interest` on the wire asking the peer for its
/// SUBSCRIBER declarations, because a zenoh router propagates a subscriber
/// declaration to a face only when that face's own `remote_interests` carries
/// `options.subscribers()` and matches the resource
/// (`hat/router/pubsub.rs:120-125`). Before this round wz emitted only TOKEN
/// interests, so `RemoteSubscriberRegistry` — and every matching listener
/// standing on it — stayed permanently empty against zenohd, silently.
///
/// Asserted on the BYTES THAT LEFT, not on a builder call: the expectation is
/// encoded independently and searched for inside the recorded transport
/// frame. And the TOKEN form of the same keyexpr is asserted ABSENT in the
/// same test — without that, an emit that kept the old `TO` byte would still
/// satisfy "one interest frame was sent".
#[cfg(all(
    feature = "session-matching",
    feature = "declare-subscriber",
    feature = "declare-interest",
    feature = "codec-declare"
))]
#[test]
fn a_publisher_matching_listener_asks_the_peer_for_subscriber_declarations() {
    use wz_session_core::interest_build::{
        build_interest_liveliness_subscriber, build_interest_subscribers,
    };

    let (session, driver) = build_session();
    mark_session_established(&session);
    let baseline = driver.frame_count();

    let pubr = session.declare_publisher("home/temp", PublishOptions::put());
    let listener = pubr
        .declare_matching_listener(|_| {})
        .expect("session-matching + declare-interest are on in this lane");

    assert_eq!(
        driver.frame_count(),
        baseline + 1,
        "declaring the listener must emit exactly one frame -- the Interest",
    );
    let frame = driver.frame_bytes(baseline);

    // The id comes from the HANDLE, not a hardcoded 0: an emit that allocated
    // one id and reported another would still satisfy a literal expectation.
    let id = listener.interest_id();
    let wanted = build_interest_subscribers(
        id,
        /*current=*/ true,
        /*future=*/ true,
        /*mapping_id=*/ 0,
        Some("home/temp"),
    )
    .unwrap()
    .try_as_borrowed()
    .expect("test: <=N exts by construction")
    .encode_to_vec();
    assert!(
        frame.windows(wanted.len()).any(|w| w == wanted),
        "the emitted frame must carry a SUBSCRIBERS Interest for the \
         publisher's keyexpr; frame was {frame:02x?}",
    );

    // ANTI-VACUITY: the byte that matters is the KIND bit, so the token form
    // of the identical keyexpr and mode must NOT be what went out.
    let token_form = build_interest_liveliness_subscriber(
        id,
        /*history=*/ true,
        /*mapping_id=*/ 0,
        Some("home/temp"),
    )
    .unwrap()
    .try_as_borrowed()
    .expect("test: <=N exts by construction")
    .encode_to_vec();
    assert!(
        !frame.windows(token_form.len()).any(|w| w == token_form),
        "a TOKENS interest is what wz used to send and is not what a router \
         gates subscriber propagation on",
    );
    assert_eq!(
        driver.frame_reliability(baseline),
        Reliability::Reliable,
        "the Interest must precede the declarations it asks for, so it rides \
         the reliable channel like every other declaration-plane emit",
    );
}

/// The QUERYABLE-plane twin, and the anti-vacuity PAIR for the test above: a
/// third distinct kind bit, so an emit hardcoded to either of the other two
/// cannot satisfy both tests. Router gate: `hat/router/queries.rs:255-259`.
#[cfg(all(
    feature = "session-matching",
    feature = "declare-queryable",
    feature = "declare-interest",
    feature = "codec-declare"
))]
#[test]
fn a_querier_matching_listener_asks_the_peer_for_queryable_declarations() {
    use wz_session_core::interest_build::{build_interest_queryables, build_interest_subscribers};

    let (session, driver) = build_session();
    mark_session_established(&session);
    let baseline = driver.frame_count();

    let querier = session.declare_querier("demo/**", QueryOptions::default());
    let listener = querier
        .declare_matching_listener(|_| {})
        .expect("session-matching + declare-interest are on in this lane");

    assert_eq!(driver.frame_count(), baseline + 1);
    let frame = driver.frame_bytes(baseline);
    let id = listener.interest_id();

    let wanted = build_interest_queryables(id, true, true, 0, Some("demo/**"))
        .unwrap()
        .try_as_borrowed()
        .expect("test: <=N exts by construction")
        .encode_to_vec();
    assert!(
        frame.windows(wanted.len()).any(|w| w == wanted),
        "the emitted frame must carry a QUERYABLES Interest; frame was {frame:02x?}",
    );

    let subscriber_form = build_interest_subscribers(id, true, true, 0, Some("demo/**"))
        .unwrap()
        .try_as_borrowed()
        .expect("test: <=N exts by construction")
        .encode_to_vec();
    assert!(
        !frame
            .windows(subscriber_form.len())
            .any(|w| w == subscriber_form),
        "a querier must not ask for SUBSCRIBERS -- that would widen what the \
         router forwards to this face beyond what the watch reads",
    );
}

/// Undeclaring the listener RETRACTS the interest. Without this the peer keeps
/// streaming declarations into a registry no watch reads for the rest of the
/// session — the leak that is the whole reason the emit lives on the listener
/// (which has a lifecycle) rather than on `declare_publisher` (which has
/// none).
///
/// The Final is matched BY ID against the id the declare allocated, so a
/// retract that named some other interest would fail here rather than merely
/// producing "some second frame".
#[cfg(all(
    feature = "session-matching",
    feature = "declare-subscriber",
    feature = "declare-interest",
    feature = "codec-declare"
))]
#[test]
fn undeclaring_a_matching_listener_retracts_the_interest_it_declared() {
    use wz_session_core::interest_build::build_interest_final;

    let (session, driver) = build_session();
    mark_session_established(&session);
    let pubr = session.declare_publisher("home/temp", PublishOptions::put());
    let listener = pubr
        .declare_matching_listener(|_| {})
        .expect("session-matching + declare-interest are on in this lane");
    let declared_id = listener.interest_id();
    let after_declare = driver.frame_count();

    assert!(listener.undeclare(), "undeclare removes the watch");

    assert_eq!(
        driver.frame_count(),
        after_declare + 1,
        "undeclare must emit exactly one frame -- the Interest(Final)",
    );
    let expected = build_interest_final(declared_id)
        .try_as_borrowed()
        .expect("Final carries no exts")
        .encode_to_vec();
    let frame = driver.frame_bytes(after_declare);
    assert!(
        frame.windows(expected.len()).any(|w| w == expected),
        "the retract must name the id the declare allocated ({declared_id}); \
         frame was {frame:02x?}",
    );
}

/// TWO listeners on one session take TWO interest ids, and each retracts its
/// OWN. Pinned because the handle carries an id it did not itself allocate:
/// if the wire id were taken from the registry's watch-list slot instead of
/// `alloc_next_interest_id`, both listeners would collide on the peer's
/// interest table and the first undeclare would retract the second's stream.
#[cfg(all(
    feature = "session-matching",
    feature = "declare-subscriber",
    feature = "declare-queryable",
    feature = "declare-interest",
    feature = "codec-declare"
))]
#[test]
fn two_matching_listeners_take_two_interest_ids_and_retract_their_own() {
    use wz_session_core::interest_build::build_interest_final;

    let (session, driver) = build_session();
    mark_session_established(&session);

    let pubr = session.declare_publisher("home/temp", PublishOptions::put());
    let first = pubr
        .declare_matching_listener(|_| {})
        .expect("declare-interest is on in this lane");
    let querier = session.declare_querier("demo/**", QueryOptions::default());
    let second = querier
        .declare_matching_listener(|_| {})
        .expect("declare-interest is on in this lane");

    let (a, b) = (first.interest_id(), second.interest_id());
    assert_ne!(
        a, b,
        "each listener must hold its own wire interest id -- a shared id \
         means one undeclare kills the other's stream",
    );

    let before = driver.frame_count();
    assert!(second.undeclare());
    let retract = driver.frame_bytes(before);
    let expected_b = build_interest_final(b)
        .try_as_borrowed()
        .expect("Final carries no exts")
        .encode_to_vec();
    let expected_a = build_interest_final(a)
        .try_as_borrowed()
        .expect("Final carries no exts")
        .encode_to_vec();
    assert!(
        retract.windows(expected_b.len()).any(|w| w == expected_b),
        "the second listener's undeclare must retract ITS id ({b})",
    );
    assert!(
        !retract.windows(expected_a.len()).any(|w| w == expected_a),
        "and must not retract the first listener's id ({a}), which is still \
         watching",
    );
}

/// R311kz — the F-6 deferred-fire contract end-to-end: the callback
/// runs OUTSIDE the observer mutex, so it may re-enter observer-locking
/// session APIs. The callback here (1) polls `get_matching_status`
/// (an observer-locking consult — the R311kj self-deadlock reproducer),
/// (2) declares a SECOND matching listener from inside the first, and
/// (3) self-undeclares via its own handle. Pre-R311kz every one of
/// these deadlocked on the std observer mutex.
#[cfg(all(feature = "session-matching", feature = "declare-subscriber"))]
#[test]
fn matching_listener_callback_may_reenter_session_apis() {
    use hashbrown::HashMap;
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();
    let pubr = session.declare_publisher("home/temp", PublishOptions::put());

    // Self-handle slot: the callback needs its own MatchingListener to
    // self-undeclare (two-phase init, the handle exists only after
    // registration).
    type ListenerSlot = Arc<Mutex<Option<MatchingListener>>>;
    let slot: ListenerSlot = Arc::new(Mutex::new(None));
    let observed: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
    let inner_log: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));

    let slot_cb = slot.clone();
    let observed_cb = observed.clone();
    let inner_log_cb = inner_log.clone();
    let pubr_cb = pubr.clone();
    let listener = pubr
        .declare_matching_listener(move |s| {
            // (1) Observer-locking consult from inside the callback.
            let polled = pubr_cb.get_matching_status();
            observed_cb
                .lock()
                .unwrap()
                .push(polled.matching && s.matching);
            // (2) Register ANOTHER listener from inside the callback.
            let inner_log = inner_log_cb.clone();
            let inner = pubr_cb
                .declare_matching_listener(move |s2| {
                    inner_log.lock().unwrap().push(s2.matching);
                })
                .expect("re-entrant registration must succeed");
            // Dropping the handle leaves the watch installed (explicit
            // undeclare only — no Drop hook, the documented contract).
            drop(inner);
            // (3) Self-undeclare via the listener's own handle.
            if let Some(me) = slot_cb.lock().unwrap().take() {
                assert!(me.undeclare(), "self-undeclare succeeds");
            }
        })
        .expect("session-matching is on in this lane");
    *slot.lock().unwrap() = Some(listener);

    let dispatch = |body: &wz_codecs::declare::DeclareOwnedVariant| {
        session
            .observer()
            .lock()
            .unwrap()
            .remote_subscribers
            .dispatch_declare(body, &HashMap::new());
        session.drain_deferred_fires();
    };

    // Flip false -> true: the outer callback fires once, polls the
    // (already-updated) status, registers the inner listener, and
    // self-undeclares — all without deadlocking.
    dispatch(&make_decl_subscriber(2, "home/temp"));
    assert_eq!(
        *observed.lock().unwrap(),
        vec![true],
        "callback ran once and the in-callback poll agreed with the verdict"
    );

    // Flip true -> false: the outer listener self-undeclared, so only
    // the inner listener observes the flip. The inner log therefore reads
    // `[true, false]`, not `[false]`: the inner listener was registered
    // from inside the outer callback, i.e. at a moment when the verdict was
    // ALREADY `true`, and pico fires an already-matching registration
    // immediately (`src/net/filtering.c:341-357`). Its `true` is the
    // registration fire; the `false` is this flip. Before that parity fix
    // this assertion read `[false]` — the seeded-but-silent shape.
    //
    // This also witnesses the fire being DELIVERED from a NESTED drain: the
    // inner registration stages while the outer callback is itself running
    // out of `drain_deferred_fires`, and the drain that
    // `declare_matching_listener` performs on return is what delivers it.
    dispatch(&make_undecl_subscriber(2));
    assert_eq!(
        *observed.lock().unwrap(),
        vec![true],
        "self-undeclared outer listener never fires again"
    );
    assert_eq!(
        *inner_log.lock().unwrap(),
        vec![true, false],
        "the listener registered from inside a callback is live"
    );
}

/// R311g1 NEG — with `session-matching` off the method keeps its
/// signature and rejects typed (build-time choice observed as a runtime
/// reject, never a missing symbol). Runs in the C1j subset lanes whose
/// base omits session-matching.
#[cfg(all(not(feature = "session-matching"), feature = "declare-subscriber"))]
#[test]
fn publisher_matching_listener_rejects_typed_when_feature_off() {
    let (session, _driver) = build_session();
    let pubr = session.declare_publisher("home/temp", PublishOptions::put());
    assert!(
        matches!(
            pubr.declare_matching_listener(|_| {}),
            Err(MatchingListenerError::FeatureDisabled)
        ),
        "session-matching off must reject typed"
    );
}
// ── R311lc Session::declare_remote_*_listener (deferred decl events) ──

/// R311lc — the subscriber-plane decl listener delivers BOTH event
/// directions as owned [`DeclEvent`]s through the deferred-fire queue
/// (dispatch + drain, the production drive-loop shape), and
/// `undeclare()` removes both staging sinks from the registry (the
/// R311lb id-keyed currency) so later activity is silent.
#[cfg(feature = "declare-subscriber")]
#[test]
fn remote_subscriber_listener_delivers_decl_and_undecl_events() {
    use hashbrown::HashMap;
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();
    let baseline = {
        let obs = session.observer().lock().unwrap();
        (
            obs.remote_subscribers.on_decl_len(),
            obs.remote_subscribers.on_undecl_len(),
        )
    };
    let log: Arc<Mutex<Vec<DeclEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let log_cb = log.clone();
    let listener = session
        .declare_remote_subscriber_listener(move |e| log_cb.lock().unwrap().push(e))
        .expect("declare-subscriber is on in this lane");

    let dispatch = |body: &wz_codecs::declare::DeclareOwnedVariant| {
        session
            .observer()
            .lock()
            .unwrap()
            .remote_subscribers
            .dispatch_declare(body, &HashMap::new());
        session.drain_deferred_fires();
    };

    dispatch(&make_decl_subscriber(5, "home/temp"));
    dispatch(&make_undecl_subscriber(5));
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            DeclEvent::Declared {
                id: 5,
                keyexpr: "home/temp".to_string()
            },
            DeclEvent::Undeclared { id: 5 },
        ],
        "both directions arrive as owned events in wire order"
    );

    assert!(listener.undeclare(), "undeclare removes both observers");
    {
        let obs = session.observer().lock().unwrap();
        assert_eq!(
            (
                obs.remote_subscribers.on_decl_len(),
                obs.remote_subscribers.on_undecl_len(),
            ),
            baseline,
            "registry observer lists back to baseline (no leaked sinks)"
        );
    }
    dispatch(&make_decl_subscriber(6, "home/temp"));
    assert_eq!(log.lock().unwrap().len(), 2, "no fire after undeclare");
}

/// R311lc — queryable-plane mirror over `remote_queryables`.
#[cfg(feature = "declare-queryable")]
#[test]
fn remote_queryable_listener_delivers_decl_and_undecl_events() {
    use hashbrown::HashMap;
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();
    let log: Arc<Mutex<Vec<DeclEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let log_cb = log.clone();
    let listener = session
        .declare_remote_queryable_listener(move |e| log_cb.lock().unwrap().push(e))
        .expect("declare-queryable is on in this lane");

    session
        .observer()
        .lock()
        .unwrap()
        .remote_queryables
        .dispatch_declare(&make_decl_queryable(7, "home/temp"), &HashMap::new());
    session
        .observer()
        .lock()
        .unwrap()
        .remote_queryables
        .dispatch_declare(&make_undecl_queryable(7), &HashMap::new());
    // One drain runs both staged fires in stage order.
    session.drain_deferred_fires();
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            DeclEvent::Declared {
                id: 7,
                keyexpr: "home/temp".to_string()
            },
            DeclEvent::Undeclared { id: 7 },
        ]
    );
    assert!(listener.undeclare());
}

/// R290-style local DeclToken / UndeclToken constructors for the
/// R311lc token-plane listener test (the wz-session-core-test-support
/// builders are not a dev-dep here per R311ds).
#[cfg(feature = "liveliness-token")]
fn make_decl_token(id: u64, keyexpr_literal: &str) -> wz_codecs::declare::DeclareOwnedVariant {
    use wz_codecs::decl_token::DeclToken;
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_local::WireexprLocal;
    let suffix_len = Some(keyexpr_literal.len() as u64);
    let keyexpr = Wireexpr {
        body: WireexprVariant::WireexprLocal(WireexprLocal {
            id: 0,
            suffix_len,
            suffix: Some(keyexpr_literal),
        }),
    };
    wz_codecs::declare::DeclareVariant::CodecZenohDeclToken(DeclToken {
        id,
        keyexpr,
        ..DeclToken::default()
    })
    .try_into_owned()
    .unwrap()
}

#[cfg(feature = "liveliness-token")]
fn make_undecl_token(id: u64) -> wz_codecs::declare::DeclareOwnedVariant {
    use wz_codecs::undecl_token::UndeclToken;
    wz_codecs::declare::DeclareVariant::CodecZenohUndeclToken(UndeclToken {
        id,
        ..UndeclToken::default()
    })
    .try_into_owned()
    .unwrap()
}

/// R311lc — liveliness-token-plane mirror over the `liveliness`
/// (peer-token) registry.
#[cfg(feature = "liveliness-token")]
#[test]
fn remote_token_listener_delivers_decl_and_undecl_events() {
    use hashbrown::HashMap;
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();
    let log: Arc<Mutex<Vec<DeclEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let log_cb = log.clone();
    let listener = session
        .declare_remote_token_listener(move |e| log_cb.lock().unwrap().push(e))
        .expect("liveliness-token is on in this lane");

    session
        .observer()
        .lock()
        .unwrap()
        .liveliness
        .dispatch_declare(&make_decl_token(9, "liveliness/x"), &HashMap::new());
    session
        .observer()
        .lock()
        .unwrap()
        .liveliness
        .dispatch_declare(&make_undecl_token(9), &HashMap::new());
    session.drain_deferred_fires();
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            DeclEvent::Declared {
                id: 9,
                keyexpr: "liveliness/x".to_string()
            },
            DeclEvent::Undeclared { id: 9 },
        ]
    );
    assert!(listener.undeclare());
}

/// R311lc — the F-6 deferred-fire contract on the decl plane: the
/// callback runs OUTSIDE the observer mutex, so it may (1) consult an
/// observer-locking session API, (2) register ANOTHER decl listener,
/// and (3) self-undeclare via its own handle — each a deadlock under
/// the R311kj inline constraint the raw registry sinks carry.
#[cfg(feature = "declare-subscriber")]
#[test]
fn decl_listener_callback_may_reenter_session_apis() {
    use hashbrown::HashMap;
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();

    type ListenerSlot = Arc<Mutex<Option<DeclListener>>>;
    let slot: ListenerSlot = Arc::new(Mutex::new(None));
    let outer_log: Arc<Mutex<Vec<DeclEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let inner_log: Arc<Mutex<Vec<DeclEvent>>> = Arc::new(Mutex::new(Vec::new()));

    let slot_cb = slot.clone();
    let outer_log_cb = outer_log.clone();
    let inner_log_cb = inner_log.clone();
    let session_cb = session.clone();
    let listener = session
        .declare_remote_subscriber_listener(move |event| {
            // (1) Observer-locking consult from inside the callback.
            let declared = session_cb
                .observer()
                .lock()
                .unwrap()
                .remote_subscribers
                .declared_count();
            assert_eq!(declared, 1, "in-callback registry consult sees the decl");
            outer_log_cb.lock().unwrap().push(event);
            // (2) Register ANOTHER listener from inside the callback.
            let inner_log = inner_log_cb.clone();
            let inner = session_cb
                .declare_remote_subscriber_listener(move |e2| {
                    inner_log.lock().unwrap().push(e2);
                })
                .expect("re-entrant registration must succeed");
            drop(inner); // dropped handle leaves the observers installed
                         // (3) Self-undeclare via the listener's own handle.
            if let Some(me) = slot_cb.lock().unwrap().take() {
                assert!(me.undeclare(), "self-undeclare succeeds");
            }
        })
        .expect("declare-subscriber is on in this lane");
    *slot.lock().unwrap() = Some(listener);

    let dispatch = |body: &wz_codecs::declare::DeclareOwnedVariant| {
        session
            .observer()
            .lock()
            .unwrap()
            .remote_subscribers
            .dispatch_declare(body, &HashMap::new());
        session.drain_deferred_fires();
    };

    dispatch(&make_decl_subscriber(2, "home/temp"));
    assert_eq!(
        *outer_log.lock().unwrap(),
        vec![DeclEvent::Declared {
            id: 2,
            keyexpr: "home/temp".to_string()
        }],
        "callback ran once without deadlocking"
    );

    // The outer listener self-undeclared; only the inner listener
    // (registered during the previous fire) observes the undeclare.
    dispatch(&make_undecl_subscriber(2));
    assert_eq!(
        outer_log.lock().unwrap().len(),
        1,
        "self-undeclared outer listener never fires again"
    );
    assert_eq!(
        *inner_log.lock().unwrap(),
        vec![DeclEvent::Undeclared { id: 2 }],
        "the listener registered from inside a callback is live"
    );
}

/// R311g1 NEG — with `declare-subscriber` off the subscriber-plane
/// surface keeps its signature and rejects typed.
#[cfg(not(feature = "declare-subscriber"))]
#[test]
fn remote_subscriber_listener_rejects_typed_when_feature_off() {
    let (session, _driver) = build_session();
    assert!(
        matches!(
            session.declare_remote_subscriber_listener(|_| {}),
            Err(DeclListenerError::FeatureDisabled)
        ),
        "declare-subscriber off must reject typed"
    );
}

/// R311y342 NEG — the queryable twin of the guard above. `decl_listener.rs`
/// holds two listeners whose OFF arms are character-for-character identical
/// (`let _ = callback; Err(DeclListenerError::FeatureDisabled)`), and only
/// the subscriber one was pinned. An unguarded typed-reject arm is exactly
/// the shape R311hw/R311hx names: a compile/footprint proof does NOT prove
/// the signature-stable surface BEHAVES when the feature is off.
#[cfg(not(feature = "declare-queryable"))]
#[test]
fn remote_queryable_listener_rejects_typed_when_feature_off() {
    let (session, _driver) = build_session();
    assert!(
        matches!(
            session.declare_remote_queryable_listener(|_| {}),
            Err(DeclListenerError::FeatureDisabled)
        ),
        "declare-queryable off must reject typed"
    );
}

// ── R311y232 direct multicast Session publish QoS band ──

/// R311y232 (transport-qos ACTIVATION) — the direct multicast-Session send seam
/// threads the app QoS band onto the enqueued
/// [`MulticastTxItem`](wz_session_core::multicast_tx::MulticastTxItem): `publish_qos`
/// stamps the caller's chosen priority (closing the WHOLE-SESSION finding — the
/// multicast arm formerly hard-coded `Priority::DEFAULT`, so a direct prioritized
/// publish over a QoS group egressed at DEFAULT), while the base `publish` stays
/// DEFAULT (byte-identical to the pre-QoS single conduit). The group-level
/// `is_qos` CLAMP that turns a non-DEFAULT band into the per-priority conduit +
/// frame `ext_qos` is proven at the dispatch level by
/// `wz_session_core::multicast_tx::qos_emit_tests`
/// (`qos_group_emits_frame_ext_qos_and_mints_on_the_priority_conduit` /
/// `non_qos_group_clamps_to_default_no_ext_qos`) — those need
/// `transport-qos + codec-push`, so the run-ci C1bc lane RUNS them (the C1bb
/// transport-qos test lane omits `codec-push` and cfg's them out). THIS witness
/// pins the `Session` -> tx-item hand-off the finding named, which those cannot see.
#[cfg(all(feature = "transport-multicast", feature = "codec-push"))]
#[test]
fn multicast_publish_qos_stamps_band_base_publish_stays_default() {
    use wz_session_core::multicast_tx::MulticastTxItem;
    use wz_session_core::qos::Priority;

    // The band accessor: exhaustive in every feature combo the test runs in — the
    // catch-all is cfg-gated to the codecs that add the reply-plane variants, so a
    // codec-push-only lane (where `Push` is the sole variant) has no unreachable
    // arm, and a lane with reply variants has a reachable one.
    let tx_band = |item: &MulticastTxItem| -> Priority {
        match item {
            MulticastTxItem::Push { priority, .. } => *priority,
            #[cfg(any(
                feature = "codec-response",
                feature = "codec-response-final",
                feature = "liveliness-token"
            ))]
            _ => panic!("expected a multicast Push tx item"),
        }
    };

    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let clock = Arc::new(TokioTime::new());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<MulticastTxItem>();
    let session: TokioMulticastSession = Session::new_multicast(observer, clock, tx);

    // `Remote` locality routes the codec-push wire leg only (no loopback subscriber
    // needed); the leg enqueues one `MulticastTxItem::Push` per publish.
    let remote = PublishOptions::put().with_locality(Locality::Remote);

    session
        .publish_qos(
            "home/temp",
            b"hot",
            remote.clone(),
            Priority::InteractiveHigh,
        )
        .expect("multicast publish_qos enqueues");
    assert_eq!(
        tx_band(&rx.try_recv().expect("publish_qos staged a tx item")),
        Priority::InteractiveHigh,
        "publish_qos must stamp the app band, not the pre-y232 hard-coded DEFAULT"
    );

    session
        .publish("home/temp", b"cold", remote)
        .expect("multicast publish enqueues");
    assert_eq!(
        tx_band(&rx.try_recv().expect("publish staged a tx item")),
        Priority::DEFAULT,
        "the base publish stays DEFAULT-band (byte-identical to the pre-QoS send)"
    );
}

/// R311y-item3 — the COMPOSED unification proof: the base `publish` (NOT
/// `publish_qos`) with `PublishOptions::with_priority` set drives the multicast
/// per-priority conduit band from the SINGLE `opts.qos` source. Pre-item3 the
/// base publish hard-coded `Priority::DEFAULT` regardless of `opts.qos`, so a
/// prioritized-but-observable publish egressed at DEFAULT while the app saw the
/// band — the exact split this closes. The multicast tx item exposes the band as
/// a struct field (unlike the unicast wire-byte-buried form), so this is the leg
/// where the `publish -> priority_band() -> tx band` chain is directly
/// observable. Needs `pubsub-qos` (with_priority) + `transport-multicast`
/// (the tx-item harness); the both-transports+`pubsub-priority` run-ci lane runs
/// it, reaching the gate through that alias. R311y314: this said the test
/// "needs pubsub-priority" while its own cfg below reads `pubsub-qos` -- the
/// alias is sufficient, never necessary.
#[cfg(all(
    feature = "transport-multicast",
    feature = "codec-push",
    feature = "pubsub-qos"
))]
#[test]
fn publish_with_priority_routes_multicast_conduit_band() {
    use wz_session_core::multicast_tx::MulticastTxItem;
    use wz_session_core::qos::Priority;

    let tx_band = |item: &MulticastTxItem| -> Priority {
        match item {
            MulticastTxItem::Push { priority, .. } => *priority,
            #[cfg(any(
                feature = "codec-response",
                feature = "codec-response-final",
                feature = "liveliness-token"
            ))]
            _ => panic!("expected a multicast Push tx item"),
        }
    };

    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let clock = Arc::new(TokioTime::new());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<MulticastTxItem>();
    let session: TokioMulticastSession = Session::new_multicast(observer, clock, tx);

    // Base `publish` with with_priority set -> the band flows from
    // `opts.qos.priority()` to the enqueued tx item (the item3 change).
    let hi = PublishOptions::put()
        .with_locality(Locality::Remote)
        .with_priority(Priority::InteractiveHigh);
    session
        .publish("home/temp", b"hot", hi)
        .expect("multicast publish enqueues");
    assert_eq!(
        tx_band(&rx.try_recv().expect("publish staged a tx item")),
        Priority::InteractiveHigh,
        "base publish routes the conduit band from opts.with_priority (item3 unification)",
    );

    // No with_priority -> DEFAULT band, byte-identical to the pre-QoS send.
    let plain = PublishOptions::put().with_locality(Locality::Remote);
    session
        .publish("home/temp", b"cold", plain)
        .expect("multicast publish enqueues");
    assert_eq!(
        tx_band(&rx.try_recv().expect("publish staged a tx item")),
        Priority::DEFAULT,
        "no with_priority -> DEFAULT band (unchanged base-publish contract)",
    );
}

// ── R311ld Session::dispatch_iteration_event (dispatch SSOT) ──

/// R311ld — the dispatch SSOT pairs the observer fan with the
/// deferred-fire drain in ONE call: a real drive-loop-shaped
/// `IterationEvent::Poll(FramePayload)` carrying a peer
/// `Declare(DeclSubscriber)` reaches both the registry (membership)
/// and a deferred decl listener (callback ran, NO manual
/// `drain_deferred_fires` anywhere in this test).
#[cfg(feature = "declare-subscriber")]
#[test]
fn dispatch_iteration_event_fans_and_drains_in_one_call() {
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();
    let log: Arc<Mutex<Vec<DeclEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let log_cb = log.clone();
    let _listener = session
        .declare_remote_subscriber_listener(move |e| log_cb.lock().unwrap().push(e))
        .expect("declare-subscriber is on in this lane");

    let declare = wz_codecs::declare::DeclareOwned {
        header: 0,
        interest_id: None,
        extensions: None,
        body: make_decl_subscriber(4, "home/temp"),
    };
    let outcome = wz_session_core::driver_loop::DriverLoopOutcome::FramePayload {
        priority: wz_session_core::qos::Priority::DEFAULT,
        reliable: true,
        sn: 0,
        messages: vec![wz_session_core::network_message::NetworkMessage::Declare(
            Box::new(declare),
        )],
        has_ext: false,
        extensions: Vec::new(),
    };
    session.dispatch_iteration_event(crate::session_glue::IterationEvent::Poll(&outcome));

    assert_eq!(
        *log.lock().unwrap(),
        vec![DeclEvent::Declared {
            id: 4,
            keyexpr: "home/temp".to_string()
        }],
        "one SSOT call fanned the declare AND drained the deferred fire"
    );
    assert_eq!(
        session
            .observer()
            .lock()
            .unwrap()
            .remote_subscribers
            .declared_count(),
        1,
        "registry membership updated by the same call"
    );
}

/// R311ld — the `_with` form runs its hook INSIDE the same lock scope
/// (the observer handed to it is the locked one) and still drains
/// afterwards, covering fires staged by the dispatch.
#[cfg(feature = "declare-subscriber")]
#[test]
fn dispatch_iteration_event_with_runs_hook_under_lock_then_drains() {
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();
    let log: Arc<Mutex<Vec<DeclEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let log_cb = log.clone();
    let _listener = session
        .declare_remote_subscriber_listener(move |e| log_cb.lock().unwrap().push(e))
        .expect("declare-subscriber is on in this lane");

    let declare = wz_codecs::declare::DeclareOwned {
        header: 0,
        interest_id: None,
        extensions: None,
        body: make_decl_subscriber(8, "home/temp"),
    };
    let outcome = wz_session_core::driver_loop::DriverLoopOutcome::FramePayload {
        priority: wz_session_core::qos::Priority::DEFAULT,
        reliable: true,
        sn: 0,
        messages: vec![wz_session_core::network_message::NetworkMessage::Declare(
            Box::new(declare),
        )],
        has_ext: false,
        extensions: Vec::new(),
    };
    let mut hook_saw_membership = 0;
    session.dispatch_iteration_event_with(
        crate::session_glue::IterationEvent::Poll(&outcome),
        |obs| {
            // The hook observes post-dispatch registry state under the
            // SAME lock; the deferred listener has NOT fired yet (the
            // drain runs only after this scope ends).
            hook_saw_membership = obs.remote_subscribers.declared_count();
            assert!(
                log.lock().unwrap().is_empty(),
                "deferred fire still staged while the hook holds the lock"
            );
        },
    );
    assert_eq!(hook_saw_membership, 1, "hook ran after the registry fan");
    assert_eq!(
        log.lock().unwrap().len(),
        1,
        "deferred fire drained after the hook's lock scope ended"
    );
}

// ── R311lg deferred data-plane callbacks (liveliness samples + reply/final) ──

/// R311lg — the liveliness-sample plane rides the F-6 deferred-fire
/// queue (the R311lf lock-free callback invariant): the callback runs
/// OUTSIDE the observer mutex, so it may re-enter an observer-locking
/// session API — here `declare_subscriber` (registers under the
/// observer lock) and the returned handle's Drop (also locks). The
/// pre-R311lg inline sink self-deadlocked on exactly this shape
/// (R311kj constraint).
#[cfg(all(feature = "liveliness-subscriber", feature = "liveliness-token"))]
#[test]
fn liveliness_sample_callback_runs_deferred_and_may_reenter_session() {
    use crate::declare::LivelinessSampleKind;
    use hashbrown::HashMap;
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();
    type SampleLog = Arc<Mutex<Vec<(LivelinessSampleKind, String, u64)>>>;
    let log: SampleLog = Arc::new(Mutex::new(Vec::new()));
    let log_cb = log.clone();
    let session_cb = session.clone();
    let _sub = session
        .declare_liveliness_subscriber(
            "liveliness/**",
            LivelinessSubscriberOptions::default(),
            move |sample| {
                log_cb.lock().unwrap().push((
                    sample.kind,
                    sample.keyexpr.to_string(),
                    sample.token_id,
                ));
                // Re-enter an observer-locking session API from inside
                // the callback; the handle Drop at scope end locks the
                // observer a second time.
                // R311ou — SessionLocal re-entrancy probe (re-locks the observer
                // from inside the callback); not a routed subscriber, so no
                // spurious wire emit.
                let _re = session_cb
                    .declare_subscriber(
                        "reentry/ok",
                        SubscribeOptions::new().with_allowed_origin(Locality::SessionLocal),
                        |_s| {},
                    )
                    .expect("re-entrant session-local declare from inside the callback succeeds");
            },
        )
        .expect("liveliness-subscriber is on in this lane");

    session
        .observer()
        .lock()
        .unwrap()
        .liveliness_subscribers
        .dispatch_declare(&make_decl_token(9, "liveliness/x"), &HashMap::new());
    assert!(
        log.lock().unwrap().is_empty(),
        "the registry sink only STAGES — no fire under the dispatch"
    );
    session.drain_deferred_fires();
    assert_eq!(
        *log.lock().unwrap(),
        vec![(LivelinessSampleKind::Put, "liveliness/x".to_string(), 9)],
        "owned-copy deferred sample preserves kind/keyexpr/token_id"
    );
}

/// R311y790 — the SESSION-level witness for the declare-time history replay.
/// The registry-level tests pin that `register` fires the known tokens into
/// the slot's sink; this pins that the samples reach the APPLICATION
/// callback, which they only do by riding the same F-6 deferred-fire queue
/// every live sample rides (the replay is staged under the observer lock, so
/// a replay that staged and never drained would satisfy every registry
/// assertion and still deliver nothing).
///
/// Shape: subscriber A is declared future-only and sees a token arrive live.
/// Subscriber B is declared AFTERWARDS with history — and is given that same
/// token, which is exactly what waiting for the peer's CURRENT reply would
/// NOT give it behind a zenoh router: upstream suppresses re-declaring a
/// token it has already declared to that face
/// (`net/routing/hat/router/token.rs:127`).
#[cfg(all(
    feature = "liveliness-subscriber",
    feature = "liveliness-token",
    feature = "liveliness-history"
))]
#[test]
fn a_later_history_subscriber_is_replayed_a_token_the_session_already_knows() {
    use crate::declare::LivelinessSampleKind;
    use hashbrown::HashMap;
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();
    type SampleLog = Arc<Mutex<Vec<(LivelinessSampleKind, String, u64)>>>;

    let first: SampleLog = Arc::new(Mutex::new(Vec::new()));
    let first_cb = first.clone();
    let _a = session
        .declare_liveliness_subscriber(
            "liveliness/**",
            LivelinessSubscriberOptions::default(),
            move |sample| {
                first_cb.lock().unwrap().push((
                    sample.kind,
                    sample.keyexpr.to_string(),
                    sample.token_id,
                ));
            },
        )
        .expect("liveliness-subscriber is on in this lane");

    session
        .observer()
        .lock()
        .unwrap()
        .liveliness_subscribers
        .dispatch_declare(&make_decl_token(9, "liveliness/x"), &HashMap::new());
    session.drain_deferred_fires();
    assert_eq!(
        first.lock().unwrap().len(),
        1,
        "A saw the token arrive live -- the session now KNOWS it"
    );

    let second: SampleLog = Arc::new(Mutex::new(Vec::new()));
    let second_cb = second.clone();
    let _b = session
        .declare_liveliness_subscriber(
            "liveliness/**",
            LivelinessSubscriberOptions::default().with_history(true),
            move |sample| {
                second_cb.lock().unwrap().push((
                    sample.kind,
                    sample.keyexpr.to_string(),
                    sample.token_id,
                ));
            },
        )
        .expect("liveliness-subscriber is on in this lane");
    session.drain_deferred_fires();

    assert_eq!(
        *second.lock().unwrap(),
        vec![(LivelinessSampleKind::Put, "liveliness/x".to_string(), 9)],
        "the history subscriber is replayed the token this session already \
         knew, and it arrives through the deferred-fire queue rather than \
         under the declare's own observer lock",
    );
    assert_eq!(
        first.lock().unwrap().len(),
        1,
        "the replay is owed to the DECLARING subscriber only -- A was told \
         about this token when it arrived live",
    );
}

/// R311lg — a sample staged before `undeclare` but drained after it is
/// suppressed (the kill-first ordering on the handle): the callback
/// never observes a post-undeclare sample.
#[cfg(all(feature = "liveliness-subscriber", feature = "liveliness-token"))]
#[test]
fn liveliness_sample_staged_before_undeclare_is_suppressed() {
    use hashbrown::HashMap;
    use std::sync::Arc;

    let (session, _driver) = build_session();
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    let sub = session
        .declare_liveliness_subscriber(
            "liveliness/**",
            LivelinessSubscriberOptions::default(),
            move |_sample| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("liveliness-subscriber is on in this lane");

    session
        .observer()
        .lock()
        .unwrap()
        .liveliness_subscribers
        .dispatch_declare(&make_decl_token(3, "liveliness/x"), &HashMap::new());
    sub.undeclare();
    session.drain_deferred_fires();
    assert_eq!(
        fired.load(Ordering::SeqCst),
        0,
        "staged-but-undrained sample is suppressed by the killed cell"
    );
}

/// R311lg — cell backlog (lossless overlap): a re-entrant drain that
/// reaches the SAME cell mid-fire backlogs the call instead of
/// dropping it; the active drainer delivers it before restoring, so
/// both samples arrive exactly once in stage order.
#[cfg(all(feature = "liveliness-subscriber", feature = "liveliness-token"))]
#[test]
fn liveliness_sample_reentrant_same_cell_fire_is_backlogged_not_lost() {
    use hashbrown::HashMap;
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();
    let log: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let log_cb = log.clone();
    let session_cb = session.clone();
    let _sub = session
        .declare_liveliness_subscriber(
            "liveliness/**",
            LivelinessSubscriberOptions::default(),
            move |sample| {
                log_cb.lock().unwrap().push(sample.token_id);
                if sample.token_id == 1 {
                    // From INSIDE the callback: stage another sample
                    // for this same cell and drain re-entrantly. The
                    // inner drain finds the callback mid-fire and
                    // BACKLOGS the call (pre-R311lg cells dropped it).
                    session_cb
                        .observer()
                        .lock()
                        .unwrap()
                        .liveliness_subscribers
                        .dispatch_declare(&make_decl_token(2, "liveliness/y"), &HashMap::new());
                    let _ = session_cb.drain_deferred_fires();
                    assert_eq!(
                        *log_cb.lock().unwrap(),
                        vec![1],
                        "the backlogged call must NOT run inside the inner drain"
                    );
                }
            },
        )
        .expect("liveliness-subscriber is on in this lane");

    session
        .observer()
        .lock()
        .unwrap()
        .liveliness_subscribers
        .dispatch_declare(&make_decl_token(1, "liveliness/x"), &HashMap::new());
    session.drain_deferred_fires();
    assert_eq!(
        *log.lock().unwrap(),
        vec![1, 2],
        "the overlapped fire is delivered by the active drainer (lossless, FIFO)"
    );
}

/// R311lg — the reply/final plane: `on_reply` / `on_final` run
/// deferred (outside the observer mutex), yet a SessionLocal query
/// still delivers synchronously before `query` returns (the tail
/// drain — zenoh-pico `_z_session_deliver_query_locally` fires on the
/// caller thread, outside the session mutex). The callback re-enters
/// the session by issuing a SECOND query from inside `on_reply` —
/// the pre-R311lg inline sink self-deadlocked there (`query` locks
/// the observer for registration + loopback fan).
#[cfg(all(feature = "query-get", feature = "query-queryable"))]
#[test]
fn query_reply_callbacks_run_deferred_lock_free_and_local_sync() {
    use std::sync::Arc;

    let (session, _driver) = build_session();
    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("home/temp", |_q, responder| {
            responder.reply(b"22.5");
        });

    let outer_replies = Arc::new(AtomicUsize::new(0));
    let outer_finals = Arc::new(AtomicUsize::new(0));
    let inner_replies = Arc::new(AtomicUsize::new(0));
    let inner_finals = Arc::new(AtomicUsize::new(0));

    let or = outer_replies.clone();
    let of = outer_finals.clone();
    let ir = inner_replies.clone();
    let inf = inner_finals.clone();
    let session_cb = session.clone();
    session
        .query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |_reply| {
                or.fetch_add(1, Ordering::SeqCst);
                let ir = ir.clone();
                let inf = inf.clone();
                let _ = session_cb
                    .query(
                        "home/temp",
                        QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
                        move |_r| {
                            ir.fetch_add(1, Ordering::SeqCst);
                        },
                        move |_rid| {
                            inf.fetch_add(1, Ordering::SeqCst);
                        },
                    )
                    .expect("re-entrant query from inside on_reply succeeds lock-free");
            },
            move |_rid| {
                of.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("query-get is on in this lane");

    assert_eq!(
        (
            outer_replies.load(Ordering::SeqCst),
            outer_finals.load(Ordering::SeqCst),
            inner_replies.load(Ordering::SeqCst),
            inner_finals.load(Ordering::SeqCst),
        ),
        (1, 1, 1, 1),
        "both queries (outer + re-entrant inner) fully delivered before the outer call returned"
    );
}

// ── R311lh deferred subscriber-sample plane ──

/// R311lh — the subscriber-sample plane rides the deferred-fire queue:
/// the callback runs OUTSIDE the observer mutex, so it may re-enter
/// observer-locking session APIs. The classic echo shape: a sample
/// callback that PUBLISHES (local loopback locks the observer) —
/// pre-R311lh this self-deadlocked. The nested publish's own loopback
/// fire on the same cell backlogs and is delivered before the outer
/// invoke restores (lossless re-entrant echo, bounded by the guard).
#[cfg(feature = "pubsub-allow-loop")]
#[test]
fn subscriber_sample_callback_runs_deferred_and_may_publish_back() {
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();
    type DeliveredLog = Arc<Mutex<Vec<(SampleKind, String, Vec<u8>)>>>;
    let log: DeliveredLog = Arc::new(Mutex::new(Vec::new()));
    let log_cb = log.clone();
    let session_cb = session.clone();
    let _sub = session
        .declare_subscriber(
            "home/**",
            SubscribeOptions::default(),
            move |sample: &dyn SampleView| {
                log_cb.lock().unwrap().push((
                    sample.kind(),
                    sample.keyexpr().to_string(),
                    sample.payload().to_vec(),
                ));
                // Echo exactly once: re-enter publish (locks the observer
                // for the loopback fan) from inside the callback.
                if sample.keyexpr() == "home/temp" {
                    let delivered = session_cb
                        .publish(
                            "home/echo",
                            b"echo",
                            PublishOptions::put().with_locality(Locality::SessionLocal),
                        )
                        .expect("re-entrant publish from inside the callback succeeds lock-free");
                    assert_eq!(delivered, 1, "echo matched this same subscriber");
                }
            },
        )
        .expect("remote declare against the test link succeeds");

    let delivered = session
        .publish(
            "home/temp",
            b"21.5",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        )
        .expect("publish with loopback succeeds");
    assert_eq!(delivered, 1, "one matching subscriber");
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            (SampleKind::Put, "home/temp".to_string(), b"21.5".to_vec()),
            (SampleKind::Put, "home/echo".to_string(), b"echo".to_vec()),
        ],
        "original + echoed sample both delivered synchronously before publish returned"
    );
}

/// R311lh — a sample staged before `undeclare` but drained after it is
/// suppressed (kill-first ordering on the Subscriber handle).
#[test]
fn subscriber_sample_staged_before_undeclare_is_suppressed() {
    use std::sync::Arc;

    let (session, _driver) = build_session();
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    let sub = session
        .declare_subscriber(
            "home/**",
            SubscribeOptions::default(),
            move |_sample: &dyn SampleView| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("remote declare against the test link succeeds");

    // Stage a fire through the raw registry (no drain yet).
    {
        let mut obs = session.observer().lock().unwrap();
        let sample = Sample::new_put("home/temp", b"x".to_vec());
        obs.subscribers.local_publish(&sample);
    }
    assert!(sub.undeclare(), "undeclare removes the registration");
    session.drain_deferred_fires();
    assert_eq!(
        fired.load(Ordering::SeqCst),
        0,
        "staged-but-undrained sample is suppressed by the killed cell"
    );
}

// ── R311li deferred queryable plane ──

/// R290-style local Request(Query) constructor for the R311li
/// queryable-plane tests (mirror of `make_decl_token` — the
/// wz-session-core test builders are not a dev-dep here per R311ds).
#[cfg(all(feature = "query-queryable", feature = "codec-response-final"))]
fn make_request_query(rid: u64, keyexpr_literal: &str) -> wz_codecs::request::RequestOwned {
    use wz_codecs::request::{Request, RequestVariant};
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_local::WireexprLocal;
    let keyexpr = Wireexpr {
        body: WireexprVariant::WireexprLocal(WireexprLocal {
            id: 0,
            suffix_len: Some(keyexpr_literal.len() as u64),
            suffix: Some(keyexpr_literal),
        }),
    };
    Request {
        header: 0x1c,
        rid,
        keyexpr,
        extensions: None,
        body: RequestVariant::CodecZenohQuery(wz_codecs::query::Query::default()),
    }
    .try_into_owned()
    .unwrap()
}

#[cfg(all(feature = "query-queryable", feature = "codec-response-final"))]
fn query_frame_outcome(
    request: wz_codecs::request::RequestOwned,
) -> wz_session_core::driver_loop::DriverLoopOutcome {
    wz_session_core::driver_loop::DriverLoopOutcome::FramePayload {
        priority: wz_session_core::qos::Priority::DEFAULT,
        reliable: true,
        sn: 0,
        messages: vec![wz_session_core::network_message::NetworkMessage::Request(
            Box::new(request),
        )],
        has_ext: false,
        extensions: Vec::new(),
    }
}

/// R311li — the queryable plane rides the deferred-fire queue: the
/// handler runs OUTSIDE the observer mutex (it re-enters the session
/// here by declaring a subscriber and dropping its handle — both lock
/// the observer; pre-R311li this self-deadlocked), its replies are
/// emitted at the drain, and the ResponseFinal job staged by the
/// dispatch SSOT runs after them — Reply-before-Final on the wire.
#[cfg(all(feature = "query-queryable", feature = "codec-response-final"))]
#[test]
fn queryable_handler_runs_deferred_replies_then_final_on_wire() {
    use std::sync::Arc;

    let (session, driver) = build_session();
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    let session_cb = session.clone();
    let _q = session
        .declare_queryable(
            "home/**",
            QueryableOptions::default(),
            move |query: &dyn QueryView, out: &mut dyn ReplyOut| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
                assert_eq!(query.keyexpr(), "home/temp");
                assert!(!query.is_local(), "wire-shaped dispatch");
                // Re-enter an observer-locking session API from inside
                // the handler (deadlocked pre-R311li). R311ou — SessionLocal so
                // this re-entrancy probe locks the observer (the point) WITHOUT
                // emitting a wire `Declare(DeclSubscriber)` that would pollute
                // the Reply/Final frame assertions below; it is a probe, not a
                // routed subscriber.
                let _re = session_cb.declare_subscriber(
                    "reentry/ok",
                    SubscribeOptions::new().with_allowed_origin(Locality::SessionLocal),
                    |_| {},
                );
                out.reply(b"22.5");
            },
        )
        .expect("query-queryable on in this lane");

    // R311ow — the routed declare above emitted its `Declare(DeclQueryable)`
    // (when `declare-queryable` is on); snapshot the frame count so the
    // assertions below measure ONLY the QUERY -> Reply -> Final flow. `base`
    // adapts to the feature config (0 when declare-queryable is off, 1 when it
    // emitted), so the delta + reply-frame index stay correct in every lane.
    // The declare-emit itself is covered by
    // `declare_queryable_remote_emits_one_reliable_decl_queryable`.
    let base = driver.frame_count();

    let outcome = query_frame_outcome(make_request_query(11, "home/temp"));
    session.dispatch_iteration_event(crate::session_glue::IterationEvent::Poll(&outcome));

    assert_eq!(fired.load(Ordering::SeqCst), 1, "handler ran at the drain");
    assert_eq!(
        driver.frame_count() - base,
        2,
        "one Response + one ResponseFinal left the session"
    );
    let reply_frame = driver.frame_bytes(base);
    assert!(
        reply_frame.windows(4).any(|w| w == b"22.5"),
        "first frame is the Reply (carries the payload bytes) — Reply precedes Final"
    );
}

/// R311y337 — the sibling of the R311li guard below, on the arm R311li did not
/// name. That one proves a MATCHED-but-silent handler still terminates its
/// stream; this one proves the case the registry used to drop outright: a
/// resolvable wire query that matches NO queryable at all. zenoh terminates it
/// through `Drop for QueryInner` (its `QueryInner` is built unconditionally,
/// session.rs:2440-2450 + queryable.rs:75-83); pico through its explicit
/// `if (qle_nb == 0) { ...; _z_session_send_reply_final(..); }`
/// (queryable.c:246-252). Before y337 wz stayed silent here and the requester
/// waited out its own timeout — and R311y334's completeness filter had just made
/// the arm easy to reach.
#[cfg(all(feature = "query-queryable", feature = "codec-response-final"))]
#[test]
fn unmatched_wire_query_still_sends_final() {
    let (session, driver) = build_session();
    let _q = session
        .declare_queryable(
            "home/**",
            QueryableOptions::default(),
            |_query: &dyn QueryView, _out: &mut dyn ReplyOut| {
                // never fires: the query below matches no registered pattern
            },
        )
        .expect("query-queryable on in this lane");

    // Snapshot past the routed declare's `Declare(DeclQueryable)`.
    let base = driver.frame_count();

    // `garden/temp` RESOLVES (literal, mapping id 0) but matches nothing.
    let outcome = query_frame_outcome(make_request_query(13, "garden/temp"));
    session.dispatch_iteration_event(crate::session_glue::IterationEvent::Poll(&outcome));

    assert_eq!(
        driver.frame_count() - base,
        1,
        "a resolvable wire query that matched NOBODY still gets its bare \
         ResponseFinal — otherwise the requester waits out its own timeout"
    );
}

/// R311li — a matched-but-silent handler still terminates the reply
/// stream: the Final trigger keys on the MATCH count, not the staged
/// reply delta (the prior delta detection starved the querier until
/// timeout — zenoh-pico emits the reply Final on query drop
/// regardless of reply count).
#[cfg(all(feature = "query-queryable", feature = "codec-response-final"))]
#[test]
fn queryable_matched_but_silent_handler_still_sends_final() {
    let (session, driver) = build_session();
    let _q = session
        .declare_queryable(
            "home/**",
            QueryableOptions::default(),
            |_query: &dyn QueryView, _out: &mut dyn ReplyOut| {
                // deliberately no reply
            },
        )
        .expect("query-queryable on in this lane");

    // R311ow — snapshot past the routed declare's `Declare(DeclQueryable)` so
    // the assertion measures only the bare ResponseFinal of the silent handler.
    let base = driver.frame_count();

    let outcome = query_frame_outcome(make_request_query(12, "home/temp"));
    session.dispatch_iteration_event(crate::session_glue::IterationEvent::Poll(&outcome));

    assert_eq!(
        driver.frame_count() - base,
        1,
        "bare ResponseFinal terminates the silent handler's reply stream"
    );
}

/// R311li — a SessionLocal query against a Session-tier (deferred)
/// queryable delivers every local reply, then the loopback Final, all
/// synchronously before `query` returns (the query-tail drain runs the
/// deferred handler; the loopback Final is delivered after that drain).
#[cfg(all(feature = "query-get", feature = "query-queryable"))]
#[test]
fn local_query_against_deferred_queryable_delivers_before_return() {
    use std::sync::{Arc, Mutex};

    let (session, _driver) = build_session();
    let _q = session
        .declare_queryable(
            "home/**",
            QueryableOptions::default(),
            |query: &dyn QueryView, out: &mut dyn ReplyOut| {
                assert!(query.is_local(), "loopback-shaped dispatch");
                out.reply(b"21.0");
            },
        )
        .expect("query-queryable on in this lane");

    let log: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
    let log_r = log.clone();
    let log_f = log.clone();
    session
        .query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |reply| {
                assert_eq!(reply.payload(), b"21.0");
                log_r.lock().unwrap().push("reply");
            },
            move |_rid| {
                log_f.lock().unwrap().push("final");
            },
        )
        .expect("query-get on in this lane");

    assert_eq!(
        *log.lock().unwrap(),
        vec!["reply", "final"],
        "deferred local handler's reply precedes the loopback Final, both before query returned"
    );
}

/// R311li — a query staged before `undeclare` but drained after it is
/// suppressed (kill-first), while the registry-staged ResponseFinal is
/// still owed — the requester is never starved by a racing undeclare.
#[cfg(all(feature = "query-queryable", feature = "codec-response-final"))]
#[test]
fn queryable_staged_before_undeclare_suppressed_but_final_still_sent() {
    use std::sync::Arc;

    let (session, driver) = build_session();
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    let q = session
        .declare_queryable(
            "home/**",
            QueryableOptions::default(),
            move |_query: &dyn QueryView, _out: &mut dyn ReplyOut| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("query-queryable on in this lane");

    // Stage through the raw observer (no drain yet), mirroring the
    // drive loop's fan with a window before the drain.
    let outcome = query_frame_outcome(make_request_query(13, "home/temp"));
    {
        let mut obs = session.observer().lock().unwrap();
        obs.dispatch_event(crate::session_glue::IterationEvent::Poll(&outcome));
    }
    assert!(q.undeclare(), "undeclare removes the registration");
    // R311ow — snapshot past the routed declare's `Declare(DeclQueryable)` AND
    // the `undeclare`'s `Declare(UndeclQueryable)` retraction so the assertion
    // measures only the flush's owed ResponseFinal. `base` adapts to the feature
    // config; the retraction emit itself is covered by
    // `routed_queryable_drop_emits_undecl_queryable`.
    let base = driver.frame_count();
    session.drain_deferred_fires();
    // The raw-dispatch site still owes the staged Final through the
    // combined flush (the SSOT path stages it as a job instead).
    // R311nf — `actions()` is infallible on `TokioSession`; `.as_ref()` coerces
    // `&Arc<SessionLinkActions>` → `&SessionLinkActions` for `flush_pending`.
    {
        let mut obs = session.observer().lock().unwrap();
        obs.flush_pending(session.actions().as_ref());
    }
    assert_eq!(fired.load(Ordering::SeqCst), 0, "handler suppressed");
    assert_eq!(
        driver.frame_count() - base,
        1,
        "the ResponseFinal is still emitted — the requester is not starved"
    );
}

// R311y290 — `query`'s deferred-fire drain is gated on `allows_local`, mirroring
// `publish`. The gate matters for a caller whose inbound dispatch runs on a
// DIFFERENT thread from the one calling `query` (wz-capi-pico drives its peer
// faces on a drive thread while a C application thread calls `z_get`): an
// UNGATED drain takes the WHOLE per-session queue, so a Remote-only query would
// run another plane's staged subscriber callback on the querying thread,
// concurrently with the drive thread running its own — the same callback context
// on two threads at once. Everything `query` itself stages is loopback-only, so
// gating costs a Remote-only query nothing.
//
// All three features are preconditions, not decoration: `pubsub-allow-loop` is a
// COMPILE need (`build_loopback_sample` is gated on it), while `declare-subscriber`
// and `query-get` are RUNTIME needs — both methods are signature-stable and return
// `FeatureDisabled` when off, so without the gate this would compile and then fail
// at the `.expect` / `assert!(issued.is_ok())` in the Layer C1j subset lanes.
#[cfg(all(
    feature = "query-get",
    feature = "declare-subscriber",
    feature = "pubsub-allow-loop"
))]
#[test]
fn remote_only_query_does_not_drain_another_planes_staged_fire() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (session, _driver) = build_session();
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    let _sub = session
        .declare_subscriber(
            "demo/**",
            SubscribeOptions::default(),
            move |_v: &dyn wz_session_core::sink::SampleView| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("declare_subscriber");

    // Stage a loopback fire WITHOUT draining it — exactly the window the drive
    // loop is in between its `dispatch_event` and its `drain_deferred_fires`.
    let sample =
        super::publish_common::build_loopback_sample("demo/a", b"payload", &PublishOptions::put());
    session
        .observer()
        .lock()
        .unwrap()
        .subscribers
        .local_publish(&sample);
    assert_eq!(
        fired.load(Ordering::SeqCst),
        0,
        "precondition: the fire is staged, not yet drained"
    );

    // A Remote-only query must NOT drain it.
    let opts = QueryOptions {
        allowed_destination: Locality::Remote,
        ..Default::default()
    };
    let issued = session.query(
        "q/**",
        opts,
        |_r: &dyn wz_session_core::reply_sink::ReplyView| {},
        |_rid: u64| {},
    );
    // Non-vacuity: the query must actually have reached the drain site. A query
    // that errored early would leave the fire staged for the wrong reason.
    assert!(
        issued.is_ok(),
        "precondition: the query must succeed so it reaches the drain site"
    );
    assert_eq!(
        fired.load(Ordering::SeqCst),
        0,
        "a Remote-only query drained another plane's staged fire — the R311y290 \
         gate is gone, and a foreign caller's callback can now run on two threads"
    );

    // The drive loop's drain still runs it.
    assert_eq!(session.drain_deferred_fires(), 1);
    assert_eq!(fired.load(Ordering::SeqCst), 1);
}

/// R311y321 — the APPLY half of `query-consolidation`, proven THROUGH
/// `Session::query`'s own wiring rather than at the `ConsolidatingSink` unit
/// seam. The unit tests in `wz-session-core::reply_sink` prove the decorator's
/// per-mode contract; this proves the runtime actually INSTALLS it with the
/// query's mode, which is a separate claim — before y321 the mode reached the
/// wire as the Q_C ext and the local delivery ignored it entirely.
///
/// THE BREAK THIS CLOSES IS ON THE PICO C API'S DEFAULT PATH:
/// `z_get_options_default` sets `Z_CONSOLIDATION_MODE_AUTO`
/// (`vendor/zenoh-pico/src/api/api.c:1725` -> `:462` -> `:446`), `wz-capi-pico`
/// resolves AUTO to LATEST exactly as pico's `primitives.c:567-573` does and
/// calls `with_consolidation(Latest)` — so every default `z_get()` through wz
/// used to deliver BOTH replies below where pico delivers one.
#[cfg(all(
    feature = "query-get",
    feature = "query-queryable",
    feature = "query-consolidation",
    feature = "pubsub-timestamp"
))]
#[test]
fn query_with_latest_consolidation_delivers_one_reply_per_keyexpr() {
    use wz_session_core::query_mode::ConsolidationMode;
    use wz_session_core::sample::TimestampHint;

    let (session, _driver) = build_session();
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_cb = seen.clone();

    // One queryable answering the SAME keyexpr twice with two versions — the
    // History::All storage shape consolidation exists for.
    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("hist/key", |_q, responder| {
            responder.reply_keyed_stamped(
                "hist/key",
                b"old",
                None,
                &TimestampHint {
                    time: 10,
                    zid: vec![0x01],
                },
            );
            responder.reply_keyed_stamped(
                "hist/key",
                b"new",
                None,
                &TimestampHint {
                    time: 20,
                    zid: vec![0x01],
                },
            );
        });

    session
        .query(
            "hist/key",
            QueryOptions::get()
                .with_allowed_destination(Locality::SessionLocal)
                .with_consolidation(ConsolidationMode::Latest),
            move |reply| seen_cb.lock().unwrap().push(reply.payload().to_vec()),
            |_| {},
        )
        .expect("query-get feature is ON in this test build");

    let got = seen.lock().unwrap();
    assert_eq!(
        *got,
        vec![b"new".to_vec()],
        "Latest must collapse the two versions to the newest by timestamp"
    );
}

/// The companion NEG at the same seam: the SAME two replies, with an EXPLICIT
/// `None`, must BOTH arrive. Without this, a decorator that consolidated
/// unconditionally would pass the test above and silently break every
/// non-consolidating z_get in the tree — the wrapper is installed on every
/// pending, so "does None still passthrough" is a real question, not a given.
///
/// R311y836 — this test was `query_without_consolidation_still_delivers_every_reply`
/// and reached the `None` mode by naming NO mode at all, asserting "the default
/// get must not consolidate". That was wz's default, never zenoh's: upstream
/// resolves the unnamed case to LATEST (`zenoh/src/api/session.rs:2250`), so the
/// old trigger was pinning a divergence. The LOAD-BEARING claim is unchanged and
/// still asserted — `ConsolidationMode::None` is a pass-through — only the
/// trigger moved, from "named nothing" to "named None", which is the one that
/// actually expresses it. The default now has its own test above.
#[cfg(all(
    feature = "query-get",
    feature = "query-queryable",
    feature = "query-consolidation",
    feature = "pubsub-timestamp"
))]
#[test]
fn query_with_explicit_none_consolidation_still_delivers_every_reply() {
    use wz_session_core::query_mode::ConsolidationMode;
    use wz_session_core::sample::TimestampHint;

    let (session, _driver) = build_session();
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_cb = seen.clone();

    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("hist/key", |_q, responder| {
            responder.reply_keyed_stamped(
                "hist/key",
                b"old",
                None,
                &TimestampHint {
                    time: 10,
                    zid: vec![0x01],
                },
            );
            responder.reply_keyed_stamped(
                "hist/key",
                b"new",
                None,
                &TimestampHint {
                    time: 20,
                    zid: vec![0x01],
                },
            );
        });

    session
        .query(
            "hist/key",
            QueryOptions::get()
                .with_allowed_destination(Locality::SessionLocal)
                .with_consolidation(ConsolidationMode::None),
            move |reply| seen_cb.lock().unwrap().push(reply.payload().to_vec()),
            |_| {},
        )
        .expect("query-get feature is ON in this test build");

    let got = seen.lock().unwrap();
    assert_eq!(
        *got,
        vec![b"old".to_vec(), b"new".to_vec()],
        "an explicit None must not consolidate: both versions, in arrival order"
    );
}

/// R311y836 — the OFF arm of the resolution, and it needs its own witness
/// because it is the arm no `query-consolidation` build can express: with the
/// feature compiled out, `resolved_consolidation` reads `None` and the default
/// get keeps its pre-y836 pass-through. A resolution that leaked past the gate
/// — say by living in the `ConsolidatingSink` instead of behind the accessor —
/// would consolidate here and break the A3 `active <=> cfg-site` invariant
/// silently, since every ON-arm test would stay green.
#[cfg(all(
    feature = "query-get",
    feature = "query-queryable",
    not(feature = "query-consolidation"),
    feature = "pubsub-timestamp"
))]
#[test]
fn a_default_get_does_not_consolidate_without_the_query_consolidation_feature() {
    use wz_session_core::sample::TimestampHint;

    let (session, _driver) = build_session();
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_cb = seen.clone();

    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("hist/key", |_q, responder| {
            responder.reply_keyed_stamped(
                "hist/key",
                b"old",
                None,
                &TimestampHint {
                    time: 10,
                    zid: vec![0x01],
                },
            );
            responder.reply_keyed_stamped(
                "hist/key",
                b"new",
                None,
                &TimestampHint {
                    time: 20,
                    zid: vec![0x01],
                },
            );
        });

    session
        .query(
            "hist/key",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |reply| seen_cb.lock().unwrap().push(reply.payload().to_vec()),
            |_| {},
        )
        .expect("query-get feature is ON in this test build");

    assert_eq!(
        *seen.lock().unwrap(),
        vec![b"old".to_vec(), b"new".to_vec()],
        "with query-consolidation OFF the default get must stay a pass-through: \
         the feature IS the capability, and it must not arrive through a default"
    );
}

/// R311y836 — the DEFAULT get's consolidation, which is a different claim from
/// the two tests above: they pin what an EXPLICIT mode does, this pins what the
/// absence of one means.
///
/// zenoh's option default is `QueryConsolidation::DEFAULT = AUTO`
/// (`zenoh/src/api/query.rs:43-46`) and `get()` RESOLVES it before it does
/// anything else — `ConsolidationMode::Auto => ConsolidationMode::Latest`
/// (`zenoh/src/api/session.rs:2250`). So a zenoh caller who names no mode gets
/// LATEST, and the two versions below collapse to one.
#[cfg(all(
    feature = "query-get",
    feature = "query-queryable",
    feature = "query-consolidation",
    feature = "pubsub-timestamp"
))]
#[test]
fn a_default_get_consolidates_to_the_latest_reply_like_zenoh() {
    use wz_session_core::sample::TimestampHint;

    let (session, _driver) = build_session();
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_cb = seen.clone();
    let finals = Arc::new(AtomicUsize::new(0));
    let finals_cb = finals.clone();

    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("hist/key", |_q, responder| {
            responder.reply_keyed_stamped(
                "hist/key",
                b"old",
                None,
                &TimestampHint {
                    time: 10,
                    zid: vec![0x01],
                },
            );
            responder.reply_keyed_stamped(
                "hist/key",
                b"new",
                None,
                &TimestampHint {
                    time: 20,
                    zid: vec![0x01],
                },
            );
        });

    session
        .query(
            "hist/key",
            // NO consolidation named — this is the whole point of the test.
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |reply| seen_cb.lock().unwrap().push(reply.payload().to_vec()),
            move |_| {
                finals_cb.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("query-get feature is ON in this test build");

    assert_eq!(
        *seen.lock().unwrap(),
        vec![b"new".to_vec()],
        "a get that names no mode must resolve AUTO -> LATEST as zenoh's \
         session.rs:2250 does, delivering only the newest version per keyexpr"
    );
    // CONTROL, in the same test on purpose: an implementation that reached the
    // asserted set by delivering NOTHING would satisfy the assertion above. The
    // caller must still be terminated, and exactly once.
    assert_eq!(
        finals.load(Ordering::SeqCst),
        1,
        "consolidating the default get must not cost the caller its final"
    );
}

/// The carve-out that rides with the resolution, and it is upstream's, not an
/// invention: `ConsolidationMode::Auto if parameters.time_range().is_some() =>
/// ConsolidationMode::None` (`zenoh/src/api/session.rs:2249`), keyed on the
/// `_time` selector parameter (`TIME_RANGE_KEY`, `zenoh/src/api/selector.rs:145`).
///
/// A `_time` range asks for a WINDOW of history; collapsing it to one sample per
/// keyexpr would answer a different question. Without this arm the resolution
/// would silently truncate every time-ranged get, which is the same data-loss
/// shape the `@adv` history GETs are pinned against below.
#[cfg(all(
    feature = "query-get",
    feature = "query-queryable",
    feature = "query-consolidation",
    feature = "query-selector-parameters",
    feature = "pubsub-timestamp"
))]
#[test]
fn a_default_get_with_a_time_range_selector_does_not_consolidate() {
    use wz_session_core::sample::TimestampHint;

    let (session, _driver) = build_session();
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_cb = seen.clone();

    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("hist/key", |_q, responder| {
            responder.reply_keyed_stamped(
                "hist/key",
                b"old",
                None,
                &TimestampHint {
                    time: 10,
                    zid: vec![0x01],
                },
            );
            responder.reply_keyed_stamped(
                "hist/key",
                b"new",
                None,
                &TimestampHint {
                    time: 20,
                    zid: vec![0x01],
                },
            );
        });

    session
        .query(
            "hist/key",
            QueryOptions::get()
                .with_allowed_destination(Locality::SessionLocal)
                .with_parameters(b"_time=[now(-10s)..]".to_vec()),
            move |reply| seen_cb.lock().unwrap().push(reply.payload().to_vec()),
            |_| {},
        )
        .expect("query-get feature is ON in this test build");

    assert_eq!(
        *seen.lock().unwrap(),
        vec![b"old".to_vec(), b"new".to_vec()],
        "a `_time` range must hold the resolution at NONE (session.rs:2249): the \
         caller asked for a window of history, not the newest sample in it"
    );
}

/// R311y833 — zenoh states this as a GUARANTEE of `get()` itself: "Unless
/// explicitly requested via `accept_replies`, replies are guaranteed to have
/// key expressions that match the requested selector"
/// (`zenoh/src/api/session.rs:1181`), enforced at `session.rs:2845-2854`;
/// zenoh-pico enforces the same at `vendor/zenoh-pico/src/session/query.c:121`.
///
/// MEASURED BEFORE THE FIX, on this tree: the identical body ran with a
/// `panic!` reporting what arrived, and it printed BOTH payloads
/// (`[[105, 110], [111, 117, 116]]` = `[b"in", b"out"]`). wz's native getter
/// delivered a reply keyed `other/outside` for a query asked on `demo/**` —
/// a reply every real zenoh and zenoh-pico client drops.
///
/// The CONTROL rides in the same test on purpose: an implementation that
/// simply stopped delivering replies would satisfy the negative half alone.
/// `demo/inside` must still arrive, and the final must still fire, because a
/// caller whose replies are all refused must be TERMINATED, not hung.
///
/// The query is LITERAL here and the measured `demo/**` shape is pinned by the
/// wildcard-gated twin below. The gate judges by this build's own matching
/// rules, so a pattern fixture in an ungated test would silently be asserting
/// `keyexpr-wildcard-double` instead of the acceptance policy — Layer C1f
/// measured exactly that on the session-core side of this round.
#[cfg(all(feature = "query-get", feature = "query-queryable"))]
#[test]
fn a_default_get_refuses_a_reply_keyed_outside_the_query() {
    let (session, _driver) = build_session();
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_cb = seen.clone();
    let finals = Arc::new(AtomicUsize::new(0));
    let finals_cb = finals.clone();

    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("demo/inside", |_q, responder| {
            responder.reply_keyed("demo/inside", b"in");
            responder.reply_keyed("other/outside", b"out");
        });

    session
        .query(
            "demo/inside",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |reply| seen_cb.lock().unwrap().push(reply.payload().to_vec()),
            move |_| {
                finals_cb.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("query-get feature is ON in this test build");

    assert_eq!(
        *seen.lock().unwrap(),
        vec![b"in".to_vec()],
        "the intersecting reply must arrive and the outside one must not"
    );
    assert_eq!(
        finals.load(Ordering::SeqCst),
        1,
        "refusing every reply must still terminate the query"
    );
}

/// The MEASURED shape, kept verbatim: a `demo/**` get whose queryable answers
/// on both `demo/inside` and `other/outside`. Before y833 this delivered BOTH
/// (`[[105, 110], [111, 117, 116]]`); a wildcard query is the ordinary case
/// upstream's guarantee is written for, since a pattern get is exactly the one
/// that reaches queryables free to answer under any key they like.
#[cfg(all(
    feature = "query-get",
    feature = "query-queryable",
    feature = "keyexpr-wildcard-double"
))]
#[test]
fn a_wildcard_get_refuses_a_reply_outside_the_pattern() {
    let (session, _driver) = build_session();
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_cb = seen.clone();

    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("demo/**", |_q, responder| {
            responder.reply_keyed("demo/inside", b"in");
            responder.reply_keyed("other/outside", b"out");
        });

    session
        .query(
            "demo/**",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |reply| seen_cb.lock().unwrap().push(reply.payload().to_vec()),
            |_| {},
        )
        .expect("query-get feature is ON in this test build");

    assert_eq!(*seen.lock().unwrap(), vec![b"in".to_vec()]);
}

/// The opt-out, and the proof the gate is a policy rather than a hard-wired
/// refusal. `accept_replies(Any)` is how zenoh spells "queryables may also
/// reply on key expressions that don't intersect with the query's"
/// (`zenoh/src/api/builders/query.rs:284-287`), and after it BOTH replies of
/// the test above must arrive — the pre-y833 behaviour, now reachable only by
/// asking for it.
#[cfg(all(
    feature = "query-get",
    feature = "query-queryable",
    feature = "query-selector-parameters"
))]
#[test]
fn accept_replies_any_reinstates_a_reply_keyed_outside_the_query() {
    use wz_session_core::reply_acceptance::ReplyKeyExpr;

    let (session, _driver) = build_session();
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_cb = seen.clone();

    session
        .observer()
        .lock()
        .unwrap()
        .queryables
        .register("demo/inside", |_q, responder| {
            responder.reply_keyed("demo/inside", b"in");
            responder.reply_keyed("other/outside", b"out");
        });

    session
        .query(
            "demo/inside",
            get_opts_in_arrival_order()
                .with_allowed_destination(Locality::SessionLocal)
                .with_accept_replies(ReplyKeyExpr::Any),
            move |reply| seen_cb.lock().unwrap().push(reply.payload().to_vec()),
            |_| {},
        )
        .expect("query-get feature is ON in this test build");

    assert_eq!(
        *seen.lock().unwrap(),
        vec![b"in".to_vec(), b"out".to_vec()],
        "an _anyke get must accept both, in arrival order"
    );
}

/// The TX half of the same knob, and the reason there is no separate
/// `accept_replies` field: the opt-out has to REACH THE RESPONDER, which learns
/// it only from the selector parameters. zenoh's builder makes the identical
/// single write (`Parameters::set_reply_key_expr_any`,
/// `zenoh/src/api/builders/query.rs:288-300`); pico reads it back with
/// `_z_parameters_has_anyke`. Without these bytes a remote queryable keeps
/// refusing at ITS end (`vendor/zenoh-pico/src/net/primitives.c:438`) and the
/// local opt-out would be a knob that changes nothing over the wire.
#[cfg(all(feature = "query-get", feature = "query-selector-parameters"))]
#[test]
fn accept_replies_any_writes_the_anyke_selector_parameter() {
    use wz_session_core::reply_acceptance::ReplyKeyExpr;

    let bare = QueryOptions::get().with_accept_replies(ReplyKeyExpr::Any);
    assert_eq!(bare.parameters.as_deref(), Some(b"_anyke".as_slice()));

    // Appended to an existing list with the upstream `;` separator, not
    // clobbering it.
    let joined = QueryOptions::get()
        .with_parameters(b"_max=5".to_vec())
        .with_accept_replies(ReplyKeyExpr::Any);
    assert_eq!(
        joined.parameters.as_deref(),
        Some(b"_max=5;_anyke".as_slice())
    );

    // Idempotent — pico's `implicit_anyke = _anyke_option &&
    // !_anyke_in_parameters` (`vendor/zenoh-pico/src/net/primitives.c:575-578`).
    let twice = QueryOptions::get()
        .with_accept_replies(ReplyKeyExpr::Any)
        .with_accept_replies(ReplyKeyExpr::Any);
    assert_eq!(twice.parameters.as_deref(), Some(b"_anyke".as_slice()));

    // The default writes nothing at all: a get that never asks carries no
    // parameter, which is what keeps its wire bytes byte-identical to pre-y833.
    let default = QueryOptions::get().with_accept_replies(ReplyKeyExpr::MatchingQuery);
    assert_eq!(default.parameters, None);

    // And a caller who wrote the flag by hand is the same caller as one who
    // asked for it — pico's `_anyke_in_parameters || _anyke_option`.
    let by_hand = QueryOptions::get().with_parameters(b"_anyke".to_vec());
    assert_eq!(
        by_hand.effective_accept_replies(),
        ReplyKeyExpr::Any,
        "the parameters ARE the state; there is no second flag to disagree with"
    );
}

/// The `@adv` planes already emit `_anyke` on every history / recovery GET
/// (R311y442), precisely because those replies are keyed on the CACHED
/// SAMPLE's own expression rather than on the `@adv` selector the GET was
/// asked under. This pins that the y833 gate reads that flag out of the
/// selector those helpers build, so the round cannot have silently broken
/// advanced-subscriber recovery.
#[cfg(feature = "query-get")]
#[test]
fn an_adv_recovery_selector_reads_as_accept_any() {
    use wz_session_core::reply_acceptance::ReplyKeyExpr;

    let selector = wz_session_core::selector_params::anyke_params(&["_sn=3..".to_string()]);
    let opts = QueryOptions {
        parameters: Some(selector.into_bytes()),
        ..QueryOptions::get()
    };
    assert_eq!(opts.effective_accept_replies(), ReplyKeyExpr::Any);
}

// --- R311y554: LocalDeliveryDrain ------------------------------------------

#[test]
fn local_delivery_drain_defaults_to_caller_and_survives_clone() {
    let (session, _driver) = build_session();
    assert_eq!(
        session.local_delivery_drain(),
        LocalDeliveryDrain::Caller,
        "the default must be the pre-policy behaviour: the staging call drains"
    );
    let deferred = session.with_local_delivery_drain(LocalDeliveryDrain::DriveTask);
    assert_eq!(
        deferred.local_delivery_drain(),
        LocalDeliveryDrain::DriveTask
    );
    assert_eq!(
        deferred.clone().local_delivery_drain(),
        LocalDeliveryDrain::DriveTask,
        "a clone is the same host, so it must carry the same policy — a clone \
         that reverted to Caller would reopen the hole on any background task"
    );
}

/// R311y554 — THE mechanism, asserted as a difference rather than as a
/// property of one arm.
///
/// Both arms publish the same sample to the same registry. Under `Caller` the
/// subscriber callback has already run when `publish` returns; under
/// `DriveTask` it has NOT, the fire is queued, and the drain runs it. The
/// second half is what makes `allowed_destination` honourable on an FFI ABI
/// whose `unsafe impl Sync` rests on one thread invoking the callback.
#[cfg(feature = "pubsub-allow-loop")]
#[test]
fn drive_task_policy_stages_the_local_delivery_where_caller_runs_it_inline() {
    for (policy, expect_inline) in [
        (LocalDeliveryDrain::Caller, 1usize),
        (LocalDeliveryDrain::DriveTask, 0usize),
    ] {
        let (base, _driver) = build_session();
        let session = base.with_local_delivery_drain(policy);
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        // The DEFERRING registration path — `Session::declare_subscriber`, which
        // is what the C ABI declares through. The bare
        // `observer().subscribers.register` used elsewhere in this file installs
        // a DIRECT callback that no policy can defer, so a test written against
        // it would report `Caller` behaviour under both arms.
        let _sub = session
            .declare_subscriber("home/temp", SubscribeOptions::default(), move |_sample| {
                c.fetch_add(1, Ordering::SeqCst);
            })
            .expect("declare");

        let fired = session
            .publish(
                "home/temp",
                b"22.5",
                PublishOptions::put().with_locality(Locality::SessionLocal),
            )
            .expect("loopback publish");
        assert_eq!(
            fired, 1,
            "{policy:?}: the MATCH count is the registry's answer and is \
             independent of who drains — only the timing of the callback moves"
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            expect_inline,
            "{policy:?}: callback-ran-before-publish-returned"
        );
        assert_eq!(
            session.has_pending_fires(),
            expect_inline == 0,
            "{policy:?}: a deferred delivery must be VISIBLE as pending, which \
             is what lets the host arm its drive loop to run it"
        );

        // Whoever drains next runs it — nothing was lost, only deferred.
        session.drain_deferred_fires();
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "{policy:?}: the fire is delivered exactly once either way"
        );
        assert!(!session.has_pending_fires());
    }
}

/// R311y554 — the hazard the publish-plane guard could not see, measured.
///
/// `Session::query` gates its drain on `allows_local`, and that drain takes the
/// WHOLE per-session queue, not the fires the query staged. So a default-
/// locality get — which is what `z_get` issues, since both zenoh-c's
/// `allowed_destination` default and `QueryOptions`' are `Any` — runs whatever
/// an inbound Push staged, on the caller's thread. `wz-capi-c`'s
/// `every_publish_this_crate_issues_is_remote_only` pinned the PUBLISH plane
/// against exactly this and the get walked through the same door.
///
/// Both arms share ONE `fires` queue (clone shares the Arc) and differ only in
/// the policy, so the assertion is about the policy and nothing else.
#[cfg(all(feature = "query-get", feature = "pubsub-allow-loop"))]
#[test]
fn a_default_locality_query_runs_fires_it_did_not_stage_unless_the_drain_is_deferred() {
    for (getter_policy, expect_ran) in [
        (LocalDeliveryDrain::Caller, 1usize),
        (LocalDeliveryDrain::DriveTask, 0usize),
    ] {
        let (base, _driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let _sub = base
            .declare_subscriber("home/temp", SubscribeOptions::default(), move |_sample| {
                c.fetch_add(1, Ordering::SeqCst);
            })
            .expect("declare");

        // Stage a subscriber fire that has NOTHING to do with the query below.
        let stager = base
            .clone()
            .with_local_delivery_drain(LocalDeliveryDrain::DriveTask);
        stager
            .publish(
                "home/temp",
                b"22.5",
                PublishOptions::put().with_locality(Locality::SessionLocal),
            )
            .expect("loopback publish");
        assert_eq!(counter.load(Ordering::SeqCst), 0, "staged, not run");

        // A get on an unrelated keyexpr, at the DEFAULT locality.
        let getter = base.clone().with_local_delivery_drain(getter_policy);
        let _handle = getter.query("other/key", QueryOptions::get(), |_reply| {}, |_rid| {});

        assert_eq!(
            counter.load(Ordering::SeqCst),
            expect_ran,
            "{getter_policy:?}: whether an unrelated get ran the staged \
             subscriber callback on the calling thread"
        );
    }
}
