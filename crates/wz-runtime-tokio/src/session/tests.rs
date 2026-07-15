// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
        QueryOptions::get(),
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
    assert_eq!(got.body, InboundReplyBody::Del { source_info: None });
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
    assert_eq!(
        keys.len(),
        3,
        "wildcard admin GET fires local_data + config + metrics"
    );
    assert!(keys.contains(&root), "local_data reply present");
    assert!(keys.contains(&config), "config reply present");
    assert!(keys.contains(&metrics), "metrics reply present");
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

#[cfg(feature = "query-get")]
#[test]
fn query_options_default_query_metadata_is_empty() {
    let meta = QueryOptions::default().query_metadata();
    assert!(
        meta.is_empty(),
        "default options produce empty wire metadata"
    );
}

#[cfg(feature = "query-get")]
#[test]
fn query_wire_branch_with_empty_meta_emits_no_meta_fast_path_frame() {
    // Session::query with default options (Locality::Any, no
    // metadata) MUST take the no-meta fast path → wire frame is
    // byte-identical to a standalone send_request_query call.
    // Pins the R240 short-circuit invariant at the Session
    // level.
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

    // Re-encode an equivalent standalone Request with target=All
    // and assert the wire bytes appear verbatim in the recorded
    // frame.
    use crate::session_glue::build_request_query_with_target;
    let standalone =
        build_request_query_with_target(0, 0, Some("home/temp"), QueryTarget::AllComplete).unwrap();
    let standalone_bytes = standalone
        .try_as_borrowed()
        .expect("test: <=N exts by construction")
        .encode_to_vec();
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

    use crate::session_glue::build_request_query_with_attachment;
    let standalone =
        build_request_query_with_attachment(0, 0, Some("home/temp"), b"q-att").unwrap();
    let standalone_bytes = standalone
        .try_as_borrowed()
        .expect("test: <=N exts by construction")
        .encode_to_vec();
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

    use crate::session_glue::build_request_query_with_consolidation;
    let standalone =
        build_request_query_with_consolidation(0, 0, Some("home/temp"), ConsolidationMode::Latest)
            .unwrap();
    let standalone_bytes = standalone
        .try_as_borrowed()
        .expect("test: <=N exts by construction")
        .encode_to_vec();
    let frame = driver.frame_bytes(0);
    assert!(
        frame
            .windows(standalone_bytes.len())
            .any(|w| w == standalone_bytes),
        "wire frame must contain with-consolidation Request bytes"
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
#[cfg(all(feature = "query-get", not(feature = "query-target")))]
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

/// R311hu — NEG / isolation counterpart for `query-consolidation`
/// (see the `query-target` guard above for the rationale). With the
/// feature off, `QueryOptions::with_consolidation` is a
/// signature-stable no-op: the Q_C flag and its consolidation byte
/// must be absent, so the outbound frame must equal the bare
/// no-metadata baseline.
#[cfg(all(feature = "query-get", not(feature = "query-consolidation")))]
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

    // Verify the recorded frame is byte-equivalent to a standalone
    // build_request_query with mapping_id=7.
    use crate::session_glue::build_request_query;
    let standalone = build_request_query(0, 7, None).unwrap();
    let standalone_bytes = standalone
        .try_as_borrowed()
        .expect("test: <=N exts by construction")
        .encode_to_vec();
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
            QueryOptions::get(),
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
            QueryOptions::get(),
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
            QueryOptions::get(),
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

    use crate::session_glue::build_request_query_with_attachment;
    let standalone = build_request_query_with_attachment(0, 7, None, b"q-att").unwrap();
    let standalone_bytes = standalone
        .try_as_borrowed()
        .expect("test: <=N exts by construction")
        .encode_to_vec();
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

    use crate::session_glue::build_request_query_with_target;
    let standalone =
        build_request_query_with_target(0, 0, Some("home/temp"), QueryTarget::All).unwrap();
    let standalone_bytes = standalone
        .try_as_borrowed()
        .expect("test: <=N exts by construction")
        .encode_to_vec();
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

// ── R246 Queryable + QueryableOptions + declare_queryable{,_aliased} ──

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

#[test]
fn declare_queryable_session_local_does_not_emit_wire_frame() {
    // R311ow — pico parity (`_z_register_queryable`, primitives.c:348): a
    // SessionLocal queryable registers locally only; `allowed_origin` does not
    // allow remote, so NO `Declare(DeclQueryable)` is announced. (This is the
    // surviving half of the old `declare_queryable_does_not_emit_wire_frame` —
    // the wire-no-op is now the session-local case, not the default.)
    let (session, driver) = build_session();
    let _q = session.declare_queryable(
        "home/temp",
        QueryableOptions::new().with_allowed_origin(Locality::SessionLocal),
        |_q, _r| {},
    );
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

#[cfg(feature = "query-get")]
#[test]
fn declare_queryable_with_locality_remote_skips_loopback_query() {
    let (session, _driver) = build_session();
    let fired = Arc::new(AtomicUsize::new(0));
    let fired_cb = fired.clone();
    let _q = session.declare_queryable(
        "home/temp",
        QueryableOptions::new().with_allowed_origin(Locality::Remote),
        move |_q, _r| {
            fired_cb.fetch_add(1, Ordering::SeqCst);
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
    assert!(log.lock().unwrap().is_empty(), "registration never fires");

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
    // the inner listener (registered during the previous fire, seeded
    // with the then-current `true` verdict) observes the flip.
    dispatch(&make_undecl_subscriber(2));
    assert_eq!(
        *observed.lock().unwrap(),
        vec![true],
        "self-undeclared outer listener never fires again"
    );
    assert_eq!(
        *inner_log.lock().unwrap(),
        vec![false],
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
