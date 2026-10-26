// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The advanced subscriber's host on the cooperative engine, against a router stand-in that plays
//! the advanced publisher: it pushes sequenced samples, announces its heartbeat and its liveliness
//! token, and answers the subscriber's gets out of a real cache ring, as the publisher's own cache
//! queryable does. Each path of the host that the scripted-engine tests prove rule by rule is run
//! here on the engine it is for: the gap recovery, the heartbeat, the periodic re-ask and the
//! detection of a publisher that appears late. The engine reads nothing between two steps, so
//! what each test waits for is the host's own jobs run from the call that steps the session.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_capi_port::SessionEngine;
use wz_ext_pubsub::advanced_subscriber::{
    AdvancedSubscriberOptions, EngineSubscriber, HistoryConfig, RecoveryConfig,
};
use wz_session_core::serde_codec::z_serialize;

use super::{open, until, CatchAll, Command, Engine, Router};

/// The payloads the subscriber's callback was handed, in order.
type Delivered = Arc<Mutex<Vec<u8>>>;

/// A subscriber on `demo/data` of the engine, with `options`, and what it is handed.
fn subscribe(
    engine: &Arc<Engine>,
    router: &Router,
    options: AdvancedSubscriberOptions,
) -> (EngineSubscriber, Delivered) {
    let delivered: Delivered = Arc::new(Mutex::new(Vec::new()));
    let into = delivered.clone();
    let declares_before = router.seen(|s| s.declares);
    let port: Arc<dyn SessionEngine> = engine.clone();
    let subscriber = EngineSubscriber::declare(&port, "demo/data", options, move |sample| {
        into.lock().unwrap().push(sample.payload[0]);
    })
    .expect("the subscriber declares on the cooperative engine");
    until(engine, "the router to see the subscription", || {
        router.seen(|s| s.declares) > declares_before
    });
    (subscriber, delivered)
}

/// Step the engine until `expected` payloads were delivered, for at most five seconds, and say
/// what was delivered and what the router was asked when they were not.
fn wait_for(engine: &Arc<Engine>, router: &Router, delivered: &Delivered, expected: &[u8]) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while delivered.lock().unwrap().len() < expected.len() && std::time::Instant::now() < deadline {
        let _ = wz_capi_port::SessionDrive::read(&**engine, false);
    }
    assert_eq!(
        *delivered.lock().unwrap(),
        expected,
        "the router was asked {:?}",
        router.seen(|s| s.selectors.clone())
    );
}

/// A get answered with several replies hands its leg every one of them, the first among them,
/// before it ends. The cache of the advanced publisher answers a range this way, so a recovery
/// that loses the first of its replies is a recovery that is short by one.
#[test]
fn a_get_answered_with_several_replies_hands_the_leg_all_of_them() {
    use wz_session_core::query_mode::{ConsolidationMode, QueryTarget};
    use wz_session_core::query_options::QueryOptions;
    use wz_session_core::selector_params::ANYKE_PARAM;

    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    router.send(Command::HoldCache(&[1, 2, 3]));
    until(&engine, "the router to hold the cache", || {
        router.seen(|s| s.settled)
    });
    // The options of a recovery get: the replies answer on the samples' own key, which the
    // selector's `_anyke` admits, each once and with its timestamp.
    let mut options = QueryOptions::get()
        .with_expose_timestamp(true)
        .with_parameters(ANYKE_PARAM.as_bytes().to_vec())
        .with_target(QueryTarget::All)
        .with_consolidation(ConsolidationMode::None);
    // The publisher's cache is a peer's: the session's own queryables are not asked.
    options.allowed_destination = wz_session_core::locality::Locality::Remote;
    assert_eq!(
        options.resolved_consolidation(),
        ConsolidationMode::None,
        "the options ask for every reply"
    );
    let (issued, leg) = super::get::ask(&engine, "demo/data/@adv/**", &options, None, None, None);
    assert_eq!(issued, Some(1));
    until(&engine, "the leg to end", || leg.lock().unwrap().ended);
    let payloads: Vec<Vec<u8>> = leg
        .lock()
        .unwrap()
        .replies
        .iter()
        .map(|(_, _, payload)| payload.clone())
        .collect();
    assert_eq!(payloads, vec![vec![1], vec![2], vec![3]]);
}

/// A forward gap is buffered, the publisher's cache is asked for the range, and what it answers
/// is delivered in its place and in order, with the sample that arrived past the hole after it.
/// The selector the cache was asked names the hole.
#[test]
fn a_gap_is_filled_from_the_publishers_cache() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let (_subscriber, delivered) = subscribe(
        &engine,
        &router,
        AdvancedSubscriberOptions::default().with_recovery(RecoveryConfig::new()),
    );
    router.send(Command::HoldCache(&[1]));

    router.send(Command::PushSequenced("demo/data", &[0], 0));
    wait_for(&engine, &router, &delivered, &[0]);
    router.send(Command::PushSequenced("demo/data", &[2], 2));
    wait_for(&engine, &router, &delivered, &[0, 1, 2]);
    assert!(
        router.seen(|s| s.selectors.iter().any(|p| p.contains("_sn=1.."))),
        "the cache was asked for the hole: {:?}",
        router.seen(|s| s.selectors.clone())
    );
}

/// A heartbeat that announces a sequence number the subscriber has not reached asks the cache for
/// the range up to it, bounded, and what comes back is delivered in order.
#[test]
fn a_heartbeat_ahead_of_the_stream_asks_the_cache_for_the_range() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let (_subscriber, delivered) = subscribe(
        &engine,
        &router,
        AdvancedSubscriberOptions::default().with_recovery(RecoveryConfig::new().with_heartbeat()),
    );
    router.send(Command::HoldCache(&[2, 3]));

    router.send(Command::PushSequenced("demo/data", &[0], 0));
    router.send(Command::PushSequenced("demo/data", &[1], 1));
    wait_for(&engine, &router, &delivered, &[0, 1]);

    // The publisher's last number is 3, which no sample has said: a beacon is a plain push of the
    // number in the serialization format, on the publisher's own key.
    assert_eq!(z_serialize::<u32>(&3), [3, 0, 0, 0]);
    router.send(Command::Push("demo/data/@adv/pub/2/7/_", &[3, 0, 0, 0]));
    wait_for(&engine, &router, &delivered, &[0, 1, 2, 3]);
    assert!(
        router.seen(|s| s.selectors.iter().any(|p| p.contains("_sn=2..3"))),
        "the range asked was bounded by the beacon: {:?}",
        router.seen(|s| s.selectors.clone())
    );
}

/// A periodic re-ask is a job of the engine, run from the step: with no gap and no beacon, a
/// subscriber that has heard the source once asks the cache from the next number on, on its own,
/// and what it is answered is delivered.
#[test]
fn a_periodic_query_asks_for_what_followed_the_last_sample() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let (_subscriber, delivered) = subscribe(
        &engine,
        &router,
        AdvancedSubscriberOptions::default()
            .with_recovery(RecoveryConfig::new().with_periodic_queries(Duration::from_millis(100))),
    );
    router.send(Command::HoldCache(&[1, 2]));

    router.send(Command::PushSequenced("demo/data", &[0], 0));
    wait_for(&engine, &router, &delivered, &[0, 1, 2]);
    assert!(
        router.seen(|s| s.selectors.iter().any(|p| p.contains("_sn=1.."))),
        "the cache was asked from the number after the last one heard: {:?}",
        router.seen(|s| s.selectors.clone())
    );
}

/// A publisher that appears after the subscriber is detected through the liveliness token it
/// declares, and its cache is asked for what it holds. The control is the cache alone: it is held
/// before the token and the subscriber has not asked it.
#[test]
fn a_late_publisher_is_detected_and_its_cache_is_recovered() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let options = AdvancedSubscriberOptions::default()
        .with_recovery(RecoveryConfig::new())
        .with_history(HistoryConfig::new().detect_late_publishers());
    let (_subscriber, delivered) = subscribe(&engine, &router, options);
    router.send(Command::HoldCache(&[0, 1]));
    for _ in 0..20 {
        let _ = wz_capi_port::SessionDrive::read(&*engine, false);
    }
    assert!(
        delivered.lock().unwrap().is_empty(),
        "CONTROL: a cache nobody has announced is not asked"
    );

    router.send(Command::DeclareToken(1, "demo/data/@adv/pub/2/7/_"));
    wait_for(&engine, &router, &delivered, &[0, 1]);
}
