// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a plain put through a publisher's write filter costs the session: the takes of its lock and
//! the searches of what its peers declared, counted through the engine's test seams
//! (`CoopEngine::takes`, `CoopEngine::peer_looks`).

use std::sync::atomic::Ordering;

use wz_capi_port::{FilterId, FilterPlane, FilteredPut, SessionEngine, WireKey};
use wz_session_core::declare_form::InterestForm;
use wz_session_core::publish_options::PublishOptions;

use super::{open, until, CatchAll, Command, Engine, Router};

/// A write filter on `key` that asks the router who subscribes to it.
fn filter_on(engine: &Engine, key: &str) -> FilterId {
    engine
        .declare_write_filter(
            FilterPlane::Subscribers,
            key.to_owned(),
            &WireKey::literal(),
            Some(InterestForm {
                mapping_id: 0,
                suffix: Some(key.to_owned()),
                aggregate: false,
            }),
            false,
        )
        .expect("a session with ids left declares")
}

/// How many times the session's lock was taken since the open.
fn takes(engine: &Engine) -> usize {
    engine.takes.core.load(Ordering::SeqCst)
}

/// A plain put through a write filter takes the session's lock once, for the filter's answer and
/// its send together, whether the filter holds it back or lets it through, as zenoh-pico's put
/// reads its filter's state and takes its transmit lock alone. The filter's own question takes it
/// once too, on a build with groups as on one without.
#[test]
fn a_plain_put_through_a_write_filter_takes_the_session_once() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let filter = filter_on(&engine, "demo/x");
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) > 0
    });
    let params = PublishOptions::put()
        .plain_put_params()
        .expect("a plain put");

    let before = takes(&engine);
    assert_eq!(
        engine.put_plain_filtered(filter, "demo/x", 0, b"v", &params),
        FilteredPut::Suppressed,
        "no subscriber yet: the put is held back"
    );
    assert_eq!(takes(&engine) - before, 1, "a held-back put takes it once");

    router.send(Command::DeclareSubscriber(1, "demo/**"));
    until(&engine, "the filter to open", || {
        !engine.write_filter_active(filter)
    });
    let before = takes(&engine);
    for _ in 0..10 {
        assert_eq!(
            engine.put_plain_filtered(filter, "demo/x", 0, b"v", &params),
            FilteredPut::Sent(Ok(0))
        );
    }
    assert_eq!(takes(&engine) - before, 10, "one take a put that is sent");
    until(&engine, "the router to receive the puts", || {
        router.seen(|s| s.pushes) == 10
    });

    let before = takes(&engine);
    assert!(!engine.write_filter_holds_back(filter));
    assert_eq!(
        takes(&engine) - before,
        1,
        "the filter's question takes it once"
    );
}

/// How many times what the peers declared was searched since the open.
fn looks(engine: &Engine) -> usize {
    engine.peer_looks()
}

/// A filter's answer read off what its peers declared is kept for the puts after it until a face's
/// tables are written: a stream of puts searches the declarations no more, as zenoh-pico's filter
/// keeps its state between the declarations that move it. A declaration that arrives writes the
/// faces' tables, and the next put searches again (the CONTROL that the count sees a search), then
/// keeps that answer.
#[test]
fn a_write_filters_answer_is_kept_until_a_face_is_written() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let filter = filter_on(&engine, "demo/x");
    let other = filter_on(&engine, "other/x");
    until(&engine, "the router to see the Interests", || {
        router.seen(|s| s.interests) >= 2
    });
    let params = PublishOptions::put()
        .plain_put_params()
        .expect("a plain put");
    router.send(Command::DeclareSubscriber(1, "demo/**"));
    until(&engine, "the filter to open", || {
        !engine.write_filter_active(filter)
    });

    let before = looks(&engine);
    for _ in 0..10 {
        assert_eq!(
            engine.put_plain_filtered(filter, "demo/x", 0, b"v", &params),
            FilteredPut::Sent(Ok(0))
        );
    }
    assert_eq!(looks(&engine), before, "no search while no face is written");

    router.send(Command::DeclareSubscriber(2, "other/**"));
    until(&engine, "the other filter to open", || {
        !engine.write_filter_active(other)
    });
    let before = looks(&engine);
    assert_eq!(
        engine.put_plain_filtered(filter, "demo/x", 0, b"v", &params),
        FilteredPut::Sent(Ok(0))
    );
    assert_eq!(
        looks(&engine) - before,
        1,
        "CONTROL: a face was written since the answer was read, so it is read again"
    );
    for _ in 0..9 {
        assert_eq!(
            engine.put_plain_filtered(filter, "demo/x", 0, b"v", &params),
            FilteredPut::Sent(Ok(0))
        );
    }
    assert_eq!(looks(&engine) - before, 1, "and that answer is kept");
}
