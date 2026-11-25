// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a plain put through a publisher's write filter costs the session: the takes of its lock and
//! the searches of what its peers declared, counted through the engine's test seams
//! (`CoopEngine::takes`, `CoopEngine::peer_looks`).

use std::sync::atomic::Ordering;

use wz_capi_port::{FilterId, FilterPlane, FilteredPut, SessionEngine, WireKey};
use wz_session_core::declare_form::InterestAsk;
use wz_session_core::publish_options::PublishOptions;

use super::{open, until, CatchAll, Command, Engine, Router};

/// A write filter on `key` that asks the router who subscribes to it.
fn filter_on(engine: &Engine, key: &str) -> FilterId {
    engine
        .declare_write_filter(
            FilterPlane::Subscribers,
            key,
            &WireKey::literal(),
            Some(InterestAsk {
                mapping_id: 0,
                suffix: Some(key),
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
        engine.put_plain_filtered(
            filter,
            "demo/x",
            wz_session_core::session_tables::KeyexprRef::by_id(0),
            b"v",
            &params
        ),
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
            engine.put_plain_filtered(
                filter,
                "demo/x",
                wz_session_core::session_tables::KeyexprRef::by_id(0),
                b"v",
                &params
            ),
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
            engine.put_plain_filtered(
                filter,
                "demo/x",
                wz_session_core::session_tables::KeyexprRef::by_id(0),
                b"v",
                &params
            ),
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
        engine.put_plain_filtered(
            filter,
            "demo/x",
            wz_session_core::session_tables::KeyexprRef::by_id(0),
            b"v",
            &params
        ),
        FilteredPut::Sent(Ok(0))
    );
    assert_eq!(
        looks(&engine) - before,
        1,
        "CONTROL: a face was written since the answer was read, so it is read again"
    );
    for _ in 0..9 {
        assert_eq!(
            engine.put_plain_filtered(
                filter,
                "demo/x",
                wz_session_core::session_tables::KeyexprRef::by_id(0),
                b"v",
                &params
            ),
            FilteredPut::Sent(Ok(0))
        );
    }
    assert_eq!(looks(&engine) - before, 1, "and that answer is kept");
}

/// How many sends on a face were marked as the session holder's since the open.
fn face_marks(engine: &Engine) -> usize {
    engine.takes.face_marks.load(Ordering::SeqCst)
}

/// A plain put through a write filter is sent to each face marked as the session holder's send on
/// it, as a publish is: a droppable publish that finds the session held by it reads which face the
/// send holds, and not a step it waits behind. CONTROL: the general publish marks its one face
/// too. Turned red by a filtered put that sends to the links unmarked.
#[test]
fn a_plain_put_through_a_write_filter_marks_its_send_on_each_face() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let filter = filter_on(&engine, "demo/x");
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) > 0
    });
    router.send(Command::DeclareSubscriber(1, "demo/**"));
    until(&engine, "the filter to open", || {
        !engine.write_filter_active(filter)
    });

    let before = face_marks(&engine);
    let published =
        engine.publish_on_wire_all("demo/x", &WireKey::literal(), b"v", &PublishOptions::put());
    assert!(published.is_ok(), "the publish is sent");
    assert_eq!(
        face_marks(&engine) - before,
        1,
        "CONTROL: the publish marks its one face"
    );

    let params = PublishOptions::put()
        .plain_put_params()
        .expect("a plain put");
    let before = face_marks(&engine);
    assert_eq!(
        engine.put_plain_filtered(
            filter,
            "demo/x",
            wz_session_core::session_tables::KeyexprRef::by_id(0),
            b"v",
            &params
        ),
        FilteredPut::Sent(Ok(0))
    );
    assert_eq!(
        face_marks(&engine) - before,
        1,
        "the filtered put marks its one face"
    );
}

/// How many face sends of a plain put were written from the head its publisher's plain way made.
#[cfg(not(feature = "shared-key-ids"))]
fn planned(engine: &Engine) -> usize {
    engine.takes.planned.load(Ordering::SeqCst)
}

/// A put on a declared key that brings nothing of its own is written from the head its plain way
/// made when the publisher stated it: each face send of it counts as planned, and each reaches the
/// router. CONTROL: a way the caller gives (`put_plain_filtered`) brings no head, and a way kept on
/// the literal key has none, and both are still sent. Turned red by a plain way that keeps no head,
/// or by a send that writes the head for a key its link does not name by the declaration. A build
/// with the shared key ids may name the key its own way on a link, so the plain way declines the
/// put there and the test is not built.
#[cfg(not(feature = "shared-key-ids"))]
#[test]
fn a_put_on_a_declared_key_is_written_from_its_plain_ways_head() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let hold = engine
        .acquire_keyexpr("demo/x")
        .expect("a session with ids left declares");
    let wire = WireKey::aliased(hold.mapping_id(), None).at_row(hold.row());
    let filter = filter_on(&engine, "demo/x");
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) > 0
    });
    router.send(Command::DeclareSubscriber(1, "demo/**"));
    until(&engine, "the filter to open", || {
        !engine.write_filter_active(filter)
    });
    let params = PublishOptions::put()
        .plain_put_params()
        .expect("a plain put");
    engine.keep_write_filter_plain(filter, Some((params, wire.declared())));

    let before = planned(&engine);
    for _ in 0..3 {
        assert_eq!(
            engine.publish_filtered(filter, "demo/x", &wire, b"v", None),
            FilteredPut::Sent(Ok(0))
        );
    }
    assert_eq!(
        planned(&engine) - before,
        3,
        "each put is written from its head"
    );
    until(&engine, "the router to receive the puts", || {
        router.seen(|s| s.pushes) == 3
    });

    let before = planned(&engine);
    assert_eq!(
        engine.put_plain_filtered(filter, "demo/x", wire.declared(), b"v", &params),
        FilteredPut::Sent(Ok(0))
    );
    assert_eq!(
        planned(&engine),
        before,
        "CONTROL: a way the caller gives brings no head"
    );
    engine.keep_write_filter_plain(
        filter,
        Some((
            params,
            wz_session_core::session_tables::KeyexprRef::by_id(0),
        )),
    );
    assert_eq!(
        engine.publish_filtered(filter, "demo/x", &WireKey::literal(), b"v", None),
        FilteredPut::Sent(Ok(0))
    );
    assert_eq!(
        planned(&engine),
        before,
        "CONTROL: the literal key has no head"
    );
    until(&engine, "the router to receive every put", || {
        router.seen(|s| s.pushes) == 5
    });
}
