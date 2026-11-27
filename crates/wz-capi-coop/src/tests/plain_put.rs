// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a plain put through a publisher's write filter costs the session: the takes of its lock and
//! the searches of what its peers declared, counted through the engine's test seams
//! (`CoopEngine::takes`, `CoopEngine::peer_looks`).

use std::sync::atomic::Ordering;

use wz_capi_port::{
    FilterId, FilterPlane, FilteredPut, KeyHold, PeerLists, SessionDrive, SessionEngine, WireKey,
};
use wz_session_core::declare_form::InterestAsk;
use wz_session_core::publish_options::{PlainPutParams, PublishOptions};
use wz_session_core::reliability::Reliability;

use super::{config, open, open_with, until, CatchAll, Command, Engine, Router};
use crate::CoopConfig;

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
        .id
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

/// A put with options of a publisher asks its write filter under the take its own leg makes: held
/// back, it takes the session once and sends nothing; let through, each takes it once and is sent.
/// A build that delivers to the session's own subscribers takes it once more for a sent put whose
/// destination admits them, to find them (`CoopEngine::publish_to_subscribers`), whatever the
/// filter answered, and so does the general publish without a filter. Turned red by a put with
/// options that asks its filter by a take of its own before it publishes, or by one held back
/// whose leg still sends.
#[test]
fn a_put_with_options_asks_its_filter_under_its_own_take() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let filter = filter_on(&engine, "demo/x");
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) > 0
    });
    let options = PublishOptions::put().with_attachment(b"a");

    let before = takes(&engine);
    assert_eq!(
        engine.publish_filtered(filter, "demo/x", &WireKey::literal(), b"v", Some(&options)),
        FilteredPut::Suppressed,
        "no subscriber yet: the put is held back"
    );
    assert_eq!(
        takes(&engine) - before,
        1,
        "a held-back put with options takes it once"
    );

    router.send(Command::DeclareSubscriber(1, "demo/**"));
    until(&engine, "the filter to open", || {
        !engine.write_filter_active(filter)
    });
    let local = usize::from(cfg!(feature = "local-subscriber"));
    let before = takes(&engine);
    for _ in 0..3 {
        assert!(matches!(
            engine.publish_filtered(filter, "demo/x", &WireKey::literal(), b"v", Some(&options)),
            FilteredPut::Sent(Ok(_))
        ));
    }
    assert_eq!(
        takes(&engine) - before,
        3 * (1 + local),
        "one take a put with options that is sent, and one for the session's own subscribers"
    );
    until(&engine, "the router to receive the puts", || {
        router.seen(|s| s.pushes) == 3
    });
    assert_eq!(
        router.seen(|s| s.pushes),
        3,
        "and the held-back one was not sent"
    );
}

/// A put none of whose legs reaches the session, its one link lost, is answered under one take of
/// its own and sends nothing: a bare put of its publisher's way and one with options alike are
/// held back by a filter nothing opened. The session dials its router again, so it outlives the
/// link: one that dials none ends with its one link, and a closed session holds nothing back.
/// Turned red by a put that asks its filter by two takes once no leg holds the session, or by one
/// answered as sent by a filter that holds it back.
#[test]
fn a_put_with_no_link_up_is_answered_under_one_take() {
    let router = Router::start(CatchAll::None);
    let engine = open_with(CoopConfig {
        redial_ms: Some(50),
        open_timeout_ms: 300,
        ..config(&router)
    });
    let hold = engine
        .acquire_keyexpr("demo/x")
        .expect("a session with ids left declares");
    let wire = WireKey::aliased(hold.mapping_id(), None).at_row(hold.row());
    let filter = filter_on(&engine, "demo/x");
    let params = PublishOptions::put()
        .plain_put_params()
        .expect("a plain put");
    engine.keep_write_filter_plain(filter, Some((params, wire.declared())));
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) > 0
    });
    router.send(Command::Close);
    drop(router);
    until(&engine, "the link to be lost", || {
        engine.peer_identities().is_empty()
    });
    assert!(
        !SessionDrive::is_closed(&*engine),
        "the session outlives its link"
    );
    assert!(
        engine.write_filter_active(filter),
        "nothing opened the filter"
    );

    let options = PublishOptions::put().with_attachment(b"a");
    for opts in [None, Some(&options)] {
        let before = takes(&engine);
        assert_eq!(
            engine.publish_filtered(filter, "demo/x", &wire, b"v", opts),
            FilteredPut::Suppressed,
            "a filter nothing opened holds the put back"
        );
        assert_eq!(takes(&engine) - before, 1, "one take for its answer");
    }
}

/// A plain put whose destination admits no peer is answered as sent, to none, under one take for
/// its filter's answer, and reaches no link. CONTROL: the same put to any destination reaches the
/// router. Turned red by a plain put sent to the links its destination does not admit, or by one
/// that takes the session twice for its answer.
#[test]
fn a_plain_put_for_the_session_alone_reaches_no_link() {
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
    let local = PublishOptions::put()
        .with_locality(wz_session_core::locality::Locality::SessionLocal)
        .plain_put_params()
        .expect("a plain put");
    let before = takes(&engine);
    assert_eq!(
        engine.put_plain_filtered(
            filter,
            "demo/x",
            wz_session_core::session_tables::KeyexprRef::by_id(0),
            b"v",
            &local
        ),
        FilteredPut::Sent(Ok(0))
    );
    assert_eq!(takes(&engine) - before, 1, "one take for its answer");

    let any = PublishOptions::put()
        .plain_put_params()
        .expect("a plain put");
    assert_eq!(
        engine.put_plain_filtered(
            filter,
            "demo/x",
            wz_session_core::session_tables::KeyexprRef::by_id(0),
            b"v",
            &any
        ),
        FilteredPut::Sent(Ok(0))
    );
    until(
        &engine,
        "the router to receive the put to any destination",
        || router.seen(|s| s.pushes) == 1,
    );
    assert_eq!(
        router.seen(|s| s.pushes),
        1,
        "CONTROL: only the put to any destination was sent"
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
fn planned(engine: &Engine) -> usize {
    engine.takes.planned.load(Ordering::SeqCst)
}

/// A put on a declared key that brings nothing of its own is written from the head its plain way
/// made when the publisher stated it: each face send of it counts as planned, and each reaches the
/// router. A way the caller gives (`put_plain_filtered`) on the same key is written from that head
/// too. CONTROL: a way kept on the literal key has none, and its put is still sent. Turned red by a
/// plain way that keeps no head, by a given way that does not take its row's head, or by a send
/// that writes the head for a key its link does not name by the declaration.
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
        planned(&engine) - before,
        1,
        "a way the caller gives on the plan's key is written from its row's head"
    );
    let before = planned(&engine);
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

/// A publish with options of a publisher whose plan its declare made is written from the plan's
/// head when the options leave it a plain put: each counts as planned and reaches the router.
/// CONTROL: the same publish made by no publisher (`publish_on_wire_all`), and one whose options
/// carry an attachment, are written from their parts and still sent. Turned red by a publish that
/// does not take its publisher's plan, or by one that takes it for a put that is not plain.
#[cfg(not(feature = "shared-key-ids"))]
#[test]
fn a_plain_publish_of_a_publisher_is_written_from_its_plan() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let hold = engine
        .acquire_keyexpr("demo/y")
        .expect("a session with ids left declares");
    let wire = WireKey::aliased(hold.mapping_id(), None).at_row(hold.row());
    let filter = filter_on(&engine, "demo/y");
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
    let options = PublishOptions::put();
    for _ in 0..2 {
        assert!(matches!(
            engine.publish_filtered(filter, "demo/y", &wire, b"v", Some(&options)),
            FilteredPut::Sent(Ok(_))
        ));
    }
    assert_eq!(
        planned(&engine) - before,
        2,
        "each publish is written from its publisher's plan"
    );

    let before = planned(&engine);
    assert!(engine
        .publish_on_wire_all("demo/y", &wire, b"v", &options)
        .is_ok());
    let attached = PublishOptions::put().with_attachment(b"a");
    assert!(matches!(
        engine.publish_filtered(filter, "demo/y", &wire, b"v", Some(&attached)),
        FilteredPut::Sent(Ok(_))
    ));
    assert_eq!(
        planned(&engine),
        before,
        "CONTROL: no publisher's plan, and a put that is not plain, take no head"
    );
    until(&engine, "the router to receive every publish", || {
        router.seen(|s| s.pushes) == 4
    });
}

/// How many plain puts of a write filter's own way were written from its plan.
fn plans(engine: &Engine) -> usize {
    engine.takes.plans.load(Ordering::SeqCst)
}

/// How many keys the session's tables named for a plain put through a write filter.
fn namings(engine: &Engine) -> usize {
    engine.takes.namings.load(Ordering::SeqCst)
}

/// A publisher's way on the declared key `key` under `demo/`, its filter opened by the router's
/// subscriber: the declaration's hold, the filter and the key as the publisher names it.
fn way_on(engine: &Engine, router: &Router, key: &str) -> (KeyHold, FilterId, WireKey) {
    let params = PublishOptions::put()
        .plain_put_params()
        .expect("a plain put");
    way_with(engine, router, key, params)
}

/// `way_on` whose bare put is sent from `params`. The router declares the subscriber that opens
/// the filter whether or not it holds a catch-all, which it tells a session only in answer to an
/// Interest, and its session answers one only with `interest-answer` (`CatchAll`). Where it does,
/// the filter opens at the first of the two declarations; the other moves the send epoch only at
/// the step that reads it, so the puts made between two steps share one epoch.
fn way_with(
    engine: &Engine,
    router: &Router,
    key: &str,
    params: PlainPutParams,
) -> (KeyHold, FilterId, WireKey) {
    let hold = engine
        .acquire_keyexpr(key)
        .expect("a session with ids left declares");
    let wire = WireKey::aliased(hold.mapping_id(), None).at_row(hold.row());
    let filter = filter_on(engine, key);
    until(engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) > 0
    });
    router.send(Command::DeclareSubscriber(1, "demo/**"));
    until(engine, "the filter to open", || {
        !engine.write_filter_active(filter)
    });
    engine.keep_write_filter_plain(filter, Some((params, wire.declared())));
    (hold, filter, wire)
}

/// The bare puts of a publisher at one send epoch: the first is sent by its filter's answer and
/// its key's naming, and plans its way; each after it is written from the plan, its key named no
/// more, and every one from the head. CONTROL: a way the caller gives (`put_plain_filtered`) names
/// its key at each put. Turned red by a way never planned, by a planned put that names its key or
/// reads its filter again, or by a planned put not written from the head.
#[test]
fn the_puts_of_a_publisher_at_one_send_epoch_are_written_from_its_plan() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let (_hold, filter, wire) = way_on(&engine, &router, "demo/x");

    let (plans_before, named_before, heads_before) =
        (plans(&engine), namings(&engine), planned(&engine));
    for _ in 0..4 {
        assert_eq!(
            engine.publish_filtered(filter, "demo/x", &wire, b"v", None),
            FilteredPut::Sent(Ok(0))
        );
    }
    assert_eq!(
        namings(&engine) - named_before,
        1,
        "the first put names its key, and plans"
    );
    assert_eq!(
        plans(&engine) - plans_before,
        3,
        "each put after it is written from the plan"
    );
    assert_eq!(
        planned(&engine) - heads_before,
        4,
        "every put is written from the head"
    );

    let params = PublishOptions::put()
        .plain_put_params()
        .expect("a plain put");
    let (plans_before, named_before) = (plans(&engine), namings(&engine));
    for _ in 0..2 {
        assert_eq!(
            engine.put_plain_filtered(filter, "demo/x", wire.declared(), b"v", &params),
            FilteredPut::Sent(Ok(0))
        );
    }
    assert_eq!(
        namings(&engine) - named_before,
        2,
        "CONTROL: a given way names its key at each put"
    );
    assert_eq!(plans(&engine), plans_before, "and takes no plan");
    until(&engine, "the router to receive every put", || {
        router.seen(|s| s.pushes) == 6
    });
}

/// How often a put looked its write filter's row up since the open.
fn filter_rows(engine: &Engine) -> usize {
    engine.filter_rows()
}

/// A put through a publisher's write filter looks the filter's row up once, for its plan, its
/// filter's answer and the head its plain way wrote, which the leg's send writes it from: a planned
/// bare put and a put with options once each, and the first bare put at a send epoch once more,
/// to plan its way. The put with options is still written from that head where its build names
/// the key by the head's declaration. CONTROL: a publish no publisher made has no row to look up.
/// Turned red by a leg that looks the row up again to find the head, or by a put with options
/// handed no head by its decision.
#[test]
fn a_put_looks_its_write_filters_row_up_once() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let (_hold, filter, wire) = way_on(&engine, &router, "demo/x");

    let before = filter_rows(&engine);
    assert_eq!(
        engine.publish_filtered(filter, "demo/x", &wire, b"v", None),
        FilteredPut::Sent(Ok(0))
    );
    assert_eq!(
        filter_rows(&engine) - before,
        2,
        "the first bare put looks it up to send, and again to plan its way"
    );

    let before = filter_rows(&engine);
    assert_eq!(
        engine.publish_filtered(filter, "demo/x", &wire, b"v", None),
        FilteredPut::Sent(Ok(0))
    );
    assert_eq!(
        filter_rows(&engine) - before,
        1,
        "a planned put looks it up once"
    );

    let options = PublishOptions::put();
    let (before, heads) = (filter_rows(&engine), planned(&engine));
    assert!(matches!(
        engine.publish_filtered(filter, "demo/x", &wire, b"v", Some(&options)),
        FilteredPut::Sent(Ok(_))
    ));
    assert_eq!(
        filter_rows(&engine) - before,
        1,
        "a put with options looks it up once"
    );
    if cfg!(not(feature = "shared-key-ids")) {
        assert_eq!(
            planned(&engine) - heads,
            1,
            "and is written from the head its decision read"
        );
    }

    let before = filter_rows(&engine);
    assert!(engine
        .publish_on_wire_all("demo/x", &wire, b"v", &options)
        .is_ok());
    assert_eq!(
        filter_rows(&engine),
        before,
        "CONTROL: a publish no publisher made looks up no row"
    );
    until(&engine, "the router to receive every put", || {
        router.seen(|s| s.pushes) == 4
    });
}

/// A bare put plans its publisher's way by the key its leg named, the one it is sent on: a
/// publisher whose filter is on `demo/x` that puts on `demo/z`, under the declaration of
/// `demo/x`, plans nothing, so the first of its puts on `demo/x` after them is named and plans,
/// and each put reaches the router on the key it was made on, as the router's catch-all records
/// them. Turned red by a plan made of the filter's key in place of the key the put's leg named,
/// which a put on `demo/z` would make and the first put on `demo/x` would be written from.
#[test]
fn a_put_plans_its_way_by_the_key_its_leg_named() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);
    let (_hold, filter, wire) = way_on(&engine, &router, "demo/x");

    let before = plans(&engine);
    for _ in 0..2 {
        assert_eq!(
            engine.publish_filtered(filter, "demo/z", &wire, b"z", None),
            FilteredPut::Sent(Ok(0))
        );
    }
    assert_eq!(
        plans(&engine),
        before,
        "a put on a key other than its filter's plans nothing"
    );
    let named_before = namings(&engine);
    for _ in 0..2 {
        assert_eq!(
            engine.publish_filtered(filter, "demo/x", &wire, b"x", None),
            FilteredPut::Sent(Ok(0))
        );
    }
    assert_eq!(
        (namings(&engine) - named_before, plans(&engine) - before),
        (1, 1),
        "the first put on its filter's key is named and plans, the second is planned"
    );
    until(&engine, "the router to receive every put", || {
        router.seen(|s| s.samples.len()) == 4
    });
    let on = |key: &str| router.seen(|s| s.samples.iter().filter(|(k, _)| k == key).count());
    assert_eq!(
        (on("demo/z"), on("demo/x")),
        (2, 2),
        "each put reaches the router on the key it was made on"
    );
}

/// A plan is its filter's key's alone: once a publisher's way on `demo/x` is planned, a bare put
/// through its filter on `demo/z` at the same send epoch is sent with its own key named and
/// reaches the router on `demo/z`, and the plan stands for the put on `demo/x` after it. CONTROL:
/// the second put on `demo/x` before it is written from the plan. Turned red by a plan taken by
/// its epoch alone (`WriteFilterRow::planned_put` comparing no key), whose put on `demo/z` is
/// written on the filter's key, or by a put on another key that drops the plan.
#[test]
fn a_plan_is_taken_for_its_filters_key_alone() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);
    let (_hold, filter, wire) = way_on(&engine, &router, "demo/x");

    let before = plans(&engine);
    for _ in 0..2 {
        assert_eq!(
            engine.publish_filtered(filter, "demo/x", &wire, b"x", None),
            FilteredPut::Sent(Ok(0))
        );
    }
    assert_eq!(
        plans(&engine) - before,
        1,
        "CONTROL: the second put on its filter's key is written from the plan"
    );

    let (before, named_before) = (plans(&engine), namings(&engine));
    assert_eq!(
        engine.publish_filtered(filter, "demo/z", &wire, b"z", None),
        FilteredPut::Sent(Ok(0))
    );
    assert_eq!(
        (plans(&engine) - before, namings(&engine) - named_before),
        (0, 1),
        "a put on another key is sent with its key named, not from the plan"
    );
    assert_eq!(
        engine.publish_filtered(filter, "demo/x", &wire, b"x", None),
        FilteredPut::Sent(Ok(0))
    );
    assert_eq!(
        plans(&engine) - before,
        1,
        "and the plan stands for the put on its filter's key after it"
    );
    until(&engine, "the router to receive every put", || {
        router.seen(|s| s.samples.len()) == 4
    });
    let on = |key: &str| router.seen(|s| s.samples.iter().filter(|(k, _)| k == key).count());
    assert_eq!(
        (on("demo/z"), on("demo/x")),
        (1, 3),
        "the put on another key reaches the router on its own key"
    );
}

/// How often the session's send epoch was read since the open.
fn epoch_reads(engine: &Engine) -> usize {
    engine.epoch_reads()
}

/// A bare put of a publisher's way reads the session's send epoch once: the first at an epoch to
/// look for its plan, which it then plans the way at once it is sent, and each after it to find
/// the plan standing there. CONTROL: a put with options and a put of a way its caller gives look
/// for no plan and read none. Turned red by a leg that reads the epoch a second time to plan the
/// way.
#[test]
fn a_bare_put_reads_the_send_epoch_once() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let (_hold, filter, wire) = way_on(&engine, &router, "demo/x");

    let (before, plans_before) = (epoch_reads(&engine), plans(&engine));
    assert_eq!(
        engine.publish_filtered(filter, "demo/x", &wire, b"v", None),
        FilteredPut::Sent(Ok(0))
    );
    assert_eq!(
        epoch_reads(&engine) - before,
        1,
        "the first put reads it to look for its plan, and plans at that reading"
    );
    let before = epoch_reads(&engine);
    assert_eq!(
        engine.publish_filtered(filter, "demo/x", &wire, b"v", None),
        FilteredPut::Sent(Ok(0))
    );
    assert_eq!(
        epoch_reads(&engine) - before,
        1,
        "a planned put reads it once"
    );
    assert_eq!(
        plans(&engine) - plans_before,
        1,
        "CONTROL: the second put is written from the plan made at the first one's reading"
    );

    let options = PublishOptions::put();
    let params = PublishOptions::put()
        .plain_put_params()
        .expect("a plain put");
    let before = epoch_reads(&engine);
    assert!(matches!(
        engine.publish_filtered(filter, "demo/x", &wire, b"v", Some(&options)),
        FilteredPut::Sent(Ok(_))
    ));
    assert_eq!(
        engine.put_plain_filtered(filter, "demo/x", wire.declared(), b"v", &params),
        FilteredPut::Sent(Ok(0))
    );
    assert_eq!(
        epoch_reads(&engine),
        before,
        "CONTROL: a put with options and a given way read no epoch"
    );
    until(&engine, "the router to receive every put", || {
        router.seen(|s| s.pushes) == 4
    });
}

/// How many links a put's plan asked how they name its key since the open.
fn plan_links(engine: &Engine) -> usize {
    engine.plan_links()
}

/// The first bare put at a send epoch plans its publisher's way asking the links how they name its
/// key only where a link may name a key its own way (`shared-key-ids`): there each link up is
/// asked once; without them every link names every key as the session does, and none is asked.
/// CONTROL: the put after it is written from the plan either way. Turned red by a plan that walks
/// the links in a build whose links all name a key the session's way, or by one that asks none
/// where a link may name it its own way.
#[test]
fn a_plan_asks_the_links_only_where_they_name_keys_their_own_way() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let (_hold, filter, wire) = way_on(&engine, &router, "demo/x");

    let (asked, plans_before) = (plan_links(&engine), plans(&engine));
    for _ in 0..2 {
        assert_eq!(
            engine.publish_filtered(filter, "demo/x", &wire, b"v", None),
            FilteredPut::Sent(Ok(0))
        );
    }
    assert_eq!(
        plan_links(&engine) - asked,
        usize::from(cfg!(feature = "shared-key-ids")),
        "the one link is asked only where it may name the key its own way"
    );
    assert_eq!(
        plans(&engine) - plans_before,
        1,
        "CONTROL: the second put is written from the plan"
    );
    until(&engine, "the router to receive both puts", || {
        router.seen(|s| s.pushes) == 2
    });
}

/// A bare put of a publisher's best-effort way rides as the way says whether its key is named or
/// its plan writes it: the first at a send epoch and the planned one after it both reach the
/// router on the best-effort channel, as the router's catch-all records the frame each came in.
/// CONTROL: the second was written from the plan. Turned red by a plain put sent by facts other
/// than its way's in either arm.
#[test]
fn a_bare_put_rides_as_its_way_says_named_or_planned() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);
    let params = PublishOptions::put()
        .with_reliability(Reliability::BestEffort)
        .plain_put_params()
        .expect("a plain put");
    assert!(!params.reliable, "the premise: a best-effort way");
    let (_hold, filter, wire) = way_with(&engine, &router, "demo/x", params);

    let before = plans(&engine);
    for _ in 0..2 {
        assert_eq!(
            engine.publish_filtered(filter, "demo/x", &wire, b"v", None),
            FilteredPut::Sent(Ok(0))
        );
    }
    assert_eq!(
        plans(&engine) - before,
        1,
        "CONTROL: the second put is written from the plan"
    );
    until(&engine, "the router to receive both puts", || {
        router.seen(|s| s.samples.len()) == 2
    });
    assert_eq!(
        router.seen(|s| s.reliabilities.clone()),
        [Reliability::BestEffort; 2],
        "the named put and the planned one ride as the way says"
    );
}

/// A plan stands at its send epoch alone: once the router retracts the subscriber that opened the
/// filter, the epoch has moved and the publisher's bare put is held back, not written from the
/// plan. CONTROL: the put before the retraction is written from it. Turned red by an epoch that
/// does not count what the peers declared, whose plan would send the put the filter holds back.
#[test]
fn a_plan_is_not_taken_once_a_peer_retracts_what_opened_its_filter() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let (_hold, filter, wire) = way_on(&engine, &router, "demo/x");
    let before = plans(&engine);
    for _ in 0..2 {
        assert_eq!(
            engine.publish_filtered(filter, "demo/x", &wire, b"v", None),
            FilteredPut::Sent(Ok(0))
        );
    }
    assert_eq!(
        plans(&engine) - before,
        1,
        "CONTROL: the second put is written from the plan"
    );

    router.send(Command::PushThenUndeclareSubscriber(1, "demo/x", b"v"));
    until(&engine, "the filter to shut", || {
        engine.write_filter_active(filter)
    });
    let before = plans(&engine);
    assert_eq!(
        engine.publish_filtered(filter, "demo/x", &wire, b"v", None),
        FilteredPut::Suppressed,
        "no subscriber is left: the put is held back"
    );
    assert_eq!(
        plans(&engine),
        before,
        "the plan of the old epoch is not taken"
    );
}

/// A plan stands while the link it was made over does: once that link is lost and the router
/// dialled again, the first bare put is sent by the filter's answer and its key's naming over the
/// new link and plans anew, and the puts after it are written from the new plan and reach the new
/// router. Turned red by a plan that outlives the link it was made over, or by one never made
/// again.
#[test]
fn a_plan_is_made_again_over_a_link_dialled_again() {
    let router = Router::start(CatchAll::None);
    let port = router.port;
    let engine = open_with(CoopConfig {
        redial_ms: Some(50),
        open_timeout_ms: 300,
        ..config(&router)
    });
    let (_hold, filter, wire) = way_on(&engine, &router, "demo/x");
    let before = plans(&engine);
    for _ in 0..2 {
        assert_eq!(
            engine.publish_filtered(filter, "demo/x", &wire, b"v", None),
            FilteredPut::Sent(Ok(0))
        );
    }
    assert_eq!(
        plans(&engine) - before,
        1,
        "CONTROL: the second put is written from the plan"
    );

    router.send(Command::Close);
    drop(router);
    until(&engine, "the link to be lost", || {
        engine.peer_identities().is_empty()
    });
    let router = Router::start_on(port, CatchAll::None);
    until(&engine, "the session to ask again", || {
        router.seen(|s| s.interests) >= 1
    });
    router.send(Command::DeclareSubscriber(1, "demo/**"));
    until(&engine, "the filter to open again", || {
        !engine.write_filter_active(filter)
    });
    let (plans_before, named_before) = (plans(&engine), namings(&engine));
    for _ in 0..3 {
        assert_eq!(
            engine.publish_filtered(filter, "demo/x", &wire, b"v", None),
            FilteredPut::Sent(Ok(0))
        );
    }
    assert_eq!(
        namings(&engine) - named_before,
        1,
        "the first put over the new link names its key, and plans anew"
    );
    assert_eq!(
        plans(&engine) - plans_before,
        2,
        "the puts after it are written from the new plan"
    );
    until(&engine, "the new router to receive the puts", || {
        router.seen(|s| s.pushes) == 3
    });
}
