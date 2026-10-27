// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session on two faces: it opens to one router and dials a second beside it
//! ([`Engine::attach_face`]), so what the session declares, publishes and asks reaches both, what
//! each router declares counts, and a query is answered to the router it came from. The session
//! has one face everywhere else in these tests; these are what the face table decides with two.

use std::cell::Cell;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_capi_port::{
    FilterPlane, QueryCallback, QueryHolder, ReplyCallback, SessionDrive, SessionEngine, WireKey,
};
use wz_session_core::declare_form::InterestForm;
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::reply_sink::ReplyView;
use wz_session_core::sink::SampleView;

use super::get::remote_get;
use super::{open, until, CatchAll, Command, Engine, Router};

/// The second router is another node: a session holds one face for each zid, and two routers of
/// one zid would be the one node dialled twice (`tests::one_face`).
const SECOND_ROUTER_ZID: u8 = 0xc4;

/// A session opened to `first`, which then dials `second` as a face of its own and waits for both
/// links to complete their handshakes.
fn on_two_faces(first: &Router, second: &Router) -> Arc<Engine> {
    let engine = open(first);
    engine
        .attach_face(&second.endpoint())
        .expect("the second router is dialled");
    until(&engine, "both faces to be up", || engine.faces_up() == 2);
    engine
}

/// Step the session for `ms` milliseconds, for a test of what does NOT happen.
fn step_for(engine: &Engine, ms: u64) {
    let until = std::time::Instant::now() + Duration::from_millis(ms);
    while std::time::Instant::now() < until {
        let _ = SessionDrive::read(engine, false);
    }
}

/// A subscriber declared before the second face came up is told to its router by the replay; one
/// declared after is told to both; and a put reaches both routers.
#[test]
fn a_declaration_and_a_put_reach_every_face() {
    let first = Router::start(CatchAll::Held);
    let second = Router::start_as(SECOND_ROUTER_ZID, CatchAll::Held);
    let engine = open(&first);
    let subscribe = |keyexpr: &str| {
        engine.declare_subscriber_on_wire(
            keyexpr.to_owned(),
            WireKey::literal(),
            Locality::Any,
            None,
            Arc::new(|| Box::new(|_: &dyn SampleView| {})),
        )
    };
    subscribe("demo/early/**");
    until(&engine, "the first router to see it", || {
        first.seen(|s| s.declares) >= 1
    });
    assert_eq!(
        second.seen(|s| s.declares),
        0,
        "CONTROL: the second router is not yet a face"
    );

    engine
        .attach_face(&second.endpoint())
        .expect("the second router is dialled");
    until(&engine, "the replay to tell the second router", || {
        second.seen(|s| s.declares) >= 1
    });

    let (before_first, before_second) = (first.seen(|s| s.declares), second.seen(|s| s.declares));
    subscribe("demo/late/**");
    until(&engine, "both routers to see the later one", || {
        first.seen(|s| s.declares) > before_first && second.seen(|s| s.declares) > before_second
    });

    engine
        .publish_on_wire_all(
            "demo/p",
            &WireKey::literal(),
            b"v",
            &PublishOptions::put().with_locality(Locality::Remote),
        )
        .expect("a put the links carry");
    until(&engine, "both routers to receive the put", || {
        [&first, &second]
            .iter()
            .all(|router| router.seen(|s| s.samples.iter().any(|(k, _)| k == "demo/p")))
    });
}

/// A get is one leg for each face: each router answers its own, each answer reaches its own leg,
/// and the get is over when the last leg is.
#[test]
fn a_get_is_asked_of_every_face_and_ends_with_the_last_final() {
    let first = Router::start(CatchAll::None);
    let second = Router::start_as(SECOND_ROUTER_ZID, CatchAll::None);
    let engine = on_two_faces(&first, &second);
    first.send(Command::Answer("demo/g/**", b"from-first"));
    second.send(Command::Answer("demo/g/**", b"from-second"));
    until(&engine, "both routers to hold their queryables", || {
        first.seen(|s| s.settled) && second.seen(|s| s.settled)
    });

    #[derive(Default)]
    struct Legs {
        replies: Vec<(usize, Vec<u8>)>,
        ended: Vec<usize>,
    }
    struct End(usize, Arc<Mutex<Legs>>);
    impl Drop for End {
        fn drop(&mut self) {
            self.1.lock().unwrap().ended.push(self.0);
        }
    }
    let legs = Arc::new(Mutex::new(Legs::default()));
    let minted = Cell::new(0);
    let issued = engine.get_on_wire(
        "demo/g/a",
        &WireKey::literal(),
        &remote_get(),
        None,
        &mut || {
            let index = minted.get();
            minted.set(index + 1);
            let end = End(index, legs.clone());
            let seen = legs.clone();
            Box::new(move |view: &dyn ReplyView| {
                let _held = &end;
                seen.lock()
                    .unwrap()
                    .replies
                    .push((index, view.payload().to_vec()));
            }) as ReplyCallback
        },
    );
    assert_eq!(issued, Some(2), "one leg for each face");
    assert!(
        legs.lock().unwrap().ended.is_empty(),
        "CONTROL: both legs are open until their routers' Finals come"
    );
    until(&engine, "both legs to end", || {
        legs.lock().unwrap().ended.len() == 2
    });
    let legs = legs.lock().unwrap();
    let mut payloads: Vec<_> = legs.replies.iter().map(|(_, p)| p.clone()).collect();
    payloads.sort();
    assert_eq!(payloads, [b"from-first".to_vec(), b"from-second".to_vec()]);
    assert_ne!(
        legs.replies[0].0, legs.replies[1].0,
        "each answer reached the leg of its own face"
    );
    assert_eq!(first.seen(|s| s.queries), 1);
    assert_eq!(second.seen(|s| s.queries), 1);
}

/// A write filter and a matching listener count what the peers of EVERY face declare: the filter
/// lets writes through and the listener says it matches while either router holds a queryable, and
/// goes back only when the last one lets go. A listener that read the face whose declaration just
/// changed alone would flip to "no match" when the first router retracted.
#[test]
fn a_filter_and_a_listener_count_the_peers_of_every_face() {
    let first = Router::start(CatchAll::None);
    let second = Router::start_as(SECOND_ROUTER_ZID, CatchAll::None);
    let engine = on_two_faces(&first, &second);
    let plane = FilterPlane::Queryables {
        complete_required: false,
    };
    let told = Arc::new(Mutex::new(Vec::new()));
    let into = told.clone();
    engine.declare_matching_listener(
        plane,
        "demo/m/x".to_owned(),
        Arc::new(move |matching| into.lock().unwrap().push(matching)),
        false,
    );
    let filter = engine.declare_write_filter(
        plane,
        "demo/m/x".to_owned(),
        &WireKey::literal(),
        Some(InterestForm {
            mapping_id: 0,
            suffix: Some("demo/m/x".to_owned()),
            aggregate: false,
        }),
        false,
    );
    until(&engine, "both routers to see the Interest", || {
        first.seen(|s| s.interests) >= 1 && second.seen(|s| s.interests) >= 1
    });
    assert!(
        engine.write_filter_holds_back(filter),
        "CONTROL: no peer holds a queryable yet"
    );

    first.send(Command::DeclareQueryable(1, "demo/m/**", false));
    until(&engine, "the listener to match", || {
        *told.lock().unwrap() == [true]
    });
    assert!(!engine.write_filter_holds_back(filter));

    second.send(Command::DeclareQueryable(1, "demo/m/**", false));
    step_for(&engine, 150);
    assert_eq!(*told.lock().unwrap(), [true], "a second match is no flip");

    first.send(Command::UndeclareQueryable(1));
    step_for(&engine, 150);
    assert_eq!(
        *told.lock().unwrap(),
        [true],
        "the first router let go and the second still holds its queryable"
    );
    assert!(!engine.write_filter_holds_back(filter));

    second.send(Command::UndeclareQueryable(1));
    until(&engine, "the listener to stop matching", || {
        *told.lock().unwrap() == [true, false]
    });
    assert!(engine.write_filter_holds_back(filter));
}

/// A query is answered to the router it came in on: the second router asks, and only it hears the
/// reply and the Final. A face that is lost takes only its own declarations with it, and the
/// session goes on over the other.
#[test]
fn a_query_is_answered_to_its_face_and_a_lost_face_leaves_the_other() {
    let first = Router::start(CatchAll::None);
    let second = Router::start_as(SECOND_ROUTER_ZID, CatchAll::None);
    let engine = on_two_faces(&first, &second);
    engine
        .declare_queryable_on_wire(
            "demo/q/**".to_owned(),
            WireKey::literal(),
            false,
            Locality::Remote,
            None,
            Arc::new(|_: Arc<dyn QueryHolder>| {
                Box::new(|query: &dyn QueryView, out: &mut dyn ReplyOut| {
                    out.reply_keyed(query.keyexpr(), b"mine")
                        .expect("a reply on the query's own key");
                }) as QueryCallback
            }),
        )
        .expect("the engine has queryables in this build");
    until(&engine, "both routers to see the queryable", || {
        first.seen(|s| s.declares) >= 1 && second.seen(|s| s.declares) >= 1
    });

    second.send(Command::Query(7, "demo/q/a"));
    until(&engine, "the reply and the final", || {
        second.seen(|s| s.answers.len()) >= 2
    });
    assert_eq!(second.seen(|s| s.answers.clone()), ["reply", "final"]);
    assert!(
        first.seen(|s| s.answers.is_empty()),
        "the router that asked nothing was answered nothing"
    );

    // The router that was dialled FIRST asks while both links stand: its query arrives on the
    // older link, not the one dialled last, and is answered to it.
    first.send(Command::Query(8, "demo/q/b"));
    until(&engine, "the first router to be answered", || {
        first.seen(|s| s.answers.len()) >= 2
    });
    assert_eq!(first.seen(|s| s.answers.clone()), ["reply", "final"]);
    assert_eq!(
        second.seen(|s| s.answers.len()),
        2,
        "and the second router was told nothing of it"
    );

    second.send(Command::Close);
    drop(second);
    until(&engine, "the second face to be lost", || {
        engine.faces_up() == 1
    });
    assert!(
        SessionDrive::read(&*engine, false).is_ok(),
        "the session goes on over the face that is left"
    );
    first.send(Command::Query(9, "demo/q/c"));
    until(&engine, "the first router to be answered again", || {
        first.seen(|s| s.answers.len()) >= 4
    });
    assert_eq!(
        first.seen(|s| s.answers.clone()),
        ["reply", "final", "reply", "final"]
    );
}
