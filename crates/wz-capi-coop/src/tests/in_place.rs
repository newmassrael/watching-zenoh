// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session that reads each inbound datagram where its link holds it (`rx-in-place`): a Push
//! reaches the subscriber, and a Response the get that asked for it, from the frame's own bytes,
//! each record lent for its dispatch, as the copying receive delivers them.

use std::sync::{Arc, Mutex};

use wz_capi_port::{SessionEngine, WireKey};
use wz_session_core::locality::Locality;
use wz_session_core::sink::SampleView;

use super::{open, until, CatchAll, Command, Router};

/// A Push the router sends is read in place and reaches the subscriber with its key and payload.
#[test]
fn a_push_read_in_place_reaches_the_subscriber() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let got = Arc::new(Mutex::new(Vec::new()));
    let into = got.clone();
    engine.declare_subscriber_on_wire(
        "demo/**".to_owned(),
        WireKey::literal(),
        Locality::Any,
        None,
        Arc::new(move || {
            let into = into.clone();
            Box::new(move |sample: &dyn SampleView| {
                into.lock()
                    .unwrap()
                    .push((sample.keyexpr().to_owned(), sample.payload().to_vec()));
            })
        }),
    );
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares >= 1)
    });
    router.send(Command::Push("demo/in-place", b"lent"));
    until(&engine, "the sample", || !got.lock().unwrap().is_empty());
    assert_eq!(
        *got.lock().unwrap(),
        [("demo/in-place".to_owned(), b"lent".to_vec())]
    );
}

/// A get the router's queryable answers ends with its reply, read in place, and its Final.
#[cfg(feature = "query")]
#[test]
fn a_reply_read_in_place_answers_its_get() {
    use super::get::{ask, remote_get, settle};
    use wz_session_core::reply_sink::ReplyKind;

    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(&router, &engine, Command::Answer("demo/g/**", b"r"));
    let (issued, leg) = ask(&engine, "demo/g/a", &remote_get(), None, None, None);
    assert_eq!(issued, Some(1), "one leg: the link's peer");
    until(&engine, "the leg to end", || leg.lock().unwrap().ended);
    assert_eq!(
        leg.lock().unwrap().replies,
        vec![(ReplyKind::Put, "demo/g/a".to_owned(), b"r".to_vec())]
    );
}
