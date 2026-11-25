// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The faces of the session, as a connectivity plane reads them: a snapshot of the face the
//! session stands on, and the events a watcher is told when that face is lost and when the link
//! dialled again brings one up.

use std::sync::{Arc, Mutex};

use wz_capi_port::told::{ToldKey, ToldPlane};
use wz_capi_port::SessionEngine;
use wz_session_core::face::{FaceEventKind, FaceSnapshot};
use wz_session_core::link::LinkKind;

use super::{config, open, open_with, until, CatchAll, Command, CoopConfig, Router};

/// What a watcher was told, in order: the event, the face's first zid byte and link count, and
/// how many faces stood when the sink reached back into the session.
type Told = Arc<Mutex<Vec<(FaceEventKind, u8, usize, usize)>>>;

/// The face is the router's: its zid, its role, one UDP link whose far end is the router's port,
/// and an outbound frame budget. A session with no link up stands on no face.
#[test]
fn a_session_reports_the_face_it_stands_on() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);

    let faces = engine.face_snapshots();
    assert_eq!(faces.len(), 1, "one link, one face");
    let face = &faces[0];
    assert_eq!(face.zid[..4], [0xc3; 4], "the router's zid");
    assert_eq!(face.zid[4..], [0; 12], "padded with zeros to sixteen");
    assert_eq!(face.whatami, 0, "a router, in its wire form");
    assert!(!face.is_multicast);
    assert_eq!(face.links.len(), 1);
    let link = &face.links[0];
    assert_eq!(link.kind, Some(LinkKind::Udp), "the stand-in speaks UDP");
    assert_eq!(link.dst, format!("udp/127.0.0.1:{}", router.port));
    assert!(link.src.starts_with("udp/127.0.0.1:"), "{}", link.src);
    assert!(link.mtu > 0, "a negotiated outbound budget");
    assert_eq!(
        link.interfaces, None,
        "the NICs are not resolved, which reads as undetermined and not as none"
    );
    assert!(link.group.is_none(), "a unicast link");
}

/// A watch asked of a closed session is refused as closed and its sink let go of: no face comes up
/// on it to tell.
#[test]
fn a_closed_session_refuses_a_face_watch() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    wz_capi_port::SessionDrive::close(&*engine);
    let watcher = Arc::new(|_: FaceEventKind, _: &FaceSnapshot| {});
    let held = Arc::downgrade(&watcher);
    let sink = wz_session_core::face::FaceEventSink::of_arc(watcher);
    assert_eq!(engine.watch_faces(sink), Err(wz_capi_port::Refusal::Closed));
    assert!(held.upgrade().is_none(), "the refused sink is let go of");
}

/// A watcher is told when the face goes and when the link dialled again brings one up, in that
/// order and with what the face was. The face the open brought up is no event to a watcher that
/// came after it. The sink runs with the session free: it lists the faces from inside the event.
/// A watcher that stopped hears no more.
#[test]
fn a_watcher_is_told_of_the_face_lost_and_the_one_dialled_again() {
    let router = Router::start(CatchAll::None);
    let port = router.port;
    let engine = open_with(CoopConfig {
        redial_ms: Some(50),
        open_timeout_ms: 300,
        ..config(&router)
    });
    let told: Told = Arc::default();
    let into = told.clone();
    let reach = engine.clone();
    let id = engine
        .watch_faces(wz_session_core::face::FaceEventSink::of_arc(Arc::new(
            move |kind: FaceEventKind, face: &FaceSnapshot| {
                into.lock().unwrap().push((
                    kind,
                    face.zid[0],
                    face.links.len(),
                    reach.face_snapshots().len(),
                ));
            },
        )))
        .expect("an open session watches its faces");
    assert!(
        told.lock().unwrap().is_empty(),
        "CONTROL: the face the open brought up is no event to a later watcher"
    );
    assert_eq!(engine.face_snapshots().len(), 1, "it is a face that stands");

    router.send(Command::Close);
    drop(router);
    until(&engine, "the face to be lost", || {
        !told.lock().unwrap().is_empty()
    });
    assert_eq!(
        *told.lock().unwrap(),
        [(FaceEventKind::Down, 0xc3, 1, 0)],
        "the face as it was, told with no face standing and the session free"
    );

    let router = Router::start_on(port, CatchAll::None);
    until(&engine, "the link to be dialled again", || {
        told.lock().unwrap().len() >= 2
    });
    assert_eq!(
        told.lock().unwrap()[1],
        (FaceEventKind::Up, 0xc3, 1, 1),
        "the face that came up stands by the time it is told"
    );

    assert!(engine.unwatch_faces(id));
    assert!(!engine.unwatch_faces(id), "a second stop finds nothing");
    router.send(Command::Close);
    drop(router);
    until(&engine, "the face to be lost again", || {
        engine.face_snapshots().is_empty()
    });
    assert_eq!(
        told.lock().unwrap().len(),
        2,
        "a watcher that stopped hears no more"
    );
}

/// Walking the faces a row at a time allocates nothing: a row's ends are written into the row in
/// place under the session's lock, and the row is handed out whole. Turned red by a walk that
/// builds the face's snapshot or a list of them, which the control below shows allocates.
#[test]
fn walking_the_faces_a_row_at_a_time_allocates_nothing() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    assert!(
        engine.face_link_at(0).is_some(),
        "the session stands on a face"
    );
    let mut rows = 0;
    let allocations = super::redial_heap::counted(|| {
        while let Some(row) = engine.face_link_at(rows) {
            core::hint::black_box(&row);
            rows += 1;
        }
    });
    assert_eq!(rows, 1, "one link, one row");
    assert_eq!(allocations, 0, "the walk allocates nothing");
    let snapshots = super::redial_heap::counted(|| {
        core::hint::black_box(engine.face_snapshots());
    });
    assert!(snapshots > 0, "a snapshot of the same face allocates");
}

/// The face rows a replaying listener converges to as `converge_transports` of the pico ABI
/// brings one to them: each departure it is owed, then each face that stands it was not told,
/// as `DEL`/`PUT` and the zid's first byte.
fn converge(engine: &super::Engine, listener: usize) -> Vec<(&'static str, u8)> {
    let plane = ToldPlane::Transports;
    let mut told = Vec::new();
    while let Some(row) = engine.first_told_gone(plane, listener) {
        assert!(
            engine.tell_went(plane, listener, &ToldKey::of_row(&row)),
            "a departure owed is told"
        );
        told.push(("DEL", row.zid[0]));
    }
    let mut at = 0;
    while let Some(row) = engine.face_link_at(at) {
        if engine.tell_came(plane, listener, &ToldKey::of_row(&row)) {
            told.push(("PUT", row.zid[0]));
        }
        at += 1;
    }
    told
}

/// What a replaying listener was told is kept on the face's own row. A face it was told keeps the
/// row it was told as when it goes, a tomb owed to that listener alone; the face dialled again
/// under the same key is not told to it before that departure, and is told once after it, so a
/// reconnect reads as one, in order. A face no listener was told leaves nothing behind, and one
/// that does not stand is told neither way (it came and went unseen).
///
/// # Control
///
/// An engine that keeps no told bits (the port's provided answers) tells `tell_came` twice and
/// reds the second assertion; one that keeps no tomb reds the `first_told_gone` after the loss.
#[test]
fn a_told_face_that_goes_keeps_its_tomb_until_its_departure_is_told() {
    let router = Router::start(CatchAll::None);
    let port = router.port;
    let engine = open_with(CoopConfig {
        redial_ms: Some(50),
        open_timeout_ms: 300,
        ..config(&router)
    });
    let plane = ToldPlane::Transports;
    let row = engine
        .face_link_at(0)
        .expect("the session stands on a face");
    let key = ToldKey::of_row(&row);
    assert!(engine.tell_came(plane, 0, &key), "told once");
    assert!(!engine.tell_came(plane, 0, &key), "and not again");
    assert!(
        engine.first_told_gone(plane, 0).is_none(),
        "a face that stands is no tomb"
    );

    router.send(Command::Close);
    drop(router);
    until(&engine, "the face to be lost", || {
        engine.face_link_at(0).is_none()
    });
    assert_eq!(
        engine.first_told_gone(plane, 0).map(|row| row.zid),
        Some(row.zid),
        "the face that went is owed to the listener told it"
    );
    assert!(
        engine.first_told_gone(plane, 1).is_none(),
        "and to no other"
    );
    assert!(
        !engine.tell_came(plane, 1, &key),
        "a face that does not stand is not told"
    );
    assert!(
        !engine.tell_went(plane, 1, &key),
        "nor its departure, to a listener never told it came"
    );

    let router = Router::start_on(port, CatchAll::None);
    until(&engine, "the link to be dialled again", || {
        engine.face_link_at(0).is_some()
    });
    assert!(
        !engine.tell_came(plane, 0, &key),
        "the face again waits for the departure owed under its key"
    );
    assert!(
        engine.tell_came(plane, 1, &key),
        "a listener owed nothing is told it"
    );
    assert!(engine.tell_went(plane, 0, &key), "the departure is told");
    assert!(!engine.tell_went(plane, 0, &key), "once");
    assert!(engine.tell_came(plane, 0, &key), "then the reconnect");

    engine.forget_told(plane, 0);
    engine.forget_told(plane, 1);
    router.send(Command::Close);
    drop(router);
    until(&engine, "the face to be lost again", || {
        engine.face_link_at(0).is_none()
    });
    assert!(
        engine.first_told_gone(plane, 0).is_none() && engine.first_told_gone(plane, 1).is_none(),
        "a face no replaying listener was told keeps no tomb"
    );
}

/// The dial role's face keeps one tomb beside the link it dials again: a second departure under
/// another key, the face dialled to another node, takes a free place of the face table as a
/// departed face, and each listener is owed its own departure until it was told it.
///
/// # Control
///
/// Dropping the tomb `FaceTold::went` hands back (no departed place) reds listener 1's
/// `first_told_gone`; writing it over the first reds listener 0's. Only a build that takes faces
/// beside its dial role's has a free place for it.
#[cfg(any(feature = "listen", feature = "group"))]
#[test]
fn a_second_departure_of_the_dial_face_under_another_key_is_kept_apart() {
    let router = Router::start(CatchAll::None);
    let port = router.port;
    let engine = open_with(CoopConfig {
        redial_ms: Some(50),
        open_timeout_ms: 300,
        ..config(&router)
    });
    let plane = ToldPlane::Transports;
    let first = ToldKey::of_row(&engine.face_link_at(0).expect("a face stands"));
    assert!(engine.tell_came(plane, 0, &first));
    router.send(Command::Close);
    drop(router);
    until(&engine, "the face to be lost", || {
        engine.face_link_at(0).is_none()
    });

    let router = Router::start_on_as(port, 0x5a, CatchAll::None);
    until(&engine, "the link to another node", || {
        engine.face_link_at(0).is_some()
    });
    let second_row = engine.face_link_at(0).expect("the face again");
    assert_eq!(second_row.zid[0], 0x5a, "another node, another key");
    let second = ToldKey::of_row(&second_row);
    assert!(engine.tell_came(plane, 1, &second));
    router.send(Command::Close);
    drop(router);
    until(&engine, "the second face to be lost", || {
        engine.face_link_at(0).is_none()
    });

    assert_eq!(
        engine.first_told_gone(plane, 0).map(|row| row.zid[0]),
        Some(0xc3),
        "the first departure is still owed"
    );
    assert_eq!(
        engine.first_told_gone(plane, 1).map(|row| row.zid[0]),
        Some(0x5a),
        "the second is kept apart"
    );
    assert!(engine.tell_went(plane, 1, &second));
    assert!(engine.tell_went(plane, 0, &first));
    assert!(
        engine.first_told_gone(plane, 0).is_none() && engine.first_told_gone(plane, 1).is_none(),
        "both told, nothing kept"
    );
}

/// A session that only dials holds its dial role's face alone, so a second departure of that face
/// under another key finds no place to be kept in: the listener told the second row is owed
/// nothing, and the one told the first is still owed its departure, which the face's own tomb
/// keeps.
///
/// # Control
///
/// A table that kept the second tomb at another place reds listener 1's `first_told_gone`; one
/// that wrote it over the first reds listener 0's.
#[cfg(not(any(feature = "listen", feature = "group")))]
#[test]
fn a_second_departure_of_the_dial_face_of_a_dial_only_session_is_not_kept() {
    let router = Router::start(CatchAll::None);
    let port = router.port;
    let engine = open_with(CoopConfig {
        redial_ms: Some(50),
        open_timeout_ms: 300,
        ..config(&router)
    });
    let plane = ToldPlane::Transports;
    let first = ToldKey::of_row(&engine.face_link_at(0).expect("a face stands"));
    assert!(engine.tell_came(plane, 0, &first));
    router.send(Command::Close);
    drop(router);
    until(&engine, "the face to be lost", || {
        engine.face_link_at(0).is_none()
    });

    let router = Router::start_on_as(port, 0x5a, CatchAll::None);
    until(&engine, "the link to another node", || {
        engine.face_link_at(0).is_some()
    });
    let second = ToldKey::of_row(&engine.face_link_at(0).expect("the face again"));
    assert!(engine.tell_came(plane, 1, &second));
    router.send(Command::Close);
    drop(router);
    until(&engine, "the second face to be lost", || {
        engine.face_link_at(0).is_none()
    });

    assert_eq!(
        engine.first_told_gone(plane, 0).map(|row| row.zid[0]),
        Some(0xc3),
        "the first departure is still owed"
    );
    assert!(
        engine.first_told_gone(plane, 1).is_none(),
        "the second has no place to be kept in"
    );
    assert!(!engine.tell_went(plane, 1, &second));
    assert!(engine.tell_went(plane, 0, &first));
}

/// A listener whose replay queue ran out of rows converges to the faces as they stand: told the
/// departure of the face it heard come, then the face dialled again, once each. Converging again
/// tells nothing, so no face that stands is told twice.
///
/// # Control
///
/// The port's provided answers (no told bits on coop) tell no `DEL` and `PUT` the face again on
/// the second convergence, which reds both lists.
#[test]
fn a_listener_past_its_queue_converges_to_the_faces_that_stand() {
    let router = Router::start(CatchAll::None);
    let port = router.port;
    let engine = open_with(CoopConfig {
        redial_ms: Some(50),
        open_timeout_ms: 300,
        ..config(&router)
    });
    assert_eq!(converge(&engine, 0), [("PUT", 0xc3)], "the history");

    router.send(Command::Close);
    drop(router);
    until(&engine, "the face to be lost", || {
        engine.face_link_at(0).is_none()
    });
    let router = Router::start_on(port, CatchAll::None);
    until(&engine, "the link to be dialled again", || {
        engine.face_link_at(0).is_some()
    });
    assert_eq!(
        converge(&engine, 0),
        [("DEL", 0xc3), ("PUT", 0xc3)],
        "the departure, then the reconnect"
    );
    assert!(converge(&engine, 0).is_empty(), "nothing told twice");
    engine.forget_told(ToldPlane::Transports, 0);
    router.send(Command::Close);
    drop(router);
}

/// Noting what a replaying listener was told, reading the departure it is owed and forgetting it
/// allocate nothing: the bits and the tomb lie in the face's row, and the tomb's row is copied
/// out whole.
///
/// # Control
///
/// A ledger on the heap (the port's `ToldLedger`) allocates at the first `tell_came`.
#[test]
fn noting_what_a_replaying_listener_was_told_allocates_nothing() {
    let router = Router::start(CatchAll::None);
    let engine = open_with(CoopConfig {
        redial_ms: Some(50),
        open_timeout_ms: 300,
        ..config(&router)
    });
    let plane = ToldPlane::Links;
    let key = ToldKey::of_row(&engine.face_link_at(0).expect("a face stands"));
    let standing = super::redial_heap::counted(|| {
        assert!(engine.tell_came(plane, 3, &key));
        assert!(engine.first_told_gone(plane, 3).is_none());
    });
    assert_eq!(standing, 0, "noting a face that stands allocates nothing");

    router.send(Command::Close);
    drop(router);
    until(&engine, "the face to be lost", || {
        engine.face_link_at(0).is_none()
    });
    let gone = super::redial_heap::counted(|| {
        let row = engine.first_told_gone(plane, 3);
        core::hint::black_box(&row);
        assert!(row.is_some(), "the tomb is read");
        assert!(engine.tell_went(plane, 3, &key));
        engine.forget_told(plane, 3);
    });
    assert_eq!(gone, 0, "reading and telling a tomb allocates nothing");
}
