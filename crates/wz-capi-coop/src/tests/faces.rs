// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The faces of the session, as a connectivity plane reads them: a snapshot of the face the
//! session stands on, and the events a watcher is told when that face is lost and when the link
//! dialled again brings one up.

use std::sync::{Arc, Mutex};

use wz_capi_port::SessionEngine;
use wz_session_core::face::FaceEventKind;
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
    let id = engine.watch_faces(Arc::new(move |kind, face| {
        into.lock().unwrap().push((
            kind,
            face.zid[0],
            face.links.len(),
            reach.face_snapshots().len(),
        ));
    }));
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
