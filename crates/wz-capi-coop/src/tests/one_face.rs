// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A session holds one face for each remote zid. A peer that listens and dials is told of the
//! same node by two links, whichever of them it dialled or took off its port, and the session
//! keeps one: the first up when both links went the same way, and when they went opposite ways
//! (two nodes that dialled each other at once) the one the node with the lower zid dialled, which
//! both ends read the same, so neither closes the link the other kept. The sessions are the engine
//! against itself over loopback, each stepped by its read task.

use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use wz_capi_port::{SessionEngine, WireKey};
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::sink::SampleView;

use super::listen::{client, eventually, listening, Stepped};

/// A subscriber on `demo/one/**` of `session`, and what it has heard.
fn hearing(session: &Stepped) -> Arc<Mutex<Vec<Vec<u8>>>> {
    let heard = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let into = heard.clone();
    session.declare_subscriber_on_wire(
        "demo/one/**".to_owned(),
        WireKey::literal(),
        Locality::Any,
        None,
        Arc::new(move || {
            let into = into.clone();
            Box::new(move |sample: &dyn SampleView| {
                into.lock().unwrap().push(sample.payload().to_vec());
            })
        }),
    );
    heard
}

/// `from` puts `text` on `demo/one/x`, and `into` is waited on to hear it.
fn puts_and_is_heard(
    from: &Stepped,
    into: &Arc<Mutex<Vec<Vec<u8>>>>,
    text: &'static [u8],
    what: &str,
) {
    from.publish_on_wire_all(
        "demo/one/x",
        &WireKey::literal(),
        text,
        &PublishOptions::put().with_locality(Locality::Remote),
    )
    .expect("a put the link carries");
    eventually(what, || into.lock().unwrap().iter().any(|got| got == text));
}

/// Both sessions hold exactly one face, and go on holding it for a while: a pair that closed both
/// links reads zero, and one that closed them late reads one first and zero after.
fn settle_on_one_face(a: &Stepped, b: &Stepped) {
    eventually("each session to hold a face", || {
        a.faces_up() == 1 && b.faces_up() == 1
    });
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        a.faces_up(),
        1,
        "the first session holds one face and keeps it"
    );
    assert_eq!(
        b.faces_up(),
        1,
        "the second session holds one face and keeps it"
    );
}

/// Two nodes that dial each other at the same moment keep one link between them, whichever of the
/// two has the lower zid, and the link carries what each puts. Each round starts two fresh nodes
/// and releases both dials from one barrier, so the race is run and not arranged: each node sees
/// the link it dialled and the link the other dialled complete in either order.
#[test]
fn two_nodes_that_dial_each_other_at_once_keep_one_link() {
    for round in 0..12u8 {
        // The lower zid is the first node's in the even rounds and the second's in the odd ones.
        let (low, high) = (0x10 + round, 0xa0 + round);
        let (first_id, second_id) = if round % 2 == 0 {
            (low, high)
        } else {
            (high, low)
        };
        let (first, first_at) = listening(|config| config.zid = Some(vec![first_id; 4]));
        let (second, second_at) = listening(|config| config.zid = Some(vec![second_id; 4]));
        let first_heard = hearing(&first);
        let second_heard = hearing(&second);

        let barrier = Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                first.attach_face(&second_at).expect("the first node dials");
            });
            scope.spawn(|| {
                barrier.wait();
                second
                    .attach_face(&first_at)
                    .expect("the second node dials");
            });
        });

        settle_on_one_face(&first, &second);
        puts_and_is_heard(
            &first,
            &second_heard,
            b"to-second",
            "the second node to hear the first",
        );
        puts_and_is_heard(
            &second,
            &first_heard,
            b"to-first",
            "the first node to hear the second",
        );
    }
}

/// A node dialled twice by one peer, and holds the first: the second link goes (it is the same
/// node), so each end holds one face. The control is the session before the second dial, which is
/// already the one face each.
#[test]
fn a_second_dial_to_a_node_the_session_holds_is_refused() {
    let (listener, endpoint) = listening(|_| {});
    let dialler = client(&endpoint, 0xc1);
    eventually("the first link", || {
        listener.faces_up() == 1 && dialler.faces_up() == 1
    });

    dialler
        .attach_face(&endpoint)
        .expect("the second dial reaches the port");
    settle_on_one_face(&listener, &dialler);

    let heard = hearing(&listener);
    puts_and_is_heard(
        &dialler,
        &heard,
        b"over-the-one",
        "the listener to hear the dialler",
    );
}

/// A node that listens and dials the node that has dialled it already stands by (its dial role's
/// face is held, not dialled again at every redial) and reaches the node again when the face that
/// held it is lost. The lower zid is the other node's, so the link the other dialled is the one
/// kept at both ends: this node's dial role loses to a link that arrived first.
#[test]
fn the_dial_role_stands_by_for_a_held_node_and_dials_again_when_it_is_lost() {
    // The port the lower node listens on is fixed so that a node can come back to it.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|bound| bound.local_addr())
        .expect("a free port")
        .port();
    let low_at = format!("tcp/127.0.0.1:{port}");
    let (low, _) = listening(|config| {
        config.zid = Some(vec![0x11; 4]);
        config.listen = vec![low_at.clone()];
    });
    let (high, high_at) = listening(|config| {
        config.zid = Some(vec![0x99; 4]);
        config.endpoints = vec![low_at.clone()];
        config.redial_ms = Some(50);
    });
    // The low node dials the high one as well: the two dials cross, and the one the low node made
    // is kept at both ends.
    low.attach_face(&high_at).expect("the low node dials");
    settle_on_one_face(&low, &high);

    // The low node goes, and with it the face that held it: the high node's dial role is dialled
    // again, and finds the node when it is back.
    drop(low);
    eventually("the high node to lose its face", || high.faces_up() == 0);
    let (back, _) = listening(|config| {
        config.zid = Some(vec![0x11; 4]);
        config.listen = vec![low_at.clone()];
    });
    eventually("the high node to dial the node that came back", || {
        high.faces_up() == 1 && back.faces_up() == 1
    });
    let heard = hearing(&back);
    puts_and_is_heard(
        &high,
        &heard,
        b"after-the-return",
        "the returned node to hear it",
    );
}
