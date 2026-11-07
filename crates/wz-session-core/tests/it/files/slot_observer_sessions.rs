// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! One application observer serving two sessions, each with its own peer tables
//! (fixed-memory step S9a, decision Q7), end to end through the dispatch.
//!
//! The decision's second reason, that the ids a peer names are scoped by its
//! session, was inferred when it was taken and never driven. This drives it: two
//! peers number their aliases from the same id, and the one subscriber the
//! application registered must see each peer's push under THAT peer's keyexpr.
//! Beside it, the flood case through the whole fan: one peer fills its alias
//! table and its pushes under the refused ids go nowhere, while the other's are
//! delivered.
//!
//! Compiles only on the fixed backing, where the tables' capacities are hard.
#![cfg(all(
    feature = "bounded-heapless",
    feature = "codec-push",
    feature = "codec-declare",
    feature = "pubsub-put"
))]

use std::sync::{Arc, Mutex};

use wz_session_core::caps;
use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
use wz_session_core::locality::Locality;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::peer_tables::PeerTables;
use wz_session_core::push_build::build_push_aliased;
use wz_session_core::reply_sink::BoxedReplySink;
use wz_session_core::sink::{BoxedSink, SampleView};
use wz_session_core::slot_observer::{Requesters, SlotObserver};
use wz_session_core_test_support as fx;

type Req = Requesters<BoxedReplySink, BoxedReplySink>;

fn frame(messages: Vec<NetworkMessage>) -> DriverLoopOutcome {
    DriverLoopOutcome::FramePayload {
        priority: wz_session_core::qos::Priority::DEFAULT,
        reliable: true,
        sn: 0,
        messages,
        has_ext: false,
        extensions: Vec::new(),
    }
}

fn declare_alias(id: u64, keyexpr: &str) -> NetworkMessage {
    NetworkMessage::Declare(Box::new(fx::declare_envelope_decl_kexpr(fx::decl_kexpr(
        id, keyexpr,
    ))))
}

fn push_on(id: u64) -> NetworkMessage {
    NetworkMessage::Push(Box::new(
        build_push_aliased(id, None, b"v").expect("build the push"),
    ))
}

/// An observer with one subscriber on everything, and the keyexprs it was handed.
fn observer() -> (SlotObserver, Arc<Mutex<Vec<String>>>) {
    let mut observer = SlotObserver::new();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let into = seen.clone();
    observer
        .subscribers
        .register_sink(
            "**",
            Locality::Any,
            BoxedSink::new(move |sample: &dyn SampleView| {
                into.lock()
                    .expect("not poisoned")
                    .push(sample.keyexpr().to_string());
            }),
        )
        .expect("register");
    (observer, seen)
}

fn dispatch(
    observer: &mut SlotObserver,
    peers: &mut PeerTables,
    requesters: &mut Req,
    messages: Vec<NetworkMessage>,
) {
    let outcome = frame(messages);
    observer.dispatch_event(peers, requesters, IterationEvent::Poll(&outcome));
}

#[test]
fn the_same_alias_id_from_two_sessions_names_two_keyexprs() {
    let (mut observer, seen) = observer();
    let (mut a, mut b) = (PeerTables::new(), PeerTables::new());
    let (mut ra, mut rb) = (Req::new(), Req::new());

    dispatch(
        &mut observer,
        &mut a,
        &mut ra,
        vec![declare_alias(5, "a/side")],
    );
    dispatch(
        &mut observer,
        &mut b,
        &mut rb,
        vec![declare_alias(5, "b/side")],
    );
    dispatch(&mut observer, &mut a, &mut ra, vec![push_on(5)]);
    dispatch(&mut observer, &mut b, &mut rb, vec![push_on(5)]);

    assert_eq!(
        *seen.lock().expect("not poisoned"),
        vec!["a/side".to_string(), "b/side".to_string()],
        "id 5 means a/side in session A and b/side in session B"
    );
    // The CONTROL: a session that never declared id 5 resolves nothing for it.
    let mut c = PeerTables::new();
    let mut rc = Req::new();
    dispatch(&mut observer, &mut c, &mut rc, vec![push_on(5)]);
    assert_eq!(
        seen.lock().expect("not poisoned").len(),
        2,
        "no alias, no delivery"
    );
}

#[test]
fn a_session_that_filled_its_alias_table_loses_its_own_pushes_and_no_one_elses() {
    let (mut observer, seen) = observer();
    let (mut flooded, mut quiet) = (PeerTables::new(), PeerTables::new());
    let (mut rf, mut rq) = (Req::new(), Req::new());
    let n = caps::MAX_PEER_KEYEXPR_ALIASES as u64;

    // The flooded peer declares one alias more than its table holds.
    let declares: Vec<NetworkMessage> = (1..=n + 1)
        .map(|id| declare_alias(id, &format!("flood/{id}")))
        .collect();
    dispatch(&mut observer, &mut flooded, &mut rf, declares);
    // The quiet peer declares the very id the flooded one was refused.
    dispatch(
        &mut observer,
        &mut quiet,
        &mut rq,
        vec![declare_alias(n + 1, "quiet/last")],
    );

    // A push under the refused id is dropped in the flooded session and delivered
    // in the quiet one; a push under an id that fit is delivered in the flooded one.
    dispatch(&mut observer, &mut flooded, &mut rf, vec![push_on(n + 1)]);
    dispatch(&mut observer, &mut quiet, &mut rq, vec![push_on(n + 1)]);
    dispatch(&mut observer, &mut flooded, &mut rf, vec![push_on(1)]);

    assert_eq!(
        (
            seen.lock().expect("not poisoned").clone(),
            flooded.subscribers.alias_refusals(),
            quiet.subscribers.alias_refusals()
        ),
        (vec!["quiet/last".to_string(), "flood/1".to_string()], 1, 0),
        "(keyexprs delivered, flooded refusals, quiet refusals)"
    );
}
