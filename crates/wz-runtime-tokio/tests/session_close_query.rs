// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The close verb as a QUERY closes a RUNNING session, and says what it did.
//!
//! `session_close_ingress.rs` witnesses the Push form: a matched sample stages a
//! close request and the drive loop's comparator turns it into `Closing`. This is
//! the same verb asked as a GET, which has a reply, and the claim is the one that
//! file makes about its own: the EFFECT is what is asserted. A verdict that said
//! `closing` over a session that kept running would be the worst answer the verb
//! could give, so every arm that expects a close reads the session's state, and
//! every arm that expects none reads it too.
//!
//! The directory here names its one session by a zid of the test's choosing,
//! because the fixture session has no handshake to read a peer from; everything
//! else is the production path: the answerer, the authority port, the order that
//! `order_close_over` places on the session bundle, and the comparator.

#![cfg(feature = "session-close-ingress")]

use std::cell::RefCell;
use std::sync::Arc;

use sce_rust_runtime::Engine;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent, SessionFsmUnicastPolicy, SessionFsmUnicastState,
};
use wz_runtime_tokio::session_glue::{
    new_session_actions, new_session_engine, BoxedLinkDriver, SessionActionsBinding,
    SessionLinkActions,
};
use wz_runtime_tokio_test_support::{fixture_session_init_params, NoopOutboundDriver};
use wz_session_core::drive::{check_requested_close, LifecycleKey, SessionLifecycleAuthority};
use wz_session_core::lifecycle_query::{
    order_close_over, Answered, CloseOrder, CloseVerdict, LifecycleQueries, RefusedReason,
    SessionDirectory, SessionTarget,
};
use wz_session_core::query_sink::{BorrowedQuery, QueryView, ReplyError, ReplyOut};
use wz_session_core::sample::{EncodingHint, QosLevel};

const NODE: &str = "a1b2";
const PEER: &str = "c3d4";

/// A session standing in `Established` -- the only state whose document carries a
/// `session.close` transition.
fn established_session() -> (
    Arc<SessionLinkActions>,
    Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>,
) {
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(NoopOutboundDriver::default());
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    engine.process_event(SessionFsmUnicastEvent::OutboundStart);
    engine.process_event(SessionFsmUnicastEvent::LinkOpened);
    engine.process_event(SessionFsmUnicastEvent::InitAckReceived);
    engine.process_event(SessionFsmUnicastEvent::OpenAckReceived);
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::Established,
        "the walk to Established is this witness's premise, not its claim"
    );
    (actions, engine)
}

/// The fixture session, answering to a peer zid the test names.
struct Named {
    actions: Arc<SessionLinkActions>,
    zid: Vec<u8>,
}

impl SessionTarget for Named {
    fn peer_zid(&self) -> Option<Vec<u8>> {
        Some(self.zid.clone())
    }
    fn close_ordered(&self) -> bool {
        self.actions.close_ordered()
    }
    fn order_close(&self) {
        self.actions.request_close();
    }
}

struct Table(Vec<Named>);

impl SessionDirectory for Table {
    fn order_close(&self, peer_zid: &[u8]) -> CloseOrder {
        order_close_over(self.0.iter(), peer_zid)
    }
}

struct Authority(bool);

impl SessionLifecycleAuthority for Authority {
    fn admits_close(&self, _key: &LifecycleKey<'_>) -> bool {
        self.0
    }
}

#[derive(Default)]
struct Recorder {
    replies: RefCell<Vec<(String, String)>>,
}

impl ReplyOut for Recorder {
    fn reply(&mut self, _payload: &[u8]) {}
    fn reply_del(&mut self) {}
    fn reply_keyed_encoded(
        &mut self,
        keyexpr: &str,
        payload: &[u8],
        _encoding: Option<&EncodingHint>,
    ) -> Result<(), ReplyError> {
        self.replies.borrow_mut().push((
            keyexpr.to_string(),
            String::from_utf8(payload.to_vec()).expect("text"),
        ));
        Ok(())
    }
    fn reply_err(&mut self, _id: Option<u32>, _schema: Option<&str>, _payload: &[u8]) {}
    fn with_responder(&mut self, _zid: &[u8], _eid: u32) {}
    fn clear_responder(&mut self) {}
    fn responder(&self) -> Option<(&[u8], u32)> {
        None
    }
}

fn query(keyexpr: &str) -> impl QueryView + '_ {
    BorrowedQuery {
        keyexpr,
        parameters: None,
        attachment: None,
        source_info: None,
        payload: None,
        encoding: None,
        rid: 1,
        is_local: false,
        qos: QosLevel::DEFAULT,
    }
}

fn node(permit: bool, actions: &Arc<SessionLinkActions>) -> LifecycleQueries<Authority, Table> {
    LifecycleQueries::new(
        NODE,
        "peer",
        Authority(permit),
        Table(vec![Named {
            actions: Arc::clone(actions),
            zid: wz_session_core::zid_hex::zenoh_hex_to_zid(PEER).expect("a zid"),
        }]),
    )
}

fn close_key(peer: &str) -> String {
    format!("@/{NODE}/peer/session/close/{peer}")
}

fn ask(node: &LifecycleQueries<Authority, Table>, key: &str) -> (Answered, Vec<String>) {
    let mut out = Recorder::default();
    let answered = node.answer(&query(key), &mut out);
    let bodies = out
        .replies
        .into_inner()
        .into_iter()
        .map(|(_, b)| b)
        .collect();
    (answered, bodies)
}

/// A permitted close query ends the session: the verdict is `closing`, and the
/// drive loop's comparator then takes the session to `Closing`. Asking again finds
/// nothing new, and says so without a second close.
#[test]
fn a_close_query_closes_a_running_session_and_says_so() {
    let (actions, mut engine) = established_session();
    let node = node(true, &actions);

    // Nothing has asked: the session runs.
    assert!(!check_requested_close(&actions, &mut engine));

    let (answered, bodies) = ask(&node, &close_key(PEER));
    assert_eq!(
        answered,
        Answered::Close(CloseVerdict::Closing { links: 1 })
    );
    assert_eq!(bodies, vec![r#"{"verdict":"closing","links":1}"#]);
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::Established,
        "the query stages an order and holds no engine, as the Push form does"
    );

    // The drive loop owns the engine and is what raises.
    assert!(check_requested_close(&actions, &mut engine));
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::Closing,
        "the session actually closed -- the effect, not the verdict, is the claim"
    );

    // Asked again, the session is already on its way out: no second order.
    let (answered, bodies) = ask(&node, &close_key(PEER));
    assert_eq!(answered, Answered::Close(CloseVerdict::AlreadyClosed));
    assert_eq!(bodies, vec![r#"{"verdict":"already_closed"}"#]);
    assert!(
        !check_requested_close(&actions, &mut engine),
        "a verdict of already_closed orders nothing"
    );
}

/// A refused close, a peer the node does not hold and a key that is not a zid each
/// leave the session running, and each says which it was.
#[test]
fn a_close_query_that_is_refused_or_aimed_at_nobody_leaves_the_session_running() {
    let (actions, mut engine) = established_session();

    // The authority says no.
    let denied = node(false, &actions);
    let (answered, bodies) = ask(&denied, &close_key(PEER));
    assert_eq!(
        answered,
        Answered::Close(CloseVerdict::Refused(RefusedReason::NotPermitted))
    );
    assert!(
        bodies[0].starts_with(r#"{"verdict":"refused","reason":""#),
        "{bodies:?}"
    );

    // The authority says yes, to a peer this node has no session with.
    let permitted = node(true, &actions);
    let (answered, bodies) = ask(&permitted, &close_key("1f0e"));
    assert_eq!(answered, Answered::Close(CloseVerdict::NotFound));
    assert_eq!(bodies, vec![r#"{"verdict":"not_found"}"#]);

    // A last chunk that is not a zid (a leading zero is refused, as zenohd refuses
    // it in an id) is refused with its reason, and orders nothing.
    let (answered, bodies) = ask(&permitted, &close_key("0f1e"));
    assert_eq!(
        answered,
        Answered::Close(CloseVerdict::Refused(RefusedReason::PeerNotAZid))
    );
    assert!(bodies[0].contains("is not a zid"), "{bodies:?}");

    // A wildcard is no target.
    let (answered, bodies) = ask(&permitted, &close_key("*"));
    assert_eq!(answered, Answered::Unserved);
    assert!(bodies.is_empty());

    assert!(
        !check_requested_close(&actions, &mut engine),
        "none of the three ordered anything"
    );
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::Established,
        "the session kept running"
    );
}

/// The capability query answers the same whatever the authority says, because it
/// is about the node's verbs and not the caller's permission.
#[test]
fn the_capability_query_lists_close_whatever_the_authority_says() {
    let (actions, _engine) = established_session();
    for permit in [true, false] {
        let node = node(permit, &actions);
        let (answered, bodies) = ask(&node, &format!("@/{NODE}/peer/session/verbs"));
        assert_eq!(answered, Answered::Verbs);
        assert_eq!(bodies, vec![r#"{"verbs":["close","reset"]}"#]);
    }
}
