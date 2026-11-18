// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "router-connect-reconcile",
    feature = "session-close-ingress",
    feature = "transport-link-tls"
))]

//! Decision D10 of `docs/session-lifecycle-intent.md` over a real secure channel: a node told to
//! wait for a peer (`open/passive/<peer>`) holds the session the peer opens to it over mutual TLS,
//! and the lifecycle verbs reach that session.
//!
//! Two real face loops on loopback. The waiting node listens on `tls/` with a certificate whose
//! key names its zid and asks every client for one; it hosts the lifecycle queries as a node does
//! (the router's session directory, the loop's intent, the board its machines are published to,
//! the link-state opener), and the test asks them in process. The dialling node presents a client
//! certificate and holds the waiting node by its zid, so it dials it, and dials it again when its
//! session is lost. What is read is the waiting node's board, its faces and the verdicts of the
//! queries:
//!
//! - the peer's own session is held under the passive intent (`established`, cause `passive`),
//!   and is the peer's one link in the status read;
//! - a reset ends that session once and the peer's next session is held again, and the same
//!   generation sent again closes nothing;
//! - a close ends it and takes the peer out of the intent, so the session the peer opens next is
//!   admitted as the accept policy says and held by no machine;
//! - CONTROL: a peer that claims a zid its key does not name opens the same session over the same
//!   channel and is not held, so what holds a session is the key's proof and not its arrival;
//! - a passive intent that comes after the peer's session is up holds that session at once,
//!   with no session of its own.

use std::cell::RefCell;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::watch;
use tokio_rustls::rustls::pki_types::ServerName;

use wz_runtime_tokio::accept_loop::{
    peer_loop, AcceptEvent, ConnectReconcile, FaceSources, LoopIntent, NoOpForwarder,
};
use wz_runtime_tokio::link_pipeline::bind_tcp;
use wz_runtime_tokio::link_socket::LinkSocket;
use wz_runtime_tokio::linkstate_forward::Zid;
use wz_runtime_tokio::peer_board::{BoardRow, PeerBoard};
use wz_runtime_tokio::retry_period::RetryPolicy;
use wz_runtime_tokio::router_forward::{RouterForwarder, RouterSessionDirectory};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_lifecycle_open::LinkstateOpener;
use wz_runtime_tokio::session_open::{
    BoundListener, DialConfig, SessionOffer, TlsAcceptPolicy, TlsDialConfig, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::tls_config::{
    client_config_from_pem, server_config_from_pem, ClientAuthPem, ServerNameVerification,
};
use wz_runtime_tokio_test_support::{fixture_session_init_params, loopback_mtls_pems};
use wz_session_core::drive::{LifecycleKey, SessionLifecycleAuthority};
use wz_session_core::lifecycle_query::{
    Answered, CloseVerdict, LifecycleQueries, OpenVerdict, ResetVerdict, SessionLinks,
    StatusVerdict,
};
use wz_session_core::query_sink::{BorrowedQuery, QueryView, ReplyError, ReplyOut};
use wz_session_core::sample::{EncodingHint, QosLevel};
use wz_session_core::zid_hex::zid_to_zenoh_hex;

/// How long any one thing the script waits for may take: a handshake over loopback and a retry
/// wait of the dialling node are each a fraction of it.
const BUDGET: Duration = Duration::from_secs(15);

/// The dialling node's wait before it dials again after a lost session.
const RETRY_MS: u64 = 150;

/// The zid the key in `key_pem` names, over the `SubjectPublicKeyInfo` `rcgen` serialises from the
/// private key itself: the oracle is not read back out of the certificate the session parsed.
fn zid_named_by(key_pem: &str) -> [u8; 16] {
    let key = rcgen::KeyPair::from_pem(key_pem).expect("key PEM");
    wz_session_core::credential_identity::zid_from_spki_der(&key.public_key_der())
}

/// Every verb permitted: the commander is not what these tests are about.
struct Permit;

impl SessionLifecycleAuthority for Permit {
    fn admits_close(&self, _key: &LifecycleKey<'_>) -> bool {
        true
    }
    fn admits_open(&self, _key: &LifecycleKey<'_>) -> bool {
        true
    }
    fn admits_reset(&self, _key: &LifecycleKey<'_>) -> bool {
        true
    }
    fn admits_status(&self, _key: &LifecycleKey<'_>) -> bool {
        true
    }
}

/// The lifecycle queries of the waiting node, over the ports a node hosts them with.
type Queries =
    LifecycleQueries<Permit, RouterSessionDirectory, LoopIntent, PeerBoard, LinkstateOpener>;

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
    fn reply_err(&mut self, _id: Option<u32>, _schema: Option<&[u8]>, _payload: &[u8]) {}
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

/// Which zid the dialling node claims on the wire.
#[derive(Clone, Copy)]
enum Claim {
    /// The one its certificate's key names.
    OfItsKey,
    /// Another one, over the same certificate.
    NotOfItsKey,
}

/// What the waiting node's loop reported of its faces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    Up,
    Down,
}

/// The two nodes, as the script of one test sees them.
struct Pair {
    queries: Queries,
    board: PeerBoard,
    /// The waiting node's zid.
    a_zid: [u8; 16],
    /// Where the waiting node listens.
    a_addr: SocketAddr,
    /// The zid the dialling node claims.
    b_zid: [u8; 16],
    /// The dialling node's reconcile channel.
    b_tx: UnboundedSender<ConnectReconcile>,
    seen: Arc<StdMutex<Vec<Seen>>>,
}

impl Pair {
    /// Ask the waiting node `verb_tail` (`status/<peer>`, `reset/<generation>/<peer>`, ...).
    fn ask(&self, verb_tail: &str) -> Answered {
        let key = format!(
            "@/{}/peer/session/{verb_tail}",
            zid_to_zenoh_hex(&self.a_zid)
        );
        let mut out = Recorder::default();
        // The view borrows `key`; it is bound so that it is dropped before `key` is.
        let asked = query(&key);
        self.queries.answer(&asked, &mut out)
    }

    /// The dialling node's zid as a key carries it.
    fn b(&self) -> String {
        zid_to_zenoh_hex(&self.b_zid)
    }

    fn status(&self) -> Answered {
        self.ask(&format!("status/{}", self.b()))
    }

    /// The machines the waiting node holds for the dialling node, as its board says.
    fn machine(&self) -> Vec<BoardRow> {
        self.board.rows(&self.b_zid)
    }

    /// Tell the dialling node to hold the waiting node by its zid, at where it listens.
    fn dial_a(&self) {
        self.b_tx
            .send(ConnectReconcile::AddNode {
                zid: self.a_zid,
                locators: vec![format!("tls/{}", self.a_addr)],
            })
            .expect("the dialling node's loop");
    }

    fn count(&self, which: Seen) -> usize {
        self.seen
            .lock()
            .expect("seen")
            .iter()
            .filter(|seen| **seen == which)
            .count()
    }

    fn ups(&self) -> usize {
        self.count(Seen::Up)
    }

    fn downs(&self) -> usize {
        self.count(Seen::Down)
    }
}

/// The waiting node's machine for the dialling node, as its board shows it.
fn row(state: &'static str, cause: Option<&'static str>, in_intent: bool) -> BoardRow {
    BoardRow {
        endpoint: None,
        state,
        cause,
        in_intent,
    }
}

/// Wait until `done` holds, or fail saying `what` did not happen within [`BUDGET`].
async fn until(what: &str, done: impl Fn() -> bool) {
    let end = Instant::now() + BUDGET;
    while !done() {
        assert!(Instant::now() < end, "{what}: not within {BUDGET:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn sources(
    listeners: Vec<BoundListener>,
    reconcile: tokio::sync::mpsc::UnboundedReceiver<ConnectReconcile>,
    dial_config: DialConfig,
    peer_board: Option<PeerBoard>,
) -> FaceSources {
    FaceSources {
        listeners,
        dial_targets: Vec::new(),
        dial_config: Arc::new(dial_config),
        dial_intents: None,
        mcast_ingress: None,
        mcast_members: None,
        mcast_group_subs: None,
        reconcile: Some(reconcile),
        #[cfg(feature = "transport-multilink")]
        max_links: 1,
        max_sessions: usize::MAX,
        accept: wz_runtime_tokio::accept_loop::AcceptBounds::default(),
        ceiling: None,
        peer_board,
        offer: SessionOffer::universal(),
        retry: RetryPolicy::constant(RETRY_MS),
        stats: None,
    }
}

async fn shutdown_on(mut rx: watch::Receiver<bool>) {
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Run the two nodes, the dialling one claiming as `claim` says, and `script` beside them; stop
/// both when the script ends.
async fn with_pair<F, Fut>(claim: Claim, script: F)
where
    F: FnOnce(Pair) -> Fut,
    Fut: Future<Output = ()>,
{
    let pems = loopback_mtls_pems();
    let a_zid = zid_named_by(&pems.server_key_pem);
    let b_zid = match claim {
        Claim::OfItsKey => zid_named_by(&pems.client_key_pem),
        Claim::NotOfItsKey => {
            let mut zid = zid_named_by(&pems.client_key_pem);
            zid[0] ^= 0x5a;
            zid
        }
    };

    // The waiting node presents its certificate and asks every client for one that chains to the
    // CA; the dialling node trusts the CA and presents its own.
    let server_config = server_config_from_pem(
        pems.server_cert_pem.as_bytes(),
        pems.server_key_pem.as_bytes(),
        Some(pems.ca_pem.as_bytes()),
    )
    .expect("the waiting node's mutual-TLS server config");
    let client_config = client_config_from_pem(
        Some(pems.ca_pem.as_bytes()),
        Some(ClientAuthPem {
            cert_chain_pem: pems.client_cert_pem.as_bytes(),
            private_key_pem: pems.client_key_pem.as_bytes(),
        }),
        ServerNameVerification::Verify,
    )
    .expect("the dialling node's mutual-TLS client config");

    let listener = bind_tcp(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &LinkSocket::NONE,
    )
    .await
    .expect("bind the waiting node");
    let a_addr = listener.local_addr().expect("the waiting node's address");
    let a_listener = BoundListener::Tls(
        listener,
        server_config,
        TlsAcceptPolicy {
            closes_on_expiration: false,
            handshake_timeout: Duration::from_secs(10),
        },
    );

    let (shut_tx, shut_rx) = watch::channel(false);

    // The waiting node, and the lifecycle queries it hosts, made of what a node makes them of.
    let a_router = RouterForwarder::new(Zid::from_slice(&a_zid));
    let board = PeerBoard::new();
    let (a_tx, a_rx) = tokio::sync::mpsc::unbounded_channel();
    let queries = LifecycleQueries::new(
        &zid_to_zenoh_hex(&a_zid),
        "peer",
        Permit,
        a_router.lifecycle_directory(),
    )
    .with_intent(LoopIntent(a_tx.clone()))
    .with_machines(board.clone())
    .with_opener(LinkstateOpener::over(a_router.node_locators(), a_tx));
    let seen: Arc<StdMutex<Vec<Seen>>> = Arc::new(StdMutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let mut a_params = fixture_session_init_params();
    a_params.zid = a_zid.into();
    let a = peer_loop(
        sources(
            vec![a_listener],
            a_rx,
            DialConfig::default(),
            Some(board.clone()),
        ),
        a_params,
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(shut_rx.clone()),
        move |event: &AcceptEvent| match event {
            AcceptEvent::FaceUp(_) => sink.lock().expect("seen").push(Seen::Up),
            AcceptEvent::FaceDown(..) => sink.lock().expect("seen").push(Seen::Down),
            _ => {}
        },
        &a_router,
    );

    // The dialling node: no listener, a client certificate, and the waiting node held by its zid
    // when the script says so.
    let (b_tx, b_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut b_params = fixture_session_init_params();
    b_params.zid = b_zid.into();
    let b_dial = DialConfig::default().with_tls(TlsDialConfig {
        client_config,
        server_name: ServerName::try_from("localhost").expect("the server's name"),
    });
    let b = peer_loop(
        sources(Vec::new(), b_rx, b_dial, None),
        b_params,
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(shut_rx),
        |_: &AcceptEvent| {},
        &NoOpForwarder,
    );

    let pair = Pair {
        queries,
        board,
        a_zid,
        a_addr,
        b_zid,
        b_tx,
        seen,
    };
    let run = async move {
        script(pair).await;
        let _ = shut_tx.send(true);
    };
    tokio::time::timeout(Duration::from_secs(120), async { tokio::join!(a, b, run) })
        .await
        .expect("the script ends and both loops stop when told");
}

/// The hold, the reset and the close of a peer held by the session it opens, over mutual TLS.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_waiting_node_holds_the_session_a_peer_opens_over_mutual_tls_and_the_verbs_reach_it() {
    with_pair(Claim::OfItsKey, |pair| async move {
        assert_eq!(
            pair.ask(&format!("open/passive/{}", pair.b())),
            Answered::Open(OpenVerdict::Opening)
        );
        until("the passive intent reaches the loop", || {
            pair.machine() == vec![row("passive", None, true)]
        })
        .await;
        assert_eq!(pair.ups(), 0, "waiting dials nothing and nothing has come");

        // THE HOLD: the peer opens its session, and the key it proved holds it.
        pair.dial_a();
        until("the peer's own session is held", || {
            pair.machine() == vec![row("established", Some("passive"), true)]
        })
        .await;
        assert_eq!(pair.ups(), 1);
        assert_eq!(
            pair.status(),
            Answered::Status(StatusVerdict::Status {
                links: SessionLinks {
                    open: 1,
                    closing: 0
                },
                intent: true,
                machines: 1,
            })
        );

        // RESET: the session ends once, the peer's next one is held, and the same generation
        // sent again (a retransmission) ends nothing.
        let reset = format!("reset/1/{}", pair.b());
        assert_eq!(
            pair.ask(&reset),
            Answered::Reset(ResetVerdict::Resetting { links: 1 })
        );
        until(
            "the reset ends the session and the peer's next one is held",
            || {
                pair.downs() == 1
                    && pair.ups() == 2
                    && pair.machine() == vec![row("established", Some("passive"), true)]
            },
        )
        .await;
        assert_eq!(
            pair.ask(&reset),
            Answered::Reset(ResetVerdict::Duplicate { last: 1 })
        );
        tokio::time::sleep(Duration::from_millis(1_000)).await;
        assert_eq!(pair.downs(), 1, "a retransmitted reset ended a session");

        // CLOSE: the session ends and the peer leaves the intent.
        assert_eq!(
            pair.ask(&format!("close/{}", pair.b())),
            Answered::Close(CloseVerdict::Closing { links: 1 })
        );
        until("the close ends the session and takes the peer out", || {
            pair.downs() == 2 && pair.machine() == vec![row("idle", None, false)]
        })
        .await;
        // The peer still holds this node by its own intent and dials it again; its session is
        // admitted as the accept policy says, and no machine here holds it.
        until("the peer dials again", || pair.ups() == 3).await;
        tokio::time::sleep(Duration::from_millis(5 * RETRY_MS)).await;
        assert_eq!(pair.machine(), vec![row("idle", None, false)]);
        assert!(
            matches!(
                pair.status(),
                Answered::Status(StatusVerdict::Status { intent: false, .. })
            ),
            "a closed peer is out of the intent: {:?}",
            pair.status()
        );
    })
    .await;
}

/// CONTROL: the same session over the same channel, from a peer that claims a zid its key does
/// not name, is admitted and held by no machine, so the hold above is the key's proof.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_claims_a_zid_its_key_does_not_name_is_not_held() {
    with_pair(Claim::NotOfItsKey, |pair| async move {
        assert_eq!(
            pair.ask(&format!("open/passive/{}", pair.b())),
            Answered::Open(OpenVerdict::Opening)
        );
        until("the passive intent reaches the loop", || {
            pair.machine() == vec![row("passive", None, true)]
        })
        .await;
        pair.dial_a();
        until("the claimed peer's session is admitted", || pair.ups() == 1).await;
        tokio::time::sleep(Duration::from_millis(1_000)).await;
        assert_eq!(
            pair.machine(),
            vec![row("passive", None, true)],
            "an unproven claim of the zid held the session"
        );
        assert_eq!(
            pair.status(),
            Answered::Status(StatusVerdict::Status {
                links: SessionLinks {
                    open: 1,
                    closing: 0
                },
                intent: true,
                machines: 1,
            }),
            "the session is there, named by the zid it claims, and still waited for"
        );
    })
    .await;
}

/// A passive intent that comes after the peer's session is up holds that session at once: the
/// intent is the peer's session, and waiting for the next one would leave this one unheld.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_passive_open_holds_the_session_the_peer_already_opened() {
    with_pair(Claim::OfItsKey, |pair| async move {
        pair.dial_a();
        until("the peer's session is admitted", || pair.ups() == 1).await;
        assert!(
            pair.machine().is_empty(),
            "no machine holds a peer nobody asked for"
        );

        assert_eq!(
            pair.ask(&format!("open/passive/{}", pair.b())),
            Answered::Open(OpenVerdict::Opening)
        );
        until("the session that is up is held", || {
            pair.machine() == vec![row("established", Some("passive"), true)]
        })
        .await;
        assert_eq!(
            (pair.ups(), pair.downs()),
            (1, 0),
            "held without a session of its own"
        );
    })
    .await;
}
