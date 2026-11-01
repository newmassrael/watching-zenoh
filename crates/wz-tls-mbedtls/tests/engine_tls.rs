// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The cooperative engine over `tls/`, both roles (step T3 of L6 in
//! `docs/capi-pico-on-coop-engine.md`): the listener binds a `tls/` port and takes the
//! connections that arrive as faces of its own, and a client dials one, exactly as over `tcp/`
//! (`wz-capi-coop`'s `tests/listen.rs`). Both ends are the engine, each stepped by a read task of
//! its own, so two threads reach the channel and the library's `host-lock` is what lets them.
//!
//! What is held: a session opens over a chain-verified `tls/` link and carries a put each way;
//! under mutual TLS a listener holds a face for each client whose chain it vouches for and none
//! for a client it does not; a client that does not trust the listener's root never opens; and a
//! pinned link (decision D1) carries a session whose zid is its key's zid.
#![cfg(all(feature = "vendored", feature = "host-lock"))]

mod common;

use std::ops::Deref;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use rcgen::ExtendedKeyUsagePurpose;

use common::{library, Authority, End};
use wz_capi_coop::{CoopConfig, CoopEngine, OpenError, DEFAULT_ACCEPT_PENDING, DEFAULT_MAX_FACES};
use wz_capi_port::{SessionDrive, SessionEngine, WireKey};
use wz_runtime_coop::ip_stack::IpLinks;
use wz_runtime_posix::net::PosixUdpSocket;
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::session_init_params::{KeepAliveConf, LinkRxConf, TxQueueConf};
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::sink::SampleView;
use wz_session_core::WhatAmI;
use wz_tls_mbedtls::channel::{Identity, Trust};
use wz_tls_mbedtls::stream::{AcceptBudget, ChainTrust, TlsDial};

const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

type Links = IpLinks<PosixUdpSocket, PosixTcpDial, TlsDial<PosixTcpDial>>;
type Engine = CoopEngine<Links, PosixClock>;

fn clock_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    u64::try_from(START.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX)
}

const ACCEPT: AcceptBudget = AcceptBudget {
    clock: clock_ms,
    timeout_ms: 5_000,
};

/// A config that dials nothing and listens on nothing: what a test states the endpoints of.
fn base_config() -> CoopConfig {
    CoopConfig {
        endpoints: Vec::new(),
        whatami: WhatAmI::Client,
        zid: Some(vec![0xb1; 4]),
        batch_size: 1024,
        lease_ms: 10_000,
        keep_alive: KeepAliveConf::PICO,
        sn_resolution: wz_session_core::policy::SnResolution::default(),
        link_rx: LinkRxConf::default(),
        tx_queue: TxQueueConf::pico(),
        timeouts: SessionTimeouts::spec_defaults(),
        open_timeout_ms: 5_000,
        redial_ms: None,
        idle_wait_ms: 100,
        listen: Vec::new(),
        accept_pending: DEFAULT_ACCEPT_PENDING,
        max_faces: DEFAULT_MAX_FACES,
    }
}

fn open(dial: TlsDial<PosixTcpDial>, config: CoopConfig) -> Result<Arc<Engine>, OpenError> {
    Engine::open(
        IpLinks::new(LOOPBACK, PosixTcpDial)
            .with_tls(dial)
            .waited_by_owner(),
        PosixClock,
        PosixEntropy,
        config,
    )
}

/// A session whose read task is running, closed when it is let go of.
struct Stepped(Arc<Engine>);

impl Stepped {
    fn new(engine: Arc<Engine>) -> Self {
        SessionDrive::start_read_task(&*engine).expect("the read task starts");
        Self(engine)
    }
}

impl Deref for Stepped {
    type Target = Engine;

    fn deref(&self) -> &Engine {
        &self.0
    }
}

impl Drop for Stepped {
    fn drop(&mut self) {
        SessionDrive::close(&*self.0);
    }
}

fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn identity(end: &End) -> &'static Identity {
    Box::leak(Box::new(end.identity()))
}

fn roots(authority: &Authority) -> &'static Trust {
    Box::leak(Box::new(
        Trust::roots(&authority.root_pem(), None).expect("the roots"),
    ))
}

/// The dial of a listener: presents `server`, and under mutual TLS requires a chain `authority`
/// vouches for.
fn listener_dial(server: &End, mutual_roots: Option<&Authority>) -> TlsDial<PosixTcpDial> {
    TlsDial::chain(
        PosixTcpDial,
        ChainTrust {
            identity: Some(identity(server)),
            roots: mutual_roots.map(roots),
            mutual: mutual_roots.is_some(),
            verify_name: false,
        },
    )
    .with_accept(ACCEPT)
}

/// The dial of a client that verifies the listener's chain against `authority`, its name as the
/// address it dials, presenting `mutual_as` under mutual TLS.
fn client_dial(authority: &Authority, mutual_as: Option<&End>) -> TlsDial<PosixTcpDial> {
    TlsDial::chain(
        PosixTcpDial,
        ChainTrust {
            identity: mutual_as.map(identity),
            roots: Some(roots(authority)),
            mutual: mutual_as.is_some(),
            verify_name: true,
        },
    )
}

/// A session that listens on a loopback `tls/` port the kernel picks and dials nothing, with the
/// endpoint it is bound to.
fn listening(dial: TlsDial<PosixTcpDial>, zid: Vec<u8>) -> (Stepped, String) {
    let engine = open(
        dial,
        CoopConfig {
            whatami: WhatAmI::Peer,
            zid: Some(zid),
            listen: vec!["tls/127.0.0.1:0".to_owned()],
            ..base_config()
        },
    )
    .expect("the listener opens");
    let endpoint = engine.listening().pop().expect("one port is bound");
    (Stepped::new(engine), endpoint)
}

/// A client session that dials `endpoint`, or why it did not open.
fn client(
    dial: TlsDial<PosixTcpDial>,
    endpoint: &str,
    zid: Vec<u8>,
    open_timeout_ms: u64,
) -> Result<Stepped, OpenError> {
    open(
        dial,
        CoopConfig {
            endpoints: vec![endpoint.to_owned()],
            zid: Some(zid),
            open_timeout_ms,
            ..base_config()
        },
    )
    .map(Stepped::new)
}

/// Declare a subscriber on `demo/t/**` and collect the payloads it hears.
fn hearing(session: &Engine) -> Arc<Mutex<Vec<Vec<u8>>>> {
    let heard = Arc::new(Mutex::new(Vec::new()));
    let into = heard.clone();
    session.declare_subscriber_on_wire(
        "demo/t/**".to_owned(),
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

fn put(session: &Engine, payload: &[u8]) {
    session
        .publish_on_wire_all(
            "demo/t/x",
            &WireKey::literal(),
            payload,
            &PublishOptions::put().with_locality(Locality::Remote),
        )
        .expect("a put the link carries");
}

#[test]
fn a_session_opens_over_a_chain_verified_tls_link_and_carries_a_put_each_way() {
    let _library = library();
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let (listener, endpoint) = listening(listener_dial(&server, None), vec![0xa1; 4]);
    assert!(
        endpoint.starts_with("tls/127.0.0.1:") && !endpoint.ends_with(":0"),
        "the endpoint names the scheme and the port the kernel picked: {endpoint}"
    );
    assert_eq!(listener.faces_up(), 0, "CONTROL: no face before a client");

    let at_listener = hearing(&listener);
    let peer = client(
        client_dial(&authority, None),
        &endpoint,
        vec![0xc1; 4],
        5_000,
    )
    .expect("the client opens over tls");
    eventually("the listener to hold the face", || listener.faces_up() == 1);
    let at_client = hearing(&peer);

    put(&peer, b"to-listener");
    eventually("the listener to hear the client", || {
        at_listener.lock().unwrap().len() == 1
    });
    assert_eq!(at_listener.lock().unwrap()[0], b"to-listener");

    // The listener's put reaches the client once the client's subscriber is declared there.
    eventually("the listener to know the client's subscriber", || {
        put(&listener, b"to-client");
        !at_client.lock().unwrap().is_empty()
    });
    assert_eq!(at_client.lock().unwrap()[0], b"to-client");
}

#[test]
fn under_mutual_tls_a_listener_holds_a_face_for_each_vouched_client_and_none_for_another() {
    let _library = library();
    let authority = Authority::new();
    let stranger = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let (listener, endpoint) = listening(listener_dial(&server, Some(&authority)), vec![0xa1; 4]);
    let heard = hearing(&listener);

    let mut peers = Vec::new();
    for id in [0xc1u8, 0xc2] {
        let own = authority.issue(ExtendedKeyUsagePurpose::ClientAuth);
        peers.push(
            client(
                client_dial(&authority, Some(&own)),
                &endpoint,
                vec![id; 4],
                5_000,
            )
            .expect("a vouched client opens"),
        );
    }
    eventually("the listener to hold both faces", || {
        listener.faces_up() == 2
    });
    for (peer, text) in peers.iter().zip([&b"first"[..], &b"second"[..]]) {
        put(peer, text);
    }
    eventually("the listener to hear both", || {
        heard.lock().unwrap().len() == 2
    });

    // A client whose chain the listener's roots do not vouch for never opens, and takes no face.
    let strange = stranger.issue(ExtendedKeyUsagePurpose::ClientAuth);
    let refused = client(
        client_dial(&authority, Some(&strange)),
        &endpoint,
        vec![0xc3; 4],
        1_500,
    );
    assert!(
        refused.is_err(),
        "a client the roots do not vouch for opened"
    );
    assert_eq!(listener.faces_up(), 2, "and the faces held stand");
}

#[test]
fn a_client_that_does_not_trust_the_listeners_root_never_opens() {
    let _library = library();
    let authority = Authority::new();
    let stranger = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let (listener, endpoint) = listening(listener_dial(&server, None), vec![0xa1; 4]);

    let refused = client(
        client_dial(&stranger, None),
        &endpoint,
        vec![0xc1; 4],
        5_000,
    );
    assert!(
        matches!(refused, Err(OpenError::Unreachable(_))),
        "the listener's chain does not verify against these roots"
    );
    assert_eq!(listener.faces_up(), 0);

    // The refused handshake did not wedge the port: a client that trusts the root is taken.
    let _peer = client(
        client_dial(&authority, None),
        &endpoint,
        vec![0xc2; 4],
        5_000,
    )
    .expect("a client that trusts the root opens");
    eventually("the face to be up", || listener.faces_up() == 1);
}

/// A pinned dial: the identity is the zid, and the listener lists the port when it can accept.
fn pinned(identity: &'static Identity, accepts: bool) -> TlsDial<PosixTcpDial> {
    let dial = TlsDial::new(PosixTcpDial, identity);
    if accepts {
        dial.with_accept(ACCEPT)
    } else {
        dial
    }
}

/// Under the pinned policy a session's zid is the zid of its key (decision D1), and the session
/// opens and carries a put as over any link. The binding itself is not a refusal at the
/// handshake: the session reports it (`SessionLinkActions::peer_identity_verified`) for the
/// consumers that need it (the lifecycle verbs), and the engine's port does not expose it, so a
/// zid the key does not name is not a refusal here and is not asserted as one.
#[test]
fn a_pinned_tls_link_carries_a_session_whose_zid_is_its_keys_zid() {
    let _library = library();
    let server_id: &'static Identity = Box::leak(Box::new(
        Identity::generate(c"CN=wz-pinned-listener").unwrap(),
    ));
    let client_id: &'static Identity = Box::leak(Box::new(
        Identity::generate(c"CN=wz-pinned-client").unwrap(),
    ));
    let (listener, endpoint) = listening(pinned(server_id, true), server_id.zid().to_vec());
    assert_eq!(listener.faces_up(), 0, "CONTROL: no face before a client");

    let peer = client(
        pinned(client_id, false),
        &endpoint,
        client_id.zid().to_vec(),
        5_000,
    )
    .expect("a client that states its key's zid opens");
    eventually("the face to be up", || listener.faces_up() == 1);
    let heard = hearing(&listener);
    put(&peer, b"pinned");
    eventually("the listener to hear the client", || {
        heard.lock().unwrap().len() == 1
    });
}
