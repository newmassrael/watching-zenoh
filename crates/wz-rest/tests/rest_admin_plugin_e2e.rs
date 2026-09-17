// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! End-to-end proof that the REST bridge ADVERTISES ITSELF on the adminspace,
//! the wz analogue of `zenoh-plugin-rest`'s `adminspace_getter`
//! (`plugins/zenoh-plugin-rest/src/lib.rs` @ `fn adminspace_getter<'a>(`).
//!
//! An HTTP client asks the bridge about the bridge: `GET
//! /@/local/peer/status/plugins/rest/**` goes in over HTTP/1.1, becomes a wz
//! query, is answered by the node's own admin queryable, and comes back as the
//! bridge's JSON reply array. That is the same round trip an operator makes
//! against a zenohd whose rest plugin is loaded — where the plugin's status is
//! read through the plugin.
//!
//! ## What each assertion can fail on, and why that is the point
//!
//! - **The record exists at all.** Before this round the bridge was absent from
//!   `compiled_plugins`, so `status/plugins/rest/**` had nothing to intersect
//!   and the GET returned an empty array. An empty array is what a node with no
//!   such plugin returns, which is why the absence was invisible.
//! - **It is `Started`, and only while serving.** The `status/plugins` legs are
//!   behind a `Started` gate (upstream's `started_plugins_iter`). The control
//!   below drives that boundary directly: the SAME live registry is read at a
//!   moment when the bridge is not accepting, and the sub-tree must vanish.
//! - **The `port` body carries the LIVE bound address.** The test binds port 0,
//!   so a record rendering the *requested* address would report `:0` here and
//!   pass every shape assertion. The literal it must match is read back out of
//!   the listener.
//!
//! ## Non-flakiness ([[feedback-no-flaky-ever]])
//!
//! Nothing here waits on propagation: the admin queryable and the querying
//! session are the same session, so the GET is answered on the loopback leg
//! within the call. The one ordering fact — the bridge must be accepting before
//! the HTTP request — is established by connecting to it, which cannot succeed
//! before the listener is serving.

#![cfg(feature = "adminspace-plugins-handlers")]

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::TokioSession;
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::adminspace::{AdminLiveInputs, AdminSpacePermissions};
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::zid_hex::zid_to_zenoh_hex;

use wz_rest::admin::PLUGIN_ID;
use wz_rest::RestAdmin;

const ITER_CAP: usize = 64;
const VERSION: &str = "0.4.2";
const BRIDGE_ZID: &[u8] = &[0x01, 0x01, 0x01, 0x01];

/// Send one raw HTTP request to `addr` and read the whole response (the bridge
/// replies `Connection: close`, so read to EOF). Returns `(status, body)`.
async fn http(addr: std::net::SocketAddr, request: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).await.expect("connect http");
    stream.write_all(request).await.expect("write request");
    stream.flush().await.expect("flush request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read response");

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a header terminator");
    let head = &raw[..split];
    let body = raw[split + 4..].to_vec();
    let status: u16 = std::str::from_utf8(head)
        .expect("ascii head")
        .lines()
        .next()
        .expect("status line")
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status code");
    (status, body)
}

fn get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").into_bytes()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_bridge_reports_itself_on_the_adminspace() {
    // ── A wz link so the bridge's session can reach Established. The far side
    //    only exists to complete the handshake; every assertion below is about
    //    the bridge node's own admin surface.
    let link = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz link");
    let link_addr = link.local_addr().expect("wz link addr");

    // Port 0: the record must report what the OS assigned, not what was asked
    // for. Bound here so this test knows the answer independently of the record.
    let http_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind http");
    let http_addr = http_listener.local_addr().expect("http addr");

    let peer_open = async {
        let (stream, _peer) = link.accept().await.expect("accept");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
        accept_and_open_session(
            DialedLink::Tcp(stream),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor Established")
    };
    let bridge_open = async {
        let locator = parse_any_locator(&format!("tcp/{link_addr}")).expect("parse locator");
        let mut params = fixture_session_init_params();
        params.zid = BRIDGE_ZID.to_vec();
        connect_and_open_session(
            locator,
            params,
            &DialConfig::default(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("bridge Established")
    };
    let (mut opened_peer, mut opened_bridge) = tokio::join!(peer_open, bridge_open);

    let timeouts = SessionTimeouts::spec_defaults();
    let zid_hex = zid_to_zenoh_hex(BRIDGE_ZID);
    let whatami = opened_bridge.actions.params.whatami.to_str();

    let session_bridge = TokioSession::new(
        opened_bridge.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened_bridge.clock),
    );

    // ── THE FOLD. The static registry reports what this binary compiled in;
    //    `RestAdmin` reports what is actually accepting. The `Some` REPLACES the
    //    `Loaded` entry for the same id, which is what makes one GET describe one
    //    moment — the record and its sub-tree are minted together.
    let admin = RestAdmin::new();
    let admin_for_get = admin.clone();
    let _adminspace = session_bridge
        .declare_adminspace_with_live_inputs(VERSION, Vec::new(), move || {
            let mut plugins = wz_runtime_tokio::compiled_plugins(VERSION);
            if let Some(live) = admin_for_get.plugin_record(VERSION) {
                match plugins.iter_mut().find(|p| p.id == live.id) {
                    Some(slot) => *slot = live,
                    None => plugins.push(live),
                }
            }
            AdminLiveInputs {
                permissions: AdminSpacePermissions::default(),
                plugins,
                config_json: String::from("{}"),
                stats: None,
            }
        })
        .expect("adminspace-core ON in this build");

    // The static registry must already name the bridge — the marker feature
    // travels with the wz-rest crate, so a build running this test is a build
    // whose registry knows the bridge is compiled in.
    let compiled = wz_runtime_tokio::compiled_plugins(VERSION);
    assert!(
        compiled.iter().any(|p| p.id == PLUGIN_ID),
        "the bridge is linked, so the compiled registry must name it: {:?}",
        compiled.iter().map(|p| &p.id).collect::<Vec<_>>()
    );

    let serve = tokio::spawn(wz_rest::serve_on_with_admin(
        http_listener,
        session_bridge.clone(),
        BRIDGE_ZID.to_vec(),
        admin.clone(),
    ));

    let session_bridge_drive = session_bridge.clone();
    let drive_bridge = drive_session_until_terminal(
        &mut opened_bridge.inbound,
        &opened_bridge.actions,
        &mut opened_bridge.engine,
        None,
        &opened_bridge.clock,
        &timeouts,
        move |event| session_bridge_drive.dispatch_iteration_event(event),
    );
    let drive_peer = drive_session_until_terminal(
        &mut opened_peer.inbound,
        &opened_peer.actions,
        &mut opened_peer.engine,
        None,
        &opened_peer.clock,
        &timeouts,
        |_event| {},
    );

    let exercise = async {
        // ── THE ROUND TRIP: ask the bridge about the bridge. ONE GET over the
        //    node's whole admin subtree, so the registry leg and the status
        //    sub-tree below are answered from one call to the live source and
        //    therefore describe one moment — which is the property
        //    `AdminLiveInputs` exists to give and a second GET would give up.
        //
        //    ⚠ It costs the bridge's full `QUERY_TIMEOUT_MS`. Measured, not
        //    assumed: the admin queryable answers on the loopback leg
        //    immediately, but the query is also routed to the far face, which
        //    has no matching queryable and so never sends a ResponseFinal — the
        //    sweep fires `on_final` at the deadline. Upstream's plugin issues
        //    its GET the same way (`queries_default_timeout`), so this is the
        //    shape of a REST admin GET rather than a wz defect, and it is why
        //    this test asks once.
        let (status, body) = http(http_addr, &get(&format!("/@/local/{whatami}/**"))).await;
        assert_eq!(status, 200, "admin GET answered");
        let text = String::from_utf8(body).expect("utf8 reply array");

        // `@/local` is the bridge's alias for this node's own zid; the reply keys
        // must come back fully resolved, as a zenoh admin reply does.
        //
        // ⚠ EVERY assertion below pins a KEY AND ITS BODY TOGETHER, as the one
        // contiguous `"key":<K>,"value":<V>` pair the bridge's renderer emits.
        // Asserting them apart is what the first draft did, and it does not
        // check what it says: `text.contains(VERSION)` passed with the version
        // leaf ABSENT, because `"version":"0.4.2"` also occurs in `local_data`
        // and in the registry record -- measured on this test's own control
        // run, where the string survived twice with the whole sub-tree gone.
        // Two substring assertions over one array never have to be about the
        // same reply.
        let root = format!("@/{zid_hex}/{whatami}/status/plugins/{PLUGIN_ID}");
        let pair = |key: &str, value: &str| format!("{{\"key\":\"{key}\",\"value\":{value}");

        // The plugin path leg: `text/plain`, the wz static-subsystem marker.
        assert!(
            text.contains(&pair(&format!("{root}/__path__"), "\"__static__\"")),
            "the plugin path leg is served with the static marker ({text})"
        );
        // `version` -- the node build version a static wz subsystem reports,
        // as a bare JSON string (upstream's `GIT_VERSION` shape).
        assert!(
            text.contains(&pair(&format!("{root}/version"), &format!("\"{VERSION}\""))),
            "the version leaf carries the node build version ({text})"
        );
        // `port` -- upstream's config object, carrying the address the listener
        // is REALLY on. The request asked for port 0, so a record rendering the
        // REQUESTED address would put `:0` here.
        assert!(
            text.contains(&pair(
                &format!("{root}/port"),
                &format!("{{\"http_port\":\"{http_addr}\"}}")
            )),
            "the port leaf carries the live bound address {http_addr} ({text})"
        );

        // The registry leg (`plugins/<id>`) answered by the SAME call, pinned
        // whole: `state` is checked INSIDE the bridge's own record rather than
        // anywhere in the array, so another plugin's state can never satisfy
        // it. `Started` is also the gate the sub-tree above sits behind, so the
        // two halves cannot disagree about whether the bridge is running.
        assert!(
            text.contains(&pair(
                &format!("@/{zid_hex}/{whatami}/plugins/{PLUGIN_ID}"),
                &format!(
                    "{{\"name\":\"{PLUGIN_ID}\",\"id\":\"{PLUGIN_ID}\",\
                     \"version\":\"{VERSION}\",\"long_version\":null,\
                     \"path\":\"__static__\",\"state\":\"Started\""
                )
            )),
            "the registry record names the bridge and reports it Started ({text})"
        );

        // ── THE CONTROL, at the boundary the `Started` gate actually turns on.
        //    A record built from a host-held flag would survive a bridge that
        //    stopped accepting; one minted from the accept loop's guard cannot.
        //    This is the same live source the GET above read, asked at a moment
        //    when nothing is serving.
        let stale = RestAdmin::new();
        assert!(
            stale.plugin_record(VERSION).is_none(),
            "a bridge that is not accepting mints no Started record"
        );
        assert!(
            stale.status_leaves(VERSION).is_none(),
            "and no sub-tree either — the leaves and the state are minted together"
        );
    };

    tokio::select! {
        _ = drive_bridge => panic!("bridge session left Established"),
        _ = drive_peer => panic!("peer session left Established"),
        _ = exercise => {}
        _ = tokio::time::sleep(Duration::from_secs(30)) => panic!("admin GET never completed"),
    }

    serve.abort();
}
