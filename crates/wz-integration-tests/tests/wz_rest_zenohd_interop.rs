// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y501 §5.26 — wz's REST bridge against the REAL `zenoh-plugin-rest`.
//!
//! One zenohd runs the reference REST plugin; a wz client session dials it over
//! TCP and serves wz's own bridge on a second HTTP port. Both bridges therefore
//! sit on the SAME zenoh network, which is what makes a differential possible:
//! one sample, two independent HTTP renderings of it.
//!
//! ## Why this is the oracle, and why it did not exist before
//!
//! `wz-rest` is a hand-rolled HTTP/1.1 server written as a compile-time
//! superset of zenoh's dlopen `tide` plugin. Its counterparty is therefore not
//! zenoh-pico (which has no REST surface at all) but the plugin cdylib — and
//! `scripts/build-zenohd.sh` built the storage-manager and zenoh-ext oracles
//! while never building this one, so §5.26 had no foreign witness. The flag
//! `--rest-http-port` being present in `zenohd --help` is NOT evidence the
//! plugin exists: zenohd accepts it unconditionally and then dies at startup
//! with `Plugin load failure`. [`rest_plugin`] asserts the `.so` itself.
//!
//! ## What each leg proves
//!
//! 1. [`wz_rest_put_reaches_the_zenohd_rest_plugin`] (`wz->zenohd`) — an HTTP
//!    `PUT` to WZ's bridge is translated to a zenoh `Put`, routed by zenohd, and
//!    read back out of the REFERENCE plugin's SSE stream. wz's HTTP-to-zenoh
//!    direction is thus validated by a foreign HTTP surface, end to end.
//! 2. [`wz_rest_sse_renders_the_same_sample_as_the_zenohd_rest_plugin`]
//!    (`zenohd->wz`) — the mirror, and the DIFFERENTIAL. A foreign `PUT` issued
//!    against zenohd's plugin fans out to BOTH bridges' SSE subscriptions, and
//!    the two `JSONSample` objects must be EQUAL, field for field, for a
//!    payload of each rendering class (`text/plain` -> bare string,
//!    `application/json` -> embedded JSON, `application/octet-stream` -> base64).
//!    The timestamp is included, so this also pins wz's `<ntp64>/<zid-hex>`
//!    rendering to the reference's `uhlc::Timestamp` Display.
//!
//! Leg 2 is deliberately a differential rather than a golden-string assertion:
//! the expected bytes are produced by the reference implementation IN THE SAME
//! RUN, so the leg cannot rot into agreeing with a transcription of what zenoh
//! used to emit.
//!
//! ## Non-flakiness ([[feedback-no-flaky-ever]])
//!
//! `Declare` propagation is absorbed by re-publishing on a poll cadence rather
//! than slept through, and every assertion still requires the real remote
//! effect within the budget. Each sample is matched by a key UNIQUE to its leg
//! and class, so a substring scan cannot be satisfied by a neighbouring event
//! ([[feedback-log-barrier-unique-or-counted]]).
//!
//! **Leg 2 needs more than that, and the first version of it was WRONG.** A
//! differential compares two renderings OF ONE SAMPLE, but every re-publish
//! mints a NEW sample with a new timestamp — so when one subscriber's `Declare`
//! landed a round later than the other's, each side's "first event for this
//! key" was a DIFFERENT publish, and the leg compared two unrelated objects.
//! It passed repeatedly before a re-run caught it: identical key, value and
//! encoding, timestamps one publish apart. Retrying was never the fix; the
//! retry itself was the defect.
//!
//! So the retry now targets a WARMUP key whose only job is to establish both
//! subscriptions, and only once BOTH streams have shown that warmup sample is
//! each class published — EXACTLY ONCE. Sample identity is then structural
//! rather than hoped for, and `assert_eq!((wz.len(), foreign.len()), (1, 1))`
//! makes any recurrence fail loudly instead of silently comparing the wrong
//! pair.
//!
//! `#[ignore]` (binary-dep e2e): needs `target/zenohd/zenohd` +
//! `target/zenohd/libzenoh_plugin_rest.so`, both from `scripts/build-zenohd.sh`
//! (a SOURCE build — `cargo install` yields no cdylib). Run via Layer Z /
//! `--ignored`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use wz_integration_tests::common::{
    rest_plugin, spawn_zenohd_dialer_on_ephemeral_tcp_with_cfgs, zenohd_binary, ChildGuard,
    PortReservation,
};

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::TokioSession;
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    connect_and_open_session, DialConfig, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::zenohd_interop_session_init_params;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 256;
/// Budget for "both SSE streams delivered the sample": 200 publish rounds of
/// ~4x50ms of reading. Generous over a loopback round trip; the assertion is
/// still "the foreign process actually delivered it", never a sleep.
const PUBLISH_ROUNDS: usize = 200;
const READ_SLICES: usize = 4;
const READ_SLICE: Duration = Duration::from_millis(50);

/// Leg 1's key — an HTTP PUT into wz's bridge, observed on zenohd's plugin.
const WZ_TO_ZENOHD_KEY: &str = "demo/rest/interop/wz-to-zenohd";
const WZ_TO_ZENOHD_VALUE: &str = "put-through-the-wz-bridge";

/// One parsed `JSONSample` — the four fields both implementations emit, kept as
/// raw JSON text per field so the comparison is on the RENDERING, not on a
/// re-parse that would normalise away exactly the differences under test.
#[derive(Debug, PartialEq, Eq)]
struct JsonSample {
    key: String,
    value: String,
    encoding: String,
    timestamp: String,
}

/// Split a compact `{"key":..,"value":..,"encoding":..,"timestamp":..}` object
/// into its four raw field texts.
///
/// A hand-written splitter rather than a JSON parser, deliberately: the point of
/// the differential is that `"value":{"a":1}` and `"value":"{\"a\":1}"` are
/// DIFFERENT renderings of the same data, and any parse-then-compare would have
/// to be careful not to erase that. Splitting on the top-level field boundaries
/// keeps each field's literal text intact.
fn parse_json_sample(object: &str) -> Option<JsonSample> {
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let body = object.strip_prefix('{')?.strip_suffix('}')?;
    let bytes = body.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // Field name.
        while i < bytes.len() && bytes[i] != b'"' {
            i += 1;
        }
        let name_start = i + 1;
        i += 1;
        while i < bytes.len() && bytes[i] != b'"' {
            i += 1;
        }
        let name = body.get(name_start..i)?.to_string();
        i += 1;
        while i < bytes.len() && bytes[i] != b':' {
            i += 1;
        }
        i += 1; // past ':'

        // Field value: scan to the top-level ',' that ends it, tracking nesting
        // and string state so a comma inside a value never splits it.
        let value_start = i;
        let mut depth = 0i32;
        let mut in_string = false;
        let mut escaped = false;
        while i < bytes.len() {
            let b = bytes[i];
            if in_string {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == b'"' {
                    in_string = false;
                }
            } else {
                match b {
                    b'"' => in_string = true,
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => depth -= 1,
                    b',' if depth == 0 => break,
                    _ => {}
                }
            }
            i += 1;
        }
        fields.insert(name, body.get(value_start..i)?.trim().to_string());
        i += 1; // past ','
    }
    Some(JsonSample {
        key: fields.get("key")?.clone(),
        value: fields.get("value")?.clone(),
        encoding: fields.get("encoding")?.clone(),
        timestamp: fields.get("timestamp")?.clone(),
    })
}

/// Pull the `data:` payload of the first SSE event in `text` whose `data:` line
/// mentions `key_needle`, together with its `event:` name.
///
/// Both `event:NAME` and `event: NAME` are accepted — the single space after
/// the colon is optional in `text/event-stream` and the two implementations
/// differ on it (zenoh's `tide` writes `event:PUT`, wz writes `event: PUT`);
/// an SSE client strips it either way, so it is not a divergence to assert on.
fn events_for(text: &str, key_needle: &str) -> Vec<(String, JsonSample)> {
    let mut out = Vec::new();
    for block in text.split("\n\n") {
        let mut name = None;
        let mut data = None;
        for line in block.lines() {
            if let Some(rest) = line.strip_prefix("event:") {
                name = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("data:") {
                data = Some(rest.trim().to_string());
            }
        }
        let (Some(name), Some(data)) = (name, data) else {
            continue;
        };
        if data.contains(key_needle) {
            if let Some(sample) = parse_json_sample(&data) {
                out.push((name, sample));
            }
        }
    }
    out
}

/// The first event for `key_needle`, or `None`.
fn first_event_for(text: &str, key_needle: &str) -> Option<(String, JsonSample)> {
    events_for(text, key_needle).into_iter().next()
}

/// Spawn a zenohd whose REST plugin listens on `rest_port`, and return it with
/// the ephemeral TCP port wz dials.
///
/// REST is enabled through the generic `--cfg` overrides rather than a new
/// spawn helper: zenohd applies `--cfg KEY:VALUE` pairs LAST
/// (`zenohd/src/main.rs:251-266`), after the `--rest-http-port` handling, and
/// the shared spawner's hard-coded `--rest-http-port none` is a documented
/// no-op (`main.rs:126-136` skips the whole block for the literal `none`). So
/// these two keys are what the flag itself would have set, applied later.
fn spawn_zenohd_with_rest(rest_port: u16) -> (ChildGuard, u16) {
    // Assert the ORACLE before spawning: without the cdylib zenohd exits during
    // plugin load and every downstream failure would read as a wz defect.
    let plugin = rest_plugin();
    assert!(
        plugin.is_file(),
        "the REST plugin cdylib must exist at {}",
        plugin.display()
    );
    let http_port = format!("plugins/rest/http_port:\"{rest_port}\"");
    spawn_zenohd_dialer_on_ephemeral_tcp_with_cfgs(
        &zenohd_binary(),
        "zenohd (REST plugin oracle)",
        None,
        &[],
        None,
        &[&http_port, "plugins/rest/__required__:true"],
    )
}

/// Bring a wz client session up against zenohd on `port`.
async fn connect_to_zenohd(port: u16) -> OpenedSession {
    let locator = parse_any_locator(&format!("tcp/127.0.0.1:{port}")).expect("parse locator");
    for attempt in 1..=20 {
        match connect_and_open_session(
            locator.clone(),
            zenohd_interop_session_init_params(),
            &DialConfig::default(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        {
            Ok(opened) => return opened,
            Err(_) if attempt < 20 => tokio::time::sleep(Duration::from_millis(100)).await,
            Err(e) => panic!("wz never reached Established against zenohd: {e:?}"),
        }
    }
    unreachable!("the loop returns or panics")
}

/// Open an SSE stream against `addr` for `keyexpr` and return the live socket.
async fn open_sse(addr: std::net::SocketAddr, keyexpr: &str) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.expect("connect SSE");
    let get = format!("GET /{keyexpr} HTTP/1.1\r\nHost: x\r\nAccept: text/event-stream\r\n\r\n");
    stream
        .write_all(get.as_bytes())
        .await
        .expect("write SSE GET");
    stream.flush().await.expect("flush SSE GET");
    stream
}

/// Read whatever is available on `stream` into `buf` for a bounded slice.
async fn pump(stream: &mut TcpStream, buf: &mut Vec<u8>) -> bool {
    let mut tmp = [0u8; 8192];
    match tokio::time::timeout(READ_SLICE, stream.read(&mut tmp)).await {
        Ok(Ok(0)) => false, // peer closed
        Ok(Ok(n)) => {
            buf.extend_from_slice(&tmp[..n]);
            true
        }
        Ok(Err(_)) => false,
        Err(_) => true, // idle, keep going
    }
}

/// One-shot HTTP `PUT` of `body` to `addr`, returning `(status, body)`.
///
/// The request is BUILT here, not passed in, so `Connection: close` can never
/// be forgotten — and it is load-bearing, not hygiene. Read-to-EOF is how this
/// helper delimits the response, and the reference plugin's `tide` server does
/// NOT close on its own: a `PUT` answered `200 / content-length: 0` with no
/// `connection:` header is HTTP/1.1-persistent, so the socket stays open and
/// the read blocks forever. Measured both ways against the live plugin: without
/// the header, no EOF inside 3s; with it, EOF immediately. wz's own bridge
/// always answers `Connection: close`, so only the foreign side needs this —
/// which is exactly why a wz-only test could not have caught it.
async fn http_put(
    addr: std::net::SocketAddr,
    keyexpr: &str,
    content_type: &str,
    body: &str,
) -> (u16, Vec<u8>) {
    let request = format!(
        "PUT /{keyexpr} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
         Content-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect(addr).await.expect("connect http");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    stream.flush().await.expect("flush request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read response");
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a header terminator");
    let status = std::str::from_utf8(&raw[..split])
        .expect("ascii head")
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .expect("status code");
    (status, raw[split + 4..].to_vec())
}

/// Everything one leg needs: a live zenohd with its REST plugin, a wz session
/// driven by a background task, and wz's bridge serving on a known address.
struct Fixture {
    _zenohd: ChildGuard,
    zenohd_rest: std::net::SocketAddr,
    wz_rest: std::net::SocketAddr,
    _serve: tokio::task::JoinHandle<()>,
    _drive: tokio::task::JoinHandle<()>,
}

async fn fixture() -> Fixture {
    // Reserve the two HTTP ports together so neither can collide with the other
    // or with a concurrent test binary's pick.
    let rest_res = PortReservation::pick();
    let zenohd_rest_port = rest_res.port();
    let (zenohd, tcp_port) = spawn_zenohd_with_rest(zenohd_rest_port);
    drop(rest_res);

    let mut opened = connect_to_zenohd(tcp_port).await;
    // The bridge's zid is used ONLY to resolve the `@/local` admin alias to
    // `@/<zid-hex>`; no leg here exercises that path. Read it off the SAME
    // builder the session opened with, rather than restating the literal, so
    // the two can never drift apart.
    let zid = zenohd_interop_session_init_params().zid.clone();
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(opened.actions.clone(), observer, Arc::new(opened.clock));

    // Bind wz's bridge on an ephemeral port and read the concrete address back.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz REST listener");
    let wz_rest = listener.local_addr().expect("wz REST local addr");
    let serve_session = session.clone();
    let serve = tokio::spawn(async move {
        // Through the umbrella re-export, so this call site sits BEHIND the
        // `rest-http-bridge` cfg gate the atom is defined by.
        let _ = wz::rest::serve_on(listener, serve_session, zid).await;
    });

    let timeouts = SessionTimeouts::spec_defaults();
    let drive_session = session.clone();
    let drive = tokio::spawn(async move {
        drive_session_until_terminal(
            &mut opened.inbound,
            &opened.actions,
            &mut opened.engine,
            None,
            &opened.clock,
            &timeouts,
            move |event| drive_session.dispatch_iteration_event(event),
        )
        .await;
    });

    Fixture {
        _zenohd: zenohd,
        zenohd_rest: format!("127.0.0.1:{zenohd_rest_port}").parse().unwrap(),
        wz_rest,
        _serve: serve,
        _drive: drive,
    }
}

/// LEG 1 (`wz->zenohd`) — an HTTP `PUT` into WZ's bridge is routed by zenohd and
/// surfaces on the REFERENCE REST plugin's SSE stream.
///
/// The observer is a foreign HTTP surface, so nothing about the assertion is
/// wz-side: zenohd's own plugin had to receive, decode and render the sample
/// that wz's bridge published.
// wz-proves: rest-http-bridge wz->zenohd
// wz-proves: pubsub-encoding wz->zenohd
// wz-proves: codec-push wz->zenohd
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binary-dep e2e: needs target/zenohd/{zenohd,libzenoh_plugin_rest.so}"]
async fn wz_rest_put_reaches_the_zenohd_rest_plugin() {
    let fx = fixture().await;

    // Subscribe on the FOREIGN bridge first, so the PUT below cannot precede
    // the subscription (the declare still has to propagate; the retry absorbs
    // that, and the assertion still needs the real delivery).
    let mut foreign = open_sse(fx.zenohd_rest, WZ_TO_ZENOHD_KEY).await;

    let mut buf = Vec::new();
    let mut seen = None;
    'outer: for _ in 0..PUBLISH_ROUNDS {
        let (status, _) = http_put(
            fx.wz_rest,
            WZ_TO_ZENOHD_KEY,
            "text/plain",
            WZ_TO_ZENOHD_VALUE,
        )
        .await;
        assert_eq!(status, 200, "wz's bridge accepted the PUT");
        for _ in 0..READ_SLICES {
            if !pump(&mut foreign, &mut buf).await {
                break 'outer;
            }
            let text = String::from_utf8_lossy(&buf);
            if let Some(found) = first_event_for(&text, WZ_TO_ZENOHD_KEY) {
                seen = Some(found);
                break 'outer;
            }
        }
    }

    let (event, sample) = seen.unwrap_or_else(|| {
        panic!(
            "zenoh's REST plugin never streamed wz's PUT on {WZ_TO_ZENOHD_KEY}; got:\n{}",
            String::from_utf8_lossy(&buf)
        )
    });

    assert_eq!(event, "PUT", "the reference plugin classified it as a PUT");
    assert_eq!(sample.key, format!("\"{WZ_TO_ZENOHD_KEY}\""));
    assert_eq!(
        sample.value,
        format!("\"{WZ_TO_ZENOHD_VALUE}\""),
        "the reference rendered wz's text/plain payload as a bare string"
    );
    assert_eq!(
        sample.encoding, "\"text/plain\"",
        "wz's Content-Type -> zenoh encoding mapping survived the wire"
    );
}

/// LEG 2 (`zenohd->wz`) — THE DIFFERENTIAL. A foreign `PUT` against zenohd's
/// plugin reaches both bridges, and wz's `JSONSample` must equal the reference
/// plugin's for the same sample, in every rendering class.
///
/// The three classes are the branches of zenoh's `payload_to_json`: a
/// `text/plain` payload renders as a bare string, `application/json` embeds the
/// parsed document, and any other encoding base64s it. A single class would not
/// discriminate — wz's pre-R311y501 UTF-8-driven rule agreed with the reference
/// on `text/plain` and disagreed on the other two.
// wz-proves: rest-sse-subscribe zenohd->wz
// wz-proves: rest-http-bridge zenohd->wz
// wz-proves: declare-subscriber wz->zenohd
// wz-proves: pubsub-timestamp zenohd->wz
// wz-proves: pubsub-encoding zenohd->wz
// wz-proves: pubsub-sample zenohd->wz
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binary-dep e2e: needs target/zenohd/{zenohd,libzenoh_plugin_rest.so}"]
async fn wz_rest_sse_renders_the_same_sample_as_the_zenohd_rest_plugin() {
    // (key suffix, Content-Type, body) — one per rendering class.
    const CLASSES: &[(&str, &str, &str)] = &[
        ("text", "text/plain", "plain-text-payload"),
        ("json", "application/json", "{\"a\":1,\"b\":[2,3]}"),
        ("octet", "application/octet-stream", "octet-payload"),
    ];

    let fx = fixture().await;
    let root = "demo/rest/interop/differential";

    // BOTH bridges subscribe to the whole family before anything is published.
    let mut wz_sse = open_sse(fx.wz_rest, &format!("{root}/**")).await;
    let mut foreign_sse = open_sse(fx.zenohd_rest, &format!("{root}/**")).await;

    let mut wz_buf = Vec::new();
    let mut foreign_buf = Vec::new();

    // ── BARRIER: both subscriptions live, before any class is published.
    //
    // Re-publishing a class key until both streams show it is NOT sound, and a
    // green run does not make it so: each PUT mints a NEW sample with a new
    // timestamp, so if one subscriber's `Declare` propagates a round later, the
    // "first event for this key" on the two sides are DIFFERENT samples and the
    // comparison is between two unrelated renderings. That is exactly what a
    // re-run produced — identical key/value/encoding, timestamps one publish
    // apart. So the retry moves to a WARMUP key whose only job is to establish
    // both subscriptions; each class is then published EXACTLY ONCE, and the
    // single resulting sample is what both sides must render.
    let warmup_key = format!("{root}/warmup");
    let mut ready = false;
    'warmup: for _ in 0..PUBLISH_ROUNDS {
        let (status, _) = http_put(fx.zenohd_rest, &warmup_key, "text/plain", "warmup").await;
        assert_eq!(status, 200, "zenoh's REST plugin accepted the warmup PUT");
        for _ in 0..READ_SLICES {
            if !pump(&mut wz_sse, &mut wz_buf).await
                || !pump(&mut foreign_sse, &mut foreign_buf).await
            {
                break 'warmup;
            }
            if first_event_for(&String::from_utf8_lossy(&wz_buf), &warmup_key).is_some()
                && first_event_for(&String::from_utf8_lossy(&foreign_buf), &warmup_key).is_some()
            {
                ready = true;
                break 'warmup;
            }
        }
    }
    assert!(
        ready,
        "both SSE subscriptions became live (warmup).\n--- wz ---\n{}\n--- zenohd ---\n{}",
        String::from_utf8_lossy(&wz_buf),
        String::from_utf8_lossy(&foreign_buf)
    );

    for (suffix, content_type, body) in CLASSES {
        let key = format!("{root}/{suffix}");

        // Exactly ONE publish per class — see the barrier above.
        let (status, _) = http_put(fx.zenohd_rest, &key, content_type, body).await;
        assert_eq!(status, 200, "zenoh's REST plugin accepted the PUT");

        let mut pair = None;
        'drain: for _ in 0..PUBLISH_ROUNDS {
            for _ in 0..READ_SLICES {
                if !pump(&mut wz_sse, &mut wz_buf).await
                    || !pump(&mut foreign_sse, &mut foreign_buf).await
                {
                    break 'drain;
                }
                let wz_events = events_for(&String::from_utf8_lossy(&wz_buf), &key);
                let foreign_events = events_for(&String::from_utf8_lossy(&foreign_buf), &key);
                if !wz_events.is_empty() && !foreign_events.is_empty() {
                    // One publish must yield one event per side. A second would
                    // mean the sample identity is not pinned and the field-for-
                    // field comparison below is not about ONE sample.
                    assert_eq!(
                        (wz_events.len(), foreign_events.len()),
                        (1, 1),
                        "{key}: one publish, one event per bridge"
                    );
                    pair = Some((
                        wz_events.into_iter().next().unwrap(),
                        foreign_events.into_iter().next().unwrap(),
                    ));
                    break 'drain;
                }
            }
        }

        let ((wz_event, wz_sample), (foreign_event, foreign_sample)) = pair.unwrap_or_else(|| {
            panic!(
                "both bridges did not deliver {key}.\n--- wz ---\n{}\n--- zenohd ---\n{}",
                String::from_utf8_lossy(&wz_buf),
                String::from_utf8_lossy(&foreign_buf)
            )
        });

        assert_eq!(
            wz_event, foreign_event,
            "{key}: the two bridges agree on the SSE event name"
        );
        // The whole object, field for field. `timestamp` is included on
        // purpose: it pins wz's <ntp64>/<zid-hex> rendering to the reference's
        // uhlc Display for the SAME sample, which no wz-side test can do.
        assert_eq!(
            wz_sample, foreign_sample,
            "{key}: wz's JSONSample must equal the reference plugin's"
        );
        // Guard against the degenerate pass where both rendered nothing.
        assert_ne!(
            wz_sample.timestamp, "null",
            "{key}: the sample carried a real timestamp (else the comparison is vacuous)"
        );
        assert_eq!(
            wz_sample.encoding,
            format!("\"{content_type}\""),
            "{key}: the encoding round-tripped"
        );
    }
}
