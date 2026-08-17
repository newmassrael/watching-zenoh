// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y837 (debt 161) — the consolidation wire byte, measured against BOTH
//! reference implementations by execution rather than by reading either one.
//!
//! # The claim under test
//!
//! `Round 1872`'s carry named a divergence it found while reading upstream and
//! deliberately did not act on: zenoh numbers the Query/Reply consolidation
//! field `Auto=0 / None=1 / Monotonic=2 / Latest=3`, while zenoh-pico writes
//! its API enum raw, `NONE=0 / MONOTONIC=1 / LATEST=2`. wz follows pico, so a
//! wz `Latest` would read as `Monotonic` to a zenohd. The carry required a
//! foreign witness on BOTH planes before the byte moved, "because the two
//! upstreams disagree and wz claims to replace both".
//!
//! This file is that witness, and it is a witness rather than a citation: each
//! leg puts a REAL foreign encoder on one end of a real session, relays the
//! bytes through the shared `wire_tap`, and reads the consolidation byte out of
//! the Query with wz's own decoder. Nothing here reads an upstream source file.
//!
//! # Why both legs ask for the SAME logical mode
//!
//! A byte difference is only a divergence if the two encoders were asked for
//! the same thing. Both legs ask for LATEST, and neither leg names it:
//!
//! * zenohd's REST plugin resolves a plain HTTP GET to `ConsolidationMode::
//!   Latest` before calling `Session::get`, so the byte it writes is what stock
//!   zenoh puts on the wire for the ordinary case.
//! * zenoh-pico's `z_get` leaves the mode at `Z_CONSOLIDATION_MODE_AUTO`, and
//!   pico resolves AUTO to LATEST client-side before encoding.
//!
//! So the two bytes are the same mode written by two implementations, which is
//! the only shape in which "they disagree" means anything.
//!
//! # What each leg does NOT prove
//!
//! Neither leg proves the byte is CONSUMED. It is requester-side and stock
//! zenoh never reads it back — that is precisely why the divergence survived
//! this long, and it is stated here so a reader does not take a green run as
//! evidence of a behavioural difference. What the legs establish is what each
//! reference implementation WRITES, which is what a replacement has to match.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capture::Dissection;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, rest_plugin,
    spawn_zenohd_dialer_on_ephemeral_tcp_with_cfgs, wait_for_substring, wz_ap_demo_binary,
    wz_e2e_queryable_binary, zenoh_pico_cli_binary, zenohd_binary, ChildGuard, PortReservation,
};
use wz_integration_tests::wire_tap::{synthesise_pcap, tap_proxy, Recording, Side};
use wz_session_core::network_message::{parse_frame_payload, NetworkMessage};
use wz_session_core::passive::Direction;

use wz_codecs::request::RequestOwnedVariant;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{QueryOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{connect_and_open_session, DialConfig, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::zenohd_interop_session_init_params;
use wz_session_core::inbound::InboundFrame;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

/// Iteration cap for the open handshake, matching `wz_rest_zenohd_interop.rs`.
const ITER_CAP: usize = 256;

/// The synthesised endpoint ports. They are NOT the real ones (the real dialer
/// port is ephemeral and the proxy sits between); they are named because they
/// decide which half `Direction::A` is — `FlowKey` orders its endpoints by
/// `(addr, port)` and both addresses are 127.0.0.1, so the LISTENER is `low`
/// and therefore `Direction::A`. Both legs assert that mapping rather than
/// assume it (R311y761's correction).
const DIALER_PORT: u16 = 40_000;
const LISTENER_PORT: u16 = 7447;

/// Every consolidation byte carried by a `Request(Query)` on one half of the
/// relayed flow, in wire order.
///
/// `Option<u8>` is the decoder's own spelling of the header's Q_C flag: `None`
/// means the flag was clear and the field absent, which is a DIFFERENT fact
/// from any value and must not be collapsed into one — an elided field reads as
/// `Auto` on both upstreams.
fn query_consolidation_bytes(
    flow: &wz_capture::FlowDissection,
    side: Direction,
) -> Vec<Option<u8>> {
    let mut out = Vec::new();
    for frame in flow.frames.iter() {
        if frame.direction != side {
            continue;
        }
        let Ok(InboundFrame::Frame { payload, .. }) = &frame.frame else {
            continue;
        };
        let Ok(records) = parse_frame_payload(payload) else {
            continue;
        };
        for record in records {
            if let NetworkMessage::Request(request) = record {
                if let RequestOwnedVariant::CodecZenohQuery(query) = &request.body {
                    out.push(query.consolidation);
                }
            }
        }
    }
    out
}

/// Wait until BOTH directions have carried bytes — the earliest point a
/// handshake can have completed. Polls the recording rather than a log line so
/// the marker is the same artefact the assertions read.
fn wait_for_both_directions(recording: &Recording, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        {
            let segments = recording.lock().expect("recording lock");
            let dialer = segments.iter().any(|(s, _)| *s == Side::FromDialer);
            let listener = segments.iter().any(|(s, _)| *s == Side::FromListener);
            if dialer && listener {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Dissect the recording and hand back the single flow's consolidation bytes on
/// the half named by `subject_is_listener` — the half whose ENCODER this leg is
/// measuring, which is the foreign one in two legs and wz's own in the third.
///
/// The Direction mapping is COMPUTED from the flow key and asserted, never
/// written down: `low` is the lesser endpoint by `(addr, port)`, which with one
/// address is decided entirely by the two synthesised port constants.
fn foreign_consolidation_bytes(
    recording: &Recording,
    subject_is_listener: bool,
) -> Vec<Option<u8>> {
    let segments = recording.lock().expect("recording lock").clone();
    let from_dialer: usize = segments
        .iter()
        .filter(|(s, _)| *s == Side::FromDialer)
        .map(|(_, b)| b.len())
        .sum();
    let from_listener: usize = segments
        .iter()
        .filter(|(s, _)| *s == Side::FromListener)
        .map(|(_, b)| b.len())
        .sum();
    assert!(
        from_dialer > 0 && from_listener > 0,
        "a one-way recording is not a session: {from_dialer} byte(s) from the \
         dialer, {from_listener} from the listener"
    );

    let pcap = synthesise_pcap(&segments, DIALER_PORT, LISTENER_PORT);
    let dissection = Dissection::from_pcap(&pcap).expect("the synthesised pcap parses");
    let flows = dissection.flows();
    assert_eq!(
        flows.len(),
        1,
        "one relayed connection is one flow; got {}",
        flows.len()
    );
    let flow = &flows[0];
    assert_eq!(
        (flow.flow.low.port, flow.flow.high.port),
        (u32::from(LISTENER_PORT), u32::from(DIALER_PORT)),
        "the synthesised ports decide which half is Direction::A, so this is \
         pinned: the listener is the LOW endpoint and therefore Direction::A"
    );
    let side = if subject_is_listener {
        Direction::A
    } else {
        Direction::B
    };
    query_consolidation_bytes(flow, side)
}

/// Poll the recording until a `Request(Query)` has been dissected on the named
/// half, then return every consolidation byte seen there.
///
/// A poll rather than a fixed wait because the artefact polled IS the artefact
/// asserted: a run that reaches the assertion cannot have raced a Query the tap
/// had not yet relayed, which a `sleep` long enough to "usually" work cannot say.
fn wait_for_query_consolidation(
    recording: &Recording,
    subject_is_listener: bool,
    budget: Duration,
) -> Vec<Option<u8>> {
    let deadline = Instant::now() + budget;
    loop {
        let both = {
            let segments = recording.lock().expect("recording lock");
            segments.iter().any(|(s, _)| *s == Side::FromDialer)
                && segments.iter().any(|(s, _)| *s == Side::FromListener)
        };
        if both {
            let bytes = foreign_consolidation_bytes(recording, subject_is_listener);
            if !bytes.is_empty() {
                return bytes;
            }
        }
        if Instant::now() >= deadline {
            return Vec::new();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// One HTTP/1.1 GET against zenohd's REST plugin, returning the whole response.
///
/// Hand-rolled over `std::net::TcpStream` rather than reached for through a
/// client crate: the request is three lines and the leg is synchronous, so a
/// dependency would buy nothing this file needs.
fn http_get(port: u16, path: &str, budget: Duration) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(budget))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: application/json\r\n\
         Connection: close\r\n\r\n"
    )?;
    stream.flush()?;
    let mut body = Vec::new();
    // A short read is normal here (`Connection: close` ends the body), and a
    // timeout is reported as whatever arrived rather than as an error: the
    // caller's assertion is about the CONTENT, and swallowing a partial
    // response would turn a content failure into a transport one.
    let _ = stream.read_to_end(&mut body);
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// zenohd with the REST plugin loaded, listening on an ephemeral TCP port.
///
/// REST is enabled through `--cfg` overrides for the reason
/// `wz_rest_zenohd_interop.rs` documents: zenohd applies them last, after the
/// shared spawner's hard-coded `--rest-http-port none`, which is a documented
/// no-op for the literal `none`.
fn spawn_zenohd_with_rest(rest_port: u16) -> (ChildGuard, u16) {
    let plugin = rest_plugin();
    assert!(
        plugin.is_file(),
        "the REST plugin cdylib must exist at {}",
        plugin.display()
    );
    let http_port = format!("plugins/rest/http_port:\"{rest_port}\"");
    spawn_zenohd_dialer_on_ephemeral_tcp_with_cfgs(
        &zenohd_binary(),
        "zenohd (REST plugin, consolidation witness)",
        None,
        &[],
        None,
        &[&http_port, "plugins/rest/__required__:true"],
    )
}

/// THE ZENOH-PLANE WITNESS: what stock zenoh writes for an unnamed get.
// wz-proves: codec-request zenohd->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenohd + REST plugin); Layer Z runs via --ignored"]
fn a_real_zenohd_writes_latest_as_the_consolidation_byte_zenoh_numbers_it() {
    let demo = wz_ap_demo_binary();
    // A stale demo would answer this leg's REST GET from code that predates the
    // round, which is the one way a byte assertion can pass while measuring
    // yesterday's build.
    assert_demo_binary_newer_than_sources(&demo);
    let queryable_key = "demo/consolidation";
    let reply_value = "reply-from-wz-queryable";

    let rest_res = PortReservation::pick();
    let rest_port = rest_res.port();
    drop(rest_res);
    let (mut zenohd, zenohd_port) = spawn_zenohd_with_rest(rest_port);

    // The tap sits between wz and zenohd: wz dials the proxy, the proxy dials
    // zenohd. zenohd is therefore the LISTENER half.
    let (tap_port, recording) = tap_proxy(zenohd_port);

    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect tap --queryable --reply)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{tap_port}"))
            .arg("--queryable")
            .arg(queryable_key)
            .arg("--reply")
            .arg(reply_value)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo"),
    );

    let declared = wait_for_substring(
        &mut demo_stderr_reader,
        "DECLARED ROUTED QUERYABLE",
        Duration::from_secs(15),
    );
    let both = wait_for_both_directions(&recording, Duration::from_secs(10));

    // The REST GET is retried: zenohd routes the Query only once wz's
    // DeclQueryable has propagated, and a one-shot GET that lands early
    // returns an empty result set and exits. The RETRY is for the
    // propagation window, not for wz — the reply side is deterministic once
    // the query arrives.
    //
    // The witness needle is the ANSWERED KEY, not the reply payload: the REST
    // plugin renders a sample's value base64-encoded, so a literal search for
    // `reply_value` reads a perfectly good answer as no answer (measured — the
    // first run of this leg failed on exactly that while the body carried
    // `cmVwbHktZnJvbS13ei1xdWVyeWFibGU=`). The key only appears when some
    // queryable replied, which is the fact this retry loop is waiting for.
    let answered_needle = format!("\"key\":\"{queryable_key}\"");
    let mut rest_body = String::new();
    let mut answered = false;
    if declared.is_ok() {
        for _ in 0..12 {
            match http_get(
                rest_port,
                &format!("/{queryable_key}"),
                Duration::from_secs(5),
            ) {
                Ok(body) => {
                    rest_body = body;
                    if rest_body.contains(&answered_needle) {
                        answered = true;
                        break;
                    }
                }
                Err(e) => rest_body = format!("<http error: {e}>"),
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    let bytes = foreign_consolidation_bytes(&recording, true);
    eprintln!("zenohd -> wz Query consolidation byte(s): {bytes:?}");

    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    let demo_captured = read_captured(&mut demo_stderr_reader);

    assert!(
        declared.is_ok(),
        "wz-ap-demo never logged 'DECLARED ROUTED QUERYABLE'; zenohd has no \
         route to send a Query down.\n--- wz-ap-demo stderr ---\n{demo_captured}"
    );
    assert!(both, "the tap never saw both directions");
    assert!(
        answered,
        "the REST GET never returned the wz queryable's reply, so no Query was \
         routed to wz.\n--- last REST body ---\n{rest_body}\n\
         --- wz-ap-demo stderr ---\n{demo_captured}"
    );

    assert_eq!(
        bytes,
        vec![Some(3u8)],
        "stock zenoh resolves an unnamed get to Latest and writes it as 3 \
         (Auto=0/None=1/Monotonic=2/Latest=3). Observed: {bytes:?}"
    );
}

/// THE PICO-PLANE WITNESS: what stock zenoh-pico writes for the same mode.
// wz-proves: codec-request pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-e2e-queryable + zenoh-pico CLI); Layer Z runs via --ignored"]
fn wz_e2e_queryable_sees_a_real_zenoh_pico_write_latest_as_the_consolidation_byte() {
    let bin = wz_e2e_queryable_binary();
    let z_get = zenoh_pico_cli_binary("z_get");
    let port_res = PortReservation::pick();
    let wz_port = port_res.port();
    let listen_addr = format!("127.0.0.1:{wz_port}");
    let queryable_pattern = "demo/**";
    let query_keyexpr = "demo/consolidation";
    let reply_value = "reply-from-wz-queryable";

    let bin_stderr = tempfile::tempfile().expect("tempfile for binary stderr");
    let bin_stderr_writer = bin_stderr.try_clone().expect("dup binary stderr handle");
    let mut bin_stderr_reader = bin_stderr;
    let mut bin_child = ChildGuard::wrap(
        "wz-e2e-queryable (--listen --queryable --reply)",
        Command::new(&bin)
            .arg("--listen")
            .arg(&listen_addr)
            .arg("--queryable")
            .arg(queryable_pattern)
            .arg("--reply")
            .arg(reply_value)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(bin_stderr_writer))
            .spawn()
            .expect("spawn wz-e2e-queryable"),
    );
    let bound = wait_for_substring(
        &mut bin_stderr_reader,
        "listening on",
        Duration::from_secs(5),
    );
    drop(port_res);

    // The tap sits in front of wz: z_get dials the proxy, the proxy dials wz.
    // pico is therefore the DIALER half.
    let (tap_port, recording) = tap_proxy(wz_port);
    let endpoint = format!("tcp/127.0.0.1:{tap_port}");

    let z_get_stdout = tempfile::tempfile().expect("tempfile for z_get stdout");
    let z_get_stdout_writer = z_get_stdout.try_clone().expect("dup z_get stdout handle");
    let mut z_get_stdout_reader = z_get_stdout;
    let mut z_get_child = ChildGuard::wrap(
        "z_get client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_get)
            .args(["-k", query_keyexpr, "-e", &endpoint, "-m", "client"])
            .stdout(Stdio::from(z_get_stdout_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_get via stdbuf"),
    );

    let received = wait_for_substring(
        &mut z_get_stdout_reader,
        ">> Received",
        Duration::from_secs(10),
    );
    let both = wait_for_both_directions(&recording, Duration::from_secs(10));
    let bytes = foreign_consolidation_bytes(&recording, false);

    let _ = z_get_child.child_mut().kill();
    let _ = z_get_child.child_mut().wait();
    let _ = bin_child.child_mut().kill();
    let _ = bin_child.child_mut().wait();
    let bin_captured = read_captured(&mut bin_stderr_reader);
    let z_get_captured = read_captured(&mut z_get_stdout_reader);

    assert!(
        bound.is_ok(),
        "wz-e2e-queryable did not log 'listening on'\n{bin_captured}"
    );
    assert!(both, "the tap never saw both directions");
    assert!(
        received.is_ok(),
        "z_get never printed '>> Received', so its Query never got answered.\n\
         --- z_get stdout ---\n{z_get_captured}\n\
         --- wz-e2e-queryable stderr ---\n{bin_captured}"
    );

    eprintln!("pico -> wz Query consolidation byte(s): {bytes:?}");
    assert_eq!(
        bytes,
        vec![Some(2u8)],
        "zenoh-pico resolves AUTO to LATEST client-side and writes its API enum \
         raw, so LATEST is 2 (NONE=0/MONOTONIC=1/LATEST=2). Observed: {bytes:?}"
    );
}

/// THE PARITY ASSERTION: wz's own default get, on the same wire, against the
/// same router — measured against the byte the sibling leg watched a real
/// zenohd write, not against a number read out of an upstream source file.
///
/// This is the leg that closes debt 161 + 162 together, and it is one leg
/// rather than two because the two halves are only meaningful jointly: a byte
/// nobody transmits is not parity, and a transmitted byte a zenohd misreads is
/// worse than silence. Before this round it read `[None]` — wz elided the field
/// entirely where stock zenoh writes `3`.
///
/// # Why the session is IN-PROCESS and not one of the demo binaries
///
/// The subject has to be the path an APPLICATION takes — `Session::query` with a
/// default `QueryOptions`, which is wz's spelling of the REST plugin's own
/// unnamed get, so both legs ask their two stacks the same question. Neither
/// demo binary is that path, and both were tried:
///
/// * `wz-ap-demo --query` hand-builds a `QueryMetadata` and calls
///   `send_request_query_with_meta` directly (`wz-ap-demo/src/tasks.rs:182-189`),
///   bypassing `QueryOptions` and every resolution rule on it. Measured: it read
///   `[None]` with the fix in place, which is a fact about the fixture.
/// * `wz-e2e-zget` DOES call `Session::query`, but its pinned `zget-reply-only`
///   subset omits `query-consolidation` entirely, so it elides the field by
///   design. A green run there would have measured the feature being absent.
///
/// So the leg opens the session here, where the crate's own feature set has the
/// capability, using the same `connect_and_open_session` + `TokioSession` +
/// `drive_session_until_terminal` shape `wz_rest_zenohd_interop.rs` uses.
// wz-proves: query-consolidation wz->zenohd
// wz-proves: query-get wz->zenohd
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd); Layer Z runs via --ignored"]
async fn wz_writes_the_consolidation_byte_a_real_zenohd_writes_for_the_same_get() {
    let query_key = "demo/consolidation";

    let (mut zenohd, zenohd_port) = spawn_zenohd_dialer_on_ephemeral_tcp_with_cfgs(
        &zenohd_binary(),
        "zenohd (consolidation parity witness)",
        None,
        &[],
        None,
        &[],
    );
    // wz dials the proxy, the proxy dials zenohd: wz is the DIALER half.
    let (tap_port, recording) = tap_proxy(zenohd_port);

    let locator = parse_any_locator(&format!("tcp/127.0.0.1:{tap_port}")).expect("parse locator");
    let mut opened = {
        let mut last = None;
        let mut got = None;
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
                Ok(o) => {
                    got = Some(o);
                    break;
                }
                Err(e) => {
                    last = Some(e);
                    if attempt < 20 {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
        match got {
            Some(o) => o,
            None => panic!("wz never reached Established against zenohd: {last:?}"),
        }
    };

    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(opened.actions.clone(), observer, Arc::new(opened.clock));
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

    // THE SUBJECT: one default get. No mode named, no selector parameters —
    // the ordinary call, which is the whole reason the divergence matters.
    let handle = session.query(query_key, QueryOptions::default(), |_reply| {}, |_rid| {});
    let issued = handle.is_ok();

    let bytes = tokio::task::spawn_blocking({
        let recording = recording.clone();
        move || wait_for_query_consolidation(&recording, false, Duration::from_secs(15))
    })
    .await
    .expect("join the recording poll");

    drive.abort();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    eprintln!("wz -> zenohd Query consolidation byte(s): {bytes:?}");
    assert!(
        issued,
        "Session::query was refused, so nothing was put on the wire to measure"
    );
    assert!(
        !bytes.is_empty(),
        "no Request(Query) was dissected on wz's half within the budget, so \
         this leg measured nothing at all"
    );
    assert_eq!(
        bytes,
        vec![Some(3u8)],
        "wz names no mode on this get, exactly as the REST plugin's get names \
         none, so wz must put the byte a real zenohd was MEASURED writing for \
         it in the zenohd leg of this file — Some(3). Observed: {bytes:?}"
    );
}
