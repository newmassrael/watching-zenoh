// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2594 — the QoS a queryable's reply carries, adjudicated by a stock zenoh
//! queryable answering the SAME query through the SAME router.
//!
//! ## The claim under test
//!
//! Upstream's reply builders do not start from a constant. `Query::reply`,
//! `reply_del` and `reply_err` all seed the reply's QoS from the QUERY's own
//! (`zenoh/src/api/builders/reply.rs` @ `qos: query.inner.qos.into(),`), and a
//! remote query's QoS is the `ext_qos` its `Request` arrived with. A stock
//! `get` sends `QoSType::REQUEST`, which is `Block` rather than the codec's
//! `Drop` DEFAULT, so the extension is written on the Request AND on every
//! Response answering it. zenoh-pico agrees on the reply by a different route:
//! its reply options default to `Z_CONGESTION_CONTROL_BLOCK`
//! (`vendor/zenoh-pico/src/api/api.c` @ `void z_query_reply_options_default(`).
//!
//! wz's reply path emitted no Response extension but the responder identity,
//! under a comment that called the omission "pico-calibrated". A receiver
//! decodes an absent `ext_qos` as DEFAULT, so wz's replies read as
//! droppable where both references say they must not be dropped.
//!
//! ## Why a differential and not a constant
//!
//! The expected value is not written in this file. Each run puts a stock
//! `zenoh_z_queryable` behind the tap first and records what it emits; the wz
//! leg is then held to THAT. A test pinning `13` would pass against a wz that
//! stamped 13 on every reply regardless of the query, which is not what
//! upstream does — so the inheritance rule itself is witnessed in
//! `wz-session-core`'s own tests, and this file owns only the half a foreign
//! binary can decide: that a default query gets the reply QoS a stock
//! queryable gives it.
//!
//! ## What this does NOT witness yet
//!
//! The `ResponseFinal` carries the query's QoS too in upstream (its
//! `QueryInner` drop stamps `ext_qos: self.qos.into()`), and the first run of
//! this file measured it there: the stock queryable's final reads the same
//! byte as its reply. It is collected and printed below and NOT asserted,
//! because wz's final is keyed by a bare request id at every site that owes
//! one, so the carrier cannot express it yet. That is the next round's
//! subject, and this file is where its assertion lands.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_capture::Dissection;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, run_query_until_answered,
    spawn_zenohd_dialer_on_ephemeral_tcp, wait_for_substring, wz_ap_demo_binary,
    zenoh_core_example_binary, zenohd_binary, ChildGuard, QueryAttempts,
};
use wz_integration_tests::wire_tap::{synthesise_pcap, tap_proxy, Recording, Side};
use wz_session_core::declare_ext_qos::QOS_EXT_ID;
use wz_session_core::ext_nodeid::read_z64_ext;
use wz_session_core::inbound::InboundFrame;
use wz_session_core::network_message::{parse_frame_payload, NetworkMessage};
use wz_session_core::passive::Direction;
use wz_session_core::sample::QosLevel;

/// The synthesised endpoint ports. They decide which half is `Direction::A`
/// (`FlowKey` orders endpoints by `(addr, port)` on one address), so the
/// mapping is asserted below rather than assumed.
const DIALER_PORT: u16 = 40_000;
const LISTENER_PORT: u16 = 7447;

/// The one key both queryables declare and the querier names. Exact rather
/// than a wildcard so the two answerers are declared identically.
const QABL_KEY: &str = "demo/reply-qos/answer";

/// The querier's per-reply marker: the whole chain completed, so the tap holds
/// a Response and not only a handshake.
const GET_RECEIVED: &str = ">> Received (";
const GET_TIMEOUT_MS: &str = "3000";
const GET_WALL_CLOCK: Duration = Duration::from_secs(15);

/// The declaration-propagation window, on `zenoh_ext_body_foreign_witness.rs`'s
/// budget: an attempt that missed the route costs milliseconds.
const GET_ATTEMPTS: usize = 6;

/// Who answers the query from behind the tap.
#[derive(Clone, Copy, Debug)]
enum Answerer {
    StockZenoh,
    Wz,
}

/// What one leg's answerer put on the wire, in wire order.
struct Answers {
    responses: Vec<QosLevel>,
    finals: Vec<QosLevel>,
}

/// A message's `ext_qos` as a receiver acts on it: an absent extension keeps
/// the decoder's DEFAULT:
/// `commons/zenoh-codec/src/network/response.rs` @ `let mut ext_qos = ext::QoSType::DEFAULT;`
/// Comparing this rather than
/// presence is what makes the assertion about behaviour — under the shared
/// omit-on-DEFAULT encode rule the two are the same fact.
fn effective_qos(exts: Option<&Vec<wz_codecs::ext_entry::ExtEntryOwned>>) -> QosLevel {
    read_z64_ext(exts, QOS_EXT_ID)
        .map(|v| QosLevel::from_raw(v as u8))
        .unwrap_or(QosLevel::DEFAULT)
}

fn spawn_answerer(answerer: Answerer, tap_port: u16) -> (ChildGuard, File) {
    let out = tempfile::tempfile().expect("tempfile for answerer output");
    let writer = out.try_clone().expect("dup answerer output handle");
    let mut reader = out;
    let (child, marker) = match answerer {
        Answerer::StockZenoh => {
            let mut cmd = Command::new("stdbuf");
            cmd.args(["-oL", "-eL"])
                .arg(zenoh_core_example_binary("z_queryable"))
                .args([
                    "-k",
                    QABL_KEY,
                    "-p",
                    "answer-from-a-stock-zenoh-queryable",
                    "-m",
                    "client",
                    "-e",
                    &format!("tcp/127.0.0.1:{tap_port}"),
                    "--no-multicast-scouting",
                ]);
            let child = ChildGuard::wrap(
                "z_queryable (stock zenoh, through the tap)",
                cmd.stderr(Stdio::from(writer.try_clone().expect("dup stderr")))
                    .stdout(Stdio::from(writer))
                    .spawn()
                    .expect("spawn z_queryable via stdbuf"),
            );
            (child, "Declaring Queryable on")
        }
        Answerer::Wz => {
            let demo = wz_ap_demo_binary();
            // A stale demo answers from code that predates the round, which is
            // the one way this leg could pass while measuring yesterday's build.
            assert_demo_binary_newer_than_sources(&demo);
            let child = ChildGuard::wrap(
                "wz-ap-demo (--connect tap --queryable --reply)",
                Command::new(&demo)
                    .arg("--connect")
                    .arg(format!("127.0.0.1:{tap_port}"))
                    .arg("--queryable")
                    .arg(QABL_KEY)
                    .arg("--reply")
                    .arg("answer-from-a-wz-queryable")
                    .env("RUST_LOG", "info")
                    .stdout(Stdio::null())
                    .stderr(Stdio::from(writer))
                    .spawn()
                    .expect("spawn wz-ap-demo"),
            );
            (child, "DECLARED ROUTED QUERYABLE")
        }
    };
    if let Err(captured) = wait_for_substring(&mut reader, marker, Duration::from_secs(15)) {
        panic!("{answerer:?} never declared ('{marker}' absent):\n{captured}");
    }
    (child, reader)
}

fn spawn_zget(zenohd_port: u16) -> (ChildGuard, File) {
    let out = tempfile::tempfile().expect("tempfile for z_get output");
    let writer = out.try_clone().expect("dup z_get output handle");
    let mut cmd = Command::new("stdbuf");
    cmd.args(["-oL", "-eL"])
        .arg(zenoh_core_example_binary("z_get"))
        .args([
            "-s",
            QABL_KEY,
            "-o",
            GET_TIMEOUT_MS,
            "-m",
            "client",
            "-e",
            &format!("tcp/127.0.0.1:{zenohd_port}"),
            "--no-multicast-scouting",
        ]);
    let child = ChildGuard::wrap(
        "z_get (stock zenoh, straight at zenohd)",
        cmd.stderr(Stdio::from(writer.try_clone().expect("dup stderr")))
            .stdout(Stdio::from(writer))
            .spawn()
            .expect("spawn z_get via stdbuf"),
    );
    (child, out)
}

/// Dissect the recording and collect the answerer half's Response and
/// ResponseFinal QoS. The answerer DIALS the tap and zenohd listens, so the
/// answerer is the HIGH endpoint, `Direction::B` — asserted, not assumed.
fn answers_on_the_answerer_half(recording: &Recording) -> Answers {
    let segments = recording.lock().expect("recording lock").clone();
    let pcap = synthesise_pcap(&segments, DIALER_PORT, LISTENER_PORT);
    let dissection = Dissection::from_pcap(&pcap).expect("the synthesised pcap parses");
    let flows = dissection.flows();
    assert_eq!(flows.len(), 1, "one relayed connection is one flow");
    let flow = &flows[0];
    assert_eq!(
        (flow.flow.low.port, flow.flow.high.port),
        (u32::from(LISTENER_PORT), u32::from(DIALER_PORT)),
        "zenohd (the listener) must be the LOW endpoint, so the answerer is B"
    );
    let mut answers = Answers {
        responses: Vec::new(),
        finals: Vec::new(),
    };
    for frame in flow.frames.iter() {
        if frame.direction != Direction::B {
            continue;
        }
        let Ok(InboundFrame::Frame { payload, .. }) = &frame.frame else {
            continue;
        };
        let Ok(records) = parse_frame_payload(payload) else {
            continue;
        };
        for record in records {
            match record {
                NetworkMessage::Response(r) => {
                    answers.responses.push(effective_qos(r.extensions.as_ref()))
                }
                NetworkMessage::ResponseFinal(f) => {
                    answers.finals.push(effective_qos(f.extensions.as_ref()))
                }
                _ => {}
            }
        }
    }
    answers
}

/// One leg: a fresh zenohd, a tap in front of it, `answerer` behind the tap,
/// and a stock querier straight at zenohd.
fn run_leg(answerer: Answerer) -> Answers {
    let (mut zenohd, zenohd_port) = spawn_zenohd_dialer_on_ephemeral_tcp(
        &zenohd_binary(),
        "zenohd (reply-QoS differential)",
        None,
        &[],
        None,
    );
    let (tap_port, recording) = tap_proxy(zenohd_port);
    let (mut answering, mut answer_reader) = spawn_answerer(answerer, tap_port);

    let answered = run_query_until_answered(
        "stock z_get straight at zenohd",
        QueryAttempts::UpTo(GET_ATTEMPTS),
        GET_RECEIVED,
        GET_WALL_CLOCK,
        || spawn_zget(zenohd_port),
    );
    let answerer_out = read_captured(&mut answer_reader);
    let (mut get_child, _get_reader, _get_out) = answered.unwrap_or_else(|captured| {
        panic!(
            "{answerer:?}: the stock querier got no reply in {GET_ATTEMPTS} attempts, so no \
             Response crossed the tap.\n--- z_get ---\n{captured}\n--- answerer ---\n{answerer_out}"
        )
    });
    let _ = get_child.child_mut().kill();
    let _ = get_child.child_mut().wait();
    // The final follows the reply; give the tap time to relay it before the
    // answerer dies.
    std::thread::sleep(Duration::from_millis(300));
    let _ = answering.child_mut().kill();
    let _ = answering.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    {
        let segments = recording.lock().expect("recording lock");
        let from = |side: Side| -> usize {
            segments
                .iter()
                .filter(|(s, _)| *s == side)
                .map(|(_, b)| b.len())
                .sum()
        };
        assert!(
            from(Side::FromDialer) > 0 && from(Side::FromListener) > 0,
            "{answerer:?}: a one-way recording is not a session"
        );
    }
    let answers = answers_on_the_answerer_half(&recording);
    eprintln!(
        "{answerer:?}: Response qos {:?}, ResponseFinal qos {:?}",
        answers.responses, answers.finals
    );
    // ANTI-VACUITY: an answerer that put no Response on this half makes every
    // comparison below a comparison of two empty sets.
    assert!(
        !answers.responses.is_empty(),
        "{answerer:?}: the querier printed a reply but no Response was dissected on the \
         answerer's half:\n{answerer_out}"
    );
    answers
}

fn distinct(values: &[QosLevel]) -> Vec<u8> {
    let mut raw: Vec<u8> = values.iter().map(|q| q.raw).collect();
    raw.sort_unstable();
    raw.dedup();
    raw
}

/// THE WITNESS. The `zenohd` token in the name is load-bearing: Layer C0's
/// skip-token rule reads the function name, and this test spawns zenohd.
// wz-proves: query-reply wz->zenoh partial
#[test]
#[ignore = "binary-dep e2e (zenohd + zenoh z_queryable/z_get + wz-ap-demo); Layer Z runs via --ignored"]
fn a_wz_reply_carries_the_qos_a_stock_zenoh_queryable_gives_the_same_query_via_zenohd() {
    let stock = run_leg(Answerer::StockZenoh);
    let wz = run_leg(Answerer::Wz);

    assert_eq!(
        distinct(&wz.responses),
        distinct(&stock.responses),
        "the same default query, routed by the same zenohd, was answered with a different \
         Response QoS. Stock zenoh's reply inherits the query's QoS \
         (`zenoh/src/api/builders/reply.rs` @ `qos: query.inner.qos.into(),`); a wz reply that \
         reads as DEFAULT is droppable where the reference's is not. \
         stock={:?} wz={:?}",
        stock.responses,
        wz.responses
    );
}
