// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The protocol patch level a wz ACCEPTOR answers, read off the wire of a session a real
//! zenoh-pico program opened.
//!
//! wz's acceptor answers `min(CURRENT, the level the InitSyn announced)`, as zenoh
//! (`io/zenoh-transport/src/unicast/establishment/ext/patch.rs` @
//! `Ok(min(PatchType::CURRENT, state.patch))`) and pico
//! (`src/transport/unicast/transport.c`, the InitAck `_patch` cap) do. The in-process witness is
//! `wz-runtime-tokio`'s `init_ack_patch_level.rs`, which feeds the acceptor InitSyns wz crafted.
//!
//! The stock initiators that VALIDATE the answer (zenoh, and pico with fragmentation on) are the
//! ones that announce CURRENT, so they never present the low input. The one that does present it,
//! pico built with `Z_FEATURE_FRAGMENTATION=0`, writes no `0x7` extension at all and does not read
//! the answer either: its verdict would be green whatever wz said. So the answer is read here from
//! the bytes, relayed through the tap proxy and parsed by wz's own decoder, while the INPUT is
//! the real program's.
//!
//! Two legs, each the other's control:
//!
//! * the fragmentation-disabled `z_put` announces nothing and must be answered `NO_PATCH`, which
//!   an acceptor that answers CURRENT unconditionally fails;
//! * the stock `z_put` announces CURRENT and must be answered CURRENT, which an acceptor that
//!   answers `NO_PATCH` unconditionally fails.
//!
//! Each leg also asserts what its oracle announced, so a rebuilt oracle that stopped taking the
//! switch reads as a wrong input rather than as a wz defect.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use wz_capture::Dissection;
use wz_integration_tests::bounded::BoundedStatus as _;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, graceful_terminate, read_captured,
    spawn_on_ephemeral_port, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary,
    zenoh_pico_nofrag_cli_binary,
};
use wz_integration_tests::wire_tap::{synthesise_pcap, tap_proxy, Side};
use wz_session_core::extpatch::{patch_of_entry, peer_patch, PatchLevel, CURRENT_PATCH, NO_PATCH};
use wz_session_core::inbound::InboundFrame;
use wz_session_core::passive::Direction;

/// The synthesised endpoint ports; the lower one is `Direction::A`, so wz (the listener) is A.
/// The order is asserted below rather than assumed.
const DIALER_PORT: u16 = 40_000;
const LISTENER_PORT: u16 = 7447;

/// What one relayed session's handshake carried.
struct Handshake {
    /// The patch level the initiator's InitSyn announced, `None` when it carried no `0x7` entry.
    announced: Option<PatchLevel>,
    /// The level wz's InitAck answered, read the way a peer reads it (`peer_patch`).
    answered: PatchLevel,
}

/// Relay one `z_put` from `z_put` to a listening `wz-ap-demo` and read both Init messages back.
fn relayed_handshake(z_put: &Path, key: &str) -> Handshake {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let demo_stderr = tempfile::tempfile().expect("tempfile for demo stderr");
    let (mut demo_guard, mut demo_reader, wz_port) = spawn_on_ephemeral_port(
        &demo,
        &["--listen", "127.0.0.1:0", "--key", "demo/**"],
        "listening on 127.0.0.1:",
        "wz-ap-demo (--listen, behind the tap proxy)",
        demo_stderr,
    );
    let (proxy_port, recording) = tap_proxy(wz_port);

    let mut capture = tempfile::tempfile().expect("zenoh-pico z_put capture");
    let put = Command::new(z_put)
        .args([
            "-e",
            &format!("tcp/127.0.0.1:{proxy_port}"),
            "-k",
            key,
            "-v",
            "patch-level-through-the-tap",
        ])
        .stdout(capture.try_clone().expect("clone capture"))
        .stderr(capture.try_clone().expect("clone capture"))
        .status_bounded()
        .expect("spawn zenoh-pico z_put");
    assert!(
        put.success(),
        "{} exited {put:?} against the tapped wz acceptor; its output was:\n{}",
        z_put.display(),
        read_captured(&mut capture)
    );
    wait_for_substring(
        &mut demo_reader,
        "SUBSCRIBER FIRED",
        Duration::from_secs(10),
    )
    .expect("wz-ap-demo never delivered the relayed sample, so the session did not complete");
    graceful_terminate(demo_guard.child_mut(), Duration::from_secs(5));
    // The relay threads see their EOF after the demo exits.
    std::thread::sleep(Duration::from_millis(200));
    let segments = recording.lock().expect("recording lock").clone();
    assert!(
        segments.iter().any(|(s, _)| *s == Side::FromDialer)
            && segments.iter().any(|(s, _)| *s == Side::FromListener),
        "the tap recorded {} segment(s) and not both directions",
        segments.len()
    );

    let pcap = synthesise_pcap(&segments, DIALER_PORT, LISTENER_PORT);
    let dissection = Dissection::from_pcap(&pcap).expect("the synthesised pcap parses");
    let flows = dissection.flows();
    assert_eq!(flows.len(), 1, "one relayed connection is one flow");
    let flow = &flows[0];
    assert_eq!(
        (flow.flow.low.port, flow.flow.high.port),
        (u32::from(LISTENER_PORT), u32::from(DIALER_PORT)),
        "the synthesised ports decide that wz's half is Direction::A"
    );

    let mut syn: Option<Option<PatchLevel>> = None;
    let mut ack: Option<PatchLevel> = None;
    for frame in flow.frames().iter() {
        let Ok(InboundFrame::Init {
            is_ack, extensions, ..
        }) = &frame.frame
        else {
            continue;
        };
        match (frame.direction, *is_ack) {
            (Direction::B, false) if syn.is_none() => {
                syn = Some(extensions.iter().find_map(patch_of_entry));
            }
            (Direction::A, true) if ack.is_none() => {
                ack = Some(peer_patch(extensions));
            }
            (direction, is_ack) => panic!(
                "an Init with is_ack={is_ack} on {direction:?} is not the one InitSyn from \
                 pico and one InitAck from wz this handshake should hold"
            ),
        }
    }
    Handshake {
        announced: syn.expect("no InitSyn was read on pico's half"),
        answered: ack.expect("no InitAck was read on wz's half"),
    }
}

/// THE WITNESS: a pico that announces no patch level is answered `NO_PATCH`.
// wz-proves: session-unicast-accept pico->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + fragmentation-disabled zenoh-pico CLI); Layer Ewire runs via --ignored"]
fn the_analyzer_reads_a_no_patch_answer_to_a_fragmentation_disabled_pico() {
    let handshake = relayed_handshake(&zenoh_pico_nofrag_cli_binary("z_put"), "demo/nofrag");
    assert_eq!(
        handshake.announced, None,
        "the fragmentation-disabled oracle wrote a patch extension on its InitSyn; it is not \
         the pre-patch initiator this leg needs (was the arm built with \
         Z_FEATURE_FRAGMENTATION=0?)"
    );
    assert_eq!(
        handshake.answered, NO_PATCH,
        "a peer that announced no patch level must be answered min(CURRENT, NONE) = NONE; wz \
         answered {}",
        handshake.answered
    );
}

/// THE CONTROL: the stock pico announces CURRENT and is answered CURRENT.
// wz-proves: session-unicast-accept pico->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenoh-pico CLI); Layer Ewire runs via --ignored"]
fn the_analyzer_reads_a_current_patch_answer_to_a_stock_pico() {
    let handshake = relayed_handshake(&zenoh_pico_cli_binary("z_put"), "demo/stockfrag");
    assert_eq!(
        handshake.announced,
        Some(CURRENT_PATCH),
        "the stock oracle is built with fragmentation on and announces CURRENT"
    );
    assert_eq!(
        handshake.answered, CURRENT_PATCH,
        "min(CURRENT, CURRENT) = CURRENT; an answer below the peer's level turns off the \
         fragment chain markers both ends support"
    );
}
