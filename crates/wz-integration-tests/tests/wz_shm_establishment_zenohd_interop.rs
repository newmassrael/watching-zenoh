// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y505 — wz's SHM ESTABLISHMENT offer against a zenohd that actually has
//! `init::ext::Shm`, and the defect that only this pairing could show.
//!
//! ## What was untested, and why it stayed that way
//!
//! wz puts a UNIT ext at establishment id 0x2 (`extshm::SHM_ESTABLISHMENT_EXT_ID`)
//! where zenoh declares `Shm = zextzbuf!(0x2, false)`
//! (`commons/zenoh-protocol/src/transport/init.rs:152`). The inventory called that
//! WIRE-INCOMPATIBLE and left it there. Two separate things kept the actual wire
//! behaviour unmeasured for the whole life of the atom:
//!
//! 1. **No spawnable binary offered it.** `SessionOffer::with_shm` and
//!    `connect_and_open_session_with_shm` have existed since R3b, and nothing
//!    called them outside unit tests, so wz's one occupant of zenoh's
//!    establishment ext space had never faced a foreign decoder. `wz-ap-demo`
//!    gained `--shm` (both roles) in this round.
//! 2. **No oracle carried the extension.** `shared-memory` is absent from zenoh's
//!    `default` feature set (`zenoh/Cargo.toml:34-46`) and zenohd's default is
//!    `zenoh/default`, so the STOCK oracle has no `Shm` compiled in at all — it
//!    can neither send the challenge nor react to an offer. Pointing wz at it
//!    yields `shm negotiated = false` for a reason that has nothing to do with the
//!    question, which is exactly the shape of a foreign CLI hiding the property.
//!    `ZENOHD_SHM=1 scripts/build-zenohd.sh` builds the oracle that has it.
//!
//! ## The two directions are NOT symmetric, and only one could catch the bug
//!
//! zenoh sends its `Shm` on the InitSyn unconditionally when the feature is built
//! (`establishment/open.rs:152`), but on the InitAck only in REPLY to one it
//! understood (`establishment/ext/shm.rs:455` returns `None` for an absent input).
//! So:
//!
//! - **wz DIALS** (leg 1): zenohd receives wz's UNIT@0x2, does not recognise it,
//!   and sends no `Shm` back. wz sees no offer, `is_shm` resolves to false. This
//!   proves the format's skip contract holds for wz's extra extension — a real
//!   result, and it was already green before the fix.
//! - **zenohd DIALS** (leg 2): wz's decoder receives zenoh's real `Shm` ZBuf. This
//!   is the only arm where wz can be wrong, and it WAS: `peer_offered_shm` matched
//!   on the 4-bit id field alone, so header `0x42` (ZBuf|0x2) read as wz's own
//!   `0x02` and the session negotiated `shm negotiated = true`. wz would then have
//!   put SHM DESCRIPTORS on a link whose peer had issued a challenge wz cannot
//!   answer and expects real payload bytes — silent corruption at the application
//!   layer, not a clean refusal.
//!
//! The fix is in the mechanism, not at the SHM site: `unit_ext::chain_has_ext_eid`
//! now matches on the extension IDENTITY (`iext::eid` — the header minus only the
//! chain flag, so ENCODING and mandatory bits are part of it), which is what
//! identifies a zenoh extension. zenoh relies on that itself, pairing
//! `QoS = zextunit!(0x1)` with `QoSLink = zextz64!(0x1)` as two distinct
//! extensions at one id. `peer_offered_qos` therefore names BOTH forms explicitly
//! rather than getting them from a loose match.
//!
//! Both legs assert `shm negotiated = false` with the session ESTABLISHED. The
//! `false` is the whole point: it is what a correct negotiation against a peer
//! that never agreed must produce, and before the fix leg 2 produced `true`.
//!
//! Requires `ZENOHD_SHM=1 scripts/build-zenohd.sh` (a SOURCE build) and a
//! `wz-ap-demo` built `--features session-extshm`. SKIPs where the oracle is
//! absent — it is not provisioned in hosted CI, the vsock precedent.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, zenohd_shm_binary, ChildGuard,
    PortReservation,
};

/// The demo's negotiated-capability witness. `is_shm()` is
/// `local_offer && peer_offer`, logged by both roles.
const SHM_WITNESS: &str = "wz-ap-demo: shm negotiated = ";

/// Fail NOW, naming the feature list, if the shared demo binary is not the
/// `session-extshm` one — the atom is compiled out otherwise and `--shm` is inert,
/// which would make both legs pass while proving nothing.
fn assert_shm_was_built(captured: &str) {
    let line = captured
        .lines()
        .find(|l| l.contains("BUILD FEATURES = ["))
        .unwrap_or_else(|| {
            panic!("the wz-ap-demo never printed its BUILD FEATURES line\n{captured}")
        });
    assert!(
        line.contains(" session-extshm ") || line.contains("[session-extshm "),
        "the wz-ap-demo was built WITHOUT `session-extshm`, so `--shm` stages no \
         offer and neither leg asserts anything. Build it with \
         `cargo build -p wz-ap-demo --features session-extshm`.\n{line}"
    );
}

/// Read the `shm negotiated = <bool>` value out of a captured demo log.
fn negotiated(captured: &str) -> bool {
    let line = captured
        .lines()
        .find(|l| l.contains(SHM_WITNESS))
        .unwrap_or_else(|| {
            panic!("the demo never logged `{SHM_WITNESS}` — was `--shm` passed?\n{captured}")
        });
    let (_, v) = line
        .split_once(SHM_WITNESS)
        .expect("witness prefix present");
    v.trim()
        .parse::<bool>()
        .unwrap_or_else(|e| panic!("the witness value is not a bool ({e})\n  line: {line}"))
}

fn tempfile_pair() -> (std::fs::File, std::fs::File) {
    let f = tempfile::tempfile().expect("tempfile");
    let w = f.try_clone().expect("dup handle");
    (f, w)
}

/// Leg 1 — wz DIALS the SHM-enabled zenohd with `--shm`.
///
/// zenohd does not recognise wz's UNIT@0x2, so it replies with no `Shm` and the
/// capability resolves to off. What this proves is the zenoh extension format's
/// own skip contract on a real decoder: an unknown, non-mandatory, UNIT-encoded
/// extension costs the handshake nothing. The session reaches Established.
// wz-proves: session-extshm wz->zenohd
// wz-proves: transport-shm wz->zenohd
#[test]
#[ignore = "binary-dep e2e (ZENOHD_SHM=1 build-zenohd.sh + wz-ap-demo --features session-extshm); Layer Z runs via --ignored"]
fn wz_negotiates_shm_with_a_zenohd_it_dials() {
    let Some(zenohd) = zenohd_shm_binary() else {
        eprintln!(
            "SKIP: no shared-memory zenohd at target/zenohd-shm/zenohd \
             (run `ZENOHD_SHM=1 scripts/build-zenohd.sh`)"
        );
        return;
    };
    let port = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port.port());

    let (mut zd_log, zd_w) = tempfile_pair();
    // zenohd's tracing goes to STDOUT, so both handles land in one capture —
    // otherwise the readiness barrier below waits on a file nothing writes to.
    let zd_w2 = zd_w.try_clone().expect("dup zenohd handle");
    let mut zd = ChildGuard::wrap(
        "zenohd (shared-memory oracle)",
        Command::new(&zenohd)
            .args(["-l", &format!("tcp/{addr}")])
            .args(["--no-multicast-scouting", "--rest-http-port", "none"])
            .stdout(Stdio::from(zd_w))
            .stderr(Stdio::from(zd_w2))
            .spawn()
            .expect("spawn shm zenohd"),
    );
    if let Err(c) = wait_for_substring(&mut zd_log, "can be reached at", Duration::from_secs(20)) {
        panic!("the shm zenohd never announced its listener within 20s\n--- zenohd ---\n{c}");
    }
    drop(port);

    let (mut wz_log, wz_w) = tempfile_pair();
    let mut wz = ChildGuard::wrap(
        "wz-ap-demo (--connect --shm)",
        Command::new(wz_ap_demo_binary())
            .args(["--connect", &addr, "--shm", "--key", "demo/shm"])
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(wz_w))
            .spawn()
            .expect("spawn wz-ap-demo"),
    );

    let captured = wait_for_substring(&mut wz_log, SHM_WITNESS, Duration::from_secs(20));
    let _ = wz.child_mut().kill();
    let _ = wz.child_mut().wait();
    let _ = zd.child_mut().kill();
    let _ = zd.child_mut().wait();
    let captured = captured
        .unwrap_or_else(|c| panic!("wz never logged the SHM witness within 20s\n--- wz ---\n{c}"));
    assert_shm_was_built(&captured);

    assert!(
        negotiated(&captured),
        "wz must now negotiate SHM with a shared-memory zenohd. R311y505 asserted \
         the OPPOSITE here and was right at the time: wz then sent a UNIT@0x2 that \
         zenoh does not recognise, so `false` was the only correct outcome. \
         R311y507 replaced that with zenoh's real challenge-response, and `true` \
         is what the exchange completing looks like — the acceptor mapped wz's \
         auth segment and echoed the challenge from inside it, and wz did the \
         same to zenohd's.\n--- wz ---\n{captured}"
    );
    assert!(
        captured.contains("session Established"),
        "the session must reach Established\n--- wz ---\n{captured}"
    );
}

/// Leg 2 — the SHM-enabled zenohd DIALS wz, so wz's decoder receives zenoh's real
/// `Shm` ZBuf ext (header 0x42).
///
/// THIS is the arm that caught the defect, and it is the only arm that could: a wz
/// that merely dials never receives a zenoh `Shm` at all (zenoh replies with one
/// only to an offer it understood). wz must offer here too, so that `is_shm`
/// starts `true` and a false positive is visible as `true` rather than being
/// masked by an already-`false` local side.
// wz-proves: session-extshm zenohd->wz
// wz-proves: transport-shm zenohd->wz
#[test]
#[ignore = "binary-dep e2e (ZENOHD_SHM=1 build-zenohd.sh + wz-ap-demo --features session-extshm); Layer Z runs via --ignored"]
fn wz_answers_a_real_zenohd_shm_challenge_when_zenohd_dials() {
    let Some(zenohd) = zenohd_shm_binary() else {
        eprintln!(
            "SKIP: no shared-memory zenohd at target/zenohd-shm/zenohd \
             (run `ZENOHD_SHM=1 scripts/build-zenohd.sh`)"
        );
        return;
    };
    let port = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port.port());

    // wz ACCEPTS, offering SHM: `is_shm` starts true, so only the peer's ext can
    // bring it down — which is the property under test.
    let (mut wz_log, wz_w) = tempfile_pair();
    let mut wz = ChildGuard::wrap(
        "wz-ap-demo (--listen --shm)",
        Command::new(wz_ap_demo_binary())
            .args(["--listen", &addr, "--shm", "--key", "demo/shm"])
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(wz_w))
            .spawn()
            .expect("spawn wz-ap-demo"),
    );
    if let Err(c) = wait_for_substring(&mut wz_log, "shm = on", Duration::from_secs(10)) {
        let _ = wz.child_mut().kill();
        let _ = wz.child_mut().wait();
        panic!("wz never announced its SHM offer within 10s\n--- wz ---\n{c}");
    }
    drop(port);

    let (zd_log, zd_w) = tempfile_pair();
    let zd_w2 = zd_w.try_clone().expect("dup zenohd handle");
    let mut zd = ChildGuard::wrap(
        "zenohd (shared-memory oracle, dialling)",
        Command::new(&zenohd)
            .args(["-e", &format!("tcp/{addr}")])
            .args(["--no-multicast-scouting", "--rest-http-port", "none"])
            .stdout(Stdio::from(zd_w))
            .stderr(Stdio::from(zd_w2))
            .spawn()
            .expect("spawn shm zenohd dialer"),
    );

    let captured = wait_for_substring(&mut wz_log, SHM_WITNESS, Duration::from_secs(25));
    let _ = zd.child_mut().kill();
    let _ = zd.child_mut().wait();
    let _ = wz.child_mut().kill();
    let _ = wz.child_mut().wait();
    let mut zd_tail = zd_log;
    let mut zd_text = String::new();
    let _ = zd_tail.read_to_string(&mut zd_text);
    let captured = captured.unwrap_or_else(|c| {
        panic!("wz never logged the SHM witness within 25s\n--- wz ---\n{c}\n--- zenohd ---\n{zd_text}")
    });
    assert_shm_was_built(&captured);

    assert!(
        negotiated(&captured),
        "wz must ANSWER a real zenoh `Shm` challenge, not merely avoid mistaking it \
         for its own UNIT offer. R311y505 asserted `false` here and it was the \
         right assertion then — wz could not answer, so negotiating `true` would \
         have meant sending descriptors to a peer expecting payload bytes. \
         R311y507 built the answer: wz maps the segment id in zenohd's ZBuf, reads \
         the challenge, and echoes it on OpenSyn.\n--- wz ---\n{captured}"
    );
    assert!(
        captured.contains("session Established"),
        "the session must reach Established\n--- wz ---\n{captured}"
    );
    let _ = read_captured(&mut wz_log);
}
