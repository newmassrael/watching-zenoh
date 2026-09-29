// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y506 — wz's `init::ext::QoSLink` (the z64 half of zenoh's DUAL QoS
//! establishment ext) against a real zenohd, in both directions.
//!
//! ## What the atom is, and what was missing
//!
//! zenoh negotiates QoS at ext id `0x1` in one of two mutually exclusive forms
//! (`commons/zenoh-protocol/src/transport/init.rs`
//! @ `pub type QoSLink = zextz64!(0x1, false)`):
//! `QoS = zextunit!(0x1)`, a presence marker, and `QoSLink = zextz64!(0x1)`,
//! whose z64 body packs the link's PRIORITY RANGE and RELIABILITY class. wz built
//! the unit form under `transport-qos` and DECODED both as "this peer does QoS",
//! but never emitted the z64 form and never read its body — so `session-extqos`
//! sat `reserved` with 0 cfg sites and the band was a documented residual.
//!
//! The band is not a hint. Both roles enforce a CONTAINMENT and ABORT the
//! handshake on a violation (`establishment/ext/qos.rs`):
//!
//! - the ACCEPTOR requires the initiator's range to be a SUBSET of its own
//!   (`recv_init_syn`, "not a subset of my PriorityRange") and adopts theirs;
//! - the INITIATOR requires the acceptor's to be a SUPERSET of its own
//!   (`recv_init_ack`, "not a superset of my PriorityRange") and keeps its own;
//! - an undeclared side inherits the other's; a declared RELIABILITY must MATCH.
//!
//! ## Only one direction is reachable, and the reason is upstream's, not ours
//!
//! zenoh seeds its state from an ENDPOINT's `prio=` / `rel=` metadata
//! (`Metadata::PRIORITIES` / `RELIABILITY`,
//! `commons/zenoh-protocol/src/core/endpoint.rs`
//! @ `pub const PRIORITIES: &'static str = "prio";`). On the DIAL side that is
//! the dial endpoint, metadata included. On the ACCEPT side it is
//! `link.get_src().to_endpoint()`
//! (`io/zenoh-transport/src/unicast/establishment/accept.rs`
//! @ `let endpoint = link.get_src().to_endpoint();`) — and the TCP link
//! constructs an accepted link's src locator with a HARD-CODED empty metadata
//! string (`io/zenoh-links/zenoh-link-tcp/src/unicast.rs`
//! @ `src_locator: Locator::new(TCP_LOCATOR_PREFIX, src_addr.to_string(), "")`).
//!
//! So a zenohd LISTENING on `tcp/…?prio=2-5` has no band at all, and pointing wz
//! at it proves nothing about the containment: measured first, and it accepted a
//! deliberately non-subset band. The legs below therefore have **zenohd DIAL
//! wz**, which is where zenohd's own band exists. That is a property of zenoh's
//! TCP link layer, not a wz limitation — and it is exactly the shape of a foreign
//! CLI hiding the property, so it is recorded rather than worked around.
//!
//! ## The four legs, and what separates them
//!
//! 1. `wz_reads_the_band_and_reliability_out_of_zenohds_qoslink_body` — wz
//!    declares NOTHING (`--qos` alone) and reports `prio=2-5;rel=1` after the
//!    handshake. Neither value exists anywhere in wz's configuration; both are
//!    decoded out of zenohd's z64 body, including the reliability bit at shift
//!    19. This is the leg that cannot be faked by local state.
//! 2. `a_wz_listener_declares_no_band_for_what_zenohd_dials` — R2944: wz listens
//!    on `?prio=3-4`, zenohd dials `?prio=0-7`, and wz ADOPTS `0-7`, because a
//!    listen endpoint's metadata is not the accepted link's — the same
//!    behaviour this doc measured on zenohd. It replaced R311y506's refusal
//!    leg, whose wz acceptor declared a band from a node-wide flag: a
//!    capability no TCP acceptor has upstream.
//! 3. `zenohd_accepts_a_band_only_qoslink_wz_encodes` — wz dials declaring
//!    `prio=2-5` and no reliability; zenohd adopts and echoes it. It carries
//!    the separating role R311y506's leg 3 had (see below).
//! 4. `zenohd_accepts_the_qoslink_wz_encodes_when_wz_dials` — the ENCODE
//!    direction: wz dials declaring `prio=1-4;rel=1` on the endpoint, zenohd's
//!    acceptor parses wz's z64 body (its `State::try_from_u64` aborts the
//!    handshake on a malformed one), adopts it, and echoes it in the InitAck,
//!    which wz's initiator merge then accepts. A full encode -> foreign parse ->
//!    foreign emit -> decode round trip.
//!
//! The containment REFUSAL itself is not a leg: it needs a band on both ends,
//! and over TCP the accepting end has none in either implementation. The
//! merge rules that decide it are unit-pinned in `extqos`.
//!
//! ## Damage that binds them (measured on R311y506's legs; re-measure after R2944)
//!
//! - DECODER, reading the range's END byte at shift 12 instead of 11: every leg
//!   reds (`QosLinkRejected(InvalidValue)` / `Terminal`) — the decoder is on
//!   every leg, including the dialling ones, where wz reads zenohd's echo.
//! - ENCODER, writing the reliability bit at shift 18 instead of 19: legs 1 and 4
//!   red while **leg 3 stays GREEN** — leg 3 declares no reliability, so the
//!   damaged bit is never written. That is what separates the legs from each
//!   other rather than leaving them one undifferentiated bundle.
//!
//! Requires `scripts/build-zenohd.sh` (the STOCK oracle — `QoSLink` is not
//! feature-gated in zenoh and `qos.enabled` is true in its DEFAULT config, so no
//! variant build is needed) and a `wz-ap-demo` built `--features
//! session-extqos`. Resolves the oracle through `zenohd_binary()`, which PANICS
//! when absent rather than skipping: that is the stock-zenohd convention here,
//! and it is also what makes the corpus audit see these as foreign witnesses.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    wait_for_substring, wz_ap_demo_binary, zenohd_binary, ChildGuard, PortReservation,
    ZENOHD_LISTENER_LINE,
};

/// The demo's post-handshake witness: the QoS link metadata NEGOTIATED on a
/// face, rendered in zenoh's own endpoint spelling.
const NEGOTIATED: &str = "qos link negotiated = ";
/// R2944 — the barrier that says the wz peer has bound. It used to be a
/// node-wide `qos link declared = ` line; a link's QoS metadata is its
/// endpoint's now, so what a leg declares is exactly the endpoint string it
/// passes, and the listen line is what says wz is ready.
const LISTENING: &str = "wz-ap-demo peer: listening on";

/// Fail NOW, naming the feature, if the shared demo binary is not the
/// `session-extqos` one. Every feature-set lane writes the same artifact path, so
/// without this the flags would be rejected (or run inert) and the legs would
/// report a failure that has nothing to do with the property.
fn assert_extqos_was_built(captured: &str) {
    let line = captured
        .lines()
        .find(|l| l.contains("BUILD FEATURES = ["))
        .unwrap_or_else(|| {
            panic!("the wz-ap-demo never printed its BUILD FEATURES line\n{captured}")
        });
    assert!(
        line.contains(" session-extqos ") || line.contains("[session-extqos "),
        "the wz-ap-demo was built WITHOUT `session-extqos`, so an endpoint's \
         `prio` / `rel` stages no QoSLink and every leg below would assert \
         nothing. Build it with `cargo build -p wz-ap-demo --features \
         session-extqos`.\n{line}"
    );
}

/// Read the value of the LAST `qos link negotiated = ` line in a capture.
fn negotiated(captured: &str) -> String {
    captured
        .lines()
        .filter_map(|l| l.split_once(NEGOTIATED))
        .map(|(_, v)| v.trim().to_string())
        .next_back()
        .unwrap_or_else(|| panic!("the demo never logged `{NEGOTIATED}`\n{captured}"))
}

fn tempfile_pair() -> (std::fs::File, std::fs::File) {
    let f = tempfile::tempfile().expect("tempfile");
    let w = f.try_clone().expect("dup handle");
    (f, w)
}

/// Bring up a wz peer that BINDS `wz_listen` (an endpoint, metadata included)
/// with `--qos`, wait for its listen line, then have a zenohd DIAL
/// `bind_addr` with `dial_metadata` appended to the locator. Returns the wz
/// capture once `needle` appears (or the capture so far, on timeout).
///
/// The wz side binds and the zenohd side dials because that is the only ordering
/// in which zenohd HAS a band (see the module doc): the fixture owns that
/// ordering rather than sleeping toward it — the listen line is the barrier
/// that says wz is ready.
fn run_leg(
    zenohd: &std::path::Path,
    bind_addr: &str,
    wz_listen: &str,
    dial_metadata: &str,
    needle: &str,
) -> String {
    let (mut wz_log, wz_w) = tempfile_pair();
    let mut wz = ChildGuard::wrap(
        "wz-ap-demo (--peer, session-extqos)",
        Command::new(wz_ap_demo_binary())
            .args(["--peer", wz_listen, "--key", "demo/qos", "--qos"])
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(wz_w))
            .spawn()
            .expect("spawn wz-ap-demo"),
    );
    if let Err(c) = wait_for_substring(&mut wz_log, LISTENING, Duration::from_secs(20)) {
        panic!("wz never announced its listener within 20s\n--- wz ---\n{c}");
    }

    let (_zd_log, zd_w) = tempfile_pair();
    let zd_w2 = zd_w.try_clone().expect("dup zenohd handle");
    let mut zd = ChildGuard::wrap(
        "zenohd (dialing, with endpoint prio/rel metadata)",
        Command::new(zenohd)
            .args(["-e", &format!("tcp/{bind_addr}{dial_metadata}")])
            .args(["--no-multicast-scouting", "--rest-http-port", "none"])
            .stdout(Stdio::from(zd_w))
            .stderr(Stdio::from(zd_w2))
            .spawn()
            .expect("spawn zenohd dialer"),
    );

    let captured = wait_for_substring(&mut wz_log, needle, Duration::from_secs(25));
    let _ = zd.child_mut().kill();
    let _ = zd.child_mut().wait();
    let _ = wz.child_mut().kill();
    let _ = wz.child_mut().wait();
    let captured = captured
        .unwrap_or_else(|c| panic!("wz never logged `{needle}` within 25s\n--- wz ---\n{c}"));
    assert_extqos_was_built(&captured);
    captured
}

/// Leg 1 — wz declares NOTHING and still ends up with zenohd's band and
/// reliability, because the merge adopts an undeclared side's counterpart
/// (`(None, p) => p`, zenoh's own arm in both `recv_init_*`).
///
/// This is the leg local state cannot fake: `prio=2-5` and `rel=1` appear in no
/// wz configuration on this run — wz listens on a bare `tcp/` endpoint — so the
/// only place they can have come from is the z64 body a real zenohd put on the
/// wire, reliability bit at shift 19 included.
// wz-proves: session-extqos zenohd->wz
#[test]
#[ignore = "binary-dep e2e (build-zenohd.sh + wz-ap-demo --features session-extqos); Layer Z runs via --ignored"]
fn wz_reads_the_band_and_reliability_out_of_zenohds_qoslink_body() {
    let zenohd = zenohd_binary();
    let port = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port.port());
    drop(port);

    let captured = run_leg(&zenohd, &addr, &addr, "?prio=2-5;rel=1", NEGOTIATED);

    assert_eq!(
        negotiated(&captured),
        "prio=2-5;rel=1",
        "wz must decode BOTH halves of zenohd's `QoSLink` z64 body: the priority \
         range at shifts 3 and 11, and the reliability bit at shift 19\n\
         --- wz ---\n{captured}"
    );
}

/// Leg 2 — R2944: a wz LISTENING on an endpoint that carries `?prio=3-4`
/// declares no band for the links it accepts, exactly as the zenohd this
/// module doc measured does: the accepted link's own endpoint is what the
/// acceptor reads, and TCP gives it none. So zenohd dialling with `prio=0-7` —
/// a range that is NOT inside `3-4` — is not refused; wz adopts it.
///
/// This leg replaced R311y506's refusal leg, whose wz acceptor declared
/// `3-4` from a node-wide flag and refused. That refusal was a capability no
/// TCP acceptor has upstream, so it witnessed a divergence; a containment
/// refusal needs a band on BOTH ends, which over TCP never happens in either
/// implementation, and the merge rules that decide it are unit-pinned in
/// `extqos` instead. A wz that read its LISTEN metadata as the accepted
/// link's would refuse here.
///
/// The name carries `zenohd` because libtest's `--skip` matches the FUNCTION
/// name, and Layer E's sweep skips this file's binary-dependent legs by that
/// token (`test_discipline_gate.py`); R2944 named it without one, so Layer E's
/// sweep ran it as well as Layer Z, the lane that owns it.
// wz-proves: session-extqos zenohd->wz
#[test]
#[ignore = "binary-dep e2e (build-zenohd.sh + wz-ap-demo --features session-extqos); Layer Z runs via --ignored"]
fn a_wz_listener_declares_no_band_for_what_zenohd_dials() {
    let zenohd = zenohd_binary();
    let port = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port.port());
    drop(port);

    let captured = run_leg(
        &zenohd,
        &addr,
        &format!("tcp/{addr}?prio=3-4"),
        "?prio=0-7",
        NEGOTIATED,
    );

    assert_eq!(
        negotiated(&captured),
        "prio=0-7",
        "the listen endpoint's band is not the accepted link's: wz adopts the \
         dialler's band, as a zenohd listener does\n--- wz ---\n{captured}"
    );
    assert!(
        !captured.contains("QosLinkRejected"),
        "nothing on the accepting end declared a band to refuse against\n\
         --- wz ---\n{captured}"
    );
}

/// Leg 3 — the ENCODE direction with a band and NO reliability. wz dials a
/// zenohd with the endpoint `?prio=2-5`, so the z64 body wz puts on the wire
/// carries a range and no reliability bit; zenohd adopts and echoes it.
///
/// Carrying no reliability is what separates it from leg 4: the encoder damage
/// (reliability bit at shift 18) leaves this leg green while reddening legs 1
/// and 4 — the legs are separately bound, not one bundle. R311y506's leg 3
/// played that role from the acceptor side with a node-wide band; R2944
/// retired that band, and the role moved to the dialling side, where a wz band
/// now lives.
// wz-proves: session-extqos wz->zenohd
#[test]
#[ignore = "binary-dep e2e (build-zenohd.sh + wz-ap-demo --features session-extqos); Layer Z runs via --ignored"]
fn zenohd_accepts_a_band_only_qoslink_wz_encodes() {
    let captured = wz_dials_zenohd_with("?prio=2-5");
    assert_eq!(
        negotiated(&captured),
        "prio=2-5",
        "zenohd must accept the band-only body wz encoded and echo it back\n\
         --- wz ---\n{captured}"
    );
    assert!(
        !captured.contains("QosLinkRejected"),
        "the round trip must not be refused\n--- wz ---\n{captured}"
    );
}

/// Leg 4 — the ENCODE direction. wz DIALS a plain zenohd declaring
/// `prio=1-4;rel=1`, so wz's own z64 body faces a foreign parser: zenohd's
/// acceptor runs `State::try_from_u64` on it and ABORTS the handshake if it is
/// not a valid encoding, then adopts the range (its own is empty, per the module
/// doc) and echoes it back in the InitAck, which wz's initiator merge validates
/// against its own under the SUPERSET rule.
///
/// So a session here is a full round trip — wz encode, zenoh parse, zenoh emit,
/// wz decode — and any of the four can break it. Measured: the encoder damage
/// (reliability bit one position low) reds this leg, because zenohd then reads
/// BestEffort, echoes it, and wz's own reliability-must-match rule refuses.
///
/// R2944 — wz declares it the way zenoh does, on the dialled endpoint
/// (`--connect 'tcp/HOST:PORT?prio=1-4;rel=1'`), where it used to take two
/// node-wide flags.
// wz-proves: session-extqos wz->zenohd
#[test]
#[ignore = "binary-dep e2e (build-zenohd.sh + wz-ap-demo --features session-extqos); Layer Z runs via --ignored"]
fn zenohd_accepts_the_qoslink_wz_encodes_when_wz_dials() {
    let captured = wz_dials_zenohd_with("?prio=1-4;rel=1");
    assert_eq!(
        negotiated(&captured),
        "prio=1-4;rel=1",
        "a real zenohd must accept the z64 body wz encoded, adopt it, and echo it \
         back unchanged; any drift in wz's bit packing shows up here as a refused \
         handshake or a different band\n--- wz ---\n{captured}"
    );
    assert!(
        !captured.contains("QosLinkRejected"),
        "the round trip must not be refused\n--- wz ---\n{captured}"
    );
}

/// Bring up a listening zenohd, have a wz peer DIAL it with `metadata` on the
/// connect endpoint, and return the wz capture once a band is negotiated.
fn wz_dials_zenohd_with(metadata: &str) -> String {
    let zenohd = zenohd_binary();
    // TWO ports under ONE lock acquisition. `pick()` twice on this thread
    // re-enters the process-global port mutex and DEADLOCKS — which is what the
    // first draft of this leg did, hanging past every timeout instead of
    // failing. `pick_pair` is the documented seam for exactly this.
    let (zd_port, wz_raw_port) = PortReservation::pick_pair();
    let zd_addr = format!("127.0.0.1:{}", zd_port.port());
    let wz_addr = format!("127.0.0.1:{wz_raw_port}");

    let (mut zd_log, zd_w) = tempfile_pair();
    let zd_w2 = zd_w.try_clone().expect("dup zenohd handle");
    let mut zd = ChildGuard::wrap(
        "zenohd (listening oracle)",
        Command::new(&zenohd)
            .args(["-l", &format!("tcp/{zd_addr}")])
            .args(["--no-multicast-scouting", "--rest-http-port", "none"])
            // R2230 (open-debt item 579) — the readiness needle below is a
            // `debug!`. See `common::ZENOHD_LISTENER_LINE`: the `info!` line this
            // leg used to wait on stopped covering LOOPBACK in 1.10.0, and every
            // leg here binds loopback, so it waited out its whole budget on a
            // healthy router.
            .env("RUST_LOG", "z=debug")
            .stdout(Stdio::from(zd_w))
            .stderr(Stdio::from(zd_w2))
            .spawn()
            .expect("spawn zenohd"),
    );
    if let Err(c) = wait_for_substring(&mut zd_log, ZENOHD_LISTENER_LINE, Duration::from_secs(20)) {
        panic!("zenohd never announced its listener within 20s\n--- zenohd ---\n{c}");
    }
    // zenohd has bound; release the reservation so wz can take its own port.
    drop(zd_port);

    let (mut wz_log, wz_w) = tempfile_pair();
    let mut wz = ChildGuard::wrap(
        "wz-ap-demo (--peer --connect, session-extqos)",
        Command::new(wz_ap_demo_binary())
            .args([
                "--peer",
                &wz_addr,
                "--connect",
                &format!("tcp/{zd_addr}{metadata}"),
            ])
            .args(["--key", "demo/qos", "--qos"])
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(wz_w))
            .spawn()
            .expect("spawn wz-ap-demo"),
    );

    let captured = wait_for_substring(&mut wz_log, NEGOTIATED, Duration::from_secs(25));
    let _ = wz.child_mut().kill();
    let _ = wz.child_mut().wait();
    let _ = zd.child_mut().kill();
    let _ = zd.child_mut().wait();
    let captured = captured
        .unwrap_or_else(|c| panic!("wz never logged `{NEGOTIATED}` within 25s\n--- wz ---\n{c}"));
    assert_extqos_was_built(&captured);
    captured
}
