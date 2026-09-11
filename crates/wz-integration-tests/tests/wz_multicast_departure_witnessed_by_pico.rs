// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2562 — FOREIGN-INTEROP multicast DEPARTURE: a real zenoh-pico peer
//! adjudicates a watching-zenoh node LEAVING the group, not merely joining it.
//!
//! ## What was missing, and why an atom stayed PARTIAL on it
//!
//! `session-multicast` has carried the residual "no FOREIGN witness for the
//! departure story" since R311y784, and it survived every re-measurement since:
//! every proof line naming that atom is marked `partial`, and not one of
//! them observes a departure of any kind. wz emits a multicast Close on a
//! graceful stop (R311y782) and reports `MulticastPeerLost` on the receive side
//! (R311y784), and BOTH halves were only ever read by wz. A wire format that
//! only its own author parses is agreement, not interoperability.
//!
//! ## Why this test could not be written before this round
//!
//! The signal to witness against exists in the vendored pico —
//! `vendor/zenoh-pico/src/transport/multicast/rx.c` @ `_z_connectivity_peer_disconnected(_z_transport_common_get_session(&ztm->_common), &disconnected_peer,`
//! is its Close arm — but it sits under `Z_FEATURE_CONNECTIVITY`, which
//! `vendor/zenoh-pico/CMakeLists.txt` defaults to 0. MEASURED before this round:
//! the built `libzenohpico.so` exported ZERO `connectivit*` symbols, so the
//! "named foreign signal" the atom's reason offers as a lead did not exist in
//! this tree's own oracle. `scripts/build-zenoh-pico-cli.sh` now requests the
//! flag, asserts it against the GENERATED `config.h`, and installs `z_info` —
//! the one upstream example that declares a transport-events listener.
//!
//! ## The witness is upstream's own sentence
//!
//! `z_info` prints `>> [Transport Event] Closed:` followed by
//! `transport{zid=..., is_multicast=true, ...}`. Nothing in wz produces that
//! line, and nothing in this test parses a wz-authored artefact: pico decodes
//! wz's Close off a live UDP multicast socket and says, in its own words, that
//! the peer is gone.
//!
//! ## The discriminator is the ZID CARRIED ACROSS the two events
//!
//! Asserting only that `Closed:` appeared would pass on a pico that logged a
//! departure for any reason at all — including its own shutdown, or a peer that
//! was never wz. So the zid is EXTRACTED from the `Opened:` event pico raised
//! when it admitted wz, and the SAME string is then required on the `Closed:`
//! event. That binds the departure to the very peer whose arrival pico
//! adjudicated, and it needs no guess about how pico renders a zid — the run
//! supplies the literal.
//!
//! ⚠ The `Opened:` half is load-bearing and is NOT redundant with the existing
//! JOIN-admission tests. Without it a `Closed:` assertion could be satisfied by
//! a peer pico never admitted, which is the vacuous pass this shape exists to
//! refuse.
//!
//! ## Why the departure is a graceful stop rather than a kill
//!
//! `drive_multicast_session_with_shutdown`'s shutdown arm is what emits the
//! Close (`crates/wz-runtime-tokio/src/multicast_glue.rs` @ `let dgram = wz_session_core::handshake_encode::encode_multicast_close();`).
//! Killing the process would instead exercise pico's LEASE-expiry path
//! (`vendor/zenoh-pico/src/transport/multicast/lease.c`), a different arm with a
//! different reason, and it would take a lease to fire. The announced departure
//! is the half wz builds deliberately, so it is the half witnessed here; the
//! inferred one is a separate case and is not claimed by this test.
//!
//! ## Environment dependence (`#[ignore]`, Layer M)
//!
//! Multicast routing is environment-dependent, as for every test in this family,
//! so this is opt-in and runs via `--ignored`. `stdbuf -oL` line-buffers z_info's
//! stdout; glibc block-buffers a piped fd and would otherwise hide both witness
//! lines until exit.

use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use wz_integration_tests::common::{
    default_route_iface, read_captured, wait_for_substring, zenoh_pico_cli_binary, ChildGuard,
    PICO_BATCH_MULTICAST_SIZE, PICO_PROTO_VERSION, PICO_SN_RESOLUTION, ZENOH_MULTICAST_GROUP,
    Z_SUB_INIT_TIMEOUT,
};
use wz_runtime_tokio::multicast_glue::{
    drive_multicast_session_with_shutdown, MulticastDriveConfig,
};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::UdpDriver;
use wz_session_core::multicast_dispatch::{MulticastConfig, MulticastDispatcher};
use wz_session_core::multicast_params::MulticastParams;
use wz_session_core::WhatAmI;

const GROUP: Ipv4Addr = ZENOH_MULTICAST_GROUP;
// Distinct from every other multicast test's port (7446-7459 are taken) so the
// `--ignored` lane never contends on the same multicast bind.
const PORT: u16 = 7461;
/// The lease-expiry case gets its OWN port: the two tests run concurrently under
/// `cargo test`, and sharing a group port would let one node's beacons keep the
/// other's peer alive -- which would silently defeat the case whose whole
/// subject is silence.
const LEASE_PORT: u16 = 7462;

/// How long pico is given to admit wz from its JOIN beacon. wz beacons every
/// `join_interval_ms`, so this is many beacons wide rather than a race.
const ADMIT_BUDGET: Duration = Duration::from_secs(20);
/// How long pico is given to report the departure after wz's Close goes out.
/// The Close is a single best-effort datagram on an already-established group,
/// so this is generous rather than tight — but it is NOT a lease-length wait,
/// which is the point: a budget long enough to cover the lease would let the
/// lease-expiry arm satisfy a test that claims to witness the announced one.
const DEPART_BUDGET: Duration = Duration::from_secs(10);

/// The announced case advertises a lease THREE TIMES its own departure budget,
/// so pico's lease sweep cannot be what satisfies it. Without this gap the two
/// tests in this file would not be measuring different arms of pico at all.
const ANNOUNCED_LEASE_MS: u64 = 30_000;
/// The inferred case advertises a short lease because reaching the sweep is its
/// whole subject.
const INFERRED_LEASE_MS: u64 = 2_000;
/// Room for several sweep periods after the last beacon. pico expires on the
/// advertised lease elapsing with nothing received, and the sweep is periodic
/// rather than instant, so this is a multiple of the lease and not a guess at
/// one.
const LEASE_BUDGET: Duration = Duration::from_secs(20);

/// wz multicast self-advertisement pinned to zenoh-pico's own CONFIG constants
/// so pico admits the wz peer from its JOIN rather than rejecting it on
/// parameters. The zid is distinctive so a human reading a failure capture can
/// tell wz's transport from any other peer that happens to be on the group.
///
/// `lease_ms` is a PARAMETER because it is what separates the two cases in this
/// file. pico expires a multicast peer whose advertised lease elapses with
/// nothing received (`vendor/zenoh-pico/src/transport/multicast/lease.c` @
/// `_ZP_UNUSED(target);`'s enclosing `_zp_multicast_peer_is_expired`), so the
/// announced case advertises a lease far LONGER than its own budget — putting
/// the lease arm out of reach — while the inferred case advertises a short one
/// precisely to reach it.
fn wz_mc_params(zid: Vec<u8>, lease_ms: u64) -> MulticastParams {
    MulticastParams {
        version: PICO_PROTO_VERSION,
        whatami: WhatAmI::Peer,
        zid,
        lease_ms,
        join_interval_ms: 50,
        seq_num_res: PICO_SN_RESOLUTION,
        req_id_res: PICO_SN_RESOLUTION,
        batch_size: PICO_BATCH_MULTICAST_SIZE,
        is_qos: false,
    }
}

/// Pull the zid out of the FIRST `>> [Transport Event] <kind>:` block in a
/// z_info capture.
///
/// Returns the zid exactly as pico rendered it, which is deliberate: this test
/// never needs to know pico's formatting, only that the same peer identity
/// appears on both events.
fn transport_event_zid(captured: &str, kind: &str) -> Option<String> {
    for segment in captured.split(">> [Transport Event] ").skip(1) {
        if !segment.starts_with(kind) {
            continue;
        }
        let at = segment.find("zid=")? + "zid=".len();
        let rest = &segment[at..];
        let end = rest.find([',', '}'])?;
        let zid = rest[..end].trim();
        if !zid.is_empty() {
            return Some(zid.to_string());
        }
    }
    None
}

/// True when a `>> [Transport Event] <kind>:` block names `zid` AND says the
/// transport is multicast. The multicast assertion is not decoration: z_info
/// reports unicast transports through the same callback, so a test that only
/// matched the zid could be satisfied by a completely different link type.
fn has_multicast_event_for(captured: &str, kind: &str, zid: &str) -> bool {
    captured
        .split(">> [Transport Event] ")
        .skip(1)
        .filter(|segment| segment.starts_with(kind))
        .any(|segment| {
            let head = segment.split(">> [").next().unwrap_or(segment);
            head.contains(zid) && head.contains("is_multicast=true")
        })
}

// The claims below are deliberately NOT marked `partial`, and that is the
// round's point: every pre-existing proof line naming `session-multicast` carries
// the `partial` marker, which is how its reason could say "no foreign witness for
// the departure story" while seven proofs already named the atom. A foreign peer
// adjudicating the departure is the full claim.
// wz-proves: session-multicast wz->pico
// wz-proves: transport-multicast wz->pico
// wz-proves: codec-join wz->pico
// wz-proves: codec-close wz->pico
// wz-proves: transport-link-udp wz->pico
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep multicast e2e (zenoh-pico CLI z_info); Layer M runs via --ignored"]
async fn pico_witnesses_a_wz_multicast_departure() {
    let z_info = zenoh_pico_cli_binary("z_info");
    let iface = default_route_iface();
    let locator = format!("udp/{GROUP}:{PORT}#iface={iface}");

    // ── pico z_info (multicast peer + transport-events listener) ─────
    let capture = tempfile::tempfile().expect("tempfile for z_info capture");
    let out = capture.try_clone().expect("dup z_info stdout handle");
    let err = capture.try_clone().expect("dup z_info stderr handle");
    let mut reader = capture;

    let mut child = ChildGuard::wrap(
        "z_info multicast peer (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_info)
            .args(["-l", &locator, "-m", "peer"])
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("spawn z_info via stdbuf"),
    );

    // Gate 1: the listener is declared. Until this prints, a departure has
    // nobody watching for it and a green run would mean nothing.
    //
    // ⚠ This line only EXISTS when `Z_FEATURE_CONNECTIVITY` compiled in: the
    // whole block is `#if`-d out otherwise and z_info still exits 0. So this
    // wait is also the assertion that the oracle was built with the flag --
    // the failure mode it refuses is a green test against a stub binary.
    if let Err(captured) = wait_for_substring(
        &mut reader,
        "Declaring transport events listener",
        Z_SUB_INIT_TIMEOUT,
    ) {
        let _ = child.child_mut().kill();
        let _ = child.child_mut().wait();
        panic!(
            "z_info never declared its transport-events listener on {locator}. Either the \
             multicast bind/join failed, or this oracle was built WITHOUT \
             Z_FEATURE_CONNECTIVITY and the listener block is compiled out -- rebuild with \
             `bash scripts/build-zenoh-pico-cli.sh`.\n--- captured z_info ---\n{captured}"
        );
    }

    // ── wz multicast node, driven until we ask it to leave ───────────
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let drive = tokio::spawn(async move {
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .expect("bind ephemeral wz multicast socket");
        let mut driver = UdpDriver::from_socket(sock, SocketAddr::from((GROUP, PORT)));
        let mut dispatcher = MulticastDispatcher::<8>::new(MulticastConfig::new(30_000));
        let params = wz_mc_params(vec![0xD1, 0xD2, 0xD3, 0xD4], ANNOUNCED_LEASE_MS);
        let (_tx, mut outbound) = tokio::sync::mpsc::unbounded_channel();
        let clock = TokioTime::new();
        let mut shutdown = shutdown_rx;
        drive_multicast_session_with_shutdown(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &params,
                tick_ms: 10,
                max_iters: None,
            },
            &mut driver,
            &clock,
            |_| {},
            &mut outbound,
            &mut shutdown,
        )
        .await
    });

    // Gate 2: pico ADMITTED wz and said so. The zid it prints is the literal
    // this test carries forward -- no guess about pico's rendering.
    let deadline = Instant::now() + ADMIT_BUDGET;
    let zid = loop {
        let captured = read_captured(&mut reader);
        if let Some(zid) = transport_event_zid(&captured, "Opened") {
            break zid;
        }
        if let Ok(Some(status)) = child.child_mut().try_wait() {
            panic!(
                "z_info exited (status: {status}) before admitting wz on {locator}\n\
                 --- captured z_info ---\n{captured}"
            );
        }
        if Instant::now() >= deadline {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            panic!(
                "pico never raised a Transport Event for wz's JOIN on {locator} within \
                 {ADMIT_BUDGET:?} -- wz's JOIN was not admitted, so there is no admitted \
                 peer whose departure could be witnessed.\n--- captured z_info ---\n{captured}"
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    assert!(
        has_multicast_event_for(&read_captured(&mut reader), "Opened", &zid),
        "pico raised an Opened event for zid {zid} but not on a MULTICAST transport; this \
         test's subject is the multicast group face, not a unicast link"
    );

    // ── the departure: a GRACEFUL stop, which is what emits the Close ──
    shutdown_tx.send(true).expect("signal wz shutdown");
    let outcome = drive.await.expect("wz multicast drive task panicked");
    assert_eq!(
        outcome,
        wz_session_core::multicast_params::MulticastOutcome::Stopped,
        "the wz node must have left through its graceful-stop arm -- that arm is the one \
         that emits the multicast Close, and any other terminal means no Close was sent"
    );

    // Gate 3: pico ADJUDICATED the departure, naming the same peer.
    let deadline = Instant::now() + DEPART_BUDGET;
    let captured = loop {
        let captured = read_captured(&mut reader);
        if has_multicast_event_for(&captured, "Closed", &zid) {
            break captured;
        }
        if let Ok(Some(status)) = child.child_mut().try_wait() {
            panic!(
                "z_info exited (status: {status}) before reporting wz's departure\n\
                 --- captured z_info ---\n{captured}"
            );
        }
        if Instant::now() >= deadline {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            panic!(
                "pico never reported a Closed Transport Event for zid {zid} within \
                 {DEPART_BUDGET:?} after wz's graceful stop. wz sent its multicast Close \
                 and a foreign implementation did not act on it -- which is exactly the \
                 interop claim this test exists to grade.\n--- captured z_info ---\n{captured}"
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    let _ = child.child_mut().kill();
    let _ = child.child_mut().wait();

    // Localized assertions so a partial regression names itself rather than
    // collapsing into one opaque failure.
    assert!(
        captured.contains(">> [Transport Event] Closed:"),
        "missing the departure witness line.\n--- captured ---\n{captured}"
    );
    assert!(
        captured.contains(&zid),
        "the departure witness does not name wz's zid {zid}.\n--- captured ---\n{captured}"
    );
}

/// R2562 — the OTHER half of the departure story: pico INFERS wz's departure
/// from silence, rather than being told.
///
/// ## Why one test could not cover both
///
/// wz distinguishes the two causes deliberately — `MulticastPeerLostReason`
/// separates `Closed` (the peer SAYING it left) from `LeaseExpired` (this node
/// inferring it), and R311y784 records that an application which conflates them
/// "cannot tell a clean shutdown from a dead link". pico separates them the same
/// way, in two different files: the announced arm is its Close handler, and this
/// one is `vendor/zenoh-pico/src/transport/multicast/lease.c` @ `_Z_INFO("Deleting peer because it has expired after %zums", peer->_lease);`.
/// A single test that merely saw SOME departure would have left the atom's
/// residual — "no foreign witness for EITHER half" — half open while reading as
/// closed.
///
/// ## The discriminator is that NO CLOSE IS EVER SENT
///
/// The drive task is ABORTED rather than shut down. Abort cancels the future at
/// its next await point, so the graceful-stop arm never runs and no Close
/// datagram is produced; the socket is simply dropped, which puts nothing on the
/// wire. So a `Closed:` event here can only have come from pico's sweep. That is
/// also why this case advertises a SHORT lease while the announced case
/// advertises one three times its own budget: each test can only be satisfied by
/// the arm it names.
///
/// ⚠ The `Opened:` gate is retained for the same anti-vacuity reason as above --
/// a sweep that expired a peer pico never admitted would prove nothing.
// wz-proves: session-multicast wz->pico
// wz-proves: transport-multicast wz->pico
// wz-proves: codec-join wz->pico
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep multicast e2e (zenoh-pico CLI z_info); Layer M runs via --ignored"]
async fn pico_infers_a_wz_multicast_departure_from_silence() {
    let z_info = zenoh_pico_cli_binary("z_info");
    let iface = default_route_iface();
    let locator = format!("udp/{GROUP}:{LEASE_PORT}#iface={iface}");

    let capture = tempfile::tempfile().expect("tempfile for z_info capture");
    let out = capture.try_clone().expect("dup z_info stdout handle");
    let err = capture.try_clone().expect("dup z_info stderr handle");
    let mut reader = capture;

    let mut child = ChildGuard::wrap(
        "z_info multicast peer (zenoh-pico, lease arm)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_info)
            .args(["-l", &locator, "-m", "peer"])
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("spawn z_info via stdbuf"),
    );

    if let Err(captured) = wait_for_substring(
        &mut reader,
        "Declaring transport events listener",
        Z_SUB_INIT_TIMEOUT,
    ) {
        let _ = child.child_mut().kill();
        let _ = child.child_mut().wait();
        panic!(
            "z_info never declared its transport-events listener on {locator}; rebuild the \
             oracle with `bash scripts/build-zenoh-pico-cli.sh`.\n\
             --- captured z_info ---\n{captured}"
        );
    }

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let drive = tokio::spawn(async move {
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .expect("bind ephemeral wz multicast socket");
        let mut driver = UdpDriver::from_socket(sock, SocketAddr::from((GROUP, LEASE_PORT)));
        let mut dispatcher = MulticastDispatcher::<8>::new(MulticastConfig::new(30_000));
        let params = wz_mc_params(vec![0xE1, 0xE2, 0xE3, 0xE4], INFERRED_LEASE_MS);
        let (_tx, mut outbound) = tokio::sync::mpsc::unbounded_channel();
        let clock = TokioTime::new();
        let mut shutdown = shutdown_rx;
        drive_multicast_session_with_shutdown(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &params,
                tick_ms: 10,
                max_iters: None,
            },
            &mut driver,
            &clock,
            |_| {},
            &mut outbound,
            &mut shutdown,
        )
        .await
    });

    let deadline = Instant::now() + ADMIT_BUDGET;
    let zid = loop {
        let captured = read_captured(&mut reader);
        if let Some(zid) = transport_event_zid(&captured, "Opened") {
            break zid;
        }
        if let Ok(Some(status)) = child.child_mut().try_wait() {
            panic!(
                "z_info exited (status: {status}) before admitting wz on {locator}\n\
                 --- captured z_info ---\n{captured}"
            );
        }
        if Instant::now() >= deadline {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            panic!(
                "pico never admitted wz on {locator} within {ADMIT_BUDGET:?}; there is no \
                 admitted peer to expire.\n--- captured z_info ---\n{captured}"
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    // THE DEPARTURE: silence. Abort stops the beacons at the next await point
    // without running the graceful-stop arm, so no Close is ever encoded.
    drive.abort();

    let deadline = Instant::now() + LEASE_BUDGET;
    let captured = loop {
        let captured = read_captured(&mut reader);
        if has_multicast_event_for(&captured, "Closed", &zid) {
            break captured;
        }
        if let Ok(Some(status)) = child.child_mut().try_wait() {
            panic!(
                "z_info exited (status: {status}) before expiring wz\n\
                 --- captured z_info ---\n{captured}"
            );
        }
        if Instant::now() >= deadline {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            panic!(
                "pico never expired zid {zid} within {LEASE_BUDGET:?} of wz going silent, \
                 though wz advertised a {INFERRED_LEASE_MS}ms lease in its JOIN. Either the \
                 advertised lease is not the one pico applies, or the sweep did not run.\n\
                 --- captured z_info ---\n{captured}"
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    let _ = child.child_mut().kill();
    let _ = child.child_mut().wait();

    assert!(
        captured.contains(">> [Transport Event] Closed:"),
        "missing the expiry witness line.\n--- captured ---\n{captured}"
    );
    assert!(
        captured.contains(&zid),
        "the expiry witness does not name wz's zid {zid}.\n--- captured ---\n{captured}"
    );
}
