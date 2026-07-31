// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! Does a closing client send a session Close, or just a TCP FIN? MEASURED.
//!
//! R311y486's carry recorded that `wz-capi-pico`'s `z_close` emits no Close frame
//! "where pico sends a session Close". Only the first half was ever measured; the
//! second was inferred from `_z_unicast_send_close` existing in the vendored pico
//! tree. That inference is exactly the shape of claim this project keeps having to
//! retract, so this file measures all three teardowns on the wire. The question is
//! not "is wz missing a Close" but "which of these sends one".
//!
//! ## The instrument
//!
//! `spawn_counting_relay` — the harness's existing batch counter, not a new one —
//! sits between the client under test and one `wz-ap-demo --listen` acceptor and
//! counts DIALER -> ACCEPTOR batches whose FIRST message header carries
//! `T_MID_CLOSE`. Its scope is therefore a Close that opens a batch; a Close
//! trailing a Frame inside one batch would not be counted, and the assertions say
//! so rather than claiming a proof of absence they cannot make.
//!
//! ## Why one leg exists only to calibrate
//!
//! A detector reporting "no Close" is worthless until it has reported "Close" on a
//! stream that has one — otherwise a broken instrument and a missing frame are the
//! same output, and three tidy zeroes read as a finding. `wz-ap-demo`'s
//! signal-cancel teardown emits a Close by construction (the R284/R292 typestate
//! chain exists to order UndeclToken before it), so leg 1 is the positive control
//! and its failure aborts the measurement instead of publishing it.
//!
//! All three clients dial the SAME acceptor through the SAME relay type, so the
//! legs differ only in who is closing.
//!
//! ## What twenty runs measured, and what it retracted
//!
//! * `wz-ap-demo` on SIGTERM — 1 Close, 20/20. The control.
//! * real `zenoh-pico` `z_put` (whose `z_drop(z_move(s))` routes through
//!   `z_session_drop` -> `z_close`, so this IS its close path) — 1 Close in
//!   **3 of 20**, none in the other 17. Its teardown is NONDETERMINISTIC.
//! * `wz-capi-pico` `z_close` — 0 Closes, 20/20.
//!
//! So the R311y486 carry was WRONG: a bare TCP FIN is inside real pico's own
//! envelope, and wz-capi-pico's silence is fidelity rather than the gap that
//! carry named. The carry reached the opposite conclusion by reading
//! `_z_unicast_send_close` in the pico tree and assuming `z_close` reaches it —
//! it does not. The only caller is the lease task (`lease.c`, `_Z_CLOSE_EXPIRED`),
//! which is also why pico's occasional Close is an OPEN QUESTION here: a
//! sub-second process should not reach a lease expiry, so the 3/20 is measured
//! but unexplained.
//!
//! The equality gate this file was written to carry (`capi > 0 == pico > 0`) is
//! therefore NOT shipped — at 3/20 it would red about 15% of runs. See the
//! comment at the assertion for what is asserted instead.

use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, spawn_counting_relay, spawn_on_ephemeral_port, wait_for_substring,
    wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard, RelayFault,
};

use wz_codecs::wire_const::T_MID_CLOSE;

/// How long a foreign or child process gets to reach its own teardown.
const LEG_TIMEOUT: Duration = Duration::from_secs(20);

/// The measurement. One acceptor, one relay per client, three closers.
///
/// The three legs share one test because no single count is interpretable
/// alone: the capi's zero means nothing without the control proving the counter
/// can reach one, and the pico leg is what places that zero inside or outside
/// the foreign envelope. Split into three tests, the two that carry no assertion
/// could stop running and the survivor would still be green.
// wz-proves: none -- a MEASUREMENT, and its result was a RETRACTION rather than
// a witness. It establishes that a bare TCP FIN at close is inside real pico's
// own envelope (pico emitted a Close in 3 of 20 runs), which removes a claimed
// gap instead of proving an atom. The pico round trip it rides on is already
// witnessed by ap_demo_round_trip.rs; claiming it again here would double-count
// the same exchange under a second atom.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenoh-pico CLI); measurement lane"]
fn who_sends_a_session_close_at_teardown() {
    let demo = wz_ap_demo_binary();

    // --- leg 1: wz-ap-demo dialer, SIGTERM. The positive control. ------------
    let (_acc1, _acc1_reader, upstream) = spawn_acceptor(&demo);
    let relay = spawn_counting_relay(upstream, T_MID_CLOSE, RelayFault::None);
    let mut stderr = tempfile::tempfile().expect("tempfile for dialer stderr");
    let mut reader = stderr.try_clone().expect("clone dialer stderr reader");
    let dialer = Command::new(&demo)
        .args([
            "--connect",
            &format!("tcp/127.0.0.1:{}", relay.port()),
            "--key",
            "demo/**",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr.try_clone().expect("dup dialer stderr")))
        .spawn()
        .expect("spawn wz-ap-demo --connect");
    let mut dialer = ChildGuard::wrap("wz-ap-demo (--connect through the relay)", dialer);

    // Terminate only once the session is UP: a demo killed mid-handshake has no
    // session to close, and its silence would be mistaken for the property.
    let established = wait_for_substring(&mut reader, "session Established", LEG_TIMEOUT);
    assert!(
        established.is_ok(),
        "the wz-ap-demo dialer never reported an established session through the \
         relay, so leg 1 never reached a teardown to measure\n--- stderr ---\n{}",
        wz_integration_tests::common::read_captured(&mut stderr)
    );
    graceful_terminate(dialer.child_mut(), Duration::from_secs(5));
    let demo_closes = relay.dialer_to_acceptor_count();
    println!("CLOSE-FRAME MEASUREMENT [wz-ap-demo --connect, SIGTERM]: {demo_closes}");

    assert!(
        demo_closes > 0,
        "THE INSTRUMENT IS NOT CALIBRATED. wz-ap-demo's signal-cancel teardown \
         emits a Close by construction, so counting zero here means the relay, \
         the mid, or the kill path is wrong — not that the demo is silent. Every \
         other leg's zero is unreadable until this one is positive."
    );

    // --- leg 2: real zenoh-pico z_put, ordinary exit. The foreign oracle. ----
    let (_acc2, mut acc2_reader, upstream) = spawn_acceptor(&demo);
    let relay = spawn_counting_relay(upstream, T_MID_CLOSE, RelayFault::None);
    let z_put = zenoh_pico_cli_binary("z_put");
    let status = Command::new(&z_put)
        .args([
            "-k",
            "demo/closeframe",
            "-v",
            "measuring-pico-teardown",
            "-e",
            &format!("tcp/127.0.0.1:{}", relay.port()),
            "-m",
            "client",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn zenoh-pico z_put");
    assert!(
        status.success(),
        "the real zenoh-pico z_put exited {status:?} through the relay, so leg 2 \
         never reached a teardown to measure"
    );
    require_delivery(&mut acc2_reader, "leg 2 (zenoh-pico z_put)");
    // The count is read after the child has exited, so its FIN has already been
    // pumped and no batch is still in flight.
    std::thread::sleep(Duration::from_millis(300));
    let pico_closes = relay.dialer_to_acceptor_count();
    println!("CLOSE-FRAME MEASUREMENT [zenoh-pico z_put, normal exit]: {pico_closes}");

    // --- leg 3: wz-capi-pico z_close. The subject. ---------------------------
    let (_acc3, mut acc3_reader, upstream) = spawn_acceptor(&demo);
    let relay = spawn_counting_relay(upstream, T_MID_CLOSE, RelayFault::None);
    capi_put_then_close(relay.port());
    require_delivery(&mut acc3_reader, "leg 3 (wz-capi-pico z_close)");
    std::thread::sleep(Duration::from_millis(300));
    let capi_closes = relay.dialer_to_acceptor_count();
    println!("CLOSE-FRAME MEASUREMENT [wz-capi-pico z_close]: {capi_closes}");

    // PICO IS DELIBERATELY NOT ASSERTED ON, and the reason is the measurement.
    //
    // The obvious gate here is `capi_closes > 0 == pico_closes > 0`. It was
    // written, and then twenty runs said it would be flaky: real zenoh-pico
    // emitted a Close in 3 of 20 teardowns of this exact program and none in the
    // other 17. Its teardown is NONDETERMINISTIC, so it cannot serve as an
    // equality oracle, and anyone who later "fixes" this by asserting
    // `pico_closes == 0` is re-introducing a 15%-red lane. Why pico sometimes
    // speaks is unmeasured; the only Close emitter reachable in its tree is the
    // lease task's `_Z_CLOSE_EXPIRED`, which a sub-second process should not
    // reach, so the cause is an open question rather than a known one.
    //
    // What the 20 runs DO establish is the fact this file exists to record: a
    // bare TCP FIN at `z_close` is inside real pico's own behaviour envelope,
    // not outside it. The R311y486 carry that called wz-capi-pico's silence a
    // fidelity gap was wrong, and it was wrong because it read
    // `_z_unicast_send_close` in the pico tree without checking that `z_close`
    // reaches it -- it does not; only the lease task does.
    println!(
        "CLOSE-FRAME MEASUREMENT [summary]: demo(control)={demo_closes} \
         pico={pico_closes} (nondeterministic, measured 3/20) capi={capi_closes}"
    );

    // The one stable, non-vacuous assertion: wz-capi-pico never emits a Close,
    // measured 0 of 20. This PINS current behaviour rather than blessing it --
    // emitting one would also be inside pico's envelope. If a later round makes
    // the C ABI emit a Close, this red is the prompt to update the line and say
    // why, which is the point of pinning it.
    assert_eq!(
        capi_closes, 0,
        "wz-capi-pico now emits {capi_closes} Close-opening batch(es) at z_close \
         where it previously emitted none. That is not necessarily wrong -- real \
         pico does it sometimes too -- but it is a deliberate wire change and \
         this line is where it gets acknowledged."
    );
}

/// A FRESH acceptor per leg, and that is not tidiness.
///
/// `wz-ap-demo --listen` is a single-session app: it terminates when its one peer
/// closes. Leg 1's Close therefore kills it, and every later leg would find the
/// upstream port refusing connections — measuring nothing while looking like a
/// wz defect. That failure mode was observed before this helper existed. It also
/// keeps the legs independent, so one leg's teardown cannot colour the next's.
fn spawn_acceptor(demo: &std::path::Path) -> (impl Drop, std::fs::File, u16) {
    let stderr = tempfile::tempfile().expect("tempfile for acceptor stderr");
    let (guard, reader, port) = spawn_on_ephemeral_port(
        demo,
        &["--listen", "127.0.0.1:0", "--key", "demo/**"],
        "listening on 127.0.0.1:",
        "wz-ap-demo (--listen, close-frame measurement acceptor)",
        stderr,
    );
    (guard, reader, port)
}

/// A leg that counted ZERO Closes has to prove it counted zero of something.
///
/// Nothing else in the leg distinguishes "this client sends no Close" from "this
/// client never got a session up", and those are the same number. The acceptor
/// logging SUBSCRIBER FIRED for the leg own put settles it: the handshake
/// completed, a sample crossed, and the teardown that followed was a real one.
fn require_delivery(reader: &mut std::fs::File, leg: &str) {
    assert!(
        wait_for_substring(reader, "SUBSCRIBER FIRED", LEG_TIMEOUT).is_ok(),
        "{leg}: the acceptor never logged SUBSCRIBER FIRED, so this leg never \
         established a session and delivered - its Close count of zero measures \
         nothing"
    );
}

/// Leg 3's client: the exported C ABI opens through the relay, publishes, and
/// closes — the same publish-then-close program `teardown_drain.rs` gates.
///
/// Driven on its own thread so a wedged `z_open` / `z_close` surfaces as this
/// function's timeout with a named cause, rather than hanging the whole lane.
fn capi_put_then_close(relay_port: u16) {
    use wz_capi_pico::{
        z_bytes_copy_from_buf, z_close, z_config_default, z_config_loan_mut, z_config_move, z_open,
        z_owned_config_t, z_owned_session_t, z_put, z_session_drop, z_session_loan,
        z_session_loan_mut, z_session_move, z_view_keyexpr_from_str, z_view_keyexpr_loan,
        z_view_keyexpr_t, zp_config_insert, Z_CONFIG_CONNECT_KEY, Z_OK,
    };

    let connect = std::ffi::CString::new(format!("tcp/127.0.0.1:{relay_port}")).unwrap();
    let (tx, rx) = mpsc::channel::<()>();
    std::thread::spawn(move || unsafe {
        let mut session: z_owned_session_t = std::mem::zeroed();
        let mut opened = false;
        for _ in 0..250 {
            let mut cfg: z_owned_config_t = std::mem::zeroed();
            assert_eq!(z_config_default(&mut cfg), Z_OK);
            assert_eq!(
                zp_config_insert(
                    z_config_loan_mut(&mut cfg),
                    Z_CONFIG_CONNECT_KEY,
                    connect.as_ptr()
                ),
                Z_OK
            );
            if z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()) == Z_OK {
                opened = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            opened,
            "wz-capi-pico z_open never succeeded through the relay"
        );

        let payload = b"measuring-capi-teardown";
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut ke, c"demo/closeframe".as_ptr()),
            Z_OK
        );
        let mut bytes = std::mem::zeroed();
        assert_eq!(
            z_bytes_copy_from_buf(&mut bytes, payload.as_ptr(), payload.len()),
            Z_OK
        );
        assert_eq!(
            z_put(
                z_session_loan(&session),
                z_view_keyexpr_loan(&ke),
                wz_capi_pico::z_bytes_move(&mut bytes),
                std::ptr::null(),
            ),
            Z_OK
        );

        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
        let _ = tx.send(());
    });
    rx.recv_timeout(LEG_TIMEOUT + Duration::from_secs(10))
        .expect("wz-capi-pico leg did not finish its open/put/close in time");
}
