// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2576 (§5.4 `session-matching`) — a FOREIGN peer that VANISHES is purged
//! from wz's matching aggregate.
//!
//! ## The residual, and why the neighbouring legs do not cover it
//!
//! The atom carries "the link-loss purge is witnessed only wz-to-wz over
//! loopback, so no foreign implementation adjudicates the transition". Two legs
//! look like they already do and do not:
//!
//! * `wz_matching_status_driven_by_pico_zsub.rs` lowers the status by a CLEAN
//!   RETRACTION — its `z_sub -n 1` breaks its loop after one message and reaches
//!   `z_drop`, so an `UndeclSubscriber` goes out and wz lowers the verdict by
//!   READING it. The code under test there is the retraction path, not the purge.
//! * `a_vanishing_peer_is_purged_from_the_matching_aggregate`
//!   (`wz-capi-pico/tests/matching_multiface.rs`) does exercise the purge, but
//!   its vanishing peer is a wz NATIVE THREAD and the far side is wz's own capi.
//!   Both ends are this implementation — exactly what the residual names.
//!
//! This leg is the missing corner: wz's capi holds the publisher, the peer is
//! pico's real `z_sub`, and it is KILLED rather than asked to leave.
//!
//! ## Why the kill is a sound way to produce the transition
//!
//! `z_sub` parses `-n` into a count and loops
//! `while (1) { if ((n != 0) && (msg_nb >= n)) break; sleep(1); }` with `n`
//! defaulting to 0, so WITHOUT `-n` it never leaves that loop and never reaches
//! the `z_drop` below it. SIGKILL cannot be caught, so no retraction can be sent
//! by any path. What wz observes is the socket closing with the subscriber
//! declaration still standing, which is what the purge exists for.
//!
//! The two pico legs therefore differ in ONE argument while the `false` edge has
//! a DIFFERENT CAUSE in each — retraction there, purge here. That is what makes
//! this a discriminator rather than a second copy.
//!
//! ## Why the harness is wz's capi rather than the demo
//!
//! MEASURED, after a first attempt against `wz-ap-demo --listen` failed: that
//! mode is a SINGLE-SESSION acceptor and logs `session ended: Terminated` the
//! moment the peer dies, so nothing survives to observe a purge and the leg
//! would have redded under every implementation. A witness whose harness cannot
//! see the claim is indistinguishable from the defect it pretends to find. The
//! capi listener holds its faces independently of any one peer, which is why the
//! wz-to-wz purge witness lives there and why this one does too.
//!
//! This file lives in `wz-integration-tests` because that crate ALREADY depends
//! on `wz-capi-pico` (rlib) and owns `zenoh_pico_cli_binary`, whose provenance
//! check refuses an oracle built from a different `vendor/zenoh-pico` state
//! (R2326: existence was the wrong question). Putting it beside the other capi
//! harness would have needed either a dev-dep CYCLE or a copy of that check.

use std::ffi::{c_void, CStr, CString};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_pico::matching::{
    z_closure_matching_status, z_closure_matching_status_move, z_matching_status_t,
    z_owned_closure_matching_status_t, z_owned_matching_listener_t,
    z_publisher_declare_matching_listener, z_publisher_get_matching_status,
};
use wz_capi_pico::{
    z_config_default, z_config_loan_mut, z_config_move, z_declare_publisher, z_open,
    z_owned_config_t, z_owned_publisher_t, z_owned_session_t, z_publisher_loan,
    z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert,
    Z_CONFIG_LISTEN_KEY, Z_OK,
};
use wz_integration_tests::common::{zenoh_pico_cli_binary, ChildGuard, PortReservation};

/// Ceiling for each edge. The purge edge is the slower one: wz has to notice the
/// closed socket, run the face-down path, and drain the deferred fire.
const BARRIER: Duration = Duration::from_secs(20);

struct VerdictLog {
    seen: Arc<Mutex<Vec<bool>>>,
    dropped: Arc<AtomicUsize>,
}

unsafe extern "C" fn on_matching(status: *const z_matching_status_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const VerdictLog);
    ctx.seen.lock().unwrap().push((*status).matching);
}

unsafe extern "C" fn on_matching_drop(ctx: *mut c_void) {
    let ctx = Box::from_raw(ctx as *mut VerdictLog);
    ctx.dropped.fetch_add(1, Ordering::SeqCst);
}

unsafe fn open_listen(port: u16) -> z_owned_session_t {
    let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(
            z_config_loan_mut(&mut cfg),
            Z_CONFIG_LISTEN_KEY,
            endpoint.as_ptr()
        ),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK,
        "listener z_open failed"
    );
    session
}

unsafe fn declare_publisher(session: &z_owned_session_t, keyexpr: &CStr) -> z_owned_publisher_t {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, keyexpr.as_ptr()), Z_OK);
    let mut pubr: z_owned_publisher_t = std::mem::zeroed();
    assert_eq!(
        z_declare_publisher(
            wz_capi_pico::z_session_loan(session),
            &mut pubr,
            z_view_keyexpr_loan(&ke),
            std::ptr::null(),
        ),
        Z_OK
    );
    pubr
}

unsafe fn declare_matching(
    pubr: &z_owned_publisher_t,
    seen: Arc<Mutex<Vec<bool>>>,
    dropped: Arc<AtomicUsize>,
) -> z_owned_matching_listener_t {
    let ctx = Box::into_raw(Box::new(VerdictLog { seen, dropped })) as *mut c_void;
    let mut closure: z_owned_closure_matching_status_t = std::mem::zeroed();
    assert_eq!(
        z_closure_matching_status(&mut closure, Some(on_matching), Some(on_matching_drop), ctx),
        Z_OK
    );
    let mut listener: z_owned_matching_listener_t = std::mem::zeroed();
    assert_eq!(
        z_publisher_declare_matching_listener(
            z_publisher_loan(pubr),
            &mut listener,
            z_closure_matching_status_move(&mut closure),
        ),
        Z_OK
    );
    listener
}

/// The LIVE verdict, recomputed from the connected faces rather than read off
/// the aggregate's cache — so "it reads false now" means the face is genuinely
/// gone, which is what turns a missing `false` into a defect rather than a race.
unsafe fn matching_now(pubr: &z_owned_publisher_t) -> bool {
    let mut status = z_matching_status_t { matching: false };
    assert_eq!(
        z_publisher_get_matching_status(z_publisher_loan(pubr), &mut status),
        Z_OK
    );
    status.matching
}

unsafe fn await_live_verdict(pubr: &z_owned_publisher_t, want: bool, what: &str) {
    let deadline = Instant::now() + BARRIER;
    while Instant::now() < deadline {
        if matching_now(pubr) == want {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("live matching verdict never reached {want} ({what})");
}

fn await_log(seen: &Arc<Mutex<Vec<bool>>>, want: &[bool], what: &str) {
    let deadline = Instant::now() + BARRIER;
    while Instant::now() < deadline {
        if *seen.lock().unwrap() == want {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!(
        "matching verdicts were {:?}, expected {want:?} ({what})",
        seen.lock().unwrap()
    );
}

fn spawn_resident_zsub(z_sub: &std::path::Path, endpoint: &str, label: &'static str) -> ChildGuard {
    ChildGuard::wrap(
        label,
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(z_sub)
            // No `-n`: z_sub never leaves `while (1)` and so never reaches its
            // own `z_drop`. Only a kill can stop it subscribing.
            .args(["-k", "demo/**", "-e", endpoint, "-m", "client"])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_sub via stdbuf"),
    )
}

// `partial`: this closes ONE of the atom's four witness gaps -- the link-loss
// purge -- and says nothing about the other three.
// wz-proves: session-matching pico->wz partial
#[test]
#[ignore = "binary-dep e2e (zenoh-pico CLI); Layer E runs via --ignored"]
fn a_vanished_pico_subscriber_is_purged_from_wz_matching_status() {
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");

    let seen = Arc::new(Mutex::new(Vec::new()));
    let dropped = Arc::new(AtomicUsize::new(0));

    unsafe {
        let listener = open_listen(port);
        let pubr = declare_publisher(&listener, c"demo/matching");
        let _mlistener = declare_matching(&pubr, seen.clone(), dropped.clone());

        drop(port_res);

        // ── A REAL pico subscriber raises the verdict. wz has no local
        //    subscriber here, so pico's DeclSubscriber is the only thing that
        //    could have raised it.
        let mut vanishing = spawn_resident_zsub(&z_sub, &endpoint, "z_sub (will be killed)");
        await_live_verdict(&pubr, true, "pico's z_sub declared a matching subscriber");
        await_log(
            &seen,
            &[true],
            "the matching listener delivers true for pico",
        );

        // ── THE VANISH. SIGKILL, so no UndeclSubscriber exists on this wire.
        vanishing.child_mut().kill().expect("SIGKILL the z_sub");
        let _ = vanishing.child_mut().wait();

        await_live_verdict(
            &pubr,
            false,
            "a KILLED pico subscriber was never purged: no UndeclSubscriber was \
             sent, so only the link-loss purge could lower this verdict",
        );
        await_log(
            &seen,
            &[true, false],
            "the purge never reached the matching listener -- a publisher still \
             believing it has subscribers keeps serialising samples nobody reads",
        );

        // ── The aggregate is EMPTY, not merely forced false once: a SECOND
        //    foreign subscriber must raise it again. Without this arm a build
        //    that emitted one false on link-down and then latched would pass.
        let mut revived = spawn_resident_zsub(&z_sub, &endpoint, "z_sub (after the vanish)");
        await_live_verdict(&pubr, true, "a fresh pico subscriber after the purge");
        await_log(
            &seen,
            &[true, false, true],
            "the aggregate latched instead of purging: the face was reported \
             false but never removed, so every later match is suppressed",
        );

        let _ = revived.child_mut().kill();
        let _ = revived.child_mut().wait();
        drop(listener);
    }
}
