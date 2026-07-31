// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! Teardown-drain gate for §5.27 api-compat-pico — the SIXTH fixture.
//!
//! R311y484 built five fixtures for this defect and none of them measured it.
//! Read that entry's verification bullets before touching this file: load could
//! not summon it, a 64 KB pico put was refuted by the pico CLI's own
//! `Z_FRAG_MAX_SIZE` of 4096, a 3900-byte one had too few writes to lose, a bare
//! stalling TCP peer could not answer the handshake, and a recording relay
//! passed 3/3 without the fix. The reason all five failed was one missing lever:
//! `wz-capi-pico` composed no `transport-fragmentation`, so no `z_put` could
//! queue more bytes than a single 65535-byte batch, and a single batch is small
//! enough that the writer task always got it out before teardown.
//!
//! R311y485 removed that blocker — the C ABI now fragments and delivers up to
//! the 1 MiB reassembly cap. So this fixture uses the lever the first five
//! lacked: queue a chain far larger than the writer can hand to the kernel in
//! the microseconds between `z_close` latching `stop` and the per-session
//! runtime being dropped, and then require it to arrive anyway.
//!
//! What it binds to: `drive_dial` ended with `drop(writer_handle)`, which only
//! DETACHES the writer task. The `rt` that owns that task is dropped on the very
//! next line (`open_blocking`'s driver thread), which ABORTS it wherever it
//! stands — including with encoded frames still sitting in its channel. The
//! library already owns the correct terminal sequence for this
//! (`OpenedSession::drain_to_close`: drop the two `Arc<SessionLinkActions>`
//! holders so the channel closes, then await the task bounded by
//! `WRITER_DRAIN_MS`); the dial role simply did not run it.
//!
//! Both peers are the exported C ABI, so this is the drop-in program's own view:
//! a pico C program that publishes and then closes.
//!
//! Why that program is entitled to expect delivery, stated precisely, because
//! the obvious version of it is wrong: real pico's `z_close` does NOT flush the
//! transport. `_z_session_close` (`vendor/zenoh-pico/src/session/utils.c:167`)
//! stops the runtime and frees the resource / subscription / queryable /
//! pending-query registries, and moves no outbound byte. It has nothing to
//! flush — pico's `z_put` writes on the CALLING thread the whole way down
//! (`_z_write` -> `_z_send_n_msg` -> `_z_transport_tx_send_n_msg`), so by the
//! time it returns the bytes are the kernel's. wz-capi-pico's `z_put` instead
//! hands the encoded frames to an async writer task, which is a queue pico does
//! not have and so a teardown obligation pico does not have. The drain is what
//! makes the two `z_put`s mean the same thing to the C caller.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_runtime_tokio::session_open::WRITER_DRAIN_MS;

use wz_capi_pico::{
    z_bytes_copy_from_buf, z_bytes_to_slice, z_close, z_closure_sample, z_config_default,
    z_config_loan_mut, z_config_move, z_declare_subscriber, z_loaned_bytes_t, z_loaned_sample_t,
    z_open, z_owned_config_t, z_owned_session_t, z_owned_slice_t, z_owned_subscriber_t, z_put,
    z_sample_payload, z_session_drop, z_session_loan, z_session_loan_mut, z_session_move,
    z_slice_data, z_slice_drop, z_slice_len, z_slice_loan, z_slice_move, z_undeclare_subscriber,
    z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert,
    Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_OK,
};

/// The payload published immediately before `z_close`.
///
/// It is sized by what has to be TRUE of it, not by taste. It must exceed one
/// negotiated 65535-byte batch by enough fragments that the writer task cannot
/// possibly have handed them all to the kernel in the time `z_close` takes to
/// latch `stop`, wake the drive future, and drop the runtime — that is what
/// makes the un-drained loss deterministic rather than a race this fixture only
/// sometimes wins. And it must stay under the 1 MiB AP reassembly cap
/// (R311y485), or the sender would refuse it locally and the test would be
/// measuring the refusal instead of the drain. 786432 = 12 batches, three
/// quarters of the cap.
const TAIL_BYTES: usize = 768 * 1024;

/// How many tail puts are queued back-to-back before the close.
const TAIL_COUNT: usize = 8;

fn tail_size(i: usize) -> usize {
    TAIL_BYTES + i * 1024
}

/// The put whose delivery makes the acceptor stop reading.
///
/// This is the lever the first five fixtures lacked a way to pull. A subscriber
/// closure runs on the acceptor's drive task — the same task that polls the
/// link's read half — so a closure that sleeps stops the peer reading, its
/// receive buffer fills, the dialer's send buffer fills behind it, and the
/// writer task blocks with frames still in its channel. That is the state
/// `z_close` has to survive, and nothing smaller than a socket-buffer's worth of
/// payload can produce it.
///
/// A slow subscriber callback is also just what a pico C program does, so this
/// is not a synthetic condition — it is the ordinary one.
const STALL_TRIGGER_BYTES: usize = 8192;

/// How long that closure sleeps.
///
/// Bounded BELOW `WRITER_DRAIN_MS` (50) on purpose. R311y484's fifth fixture
/// stalled for 400 ms and so demanded what no bounded best-effort drain can
/// deliver; a stall the drain window can outlast is the difference between
/// testing the drain and testing the timeout.
const STALL_MS: u64 = 25;

/// The calibration payload, published and confirmed BEFORE the tail.
///
/// It owns this fixture's precondition: it proves the subscriber declaration has
/// propagated and the publish path reaches the acceptor's closure, so a red on
/// the tail is the teardown drain and not an un-propagated subscription. Three
/// of R311y484's five fixtures were refuted by a fixture defect rather than by
/// wz; this leg is what keeps a sixth from joining them.
const CALIBRATION_BYTES: usize = 4096;

/// Deterministic, size-dependent filler: a truncated delivery cannot masquerade
/// as a whole one because the trailing bytes are position-dependent.
fn payload_of(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

type Delivered = Arc<Mutex<HashMap<usize, Vec<u8>>>>;

struct Ctx {
    delivered: Delivered,
}

unsafe extern "C" fn on_sample(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const Ctx);

    let payload: *const z_loaned_bytes_t = z_sample_payload(sample);
    let mut slice: z_owned_slice_t = std::mem::zeroed();
    if z_bytes_to_slice(payload, &mut slice) == Z_OK {
        let loaned = z_slice_loan(&slice);
        let data = z_slice_data(loaned);
        let len = z_slice_len(loaned);
        if !data.is_null() {
            let bytes = std::slice::from_raw_parts(data, len).to_vec();
            ctx.delivered.lock().unwrap().insert(len, bytes);
        }
        z_slice_drop(z_slice_move(&mut slice));

        // RECORD FIRST, THEN SLEEP. The publisher polls for this length to
        // learn that the stall has begun, so sleeping before the insert above
        // would hand it a window that had already closed.
        if len == STALL_TRIGGER_BYTES {
            std::thread::sleep(Duration::from_millis(STALL_MS));
        }
    }
}

unsafe extern "C" fn on_drop(ctx: *mut c_void) {
    drop(Box::from_raw(ctx as *const Ctx as *mut Ctx));
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A `z_put` that `z_close` follows immediately must still reach the peer.
///
/// This is the observable a pico C program has: pico's `z_close` runs
/// `_z_session_close`, which flushes the transport before the session dies, so a
/// program that publishes and closes on the next line does not lose the publish.
/// wz-capi-pico's dial role detached its writer instead, and the runtime drop
/// that follows aborted it — every frame still queued was discarded with no
/// error anywhere, because `z_put` had already returned `Z_OK`.
#[test]
fn a_put_immediately_before_z_close_is_drained_not_discarded() {
    let port = free_port();
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let connect = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();

    let delivered: Delivered = Arc::new(Mutex::new(HashMap::new()));
    let delivered_acc = delivered.clone();
    let sub_ready = Arc::new(AtomicBool::new(false));
    let sub_ready_acc = sub_ready.clone();
    let done = Arc::new(AtomicBool::new(false));
    let done_acc = done.clone();

    let (started_tx, started_rx) = mpsc::channel::<()>();
    let acceptor = std::thread::spawn(move || unsafe {
        let mut cfg: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut cfg), Z_OK);
        assert_eq!(
            zp_config_insert(
                z_config_loan_mut(&mut cfg),
                Z_CONFIG_LISTEN_KEY,
                listen.as_ptr()
            ),
            Z_OK
        );
        let _ = started_tx.send(());
        let mut session: z_owned_session_t = std::mem::zeroed();
        assert_eq!(
            z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
            Z_OK,
            "acceptor z_open failed"
        );

        let ctx = Box::into_raw(Box::new(Ctx {
            delivered: delivered_acc,
        })) as *mut c_void;
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_sample(&mut closure, Some(on_sample), Some(on_drop), ctx),
            Z_OK
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut ke, c"teardown/**".as_ptr()),
            Z_OK
        );
        let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&session),
                &mut subscriber,
                z_view_keyexpr_loan(&ke),
                wz_capi_pico::z_closure_sample_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK,
            "acceptor z_declare_subscriber failed"
        );
        sub_ready_acc.store(true, Ordering::SeqCst);

        // The acceptor outlives the dialer on purpose: the whole question is
        // what the peer sees AFTER the publisher has closed, so it must still
        // be reading when the dialer's session is already gone.
        for _ in 0..3000 {
            if done_acc.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        z_undeclare_subscriber(wz_capi_pico::z_subscriber_move(&mut subscriber));
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
    });

    started_rx.recv().unwrap();

    let mut session: z_owned_session_t = unsafe { std::mem::zeroed() };
    let mut opened = false;
    for _ in 0..250 {
        unsafe {
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
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(opened, "dialer z_open never succeeded");

    for _ in 0..500 {
        if sub_ready.load(Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        sub_ready.load(Ordering::SeqCst),
        "acceptor never declared its subscriber"
    );

    // --- calibration: the fixture proves its own precondition ---------------
    //
    // Retried, because the subscription may still be propagating. Once THIS
    // arrives, the publish path is known good and the session is known live, so
    // the single-shot tail below has no excuse but the drain.
    let calibration = payload_of(CALIBRATION_BYTES);
    let mut calibrated = false;
    for _ in 0..150 {
        if delivered.lock().unwrap().contains_key(&CALIBRATION_BYTES) {
            calibrated = true;
            break;
        }
        unsafe {
            let mut ke: z_view_keyexpr_t = std::mem::zeroed();
            assert_eq!(
                z_view_keyexpr_from_str(&mut ke, c"teardown/calibration".as_ptr()),
                Z_OK
            );
            let mut bytes = std::mem::zeroed();
            assert_eq!(
                z_bytes_copy_from_buf(&mut bytes, calibration.as_ptr(), calibration.len()),
                Z_OK
            );
            assert_eq!(
                z_put(
                    z_session_loan(&session),
                    z_view_keyexpr_loan(&ke),
                    wz_capi_pico::z_bytes_move(&mut bytes),
                    std::ptr::null(),
                ),
                Z_OK,
                "calibration z_put returned an error"
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        calibrated,
        "the calibration put never arrived — the fixture's own publish path is \
         broken, so nothing below measures the teardown drain"
    );

    // --- the gate: publish once, close on the next line ---------------------
    //
    // SINGLE SHOT. A retry loop here would defeat the fixture: the property is
    // that the ONE put issued before `z_close` survives the close, and a second
    // attempt cannot be made once the session is closed anyway.
    // --- arm the stall ------------------------------------------------------
    //
    // Every buffer below is precomputed, because the whole publish-and-close
    // sequence has to fit inside the acceptor's STALL_MS sleep.
    let tails: Vec<Vec<u8>> = (0..TAIL_COUNT).map(|i| payload_of(tail_size(i))).collect();
    let trigger = payload_of(STALL_TRIGGER_BYTES);
    let mut stalled = false;
    for _ in 0..300 {
        if delivered.lock().unwrap().contains_key(&STALL_TRIGGER_BYTES) {
            stalled = true;
            break;
        }
        unsafe {
            let mut ke: z_view_keyexpr_t = std::mem::zeroed();
            assert_eq!(
                z_view_keyexpr_from_str(&mut ke, c"teardown/stall".as_ptr()),
                Z_OK
            );
            let mut bytes = std::mem::zeroed();
            assert_eq!(
                z_bytes_copy_from_buf(&mut bytes, trigger.as_ptr(), trigger.len()),
                Z_OK
            );
            assert_eq!(
                z_put(
                    z_session_loan(&session),
                    z_view_keyexpr_loan(&ke),
                    wz_capi_pico::z_bytes_move(&mut bytes),
                    std::ptr::null(),
                ),
                Z_OK,
                "the stall-trigger z_put returned an error"
            );
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        stalled,
        "the acceptor never reported the stall trigger, so it is still reading \
         and the tails below would drain with no back pressure — the fixture \
         would pass without measuring anything"
    );

    for (i, tail) in tails.iter().enumerate() {
        let ke_str = std::ffi::CString::new(format!("teardown/tail/{i}")).unwrap();
        let rc = unsafe {
            let mut ke: z_view_keyexpr_t = std::mem::zeroed();
            assert_eq!(z_view_keyexpr_from_str(&mut ke, ke_str.as_ptr()), Z_OK);
            let mut bytes = std::mem::zeroed();
            assert_eq!(
                z_bytes_copy_from_buf(&mut bytes, tail.as_ptr(), tail.len()),
                Z_OK
            );
            z_put(
                z_session_loan(&session),
                z_view_keyexpr_loan(&ke),
                wz_capi_pico::z_bytes_move(&mut bytes),
                std::ptr::null(),
            )
        };
        assert_eq!(
            rc, Z_OK,
            "tail z_put {i} was rejected before the close, so the close is untested"
        );
    }

    // No sleep, no flush, no politeness: this is the C program that publishes
    // and closes.
    unsafe {
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
    }

    // The close has returned, so the drain (if any) has already run to
    // completion — `z_close` joins the driver thread. What remains is only the
    // acceptor's own read + reassembly of bytes already on the wire.
    // ONE bounded wait for the whole set, not one per size: `z_close` has
    // already returned, so no further byte can leave this host and a per-size
    // timeout would only multiply the same expired deadline.
    let mut missing: Vec<usize> = Vec::new();
    for _ in 0..150 {
        let map = delivered.lock().unwrap();
        missing = (0..TAIL_COUNT)
            .map(tail_size)
            .filter(|size| !map.contains_key(size))
            .collect();
        drop(map);
        if missing.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    done.store(true, Ordering::SeqCst);
    acceptor.join().expect("acceptor thread panicked");

    assert!(
        missing.is_empty(),
        "z_put returned Z_OK and then z_close discarded these payloads: \
         {missing:?}. The peer received the {CALIBRATION_BYTES}-byte \
         calibration but not every tail (delivered: {:?}). The dial role \
         detaches its writer task instead of draining it, and the per-session \
         runtime drop that follows aborts it with frames still queued.",
        {
            let mut k: Vec<usize> = delivered.lock().unwrap().keys().copied().collect();
            k.sort_unstable();
            k
        }
    );

    // Arrival is not enough: an aborted writer can also leave a PREFIX of a
    // chain on the wire, and a fixture that only counted samples would call a
    // truncated reassembly a pass.
    let map = delivered.lock().unwrap();
    for (i, tail) in tails.iter().enumerate() {
        let size = tail_size(i);
        let actual = map.get(&size).expect("checked above");
        assert!(
            actual == tail,
            "tail {i} arrived with {} bytes but they differ from what was \
             published — the drain flushed a partial chain",
            actual.len()
        );
    }
}

/// The drain must END when the writer is done, not sit out its whole window.
///
/// This guards the ONE thing the delivery test above cannot see. The drain ends
/// when the writer task's channel closes, and the channel closes only when the
/// last `Arc<SessionLinkActions>` drops — one of which is held by the registry's
/// `FaceEntry`. So `face_down` has to precede the drain.
///
/// Getting that order wrong does not lose a single byte: the writer still drains
/// its channel during the window and only the task's EXIT is missed, so the
/// delivery test stays green. What it costs is the whole `WRITER_DRAIN_MS` on
/// every `z_close`, forever, for a session with nothing pending — measured at
/// 51.5 ms against 0.1-0.5 ms, five rounds each. A latency regression that no
/// correctness assertion can see is exactly the kind that ships.
///
/// The bound is the MINIMUM over several closes rather than any single one: a
/// loaded host can stretch one teardown, but the ordering defect stretches EVERY
/// one to the full window, so the minimum separates the two without depending on
/// the host being quiet.
#[test]
fn an_idle_z_close_does_not_burn_the_whole_drain_window() {
    const ROUNDS: usize = 5;

    let port = free_port();
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let connect = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let done_acc = done.clone();

    let (started_tx, started_rx) = mpsc::channel::<()>();
    let acceptor = std::thread::spawn(move || unsafe {
        let mut cfg: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut cfg), Z_OK);
        assert_eq!(
            zp_config_insert(
                z_config_loan_mut(&mut cfg),
                Z_CONFIG_LISTEN_KEY,
                listen.as_ptr()
            ),
            Z_OK
        );
        let _ = started_tx.send(());
        let mut session: z_owned_session_t = std::mem::zeroed();
        assert_eq!(
            z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
            Z_OK,
            "acceptor z_open failed"
        );
        for _ in 0..3000 {
            if done_acc.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
    });
    started_rx.recv().unwrap();

    let mut fastest = Duration::MAX;
    for round in 0..ROUNDS {
        let mut session: z_owned_session_t = unsafe { std::mem::zeroed() };
        let mut opened = false;
        for _ in 0..250 {
            unsafe {
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
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(opened, "dialer z_open never succeeded on round {round}");

        // Nothing was published, so there is nothing to flush and the drain has
        // no work to wait for.
        let started = std::time::Instant::now();
        unsafe {
            z_close(z_session_loan_mut(&mut session), std::ptr::null());
        }
        let elapsed = started.elapsed();
        unsafe {
            z_session_drop(z_session_move(&mut session));
        }
        fastest = fastest.min(elapsed);
    }

    done.store(true, Ordering::SeqCst);
    acceptor.join().expect("acceptor thread panicked");

    let budget = Duration::from_millis(WRITER_DRAIN_MS * 4 / 5);
    assert!(
        fastest < budget,
        "the fastest of {ROUNDS} idle z_close calls took {fastest:?}, which is \
         not below {budget:?} — the drain is running to its {WRITER_DRAIN_MS} ms \
         timeout instead of ending when the writer does. The usual cause is a \
         surviving Arc<SessionLinkActions> holding the outbound channel open: \
         `face_down` must run BEFORE the drain, not after."
    );
}
