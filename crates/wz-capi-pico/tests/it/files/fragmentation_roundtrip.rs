// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! Oversize-payload delivery gate for §5.27 api-compat-pico.
//!
//! R311y484 measured, through a recording TCP relay, that `wz-capi-pico`
//! composes no `transport-fragmentation`: a `z_put` above the negotiated
//! 65535-byte batch produced ZERO wire bytes while `z_put` still returned
//! `Z_OK`, so a C caller could not distinguish a delivered put from a
//! discarded one. That measurement observed the WIRE; this gate observes the
//! only thing a pico C program can actually observe — whether the subscriber
//! closure fires with the bytes that were published.
//!
//! Both peers are the exported C ABI (an acceptor that subscribes, a dialer
//! that publishes), so this is the drop-in program's own view. Each size is
//! republished until the acceptor's closure reports it, bounded, so a
//! propagation delay retries and a genuine loss fails fast.
//!
//! The acceptor is this crate, so it rejoins what pico rejoins: no message past
//! pico's `FRAG_MAX_SIZE` as the build states it
//! (`wz_session_core::caps::PICO_FRAG_MAX_BYTES`, 4096 by default). A chain past
//! that is dropped on arrival and the session goes on, as pico drops it
//! (`vendor/zenoh-pico/src/transport/unicast/rx.c` @
//! `if ((_z_wbuf_len(dbuf) + msg->_payload.len) > Z_FRAG_MAX_SIZE) {`), and its
//! `z_put` still returns `Z_OK`: pico's sender fragments a message of any size
//! and cannot know the peer's ceiling. So this file asserts both halves of pico's
//! behaviour. Chains past the ceiling and up to the slot a wz receiver rejoins are
//! measured where the receiver rejoins them, the zenoh-c ABI's
//! `tests/fragmentation_roundtrip.rs`.
//!
//! The 200-byte case rides a single batch and passed before the fix; it stays in
//! the table as the calibration that the harness itself delivers, so a red on the
//! fragmented size is the fragmentation gap and not a broken fixture.

#![cfg(feature = "peer")]

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_capi_pico::{
    z_bytes_copy_from_buf, z_bytes_to_slice, z_close, z_closure_sample, z_config_default,
    z_config_loan_mut, z_config_move, z_declare_subscriber, z_loaned_bytes_t, z_loaned_sample_t,
    z_open, z_owned_config_t, z_owned_session_t, z_owned_slice_t, z_owned_subscriber_t, z_put,
    z_sample_payload, z_session_drop, z_session_loan, z_session_loan_mut, z_session_move,
    z_slice_data, z_slice_drop, z_slice_len, z_slice_loan, z_slice_move, z_undeclare_subscriber,
    z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert,
    Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_OK,
};

/// The largest message the acceptor rejoins from fragments, in bytes.
const CEILING: usize = wz_session_core::caps::PICO_FRAG_MAX_BYTES;

/// The payload of the largest put the test expects rejoined: the ceiling less
/// the message's encoding beside its payload (the key and the headers, a few
/// dozen bytes), so its message is within the ceiling whatever the key costs.
const UNDER: usize = CEILING - 256;

/// Payload sizes the acceptor must rejoin, in publish order: 200 rides one
/// batch, and [`UNDER`] needs TX fragmentation on the publisher and reassembly
/// on the subscriber.
const SIZES: &[usize] = &[200, UNDER];

/// A payload whose message is past the ceiling by its whole encoding: dropped.
const PAST: usize = CEILING + 1;

/// The put after the dropped one, which shows the session survived the drop.
const AFTER: usize = 300;

/// The fixture's sizes are what it claims of them, for the numbers this build
/// states: [`UNDER`] fragments.
const _: () = assert!(
    UNDER > wz_session_core::caps::PICO_UNICAST_BATCH_BYTES,
    "the rejoined size must be past one batch, or nothing fragments"
);

/// Deterministic, size-dependent filler: a same-length payload of a different
/// size never collides, and a truncated delivery cannot masquerade as a whole
/// one because the trailing bytes are position-dependent.
fn payload_of(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

/// What the acceptor's closure records: for every delivered sample, its length
/// mapped to the payload bytes, so the test asserts on content, not just size.
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
    }
}

unsafe extern "C" fn on_drop(ctx: *mut c_void) {
    drop(Box::from_raw(ctx as *const Ctx as *mut Ctx));
}

use wz_runtime_tokio_test_support::free_port;

/// One `z_put` of `payload` on `key`, asserting it returns `Z_OK`.
unsafe fn put(session: &z_owned_session_t, key: &std::ffi::CStr, payload: &[u8]) {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
    let mut bytes = std::mem::zeroed();
    assert_eq!(
        z_bytes_copy_from_buf(&mut bytes, payload.as_ptr(), payload.len()),
        Z_OK,
        "z_bytes_copy_from_buf failed for {} bytes",
        payload.len()
    );
    assert_eq!(
        z_put(
            z_session_loan(session),
            z_view_keyexpr_loan(&ke),
            wz_capi_pico::z_bytes_move(&mut bytes),
            std::ptr::null(),
        ),
        Z_OK,
        "z_put returned an error for {} bytes",
        payload.len()
    );
}

#[test]
fn a_fragmented_put_is_rejoined_up_to_the_ceiling_and_dropped_past_it() {
    let port = free_port();
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let connect = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();

    let delivered: Delivered = Arc::new(Mutex::new(HashMap::new()));
    let delivered_acc = delivered.clone();

    // The acceptor's subscriber is declared and live; the dialer may start
    // publishing before that propagates, which the per-size retry absorbs.
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
        assert_eq!(z_view_keyexpr_from_str(&mut ke, c"frag/**".as_ptr()), Z_OK);
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

        // Hold the session open until the publisher has finished every size.
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

    // Publish each size, republishing until the acceptor's closure reports a
    // sample of exactly that length. Every `z_put` return code is asserted:
    // the defect's signature is Z_OK *with* no delivery, so a silent drop must
    // fail on the delivery assertion below, never on the return code.
    let mut missing: Vec<usize> = Vec::new();
    for &size in SIZES {
        let expected = payload_of(size);
        let ke_str = std::ffi::CString::new(format!("frag/{size}")).unwrap();
        let mut got = false;
        for _ in 0..150 {
            if delivered.lock().unwrap().contains_key(&size) {
                got = true;
                break;
            }
            unsafe { put(&session, &ke_str, &expected) };
            std::thread::sleep(Duration::from_millis(20));
        }
        if !got {
            missing.push(size);
        }
    }

    // Past the ceiling: published, accepted by `z_put` (asserted in `put`), and
    // dropped by the acceptor. The put after it rides the same reliable conduit,
    // so once it has arrived the acceptor has read every fragment of the dropped
    // chain before it, and the absence below is a verdict and not an impatience.
    unsafe { put(&session, c"frag/past", &payload_of(PAST)) };
    let after = payload_of(AFTER);
    let mut recovered = false;
    for _ in 0..150 {
        if delivered.lock().unwrap().contains_key(&AFTER) {
            recovered = true;
            break;
        }
        unsafe { put(&session, c"frag/after", &after) };
        std::thread::sleep(Duration::from_millis(20));
    }

    done.store(true, Ordering::SeqCst);

    // Report every missing size at once: the calibration sizes and the
    // fragmenting sizes fail differently, and seeing both halves in one line
    // is what distinguishes a broken fixture from the fragmentation gap.
    assert!(
        missing.is_empty(),
        "z_put returned Z_OK but the subscriber never received these sizes: \
         {missing:?} (delivered: {:?})",
        {
            let mut k: Vec<usize> = delivered.lock().unwrap().keys().copied().collect();
            k.sort_unstable();
            k
        }
    );

    // Content, not just arrival: a reassembled chain must equal what was put.
    for &size in SIZES {
        let expected = payload_of(size);
        let map = delivered.lock().unwrap();
        let actual = map.get(&size).expect("checked non-empty above");
        assert_eq!(actual.len(), size, "delivered length mismatch for {size}");
        assert!(
            actual == &expected,
            "delivered payload differs from the published bytes at size {size} \
             (reassembly reordered or corrupted the chain)"
        );
    }
    assert!(
        recovered,
        "the session stopped delivering after a chain past the {CEILING}-byte \
         ceiling: pico drops that chain and goes on"
    );
    assert!(
        !delivered.lock().unwrap().contains_key(&PAST),
        "a {PAST}-byte message was rejoined past the {CEILING}-byte ceiling \
         this build states for pico's FRAG_MAX_SIZE, which pico drops"
    );

    unsafe {
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
    }

    acceptor.join().expect("acceptor thread panicked");
}

/// A put past every ceiling is sent as zenoh-pico sends it, and the receiver's
/// ceiling is what drops it.
///
/// R311y484 asked the sender to refuse a put no wz receiver could rejoin, since a
/// peer's cap is not observable. Round 4617 took that bound away: the AP sender
/// refuses no message for its size (`wz_runtime_tokio::reassembly::REASSEMBLY_CHAIN_CAP`
/// is `usize::MAX`), as upstream's sender refuses none and as zenoh-pico's fragments
/// a message of any size and returns `Z_OK` (`vendor/zenoh-pico/src/transport/common/tx.c`
/// @ `// Message still doesn't fit in buffer, send as fragments`). Both engines behind
/// this door now answer as pico does, so the contract is one: the put is `Z_OK`, the
/// receiver here (this door, which rejoins no chain past pico's `FRAG_MAX_SIZE`)
/// drops the chain, and the session goes on to carry the next put.
#[test]
fn a_put_past_every_ceiling_is_sent_as_pico_sends_it_and_dropped_by_the_receiver() {
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
            Z_OK
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
        assert_eq!(z_view_keyexpr_from_str(&mut ke, c"frag/**".as_ptr()), Z_OK);
        let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&session),
                &mut subscriber,
                z_view_keyexpr_loan(&ke),
                wz_capi_pico::z_closure_sample_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK
        );
        sub_ready_acc.store(true, Ordering::SeqCst);

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
        "subscriber never declared"
    );

    // Twice this door's receiving ceiling (pico's FRAG_MAX_SIZE): a chain only the receiver's
    // drop can answer for, and a payload every build of this door holds. The release form keeps
    // payloads in the process pools' bounded area, which refuses a copy of megabytes with pico's
    // _Z_ERR_SYSTEM_OUT_OF_MEMORY, as zenoh-pico on a small heap does: the size of the put is not
    // what this test asks about, the sender's answer past the ceiling is.
    const TOO_BIG: usize = 2 * CEILING;
    let payload = payload_of(TOO_BIG);
    let rc = unsafe {
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut ke, c"frag/toobig".as_ptr()),
            Z_OK
        );
        let mut bytes = std::mem::zeroed();
        assert_eq!(
            z_bytes_copy_from_buf(&mut bytes, payload.as_ptr(), payload.len()),
            Z_OK
        );
        z_put(
            z_session_loan(&session),
            z_view_keyexpr_loan(&ke),
            wz_capi_pico::z_bytes_move(&mut bytes),
            std::ptr::null(),
        )
    };

    // Give a delivery every chance to land before concluding it did not.
    for _ in 0..100 {
        if delivered.lock().unwrap().contains_key(&TOO_BIG) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let arrived = delivered.lock().unwrap().contains_key(&TOO_BIG);

    // A dropped chain must not cost the session: the receiver discards the
    // chain's fragments and the reliable conduit goes on, so THIS put, an
    // ordinary one after the dropped chain, arrives.
    let after_payload = payload_of(AFTER);
    let mut recovered = false;
    for _ in 0..150 {
        if delivered.lock().unwrap().contains_key(&AFTER) {
            recovered = true;
            break;
        }
        unsafe {
            let mut ke: z_view_keyexpr_t = std::mem::zeroed();
            assert_eq!(
                z_view_keyexpr_from_str(&mut ke, c"frag/after".as_ptr()),
                Z_OK
            );
            let mut bytes = std::mem::zeroed();
            assert_eq!(
                z_bytes_copy_from_buf(&mut bytes, after_payload.as_ptr(), after_payload.len()),
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
                "an ordinary put after a dropped chain was itself rejected"
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    done.store(true, Ordering::SeqCst);
    unsafe {
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
    }
    acceptor.join().expect("acceptor thread panicked");

    // The sender is zenoh-pico's on either engine: it fragments the chain and
    // answers Z_OK; the drop is the receiver's ceiling, held by the test above.
    assert_eq!(
        rc, Z_OK,
        "a put past every ceiling is sent as zenoh-pico sends it, and z_put answers Z_OK"
    );
    assert!(
        !arrived,
        "a {TOO_BIG}-byte chain was rejoined past this door's {CEILING}-byte receiving ceiling"
    );
    assert!(
        recovered,
        "the session stopped delivering after a refused oversize put — the \
         1-SN gap the refusal leaves in the conduit ring is NOT tolerated"
    );
}
