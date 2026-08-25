// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! The 200- and 65000-byte cases ride a single batch and passed before the
//! fix; they stay in the table as the calibration that the harness itself
//! delivers, so a red on 131072 / 262144 is the fragmentation gap and not a
//! broken fixture.

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

/// Payload sizes under test, in publish order.
///
/// 200 and 65000 sit inside the negotiated 65535-byte batch (the sizes
/// R311y484 measured as reaching the wire). 131072 and 262144 are the two
/// that produced zero wire bytes; they require TX fragmentation on the
/// publisher and reassembly on the subscriber.
/// 1044480 is the boundary case, and it is here to check the UNIT of the
/// sender's refusal, not just its existence. The sender refuses a chain whose
/// reassembled body exceeds the AP slot cap; the receiver stages that same
/// body. If those two were measuring different things — the framed bytes on
/// one side, the caller's payload on the other — there would be a band just
/// under the cap that the sender accepts and the receiver still drops, which
/// is the silent loss this round exists to remove. This size sits in that
/// band (4 KiB under 1 MiB, so its envelope cannot push it over), and it must
/// arrive.
const SIZES: &[usize] = &[200, 65_000, 131_072, 262_144, 1_044_480];

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

#[test]
fn oversize_put_is_fragmented_and_delivered_whole() {
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
            unsafe {
                let mut ke: z_view_keyexpr_t = std::mem::zeroed();
                assert_eq!(z_view_keyexpr_from_str(&mut ke, ke_str.as_ptr()), Z_OK);
                let mut payload = std::mem::zeroed();
                assert_eq!(
                    z_bytes_copy_from_buf(&mut payload, expected.as_ptr(), expected.len()),
                    Z_OK,
                    "z_bytes_copy_from_buf failed for {size} bytes"
                );
                assert_eq!(
                    z_put(
                        z_session_loan(&session),
                        z_view_keyexpr_loan(&ke),
                        wz_capi_pico::z_bytes_move(&mut payload),
                        std::ptr::null(),
                    ),
                    Z_OK,
                    "z_put returned an error for {size} bytes"
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if !got {
            missing.push(size);
        }
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

    unsafe {
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
    }

    acceptor.join().expect("acceptor thread panicked");
}

/// The invariant the fragmentation fix must not leave half-closed.
///
/// R311y484's finding was not "large puts are lost" — it was that `z_put`
/// returned `Z_OK` for a put that never left the host, so a C caller could not
/// tell a delivered put from a discarded one. Raising the reassembly cap moves
/// that boundary; it does not remove it. Above the cap the chain is staged past
/// the receiver's slot limit and dropped, so the same indistinguishability
/// returns unless the sender refuses locally.
///
/// It CAN refuse locally, and only locally: a peer's cap is not observable, but
/// this profile's own is, and in the pico C-ABI topology both ends are this
/// crate. So the contract asserted here is the locally decidable one — a put
/// this profile could never reassemble must report an error rather than a
/// success that silently goes nowhere.
#[test]
fn a_put_too_large_to_reassemble_reports_an_error_instead_of_z_ok() {
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

    // Four MiB: four times the AP reassembly slot cap, so no same-profile peer
    // can absorb the chain however well the sender fragments it.
    const TOO_BIG: usize = 4 * 1024 * 1024;
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

    // A refusal must not cost the session. The refused send has already
    // minted one Frame SN by the time its size is known (the encode is what
    // reveals the size), so it leaves a 1-SN gap in that conduit's ring. If
    // the peer's half-window check did not tolerate the gap, THIS put — an
    // ordinary one, after the refusal — would never arrive.
    const AFTER: usize = 4096;
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
                "an ordinary put after a refused one was itself rejected"
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

    // Either outcome is acceptable on its own; the conjunction is the defect.
    assert!(
        !(rc == Z_OK && !arrived),
        "z_put returned Z_OK ({rc}) for a {TOO_BIG}-byte payload that was never \
         delivered — the R311y484 silent-drop semantic survives above the \
         reassembly cap, so a C caller still cannot tell delivered from discarded"
    );
    assert!(
        recovered,
        "the session stopped delivering after a refused oversize put — the \
         1-SN gap the refusal leaves in the conduit ring is NOT tolerated"
    );
}
