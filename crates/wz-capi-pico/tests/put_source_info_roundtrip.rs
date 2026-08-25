// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! R311y561 — a `z_source_info_t` set on `z_put_options_t` reaches the wire and
//! surfaces on a real peer's sample, measured over TCP between two sessions.
//!
//! ## Why this leg exists
//!
//! R311y559 gave the pico ABI a `z_source_info_t` and the `z_source_info_new` /
//! `z_source_info_id` / `z_source_info_sn` family, and closed the symbol census.
//! What it did NOT do is READ the field: every put/delete fold on this ABI
//! dropped `options->source_info`, with a stated reason — no exported
//! constructor existed, so no C program could build one to pass, and wiring an
//! unbuildable field would have been untestable surface.
//!
//! `z_source_info_new` shipped in that same round. The reason expired with it,
//! and the field stayed unread anyway. That is the class this workspace keeps
//! paying for: a residual is a claim with a date on it, and the date had passed.
//!
//! ## What is measured, and what a green result would mean without the arms
//!
//! ARM 1 sets a source identity a wz session would never mint for itself — zid
//! `0xA1 0xA2 ..`, eid `0x5150`, sn `9001` — and asserts the peer reads back
//! exactly those. Distinctive values are load-bearing: any identity the runtime
//! could plausibly have produced on its own would leave "it arrived" and "we
//! sent it" indistinguishable.
//!
//! ARM 2 is the NEGATIVE arm, and it is what makes ARM 1 a claim about the
//! option rather than about the transport. The same publisher, the same
//! subscriber, one more put with `source_info = NULL` — the sample still
//! arrives, and carries NO source identity. Without it, a build that stamped
//! some source_info on every put unconditionally would pass ARM 1 for the wrong
//! reason.
//!
//! ARM 3 pins pico's own null-value contract: `_z_source_info_null` is all-zero
//! and `_z_source_info_check` rejects it on the zero zid, so an all-zero struct
//! passed by pointer must behave as absent rather than as "a publisher whose
//! zid is 0".

use std::ffi::c_void;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_capi_pico::advanced::z_entity_global_id_t;
use wz_capi_pico::zid::z_id_t;
use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_sample, z_config_default,
    z_config_loan_mut, z_config_move, z_declare_subscriber, z_entity_global_id_new,
    z_loaned_sample_t, z_open, z_owned_config_t, z_owned_session_t, z_owned_subscriber_t, z_put,
    z_put_options_default, z_put_options_t, z_sample_source_info, z_session_drop, z_session_loan,
    z_session_loan_mut, z_session_move, z_source_info_id, z_source_info_new, z_source_info_sn,
    z_source_info_t, z_subscriber_move, z_undeclare_subscriber, z_view_keyexpr_from_str,
    z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert, Z_CONFIG_CONNECT_KEY,
    Z_CONFIG_LISTEN_KEY, Z_OK,
};

/// One delivered sample's source identity, or `None` when the sample carried
/// none. Recorded per delivery so the negative arm is a distinct observation
/// rather than the absence of one.
type Seen = Option<([u8; 16], u32, u32)>;

struct Ctx {
    seen: Arc<Mutex<Vec<Seen>>>,
}

unsafe extern "C" fn on_sample(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const Ctx);
    let info = z_sample_source_info(sample);
    let entry = if info.is_null() {
        None
    } else {
        let gid = z_source_info_id(info);
        Some((gid.zid.id, gid.eid, z_source_info_sn(info)))
    };
    ctx.seen.lock().unwrap().push(entry);
}

use wz_runtime_tokio_test_support::free_port;

unsafe fn open_with(key: u8, endpoint: &std::ffi::CStr) -> Option<z_owned_session_t> {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    if z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()) == Z_OK {
        Some(session)
    } else {
        None
    }
}

/// One `z_put` on `keyexpr` carrying `source_info` (NULL = the option unset).
unsafe fn put_with_source_info(
    session: &z_owned_session_t,
    keyexpr: &std::ffi::CStr,
    source_info: *mut z_source_info_t,
) {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, keyexpr.as_ptr()), Z_OK);
    let mut payload = std::mem::zeroed();
    assert_eq!(
        z_bytes_copy_from_str(&mut payload, c"source-info-probe".as_ptr()),
        Z_OK
    );
    let mut options: z_put_options_t = std::mem::zeroed();
    z_put_options_default(&mut options);
    options.source_info = source_info;
    assert_eq!(
        z_put(
            z_session_loan(session),
            z_view_keyexpr_loan(&ke),
            z_bytes_move(&mut payload),
            &options,
        ),
        Z_OK
    );
}

/// Build the `z_source_info_t` a C program would, through the exported
/// constructors rather than by struct literal — the ABI path is what is under
/// test, not the Rust type.
unsafe fn source_info(zid_bytes: [u8; 16], eid: u32, sn: u32) -> z_source_info_t {
    let zid = z_id_t { id: zid_bytes };
    let mut gid: z_entity_global_id_t = std::mem::zeroed();
    assert_eq!(z_entity_global_id_new(&mut gid, &zid, eid), Z_OK);
    z_source_info_new(&gid, sn)
}

#[test]
fn put_options_source_info_crosses_the_wire_and_null_leaves_it_absent() {
    let port = free_port();
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let connect = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();

    // A zid no wz session would mint for itself, so "it arrived" and "we sent
    // it" cannot be confused.
    let mut probe_zid = [0u8; 16];
    for (i, b) in probe_zid.iter_mut().enumerate() {
        *b = 0xA1 + i as u8;
    }
    const PROBE_EID: u32 = 0x5150;
    const PROBE_SN: u32 = 9001;

    unsafe {
        let mut listener = open_with(Z_CONFIG_LISTEN_KEY, &listen).expect("listener z_open failed");

        let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
        let ctx = Box::into_raw(Box::new(Ctx { seen: seen.clone() })) as *mut c_void;
        let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_sample(&mut closure, Some(on_sample), None, ctx),
            Z_OK
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/si".as_ptr()), Z_OK);
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&listener),
                &mut subscriber,
                z_view_keyexpr_loan(&ke),
                wz_capi_pico::z_closure_sample_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK
        );

        let mut dialer = None;
        for _ in 0..250 {
            if let Some(session) = open_with(Z_CONFIG_CONNECT_KEY, &connect) {
                dialer = Some(session);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut dialer = dialer.expect("dialer z_open never succeeded");

        // ARM 1 — the option is SET. Republish until the declaration has
        // propagated (bounded, so a genuine failure fails fast).
        let mut si = source_info(probe_zid, PROBE_EID, PROBE_SN);
        for _ in 0..250 {
            if !seen.lock().unwrap().is_empty() {
                break;
            }
            put_with_source_info(&dialer, c"demo/si", &mut si);
            std::thread::sleep(Duration::from_millis(20));
        }
        let first = seen.lock().unwrap().first().copied().expect(
            "CALIBRATION FAILED: no sample crossed the wire at all, so \
                     nothing below measures the source_info option",
        );
        assert_eq!(
            first,
            Some((probe_zid, PROBE_EID, PROBE_SN)),
            "z_put_options_t::source_info must reach the peer intact — zid all \
             16 bytes, eid and sn. R311y559 dropped this field on every pico \
             put/delete fold"
        );

        // ARM 2 — the NEGATIVE arm. The option UNSET on the same publisher and
        // subscriber: the sample still arrives, carrying no source identity.
        // Without this, a build stamping some source_info on every put would
        // pass ARM 1 for the wrong reason.
        let before = seen.lock().unwrap().len();
        let mut null_seen = None;
        for _ in 0..250 {
            put_with_source_info(&dialer, c"demo/si", std::ptr::null_mut());
            std::thread::sleep(Duration::from_millis(20));
            let got = seen.lock().unwrap();
            if got.len() > before {
                null_seen = Some(got[before]);
                break;
            }
        }
        assert_eq!(
            null_seen,
            Some(None),
            "with source_info NULL the sample must still arrive and carry NO \
             source identity — the delivery proves the arm ran, the None proves \
             the identity in ARM 1 came from the option"
        );

        // ARM 3 — pico's own null value. `_z_source_info_null` is all-zero and
        // `_z_source_info_check` rejects it on the zero zid, so an all-zero
        // struct passed BY POINTER must read as absent, not as a publisher
        // whose zid is 0.
        let before = seen.lock().unwrap().len();
        let mut zero_si = source_info([0u8; 16], 0, 0);
        let mut zero_seen = None;
        for _ in 0..250 {
            put_with_source_info(&dialer, c"demo/si", &mut zero_si);
            std::thread::sleep(Duration::from_millis(20));
            let got = seen.lock().unwrap();
            if got.len() > before {
                zero_seen = Some(got[before]);
                break;
            }
        }
        assert_eq!(
            zero_seen,
            Some(None),
            "an all-zero z_source_info_t is pico's NULL value and must read as \
             absent (_z_source_info_check is a zero-zid test), not as a source \
             identity of zid 0"
        );

        z_undeclare_subscriber(z_subscriber_move(&mut subscriber));
        z_close(z_session_loan_mut(&mut dialer), std::ptr::null());
        z_session_drop(z_session_move(&mut dialer));
        z_close(z_session_loan_mut(&mut listener), std::ptr::null());
        z_session_drop(z_session_move(&mut listener));
        drop(Box::from_raw(ctx as *mut Ctx));
    }
}

/// The OTHER THREE folds — `z_delete`, `z_publisher_put`, `z_publisher_delete`.
///
/// Four separate functions read `options->source_info` on this ABI, each with
/// its own options struct, and the round that wired them wired all four at once.
/// A test that drove only `z_put` would leave three of them proven by the shape
/// of the diff rather than by measurement — which is the same "both halves were
/// built and no slot joined them" failure this workspace has hit before. So each
/// entry point carries its OWN distinctive sn, and the assertion is on the SET
/// of `(sn, kind)` pairs the peer saw: a fold that dropped the field contributes
/// a `None` and the set no longer matches, and a fold wired to the wrong
/// entry point shows up as a duplicated or missing sn rather than as a pass.
#[test]
fn source_info_reaches_the_wire_from_delete_and_both_publisher_paths() {
    let port = free_port();
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let connect = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();

    let mut probe_zid = [0u8; 16];
    for (i, b) in probe_zid.iter_mut().enumerate() {
        *b = 0xC0 + i as u8;
    }
    // One sn per entry point, so each fold is individually identifiable.
    const SN_SESSION_DELETE: u32 = 7001;
    const SN_PUBLISHER_PUT: u32 = 7002;
    const SN_PUBLISHER_DELETE: u32 = 7003;

    unsafe {
        let mut listener = open_with(Z_CONFIG_LISTEN_KEY, &listen).expect("listener z_open failed");

        let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
        let ctx = Box::into_raw(Box::new(Ctx { seen: seen.clone() })) as *mut c_void;
        let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_sample(&mut closure, Some(on_sample), None, ctx),
            Z_OK
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/si2".as_ptr()), Z_OK);
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&listener),
                &mut subscriber,
                z_view_keyexpr_loan(&ke),
                wz_capi_pico::z_closure_sample_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK
        );

        let mut dialer = None;
        for _ in 0..250 {
            if let Some(session) = open_with(Z_CONFIG_CONNECT_KEY, &connect) {
                dialer = Some(session);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut dialer = dialer.expect("dialer z_open never succeeded");

        // Wait for the remote declaration to land before the measured puts, so
        // the retry loop does not pollute the observed set with duplicates.
        let mut warmup = source_info(probe_zid, 1, 1);
        for _ in 0..250 {
            if !seen.lock().unwrap().is_empty() {
                break;
            }
            put_with_source_info(&dialer, c"demo/si2", &mut warmup);
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !seen.lock().unwrap().is_empty(),
            "CALIBRATION FAILED: nothing crossed the wire during warm-up"
        );
        seen.lock().unwrap().clear();

        // --- z_delete (z_delete_options_t) ---
        let mut si_del = source_info(probe_zid, 11, SN_SESSION_DELETE);
        let mut del_ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut del_ke, c"demo/si2".as_ptr()),
            Z_OK
        );
        let mut del_opts: wz_capi_pico::z_delete_options_t = std::mem::zeroed();
        wz_capi_pico::z_delete_options_default(&mut del_opts);
        del_opts.source_info = &mut si_del;
        assert_eq!(
            wz_capi_pico::z_delete(
                z_session_loan(&dialer),
                z_view_keyexpr_loan(&del_ke),
                &del_opts,
            ),
            Z_OK
        );

        // --- z_publisher_put / z_publisher_delete ---
        let mut publisher: wz_capi_pico::z_owned_publisher_t = std::mem::zeroed();
        let mut pub_ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut pub_ke, c"demo/si2".as_ptr()),
            Z_OK
        );
        assert_eq!(
            wz_capi_pico::z_declare_publisher(
                z_session_loan(&dialer),
                &mut publisher,
                z_view_keyexpr_loan(&pub_ke),
                std::ptr::null(),
            ),
            Z_OK
        );

        let mut si_pput = source_info(probe_zid, 12, SN_PUBLISHER_PUT);
        let mut payload = std::mem::zeroed();
        assert_eq!(
            z_bytes_copy_from_str(&mut payload, c"publisher-put".as_ptr()),
            Z_OK
        );
        let mut pput_opts: wz_capi_pico::z_publisher_put_options_t = std::mem::zeroed();
        wz_capi_pico::z_publisher_put_options_default(&mut pput_opts);
        pput_opts.source_info = &mut si_pput;
        assert_eq!(
            wz_capi_pico::z_publisher_put(
                wz_capi_pico::z_publisher_loan(&publisher),
                z_bytes_move(&mut payload),
                &pput_opts,
            ),
            Z_OK
        );

        let mut si_pdel = source_info(probe_zid, 13, SN_PUBLISHER_DELETE);
        let mut pdel_opts: wz_capi_pico::z_publisher_delete_options_t = std::mem::zeroed();
        wz_capi_pico::z_publisher_delete_options_default(&mut pdel_opts);
        pdel_opts.source_info = &mut si_pdel;
        assert_eq!(
            wz_capi_pico::z_publisher_delete(
                wz_capi_pico::z_publisher_loan(&publisher),
                &pdel_opts,
            ),
            Z_OK
        );

        // Collect until all three land, bounded.
        let mut sns: Vec<Option<u32>> = Vec::new();
        for _ in 0..250 {
            sns = seen
                .lock()
                .unwrap()
                .iter()
                .map(|e| e.map(|(_, _, sn)| sn))
                .collect();
            if sns.len() >= 3 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut got: Vec<Option<u32>> = sns;
        got.sort();
        assert_eq!(
            got,
            vec![
                Some(SN_SESSION_DELETE),
                Some(SN_PUBLISHER_PUT),
                Some(SN_PUBLISHER_DELETE),
            ],
            "each of z_delete / z_publisher_put / z_publisher_delete must carry \
             its own source_info to the peer; a fold that still drops the field \
             contributes a None here"
        );

        wz_capi_pico::z_undeclare_publisher(wz_capi_pico::z_publisher_move(&mut publisher));
        z_undeclare_subscriber(z_subscriber_move(&mut subscriber));
        z_close(z_session_loan_mut(&mut dialer), std::ptr::null());
        z_session_drop(z_session_move(&mut dialer));
        z_close(z_session_loan_mut(&mut listener), std::ptr::null());
        z_session_drop(z_session_move(&mut listener));
        drop(Box::from_raw(ctx as *mut Ctx));
    }
}
