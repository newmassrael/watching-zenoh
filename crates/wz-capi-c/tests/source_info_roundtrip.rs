// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! R311y563 — the zenoh-c `source_info` family, driven through the exported
//! `z_*` symbols exactly as a C program would.
//!
//! ## What this closes, and why it is not the pico work again
//!
//! Six option structs on this ABI declared `source_info` and all six carried it
//! as an unread `*mut c_void`, with a stated reason: `z_source_info_t` "is not
//! declared by this crate, so honouring it would need the source-info family
//! first". That reason was accurate and it stayed accurate for rounds, because
//! on THIS ABI the family is not a struct plus a getter — zenoh-c's source info
//! is an OWNED OPAQUE (`z_owned_source_info_t`, 32 bytes at align 4) whose
//! option fields are `z_moved_source_info_t*` the callee CONSUMES, so the work
//! is `_new` / `_loan` / `_drop` / `_id` / `_sn` / `z_internal_source_info_*`
//! plus a `z_sample_source_info` to read it back. The pico sibling
//! (R311y559/y561) is a plain by-pointer struct and shares none of that shape.
//!
//! ## What each arm rules out
//!
//! ARM 1 sets an identity no wz session would mint for itself — zid `0xC1..`,
//! eid `0x7070`, sn `4242` — through the exported constructors, and asserts the
//! subscriber reads back exactly those. Distinctive values are load-bearing:
//! an identity the runtime could have produced on its own would leave "it
//! arrived" and "we sent it" indistinguishable.
//!
//! ARM 2 is the NEGATIVE arm, and it is what makes ARM 1 a claim about the
//! OPTION rather than about the transport: the same publisher and subscriber,
//! one more put with `source_info` left NULL, and the sample still arrives
//! carrying no identity.
//!
//! ARM 3 pins the MOVE semantics, which is the half a borrowed-pointer mirror
//! of the pico work would have got wrong. After the put, the caller's
//! `z_owned_source_info_t` must read as a gravestone —
//! `z_internal_source_info_check` false — because upstream documents every
//! owned options field as consumed on return. A build that merely READ the
//! field would pass ARM 1 and fail here, which is exactly the distinction
//! `*mut c_void` hid.

// The whole family is UNSTABLE-gated upstream (`zenoh_commons.h:4410,
// 5189-5223`) and so is wz's, so on the no-unstable arm there is no API to
// drive and this file compiles to zero tests. That is a real coverage hole in
// exactly one direction and it is named rather than hidden: a lane running only
// this arm would report green having measured nothing, which is why the arm
// that MATTERS for the source-info claim is the default one — and Layer C1cc
// clippies both.
#![cfg(not(feature = "zenoh-c-no-unstable-api"))]

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_sample_t, z_moved_bytes_t, z_moved_closure_sample_t, z_moved_config_t,
    z_moved_session_t, z_moved_subscriber_t, z_owned_bytes_t, z_owned_closure_sample_t,
    z_owned_config_t, z_owned_session_t, z_owned_subscriber_t, z_view_keyexpr_t,
};
use wz_capi_c::advanced::z_entity_global_id_t;
use wz_capi_c::bytes::z_bytes_copy_from_str;
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::put::{z_put, z_put_options_default, z_put_options_t};
use wz_capi_c::result::Z_OK;
use wz_capi_c::sample::z_sample_source_info;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::source_info::{
    z_internal_source_info_check, z_moved_source_info_t, z_owned_source_info_t, z_source_info_id,
    z_source_info_new, z_source_info_sn,
};
use wz_capi_c::sub::{z_closure_sample, z_declare_subscriber, z_undeclare_subscriber};
use wz_capi_c::zid::z_id_t;

const KEYEXPR: &str = "wz/sourceinfo/demo";
const PROBE_ZID0: u8 = 0xC1;
const PROBE_EID: u32 = 0x7070;
const PROBE_SN: u32 = 4242;

/// One delivered sample's source identity, or `None` when it carried none.
type Seen = Option<([u8; 16], u32, u32)>;

struct Ctx {
    seen: Arc<Mutex<Vec<Seen>>>,
    count: Arc<AtomicUsize>,
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
    ctx.count.fetch_add(1, Ordering::SeqCst);
}

use wz_runtime_tokio_test_support::free_port;

unsafe fn open_listen(port: u16) -> z_owned_session_t {
    let key = CString::new("listen/endpoints").unwrap();
    let value = CString::new(format!("[\"tcp/127.0.0.1:{port}\"]")).unwrap();
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zc_config_insert_json5(z_config_loan_mut(&mut cfg), key.as_ptr(), value.as_ptr()),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(
            &mut session,
            (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
            std::ptr::null()
        ),
        Z_OK
    );
    session
}

/// Build the probe identity through the exported constructors rather than by
/// struct literal — the ABI path is what is under test, not the Rust type.
unsafe fn probe_source_info() -> z_owned_source_info_t {
    let mut zid_bytes = [0u8; 16];
    for (i, b) in zid_bytes.iter_mut().enumerate() {
        *b = PROBE_ZID0 + i as u8;
    }
    let gid = z_entity_global_id_t {
        zid: z_id_t { id: zid_bytes },
        eid: PROBE_EID,
    };
    let mut owned: z_owned_source_info_t = std::mem::zeroed();
    assert_eq!(z_source_info_new(&mut owned, &gid, PROBE_SN), Z_OK);
    owned
}

/// One `z_put` carrying `source_info` (NULL = the option unset).
unsafe fn put_with_source_info(
    session: &z_owned_session_t,
    source_info: *mut z_moved_source_info_t,
) {
    let ke = CString::new(KEYEXPR).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    let msg = CString::new("source-info-probe").unwrap();
    let mut payload: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut payload, msg.as_ptr()), Z_OK);
    let mut options: z_put_options_t = std::mem::zeroed();
    z_put_options_default(&mut options);
    options.source_info = source_info;
    assert_eq!(
        z_put(
            z_session_loan(session),
            z_view_keyexpr_loan(&view),
            (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
            &mut options,
        ),
        Z_OK
    );
}

/// Wait (bounded) for the recorder to have seen `want` samples.
fn wait_for(count: &AtomicUsize, want: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while count.load(Ordering::SeqCst) < want && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn put_options_source_info_crosses_the_wire_and_is_consumed() {
    let port = free_port();

    unsafe {
        let mut session = open_listen(port);

        let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
        let count = Arc::new(AtomicUsize::new(0));
        let ctx = Box::into_raw(Box::new(Ctx {
            seen: seen.clone(),
            count: count.clone(),
        })) as *mut c_void;

        let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
        z_closure_sample(&mut closure, Some(on_sample), None, ctx);
        let ke = CString::new(KEYEXPR).unwrap();
        let mut view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
        let mut sub: z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&session),
                &mut sub,
                z_view_keyexpr_loan(&view),
                (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
                std::ptr::null_mut(),
            ),
            Z_OK
        );

        // ARM 1 — the option is SET.
        let mut owned = probe_source_info();
        assert!(
            z_internal_source_info_check(&owned),
            "CALIBRATION: the constructor produced a live value, so the \
             gravestone assertion below measures the MOVE rather than a \
             constructor that never worked"
        );
        put_with_source_info(
            &session,
            (&mut owned as *mut z_owned_source_info_t).cast::<z_moved_source_info_t>(),
        );

        // ARM 3 — the MOVE. Upstream consumes every owned options field on
        // return, so the caller's value is a gravestone now. This is the arm a
        // read-only implementation fails.
        assert!(
            !z_internal_source_info_check(&owned),
            "z_put CONSUMED the moved source info, leaving the caller's owned \
             value a gravestone"
        );

        wait_for(&count, 1);

        // ARM 2 — the NEGATIVE arm: the same path with the option unset.
        put_with_source_info(&session, std::ptr::null_mut());
        wait_for(&count, 2);

        let got = seen.lock().unwrap().clone();
        assert_eq!(got.len(), 2, "both puts were delivered: {got:?}");

        let mut want_zid = [0u8; 16];
        for (i, b) in want_zid.iter_mut().enumerate() {
            *b = PROBE_ZID0 + i as u8;
        }
        assert_eq!(
            got[0],
            Some((want_zid, PROBE_EID, PROBE_SN)),
            "the delivered sample carries the identity the put options set"
        );
        assert_eq!(
            got[1], None,
            "a put with source_info NULL delivers a sample carrying none — so \
             the arm above measured the option, not something the runtime \
             stamps on every put"
        );

        z_undeclare_subscriber(
            (&mut sub as *mut z_owned_subscriber_t).cast::<z_moved_subscriber_t>(),
        );
        z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
        z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
    }
}
