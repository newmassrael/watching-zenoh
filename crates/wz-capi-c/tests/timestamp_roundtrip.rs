// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! R311y557 — `z_put_options_t::timestamp` on the zenoh-c ABI, driven through
//! the exported `z_*` symbols exactly as a C program would.
//!
//! ## What was missing, and why a unit test could not have shown it
//!
//! The field had been carried for LAYOUT since the option surface was laid out:
//! a `*const c_void` that nothing dereferenced, because the type it points at
//! (`z_timestamp_t`) was not declared by this crate. Two halves were therefore
//! absent and they are separately omittable, which is why both are asserted
//! here rather than one standing in for the other:
//!
//! 1. the SEND half — the caller's timestamp reaching `PublishOptions`, hence
//!    the `MsgPut` T-flag and the loopback sample;
//! 2. the READ half — `z_sample_timestamp`, without which a C program has no
//!    way to observe what arrived and the send half is unfalsifiable.
//!
//! The legs run on a listener with NO peer, so the delivery rides the
//! face-independent local plane this same round introduced. That is deliberate:
//! it keeps the timestamp claim about the VALUE rather than about the transport,
//! and it makes the assertions independent of a handshake completing.

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_sample_t, z_moved_bytes_t, z_moved_closure_sample_t, z_moved_config_t,
    z_moved_session_t, z_moved_subscriber_t, z_owned_bytes_t, z_owned_closure_sample_t,
    z_owned_config_t, z_owned_session_t, z_owned_subscriber_t, z_view_keyexpr_t,
};
use wz_capi_c::bytes::z_bytes_copy_from_str;
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::put::{z_put, z_put_options_default, z_put_options_t};
use wz_capi_c::result::Z_OK;
use wz_capi_c::sample::z_sample_timestamp;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::sub::{z_closure_sample, z_declare_subscriber, z_undeclare_subscriber};
use wz_capi_c::timestamp::{
    z_timestamp_id, z_timestamp_new, z_timestamp_ntp64_time, z_timestamp_t,
};
use wz_capi_c::zid::{z_id_t, z_info_zid};

const KEYEXPR: &str = "wz/timestamp/demo";

/// What the subscriber callback observed, per sample.
struct SeenCtx {
    /// How many samples arrived at all — so a leg asserting "no timestamp" can
    /// still prove the sample itself was delivered.
    arrived: AtomicUsize,
    /// Whether `z_sample_timestamp` returned NULL for the last sample.
    was_null: AtomicBool,
    ntp64: AtomicU64,
    id: Mutex<[u8; 16]>,
}

unsafe extern "C" fn on_sample_record(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const SeenCtx);
    let ts = z_sample_timestamp(sample);
    if ts.is_null() {
        ctx.was_null.store(true, Ordering::SeqCst);
    } else {
        ctx.was_null.store(false, Ordering::SeqCst);
        ctx.ntp64
            .store(z_timestamp_ntp64_time(ts), Ordering::SeqCst);
        *ctx.id.lock().expect("test mutex") = z_timestamp_id(ts).id;
    }
    // Stored LAST, so a reader that sees the count move also sees the fields.
    ctx.arrived.fetch_add(1, Ordering::SeqCst);
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

unsafe fn declare_recording_sub(
    session: &z_owned_session_t,
    ctx: *mut c_void,
) -> z_owned_subscriber_t {
    let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
    z_closure_sample(&mut closure, Some(on_sample_record), None, ctx);
    let ke = CString::new(KEYEXPR).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    let mut sub: z_owned_subscriber_t = std::mem::zeroed();
    assert_eq!(
        z_declare_subscriber(
            z_session_loan(session),
            &mut sub,
            z_view_keyexpr_loan(&view),
            (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
            std::ptr::null_mut(),
        ),
        Z_OK
    );
    sub
}

/// Publish once with the given timestamp pointer (NULL for "unstamped").
unsafe fn put_with_timestamp(session: &z_owned_session_t, timestamp: *const z_timestamp_t) {
    let ke = CString::new(KEYEXPR).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    let body = CString::new("stamped").unwrap();
    let mut payload: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut payload, body.as_ptr()), Z_OK);
    let mut opts: z_put_options_t = std::mem::zeroed();
    z_put_options_default(&mut opts);
    assert!(
        opts.timestamp.is_null(),
        "upstream's default leaves the timestamp NULL; a non-null default would \
         stamp every put in every program"
    );
    opts.timestamp = timestamp.cast::<c_void>();
    assert_eq!(
        z_put(
            z_session_loan(session),
            z_view_keyexpr_loan(&view),
            (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
            &mut opts as *mut z_put_options_t,
        ),
        Z_OK
    );
}

fn settle(arrived: &Arc<SeenCtx>, want: usize, settle_for: Duration) -> usize {
    let deadline = Instant::now() + Duration::from_secs(5);
    while arrived.arrived.load(Ordering::SeqCst) < want && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(settle_for);
    arrived.arrived.load(Ordering::SeqCst)
}

unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}

/// THE leg: a timestamp minted with `z_timestamp_new` and set on
/// `z_put_options_t` comes back BYTE-IDENTICAL through `z_sample_timestamp`.
///
/// Both halves of the value are asserted, and neither is redundant: the NTP64
/// word alone would pass on an implementation that dropped the zid, and the zid
/// alone would pass on one that dropped the clock. Together they are the whole
/// of what upstream's `z_timestamp_t` carries.
#[test]
fn a_timestamp_set_on_a_put_comes_back_on_the_sample() {
    let port = free_port();
    unsafe {
        let session = open_listen(port);

        let ctx_owned = Arc::new(SeenCtx {
            arrived: AtomicUsize::new(0),
            was_null: AtomicBool::new(true),
            ntp64: AtomicU64::new(0),
            id: Mutex::new([0u8; 16]),
        });
        let ctx = Arc::into_raw(ctx_owned.clone()) as *mut c_void;
        let mut _sub = declare_recording_sub(&session, ctx);

        let mut stamp: z_timestamp_t = std::mem::zeroed();
        assert_eq!(
            z_timestamp_new(&mut stamp, z_session_loan(&session)),
            Z_OK,
            "minting from a live session succeeds"
        );
        let minted_id = z_timestamp_id(&stamp).id;
        let minted_time = z_timestamp_ntp64_time(&stamp);
        // The zid half is attributable: upstream's timestamp identifies WHICH
        // node stamped, and a mint that returned a zero id would still satisfy
        // a round-trip assertion on its own.
        let own: z_id_t = z_info_zid(z_session_loan(&session));
        assert_eq!(
            minted_id, own.id,
            "z_timestamp_new stamps THIS session's zid, which is what makes the \
             timestamp attributable"
        );
        assert_ne!(minted_id, [0u8; 16], "and that zid is not the empty id");

        put_with_timestamp(&session, &stamp);
        let count = settle(&ctx_owned, 1, Duration::from_millis(300));
        assert_eq!(count, 1, "the stamped put was delivered in-process");
        assert!(
            !ctx_owned.was_null.load(Ordering::SeqCst),
            "z_sample_timestamp must not be NULL for a sample whose publisher \
             set the field — NULL is what this ABI answered before R311y557"
        );
        assert_eq!(
            ctx_owned.ntp64.load(Ordering::SeqCst),
            minted_time,
            "the NTP64 word survives the round trip unchanged"
        );
        assert_eq!(
            *ctx_owned.id.lock().expect("test mutex"),
            minted_id,
            "and so does the zid half"
        );

        z_undeclare_subscriber(
            (&mut _sub as *mut z_owned_subscriber_t).cast::<z_moved_subscriber_t>(),
        );
        close_session(session);
        drop(Arc::from_raw(ctx as *const SeenCtx));
    }
}

/// The discriminator: the SAME program with the field left NULL, and the sample
/// arrives carrying no timestamp.
///
/// Without it the leg above would also pass on a build that stamped every put
/// from its own clock and ignored the caller entirely — which is a real
/// possibility rather than a hypothetical, because wz has a node HLC that can
/// stamp on the publish path independently of this field.
#[test]
fn a_put_with_no_timestamp_delivers_a_sample_with_none() {
    let port = free_port();
    unsafe {
        let session = open_listen(port);

        let ctx_owned = Arc::new(SeenCtx {
            arrived: AtomicUsize::new(0),
            // Seeded FALSE so the assertion below cannot pass on the initial
            // value — only an actual observation can put it back to true.
            was_null: AtomicBool::new(false),
            ntp64: AtomicU64::new(0),
            id: Mutex::new([0u8; 16]),
        });
        let ctx = Arc::into_raw(ctx_owned.clone()) as *mut c_void;
        let mut _sub = declare_recording_sub(&session, ctx);

        put_with_timestamp(&session, std::ptr::null());
        let count = settle(&ctx_owned, 1, Duration::from_millis(300));
        assert_eq!(count, 1, "the unstamped put was still delivered");
        assert!(
            ctx_owned.was_null.load(Ordering::SeqCst),
            "a put that set no timestamp must deliver a sample whose \
             z_sample_timestamp is NULL"
        );

        z_undeclare_subscriber(
            (&mut _sub as *mut z_owned_subscriber_t).cast::<z_moved_subscriber_t>(),
        );
        close_session(session);
        drop(Arc::from_raw(ctx as *const SeenCtx));
    }
}
