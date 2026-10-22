// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! One sample across one link, through the exported `z_*` symbols as a C program calls them:
//! what each link's test asks of the endpoint pair it builds. The link is the only thing the
//! tests that share this module vary, so a red names the link and not the harness.

use std::ffi::{c_void, CStr, CString};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_bytes_to_slice, z_close, z_closure_sample,
    z_closure_sample_move, z_config_default, z_config_loan_mut, z_config_move,
    z_declare_subscriber, z_loaned_sample_t, z_open, z_owned_config_t, z_owned_session_t,
    z_owned_slice_t, z_owned_subscriber_t, z_put, z_sample_payload, z_session_drop, z_session_loan,
    z_session_loan_mut, z_session_move, z_slice_data, z_slice_drop, z_slice_len, z_slice_loan,
    z_slice_move, z_subscriber_move, z_undeclare_subscriber, z_view_keyexpr_from_str,
    z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert, Z_CONFIG_CONNECT_KEY,
    Z_CONFIG_LISTEN_KEY, Z_OK,
};

/// The key the listener subscribes to and the dialler puts on.
const KEYEXPR: &CStr = c"demo/link";

/// What the dialler puts, and what the listener must receive byte for byte.
pub const PAYLOAD: &CStr = c"one-sample-across-the-link";

/// How long the dialler goes on putting before the crossing is judged absent. A put made
/// before the subscriber's declaration has reached the dialler is not sent, so the first few
/// may be lost by design; the bound covers that and a serial link's own handshake.
const CROSSING_BOUND: Duration = Duration::from_secs(10);

/// The payloads a subscriber received, in order.
type Received = Arc<Mutex<Vec<Vec<u8>>>>;

unsafe extern "C" fn on_sample(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let received = &*(ctx as *const Received);
    let mut slice: z_owned_slice_t = std::mem::zeroed();
    if z_bytes_to_slice(z_sample_payload(sample), &mut slice) == Z_OK {
        let loaned = z_slice_loan(&slice);
        let data = z_slice_data(loaned);
        if !data.is_null() {
            let bytes = std::slice::from_raw_parts(data, z_slice_len(loaned)).to_vec();
            received.lock().unwrap().push(bytes);
        }
        z_slice_drop(z_slice_move(&mut slice));
    }
}

unsafe extern "C" fn on_drop(ctx: *mut c_void) {
    drop(Box::from_raw(ctx as *mut Received));
}

/// Open a session whose config states one endpoint under `key`. `Err` is the code `z_open`
/// returned.
unsafe fn open_with(key: u8, endpoint: &str) -> Result<z_owned_session_t, i8> {
    let endpoint = CString::new(endpoint).expect("an endpoint holds no NUL");
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    match z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()) {
        Z_OK => Ok(session),
        rc => Err(rc),
    }
}

unsafe fn put(session: &z_owned_session_t) {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, KEYEXPR.as_ptr()), Z_OK);
    let mut buf = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut buf, PAYLOAD.as_ptr()), Z_OK);
    assert_eq!(
        z_put(
            z_session_loan(session),
            z_view_keyexpr_loan(&ke),
            z_bytes_move(&mut buf),
            std::ptr::null(),
        ),
        Z_OK
    );
}

unsafe fn close_session(session: &mut z_owned_session_t) {
    z_close(z_session_loan_mut(session), std::ptr::null());
    z_session_drop(z_session_move(session));
}

/// Open a listener on `listen` with a subscriber on [`KEYEXPR`], open a second session that
/// dials `connect`, and put [`PAYLOAD`] from the dialler until the listener has received a
/// sample or [`CROSSING_BOUND`] has passed. Answers what the listener received; both sessions
/// are closed before it returns.
///
/// Panics, naming the end, when either open fails: a link whose feature is compiled in and
/// still refuses its endpoint fails there, before any sample is put.
pub fn payloads_across(listen: &str, connect: &str) -> Vec<Vec<u8>> {
    let received: Received = Arc::new(Mutex::new(Vec::new()));
    // SAFETY: fresh configs, sessions and entities, each released before the function returns;
    // the closure context is a boxed `Received` that `on_drop` frees.
    unsafe {
        let mut listener = open_with(Z_CONFIG_LISTEN_KEY, listen)
            .unwrap_or_else(|rc| panic!("z_open(listen={listen}) failed with {rc}"));

        let ctx = Box::into_raw(Box::new(received.clone())) as *mut c_void;
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_sample(&mut closure, Some(on_sample), Some(on_drop), ctx),
            Z_OK
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, KEYEXPR.as_ptr()), Z_OK);
        let mut sub: z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&listener),
                &mut sub,
                z_view_keyexpr_loan(&ke),
                z_closure_sample_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK
        );

        let mut dialler = match open_with(Z_CONFIG_CONNECT_KEY, connect) {
            Ok(session) => session,
            Err(rc) => {
                z_undeclare_subscriber(z_subscriber_move(&mut sub));
                close_session(&mut listener);
                panic!("z_open(connect={connect}) failed with {rc}");
            }
        };

        let deadline = Instant::now() + CROSSING_BOUND;
        while received.lock().unwrap().is_empty() && Instant::now() < deadline {
            put(&dialler);
            std::thread::sleep(Duration::from_millis(20));
        }

        z_undeclare_subscriber(z_subscriber_move(&mut sub));
        close_session(&mut dialler);
        close_session(&mut listener);
    }
    let mut payloads = received.lock().unwrap();
    std::mem::take(&mut *payloads)
}
