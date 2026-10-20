// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A node that listens, for a test of the build that cannot: `hold_a_listener <port>`.
//!
//! A build without the `peer` feature has no listener, so the test of what it can do (open a
//! client session to a node, publish to it and hear from it) needs a node of the full build to
//! dial. This is that node. It listens on `tcp/127.0.0.1:<port>`, subscribes to `demo/**` and
//! prints the key of every sample it hears as `heard <key>`, and publishes `demo/from-listener`
//! every 50 ms. It prints `READY` once it listens and runs until its standard input closes.

use std::ffi::{c_void, CStr, CString};
use std::io::Read;
use std::time::Duration;

use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_sample, z_closure_sample_move,
    z_config_default, z_config_loan_mut, z_config_move, z_declare_subscriber,
    z_keyexpr_as_view_string, z_loaned_sample_t, z_open, z_owned_config_t, z_owned_session_t,
    z_owned_subscriber_t, z_put, z_sample_keyexpr, z_session_drop, z_session_loan,
    z_session_loan_mut, z_session_move, z_string_data, z_string_len, z_view_keyexpr_from_str,
    z_view_keyexpr_loan, z_view_keyexpr_t, z_view_string_loan, z_view_string_t, zp_config_insert,
    Z_CONFIG_LISTEN_KEY, Z_OK,
};

unsafe extern "C" fn on_sample(sample: *const z_loaned_sample_t, _ctx: *mut c_void) {
    let ke = z_sample_keyexpr(sample);
    let mut view: z_view_string_t = std::mem::zeroed();
    if z_keyexpr_as_view_string(ke, &mut view) != Z_OK {
        return;
    }
    let string = z_view_string_loan(&view);
    let (data, len) = (z_string_data(string), z_string_len(string));
    if data.is_null() {
        return;
    }
    if let Ok(key) = std::str::from_utf8(std::slice::from_raw_parts(data as *const u8, len)) {
        println!("heard {key}");
    }
}

unsafe fn put(session: &z_owned_session_t, key: &CStr, payload: &CStr) {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
    let mut buf = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut buf, payload.as_ptr()), Z_OK);
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

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|text| text.parse().ok())
        .expect("usage: hold_a_listener <port>");
    // SAFETY: fresh config, session and subscriber, all released before the process ends.
    unsafe {
        let mut cfg: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut cfg), Z_OK);
        let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
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
            Z_OK
        );

        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_sample(&mut closure, Some(on_sample), None, std::ptr::null_mut()),
            Z_OK
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/**".as_ptr()), Z_OK);
        let mut sub: z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&session),
                &mut sub,
                z_view_keyexpr_loan(&ke),
                z_closure_sample_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK
        );
        println!("READY");

        let (closed_tx, closed_rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            let mut sink = Vec::new();
            let _ = std::io::stdin().read_to_end(&mut sink);
            let _ = closed_tx.send(());
        });
        while closed_rx.recv_timeout(Duration::from_millis(50)).is_err() {
            put(&session, c"demo/from-listener", c"payload");
        }

        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
    }
}
