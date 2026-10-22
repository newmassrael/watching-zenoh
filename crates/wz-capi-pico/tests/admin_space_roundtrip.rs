// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A pico session's admin space, asked by a peer over the wire.
//!
//! The listener starts its admin space and a dialling session gets
//! `@/<listener zid>/pico/**` through the exported `z_get`, reading every reply
//! the way a pico program does. The same get is asked before the start and after
//! the stop, and both times nothing answers: the queryable exists exactly while
//! the admin space runs. "Nothing answered" alone is satisfied by a broken get or
//! session, so each negative arm sits beside a positive one on the same pair of
//! sessions.

use std::ffi::{c_void, CStr, CString};
use std::sync::Mutex;
use std::time::Duration;

use wz_capi_pico::admin_space::{zp_start_admin_space, zp_stop_admin_space};
use wz_capi_pico::zid::{z_id_to_string, z_info_zid};
use wz_capi_pico::{
    z_bytes_to_string, z_close, z_closure_reply, z_closure_reply_move, z_config_default,
    z_config_loan_mut, z_config_move, z_encoding_to_string, z_get, z_get_options_default,
    z_get_options_t, z_keyexpr_as_view_string, z_loaned_reply_t, z_loaned_string_t, z_open,
    z_open_options_default, z_open_options_t, z_owned_config_t, z_owned_session_t,
    z_owned_string_t, z_reply_is_ok, z_reply_ok, z_sample_encoding, z_sample_keyexpr,
    z_sample_payload, z_session_drop, z_session_loan, z_session_loan_mut, z_session_move,
    z_string_data, z_string_drop, z_string_len, z_string_loan, z_string_move,
    z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t, z_view_string_loan,
    z_view_string_t, zp_config_insert, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// One reply as the C side read it: key, payload, encoding.
type Reply = (String, String, String);

/// What the reply callback saw. Failures inside the callback are recorded, not
/// asserted: a panic there is caught at the ABI boundary and would read as "no
/// reply arrived".
#[derive(Default)]
struct Probe {
    replies: Mutex<Vec<Reply>>,
    errors: Mutex<Vec<String>>,
}

impl Probe {
    fn replies(&self) -> Vec<Reply> {
        self.replies.lock().unwrap().clone()
    }

    fn clear(&self) {
        self.replies.lock().unwrap().clear();
    }

    fn assert_no_callback_errors(&self) {
        let errors = self.errors.lock().unwrap();
        assert!(errors.is_empty(), "the C reply callback failed: {errors:?}");
    }
}

unsafe fn text(string: *const z_loaned_string_t) -> String {
    let data = z_string_data(string);
    if data.is_null() {
        return String::new();
    }
    let bytes = std::slice::from_raw_parts(data.cast::<u8>(), z_string_len(string));
    String::from_utf8_lossy(bytes).into_owned()
}

/// Read an owned string out and release it.
unsafe fn take_text(owned: &mut z_owned_string_t) -> String {
    let read = text(z_string_loan(owned));
    z_string_drop(z_string_move(owned));
    read
}

unsafe extern "C" fn on_reply(reply: *mut z_loaned_reply_t, ctx: *mut c_void) {
    let probe = &*(ctx as *const Probe);
    let fail = |msg: &str| probe.errors.lock().unwrap().push(msg.to_owned());
    if !z_reply_is_ok(reply) {
        fail("an admin space reply was not a data reply");
        return;
    }
    let sample = z_reply_ok(reply);
    if sample.is_null() {
        fail("z_reply_ok returned null for an ok reply");
        return;
    }
    let mut view: z_view_string_t = std::mem::zeroed();
    if z_keyexpr_as_view_string(z_sample_keyexpr(sample), &mut view) != Z_OK {
        fail("z_keyexpr_as_view_string failed on the reply key");
        return;
    }
    let key = text(z_view_string_loan(&view));
    let mut payload: z_owned_string_t = std::mem::zeroed();
    if z_bytes_to_string(z_sample_payload(sample), &mut payload) != Z_OK {
        fail("z_bytes_to_string failed on the reply payload");
        return;
    }
    let payload = take_text(&mut payload);
    let mut encoding: z_owned_string_t = std::mem::zeroed();
    if z_encoding_to_string(z_sample_encoding(sample), &mut encoding) != Z_OK {
        fail("z_encoding_to_string failed on the reply encoding");
        return;
    }
    let encoding = take_text(&mut encoding);
    probe.replies.lock().unwrap().push((key, payload, encoding));
}

unsafe fn open_with(
    key: u8,
    endpoint: &CStr,
    options: *const z_open_options_t,
) -> Option<z_owned_session_t> {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    if z_open(&mut session, z_config_move(&mut cfg), options) == Z_OK {
        Some(session)
    } else {
        None
    }
}

/// Dial `endpoint`, retrying while the listener's bind settles.
unsafe fn dial(endpoint: &CStr) -> z_owned_session_t {
    for _ in 0..250 {
        if let Some(session) = open_with(Z_CONFIG_CONNECT_KEY, endpoint, std::ptr::null()) {
            return session;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("the dialler's z_open never succeeded");
}

/// The zid of `session` as `z_id_to_string` spells it.
unsafe fn zid_of(session: &z_owned_session_t) -> String {
    let id = z_info_zid(z_session_loan(session));
    let mut owned: z_owned_string_t = std::mem::zeroed();
    assert_eq!(z_id_to_string(&id, &mut owned), Z_OK);
    take_text(&mut owned)
}

/// Issue one `z_get` on `keyexpr` from `session`, its replies read into `probe`.
unsafe fn get_once(session: &z_owned_session_t, keyexpr: &CStr, probe: &Probe) {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, keyexpr.as_ptr()), Z_OK);
    let mut closure = std::mem::zeroed();
    let ctx = probe as *const Probe as *mut c_void;
    assert_eq!(
        z_closure_reply(&mut closure, Some(on_reply), None, ctx),
        Z_OK
    );
    let mut options: z_get_options_t = std::mem::zeroed();
    z_get_options_default(&mut options);
    assert_eq!(
        z_get(
            z_session_loan(session),
            z_view_keyexpr_loan(&ke),
            std::ptr::null(),
            z_closure_reply_move(&mut closure),
            &mut options,
        ),
        Z_OK
    );
}

/// Ask until a reply on `wanted` arrives, bounded; the replies seen by then.
unsafe fn ask_until(
    session: &z_owned_session_t,
    keyexpr: &CStr,
    probe: &Probe,
    wanted: &str,
) -> Vec<Reply> {
    for _ in 0..250 {
        get_once(session, keyexpr, probe);
        std::thread::sleep(Duration::from_millis(20));
        let replies = probe.replies();
        if replies.iter().any(|(key, _, _)| key == wanted) {
            return replies;
        }
    }
    panic!(
        "no reply on `{wanted}` arrived; replies seen: {:?}",
        probe.replies()
    );
}

/// One get, then long enough for any reply to land; the replies seen.
unsafe fn ask_once_and_wait(
    session: &z_owned_session_t,
    keyexpr: &CStr,
    probe: &Probe,
) -> Vec<Reply> {
    get_once(session, keyexpr, probe);
    std::thread::sleep(Duration::from_millis(600));
    probe.replies()
}

#[test]
fn a_peer_reads_the_admin_space_while_it_runs_and_not_before_or_after() {
    let port = free_port();
    let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let probe = Probe::default();

    unsafe {
        let mut listener = open_with(Z_CONFIG_LISTEN_KEY, &endpoint, std::ptr::null())
            .expect("listener z_open failed");
        let mut dialer = dial(&endpoint);
        let listener_zid = zid_of(&listener);
        let dialer_zid = zid_of(&dialer);
        let query = CString::new(format!("@/{listener_zid}/pico/**")).unwrap();
        let root = format!("@/{listener_zid}/pico");
        let peer_key = format!("@/{listener_zid}/pico/session/transports/0/peers/{dialer_zid}");

        // Before the start nothing answers.
        let before = ask_once_and_wait(&dialer, &query, &probe);
        assert!(before.is_empty(), "replies before the start: {before:?}");

        assert_eq!(
            zp_start_admin_space(z_session_loan_mut(&mut listener)),
            Z_OK
        );
        assert_eq!(
            zp_start_admin_space(z_session_loan_mut(&mut listener)),
            Z_OK,
            "a second start is pico's no-op, not an error"
        );

        let replies = ask_until(&dialer, &query, &probe, &peer_key);
        probe.assert_no_callback_errors();
        let (_, root_doc, root_encoding) = replies
            .iter()
            .find(|(key, _, _)| *key == root)
            .unwrap_or_else(|| panic!("no reply on `{root}`: {replies:?}"));
        assert_eq!(root_encoding, "application/json");
        let head = format!("{{\"session\":{{\"zid\":\"{listener_zid}\",\"whatami\":\"peer\",");
        assert!(root_doc.starts_with(&head), "{root_doc}");
        let address = format!("\"address\":\"127.0.0.1:{port}\"");
        assert!(
            root_doc.contains(&address),
            "the link is the listen locator: {root_doc}"
        );
        let peer_doc = format!("{{\"zid\":\"{dialer_zid}\",\"whatami\":\"client\"}}");
        assert!(
            root_doc.contains(&format!("\"peers\":[{peer_doc}]")),
            "the dialler is the transport's one peer: {root_doc}"
        );
        let (_, peer_reply, _) = replies
            .iter()
            .find(|(key, _, _)| *key == peer_key)
            .expect("ask_until returned without the peer reply");
        assert_eq!(*peer_reply, peer_doc);

        // Let the gets still in flight land before the stop, so a late reply to
        // one of them cannot be read as an answer after it.
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(zp_stop_admin_space(z_session_loan_mut(&mut listener)), Z_OK);
        assert_eq!(
            zp_stop_admin_space(z_session_loan_mut(&mut listener)),
            Z_OK,
            "a second stop is pico's no-op, not an error"
        );
        probe.clear();
        let after = ask_once_and_wait(&dialer, &query, &probe);
        assert!(after.is_empty(), "replies after the stop: {after:?}");

        // A stopped admin space starts again.
        assert_eq!(
            zp_start_admin_space(z_session_loan_mut(&mut listener)),
            Z_OK
        );
        ask_until(&dialer, &query, &probe, &root);
        probe.assert_no_callback_errors();

        z_close(z_session_loan_mut(&mut dialer), std::ptr::null());
        z_session_drop(z_session_move(&mut dialer));
        z_close(z_session_loan_mut(&mut listener), std::ptr::null());
        z_session_drop(z_session_move(&mut listener));
    }
}

#[test]
fn the_open_option_starts_the_admin_space_and_defaults_off() {
    let port = free_port();
    let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let probe = Probe::default();

    unsafe {
        let mut options: z_open_options_t = std::mem::zeroed();
        options.auto_start_admin_space = true;
        z_open_options_default(&mut options);
        assert!(
            !options.auto_start_admin_space,
            "pico's default leaves the admin space stopped"
        );
        options.auto_start_admin_space = true;
        let mut listener =
            open_with(Z_CONFIG_LISTEN_KEY, &endpoint, &options).expect("listener z_open failed");
        let mut dialer = dial(&endpoint);
        let listener_zid = zid_of(&listener);
        let session_key = format!("@/{listener_zid}/pico/session");
        let query = CString::new(session_key.clone()).unwrap();
        let replies = ask_until(&dialer, &query, &probe, &session_key);
        probe.assert_no_callback_errors();
        assert!(
            replies.iter().all(|(key, _, _)| *key == session_key),
            "an exact query is answered on its own key only: {replies:?}"
        );

        assert_eq!(zp_stop_admin_space(z_session_loan_mut(&mut listener)), Z_OK);
        z_close(z_session_loan_mut(&mut dialer), std::ptr::null());
        z_session_drop(z_session_move(&mut dialer));
        z_close(z_session_loan_mut(&mut listener), std::ptr::null());
        z_session_drop(z_session_move(&mut listener));
    }
}
