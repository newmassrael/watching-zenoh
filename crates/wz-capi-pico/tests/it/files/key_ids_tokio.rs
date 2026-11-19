// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! Two sessions of the tokio engine, through the C doors, that hold one dictionary of key ids and
//! state the key-wire form `shared` for the endpoint between them: a put by a key's own id, a put
//! by an id and the rest of the key, and a get by an id and the rest, none of which a
//! declaration precedes, reach the other end. The CONTROL is a listener that holds no
//! dictionary: it drops what is named by an id it was never declared, and hears the put that
//! the dictionary does not cover, which goes as the literal. The ids and keys are synthetic.
#![cfg(all(
    feature = "shared-key-ids",
    feature = "engine-tokio",
    feature = "peer",
    feature = "query",
    feature = "queryable"
))]

use std::collections::BTreeSet;
use std::ffi::{c_void, CStr, CString};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_pico::key_ids::{wz_ext_config_key_ids, wz_ext_config_key_wire_form_for};
use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_bytes_to_slice, z_close, z_closure_query,
    z_closure_query_move, z_closure_reply, z_closure_reply_move, z_closure_sample,
    z_closure_sample_move, z_config_default, z_config_loan_mut, z_config_move, z_declare_queryable,
    z_declare_subscriber, z_get, z_keyexpr_as_view_string, z_loaned_query_t, z_loaned_reply_t,
    z_loaned_sample_t, z_open, z_owned_closure_reply_t, z_owned_config_t, z_owned_queryable_t,
    z_owned_session_t, z_owned_slice_t, z_owned_subscriber_t, z_put, z_query_keyexpr,
    z_query_reply, z_queryable_move, z_reply_is_ok, z_reply_ok, z_sample_keyexpr, z_sample_payload,
    z_session_drop, z_session_loan, z_session_loan_mut, z_session_move, z_slice_data, z_slice_drop,
    z_slice_len, z_slice_loan, z_slice_move, z_string_data, z_string_len, z_subscriber_move,
    z_undeclare_queryable, z_undeclare_subscriber, z_view_keyexpr_from_str, z_view_keyexpr_loan,
    z_view_keyexpr_t, z_view_string_loan, z_view_string_t, zp_config_insert, Z_CONFIG_CONNECT_KEY,
    Z_CONFIG_LISTEN_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// The dictionary every session here that holds one holds: a key, a key below it, and a prefix
/// a get names its key under.
const IDS: [u16; 3] = [40, 41, 43];
const KEYS: [&CStr; 3] = [c"lab/rig", c"lab/rig/alpha", c"lab/q"];

/// Open a session whose config states `endpoint` under `key`, the dictionary when `holds`, and
/// `form` for that endpoint.
unsafe fn open_with(key: u8, endpoint: &str, holds: bool, form: &CStr) -> z_owned_session_t {
    let text = CString::new(endpoint).expect("an endpoint holds no NUL");
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, text.as_ptr()),
        Z_OK
    );
    if holds {
        let keys: Vec<*const std::ffi::c_char> = KEYS.iter().map(|key| key.as_ptr()).collect();
        assert_eq!(
            wz_ext_config_key_ids(
                z_config_loan_mut(&mut cfg),
                IDS.as_ptr(),
                keys.as_ptr(),
                IDS.len()
            ),
            Z_OK
        );
    }
    assert_eq!(
        wz_ext_config_key_wire_form_for(z_config_loan_mut(&mut cfg), text.as_ptr(), form.as_ptr()),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK
    );
    session
}

unsafe fn close_session(session: &mut z_owned_session_t) {
    z_close(z_session_loan_mut(session), std::ptr::null());
    z_session_drop(z_session_move(session));
}

/// The keys a subscriber heard.
type Heard = Arc<Mutex<BTreeSet<String>>>;

unsafe extern "C" fn on_sample(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let heard = &*(ctx as *const Heard);
    let mut view: z_view_string_t = std::mem::zeroed();
    if z_keyexpr_as_view_string(z_sample_keyexpr(sample), &mut view) != Z_OK {
        return;
    }
    let string = z_view_string_loan(&view);
    let (data, len) = (z_string_data(string), z_string_len(string));
    if data.is_null() {
        return;
    }
    if let Ok(key) = std::str::from_utf8(std::slice::from_raw_parts(data as *const u8, len)) {
        heard.lock().unwrap().insert(key.to_owned());
    }
}

unsafe extern "C" fn on_sample_drop(ctx: *mut c_void) {
    drop(Box::from_raw(ctx as *mut Heard));
}

/// A subscriber of `session` on `lab/**`, and the keys it hears.
unsafe fn hear(session: &z_owned_session_t) -> (z_owned_subscriber_t, Heard) {
    let heard: Heard = Arc::new(Mutex::new(BTreeSet::new()));
    let ctx = Box::into_raw(Box::new(heard.clone())) as *mut c_void;
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_sample(&mut closure, Some(on_sample), Some(on_sample_drop), ctx),
        Z_OK
    );
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, c"lab/**".as_ptr()), Z_OK);
    let mut sub: z_owned_subscriber_t = std::mem::zeroed();
    assert_eq!(
        z_declare_subscriber(
            z_session_loan(session),
            &mut sub,
            z_view_keyexpr_loan(&ke),
            z_closure_sample_move(&mut closure),
            std::ptr::null(),
        ),
        Z_OK
    );
    (sub, heard)
}

unsafe fn put(session: &z_owned_session_t, key: &CStr) {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
    let mut buf = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut buf, c"value".as_ptr()), Z_OK);
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

/// Put each of `keys` from `from`, in order, until `heard` holds `until`: what it holds then.
unsafe fn put_until(
    from: &z_owned_session_t,
    keys: &[&CStr],
    heard: &Heard,
    until: &str,
) -> BTreeSet<String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !heard.lock().unwrap().contains(until) {
        assert!(Instant::now() < deadline, "{until} was never heard");
        for key in keys {
            put(from, key);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    heard.lock().unwrap().clone()
}

/// What the listener hears of puts on a key the dictionary holds, a key below one of its
/// entries, and a key it does not cover, from a dialler that holds the dictionary and states the
/// endpoint `shared`, when the listener holds it (`listener_holds`) or not.
fn heard_by_a_listener(listener_holds: bool) -> BTreeSet<String> {
    let endpoint = format!("tcp/127.0.0.1:{}", free_port());
    // SAFETY: fresh configs, sessions and a subscriber, all released before the function returns.
    unsafe {
        let listener_form = if listener_holds {
            c"shared"
        } else {
            c"declared"
        };
        let mut listener = open_with(
            Z_CONFIG_LISTEN_KEY,
            &endpoint,
            listener_holds,
            listener_form,
        );
        let (mut sub, heard) = hear(&listener);
        let mut dialler = open_with(Z_CONFIG_CONNECT_KEY, &endpoint, true, c"shared");
        let keys = [c"lab/rig/alpha", c"lab/rig/gamma", c"lab/mark"];
        let heard = put_until(&dialler, &keys, &heard, "lab/mark");
        z_undeclare_subscriber(z_subscriber_move(&mut sub));
        close_session(&mut dialler);
        close_session(&mut listener);
        heard
    }
}

#[test]
fn puts_by_a_shared_id_and_by_an_id_and_the_rest_reach_a_session_that_holds_the_dictionary() {
    let heard = heard_by_a_listener(true);
    assert!(
        heard.contains("lab/rig/alpha"),
        "by the key's own id: {heard:?}"
    );
    assert!(
        heard.contains("lab/rig/gamma"),
        "by an id and the rest: {heard:?}"
    );
}

#[test]
fn a_session_without_the_dictionary_drops_what_an_id_names_and_hears_the_literal() {
    let heard = heard_by_a_listener(false);
    assert_eq!(
        heard,
        BTreeSet::from(["lab/mark".to_owned()]),
        "CONTROL: only the key the dictionary does not cover went as the literal"
    );
}

unsafe extern "C" fn on_query(query: *const z_loaned_query_t, _ctx: *mut c_void) {
    let mut bytes = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut bytes, c"answer".as_ptr()), Z_OK);
    let _ = z_query_reply(
        query,
        z_query_keyexpr(query),
        z_bytes_move(&mut bytes),
        std::ptr::null(),
    );
}

/// What a get's closure saw: each reply's payload, and whether the closure was dropped.
#[derive(Default)]
struct Asked {
    replies: Vec<String>,
    done: bool,
}

unsafe extern "C" fn on_reply(reply: *mut z_loaned_reply_t, ctx: *mut c_void) {
    let asked = &*(ctx as *const Mutex<Asked>);
    if !z_reply_is_ok(reply) {
        asked.lock().unwrap().replies.push("err".to_owned());
        return;
    }
    let mut slice: z_owned_slice_t = std::mem::zeroed();
    assert_eq!(
        z_bytes_to_slice(z_sample_payload(z_reply_ok(reply)), &mut slice),
        Z_OK
    );
    let loaned = z_slice_loan(&slice);
    let bytes = std::slice::from_raw_parts(z_slice_data(loaned), z_slice_len(loaned));
    asked
        .lock()
        .unwrap()
        .replies
        .push(String::from_utf8_lossy(bytes).into_owned());
    z_slice_drop(z_slice_move(&mut slice));
}

unsafe extern "C" fn on_reply_drop(ctx: *mut c_void) {
    let asked = Arc::from_raw(ctx as *const Mutex<Asked>);
    asked.lock().unwrap().done = true;
}

#[test]
fn a_get_by_an_id_and_the_rest_is_answered_by_a_session_that_holds_the_dictionary() {
    let endpoint = format!("tcp/127.0.0.1:{}", free_port());
    // SAFETY: fresh configs, sessions and a queryable, all released before the function returns.
    unsafe {
        let mut listener = open_with(Z_CONFIG_LISTEN_KEY, &endpoint, true, c"shared");
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_query(&mut closure, Some(on_query), None, std::ptr::null_mut()),
            Z_OK
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, c"lab/q/**".as_ptr()), Z_OK);
        let mut queryable: z_owned_queryable_t = std::mem::zeroed();
        assert_eq!(
            z_declare_queryable(
                z_session_loan(&listener),
                &mut queryable,
                z_view_keyexpr_loan(&ke),
                z_closure_query_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK
        );
        let mut dialler = open_with(Z_CONFIG_CONNECT_KEY, &endpoint, true, c"shared");
        // The listener's queryable reaches the dialler before it asks.
        std::thread::sleep(Duration::from_millis(300));

        let asked = Arc::new(Mutex::new(Asked::default()));
        let mut reply: z_owned_closure_reply_t = std::mem::zeroed();
        assert_eq!(
            z_closure_reply(
                &mut reply,
                Some(on_reply),
                Some(on_reply_drop),
                Arc::into_raw(asked.clone()) as *mut c_void
            ),
            Z_OK
        );
        let mut key: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut key, c"lab/q/x".as_ptr()), Z_OK);
        assert_eq!(
            z_get(
                z_session_loan(&dialler),
                z_view_keyexpr_loan(&key),
                std::ptr::null(),
                z_closure_reply_move(&mut reply),
                std::ptr::null_mut(),
            ),
            Z_OK
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !asked.lock().unwrap().done {
            assert!(Instant::now() < deadline, "the get never ended");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(asked.lock().unwrap().replies, ["answer"]);

        z_undeclare_queryable(z_queryable_move(&mut queryable));
        close_session(&mut dialler);
        close_session(&mut listener);
    }
}
