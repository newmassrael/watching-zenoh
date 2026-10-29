// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The resource snapshot a program has taken is a document of its admin space, asked by a peer
//! (`docs/observation-plane.md` M4).
//!
//! One test, in a process of its own, because the sampler is the process's and a snapshot taken
//! here would show in any admin space of the same process. The listener starts its admin space; a
//! dialling session asks `@/<listener zid>/pico/**` before the program has taken a snapshot and
//! then for `@/<listener zid>/pico/wz/snapshot` after. Before, the other documents answer and this
//! one does not: the negative arm beside a positive one on the same pair of sessions.

#![cfg(all(
    feature = "resource-snapshot",
    feature = "admin-space",
    feature = "peer",
    feature = "query"
))]

use std::ffi::{c_void, CStr, CString};
use std::sync::Mutex;
use std::time::Duration;

use wz_capi_pico::admin_space::zp_start_admin_space;
use wz_capi_pico::snapshot::{
    wz_ext_resource_reading_t, wz_ext_snapshot_poll, wz_ext_snapshot_set_source,
    WZ_EXT_SNAPSHOT_HAS_CPU, WZ_EXT_SNAPSHOT_HAS_HEAP, WZ_EXT_SNAPSHOT_HAS_TASKS,
};
use wz_capi_pico::zid::{z_id_to_string, z_info_zid};
use wz_capi_pico::{
    z_bytes_to_string, z_close, z_closure_reply, z_closure_reply_move, z_config_default,
    z_config_loan_mut, z_config_move, z_encoding_to_string, z_get, z_get_options_default,
    z_get_options_t, z_keyexpr_as_view_string, z_loaned_reply_t, z_loaned_string_t, z_open,
    z_owned_config_t, z_owned_session_t, z_owned_string_t, z_reply_is_ok, z_reply_ok,
    z_sample_encoding, z_sample_keyexpr, z_sample_payload, z_session_drop, z_session_loan,
    z_session_loan_mut, z_session_move, z_string_data, z_string_drop, z_string_len, z_string_loan,
    z_string_move, z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t,
    z_view_string_loan, z_view_string_t, zp_config_insert, Z_CONFIG_CONNECT_KEY,
    Z_CONFIG_LISTEN_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// One reply as the C side read it: key, payload, encoding.
type Reply = (String, String, String);

/// What the reply callback saw. Failures inside the callback are recorded, not asserted: a panic
/// there is caught at the ABI boundary and would read as "no reply arrived".
#[derive(Default)]
struct Probe {
    replies: Mutex<Vec<Reply>>,
    errors: Mutex<Vec<String>>,
}

unsafe fn text(string: *const z_loaned_string_t) -> String {
    let data = z_string_data(string);
    if data.is_null() {
        return String::new();
    }
    let bytes = std::slice::from_raw_parts(data.cast::<u8>(), z_string_len(string));
    String::from_utf8_lossy(bytes).into_owned()
}

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

unsafe fn open_with(key: u8, endpoint: &CStr) -> Option<z_owned_session_t> {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    (z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()) == Z_OK).then_some(session)
}

/// Dial `endpoint`, retrying while the listener's bind settles.
unsafe fn dial(endpoint: &CStr) -> z_owned_session_t {
    for _ in 0..250 {
        if let Some(session) = open_with(Z_CONFIG_CONNECT_KEY, endpoint) {
            return session;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("the dialler's z_open never succeeded");
}

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
        let replies = probe.replies.lock().unwrap().clone();
        if replies.iter().any(|(key, _, _)| key == wanted) {
            return replies;
        }
    }
    panic!(
        "no reply on `{wanted}` arrived; replies seen: {:?}",
        probe.replies.lock().unwrap()
    );
}

unsafe extern "C" fn platform(_context: *mut c_void, out: *mut wz_ext_resource_reading_t) -> i8 {
    *out = wz_ext_resource_reading_t {
        available: WZ_EXT_SNAPSHOT_HAS_CPU | WZ_EXT_SNAPSHOT_HAS_HEAP | WZ_EXT_SNAPSHOT_HAS_TASKS,
        cpu_permille: 420,
        tasks: 7,
        heap_in_use: 10_000,
        heap_high_water: 12_000,
        ..Default::default()
    };
    0
}

#[test]
fn a_peer_reads_the_snapshot_once_the_program_has_taken_one() {
    let port = free_port();
    let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let probe = Probe::default();

    // SAFETY: fresh configs and sessions, each closed before the function returns.
    unsafe {
        let mut listener = open_with(Z_CONFIG_LISTEN_KEY, &endpoint).expect("listener z_open");
        let mut dialer = dial(&endpoint);
        let listener_zid = zid_of(&listener);
        let everything = CString::new(format!("@/{listener_zid}/pico/**")).unwrap();
        let root = format!("@/{listener_zid}/pico");
        // Under the wz-owned root, as the hosted admin space serves its own, and not inside pico's
        // tree at `@/<zid>/pico`.
        let key = format!("wz/@/{listener_zid}/snapshot");
        let after_key = CString::new(key.clone()).unwrap();
        assert_eq!(
            zp_start_admin_space(z_session_loan_mut(&mut listener)),
            Z_OK
        );

        // Before a snapshot: the admin space answers with pico's documents, and the snapshot's key
        // answers nothing, since nobody took one.
        ask_until(&dialer, &everything, &probe, &root);
        probe.replies.lock().unwrap().clear();
        get_once(&dialer, &after_key, &probe);
        std::thread::sleep(Duration::from_millis(600));
        assert!(
            probe.replies.lock().unwrap().is_empty(),
            "a snapshot nobody took is not a document: {:?}",
            probe.replies.lock().unwrap()
        );

        // After: the document is the snapshot, as JSON, with what the source answered.
        assert_eq!(
            wz_ext_snapshot_set_source(Some(platform), std::ptr::null_mut()),
            Z_OK
        );
        assert_eq!(wz_ext_snapshot_poll(z_session_loan(&listener)), 1);
        let replies = ask_until(&dialer, &after_key, &probe, &key);
        assert!(probe.errors.lock().unwrap().is_empty());
        let (_, document, encoding) = replies
            .iter()
            .find(|(reply_key, _, _)| *reply_key == key)
            .expect("ask_until returned without the snapshot reply");
        assert_eq!(encoding, "application/json");
        for part in [
            "\"version\":1",
            "\"sequence\":0",
            "\"cpu_permille\":420",
            "\"tasks\":7",
            "\"heap\":{\"in_use\":10000,\"high_water\":12000}",
            "\"resource-snapshot\"",
            "\"messages\":",
            "\"intervals\":[",
        ] {
            assert!(document.contains(part), "`{part}` is not in {document}");
        }

        // The property the wz root exists for: a query for pico's own documents, asked now that a
        // snapshot exists, still meets exactly the documents pico has and not this one.
        std::thread::sleep(Duration::from_millis(600));
        probe.replies.lock().unwrap().clear();
        let pico_documents = ask_until(&dialer, &everything, &probe, &root);
        assert!(
            pico_documents
                .iter()
                .all(|(reply_key, _, _)| reply_key.starts_with(&format!("@/{listener_zid}/pico"))),
            "pico's tree holds only pico's documents: {pico_documents:?}"
        );

        z_close(z_session_loan_mut(&mut dialer), std::ptr::null());
        z_session_drop(z_session_move(&mut dialer));
        z_close(z_session_loan_mut(&mut listener), std::ptr::null());
        z_session_drop(z_session_move(&mut listener));
    }
}
