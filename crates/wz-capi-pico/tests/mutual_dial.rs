// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A node that restarts while its old dialler still redials it ends with ONE transport on each
//! side, the other node's, and what each puts reaches the other.
//!
//! A pico config carrying `listen` and `connect` opens a session that is both. Session `a` listens
//! and dials `b`, a plain listener; `b` goes away and `a`'s dial role redials its endpoint every
//! second, as pico does while a reopen fails. `b` then comes back, a node of a new zid on the same
//! port, and dials `a` in the same breath. The two ends are now each other's dialler: the link
//! `b` opens and the link `a`'s redial opens go between one pair of nodes, and a session holds one
//! face for each remote zid (`docs/capi-pico-on-coop-engine.md`, step L5). It must close one and
//! keep the other, and both ends must keep the SAME one, or each closes the link the other kept
//! and the pair is left with none. The engine's own test (`wz-capi-coop`, `tests::one_face`) runs
//! that race with the engine against itself; this reaches it through the exported `z_*` symbols,
//! as two C programs would, whichever engine the build selects.
//!
//! Two sessions cannot be opened at one moment to dial each other: a `z_open` that dials a port
//! nothing listens on yet fails, one attempt, as pico's does, and whichever opens first dials a
//! port the other has not bound. The restart is how this ABI reaches the race at all.
//!
//! The listing is read twice, with a pause longer than the redial period, because a pair that
//! closed both links reads none, and one that closed them late reads one first and none after.
//! What the ABI cannot show is whether the redial reached the new node before the pause ended: a
//! link refused at its admission leaves no event. The result is what is held: one transport on each
//! side, naming the other node, however the two links went.

use std::collections::BTreeSet;
use std::ffi::{c_void, CStr, CString};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_pico::connectivity::{
    z_closure_transport, z_closure_transport_move, z_info_transports, z_loaned_transport_t,
    z_owned_closure_transport_t,
};
use wz_capi_pico::zid::z_info_zid;
use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_sample, z_closure_sample_move,
    z_config_default, z_config_loan_mut, z_config_move, z_declare_subscriber,
    z_keyexpr_as_view_string, z_loaned_sample_t, z_open, z_owned_config_t, z_owned_session_t,
    z_owned_subscriber_t, z_put, z_sample_keyexpr, z_session_drop, z_session_loan,
    z_session_loan_mut, z_session_move, z_string_data, z_string_len, z_subscriber_move,
    z_undeclare_subscriber, z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t,
    z_view_string_loan, z_view_string_t, zp_config_insert, Z_CONFIG_CONNECT_KEY,
    Z_CONFIG_LISTEN_KEY, Z_CONFIG_SESSION_ZID_KEY, Z_ERR_INVALID, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

struct SetCtx {
    seen: Arc<Mutex<BTreeSet<String>>>,
}

unsafe extern "C" fn on_sample_record_keyexpr(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const SetCtx);
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
        ctx.seen.lock().unwrap().insert(key.to_owned());
    }
}

unsafe extern "C" fn on_drop_set(ctx: *mut c_void) {
    drop(Box::from_raw(ctx as *mut SetCtx));
}

/// A session that listens on `listen` and, when `connect` names a port, dials it.
/// A session that listens on `listen`, dials `connect` when given, and opens on `zid`: the id
/// `Z_CONFIG_SESSION_ZID_KEY` names, as a UUID.
unsafe fn open(listen: u16, connect: Option<u16>, zid: &CStr) -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(
            z_config_loan_mut(&mut cfg),
            Z_CONFIG_SESSION_ZID_KEY,
            zid.as_ptr()
        ),
        Z_OK
    );
    let ends = [
        (Z_CONFIG_LISTEN_KEY, Some(listen)),
        (Z_CONFIG_CONNECT_KEY, connect),
    ];
    for (key, port) in ends {
        let Some(port) = port else { continue };
        let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
        assert_eq!(
            zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
            Z_OK
        );
    }
    let mut session: z_owned_session_t = std::mem::zeroed();
    let rc = z_open(&mut session, z_config_move(&mut cfg), std::ptr::null());
    assert_eq!(
        rc, Z_OK,
        "the open of listen {listen} and connect {connect:?}"
    );
    session
}

unsafe fn put(session: &z_owned_session_t, key: &CStr) {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
    let mut buf = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut buf, c"payload".as_ptr()), Z_OK);
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

/// A subscriber on `demo/**` of `session`, and the keys it has heard.
unsafe fn hearing(
    session: &z_owned_session_t,
) -> (Arc<Mutex<BTreeSet<String>>>, z_owned_subscriber_t) {
    let seen = Arc::new(Mutex::new(BTreeSet::new()));
    let ctx = Box::into_raw(Box::new(SetCtx { seen: seen.clone() })) as *mut c_void;
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_sample(
            &mut closure,
            Some(on_sample_record_keyexpr),
            Some(on_drop_set),
            ctx
        ),
        Z_OK
    );
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/**".as_ptr()), Z_OK);
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
    (seen, sub)
}

/// Put `key` from `from` until `seen` holds it, for at most ten seconds.
unsafe fn put_until_seen(
    from: &z_owned_session_t,
    key: &CStr,
    seen: &Arc<Mutex<BTreeSet<String>>>,
) -> bool {
    let wanted = key.to_str().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if seen.lock().unwrap().contains(wanted) {
            return true;
        }
        put(from, key);
        std::thread::sleep(Duration::from_millis(20));
    }
    seen.lock().unwrap().contains(wanted)
}

unsafe extern "C" fn on_transport(transport: *mut z_loaned_transport_t, ctx: *mut c_void) {
    let listed = &*(ctx as *const Mutex<Vec<[u8; 16]>>);
    listed.lock().unwrap().push((*transport).zid.id);
}

/// The zids of the transports `session` lists now: one for each remote node it is connected to.
unsafe fn transports(session: &z_owned_session_t) -> Vec<[u8; 16]> {
    let listed: &'static Mutex<Vec<[u8; 16]>> = Box::leak(Box::default());
    let mut closure: z_owned_closure_transport_t = std::mem::zeroed();
    assert_eq!(
        z_closure_transport(
            &mut closure,
            Some(on_transport),
            None,
            listed as *const Mutex<Vec<[u8; 16]>> as *mut c_void
        ),
        Z_OK
    );
    assert_eq!(
        z_info_transports(
            z_session_loan(session),
            z_closure_transport_move(&mut closure)
        ),
        Z_OK
    );
    let zids = std::mem::take(&mut *listed.lock().unwrap());
    zids
}

unsafe fn close_session(session: &mut z_owned_session_t) {
    z_close(z_session_loan_mut(session), std::ptr::null());
    z_session_drop(z_session_move(session));
}

/// Wait for `holds` to be true of both sessions, for at most ten seconds.
fn eventually(what: &str, mut holds: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if holds() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for {what}");
}

/// `a` listens and dials `b`; `b` goes and a node of a new zid takes its port and dials `a`. The
/// pair keeps one transport on each side, and the link carries what each puts. The pause after the
/// restart is longer than the redial period (a second), so `a`'s redial has had its turn.
#[test]
fn a_restarted_peer_that_dials_back_while_its_old_dialler_redials_keeps_one_transport() {
    // The zids are stated, so which of the two is the lower one is the round's and not a draw: the
    // restarted node's is lower than `a`'s on the even rounds and higher on the odd ones, which
    // is the rule's two arms (a link refused, a held link replaced) on each engine, four rounds
    // each.
    const A: &CStr = c"80000000-0000-0000-0000-000000000001";
    const B: &CStr = c"40000000-0000-0000-0000-000000000002";
    const B_AGAIN_LOWER: &CStr = c"10000000-0000-0000-0000-000000000003";
    const B_AGAIN_HIGHER: &CStr = c"f0000000-0000-0000-0000-000000000003";
    for round in 0..8 {
        let (a_port, b_port) = (free_port(), free_port());
        let b_again_text = if round % 2 == 0 {
            B_AGAIN_LOWER
        } else {
            B_AGAIN_HIGHER
        };
        // SAFETY: fresh configs and sessions, each closed before the round ends.
        unsafe {
            let mut b = open(b_port, None, B);
            let mut a = open(a_port, Some(b_port), A);
            let a_zid = z_info_zid(z_session_loan(&a)).id;
            let b_zid = z_info_zid(z_session_loan(&b)).id;
            assert_eq!(
                a_zid[0], 0x80,
                "the session opened on the id its config names"
            );
            assert_eq!(
                b_zid[0], 0x40,
                "the session opened on the id its config names"
            );
            eventually("a to list the node it dialled", || {
                transports(&a) == [b_zid]
            });

            // The node goes. `a` is left with its dial role redialling a port nobody holds.
            close_session(&mut b);
            eventually("a to see the node go", || transports(&a).is_empty());

            // A node of a new zid takes the port and dials `a` at once.
            let mut b_again = open(b_port, Some(a_port), b_again_text);
            let b_again_zid = z_info_zid(z_session_loan(&b_again)).id;
            assert_eq!(
                b_again_zid[0],
                if round % 2 == 0 { 0x10 } else { 0xf0 },
                "round {round}: the restarted node opened on the id its config names"
            );
            assert_ne!(b_again_zid, b_zid, "round {round}: a restart is a new node");
            let (heard_by_a, mut a_sub) = hearing(&a);
            let (heard_by_b, mut b_sub) = hearing(&b_again);

            // One transport each, and each names the OTHER node: a pair that closed both links
            // lists none, and one that kept a link its peer closed lists one that carries nothing.
            eventually("each session to list the other node", || {
                transports(&a) == [b_again_zid] && transports(&b_again) == [a_zid]
            });
            std::thread::sleep(Duration::from_millis(2500));
            assert_eq!(
                transports(&a),
                [b_again_zid],
                "round {round}: the first session holds one transport and keeps it"
            );
            assert_eq!(
                transports(&b_again),
                [a_zid],
                "round {round}: the restarted session holds one transport and keeps it"
            );

            assert!(
                put_until_seen(&a, c"demo/to-b", &heard_by_b),
                "round {round}: nothing reached the restarted session"
            );
            assert!(
                put_until_seen(&b_again, c"demo/to-a", &heard_by_a),
                "round {round}: nothing reached the first session from the restarted one"
            );

            z_undeclare_subscriber(z_subscriber_move(&mut a_sub));
            z_undeclare_subscriber(z_subscriber_move(&mut b_sub));
            close_session(&mut b_again);
            close_session(&mut a);
        }
    }
}

/// `Z_CONFIG_SESSION_ZID_KEY` is the id the session opens on, read as zenoh-pico's `z_open` reads
/// it (a UUID, its sixteen bytes in the order written), and a text that reader was not written
/// for fails the open and does not become an id nobody named.
#[test]
fn a_session_opens_on_the_zid_its_config_names_and_refuses_text_that_is_not_one() {
    // SAFETY: fresh configs and sessions, each closed or never opened.
    unsafe {
        let mut session = open(free_port(), None, c"01020304-0506-0708-090a-0b0c0d0e0f10");
        assert_eq!(
            z_info_zid(z_session_loan(&session)).id,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            "the id is the UUID's bytes in the order written"
        );
        close_session(&mut session);

        for text in [
            c"not-a-uuid",
            // Thirty-two digits and no dashes: pico's reader indexes past them.
            c"01020304050607080910111213141516",
            c"00000000-0000-0000-0000-000000000000",
        ] {
            let mut cfg: z_owned_config_t = std::mem::zeroed();
            assert_eq!(z_config_default(&mut cfg), Z_OK);
            assert_eq!(
                zp_config_insert(
                    z_config_loan_mut(&mut cfg),
                    Z_CONFIG_SESSION_ZID_KEY,
                    text.as_ptr()
                ),
                Z_OK
            );
            let endpoint = CString::new(format!("tcp/127.0.0.1:{}", free_port())).unwrap();
            assert_eq!(
                zp_config_insert(
                    z_config_loan_mut(&mut cfg),
                    Z_CONFIG_LISTEN_KEY,
                    endpoint.as_ptr()
                ),
                Z_OK
            );
            let mut refused: z_owned_session_t = std::mem::zeroed();
            assert_eq!(
                z_open(&mut refused, z_config_move(&mut cfg), std::ptr::null()),
                Z_ERR_INVALID,
                "{text:?} names no id, so the open fails"
            );
        }
    }
}
