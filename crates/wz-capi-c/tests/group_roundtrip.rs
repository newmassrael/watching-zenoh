// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! R2932 — zenoh-ext's group membership through the `wz_capi_c_group_*` /
//! `wz_capi_c_member_*` doors, driven exactly as a C program would drive them.
//!
//! Three legs, each for a claim a narrower test could not make:
//!
//! 1. **Two sessions over a real link.** Each joins; each view reaches both
//!    members; the leader is the greatest id on both sides; the peer's JOIN is
//!    delivered as an event carrying its record; and when the peer leaves, its
//!    lease runs out and LEASE_EXPIRED is delivered and the view shrinks.
//! 2. **Two groups on ONE session with no peer.** They can learn of each
//!    other only through the session's local plane, and the second of them
//!    learns of the first ONLY from the first's keep-alive, a publish no door
//!    makes: the group's own task stages it on the plane. The view staying at
//!    two for several leases is what shows those beacons are delivered, which
//!    is the session's stage wake (`Session::with_local_stage_wake`).
//! 3. **The refusals upstream makes**: a wildcard member id, and a wildcard
//!    group id, are `Z_EINVAL`.
//!
//! Every wait is a bounded convergence on an observable (a view size, an
//! event count), never a fixed sleep standing in for one.

#![cfg(not(feature = "zenoh-c-no-unstable-api"))]

use std::ffi::{c_void, CString};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_moved_config_t, z_moved_session_t, z_owned_config_t, z_owned_session_t, z_view_keyexpr_t,
    z_view_string_t,
};
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::group::*;
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::result::{Z_EINVAL, Z_OK};
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::string::{z_string_data, z_string_len, z_view_string_loan};
use wz_runtime_tokio_test_support::free_port;

/// Long enough for any convergence here on a loaded host, and far below
/// anything a hang would reach.
const CONVERGE: Duration = Duration::from_secs(20);
/// A short lease, so keep-alives run every 250 ms and an expiry lands in
/// about a second.
const LEASE_MS: u64 = 500;

unsafe fn open_role(port: u16, key: &str) -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    // Multicast scouting off, as zenoh's own tests state it: a session that scouts connects to
    // every zenoh node on the default group, and this one is to talk to the port it is given.
    let off_key = CString::new("scouting/multicast/enabled").unwrap();
    let off_value = CString::new("false").unwrap();
    assert_eq!(
        zc_config_insert_json5(
            z_config_loan_mut(&mut cfg),
            off_key.as_ptr(),
            off_value.as_ptr()
        ),
        Z_OK
    );
    let key = CString::new(key).unwrap();
    let value = CString::new(format!("[\"tcp/127.0.0.1:{port}\"]")).unwrap();
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

unsafe fn close(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}

unsafe fn view_text(view: &z_view_string_t) -> String {
    let loaned = z_view_string_loan(view);
    let bytes =
        std::slice::from_raw_parts(z_string_data(loaned).cast::<u8>(), z_string_len(loaned));
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// A member with `id` and the short lease. The keyexpr view only has to live
/// through `wz_capi_c_member_new`, which copies the id.
unsafe fn member(id: &str) -> Result<wz_capi_c_owned_member_t, i8> {
    let text = CString::new(id).unwrap();
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, text.as_ptr()), Z_OK);
    let mut opts: wz_capi_c_member_options_t = std::mem::zeroed();
    wz_capi_c_member_options_default(&mut opts);
    opts.lease_ms = LEASE_MS;
    opts.refresh_ratio = 0.5;
    let mut out: wz_capi_c_owned_member_t = std::mem::zeroed();
    match wz_capi_c_member_new(&mut out, z_view_keyexpr_loan(&ke), &mut opts) {
        Z_OK => Ok(out),
        rc => Err(rc),
    }
}

unsafe fn join(
    session: &z_owned_session_t,
    group: &str,
    mut who: wz_capi_c_owned_member_t,
) -> Result<wz_capi_c_owned_group_t, i8> {
    let text = CString::new(group).unwrap();
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, text.as_ptr()), Z_OK);
    let mut out: wz_capi_c_owned_group_t = std::mem::zeroed();
    let rc = wz_capi_c_group_join(
        &mut out,
        z_session_loan(session),
        z_view_keyexpr_loan(&ke),
        (&mut who as *mut wz_capi_c_owned_member_t).cast::<wz_capi_c_moved_member_t>(),
    );
    assert!(
        !wz_capi_c_internal_member_check(&who),
        "the join consumes the member on every path"
    );
    if rc == Z_OK {
        Ok(out)
    } else {
        Err(rc)
    }
}

unsafe fn drop_group(mut group: wz_capi_c_owned_group_t) {
    wz_capi_c_group_drop(
        (&mut group as *mut wz_capi_c_owned_group_t).cast::<wz_capi_c_moved_group_t>(),
    );
    assert!(!wz_capi_c_internal_group_check(&group));
}

/// The ids `wz_capi_c_group_view` reports, in the order it reports them.
unsafe fn view_ids(group: &wz_capi_c_owned_group_t) -> Vec<String> {
    unsafe extern "C" fn push(member: *const wz_capi_c_loaned_member_t, ctx: *mut c_void) {
        let mut id: z_view_string_t = std::mem::zeroed();
        assert_eq!(wz_capi_c_member_id(member, &mut id), Z_OK);
        (*(ctx as *mut Vec<String>)).push(view_text(&id));
    }
    let mut ids: Vec<String> = Vec::new();
    let mut closure: wz_capi_c_owned_closure_member_t = std::mem::zeroed();
    wz_capi_c_closure_member(
        &mut closure,
        Some(push),
        None,
        (&mut ids as *mut Vec<String>).cast::<c_void>(),
    );
    assert_eq!(
        wz_capi_c_group_view(
            wz_capi_c_group_loan(group),
            (&mut closure as *mut wz_capi_c_owned_closure_member_t)
                .cast::<wz_capi_c_moved_closure_member_t>(),
        ),
        Z_OK
    );
    ids
}

unsafe fn leader_id(group: &wz_capi_c_owned_group_t) -> String {
    let mut leader: wz_capi_c_owned_member_t = std::mem::zeroed();
    assert_eq!(
        wz_capi_c_group_leader(wz_capi_c_group_loan(group), &mut leader),
        Z_OK
    );
    let mut id: z_view_string_t = std::mem::zeroed();
    assert_eq!(
        wz_capi_c_member_id(wz_capi_c_member_loan(&leader), &mut id),
        Z_OK
    );
    let text = view_text(&id);
    wz_capi_c_member_drop(
        (&mut leader as *mut wz_capi_c_owned_member_t).cast::<wz_capi_c_moved_member_t>(),
    );
    text
}

/// One delivered event, as `kind member-id [info]`.
type Log = Arc<Mutex<Vec<String>>>;

struct EventCtx {
    log: Log,
}

unsafe extern "C" fn record(event: *const wz_capi_c_loaned_group_event_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const EventCtx);
    let mut mid: z_view_string_t = std::mem::zeroed();
    assert_eq!(wz_capi_c_group_event_member_id(event, &mut mid), Z_OK);
    let kind = match wz_capi_c_group_event_kind(event) {
        WZ_CAPI_C_GROUP_EVENT_KIND_JOIN => "join",
        WZ_CAPI_C_GROUP_EVENT_KIND_LEAVE => "leave",
        WZ_CAPI_C_GROUP_EVENT_KIND_LEASE_EXPIRED => "expired",
        _ => "leader",
    };
    let member = wz_capi_c_group_event_member(event);
    let line = if member.is_null() {
        format!("{kind} {}", view_text(&mid))
    } else {
        let mut info: z_view_string_t = std::mem::zeroed();
        let has_info = wz_capi_c_member_info(member, &mut info);
        assert_eq!(wz_capi_c_member_lease_ms(member), LEASE_MS);
        format!("{kind} {} info={}", view_text(&mid), has_info)
    };
    ctx.log.lock().unwrap().push(line);
}

unsafe extern "C" fn free_ctx(ctx: *mut c_void) {
    drop(Box::from_raw(ctx as *mut EventCtx));
}

unsafe fn subscribe(group: &wz_capi_c_owned_group_t) -> Log {
    let log: Log = Arc::default();
    let ctx = Box::into_raw(Box::new(EventCtx {
        log: Arc::clone(&log),
    }));
    let mut closure: wz_capi_c_owned_closure_group_event_t = std::mem::zeroed();
    wz_capi_c_closure_group_event(
        &mut closure,
        Some(record),
        Some(free_ctx),
        ctx.cast::<c_void>(),
    );
    assert_eq!(
        wz_capi_c_group_subscribe(
            wz_capi_c_group_loan(group),
            (&mut closure as *mut wz_capi_c_owned_closure_group_event_t)
                .cast::<wz_capi_c_moved_closure_group_event_t>(),
        ),
        Z_OK
    );
    log
}

fn converge(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(
            start.elapsed() < CONVERGE,
            "{what}: not reached in {CONVERGE:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn two_sessions_join_one_group_and_see_each_other_come_and_go() {
    unsafe {
        let port = free_port();
        let a = open_role(port, "listen/endpoints");
        let b = open_role(port, "connect/endpoints");

        let ga = join(&a, "wz/test/group", member("a").unwrap()).unwrap();
        let log = subscribe(&ga);
        let gb = join(&b, "wz/test/group", member("b").unwrap()).unwrap();

        assert!(
            wz_capi_c_group_wait_for_view_size(wz_capi_c_group_loan(&ga), 2, 20_000),
            "a never saw b"
        );
        assert!(
            wz_capi_c_group_wait_for_view_size(wz_capi_c_group_loan(&gb), 2, 20_000),
            "b never saw a"
        );
        assert_eq!(view_ids(&ga), ["a", "b"]);
        assert_eq!(view_ids(&gb), ["a", "b"]);
        assert_eq!(leader_id(&ga), "b");
        assert_eq!(leader_id(&gb), "b");

        let mut gid: z_view_string_t = std::mem::zeroed();
        assert_eq!(
            wz_capi_c_group_group_id(wz_capi_c_group_loan(&ga), &mut gid),
            Z_OK
        );
        assert_eq!(view_text(&gid), "wz/test/group");
        let mut mid: z_view_string_t = std::mem::zeroed();
        assert_eq!(
            wz_capi_c_group_local_member_id(wz_capi_c_group_loan(&ga), &mut mid),
            Z_OK
        );
        assert_eq!(view_text(&mid), "a");

        converge("a's JOIN event for b", || {
            log.lock().unwrap().iter().any(|l| l == "join b info=false")
        });

        // Upstream announces no LEAVE on drop, so b is reported when its lease
        // runs out on a's side.
        drop_group(gb);
        converge("a's LEASE_EXPIRED event for b", || {
            log.lock().unwrap().iter().any(|l| l == "expired b")
        });
        assert_eq!(wz_capi_c_group_size(wz_capi_c_group_loan(&ga)), 1);
        assert_eq!(
            *log.lock().unwrap(),
            ["join b info=false", "expired b"],
            "each change once, in order"
        );

        drop_group(ga);
        close(b);
        close(a);
    }
}

#[test]
fn two_groups_on_one_session_meet_through_the_local_plane_and_stay_met() {
    unsafe {
        // A listener nobody dials: a session with no peer at all.
        let session = open_role(free_port(), "listen/endpoints");
        let gx = join(&session, "wz/test/solo", member("x").unwrap()).unwrap();
        let gy = join(&session, "wz/test/solo", member("y").unwrap()).unwrap();
        let log = subscribe(&gy);

        // y joined second, so it hears of x only from x's keep-alive.
        assert!(
            wz_capi_c_group_wait_for_view_size(wz_capi_c_group_loan(&gy), 2, 20_000),
            "y never heard x's keep-alive on the local plane"
        );
        assert!(wz_capi_c_group_wait_for_view_size(
            wz_capi_c_group_loan(&gx),
            2,
            20_000
        ));

        // Six leases: had the beacons not been delivered, each side's
        // watchdog would have expired the other long before this.
        std::thread::sleep(Duration::from_millis(6 * LEASE_MS));
        assert_eq!(wz_capi_c_group_size(wz_capi_c_group_loan(&gx)), 2);
        assert_eq!(wz_capi_c_group_size(wz_capi_c_group_loan(&gy)), 2);
        assert!(
            !log.lock().unwrap().iter().any(|l| l.starts_with("expired")),
            "a live member was reported expired: {:?}",
            log.lock().unwrap()
        );

        drop_group(gy);
        drop_group(gx);
        close(session);
    }
}

#[test]
fn wildcard_ids_are_refused_as_upstream_refuses_them() {
    unsafe {
        assert_eq!(member("a/*").err(), Some(Z_EINVAL));
        let session = open_role(free_port(), "listen/endpoints");
        assert_eq!(
            join(&session, "wz/test/**", member("a").unwrap()).err(),
            Some(Z_EINVAL)
        );
        close(session);
    }
}
