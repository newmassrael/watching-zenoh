// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2262 (open-debt item 608) — the LINK / TRANSPORT event planes driven by a
//! REAL face transition, through the exported `z_*` symbols exactly as a C
//! program would.
//!
//! ## Why this leg and not the unit tests R2259 already wrote
//!
//! R2259 built ninety-two symbols and proved, in unit tests, that each keeps
//! its value contract: a transport reads back through every accessor, a link
//! survives its original, a closure's drop runs once. None of that touches the
//! question the plane exists to answer — **does a C callback fire when a peer
//! arrives, and again when it leaves?** That path is
//! `face_up` / `face_down` -> `SharedSession::fire_face_event` -> the sink the
//! declare installed -> the C closure, and until this file nothing called
//! `watch_faces` outside `events.rs` itself.
//!
//! Item 608 is that gap, and R2259 carried it forward three rounds. "The symbol
//! exists" is already measured by the ABI census; this is the other claim.
//!
//! ## The two directions are separate code paths, so they are separate legs
//!
//! `face_up` snapshots BEFORE the entry moves into the registry; `face_down`
//! snapshots the DEPARTED entry while it is still alive, which is the only
//! moment its identity can still be read. Neither implies the other, and a
//! single leg asserting "some event arrived" would pass with one of them
//! broken.
//!
//! ## What the counts mean, and why they are not asserted as equality
//!
//! A wz session is ONE peer per face and a listener holds one face per dialer,
//! so a dialer arriving is one PUT. The assertions are `>= 1` on the direction
//! under test and EXACT on the kind, because a reconnect attempt can legitimately
//! produce a second transition and the leg is about the DIRECTION reaching C,
//! not about a count nobody promised.

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_moved_config_t, z_moved_session_t, z_owned_config_t, z_owned_session_t, Z_SAMPLE_KIND_DELETE,
    Z_SAMPLE_KIND_PUT,
};
use wz_capi_c::abi::{z_moved_string_t, z_owned_string_t};
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::events::{
    z_closure_link_event, z_closure_transport, z_closure_transport_event,
    z_declare_link_events_listener, z_declare_transport_events_listener, z_info_transports,
    z_internal_link_events_listener_check, z_internal_transport_events_listener_check, z_link_dst,
    z_link_event_kind, z_link_event_link, z_link_events_listener_options_default,
    z_link_events_listener_options_t, z_link_is_streamed, z_link_zid, z_loaned_link_event_t,
    z_loaned_transport_event_t, z_loaned_transport_t, z_moved_closure_link_event_t,
    z_moved_closure_transport_event_t, z_moved_closure_transport_t, z_moved_link_events_listener_t,
    z_moved_transport_events_listener_t, z_owned_closure_link_event_t,
    z_owned_closure_transport_event_t, z_owned_closure_transport_t, z_owned_link_events_listener_t,
    z_owned_transport_events_listener_t, z_transport_event_kind, z_transport_event_transport,
    z_transport_events_listener_options_t, z_transport_is_multicast, z_transport_zid,
    z_undeclare_link_events_listener, z_undeclare_transport_events_listener,
};
use wz_capi_c::result::Z_OK;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::string::{z_string_drop, z_string_len, z_string_loan};
use wz_runtime_tokio_test_support::free_port;

/// What the C callbacks count, shared with them through a raw context pointer.
#[derive(Default)]
struct Seen {
    puts: AtomicUsize,
    deletes: AtomicUsize,
    /// A zid byte the callback actually read back, so the leg can say the
    /// EVENT carried an identity rather than merely arriving.
    nonzero_zid: AtomicUsize,
    multicast: AtomicUsize,
    /// The link plane's two facts a real face can answer and a stub cannot.
    streamed: AtomicUsize,
    dst_nonempty: AtomicUsize,
}

/// The transport-event closure a C program would write.
///
/// # Safety
/// `ctx` is the `Arc<Seen>` the declare was handed, alive for the listener's
/// whole life; `event` is the loaned event upstream's contract gives it.
unsafe extern "C" fn on_transport_event(event: *mut z_loaned_transport_event_t, ctx: *mut c_void) {
    let seen = unsafe { &*(ctx as *const Seen) };
    let kind = unsafe { z_transport_event_kind(event) };
    if kind == Z_SAMPLE_KIND_PUT {
        seen.puts.fetch_add(1, Ordering::SeqCst);
    } else if kind == Z_SAMPLE_KIND_DELETE {
        seen.deletes.fetch_add(1, Ordering::SeqCst);
    }
    let transport = unsafe { z_transport_event_transport(event) };
    if !transport.is_null() {
        let zid = unsafe { z_transport_zid(transport) };
        if zid.id.iter().any(|b| *b != 0) {
            seen.nonzero_zid.fetch_add(1, Ordering::SeqCst);
        }
        if unsafe { z_transport_is_multicast(transport) } {
            seen.multicast.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// The `z_info_transports` closure, which takes a transport rather than an event.
///
/// # Safety
/// As above.
unsafe extern "C" fn on_transport(transport: *mut z_loaned_transport_t, ctx: *mut c_void) {
    let seen = unsafe { &*(ctx as *const Seen) };
    seen.puts.fetch_add(1, Ordering::SeqCst);
    if !transport.is_null() {
        let zid = unsafe { z_transport_zid(transport) };
        if zid.id.iter().any(|b| *b != 0) {
            seen.nonzero_zid.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// # Safety
/// `port` must be free; the returned session is the caller's to close.
unsafe fn open_role(port: u16, key: &str) -> z_owned_session_t {
    let key = CString::new(key).unwrap();
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

/// # Safety
/// As `open_role`.
unsafe fn declare_listener(
    session: &z_owned_session_t,
    ctx: *mut c_void,
    history: bool,
) -> z_owned_transport_events_listener_t {
    let mut closure: z_owned_closure_transport_event_t = std::mem::zeroed();
    z_closure_transport_event(&mut closure, Some(on_transport_event), None, ctx);
    let options = z_transport_events_listener_options_t { history };
    let mut listener: z_owned_transport_events_listener_t = std::mem::zeroed();
    assert_eq!(
        z_declare_transport_events_listener(
            z_session_loan(session),
            &mut listener,
            // The `z_move()` CAST a C program makes: owned and moved share a
            // layout, and the `_this` field is crate-private on purpose.
            (&mut closure as *mut z_owned_closure_transport_event_t)
                .cast::<z_moved_closure_transport_event_t>(),
            &options
        ),
        Z_OK
    );
    assert!(
        z_internal_transport_events_listener_check(&listener),
        "a declared listener must read back as live"
    );
    listener
}

/// Wait for `want` on `counter`, then settle. Bounded: a leg that never
/// reaches its count must FAIL rather than hang.
fn settle(counter: &AtomicUsize, want: usize) -> usize {
    let deadline = Instant::now() + Duration::from_secs(10);
    while counter.load(Ordering::SeqCst) < want && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(200));
    counter.load(Ordering::SeqCst)
}

/// The LINK-event closure. Reads the link out of the event and asks it for the
/// facts only a real face can answer.
///
/// # Safety
/// As `on_transport_event`.
unsafe extern "C" fn on_link_event(event: *mut z_loaned_link_event_t, ctx: *mut c_void) {
    let seen = unsafe { &*(ctx as *const Seen) };
    let kind = unsafe { z_link_event_kind(event) };
    if kind == Z_SAMPLE_KIND_PUT {
        seen.puts.fetch_add(1, Ordering::SeqCst);
    } else if kind == Z_SAMPLE_KIND_DELETE {
        seen.deletes.fetch_add(1, Ordering::SeqCst);
    }
    let link = unsafe { z_link_event_link(event) };
    if link.is_null() {
        return;
    }
    let zid = unsafe { z_link_zid(link) };
    if zid.id.iter().any(|b| *b != 0) {
        seen.nonzero_zid.fetch_add(1, Ordering::SeqCst);
    }
    // A tcp link is STREAMED and its endpoints are real locators. Both are
    // read here rather than asserted in the callback, so a failure shows up as
    // a count in the test body where the message can say what it means.
    if unsafe { z_link_is_streamed(link) } {
        seen.streamed.fetch_add(1, Ordering::SeqCst);
    }
    let mut dst: z_owned_string_t = std::mem::zeroed();
    unsafe { z_link_dst(link, &mut dst) };
    let loaned = unsafe { z_string_loan(&dst) };
    if !loaned.is_null() {
        let len = unsafe { z_string_len(loaned) };
        if len > 0 {
            seen.dst_nonempty.fetch_add(1, Ordering::SeqCst);
        }
    }
    unsafe { z_string_drop((&mut dst as *mut z_owned_string_t).cast::<z_moved_string_t>()) };
}

/// # Safety
/// As `declare_listener`.
unsafe fn declare_link_listener(
    session: &z_owned_session_t,
    ctx: *mut c_void,
) -> z_owned_link_events_listener_t {
    let mut closure: z_owned_closure_link_event_t = std::mem::zeroed();
    z_closure_link_event(&mut closure, Some(on_link_event), None, ctx);
    let mut options: z_link_events_listener_options_t = std::mem::zeroed();
    z_link_events_listener_options_default(&mut options);
    let mut listener: z_owned_link_events_listener_t = std::mem::zeroed();
    assert_eq!(
        z_declare_link_events_listener(
            z_session_loan(session),
            &mut listener,
            (&mut closure as *mut z_owned_closure_link_event_t)
                .cast::<z_moved_closure_link_event_t>(),
            &mut options
        ),
        Z_OK
    );
    assert!(z_internal_link_events_listener_check(&listener));
    listener
}

/// # Safety
/// `session` must be a live owned session this test opened.
unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}

/// THE leg: a peer ARRIVING fires a PUT at the C callback, carrying that peer's
/// zid, and the peer LEAVING fires a DELETE.
///
/// Both directions in one test on purpose — they need the same two sessions and
/// the ORDER is the claim: a DELETE that arrived before its PUT would mean the
/// snapshot in `face_down` is reading something other than the face that went.
#[test]
fn a_peer_arriving_and_leaving_reaches_the_c_transport_listener() {
    let port = free_port();
    unsafe {
        let listener_session = open_role(port, "listen/endpoints");
        let seen = Arc::new(Seen::default());
        let ctx = Arc::as_ptr(&seen) as *mut c_void;
        let mut listener = declare_listener(&listener_session, ctx, false);

        // ARRIVAL. The dialer's face lands on the listening session, which is
        // where `face_up` runs.
        let dialer = open_role(port, "connect/endpoints");
        let puts = settle(&seen.puts, 1);
        assert!(
            puts >= 1,
            "a peer arriving must fire a PUT at the C listener; saw {puts}"
        );
        assert!(
            seen.nonzero_zid.load(Ordering::SeqCst) >= 1,
            "the event must carry the peer's zid, not a zeroed transport"
        );
        assert_eq!(
            seen.multicast.load(Ordering::SeqCst),
            0,
            "a unicast face must not report itself multicast"
        );
        assert_eq!(
            seen.deletes.load(Ordering::SeqCst),
            0,
            "nothing has left yet, so a DELETE here would mean the kind is wrong"
        );

        // DEPARTURE. Closing the dialer takes its face down on the listener.
        close_session(dialer);
        let deletes = settle(&seen.deletes, 1);
        assert!(
            deletes >= 1,
            "a peer leaving must fire a DELETE at the C listener; saw {deletes}"
        );

        assert_eq!(
            z_undeclare_transport_events_listener(
                (&mut listener as *mut z_owned_transport_events_listener_t)
                    .cast::<z_moved_transport_events_listener_t>()
            ),
            Z_OK
        );
        close_session(listener_session);
    }
}

/// `history: true` replays the transports that were ALREADY established when
/// the listener is declared.
///
/// A separate leg because it is a separate code path: the replay walks
/// `face_snapshots()` at declare time, where the leg above waits for a live
/// transition. A build with the replay dropped passes the first leg entirely.
#[test]
fn history_replays_the_transports_already_established() {
    let port = free_port();
    unsafe {
        let listener_session = open_role(port, "listen/endpoints");

        // ⚠ THE ORDER IS THE FIXTURE, and the first draft got it wrong. A
        // `history: false` listener declared AFTER the dialer has already
        // landed sees nothing — the live transition is past — so it cannot be
        // used to establish that the face is up. The live listener goes FIRST,
        // the dialer second, and the PUT is what proves the face exists before
        // the replay is asked for.
        let warmup = Arc::new(Seen::default());
        let warm_ctx = Arc::as_ptr(&warmup) as *mut c_void;
        let mut warm = declare_listener(&listener_session, warm_ctx, false);
        let dialer = open_role(port, "connect/endpoints");
        assert!(
            settle(&warmup.puts, 1) >= 1,
            "the face must be up before there is a history to replay"
        );
        assert_eq!(
            z_undeclare_transport_events_listener(
                (&mut warm as *mut z_owned_transport_events_listener_t)
                    .cast::<z_moved_transport_events_listener_t>()
            ),
            Z_OK
        );

        let seen = Arc::new(Seen::default());
        let ctx = Arc::as_ptr(&seen) as *mut c_void;
        let mut listener = declare_listener(&listener_session, ctx, true);
        // The replay runs INSIDE the declare, so it has already happened.
        let puts = seen.puts.load(Ordering::SeqCst);
        assert!(
            puts >= 1,
            "history must replay the established transport at declare time; saw {puts}"
        );
        assert!(
            seen.nonzero_zid.load(Ordering::SeqCst) >= 1,
            "the replayed transport must carry the peer's zid"
        );

        assert_eq!(
            z_undeclare_transport_events_listener(
                (&mut listener as *mut z_owned_transport_events_listener_t)
                    .cast::<z_moved_transport_events_listener_t>()
            ),
            Z_OK
        );
        close_session(dialer);
        close_session(listener_session);
    }
}

/// `z_info_transports` enumerates the session's established transports.
///
/// The third path into the same snapshot walk, and the one a C program uses to
/// ask "who am I connected to" without subscribing to anything.
#[test]
fn info_transports_enumerates_the_established_peer() {
    let port = free_port();
    unsafe {
        let listener_session = open_role(port, "listen/endpoints");

        // Converge on the face being up, through the event plane, so the
        // enumeration below is not racing the handshake. Live listener FIRST —
        // see the sibling leg for why the other order measures nothing.
        let warmup = Arc::new(Seen::default());
        let warm_ctx = Arc::as_ptr(&warmup) as *mut c_void;
        let mut warm = declare_listener(&listener_session, warm_ctx, false);
        let dialer = open_role(port, "connect/endpoints");
        assert!(
            settle(&warmup.puts, 1) >= 1,
            "the face must be up before enumerating"
        );
        assert_eq!(
            z_undeclare_transport_events_listener(
                (&mut warm as *mut z_owned_transport_events_listener_t)
                    .cast::<z_moved_transport_events_listener_t>()
            ),
            Z_OK
        );

        let seen = Arc::new(Seen::default());
        let ctx = Arc::as_ptr(&seen) as *mut c_void;
        let mut closure: z_owned_closure_transport_t = std::mem::zeroed();
        z_closure_transport(&mut closure, Some(on_transport), None, ctx);
        assert_eq!(
            z_info_transports(
                z_session_loan(&listener_session),
                (&mut closure as *mut z_owned_closure_transport_t)
                    .cast::<z_moved_closure_transport_t>()
            ),
            Z_OK
        );
        assert!(
            seen.puts.load(Ordering::SeqCst) >= 1,
            "z_info_transports must hand the established peer to the callback"
        );
        assert!(
            seen.nonzero_zid.load(Ordering::SeqCst) >= 1,
            "and that transport must carry the peer's zid"
        );

        close_session(dialer);
        close_session(listener_session);
    }
}

/// The LINK plane, driven by the same real transition: a peer arriving fires a
/// PUT carrying a link whose `dst` is a locator and which reports itself
/// STREAMED, because the face is tcp.
///
/// A separate leg from the transport one and not a duplicate of it: the link
/// event carries a link reached through `z_link_event_link`, a pointer into the
/// event's own state, and every accessor here is one the transport plane does
/// not have. `is_streamed` in particular is the value R2260 had to correct
/// against upstream — a face that reported it wrong would pass every
/// symbol-existence check ever written.
#[test]
fn a_peer_arriving_reaches_the_c_link_listener_with_a_real_locator() {
    let port = free_port();
    unsafe {
        let listener_session = open_role(port, "listen/endpoints");
        let seen = Arc::new(Seen::default());
        let ctx = Arc::as_ptr(&seen) as *mut c_void;
        let mut listener = declare_link_listener(&listener_session, ctx);

        let dialer = open_role(port, "connect/endpoints");
        let puts = settle(&seen.puts, 1);
        assert!(
            puts >= 1,
            "a peer arriving must fire a link PUT at the C listener; saw {puts}"
        );
        assert!(
            seen.nonzero_zid.load(Ordering::SeqCst) >= 1,
            "the link must carry the peer's zid"
        );
        assert!(
            seen.dst_nonempty.load(Ordering::SeqCst) >= 1,
            "the link's `dst` must be a real locator, not an empty string"
        );
        assert!(
            seen.streamed.load(Ordering::SeqCst) >= 1,
            "a tcp link is STREAMED — upstream's own classification, which \
             R2260 corrected wz against"
        );

        assert_eq!(
            z_undeclare_link_events_listener(
                (&mut listener as *mut z_owned_link_events_listener_t)
                    .cast::<z_moved_link_events_listener_t>()
            ),
            Z_OK
        );
        close_session(dialer);
        close_session(listener_session);
    }
}
