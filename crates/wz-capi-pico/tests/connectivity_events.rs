// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The CONNECTIVITY plane through its C exports, against a real peer.
//!
//! A C listener session is opened, transport and link listeners are declared on
//! it with the exported functions, and a wz-native peer dials in and leaves. What
//! the listeners are told, in what order, and what `z_info_transports` and
//! `z_info_links` say while the peer is there, is what a pico program sees.
//!
//! ## What each leg is here to catch
//!
//! - ORDER. pico tells a peer's arrival as a transport `PUT` and then a link
//!   `PUT`, and its departure as a link `DELETE` and then a transport `DELETE`.
//!   Both listeners write to ONE log, so the order is what the log says.
//! - VALUES. The link reports what pico's TCP link reports — a 65535-byte MTU,
//!   streamed, reliable — and not the batch size the two ends negotiated; the
//!   transport reports the peer's zid and its role as pico's bitmask.
//! - HISTORY. A listener declared with `history` is told the peers that are
//!   already connected, as `PUT`s, before anything else.
//! - FILTERS. A link listener and `z_info_links` can be narrowed to one
//!   transport, and the moved transport that narrows them is consumed — and one
//!   that holds nothing is refused with `_Z_ERR_INVALID`, with the closure
//!   released.
//! - OWNERSHIP. A refusal for want of a session leaves the closure with the
//!   caller (pico refuses before it takes it); an undeclare releases the
//!   closure's context before it returns.
//!
//! ## Why the far end is wz-native
//!
//! The peer is a session this crate's own drive loop accepts, so the death it
//! causes is a real socket close observed by the accept loop. The real pico
//! library is the oracle in `pico_connectivity_diff`, which runs the same program
//! against both.

use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_pico::abi::z_owned_string_t;
use wz_capi_pico::connectivity::{
    z_closure_link, z_closure_link_event, z_closure_link_event_move, z_closure_link_move,
    z_closure_transport, z_closure_transport_event, z_closure_transport_event_move,
    z_closure_transport_move, z_declare_link_events_listener, z_declare_transport_events_listener,
    z_info_links, z_info_links_options_default, z_info_links_options_t, z_info_transports,
    z_link_dst, z_link_event_kind, z_link_event_link, z_link_events_listener_move,
    z_link_events_listener_options_default, z_link_events_listener_options_t, z_link_is_reliable,
    z_link_is_streamed, z_link_mtu, z_link_src, z_link_zid, z_loaned_link_event_t, z_loaned_link_t,
    z_loaned_transport_event_t, z_loaned_transport_t, z_moved_transport_t,
    z_owned_closure_link_event_t, z_owned_closure_link_t, z_owned_closure_transport_event_t,
    z_owned_closure_transport_t, z_owned_link_events_listener_t,
    z_owned_transport_events_listener_t, z_owned_transport_t, z_transport_clone,
    z_transport_event_kind, z_transport_event_transport, z_transport_events_listener_move,
    z_transport_events_listener_options_default, z_transport_events_listener_options_t,
    z_transport_is_multicast, z_transport_is_qos, z_transport_is_shm, z_transport_move,
    z_transport_whatami, z_transport_zid, z_undeclare_link_events_listener,
    z_undeclare_transport_events_listener,
};
use wz_capi_pico::result::{Z_EINVAL, Z_ERR_SESSION_CLOSED};
use wz_capi_pico::{
    z_close, z_config_default, z_config_loan_mut, z_config_move, z_open, z_owned_config_t,
    z_owned_session_t, z_session_drop, z_session_loan, z_session_loan_mut, z_session_move,
    z_string_data, z_string_drop, z_string_len, z_string_loan, z_string_move, zp_config_insert,
    Z_CONFIG_LISTEN_KEY, Z_OK, Z_SAMPLE_KIND_DELETE, Z_SAMPLE_KIND_PUT,
};

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::TokioSession;
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal, IterationEvent, SessionInitParams, SessionTimeouts, SigningKey,
    WhatAmI,
};
use wz_runtime_tokio::session_open::{
    dial_endpoint, initiate_and_open_session, DialConfig, OpenedSessionParts, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex as WzMutex;
use wz_runtime_tokio_test_support::free_port;

/// pico's `Z_WHATAMI_CLIENT`.
const WHATAMI_CLIENT: u32 = 4;

/// What the C callbacks saw, in order, and how many contexts were released.
/// Leaked so a raw pointer to it can ride as the closures' `context`.
#[derive(Default)]
struct Sink {
    seen: Mutex<Vec<String>>,
    released: AtomicUsize,
}

fn sink() -> &'static Sink {
    Box::leak(Box::default())
}

fn ctx(sink: &'static Sink) -> *mut c_void {
    sink as *const Sink as *mut c_void
}

fn seen(sink: &Sink) -> Vec<String> {
    sink.seen.lock().unwrap().clone()
}

fn hex(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn kind_name(kind: i32) -> &'static str {
    if kind == Z_SAMPLE_KIND_PUT {
        "PUT"
    } else if kind == Z_SAMPLE_KIND_DELETE {
        "DEL"
    } else {
        "???"
    }
}

/// A link string through the exported accessor, as a C program reads it.
unsafe fn link_text(
    link: *const z_loaned_link_t,
    read: unsafe extern "C" fn(*const z_loaned_link_t, *mut z_owned_string_t) -> i8,
) -> String {
    let mut out: z_owned_string_t = std::mem::zeroed();
    assert_eq!(read(link, &mut out), Z_OK);
    let loaned = z_string_loan(&out);
    let bytes =
        std::slice::from_raw_parts(z_string_data(loaned) as *const u8, z_string_len(loaned));
    let text = String::from_utf8_lossy(bytes).into_owned();
    z_string_drop(z_string_move(&mut out));
    text
}

unsafe fn describe_transport(transport: *const z_loaned_transport_t) -> String {
    format!(
        "zid={} whatami={} qos={} multicast={} shm={}",
        hex(&z_transport_zid(transport).id),
        z_transport_whatami(transport),
        z_transport_is_qos(transport),
        z_transport_is_multicast(transport),
        z_transport_is_shm(transport),
    )
}

unsafe fn describe_link(link: *const z_loaned_link_t) -> String {
    format!(
        "zid={} src={} dst={} mtu={} streamed={} reliable={}",
        hex(&z_link_zid(link).id),
        link_text(link, z_link_src),
        link_text(link, z_link_dst),
        z_link_mtu(link),
        z_link_is_streamed(link),
        z_link_is_reliable(link),
    )
}

unsafe extern "C" fn on_transport_event(
    event: *mut z_loaned_transport_event_t,
    context: *mut c_void,
) {
    let sink = &*(context as *const Sink);
    let line = format!(
        "transport {} {}",
        kind_name(z_transport_event_kind(event)),
        describe_transport(z_transport_event_transport(event)),
    );
    sink.seen.lock().unwrap().push(line);
}

unsafe extern "C" fn on_link_event(event: *mut z_loaned_link_event_t, context: *mut c_void) {
    let sink = &*(context as *const Sink);
    let line = format!(
        "link {} {}",
        kind_name(z_link_event_kind(event)),
        describe_link(z_link_event_link(event)),
    );
    sink.seen.lock().unwrap().push(line);
}

unsafe extern "C" fn on_transport(transport: *mut z_loaned_transport_t, context: *mut c_void) {
    let sink = &*(context as *const Sink);
    sink.seen.lock().unwrap().push(format!(
        "listed transport {}",
        describe_transport(transport)
    ));
}

unsafe extern "C" fn on_link(link: *mut z_loaned_link_t, context: *mut c_void) {
    let sink = &*(context as *const Sink);
    sink.seen
        .lock()
        .unwrap()
        .push(format!("listed link {}", describe_link(link)));
}

unsafe extern "C" fn released(context: *mut c_void) {
    (*(context as *const Sink))
        .released
        .fetch_add(1, Ordering::SeqCst);
}

fn init_params(zid: [u8; 16]) -> SessionInitParams {
    SessionInitParams {
        version: 0x09,
        whatami: WhatAmI::Client,
        zid: zid.to_vec(),
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 2048,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: Vec::new(),
        tx_queue: wz_runtime_tokio::session_glue::TxQueueConf::default(),
        cookie_signing_key: SigningKey::new(vec![0xAB; 32]).expect("32-byte key"),
    }
}

/// A wz-native CLIENT peer that dials the C listener and drives until told to
/// stop, then returns, dropping its link.
fn native_peer(
    endpoint: String,
    zid: [u8; 16],
    ready: mpsc::Sender<()>,
    die: Arc<tokio::sync::Notify>,
) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async move {
        let clock = TokioTime::new();
        let dialed = dial_endpoint(&endpoint, &DialConfig::default())
            .await
            .expect("dial the C listener");
        let opened =
            initiate_and_open_session(dialed, init_params(zid), clock, None, DEFAULT_OPEN_TICK_MS)
                .await
                .expect("handshake with the C listener");
        let OpenedSessionParts {
            mut engine,
            actions,
            inbound,
            writer_handle,
            ..
        } = opened.into_parts();
        let observer = Arc::new(WzMutex::new(ApplicationLayerObserver::new()));
        let session = TokioSession::new(actions.clone(), observer, Arc::new(clock));
        let mut driver = inbound;
        let timeouts = SessionTimeouts::spec_defaults();
        let dispatch_session = session.clone();
        let mut dispatch =
            |event: IterationEvent<'_>| dispatch_session.dispatch_iteration_event(event);
        let _ = ready.send(());
        let pump = drive_session_until_terminal(
            &mut driver,
            &actions,
            &mut engine,
            None,
            &clock,
            &timeouts,
            &mut dispatch,
        );
        tokio::select! {
            _ = pump => {}
            _ = die.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
        }
        drop(writer_handle);
    });
}

/// # Safety
/// The returned session must be closed and dropped by the caller.
unsafe fn open_c_listener(port: u16) -> z_owned_session_t {
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(
            z_config_loan_mut(&mut cfg),
            Z_CONFIG_LISTEN_KEY,
            listen.as_ptr()
        ),
        Z_OK
    );
    let mut zs: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut zs, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK
    );
    zs
}

fn wait_for(condition: impl Fn() -> bool, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

unsafe fn transport_listener(
    session: &z_owned_session_t,
    history: bool,
    sink: &'static Sink,
) -> z_owned_transport_events_listener_t {
    let mut closure: z_owned_closure_transport_event_t = std::mem::zeroed();
    z_closure_transport_event(
        &mut closure,
        Some(on_transport_event),
        Some(released),
        ctx(sink),
    );
    let mut options: z_transport_events_listener_options_t = std::mem::zeroed();
    z_transport_events_listener_options_default(&mut options);
    options.history = history;
    let mut listener: z_owned_transport_events_listener_t = std::mem::zeroed();
    assert_eq!(
        z_declare_transport_events_listener(
            z_session_loan(session),
            &mut listener,
            z_closure_transport_event_move(&mut closure),
            &options,
        ),
        Z_OK
    );
    listener
}

unsafe fn link_listener(
    session: &z_owned_session_t,
    history: bool,
    filter: *mut z_moved_transport_t,
    sink: &'static Sink,
) -> (i8, z_owned_link_events_listener_t) {
    let mut closure: z_owned_closure_link_event_t = std::mem::zeroed();
    z_closure_link_event(&mut closure, Some(on_link_event), Some(released), ctx(sink));
    let mut options: z_link_events_listener_options_t = std::mem::zeroed();
    z_link_events_listener_options_default(&mut options);
    options.history = history;
    options.transport = filter;
    let mut listener: z_owned_link_events_listener_t = std::mem::zeroed();
    let rc = z_declare_link_events_listener(
        z_session_loan(session),
        &mut listener,
        z_closure_link_event_move(&mut closure),
        &mut options,
    );
    (rc, listener)
}

/// An owned transport naming `zid`, cloned out of a loaned value the way a C
/// program clones one out of a callback.
unsafe fn transport_named(zid: [u8; 16]) -> z_owned_transport_t {
    let loaned = z_loaned_transport_t {
        zid: wz_capi_pico::zid::z_id_t { id: zid },
        whatami: WHATAMI_CLIENT,
        is_qos: false,
        is_multicast: false,
        is_shm: false,
    };
    let mut owned: z_owned_transport_t = std::mem::zeroed();
    assert_eq!(z_transport_clone(&mut owned, &loaned), Z_OK);
    owned
}

unsafe fn list_links(
    session: &z_owned_session_t,
    filter: *mut z_moved_transport_t,
    sink: &'static Sink,
) -> i8 {
    let mut closure: z_owned_closure_link_t = std::mem::zeroed();
    z_closure_link(&mut closure, Some(on_link), Some(released), ctx(sink));
    let mut options: z_info_links_options_t = std::mem::zeroed();
    z_info_links_options_default(&mut options);
    options.transport = filter;
    z_info_links(
        z_session_loan(session),
        z_closure_link_move(&mut closure),
        &mut options,
    )
}

unsafe fn list_transports(session: &z_owned_session_t, sink: &'static Sink) -> i8 {
    let mut closure: z_owned_closure_transport_t = std::mem::zeroed();
    z_closure_transport(&mut closure, Some(on_transport), Some(released), ctx(sink));
    z_info_transports(
        z_session_loan(session),
        z_closure_transport_move(&mut closure),
    )
}

/// A peer arrives, is listed, and leaves; the listeners and the two listings
/// say what pico's do, in pico's order.
#[test]
fn a_peer_arriving_and_leaving_is_reported_the_way_pico_reports_it() {
    let port = free_port();
    let listener_locator = format!("tcp/127.0.0.1:{port}");
    let mut peer_zid = [0u8; 16];
    getrandom::getrandom(&mut peer_zid).expect("OS entropy");
    peer_zid[0] |= 1; // a zid pico reads as set
    let peer_hex = hex(&peer_zid);

    let mut session = unsafe { open_c_listener(port) };

    // Both listeners write to ONE log, so the order is what the log says. The
    // transport listener is declared FIRST: a watcher per listener would put it
    // ahead of the link listener on a departure as well.
    let live = sink();
    let transport_a = unsafe { transport_listener(&session, false, live) };
    let (rc, link_a) = unsafe { link_listener(&session, false, std::ptr::null_mut(), live) };
    assert_eq!(rc, Z_OK);

    // With nobody connected, the listings are empty.
    let empty = sink();
    unsafe {
        assert_eq!(list_transports(&session, empty), Z_OK);
        assert_eq!(list_links(&session, std::ptr::null_mut(), empty), Z_OK);
    }
    assert!(
        seen(empty).is_empty(),
        "nothing is connected yet: {:?}",
        seen(empty)
    );
    assert_eq!(
        empty.released.load(Ordering::SeqCst),
        2,
        "each listing consumes its closure"
    );

    // THE ARRIVAL.
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let die = Arc::new(tokio::sync::Notify::new());
    let die_peer = die.clone();
    let endpoint = listener_locator.clone();
    let peer = std::thread::spawn(move || native_peer(endpoint, peer_zid, ready_tx, die_peer));
    ready_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the native peer never reached Established");
    assert!(
        wait_for(|| seen(live).len() >= 2, Duration::from_secs(10)),
        "the arrival produced no transport and link events: {:?}",
        seen(live)
    );
    let arrival = seen(live);
    assert_eq!(
        arrival[0],
        format!("transport PUT zid={peer_hex} whatami={WHATAMI_CLIENT} qos=false multicast=false shm=false"),
        "the transport comes first, reporting the peer's zid and role as pico's bitmask"
    );
    let link_prefix = format!("link PUT zid={peer_hex} src={listener_locator} dst=tcp/127.0.0.1:");
    assert!(
        arrival[1].starts_with(&link_prefix)
            && arrival[1].ends_with("mtu=65535 streamed=true reliable=true"),
        "the link comes second and reports pico's TCP link (65535 B, streamed, reliable), \
         not the batch size the two ends negotiated (2048): {}",
        arrival[1]
    );

    // THE LISTINGS while the peer is there.
    let listed = sink();
    unsafe {
        assert_eq!(list_transports(&session, listed), Z_OK);
        assert_eq!(list_links(&session, std::ptr::null_mut(), listed), Z_OK);
    }
    let listed_lines = seen(listed);
    assert_eq!(
        listed_lines.len(),
        2,
        "one transport and one link: {listed_lines:?}"
    );
    assert_eq!(
        listed_lines[0],
        format!("listed transport zid={peer_hex} whatami={WHATAMI_CLIENT} qos=false multicast=false shm=false")
    );
    assert!(listed_lines[1].starts_with(&format!(
        "listed link zid={peer_hex} src={listener_locator}"
    )));

    // FILTERS. The link listing narrowed to the peer's transport still lists
    // its link, narrowed to another it lists nothing, and the moved transport
    // is consumed either way.
    let mut stranger = [0u8; 16];
    stranger[0] = 0xEE;
    let narrowed = sink();
    unsafe {
        let mut mine = transport_named(peer_zid);
        assert_eq!(
            list_links(&session, z_transport_move(&mut mine), narrowed),
            Z_OK
        );
        assert!(
            !wz_capi_pico::connectivity::z_internal_transport_check(&mine),
            "the moved transport is consumed"
        );
        let mut other = transport_named(stranger);
        assert_eq!(
            list_links(&session, z_transport_move(&mut other), narrowed),
            Z_OK
        );
    }
    assert_eq!(
        seen(narrowed).len(),
        1,
        "the peer's transport lists its link and a stranger's lists none: {:?}",
        seen(narrowed)
    );

    // A moved transport that holds nothing is refused, and the closure released.
    let refused = sink();
    unsafe {
        let mut nothing: z_owned_transport_t = std::mem::zeroed();
        assert_eq!(
            list_links(&session, z_transport_move(&mut nothing), refused),
            Z_EINVAL
        );
    }
    assert_eq!(
        refused.released.load(Ordering::SeqCst),
        1,
        "the closure is released on the refusal"
    );
    assert!(seen(refused).is_empty());

    // HISTORY. Declared now, the peer is already there, so it is replayed as
    // PUTs first — the transport and then its link.
    let replay = sink();
    let transport_b = unsafe { transport_listener(&session, true, replay) };
    let (rc, link_b) = unsafe { link_listener(&session, true, std::ptr::null_mut(), replay) };
    assert_eq!(rc, Z_OK);
    let replayed = seen(replay);
    assert_eq!(
        replayed.len(),
        2,
        "one transport and one link: {replayed:?}"
    );
    assert!(replayed[0].starts_with(&format!("transport PUT zid={peer_hex}")));
    assert!(replayed[1].starts_with(&format!("link PUT zid={peer_hex}")));

    // A link listener bound to a stranger's transport hears nothing of this peer.
    let deaf = sink();
    let (rc, link_c) = unsafe {
        let mut stranger_transport = transport_named(stranger);
        link_listener(
            &session,
            true,
            z_transport_move(&mut stranger_transport),
            deaf,
        )
    };
    assert_eq!(rc, Z_OK);
    assert!(
        seen(deaf).is_empty(),
        "a filter to another transport replays nothing"
    );

    // THE DEPARTURE: the link goes first and the transport after it, on every
    // listener.
    die.notify_one();
    peer.join().expect("native peer thread panicked");
    assert!(
        wait_for(|| seen(live).len() >= 4, Duration::from_secs(15)),
        "the departure was never reported: {:?}",
        seen(live)
    );
    let departure = seen(live)[2..].to_vec();
    assert!(
        departure[0].starts_with(&format!("link DEL zid={peer_hex} src={listener_locator}")),
        "the link goes first: {departure:?}"
    );
    assert_eq!(
        departure[1],
        format!("transport DEL zid={peer_hex} whatami={WHATAMI_CLIENT} qos=false multicast=false shm=false"),
        "the transport goes after its link"
    );
    assert!(wait_for(|| seen(replay).len() >= 4, Duration::from_secs(5)));
    assert!(
        seen(replay)[2].starts_with("link DEL"),
        "{:?}",
        seen(replay)
    );
    assert!(
        seen(replay)[3].starts_with("transport DEL"),
        "{:?}",
        seen(replay)
    );
    assert!(
        seen(deaf).is_empty(),
        "the filtered listener still hears nothing"
    );

    // UNDECLARING releases each context before it returns, once.
    unsafe {
        let mut ta = transport_a;
        let mut la = link_a;
        assert_eq!(
            z_undeclare_transport_events_listener(z_transport_events_listener_move(&mut ta)),
            Z_OK
        );
        assert_eq!(
            z_undeclare_link_events_listener(z_link_events_listener_move(&mut la)),
            Z_OK
        );
        assert_eq!(
            live.released.load(Ordering::SeqCst),
            2,
            "both contexts released on undeclare"
        );
        // A second undeclare of a spent handle is a no-op.
        assert_eq!(
            z_undeclare_transport_events_listener(z_transport_events_listener_move(&mut ta)),
            Z_OK
        );
        assert_eq!(live.released.load(Ordering::SeqCst), 2);

        // The rest are let go of with the session.
        let (_keep_b, _keep_b2, _keep_c) = (transport_b, link_b, link_c);
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
    }
    assert_eq!(
        replay.released.load(Ordering::SeqCst),
        2,
        "the session's end releases what was left"
    );
    assert_eq!(deaf.released.load(Ordering::SeqCst), 1);
}

/// A refusal for want of a session leaves the closure with the caller; a closed
/// session takes it and releases it. pico refuses a NULL session before taking
/// the closure and a closed one after.
#[test]
fn a_listener_refused_for_want_of_a_session_is_refused_the_way_pico_refuses_it() {
    unsafe {
        let untouched = sink();
        let mut closure: z_owned_closure_transport_event_t = std::mem::zeroed();
        z_closure_transport_event(
            &mut closure,
            Some(on_transport_event),
            Some(released),
            ctx(untouched),
        );
        let mut listener: z_owned_transport_events_listener_t = std::mem::zeroed();
        assert_eq!(
            z_declare_transport_events_listener(
                std::ptr::null(),
                &mut listener,
                z_closure_transport_event_move(&mut closure),
                std::ptr::null(),
            ),
            Z_ERR_SESSION_CLOSED
        );
        assert_eq!(
            untouched.released.load(Ordering::SeqCst),
            0,
            "a NULL session is refused before the closure is taken"
        );
        assert!(
            wz_capi_pico::connectivity::z_internal_closure_transport_event_check(&closure),
            "the closure is still the caller's"
        );
        // The caller releases it.
        wz_capi_pico::connectivity::z_closure_transport_event_drop(z_closure_transport_event_move(
            &mut closure,
        ));
        assert_eq!(untouched.released.load(Ordering::SeqCst), 1);

        // A session that has been closed.
        let port = free_port();
        let mut session = open_c_listener(port);
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        let taken = sink();
        let mut closure: z_owned_closure_transport_event_t = std::mem::zeroed();
        z_closure_transport_event(
            &mut closure,
            Some(on_transport_event),
            Some(released),
            ctx(taken),
        );
        let mut listener: z_owned_transport_events_listener_t = std::mem::zeroed();
        assert_eq!(
            z_declare_transport_events_listener(
                z_session_loan(&session),
                &mut listener,
                z_closure_transport_event_move(&mut closure),
                std::ptr::null(),
            ),
            Z_ERR_SESSION_CLOSED
        );
        assert_eq!(
            taken.released.load(Ordering::SeqCst),
            1,
            "a closed session takes the closure and releases it"
        );
        z_session_drop(z_session_move(&mut session));
    }
}
