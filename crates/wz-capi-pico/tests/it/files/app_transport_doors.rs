// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The doors of a transport the program supplies (`wz_ext_transport_*`), driven as a C program
//! drives them: two sessions in one process, one listening and one dialling, joined by an
//! in-memory transport this test implements and nothing else. No socket is opened.
//!
//! The test's transport hands every byte one side sends to the other side's
//! `wz_ext_transport_received`, from inside `send`, and injects the answers a stack under load
//! gives: some sends take half of what they are offered, some would block and are reported
//! writable from another thread a moment later. The sessions see none of it: the handshake
//! completes, a put reaches the subscriber, the sequence arrives whole and in order, a query gets
//! its reply. Cutting the pipe closes both ends, and the dialling session (pico re-opens a lost
//! client session by default) dials again over the transport and is served again.

#![cfg(all(
    feature = "app-transport",
    feature = "peer",
    feature = "query",
    feature = "queryable"
))]

use std::collections::{HashMap, HashSet};
use std::ffi::{c_char, c_void, CStr, CString};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_pico::app_transport::{
    wz_ext_config_transport, wz_ext_internal_transport_check, wz_ext_link_kind_t,
    wz_ext_link_result_t, wz_ext_link_t, wz_ext_loaned_transport_t, wz_ext_owned_transport_t,
    wz_ext_transport_accepted, wz_ext_transport_drop, wz_ext_transport_event,
    wz_ext_transport_loan, wz_ext_transport_move, wz_ext_transport_new, wz_ext_transport_received,
    wz_ext_transport_t, WZ_EXT_LINK_CLOSED, WZ_EXT_LINK_DATAGRAM, WZ_EXT_LINK_DATAGRAM_LISTEN,
    WZ_EXT_LINK_EVENT_CLOSED, WZ_EXT_LINK_EVENT_CONNECTED, WZ_EXT_LINK_EVENT_WRITABLE,
    WZ_EXT_LINK_GROUP, WZ_EXT_LINK_OK, WZ_EXT_LINK_STREAM_DIAL, WZ_EXT_LINK_STREAM_LISTEN,
    WZ_EXT_LINK_WOULD_BLOCK,
};
use wz_capi_pico::result::{
    WZ_EXT_ERR_LINK_UNKNOWN, WZ_EXT_ERR_UNSUPPORTED, Z_EINVAL, Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN,
};
use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_bytes_to_slice, z_close, z_closure_query,
    z_closure_query_move, z_closure_reply, z_closure_reply_move, z_closure_sample,
    z_closure_sample_move, z_config_default, z_config_drop, z_config_loan_mut, z_config_move,
    z_declare_queryable, z_declare_subscriber, z_get, z_get_options_default, z_get_options_t,
    z_loaned_bytes_t, z_loaned_query_t, z_loaned_reply_t, z_loaned_sample_t, z_open,
    z_owned_config_t, z_owned_queryable_t, z_owned_session_t, z_owned_slice_t,
    z_owned_subscriber_t, z_put, z_query_keyexpr, z_query_reply, z_queryable_move,
    z_queryable_options_default, z_queryable_options_t, z_reply_is_ok, z_reply_ok,
    z_sample_payload, z_session_drop, z_session_loan, z_session_loan_mut, z_session_move,
    z_slice_data, z_slice_drop, z_slice_len, z_slice_loan, z_slice_move, z_subscriber_move,
    z_undeclare_queryable, z_undeclare_subscriber, z_view_keyexpr_from_str, z_view_keyexpr_loan,
    z_view_keyexpr_t, zp_config_insert, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_ERR_NULL,
    Z_OK,
};

/// The locators the sessions name. Synthetic: no socket is opened for any.
const LISTEN: &str = "tcp/192.0.2.100:7447";
const ACCEPTED_REMOTE: &str = "tcp/192.0.2.200:41000";
const DATAGRAM_LISTEN: &str = "udp/192.0.2.100:7447";
const DATAGRAM_REMOTE: &str = "udp/192.0.2.200:41000";
const GROUP: &str = "udp/239.1.2.3:7447#iface=lan7";

/// The address each member of a group sends from, which the other is told with each datagram.
fn member_source(side: Side) -> &'static CStr {
    match side {
        Side::Listening => c"udp/192.0.2.1:7447",
        Side::Dialling => c"udp/192.0.2.2:7447",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Side {
    Listening,
    Dialling,
}

impl Side {
    fn other(self) -> Self {
        match self {
            Side::Listening => Side::Dialling,
            Side::Dialling => Side::Listening,
        }
    }
}

/// The in-memory pipe between the two transports, and what it saw.
#[derive(Default)]
struct Pipe {
    /// Each side's owned transport, at a stable address, as a raw pointer.
    transports: Mutex<HashMap<Side, usize>>,
    /// The listening side's listener link.
    listener: AtomicU64,
    /// Each open link and the link at the other end of it.
    peers: Mutex<HashMap<(Side, u64), u64>>,
    dials: AtomicUsize,
    dialler_sends: AtomicUsize,
    partials: AtomicUsize,
    blocks: AtomicUsize,
    closes: AtomicUsize,
    drops: AtomicUsize,
    /// A send that found its pair gone.
    orphan_sends: AtomicUsize,
    /// Set while the pipe refuses new dials.
    refusing: AtomicBool,
    /// Whether the dialling side's stream sends are answered partly and with would-blocks.
    faults: AtomicBool,
    /// The links that carry datagrams, which are handed over whole with their source.
    datagrams: Mutex<HashSet<(Side, u64)>>,
    /// Each side's group link, when it joined one.
    groups: Mutex<HashMap<Side, u64>>,
    /// How many times the transport told a side a link was read down.
    drained: AtomicUsize,
}

impl Pipe {
    fn loan(&self, side: Side) -> *const wz_ext_loaned_transport_t {
        let raw = *self
            .transports
            .lock()
            .unwrap()
            .get(&side)
            .expect("both transports are made before any session opens");
        unsafe { wz_ext_transport_loan(raw as *const wz_ext_owned_transport_t) }
    }

    fn peer_of(&self, side: Side, link: u64) -> Option<u64> {
        self.peers.lock().unwrap().get(&(side, link)).copied()
    }
}

struct SideCtx {
    pipe: Arc<Pipe>,
    side: Side,
}

unsafe fn ctx<'a>(context: *mut c_void) -> &'a SideCtx {
    &*(context as *const SideCtx)
}

unsafe extern "C" fn on_open(
    context: *mut c_void,
    link: wz_ext_link_t,
    kind: wz_ext_link_kind_t,
    locator: *const c_char,
) -> wz_ext_link_result_t {
    let ctx = ctx(context);
    let pipe = &ctx.pipe;
    let locator = CStr::from_ptr(locator).to_str().unwrap_or("");
    match (ctx.side, kind) {
        (Side::Listening, WZ_EXT_LINK_STREAM_LISTEN) if locator == LISTEN => {
            pipe.listener.store(link, Ordering::SeqCst);
            WZ_EXT_LINK_OK
        }
        (Side::Listening, WZ_EXT_LINK_DATAGRAM_LISTEN) if locator == DATAGRAM_LISTEN => {
            pipe.listener.store(link, Ordering::SeqCst);
            WZ_EXT_LINK_OK
        }
        // Each member joins the group; the pipe hands a member's datagrams to the other.
        (side, WZ_EXT_LINK_GROUP) if locator == GROUP => {
            pipe.groups.lock().unwrap().insert(side, link);
            pipe.datagrams.lock().unwrap().insert((side, link));
            WZ_EXT_LINK_OK
        }
        (Side::Dialling, WZ_EXT_LINK_STREAM_DIAL) if locator == LISTEN => {
            if pipe.refusing.load(Ordering::SeqCst) {
                return WZ_EXT_LINK_CLOSED;
            }
            if !accept_and_pair(pipe, link, ACCEPTED_REMOTE, false) {
                return WZ_EXT_LINK_CLOSED;
            }
            // Reported up from the program's own thread, after open has answered.
            let pipe = Arc::clone(pipe);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(2));
                let _ = wz_ext_transport_event(
                    pipe.loan(Side::Dialling),
                    link,
                    WZ_EXT_LINK_EVENT_CONNECTED,
                );
            });
            WZ_EXT_LINK_WOULD_BLOCK
        }
        // A datagram link is up at once: there is no connection to make.
        (Side::Dialling, WZ_EXT_LINK_DATAGRAM) if locator == DATAGRAM_LISTEN => {
            if accept_and_pair(pipe, link, DATAGRAM_REMOTE, true) {
                WZ_EXT_LINK_OK
            } else {
                WZ_EXT_LINK_CLOSED
            }
        }
        _ => WZ_EXT_LINK_CLOSED,
    }
}

/// The listening program accepts the dialled `link` on its listener, under `remote`, and the two
/// links are paired before the dial is answered, so neither side sends into nothing.
unsafe fn accept_and_pair(pipe: &Arc<Pipe>, link: u64, remote: &str, datagram: bool) -> bool {
    pipe.dials.fetch_add(1, Ordering::SeqCst);
    let mut accepted: wz_ext_link_t = 0;
    let listener = pipe.listener.load(Ordering::SeqCst);
    let remote = CString::new(remote).unwrap();
    if wz_ext_transport_accepted(
        pipe.loan(Side::Listening),
        listener,
        remote.as_ptr(),
        &mut accepted,
    ) != Z_OK
    {
        return false;
    }
    if datagram {
        let mut datagrams = pipe.datagrams.lock().unwrap();
        datagrams.insert((Side::Dialling, link));
        datagrams.insert((Side::Listening, accepted));
    }
    let mut peers = pipe.peers.lock().unwrap();
    peers.insert((Side::Dialling, link), accepted);
    peers.insert((Side::Listening, accepted), link);
    true
}

unsafe extern "C" fn on_send(
    context: *mut c_void,
    link: wz_ext_link_t,
    data: *const u8,
    len: usize,
    written: *mut usize,
) -> wz_ext_link_result_t {
    let ctx = ctx(context);
    let pipe = &ctx.pipe;
    // A group member's datagram goes to the other member, with this member's address.
    let member = {
        let groups = pipe.groups.lock().unwrap();
        (groups.get(&ctx.side) == Some(&link)).then(|| groups.get(&ctx.side.other()).copied())
    };
    if let Some(other) = member {
        if let Some(other) = other {
            let _ = wz_ext_transport_received(
                pipe.loan(ctx.side.other()),
                other,
                data,
                len,
                member_source(ctx.side).as_ptr(),
            );
        }
        *written = len;
        return WZ_EXT_LINK_OK;
    }
    let Some(peer) = pipe.peer_of(ctx.side, link) else {
        pipe.orphan_sends.fetch_add(1, Ordering::SeqCst);
        return WZ_EXT_LINK_CLOSED;
    };
    // A datagram is handed over whole, with the address the other side knows this one by.
    if pipe.datagrams.lock().unwrap().contains(&(ctx.side, link)) {
        let source = match ctx.side {
            Side::Dialling => CString::new(DATAGRAM_REMOTE).unwrap(),
            Side::Listening => CString::new(DATAGRAM_LISTEN).unwrap(),
        };
        if wz_ext_transport_received(
            pipe.loan(ctx.side.other()),
            peer,
            data,
            len,
            source.as_ptr(),
        ) != Z_OK
        {
            return WZ_EXT_LINK_CLOSED;
        }
        *written = len;
        return WZ_EXT_LINK_OK;
    }
    let mut take = len;
    if ctx.side == Side::Dialling && pipe.faults.load(Ordering::SeqCst) {
        let n = pipe.dialler_sends.fetch_add(1, Ordering::SeqCst);
        if n % 7 == 3 {
            pipe.blocks.fetch_add(1, Ordering::SeqCst);
            let pipe = Arc::clone(pipe);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(2));
                let _ = wz_ext_transport_event(
                    pipe.loan(Side::Dialling),
                    link,
                    WZ_EXT_LINK_EVENT_WRITABLE,
                );
            });
            return WZ_EXT_LINK_WOULD_BLOCK;
        }
        if n % 5 == 1 && len > 1 {
            pipe.partials.fetch_add(1, Ordering::SeqCst);
            take = len / 2;
        }
    }
    let bytes = std::slice::from_raw_parts(data, take);
    if wz_ext_transport_received(
        pipe.loan(ctx.side.other()),
        peer,
        bytes.as_ptr(),
        bytes.len(),
        std::ptr::null(),
    ) != Z_OK
    {
        return WZ_EXT_LINK_CLOSED;
    }
    *written = take;
    WZ_EXT_LINK_OK
}

unsafe extern "C" fn on_close(context: *mut c_void, link: wz_ext_link_t) {
    let ctx = ctx(context);
    let pipe = &ctx.pipe;
    pipe.closes.fetch_add(1, Ordering::SeqCst);
    // A member that closes its group link has left the group.
    {
        let mut groups = pipe.groups.lock().unwrap();
        if groups.get(&ctx.side) == Some(&link) {
            groups.remove(&ctx.side);
        }
    }
    let peer = {
        let mut peers = pipe.peers.lock().unwrap();
        let peer = peers.remove(&(ctx.side, link));
        if let Some(peer) = peer {
            peers.remove(&(ctx.side.other(), peer));
        }
        peer
    };
    // The other end hears the close, from inside this close.
    if let Some(peer) = peer {
        let _ = wz_ext_transport_event(pipe.loan(ctx.side.other()), peer, WZ_EXT_LINK_EVENT_CLOSED);
    }
}

unsafe extern "C" fn on_drained(context: *mut c_void, _link: wz_ext_link_t) {
    ctx(context).pipe.drained.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn on_drop(context: *mut c_void) {
    let ctx = Box::from_raw(context as *mut SideCtx);
    ctx.pipe.drops.fetch_add(1, Ordering::SeqCst);
}

/// A transport of `side` over the pipe, owned at a stable address.
fn make_transport(pipe: &Arc<Pipe>, side: Side) -> *mut wz_ext_owned_transport_t {
    let context = Box::into_raw(Box::new(SideCtx {
        pipe: Arc::clone(pipe),
        side,
    })) as *mut c_void;
    let calls = wz_ext_transport_t {
        context,
        open: Some(on_open),
        send: Some(on_send),
        close: Some(on_close),
        drained: Some(on_drained),
        drop: Some(on_drop),
    };
    let owned: *mut wz_ext_owned_transport_t =
        Box::into_raw(Box::new(unsafe { std::mem::zeroed() }));
    assert_eq!(unsafe { wz_ext_transport_new(owned, &calls) }, Z_OK);
    assert!(unsafe { wz_ext_internal_transport_check(owned) });
    pipe.transports.lock().unwrap().insert(side, owned as usize);
    owned
}

/// Release the program's reference to a transport and free its slot.
fn drop_transport(owned: *mut wz_ext_owned_transport_t) {
    unsafe {
        wz_ext_transport_drop(wz_ext_transport_move(owned));
        assert!(!wz_ext_internal_transport_check(owned));
        drop(Box::from_raw(owned));
    }
}

/// A config with `key` set to `locator`, carrying `transport`.
fn config_over(
    key: u8,
    locator: &str,
    transport: *mut wz_ext_owned_transport_t,
) -> z_owned_config_t {
    let locator = CString::new(locator).unwrap();
    unsafe {
        let mut cfg: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut cfg), Z_OK);
        assert_eq!(
            zp_config_insert(z_config_loan_mut(&mut cfg), key, locator.as_ptr()),
            Z_OK
        );
        assert_eq!(
            wz_ext_config_transport(
                z_config_loan_mut(&mut cfg),
                wz_ext_transport_loan(transport)
            ),
            Z_OK
        );
        cfg
    }
}

fn wait_until(what: &str, within: Duration, done: impl Fn() -> bool) {
    let deadline = Instant::now() + within;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

unsafe fn bytes_of(payload: *const z_loaned_bytes_t) -> Vec<u8> {
    let mut slice: z_owned_slice_t = std::mem::zeroed();
    if payload.is_null() || z_bytes_to_slice(payload, &mut slice) != Z_OK {
        return Vec::new();
    }
    let loaned = z_slice_loan(&slice);
    let data = z_slice_data(loaned);
    let out = if data.is_null() {
        Vec::new()
    } else {
        std::slice::from_raw_parts(data, z_slice_len(loaned)).to_vec()
    };
    z_slice_drop(z_slice_move(&mut slice));
    out
}

/// What the listening side's subscriber was handed, in order.
#[derive(Default)]
struct Heard {
    payloads: Mutex<Vec<Vec<u8>>>,
}

unsafe extern "C" fn on_sample(sample: *const z_loaned_sample_t, context: *mut c_void) {
    let heard = &*(context as *const Heard);
    let payload = bytes_of(z_sample_payload(sample));
    heard.payloads.lock().unwrap().push(payload);
}

unsafe extern "C" fn on_sample_drop(context: *mut c_void) {
    drop(Arc::from_raw(context as *const Heard));
}

unsafe extern "C" fn on_query(query: *const z_loaned_query_t, _context: *mut c_void) {
    let mut payload = std::mem::zeroed();
    if z_bytes_copy_from_str(&mut payload, c"answer-over-the-pipe".as_ptr()) == Z_OK {
        let _ = z_query_reply(
            query,
            z_query_keyexpr(query),
            z_bytes_move(&mut payload),
            std::ptr::null(),
        );
    }
}

unsafe extern "C" fn on_query_drop(_context: *mut c_void) {}

#[derive(Default)]
struct Replies {
    payloads: Mutex<Vec<Vec<u8>>>,
    done: AtomicBool,
}

unsafe extern "C" fn on_reply(reply: *mut z_loaned_reply_t, context: *mut c_void) {
    let replies = &*(context as *const Replies);
    if z_reply_is_ok(reply) {
        let payload = bytes_of(z_sample_payload(z_reply_ok(reply)));
        replies.payloads.lock().unwrap().push(payload);
    }
}

unsafe extern "C" fn on_reply_drop(context: *mut c_void) {
    let replies = Arc::from_raw(context as *const Replies);
    replies.done.store(true, Ordering::SeqCst);
}

unsafe fn put(session: &z_owned_session_t, key: &CStr, payload: &str) {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
    let text = CString::new(payload).unwrap();
    let mut bytes = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut bytes, text.as_ptr()), Z_OK);
    let _ = z_put(
        z_session_loan(session),
        z_view_keyexpr_loan(&ke),
        z_bytes_move(&mut bytes),
        std::ptr::null(),
    );
}

/// Put `probe` on `key` until the subscriber has heard one, as the declaration of a subscriber
/// takes a moment to reach the putting session.
unsafe fn converge(session: &z_owned_session_t, key: &CStr, heard: &Heard, probe: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        put(session, key, probe);
        std::thread::sleep(Duration::from_millis(20));
        if heard
            .payloads
            .lock()
            .unwrap()
            .iter()
            .any(|payload| payload == probe.as_bytes())
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the probe {probe:?} never arrived"
        );
    }
}

#[test]
fn two_sessions_joined_by_the_programs_transport_carry_a_put_a_sequence_and_a_query() {
    let pipe = Arc::new(Pipe::default());
    pipe.faults.store(true, Ordering::SeqCst);
    let listening = make_transport(&pipe, Side::Listening);
    let dialling = make_transport(&pipe, Side::Dialling);

    unsafe {
        // The listening session: its open is its listener's, which the program answers up.
        let mut listener: z_owned_session_t = std::mem::zeroed();
        let mut cfg = config_over(Z_CONFIG_LISTEN_KEY, LISTEN, listening);
        assert_eq!(
            z_open(&mut listener, z_config_move(&mut cfg), std::ptr::null()),
            Z_OK
        );
        assert_ne!(
            pipe.listener.load(Ordering::SeqCst),
            0,
            "the listener was opened"
        );

        let heard = Arc::new(Heard::default());
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_sample(
                &mut closure,
                Some(on_sample),
                Some(on_sample_drop),
                Arc::into_raw(Arc::clone(&heard)) as *mut c_void,
            ),
            Z_OK
        );
        let mut sub_ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut sub_ke, c"demo/pipe/**".as_ptr()),
            Z_OK
        );
        let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&listener),
                &mut subscriber,
                z_view_keyexpr_loan(&sub_ke),
                z_closure_sample_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK
        );

        let mut query_closure = std::mem::zeroed();
        assert_eq!(
            z_closure_query(
                &mut query_closure,
                Some(on_query),
                Some(on_query_drop),
                std::ptr::null_mut()
            ),
            Z_OK
        );
        let mut qbl_ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut qbl_ke, c"demo/ask".as_ptr()),
            Z_OK
        );
        let mut opts: z_queryable_options_t = std::mem::zeroed();
        z_queryable_options_default(&mut opts);
        let mut queryable: z_owned_queryable_t = std::mem::zeroed();
        assert_eq!(
            z_declare_queryable(
                z_session_loan(&listener),
                &mut queryable,
                z_view_keyexpr_loan(&qbl_ke),
                z_closure_query_move(&mut query_closure),
                &opts,
            ),
            Z_OK
        );

        // The dialling session: z_open runs the whole handshake over the pipe, through the
        // partial sends and the would-blocks the pipe injects from the first byte on.
        let mut dialler: z_owned_session_t = std::mem::zeroed();
        let mut cfg = config_over(Z_CONFIG_CONNECT_KEY, LISTEN, dialling);
        assert_eq!(
            z_open(&mut dialler, z_config_move(&mut cfg), std::ptr::null()),
            Z_OK,
            "the dial over the program's transport opens"
        );
        assert_eq!(pipe.dials.load(Ordering::SeqCst), 1);

        // A put reaches the subscriber.
        converge(&dialler, c"demo/pipe/probe", &heard, "probe");

        // A sequence arrives whole and in order, through the injected faults.
        heard.payloads.lock().unwrap().clear();
        let sequence: Vec<String> = (0..40).map(|n| format!("seq-{n:03}")).collect();
        for item in &sequence {
            put(&dialler, c"demo/pipe/seq", item);
        }
        wait_until("the whole sequence", Duration::from_secs(15), || {
            heard
                .payloads
                .lock()
                .unwrap()
                .iter()
                .filter(|payload| payload.starts_with(b"seq-"))
                .count()
                >= sequence.len()
        });
        let got: Vec<Vec<u8>> = heard
            .payloads
            .lock()
            .unwrap()
            .iter()
            .filter(|payload| payload.starts_with(b"seq-"))
            .cloned()
            .collect();
        let sent: Vec<Vec<u8>> = sequence
            .iter()
            .map(|item| item.as_bytes().to_vec())
            .collect();
        assert_eq!(got, sent, "every put arrives once, in order");
        assert!(
            pipe.partials.load(Ordering::SeqCst) > 0,
            "partial sends were injected"
        );
        assert!(
            pipe.blocks.load(Ordering::SeqCst) > 0,
            "would-blocks were injected"
        );

        // A query gets its reply.
        let replies = Arc::new(Replies::default());
        let mut reply_closure = std::mem::zeroed();
        assert_eq!(
            z_closure_reply(
                &mut reply_closure,
                Some(on_reply),
                Some(on_reply_drop),
                Arc::into_raw(Arc::clone(&replies)) as *mut c_void,
            ),
            Z_OK
        );
        let mut get_ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut get_ke, c"demo/ask".as_ptr()),
            Z_OK
        );
        let mut get_opts: z_get_options_t = std::mem::zeroed();
        z_get_options_default(&mut get_opts);
        get_opts.timeout_ms = 5000;
        assert_eq!(
            z_get(
                z_session_loan(&dialler),
                z_view_keyexpr_loan(&get_ke),
                std::ptr::null(),
                z_closure_reply_move(&mut reply_closure),
                &mut get_opts,
            ),
            Z_OK
        );
        wait_until("the get to complete", Duration::from_secs(10), || {
            replies.done.load(Ordering::SeqCst)
        });
        assert_eq!(
            replies.payloads.lock().unwrap().as_slice(),
            [b"answer-over-the-pipe".to_vec()],
            "the query got its one reply"
        );

        // Cutting the pipe closes both ends; the dialling session dials again over the
        // transport, and a put reaches the subscriber over the new link.
        let cut: Vec<((Side, u64), u64)> = pipe.peers.lock().unwrap().drain().collect();
        for ((side, link), _) in &cut {
            let _ = wz_ext_transport_event(pipe.loan(*side), *link, WZ_EXT_LINK_EVENT_CLOSED);
        }
        wait_until(
            "the dialling session to dial again",
            Duration::from_secs(15),
            || pipe.dials.load(Ordering::SeqCst) >= 2,
        );
        heard.payloads.lock().unwrap().clear();
        converge(&dialler, c"demo/pipe/probe", &heard, "after-the-cut");

        // Teardown. Every link the sessions held is closed on the program, and once the
        // sessions and the program's own references are gone, each transport's drop runs once.
        z_undeclare_subscriber(z_subscriber_move(&mut subscriber));
        z_undeclare_queryable(z_queryable_move(&mut queryable));
        z_close(z_session_loan_mut(&mut dialler), std::ptr::null());
        z_session_drop(z_session_move(&mut dialler));
        z_close(z_session_loan_mut(&mut listener), std::ptr::null());
        z_session_drop(z_session_move(&mut listener));
    }
    drop_transport(dialling);
    drop_transport(listening);
    wait_until("both transports to drop", Duration::from_secs(10), || {
        pipe.drops.load(Ordering::SeqCst) == 2
    });
    assert!(
        pipe.closes.load(Ordering::SeqCst) > 0,
        "the sessions closed their links"
    );
}

#[test]
fn an_open_over_the_transport_refuses_what_it_does_not_carry_by_name() {
    let pipe = Arc::new(Pipe::default());
    let transport = make_transport(&pipe, Side::Dialling);
    for (key, locator, code) in [
        (
            Z_CONFIG_CONNECT_KEY,
            "tls/192.0.2.100:7447",
            Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN,
        ),
        (
            Z_CONFIG_CONNECT_KEY,
            "serial//dev/ttyQ9",
            Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN,
        ),
        (
            Z_CONFIG_LISTEN_KEY,
            "quic/192.0.2.100:7447",
            Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN,
        ),
    ] {
        let mut cfg = config_over(key, locator, transport);
        let mut session: z_owned_session_t = unsafe { std::mem::zeroed() };
        let rc = unsafe { z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()) };
        assert_eq!(rc, code, "{locator}");
    }
    // A config with no locator would scout on the system's sockets.
    unsafe {
        let mut cfg: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut cfg), Z_OK);
        assert_eq!(
            wz_ext_config_transport(
                z_config_loan_mut(&mut cfg),
                wz_ext_transport_loan(transport)
            ),
            Z_OK
        );
        let mut session: z_owned_session_t = std::mem::zeroed();
        assert_eq!(
            z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
            WZ_EXT_ERR_UNSUPPORTED
        );
    }
    assert_eq!(pipe.dials.load(Ordering::SeqCst), 0, "nothing was opened");
    drop_transport(transport);
    assert_eq!(
        pipe.drops.load(Ordering::SeqCst),
        1,
        "the last reference ran drop once"
    );
}

#[test]
fn a_dial_the_program_refuses_fails_the_open_and_leaves_no_link() {
    let pipe = Arc::new(Pipe::default());
    pipe.refusing.store(true, Ordering::SeqCst);
    let transport = make_transport(&pipe, Side::Dialling);
    let mut cfg = config_over(Z_CONFIG_CONNECT_KEY, LISTEN, transport);
    let mut session: z_owned_session_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()) };
    assert!(rc < 0, "a refused dial fails the open: {rc}");
    assert_eq!(
        pipe.closes.load(Ordering::SeqCst),
        0,
        "a refused link is not closed again"
    );
    drop_transport(transport);
    wait_until("the transport to drop", Duration::from_secs(10), || {
        pipe.drops.load(Ordering::SeqCst) == 1
    });
}

#[test]
fn the_programs_calls_are_refused_by_name() {
    let pipe = Arc::new(Pipe::default());
    let transport = make_transport(&pipe, Side::Listening);
    unsafe {
        let loan = wz_ext_transport_loan(transport);
        assert_eq!(
            wz_ext_transport_received(loan, 42, b"x".as_ptr(), 1, std::ptr::null()),
            WZ_EXT_ERR_LINK_UNKNOWN
        );
        assert_eq!(
            wz_ext_transport_received(loan, 42, std::ptr::null(), 1, std::ptr::null()),
            Z_ERR_NULL
        );
        assert_eq!(wz_ext_transport_event(loan, 42, 9), Z_EINVAL);
        assert_eq!(
            wz_ext_transport_event(loan, 42, WZ_EXT_LINK_EVENT_CONNECTED),
            WZ_EXT_ERR_LINK_UNKNOWN
        );
        let mut out: wz_ext_link_t = 7;
        assert_eq!(
            wz_ext_transport_accepted(loan, 42, c"tcp/192.0.2.1:1".as_ptr(), &mut out),
            WZ_EXT_ERR_LINK_UNKNOWN
        );
        assert_eq!(out, 0, "no handle on an error");
        assert_eq!(
            wz_ext_transport_accepted(loan, 42, std::ptr::null(), &mut out),
            Z_ERR_NULL
        );
        assert_eq!(
            wz_ext_transport_received(std::ptr::null(), 1, std::ptr::null(), 0, std::ptr::null()),
            Z_ERR_NULL
        );
        // A transport without its required calls is not made.
        let calls = wz_ext_transport_t {
            context: std::ptr::null_mut(),
            open: Some(on_open),
            send: None,
            close: Some(on_close),
            drained: None,
            drop: None,
        };
        let mut owned: wz_ext_owned_transport_t = std::mem::zeroed();
        assert_eq!(wz_ext_transport_new(&mut owned, &calls), Z_ERR_NULL);
        assert!(!wz_ext_internal_transport_check(&owned));
        // A config given the transport holds it past the program's own reference.
        let mut cfg: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut cfg), Z_OK);
        assert_eq!(
            wz_ext_config_transport(z_config_loan_mut(&mut cfg), loan),
            Z_OK
        );
        drop_transport(transport);
        assert_eq!(
            pipe.drops.load(Ordering::SeqCst),
            0,
            "the config still holds it"
        );
        z_config_drop(z_config_move(&mut cfg));
        assert_eq!(
            pipe.drops.load(Ordering::SeqCst),
            1,
            "drop ran with the last reference"
        );
    }
}

/// Declare a subscriber on `key` of `session`, which records what it is handed.
unsafe fn subscribe(session: &z_owned_session_t, key: &CStr) -> (Arc<Heard>, z_owned_subscriber_t) {
    let heard = Arc::new(Heard::default());
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_sample(
            &mut closure,
            Some(on_sample),
            Some(on_sample_drop),
            Arc::into_raw(Arc::clone(&heard)) as *mut c_void,
        ),
        Z_OK
    );
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
    let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
    assert_eq!(
        z_declare_subscriber(
            z_session_loan(session),
            &mut subscriber,
            z_view_keyexpr_loan(&ke),
            z_closure_sample_move(&mut closure),
            std::ptr::null(),
        ),
        Z_OK
    );
    (heard, subscriber)
}

/// Declare a queryable on `key` of `session` that answers every query with one reply.
unsafe fn serve(session: &z_owned_session_t, key: &CStr) -> z_owned_queryable_t {
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_query(
            &mut closure,
            Some(on_query),
            Some(on_query_drop),
            std::ptr::null_mut()
        ),
        Z_OK
    );
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
    let mut opts: z_queryable_options_t = std::mem::zeroed();
    z_queryable_options_default(&mut opts);
    let mut queryable: z_owned_queryable_t = std::mem::zeroed();
    assert_eq!(
        z_declare_queryable(
            z_session_loan(session),
            &mut queryable,
            z_view_keyexpr_loan(&ke),
            z_closure_query_move(&mut closure),
            &opts,
        ),
        Z_OK
    );
    queryable
}

/// Ask `key` of `session` until a reply comes, or the bound runs out: the queryable's declaration
/// takes a moment to reach the asking session. The replies of the get that was answered.
unsafe fn ask(session: &z_owned_session_t, key: &CStr) -> Vec<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let replies = Arc::new(Replies::default());
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_reply(
                &mut closure,
                Some(on_reply),
                Some(on_reply_drop),
                Arc::into_raw(Arc::clone(&replies)) as *mut c_void,
            ),
            Z_OK
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
        let mut opts: z_get_options_t = std::mem::zeroed();
        z_get_options_default(&mut opts);
        opts.timeout_ms = 1000;
        assert_eq!(
            z_get(
                z_session_loan(session),
                z_view_keyexpr_loan(&ke),
                std::ptr::null(),
                z_closure_reply_move(&mut closure),
                &mut opts,
            ),
            Z_OK
        );
        wait_until("the get to complete", Duration::from_secs(5), || {
            replies.done.load(Ordering::SeqCst)
        });
        let got = replies.payloads.lock().unwrap().clone();
        if !got.is_empty() {
            return got;
        }
        assert!(Instant::now() < deadline, "no get was ever answered");
        // A get that found no target completed at once; the next is asked after a pause.
        std::thread::sleep(Duration::from_millis(200));
    }
}

unsafe extern "C" fn on_peer(_id: *const wz_capi_pico::zid::z_id_t, context: *mut c_void) {
    (*(context as *const AtomicUsize)).fetch_add(1, Ordering::SeqCst);
}

/// Wait until `session` knows a peer, as `z_info_peers_zid` lists them. A group member knows
/// another only from the other's JOIN, which zenoh-pico sends every `Z_JOIN_INTERVAL` (2500 ms)
/// and not in answer to a new member's own, and a get asked while no peer is known completes at
/// once with no reply (`vendor/zenoh-pico/src/net/primitives.c` @ `if (remaining_finals == 0) {`).
/// A client of a pair knows its peer from its open, so this returns at once there.
unsafe fn wait_for_peer(session: &z_owned_session_t) {
    use wz_capi_pico::zid::{z_closure_zid, z_closure_zid_move, z_info_peers_zid};
    let peers = AtomicUsize::new(0);
    wait_until(
        "the asking session to know a peer",
        Duration::from_secs(10),
        || {
            peers.store(0, Ordering::SeqCst);
            let mut closure = std::mem::zeroed();
            assert_eq!(
                z_closure_zid(
                    &mut closure,
                    Some(on_peer),
                    None,
                    &peers as *const AtomicUsize as *mut c_void,
                ),
                Z_OK
            );
            let _ = z_info_peers_zid(z_session_loan(session), z_closure_zid_move(&mut closure));
            peers.load(Ordering::SeqCst) > 0
        },
    );
}

/// A session opened on `locator` under `key` over `transport`.
unsafe fn open_over(
    key: u8,
    locator: &str,
    transport: *mut wz_ext_owned_transport_t,
) -> z_owned_session_t {
    let mut session: z_owned_session_t = std::mem::zeroed();
    let mut cfg = config_over(key, locator, transport);
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK,
        "{locator} opens over the program's transport"
    );
    session
}

unsafe fn close(mut session: z_owned_session_t) {
    z_close(z_session_loan_mut(&mut session), std::ptr::null());
    z_session_drop(z_session_move(&mut session));
}

/// A put and a get between `listener` and `dialler`: the subscriber and the queryable on the
/// listening side, the put and the get from the dialling side.
unsafe fn put_and_get(listener: &z_owned_session_t, dialler: &z_owned_session_t) {
    let (heard, mut subscriber) = subscribe(listener, c"demo/pipe/**");
    let mut queryable = serve(listener, c"demo/ask");
    converge(dialler, c"demo/pipe/probe", &heard, "probe");
    wait_for_peer(dialler);
    assert_eq!(
        ask(dialler, c"demo/ask"),
        [b"answer-over-the-pipe".to_vec()],
        "the query got its one reply"
    );
    z_undeclare_subscriber(z_subscriber_move(&mut subscriber));
    z_undeclare_queryable(z_queryable_move(&mut queryable));
}

/// A client session opens over the program's transport and carries a put and a get, on the
/// engine the build has: the test of a cooperative-engine build as much as of a tokio one.
#[test]
fn a_client_session_opens_over_the_programs_transport_on_the_builds_engine() {
    let pipe = Arc::new(Pipe::default());
    let listening = make_transport(&pipe, Side::Listening);
    let dialling = make_transport(&pipe, Side::Dialling);
    unsafe {
        let listener = open_over(Z_CONFIG_LISTEN_KEY, LISTEN, listening);
        let dialler = open_over(Z_CONFIG_CONNECT_KEY, LISTEN, dialling);
        assert_eq!(pipe.dials.load(Ordering::SeqCst), 1);
        put_and_get(&listener, &dialler);
        close(dialler);
        close(listener);
    }
    drop_transport(dialling);
    drop_transport(listening);
    wait_until("both transports to drop", Duration::from_secs(10), || {
        pipe.drops.load(Ordering::SeqCst) == 2
    });
}

/// A datagram pair: the listening session listens for datagrams, the program accepts the
/// dialling session's source on it, and each datagram crosses the pipe whole with its source.
/// Both engines carry it: the tokio engine with its udp link, the cooperative one in every build.
#[cfg(any(not(feature = "engine-tokio"), feature = "link-udp"))]
#[test]
fn a_datagram_pair_carries_a_put_and_a_get() {
    let pipe = Arc::new(Pipe::default());
    let listening = make_transport(&pipe, Side::Listening);
    let dialling = make_transport(&pipe, Side::Dialling);
    unsafe {
        let listener = open_over(Z_CONFIG_LISTEN_KEY, DATAGRAM_LISTEN, listening);
        let dialler = open_over(Z_CONFIG_CONNECT_KEY, DATAGRAM_LISTEN, dialling);
        assert_eq!(pipe.dials.load(Ordering::SeqCst), 1);
        assert_eq!(
            pipe.datagrams.lock().unwrap().len(),
            2,
            "both ends of the pair are datagram links"
        );
        put_and_get(&listener, &dialler);
        close(dialler);
        close(listener);
    }
    drop_transport(dialling);
    drop_transport(listening);
    wait_until("both transports to drop", Duration::from_secs(10), || {
        pipe.drops.load(Ordering::SeqCst) == 2
    });
}

/// A two-member group: each session joins the group over its program's transport, the pipe hands
/// each member's datagrams to the other with the member's address, and a put and a get cross the
/// group. Closing a session leaves the group, which its program hears as the link's close.
#[cfg(feature = "multicast-transport")]
#[test]
fn a_two_member_group_carries_a_put_and_a_get() {
    let pipe = Arc::new(Pipe::default());
    let first = make_transport(&pipe, Side::Listening);
    let second = make_transport(&pipe, Side::Dialling);
    unsafe {
        let one = open_over(Z_CONFIG_LISTEN_KEY, GROUP, first);
        let two = open_over(Z_CONFIG_LISTEN_KEY, GROUP, second);
        assert_eq!(pipe.groups.lock().unwrap().len(), 2, "both members joined");
        put_and_get(&one, &two);
        close(two);
        wait_until(
            "the second member to leave",
            Duration::from_secs(10),
            || !pipe.groups.lock().unwrap().contains_key(&Side::Dialling),
        );
        close(one);
    }
    drop_transport(second);
    drop_transport(first);
    wait_until("both transports to drop", Duration::from_secs(10), || {
        pipe.drops.load(Ordering::SeqCst) == 2
    });
}
