// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A transport the program supplies (`wz_ext_transport_*`), fed by this target as a program's own
//! network stack feeds it: a session of the library dials over it, a far end the harness plays
//! answers the dial's handshake from inside the program's `send`, as a stack that delivers at
//! once does, and every byte the fuzzer writes then reaches the session through
//! `wz_ext_transport_received`, the door a program hands the bytes of its link to.
//!
//! Input: a byte of arguments, then the units (`wz_fuzz_ingress_common::units`), which a stream
//! link is handed as the stream they make (each unit behind its two-byte little-endian length, as
//! a zenoh stream link frames it) and a datagram link one unit to a datagram.
//!
//! | bits of byte 0 | argument |
//! |----------------|----------|
//! | 0              | the link: a stream (`tcp/`) or a datagram (`udp/`) |
//! | 1..=7          | how many bytes of the stream each call hands in (0: one unit's) |
//!
//! The session reads on its own read task, as the release build's multi-threaded arm does, so
//! how much of the input it has read when the target closes it varies from run to run; what the
//! target holds does not depend on it:
//!
//! - the far end's handshake opens the session (a failure here is the harness's, and every
//!   input shows it);
//! - each call of the program's answers a code its documentation states, and names a link the
//!   transport no longer holds only once the session has closed that link on the program;
//! - every link the session opens on the program is closed on it exactly once, no call reaches
//!   the program after its `drop(context)`, and that drop runs once, once the session and the
//!   program have let the transport go;
//! - every sample handed to the subscriber on `**` carries a payload;
//! - the live heap grows by less than `GROWTH_LIMIT` while the session reads the input.

#![no_main]

use std::collections::HashSet;
use std::ffi::{c_char, c_void};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use wz_capi_pico::app_transport::*;
use wz_capi_pico::result::{
    WZ_EXT_ERR_LINK_CLOSED, WZ_EXT_ERR_LINK_FULL, WZ_EXT_ERR_LINK_UNKNOWN, Z_OK,
};
use wz_capi_pico::{
    z_close, z_closure_sample, z_closure_sample_move, z_config_default, z_config_loan_mut,
    z_config_move, z_declare_background_subscriber, z_loaned_sample_t, z_open,
    z_owned_closure_sample_t, z_owned_config_t, z_owned_session_t, z_sample_payload,
    z_session_drop, z_session_loan, z_session_loan_mut, z_session_move, z_view_keyexpr_from_str,
    z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert, Z_CONFIG_CONNECT_KEY,
};
use wz_fuzz_ingress_common::{handshake_replies, units, CountingAlloc, Window, GROWTH_LIMIT};
use wz_fuzz_pico_ext::stated;

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// The far end's locators. Synthetic: no socket is opened for either.
const STREAM_AT: &std::ffi::CStr = c"tcp/192.0.2.100:7447";
const DATAGRAM_AT: &std::ffi::CStr = c"udp/192.0.2.100:7447";

/// How long a full link is given to be read down before the rest of the input is left unsent,
/// and how long the program's drop is waited for once everything let the transport go.
const DRAIN_WAIT: Duration = Duration::from_millis(200);
const DROP_WAIT: Duration = Duration::from_secs(10);

/// The far end the program's stack reaches, and what the session asked of the program.
struct Far {
    stream: bool,
    /// The program's own transport, for the calls made from inside its `send`.
    transport: AtomicUsize,
    /// The link the session dialled last.
    link: AtomicU64,
    /// The replies the far end still owes, in the order the session's sends call for them.
    replies: Mutex<Vec<Vec<u8>>>,
    opens: AtomicUsize,
    closes: AtomicUsize,
    /// The links the session closed on the program, each recorded before its close returns: the
    /// transport answers `WZ_EXT_ERR_LINK_UNKNOWN` for a link only once its close has returned.
    closed_links: Mutex<HashSet<wz_ext_link_t>>,
    drops: AtomicUsize,
    dropped: AtomicBool,
    samples: AtomicUsize,
}

impl Far {
    fn loan(&self) -> *const wz_ext_loaned_transport_t {
        // SAFETY: the address of the program's owned transport, which outlives every call.
        unsafe {
            wz_ext_transport_loan(
                self.transport.load(Ordering::SeqCst) as *const wz_ext_owned_transport_t
            )
        }
    }

    fn called(&self, what: &str) {
        assert!(
            !self.dropped.load(Ordering::SeqCst),
            "the program's {what} was called after its drop"
        );
    }
}

/// The far end behind a context.
///
/// # Safety
/// `context` is the `Far` this target gave the transport, alive until its drop has run.
unsafe fn far<'a>(context: *mut c_void) -> &'a Far {
    &*(context as *const Far)
}

/// A unit as the link carries it: behind its length on a stream, alone in a datagram.
fn framed(stream: bool, unit: &[u8]) -> Vec<u8> {
    if !stream {
        return unit.to_vec();
    }
    let len = u16::try_from(unit.len()).expect("a reply fits a stream unit");
    let mut out = len.to_le_bytes().to_vec();
    out.extend_from_slice(unit);
    out
}

unsafe extern "C" fn on_open(
    context: *mut c_void,
    link: wz_ext_link_t,
    kind: wz_ext_link_kind_t,
    _locator: *const c_char,
) -> wz_ext_link_result_t {
    let far = far(context);
    far.called("open");
    let wanted = if far.stream {
        WZ_EXT_LINK_STREAM_DIAL
    } else {
        WZ_EXT_LINK_DATAGRAM
    };
    if kind != wanted {
        return WZ_EXT_LINK_FAILED;
    }
    far.opens.fetch_add(1, Ordering::SeqCst);
    far.link.store(link, Ordering::SeqCst);
    WZ_EXT_LINK_OK
}

unsafe extern "C" fn on_send(
    context: *mut c_void,
    link: wz_ext_link_t,
    _data: *const u8,
    len: usize,
    written: *mut usize,
) -> wz_ext_link_result_t {
    let far = far(context);
    far.called("send");
    *written = len;
    // The far end answers the handshake as it arrives: each of the session's first sends is
    // answered by the reply it calls for, from inside the send, as a stack that delivers at once.
    let reply = {
        let mut replies = far.replies.lock().expect("the replies' lock");
        (!replies.is_empty()).then(|| replies.remove(0))
    };
    if let Some(reply) = reply {
        let bytes = framed(far.stream, &reply);
        let rc = wz_ext_transport_received(
            far.loan(),
            link,
            bytes.as_ptr(),
            bytes.len(),
            core::ptr::null(),
        );
        assert_eq!(
            rc, Z_OK,
            "transport_received: the far end's reply answered {rc}"
        );
    }
    WZ_EXT_LINK_OK
}

unsafe extern "C" fn on_close(context: *mut c_void, link: wz_ext_link_t) {
    let far = far(context);
    far.called("close");
    far.closes.fetch_add(1, Ordering::SeqCst);
    far.closed_links
        .lock()
        .expect("the closed links' lock")
        .insert(link);
}

unsafe extern "C" fn on_drop(context: *mut c_void) {
    let far = far(context);
    far.called("drop");
    far.drops.fetch_add(1, Ordering::SeqCst);
    far.dropped.store(true, Ordering::SeqCst);
}

unsafe extern "C" fn on_sample(sample: *const z_loaned_sample_t, context: *mut c_void) {
    assert!(
        !z_sample_payload(sample).is_null(),
        "a sample handed to the subscriber has no payload"
    );
    far(context).samples.fetch_add(1, Ordering::SeqCst);
}

fuzz_target!(|data: &[u8]| {
    let (args, input) = match data.split_first() {
        Some((args, input)) => (*args, input),
        None => (0, data),
    };
    let stream = args & 1 == 0;
    let chunk = usize::from(args >> 1);

    let far = Box::new(Far {
        stream,
        transport: AtomicUsize::new(0),
        link: AtomicU64::new(0),
        replies: Mutex::new(handshake_replies().to_vec()),
        opens: AtomicUsize::new(0),
        closes: AtomicUsize::new(0),
        closed_links: Mutex::new(HashSet::new()),
        drops: AtomicUsize::new(0),
        dropped: AtomicBool::new(false),
        samples: AtomicUsize::new(0),
    });
    let context = &*far as *const Far as *mut c_void;
    let calls = wz_ext_transport_t {
        context,
        open: Some(on_open),
        send: Some(on_send),
        close: Some(on_close),
        drained: None,
        drop: Some(on_drop),
    };
    let mut transport: Box<wz_ext_owned_transport_t> = Box::new(unsafe { core::mem::zeroed() });
    // SAFETY: `transport` is writable; `calls` is readable for the call.
    assert_eq!(
        unsafe { wz_ext_transport_new(&mut *transport, &calls) },
        Z_OK,
        "transport_new"
    );
    far.transport.store(
        &*transport as *const wz_ext_owned_transport_t as usize,
        Ordering::SeqCst,
    );

    let mut session: z_owned_session_t = unsafe { core::mem::zeroed() };
    // SAFETY: each pointer is to a live local; the locator is NUL-terminated.
    let rc = unsafe {
        let mut config: z_owned_config_t = core::mem::zeroed();
        assert_eq!(z_config_default(&mut config), Z_OK, "z_config_default");
        let at = if stream { STREAM_AT } else { DATAGRAM_AT };
        assert_eq!(
            zp_config_insert(
                z_config_loan_mut(&mut config),
                Z_CONFIG_CONNECT_KEY,
                at.as_ptr()
            ),
            Z_OK
        );
        assert_eq!(
            wz_ext_config_transport(
                z_config_loan_mut(&mut config),
                wz_ext_transport_loan(&*transport)
            ),
            Z_OK,
            "config_transport"
        );
        z_open(&mut session, z_config_move(&mut config), core::ptr::null())
    };
    assert_eq!(
        rc, Z_OK,
        "the far end's handshake does not open the session: the harness is wrong"
    );

    let mut closure: z_owned_closure_sample_t = unsafe { core::mem::zeroed() };
    let mut every: z_view_keyexpr_t = unsafe { core::mem::zeroed() };
    // SAFETY: each pointer is to a live local; the closure's context is `far`, which outlives the
    // session the subscription is dropped with.
    unsafe {
        assert_eq!(
            z_closure_sample(&mut closure, Some(on_sample), None, context),
            Z_OK
        );
        assert_eq!(z_view_keyexpr_from_str(&mut every, c"**".as_ptr()), Z_OK);
        let rc = z_declare_background_subscriber(
            z_session_loan(&session),
            z_view_keyexpr_loan(&every),
            z_closure_sample_move(&mut closure),
            core::ptr::null(),
        );
        assert_eq!(rc, Z_OK, "the subscriber on ** is refused ({rc})");
    }

    let window = Window::open();
    let link = far.link.load(Ordering::SeqCst);
    if stream {
        let pieces: Vec<&[u8]> = if chunk == 0 {
            let mut at = 0;
            units(input)
                .map(|unit| {
                    let whole = (at + 2 + unit.len()).min(input.len());
                    let piece = &input[at..whole];
                    at = whole;
                    piece
                })
                .collect()
        } else {
            input.chunks(chunk).collect()
        };
        for piece in pieces {
            if !hand_in(&far, link, piece) {
                break;
            }
        }
    } else {
        for unit in units(input) {
            if !hand_in(&far, link, unit) {
                break;
            }
        }
    }
    // The read task is given a moment to read what was handed in before the session closes.
    std::thread::sleep(Duration::from_millis(1));
    assert!(
        window.peak_growth() < GROWTH_LIMIT,
        "the session's heap grew by {} bytes reading {} bytes",
        window.peak_growth(),
        input.len()
    );

    // SAFETY: a live owned session, closed and dropped once; the program's transport, dropped once.
    unsafe {
        let _ = z_close(z_session_loan_mut(&mut session), core::ptr::null());
        z_session_drop(z_session_move(&mut session));
        wz_ext_transport_drop(wz_ext_transport_move(&mut *transport));
    }
    let deadline = Instant::now() + DROP_WAIT;
    while far.drops.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < deadline,
            "the program's drop never ran: the transport was not let go"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        far.drops.load(Ordering::SeqCst),
        1,
        "the program's drop ran more than once"
    );
    assert_eq!(
        far.closed_links
            .lock()
            .expect("the closed links' lock")
            .len(),
        far.closes.load(Ordering::SeqCst),
        "the session closed a link on the program twice"
    );
    assert_eq!(
        far.closes.load(Ordering::SeqCst),
        far.opens.load(Ordering::SeqCst),
        "the links opened on the program are not each closed once"
    );
    drop(transport);
    drop(far);
});

/// Hand `bytes` in on `link`: whether the link still takes bytes. A full link is given
/// `DRAIN_WAIT` to be read down; a link the session has closed takes nothing more: it answers
/// `WZ_EXT_ERR_LINK_CLOSED` until the program's close of it returns, and `WZ_EXT_ERR_LINK_UNKNOWN`
/// after, which this program's own thread meets when the session closes the link under it.
fn hand_in(far: &Far, link: wz_ext_link_t, bytes: &[u8]) -> bool {
    let deadline = Instant::now() + DRAIN_WAIT;
    loop {
        // SAFETY: the program's live transport; `bytes` is readable for the call.
        let rc = unsafe {
            wz_ext_transport_received(
                far.loan(),
                link,
                bytes.as_ptr(),
                bytes.len(),
                core::ptr::null(),
            )
        };
        stated(
            "transport_received",
            rc,
            &[
                Z_OK,
                WZ_EXT_ERR_LINK_FULL,
                WZ_EXT_ERR_LINK_CLOSED,
                WZ_EXT_ERR_LINK_UNKNOWN,
            ],
        );
        if rc == WZ_EXT_ERR_LINK_UNKNOWN {
            assert!(
                far.closed_links
                    .lock()
                    .expect("the closed links' lock")
                    .contains(&link),
                "transport_received: link {link} is unknown and the session never closed it on the program"
            );
        }
        match rc {
            Z_OK => return true,
            WZ_EXT_ERR_LINK_FULL if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_micros(200))
            }
            _ => return false,
        }
    }
}
