// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! §5.27 `api-compat-pico` — what a publisher is DECLARED with is what every
//! put and delete it makes is sent with, measured over TCP between two
//! sessions and read off the sample a peer receives.
//!
//! ## What this exists to catch
//!
//! zenoh-pico keeps a publisher's encoding, congestion control, priority,
//! express flag and reliability in the publisher (`vendor/zenoh-pico/src/net/primitives.c` @
//! `publisher->_congestion_control = congestion_control;`) and sends every put
//! and delete with THOSE: the put and delete options carry a timestamp, an
//! attachment and a source info and nothing else about QoS, so there is no
//! other place for it to come from (`vendor/zenoh-pico/src/api/api.c` @
//! `ret = _z_write(session, &pub->_key, payload_bytes, &encoding, Z_SAMPLE_KIND_PUT, pub->_congestion_control,`).
//!
//! `z_declare_publisher` here took its options as an unread `const void *`, so a
//! program that declared a publisher at `Z_PRIORITY_REAL_TIME`, BLOCK, express
//! and best-effort linked, ran, delivered, and sent every sample at the
//! defaults. Nothing about a link or a delivery can see that; a peer reading the
//! sample's QoS can.
//!
//! ## What the arms are
//!
//! Every value the declared publisher is given is the OPPOSITE of the default in
//! every field, so "the sample carries it" and "the sample carries the default"
//! cannot be confused, and the default publisher is measured on the same
//! subscriber as the arm that says the defaults still come through when nothing
//! is declared. The put with its own encoding is the arm that says the
//! declared encoding is a default and not an override.

use std::ffi::{c_int, c_void, CStr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_sample, z_closure_sample_move,
    z_config_default, z_config_loan_mut, z_config_move, z_declare_publisher, z_declare_subscriber,
    z_encoding_from_str, z_encoding_move, z_encoding_to_string, z_internal_encoding_check,
    z_loaned_sample_t, z_open, z_owned_config_t, z_owned_encoding_t, z_owned_publisher_t,
    z_owned_session_t, z_owned_string_t, z_owned_subscriber_t, z_publisher_delete,
    z_publisher_delete_options_default, z_publisher_delete_options_t, z_publisher_loan,
    z_publisher_move, z_publisher_options_default, z_publisher_options_t, z_publisher_put,
    z_publisher_put_options_default, z_publisher_put_options_t, z_sample_congestion_control,
    z_sample_encoding, z_sample_express, z_sample_kind, z_sample_priority, z_sample_reliability,
    z_session_drop, z_session_loan, z_session_loan_mut, z_session_move, z_string_data,
    z_string_drop, z_string_len, z_string_loan, z_string_move, z_subscriber_move,
    z_undeclare_publisher, z_undeclare_subscriber, z_view_keyexpr_from_str, z_view_keyexpr_loan,
    z_view_keyexpr_t, zp_config_insert, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// pico's `Z_PRIORITY_REAL_TIME`, the declared publisher's priority: the one
/// value that is neither the default (5, Data) nor pico's control (0).
const PRIORITY_REAL_TIME: c_int = 1;
/// pico's `Z_PRIORITY_DEFAULT` (`Z_PRIORITY_DATA`).
const PRIORITY_DEFAULT: c_int = 5;
/// pico's `Z_CONGESTION_CONTROL_BLOCK`; its default, DROP, is 0.
const CONGESTION_BLOCK: c_int = 1;
/// pico's `Z_RELIABILITY_BEST_EFFORT`; its default, RELIABLE, is 0.
const RELIABILITY_BEST_EFFORT: c_int = 1;

/// What one delivered sample carried.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    kind: c_int,
    priority: c_int,
    congestion_control: c_int,
    express: bool,
    reliability: c_int,
    encoding: String,
}

/// What a sample carries when its publisher was declared with defaults, or with
/// nothing: the default QoS and the default encoding.
fn defaults(kind: c_int) -> Seen {
    Seen {
        kind,
        priority: PRIORITY_DEFAULT,
        congestion_control: 0,
        express: false,
        reliability: 0,
        encoding: String::from("zenoh/bytes"),
    }
}

struct Ctx {
    seen: Arc<Mutex<Vec<Seen>>>,
}

unsafe extern "C" fn on_sample(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const Ctx);
    let mut rendered: z_owned_string_t = std::mem::zeroed();
    assert_eq!(
        z_encoding_to_string(z_sample_encoding(sample), &mut rendered),
        Z_OK
    );
    let loaned = z_string_loan(&rendered);
    let encoding = String::from_utf8_lossy(std::slice::from_raw_parts(
        z_string_data(loaned).cast::<u8>(),
        z_string_len(loaned),
    ))
    .into_owned();
    z_string_drop(z_string_move(&mut rendered));
    ctx.seen.lock().unwrap().push(Seen {
        kind: z_sample_kind(sample) as c_int,
        priority: z_sample_priority(sample),
        congestion_control: z_sample_congestion_control(sample),
        express: z_sample_express(sample),
        reliability: z_sample_reliability(sample),
        encoding,
    });
}

unsafe fn open_with(key: u8, endpoint: &CStr) -> Option<z_owned_session_t> {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    if z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()) == Z_OK {
        Some(session)
    } else {
        None
    }
}

unsafe fn view(text: &CStr) -> z_view_keyexpr_t {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, text.as_ptr()), Z_OK);
    ke
}

unsafe fn encoding(text: &CStr) -> z_owned_encoding_t {
    let mut owned: z_owned_encoding_t = std::mem::zeroed();
    assert_eq!(z_encoding_from_str(&mut owned, text.as_ptr()), Z_OK);
    owned
}

/// The options of a publisher declared to differ from the default in EVERY
/// field. The encoding is moved in by the caller, as a C program does.
unsafe fn declared_options(declared_encoding: &mut z_owned_encoding_t) -> z_publisher_options_t {
    let mut options: z_publisher_options_t = std::mem::zeroed();
    z_publisher_options_default(&mut options);
    options.encoding = z_encoding_move(declared_encoding).cast::<c_void>();
    options.congestion_control = CONGESTION_BLOCK;
    options.priority = PRIORITY_REAL_TIME;
    options.is_express = true;
    options.reliability = RELIABILITY_BEST_EFFORT;
    options
}

unsafe fn put(
    publisher: &z_owned_publisher_t,
    text: &CStr,
    own_encoding: Option<&mut z_owned_encoding_t>,
) {
    let mut payload = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut payload, text.as_ptr()), Z_OK);
    let mut options: z_publisher_put_options_t = std::mem::zeroed();
    z_publisher_put_options_default(&mut options);
    if let Some(own) = own_encoding {
        options.encoding = z_encoding_move(own).cast::<c_void>();
    }
    assert_eq!(
        z_publisher_put(
            z_publisher_loan(publisher),
            z_bytes_move(&mut payload),
            &options
        ),
        Z_OK
    );
}

unsafe fn delete(publisher: &z_owned_publisher_t) {
    let mut options: z_publisher_delete_options_t = std::mem::zeroed();
    z_publisher_delete_options_default(&mut options);
    assert_eq!(
        z_publisher_delete(z_publisher_loan(publisher), &options),
        Z_OK
    );
}

/// Wait for `n` samples in `seen`, and return them. Fails, naming what arrived,
/// when they do not.
fn wait_for(seen: &Arc<Mutex<Vec<Seen>>>, n: usize) -> Vec<Seen> {
    for _ in 0..250 {
        if seen.lock().unwrap().len() >= n {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let got = seen.lock().unwrap().clone();
    assert_eq!(got.len(), n, "expected {n} samples, got {got:#?}");
    got
}

/// Republish `text` on `publisher` until one sample has crossed, so the far
/// side's declaration has propagated, then forget what crossed.
unsafe fn warm_up(publisher: &z_owned_publisher_t, seen: &Arc<Mutex<Vec<Seen>>>) {
    for _ in 0..250 {
        if !seen.lock().unwrap().is_empty() {
            break;
        }
        put(publisher, c"warm-up", None);
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !seen.lock().unwrap().is_empty(),
        "CALIBRATION FAILED: no sample crossed the wire at all, so nothing below \
         measures the declared options"
    );
    // Let the retries in flight land before the record is cleared.
    std::thread::sleep(Duration::from_millis(300));
    seen.lock().unwrap().clear();
}

#[test]
fn a_declared_publisher_sends_every_put_and_delete_with_the_qos_it_was_declared_with() {
    let port = free_port();
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let connect = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();

    unsafe {
        let mut listener = open_with(Z_CONFIG_LISTEN_KEY, &listen).expect("listener z_open failed");

        let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
        let ctx = Box::into_raw(Box::new(Ctx { seen: seen.clone() })).cast::<c_void>();
        let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_sample(&mut closure, Some(on_sample), None, ctx),
            Z_OK
        );
        let sub_ke = view(c"demo/po/**");
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

        let mut dialer = None;
        for _ in 0..250 {
            if let Some(session) = open_with(Z_CONFIG_CONNECT_KEY, &connect) {
                dialer = Some(session);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut dialer = dialer.expect("dialer z_open never succeeded");

        // ARM 1 - a publisher declared with every option away from its default.
        let mut declared_encoding = encoding(c"text/plain");
        let options = declared_options(&mut declared_encoding);
        let declared_ke = view(c"demo/po/declared");
        let mut declared: z_owned_publisher_t = std::mem::zeroed();
        assert_eq!(
            z_declare_publisher(
                z_session_loan(&dialer),
                &mut declared,
                z_view_keyexpr_loan(&declared_ke),
                &options,
            ),
            Z_OK
        );
        // pico steals the moved encoding at declare, so the caller's is spent.
        assert!(
            !z_internal_encoding_check(&declared_encoding),
            "the declare must consume the options' moved encoding, as pico's steals it"
        );
        warm_up(&declared, &seen);

        let mut json = encoding(c"application/json");
        put(&declared, c"plain", None);
        put(&declared, c"with-own-encoding", Some(&mut json));
        delete(&declared);
        let got = wait_for(&seen, 3);

        let declared_qos = |kind: c_int, encoding: &str| Seen {
            kind,
            priority: PRIORITY_REAL_TIME,
            congestion_control: CONGESTION_BLOCK,
            express: true,
            reliability: RELIABILITY_BEST_EFFORT,
            encoding: encoding.to_owned(),
        };
        assert_eq!(
            got[0],
            declared_qos(wz_capi_pico::Z_SAMPLE_KIND_PUT as c_int, "text/plain"),
            "a put with no encoding of its own is sent with the publisher's declared \
             encoding and QoS"
        );
        assert_eq!(
            got[1],
            declared_qos(wz_capi_pico::Z_SAMPLE_KIND_PUT as c_int, "application/json"),
            "a put's own encoding wins over the declared one and the QoS is still the \
             publisher's"
        );
        let delete_seen = &got[2];
        assert_eq!(
            (
                delete_seen.kind,
                delete_seen.priority,
                delete_seen.congestion_control,
                delete_seen.express,
                delete_seen.reliability,
            ),
            (
                wz_capi_pico::Z_SAMPLE_KIND_DELETE as c_int,
                PRIORITY_REAL_TIME,
                CONGESTION_BLOCK,
                true,
                RELIABILITY_BEST_EFFORT,
            ),
            "a delete is sent with the publisher's declared QoS: its options carry \
             none of their own"
        );

        // ARM 2 - the NEGATIVE arms, on the same subscriber. A publisher declared
        // with nothing, and one declared with the defaults written out, send the
        // defaults: without them a build that stamped the declared-arm QoS on
        // every publisher would pass ARM 1.
        seen.lock().unwrap().clear();
        let default_ke = view(c"demo/po/default");
        let mut by_null: z_owned_publisher_t = std::mem::zeroed();
        assert_eq!(
            z_declare_publisher(
                z_session_loan(&dialer),
                &mut by_null,
                z_view_keyexpr_loan(&default_ke),
                std::ptr::null(),
            ),
            Z_OK
        );
        warm_up(&by_null, &seen);
        put(&by_null, c"by-null", None);
        delete(&by_null);
        let got = wait_for(&seen, 2);
        assert_eq!(
            got[0],
            defaults(wz_capi_pico::Z_SAMPLE_KIND_PUT as c_int),
            "a publisher declared with NULL options sends the default QoS and encoding"
        );
        assert_eq!(
            (got[1].kind, got[1].priority, got[1].congestion_control),
            (
                wz_capi_pico::Z_SAMPLE_KIND_DELETE as c_int,
                PRIORITY_DEFAULT,
                0
            ),
            "and its delete does too"
        );

        seen.lock().unwrap().clear();
        let written_ke = view(c"demo/po/written");
        let mut written_options: z_publisher_options_t = std::mem::zeroed();
        z_publisher_options_default(&mut written_options);
        let mut by_default: z_owned_publisher_t = std::mem::zeroed();
        assert_eq!(
            z_declare_publisher(
                z_session_loan(&dialer),
                &mut by_default,
                z_view_keyexpr_loan(&written_ke),
                &written_options,
            ),
            Z_OK
        );
        warm_up(&by_default, &seen);
        put(&by_default, c"by-default", None);
        let got = wait_for(&seen, 1);
        assert_eq!(
            got[0],
            defaults(wz_capi_pico::Z_SAMPLE_KIND_PUT as c_int),
            "a publisher declared with z_publisher_options_default() sends the default \
             QoS: its priority is Z_PRIORITY_DEFAULT and not the enum's zero"
        );

        z_undeclare_publisher(z_publisher_move(&mut declared));
        z_undeclare_publisher(z_publisher_move(&mut by_null));
        z_undeclare_publisher(z_publisher_move(&mut by_default));
        z_undeclare_subscriber(z_subscriber_move(&mut subscriber));
        z_close(z_session_loan_mut(&mut dialer), std::ptr::null());
        z_session_drop(z_session_move(&mut dialer));
        z_close(z_session_loan_mut(&mut listener), std::ptr::null());
        z_session_drop(z_session_move(&mut listener));
        drop(Box::from_raw(ctx.cast::<Ctx>()));
    }
}

/// The values `z_publisher_options_default` writes are pico's own
/// (`vendor/zenoh-pico/src/api/api.c` @ `options->priority = Z_PRIORITY_DEFAULT;`).
/// The priority was written as the enum's zero, which is pico's CONTROL priority,
/// and nothing saw it while the declare ignored the field.
#[test]
fn the_default_publisher_options_are_the_values_pico_writes() {
    unsafe {
        let mut options: z_publisher_options_t = std::mem::zeroed();
        options.priority = -1;
        options.congestion_control = -1;
        options.reliability = -1;
        options.is_express = true;
        options.encoding = 0xdead_usize as *mut c_void;
        z_publisher_options_default(&mut options);
        assert!(options.encoding.is_null());
        assert_eq!(options.congestion_control, 0, "DROP, pico's push default");
        assert_eq!(options.priority, PRIORITY_DEFAULT, "Data, not control");
        assert!(!options.is_express);
        assert_eq!(options.reliability, 0, "RELIABLE");
    }
}
