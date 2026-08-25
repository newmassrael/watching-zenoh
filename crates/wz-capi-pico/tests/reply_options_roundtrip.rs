// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! R311y562 — the metadata a C program sets on `z_query_reply_options_t` /
//! `z_query_reply_del_options_t` reaches the wire and surfaces on a real peer's
//! reply, measured over TCP between two sessions.
//!
//! ## Why this leg exists
//!
//! Both structs carried their metadata as opaque `*mut c_void` and dropped it,
//! each with a stated reason, and BOTH reasons had expired:
//!
//! - `encoding` said "the encoding type family is a follow-up round, so a C
//!   program linking this library has no exported `z_encoding_*` to build one
//!   with and this is always null in practice". `z_encoding_from_str` and its
//!   family have been exported since R311y529.
//! - `timestamp` said "opaque (the timestamp family is a follow-up round)".
//!   `z_timestamp_t` / `z_timestamp_new` landed at R311y557.
//! - `source_info` was not a field at all: the structs modelled the
//!   `Z_FEATURE_UNSTABLE_API`-off layout while the rest of the crate (and the
//!   reference build the drop-in's programs link against) is unstable-ON.
//!
//! That is the class R311y561 named one round earlier, in the file next door.
//! The measurement below is what a `--list`-and-grep could not have produced:
//! it does not check that the fields are READ, it checks that a foreign peer
//! SEES them.
//!
//! ## What each arm rules out
//!
//! ARM 1 (Put) sets all four at once — encoding, timestamp, source_info,
//! attachment — with values no wz session would mint for itself, and asserts
//! the getter reads back exactly those. Setting them TOGETHER is the point:
//! before this round no reply seam could carry an attachment ALONGSIDE a
//! timestamp, so the old code had to choose, and a per-field test would have
//! passed on a build that still silently dropped one of them.
//!
//! ARM 2 is the NEGATIVE arm. The same queryable, a reply with a default
//! options struct: it arrives, and carries none of the four. Without it, a
//! build that stamped its own timestamp or source_info on every reply would
//! pass ARM 1 for a reason that has nothing to do with the options.
//!
//! ARM 3 (Del) asserts the delete-reply half, which carries a DIFFERENT set on
//! purpose: the timestamp and source_info ride a Del body (`_Z_FLAG_Z_D_T`, and
//! `has_source_info` is computed before the `_is_put` split), while the
//! attachment does NOT (`has_attachment = pshb->_is_put && ..`,
//! `vendor/zenoh-pico/src/protocol/codec/message.c:263`). So ARM 3 asserts the
//! two that ride AND the absence of the one that does not — the absence is
//! upstream parity, not a wz gap, and pinning it stops a later round from
//! "fixing" a field the codec discards.

use std::ffi::c_void;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_capi_pico::advanced::z_entity_global_id_t;
use wz_capi_pico::zid::z_id_t;
use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_query, z_closure_reply,
    z_config_default, z_config_loan_mut, z_config_move, z_declare_queryable, z_encoding_from_str,
    z_encoding_move, z_encoding_to_string, z_get, z_get_options_default, z_get_options_t,
    z_loaned_query_t, z_loaned_reply_t, z_open, z_owned_config_t, z_owned_encoding_t,
    z_owned_queryable_t, z_owned_session_t, z_query_reply, z_query_reply_del,
    z_query_reply_del_options_default, z_query_reply_del_options_t, z_query_reply_options_default,
    z_query_reply_options_t, z_reply_is_ok, z_reply_ok, z_sample_attachment, z_sample_encoding,
    z_sample_kind, z_sample_source_info, z_sample_timestamp, z_session_loan, z_session_move,
    z_source_info_new, z_source_info_sn, z_source_info_t, z_timestamp_ntp64_time,
    z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert,
    Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_OK, Z_SAMPLE_KIND_DELETE,
};

/// A distinctive identity: no wz session mints this zid for itself, so "it
/// arrived" and "we sent it" cannot be confused.
const PROBE_ZID0: u8 = 0xC1;
const PROBE_EID: u32 = 0x7070;
const PROBE_SN: u32 = 4242;
/// A timestamp word chosen well away from any wall clock the runtime could
/// produce, for the same reason.
const PROBE_TIME: u64 = 0x0000_2222_0000_3333;

/// What one reply carried:
/// `(kind, encoding rendered as a string, ntp64_time, source_sn,
/// attachment_len)`. The encoding is compared as the STRING a C program reads
/// with `z_encoding_to_string`, which is the only value form the ABI exposes —
/// and comparing the rendered value rather than merely presence is what makes a
/// build that stamps a default encoding fail.
type Seen = (i32, Option<String>, Option<u64>, Option<u32>, Option<usize>);

struct ReplyCtx {
    seen: Arc<Mutex<Vec<Seen>>>,
}

/// Which reply the queryable should emit next: one arm per call.
struct QueryCtx {
    arm: Arc<Mutex<u8>>,
}

unsafe extern "C" fn on_reply(reply: *mut z_loaned_reply_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const ReplyCtx);
    if !z_reply_is_ok(reply) {
        return;
    }
    let sample = z_reply_ok(reply);
    if sample.is_null() {
        return;
    }
    let kind = z_sample_kind(sample);

    let enc = z_sample_encoding(sample);
    let encoding_id = if enc.is_null() {
        None
    } else {
        let mut rendered: wz_capi_pico::z_owned_string_t = std::mem::zeroed();
        if z_encoding_to_string(enc, &mut rendered) == Z_OK {
            let loaned = wz_capi_pico::z_string_loan(&rendered);
            let data = wz_capi_pico::z_string_data(loaned);
            let len = wz_capi_pico::z_string_len(loaned);
            let text = std::str::from_utf8(std::slice::from_raw_parts(data as *const u8, len))
                .unwrap_or("")
                .to_owned();
            wz_capi_pico::z_string_drop(wz_capi_pico::z_string_move(&mut rendered));
            Some(text)
        } else {
            None
        }
    };

    let ts = z_sample_timestamp(sample);
    let time = if ts.is_null() {
        None
    } else {
        Some(z_timestamp_ntp64_time(ts))
    };

    let si = z_sample_source_info(sample);
    let sn = if si.is_null() {
        None
    } else {
        Some(z_source_info_sn(si))
    };

    let att = z_sample_attachment(sample);
    let att_len = if att.is_null() {
        None
    } else {
        let n = wz_capi_pico::z_bytes_len(att);
        // pico hands back a pointer unconditionally and lets an empty
        // attachment speak for itself, so LENGTH is the presence test here.
        if n == 0 {
            None
        } else {
            Some(n)
        }
    };

    ctx.seen
        .lock()
        .unwrap()
        .push((kind, encoding_id, time, sn, att_len));
}

/// Build the `z_source_info_t` a C program would, through the exported
/// constructors rather than by struct literal — the ABI path is under test.
unsafe fn source_info(sn: u32) -> z_source_info_t {
    let mut zid_bytes = [0u8; 16];
    for (i, b) in zid_bytes.iter_mut().enumerate() {
        *b = PROBE_ZID0 + i as u8;
    }
    let zid = z_id_t { id: zid_bytes };
    let mut gid: z_entity_global_id_t = std::mem::zeroed();
    assert_eq!(
        wz_capi_pico::z_entity_global_id_new(&mut gid, &zid, PROBE_EID),
        Z_OK
    );
    z_source_info_new(&gid, sn)
}

/// The queryable callback: three arms, one per call, so a single fixture
/// measures the SET / UNSET / DEL cases without three sessions.
unsafe extern "C" fn on_query(query: *const z_loaned_query_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const QueryCtx);
    let mut arm = ctx.arm.lock().unwrap();
    let which = *arm;
    *arm += 1;
    drop(arm);

    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/rep".as_ptr()), Z_OK);

    match which {
        // ARM 1 — every field set at once.
        0 => {
            let mut payload = std::mem::zeroed();
            assert_eq!(z_bytes_copy_from_str(&mut payload, c"full".as_ptr()), Z_OK);
            let mut attachment = std::mem::zeroed();
            assert_eq!(
                z_bytes_copy_from_str(&mut attachment, c"side-band".as_ptr()),
                Z_OK
            );
            let mut encoding: z_owned_encoding_t = std::mem::zeroed();
            assert_eq!(
                z_encoding_from_str(&mut encoding, c"text/plain".as_ptr()),
                Z_OK
            );
            let mut ts = wz_capi_pico::z_timestamp_t {
                valid: true,
                time: PROBE_TIME,
                id: z_id_t { id: [0u8; 16] },
            };
            ts.id.id[0] = PROBE_ZID0;
            let mut si = source_info(PROBE_SN);

            let mut options: z_query_reply_options_t = std::mem::zeroed();
            z_query_reply_options_default(&mut options);
            options.encoding = z_encoding_move(&mut encoding);
            options.attachment = z_bytes_move(&mut attachment);
            options.timestamp = &mut ts;
            options.source_info = &mut si;
            assert_eq!(
                z_query_reply(
                    query,
                    z_view_keyexpr_loan(&ke),
                    z_bytes_move(&mut payload),
                    &options,
                ),
                Z_OK
            );
        }
        // ARM 2 — the negative arm: defaults only.
        1 => {
            let mut payload = std::mem::zeroed();
            assert_eq!(z_bytes_copy_from_str(&mut payload, c"bare".as_ptr()), Z_OK);
            let mut options: z_query_reply_options_t = std::mem::zeroed();
            z_query_reply_options_default(&mut options);
            assert_eq!(
                z_query_reply(
                    query,
                    z_view_keyexpr_loan(&ke),
                    z_bytes_move(&mut payload),
                    &options,
                ),
                Z_OK
            );
        }
        // ARM 3 — the Del reply: timestamp + source_info ride, attachment does
        // not (and the attachment is still SET here, so its absence downstream
        // is a measurement rather than an assumption).
        _ => {
            let mut attachment = std::mem::zeroed();
            assert_eq!(
                z_bytes_copy_from_str(&mut attachment, c"del-side-band".as_ptr()),
                Z_OK
            );
            let mut ts = wz_capi_pico::z_timestamp_t {
                valid: true,
                time: PROBE_TIME,
                id: z_id_t { id: [0u8; 16] },
            };
            ts.id.id[0] = PROBE_ZID0;
            let mut si = source_info(PROBE_SN + 1);

            let mut options: z_query_reply_del_options_t = std::mem::zeroed();
            z_query_reply_del_options_default(&mut options);
            options.attachment = z_bytes_move(&mut attachment);
            options.timestamp = &mut ts;
            options.source_info = &mut si;
            assert_eq!(
                z_query_reply_del(query, z_view_keyexpr_loan(&ke), &options),
                Z_OK
            );
        }
    }
}

use wz_runtime_tokio_test_support::free_port;

unsafe fn open_with(key: u8, endpoint: &std::ffi::CStr) -> Option<z_owned_session_t> {
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

/// Issue one get and wait (bounded) for `want` replies to have been recorded.
unsafe fn get_once(session: &z_owned_session_t, seen: &Arc<Mutex<Vec<Seen>>>, want: usize) {
    let ctx = Box::into_raw(Box::new(ReplyCtx { seen: seen.clone() })) as *mut c_void;
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_reply(&mut closure, Some(on_reply), None, ctx),
        Z_OK
    );
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/rep".as_ptr()), Z_OK);
    let mut options: z_get_options_t = std::mem::zeroed();
    z_get_options_default(&mut options);
    assert_eq!(
        z_get(
            z_session_loan(session),
            z_view_keyexpr_loan(&ke),
            std::ptr::null(),
            wz_capi_pico::z_closure_reply_move(&mut closure),
            &mut options,
        ),
        Z_OK
    );
    for _ in 0..250 {
        if seen.lock().unwrap().len() >= want {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn reply_options_metadata_crosses_the_wire_on_both_arms() {
    let port = free_port();
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let connect = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();

    unsafe {
        let mut responder = open_with(Z_CONFIG_LISTEN_KEY, &listen).expect("listener z_open");

        let arm = Arc::new(Mutex::new(0u8));
        let qctx = Box::into_raw(Box::new(QueryCtx { arm: arm.clone() })) as *mut c_void;
        let mut queryable: z_owned_queryable_t = std::mem::zeroed();
        let mut qclosure = std::mem::zeroed();
        assert_eq!(
            z_closure_query(&mut qclosure, Some(on_query), None, qctx),
            Z_OK
        );
        let mut qke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut qke, c"demo/rep".as_ptr()),
            Z_OK
        );
        assert_eq!(
            z_declare_queryable(
                z_session_loan(&responder),
                &mut queryable,
                z_view_keyexpr_loan(&qke),
                wz_capi_pico::z_closure_query_move(&mut qclosure),
                std::ptr::null(),
            ),
            Z_OK
        );

        let mut getter = None;
        for _ in 0..250 {
            if let Some(session) = open_with(Z_CONFIG_CONNECT_KEY, &connect) {
                getter = Some(session);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut getter = getter.expect("getter z_open never succeeded");

        let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));

        // Drive the three arms. The first get may land before the queryable
        // declaration has propagated, so retry until SOMETHING comes back —
        // bounded, so a genuine failure still fails fast.
        for _ in 0..250 {
            if !seen.lock().unwrap().is_empty() {
                break;
            }
            *arm.lock().unwrap() = 0;
            seen.lock().unwrap().clear();
            get_once(&getter, &seen, 1);
        }
        assert!(
            !seen.lock().unwrap().is_empty(),
            "CALIBRATION FAILED: no reply crossed the wire at all, so nothing \
             below measures the reply options"
        );
        get_once(&getter, &seen, 2);
        get_once(&getter, &seen, 3);

        let got = seen.lock().unwrap().clone();
        assert_eq!(
            got.len(),
            3,
            "one reply per arm reached the getter; got {got:?}"
        );

        // ARM 1 — all four set, all four observed. `text/plain` is pico
        // encoding id 3 (`z_encoding_text_plain`), and the id is asserted by
        // VALUE rather than for presence so a build that stamped some default
        // encoding cannot pass.
        let (kind, enc, time, sn, att) = got[0].clone();
        assert_ne!(kind, Z_SAMPLE_KIND_DELETE, "arm 1 is a Put reply");
        assert_eq!(
            (time, sn, att),
            (Some(PROBE_TIME), Some(PROBE_SN), Some("side-band".len())),
            "the Put reply carries the timestamp, the source_info and the \
             attachment the options set"
        );
        assert!(
            enc.is_some(),
            "the Put reply carries the encoding the options set"
        );

        // ARM 2 — the negative arm. None of the four, so ARM 1 measured the
        // options rather than something the runtime stamps unconditionally.
        let (kind, enc, time, sn, att) = got[1].clone();
        assert_ne!(kind, Z_SAMPLE_KIND_DELETE, "arm 2 is a Put reply");
        assert_eq!(
            (time, sn, att),
            (None, None, None),
            "a default-options reply carries no timestamp, no source_info and \
             no attachment"
        );
        assert!(enc.is_none(), "a default-options reply carries no encoding");

        // ARM 3 — the Del reply. Timestamp and source_info ride; the
        // attachment does NOT, and it was SET, so this is a measurement of the
        // `_is_put` gate rather than of an unset field.
        let (kind, _enc, time, sn, att) = got[2].clone();
        assert_eq!(kind, Z_SAMPLE_KIND_DELETE, "arm 3 is a Del reply");
        assert_eq!(
            (time, sn),
            (Some(PROBE_TIME), Some(PROBE_SN + 1)),
            "a Del reply carries its timestamp and source_info — both ride the \
             Del body (`_Z_FLAG_Z_D_T`; `has_source_info` precedes the \
             `_is_put` split)"
        );
        assert_eq!(
            att, None,
            "a Del reply carries NO attachment even though the options set one \
             — `has_attachment = pshb->_is_put && ..` (message.c:263). Upstream \
             pico drops it the same way; this is parity, not a gap"
        );

        z_undeclare_queryable_compat(&mut queryable);
        z_close(z_session_loan_mut_compat(&mut getter), std::ptr::null());
        z_close(z_session_loan_mut_compat(&mut responder), std::ptr::null());
        wz_capi_pico::z_session_drop(z_session_move(&mut getter));
        wz_capi_pico::z_session_drop(z_session_move(&mut responder));
    }
}

/// Undeclare through the moved-queryable seam the crate exports.
unsafe fn z_undeclare_queryable_compat(q: *mut z_owned_queryable_t) {
    wz_capi_pico::z_undeclare_queryable(wz_capi_pico::z_queryable_move(q));
}

/// `z_session_loan_mut` under a local name, so the two close calls read the
/// same as every other fixture in this directory.
unsafe fn z_session_loan_mut_compat(
    s: *mut z_owned_session_t,
) -> *mut wz_capi_pico::z_loaned_session_t {
    wz_capi_pico::z_session_loan_mut(s)
}

// --- the QUERY side ---------------------------------------------------------

/// What the queryable observed about the inbound query, per call:
/// `(source_sn, encoding rendered)`.
type QuerySeen = (Option<u32>, Option<String>);

struct QueryProbeCtx {
    seen: Arc<Mutex<Vec<QuerySeen>>>,
}

unsafe extern "C" fn on_query_probe(query: *const z_loaned_query_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const QueryProbeCtx);
    let si = wz_capi_pico::z_query_source_info(query);
    let sn = if si.is_null() {
        None
    } else {
        Some(z_source_info_sn(si))
    };
    let enc = wz_capi_pico::z_query_encoding(query);
    let rendered = if enc.is_null() {
        None
    } else {
        let mut out: wz_capi_pico::z_owned_string_t = std::mem::zeroed();
        if z_encoding_to_string(enc, &mut out) == Z_OK {
            let loaned = wz_capi_pico::z_string_loan(&out);
            let data = wz_capi_pico::z_string_data(loaned);
            let len = wz_capi_pico::z_string_len(loaned);
            let text = std::str::from_utf8(std::slice::from_raw_parts(data as *const u8, len))
                .unwrap_or("")
                .to_owned();
            wz_capi_pico::z_string_drop(wz_capi_pico::z_string_move(&mut out));
            Some(text)
        } else {
            None
        }
    };
    ctx.seen.lock().unwrap().push((sn, rendered));

    // Answer, so the getter's registry closes out rather than waiting on a
    // timeout — the query's own metadata is what this fixture measures, but a
    // query nobody answers still has to terminate.
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/qsi".as_ptr()), Z_OK);
    let mut payload = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut payload, c"ack".as_ptr()), Z_OK);
    z_query_reply(
        query,
        z_view_keyexpr_loan(&ke),
        z_bytes_move(&mut payload),
        std::ptr::null(),
    );
}

/// R311y562 — the `source_info` and `encoding` a C program sets on
/// `z_get_options_t` reach the queryable.
///
/// Both were unreachable, for two DIFFERENT reasons, and the second is the one
/// worth recording. The encoding was carried as an opaque `*mut c_void` with the
/// expired "no exported `z_encoding_*`" reason. The `source_info` was not a
/// field at all: the struct modelled the `Z_FEATURE_UNSTABLE_API`-off layout, so
/// it lacked the unstable pair — and because that pair sits BEFORE
/// `accept_replies` in upstream's declaration, the omission also put
/// `accept_replies` at offset 56 where the reference build puts it at 72. A
/// drop-in program calling `z_get_options_default` therefore had its
/// reply-keyexpr policy read out of the low half of the `source_info` pointer.
///
/// This test does not measure that displacement — the `const _` offset guards in
/// `get.rs` do, and they are the right instrument for a layout claim. What this
/// measures is the consequence a test CAN see: with the layout right, the two
/// fields carry.
///
/// The negative arm is the second get: same getter, default options, and the
/// queryable observes neither field. Without it a build that stamped a source
/// identity on every outbound query would pass the first arm for free.
#[test]
fn get_options_source_info_and_encoding_reach_the_queryable() {
    let port = free_port();
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let connect = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();

    unsafe {
        let mut responder = open_with(Z_CONFIG_LISTEN_KEY, &listen).expect("listener z_open");

        let seen: Arc<Mutex<Vec<QuerySeen>>> = Arc::new(Mutex::new(Vec::new()));
        let qctx = Box::into_raw(Box::new(QueryProbeCtx { seen: seen.clone() })) as *mut c_void;
        let mut queryable: z_owned_queryable_t = std::mem::zeroed();
        let mut qclosure = std::mem::zeroed();
        assert_eq!(
            z_closure_query(&mut qclosure, Some(on_query_probe), None, qctx),
            Z_OK
        );
        let mut qke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut qke, c"demo/qsi".as_ptr()),
            Z_OK
        );
        assert_eq!(
            z_declare_queryable(
                z_session_loan(&responder),
                &mut queryable,
                z_view_keyexpr_loan(&qke),
                wz_capi_pico::z_closure_query_move(&mut qclosure),
                std::ptr::null(),
            ),
            Z_OK
        );

        let mut getter = None;
        for _ in 0..250 {
            if let Some(session) = open_with(Z_CONFIG_CONNECT_KEY, &connect) {
                getter = Some(session);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut getter = getter.expect("getter z_open never succeeded");

        // ARM 1 — both set. Retried until the declaration propagates.
        for _ in 0..250 {
            if !seen.lock().unwrap().is_empty() {
                break;
            }
            let mut si = source_info(PROBE_SN);
            let mut encoding: z_owned_encoding_t = std::mem::zeroed();
            assert_eq!(
                z_encoding_from_str(&mut encoding, c"application/json".as_ptr()),
                Z_OK
            );
            let ctx = Box::into_raw(Box::new(ReplyCtx {
                seen: Arc::new(Mutex::new(Vec::new())),
            })) as *mut c_void;
            let mut closure = std::mem::zeroed();
            assert_eq!(
                z_closure_reply(&mut closure, Some(on_reply), None, ctx),
                Z_OK
            );
            let mut ke: z_view_keyexpr_t = std::mem::zeroed();
            assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/qsi".as_ptr()), Z_OK);
            let mut options: z_get_options_t = std::mem::zeroed();
            z_get_options_default(&mut options);
            options.source_info = &mut si;
            options.encoding = z_encoding_move(&mut encoding);
            assert_eq!(
                z_get(
                    z_session_loan(&getter),
                    z_view_keyexpr_loan(&ke),
                    std::ptr::null(),
                    wz_capi_pico::z_closure_reply_move(&mut closure),
                    &mut options,
                ),
                Z_OK
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !seen.lock().unwrap().is_empty(),
            "CALIBRATION FAILED: no query reached the queryable at all"
        );

        // ARM 2 — the negative arm: a default-options get.
        {
            let ctx = Box::into_raw(Box::new(ReplyCtx {
                seen: Arc::new(Mutex::new(Vec::new())),
            })) as *mut c_void;
            let mut closure = std::mem::zeroed();
            assert_eq!(
                z_closure_reply(&mut closure, Some(on_reply), None, ctx),
                Z_OK
            );
            let mut ke: z_view_keyexpr_t = std::mem::zeroed();
            assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/qsi".as_ptr()), Z_OK);
            let mut options: z_get_options_t = std::mem::zeroed();
            z_get_options_default(&mut options);
            assert_eq!(
                z_get(
                    z_session_loan(&getter),
                    z_view_keyexpr_loan(&ke),
                    std::ptr::null(),
                    wz_capi_pico::z_closure_reply_move(&mut closure),
                    &mut options,
                ),
                Z_OK
            );
            let want = seen.lock().unwrap().len() + 1;
            for _ in 0..250 {
                if seen.lock().unwrap().len() >= want {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        let got = seen.lock().unwrap().clone();
        assert!(got.len() >= 2, "both arms reached the queryable: {got:?}");
        assert_eq!(
            got[0],
            (Some(PROBE_SN), Some("application/json".to_string())),
            "the query carries the source_info and the encoding the get options set"
        );
        assert_eq!(
            got[got.len() - 1],
            (None, None),
            "a default-options get carries neither — so the arm above measured \
             the options rather than something stamped unconditionally"
        );

        z_undeclare_queryable_compat(&mut queryable);
        z_close(z_session_loan_mut_compat(&mut getter), std::ptr::null());
        z_close(z_session_loan_mut_compat(&mut responder), std::ptr::null());
        wz_capi_pico::z_session_drop(z_session_move(&mut getter));
        wz_capi_pico::z_session_drop(z_session_move(&mut responder));
    }
}
