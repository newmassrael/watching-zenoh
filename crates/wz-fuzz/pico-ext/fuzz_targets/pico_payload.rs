// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The message payloads of the pico C ABI (`wz_ext_payload_schema_*`, `wz_ext_message_payload_*`):
//! a schema read from a `.proto` file the fuzzer writes, a payload of a message of the catalog the
//! reader's tests use, and bytes the fuzzer writes decoded into it, values set and read at paths
//! it writes, and the payload encoded again.
//!
//! Input: a byte of choices, the message type's full name, the file's name and its text (each to
//! a NUL), then the operations, each a unit behind its two-byte little-endian length whose first
//! byte chooses it; the rest of the unit is a path (to a NUL) and then the operation's data:
//!
//! | op % 8 | operation |
//! |--------|-----------|
//! | 0      | the data are decoded into the payload (no path is read) |
//! | 1      | the integer at the path is set to the data's first eight bytes, signed |
//! | 2      | the same, unsigned; 3 the real; 4 the truth of the first byte |
//! | 5      | the string at the path is set to the data (to a NUL) |
//! | 6      | the bytes at the path are set to the data |
//! | 7      | the value at the path is read as every kind, and the repeated field counted |
//!
//! Bits 0 and 1 of the choices name the catalog message (two of the catalog's and one it does not
//! have); bit 2 drops the schema once the payload is made. An op of 8 or more clears the path
//! instead (16 and more resets the payload) before the operation.
//!
//! Held beside not crashing: each door answers a code its documentation states; a refused making
//! leaves the gravestone; a payload keeps its message's key and its schema past the schema's drop;
//! a refused call changes nothing and leaves its reason, an accepted one none; bytes a payload
//! encoded decode into it again and encode to the same bytes; a value read as text or bytes is
//! told its length in a buffer too small and written whole into one that fits; a dropped payload
//! answers like a null one and drops again without harm.

#![no_main]

use std::ffi::{CStr, CString};

use libfuzzer_sys::fuzz_target;
use wz_capi_pico::message_catalog::*;
use wz_capi_pico::message_payload::*;
use wz_capi_pico::proto_file::wz_ext_proto_file_t;
use wz_capi_pico::result::{
    ZResult, WZ_EXT_ERR_PAYLOAD_ABSENT, WZ_EXT_ERR_PAYLOAD_PATH, WZ_EXT_ERR_PAYLOAD_RANGE,
    WZ_EXT_ERR_PAYLOAD_TYPE, WZ_EXT_ERR_PAYLOAD_WIRE, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE,
    Z_ERR_INVALID, Z_ERR_NULL, Z_ERR_OVERFLOW, Z_OK,
};
use wz_fuzz_ingress_common::units;
use wz_fuzz_pico_ext::{empty_string, stated, take_string, Reader};

/// The catalog the payloads are made for: the reader's synthetic one, whose two messages are put
/// on keys of their own.
const CATALOG: &str = include_str!("../../../wz-app-frame/catalog/synthetic.json5");

/// The codes a refused call on a payload answers with, each of which leaves its reason.
const REFUSALS: [ZResult; 7] = [
    WZ_EXT_ERR_PAYLOAD_PATH,
    WZ_EXT_ERR_PAYLOAD_TYPE,
    WZ_EXT_ERR_PAYLOAD_RANGE,
    WZ_EXT_ERR_PAYLOAD_ABSENT,
    WZ_EXT_ERR_PAYLOAD_WIRE,
    Z_ERR_OVERFLOW,
    Z_ERR_CONFIG_INVALID_VALUE,
];

type Payload = wz_ext_owned_message_payload_t;

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let choices = r.u8();
    let message = r.c_field();
    let name = r.c_field();
    let text = r.c_field();
    let ops = r.rest();

    let catalog_text = CString::new(CATALOG).expect("the catalog holds no NUL");
    let mut catalog: wz_ext_owned_message_catalog_t = unsafe { core::mem::zeroed() };
    // SAFETY: `catalog` is writable; the text is NUL-terminated; no refusal is asked for.
    let rc = unsafe {
        wz_ext_message_catalog_new(&mut catalog, catalog_text.as_ptr(), core::ptr::null_mut())
    };
    assert_eq!(
        rc, Z_OK,
        "the synthetic catalog is refused ({rc}): the harness is wrong"
    );

    let files = [wz_ext_proto_file_t {
        name: name.as_ptr(),
        text: text.as_ptr(),
    }];
    let mut schema: wz_ext_owned_payload_schema_t = unsafe { core::mem::zeroed() };
    let mut refusal = empty_string();
    // SAFETY: `schema` is writable; the file's strings are NUL-terminated; `refusal` is writable.
    let rc = unsafe {
        wz_ext_payload_schema_new(&mut schema, files.as_ptr(), files.len(), &mut refusal)
    };
    let why = unsafe { take_string("payload_schema_new", &mut refusal) };
    stated(
        "payload_schema_new",
        rc,
        &[Z_OK, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE],
    );
    assert_eq!(
        unsafe { wz_ext_internal_payload_schema_check(&schema) },
        rc == Z_OK
    );
    if rc == Z_OK {
        assert!(
            why.is_empty(),
            "payload_schema_new: a read schema left a refusal: {why}"
        );
    }
    if rc == Z_ERR_CONFIG_INVALID_VALUE {
        assert!(
            !why.is_empty(),
            "payload_schema_new: refused with no reason"
        );
    }

    let index = usize::from(choices & 3).min(2);
    let catalog_loan = unsafe { wz_ext_message_catalog_loan(&catalog) };
    let mut payload: Payload = unsafe { core::mem::zeroed() };
    let mut refusal = empty_string();
    // SAFETY: every handle is owned or the gravestone; `message` is NUL-terminated.
    let rc = unsafe {
        wz_ext_message_payload_new(
            &mut payload,
            catalog_loan,
            index,
            wz_ext_payload_schema_loan(&schema),
            message.as_ptr(),
            &mut refusal,
        )
    };
    let _ = unsafe { take_string("message_payload_new", &mut refusal) };
    let schema_held = unsafe { wz_ext_internal_payload_schema_check(&schema) };
    if index >= unsafe { wz_ext_message_catalog_len(catalog_loan) } {
        assert_eq!(
            rc, Z_ERR_INVALID,
            "message_payload_new: a message the catalog has not answered {rc}"
        );
    } else if !schema_held {
        assert_eq!(
            rc, Z_ERR_NULL,
            "message_payload_new: the gravestone of a schema answered {rc}"
        );
    } else {
        stated(
            "message_payload_new",
            rc,
            &[Z_OK, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE],
        );
    }
    assert_eq!(
        unsafe { wz_ext_internal_message_payload_check(&payload) },
        rc == Z_OK
    );

    if choices & 4 != 0 {
        drop_schema(&mut schema);
    }
    if rc == Z_OK {
        key_is_the_catalogs(&payload, catalog_loan, index);
        for unit in units(ops) {
            let Some((&op, rest)) = unit.split_first() else {
                continue;
            };
            operate(&payload, op, rest);
        }
    }

    drop_payload(&mut payload);
    drop_schema(&mut schema);
    // SAFETY: an owned catalog slot, dropped once.
    unsafe { wz_ext_message_catalog_drop(wz_ext_message_catalog_move(&mut catalog)) };
});

fn loan(p: &Payload) -> *const wz_ext_loaned_message_payload_t {
    // SAFETY: a cast of an owned payload slot.
    unsafe { wz_ext_message_payload_loan(p) }
}

fn key_is_the_catalogs(p: &Payload, catalog: *const wz_ext_loaned_message_catalog_t, index: usize) {
    let mut entry: wz_ext_message_entry_t = unsafe { core::mem::zeroed() };
    // SAFETY: `catalog` is a live loaned catalog; `entry` is writable.
    assert_eq!(
        unsafe { wz_ext_message_catalog_entry(catalog, index, &mut entry) },
        Z_OK
    );
    // SAFETY: `p` is a live payload.
    let key = unsafe { wz_ext_message_payload_key_expr(loan(p)) };
    assert!(!key.is_null(), "a live payload has no key");
    // SAFETY: both are NUL-terminated keys their handles keep.
    let (key, expected) = unsafe { (CStr::from_ptr(key), CStr::from_ptr(entry.key_expr)) };
    assert_eq!(
        key, expected,
        "a payload keeps another key than its catalog message's"
    );
}

/// The bytes the payload encodes to, through the size and then a buffer of exactly that size, or
/// the code a refused encoding answers with.
fn encode(p: &Payload) -> Result<Vec<u8>, ZResult> {
    let mut size = usize::MAX;
    // SAFETY: `p` is a live payload; a null `out` with no capacity asks for the size.
    let rc = unsafe { wz_ext_message_payload_encode(loan(p), core::ptr::null_mut(), 0, &mut size) };
    stated(
        "message_payload_encode",
        rc,
        &[
            Z_OK,
            Z_ERR_OVERFLOW,
            WZ_EXT_ERR_PAYLOAD_ABSENT,
            Z_ERR_CONFIG_INVALID_VALUE,
        ],
    );
    match rc {
        Z_OK => {
            assert_eq!(
                size, 0,
                "message_payload_encode: no room asked and {size} bytes written"
            );
            return Ok(Vec::new());
        }
        Z_ERR_OVERFLOW => {}
        refused => {
            assert_eq!(
                size, 0,
                "message_payload_encode: {refused} and {size} bytes told"
            );
            return Err(refused);
        }
    }
    let mut out = vec![0u8; size];
    let mut written = usize::MAX;
    // SAFETY: `out` is writable for `size` bytes.
    let rc =
        unsafe { wz_ext_message_payload_encode(loan(p), out.as_mut_ptr(), size, &mut written) };
    assert_eq!(
        rc, Z_OK,
        "message_payload_encode: the {size} bytes it asked for answered {rc}"
    );
    assert_eq!(
        written, size,
        "message_payload_encode: {written} bytes written of {size} told"
    );
    Ok(out)
}

/// The reason the last call on the payload was refused, empty when it was not.
fn refusal_of(p: &Payload) -> String {
    let mut out = empty_string();
    // SAFETY: `p` is a live payload; `out` is writable.
    let rc = unsafe { wz_ext_message_payload_refusal(loan(p), &mut out) };
    assert_eq!(
        rc, Z_OK,
        "message_payload_refusal: a live payload answered {rc}"
    );
    unsafe { take_string("message_payload_refusal", &mut out) }
}

/// Hold a call's answer: a refusal changed nothing and left its reason, an acceptance left none.
fn held_to(door: &str, p: &Payload, rc: ZResult, before: &Result<Vec<u8>, ZResult>) {
    let reason = refusal_of(p);
    if rc == Z_OK {
        assert!(
            reason.is_empty(),
            "{door}: accepted and left a refusal: {reason}"
        );
    } else if REFUSALS.contains(&rc) {
        assert!(
            !reason.is_empty(),
            "{door}: refused with {rc} and left no reason"
        );
        assert_eq!(
            &encode(p),
            before,
            "{door}: refused with {rc} and changed the payload"
        );
    }
}

fn operate(p: &Payload, op: u8, rest: &[u8]) {
    let mut r = Reader::new(rest);
    if op >= 16 {
        // SAFETY: `p` is a live payload.
        let rc = unsafe { wz_ext_message_payload_reset(loan(p)) };
        assert_eq!(
            rc, Z_OK,
            "message_payload_reset: a live payload answered {rc}"
        );
        assert!(
            refusal_of(p).is_empty(),
            "message_payload_reset: left a refusal"
        );
    }
    if op % 8 == 0 {
        decode(p, r.rest());
        return;
    }
    let path = r.c_field();
    if op >= 8 {
        let before = encode(p);
        // SAFETY: `p` is a live payload; `path` is NUL-terminated.
        let rc = unsafe { wz_ext_message_payload_clear(loan(p), path.as_ptr()) };
        stated(
            "message_payload_clear",
            rc,
            &[
                Z_OK,
                WZ_EXT_ERR_PAYLOAD_PATH,
                WZ_EXT_ERR_PAYLOAD_RANGE,
                Z_EINVAL,
            ],
        );
        held_to("message_payload_clear", p, rc, &before);
    }
    let sets = [
        Z_OK,
        WZ_EXT_ERR_PAYLOAD_PATH,
        WZ_EXT_ERR_PAYLOAD_TYPE,
        WZ_EXT_ERR_PAYLOAD_RANGE,
        Z_EINVAL,
    ];
    let before = encode(p);
    let at = path.as_ptr();
    let rc = match op % 8 {
        // SAFETY (each arm): `p` is a live payload and `at` a NUL-terminated path.
        1 => unsafe { wz_ext_message_payload_set_int(loan(p), at, r.u64() as i64) },
        2 => unsafe { wz_ext_message_payload_set_uint(loan(p), at, r.u64()) },
        3 => unsafe { wz_ext_message_payload_set_double(loan(p), at, f64::from_bits(r.u64())) },
        4 => unsafe { wz_ext_message_payload_set_bool(loan(p), at, r.u8() & 1 != 0) },
        5 => {
            let value = r.c_field();
            unsafe { wz_ext_message_payload_set_string(loan(p), at, value.as_ptr()) }
        }
        6 => {
            let value = r.rest();
            unsafe { wz_ext_message_payload_set_bytes(loan(p), at, value.as_ptr(), value.len()) }
        }
        _ => {
            read_every_kind(p, &path);
            return;
        }
    };
    stated("message_payload_set", rc, &sets);
    held_to("message_payload_set", p, rc, &before);
}

fn decode(p: &Payload, bytes: &[u8]) {
    let before = encode(p);
    // SAFETY: `p` is a live payload; `bytes` is readable.
    let rc = unsafe { wz_ext_message_payload_decode(loan(p), bytes.as_ptr(), bytes.len()) };
    stated(
        "message_payload_decode",
        rc,
        &[Z_OK, WZ_EXT_ERR_PAYLOAD_WIRE],
    );
    held_to("message_payload_decode", p, rc, &before);
    if rc != Z_OK {
        return;
    }
    // What a payload encodes, it decodes again, into the same bytes.
    let Ok(first) = encode(p) else {
        return;
    };
    // SAFETY: `first` is readable.
    let rc = unsafe { wz_ext_message_payload_decode(loan(p), first.as_ptr(), first.len()) };
    assert_eq!(
        rc, Z_OK,
        "message_payload_decode: refused ({rc}) the bytes the payload encoded: {first:02x?}"
    );
    assert_eq!(
        encode(p),
        Ok(first),
        "the bytes a payload encoded do not encode to themselves"
    );
}

fn read_every_kind(p: &Payload, path: &CString) {
    let reads = [
        Z_OK,
        WZ_EXT_ERR_PAYLOAD_PATH,
        WZ_EXT_ERR_PAYLOAD_TYPE,
        WZ_EXT_ERR_PAYLOAD_RANGE,
        WZ_EXT_ERR_PAYLOAD_ABSENT,
        Z_EINVAL,
    ];
    let at = path.as_ptr();
    let before = encode(p);
    let (mut i, mut u, mut d, mut b, mut n) = (0i64, 0u64, 0f64, false, 0usize);
    // SAFETY (each): `p` is a live payload, `at` a NUL-terminated path, the outs writable.
    let answers = unsafe {
        [
            wz_ext_message_payload_get_int(loan(p), at, &mut i),
            wz_ext_message_payload_get_uint(loan(p), at, &mut u),
            wz_ext_message_payload_get_double(loan(p), at, &mut d),
            wz_ext_message_payload_get_bool(loan(p), at, &mut b),
            wz_ext_message_payload_count(loan(p), at, &mut n),
        ]
    };
    for rc in answers {
        stated("message_payload_get", rc, &reads);
    }
    read_whole("message_payload_get_string", p, path, true);
    read_whole("message_payload_get_bytes", p, path, false);
    assert_eq!(encode(p), before, "a read changed the payload");
}

/// Read the text or bytes at `path`: the length alone, then a buffer that fits it exactly.
fn read_whole(door: &str, p: &Payload, path: &CString, text: bool) {
    let get = |out: *mut u8, capacity: usize, len: &mut usize| -> ZResult {
        // SAFETY: `p` is a live payload, `path` NUL-terminated, `out` writable for `capacity`.
        unsafe {
            if text {
                wz_ext_message_payload_get_string(loan(p), path.as_ptr(), out.cast(), capacity, len)
            } else {
                wz_ext_message_payload_get_bytes(loan(p), path.as_ptr(), out, capacity, len)
            }
        }
    };
    let mut len = usize::MAX;
    let rc = get(core::ptr::null_mut(), 0, &mut len);
    stated(
        door,
        rc,
        &[
            Z_OK,
            Z_ERR_OVERFLOW,
            WZ_EXT_ERR_PAYLOAD_PATH,
            WZ_EXT_ERR_PAYLOAD_TYPE,
            WZ_EXT_ERR_PAYLOAD_RANGE,
            WZ_EXT_ERR_PAYLOAD_ABSENT,
            Z_EINVAL,
        ],
    );
    let fits = match rc {
        // Text needs room for its NUL, so only empty bytes fit in no room.
        Z_OK => {
            assert!(!text, "{door}: text written into no room");
            assert_eq!(len, 0, "{door}: no room and a length of {len}");
            return;
        }
        Z_ERR_OVERFLOW => len + usize::from(text),
        _ => return,
    };
    let mut out = vec![0xA5u8; fits];
    let mut again = usize::MAX;
    let rc = get(out.as_mut_ptr(), fits, &mut again);
    assert_eq!(
        rc, Z_OK,
        "{door}: a buffer of the {fits} bytes it asked for answered {rc}"
    );
    assert_eq!(again, len, "{door}: told {len}, then wrote {again}");
    if text {
        assert_eq!(out[len], 0, "{door}: no NUL after the text");
        core::str::from_utf8(&out[..len])
            .unwrap_or_else(|e| panic!("{door}: text that is not UTF-8: {e}"));
    }
}

fn drop_schema(schema: &mut wz_ext_owned_payload_schema_t) {
    // SAFETY: an owned schema slot, dropped twice; the second is a documented no-op.
    unsafe {
        wz_ext_payload_schema_drop(wz_ext_payload_schema_move(schema));
        assert!(
            !wz_ext_internal_payload_schema_check(schema),
            "a dropped schema is still held"
        );
        wz_ext_payload_schema_drop(wz_ext_payload_schema_move(schema));
    }
}

fn drop_payload(p: &mut Payload) {
    // SAFETY: an owned payload slot, dropped twice; the second is a documented no-op.
    unsafe {
        wz_ext_message_payload_drop(wz_ext_message_payload_move(p));
        assert!(
            !wz_ext_internal_message_payload_check(p),
            "a dropped payload is still held"
        );
        wz_ext_message_payload_drop(wz_ext_message_payload_move(p));
        assert!(
            wz_ext_message_payload_key_expr(loan(p)).is_null(),
            "a dropped payload has a key"
        );
        let rc = wz_ext_message_payload_decode(loan(p), core::ptr::null(), 0);
        assert_eq!(
            rc, Z_ERR_NULL,
            "message_payload_decode: a dropped payload answered {rc}"
        );
    }
}
