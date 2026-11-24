// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The payload of a catalog message through the `wz_ext_payload_schema_*` and
//! `wz_ext_message_payload_*` doors, driven as a C program drives them: a schema read from the
//! descriptor set `protoc` compiled the program's `.proto` file into (and, with `proto-text`,
//! from the file's text), a payload made for a message of the catalog, values set at paths, the
//! bytes encoded into the program's buffer, decoded into another payload and read back.
//!
//! What the payload does with a path, a value and the bytes is the model tests' of `wz-app-frame`'s
//! `message_payload`. What those cannot show is the part a C program relies on: that each refusal
//! is its own code and leaves a sentence, that a buffer too small is told with the size it needs,
//! that a refused making leaves the gravestone, and that a payload holds its schema past the
//! schema's own drop. The catalog is the reader's synthetic one, and the schema and every value are
//! synthetic; every expected byte is laid by hand.

#![cfg(feature = "message-payload")]

use std::ffi::{CStr, CString};
use std::ops::{Deref, DerefMut};

use wz_capi_pico::message_catalog::*;
use wz_capi_pico::message_payload::*;
#[cfg(feature = "proto-text")]
use wz_capi_pico::proto_file::wz_ext_proto_file_t;
use wz_capi_pico::result::{
    ZResult, WZ_EXT_ERR_PAYLOAD_ABSENT, WZ_EXT_ERR_PAYLOAD_PATH, WZ_EXT_ERR_PAYLOAD_RANGE,
    WZ_EXT_ERR_PAYLOAD_TYPE, WZ_EXT_ERR_PAYLOAD_WIRE, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE,
    Z_ERR_INVALID, Z_ERR_NULL, Z_ERR_OVERFLOW, Z_OK,
};
use wz_capi_pico::{
    z_internal_string_check, z_owned_string_t, z_string_data, z_string_drop, z_string_len,
    z_string_loan, z_string_move,
};

const CATALOG: &str = include_str!("../../../../wz-app-frame/catalog/synthetic.json5");
/// The synthetic catalog's first message and its key.
const POSE: usize = 0;
const POSE_KEY: &str = "demo/catalog/pose";

/// The schema of these tests, as the program writes it in `syn/door.proto`.
#[cfg(feature = "proto-text")]
const SCHEMA: &str = r#"
syntax = "proto3";
package syn.door;

enum Tone {
  TONE_NONE = 0;
  TONE_WARM = 1;
  TONE_COLD = 2;
}

message Point {
  sint32 x = 1;
  sint32 y = 2;
}

message Pose {
  uint32 serial = 1;
  int32 offset = 2;
  double weight = 3;
  bool lit = 4;
  string label = 5;
  bytes blob = 6;
  Tone tone = 7;
  Point origin = 8;
  repeated Point path = 9;
  optional uint64 stamp = 10;
}
"#;

/// `SCHEMA` as `protoc --include_imports -o` compiles it from `syn/door.proto`: the
/// `FileDescriptorSet` a program builds into itself.
const SCHEMA_SET: &[u8] = &[
    0x0a, 0xa0, 0x03, 0x0a, 0x0e, 0x73, 0x79, 0x6e, 0x2f, 0x64, 0x6f, 0x6f, 0x72, 0x2e, 0x70, 0x72,
    0x6f, 0x74, 0x6f, 0x12, 0x08, 0x73, 0x79, 0x6e, 0x2e, 0x64, 0x6f, 0x6f, 0x72, 0x22, 0x23, 0x0a,
    0x05, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x12, 0x0c, 0x0a, 0x01, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28,
    0x11, 0x52, 0x01, 0x78, 0x12, 0x0c, 0x0a, 0x01, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x11, 0x52,
    0x01, 0x79, 0x22, 0xa1, 0x02, 0x0a, 0x04, 0x50, 0x6f, 0x73, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x73,
    0x65, 0x72, 0x69, 0x61, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06, 0x73, 0x65, 0x72,
    0x69, 0x61, 0x6c, 0x12, 0x16, 0x0a, 0x06, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x18, 0x02, 0x20,
    0x01, 0x28, 0x05, 0x52, 0x06, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x77,
    0x65, 0x69, 0x67, 0x68, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x01, 0x52, 0x06, 0x77, 0x65, 0x69,
    0x67, 0x68, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x6c, 0x69, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08,
    0x52, 0x03, 0x6c, 0x69, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x18, 0x05,
    0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x12, 0x12, 0x0a, 0x04, 0x62,
    0x6c, 0x6f, 0x62, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x62, 0x6c, 0x6f, 0x62, 0x12,
    0x22, 0x0a, 0x04, 0x74, 0x6f, 0x6e, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0e, 0x2e,
    0x73, 0x79, 0x6e, 0x2e, 0x64, 0x6f, 0x6f, 0x72, 0x2e, 0x54, 0x6f, 0x6e, 0x65, 0x52, 0x04, 0x74,
    0x6f, 0x6e, 0x65, 0x12, 0x27, 0x0a, 0x06, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x18, 0x08, 0x20,
    0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x73, 0x79, 0x6e, 0x2e, 0x64, 0x6f, 0x6f, 0x72, 0x2e, 0x50,
    0x6f, 0x69, 0x6e, 0x74, 0x52, 0x06, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x12, 0x23, 0x0a, 0x04,
    0x70, 0x61, 0x74, 0x68, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x73, 0x79, 0x6e,
    0x2e, 0x64, 0x6f, 0x6f, 0x72, 0x2e, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x52, 0x04, 0x70, 0x61, 0x74,
    0x68, 0x12, 0x19, 0x0a, 0x05, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x04,
    0x48, 0x00, 0x52, 0x05, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x88, 0x01, 0x01, 0x42, 0x08, 0x0a, 0x06,
    0x5f, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2a, 0x33, 0x0a, 0x04, 0x54, 0x6f, 0x6e, 0x65, 0x12, 0x0d,
    0x0a, 0x09, 0x54, 0x4f, 0x4e, 0x45, 0x5f, 0x4e, 0x4f, 0x4e, 0x45, 0x10, 0x00, 0x12, 0x0d, 0x0a,
    0x09, 0x54, 0x4f, 0x4e, 0x45, 0x5f, 0x57, 0x41, 0x52, 0x4d, 0x10, 0x01, 0x12, 0x0d, 0x0a, 0x09,
    0x54, 0x4f, 0x4e, 0x45, 0x5f, 0x43, 0x4f, 0x4c, 0x44, 0x10, 0x02, 0x62, 0x06, 0x70, 0x72, 0x6f,
    0x74, 0x6f, 0x33,
];

type Owned = wz_ext_owned_message_payload_t;

/// The values and the bytes a payload of these tests holds at once: room for every test's.
const FIELDS: usize = 32;
const BYTES: usize = 256;

/// A payload and the program's storage it keeps its values in, which outlives it.
#[derive(Debug)]
struct Made {
    payload: Owned,
    _storage: Vec<u8>,
}

impl Deref for Made {
    type Target = Owned;

    fn deref(&self) -> &Owned {
        &self.payload
    }
}

impl DerefMut for Made {
    fn deref_mut(&mut self) -> &mut Owned {
        &mut self.payload
    }
}

/// The text of a string slot a door wrote, which is then dropped; empty for the null state.
unsafe fn take(out: &mut z_owned_string_t) -> String {
    if !z_internal_string_check(out) {
        return String::new();
    }
    let loaned = z_string_loan(out);
    let len = z_string_len(loaned);
    let text = if len == 0 {
        String::new()
    } else {
        let bytes = std::slice::from_raw_parts(z_string_data(loaned).cast::<u8>(), len);
        String::from_utf8_lossy(bytes).into_owned()
    };
    z_string_drop(z_string_move(out));
    text
}

fn text(value: &str) -> CString {
    CString::new(value).expect("no NUL")
}

fn catalog() -> wz_ext_owned_message_catalog_t {
    let body = text(CATALOG);
    unsafe {
        let mut this: wz_ext_owned_message_catalog_t = std::mem::zeroed();
        let mut refusal: z_owned_string_t = std::mem::zeroed();
        let rc = wz_ext_message_catalog_new(&mut this, body.as_ptr(), &mut refusal);
        let why = take(&mut refusal);
        assert_eq!(rc, Z_OK, "the synthetic catalog reads: {why}");
        this
    }
}

/// A schema of the descriptor set `set`, or the code and the reason it was refused with.
fn schema(set: &[u8]) -> Result<wz_ext_owned_payload_schema_t, (ZResult, String)> {
    unsafe {
        let mut this: wz_ext_owned_payload_schema_t = std::mem::zeroed();
        let mut refusal: z_owned_string_t = std::mem::zeroed();
        let rc = wz_ext_payload_schema_from_descriptor_set(
            &mut this,
            set.as_ptr(),
            set.len(),
            &mut refusal,
        );
        made_schema(this, rc, &mut refusal)
    }
}

/// A schema of the one file `body` read as text, or the code and the reason it was refused with.
#[cfg(feature = "proto-text")]
fn schema_text(body: &[u8]) -> Result<wz_ext_owned_payload_schema_t, (ZResult, String)> {
    let name = text("syn/door.proto");
    let mut file = body.to_vec();
    file.push(0);
    let files = [wz_ext_proto_file_t {
        name: name.as_ptr(),
        text: file.as_ptr().cast(),
    }];
    unsafe {
        let mut this: wz_ext_owned_payload_schema_t = std::mem::zeroed();
        let mut refusal: z_owned_string_t = std::mem::zeroed();
        let rc = wz_ext_payload_schema_new(&mut this, files.as_ptr(), files.len(), &mut refusal);
        made_schema(this, rc, &mut refusal)
    }
}

/// The schema a door wrote with `rc`, held to the door's contract: a schema and no refusal, or
/// the gravestone and the code with its reason.
unsafe fn made_schema(
    this: wz_ext_owned_payload_schema_t,
    rc: ZResult,
    refusal: &mut z_owned_string_t,
) -> Result<wz_ext_owned_payload_schema_t, (ZResult, String)> {
    let why = take(refusal);
    if rc == Z_OK {
        assert!(why.is_empty(), "a schema read leaves no refusal: {why}");
        assert!(wz_ext_internal_payload_schema_check(&this));
        Ok(this)
    } else {
        assert!(
            !wz_ext_internal_payload_schema_check(&this),
            "a refused schema leaves the null state"
        );
        Err((rc, why))
    }
}

/// A payload of catalog message `index`, of message type `message`, or the code and the reason.
fn payload(
    catalog: &wz_ext_owned_message_catalog_t,
    index: usize,
    schema: &wz_ext_owned_payload_schema_t,
    message: &str,
) -> Result<Made, (ZResult, String)> {
    payload_holding(catalog, index, schema, message, FIELDS, BYTES)
}

/// [`payload`] in storage of `fields` values and `bytes` bytes, sized by the library.
fn payload_holding(
    catalog: &wz_ext_owned_message_catalog_t,
    index: usize,
    schema: &wz_ext_owned_payload_schema_t,
    message: &str,
    fields: usize,
    bytes: usize,
) -> Result<Made, (ZResult, String)> {
    let mut storage = vec![0u8; wz_ext_message_payload_storage_size(fields, bytes)];
    let options = wz_ext_message_payload_options_t {
        storage: storage.as_mut_ptr(),
        storage_len: storage.len(),
        fields,
        bytes,
    };
    made_with(catalog, index, schema, message, &options).map(|payload| Made {
        payload,
        _storage: storage,
    })
}

/// The payload `wz_ext_message_payload_new` makes under `options`, or the code and the reason.
fn made_with(
    catalog: &wz_ext_owned_message_catalog_t,
    index: usize,
    schema: &wz_ext_owned_payload_schema_t,
    message: &str,
    options: *const wz_ext_message_payload_options_t,
) -> Result<Owned, (ZResult, String)> {
    let message = text(message);
    unsafe {
        let mut this: Owned = std::mem::zeroed();
        let mut refusal: z_owned_string_t = std::mem::zeroed();
        let rc = wz_ext_message_payload_new(
            &mut this,
            wz_ext_message_catalog_loan(catalog),
            index,
            wz_ext_payload_schema_loan(schema),
            message.as_ptr(),
            options,
            &mut refusal,
        );
        let why = take(&mut refusal);
        if rc == Z_OK {
            assert!(wz_ext_internal_message_payload_check(&this));
            Ok(this)
        } else {
            assert!(
                !wz_ext_internal_message_payload_check(&this),
                "a refused payload leaves the null state"
            );
            Err((rc, why))
        }
    }
}

fn loan(p: &Owned) -> *const wz_ext_loaned_message_payload_t {
    unsafe { wz_ext_message_payload_loan(p) }
}

fn set_int(p: &Owned, at: &str, value: i64) -> ZResult {
    let at = text(at);
    unsafe { wz_ext_message_payload_set_int(loan(p), at.as_ptr(), value) }
}

fn set_uint(p: &Owned, at: &str, value: u64) -> ZResult {
    let at = text(at);
    unsafe { wz_ext_message_payload_set_uint(loan(p), at.as_ptr(), value) }
}

fn set_double(p: &Owned, at: &str, value: f64) -> ZResult {
    let at = text(at);
    unsafe { wz_ext_message_payload_set_double(loan(p), at.as_ptr(), value) }
}

fn set_bool(p: &Owned, at: &str, value: bool) -> ZResult {
    let at = text(at);
    unsafe { wz_ext_message_payload_set_bool(loan(p), at.as_ptr(), value) }
}

fn set_string(p: &Owned, at: &str, value: &str) -> ZResult {
    let at = text(at);
    let value = text(value);
    unsafe { wz_ext_message_payload_set_string(loan(p), at.as_ptr(), value.as_ptr()) }
}

fn set_bytes(p: &Owned, at: &str, value: &[u8]) -> ZResult {
    let at = text(at);
    unsafe { wz_ext_message_payload_set_bytes(loan(p), at.as_ptr(), value.as_ptr(), value.len()) }
}

fn get_int(p: &Owned, at: &str) -> Result<i64, ZResult> {
    let at = text(at);
    let mut out = 0i64;
    match unsafe { wz_ext_message_payload_get_int(loan(p), at.as_ptr(), &mut out) } {
        Z_OK => Ok(out),
        rc => Err(rc),
    }
}

fn get_uint(p: &Owned, at: &str) -> Result<u64, ZResult> {
    let at = text(at);
    let mut out = 0u64;
    match unsafe { wz_ext_message_payload_get_uint(loan(p), at.as_ptr(), &mut out) } {
        Z_OK => Ok(out),
        rc => Err(rc),
    }
}

fn count(p: &Owned, at: &str) -> Result<usize, ZResult> {
    let at = text(at);
    let mut out = 0usize;
    match unsafe { wz_ext_message_payload_count(loan(p), at.as_ptr(), &mut out) } {
        Z_OK => Ok(out),
        rc => Err(rc),
    }
}

/// The sentence of the last refused call on `p`; empty when it was not refused.
fn refusal_of(p: &Owned) -> String {
    unsafe {
        let mut out: z_owned_string_t = std::mem::zeroed();
        assert_eq!(wz_ext_message_payload_refusal(loan(p), &mut out), Z_OK);
        take(&mut out)
    }
}

/// The bytes `p` encodes to, asked for by size first.
fn encoded(p: &Owned) -> Vec<u8> {
    unsafe {
        let mut size = 0usize;
        let rc = wz_ext_message_payload_encode(loan(p), std::ptr::null_mut(), 0, &mut size);
        if size == 0 {
            assert_eq!(rc, Z_OK, "an empty payload encodes into no room");
            return Vec::new();
        }
        assert_eq!(
            rc,
            Z_ERR_OVERFLOW,
            "no room is too little: {}",
            refusal_of(p)
        );
        let mut out = vec![0u8; size];
        let mut written = 0usize;
        assert_eq!(
            wz_ext_message_payload_encode(loan(p), out.as_mut_ptr(), out.len(), &mut written),
            Z_OK
        );
        assert_eq!(written, size);
        out
    }
}

fn drop_payload(p: &mut Owned) {
    unsafe {
        wz_ext_message_payload_drop(wz_ext_message_payload_move(p));
        assert!(!wz_ext_internal_message_payload_check(p));
        wz_ext_message_payload_drop(wz_ext_message_payload_move(p));
    }
}

fn drop_schema(s: &mut wz_ext_owned_payload_schema_t) {
    unsafe {
        wz_ext_payload_schema_drop(wz_ext_payload_schema_move(s));
        assert!(!wz_ext_internal_payload_schema_check(s));
        wz_ext_payload_schema_drop(wz_ext_payload_schema_move(s));
    }
}

fn drop_catalog(c: &mut wz_ext_owned_message_catalog_t) {
    unsafe { wz_ext_message_catalog_drop(wz_ext_message_catalog_move(c)) }
}

#[test]
fn a_payload_of_a_catalog_message_keeps_its_key_and_its_schema() {
    let mut c = catalog();
    let mut s = schema(SCHEMA_SET).expect("the schema reads");
    let mut p = payload(&c, POSE, &s, "syn.door.Pose").expect("the payload is made");
    unsafe {
        let key = wz_ext_message_payload_key_expr(loan(&p));
        assert!(!key.is_null());
        assert_eq!(CStr::from_ptr(key).to_str(), Ok(POSE_KEY));
    }
    // The schema and the catalog may go first: the payload holds what it needs of both.
    drop_schema(&mut s);
    drop_catalog(&mut c);
    assert_eq!(set_uint(&p, "serial", 150), Z_OK);
    assert_eq!(encoded(&p), [0x08, 0x96, 0x01]);
    drop_payload(&mut p);
    unsafe {
        assert!(wz_ext_message_payload_key_expr(loan(&p)).is_null());
    }
}

#[test]
fn a_schema_or_a_payload_that_cannot_be_made_is_refused_by_code() {
    let (rc, why) = schema(&[0xFF, 0xFE]).expect_err("refused");
    assert_eq!(
        rc, Z_ERR_CONFIG_INVALID_VALUE,
        "bytes that are no descriptor set"
    );
    assert!(!why.is_empty(), "the refusal says why");
    let (rc, _) = schema(&SCHEMA_SET[..SCHEMA_SET.len() - 1]).expect_err("refused");
    assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE, "a descriptor set cut short");
    unsafe {
        let mut this: wz_ext_owned_payload_schema_t = std::mem::zeroed();
        assert_eq!(
            wz_ext_payload_schema_from_descriptor_set(
                &mut this,
                std::ptr::null(),
                1,
                std::ptr::null_mut()
            ),
            Z_ERR_NULL,
            "null bytes with a length"
        );
        assert!(!wz_ext_internal_payload_schema_check(&this));
        assert_eq!(
            wz_ext_payload_schema_from_descriptor_set(
                std::ptr::null_mut(),
                SCHEMA_SET.as_ptr(),
                SCHEMA_SET.len(),
                std::ptr::null_mut()
            ),
            Z_ERR_NULL,
            "no slot for the schema"
        );
    }

    let mut c = catalog();
    let mut s = schema(SCHEMA_SET).expect("the schema reads");
    let (rc, _) = payload(&c, 9, &s, "syn.door.Pose").expect_err("refused");
    assert_eq!(rc, Z_ERR_INVALID, "a message the catalog has not");
    let (rc, why) = payload(&c, POSE, &s, "syn.door.Nope").expect_err("refused");
    assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
    assert!(
        why.contains("syn.door.Nope"),
        "the refusal names the type: {why}"
    );
    let (rc, _) = payload(&c, POSE, &s, "syn.door.Tone").expect_err("refused");
    assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE, "an enum is no message");
    let name = text("syn.door.Pose");
    unsafe {
        let mut this: Owned = std::mem::zeroed();
        assert_eq!(
            wz_ext_message_payload_new(
                &mut this,
                wz_ext_message_catalog_loan(&c),
                POSE,
                std::ptr::null(),
                name.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut()
            ),
            Z_ERR_NULL,
            "a null schema"
        );
    }
    drop_schema(&mut s);
    drop_catalog(&mut c);
}

#[test]
fn values_set_by_path_encode_to_their_bytes_and_decode_back() {
    let mut c = catalog();
    let mut s = schema(SCHEMA_SET).expect("the schema reads");
    let mut p = payload(&c, POSE, &s, "syn.door.Pose").expect("the payload is made");
    assert_eq!(set_uint(&p, "serial", 150), Z_OK);
    assert_eq!(set_int(&p, "offset", -2), Z_OK);
    assert_eq!(set_string(&p, "label", "hi"), Z_OK);
    assert_eq!(set_int(&p, "origin.x", -3), Z_OK);
    assert_eq!(
        encoded(&p),
        [
            0x08, 0x96, 0x01, // serial
            0x10, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, // offset: -2
            0x2A, 0x02, b'h', b'i', // label
            0x42, 0x02, 0x08, 0x05, // origin { x: -3 }, zigzagged
        ]
    );

    assert_eq!(set_double(&p, "weight", 1.5), Z_OK);
    assert_eq!(set_bool(&p, "lit", true), Z_OK);
    assert_eq!(set_bytes(&p, "blob", &[1, 2, 3]), Z_OK);
    assert_eq!(set_string(&p, "tone", "TONE_COLD"), Z_OK);
    assert_eq!(set_int(&p, "path[0].y", 4), Z_OK);
    let sent = encoded(&p);

    let mut q = payload(&c, POSE, &s, "syn.door.Pose").expect("the payload is made");
    unsafe {
        assert_eq!(
            wz_ext_message_payload_decode(loan(&q), sent.as_ptr(), sent.len()),
            Z_OK
        );
    }
    assert_eq!(get_uint(&q, "serial"), Ok(150));
    assert_eq!(get_int(&q, "offset"), Ok(-2));
    assert_eq!(get_int(&q, "origin.x"), Ok(-3));
    assert_eq!(get_int(&q, "path[0].y"), Ok(4));
    assert_eq!(get_int(&q, "tone"), Ok(2));
    let weight = text("weight");
    let lit = text("lit");
    let tone = text("tone");
    let blob = text("blob");
    unsafe {
        let mut real = 0f64;
        assert_eq!(
            wz_ext_message_payload_get_double(loan(&q), weight.as_ptr(), &mut real),
            Z_OK
        );
        assert_eq!(real.to_bits(), 1.5f64.to_bits());
        let mut flag = false;
        assert_eq!(
            wz_ext_message_payload_get_bool(loan(&q), lit.as_ptr(), &mut flag),
            Z_OK
        );
        assert!(flag);

        let mut name = [0u8; 16];
        let mut len = 0usize;
        assert_eq!(
            wz_ext_message_payload_get_string(
                loan(&q),
                tone.as_ptr(),
                name.as_mut_ptr().cast(),
                name.len(),
                &mut len
            ),
            Z_OK
        );
        assert_eq!(
            CStr::from_ptr(name.as_ptr().cast()).to_str(),
            Ok("TONE_COLD")
        );
        assert_eq!(len, 9);

        let mut bytes = [0u8; 8];
        assert_eq!(
            wz_ext_message_payload_get_bytes(
                loan(&q),
                blob.as_ptr(),
                bytes.as_mut_ptr(),
                bytes.len(),
                &mut len
            ),
            Z_OK
        );
        assert_eq!(&bytes[..len], &[1, 2, 3]);
    }
    assert_eq!(
        encoded(&q),
        sent,
        "the decoded payload encodes the same bytes"
    );
    drop_payload(&mut q);
    drop_payload(&mut p);
    drop_schema(&mut s);
    drop_catalog(&mut c);
}

#[test]
fn each_refusal_is_its_own_code_and_leaves_its_sentence() {
    let mut c = catalog();
    let mut s = schema(SCHEMA_SET).expect("the schema reads");
    let mut p = payload(&c, POSE, &s, "syn.door.Pose").expect("the payload is made");
    assert_eq!(set_int(&p, "nosuch", 1), WZ_EXT_ERR_PAYLOAD_PATH);
    let why = refusal_of(&p);
    assert!(why.contains("nosuch"), "the sentence names the path: {why}");
    assert_eq!(set_double(&p, "serial", 1.0), WZ_EXT_ERR_PAYLOAD_TYPE);
    assert_eq!(set_int(&p, "offset", 1 << 40), WZ_EXT_ERR_PAYLOAD_RANGE);
    assert_eq!(
        set_int(&p, "path[1].x", 1),
        WZ_EXT_ERR_PAYLOAD_RANGE,
        "an element past the end of an empty list"
    );
    assert_eq!(get_uint(&p, "stamp"), Err(WZ_EXT_ERR_PAYLOAD_ABSENT));
    let truncated = [0x08u8];
    unsafe {
        assert_eq!(
            wz_ext_message_payload_decode(loan(&p), truncated.as_ptr(), truncated.len()),
            WZ_EXT_ERR_PAYLOAD_WIRE
        );
    }
    assert!(!refusal_of(&p).is_empty());
    // A call that is not refused clears the sentence.
    assert_eq!(set_uint(&p, "stamp", 0), Z_OK);
    assert_eq!(refusal_of(&p), "");
    assert_eq!(get_uint(&p, "stamp"), Ok(0));
    assert_eq!(
        encoded(&p),
        [0x50, 0x00],
        "a field with presence is written at zero"
    );

    // A buffer too small is told with the size it needs, and nothing is written.
    assert_eq!(set_string(&p, "label", "seven!!"), Z_OK);
    let label = text("label");
    let mut room = [0x55u8; 4];
    let mut len = 0usize;
    unsafe {
        assert_eq!(
            wz_ext_message_payload_get_string(
                loan(&p),
                label.as_ptr(),
                room.as_mut_ptr().cast(),
                room.len(),
                &mut len
            ),
            Z_ERR_OVERFLOW
        );
    }
    assert_eq!(len, 7);
    assert!(room.iter().all(|&b| b == 0x55));
    drop_payload(&mut p);
    drop_schema(&mut s);
    drop_catalog(&mut c);
}

#[test]
fn a_null_argument_or_a_gravestone_is_refused() {
    let mut c = catalog();
    let mut s = schema(SCHEMA_SET).expect("the schema reads");
    let mut p = payload(&c, POSE, &s, "syn.door.Pose").expect("the payload is made");
    let serial = text("serial");
    let bad = [0xFFu8, 0];
    unsafe {
        assert_eq!(
            wz_ext_message_payload_set_int(loan(&p), std::ptr::null(), 1),
            Z_ERR_NULL
        );
        assert_eq!(
            wz_ext_message_payload_set_bytes(loan(&p), serial.as_ptr(), std::ptr::null(), 2),
            Z_ERR_NULL
        );
        assert_eq!(
            wz_ext_message_payload_set_string(loan(&p), serial.as_ptr(), bad.as_ptr().cast()),
            Z_EINVAL
        );
        assert_eq!(
            wz_ext_message_payload_get_int(loan(&p), serial.as_ptr(), std::ptr::null_mut()),
            Z_ERR_NULL
        );
        let mut written = 0usize;
        assert_eq!(
            wz_ext_message_payload_encode(loan(&p), std::ptr::null_mut(), 4, &mut written),
            Z_ERR_NULL,
            "a null buffer with a capacity"
        );
    }
    drop_payload(&mut p);
    assert_eq!(set_int(&p, "serial", 1), Z_ERR_NULL, "the gravestone");
    drop_schema(&mut s);
    drop_catalog(&mut c);
}

#[test]
fn a_list_is_counted_and_an_element_cleared() {
    let mut c = catalog();
    let mut s = schema(SCHEMA_SET).expect("the schema reads");
    let mut p = payload(&c, POSE, &s, "syn.door.Pose").expect("the payload is made");
    assert_eq!(set_int(&p, "path[0].x", 1), Z_OK);
    assert_eq!(set_int(&p, "path[1].x", 2), Z_OK);
    assert_eq!(count(&p, "path"), Ok(2));
    assert_eq!(count(&p, "serial"), Err(WZ_EXT_ERR_PAYLOAD_PATH));
    let first = text("path[0]");
    unsafe {
        assert_eq!(wz_ext_message_payload_clear(loan(&p), first.as_ptr()), Z_OK);
    }
    assert_eq!(count(&p, "path"), Ok(1));
    assert_eq!(get_int(&p, "path[0].x"), Ok(2));
    unsafe {
        assert_eq!(wz_ext_message_payload_reset(loan(&p)), Z_OK);
    }
    assert_eq!(encoded(&p), Vec::<u8>::new());
    drop_payload(&mut p);
    drop_schema(&mut s);
    drop_catalog(&mut c);
}

/// A payload keeps its values in the storage the program sized: the storage is refused short of
/// its size, a value past its slots or its bytes is refused with nothing changed, and bytes whose
/// values do not fit it leave the payload empty.
#[test]
fn a_payload_holds_what_its_storage_was_sized_for_and_refuses_past_it() {
    let mut c = catalog();
    let mut s = schema(SCHEMA_SET).expect("the schema reads");

    assert_eq!(wz_ext_message_payload_storage_size(0, 0), 0);
    assert_eq!(wz_ext_message_payload_storage_size(0, 9), 9);
    assert!(
        wz_ext_message_payload_storage_size(2, 9) > wz_ext_message_payload_storage_size(1, 9),
        "each value takes room"
    );
    assert_eq!(
        wz_ext_message_payload_storage_size(usize::MAX, 1),
        0,
        "a size past the address space"
    );

    // The storage short of its size, and no options at all, are refused with the gravestone.
    let size = wz_ext_message_payload_storage_size(2, 8);
    let mut short = vec![0u8; size - 1];
    let options = wz_ext_message_payload_options_t {
        storage: short.as_mut_ptr(),
        storage_len: short.len(),
        fields: 2,
        bytes: 8,
    };
    let (rc, why) = made_with(&c, POSE, &s, "syn.door.Pose", &options).expect_err("refused");
    assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
    assert!(
        why.contains("storage"),
        "the sentence names the storage: {why}"
    );
    let (rc, _) = made_with(&c, POSE, &s, "syn.door.Pose", std::ptr::null()).expect_err("refused");
    assert_eq!(rc, Z_ERR_NULL, "no options");
    let no_storage = wz_ext_message_payload_options_t {
        storage: std::ptr::null_mut(),
        storage_len: size,
        fields: 2,
        bytes: 8,
    };
    let (rc, _) = made_with(&c, POSE, &s, "syn.door.Pose", &no_storage).expect_err("refused");
    assert_eq!(rc, Z_ERR_NULL, "a null storage of a size");

    // One slot: the second value is refused and the first is as it was.
    let mut one = payload_holding(&c, POSE, &s, "syn.door.Pose", 1, 0).expect("made");
    assert_eq!(set_uint(&one, "serial", 150), Z_OK);
    assert_eq!(set_int(&one, "offset", 1), Z_ERR_OVERFLOW);
    assert!(
        !refusal_of(&one).is_empty(),
        "the refusal leaves its sentence"
    );
    assert_eq!(get_uint(&one, "serial"), Ok(150));
    assert_eq!(encoded(&one), [0x08, 0x96, 0x01]);

    // Three bytes: a string past them is refused and the one held is kept.
    let mut few = payload_holding(&c, POSE, &s, "syn.door.Pose", 4, 3).expect("made");
    assert_eq!(set_string(&few, "label", "ab"), Z_OK);
    assert_eq!(set_string(&few, "label", "abcdef"), Z_ERR_OVERFLOW);
    assert_eq!(encoded(&few), [0x2A, 0x02, b'a', b'b']);

    // Bytes of two values decoded into one slot leave the payload empty.
    let mut wide = payload(&c, POSE, &s, "syn.door.Pose").expect("made");
    assert_eq!(set_uint(&wide, "serial", 150), Z_OK);
    assert_eq!(set_int(&wide, "offset", 1), Z_OK);
    let sent = encoded(&wide);
    assert_eq!(sent, [0x08, 0x96, 0x01, 0x10, 0x01]);
    unsafe {
        assert_eq!(
            wz_ext_message_payload_decode(loan(&one), sent.as_ptr(), sent.len()),
            Z_ERR_OVERFLOW
        );
    }
    assert_eq!(
        encoded(&one),
        Vec::<u8>::new(),
        "the refused decode left it empty"
    );

    drop_payload(&mut wide);
    drop_payload(&mut few);
    drop_payload(&mut one);
    drop_schema(&mut s);
    drop_catalog(&mut c);
}

// The text door, in a build that links the text reader: the same schema read from the file the
// descriptor set was compiled from, and the refusals of its text.
#[cfg(feature = "proto-text")]
#[test]
fn a_schema_read_from_its_text_is_the_compiled_one_and_its_refusals_are_codes() {
    let mut c = catalog();
    let mut s = schema_text(SCHEMA.as_bytes()).expect("the text reads");
    let mut p = payload(&c, POSE, &s, "syn.door.Pose").expect("the payload is made");
    assert_eq!(set_uint(&p, "serial", 150), Z_OK);
    assert_eq!(set_string(&p, "label", "hi"), Z_OK);
    assert_eq!(encoded(&p), [0x08, 0x96, 0x01, 0x2a, 0x02, b'h', b'i']);
    drop_payload(&mut p);
    drop_schema(&mut s);
    drop_catalog(&mut c);

    let (rc, why) = schema_text(b"syntax = \"proto3\";\nmessage Broken {\n").expect_err("refused");
    assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
    assert!(
        why.contains("syn/door.proto"),
        "the diagnostic names the file: {why}"
    );
    assert_eq!(schema_text(&[0xFF, 0xFE]).expect_err("refused").0, Z_EINVAL);
    unsafe {
        let mut this: wz_ext_owned_payload_schema_t = std::mem::zeroed();
        assert_eq!(
            wz_ext_payload_schema_new(&mut this, std::ptr::null(), 1, std::ptr::null_mut()),
            Z_ERR_NULL,
            "a null file list with a count"
        );
    }
}
