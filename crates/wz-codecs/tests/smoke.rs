// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Phase 2 walking-skeleton smoke test for wz-codecs.
//!
//! This test does NOT validate wire interop against zenoh-pico — that
//! is the Layer 3 deliverable that lands alongside `crates/zenoh-pico-sys`
//! in R41/R42. The smoke test below is sufficient to prove three
//! properties at the codec-kind layer:
//!
//!   1. sce-codegen produces compilable Rust for every codec-kind
//!      SCXML in `sources/codecs/{timestamp,encoding,ext_unit,
//!      ext_zint,ext_zbuf,ext_entry,msg_put,msg_del}.scxml`.
//!
//!   2. The generated `decode` and `encode` methods agree with each
//!      other on default-constructed instances (encode→decode→encode
//!      idempotence on the Default state).
//!
//!   3. The dependency graph (msg_put → {timestamp, encoding,
//!      ext_entry}; ext_entry → {ext_unit, ext_zint, ext_zbuf})
//!      resolves correctly through cargo's module system — the
//!      `use super::X::Y` references in the codegen output find the
//!      sibling modules declared in `wz_codecs::lib`.
//!
//! The "no byte-value assertion" gap (we don't check that the encoded
//! bytes match a known zenoh-pico-encoded reference) is what Layer 3
//! closes. Until then, this test only checks that the codegen
//! pipeline produces self-consistent code.

use sce_forge_runtime::codec::SceCursor;
use wz_codecs::msg_del::MsgDel;
use wz_codecs::msg_put::MsgPut;

#[test]
fn msg_put_default_encode_decode_roundtrip() {
    let put = MsgPut::default();
    let encoded = put.encode();
    assert!(
        !encoded.is_empty(),
        "Default MsgPut encode produced 0 bytes — at minimum the \
         header byte should be present"
    );

    let mut cursor = SceCursor::new(&encoded);
    let decoded = MsgPut::decode(&mut cursor).expect("decode default MsgPut bytes");

    assert_eq!(decoded.header, put.header, "header byte round-trip");
    assert_eq!(decoded.payload_len, put.payload_len, "payload_len round-trip");
    assert_eq!(decoded.payload, put.payload, "payload bytes round-trip");
    assert!(decoded.timestamp.is_none(), "timestamp gate cleared in default");
    assert!(decoded.encoding.is_none(), "encoding gate cleared in default");
    assert!(decoded.extensions.is_none(), "extensions gate cleared in default");
}

#[test]
fn msg_del_default_encode_decode_roundtrip() {
    let del = MsgDel::default();
    let encoded = del.encode();
    assert!(
        !encoded.is_empty(),
        "Default MsgDel encode produced 0 bytes — at minimum the \
         header byte should be present"
    );

    let mut cursor = SceCursor::new(&encoded);
    let decoded = MsgDel::decode(&mut cursor).expect("decode default MsgDel bytes");

    assert_eq!(decoded.header, del.header);
    assert!(decoded.timestamp.is_none());
    assert!(decoded.extensions.is_none());
}

#[test]
fn reply_default_encode_decode_roundtrip() {
    // R95 — Reply is an inner body codec for the Z_RESPONSE envelope
    // landing in R97; default header bakes MID 0x04 per RFC variant-
    // default-uniformity. C=0 keeps consolidation absent; Z=0 keeps
    // the ext-chain absent; the always-present push_body variant
    // defaults to MsgPut (declared default arm) whose header is 0x01
    // baked-in.
    use wz_codecs::reply::Reply;

    let reply = Reply::default();
    let encoded = reply.encode();
    assert!(
        !encoded.is_empty(),
        "default Reply encode produced 0 bytes — header byte expected"
    );
    assert_eq!(
        encoded[0], 0x04,
        "default Reply header carries MID Z_REPLY = 0x04"
    );

    let mut cursor = SceCursor::new(&encoded);
    let decoded = Reply::decode(&mut cursor).expect("decode default Reply bytes");

    assert_eq!(decoded.header, reply.header, "header round-trip");
    assert!(decoded.consolidation.is_none(), "C clear => consolidation absent");
    assert!(decoded.extensions.is_none(), "Z clear => extensions absent");
}

#[test]
fn err_default_encode_decode_roundtrip() {
    // R96 — Err is the second inner-body codec consumed by the
    // RESPONSE envelope (R97). Default header bakes MID 0x05 per RFC
    // variant-default-uniformity. E=0 keeps the encoding embed
    // absent; Z=0 keeps the source_info ext-chain absent; the
    // always-present payload pair (length + bytes) emits as VLE(0) +
    // empty bytes = 1 byte.
    use wz_codecs::err::Err;

    let err = Err::default();
    let encoded = err.encode();
    assert!(
        !encoded.is_empty(),
        "default Err encode produced 0 bytes — header expected"
    );
    assert_eq!(
        encoded[0], 0x05,
        "default Err header carries MID Z_ERR = 0x05"
    );

    let mut cursor = SceCursor::new(&encoded);
    let decoded = Err::decode(&mut cursor).expect("decode default Err bytes");

    assert_eq!(decoded.header, err.header, "header round-trip");
    assert!(decoded.encoding.is_none(), "E clear => encoding absent");
    assert!(decoded.extensions.is_none(), "Z clear => extensions absent");
    assert_eq!(decoded.payload_len, 0, "default payload length zero");
    assert!(decoded.payload.is_empty(), "default payload bytes empty");
}
