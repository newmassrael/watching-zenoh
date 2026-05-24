// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Generated wire codecs for the watching-zenoh Phase B5 codec set.
//!
//! Each `mod <stem>` block includes the sce-codegen Rust output for
//! the matching `sources/codecs/<stem>.scxml` file; `build.rs`
//! emits those files into `$OUT_DIR` at compile time via SCE's
//! in-process `compile_forge_with_imports` entry point.
//!
//! The codegen output references sibling modules with
//! `use super::X::Y;`, so all stems are declared at the same level in
//! this lib.rs (NOT nested) — that puts every codec module as a
//! direct child of the crate root, matching the codegen's `super::X`
//! lookup target.
//!
//! Walking-skeleton scope (R40): only the §6 payload trio (`msg_put`
//! / `msg_del`) and their dependency chain are wired. The full B5
//! codec catalog lands incrementally as Layer 3 wire-interop coverage
//! expands.
//!
//! Builds against `std` for R40 (AP target = Linux + tokio). MCU
//! `no_std + alloc` variant lands when the lwip runtime crate
//! arrives; the codegen output already supports both per
//! `sce-forge-runtime` baseline `no_std` contract.
//!
//! Clippy policy: the entire crate body is sce-codegen output —
//! clippy lints on the generated code's style (unnecessary casts,
//! redundant binding patterns, etc.) are SCE template authoring
//! concerns, not consumer-tunable. `#![allow(clippy::all)]` here
//! silences clippy for the include!()-pasted modules while the
//! workspace's rustc `warnings = "deny"` policy stays in force
//! (rustc warnings ARE consumer-actionable; clippy style nits on
//! generated code are not).

#![allow(clippy::all)]

pub mod timestamp {
    include!(concat!(env!("OUT_DIR"), "/timestamp.rs"));
}

pub mod encoding {
    include!(concat!(env!("OUT_DIR"), "/encoding.rs"));
}

pub mod ext_unit {
    include!(concat!(env!("OUT_DIR"), "/ext_unit.rs"));
}

pub mod ext_zint {
    include!(concat!(env!("OUT_DIR"), "/ext_zint.rs"));
}

pub mod ext_zbuf {
    include!(concat!(env!("OUT_DIR"), "/ext_zbuf.rs"));
}

pub mod stream_envelope {
    include!(concat!(env!("OUT_DIR"), "/stream_envelope.rs"));
}

pub mod close {
    include!(concat!(env!("OUT_DIR"), "/close.rs"));
}

pub mod frame {
    include!(concat!(env!("OUT_DIR"), "/frame.rs"));
}

pub mod fragment {
    include!(concat!(env!("OUT_DIR"), "/fragment.rs"));
}

pub mod scout {
    include!(concat!(env!("OUT_DIR"), "/scout.rs"));
}

#[cfg(feature = "codec-init-body")]
pub mod init_body {
    include!(concat!(env!("OUT_DIR"), "/init_body.rs"));
}

#[cfg(feature = "codec-open-body")]
pub mod open_body {
    include!(concat!(env!("OUT_DIR"), "/open_body.rs"));
}

pub mod join {
    include!(concat!(env!("OUT_DIR"), "/join.rs"));
}

pub mod locator {
    include!(concat!(env!("OUT_DIR"), "/locator.rs"));
}

pub mod hello {
    include!(concat!(env!("OUT_DIR"), "/hello.rs"));
}

pub mod ext_entry {
    include!(concat!(env!("OUT_DIR"), "/ext_entry.rs"));
}

pub mod ext_envelope {
    include!(concat!(env!("OUT_DIR"), "/ext_envelope.rs"));
}

pub mod msg_put {
    include!(concat!(env!("OUT_DIR"), "/msg_put.rs"));
}

pub mod msg_del {
    include!(concat!(env!("OUT_DIR"), "/msg_del.rs"));
}

#[cfg(feature = "codec-keep-alive")]
pub mod keep_alive {
    include!(concat!(env!("OUT_DIR"), "/keep_alive.rs"));
}

pub mod wireexpr_local {
    include!(concat!(env!("OUT_DIR"), "/wireexpr_local.rs"));
}

pub mod wireexpr_nonlocal {
    include!(concat!(env!("OUT_DIR"), "/wireexpr_nonlocal.rs"));
}

pub mod wireexpr {
    include!(concat!(env!("OUT_DIR"), "/wireexpr.rs"));
}

pub mod query {
    include!(concat!(env!("OUT_DIR"), "/query.rs"));
}

pub mod request {
    include!(concat!(env!("OUT_DIR"), "/request.rs"));
}

pub mod push {
    include!(concat!(env!("OUT_DIR"), "/push.rs"));
}

pub mod response_final {
    include!(concat!(env!("OUT_DIR"), "/response_final.rs"));
}

pub mod oam {
    include!(concat!(env!("OUT_DIR"), "/oam.rs"));
}

pub mod interest_body {
    include!(concat!(env!("OUT_DIR"), "/interest_body.rs"));
}

pub mod interest {
    include!(concat!(env!("OUT_DIR"), "/interest.rs"));
}

pub mod reply {
    include!(concat!(env!("OUT_DIR"), "/reply.rs"));
}

pub mod err {
    include!(concat!(env!("OUT_DIR"), "/err.rs"));
}

pub mod response {
    include!(concat!(env!("OUT_DIR"), "/response.rs"));
}

pub mod decl_final {
    include!(concat!(env!("OUT_DIR"), "/decl_final.rs"));
}

pub mod decl_kexpr {
    include!(concat!(env!("OUT_DIR"), "/decl_kexpr.rs"));
}

pub mod undecl_kexpr {
    include!(concat!(env!("OUT_DIR"), "/undecl_kexpr.rs"));
}

pub mod decl_subscriber {
    include!(concat!(env!("OUT_DIR"), "/decl_subscriber.rs"));
}

pub mod decl_queryable {
    include!(concat!(env!("OUT_DIR"), "/decl_queryable.rs"));
}

pub mod decl_token {
    include!(concat!(env!("OUT_DIR"), "/decl_token.rs"));
}

pub mod undecl_subscriber {
    include!(concat!(env!("OUT_DIR"), "/undecl_subscriber.rs"));
}

pub mod undecl_queryable {
    include!(concat!(env!("OUT_DIR"), "/undecl_queryable.rs"));
}

pub mod undecl_token {
    include!(concat!(env!("OUT_DIR"), "/undecl_token.rs"));
}

pub mod declare {
    include!(concat!(env!("OUT_DIR"), "/declare.rs"));
}

#[cfg(test)]
mod ext_envelope_oracle {
    //! R67b: SCXML-comment oracle pinned as cargo test.
    //!
    //! Oracle wire (8 bytes) from sources/codecs/ext_envelope.scxml
    //! line 41-52: 0x01 0x80 0xB1 0x2A 0x52 0x02 0xAB 0xCD.
    //! Layer 3 wire-interop vs zenoh-pico `_z_msg_ext_vec_encode`
    //! is R68 carry (FFI bridge wiring complexity).
    use crate::ext_entry::ExtEntryVariant;
    use crate::ext_envelope::ExtEnvelope;
    use sce_forge_runtime::codec::SceCursor;

    const ORACLE_WIRE: [u8; 8] = [0x01, 0x80, 0xB1, 0x2A, 0x52, 0x02, 0xAB, 0xCD];

    #[test]
    fn decode_oracle_matches_scxml_comment() {
        let mut cursor = SceCursor::new(&ORACLE_WIRE);
        let env = ExtEnvelope::decode(&mut cursor).expect("decode oracle wire");
        assert_eq!(env.header_flags, 0x01);
        assert_eq!(env.extensions.len(), 3);
        assert_eq!(env.extensions[0].header, 0x80);
        assert_eq!(env.extensions[1].header, 0xB1);
        assert_eq!(env.extensions[2].header, 0x52);
        assert!(matches!(
            env.extensions[0].body,
            ExtEntryVariant::CodecZenohExtUnit(_)
        ));
        assert!(matches!(
            env.extensions[1].body,
            ExtEntryVariant::CodecZenohExtZint(_)
        ));
        assert!(matches!(
            env.extensions[2].body,
            ExtEntryVariant::CodecZenohExtZbuf(_)
        ));
    }

    #[test]
    fn round_trip_oracle_byte_equivalent() {
        let mut cursor = SceCursor::new(&ORACLE_WIRE);
        let env = ExtEnvelope::decode(&mut cursor).expect("decode oracle wire");
        let wire = env.encode_to_vec();
        assert_eq!(
            wire, ORACLE_WIRE,
            "encode(decode(oracle)) must round-trip byte-equivalent"
        );
    }
}
