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
//! R311aq — MCU `no_std + alloc` lands ahead of the lwip runtime
//! crate. The crate is `#![no_std]` unconditionally; the `alloc`
//! feature (default-on) pulls `extern crate alloc;` so generated
//! codec code referencing `alloc::vec::Vec` / `alloc::string::String`
//! resolves. `sce-forge-runtime` is imported `default-features = false`
//! with the `alloc` feature forwarded, so the baseline `no_std`
//! contract holds. Each `pub mod` block re-exposes the alloc-prelude
//! items (`String` / `ToString`) that the generated code references
//! unqualified — `Vec` already arrives via a codegen-emitted
//! `use alloc::vec::Vec;` at the top of each generated file but
//! `String` / `ToString` do not, so the host scope supplies them
//! (standard alloc-consumer pattern; not a codegen edit). Hosted
//! callers (wz-runtime-tokio + wz-ap-demo) see no behavioural
//! delta — they already pulled the default `alloc` feature; MCU
//! cross-compile lanes (Layer G.3) now build the same source against
//! `thumbv7em-none-eabihf` and the wider ARMv7-E / ARMv8-M / RISC-V
//! IMAC target catalog.
//!
//! Clippy policy: the entire crate body is sce-codegen output —
//! clippy lints on the generated code's style (unnecessary casts,
//! redundant binding patterns, etc.) are SCE template authoring
//! concerns, not consumer-tunable. `#![allow(clippy::all)]` here
//! silences clippy for the include!()-pasted modules while the
//! workspace's rustc `warnings = "deny"` policy stays in force
//! (rustc warnings ARE consumer-actionable; clippy style nits on
//! generated code are not).

#![no_std]
#![allow(clippy::all)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(test)]
extern crate std;

// Re-exposes the alloc-prelude items the SCE codegen emits without
// fully-qualifying. Invoked at the head of every `pub mod` block so
// the `include!()`-pasted generated code resolves `String` and
// `ToString`. `Vec` is omitted because the codegen already emits its
// own `use alloc::vec::Vec;`; `unused_imports` is allowed because
// codec modules that do not reference `String` (e.g. `timestamp`,
// `encoding`) would otherwise trip the workspace `warnings = "deny"`
// policy.
macro_rules! codec_alloc_prelude {
    () => {
        #[cfg(feature = "alloc")]
        #[allow(unused_imports)]
        use alloc::string::{String, ToString};
    };
}

// R311br — multi-module same-feature gating helper. Used by the
// codec-declare (10 modules), codec-response (3 modules), and
// codec-request (2 modules) families so the same `#[cfg(feature =
// "codec-X")]` attribute is authored once instead of repeated on
// each sibling `pub mod` block. Reduces the per-file cfg-site count
// from 28 -> 14 (counted by `grep 'cfg(feature' src/lib.rs`),
// closing the R311bp 부채 #7 line item.
//
// The expansion is per-module verbatim — each entry still gets its
// own `pub mod $name { codec_alloc_prelude!(); include!(...) }`
// block with the same `#[cfg(feature = $feature)]` attribute the
// non-grouped sites carry. Cargo feature behaviour is byte-
// identical; the audit-trace cfg-site count drops because the
// attribute is now authored inside the macro definition (one
// `cfg(feature = ...)` line for the macro itself) rather than
// repeated at every sibling module.
macro_rules! codec_group {
    ($feature:literal, [ $( ($name:ident, $file:literal) ),+ $(,)? ]) => {
        $(
            #[cfg(feature = $feature)]
            pub mod $name {
                codec_alloc_prelude!();
                include!(concat!(env!("OUT_DIR"), "/", $file));
            }
        )+
    };
}

pub mod timestamp {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/timestamp.rs"));
}

pub mod encoding {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/encoding.rs"));
}

pub mod ext_unit {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/ext_unit.rs"));
}

pub mod ext_zint {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/ext_zint.rs"));
}

pub mod ext_zbuf {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/ext_zbuf.rs"));
}

pub mod stream_envelope {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/stream_envelope.rs"));
}

#[cfg(feature = "codec-close")]
pub mod close {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/close.rs"));
}

#[cfg(feature = "codec-frame")]
pub mod frame {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/frame.rs"));
}

#[cfg(feature = "codec-fragment")]
pub mod fragment {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/fragment.rs"));
}

#[cfg(feature = "codec-scout")]
pub mod scout {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/scout.rs"));
}

#[cfg(feature = "codec-init-body")]
pub mod init_body {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/init_body.rs"));
}

#[cfg(feature = "codec-open-body")]
pub mod open_body {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/open_body.rs"));
}

#[cfg(feature = "codec-join")]
pub mod join {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/join.rs"));
}

pub mod locator {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/locator.rs"));
}

#[cfg(feature = "codec-hello")]
pub mod hello {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/hello.rs"));
}

pub mod ext_entry {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/ext_entry.rs"));
}

pub mod ext_envelope {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/ext_envelope.rs"));
}

pub mod msg_put {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/msg_put.rs"));
}

pub mod msg_del {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/msg_del.rs"));
}

#[cfg(feature = "codec-keep-alive")]
pub mod keep_alive {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/keep_alive.rs"));
}

pub mod wireexpr_local {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/wireexpr_local.rs"));
}

pub mod wireexpr_nonlocal {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/wireexpr_nonlocal.rs"));
}

pub mod wireexpr {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/wireexpr.rs"));
}

codec_group!(
    "codec-request",
    [(query, "query.rs"), (request, "request.rs"),]
);

#[cfg(feature = "codec-push")]
pub mod push {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/push.rs"));
}

#[cfg(feature = "codec-response-final")]
pub mod response_final {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/response_final.rs"));
}

pub mod oam {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/oam.rs"));
}

pub mod interest_body {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/interest_body.rs"));
}

pub mod interest {
    codec_alloc_prelude!();
    include!(concat!(env!("OUT_DIR"), "/interest.rs"));
}

codec_group!(
    "codec-response",
    [
        (reply, "reply.rs"),
        (err, "err.rs"),
        (response, "response.rs"),
    ]
);

codec_group!(
    "codec-declare",
    [
        (decl_final, "decl_final.rs"),
        (decl_kexpr, "decl_kexpr.rs"),
        (undecl_kexpr, "undecl_kexpr.rs"),
        (decl_subscriber, "decl_subscriber.rs"),
        (decl_queryable, "decl_queryable.rs"),
        (decl_token, "decl_token.rs"),
        (undecl_subscriber, "undecl_subscriber.rs"),
        (undecl_queryable, "undecl_queryable.rs"),
        (undecl_token, "undecl_token.rs"),
        (declare, "declare.rs"),
    ]
);

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
