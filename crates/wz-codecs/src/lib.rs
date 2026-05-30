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

/// R311dl — single-source-of-truth wire-protocol MID / flag constants.
///
/// Each constant is a wire-spec-frozen byte from
/// `vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/{transport,network}.h`.
/// Prior to R311dl these constants were duplicated across
/// `wz-runtime-tokio::session_glue::wire_const` and
/// `wz-session-core::network_message::wire_const`; the spec-frozen
/// nature of the bytes made the duplication harmless but the DRY
/// violation was an authoring smell. wz-codecs is the natural home
/// because codec emit/decode is what owns the wire-shape ground truth.
///
/// Both consumer modules now `pub use wz_codecs::wire_const::*;` and
/// keep their local `wire_const` shim purely as a re-export so callsite
/// references (`wire_const::N_MID_PUSH` etc.) stay untouched.
pub mod wire_const {
    /// Transport-message INIT (transport.h:20). Gated on
    /// `codec-init-body`.
    #[cfg(feature = "codec-init-body")]
    pub const T_MID_INIT: u8 = 0x01;
    /// Transport-message OPEN (transport.h:21). Gated on
    /// `codec-open-body`.
    #[cfg(feature = "codec-open-body")]
    pub const T_MID_OPEN: u8 = 0x02;
    /// Transport-message CLOSE (transport.h:22). Gated on `codec-close`.
    #[cfg(feature = "codec-close")]
    pub const T_MID_CLOSE: u8 = 0x03;
    /// Per-session liveness ping (transport.h:24 MID 0x04). Lease-timer
    /// reset on receive.
    #[cfg(feature = "codec-keep-alive")]
    pub const T_MID_KEEP_ALIVE: u8 = 0x04;
    /// Established-session payload carrier (transport.h:79 MID 0x05).
    /// Body = VLE sn + tail payload; optional ext chain between sn and
    /// payload when Z flag set.
    pub const T_MID_FRAME: u8 = 0x05;
    /// Reliable channel discriminator for `T_MID_FRAME` (1 = reliable,
    /// 0 = best-effort) per transport.h:80.
    pub const FLAG_T_FRAME_R: u8 = 0x20;

    /// InitAck discriminator (0 = InitSyn, 1 = InitAck).
    #[cfg(feature = "codec-init-body")]
    pub const FLAG_T_INIT_A: u8 = 0x20;
    /// Size parameters carrier (sn_res + batch_size present).
    #[cfg(feature = "codec-init-body")]
    pub const FLAG_T_INIT_S: u8 = 0x40;

    /// OpenAck discriminator (0 = OpenSyn, 1 = OpenAck).
    #[cfg(feature = "codec-open-body")]
    pub const FLAG_T_OPEN_A: u8 = 0x20;
    /// Lease in seconds (1) vs milliseconds (0).
    #[cfg(feature = "codec-open-body")]
    pub const FLAG_T_OPEN_T: u8 = 0x40;

    /// Session-close vs link-only close.
    #[cfg(feature = "codec-close")]
    pub const FLAG_T_CLOSE_S: u8 = 0x20;

    /// Transport-message ext-chain presence bit shared across every
    /// `T_MID_T_*` header (transport.h:44 `_Z_FLAG_T_Z = 0x80`).
    #[cfg(any(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close",
        feature = "codec-keep-alive",
        feature = "codec-frame"
    ))]
    pub const FLAG_T_Z: u8 = 0x80;

    /// REQUEST envelope MID (network.h:36). Gated on `codec-request`.
    #[cfg(feature = "codec-request")]
    pub const N_MID_REQUEST: u8 = 0x1C;
    /// PUSH envelope MID (network.h:35). Pub/sub data carrier.
    #[cfg(feature = "codec-push")]
    pub const N_MID_PUSH: u8 = 0x1D;
    /// RESPONSE_FINAL marker MID (network.h:38).
    #[cfg(feature = "codec-response-final")]
    pub const N_MID_RESPONSE_FINAL: u8 = 0x1A;
    /// OAM envelope MID (network.h:33). Unconditional — the `oam`
    /// codec module is always present in wz-codecs (no codec-oam
    /// feature exists).
    pub const N_MID_OAM: u8 = 0x1F;
    /// INTEREST envelope MID (network.h:39). Unconditional — the
    /// `interest` codec module is always present in wz-codecs (no
    /// codec-interest feature exists).
    pub const N_MID_INTEREST: u8 = 0x19;
    /// RESPONSE envelope MID (network.h:37). Gated on `codec-response`.
    #[cfg(feature = "codec-response")]
    pub const N_MID_RESPONSE: u8 = 0x1B;
    /// DECLARE envelope MID (network.h:34). Gated on `codec-declare`.
    #[cfg(feature = "codec-declare")]
    pub const N_MID_DECLARE: u8 = 0x1E;

    /// Scouting-message SCOUT MID (transport.h:28 `_Z_MID_SCOUT`). The
    /// scouting MID namespace is disjoint from the transport (`T_MID_*`)
    /// and network (`N_MID_*`) namespaces: scouting frames travel on the
    /// pre-session multicast link, transport/network frames on the
    /// session link, so the byte value 0x01 is context-disambiguated by
    /// which link decoded it (no collision with `T_MID_INIT`). The
    /// scout/hello body codecs carry no header byte (`_z_scout_encode`
    /// ignores it); the scouting-message envelope prepends this MID —
    /// the wz glue prepends it the same way session_glue prepends
    /// `T_MID_INIT`. Gated on `codec-scout`.
    #[cfg(feature = "codec-scout")]
    pub const S_MID_SCOUT: u8 = 0x01;
    /// Scouting-message HELLO MID (transport.h:29 `_Z_MID_HELLO`). See
    /// [`S_MID_SCOUT`] for the disjoint-namespace rationale. Gated on
    /// `codec-hello`.
    #[cfg(feature = "codec-hello")]
    pub const S_MID_HELLO: u8 = 0x02;
    /// Scouting HELLO locators-present flag (`_Z_FLAG_T_HELLO_L`, bit 5).
    /// Set on the HELLO header byte when the Hello body carries a
    /// locator list; the `hello` body codec projects it to its
    /// single-bit `l` flag-input via `(header >> 5) & 1`. Gated on
    /// `codec-hello`.
    #[cfg(feature = "codec-hello")]
    pub const FLAG_S_HELLO_L: u8 = 0x20;
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
