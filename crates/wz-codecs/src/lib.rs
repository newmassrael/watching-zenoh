// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Generated wire codecs for the watching-zenoh Phase B5 codec set.
//!
//! Each `mod <stem>` block `include!`s the sce-codegen Rust output for
//! the matching `sources/codecs/<stem>.scxml` file. R311y22: that output
//! is COMMITTED under `out/wz-codecs/<stem>.rs` (resolved via
//! `env!("CARGO_MANIFEST_DIR")`), so this crate has no build script and
//! pulls no libxml2/SCE toolchain. `xtask` (scripts/regen-codegen.sh)
//! regenerates the committed files from the SCXML SSOT and the CI
//! regen-diff lane enforces committed == regenerated. Manual edits to
//! `out/**` are forbidden.
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

// R311tf — the typed `WhatAmI` node role, the SSOT for the role byte across the
// session layer, the routing graph, and the runtime driver. Hand-written (not
// codegen), so it sits outside the `#![allow(clippy::all)]` intent — but the
// crate-level allow still covers it; rustc `warnings = "deny"` keeps it honest.
pub mod whatami;

/// R311y640 (§1.1w) — the runtime primitives a consumer needs to DRIVE the
/// codecs this crate exposes, re-exported so driving one does not require a
/// second dependency edge on the SCE runtime.
///
/// Every `decode` in this crate takes an `SceCursor` and every owned byte field
/// is an `SceByteBuf`, so a caller that holds bytes and wants a typed value
/// already needs both. `wz-capture` hit exactly that wall reading a `Query`'s
/// value out of its ext body: the bytes were in hand and the codec that reads
/// them was one module away, but the cursor to feed it was not nameable. Naming
/// the two here rather than adding `sce-forge-runtime` to each consumer's
/// manifest keeps the codec ABI and the means of driving it in ONE place —
/// which is also the version the codecs were generated against, and so cannot
/// drift from them the way an independently-pinned dependency could.
///
/// Deliberately NARROW: the four names that read or write a codec's own bytes,
/// not the runtime. A consumer needing more of it has a different relationship
/// with SCE than "reads and writes the wire", and should say so in its own
/// manifest.
pub use sce_forge_runtime::codec::{SceByteBuf, SceCursor, SceSink};

/// The `alloc`-only append sink, beside the three above for the same reason:
/// a caller assembling a nested body (an ext whose payload is itself a
/// length-prefixed field) has to WRITE a VLE, and hand-rolling base-128 at the
/// call site is the copy that drifts from the reader it must round-trip with.
#[cfg(feature = "alloc")]
pub use sce_forge_runtime::codec::VecSink;

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
                include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../out/wz-codecs/", $file));
            }
        )+
    };
}

pub mod timestamp {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/timestamp.rs"
    ));
}

pub mod encoding {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/encoding.rs"
    ));
}

pub mod ext_unit {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/ext_unit.rs"
    ));
}

pub mod ext_zint {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/ext_zint.rs"
    ));
}

pub mod ext_zbuf {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/ext_zbuf.rs"
    ));
}

// R311ns — zenoh-pico SERIAL-link frame CRC32 (algorithm kind). The
// `crc32` SCXML emits a free function (not a codec struct); the
// `serial_envelope` codec carries its 4-byte LE result as a field.
#[cfg(feature = "codec-serial")]
pub mod crc32 {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/crc32.rs"
    ));
}

// R311ns — serial-link pre-COBS frame envelope (codec kind):
// [header|len(2 LE)|payload(len)|crc32(4 LE)]. First wz codec with a
// fixed field after a length-ref field; requires SCE positional-
// validity codec path selection (SCE 57e06f1e9).
#[cfg(feature = "codec-serial")]
pub mod serial_envelope {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/serial_envelope.rs"
    ));
}

// R311ns — serial-link COBS stuffing/destuffing (algorithm kind,
// byte-buffer-build). `cobs_encode`/`cobs_decode` are free functions
// returning `Result<SceBytes<N>, CapacityExceeded>`. Mirrors pico
// _z_cobs_encode / _z_cobs_decode (encoding.c).
#[cfg(feature = "codec-serial")]
pub mod cobs_encode {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/cobs_encode.rs"
    ));
}

#[cfg(feature = "codec-serial")]
pub mod cobs_decode {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/cobs_decode.rs"
    ));
}

pub mod stream_envelope {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/stream_envelope.rs"
    ));
}

#[cfg(feature = "codec-close")]
pub mod close {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/close.rs"
    ));
}

#[cfg(feature = "codec-frame")]
pub mod frame {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/frame.rs"
    ));
}

#[cfg(feature = "codec-fragment")]
pub mod fragment {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/fragment.rs"
    ));
}

#[cfg(feature = "codec-scout")]
pub mod scout {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/scout.rs"
    ));
}

#[cfg(feature = "codec-init-body")]
pub mod init_body {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/init_body.rs"
    ));
}

#[cfg(feature = "codec-open-body")]
pub mod open_body {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/open_body.rs"
    ));
}

#[cfg(feature = "codec-join")]
pub mod join {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/join.rs"
    ));
}

pub mod locator {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/locator.rs"
    ));

    /// The wire width of one locator string — the `LocatorOwned::locator`
    /// field's `SceString<N>` capacity (`sources/codecs/locator.scxml`
    /// `sce:max-size`). The SSOT for "how long a locator may be on the wire",
    /// so a producer (e.g. the linkstate graph) caps against ONE value tied to
    /// this crate's generated type rather than hand-copying the literal — a
    /// no-alloc receiver decodes into exactly `heapless::String<N>`, so a
    /// longer locator would fail its decode. Keep in lockstep with the SCXML
    /// `sce:max-size` until codegen can emit it directly.
    pub const MAX_LOCATOR_LEN: usize = 128;

    /// The maximum number of locators one node advertises — the linkstate
    /// `locators` list `sce:max-count` (`sources/codecs/linkstate.scxml`). A
    /// producer caps the list against this so a no-alloc receiver's bounded
    /// repeat-decode never overflows.
    pub const MAX_LOCATORS_PER_NODE: usize = 64;
}

#[cfg(feature = "codec-hello")]
pub mod hello {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/hello.rs"
    ));
}

pub mod ext_entry {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/ext_entry.rs"
    ));
}

pub mod ext_envelope {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/ext_envelope.rs"
    ));
}

pub mod msg_put {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/msg_put.rs"
    ));
}

pub mod msg_del {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/msg_del.rs"
    ));
}

#[cfg(feature = "codec-keep-alive")]
pub mod keep_alive {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/keep_alive.rs"
    ));
}

pub mod wireexpr_local {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/wireexpr_local.rs"
    ));
}

pub mod wireexpr_nonlocal {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/wireexpr_nonlocal.rs"
    ));
}

pub mod wireexpr {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/wireexpr.rs"
    ));
}

codec_group!(
    "codec-request",
    [(query, "query.rs"), (request, "request.rs"),]
);

#[cfg(feature = "codec-push")]
pub mod push {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/push.rs"
    ));
}

#[cfg(feature = "codec-response-final")]
pub mod response_final {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/response_final.rs"
    ));
}

pub mod oam {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/oam.rs"
    ));
}

pub mod interest_body {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/interest_body.rs"
    ));
}

pub mod interest {
    codec_alloc_prelude!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-codecs/interest.rs"
    ));
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

// R311qm — P4 linkstate-peer topology codecs. `linkstate_link` is the
// bare-VLE-u64 element wrapper for the `links` repeat (SCE repeats only
// codec types, not scalars); `linkstate` is one LinkState entry
// (options flags + zid/whatami/locators/links); `linkstate_list` is the
// flooded LinkStateList batch. The generated `linkstate` module
// references `super::locator` (always-present top-level mod) and
// `super::linkstate_link`; all three sit at crate root so the codegen
// `super::X` lookups resolve. AP/full-node routing feature — gated off
// the MCU footprint.
codec_group!(
    "codec-linkstate",
    [
        (linkstate_link, "linkstate_link.rs"),
        (linkstate_weight, "linkstate_weight.rs"),
        (linkstate, "linkstate.rs"),
        (linkstate_list, "linkstate_list.rs"),
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
/// R311y617 — the zenoh ENCODING id table, hoisted from `wz-capi-core` so a
/// `no_std` consumer can name the encoding a Put declares. See the module's own
/// header for why a second transcription was not an option.
#[path = "encoding_ids.rs"]
pub mod encoding_ids;

pub mod wire_const {
    /// Transport-message OAM (`zenoh-protocol/src/transport/mod.rs:54`
    /// `id::OAM`). Ungated with `T_MID_INIT` below and for the same reason:
    /// the bare MID is wire-spec ground truth, and a reader that does not
    /// know 0x00 is a MID cannot tell an operations-and-maintenance message
    /// from an unrecognised one.
    ///
    /// Its body is NOT shaped like the other transport MIDs': header bits
    /// 5..6 carry the body's ENCODING (`common/extension.rs:64-67`
    /// `iext::ENC_*`) where the others carry flags, and the ext chain is
    /// written BEFORE the body rather than after it
    /// (`zenoh-codec/src/transport/oam.rs`, header -> id -> extensions ->
    /// payload).
    pub const T_MID_OAM: u8 = 0x00;
    /// Transport OAM's ENCODING field in its transport-header position:
    /// `iext::ENC_MASK` (`common/extension.rs:67`), bits 5..6, selecting the
    /// body's shape (Unit / Z64 / ZBuf, with 0b11 reserved) where every other
    /// transport MID spends those two bits on flags.
    ///
    /// Ungated with [`T_MID_OAM`] above and for the same reason. Unlike the
    /// `FLAG_T_*` consts below it has no GATED sibling to be checked against,
    /// because no `codec-*` feature decodes an OAM body — the arm that reads
    /// it in `wz_session_core::inbound` carries no feature at all.
    ///
    /// NOT in [`transport_flag_mask`]: that table answers where a lost stream
    /// may RESUME, and `oam_is_a_transport_mid_this_gate_still_refuses` is
    /// where the measured reason 0x00 is kept out of it lives. A decoder that
    /// already knows it is looking at an OAM reads the field with this mask.
    pub const FLAG_T_OAM_ENC: u8 = 0x60;
    /// Transport-message INIT (transport.h:20).
    ///
    /// R311y630 — UNGATED, on R311kx's reasoning for `T_MID_KEEP_ALIVE` below
    /// rather than a new one: the bare MID is wire-spec ground truth, an unused
    /// `pub const` is warning-free, and a SECOND independent axis now consumes
    /// it. That axis is `wz_session_core::ext_admit`, which judges which
    /// extension chains a participant of each transport message may accept —
    /// a question about the wire that does not depend on whether THIS build
    /// can decode that message's body, and a module that must therefore be
    /// unconditional. Gating the id made an unconditional consumer impossible
    /// and was caught by the isolated-crate lanes, not by any workspace build.
    pub const T_MID_INIT: u8 = 0x01;
    /// Transport-message OPEN (transport.h:21). Ungated with `T_MID_INIT`
    /// above and for the same reason.
    pub const T_MID_OPEN: u8 = 0x02;
    /// Transport-message CLOSE (transport.h:22). Ungated with `T_MID_INIT`
    /// above and for the same reason.
    pub const T_MID_CLOSE: u8 = 0x03;
    /// Per-session liveness ping (transport.h:24 MID 0x04). Lease-timer
    /// reset on receive. Ungated since R311kx (was `codec-keep-alive`):
    /// two independent axes consume it — the codec-keep-alive RX parse
    /// arm AND the transport-keepalive TX emitter
    /// (wz-session-core::handshake_encode::encode_keep_alive) — and the
    /// bare MID is wire-spec ground truth like the ungated `T_MID_FRAME`
    /// / `T_MID_FRAGMENT` below; an unused pub const is warning-free.
    pub const T_MID_KEEP_ALIVE: u8 = 0x04;
    /// Established-session payload carrier (transport.h:79 MID 0x05).
    /// Body = VLE sn + tail payload; optional ext chain between sn and
    /// payload when Z flag set.
    pub const T_MID_FRAME: u8 = 0x05;
    /// Reliable channel discriminator for `T_MID_FRAME` (1 = reliable,
    /// 0 = best-effort) per transport.h:80.
    pub const FLAG_T_FRAME_R: u8 = 0x20;

    /// Fragmented established-session payload carrier (transport.h:38 MID
    /// 0x06). Body = VLE sn + tail payload (the same body codec as
    /// `T_MID_FRAME`, `sources/codecs/fragment.scxml`); the per-fragment R
    /// (reliable) and M (more) discriminators live in the transport header
    /// byte, not the body. Header layout `|Z|M|R| FRAGMENT|`
    /// (transport.h:485). Reassembled fragments re-enter the `T_MID_FRAME`
    /// decode path as a complete NetworkMessage batch.
    pub const T_MID_FRAGMENT: u8 = 0x06;
    /// Reliable channel discriminator for `T_MID_FRAGMENT` (1 = reliable,
    /// 0 = best-effort) per transport.h:86 (`_Z_FLAG_T_FRAGMENT_R`, 1<<5).
    /// Part of the reassembly chain key alongside the peer ZID.
    pub const FLAG_T_FRAGMENT_R: u8 = 0x20;
    /// More-fragments discriminator for `T_MID_FRAGMENT` (1 = more
    /// fragments follow, 0 = final fragment) per transport.h:87
    /// (`_Z_FLAG_T_FRAGMENT_M`, 1<<6). The reassembly slot FSM guards
    /// Continue-vs-Final on this bit.
    pub const FLAG_T_FRAGMENT_M: u8 = 0x40;

    /// Multicast transport JOIN message id (`_Z_MID_T_JOIN`, transport.h:39).
    /// JOIN is the handshake-FREE multicast transport's peer-announcement
    /// beacon (the multicast analogue of INIT+OPEN): a peer periodically
    /// multicasts a JOIN carrying its zid + lease so group members learn of
    /// it (session-fsm §3.1/§3.2). Distinct namespace from the scouting
    /// `S_MID_*` ids; the `join` body codec (`sources/codecs/join.scxml`)
    /// omits this header byte, so the multicast glue prepends it (mirror of
    /// the session_glue `T_MID_*` framing).
    pub const T_MID_JOIN: u8 = 0x07;
    /// Size-parameters carrier for `T_MID_JOIN` (sn_res + batch_size
    /// present) per transport.h (`_Z_FLAG_T_JOIN_S`, 1<<6). The `join`
    /// codec gates its optional `sn_res` / `batch_size` fields on this flag
    /// (decode `s & 0x01`); a minimal JOIN (no resolution negotiation)
    /// clears it.
    #[cfg(feature = "codec-join")]
    pub const FLAG_T_JOIN_S: u8 = 0x40;
    /// Lease-unit selector for `T_MID_JOIN` per transport.h:60
    /// (`_Z_FLAG_T_JOIN_T`, 1<<5): 1 = the lease VLE is in SECONDS
    /// (zenoh-pico `_z_t_msg_make_join` sets it for every whole-second
    /// lease, so the default 10000ms rides the wire as 10), 0 =
    /// milliseconds. The `join` body codec carries the raw VLE; the
    /// multicast glue owns the unit projection (encode divides, decode
    /// multiplies — codec/transport.c:59-62 / 161-164).
    #[cfg(feature = "codec-join")]
    pub const FLAG_T_JOIN_T: u8 = 0x20;

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

    /// Ext-chain presence bit, shared across every `T_MID_T_*` header
    /// (transport.h:44 `_Z_FLAG_T_Z = 0x80`) AND the two SCOUTING headers.
    ///
    /// R311y607 — the name says `T` and the bit does not: pico spells it
    /// `_Z_MSG_EXT_FLAG_Z` at the ext layer and tests it on a scouting header
    /// with the same value (`_z_scouting_message_decode_na`, message.c:756).
    /// The name is kept rather than split, because one bit with two names is
    /// how a reader ends up believing there are two bits.
    #[cfg(any(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close",
        feature = "codec-keep-alive",
        feature = "codec-frame",
        // R311y605 — JOIN carries a Z-gated chain too (the QoS-SN
        // advertisement), and its readers reach the bit through this name. The
        // doc above says "shared across every `T_MID_T_*` header" while the
        // predicate listed five of six; a `--features codec-join` subset build
        // is what made the sixth visible.
        feature = "codec-join",
        // R311y607 — and the SCOUTING pair, the same way: `--features
        // alloc,codec-scout` is the shape with no sibling to bring the bit in,
        // and it is the third time this predicate has been short of the claim
        // written above it.
        feature = "codec-scout",
        feature = "codec-hello"
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
    /// Network-MID ext-chain presence bit, shared across every `N_MID_*`
    /// header (network.h `_Z_FLAG_N_Z = 0x80`) — the network-message
    /// sibling of [`FLAG_T_Z`]. Set when a Z-gated extension chain
    /// follows the envelope header (e.g. the OAM qos extension). Bare
    /// `0x80` literals on network headers should reference this.
    pub const FLAG_N_Z: u8 = 0x80;
    /// The `id` a conforming peer computes from an OAM's id field.
    ///
    /// `OamId` is a `u16` in BOTH namespaces — `zenoh-protocol/src/network/
    /// oam.rs:16` and `zenoh-protocol/src/transport/oam.rs:16` each declare
    /// `pub type OamId = u16;` — and both codecs reach it through the plain
    /// `Zenoh080`, whose integer derive is `let x: u64 = self.read(reader)?;
    /// Ok(x as $uint)` (`zenoh-codec/src/core/zint.rs`, `uint_impl!(u16)`).
    /// It TRUNCATES. The codec that refuses an out-of-range zint is
    /// `Zenoh080Bounded<u16>`, a different codec, and neither OAM arm selects
    /// it.
    ///
    /// So the field has TWO widths and they are not the same fact: its WIRE
    /// width is a full zint, and its VALUE width is 16 bits. A reader that
    /// collapses them is wrong whichever way it leans — read narrow and it
    /// refuses messages the network delivers (halting a batch walk on a
    /// message stock zenoh reads to the end), read wide and it reports an id
    /// no peer acts on, including missing `OAM_LINKSTATE_ID` when the low
    /// 16 bits are exactly that. R311y879 measured both directions; before
    /// it, wz held one of each.
    ///
    /// Ungated for the same reason `N_MID_OAM` and `T_MID_OAM` are: neither
    /// OAM decode arm is behind a `codec-*` feature.
    pub const fn oam_id_from_wire(raw: u64) -> u16 {
        raw as u16
    }
    /// `oam::id::OAM_LINKSTATE` (zenoh `commons/zenoh-protocol/src/
    /// network/oam.rs:27`) — the OAM message id whose ZBuf body carries a
    /// linkstate-peer topology `LinkStateList`.
    ///
    /// `u16`-typed because that is the width the VALUE has
    /// ([`oam_id_from_wire`]); the generated `Oam.id` field is a VLE `u64`
    /// because that is the width the WIRE has. Compare against a decoded id
    /// by truncating the id, never by widening this constant — the two are
    /// not interchangeable, and calling the wide read "a superset" (as this
    /// doc did until R311y879) is what let an id of `0x1_0001` be reported as
    /// a non-linkstate OAM while every conforming peer walked its body as a
    /// topology advertisement. Gated on `codec-linkstate`.
    #[cfg(feature = "codec-linkstate")]
    pub const OAM_LINKSTATE_ID: u16 = 0x0001;
    /// INTEREST envelope MID (network.h:39). Unconditional — the
    /// `interest` codec module is always present in wz-codecs (no
    /// codec-interest feature exists).
    pub const N_MID_INTEREST: u8 = 0x19;
    /// RESPONSE envelope MID (network.h:37). Gated on `codec-response`.
    #[cfg(feature = "codec-response")]
    pub const N_MID_RESPONSE: u8 = 0x1B;
    /// R311y615 (§4.10) — `N` flag on a NETWORK envelope header
    /// (network.h `_Z_FLAG_N_*_N`, bit 5): the message's wireexpr carries an
    /// inline keyexpr suffix.
    ///
    /// Same bit value as [`FLAG_D_N`] and named separately for the same reason
    /// that one is: the two live in different header namespaces, and a reader
    /// who sees a declaration-body constant on a `Push` header has been told
    /// something false about which table to consult. It exists at all because
    /// every construction site was writing the literal `0x20` — the MID beside
    /// it comes from the codec's generated `Default`, so the flag was the one
    /// byte in the header that no name covered.
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response"
    ))]
    pub const FLAG_N_N: u8 = 0x20;
    /// `T` on a zenoh-message PUT header (`sources/codecs/msg_put.scxml:104`):
    /// a timestamp follows. R311y617 — named for the same reason
    /// [`FLAG_N_N`] was: the three PUT body flags were every fixture's
    /// literals, and a fixture that spells `0x40` when it means "an encoding
    /// follows" is a byte string wearing a struct. The R311y617 payload
    /// sub-decoder's own first fixture set the WRONG one of these three and
    /// the record stopped decoding — which is exactly the failure a name
    /// prevents and a literal invites.
    pub const FLAG_Z_PUT_T: u8 = 0x20;
    /// `E` on a zenoh-message PUT header (`msg_put.scxml:105`): an encoding
    /// follows. See [`FLAG_Z_PUT_T`].
    pub const FLAG_Z_PUT_E: u8 = 0x40;
    /// `Z` on a zenoh-message PUT header (`msg_put.scxml:106`): an extension
    /// chain follows. See [`FLAG_Z_PUT_T`].
    pub const FLAG_Z_PUT_Z: u8 = 0x80;
    /// `E` on a zenoh-message ERR header (`out/wz-codecs/err.rs:94`): an
    /// encoding follows.
    ///
    /// R311y622 (§1.1s) — its own name rather than a reuse of
    /// [`FLAG_Z_PUT_E`], which happens to be the same byte. The two are flags
    /// on DIFFERENT headers, and a fixture that reached for the PUT constant to
    /// set a bit on an ERR would be asserting a coincidence: nothing in either
    /// wire spec ties them, and the day one moves the reuse becomes a silent
    /// misread rather than a compile error.
    #[cfg(feature = "codec-response")]
    pub const FLAG_Z_ERR_E: u8 = 0x40;
    /// `Z` on a zenoh-message ERR header (`sources/codecs/err.scxml:74`): an
    /// extension chain follows.
    ///
    /// R311y639 (§4.30) — added for the same reason [`FLAG_Z_ERR_E`] carries
    /// its own name rather than borrowing the PUT one, and the round that
    /// needed it is the argument: an `Err` declares the shm ext in its own
    /// right (`zenoh-protocol-1.5.0/src/zenoh/err.rs:49-68`,
    /// `zextunit!(0x2, true)`), so a fixture must be able to hang a chain on an
    /// ERR header without spelling a PUT constant at it.
    #[cfg(feature = "codec-response")]
    pub const FLAG_Z_ERR_Z: u8 = 0x80;
    /// DECLARE envelope MID (network.h:34). Gated on `codec-declare`.
    #[cfg(feature = "codec-declare")]
    pub const N_MID_DECLARE: u8 = 0x1E;
    /// `I` flag on the outer DECLARE header (network.h:62 `_Z_DECLARE_ID`):
    /// when set, an `interest_id` VLE follows the header — the DECLARE is a
    /// reply to a pending Interest (R283 liveliness-query reply) rather
    /// than an unsolicited declaration. Gated on `codec-declare`.
    #[cfg(feature = "codec-declare")]
    pub const FLAG_N_DECLARE_I: u8 = 0x20;

    // ─── inner declaration-body MIDs (declarations.h:30-39) ───
    //
    // The body kind of a DECLARE(0x1E) message. Disjoint sub-namespace
    // from the outer T_/N_/S_ MIDs — disambiguated by being read after the
    // DECLARE envelope header. Centralised here so every `build_declare_*`
    // / `build_undeclare_*` constructor (and the R283 interest-response
    // builder in wz-session-core::declare::local_token) references one
    // source instead of a per-site literal.
    /// `_Z_DECL_KEXPR_MID` — declare a keyexpr-id mapping.
    #[cfg(feature = "codec-declare")]
    pub const D_MID_KEXPR: u8 = 0x00;
    /// `_Z_UNDECL_KEXPR_MID` — retract a keyexpr-id mapping.
    #[cfg(feature = "codec-declare")]
    pub const D_MID_UNDECL_KEXPR: u8 = 0x01;
    /// `_Z_DECL_SUBSCRIBER_MID`.
    #[cfg(feature = "codec-declare")]
    pub const D_MID_SUBSCRIBER: u8 = 0x02;
    /// `_Z_UNDECL_SUBSCRIBER_MID`.
    #[cfg(feature = "codec-declare")]
    pub const D_MID_UNDECL_SUBSCRIBER: u8 = 0x03;
    /// `_Z_DECL_QUERYABLE_MID`.
    #[cfg(feature = "codec-declare")]
    pub const D_MID_QUERYABLE: u8 = 0x04;
    /// `_Z_UNDECL_QUERYABLE_MID`.
    #[cfg(feature = "codec-declare")]
    pub const D_MID_UNDECL_QUERYABLE: u8 = 0x05;
    /// `_Z_DECL_TOKEN_MID`.
    #[cfg(feature = "codec-declare")]
    pub const D_MID_TOKEN: u8 = 0x06;
    /// `_Z_UNDECL_TOKEN_MID`.
    #[cfg(feature = "codec-declare")]
    pub const D_MID_UNDECL_TOKEN: u8 = 0x07;
    /// `_Z_DECL_FINAL_MID` (declarations.c:131) — single-byte terminator
    /// of an Interest-driven declaration batch.
    #[cfg(feature = "codec-declare")]
    pub const D_MID_FINAL: u8 = 0x1A;
    /// `N` flag on a declaration-body header (declarations.h) — an inline
    /// keyexpr suffix follows. Same bit value as several other `*_N`
    /// flags but named per its declaration-body context.
    #[cfg(feature = "codec-declare")]
    pub const FLAG_D_N: u8 = 0x20;

    /// Scouting-message SCOUT MID (transport.h:28 `_Z_MID_SCOUT`). The
    /// scouting MID namespace is disjoint from the transport (`T_MID_*`)
    /// and network (`N_MID_*`) namespaces: scouting frames travel on the
    /// pre-session multicast link, transport/network frames on the
    /// session link, so the byte value 0x01 is context-disambiguated by
    /// which link decoded it (no collision with `T_MID_INIT`). The
    /// scout/hello body codecs carry no header byte (`_z_scout_encode`
    /// ignores it); the scouting-message envelope prepends this MID —
    /// the wz glue prepends it the same way session_glue prepends
    /// `T_MID_INIT`.
    ///
    /// R311y630d — UNGATED, with `T_MID_INIT` and for the same reason: the
    /// bare MID is wire-spec ground truth and `wz_session_core::ext_admit` is
    /// an unconditional consumer. It is also the id whose ambiguity that
    /// module now makes structural — the note above says `0x01` is
    /// "context-disambiguated by which link decoded it", and
    /// `ExtCarrier::Scouting` is that context turned into a type rather than
    /// left as a convention a caller has to remember.
    pub const S_MID_SCOUT: u8 = 0x01;
    /// Scouting-message HELLO MID (transport.h:29 `_Z_MID_HELLO`). See
    /// [`S_MID_SCOUT`] for the disjoint-namespace rationale, and for why it
    /// is ungated.
    pub const S_MID_HELLO: u8 = 0x02;
    /// Scouting HELLO locators-present flag (`_Z_FLAG_T_HELLO_L`, bit 5).
    /// Set on the HELLO header byte when the Hello body carries a
    /// locator list; the `hello` body codec projects it to its
    /// single-bit `l` flag-input via `(header >> 5) & 1`. Gated on
    /// `codec-hello`.
    #[cfg(feature = "codec-hello")]
    pub const FLAG_S_HELLO_L: u8 = 0x20;

    /// R311y609 — the TRANSPORT HEADER SPACE: which MIDs the transport wire
    /// format defines, and which flag bits each of them may legally carry
    /// (the shared `Z` bit included). `None` = no transport message has this
    /// MID at all.
    ///
    /// # Why this one is UNGATED
    ///
    /// Same ground as [`T_MID_FRAME`] and [`T_MID_KEEP_ALIVE`]: it is
    /// wire-spec ground truth. Its consumer — a passive observer asking "could
    /// this byte have been produced by a zenoh transport header"
    /// (`wz-session-core::passive`, stream resynchronisation) — is asking
    /// about the WIRE, not about which codecs the reading build compiled. A
    /// gated answer would call a message the build merely cannot DECODE "not a
    /// transport header", which is the R311y605 Unknown-JOIN defect one layer
    /// down: a feature-poor observer would resynchronise onto a different
    /// boundary than a feature-rich one over the same bytes.
    ///
    /// The literals below are the same bytes the gated `T_MID_*` / `FLAG_T_*`
    /// consts above spell. Two spellings on purpose, and
    /// `transport_header_space_agrees_with_the_gated_consts` (an all-features
    /// test) is what keeps them equal — the alternative, ungating eleven
    /// consts, would move a feature boundary the codec census gates measure.
    pub const fn transport_flag_mask(mid: u8) -> Option<u8> {
        // The ext-chain bit rides every transport header (`FLAG_T_Z`).
        const Z: u8 = 0x80;
        // OAM (`0x00`) is DELIBERATELY ABSENT, and it is the one MID in the
        // transport space that is. See
        // `oam_is_a_transport_mid_this_gate_still_refuses` below: this
        // predicate answers "may a stream reader RESUME here", not "is this a
        // transport MID", and admitting 0x00 was measured to cost the resync
        // scan a third of what it recovers.
        match mid {
            0x01 => Some(Z | 0x20 | 0x40), // INIT: A | S
            0x02 => Some(Z | 0x20 | 0x40), // OPEN: A | T
            0x03 => Some(Z | 0x20),        // CLOSE: S
            0x04 => Some(Z),               // KEEP_ALIVE: no flags of its own
            0x05 => Some(Z | 0x20),        // FRAME: R
            0x06 => Some(Z | 0x20 | 0x40), // FRAGMENT: R | M
            0x07 => Some(Z | 0x20 | 0x40), // JOIN: T | S
            _ => None,
        }
    }

    /// R311y609 — could `header` be the first byte of a transport message?
    ///
    /// True for 42 of the 256 byte values (`transport_header_space_is_42_of_256`
    /// counts them), which is what makes a chain of these a usable
    /// resynchronisation signal: the MID must be one of seven, AND every flag
    /// bit it sets must be one that MID defines.
    ///
    /// A byte failing either test is one a stream reader will not RESUME on.
    /// That is a NARROWER claim than "no conforming sender wrote it", and the
    /// difference has a name: `T_MID_OAM` (0x00) is a conforming header this
    /// predicate refuses anyway. See
    /// `oam_is_a_transport_mid_this_gate_still_refuses`.
    ///
    /// Says nothing about the BODY — a credible header with a corrupt body is
    /// still a decode error, reported as one.
    pub const fn is_credible_transport_header(header: u8) -> bool {
        match transport_flag_mask(header & 0x1F) {
            Some(defined) => header & 0xE0 & !defined == 0,
            None => false,
        }
    }

    /// R311y611 — the flag bits `header` sets that its own MID does not define,
    /// or `None` when the MID is not a transport MID at all.
    ///
    /// THE WEAKER QUESTION, and a reader needs both. `is_credible_transport_header`
    /// above answers "could a conforming sender have written this byte", which
    /// is the right test for a SCAN over bytes whose framing is unknown:
    /// strictness is free there, and it is what makes a chain of these
    /// discriminating.
    ///
    /// It is the wrong test at a boundary the reader is already synchronised
    /// to. Fourteen byte values — every known MID with a reserved bit set — are
    /// refused by it and NAMED by `parse_inbound`, which dispatches on
    /// `header & 0x1F` and ignores the reserved bits exactly as zenoh's own
    /// decoder does. Treating one of those as loss of framing makes a reader
    /// skip real data over a bit nobody has defined yet, which is the failure
    /// this project ranks worst: confidently wrong beats silent.
    ///
    /// So: `None` is "this cannot be a transport message", and `Some(bits)`
    /// with `bits != 0` is "a transport message from a sender whose wire-spec
    /// vintage is not this one" — a divergence to REPORT, not to refuse.
    pub const fn reserved_transport_flags(header: u8) -> Option<u8> {
        match transport_flag_mask(header & 0x1F) {
            Some(defined) => Some(header & 0xE0 & !defined),
            None => None,
        }
    }
}

/// R311y609 — the ungated transport header space, checked against the gated
/// consts that spell the same bytes. The whole point of the duplication is
/// that a feature-poor build still knows the shape of the wire; the whole
/// point of this test is that it knows the RIGHT shape.
#[cfg(test)]
mod transport_header_space {
    use super::wire_const::*;

    /// Every gated `T_MID_*` const, with the flag bits its own gated
    /// `FLAG_T_*` consts define. Compiles only with the features on, which is
    /// exactly the build that can state the claim.
    #[test]
    #[cfg(all(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close",
        feature = "codec-frame",
        feature = "codec-join"
    ))]
    fn transport_header_space_agrees_with_the_gated_consts() {
        let expect: [(u8, u8); 7] = [
            (T_MID_INIT, FLAG_T_Z | FLAG_T_INIT_A | FLAG_T_INIT_S),
            (T_MID_OPEN, FLAG_T_Z | FLAG_T_OPEN_A | FLAG_T_OPEN_T),
            (T_MID_CLOSE, FLAG_T_Z | FLAG_T_CLOSE_S),
            (T_MID_KEEP_ALIVE, FLAG_T_Z),
            (T_MID_FRAME, FLAG_T_Z | FLAG_T_FRAME_R),
            (
                T_MID_FRAGMENT,
                FLAG_T_Z | FLAG_T_FRAGMENT_R | FLAG_T_FRAGMENT_M,
            ),
            (T_MID_JOIN, FLAG_T_Z | FLAG_T_JOIN_T | FLAG_T_JOIN_S),
        ];
        for (mid, flags) in expect {
            assert_eq!(
                transport_flag_mask(mid),
                Some(flags),
                "MID {mid:#04x}: the ungated table and the gated consts disagree"
            );
        }
        // ...and nothing ELSE the gate admits. The 5-bit field holds 32
        // values; the seven above are what a stream reader may RESUME on.
        // `T_MID_OAM` (0x00) is a transport MID this table deliberately omits
        // — `oam_is_a_transport_mid_this_gate_still_refuses` states the price
        // that bought the omission.
        for mid in 0u8..32 {
            let named = expect.iter().any(|(m, _)| *m == mid);
            assert_eq!(
                transport_flag_mask(mid).is_some(),
                named,
                "MID {mid:#04x}: membership of the transport space"
            );
        }
    }

    /// The discrimination this table is bought for, COUNTED rather than
    /// asserted in prose: a resynchronisation scan that accepts any byte as a
    /// header has no signal at all, and one that accepts 42/256 per frame has
    /// `(42/256)^depth`. The number belongs in a test because the depth
    /// default is chosen from it.
    #[test]
    fn transport_header_space_is_42_of_256() {
        let credible = (0u8..=255)
            .filter(|b| is_credible_transport_header(*b))
            .count();
        assert_eq!(
            credible, 42,
            "8 INIT + 8 OPEN + 4 CLOSE + 2 KEEP_ALIVE + 4 FRAME + 8 FRAGMENT + 8 JOIN"
        );
    }

    /// A MID outside the space is rejected whatever its flags, and a MID
    /// inside it is rejected when it sets a bit it does not define. Both arms
    /// matter: dropping the second would accept 7/32 = 56 of 256 bytes.
    #[test]
    fn an_undefined_flag_bit_is_not_a_credible_header() {
        // KEEP_ALIVE (0x04) defines no flag but Z.
        assert!(is_credible_transport_header(0x04));
        assert!(is_credible_transport_header(0x84));
        assert!(!is_credible_transport_header(0x24));
        assert!(!is_credible_transport_header(0x44));
        // 0x00 and 0x08..=0x1F are refused. 0x00 IS a transport MID and is
        // refused deliberately — `oam_is_a_transport_mid_this_gate_still_refuses`
        // is where that decision and its measured price live.
        assert!(!is_credible_transport_header(0x00));
        for mid in 0x08u8..=0x1F {
            assert!(!is_credible_transport_header(mid), "MID {mid:#04x}");
        }
    }

    /// OAM (`id::OAM = 0x00`, `zenoh-protocol/src/transport/mod.rs:54`) IS a
    /// transport MID — `parse_inbound` decodes it and
    /// `zenoh-codec/src/transport/mod.rs:131` dispatches it — and this gate
    /// refuses it anyway. The refusal is a DECISION with a measured price, not
    /// the omission it looks like, and this test is where the price is written
    /// down.
    ///
    /// # What the gate is actually asked
    ///
    /// Not "is this a transport MID" but "may a stream reader RESUME a message
    /// here". `0x00` is the weakest possible evidence for that: it is the most
    /// common byte in padding, in zeroed buffers and in every truncated
    /// length field, and its two encoding bits admit all four settings (they
    /// are `iext::ENC_*`, `common/extension.rs:64-67`, not flags), so
    /// admitting the MID admits EIGHT byte values including `0x00` itself.
    ///
    /// # The price, measured
    ///
    /// Admitting it was tried and run through
    /// `passive::tests::the_resync_scan_lands_on_the_true_boundary_across_noise`,
    /// whose corpus is seeded and therefore comparable run to run. At the
    /// default resync depth the worst trial's recovered fraction fell from
    /// 55% to 39% at 512 bytes of noise and from 42% to 0% at 8192, and the
    /// lead-in — frames reported before the framing rejoins the truth — grew
    /// from 5 to 14 at 65536. A reader that recovers nothing is worse at
    /// reading OAMs than one that will not resume on their header.
    ///
    /// # What is NOT given up
    ///
    /// The decoder's reach. `parse_inbound` names an OAM and reports its
    /// LENGTH, so a batch walk steps over one and reaches what follows it;
    /// this gate only declines to restart a LOST stream on one. That
    /// asymmetry is the same one
    /// `the_header_gate_and_the_decoder_disagree_on_reserved_bits_and_on_oam`
    /// already documents for reserved bits, with a second reason.
    #[test]
    fn oam_is_a_transport_mid_this_gate_still_refuses() {
        assert_eq!(
            transport_flag_mask(T_MID_OAM),
            None,
            "the omission is deliberate; read this test's doc before closing it"
        );
        // The Z bit spelled as the ungated table spells it: `FLAG_T_Z` is
        // itself gated, and this test states a property a feature-poor build
        // must still hold.
        const Z: u8 = 0x80;
        for enc in 0u8..4 {
            let header = T_MID_OAM | (enc << 5);
            assert!(!is_credible_transport_header(header), "{header:#04x}");
            assert!(!is_credible_transport_header(header | Z), "{header:#04x}");
        }
        // And the bits a conforming OAM sets are exactly the ones
        // `FLAG_T_OAM_ENC` names, which is what a reader that DOES know the
        // MID uses to read the body — kept here so the constant has a witness
        // even though the gate above refuses the header.
        assert_eq!(FLAG_T_OAM_ENC, 0x60);
        assert_eq!(reserved_transport_flags(T_MID_OAM), None);
    }
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
