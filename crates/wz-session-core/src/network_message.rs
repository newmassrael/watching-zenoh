// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R74 / R311di-11 — Application-layer envelope batch inside a
//! `Frame.payload` carrier.
//!
//! `Frame.payload` models `Vec<NetworkMessage>` per
//! `docs/wire-spec-subset.md` §4 (the Established-session payload
//! carrier; zenoh-pico maps it to `_z_network_message_t`). Each
//! record starts with a header byte where bits 0..4 carry the network
//! MID and bits 5..7 carry per-MID flags + the shared Z bit. The full
//! network-MID set is 7 wide (PUSH 0x1D, REQUEST 0x1C, RESPONSE 0x1B,
//! RESPONSE_FINAL 0x1A, DECLARE 0x1E, INTEREST 0x19, OAM 0x1F per
//! `vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/network.h:33-39`).
//!
//! Each variant body (Request / Push / Response / ResponseFinal /
//! Declare) is cfg-gated on the matching `codec-*` feature so a
//! handshake-only deploy that turns off body codecs elides the unused
//! decode paths from the runtime. `Oam`, `Interest`, and `Unknown`
//! remain unconditional because the underlying codec modules are
//! always present in wz-codecs (no `codec-oam` / `codec-interest`
//! feature exists).

#[cfg(any(
    feature = "codec-request",
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-declare",
))]
use alloc::boxed::Box;
use alloc::vec::Vec;

#[cfg(feature = "codec-frame")]
use sce_forge_runtime::codec::{CodecError, SceCursor};

#[cfg(feature = "codec-declare")]
use wz_codecs::declare::Declare;
use wz_codecs::interest::Interest;
use wz_codecs::oam::Oam;
#[cfg(feature = "codec-push")]
use wz_codecs::push::Push;
#[cfg(feature = "codec-request")]
use wz_codecs::request::Request;
#[cfg(feature = "codec-response")]
use wz_codecs::response::Response;
#[cfg(feature = "codec-response-final")]
use wz_codecs::response_final::ResponseFinal;

/// R311dl — re-export the wire-spec MID constants from the
/// wz-codecs single-source-of-truth home. Callsite references
/// (`wire_const::N_MID_REQUEST` etc.) below keep their existing
/// shape; the constants themselves are defined in
/// [`wz_codecs::wire_const`].
#[cfg(feature = "codec-frame")]
use wz_codecs::wire_const;

/// R74 — one application-layer message inside a `Frame.payload` batch.
///
/// See the module docstring for the wire-shape rationale and per-
/// variant cfg gating policy. `#[derive(Debug)]` derives transitively
/// over wz-codecs codec structs — those carry the category-uniform
/// `Debug + Clone + PartialEq` derive set per
/// `sce-build::forge::rust_derive_policy::RustDeriveCategory::CodecStruct`
/// SSOT (SCE 14ff5e36d).
#[derive(Debug)]
pub enum NetworkMessage {
    /// Network MID `_Z_MID_N_REQUEST` (0x1C). Carries a query / put /
    /// del wrapped in a Wireexpr + request-id envelope with response
    /// correlation. Decoded via `wz_codecs::request::Request`. The
    /// `Box` keeps the enum variant size small — `Request` carries
    /// `Wireexpr` + a `RequestVariant` whose arms hold MsgPut / MsgDel
    /// / Query structs, making the inline form much larger than the
    /// `Unknown` variant.
    #[cfg(feature = "codec-request")]
    Request(Box<Request>),
    /// R90 — Network MID `_Z_MID_N_PUSH` (0x1D). Pub/sub data
    /// carrier wrapping a put / del inner body — same envelope
    /// shape as `Request` minus the rid field. The `Box` mirrors
    /// the `Request` variant's size-balancing rationale.
    #[cfg(feature = "codec-push")]
    Push(Box<Push>),
    /// R91 — Network MID `_Z_MID_N_RESPONSE_FINAL` (0x1A). Pure
    /// correlation marker that closes a Request's reply stream;
    /// payload is header + request_id VLE only (no embed, no
    /// inner body). Inlined (no `Box`) because the struct is
    /// small — just three integer fields plus an optional ext
    /// vec.
    #[cfg(feature = "codec-response-final")]
    ResponseFinal(ResponseFinal),
    /// R92 — Network MID `_Z_MID_N_OAM` (0x1F). Diagnostic /
    /// control-plane envelope; header (mid+enc+Z) + VLE id +
    /// optional ext-chain + body variant on `header.enc` (UNIT
    /// / ZINT / ZBUF inner codec). The body variant arms hold
    /// `ExtUnit` / `ExtZint` / `ExtZbuf` — small enough to inline
    /// like `ResponseFinal`.
    Oam(Oam),
    /// R93/R94 — Network MID `_Z_MID_N_INTEREST` (0x19).
    /// Declarations discovery / liveliness subscriber registration
    /// envelope; header (mid+C+F+Z) + VLE interest_id + (C||F)-gated
    /// inner body + Z-gated ext-chain. R94 closed the body via the
    /// interest_body sub-codec (body_flags byte + R-gated wireexpr).
    /// Inlined (no `Box`) because the struct is small — header byte
    /// + u64 + optional body + optional ext vec.
    Interest(Interest),
    /// R97 — Network MID `_Z_MID_N_RESPONSE` (0x1B). Query reply
    /// carrier wrapping a reply (0x04) or err (0x05) inner body
    /// dispatched via peek-byte on the inner MID bit-range. Same
    /// envelope shape as `Request` minus the body kind set. The
    /// `Box` keeps the enum variant size small — `Response`
    /// carries `Wireexpr` + `ResponseVariant` whose arms hold
    /// Reply / Err structs, making the inline form larger than
    /// the `Unknown` variant (mirrors the Request sizing
    /// rationale).
    #[cfg(feature = "codec-response")]
    Response(Box<Response>),
    /// R110/R115 — Network MID `_Z_MID_N_DECLARE` (0x1E). Declarations
    /// envelope wrapping one of the nine sub-MID inner bodies
    /// (DECL_KEXPR / DECL_SUBSCRIBER / DECL_QUERYABLE / DECL_TOKEN /
    /// UNDECL_KEXPR / UNDECL_SUBSCRIBER / UNDECL_QUERYABLE /
    /// UNDECL_TOKEN / DECL_FINAL) dispatched via peek-byte on the
    /// inner header MID. R110a-e closed the wz-side authoring chain
    /// and the byte-equiv Layer 3 wire-interop vs zenoh-pico
    /// `_z_declare_encode`; R115 wires the inbound dispatch so a
    /// peer-emitted DECLARE record surfaces here. The `Box` mirrors
    /// the `Request`/`Push`/`Response` sizing rationale — `Declare`
    /// carries an optional interest_id + ext vec + the inner
    /// `DeclareVariant` whose arms hold the nine sub-body structs,
    /// making the inline form much larger than `Unknown`.
    #[cfg(feature = "codec-declare")]
    Declare(Box<Declare>),
    /// Header byte's MID falls outside the
    /// {REQUEST, PUSH, RESPONSE_FINAL, OAM, INTEREST, RESPONSE, DECLARE}
    /// subset wz-codecs has authored envelope coverage for. `body`
    /// carries the rest of the payload bytes (header byte included)
    /// verbatim so a future per-MID decoder can re-parse without
    /// losing data; the parse stops here to avoid mis-cursor-advancing
    /// across an unknown body length.
    Unknown { mid: u8, body: Vec<u8> },
}

/// R74 — decode a `Frame.payload` byte slice into the in-order batch
/// of network messages it carries.
///
/// Loop shape: peek the cursor's next byte, mask to `mid = byte & 0x1F`,
/// dispatch to the matching envelope decoder. On `N_MID_REQUEST` calls
/// `Request::decode` which re-reads the header byte itself (peek-byte
/// primitive per RFC §5.B Y3 atomic 2b-ii) so no double-consumption.
/// On any other MID, absorbs the remaining bytes as `Unknown { mid,
/// body }` and terminates the batch loop — see
/// [`NetworkMessage::Unknown`] for the rationale.
///
/// An empty `bytes` slice returns `Ok(vec![])` (an empty batch is a
/// valid Frame.payload — the transport envelope is fine, no
/// application-layer records).
///
/// Codec errors propagate as `CodecError`. The caller is responsible
/// for deciding whether to surface them as a transport-FSM
/// `FramingError` (current `poll_and_dispatch_one` behavior, since the
/// transport envelope already parsed but the application-layer batch
/// is malformed) or to log and continue with the partially-decoded
/// batch.
///
/// R311g — gated on `codec-frame`. The only caller is the
/// `InboundFrame::Frame` arm in `poll_and_dispatch_one` (also
/// codec-frame-gated), so a codec-frame-OFF build never reaches a
/// caller; cfg-gating the definition itself elides ~80 lines of
/// dispatch + the `NetworkMessage` decoders for every body codec
/// without leaving an orphan public symbol. Individual match arms
/// inside this function carry their own per-body cfg
/// (`N_MID_PUSH` under `codec-push`, etc.).
#[cfg(feature = "codec-frame")]
pub fn parse_frame_payload(bytes: &[u8]) -> Result<Vec<NetworkMessage>, CodecError> {
    let mut messages = Vec::new();
    let mut cursor = SceCursor::new(bytes);
    while cursor.remaining() > 0 {
        let header = cursor.peek_slice(1)?[0];
        let mid = header & 0x1F;
        match mid {
            #[cfg(feature = "codec-request")]
            wire_const::N_MID_REQUEST => {
                let req = Request::decode(&mut cursor)?;
                messages.push(NetworkMessage::Request(Box::new(req)));
            }
            #[cfg(feature = "codec-push")]
            wire_const::N_MID_PUSH => {
                let push = Push::decode(&mut cursor)?;
                messages.push(NetworkMessage::Push(Box::new(push)));
            }
            #[cfg(feature = "codec-response-final")]
            wire_const::N_MID_RESPONSE_FINAL => {
                let rf = ResponseFinal::decode(&mut cursor)?;
                messages.push(NetworkMessage::ResponseFinal(rf));
            }
            wire_const::N_MID_OAM => {
                let oam = Oam::decode(&mut cursor)?;
                messages.push(NetworkMessage::Oam(oam));
            }
            wire_const::N_MID_INTEREST => {
                let interest = Interest::decode(&mut cursor)?;
                messages.push(NetworkMessage::Interest(interest));
            }
            #[cfg(feature = "codec-response")]
            wire_const::N_MID_RESPONSE => {
                let resp = Response::decode(&mut cursor)?;
                messages.push(NetworkMessage::Response(Box::new(resp)));
            }
            #[cfg(feature = "codec-declare")]
            wire_const::N_MID_DECLARE => {
                let decl = Declare::decode(&mut cursor)?;
                messages.push(NetworkMessage::Declare(Box::new(decl)));
            }
            _ => {
                let rem = cursor.remaining();
                let body = cursor.peek_slice(rem)?.to_vec();
                cursor.advance(rem)?;
                messages.push(NetworkMessage::Unknown { mid, body });
                break;
            }
        }
    }
    Ok(messages)
}
