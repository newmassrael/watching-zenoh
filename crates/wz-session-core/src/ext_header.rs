// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the zenoh `iext` extension-header vocabulary — the spec-frozen
//! encoding-marker bits and the id-field accessor shared by every extension
//! codec (transport-message exts, the node-id ext, the Z_EXT_AUTH inner method
//! chain).
//!
//! These are protocol constants (zenoh `commons/zenoh-protocol/src/common.rs`
//! `iext`), feature-INDEPENDENT, so they live in an UNCONDITIONAL module rather
//! than under a codec gate. Previously the vocabulary lived only in
//! [`crate::ext_nodeid`] (gated on `codec-push` / `-declare` / `-request`),
//! which forced every gated-out consumer (the `session-extauth` auth dispatch +
//! codec) to re-derive `0x20` / `0x40` / `header & 0x0F` locally — three copies
//! of one frozen fact. This module is that single home; `ext_nodeid` re-exports
//! from here for its existing callers' paths.

/// Mandatory flag, zenoh `iext::FLAG_M` (bit 4): a peer that does not understand
/// a mandatory ext must reject the message.
pub const EXT_FLAG_M: u8 = 0x10;

/// `Z64` encoding, zenoh `iext::ENC_Z64` (bits 5-6 = `0b01`): the ext body is a
/// `zint`.
pub const EXT_ENC_Z64: u8 = 0x20;

/// `ZBuf` encoding, zenoh `iext::ENC_ZBUF` (bits 5-6 = `0b10`): the ext body is a
/// length-prefixed byte buffer.
pub const EXT_ENC_ZBUF: u8 = 0x40;

/// Chain-continuation flag, zenoh `iext::FLAG_Z` (bit 7): another ext entry
/// follows THIS one in the chain.
pub const EXT_FLAG_Z: u8 = 0x80;

/// The extension id field (bits 0-3) of a header byte — zenoh `iext::mid`,
/// dropping the mandatory / encoding / chain flags.
pub fn ext_id(header: u8) -> u8 {
    header & 0x0F
}
