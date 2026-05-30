// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ep — per-deploy active-scouting parameters.
//!
//! The inputs `scout_emit()` packs into the outbound Scout frame
//! (`sources/codecs/scout.scxml` body = version + cbyte + zid). Pure
//! owned value type; alloc-gated (the `zid` is a `Vec<u8>`). The
//! scouting-side sibling of [`crate::session_init_params::SessionInitParams`]
//! — kept separate so the pre-session scouting subsystem does not reuse
//! (and thereby couple to) the session handshake parameter bundle.
//!
//! `timeout_ms` is intentionally absent: the scouting window is authored
//! directly in `scouting.scxml` as the `AwaitingHello.onentry`
//! `<send ... delay="1000ms">` (docs/scouting-fsm.md §2.5), so the SCXML
//! is its single source of truth. A future round that makes the window
//! deploy-configurable will thread it through the FSM codegen, not this
//! struct.

use alloc::vec::Vec;

/// Inputs for one outbound Scout frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoutParams {
    /// Zenoh protocol version byte (`Z_PROTO_VERSION`), emitted as Scout
    /// body byte 0.
    pub version: u8,
    /// WhatAmI bitmask the scouter is looking for (low 3 bits of the
    /// Scout cbyte; `0x01` ROUTER, `0x02` PEER, `0x04` CLIENT — a peer
    /// scouting for routers and peers sends `0x03`). Mirrors
    /// `_z_s_msg_make_scout(what, zid)`'s `what` argument.
    pub what: u8,
    /// The scouter's own zenoh id. When non-empty, `scout_emit` sets the
    /// Scout cbyte `I` flag, packs `zid_len - 1` into the high nibble,
    /// and appends the bytes; an empty zid emits an I=0 Scout (no id on
    /// the wire). Length must be 1..=16 when present (the 4-bit
    /// `zid_len_m1` field caps it).
    pub zid: Vec<u8>,
}
