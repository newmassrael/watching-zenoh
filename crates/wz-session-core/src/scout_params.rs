// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! `timeout_ms` is the active-scouting window (docs/scouting-fsm.md §2.5,
//! default 1000ms). R311ik moved it here from the former
//! `scouting.scxml` `AwaitingHello.onentry <send delay="1000ms">`: the
//! engine-free no_std FSM arms no self-timer (under no-std codegen a
//! `<send delay>` binds `NoOpHal` and can never fire), so the host drive
//! loop owns the scout deadline and reads its VALUE from this field. SSOT
//! is preserved — the value lives in the (deploy-sourced) ScoutParams
//! bundle, the timeout TRANSITION stays in the statechart, and the clock
//! belongs to the runtime. This is the deploy-configurable window the
//! prior revision's note anticipated.

use alloc::vec::Vec;

/// Inputs for one outbound Scout frame plus the active-scouting deadline.
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
    /// Active-scouting window in milliseconds (docs/scouting-fsm.md §2.5,
    /// `scouting.timeout_ms`, default 1000). The host drive loop
    /// (`scouting_glue::drive_scouting_until_resolved`) raises
    /// `scout.timer.elapsed` once this elapses with no Hello, driving the
    /// FSM's `AwaitingHello -> Idle` timeout transition. The FSM itself
    /// arms no timer (engine-free no_std: a `<send delay>` would bind
    /// `NoOpHal` and never fire), so this field is the deadline's single
    /// source of truth.
    pub timeout_ms: u64,
    /// zenoh-pico's `__z_scout_loop(.., bool exit_on_first)`
    /// (`src/session/scout.c:29-30`): `true` takes the FIRST Hello and
    /// ends the cycle, `false` keeps the window open for its full
    /// `timeout_ms` and records every responder.
    ///
    /// Upstream ships BOTH values and the choice belongs to the caller, not
    /// to the FSM: the session-open implicit scout passes `true`
    /// (`src/net/session.c:69` — it needs one dial target), the public
    /// `z_scout` survey API passes `false` (`src/net/primitives.c:81` — it
    /// reports every peer to its closure). The scouting statechart carries
    /// both arms guarded on this value
    /// (`sources/session/scouting.scxml`, the two `hello.received`
    /// transitions); the host drive loop re-states it on every raise
    /// because the engine-free surface has no datamodel to hold it.
    ///
    /// No `Default` — the field is REQUIRED at construction so the compiler
    /// enumerates every scouting caller and none can inherit a mode it did
    /// not choose. A survey that silently stops at the first answer and a
    /// lookup that silently waits out the whole window are both wrong, and
    /// neither is visible from the outcome.
    pub exit_on_first: bool,
}
