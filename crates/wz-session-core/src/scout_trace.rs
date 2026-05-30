// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ep — scouting script-action dispatch trace counters.
//!
//! Pure no_std + no_alloc value type (a bag of four `u32` counters, all
//! `Copy`), the scouting-side sibling of [`crate::action_trace::ActionTrace`]
//! — it sits on the runtime-agnostic side alongside [`crate::qos`] /
//! [`crate::close_reason`]. The struct records how many times each native
//! scouting script action fired; integration + unit tests read these
//! counters via `ScoutingActions::trace_snapshot` to verify the
//! SCXML-driven dispatch reached this side.
//!
//! Only the trace state lives here. The live trace slot
//! (`ScoutingActions::trace: R::Mutex<ScoutTrace>`) and the snapshot
//! accessor are runtime-bound and stay in `wz-runtime-tokio`. That
//! accessor calls [`ScoutTrace::clone_via_copy`] across the crate
//! boundary, so the helper is `pub` here.
//!
//! Kept deliberately separate from `ActionTrace` rather than folded into
//! it: scouting is a pre-session, untrusted-link subsystem with its own
//! FSM (`scouting.scxml`), so its dispatch counters do not belong in the
//! session handshake trace.

/// Counters the scouting tests inspect to verify each scouting script
/// action fired the expected number of times.
#[derive(Debug, Default)]
pub struct ScoutTrace {
    /// Incremented on `scout_emit()` dispatch (Sending.onentry): one
    /// Scout frame was encoded and staged for multicast transmission.
    pub scout_emit: u32,
    /// Incremented on `record_hello_and_emit()` dispatch
    /// (AwaitingHello -> Idle on `hello.received`): one Hello frame was
    /// decoded and its first locator captured.
    pub record_hello: u32,
    /// Incremented on `emit_scout_timeout()` dispatch (AwaitingHello ->
    /// Idle on `scout.timer.elapsed`): the scouting window expired with
    /// no Hello observed.
    pub scout_timeout: u32,
    /// Incremented on `diag_scout_tx_failed()` dispatch (Sending -> Idle
    /// on `link.tx_failed`): the multicast Scout transmit errored.
    pub tx_failed: u32,
}

impl ScoutTrace {
    /// Field-by-field `Copy` snapshot. Used by
    /// `ScoutingActions::trace_snapshot` to lift a value out from under
    /// the runtime mutex; `pub` because that accessor lives in the tokio
    /// crate while this type lives here.
    pub fn clone_via_copy(&self) -> Self {
        Self {
            scout_emit: self.scout_emit,
            record_hello: self.record_hello,
            scout_timeout: self.scout_timeout,
            tx_failed: self.tx_failed,
        }
    }
}
