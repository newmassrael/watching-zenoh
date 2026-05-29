// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ef — script-action dispatch trace counters lifted from
//! `wz-runtime-tokio::session_glue`.
//!
//! Pure no_std + no_alloc value type (a bag of `u32` counters plus a
//! [`crate::close_reason::CloseReason`] field, all `Copy`), so it sits on
//! the runtime-agnostic side alongside [`crate::qos`] /
//! [`crate::close_reason`] / [`crate::ext_chain_role`]. The struct records
//! how many times each native script action fired and the last
//! close-reason observed; the integration tests read these counters via
//! `SessionLinkActions::trace_snapshot` to verify the SCXML-driven
//! dispatch reached this side.
//!
//! Only the trace state moves: the live trace slot
//! (`SessionLinkActions::trace: R::Mutex<ActionTrace>`) and the snapshot
//! accessor (`trace_snapshot`, which reads the slot under the runtime's
//! mutex) are runtime-bound and stay in `session_glue.rs`. That accessor
//! calls [`ActionTrace::clone_via_copy`] across the crate boundary, so the
//! helper is `pub` here (it was a private fn while co-located).
//! `session_glue.rs` keeps a `pub use` re-export so the
//! `crate::session_glue::ActionTrace` callsites resolve unchanged. A DP3
//! leaf out of `session_glue.rs`.

use crate::close_reason::CloseReason;

/// Counters + last-wire-bytes snapshot the integration tests inspect
/// to verify the script-action dispatch reached this side AND the
/// codec produced the expected wire shape.
#[derive(Debug, Default)]
pub struct ActionTrace {
    pub link_driver_open: u32,
    pub send_init_syn: u32,
    pub send_open_syn: u32,
    pub send_init_ack_with_cookie: u32,
    pub send_open_ack: u32,
    pub send_close_frame_with_reason: u32,
    pub release_link: u32,
    pub enable_rx_tx_regions: u32,
    pub start_lease_monitor: u32,
    pub stop_lease_monitor: u32,
    pub start_keepalive_worker: u32,
    pub stop_keepalive_worker: u32,
    pub free_pool_slots: u32,
    pub set_close_reason_count: u32,
    pub close_reason: CloseReason,
    /// R84 — incremented on `record_established_at()` script dispatch
    /// (Established.onentry). Pairs 1:1 with the
    /// `SessionLinkActions::established_at` timestamp slot so tests
    /// can assert both the counter side-effect AND the slot
    /// population in one pass.
    pub record_established_at: u32,
    /// R89 — incremented on every `cookie_valid()` guard invocation
    /// (SentInitAck -> SentOpenAck transition condition). Tests
    /// assert this counter to confirm the dynamic guard fired
    /// instead of a constant-true fallback. The verdict itself is
    /// observed indirectly via FSM state after the transition: if
    /// guard returned true the FSM advances to SentOpenAck, if
    /// false it stays at SentInitAck.
    pub cookie_valid_check: u32,
}

impl ActionTrace {
    /// Field-by-field `Copy` snapshot. Used by
    /// `SessionLinkActions::trace_snapshot` to lift a value out from
    /// under the runtime mutex; `pub` because that accessor lives in
    /// the tokio crate while this type lives here.
    pub fn clone_via_copy(&self) -> Self {
        Self {
            link_driver_open: self.link_driver_open,
            send_init_syn: self.send_init_syn,
            send_open_syn: self.send_open_syn,
            send_init_ack_with_cookie: self.send_init_ack_with_cookie,
            send_open_ack: self.send_open_ack,
            send_close_frame_with_reason: self.send_close_frame_with_reason,
            release_link: self.release_link,
            enable_rx_tx_regions: self.enable_rx_tx_regions,
            start_lease_monitor: self.start_lease_monitor,
            stop_lease_monitor: self.stop_lease_monitor,
            start_keepalive_worker: self.start_keepalive_worker,
            stop_keepalive_worker: self.stop_keepalive_worker,
            free_pool_slots: self.free_pool_slots,
            set_close_reason_count: self.set_close_reason_count,
            close_reason: self.close_reason,
            record_established_at: self.record_established_at,
            cookie_valid_check: self.cookie_valid_check,
        }
    }
}
