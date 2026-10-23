// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The node as a GETTER: it asks the same query again and again, keeping up to `--inflight` of them
//! pending at once, and keeps the round trip of each in a table this file declares. The getter itself
//! is `wz_session_mcu::slot_getter`, which the kit's image runs too; this file is the host's half
//! of it: the table's sizes, the `static` that holds it, and the console lines and exit code of a
//! process.

use core::ops::ControlFlow;

use wz_runtime_posix::glue::log_args;
use wz_session_mcu::app_layer::GetError;
use wz_session_mcu::slot_getter::{GetterApp, GetterLayer, GetterReport, Plan, Progress, Summary};

use crate::Clock;

pub use wz_session_mcu::slot_getter::Ask;

/// The round trips the node keeps: more queries than this are asked but not timed.
pub const SAMPLES: usize = 4096;

/// The most queries in flight at once: the plan's slots.
pub const MAX_INFLIGHT: usize = 8;

/// The rows of the mailbox `--mailbox` leaves its queries in: one for each place in flight.
const MAILBOX_ROWS: usize = MAX_INFLIGHT;

/// What the node was asked to do and what has happened, in one `static`.
pub type HostPlan = Plan<Clock, SAMPLES, MAX_INFLIGHT, MAILBOX_ROWS>;

pub static PLAN: HostPlan = Plan::new();

/// The layer of a getter's sessions.
pub const fn layer() -> GetterLayer<Clock, SAMPLES, MAX_INFLIGHT, MAILBOX_ROWS> {
    GetterLayer::new(&PLAN)
}

/// What a getter does each round of the node's loop.
pub type HostGetterApp = GetterApp<Clock, HostReport, SAMPLES, MAX_INFLIGHT, MAILBOX_ROWS>;

/// The application of a node that was asked to get.
pub const fn app() -> HostGetterApp {
    GetterApp::new(&PLAN, HostReport)
}

/// Where the figures go: the process's console, and its exit code.
pub struct HostReport;

impl GetterReport for HostReport {
    fn progress(&mut self, progress: &Progress, last_refusal: Option<GetError>) {
        log_args(format_args!(
            "HOST-WZ-GET progress issued={} finished={} replies={} errors={} refused={} \
             last_refusal={:?}",
            progress.issued,
            progress.finished,
            progress.replies,
            progress.errors,
            progress.refused,
            last_refusal
        ));
    }

    /// The line a lab reads after a getter's run, and the exit code: 0 when every query was
    /// answered and none timed out or was an error, 1 otherwise.
    fn done(&mut self, s: &Summary) -> ControlFlow<i32> {
        log_args(format_args!(
            "HOST-WZ-GET done issued={} finished={} replies={} errors={} timeouts={} refused={} \
             bytes={} timed={} min_us={} median_us={} p99_us={} max_us={} elapsed_us={}",
            s.issued,
            s.finished,
            s.replies,
            s.errors,
            s.timeouts,
            s.refused,
            s.payload_bytes,
            s.timed,
            s.min_us,
            s.median_us,
            s.p99_us,
            s.max_us,
            s.elapsed_us
        ));
        ControlFlow::Break(i32::from(!s.is_clean()))
    }
}
