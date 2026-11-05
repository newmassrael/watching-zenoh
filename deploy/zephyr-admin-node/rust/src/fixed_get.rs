// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The fixed client as a GETTER (`CONFIG_WZ_GET`): the board's half of `wz_session_mcu::slot_getter`,
//! the module `deploy/host-slot-node --get` runs too. The query it asks, how many times and how is
//! stated by the build (`CONFIG_WZ_GET_KEY`, `_COUNT`, `_WARMUP`, `_INFLIGHT`, `_TIMEOUT_MS`, handed
//! to cargo as `WZ_GET_*`) and read here as constants, so that a value the build was given that is
//! not a number stops the build instead of reading as zero. What the kit supplies is the table
//! the round trips are kept in, the clock (the kernel's tick, so a round trip has the resolution of
//! one tick) and the console lines.
//!
//! The kit has no process to exit: when every query has ended it says how they went, once, and goes
//! on answering its own queries. The queries are asked in the session's event, with no mailbox (a
//! mailbox is a table of rows that is not all zero bytes, and this one's rows would move the plan's
//! round-trip table from `.bss` to `.data`).

use core::ops::ControlFlow;

use wz_session_core::caps::MAX_PENDING_QUERIES;
use wz_session_mcu::app_layer::GetError;
use wz_session_mcu::slot_getter::{
    Ask, GetterApp, GetterLayer, GetterReport, Plan, Progress, Summary,
};

use crate::fixed_client::{parse_decimal, Clock};

/// The round trips the node keeps: more queries than this are asked but not timed.
pub const SAMPLES: usize = 2048;
/// The most queries in flight at once, which the pending table needs one more row than.
pub const INFLIGHT: usize = 4;
/// The kit asks in the event: no mailbox rows.
pub const ROWS: usize = 0;

/// A decimal the build was given, or a stop: a build value that is missing or is not a number must
/// not read as zero.
macro_rules! build_number {
    ($name:literal) => {
        match option_env!($name) {
            Some(text) => match parse_decimal(text) {
                Some(value) => value,
                None => panic!(concat!($name, " is not a decimal number")),
            },
            None => panic!(concat!($name, " is not given")),
        }
    };
}

const COUNT: u32 = build_number!("WZ_GET_COUNT");
const WARMUP: u32 = build_number!("WZ_GET_WARMUP");
const IN_FLIGHT: u32 = build_number!("WZ_GET_INFLIGHT");
const TIMEOUT_MS: u32 = build_number!("WZ_GET_TIMEOUT_MS");
const KEY: &str = match option_env!("WZ_GET_KEY") {
    Some(key) => key,
    None => panic!("WZ_GET_KEY is not given"),
};

const _: () = {
    assert!(COUNT > WARMUP, "WZ_GET_WARMUP is not below WZ_GET_COUNT");
    assert!(
        IN_FLIGHT >= 1 && IN_FLIGHT as usize <= INFLIGHT,
        "WZ_GET_INFLIGHT is not from 1 to the plan's rows"
    );
    assert!(!KEY.is_empty(), "WZ_GET_KEY is empty");
    // A session's pending table holds the queries in flight and the row a late final of the last
    // still holds. Fewer rows refuse queries the plan counted as asked.
    assert!(
        MAX_PENDING_QUERIES > IN_FLIGHT as usize,
        "CONFIG_WZ_LIMIT_MAX_PENDING_QUERIES is not above CONFIG_WZ_GET_INFLIGHT"
    );
};

/// The layer of the sessions of a node that asks, by its type: the session task's cell is derived
/// from the events this layer makes (`fixed_client::TASK_BYTES`), so a row of the pending table
/// (`CONFIG_WZ_LIMIT_MAX_PENDING_QUERIES`, each the key text and the sink) grows the cell with it.
pub type Layer = GetterLayer<Clock, SAMPLES, INFLIGHT, ROWS>;

/// What the node was asked to do and what has happened, in one `static`, all zero bytes.
pub type KitPlan = Plan<Clock, SAMPLES, INFLIGHT, ROWS>;

pub static PLAN: KitPlan = Plan::new();

/// The query the build states.
pub const ASK: Ask = Ask {
    key: KEY,
    count: COUNT,
    timeout_ms: TIMEOUT_MS,
    warmup: WARMUP,
    inflight: IN_FLIGHT,
    mailbox: false,
};

/// The layer of the sessions of a node that asks.
pub const fn layer() -> Layer {
    GetterLayer::new(&PLAN)
}

/// What the getter does each round of the node's loop.
pub type KitGetterApp = GetterApp<Clock, KitReport, SAMPLES, INFLIGHT, ROWS>;

/// The application of a node that asks.
pub const fn app() -> KitGetterApp {
    GetterApp::new(&PLAN, KitReport)
}

/// Where the figures go: the board's console.
pub struct KitReport;

impl GetterReport for KitReport {
    fn progress(&mut self, progress: &Progress, last_refusal: Option<GetError>) {
        wz::runtime_zephyr::glue::log_args(format_args!(
            "ZEPHYR-WZ-GET progress issued={} finished={} replies={} errors={} refused={} \
             last_refusal={:?}",
            progress.issued,
            progress.finished,
            progress.replies,
            progress.errors,
            progress.refused,
            last_refusal
        ));
    }

    /// The line a lab reads after a run. The node goes on answering.
    fn done(&mut self, s: &Summary) -> ControlFlow<i32> {
        wz::runtime_zephyr::glue::log_args(format_args!(
            "ZEPHYR-WZ-GET done clean={} issued={} finished={} replies={} errors={} timeouts={} \
             refused={} bytes={} timed={} min_us={} median_us={} p99_us={} max_us={} elapsed_us={} \
             resolution_us={}",
            s.is_clean(),
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
            s.elapsed_us,
            1_000_000 / crate::TICK_HZ
        ));
        ControlFlow::Continue(())
    }
}
