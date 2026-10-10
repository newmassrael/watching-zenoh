// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! mcu-freertos-demo — LAYER-2 FreeRTOS cooperative single-task profile e2e on
//! QEMU mps2-an385 (Cortex-M3).
//!
//! Boot: cortex-m-rt `#[entry]` → `xTaskCreate(wz_task)` → `vTaskStartScheduler`
//! (does not return). The FreeRTOS ARM_CM3 port's SysTick / PendSV / SVCall
//! handlers are routed into the cortex-m-rt vector table by the
//! `#define vPortSVCHandler SVCall` etc. in FreeRTOSConfig.h (direct routing;
//! port.c thus DEFINES the cortex-m-rt vector symbols, overriding the weak
//! defaults). FreeRTOS owns SysTick — there is no Rust `#[exception] SysTick`.
//!
//! R2913 — `wz_task` runs a wz SESSION, not a socket echo. Until this round
//! the task hosted the coop executor and bounced one UDP datagram off lwIP
//! loopback, so no session, codec or transport code was even compiled into a
//! FreeRTOS image, while zenoh-pico's FreeRTOS port runs the whole session.
//! It now runs the acceptor session e2e the bare-metal Stage 5 deploy runs
//! (`wz_mcu_session_acceptor::run_acceptor_e2e`): the acceptor handshake to
//! `Established` against a reactive peer over lwIP loopback, with the cookie
//! round trip verified, then a post-handshake Frame dispatched to the app
//! layer. It runs on this profile's three seams — `FreertosClock` (the kernel
//! tick), `FreertosAllocator` (heap_4) and `FreertosEntropy` (the board's
//! `xApplicationGetRandomNumber`) — inside the one FreeRTOS task. R2914 adds
//! the fourth, `FreertosEpoch` (the board's `wzApplicationGetTimeSinceEpoch`),
//! read after the session to mint the NTP64 a timestamp carries. PASS/FAIL
//! are semihosted and propagated to the QEMU exit code via `debug::exit`.
//!
//! The board (allocator, scheduler start, kernel and lwIP hooks) is
//! `src/board.rs`, shared with the two-session image.

#![no_std]
#![no_main]

extern crate alloc;

mod board;

use core::ffi::c_void;
use core::sync::atomic::Ordering;

use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use panic_semihosting as _;

// R311y28 — the FreeRTOS seams come through the wz facade's
// `platform-freertos` gate (`wz::runtime_freertos`), not a direct
// wz-runtime-freertos dep: this demo is the consumer that proves the gate.
use wz::runtime_freertos::{FreertosClock, FreertosEntropy, FreertosEpoch};
use wz_mcu_session_acceptor::{run_acceptor_e2e_with_progress, AcceptorE2eOutcome, DataMode};
use wz_session_core::epoch::EpochSource;

use board::{RANDOM_DRAWS, TICK_HZ};

/// wz task stack in WORDS (16 KiB). Hosts the executor, the session FSM
/// dispatch and the lwIP poll path; `configCHECK_FOR_STACK_OVERFLOW = 2`
/// reports an overrun through the board's hook rather than corrupting silently.
const WZ_TASK_STACK_WORDS: u16 = 4096;

#[entry]
fn main() -> ! {
    hprintln!("R2913: FreeRTOS boot; xTaskCreate(wz) + vTaskStartScheduler");
    // The single application task that hosts the session.
    board::start(Some(wz_task), c"wz", WZ_TASK_STACK_WORDS)
}

/// The wz application task: the acceptor session e2e on this profile's seams.
extern "C" fn wz_task(_params: *mut c_void) {
    // R3189 (open-debt item 815) — each stage is printed as the e2e ENTERS it,
    // so a boot that stops making progress leaves the stage it stalled in as
    // its last console line.
    let report = run_acceptor_e2e_with_progress(
        FreertosClock::<TICK_HZ>,
        FreertosEntropy,
        DataMode::WholeFrame,
        || {},
        |stage| {
            hprintln!("R2913: stage {}", stage.name());
        },
    );
    match report.outcome {
        AcceptorE2eOutcome::EstablishedAndDispatched => {
            hprintln!(
                "R2913 PASS: FreeRTOS session Established + Frame dispatched \
                 (advanced_fsm={} cookie_len={} random_draws={})",
                report.advanced_fsm,
                report.peer_cookie_len,
                RANDOM_DRAWS.load(Ordering::Relaxed),
            );
        }
        other => {
            hprintln!(
                "R2913 FAIL: {:?} (advanced_fsm={} side_effect={} parse_error={} \
                 frame_payload={} initack_seen={} cookie_len={} openack_seen={} \
                 frame_sent={} random_draws={})",
                other,
                report.advanced_fsm,
                report.side_effect,
                report.parse_error,
                report.frame_payload,
                report.peer_initack_seen,
                report.peer_cookie_len,
                report.peer_openack_seen,
                report.peer_frame_sent,
                RANDOM_DRAWS.load(Ordering::Relaxed),
            );
            debug::exit(debug::EXIT_FAILURE);
        }
    }
    // R2914 — the epoch seam: mint the NTP64 a timestamp carries from this
    // board's clock, through the profile's `FreertosEpoch`. A date before
    // 2020 means the hook answered something that is not the time.
    match FreertosEpoch.try_now_ntp64() {
        Ok(ntp) if ntp.whole_secs() >= EARLIEST_PLAUSIBLE_UNIX_SECS => {
            hprintln!(
                "R2914 PASS: epoch via FreertosEpoch, NTP64 {:#018x} ({} s since 1970)",
                ntp.as_word(),
                ntp.whole_secs(),
            );
            debug::exit(debug::EXIT_SUCCESS);
        }
        Ok(ntp) => {
            hprintln!(
                "R2914 FAIL: the board clock says {} s since 1970, before 2020",
                ntp.whole_secs(),
            );
            debug::exit(debug::EXIT_FAILURE);
        }
        Err(e) => {
            hprintln!("R2914 FAIL: {}", e);
            debug::exit(debug::EXIT_FAILURE);
        }
    }
    #[allow(clippy::empty_loop)]
    loop {}
}

/// 2020-01-01T00:00:00Z: an epoch reading below this is not the time.
const EARLIEST_PLAUSIBLE_UNIX_SECS: u64 = 1_577_836_800;
