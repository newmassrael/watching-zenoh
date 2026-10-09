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

#![no_std]
#![no_main]

extern crate alloc;

use core::ffi::{c_char, c_void};
use core::sync::atomic::{AtomicU32, Ordering};

use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use panic_semihosting as _;

use freertos_sys::{pdPASS, vTaskStartScheduler, xTaskCreate, xTaskGetTickCount, BaseType_t};
// R311y28 — the FreeRTOS seams come through the wz facade's
// `platform-freertos` gate (`wz::runtime_freertos`), not a direct
// wz-runtime-freertos dep: this demo is the consumer that proves the gate.
use wz::runtime_freertos::{FreertosAllocator, FreertosClock, FreertosEntropy, FreertosEpoch};
use wz_mcu_session_acceptor::{run_acceptor_e2e_with_progress, AcceptorE2eOutcome, DataMode};
use wz_session_core::epoch::EpochSource;

/// FreeRTOS heap_4 backs every Rust allocation (the executor, the session
/// bundle, both lwIP sockets). Sized by `configTOTAL_HEAP_SIZE` in
/// FreeRTOSConfig.h.
#[global_allocator]
static ALLOC: FreertosAllocator = FreertosAllocator;

/// `configTICK_RATE_HZ` in FreeRTOSConfig.h — the `FreertosClock` timebase.
const TICK_HZ: u32 = 1000;
/// wz task stack in WORDS (16 KiB). Hosts the executor, the session FSM
/// dispatch and the lwIP poll path; `configCHECK_FOR_STACK_OVERFLOW = 2`
/// reports an overrun through the hook below rather than corrupting silently.
const WZ_TASK_STACK_WORDS: u16 = 4096;

#[entry]
fn main() -> ! {
    hprintln!("R2913: FreeRTOS boot; xTaskCreate(wz) + vTaskStartScheduler");
    // Create the single application task that hosts the session.
    // SAFETY: standard FFI; a null name-array / handle-out is permitted.
    let rc = unsafe {
        xTaskCreate(
            Some(wz_task),
            c"wz".as_ptr(),
            WZ_TASK_STACK_WORDS,
            core::ptr::null_mut(),
            1, // priority above the idle task
            core::ptr::null_mut(),
        )
    };
    if rc != pdPASS {
        hprintln!("R2913 FAIL: xTaskCreate rc={}", rc);
        debug::exit(debug::EXIT_FAILURE);
    }
    // Hand control to the scheduler; only returns on idle-task heap exhaustion.
    // SAFETY: the scheduler is not yet running; this is the standard start call.
    unsafe { vTaskStartScheduler() };
    hprintln!("R2913 FAIL: vTaskStartScheduler returned (heap?)");
    debug::exit(debug::EXIT_FAILURE);
    #[allow(clippy::empty_loop)]
    loop {}
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

/// This board's wall clock for `FreertosEpoch`. QEMU mps2-an385 has no RTC, but
/// semihosting's `SYS_TIME` (0x11) returns the HOST's seconds since 1970, which
/// is a real clock rather than a fixture; it has one-second resolution, so
/// `nanos` is 0. A board with an RTC or SNTP reads that here instead.
#[unsafe(no_mangle)]
pub extern "C" fn wzApplicationGetTimeSinceEpoch(secs: *mut u64, nanos: *mut u32) -> BaseType_t {
    // SAFETY: SYS_TIME takes no argument block and returns seconds in r0.
    let host_secs = unsafe { cortex_m_semihosting::syscall!(TIME) };
    // SAFETY: `FreertosEpoch` passes pointers to live locals.
    unsafe {
        *secs = host_secs as u64;
        *nanos = 0;
    }
    1 // pdTRUE
}

/// How many 32-bit numbers the board hook handed out. Printed with the
/// verdict, so a PASS also shows the session drew its secrets through
/// `FreertosEntropy` rather than around it.
static RANDOM_DRAWS: AtomicU32 = AtomicU32::new(0);
/// The hook's generator state (xorshift32; never zero).
static RANDOM_STATE: AtomicU32 = AtomicU32::new(0x9E37_79B9);

/// The FreeRTOS application random-number hook this board supplies
/// (`BaseType_t xApplicationGetRandomNumber(uint32_t *)`, the one FreeRTOS+TCP
/// and zenoh-pico's FreeRTOS port call).
///
/// ⚠ QEMU mps2-an385 has NO entropy hardware, so this board's hook is a FIXTURE:
/// an xorshift32 over a boot constant, predictable to anyone who reads this
/// file. It exercises the seam; it does not satisfy the entropy contract, and a
/// real board replaces this function with its TRNG (or its network stack's
/// random source), not the profile code above.
#[unsafe(no_mangle)]
pub extern "C" fn xApplicationGetRandomNumber(pul_number: *mut u32) -> BaseType_t {
    let mut x = RANDOM_STATE.load(Ordering::Relaxed);
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    RANDOM_STATE.store(x, Ordering::Relaxed);
    RANDOM_DRAWS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the caller (`FreertosEntropy`) passes a pointer to a live u32.
    unsafe { *pul_number = x };
    1 // pdTRUE
}

/// lwIP NO_SYS=1 `sys_now()` — milliseconds since boot, from the FreeRTOS tick
/// counter (the same timebase `FreertosClock` reads). lwIP's `timeouts.c` calls
/// this unconditionally; without it the link fails with "undefined sys_now".
#[unsafe(no_mangle)]
pub extern "C" fn sys_now() -> u32 {
    // ms = ticks * 1000 / TICK_HZ; with TICK_HZ = 1000, ms == ticks.
    // SAFETY: reads the kernel tick counter; no preconditions.
    let ticks = unsafe { xTaskGetTickCount() };
    ticks / (TICK_HZ / 1000)
}

/// FreeRTOS `configCHECK_FOR_STACK_OVERFLOW = 2` hook.
#[unsafe(no_mangle)]
pub extern "C" fn vApplicationStackOverflowHook(_task: *mut c_void, _name: *mut c_char) {
    hprintln!("R2913 FAIL: stack overflow");
    debug::exit(debug::EXIT_FAILURE);
}

/// FreeRTOS `configUSE_MALLOC_FAILED_HOOK = 1` hook — heap_4 exhaustion.
#[unsafe(no_mangle)]
pub extern "C" fn vApplicationMallocFailedHook() {
    hprintln!("R2913 FAIL: malloc failed (heap_4 exhausted)");
    debug::exit(debug::EXIT_FAILURE);
}
