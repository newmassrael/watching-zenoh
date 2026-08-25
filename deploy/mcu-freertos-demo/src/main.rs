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
//! `wz_task` hosts the wz-runtime-coop cooperative executor
//! (`FreertosRuntime = CoopRuntime<FreertosClock>`, the SAME executor as the
//! bare-metal sibling) and runs the wz-link-lwip UDP loopback echo — but yields
//! with `vTaskDelay(1)` (one FreeRTOS tick) between cooperative passes instead
//! of the bare-metal `wfi()`. PASS/FAIL are semihosted + propagated to the QEMU
//! exit code via `debug::exit`, identical to deploy/mcu-qemu-demo.

#![no_std]
#![no_main]

extern crate alloc;

use core::ffi::{c_char, c_void};

use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use panic_semihosting as _;

use freertos_sys::{pdPASS, vTaskDelay, vTaskStartScheduler, xTaskCreate, xTaskGetTickCount};
use wz::link_lwip::{ipv4_addr_loopback, LwipLink, LwipUdpSocket};
use wz::runtime_coop::{CoopRuntime, CoopTime};
use wz::runtime_core::{Runtime, TimeSource};
// R311y28 — the FreeRTOS seams now come through the wz facade's
// `platform-freertos` gate (`wz::runtime_freertos`), not a direct
// wz-runtime-freertos dep: this demo is the consumer that proves the gate.
use wz::runtime_freertos::{FreertosAllocator, FreertosClock};

/// FreeRTOS heap_4 backs every Rust allocation (the executor + the lwIP socket
/// Inner). Sized by `configTOTAL_HEAP_SIZE` in FreeRTOSConfig.h.
#[global_allocator]
static ALLOC: FreertosAllocator = FreertosAllocator;

/// `configTICK_RATE_HZ` in FreeRTOSConfig.h — the `FreertosClock` timebase.
const TICK_HZ: u32 = 1000;
/// wz task stack in WORDS. Generous: hosts the executor + the lwIP poll path.
const WZ_TASK_STACK_WORDS: u16 = 4096;
/// UDP echo port (matches the bare-metal sibling).
const ECHO_PORT: u16 = 5555;
/// Echo payload — identity-checked on receive to prove the full lwIP path.
const PAYLOAD: &[u8] = b"FreeRTOS lwIP UDP loopback echo";
/// Poll iterations before declaring no-echo failure (1 tick each ≈ 100 ms).
const POLL_BUDGET: u32 = 100;

#[entry]
fn main() -> ! {
    hprintln!("R311y27: FreeRTOS boot; xTaskCreate(wz) + vTaskStartScheduler");
    // Create the single application task that hosts the cooperative executor.
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
        hprintln!("R311y27 FAIL: xTaskCreate rc={}", rc);
        debug::exit(debug::EXIT_FAILURE);
    }
    // Hand control to the scheduler; only returns on idle-task heap exhaustion.
    // SAFETY: the scheduler is not yet running; this is the standard start call.
    unsafe { vTaskStartScheduler() };
    hprintln!("R311y27 FAIL: vTaskStartScheduler returned (heap?)");
    debug::exit(debug::EXIT_FAILURE);
    #[allow(clippy::empty_loop)]
    loop {}
}

/// The wz application task: hosts `CoopRuntime<FreertosClock>` (the
/// wz-runtime-coop executor SSOT) + the lwIP UDP loopback echo, yielding to the
/// scheduler with `vTaskDelay(1)` between cooperative passes.
extern "C" fn wz_task(_params: *mut c_void) {
    let link = LwipLink::init();
    let runtime = CoopRuntime::new(FreertosClock::<TICK_HZ>);
    let time = CoopTime::new(&runtime);

    let sock: LwipUdpSocket =
        LwipUdpSocket::bind(&link, ECHO_PORT).expect("bind UDP socket on ANY:5555");
    runtime.spawn(echo_task(sock, time));

    // Cooperative loop: drain lwIP's loopback queue + its timer wheel, run the
    // executor's ready tasks + expired timers, then yield one tick. The
    // FreeRTOS idle task runs while we sleep; the tick ISR (xPortSysTickHandler)
    // wakes us. echo_task calls debug::exit on PASS/FAIL, ending the demo.
    loop {
        link.poll_loopback();
        link.check_timeouts();
        runtime.run_until_idle();
        // SAFETY: standard FFI; blocks this task for one tick.
        unsafe { vTaskDelay(1) };
    }
}

/// Async echo: send one PAYLOAD to loopback:ECHO_PORT and poll for it back.
/// Identical shape to the bare-metal sibling; only the `CoopTime` clock param
/// differs (`FreertosClock` vs the SysTick clock).
async fn echo_task(mut sock: LwipUdpSocket, time: CoopTime<FreertosClock<TICK_HZ>>) {
    if let Err(e) = sock.send_to(ipv4_addr_loopback(), ECHO_PORT, PAYLOAD) {
        hprintln!("R311y27 FAIL: send_to {:?}", e);
        debug::exit(debug::EXIT_FAILURE);
    }
    for _ in 0..POLL_BUDGET {
        if let Some(dg) = sock.try_recv() {
            if dg.data.as_slice() == PAYLOAD
                && dg.src_port == ECHO_PORT
                && dg.src_addr == ipv4_addr_loopback()
            {
                hprintln!("R311y27 PASS");
                debug::exit(debug::EXIT_SUCCESS);
            }
            hprintln!("R311y27 FAIL: echo mismatch");
            debug::exit(debug::EXIT_FAILURE);
        }
        time.sleep(1).await;
    }
    hprintln!("R311y27 FAIL: no echo within budget");
    debug::exit(debug::EXIT_FAILURE);
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

/// FreeRTOS `configCHECK_FOR_STACK_OVERFLOW = 2` hook — bring-up diagnostic.
#[unsafe(no_mangle)]
pub extern "C" fn vApplicationStackOverflowHook(_task: *mut c_void, _name: *mut c_char) {
    hprintln!("R311y27 FAIL: stack overflow");
    debug::exit(debug::EXIT_FAILURE);
}

/// FreeRTOS `configUSE_MALLOC_FAILED_HOOK = 1` hook — heap_4 exhaustion.
#[unsafe(no_mangle)]
pub extern "C" fn vApplicationMallocFailedHook() {
    hprintln!("R311y27 FAIL: malloc failed (heap_4 exhausted)");
    debug::exit(debug::EXIT_FAILURE);
}
