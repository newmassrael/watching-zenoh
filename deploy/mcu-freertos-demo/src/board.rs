// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The QEMU mps2-an385 BOARD both FreeRTOS images run on: the heap_4 global
//! allocator, the scheduler start, the hooks the kernel and lwIP call, and the
//! board's entropy and wall clock. Each image (`src/main.rs`, the acceptor
//! session; `src/two_session/main.rs`, a client and a group session on one
//! local set) includes this file as its `board` module, so the two cannot
//! disagree about the board they claim to run on.

use core::ffi::{c_char, c_void};
use core::sync::atomic::{AtomicU32, Ordering};

use cortex_m_semihosting::{debug, hprintln};

use freertos_sys::{
    pdPASS, vTaskStartScheduler, xTaskCreate, xTaskGetTickCount, BaseType_t, TaskFunction_t,
};
use wz::runtime_freertos::FreertosAllocator;

/// FreeRTOS heap_4 backs every Rust allocation (the executor, the session
/// bundles, the lwIP sockets' receive pools, the task stack). Sized by
/// `configTOTAL_HEAP_SIZE` in FreeRTOSConfig.h.
#[global_allocator]
static ALLOC: FreertosAllocator = FreertosAllocator;

/// `configTICK_RATE_HZ` in FreeRTOSConfig.h — the `FreertosClock` timebase.
pub const TICK_HZ: u32 = 1000;

/// Create the ONE application task and hand the core to the scheduler.
/// `stack_words` is the task's stack in WORDS (the kernel's unit); it comes
/// out of heap_4 like every other allocation.
pub fn start(entry: TaskFunction_t, name: &core::ffi::CStr, stack_words: u16) -> ! {
    // SAFETY: standard FFI; a null parameter / handle-out is permitted.
    let rc = unsafe {
        xTaskCreate(
            entry,
            name.as_ptr(),
            stack_words,
            core::ptr::null_mut(),
            1, // priority above the idle task
            core::ptr::null_mut(),
        )
    };
    if rc != pdPASS {
        hprintln!("board FAIL: xTaskCreate rc={}", rc);
        debug::exit(debug::EXIT_FAILURE);
    }
    // Only returns on idle-task heap exhaustion.
    // SAFETY: the scheduler is not yet running; this is the standard start call.
    unsafe { vTaskStartScheduler() };
    hprintln!("board FAIL: vTaskStartScheduler returned (heap?)");
    debug::exit(debug::EXIT_FAILURE);
    #[allow(clippy::empty_loop)]
    loop {}
}

/// heap_4's bytes free now. An image that measures calls [`heap_usable_bytes`]
/// first, so the heap is initialised and the number means what it says.
#[allow(dead_code)] // the acceptor image does not measure its heap
pub fn heap_free_bytes() -> usize {
    // SAFETY: reads heap_4's counter; no preconditions.
    unsafe { freertos_sys::xPortGetFreeHeapSize() }
}

/// heap_4's usable size: what is free once the heap is initialised, before
/// anything else is allocated. Call it in `main` before [`start`]; it makes
/// one allocation of its own to initialise the heap (heap_4 does that lazily,
/// and reports 0 free until then), which it frees again.
#[allow(dead_code)]
pub fn heap_usable_bytes() -> usize {
    // SAFETY: a plain allocate-and-free before the scheduler runs.
    unsafe {
        let p = freertos_sys::pvPortMalloc(1);
        freertos_sys::vPortFree(p);
    }
    heap_free_bytes()
}

/// The deepest heap_4 has been: `usable` (from [`heap_usable_bytes`]) less
/// the kernel's low-water mark of free bytes.
#[allow(dead_code)]
pub fn heap_peak_bytes(usable: usize) -> usize {
    // SAFETY: reads heap_4's counter; no preconditions.
    usable.saturating_sub(unsafe { freertos_sys::xPortGetMinimumEverFreeHeapSize() })
}

/// The calling task's stack: its peak against the `stack_words` it was
/// created with, from the kernel's own high-water mark (the kernel paints a
/// new task's stack under `configCHECK_FOR_STACK_OVERFLOW = 2`). The judgement
/// is the bare-metal images' (`StackVerdict::fits`, `wz_mcu_stack`), so a
/// FreeRTOS task is held to the same margin as a linker-declared stack.
#[allow(dead_code)]
pub fn task_stack_verdict(stack_words: u16) -> wz_mcu_stack::StackVerdict {
    // SAFETY: NULL names the calling task.
    let free_words = unsafe { freertos_sys::uxTaskGetStackHighWaterMark(core::ptr::null_mut()) };
    let budget = stack_words as usize * 4;
    wz_mcu_stack::StackVerdict {
        peak: budget.saturating_sub(free_words as usize * 4),
        budget,
    }
}

/// How many 32-bit numbers the board hook handed out. Printed with a
/// verdict, so a PASS also shows the session drew its secrets through
/// `FreertosEntropy` rather than around it.
pub static RANDOM_DRAWS: AtomicU32 = AtomicU32::new(0);
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
    hprintln!("board FAIL: stack overflow");
    debug::exit(debug::EXIT_FAILURE);
}

/// FreeRTOS `configUSE_MALLOC_FAILED_HOOK = 1` hook — heap_4 exhaustion.
#[unsafe(no_mangle)]
pub extern "C" fn vApplicationMallocFailedHook() {
    hprintln!("board FAIL: malloc failed (heap_4 exhausted)");
    debug::exit(debug::EXIT_FAILURE);
}
