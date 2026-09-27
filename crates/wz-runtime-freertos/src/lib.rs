// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `wz-runtime-freertos` — the FreeRTOS **cooperative single-task profile**.
//!
//! This crate is deliberately THIN. It does not reimplement the async executor
//! or `impl Runtime` — that is the audited [`wz_runtime_coop::CoopRuntime`]
//! (task pool, custom waker, cancel, timer queue), generic over a
//! [`ClockSource`]. The FreeRTOS profile is exactly that executor running
//! inside ONE FreeRTOS task (the analogue of zenoh-pico's
//! `Z_FEATURE_MULTI_THREAD=0` single-thread mode), so this crate supplies only
//! the two FreeRTOS-specific SEAMS:
//!
//! 1. [`FreertosClock`] — a [`ClockSource`] over the kernel tick counter
//!    (`xTaskGetTickCount`), const-generic over `configTICK_RATE_HZ`.
//! 2. [`FreertosAllocator`] — a [`GlobalAlloc`] over the FreeRTOS heap_4
//!    allocator (`pvPortMalloc`/`vPortFree`). The deploy binary declares it as
//!    its `#[global_allocator]`.
//! 3. R2913 — [`FreertosEntropy`](crate::FreertosEntropy), the session core's
//!    entropy port over the FreeRTOS application hook
//!    `xApplicationGetRandomNumber`, the one zenoh-pico's FreeRTOS port draws
//!    from (`vendor/zenoh-pico/src/system/freertos/system.c`, `z_random_u32`).
//!
//! [`FreertosRuntime`] is then just `CoopRuntime<FreertosClock<TICK_HZ>>`.
//!
//! The synchronisation seam needs nothing here: `CoopRuntime` already uses
//! `critical_section::Mutex`, and the deploy supplies the `critical-section`
//! impl (FreeRTOS has one, as does cortex-m). Networking reuses NO_SYS=1 lwIP
//! via `wz-link-lwip` (no FreeRTOS `sys_arch` needed — the executor polls lwIP
//! single-threaded), unchanged from the bare-metal profile.

#![no_std]

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;
use core::mem::size_of;

use freertos_sys::{pvPortMalloc, vPortFree, xTaskGetTickCount};
use wz_runtime_coop::{ClockSource, CoopRuntime};

/// Monotonic [`ClockSource`] reading the FreeRTOS kernel tick counter.
///
/// Const-generic over `TICK_HZ` = the deploy's `configTICK_RATE_HZ` (the
/// reference `freertos-sys/port/cross-test` config uses 1000). Mirrors the
/// bare-metal `wz_mcu_clock::SystickClock<CYCLES_PER_US>` const-generic shape:
/// the timebase parameter is a per-deploy compile-time constant, not a runtime
/// field. Zero-sized + `Copy` (the tick counter is global kernel state).
#[derive(Clone, Copy, Default)]
pub struct FreertosClock<const TICK_HZ: u32>;

impl<const TICK_HZ: u32> ClockSource for FreertosClock<TICK_HZ> {
    fn now_us(&self) -> u64 {
        // `ticks * 1_000_000` cannot overflow u64 (ticks is u32, so the product
        // is < 2^52), and multiply-before-divide keeps the conversion exact for
        // any TICK_HZ. Returns 0 before `vTaskStartScheduler` (tick count is 0),
        // which is a valid monotonic epoch.
        // SAFETY: `xTaskGetTickCount` reads the kernel tick counter and has no
        // preconditions; it is safe to call from task context at any time.
        let ticks = unsafe { xTaskGetTickCount() } as u64;
        ticks * 1_000_000 / TICK_HZ as u64
    }
}

/// The FreeRTOS profile's runtime: the wz-runtime-coop cooperative executor
/// (the SSOT) parameterised by [`FreertosClock`]. Construct with
/// `CoopRuntime::new(FreertosClock::<TICK_HZ>)`. NOT a reimplementation — the
/// task pool / waker / timer queue are wz-runtime-coop's, only the clock seam
/// is FreeRTOS-specific.
pub type FreertosRuntime<const TICK_HZ: u32> = CoopRuntime<FreertosClock<TICK_HZ>>;

extern "C" {
    /// The FreeRTOS application's random-number hook, supplied by the BOARD:
    /// `BaseType_t xApplicationGetRandomNumber(uint32_t *pulNumber)`, returning
    /// `pdTRUE` with `*pulNumber` filled, or `pdFALSE` when no number is
    /// available. FreeRTOS+TCP requires every application to define it, and
    /// zenoh-pico's FreeRTOS port calls it for every random draw, so a board
    /// that runs either already has it.
    fn xApplicationGetRandomNumber(pul_number: *mut u32) -> freertos_sys::BaseType_t;
}

/// `pdTRUE` — the hook's success value.
const PD_TRUE: freertos_sys::BaseType_t = 1;

/// R2913 — the session core's [`EntropySource`](wz_session_core::entropy::EntropySource)
/// on this profile: every byte comes from the board's
/// `xApplicationGetRandomNumber`, drawn 32 bits at a time, as zenoh-pico's
/// FreeRTOS port draws (`z_random_u32` then `z_random_fill`).
///
/// It makes no promise of its own about the bytes: they are exactly as
/// unpredictable as the board's hook, which is the plugin-tier contract §2.5
/// ratified -- the profile names the seam, the board owns the source. A hook
/// that reports failure fails the whole fill, so the session's fail-closed
/// slot stays empty rather than holding a partly-drawn value.
#[derive(Clone, Copy, Default)]
pub struct FreertosEntropy;

impl wz_session_core::entropy::EntropySource for FreertosEntropy {
    fn try_fill_bytes(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(), wz_session_core::entropy::EntropyUnavailable> {
        for chunk in buf.chunks_mut(4) {
            let mut word = 0u32;
            // SAFETY: the hook writes one u32 through a pointer to a live
            // local; the board's implementation is the application's own.
            if unsafe { xApplicationGetRandomNumber(&mut word) } != PD_TRUE {
                return Err(wz_session_core::entropy::EntropyUnavailable);
            }
            chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

/// `portBYTE_ALIGNMENT` on the ARMv7-M (ARM_CM3) port — heap_4 returns blocks
/// aligned to this.
const HEAP_ALIGN: usize = 8;

/// A [`GlobalAlloc`] bridging Rust's allocator to the FreeRTOS heap_4 allocator
/// (`pvPortMalloc`/`vPortFree`, sized by `configTOTAL_HEAP_SIZE`).
///
/// The deploy binary declares it:
/// `#[global_allocator] static ALLOC: FreertosAllocator = FreertosAllocator;`.
/// It lives in this profile crate (not the deploy) because — unlike the
/// bare-metal profile, where the heap is the deploy's free choice
/// (`embedded_alloc`) — the FreeRTOS heap IS the kernel's, so every FreeRTOS
/// deploy must route Rust allocations through it. One audited bridge, shared.
pub struct FreertosAllocator;

unsafe impl GlobalAlloc for FreertosAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() <= HEAP_ALIGN {
            // heap_4 guarantees HEAP_ALIGN-aligned blocks — direct.
            // SAFETY: pvPortMalloc(size) returns a heap_4 block or null on OOM.
            unsafe { pvPortMalloc(layout.size()) as *mut u8 }
        } else {
            // Over-aligned request (rare on this profile): over-allocate, align
            // up, and stash the heap_4 base pointer in the usize slot just below
            // the returned address so `dealloc` can recover it.
            let align = layout.align();
            let total = layout.size() + align + size_of::<usize>();
            // SAFETY: as above; null is handled below.
            let base = unsafe { pvPortMalloc(total) } as usize;
            if base == 0 {
                return core::ptr::null_mut();
            }
            let aligned = (base + size_of::<usize>() + align - 1) & !(align - 1);
            // SAFETY: `aligned - size_of::<usize>() >= base`, inside the block.
            unsafe { *((aligned - size_of::<usize>()) as *mut usize) = base };
            aligned as *mut u8
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.align() <= HEAP_ALIGN {
            // SAFETY: `ptr` came from `pvPortMalloc` in the matching `alloc`.
            unsafe { vPortFree(ptr as *mut c_void) };
        } else {
            // Recover the stashed heap_4 base pointer written by `alloc`.
            // SAFETY: the over-aligned `alloc` branch wrote the base just below.
            let base = unsafe { *((ptr as usize - size_of::<usize>()) as *mut usize) };
            unsafe { vPortFree(base as *mut c_void) };
        }
    }
}
