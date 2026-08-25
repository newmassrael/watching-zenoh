// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `wz-runtime-zephyr` — the Zephyr **cooperative single-task profile**.
//!
//! This crate is deliberately THIN, identical in shape to
//! `wz-runtime-freertos`. It does not reimplement the async executor or
//! `impl Runtime` — that is the audited [`wz_runtime_coop::CoopRuntime`] (task
//! pool, custom waker, cancel, timer queue), generic over a [`ClockSource`].
//! The Zephyr profile is that executor running inside ONE Zephyr thread (the
//! analogue of zenoh-pico's `Z_FEATURE_MULTI_THREAD=0` single-thread mode), so
//! this crate supplies only the two Zephyr-specific SEAMS:
//!
//! 1. [`ZephyrClock`] — a [`ClockSource`] over the kernel tick counter
//!    (`sys_clock_tick_get`), const-generic over `CONFIG_SYS_CLOCK_TICKS_PER_SEC`.
//! 2. [`ZephyrAllocator`] — a [`GlobalAlloc`] over the Zephyr kernel heap
//!    (`k_malloc`/`k_free`). The deploy binary declares it as its
//!    `#[global_allocator]` and sets `CONFIG_HEAP_MEM_POOL_SIZE`.
//!
//! [`ZephyrRuntime`] is then just `CoopRuntime<ZephyrClock<TICK_HZ>>`.
//!
//! The synchronisation seam needs nothing here: `CoopRuntime` already uses
//! `critical_section::Mutex`, and the deploy supplies the `critical-section`
//! impl (Zephyr/cortex-m has one). Networking reuses NO_SYS=1 lwIP via
//! `wz-link-lwip`, unchanged from the bare-metal + FreeRTOS profiles.
#![no_std]

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;
use core::mem::size_of;

use wz_runtime_coop::{ClockSource, CoopRuntime};
use zephyr_sys::{k_free, k_malloc, sys_clock_tick_get};

/// Monotonic [`ClockSource`] reading the Zephyr kernel tick counter.
///
/// Const-generic over `TICK_HZ` = the deploy's `CONFIG_SYS_CLOCK_TICKS_PER_SEC`
/// (the qemu_cortex_m3 reference uses 100). Mirrors the FreeRTOS profile's
/// `FreertosClock<TICK_HZ>` and the bare-metal `SystickClock<CYCLES_PER_US>`
/// const-generic shape: the timebase is a per-deploy compile-time constant, not
/// a runtime field. Zero-sized + `Copy` (the tick counter is global kernel
/// state). Monotonic by construction: `sys_clock_tick_get` is the kernel's
/// non-decreasing tick count and is `i64` (no wrap at any realistic uptime), so
/// the [`ClockSource`] monotonic contract holds without a floor.
#[derive(Clone, Copy, Default)]
pub struct ZephyrClock<const TICK_HZ: u32>;

impl<const TICK_HZ: u32> ClockSource for ZephyrClock<TICK_HZ> {
    fn now_us(&self) -> u64 {
        // `ticks * 1_000_000` cannot overflow u64 for any realistic uptime
        // (ticks is the boot-relative kernel count), and multiply-before-divide
        // keeps the conversion exact for any TICK_HZ. Returns 0 before the first
        // tick, a valid monotonic epoch.
        // SAFETY: `sys_clock_tick_get` reads the kernel tick counter and has no
        // preconditions; it is safe to call from thread context at any time.
        let ticks = unsafe { sys_clock_tick_get() } as u64;
        ticks * 1_000_000 / TICK_HZ as u64
    }
}

/// The Zephyr profile's runtime: the wz-runtime-coop cooperative executor (the
/// SSOT) parameterised by [`ZephyrClock`]. Construct with
/// `CoopRuntime::new(ZephyrClock::<TICK_HZ>)`. NOT a reimplementation — the task
/// pool / waker / timer queue are wz-runtime-coop's, only the clock seam is
/// Zephyr-specific.
pub type ZephyrRuntime<const TICK_HZ: u32> = CoopRuntime<ZephyrClock<TICK_HZ>>;

/// Zephyr kernel-heap alignment guarantee for the **direct** `k_malloc` path.
///
/// `k_malloc` calls `sys_heap_noalign_alloc` (kernel/mempool.c) — it does NOT
/// over-align — so the only guarantee is the sys_heap base alignment, which for
/// a SMALL heap (the MCU default, `CONFIG_SYS_HEAP_SMALL_ONLY`) is just
/// `sizeof(void*)` = 4 bytes (heap.c asserts `ret & (big_heap ? 7 : 3) == 0`).
/// So 4, NOT 8 — unlike FreeRTOS's heap_4, which guarantees `portBYTE_ALIGNMENT`
/// = 8 (and is asserted), so `FreertosAllocator` correctly uses 8. Any request
/// with `align > 4` (e.g. a `u64`-bearing struct — including wz-runtime-coop's
/// own timer-queue entries) takes the over-aligned branch below, which aligns
/// up regardless of the `k_malloc` base alignment. Setting this to 8 would hand
/// align-8 allocations a 4-aligned pointer on the default heap = UB.
const HEAP_ALIGN: usize = 4;

/// A [`GlobalAlloc`] bridging Rust's allocator to the Zephyr kernel heap
/// (`k_malloc`/`k_free`, sized by `CONFIG_HEAP_MEM_POOL_SIZE`).
///
/// The deploy binary declares it:
/// `#[global_allocator] static ALLOC: ZephyrAllocator = ZephyrAllocator;`.
/// It lives in this profile crate (not the deploy) because — like the FreeRTOS
/// heap — the Zephyr heap IS the kernel's, so every Zephyr deploy routes Rust
/// allocations through it. One audited bridge, shared. Identical over-alignment
/// scheme to `wz_runtime_freertos::FreertosAllocator`.
pub struct ZephyrAllocator;

unsafe impl GlobalAlloc for ZephyrAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() <= HEAP_ALIGN {
            // k_malloc guarantees HEAP_ALIGN-aligned blocks — direct.
            // SAFETY: k_malloc(size) returns a kernel-heap block or null on OOM.
            unsafe { k_malloc(layout.size()) as *mut u8 }
        } else {
            // Over-aligned request (rare on this profile): over-allocate, align
            // up, and stash the k_malloc base pointer in the usize slot just
            // below the returned address so `dealloc` can recover it.
            let align = layout.align();
            let total = layout.size() + align + size_of::<usize>();
            // SAFETY: as above; null is handled below.
            let base = unsafe { k_malloc(total) } as usize;
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
            // SAFETY: `ptr` came from `k_malloc` in the matching `alloc`.
            unsafe { k_free(ptr as *mut c_void) };
        } else {
            // Recover the stashed k_malloc base pointer written by `alloc`.
            // SAFETY: the over-aligned `alloc` branch wrote the base just below.
            let base = unsafe { *((ptr as usize - size_of::<usize>()) as *mut usize) };
            unsafe { k_free(base as *mut c_void) };
        }
    }
}
