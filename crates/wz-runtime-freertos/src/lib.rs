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
//! 3. R2913 — [`FreertosEntropy`], the session core's
//!    entropy port over the FreeRTOS application hook
//!    `xApplicationGetRandomNumber`, the one zenoh-pico's FreeRTOS port draws
//!    from (`vendor/zenoh-pico/src/system/freertos/system.c`, `z_random_u32`).
//! 4. R2914 — [`FreertosEpoch`], the session core's
//!    time-since-epoch port over the board hook
//!    `wzApplicationGetTimeSinceEpoch`, the read zenoh-pico's FreeRTOS port
//!    makes through `gettimeofday` (`_z_get_time_since_epoch`).
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

extern "C" {
    /// R2914 — the board's wall clock: fill `*secs` / `*nanos` with the time
    /// since the Unix epoch (UTC, `nanos` below 1e9) and return `pdTRUE`, or
    /// return `pdFALSE` when the board does not know the date (no RTC, SNTP not
    /// yet synced). zenoh-pico's FreeRTOS port reads the same instant through
    /// `gettimeofday`; this hook names fixed-width types instead, because
    /// `struct timeval`'s `time_t` differs across newlib builds and the Rust
    /// side has to agree with it byte for byte.
    fn wzApplicationGetTimeSinceEpoch(secs: *mut u64, nanos: *mut u32) -> freertos_sys::BaseType_t;
}

/// R2914 — the session core's [`EpochSource`](wz_session_core::epoch::EpochSource)
/// on this profile: the board's `wzApplicationGetTimeSinceEpoch`, read once per
/// call. A board answer of `nanos >= 1e9` is refused rather than normalised,
/// since it means the hook and this seam disagree about the unit.
#[derive(Clone, Copy, Default)]
pub struct FreertosEpoch;

impl wz_session_core::epoch::EpochSource for FreertosEpoch {
    fn try_since_epoch(
        &self,
    ) -> Result<wz_session_core::epoch::SinceEpoch, wz_session_core::epoch::EpochUnavailable> {
        let mut secs = 0u64;
        let mut nanos = 0u32;
        // SAFETY: the hook writes one u64 and one u32 through pointers to live
        // locals; the board's implementation is the application's own.
        let rc = unsafe { wzApplicationGetTimeSinceEpoch(&mut secs, &mut nanos) };
        if rc != PD_TRUE || nanos >= 1_000_000_000 {
            return Err(wz_session_core::epoch::EpochUnavailable);
        }
        Ok(wz_session_core::epoch::SinceEpoch { secs, nanos })
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

/// R2914 — host witnesses for the profile's seams. On the host `freertos-sys`
/// builds no kernel, so each symbol a seam calls is DEFINED here, answering from
/// a static the test sets: the kernel tick for [`FreertosClock`], and the two
/// board hooks for [`FreertosEntropy`] and [`FreertosEpoch`]. What is under test
/// is the seam's own arithmetic and failure handling, which is the same code the
/// QEMU image runs against the real kernel and board.
#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
    use wz_session_core::entropy::{EntropySource, EntropyUnavailable};
    use wz_session_core::epoch::{EpochSource, EpochUnavailable, SinceEpoch};

    static TICKS: AtomicU32 = AtomicU32::new(0);
    static NEXT_RANDOM: AtomicU32 = AtomicU32::new(0);
    static RANDOM_RC: AtomicI32 = AtomicI32::new(1);
    static EPOCH_SECS: AtomicU64 = AtomicU64::new(0);
    static EPOCH_NANOS: AtomicU32 = AtomicU32::new(0);
    static EPOCH_RC: AtomicI32 = AtomicI32::new(1);

    #[no_mangle]
    extern "C" fn xTaskGetTickCount() -> freertos_sys::TickType_t {
        TICKS.load(Ordering::SeqCst)
    }

    #[no_mangle]
    extern "C" fn xApplicationGetRandomNumber(pul_number: *mut u32) -> freertos_sys::BaseType_t {
        // SAFETY: `FreertosEntropy` passes a pointer to a live u32.
        unsafe { *pul_number = NEXT_RANDOM.fetch_add(1, Ordering::SeqCst) };
        RANDOM_RC.load(Ordering::SeqCst)
    }

    #[no_mangle]
    extern "C" fn wzApplicationGetTimeSinceEpoch(
        secs: *mut u64,
        nanos: *mut u32,
    ) -> freertos_sys::BaseType_t {
        // SAFETY: `FreertosEpoch` passes pointers to live locals.
        unsafe {
            *secs = EPOCH_SECS.load(Ordering::SeqCst);
            *nanos = EPOCH_NANOS.load(Ordering::SeqCst);
        }
        EPOCH_RC.load(Ordering::SeqCst)
    }

    #[test]
    fn the_clock_converts_kernel_ticks_to_microseconds_at_the_tick_rate() {
        TICKS.store(1234, Ordering::SeqCst);
        assert_eq!(FreertosClock::<1000>.now_us(), 1_234_000);
        assert_eq!(FreertosClock::<100>.now_us(), 12_340_000);
        TICKS.store(u32::MAX, Ordering::SeqCst);
        assert_eq!(
            FreertosClock::<1000>.now_us(),
            u32::MAX as u64 * 1000,
            "a full-width tick count converts without overflow"
        );
    }

    /// The entropy seam draws 32 bits per hook call, little-endian, and a short
    /// last chunk takes the low bytes; a hook that reports failure fails the
    /// whole fill. One test, because the hook's statics are shared.
    #[test]
    fn entropy_fills_from_the_board_hook_and_fails_closed() {
        RANDOM_RC.store(1, Ordering::SeqCst);
        NEXT_RANDOM.store(0x0403_0201, Ordering::SeqCst);
        let mut buf = [0u8; 6];
        FreertosEntropy
            .try_fill_bytes(&mut buf)
            .expect("the hook answers pdTRUE");
        assert_eq!(buf, [0x01, 0x02, 0x03, 0x04, 0x02, 0x02]);

        RANDOM_RC.store(0, Ordering::SeqCst);
        assert_eq!(
            FreertosEntropy.try_fill_bytes(&mut buf),
            Err(EntropyUnavailable),
            "pdFALSE from the board fails the fill"
        );
        RANDOM_RC.store(1, Ordering::SeqCst);
    }

    /// The epoch seam returns the board's instant, refuses a failed read and a
    /// nanosecond count outside a second, and feeds the NTP64 a timestamp
    /// carries. One test, because the hook's statics are shared.
    #[test]
    fn epoch_reads_the_board_clock_and_refuses_what_it_cannot_trust() {
        EPOCH_RC.store(1, Ordering::SeqCst);
        EPOCH_SECS.store(1_700_000_000, Ordering::SeqCst);
        EPOCH_NANOS.store(250_000_000, Ordering::SeqCst);
        assert_eq!(
            FreertosEpoch.try_since_epoch(),
            Ok(SinceEpoch {
                secs: 1_700_000_000,
                nanos: 250_000_000
            })
        );
        assert_eq!(
            FreertosEpoch.try_now_ntp64().map(|t| t.to_millis()),
            Ok(1_700_000_000_250)
        );

        EPOCH_NANOS.store(1_000_000_000, Ordering::SeqCst);
        assert_eq!(
            FreertosEpoch.try_since_epoch(),
            Err(EpochUnavailable),
            "a nanosecond count of a whole second is refused"
        );

        EPOCH_NANOS.store(0, Ordering::SeqCst);
        EPOCH_RC.store(0, Ordering::SeqCst);
        assert_eq!(
            FreertosEpoch.try_since_epoch(),
            Err(EpochUnavailable),
            "a board that does not know the date says so"
        );
        EPOCH_RC.store(1, Ordering::SeqCst);
    }
}
