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
//! this crate supplies only the Zephyr-specific SEAMS:
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
//! impl (Zephyr/cortex-m has one).
//!
//! 3. R2916 — [`net`], the network seam: UDP over Zephyr's own BSD sockets
//!    and the session's link over them. Networking used to reuse `NO_SYS`
//!    lwIP via `wz-link-lwip`, as the bare-metal and FreeRTOS profiles do,
//!    which has no netif over Zephyr's drivers; zenoh-pico's Zephyr port
//!    uses Zephyr's sockets, and so does this profile now.
//! 4. R2918 — [`ZephyrEntropy`], the session core's `EntropySource`, over the
//!    board hook `wzApplicationGetRandom`, which a board serves from its RNG
//!    (`sys_rand_get`, the call zenoh-pico's Zephyr port makes).
//! 5. R2918 — [`ZephyrEpoch`], the session core's `EpochSource`, over the
//!    board hook `wzApplicationGetTimeSinceEpoch` — the same hook, with the
//!    same contract, the FreeRTOS profile reads — which a board serves from
//!    `clock_gettime(CLOCK_REALTIME)`, the read zenoh-pico's port makes.
//!
//! Both are BOARD hooks rather than FFI to the kernel because neither kernel
//! call is a link symbol this crate can name: `sys_rand_get` is a `__syscall`
//! wrapper, and `getentropy` demands an entropy DEVICE, which a board without
//! a TRNG does not have; `clock_gettime` is real but fills a `struct
//! timespec` whose `time_t` width is the C library's choice, so the hook names
//! fixed-width types instead.
#![no_std]

extern crate alloc;

pub mod net;

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;
use core::mem::size_of;

use wz_runtime_coop::{ClockSource, CoopRuntime};
use zephyr_sys::{k_free, k_malloc, sys_clock_tick_get};

/// Monotonic [`ClockSource`] reading the Zephyr kernel tick counter.
///
/// Const-generic over `TICK_HZ` = the deploy's `CONFIG_SYS_CLOCK_TICKS_PER_SEC`
/// (the reference deploy pins 100). Mirrors the FreeRTOS profile's
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

extern "C" {
    /// R2918 — the board's random source: fill `len` bytes at `buf` and return
    /// 0, or return non-zero when the board cannot produce them. A board serves
    /// it from `sys_rand_get` (what zenoh-pico's Zephyr port calls) or, where it
    /// has one, `sys_csrand_get`.
    fn wzApplicationGetRandom(buf: *mut c_void, len: usize) -> i32;

    /// R2918 — the board's wall clock: fill `*secs` / `*nanos` with the time
    /// since the Unix epoch (UTC, `nanos` below 1e9) and return 1, or return 0
    /// when the board does not know the date (no RTC, SNTP not yet synced). The
    /// same hook and contract the FreeRTOS profile reads, so one board-side
    /// answer serves either RTOS.
    fn wzApplicationGetTimeSinceEpoch(secs: *mut u64, nanos: *mut u32) -> i32;
}

/// R2918 — the session core's [`EntropySource`](wz_session_core::entropy::EntropySource)
/// on this profile: the board's `wzApplicationGetRandom`, asked for the whole
/// buffer in one call. A board that fails the call fails the fill — the cookie
/// nonce and the signing key must never be made of whatever the buffer held.
#[derive(Clone, Copy, Default)]
pub struct ZephyrEntropy;

impl wz_session_core::entropy::EntropySource for ZephyrEntropy {
    fn try_fill_bytes(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(), wz_session_core::entropy::EntropyUnavailable> {
        // SAFETY: `buf` is live and writable for its whole length.
        let rc = unsafe { wzApplicationGetRandom(buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if rc != 0 {
            return Err(wz_session_core::entropy::EntropyUnavailable);
        }
        Ok(())
    }
}

/// R2918 — the session core's [`EpochSource`](wz_session_core::epoch::EpochSource)
/// on this profile: the board's `wzApplicationGetTimeSinceEpoch`, read once
/// per call. A board answer of `nanos >= 1e9` is refused rather than
/// normalised, since it means the hook and this seam disagree about the unit.
#[derive(Clone, Copy, Default)]
pub struct ZephyrEpoch;

impl wz_session_core::epoch::EpochSource for ZephyrEpoch {
    fn try_since_epoch(
        &self,
    ) -> Result<wz_session_core::epoch::SinceEpoch, wz_session_core::epoch::EpochUnavailable> {
        let mut secs = 0u64;
        let mut nanos = 0u32;
        // SAFETY: the hook writes one u64 and one u32 through pointers to live
        // locals; the board's implementation is the application's own.
        let rc = unsafe { wzApplicationGetTimeSinceEpoch(&mut secs, &mut nanos) };
        if rc != 1 || nanos >= 1_000_000_000 {
            return Err(wz_session_core::epoch::EpochUnavailable);
        }
        Ok(wz_session_core::epoch::SinceEpoch { secs, nanos })
    }
}

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

/// R2918 — host witnesses for the profile's seams. On the host there is no
/// Zephyr kernel, so each symbol a seam calls is DEFINED here, answering from a
/// static the test sets: the kernel tick for [`ZephyrClock`], and the two board
/// hooks for [`ZephyrEntropy`] and [`ZephyrEpoch`]. What is under test is the
/// seam's own arithmetic and failure handling, which is the same code the QEMU
/// image runs against the real kernel and board. (The socket link in [`net`]
/// has no such witness: its symbols are the host C library's own names, so it
/// is witnessed on target, by Layer Qz.)
#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicI32, AtomicI64, AtomicU32, AtomicU64, AtomicU8, Ordering};
    use wz_session_core::entropy::{EntropySource, EntropyUnavailable};
    use wz_session_core::epoch::{EpochSource, EpochUnavailable, SinceEpoch};

    static TICKS: AtomicI64 = AtomicI64::new(0);
    static RANDOM_BYTE: AtomicU8 = AtomicU8::new(0);
    static RANDOM_RC: AtomicI32 = AtomicI32::new(0);
    static EPOCH_SECS: AtomicU64 = AtomicU64::new(0);
    static EPOCH_NANOS: AtomicU32 = AtomicU32::new(0);
    static EPOCH_RC: AtomicI32 = AtomicI32::new(1);

    #[no_mangle]
    extern "C" fn sys_clock_tick_get() -> i64 {
        TICKS.load(Ordering::SeqCst)
    }

    #[no_mangle]
    extern "C" fn wzApplicationGetRandom(buf: *mut c_void, len: usize) -> i32 {
        // SAFETY: `ZephyrEntropy` passes a live buffer of `len` bytes.
        let out = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) };
        for b in out {
            *b = RANDOM_BYTE.fetch_add(1, Ordering::SeqCst);
        }
        RANDOM_RC.load(Ordering::SeqCst)
    }

    #[no_mangle]
    extern "C" fn wzApplicationGetTimeSinceEpoch(secs: *mut u64, nanos: *mut u32) -> i32 {
        // SAFETY: `ZephyrEpoch` passes pointers to live locals.
        unsafe {
            *secs = EPOCH_SECS.load(Ordering::SeqCst);
            *nanos = EPOCH_NANOS.load(Ordering::SeqCst);
        }
        EPOCH_RC.load(Ordering::SeqCst)
    }

    #[test]
    fn the_clock_converts_kernel_ticks_to_microseconds_at_the_tick_rate() {
        TICKS.store(1234, Ordering::SeqCst);
        assert_eq!(ZephyrClock::<100>.now_us(), 12_340_000);
        assert_eq!(ZephyrClock::<1000>.now_us(), 1_234_000);
        TICKS.store(i64::from(u32::MAX) * 10, Ordering::SeqCst);
        assert_eq!(
            ZephyrClock::<100>.now_us(),
            u64::from(u32::MAX) * 100_000,
            "a tick count past 32 bits converts without wrapping"
        );
    }

    /// The entropy seam hands the board the whole buffer, and a board that
    /// reports failure fails the fill. One test, because the hook's statics
    /// are shared.
    #[test]
    fn entropy_fills_from_the_board_hook_and_fails_closed() {
        RANDOM_RC.store(0, Ordering::SeqCst);
        RANDOM_BYTE.store(0x10, Ordering::SeqCst);
        let mut buf = [0u8; 5];
        ZephyrEntropy
            .try_fill_bytes(&mut buf)
            .expect("the hook answers 0");
        assert_eq!(buf, [0x10, 0x11, 0x12, 0x13, 0x14]);

        RANDOM_RC.store(-5, Ordering::SeqCst);
        assert_eq!(
            ZephyrEntropy.try_fill_bytes(&mut buf),
            Err(EntropyUnavailable),
            "a non-zero answer from the board fails the fill"
        );
        RANDOM_RC.store(0, Ordering::SeqCst);
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
            ZephyrEpoch.try_since_epoch(),
            Ok(SinceEpoch {
                secs: 1_700_000_000,
                nanos: 250_000_000
            })
        );
        assert_eq!(
            ZephyrEpoch.try_now_ntp64().map(|t| t.to_millis()),
            Ok(1_700_000_000_250)
        );

        EPOCH_NANOS.store(1_000_000_000, Ordering::SeqCst);
        assert_eq!(
            ZephyrEpoch.try_since_epoch(),
            Err(EpochUnavailable),
            "a nanosecond count of a whole second is refused"
        );

        EPOCH_NANOS.store(0, Ordering::SeqCst);
        EPOCH_RC.store(0, Ordering::SeqCst);
        assert_eq!(
            ZephyrEpoch.try_since_epoch(),
            Err(EpochUnavailable),
            "a board that does not know the date says so"
        );
        EPOCH_RC.store(1, Ordering::SeqCst);
    }
}
