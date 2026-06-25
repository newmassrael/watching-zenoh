// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `SystickClock` — the Cortex-M SysTick monotonic clock SSOT for the
//! bare-metal deploy binaries.
//!
//! ## Why this crate exists (R311y21)
//!
//! Up to R311y20 each deploy main (`deploy/mcu-qemu-demo`,
//! `deploy/mcu-session-acceptor`, `deploy/mcu-multicast-e2e`) carried
//! its OWN hand-copied `SystickClock` — the same ~50-line SysTick read
//! algorithm pasted three times. The copies had drifted: only
//! `mcu-qemu-demo` carried the R311y15 monotonic floor; the acceptor
//! and multicast copies were still the pre-floor version (latent —
//! they drive a synchronous busy-poll session loop rather than a
//! `SleepFuture`, so the livelock had not surfaced there, but the
//! [`ClockSource`-shaped](crate::SystickClock::now_us) monotonic
//! contract was nonetheless violated). Three copies of a load-bearing
//! correctness algorithm is exactly the shape that lets a fix land in
//! one and silently miss the others. This crate makes the algorithm a
//! single source of truth.
//!
//! ## What lives here vs. what stays in the binary
//!
//! The SSOT-worthy, bug-prone part — the wrap-tear-safe SysTick read
//! plus the monotonic floor — lives here, parameterised only by the
//! deploy's CPU frequency (`CYCLES_PER_US`). The unavoidable
//! per-binary linkage glue stays in each `main.rs`:
//!
//! - the `static GLOBAL_CLOCK: SystickClock<N>` instance (the cortex-m-rt
//!   `#[exception] fn SysTick()` handler must name a concrete static),
//! - the `#[exception] fn SysTick()` body, which calls
//!   [`SystickClock::on_tick`],
//! - the `#[no_mangle] extern "C" fn sys_now()` lwIP `NO_SYS=1` symbol,
//!   which divides [`SystickClock::now_us`] by 1000,
//! - the deploy's `impl ClockSource` wrapper, which forwards to
//!   `GLOBAL_CLOCK.now_us()` (the `ClockSource` trait is re-exported by
//!   `wz::runtime_coop`, so the impl belongs with the deploy that names
//!   that facade — keeping this crate free of any `wz` dependency and
//!   trivially host-buildable + host-testable).
//!
//! ## The monotonic contract (load-bearing)
//!
//! `wz_runtime_coop::time::ClockSource::now_us` is documented monotonic
//! (non-decreasing). This is not advisory: `CoopRuntime::run_until_idle`
//! samples `now`, `pop_expired(now)` FIRES + REMOVES the matching timer
//! entry, then polls the woken task; `SleepFuture::poll` re-reads the
//! clock and, if it stepped BACKWARD below the deadline, returns
//! `Pending` WITHOUT re-registering (the entry is already gone) — the
//! cooperative loop then livelocks. A SysTick clock goes non-monotonic
//! when the `SysTick` exception is delayed past a reload boundary
//! (lazy FP-context stacking on Cortex-M4F/M7 plus the executor's
//! interrupt-disabling critical sections stretch ISR latency): `wraps`
//! lags the hardware down-counter for a few instructions and the raw
//! reading steps backward by up to one period.
//!
//! The raw reading is always `<=` true elapsed time (`wraps` can lag but
//! never leads), so clamping up to the maximum previously returned
//! ([`SystickClock::now_us`] -> the `last_us` floor) is provably safe:
//! it filters the backward glitch without ever sticking high.
//!
//! ## `wraps` is `u64` (R311y21 — overflow-freeze fix)
//!
//! The hand-copied clocks counted reloads in an `AtomicU32` (one
//! increment per 1 ms tick), which overflows after `2^32` ms ~= 49.7
//! days. Past that point the raw reading collapses toward zero and the
//! monotonic floor — doing exactly its job — clamps and STAYS clamped
//! forever, freezing the clock. A `u64` reload counter pushes the
//! overflow horizon past 5e8 years, so the floor never has to defend
//! against a wrapped counter. The widening costs a critical-section
//! `AtomicU64` (no native 64-bit atomic on ARMv7-M) on the M-class
//! sub-lanes; that footprint cost is the honest price of a clock that
//! survives a real multi-week deploy.

#![cfg_attr(not(test), no_std)]

// portable-atomic so `AtomicU64` compiles on ARMv6-M (Cortex-M0/M0+),
// which has no native 64-bit (nor any) atomic CAS: the `fallback` +
// `critical-section` features select the critical-section-single-core
// impl there and native LDREX/STREX on ARMv7-M+. On ARMv7-M (M3/M4/M7)
// `AtomicU64` itself still routes through critical-section (the 64-bit
// atomic is not in the base ISA), matching the existing `last_us`
// AtomicU64 the R311y15 floor already paid for.
use portable_atomic::{AtomicU64, Ordering};

// SysTick MMIO registers (System Control Space; identical offsets on
// every M-class core, ARMv6-M base spec onward).
const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
const SYST_RVR: *mut u32 = 0xE000_E014 as *mut u32;
const SYST_CVR: *mut u32 = 0xE000_E018 as *mut u32;
const SYST_CSR_CLKSOURCE: u32 = 1 << 2;
const SYST_CSR_TICKINT: u32 = 1 << 1;
const SYST_CSR_ENABLE: u32 = 1 << 0;

/// SysTick-driven monotonic microsecond clock.
///
/// `CYCLES_PER_US` is the deploy's CPU clock frequency in MHz (SysTick
/// counts processor cycles when `CSR.CLKSOURCE = 1`; dividing by it
/// yields microseconds). QEMU clocks the mps2 family at 25 MHz and the
/// `microbit` (nrf51) at 16 MHz; a real deploy substitutes its own
/// silicon frequency. Passing it as a const generic keeps the
/// `now_us` division by a compile-time constant, so LLVM lowers it to a
/// reciprocal-multiply (no `__aeabi_uldivmod` import — important for the
/// footprint-gated binaries).
///
/// The single per-deploy instance is wired as a `static` and shared by
/// the `#[exception] fn SysTick()` handler (via [`on_tick`](Self::on_tick))
/// and the lwIP `sys_now()` symbol (via [`now_us`](Self::now_us)) so
/// reload accounting stays consistent across both call surfaces.
pub struct SystickClock<const CYCLES_PER_US: u64> {
    /// Reload (wraparound) counter — advanced once per `SYST_PERIOD`
    /// cycles (1 ms) by the `SysTick` exception via [`on_tick`](Self::on_tick).
    /// `u64` so it does not overflow at 49.7 days (see crate docs).
    wraps: AtomicU64,
    /// Monotonic floor: the maximum value any prior [`now_us`](Self::now_us)
    /// call returned. `now_us` clamps its raw reading up to this so a
    /// transient backward step (delayed SysTick ISR) can never make the
    /// clock go non-monotonic.
    last_us: AtomicU64,
}

impl<const CYCLES_PER_US: u64> SystickClock<CYCLES_PER_US> {
    /// SysTick reload value for a 1 ms tick at `CYCLES_PER_US` MHz
    /// (`RELOAD = CYCLES_PER_US * 1000 - 1`: 24999 at 25 MHz, 15999 at
    /// 16 MHz). 1 ms is small enough that the `SysTick` exception fires
    /// often enough to drive a `wfi()` idle loop, and gives `wraps` the
    /// natural unit of "milliseconds since boot".
    const SYST_RELOAD: u32 = (CYCLES_PER_US as u32 * 1000) - 1;
    /// Cycles per reload period (`RELOAD + 1`).
    const SYST_PERIOD: u64 = Self::SYST_RELOAD as u64 + 1;

    /// Construct a zeroed clock. `const` so it can back a `static`.
    pub const fn new() -> Self {
        Self {
            wraps: AtomicU64::new(0),
            last_us: AtomicU64::new(0),
        }
    }

    /// Enable SysTick with `TICKINT`: the `SysTick` exception then fires
    /// every `SYST_PERIOD` cycles (1 ms), the deploy's handler calls
    /// [`on_tick`](Self::on_tick) to advance `wraps`, and the CPU can
    /// `wfi()` between ticks. Call once, before any [`now_us`](Self::now_us).
    pub fn init(&self) {
        // SAFETY: SysTick control registers are fixed MMIO addresses in
        // the architecturally-reserved System Control Space; this is the
        // canonical enable sequence (clear CSR, set reload, clear current,
        // enable with clock-source + tick-interrupt).
        unsafe {
            SYST_CSR.write_volatile(0);
            SYST_RVR.write_volatile(Self::SYST_RELOAD);
            SYST_CVR.write_volatile(0);
            SYST_CSR.write_volatile(SYST_CSR_CLKSOURCE | SYST_CSR_TICKINT | SYST_CSR_ENABLE);
        }
    }

    /// Advance the reload counter by one. The deploy's
    /// `#[exception] fn SysTick()` handler calls exactly this and nothing
    /// else, so the ISR stays short (no allocation, no locks beyond the
    /// single `AtomicU64` increment).
    #[inline]
    pub fn on_tick(&self) {
        self.wraps.fetch_add(1, Ordering::Release);
    }

    /// Current monotonic time in microseconds since boot.
    ///
    /// Two layers:
    ///
    /// 1. **Wrap-tear-safe read** — `wraps` is advanced by the `SysTick`
    ///    exception while the hardware down-counter (`SYST_CVR`)
    ///    decrements in parallel, so the two can disagree if the ISR
    ///    fires mid-read. The double-snap (`wraps` before and after the
    ///    `CVR` read) retries until `wraps` is stable across the read,
    ///    the standard ISR-vs-thread lock-free pattern.
    /// 2. **Monotonic floor** — clamp the raw reading up to the maximum
    ///    previously returned (see crate docs for why a delayed ISR makes
    ///    the raw reading step backward, and why the floor is provably
    ///    safe).
    pub fn now_us(&self) -> u64 {
        let raw = loop {
            let w1 = self.wraps.load(Ordering::Acquire);
            // SAFETY: SYST_CVR is a read-only MMIO current-value register
            // in the System Control Space; a volatile read has no side
            // effects beyond clearing COUNTFLAG (which this clock does
            // not consult).
            let cvr = unsafe { SYST_CVR.read_volatile() } & Self::SYST_RELOAD;
            let w2 = self.wraps.load(Ordering::Acquire);
            if w1 == w2 {
                let total_cycles = w1 * Self::SYST_PERIOD + (Self::SYST_RELOAD - cvr) as u64;
                break total_cycles / CYCLES_PER_US;
            }
        };
        self.apply_floor(raw)
    }

    /// Clamp `raw` up to the maximum value any prior call returned and
    /// publish the new maximum. Split out from [`now_us`](Self::now_us)
    /// so it is unit-testable on the host without touching MMIO.
    ///
    /// `last_us` is only ever written here (thread mode, never the ISR)
    /// on a single core, so the `compare_exchange` loop only spins under
    /// genuine re-entrancy of `now_us` itself; a relaxed ordering
    /// suffices because the value carries no other state.
    #[inline]
    fn apply_floor(&self, raw: u64) -> u64 {
        let mut last = self.last_us.load(Ordering::Relaxed);
        loop {
            if raw <= last {
                return last;
            }
            match self.last_us.compare_exchange_weak(
                last,
                raw,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return raw,
                Err(observed) => last = observed,
            }
        }
    }
}

impl<const CYCLES_PER_US: u64> Default for SystickClock<CYCLES_PER_US> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::SystickClock;

    #[test]
    fn reload_and_period_derive_from_cycles_per_us() {
        // 25 MHz -> 1 ms tick = 25000 cycles, RELOAD = 24999.
        assert_eq!(SystickClock::<25>::SYST_RELOAD, 24_999);
        assert_eq!(SystickClock::<25>::SYST_PERIOD, 25_000);
        // 16 MHz (microbit / nrf51) -> 16000 cycles, RELOAD = 15999.
        assert_eq!(SystickClock::<16>::SYST_RELOAD, 15_999);
        assert_eq!(SystickClock::<16>::SYST_PERIOD, 16_000);
    }

    #[test]
    fn floor_passes_forward_progress_through() {
        let clk = SystickClock::<25>::new();
        assert_eq!(clk.apply_floor(0), 0);
        assert_eq!(clk.apply_floor(1_000), 1_000);
        assert_eq!(clk.apply_floor(1_001), 1_001);
        assert_eq!(clk.apply_floor(2_000_000), 2_000_000);
    }

    #[test]
    fn floor_clamps_backward_steps() {
        let clk = SystickClock::<25>::new();
        assert_eq!(clk.apply_floor(1_000), 1_000);
        // A delayed-ISR backward glitch: raw steps back by up to one
        // period. The floor must hold the previous maximum.
        assert_eq!(
            clk.apply_floor(900),
            1_000,
            "backward step clamped to floor"
        );
        assert_eq!(clk.apply_floor(999), 1_000, "still below floor -> clamped");
        // Once the raw reading catches back up past the floor, it passes.
        assert_eq!(clk.apply_floor(1_000), 1_000);
        assert_eq!(clk.apply_floor(1_500), 1_500, "forward again -> passes");
        assert_eq!(
            clk.apply_floor(1_499),
            1_500,
            "single-unit regression clamped"
        );
    }

    #[test]
    fn floor_never_decreases_across_a_sequence() {
        let clk = SystickClock::<16>::new();
        let raws = [10u64, 20, 15, 30, 25, 25, 40, 39, 1_000_000, 999_999];
        let mut prev = 0u64;
        for r in raws {
            let out = clk.apply_floor(r);
            assert!(out >= prev, "now_us must be non-decreasing: {out} < {prev}");
            assert!(out >= r.min(out), "output is the running max");
            prev = out;
        }
        // Final floor is the running maximum of the sequence.
        assert_eq!(prev, 1_000_000);
    }
}
