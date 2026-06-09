// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Stage 5 — Layer Q.4 QEMU acceptor session e2e.
//!
//! Boots [`wz_mcu_session_acceptor::run_acceptor_e2e`] on a Cortex-M3/M4/M7
//! (and, on the slim buffer-pool profile, Cortex-M0 / microbit)
//! under QEMU with a real lwIP cross-build: the acceptor half of the zenoh
//! unicast handshake (InitSyn -> InitAck -> OpenSyn with the real
//! round-tripped cookie -> OpenAck -> Established) followed by an
//! application Frame dispatch, over a live lwIP loopback, driven by the
//! Stage 4b `wz_session_lwip::run_session` sync loop.
//!
//! The e2e LOGIC lives in the `wz-mcu-session-acceptor` lib, shared verbatim
//! with the host integration test (Layer C1n). This bin is only the SysTick
//! clock + heap + the PASS/FAIL verdict: it semihosts `Stage5 PASS` /
//! `Stage5 FAIL <report>` and calls `debug::exit`, whose SYS_EXIT code the
//! Layer Q.4 lane in scripts/run-ci.sh asserts on.
//!
//! ## SysTick IRQ-driven clock (same as deploy/mcu-qemu-demo)
//!
//! QEMU's Cortex-M emulation stubs the DWT cycle counter to 0, so monotonic
//! time comes from SysTick poll mode: `TICKINT` fires the `SysTick`
//! exception every 1 ms (RELOAD = CYCLES_PER_US * 1000 - 1: 24999 at the
//! mps2 25 MHz, 15999 at the microbit 16 MHz), the handler bumps a
//! wraparound counter, and `now_us` snaps it either side of the CVR read
//! (the standard ISR-vs-thread lock-free pattern). SysTick is ARMv6-M base
//! spec onward, so the same impl boots on every M-class machine the Layer
//! Q.4 lane targets: the mps2 family (M3 / M4 / M7) and — on the slim
//! buffer-pool profile (buffer-pool-session-rx-slim) — the microbit
//! (Cortex-M0), whose ~3.15 KB slim peak heap fits nrf51's 16 KB SRAM.

#![no_std]
#![no_main]

extern crate alloc;

use core::mem::MaybeUninit;

use cortex_m_rt::{entry, exception};
use cortex_m_semihosting::{debug, hprintln};
use embedded_alloc::LlffHeap as Heap;
use panic_semihosting as _;
use portable_atomic::{AtomicU32, Ordering};

use wz_mcu_session_acceptor::{run_acceptor_e2e, AcceptorE2eOutcome, ClockSource, DataMode};

// Heap sizing fork per target SRAM budget. The mps2 family (M3/M4/M7) has
// 4 MB SRAM, so a generous 256 KB heap holds the alloc-backed session stack
// (SessionLinkActions handle + the engine + the codec byte buffers) with
// room to spare. The microbit (Cortex-M0, nrf51822) has 16 KB SRAM total;
// the thumbv6m build is the slim profile (buffer-pool-session-rx-slim), whose
// measured peak heap is ~3.15 KB (vs ~32 KB on the default pool), so a 4 KB
// heap holds it (matching deploy/mcu-qemu-demo's microbit heap) while leaving
// lwIP's static MEM_SIZE + stack + .bss inside the remaining ~12 KB.
#[cfg(target_has_atomic = "32")]
const HEAP_SIZE: usize = 1024 * 256;
#[cfg(not(target_has_atomic = "32"))]
const HEAP_SIZE: usize = 1024 * 4;

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// CPU clock per target (MHz) — QEMU clocks the mps2 family at 25 MHz and the
/// `microbit` (nrf51) at 16 MHz. SysTick counts processor cycles when
/// `CSR.CLKSOURCE = 1`; dividing by this yields microseconds.
#[cfg(target_has_atomic = "32")]
const CYCLES_PER_US: u64 = 25;
#[cfg(not(target_has_atomic = "32"))]
const CYCLES_PER_US: u64 = 16;
/// SysTick reload sized to a 1 ms tick (RELOAD = 24999 cycles at 25 MHz).
const SYST_RELOAD: u32 = (CYCLES_PER_US as u32 * 1000) - 1;
const SYST_PERIOD: u64 = SYST_RELOAD as u64 + 1;

// SysTick MMIO registers (System Control Space; same offsets on every
// M-class core).
const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
const SYST_RVR: *mut u32 = 0xE000_E014 as *mut u32;
const SYST_CVR: *mut u32 = 0xE000_E018 as *mut u32;
const SYST_CSR_CLKSOURCE: u32 = 1 << 2;
const SYST_CSR_TICKINT: u32 = 1 << 1;
const SYST_CSR_ENABLE: u32 = 1 << 0;

/// Interrupt-incremented wraparound counter — `wraps` advances once per 1 ms
/// reload from the `SysTick` exception; `now_us` reconstructs microseconds.
struct SystickClock {
    wraps: AtomicU32,
}

impl SystickClock {
    const fn new() -> Self {
        Self {
            wraps: AtomicU32::new(0),
        }
    }

    fn init(&self) {
        unsafe {
            SYST_CSR.write_volatile(0);
            SYST_RVR.write_volatile(SYST_RELOAD);
            SYST_CVR.write_volatile(0);
            SYST_CSR.write_volatile(SYST_CSR_CLKSOURCE | SYST_CSR_TICKINT | SYST_CSR_ENABLE);
        }
    }

    fn now_us(&self) -> u64 {
        // Double-snap: if `wraps` advanced during the CVR read, the snapshot
        // belongs to a different period — retry until `wraps` is stable.
        loop {
            let w1 = self.wraps.load(Ordering::Acquire);
            let cvr = unsafe { SYST_CVR.read_volatile() } & SYST_RELOAD;
            let w2 = self.wraps.load(Ordering::Acquire);
            if w1 == w2 {
                let total_cycles = w1 as u64 * SYST_PERIOD + (SYST_RELOAD - cvr) as u64;
                return total_cycles / CYCLES_PER_US;
            }
        }
    }
}

#[exception]
fn SysTick() {
    GLOBAL_CLOCK.wraps.fetch_add(1, Ordering::Release);
}

/// The single SysTick instance shared by the `ClockSource` handle and the
/// lwIP-side `sys_now()` so wrap accounting stays consistent across both.
static GLOBAL_CLOCK: SystickClock = SystickClock::new();

/// Zero-sized [`ClockSource`] forwarding every `now_us` to [`GLOBAL_CLOCK`].
#[derive(Clone, Copy, Default)]
struct SystickClockRef;

impl ClockSource for SystickClockRef {
    fn now_us(&self) -> u64 {
        GLOBAL_CLOCK.now_us()
    }
}

/// lwIP NO_SYS=1 deploy-provided clock — lwIP's `timeouts.c` calls
/// `sys_now()` (ms since boot) to expire its timer wheel; the deploy owns
/// this symbol on cross targets (`target_os = "none"`). Reads the same
/// [`GLOBAL_CLOCK`] the `ClockSource` impl does.
#[unsafe(no_mangle)]
pub extern "C" fn sys_now() -> u32 {
    (GLOBAL_CLOCK.now_us() / 1000) as u32
}

/// Post-handshake data plane the boot exercises. The default build proves
/// the whole-`T_MID_FRAME` dispatch (Stage 5); `--features reassembly`
/// switches it to a `T_MID_FRAGMENT` chain the acceptor reassembles +
/// dispatches (Tier B on-target proof). Compile-time selection because lwIP
/// NO_SYS is process-global single-init, so one QEMU boot runs one scenario.
#[cfg(not(feature = "reassembly"))]
const DATA_MODE: DataMode = DataMode::WholeFrame;
#[cfg(feature = "reassembly")]
const DATA_MODE: DataMode = DataMode::FragmentChain;

#[entry]
fn main() -> ! {
    init_heap();
    GLOBAL_CLOCK.init();
    hprintln!("Stage5: MCU acceptor session e2e starting");

    // No-op fragment hook: the on-target clock is the real SysTick (never
    // artificially advanced); the advancing-clock seam is host-test-only.
    let report = run_acceptor_e2e(SystickClockRef, DATA_MODE, || {});
    match report.outcome {
        AcceptorE2eOutcome::EstablishedAndDispatched => {
            hprintln!(
                "Stage5 PASS: Established + Frame dispatched (advanced_fsm={} cookie_len={})",
                report.advanced_fsm,
                report.peer_cookie_len,
            );
            debug::exit(debug::EXIT_SUCCESS);
        }
        other => {
            // Surface the full per-stage report so a stalled handshake is
            // locatable on target without a debugger.
            hprintln!(
                "Stage5 FAIL: {:?} (advanced_fsm={} side_effect={} parse_error={} \
                 frame_payload={} initack_seen={} cookie_len={} opensyn_sent={} \
                 openack_seen={} frame_sent={} peer_rx={} init_ack_fired={} open_ack_fired={})",
                other,
                report.advanced_fsm,
                report.side_effect,
                report.parse_error,
                report.frame_payload,
                report.peer_initack_seen,
                report.peer_cookie_len,
                report.peer_opensyn_sent,
                report.peer_openack_seen,
                report.peer_frame_sent,
                report.peer_rx_count,
                report.init_ack_action_fired,
                report.open_ack_action_fired,
            );
            debug::exit(debug::EXIT_FAILURE);
        }
    }

    // `debug::exit` terminates QEMU, so this is unreachable; the diverging
    // loop only satisfies the `-> !` entry signature.
    loop {}
}

/// Initialise the heap allocator backing `alloc::*` from a static BSS region.
fn init_heap() {
    static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    // SAFETY: `HEAP_MEM` is a `static mut` accessed only here, before any
    // other code runs (entry point's first action); no aliasing borrow exists.
    unsafe {
        let ptr = core::ptr::addr_of_mut!(HEAP_MEM) as usize;
        HEAP.init(ptr, HEAP_SIZE);
    }
}
