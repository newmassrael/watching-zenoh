// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311mi — composable-framework MCU multicast footprint artifact.
//!
//! Links the full MCU multicast feature profile (session-lwip +
//! transport-multicast + transport-fragmentation + codec-push) via
//! [`wz_mcu_multicast_e2e::run_multicast_e2e`] so the Layer Q.5 footprint gate
//! (`scripts/check-footprint.sh`) can size the ROM the multicast transport
//! adds on each Cortex-M target.
//!
//! The e2e LOGIC lives in the `wz-mcu-multicast-e2e` lib, shared verbatim with
//! the host integration test (Layer C1r). This bin is only the SysTick clock +
//! heap + the verdict map.
//!
//! ## Build + size, not a QEMU boot
//!
//! Unlike `deploy/mcu-session-acceptor` (Layer Q.4), this bin is NOT booted in
//! CI: multicast self-loopback needs the host-only `LWIP_LOOPIF_MULTICAST` +
//! `LWIP_TESTMODE` lwIP affordance, so on a QEMU loopback environment
//! `run_multicast_e2e` returns `join_ok=false` (no IGMP netif). The RUNTIME
//! proof of the round trip lives on the host (C1r); this artifact is
//! cross-compiled + `arm-none-eabi-size`d. The `main` below maps the verdict to
//! a semihost exit anyway (it is a genuine `run_multicast_e2e` call, not a
//! footprint-retention trick) so a developer booting it on real multicast
//! hardware gets a host-visible PASS.
//!
//! ## SysTick IRQ-driven clock (same as deploy/mcu-session-acceptor)
//!
//! QEMU's Cortex-M emulation stubs the DWT cycle counter to 0, so monotonic
//! time comes from SysTick poll mode: `TICKINT` fires the `SysTick` exception
//! every 1 ms (RELOAD = CYCLES_PER_US * 1000 - 1 = 24999 at the mps2 25 MHz),
//! the handler bumps a wraparound counter, and `now_us` snaps it either side of
//! the CVR read (the standard ISR-vs-thread lock-free pattern). The multicast
//! profile is mps2-class only (M3/M4/M7; the 32 x 1536 multicast rx pool does
//! not fit nrf51's 16 KB SRAM), so there is no Cortex-M0 / microbit fork.

#![no_std]
#![no_main]

extern crate alloc;

use core::mem::MaybeUninit;

use cortex_m_rt::{entry, exception};
use cortex_m_semihosting::{debug, hprintln};
use embedded_alloc::LlffHeap as Heap;
use panic_semihosting as _;
use portable_atomic::{AtomicU32, Ordering};

use wz_mcu_multicast_e2e::{run_multicast_e2e, ClockSource, LwipLink, MulticastOutcome};

// The mps2 family (M3/M4/M7) has 4 MB SRAM, so a generous 256 KB heap holds
// the alloc-backed multicast stack (the dispatcher + the 32 x 1536 multicast
// rx socket ~49 KB + the reassembly slot pool + the codec byte buffers) with
// room to spare.
const HEAP_SIZE: usize = 1024 * 256;

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// CPU clock (MHz) — QEMU clocks the mps2 family at 25 MHz. SysTick counts
/// processor cycles when `CSR.CLKSOURCE = 1`; dividing by this yields
/// microseconds.
const CYCLES_PER_US: u64 = 25;
/// SysTick reload sized to a 1 ms tick (RELOAD = 24999 cycles at 25 MHz).
const SYST_RELOAD: u32 = (CYCLES_PER_US as u32 * 1000) - 1;
const SYST_PERIOD: u64 = SYST_RELOAD as u64 + 1;

// SysTick MMIO registers (System Control Space; same offsets on every M-class
// core).
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

/// lwIP NO_SYS=1 deploy-provided clock — lwIP's `timeouts.c` calls `sys_now()`
/// (ms since boot) to expire its timer wheel; the deploy owns this symbol on
/// cross targets (`target_os = "none"`). Reads the same [`GLOBAL_CLOCK`] the
/// `ClockSource` impl does.
#[unsafe(no_mangle)]
pub extern "C" fn sys_now() -> u32 {
    (GLOBAL_CLOCK.now_us() / 1000) as u32
}

#[entry]
fn main() -> ! {
    init_heap();
    GLOBAL_CLOCK.init();
    hprintln!("R311mi: MCU multicast transport e2e starting");

    let link = LwipLink::init();
    let report = run_multicast_e2e(&link, SystickClockRef);

    let full_success = report.join_ok
        && report.outcome == Some(MulticastOutcome::IterationLimit)
        && report.peer_admitted
        && report.tx_fragmented
        && report.saw_push
        && !report.saw_drop;

    if !report.join_ok {
        // Expected on a loopback-only environment (QEMU CI): no IGMP netif, so
        // the multicast group join failed and the loop never ran. This bin is
        // build + footprint-size only; the host C1r lane is the runtime proof.
        // A real-IGMP-netif deploy reaches the PASS arm below.
        hprintln!(
            "R311mi SKIP: no multicast IGMP netif (loopback-only env; this is a \
             cross-compile + footprint artifact, not a CI boot — runtime proof \
             is the host C1r lane)"
        );
        debug::exit(debug::EXIT_SUCCESS);
    } else if full_success {
        hprintln!(
            "R311mi PASS: peer admitted + oversize Put fragmented + reassembled \
             into one Push over multicast loopback (active_peers={})",
            report.active_peers,
        );
        debug::exit(debug::EXIT_SUCCESS);
    } else {
        // Joined the group but the round trip degraded — a real regression.
        hprintln!(
            "R311mi FAIL: joined but degraded (outcome={:?} peer_admitted={} \
             tx_fragmented={} saw_push={} saw_drop={} active_peers={})",
            report.outcome,
            report.peer_admitted,
            report.tx_fragmented,
            report.saw_push,
            report.saw_drop,
            report.active_peers,
        );
        debug::exit(debug::EXIT_FAILURE);
    }

    // `debug::exit` terminates QEMU, so this is unreachable; the diverging loop
    // only satisfies the `-> !` entry signature.
    loop {}
}

/// Initialise the heap allocator backing `alloc::*` from a static BSS region.
fn init_heap() {
    static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    // SAFETY: `HEAP_MEM` is a `static mut` accessed only here, before any other
    // code runs (entry point's first action); no aliasing borrow exists.
    unsafe {
        let ptr = core::ptr::addr_of_mut!(HEAP_MEM) as usize;
        HEAP.init(ptr, HEAP_SIZE);
    }
}
