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
//! ## SysTick IRQ-driven clock (shared SSOT: `wz_mcu_clock::SystickClock`)
//!
//! QEMU's Cortex-M emulation stubs the DWT cycle counter to 0, so monotonic
//! time comes from SysTick: `TICKINT` fires the `SysTick` exception every 1 ms
//! (RELOAD = CYCLES_PER_US * 1000 - 1 = 24999 at the mps2 25 MHz), the handler
//! advances a reload counter, and `now_us` snaps it either side of the CVR read
//! (the standard ISR-vs-thread lock-free pattern) then applies a monotonic
//! floor. The clock algorithm lives once in `wz-mcu-clock` (R311y21); this bin
//! only wires the `static`, the `#[exception]` handler, the `sys_now()` symbol,
//! and the `ClockSource` impl. The multicast profile is mps2-class only
//! (M3/M4/M7; the 32 x 1536 multicast rx pool does not fit nrf51's 16 KB SRAM),
//! so there is no Cortex-M0 / microbit fork.

#![no_std]
#![no_main]

extern crate alloc;

use core::mem::MaybeUninit;

use cortex_m_rt::{entry, exception};
use cortex_m_semihosting::{debug, hprintln};
use embedded_alloc::LlffHeap as Heap;
use panic_semihosting as _;
use wz_mcu_clock::SystickClock;

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
/// microseconds. Fed to `SystickClock<CYCLES_PER_US>` as the const-generic
/// frequency; a real deploy substitutes its own silicon frequency.
const CYCLES_PER_US: u64 = 25;

/// The single SysTick clock instance, shared by the `SysTick` exception
/// handler (via `on_tick`), the lwIP `sys_now()` symbol, and the `ClockSource`
/// handle (via `now_us`) so reload accounting stays consistent across all
/// three. The wrap-tear-safe read + monotonic floor + u64 reload counter live
/// once in `wz_mcu_clock::SystickClock` (R311y21 SSOT).
static GLOBAL_CLOCK: SystickClock<{ CYCLES_PER_US }> = SystickClock::new();

/// `SysTick` exception — fires every 1 ms once `GLOBAL_CLOCK.init()` enables
/// `TICKINT`; advances the reload counter and nothing else (short ISR).
#[exception]
fn SysTick() {
    GLOBAL_CLOCK.on_tick();
}

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
    // R311y190 — with `loopback-multicast`, route multicast TX egress over the
    // loop netif BEFORE the drive loop so `run_multicast_e2e` completes a REAL
    // on-target IGMP-join + multicast-loopback roundtrip (the no_std promotion of
    // lwip_test_link's host routing). The FFI is linked only when the port sets
    // LWIP_TESTMODE (cross-test-mcast) — a mismatched build fails to compile. The
    // group JOIN itself succeeds via the port's LWIP_LOOPIF_MULTICAST flag.
    #[cfg(feature = "loopback-multicast")]
    link.route_multicast_over_loopback()
        .expect("loopback-multicast build routes multicast TX over the loop netif");
    let report = run_multicast_e2e(&link, SystickClockRef);

    let full_success = report.join_ok
        && report.outcome == Some(MulticastOutcome::IterationLimit)
        && report.peer_admitted
        && report.tx_fragmented
        && report.saw_push
        && !report.saw_drop;

    // The loopback-only SKIP concession applies ONLY to the plain-link build (the
    // cross-compile + footprint artifact): on QEMU with no routed multicast netif
    // the join fails and the host C1r lane is the runtime proof. With
    // `loopback-multicast` the TX is routed over the loop netif, so a failed join
    // is a REAL regression (the FAIL arm below), not an expected skip.
    #[cfg(not(feature = "loopback-multicast"))]
    if !report.join_ok {
        hprintln!(
            "R311mi SKIP: no multicast IGMP netif (loopback-only env; this is a \
             cross-compile + footprint artifact, not a CI boot — runtime proof \
             is the host C1r lane, or a `loopback-multicast` build)"
        );
        debug::exit(debug::EXIT_SUCCESS);
    }

    if full_success {
        hprintln!(
            "R311mi PASS: peer admitted + oversize Put fragmented + reassembled \
             into one Push over multicast loopback (active_peers={})",
            report.active_peers,
        );
        debug::exit(debug::EXIT_SUCCESS);
    } else {
        // A degraded round trip — a real regression (join_ok surfaced so a
        // `loopback-multicast` build that fails the join is not misread as
        // "joined but degraded").
        hprintln!(
            "R311mi FAIL: multicast roundtrip degraded (join_ok={} outcome={:?} \
             peer_admitted={} tx_fragmented={} saw_push={} saw_drop={} \
             active_peers={})",
            report.join_ok,
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
