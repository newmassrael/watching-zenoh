// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311be — QEMU `mps2-an386` UDP loopback e2e demo.
//!
//! Composes every Phase W primitive landed R311au → R311bd into a
//! single Cortex-M3 binary that boots under QEMU, brings up lwIP's
//! loopback netif, sends a UDP datagram to 127.0.0.1:5555, and
//! verifies the echo arrives via the same socket's recv callback.
//!
//! Success path writes `R311be PASS` to the QEMU semihost channel
//! and calls `debug::exit(EXIT_SUCCESS)`; the QEMU process exits
//! with status 0 and the Layer Q lane in `scripts/run-ci.sh`
//! interprets that as PASS. Failure path writes `R311be FAIL`,
//! exits with EXIT_FAILURE.
//!
//! ## Why this is the FULL closure mantissa
//!
//! Up to R311ay the Phase W ladder reached "preset-cortex-m4-default
//! catalog truthfulness" — i.e. the cargo feature graph + crate
//! cross-compile correctly resolves an MCU preset. R311az-1..3c
//! lifted that into "lwip-sys cross-real builds + wz facade
//! `runtime-lwip` re-exports the link tier". R311bc + R311bd
//! made `LwipRuntime` honest (real timer queue + abort).
//!
//! What was still missing: proof that all of the above actually
//! RUNS on a non-host target. R311be closes that — every
//! abstraction the catalog claims to ship is exercised end-to-end
//! on Cortex-M3 emulation:
//!
//! - cortex-m + cortex-m-rt entry → wz facade composition under
//!   `#![no_std]` (R311am Layer G.2 + R311ax G.5).
//! - critical_section + portable-atomic polyfill paths → lwip-sys
//!   FFI invocations → lwIP NO_SYS=1 loopback netif.
//! - LwipRuntime task pool → spawned `async` closure → `LwipTime::
//!   sleep` registering on the R311bc TimerQueue → wake on the
//!   next `run_until_idle` pass after the loopback callback
//!   enqueues the datagram.
//!
//! ## Why SysTick IRQ-driven `ClockSource` + `wfi()` main loop
//!
//! R311bi migrated the clock source from DWT cycle counter (which
//! QEMU 6.2's Cortex-M3 emulation stubs to 0) to SysTick poll mode.
//! R311bi closes R311be carry #2 by enabling SysTick `TICKINT` and
//! providing a `SysTick` exception handler so the wraparound count
//! advances from the ISR, the CPU can `wfi()` between ticks
//! (genuine power-down between IRQs — proving the R311bc
//! TimerQueue + LwipTime::sleep path uses the runtime services
//! tier the way a real MCU deploy would), and the demo's tight
//! poll loop becomes interrupt-driven.
//!
//! Reload value: 1 ms at 25 MHz (RELOAD = 24999 cycles per tick).
//! Picked so the demo's 1 ms sleep budget surfaces one ISR per
//! sleep iteration; the `wraps` AtomicU32 represents milliseconds
//! since boot, and `now_us` snaps `wraps` either side of the CVR
//! read to detect ISR firing during the sample (re-loops on
//! mismatch — the standard ISR-vs-thread lock-free read pattern
//! for an interrupt-incremented counter + a hardware counter
//! that decrements in parallel).
//!
//! SysTick is ARMv6-M base spec onward, so the same impl boots
//! on every M-class core the catalog targets (M3 / M4 / M7
//! covered by R311bg's Layer Q sub-lanes; M0 / M23 / M33 / M55
//! tracked as separate carries).

#![no_std]
#![no_main]

extern crate alloc;

use core::mem::MaybeUninit;
// R311bm-m0 — portable-atomic substitutes for `core::sync::atomic`
// so the same SystickClock counter compiles on ARMv6-M (Cortex-M0/
// M0+/M1) where native CAS is absent. The `fallback` +
// `critical-section` feature combo selects the
// critical-section-single-core impl on those targets and native
// LDREX/STREX on ARMv7-M+. `portable_atomic::Ordering` is layout-
// compatible with `core::sync::atomic::Ordering`; semantics
// unchanged on the M3/M4/M7 sub-lanes that already PASSed under
// R311bg.
use portable_atomic::{AtomicU32, Ordering};

use cortex_m_rt::{entry, exception};
use cortex_m_semihosting::{debug, hprintln};
// embedded-alloc 0.6 split the API: `LlffHeap` = linked-list-first-fit
// (the conventional `embedded_alloc::Heap` from 0.5 series).
use embedded_alloc::LlffHeap as Heap;
use panic_semihosting as _;

use wz::link_lwip::{ipv4_addr_loopback, LwipLink, LwipUdpSocket};

// R311bq — runtime + time imports gated on native-atomic targets only.
// thumbv6m (Cortex-M0/M0+) follows the sync-only main path below and
// does not instantiate `LwipRuntime` / `LwipTime`; gating the imports
// keeps `cargo clippy -D warnings` clean on the M0 lane (unused-import
// would otherwise fire).
#[cfg(target_has_atomic = "32")]
use wz::runtime_core::Runtime;
#[cfg(target_has_atomic = "32")]
use wz::runtime_core::TimeSource;
#[cfg(target_has_atomic = "32")]
use wz::runtime_lwip::{ClockSource, LwipRuntime, LwipTime};

// Heap sizing fork per target SRAM budget. mps2 family (M3/M4/M7)
// has 4 MB SRAM so the conservative 256 KB heap fits trivially.
// microbit (Cortex-M0, nrf51822) has 16 KB SRAM total — heap +
// stack + .data + .bss must share that budget, so the M0 lane
// gets a 4 KB heap with .bss pruned by feature-graph slimming at
// the wz facade layer. R311bm-m0 honest disclosure: if the wz
// runtime-lwip + alloc surface does not fit 16 KB with this
// heap, the microbit Q.2 run will exit FAIL and the lane records
// that the composable framework currently lacks a slim-enough
// preset for nrf51-class devices — exactly the kind of catalog
// gap a "preset-mcu-minimal" round (north-star phase 1 atomic
// feature decomposition) is meant to fill.
#[cfg(target_has_atomic = "32")]
const HEAP_SIZE: usize = 1024 * 256;
#[cfg(not(target_has_atomic = "32"))]
const HEAP_SIZE: usize = 1024 * 4;

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// CPU clock fork per target. QEMU mps2 family clocks the Cortex-M
/// core at 25 MHz nominal; the QEMU `microbit` machine emulates
/// the nrf51822 at 16 MHz. SysTick counts processor cycles when
/// `CSR.CLKSOURCE = 1`; dividing by the target's MHz yields
/// microseconds. A real deploy on different silicon would replace
/// this constant with its actual CPU clock frequency in MHz.
#[cfg(target_has_atomic = "32")]
const CYCLES_PER_US: u64 = 25;
#[cfg(not(target_has_atomic = "32"))]
const CYCLES_PER_US: u64 = 16;

/// SysTick reload value sized to 1 ms tick per target. mps2
/// (25 MHz): RELOAD = 24999, period = 25000 cycles. microbit
/// (16 MHz): RELOAD = 15999, period = 16000 cycles. R311bi
/// shrunk this from the 24-bit max (~671 ms wrap on M3) to 1 ms
/// so the SysTick exception fires every millisecond — that drives
/// the `wfi()` wake in the demo's main loop and gives the
/// `wraps` counter the natural unit of "milliseconds since boot".
const SYST_RELOAD: u32 = (CYCLES_PER_US as u32 * 1000) - 1;
const SYST_PERIOD: u64 = SYST_RELOAD as u64 + 1;

// SysTick MMIO registers (System Control Space, ARMv*-M architecture
// reference; same offsets on every M-class core).
const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
const SYST_RVR: *mut u32 = 0xE000_E014 as *mut u32;
const SYST_CVR: *mut u32 = 0xE000_E018 as *mut u32;
const SYST_CSR_CLKSOURCE: u32 = 1 << 2;
const SYST_CSR_TICKINT: u32 = 1 << 1;
const SYST_CSR_ENABLE: u32 = 1 << 0;

/// Interrupt-incremented wraparound counter. With `TICKINT` set in
/// `SYST_CSR` the `SysTick` exception increments `wraps` once per
/// reload (every `SYST_PERIOD` cycles = 1 ms at 25 MHz). `now_us`
/// snaps `wraps` either side of the CVR read and re-loops on a
/// mismatch — the standard ISR-vs-thread lock-free read pattern
/// for an interrupt-incremented counter paired with a hardware
/// counter that decrements independently.
struct SystickClock {
    wraps: AtomicU32,
}

impl SystickClock {
    const fn new() -> Self {
        Self {
            wraps: AtomicU32::new(0),
        }
    }

    /// Enable SysTick with TICKINT — the SysTick exception then
    /// fires on every reload (every `SYST_PERIOD` cycles), the
    /// `SysTick` handler advances `wraps`, and the main loop's
    /// `wfi()` wakes on each tick. R311bi replaces R311bi's poll
    /// mode + `nop()` main loop, closing R311be carry #2.
    fn init(&self) {
        unsafe {
            SYST_CSR.write_volatile(0);
            SYST_RVR.write_volatile(SYST_RELOAD);
            SYST_CVR.write_volatile(0);
            SYST_CSR.write_volatile(SYST_CSR_CLKSOURCE | SYST_CSR_TICKINT | SYST_CSR_ENABLE);
        }
    }

    fn now_us(&self) -> u64 {
        // Standard double-snap pattern for an interrupt-incremented
        // counter paired with a hardware down-counter. If `wraps`
        // advanced during the CVR read, the CVR snapshot belongs to
        // a different period than the snapped `wraps` value — retry
        // once `wraps` is stable across the read.
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

/// SysTick exception handler — fires every `SYST_PERIOD` cycles
/// (1 ms at 25 MHz) once `SystickClock::init` enables `TICKINT`.
/// Sole side effect is the `wraps` increment so the ISR stays
/// short (no allocation, no locks); the main loop reads `wraps`
/// for monotonic time and lwIP's `sys_now()` reads the same.
#[exception]
fn SysTick() {
    GLOBAL_CLOCK.wraps.fetch_add(1, Ordering::Release);
}

/// Single global SysTick instance — both the `ClockSource` handle
/// passed to `LwipRuntime::new` and the lwIP-side `sys_now()`
/// extern share this so wrap accounting stays consistent across
/// both call surfaces.
static GLOBAL_CLOCK: SystickClock = SystickClock::new();

/// Zero-sized `ClockSource` that forwards every `now_us` call to
/// the shared [`GLOBAL_CLOCK`]. Cheap to clone (unit struct).
///
/// R311bq — only used by the async main path (which constructs
/// `LwipRuntime::new(SystickClockRef)` + `LwipTime::new(&runtime)`).
/// The sync-only thumbv6m path reads `GLOBAL_CLOCK.now_us()` directly
/// for any timing it needs (currently none — `wfi()` + the SysTick
/// interrupt drive cadence), so the impl is gated on native-atomic
/// targets to keep the M0 build free of unused-symbol warnings.
#[cfg(target_has_atomic = "32")]
#[derive(Clone, Copy, Default)]
struct SystickClockRef;

#[cfg(target_has_atomic = "32")]
impl ClockSource for SystickClockRef {
    fn now_us(&self) -> u64 {
        GLOBAL_CLOCK.now_us()
    }
}

/// lwIP NO_SYS=1 deploy-provided clock — R311az-pre D7 tier
/// separation says the deploy owns this symbol on cross-targets
/// (`target_os = "none"`). lwIP's `timeouts.c` calls `sys_now()`
/// unconditionally to expire its internal timer wheel; without
/// this symbol the link fails with "undefined symbol: sys_now".
///
/// Returns milliseconds since boot, sampled from the same
/// [`GLOBAL_CLOCK`] the `ClockSource` impl reads so lwIP's
/// timer wheel and the runtime's `TimerQueue` see identical time.
#[unsafe(no_mangle)]
pub extern "C" fn sys_now() -> u32 {
    (GLOBAL_CLOCK.now_us() / 1000) as u32
}

/// UDP port the demo socket binds to. 5555 is arbitrary and
/// outside the well-known + registered IANA ranges so no
/// theoretical collision with future lwIP feature additions.
const ECHO_PORT: u16 = 5555;

/// The bytes the demo sends + expects back. Identity check on
/// recv proves the full lwIP path (pbuf_alloc → pbuf_take →
/// udp_sendto → loopback netif → udp_input → recv callback →
/// heapless queue → try_recv) without payload corruption.
const PAYLOAD: &[u8] = b"R311be lwIP UDP loopback echo";

/// Number of poll iterations the demo waits for the echo before
/// declaring failure. Each iteration sleeps 1 ms (via
/// `LwipTime::sleep(1).await` which registers on the R311bc
/// timer queue) so the total budget is 100 ms wall-clock — far
/// beyond what a working loopback path needs.
const POLL_BUDGET: u32 = 100;

#[entry]
fn main() -> ! {
    init_heap();
    GLOBAL_CLOCK.init();
    let link = LwipLink::init();
    run(link)
}

/// Async main path — mps2 family (Cortex-M3/M4/M7/M33). Constructs
/// `LwipRuntime` + `LwipTime`, spawns an async echo task, drives the
/// cooperative loop with `wfi()` between SysTick ticks.
///
/// R311bq made this branch native-atomic-only because spawn-mode pulls
/// the full executor (Pin<Box<dyn Future + Send>> task slot + JoinState
/// Arc + wrapper future state machine) which lives in the heap. With
/// the default `LwipUdpSocket` (1500-byte payload × 8 queue slots ≈
/// 12 KB Inner allocation) the spawn-mode path comfortably fits the
/// 256 KB heap on mps2 SRAM. The microbit `<128, 2>` slim socket +
/// sync path is the spawn-less twin in the branch below.
#[cfg(target_has_atomic = "32")]
fn run(link: LwipLink) -> ! {
    hprintln!("R311bi: lwIP UDP loopback e2e demo starting");

    let runtime = LwipRuntime::new(SystickClockRef);
    let time = LwipTime::new(&runtime);

    let sock: LwipUdpSocket =
        LwipUdpSocket::bind(&link, ECHO_PORT).expect("bind UDP socket on ANY:5555");

    runtime.spawn(echo_task(sock, time));

    // Cooperative main loop. lwIP's loopback netif holds the
    // outbound datagram in its output queue until `netif_poll_all`
    // (via `LwipLink::poll_loopback`) walks the queue + invokes
    // ip_input on each entry — which is what dispatches into our
    // recv callback. `check_timeouts` drives lwIP's own timer
    // wheel (ARP retransmit etc.; idle for UDP-only). The
    // runtime's `run_until_idle` then pops any expired
    // SleepFuture timers + polls ready tasks.
    //
    // After each pass, `wfi()` puts the CPU to sleep until the
    // next interrupt — the SysTick exception fires every 1 ms
    // (R311bi enabled TICKINT in SystickClock::init), at which
    // point the handler bumps `GLOBAL_CLOCK.wraps`, the CPU wakes,
    // and the loop polls again. This is the textbook MCU idle
    // pattern: cycles only burn during work + the time it takes
    // to handle the tick ISR, not in a tight nop spin.
    loop {
        link.poll_loopback();
        link.check_timeouts();
        runtime.run_until_idle();
        cortex_m::asm::wfi();
    }
}

/// Sync-only main path — thumbv6m (Cortex-M0/M0+ / microbit). No
/// `LwipRuntime`, no `spawn`, no async/await — exercises the same
/// lwIP UDP loopback path as the async branch but inline so the
/// 4 KB heap budget fits.
///
/// R311bq the heap budget on microbit (nrf51822, 16 KB SRAM total) is
/// shared with cortex-m-rt + portable-atomic + lwIP MEM_SIZE +
/// .data/.bss; the wz facade `runtime-lwip` feature would have spawn
/// allocate a wrapper future + 12 KB `Inner<1500, 8>` rx queue (R311bm
/// "12 KB BoxFuture" carry, traced to the rx queue rather than the
/// future state machine). Slim socket `<128, 2>` ≈ 280-byte rx queue
/// + no spawn path keeps total heap use under 1 KB.
///
/// The protocol exchange is identical: send one PAYLOAD to
/// 127.0.0.1:ECHO_PORT, drain the loopback netif on each iteration,
/// drain the rx queue, compare. PASS / FAIL semihosted as
/// `R311bq PASS` / `R311bq FAIL: <reason>` so the Layer Q audit can
/// distinguish the sync-path PASS from the async-path PASS.
#[cfg(not(target_has_atomic = "32"))]
fn run(link: LwipLink) -> ! {
    hprintln!("R311bq: lwIP UDP loopback e2e demo starting (sync-only)");

    // R311bq slim socket sizing rationale:
    // - PAYLOAD len = 29 bytes; 128 covers any reasonable echo response.
    // - Queue depth 2 = one inflight + one buffered; the demo never
    //   has more than one packet outstanding at a time.
    // Inner<128, 2> footprint ≈ Datagram<128>(128B + 6B + padding) × 2
    // + heapless::Queue overhead + NonNull + u32 + PhantomPinned
    // ≈ 280 bytes versus the default Inner<1500, 8> ≈ 12 KB.
    let mut sock: LwipUdpSocket<128, 2> =
        LwipUdpSocket::bind(&link, ECHO_PORT).expect("bind UDP socket on ANY:5555");

    if let Err(e) = sock.send_to(ipv4_addr_loopback(), ECHO_PORT, PAYLOAD) {
        hprintln!("R311bq FAIL: send_to error {:?}", e);
        debug::exit(debug::EXIT_FAILURE);
    }

    // Sync poll budget — POLL_BUDGET iterations at one SysTick (1 ms)
    // per `wfi()` ≈ 100 ms wall-clock budget, matching the async path.
    let mut polls_left = POLL_BUDGET;
    loop {
        link.poll_loopback();
        link.check_timeouts();
        if let Some(dg) = sock.try_recv() {
            if dg.data.as_slice() == PAYLOAD
                && dg.src_port == ECHO_PORT
                && dg.src_addr == ipv4_addr_loopback()
            {
                hprintln!("R311bq PASS");
                debug::exit(debug::EXIT_SUCCESS);
            }
            hprintln!("R311bq FAIL: echo mismatch");
            debug::exit(debug::EXIT_FAILURE);
        }
        polls_left = polls_left.saturating_sub(1);
        if polls_left == 0 {
            hprintln!("R311bq FAIL: no echo within 100 ms budget");
            debug::exit(debug::EXIT_FAILURE);
        }
        cortex_m::asm::wfi();
    }
}

/// Spawned task body for the async main path. Sends one packet to
/// 127.0.0.1:ECHO_PORT and polls the socket's RX queue for the echo.
/// PASS / FAIL signalled via semihosting + `debug::exit`.
///
/// R311bq native-atomic-only — the sync-path thumbv6m branch does the
/// same work inline in `run` without going through the executor.
#[cfg(target_has_atomic = "32")]
async fn echo_task(mut sock: LwipUdpSocket, time: LwipTime<SystickClockRef>) {
    if let Err(e) = sock.send_to(ipv4_addr_loopback(), ECHO_PORT, PAYLOAD) {
        hprintln!("R311bi FAIL: send_to error {:?}", e);
        debug::exit(debug::EXIT_FAILURE);
    }

    for _ in 0..POLL_BUDGET {
        if let Some(dg) = sock.try_recv() {
            if dg.data.as_slice() == PAYLOAD
                && dg.src_port == ECHO_PORT
                && dg.src_addr == ipv4_addr_loopback()
            {
                hprintln!("R311bi PASS");
                debug::exit(debug::EXIT_SUCCESS);
            }
            // Payload mismatch or unexpected source — surface
            // explicitly so a future regression in the lwIP path
            // (pbuf copy, src addr mangling, port routing) is
            // distinguishable from a no-echo failure.
            hprintln!("R311bi FAIL: echo mismatch");
            debug::exit(debug::EXIT_FAILURE);
        }
        time.sleep(1).await;
    }
    hprintln!("R311bi FAIL: no echo within 100 ms budget");
    debug::exit(debug::EXIT_FAILURE);
}

/// Initialise the heap allocator backing `alloc::*`. The wz upper
/// stack (`alloc` feature on `wz-runtime-core` / `wz-runtime-lwip`)
/// requires a `#[global_allocator]`; embedded-alloc's `Heap` is
/// the conventional Cortex-M choice (linked-list allocator backed
/// by a static BSS region the binary initialises here).
fn init_heap() {
    static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    // SAFETY: `HEAP_MEM` is a `static mut` accessed only here
    // before any other code in the binary runs (entry point's
    // first action); no aliasing borrow can exist.
    unsafe {
        let ptr = core::ptr::addr_of_mut!(HEAP_MEM) as usize;
        HEAP.init(ptr, HEAP_SIZE);
    }
}
