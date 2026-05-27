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
//! ## Why DWT cycle counter for `ClockSource`
//!
//! QEMU's `mps2-an386` machine emulates a Cortex-M3 at 25 MHz
//! nominal. The DWT (Data Watchpoint and Trace) unit exposes a
//! 32-bit `CYCCNT` register that increments every CPU cycle —
//! the simplest monotonic clock source on ARMv7-M that doesn't
//! require configuring SysTick or a peripheral timer. Wraparound
//! at 2^32 cycles ≈ 171 seconds is well beyond the demo's 100 ms
//! budget; a production deploy would extend via a software
//! wraparound counter incremented from the SysTick ISR.

#![no_std]
#![no_main]

extern crate alloc;

use core::mem::MaybeUninit;

use cortex_m::peripheral::DWT;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
// embedded-alloc 0.6 split the API: `LlffHeap` = linked-list-first-fit
// (the conventional `embedded_alloc::Heap` from 0.5 series).
use embedded_alloc::LlffHeap as Heap;
use panic_semihosting as _;

use wz::link_lwip::{ipv4_addr_loopback, LwipLink, LwipUdpSocket};
use wz::runtime_core::Runtime;
use wz::runtime_core::TimeSource;
use wz::runtime_lwip::{ClockSource, LwipRuntime, LwipTime};

// 256 KB heap — enough for the wz upper stack's alloc traffic
// (BoxFuture per spawn + lwIP MEM_SIZE budget + heapless::Vec
// per Datagram). A real M3 deploy with constrained SRAM would
// shrink this; QEMU mps2-an386's 4 MB RAM has the headroom.
const HEAP_SIZE: usize = 1024 * 256;

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// QEMU mps2-an386 nominal frequency is 25 MHz; DWT::cycle_count()
/// reports cycles, so divide by 25 to get microseconds. A real
/// Cortex-M3 deploy on different silicon would replace this
/// constant with its actual clock frequency in MHz.
const CYCLES_PER_US: u64 = 25;

/// [`wz::runtime_lwip::ClockSource`] backed by the ARMv7-M DWT
/// cycle counter. Cheap to clone (unit struct). The DWT counter
/// must be enabled before any `now_us()` call returns a non-zero
/// value; `main()` performs the enable sequence on entry.
#[derive(Clone, Copy, Default)]
struct DwtClock;

impl ClockSource for DwtClock {
    fn now_us(&self) -> u64 {
        DWT::cycle_count() as u64 / CYCLES_PER_US
    }
}

/// lwIP NO_SYS=1 deploy-provided clock — R311az-pre D7 tier
/// separation says the deploy owns this symbol on cross-targets
/// (`target_os = "none"`). lwIP's `timeouts.c` calls `sys_now()`
/// unconditionally to expire its internal timer wheel; without
/// this symbol the link fails with "undefined symbol: sys_now".
///
/// Returns milliseconds since boot. Same source as `DwtClock` —
/// cycle counter divided to milliseconds (25 MHz × 1000 = 25 000
/// cycles per ms). Wraps every ~171 s at 25 MHz which is well
/// beyond the demo's 100 ms budget.
#[unsafe(no_mangle)]
pub extern "C" fn sys_now() -> u32 {
    (DWT::cycle_count() as u64 / (CYCLES_PER_US * 1000)) as u32
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
    enable_dwt_cycle_counter();

    hprintln!("R311be: lwIP UDP loopback e2e demo starting");

    let runtime = LwipRuntime::new(DwtClock);
    let time = LwipTime::new(&runtime);
    let link = LwipLink::init();

    let sock = LwipUdpSocket::bind(&link, ECHO_PORT).expect("bind UDP socket on ANY:5555");

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
    // We deliberately do NOT call `cortex_m::asm::wfi()` here —
    // QEMU mps2-an386's default setup has no SysTick / peripheral
    // IRQ configured to wake from wfi(), so a wfi() would block
    // forever and the DWT cycle counter would not advance. The
    // tight `nop` keeps cycles ticking; a real MCU deploy with
    // SysTick configured would substitute `wfi()` here for
    // genuine power-down between IRQs.
    loop {
        link.poll_loopback();
        link.check_timeouts();
        runtime.run_until_idle();
        cortex_m::asm::nop();
    }
}

/// Spawned task body. Sends one packet to 127.0.0.1:ECHO_PORT and
/// polls the socket's RX queue for the echo. PASS / FAIL is
/// signalled via semihosting + `debug::exit`.
async fn echo_task(mut sock: LwipUdpSocket, time: LwipTime<DwtClock>) {
    if let Err(e) = sock.send_to(ipv4_addr_loopback(), ECHO_PORT, PAYLOAD) {
        hprintln!("R311be FAIL: send_to error {:?}", e);
        debug::exit(debug::EXIT_FAILURE);
    }

    for _ in 0..POLL_BUDGET {
        if let Some(dg) = sock.try_recv() {
            if dg.data.as_slice() == PAYLOAD
                && dg.src_port == ECHO_PORT
                && dg.src_addr == ipv4_addr_loopback()
            {
                hprintln!("R311be PASS");
                debug::exit(debug::EXIT_SUCCESS);
            }
            // Payload mismatch or unexpected source — surface
            // explicitly so a future regression in the lwIP path
            // (pbuf copy, src addr mangling, port routing) is
            // distinguishable from a no-echo failure.
            hprintln!("R311be FAIL: echo mismatch");
            debug::exit(debug::EXIT_FAILURE);
        }
        time.sleep(1).await;
    }
    hprintln!("R311be FAIL: no echo within 100 ms budget");
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

/// Enable the ARMv7-M DWT cycle counter so [`DwtClock::now_us`]
/// returns monotonic values. The unlock sequence is required on
/// ARMv7-M to clear the lock register before CYCCNT can be
/// enabled; cortex-m 0.7's `unlock` API encapsulates the unlock
/// MMIO write. On a real silicon that gates DWT behind a debug
/// authentication step the equivalent setup happens at boot.
fn enable_dwt_cycle_counter() {
    let mut cp = cortex_m::Peripherals::take().expect("Peripherals::take");
    cp.DCB.enable_trace();
    cp.DWT.enable_cycle_counter();
}
