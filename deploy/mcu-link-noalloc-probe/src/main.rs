// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The link tier without an allocator, on a linked image.
//!
//! Boots, brings up lwIP's loopback interface, binds a UDP socket out of a
//! `static` pool (`wz_link_lwip::UdpSocketPool`, the `static-link-storage`
//! selector), sends one datagram to itself and reads it back. There is no
//! `#[global_allocator]` and no `extern crate alloc`, so a reference to the
//! heap from anything reachable is a link error, and
//! `scripts/lib/no_allocator_link_gate.py` reads the linked ELF's symbol table
//! as the second, independent witness.
//!
//! PASS or FAIL goes out over semihosting and as the exit code, as the other
//! deploy/mcu-* images do, so the Layer Q lane can run it under QEMU.

#![no_std]
#![no_main]

use cortex_m_rt::{entry, exception};
use cortex_m_semihosting::{debug, hprintln};
use panic_semihosting as _;
use wz_link_lwip::{ipv4_addr_loopback, LwipLink, LwipUdpSocket, UdpSocketPool};
use wz_mcu_clock::SystickClock;

/// CPU clock in MHz: QEMU clocks the mps2 family at 25 MHz and the `microbit`
/// (nrf51) at 16 MHz. Native compare-and-swap is what tells the families apart.
#[cfg(target_has_atomic = "32")]
const CYCLES_PER_US: u64 = 25;
#[cfg(not(target_has_atomic = "32"))]
const CYCLES_PER_US: u64 = 16;

static GLOBAL_CLOCK: SystickClock<{ CYCLES_PER_US }> = SystickClock::new();

/// `SysTick` fires every millisecond once the clock is initialised and does
/// nothing but advance the reload counter.
#[exception]
fn SysTick() {
    GLOBAL_CLOCK.on_tick();
}

/// lwIP's `NO_SYS` clock: the image owns this symbol on a bare-metal target.
#[unsafe(no_mangle)]
pub extern "C" fn sys_now() -> u32 {
    (GLOBAL_CLOCK.now_us() / 1000) as u32
}

/// The datagram's slot size and queue depth. One socket of 128 x 2 is about 280
/// bytes of `.bss`, which fits the 16 KB of a Cortex-M0 as well as the 4 MB of
/// the mps2 machines.
const SLOT_BYTES: usize = 128;
const QUEUE_SLOTS: usize = 2;

type Socket = LwipUdpSocket<SLOT_BYTES, QUEUE_SLOTS>;

/// The only socket storage the image has: one cell, in `.bss`. A second bind
/// while it is held is a counted refusal (`LinkError::SlotsExhausted`), never a
/// heap fallback.
static SOCKETS: UdpSocketPool<SLOT_BYTES, QUEUE_SLOTS, 1> = UdpSocketPool::new();

const PORT: u16 = 5556;
const PAYLOAD: &[u8] = b"link tier, no allocator";

/// Polls the loopback interface for at most this many one-millisecond turns.
const POLL_BUDGET: u32 = 100;

#[entry]
fn main() -> ! {
    GLOBAL_CLOCK.init();
    hprintln!("link-noalloc: static-pool UDP loopback starting");

    let link = LwipLink::init();
    let mut socket = match Socket::bind_in(&link, PORT, &SOCKETS) {
        Ok(socket) => socket,
        Err(e) => fail(format_args!("bind_in refused: {:?}", e)),
    };

    // The pool has one cell and it is taken: the second claim is refused and
    // counted, and nothing is allocated in its place.
    if Socket::bind_in(&link, PORT + 1, &SOCKETS).is_ok()
        || SOCKETS.refusals() != 1
        || SOCKETS.in_use() != 1
    {
        fail(format_args!("a full pool did not refuse and count"));
    }

    if let Err(e) = socket.send_to(ipv4_addr_loopback(), PORT, PAYLOAD) {
        fail(format_args!("send_to failed: {:?}", e));
    }

    let mut turns_left = POLL_BUDGET;
    loop {
        link.poll_loopback();
        link.check_timeouts();
        if let Some(datagram) = socket.try_recv() {
            if datagram.data.as_slice() == PAYLOAD
                && datagram.src_port == PORT
                && datagram.src_addr == ipv4_addr_loopback()
            {
                hprintln!("link-noalloc PASS");
                debug::exit(debug::EXIT_SUCCESS);
            }
            fail(format_args!("the datagram that came back differs"));
        }
        turns_left -= 1;
        if turns_left == 0 {
            fail(format_args!("no datagram within the poll budget"));
        }
        cortex_m::asm::wfi();
    }
}

fn fail(why: core::fmt::Arguments<'_>) -> ! {
    hprintln!("link-noalloc FAIL: {}", why);
    debug::exit(debug::EXIT_FAILURE);
    loop {
        cortex_m::asm::wfi();
    }
}
