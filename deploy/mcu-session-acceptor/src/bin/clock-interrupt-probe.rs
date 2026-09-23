// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2808 (open-debt item 815): the clock must progress while SysTick
//! preempts thread-mode clock reads and unrelated 64-bit atomic updates.
//! The handler must not depend on a lock held by the interrupted thread.

#![no_std]
#![no_main]

use cortex_m_rt::{entry, exception};
use cortex_m_semihosting::{debug, hprintln};
use panic_semihosting as _;
use portable_atomic::{AtomicU64, Ordering};
use wz_mcu_clock::SystickClock;

static CLOCK: SystickClock<25> = SystickClock::new();
// Exercise many addresses: fallback locks can be shared by unrelated
// atomics, as the captured OpenAck/clock collision demonstrated.
static COUNTERS: [AtomicU64; 128] = [const { AtomicU64::new(0) }; 128];

#[exception]
fn SysTick() {
    CLOCK.on_tick();
}

#[entry]
fn main() -> ! {
    CLOCK.init();
    hprintln!("clock interrupt probe: starting");
    let start = CLOCK.now_us();
    let mut previous = start;
    let mut reads = 0u32;
    loop {
        for counter in &COUNTERS {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        let now = CLOCK.now_us();
        assert!(now >= previous, "clock moved backward");
        previous = now;
        reads += 1;
        if now - start >= 100_000 {
            assert!(reads > 1, "probe did not exercise repeated reads");
            hprintln!("clock interrupt probe: PASS ({} reads)", reads);
            debug::exit(debug::EXIT_SUCCESS);
            loop {}
        }
    }
}
