// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! zephyr-pico-compare (Rust staticlib) -- the CYT4BF's MAC for a Zephyr application that is not
//! wz.
//!
//! The application is zenoh-pico's own C over Zephyr's network stack (`src/main.c`). Zephyr has
//! no Ethernet driver for this controller, so the driver is `deploy/zephyr-eth-wzmac`'s, and its
//! Rust half is this crate: the same `mac_cyt4bf` bring-up the wz admin node uses, behind the same
//! `wz_zeth_*` C ABI, built from the same source files. No wz session, node or transport is in
//! this image.
#![no_std]

use wz::runtime_coop::ClockSource;
use wz::runtime_zephyr::ZephyrClock;

// The allocator over the kernel heap, the critical section over the kernel IRQ lock and the panic
// handler. Nothing in this image allocates, but the crates under the MAC's seams name the heap
// form of their task pool.
wz::runtime_zephyr::zephyr_image!();

/// The board's `CONFIG_SYS_CLOCK_TICKS_PER_SEC`, as this build was configured: the `ZephyrClock`
/// timebase every wait of the MAC driver is bounded by.
const TICK_HZ: u32 = wz::runtime_zephyr::tick_hz_from_build!();

/// Milliseconds since boot by the kernel's own tick count, for the MAC bring-up's stage lines.
fn uptime_ms() -> u64 {
    ZephyrClock::<TICK_HZ>.now_us() / 1000
}

// The admin node's board glue for the MAC (pins, DMA area, bring-up), compiled here too: it is the
// one piece of code that opens ETH0, whichever application is above it.
#[path = "../../../zephyr-admin-node/rust/src/mac_cyt4bf.rs"]
mod mac_cyt4bf;
#[path = "../../../zephyr-eth-wzmac/zeth_exports.rs"]
mod zeth_exports;
