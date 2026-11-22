// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! zephyr-capi-pico (Rust staticlib) -- the pico C ABI as an MCU library.
//!
//! The application is zenoh-pico's own C program (`deploy/zephyr-pico-compare/src/main.c`),
//! compiled against zenoh-pico's headers; the library it links is this archive, whose exports are
//! `wz-capi-pico`'s, built without `std` on the cooperative engine over Zephyr's sockets
//! (`os-zephyr`, docs/upstream-parity.md section 5a). The rest is the image's glue: the allocator
//! over the kernel heap, which the C ABI allocates from as pico's `z_malloc` does; the critical
//! section and the panic handler; and the CYT4BF's MAC behind the Zephyr Ethernet driver, the same
//! source the comparison image compiles (`board-mac-cyt4bf`, a default feature: a board whose
//! Ethernet has a driver of Zephyr's own builds without it).
#![no_std]

#[cfg(feature = "board-mac-cyt4bf")]
use wz::runtime_coop::ClockSource;
#[cfg(feature = "board-mac-cyt4bf")]
use wz::runtime_zephyr::ZephyrClock;

// The C ABI is a dependency, and an archive carries a dependency's `#[no_mangle]` exports only when
// the dependency is linked into it: naming the crate is what links it.
pub use wz_capi_pico as pico;

// The allocator over the kernel heap, the critical section over the kernel IRQ lock and the panic
// handler.
wz::runtime_zephyr::zephyr_image!();

/// The board's `CONFIG_SYS_CLOCK_TICKS_PER_SEC`, as this build was configured: the `ZephyrClock`
/// timebase every wait of the MAC driver is bounded by.
#[cfg(feature = "board-mac-cyt4bf")]
const TICK_HZ: u32 = wz::runtime_zephyr::tick_hz_from_build!();

/// Milliseconds since boot by the kernel's own tick count, for the MAC bring-up's stage lines.
#[cfg(feature = "board-mac-cyt4bf")]
fn uptime_ms() -> u64 {
    ZephyrClock::<TICK_HZ>.now_us() / 1000
}

// The admin node's board glue for the MAC (pins, DMA area, bring-up), compiled here too: it is the
// one piece of code that opens ETH0, whichever application is above it.
#[cfg(feature = "board-mac-cyt4bf")]
#[path = "../../../zephyr-admin-node/rust/src/mac_cyt4bf.rs"]
mod mac_cyt4bf;
#[cfg(feature = "board-mac-cyt4bf")]
#[path = "../../../zephyr-eth-wzmac/zeth_exports.rs"]
mod zeth_exports;
