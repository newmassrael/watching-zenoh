// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The C ABI of the Zephyr Ethernet driver over the CYT4BF's MAC (`wz_zeth_driver.c`).
//!
//! Zephyr has no Ethernet driver for this controller, and wz has: `wz-eth-mac-cyt4bf`. This
//! file is the seam between them. The C side is a Zephyr Ethernet driver (an `ethernet_api`
//! and a receive thread); this side is the MAC, brought up by the same `mac_cyt4bf::open` the
//! lwIP backend uses, so the controller is driven by one piece of code whichever stack sits on
//! top of it.
//!
//! It is included by `#[path]` into every Rust crate that links the driver (the admin node's
//! and the zenoh-pico application's), which each name `mac_cyt4bf` and the board values it
//! needs; it is one source, not a copy.
//!
//! ## Who may call what, and when
//!
//! The MAC is `&mut` state and the controller has one set of rings, so calls are SERIALISED by
//! the C side: one mutex held across every `wz_zeth_*` call after the open. `wz_zeth_open` is
//! called once, by the receive thread, before it takes the mutex for the first time and before
//! any frame is sent (the interface is not marked up until it returns 0).

use core::cell::UnsafeCell;
use core::slice;

use wz::runtime_core::EthernetMac;
use wz_eth_mac_cyt4bf::RefClock;

use crate::mac_cyt4bf::{self, T2gMac};

/// The MAC, once opened. Written by `wz_zeth_open` and read by the other calls, which the C
/// side orders after it (see the module documentation).
struct MacSlot(UnsafeCell<Option<T2gMac>>);

// SAFETY: the C driver serialises every call with one mutex, and the open happens-before the
// interface is marked up, which is what lets any other call run. There is no other accessor.
unsafe impl Sync for MacSlot {}

static MAC: MacSlot = MacSlot(UnsafeCell::new(None));

/// The opened MAC, or `None` before the open (or after one that failed).
///
/// # Safety
/// The caller holds the driver's mutex (or is the one thread that is opening).
unsafe fn mac() -> Option<&'static mut T2gMac> {
    // SAFETY: the caller's contract is that no other reference to the slot is live.
    unsafe { (*MAC.0.get()).as_mut() }
}

/// Bring ETH0 up: pins, MAC, PHY and a link if one comes within `link_wait_ms`.
/// `address` points at the six bytes of the station address. `ref_clock_divider` is 0 when
/// the PHY drives the RMII reference clock and the divider of the internal PLL otherwise.
/// Returns 0 on success; a missing link is not a failure (the MAC's link service reports it
/// when it appears). Any other result is a FAIL line on the console and a non-zero return.
///
/// # Safety
/// `address` must point at six readable bytes. Called once, before any other `wz_zeth_*`.
#[no_mangle]
pub unsafe extern "C" fn wz_zeth_open(
    address: *const u8,
    ref_clock_divider: u32,
    link_wait_ms: u32,
) -> i32 {
    if address.is_null() {
        return -1;
    }
    let mut station = [0u8; 6];
    // SAFETY: the caller's contract gives six readable bytes.
    station.copy_from_slice(unsafe { slice::from_raw_parts(address, 6) });
    let ref_clock = match ref_clock_divider {
        0 => RefClock::External,
        divider => RefClock::InternalPll {
            divider: divider.min(u16::MAX as u32) as u16,
        },
    };
    match mac_cyt4bf::open(station, ref_clock, link_wait_ms) {
        Ok(opened) => {
            // SAFETY: the open is the only writer and runs before any reader (module docs).
            unsafe { *MAC.0.get() = Some(opened) };
            0
        }
        Err(failure) => {
            wz::runtime_zephyr::glue::log(failure);
            -1
        }
    }
}

/// Put one frame on the wire. Returns 1 when the MAC took it, 0 when it did not (no free
/// descriptor, or the MAC is not open).
///
/// # Safety
/// `frame` must point at `len` readable bytes; the caller holds the driver's mutex.
#[no_mangle]
pub unsafe extern "C" fn wz_zeth_transmit(frame: *const u8, len: usize) -> i32 {
    // SAFETY: the caller holds the driver's mutex.
    let Some(mac) = (unsafe { mac() }) else {
        return 0;
    };
    if frame.is_null() {
        return 0;
    }
    // SAFETY: the caller's contract gives `len` readable bytes.
    let frame = unsafe { slice::from_raw_parts(frame, len) };
    i32::from(mac.transmit(frame))
}

/// Take one received frame into `buf`. Returns its length, or 0 when none is waiting (or the
/// MAC is not open).
///
/// # Safety
/// `buf` must point at `capacity` writable bytes; the caller holds the driver's mutex.
#[no_mangle]
pub unsafe extern "C" fn wz_zeth_receive(buf: *mut u8, capacity: usize) -> i32 {
    // SAFETY: the caller holds the driver's mutex.
    let Some(mac) = (unsafe { mac() }) else {
        return 0;
    };
    if buf.is_null() {
        return 0;
    }
    // SAFETY: the caller's contract gives `capacity` writable bytes.
    let buf = unsafe { slice::from_raw_parts_mut(buf, capacity) };
    mac.receive(buf)
        .map_or(0, |len| len.min(i32::MAX as usize) as i32)
}

/// Run the link service: the PHY's state is read and a change is told on the console.
/// `now_ms` is the kernel's uptime. Returns 1 when the link is up after the pass and 0
/// when it is not (or the MAC is not open), which is what the driver tells Zephyr's
/// carrier state.
///
/// # Safety
/// The caller holds the driver's mutex.
#[no_mangle]
pub unsafe extern "C" fn wz_zeth_poll_link(now_ms: u64) -> i32 {
    // SAFETY: the caller holds the driver's mutex.
    let Some(mac) = (unsafe { mac() }) else {
        return 0;
    };
    mac.poll_link(now_ms);
    i32::from(mac.link_is_up())
}

/// Whether the link is up as of the last service pass (or the open's bring-up).
///
/// # Safety
/// The caller holds the driver's mutex.
#[no_mangle]
pub unsafe extern "C" fn wz_zeth_link_up() -> i32 {
    // SAFETY: the caller holds the driver's mutex.
    unsafe { mac() }.map_or(0, |mac| i32::from(mac.link_is_up()))
}
