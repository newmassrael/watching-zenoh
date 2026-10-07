// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The memory the controller's DMA reads and writes: two descriptor rings and
//! the frame buffers they point at.
//!
//! One static [`DmaArea`] per MAC, handed to the driver, laid out so the
//! controller and the CPU never disagree about it:
//!
//! * every buffer is [`BUF_LEN`] bytes, 32-byte aligned, a multiple of a Cortex-M7
//!   cache line, so no two buffers share a line;
//! * the area itself is 32-byte aligned, and a descriptor is eight bytes, so a
//!   cache line holds four of them. That sharing is why the area is meant to live
//!   in NON-CACHEABLE memory (Zephyr's `.nocache` section, an MPU region marked
//!   non-cacheable): with maintenance by line, cleaning one descriptor would
//!   write back its neighbours' stale copies over what the controller just wrote.
//!   A board that cannot place it so supplies cache maintenance through
//!   [`Board::clean`](crate::Board::clean) and
//!   [`Board::invalidate`](crate::Board::invalidate), and must then keep the
//!   rings to one descriptor per line itself.
//!
//! Descriptor words are accessed ONLY through volatile reads and writes: the
//! controller changes them behind the compiler's back.

use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

/// The size of each frame buffer: the controller is told to receive 1536 bytes
/// (`DMA_CONFIG.RX_BUF_SIZE` is in units of 64), and a transmit buffer is the
/// same so one constant answers both.
pub const BUF_LEN: usize = 1536;

/// The receive buffer size field of `DMA_CONFIG`, in 64-byte units.
pub const RX_BUF_UNITS: u32 = (BUF_LEN / 64) as u32;

/// One buffer descriptor: the two words the controller reads and writes.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct Descriptor {
    pub word0: u32,
    pub word1: u32,
}

/// One frame buffer, aligned to a cache line.
#[repr(C, align(32))]
pub struct Buffer(pub [u8; BUF_LEN]);

/// The rings and buffers of one MAC, `RX` receive and `TX` transmit slots.
#[repr(C, align(32))]
pub struct DmaArea<const RX: usize, const TX: usize> {
    pub(crate) rx_desc: [Descriptor; RX],
    pub(crate) tx_desc: [Descriptor; TX],
    pub(crate) rx_buf: [Buffer; RX],
    pub(crate) tx_buf: [Buffer; TX],
}

impl<const RX: usize, const TX: usize> DmaArea<RX, TX> {
    /// An all-zero area, for a `static`. The driver initialises the rings.
    pub const fn new() -> Self {
        Self {
            rx_desc: [Descriptor { word0: 0, word1: 0 }; RX],
            tx_desc: [Descriptor { word0: 0, word1: 0 }; TX],
            rx_buf: [const { Buffer([0; BUF_LEN]) }; RX],
            tx_buf: [const { Buffer([0; BUF_LEN]) }; TX],
        }
    }
}

impl<const RX: usize, const TX: usize> Default for DmaArea<RX, TX> {
    fn default() -> Self {
        Self::new()
    }
}

/// Volatile access to one descriptor of a ring, by raw pointer: the area is
/// shared with hardware, so no `&mut` to it outlives a call.
#[derive(Clone, Copy)]
pub(crate) struct Slot(pub(crate) *mut Descriptor);

impl Slot {
    pub(crate) fn word0(self) -> u32 {
        // SAFETY: points into the live `DmaArea` the MAC owns; volatile because
        // the controller writes it.
        unsafe { read_volatile(addr_of!((*self.0).word0)) }
    }

    pub(crate) fn word1(self) -> u32 {
        // SAFETY: as `word0`.
        unsafe { read_volatile(addr_of!((*self.0).word1)) }
    }

    pub(crate) fn set_word0(self, value: u32) {
        // SAFETY: as `word0`.
        unsafe { write_volatile(addr_of_mut!((*self.0).word0), value) }
    }

    pub(crate) fn set_word1(self, value: u32) {
        // SAFETY: as `word0`.
        unsafe { write_volatile(addr_of_mut!((*self.0).word1), value) }
    }
}
