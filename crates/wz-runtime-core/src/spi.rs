// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The SPI master seam: the one thing a MAC-PHY chip's driver needs of a bus.
//!
//! A 10BASE-T1S MAC-PHY (the OPEN Alliance TC6 serial interface) is a whole
//! Ethernet controller behind four wires, and its protocol is a sequence of
//! fixed-length full-duplex exchanges in each of which the chip answers WHILE the
//! host is still sending. That is the shape this seam has: one call is one
//! chip-select assertion, `tx` out and `rx` in during the same clocks.
//!
//! It is declared here, in the tier that depends on nothing, for the reason
//! [`EthernetMac`](crate::EthernetMac) is: the protocol crate on one side and the
//! board's SPI master on the other must reach it without reaching each other, and
//! a chip driver must not depend on the bus driver of the one board it happens to
//! be wired to. What implements it is the board's: a Zephyr SPI device, a bare SCB
//! block, or a test double that plays the chip.

/// A full-duplex SPI master, as a peripheral driver uses it.
pub trait SpiTransfer {
    /// What a failed exchange reports.
    type Error: core::fmt::Debug;

    /// Assert chip select, clock `tx.len()` bytes out of `tx` while clocking the
    /// same number into `rx`, and release chip select.
    ///
    /// `tx.len() == rx.len()` is the caller's precondition, and an implementation
    /// may panic on a mismatch: a protocol whose exchanges are fixed-length has no
    /// use for a short read.
    fn transfer(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<(), Self::Error>;
}
