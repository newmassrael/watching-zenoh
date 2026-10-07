// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Ethernet MAC seam: the part of a NIC driver a network stack needs.
//!
//! ## Why it lives in the trait-skeleton tier
//!
//! It began in `wz-link-lwip`, next to the only stack that used it, together
//! with the one chip driver (the LAN9118 on Arm's MPS2 boards) that implemented
//! it. A second chip makes that placement wrong for the reason
//! [`rx_slots`](crate::rx_slots) records for its own move: a driver for a
//! Cortex-M7 part has no business depending on a crate that builds lwIP's C
//! sources, and a firmware only ever drives one chip. The seam is therefore here,
//! in the tier that declares nothing of its own and depends on nothing, so a chip
//! crate and a stack crate each reach it without either reaching the other.
//!
//! ## What the seam is, and is not
//!
//! A MAC sends one whole frame and hands whole frames in. It does not learn
//! what stack sits above it and it does not know what the frames carry, which is
//! what lets lwIP's `ethernetif` template, a future Rust stack and a loopback
//! test double all drive the same driver.
//!
//! It is a COPYING interface: [`EthernetMac::receive`] fills a buffer the caller
//! owns. A peripheral that writes received frames into descriptor-ring buffers
//! can implement it by copying out, which is correct and is the first
//! implementation a chip gets; handing the ring's buffer up without the copy is
//! the [`RxSlots`](crate::RxSlots) seam's job and needs the buffer-pool
//! generator to expose the address of an armed slot, which it does not yet.

/// The longest frame a MAC sends or accepts, without the FCS: a 14-byte
/// Ethernet header and a 1500-byte MTU.
///
/// The stack side holds its own buffers to the same bound (lwIP's transmit
/// buffer in `lwip-sys/shim.c`), so a frame this long is never refused for size
/// on either side.
pub const FRAME_MAX: usize = 1514;

/// An Ethernet MAC: the part of a NIC driver a network stack needs.
pub trait EthernetMac {
    /// The station address this MAC answers to.
    fn mac_address(&self) -> [u8; 6];

    /// Put one whole frame (header and payload, no FCS) on the wire. `false`
    /// when it could not be sent; the stack counts it as an interface error.
    fn transmit(&mut self, frame: &[u8]) -> bool;

    /// Take the next received frame (no FCS) into `buf` and return its
    /// length, or `None` when nothing is waiting. A frame longer than `buf`
    /// is dropped whole rather than truncated.
    fn receive(&mut self, buf: &mut [u8]) -> Option<usize>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A MAC that echoes: what it is asked to send comes back as the next
    /// received frame. Enough to drive the trait the way a stack does.
    struct Echo {
        held: Option<([u8; FRAME_MAX], usize)>,
    }

    impl EthernetMac for Echo {
        fn mac_address(&self) -> [u8; 6] {
            [2, 0, 0, 0, 0, 1]
        }

        fn transmit(&mut self, frame: &[u8]) -> bool {
            if frame.len() > FRAME_MAX || self.held.is_some() {
                return false;
            }
            let mut copy = [0u8; FRAME_MAX];
            copy[..frame.len()].copy_from_slice(frame);
            self.held = Some((copy, frame.len()));
            true
        }

        fn receive(&mut self, buf: &mut [u8]) -> Option<usize> {
            let (frame, len) = self.held.take()?;
            if len > buf.len() {
                return None;
            }
            buf[..len].copy_from_slice(&frame[..len]);
            Some(len)
        }
    }

    /// The frame bound is the Ethernet header plus the MTU, and a MAC is usable
    /// behind a trait object, which is how a stack that is generic over nothing
    /// holds one.
    #[test]
    fn a_frame_is_a_header_and_an_mtu_and_the_trait_is_object_safe() {
        assert_eq!(FRAME_MAX, 14 + 1500);

        let mac: &mut dyn EthernetMac = &mut Echo { held: None };
        assert_eq!(mac.mac_address(), [2, 0, 0, 0, 0, 1]);
        assert!(mac.transmit(&[7u8; 60]));
        let mut buf = [0u8; FRAME_MAX];
        assert_eq!(mac.receive(&mut buf), Some(60));
        assert_eq!(&buf[..60], &[7u8; 60]);
        assert_eq!(mac.receive(&mut buf), None, "nothing is waiting");
    }
}
