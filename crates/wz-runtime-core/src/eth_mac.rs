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

    /// Whether [`transmit_gather`](Self::transmit_gather) can QUEUE a frame to be
    /// read in place. A stack asks before it offers pieces: for a MAC that cannot,
    /// the default joins them into a buffer on the stack, which a stack that
    /// already holds a flat transmit buffer has no need to pay for. `false` unless
    /// the MAC says otherwise.
    fn gathers_in_place(&self) -> bool {
        false
    }

    /// Put one frame on the wire from several pieces, WITHOUT first joining them
    /// into one buffer, when the controller can read them where they are
    /// (ARCHITECTURE section 9.1: the codec's bytes are written once, and the DMA
    /// reads them from there).
    ///
    /// The answer says which of three things happened:
    ///
    /// * [`TxGather::Refused`]: nothing was sent and nothing is held. Same as
    ///   [`transmit`](Self::transmit) returning `false`.
    /// * [`TxGather::Copied`]: the frame was sent from a copy. The pieces are the
    ///   caller's again at once and `cookie` will never be reported. This is what
    ///   the default does, so a MAC that cannot gather loses nothing.
    /// * [`TxGather::Queued`]: the controller will read the pieces IN PLACE. They
    ///   must stay where they are, unchanged, until
    ///   [`reap_tx`](Self::reap_tx) reports `cookie`, once.
    ///
    /// # Safety
    ///
    /// Every segment must point at `len` readable bytes, and for a `Queued` answer
    /// they must stay readable and unchanged until `cookie` is reported. The MAC
    /// reads them from a different bus master, so the caller must not hand it
    /// memory that master cannot reach.
    unsafe fn transmit_gather(&mut self, segments: &[TxSegment], cookie: u32) -> TxGather {
        let _ = cookie;
        let mut frame = [0u8; FRAME_MAX];
        // SAFETY: the caller's contract makes every segment readable.
        let Some(joined) = (unsafe { join_segments(segments, &mut frame) }) else {
            return TxGather::Refused;
        };
        if joined != 0 && self.transmit(&frame[..joined]) {
            TxGather::Copied
        } else {
            TxGather::Refused
        }
    }

    /// Report, through `done`, the `cookie` of every [`TxGather::Queued`] frame
    /// whose pieces the controller no longer reads, in the order they were
    /// queued. A MAC that never queues has nothing to report.
    ///
    /// A MAC that queues in place HOLDS a finished frame's cookie until this is
    /// called, and refuses further frames behind it once its ring is full, so a
    /// caller that queues must call this regularly.
    fn reap_tx(&mut self, done: &mut dyn FnMut(u32)) {
        let _ = done;
    }
}

/// One piece of an outgoing frame, in memory the caller keeps in place.
#[derive(Clone, Copy, Debug)]
pub struct TxSegment {
    /// The first byte.
    pub ptr: *const u8,
    /// How many bytes, at least one.
    pub len: usize,
}

/// Copy `segments` one after another into `out` and return how many bytes that
/// made, or `None` when they do not fit. The join a MAC that cannot send in place
/// (or cannot send THIS frame in place) does, so it is written once.
///
/// # Safety
///
/// Every segment must point at `len` readable bytes that do not overlap `out`.
pub unsafe fn join_segments(segments: &[TxSegment], out: &mut [u8]) -> Option<usize> {
    let mut at = 0;
    for segment in segments {
        if segment.len > out.len() - at {
            return None;
        }
        // SAFETY: the caller promised `len` readable bytes; the bound above keeps
        // the write inside `out`.
        unsafe {
            core::ptr::copy_nonoverlapping(segment.ptr, out.as_mut_ptr().add(at), segment.len)
        };
        at += segment.len;
    }
    Some(at)
}

/// What [`EthernetMac::transmit_gather`] did with a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxGather {
    /// Not sent, not held.
    Refused,
    /// Sent from a copy; the pieces are free now.
    Copied,
    /// Queued to be read in place; free once [`EthernetMac::reap_tx`] reports the
    /// cookie.
    Queued,
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

    fn segment(bytes: &[u8]) -> TxSegment {
        TxSegment {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
        }
    }

    /// A MAC that does not gather still sends a gathered frame: the default joins
    /// the pieces in order into one frame, says it COPIED (so the caller's memory
    /// is free at once and no cookie will ever come), and has nothing to reap.
    #[test]
    fn the_default_gather_joins_the_pieces_and_reports_a_copy() {
        let mut mac = Echo { held: None };
        assert!(
            !mac.gathers_in_place(),
            "a MAC says nothing and is not offered pieces by a stack"
        );
        let (head, body) = ([1u8, 2, 3], [4u8, 5]);
        // SAFETY: both arrays outlive the call and are fully readable.
        let outcome = unsafe { mac.transmit_gather(&[segment(&head), segment(&body)], 99) };
        assert_eq!(outcome, TxGather::Copied);
        let mut buf = [0u8; FRAME_MAX];
        assert_eq!(mac.receive(&mut buf), Some(5));
        assert_eq!(&buf[..5], &[1, 2, 3, 4, 5], "the pieces, in order");
        let mut reported = 0;
        mac.reap_tx(&mut |_| reported += 1);
        assert_eq!(reported, 0, "a copy never reports a cookie");
    }

    #[test]
    fn the_default_gather_refuses_what_a_frame_cannot_be() {
        let mut mac = Echo { held: None };
        // SAFETY: the pieces are readable for the call; nothing is queued.
        unsafe {
            assert_eq!(mac.transmit_gather(&[], 0), TxGather::Refused, "no frame");
            let empty: [u8; 0] = [];
            assert_eq!(
                mac.transmit_gather(&[segment(&empty)], 0),
                TxGather::Refused,
                "no bytes"
            );
            let big = [0u8; FRAME_MAX];
            let one = [0u8; 1];
            assert_eq!(
                mac.transmit_gather(&[segment(&big), segment(&one)], 0),
                TxGather::Refused,
                "one byte past the longest frame"
            );
            assert_eq!(
                mac.transmit_gather(&[segment(&big)], 0),
                TxGather::Copied,
                "the longest frame is fine"
            );
        }
    }
}
