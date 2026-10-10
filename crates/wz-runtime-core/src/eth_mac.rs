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
//! Its first door is a COPYING one: [`EthernetMac::receive`] fills a buffer the
//! caller owns. A peripheral that writes received frames into descriptor-ring
//! buffers can implement it by copying out, which is correct and is the first
//! implementation a chip gets. Handing the ring's buffer up without the copy is
//! [`EthernetMac::receive_loan`]; and a ring whose buffers are the slots of a
//! generated buffer pool, so the pool's lifecycle governs each received frame, is
//! drawn from a [`MacRxPool`].

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

    /// Whether [`receive_loan`](Self::receive_loan) can hand a received frame up
    /// where the controller wrote it. A stack asks before it uses the loan: a MAC
    /// that cannot gets the copying [`receive`](Self::receive), as before. `false`
    /// unless the MAC says otherwise.
    fn loans_rx(&self) -> bool {
        false
    }

    /// ARCHITECTURE section 9.2 -- take the next received frame WITHOUT copying
    /// it: the frame is lent in place, in the buffer the controller wrote it to,
    /// and the buffer is the stack's to read until it is given back with
    /// [`return_rx`](Self::return_rx). `None` when nothing is waiting, or when the
    /// MAC cannot lend (the default), in which case [`receive`](Self::receive) is
    /// the way to take a frame.
    ///
    /// A frame that is lent holds its buffer out of the controller's reach, so a
    /// stack that lends and never returns starves the receive ring; the
    /// controller then drops frames, which is what a full ring does.
    fn receive_loan(&mut self) -> Option<RxLoan> {
        None
    }

    /// Give back the buffer of a frame lent by [`receive_loan`](Self::receive_loan),
    /// named by the loan's `cookie`. The bytes of the loan are not readable after
    /// this. A cookie that names no lent buffer is ignored.
    fn return_rx(&mut self, cookie: u32) {
        let _ = cookie;
    }

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

/// A received frame lent in place by [`EthernetMac::receive_loan`].
#[derive(Clone, Copy, Debug)]
pub struct RxLoan {
    /// The first byte of the frame (no FCS), in the controller's own buffer. Valid
    /// until [`EthernetMac::return_rx`] is called with `cookie`.
    pub ptr: *const u8,
    /// The frame's length in bytes.
    pub len: usize,
    /// What to give back to [`EthernetMac::return_rx`].
    pub cookie: u32,
}

/// ARCHITECTURE section 9.2 -- receive buffers a descriptor-ring MAC draws from a
/// BUFFER POOL instead of owning them: the pool's receive edges, each slot named by
/// its index, which is what a descriptor's record and a loan's cookie carry.
///
/// A MAC that owns its ring's buffers has a buffer per descriptor, and a frame it
/// lends keeps that descriptor out of the ring until the stack gives it back. Over a
/// pool, the descriptor is re-armed with another free slot at once, so a frame the
/// stack holds is held in its slot and not in the ring; and the slot's state is the
/// generated lifecycle's, so where a received frame is at any moment (in the
/// controller's hands, being read, free) is the pool's own answer.
///
/// | what the ring does | edge of the generated pool |
/// |---|---|
/// | a descriptor is given a buffer | [`arm_rx`](Self::arm_rx) (free to dma-armed-rx) |
/// | the descriptor is released to the controller | [`start_rx`](Self::start_rx) (to dma-busy-rx) |
/// | the controller reports the frame written | [`complete_rx`](Self::complete_rx) (to cpu-ref) |
/// | the frame's readers are done with it | [`release_rx`](Self::release_rx) (cpu-ref to free) |
///
/// A slot is only ever armed for one descriptor, so its index is the token: the
/// MAC records which slot each descriptor holds, and lends a frame with the slot's
/// index as the cookie it is returned by.
///
/// The memory is the bus master's to write, so the pool must lie where the MAC's
/// DMA reaches and where what the controller wrote is what the CPU reads. Only the
/// board knows where that is; a MAC checks the pool's [`span`](Self::span) against
/// its board before it arms a slot.
pub trait MacRxPool {
    /// Bytes in each slot.
    fn slot_size(&self) -> usize;

    /// How many slots the pool has.
    fn slot_count(&self) -> usize;

    /// The first byte of the first slot and the length of all of them: every
    /// address the pool publishes lies inside.
    fn span(&self) -> (*const u8, usize);

    /// Take a free slot and arm it for receive: its index and the address the bus
    /// master is to write the frame to. `None` when every slot is out, which a ring
    /// answers by leaving the descriptor unarmed.
    fn arm_rx(&mut self) -> Option<(usize, *mut u8)>;

    /// The armed slot `idx` has been handed to the bus master: its descriptor is
    /// released. `false` when `idx` is not an armed slot.
    ///
    /// # Safety
    /// The caller must have released a descriptor with this slot's address to the
    /// controller. The pool then records the slot as the bus master's.
    unsafe fn start_rx(&mut self, idx: usize) -> bool;

    /// The bus master has finished writing slot `idx`: the slot is the CPU's to
    /// READ, shared, and its first byte is returned. `None` when `idx` is not a slot
    /// in the bus master's hands, so a stale or replayed completion advances nothing.
    ///
    /// # Safety
    /// The caller must have seen the controller report this slot's frame written.
    /// Calling early hands out memory the controller is still writing.
    unsafe fn complete_rx(&mut self, idx: usize) -> Option<*const u8>;

    /// Every reader of the completed slot `idx` is done with it: it goes back on the
    /// freelist. `false` when `idx` is not a completed slot, so a stale or foreign
    /// cookie frees nothing.
    fn release_rx(&mut self, idx: usize) -> bool;

    /// Slots on the freelist now.
    fn free_count(&self) -> usize;
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

    /// A MAC that says nothing about lending lends nothing: a stack is told so,
    /// takes frames through `receive`, and a stray return is harmless.
    #[test]
    fn a_mac_that_does_not_lend_says_so_and_lends_nothing() {
        let mut mac = Echo { held: None };
        assert!(mac.transmit(&[9u8; 40]));
        assert!(!mac.loans_rx());
        assert!(
            mac.receive_loan().is_none(),
            "even with a frame waiting, the default lends none"
        );
        mac.return_rx(0);
        let mut buf = [0u8; FRAME_MAX];
        assert_eq!(
            mac.receive(&mut buf),
            Some(40),
            "the frame is still there for the copying door"
        );
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
