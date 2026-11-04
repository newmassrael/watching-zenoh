// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Frame boundaries over bytes that already arrived, for every length-prefixed stream link.
//!
//! A stream carries no message boundary, so a stream link frames it with a length prefix: two
//! bytes on the universal path, four under `transport-lowlatency`, little-endian. A reader that
//! does not size its reads (a registered-slot read on a host, a TCP receive callback on a node
//! with no heap) is handed whatever arrived: several frames, one, a frame and a piece of the next,
//! or a single byte of a prefix. [`RxWindow`](crate::stream_window::RxWindow) turns "these bytes
//! arrived" into "these frames ended", and it is the one decision of that kind: the host's reader
//! and a node's reader both run it, so a link does not mean one thing on a host and another on a
//! node.
//!
//! Three states, because a stream can break in exactly three places: between frames, inside a
//! prefix, and inside a payload. Only the third copies, and only a frame that does not lie whole
//! inside one push: such a frame is assembled in the window's
//! [`Carry`](crate::stream_window::Carry), whose storage is the caller's choice. A host gives it a
//! `Vec` (the frame can be as large as the prefix allows); a node with no heap gives it
//! [`FixedCarry`](crate::stream_window::FixedCarry), and a spanning frame larger than that is
//! refused ([`WindowError::CarryTooSmall`](crate::stream_window::WindowError::CarryTooSmall))
//! where a whole frame of the same size would still be passed through.
//!
//! The links of these module docs name their targets from the crate root, as the crate's other
//! modules documented on their `pub mod` line too do (`pool_gauge`): by their short names rustdoc
//! resolved none of them, under every feature set of the crate.
//!
//! Rules the window keeps, all of them what the host's sized reader keeps:
//!
//! * The prefix width is read when a prefix STARTS and carried with it, so a flag flip between
//!   two pushes never widens a prefix that is half read.
//! * A zero-length batch is skipped, not passed up: an empty payload parses to nothing.
//! * A four-byte prefix is an untrusted `u32`: one naming more than
//!   [`MAX_FRAME_PAYLOAD`](crate::stream_window::MAX_FRAME_PAYLOAD) is refused before anything is
//!   carried, and the window is left between frames.
//!
//! Unconditional, no_std and no_alloc; the `Vec` carry exists with the `alloc` feature.

use core::fmt;

/// The most a frame's payload may hold: the largest batch a peer negotiates is one the two-byte
/// prefix can name.
pub const MAX_FRAME_PAYLOAD: usize = u16::MAX as usize;

/// The width of the length prefix a stream link frames with: four bytes on a negotiated and
/// established `transport-lowlatency` link, two on every other frame (the handshake of a
/// lowlatency link included).
pub const fn prefix_width(lowlatency: bool) -> usize {
    if lowlatency {
        4
    } else {
        2
    }
}

/// The length a prefix names, at either width (little-endian).
///
/// The ceiling is not applied here. Each reader refuses an over-max length in its own vocabulary
/// (a lost link there, a [`WindowError`] here), and a shared decoder that returned an `Option`
/// would make one of them invent a cause for the other's refusal.
pub fn decode_prefix(prefix: &[u8; 4], width: usize) -> usize {
    if width == 4 {
        u32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize
    } else {
        u16::from_le_bytes([prefix[0], prefix[1]]) as usize
    }
}

/// Why a push stopped short of consuming its bytes.
///
/// Running out of bytes is not an error, it is the window's ordinary carry; and the end of the
/// stream is the reader's to interpret, which is why [`RxWindow::between_frames`] exists rather
/// than an end-of-stream variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowError {
    /// A four-byte prefix named a payload above [`MAX_FRAME_PAYLOAD`].
    ///
    /// The window is reset to between frames before this returns, so a caller that loses the link
    /// and a caller that keeps the window both find a machine holding nothing.
    OversizeBatch {
        /// The length the prefix named.
        named: usize,
    },
    /// A frame that spans pushes named more than the window's [`Carry`] can hold. The window is
    /// reset to between frames; the link cannot be read on from here, because the bytes of the
    /// frame that follow would be read as a prefix.
    CarryTooSmall {
        /// The length the prefix named.
        named: usize,
    },
}

impl fmt::Display for WindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // The bound is named beside the offending length: a reader who sees only "invalid
            // length" cannot tell a hostile peer from a wz defect, and the two send them to
            // different places.
            Self::OversizeBatch { named } => write!(
                f,
                "a length prefix named {named} bytes, above the {MAX_FRAME_PAYLOAD} a frame may carry"
            ),
            Self::CarryTooSmall { named } => write!(
                f,
                "a frame of {named} bytes spans reads and is larger than the window's carry"
            ),
        }
    }
}

impl core::error::Error for WindowError {}

/// Where a frame that spans pushes is assembled. The window decides when; the storage decides
/// whether it can.
pub trait Carry {
    /// Make room for a frame of `want` bytes, or say there is none (`false`: the frame is
    /// refused). Called once per spanning frame, before its first byte is added.
    fn begin(&mut self, want: usize) -> bool;
    /// Append `bytes`, which the last `begin` made room for.
    fn extend(&mut self, bytes: &[u8]);
    /// The bytes added since `begin`.
    fn bytes(&self) -> &[u8];
    /// Forget the frame, and hold nothing between frames where the storage can.
    fn release(&mut self);
}

#[cfg(feature = "alloc")]
impl Carry for alloc::vec::Vec<u8> {
    fn begin(&mut self, _want: usize) -> bool {
        true
    }

    fn extend(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }

    fn bytes(&self) -> &[u8] {
        self
    }

    fn release(&mut self) {
        // Dropped, not cleared: nothing is held between frames, as the sized reader held nothing.
        *self = alloc::vec::Vec::new();
    }
}

/// A carry of `N` bytes held in the window itself, for a node with no heap.
#[derive(Debug, Clone, Copy)]
pub struct FixedCarry<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> FixedCarry<N> {
    /// A carry holding nothing.
    pub const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }
}

impl<const N: usize> Default for FixedCarry<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Carry for FixedCarry<N> {
    fn begin(&mut self, want: usize) -> bool {
        self.len = 0;
        want <= N
    }

    fn extend(&mut self, bytes: &[u8]) {
        // `begin` made room for the whole frame and the window adds no more than the frame.
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn release(&mut self) {
        self.len = 0;
    }
}

/// Where the stream can break, and what has to be remembered when it does.
#[derive(Debug, Clone, Copy)]
enum State {
    /// Between frames: the next byte starts a length prefix.
    Between,
    /// Inside a prefix: `have` of `width` bytes are in `prefix`. `width` is carried rather than
    /// re-read per push, so a flip between two pushes never widens a prefix half read.
    Prefix {
        prefix: [u8; 4],
        have: usize,
        width: usize,
    },
    /// Inside a payload: `have` of `want` bytes are seen, and are in the carry once any are.
    Payload { want: usize, have: usize },
}

/// The frame-boundary state machine for a reader that does not size its reads.
///
/// Feed it whatever a read delivered with [`RxWindow::push`]; it calls back once per complete
/// frame payload, in wire order, and remembers the remainder. It holds no frame between frames, so
/// a reader may hand it a different buffer every time.
#[derive(Debug)]
pub struct RxWindow<C: Carry> {
    state: State,
    carry: C,
}

impl<C: Carry + Default> Default for RxWindow<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Carry + Default> RxWindow<C> {
    /// A window holding nothing, over a default carry.
    pub fn new() -> Self {
        Self::with_carry(C::default())
    }
}

impl<C: Carry> RxWindow<C> {
    /// A window holding nothing, assembling spanning frames in `carry`.
    pub const fn with_carry(carry: C) -> Self {
        Self {
            state: State::Between,
            carry,
        }
    }

    /// Whether the stream could end here without truncating a frame.
    ///
    /// The reader's question, not the window's: a read of zero bytes is a clean peer close between
    /// frames and a truncated frame anywhere else.
    pub fn between_frames(&self) -> bool {
        matches!(self.state, State::Between)
    }

    fn reset(&mut self) {
        self.state = State::Between;
        self.carry.release();
    }

    /// Consume `bytes`, calling `on_frame` once per complete frame payload.
    ///
    /// The payload excludes the length prefix. `width` is 2 on the universal path and 4 under
    /// `transport-lowlatency` ([`prefix_width`]), and is read only when a prefix starts.
    ///
    /// A frame lying whole inside `bytes` is passed as a subslice of `bytes`, so nothing is
    /// copied; one that spans pushes is assembled in the carry and passed from there. The callback
    /// must consume what it is given before it returns.
    pub fn push<F>(
        &mut self,
        mut bytes: &[u8],
        width: usize,
        on_frame: &mut F,
    ) -> Result<(), WindowError>
    where
        F: FnMut(&[u8]),
    {
        while !bytes.is_empty() {
            match self.state {
                State::Between => {
                    self.state = State::Prefix {
                        prefix: [0u8; 4],
                        have: 0,
                        width,
                    };
                }
                State::Prefix {
                    mut prefix,
                    mut have,
                    width,
                } => {
                    let n = (width - have).min(bytes.len());
                    prefix[have..have + n].copy_from_slice(&bytes[..n]);
                    have += n;
                    bytes = &bytes[n..];
                    if have < width {
                        self.state = State::Prefix {
                            prefix,
                            have,
                            width,
                        };
                        continue;
                    }
                    let want = decode_prefix(&prefix, width);
                    // The four-byte prefix is an untrusted u32 and a well-formed peer rides the
                    // negotiated batch, so this never rejects one. The two-byte prefix is capped
                    // by its own type and cannot reach here.
                    if want > MAX_FRAME_PAYLOAD {
                        self.reset();
                        return Err(WindowError::OversizeBatch { named: want });
                    }
                    if want == 0 {
                        // A batch of no messages is read by doing nothing.
                        self.state = State::Between;
                        continue;
                    }
                    self.state = State::Payload { want, have: 0 };
                }
                State::Payload { want, mut have } => {
                    if have == 0 && bytes.len() >= want {
                        // Whole inside this push: lend it.
                        on_frame(&bytes[..want]);
                        bytes = &bytes[want..];
                        self.state = State::Between;
                        continue;
                    }
                    if have == 0 && !self.carry.begin(want) {
                        self.reset();
                        return Err(WindowError::CarryTooSmall { named: want });
                    }
                    let n = (want - have).min(bytes.len());
                    self.carry.extend(&bytes[..n]);
                    have += n;
                    bytes = &bytes[n..];
                    if have < want {
                        self.state = State::Payload { want, have };
                        continue;
                    }
                    on_frame(self.carry.bytes());
                    self.carry.release();
                    self.state = State::Between;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// A wire carrying the four shapes a framing body has to tell apart: a plain frame, a
    /// zero-length batch, a one-byte frame and a longer one, at the width given.
    fn wire(width: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for payload in [
            b"abc".as_slice(),
            b"".as_slice(),
            b"z".as_slice(),
            b"hello".as_slice(),
        ] {
            let n = payload.len();
            if width == 4 {
                out.extend_from_slice(&(n as u32).to_le_bytes());
            } else {
                out.extend_from_slice(&(n as u16).to_le_bytes());
            }
            out.extend_from_slice(payload);
        }
        out
    }

    fn expected() -> Vec<Vec<u8>> {
        std::vec![b"abc".to_vec(), b"z".to_vec(), b"hello".to_vec()]
    }

    /// The frames a window makes of `bytes` delivered in the pieces `cuts` names.
    fn frames_via<C: Carry>(
        mut window: RxWindow<C>,
        bytes: &[u8],
        width: usize,
        cuts: &[usize],
    ) -> Result<Vec<Vec<u8>>, WindowError> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut prev = 0usize;
        for &cut in cuts.iter().chain(core::iter::once(&bytes.len())) {
            window.push(&bytes[prev..cut], width, &mut |frame: &[u8]| {
                out.push(frame.to_vec())
            })?;
            prev = cut;
        }
        Ok(out)
    }

    /// The prefix width is the one the lowlatency flag names, and the decode is little-endian at
    /// both.
    #[test]
    fn the_prefix_is_two_bytes_or_four_and_little_endian() {
        assert_eq!(prefix_width(false), 2);
        assert_eq!(prefix_width(true), 4);
        assert_eq!(decode_prefix(&[0x34, 0x12, 0xff, 0xff], 2), 0x1234);
        assert_eq!(decode_prefix(&[0x78, 0x56, 0x34, 0x12], 4), 0x1234_5678);
    }

    /// The window frames a stream the same way however the bytes are delivered, over a heap carry
    /// and over a fixed one. The population is every pair `0 <= i <= j <= L`, which breaks the
    /// stream into at most three pieces at every byte; its size is asserted, so an enumerator that
    /// produced nothing would not leave the test green.
    #[test]
    fn every_chunking_of_a_wire_frames_the_same() {
        for width in [2usize, 4] {
            let bytes = wire(width);
            let len = bytes.len();
            let mut chunkings = 0usize;
            for i in 0..=len {
                for j in i..=len {
                    #[cfg(feature = "alloc")]
                    {
                        let heap =
                            frames_via(RxWindow::<Vec<u8>>::new(), &bytes, width, &[i, j]).unwrap();
                        assert_eq!(heap, expected(), "heap carry, width {width}, cuts {i} {j}");
                    }
                    let fixed =
                        frames_via(RxWindow::<FixedCarry<8>>::new(), &bytes, width, &[i, j])
                            .unwrap();
                    assert_eq!(
                        fixed,
                        expected(),
                        "fixed carry, width {width}, cuts {i} {j}"
                    );
                    chunkings += 1;
                }
            }
            assert_eq!(chunkings, (len + 1) * (len + 2) / 2);

            // One byte per delivery: every prefix and every payload split at every byte.
            let all: Vec<usize> = (0..=len).collect();
            assert_eq!(
                frames_via(RxWindow::<FixedCarry<8>>::new(), &bytes, width, &all).unwrap(),
                expected()
            );
        }
    }

    /// A frame lying whole inside one delivery is lent, not copied, and a spanning one is
    /// assembled in the carry: the difference exists only at the address.
    #[test]
    fn a_frame_whole_inside_one_delivery_is_lent_and_a_spanning_one_is_assembled() {
        let bytes = wire(2);
        let range = bytes.as_ptr_range();

        let mut window = RxWindow::<FixedCarry<8>>::new();
        let mut lent = Vec::new();
        window
            .push(&bytes, 2, &mut |frame: &[u8]| {
                lent.push(range.contains(&frame.as_ptr()))
            })
            .unwrap();
        assert_eq!(lent, std::vec![true, true, true]);

        let mut window = RxWindow::<FixedCarry<8>>::new();
        let mut inside = Vec::new();
        let (head, rest) = (&bytes[..4], &bytes[4..]);
        let (r1, r2) = (head.as_ptr_range(), rest.as_ptr_range());
        window
            .push(head, 2, &mut |_: &[u8]| {
                unreachable!("the frame is incomplete")
            })
            .unwrap();
        window
            .push(rest, 2, &mut |frame: &[u8]| {
                inside.push(r1.contains(&frame.as_ptr()) || r2.contains(&frame.as_ptr()))
            })
            .unwrap();
        assert_eq!(inside.first(), Some(&false), "assembled in the carry");
        assert!(inside[1..].iter().all(|x| *x), "the carry is not sticky");
    }

    /// A four-byte prefix naming more than a frame may hold is refused with the length it named,
    /// and the window is left between frames.
    #[test]
    fn an_oversize_u32_prefix_is_refused_before_anything_is_carried() {
        // u32 LE 0x0001_0000 = 65536 = u16::MAX + 1.
        let bytes = [0x00u8, 0x00, 0x01, 0x00, 0xde, 0xad];
        let mut window = RxWindow::<FixedCarry<8>>::new();
        let err = window
            .push(&bytes, 4, &mut |_: &[u8]| unreachable!("nothing is framed"))
            .unwrap_err();
        assert_eq!(err, WindowError::OversizeBatch { named: 65536 });
        assert!(window.between_frames());
    }

    /// A spanning frame larger than the fixed carry is refused, naming its length and leaving the
    /// window between frames; the same frame lying whole inside one delivery is still passed, and
    /// a frame that fits is assembled.
    #[test]
    fn a_fixed_carry_refuses_only_a_spanning_frame_larger_than_itself() {
        let mut big = std::vec![9u8, 0];
        big.extend_from_slice(b"123456789");

        let mut window = RxWindow::<FixedCarry<8>>::new();
        let mut seen = Vec::new();
        window
            .push(&big, 2, &mut |f: &[u8]| seen.push(f.to_vec()))
            .unwrap();
        assert_eq!(seen, std::vec![b"123456789".to_vec()], "whole: lent");

        let err = window
            .push(&big[..5], 2, &mut |_: &[u8]| unreachable!())
            .unwrap_err();
        assert_eq!(err, WindowError::CarryTooSmall { named: 9 });
        assert!(window.between_frames());

        let mut fits = std::vec![8u8, 0];
        fits.extend_from_slice(b"12345678");
        let got = frames_via(RxWindow::<FixedCarry<8>>::new(), &fits, 2, &[3]).unwrap();
        assert_eq!(got, std::vec![b"12345678".to_vec()]);
    }

    /// A window mid-frame says so, which is how a reader tells a clean end from a truncated one;
    /// all three states are visited, because "between frames" is the answer in one of them and the
    /// wrong answer in the other two.
    #[test]
    fn the_window_says_whether_a_stream_could_end_here() {
        let bytes = wire(2);
        let mut window = RxWindow::<FixedCarry<8>>::new();
        assert!(window.between_frames());

        window
            .push(&bytes[..1], 2, &mut |_: &[u8]| unreachable!())
            .unwrap();
        assert!(!window.between_frames(), "half a prefix");

        window
            .push(&bytes[1..3], 2, &mut |_: &[u8]| unreachable!())
            .unwrap();
        assert!(!window.between_frames(), "half a payload");

        let mut seen = 0;
        window
            .push(&bytes[3..5], 2, &mut |_: &[u8]| seen += 1)
            .unwrap();
        assert_eq!(seen, 1);
        assert!(window.between_frames());
    }

    /// The width is read when a prefix starts: a flip to the wider prefix between two pushes does
    /// not widen a prefix already half read.
    #[test]
    fn a_width_change_mid_prefix_does_not_widen_that_prefix() {
        let mut window = RxWindow::<FixedCarry<8>>::new();
        let mut seen = Vec::new();
        window
            .push(&[2u8], 2, &mut |_: &[u8]| unreachable!())
            .unwrap();
        window
            .push(&[0u8, b'o', b'k'], 4, &mut |f: &[u8]| seen.push(f.to_vec()))
            .unwrap();
        assert_eq!(seen, std::vec![b"ok".to_vec()]);
    }
}
