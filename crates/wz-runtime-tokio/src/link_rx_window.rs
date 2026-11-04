// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2747 — FRAME BOUNDARIES OVER BYTES THAT ALREADY ARRIVED.
//!
//! ## The structure that did not exist
//!
//! `crate::poll_framed` frames by SIZING ITS READS: it asks the stream for
//! exactly the prefix, decodes a length, asks for exactly that payload, and
//! returns one frame. Every read is sized to what the loop still needs, so the
//! loop never holds a byte it has not accounted for — and that is precisely
//! what a fixed-buffer read cannot give it. `IORING_OP_READ_FIXED` fills a
//! REGISTERED slot and reports how much the kernel wrote; one completion can
//! carry several frames, one frame, a frame and a piece of the next, or a
//! single byte of a length prefix. Nothing in this crate turned "these bytes
//! arrived" into "these frames ended", so `crate::uring`'s adapter had nothing
//! to hand its slot to.
//!
//! That absence is what `runtime-tokio-uring`'s first residual comes down to.
//! It reads "nothing selects this path for a production link"; the reason
//! nothing could is that selecting it means framing bytes the reader did not
//! size, and no type here could express that.
//!
//! ## Upstream's shape, read rather than invented
//!
//! The pinned zenoh does not make its framing loop fixed-buffer aware. It runs
//! a SECOND read body — `rx_task` dispatches at task start to
//! `io/zenoh-transport/src/unicast/universal/link.rs` @ `async fn rx_task_uring(`
//! and leaves `rx_task_non_uring` untouched — and that body's streamed arm
//! hands the ring a callback rather than a loop. Between the completion and
//! the callback sits a state machine over delivered buffers:
//! `commons/zenoh-uring/src/linux/reader/window.rs` @ `enum RxWindowState {`,
//! whose `commons/zenoh-uring/src/linux/reader/window.rs` @ `pub(crate) fn push<F>(`
//! slices length-prefixed batches out of one buffer and carries what does not
//! fit into the next. [`RxWindow`] is that machine with wz's nouns.
//!
//! Three states, because a stream can break in exactly three places: between
//! frames, inside a length PREFIX, and inside a PAYLOAD. Upstream calls them
//! `Initial`, `SizeFragmented` and `Accumulating`; the third is where its
//! `commons/zenoh-uring/src/linux/api/reader/fragmented_batch.rs` @ `pub fn defragment(mut self) -> ZResult<DefragmentationState> {`
//! copies, and it is where this one copies too.
//!
//! ## What is DELIBERATELY not upstream's
//!
//! * THE PREFIX WIDTH. Upstream parses two bytes and only two. wz's reader
//!   takes 2 on the universal path and 4 under `transport-lowlatency`, fixing
//!   the width at FRAME START so a flag flip between frames never splits a
//!   prefix mid-read — so [`RxWindow::push`] takes the width and captures it
//!   into the prefix state, which is that same rule written for a reader that
//!   does not own its reads. The decode itself is not rewritten here:
//!   `decode_prefix` is what `crate::poll_framed` calls too, so the two
//!   bodies cannot read one number two ways. (A code span and not a link,
//!   because that function is `pub(crate)` and this module is `pub`: rustdoc
//!   refuses a public item's doc linking to a private one, which is exactly
//!   what the doc-link budget counts.)
//! * A ZERO-LENGTH BATCH IS SKIPPED, not emitted. Upstream emits an empty
//!   batch whose read loop then runs zero times. `crate::poll_framed` skips it
//!   instead (R2271, open-debt item 577: passing an empty payload up made
//!   `parse_inbound` answer `Empty` and lose the link), and wz's two bodies
//!   must agree frame-for-frame or a link changes meaning when it changes read
//!   path. So this one skips: the divergence is from upstream's SHAPE, not
//!   from its behaviour — both deliver no messages.
//! * THE FRAME IS LENT, NOT OWNED. Upstream's batch holds an `Arc<RxBuffer>`
//!   and keeps the slot alive; [`RxWindow::push`] hands `on_frame` a slice and
//!   the caller decides. A frame lying whole inside the pushed bytes is passed
//!   without a copy; only one that SPANS pushes is assembled, which is the same
//!   split upstream draws between a borrowed batch and a defragmented one.
//!
//! ## The refusal, and what does and does not witness it
//!
//! A 4-byte prefix is an untrusted `u32`, and a payload above `u16::MAX` is
//! refused before anything is carried, exactly as `crate::poll_framed` refuses
//! it. `scripts/lib/framing_refusal_reachability_gate.py` derives its
//! population from `poll_framed`'s BODY, so it does not see this one: the
//! refusal below is witnessed by a test in this module and NOT by that gate.
//! Stated rather than left for a later round to assume either way.

// THE MACHINE LIVES IN `wz_session_core::stream_window`, since a node with no heap frames a stream
// with the same decisions (its carry is fixed storage there, a `Vec` here). What this module keeps is
// the host's name for it and the tests that hold it to the sized reader, `crate::poll_framed`: the
// pieces below are that machine instantiated over a heap carry.
pub use wz_session_core::stream_window::WindowError;

/// The frame-boundary state machine for a reader that does not size its reads, over a heap carry:
/// [`wz_session_core::stream_window::RxWindow`], whose documentation is the machine's.
pub type RxWindow = wz_session_core::stream_window::RxWindow<Vec<u8>>;

/// The length a prefix names, at either width: shared with `crate::poll_framed` and with every
/// other reader of a length-prefixed stream
/// ([`wz_session_core::stream_window::decode_prefix`]).
pub(crate) use wz_session_core::stream_window::decode_prefix;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame_arena::HeapArena;
    use crate::{poll_framed, LinkEvent, ReadState};

    /// A wire carrying the four shapes a framing body has to tell apart: a
    /// plain frame, a ZERO-length batch, a one-byte frame, and a longer one.
    ///
    /// Built rather than written out so the prefix width is a parameter — the
    /// same frames at 2 bytes and at 4 are what the universal and lowlatency
    /// paths read, and a window that hard-coded either would still pass one of
    /// them.
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

    /// What `crate::poll_framed` makes of a wire — THE GROUND TRUTH the window
    /// has to agree with.
    ///
    /// Read from the other body rather than written down, because what is
    /// being pinned is that the two AGREE: a literal expectation here would
    /// still be met by two readers that had drifted apart, as long as both
    /// drifted to the literal.
    async fn frames_via_poll_framed(bytes: &[u8], lowlatency: bool) -> Vec<Vec<u8>> {
        let mut src: &[u8] = bytes;
        let mut st = ReadState::Idle;
        let mut out = Vec::new();
        loop {
            match poll_framed(&mut st, &mut src, lowlatency, &mut HeapArena).await {
                LinkEvent::Rx(frame) => out.push(frame.bytes.into_vec()),
                // The slice runs out, which that loop reads as EOF. Every other
                // event ends the stream too and none is expected here.
                _ => return out,
            }
        }
    }

    /// What [`RxWindow`] makes of the same wire, delivered in the pieces
    /// `cuts` names.
    fn frames_via_window(bytes: &[u8], width: usize, cuts: &[usize]) -> Vec<Vec<u8>> {
        let mut window = RxWindow::new();
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut prev = 0usize;
        for &cut in cuts.iter().chain(std::iter::once(&bytes.len())) {
            window
                .push(&bytes[prev..cut], width, &mut |frame: &[u8]| {
                    out.push(frame.to_vec())
                })
                .expect("this wire carries no oversize prefix");
            prev = cut;
        }
        out
    }

    /// THE CLAIM: the window frames a stream the same way the read-sizing body
    /// does, however the bytes are DELIVERED.
    ///
    /// The population is derived from the wire's own length rather than
    /// listed: every pair `0 <= i <= j <= L` is a way to break the stream into
    /// at most three pieces, which covers a prefix split at every byte, a
    /// payload split at every byte, deliveries that end exactly on a frame
    /// boundary, and deliveries that carry several frames at once. A list of
    /// "interesting" splits would have been written by the same reasoning the
    /// window was, and would agree with it for the same reasons.
    ///
    /// The count is ASSERTED, not merely used: an enumerator that silently
    /// produced nothing would leave this test green while measuring no
    /// delivery at all.
    #[tokio::test]
    async fn every_chunking_of_a_wire_frames_the_way_poll_framed_does() {
        for (width, lowlatency) in [(2usize, false), (4usize, true)] {
            let bytes = wire(width);
            let len = bytes.len();
            let expected = frames_via_poll_framed(&bytes, lowlatency).await;
            assert_eq!(
                expected,
                vec![b"abc".to_vec(), b"z".to_vec(), b"hello".to_vec()],
                "the other body skips the zero-length batch; if it stops doing \
                 that, the window must be re-derived rather than this loosened"
            );

            let mut chunkings = 0usize;
            for i in 0..=len {
                for j in i..=len {
                    let got = frames_via_window(&bytes, width, &[i, j]);
                    assert_eq!(
                        got, expected,
                        "width {width}, delivered as [0..{i}, {i}..{j}, {j}..{len}]"
                    );
                    chunkings += 1;
                }
            }
            assert_eq!(
                chunkings,
                (len + 1) * (len + 2) / 2,
                "the population is every pair 0 <= i <= j <= {len}"
            );

            // The extreme those pairs cannot reach: one byte per delivery, so
            // every prefix and every payload is split at every byte at once.
            let all: Vec<usize> = (0..=len).collect();
            assert_eq!(
                frames_via_window(&bytes, width, &all),
                expected,
                "width {width}, delivered one byte at a time"
            );
        }
    }

    /// A frame lying WHOLE inside one delivery is LENT, not copied — witnessed
    /// at the ADDRESS, which is the only place the difference exists.
    ///
    /// Asserting the payload bytes cannot see this: a window that copied every
    /// frame would produce identical bytes, which is why the differential test
    /// above is blind to it. The address says which storage the callback was
    /// handed, and the second half is what stops "it is always a subslice"
    /// from being the trivial reading — a frame that SPANS deliveries cannot
    /// be one, and is not.
    #[test]
    fn a_frame_whole_inside_one_delivery_is_lent_and_a_spanning_one_is_assembled() {
        let bytes = wire(2);
        let range = bytes.as_ptr_range();

        let mut window = RxWindow::new();
        let mut lent = Vec::new();
        window
            .push(&bytes, 2, &mut |frame: &[u8]| {
                lent.push(range.contains(&frame.as_ptr()))
            })
            .expect("no oversize prefix");
        assert_eq!(
            lent,
            vec![true, true, true],
            "every frame lay whole inside the delivery, so every one is a \
             subslice of it"
        );

        // Now split the first frame's payload across two deliveries. Its
        // callback slice can be inside NEITHER, because neither holds all of
        // it.
        let mut window = RxWindow::new();
        let mut inside = Vec::new();
        let head = &bytes[..4];
        let rest = &bytes[4..];
        let (r1, r2) = (head.as_ptr_range(), rest.as_ptr_range());
        window
            .push(head, 2, &mut |_: &[u8]| {
                unreachable!("the frame is incomplete")
            })
            .expect("no oversize prefix");
        window
            .push(rest, 2, &mut |frame: &[u8]| {
                inside.push(r1.contains(&frame.as_ptr()) || r2.contains(&frame.as_ptr()))
            })
            .expect("no oversize prefix");
        assert_eq!(
            inside.first(),
            Some(&false),
            "a frame that spans deliveries is assembled in the window's own \
             carry, so it is a subslice of neither"
        );
        assert!(
            inside[1..].iter().all(|x| *x),
            "the frames after it lie whole inside the second delivery and are \
             lent again -- the carry is not sticky"
        );
    }

    /// The refusal: a 4-byte prefix naming more than `u16::MAX`.
    ///
    /// Asserts the NAMED length as well as the refusal, so a window that
    /// refused every lowlatency prefix would not pass, and asserts the window
    /// is left BETWEEN FRAMES — a reader that loses the link and one that keeps
    /// the window must both find a machine holding nothing.
    #[test]
    fn an_oversize_u32_prefix_is_refused_before_anything_is_carried() {
        // u32 LE 0x0001_0000 = 65536 = u16::MAX + 1, the same value
        // `lowlatency_rx_rejects_oversize_u32_prefix` feeds the other body.
        let bytes = [0x00u8, 0x00, 0x01, 0x00, 0xde, 0xad];
        let mut window = RxWindow::new();
        let err = window
            .push(&bytes, 4, &mut |_: &[u8]| unreachable!("nothing is framed"))
            .expect_err("a prefix above u16::MAX is refused");
        assert_eq!(err, WindowError::OversizeBatch { named: 65536 });
        assert!(
            window.between_frames(),
            "the refusal resets the window, as poll_framed resets its ReadState"
        );
    }

    /// A window mid-frame says so, which is how a reader tells a clean end
    /// from a truncated one.
    ///
    /// `crate::poll_framed` answers that from its `ReadState`; a reader whose
    /// reads are sized by the kernel has only this. All three states are
    /// visited, because "between frames" is the answer in one of them and the
    /// wrong answer in the other two.
    #[test]
    fn the_window_says_whether_a_stream_could_end_here() {
        let bytes = wire(2);
        let mut window = RxWindow::new();
        assert!(window.between_frames(), "a fresh window holds nothing");

        // One byte in: half a length prefix.
        window
            .push(&bytes[..1], 2, &mut |_: &[u8]| unreachable!())
            .expect("no oversize prefix");
        assert!(
            !window.between_frames(),
            "half a prefix is a truncated frame"
        );

        // Three bytes in: the prefix is whole and one payload byte is carried.
        window
            .push(&bytes[1..3], 2, &mut |_: &[u8]| unreachable!())
            .expect("no oversize prefix");
        assert!(
            !window.between_frames(),
            "half a payload is a truncated frame"
        );

        // The rest of that frame, and nothing more.
        let mut seen = 0;
        window
            .push(&bytes[3..5], 2, &mut |_: &[u8]| seen += 1)
            .expect("no oversize prefix");
        assert_eq!(seen, 1, "the frame completes");
        assert!(
            window.between_frames(),
            "and the window is empty again, so a stream ending here is clean"
        );
    }
}
