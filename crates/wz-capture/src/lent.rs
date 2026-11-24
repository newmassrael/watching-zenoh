// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The capture containers a [`crate::Dissection`] is lent, read by the offset
//! a kept place names.
//!
//! A place in a lent container is one word, an offset, and a capture written as
//! several containers is lent one container after another. The offset is
//! therefore counted across the capture: a container's first byte stands at the
//! sum of the lengths the containers before it were read to
//! ([`crate::CaptureCursor::next_container`]). One word still says which
//! container a place is in, every kept record stays its width, and a place in
//! an earlier container is read from that container for as long as it is
//! lent.

use alloc::sync::Arc;
use alloc::vec::Vec;
use wz_session_core::byte_log::LentBytes;

use crate::LentCapture;

/// One container of the capture, as it was lent.
#[derive(Debug, Clone)]
struct Piece {
    /// The capture offset of its first byte.
    first_byte: usize,
    /// Its place among the capture's containers, counting from zero.
    ordinal: usize,
    capture: Arc<dyn LentCapture>,
}

/// Every container a dissection has been lent, oldest first.
#[derive(Debug, Clone, Default)]
pub(crate) struct LentContainers {
    pieces: Vec<Piece>,
}

impl LentContainers {
    /// These containers with `capture` lent as the container numbered
    /// `ordinal`, whose first byte stands at capture offset `first_byte`.
    ///
    /// A container already lent under that number is the same container
    /// grown or moved, and `capture` takes its place, holding every byte it
    /// held at the same offset ([`LentCapture`]); a later number is appended.
    pub(crate) fn with(
        self,
        capture: Arc<dyn LentCapture>,
        first_byte: usize,
        ordinal: usize,
    ) -> Self {
        let mut pieces = self.pieces;
        match pieces.last_mut() {
            Some(last) if last.ordinal == ordinal => {
                last.capture = capture;
                last.first_byte = first_byte;
            }
            _ => pieces.push(Piece {
                first_byte,
                ordinal,
                capture,
            }),
        }
        Self { pieces }
    }

    /// Whether `capture` is already lent as the container numbered
    /// `ordinal`: lending it again changes nothing.
    pub(crate) fn holds(&self, capture: &Arc<dyn LentCapture>, ordinal: usize) -> bool {
        self.pieces
            .last()
            .is_some_and(|last| last.ordinal == ordinal && Arc::ptr_eq(&last.capture, capture))
    }

    /// The number of the container that holds capture offset `at`.
    pub(crate) fn ordinal_of(&self, at: usize) -> Option<usize> {
        self.piece_of(at).map(|piece| piece.ordinal)
    }

    /// The container whose bytes begin at or before `at` last.
    fn piece_of(&self, at: usize) -> Option<&Piece> {
        let after = self.pieces.partition_point(|piece| piece.first_byte <= at);
        self.pieces.get(after.checked_sub(1)?)
    }
}

impl LentBytes for LentContainers {
    fn lent(&self, at: usize, len: usize) -> Option<&[u8]> {
        let piece = self.piece_of(at)?;
        let from = at - piece.first_byte;
        piece.capture.bytes().get(from..from.checked_add(len)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lent(bytes: &[u8]) -> Arc<dyn LentCapture> {
        Arc::new(bytes.to_vec())
    }

    /// An offset is read from the container it falls in, a later container is
    /// appended under its number, and the same number lent again replaces the
    /// container it names.
    #[test]
    fn an_offset_is_read_from_the_container_it_falls_in() {
        let first = LentContainers::default().with(lent(b"abcdef"), 0, 0);
        assert_eq!(first.lent(2, 3), Some(&b"cde"[..]));
        assert_eq!(first.lent(4, 3), None, "past the container's end");
        let grown = first.with(lent(b"abcdefgh"), 0, 0);
        assert_eq!(grown.lent(4, 3), Some(&b"efg"[..]), "the grown container");
        let two = grown.with(lent(b"XYZ"), 6, 1);
        assert_eq!(two.lent(1, 2), Some(&b"bc"[..]), "the first one stays");
        assert_eq!(two.lent(6, 3), Some(&b"XYZ"[..]), "the second at its base");
        assert_eq!(two.lent(7, 3), None, "a read never spans two containers");
        assert_eq!(two.ordinal_of(5), Some(0));
        assert_eq!(two.ordinal_of(6), Some(1));
        assert_eq!(LentContainers::default().ordinal_of(0), None);
    }

    /// Lending the container already lent under its number changes nothing.
    #[test]
    fn the_same_container_lent_again_is_held() {
        let capture = lent(b"abc");
        let held = LentContainers::default().with(capture.clone(), 0, 0);
        assert!(held.holds(&capture, 0));
        assert!(!held.holds(&capture, 1), "another number, another one");
        assert!(!held.holds(&lent(b"abc"), 0), "another buffer is lent");
    }
}
