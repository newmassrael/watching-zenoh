// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The outbound frame buffer seam (ARCHITECTURE section 9.1).
//!
//! Section 9.1 says the codec "writes directly into a pool slot" and the link
//! then sends that slot, with no intermediate copy. The encoders in
//! [`crate::frame_encode`] were written against `VecSink` over a growable
//! `Vec<u8>`, so every outgoing frame (or every batch, on the batching path)
//! allocated a vector of its own and nothing could hand them a slot. This
//! module is the place the destination is chosen from:
//!
//! * [`TxBuf`] is what an encoder needs of its destination: how much is
//!   written, a way to roll a partial encode back, the written bytes (which
//!   is all a link's `send_blocking` takes), and an append that may refuse.
//! * `Vec<u8>` implements it and never refuses, so the heap path is the same
//!   bytes it always was.
//! * [`SliceTxBuf`] implements it over a borrowed fixed slice and refuses with
//!   [`CodecError::BufferOverflow`] when a write would pass the end. A pool
//!   slot's storage is such a slice, and so is any static MCU frame buffer.
//! * [`TxSink`] adapts any `TxBuf` to the codec's [`SceSink`], so the body
//!   encoders (`push_body` and its siblings) are written once against one
//!   concrete sink type instead of one per destination.
//!
//! The trait is object safe on purpose: the encoders take `&mut dyn TxBuf`, so
//! the choice of destination does not multiply their instantiations, and the
//! MCU profile does not carry a copy of the framing code per buffer type.
//!
//! The targets are spelled out in full: this page's text is merged with the
//! outer doc on `pub mod tx_buf;` and the merged text resolves its relative
//! links from the crate root, so a bare name would not be found.
//!
//! [`TxBuf`]: crate::tx_buf::TxBuf
//! [`SliceTxBuf`]: crate::tx_buf::SliceTxBuf
//! [`TxSink`]: crate::tx_buf::TxSink
//! [`CodecError::BufferOverflow`]: sce_forge_runtime::codec::CodecError::BufferOverflow
//! [`SceSink`]: sce_forge_runtime::codec::SceSink

use sce_forge_runtime::codec::{CodecError, SceSink};

/// What an outbound frame encoder needs of the place it writes to.
pub trait TxBuf {
    /// Bytes written so far.
    fn len(&self) -> usize;

    /// Nothing written yet. An empty buffer is "no frame open" to the batching
    /// writer.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The bytes written so far: what the link is handed.
    fn as_slice(&self) -> &[u8];

    /// Keep only the first `len` bytes. A `len` at or past the current length
    /// changes nothing (the contract of `Vec::truncate`). The batching writer
    /// uses it to roll back a message that did not fit the open frame.
    fn truncate(&mut self, len: usize);

    /// Append `bytes`. A growable buffer always succeeds; a fixed one returns
    /// [`CodecError::BufferOverflow`] and leaves its length as it was.
    fn append(&mut self, bytes: &[u8]) -> Result<(), CodecError>;

    /// Append one byte.
    fn append_byte(&mut self, byte: u8) -> Result<(), CodecError> {
        self.append(&[byte])
    }
}

#[cfg(feature = "alloc")]
impl TxBuf for alloc::vec::Vec<u8> {
    fn len(&self) -> usize {
        alloc::vec::Vec::len(self)
    }

    fn as_slice(&self) -> &[u8] {
        self
    }

    fn truncate(&mut self, len: usize) {
        alloc::vec::Vec::truncate(self, len);
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        self.extend_from_slice(bytes);
        Ok(())
    }

    fn append_byte(&mut self, byte: u8) -> Result<(), CodecError> {
        self.push(byte);
        Ok(())
    }
}

/// A [`TxBuf`] over a borrowed fixed slice: a pool slot's storage, or a static
/// frame buffer. It never allocates, and a write that would pass the end is
/// refused whole, so the bytes already written stay a valid prefix.
#[derive(Debug)]
pub struct SliceTxBuf<'a> {
    storage: &'a mut [u8],
    len: usize,
}

impl<'a> SliceTxBuf<'a> {
    /// Wrap `storage` with nothing written.
    pub fn new(storage: &'a mut [u8]) -> Self {
        Self { storage, len: 0 }
    }

    /// The most this buffer can hold.
    pub fn capacity(&self) -> usize {
        self.storage.len()
    }

    /// Room left.
    pub fn remaining(&self) -> usize {
        self.storage.len() - self.len
    }
}

impl TxBuf for SliceTxBuf<'_> {
    fn len(&self) -> usize {
        self.len
    }

    fn as_slice(&self) -> &[u8] {
        &self.storage[..self.len]
    }

    fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.len = len;
        }
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        if self.remaining() < bytes.len() {
            return Err(CodecError::BufferOverflow);
        }
        let end = self.len + bytes.len();
        self.storage[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

/// Adapts a [`TxBuf`] to the codec's [`SceSink`].
///
/// Like `VecSink`, it reports the bytes written by THIS sink since it wrapped
/// the buffer, not the buffer's absolute length, so codec emit stays
/// positionally consistent when the destination already holds a frame prefix
/// (the batching writer appends a message to an open frame).
pub struct TxSink<'a> {
    buf: &'a mut dyn TxBuf,
    start: usize,
}

impl<'a> TxSink<'a> {
    /// Wrap `buf`; the position starts at the buffer's current length.
    pub fn new(buf: &'a mut dyn TxBuf) -> Self {
        let start = buf.len();
        Self { buf, start }
    }
}

impl SceSink for TxSink<'_> {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        self.buf.append(bytes)
    }

    fn write_u8(&mut self, b: u8) -> Result<(), CodecError> {
        self.buf.append_byte(b)
    }

    fn position(&self) -> usize {
        self.buf.len() - self.start
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slice_buffer_is_a_prefix_of_what_was_written() {
        let mut storage = [0u8; 8];
        let mut buf = SliceTxBuf::new(&mut storage);
        buf.append(&[1, 2, 3]).unwrap();
        buf.append_byte(4).unwrap();
        assert_eq!(buf.as_slice(), &[1, 2, 3, 4]);
        assert_eq!(buf.len(), 4);
        assert_eq!(buf.remaining(), 4);
    }

    #[test]
    fn a_slice_buffer_refuses_a_write_past_the_end_and_keeps_its_prefix() {
        let mut storage = [0u8; 4];
        let mut buf = SliceTxBuf::new(&mut storage);
        buf.append(&[9, 9, 9]).unwrap();
        assert_eq!(buf.append(&[1, 2]), Err(CodecError::BufferOverflow));
        // The refused write wrote nothing: the length is unchanged and a write
        // that does fit still lands right after the old prefix.
        assert_eq!(buf.as_slice(), &[9, 9, 9]);
        buf.append_byte(7).unwrap();
        assert_eq!(buf.as_slice(), &[9, 9, 9, 7]);
        assert_eq!(buf.append_byte(8), Err(CodecError::BufferOverflow));
    }

    #[test]
    fn truncate_rolls_back_and_never_grows() {
        let mut storage = [0u8; 8];
        let mut buf = SliceTxBuf::new(&mut storage);
        buf.append(&[1, 2, 3, 4, 5]).unwrap();
        buf.truncate(2);
        assert_eq!(buf.as_slice(), &[1, 2]);
        buf.truncate(6); // past the end: nothing happens, as Vec::truncate
        assert_eq!(buf.as_slice(), &[1, 2]);
    }

    #[test]
    fn the_sink_counts_its_own_bytes_over_an_open_prefix() {
        let mut storage = [0u8; 16];
        let mut buf = SliceTxBuf::new(&mut storage);
        buf.append(&[0xAA, 0xBB]).unwrap();
        let mut sink = TxSink::new(&mut buf);
        assert_eq!(sink.position(), 0);
        sink.write_u8(1).unwrap();
        sink.write_bytes(&[2, 3]).unwrap();
        assert_eq!(sink.position(), 3);
        assert_eq!(buf.as_slice(), &[0xAA, 0xBB, 1, 2, 3]);
    }

    #[test]
    fn the_sink_surfaces_the_buffers_refusal() {
        let mut storage = [0u8; 2];
        let mut buf = SliceTxBuf::new(&mut storage);
        let mut sink = TxSink::new(&mut buf);
        sink.write_u8(1).unwrap();
        assert_eq!(sink.write_bytes(&[2, 3]), Err(CodecError::BufferOverflow));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn a_vec_buffer_grows_and_truncates_like_the_vec_it_is() {
        let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        let buf: &mut dyn TxBuf = &mut v;
        buf.append(&[1, 2, 3]).unwrap();
        buf.append_byte(4).unwrap();
        assert_eq!(buf.as_slice(), &[1, 2, 3, 4]);
        buf.truncate(1);
        assert_eq!(buf.len(), 1);
        assert!(!buf.is_empty());
    }
}
