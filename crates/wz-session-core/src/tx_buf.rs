// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
//! The trait is object safe on purpose: in a build that lends a slot
//! (`transport-tx-lend`) the encoders take `&mut dyn TxBuf` ([`EncodeBuf`]), so
//! the choice of destination does not multiply their instantiations, and the
//! MCU profile does not carry a copy of the framing code per buffer type. A
//! build that never lends names the vector itself instead: the sink then cannot
//! refuse a write and the encoders are as small as they were over `VecSink`.
//!
//! The targets are spelled out in full: this page's text is merged with the
//! outer doc on `pub mod tx_buf;` and the merged text resolves its relative
//! links from the crate root, so a bare name would not be found.
//!
//! [`TxBuf`]: crate::tx_buf::TxBuf
//! [`SliceTxBuf`]: crate::tx_buf::SliceTxBuf
//! [`TxSink`]: crate::tx_buf::TxSink
//! [`EncodeBuf`]: crate::tx_buf::EncodeBuf
//! [`CodecError::BufferOverflow`]: sce_forge_runtime::codec::CodecError::BufferOverflow
//! [`SceSink`]: sce_forge_runtime::codec::SceSink

use sce_forge_runtime::codec::{CodecError, SceSink};

/// What an outbound frame encoder needs of the place it writes to.
pub trait TxBuf {
    /// What a write this buffer refuses is refused with: [`CodecError`] for a buffer whose room
    /// runs out. A sink over the buffer answers the same error ([`TxSink`]), so the type of a
    /// destination says whether a frame written into it can be refused.
    type Error: core::fmt::Debug;

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
    fn append(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;

    /// Append one byte.
    fn append_byte(&mut self, byte: u8) -> Result<(), Self::Error> {
        self.append(&[byte])
    }

    /// Take the next `n` bytes as a window the caller fills: the length grows by `n` and the
    /// caller must write all of them. A writer that knows how long its message is checks the
    /// room once and stores each byte where it goes, where [`Self::append_byte`] checks it and
    /// is called through the trait object at every byte.
    ///
    /// `Ok(None)` means this buffer does not hand windows out and nothing was taken; the writer
    /// appends instead. [`CodecError::BufferOverflow`] means the `n` bytes do not fit, and the
    /// length is as it was, as for [`Self::append`].
    fn reserve(&mut self, n: usize) -> Result<Option<&mut [u8]>, Self::Error> {
        let _ = n;
        Ok(None)
    }
}

#[cfg(feature = "alloc")]
impl TxBuf for alloc::vec::Vec<u8> {
    type Error = CodecError;

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

    fn reserve(&mut self, n: usize) -> Result<Option<&mut [u8]>, CodecError> {
        let at = alloc::vec::Vec::len(self);
        self.resize(at.saturating_add(n), 0);
        Ok(self.get_mut(at..))
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
        self.storage.len().saturating_sub(self.len)
    }
}

impl TxBuf for SliceTxBuf<'_> {
    type Error = CodecError;

    fn len(&self) -> usize {
        self.len
    }

    fn as_slice(&self) -> &[u8] {
        // `len` only moves to the end of a window found in `storage`.
        self.storage.get(..self.len).unwrap_or_default()
    }

    fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.len = len;
        }
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        // A write past the end finds no window, and is refused whole.
        // A sum past `usize` would wrap below `len`, which names no window: refused all the same.
        let end = self.len.wrapping_add(bytes.len());
        let into = self
            .storage
            .get_mut(self.len..end)
            .ok_or(CodecError::BufferOverflow)?;
        into.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    fn reserve(&mut self, n: usize) -> Result<Option<&mut [u8]>, CodecError> {
        let end = self.len.wrapping_add(n);
        let window = self
            .storage
            .get_mut(self.len..end)
            .ok_or(CodecError::BufferOverflow)?;
        self.len = end;
        Ok(Some(window))
    }
}

/// A [`TxBuf`] that keeps no byte and counts the ones written to it.
///
/// What a send finds a message's length with when it holds the encoder its dispatch then runs
/// into the lent slot ([`encoded_len`]): the count and the write are then one compiled encoder,
/// where the codec's `measure` compiles the same field walk a second time over a sink of its
/// own type. It holds nothing to send, so [`TxBuf::as_slice`] is empty and it hands out no
/// window; it is never given to a link.
#[derive(Debug, Default)]
pub struct CountTxBuf {
    len: usize,
}

impl CountTxBuf {
    /// A count of nothing.
    pub const fn new() -> Self {
        Self { len: 0 }
    }
}

impl TxBuf for CountTxBuf {
    type Error = CodecError;

    fn len(&self) -> usize {
        self.len
    }

    fn as_slice(&self) -> &[u8] {
        &[]
    }

    fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.len = len;
        }
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        self.len = self.len.saturating_add(bytes.len());
        Ok(())
    }

    fn append_byte(&mut self, _byte: u8) -> Result<(), CodecError> {
        self.len = self.len.saturating_add(1);
        Ok(())
    }
}

/// The bytes `encode` writes, counted with nothing written ([`CountTxBuf`]): the length a send
/// asks its link to lend for a message whose encoder is the one its dispatch then runs. Zero for
/// a message the encoder refuses, which the dispatch's own run refuses with the same error.
///
/// Present where the encoders write through `dyn TxBuf` ([`EncodeBuf`]), which is what lets one
/// compiled encoder serve the count and the slot.
#[cfg(any(feature = "transport-tx-lend", not(feature = "alloc")))]
pub fn encoded_len(encode: &dyn Fn(&mut TxSink<'_>) -> Result<(), CodecError>) -> usize {
    let mut count = CountTxBuf::new();
    let written = encode(&mut TxSink::new(&mut count)).is_ok();
    if written {
        count.len
    } else {
        0
    }
}

/// A [`TxBuf`] that refuses to hold more than `cap` bytes, over another one.
///
/// What a sender encodes a frame through when the frame must not pass the batch
/// budget: a write that would carry it past the cap is refused whole, so a frame
/// that turns out to be too long is found out as soon as it is, and the payload
/// write that would have crossed the cap is never copied at all. Over a lent
/// slot at least `cap` long, a refusal therefore says the frame is past the
/// budget and must be cut into fragments, which is how the send path tells that
/// case from the others.
///
/// Like [`SliceTxBuf`] it needs no allocation and no runtime, so it is
/// unconditional; its caller in the session is the lending send path.
pub struct CappedTxBuf<'a, 'b> {
    inner: &'a mut (dyn TxBuf<Error = CodecError> + 'b),
    cap: usize,
}

impl<'a, 'b> CappedTxBuf<'a, 'b> {
    /// `inner`, held to `cap` bytes in all (what it already holds included).
    pub fn new(inner: &'a mut (dyn TxBuf<Error = CodecError> + 'b), cap: usize) -> Self {
        Self { inner, cap }
    }
}

impl TxBuf for CappedTxBuf<'_, '_> {
    type Error = CodecError;

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }

    fn truncate(&mut self, len: usize) {
        self.inner.truncate(len);
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        if self.inner.len().saturating_add(bytes.len()) > self.cap {
            return Err(CodecError::BufferOverflow);
        }
        self.inner.append(bytes)
    }

    /// Forwarded as a byte, so the buffer underneath can store it without the
    /// one-byte slice the default would build and pass through two calls.
    fn append_byte(&mut self, byte: u8) -> Result<(), CodecError> {
        if self.inner.len() >= self.cap {
            return Err(CodecError::BufferOverflow);
        }
        self.inner.append_byte(byte)
    }

    /// The cap is checked as an append checks it, then the window is the buffer's own.
    fn reserve(&mut self, n: usize) -> Result<Option<&mut [u8]>, CodecError> {
        if self.inner.len().saturating_add(n) > self.cap {
            return Err(CodecError::BufferOverflow);
        }
        self.inner.reserve(n)
    }
}

/// Adapts a [`TxBuf`] to the codec's [`SceSink`].
///
/// Like `VecSink`, it reports the bytes written by THIS sink since it wrapped
/// the buffer, not the buffer's absolute length, so codec emit stays
/// positionally consistent when the destination already holds a frame prefix
/// (the batching writer appends a message to an open frame).
pub struct TxSink<'a, B: TxBuf + ?Sized = EncodeBuf<'a>> {
    buf: &'a mut B,
    start: usize,
}

/// The buffer type every body encoder is written against.
///
/// A build that lends outbound slots (`transport-tx-lend`) writes through
/// `dyn TxBuf`, so one encoder serves a heap vector and a link's slot alike.
/// A build that never lends names the vector itself: its sink then cannot
/// refuse a write, the codec's `?` after each write folds away, and the
/// encoders are the size they were when they wrote a `VecSink`. The choice is
/// a feature and not a generic parameter because the link a session writes to
/// is a trait object, so no type reachable from the session can prove that a
/// slot is never lent.
#[cfg(any(feature = "transport-tx-lend", not(feature = "alloc")))]
pub type EncodeBuf<'a> = dyn TxBuf<Error = CodecError> + 'a;
/// See the lending form above.
#[cfg(all(not(feature = "transport-tx-lend"), feature = "alloc"))]
pub type EncodeBuf<'a> = alloc::vec::Vec<u8>;

/// Whether this build is the LEND-ONLY profile (`tx-lend-only`, fixed-memory
/// step S4): every frame the session sends is encoded into a slot its link
/// lends, and a send for which none is lent is a counted refusal, never a frame
/// built on the heap.
///
/// A constant and not only a `cfg`, so a crate that is written for the other
/// profile can state the fact in one place and refuse the build that disagrees:
/// the AP's `wz-runtime-tokio` falls back to a heap frame when its pool is dry,
/// and a session that refused there instead would be a regression no test of
/// the AP's own configuration could see.
pub const TX_LEND_ONLY: bool = cfg!(feature = "tx-lend-only");

/// Whether this build compiled the per-session slot profile (`session-slot`,
/// fixed-memory step S5): `false` on every build the AP links. (Here, beside
/// [`TX_LEND_ONLY`], because this module is compiled in every build and the
/// session bundle's is not.)
///
/// A crate that shares this one with an MCU build and cannot work on that
/// profile does not assert this constant: it wraps its items in
/// [`heap_session_profile!`](crate::heap_session_profile). The selector does not
/// add to the heap forms, it replaces them (the session handle, the link sink,
/// the received extension chains), so a heap crate that a build graph unified it
/// into fails to type-check, and an assertion on a constant is evaluated after
/// the type check: its message is the one such a build does not print.
pub const SESSION_SLOT: bool = cfg!(feature = "session-slot");

/// The items given, on a build of the heap session profile; on a build that
/// compiled the per-session slot profile (`session-slot`), one `compile_error!`
/// that names the crate refused and the cause, and no item.
///
/// For a crate written for the heap profile only, around every item of its
/// root (`"crate-name"; items`). Features unify across the build graph, and a
/// workspace-wide `--all-features` turns this selector on from every crate that
/// has it; without the wrapper such a build reports each heap item of the crate
/// that the slot profile lacks, and no line of it names the selector. The
/// refusal is raised while the crate's macros expand, before its items are
/// resolved or type-checked, and the items it drops add no error of their own.
/// A crate whose root is more than a list of modules may give no items: its
/// refusal is then the first error of the build and not the only one.
#[cfg(not(feature = "session-slot"))]
#[macro_export]
macro_rules! heap_session_profile {
    ($krate:literal; $($items:tt)*) => { $($items)* };
}

/// See the heap-profile form of this macro: the refusal, on a build that
/// compiled the slot profile.
#[cfg(feature = "session-slot")]
#[macro_export]
macro_rules! heap_session_profile {
    ($krate:literal; $($items:tt)*) => {
        ::core::compile_error!(::core::concat!(
            $krate,
            " is written for the heap session profile, and this build turned on \
             `wz-session-core/session-slot`, the per-session slot profile of an MCU image. \
             The two are exclusive: the slot profile replaces the heap forms of the session \
             and does not add to them. The selector reached this crate by feature \
             unification (a workspace-wide `--all-features`, or a crate of this build that \
             names it on a dependency line); build this crate and the slot image apart."
        ));
    };
}

impl<'a> TxSink<'a, EncodeBuf<'a>> {
    /// Wrap `buf`; the position starts at the buffer's current length.
    pub fn new(buf: &'a mut EncodeBuf<'a>) -> Self {
        let start = buf.len();
        Self { buf, start }
    }
}

impl<'a, B: TxBuf + ?Sized> TxSink<'a, B> {
    /// Wrap a buffer of any type; the position starts at its current length. [`Self::new`] is
    /// this for the one buffer type the build's encoders are written against.
    pub fn over(buf: &'a mut B) -> Self {
        let start = buf.len();
        Self { buf, start }
    }

    /// The next `n` bytes of the buffer as a window to fill, or `None` when the buffer hands
    /// none out (see [`TxBuf::reserve`]). The sink's position counts the window as written.
    pub fn reserve(&mut self, n: usize) -> Result<Option<&mut [u8]>, B::Error> {
        self.buf.reserve(n)
    }
}

impl<B: TxBuf + ?Sized> SceSink for TxSink<'_, B>
where
    CodecError: From<B::Error>,
{
    /// A write the buffer refuses is the sink's error, and it is the codec's own: a codec that can
    /// refuse a value takes `CodecError: From<Self::Error>`, which this type meets by being it.
    type Error = CodecError;

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        self.buf.append(bytes).map_err(CodecError::from)
    }

    fn write_u8(&mut self, b: u8) -> Result<(), CodecError> {
        self.buf.append_byte(b).map_err(CodecError::from)
    }

    fn position(&self) -> usize {
        self.buf.len().saturating_sub(self.start)
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

    #[test]
    fn a_count_buffer_counts_what_is_written_and_holds_none_of_it() {
        let mut count = CountTxBuf::new();
        {
            let mut sink = TxSink::over(&mut count);
            sink.write_u8(1).unwrap();
            sink.write_bytes(&[2, 3, 4]).unwrap();
            sink.write_bytes(&[]).unwrap();
            assert_eq!(sink.position(), 4);
            assert!(
                matches!(sink.reserve(2), Ok(None)),
                "a count hands out no window"
            );
        }
        assert_eq!(count.len(), 4);
        assert!(count.as_slice().is_empty());
        count.truncate(9);
        assert_eq!(count.len(), 4, "a truncate past the end changes nothing");
        count.truncate(1);
        assert_eq!(count.len(), 1);
    }

    #[cfg(any(feature = "transport-tx-lend", not(feature = "alloc")))]
    #[test]
    fn the_encoded_length_is_what_the_encoder_writes_and_zero_for_a_refusal() {
        let written = encoded_len(&|sink: &mut TxSink<'_>| {
            sink.write_u8(0x7f)?;
            sink.write_bytes(&[0u8; 300])
        });
        assert_eq!(written, 301);
        // A refusal after a byte was written still counts as nothing.
        let refused = encoded_len(&|sink: &mut TxSink<'_>| {
            sink.write_u8(1)?;
            Err(CodecError::LengthOutOfRange)
        });
        assert_eq!(refused, 0);
        assert_eq!(encoded_len(&|_: &mut TxSink<'_>| Ok(())), 0);
    }

    #[cfg(not(feature = "session-slot"))]
    crate::heap_session_profile! {
        "wz-session-core";
        fn given_to_the_heap_profile() -> u8 {
            7
        }
    }

    // The slot arm is a `compile_error!` and has no test that can compile; the
    // build it refuses is the check (`wz-capi-coop` with the selector unified).
    #[cfg(not(feature = "session-slot"))]
    #[test]
    fn the_heap_profile_compiles_the_items_it_is_given() {
        assert_eq!(given_to_the_heap_profile(), 7);
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
