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

    /// Hold the buffer to `end` bytes: a write that would carry it past `end` is refused as one
    /// past the storage is, before a byte of it is copied, so a frame budget smaller than the
    /// storage is the buffer's own end. Storage shorter than `end` keeps its end, and the bytes
    /// already written are never cut.
    pub fn hold_to(&mut self, end: usize) {
        let storage = core::mem::take(&mut self.storage);
        let end = core::cmp::min(core::cmp::max(end, self.len), storage.len());
        self.storage = storage.split_at_mut(end).0;
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
/// into the lent slot (`encoded_len`): the count and the write are then one compiled encoder,
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
    try_encoded_len(encode).unwrap_or(0)
}

/// [`encoded_len`] with the encoder's refusal kept: the length a lent fragment chain is planned
/// over, where a message its encoder refuses is answered with that error and not cut at all.
///
/// Kept out of line: it is the one count both forms share, and inlined it would be compiled
/// again into each.
#[cfg(any(feature = "transport-tx-lend", not(feature = "alloc")))]
#[inline(never)]
pub fn try_encoded_len(
    encode: &dyn Fn(&mut TxSink<'_>) -> Result<(), CodecError>,
) -> Result<usize, CodecError> {
    let mut count = CountTxBuf::new();
    encode(&mut TxSink::new(&mut count))?;
    Ok(count.len)
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
/// For a crate written for the heap profile only, at its root and given no
/// items (`"crate-name";`). Features unify across the build graph, and a
/// workspace-wide `--all-features` turns this selector on from every crate that
/// has it; without the refusal such a build reports each heap item of the crate
/// that the slot profile lacks, and no line of it names the selector. The
/// refusal is raised while the crate's macros expand, before the crate's items
/// are resolved or type-checked, so it is the first error of the build. Items
/// given to it are dropped with it and add no error of their own, but a root's
/// `mod` declarations are not given: rustfmt does not read a macro's body, and
/// the modules declared in one would be formatted by no `cargo fmt`.
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

    /// The u64 form's bytes: a u32 runs out of bits before either width's continuation cap, so
    /// the two forms write the same VLE, and one body writes both.
    fn write_vle_u32(&mut self, v: u32) -> Result<(), CodecError> {
        self.write_vle_u64(u64::from(v))
    }

    /// The u64 form's bytes, as for the u32 form: a u16 runs out of bits before its cap too.
    fn write_vle_u16(&mut self, v: u16) -> Result<(), CodecError> {
        self.write_vle_u64(u64::from(v))
    }

    // Out of line, so the narrower forms are a call to this body and not a copy of it. The bytes
    // are the trait's own writer's, appended in one call of the buffer, or refused whole.
    #[inline(never)]
    fn write_vle_u64(&mut self, v: u64) -> Result<(), CodecError> {
        let mut bytes = [0u8; wz_codecs::vle::VLE_LEN];
        let n = wz_codecs::vle::encode_zint(&mut bytes, v);
        self.write_bytes(bytes.get(..n).unwrap_or(&bytes))
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
    fn a_slice_buffer_held_to_a_budget_refuses_a_write_past_it() {
        let mut storage = [0u8; 8];
        {
            let mut buf = SliceTxBuf::new(&mut storage);
            buf.append(&[1, 2]).unwrap();
            buf.hold_to(4);
            assert_eq!((buf.capacity(), buf.remaining()), (4, 2));
            assert_eq!(buf.append(&[3, 3, 3]), Err(CodecError::BufferOverflow));
            assert!(matches!(buf.reserve(3), Err(CodecError::BufferOverflow)));
            buf.append(&[3, 4]).unwrap();
            assert_eq!(buf.append_byte(5), Err(CodecError::BufferOverflow));
            buf.hold_to(1);
            assert_eq!(buf.as_slice(), &[1, 2, 3, 4], "a hold cuts no written byte");
            buf.hold_to(64);
            assert_eq!(buf.capacity(), 4, "a hold never moves the end out again");
        }
        assert_eq!(
            &storage[4..],
            &[0u8; 4],
            "nothing was written past the budget"
        );

        let mut storage = [0u8; 3];
        let mut buf = SliceTxBuf::new(&mut storage);
        buf.hold_to(16);
        assert_eq!(
            buf.capacity(),
            3,
            "storage shorter than the budget keeps its end"
        );
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

    /// The u32 VLE is the u64 VLE of the same value, at every width a u32 takes and at both ends
    /// of each. Turned red by a u32 form that writes other bytes than the u64 form's.
    #[test]
    fn a_u32_vle_is_written_as_the_u64_vle_of_its_value() {
        let widths = [
            0u32,
            0x7F,
            0x80,
            0x3FFF,
            0x4000,
            0x1F_FFFF,
            0x20_0000,
            0x0FFF_FFFF,
            0x1000_0000,
            u32::MAX,
        ];
        for v in widths {
            let mut narrow = [0u8; 16];
            let mut narrow_buf = SliceTxBuf::new(&mut narrow);
            TxSink::new(&mut narrow_buf).write_vle_u32(v).unwrap();
            let mut wide = [0u8; 16];
            let mut wide_buf = SliceTxBuf::new(&mut wide);
            TxSink::new(&mut wide_buf)
                .write_vle_u64(u64::from(v))
                .unwrap();
            assert_eq!(narrow_buf.as_slice(), wide_buf.as_slice(), "value {v:#x}");
        }
        let mut storage = [0u8; 16];
        let mut buf = SliceTxBuf::new(&mut storage);
        TxSink::new(&mut buf).write_vle_u32(u32::MAX).unwrap();
        assert_eq!(buf.as_slice(), &[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);
    }

    /// A sink with the trait's own writers, over a fixed array: the bytes a VLE is held to.
    struct TraitWriter {
        bytes: [u8; 16],
        len: usize,
    }

    impl SceSink for TraitWriter {
        type Error = CodecError;

        fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
            let end = self.len + bytes.len();
            self.bytes[self.len..end].copy_from_slice(bytes);
            self.len = end;
            Ok(())
        }

        fn write_u8(&mut self, b: u8) -> Result<(), CodecError> {
            self.write_bytes(&[b])
        }

        fn position(&self) -> usize {
            self.len
        }
    }

    /// A slice buffer that counts the calls that write it.
    struct Appends<'a> {
        buf: SliceTxBuf<'a>,
        calls: usize,
    }

    impl TxBuf for Appends<'_> {
        type Error = CodecError;

        fn len(&self) -> usize {
            self.buf.len()
        }

        fn as_slice(&self) -> &[u8] {
            self.buf.as_slice()
        }

        fn truncate(&mut self, len: usize) {
            self.buf.truncate(len);
        }

        fn append(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
            self.calls += 1;
            self.buf.append(bytes)
        }

        fn append_byte(&mut self, byte: u8) -> Result<(), CodecError> {
            self.calls += 1;
            self.buf.append_byte(byte)
        }
    }

    /// The sink writes a VLE of each width in the bytes of the codec's own writer, at both ends of
    /// every width the form takes, and in one call of its buffer. Turned red by an encoding that
    /// differs from the trait's writer in a byte, and by a writer that appends a byte at a time.
    #[test]
    fn a_vle_is_the_codecs_bytes_in_one_append() {
        let mut edges = std::vec![0u64, 1, u64::MAX];
        for bits in (7..64).step_by(7) {
            edges.push((1u64 << bits) - 1);
            edges.push(1u64 << bits);
        }
        for value in edges {
            for width in [16u32, 32, 64] {
                if width < 64 && value >> width != 0 {
                    continue;
                }
                let mut want = TraitWriter {
                    bytes: [0; 16],
                    len: 0,
                };
                let mut storage = [0u8; 16];
                let mut got = Appends {
                    buf: SliceTxBuf::new(&mut storage),
                    calls: 0,
                };
                let mut sink = TxSink::over(&mut got);
                match width {
                    16 => {
                        want.write_vle_u16(value as u16).unwrap();
                        sink.write_vle_u16(value as u16).unwrap();
                    }
                    32 => {
                        want.write_vle_u32(value as u32).unwrap();
                        sink.write_vle_u32(value as u32).unwrap();
                    }
                    _ => {
                        want.write_vle_u64(value).unwrap();
                        sink.write_vle_u64(value).unwrap();
                    }
                }
                assert_eq!(
                    got.as_slice(),
                    &want.bytes[..want.len],
                    "the u{width} VLE of {value:#x}"
                );
                assert_eq!(got.calls, 1, "the u{width} VLE of {value:#x}");
            }
        }
    }

    /// A VLE past the room is refused whole: the buffer keeps the length it had. Turned red by a
    /// writer that appends what fits before it refuses.
    #[test]
    fn a_vle_past_the_room_is_refused_whole() {
        let mut storage = [0u8; 3];
        let mut buf = SliceTxBuf::new(&mut storage);
        buf.append(&[9]).unwrap();
        assert_eq!(
            TxSink::over(&mut buf).write_vle_u64(0x4000),
            Err(CodecError::BufferOverflow)
        );
        assert_eq!(buf.as_slice(), &[9]);
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

    #[cfg(any(feature = "transport-tx-lend", not(feature = "alloc")))]
    #[test]
    fn the_tried_length_keeps_the_encoders_refusal() {
        let written = try_encoded_len(&|sink: &mut TxSink<'_>| {
            sink.write_u8(0x7f)?;
            sink.write_bytes(&[0u8; 300])
        });
        assert_eq!(written, Ok(301));
        let refused = try_encoded_len(&|sink: &mut TxSink<'_>| {
            sink.write_u8(1)?;
            Err(CodecError::LengthOutOfRange)
        });
        assert_eq!(refused, Err(CodecError::LengthOutOfRange));
        assert_eq!(try_encoded_len(&|_: &mut TxSink<'_>| Ok(())), Ok(0));
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
        let buf: &mut dyn TxBuf<Error = CodecError> = &mut v;
        buf.append(&[1, 2, 3]).unwrap();
        buf.append_byte(4).unwrap();
        assert_eq!(buf.as_slice(), &[1, 2, 3, 4]);
        buf.truncate(1);
        assert_eq!(buf.len(), 1);
        assert!(!buf.is_empty());
    }
}
