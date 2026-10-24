//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-buffers 1.10.1, file
// src/zbuf.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

//! A buffer that is a sequence of shared slices, and its reader and writer.

use alloc::{sync::Arc, vec::Vec};
use core::{cmp, iter, num::NonZeroUsize};
#[cfg(feature = "std")]
use std::io;

use zenoh_collections::SingleOrVec;

use crate::{
    buffer::{Buffer, SplitBuffer},
    reader::{
        AdvanceableReader, BacktrackableReader, DidntRead, DidntSiphon, HasReader, Reader,
        SiphonableReader,
    },
    writer::{BacktrackableWriter, DidntWrite, HasWriter, Writer},
    ZSlice, ZSliceBuffer, ZSliceWriter,
};

/// A buffer of bytes that is a sequence of [`ZSlice`]s, which can share the memory of other
/// buffers: joining two buffers, or cutting one, copies no bytes.
#[derive(Debug, Clone, Default, Eq)]
pub struct ZBuf {
    slices: SingleOrVec<ZSlice>,
}

impl ZBuf {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            slices: SingleOrVec::empty(),
        }
    }

    pub fn clear(&mut self) {
        self.slices.clear();
    }

    #[inline(always)]
    pub fn zslices(&self) -> impl Iterator<Item = &ZSlice> + '_ {
        self.slices.as_ref().iter()
    }

    pub fn zslices_mut(&mut self) -> impl Iterator<Item = &mut ZSlice> + '_ {
        self.slices.as_mut().iter_mut()
    }

    pub fn into_zslices(self) -> impl Iterator<Item = ZSlice> {
        self.slices.into_iter()
    }

    /// Appends the slice, unless it is empty.
    #[inline(always)]
    pub fn push_zslice(&mut self, zslice: ZSlice) {
        if !zslice.is_empty() {
            self.slices.push(zslice);
        }
    }

    /// The whole buffer as one slice: the slice itself if there is one, and a copy if there are
    /// several (or an empty slice if there are none).
    pub fn to_zslice(&self) -> ZSlice {
        match self.slices.as_ref() {
            [] => ZSlice::empty(),
            [only] => only.clone(),
            all => {
                let mut bytes = Vec::with_capacity(all.iter().map(ZSlice::len).sum());
                for slice in all {
                    bytes.extend_from_slice(slice.as_slice());
                }
                bytes.into()
            }
        }
    }

    /// The writer of the last slice, if it has one (see [`ZSlice::writer`]).
    #[inline]
    fn opt_zslice_writer(&mut self) -> Option<ZSliceWriter<'_>> {
        self.slices.last_mut().and_then(|s| s.writer())
    }
}

// Buffer
impl Buffer for ZBuf {
    #[inline(always)]
    fn len(&self) -> usize {
        self.slices.as_ref().iter().map(ZSlice::len).sum()
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        // Cheaper than the length: it stops at the first byte.
        self.slices.as_ref().iter().all(ZSlice::is_empty)
    }
}

// SplitBuffer
impl SplitBuffer for ZBuf {
    type Slices<'a> = iter::Map<core::slice::Iter<'a, ZSlice>, fn(&'a ZSlice) -> &'a [u8]>;

    fn slices(&self) -> Self::Slices<'_> {
        self.slices.as_ref().iter().map(ZSlice::as_slice)
    }
}

/// Two buffers are equal if they hold the same bytes, wherever the slices are cut and whether or
/// not there is an empty slice among them (upstream calls a buffer that has an empty slice at its
/// end different from the same bytes without it).
impl PartialEq for ZBuf {
    fn eq(&self, other: &Self) -> bool {
        let (mut left, mut right) = (self.slices(), other.slices());
        let (mut here, mut there): (&[u8], &[u8]) = (&[], &[]);
        loop {
            // Both sides go on to their next slice that has a byte in it.
            while here.is_empty() {
                match left.next() {
                    Some(slice) => here = slice,
                    None => break,
                }
            }
            while there.is_empty() {
                match right.next() {
                    Some(slice) => there = slice,
                    None => break,
                }
            }
            match (here.is_empty(), there.is_empty()) {
                (true, true) => return true,
                (true, false) | (false, true) => return false,
                (false, false) => {}
            }
            let n = here.len().min(there.len());
            if here[..n] != there[..n] {
                return false;
            }
            here = &here[n..];
            there = &there[n..];
        }
    }
}

// From impls
impl From<ZSlice> for ZBuf {
    fn from(t: ZSlice) -> Self {
        let mut zbuf = ZBuf::empty();
        zbuf.push_zslice(t);
        zbuf
    }
}

impl<T> From<Arc<T>> for ZBuf
where
    T: ZSliceBuffer + 'static,
{
    fn from(t: Arc<T>) -> Self {
        let zslice: ZSlice = t.into();
        Self::from(zslice)
    }
}

impl<T> From<T> for ZBuf
where
    T: ZSliceBuffer + 'static,
{
    fn from(t: T) -> Self {
        let zslice: ZSlice = t.into();
        Self::from(zslice)
    }
}

// Reader
/// A position in a [`ZBuf`]: a slice, and a byte in it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ZBufPos {
    slice: usize,
    byte: usize,
}

/// Reads a [`ZBuf`] from its front.
#[derive(Debug, Clone)]
pub struct ZBufReader<'a> {
    inner: &'a ZBuf,
    cursor: ZBufPos,
}

impl ZBufReader<'_> {
    /// Moves the cursor to the start of the next slice.
    fn next_slice(&mut self) {
        self.cursor.slice += 1;
        self.cursor.byte = 0;
    }
}

impl Buffer for ZBufReader<'_> {
    fn len(&self) -> usize {
        self.remaining()
    }

    fn is_empty(&self) -> bool {
        self.cursor.slice >= self.inner.slices.len()
    }
}

impl<'a> HasReader for &'a ZBuf {
    type Reader = ZBufReader<'a>;

    fn reader(self) -> Self::Reader {
        ZBufReader {
            inner: self,
            cursor: ZBufPos { slice: 0, byte: 0 },
        }
    }
}

impl Reader for ZBufReader<'_> {
    fn read(&mut self, mut into: &mut [u8]) -> Result<NonZeroUsize, DidntRead> {
        let mut read = 0;
        while let Some(slice) = self.inner.slices.get(self.cursor.slice) {
            // What is left of the slice being read, and as much of it as `into` takes.
            let from = crate::unsafe_slice!(slice.as_slice(), self.cursor.byte..);
            let len = from.len().min(into.len());
            let (head, rest) = core::mem::take(&mut into).split_at_mut(len);
            head.copy_from_slice(&from[..len]);
            into = rest;
            read += len;
            self.cursor.byte += len;
            // The slice is used up: on to the next one.
            if self.cursor.byte == slice.len() {
                self.next_slice();
            }
            if into.is_empty() {
                break;
            }
        }
        NonZeroUsize::new(read).ok_or(DidntRead)
    }

    fn read_exact(&mut self, into: &mut [u8]) -> Result<(), DidntRead> {
        let len = Reader::read(self, into)?;
        if len.get() == into.len() {
            Ok(())
        } else {
            Err(DidntRead)
        }
    }

    fn remaining(&self) -> usize {
        let slices = crate::unsafe_slice!(self.inner.slices.as_ref(), self.cursor.slice..);
        slices.iter().map(ZSlice::len).sum::<usize>() - self.cursor.byte
    }

    fn read_zslices<F: FnMut(ZSlice)>(&mut self, len: usize, mut f: F) -> Result<(), DidntRead> {
        if self.remaining() < len {
            return Err(DidntRead);
        }

        let iter = ZBufSliceIterator {
            reader: self,
            remaining: len,
        };
        for slice in iter {
            f(slice);
        }

        Ok(())
    }

    fn read_zslice(&mut self, len: usize) -> Result<ZSlice, DidntRead> {
        if self.remaining() < len {
            return Err(DidntRead);
        }
        let slice = self.inner.slices.get(self.cursor.slice).ok_or(DidntRead)?;
        match (slice.len() - self.cursor.byte).cmp(&len) {
            // The bytes span slices: they are copied into one.
            cmp::Ordering::Less => {
                let mut buffer = crate::vec::uninit(len);
                Reader::read_exact(self, &mut buffer)?;
                Ok(buffer.into())
            }
            // They are the rest of the slice.
            cmp::Ordering::Equal => {
                let s = slice.subslice(self.cursor.byte..).ok_or(DidntRead)?;
                self.next_slice();
                Ok(s)
            }
            // They are inside the slice.
            cmp::Ordering::Greater => {
                let start = self.cursor.byte;
                self.cursor.byte += len;
                slice.subslice(start..self.cursor.byte).ok_or(DidntRead)
            }
        }
    }

    /// Reads one byte, going past an empty slice to the next byte there is (upstream stops at an
    /// empty slice and reports that there is nothing to read).
    fn read_u8(&mut self) -> Result<u8, DidntRead> {
        loop {
            let slice = self.inner.slices.get(self.cursor.slice).ok_or(DidntRead)?;
            let Some(&byte) = slice.get(self.cursor.byte) else {
                self.next_slice();
                continue;
            };
            self.cursor.byte += 1;
            if self.cursor.byte == slice.len() {
                self.next_slice();
            }
            return Ok(byte);
        }
    }

    fn can_read(&self) -> bool {
        self.inner.slices.get(self.cursor.slice).is_some()
    }
}

impl BacktrackableReader for ZBufReader<'_> {
    type Mark = ZBufPos;

    fn mark(&mut self) -> Self::Mark {
        self.cursor
    }

    /// Puts the cursor back at the mark, if it is a position of this buffer (upstream takes any,
    /// and a position of a longer buffer makes the next length a panic).
    fn rewind(&mut self, mark: Self::Mark) -> bool {
        let slices = self.inner.slices.as_ref();
        let inside = match slices.get(mark.slice) {
            Some(slice) => mark.byte <= slice.len(),
            None => mark.slice == slices.len() && mark.byte == 0,
        };
        if inside {
            self.cursor = mark;
        }
        inside
    }
}

impl SiphonableReader for ZBufReader<'_> {
    fn siphon<W>(&mut self, writer: &mut W) -> Result<NonZeroUsize, DidntSiphon>
    where
        W: Writer,
    {
        let mut read = 0;
        while let Some(slice) = self.inner.slices.get(self.cursor.slice) {
            // What is left of the slice being read, written as far as the writer takes it.
            let from = crate::unsafe_slice!(slice.as_slice(), self.cursor.byte..);
            match writer.write(from) {
                Ok(len) => {
                    read += len.get();
                    self.cursor.byte += len.get();
                    if self.cursor.byte == slice.len() {
                        self.next_slice();
                    }
                }
                Err(_) => {
                    return NonZeroUsize::new(read).ok_or(DidntSiphon);
                }
            }
        }
        NonZeroUsize::new(read).ok_or(DidntSiphon)
    }
}

#[cfg(feature = "std")]
impl io::Read for ZBufReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match <Self as Reader>::read(self, buf) {
            Ok(n) => Ok(n.get()),
            Err(_) => Ok(0),
        }
    }
}

impl AdvanceableReader for ZBufReader<'_> {
    fn skip(&mut self, offset: usize) -> Result<(), DidntRead> {
        let mut remaining_offset = offset;
        while remaining_offset > 0 {
            let s = self.inner.slices.get(self.cursor.slice).ok_or(DidntRead)?;
            let remains_in_current_slice = s.len() - self.cursor.byte;
            let advance = remaining_offset.min(remains_in_current_slice);
            remaining_offset -= advance;
            self.cursor.byte += advance;
            if self.cursor.byte == s.len() {
                self.next_slice();
            }
        }
        Ok(())
    }

    fn backtrack(&mut self, offset: usize) -> Result<(), DidntRead> {
        let mut remaining_offset = offset;
        while remaining_offset > 0 {
            let backtrack = remaining_offset.min(self.cursor.byte);
            remaining_offset -= backtrack;
            self.cursor.byte -= backtrack;
            if self.cursor.byte == 0 {
                if self.cursor.slice == 0 {
                    break;
                }
                self.cursor.slice -= 1;
                self.cursor.byte = self
                    .inner
                    .slices
                    .get(self.cursor.slice)
                    .ok_or(DidntRead)?
                    .len();
            }
        }
        if remaining_offset == 0 {
            Ok(())
        } else {
            Err(DidntRead)
        }
    }
}

#[cfg(feature = "std")]
impl io::Seek for ZBufReader<'_> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let current_pos = self
            .inner
            .slices()
            .take(self.cursor.slice)
            .fold(0, |acc, s| acc + s.len())
            + self.cursor.byte;
        let current_pos =
            i64::try_from(current_pos).map_err(|e| std::io::Error::other(e.to_string()))?;

        let offset = match pos {
            std::io::SeekFrom::Start(s) => i64::try_from(s).unwrap_or(i64::MAX) - current_pos,
            std::io::SeekFrom::Current(s) => s,
            std::io::SeekFrom::End(s) => self.inner.len() as i64 + s - current_pos,
        };
        match self.advance(offset as isize) {
            Ok(()) => Ok((offset + current_pos) as u64),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "InvalidInput",
            )),
        }
    }
}

// ZSlice iterator
/// The slices a reader reads for [`Reader::read_zslices`]: cuts of the slices of the buffer that
/// add up to the length asked for.
#[derive(Debug)]
pub struct ZBufSliceIterator<'a, 'b> {
    reader: &'a mut ZBufReader<'b>,
    remaining: usize,
}

impl Iterator for ZBufSliceIterator<'_, '_> {
    type Item = ZSlice;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        let slice = self.reader.inner.slices.get(self.reader.cursor.slice)?;
        let start = self.reader.cursor.byte;
        let available = slice.len() - start;
        // The part of the slice that is taken, and whether that is all that is left of it.
        let (taken, used_up) = match self.remaining.cmp(&available) {
            cmp::Ordering::Less => (self.remaining, false),
            cmp::Ordering::Equal | cmp::Ordering::Greater => (available, true),
        };
        let part = slice.subslice(start..start + taken);
        if used_up {
            self.reader.next_slice();
        } else {
            self.reader.cursor.byte = start + taken;
        }
        self.remaining -= taken;
        part
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (1, None)
    }
}

// Writer
/// Writes to the end of a [`ZBuf`]: into its last slice if that is a vector no one else holds and
/// the slice ends with it, and into a new slice otherwise.
///
/// It holds the buffer by a mutable borrow and finds the slice it writes to at each write, where
/// upstream keeps a pointer to the buffer and a borrow into it at once.
#[derive(Debug)]
pub struct ZBufWriter<'a> {
    inner: &'a mut ZBuf,
    /// Whether the writer is writing into the last slice. A slice that was written whole is not
    /// written into after, even if it could be, and the next write starts a new slice.
    open: bool,
}

impl ZBufWriter<'_> {
    /// The writer of the slice to write to, which is a new empty slice if there is none open.
    #[inline]
    fn zslice_writer(&mut self) -> ZSliceWriter<'_> {
        if !self.open {
            self.inner.slices.push(ZSlice::empty());
            self.open = true;
        }
        self.inner
            .opt_zslice_writer()
            .expect("the last slice is a vector that is alone and ends with the slice")
    }
}

impl<'a> HasWriter for &'a mut ZBuf {
    type Writer = ZBufWriter<'a>;

    fn writer(self) -> Self::Writer {
        let open = self.opt_zslice_writer().is_some();
        ZBufWriter { inner: self, open }
    }
}

impl Writer for ZBufWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<NonZeroUsize, DidntWrite> {
        self.zslice_writer().write(bytes)
    }

    fn write_exact(&mut self, bytes: &[u8]) -> Result<(), DidntWrite> {
        self.zslice_writer().write_exact(bytes)
    }

    fn remaining(&self) -> usize {
        usize::MAX
    }

    fn write_zslice(&mut self, slice: &ZSlice) -> Result<(), DidntWrite> {
        self.open = false;
        self.inner.push_zslice(slice.clone());
        Ok(())
    }

    /// # Safety
    ///
    /// The `write` closure must return the number of bytes actually written to the slice,
    /// which must be less than or equal to `len`.
    unsafe fn with_slot<F>(&mut self, len: usize, write: F) -> Result<NonZeroUsize, DidntWrite>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        // SAFETY: Same precondition as this function. Call to `with_slot` is safe because
        // the requirements are passed through.
        unsafe { self.zslice_writer().with_slot(len, write) }
    }
}

impl BacktrackableWriter for ZBufWriter<'_> {
    type Mark = ZBufPos;

    fn mark(&mut self) -> Self::Mark {
        let slice = self.inner.slices.len();
        let byte = self
            .inner
            .opt_zslice_writer()
            .map_or(0, |mut writer| writer.mark());
        ZBufPos { slice, byte }
    }

    /// Cuts the buffer back to the mark, if the last slice it leaves can be cut there (upstream
    /// panics if it cannot).
    fn rewind(&mut self, mark: Self::Mark) -> bool {
        self.inner.slices.truncate(mark.slice);
        let mut writer = self.inner.opt_zslice_writer();
        self.open = writer.is_some();
        match &mut writer {
            Some(writer) => mark.byte <= writer.mark() && writer.rewind(mark.byte),
            None => true,
        }
    }
}

#[cfg(feature = "std")]
impl io::Write for ZBufWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        match <Self as Writer>::write(self, buf) {
            Ok(n) => Ok(n.get()),
            Err(_) => Err(io::ErrorKind::UnexpectedEof.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "test")]
impl ZBuf {
    #[doc(hidden)]
    pub fn rand(len: usize) -> Self {
        let mut zbuf = ZBuf::empty();
        zbuf.push_zslice(ZSlice::rand(len));
        zbuf
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn zbuf(parts: &[&[u8]]) -> ZBuf {
        let mut z = ZBuf::empty();
        for p in parts {
            z.push_zslice(p.to_vec().into());
        }
        z
    }

    #[test]
    fn two_buffers_are_equal_if_they_hold_the_same_bytes_cut_anywhere() {
        let slice: ZSlice = [0u8, 1, 2, 3, 4, 5, 6, 7].to_vec().into();
        let mut one = ZBuf::empty();
        one.push_zslice(slice.subslice(..4).unwrap());
        one.push_zslice(slice.subslice(4..8).unwrap());
        let mut two = ZBuf::empty();
        two.push_zslice(slice.subslice(..1).unwrap());
        two.push_zslice(slice.subslice(1..4).unwrap());
        two.push_zslice(slice.subslice(4..8).unwrap());
        assert_eq!(one, two);
        assert_ne!(one, zbuf(&[&[0, 1, 2, 3, 4, 5, 6]]));
        assert_ne!(zbuf(&[&[1]]), zbuf(&[&[2]]));
        assert_eq!(ZBuf::empty(), ZBuf::default());
    }

    #[test]
    fn an_empty_slice_does_not_make_two_buffers_different() {
        // Only a writer that was given nothing leaves one, and it leaves it at the end.
        let mut with_empty = zbuf(&[&[1, 2]]);
        let mut w = (&mut with_empty).writer();
        w.write_zslice(&ZSlice::empty()).unwrap();
        assert!(w.write(&[]).is_err());
        assert!(with_empty.zslices().count() >= 2);
        assert_eq!(with_empty, zbuf(&[&[1, 2]]));
        assert_eq!(zbuf(&[&[1, 2]]), with_empty);
    }

    #[test]
    fn the_buffer_reads_across_its_slices_and_marks_where_it_was() {
        let buf = zbuf(&[&[0, 1, 2, 3], &[4, 5], &[6]]);
        assert_eq!(
            (buf.len(), Buffer::is_empty(&buf), buf.slices().len()),
            (7, false, 3)
        );
        let mut r = (&buf).reader();
        assert_eq!(r.read_u8().unwrap(), 0);
        let mark = r.mark();
        let mut five = [0u8; 5];
        r.read_exact(&mut five).unwrap();
        assert_eq!(five, [1, 2, 3, 4, 5]);
        assert_eq!((r.remaining(), r.can_read()), (1, true));
        assert!(r.rewind(mark) && r.remaining() == 6);
        assert_eq!(r.read_zslice(3).unwrap(), [1u8, 2, 3]);
        assert_eq!(r.read_zslice(2).unwrap(), [4u8, 5]);
        assert!(r.read_zslice(2).is_err());
        assert_eq!(r.read_u8().unwrap(), 6);
        assert!(!r.can_read() && r.read_u8().is_err() && Buffer::is_empty(&r));
        assert!(
            !r.rewind(ZBufPos { slice: 9, byte: 0 }),
            "a position of a longer buffer"
        );
        assert!(!r.rewind(ZBufPos { slice: 0, byte: 9 }));
    }

    #[test]
    fn a_zbuf_read_is_cuts_of_the_slices_and_a_copy_only_where_it_spans_them() {
        let buf = zbuf(&[&[1, 2, 3], &[4, 5, 6]]);
        let mut r = (&buf).reader();
        let mut got = vec![];
        r.read_zslices(5, |s| got.push(s.to_vec())).unwrap();
        assert_eq!(got, [vec![1, 2, 3], vec![4, 5]]);
        assert!(r.read_zslices(2, |_| ()).is_err());
        let rest = r.read_zbuf(1).unwrap();
        assert_eq!(rest, zbuf(&[&[6]]));
        let mut r = (&buf).reader();
        let spanning = r.read_zslice(4).unwrap();
        assert_eq!(spanning, [1u8, 2, 3, 4]);
        assert_eq!(buf.to_zslice(), [1u8, 2, 3, 4, 5, 6]);
        assert_eq!(zbuf(&[&[9]]).to_zslice(), [9u8]);
        assert!(ZBuf::empty().to_zslice().is_empty());
    }

    #[test]
    fn a_byte_is_read_past_an_empty_slice() {
        let mut buf = zbuf(&[&[1]]);
        // `push_zslice` refuses an empty slice, so one is put in by hand, as a writer that was
        // given nothing leaves it.
        buf.slices.push(ZSlice::empty());
        buf.slices.push(vec![2u8].into());
        let mut r = (&buf).reader();
        assert_eq!(r.read_u8().unwrap(), 1);
        assert_eq!(r.read_u8().unwrap(), 2);
        assert!(r.read_u8().is_err());
    }

    #[test]
    fn a_reader_skips_backtracks_siphons_and_advances_by_any_distance() {
        let buf = zbuf(&[&[0, 1, 2, 3], &[4, 5, 6, 7, 8]]);
        let mut r = (&buf).reader();
        r.skip(6).unwrap();
        assert_eq!(r.read_u8().unwrap(), 6);
        r.backtrack(5).unwrap();
        assert_eq!(r.read_u8().unwrap(), 2);
        assert!(r.skip(100).is_err());
        let mut r = (&buf).reader();
        r.advance(3).unwrap();
        r.advance(-2).unwrap();
        assert_eq!(r.read_u8().unwrap(), 1);
        // The smallest distance is a distance, not an overflow.
        assert!(r.advance(isize::MIN).is_err());
        let mut r = (&buf).reader();
        let mut out = Vec::new();
        assert_eq!(r.siphon(&mut out).unwrap().get(), 9);
        assert_eq!(out, [0, 1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn the_writer_extends_the_last_slice_when_it_is_alone_and_starts_one_when_it_is_not() {
        let mut buf = ZBuf::empty();
        {
            let mut w = (&mut buf).writer();
            assert_eq!((w.remaining(), w.can_write()), (usize::MAX, true));
            w.write_exact(&[1, 2]).unwrap();
            w.write_u8(3).unwrap();
            let mark = w.mark();
            w.write_exact(&[4]).unwrap();
            assert!(w.rewind(mark));
            // SAFETY: the closure reports no more than the slot holds.
            assert_eq!(
                unsafe {
                    w.with_slot(5, |s| {
                        s[0] = 9;
                        1
                    })
                }
                .unwrap()
                .get(),
                1
            );
        }
        assert_eq!(buf.zslices().count(), 1);
        assert_eq!(buf.to_zslice(), [1u8, 2, 3, 9]);
        let shared = buf.to_zslice();
        {
            let mut w = (&mut buf).writer();
            w.write_zslice(&shared).unwrap();
            w.write_exact(&[7]).unwrap();
            w.write_exact(&[8]).unwrap();
        }
        assert_eq!(
            buf.zslices().count(),
            3,
            "the shared slice is not written into"
        );
        assert_eq!(buf.to_zslice(), [1u8, 2, 3, 9, 1, 2, 3, 9, 7, 8]);
    }

    #[test]
    fn a_mark_a_buffer_cannot_be_cut_at_is_refused() {
        let mut buf = zbuf(&[&[1, 2, 3]]);
        let mut w = (&mut buf).writer();
        assert!(!w.rewind(ZBufPos { slice: 1, byte: 99 }));
        assert!(w.rewind(ZBufPos { slice: 1, byte: 1 }));
        assert_eq!(buf.to_zslice(), [1u8]);
    }

    /// `Read`, `Write` and `Seek` are the buffer's `std` feature's.
    #[cfg(feature = "std")]
    #[test]
    fn the_buffer_is_an_io_reader_writer_and_seeker() {
        use std::io::{Read, Seek, Write};
        let mut buf = ZBuf::empty();
        buf.push_zslice([0u8, 1, 2, 3].into());
        buf.push_zslice([4u8, 5, 6, 7, 8].into());
        buf.push_zslice([9u8, 10, 11, 12, 13, 14].into());
        let mut reader = (&buf).reader();
        assert_eq!(reader.stream_position().unwrap(), 0);
        assert_eq!(reader.read_u8().unwrap(), 0);
        assert_eq!(reader.seek(std::io::SeekFrom::Current(6)).unwrap(), 7);
        assert_eq!(reader.read_u8().unwrap(), 7);
        assert_eq!(reader.seek(std::io::SeekFrom::Current(-5)).unwrap(), 3);
        assert_eq!(reader.seek(std::io::SeekFrom::Start(15)).unwrap(), 15);
        reader.read_u8().unwrap_err();
        reader.seek(std::io::SeekFrom::Start(100)).unwrap_err();
        assert_eq!(reader.seek(std::io::SeekFrom::End(-5)).unwrap(), 10);
        let mut tail = Vec::new();
        assert_eq!(Read::read_to_end(&mut reader, &mut tail).unwrap(), 5);
        assert_eq!(tail, [10, 11, 12, 13, 14]);
        let mut out = ZBuf::empty();
        let mut w = (&mut out).writer();
        assert_eq!(Write::write(&mut w, &[]).unwrap(), 0);
        assert_eq!(Write::write(&mut w, &[1, 2]).unwrap(), 2);
        assert!(w.flush().is_ok());
    }
}
