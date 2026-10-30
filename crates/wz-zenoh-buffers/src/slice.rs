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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-buffers 1.10.2, file
// src/slice.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

//! A slice of bytes as a buffer, a writer and a reader: what is read is the front of the slice,
//! and what is written the front of the slice that is left, which is how the slice is consumed.

use core::{marker::PhantomData, mem, num::NonZeroUsize, option, slice};

use crate::{
    buffer::{Buffer, SplitBuffer},
    reader::{BacktrackableReader, DidntRead, DidntSiphon, HasReader, Reader, SiphonableReader},
    writer::{BacktrackableWriter, DidntWrite, HasWriter, Writer},
    ZBuf, ZSlice,
};

// Buffer
impl Buffer for &[u8] {
    #[inline(always)]
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
}

impl Buffer for &mut [u8] {
    #[inline(always)]
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
}

// SplitBuffer
impl<'b> SplitBuffer for &'b [u8] {
    type Slices<'a>
        = option::IntoIter<&'a [u8]>
    where
        'b: 'a;

    fn slices(&self) -> Self::Slices<'_> {
        Some(*self).into_iter()
    }
}

// Writer
impl HasWriter for &mut [u8] {
    type Writer = Self;

    fn writer(self) -> Self::Writer {
        self
    }
}

impl Writer for &mut [u8] {
    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) -> Result<NonZeroUsize, DidntWrite> {
        let Some(len) = NonZeroUsize::new(bytes.len().min(self.len())) else {
            return Err(DidntWrite);
        };
        let (to_write, remain) = mem::take(self).split_at_mut(len.get());
        to_write.copy_from_slice(&bytes[..len.get()]);
        *self = remain;
        Ok(len)
    }

    #[inline(always)]
    fn write_exact(&mut self, bytes: &[u8]) -> Result<(), DidntWrite> {
        let len = bytes.len();
        if self.len() < len {
            return Err(DidntWrite);
        }
        let _ = self.write(bytes);
        Ok(())
    }

    fn remaining(&self) -> usize {
        self.len()
    }

    /// # Safety
    ///
    /// The `write` closure must return the number of bytes actually written to the slice,
    /// which must be less than or equal to `len`.
    ///
    /// A count past `len` is a panic, as is any index past the end of a slice.
    unsafe fn with_slot<F>(&mut self, len: usize, write: F) -> Result<NonZeroUsize, DidntWrite>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        if len > self.len() {
            return Err(DidntWrite);
        }
        let written = write(&mut self[..len]);
        assert!(
            written <= len,
            "a slot of {len} bytes was reported as written for {written}"
        );
        *self = &mut mem::take(self)[written..];
        NonZeroUsize::new(written).ok_or(DidntWrite)
    }
}

/// Where a slice writer was: the slice it had, which a rewind gives it back.
///
/// The mark holds the slice as a pointer and a length and not as a borrow, because the writer has
/// the same memory borrowed mutably while it goes on writing; the lifetime ties the mark to the
/// memory all the same.
#[derive(Debug)]
pub struct SliceMark<'s> {
    ptr: *const u8,
    len: usize,
    // Enforce lifetime for the pointer
    _phantom: PhantomData<&'s u8>,
}

impl<'s> BacktrackableWriter for &'s mut [u8] {
    type Mark = SliceMark<'s>;

    fn mark(&mut self) -> Self::Mark {
        SliceMark {
            ptr: self.as_ptr(),
            len: self.len(),
            _phantom: PhantomData,
        }
    }

    /// Gives the writer back the slice it had at the mark, and says so; false, with the writer
    /// unchanged, if the mark is not of a slice this one was cut from the front of (upstream takes
    /// any mark of the same lifetime, and so can be made to hold two mutable borrows of one memory).
    fn rewind(&mut self, mark: Self::Mark) -> bool {
        let here = self.as_ptr() as usize;
        let (from, end) = (mark.ptr as usize, mark.ptr as usize + mark.len);
        if here < from || here + self.len() != end {
            return false;
        }
        // SAFETY: the mark was taken from a slice of lifetime `'s` that ends where this one does,
        // and this one begins inside it, so this one was cut from the front of it; the part cut off
        // was only handed out by a write, which is over. The memory from the mark to its end is
        // therefore borrowed by this writer alone, and is valid and initialised for `'s`.
        *self = unsafe { slice::from_raw_parts_mut(mark.ptr as *mut u8, mark.len) };
        true
    }
}

// Reader
impl HasReader for &[u8] {
    type Reader = Self;

    fn reader(self) -> Self::Reader {
        self
    }
}

impl Reader for &[u8] {
    #[inline(always)]
    fn read(&mut self, into: &mut [u8]) -> Result<NonZeroUsize, DidntRead> {
        let Some(len) = NonZeroUsize::new(self.len().min(into.len())) else {
            return Err(DidntRead);
        };
        let (to_write, remain) = self.split_at(len.get());
        into[..len.get()].copy_from_slice(to_write);
        *self = remain;
        Ok(len)
    }

    #[inline(always)]
    fn read_exact(&mut self, into: &mut [u8]) -> Result<(), DidntRead> {
        let len = into.len();
        if self.len() < len {
            return Err(DidntRead);
        }
        let (to_write, remain) = self.split_at(len);
        into[..len].copy_from_slice(to_write);
        *self = remain;
        Ok(())
    }

    fn remaining(&self) -> usize {
        self.len()
    }

    fn read_zbuf(&mut self, len: usize) -> Result<ZBuf, DidntRead> {
        Ok(self.read_zslice(len)?.into())
    }

    fn read_zslices<F: FnMut(ZSlice)>(&mut self, len: usize, mut f: F) -> Result<(), DidntRead> {
        let zslice = self.read_zslice(len)?;
        f(zslice);
        Ok(())
    }

    fn read_zslice(&mut self, len: usize) -> Result<ZSlice, DidntRead> {
        if self.len() < len {
            return Err(DidntRead);
        }
        let (taken, remain) = self.split_at(len);
        *self = remain;
        Ok(taken.to_vec().into())
    }

    #[inline(always)]
    fn read_u8(&mut self) -> Result<u8, DidntRead> {
        let (first, remain) = self.split_first().ok_or(DidntRead)?;
        *self = remain;
        Ok(*first)
    }

    fn can_read(&self) -> bool {
        !self.is_empty()
    }
}

impl<'a> BacktrackableReader for &'a [u8] {
    type Mark = &'a [u8];

    fn mark(&mut self) -> Self::Mark {
        self
    }

    fn rewind(&mut self, mark: Self::Mark) -> bool {
        *self = mark;
        true
    }
}

impl SiphonableReader for &[u8] {
    fn siphon<W>(&mut self, writer: &mut W) -> Result<NonZeroUsize, DidntSiphon>
    where
        W: Writer,
    {
        let res = writer.write(self).map_err(|_| DidntSiphon);
        if let Ok(len) = res {
            *self = crate::unsafe_slice!(self, len.get()..);
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slice_is_written_from_its_front_and_the_rest_is_what_remains() {
        let mut storage = [0u8; 6];
        let mut w: &mut [u8] = &mut storage;
        assert_eq!(w.write(&[1, 2]).unwrap().get(), 2);
        assert_eq!(w.remaining(), 4);
        assert!(w.write_exact(&[3; 5]).is_err());
        assert_eq!(w.write(&[3; 9]).unwrap().get(), 4);
        assert!(!w.can_write() && w.write(&[1]).is_err());
        assert_eq!(storage, [1, 2, 3, 3, 3, 3]);
    }

    #[test]
    fn a_mark_gives_the_slice_back_but_only_a_mark_of_the_same_slice() {
        let mut a = [0u8; 4];
        let mut b = [0u8; 4];
        let mut wa: &mut [u8] = &mut a;
        let mark = wa.mark();
        wa.write_exact(&[1, 2, 3]).unwrap();
        assert_eq!(wa.remaining(), 1);
        assert!(wa.rewind(mark));
        assert_eq!(wa.remaining(), 4);
        wa.write_exact(&[9, 9]).unwrap();
        let mut wb: &mut [u8] = &mut b;
        let foreign = wb.mark();
        assert!(!wa.rewind(foreign), "a mark of another slice is refused");
        assert_eq!(wa.remaining(), 2);
        assert_eq!(a, [9, 9, 3, 0]);
    }

    #[test]
    fn a_slot_advances_by_what_was_written() {
        let mut storage = [0u8; 4];
        let mut w: &mut [u8] = &mut storage;
        // SAFETY: the closure reports no more than the slot holds.
        let n = unsafe {
            w.with_slot(3, |slot| {
                slot[0] = 5;
                1
            })
        };
        assert_eq!((n.unwrap().get(), w.remaining()), (1, 3));
        // SAFETY: as above.
        assert!(unsafe { w.with_slot(9, |_| 0) }.is_err());
        // SAFETY: as above.
        assert!(unsafe { w.with_slot(2, |_| 0) }.is_err());
        assert_eq!(storage[0], 5);
    }

    #[test]
    fn a_slice_is_read_from_its_front() {
        let mut r: &[u8] = &[1, 2, 3, 4, 5];
        let mut two = [0u8; 2];
        assert_eq!(r.read(&mut two).unwrap().get(), 2);
        assert_eq!(two, [1, 2]);
        let mark = r.mark();
        assert_eq!(r.read_u8().unwrap(), 3);
        assert!(r.rewind(mark) && r.remaining() == 3);
        assert!(r.read_exact(&mut [0u8; 4]).is_err() && r.remaining() == 3);
        assert_eq!(r.read_zslice(2).unwrap(), [3u8, 4]);
        assert_eq!(r.read_zbuf(1).unwrap().len(), 1);
        assert!(!r.can_read() && r.read_u8().is_err() && r.read(&mut two).is_err());
    }

    #[test]
    fn a_slice_siphons_into_a_writer() {
        let mut r: &[u8] = &[1, 2, 3];
        let mut out = alloc::vec::Vec::new();
        assert_eq!(r.siphon(&mut out).unwrap().get(), 3);
        assert_eq!(out, [1, 2, 3]);
        assert!(r.is_empty());
        let mut full: &mut [u8] = &mut [];
        let mut r: &[u8] = &[1];
        assert!(r.siphon(&mut full).is_err());
    }
}
