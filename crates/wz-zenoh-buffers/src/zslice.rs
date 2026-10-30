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
// src/zslice.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

//! A cloneable window onto shared bytes.

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    any::Any,
    fmt, iter,
    num::NonZeroUsize,
    ops::{Bound, Deref, RangeBounds},
};

use crate::{
    buffer::{Buffer, SplitBuffer},
    reader::{BacktrackableReader, DidntRead, HasReader, Reader},
    writer::{BacktrackableWriter, DidntWrite, Writer},
    ZBuf,
};

/*************************************/
/*           ZSLICE BUFFER           */
/*************************************/
/// What a [`ZSlice`] is a window onto: bytes that can be shared between threads, and that can be
/// asked what they are (so that the owner of a slice can get its buffer back).
pub trait ZSliceBuffer: Any + Send + Sync + fmt::Debug {
    fn as_slice(&self) -> &[u8];
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl ZSliceBuffer for Vec<u8> {
    fn as_slice(&self) -> &[u8] {
        self
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl ZSliceBuffer for Box<[u8]> {
    fn as_slice(&self) -> &[u8] {
        self
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl<const N: usize> ZSliceBuffer for [u8; N] {
    fn as_slice(&self) -> &[u8] {
        self
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/*************************************/
/*               ZSLICE              */
/*************************************/
#[cfg(feature = "shared-memory")]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ZSliceKind {
    Raw = 0,
    ShmPtr = 1,
}

/// A cloneable wrapper to a contiguous slice of bytes.
#[derive(Clone)]
pub struct ZSlice {
    buf: Arc<dyn ZSliceBuffer>,
    start: usize,
    end: usize,
    #[cfg(feature = "shared-memory")]
    pub kind: ZSliceKind,
}

impl ZSlice {
    /// The window `start..end` of `buf`, or `buf` back if that is not a window of it.
    #[inline]
    pub fn new(
        buf: Arc<dyn ZSliceBuffer>,
        start: usize,
        end: usize,
    ) -> Result<ZSlice, Arc<dyn ZSliceBuffer>> {
        if start <= end && end <= buf.as_slice().len() {
            Ok(Self {
                buf,
                start,
                end,
                #[cfg(feature = "shared-memory")]
                kind: ZSliceKind::Raw,
            })
        } else {
            Err(buf)
        }
    }

    #[inline]
    pub fn empty() -> Self {
        Self::from(Vec::<u8>::new())
    }

    #[inline]
    #[must_use]
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        self.buf.as_any().downcast_ref()
    }

    /// # Safety
    ///
    /// Buffer modification must not modify slice range or invalidate the data.
    ///
    /// A buffer changed so that the range is no longer inside it makes the next read of the slice
    /// a panic, where upstream reads past the buffer.
    #[inline]
    #[must_use]
    pub unsafe fn downcast_mut<T: Any>(&mut self) -> Option<&mut T> {
        Arc::get_mut(&mut self.buf)?.as_any_mut().downcast_mut()
    }

    /// The writer of this slice, if its buffer is a vector that no one else holds and the slice
    /// ends where the vector does, so that what is written goes on after the slice.
    ///
    /// This is internal and is only meant to be used by `ZBufWriter`; it is in this module because
    /// it relies on what a `ZSlice` guarantees of its range.
    #[inline]
    pub(crate) fn writer(&mut self) -> Option<ZSliceWriter<'_>> {
        let Self { buf, end, .. } = self;
        let vec = Arc::get_mut(buf)?.as_any_mut().downcast_mut::<Vec<u8>>()?;
        if *end == vec.len() {
            Some(ZSliceWriter { vec, end })
        } else {
            None
        }
    }

    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf.as_slice()[self.start..self.end]
    }

    /// A slice of this slice, sharing its buffer, or `None` if the range is not inside it.
    pub fn subslice(&self, range: impl RangeBounds<usize>) -> Option<Self> {
        let start = match range.start_bound() {
            Bound::Included(&n) => n,
            Bound::Excluded(&n) => n.checked_add(1)?,
            Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            Bound::Included(&n) => n.checked_add(1)?,
            Bound::Excluded(&n) => n,
            Bound::Unbounded => self.len(),
        };
        if start <= end && end <= self.len() {
            Some(ZSlice {
                buf: self.buf.clone(),
                start: self.start + start,
                end: self.start + end,
                #[cfg(feature = "shared-memory")]
                kind: self.kind,
            })
        } else {
            None
        }
    }
}

impl Deref for ZSlice {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[u8]> for ZSlice {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl<Rhs: AsRef<[u8]> + ?Sized> PartialEq<Rhs> for ZSlice {
    fn eq(&self, other: &Rhs) -> bool {
        self.as_slice() == other.as_ref()
    }
}

impl Eq for ZSlice {}

#[cfg(feature = "std")]
impl std::hash::Hash for ZSlice {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}

impl fmt::Display for ZSlice {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:02x?}", self.as_slice())
    }
}

impl fmt::Debug for ZSlice {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:02x?}", self.as_slice())
    }
}

// From impls
impl<T> From<Arc<T>> for ZSlice
where
    T: ZSliceBuffer + 'static,
{
    fn from(buf: Arc<T>) -> Self {
        let end = buf.as_slice().len();
        Self {
            buf,
            start: 0,
            end,
            #[cfg(feature = "shared-memory")]
            kind: ZSliceKind::Raw,
        }
    }
}

impl<T> From<T> for ZSlice
where
    T: ZSliceBuffer + 'static,
{
    fn from(buf: T) -> Self {
        Self::from(Arc::new(buf))
    }
}

// Buffer
impl Buffer for ZSlice {
    fn len(&self) -> usize {
        ZSlice::len(self)
    }
}

impl Buffer for &ZSlice {
    fn len(&self) -> usize {
        ZSlice::len(self)
    }
}

impl Buffer for &mut ZSlice {
    fn len(&self) -> usize {
        ZSlice::len(self)
    }
}

// SplitBuffer
impl SplitBuffer for ZSlice {
    type Slices<'a> = iter::Once<&'a [u8]>;

    fn slices(&self) -> Self::Slices<'_> {
        iter::once(self.as_slice())
    }
}

/// Appends to the vector of a slice and moves the end of the slice with it.
#[derive(Debug)]
pub(crate) struct ZSliceWriter<'a> {
    vec: &'a mut Vec<u8>,
    end: &'a mut usize,
}

impl Writer for ZSliceWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<NonZeroUsize, DidntWrite> {
        let len = self.vec.write(bytes)?;
        *self.end += len.get();
        Ok(len)
    }

    fn write_exact(&mut self, bytes: &[u8]) -> Result<(), DidntWrite> {
        if bytes.is_empty() {
            Ok(())
        } else {
            self.write(bytes).map(|_| ())
        }
    }

    fn remaining(&self) -> usize {
        self.vec.remaining()
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
        let len = unsafe { self.vec.with_slot(len, write) }?;
        *self.end += len.get();
        Ok(len)
    }
}

impl BacktrackableWriter for ZSliceWriter<'_> {
    type Mark = usize;

    fn mark(&mut self) -> Self::Mark {
        *self.end
    }

    fn rewind(&mut self, mark: Self::Mark) -> bool {
        assert!(mark <= self.vec.len());
        self.vec.truncate(mark);
        *self.end = mark;
        true
    }
}

// Reader
impl HasReader for &mut ZSlice {
    type Reader = Self;

    fn reader(self) -> Self::Reader {
        self
    }
}

impl Reader for ZSlice {
    #[inline(always)]
    fn read(&mut self, into: &mut [u8]) -> Result<NonZeroUsize, DidntRead> {
        let mut reader = self.as_slice().reader();
        let len = reader.read(into)?;
        // The reader of a slice of bytes does not take more than the slice holds.
        self.start += len.get();
        Ok(len)
    }

    #[inline(always)]
    fn read_exact(&mut self, into: &mut [u8]) -> Result<(), DidntRead> {
        let mut reader = self.as_slice().reader();
        reader.read_exact(into)?;
        // The reader of a slice of bytes does not take more than the slice holds.
        self.start += into.len();
        Ok(())
    }

    #[inline(always)]
    fn remaining(&self) -> usize {
        self.len()
    }

    #[inline(always)]
    fn read_zbuf(&mut self, len: usize) -> Result<ZBuf, DidntRead> {
        Ok(self.read_zslice(len)?.into())
    }

    fn read_zslices<F: FnMut(ZSlice)>(&mut self, len: usize, mut f: F) -> Result<(), DidntRead> {
        let zslice = self.read_zslice(len)?;
        f(zslice);
        Ok(())
    }

    #[inline(always)]
    fn read_zslice(&mut self, len: usize) -> Result<ZSlice, DidntRead> {
        let res = self.subslice(..len).ok_or(DidntRead)?;
        self.start += len;
        Ok(res)
    }

    #[inline(always)]
    fn read_u8(&mut self) -> Result<u8, DidntRead> {
        let mut reader = self.as_slice().reader();
        let res = reader.read_u8()?;
        // The reader of a slice of bytes does not take more than the slice holds.
        self.start += 1;
        Ok(res)
    }

    #[inline(always)]
    fn can_read(&self) -> bool {
        !self.is_empty()
    }
}

impl BacktrackableReader for ZSlice {
    type Mark = usize;

    fn mark(&mut self) -> Self::Mark {
        self.start
    }

    fn rewind(&mut self, mark: Self::Mark) -> bool {
        assert!(mark <= self.end);
        self.start = mark;
        true
    }
}

#[cfg(feature = "std")]
impl std::io::Read for &mut ZSlice {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match <Self as Reader>::read(self, buf) {
            Ok(n) => Ok(n.get()),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "UnexpectedEof",
            )),
        }
    }
}

#[cfg(feature = "test")]
impl ZSlice {
    #[doc(hidden)]
    pub fn rand(len: usize) -> Self {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        (0..len).map(|_| rng.gen()).collect::<Vec<u8>>().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slice_is_a_window_onto_its_buffer_and_gives_the_buffer_back_if_it_is_alone() {
        let buf = crate::vec::uninit(16);
        let mut zslice: ZSlice = buf.clone().into();
        assert_eq!(buf.as_slice(), zslice.as_slice());
        // SAFETY: the buffer's length is not changed.
        let mut_slice = unsafe { zslice.downcast_mut::<Vec<u8>>() }.unwrap();
        mut_slice[..4].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(&zslice[..4], [1, 2, 3, 4]);
        let shared = zslice.clone();
        // SAFETY: the buffer is not touched, which the sharing refuses anyway.
        assert!(unsafe { zslice.downcast_mut::<Vec<u8>>() }.is_none());
        assert!(
            shared.downcast_ref::<Vec<u8>>().is_some() && shared.downcast_ref::<u8>().is_none()
        );
    }

    #[test]
    fn a_window_is_checked_where_it_is_made() {
        let buf: Arc<dyn ZSliceBuffer> = Arc::new(vec![0u8; 4]);
        assert!(ZSlice::new(buf.clone(), 1, 3).is_ok());
        assert!(ZSlice::new(buf.clone(), 3, 1).is_err());
        assert!(ZSlice::new(buf, 0, 5).is_err());
        let z: ZSlice = vec![1u8, 2, 3, 4, 5].into();
        assert_eq!(z.subslice(1..3).unwrap(), [2u8, 3]);
        assert_eq!(z.subslice(..=1).unwrap(), [1u8, 2]);
        assert_eq!(z.subslice(4..).unwrap(), [5u8]);
        assert!(z.subslice(3..6).is_none());
        // A start past the end is refused (written so that it is not a reversed literal range).
        assert!(z
            .subslice((Bound::Included(4), Bound::Excluded(2)))
            .is_none());
        // A bound at the largest number is refused and not wrapped around.
        assert!(z.subslice(..=usize::MAX).is_none());
        assert!(z
            .subslice((Bound::Excluded(usize::MAX), Bound::Unbounded))
            .is_none());
    }

    #[test]
    fn a_slice_is_read_from_its_front_and_marked() {
        let mut z: ZSlice = vec![1u8, 2, 3, 4, 5].into();
        assert_eq!(z.read_u8().unwrap(), 1);
        let mark = z.mark();
        let mut two = [0u8; 2];
        assert_eq!(z.read(&mut two).unwrap().get(), 2);
        assert!(z.rewind(mark) && z.remaining() == 4);
        assert_eq!(z.read_zslice(3).unwrap(), [2u8, 3, 4]);
        assert!(z.read_exact(&mut two).is_err() && z.read_zslice(2).is_err());
        assert_eq!(z.read_zbuf(1).unwrap().len(), 1);
        assert!(!z.can_read());
    }

    #[test]
    fn equal_hash_and_text_are_those_of_the_bytes() {
        use std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        };
        let buf = vec![1u8, 2, 3, 4, 5];
        let mut a = DefaultHasher::new();
        buf.hash(&mut a);
        let zslice: ZSlice = buf.clone().into();
        let mut b = DefaultHasher::new();
        zslice.hash(&mut b);
        assert_eq!(a.finish(), b.finish());
        assert_eq!(zslice, buf);
        assert_eq!(
            format!("{zslice} {zslice:?}"),
            "[01, 02, 03, 04, 05] [01, 02, 03, 04, 05]"
        );
        assert!(ZSlice::empty().is_empty());
    }

    #[test]
    fn only_a_lone_vector_that_ends_with_the_slice_can_be_written_to() {
        let mut z: ZSlice = vec![1u8, 2].into();
        {
            let mut w = z.writer().expect("a lone vector ending with the slice");
            assert_eq!(w.write(&[3]).unwrap().get(), 1);
            let mark = w.mark();
            w.write_exact(&[4, 5]).unwrap();
            assert!(w.rewind(mark));
        }
        assert_eq!(z, [1u8, 2, 3]);
        let mut sub = z.subslice(..2).unwrap();
        assert!(sub.writer().is_none(), "shared");
        let mut windowed: ZSlice = z.subslice(1..).unwrap();
        drop((z, sub));
        assert!(
            windowed.writer().is_some(),
            "now alone, and ends with the vector"
        );
        let mut boxed: ZSlice = vec![1u8, 2].into_boxed_slice().into();
        assert!(boxed.writer().is_none(), "not a vector");
    }
}
