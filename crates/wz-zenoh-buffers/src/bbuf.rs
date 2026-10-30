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
// src/bbuf.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

//! A buffer of fixed capacity that is written from its front.

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::{fmt, num::NonZeroUsize, option};

use crate::{
    buffer::{Buffer, SplitBuffer},
    reader::HasReader,
    vec,
    writer::{BacktrackableWriter, DidntWrite, HasWriter, Writer},
    ZSlice,
};

/// A buffer of a capacity set at construction, of which the first `len` bytes have been written.
#[derive(Clone, PartialEq, Eq)]
pub struct BBuf {
    buffer: Box<[u8]>,
    len: usize,
}

impl BBuf {
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: vec::uninit(capacity).into_boxed_slice(),
            len: 0,
        }
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.buffer.len()
    }

    /// The bytes written.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        crate::unsafe_slice!(self.buffer, ..self.len)
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        crate::unsafe_slice_mut!(self.buffer, ..self.len)
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// The room that is left, which is what a write goes to.
    fn as_writable_slice(&mut self) -> &mut [u8] {
        crate::unsafe_slice_mut!(self.buffer, self.len..)
    }
}

impl fmt::Debug for BBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:02x?}", self.as_slice())
    }
}

// Buffer
impl Buffer for BBuf {
    fn len(&self) -> usize {
        self.len
    }
}

impl Buffer for &BBuf {
    fn len(&self) -> usize {
        self.len
    }
}

impl Buffer for &mut BBuf {
    fn len(&self) -> usize {
        self.len
    }
}

// SplitBuffer
impl SplitBuffer for BBuf {
    type Slices<'a> = option::IntoIter<&'a [u8]>;

    fn slices(&self) -> Self::Slices<'_> {
        Some(self.as_slice()).into_iter()
    }
}

// Writer
impl HasWriter for &mut BBuf {
    type Writer = Self;

    fn writer(self) -> Self::Writer {
        self
    }
}

impl Writer for BBuf {
    fn write(&mut self, bytes: &[u8]) -> Result<NonZeroUsize, DidntWrite> {
        let mut writer = self.as_writable_slice().writer();
        let len = writer.write(bytes)?;
        self.len += len.get();
        Ok(len)
    }

    #[inline(always)]
    fn write_exact(&mut self, bytes: &[u8]) -> Result<(), DidntWrite> {
        let mut writer = self.as_writable_slice().writer();
        writer.write_exact(bytes)?;
        self.len += bytes.len();
        Ok(())
    }

    fn remaining(&self) -> usize {
        self.capacity() - self.len()
    }

    /// # Safety
    ///
    /// The `write` closure must return the number of bytes actually written to the slice,
    /// which must be less than or equal to `len`.
    ///
    /// A count past `len` is a panic and not a length past the capacity.
    unsafe fn with_slot<F>(&mut self, len: usize, write: F) -> Result<NonZeroUsize, DidntWrite>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        if self.remaining() < len {
            return Err(DidntWrite);
        }
        let written = write(&mut self.as_writable_slice()[..len]);
        assert!(
            written <= len,
            "a slot of {len} bytes was reported as written for {written}"
        );
        self.len += written;

        NonZeroUsize::new(written).ok_or(DidntWrite)
    }
}

impl BacktrackableWriter for BBuf {
    type Mark = usize;

    fn mark(&mut self) -> Self::Mark {
        self.len
    }

    /// Sets the length to the mark, which may not be past the capacity (upstream accepts any, and
    /// a length past the capacity makes the next read of the bytes written go out of bounds).
    fn rewind(&mut self, mark: Self::Mark) -> bool {
        if mark > self.capacity() {
            return false;
        }
        self.len = mark;
        true
    }
}

#[cfg(feature = "std")]
impl std::io::Write for BBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match <Self as Writer>::write(self, buf) {
            Ok(n) => Ok(n.get()),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "UnexpectedEof",
            )),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Reader
impl<'a> HasReader for &'a BBuf {
    type Reader = &'a [u8];

    fn reader(self) -> Self::Reader {
        self.as_slice()
    }
}

// From impls
impl From<BBuf> for ZSlice {
    fn from(value: BBuf) -> Self {
        // The written part is a range of the buffer, which is what a slice of it is.
        ZSlice::new(Arc::new(value.buffer), 0, value.len)
            .expect("the length of a buffer is at most its capacity")
    }
}

#[cfg(feature = "test")]
impl BBuf {
    #[doc(hidden)]
    pub fn rand(len: usize) -> Self {
        #[cfg(not(feature = "std"))]
        use alloc::vec::Vec;

        use rand::Rng;

        let mut rng = rand::thread_rng();
        let buffer = (0..len)
            .map(|_| rng.gen())
            .collect::<Vec<u8>>()
            .into_boxed_slice();

        Self { buffer, len }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_buffer_takes_what_fits_and_reads_back_what_was_written() {
        let mut b = BBuf::with_capacity(5);
        assert_eq!((b.capacity(), b.len(), b.remaining()), (5, 0, 5));
        assert_eq!(b.write(&[1, 2, 3]).unwrap().get(), 3);
        assert!(b.write_exact(&[4, 5, 6]).is_err());
        assert_eq!(b.write(&[4, 5, 6]).unwrap().get(), 2);
        assert!(b.write(&[7]).is_err() && !b.can_write());
        assert_eq!(b.as_slice(), [1, 2, 3, 4, 5]);
        b.as_mut_slice()[0] = 9;
        assert_eq!(format!("{b:?}"), "[09, 02, 03, 04, 05]");
        b.clear();
        assert!(Buffer::is_empty(&b) && b.remaining() == 5);
    }

    #[test]
    fn a_mark_rewinds_to_a_length_within_the_capacity_only() {
        let mut b = BBuf::with_capacity(4);
        b.write_exact(&[1, 2]).unwrap();
        let mark = b.mark();
        b.write_exact(&[3]).unwrap();
        assert!(b.rewind(mark) && b.as_slice() == [1, 2]);
        assert!(!b.rewind(5) && b.as_slice() == [1, 2]);
        assert!(b.rewind(4) && b.len() == 4);
    }

    #[test]
    fn a_slot_and_the_conversion_to_a_slice() {
        let mut b = BBuf::with_capacity(4);
        // SAFETY: the closure reports no more than the slot holds.
        assert_eq!(
            unsafe {
                b.with_slot(3, |s| {
                    s[0] = 8;
                    1
                })
            }
            .unwrap()
            .get(),
            1
        );
        // SAFETY: as above.
        assert!(unsafe { b.with_slot(4, |_| 0) }.is_err());
        let z: ZSlice = b.clone().into();
        assert_eq!(z, [8u8]);
        assert_eq!(b.reader(), [8u8]);
        assert_eq!(b.slices().count(), 1);
    }

    #[cfg(feature = "std")]
    #[test]
    fn a_buffer_is_an_io_writer_that_refuses_past_its_capacity() {
        use std::io::Write;
        let mut b = BBuf::with_capacity(2);
        assert_eq!(Write::write(&mut b, &[1, 2, 3]).unwrap(), 2);
        assert_eq!(
            Write::write(&mut b, &[1]).unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        assert!(b.flush().is_ok());
    }
}
