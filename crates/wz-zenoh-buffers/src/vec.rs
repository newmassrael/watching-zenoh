// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A vector of bytes as a buffer, a writer and, by reference, a reader.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::{num::NonZeroUsize, option};

use crate::{
    buffer::{Buffer, SplitBuffer},
    reader::HasReader,
    writer::{BacktrackableWriter, DidntWrite, HasWriter, Writer},
};

/// Allocate a vector with a given capacity and sets the length to that capacity.
///
/// The bytes are zero, which the caller may not rely on: they are the contents of a buffer that is
/// about to be written, and are as good as any. A zeroed allocation costs next to nothing where the
/// allocator has fresh pages to give (upstream sets the length over memory it has not written, which
/// makes every read of it undefined behaviour).
#[must_use]
pub fn uninit(capacity: usize) -> Vec<u8> {
    alloc::vec![0; capacity]
}

// Buffer
impl Buffer for Vec<u8> {
    fn len(&self) -> usize {
        Vec::len(self)
    }
}

impl Buffer for &Vec<u8> {
    fn len(&self) -> usize {
        Vec::len(self)
    }
}

impl Buffer for &mut Vec<u8> {
    fn len(&self) -> usize {
        Vec::len(self)
    }
}

// SplitBuffer
impl SplitBuffer for Vec<u8> {
    type Slices<'a> = option::IntoIter<&'a [u8]>;

    fn slices(&self) -> Self::Slices<'_> {
        Some(self.as_slice()).into_iter()
    }
}

// Writer
impl HasWriter for &mut Vec<u8> {
    type Writer = Self;

    fn writer(self) -> Self::Writer {
        self
    }
}

impl Writer for Vec<u8> {
    fn write(&mut self, bytes: &[u8]) -> Result<NonZeroUsize, DidntWrite> {
        let len = NonZeroUsize::new(bytes.len()).ok_or(DidntWrite)?;
        self.extend_from_slice(bytes);
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
        usize::MAX
    }

    fn write_u8(&mut self, byte: u8) -> Result<(), DidntWrite> {
        self.push(byte);
        Ok(())
    }

    /// # Safety
    ///
    /// The `write` closure must return the number of bytes actually written to the slice,
    /// which must be less than or equal to `len`.
    ///
    /// The slice is `len` zero bytes at the end of the vector (upstream hands out the vector's
    /// uninitialised spare capacity), and a count past `len` is a panic and not the length of a
    /// vector over memory it does not own.
    unsafe fn with_slot<F>(&mut self, len: usize, write: F) -> Result<NonZeroUsize, DidntWrite>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        let start = self.len();
        self.resize(start + len, 0);
        let written = write(&mut self[start..]);
        assert!(
            written <= len,
            "a slot of {len} bytes was reported as written for {written}"
        );
        self.truncate(start + written);
        NonZeroUsize::new(written).ok_or(DidntWrite)
    }
}

impl BacktrackableWriter for Vec<u8> {
    type Mark = usize;

    fn mark(&mut self) -> Self::Mark {
        self.len()
    }

    fn rewind(&mut self, mark: Self::Mark) -> bool {
        self.truncate(mark);
        true
    }
}

// Reader
impl<'a> HasReader for &'a Vec<u8> {
    type Reader = &'a [u8];

    fn reader(self) -> Self::Reader {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vector_is_written_to_and_marked() {
        let mut v = Vec::new();
        assert!(v.write(&[]).is_err() && v.write_exact(&[]).is_ok());
        assert_eq!(v.write(&[1, 2]).unwrap().get(), 2);
        v.write_u8(3).unwrap();
        let mark = v.mark();
        v.write_exact(&[4, 5]).unwrap();
        assert_eq!(v, [1, 2, 3, 4, 5]);
        assert!(v.rewind(mark));
        assert_eq!(
            (v.as_slice(), v.remaining(), v.can_write()),
            ([1u8, 2, 3].as_slice(), usize::MAX, true)
        );
    }

    #[test]
    fn a_slot_is_given_zeroed_and_keeps_what_was_written() {
        let mut v = vec![9u8];
        // SAFETY: the closure reports no more than the slot holds.
        let n = unsafe {
            v.with_slot(4, |slot| {
                assert_eq!(slot, [0, 0, 0, 0]);
                slot[..2].copy_from_slice(&[7, 8]);
                2
            })
        };
        assert_eq!(n.unwrap().get(), 2);
        assert_eq!(v, [9, 7, 8]);
        // SAFETY: as above.
        assert!(unsafe { v.with_slot(3, |_| 0) }.is_err());
        assert_eq!(v, [9, 7, 8]);
    }

    #[test]
    #[should_panic(expected = "reported as written")]
    fn a_slot_reported_longer_than_it_is_is_a_panic() {
        let mut v = Vec::new();
        // SAFETY: it is not: this is the violation, which is refused.
        let _ = unsafe { v.with_slot(2, |_| 3) };
    }

    #[test]
    fn the_buffer_is_its_length_in_one_slice() {
        let v = vec![1u8, 2, 3];
        assert_eq!((v.len(), Buffer::is_empty(&v)), (3, false));
        assert_eq!(v.slices().collect::<Vec<_>>(), [&[1u8, 2, 3][..]]);
        assert_eq!(&*v.contiguous(), [1, 2, 3]);
        assert_eq!(uninit(5).len(), 5);
    }
}
