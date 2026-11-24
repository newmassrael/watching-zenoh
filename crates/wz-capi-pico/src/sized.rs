// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The structs a door writes into the program's memory, each sized by the program.
//!
//! Such a struct starts with `struct_size`, a `size_t` the program sets to the size of the struct
//! it was compiled with. A field is added at the end of its struct; a program compiled before it
//! hands a shorter struct, whose bytes past its size are not the library's to write. So a door
//! writes no further than `struct_size`, sets it to the bytes it wrote, and refuses a struct
//! shorter than the fields every program of it has ([`SizedOut::BASE`]) with `Z_EINVAL`, writing
//! nothing.

use core::mem::size_of;
use core::ptr;

use crate::result::{ZResult, Z_EINVAL, Z_ERR_NULL};

/// A struct a door writes into memory the program sized.
///
/// # Safety
/// The implementor is `#[repr(C)]` and its first field is `struct_size: usize`.
pub(crate) unsafe trait SizedOut: Copy {
    /// The bytes of the fields every program of this struct has: its size when it took
    /// `struct_size`. A field added later lies past them, and leaves this as it is.
    const BASE: usize;
}

/// The program's struct a door writes, its `struct_size` read and found long enough.
pub(crate) struct Out<T> {
    at: *mut T,
    /// The bytes the door writes: the program's `struct_size`, at most this build's struct.
    room: usize,
}

impl<T: SizedOut> Out<T> {
    /// The program's struct at `at`: `Z_ERR_NULL` for a null `at`, `Z_EINVAL` for a
    /// `struct_size` under [`SizedOut::BASE`]; nothing is written either way.
    ///
    /// # Safety
    /// `at` is null or points at a struct whose first field is `struct_size`, with that many bytes
    /// writable for as long as the [`Out`] is used. No alignment is assumed.
    pub(crate) unsafe fn of(at: *mut T) -> Result<Self, ZResult> {
        if at.is_null() {
            return Err(Z_ERR_NULL);
        }
        // SAFETY: the caller's: `struct_size` is the first word, read alone since the struct may
        // be shorter than this build's.
        let declared = unsafe { at.cast::<usize>().read_unaligned() };
        if declared < T::BASE {
            return Err(Z_EINVAL);
        }
        Ok(Self {
            at,
            room: declared.min(size_of::<T>()),
        })
    }

    /// Write `value` as far as the program's struct holds, `struct_size` set to the bytes written.
    pub(crate) fn put(&self, value: &T) {
        // SAFETY: `Self::of`'s caller promised `struct_size` writable bytes at `at`, and `room` is
        // at most that and at most `T`'s size; the copy is of bytes, which need no alignment.
        unsafe {
            ptr::copy_nonoverlapping(
                ptr::from_ref(value).cast::<u8>(),
                self.at.cast::<u8>(),
                self.room,
            );
            self.at.cast::<usize>().write_unaligned(self.room);
        }
    }
}

/// The check every door of a sized struct has: one handed a `struct_size` a byte short of the
/// base answers `refused` (`Z_EINVAL` from a door that answers a code) and changes no byte of the
/// struct, `struct_size` among them.
#[cfg(test)]
pub(crate) fn a_short_struct_is_refused_untouched<T: SizedOut, R: PartialEq + core::fmt::Debug>(
    door: impl FnOnce(*mut T) -> R,
    refused: R,
) {
    let mut held = core::mem::MaybeUninit::<T>::uninit();
    let at = held.as_mut_ptr();
    // SAFETY: `held` is this function's, `size_of::<T>()` bytes; its first word is `struct_size`.
    unsafe {
        ptr::write_bytes(at.cast::<u8>(), 0xA5, size_of::<T>());
        at.cast::<usize>().write_unaligned(T::BASE - 1);
    }
    assert_eq!(door(at), refused);
    // SAFETY: as above; every byte was written before the door ran.
    let (size, rest) = unsafe {
        (
            at.cast::<usize>().read_unaligned(),
            core::slice::from_raw_parts(
                at.cast::<u8>().add(size_of::<usize>()),
                size_of::<T>() - size_of::<usize>(),
            ),
        )
    };
    assert_eq!(size, T::BASE - 1, "a refused struct keeps its size");
    assert!(
        rest.iter().all(|byte| *byte == 0xA5),
        "a refused struct is left as it was"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A struct as it is after a field was added past its base.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Grown {
        struct_size: usize,
        first: u64,
        added: u64,
    }

    // SAFETY: `#[repr(C)]`, `struct_size` first.
    unsafe impl SizedOut for Grown {
        const BASE: usize = core::mem::offset_of!(Grown, added);
    }

    const VALUE: Grown = Grown {
        struct_size: 0,
        first: 7,
        added: 9,
    };

    /// A program compiled before `added` has its `first` written and not a byte past its size,
    /// and is told the bytes written. Turned red by a write of the whole of this build's struct.
    #[test]
    fn an_older_struct_has_only_its_own_fields_written() {
        let mut held = Grown {
            struct_size: Grown::BASE,
            first: 0,
            added: 0xA5A5,
        };
        // SAFETY: `held` is a live struct of more bytes than its `struct_size`.
        let out = unsafe { Out::of(&mut held) }.expect("a struct of the base is written");
        out.put(&VALUE);
        assert_eq!(
            held,
            Grown {
                struct_size: Grown::BASE,
                first: 7,
                added: 0xA5A5,
            }
        );
    }

    /// A struct of this build's size, or a later build's larger one, has every field this build
    /// has written, and `struct_size` says how many bytes that was.
    #[test]
    fn a_struct_of_this_size_or_larger_has_every_field_written() {
        #[repr(C)]
        struct Later {
            grown: Grown,
            later: u64,
        }
        let mut held = Later {
            grown: Grown {
                struct_size: size_of::<Later>(),
                first: 0,
                added: 0,
            },
            later: 0xA5A5,
        };
        // SAFETY: `held` holds `struct_size` bytes from its first field on.
        let out = unsafe { Out::of(ptr::addr_of_mut!(held).cast::<Grown>()) }.expect("written");
        out.put(&VALUE);
        assert_eq!(held.grown.struct_size, size_of::<Grown>());
        assert_eq!(
            held.grown,
            Grown {
                struct_size: size_of::<Grown>(),
                ..VALUE
            }
        );
        assert_eq!(
            held.later, 0xA5A5,
            "past this build's struct is the program's"
        );
    }

    /// A struct short of the base, by a byte or entirely, is refused untouched; a null one is
    /// refused as null. Turned red by a door that writes before it reads the size.
    #[test]
    fn a_struct_short_of_the_base_is_refused() {
        a_short_struct_is_refused_untouched::<Grown, _>(
            |at| {
                // SAFETY: `at` is a live struct of this build's size.
                unsafe { Out::of(at) }.map_or_else(|code| code, |_| 0)
            },
            Z_EINVAL,
        );
        let mut empty = Grown {
            struct_size: 0,
            first: 1,
            added: 2,
        };
        // SAFETY: as above.
        assert_eq!(unsafe { Out::of(&mut empty) }.err(), Some(Z_EINVAL));
        assert_eq!((empty.first, empty.added), (1, 2));
        // SAFETY: a null pointer is the case under test.
        assert_eq!(
            unsafe { Out::<Grown>::of(ptr::null_mut()) }.err(),
            Some(Z_ERR_NULL)
        );
    }
}
