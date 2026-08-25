// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The slice family — owned, view, and the loaned shape both of them cast to.
//!
//! Structurally the string family's twin ([`crate::string`]), and deliberately
//! so: upstream's `z_slice_loan` and `z_view_slice_loan` are both pointer casts,
//! so an owned slice and a view slice are already required to be readable as one
//! loaned shape. [`SliceRepr`](crate::abi::SliceRepr) makes that one definition
//! rather than two layouts that agree by coincidence.
//!
//! The difference from the string family is that a slice carries BYTES, not
//! text: no trailing NUL is appended, because `z_slice_data` /`z_slice_len` are
//! the whole contract and `z_bytes.c` prints the bytes as hex rather than as a
//! string.

use crate::abi::{z_loaned_slice_t, z_moved_slice_t, z_owned_slice_t, z_view_slice_t, Handle};
use crate::ffi::{guard_val, guarded};
use crate::result::Z_OK;

/// Build an OWNED slice from bytes, taking a copy the caller then owns.
pub(crate) fn owned_slice_from(bytes: &[u8]) -> z_owned_slice_t {
    let boxed = Box::new(bytes.to_vec());
    let ptr = boxed.as_ptr();
    z_owned_slice_t {
        ptr,
        len: boxed.len(),
        owned: Box::into_raw(boxed) as Handle,
        _pad: 0,
    }
}

/// Build a VIEW slice borrowing `bytes`, which must outlive every use of it.
pub(crate) fn view_slice_over(bytes: &[u8]) -> z_view_slice_t {
    z_view_slice_t {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        owned: std::ptr::null_mut(),
        _pad: 0,
    }
}

/// The bytes behind a loaned slice, or `None` for a gravestone.
///
/// R311y568 — re-exported as [`loaned_slice_bytes`] for `z_bytes_copy_from_slice`
/// next door.
///
/// # Safety
/// `this_` must be null or a valid loaned slice.
unsafe fn slice_bytes<'a>(this_: *const z_loaned_slice_t) -> Option<&'a [u8]> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let (ptr, len) = unsafe { ((*this_).ptr, (*this_).len) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: `ptr`/`len` describe a buffer this crate minted (owned) or a
    // borrow whose lifetime is the caller's obligation (view).
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// The slice's bytes (zenoh-c `z_slice_data`).
///
/// # Safety
/// `this_` must be null or a valid loaned slice.
#[no_mangle]
pub unsafe extern "C" fn z_slice_data(this_: *const z_loaned_slice_t) -> *const u8 {
    guard_val(std::ptr::null(), || {
        if this_.is_null() {
            return std::ptr::null();
        }
        // SAFETY: the caller's contract.
        unsafe { (*this_).ptr }
    })
}

/// The slice's length in bytes (zenoh-c `z_slice_len`).
///
/// # Safety
/// `this_` must be null or a valid loaned slice.
#[no_mangle]
pub unsafe extern "C" fn z_slice_len(this_: *const z_loaned_slice_t) -> usize {
    guard_val(0, || {
        // SAFETY: the caller's contract, delegated.
        unsafe { slice_bytes(this_) }.map_or(0, <[u8]>::len)
    })
}

/// Borrow an owned slice (zenoh-c `z_slice_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned slice.
#[no_mangle]
pub unsafe extern "C" fn z_slice_loan(this_: *const z_owned_slice_t) -> *const z_loaned_slice_t {
    this_
}

/// Borrow a view slice (zenoh-c `z_view_slice_loan`).
///
/// # Safety
/// `this_` must be null or a valid view slice.
#[no_mangle]
pub unsafe extern "C" fn z_view_slice_loan(
    this_: *const z_view_slice_t,
) -> *const z_loaned_slice_t {
    this_
}

/// `true` iff the owned slice holds a live buffer (zenoh-c
/// `z_internal_slice_check`).
///
/// # Safety
/// `this_` must be null or a valid owned slice.
#[no_mangle]
pub unsafe extern "C" fn z_internal_slice_check(this_: *const z_owned_slice_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).ptr }.is_null()
    })
}

/// Zero an owned slice (zenoh-c `z_internal_slice_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned slice.
#[no_mangle]
pub unsafe extern "C" fn z_internal_slice_null(this_: *mut z_owned_slice_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_slice_t::null_value() };
    }
}

/// Free an owned slice and reset it to its gravestone (zenoh-c `z_slice_drop`).
///
/// A VIEW slice reaching here has a null `owned` slot and drops to a no-op,
/// which is upstream's behaviour: a view never owned the bytes.
///
/// # Safety
/// `this_` must be null or a valid moved slice.
#[no_mangle]
pub unsafe extern "C" fn z_slice_drop(this_: *mut z_moved_slice_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let owned = unsafe { (*this_)._this.owned };
        if !owned.is_null() {
            // SAFETY: a live `Box<Vec<u8>>` this crate leaked in
            // `owned_slice_from`; reclaimed once because the slot is nulled
            // immediately after.
            drop(unsafe { Box::from_raw(owned as *mut Vec<u8>) });
        }
        // Nulled on EVERY path, so a defensive second drop is a no-op.
        unsafe { (*this_)._this = z_owned_slice_t::null_value() };
        Z_OK
    });
}

// --- R311y564: the rest of upstream's slice surface -------------------------

/// The GRAVESTONE owned slice — a null buffer.
///
/// Distinct from an EMPTY slice: the empty one CHECKS as present. See the
/// string family's note; the same two-state distinction applies.
pub(crate) fn null_slice() -> z_owned_slice_t {
    z_owned_slice_t {
        ptr: std::ptr::null(),
        len: 0,
        owned: std::ptr::null_mut(),
        _pad: 0,
    }
}

/// Construct an EMPTY owned slice (zenoh-c `z_slice_empty`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_slice_empty(this_: *mut z_owned_slice_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = owned_slice_from(&[]) };
    }
}

/// `true` iff the loaned slice has zero length (zenoh-c `z_slice_is_empty`).
///
/// # Safety
/// `this_` must be null or a valid loaned slice.
#[no_mangle]
pub unsafe extern "C" fn z_slice_is_empty(this_: *const z_loaned_slice_t) -> bool {
    guard_val(true, || {
        // SAFETY: the caller's contract.
        unsafe { slice_bytes(this_) }.map_or(true, <[u8]>::is_empty)
    })
}

// --- R311y568: the two cross-module readers `crate::bytes` needs -------------

/// The bytes behind a loaned slice, for a consumer outside this module.
///
/// # Safety
/// As [`slice_bytes`].
pub(crate) unsafe fn loaned_slice_bytes<'a>(this_: *const z_loaned_slice_t) -> Option<&'a [u8]> {
    // SAFETY: the caller's contract, delegated.
    unsafe { slice_bytes(this_) }
}

/// CONSUME a moved slice: take its bytes, gravestone the caller's slot, and free
/// the buffer when it was owned.
///
/// The slice-side twin of [`crate::encoding::take_moved_encoding`], and the same
/// argument applies: a `z_moved_*` parameter is consumed on every path, so a READ
/// would leave the caller's owned value non-null and leak its buffer.
///
/// A VIEW slice reaching here has a null `owned` slot, so its bytes are copied
/// and nothing is freed — the borrow was never this crate's to release.
///
/// # Safety
/// `moved` must be null, or a valid, writable moved slice.
pub(crate) unsafe fn take_moved_slice(moved: *mut z_moved_slice_t) -> Option<Vec<u8>> {
    if moved.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let (ptr, len, owned) = unsafe {
        let s = &(*moved)._this;
        (s.ptr, s.len, s.owned)
    };
    // SAFETY: gravestoned before any free, so a second drop is a no-op.
    unsafe { (*moved)._this = z_owned_slice_t::null_value() };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: `ptr`/`len` describe a live buffer per the caller's contract.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
    if !owned.is_null() {
        // SAFETY: a live `Box<Vec<u8>>` this crate leaked in `owned_slice_from`.
        drop(unsafe { Box::from_raw(owned as *mut Vec<u8>) });
    }
    Some(bytes)
}

/// Deep-copy a slice (zenoh-c `z_slice_clone`).
///
/// # Safety
/// `dst` must be valid and writable; `this_` must be null or a valid loaned
/// slice.
#[no_mangle]
pub unsafe extern "C" fn z_slice_clone(dst: *mut z_owned_slice_t, this_: *const z_loaned_slice_t) {
    guard_val((), || {
        if dst.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *dst = null_slice() };
        // SAFETY: as above.
        let Some(bytes) = (unsafe { slice_bytes(this_) }) else {
            return;
        };
        unsafe { *dst = owned_slice_from(bytes) };
    });
}

/// Copy `len` bytes into an owned slice (zenoh-c `z_slice_copy_from_buf`).
///
/// # Safety
/// `this_` must be valid and writable; `start` must be null or point at `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_slice_copy_from_buf(
    this_: *mut z_owned_slice_t,
    start: *const u8,
    len: usize,
) -> crate::result::ZResult {
    guarded(|| {
        if this_.is_null() {
            return crate::result::Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = null_slice() };
        if start.is_null() {
            return crate::result::Z_ENULL;
        }
        // SAFETY: as above — `len` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(start, len) };
        unsafe { *this_ = owned_slice_from(bytes) };
        Z_OK
    })
}

/// ADOPT a caller-allocated buffer into an owned slice (zenoh-c
/// `z_slice_from_buf`).
///
/// Upstream transfers ownership: the slice takes the buffer and calls `drop`
/// when it is done. wz COPIES and invokes the deleter immediately, which is the
/// same divergence `wz-capi-pico`'s `z_bytes_from_buf` records and for the same
/// reason — this crate's owned slice frees through `Box<Vec<u8>>`, and a
/// foreign allocation cannot be handed to that.
///
/// The deleter runs on EVERY path including the failure ones. Upstream's
/// ownership transfer is unconditional, so skipping it would leak the caller's
/// buffer rather than merely diverging.
///
/// # Safety
/// `this_` must be valid and writable; `data` must be null or point at `len`
/// readable bytes owned by the caller; `drop` must be null or callable with
/// `(data, context)`.
#[no_mangle]
pub unsafe extern "C" fn z_slice_from_buf(
    this_: *mut z_owned_slice_t,
    data: *mut u8,
    len: usize,
    drop: Option<unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void)>,
    context: *mut std::ffi::c_void,
) -> crate::result::ZResult {
    let copied = if data.is_null() {
        None
    } else {
        // SAFETY: the caller's contract — `len` readable bytes at `data`.
        Some(unsafe { std::slice::from_raw_parts(data, len) }.to_vec())
    };
    // The transfer is unconditional upstream, so the deleter runs before any
    // early return below.
    if let Some(deleter) = drop {
        // SAFETY: the caller's contract for the function pointer.
        unsafe { deleter(data.cast(), context) };
    }
    guarded(|| {
        if this_.is_null() {
            return crate::result::Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = null_slice() };
        let Some(copied) = copied else {
            return crate::result::Z_ENULL;
        };
        unsafe { *this_ = owned_slice_from(&copied) };
        Z_OK
    })
}

/// Gravestone a view slice (zenoh-c `z_view_slice_empty`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_view_slice_empty(this_: *mut z_view_slice_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = view_slice_over(&[]) };
    }
}

/// `true` iff the view slice is empty (zenoh-c `z_view_slice_is_empty`).
///
/// # Safety
/// `this_` must be null or a valid view slice.
#[no_mangle]
pub unsafe extern "C" fn z_view_slice_is_empty(this_: *const z_view_slice_t) -> bool {
    guard_val(true, || {
        // SAFETY: the caller's contract — the two types share a footprint.
        unsafe { z_slice_is_empty(this_ as *const z_loaned_slice_t) }
    })
}

/// Build a view slice ALIASING the caller's buffer (zenoh-c
/// `z_view_slice_from_buf`).
///
/// # Safety
/// `this_` must be valid and writable; `start` must be null or point at `len`
/// readable bytes that outlive every use of the view.
#[no_mangle]
pub unsafe extern "C" fn z_view_slice_from_buf(
    this_: *mut z_view_slice_t,
    start: *const u8,
    len: usize,
) -> crate::result::ZResult {
    guarded(|| {
        if this_.is_null() {
            return crate::result::Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = view_slice_over(&[]) };
        if start.is_null() {
            return crate::result::Z_ENULL;
        }
        // SAFETY: as above — the view borrows, so no copy is made.
        unsafe {
            *this_ = z_view_slice_t {
                ptr: start,
                len,
                owned: std::ptr::null_mut(),
                _pad: 0,
            }
        };
        Z_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An owned slice round-trips its bytes and a view over the same bytes
    /// reads identically through the ONE loaned shape — the property that makes
    /// both loans honest pointer casts.
    #[test]
    fn owned_and_view_slices_read_the_same_through_one_loaned_shape() {
        let src = [1u8, 2, 3, 4];
        let owned = owned_slice_from(&src);
        let view = view_slice_over(&src);
        // SAFETY: both values are live locals this test just built.
        unsafe {
            let a = z_slice_loan(&owned);
            let b = z_view_slice_loan(&view);
            assert_eq!(z_slice_len(a), 4);
            assert_eq!(z_slice_len(b), 4);
            assert_eq!(std::slice::from_raw_parts(z_slice_data(a), 4), &src);
            assert_eq!(std::slice::from_raw_parts(z_slice_data(b), 4), &src);
            assert!(z_internal_slice_check(&owned));

            // The view must NOT free the caller's buffer.
            let mut moved_view = crate::abi::z_moved_slice_t { _this: view };
            z_slice_drop(&mut moved_view);
            assert_eq!(src, [1u8, 2, 3, 4]);

            let mut moved = crate::abi::z_moved_slice_t { _this: owned };
            z_slice_drop(&mut moved);
            assert!(!z_internal_slice_check(&moved._this));
            // Idempotent: the slot was nulled, so this is not a double free.
            z_slice_drop(&mut moved);
        }
    }

    /// Every accessor answers a NULL rather than dereferencing it.
    #[test]
    fn the_slice_accessors_answer_null_without_dereferencing_it() {
        // SAFETY: passing NULL is exactly what these guards exist for.
        unsafe {
            assert!(z_slice_data(std::ptr::null()).is_null());
            assert_eq!(z_slice_len(std::ptr::null()), 0);
            assert!(!z_internal_slice_check(std::ptr::null()));
            z_slice_drop(std::ptr::null_mut());
        }
    }
}
