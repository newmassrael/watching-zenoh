// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a `z_loaned_X_t*` of a marshalled type points at.
//!
//! zenoh-c's loaned type has the memory of the owned one: `z_loan_mut(v)` is the address of
//! `v`, and `z_take_from_loaned(&dst, loaned)` moves the value OUT of that address and leaves a
//! gravestone in it, which is what a program reads when it takes a value, drops its owned
//! variable and checks it. wz's marshalled types (sample, query, reply, hello) are a pointer to
//! a state somebody owns: a boxed one behind an owned value, or the one a callback's argument
//! stands on. Nothing in the pointer said which, so a take could only copy and could never
//! empty the owned value it came from (`z_api_null_drop_test`, which takes from an owned value
//! filled with garbage and then drops it).
//!
//! The rule that fixes it: the FIRST WORD at the address a loaned pointer names is the address
//! of the state. A state keeps its own address in its first field (a `#[repr(C)]` struct whose
//! first field is a `usize` bound once the state sits where it will stay), so a pointer to the
//! state reads back as itself. An owned value's first field is its handle, which is the state's
//! address, so a pointer to the owned value reads back as the state it holds, and as zero for a
//! gravestone. One load finds the state from either, and comparing the word with the pointer
//! says which of the two it was: equal means the state itself (a callback's argument,
//! borrowed), different means an owned slot (a mutable loan, which a take may empty).

use std::ffi::c_void;

/// The address of the state a loaned pointer names, or zero for an empty owned slot or a null
/// pointer.
///
/// # Safety
/// `p` must be null or point at a readable word: a live state whose first field is its own
/// address, or an owned value whose first field is its handle.
pub(crate) unsafe fn state_addr(p: *const c_void) -> usize {
    if p.is_null() {
        return 0;
    }
    // SAFETY: the caller's contract.
    unsafe { *(p as *const usize) }
}

/// Whether `p` names a state itself (a callback's borrowed argument) and not an owned slot.
///
/// # Safety
/// As [`state_addr`].
pub(crate) unsafe fn is_state_itself(p: *const c_void) -> bool {
    // SAFETY: the caller's contract.
    !p.is_null() && unsafe { state_addr(p) } == p as usize
}

/// Move the handle out of the owned slot `p` names and leave `empty` in its place, or `None` when
/// `p` names a state itself or is null (so a caller copies, or has nothing to take).
///
/// Reads the one word and never follows it: the slot may hold garbage, which a take must move
/// and a later drop of the emptied slot must not trip over.
///
/// # Safety
/// `p` must point at a readable, writable owned value of type `O` whose first field is its
/// handle, or at a state as [`state_addr`] describes.
pub(crate) unsafe fn take_slot<O>(p: *mut c_void, empty: O) -> Option<usize> {
    // SAFETY: the caller's contract.
    if p.is_null() || unsafe { is_state_itself(p) } {
        return None;
    }
    // SAFETY: as above — an owned slot, read and then overwritten whole.
    let handle = unsafe { *(p as *const usize) };
    unsafe { *(p as *mut O) = empty };
    Some(handle)
}
