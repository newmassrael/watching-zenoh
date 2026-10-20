// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_owned_string_array_t`, the array of strings a hello lends its locators in and a link lends
//! its interfaces in.
//!
//! Its own module, not part of [`crate::scout`], because the array is not scouting's alone: the
//! link event plane returns one, and a build without `z_scout` keeps the type it returns.

use crate::abi::{
    z_loaned_string_array_t, z_loaned_string_t, z_moved_string_array_t, z_owned_string_array_t,
    z_owned_string_t, Handle,
};
use crate::ffi::{guard_val, guarded};
use crate::result::Z_OK;
use crate::string::owned_string_from;

/// Behind a `z_owned_string_array_t` handle: the owned strings and the loaned
/// views handed back by index.
///
/// ## Why the entries are BOXED
///
/// `z_string_array_get` hands out a pointer INTO this collection, and those
/// pointers must stay valid while the caller holds them.
///
/// Until R311y568 that was guaranteed by IMMUTABILITY — the state was built once
/// from a hello's locator list and never pushed to — and this comment said, in
/// as many words, that adding a `push` "would silently break every pointer
/// already handed out". The census then found `z_string_array_push_by_alias` /
/// `_push_by_copy` / `_new` among the symbols upstream defines and wz did not,
/// so the array had to become mutable and the argument had to be replaced rather
/// than waived.
///
/// The replacement is one indirection: each entry is its own `Box`, so a push
/// that reallocates the `Vec` moves the BOXES and never the strings they point
/// at. Every pointer handed out by `z_string_array_get` stays valid for the
/// lifetime of the array, which is a stronger guarantee than the immutable
/// version had — it now survives growth as well as stillness.
pub(crate) struct StringArrayState {
    // `clippy::vec_box` fires here and is WRONG for this type: the lint's premise
    // is that the `Vec` already heap-allocates, so the `Box` buys nothing. What
    // it buys is exactly what the doc above needs — an element address that
    // survives a reallocation. Without it, one `push` past capacity invalidates
    // every pointer `z_string_array_get` has handed out.
    #[allow(clippy::vec_box)]
    entries: Vec<Box<z_owned_string_t>>,
}

/// R2259 (open-debt item 593) — build an OWNED string array over `values`, the
/// one constructor callers outside this module use.
///
/// `z_link_interfaces` is the second producer of a `z_owned_string_array_t`
/// (`z_hello_locators` was the first), and it lives in another module. Exposing
/// the CONSTRUCTOR rather than the state type keeps `StringArrayState` private:
/// the invariant that makes the array safe — every entry is a boxed owned string
/// this crate minted, dropped exactly once by `StringArrayState::drop` — is one
/// this function establishes and a caller cannot break.
///
/// Gated on its one consumer, `z_link_interfaces`, which the no-unstable arms do
/// not compile — an ungated definition is dead code there, and `-D warnings` is
/// right about that.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
pub(crate) fn owned_string_array_from(values: &[String]) -> z_owned_string_array_t {
    let handle = Box::into_raw(Box::new(StringArrayState::from_strings(values))) as Handle;
    z_owned_string_array_t::from_handle(handle)
}

impl StringArrayState {
    #[cfg(any(test, feature = "scout", not(feature = "zenoh-c-no-unstable-api")))]
    pub(crate) fn from_strings(values: &[String]) -> Self {
        Self {
            entries: values
                .iter()
                .map(|value| Box::new(owned_string_from(value.as_bytes())))
                .collect(),
        }
    }

    /// R311y568 — the EMPTY array `z_string_array_new` constructs.
    fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// R311y568 — append one entry and report the NEW length, which is what
    /// upstream's two push functions return.
    fn push(&mut self, entry: z_owned_string_t) -> usize {
        self.entries.push(Box::new(entry));
        self.entries.len()
    }
}

impl Drop for StringArrayState {
    fn drop(&mut self) {
        for entry in self.entries.drain(..) {
            let mut moved = crate::abi::z_moved_string_t { _this: *entry };
            // SAFETY: each entry is an owned string this state minted (or an
            // ALIAS whose `owned` slot is null and which therefore drops to a
            // no-op); dropped exactly once because the vector is drained.
            unsafe { crate::string::z_string_drop(&mut moved) };
        }
    }
}

/// Read the [`StringArrayState`] behind a loaned string array.
///
/// # Safety
/// `this_` must be null or a valid loaned array whose handle is live.
unsafe fn string_array_state<'a>(
    this_: *const z_loaned_string_array_t,
) -> Option<&'a StringArrayState> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<StringArrayState>` this crate leaked.
    Some(unsafe { &*(handle as *const StringArrayState) })
}

/// Borrow a string array (zenoh-c `z_string_array_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned string array.
#[no_mangle]
pub unsafe extern "C" fn z_string_array_loan(
    this_: *const z_owned_string_array_t,
) -> *const z_loaned_string_array_t {
    this_ as *const z_loaned_string_array_t
}

/// How many strings the array holds (zenoh-c `z_string_array_len`).
///
/// # Safety
/// `this_` must be null or a valid loaned string array.
#[no_mangle]
pub unsafe extern "C" fn z_string_array_len(this_: *const z_loaned_string_array_t) -> usize {
    guard_val(0, || {
        // SAFETY: the caller's contract, delegated.
        unsafe { string_array_state(this_) }.map_or(0, |s| s.entries.len())
    })
}

/// `true` iff the array is empty (zenoh-c `z_string_array_is_empty`).
///
/// # Safety
/// `this_` must be null or a valid loaned string array.
#[no_mangle]
pub unsafe extern "C" fn z_string_array_is_empty(this_: *const z_loaned_string_array_t) -> bool {
    // SAFETY: delegated.
    unsafe { z_string_array_len(this_) == 0 }
}

/// Borrow the string at `index`, or NULL past the end (zenoh-c
/// `z_string_array_get`).
///
/// # Safety
/// `this_` must be null or a valid loaned string array.
#[no_mangle]
pub unsafe extern "C" fn z_string_array_get(
    this_: *const z_loaned_string_array_t,
    index: usize,
) -> *const z_loaned_string_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { string_array_state(this_) } {
            Some(state) => state.entries.get(index).map_or(std::ptr::null(), |entry| {
                // Through the BOX, so the address is the string's own heap slot
                // rather than a position in the vector — see the state's docs
                // for why that is what keeps this pointer valid across a push.
                entry.as_ref() as *const z_owned_string_t as *const z_loaned_string_t
            }),
            None => std::ptr::null(),
        }
    })
}

/// `true` iff the owned array holds a live state (zenoh-c
/// `z_internal_string_array_check`).
///
/// # Safety
/// `this_` must be null or a valid owned string array.
#[no_mangle]
pub unsafe extern "C" fn z_internal_string_array_check(
    this_: *const z_owned_string_array_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned string array (zenoh-c `z_internal_string_array_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned string array.
#[no_mangle]
pub unsafe extern "C" fn z_internal_string_array_null(this_: *mut z_owned_string_array_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_string_array_t::null_value() };
    }
}

// --- R311y568: the string array's MUTABLE half ------------------------------
//
// Five symbols upstream defines and this cdylib did not. The array had been
// receive-only — a hello's locator list, built once — and these are what make it
// a container a C program can build.

/// Construct an EMPTY string array (zenoh-c `z_string_array_new`).
///
/// Empty is not the same as the gravestone: this array CHECKS as present and can
/// be pushed to, while `z_internal_string_array_null` produces one that does
/// not. The same two-state distinction [`crate::string`] records for strings.
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_string_array_new(this_: *mut z_owned_string_array_t) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        let handle = Box::into_raw(Box::new(StringArrayState::empty())) as Handle;
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_string_array_t::from_handle(handle) };
    });
}

/// Mutably borrow a string array (zenoh-c `z_string_array_loan_mut`).
///
/// The loan is a POINTER CAST like its immutable twin — owned and loaned share
/// one layout — so a caller can push through the result.
///
/// # Safety
/// `this_` must be null or a valid owned string array.
#[no_mangle]
pub unsafe extern "C" fn z_string_array_loan_mut(
    this_: *mut z_owned_string_array_t,
) -> *mut z_loaned_string_array_t {
    this_ as *mut z_loaned_string_array_t
}

/// The mutable [`StringArrayState`] behind a loaned string array.
///
/// # Safety
/// `this_` must be null or a valid loaned array whose handle is live.
unsafe fn string_array_state_mut<'a>(
    this_: *mut z_loaned_string_array_t,
) -> Option<&'a mut StringArrayState> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<StringArrayState>` this crate leaked. The `&mut` is
    // sound for the same reason every other handle deref in this crate is: the
    // C side owns the array and zenoh-c's contract makes it single-threaded for
    // the duration of a call.
    Some(unsafe { &mut *(handle as *mut StringArrayState) })
}

/// Append a BORROW of `value` and report the new length (zenoh-c
/// `z_string_array_push_by_alias`).
///
/// Stores a VIEW — the entry's `owned` slot stays null, so dropping the array
/// does not free the caller's buffer. The caller must keep `value` alive for as
/// long as the array, which is upstream's contract for the aliasing push.
///
/// # Safety
/// `this_` must be null or a valid loaned string array; `value` must be null or a
/// valid loaned string that outlives the array.
#[no_mangle]
pub unsafe extern "C" fn z_string_array_push_by_alias(
    this_: *mut z_loaned_string_array_t,
    value: *const z_loaned_string_t,
) -> usize {
    guard_val(0, || {
        // SAFETY: the caller's contract, delegated.
        let Some(state) = (unsafe { string_array_state_mut(this_) }) else {
            return 0;
        };
        // SAFETY: the caller's contract.
        let Some(bytes) = (unsafe { crate::string::loaned_string_bytes(value) }) else {
            return state.entries.len();
        };
        // The VIEW shape: a borrow of the caller's buffer, whose drop is a
        // no-op. `view_string_over` takes `&str`, and this is bytes that may not
        // be UTF-8, so the struct is built directly rather than through it.
        state.push(z_owned_string_t {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
            owned: std::ptr::null_mut(),
            _pad: 0,
        })
    })
}

/// Append a COPY of `value` and report the new length (zenoh-c
/// `z_string_array_push_by_copy`).
///
/// # Safety
/// `this_` must be null or a valid loaned string array; `value` must be null or a
/// valid loaned string.
#[no_mangle]
pub unsafe extern "C" fn z_string_array_push_by_copy(
    this_: *mut z_loaned_string_array_t,
    value: *const z_loaned_string_t,
) -> usize {
    guard_val(0, || {
        // SAFETY: the caller's contract, delegated.
        let Some(state) = (unsafe { string_array_state_mut(this_) }) else {
            return 0;
        };
        // SAFETY: the caller's contract.
        let Some(bytes) = (unsafe { crate::string::loaned_string_bytes(value) }) else {
            return state.entries.len();
        };
        state.push(owned_string_from(bytes))
    })
}

/// Deep-copy a string array (zenoh-c `z_string_array_clone`).
///
/// ## Every entry becomes OWNED, including the aliased ones
///
/// A clone of an array holding aliases could keep them aliased — upstream's own
/// entries are a borrowed-or-owned union, so that would be the literal mirror.
/// wz copies instead, and the difference is one of LIFETIME rather than of
/// value: a wz clone outlives the buffers the original aliased, where upstream's
/// would dangle with them. Nothing a C program can read off the array
/// distinguishes the two, and the direction of the divergence is toward the
/// safer side of a use-after-free.
///
/// # Safety
/// `dst` must be null or valid and writable; `this_` must be null or a valid
/// loaned string array.
#[no_mangle]
pub unsafe extern "C" fn z_string_array_clone(
    dst: *mut z_owned_string_array_t,
    this_: *const z_loaned_string_array_t,
) {
    guard_val((), || {
        if dst.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *dst = z_owned_string_array_t::null_value() };
        // SAFETY: the caller's contract, delegated.
        let Some(state) = (unsafe { string_array_state(this_) }) else {
            return;
        };
        let mut copy = StringArrayState::empty();
        for entry in &state.entries {
            // SAFETY: each entry is a live owned-or-view string this state
            // holds; read through the same accessor `z_string_data` uses.
            let bytes = unsafe {
                crate::string::loaned_string_bytes(
                    entry.as_ref() as *const z_owned_string_t as *const z_loaned_string_t
                )
            }
            .unwrap_or(&[]);
            copy.push(owned_string_from(bytes));
        }
        let handle = Box::into_raw(Box::new(copy)) as Handle;
        // SAFETY: the caller's contract.
        unsafe { *dst = z_owned_string_array_t::from_handle(handle) };
    });
}

/// Free a string array (zenoh-c `z_string_array_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved string array.
#[no_mangle]
pub unsafe extern "C" fn z_string_array_drop(this_: *mut z_moved_string_array_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<StringArrayState>` this crate leaked.
            drop(unsafe { Box::from_raw(handle as *mut StringArrayState) });
            unsafe { (*this_)._this = z_owned_string_array_t::null_value() };
        }
        Z_OK
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A string array hands out STABLE pointers by index, reads its length, and
    /// frees everything on drop. The stability is what the boxed entries buy:
    /// `z_scout.c` holds one locator pointer while asking for the next.
    #[test]
    fn the_string_array_reads_by_index_and_keeps_its_pointers_stable() {
        let handle = Box::into_raw(Box::new(StringArrayState::from_strings(&[
            "tcp/127.0.0.1:7447".to_string(),
            "udp/127.0.0.1:7447".to_string(),
        ]))) as Handle;
        let owned = z_owned_string_array_t::from_handle(handle);
        // SAFETY: `owned` is a live array this test built.
        unsafe {
            let loaned = z_string_array_loan(&owned);
            assert_eq!(z_string_array_len(loaned), 2);
            assert!(!z_string_array_is_empty(loaned));
            let first = z_string_array_get(loaned, 0);
            let second = z_string_array_get(loaned, 1);
            assert!(!first.is_null() && !second.is_null());
            assert_ne!(first, second);
            // Re-reading index 0 gives the SAME pointer — the property a
            // caller holding it across another `get` depends on.
            assert_eq!(z_string_array_get(loaned, 0), first);
            assert_eq!(
                std::slice::from_raw_parts(
                    crate::string::z_string_data(first) as *const u8,
                    crate::string::z_string_len(first)
                ),
                b"tcp/127.0.0.1:7447"
            );
            assert!(
                z_string_array_get(loaned, 2).is_null(),
                "past the end must be NULL, not a wrapped index"
            );

            let mut moved = z_moved_string_array_t { _this: owned };
            z_string_array_drop(&mut moved);
            assert!(!z_internal_string_array_check(&moved._this));
            z_string_array_drop(&mut moved);
        }
    }

    /// R311y568 — an element pointer SURVIVES a reallocating push.
    ///
    /// ## Why this is a wz-side unit test and not a twice-and-diff leg
    ///
    /// This is the property [`StringArrayState`]'s boxed entries exist for, and
    /// it is a wz SUPERSET: the real `libzenohc.so` stores its entries inline,
    /// so the same program SEGFAULTS against it. The pure-function oracle
    /// discovered that by crashing its reference arm, which is exactly the
    /// outcome that says "this claim has no reference answer to agree with".
    ///
    /// A superset still has to be TRUE, though, and nothing else checks it —
    /// the census sees only symbol names and the diff cannot compare a property
    /// one side lacks. So it is asserted here, against wz alone, with the claim
    /// stated as what it is.
    ///
    /// The test is meaningful only if the push actually REALLOCATES, which is
    /// why it grows well past any plausible initial capacity rather than pushing
    /// once: a `Vec` that never resized would pass this on the inline layout too.
    #[test]
    fn an_element_pointer_survives_a_reallocating_push() {
        // SAFETY: every pointer below is a live stack slot this test owns, and
        // the array is dropped exactly once at the end.
        unsafe {
            let mut arr = z_owned_string_array_t::null_value();
            z_string_array_new(&mut arr);
            let mut first = crate::string::owned_string_from(b"first");
            assert_eq!(
                z_string_array_push_by_copy(
                    z_string_array_loan_mut(&mut arr),
                    &first as *const z_owned_string_t as *const z_loaned_string_t,
                ),
                1
            );

            // The pointer taken BEFORE the growth — the one upstream's layout
            // would invalidate.
            let e0 = z_string_array_get(z_string_array_loan(&arr), 0);
            assert!(!e0.is_null());
            let before = std::slice::from_raw_parts(
                crate::string::z_string_data(e0) as *const u8,
                crate::string::z_string_len(e0),
            )
            .to_vec();

            let mut filler = crate::string::owned_string_from(b"filler");
            for _ in 0..64 {
                z_string_array_push_by_copy(
                    z_string_array_loan_mut(&mut arr),
                    &filler as *const z_owned_string_t as *const z_loaned_string_t,
                );
            }
            assert_eq!(z_string_array_len(z_string_array_loan(&arr)), 65);

            // Read through the PRE-GROWTH pointer, not a fresh `get`. A fresh
            // one would pass on either layout and would be testing nothing.
            let after = std::slice::from_raw_parts(
                crate::string::z_string_data(e0) as *const u8,
                crate::string::z_string_len(e0),
            )
            .to_vec();
            assert_eq!(
                after, before,
                "the pointer handed out before the growth no longer reads its own \
                 string, so a reallocating push moved the entry"
            );
            assert_eq!(after, b"first");

            let mut moved_arr = crate::abi::z_moved_string_array_t { _this: arr };
            z_string_array_drop(&mut moved_arr);
            let mut mf = crate::abi::z_moved_string_t { _this: filler };
            crate::string::z_string_drop(&mut mf);
            filler = z_owned_string_t::null_value();
            let _ = &filler;
            let mut m1 = crate::abi::z_moved_string_t { _this: first };
            crate::string::z_string_drop(&mut m1);
            first = z_owned_string_t::null_value();
            let _ = &first;
        }
    }
}
