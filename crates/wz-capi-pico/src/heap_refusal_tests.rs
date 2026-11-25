// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The doors that make an object for the program on the heap, met by a full heap: each answers
//! `_Z_ERR_SYSTEM_OUT_OF_MEMORY` as zenoh-pico answers its failed `malloc` (a door with no result
//! leaves its output null) and the program goes on, where a box made by `Box::new` would end it.
//! Each door is called once with the heap giving first, so a pool it reserves on its first call is
//! reserved, and then with every allocation of the thread refused ([`crate::test_heap::refused`]).

use core::ffi::{c_char, c_void};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::bytes::{
    z_internal_slice_check, z_internal_string_check, z_slice_copy_from_buf, z_slice_drop,
    z_slice_move, z_string_copy_from_str, z_string_drop, z_string_empty, z_string_from_str,
    z_string_loan, z_string_move,
};
use crate::encoding::z_encoding_to_string;
use crate::handlers::{_z_fifo_mt_t, _z_rc_decrease_strong, _z_rc_init};
use crate::keyexpr::{
    z_internal_keyexpr_check, z_keyexpr_clone, z_keyexpr_drop, z_keyexpr_from_substr,
    z_keyexpr_loan, z_keyexpr_move,
};
use crate::result::{Z_ERR_SYSTEM_OUT_OF_MEMORY, Z_OK};
use crate::serde::{z_bytes_writer_empty, ze_serializer_empty};
use crate::string_array::{
    z_internal_string_array_check, z_string_array_clone, z_string_array_drop, z_string_array_len,
    z_string_array_loan, z_string_array_loan_mut, z_string_array_move, z_string_array_new,
    z_string_array_push_by_copy,
};
use crate::test_heap::refused;

/// How many times [`count_release`] ran.
static RELEASED: AtomicUsize = AtomicUsize::new(0);

/// A deleter that counts its runs and frees nothing: the bytes are the test's own.
unsafe extern "C" fn count_release(_value: *mut c_void, _context: *mut c_void) {
    RELEASED.fetch_add(1, Ordering::SeqCst);
}

/// A string or a slice the heap has no room for is refused and left null, and a string that
/// describes the caller's bytes hands them back to the caller's deleter at once, once. Turned red
/// by a string or a slice boxed with `Box::new`.
#[test]
fn a_full_heap_is_answered_by_the_string_and_slice_doors() {
    let text = c"demo/text";
    // SAFETY: each output is the test's own, and each pointer handed is a live text or buffer.
    unsafe {
        let mut string = crate::abi::z_owned_string_t::null_value();
        assert_eq!(z_string_copy_from_str(&mut string, text.as_ptr()), Z_OK);
        z_string_drop(z_string_move(&mut string));
        z_string_empty(&mut string);
        z_string_drop(z_string_move(&mut string));
        let copied = refused(|| z_string_copy_from_str(&mut string, text.as_ptr()));
        assert_eq!(copied, Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert!(!z_internal_string_check(&string));
        refused(|| z_string_empty(&mut string));
        assert!(!z_internal_string_check(&string), "an empty string refused");
        let mut owned = *b"demo/owned\0";
        let before = RELEASED.load(Ordering::SeqCst);
        let adopted = refused(|| {
            z_string_from_str(
                &mut string,
                owned.as_mut_ptr().cast::<c_char>(),
                Some(count_release),
                core::ptr::null_mut(),
            )
        });
        assert_eq!(adopted, Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert!(!z_internal_string_check(&string));
        assert_eq!(
            RELEASED.load(Ordering::SeqCst),
            before + 1,
            "the caller's bytes handed back once"
        );
        let mut slice = crate::abi::z_owned_slice_t::null_value();
        let bytes = *b"\x01\x02\x03";
        assert_eq!(
            z_slice_copy_from_buf(&mut slice, bytes.as_ptr(), bytes.len()),
            Z_OK
        );
        z_slice_drop(z_slice_move(&mut slice));
        let sliced = refused(|| z_slice_copy_from_buf(&mut slice, bytes.as_ptr(), bytes.len()));
        assert_eq!(sliced, Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert!(!z_internal_slice_check(&slice));
    }
}

/// A writer and a serializer the heap has no room for are refused and left null. Turned red by
/// either boxed with `Box::new`.
#[test]
fn a_full_heap_is_answered_by_the_writer_doors() {
    // SAFETY: each output is the test's own.
    unsafe {
        let mut writer = crate::serde::z_owned_bytes_writer_t::null_value();
        let wrote = refused(|| z_bytes_writer_empty(&mut writer));
        assert_eq!(wrote, Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert!(writer.handle.is_null());
        let mut serializer = crate::serde::ze_owned_serializer_t::null_value();
        let serialized = refused(|| ze_serializer_empty(&mut serializer));
        assert_eq!(serialized, Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert!(serializer.handle.is_null());
    }
}

/// A string array the heap has no room for is left null; a push it has no room for adds nothing
/// and answers the length as it was; a copy it has no room for is refused, left null, and leaves
/// the array copied from as it was. Turned red by an array, an entry or an entry's bytes boxed
/// with `Box::new`, or by an entry pushed with `Vec::push`.
#[test]
fn a_full_heap_is_answered_by_the_string_array_doors() {
    let text = c"demo/entry";
    // SAFETY: each output is the test's own, and each array handed is live.
    unsafe {
        let mut array = crate::string_array::z_owned_string_array_t::null_value();
        refused(|| z_string_array_new(&mut array));
        assert!(!z_internal_string_array_check(&array));
        z_string_array_new(&mut array);
        assert!(z_internal_string_array_check(&array));
        let mut entry = crate::abi::z_owned_string_t::null_value();
        assert_eq!(z_string_copy_from_str(&mut entry, text.as_ptr()), Z_OK);
        let loaned = z_string_array_loan_mut(&mut array);
        assert_eq!(
            z_string_array_push_by_copy(loaned, z_string_loan(&entry)),
            1
        );
        let pushed = refused(|| z_string_array_push_by_copy(loaned, z_string_loan(&entry)));
        assert_eq!(pushed, 1, "the length as it was");
        let mut copy = crate::string_array::z_owned_string_array_t::null_value();
        let copied = refused(|| z_string_array_clone(&mut copy, z_string_array_loan(&array)));
        assert_eq!(copied, Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert!(!z_internal_string_array_check(&copy));
        assert_eq!(z_string_array_len(z_string_array_loan(&array)), 1);
        assert_eq!(
            z_string_array_clone(&mut copy, z_string_array_loan(&array)),
            Z_OK
        );
        assert_eq!(z_string_array_len(z_string_array_loan(&copy)), 1);
        z_string_array_drop(z_string_array_move(&mut copy));
        z_string_array_drop(z_string_array_move(&mut array));
        z_string_drop(z_string_move(&mut entry));
    }
}

/// A key the heap has no room for, made from a text or copied from a key, is refused and left
/// null. Turned red by a key's text or its box made with `Box::new`.
#[test]
fn a_full_heap_is_answered_by_the_keyexpr_doors() {
    let text = "demo/refused/key";
    // SAFETY: each output is the test's own, and the text is `text.len()` readable bytes.
    unsafe {
        let mut key = crate::abi::z_owned_keyexpr_t::null_value();
        let made =
            refused(|| z_keyexpr_from_substr(&mut key, text.as_ptr().cast::<c_char>(), text.len()));
        assert_eq!(made, Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert!(!z_internal_keyexpr_check(&key));
        assert_eq!(
            z_keyexpr_from_substr(&mut key, text.as_ptr().cast::<c_char>(), text.len()),
            Z_OK
        );
        let mut copy = crate::abi::z_owned_keyexpr_t::null_value();
        let copied = refused(|| z_keyexpr_clone(&mut copy, z_keyexpr_loan(&key)));
        assert_eq!(copied, Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert!(!z_internal_keyexpr_check(&copy));
        z_keyexpr_drop(z_keyexpr_move(&mut key));
    }
}

/// A counter and a channel the heap has no room for are refused. Turned red by either boxed with
/// `Box::new`.
#[test]
fn a_full_heap_is_answered_by_the_handler_doors() {
    // SAFETY: the counter's place and the collection's bytes are the test's own; the counter made
    // is let go of by its one strong count.
    unsafe {
        let mut counter: *mut c_void = core::ptr::null_mut();
        assert_eq!(
            refused(|| _z_rc_init(&mut counter)),
            Z_ERR_SYSTEM_OUT_OF_MEMORY
        );
        assert!(counter.is_null());
        assert_eq!(_z_rc_init(&mut counter), Z_OK);
        assert!(_z_rc_decrease_strong(&mut counter));
        let mut fifo = core::mem::MaybeUninit::<_z_fifo_mt_t>::zeroed();
        let installed = refused(|| crate::handlers::_z_fifo_mt_init(fifo.as_mut_ptr(), 4));
        assert_eq!(installed, Z_ERR_SYSTEM_OUT_OF_MEMORY);
    }
}

/// An encoding rendered as a string the heap has no room for is refused and the string left null;
/// with room it is rendered. Turned red by the rendering made with the encoding module's infallible
/// `parts_to_bytes`, which ends the process on the refusal.
#[test]
fn a_full_heap_is_answered_by_the_encoding_to_string_door() {
    // SAFETY: the string is the test's own; the null encoding reads as the default.
    unsafe {
        let mut string = crate::abi::z_owned_string_t::null_value();
        let rendered = refused(|| z_encoding_to_string(core::ptr::null(), &mut string));
        assert_eq!(rendered, Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert!(!z_internal_string_check(&string));
        assert_eq!(z_encoding_to_string(core::ptr::null(), &mut string), Z_OK);
        assert!(z_internal_string_check(&string));
        z_string_drop(z_string_move(&mut string));
    }
}
