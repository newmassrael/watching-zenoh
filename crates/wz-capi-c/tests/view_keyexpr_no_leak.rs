// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A view keyexpr leaves nothing behind.
//!
//! zenoh-c's view family has no release call: `z_view_keyexpr_t` is a plain struct that
//! the C caller stack-allocates and drops by leaving scope. The drop-in used to keep an
//! owned copy of the string on the heap behind the view's handle, which nothing could free,
//! so every call leaked it: an address-sanitizer sweep of a consumer found 56 bytes per call.
//!
//! This counts the bytes this thread has allocated and not freed, across thousands of views
//! of each of the four constructors, and requires the count not to move. The counter is
//! per thread, so the test harness's own allocations on other threads cannot disturb it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use wz_capi_c::abi::z_view_keyexpr_t;
use wz_capi_c::keyexpr::{
    z_view_keyexpr_from_str, z_view_keyexpr_from_str_unchecked, z_view_keyexpr_from_substr,
    z_view_keyexpr_from_substr_unchecked,
};
use wz_capi_c::result::Z_OK;

thread_local! {
    /// Bytes allocated by this thread and not yet freed. `const`-initialised, so reading it
    /// never allocates.
    static OUTSTANDING: Cell<isize> = const { Cell::new(0) };
}

struct Counting;

// SAFETY: every call is forwarded to the system allocator unchanged; the counter only
// observes the sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = OUTSTANDING.try_with(|c| c.set(c.get() + layout.size() as isize));
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = OUTSTANDING.try_with(|c| c.set(c.get() - layout.size() as isize));
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ =
            OUTSTANDING.try_with(|c| c.set(c.get() + new_size as isize - layout.size() as isize));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn outstanding() -> isize {
    OUTSTANDING.with(Cell::get)
}

/// One round of all four constructors over a string that outlives the views.
fn one_round(text: &std::ffi::CStr) {
    // SAFETY: a zeroed view is this ABI's gravestone, `text` is a live C string and `view` a
    // live local, for every call.
    unsafe {
        let mut view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut view, text.as_ptr()), Z_OK);
        z_view_keyexpr_from_str_unchecked(&mut view, text.as_ptr());
        assert_eq!(
            z_view_keyexpr_from_substr(&mut view, text.as_ptr(), text.to_bytes().len()),
            Z_OK
        );
        z_view_keyexpr_from_substr_unchecked(&mut view, text.as_ptr(), text.to_bytes().len());
    }
}

#[test]
fn views_leave_no_memory_that_nothing_can_release() {
    let text = c"demo/example/a/b/c";
    // The first round may initialise lazy state of the library (a once-only table, a
    // thread's guard); what is measured is the growth after it.
    one_round(text);
    let before = outstanding();
    for _ in 0..10_000 {
        one_round(text);
    }
    let after = outstanding();
    assert_eq!(
        after - before,
        0,
        "{} bytes are still allocated after 40000 views: a view must own nothing",
        after - before
    );
}
