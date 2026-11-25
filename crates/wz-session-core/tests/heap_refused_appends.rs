// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The heap texts and byte buffers a door appends to, met by a full heap: each append is refused
//! and leaves what it appended to as it was, where an append that grows a `Vec` the infallible way
//! would end the program. The heap is made full for the calling thread by this executable's own
//! allocator, which refuses every allocation of a thread that asks, which is why the file is an
//! executable of its own.
#![cfg(feature = "alloc")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use wz_session_core::bounded::{
    heap_copy, push_heap_bytes, push_heap_text, CapacityFull, TextBacking,
};
use wz_session_core::keyexpr_canon::{check_outbound_keyexpr_pico_safe, OutboundKeyexprError};

thread_local! {
    /// Whether every allocation this thread asks for is refused.
    static REFUSING: Cell<bool> = const { Cell::new(false) };
}

/// The system's allocator, refusing every allocation of a thread inside [`refused`].
struct RefusingAllocator;

// SAFETY: every call is the system allocator's, with the arguments it was given, or a refusal
// (null), which hands out no memory.
unsafe impl GlobalAlloc for RefusingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if REFUSING.try_with(Cell::get).unwrap_or(false) {
            return std::ptr::null_mut();
        }
        // SAFETY: the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, at: *mut u8, layout: Layout) {
        // SAFETY: the caller's.
        unsafe { System.dealloc(at, layout) }
    }
}

#[global_allocator]
static GLOBAL: RefusingAllocator = RefusingAllocator;

/// `run`'s answer, every allocation of the calling thread refused while it runs.
fn refused<R>(run: impl FnOnce() -> R) -> R {
    REFUSING.with(|refusing| refusing.set(true));
    let answer = run();
    REFUSING.with(|refusing| refusing.set(false));
    answer
}

/// An append the heap has no room for is refused with the buffer as it was, and one it has room
/// for appends every byte; an empty append asks for no room. Turned red by `push_heap_bytes`
/// growing with `extend_from_slice`, which ends the process on the refusal.
#[test]
fn a_byte_append_the_heap_refuses_leaves_the_buffer_as_it_was() {
    let mut bytes = Vec::new();
    assert!(push_heap_bytes(&mut bytes, b"ab").is_ok());
    bytes.shrink_to_fit();
    assert!(refused(|| push_heap_bytes(&mut bytes, b"cdef")).is_err());
    assert_eq!(bytes, b"ab");
    assert!(refused(|| push_heap_bytes(&mut bytes, b"")).is_ok());
    assert!(push_heap_bytes(&mut bytes, b"cd").is_ok());
    assert_eq!(bytes, b"abcd");
}

/// A copy the heap has no room for is none, and an empty one takes no room. Turned red by
/// `heap_copy` made with `to_vec`.
#[test]
fn a_copy_the_heap_refuses_is_none() {
    assert_eq!(refused(|| heap_copy(b"schema")), None);
    assert_eq!(refused(|| heap_copy(b"")), Some(Vec::new()));
    assert_eq!(heap_copy(b"schema"), Some(b"schema".to_vec()));
}

/// A heap text refuses a text and a character the heap has no room for, the text as it was,
/// through its own append and through the backing a bounded string keeps. Turned red by the
/// `String` backing appending with `String::push_str` or `String::push`.
#[test]
fn a_heap_text_refuses_what_the_heap_has_no_room_for() {
    let mut text = String::new();
    assert!(push_heap_text(&mut text, "key").is_ok());
    text.shrink_to_fit();
    assert!(refused(|| push_heap_text(&mut text, "/expr")).is_err());
    assert!(refused(|| TextBacking::push_str(&mut text, "/expr")).is_err());
    assert_eq!(
        refused(|| TextBacking::push(&mut text, '/')).map_err(|CapacityFull(c)| c),
        Err('/'),
        "the refused character is handed back"
    );
    assert_eq!(text, "key");
    assert!(TextBacking::push(&mut text, 'é').is_ok());
    assert!(TextBacking::push_str(&mut text, "/x").is_ok());
    assert_eq!(text, "keyé/x");
}

/// A keyexpr that would end a zenoh-pico peer is refused whatever the heap holds: with room, the
/// refusal quotes it; with none, it quotes nothing. Turned red by the quote made with
/// `to_string`, which ends the process on the refusal.
#[test]
fn a_refused_keyexpr_is_refused_on_a_full_heap_with_no_quote() {
    match check_outbound_keyexpr_pico_safe("**/c/*") {
        Err(OutboundKeyexprError::PicoBugThreeFamily {
            keyexpr,
            offending_chunk,
        }) => {
            assert_eq!(keyexpr, "**/c/*");
            assert_eq!(offending_chunk, "*");
        }
        other => panic!("CONTROL: refused with the quote, got {other:?}"),
    }
    match refused(|| check_outbound_keyexpr_pico_safe("**/c/*")) {
        Err(OutboundKeyexprError::PicoBugThreeFamily {
            keyexpr,
            offending_chunk,
        }) => {
            assert!(keyexpr.is_empty() && offending_chunk.is_empty());
        }
        other => panic!("refused with no quote, got {other:?}"),
    }
    assert_eq!(
        refused(|| check_outbound_keyexpr_pico_safe("home/temp")),
        Ok(())
    );
}
