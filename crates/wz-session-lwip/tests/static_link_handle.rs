// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What it costs the heap to hold the lwIP stack on the `session-slot` profile
//! (fixed-memory step S9c).
//!
//! A node's links, its session host and its listener all reach the stack through a
//! handle, and until this step the handle the shell made was an `Rc<LwipLink>`: one
//! small allocation at startup, and a `use alloc::rc::Rc` that kept `extern crate
//! alloc` in the crate under the slot profile. The handle is `&'static LwipLink`
//! there now (`LwipLink::init_static`, which brings lwIP up and hands back a
//! zero-sized `static`), and the crate does not link `alloc` at all under the
//! selector, so a use that crept back would not compile.
//!
//! Two windows, one counting `#[global_allocator]`:
//!
//! - the `&'static` handle, which must cost the heap nothing, and is the same
//!   reference every time (there is one stack);
//! - an `Rc` of a zero-sized handle, which is what the other profiles hold and the
//!   instrument's control: a count that read zero on the form known to allocate
//!   would prove nothing about the form meant not to.
//!
//! This file never uses the host harness's `lwip_test_link`: that brings lwIP up
//! once on its own, and `init_static` is the only thing here that does.

use std::rc::Rc;

use wz_link_lwip::LwipLink;
use wz_session_lwip::links::StackHandle;
use wz_session_lwip::LwipLinks;

#[path = "support/alloc_count.rs"]
mod alloc_count;
use alloc_count::Measurement;

#[global_allocator]
static GLOBAL: alloc_count::CountingAllocator = alloc_count::CountingAllocator;

/// The stack handle of the slot profile is a reference to a `static`, and making it
/// costs the heap nothing; asking twice gives the one stack.
#[test]
fn the_static_stack_handle_costs_the_heap_nothing_and_is_one_stack() {
    let m = Measurement::new();

    let ((first, second), n) = m.count("init_static", || {
        (LwipLink::init_static(), LwipLink::init_static())
    });
    assert_eq!(n, 0, "bringing the stack up as a static handle allocates 0");
    assert!(
        std::ptr::eq(first, second),
        "there is one stack and so one handle to it"
    );

    // The handle is the type the slot profile's links hold by default, and a links
    // value over it is made without a heap too.
    let _typed: StackHandle = first;
    let (links, n) = m.count("links over the handle", || links_over(first));
    assert_eq!(n, 0, "a links value over the static handle allocates 0");
    assert!(std::ptr::eq(*links.link(), first), "it holds that handle");
}

/// The control: a reference count around a handle that holds nothing costs the heap
/// one box, which is what the `Rc<LwipLink>` of the heap profiles cost and what the
/// `static` form removes.
#[test]
fn an_rc_around_a_zero_sized_handle_costs_one_allocation() {
    struct Handle;
    let m = Measurement::new();
    let (_held, n) = m.count("an Rc of a handle", || Rc::new(Handle));
    assert_eq!(n, 1, "the instrument sees the form that allocates");
}

/// A links value over `handle`; on `static-link-storage` its sockets are a pool of
/// one cell, declared where a firmware would declare it.
fn links_over(handle: &'static LwipLink) -> LwipLinks<&'static LwipLink> {
    #[cfg(feature = "static-link-storage")]
    {
        static SOCKETS: wz_link_lwip::rx_sockets::SessionRxPool<1> =
            wz_link_lwip::rx_sockets::SessionRxPool::new();
        LwipLinks::new(handle, &SOCKETS)
    }
    #[cfg(not(feature = "static-link-storage"))]
    {
        LwipLinks::new(handle)
    }
}
