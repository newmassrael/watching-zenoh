// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A socket whose state the heap has no room for, met as a refusal and not as the end of the
//! program: a bind and a connect answer an error before any pcb is taken, and a connection that
//! arrives at a listener is refused and counted as one the queue has no room for. The heap is made
//! full for the calling thread by this executable's own allocator, which is why the file is an
//! executable of its own. The heap shape only: with `static-link-storage` a socket's state is a
//! cell of a pool, whose refusals `link_storage_allocations` witnesses.
#![cfg(not(feature = "static-link-storage"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use wz_link_lwip::{lwip_test_link, LinkError, LwipUdpSocket};

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

/// A bind the heap has no room for is refused before a pcb is bound, so the port is free for the
/// bind that follows. Turned red by `Inner::try_boxed` answering the refusal with
/// `handle_alloc_error`, which ends the process.
#[test]
fn a_bind_the_heap_has_no_room_for_is_refused_and_binds_nothing() {
    let (_gate, link) = lwip_test_link();
    let bound = refused(|| LwipUdpSocket::<256, 4>::bind(&link, 47_601));
    assert!(matches!(bound, Err(LinkError::HeapRefused)));
    assert!(
        LwipUdpSocket::<256, 4>::bind(&link, 47_601).is_ok(),
        "the refused bind took no pcb and held no port"
    );
}

#[cfg(feature = "tcp")]
mod tcp {
    use super::refused;
    use wz_link_lwip::lwip_test_link;
    use wz_link_lwip::tcp::{LwipTcpListener, LwipTcpSocket, TcpError};
    use wz_link_lwip::LwipLink;

    /// Above the window of the host port, as the crate's own TCP tests size it.
    const RX: usize = 4096;

    fn pump(link: &LwipLink) {
        link.poll_loopback();
        link.check_timeouts();
    }

    /// A connect the heap has no room for is refused, nothing made. Turned red by
    /// `try_boxed_inner` answering the refusal with `handle_alloc_error`.
    #[test]
    fn a_connect_the_heap_has_no_room_for_is_refused() {
        let (_gate, link) = lwip_test_link();
        let made = refused(|| LwipTcpSocket::<RX>::connect(&link, [127, 0, 0, 1], 47_602));
        assert!(matches!(made, Err(TcpError::HeapRefused)));
    }

    /// A connection that arrives when the heap has no room for its state is refused and counted,
    /// and nothing waits to be taken. lwIP is polled with the heap refused, so the accept callback
    /// meets the refusal; the dialler was made before. Turned red by the listener's `make_inner`
    /// ending the process on the refusal, or by it not counting the refusal.
    #[test]
    fn an_arrival_the_heap_has_no_room_for_is_refused_and_counted() {
        static LISTENER: LwipTcpListener<RX, 2> = LwipTcpListener::new();
        let (_gate, link) = lwip_test_link();
        LISTENER.listen(47_603).expect("the port is free");
        let client = LwipTcpSocket::<RX>::connect(&link, [127, 0, 0, 1], 47_603)
            .expect("the heap has room for the dialler");
        for _ in 0..4_000 {
            refused(|| pump(&link));
            if LISTENER.refused() == 1 {
                break;
            }
        }
        assert_eq!(LISTENER.refused(), 1);
        assert_eq!(LISTENER.waiting(), 0);
        drop(client);
    }
}
