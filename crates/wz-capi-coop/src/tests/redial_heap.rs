// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A session whose link is lost dials its endpoints again with no memory of the heap: the text of
//! each endpoint is a row its open wrote, a dial names its row, and the refusal of a dial keeps
//! the endpoint in a row's length. The allocations counted are the calling thread's, the thread a
//! cooperative session's reads run on; the router stand-in's own are another thread's.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_port::SessionDrive;
use wz_runtime_coop::link_storage::LinkTables;
use wz_runtime_coop::session_drive::{LinkOpenError, Locator, OpenedLink, SessionLinks};
use wz_runtime_posix::links::PosixLinks;
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::{PosixClock, PosixEntropy};

use super::{config, CatchAll, Command, Router, LOOPBACK};
use crate::{CoopConfig, CoopEngine};

thread_local! {
    /// Whether the thread's allocations are being counted.
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    /// The thread's allocations counted.
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

/// The system's allocator, which counts the allocations of a thread that asks it to
/// ([`counted`]).
struct Counting;

impl Counting {
    /// Count one allocation, on a thread that counts.
    fn note() {
        let _ = COUNTING.try_with(|on| {
            if on.get() {
                let _ = ALLOCATIONS.try_with(|count| count.set(count.get().saturating_add(1)));
            }
        });
    }
}

// SAFETY: every call is the system allocator's, with the caller's arguments; counting touches a
// thread's own cells and allocates nothing.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        Self::note();
        // SAFETY: the caller's contract of `GlobalAlloc::alloc`, handed on.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        Self::note();
        // SAFETY: the caller's contract of `GlobalAlloc::alloc_zeroed`, handed on.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        Self::note();
        // SAFETY: the caller's contract of `GlobalAlloc::realloc`, handed on.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract of `GlobalAlloc::dealloc`, handed on.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The allocations this thread makes while `f` runs.
fn counted(f: impl FnOnce()) -> u64 {
    ALLOCATIONS.with(|count| count.set(0));
    COUNTING.with(|on| on.set(true));
    f();
    COUNTING.with(|on| on.set(false));
    ALLOCATIONS.with(Cell::get)
}

/// The host's links, whose dials, once `refusing` is set, are each refused at once, and counted.
struct Refusals {
    inner: PosixLinks,
    refusing: Arc<AtomicBool>,
    dials: Arc<AtomicUsize>,
}

impl SessionLinks for Refusals {
    type Pump = <PosixLinks as SessionLinks>::Pump;

    type Dial = <PosixLinks as SessionLinks>::Dial;

    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        self.inner.open_acceptor(port)
    }

    // The session's tables reach the links it dials through, as they reach the host's links.
    fn lend_buffers(&mut self, tables: LinkTables) {
        self.inner.lend_buffers(tables);
    }

    fn open_initiator(&self, to: Locator) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        if !self.refusing.load(Ordering::SeqCst) {
            return self.inner.open_initiator(to);
        }
        self.dials.fetch_add(1, Ordering::SeqCst);
        Err(LinkOpenError::Refused)
    }
}

/// A session whose link was lost, and whose every dial of its endpoint is refused, dials it again
/// read after read and allocates nothing doing so. The CONTROL is the dials counted while the
/// allocations are: the reads dialled again.
#[test]
fn a_session_that_dials_its_lost_link_again_allocates_nothing() {
    let router = Router::start(CatchAll::None);
    let refusing = Arc::new(AtomicBool::new(false));
    let dials = Arc::new(AtomicUsize::new(0));
    let links = Refusals {
        inner: PosixLinks::new(LOOPBACK, PosixTcpDial).waited_by_owner(),
        refusing: refusing.clone(),
        dials: dials.clone(),
    };
    let engine = CoopEngine::open(
        links,
        PosixClock,
        PosixEntropy,
        CoopConfig {
            redial_ms: Some(0),
            ..config(&router)
        },
    )
    .expect("the session opens");

    refusing.store(true, Ordering::SeqCst);
    router.send(Command::Close);
    drop(router);
    // The loss is told and the first rounds are dialled before anything is counted: what the
    // loss itself lets go of and tells is not a dial.
    let until = Instant::now() + Duration::from_secs(5);
    while dials.load(Ordering::SeqCst) < 3 {
        assert!(
            Instant::now() < until,
            "the lost link was not dialled again"
        );
        let _ = SessionDrive::read(&*engine, false);
    }
    let before = dials.load(Ordering::SeqCst);
    let allocations = counted(|| {
        for _ in 0..20 {
            let _ = SessionDrive::read(&*engine, false);
        }
    });
    assert!(
        dials.load(Ordering::SeqCst) > before,
        "CONTROL: the reads dialled the endpoint again"
    );
    assert_eq!(
        allocations, 0,
        "a dial again of a lost link takes no memory of the heap"
    );
}
