// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a session allocates for its endpoints: nothing once it is open, and at its open nothing
//! for each endpoint when its source writes the texts into its rows itself. A session whose link
//! is lost dials its endpoints again with no memory of the heap: the text of each endpoint is a
//! row its open wrote, a dial names its row, and the refusal of a dial keeps the endpoint in a
//! row's length. The allocations counted are the calling thread's, the thread a cooperative
//! session's open and reads run on; the router stand-in's own are another thread's.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::tests::{host_links, PosixLinks};
use crate::LinkCount;
use wz_capi_port::SessionDrive;
use wz_runtime_coop::link_cells::CountKind;
use wz_runtime_coop::link_storage::LinkTables;
use wz_runtime_coop::session_drive::{LinkOpenError, Locator, OpenedLink, SessionLinks};
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::link_life::LinkPhase;
use wz_session_core::policy::SessionPolicy;

use super::{client_config, config, CatchAll, Command, Router, LOOPBACK};
use crate::arena::AllocatorMemory;
use crate::open_source::{Counted, EndpointTextList, OpenEndpoints, OpenInput, OpenSource};
use crate::{CoopConfig, CoopEngine, OpenError, OpenKeyIds, RowClaim};

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

/// The allocations this thread makes while `f` runs: what every test of this crate that holds a
/// path to allocate nothing after the open counts with, over this one allocator.
pub(crate) fn counted(f: impl FnOnce()) -> u64 {
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

impl SessionLinks<LinkCount> for Refusals {
    type Pump = <PosixLinks as SessionLinks<LinkCount>>::Pump;

    type Dial = <PosixLinks as SessionLinks<LinkCount>>::Dial;

    type Waits = <PosixLinks as SessionLinks<LinkCount>>::Waits;

    fn waits(&self) -> Self::Waits {
        self.inner.waits()
    }

    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<Self::Pump, LinkCount>, LinkOpenError> {
        self.inner.open_acceptor(port)
    }

    // The session's tables reach the links it dials through, as they reach the host's links.
    fn lend_buffers(&mut self, tables: LinkTables<<LinkCount as CountKind>::Flag>) {
        self.inner.lend_buffers(tables);
    }

    fn open_initiator(
        &self,
        to: Locator,
    ) -> Result<OpenedLink<Self::Pump, LinkCount>, LinkOpenError> {
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
        inner: host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
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
    // Each refusal ends a walk over the endpoints, and the life of a link that was up waits
    // `redial_ms` to walk them again; a life that ended the session would dial no more.
    assert!(
        matches!(
            engine.dial_phase(),
            Some(LinkPhase::Backoff { .. } | LinkPhase::Dialing { .. })
        ),
        "the face's life walks its endpoints again: {:?}",
        engine.dial_phase()
    );
}

/// What watches the faces of a session whose loss is counted ([`a_loss_counted`]).
#[cfg(feature = "connectivity")]
#[derive(Clone, Copy)]
enum Watching {
    Nothing,
    Rows,
    Snapshots,
}

/// The allocations of the reads that take a session's face as lost and tell it, with `watching`
/// watching the faces, and how many departures the watcher was told. Every dial after the loss is
/// refused at once, so what is counted is the loss and its telling.
#[cfg(feature = "connectivity")]
fn a_loss_counted(watching: Watching) -> (u64, usize) {
    use wz_capi_port::SessionEngine;
    use wz_session_core::face::{
        FaceEventKind, FaceEventSink, FaceLinkRow, FaceRowSink, FaceSnapshot,
    };

    let router = Router::start(CatchAll::None);
    let refusing = Arc::new(AtomicBool::new(false));
    let links = Refusals {
        inner: host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
        refusing: refusing.clone(),
        dials: Arc::new(AtomicUsize::new(0)),
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
    let downs = Arc::new(AtomicUsize::new(0));
    let into = downs.clone();
    let watched = match watching {
        Watching::Nothing => Ok(0),
        Watching::Rows => SessionEngine::watch_face_rows(
            &*engine,
            FaceRowSink::of_arc(Arc::new(move |kind: FaceEventKind, _row: &FaceLinkRow| {
                if kind == FaceEventKind::Down {
                    into.fetch_add(1, Ordering::SeqCst);
                }
            })),
        ),
        Watching::Snapshots => SessionEngine::watch_faces(
            &*engine,
            FaceEventSink::of_arc(Arc::new(
                move |kind: FaceEventKind, _face: &FaceSnapshot| {
                    if kind == FaceEventKind::Down {
                        into.fetch_add(1, Ordering::SeqCst);
                    }
                },
            )),
        ),
    };
    assert!(watched.is_ok(), "an open session watches its faces");
    assert!(
        SessionEngine::face_link_at(&*engine, 0).is_some(),
        "the session stands on a face"
    );

    refusing.store(true, Ordering::SeqCst);
    router.send(Command::Close);
    drop(router);
    let until = Instant::now() + Duration::from_secs(5);
    let allocations = counted(|| {
        while SessionEngine::face_link_at(&*engine, 0).is_some() && Instant::now() < until {
            let _ = SessionDrive::read(&*engine, false);
        }
    });
    assert!(
        SessionEngine::face_link_at(&*engine, 0).is_none(),
        "the face was not lost"
    );
    (allocations, downs.load(Ordering::SeqCst))
}

/// A face lost while its rows are watched is told with no memory of the heap: its rows are
/// written in place under the session's lock, queued in the rows the watch reserved, and handed to
/// each watcher one at a time with no list of them made. The loss with nothing watching is counted
/// first, so a red names what allocates.
///
/// # Control
///
/// A watcher of snapshots, which is told a snapshot made of the same rows, allocates it, and the
/// count sees it.
#[cfg(feature = "connectivity")]
#[test]
fn a_face_lost_is_told_to_a_watcher_of_its_rows_with_nothing_allocated() {
    assert_eq!(
        a_loss_counted(Watching::Nothing),
        (0, 0),
        "the loss itself takes no memory of the heap"
    );
    assert_eq!(
        a_loss_counted(Watching::Rows),
        (0, 1),
        "the loss is told once to the watcher of the rows, with nothing allocated"
    );
    let (snapshots, told) = a_loss_counted(Watching::Snapshots);
    assert_eq!(
        told, 1,
        "CONTROL: the watcher of snapshots is told the loss once"
    );
    assert!(
        snapshots > 0,
        "CONTROL: a snapshot of the face lost takes memory of the heap"
    );
}

/// A session watched only after its open, whose faces turn over past the rows its queue holds
/// between two deliveries, tells its watcher the rows it kept and, once, how many it lost, with no
/// memory of the heap: the rows lie in the plane placed at the open, and a row past them is
/// counted on the last row kept rather than grown into. The watch takes a row of the plane's table
/// of watchers and nothing of the heap. Turned red by a watch that allocates its entry or the
/// queue's rows, by a queue that grows past its room (an allocation, and every row told), or by a
/// loss told with no row or with two.
#[cfg(feature = "connectivity")]
#[test]
fn rows_past_the_room_of_a_session_watched_after_its_open_are_told_lost_with_nothing_allocated() {
    use wz_capi_port::SessionEngine;
    use wz_session_core::caps;
    use wz_session_core::face::{FaceEventKind, FaceLinkRow, FaceRowSink, LentEnd, RowEnds};

    let router = Router::start(CatchAll::None);
    let engine = CoopEngine::open(
        host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        PosixEntropy,
        config(&router),
    )
    .expect("the session opens");
    let plane = engine.face_plane();
    let room = plane.room();
    assert!(
        (1..=caps::MAX_FACE_WATCH_ROWS).contains(&room),
        "the queue holds at least one row and no more than the build's: {room}"
    );

    let told = Arc::new(AtomicUsize::new(0));
    let losses = Arc::new(AtomicUsize::new(0));
    let lost = Arc::new(AtomicUsize::new(0));
    let sink = {
        let (told, losses, lost) = (told.clone(), losses.clone(), lost.clone());
        FaceRowSink::of_arc(Arc::new(move |_kind: FaceEventKind, row: &FaceLinkRow| {
            told.fetch_add(1, Ordering::SeqCst);
            if row.lost_after > 0 {
                losses.fetch_add(1, Ordering::SeqCst);
                lost.fetch_add(row.lost_after, Ordering::SeqCst);
            }
        }))
    };
    let watching = counted(|| {
        assert!(
            SessionEngine::watch_face_rows(&*engine, sink).is_ok(),
            "an open session watches its faces"
        );
    });
    assert_eq!(
        watching, 0,
        "the watch takes a row of the plane's table of watchers and nothing of the heap"
    );

    let row = |first: u8| FaceLinkRow {
        zid: [first; 16],
        whatami: 1,
        is_qos: false,
        is_multicast: false,
        is_shm: false,
        link: 0,
        links: 1,
        ends: RowEnds::Lent {
            kind: wz_session_core::link::LinkKind::Tcp,
            src: LentEnd::Ip(core::net::SocketAddr::from(([127, 0, 0, 1], 1))),
            dst: LentEnd::Ip(core::net::SocketAddr::from(([127, 0, 0, 1], 2))),
        },
        kind: None,
        mtu: 0,
        group_endpoint: None,
        lost_after: 0,
    };
    let past = 3;
    let rows: Vec<FaceLinkRow> = (0..room + past).map(|_| row(1)).collect();
    let allocations = counted(|| {
        for made in rows {
            plane.happened(FaceEventKind::Up, made);
        }
        while plane.hand_out_next() {}
    });
    assert_eq!(
        allocations, 0,
        "rows past the queue's room take no memory of the heap"
    );
    assert_eq!(told.load(Ordering::SeqCst), room, "the rows kept are told");
    assert_eq!(
        (losses.load(Ordering::SeqCst), lost.load(Ordering::SeqCst)),
        (1, past),
        "the rows lost are told once, with the last row kept"
    );

    plane.happened(FaceEventKind::Down, row(0));
    assert!(plane.hand_out_next());
    assert_eq!(
        (told.load(Ordering::SeqCst), losses.load(Ordering::SeqCst)),
        (room + 1, 1),
        "a row queued once there is room again tells no loss"
    );
}

/// A session built without the connectivity plane tells no face, so a watch of the faces' rows is
/// refused with `Refusal::NotBuilt`, with nothing of the heap taken and the sink let go of with the refusal.
/// Turned red by an engine that answers through the provided watch, which takes a place of the
/// heap for the watcher before it is refused.
#[cfg(not(feature = "connectivity"))]
#[test]
fn a_watch_of_face_rows_without_the_plane_is_refused_with_nothing_allocated() {
    use wz_capi_port::{Refusal, SessionEngine};
    use wz_session_core::face::{FaceEventKind, FaceLinkRow, FaceRowSink};

    let router = Router::start(CatchAll::None);
    let engine = CoopEngine::open(
        host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        PosixEntropy,
        config(&router),
    )
    .expect("the session opens");
    let watcher = Arc::new(|_: FaceEventKind, _: &FaceLinkRow| {});
    let held = Arc::downgrade(&watcher);
    let sink = FaceRowSink::of_arc(watcher);
    let mut answer = None;
    let watching = counted(|| answer = Some(SessionEngine::watch_face_rows(&*engine, sink)));
    assert_eq!(answer, Some(Err(Refusal::NotBuilt)));
    assert_eq!(watching, 0, "a refused watch takes nothing of the heap");
    assert!(held.upgrade().is_none(), "the refused sink is let go of");
}

/// A session reserves two rows for each face it may hold, its going and its coming back, its
/// groups' members among them, and never more than the build's rows. Turned red by a session that
/// reserves the build's rows whatever it holds, or one past them for a session of many faces.
#[cfg(feature = "connectivity")]
#[test]
fn a_session_reserves_the_rows_its_faces_turn_over_in_up_to_the_builds() {
    use crate::engine::face_event_rows;
    use wz_session_core::caps;

    let most = caps::MAX_FACE_WATCH_ROWS;
    assert_eq!(
        face_event_rows(0, 0),
        most.min(2),
        "the dial role's face, going and coming back"
    );
    assert_eq!(
        face_event_rows(0, 1),
        most.min(2 * (1 + caps::MAX_GROUP_MEMBERS)),
        "each member of a group is a face"
    );
    assert_eq!(
        face_event_rows(usize::MAX, 1),
        most,
        "no more than the build's rows"
    );
}

/// A source whose config counts its endpoints and whose texts are `'static`: what an ABI that
/// keeps its texts in a form of its own hands an open.
struct Written {
    config: CoopConfig<Counted>,
    dial: &'static [&'static str],
}

impl OpenSource for Written {
    fn open_with<R>(self, open: impl FnOnce(OpenInput<'_>) -> R) -> R {
        open(OpenInput {
            config: self.config,
            endpoints: OpenEndpoints {
                dial: EndpointTextList {
                    views: self.dial,
                    strings: &[],
                },
                ..OpenEndpoints::NONE
            },
        })
    }
}

/// Endpoints of the loopback no session here reaches: every dial of them is refused.
const ONE: &[&str] = &["tcp/127.0.0.1:1"];
const THREE: &[&str] = &["tcp/127.0.0.1:1", "tcp/127.0.0.1:2", "tcp/127.0.0.1:3"];

/// Links whose every dial is refused at once.
fn refusing() -> Refusals {
    Refusals {
        inner: host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
        refusing: Arc::new(AtomicBool::new(true)),
        dials: Arc::new(AtomicUsize::new(0)),
    }
}

/// The allocations of an open from `source` whose dials are all refused, and that it was refused
/// as unreachable, less the row of the heap its claim took, if it took one. The process's table of
/// engines takes that row only when no row it kept is vacant, which the opens of every test of the
/// process decide, and keeps it for the next open, so it is no allocation of what the open was
/// asked.
fn open_counted(source: impl OpenSource) -> u64 {
    let mut refused = None;
    let rows_before = RowClaim::rows_taken_here();
    let allocations = counted(|| {
        refused = CoopEngine::open_made_in(
            refusing(),
            PosixClock,
            PosixEntropy,
            source,
            SessionPolicy::defaults(),
            OpenKeyIds::none(),
            crate::arena::OpenStorage {
                memory: &AllocatorMemory,
                plan: crate::arena::PlanFrom::Config(&crate::arena::HeldPlaces::NONE),
            },
        )
        .err();
    });
    let rows = RowClaim::rows_taken_here() - rows_before;
    assert!(
        matches!(refused, Some(OpenError::Unreachable(_))),
        "every dial is refused: {refused:?}"
    );
    assert!(
        rows <= 1,
        "an open claims one row: {rows} taken of the heap"
    );
    allocations
        .checked_sub(rows)
        .expect("the row taken of the heap is one of the allocations counted")
}

/// An open whose source writes its endpoints' texts into the session's rows itself allocates as
/// much for three endpoints as for one: no text of an endpoint is a value of the heap at the open.
/// The CONTROL is the host's form, whose config holds a text of the heap for each endpoint: there
/// three endpoints allocate more than one, so the count sees an endpoint's text where it is one.
/// Turned red by a text of an endpoint made a value of the heap at the open, or by the row of the
/// heap the process's table takes counted as the open's own (`rows_taken_here` in
/// `open_counted`): on the heap policy, run alone, the test's first open takes the process's first
/// row and counts one more than the open after it.
#[test]
fn an_open_whose_source_writes_the_texts_allocates_nothing_for_each_endpoint() {
    let written = |dial: &'static [&'static str]| Written {
        config: CoopConfig {
            endpoints: dial.iter().map(|text| (*text).to_owned()).collect(),
            ..client_config()
        }
        .counted()
        .0,
        dial,
    };
    let (one, three) = (written(ONE), written(THREE));
    assert_eq!(
        open_counted(one),
        open_counted(three),
        "the source's texts take no memory of the heap at the open"
    );
    let host = |dial: &'static [&'static str]| {
        move || CoopConfig {
            endpoints: dial.iter().map(|text| (*text).to_owned()).collect(),
            ..client_config()
        }
    };
    assert!(
        open_counted(host(ONE)) < open_counted(host(THREE)),
        "CONTROL: a config that holds the texts allocates one for each endpoint"
    );
}

/// Links without a resolver refuse a host name before any dial, by the locator's reason, so the
/// open reports what the build lacks and not a link the other end refused; the links are never
/// asked. Turned red by a name over links without a resolver dialled, or refused as a link.
#[test]
fn links_without_a_resolver_refuse_a_host_name_before_any_dial() {
    use crate::{EndpointRefusal, Refusal};
    use wz_runtime_coop::locator_text::DialRefused;

    // Asked through a function, as the transport asks it of the links it is generic over.
    fn resolves<L: SessionLinks<LinkCount>>() -> bool {
        L::RESOLVES
    }

    let dials = Arc::new(AtomicUsize::new(0));
    let links = Refusals {
        inner: host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
        refusing: Arc::new(AtomicBool::new(true)),
        dials: dials.clone(),
    };
    assert!(!resolves::<Refusals>(), "these links have no resolver");
    let endpoint = "tcp/router.example:7447";
    let refused = CoopEngine::open(
        links,
        PosixClock,
        PosixEntropy,
        CoopConfig {
            endpoints: vec![endpoint.into()],
            ..client_config()
        },
    )
    .err();
    assert_eq!(
        refused,
        Some(OpenError::Unreachable(EndpointRefusal::new(
            endpoint,
            Refusal::Locator(DialRefused::NoResolver)
        )))
    );
    assert_eq!(dials.load(Ordering::SeqCst), 0, "no dial was asked");
}
