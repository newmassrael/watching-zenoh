// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The tables a session's runtime reserves when it opens (`RuntimeTables`): a task cell for each
//! link the config admits, in the bytes a link's session task takes, held with the groups' cells to
//! the build's `MAX_TASKS`; and the deadlines a task of the build that sleeps places
//! (`RUNTIME_TIMERS`): none in a build none of whose tasks sleeps.
//!
//! The clock the tables are for is the simulated world's (`tests::sim`): what a cell holds of a
//! clock is its type's, and the runtimes made here read it only at the test's reading.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use wz_runtime_coop::executor::SpawnRefusal;
use wz_runtime_coop::{CoopLocalSet, CoopRuntime};
use wz_session_core::caps;

use super::client_config;
use super::sim::SetClock;
use crate::arena::{AllocatorMemory, ArenaPlan, SessionArena};
use crate::engine::{link_task_bytes, read_wait_room, RuntimeTables, RUNTIME_TIMERS};
use crate::CoopConfig;

/// The runtime `tables` are for, placed as an open places it: in a span of an arena that holds
/// that span alone, which the runtime keeps until its last holder lets go, with the set of the
/// session's tasks it runs.
fn placed_runtime(tables: RuntimeTables) -> (CoopRuntime<SetClock>, CoopLocalSet<SetClock>) {
    let bytes = tables
        .placed_bytes::<SetClock>()
        .expect("a span of the tables' rows");
    let mut plan = ArenaPlan::vacant();
    plan.holding_runtime(bytes).expect("the span fits");
    let mut arena = SessionArena::reserve(&plan, &AllocatorMemory).expect("the host has it");
    let place = arena.runtime_place(bytes).expect("the plan holds the span");
    tables
        .runtime(SetClock(Arc::new(AtomicU64::new(0))), place)
        .expect("the span fits the runtime")
}

/// A read's waits are reserved at the open for every link the session may wait on at once: each
/// face's (the dial role's and each `max_faces` admits), each port's, each group's and the
/// clock's word beside them, so a face accepted after the open grows nothing. Turned red by a
/// room that leaves out the faces past the dial role's, which the first wait over them grows.
#[test]
fn a_reads_waits_are_reserved_for_every_face_the_session_admits() {
    let client = CoopConfig {
        max_faces: 0,
        ..client_config()
    };
    assert_eq!(
        read_wait_room(&client),
        2,
        "the dial role's link and the clock's word"
    );
    let listener = CoopConfig {
        listen: vec!["tcp/127.0.0.1:0".to_owned(), "udp/127.0.0.1:0".to_owned()],
        max_faces: 3,
        ..client_config()
    };
    assert_eq!(
        read_wait_room(&listener),
        1 + 3 + 2 + 1,
        "four faces, two ports and the clock's word"
    );
}

/// A client that attaches no face holds the one link it dials, and its runtime one cell for that
/// link's session, of the bytes the session's task takes.
#[test]
fn a_client_reserves_one_cell_for_the_link_it_dials() {
    let tables = RuntimeTables::of::<SetClock>(&CoopConfig {
        max_faces: 0,
        ..client_config()
    });
    assert_eq!(tables.rows.tasks, caps::MAX_TASKS.min(1));
    assert_eq!(tables.groups, 0, "the config joins no group");
    assert_eq!(tables.rows.task_bytes, link_task_bytes::<SetClock>());
    assert!(tables.rows.task_bytes > 0, "a session's task has bytes");
    assert_eq!(tables.rows.timers, RUNTIME_TIMERS);
}

/// The timer table a session's runtime reserves is the build's `MAX_TIMERS` entries only where a
/// feature spawns a task that sleeps on the runtime, and none otherwise: a session keeps its own
/// deadlines, so a table no task places a deadline in is not reserved.
///
/// # Control
///
/// A runtime made of a hand count of timers, the build's `MAX_TIMERS` in a build none of whose
/// tasks sleeps, reds the capacity of its table.
#[test]
fn a_sessions_runtime_reserves_timers_only_for_a_task_that_sleeps() {
    let tables = RuntimeTables::of::<SetClock>(&CoopConfig {
        max_faces: 0,
        ..client_config()
    });
    let (runtime, _set) = placed_runtime(tables);
    assert_eq!(runtime.timers().capacity(), RUNTIME_TIMERS);
    assert_eq!(runtime.timers().next_deadline_us(), None);
    assert_eq!(
        RUNTIME_TIMERS, 0,
        "no feature of this engine spawns a task that sleeps"
    );
}

/// A listener reserves a cell for each face it admits, a link in its handshake among them, and for
/// the dial role's link only when it dials; a link past them is closed before it has a task, so a
/// handshake it holds takes no cell of its own.
#[test]
fn a_listener_reserves_a_cell_for_each_face_it_admits() {
    let listener = |endpoints: Vec<String>| CoopConfig {
        endpoints,
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        max_faces: 3,
        accept_pending: 2,
        ..client_config()
    };
    let tables = RuntimeTables::of::<SetClock>(&listener(Vec::new()));
    assert_eq!(tables.rows.tasks, caps::MAX_TASKS.min(3));
    let tables = RuntimeTables::of::<SetClock>(&listener(vec!["tcp/127.0.0.1:7447".to_owned()]));
    assert_eq!(tables.rows.tasks, caps::MAX_TASKS.min(1 + 3));
}

/// A session that listens with the peers zenoh-pico takes (its ten, `Z_LISTEN_MAX_CONNECTION_NB`)
/// runs a task for each: ten cells, and the eighth to the tenth session are spawned as the first
/// is; one that also dials has a cell for its dial beside them. Only a link past the faces it
/// admits finds no cell. A build that takes faces, whose runtime is one of many cells.
#[cfg(any(feature = "listen", feature = "group"))]
#[test]
fn a_listener_with_the_ten_peers_pico_takes_runs_a_task_for_each() {
    let tables = RuntimeTables::of::<SetClock>(&CoopConfig {
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        max_faces: 10,
        accept_pending: 1,
        ..client_config()
    });
    assert_eq!(tables.rows.tasks, 10, "the ten faces, and no dial");
    let dialling = RuntimeTables::of::<SetClock>(&CoopConfig {
        endpoints: vec!["tcp/127.0.0.1:7447".to_owned()],
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        max_faces: 10,
        accept_pending: 1,
        ..client_config()
    });
    assert_eq!(dialling.rows.tasks, 11, "the dial role's and ten faces");
    let (runtime, _set) = placed_runtime(tables);
    let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
    let sessions: Vec<_> = (0..10u8)
        .map(|at| {
            local
                .try_spawn_local(async move { at })
                .unwrap_or_else(|_| panic!("the session of link {at} has a cell"))
        })
        .collect();
    assert!(
        matches!(
            local
                .try_spawn_local(async { 0u8 })
                .map(|_| ())
                .map_err(|refused| refused.why),
            Err(SpawnRefusal::NoTaskCell)
        ),
        "a link past the faces finds no cell"
    );
    drop(sessions);
}

/// A build that takes no face beside its dial role's runs that one link's task in the one cell of
/// its runtime, whatever count of faces the config states: a second task is refused for want of a
/// cell, counted, and the cell takes the next task once the first is over and read.
///
/// # Control
///
/// A runtime made of the tables' rows as a table of many reds the refusal of the second task.
#[cfg(not(any(feature = "listen", feature = "group")))]
#[test]
fn a_dial_only_runtime_runs_one_task_at_a_time_whatever_faces_the_config_states() {
    let tables = RuntimeTables::of::<SetClock>(&CoopConfig {
        max_faces: 3,
        ..client_config()
    });
    let (runtime, _set) = placed_runtime(tables);
    let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
    let first = local
        .try_spawn_local(async { 1u8 })
        .unwrap_or_else(|_| panic!("the dial role's link has the cell"));
    assert!(
        matches!(
            local
                .try_spawn_local(async { 2u8 })
                .map(|_| ())
                .map_err(|refused| refused.why),
            Err(SpawnRefusal::NoTaskCell)
        ),
        "no second cell"
    );
    assert_eq!(runtime.task_refusals().no_task_cell, 1);
    assert_eq!(local.block_on_local(first).expect("ran"), 1);
    let next = local
        .try_spawn_local(async { 3u8 })
        .unwrap_or_else(|_| panic!("the cell is free once its task is read"));
    assert_eq!(local.block_on_local(next).expect("ran"), 3);
}

/// The cells are held to the build's `MAX_TASKS` whatever the config admits, a count past the
/// address space too: a face past them is refused as one past `max_faces` is.
#[test]
fn the_cells_reserved_are_never_more_than_max_tasks() {
    let tables = RuntimeTables::of::<SetClock>(&CoopConfig {
        max_faces: usize::MAX,
        ..client_config()
    });
    assert_eq!(tables.rows.tasks, caps::MAX_TASKS);
    assert_eq!(tables.rows.tasks + tables.groups, caps::MAX_TASKS);
}

/// The runtime the tables are for holds a cell of a link's session task's bytes for each link: a
/// task that fits is placed, and one a byte larger is refused as too large, counted, whatever the
/// build, as no cell of the runtime takes the bytes a task asks for once it is made.
#[test]
fn the_runtime_of_the_tables_places_a_task_a_link_cell_fits_and_refuses_a_larger_one() {
    const LARGER: usize = link_task_bytes::<SetClock>() + 1;
    let tables = RuntimeTables::of::<SetClock>(&CoopConfig {
        max_faces: 0,
        ..client_config()
    });
    let (runtime, _set) = placed_runtime(tables);
    let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
    let large = [7u8; LARGER];
    let refused = local
        .try_spawn_local(async move { large[0] })
        .map(|_| ())
        .map_err(|refused| refused.why);
    assert_eq!(refused, Err(SpawnRefusal::TooLarge));
    assert_eq!(runtime.task_refusals().too_large, 1);
    let small = local
        .try_spawn_local(async { 3u8 })
        .expect("a link's cell takes a small task");
    assert_eq!(local.block_on_local(small).expect("ran"), 3);
}

/// The parts of the cell a link's session task takes, by size, for the cell to be made smaller
/// where it is largest: the pump (the session's machine, its handle, its timers, its receive with
/// the reassembly Router and the record buffer) built in the task's own memory, what the task holds
/// to build it, and what it hands each event to. Read with `--ignored --nocapture`.
#[test]
#[ignore = "a measurement: prints the parts of a link task's cell"]
fn print_the_parts_of_a_link_tasks_cell() {
    use core::mem::size_of;
    use wz_runtime_coop::session_drive::{SessionDatagramLink, SessionDriveConfig, SessionPump};
    use wz_runtime_coop::session_runtime::SessionHandle;
    use wz_runtime_coop::{CoopRuntime, CoopTime};
    use wz_session_core::drive::SessionEngine;
    use wz_session_core::link::BoxedLinkDriver;
    use wz_session_core::network_message::RecordBuf;
    use wz_session_core::transport_timers::TransportTimers;
    use wz_session_core::unicast_rx::RouterLend;
    use wz_session_core::unicast_rx::UnicastRx;

    use crate::engine::{FaceDispatch, SessionReassembly};

    type C = SetClock;
    type Link = wz_runtime_coop::link_cells::CellRc<dyn SessionDatagramLink>;
    type Router = RouterLend<SessionReassembly>;
    let cell = link_task_bytes::<C>();
    let pump = size_of::<SessionPump<C, Link, dyn BoxedLinkDriver, Router>>();
    let parts: [(&str, usize); 13] = [
        ("pump", pump),
        (
            "  engine (the session machine)",
            size_of::<SessionEngine<CoopRuntime<C>, CoopTime<C>>>(),
        ),
        ("  rx (receive)", size_of::<UnicastRx<Router>>()),
        ("    router lend (reassembly)", size_of::<Router>()),
        ("  the session's one router", size_of::<SessionReassembly>()),
        ("    record buffer", size_of::<RecordBuf>()),
        ("  timers", size_of::<TransportTimers>()),
        ("  actions handle", size_of::<SessionHandle<C>>()),
        ("  runtime", size_of::<CoopRuntime<C>>()),
        ("  clock", size_of::<CoopTime<C>>()),
        ("  link", size_of::<Link>()),
        (
            "parts to build it: maker + config",
            size_of::<Router>() + size_of::<SessionDriveConfig>(),
        ),
        (
            "event sink (FaceDispatch)",
            size_of::<FaceDispatch<C, dyn BoxedLinkDriver>>(),
        ),
    ];
    std::println!("link task cell: {cell} B");
    for (name, bytes) in parts {
        std::println!("{name:<40} {bytes:>7} B");
    }
    assert!(pump <= cell, "the pump is built in the cell");
}
