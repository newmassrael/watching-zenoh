// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The tables a session's runtime reserves when it opens (`RuntimeTables`): a task cell for each
//! link the config admits, in the bytes a link's session task takes, held with the groups' cells to
//! the build's `MAX_TASKS`; and the build's `MAX_TIMERS` deadlines.

use wz_runtime_coop::executor::SpawnRefusal;
use wz_runtime_coop::CoopLocalSet;
use wz_runtime_posix::PosixClock;
use wz_session_core::caps;

use super::client_config;
use crate::engine::{link_task_bytes, RuntimeTables};
use crate::CoopConfig;

/// A client that attaches no face holds the one link it dials, and its runtime one cell for that
/// link's session, of the bytes the session's task takes.
#[test]
fn a_client_reserves_one_cell_for_the_link_it_dials() {
    let tables = RuntimeTables::of::<PosixClock>(&CoopConfig {
        max_faces: 0,
        ..client_config()
    });
    assert_eq!(tables.rows.tasks, caps::MAX_TASKS.min(1));
    assert_eq!(tables.groups, 0, "the config joins no group");
    assert_eq!(tables.rows.task_bytes, link_task_bytes::<PosixClock>());
    assert!(tables.rows.task_bytes > 0, "a session's task has bytes");
    assert_eq!(tables.rows.timers, caps::MAX_TIMERS);
}

/// A listener reserves a cell for the dial role's link and each face it admits, a link in its
/// handshake among them; a link past them is closed before it has a task, so a handshake it holds
/// takes no cell of its own.
#[test]
fn a_listener_reserves_a_cell_for_each_face_it_admits() {
    let tables = RuntimeTables::of::<PosixClock>(&CoopConfig {
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        max_faces: 3,
        accept_pending: 2,
        ..client_config()
    });
    assert_eq!(tables.rows.tasks, caps::MAX_TASKS.min(1 + 3));
}

/// A session that listens with the peers zenoh-pico takes (its ten, `Z_LISTEN_MAX_CONNECTION_NB`)
/// runs a task for each and for its dial: eleven cells, and the eighth to the eleventh session are
/// spawned as the first is. Only a twelfth, a link past the faces it admits, finds no cell.
#[test]
fn a_listener_with_the_ten_peers_pico_takes_runs_a_task_for_each() {
    let tables = RuntimeTables::of::<PosixClock>(&CoopConfig {
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        max_faces: 10,
        accept_pending: 1,
        ..client_config()
    });
    assert_eq!(tables.rows.tasks, 11, "the dial role's and ten faces");
    let runtime = tables.runtime(PosixClock);
    let local = CoopLocalSet::new(&runtime);
    let sessions: Vec<_> = (0..11u8)
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

/// The cells are held to the build's `MAX_TASKS` whatever the config admits, a count past the
/// address space too: a face past them is refused as one past `max_faces` is.
#[test]
fn the_cells_reserved_are_never_more_than_max_tasks() {
    let tables = RuntimeTables::of::<PosixClock>(&CoopConfig {
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
    const LARGER: usize = link_task_bytes::<PosixClock>() + 1;
    let tables = RuntimeTables::of::<PosixClock>(&CoopConfig {
        max_faces: 0,
        ..client_config()
    });
    let runtime = tables.runtime(PosixClock);
    let local = CoopLocalSet::new(&runtime);
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
    use alloc::rc::Rc;
    use core::mem::size_of;
    use wz_runtime_coop::reassembly_rx::{LentReassembly, LentReassemblyMaker};
    use wz_runtime_coop::session_drive::{SessionDatagramLink, SessionDriveConfig, SessionPump};
    use wz_runtime_coop::session_runtime::SessionHandle;
    use wz_runtime_coop::{CoopRuntime, CoopTime};
    use wz_session_core::drive::SessionEngine;
    use wz_session_core::link::BoxedLinkDriver;
    use wz_session_core::network_message::RecordBuf;
    use wz_session_core::transport_timers::TransportTimers;
    use wz_session_core::unicast_rx::UnicastRx;

    use crate::engine::FaceDispatch;

    type C = PosixClock;
    type Link = Rc<dyn SessionDatagramLink>;
    let cell = link_task_bytes::<C>();
    let pump = size_of::<SessionPump<C, Link, dyn BoxedLinkDriver, LentReassembly>>();
    let parts: [(&str, usize); 12] = [
        ("pump", pump),
        (
            "  engine (the session machine)",
            size_of::<SessionEngine<CoopRuntime<C>, CoopTime<C>>>(),
        ),
        ("  rx (receive)", size_of::<UnicastRx<LentReassembly>>()),
        ("    router (reassembly)", size_of::<LentReassembly>()),
        ("    record buffer", size_of::<RecordBuf>()),
        ("  timers", size_of::<TransportTimers>()),
        ("  actions handle", size_of::<SessionHandle<C>>()),
        ("  runtime", size_of::<CoopRuntime<C>>()),
        ("  clock", size_of::<CoopTime<C>>()),
        ("  link", size_of::<Link>()),
        (
            "parts to build it: maker + config",
            size_of::<LentReassemblyMaker>() + size_of::<SessionDriveConfig>(),
        ),
        ("event sink (FaceDispatch)", size_of::<FaceDispatch<C>>()),
    ];
    std::println!("link task cell: {cell} B");
    for (name, bytes) in parts {
        std::println!("{name:<40} {bytes:>7} B");
    }
    assert!(pump <= cell, "the pump is built in the cell");
}
