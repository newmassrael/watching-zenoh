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

/// A listener reserves a cell for the dial role's link, each face it admits and each handshake it
/// holds, as its arena lays out a link for each.
#[test]
fn a_listener_reserves_a_cell_for_each_link_it_admits() {
    let tables = RuntimeTables::of::<PosixClock>(&CoopConfig {
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        max_faces: 3,
        accept_pending: 2,
        ..client_config()
    });
    assert_eq!(tables.rows.tasks, caps::MAX_TASKS.min(1 + 3 + 2));
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
