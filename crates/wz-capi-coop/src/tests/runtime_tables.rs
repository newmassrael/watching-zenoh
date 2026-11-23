// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The tables a session's runtime reserves when it opens (`RuntimeTables`): a task cell for each
//! link the config admits, in the bytes a link's session task takes, held with the groups' cells to
//! the build's `MAX_TASKS`; and the build's `MAX_TIMERS` deadlines.

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
