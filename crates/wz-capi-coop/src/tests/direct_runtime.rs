// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The runtime of a session whose read steps every face itself (`direct`): no link runs as a
//! task, whether the session dials, listens or reads on a thread beside the program's calls, so
//! the runtime is made of no cell (`RuntimeForm::Taskless`), and the build links no walk that
//! polls, settles or drops a task. A build that joins groups runs each group's session as a task
//! and keeps its cells, so it has none of these tests.

use wz_runtime_coop::RuntimeForm;
use wz_runtime_posix::PosixClock;

use super::client_config;
#[cfg(not(wz_on_use))]
use crate::arena::{AllocatorMemory, ArenaPlan, SessionArena};
use crate::engine::RuntimeTables;
use crate::CoopConfig;

/// The runtime `tables` are for, made as an open makes it (placed in a span of its arena, or of
/// the allocator where the session's tables take their memory on use), holds no cell: a spawn on
/// it is refused, counted, and a pass runs nothing.
fn assert_no_cell(tables: RuntimeTables) {
    #[cfg(not(wz_on_use))]
    let (runtime, local) = {
        let bytes = tables
            .placed_bytes::<PosixClock>()
            .expect("a span of the tables' rows");
        let mut plan = ArenaPlan::vacant();
        plan.holding_runtime(bytes).expect("the span fits");
        let mut arena = SessionArena::reserve(&plan, &AllocatorMemory).expect("the host has it");
        let place = arena.runtime_place(bytes).expect("the plan holds the span");
        tables
            .runtime(PosixClock, place)
            .expect("the span fits the runtime")
    };
    #[cfg(wz_on_use)]
    let (runtime, local) = tables
        .made(PosixClock)
        .expect("the allocator has room for the runtime");
    assert!(
        local.try_spawn_local(async { 1u8 }).is_err(),
        "no cell for any task"
    );
    let refused = runtime.task_refusals();
    assert_eq!(
        refused.no_task_cell.saturating_add(refused.too_large),
        1,
        "the refusal is counted"
    );
    local.run_until_idle();
    assert_eq!(
        local.live_local_task_count(),
        0,
        "nothing was placed to run"
    );
}

/// The runtime such a session opens holds no cell, whatever the groups its config names. Turned
/// red by a form of this build made for one task or for many, whose walks poll and drop them, or
/// by a runtime that took the spawn.
#[test]
fn a_session_whose_read_steps_its_link_opens_a_runtime_of_no_cell() {
    assert_eq!(RuntimeTables::form(0), RuntimeForm::Taskless);
    assert_eq!(RuntimeTables::form(3), RuntimeForm::Taskless);
    assert_no_cell(RuntimeTables::of(&client_config()));
}

/// A session that listens takes each connection off its ports in its read and steps each face it
/// accepts where it lies, so its runtime holds no cell either, whatever faces and handshakes its
/// config admits. Turned red by a listening build whose runtime is a reserved table of many cells,
/// which links the walks of many for a table no task is ever placed in.
#[test]
fn a_listening_session_whose_read_steps_its_faces_opens_a_runtime_of_no_cell() {
    let listening = CoopConfig {
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        max_faces: 3,
        accept_pending: 2,
        ..client_config()
    };
    assert_eq!(
        RuntimeTables::form(listening.groups.len()),
        RuntimeForm::Taskless
    );
    assert_no_cell(RuntimeTables::of(&listening));
}
