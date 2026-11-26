// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The runtime of a session whose read steps its one link itself (`direct`): the link runs as no
//! task, so the runtime is made of no cell (`RuntimeForm::Taskless`), and the build links no walk
//! that polls, settles or drops a task.

use wz_runtime_coop::RuntimeForm;
use wz_runtime_posix::PosixClock;

use super::client_config;
use crate::arena::{AllocatorMemory, ArenaPlan, SessionArena};
use crate::engine::RuntimeTables;

/// The runtime such a session opens holds no cell, whatever the groups its config names: a spawn
/// on it is refused, counted, and a pass runs nothing. Turned red by a form of this build made for
/// one task, whose walks poll and drop one, or by a runtime that took the spawn.
#[test]
fn a_session_whose_read_steps_its_link_opens_a_runtime_of_no_cell() {
    assert_eq!(RuntimeTables::form(0), RuntimeForm::Taskless);
    assert_eq!(RuntimeTables::form(3), RuntimeForm::Taskless);
    let tables = RuntimeTables::of(&client_config());
    let bytes = tables
        .placed_bytes::<PosixClock>()
        .expect("a span of the tables' rows");
    let mut plan = ArenaPlan::vacant();
    plan.holding_runtime(bytes).expect("the span fits");
    let mut arena = SessionArena::reserve(&plan, &AllocatorMemory).expect("the host has it");
    let place = arena.runtime_place(bytes).expect("the plan holds the span");
    let (runtime, local) = tables
        .runtime(PosixClock, place)
        .expect("the span fits the runtime");
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
