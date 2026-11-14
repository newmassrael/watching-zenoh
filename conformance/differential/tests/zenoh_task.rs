// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-task`: upstream's task controller (`up_task`) and wz's (`wz_task`) asked to spawn and end
//! the same tasks, and what each did held equal.
//!
//! Each crate spawns on the pool of its own `zenoh-runtime` (`up_runtime` and `wz_runtime`), and
//! its blocking calls (`terminate_all`, `terminate`) wait on that pool, so neither controller is
//! measured on the other's runtime. The tests are plain threads, as an application that calls the
//! blocking API is: the pool is the only runtime involved.

use std::time::Duration;

/// A controller asked to run a future while nothing is cancelled, then to end the three kinds of
/// task it tracks: one it may abort, one that watches the controller's token, one that ends on its
/// own. What it answered: the early future's output, the number of tasks `terminate_all` left, and
/// each task's output.
macro_rules! controller_run {
    ($task:ident, $rt:ident) => {{
        let rt = $rt::ZRuntime::Application;
        let controller = $task::TaskController::default();
        let early = rt.block_in_place(controller.into_abortable(async { 3_u8 }));
        let never = controller.spawn_abortable_with_rt(rt, std::future::pending::<()>());
        let token = controller.get_cancellation_token();
        let watching = controller.spawn_with_rt(rt, async move {
            token.cancelled().await;
            7_u32
        });
        let finite = controller.spawn_with_rt(rt, async { 5_u32 });
        let left = controller.terminate_all(Duration::from_secs(10));
        let never = rt.block_in_place(never).expect("the abortable task ends");
        let watching = rt.block_in_place(watching).expect("the watching task ends");
        let finite = rt.block_in_place(finite).expect("the finite task ends");
        (early, left, never, watching, finite)
    }};
}

/// A controller whose one task neither ends nor watches the token: `terminate_all` gives up at its
/// timeout and answers how many tasks are left.
macro_rules! stubborn_run {
    ($task:ident, $rt:ident) => {{
        let controller = $task::TaskController::default();
        let _stubborn =
            controller.spawn_with_rt($rt::ZRuntime::Application, std::future::pending::<()>());
        controller.terminate_all(Duration::from_millis(200))
    }};
}

/// Three single tasks ended by `terminate`: one it aborts, one that ends when its token is
/// cancelled, and one that ignores its token and outlives the timeout.
macro_rules! terminatable_run {
    ($task:ident, $rt:ident) => {{
        let rt = $rt::ZRuntime::Application;
        let mut aborted =
            $task::TerminatableTask::spawn_abortable(rt, std::future::pending::<()>());
        let token = $task::TerminatableTask::create_cancellation_token();
        let watching = token.clone();
        let mut cooperative =
            $task::TerminatableTask::spawn(rt, async move { watching.cancelled().await }, token);
        let mut stubborn = $task::TerminatableTask::spawn(
            rt,
            std::future::pending::<()>(),
            $task::TerminatableTask::create_cancellation_token(),
        );
        (
            aborted.terminate(Duration::from_secs(10)),
            cooperative.terminate(Duration::from_secs(10)),
            stubborn.terminate(Duration::from_millis(200)),
        )
    }};
}

#[test]
fn both_controllers_end_what_they_track_alike() {
    let up = controller_run!(up_task, up_runtime);
    let wz = controller_run!(wz_task, wz_runtime);
    assert_eq!(up, wz, "the two controllers differ");
    // What the comparison agrees ON, so two crates wrong the same way cannot pass for right: the
    // early future ran, nothing was left, the abortable task was cut off, the watching task saw the
    // cancellation and the finite one ran to its end.
    assert_eq!(wz, (Some(3), 0, None, 7, 5));
}

#[test]
fn both_controllers_count_a_task_that_ignores_the_cancellation() {
    let up = stubborn_run!(up_task, up_runtime);
    let wz = stubborn_run!(wz_task, wz_runtime);
    assert_eq!(up, wz, "the two controllers differ");
    assert_eq!(wz, 1, "the one task that outlives the timeout is left");
}

#[test]
fn both_terminatable_tasks_end_alike() {
    let up = terminatable_run!(up_task, up_runtime);
    let wz = terminatable_run!(wz_task, wz_runtime);
    assert_eq!(up, wz, "the two crates differ");
    assert_eq!(
        wz,
        (true, true, false),
        "aborted and cooperative end in time, the stubborn task does not"
    );
}
