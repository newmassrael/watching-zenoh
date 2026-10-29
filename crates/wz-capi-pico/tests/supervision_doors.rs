// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The node's supervisor driven through the C doors (`docs/observation-plane.md` M3).
//!
//! One test, in a process of its own, because the supervisor is the process's: the arms run in
//! order against it. They use real time (a deadline of 100 ms and a sleep past it), with no
//! assertion that depends on how long a thread was kept waiting beyond that: an arm is about what
//! happened, never about how soon.
//!
//! The build keeps the default policy, `latch`; the `rearm` policy is the unit test of
//! `wz-session-core`, which names both values.

#![cfg(feature = "supervision")]

use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::time::Duration;

use wz_capi_pico::result::{Z_ERR_GENERIC, Z_ERR_INVALID, Z_OK};
use wz_capi_pico::supervision::{
    wz_ext_supervision_check, wz_ext_supervision_feed, wz_ext_supervision_healthy,
    wz_ext_supervision_set_hook, wz_ext_supervision_start, wz_ext_supervision_state,
    wz_ext_supervision_stop, WZ_EXT_SUPERVISION_ARMED, WZ_EXT_SUPERVISION_DISARMED,
    WZ_EXT_SUPERVISION_EXPIRED, WZ_EXT_SUPERVISION_NO_SUCH_CHECKPOINT,
};
use wz_session_core::caps::SUPERVISION_CHECKPOINTS;

/// What the hook saw: how many times it ran, for which checkpoint, and what a stop of that
/// checkpoint from inside the hook answered.
#[derive(Default)]
struct Seen {
    calls: AtomicU32,
    checkpoint: AtomicU8,
    stop_inside_the_hook: AtomicU8,
}

unsafe extern "C" fn hook(context: *mut c_void, checkpoint: u8) {
    let seen = &*(context as *const Seen);
    seen.calls.fetch_add(1, Ordering::SeqCst);
    seen.checkpoint.store(checkpoint, Ordering::SeqCst);
    // The hook runs with no lock held, so it can call a door; and the checkpoint whose hook this
    // is does not stop until the hook returns.
    seen.stop_inside_the_hook
        .store(wz_ext_supervision_stop(checkpoint) as u8, Ordering::SeqCst);
}

#[test]
fn a_checkpoint_fed_in_time_stays_healthy_and_one_that_is_not_runs_the_hook_once() {
    let seen: &'static Seen = Box::leak(Box::default());
    unsafe {
        assert_eq!(
            wz_ext_supervision_set_hook(Some(hook), seen as *const Seen as *mut c_void),
            Z_OK
        );
    }

    // ARM 1: nothing supervised is not healthy.
    assert_eq!(wz_ext_supervision_healthy(), 0);
    assert_eq!(wz_ext_supervision_state(0), WZ_EXT_SUPERVISION_DISARMED);

    // ARM 2: a supervised checkpoint that is fed is healthy, and a check finds nothing.
    assert_eq!(wz_ext_supervision_start(0, 100), Z_OK);
    assert_eq!(wz_ext_supervision_state(0), WZ_EXT_SUPERVISION_ARMED);
    assert_eq!(wz_ext_supervision_healthy(), 1);
    assert_eq!(wz_ext_supervision_feed(0), Z_OK);
    assert_eq!(wz_ext_supervision_check(), Z_OK);
    assert_eq!(seen.calls.load(Ordering::SeqCst), 0);

    // ARM 3: not fed past the deadline, it expires, the hook runs once, and the node is no longer
    // healthy.
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(wz_ext_supervision_check(), Z_OK);
    assert_eq!(seen.calls.load(Ordering::SeqCst), 1);
    assert_eq!(seen.checkpoint.load(Ordering::SeqCst), 0);
    assert_eq!(wz_ext_supervision_state(0), WZ_EXT_SUPERVISION_EXPIRED);
    assert_eq!(wz_ext_supervision_healthy(), 0);
    assert_eq!(wz_ext_supervision_check(), Z_OK);
    assert_eq!(
        seen.calls.load(Ordering::SeqCst),
        1,
        "the hook runs once per expiry"
    );

    // ARM 4: a stop asked for from inside the hook was refused, and the door was callable there.
    assert_eq!(
        seen.stop_inside_the_hook.load(Ordering::SeqCst),
        Z_ERR_GENERIC as u8,
        "a checkpoint does not stop while its hook runs"
    );

    // ARM 5: under `latch` a late feed does not hide the missed deadline; stopping and starting
    // supervises it again.
    assert_eq!(wz_ext_supervision_feed(0), Z_OK);
    assert_eq!(wz_ext_supervision_state(0), WZ_EXT_SUPERVISION_EXPIRED);
    assert_eq!(wz_ext_supervision_stop(0), Z_OK);
    assert_eq!(wz_ext_supervision_state(0), WZ_EXT_SUPERVISION_DISARMED);
    assert_eq!(wz_ext_supervision_start(0, 100), Z_OK);
    assert_eq!(wz_ext_supervision_healthy(), 1);

    // ARM 6: the doors refuse what they cannot use.
    assert_eq!(
        wz_ext_supervision_start(SUPERVISION_CHECKPOINTS as u8, 100),
        Z_ERR_INVALID
    );
    assert_eq!(
        wz_ext_supervision_start(0, 100),
        Z_OK,
        "already supervised: left as it is"
    );
    assert_eq!(
        wz_ext_supervision_feed(SUPERVISION_CHECKPOINTS as u8),
        Z_ERR_INVALID
    );
    assert_eq!(
        wz_ext_supervision_stop(SUPERVISION_CHECKPOINTS as u8),
        Z_ERR_INVALID
    );
    assert_eq!(
        wz_ext_supervision_state(SUPERVISION_CHECKPOINTS as u8),
        WZ_EXT_SUPERVISION_NO_SUCH_CHECKPOINT
    );
    assert_eq!(wz_ext_supervision_stop(0), Z_OK);
    assert_eq!(
        wz_ext_supervision_start(0, 0),
        Z_ERR_INVALID,
        "a timeout of 0 is refused"
    );
}
