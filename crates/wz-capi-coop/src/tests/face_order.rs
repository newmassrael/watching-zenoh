// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The order of the session's lock and a face's: a read waits for the session's lock inside its
//! face's lend, and the session's lock is held over a face only by a try, never a wait
//! (`wz_runtime_coop::sync::NoFaceWait`), which a debug build on a host fails at once. The one
//! wait between the two runs from a face to the session's lock, so no cycle closes.

use wz_runtime_coop::sync::{FacePlace, Lend};

use super::{open, CatchAll, Router};
use crate::form::SessionLock;

/// A face's place holding `value`, under the lock kind the engine's sessions are built with.
fn face_holding(value: u32) -> FacePlace<SessionLock, u32> {
    let place = FacePlace::empty();
    place.hold(value);
    place
}

/// The session's lock is taken inside a face's lend, by a take that waits and by a try alike, as
/// a read takes it with its face held, and is free once the lends are done. Turned red by a take
/// that refuses to run inside a face's lend.
#[test]
fn the_sessions_lock_is_taken_inside_a_faces_lend() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let place = face_holding(4);
    let looks = engine.peer_looks();
    assert_eq!(place.lend(|_| engine.peer_looks()), Some(looks));
    assert_eq!(
        place.try_lend(|_| engine.session_is_free()),
        Lend::Lent(true)
    );
    assert!(engine.session_is_free(), "the lends left the lock free");
}

/// A face is tried under the session's lock, the way a step sends, and a wait on it there fails,
/// which leaves the lock held to the step and free after it. A build whose values all lie under
/// the session's one lock (no value locks) makes a face's lend no wait, so it runs there. Turned
/// red by a check that refuses a try under the session's lock, or one that lets a wait through
/// (`CoreGuard`'s mark), or fails a lend that cannot wait.
#[cfg(feature = "threads")]
#[test]
fn a_face_is_tried_and_not_waited_on_under_the_sessions_lock() {
    use wz_runtime_coop::sync::LockKind;
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let place = face_holding(5);
    let mut tried = Lend::Empty;
    let mut waited = None;
    engine.holding_as_a_step(|| {
        tried = place.try_lend(|value| *value);
        waited = Some(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| place.lend(|value| *value)))
                .is_err(),
        );
    });
    assert_eq!(tried, Lend::Lent(5));
    assert_eq!(
        waited,
        Some(<SessionLock as LockKind>::WAITS),
        "a wait on a face under the session's lock fails where a face's lend waits"
    );
    assert!(engine.session_is_free(), "the step let the lock go");
    assert_eq!(
        place.lend(|value| *value),
        Some(5),
        "a wait with no lock held"
    );
}
