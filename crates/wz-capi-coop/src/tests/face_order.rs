// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The order of the session's lock and a face's: the session's is taken first and a face's
//! under it, or a face's alone, never the session's inside a face's lend
//! (`wz_runtime_coop::sync::face_lent_here`), which a debug build on a host fails at once.

use wz_runtime_coop::sync::{FacePlace, Lend};

use super::{open, CatchAll, Router};
use crate::form::SessionLock;

/// A face's place holding `value`, under the lock kind the engine's sessions are built with.
fn face_holding(value: u32) -> FacePlace<SessionLock, u32> {
    let place = FacePlace::empty();
    place.hold(value);
    place
}

/// The session's lock taken inside a face's lend fails, by a take that waits and by a try alike,
/// and the face's lend that unwound leaves the lock free for a take after it. Turned red by a
/// take that does not ask whether a face is lent on its thread (`CoreLock::not_inside_a_face`).
#[test]
fn the_sessions_lock_is_not_taken_inside_a_faces_lend() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    // A place for each try: a lock kind that poisons on a panic inside it would fail the second
    // try for its own reason.
    let place = face_holding(4);
    let waited = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        place.try_lend(|_| engine.peer_looks())
    }));
    assert!(waited.is_err(), "a take inside a face's lend fails");
    let other = face_holding(6);
    let tried = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        other.try_lend(|_| engine.session_is_free())
    }));
    assert!(tried.is_err(), "a try inside a face's lend fails too");
    assert!(
        engine.session_is_free(),
        "the unwound lends left the lock free"
    );
    let _ = engine.peer_looks();
}

/// A face lent while the session's lock is held, which is the order a step's send takes them in,
/// lends it. Turned red by a check that refuses a face's lend under the session's lock.
#[cfg(feature = "threads")]
#[test]
fn a_face_is_lent_under_the_sessions_lock() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let place = face_holding(5);
    let mut lent = Lend::Empty;
    engine.holding_as_a_step(|| lent = place.try_lend(|value| *value));
    assert_eq!(lent, Lend::Lent(5));
}
