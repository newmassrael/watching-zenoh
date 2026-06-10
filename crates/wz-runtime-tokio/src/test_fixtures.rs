// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Crate-local fixtures for `wz-runtime-tokio`'s OWN unit tests.
//!
//! These live INSIDE the crate (compiled under `#[cfg(test)]`) rather
//! than in the `wz-runtime-tokio-test-support` sibling on purpose. The
//! sibling depends on `wz-runtime-tokio`, so a unit test that sourced
//! its `SessionLinkActions` / `RecordingLinkDriver` from the sibling
//! would receive the dev-dependency cycle's SECOND `wz-runtime-tokio`
//! copy — a distinct type that cannot be handed to the crate-local
//! `Session::new` and exposes no `pub(crate)` / private API here (see
//! the `feedback-test-support-dev-dep-cycle` note). Built locally,
//! these produce the same crate version the unit tests compile against,
//! so `build_session`, the `reconstruct_outbound_keyexpr` shape table,
//! and the wire-byte send guards all converge onto ONE fixture with no
//! per-test exceptions.
//!
//! `fixture_session_init_params` deliberately stays in the sibling: the
//! integration tests (`tests/*.rs`) consume it, and it returns a
//! `wz-session-core` type (`SessionInitParams`) that is SHARED across
//! both `wz-runtime-tokio` copies in the graph — so importing it across
//! the boundary here is sound (unlike a `wz-runtime-tokio`-defined type
//! such as `SessionLinkActions`). The recording driver + actions
//! builders are the ONLY surface that must be crate-local.

use std::sync::{Arc, Mutex};

use wz_runtime_tokio_test_support::fixture_session_init_params;

use crate::runtime_impl::TokioTime;
use crate::session_glue::{
    new_session_actions, BoxedLinkDriver, SessionInitParams, SessionLinkActions,
};
use crate::Reliability;

/// Test [`BoxedLinkDriver`] that records every outbound frame so a
/// behavioural guard can assert the emitted wire bytes / reliability
/// channel, or the *no-emit* half of a typed-reject contract
/// (`frame_count() == 0` — "no wire bytes leave on Err").
pub(crate) struct RecordingLinkDriver {
    frames: Mutex<Vec<(Vec<u8>, Reliability)>>,
}

impl RecordingLinkDriver {
    /// Number of frames observed via `send_blocking` so far.
    pub(crate) fn frame_count(&self) -> usize {
        self.frames
            .lock()
            .expect("recording driver mutex poisoned")
            .len()
    }

    /// Wire bytes of the `idx`-th recorded frame (panics if absent), so
    /// a wire-byte assertion can compare against an independently encoded
    /// expectation without reaching into the driver's private storage.
    pub(crate) fn frame_bytes(&self, idx: usize) -> Vec<u8> {
        self.frames.lock().expect("recording driver mutex poisoned")[idx]
            .0
            .clone()
    }

    /// Reliability channel the `idx`-th recorded frame was emitted on
    /// (panics if absent) — pins the action layer's reliable/best-effort
    /// channel pick (e.g. Close + Reply are reliable-only).
    pub(crate) fn frame_reliability(&self, idx: usize) -> Reliability {
        self.frames.lock().expect("recording driver mutex poisoned")[idx].1
    }
}

impl BoxedLinkDriver for RecordingLinkDriver {
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) {
        self.frames
            .lock()
            .expect("recording driver mutex poisoned")
            .push((bytes.to_vec(), reliability));
    }
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
}

/// Build a [`SessionLinkActions`] backed by a fresh [`RecordingLinkDriver`]
/// and the deterministic [`fixture_session_init_params`]. Returns both
/// handles so a caller can drive a signature-stable emit method and then
/// assert on the emitted frames (count / bytes / reliability).
pub(crate) fn recording_actions() -> (Arc<SessionLinkActions>, Arc<RecordingLinkDriver>) {
    recording_actions_with_params(fixture_session_init_params())
}

/// [`recording_actions`] variant that accepts caller-supplied
/// [`SessionInitParams`]. Use when a wire-byte assertion depends on a
/// specific field — typically `initial_sn`, which seeds
/// `next_outbound_frame_sn` and therefore the SN byte of every emitted
/// Frame. Build the params from [`fixture_session_init_params`] and
/// override only the asserted field so the rest stays on the SSOT.
pub(crate) fn recording_actions_with_params(
    params: SessionInitParams,
) -> (Arc<SessionLinkActions>, Arc<RecordingLinkDriver>) {
    let driver = recording_driver();
    let actions = new_session_actions(driver.clone(), params, TokioTime::new());
    (actions, driver)
}

/// A4 — a bare [`RecordingLinkDriver`] handle, for tests that wire the
/// recorder BEHIND another [`BoxedLinkDriver`] layer (the `SwappableLink`
/// transport-replacement seam) instead of using it as the actions driver
/// directly.
pub(crate) fn recording_driver() -> Arc<RecordingLinkDriver> {
    Arc::new(RecordingLinkDriver {
        frames: Mutex::new(Vec::new()),
    })
}

/// A4 — [`recording_actions`] variant that accepts the caller's driver
/// (e.g. a `SwappableLink` wrapping a [`RecordingLinkDriver`]) so a test
/// can interpose on the link seam while keeping the deterministic
/// [`fixture_session_init_params`]. Gated like its sole consumer
/// (`session_glue::reconnect_tx_tests`) so the C1j deny-warnings subset
/// lane (no `session-reconnect`) does not see it as dead code.
#[cfg(feature = "session-reconnect")]
pub(crate) fn recording_actions_with_driver(
    driver: Arc<dyn BoxedLinkDriver + Send + Sync>,
) -> Arc<SessionLinkActions> {
    new_session_actions(driver, fixture_session_init_params(), TokioTime::new())
}
