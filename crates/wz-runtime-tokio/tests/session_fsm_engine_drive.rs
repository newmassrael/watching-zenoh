// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R55b integration test — drives the generated `SessionFsmUnicastPolicy`
//! through `sce_rust_runtime::Engine` and verifies that the emitted
//! `execute_script` sequence matches the action ordering R54 pinned
//! by hand. The R54 test exercises the script-name → native-fn
//! dispatch in isolation; R55b proves that the FSM, when driven by
//! a real Engine, emits those scripts in the expected order on the
//! outbound-initiator path.
//!
//! Scope ceiling. The test walks `Init → LinkOpening` (one
//! macrostep) and asserts the LinkOpening.onentry script
//! (`link_driver_open()`) ran. Driving further along the handshake
//! requires either external events the test would synthesise
//! (`link.opened`, `init_ack.received`, `open_ack.received`) or the
//! cooperative scheduler's `tick()` to fire delayed `<send>`
//! events (the 5s `link.open_timeout` from LinkOpening.onentry).
//! Both paths broaden the test's responsibility beyond the R55b
//! audit — they are the R55c carry for the codec-encoded wire-bytes
//! round.

use std::sync::Arc;
use std::sync::Mutex;

use sce_rust_runtime::Engine;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent, SessionFsmUnicastPolicy, SessionFsmUnicastState,
};
use wz_runtime_tokio::session_glue::{BoxedLinkDriver, SessionLinkActions};
use wz_runtime_tokio::Reliability;
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, install_session_actions_for_test,
};

#[derive(Default)]
struct RecordingDriver {
    inner: Mutex<RecordingState>,
}

#[derive(Default)]
struct RecordingState {
    opens: u32,
    closes: u32,
    sends: Vec<(Vec<u8>, Reliability)>,
}

impl BoxedLinkDriver for RecordingDriver {
    fn open_blocking(&self) {
        self.inner.lock().unwrap().opens += 1;
    }
    fn close_blocking(&self) {
        self.inner.lock().unwrap().closes += 1;
    }
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) {
        self.inner
            .lock()
            .unwrap()
            .sends
            .push((bytes.to_vec(), reliability));
    }
}

#[test]
fn r55b_engine_drives_link_opening_onentry_script() {
    let driver = Arc::new(RecordingDriver::default());
    let actions = SessionLinkActions::new(
        driver.clone(),
        fixture_session_init_params(),
        TokioTime::new(),
    );
    let lua = install_session_actions_for_test(actions.clone());

    let mut engine: Engine<SessionFsmUnicastPolicy> =
        Engine::new(SessionFsmUnicastPolicy::new(lua));
    engine.initialize();

    // SCXML <scxml initial="Init"> places the engine at Init after
    // initialize(); no script actions run on Init's onentry (there
    // are none in the SCXML). Confirm the starting state before
    // driving.
    assert_eq!(engine.get_current_state(), SessionFsmUnicastState::Init);
    let trace_pre = actions.trace_snapshot();
    assert_eq!(trace_pre.link_driver_open, 0);

    // Drive Init -> LinkOpening with the outbound.start external event.
    // process_event is raise_external + step(); the step()'s
    // macrostep runs the LinkOpening.onentry actions including the
    // <script>link_driver_open()</script> call site.
    engine.process_event(SessionFsmUnicastEvent::OutboundStart);

    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::LinkOpening,
        "Init + outbound.start must transition to LinkOpening"
    );

    let trace_post = actions.trace_snapshot();
    assert_eq!(
        trace_post.link_driver_open, 1,
        "LinkOpening.onentry script must dispatch link_driver_open exactly once"
    );

    let snap = driver.inner.lock().unwrap();
    assert_eq!(
        snap.opens, 1,
        "the trace's link_driver_open must propagate through to driver.open()"
    );
    // The 5s link.open_timeout delayed send is scheduled on the
    // engine's internal scheduler; this test does not tick() time
    // forward so the timeout does not fire and no further actions
    // run.
    assert_eq!(snap.closes, 0);
    assert!(snap.sends.is_empty());
}
