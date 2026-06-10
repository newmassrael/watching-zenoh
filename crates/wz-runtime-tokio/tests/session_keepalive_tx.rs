// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311kw — outbound TX stamp (`last_outbound_at`) wiring tests.
//!
//! Every production TX path funnels through the
//! `SessionLinkActions::send_wire` seam, which stamps the
//! `last_outbound_at` slot — the deadline-model equivalent of
//! zenoh-pico's `_z_transport_common_t._transmitted` flag (set on
//! every send in common/tx.c:98/153, consumed by the keepalive tasks
//! in unicast/lease.c:183/196 to suppress a KeepAlive when the line
//! already spoke). These tests pin the stamp behaviour the keepalive
//! emitter's idle-window comparison depends on: a wire emit from the
//! direct primitive path AND from the FSM action path both populate
//! the slot.

use std::sync::Arc;

use sce_rust_runtime::Engine;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::{
    new_session_actions, new_session_engine, BoxedLinkDriver, SessionActionsBinding,
    SessionLinkActions,
};
use wz_runtime_tokio_test_support::{fixture_session_init_params, NoopOutboundDriver};

fn fresh_setup() -> (
    Arc<SessionLinkActions>,
    Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>,
) {
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(NoopOutboundDriver::default());
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    (actions, engine)
}

/// The slot starts empty: no wire emit has happened at construction,
/// so the keepalive emitter's baseline falls back to `established_at`
/// (and pre-Established it has no baseline at all).
#[test]
fn last_outbound_at_starts_empty() {
    let (actions, _engine) = fresh_setup();
    assert!(
        actions.last_outbound_at.lock().unwrap().is_none(),
        "no TX has happened at construction"
    );
}

/// The direct wire primitive (`send_close_with_reason`, the same
/// `send_wire` seam every Frame / Fragment / batch-flush emit routes
/// through) stamps the slot.
#[cfg(feature = "codec-close")]
#[test]
fn close_emit_stamps_last_outbound_at() {
    use wz_runtime_tokio::session_glue::CloseReason;
    let (actions, _engine) = fresh_setup();
    actions.send_close_with_reason(CloseReason::Generic);
    assert!(
        actions.last_outbound_at.lock().unwrap().is_some(),
        "CLOSE emit must stamp the outbound slot (pico sets _transmitted on every t_msg send)"
    );
}

/// The FSM action path (SentInitSyn.onentry -> `send_init_syn`)
/// stamps the slot too — handshake t_msg emits count as line
/// activity exactly as pico's common/tx.c seam records them.
#[cfg(all(feature = "codec-init-body", feature = "session-unicast-open"))]
#[test]
fn handshake_emit_stamps_last_outbound_at() {
    let (actions, mut engine) = fresh_setup();
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);
    assert_eq!(engine.get_current_state(), S::SentInitSyn);
    assert!(
        actions.last_outbound_at.lock().unwrap().is_some(),
        "InitSyn emit must stamp the outbound slot"
    );
}
