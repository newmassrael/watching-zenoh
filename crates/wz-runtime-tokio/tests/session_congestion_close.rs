// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2923 (`transport-qos`) — a message that may not be dropped, finding no room
//! on its link, closes the RUNNING session as unresponsive.
//!
//! zenoh closes a transport whose blocking message could not be queued within
//! `wait_before_close` (`io/zenoh-transport/src/unicast/universal/tx.rs` @
//! `if !pushed && !msg.is_droppable() {`, reason `UNRESPONSIVE`). wz's session
//! statechart has had the matching transition for a long time —
//! `tx.congestion.exhaust -> Closing` with `set_close_reason_unresponsive` —
//! and nothing raised it. Both ends are witnessed apart elsewhere: the sender
//! staging the request (`session_glue`'s `link_congestion_tests`) and the
//! transition (the statechart). This witnesses the JOIN: the real drive loop,
//! parked on a link that delivers nothing, is woken by a sender on another task
//! and puts the Close on the wire with the unresponsive reason — which is what
//! is asserted, because an assertion on the staged request alone would pass
//! with the loop's raise deleted.
//!
//! Gated at file scope on the feature whose sender it drives.

#![cfg(feature = "declare-keyexpr")]

use std::sync::Arc;
use std::time::Duration;

use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{SessionFsmUnicastEvent, SessionFsmUnicastState};
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal, new_session_actions, new_session_engine, BoxedLinkDriver,
    LinkSendOutcome,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::close_reason::CloseReason;
use wz_session_core::link::{LinkRoom, RoomAnswer, RoomWait};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;
use wz_session_core::session_timeouts::SessionTimeouts;

/// An outbound link with no room on any lane: every data message congests.
struct FullLink;

impl BoxedLinkDriver for FullLink {
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        LinkSendOutcome::Sent
    }
    fn wait_for_room(&self, _priority: Priority, _wait: RoomWait) -> RoomAnswer {
        RoomAnswer::at_once(LinkRoom::Congested)
    }
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
}

/// An inbound link that never delivers, so the loop parks until woken.
struct SilentLink;

impl wz_runtime_tokio::LinkDriver for SilentLink {
    async fn open(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    async fn send(
        &mut self,
        _frame: &wz_runtime_tokio::TxFrame<'_>,
        _reliability: wz_runtime_tokio::Reliability,
    ) -> std::io::Result<()> {
        Ok(())
    }
    async fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    async fn poll_event(&mut self) -> wz_runtime_tokio::LinkEvent {
        std::future::pending().await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocking_message_on_a_congested_link_closes_the_running_session_as_unresponsive() {
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(FullLink);
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    engine.process_event(SessionFsmUnicastEvent::OutboundStart);
    engine.process_event(SessionFsmUnicastEvent::LinkOpened);
    engine.process_event(SessionFsmUnicastEvent::InitAckReceived);
    engine.process_event(SessionFsmUnicastEvent::OpenAckReceived);
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::Established,
        "the walk to Established is this witness's premise, not its claim"
    );

    let loop_actions = actions.clone();
    let session = tokio::spawn(async move {
        let mut link = SilentLink;
        let clock = TokioTime::new();
        drive_session_until_terminal(
            &mut link,
            &loop_actions,
            &mut engine,
            None,
            &clock,
            &SessionTimeouts::spec_defaults(),
            |_| {},
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        actions.trace_snapshot().send_close_frame_with_reason,
        0,
        "nothing has closed the session yet"
    );

    // The sender is not the loop: a Declare (`QoSType::DECLARE`, `Block`)
    // sent from another task.
    let sender = actions.clone();
    tokio::task::spawn_blocking(move || sender.send_declare_keyexpr(1, "home/k"))
        .await
        .expect("sender task")
        .expect("the declare is refused by no gate of its own");

    let closed = tokio::time::timeout(Duration::from_millis(500), async {
        while actions.trace_snapshot().send_close_frame_with_reason == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    session.abort();
    assert!(
        closed.is_ok(),
        "the running loop did not close the session: the congestion close was \
         staged and never raised"
    );
    assert_eq!(
        actions.trace_snapshot().close_reason,
        CloseReason::Unresponsive,
        "zenoh closes a transport it could not push a blocking message to as \
         UNRESPONSIVE"
    );
}
