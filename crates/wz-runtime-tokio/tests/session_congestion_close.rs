// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2923 (`transport-qos`) — a message that may not be dropped, finding no room
//! on its link, ends the RUNNING session, and writes nothing more to the link.
//!
//! zenoh drops a transport whose blocking message could not be queued within
//! `wait_before_close` (`io/zenoh-transport/src/unicast/universal/tx.rs` @
//! `if !pushed && !msg.is_droppable() {`). Until 1.10.1 it closed it with a
//! Close frame of reason `UNRESPONSIVE`; 1.10.2 marks the transmission pipelines
//! disabled at once and deletes the transport without enqueuing a frame, because
//! a push to an unresponsive pipeline can wait without end
//! (`io/zenoh-transport/src/unicast/universal/tx.rs` @ `tl.pipeline.mark_disabled();`).
//! wz's session statechart has the matching transition,
//! `tx.congestion.exhaust -> Closed`, and nothing raised it before R2923. Both
//! ends are witnessed apart elsewhere: the sender staging the request
//! (`session_glue`'s `link_congestion_tests`) and the transition (the
//! statechart). This witnesses the JOIN: the real drive loop, parked on a link
//! that delivers nothing, is woken by a sender on another task, takes the
//! session to its terminal state and releases the link, and no byte is written
//! after the request — which is what is asserted, because an assertion on the
//! staged request alone would pass with the loop's raise deleted.
//!
//! Gated at file scope on the feature whose sender it drives.

#![cfg(feature = "declare-keyexpr")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{SessionFsmUnicastEvent, SessionFsmUnicastState};
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal, new_session_actions, new_session_engine, BoxedLinkDriver,
    DriverOutcome, LinkSendOutcome,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::link::{LinkRoom, RoomAnswer, RoomWait};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;
use wz_session_core::session_timeouts::SessionTimeouts;

/// An outbound link with no room on any lane: every data message congests. It counts what
/// it is given to write.
struct FullLink {
    written: Arc<AtomicUsize>,
}

impl BoxedLinkDriver for FullLink {
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        self.written.fetch_add(1, Ordering::SeqCst);
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
async fn a_blocking_message_on_a_congested_link_ends_the_running_session_without_a_close_frame() {
    let written = Arc::new(AtomicUsize::new(0));
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(FullLink {
        written: written.clone(),
    });
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
        actions.trace_snapshot().release_link,
        0,
        "nothing has ended the session yet"
    );
    let written_before = written.load(Ordering::SeqCst);

    // The sender is not the loop: a Declare (`QoSType::DECLARE`, `Block`)
    // sent from another task.
    let sender = actions.clone();
    tokio::task::spawn_blocking(move || sender.send_declare_keyexpr(1, "home/k"))
        .await
        .expect("sender task")
        .expect("the declare is refused by no gate of its own");

    let outcome = tokio::time::timeout(Duration::from_millis(500), session)
        .await
        .expect(
            "the running loop did not end the session: the congestion close was staged and \
             never raised",
        )
        .expect("the drive task");
    assert!(
        matches!(outcome, DriverOutcome::Terminated),
        "the session reached its terminal state: {outcome:?}"
    );
    assert_eq!(
        actions.trace_snapshot().release_link,
        1,
        "and released its link"
    );
    assert_eq!(
        actions.trace_snapshot().send_close_frame_with_reason,
        0,
        "zenoh 1.10.2 deletes a transport it could not push a blocking message to, and \
         enqueues no Close frame on a pipeline that cannot take one"
    );
    assert_eq!(
        written.load(Ordering::SeqCst),
        written_before,
        "no byte was written to the link after the request"
    );
}
