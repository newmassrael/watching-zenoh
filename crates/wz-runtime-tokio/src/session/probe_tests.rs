// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A publish that does not wait for room (`Session::publish_probe` and its aliased forms), which
//! is what an admission retry is made of: the answer a link gives, and that the frame it writes
//! is the frame the publish that waits writes.

use super::*;
use crate::observer::ApplicationLayerObserver;
use crate::runtime_impl::TokioTime;
use crate::test_fixtures::{recording_actions, RecordingLinkDriver};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::link::{LinkRoom, RoomAnswer, RoomWait};

/// A link whose queue is full or has room as the test says, and that counts the frames it was
/// handed.
struct RoomDriver {
    full: AtomicBool,
    sent: AtomicUsize,
}

impl RoomDriver {
    fn new(full: bool) -> Arc<Self> {
        Arc::new(Self {
            full: AtomicBool::new(full),
            sent: AtomicUsize::new(0),
        })
    }

    fn sent(&self) -> usize {
        self.sent.load(Ordering::SeqCst)
    }

    fn set_full(&self, full: bool) {
        self.full.store(full, Ordering::SeqCst);
    }
}

impl crate::session_glue::BoxedLinkDriver for RoomDriver {
    fn send_blocking(
        &self,
        _bytes: &[u8],
        _reliability: crate::Reliability,
    ) -> crate::session_glue::LinkSendOutcome {
        self.sent.fetch_add(1, Ordering::SeqCst);
        crate::session_glue::LinkSendOutcome::Sent
    }
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
    fn wait_for_room(
        &self,
        _priority: wz_session_core::qos::Priority,
        _wait: RoomWait,
    ) -> RoomAnswer {
        RoomAnswer::at_once(if self.full.load(Ordering::SeqCst) {
            LinkRoom::Congested
        } else {
            LinkRoom::Free
        })
    }
}

fn session_over(driver: &Arc<RoomDriver>) -> TokioSession {
    let actions = crate::session_glue::new_session_actions(
        driver.clone(),
        fixture_session_init_params(),
        TokioTime::new(),
    );
    let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
    TokioSession::new(actions, observer, Arc::new(TokioTime::new()))
}

/// A session whose link records the frames it is handed.
fn recording_session() -> (TokioSession, Arc<RecordingLinkDriver>) {
    let (actions, driver) = recording_actions();
    let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
    (
        TokioSession::new(actions, observer, Arc::new(TokioTime::new())),
        driver,
    )
}

fn remote() -> PublishOptions {
    PublishOptions::put().with_locality(Locality::Remote)
}

#[test]
fn a_probe_on_a_link_with_room_queues_the_frame_the_waiting_publish_writes() {
    let (probing, probing_driver) = recording_session();
    let (waiting, waiting_driver) = recording_session();
    assert_eq!(
        probing.publish_probe("home/temp", b"22.5", remote()),
        Ok(WireProbe::Queued)
    );
    waiting
        .publish("home/temp", b"22.5", remote())
        .expect("the waiting publish");
    assert_eq!(probing_driver.frame_count(), 1);
    assert_eq!(
        probing_driver.frame_bytes(0),
        waiting_driver.frame_bytes(0),
        "the probe puts the same bytes on the link as the publish that waits"
    );

    // A Del is built by the same helper and is a frame of its own.
    let del = PublishOptions::del().with_locality(Locality::Remote);
    assert_eq!(
        probing.publish_probe("home/temp", b"", del),
        Ok(WireProbe::Queued)
    );
    assert_eq!(probing_driver.frame_count(), 2);
}

#[test]
fn a_probe_on_a_full_link_reports_no_room_and_writes_nothing_until_there_is_room() {
    let driver = RoomDriver::new(true);
    let session = session_over(&driver);
    assert_eq!(
        session.publish_probe("home/temp", b"22.5", remote()),
        Ok(WireProbe::NoRoom)
    );
    assert_eq!(driver.sent(), 0, "a frame with no room is not written");
    driver.set_full(false);
    assert_eq!(
        session.publish_probe("home/temp", b"22.5", remote()),
        Ok(WireProbe::Queued)
    );
    assert_eq!(driver.sent(), 1);
}

#[test]
fn a_probe_that_may_not_go_remote_offers_the_link_nothing() {
    let (session, driver) = recording_session();
    let local = PublishOptions::put().with_locality(Locality::SessionLocal);
    assert_eq!(
        session.publish_probe("home/temp", b"22.5", local),
        Ok(WireProbe::Queued)
    );
    assert_eq!(driver.frame_count(), 0);
}

#[cfg(all(feature = "codec-declare", feature = "declare-keyexpr"))]
#[test]
fn an_aliased_probe_needs_the_declaration_and_writes_the_frame_the_aliased_publish_writes() {
    let (probing, probing_driver) = recording_session();
    let (waiting, waiting_driver) = recording_session();

    // An id the table does not hold is refused before the link is asked.
    assert_eq!(
        probing.publish_aliased_auto_probe(42, None, b"x", remote()),
        Err(PublishAliasError::UnknownMapping(42))
    );
    assert_eq!(probing_driver.frame_count(), 0);

    for session in [&probing, &waiting] {
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");
    }
    assert_eq!(
        probing.publish_aliased_auto_probe(7, Some("/kitchen"), b"x", remote()),
        Ok(WireProbe::Queued)
    );
    waiting
        .publish_aliased_auto(7, Some("/kitchen"), b"x", remote())
        .expect("the waiting aliased publish");
    assert_eq!(
        probing_driver.frame_count(),
        2,
        "the declaration, then the push"
    );
    assert_eq!(
        probing_driver.frame_bytes(1),
        waiting_driver.frame_bytes(1),
        "the aliased probe puts the same bytes on the link as the aliased publish"
    );
}

#[cfg(all(feature = "codec-declare", feature = "declare-keyexpr"))]
#[test]
fn an_aliased_probe_on_a_full_link_reports_no_room() {
    let driver = RoomDriver::new(false);
    let session = session_over(&driver);
    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");
    let declared = driver.sent();
    driver.set_full(true);
    assert_eq!(
        session.publish_aliased_auto_probe(7, None, b"x", remote()),
        Ok(WireProbe::NoRoom)
    );
    assert_eq!(
        session.publish_aliased_probe(7, None, b"x", remote()),
        Ok(WireProbe::NoRoom)
    );
    assert_eq!(driver.sent(), declared, "nothing was written");
}
