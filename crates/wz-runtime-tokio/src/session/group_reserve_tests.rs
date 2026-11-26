// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A publish sent on a group under room it reserved (`Session::reserve_on_group`,
//! `Session::publish_on_group_reserved`), which is how a group takes part in a publish that
//! reaches all of its links or none: the promise the group's lanes give, the whole fragment chain
//! it covers, and what a group with no link or a publish that owes it nothing are answered.

use super::*;
use crate::multicast_pipeline::{MulticastTxProducer, MulticastTxTap};
use crate::observer::ApplicationLayerObserver;
use crate::runtime_impl::TokioTime;
use wz_session_core::inbound::{parse_inbound, InboundFrame};
use wz_session_core::multicast_params::MulticastParams;
use wz_session_core::network_message::{parse_frame_payload, NetworkMessage};
use wz_session_core::qos::Priority;

/// A group of batch `batch_size` whose lane holds sixteen batches, and whose pushes wait a
/// millisecond for room at most: a push that asked a lane its own promises fill would be dropped
/// at once, and not wait the test out.
fn params(batch_size: u16) -> MulticastParams {
    MulticastParams {
        whatami: wz_session_core::WhatAmI::Peer,
        zid: [0xAA, 0xBB, 0xCC, 0xDD].into(),
        lease_ms: 5_000,
        join_interval_ms: 100,
        seq_num_res: 0x02,
        req_id_res: 0x02,
        batch_size,
        is_qos: false,
        compression: false,
        tx_queue: wz_session_core::session_init_params::TxQueueConf {
            sizes: [16; Priority::NUM],
            wait_before_drop_us: 1_000,
            wait_before_close_us: 1_000,
            ..wz_session_core::session_init_params::TxQueueConf::of_snapshot(
                &wz_session_core::policy::SessionPolicy::defaults(),
                &wz_session_core::limits::SessionLimits::BUILD,
            )
        },
        link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
        join_rule: wz_session_core::multicast_params::GroupJoinRule::Pico,
        max_sessions: None,
        policy: wz_session_core::policy::SessionPolicy::defaults(),
        limits: wz_session_core::limits::SessionLimits::BUILD,
    }
}

/// A group session that pushes through `producer`.
fn group_over(producer: MulticastTxProducer, params: &MulticastParams) -> TokioMulticastSession {
    let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
    Session::new_multicast(
        observer,
        Arc::new(TokioTime::new()),
        params.policy,
        producer,
    )
}

/// A group session of batch `batch_size` over a pipeline the test reads.
fn tapped(batch_size: u16) -> (TokioMulticastSession, MulticastTxTap) {
    let params = params(batch_size);
    let (producer, tap) = MulticastTxTap::attach(&params);
    (group_over(producer, &params), tap)
}

fn remote() -> PublishOptions<'static> {
    PublishOptions::put().with_locality(Locality::Remote)
}

/// The reservation the group grants for the publish of `payload` on `keyexpr`; the test fails
/// when the lane had no room for it.
fn granted(session: &TokioMulticastSession, keyexpr: &str, payload: &[u8]) -> GroupReservation {
    match session.reserve_on_group(keyexpr, None, payload, &remote()) {
        Ok(GroupRoom::Granted(reservation)) => reservation,
        Ok(GroupRoom::NoRoom) => panic!("the lane had no room for the publish"),
        Err(e) => panic!("the group could not reserve: {e:?}"),
    }
}

/// A payload past the group's batch is a chain of fragments, and its reservation takes the room
/// of every one of them at once, or of none: a lane one datagram short promises nothing and
/// pushes nothing, and one with exactly the chain's room takes it. Pushed under it while every
/// datagram of the lane is promised, the whole chain is on the lane, which a push that asked the
/// lane for room would not be. Turned red by a reserved push that asks the lane for room (the
/// chain is then a congestion drop and the lane holds nothing), or by a reservation of one
/// datagram for a chain.
#[cfg(feature = "transport-fragmentation")]
#[test]
fn a_group_reservation_takes_the_room_of_every_fragment_or_of_none() {
    let (session, mut tap) = tapped(128);
    let payload = vec![0x5a_u8; 600];

    // The lane's room in datagrams, counted by promises of a message that fits one.
    let mut singles = Vec::new();
    while let Ok(GroupRoom::Granted(one)) =
        session.reserve_on_group("home/one", None, b"x", &remote())
    {
        assert_eq!(one.datagrams(), 1);
        singles.push(one);
        assert!(singles.len() <= 64, "the lane never filled");
    }
    let room = singles.len();
    drop(singles);

    let chain = granted(&session, "home/chain", &payload);
    let frames = chain.datagrams();
    assert!(
        frames >= 2,
        "600 bytes at a batch of 128 is a chain, and every fragment of it is promised: {frames}"
    );
    assert!(
        room > frames,
        "the lane holds the chain and more: {room} for {frames}"
    );
    drop(chain);

    let mut others: Vec<GroupReservation> = (0..=room - frames)
        .map(|_| granted(&session, "home/one", b"x"))
        .collect();
    assert!(
        matches!(
            session.reserve_on_group("home/chain", None, &payload, &remote()),
            Ok(GroupRoom::NoRoom)
        ),
        "a lane one datagram short of the chain promises none of it"
    );
    assert!(tap.try_next().is_none(), "and nothing was pushed");

    others.pop();
    let chain = granted(&session, "home/chain", &payload);
    assert_eq!(chain.datagrams(), frames);
    assert_eq!(session.publish_on_group_reserved(chain), Ok(()));

    let mut fragments = 0usize;
    let mut last_more = true;
    while let Some(datagram) = tap.try_next() {
        let Ok(InboundFrame::Fragment { more, .. }) = parse_inbound(&datagram) else {
            panic!("every datagram of the chain is a fragment");
        };
        fragments += 1;
        last_more = more;
    }
    assert!(
        (2..=frames).contains(&fragments),
        "the whole chain is on the lane, within what was promised: {fragments} of {frames}"
    );
    assert!(!last_more, "the chain ends with its last fragment");
    drop(others);
}

/// A publish that fits one frame is one Push on the group, pushed under the one datagram of room
/// its reservation holds.
#[test]
fn a_reserved_publish_that_fits_a_frame_puts_one_push_on_the_group() {
    let (session, mut tap) = tapped(2_048);
    let reservation = granted(&session, "home/one", b"x");
    assert!(reservation.is_held());
    assert_eq!(reservation.datagrams(), 1);

    assert_eq!(session.publish_on_group_reserved(reservation), Ok(()));

    let datagram = tap.try_next().expect("the publish pushed a datagram");
    let Ok(InboundFrame::Frame { payload, .. }) = parse_inbound(&datagram) else {
        panic!("the pushed datagram is a Frame");
    };
    let messages = parse_frame_payload(&payload).expect("the frame decodes");
    assert_eq!(messages.len(), 1);
    assert!(matches!(messages[0], NetworkMessage::Push(_)));
    assert!(tap.try_next().is_none(), "one datagram");
}

/// A publish that may not go remote owes the group nothing: its reservation holds no room, and
/// sending under it pushes nothing.
#[test]
fn a_publish_that_may_not_go_remote_owes_the_group_nothing() {
    let (session, mut tap) = tapped(2_048);
    let local = PublishOptions::put().with_locality(Locality::SessionLocal);
    let Ok(GroupRoom::Granted(reservation)) =
        session.reserve_on_group("home/one", None, b"x", &local)
    else {
        panic!("a publish that owes the group nothing is granted");
    };
    assert!(!reservation.is_held());
    assert_eq!(reservation.datagrams(), 0);
    assert_eq!(session.publish_on_group_reserved(reservation), Ok(()));
    assert!(tap.try_next().is_none());
}

/// A group with no link has no room to promise and takes no part: it is answered as a link that
/// is down is, and not as a lane with no room, which would end the publish for every link.
#[test]
fn a_group_with_no_link_is_answered_unavailable() {
    let params = params(2_048);
    let session = group_over(MulticastTxProducer::new(), &params);
    assert!(matches!(
        session.reserve_on_group("home/one", None, b"x", &remote()),
        Err(PublishError::TransportUnavailable)
    ));
}
