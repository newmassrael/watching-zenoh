// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Sessions that join one multicast group over the host's own sockets: the host's links given the
//! host's joiner (`HostGroups`), and the same group face the program's transport carries. The
//! members learn each other from their JOINs alone and a put crosses the group. The group is a
//! real one, so the test needs a multicast route on the host, as every group test of the host's
//! sockets does.

use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_port::group::{GroupDeclarations, GroupJoin, GroupProfile};
use wz_capi_port::{SessionDrive, SessionEngine, WireKey};
use wz_runtime_coop::ip_stack::IpLinks;
use wz_runtime_coop::stream_link::NoDial;
use wz_runtime_posix::links::PosixLinks;
use wz_runtime_posix::net::PosixUdpSocket;
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::locality::Locality;
use wz_session_core::multicast_params::GroupJoinRule;
use wz_session_core::policy::{MulticastLoopback, SessionPolicy};
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::sink::SampleView;
use wz_session_core::WhatAmI;

use super::client_config;
use crate::host_group::HostGroups;
use crate::{CoopConfig, CoopEngine};

/// The host's links, joining groups on the host's sockets.
type Links = IpLinks<PosixUdpSocket, PosixTcpDial, NoDial, HostGroups>;

type Engine = CoopEngine<Links, PosixClock>;

/// What every member's beacon advertises: zenoh-pico's terms, beaconed often so the members
/// learn each other within the test.
fn profile() -> GroupProfile {
    GroupProfile {
        lease_ms: 10_000,
        join_interval_ms: 100,
        max_sessions: None,
        seq_num_res: 0x02,
        req_id_res: 0x02,
        batch_size: 2_048,
        is_qos: false,
        compression: false,
        join_rule: GroupJoinRule::Pico,
    }
}

/// A peer of id `member` that dials nothing and joins `endpoint`, under `policy`, on the host's
/// sockets.
fn open_member(member: u8, endpoint: &str, policy: SessionPolicy) -> Arc<Engine> {
    let config = CoopConfig {
        whatami: WhatAmI::Peer,
        zid: Some(vec![member; 4]),
        groups: vec![GroupJoin {
            endpoint: endpoint.to_owned(),
            profile: profile(),
            is_shm: false,
            declarations: GroupDeclarations::Entities,
        }],
        ..client_config()
    };
    let links = PosixLinks::new([0, 0, 0, 0], PosixTcpDial)
        .waited_by_owner()
        .with_groups(HostGroups::of_policy(&policy));
    Engine::open_with_policy(links, PosixClock, PosixEntropy, config, policy)
        .expect("the member joins the group on the host's sockets")
}

/// Wait, for at most five seconds, until `done`: each session is stepped by its read task.
fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Two sessions of this host join one group on the host's sockets, learn each other by their
/// JOINs, and a put of the first reaches the second's subscriber over the group. Closing the
/// second tells the group it leaves, which the first hears before any lease runs out.
#[test]
#[ignore = "environment-dependent: needs a multicast route on this host (Layer M runs it)"]
fn two_members_on_the_hosts_sockets_learn_each_other_and_a_put_crosses_the_group() {
    // A port no other group of this host is on: the members share it, the group's port.
    let port = UdpSocket::bind("0.0.0.0:0")
        .and_then(|probe| probe.local_addr())
        .expect("a free port")
        .port();
    let endpoint = format!("udp/239.255.77.12:{port}");
    // Each member hears the other on this one host: the loopback a build lets a session select,
    // the host's own setting otherwise (on, on the hosts that run the test).
    let mut policy = SessionPolicy::defaults();
    let _ = policy.select_multicast_loopback(MulticastLoopback::On);
    let first = open_member(1, &endpoint, policy);
    let second = open_member(2, &endpoint, policy);
    SessionDrive::start_read_task(&*first).expect("the first's read task starts");
    SessionDrive::start_read_task(&*second).expect("the second's read task starts");
    eventually("each member to list the other", || {
        first.peer_identities() == [(vec![2u8; 4], 1u8)]
            && second.peer_identities() == [(vec![1u8; 4], 1u8)]
    });

    let heard = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let into = Arc::clone(&heard);
    second
        .declare_subscriber_on_wire(
            "demo/host-group/**".to_owned(),
            WireKey::literal(),
            Locality::Any,
            None,
            Arc::new(move || {
                let into = Arc::clone(&into);
                Box::new(move |sample: &dyn SampleView| {
                    into.lock().unwrap().push(sample.payload().to_vec());
                })
            }),
        )
        .expect("a session with ids left declares");
    eventually("a put of the first to reach the second", || {
        first
            .publish_on_wire_all(
                "demo/host-group/a",
                &WireKey::literal(),
                b"over-the-hosts-group",
                &PublishOptions::put().with_locality(Locality::Remote),
            )
            .expect("a put the group carries");
        heard
            .lock()
            .unwrap()
            .iter()
            .any(|payload| payload == b"over-the-hosts-group")
    });

    SessionDrive::close(&*second);
    eventually("the first member to lose the second", || {
        first.peer_identities().is_empty()
    });
    SessionDrive::close(&*first);
}
