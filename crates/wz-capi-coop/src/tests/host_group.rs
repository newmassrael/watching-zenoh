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

use crate::tests::host_links;
use crate::EngineHold;
use wz_capi_port::group::{GroupDeclarations, GroupJoin, GroupProfile};
#[cfg(feature = "threads")]
use wz_capi_port::SessionDrive;
use wz_capi_port::{PeerLists, SessionEngine, SubscriberSink, WireKey};
use wz_runtime_coop::ip_stack::IpLinks;
use wz_runtime_coop::session_drive::WaitedByOwner;
use wz_runtime_coop::stream_link::NoDial;
use wz_runtime_posix::net::PosixUdpSocket;
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::locality::Locality;
use wz_session_core::multicast_params::GroupJoinRule;
use wz_session_core::policy::{MulticastLoopback, SessionPolicy};
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::sink::SampleView;
use wz_session_core::WhatAmI;

#[cfg(not(feature = "threads"))]
use super::one_thread::OwnThread;
use super::{client_config, config_zid};
use crate::host_group::HostGroups;
use crate::{CoopConfig, CoopEngine};

/// The host's links, joining groups on the host's sockets, counted as the engine counts the links
/// it opens over (`host_links` hands them so) and waited for by their owner.
type Links = IpLinks<
    PosixUdpSocket,
    PosixTcpDial,
    NoDial,
    HostGroups<PosixUdpSocket>,
    crate::LinkCount,
    WaitedByOwner,
>;

type Engine = CoopEngine<Links, PosixClock>;

/// What every member's beacon advertises: zenoh-pico's terms, beaconed often so the members
/// learn each other within the test.
fn profile() -> GroupProfile {
    GroupProfile {
        lease_ms: 10_000,
        join_interval_ms: 100,
        max_sessions: None,
        seq_num_res: wz_session_core::policy::SnResolution::Bits32,
        req_id_res: 0x02,
        batch_size: 2_048,
        is_qos: false,
        compression: false,
        join_rule: GroupJoinRule::Pico,
    }
}

/// A peer of id `member` that dials nothing and joins `endpoint`, under `policy`, on the host's
/// sockets.
fn open_member(member: u8, endpoint: &str, policy: SessionPolicy) -> EngineHold<Engine> {
    open_member_with(member, endpoint, policy, |_| {})
}

/// [`open_member`], its config tuned by `tune` before the open.
fn open_member_with(
    member: u8,
    endpoint: &str,
    policy: SessionPolicy,
    tune: impl FnOnce(&mut CoopConfig),
) -> EngineHold<Engine> {
    let mut config = CoopConfig {
        whatami: WhatAmI::Peer,
        zid: config_zid(member),
        groups: vec![GroupJoin {
            endpoint: endpoint.to_owned(),
            profile: profile(),
            is_shm: false,
            declarations: GroupDeclarations::Entities,
        }],
        ..client_config()
    };
    tune(&mut config);
    let links = host_links([0, 0, 0, 0], PosixTcpDial)
        .waited_by_owner()
        .with_groups(HostGroups::<PosixUdpSocket>::of_policy(&policy));
    Engine::open_with_policy(links, PosixClock, PosixEntropy, config, policy)
        .expect("the member joins the group on the host's sockets")
}

/// Wait, for at most five seconds, until `done`: each session is stepped by a thread of its own.
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
#[cfg(feature = "threads")]
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
        first.group_member_zids() == [vec![2u8; 4]] && second.group_member_zids() == [vec![1u8; 4]]
    });

    let heard = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let into = Arc::clone(&heard);
    second
        .declare_subscriber_on_wire(
            "demo/host-group/**",
            WireKey::literal(),
            Locality::Any,
            None,
            {
                let into = Arc::clone(&into);
                SubscriberSink::shared(move |sample: &dyn SampleView| {
                    into.lock().unwrap().push(sample.payload().to_vec());
                })
            },
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
        first.group_member_zids().is_empty()
    });
    SessionDrive::close(&*first);
}

/// The same two members in the form of one thread, each opened, called and read on a thread of its
/// own ([`OwnThread`]): their own reads beacon and take the JOINs, a put of the first reaches the
/// second's subscriber over the group, and the second, closed, tells the group it leaves.
#[cfg(not(feature = "threads"))]
#[test]
#[ignore = "environment-dependent: needs a multicast route on this host (Layer M runs it)"]
fn two_members_of_one_thread_on_the_hosts_sockets_learn_each_other() {
    let port = UdpSocket::bind("0.0.0.0:0")
        .and_then(|probe| probe.local_addr())
        .expect("a free port")
        .port();
    let endpoint = format!("udp/239.255.77.13:{port}");
    let mut policy = SessionPolicy::defaults();
    let _ = policy.select_multicast_loopback(MulticastLoopback::On);
    let member = |id: u8| {
        let endpoint = endpoint.clone();
        OwnThread::open(move || open_member(id, &endpoint, policy))
    };
    let first = member(1);
    let second = member(2);
    eventually("each member to list the other", || {
        first.call(|engine| engine.group_member_zids()) == [vec![2u8; 4]]
            && second.call(|engine| engine.group_member_zids()) == [vec![1u8; 4]]
    });

    let heard = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let into = Arc::clone(&heard);
    second.call(move |engine| {
        engine
            .declare_subscriber_on_wire(
                "demo/host-group/**",
                WireKey::literal(),
                Locality::Any,
                None,
                SubscriberSink::shared(move |sample: &dyn SampleView| {
                    into.lock().unwrap().push(sample.payload().to_vec());
                }),
            )
            .expect("a session with ids left declares");
    });
    eventually("a put of the first to reach the second", || {
        first.call(|engine| {
            engine
                .publish_on_wire_all(
                    "demo/host-group/a",
                    &WireKey::literal(),
                    b"over-the-hosts-group",
                    &PublishOptions::put().with_locality(Locality::Remote),
                )
                .expect("a put the group carries");
        });
        heard
            .lock()
            .unwrap()
            .iter()
            .any(|payload| payload == b"over-the-hosts-group")
    });

    drop(second);
    eventually("the first member to lose the second", || {
        first.call(|engine| engine.group_member_zids()).is_empty()
    });
}

/// A session that listens and joins a group reads its quiet client face and the group in one run
/// of its read task: puts from its client and from another member of the group, in turn, each its
/// own batch, are each heard, and cost the face a few turns between them, not one a batch. The
/// CONTROL is the face found quiet beside the group, which a look refused while any group was
/// joined. Turned red by a look that refuses a face for a joined group
/// (`CoopEngine::quiet_until`), a run that refuses a group owing a whole read nothing
/// (`GroupFace::in_run`), or a kept set that leaves the group's input out
/// (`LinkSupervisor::run_waits`), whose datagrams would then wait for the run's deadline.
#[cfg(all(
    feature = "threads",
    feature = "listen",
    feature = "query",
    feature = "queryable",
    not(wz_round)
))]
#[test]
#[ignore = "environment-dependent: needs a multicast route on this host (Layer M runs it)"]
fn a_quiet_read_reads_a_face_and_a_group_in_one_run() {
    const PUTS: usize = 40;
    let port = UdpSocket::bind("0.0.0.0:0")
        .and_then(|probe| probe.local_addr())
        .expect("a free port")
        .port();
    let endpoint = format!("udp/239.255.77.14:{port}");
    let mut policy = SessionPolicy::defaults();
    let _ = policy.select_multicast_loopback(MulticastLoopback::On);
    // Beacons a second apart, so the run's deadline is the look's and not the next JOIN's.
    let slow_beacon = |config: &mut CoopConfig| {
        for group in &mut config.groups {
            group.profile.join_interval_ms = 1_000;
        }
    };
    let listener = open_member_with(1, &endpoint, policy, |config| {
        slow_beacon(config);
        config.listen = vec!["tcp/127.0.0.1:0".to_owned()];
        config.idle_wait_ms = 1_000;
        config.lease_ms = 60_000;
    });
    let member = open_member_with(2, &endpoint, policy, slow_beacon);
    let port_endpoint = listener.listening().pop().expect("one port is bound");
    // The client's open waits for the listener's answer, which only a read of the listener reads.
    for engine in [&listener, &member] {
        SessionDrive::start_read_task(&**engine).expect("the read task starts");
    }
    let client = Engine::open_with_policy(
        host_links([0, 0, 0, 0], PosixTcpDial)
            .waited_by_owner()
            .with_groups(HostGroups::<PosixUdpSocket>::of_policy(&policy)),
        PosixClock,
        PosixEntropy,
        CoopConfig {
            endpoints: vec![port_endpoint],
            zid: config_zid(3),
            ..client_config()
        },
        policy,
    )
    .expect("the client dials the listener");
    SessionDrive::start_read_task(&*client).expect("the read task starts");
    eventually("the members to list each other", || {
        listener.group_member_zids() == [vec![2u8; 4]]
            && member.group_member_zids() == [vec![1u8; 4]]
    });
    let heard = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = Arc::clone(&heard);
    listener
        .declare_subscriber_on_wire("demo/run/**", WireKey::literal(), Locality::Any, None, {
            SubscriberSink::shared(move |_sample: &dyn SampleView| {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        })
        .expect("the listener declares the subscriber");
    let heard_now = || heard.load(std::sync::atomic::Ordering::SeqCst);
    let put = |from: &Engine| {
        from.publish_on_wire_all(
            "demo/run/x",
            &WireKey::literal(),
            b"r",
            &PublishOptions::put().with_locality(Locality::Remote),
        )
        .expect("a put the link or the group carries");
    };
    let sources: [&Engine; 2] = [&client, &member];
    for from in sources {
        let before = heard_now();
        eventually("a put heard once its sender knows the subscriber", || {
            put(from);
            std::thread::sleep(Duration::from_millis(10));
            heard_now() > before
        });
    }
    eventually("CONTROL: the face found quiet beside the group", || {
        listener.quiet_faces() == 1
    });
    let from = heard_now();
    let turns = listener
        .takes
        .face_turns
        .load(std::sync::atomic::Ordering::SeqCst);
    for n in 1..=PUTS {
        put(sources[n % 2]);
        eventually("the put heard", || heard_now() >= from + n);
    }
    let turns = listener
        .takes
        .face_turns
        .load(std::sync::atomic::Ordering::SeqCst)
        - turns;
    assert!(
        turns * 4 < PUTS,
        "the face was turned {turns} times for {PUTS} batches beside the group"
    );
    for engine in [&client, &member, &listener] {
        SessionDrive::close(&**engine);
    }
}
