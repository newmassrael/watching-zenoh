// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Sessions that join one multicast group over a transport the program supplies, and nothing
//! else: no link, no socket. The program's stack here is an in-memory group: each member's
//! datagram is handed to every other member with the address the sender is known by, as a group
//! socket hands it in. The members learn each other only from the JOINs their sessions beacon, a
//! put crosses the group, and a session that closes tells the group it leaves and lets its stack
//! leave the group.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use wz_capi_port::group::{GroupDeclarations, GroupJoin, GroupProfile};
use wz_capi_port::{SessionDrive, SessionEngine, WireKey};
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::app_link_table::{
    AppLinkKind, AppLinkTable, LinkHandle, ProgramOpen, ProgramSend,
};
use wz_session_core::app_transport::{AppPort, AppTransport, TableLock};
use wz_session_core::locality::Locality;
use wz_session_core::multicast_params::GroupJoinRule;
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::sink::SampleView;
use wz_session_core::WhatAmI;

use super::client_config;
use crate::app_link::AppLinks;
use crate::{CoopConfig, CoopEngine, OpenError};

type Engine = CoopEngine<AppLinks, PosixClock>;

/// The group every member joins. Synthetic: no socket is opened for it.
const GROUP: &str = "udp/239.7.7.7:7447#iface=lan7";

/// The address a member's datagrams come from.
fn source(member: u8) -> String {
    format!("udp/192.0.2.{member}:7447")
}

/// The group as the members' stacks share it.
#[derive(Default)]
struct Network {
    /// Each member's group link and its transport.
    joined: Mutex<Vec<Joined>>,
    /// How many times a member's stack was told to leave the group.
    leaves: AtomicUsize,
}

struct Joined {
    member: u8,
    link: LinkHandle,
    transport: Weak<AppTransport>,
}

/// One member's stack: it joins [`GROUP`] and refuses anything else, and hands what its session
/// sends on the group to every other member, from [`source`].
struct MemberStack {
    network: Arc<Network>,
    member: u8,
    /// Its own transport, given once the transport is made over this stack.
    transport: Arc<Mutex<Weak<AppTransport>>>,
}

impl AppPort for MemberStack {
    fn open(&self, link: LinkHandle, kind: AppLinkKind, locator: &str) -> ProgramOpen {
        if kind != AppLinkKind::Group || locator != GROUP {
            return ProgramOpen::Refused;
        }
        let transport = self.transport.lock().unwrap().clone();
        self.network.joined.lock().unwrap().push(Joined {
            member: self.member,
            link,
            transport,
        });
        ProgramOpen::Up
    }

    fn send(&self, _link: LinkHandle, bytes: &[u8]) -> ProgramSend {
        let others: Vec<(LinkHandle, Arc<AppTransport>)> = self
            .network
            .joined
            .lock()
            .unwrap()
            .iter()
            .filter(|joined| joined.member != self.member)
            .filter_map(|joined| Some((joined.link, joined.transport.upgrade()?)))
            .collect();
        let from = source(self.member);
        for (link, transport) in others {
            // A member that cannot take it now drops it, as a group socket does.
            let _ = transport.received(link, bytes, Some(from.as_str()));
        }
        ProgramSend::Wrote(bytes.len())
    }

    fn close(&self, link: LinkHandle) {
        self.network
            .joined
            .lock()
            .unwrap()
            .retain(|joined| !(joined.member == self.member && joined.link == link));
        self.network.leaves.fetch_add(1, Ordering::SeqCst);
    }
}

/// The table of a member's transport, under the host's lock.
struct Table(Mutex<AppLinkTable>);

impl TableLock for Table {
    fn lock_with(&self, f: &mut dyn FnMut(&mut AppLinkTable)) {
        f(&mut self.0.lock().unwrap());
    }
}

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

/// A peer's config that dials nothing and joins `endpoint`.
fn member_config(member: u8, endpoint: &str) -> CoopConfig {
    CoopConfig {
        whatami: WhatAmI::Peer,
        zid: Some(vec![member; 4]),
        groups: vec![GroupJoin {
            endpoint: endpoint.to_owned(),
            profile: profile(),
            is_shm: false,
            declarations: GroupDeclarations::Entities,
        }],
        ..client_config()
    }
}

/// Open a session for `member` over a stack of `network`.
fn open_member(
    network: &Arc<Network>,
    member: u8,
    config: CoopConfig,
) -> Result<Arc<Engine>, OpenError> {
    let own = Arc::new(Mutex::new(Weak::new()));
    let transport = Arc::new(AppTransport::new(
        Box::new(Table(Mutex::new(AppLinkTable::new()))),
        Box::new(MemberStack {
            network: Arc::clone(network),
            member,
            transport: Arc::clone(&own),
        }),
    ));
    *own.lock().unwrap() = Arc::downgrade(&transport);
    Engine::open(AppLinks::new(transport), PosixClock, PosixEntropy, config)
}

/// Wait, for at most five seconds, until `done`: each session is stepped by its read task.
fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn two_members_learn_each_other_by_their_joins_and_a_put_crosses_the_group() {
    let network = Arc::new(Network::default());
    let first = open_member(&network, 1, member_config(1, GROUP)).expect("the first joins");
    let second = open_member(&network, 2, member_config(2, GROUP)).expect("the second joins");
    assert_eq!(
        network.joined.lock().unwrap().len(),
        2,
        "each session asked its stack to join the group, and dialled nothing"
    );
    SessionDrive::start_read_task(&*first).expect("the first's read task starts");
    SessionDrive::start_read_task(&*second).expect("the second's read task starts");

    // Each member is known to the other from the other's JOIN alone, by its zid and its role
    // (1, a peer).
    until_members_know_each_other(&first, &second);

    let heard = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let into = Arc::clone(&heard);
    second
        .declare_subscriber_on_wire(
            "demo/group/**".to_owned(),
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
    first
        .publish_on_wire_all(
            "demo/group/a",
            &WireKey::literal(),
            b"over-the-group",
            &PublishOptions::put().with_locality(Locality::Remote),
        )
        .expect("a put the group carries");
    eventually("the second member to hear the put", || {
        heard
            .lock()
            .unwrap()
            .iter()
            .any(|payload| payload == b"over-the-group")
    });

    // Closing the second session tells the group it leaves, which the first hears before any
    // lease runs out, and lets its stack leave the group.
    SessionDrive::close(&*second);
    assert_eq!(
        network.leaves.load(Ordering::SeqCst),
        1,
        "the closed session's stack left the group"
    );
    eventually("the first member to lose the second", || {
        first.peer_identities().is_empty()
    });
    SessionDrive::close(&*first);
    assert_eq!(network.leaves.load(Ordering::SeqCst), 2);
}

#[test]
fn a_group_the_stack_does_not_join_fails_the_open_by_name() {
    let network = Arc::new(Network::default());
    // A datagram listen names no group, and is refused before the stack is asked; a group the
    // stack refuses to join is refused when it answers.
    for endpoint in ["udp/192.0.2.9:7447", "udp/239.9.9.9:7447#iface=lan9"] {
        match open_member(&network, 1, member_config(1, endpoint)) {
            Err(OpenError::Group(why)) => assert!(why.starts_with(endpoint), "{why}"),
            Err(other) => panic!("{endpoint}: refused as {other:?}"),
            Ok(_) => panic!("{endpoint}: opened"),
        }
    }
    assert!(
        network.joined.lock().unwrap().is_empty(),
        "no member joined a group"
    );
}

/// Wait until the two members each list the other, which is when a member reads what the other
/// sends: a group admits a member's frames only once it heard that member's JOIN.
fn until_members_know_each_other(first: &Engine, second: &Engine) {
    eventually("each member to list the other", || {
        first.peer_identities() == [(vec![2u8; 4], 1u8)]
            && second.peer_identities() == [(vec![1u8; 4], 1u8)]
    });
}

/// The asking and the answering end over the group: a get asked of the group is answered by a
/// member's queryable, its reply and its Final going back on the group, and a get asked while the
/// group holds no member reaches nobody.
#[cfg(all(feature = "query", feature = "queryable"))]
mod asked {
    use std::sync::{Arc, Mutex};

    use wz_capi_port::{
        QueryCallback, QueryHolder, ReplyCallback, SessionDrive, SessionEngine, WireKey,
    };
    use wz_session_core::locality::Locality;
    use wz_session_core::query_options::QueryOptions;
    use wz_session_core::query_sink::{QueryView, ReplyOut};
    use wz_session_core::reply_sink::{ReplyKind, ReplyView};

    use super::{
        eventually, member_config, open_member, until_members_know_each_other, Engine, Network,
        GROUP,
    };

    /// What the legs of a get saw: each reply as its kind, key and payload, and whether every
    /// leg's callback is gone, which is when the get is over.
    #[derive(Default)]
    struct Seen {
        replies: Vec<(ReplyKind, String, Vec<u8>)>,
        open: usize,
        ended: bool,
    }

    /// Owned by a leg's callback: the get is over when the last one is dropped.
    struct Ends(Arc<Mutex<Seen>>);

    impl Drop for Ends {
        fn drop(&mut self) {
            let mut seen = self.0.lock().unwrap();
            seen.open -= 1;
            seen.ended = seen.open == 0;
        }
    }

    /// Ask the peers of `engine` on `keyexpr`, with a deadline long past the test's waits.
    fn ask(engine: &Engine, keyexpr: &str) -> (Option<usize>, Arc<Mutex<Seen>>) {
        let mut opts = QueryOptions::get();
        opts.allowed_destination = Locality::Remote;
        opts.timeout_ms = 3_000;
        let seen = Arc::new(Mutex::new(Seen::default()));
        let into = Arc::clone(&seen);
        let issued = engine.get_on_wire(keyexpr, &WireKey::literal(), &opts, None, &mut || {
            into.lock().unwrap().open += 1;
            let ends = Ends(Arc::clone(&into));
            Box::new(move |view: &dyn ReplyView| {
                ends.0.lock().unwrap().replies.push((
                    view.kind(),
                    view.keyexpr().to_owned(),
                    view.payload().to_vec(),
                ));
            }) as ReplyCallback
        });
        (issued, seen)
    }

    /// Declare a queryable on `keyexpr` of `engine` that answers each query with `payload`.
    fn serve(engine: &Engine, keyexpr: &str, payload: &'static [u8]) {
        engine
            .declare_queryable_on_wire(
                keyexpr.to_owned(),
                WireKey::literal(),
                false,
                Locality::Remote,
                None,
                Arc::new(move |_holder: Arc<dyn QueryHolder>| {
                    Box::new(move |query: &dyn QueryView, out: &mut dyn ReplyOut| {
                        out.reply_keyed(query.keyexpr(), payload)
                            .expect("a reply on the query's own key");
                    }) as QueryCallback
                }),
            )
            .expect("the engine has queryables in this build");
    }

    #[test]
    fn a_get_of_the_group_is_answered_by_a_members_queryable_and_ends_with_its_final() {
        let network = Arc::new(Network::default());
        let first = open_member(&network, 1, member_config(1, GROUP)).expect("the first joins");
        SessionDrive::start_read_task(&*first).expect("the first's read task starts");

        // Alone in the group: the group is owed no Final, so the get asks nobody.
        let (issued, seen) = ask(&first, "demo/group/ask");
        assert_eq!(issued, Some(0), "a group with no member is asked nothing");
        assert!(seen.lock().unwrap().replies.is_empty());

        let second = open_member(&network, 2, member_config(2, GROUP)).expect("the second joins");
        SessionDrive::start_read_task(&*second).expect("the second's read task starts");
        serve(&second, "demo/group/**", b"answer-over-the-group");
        until_members_know_each_other(&first, &second);

        // One leg, owed one Final by the one member: the reply and the Final come back on the
        // group, long before the deadline would end the leg with a timeout.
        let (issued, seen) = ask(&first, "demo/group/ask");
        assert_eq!(issued, Some(1), "one leg: the group");
        eventually("the leg to end", || seen.lock().unwrap().ended);
        assert_eq!(
            seen.lock().unwrap().replies,
            vec![(
                ReplyKind::Put,
                "demo/group/ask".to_owned(),
                b"answer-over-the-group".to_vec()
            )]
        );
        SessionDrive::close(&*second);
        SessionDrive::close(&*first);
    }
}
