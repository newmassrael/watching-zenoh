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
use wz_capi_port::{
    BatchStep, FilterPlane, PeerLists, SessionDrive, SessionEngine, SubscriberSink, WireKey,
};
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::app_link_table::{
    AppLinkKind, AppLinkTable, LinkHandle, ProgramEvent, ProgramOpen, ProgramSend,
};
use wz_session_core::app_transport::{AppPort, AppTransport, SessionTransport, TableLock};
use wz_session_core::locality::Locality;
use wz_session_core::multicast_params::GroupJoinRule;
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::sink::SampleView;
use wz_session_core::wire_const::T_MID_JOIN;
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
    /// Each member whose stack was asked to join the group, once per join.
    joins: Mutex<Vec<u8>>,
    /// Each member that sent a JOIN beacon on the group, once per beacon.
    beacons: Mutex<Vec<u8>>,
    /// Each datagram a member sent on the group, with the member (read by the tests of a get).
    #[cfg(feature = "query")]
    datagrams: Mutex<Vec<(u8, Vec<u8>)>>,
}

impl Network {
    /// How many JOIN beacons `member` sent on the group.
    fn beacons_of(&self, member: u8) -> usize {
        self.beacons
            .lock()
            .unwrap()
            .iter()
            .filter(|sent| **sent == member)
            .count()
    }

    /// How many times `member`'s stack was asked to join the group.
    fn joins_of(&self, member: u8) -> usize {
        self.joins
            .lock()
            .unwrap()
            .iter()
            .filter(|joined| **joined == member)
            .count()
    }

    /// `member`'s stack loses its group link, as an interface that goes down loses it: the stack
    /// tells the session the link is closed.
    fn cut(&self, member: u8) {
        let lost: Vec<Joined> = {
            let mut joined = self.joined.lock().unwrap();
            let (lost, kept) = joined.drain(..).partition(|j| j.member == member);
            *joined = kept;
            lost
        };
        for joined in lost {
            if let Some(transport) = joined.transport.upgrade() {
                let _ = transport.event(joined.link, ProgramEvent::Closed);
            }
        }
    }
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
        self.network.joins.lock().unwrap().push(self.member);
        self.network.joined.lock().unwrap().push(Joined {
            member: self.member,
            link,
            transport,
        });
        ProgramOpen::Up
    }

    fn send(&self, _link: LinkHandle, bytes: &[u8]) -> ProgramSend {
        // A beacon is sent alone in its datagram; the low five bits of a header are its id.
        if bytes
            .first()
            .is_some_and(|header| header & 0x1f == T_MID_JOIN)
        {
            self.network.beacons.lock().unwrap().push(self.member);
        }
        #[cfg(feature = "query")]
        self.network
            .datagrams
            .lock()
            .unwrap()
            .push((self.member, bytes.to_vec()));
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
    let links = AppLinks::new(SessionTransport::new(transport, &config.limits));
    Engine::open(links, PosixClock, PosixEntropy, config)
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

    // Each member is known to the other from the other's JOIN alone, by its zid, and as a
    // member of the group and not a peer of a link.
    until_members_know_each_other(&first, &second);
    assert!(first.peer_identities().is_empty() && second.peer_identities().is_empty());

    let heard = subscribe(&second, "demo/group/**");
    put(&first, "demo/group/a", b"over-the-group");
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
        first.group_member_zids().is_empty()
    });
    SessionDrive::close(&*first);
    assert_eq!(network.leaves.load(Ordering::SeqCst), 2);
}

/// A JOIN asked of the session between two beacons is sent at once, and the cadence goes on from
/// it: a member whose beacon is due every minute sends its first at the open, none more while
/// nothing asks, and a second when the session is asked for one. A session that closed asks no
/// group.
#[test]
fn a_join_asked_between_two_beacons_is_sent_at_once() {
    let network = Arc::new(Network::default());
    let mut config = member_config(1, GROUP);
    config.groups[0].profile.lease_ms = 180_000;
    config.groups[0].profile.join_interval_ms = 60_000;
    let member = open_member(&network, 1, config).expect("the member joins");
    SessionDrive::start_read_task(&*member).expect("the read task starts");
    eventually("the beacon of the open", || network.beacons_of(1) == 1);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(network.beacons_of(1), 1, "no beacon is due within a minute");

    assert_eq!(
        member.send_join_on_groups(),
        Ok(1),
        "the one group is asked"
    );
    eventually("the JOIN asked for", || network.beacons_of(1) == 2);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(network.beacons_of(1), 2, "and the cadence runs from it");

    SessionDrive::close(&*member);
    assert_eq!(
        member.send_join_on_groups(),
        Err(wz_capi_port::Refusal::Closed),
        "a closed session asks no group, and says why"
    );
}

#[test]
fn a_group_the_stack_does_not_join_fails_the_open_by_name() {
    let network = Arc::new(Network::default());
    // A datagram listen names no group, and is refused before the stack is asked; a group the
    // stack refuses to join is refused when it answers.
    for endpoint in ["udp/192.0.2.9:7447", "udp/239.9.9.9:7447#iface=lan9"] {
        match open_member(&network, 1, member_config(1, endpoint)) {
            Err(OpenError::Group(why)) => assert!(why.endpoint.starts_with(endpoint), "{why}"),
            Err(other) => panic!("{endpoint}: refused as {other:?}"),
            Ok(_) => panic!("{endpoint}: opened"),
        }
    }
    assert!(
        network.joined.lock().unwrap().is_empty(),
        "no member joined a group"
    );
}

/// A session told to join a group past its task cells is refused for want of a task cell, as its
/// spawn would be, whether a face set is left for the group or not: `max_faces` of none leaves
/// none past the groups the cells hold, one leaves a set and the spawn refuses. The CONTROL is the
/// session told to join as many groups as the cells hold, which opens.
#[test]
fn a_group_past_the_task_cells_is_refused_for_want_of_a_task() {
    use wz_runtime_coop::executor::SpawnRefusal;
    use wz_session_core::caps::MAX_TASKS;

    let network = Arc::new(Network::default());
    let told = |groups: usize, max_faces: usize| {
        let mut config = member_config(1, GROUP);
        let join = config.groups[0].clone();
        config.groups = vec![join; groups];
        config.max_faces = max_faces;
        config
    };
    let held = open_member(&network, 1, told(MAX_TASKS, 0)).expect("CONTROL: the cells hold them");
    SessionDrive::close(&*held);
    for max_faces in [0, 1] {
        assert_eq!(
            open_member(&network, 2, told(MAX_TASKS + 1, max_faces)).err(),
            Some(OpenError::NoTask(SpawnRefusal::NoTaskCell)),
            "max_faces {max_faces}"
        );
    }
}

/// Declare a subscriber on `keyexpr` of `engine`, and the payloads it is handed, in order.
fn subscribe(engine: &Engine, keyexpr: &str) -> Arc<Mutex<Vec<Vec<u8>>>> {
    let heard = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let into = Arc::clone(&heard);
    engine
        .declare_subscriber_on_wire(keyexpr, WireKey::literal(), Locality::Any, None, {
            let into = Arc::clone(&into);
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                into.lock().unwrap().push(sample.payload().to_vec());
            })
        })
        .expect("a session with ids left declares");
    heard
}

/// Put `payload` on `keyexpr` from `engine`, for its peers alone.
fn put(engine: &Engine, keyexpr: &str, payload: &[u8]) {
    engine
        .publish_on_wire_all(
            keyexpr,
            &WireKey::literal(),
            payload,
            &PublishOptions::put().with_locality(Locality::Remote),
        )
        .expect("a put the group carries");
}

/// A member whose stack loses its group link lets the group go, and joins it again a redial
/// period later with a session of its own: the stack is asked to join a second time, the members
/// learn each other again by their JOINs, and a put crosses the group again. A member that
/// redials nothing would not join again, so the session here redials every 100 ms.
#[test]
fn a_member_whose_group_link_is_lost_joins_the_group_again() {
    let network = Arc::new(Network::default());
    let redialling = |member: u8| CoopConfig {
        redial_ms: Some(100),
        ..member_config(member, GROUP)
    };
    let first = open_member(&network, 1, redialling(1)).expect("the first joins");
    let second = open_member(&network, 2, redialling(2)).expect("the second joins");
    SessionDrive::start_read_task(&*first).expect("the first's read task starts");
    SessionDrive::start_read_task(&*second).expect("the second's read task starts");
    until_members_know_each_other(&first, &second);
    assert_eq!(network.joins_of(2), 1);

    network.cut(2);
    eventually(
        "the second member's stack to be asked to join again",
        || network.joins_of(2) == 2,
    );
    until_members_know_each_other(&first, &second);
    let heard = subscribe(&second, "demo/group/**");
    eventually("a put to cross the group joined again", || {
        put(&first, "demo/group/b", b"after-the-loss");
        heard
            .lock()
            .unwrap()
            .iter()
            .any(|payload| payload == b"after-the-loss")
    });
    assert_eq!(network.joins_of(2), 2, "joined again once, and only once");
    SessionDrive::close(&*second);
    SessionDrive::close(&*first);
}

/// A subscriber a member declares is announced on the group, as zenoh-pico declares its entities
/// over a multicast transport (`GroupDeclarations::Entities`), and retracted from it when it is
/// undeclared: the other member's write filter, which counts what its peers declare, opens on the
/// announcement and shuts on the retraction. The CONTROL is the filter before any declaration.
#[test]
fn a_members_subscriber_is_announced_on_the_group_and_retracted_from_it() {
    let network = Arc::new(Network::default());
    let first = open_member(&network, 1, member_config(1, GROUP)).expect("the first joins");
    let second = open_member(&network, 2, member_config(2, GROUP)).expect("the second joins");
    SessionDrive::start_read_task(&*first).expect("the first's read task starts");
    SessionDrive::start_read_task(&*second).expect("the second's read task starts");
    until_members_know_each_other(&first, &second);

    let filter = first
        .declare_write_filter(
            FilterPlane::Subscribers,
            "demo/group/x",
            &WireKey::literal(),
            None,
            false,
        )
        .expect("a session with ids left declares");
    assert!(
        first.write_filter_active(filter),
        "CONTROL: no member holds a subscriber yet"
    );
    let subscriber = second
        .declare_subscriber_on_wire(
            "demo/group/**",
            WireKey::literal(),
            Locality::Any,
            None,
            SubscriberSink::shared(|_: &dyn SampleView| {}),
        )
        .expect("a session with ids left declares");
    eventually("the announcement to open the first's filter", || {
        !first.write_filter_active(filter)
    });
    second.undeclare_subscriber(subscriber);
    eventually("the retraction to shut the first's filter", || {
        first.write_filter_active(filter)
    });
    SessionDrive::close(&*second);
    SessionDrive::close(&*first);
}

/// Wait until the two members each list the other, which is when a member reads what the other
/// sends: a group admits a member's frames only once it heard that member's JOIN.
fn until_members_know_each_other(first: &Engine, second: &Engine) {
    eventually("each member to list the other", || {
        first.group_member_zids() == [vec![2u8; 4]] && second.group_member_zids() == [vec![1u8; 4]]
    });
}

/// The asking and the answering end over the group: a get asked of the group is answered by a
/// member's queryable, its reply and its Final going back on the group, and a get asked while the
/// group holds no member reaches nobody.
#[cfg(all(feature = "query", feature = "queryable"))]
mod asked {
    use std::sync::{Arc, Mutex};

    use wz_capi_port::{
        HeldQuery, QueryCallback, QueryHolder, Refusal, ReplyCallback, SessionDrive, SessionEngine,
        WireKey,
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
    fn ask(engine: &Engine, keyexpr: &str) -> (Result<usize, Refusal>, Arc<Mutex<Seen>>) {
        let mut opts = QueryOptions::get();
        opts.allowed_destination = Locality::Remote;
        opts.timeout_ms = 3_000;
        let seen = Arc::new(Mutex::new(Seen::default()));
        let into = Arc::clone(&seen);
        let issued = engine.get_on_wire(keyexpr, &WireKey::literal(), &opts, None, &mut || {
            into.lock().unwrap().open += 1;
            let ends = Ends(Arc::clone(&into));
            ReplyCallback::shared(move |view: &dyn ReplyView| {
                ends.0.lock().unwrap().replies.push((
                    view.kind(),
                    view.keyexpr().to_owned(),
                    view.payload().to_vec(),
                ));
            })
        });
        (issued, seen)
    }

    /// Declare a queryable on `keyexpr` of `engine` that answers each query with `payload`.
    fn serve(engine: &Engine, keyexpr: &str, payload: &'static [u8]) {
        engine
            .declare_queryable_on_wire(
                keyexpr,
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
        assert_eq!(issued, Ok(0), "a group with no member is asked nothing");
        assert!(seen.lock().unwrap().replies.is_empty());

        let second = open_member(&network, 2, member_config(2, GROUP)).expect("the second joins");
        SessionDrive::start_read_task(&*second).expect("the second's read task starts");
        serve(&second, "demo/group/**", b"answer-over-the-group");
        until_members_know_each_other(&first, &second);

        // One leg, owed one Final by the one member: the reply and the Final come back on the
        // group, long before the deadline would end the leg with a timeout.
        let (issued, seen) = ask(&first, "demo/group/ask");
        assert_eq!(issued, Ok(1), "one leg: the group");
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

    /// Whether `datagram` carries `payload` anywhere in it.
    fn carries(datagram: &[u8], payload: &[u8]) -> bool {
        datagram
            .windows(payload.len())
            .any(|window| window == payload)
    }

    /// A query a member's queryable keeps is answered later from the program's own thread, with
    /// the member's read task stopped: the reply, and then the Final, are on the group by the time
    /// each call returns, written by the answering thread as a put on the group is. A read waiting
    /// on the group's socket is not woken by an answer, so one left on the group's stage would
    /// leave only when that wait ends. The CONTROL is the kept query: nothing of its answer is on
    /// the group, and the asking leg stays open, until the program answers it.
    #[test]
    fn a_kept_query_answered_by_the_program_is_written_on_the_group_by_its_thread() {
        let network = Arc::new(Network::default());
        let first = open_member(&network, 1, member_config(1, GROUP)).expect("the first joins");
        SessionDrive::start_read_task(&*first).expect("the first's read task starts");
        let second = open_member(&network, 2, member_config(2, GROUP)).expect("the second joins");
        SessionDrive::start_read_task(&*second).expect("the second's read task starts");
        let kept: Arc<Mutex<Option<Box<dyn HeldQuery>>>> = Arc::new(Mutex::new(None));
        let slot = Arc::clone(&kept);
        second
            .declare_queryable_on_wire(
                "demo/group/**",
                WireKey::literal(),
                false,
                Locality::Remote,
                None,
                Arc::new(move |holder: Arc<dyn QueryHolder>| {
                    let slot = Arc::clone(&slot);
                    Box::new(move |query: &dyn QueryView, _out: &mut dyn ReplyOut| {
                        *slot.lock().unwrap() = Some(holder.hold_query(query));
                    }) as QueryCallback
                }),
            )
            .expect("the engine has queryables in this build");
        until_members_know_each_other(&first, &second);

        let (issued, seen) = ask(&first, "demo/group/kept");
        assert_eq!(issued, Ok(1), "one leg: the group");
        eventually("the second's queryable to keep the query", || {
            kept.lock().unwrap().is_some()
        });
        // From here nothing writes the second's datagrams but the thread that answers.
        SessionDrive::stop_read_task(&*second).expect("the second's read task stops");
        let sent_by_second = || -> Vec<Vec<u8>> {
            network
                .datagrams
                .lock()
                .unwrap()
                .iter()
                .filter(|(member, _)| *member == 2)
                .map(|(_, datagram)| datagram.clone())
                .collect()
        };
        assert!(
            !sent_by_second()
                .iter()
                .any(|datagram| carries(datagram, b"kept-answer")),
            "CONTROL: a kept query sends nothing of its own accord"
        );
        assert!(
            !seen.lock().unwrap().ended,
            "CONTROL: the leg waits for the kept query's Final"
        );

        let held = kept.lock().unwrap().take().expect("the kept query");
        held.reply(&mut |out| {
            out.reply_keyed("demo/group/kept", b"kept-answer")
                .expect("a reply on the query's own key");
        });
        let after_reply = sent_by_second();
        assert!(
            after_reply
                .iter()
                .any(|datagram| carries(datagram, b"kept-answer")),
            "the reply is on the group before the answering call returns"
        );
        drop(held);
        assert_eq!(
            sent_by_second().len(),
            after_reply.len() + 1,
            "the Final is on the group before the drop returns"
        );
        eventually("the leg to end", || seen.lock().unwrap().ended);
        assert_eq!(
            seen.lock().unwrap().replies,
            vec![(
                ReplyKind::Put,
                "demo/group/kept".to_owned(),
                b"kept-answer".to_vec()
            )]
        );
        SessionDrive::close(&*second);
        SessionDrive::close(&*first);
    }
}

/// The members of a group as a connectivity plane reads them: each a multicast transport of its
/// own, with one UDP link to the address its datagrams come from over the group, which a watcher
/// is told of as the member comes and as it goes.
#[cfg(feature = "connectivity")]
mod watched {
    use std::sync::{Arc, Mutex};

    use wz_capi_port::{SessionDrive, SessionEngine};
    use wz_session_core::face::{FaceEventKind, FaceSnapshot};
    use wz_session_core::link::LinkKind;

    use super::{
        eventually, member_config, open_member, until_members_know_each_other, Network, GROUP,
    };

    #[test]
    fn each_member_is_a_transport_a_watcher_is_told_of_as_it_comes_and_goes() {
        let network = Arc::new(Network::default());
        let first = open_member(&network, 1, member_config(1, GROUP)).expect("the first joins");
        let told: Arc<Mutex<Vec<(FaceEventKind, FaceSnapshot)>>> = Arc::default();
        let into = Arc::clone(&told);
        first
            .watch_faces(Arc::new(move |kind: FaceEventKind, face: &FaceSnapshot| {
                into.lock().unwrap().push((kind, face.clone()));
            }))
            .expect("an open session watches its faces");
        SessionDrive::start_read_task(&*first).expect("the first's read task starts");
        let second = open_member(&network, 2, member_config(2, GROUP)).expect("the second joins");
        SessionDrive::start_read_task(&*second).expect("the second's read task starts");
        until_members_know_each_other(&first, &second);
        eventually("the watcher to be told the second came", || {
            told.lock()
                .unwrap()
                .iter()
                .any(|(kind, face)| *kind == FaceEventKind::Up && face.zid[..4] == [2; 4])
        });

        let faces = first.face_snapshots();
        assert_eq!(faces.len(), 1, "one member, one transport");
        let face = &faces[0];
        assert_eq!(face.zid[..4], [2; 4]);
        assert_eq!(face.whatami, 1, "a peer, in its wire form");
        assert!(face.is_multicast);
        assert_eq!(face.links.len(), 1);
        let link = &face.links[0];
        assert_eq!(link.kind, Some(LinkKind::Udp));
        assert_eq!(link.dst, "udp/192.0.2.2:7447", "the member's address");
        assert_eq!(link.src, "udp/239.7.7.7:7447", "the group's locator");
        assert_eq!(
            link.group.as_ref().map(|group| group.endpoint.as_str()),
            Some(GROUP)
        );

        SessionDrive::close(&*second);
        eventually("the watcher to be told the second went", || {
            told.lock()
                .unwrap()
                .iter()
                .any(|(kind, face)| *kind == FaceEventKind::Down && face.zid[..4] == [2; 4])
        });
        assert!(first.face_snapshots().is_empty(), "no member stands");
        SessionDrive::close(&*first);
    }
}

/// Liveliness over the group: a liveliness subscriber asks the group for its members' tokens,
/// and a member answers from the tokens its session holds, which it holds before it announces
/// any of them.
#[cfg(feature = "liveliness")]
mod alive {
    use std::sync::{Arc, Mutex};

    use wz_capi_port::{LivelinessSink, SessionDrive, SessionEngine, SubId, WireKey};
    use wz_session_core::declare::liveliness_sample::{LivelinessSample, LivelinessSampleKind};

    use super::{
        eventually, member_config, open_member, until_members_know_each_other, Engine, Network,
        GROUP,
    };

    /// What a liveliness subscriber heard: each sample as its kind and key.
    type Heard = Arc<Mutex<Vec<(LivelinessSampleKind, String)>>>;

    /// Subscribe to the tokens on `keyexpr` of `engine`, with `history`.
    fn subscribe(engine: &Engine, keyexpr: &str, history: bool) -> (SubId, Heard) {
        let heard: Heard = Arc::default();
        let into = heard.clone();
        let sink = LivelinessSink::shared(move |sample: LivelinessSample<'_>| {
            into.lock()
                .unwrap()
                .push((sample.kind, sample.keyexpr.to_owned()));
        });
        let id = engine
            .declare_liveliness_subscriber_on_wire(keyexpr, WireKey::literal(), history, sink)
            .expect("the engine has liveliness");
        (id, heard)
    }

    /// A token the first member declared while it was alone in the group, whose announcement no
    /// one heard, reaches the second member's liveliness subscriber by the Interest the
    /// subscriber asks the group with: the first answers it from the tokens its session holds.
    #[test]
    fn a_liveliness_subscriber_asks_the_group_for_the_tokens_its_members_hold() {
        let network = Arc::new(Network::default());
        let first = open_member(&network, 1, member_config(1, GROUP)).expect("the first joins");
        SessionDrive::start_read_task(&*first).expect("the first's read task starts");
        let _token = first
            .declare_liveliness_token_on_wire("demo/alive/one", WireKey::literal(), None)
            .expect("the engine has liveliness");
        let second = open_member(&network, 2, member_config(2, GROUP)).expect("the second joins");
        SessionDrive::start_read_task(&*second).expect("the second's read task starts");
        until_members_know_each_other(&first, &second);

        let (_subscriber, heard) = subscribe(&second, "demo/alive/**", true);
        eventually("the first's token to reach the second's subscriber", || {
            heard
                .lock()
                .unwrap()
                .iter()
                .any(|(kind, key)| *kind == LivelinessSampleKind::Put && key == "demo/alive/one")
        });
        SessionDrive::close(&*second);
        SessionDrive::close(&*first);
    }
}

/// A group told the session's keyexprs and asked by its write filters
/// (`GroupDeclarations::Mapped`, zenoh-pico's multicast declarations).
mod mapped {
    use std::sync::Arc;

    use wz_capi_port::group::GroupDeclarations;
    use wz_capi_port::{FilterPlane, KeyHolds, SessionDrive, SessionEngine, WireKey};

    use super::{
        eventually, member_config, open_member, put, subscribe, until_members_know_each_other,
        CoopConfig, Engine, Network, OpenError, GROUP,
    };

    /// A member of the group, told the session's keyexprs.
    fn open_mapped(network: &Arc<Network>, member: u8) -> Result<Arc<Engine>, OpenError> {
        let mut config: CoopConfig = member_config(member, GROUP);
        config.groups[0].declarations = GroupDeclarations::Mapped;
        open_member(network, member, config)
    }

    /// Whether a datagram `member` sent carries `bytes`.
    #[cfg(feature = "query")]
    fn carried(network: &Network, member: u8, bytes: &[u8]) -> bool {
        network
            .datagrams
            .lock()
            .unwrap()
            .iter()
            .any(|(from, datagram)| {
                *from == member && datagram.windows(bytes.len()).any(|at| at == bytes)
            })
    }

    /// A get on a group told the session's keyexprs names its key by the declaration the group
    /// was told, as a put does: once the declaration has left, nothing the member sends carries
    /// the key's text again, the query included.
    #[cfg(feature = "query")]
    #[test]
    fn a_get_by_a_declared_keyexpr_names_its_key_by_the_declaration() {
        use wz_capi_port::ReplyCallback;
        use wz_session_core::locality::Locality;
        use wz_session_core::query_options::QueryOptions;
        use wz_session_core::reply_sink::ReplyView;
        use wz_session_core::wire_const::T_MID_JOIN;

        let network = Arc::new(Network::default());
        let first = open_mapped(&network, 1).expect("the first joins");
        let second = open_mapped(&network, 2).expect("the second joins");
        SessionDrive::start_read_task(&*first).expect("the first's read task starts");
        SessionDrive::start_read_task(&*second).expect("the second's read task starts");
        until_members_know_each_other(&first, &second);
        let id = first
            .acquire_keyexpr("demo/mapped/q")
            .expect("a session with ids left declares a keyexpr");
        eventually("the declaration to leave", || {
            carried(&network, 1, b"mapped/q")
        });
        network.datagrams.lock().unwrap().clear();

        let mut opts = QueryOptions::get();
        opts.allowed_destination = Locality::Remote;
        opts.timeout_ms = 500;
        let issued = first.get_on_wire(
            "demo/mapped/q",
            &WireKey::aliased(id, None),
            &opts,
            None,
            &mut || ReplyCallback::shared(|_view: &dyn ReplyView| {}),
        );
        assert!(issued.is_ok(), "the get was asked");
        // The query is the first datagram after the clear that is not a beacon.
        eventually("the query to leave", || {
            network
                .datagrams
                .lock()
                .unwrap()
                .iter()
                .any(|(from, datagram)| {
                    *from == 1 && datagram.first().is_some_and(|h| h & 0x1f != T_MID_JOIN)
                })
        });
        assert!(
            !carried(&network, 1, b"mapped/q"),
            "the query named its key by the declaration"
        );
        SessionDrive::close(&*second);
        SessionDrive::close(&*first);
    }

    /// A write filter asks the group for its members' subscribers, and the answer of a member
    /// whose subscriber was declared before this session joined, which it never heard announced,
    /// opens the filter: it holds a put back until then, and not after.
    #[test]
    fn a_write_filter_asks_the_group_and_a_members_answer_opens_it() {
        let network = Arc::new(Network::default());
        let second = open_mapped(&network, 2).expect("the second joins");
        SessionDrive::start_read_task(&*second).expect("the second's read task starts");
        let _heard = subscribe(&second, "demo/mapped/**");
        let first = open_mapped(&network, 1).expect("the first joins");
        SessionDrive::start_read_task(&*first).expect("the first's read task starts");
        until_members_know_each_other(&first, &second);

        let filter = first
            .declare_write_filter(
                FilterPlane::Subscribers,
                "demo/mapped/a",
                &WireKey::literal(),
                None,
                false,
            )
            .expect("a session with ids left declares a filter");
        eventually("the member's answer to open the filter", || {
            !first.write_filter_holds_back(filter)
        });
        first.undeclare_write_filter(filter);
        SessionDrive::close(&*first);
        SessionDrive::close(&*second);
    }

    /// A put names its key by the keyexpr the session declared, which a member that joined after
    /// the declaration learns by asking the group for its members' keyexprs as it comes up: the
    /// put reaches its subscriber.
    #[test]
    fn a_put_by_a_declared_keyexpr_reaches_a_member_that_asked_for_it() {
        let network = Arc::new(Network::default());
        let first = open_mapped(&network, 1).expect("the first joins");
        SessionDrive::start_read_task(&*first).expect("the first's read task starts");
        let id = first
            .acquire_keyexpr("demo/mapped/b")
            .expect("a session with ids left declares a keyexpr");
        let second = open_mapped(&network, 2).expect("the second joins");
        SessionDrive::start_read_task(&*second).expect("the second's read task starts");
        until_members_know_each_other(&first, &second);
        let heard = subscribe(&second, "demo/mapped/**");

        eventually("a put by the declaration to reach the second", || {
            first
                .publish_on_wire_all(
                    "demo/mapped/b",
                    &WireKey::aliased(id, None),
                    b"by-its-declaration",
                    &wz_session_core::publish_options::PublishOptions::put()
                        .with_locality(wz_session_core::locality::Locality::Remote),
                )
                .expect("a put the group carries");
            heard
                .lock()
                .unwrap()
                .iter()
                .any(|payload| payload == b"by-its-declaration")
        });
        // A literal put still reaches it, by the same group.
        put(&first, "demo/mapped/c", b"by-its-literal");
        eventually("a literal put to reach the second", || {
            heard
                .lock()
                .unwrap()
                .iter()
                .any(|payload| payload == b"by-its-literal")
        });
        first.release_keyexpr(id);
        SessionDrive::close(&*second);
        SessionDrive::close(&*first);
    }
}

/// A member whose group socket fills: the session's puts follow the stage rule the tokio
/// engine's group does, on a queue bounded by its lanes. No read task runs, so what moves the
/// group's task is the session's own puts.
mod congested {
    use std::sync::atomic::AtomicBool;

    use wz_session_core::qos::{CongestionControl, Priority};
    use wz_session_core::session_init_params::TxQueueConf;

    use super::*;

    /// What a droppable put waits for room, at most.
    const DROP_WAIT: Duration = Duration::from_millis(20);
    /// What a blocking put waits for room, at most.
    const CLOSE_WAIT: Duration = Duration::from_millis(300);
    /// A payload two of which fill a lane of one 2 KiB batch.
    const PAYLOAD: [u8; 1_500] = [0x5a; 1_500];

    /// A stack whose group socket takes every datagram until it is told it is full, and then
    /// none, answering would-block, until it is told it is writable again.
    #[derive(Default)]
    struct Filling {
        full: AtomicBool,
        sent: AtomicUsize,
        closes: AtomicUsize,
        link: Mutex<Option<LinkHandle>>,
    }

    struct FillingPort(Arc<Filling>);

    impl AppPort for FillingPort {
        fn open(&self, link: LinkHandle, kind: AppLinkKind, locator: &str) -> ProgramOpen {
            if kind != AppLinkKind::Group || locator != GROUP {
                return ProgramOpen::Refused;
            }
            *self.0.link.lock().unwrap() = Some(link);
            ProgramOpen::Up
        }

        fn send(&self, _link: LinkHandle, bytes: &[u8]) -> ProgramSend {
            if self.0.full.load(Ordering::SeqCst) {
                return ProgramSend::WouldBlock;
            }
            self.0.sent.fetch_add(1, Ordering::SeqCst);
            ProgramSend::Wrote(bytes.len())
        }

        fn close(&self, _link: LinkHandle) {
            self.0.closes.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A member over a filling stack whose lanes hold one batch each, with the two waits above.
    fn open_filling() -> (Arc<Engine>, Arc<Filling>, Arc<AppTransport>) {
        let stack = Arc::new(Filling::default());
        let transport = Arc::new(AppTransport::new(
            Box::new(Table(Mutex::new(AppLinkTable::new()))),
            Box::new(FillingPort(Arc::clone(&stack))),
        ));
        let config = CoopConfig {
            tx_queue: TxQueueConf {
                sizes: [1; Priority::NUM],
                wait_before_drop_us: DROP_WAIT.as_micros() as u64,
                wait_before_close_us: CLOSE_WAIT.as_micros() as u64,
                no_progress_us: None,
                ..client_config().tx_queue
            },
            ..member_config(1, GROUP)
        };
        let engine = Engine::open(
            AppLinks::new(SessionTransport::new(
                Arc::clone(&transport),
                &config.limits,
            )),
            PosixClock,
            PosixEntropy,
            config,
        )
        .expect("the member joins");
        (engine, stack, transport)
    }

    /// Put [`PAYLOAD`] on the group with `congestion`, and how long the put took.
    fn put_with(engine: &Engine, congestion: CongestionControl) -> Duration {
        let started = Instant::now();
        let sent = engine.publish_on_wire_all(
            "demo/group/full",
            &WireKey::literal(),
            &PAYLOAD,
            &PublishOptions::put()
                .with_locality(Locality::Remote)
                .with_congestion_control(congestion),
        );
        assert_eq!(sent, Ok(0), "a dropped put succeeds, as zenoh's does");
        started.elapsed()
    }

    /// The stack takes datagrams again and says so.
    fn writable(stack: &Filling, transport: &AppTransport) {
        stack.full.store(false, Ordering::SeqCst);
        let link = stack.link.lock().unwrap().expect("the group was joined");
        let _ = transport.event(link, ProgramEvent::Writable);
    }

    /// On a full socket the lane fills with what the session puts, and a droppable put that
    /// finds it full waits its `wait_before_drop` for room and is dropped and counted; the lane's
    /// mark then drops the next one at once. Once the socket takes datagrams again, the group's
    /// task, stepped by the session's read, drains what was queued.
    #[test]
    fn a_droppable_put_on_a_full_group_is_dropped_within_its_wait_and_counted() {
        let (member, stack, transport) = open_filling();
        stack.full.store(true, Ordering::SeqCst);

        // The first put's own write takes it off its lane, and the socket keeps it from writing
        // it; the two after it fill the lane.
        for _ in 0..3 {
            let took = put_with(&member, CongestionControl::Drop);
            assert!(
                took < Duration::from_secs(1),
                "a put on a lane with room took {took:?}"
            );
        }
        assert_eq!(member.group_congestion_drops(Priority::DEFAULT), 0);

        let took = put_with(&member, CongestionControl::Drop);
        assert_eq!(
            member.group_congestion_drops(Priority::DEFAULT),
            1,
            "a droppable put on the full lane is dropped and counted"
        );
        assert!(took >= DROP_WAIT, "dropped after {took:?}, before its wait");
        assert!(
            took < Duration::from_secs(1),
            "a droppable put waited {took:?}"
        );

        let took = put_with(&member, CongestionControl::Drop);
        assert_eq!(member.group_congestion_drops(Priority::DEFAULT), 2);
        #[cfg(feature = "transport-stats")]
        assert_eq!(
            member.transport_stats().tx.n_dropped,
            2,
            "the group's drops are the transport's, as the tokio group counts them"
        );
        assert!(
            took < DROP_WAIT,
            "the lane's mark drops a put at once, not after {took:?}"
        );

        let before = stack.sent.load(Ordering::SeqCst);
        writable(&stack, &transport);
        SessionDrive::start_read_task(&*member).expect("the read task starts");
        eventually("what was queued to leave", || {
            stack.sent.load(Ordering::SeqCst) >= before + 3
        });
        SessionDrive::close(&*member);
    }

    /// The replies a group's dispatch stages past the reply limit are dropped and charged to the
    /// transport's drops, beside the session's own messages its lanes had no room for, as the tokio
    /// engine's group charges every message it drops. No read runs, so nothing staged leaves.
    #[cfg(feature = "transport-stats")]
    #[test]
    fn replies_past_the_reply_limit_are_the_transports_drops() {
        use wz_session_core::caps::MAX_MULTICAST_REPLIES;
        use wz_session_core::multicast_tx::MulticastTxItem;
        let (member, _stack, _transport) = open_filling();
        let reply = || {
            let push = wz_session_core::push_build::build_push_literal_with_meta(
                "demo/group/reply",
                b"r",
                &wz_session_core::metadata::PushMetadata::default(),
            )
            .expect("a push of a short key");
            MulticastTxItem::Push {
                push: Box::new(push),
                reliable: true,
                priority: Priority::DEFAULT,
            }
        };
        member.stage_group_replies(MAX_MULTICAST_REPLIES, reply);
        assert_eq!(
            member.transport_stats().tx.n_dropped,
            0,
            "CONTROL: the reply limit holds this many"
        );
        member.stage_group_replies(2, reply);
        assert_eq!(
            member.transport_stats().tx.n_dropped,
            2,
            "the replies past the limit are the transport's drops"
        );
        SessionDrive::close(&*member);
    }

    /// A droppable put that finds the session held asks the group's socket for room as it asks a
    /// link's: the session's waits for room hold the group's, which answers congestion while the
    /// socket is full and room once it takes datagrams again.
    #[test]
    fn a_held_session_asks_the_group_socket_for_room() {
        use crate::engine::Room;
        let (member, stack, transport) = open_filling();
        assert_eq!(
            member.rooms().within(1_000),
            Room::Free,
            "CONTROL: a socket with room"
        );
        stack.full.store(true, Ordering::SeqCst);
        // Each put offers the socket a datagram, which it refuses.
        for _ in 0..3 {
            put_with(&member, CongestionControl::Drop);
        }
        assert!(
            matches!(member.rooms().within(1_000), Room::Congested(faces) if faces.len() == 1),
            "the group's socket is the congestion, and the session's only face"
        );
        writable(&stack, &transport);
        assert_eq!(member.rooms().within(1_000), Room::Free);
        SessionDrive::close(&*member);
    }

    /// Under the pico profile a droppable put that finds the session held, here by a blocking put
    /// waiting for room on the full group, is dropped at once and its caller is told, as pico's
    /// put fails when its held transmit lock drops the message: the group's leg reports the held
    /// session as a link's does.
    #[test]
    fn under_the_pico_profile_a_put_behind_a_held_group_session_is_told() {
        let (member, stack, _transport) = open_filling();
        stack.full.store(true, Ordering::SeqCst);
        for _ in 0..3 {
            put_with(&member, CongestionControl::Drop);
        }
        let blocking = {
            let member = Arc::clone(&member);
            std::thread::spawn(move || put_with(&member, CongestionControl::Block))
        };
        // Long enough for the blocking put to take the session, well inside its wait.
        std::thread::sleep(CLOSE_WAIT / 3);
        let started = Instant::now();
        let dropped = member.publish_on_wire_all(
            "demo/group/full",
            &WireKey::literal(),
            b"behind",
            &PublishOptions::put()
                .with_locality(Locality::Remote)
                .with_congestion_control(CongestionControl::Drop),
        );
        assert_eq!(dropped, Err(wz_capi_port::FanoutError::HeldConduit));
        assert!(
            started.elapsed() < CLOSE_WAIT / 3,
            "the droppable put waited {:?}",
            started.elapsed()
        );
        assert!(
            !blocking.is_finished(),
            "the blocking put still holds the session"
        );
        let waited = blocking.join().expect("the blocking put");
        assert!(
            waited >= CLOSE_WAIT,
            "the blocking put returned after {waited:?}"
        );
        SessionDrive::close(&*member);
    }

    /// A blocking put that finds the lane full waits its whole `wait_before_close` for room, and
    /// is then dropped and counted, as the tokio engine's group drops it: a multicast transport
    /// closes nothing on a congestion drop. The group is still joined, and carries the next put
    /// once the socket takes datagrams again.
    #[test]
    fn a_blocking_put_on_a_full_group_waits_its_close_wait_and_closes_nothing() {
        let (member, stack, transport) = open_filling();
        stack.full.store(true, Ordering::SeqCst);
        for _ in 0..3 {
            put_with(&member, CongestionControl::Drop);
        }

        let took = put_with(&member, CongestionControl::Block);
        assert!(took >= CLOSE_WAIT, "a blocking put returned after {took:?}");
        assert!(
            took < Duration::from_secs(5),
            "a blocking put waited {took:?}"
        );
        assert_eq!(member.group_congestion_drops(Priority::DEFAULT), 1);
        assert!(!SessionDrive::is_closed(&*member), "the session is open");
        assert_eq!(
            stack.closes.load(Ordering::SeqCst),
            0,
            "the group was not left"
        );

        let before = stack.sent.load(Ordering::SeqCst);
        writable(&stack, &transport);
        put_with(&member, CongestionControl::Block);
        assert!(stack.sent.load(Ordering::SeqCst) >= before + 2);
        SessionDrive::close(&*member);
    }
}

/// A put whose fragment chain finds its lane full part of the way: the session pushes a chain onto
/// the group's stage fragment by fragment, as the tokio engine's group producer pushes it, so a
/// chain whose lane stays full between two fragments is stopped by the drop marker, and the other
/// member drops what it had of it; and each JOIN the member sends advertises the sequence number
/// its socket takes next, not one numbered ahead of it.
mod cut {
    use std::sync::atomic::AtomicBool;

    use wz_session_core::inbound::{parse_inbound, InboundFrame};
    use wz_session_core::join_decode::decode_join;
    use wz_session_core::qos::{CongestionControl, Priority};
    use wz_session_core::session_init_params::TxQueueConf;

    use super::*;

    /// A payload whose put is a chain of several more fragments than a lane of one batch holds.
    const LARGE: [u8; 12_000] = [0x6c; 12_000];
    /// The group's batch, which every fragment of a chain fits.
    const BATCH: usize = 2_048;

    /// A member's stack whose group socket can be made full: while it is, the socket takes nothing
    /// and answers would-block; otherwise it is the member's stack. It keeps each datagram it
    /// takes, in order.
    struct Gated {
        stack: MemberStack,
        full: Arc<AtomicBool>,
        wire: Arc<Mutex<Vec<Vec<u8>>>>,
        link: Arc<Mutex<Option<LinkHandle>>>,
    }

    impl AppPort for Gated {
        fn open(&self, link: LinkHandle, kind: AppLinkKind, locator: &str) -> ProgramOpen {
            let opened = self.stack.open(link, kind, locator);
            if matches!(opened, ProgramOpen::Up) {
                *self.link.lock().unwrap() = Some(link);
            }
            opened
        }

        fn send(&self, link: LinkHandle, bytes: &[u8]) -> ProgramSend {
            if self.full.load(Ordering::SeqCst) {
                return ProgramSend::WouldBlock;
            }
            self.wire.lock().unwrap().push(bytes.to_vec());
            self.stack.send(link, bytes)
        }

        fn close(&self, link: LinkHandle) {
            self.stack.close(link);
        }
    }

    /// A member over a [`Gated`] stack, whose lanes hold one batch each.
    struct GatedMember {
        engine: Arc<Engine>,
        transport: Arc<AppTransport>,
        full: Arc<AtomicBool>,
        wire: Arc<Mutex<Vec<Vec<u8>>>>,
        link: Arc<Mutex<Option<LinkHandle>>>,
    }

    impl GatedMember {
        fn open(network: &Arc<Network>, member: u8) -> Self {
            let own = Arc::new(Mutex::new(Weak::new()));
            let full = Arc::new(AtomicBool::new(false));
            let wire = Arc::new(Mutex::new(Vec::new()));
            let link = Arc::new(Mutex::new(None));
            let transport = Arc::new(AppTransport::new(
                Box::new(Table(Mutex::new(AppLinkTable::new()))),
                Box::new(Gated {
                    stack: MemberStack {
                        network: Arc::clone(network),
                        member,
                        transport: Arc::clone(&own),
                    },
                    full: Arc::clone(&full),
                    wire: Arc::clone(&wire),
                    link: Arc::clone(&link),
                }),
            ));
            *own.lock().unwrap() = Arc::downgrade(&transport);
            let config = CoopConfig {
                tx_queue: TxQueueConf {
                    sizes: [1; Priority::NUM],
                    wait_before_drop_us: 20_000,
                    no_progress_us: None,
                    ..client_config().tx_queue
                },
                ..member_config(member, GROUP)
            };
            let engine = Engine::open(
                AppLinks::new(SessionTransport::new(
                    Arc::clone(&transport),
                    &config.limits,
                )),
                PosixClock,
                PosixEntropy,
                config,
            )
            .expect("the member joins");
            Self {
                engine,
                transport,
                full,
                wire,
                link,
            }
        }

        /// The stack takes datagrams again and says so.
        fn writable(&self) {
            self.full.store(false, Ordering::SeqCst);
            let link = self.link.lock().unwrap().expect("the group was joined");
            let _ = self.transport.event(link, ProgramEvent::Writable);
        }
    }

    /// How many JOINs the socket took.
    fn joins_on(wire: &Mutex<Vec<Vec<u8>>>) -> usize {
        wire.lock()
            .unwrap()
            .iter()
            .filter(|datagram| decode_join(datagram).is_some())
            .count()
    }

    /// The sequence number of a datagram on the reliable channel: a frame's, or a fragment's.
    fn reliable_sn(datagram: &[u8]) -> Option<u64> {
        match parse_inbound(datagram) {
            Ok(InboundFrame::Frame {
                reliable: true, sn, ..
            })
            | Ok(InboundFrame::Fragment {
                reliable: true, sn, ..
            }) => Some(sn),
            _ => None,
        }
    }

    /// The first member's socket is full when it puts a chain: the first fragment is queued, the
    /// group's writer takes it and finds no room, the second takes the room that made, and the
    /// third finds the lane full for the whole of the put's wait, so the chain is cut with the
    /// drop marker and the put counted as a congestion drop. Once the socket takes datagrams
    /// again, the second member reads two fragments and the marker, and drops the chain: it hears
    /// the put that follows and never the large one. Every JOIN the first sent advertises the
    /// sequence number of the next reliable datagram its socket took, the one asked for while the
    /// socket was full among them.
    #[test]
    fn a_chain_the_lane_has_no_room_for_is_cut_with_the_drop_marker_and_dropped() {
        let network = Arc::new(Network::default());
        let second = open_member(&network, 2, member_config(2, GROUP)).expect("the second joins");
        SessionDrive::start_read_task(&*second).expect("the second's read task starts");
        let heard = subscribe(&second, "demo/group/**");
        // The first's JOIN at its open admits it at the second, which reads its frames from then.
        let first = GatedMember::open(&network, 1);
        eventually("the second to list the first", || {
            second.group_member_zids() == [vec![1u8; 4]]
        });

        first.full.store(true, Ordering::SeqCst);
        let sent = first.engine.publish_on_wire_all(
            "demo/group/large",
            &WireKey::literal(),
            &LARGE,
            &PublishOptions::put()
                .with_locality(Locality::Remote)
                .with_congestion_control(CongestionControl::Drop),
        );
        assert_eq!(sent, Ok(0), "a dropped put succeeds, as zenoh's does");
        assert_eq!(
            first.engine.group_congestion_drops(Priority::DEFAULT),
            1,
            "the chain found no room for a fragment"
        );

        // A JOIN asked while the socket is full waits for it, behind what the writer holds, and
        // leaves at the group's next step once the socket takes datagrams again: the put after it
        // waits for it, since the put writes what is staged itself.
        assert_eq!(first.engine.send_join_on_groups(), Ok(1));
        let joins_in_the_cut = joins_on(&first.wire);
        first.writable();
        SessionDrive::start_read_task(&*first.engine).expect("the first's read task starts");
        eventually("the JOIN asked during the cut to leave", || {
            joins_on(&first.wire) > joins_in_the_cut
        });
        put(&first.engine, "demo/group/small", b"after-the-cut");
        eventually("the second to hear the put after the cut", || {
            heard
                .lock()
                .unwrap()
                .iter()
                .any(|payload| payload == b"after-the-cut")
        });
        assert!(
            !heard
                .lock()
                .unwrap()
                .iter()
                .any(|payload| payload.len() == LARGE.len()),
            "the second dropped the chain that was cut"
        );
        SessionDrive::close(&*first.engine);
        SessionDrive::close(&*second);

        let wire = first.wire.lock().unwrap().clone();
        // The chain as the socket took it: fragments that say more follows, then the marker.
        let fragments: Vec<(u64, bool, bool)> = wire
            .iter()
            .filter_map(|datagram| match parse_inbound(datagram) {
                Ok(InboundFrame::Fragment {
                    sn, more, markers, ..
                }) => Some((sn, more, markers.dropped)),
                _ => None,
            })
            .collect();
        let (marker, run) = fragments
            .split_last()
            .expect("the chain's fragments were sent");
        assert!(
            marker.2 && marker.1,
            "the chain ends with the drop marker: {fragments:?}"
        );
        assert!(
            !run.is_empty() && run.iter().all(|(_, more, dropped)| *more && !*dropped),
            "{fragments:?}"
        );
        assert!(
            run.len() < LARGE.len() / BATCH,
            "the chain was cut, not sent whole: {fragments:?}"
        );
        assert!(
            fragments.windows(2).all(|pair| pair[1].0 == pair[0].0 + 1),
            "one sequence number after another, the marker's too: {fragments:?}"
        );

        let mut joins = 0;
        for (at, datagram) in wire.iter().enumerate() {
            let Some(join) = decode_join(datagram) else {
                continue;
            };
            if let Some(next) = wire[at + 1..]
                .iter()
                .find_map(|later| reliable_sn(later.as_slice()))
            {
                assert_eq!(
                    join.next_sn_reliable, next,
                    "the JOIN at {at} advertises the next reliable datagram written"
                );
                joins += 1;
            }
        }
        assert!(
            joins >= 2,
            "the JOIN of the open and the one asked during the cut: {joins}"
        );
    }
}

/// What wakes a read of a session that holds a group: the group's next datagram, which the read
/// waits on beside the session's links, and the group's session being due with nothing arriving,
/// and nothing else.
mod woken {
    use wz_runtime_coop::ClockSource;

    use super::*;

    /// A clock that stands still, far from where it started.
    #[derive(Clone)]
    struct Stopped;

    impl ClockSource for Stopped {
        fn now_us(&self) -> u64 {
            1_000_000_000_000
        }
    }

    /// A member's stack alone on the group: it joins [`GROUP`] and keeps each datagram its session
    /// sends, with the thread that sent it; what the members send is what the test hands in.
    #[derive(Default)]
    struct Alone {
        sent: Mutex<Vec<Vec<u8>>>,
        threads: Mutex<Vec<std::thread::ThreadId>>,
        link: Mutex<Option<LinkHandle>>,
    }

    struct AlonePort(Arc<Alone>);

    impl AppPort for AlonePort {
        fn open(&self, link: LinkHandle, kind: AppLinkKind, locator: &str) -> ProgramOpen {
            if kind != AppLinkKind::Group || locator != GROUP {
                return ProgramOpen::Refused;
            }
            *self.0.link.lock().unwrap() = Some(link);
            ProgramOpen::Up
        }

        fn send(&self, _link: LinkHandle, bytes: &[u8]) -> ProgramSend {
            self.0.sent.lock().unwrap().push(bytes.to_vec());
            self.0
                .threads
                .lock()
                .unwrap()
                .push(std::thread::current().id());
            ProgramSend::Wrote(bytes.len())
        }

        fn close(&self, _link: LinkHandle) {}
    }

    /// A member whose beacon is due a minute after its open and whose read waits at most
    /// `idle_wait_ms` for input, alone on the group over a stack of its own, on `clock`.
    fn open_alone<C: ClockSource + Clone + 'static>(
        clock: C,
        idle_wait_ms: u32,
    ) -> (Arc<CoopEngine<AppLinks, C>>, Arc<Alone>, Arc<AppTransport>) {
        let mut config = member_config(1, GROUP);
        config.groups[0].profile.lease_ms = 180_000;
        config.groups[0].profile.join_interval_ms = 60_000;
        config.idle_wait_ms = idle_wait_ms;
        let stack = Arc::new(Alone::default());
        let transport = Arc::new(AppTransport::new(
            Box::new(Table(Mutex::new(AppLinkTable::new()))),
            Box::new(AlonePort(Arc::clone(&stack))),
        ));
        let engine = CoopEngine::open(
            AppLinks::new(SessionTransport::new(
                Arc::clone(&transport),
                &config.limits,
            )),
            clock,
            PosixEntropy,
            config,
        )
        .expect("the member joins");
        (engine, stack, transport)
    }

    /// With nothing arriving and a clock that does not move, each read waits its whole idle wait
    /// on the group's socket and on the session's next beacon, which such a clock never reaches:
    /// the reads do not spin.
    #[test]
    fn a_quiet_group_on_a_stopped_clock_is_not_read_without_end() {
        let (member, _stack, _transport) = open_alone(Stopped, 100);
        let started = Instant::now();
        let mut reads = 0usize;
        while started.elapsed() < Duration::from_millis(600) {
            SessionDrive::read(&*member, false).expect("the session is open");
            reads += 1;
        }
        assert!(reads <= 20, "{reads} reads in 600 ms: a read did not wait");
        SessionDrive::close(&*member);
    }

    /// A read with nothing due for five seconds waits on the group's socket: no tick ends it, and
    /// the datagram handed in does, long before its wait is out.
    #[test]
    fn a_datagram_handed_in_wakes_a_read_that_waits_on_the_group() {
        let (member, stack, transport) = open_alone(PosixClock, 5_000);
        let link = stack.link.lock().unwrap().expect("the group was joined");
        let reading = {
            let member = Arc::clone(&member);
            std::thread::spawn(move || {
                SessionDrive::read(&*member, false).expect("the session is open");
                Instant::now()
            })
        };
        std::thread::sleep(Duration::from_millis(300));
        let handed_in = Instant::now();
        transport
            .received(link, &[0u8; 4], Some(source(9).as_str()))
            .expect("handed in");
        let returned = reading.join().expect("the read");
        assert!(
            returned >= handed_in,
            "the read returned {:?} before the datagram came",
            handed_in.duration_since(returned)
        );
        assert!(
            returned.duration_since(handed_in) < Duration::from_millis(2_500),
            "woken by the datagram, not the end of its wait: {:?}",
            returned.duration_since(handed_in)
        );
        SessionDrive::close(&*member);
    }

    /// Ten puts on the group are ten datagrams, each written by the putting thread before its put
    /// returns, with one take of the session a put and no read run: nothing waits for a step of
    /// the group, or for a read to wake, to leave, as zenoh-pico's put writes a multicast message
    /// on its caller's thread.
    #[test]
    fn a_put_on_the_group_is_written_by_the_putting_thread_before_it_returns() {
        let (member, stack, _transport) = open_alone(PosixClock, 5_000);
        let here = std::thread::current().id();
        let sent_before = stack.sent.lock().unwrap().len();
        let takes_before = member.takes.core.load(Ordering::SeqCst);
        for at in 0..10u8 {
            let payload = [b'p', at];
            put(&member, "demo/group/now", &payload);
            let sent = stack.sent.lock().unwrap();
            assert_eq!(
                sent.len(),
                sent_before + usize::from(at) + 1,
                "put {at} was written before it returned"
            );
            assert!(sent
                .last()
                .is_some_and(|datagram| datagram.ends_with(&payload)));
        }
        assert!(
            stack.threads.lock().unwrap()[sent_before..]
                .iter()
                .all(|thread| *thread == here),
            "every one on the putting thread"
        );
        assert_eq!(
            member.takes.core.load(Ordering::SeqCst) - takes_before,
            10,
            "one take of the session a put"
        );
        SessionDrive::close(&*member);
    }

    /// A put made while a read waits on the group's socket is written by the putting thread before
    /// the put returns: the read, on a thread of its own, has no part in it, and the datagram it
    /// waits for ends its wait after.
    #[test]
    fn a_put_made_while_a_read_waits_is_written_by_the_putting_thread() {
        let (member, stack, transport) = open_alone(PosixClock, 5_000);
        let link = stack.link.lock().unwrap().expect("the group was joined");
        let reading = {
            let member = Arc::clone(&member);
            std::thread::spawn(move || {
                SessionDrive::read(&*member, false).expect("the session is open");
            })
        };
        std::thread::sleep(Duration::from_millis(300));
        let started = Instant::now();
        put(&member, "demo/group/now", b"while-a-read-waits");
        let took = started.elapsed();
        assert!(
            stack
                .sent
                .lock()
                .unwrap()
                .last()
                .is_some_and(|datagram| datagram.ends_with(b"while-a-read-waits")),
            "written before the put returned"
        );
        assert_eq!(
            stack.threads.lock().unwrap().last(),
            Some(&std::thread::current().id()),
            "by the putting thread"
        );
        assert!(
            took < Duration::from_millis(1_000),
            "the put took {took:?}, as long as a read's wait"
        );
        transport
            .received(link, &[0u8; 4], Some(source(9).as_str()))
            .expect("handed in");
        reading.join().expect("the read");
        SessionDrive::close(&*member);
    }

    /// Whether `datagram` carries `payload` anywhere in it.
    fn carries(datagram: &[u8], payload: &[u8]) -> bool {
        datagram
            .windows(payload.len())
            .any(|window| window == payload)
    }

    /// Inside a batch window a put on the group is held, not written: the flush writes the
    /// window's puts as one datagram and keeps the window open; an express put takes the window's
    /// frame with it at once; the stop writes what is left and closes the window, after which a
    /// put is written by itself again. Every write is the calling thread's.
    #[test]
    fn inside_a_batch_window_a_put_on_the_group_is_written_at_the_flush() {
        let (member, stack, _transport) = open_alone(PosixClock, 5_000);
        let sent = || stack.sent.lock().unwrap().clone();
        let before = sent().len();
        assert_eq!(
            member.batch_all(BatchStep::Start),
            1,
            "the group opens a window"
        );
        put(&member, "demo/group/a", b"batched-first");
        put(&member, "demo/group/b", b"batched-second");
        assert_eq!(sent().len(), before, "the window holds both");

        assert_eq!(member.batch_all(BatchStep::Flush), 1);
        let flushed = sent();
        assert_eq!(flushed.len(), before + 1, "one datagram for both");
        let frame = flushed.last().expect("the window's frame");
        assert!(carries(frame, b"batched-first") && frame.ends_with(b"batched-second"));

        put(&member, "demo/group/c", b"batched-third");
        assert_eq!(sent().len(), before + 1, "the window is still open");
        member
            .publish_on_wire_all(
                "demo/group/d",
                &WireKey::literal(),
                b"express",
                &PublishOptions::put()
                    .with_locality(Locality::Remote)
                    .with_express(true),
            )
            .expect("a put the group carries");
        let expressed = sent();
        assert_eq!(
            expressed.len(),
            before + 2,
            "the express put takes the window's frame with it"
        );
        let frame = expressed.last().expect("the express frame");
        assert!(carries(frame, b"batched-third") && frame.ends_with(b"express"));

        put(&member, "demo/group/e", b"batched-fourth");
        assert_eq!(sent().len(), before + 2, "held again");
        assert_eq!(member.batch_all(BatchStep::Stop), 1);
        let stopped = sent();
        assert_eq!(stopped.len(), before + 3, "the stop writes what is left");
        assert!(stopped
            .last()
            .is_some_and(|datagram| datagram.ends_with(b"batched-fourth")));

        put(&member, "demo/group/f", b"unbatched");
        let after = sent();
        assert_eq!(
            after.len(),
            before + 4,
            "a closed window holds nothing back"
        );
        assert!(after
            .last()
            .is_some_and(|datagram| datagram.ends_with(b"unbatched")));
        let here = std::thread::current().id();
        assert!(
            stack.threads.lock().unwrap()[before..]
                .iter()
                .all(|thread| *thread == here),
            "every write the calling thread's"
        );
        SessionDrive::close(&*member);
    }

    /// Puts of one size inside a batch window leave as full frames, as zenoh-pico's overflow sends
    /// its batch: each frame is written by the putting thread in the put it has no room for, before
    /// that put returns, with one take of the session a put and no read; a put that finds room
    /// writes nothing. N puts are N over what a frame of the group's batch holds, rounded up,
    /// datagrams, where each put alone was a datagram of its own.
    #[test]
    fn inside_a_batch_window_puts_on_the_group_leave_one_datagram_a_full_frame() {
        let (member, stack, _transport) = open_alone(PosixClock, 5_000);
        let sent = || stack.sent.lock().unwrap().clone();
        let payload = |at: usize| format!("{at:08}").into_bytes();
        let key = "demo/group/thr";
        let budget = usize::from(profile().batch_size);
        assert_eq!(
            member.batch_all(BatchStep::Start),
            1,
            "the group opens a window"
        );

        // The bytes one put adds to a frame, and the frame's head: a frame of one and one of two.
        let base = sent().len();
        put(&member, key, &payload(0));
        assert_eq!(member.batch_all(BatchStep::Flush), 1);
        put(&member, key, &payload(1));
        put(&member, key, &payload(2));
        assert_eq!(member.batch_all(BatchStep::Flush), 1);
        let calibration = sent();
        assert_eq!(calibration.len(), base + 2);
        let (one, two) = (calibration[base].len(), calibration[base + 1].len());
        let each = two - one;
        let head = one - each;
        let fits = (budget - head) / each;
        assert!(
            fits > 1,
            "a frame of the group's batch holds several such puts"
        );

        let base = sent().len();
        let takes = member.takes.core.load(Ordering::SeqCst);
        let puts = 2 * fits + 3;
        for at in 0..puts {
            put(&member, key, &payload(at));
            assert_eq!(sent().len() - base, at / fits, "written by put {at}");
        }
        assert_eq!(
            member.takes.core.load(Ordering::SeqCst) - takes,
            puts,
            "one take of the session a put"
        );
        assert_eq!(member.batch_all(BatchStep::Stop), 1);
        let frames = sent().split_off(base);
        assert_eq!(frames.len(), puts.div_ceil(fits));
        for (at, frame) in frames.iter().enumerate() {
            let first = at * fits;
            let last = (first + fits).min(puts) - 1;
            assert_eq!(frame.len(), head + (last + 1 - first) * each, "frame {at}");
            assert!(carries(frame, &payload(first)) && frame.ends_with(&payload(last)));
        }
        assert!(
            head + (fits + 1) * each > budget,
            "a full frame has no room for one more"
        );
        let here = std::thread::current().id();
        assert!(
            stack.threads.lock().unwrap()[base..]
                .iter()
                .all(|thread| *thread == here),
            "every write the putting thread's"
        );

        // CONTROL: with the window closed each put is a datagram of its own.
        let base = sent().len();
        for at in 0..3 {
            put(&member, key, &payload(at));
        }
        assert_eq!(sent().len() - base, 3);
        SessionDrive::close(&*member);
    }
}

/// What a member sends is read where its datagram lies, record by record, as a link's frames are:
/// a beacon and a frame in one datagram both reach the session, a member's declarations are kept
/// apart from another member's of the same id, and a datagram whose walk the host stopped is read
/// on from where it stopped.
mod in_place {
    use std::sync::Arc;

    use wz_capi_port::{FilterPlane, SessionDrive, SessionEngine, WireKey};
    use wz_session_core::declare_build::build_declare_subscriber;
    use wz_session_core::frame_encode::{encode_frame_with_declare, encode_frame_with_push};
    use wz_session_core::handshake_encode::encode_multicast_close_into_slice;
    use wz_session_core::limits::SessionLimits;
    use wz_session_core::multicast_join::encode_join;
    use wz_session_core::multicast_params::{zid_vec, GroupJoinRule, MulticastParams};
    use wz_session_core::policy::SessionPolicy;
    use wz_session_core::push_build::build_push_literal;
    use wz_session_core::session_init_params::{LinkRxConf, TxQueueConf};
    use wz_session_core::sn::{mask_from_res, MulticastTxConduits};
    use wz_session_core::WhatAmI;

    use super::{eventually, member_config, open_member, source, subscribe, Network, GROUP};

    /// The terms member `member` beacons, the group's (`super::profile`).
    fn params(member: u8) -> MulticastParams {
        let policy = SessionPolicy::defaults();
        MulticastParams {
            whatami: WhatAmI::Peer,
            zid: zid_vec(&[member; 4]),
            lease_ms: 10_000,
            join_interval_ms: 100,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size: 2_048,
            is_qos: false,
            compression: false,
            tx_queue: TxQueueConf::of_snapshot(&policy, &SessionLimits::BUILD),
            link_rx: LinkRxConf::default(),
            join_rule: GroupJoinRule::Pico,
            max_sessions: None,
            policy,
            limits: SessionLimits::BUILD,
        }
    }

    /// Member `member`'s beacon, which says its first frame is numbered 0.
    fn beacon(member: u8) -> Vec<u8> {
        let params = params(member);
        encode_join(
            &params,
            &MulticastTxConduits::new(mask_from_res(params.seq_num_res)),
        )
    }

    /// One reliable frame numbered `sn` whose records are a Put of `b"x"` on each of `keys`, in
    /// order: the first record's frame with the records of the others behind it. A frame numbered
    /// below 128 with no extension has a head of two bytes, which is what is taken off the others.
    fn frame_of_puts(sn: u64, keys: &[&str]) -> Vec<u8> {
        assert!(sn < 128, "a head of two bytes");
        let mut frame = Vec::new();
        for (at, key) in keys.iter().enumerate() {
            let one =
                encode_frame_with_push(sn, build_push_literal(key, b"x").expect("a put"), true);
            frame.extend_from_slice(if at == 0 { &one } else { &one[2..] });
        }
        frame
    }

    /// Hand `datagram` to `to`'s session as its stack hands in what the group carries, from
    /// `from`'s address.
    fn hand_in(network: &Network, to: u8, from: u8, datagram: &[u8]) {
        let (link, transport) = {
            let joined = network.joined.lock().unwrap();
            let to = joined
                .iter()
                .find(|joined| joined.member == to)
                .expect("the member joined");
            (to.link, to.transport.upgrade().expect("its transport"))
        };
        transport
            .received(link, datagram, Some(source(from).as_str()))
            .expect("the stack takes the datagram");
    }

    /// Two members that number their subscribers alike reach the session as two: each one's
    /// declaration, read where its datagram lies behind the member's beacon, opens its own filter,
    /// the second does not take the first's place, and the first's departure retracts its own
    /// declaration and nothing else.
    #[test]
    fn two_members_declarations_of_one_id_read_in_place_stay_apart() {
        let network = Arc::new(Network::default());
        let session = open_member(&network, 1, member_config(1, GROUP)).expect("the member joins");
        SessionDrive::start_read_task(&*session).expect("the read task starts");
        let filter = |key: &str| {
            session
                .declare_write_filter(
                    FilterPlane::Subscribers,
                    key,
                    &WireKey::literal(),
                    None,
                    false,
                )
                .expect("a session with ids left declares")
        };
        let (on_a, on_b) = (filter("demo/scoped/a"), filter("demo/scoped/b"));
        assert!(
            session.write_filter_active(on_a) && session.write_filter_active(on_b),
            "CONTROL: no member holds a subscriber yet"
        );

        for (member, key) in [(9u8, "demo/scoped/a"), (8, "demo/scoped/b")] {
            let mut datagram = beacon(member);
            datagram.extend_from_slice(&encode_frame_with_declare(
                0,
                build_declare_subscriber(2, 0, Some(key)).expect("a subscriber"),
                true,
            ));
            hand_in(&network, 1, member, &datagram);
        }
        eventually("each member's subscriber to open its filter", || {
            !session.write_filter_active(on_a) && !session.write_filter_active(on_b)
        });

        let mut close = [0u8; 8];
        let len = encode_multicast_close_into_slice(&mut close).expect("a close");
        hand_in(&network, 1, 9, &close[..len]);
        eventually("the leaving member's subscriber to be retracted", || {
            session.write_filter_active(on_a)
        });
        assert!(
            !session.write_filter_active(on_b),
            "the member that stayed keeps its subscriber of the same id"
        );
        SessionDrive::close(&*session);
    }

    /// A frame of several samples behind a member's beacon is delivered whole, in order and once
    /// each, however many of its records the delivery lane takes at a time.
    #[test]
    fn a_frame_of_several_samples_from_a_member_is_delivered_whole_and_in_order() {
        let network = Arc::new(Network::default());
        let session = open_member(&network, 1, member_config(1, GROUP)).expect("the member joins");
        SessionDrive::start_read_task(&*session).expect("the read task starts");
        let heard = subscribe(&session, "demo/kept/**");
        let keys = ["demo/kept/a", "demo/kept/b", "demo/kept/c"];
        let mut datagram = beacon(7);
        datagram.extend_from_slice(&frame_of_puts(0, &keys));
        hand_in(&network, 1, 7, &datagram);
        eventually("the three samples", || heard.lock().unwrap().len() >= 3);
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(
            heard.lock().unwrap().len(),
            3,
            "each sample once: a datagram read on is not read again from its start"
        );
        SessionDrive::close(&*session);
    }

    /// Below the engine: the group's receive over a datagram its transport keeps. A host with room
    /// for no other stops the walk before the next message, and with room for one record stops it
    /// before the next record; each walk goes on from where the last stopped, the frame admitted
    /// by its sequence number once, until the datagram is read whole.
    #[cfg(not(feature = "transport-stats"))]
    #[test]
    fn a_kept_group_datagram_is_read_on_from_where_the_host_stopped() {
        use core::net::SocketAddr;
        use wz_session_core::driver_loop::{EventSink, InPlaceRecord, IterationEvent};
        use wz_session_core::multicast_dispatch::{MulticastConfig, MulticastDispatcher};
        use wz_session_core::multicast_rx::dispatch_multicast_inbound_kept;
        use wz_session_core::reassembly_dispatch::{ReassemblyConfig, ReassemblyDispatcher};
        use wz_session_core::wire_const::T_MID_KEEP_ALIVE;
        use wz_session_core::wireexpr_resolve::id_and_suffix_view;

        /// The keys of the Puts it was handed, and how many more records it takes.
        struct Host {
            keys: Vec<String>,
            room: usize,
        }

        impl EventSink for Host {
            fn event(&mut self, _event: IterationEvent<'_, '_>) {}

            fn record(&mut self, record: InPlaceRecord<'_, '_>) {
                if let Some(push) = record.push() {
                    let (_, suffix) = id_and_suffix_view(&push.keyexpr.body);
                    self.keys.push(suffix.unwrap_or_default().to_owned());
                }
                self.room = self.room.saturating_sub(1);
            }

            fn takes_another(&mut self) -> bool {
                self.room > 0
            }
        }

        let keys = ["demo/kept/a", "demo/kept/b", "demo/kept/c"];
        let mut datagram = beacon(9);
        datagram.push(T_MID_KEEP_ALIVE);
        datagram.extend_from_slice(&frame_of_puts(0, &keys));
        let from = SocketAddr::from(([192, 0, 2, 9], 7447));
        let local = params(1);
        let group = || {
            let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
            assert!(dispatcher.create().open());
            assert!(!dispatcher.notify_link_ready().release());
            let reasm: ReassemblyDispatcher<4, 4096> =
                ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000));
            (dispatcher, reasm)
        };

        let (mut dispatcher, mut reasm) = group();
        let mut host = Host {
            keys: Vec::new(),
            room: 0,
        };
        let mut walk = |host: &mut Host, resume| {
            dispatch_multicast_inbound_kept(
                &mut dispatcher,
                &mut reasm,
                &local,
                &datagram,
                from,
                1_000,
                resume,
                true,
                host,
                &(),
            )
        };
        let stopped = walk(&mut host, None);
        assert!(
            stopped.is_some(),
            "stopped after the beacon, before the next message"
        );
        assert!(host.keys.is_empty());
        host.room = 1;
        let stopped = walk(&mut host, stopped);
        assert!(stopped.is_some(), "stopped after one record");
        assert_eq!(host.keys, ["demo/kept/a"]);
        host.room = 1;
        let stopped = walk(&mut host, stopped);
        assert!(stopped.is_some());
        assert_eq!(
            host.keys,
            ["demo/kept/a", "demo/kept/b"],
            "the next record, its frame not refused as one seen"
        );
        host.room = usize::MAX;
        let stopped = walk(&mut host, stopped);
        assert_eq!(stopped, None, "read whole");
        assert_eq!(host.keys, keys);

        // CONTROL: a transport that keeps nothing has its datagram read whole at once.
        let (mut dispatcher, mut reasm) = group();
        let mut whole = Host {
            keys: Vec::new(),
            room: 0,
        };
        let stopped = dispatch_multicast_inbound_kept(
            &mut dispatcher,
            &mut reasm,
            &local,
            &datagram,
            from,
            1_000,
            None,
            false,
            &mut whole,
            &(),
        );
        assert_eq!(stopped, None);
        assert_eq!(whole.keys, keys);
    }
}
