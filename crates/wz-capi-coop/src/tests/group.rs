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
use wz_capi_port::{FilterPlane, SessionDrive, SessionEngine, WireKey};
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::app_link_table::{
    AppLinkKind, AppLinkTable, LinkHandle, ProgramEvent, ProgramOpen, ProgramSend,
};
use wz_session_core::app_transport::{AppPort, AppTransport, TableLock};
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

    assert_eq!(member.send_join_on_groups(), 1, "the one group is asked");
    eventually("the JOIN asked for", || network.beacons_of(1) == 2);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(network.beacons_of(1), 2, "and the cadence runs from it");

    SessionDrive::close(&*member);
    assert_eq!(
        member.send_join_on_groups(),
        0,
        "a closed session asks no group"
    );
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

/// Declare a subscriber on `keyexpr` of `engine`, and the payloads it is handed, in order.
fn subscribe(engine: &Engine, keyexpr: &str) -> Arc<Mutex<Vec<Vec<u8>>>> {
    let heard = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let into = Arc::clone(&heard);
    engine
        .declare_subscriber_on_wire(
            keyexpr.to_owned(),
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
            "demo/group/x".to_owned(),
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
            "demo/group/**".to_owned(),
            WireKey::literal(),
            Locality::Any,
            None,
            Arc::new(|| Box::new(|_: &dyn SampleView| {})),
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
        let _watcher =
            first.watch_faces(Arc::new(move |kind: FaceEventKind, face: &FaceSnapshot| {
                into.lock().unwrap().push((kind, face.clone()));
            }));
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
        let sink: LivelinessSink = Arc::new(move || {
            let into = into.clone();
            Box::new(move |sample: LivelinessSample<'_>| {
                into.lock()
                    .unwrap()
                    .push((sample.kind, sample.keyexpr.to_owned()));
            })
        });
        let id = engine
            .declare_liveliness_subscriber_on_wire(
                keyexpr.to_owned(),
                WireKey::literal(),
                history,
                sink,
            )
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
            .declare_liveliness_token_on_wire("demo/alive/one".to_owned(), WireKey::literal(), None)
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
    use wz_capi_port::{FilterPlane, SessionDrive, SessionEngine, WireKey};

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
            .acquire_keyexpr("demo/mapped/q".to_owned())
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
            &mut || Box::new(|_view: &dyn ReplyView| {}) as ReplyCallback,
        );
        assert!(issued.is_some(), "the get was asked");
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
                "demo/mapped/a".to_owned(),
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
            .acquire_keyexpr("demo/mapped/b".to_owned())
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
            AppLinks::new(Arc::clone(&transport)),
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

        // Two fill the lane; the third finds room once the group's task takes the first, which
        // the socket then keeps it from writing.
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
        // The third put has the group's task offer the socket a datagram, which it refuses.
        for _ in 0..3 {
            put_with(&member, CongestionControl::Drop);
        }
        assert_eq!(member.rooms().within(1_000), Room::Congested);
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
