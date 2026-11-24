// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The arena a session's open reserves: its size is its plan's, every row of the plan is lent from
//! it with nothing over, and an open whose arena cannot be reserved, or whose limits are over the
//! build's, dials nothing.

use std::net::UdpSocket;
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_port::{SessionEngine, WireKey};
use wz_runtime_coop::session_drive::SessionDatagramLink;
use wz_runtime_coop::udp_link::{DatagramSocket, UdpDriver};
use wz_runtime_posix::links::PosixLinks;
use wz_runtime_posix::net::PosixUdpSocket;
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::bounded::{BoundedVec, Lent};
use wz_session_core::caps;
use wz_session_core::limit_binding::{LimitValue, Quota, UnlentRows};
use wz_session_core::limits::{SessionLimits, CAPACITY_LIMITS, SESSION_LIMITS};
use wz_session_core::locality::Locality;
use wz_session_core::policy::SessionPolicy;
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::session_actions::{BatchLendCounts, FrameLendCounts};

use super::entity_tables::lowered;
use super::{
    client_config, config, open, open_with, until, CatchAll, Command, Engine, Router, LOOPBACK,
};
use crate::arena::{
    AllocatorMemory, ArenaMemory, ArenaPlan, ArenaRefused, SessionArena, LINK_TX_SLOTS,
};
use crate::round::RoundRowCounts;
use crate::{CoopConfig, OpenError, OpenKeyIds};

/// A memory with none to give, whatever it is asked.
struct NoMemory;

impl ArenaMemory for NoMemory {
    fn reserve(&self, _layout: core::alloc::Layout) -> Option<core::ptr::NonNull<u8>> {
        None
    }

    unsafe fn release(&self, _base: core::ptr::NonNull<u8>, _layout: core::alloc::Layout) {
        unreachable!("a memory that gave nothing is given nothing back");
    }
}

/// A socket an open dials, which says whether anything reached it: a session that dials a `udp/`
/// endpoint sends its InitSyn there first.
struct Probe {
    socket: UdpSocket,
}

impl Probe {
    fn bind() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a free port");
        socket
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("a read timeout");
        Self { socket }
    }

    fn endpoint(&self) -> String {
        let port = self.socket.local_addr().expect("bound").port();
        format!("udp/127.0.0.1:{port}")
    }

    /// Whether a datagram has reached the socket.
    fn reached(&self) -> bool {
        let mut datagram = [0u8; 2048];
        self.socket.recv_from(&mut datagram).is_ok()
    }
}

/// A client that dials `probe` once, under `limits`, and gives the handshake 300 ms.
fn dialling(probe: &Probe, limits: SessionLimits) -> CoopConfig {
    CoopConfig {
        endpoints: vec![probe.endpoint()],
        open_timeout_ms: 300,
        limits,
        ..client_config()
    }
}

/// Open a session dialling `probe` under `limits`, its arena reserved from `memory`.
fn open_dialling(
    probe: &Probe,
    limits: SessionLimits,
    memory: &'static dyn ArenaMemory,
) -> Result<Arc<Engine>, OpenError> {
    Engine::open_in(
        PosixLinks::new(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        PosixEntropy,
        dialling(probe, limits),
        SessionPolicy::defaults(),
        OpenKeyIds::none(),
        memory,
    )
}

/// The count of a link row of a pool of `pool` for `links` links: the pool's, at most the links,
/// in a build that listens; one for each link in a build that only dials, whose links keep buffers
/// of their own.
fn pooled(pool: usize, links: usize) -> usize {
    if cfg!(feature = "listen") {
        pool.min(links)
    } else {
        links
    }
}

/// How many links `plan` holds places for: its row of places in a build that listens, its
/// transmit rows, one for each link, in a build that only dials.
fn link_places(plan: &ArenaPlan) -> usize {
    plan.rows()
        .iter()
        .find(|row| row.part == "link places")
        .map_or_else(|| row(plan, "link transmit slots").count, |row| row.count)
}

/// The row of `plan` named `part`.
fn row(plan: &ArenaPlan, part: &str) -> crate::arena::ArenaRow {
    *plan
        .rows()
        .iter()
        .find(|row| row.part == part)
        .expect("the plan has the row")
}

/// The arena is the sum of its rows' spans, and lending every row from it brings its high-water
/// mark to its size: the plan the open reserves by is exactly what the rows take. The client
/// dials an endpoint, whose text is a row as every other part is.
#[test]
fn the_reservation_is_the_plan_and_lending_every_row_fills_it() {
    let plan = ArenaPlan::of(
        &CoopConfig {
            endpoints: vec!["tcp/127.0.0.1:7447".to_owned()],
            ..client_config()
        },
        &SessionLimits::defaults(),
    )
    .expect("the build's limits lay an arena out");
    let reserved = plan.reserved_bytes().expect("within the address space");
    assert!(
        plan.rows()
            .iter()
            .all(|row| row.bytes().is_some_and(|b| b > 0)),
        "every row holds something: {plan:?}"
    );
    let mut session =
        SessionArena::reserve(&plan, &AllocatorMemory).expect("the host has the memory");
    assert_eq!(session.bytes(), reserved);
    for row in plan.rows() {
        let bytes = row.bytes().expect("within the address space");
        let _span: BoundedVec<u8, { usize::MAX }, Lent> = session
            .arena_mut()
            .lend(bytes)
            .expect("the arena is laid out for every row");
    }
    assert_eq!(
        session.arena_mut().high_water(),
        reserved,
        "the rows take the whole arena and no more"
    );
}

/// An open reserves the arena its plan lays out for the config and the limits it was handed.
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn an_open_reserves_the_arena_its_plan_lays_out() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let plan = host_plan(&super::config(&router)).expect("the build's limits lay an arena out");
    assert_eq!(Some(engine.arena_bytes()), plan.reserved_bytes());
}

/// The arena an open of `config` over the host's links the tests open with reserves, as the
/// engine plans it: its links' cells and their gates' included.
fn host_plan(config: &CoopConfig) -> Result<ArenaPlan, ArenaRefused> {
    crate::engine::arena_plan::<PosixClock, _>(
        &PosixLinks::new(super::LOOPBACK, PosixTcpDial),
        config,
    )
}

/// An open whose memory has none to give is refused with the bytes it asked for, before anything
/// is dialled. The CONTROL is the same open with memory, which dials the probe (and fails, as
/// nothing answers it).
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn an_open_whose_arena_the_memory_refuses_dials_nothing() {
    let probe = Probe::bind();
    let plan = host_plan(&dialling(&probe, SessionLimits::defaults()))
        .expect("the build's limits lay an arena out");
    let bytes = plan.reserved_bytes().expect("within the address space");
    let refused = open_dialling(&probe, SessionLimits::defaults(), &NoMemory).err();
    assert_eq!(
        refused,
        Some(OpenError::Arena(ArenaRefused::NoMemory { bytes }))
    );
    assert!(!probe.reached(), "nothing was dialled");

    let unanswered = open_dialling(&probe, SessionLimits::defaults(), &AllocatorMemory).err();
    assert!(
        matches!(unanswered, Some(OpenError::Unreachable(_))),
        "{unanswered:?}"
    );
    assert!(probe.reached(), "CONTROL: the probe sees a dial");
}

/// A session limit the open is handed over the build's value refuses the open, naming the limit
/// and both values, before anything is dialled: a stage after the build only lowers it.
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn an_open_whose_limit_is_over_the_builds_value_dials_nothing() {
    let over = caps::MAX_SUBSCRIPTIONS + 1;
    let mut limits = SessionLimits::defaults();
    if limits
        .select_max_subscriptions(Quota::at_most(over))
        .is_err()
    {
        // A build that sizes the table by the limit has no such value in its domain.
        return;
    }
    let probe = Probe::bind();
    let refused = open_dialling(&probe, limits, &AllocatorMemory).err();
    assert_eq!(
        refused,
        Some(OpenError::Arena(ArenaRefused::Limit {
            limit: "MAX_SUBSCRIPTIONS",
            why: UnlentRows::OverCeiling {
                value: over,
                ceiling: caps::MAX_SUBSCRIPTIONS,
            },
        }))
    );
    assert!(!probe.reached(), "nothing was dialled");
}

/// A value under the build's lowers the row of its table, and the build's value is the row of a
/// session that states none.
#[test]
fn a_limit_lowered_at_open_lowers_its_row() {
    let lowered = lowered(|l| l.select_max_subscriptions(Quota::at_most(2)));
    let at_two = ArenaPlan::of(&client_config(), &lowered).expect("lays an arena out");
    let built =
        ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
    assert_eq!(at_two.tables().subscribers, 2);
    assert_eq!(built.tables().subscribers, caps::MAX_SUBSCRIPTIONS);
    assert!(at_two.reserved_bytes() < built.reserved_bytes());
}

/// The watchers' lists of the application's observer take the row the plan lays out for them: the
/// session's `MAX_DECL_OBSERVERS` rows of each list, as the observer lent under the same limits
/// takes them, so a lowered value lowers the row. Turned red by a plan that leaves the lists out,
/// or an observer that lends them other rows than the plan counts.
#[test]
fn the_plan_lays_out_the_watcher_lists_the_limits_state() {
    use wz_session_core::slot_observer::{HeapSinks, SlotObserverOf};
    type App = SlotObserverOf<HeapSinks, Lent>;
    let built =
        ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
    let watchers = row(&built, "declaration watchers");
    let rows = App::decl_watcher_rows(&SessionLimits::defaults()).expect("the build's value");
    assert_eq!(rows, caps::MAX_DECL_OBSERVERS);
    assert_eq!(watchers.count, 1, "one row of the lists' spans");
    assert_eq!(Some(watchers.entry_bytes), App::decl_watcher_bytes(rows));
    assert!(
        watchers.entry_bytes > 0,
        "a build that reads what a peer declares has watchers"
    );
    if caps::MAX_DECL_OBSERVERS > 1 {
        let one = lowered(|l| l.select_max_decl_observers(Quota::at_most(1)));
        let plan = ArenaPlan::of(&client_config(), &one).expect("lays an arena out");
        assert_eq!(
            Some(row(&plan, "declaration watchers").entry_bytes),
            App::decl_watcher_bytes(1)
        );
        assert!(plan.reserved_bytes() < built.reserved_bytes());
    }
}

/// The limits of the engine's record of its declarations are the snapshot's, under the build's
/// value: with nothing stated each table is lent the build's value, one stated lowers it, and one
/// over the build's refuses the plan naming the limit and both values.
#[test]
fn each_declaration_limit_is_the_snapshots_under_the_builds_value() {
    type Select = fn(
        &mut SessionLimits,
        Quota,
    ) -> Result<(), wz_session_core::limit_binding::OutsideLimitDomain>;
    type Count = fn(&ArenaPlan) -> usize;
    let cases: [(&str, usize, Select, Count); 4] = [
        (
            "MAX_PUBLISHERS",
            caps::MAX_PUBLISHERS,
            SessionLimits::select_max_publishers,
            |plan| plan.entities().publishers,
        ),
        (
            "MAX_QUERIERS",
            caps::MAX_QUERIERS,
            SessionLimits::select_max_queriers,
            |plan| plan.entities().queriers,
        ),
        (
            "MAX_MATCHING_LISTENERS",
            caps::MAX_MATCHING_LISTENERS,
            SessionLimits::select_max_matching_listeners,
            |plan| plan.entities().matching_listeners,
        ),
        (
            "MAX_DECLARED_KEYEXPRS",
            caps::MAX_DECLARED_KEYEXPRS,
            SessionLimits::select_max_declared_keyexprs,
            |plan| plan.entities().keyexprs,
        ),
    ];
    let built =
        ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
    for (limit, build, select, count) in cases {
        assert_eq!(count(&built), build, "{limit} with nothing stated");
        let mut one = SessionLimits::defaults();
        if build >= 1 && select(&mut one, Quota::at_most(1)).is_ok() {
            let plan = ArenaPlan::of(&client_config(), &one).expect("lays an arena out");
            assert_eq!(count(&plan), 1, "{limit} stated as one");
        }
        let mut over = SessionLimits::defaults();
        // A build that sizes the table by the limit has no value over it in its domain.
        if select(&mut over, Quota::at_most(build + 1)).is_ok() {
            assert_eq!(
                ArenaPlan::of(&client_config(), &over),
                Err(ArenaRefused::Limit {
                    limit,
                    why: UnlentRows::OverCeiling {
                        value: build + 1,
                        ceiling: build,
                    },
                }),
                "{limit} over the build's value"
            );
        }
    }
}

/// The links' buffers are the batch the config advertises, held to the batch the session's limits
/// state: a lowered batch the config fits lays the buffers out at the config's, and a config
/// batch over the stated one refuses the plan, naming the limit and both values.
#[test]
fn the_links_batch_is_held_to_the_snapshots() {
    let lowered = lowered(|l| l.select_pico_unicast_batch_bytes(512));
    let fits = ArenaPlan::of(
        &CoopConfig {
            batch_size: 512,
            ..client_config()
        },
        &lowered,
    )
    .expect("a batch the snapshot holds lays an arena out");
    assert_eq!(row(&fits, "link receive buffers").entry_bytes, 512);
    assert_eq!(
        ArenaPlan::of(
            &CoopConfig {
                batch_size: 513,
                ..client_config()
            },
            &lowered,
        ),
        Err(ArenaRefused::Limit {
            limit: "PICO_UNICAST_BATCH_BYTES",
            why: UnlentRows::OverCeiling {
                value: 513,
                ceiling: 512,
            },
        })
    );
}

/// A batch the session's limits state over the build's refuses the plan whatever the config
/// advertises: the build fixes the most a link's buffers take.
#[test]
fn a_snapshot_batch_over_the_builds_refuses_the_plan() {
    let over = caps::PICO_UNICAST_BATCH_BYTES + 1;
    let mut raised = SessionLimits::defaults();
    if raised.select_pico_unicast_batch_bytes(over).is_err() {
        // A build whose domain stops at its own batch has no value over it.
        return;
    }
    assert_eq!(
        ArenaPlan::of(&client_config(), &raised),
        Err(ArenaRefused::Limit {
            limit: "PICO_UNICAST_BATCH_BYTES",
            why: UnlentRows::OverCeiling {
                value: over,
                ceiling: caps::PICO_UNICAST_BATCH_BYTES,
            },
        })
    );
}

/// The plan counts the faces a config can open with and no more, all within the sets the arena
/// lends (`MAX_FACE_SETS`): as many as the build admits besides the dial role's, and in a build
/// that joins groups one for each group the task cells hold. A config told to join more groups than
/// that, whose open is refused at the join past them, still lays out, so it is refused there as it
/// was; a build without `group` counts no group, as it refuses any by name.
#[test]
fn the_faces_a_config_opens_with_fit_the_sets_the_arena_lends() {
    use crate::arena::{admitted_faces, MAX_FACE_SETS};
    use wz_capi_port::group::{GroupDeclarations, GroupJoin, GroupProfile};

    let join = GroupJoin {
        endpoint: "udp/239.7.7.7:7447#iface=lan7".to_owned(),
        profile: GroupProfile {
            lease_ms: 10_000,
            join_interval_ms: 2_500,
            max_sessions: None,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size: 2_048,
            is_qos: false,
            compression: false,
            join_rule: wz_session_core::multicast_params::GroupJoinRule::Pico,
        },
        is_shm: false,
        declarations: GroupDeclarations::Entities,
    };
    let most = admitted_faces(&SessionLimits::defaults()).expect("the build's limits");
    let groups = if cfg!(feature = "group") {
        caps::MAX_TASKS
    } else {
        0
    };
    for asked in [groups, groups + 2] {
        // A session that dials as well as joining, so its dial role's face is counted whatever
        // the groups it joins.
        let plan = ArenaPlan::of(
            &CoopConfig {
                endpoints: vec!["tcp/127.0.0.1:7447".to_owned()],
                max_faces: most,
                groups: vec![join.clone(); asked],
                ..client_config()
            },
            &SessionLimits::defaults(),
        )
        .expect("lays an arena out");
        assert_eq!(
            plan.peers().tables,
            1 + most + groups,
            "{asked} groups asked"
        );
        assert!(plan.peers().tables <= MAX_FACE_SETS);
        assert_eq!(row(&plan, "face tables").count, plan.peers().sets());
        assert_eq!(row(&plan, "held faces").count, plan.peers().sets());
    }
}

/// The tokens of faces that went before each was retracted are owed apart from the sets those
/// faces gave back, a table of them lent at the open with a row for each row of the session's token
/// pool: a face owes apart only while its tokens hold a row of the pool, so the faces owing at
/// once are never more. A session of one face, whose one face never goes, is lent none.
#[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
#[test]
fn the_tokens_owed_apart_are_bounded_by_the_sessions_token_pool() {
    let many = ArenaPlan::of(
        &CoopConfig {
            max_faces: 3,
            ..client_config()
        },
        &SessionLimits::defaults(),
    )
    .expect("lays an arena out");
    let pools = many.peers().pools;
    assert!(pools.shared, "a session of many faces shares its pools");
    assert_eq!(many.peers().owed_tokens(), pools.remote_decls);
    assert_eq!(row(&many, "owed tokens").count, pools.remote_decls);
    let one = ArenaPlan::of(
        &CoopConfig {
            max_faces: 0,
            ..client_config()
        },
        &SessionLimits::defaults(),
    )
    .expect("lays an arena out");
    assert!(
        !one.peers().pools.shared,
        "CONTROL: one face shares nothing"
    );
    assert_eq!(one.peers().owed_tokens(), 0);
    assert!(
        one.rows().iter().all(|row| row.part != "owed tokens"),
        "a session of one face is lent no table of tokens owed"
    );
}

/// The round's tables are as many rows as the session's `DELIVERY_LANE_EVENTS` and
/// `DELIVERY_LANE_CALLBACKS` state and two of its longest key, each lowered with its limit, and are
/// laid out right after the lane's area, the order the open lends them in.
#[test]
fn the_plan_lays_out_the_rounds_tables_the_limits_state() {
    let built =
        ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
    assert_eq!(
        built.round(),
        RoundRowCounts {
            records: caps::DELIVERY_LANE_EVENTS,
            callbacks: caps::DELIVERY_LANE_CALLBACKS,
            longest_key: caps::MAX_KEYEXPR_BYTES,
        }
    );
    assert_eq!(
        row(&built, "delivery records").count,
        caps::DELIVERY_LANE_EVENTS
    );
    assert_eq!(
        row(&built, "delivery callbacks").count,
        caps::DELIVERY_LANE_CALLBACKS
    );
    let lowered = lowered(|l| {
        l.select_delivery_lane_events(Quota::at_most(4))?;
        l.select_max_keyexpr_bytes(Quota::at_most(32))
    });
    let plan = ArenaPlan::of(&client_config(), &lowered).expect("lays an arena out");
    assert_eq!(row(&plan, "delivery records").count, 4);
    assert_eq!(row(&plan, "delivery keys").count, 1);
    assert_eq!(row(&plan, "delivery keys").entry_bytes, 64);
    assert!(
        plan.reserved_bytes() < built.reserved_bytes(),
        "the lowered limits lower the arena"
    );
    let parts: Vec<&str> = plan.rows().iter().map(|row| row.part).collect();
    let lane = parts
        .iter()
        .position(|part| *part == "delivery lane")
        .expect("the plan has the lane");
    assert_eq!(
        parts[lane + 1..lane + 4],
        ["delivery records", "delivery callbacks", "delivery keys"]
    );
}

/// The delivery lane's area is the `DELIVERY_LANE_BYTES` the session's limits state, one buffer
/// and its flag: a lowered value lowers it, and one over the build's refuses the plan, naming the
/// limit and both values.
#[test]
fn the_plan_lays_out_the_delivery_lane_the_limits_state() {
    let built =
        ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
    assert_eq!(row(&built, "delivery lane").count, 1);
    assert_eq!(
        row(&built, "delivery lane").entry_bytes,
        SessionLimits::defaults().delivery_lane_bytes()
    );
    assert_eq!(row(&built, "delivery lane flag").count, 1);
    let lowered = lowered(|l| l.select_delivery_lane_bytes(1024));
    let plan = ArenaPlan::of(&client_config(), &lowered).expect("lays an arena out");
    assert_eq!(row(&plan, "delivery lane").entry_bytes, 1024);
    let over = caps::DELIVERY_LANE_BYTES + 1;
    let mut raised = SessionLimits::defaults();
    if raised.select_delivery_lane_bytes(over).is_ok() {
        assert_eq!(
            ArenaPlan::of(&client_config(), &raised),
            Err(ArenaRefused::Limit {
                limit: "DELIVERY_LANE_BYTES",
                why: UnlentRows::OverCeiling {
                    value: over,
                    ceiling: caps::DELIVERY_LANE_BYTES,
                },
            })
        );
    }
}

/// The key arena is the `KEY_ARENA_BYTES` the session's limits state, one area with its state: a
/// lowered value lowers it, and one over the build's refuses the plan, naming the limit and both
/// values.
#[test]
fn the_plan_lays_out_the_key_arena_the_limits_state() {
    use wz_session_core::key_arena::KeySpace;

    let built =
        ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
    assert_eq!(
        built.key_bytes(),
        SessionLimits::defaults().key_arena_bytes()
    );
    assert_eq!(row(&built, "key arena").count, 1);
    assert_eq!(
        Some(row(&built, "key arena").entry_bytes),
        KeySpace::span_bytes(built.key_bytes())
    );
    let lowered = lowered(|l| l.select_key_arena_bytes(512));
    let plan = ArenaPlan::of(&client_config(), &lowered).expect("lays an arena out");
    assert_eq!(plan.key_bytes(), 512);
    assert_eq!(
        Some(row(&plan, "key arena").entry_bytes),
        KeySpace::span_bytes(512)
    );
    assert!(plan.reserved_bytes() < built.reserved_bytes());
    let over = caps::KEY_ARENA_BYTES + 1;
    let mut raised = SessionLimits::defaults();
    if raised.select_key_arena_bytes(over).is_ok() {
        assert_eq!(
            ArenaPlan::of(&client_config(), &raised),
            Err(ArenaRefused::Limit {
                limit: "KEY_ARENA_BYTES",
                why: UnlentRows::OverCeiling {
                    value: over,
                    ceiling: caps::KEY_ARENA_BYTES,
                },
            })
        );
    }
}

/// The plan lends each keyed row of the session at the lent policy's size, which keeps the place
/// of its key and not its text: a subscription's row and a face's peer tables are shorter than the
/// static policy's, whose rows keep a key of `MAX_KEYEXPR_BYTES` inline, and the text of every key
/// lies in the plan's one key arena row.
#[test]
fn the_plans_keyed_rows_keep_a_keys_place_and_not_its_text() {
    use wz_session_core::bounded::Static;
    use wz_session_core::id_map::{DeclaredKeys, PeerAliases};
    use wz_session_core::key_arena::KeyRef;
    use wz_session_core::pubsub::SubscriberTable;
    use wz_session_core::sink::BoxedSink;

    let plan =
        ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
    assert_eq!(
        row(&plan, "session tables").entry_bytes,
        crate::engine::CoopTables::arena_bytes(&plan.tables()).expect("within the address space"),
        "the subscribers are rows of the session's one table set"
    );
    assert_eq!(row(&plan, "key arena").count, 1, "one area for every key");
    // A key of the static policy is its text and its length; a place is a few words.
    if caps::MAX_KEYEXPR_BYTES >= 2 * core::mem::size_of::<KeyRef>()
        && caps::MAX_PEER_KEYEXPR_ALIASES > 0
        && caps::MAX_REMOTE_DECLS > 0
    {
        const {
            assert!(
                SubscriberTable::<BoxedSink, Lent>::ROW_BYTES
                    < SubscriberTable::<BoxedSink, Static>::ROW_BYTES
            );
        }
        assert!(
            core::mem::size_of::<PeerAliases<Lent>>() < core::mem::size_of::<PeerAliases<Static>>()
        );
        assert!(
            core::mem::size_of::<DeclaredKeys<Lent>>()
                < core::mem::size_of::<DeclaredKeys<Static>>()
        );
    }
}

/// A listener lays out the gets and the peer tables of a face for each face it admits, a handshake
/// among them, and for the dial role only when it dials; the buffers of a link for each of those
/// and for each handshake it may take off its port besides; and the application's tables once,
/// however many faces it holds.
#[test]
fn a_listener_lays_out_the_gets_of_each_face_it_admits() {
    let dial = ArenaPlan::of(
        &CoopConfig {
            max_faces: 0,
            ..client_config()
        },
        &SessionLimits::defaults(),
    )
    .expect("lays an arena out");
    let listening = ArenaPlan::of(
        &CoopConfig {
            listen: vec!["tcp/127.0.0.1:0".to_owned()],
            max_faces: 3,
            accept_pending: 2,
            ..client_config()
        },
        &SessionLimits::defaults(),
    )
    .expect("lays an arena out");
    // The gets pending on the session's own queryables are held apart from every face's. A build
    // that asks no query lays out no table of them.
    #[cfg(feature = "query")]
    {
        let own = usize::from(cfg!(feature = "local-queryable"));
        assert_eq!(row(&dial, "pending gets").count, 1 + own);
        assert_eq!(row(&listening, "pending gets").count, 3 + own);
        assert_eq!(listening.gets().tables, 3 + own);
        assert_eq!(
            row(&listening, "pending gets").entry_bytes,
            row(&dial, "pending gets").entry_bytes,
            "every face's table is the same"
        );
    }
    #[cfg(not(feature = "query"))]
    assert!(
        dial.rows().iter().all(|row| row.part != "pending gets"),
        "a build that asks no query lays out no table of gets"
    );
    // What a face's peer writes is held once for each face, as its gets are, and never for the
    // session's own gets.
    assert_eq!(row(&dial, "peer tables").count, 1);
    assert_eq!(row(&listening, "peer tables").count, 3);
    assert_eq!(listening.peers().tables, 3);
    assert!(dial.peers().dial && !listening.peers().dial);
    assert_eq!(
        row(&listening, "peer tables").entry_bytes,
        row(&dial, "peer tables").entry_bytes,
        "every face's peer tables are the same"
    );
    assert_eq!(row(&dial, "link receive buffers").count, 1);
    assert_eq!(link_places(&listening), 3 + 2);
    assert_eq!(
        row(&listening, "link receive buffers").count,
        pooled(caps::RX_POOL_BUFFERS, 3 + 2),
        "the links share a pool of receive buffers"
    );
    assert_eq!(
        dial.gets().rows.queries,
        if cfg!(feature = "query") {
            caps::MAX_PENDING_QUERIES
        } else {
            0
        },
        "a build that asks no query lends its gets no row"
    );
    assert_eq!(
        row(&listening, "session tables"),
        row(&dial, "session tables"),
        "the application's tables are held once"
    );
}

/// The dial role's face is lent a link's buffers and a face's tables only when the session dials:
/// a listener that lists an endpoint lays out one link and one face more than the same listener
/// with none, and a session that lists neither an endpoint nor a port still lays the dial role's
/// out, as its open tries to dial (and fails for want of an endpoint, as before).
#[test]
fn the_dial_roles_link_and_face_are_laid_out_only_for_a_session_that_dials() {
    let listener = |endpoints: Vec<String>| CoopConfig {
        endpoints,
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        max_faces: 3,
        accept_pending: 2,
        ..client_config()
    };
    let plan = |config: &CoopConfig| {
        ArenaPlan::of(config, &SessionLimits::defaults()).expect("lays an arena out")
    };
    let only = listener(Vec::new());
    let dialling = listener(vec!["tcp/127.0.0.1:7447".to_owned()]);
    assert!(!crate::arena::dials(&only) && crate::arena::dials(&dialling));
    let (only, dialling) = (plan(&only), plan(&dialling));
    let own = usize::from(cfg!(feature = "local-queryable"));
    assert_eq!(link_places(&only), 3 + 2);
    assert_eq!(link_places(&dialling), 1 + 3 + 2);
    assert_eq!((only.peers().tables, only.gets().tables), (3, 3 + own));
    assert_eq!(
        (dialling.peers().tables, dialling.gets().tables),
        (1 + 3, 1 + 3 + own)
    );
    assert!(dialling.peers().dial && !only.peers().dial);
    assert!(
        only.reserved_bytes() < dialling.reserved_bytes(),
        "the listener that dials nothing reserves less"
    );
    let nothing = CoopConfig {
        max_faces: 0,
        ..client_config()
    };
    assert!(
        crate::arena::dials(&nothing),
        "its open tries the dial role"
    );
    assert_eq!(row(&plan(&nothing), "link receive buffers").count, 1);
}

/// Each face's peer tables are lent the values of their limits the open resolved, the build's for a
/// session that states none, the `Final`s none in a build without `queryable`; a limit lowered at
/// the open lowers the row. The reply stage is lent no row in any build: the engine's queryable
/// answers into a stage of its own, and a reply limit over the build's still refuses the open by
/// its name.
#[test]
fn each_faces_peer_tables_take_the_values_the_open_resolved() {
    let built =
        ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
    let rows = built.peers().rows;
    assert_eq!(rows.pending_declares, caps::MAX_PENDING_DECLARES);
    let answers = cfg!(feature = "queryable");
    assert_eq!(
        (rows.replies, rows.reply_bytes, rows.finals),
        (0, 0, if answers { caps::MAX_PENDING_FINALS } else { 0 })
    );
    let mut over = SessionLimits::defaults();
    // A build that sizes the stage by the limit has no value over it in its domain.
    if answers
        && over
            .select_max_pending_replies(Quota::at_most(caps::MAX_PENDING_REPLIES + 1))
            .is_ok()
    {
        assert_eq!(
            ArenaPlan::of(&client_config(), &over),
            Err(ArenaRefused::Limit {
                limit: "MAX_PENDING_REPLIES",
                why: UnlentRows::OverCeiling {
                    value: caps::MAX_PENDING_REPLIES + 1,
                    ceiling: caps::MAX_PENDING_REPLIES,
                },
            }),
            "a reply limit over the build's refuses the open"
        );
    }
    let lowered = lowered(|l| l.select_max_pending_declares(Quota::at_most(1)));
    let at_one = ArenaPlan::of(&client_config(), &lowered).expect("lays an arena out");
    assert_eq!(at_one.peers().rows.pending_declares, 1);
    assert!(
        row(&at_one, "peer tables").entry_bytes < row(&built, "peer tables").entry_bytes,
        "the staging lent fewer rows"
    );
}

/// The pools of what the faces' peers write hold the fewer of the session's limit and what the
/// faces could hold together, each at the bound of one peer: a session of one face lends what that
/// face's tables held, a listener of four lends four faces' worth, and a session limit lowered at
/// the open lowers its pool and no other, the faces' own tables untouched.
#[test]
fn the_pools_hold_the_fewer_of_the_sessions_limit_and_what_its_faces_could() {
    let one = ArenaPlan::of(
        &CoopConfig {
            max_faces: 0,
            ..client_config()
        },
        &SessionLimits::defaults(),
    )
    .expect("lays an arena out");
    let four = ArenaPlan::of(
        &CoopConfig {
            max_faces: 3,
            ..client_config()
        },
        &SessionLimits::defaults(),
    )
    .expect("lays an arena out");
    let face = |each: usize, session: usize, sets: usize| (each * sets).min(session);
    for (plan, sets) in [(&one, 1), (&four, 4)] {
        let pools = plan.peers().pools;
        assert_eq!(
            (pools.remote_decls, pools.aliases, pools.interests),
            (
                face(caps::MAX_REMOTE_DECLS, caps::SESSION_MAX_REMOTE_DECLS, sets),
                face(
                    caps::MAX_PEER_KEYEXPR_ALIASES,
                    caps::SESSION_MAX_PEER_KEYEXPR_ALIASES,
                    sets
                ),
                face(
                    caps::MAX_INBOUND_SUB_INTERESTS,
                    caps::SESSION_MAX_INBOUND_SUB_INTERESTS,
                    sets
                ),
            ),
            "a session of {sets} faces"
        );
    }
    if caps::MAX_REMOTE_DECLS < 2 || caps::SESSION_MAX_REMOTE_DECLS < 2 {
        // A pool of one row cannot be lowered and still hold one.
        return;
    }
    let lowered = lowered(|l| l.select_session_max_remote_decls(Quota::at_most(1)));
    let at_one = ArenaPlan::of(
        &CoopConfig {
            max_faces: 3,
            ..client_config()
        },
        &lowered,
    )
    .expect("lays an arena out");
    assert_eq!(at_one.peers().pools.remote_decls, 1);
    assert_eq!(
        (at_one.peers().pools.aliases, at_one.peers().rows),
        (four.peers().pools.aliases, four.peers().rows),
        "the other pools and the faces' tables are untouched"
    );
    assert!(
        row(&at_one, "peer declaration pools").entry_bytes
            < row(&four, "peer declaration pools").entry_bytes,
        "the declarations' pools lent fewer rows"
    );
}

/// A pool or a span names its rows by `u16`: a count past `MAX_POOL_ROWS` refuses the open by the
/// limit that set it, the session's for a pool of many faces and the face's for a span of one,
/// and a count at it is lent.
#[test]
fn a_pool_past_what_a_u16_names_refuses_the_open_by_its_limit() {
    use crate::arena::kind_rows;
    use wz_session_core::row_pool::MAX_POOL_ROWS;
    let over = |limit| {
        Err(ArenaRefused::Limit {
            limit,
            why: UnlentRows::OverCeiling {
                value: MAX_POOL_ROWS + 1,
                ceiling: MAX_POOL_ROWS,
            },
        })
    };
    let (face, session) = ("MAX_REMOTE_DECLS", "SESSION_MAX_REMOTE_DECLS");
    assert_eq!(
        kind_rows(2, (face, MAX_POOL_ROWS), (session, MAX_POOL_ROWS + 1)),
        over(session),
        "the session's limit sets a pool of two faces"
    );
    assert_eq!(
        kind_rows(1, (face, MAX_POOL_ROWS + 1), (session, usize::MAX)),
        over(face),
        "the face's bound sets a span of one"
    );
    assert_eq!(
        kind_rows(3, (face, 16), (session, MAX_POOL_ROWS)),
        Ok(48),
        "under both"
    );
    assert_eq!(
        kind_rows(3, (face, MAX_POOL_ROWS), (session, MAX_POOL_ROWS)),
        Ok(MAX_POOL_ROWS),
        "at the most a u16 names"
    );
}

/// The session is lent one table of reassembly buffers its links share, a buffer for each chain
/// one peer stages at once however many links the session may hold, each as long as the
/// session's `PICO_FRAG_MAX_BYTES`: the build's for a session that states none, the value a
/// session lowers it to, and a value over the build's refuses the plan under its own name.
#[test]
fn the_session_is_lent_one_table_of_reassembly_buffers_of_the_snapshots_length() {
    use wz_runtime_coop::reassembly_rx::LENT_CHAINS;

    let config = CoopConfig {
        max_faces: 2,
        ..client_config()
    };
    let built = ArenaPlan::of(&config, &SessionLimits::defaults()).expect("lays an arena out");
    assert_eq!(row(&built, "reassembly buffers").count, LENT_CHAINS);
    assert_eq!(
        row(&built, "reassembly buffers").entry_bytes,
        caps::PICO_FRAG_MAX_BYTES
    );
    assert_eq!(built.reassembly(), (caps::PICO_FRAG_MAX_BYTES, LENT_CHAINS));
    let one_link = ArenaPlan::of(
        &CoopConfig {
            max_faces: 0,
            ..client_config()
        },
        &SessionLimits::defaults(),
    )
    .expect("lays an arena out");
    assert_eq!(
        one_link.reassembly(),
        built.reassembly(),
        "the table does not grow with the links"
    );
    let lowered = lowered(|l| l.select_pico_frag_max_bytes(Quota::at_most(1024)));
    let plan = ArenaPlan::of(&config, &lowered).expect("lays an arena out");
    assert_eq!(row(&plan, "reassembly buffers").entry_bytes, 1024);
    let over = caps::PICO_FRAG_MAX_BYTES + 1;
    let mut raised = SessionLimits::defaults();
    if raised
        .select_pico_frag_max_bytes(Quota::at_most(over))
        .is_ok()
    {
        assert_eq!(
            ArenaPlan::of(&config, &raised),
            Err(ArenaRefused::Limit {
                limit: "PICO_FRAG_MAX_BYTES",
                why: UnlentRows::OverCeiling {
                    value: over,
                    ceiling: caps::PICO_FRAG_MAX_BYTES,
                },
            })
        );
    }
}

/// The ends of the session's legs are lent a row for each get every table of pending gets holds,
/// the only place an end waits for its delivery.
#[cfg(feature = "query")]
#[test]
fn the_plan_lends_a_row_for_the_end_of_each_get() {
    let plan = ArenaPlan::of(
        &CoopConfig {
            max_faces: 2,
            ..client_config()
        },
        &SessionLimits::defaults(),
    )
    .expect("lays an arena out");
    let gets = plan.gets();
    let legs = gets.tables * (gets.rows.queries + gets.rows.liveliness_gets);
    assert_eq!(gets.legs(), Some(legs));
    assert_eq!(row(&plan, "ended legs").count, legs);
    assert_eq!(
        row(&plan, "ended legs").entry_bytes,
        core::mem::size_of::<crate::engine::Ended>()
    );
}

/// The queries held for their callbacks are the value of `MAX_PENDING_FINALS` the open resolved,
/// the build's for a session that states none.
#[cfg(feature = "queryable")]
#[test]
fn the_plan_holds_the_queries_its_limit_resolves() {
    let built =
        ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
    assert_eq!(built.held_queries(), caps::MAX_PENDING_FINALS);
    let lowered = lowered(|l| l.select_max_pending_finals(Quota::at_most(1)));
    let at_one = ArenaPlan::of(&client_config(), &lowered).expect("lays an arena out");
    assert_eq!(at_one.held_queries(), 1);
}

/// A config that states more faces than the session's `MAX_FACES`, or a listener more handshakes
/// than its `MAX_ACCEPT_PENDING`, is refused by the limit's name before any memory is asked, as is
/// one past the build's value; a session that only dials is not held to the handshakes' bound, as
/// it takes none. The CONTROL is the same config at the limit, which lays an arena out.
#[test]
fn a_config_past_its_faces_or_handshakes_is_refused_by_name() {
    let listen = vec!["tcp/127.0.0.1:0".to_owned()];
    let two_faces = lowered(|l| l.select_max_faces(Quota::at_most(2)));
    assert_eq!(
        ArenaPlan::of(
            &CoopConfig {
                listen: listen.clone(),
                max_faces: 3,
                ..client_config()
            },
            &two_faces,
        ),
        Err(ArenaRefused::Limit {
            limit: "MAX_FACES",
            why: UnlentRows::OverCeiling {
                value: 3,
                ceiling: 2,
            },
        })
    );
    let at_two = ArenaPlan::of(
        &CoopConfig {
            listen: listen.clone(),
            max_faces: 2,
            ..client_config()
        },
        &two_faces,
    )
    .expect("CONTROL: the faces the session admits lay an arena out");
    assert_eq!(at_two.peers().tables, 2);

    let one_handshake = lowered(|l| l.select_max_accept_pending(Quota::at_most(1)));
    let listener = CoopConfig {
        listen,
        max_faces: 2,
        accept_pending: 2,
        ..client_config()
    };
    assert_eq!(
        ArenaPlan::of(&listener, &one_handshake),
        Err(ArenaRefused::Limit {
            limit: "MAX_ACCEPT_PENDING",
            why: UnlentRows::OverCeiling {
                value: 2,
                ceiling: 1,
            },
        })
    );
    ArenaPlan::of(
        &CoopConfig {
            listen: Vec::new(),
            ..listener
        },
        &one_handshake,
    )
    .expect("a session that only dials takes no handshake");

    assert_eq!(
        ArenaPlan::of(
            &CoopConfig {
                max_faces: usize::MAX,
                ..client_config()
            },
            &SessionLimits::defaults(),
        ),
        Err(ArenaRefused::Limit {
            limit: "MAX_FACES",
            why: UnlentRows::OverCeiling {
                value: usize::MAX,
                ceiling: caps::MAX_FACES,
            },
        })
    );
}

/// The links' rows are what the open lends first: their tables take exactly the rows' spans, a
/// receive buffer of the batch and [`LINK_TX_SLOTS`] slots of it for each link the config admits,
/// and the rest of the plan fills the arena to its size, so the reservation is still the plan.
#[test]
fn the_links_rows_are_lent_first_and_the_reservation_is_still_the_plan() {
    let config = CoopConfig {
        max_faces: 2,
        ..client_config()
    };
    let batch = usize::from(config.batch_size);
    let plan = ArenaPlan::of(&config, &SessionLimits::defaults()).expect("lays an arena out");
    assert_eq!(
        row(&plan, "link receive buffers").count,
        pooled(caps::RX_POOL_BUFFERS, 3),
        "the links share a pool, of no more buffers than links"
    );
    assert_eq!(row(&plan, "link receive buffers").entry_bytes, batch);
    assert_eq!(link_places(&plan), 3);
    assert_eq!(
        row(&plan, "link transmit slots").count,
        pooled(caps::TX_POOL_SLOTS, 3),
        "the links share a pool of outbound slots, of no more than links"
    );
    assert_eq!(
        row(&plan, "link transmit slots").entry_bytes,
        LINK_TX_SLOTS * batch
    );
    let links: usize = plan
        .rows()
        .iter()
        .filter(|row| row.part.starts_with("link "))
        .map(|row| row.span().expect("within the address space"))
        .sum();
    let mut session =
        SessionArena::reserve(&plan, &AllocatorMemory).expect("the host has the memory");
    let mut lend = session.lender();
    let tables = plan.transport().links_from(&mut lend);
    lend.finish().expect("the plan lays the links out");
    assert_eq!(session.arena_mut().high_water(), links);
    for row in plan
        .rows()
        .iter()
        .filter(|row| !row.part.starts_with("link "))
    {
        let bytes = row.bytes().expect("within the address space");
        let _span: BoundedVec<u8, { usize::MAX }, Lent> = session
            .arena_mut()
            .lend(bytes)
            .expect("the arena is laid out for every row");
    }
    assert_eq!(
        Some(session.arena_mut().high_water()),
        plan.reserved_bytes(),
        "the links' rows and the others take the whole arena and no more"
    );
    let held: Vec<_> = (0..3)
        .map(|_| tables.claim().expect("a link's buffers"))
        .collect();
    assert!(tables.claim().is_none(), "a fourth link has none");
    drop(held);
    assert_eq!(tables.in_use(), 0);
}

/// A link over the buffers its session's arena lent reads a datagram where the arena holds its
/// receive buffer, and nowhere else.
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn a_link_reads_into_the_buffer_its_sessions_arena_lent() {
    let config = CoopConfig {
        max_faces: 0,
        ..client_config()
    };
    let plan = ArenaPlan::of(&config, &SessionLimits::defaults()).expect("lays an arena out");
    let mut session =
        SessionArena::reserve(&plan, &AllocatorMemory).expect("the host has the memory");
    let mut lend = session.lender();
    let tables = plan.transport().links_from(&mut lend);
    lend.finish().expect("the plan lays the links out");
    let (rx, tx) = tables.claim().expect("the link's buffers");
    let peer = UdpSocket::bind("127.0.0.1:0").expect("a free port");
    let socket = PosixUdpSocket::bind("127.0.0.1:0".parse().expect("an address"))
        .expect("a socket of the link");
    let at = socket.local();
    let link = UdpDriver::initiator_in(socket, peer.local_addr().expect("bound"), rx, tx);
    peer.send_to(b"a batch", at).expect("sent to the link");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut read = None;
    while read.is_none() {
        assert!(Instant::now() < deadline, "the datagram never arrived");
        link.service();
        link.recv_with(&mut |bytes| read = Some((bytes.as_ptr(), bytes.to_vec())));
    }
    let (held_at, bytes) = read.expect("read above");
    assert_eq!(bytes, b"a batch");
    assert!(
        session.holds(held_at),
        "the link read the datagram where the arena holds its buffer"
    );
    drop(link);
    assert_eq!(
        tables.in_use(),
        0,
        "the buffers are back once the link goes"
    );
}

/// A put leaves in a slot its link took from the session's arena: whether the session stages it
/// in a batch frame or sends it as a frame of its own, the frame is written into the slot and
/// none is built on the heap. The counts are read before and after the put, so the slot frame is
/// the put's.
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn a_put_is_encoded_into_a_slot_the_arena_lent() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);
    until(&engine, "the link to be up", || engine.faces_up() == 1);
    let slots =
        |(batch, whole): (BatchLendCounts, FrameLendCounts)| batch.slot_frames + whole.slot_frames;
    let before = engine.lend_counts().expect("the link is up");
    engine
        .publish_on_wire_all(
            "demo/lent",
            &WireKey::literal(),
            b"v",
            &PublishOptions::put().with_locality(Locality::Remote),
        )
        .expect("a put the link carries");
    until(&engine, "the router to receive the put", || {
        router.seen(|s| s.samples.iter().any(|(k, _)| k == "demo/lent"))
    });
    let after = engine.lend_counts().expect("the link is up");
    assert!(slots(after) > slots(before), "{before:?} then {after:?}");
    let (batch, whole) = after;
    assert_eq!(
        (batch.heap_no_slot, batch.heap_short_slot, whole.heap_frames),
        (0, 0, 0),
        "no frame was built on the heap: {after:?}"
    );
}

/// A link is lent one transmit slot: a run of puts leaves frame after frame from it, each frame
/// sent before the next takes the slot, none built on the heap and none refused for want of a
/// slot, and every put reaches the router.
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn one_slot_a_link_carries_a_run_of_puts() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);
    until(&engine, "the link to be up", || engine.faces_up() == 1);
    let before = engine.lend_counts().expect("the link is up");
    for n in 0..16u8 {
        engine
            .publish_on_wire_all(
                "demo/one-slot",
                &WireKey::literal(),
                &[n],
                &PublishOptions::put().with_locality(Locality::Remote),
            )
            .expect("a put the link carries");
    }
    until(&engine, "the router to receive every put", || {
        router.seen(|s| {
            s.samples
                .iter()
                .filter(|(k, _)| k == "demo/one-slot")
                .count()
                == 16
        })
    });
    let (batch, whole) = engine.lend_counts().expect("the link is up");
    assert!(
        batch.slot_frames + whole.slot_frames > before.0.slot_frames + before.1.slot_frames,
        "the puts left from the slot: {batch:?} {whole:?}"
    );
    assert_eq!(
        (batch.heap_no_slot, batch.heap_short_slot, whole.heap_frames),
        (0, 0, 0),
        "no frame was built on the heap for want of a second slot: {batch:?} {whole:?}"
    );
}

/// A session whose arena holds one link dials again, after its link is lost, over the buffers the
/// lost link held: the lost link lets them go before the next is opened.
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn a_redial_takes_the_buffers_the_lost_link_held() {
    let router = Router::start(CatchAll::None);
    let port = router.port;
    let engine = open_with(CoopConfig {
        redial_ms: Some(50),
        open_timeout_ms: 300,
        max_faces: 0,
        ..config(&router)
    });
    until(&engine, "the first link", || engine.faces_up() == 1);
    router.send(Command::Close);
    drop(router);
    until(&engine, "the link to be lost", || engine.faces_up() == 0);
    let router = Router::start_on(port, CatchAll::None);
    until(&engine, "a link over the buffers the lost one held", || {
        engine.faces_up() == 1
    });
    drop(router);
}

/// A session whose config admits no face besides the dial role's attaches none, as its arena holds
/// the buffers of one link; the CONTROL is the plan of the same config.
#[cfg(feature = "listen")]
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn a_face_past_max_faces_is_not_attached() {
    let router = Router::start(CatchAll::None);
    let second = Router::start_as(0xc4, CatchAll::None);
    let one = CoopConfig {
        max_faces: 0,
        ..config(&router)
    };
    let plan = ArenaPlan::of(&one, &SessionLimits::defaults()).expect("lays an arena out");
    assert_eq!(row(&plan, "link receive buffers").count, 1);
    let engine = open_with(one);
    until(&engine, "the dial role's link", || engine.faces_up() == 1);
    assert!(matches!(
        engine.attach_face(&second.endpoint()),
        Err(OpenError::Unreachable(_))
    ));
    assert_eq!(engine.faces_up(), 1);
}

/// The pico preset of the limits zenoh-pico bounds by no constant, as the generated Kconfig states
/// it: each limit's id and the default it takes under the switch zenoh-pico's defconfig turns on.
fn pico_preset() -> Vec<(&'static str, usize)> {
    const KCONFIG: &str = include_str!("../../../../deploy/Kconfig.limits");
    let mut presets = Vec::new();
    let mut limit = None;
    for line in KCONFIG.lines() {
        if let Some(id) = line.strip_prefix("config WZ_LIMIT_") {
            limit = Some(id);
        } else if let Some(value) = line
            .trim()
            .strip_prefix("default ")
            .and_then(|rest| rest.strip_suffix(" if WZ_LIMITS_ZENOH_PICO"))
        {
            let id = limit.expect("a default follows the limit it is of");
            presets.push((id, value.parse().expect("a preset is a number")));
        }
    }
    presets
}

/// The build's limits with the pico preset selected over them, through the lowering every build
/// these tests run in allows (`lowered`). A preset of a capacity the build fixes and no snapshot
/// holds (a config's table, a scouting window's) sizes storage outside a session and is the build's
/// to apply, so it is passed over here; any other preset names a limit of the session.
fn pico_preset_limits() -> SessionLimits {
    lowered(|limits| {
        for (id, value) in pico_preset() {
            let Some(entry) = SESSION_LIMITS.iter().find(|entry| entry.id() == id) else {
                assert!(
                    CAPACITY_LIMITS.contains(&id),
                    "{id}: a preset names a limit of the session, or a capacity of the build"
                );
                continue;
            };
            entry
                .select(limits, LimitValue::Integer(value))
                .expect("the session reads the limit from its snapshot")?;
        }
        Ok(())
    })
}

/// What the pico interface opens for a session that listens on nothing: the dial role's face and
/// no other, as zenoh-pico's client holds its one transport.
fn preset_client() -> CoopConfig {
    CoopConfig {
        max_faces: 0,
        ..client_config()
    }
}

/// The value the pico preset gives `id`, if it gives one.
fn preset_of(presets: &[(&str, usize)], id: &str) -> Option<usize> {
    presets
        .iter()
        .find(|(limit, _)| *limit == id)
        .map(|(_, value)| *value)
}

/// The limits of entity tables the pico preset leaves at the build's default: zenoh-pico's own
/// client test holds a hundred of each on one session, as many as the default admits.
const HELD_AT_THE_DEFAULT: [&str; 3] = ["MAX_SUBSCRIPTIONS", "MAX_QUERYABLES", "MAX_PUBLISHERS"];

/// The value a session of the pico preset holds of `id`, as the generated Kconfig states it: the
/// preset's where it states one, and the limit's default where it does not, as for a limit
/// zenoh-pico's own tests need the whole default of.
fn pico_value(id: &str) -> usize {
    const KCONFIG: &str = include_str!("../../../../deploy/Kconfig.limits");
    let mut within = false;
    let mut default = None;
    for line in KCONFIG.lines() {
        if let Some(limit) = line.strip_prefix("config WZ_LIMIT_") {
            if within {
                break;
            }
            within = limit == id;
        } else if within {
            if let Some(value) = line.trim().strip_prefix("default ") {
                match value.strip_suffix(" if WZ_LIMITS_ZENOH_PICO") {
                    Some(preset) => return preset.parse().expect("a preset is a number"),
                    None => default = default.or_else(|| value.parse().ok()),
                }
            }
        }
    }
    default.unwrap_or_else(|| panic!("the generated Kconfig states {id}"))
}

/// A session at the pico preset's limits lends each table the preset sizes as many rows as the
/// preset states, the tables that share a limit's rows as many as their limits add up to, and an
/// arena that is the sum of its rows' spans and smaller than the build's.
#[test]
fn the_pico_presets_arena_lends_the_presets_rows() {
    let presets = pico_preset();
    for id in [
        "MAX_QUERIERS",
        "MAX_MATCHING_LISTENERS",
        "MAX_DECLARED_KEYEXPRS",
        "MAX_PENDING_QUERIES",
    ] {
        assert!(
            preset_of(&presets, id).is_some(),
            "the generated Kconfig states the pico preset of {id}"
        );
    }
    let limits = pico_preset_limits();
    let plan = ArenaPlan::of(&preset_client(), &limits).expect("the preset is under the build");
    let built =
        ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
    let preset = pico_value;
    let mut held = 0;
    for row in plan.rows() {
        // The lane's row is one buffer of the limit's bytes, the key arena's one area of them, a
        // pool's one area of the rows its faces share, the watchers' one row of the spans of
        // their lists, and the session's table set one area of its tables, not a row of each.
        if row.basis == "DELIVERY_LANE_BYTES"
            || row.basis == "KEY_ARENA_BYTES"
            || row.basis == "MAX_DECL_OBSERVERS"
            || row.part == "session tables"
            || POOL_PARTS.contains(&row.part)
        {
            continue;
        }
        // A table of a limit the preset leaves at its default, as many as zenoh-pico's own tests
        // hold, is as many rows as that default; any other limit is counted where it has a preset.
        let value = preset_of(&presets, row.basis).or_else(|| {
            HELD_AT_THE_DEFAULT
                .contains(&row.basis)
                .then(|| pico_value(row.basis))
        });
        if let Some(value) = value {
            // A pool the links share holds no more than the links: the client's one.
            let value = if row.basis == "RX_POOL_BUFFERS" || row.basis == "TX_POOL_SLOTS" {
                value.min(1)
            } else {
                value
            };
            assert_eq!(row.count, value, "{} at the pico preset", row.part);
            held += 1;
        }
    }
    // The session's table set is one row of the arena; the rows of each of its tables are the
    // plan's own count of them.
    assert_eq!(
        plan.tables().keyexprs,
        preset("MAX_DECLARED_KEYEXPRS"),
        "the session's keyexpr table at the pico preset"
    );
    held += 1;
    assert!(held >= 3, "the preset sizes the plan's rows: {plan:?}");
    let entities = plan.entities();
    assert_eq!(
        entities.filters(),
        Some(preset("MAX_PUBLISHERS") + preset("MAX_QUERIERS"))
    );
    assert_eq!(
        entities.interests(),
        Some(preset("MAX_PUBLISHERS") + preset("MAX_QUERIERS") + preset("MAX_MATCHING_LISTENERS"))
    );
    assert_eq!(
        plan.gets().rows.queries,
        if cfg!(feature = "query") {
            preset("MAX_PENDING_QUERIES")
        } else {
            0
        }
    );
    assert_eq!(
        plan.peers().rows.pending_declares,
        preset("MAX_PENDING_DECLARES")
    );
    assert_eq!(plan.key_bytes(), preset("KEY_ARENA_BYTES"));
    let reserved = plan.reserved_bytes().expect("within the address space");
    assert_eq!(
        Some(reserved),
        plan.rows()
            .iter()
            .try_fold(0usize, |sum, row| sum.checked_add(row.span()?)),
        "the arena is the sum of its rows' spans"
    );
    assert!(
        Some(reserved) < built.reserved_bytes(),
        "the preset's arena is under the build's"
    );
}

/// A pico preset holds the build's relations between its limits: the staging of a peer's interest
/// answers holds every subscriber and every local token the preset admits, and a final.
#[test]
fn the_pico_preset_stages_an_answer_to_every_entity_it_admits() {
    let declares = pico_value("MAX_PENDING_DECLARES");
    let subscribers = pico_value("MAX_SUBSCRIPTIONS");
    let tokens = pico_value("MAX_LOCAL_TOKENS");
    assert!(declares > subscribers && declares > tokens);
}

/// The pico preset admits the liveliness subscribers zenoh-pico's own advanced subscriber example
/// holds on one session: the one its history detects late publishers with and the one the program
/// detects publishers with. Under the preset's value two are declared and asked for; the CONTROL
/// is the third, which the table refuses, so the preset is the bound the session is held to.
#[cfg(feature = "liveliness")]
#[test]
fn the_pico_preset_holds_an_advanced_subscribers_two_liveliness_subscribers() {
    use wz_capi_port::LivelinessSink;
    use wz_session_core::declare::liveliness_sample::LivelinessSample;

    let presets = pico_preset();
    let preset = preset_of(&presets, "MAX_LIVELINESS_SUBSCRIPTIONS").expect("the preset states it");
    assert_eq!(preset, 2, "z_advanced_sub holds two at once");
    let limits = lowered(|l| l.select_max_liveliness_subscriptions(Quota::at_most(preset)));
    let router = Router::start(CatchAll::None);
    let engine = super::entity_tables::open_under(&router, limits);
    let sink = || LivelinessSink::shared(|_sample: LivelinessSample<'_>| {});
    let declare = |key: &str| {
        engine.declare_liveliness_subscriber_on_wire(key, WireKey::literal(), false, sink())
    };
    assert!(
        declare("demo/@adv/pub/**").is_ok(),
        "the history's late-publisher detection"
    );
    assert!(
        declare("demo/**/@adv/pub/**").is_ok(),
        "the program's own publisher detection"
    );
    until(&engine, "the router to see both Interests", || {
        router.seen(|s| s.interests) >= 2
    });
    assert_eq!(
        declare("demo/third"),
        Err(wz_capi_port::Refusal::TableFull),
        "CONTROL: the third is refused"
    );
}

/// The pico preset's delivery lane is the least lane the build accepts at the preset's other
/// values: one record of the larger of the batch and the largest message the session rejoins, with
/// the most a sample adds to it, so a read always finds room for the record it takes next.
#[test]
fn the_pico_presets_lane_holds_one_record() {
    let presets = pico_preset();
    let lane = preset_of(&presets, "DELIVERY_LANE_BYTES").expect("the preset states the lane");
    let limits = pico_preset_limits();
    let frag = limits
        .pico_frag_max_bytes()
        .lent_under(Quota::at_most(caps::PICO_FRAG_MAX_BYTES))
        .expect("the preset's rejoined message is under the build's");
    let key = limits
        .max_keyexpr_bytes()
        .lent_under(Quota::at_most(caps::MAX_KEYEXPR_BYTES))
        .expect("the preset's key is under the build's");
    let subscribers = pico_value("MAX_SUBSCRIPTIONS");
    let liveliness = pico_value("MAX_LIVELINESS_SUBSCRIPTIONS");
    let most = if cfg!(feature = "liveliness") {
        subscribers.max(liveliness)
    } else {
        subscribers
    };
    assert_eq!(
        lane,
        crate::round::read_bytes(limits.pico_unicast_batch_bytes(), frag, key, most),
        "the preset's lane is one record's room"
    );
    let plan = ArenaPlan::of(&preset_client(), &limits).expect("the preset is under the build");
    assert_eq!(row(&plan, "delivery lane").entry_bytes, lane);
    assert!(lane < SessionLimits::defaults().delivery_lane_bytes());
}

/// The parts of an arena held once for each face: the tables of what its peer writes and is owed,
/// its table of pending gets and the ends of their legs.
const FACE_PARTS: [&str; 3] = ["peer tables", "pending gets", "ended legs"];

/// The parts of an arena held once for the session whose size follows its faces: the pools of what
/// the faces' peers write, each one area.
const POOL_PARTS: [&str; 3] = [
    "peer alias pool",
    "peer declaration pools",
    "peer interest pool",
];

/// The parts of an arena held once for each link: its place among the session's links.
const LINK_PARTS: [&str; 1] = ["link places"];

/// The parts of the pool of receive buffers the links share (`RX_POOL_BUFFERS`, at most one for
/// each link).
const RX_PARTS: [&str; 2] = ["link receive flags", "link receive buffers"];

/// The parts of the pool of outbound slots the links share (`TX_POOL_SLOTS`, at most one for each
/// link).
const TX_PARTS: [&str; 2] = ["link transmit flags", "link transmit slots"];

/// The pico preset holds a session's faces to zenoh-pico's own bounds: ten peers on a listener
/// (`Z_LISTEN_MAX_CONNECTION_NB`) and one handshake at a time, and a client its one transport. A
/// client's arena lends one set of a face's tables and the buffers of one link; a peer's lends the
/// same rows, with a set and a link for each of the ten faces it admits and a link for its one
/// handshake: every other row is the client's, item for item, which is the sum
/// `docs/c-abi-no-heap-pools.md` (section 9.6) states.
#[test]
fn the_pico_presets_arena_for_a_client_and_a_peer_is_the_notes_sum() {
    use crate::arena::{admitted_faces, admitted_handshakes};

    let presets = pico_preset();
    let preset = |id: &str| {
        preset_of(&presets, id).unwrap_or_else(|| panic!("the generated Kconfig states {id}"))
    };
    assert_eq!(
        preset("MAX_FACES"),
        10,
        "zenoh-pico's Z_LISTEN_MAX_CONNECTION_NB"
    );
    assert_eq!(
        preset("MAX_ACCEPT_PENDING"),
        1,
        "zenoh-pico accepts one link at a time"
    );
    // What a peer writes keeps the build's bounds: the peer decides how much it sends, and
    // zenoh-pico takes each as it comes. What the peers write together is bounded by the session.
    for id in [
        "MAX_REMOTE_DECLS",
        "MAX_PEER_KEYEXPR_ALIASES",
        "MAX_INBOUND_SUB_INTERESTS",
    ] {
        assert!(
            preset_of(&presets, id).is_none(),
            "the pico preset lowers no limit of what a peer writes, {id}"
        );
    }
    assert_eq!(
        (
            preset("SESSION_MAX_REMOTE_DECLS"),
            preset("SESSION_MAX_PEER_KEYEXPR_ALIASES"),
            preset("SESSION_MAX_INBOUND_SUB_INTERESTS"),
        ),
        (32, 32, 16)
    );
    let limits = pico_preset_limits();
    let faces = admitted_faces(&limits).expect("the preset is under the build");
    let handshakes = admitted_handshakes(&limits).expect("the preset is under the build");
    assert_eq!((faces, handshakes), (10, 1));

    let client = ArenaPlan::of(
        &CoopConfig {
            accept_pending: handshakes,
            ..preset_client()
        },
        &limits,
    )
    .expect("the preset is under the build");
    let peer = ArenaPlan::of(
        &CoopConfig {
            listen: vec!["tcp/127.0.0.1:0".to_owned()],
            max_faces: faces,
            accept_pending: handshakes,
            ..client_config()
        },
        &limits,
    )
    .expect("the preset is under the build");

    let own = usize::from(cfg!(feature = "local-queryable"));
    assert_eq!(client.peers().tables, 1);
    assert_eq!(client.gets().tables, 1 + own);
    assert_eq!(row(&client, "link receive buffers").count, 1);
    assert_eq!(peer.peers().tables, faces);
    assert_eq!(peer.gets().tables, faces + own);
    assert_eq!(link_places(&peer), faces + handshakes);
    assert_eq!(
        row(&peer, "link transmit slots").count,
        pooled(preset("TX_POOL_SLOTS"), faces + handshakes),
        "the peer's links share the preset's outbound pool"
    );
    assert_eq!(
        row(&peer, "link receive buffers").count,
        pooled(preset("RX_POOL_BUFFERS"), faces + handshakes),
        "the peer's links share the preset's pool"
    );

    // The pools hold the fewer of the session's limit and what the faces could hold, each at a
    // peer's own bound: a client's one face what its tables held, and the peer's ten the
    // preset's: it listens and dials nothing, so its dial role's face holds none.
    let shared = |each: usize, session: &str, sets: usize| (each * sets).min(preset(session));
    for (plan, sets) in [(&client, 1), (&peer, faces)] {
        let pools = plan.peers().pools;
        assert_eq!(
            (pools.remote_decls, pools.aliases, pools.interests),
            (
                shared(caps::MAX_REMOTE_DECLS, "SESSION_MAX_REMOTE_DECLS", sets),
                shared(
                    caps::MAX_PEER_KEYEXPR_ALIASES,
                    "SESSION_MAX_PEER_KEYEXPR_ALIASES",
                    sets
                ),
                shared(
                    caps::MAX_INBOUND_SUB_INTERESTS,
                    "SESSION_MAX_INBOUND_SUB_INTERESTS",
                    sets
                ),
            ),
            "the pools of a session of {sets} faces"
        );
    }

    // The tokens the faces that went owe apart are the peer's alone: a client's one face never
    // goes. A row for each row of the session's token pool.
    let owed: Vec<_> = peer
        .rows()
        .iter()
        .filter(|row| row.part == "owed tokens")
        .collect();
    let owes = cfg!(all(
        feature = "liveliness",
        any(feature = "listen", feature = "group")
    ));
    assert_eq!(owed.len(), usize::from(owes), "{owed:?}");
    if let Some(row) = owed.first() {
        assert_eq!(row.count, peer.peers().pools.remote_decls);
    }
    let rows: Vec<_> = peer
        .rows()
        .iter()
        .filter(|row| row.part != "owed tokens")
        .collect();
    assert_eq!(rows.len(), client.rows().len());
    for (theirs, ours) in rows.into_iter().zip(client.rows()) {
        assert_eq!(
            (theirs.part, theirs.basis),
            (ours.part, ours.basis),
            "the same rows in the same order"
        );
        if POOL_PARTS.contains(&theirs.part) {
            assert!(
                theirs.entry_bytes >= ours.entry_bytes,
                "{}: a pool of more faces is no smaller",
                theirs.part
            );
            assert_eq!(theirs.count, 1, "{} is one area", theirs.part);
            continue;
        }
        // Each session's endpoint texts are its own config's, one area of them: the client here
        // names none, the peer the one endpoint it listens on.
        if theirs.part == "endpoint texts" {
            assert_eq!((theirs.count, ours.count), (1, 1), "the texts are one area");
            assert!(
                theirs.entry_bytes > ours.entry_bytes,
                "the peer's endpoint takes a text's row and the client's none"
            );
            continue;
        }
        assert_eq!(
            theirs.entry_bytes, ours.entry_bytes,
            "a face's and a link's items are the same size on either"
        );
        // The peer listens and dials nothing: no link and no face of the dial role's. Its links
        // share the preset's pool of receive buffers, of which the client's one link takes one.
        let count = if RX_PARTS.contains(&theirs.part) {
            pooled(preset("RX_POOL_BUFFERS"), faces + handshakes)
        } else if TX_PARTS.contains(&theirs.part) {
            pooled(preset("TX_POOL_SLOTS"), faces + handshakes)
        } else if LINK_PARTS.contains(&theirs.part) {
            ours.count * (faces + handshakes)
        } else if theirs.part == "peer tables" {
            ours.count * faces
        } else if ["face tables", "held faces"].contains(&theirs.part) {
            // Its dial role's face holds a set of no rows all the same, first, beside the faces'.
            ours.count * (1 + faces)
        } else if FACE_PARTS.contains(&theirs.part) {
            // The gets' tables, and the ends of their legs, hold the session's own once.
            ours.count / (1 + own) * (faces + own)
        } else {
            ours.count
        };
        assert_eq!(
            theirs.count, count,
            "{} of a peer at the pico preset",
            theirs.part
        );
    }
    assert!(
        peer.reserved_bytes()
            < ArenaPlan::of(
                &CoopConfig {
                    listen: vec!["tcp/127.0.0.1:0".to_owned()],
                    ..client_config()
                },
                &SessionLimits::defaults(),
            )
            .expect("lays an arena out")
            .reserved_bytes(),
        "a peer at the preset reserves less than a listener at the build's defaults"
    );
}

/// The rows of the arena a session reserves at its open, item by item, for a client and a peer at
/// the build's limits and at the pico preset's: what each row holds, the limit that counts it, how
/// many items, the bytes of one and of the row, and the reservation. What the measurement of a
/// release library's memory against zenoh-pico's is read row by row from.
///
/// A MEASUREMENT: it asserts only that each plan lays out.
#[test]
#[ignore = "a measurement of a session's arena by row; run with --ignored --nocapture"]
fn the_arena_of_a_session_by_row_measured() {
    use crate::arena::{admitted_faces, admitted_handshakes};

    let print = |name: &str, plan: &ArenaPlan| {
        println!("arena-rows: {name}");
        for row in plan.rows() {
            println!(
                "arena-rows:   {:<36} {:<52} {:>6} x {:>7} = {:>9}",
                row.part,
                row.basis,
                row.count,
                row.entry_bytes,
                row.bytes().unwrap_or(usize::MAX),
            );
        }
        println!(
            "arena-rows:   reserved {}",
            plan.reserved_bytes().unwrap_or(usize::MAX)
        );
    };
    let defaults = SessionLimits::defaults();
    let preset = pico_preset_limits();
    for (name, limits) in [("build limits", defaults), ("pico preset", preset)] {
        let faces = admitted_faces(&limits).expect("the limits are under the build");
        let handshakes = admitted_handshakes(&limits).expect("the limits are under the build");
        let client = ArenaPlan::of(
            &CoopConfig {
                accept_pending: handshakes,
                ..preset_client()
            },
            &limits,
        )
        .expect("a client's plan lays out");
        print(&format!("client at the {name}"), &client);
        let peer = ArenaPlan::of(
            &CoopConfig {
                listen: vec!["tcp/127.0.0.1:0".to_owned()],
                max_faces: faces,
                accept_pending: handshakes,
                ..client_config()
            },
            &limits,
        )
        .expect("a peer's plan lays out");
        print(&format!("peer of {faces} faces at the {name}"), &peer);
    }
}
/// What a listener's open reserves when it is opened at the build's own limits and at the pico
/// preset's, its links' cells included, as the engine plans it: the measure of the default each
/// ABI opens under (the pico ABI at its preset, zenoh-c and the Rust API at the build's). Read
/// with `--ignored --nocapture`.
#[test]
#[ignore = "a measurement: prints the arena a listener reserves at each default"]
fn print_the_arena_a_listener_reserves_at_each_default() {
    for (name, limits) in [
        ("build defaults", SessionLimits::defaults()),
        ("pico preset", pico_preset_limits()),
    ] {
        let config = listener_config(limits).expect("the limits admit their own faces");
        let plan = host_plan(&config).expect("the limits lay an arena out");
        std::println!(
            "{name}: {} faces, {} pending: {} B",
            config.max_faces,
            config.accept_pending,
            plan.reserved_bytes().unwrap_or(usize::MAX)
        );
        for row in plan.rows() {
            std::println!(
                "  {:<40} {:>6} x {:>7} = {:>9} B",
                row.part,
                row.count,
                row.entry_bytes,
                row.bytes().unwrap_or(usize::MAX)
            );
        }
    }

    // What one more of each kind adds at the pico preset: its rows in the engine's tables, and in
    // the tables it is counted in with other kinds (filters, interests). The ABI's own object for
    // the entity, in its place of the arena, comes on top, as the key arena does for its key.
    let preset = pico_preset_limits();
    let at_preset = listener_bytes(preset).expect("the pico preset lays an arena out");
    std::println!("one more of each kind at the pico preset ({at_preset} B):");
    let mut each = Vec::new();
    for id in ENTITY_LIMITS {
        let Some(held) = held_count(&preset, id) else {
            std::println!("  {id:<30} not read by this build");
            continue;
        };
        match selecting(preset, id, held.saturating_add(1)).and_then(listener_bytes) {
            Some(bytes) => {
                let one = bytes.saturating_sub(at_preset);
                each.push((id, held, one));
                std::println!("  {id:<30} {held:>4} held: {one:>7} B each");
            }
            None => std::println!("  {id:<30} {held:>4} held: this build admits no more"),
        }
    }

    // The preset raised to the counts it is to hold: what the plan lays out when the build's
    // capacities admit it, and what the bytes of one of each above make of it in any build.
    let projected = RAISED_PRESET.iter().fold(at_preset, |sum, &(id, value)| {
        each.iter()
            .find(|(kind, _, _)| *kind == id)
            .map_or(sum, |&(_, held, one)| {
                sum.saturating_add(value.saturating_sub(held).saturating_mul(one))
            })
    });
    std::println!("pico preset raised to {RAISED_PRESET:?}:");
    std::println!("  by the bytes of one of each: {projected} B");
    let raised = RAISED_PRESET
        .iter()
        .try_fold(preset, |limits, &(id, value)| selecting(limits, id, value));
    match raised.and_then(listener_bytes) {
        Some(bytes) => std::println!("  as the plan lays it out: {bytes} B"),
        None => {
            std::println!("  as the plan lays it out: past this build's capacities (WZ_LIMIT_*)")
        }
    }
}

/// The counts of each kind the pico preset is to be raised to, by the limit that counts it.
const RAISED_PRESET: [(&str, usize); 4] = [
    ("MAX_PUBLISHERS", 100),
    ("MAX_SUBSCRIPTIONS", 100),
    ("MAX_QUERYABLES", 100),
    ("MAX_DECLARED_KEYEXPRS", 200),
];

/// The limits that count the session's own declarations, a kind each.
const ENTITY_LIMITS: [&str; 8] = [
    "MAX_PUBLISHERS",
    "MAX_SUBSCRIPTIONS",
    "MAX_QUERYABLES",
    "MAX_LOCAL_TOKENS",
    "MAX_LIVELINESS_SUBSCRIPTIONS",
    "MAX_QUERIERS",
    "MAX_MATCHING_LISTENERS",
    "MAX_DECLARED_KEYEXPRS",
];

/// A session that listens, with the faces and handshakes `limits` admit, `None` when the build's
/// capacities admit fewer.
fn listener_config(limits: SessionLimits) -> Option<CoopConfig> {
    use crate::arena::{admitted_faces, admitted_handshakes};

    Some(CoopConfig {
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        max_faces: admitted_faces(&limits).ok()?,
        accept_pending: admitted_handshakes(&limits).ok()?,
        limits,
        ..client_config()
    })
}

/// The bytes the arena of a session that listens under `limits` reserves, `None` when the build
/// lays none out for them.
fn listener_bytes(limits: SessionLimits) -> Option<usize> {
    host_plan(&listener_config(limits)?).ok()?.reserved_bytes()
}

/// How many of the kind the limit `id` counts `limits` holds, `None` for a limit the build does
/// not read.
fn held_count(limits: &SessionLimits, id: &str) -> Option<usize> {
    let entry = SESSION_LIMITS.iter().find(|entry| entry.id() == id)?;
    match entry.value_in(limits) {
        LimitValue::Integer(held) => Some(held),
        LimitValue::Unbounded => None,
    }
}

/// `limits` with `value` selected for the limit `id`, `None` when the build reads no such limit or
/// refuses the value.
fn selecting(mut limits: SessionLimits, id: &str, value: usize) -> Option<SessionLimits> {
    let entry = SESSION_LIMITS.iter().find(|entry| entry.id() == id)?;
    entry
        .select(&mut limits, LimitValue::Integer(value))?
        .ok()?;
    Some(limits)
}

/// A plan with every row of the build, the links' cells, their gates', their actions', the ABI's
/// handle and its places for every kind of entity among them, holds exactly `ARENA_ROWS` rows: the
/// groups' counts are the rows the plan puts, in whichever build. A group that puts a row it does
/// not count, or counts one it does not put, turns this red.
#[test]
fn a_plan_with_every_row_holds_exactly_arena_rows() {
    use crate::arena::{EntityKind, HeldPlaces};
    let place = core::alloc::Layout::new::<u64>();
    let held = EntityKind::ALL
        .into_iter()
        .fold(HeldPlaces::handle(place), |held, kind| {
            held.with_entity(kind, place)
        });
    // Faces that share their pools, so the table of tokens the faces that went owe is put too.
    let plan = ArenaPlan::of(
        &CoopConfig {
            max_faces: 3,
            ..client_config()
        },
        &SessionLimits::defaults(),
    )
    .and_then(|plan| {
        plan.holding_cells(crate::arena::LinkCells {
            driver: 64,
            gate: 64,
            actions: 64,
        })
    })
    .and_then(|plan| plan.holding(&held))
    .expect("the build's limits lay an arena out");
    assert_eq!(plan.rows().len(), crate::arena::ARENA_ROWS);
}
