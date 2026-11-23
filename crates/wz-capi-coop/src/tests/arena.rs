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
use wz_session_core::limits::{SessionLimits, SESSION_LIMITS};
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

/// The row of `plan` named `part`.
fn row(plan: &ArenaPlan, part: &str) -> crate::arena::ArenaRow {
    *plan
        .rows()
        .iter()
        .find(|row| row.part == part)
        .expect("the plan has the row")
}

/// The arena is the sum of its rows' spans, and lending every row from it brings its high-water
/// mark to its size: the plan the open reserves by is exactly what the rows take.
#[test]
fn the_reservation_is_the_plan_and_lending_every_row_fills_it() {
    let plan = ArenaPlan::of(&client_config(), &SessionLimits::defaults())
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
fn an_open_reserves_the_arena_its_plan_lays_out() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let plan = ArenaPlan::of(&super::config(&router), &SessionLimits::defaults())
        .expect("the build's limits lay an arena out");
    assert_eq!(Some(engine.arena_bytes()), plan.reserved_bytes());
}

/// An open whose memory has none to give is refused with the bytes it asked for, before anything
/// is dialled. The CONTROL is the same open with memory, which dials the probe (and fails, as
/// nothing answers it).
#[test]
fn an_open_whose_arena_the_memory_refuses_dials_nothing() {
    let probe = Probe::bind();
    let plan = ArenaPlan::of(
        &dialling(&probe, SessionLimits::defaults()),
        &SessionLimits::defaults(),
    )
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
    assert_eq!(row(&at_two, "subscribers").count, 2);
    assert_eq!(row(&built, "subscribers").count, caps::MAX_SUBSCRIPTIONS);
    assert!(at_two.reserved_bytes() < built.reserved_bytes());
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
        row(&plan, "subscribers").entry_bytes,
        SubscriberTable::<BoxedSink, Lent>::ROW_BYTES
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

/// A listener lays out the gets and the peer tables of a face for the dial role and each face it
/// admits, a handshake among them, and no more; the buffers of a link for each of those and for
/// each handshake it may take off its port besides; and the application's tables once, however many
/// faces it holds.
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
    // The gets pending on the session's own queryables are held apart from every face's.
    let own = usize::from(cfg!(feature = "local-queryable"));
    assert_eq!(row(&dial, "pending gets").count, 1 + own);
    assert_eq!(row(&listening, "pending gets").count, 1 + 3 + own);
    assert_eq!(listening.gets().tables, 1 + 3 + own);
    assert_eq!(
        row(&listening, "pending gets").entry_bytes,
        row(&dial, "pending gets").entry_bytes,
        "every face's table is the same"
    );
    // What a face's peer writes is held once for each face, as its gets are, and never for the
    // session's own gets.
    assert_eq!(row(&dial, "peer tables").count, 1);
    assert_eq!(row(&listening, "peer tables").count, 1 + 3);
    assert_eq!(listening.peers().tables, 1 + 3);
    assert_eq!(
        row(&listening, "peer tables").entry_bytes,
        row(&dial, "peer tables").entry_bytes,
        "every face's peer tables are the same"
    );
    assert_eq!(row(&dial, "link receive buffers").count, 1);
    assert_eq!(row(&listening, "link receive buffers").count, 1 + 3 + 2);
    assert_eq!(dial.gets().rows.queries, caps::MAX_PENDING_QUERIES);
    assert_eq!(
        row(&listening, "subscribers"),
        row(&dial, "subscribers"),
        "the application's tables are held once"
    );
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
        core::mem::size_of::<u64>()
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
    assert_eq!(at_two.peers().tables, 1 + 2);

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
    assert_eq!(row(&plan, "link receive buffers").count, 3);
    assert_eq!(row(&plan, "link receive buffers").entry_bytes, batch);
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
    let tables = session
        .lend_links(&plan)
        .expect("the plan lays the links out");
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
fn a_link_reads_into_the_buffer_its_sessions_arena_lent() {
    let config = CoopConfig {
        max_faces: 0,
        ..client_config()
    };
    let plan = ArenaPlan::of(&config, &SessionLimits::defaults()).expect("lays an arena out");
    let mut session =
        SessionArena::reserve(&plan, &AllocatorMemory).expect("the host has the memory");
    let tables = session
        .lend_links(&plan)
        .expect("the plan lays the links out");
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
#[test]
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
/// these tests run in allows (`lowered`).
fn pico_preset_limits() -> SessionLimits {
    lowered(|limits| {
        for (id, value) in pico_preset() {
            let entry = SESSION_LIMITS
                .iter()
                .find(|entry| entry.id() == id)
                .expect("a preset names a limit of the session");
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

/// A session at the pico preset's limits lends each table the preset sizes as many rows as the
/// preset states, the tables that share a limit's rows as many as their limits add up to, and an
/// arena that is the sum of its rows' spans and smaller than the build's.
#[test]
fn the_pico_presets_arena_lends_the_presets_rows() {
    let presets = pico_preset();
    for id in [
        "MAX_SUBSCRIPTIONS",
        "MAX_PUBLISHERS",
        "MAX_QUERIERS",
        "MAX_MATCHING_LISTENERS",
        "MAX_DECLARED_KEYEXPRS",
        "MAX_PENDING_QUERIES",
        "MAX_PENDING_DECLARES",
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
    let preset = |id: &str| preset_of(&presets, id).expect("the preset states it");
    let mut held = 0;
    for row in plan.rows() {
        // The lane's row is one buffer of the limit's bytes, the key arena's one area of them,
        // and a pool's one area of the rows its faces share, not a row of each.
        if row.basis == "DELIVERY_LANE_BYTES"
            || row.basis == "KEY_ARENA_BYTES"
            || POOL_PARTS.contains(&row.part)
        {
            continue;
        }
        if let Some(value) = preset_of(&presets, row.basis) {
            assert_eq!(row.count, value, "{} at the pico preset", row.part);
            held += 1;
        }
    }
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
    assert_eq!(plan.gets().rows.queries, preset("MAX_PENDING_QUERIES"));
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
    let presets = pico_preset();
    let declares = preset_of(&presets, "MAX_PENDING_DECLARES").expect("the preset states it");
    let subscribers = preset_of(&presets, "MAX_SUBSCRIPTIONS").expect("the preset states it");
    let tokens = preset_of(&presets, "MAX_LOCAL_TOKENS").expect("the preset states it");
    assert!(declares > subscribers && declares > tokens);
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
    let subscribers = preset_of(&presets, "MAX_SUBSCRIPTIONS").expect("the preset states it");
    let liveliness =
        preset_of(&presets, "MAX_LIVELINESS_SUBSCRIPTIONS").expect("the preset states it");
    let most = if cfg!(feature = "liveliness") {
        subscribers.max(liveliness)
    } else {
        subscribers
    };
    assert_eq!(
        lane,
        crate::lane::read_bytes(limits.pico_unicast_batch_bytes(), frag, key, most),
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

/// The parts of an arena held once for each link: its buffers and the flags that lend them.
const LINK_PARTS: [&str; 4] = [
    "link receive flags",
    "link receive buffers",
    "link transmit flags",
    "link transmit slots",
];

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
    assert_eq!(peer.peers().tables, 1 + faces);
    assert_eq!(peer.gets().tables, 1 + faces + own);
    assert_eq!(
        row(&peer, "link receive buffers").count,
        1 + faces + handshakes
    );

    // The pools hold the fewer of the session's limit and what the faces could hold, each at a
    // peer's own bound: a client's one face what its tables held, and the peer's eleven the
    // preset's.
    let shared = |each: usize, session: &str, sets: usize| (each * sets).min(preset(session));
    for (plan, sets) in [(&client, 1), (&peer, 1 + faces)] {
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

    assert_eq!(peer.rows().len(), client.rows().len());
    for (theirs, ours) in peer.rows().iter().zip(client.rows()) {
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
        assert_eq!(
            theirs.entry_bytes, ours.entry_bytes,
            "a face's and a link's items are the same size on either"
        );
        let count = if LINK_PARTS.contains(&theirs.part) {
            ours.count * (1 + faces + handshakes)
        } else if theirs.part == "peer tables" {
            ours.count * (1 + faces)
        } else if FACE_PARTS.contains(&theirs.part) {
            // The gets' tables, and the ends of their legs, hold the session's own once.
            ours.count / (1 + own) * (1 + faces + own)
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
