// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The arena a session's open reserves: its size is its plan's, every row of the plan is lent from
//! it with nothing over, and an open whose arena cannot be reserved, or whose limits are over the
//! build's, dials nothing.

use crate::EngineHold;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::tests::host_links;
use wz_capi_port::{SessionEngine, WireKey};
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

use super::entity_tables::{lowered, open_under};
use super::{
    client_config, config, open, open_with, until, CatchAll, Command, Engine, Router, LOOPBACK,
};
use crate::arena::{
    AllocatorMemory, ArenaLimit, ArenaMemory, ArenaPlan, ArenaRefused, SessionArena,
};
#[cfg(wz_round)]
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
) -> Result<EngineHold<Engine>, OpenError> {
    Engine::open_in(
        host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
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
/// of their own. Read where the plan lays the links' rows out.
#[cfg(any(feature = "listen", not(wz_on_use)))]
fn pooled(pool: usize, links: usize) -> usize {
    if cfg!(feature = "listen") {
        pool.min(links)
    } else {
        links
    }
}

/// How many links `plan` holds places for: its row of places in a build that listens, its
/// transmit rows, one for each link, in a build that only dials.
#[cfg(any(feature = "listen", not(wz_on_use)))]
fn link_places(plan: &ArenaPlan) -> usize {
    plan.rows()
        .find(|row| row.part() == "link places")
        .map_or_else(|| row(plan, "link transmit slots").count, |row| row.count)
}

/// The row of `plan` named `part`.
fn row(plan: &ArenaPlan, part: &str) -> crate::arena::ArenaRow {
    *plan
        .rows()
        .find(|row| row.part() == part)
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
        plan.rows().all(|row| row.bytes().is_some_and(|b| b > 0)),
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

/// An open asked to hold the ABI's handle reserves the plan the open lays out with the handle's
/// place, and one asked for none the plan without it: the places are laid out on the one plan the
/// open reserves by. Turned red by an open that reserves a plan other than the one it lends from,
/// or lays the places out apart from it.
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn an_open_holding_the_handle_reserves_the_plan_with_its_place() {
    use crate::arena::{HeldPlaces, OpenStorage};

    let layout = core::alloc::Layout::from_size_align(40, 8).expect("a layout");
    let held = HeldPlaces::handle(layout);
    let router = Router::start(CatchAll::None);
    let holding = Engine::open_made_in(
        host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        PosixEntropy,
        || config(&router),
        SessionPolicy::defaults(),
        OpenKeyIds::none(),
        OpenStorage {
            memory: &AllocatorMemory,
            plan: crate::arena::PlanFrom::Config(Box::leak(Box::new(held))),
        },
    )
    .expect("the session opens");
    let with_place = held_plan(&config(&router), &held)
        .expect("the handle fits the plan")
        .reserved_bytes()
        .expect("within the address space");
    let without = host_plan(&config(&router))
        .expect("the build's limits lay an arena out")
        .reserved_bytes()
        .expect("within the address space");
    assert_eq!(holding.arena_bytes(), with_place);
    assert!(
        with_place > without,
        "the handle's place is a row of the plan"
    );
}

/// The arena an open of `config` over the host's links the tests open with reserves, as the
/// engine plans it: its links' cells and their gates' included, and no place of the ABI's.
fn host_plan(config: &CoopConfig) -> Result<ArenaPlan, ArenaRefused> {
    held_plan(config, &crate::arena::HeldPlaces::NONE)
}

/// The runtime tables a session `config` opens, as the engine's form sizes them: a form whose
/// links run as tasks sizes their cells by the clock's task, the one-link read reserves none.
#[cfg(all(wz_round, not(wz_on_use)))]
fn runtime_tables(config: &CoopConfig) -> crate::engine::RuntimeTables {
    crate::engine::RuntimeTables::of::<PosixClock>(config)
}

/// The runtime tables a session `config` opens, as the engine's form sizes them: a form whose
/// links run as tasks sizes their cells by the clock's task, the one-link read reserves none.
#[cfg(all(not(wz_round), not(wz_on_use)))]
fn runtime_tables(config: &CoopConfig) -> crate::engine::RuntimeTables {
    crate::engine::RuntimeTables::of(config)
}

/// `host_plan` with the ABI's places `held` laid out after every other row.
fn held_plan(
    config: &CoopConfig,
    held: &crate::arena::HeldPlaces,
) -> Result<ArenaPlan, ArenaRefused> {
    let mut plan = ArenaPlan::vacant();
    plan.count(config, &config.limits)?;
    #[cfg(not(wz_on_use))]
    let links = host_links(super::LOOPBACK, PosixTcpDial);
    #[cfg(not(wz_on_use))]
    let runtime = runtime_tables(config)
        .placed_bytes::<PosixClock>()
        .ok_or(ArenaRefused::TooLarge)?;
    crate::engine::lay_out_open(
        &mut plan,
        &crate::engine::OpenHolds {
            #[cfg(not(wz_on_use))]
            cells: crate::engine::link_cells::<PosixClock>(&links),
            #[cfg(not(wz_on_use))]
            rooms: crate::engine::link_rooms_bytes::<crate::tests::PosixLinks>(),
            held,
            #[cfg(not(wz_on_use))]
            runtime,
            engine: wz_runtime_coop::kept::Shared::<Engine>::layout().size(),
            planes: crate::engine::SessionPlanes::OF_BUILD,
            #[cfg(all(feature = "link-admission", not(wz_on_use)))]
            admission: core::mem::size_of::<crate::engine::Admission<PosixClock>>(),
            #[cfg(all(not(wz_round), not(wz_on_use)))]
            direct_face: Engine::DIRECT_FACE_BYTES,
        },
    )?;
    Ok(plan)
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
    // A session of the region's form asks for its region and its arena as one block, the arena
    // after the region on a span's alignment; one whose tables take their memory on use takes its
    // state from the allocator apart, and asks the memory for its arena alone.
    #[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
    let bytes = bytes
        + wz_session_core::bounded::Arena::span(core::mem::size_of::<crate::region::StateRegion>())
            .expect("a region within the address space");
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
            limit: ArenaLimit::MaxSubscriptions,
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
    // A build of the region's form keeps the table's rows in its region at the build's bound, and
    // holds it to the limit by its count alone: its arena lends none of them.
    #[cfg(wz_lent)]
    assert!(at_two.reserved_bytes() < built.reserved_bytes());
}

/// The watchers' lists of the application's observer take the row the plan lays out for them: the
/// session's `MAX_DECL_OBSERVERS` rows of each list, as the observer lent under the same limits
/// takes them, so a lowered value lowers the row. Turned red by a plan that leaves the lists out,
/// or an observer that lends them other rows than the plan counts. A build of the region's form
/// lends no list from its arena (`crate::region::StateRegion`).
#[cfg(wz_lent)]
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
    let cases: [(ArenaLimit, usize, Select, Count); 4] = [
        (
            ArenaLimit::MaxPublishers,
            caps::MAX_PUBLISHERS,
            SessionLimits::select_max_publishers,
            |plan| plan.entities().of_kind(crate::arena::EntityKind::Publisher),
        ),
        (
            ArenaLimit::MaxQueriers,
            caps::MAX_QUERIERS,
            SessionLimits::select_max_queriers,
            |plan| plan.entities().of_kind(crate::arena::EntityKind::Querier),
        ),
        (
            ArenaLimit::MaxMatchingListeners,
            caps::MAX_MATCHING_LISTENERS,
            SessionLimits::select_max_matching_listeners,
            |plan| {
                plan.entities()
                    .of_kind(crate::arena::EntityKind::MatchingListener)
            },
        ),
        (
            ArenaLimit::MaxDeclaredKeyexprs,
            caps::MAX_DECLARED_KEYEXPRS,
            SessionLimits::select_max_declared_keyexprs,
            |plan| plan.entities().keyexprs,
        ),
    ];
    let built =
        ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
    for (limit, build, select, count) in cases {
        let name = limit.name();
        assert_eq!(count(&built), build, "{name} with nothing stated");
        let mut one = SessionLimits::defaults();
        if build >= 1 && select(&mut one, Quota::at_most(1)).is_ok() {
            let plan = ArenaPlan::of(&client_config(), &one).expect("lays an arena out");
            assert_eq!(count(&plan), 1, "{name} stated as one");
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
                "{name} over the build's value"
            );
        }
    }
}

/// The links' buffers are the batch the config advertises, held to the batch the session's limits
/// state: a lowered batch the config fits sizes the buffers at the config's, laid out so where the
/// arena lends them, and a config batch over the stated one refuses the plan, naming the limit and
/// both values.
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
    assert_eq!(fits.link_bytes(), 512);
    #[cfg(not(wz_on_use))]
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
            limit: ArenaLimit::PicoUnicastBatchBytes,
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
            limit: ArenaLimit::PicoUnicastBatchBytes,
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
            seq_num_res: wz_session_core::policy::SnResolution::Bits32,
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
        // A build of the region's form holds its one face's set in its region.
        #[cfg(wz_lent)]
        assert_eq!(row(&plan, "face tables").count, plan.peers().sets());
        #[cfg(not(wz_lent))]
        assert!(plan.rows().all(|laid| laid.part() != "face tables"));
        #[cfg(wz_lent)]
        assert_eq!(row(&plan, "room places").count, plan.peers().sets());
        #[cfg(not(wz_lent))]
        assert!(plan.rows().all(|laid| laid.part() != "room places"));
        // The index of held sets is a row of a build that takes faces beside the dial role's and
        // lends its tables; one whose tables take their memory on use counts it.
        if crate::arena::TAKES_FACES && cfg!(wz_lent) {
            assert_eq!(row(&plan, "held faces").count, plan.peers().sets());
        } else {
            assert!(plan.rows().all(|laid| laid.part() != "held faces"));
        }
    }
}

/// A session that listens is lent the slots its udp ports share for their datagrams, each a
/// link's batch long, with the ports' rows; one that listens on nothing is lent none. Turned
/// red by slots of anything but the links' batch, or slots reserved for a session with no port.
#[cfg(all(feature = "udp-listen", not(wz_on_use)))]
#[test]
fn a_listening_session_is_lent_slots_for_its_ports_datagrams() {
    let listening = ArenaPlan::of(
        &CoopConfig {
            listen: vec!["udp/127.0.0.1:0".to_owned()],
            max_faces: 2,
            ..client_config()
        },
        &SessionLimits::defaults(),
    )
    .expect("lays an arena out");
    let batch = usize::from(client_config().batch_size);
    let slots = row(&listening, "link port datagram slots");
    assert_eq!(slots.count, caps::UDP_PORT_SLOTS);
    assert_eq!(slots.entry_bytes, batch, "a slot is a batch long");
    assert_eq!(
        row(&listening, "link port datagram flags").count,
        slots.count
    );
    let mut session =
        SessionArena::reserve(&listening, &AllocatorMemory).expect("the host has the memory");
    let mut lend = session.lender();
    let _links = listening.transport().links_from(&mut lend);
    let ports = listening.transport().ports_from(&mut lend);
    lend.finish().expect("the plan lays the links out");
    let table = ports.expect("a table for the ports").slots();
    assert_eq!(
        (table.capacity(), table.size()),
        (caps::UDP_PORT_SLOTS, batch)
    );
    // The ports' book: a peer row for each link the session may hold, and a queue row for each
    // slot a waiting datagram holds.
    let links = listening.links();
    assert_eq!(
        Some(row(&listening, "udp port peers").entry_bytes),
        wz_session_core::bounded::Arena::table_bytes::<wz_runtime_coop::udp_link::PortPeerRow>(
            links
        )
    );
    assert_eq!(
        Some(row(&listening, "udp port queue").entry_bytes),
        wz_session_core::bounded::Arena::table_bytes::<wz_runtime_coop::udp_link::QueuedDatagram>(
            caps::UDP_PORT_SLOTS
        )
    );

    let dialling = ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("a plan");
    assert!(
        dialling.rows().all(|row| !PORT_PARTS.contains(&row.part())),
        "a session that listens on nothing lays out no row of the ports: {dialling:?}"
    );
    let mut session =
        SessionArena::reserve(&dialling, &AllocatorMemory).expect("the host has the memory");
    let mut lend = session.lender();
    let _links = dialling.transport().links_from(&mut lend);
    let ports = dialling.transport().ports_from(&mut lend);
    lend.finish().expect("the plan lays the links out");
    assert!(
        ports.is_none(),
        "a session that listens on nothing is lent no table for ports"
    );
}

/// Where the tables take their memory on use, a session that listens on `udp/` lays out no row of
/// its ports and sizes the heap's memory for them to the counts the lent form lends: a peer's row
/// for each link it may hold, `UDP_PORT_SLOTS` datagrams, each port's read buffer a link's batch.
/// One that listens on nothing sizes none, so its links open no port. Turned red by a plan that
/// still lays the ports' rows out, or a source sized to other counts than the lent form's.
#[cfg(all(feature = "udp-listen", wz_on_use))]
#[test]
fn an_on_use_listening_session_sizes_its_ports_and_lays_out_none() {
    use wz_runtime_coop::udp_link::HeapPorts;

    let listening = ArenaPlan::of(
        &CoopConfig {
            listen: vec!["udp/127.0.0.1:0".to_owned()],
            max_faces: 2,
            ..client_config()
        },
        &SessionLimits::defaults(),
    )
    .expect("lays an arena out");
    assert!(
        listening
            .rows()
            .all(|row| !PORT_PARTS.contains(&row.part())),
        "an on-use plan lays out no row of the ports: {listening:?}"
    );
    let batch = usize::from(client_config().batch_size);
    assert_eq!(
        listening.transport().ports_sized(),
        HeapPorts::sized(listening.links(), caps::UDP_PORT_SLOTS, batch)
    );

    let dialling = ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("a plan");
    assert_eq!(
        dialling.transport().ports_sized(),
        HeapPorts::default(),
        "a session that listens on nothing sizes no port"
    );
}

/// A session that listens on `tcp/` alone binds no udp port, so its plan lays out none of the
/// ports' rows, as one that listens on nothing; a `udp/` endpoint beside it lends the slots. Each
/// row is printed, so a run with `--nocapture` shows the bytes the tcp listener does not reserve.
/// Turned red by port rows planned from the count of listeners rather than of the `udp/` ones,
/// or laid out empty for a session with no port.
#[cfg(all(feature = "udp-listen", not(wz_on_use)))]
#[test]
fn a_session_that_listens_on_tcp_alone_is_lent_no_port_slot() {
    let config = |listen: &[&str]| CoopConfig {
        listen: listen.iter().map(|text| (*text).to_owned()).collect(),
        max_faces: 2,
        ..client_config()
    };
    let tcp = ArenaPlan::of(&config(&["tcp/127.0.0.1:0"]), &SessionLimits::defaults())
        .expect("lays an arena out");
    let both = ArenaPlan::of(
        &config(&["tcp/127.0.0.1:0", "udp/127.0.0.1:0"]),
        &SessionLimits::defaults(),
    )
    .expect("lays an arena out");
    for part in [
        "link port datagram flags",
        "link port datagram slots",
        "udp port peers",
        "udp port queue",
    ] {
        std::println!("{part}: beside a udp port {:?} B", row(&both, part).bytes());
        assert!(
            tcp.rows().all(|laid| laid.part() != part),
            "a session with no udp port lays out no {part}"
        );
    }
    std::println!(
        "reserved: tcp alone {:?} B, beside a udp port {:?} B",
        tcp.reserved_bytes(),
        both.reserved_bytes()
    );
    assert_eq!(
        row(&both, "link port datagram slots").count,
        caps::UDP_PORT_SLOTS
    );
    let (Some(tcp_bytes), Some(both_bytes)) = (tcp.reserved_bytes(), both.reserved_bytes()) else {
        panic!("both plans have a size");
    };
    assert!(
        tcp_bytes < both_bytes,
        "{tcp_bytes} B is not under {both_bytes} B"
    );
}

/// A session that listens lays out the place of its link admission where the build has one
/// (`link-admission`), and none where it does not, as the zenoh-pico preset's peer, whose links
/// are each a face of their own and ask no admission. Turned red by an admission laid out in a
/// build without the capability (`lay_out_open`), or one left out of a build that has it.
#[cfg(feature = "listen")]
#[test]
fn a_listening_session_lays_out_its_link_admission_only_where_the_build_has_one() {
    let listening = host_plan(&CoopConfig {
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        max_faces: 2,
        ..client_config()
    })
    .expect("the build's limits lay an arena out");
    assert_eq!(
        listening.rows().any(|laid| laid.part() == "link admission"),
        cfg!(feature = "link-admission"),
        "the admission's place is laid out exactly where the build has the admission"
    );
}

/// The buffers of a session's links a report of its memory reads (`link_buffers`) are the plan's
/// rows, count and bytes, for a client and, in a build that listens, a listener: one reckoning
/// for both. In a build whose links share pools the receive buffers are the pool's, under
/// `RX_POOL_BUFFERS`; otherwise one for each link. Turned red by a plan that lays its link rows
/// out by another reckoning than the one a report reads, or a report that counts a buffer for
/// each link of a pooled build.
#[cfg(not(wz_on_use))]
#[test]
fn the_link_buffers_a_report_reads_are_the_plans_rows() {
    use crate::arena::{link_buffers, links_of, LINKS_SHARE_POOLS};

    let mut configs = vec![client_config()];
    if cfg!(feature = "listen") {
        configs.push(CoopConfig {
            listen: vec!["tcp/127.0.0.1:0".to_owned()],
            ..client_config()
        });
    }
    let limits = SessionLimits::defaults();
    for config in configs {
        let plan = ArenaPlan::of(&config, &limits).expect("lays an arena out");
        let links = links_of(&config).expect("within the address space");
        let buffers = link_buffers(links, config.max_faces, config.batch_size, &limits)
            .expect("the plan's batch and pools");
        let receive = row(&plan, "link receive buffers");
        let transmit = row(&plan, "link transmit slots");
        assert_eq!(
            (receive.count, receive.entry_bytes),
            (buffers.receive, buffers.bytes)
        );
        assert_eq!(
            (transmit.count, transmit.entry_bytes),
            (buffers.transmit, buffers.bytes)
        );
        assert_eq!(buffers.bytes, usize::from(config.batch_size));
        assert_eq!(plan.reassembly().1, buffers.chains);
        if LINKS_SHARE_POOLS {
            assert!(buffers.receive <= caps::RX_POOL_BUFFERS.min(links));
        } else {
            assert_eq!(buffers.receive, links);
        }
    }
}

/// A report's table of chains is the session's share for each face read where it lies, the dial
/// role's place and one for each face besides it where the session listens and reads each face
/// where it lies, and the share alone otherwise; a count past the address space is refused as the
/// plan is. Turned red by a report that reads the share alone where the plan multiplies it.
#[test]
fn a_reports_table_of_chains_is_a_share_for_each_face_read_where_it_lies() {
    let limits = SessionLimits::defaults();
    let batch = client_config().batch_size;
    let report = |beside: usize| {
        crate::arena::link_buffers(1, beside, batch, &limits).map(|buffers| buffers.chains)
    };
    let apart = cfg!(feature = "listen") && !cfg!(wz_round);
    let places = |beside: usize| if apart { beside + 1 } else { 1 };
    assert_eq!(report(0), Ok(caps::REASSEMBLY_CHAINS));
    assert_eq!(report(3), Ok(caps::REASSEMBLY_CHAINS * places(3)));
    if apart && caps::REASSEMBLY_CHAINS > 1 {
        assert_eq!(
            report(usize::MAX),
            Err(ArenaRefused::TooLarge),
            "a table past the address space"
        );
    }
}

/// A list of endpoints counts its `udp/` ones, in the host's form and in a source's alike.
/// Turned red by a count that reads another scheme as udp, or a source's count that drops one.
#[test]
fn a_list_of_endpoints_counts_its_udp_ones() {
    use crate::open_source::{Counted, EndpointList};

    let texts = ["tcp/127.0.0.1:7447", "udp/127.0.0.1:7447", "udp/[::1]:7447"];
    let host = texts
        .iter()
        .map(|text| (*text).to_owned())
        .collect::<std::vec::Vec<_>>();
    assert_eq!((host.count(), host.udp()), (3, 2));
    let counted = Counted::of(texts);
    assert_eq!((counted.count(), counted.udp()), (3, 2));
    assert_eq!(Counted::of(None::<&str>), Counted::default());
}

/// The parts of an arena that only a session that listens lays out: the slots its udp ports read
/// their datagrams into, and the ports' books of their peers and of the datagrams waiting.
#[cfg(feature = "listen")]
const PORT_PARTS: [&str; 4] = [
    "link port datagram flags",
    "link port datagram slots",
    "udp port peers",
    "udp port queue",
];

/// A session that joins groups is lent a receive buffer for each group it may join, of the largest
/// batch a group it names sends, under the build's multicast batch, after the links' tables: the
/// stack claims one when a group is joined. Turned red by a buffer for each group asked past the
/// task cells, or one shorter than the largest group's batch.
#[cfg(feature = "group")]
#[test]
fn a_session_that_joins_groups_is_lent_a_receive_buffer_for_each() {
    use wz_capi_port::group::{GroupDeclarations, GroupJoin, GroupProfile};

    let join = |batch_size: u16| GroupJoin {
        endpoint: "udp/239.7.7.7:7447#iface=lan7".to_owned(),
        profile: GroupProfile {
            lease_ms: 10_000,
            join_interval_ms: 2_500,
            max_sessions: None,
            seq_num_res: wz_session_core::policy::SnResolution::Bits32,
            req_id_res: 0x02,
            batch_size,
            is_qos: false,
            compression: false,
            join_rule: wz_session_core::multicast_params::GroupJoinRule::Pico,
        },
        is_shm: false,
        declarations: GroupDeclarations::Entities,
    };
    let groups = vec![join(1_024), join(2_048)];
    let asked = groups.len().min(caps::MAX_TASKS);
    let plan = ArenaPlan::of(
        &CoopConfig {
            groups,
            ..client_config()
        },
        &SessionLimits::defaults(),
    )
    .expect("lays an arena out");
    let bytes = 2_048_usize.min(caps::PICO_MULTICAST_BATCH_BYTES);
    let buffers = row(&plan, "link group receive buffers");
    assert_eq!(buffers.count, asked);
    assert_eq!(buffers.entry_bytes, bytes, "the largest group's batch");
    assert_eq!(row(&plan, "link group receive flags").count, asked);
    let mut session =
        SessionArena::reserve(&plan, &AllocatorMemory).expect("the host has the memory");
    let mut lend = session.lender();
    #[cfg(not(wz_on_use))]
    let _links = plan.transport().links_from(&mut lend);
    let groups = plan.transport().group_rx_from(&mut lend);
    lend.finish().expect("the plan lays the links out");
    let table = groups.expect("a table for the groups");
    assert_eq!((table.capacity(), table.size()), (asked, bytes));

    let none = ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("a plan");
    assert!(
        none.rows()
            .all(|row| !row.part().starts_with("link group receive")),
        "a config that names no group plans no table of them: {none:?}"
    );
    let mut session =
        SessionArena::reserve(&none, &AllocatorMemory).expect("the host has the memory");
    let mut lend = session.lender();
    #[cfg(not(wz_on_use))]
    let _links = none.transport().links_from(&mut lend);
    let groups = none.transport().group_rx_from(&mut lend);
    lend.finish().expect("the plan lays the links out");
    assert!(groups.is_none(), "and lends none");
}

/// The tokens of faces that went before each was retracted are owed apart from the sets those
/// faces gave back, a table of them lent at the open with a row for each row of the session's token
/// pool: a face owes apart only while its tokens hold a row of the pool, so the faces owing at
/// once are never more. A session of one face, whose one face never goes, is lent none.
#[cfg(all(
    wz_lent,
    feature = "liveliness",
    any(feature = "listen", feature = "group")
))]
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
        one.rows().all(|row| row.part() != "owed tokens"),
        "a session of one face is lent no table of tokens owed"
    );
}

/// The round's tables are as many rows as the session's `DELIVERY_LANE_EVENTS` and
/// `DELIVERY_LANE_CALLBACKS` state and its longest key, two of it for a round of threads and one for
/// a round of one thread, each lowered with its limit, and are laid out right after the lane's area,
/// the order the open lends them in. A round of one thread keeps its records in itself and is laid
/// out no row of them. Turned red by a round of one thread lent two keys, or a row of records laid
/// out where the arena lends none.
#[cfg(wz_round)]
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
    let lowered = lowered(|l| {
        l.select_delivery_lane_events(Quota::at_most(4))?;
        l.select_max_keyexpr_bytes(Quota::at_most(32))
    });
    let plan = ArenaPlan::of(&client_config(), &lowered).expect("lays an arena out");
    assert_eq!(plan.round().records, 4);
    assert_eq!(plan.round().longest_key, 32);
    // A build of the region's form keeps the round's tables in its region over these counts
    // (`StatePlaces::round`): its arena lays out no row of them.
    #[cfg(not(wz_lent))]
    assert!(plan
        .rows()
        .chain(built.rows())
        .all(|laid| !laid.part().starts_with("delivery")));
    #[cfg(wz_lent)]
    {
        let records = |plan: &ArenaPlan| {
            plan.rows()
                .find(|row| row.part() == "delivery records")
                .map(|row| row.count)
        };
        let lent = |count: usize| (crate::round::RECORD_BYTES != 0).then_some(count);
        assert_eq!(records(&built), lent(caps::DELIVERY_LANE_EVENTS));
        assert_eq!(
            row(&built, "delivery callbacks").count,
            caps::DELIVERY_LANE_CALLBACKS
        );
        assert_eq!(records(&plan), lent(4));
        assert_eq!(row(&plan, "delivery keys").count, 1);
        let keys =
            if <crate::form::CoopForm as wz_session_core::row_callback::ThreadForm>::OTHER_THREADS {
                2
            } else {
                1
            };
        assert_eq!(row(&plan, "delivery keys").entry_bytes, 32 * keys);
        assert!(
            plan.reserved_bytes() < built.reserved_bytes(),
            "the lowered limits lower the arena"
        );
    }
}

/// The plan lays out no delivery area: every record is read where it lies, so the plan has no lane
/// and no flag of one, and the round's tables are laid out next to each other, the round itself
/// after them, one of it where the open places the round in the arena; none of them where the build
/// fixes the session's shape and the round and its tables lie in its region (`StatePlaces`).
/// Turned red by a plan that reserves the area again, that lays out no place for the round the open
/// places in the arena (`lend_session`), or a row of the round the region holds.
#[cfg(wz_round)]
#[test]
fn the_plan_lays_out_no_delivery_lane() {
    let built =
        ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
    let parts: Vec<&str> = built.rows().map(|row| row.part()).collect();
    assert!(!parts.contains(&"delivery lane"));
    assert!(!parts.contains(&"delivery lane flag"));
    // A round of one thread keeps its records in itself, and is laid out no row of them; a round
    // the region holds is laid out no place either.
    // A build of the region's form keeps the round and its tables in its region
    // (`StatePlaces::round`), and its arena lays out none of them.
    #[cfg(not(wz_lent))]
    assert!(parts.iter().all(|part| !part.starts_with("delivery")));
    #[cfg(wz_lent)]
    {
        let tables: Vec<&str> = [
            "delivery records",
            "delivery callbacks",
            "delivery keys",
            "delivery round",
        ]
        .into_iter()
        .filter(|part| crate::round::RECORD_BYTES != 0 || *part != "delivery records")
        .collect();
        let first = parts
            .iter()
            .position(|part| *part == tables[0])
            .expect("CONTROL: the round's tables are laid out");
        assert_eq!(parts[first..first + tables.len()], tables[..]);
        let round = row(&built, "delivery round");
        assert_eq!(
            (round.count, round.entry_bytes),
            (1, core::mem::size_of::<crate::round::Round>())
        );
    }
}

/// A build that puts nothing in the round (`wz_round`) lays out none of it: no records, no
/// callbacks, no keys and no round, however many the limits state. The CONTROL is the router's
/// lend, which every plan of a build that lays its session out at the open lays out; a build that
/// does not keeps what it has in its region, and its arena holds no part of a round to look for,
/// nor does one whose tables take their memory on use, whose places lie in its own state.
/// Turned red by a plan that still lays out a part of the round where the open places none.
#[cfg(all(not(wz_round), wz_lent))]
#[test]
fn a_build_that_puts_nothing_in_the_round_lays_out_none_of_it() {
    let built =
        ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
    let parts: Vec<&str> = built.rows().map(|row| row.part()).collect();
    assert!(
        parts.contains(&"router lend"),
        "CONTROL: the plan lays its parts out"
    );
    for part in [
        "delivery records",
        "delivery callbacks",
        "delivery keys",
        "delivery round",
    ] {
        assert!(!parts.contains(&part), "{part}");
    }
}

/// The plan lays out one place for each step lend the open places in the arena
/// (`crate::engine::StepPlaces`): the registry's and the reassembly Router's, a cell each, and no
/// registry's where the read steps its one link itself and dispatches under the session's lock;
/// none where the build fixes the session's shape and the places lie in its region
/// (`StatePlaces::steps`). Turned red by a plan that leaves a lend out, whose open would place it
/// past what the arena has, or that reserves one the open never places, which lending every row
/// would leave empty.
#[test]
fn the_plan_lays_out_the_places_the_session_lends_in_for_a_step() {
    let built =
        ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
    #[cfg(any(not(wz_lent), not(wz_round)))]
    assert!(
        built.rows().all(|row| row.part() != "registry lend"),
        "a read that steps its one link, or a region, lends no registry from the arena"
    );
    #[cfg(not(wz_lent))]
    assert!(
        built.rows().all(|row| row.part() != "router lend"),
        "the region holds the Router's place"
    );
    #[cfg(wz_lent)]
    let lends: &[(&str, usize)] = &[
        #[cfg(wz_round)]
        ("registry lend", crate::engine::REGISTRY_LEND_BYTES),
        ("router lend", crate::engine::ROUTER_LEND_BYTES),
    ];
    #[cfg(wz_lent)]
    for &(part, bytes) in lends {
        let laid = row(&built, part);
        assert_eq!((laid.count, laid.entry_bytes), (1, bytes), "{part}");
    }
}

/// The faces' rooms lie in the arena: their places, a place for each set of face tables, are rows
/// of the plan the limits lay out, and the rooms themselves, whose size is the stack's waits', a
/// row the open lays out over the links (`lay_out_open`). Turned red by a plan that leaves either
/// out, whose open would place it past what the arena has, or that lays the rooms out before the
/// open knows the stack. A session whose tables take their memory on use holds its rooms in an
/// allocation of their own, and its open lays out no row of them (`tests::on_use`).
#[test]
fn the_plan_lays_out_the_faces_rooms_and_their_places() {
    let config = CoopConfig {
        max_faces: BESIDE_DIAL,
        ..client_config()
    };
    let limits = ArenaPlan::of(&config, &SessionLimits::defaults()).expect("lays an arena out");
    // A build of the region's form keeps its one set's place in its region (`StatePlaces::rooms`).
    #[cfg(wz_lent)]
    {
        let places = row(&limits, "room places");
        assert_eq!(
            (places.count, places.entry_bytes),
            (limits.peers().sets(), crate::engine::ROOM_PLACE_BYTES)
        );
    }
    #[cfg(not(wz_lent))]
    assert!(limits.rows().all(|laid| laid.part() != "room places"));
    assert!(
        limits.rows().all(|laid| laid.part() != "link rooms"),
        "the limits alone do not know the rooms' size"
    );
    let open = host_plan(&config).expect("the build's limits lay an arena out");
    #[cfg(not(wz_on_use))]
    {
        let rooms = row(&open, "link rooms");
        let bytes = crate::engine::link_rooms_bytes::<crate::tests::PosixLinks>();
        assert!(bytes > 0, "CONTROL: the rooms take bytes");
        assert_eq!((rooms.count, rooms.entry_bytes), (1, bytes));
    }
    #[cfg(wz_on_use)]
    assert!(open.rows().all(|laid| laid.part() != "link rooms"));
}

/// The key arena is the `KEY_ARENA_BYTES` the session's limits state, one area with its state: a
/// lowered value lowers it, and one over the build's refuses the plan, naming the limit and both
/// values.
#[test]
fn the_plan_lays_out_the_key_arena_the_limits_state() {
    let built =
        ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
    assert_eq!(
        built.key_bytes(),
        SessionLimits::defaults().key_arena_bytes()
    );
    let lowered = lowered(|l| l.select_key_arena_bytes(512));
    let plan = ArenaPlan::of(&client_config(), &lowered).expect("lays an arena out");
    assert_eq!(plan.key_bytes(), 512);
    // The key arena of a build of the region's form lies in its region, held to the limit by the
    // bytes it is opened with (`StateRegion::place`): its arena lays out no row of it.
    #[cfg(wz_lent)]
    {
        use wz_session_core::key_arena::KeySpace;

        assert_eq!(row(&built, "key arena").count, 1);
        assert_eq!(
            Some(row(&built, "key arena").entry_bytes),
            KeySpace::span_bytes(built.key_bytes())
        );
        assert_eq!(
            Some(row(&plan, "key arena").entry_bytes),
            KeySpace::span_bytes(512)
        );
        assert!(plan.reserved_bytes() < built.reserved_bytes());
    }
    #[cfg(not(wz_lent))]
    assert!(built.rows().all(|laid| laid.part() != "key arena"));
    let over = caps::KEY_ARENA_BYTES + 1;
    let mut raised = SessionLimits::defaults();
    if raised.select_key_arena_bytes(over).is_ok() {
        assert_eq!(
            ArenaPlan::of(&client_config(), &raised),
            Err(ArenaRefused::Limit {
                limit: ArenaLimit::KeyArenaBytes,
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
/// lies in the plan's one key arena row. A build of the region's form lends none of those rows
/// from its arena (`crate::region::StateRegion`).
#[cfg(wz_lent)]
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
#[cfg(feature = "listen")]
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
    // Two handshakes at once where the build admits them: a build at a preset of one admits one.
    let handshakes = caps::MAX_ACCEPT_PENDING.min(2);
    let listening = ArenaPlan::of(
        &CoopConfig {
            listen: vec!["tcp/127.0.0.1:0".to_owned()],
            max_faces: 3,
            accept_pending: handshakes,
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
        dial.rows().all(|row| row.part() != "pending gets"),
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
    assert_eq!(link_places(&listening), 3 + handshakes);
    assert_eq!(
        row(&listening, "link receive buffers").count,
        pooled(caps::RX_POOL_BUFFERS, 3 + handshakes),
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
#[cfg(feature = "listen")]
#[test]
fn the_dial_roles_link_and_face_are_laid_out_only_for_a_session_that_dials() {
    // Two handshakes at once where the build admits them: a build at a preset of one admits one.
    let handshakes = caps::MAX_ACCEPT_PENDING.min(2);
    let listener = |endpoints: Vec<String>| CoopConfig {
        endpoints,
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        max_faces: 3,
        accept_pending: handshakes,
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
    assert_eq!(link_places(&only), 3 + handshakes);
    assert_eq!(link_places(&dialling), 1 + 3 + handshakes);
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
/// the open lowers the row where the build stages what the limit sizes. The reply stage is lent no
/// row in any build: the engine's queryable answers into a stage of its own, and a reply limit over
/// the build's still refuses the open by its name.
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
                limit: ArenaLimit::MaxPendingReplies,
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
    // A build of the region's form lends no peer tables from its arena: its one face's lie in the
    // region (`crate::region::StateRegion`), held to the limit by the tables themselves.
    #[cfg(wz_lent)]
    {
        use wz_session_core::peer_tables::PeerTables;

        let tables = |plan: &ArenaPlan| row(plan, "peer tables").entry_bytes;
        for plan in [&built, &at_one] {
            assert_eq!(
                Some(tables(plan)),
                PeerTables::<Lent>::arena_bytes(plan.peers().rows),
                "the row is what the tables of the rows the open resolved take"
            );
        }
        // `MAX_PENDING_DECLARES` sizes the answers staged for a peer's Interests
        // (`interest-answer`) and for its liveliness Interests (`liveliness`): a build of neither
        // stages none, and its row does not move with the limit.
        #[cfg(any(feature = "interest-answer", feature = "liveliness"))]
        assert!(
            tables(&at_one) < tables(&built),
            "the staging lent fewer rows"
        );
    }
    #[cfg(not(wz_lent))]
    assert!(at_one.rows().all(|laid| laid.part() != "peer tables"));
}

/// A plan lays out the pool of its peers' interests only where the build keeps their rows
/// (`KEEPS_INTEREST_ROWS`): one area of what lending them takes in a build that answers a peer's
/// Interest (`interest-answer`), and no row in one that answers none, as the zenoh-pico preset
/// builds a peer, whose pools lend the interests nothing. For a client's one face and for faces
/// that share the pools. Turned red by a row laid out for interests the pools do not keep (the
/// `KEEPS_INTEREST_ROWS` of `ArenaPlan::lay_out`), or by none laid out where they keep them.
#[cfg(wz_lent)]
#[test]
fn the_peers_interest_pool_is_laid_out_only_where_the_build_keeps_their_rows() {
    interest_pool_laid_as_kept(&client_config());
    #[cfg(any(feature = "listen", feature = "group"))]
    interest_pool_laid_as_kept(&CoopConfig {
        max_faces: 3,
        ..client_config()
    });
    #[cfg(feature = "interest-answer")]
    {
        let plan =
            ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
        assert!(
            row(&plan, "peer interest pool")
                .bytes()
                .is_some_and(|bytes| bytes > 0),
            "a build that answers a peer's Interest keeps its rows"
        );
    }
}

/// The rows the plan of `config` lays out for its peers' interests: one area of the bytes lending
/// them takes where the build keeps them, and none, of a pool that lends nothing, where it does
/// not.
#[cfg(wz_lent)]
fn interest_pool_laid_as_kept(config: &CoopConfig) {
    use wz_session_core::peer_tables::KEEPS_INTEREST_ROWS;

    let plan = ArenaPlan::of(config, &SessionLimits::defaults()).expect("lays an arena out");
    let lent = plan
        .peers()
        .pools
        .interest_bytes()
        .expect("within the address space");
    let laid: Vec<(usize, usize)> = plan
        .rows()
        .filter(|row| row.part() == "peer interest pool")
        .map(|row| (row.count, row.entry_bytes))
        .collect();
    if KEEPS_INTEREST_ROWS {
        assert_eq!(
            laid,
            [(1, lent)],
            "one area of what lending the interests takes"
        );
    } else {
        assert_eq!(
            lent, 0,
            "a build that keeps no interest of a peer lends them nothing"
        );
        assert!(laid.is_empty(), "and lays out no row of them: {laid:?}");
    }
}

/// The pools of what the faces' peers write hold the fewer of the session's limit and what the
/// faces could hold together, each at the bound of one peer: a session of one face lends what that
/// face's tables held, a listener of four lends four faces' worth, and a session limit lowered at
/// the open lowers its pool and no other, the faces' own tables untouched. The arena lays the
/// lowered pool out in fewer bytes where it lends the pools; where the tables take their memory on
/// use the pools are counted and the plan lays out no row of them.
#[cfg(any(feature = "listen", feature = "group"))]
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
    #[cfg(wz_lent)]
    assert!(
        row(&at_one, "peer declaration pools").entry_bytes
            < row(&four, "peer declaration pools").entry_bytes,
        "the declarations' pools lent fewer rows"
    );
    #[cfg(wz_on_use)]
    assert!(
        at_one
            .rows()
            .chain(four.rows())
            .all(|row| row.part() != "peer declaration pools"),
        "the pools are counted, not laid out"
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
    let (face, session) = (
        ArenaLimit::MaxRemoteDecls,
        ArenaLimit::SessionMaxRemoteDecls,
    );
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

/// A session that listens reserves the places of the droppable publishes it keeps for its other
/// faces: `HANDED_LEG_BYTES` cut into places of its links' batch, with their flags, under the
/// build's `held-faces` value of `held-publish-drop`, and none under `every-face`. Turned red
/// by places sized by anything but the links' batch, or reserved when the policy keeps none.
#[cfg(all(feature = "listen", wz_round))]
#[test]
fn a_listening_session_reserves_places_for_the_publishes_it_keeps() {
    use wz_session_core::policy::HeldPublishDrop;

    let config = CoopConfig {
        max_faces: 2,
        ..client_config()
    };
    let plan = ArenaPlan::of(&config, &SessionLimits::defaults()).expect("lays an arena out");
    let batch = row(&plan, "link receive buffers").entry_bytes;
    let places = row(&plan, "handed leg places");
    assert_eq!(places.entry_bytes, batch, "a place is a batch long");
    let expected = match SessionPolicy::defaults().held_publish_drop() {
        HeldPublishDrop::HeldFaces => caps::HANDED_LEG_BYTES / batch,
        HeldPublishDrop::EveryFace => 0,
    };
    assert_eq!(places.count, expected);
    assert_eq!(row(&plan, "handed leg flags").count, expected);
}

/// A session that listens and sends each face its own leg (`direct`) reserves no place for a
/// handed publish, whatever `held-publish-drop` says: a leg dropped is dropped on its own face,
/// and no other face is owed it. The CONTROL is the links' receive buffers, which it reserves.
/// Turned red by the handed legs' rows laid out in a build that reads its faces where they lie.
#[cfg(all(feature = "listen", not(wz_round)))]
#[test]
fn a_session_that_sends_each_face_its_own_leg_reserves_no_handed_places() {
    let config = CoopConfig {
        max_faces: 2,
        ..client_config()
    };
    let plan = ArenaPlan::of(&config, &SessionLimits::defaults()).expect("lays an arena out");
    assert!(
        row(&plan, "link receive buffers").count > 0,
        "CONTROL: the links' buffers are laid out"
    );
    for part in ["handed leg places", "handed leg flags", "handed legs"] {
        assert!(
            plan.rows().all(|row| row.part() != part),
            "no row of {part}"
        );
    }
}

/// The faces whose reads stage their chains apart, a share of the reassembly table each: each set
/// of face tables of a session that listens and reads each face where it lies, and one otherwise
/// (`crate::arena::ArenaPlan::lay_out`).
fn chain_shares(plan: &ArenaPlan) -> usize {
    if cfg!(wz_round) || !cfg!(feature = "listen") {
        1
    } else {
        plan.peers().sets()
    }
}

/// The session is lent one table of reassembly buffers its links share, as many as its
/// `REASSEMBLY_CHAINS` however many links the session may hold, each as long as the session's
/// `PICO_FRAG_MAX_BYTES`: the build's count and length for a session that states neither, the
/// count and the length a session lowers them to, no buffer for a session that states none, and a
/// value over the build's refuses the plan under its own name. A report reads the same count
/// (`link_buffers`). Turned red by a table laid out at the build's count whatever the session
/// states, or one that grows with the links.
#[test]
fn the_session_is_lent_one_table_of_reassembly_buffers_of_the_snapshots_count_and_length() {
    let config = CoopConfig {
        max_faces: BESIDE_DIAL,
        ..client_config()
    };
    let built = ArenaPlan::of(&config, &SessionLimits::defaults()).expect("lays an arena out");
    // Where the links are tasks they share the one table's chains; where each face's read stages
    // its chains in a Router of its own (`direct`), the table holds the session's count for each
    // face read where it lies, so the chains of one face never take another's buffers: each set
    // of tables where the session listens, and the dial role's alone otherwise, a group's session
    // staging its chains itself.
    let chains = caps::REASSEMBLY_CHAINS * chain_shares(&built);
    assert_eq!(row(&built, "reassembly buffers").count, chains);
    assert_eq!(
        row(&built, "reassembly buffers").entry_bytes,
        caps::PICO_FRAG_MAX_BYTES
    );
    assert_eq!(built.reassembly(), (caps::PICO_FRAG_MAX_BYTES, chains));
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
        (
            caps::PICO_FRAG_MAX_BYTES,
            caps::REASSEMBLY_CHAINS * chain_shares(&one_link)
        ),
        "the table grows with the sets of the faces read where they lie alone"
    );
    let lowered_bytes = lowered(|l| l.select_pico_frag_max_bytes(Quota::at_most(1024)));
    let plan = ArenaPlan::of(&config, &lowered_bytes).expect("lays an arena out");
    assert_eq!(row(&plan, "reassembly buffers").entry_bytes, 1024);
    let one = lowered(|l| l.select_reassembly_chains(Quota::at_most(1)));
    let plan = ArenaPlan::of(&config, &one).expect("lays an arena out");
    let stated = chain_shares(&plan);
    assert_eq!(
        plan.reassembly(),
        (caps::PICO_FRAG_MAX_BYTES, stated),
        "the count the session states, for each face read where it lies"
    );
    assert_eq!(row(&plan, "reassembly buffers").count, stated);
    assert_eq!(row(&plan, "reassembly flags").count, stated);
    assert_eq!(
        crate::arena::link_buffers(1, config.max_faces, config.batch_size, &one)
            .map(|buffers| buffers.chains),
        Ok(stated),
        "a report reads the plan's count"
    );
    let none = lowered(|l| l.select_reassembly_chains(Quota::at_most(0)));
    let plan = ArenaPlan::of(&config, &none).expect("lays an arena out");
    assert_eq!(
        plan.reassembly().1,
        0,
        "a session that states no chain is lent no buffer"
    );
    let over = caps::PICO_FRAG_MAX_BYTES + 1;
    let mut raised = SessionLimits::defaults();
    if raised
        .select_pico_frag_max_bytes(Quota::at_most(over))
        .is_ok()
    {
        assert_eq!(
            ArenaPlan::of(&config, &raised),
            Err(ArenaRefused::Limit {
                limit: ArenaLimit::PicoFragMaxBytes,
                why: UnlentRows::OverCeiling {
                    value: over,
                    ceiling: caps::PICO_FRAG_MAX_BYTES,
                },
            })
        );
    }
    let more = caps::REASSEMBLY_CHAINS + 1;
    let mut raised = SessionLimits::defaults();
    if raised
        .select_reassembly_chains(Quota::at_most(more))
        .is_ok()
    {
        let refused = ArenaRefused::Limit {
            limit: ArenaLimit::ReassemblyChains,
            why: UnlentRows::OverCeiling {
                value: more,
                ceiling: caps::REASSEMBLY_CHAINS,
            },
        };
        assert_eq!(ArenaPlan::of(&config, &raised), Err(refused));
        assert_eq!(
            crate::arena::link_buffers(1, 0, config.batch_size, &raised)
                .map(|buffers| buffers.chains),
            Err(refused),
            "a report is refused as the plan is"
        );
    }
}

/// A session whose config states one reassembly buffer rejoins one chain at a time: a chain of
/// the other reliability that starts while the first is open is refused as pool exhaustion and
/// counted by the session's staging, and once the first has rejoined its message and given its
/// buffer back the next chain begins, uncounted. The CONTROL is a session at the build's count,
/// where the same second chain begins. Turned red by an open that lends the table at the build's
/// count whatever the config states, or a refusal the staging does not count.
#[test]
fn a_session_rejoins_as_many_chains_at_once_as_its_config_states() {
    use wz_session_core::extfragment::FragmentMarkers;
    use wz_session_core::qos::Priority;
    use wz_session_core::reassembly_dispatch::{Fragment, IngestOutcome, RefuseReason};

    /// One fragment of the chain of `reliable` at `sn`, the last of it where `more` is `0`,
    /// rejoined by the session's Router.
    fn ingest(engine: &Engine, reliable: bool, sn: u64, more: u8) -> IngestOutcome {
        engine.with_chain_router(|reassembly, now_ms| {
            reassembly.ingest(
                Fragment {
                    peer_key: &[0x5a; 16],
                    reliable,
                    sn,
                    more,
                    payload: b"part",
                    priority: Priority::DEFAULT,
                    markers: FragmentMarkers::NONE,
                },
                wz_session_core::sn::mask_from_res(0x02),
                now_ms,
                |_| {},
            )
        })
    }
    /// The chains the session's staging refused a buffer to.
    fn refused(engine: &Engine) -> u64 {
        engine.with_chain_router(|reassembly, _| reassembly.staging().refused())
    }

    // A router stand-in serves one session, so each session below dials one of its own.
    let router = Router::start(CatchAll::None);
    let one = open_under(
        &router,
        lowered(|l| l.select_reassembly_chains(Quota::at_most(1))),
    );
    assert_eq!(ingest(&one, true, 1, 1), IngestOutcome::Begun);
    assert_eq!(
        ingest(&one, false, 1, 1),
        IngestOutcome::Refused(RefuseReason::PoolExhausted),
        "the one buffer is the open chain's"
    );
    assert_eq!(refused(&one), 1, "the refused chain is counted");
    assert_eq!(ingest(&one, true, 2, 0), IngestOutcome::Reassembled);
    assert_eq!(
        ingest(&one, false, 2, 1),
        IngestOutcome::Begun,
        "the buffer given back serves the next chain"
    );
    assert_eq!(refused(&one), 1, "a chain served counts nothing");
    drop(one);
    drop(router);
    if caps::REASSEMBLY_CHAINS >= 2 {
        let router = Router::start(CatchAll::None);
        let built = open(&router);
        assert_eq!(ingest(&built, true, 1, 1), IngestOutcome::Begun);
        assert_eq!(
            ingest(&built, false, 1, 1),
            IngestOutcome::Begun,
            "CONTROL: at the build's count the second chain has a buffer"
        );
        assert_eq!(refused(&built), 0);
    }
}

/// The ends of the session's legs, the rows of their callbacks and the session's note of each leg
/// pending are lent a row for each get every table of pending gets holds: a leg takes one of
/// each, and none is held anywhere else.
#[cfg(feature = "query")]
#[test]
fn the_plan_lends_a_row_for_the_end_of_each_get() {
    let plan = ArenaPlan::of(
        &CoopConfig {
            max_faces: BESIDE_DIAL,
            ..client_config()
        },
        &SessionLimits::defaults(),
    )
    .expect("lays an arena out");
    let gets = plan.gets();
    let legs = gets.tables * (gets.rows.queries + gets.rows.liveliness_gets);
    assert_eq!(gets.legs(), Some(legs));
    // A build of the region's form keeps these rows in its region at the build's bound
    // (`StatePlaces::tables`): its arena lays out none of them.
    #[cfg(not(wz_lent))]
    for part in [
        "ended legs",
        "leg callbacks",
        "pending legs",
        "held replies",
    ] {
        assert!(
            plan.rows().all(|laid| laid.part() != part),
            "the region holds the {part}"
        );
    }
    #[cfg(wz_lent)]
    the_arena_lends_a_row_for_the_end_of_each_get(&plan, legs);
}

/// The rows of the ends of `legs` legs, their callbacks, the session's notes of them and the
/// replies the gets hold, as `plan` lays them out where the arena lends them.
#[cfg(all(feature = "query", wz_lent))]
fn the_arena_lends_a_row_for_the_end_of_each_get(plan: &ArenaPlan, legs: usize) {
    assert_eq!(row(plan, "ended legs").count, legs);
    assert_eq!(
        row(plan, "ended legs").entry_bytes,
        core::mem::size_of::<crate::engine::Ended>()
    );
    assert_eq!(row(plan, "leg callbacks").count, legs);
    assert_eq!(
        row(plan, "leg callbacks").entry_bytes,
        core::mem::size_of::<Option<crate::engine::LegRow>>()
    );
    assert_eq!(row(plan, "pending legs").count, legs);
    assert_eq!(
        row(plan, "pending legs").entry_bytes,
        core::mem::size_of::<crate::engine::PendingGet>()
    );
    // The replies held to their Finals are a row each, as many as the session holds at once, of
    // the rows the engine lends them (`HeldReplies::lent`).
    let held = row(plan, "held replies");
    assert_eq!(held.count, plan.session().held_replies());
    assert_eq!(
        held.span(),
        wz_session_core::reply_hold::HeldReplies::<u64, Lent>::arena_bytes(held.count)
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

/// The Finals held for those queries and the requests a dispatch refused lie in rows of the
/// arena, one of each for each query the session holds at once, as its limit resolves it, where
/// the arena lends them; a build of the region's form keeps them in its region
/// (`StatePlaces::tables`) and its arena lays out none. Turned red by rows sized by the build's
/// ceiling, by a plan that lends none, or by a region's plan that lends them again.
#[cfg(feature = "queryable")]
#[test]
fn the_plan_lends_a_row_of_held_and_refused_finals_for_each_query_held() {
    let lowered = lowered(|l| l.select_max_pending_finals(Quota::at_most(3)));
    let plan = ArenaPlan::of(&client_config(), &lowered).expect("lays an arena out");
    assert_eq!(plan.held_queries(), 3, "the limit is held either way");
    let finals: Vec<_> = plan
        .rows()
        .filter(|row| row.part().ends_with(" finals"))
        .map(|row| (row.part(), row.count, row.entry_bytes))
        .collect();
    #[cfg(not(wz_lent))]
    assert!(finals.is_empty(), "{finals:?}");
    #[cfg(wz_lent)]
    assert_eq!(
        finals,
        [
            (
                "held finals",
                3,
                core::mem::size_of::<crate::engine::FinalHold>()
            ),
            (
                "refused finals",
                3,
                core::mem::size_of::<crate::engine::RefusedFinal>()
            ),
        ]
    );
}

/// A build without queryables holds no query, so its plan lays out no row of Finals.
#[cfg(not(feature = "queryable"))]
#[test]
fn a_build_without_queryables_lays_out_no_row_of_finals() {
    let plan =
        ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
    assert!(plan.rows().all(|row| !row.part().ends_with(" finals")));
}

/// A config that states more faces than the session's `MAX_FACES`, or a listener more handshakes
/// than its `MAX_ACCEPT_PENDING`, is refused by the limit's name before any memory is asked, as is
/// one past the build's value; a session that only dials is not held to the handshakes' bound, as
/// it takes none. The CONTROL is the same config at the limit, which lays an arena out.
#[cfg(feature = "listen")]
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
            limit: ArenaLimit::MaxFaces,
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
            limit: ArenaLimit::MaxAcceptPending,
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
            limit: ArenaLimit::MaxFaces,
            why: UnlentRows::OverCeiling {
                value: usize::MAX,
                ceiling: caps::MAX_FACES,
            },
        })
    );
}

/// The faces a test session takes beside its dial role's where the build takes any: none in a
/// build that holds its dial role's face alone, which refuses one more (`TAKES_FACES`).
const BESIDE_DIAL: usize = if crate::arena::TAKES_FACES { 2 } else { 0 };

/// A build without `listen` and `group` holds its dial role's face alone: its limits admit no
/// face beside it, whatever the session states, and a config that asks for one is refused by the
/// limit's name before any memory is asked. The CONTROL is the same config with none, which lays
/// out the dial role's one set of face tables.
///
/// Turned red by an `admitted_faces` that answers the session's `MAX_FACES` in such a build.
#[cfg(not(any(feature = "listen", feature = "group")))]
#[test]
fn a_session_that_only_dials_is_refused_a_face_beside_its_dial() {
    use crate::arena::admitted_faces;

    assert_eq!(admitted_faces(&SessionLimits::defaults()), Ok(0));
    assert_eq!(
        ArenaPlan::of(
            &CoopConfig {
                max_faces: 1,
                ..client_config()
            },
            &SessionLimits::defaults(),
        ),
        Err(ArenaRefused::Limit {
            limit: ArenaLimit::MaxFaces,
            why: UnlentRows::OverCeiling {
                value: 1,
                ceiling: 0,
            },
        })
    );
    let plan = ArenaPlan::of(
        &CoopConfig {
            max_faces: 0,
            ..client_config()
        },
        &SessionLimits::defaults(),
    )
    .expect("CONTROL: the dial role's face alone lays an arena out");
    assert_eq!((plan.peers().tables, plan.peers().sets()), (1, 1));
    assert!(plan.peers().dial, "the one face is the dial role's");
}

/// The links' rows are what the open lends first: their tables take exactly the rows' spans, a
/// receive buffer of the batch and [`LINK_TX_SLOTS`] slots of it for each link the config admits,
/// and the rest of the plan fills the arena to its size, so the reservation is still the plan.
#[cfg(not(wz_on_use))]
#[test]
fn the_links_rows_are_lent_first_and_the_reservation_is_still_the_plan() {
    use crate::arena::LINK_TX_SLOTS;

    let config = CoopConfig {
        max_faces: BESIDE_DIAL,
        ..client_config()
    };
    let held = 1 + BESIDE_DIAL;
    let batch = usize::from(config.batch_size);
    let plan = ArenaPlan::of(&config, &SessionLimits::defaults()).expect("lays an arena out");
    assert_eq!(
        row(&plan, "link receive buffers").count,
        pooled(caps::RX_POOL_BUFFERS, held),
        "the links share a pool, of no more buffers than links"
    );
    assert_eq!(row(&plan, "link receive buffers").entry_bytes, batch);
    assert_eq!(link_places(&plan), held);
    assert_eq!(
        row(&plan, "link transmit slots").count,
        pooled(caps::TX_POOL_SLOTS, held),
        "the links share a pool of outbound slots, of no more than links"
    );
    assert_eq!(
        row(&plan, "link transmit slots").entry_bytes,
        LINK_TX_SLOTS * batch
    );
    let links: usize = plan
        .rows()
        .filter(|row| row.part().starts_with("link "))
        .map(|row| row.span().expect("within the address space"))
        .sum();
    let mut session =
        SessionArena::reserve(&plan, &AllocatorMemory).expect("the host has the memory");
    let mut lend = session.lender();
    let tables = plan.transport().links_from(&mut lend);
    lend.finish().expect("the plan lays the links out");
    assert_eq!(session.arena_mut().high_water(), links);
    for row in plan.rows().filter(|row| !row.part().starts_with("link ")) {
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
    let claimed: Vec<_> = (0..held)
        .map(|_| tables.claim().expect("a link's buffers"))
        .collect();
    assert!(
        tables.claim().is_none(),
        "a link past the config's has none"
    );
    drop(claimed);
    assert_eq!(tables.in_use(), 0);
}

/// A link over the buffers its session's arena lent reads a datagram where the arena holds its
/// receive buffer, and nowhere else.
#[cfg(not(wz_on_use))]
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn a_link_reads_into_the_buffer_its_sessions_arena_lent() {
    use std::time::Instant;
    use wz_runtime_coop::session_drive::SessionDatagramLink;
    use wz_runtime_coop::udp_link::{DatagramSocket, UdpDriver};
    use wz_runtime_posix::net::PosixUdpSocket;

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

/// The two halves a link's actions hold (the link's own state and the session's kernel) lie in
/// the link's cell of the session's table: the dial role's link holds one, and the link dialled
/// again after the first is lost holds one, the lost link's given back first, so a link made
/// after the open takes no memory of the heap for them. The arena holds one link, so a lost link
/// whose cell is not given back leaves the next dial no cell. Turned red by halves held on the
/// heap (`McuActions::build` in `start_wire`), which take no cell of the table. A session whose
/// tables take their memory on use lends its links no table (`tests::on_use`).
#[cfg(not(wz_on_use))]
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn a_links_halves_lie_in_its_cell_across_a_redial() {
    let router = Router::start(CatchAll::None);
    let port = router.port;
    let engine = open_with(CoopConfig {
        redial_ms: Some(50),
        open_timeout_ms: 300,
        max_faces: 0,
        ..config(&router)
    });
    until(&engine, "the first link", || engine.faces_up() == 1);
    assert_eq!(
        engine.link_halves_in_use(),
        Some(1),
        "the dial role's link holds its halves in one cell"
    );
    router.send(Command::Close);
    drop(router);
    until(&engine, "the link to be lost", || engine.faces_up() == 0);
    let router = Router::start_on(port, CatchAll::None);
    // The lost link's task may let go of its actions a step after the link dialled again is up.
    until(
        &engine,
        "the lost link's cell to go back and the link dialled again to hold one",
        || engine.faces_up() == 1 && engine.link_halves_in_use() == Some(1),
    );
    drop(router);
}

/// A link nothing holds back (a read that hands each record out as it is read, no `wz_round`) is
/// its own gate: every call on it goes through its driver's table, and it takes no cell of the
/// gates' table. Where the round holds its links back, the dial role's link holds its gates in one
/// cell of that table. Turned red by a direct read whose gate is placed in a cell
/// (`LinkMaking::gate` through `CellRc::in_cells_of`), which puts a second table in front of
/// every call on the link.
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn a_link_nothing_holds_back_takes_no_cell_of_the_gates() {
    let router = Router::start(CatchAll::None);
    let engine = open_with(CoopConfig {
        max_faces: 0,
        ..config(&router)
    });
    until(&engine, "the dial role's link", || engine.faces_up() == 1);
    let gates = engine.link_gates_in_use();
    #[cfg(not(wz_round))]
    assert_eq!(gates.unwrap_or(0), 0, "the link is its own gate");
    #[cfg(wz_round)]
    assert!(
        matches!(gates, None | Some(1)),
        "the dial role's link holds its gates in one cell: {gates:?}"
    );
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
fn one_face_client() -> CoopConfig {
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
/// arena that is the sum of its rows' spans and smaller than the build's where the open lends the
/// rows the preset lowers from it, no larger where a region holds them at the build's bound.
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
    let plan = ArenaPlan::of(&one_face_client(), &limits).expect("the preset is under the build");
    let built =
        ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
    let preset = pico_value;
    let mut held = 0;
    for row in plan.rows() {
        // The key arena's row and the advanced cache's ring are one area of the limit's bytes, a
        // pool's one area of the rows its faces share, the watchers' one row of the spans of their
        // lists, and the session's table set one area of its tables, not a row of each. The udp ports' slots and their queue are a listening
        // session's, which the preset's client is not: it holds none whatever the limit.
        if row.basis() == "KEY_ARENA_BYTES"
            || row.basis() == "ADVANCED_CACHE_BYTES"
            || row.basis() == "UDP_PORT_SLOTS"
            || row.basis() == "MAX_DECL_OBSERVERS"
            || row.part() == "session tables"
            || POOL_PARTS.contains(&row.part())
        {
            continue;
        }
        // A table of a limit the preset leaves at its default, as many as zenoh-pico's own tests
        // hold, is as many rows as that default; any other limit is counted where it has a preset.
        let value = preset_of(&presets, row.basis()).or_else(|| {
            HELD_AT_THE_DEFAULT
                .contains(&row.basis())
                .then(|| pico_value(row.basis()))
        });
        if let Some(value) = value {
            // A pool the links share holds no more than the links: the client's one.
            let value = if row.basis() == "RX_POOL_BUFFERS" || row.basis() == "TX_POOL_SLOTS" {
                value.min(1)
            } else {
                value
            };
            assert_eq!(row.count, value, "{} at the pico preset", row.part());
            held += 1;
        }
    }
    // A matching listener declared on a key judges through a filter of its own in the one table,
    // in a build that keeps such listeners.
    let key_listeners = if cfg!(feature = "key-matching-listener") {
        preset("MAX_MATCHING_LISTENERS")
    } else {
        0
    };
    let filters = preset("MAX_PUBLISHERS") + preset("MAX_QUERIERS") + key_listeners;
    // The session's table set is one row of the arena; the rows of each of its tables are the
    // plan's own count of them, each table counted here as a row of its own limit was before the
    // set took it.
    let tables = plan.tables();
    for (rows, limit, what) in [
        (
            tables.keyexprs,
            preset("MAX_DECLARED_KEYEXPRS"),
            "keyexpr table",
        ),
        (tables.write_filters(), filters, "write filter table"),
        (
            tables.matching_listeners,
            preset("MAX_MATCHING_LISTENERS"),
            "matching listener table",
        ),
    ] {
        assert_eq!(rows, limit, "the session's {what} at the pico preset");
        held += 1;
    }
    assert!(held >= 3, "the preset sizes the plan's rows: {plan:?}");
    let entities = plan.entities();
    assert_eq!(entities.filters(), Some(filters));
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
            .try_fold(0usize, |sum, row| sum.checked_add(row.span()?)),
        "the arena is the sum of its rows' spans"
    );
    // The open lends the rows the preset lowers from the arena, so the preset's arena is under the
    // build's. A build of the region's form holds those rows in its region at the build's bound,
    // which a session's preset does not lower: each row its arena still lends is no larger than
    // the build's, and so is the arena.
    #[cfg(wz_lent)]
    assert!(
        Some(reserved) < built.reserved_bytes(),
        "the preset's arena is under the build's"
    );
    #[cfg(not(wz_lent))]
    {
        for laid in plan.rows() {
            let of_build = built.rows().find(|row| row.name == laid.name);
            assert!(
                of_build.is_some_and(|row| laid.span() <= row.span()),
                "the preset's {} is no larger than the build's",
                laid.part()
            );
        }
        assert!(
            Some(reserved) <= built.reserved_bytes(),
            "the preset's arena is not over the build's"
        );
    }
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

/// The parts of an arena held once for each face: the tables of what its peer writes and is owed,
/// its table of pending gets, and the ends of their legs, their callbacks and the session's note
/// of each.
#[cfg(feature = "listen")]
const FACE_PARTS: [&str; 5] = [
    "peer tables",
    "pending gets",
    "ended legs",
    "leg callbacks",
    "pending legs",
];

/// The parts of an arena held once for the session whose size follows its faces: the pools of what
/// the faces' peers write, each one area.
const POOL_PARTS: [&str; 3] = [
    "peer alias pool",
    "peer declaration pools",
    "peer interest pool",
];

/// The part of an arena that names where the pools' rows lie, one span whatever the faces.
#[cfg(wz_lent)]
const DIRECTORY_PART: &str = "peer row directory";

/// The rows a plan lays out for what the faces' peers write are the bytes lending those pools
/// takes, the directory of where their rows lie among them, so an arena of exactly those rows lends
/// the pools with nothing over: for a client's one face, whose tables take spans of their own, and
/// for a listener's faces, which share pools. Turned red by a plan that leaves out a span the lend
/// takes: the open's arena is then short by that span at the last place it lends, and the pico C
/// ABI answers the open with `_Z_ERR_SYSTEM_OUT_OF_MEMORY`.
#[cfg(wz_lent)]
#[test]
fn the_pool_rows_of_a_plan_are_what_lending_the_pools_takes() {
    let limits = pico_preset_limits();
    pools_lent_as_planned(&one_face_client(), &limits, false);
    #[cfg(feature = "listen")]
    {
        let faces = crate::arena::admitted_faces(&limits).expect("the preset is under the build");
        let handshakes =
            crate::arena::admitted_handshakes(&limits).expect("the preset is under the build");
        pools_lent_as_planned(
            &CoopConfig {
                listen: vec!["tcp/127.0.0.1:0".to_owned()],
                max_faces: faces,
                accept_pending: handshakes,
                ..client_config()
            },
            &limits,
            true,
        );
    }
}

/// Lend the pools the plan of `config` under `limits` counts from an arena of exactly the plan's
/// rows of them: those rows are what the pools take, the faces share them as `shared` says, and
/// the lend fills the arena.
#[cfg(wz_lent)]
fn pools_lent_as_planned(config: &CoopConfig, limits: &SessionLimits, shared: bool) {
    use wz_session_core::peer_tables::PeerPools;

    let plan = ArenaPlan::of(config, limits).expect("the preset is under the build");
    let pools = plan.peers().pools;
    assert_eq!(pools.shared, shared, "whether the faces share their pools");
    assert_eq!(
        row(&plan, DIRECTORY_PART).count,
        1,
        "the directory is one span"
    );
    let planned: usize = plan
        .rows()
        .filter(|row| POOL_PARTS.contains(&row.part()) || row.part() == DIRECTORY_PART)
        .map(|row| row.span().expect("within the address space"))
        .sum();
    assert_eq!(
        Some(planned),
        PeerPools::arena_bytes(pools),
        "the plan's rows of the pools are what lending them takes"
    );
    let mut keys_arena =
        SessionArena::of_bytes(1 << 16, &AllocatorMemory).expect("the host has the memory");
    let keys = keys_arena
        .arena_mut()
        .lend_keys(256, limits.max_keyexpr_bytes_held())
        .expect("the arena holds the key arena");
    let mut arena =
        SessionArena::of_bytes(planned, &AllocatorMemory).expect("the host has the memory");
    let lent = PeerPools::lent(arena.arena_mut(), keys, pools)
        .expect("an arena of the plan's rows lends the pools");
    assert_eq!(
        lent.is_shared(),
        shared,
        "the pools lent are shared as planned"
    );
    assert_eq!(
        arena.arena_mut().high_water(),
        planned,
        "the pools take the plan's rows and no more"
    );
}

/// The parts of an arena held once for each link: its place among the session's links.
#[cfg(feature = "listen")]
const LINK_PARTS: [&str; 1] = ["link places"];

/// The parts of the pool of receive buffers the links share (`RX_POOL_BUFFERS`, at most one for
/// each link).
#[cfg(feature = "listen")]
const RX_PARTS: [&str; 2] = ["link receive flags", "link receive buffers"];

/// The parts of the pool of outbound slots the links share (`TX_POOL_SLOTS`, at most one for each
/// link).
#[cfg(feature = "listen")]
const TX_PARTS: [&str; 2] = ["link transmit flags", "link transmit slots"];

/// The pico preset holds a session's faces to zenoh-pico's own bounds: ten peers on a listener
/// (`Z_LISTEN_MAX_CONNECTION_NB`) and one handshake at a time, and a client its one transport. A
/// client's arena lends one set of a face's tables and the buffers of one link; a peer's lends the
/// same rows, with a set and a link for each of the ten faces it admits and a link for its one
/// handshake: every other row is the client's, item for item, which is the sum
/// `docs/c-abi-no-heap-pools.md` (section 9.6) states. The peer listens, so a build without
/// `listen` refuses its faces.
#[cfg(feature = "listen")]
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
            ..one_face_client()
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
        .filter(|row| row.part() == "owed tokens")
        .collect();
    let owes = cfg!(all(
        wz_lent,
        feature = "liveliness",
        any(feature = "listen", feature = "group")
    ));
    assert_eq!(owed.len(), usize::from(owes), "{owed:?}");
    if let Some(row) = owed.first() {
        assert_eq!(row.count, peer.peers().pools.remote_decls);
    }
    // The peer listens on `tcp/` alone and binds no udp port, so neither lays out a port's row.
    assert!(
        peer.rows()
            .chain(client.rows())
            .all(|row| !PORT_PARTS.contains(&row.part())),
        "a session that binds no udp port lays out no row of one"
    );
    let rows: Vec<_> = peer
        .rows()
        .filter(|row| row.part() != "owed tokens")
        .collect();
    assert_eq!(rows.len(), client.rows().count());
    for (theirs, ours) in rows.into_iter().zip(client.rows()) {
        assert_eq!(
            (theirs.part(), theirs.basis()),
            (ours.part(), ours.basis()),
            "the same rows in the same order"
        );
        if POOL_PARTS.contains(&theirs.part()) {
            assert!(
                theirs.entry_bytes >= ours.entry_bytes,
                "{}: a pool of more faces is no smaller",
                theirs.part()
            );
            assert_eq!(theirs.count, 1, "{} is one area", theirs.part());
            continue;
        }
        // Each session's endpoint texts are its own config's, one area of them: the client here
        // names none, the peer the one endpoint it listens on.
        if theirs.part() == "endpoint texts" {
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
        let count = if RX_PARTS.contains(&theirs.part()) {
            pooled(preset("RX_POOL_BUFFERS"), faces + handshakes)
        } else if TX_PARTS.contains(&theirs.part()) {
            pooled(preset("TX_POOL_SLOTS"), faces + handshakes)
        } else if LINK_PARTS.contains(&theirs.part()) {
            ours.count * (faces + handshakes)
        } else if theirs.part() == "peer tables" {
            ours.count * faces
        } else if ["face tables", "held faces", "room places"].contains(&theirs.part()) {
            // Its dial role's face holds a set of no rows all the same, first, beside the faces'.
            ours.count * (1 + faces)
        } else if FACE_PARTS.contains(&theirs.part()) {
            // The gets' tables, and the ends of their legs, hold the session's own once.
            ours.count / (1 + own) * (faces + own)
        } else if !cfg!(wz_round)
            && ["reassembly flags", "reassembly buffers"].contains(&theirs.part())
        {
            // Each face's read stages its chains in a Router of its own (`direct`): the table
            // holds a share for each set of tables.
            ours.count / client.peers().sets() * peer.peers().sets()
        } else {
            ours.count
        };
        assert_eq!(
            theirs.count,
            count,
            "{} of a peer at the pico preset",
            theirs.part()
        );
    }
    let at_the_build = ArenaPlan::of(
        &CoopConfig {
            listen: vec!["tcp/127.0.0.1:0".to_owned()],
            ..client_config()
        },
        &SessionLimits::defaults(),
    )
    .expect("lays an arena out")
    .reserved_bytes();
    // A build that admits no more faces and handshakes than the preset, one made at it, lays out
    // the peer's links and faces at its defaults too, and so has nothing of them to lower.
    let build = SessionLimits::defaults();
    if admitted_faces(&build) == Ok(faces) && admitted_handshakes(&build) == Ok(handshakes) {
        assert!(
            peer.reserved_bytes() <= at_the_build,
            "a peer at the preset reserves no more than a listener at a build of the preset"
        );
    } else {
        assert!(
            peer.reserved_bytes() < at_the_build,
            "a peer at the preset reserves less than a listener at the build's defaults"
        );
    }
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
                row.part(),
                row.basis(),
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
                ..one_face_client()
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
                row.part(),
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

/// The ABI's places of pending gets are as many as the rows of a table of pending gets, and those
/// of pending liveliness gets as many as its liveliness gets', each kind under its own limit; a
/// build that asks no get, or no liveliness get, lays none of the kind. Turned red by places
/// counted by another limit, or a kind laid out in a build that cannot ask for it.
#[test]
fn the_places_of_pending_gets_are_the_rows_of_a_table_of_them() {
    use crate::arena::{EntityKind, HeldPlaces};
    let place = core::alloc::Layout::new::<u64>();
    let held = HeldPlaces::default()
        .with_entity(EntityKind::PendingGet, place)
        .with_entity(EntityKind::PendingLivelinessGet, place);
    let mut plan = ArenaPlan::of(&client_config(), &SessionLimits::defaults())
        .expect("the build's limits lay an arena out");
    plan.holding(&held)
        .expect("the build's limits lay the places out");
    let count = |part: &str| {
        plan.rows()
            .find(|row| row.part() == part)
            .map(|row| row.count)
    };
    assert_eq!(
        count("pending get places"),
        cfg!(feature = "query").then(|| plan.gets().rows.queries)
    );
    assert_eq!(
        count("pending liveliness get places"),
        cfg!(feature = "liveliness-get").then(|| plan.gets().rows.liveliness_gets)
    );
    assert_eq!(
        plan.entities().of_kind(EntityKind::PendingGet),
        plan.gets().rows.queries
    );
}

/// The ABI's places of matching listeners are as many as the rows of the engine's table of them,
/// counted by `MAX_MATCHING_LISTENERS`, in every build. Turned red by places counted by another
/// limit, or none laid out for the kind.
#[test]
fn the_places_of_matching_listeners_are_the_rows_of_their_table() {
    use crate::arena::{EntityKind, HeldPlaces};
    let place = core::alloc::Layout::new::<u64>();
    let held = HeldPlaces::default().with_entity(EntityKind::MatchingListener, place);
    let mut plan = ArenaPlan::of(&client_config(), &SessionLimits::defaults())
        .expect("the build's limits lay an arena out");
    plan.holding(&held)
        .expect("the build's limits lay the places out");
    let rows = plan.entities().of_kind(EntityKind::MatchingListener);
    assert!(rows > 0, "the build's limits admit matching listeners");
    let laid = plan
        .rows()
        .find(|row| row.part() == "matching listener places")
        .map(|row| (row.basis(), row.count));
    assert_eq!(laid, Some(("MAX_MATCHING_LISTENERS", rows)));
    assert_eq!(plan.tables().matching_listeners, rows);
}

/// The ABI's places of declaration watches are as many as `MAX_DECL_WATCHES` admits in a build
/// with the watch, and none without it. Turned red by places counted by another limit, or laid
/// out in a build that has no watch to hold.
#[test]
fn the_places_of_declaration_watches_are_counted_by_their_limit() {
    use crate::arena::{EntityKind, HeldPlaces};
    let place = core::alloc::Layout::new::<u64>();
    let held = HeldPlaces::default().with_entity(EntityKind::DeclWatch, place);
    let mut plan = ArenaPlan::of(&client_config(), &SessionLimits::defaults())
        .expect("the build's limits lay an arena out");
    plan.holding(&held)
        .expect("the build's limits lay the places out");
    let rows = plan.entities().of_kind(EntityKind::DeclWatch);
    let laid = plan
        .rows()
        .find(|row| row.part() == "declaration watch places")
        .map(|row| (row.basis(), row.count));
    if cfg!(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    )) {
        assert!(rows > 0, "the build's limits admit declaration watches");
        assert_eq!(laid, Some(("MAX_DECL_WATCHES", rows)));
    } else {
        assert_eq!(rows, 0, "a build without the watch holds none");
        assert_eq!(laid, None, "and lays no place out for one");
    }
}

/// The ABI's places of transport events listeners are as many as
/// `MAX_TRANSPORT_EVENTS_LISTENERS` admits in a build with `connectivity`, and none without it.
/// Turned red by places counted by another limit, or laid out in a build with no listener to hold.
#[test]
fn the_places_of_transport_events_listeners_are_counted_by_their_limit() {
    use crate::arena::{EntityKind, HeldPlaces};
    let place = core::alloc::Layout::new::<u64>();
    let held = HeldPlaces::default().with_entity(EntityKind::TransportEventsListener, place);
    let mut plan = ArenaPlan::of(&client_config(), &SessionLimits::defaults())
        .expect("the build's limits lay an arena out");
    plan.holding(&held)
        .expect("the build's limits lay the places out");
    let rows = plan.entities().of_kind(EntityKind::TransportEventsListener);
    let laid = plan
        .rows()
        .find(|row| row.part() == "transport events listener places")
        .map(|row| (row.basis(), row.count));
    if cfg!(feature = "connectivity") {
        assert!(
            rows > 0,
            "the build's limits admit transport events listeners"
        );
        assert_eq!(laid, Some(("MAX_TRANSPORT_EVENTS_LISTENERS", rows)));
    } else {
        assert_eq!(rows, 0, "a build without connectivity holds none");
        assert_eq!(laid, None, "and lays no place out for one");
    }
}

/// The ABI's places of link events listeners are as many as `MAX_LINK_EVENTS_LISTENERS` admits in
/// a build with `connectivity`, and none without it, apart from the transport events listeners'.
/// Turned red by places counted by another limit, or laid out in a build with no listener to hold.
#[test]
fn the_places_of_link_events_listeners_are_counted_by_their_limit() {
    use crate::arena::{EntityKind, HeldPlaces};
    let place = core::alloc::Layout::new::<u64>();
    let held = HeldPlaces::default().with_entity(EntityKind::LinkEventsListener, place);
    let mut plan = ArenaPlan::of(&client_config(), &SessionLimits::defaults())
        .expect("the build's limits lay an arena out");
    plan.holding(&held)
        .expect("the build's limits lay the places out");
    let rows = plan.entities().of_kind(EntityKind::LinkEventsListener);
    let laid = plan
        .rows()
        .find(|row| row.part() == "link events listener places")
        .map(|row| (row.basis(), row.count));
    if cfg!(feature = "connectivity") {
        assert!(rows > 0, "the build's limits admit link events listeners");
        assert_eq!(laid, Some(("MAX_LINK_EVENTS_LISTENERS", rows)));
    } else {
        assert_eq!(rows, 0, "a build without connectivity holds none");
        assert_eq!(laid, None, "and lays no place out for one");
    }
}

/// A plan with every row of the build, the links' cells, their gates', their actions', the faces'
/// rooms, the ABI's handle and its places for every kind of entity among them, holds exactly
/// `ARENA_ROWS` rows: the groups' counts are the rows the plan puts, in whichever build. A group
/// that puts a row it does not count, or counts one it does not put, turns this red. A build that
/// joins groups names one, since a config that names none plans no group receive table, and a build
/// that listens listens on a `udp/` endpoint, since a session with no port plans none of the
/// ports' rows. Each of
/// those rows names a part of its own, which a report finds it by: a part named as another, or a
/// table laid out under the part of its flags twice, turns this red too.
#[test]
fn a_plan_with_every_row_holds_exactly_arena_rows() {
    use crate::arena::{EntityKind, HeldPlaces};
    use wz_capi_port::group::{GroupDeclarations, GroupJoin, GroupProfile};

    let join = GroupJoin {
        endpoint: "udp/239.7.7.7:7447#iface=lan7".to_owned(),
        profile: GroupProfile {
            lease_ms: 10_000,
            join_interval_ms: 2_500,
            max_sessions: None,
            seq_num_res: wz_session_core::policy::SnResolution::Bits32,
            req_id_res: 0x02,
            batch_size: 2_048,
            is_qos: false,
            compression: false,
            join_rule: wz_session_core::multicast_params::GroupJoinRule::Pico,
        },
        is_shm: false,
        declarations: GroupDeclarations::Entities,
    };
    let groups = usize::from(cfg!(feature = "group"));
    let place = core::alloc::Layout::new::<u64>();
    let held = EntityKind::ALL
        .into_iter()
        .fold(HeldPlaces::handle(place), |held, kind| {
            held.with_entity(kind, place)
        })
        .with_lodgings(place, 1);
    // Faces that share their pools where the build takes faces beside its dial role's, so the
    // table of tokens the faces that went owe is put too.
    let listen = if cfg!(feature = "listen") {
        vec!["udp/127.0.0.1:0".to_owned()]
    } else {
        Vec::new()
    };
    let mut plan = ArenaPlan::of(
        &CoopConfig {
            max_faces: BESIDE_DIAL,
            groups: vec![join; groups],
            listen,
            ..client_config()
        },
        &SessionLimits::defaults(),
    )
    .expect("the build's limits lay an arena out");
    plan.holding_cells(crate::arena::LinkCells {
        driver: 64,
        gate: 64,
        actions: 64,
        halves: 64,
    })
    .expect("the build's limits lay the cells out");
    plan.holding_rooms(64)
        .expect("the build's limits lay the rooms out");
    plan.holding(&held)
        .expect("the build's limits lay the places out");
    plan.holding_runtime(64)
        .expect("the build's limits lay the runtime's span out");
    plan.holding_engine(64)
        .expect("the build's limits lay the engine's place out");
    plan.lay_planes(crate::engine::SessionPlanes::OF_BUILD);
    #[cfg(all(feature = "link-admission", not(wz_on_use)))]
    plan.lay_admission(64);
    #[cfg(all(not(wz_round), not(wz_on_use)))]
    plan.lay_direct_faces(64);
    plan.settled()
        .expect("the build's limits lay the planes' and the admission's places out");
    assert_eq!(plan.rows().count(), crate::arena::ARENA_ROWS);
    let mut parts: Vec<&str> = plan.rows().map(|row| row.part()).collect();
    parts.sort_unstable();
    parts.dedup();
    assert_eq!(parts.len(), crate::arena::ARENA_ROWS, "a part named twice");
}

/// The allocator, counting what it gives and what it is given back. Each value of it is reserved
/// from by one test alone.
struct Recorded {
    reserves: AtomicUsize,
    reserved: AtomicUsize,
    releases: AtomicUsize,
    released: AtomicUsize,
}

impl ArenaMemory for Recorded {
    fn reserve(&self, layout: core::alloc::Layout) -> Option<core::ptr::NonNull<u8>> {
        let base = AllocatorMemory.reserve(layout)?;
        self.reserves.fetch_add(1, Ordering::SeqCst);
        self.reserved.fetch_add(layout.size(), Ordering::SeqCst);
        Some(base)
    }

    unsafe fn release(&self, base: core::ptr::NonNull<u8>, layout: core::alloc::Layout) {
        self.releases.fetch_add(1, Ordering::SeqCst);
        self.released.fetch_add(layout.size(), Ordering::SeqCst);
        // SAFETY: the caller's contract: the allocator gave `base` for `layout`, given back once.
        unsafe { AllocatorMemory.release(base, layout) }
    }
}

static RECORDED: Recorded = Recorded {
    reserves: AtomicUsize::new(0),
    reserved: AtomicUsize::new(0),
    releases: AtomicUsize::new(0),
    released: AtomicUsize::new(0),
};

/// An open refused once its arena has lent every table (an endpoint's text longer than a row,
/// which the source writes after the lend) lets go of what it was lent whole: its tables, then
/// the arena, given back once and every byte of it. Turned red by a value of the lent tables that
/// keeps the arena past a refusal, or gives it back twice.
#[test]
fn an_open_refused_after_its_lend_gives_its_arena_back_once() {
    use crate::arena::{HeldPlaces, OpenStorage};
    use crate::{EndpointRefusal, Refusal};

    let long = format!("tcp/127.0.0.1:{}", "7".repeat(caps::MAX_LOCATOR_LEN));
    let refused = Engine::open_made_in(
        host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        PosixEntropy,
        || CoopConfig {
            endpoints: vec![long.clone()],
            ..client_config()
        },
        SessionPolicy::defaults(),
        OpenKeyIds::none(),
        OpenStorage {
            memory: &RECORDED,
            plan: crate::arena::PlanFrom::Config(&HeldPlaces::NONE),
        },
    )
    .err();
    assert_eq!(
        refused,
        Some(OpenError::Unreachable(EndpointRefusal::new(
            &long,
            Refusal::TextTooLong
        )))
    );
    // A session of the region's form reserves its region and its arena as one block.
    assert_eq!(
        RECORDED.reserves.load(Ordering::SeqCst),
        1,
        "one block, its region's and its arena's"
    );
    assert_eq!(
        RECORDED.releases.load(Ordering::SeqCst),
        1,
        "given back once"
    );
    let reserved = RECORDED.reserved.load(Ordering::SeqCst);
    assert!(reserved > 0, "the arena was reserved before the refusal");
    assert_eq!(RECORDED.released.load(Ordering::SeqCst), reserved);
}

/// What `an_open_refused_at_its_drawn_zid_gives_its_arena_back_once` reserves from.
static RECORDED_AT_ZID: Recorded = Recorded {
    reserves: AtomicUsize::new(0),
    reserved: AtomicUsize::new(0),
    releases: AtomicUsize::new(0),
    released: AtomicUsize::new(0),
};

/// An open refused at its drawn zid (a source that gives nothing, for a config that states no zid),
/// once its arena lent every table, its texts were written and its entropy's cell was taken, lets
/// go of what it was lent whole: the cell, the tables, then the arena, given back once and every
/// byte of it. Turned red by a refusal after the lend that keeps the arena past it, or gives it
/// back twice.
#[test]
fn an_open_refused_at_its_drawn_zid_gives_its_arena_back_once() {
    use crate::arena::{HeldPlaces, OpenStorage};
    use wz_session_core::entropy::{EntropySource, EntropyUnavailable};
    use wz_session_core::policy::ZidDerivation;

    struct Dry;
    impl EntropySource for Dry {
        fn try_fill_bytes(&mut self, _buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
            Err(EntropyUnavailable)
        }
    }

    let mut policy = SessionPolicy::defaults();
    policy
        .select_zid_derivation(ZidDerivation::Random)
        .expect("a host build allows every value of the zid derivation");
    let refused = Engine::open_made_in(
        host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        Dry,
        || CoopConfig {
            zid: None,
            ..client_config()
        },
        policy,
        OpenKeyIds::none(),
        OpenStorage {
            memory: &RECORDED_AT_ZID,
            plan: crate::arena::PlanFrom::Config(&HeldPlaces::NONE),
        },
    )
    .err();
    assert_eq!(refused, Some(OpenError::EntropyUnavailable));
    assert_eq!(
        RECORDED_AT_ZID.reserves.load(Ordering::SeqCst),
        1,
        "one block, its region's and its arena's"
    );
    assert_eq!(
        RECORDED_AT_ZID.releases.load(Ordering::SeqCst),
        1,
        "given back once"
    );
    let reserved = RECORDED_AT_ZID.reserved.load(Ordering::SeqCst);
    assert!(reserved > 0, "the arena was reserved before the refusal");
    assert_eq!(RECORDED_AT_ZID.released.load(Ordering::SeqCst), reserved);
}

/// A plan laid out when the build is compiled is the plan an open lays out at run time, row by
/// row: for a client of the build's limits, and for a client of the pico preset that dials as many
/// endpoints as the build admits, the shape a build of fixed limits lays its arena out by. Turned
/// red by a row the walk lays out at one time and not the other, or by a number of the config the
/// shape reads apart from the one the open reads.
#[test]
fn a_plan_laid_out_when_the_build_is_compiled_is_the_one_an_open_lays_out() {
    use crate::arena::PlanShape;
    // A build that takes no face beside its dial role's lays none out, whatever the limit.
    const CLIENT: PlanShape = PlanShape {
        max_faces: if crate::arena::TAKES_FACES {
            caps::MAX_FACES
        } else {
            0
        },
        accept_pending: caps::MAX_ACCEPT_PENDING,
        ..PlanShape::dial_only(0, 1024, &SessionPolicy::defaults())
    };
    const CLIENT_PLAN: Result<ArenaPlan, ArenaRefused> =
        ArenaPlan::planned(CLIENT, &SessionLimits::BUILD);
    assert_eq!(PlanShape::of(&client_config()), CLIENT);
    let at_open = ArenaPlan::of(&client_config(), &SessionLimits::defaults());
    assert!(
        at_open.is_ok(),
        "CONTROL: the build lays its own client out"
    );
    assert_eq!(CLIENT_PLAN, at_open);

    const PRESET: PlanShape =
        PlanShape::dial_only(caps::MAX_STATIC_CONNECT, 1024, &SessionPolicy::defaults());
    const PRESET_PLAN: Result<ArenaPlan, ArenaRefused> =
        ArenaPlan::planned(PRESET, &SessionLimits::PICO_PRESET);
    let preset = CoopConfig {
        endpoints: vec![String::from("udp/127.0.0.1:7447"); caps::MAX_STATIC_CONNECT],
        max_faces: 0,
        accept_pending: 0,
        limits: SessionLimits::PICO_PRESET,
        ..client_config()
    };
    assert_eq!(PlanShape::of(&preset), PRESET);
    let at_open = ArenaPlan::of(&preset, &SessionLimits::PICO_PRESET);
    assert!(at_open.is_ok(), "CONTROL: the preset lays a client out");
    let (Ok(at_build), Ok(at_open)) = (&PRESET_PLAN, &at_open) else {
        unreachable!("both laid out");
    };
    assert!(
        at_build.rows().eq(at_open.rows()),
        "row by row: {at_build:?} against {at_open:?}"
    );
    assert_eq!(at_build.reserved_bytes(), at_open.reserved_bytes());
    assert_eq!(PRESET_PLAN.as_ref(), Ok(at_open));
}

/// The rows of a client of the pico preset that dials as many endpoints as the build admits and
/// advertises a batch of 1024 bytes, as a build of fixed limits lays them out when it is compiled.
const fn preset_rows() -> crate::arena::ArenaRegion {
    match crate::arena::ArenaRegion::of(
        crate::arena::PlanShape::dial_only(
            caps::MAX_STATIC_CONNECT,
            1024,
            &SessionPolicy::defaults(),
        ),
        SessionLimits::PICO_PRESET,
    ) {
        Ok(region) => region,
        Err(_) => panic!("the preset lays a client out"),
    }
}

/// [`preset_rows`] as a build states its region.
static PRESET_REGION: crate::arena::ArenaRegion = preset_rows();

/// A client of [`PRESET_REGION`]'s shape and limits that dials `dials` endpoints.
fn preset_client(dials: usize) -> CoopConfig {
    CoopConfig {
        endpoints: vec![String::from("udp/127.0.0.1:7447"); dials],
        max_faces: 0,
        limits: SessionLimits::PICO_PRESET,
        ..client_config()
    }
}

/// The pico preset with one limit moved off its value: limits a region of the preset was not laid
/// out for.
fn other_than_preset() -> SessionLimits {
    let preset = SessionLimits::PICO_PRESET;
    let moved = if preset.max_subscriptions() == Quota::at_most(2) {
        1
    } else {
        2
    };
    let mut other = preset;
    other
        .select_max_subscriptions(Quota::at_most(moved))
        .expect("the build admits a few subscribers");
    assert_ne!(other, preset, "CONTROL: the limits differ from the preset");
    other
}

/// A region lays out, for an open of a config of its shape and limits, the rows an open of its own
/// shape lays out from the config, whether the config dials as many endpoints as the region holds
/// rows for or fewer, and admits handshakes it never takes, listening on nothing. A config that
/// dials more, listens, advertises another batch, admits another face or holds other limits is
/// refused under what differs, and is laid out no row. Turned red by a region that lays its rows
/// out for a config it was not laid out for, or refuses one it was.
#[test]
fn a_region_lays_out_its_rows_for_its_own_shape_and_limits_alone() {
    let lay_out = |config: &CoopConfig| {
        let mut plan = ArenaPlan::vacant();
        PRESET_REGION.lay_out_on(&mut plan, config).map(|()| plan)
    };
    let most = ArenaPlan::of(
        &preset_client(caps::MAX_STATIC_CONNECT),
        &SessionLimits::PICO_PRESET,
    );
    assert!(most.is_ok(), "CONTROL: the preset lays a client out");
    assert_ne!(
        preset_client(1).accept_pending,
        0,
        "CONTROL: the client admits handshakes it never takes"
    );
    assert_eq!(lay_out(&preset_client(caps::MAX_STATIC_CONNECT)), most);
    assert_eq!(lay_out(&preset_client(1)), most);
    assert_eq!(
        lay_out(&preset_client(caps::MAX_STATIC_CONNECT + 1)),
        Err(ArenaRefused::Limit {
            limit: ArenaLimit::MaxStaticConnect,
            why: UnlentRows::OverCeiling {
                value: caps::MAX_STATIC_CONNECT + 1,
                ceiling: caps::MAX_STATIC_CONNECT,
            },
        })
    );
    let other_shape = Err(ArenaRefused::Limit {
        limit: ArenaLimit::ShapeDiffersFromBuild,
        why: UnlentRows::NoCeiling,
    });
    assert_eq!(
        lay_out(&CoopConfig {
            batch_size: 512,
            ..preset_client(1)
        }),
        other_shape
    );
    assert_eq!(
        lay_out(&CoopConfig {
            max_faces: 1,
            ..preset_client(1)
        }),
        other_shape
    );
    assert_eq!(
        lay_out(&CoopConfig {
            listen: vec![String::from("tcp/127.0.0.1:7447")],
            ..preset_client(1)
        }),
        other_shape
    );
    assert_eq!(
        lay_out(&CoopConfig {
            limits: other_than_preset(),
            ..preset_client(1)
        }),
        Err(ArenaRefused::Limit {
            limit: ArenaLimit::LimitsDifferFromBuild,
            why: UnlentRows::NoCeiling,
        })
    );
}

/// A region laid out with the engine's places holds every row an open over a config of its shape
/// lays out at the open, the links' cells, the rooms, the ABI's places, the runtime's span and the
/// engine's place after the tables included, so an open by it takes the plan whole and lays out
/// no row. Turned red by a region that leaves a place out (`OpenRegion::laid` laying none) or
/// sizes one by anything but the engine's types and the ABI's constants.
#[test]
fn a_region_with_the_engines_places_holds_every_row_an_open_lays_out() {
    use crate::arena::HeldPlaces;

    let held = HeldPlaces::handle(core::alloc::Layout::from_size_align(40, 8).expect("a layout"));
    let config = preset_client(caps::MAX_STATIC_CONNECT);
    let region = Engine::open_region(preset_rows(), held).expect("the engine's places lay out");
    let at_open = held_plan(&config, &held).expect("the preset lays a client out");
    let mut taken = ArenaPlan::vacant();
    region
        .rows()
        .lay_out_on(&mut taken, &config)
        .expect("the region admits its own");
    let tables = ArenaPlan::planned(
        crate::arena::PlanShape::dial_only(
            caps::MAX_STATIC_CONNECT,
            1024,
            &SessionPolicy::defaults(),
        ),
        &SessionLimits::PICO_PRESET,
    )
    .expect("the preset lays a client out");
    assert!(
        region.reserved_bytes() > tables.reserved_bytes(),
        "CONTROL: the places take bytes past the tables"
    );
    assert_eq!(taken, at_open);
    assert_eq!(region.reserved_bytes(), at_open.reserved_bytes());
}

/// A place of the ABI's that asks for more alignment than a span of the arena starts on refuses
/// the region when it is laid out, as it refuses an open over a config, and leaves no region to
/// open by. Turned red by a region laid out past the refusal of its places.
#[test]
fn a_region_whose_places_the_arena_cannot_hold_is_refused() {
    use crate::arena::HeldPlaces;
    use wz_session_core::bounded::ARENA_ALIGN;

    let over = core::alloc::Layout::from_size_align(8, ARENA_ALIGN * 2).expect("a layout");
    assert_eq!(
        Engine::open_region(preset_rows(), HeldPlaces::handle(over)).err(),
        Some(ArenaRefused::TooLarge)
    );
    assert!(
        Engine::open_region(preset_rows(), HeldPlaces::NONE).is_ok(),
        "CONTROL: the region of no place of the ABI's lays out"
    );
}

/// An open whose rows come from a region reserves the arena an open of the same config lays out
/// from the config, and an open of limits the region was not laid out for is refused before
/// anything is dialled. Turned red by an open that reads the region apart from the config, or
/// lends from a region it should refuse.
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn an_open_by_a_region_reserves_the_plan_its_config_lays_out_and_no_other() {
    use crate::arena::{ArenaRegion, HeldPlaces, OpenRegion, OpenStorage, PlanFrom, PlanShape};

    let open_by = |config: CoopConfig, region: &'static OpenRegion| {
        Engine::open_made_in(
            host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
            PosixClock,
            PosixEntropy,
            || config,
            SessionPolicy::defaults(),
            OpenKeyIds::none(),
            OpenStorage {
                memory: &AllocatorMemory,
                plan: PlanFrom::Region(region),
            },
        )
    };
    let laid = |rows: ArenaRegion| -> &'static OpenRegion {
        Box::leak(Box::new(
            Engine::open_region(rows, HeldPlaces::NONE).expect("the engine's places lay out"),
        ))
    };
    let router = Router::start(CatchAll::None);
    let own = laid(
        ArenaRegion::of(PlanShape::of(&config(&router)), config(&router).limits)
            .expect("the build's limits lay an arena out"),
    );
    let engine = open_by(config(&router), own).expect("the session opens");
    let plan = host_plan(&config(&router)).expect("the build's limits lay an arena out");
    assert_eq!(Some(engine.arena_bytes()), plan.reserved_bytes());
    let probe = Probe::bind();
    let refused = open_by(
        CoopConfig {
            endpoints: vec![probe.endpoint()],
            open_timeout_ms: 300,
            limits: other_than_preset(),
            ..preset_client(0)
        },
        laid(preset_rows()),
    )
    .err();
    assert_eq!(
        refused,
        Some(OpenError::Arena(ArenaRefused::Limit {
            limit: ArenaLimit::LimitsDifferFromBuild,
            why: UnlentRows::NoCeiling,
        }))
    );
    assert!(!probe.reached(), "a refused open dials nothing");
}

/// A group whose members' keyexprs are each their own counts every member's aliases at its face's
/// place in the session's pool, and each other face one peer's.
#[cfg(feature = "multicast-declarations")]
#[test]
fn a_groups_face_counts_every_members_aliases_in_the_pool() {
    use crate::arena::{faces_aliases, GROUP_FACE_ALIASES};
    assert_eq!(faces_aliases(3, 0, 16), 48, "CONTROL: no group's face");
    assert_eq!(
        faces_aliases(3, 1, 16),
        2 * 16 + GROUP_FACE_ALIASES,
        "two faces of one peer and one group's"
    );
    assert_eq!(
        GROUP_FACE_ALIASES,
        caps::MAX_GROUP_MEMBERS * caps::MAX_MEMBER_KEYEXPRS
    );
}

/// The planes the session's state owns lie in the session's own memory, reached by its engine and
/// its tasks through handles that count nothing: each in the place its plan laid out for it in the
/// arena where the open lays the plan out, and in its field of the state (`StatePlaces`) where it
/// does not: the region, the head of the block the arena is the tail of, where the build fixes the
/// session's shape, or the session's own state where its tables take their memory on use. Turned
/// red by a plane made on the heap apart from that state, or by one placed anywhere but where its
/// build puts it.
#[test]
#[cfg(any(feature = "queryable", feature = "query", feature = "connectivity"))]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn a_sessions_planes_lie_in_its_own_arena() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let places = engine.plane_places();
    assert!(!places.is_empty(), "the build has a plane");
    for at in places {
        #[cfg(wz_lent)]
        assert!(engine.arena_holds(at), "the plane lies in the arena");
        #[cfg(not(wz_lent))]
        assert!(engine.state_holds(at), "the plane lies in the state");
    }
}

/// A session's engine lies in the session's own arena, and is reached through its row while the
/// session is open and by no handle once it is closed, though a holder still keeps it. Turned red
/// by an engine written anywhere but the place its plan laid out, or by a close that leaves its row
/// held. A session whose tables take their memory on use holds its engine apart from its arena
/// (`tests::on_use`), and is held here to its row alone.
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn a_sessions_engine_lies_in_its_own_arena_and_is_reached_until_it_closes() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    #[cfg(not(wz_on_use))]
    assert!(engine.arena_holds(EngineHold::as_ptr(&engine).cast()));
    let handle = EngineHold::downgrade(&engine);
    assert!(handle
        .upgrade()
        .is_some_and(|reached| EngineHold::ptr_eq(&reached, &engine)));
    wz_capi_port::SessionDrive::close(&*engine);
    assert!(
        handle.upgrade().is_none(),
        "closed, it is reached by no handle"
    );
}

/// A session its dial role's lost link ended, with no redial, reads closed through a handle by
/// the row's mark alone, as one its program closed does, though the handle still reaches the
/// engine, which the row holds; the program's close then lets the row go, so the next open takes
/// it, and a second close lets go of nothing twice. Turned red by a step's end of the session that
/// leaves the row's mark current (no `ReachEngine::end`), a handle that reads an open session
/// closed, or a close that lets go of nothing because a step said the session closed first.
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn a_session_a_lost_link_ended_reads_closed_through_its_handle() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let handle = EngineHold::downgrade(&engine);
    assert!(handle.is_open(), "an open session's handle reads it open");
    router.send(Command::Close);
    drop(router);
    until(&engine, "the lost link to end the session", || {
        wz_capi_port::SessionDrive::is_closed(&*engine)
    });
    assert!(!handle.is_open(), "ended by its step, it reads closed");
    assert!(
        handle.upgrade().is_some(),
        "the row still holds the engine a step ended"
    );
    wz_capi_port::SessionDrive::close(&*engine);
    assert!(
        handle.upgrade().is_none(),
        "the close vacates the row of a session a step ended"
    );
    wz_capi_port::SessionDrive::close(&*engine);
    assert!(!handle.is_open(), "a second close changes nothing");
}

/// Where each face is read where it lies (no `wz_round`), each face's Router stages its chains
/// apart: the reassembly table holds one face's share for each face read where it lies, and the
/// faces past the dial role's are laid out a row each, of one face's read slot and send place.
/// Only a session that listens reads a face past the dial role's where it lies: a build without
/// `listen`, groups and all, has one share and no such row whatever its face table's places, a
/// group's place being read through the group's own session. Turned red by a table of one share
/// whatever the faces of a build that listens (`ArenaPlan::lay_out`), by a row or a share for
/// each place of a build that does not (`read_faces`), or by a row for the dial role's face,
/// which lies in the engine's place (`ArenaPlan::lay_direct_faces`). A session whose tables take
/// their memory on use lays out no such row, each face being made at its place's first face, but
/// keeps the shares: turned red there by a row laid out for them (`DIRECT_FACE_ROWS`).
#[cfg(not(wz_round))]
#[test]
fn each_face_read_where_it_lies_is_lent_a_share_of_chain_buffers_of_its_own() {
    let config = CoopConfig {
        max_faces: BESIDE_DIAL,
        ..client_config()
    };
    let plan = host_plan(&config).expect("lays an arena out");
    let sets = plan.peers().sets();
    if crate::arena::TAKES_FACES {
        assert!(
            sets > 1,
            "CONTROL: the face table has places past the dial role's"
        );
    }
    let read = if cfg!(feature = "listen") { sets } else { 1 };
    assert_eq!(
        row(&plan, "reassembly buffers").count,
        caps::REASSEMBLY_CHAINS * read
    );
    let direct = plan.rows().find(|row| row.part() == "direct faces");
    #[cfg(not(wz_on_use))]
    if read > 1 {
        let direct = direct.expect("a row of the faces past the dial role's");
        assert_eq!(direct.count, read - 1);
        assert_eq!(direct.entry_bytes, Engine::DIRECT_FACE_BYTES);
        return;
    }
    // The dial role's face lies in the engine's place, and on use each face past it is made at
    // its place's first face.
    assert!(
        direct.is_none(),
        "no row is laid out for a face's read slot"
    );
}

/// An open's plan lays out what a listed plan of the same session lays out, every sum and every
/// layer's rows, and lists no row, so the open's frame holds no table of them; a listed plan taken
/// on by an open's plan, as a region's is, is the same plan. Turned red by a walk whose sums depend
/// on the list it keeps, or a `take_on` that leaves a sum or a layer's rows behind.
#[cfg(feature = "runtime-plan")]
#[test]
fn an_open_s_plan_lays_out_a_listed_plan_s_sums_and_lists_no_row() {
    let config = client_config();
    let listed = ArenaPlan::of(&config, &config.limits).expect("lays an arena out");
    let mut open = crate::arena::OpenPlan::blank();
    open.count(&config, &config.limits)
        .expect("lays an arena out");
    assert!(
        listed.rows().count() > 0,
        "CONTROL: the listed plan lists its rows"
    );
    assert_eq!(open.rows().count(), 0);
    assert_eq!(open.reserved_bytes(), listed.reserved_bytes());
    assert_eq!(open.transport(), listed.transport());
    assert_eq!(open.session(), listed.session());
    assert_eq!(open.places(), listed.places());
    let mut taken = crate::arena::OpenPlan::blank();
    taken.take_on(&listed);
    assert_eq!(taken, open);
}

/// A plan that takes a laid plan on is that plan, whatever it held before: every sum, every layer's
/// rows and every listed row, so the plan an open made is replaced whole and keeps nothing of its
/// own. Turned red by a `take_on` that leaves a sum, a layer's rows or a listed row of the plan it
/// overwrote as it was.
#[cfg(feature = "runtime-plan")]
#[test]
fn a_plan_taken_on_is_the_laid_plan_whatever_it_held() {
    let laid = ArenaPlan::of(
        &preset_client(caps::MAX_STATIC_CONNECT),
        &SessionLimits::PICO_PRESET,
    )
    .expect("the preset lays a client out");
    let mut taken = ArenaPlan::of(&preset_client(1), &other_than_preset())
        .expect("the other limits lay a client out");
    assert_ne!(
        taken, laid,
        "CONTROL: the plan written over differs from the one taken on"
    );
    taken.take_on(&laid);
    assert_eq!(taken, laid);
}

/// A region lays its plan out over a plan that held another as over a vacant one, in a build that
/// lays its plans out at the open and in one that does not: the open lays the region's plan over
/// the plan it made, which keeps nothing of its own. Turned red by a `lay_out_on` that leaves a sum,
/// a layer's rows or a listed row of the plan it lays out over as it was.
#[test]
fn a_region_lays_its_plan_over_one_that_held_another() {
    let config = preset_client(caps::MAX_STATIC_CONNECT);
    let mut vacant = ArenaPlan::vacant();
    PRESET_REGION
        .lay_out_on(&mut vacant, &config)
        .expect("the region admits a client of its own shape");
    let mut held = ArenaPlan::of(&preset_client(1), &other_than_preset())
        .expect("the other limits lay a client out");
    assert_ne!(
        held, vacant,
        "CONTROL: the plan laid over differs from the region's"
    );
    PRESET_REGION
        .lay_out_on(&mut held, &config)
        .expect("the region admits a client of its own shape");
    assert_eq!(held, vacant);
}
