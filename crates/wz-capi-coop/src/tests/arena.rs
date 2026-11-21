// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The arena a session's open reserves: its size is its plan's, every row of the plan is lent from
//! it with nothing over, and an open whose arena cannot be reserved, or whose limits are over the
//! build's, dials nothing.

use std::net::UdpSocket;
use std::sync::Arc;
use std::time::Duration;

use wz_runtime_posix::links::PosixLinks;
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::bounded::{BoundedVec, Lent};
use wz_session_core::caps;
use wz_session_core::limit_binding::{Quota, UnlentRows};
use wz_session_core::limits::SessionLimits;
use wz_session_core::policy::SessionPolicy;

use super::{client_config, open, CatchAll, Engine, Router, LOOPBACK};
use crate::arena::{AllocatorMemory, ArenaMemory, ArenaPlan, ArenaRefused, SessionArena};
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
    let mut lowered = SessionLimits::defaults();
    if lowered.select_max_subscriptions(Quota::at_most(2)).is_err() {
        // A build that keeps the limit to its own value has no other.
        return;
    }
    let at_two = ArenaPlan::of(&client_config(), &lowered).expect("lays an arena out");
    let built =
        ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
    assert_eq!(row(&at_two, "subscribers").count, 2);
    assert_eq!(row(&built, "subscribers").count, caps::MAX_SUBSCRIPTIONS);
    assert!(at_two.reserved_bytes() < built.reserved_bytes());
}

/// A listener lays out the gets of a face for the dial role, each face it admits and each
/// handshake it holds; the application's tables are the session's, once, however many faces it
/// holds.
#[test]
fn a_listener_lays_out_the_gets_of_each_face_it_admits() {
    let dial =
        ArenaPlan::of(&client_config(), &SessionLimits::defaults()).expect("lays an arena out");
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
    assert_eq!(
        row(&dial, "pending queries").count,
        (1 + own) * caps::MAX_PENDING_QUERIES
    );
    assert_eq!(
        row(&listening, "pending queries").count,
        (1 + 3 + 2 + own) * caps::MAX_PENDING_QUERIES
    );
    assert_eq!(
        row(&listening, "subscribers"),
        row(&dial, "subscribers"),
        "the application's tables are held once"
    );
}

/// An arena past the address space is refused before any memory is asked.
#[test]
fn an_arena_past_the_address_space_is_refused() {
    let refused = ArenaPlan::of(
        &CoopConfig {
            listen: vec!["tcp/127.0.0.1:0".to_owned()],
            max_faces: usize::MAX,
            ..client_config()
        },
        &SessionLimits::defaults(),
    );
    assert_eq!(refused, Err(ArenaRefused::TooLarge));
}
