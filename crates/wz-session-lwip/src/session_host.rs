// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! How a node of the `session-slot` profile opens a session, dialled or accepted:
//! every table the session needs is claimed BEFORE the session can put a byte on
//! the wire, and a table that has no room is a typed, counted refusal that leaves
//! nothing taken (fixed-memory step S6, exhaustion cases R1 and R2).
//!
//! A session on this profile is four things, each in a table of fixed size the
//! image declared:
//!
//! 1. a socket (a cell of a `static` pool, for a session that dials; the
//!    listener's own, for one that is accepted);
//! 2. a slot of the session table, which holds the link driver, the entropy
//!    source and the bundle that drives the session;
//! 3. a cell of the pump table, which holds the engine and the record buffer;
//! 4. a cell of the runtime's task table, for the task that runs the pump.
//!
//! [`SessionHost::open`] claims 2, 3 and 4 in that order and gives back whatever it
//! had when one says no, so a refusal costs the node nothing but the count each
//! table keeps. The pump does not speak until the task that runs it first runs
//! (`PumpSlots::claim` defers the role's activation to the first step), so by the
//! time an `InitSyn` leaves a dialling session its task cell is already claimed: a
//! dial that is refused a task cell has sent nothing. An accepted session sends
//! nothing until it has read the `InitSyn` that asked for it, and the listener
//! leaves that datagram unread unless `open` said yes.
//!
//! The file is named for the host, not for the opening, because `session_open.rs`
//! of `wz-runtime-tokio` is cited by that name in the store's reasons, and a second
//! file of that name would make every one of those citations ambiguous.

use core::ops::Deref;

use wz_link_lwip::LwipLink;
use wz_runtime_coop::executor::SpawnRefusal;
use wz_runtime_coop::session_drive::{
    spawn_pump, LinkOpenError, PumpSlots, SessionDriveConfig, SessionSpawnRefused, UdpPeer,
};
use wz_runtime_coop::session_runtime::{new_session_in_slot, SessionHandle};
use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopRuntime, CoopTime};
use wz_session_core::driver_loop::{DriverOutcome, IterationEvent};
use wz_session_core::entropy::EntropySource;
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_slot::SessionSlots;

use crate::driver::LwipUdpDriver;
use crate::links::LwipLinks;
use crate::listener::{Admission, LaneGuard};
use crate::session_drive::LwipSessionLink;

/// Why a session could not be opened for want of room in a table. Each table keeps
/// its own count of the refusals it made (`SessionSlots::refused`,
/// `PumpSlots::refused`, `CoopRuntime::task_refusals`), so the refusal is
/// counted wherever it is made, and nothing the open took is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenRefused {
    /// Every slot of the session table is taken.
    SessionSlot,
    /// Every cell of the pump table is taken.
    PumpCell,
    /// The task table refused the task that would run the session.
    Task(SpawnRefusal),
}

/// Why a dial did not open a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialRefused {
    /// The stack has no socket to give (the pool the image declared is empty, or
    /// lwIP has no pcb or refuses the port): counted by the pool.
    Link(LinkOpenError),
    /// A table the session needs has no room.
    Open(OpenRefused),
}

/// A session that was opened: its handle, and the task that runs it.
pub struct OpenedSession<C: ClockSource + 'static> {
    /// The handle to the session in its slot. The session lives as long as any
    /// handle does, so dropping this one while the task runs ends nothing.
    pub actions: SessionHandle<C>,
    /// The task that runs the session's pump. Aborting it, or its ending, frees
    /// the pump's cell and, with the last handle, the session's slot.
    pub task: CoopLocalJoinHandle<DriverOutcome>,
}

/// The tables a node opens sessions in, and the means to run what it opens. All
/// are `static`s the image declared, or handles to them, so the host is a few
/// references and costs the heap nothing; it is built once.
pub struct SessionHost<C, L, E, const S: usize, const P: usize>
where
    C: ClockSource + 'static,
    L: Deref<Target = LwipLink> + Clone + 'static,
    E: EntropySource + Send + 'static,
{
    local: CoopLocalSet<C>,
    sessions: &'static SessionSlots<CoopRuntime<C>, CoopTime<C>, LwipUdpDriver, E, S>,
    pumps: &'static PumpSlots<C, LwipSessionLink<L>, P>,
    link: L,
}

impl<C, L, E, const S: usize, const P: usize> SessionHost<C, L, E, S, P>
where
    C: ClockSource + 'static,
    L: Deref<Target = LwipLink> + Clone + 'static,
    E: EntropySource + Send + 'static,
{
    /// A host over `sessions` and `pumps`, running tasks on `local` and pumping
    /// lwIP through `link`.
    pub fn new(
        local: CoopLocalSet<C>,
        sessions: &'static SessionSlots<CoopRuntime<C>, CoopTime<C>, LwipUdpDriver, E, S>,
        pumps: &'static PumpSlots<C, LwipSessionLink<L>, P>,
        link: L,
    ) -> Self {
        Self {
            local,
            sessions,
            pumps,
            link,
        }
    }

    /// Open a session over `driver`: claim a slot, a pump cell and a task cell, in
    /// that order, and run the session as a task. `lane` is the listener's lane for
    /// an accepted session and `None` for a dialled one.
    ///
    /// `on_event` is made from the session's own handle, after its slot is claimed
    /// and before its pump is, since an application layer is written against the
    /// handle of the session it serves.
    ///
    /// A refusal at any step returns what that step and the ones before it took:
    /// the driver, the entropy source, the lane and the handle are dropped, so the
    /// slot, the cell and the lane are free and the socket is back with whoever
    /// owns it. Nothing has been sent: a dialling pump has not activated, and an
    /// accepted one has not read its `InitSyn`.
    pub fn open<F>(
        &self,
        driver: LwipUdpDriver,
        lane: Option<LaneGuard>,
        entropy: E,
        params: SessionInitParams,
        config: SessionDriveConfig,
        on_event: impl FnOnce(&SessionHandle<C>) -> F,
    ) -> Result<OpenedSession<C>, OpenRefused>
    where
        F: FnMut(IterationEvent<'_>) + 'static,
    {
        let runtime = self.local.runtime();
        let Ok(claim) = self.sessions.claim(driver, entropy) else {
            return Err(OpenRefused::SessionSlot);
        };
        let driver = claim.driver_handle();
        let actions = new_session_in_slot(claim, params, CoopTime::new(runtime));
        let pump_link = match lane {
            Some(lane) => LwipSessionLink::with_lane(self.link.clone(), driver, lane),
            None => LwipSessionLink::new(self.link.clone(), driver),
        };
        let on_event = on_event(&actions);
        let Ok(pump) = self.pumps.claim(
            runtime.clone(),
            pump_link,
            actions.clone(),
            CoopTime::new(runtime),
            config,
        ) else {
            return Err(OpenRefused::PumpCell);
        };
        match spawn_pump(&self.local, pump, on_event) {
            Ok(task) => Ok(OpenedSession { actions, task }),
            Err(SessionSpawnRefused::Task(why)) => Err(OpenRefused::Task(why)),
            // `spawn_pump` is handed a pump that is already claimed, so the pump
            // table cannot be what refuses it.
            Err(SessionSpawnRefused::NoPumpCell) => Err(OpenRefused::PumpCell),
        }
    }

    /// Admit the session an [`Admission`] asks for, as an acceptor: what the
    /// listener's `accept_pass` closure calls.
    pub fn admit<F>(
        &self,
        admission: Admission,
        entropy: E,
        params: SessionInitParams,
        config: SessionDriveConfig,
        on_event: impl FnOnce(&SessionHandle<C>) -> F,
    ) -> Result<OpenedSession<C>, OpenRefused>
    where
        F: FnMut(IterationEvent<'_>) + 'static,
    {
        let Admission { driver, lane } = admission;
        self.open(driver, Some(lane), entropy, params, config, on_event)
    }

    /// Dial `peer`: bind a socket on a port the stack picks (out of the pool the
    /// image declared, so a full pool is [`DialRefused::Link`]), then open the
    /// session over it. The socket is bound before any table is claimed and is
    /// given back when one refuses; the `InitSyn` leaves only once the session's
    /// task first runs.
    pub fn dial<F>(
        &self,
        links: &LwipLinks<L>,
        peer: UdpPeer,
        entropy: E,
        params: SessionInitParams,
        config: SessionDriveConfig,
        on_event: impl FnOnce(&SessionHandle<C>) -> F,
    ) -> Result<OpenedSession<C>, DialRefused>
    where
        F: FnMut(IterationEvent<'_>) + 'static,
    {
        let driver = links.bind_driver(0, peer).map_err(DialRefused::Link)?;
        self.open(driver, None, entropy, params, config, on_event)
            .map_err(DialRefused::Open)
    }
}
