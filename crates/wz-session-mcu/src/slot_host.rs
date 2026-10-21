// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! How a node of the `session-slot` profile opens a session, dialled or accepted, written
//! ONCE for every network stack: every table the session needs is claimed BEFORE the session
//! can put a byte on the wire, and a table that has no room is a typed, counted refusal that
//! leaves nothing taken (fixed-memory step S6, exhaustion cases R1 and R2).
//!
//! A session on this profile is four things, each in a table of fixed size the image declared:
//!
//! 1. a socket (a cell of a `static` pool, for a session that dials; the listener's own, for
//!    one that is accepted);
//! 2. a slot of the session table, which holds the link driver, the entropy source and the
//!    bundle that drives the session;
//! 3. a cell of the pump table, which holds the engine and the record buffer;
//! 4. a cell of the runtime's task table, for the task that runs the pump.
//!
//! [`SessionHost::open`] claims 2, 3 and 4 in that order and gives back whatever it had when
//! one says no, so a refusal costs the node nothing but the count each table keeps. The pump
//! does not speak until the task that runs it first runs (`PumpSlots::claim` defers the role's
//! activation to the first step), so by the time an `InitSyn` leaves a dialling session its
//! task cell is already claimed: a dial that is refused a task cell has sent nothing. An
//! accepted session sends nothing until it has read the `InitSyn` that asked for it, and the
//! listener leaves that datagram unread unless `open` said yes.
//!
//! # What a stack supplies
//!
//! The host was written for lwIP first and named its driver, its pump link and its socket pool.
//! None of that is the host's business: a stack supplies a [`SlotStack`], which says what the
//! driver in the slot is, what the drive loop pumps for it, and how the pump is built from the
//! handle to the slot that holds the driver. The lwIP crate and the Zephyr socket tier each
//! implement it in a few lines and keep their own socket pools, listeners and names
//! (`docs/storage-policy-and-link-layer.md`, D2).

use wz_runtime_coop::executor::SpawnRefusal;
use wz_runtime_coop::session_drive::{
    spawn_pump, LinkOpenError, PumpSlots, SessionDatagramLink, SessionDriveConfig,
    SessionSpawnRefused,
};
use wz_runtime_coop::session_runtime::{new_session_in_slot, SessionHandle};
use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopRuntime, CoopTime};
use wz_session_core::driver_loop::{DriverOutcome, IterationEvent};
use wz_session_core::entropy::EntropySource;
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_slot::{SessionSlots, SlotDriver};

/// What a network stack gives the session host: the types of its link, and how the pump is built.
pub trait SlotStack: 'static {
    /// The link driver a session holds in its slot: the outbound half the session's actions
    /// send through, and (usually) the datagram queue the pump reads.
    type Driver: BoxedLinkDriver + 'static;
    /// What the drive loop pumps for a session: it services the stack and takes the next
    /// datagram from the driver, which it reaches through a handle to the slot that holds it.
    type Pump: SessionDatagramLink + 'static;
    /// What an accepted session carries beyond a dialled one, held for as long as it runs and
    /// given back when it ends: the listener's lane. A stack with no listener names `()`.
    type Lane;

    /// The pump for the session whose driver `driver` is the handle to; `lane` is the listener's
    /// lane for an accepted session and `None` for a dialled one.
    fn pump(&self, driver: SlotDriver<Self::Driver>, lane: Option<Self::Lane>) -> Self::Pump;
}

/// Why a session could not be opened for want of room in a table. Each table keeps its own
/// count of the refusals it made (`SessionSlots::refused`, `PumpSlots::refused`,
/// `CoopRuntime::task_refusals`), so the refusal is counted wherever it is made, and nothing
/// the open took is kept.
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
    /// The stack has no socket to give (the pool the image declared is empty, or the stack has
    /// no control block or refuses the port): counted by the pool.
    Link(LinkOpenError),
    /// A table the session needs has no room.
    Open(OpenRefused),
}

/// A session that was opened: its handle, and the task that runs it.
pub struct OpenedSession<C: ClockSource + 'static> {
    /// The handle to the session in its slot. The session lives as long as any handle does, so
    /// dropping this one while the task runs ends nothing.
    pub actions: SessionHandle<C>,
    /// The task that runs the session's pump. Aborting it, or its ending, frees the pump's cell
    /// and, with the last handle, the session's slot.
    pub task: CoopLocalJoinHandle<DriverOutcome>,
}

/// The tables a node opens sessions in, and the means to run what it opens. All are `static`s
/// the image declared, or handles to them, so the host is a few references and costs the heap
/// nothing; it is built once.
pub struct SessionHost<C, T, E, const S: usize, const P: usize>
where
    C: ClockSource + 'static,
    T: SlotStack,
    E: EntropySource + Send + 'static,
{
    local: CoopLocalSet<C>,
    sessions: &'static SessionSlots<CoopRuntime<C>, CoopTime<C>, T::Driver, E, S>,
    pumps: &'static PumpSlots<C, T::Pump, P>,
    stack: T,
}

impl<C, T, E, const S: usize, const P: usize> SessionHost<C, T, E, S, P>
where
    C: ClockSource + 'static,
    T: SlotStack,
    E: EntropySource + Send + 'static,
{
    /// A host over `sessions` and `pumps`, running tasks on `local` and building pumps through
    /// `stack`.
    pub fn new(
        local: CoopLocalSet<C>,
        sessions: &'static SessionSlots<CoopRuntime<C>, CoopTime<C>, T::Driver, E, S>,
        pumps: &'static PumpSlots<C, T::Pump, P>,
        stack: T,
    ) -> Self {
        Self {
            local,
            sessions,
            pumps,
            stack,
        }
    }

    /// The stack the host builds its pumps through.
    pub fn stack(&self) -> &T {
        &self.stack
    }

    /// Open a session over `driver`: claim a slot, a pump cell and a task cell, in that order,
    /// and run the session as a task. `lane` is the listener's lane for an accepted session and
    /// `None` for a dialled one.
    ///
    /// `on_event` is made from the session's own handle, after its slot is claimed and before its
    /// pump is, since an application layer is written against the handle of the session it
    /// serves.
    ///
    /// A refusal at any step returns what that step and the ones before it took: the driver, the
    /// entropy source, the lane and the handle are dropped, so the slot, the cell and the lane
    /// are free and the socket is back with whoever owns it. Nothing has been sent: a dialling
    /// pump has not activated, and an accepted one has not read its `InitSyn`.
    pub fn open<F>(
        &self,
        driver: T::Driver,
        lane: Option<T::Lane>,
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
        let pump_link = self.stack.pump(driver, lane);
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
            // `spawn_pump` is handed a pump that is already claimed, so the pump table cannot be
            // what refuses it.
            Err(SessionSpawnRefused::NoPumpCell) => Err(OpenRefused::PumpCell),
        }
    }

    /// Dial: `bind` opens the socket of the link (a cell of the pool the image declared, a port
    /// the stack picks), then the session is opened over it. The socket is bound before any
    /// table is claimed and is given back when one refuses; the `InitSyn` leaves only once the
    /// session's task first runs. A pool with no socket is [`DialRefused::Link`].
    pub fn dial<F>(
        &self,
        bind: impl FnOnce() -> Result<T::Driver, LinkOpenError>,
        entropy: E,
        params: SessionInitParams,
        config: SessionDriveConfig,
        on_event: impl FnOnce(&SessionHandle<C>) -> F,
    ) -> Result<OpenedSession<C>, DialRefused>
    where
        F: FnMut(IterationEvent<'_>) + 'static,
    {
        let driver = bind().map_err(DialRefused::Link)?;
        self.open(driver, None, entropy, params, config, on_event)
            .map_err(DialRefused::Open)
    }
}
