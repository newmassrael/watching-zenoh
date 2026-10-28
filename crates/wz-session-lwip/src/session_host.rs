// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! How a node of the `session-slot` profile opens a session on lwIP, dialled or accepted.
//!
//! The host itself, which claims a socket's driver slot, a pump cell and a task cell in that
//! order and refuses with a count and nothing taken when one has no room (fixed-memory step S6,
//! exhaustion cases R1 and R2), is written once for every stack in
//! [`wz_session_mcu::slot_host`]. This module is what lwIP adds to it: [`LwipStack`], which
//! names lwIP's driver and pump link for the host, and [`SessionHost`], the host with the two
//! ways a session reaches it that are lwIP's own, the listener's admission
//! ([`SessionHost::admit`]) and the socket pool ([`SessionHost::dial`]).
//!
//! The file is named for the host, not for the opening, because `session_open.rs` of
//! `wz-runtime-tokio` is cited by that name in the store's reasons, and a second file of that
//! name would make every one of those citations ambiguous.

use core::ops::Deref;

use wz_link_lwip::LwipLink;
use wz_runtime_coop::session_drive::{IpEndpoint, PumpSlots, SessionDriveConfig};
use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime};
use wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES;
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::entropy::EntropySource;
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_slot::SessionSlots;
use wz_session_mcu::slot_host::{SessionHost as StackHost, SlotStack};

pub use wz_session_mcu::slot_host::{DialRefused, OpenRefused, OpenedSession};

use crate::driver::{DriverHandle, LwipUdpDriver};
use crate::links::LwipLinks;
use crate::listener::{Admission, LaneGuard};
use crate::session_drive::LwipSessionLink;

/// lwIP as a stack of the session host: its UDP driver sits in the session slot, and the drive
/// loop pumps it through a [`LwipSessionLink`], which holds `L`, the handle to lwIP's input path.
pub struct LwipStack<L> {
    link: L,
}

impl<L> SlotStack for LwipStack<L>
where
    L: Deref<Target = LwipLink> + Clone + 'static,
{
    type Driver = LwipUdpDriver;
    type Pump = LwipSessionLink<L>;
    type Lane = LaneGuard;

    fn pump(&self, driver: DriverHandle, lane: Option<LaneGuard>) -> LwipSessionLink<L> {
        match lane {
            Some(lane) => LwipSessionLink::with_lane(self.link.clone(), driver, lane),
            None => LwipSessionLink::new(self.link.clone(), driver),
        }
    }
}

/// Where a dial goes and the node it is made for: the peer's address, and the zid of the node the
/// dial is for or `None` for a dial made to the address alone (decision D4 of
/// `docs/session-lifecycle-intent.md`). A session dialled for a node closes at an InitAck from
/// another zid, before any OpenSyn, as the stack-neutral host's
/// [`dial`](wz_session_mcu::slot_host::SessionHost::dial) installs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DialTarget {
    /// The peer's address.
    pub peer: IpEndpoint,
    /// The node the dial is made for.
    pub expected_zid: Option<[u8; CREDENTIAL_ZID_BYTES]>,
}

impl DialTarget {
    /// A dial to `peer` that names no node: a configured endpoint's.
    pub fn address(peer: IpEndpoint) -> Self {
        Self {
            peer,
            expected_zid: None,
        }
    }

    /// A dial to `peer` made for the node `zid` names.
    pub fn node(peer: IpEndpoint, zid: [u8; CREDENTIAL_ZID_BYTES]) -> Self {
        Self {
            peer,
            expected_zid: Some(zid),
        }
    }
}

/// The tables a node opens sessions in, and the means to run what it opens, over lwIP. All are
/// `static`s the image declared, or handles to them, so the host is a few references and costs
/// the heap nothing; it is built once. `open` and the rest of the stack-neutral host are
/// reached through `Deref`.
pub struct SessionHost<C, L, E, const S: usize, const P: usize>
where
    C: ClockSource + 'static,
    L: Deref<Target = LwipLink> + Clone + 'static,
    E: EntropySource + Send + 'static,
{
    host: StackHost<C, LwipStack<L>, E, S, P>,
}

impl<C, L, E, const S: usize, const P: usize> Deref for SessionHost<C, L, E, S, P>
where
    C: ClockSource + 'static,
    L: Deref<Target = LwipLink> + Clone + 'static,
    E: EntropySource + Send + 'static,
{
    type Target = StackHost<C, LwipStack<L>, E, S, P>;

    fn deref(&self) -> &Self::Target {
        &self.host
    }
}

impl<C, L, E, const S: usize, const P: usize> SessionHost<C, L, E, S, P>
where
    C: ClockSource + 'static,
    L: Deref<Target = LwipLink> + Clone + 'static,
    E: EntropySource + Send + 'static,
{
    /// A host over `sessions` and `pumps`, running tasks on `local` and pumping lwIP through
    /// `link`.
    pub fn new(
        local: CoopLocalSet<C>,
        sessions: &'static SessionSlots<
            CoopRuntime<C, LwipUdpDriver>,
            CoopTime<C>,
            LwipUdpDriver,
            E,
            S,
        >,
        pumps: &'static PumpSlots<C, LwipSessionLink<L>, P, LwipUdpDriver>,
        link: L,
    ) -> Self {
        Self {
            host: StackHost::new(local, sessions, pumps, LwipStack { link }),
        }
    }

    /// Admit the session an [`Admission`] asks for, as an acceptor: what the listener's
    /// `accept_pass` closure calls.
    pub fn admit<F>(
        &self,
        admission: Admission,
        entropy: E,
        params: SessionInitParams,
        config: SessionDriveConfig,
        on_event: impl FnOnce(&SessionHandle<C, LwipUdpDriver>) -> F,
    ) -> Result<OpenedSession<C, LwipUdpDriver>, OpenRefused>
    where
        F: FnMut(IterationEvent<'_>) + 'static,
    {
        let Admission { driver, lane } = admission;
        self.host
            .open(driver, Some(lane), entropy, params, config, on_event)
    }

    /// Dial `target`'s peer over UDP: bind a socket on a port the stack picks (out of the pool
    /// the image declared, so a full pool is [`DialRefused::Link`]), then open the session over
    /// it. The socket is bound before any table is claimed and is given back when one refuses;
    /// the `InitSyn` leaves only once the session's task first runs.
    pub fn dial<F>(
        &self,
        links: &LwipLinks<L>,
        target: DialTarget,
        entropy: E,
        params: SessionInitParams,
        config: SessionDriveConfig,
        on_event: impl FnOnce(&SessionHandle<C, LwipUdpDriver>) -> F,
    ) -> Result<OpenedSession<C, LwipUdpDriver>, DialRefused>
    where
        F: FnMut(IterationEvent<'_>) + 'static,
    {
        let DialTarget { peer, expected_zid } = target;
        self.host.dial(
            || links.bind_driver(0, peer),
            expected_zid,
            entropy,
            params,
            config,
            on_event,
        )
    }
}
