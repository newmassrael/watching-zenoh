// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The lwIP side of the multicast group session.
//!
//! The drive loop, its pump, the reply queue and the slot table are
//! `wz_session_mcu::group_drive`, written once for every network stack and
//! generic over [`GroupTransport`]. This module is lwIP's half of that seam:
//! [`LwipGroupTransport`] implements the trait (pump lwIP's input path, read the
//! carrier, multicast through a [`LwipMulticastDriver`], take a datagram from it
//! with its source), and the functions below keep the lwIP-typed signatures every
//! existing caller writes, building the transport and handing it to the shared
//! loop, as `session_drive` does for the unicast one.

use core::borrow::BorrowMut;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::ops::Deref;

use wz_link_lwip::rx_sockets::{SessionMulticastRxSocket, SESSION_MULTICAST_RX_SLOT_SIZE};
use wz_link_lwip::{Datagram, LwipLink};
use wz_runtime_coop::{ClockSource, CoopRuntime};
#[cfg(not(feature = "session-slot"))]
use wz_runtime_coop::{CoopLocalJoinHandle, CoopLocalSet};
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::multicast_dispatch::{MulticastConfig, MulticastDispatcher};
use wz_session_core::multicast_params::{MulticastDriveConfig, MulticastOutcome, MulticastParams};
use wz_session_core::multicast_tx::MulticastTxOffer;
use wz_session_mcu::group_drive as group;
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
pub use wz_session_mcu::group_drive::MulticastReplyQueue;
#[cfg(feature = "session-slot")]
pub use wz_session_mcu::group_drive::{
    multicast_pump_task, spawn_multicast_pump, MulticastSpawnRefused,
};
pub use wz_session_mcu::group_drive::{GroupTransport, MulticastPump};

/// The MCU multicast I/O seam: a [`SessionMulticastRxSocket`] (joined to the
/// group at bind) plus the group `(addr, port)` the loop multicasts to. The
/// multicast mirror of [`crate::driver::LwipUdpDriver`] (which carries the
/// retargetable unicast peer): here the destination is the fixed group, so the
/// loop owns the socket exclusively (no `Rc<RefCell>` — single-task, one
/// consumer) and `send_to_group` / `try_recv` are direct `&mut` calls.
pub struct LwipMulticastDriver {
    socket: SessionMulticastRxSocket,
    group: u32,
    port: u16,
}

impl LwipMulticastDriver {
    /// Wrap a bound multicast socket with its group destination. `group` /
    /// `port` are the locator the JOIN beacon + data frames multicast to —
    /// the same `(group, port)` passed to
    /// `wz_link_lwip::rx_sockets::bind_session_multicast_rx` (or its `_in` form
    /// under `static-link-storage`) so TX and the joined RX membership match.
    pub fn new(socket: SessionMulticastRxSocket, group: u32, port: u16) -> Self {
        Self {
            socket,
            group,
            port,
        }
    }

    /// Multicast one datagram to the group. Best-effort like the AP loop's
    /// JOIN / data emit (a failed send is non-fatal — the next cadence
    /// retries); the `LinkError` is dropped.
    pub fn send_to_group(&mut self, bytes: &[u8]) {
        let _ = self.socket.send_to(self.group, self.port, bytes);
    }

    /// Non-blocking dequeue of one inbound multicast datagram (the caller must
    /// have driven the lwIP input path via `LwipLink::poll_loopback` / netif RX
    /// first). Carries the datagram's source address for §3.2 peer
    /// attribution.
    pub fn try_recv(&mut self) -> Option<Datagram<SESSION_MULTICAST_RX_SLOT_SIZE>> {
        self.socket.try_recv()
    }
}

/// The §3.2 peer key for an inbound multicast datagram: its source address.
/// Frame / KeepAlive / Close carry no zid on the wire, so — exactly like
/// zenoh-pico `_z_find_peer_entry(addr)` — every inbound message is attributed
/// by `(src_addr, src_port)`. The `src_addr` is lwIP's network-order `u32`;
/// the exact dotted-quad interpretation is irrelevant here because the
/// [`SocketAddr`] is used only as an opaque equality key (a given peer's
/// datagrams always carry the same `src_addr`).
fn peer_key(src_addr: u32, src_port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(src_addr)), src_port)
}

/// The lwIP implementation of [`GroupTransport`]: the stack's link, whose input
/// path and timers are pumped and whose carrier is read, and the
/// [`LwipMulticastDriver`] that multicasts and receives.
///
/// Both halves are held by whatever the call site has: the synchronous entry points
/// below borrow them off the caller's stack (`&LwipLink`, `&mut LwipMulticastDriver`),
/// while a spawned session must be `'static` and owns the driver outright and
/// shares the link (`Rc<LwipLink>`, or a `&'static LwipLink` on the slot profile).
/// A `Deref<Target = LwipLink>` bound on the link and a `BorrowMut` on the driver
/// admit all of them at no runtime cost, as `LwipSessionLink` does for the unicast
/// loop. A transport that OWNS its driver gives the group socket back (its PCB
/// returns to the pool) when the session releases its link, which the rejoining
/// entry point relies on before it binds the same port again.
pub struct LwipGroupTransport<L: Deref<Target = LwipLink>, D: BorrowMut<LwipMulticastDriver>> {
    link: L,
    /// `None` once the session has released its link.
    driver: Option<D>,
}

impl<L: Deref<Target = LwipLink>, D: BorrowMut<LwipMulticastDriver>> LwipGroupTransport<L, D> {
    /// Pair the lwIP link whose input path is pumped with the driver whose
    /// socket carries the group.
    pub fn new(link: L, driver: D) -> Self {
        Self {
            link,
            driver: Some(driver),
        }
    }
}

impl<L: Deref<Target = LwipLink>, D: BorrowMut<LwipMulticastDriver>> GroupTransport
    for LwipGroupTransport<L, D>
{
    fn open(&mut self) -> bool {
        self.driver.is_some()
    }

    fn close(&mut self) {
        self.driver = None;
    }

    fn service(&self) {
        // Drive the lwIP input path (loopback / QEMU shape). Real-NIC deploys
        // drive netif input from the RX ISR instead of poll_loopback.
        self.link.poll_loopback();
        self.link.check_timeouts();
    }

    fn carrier_up(&self) -> bool {
        self.link.any_link_is_up()
    }

    fn send_to_group(&mut self, datagram: &[u8]) {
        if let Some(driver) = &mut self.driver {
            driver.borrow_mut().send_to_group(datagram);
        }
    }

    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
        let Some(driver) = &mut self.driver else {
            return false;
        };
        match driver.borrow_mut().try_recv() {
            Some(dg) => {
                f(dg.data.as_slice(), peer_key(dg.src_addr, dg.src_port));
                true
            }
            None => false,
        }
    }
}

/// Drive a multicast session over the lwIP link —
/// `wz_session_mcu::group_drive::run_multicast_session` over a
/// [`LwipGroupTransport`] of `link` and `driver`.
///
/// - `runtime` / `link` — the cooperative runtime and the lwIP link pumped each tick
///   (`run_until_idle` + `poll_loopback` + `check_timeouts`), the loopback /
///   QEMU shape (a real-NIC deploy drives netif input from the RX ISR instead).
/// - `driver` — the [`LwipMulticastDriver`] (group socket: JOIN/data TX +
///   inbound `try_recv`).
///
/// The other parameters are the shared loop's.
pub fn run_multicast_session<'g, C, F, G, const MAX_PEERS: usize>(
    dispatcher: &mut MulticastDispatcher<MAX_PEERS>,
    cfg: MulticastDriveConfig<'_>,
    runtime: &CoopRuntime<C>,
    link: &LwipLink,
    driver: &mut LwipMulticastDriver,
    on_event: F,
    next_tx: G,
) -> MulticastOutcome
where
    C: ClockSource,
    F: FnMut(IterationEvent<'_>),
    G: FnMut() -> Option<MulticastTxOffer<'g>>,
{
    group::run_multicast_session(
        dispatcher,
        cfg,
        runtime,
        &mut LwipGroupTransport::new(link, driver),
        on_event,
        next_tx,
    )
}

/// R2375 — [`run_multicast_session`] plus the GRACEFUL STOP signal; the shared
/// loop's `run_multicast_session_with_shutdown` over a [`LwipGroupTransport`].
#[allow(clippy::too_many_arguments)]
pub fn run_multicast_session_with_shutdown<'g, C, F, G, H, const MAX_PEERS: usize>(
    dispatcher: &mut MulticastDispatcher<MAX_PEERS>,
    cfg: MulticastDriveConfig<'_>,
    runtime: &CoopRuntime<C>,
    link: &LwipLink,
    driver: &mut LwipMulticastDriver,
    on_event: F,
    next_tx: G,
    should_stop: H,
) -> MulticastOutcome
where
    C: ClockSource,
    F: FnMut(IterationEvent<'_>),
    G: FnMut() -> Option<MulticastTxOffer<'g>>,
    H: FnMut() -> bool,
{
    group::run_multicast_session_with_shutdown(
        dispatcher,
        cfg,
        runtime,
        &mut LwipGroupTransport::new(link, driver),
        on_event,
        next_tx,
        should_stop,
    )
}

/// R2561 — [`run_multicast_session_with_shutdown`] that RE-JOINS the group after a
/// lost carrier; the shared loop's `run_multicast_session_rejoining` over a
/// [`LwipGroupTransport`] that OWNS `driver`, so the group socket is released
/// before `rebind` asks for it again (lwIP refuses a second bind to a live port;
/// the reasoning is on the shared function). `rebind` answers a fresh driver, or
/// `None` to give up.
#[allow(clippy::too_many_arguments)]
pub fn run_multicast_session_rejoining<'g, C, F, G, H, B, D, const MAX_PEERS: usize>(
    new_dispatcher: D,
    cfg: MulticastDriveConfig<'_>,
    runtime: &CoopRuntime<C>,
    link: &LwipLink,
    driver: LwipMulticastDriver,
    on_event: F,
    next_tx: G,
    should_stop: H,
    mut rebind: B,
    rejoin_delay_ms: u64,
) -> MulticastOutcome
where
    C: ClockSource,
    F: FnMut(IterationEvent<'_>),
    G: FnMut() -> Option<MulticastTxOffer<'g>>,
    H: FnMut() -> bool,
    B: FnMut() -> Option<LwipMulticastDriver>,
    D: FnMut() -> MulticastDispatcher<MAX_PEERS>,
{
    group::run_multicast_session_rejoining(
        new_dispatcher,
        cfg,
        runtime,
        LwipGroupTransport::new(link, driver),
        on_event,
        next_tx,
        should_stop,
        || rebind().map(|fresh| LwipGroupTransport::new(link, fresh)),
        rejoin_delay_ms,
    )
}

/// What a multicast session OWNS when it runs as a task: everything
/// [`run_multicast_session_with_shutdown`] borrows from its caller's stack,
/// which a detached task cannot do.
///
/// Open-debt item 900. The heap profiles hold this in the task's future, so its
/// memory comes from the image heap and is NOT a per-session budget: the
/// per-session shape that later fixed-memory work keeps is the session's own
/// static pools (the group socket's RX ring is one), not an allocator split.
///
/// The shared session (`wz_session_mcu::group_drive::MulticastSession`) holds the
/// whole transport; this one holds lwIP's driver and is paired with its link when
/// it is run ([`Self::into_group`]), which is how every caller has written it.
pub struct MulticastSession<const MAX_PEERS: usize> {
    /// The §3.1 session FSM and the §3.2 peer table.
    pub dispatcher: MulticastDispatcher<MAX_PEERS>,
    /// The group socket, joined at bind.
    pub driver: LwipMulticastDriver,
    /// The protocol parameters this session advertises, its own zid among them.
    pub params: MulticastParams,
    /// The sweep cadence (see [`MulticastDriveConfig::tick_ms`]).
    pub tick_ms: u64,
    /// The test budget (see [`MulticastDriveConfig::max_iters`]); `None` in
    /// production.
    pub max_iters: Option<usize>,
}

impl<const MAX_PEERS: usize> MulticastSession<MAX_PEERS> {
    /// The shared session over `link`: the same dispatcher, parameters and
    /// cadences, with the driver paired to the lwIP link it is pumped through.
    pub fn into_group<L: Deref<Target = LwipLink>>(
        self,
        link: L,
    ) -> group::MulticastSession<LwipGroupTransport<L, LwipMulticastDriver>, MAX_PEERS> {
        let Self {
            dispatcher,
            driver,
            params,
            tick_ms,
            max_iters,
        } = self;
        group::MulticastSession {
            dispatcher,
            transport: LwipGroupTransport::new(link, driver),
            params,
            tick_ms,
            max_iters,
        }
    }
}

/// The MCU multicast session AS A TASK — the `!Send` future a
/// `CoopLocalSet` hosts beside other sessions: the shared
/// `multicast_session_task` over a [`LwipGroupTransport`] of `link` and the
/// session's driver. `should_stop` is the graceful-stop predicate the synchronous
/// entry takes; pass `|| false` for a session that runs until its link is lost.
pub async fn multicast_session_task<'g, C, L, F, G, H, const MAX_PEERS: usize>(
    runtime: CoopRuntime<C>,
    link: L,
    session: MulticastSession<MAX_PEERS>,
    on_event: F,
    next_tx: G,
    should_stop: H,
) -> MulticastOutcome
where
    C: ClockSource,
    L: Deref<Target = LwipLink>,
    F: FnMut(IterationEvent<'_>),
    G: FnMut() -> Option<MulticastTxOffer<'g>>,
    H: FnMut() -> bool,
{
    group::multicast_session_task(
        runtime,
        session.into_group(link),
        on_event,
        next_tx,
        should_stop,
    )
    .await
}

/// Spawn one MCU multicast session onto `local` and return its join handle —
/// [`multicast_session_task`] on the local set's own runtime, so the session
/// cannot ride a different runtime from the one the set pumps. The multicast
/// twin of `spawn_session` (absent under `session-slot`).
///
/// Absent under `session-slot`: it builds the session inside the task's future,
/// where a task cell of the runtime's fixed size cannot hold a peer table and a
/// reassembly router. The slot profile's form is a cell of `MulticastSlots` and
/// `spawn_multicast_pump`.
#[cfg(not(feature = "session-slot"))]
pub fn spawn_multicast_session<C, L, F, G, H, const MAX_PEERS: usize>(
    local: &CoopLocalSet<C>,
    link: L,
    session: MulticastSession<MAX_PEERS>,
    on_event: F,
    next_tx: G,
    should_stop: H,
) -> CoopLocalJoinHandle<MulticastOutcome>
where
    C: ClockSource + 'static,
    L: Deref<Target = LwipLink> + 'static,
    F: FnMut(IterationEvent<'_>) + 'static,
    G: FnMut() -> Option<MulticastTxOffer<'static>> + 'static,
    H: FnMut() -> bool + 'static,
{
    group::spawn_multicast_session(
        local,
        session.into_group(link),
        on_event,
        next_tx,
        should_stop,
    )
}

/// A multicast session before its dispatcher exists: [`MulticastSession`] without the dispatcher,
/// which `spawn_multicast_session_seeded` (a build without `session-slot` has it) builds where
/// the task keeps it. A caller that spawns
/// the session beside others uses this one to keep the dispatcher (7.7 KB at four peers) off its
/// own stack, where [`MulticastSession`] makes it hold two.
pub struct MulticastSeed<const MAX_PEERS: usize> {
    config: MulticastConfig,
    driver: LwipMulticastDriver,
    params: MulticastParams,
    tick_ms: u64,
    max_iters: Option<usize>,
}

impl<const MAX_PEERS: usize> MulticastSeed<MAX_PEERS> {
    /// A seed over `driver`, with no test budget; the fields of [`MulticastSession`] of the same
    /// names mean the same here, and `config` is what the dispatcher is built over.
    pub fn new(
        config: MulticastConfig,
        driver: LwipMulticastDriver,
        params: MulticastParams,
        tick_ms: u64,
    ) -> Self {
        Self {
            config,
            driver,
            params,
            tick_ms,
            max_iters: None,
        }
    }

    /// The test budget (see [`MulticastDriveConfig::max_iters`]); `None` in production.
    pub fn with_max_iters(mut self, max_iters: Option<usize>) -> Self {
        self.max_iters = max_iters;
        self
    }

    /// The shared seed over `link`, the driver paired to the lwIP link it is pumped through.
    pub fn into_group<L: Deref<Target = LwipLink>>(
        self,
        link: L,
    ) -> group::MulticastSessionSeed<LwipGroupTransport<L, LwipMulticastDriver>, MAX_PEERS> {
        group::MulticastSessionSeed::new(
            self.config,
            LwipGroupTransport::new(link, self.driver),
            self.params,
            self.tick_ms,
        )
        .with_max_iters(self.max_iters)
    }
}

/// [`spawn_multicast_session`] from a [`MulticastSeed`]: the same task, with the dispatcher built
/// in the task and not on the caller's stack (absent under `session-slot`, as that one is).
#[cfg(not(feature = "session-slot"))]
pub fn spawn_multicast_session_seeded<C, L, F, G, H, const MAX_PEERS: usize>(
    local: &CoopLocalSet<C>,
    link: L,
    seed: MulticastSeed<MAX_PEERS>,
    on_event: F,
    next_tx: G,
    should_stop: H,
) -> CoopLocalJoinHandle<MulticastOutcome>
where
    C: ClockSource + 'static,
    L: Deref<Target = LwipLink> + 'static,
    F: FnMut(IterationEvent<'_>) + 'static,
    G: FnMut() -> Option<MulticastTxOffer<'static>> + 'static,
    H: FnMut() -> bool + 'static,
{
    group::spawn_multicast_session_seeded(
        local,
        seed.into_group(link),
        on_event,
        next_tx,
        should_stop,
    )
}

// ─────────── the multicast pump in a cell of a table the image declares ───────────
//
// Fixed-memory step S9c. The table, its cells, the handle to a claimed cell and the
// task that drives it are `wz_session_mcu::group_drive`'s, generic over the
// transport; what an lwIP image names is below, with the signatures it has always
// written: `claim` takes the link and a session that holds the driver.

/// The transport of an lwIP image on the slot profile: the image's own
/// `&'static LwipLink` and a group driver the session owns.
#[cfg(feature = "session-slot")]
pub type SlotGroupTransport = LwipGroupTransport<&'static LwipLink, LwipMulticastDriver>;

/// The exclusive handle to a multicast pump in its cell of a [`MulticastSlots`]
/// table. Dropping it drops the pump, then the runtime handle and the session, and
/// frees the cell. The task that drives a pump ([`multicast_pump_task`]) owns it.
#[cfg(feature = "session-slot")]
pub type MulticastRef<C, const MAX_PEERS: usize> =
    group::MulticastRef<C, SlotGroupTransport, MAX_PEERS>;

/// The multicast table an lwIP image declares: `N` cells, each holding one multicast
/// session and its pump, in a `static`. The counterpart of [`crate::PumpSlots`],
/// declared the same way:
///
/// ```text
/// static GROUPS: MulticastSlots<BoardClock, 4, 1> = MulticastSlots::new();
/// let pump = GROUPS.claim(runtime.clone(), link, session)?;
/// spawn_multicast_pump(&local, pump, on_event, || REPLIES.pop(), || false)?;
/// ```
///
/// The table is `wz_session_mcu::group_drive::MulticastSlots` over
/// [`SlotGroupTransport`]; this wrapper keeps the call that takes the link and an
/// lwIP session, and the rest is the shared table's.
#[cfg(feature = "session-slot")]
pub struct MulticastSlots<C: ClockSource + 'static, const MAX_PEERS: usize, const N: usize>(
    group::MulticastSlots<C, SlotGroupTransport, MAX_PEERS, N>,
);

#[cfg(feature = "session-slot")]
impl<C: ClockSource + 'static, const MAX_PEERS: usize, const N: usize>
    MulticastSlots<C, MAX_PEERS, N>
{
    /// A table of free cells.
    pub const fn new() -> Self {
        Self(group::MulticastSlots::new())
    }

    /// How many cells the table has.
    pub const fn capacity(&self) -> usize {
        self.0.capacity()
    }

    /// How many cells hold a session.
    pub fn in_use(&self) -> usize {
        self.0.in_use()
    }

    /// How many claims were refused for want of a free cell.
    pub fn refused(&self) -> u32 {
        self.0.refused()
    }

    /// The bytes this table takes in the image's `.bss`, with each cell's session and
    /// pump (and, with `reassembly`, the router's staging).
    pub const fn size_bytes() -> usize {
        core::mem::size_of::<Self>()
    }

    /// Put `session` and its pump in a free cell: the dispatcher comes up (Idle to
    /// Running) and the JOIN and sweep cadences are armed, as
    /// [`MulticastPump::new`] does. Nothing of that is done when no cell is free: the
    /// session offered is dropped (its socket goes back to its pool) and the refusal
    /// is counted.
    pub fn claim(
        &'static self,
        runtime: CoopRuntime<C>,
        link: &'static LwipLink,
        session: MulticastSession<MAX_PEERS>,
    ) -> Result<MulticastRef<C, MAX_PEERS>, MulticastSpawnRefused> {
        self.0.claim(runtime, session.into_group(link))
    }
}

#[cfg(feature = "session-slot")]
impl<C: ClockSource + 'static, const MAX_PEERS: usize, const N: usize> Default
    for MulticastSlots<C, MAX_PEERS, N>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, not(feature = "session-slot")))]
mod tests {
    use super::*;
    // What the loop and its pump used to bring into this module's scope: they are
    // `wz_session_mcu::group_drive`'s now, and the tests name what they build with.
    use alloc::rc::Rc;
    use wz_link_lwip::lwip_test_link;
    use wz_link_lwip::rx_sockets::SESSION_MULTICAST_GROUP_DEFAULT;
    use wz_runtime_coop::yield_now;
    use wz_session_core::link::LostCause;
    #[cfg(all(
        feature = "alloc",
        any(
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "liveliness-token"
        )
    ))]
    use wz_session_core::multicast_tx::MulticastTxItem;
    use wz_session_core::session_fsm_multicast::SessionFsmMulticastState;
    use wz_session_core::sn::{self, MulticastTxConduits};
    // Round 3277 -- the binder of `test_bind`: one body on both profiles.
    use wz_link_lwip::test_bind::session_multicast_rx as bind_session_multicast_rx;
    use wz_session_core::multicast_dispatch::MulticastConfig;
    use wz_session_core::multicast_join::encode_join;
    use wz_session_core::multicast_params::{zid_vec, MulticastParams};
    #[cfg(all(feature = "transport-fragmentation", feature = "codec-push"))]
    use wz_session_core::multicast_tx::multicast_tx_emit;
    use wz_session_core::WhatAmI;

    /// Frozen host clock — `now_us` is constant, so no JOIN-interval / lease
    /// deadline ever advances past a peer's admit time. Keeps the drive-loop
    /// integration test deterministic (terminates on max_iters; the admitted
    /// peer is never swept), the same shape as session_drive's `FrozenClock`.
    #[derive(Clone, Default)]
    struct FrozenClock;
    impl ClockSource for FrozenClock {
        fn now_us(&self) -> u64 {
            0
        }
    }

    /// A multicast params fixture (the AP multicast_glue test's shape): a peer
    /// JOIN built with one `zid` is admitted by a loop running another.
    fn params(zid: &[u8]) -> MulticastParams {
        MulticastParams {
            whatami: WhatAmI::Peer,
            zid: zid_vec(zid),
            lease_ms: 5_000,
            join_interval_ms: 1,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size: 2_048,
            is_qos: false,
            tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
            link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
        }
    }

    /// The §3.2 peer key is a stable, collision-free function of the datagram
    /// source: equal `(src_addr, src_port)` -> equal key (so a peer's
    /// successive datagrams attribute to one entry); a differing addr OR port
    /// -> a distinct key (so two peers never alias). lwIP-free (pure
    /// arithmetic), so it runs without the init-once link harness.
    #[test]
    fn peer_key_is_a_stable_collision_free_source_key() {
        let a = peer_key(0x7F00_0001, 7446);
        std::assert_eq!(a, peer_key(0x7F00_0001, 7446), "same source -> same key");
        std::assert_ne!(a, peer_key(0x7F00_0002, 7446), "differing addr -> distinct");
        std::assert_ne!(a, peer_key(0x7F00_0001, 7447), "differing port -> distinct");
    }

    /// R311lu — the drive loop end-to-end over a real lwIP multicast socket: a
    /// peer's JOIN (a zid distinct from ours), injected onto the group, is
    /// delivered by `poll_loopback` to the loop's `try_recv`, classified as
    /// `T_MID_JOIN`, validated, and admitted into the dispatcher's peer table —
    /// while our own JOIN beacon echoes back and is own-zid-filtered. Shares
    /// the `lwip_test_link` init-once harness with `session_drive`'s test (one
    /// `lwip_init` per binary). A distinct port (7449) from the scout (7446) /
    /// unicast (7447) / link-tier multicast (7448) tests; the harness mutex
    /// serialises the lwIP group membership.
    #[test]
    fn run_multicast_session_admits_a_peer_over_loopback() {
        let (_serial, link) = lwip_test_link();
        let group = SESSION_MULTICAST_GROUP_DEFAULT;
        let port: u16 = 7449;
        let socket = bind_session_multicast_rx(&link, group, port).expect("bind + join group");

        // Inject a PEER's JOIN (distinct zid) onto the group BEFORE wrapping
        // the socket in the driver — it queues in lwIP, and the loop's first
        // poll_loopback delivers it to try_recv ahead of our own beacon echo.
        let peer = params(&[0x01, 0x02, 0x03, 0x04]);
        let peer_join = encode_join(
            &peer,
            &MulticastTxConduits::new(sn::mask_from_res(peer.seq_num_res)),
        );
        socket
            .send_to(group, port, &peer_join)
            .expect("inject peer JOIN");

        let mut driver = LwipMulticastDriver::new(socket, group, port);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let runtime = CoopRuntime::new(FrozenClock);
        let self_params = params(&[0xAA, 0xBB, 0xCC, 0xDD]);

        let outcome = run_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &self_params,
                tick_ms: 5,
                max_iters: Some(12),
            },
            &runtime,
            &link,
            &mut driver,
            |_event| {},
            // RX-only: no application TX. Under the no-codec C1m build the item
            // is uninhabited, so this is the only well-typed seam value.
            || None,
        );

        std::assert_eq!(outcome, MulticastOutcome::IterationLimit);
        std::assert_eq!(
            dispatcher.active_peers(),
            1,
            "the inbound JOIN admitted the peer (our own beacon is zid-filtered)"
        );

        link.leave_multicast_group(group).expect("leave group");
    }

    /// Open-debt item 900 — the multicast session runs AS A TASK and gives the
    /// thread back after every iteration, so a sibling task on the same local
    /// set is polled once per pass for as long as the session runs.
    ///
    /// The synchronous loop could not share a program with a second session:
    /// it keeps the thread until the session ends. The counts below are what
    /// tell the two apart. With `max_iters = 12` the task needs THIRTEEN passes
    /// (twelve iterations, then the one that meets the budget), and the sibling
    /// must have taken a turn in each of them. A task that ran its loop inside
    /// one poll finishes in the first pass with the sibling at one turn.
    ///
    /// The outcome is the synchronous loop's for the same fixture and budget
    /// (`run_multicast_session_admits_a_peer_over_loopback`), because the two
    /// drivers run one step. A distinct port (7470).
    #[test]
    fn the_multicast_session_runs_as_a_task_and_yields_after_every_iteration() {
        use core::cell::Cell;

        let (_serial, link) = lwip_test_link();
        let link = Rc::new(link);
        let group = SESSION_MULTICAST_GROUP_DEFAULT;
        let port: u16 = 7470;
        let socket = bind_session_multicast_rx(&link, group, port).expect("bind + join group");
        let peer = params(&[0x01, 0x02, 0x03, 0x04]);
        let peer_join = encode_join(
            &peer,
            &MulticastTxConduits::new(sn::mask_from_res(peer.seq_num_res)),
        );
        socket
            .send_to(group, port, &peer_join)
            .expect("inject peer JOIN");

        let runtime = CoopRuntime::new(FrozenClock);
        let local = CoopLocalSet::new(&runtime);

        // The sibling: a task that counts the passes it was polled in.
        let sibling_turns = Rc::new(Cell::new(0usize));
        let turns = sibling_turns.clone();
        let _sibling = local.spawn_local(async move {
            loop {
                turns.set(turns.get() + 1);
                yield_now().await;
            }
        });

        let handle = spawn_multicast_session(
            &local,
            link.clone(),
            MulticastSession {
                dispatcher: MulticastDispatcher::<4>::new(MulticastConfig::new(5_000)),
                driver: LwipMulticastDriver::new(socket, group, port),
                params: params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                tick_ms: 5,
                max_iters: Some(12),
            },
            |_event| {},
            || None,
            || false,
        );
        std::assert!(!handle.is_finished(), "spawning queues the task");

        let mut passes = 0usize;
        while !handle.is_finished() && passes < 64 {
            local.run_until_idle();
            passes += 1;
        }
        std::assert_eq!(
            passes,
            13,
            "twelve iterations and the budget check, one per pass -- a task \
             that keeps the thread finishes in the first pass"
        );
        std::assert_eq!(
            sibling_turns.get(),
            passes,
            "the sibling must be polled in every pass the session was"
        );
        std::assert_eq!(
            local.block_on_local(handle).expect("not aborted"),
            MulticastOutcome::IterationLimit
        );

        link.leave_multicast_group(group).expect("leave group");
    }

    /// R311ly — the multicast TX seam end-to-end over real lwIP: a `z_put` Push
    /// queued on the loop's `next_tx` pull-seam is framed by the shared
    /// `multicast_tx_emit` SSOT, multicast to the group, and (via multicast
    /// loopback) delivered back to the loop's own socket. To OBSERVE it as an
    /// admitted data frame we pre-admit a peer at our own loopback source: a JOIN
    /// with a DISTINCT zid (so it is not own-zid-filtered), injected from our
    /// socket, creates a peer entry keyed by (src_addr, src_port); the echoed
    /// Push Frame (zid-less, attributed by source) then matches that entry,
    /// passes the SN gate (SN 0 against the JOIN's advertised next_sn 0), and
    /// fans to `on_event`. Shares the lwip_test_link harness; a distinct port
    /// (7452) from the peer-admit (7449) / link-tier (7448) tests.
    #[cfg(feature = "codec-push")]
    #[test]
    fn run_multicast_session_publishes_a_put_over_loopback() {
        use wz_session_core::driver_loop::DriverLoopOutcome;
        use wz_session_core::multicast_tx::multicast_put_literal;
        use wz_session_core::network_message::NetworkMessage;

        let (_serial, link) = lwip_test_link();
        let group = SESSION_MULTICAST_GROUP_DEFAULT;
        let port: u16 = 7452;
        let socket = bind_session_multicast_rx(&link, group, port).expect("bind + join group");

        // Pre-admit a peer at OUR loopback source: a JOIN with a zid distinct
        // from ours (so it is admitted, not own-zid-filtered) advertising
        // next_sn 0 on a fresh ring. Injected before wrapping the socket so the
        // loop's first poll delivers it ahead of our own beacon / Push echo,
        // creating the (src_addr, src_port) peer entry the echoed Push matches.
        let other = params(&[0x01, 0x02, 0x03, 0x04]);
        let other_join = encode_join(
            &other,
            &MulticastTxConduits::new(sn::mask_from_res(other.seq_num_res)),
        );
        socket
            .send_to(group, port, &other_join)
            .expect("inject peer JOIN");

        let mut driver = LwipMulticastDriver::new(socket, group, port);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let runtime = CoopRuntime::new(FrozenClock);
        let self_params = params(&[0xAA, 0xBB, 0xCC, 0xDD]);

        // One queued Put on the reliable channel (pico Z_RELIABILITY_DEFAULT);
        // the pull-seam yields it once, then None (the loop keeps serving RX +
        // JOIN). Frozen clock + bounded max_iters keep the round trip
        // deterministic (no-flaky).
        let mut pending = Some(multicast_put_literal("demo/mc", b"tx-half").expect("build put"));

        let mut saw_push = false;
        let outcome = run_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &self_params,
                tick_ms: 5,
                max_iters: Some(16),
            },
            &runtime,
            &link,
            &mut driver,
            |event| {
                if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) =
                    event
                {
                    if messages
                        .iter()
                        .any(|m| matches!(m, NetworkMessage::Push(_)))
                    {
                        saw_push = true;
                    }
                }
            },
            || pending.take(),
        );

        std::assert_eq!(outcome, MulticastOutcome::IterationLimit);
        std::assert!(
            saw_push,
            "the queued Put was framed by multicast_tx_emit, multicast to the \
             group, echoed back, admitted at our source, and observed as a Push"
        );

        link.leave_multicast_group(group).expect("leave group");
    }

    /// R311lz — the multicast TX seam is variant-complete: a NON-`codec-push`
    /// item (a liveliness `DeclareReply` — the terminating `DeclFinal` for an
    /// interest) queued on `next_tx` is framed by the SAME shared
    /// `multicast_tx_emit` SSOT, multicast to the group, and (via multicast
    /// loopback) observed back as a `Declare(DeclFinal)`. This proves the loop's
    /// TX gate now reaches every forwarded variant, not just Push — the round's
    /// union-gate generalisation. Same pre-admit-our-source trick as the Push
    /// test: a distinct-zid JOIN injected from our socket creates the
    /// (src_addr, src_port) peer entry the echoed Declare Frame matches, passes
    /// the SN gate (SN 0 against the JOIN's advertised next_sn 0 — DeclareReply is
    /// pinned reliable, so it mints on the reliable ring), and fans to `on_event`.
    /// A distinct port (7453) from the Push (7452) / peer-admit (7449) tests.
    #[cfg(feature = "liveliness-token")]
    #[test]
    fn run_multicast_session_publishes_a_declare_reply_over_loopback() {
        use wz_session_core::declare::local_token::build_final_reply;
        use wz_session_core::driver_loop::DriverLoopOutcome;
        use wz_session_core::network_message::NetworkMessage;

        let (_serial, link) = lwip_test_link();
        let group = SESSION_MULTICAST_GROUP_DEFAULT;
        let port: u16 = 7453;
        let socket = bind_session_multicast_rx(&link, group, port).expect("bind + join group");

        // Pre-admit a peer at OUR loopback source (distinct zid -> not
        // own-filtered), advertising next_sn 0 on a fresh ring; injected before
        // wrapping the socket so the loop's first poll creates the peer entry the
        // echoed Declare matches (mirror of the Push round-trip test).
        let other = params(&[0x01, 0x02, 0x03, 0x04]);
        let other_join = encode_join(
            &other,
            &MulticastTxConduits::new(sn::mask_from_res(other.seq_num_res)),
        );
        socket
            .send_to(group, port, &other_join)
            .expect("inject peer JOIN");

        let mut driver = LwipMulticastDriver::new(socket, group, port);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let runtime = CoopRuntime::new(FrozenClock);
        let self_params = params(&[0xAA, 0xBB, 0xCC, 0xDD]);

        // One queued DeclFinal reply for interest id 9 — the trivial terminal of a
        // liveliness interest-response, owned via try_into_owned (DeclFinal
        // borrows nothing). The pull-seam yields it once, then None.
        let declare = build_final_reply(9)
            .try_into_owned()
            .expect("DeclFinal reply carries no bounded fields");
        let mut pending = Some(MulticastTxItem::DeclareReply {
            declare: alloc::boxed::Box::new(declare),
        });

        // The only Declare we emit is this DeclFinal (build_final_reply), so an
        // observed Declare carrying interest id 9 IS our round-tripped reply —
        // the variant-body check the AP test does (DeclFinal vs DeclToken) would
        // need wz-codecs, which this MCU crate does not dep; interest_id is the
        // correlation the querier matches on regardless, so it suffices here.
        let mut saw_declare = false;
        let outcome = run_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &self_params,
                tick_ms: 5,
                max_iters: Some(16),
            },
            &runtime,
            &link,
            &mut driver,
            |event| {
                if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) =
                    event
                {
                    for m in messages.iter() {
                        if let NetworkMessage::Declare(d) = m {
                            std::assert_eq!(
                                d.interest_id,
                                Some(9),
                                "the DeclFinal terminates interest id 9"
                            );
                            saw_declare = true;
                        }
                    }
                }
            },
            || pending.take(),
        );

        std::assert_eq!(outcome, MulticastOutcome::IterationLimit);
        std::assert!(
            saw_declare,
            "the queued DeclareReply was framed by multicast_tx_emit, multicast to \
             the group, echoed back, admitted at our source, and observed as a \
             Declare carrying interest id 9"
        );

        link.leave_multicast_group(group).expect("leave group");
    }

    /// R311ma — the observer-staging round trip on the MCU loop: an inbound
    /// liveliness `Interest` (CURRENT) for a held local token is dispatched to
    /// the observer, which stages a `Declare(DeclToken)` + terminating
    /// `DeclFinal`; the `on_event` closure drains them through
    /// [`MulticastReplyQueue`]'s `DeclareReplySink` impl into the shared queue,
    /// and the loop's `next_tx` seam drains the queue back out (each item then
    /// framed by `multicast_tx_emit`). The MCU mirror of the AP
    /// `drive_loop_emits_liveliness_token_reply_over_multicast`. Asserts the
    /// observer staged exactly the two declare replies and the seam drained
    /// both — proving the observer -> sink -> next_tx wiring.
    ///
    /// It asserts on the DRAINED items, not a loopback echo: observing the echo
    /// would hit the per-peer SN gate (the injected Interest at SN 0 advances the
    /// shared source peer entry past our reply mints, so our echoed DeclToken at
    /// SN 0 would be SN-stale-dropped). The wire emit of a queued DeclareReply is
    /// separately covered by `run_multicast_session_publishes_a_declare_reply_over_loopback`.
    /// Distinct port (7454) from the prior multicast tests.
    #[cfg(feature = "liveliness-token")]
    #[test]
    fn run_multicast_session_stages_observer_declare_replies_into_next_tx() {
        use wz_session_core::frame_encode::encode_frame_with_interest;
        use wz_session_core::interest_build::build_interest_liveliness_get;
        use wz_session_core::observer::ApplicationLayerObserver;

        let (_serial, link) = lwip_test_link();
        let group = SESSION_MULTICAST_GROUP_DEFAULT;
        let port: u16 = 7454;
        let socket = bind_session_multicast_rx(&link, group, port).expect("bind + join group");

        // A peer JOIN (distinct zid, advertising next_sn 0) admits the peer at
        // our loopback source; the liveliness Interest then rides that peer's
        // reliable channel at the advertised SN 0 so the per-peer SN gate admits
        // it. Both injected before wrapping the socket (delivered ahead of our
        // own beacon echo by the loop's first polls).
        let other = params(&[0x01, 0x02, 0x03, 0x04]);
        let other_join = encode_join(
            &other,
            &MulticastTxConduits::new(sn::mask_from_res(other.seq_num_res)),
        );
        socket
            .send_to(group, port, &other_join)
            .expect("inject peer JOIN");
        // A CURRENT liveliness get for "demo/live", interest id 9, at SN 0
        // (mapping_id 0 + literal suffix = a literal keyexpr).
        let interest = encode_frame_with_interest(
            0,
            build_interest_liveliness_get(9, 0, Some("demo/live")).expect("interest fixture"),
            true,
        );
        socket
            .send_to(group, port, &interest)
            .expect("inject Interest");

        let mut driver = LwipMulticastDriver::new(socket, group, port);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let runtime = CoopRuntime::new(FrozenClock);
        let self_params = params(&[0xAA, 0xBB, 0xCC, 0xDD]);

        // A held local liveliness token at the queried keyexpr — the declarer
        // replies with it (and only it: the sole registered token matches).
        let mut observer = ApplicationLayerObserver::new();
        observer
            .local_tokens
            .register(/*token_id=*/ 3, "demo/live")
            .expect("register held token");

        // The reply backing shared between the sink (the observer flushes its
        // staged declare replies through it) and next_tx (drains them back out).
        // R311md: the observer drains the shared MulticastReplySink<Q>, which
        // enqueues onto this backing.
        use wz_session_core::multicast_reply_sink::MulticastReplySink;
        let queue = MulticastReplyQueue::new();
        let sink = MulticastReplySink::new(queue.clone());
        let drain = queue.clone();

        let mut drained_declares = 0usize;
        let outcome = run_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &self_params,
                tick_ms: 5,
                max_iters: Some(16),
            },
            &runtime,
            &link,
            &mut driver,
            |event| {
                observer.dispatch_event(event);
                observer.flush_declare_replies(&sink);
            },
            || {
                let item = drain.pop();
                if let Some(MulticastTxItem::DeclareReply { .. }) = &item {
                    drained_declares += 1;
                }
                item
            },
        );

        std::assert_eq!(outcome, MulticastOutcome::IterationLimit);
        std::assert_eq!(
            dispatcher.active_peers(),
            1,
            "the inbound JOIN admitted the querying peer"
        );
        std::assert_eq!(
            drained_declares,
            2,
            "the observer staged a DeclToken + DeclFinal for the interest, the \
             queue enqueued both, and next_tx drained both"
        );

        link.leave_multicast_group(group).expect("leave group");
    }

    /// R311mb — the queryable observer-staging round trip on the MCU loop: an
    /// inbound `Query` for a registered queryable is dispatched to the observer,
    /// whose handler stages a `Response` + terminating `ResponseFinal`; the
    /// `on_event` closure drains them through [`MulticastReplyQueue`]'s
    /// `ResponseSink` impl into the shared queue, and the loop's `next_tx` seam
    /// drains the queue back out. The MCU mirror of the AP
    /// `drive_loop_emits_queryable_reply_over_multicast`. Asserts the observer
    /// staged exactly one `Response` + one `ResponseFinal` and the seam drained
    /// both — proving the queryable observer -> sink -> next_tx wiring.
    ///
    /// Like the liveliness sibling it asserts on the DRAINED items, not a
    /// loopback echo (the injected Query at SN 0 advances the shared source peer
    /// entry past our reply mints, so an echoed `Response` at SN 0 would be
    /// SN-stale-dropped). Distinct port (7455). Runs only when the queryable
    /// registry (`query-queryable`) + both reply codecs are present.
    #[cfg(all(
        feature = "query-queryable",
        feature = "codec-response",
        feature = "codec-response-final"
    ))]
    #[test]
    fn run_multicast_session_stages_observer_query_replies_into_next_tx() {
        use wz_session_core::frame_encode::encode_frame_with_request;
        use wz_session_core::observer::ApplicationLayerObserver;
        use wz_session_core::request_build::build_request_query;

        let (_serial, link) = lwip_test_link();
        let group = SESSION_MULTICAST_GROUP_DEFAULT;
        let port: u16 = 7455;
        let socket = bind_session_multicast_rx(&link, group, port).expect("bind + join group");

        // A peer JOIN (distinct zid, next_sn 0) admits the querier at our
        // loopback source; the Query then rides that peer's reliable channel at
        // the advertised SN 0 so the per-peer SN gate admits it.
        let other = params(&[0x01, 0x02, 0x03, 0x04]);
        let other_join = encode_join(
            &other,
            &MulticastTxConduits::new(sn::mask_from_res(other.seq_num_res)),
        );
        socket
            .send_to(group, port, &other_join)
            .expect("inject peer JOIN");
        // A literal-keyexpr Query for "demo/mc", request id 7, at SN 0.
        let query = encode_frame_with_request(
            0,
            build_request_query(7, 0, Some("demo/mc")).expect("query fixture"),
            true,
        );
        socket.send_to(group, port, &query).expect("inject Query");

        let mut driver = LwipMulticastDriver::new(socket, group, port);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let runtime = CoopRuntime::new(FrozenClock);
        let self_params = params(&[0xAA, 0xBB, 0xCC, 0xDD]);

        // A registered queryable at the queried keyexpr — its handler stages one
        // reply, which the observer terminates with a ResponseFinal.
        // Through the fallible `register_sink`, which exists on both bounded
        // backings: this crate is also built with `bounded-heapless`, which
        // compiles out the infallible closure wrapper.
        let mut observer = ApplicationLayerObserver::new();
        observer
            .queryables
            .register_sink(
                "demo/mc",
                wz_session_core::locality::Locality::Any,
                false,
                wz_session_core::query_sink::BoxedQuerySink::new(|_query, responder| {
                    responder.reply(b"reply-over-multicast");
                }),
            )
            .expect("a fresh observer takes the queryable");

        // The reply backing shared between the sink (the observer flushes its
        // staged query replies through it) and next_tx (drains them back out).
        // R311md: the observer drains the shared MulticastReplySink<Q>.
        use wz_session_core::multicast_reply_sink::MulticastReplySink;
        let queue = MulticastReplyQueue::new();
        let sink = MulticastReplySink::new(queue.clone());
        let drain = queue.clone();

        let mut drained_responses = 0usize;
        let mut drained_finals = 0usize;
        let outcome = run_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &self_params,
                tick_ms: 5,
                max_iters: Some(16),
            },
            &runtime,
            &link,
            &mut driver,
            |event| {
                observer.dispatch_event(event);
                observer.flush_query_replies(&sink);
            },
            || {
                let item = drain.pop();
                match &item {
                    Some(MulticastTxItem::Response { .. }) => drained_responses += 1,
                    Some(MulticastTxItem::ResponseFinal { .. }) => drained_finals += 1,
                    _ => {}
                }
                item
            },
        );

        std::assert_eq!(outcome, MulticastOutcome::IterationLimit);
        std::assert_eq!(
            dispatcher.active_peers(),
            1,
            "the inbound JOIN admitted the querying peer"
        );
        std::assert_eq!(
            drained_responses,
            1,
            "the observer staged one Response, the queue enqueued it, next_tx drained it"
        );
        std::assert_eq!(
            drained_finals,
            1,
            "the reply chain's terminating ResponseFinal was staged + drained too"
        );

        link.leave_multicast_group(group).expect("leave group");
    }

    /// R311mf — the multicast Fragment RX/TX leg end-to-end over real lwIP: an
    /// oversize `z_put` queued on `next_tx` is split by the shared
    /// `multicast_tx_emit` SSOT into multiple `T_MID_FRAGMENT` datagrams (the
    /// 200-byte payload exceeds the 64-byte batch budget), multicast to the
    /// group, and (via multicast loopback) reassembled by the loop's R311mf
    /// Fragment arm back into the SAME single Push the whole-Frame path fans.
    /// Same pre-admit-our-source trick as the Push round-trip: a distinct-zid
    /// JOIN injected from our socket creates the (src_addr, src_port) peer entry
    /// the echoed fragments attribute to; they mint consecutive SNs from the
    /// JOIN's advertised next_sn 0 on the reliable ring, so the per-peer SN gate
    /// admits the chain in order. A distinct port (7456) from the prior tests.
    #[cfg(all(feature = "transport-fragmentation", feature = "codec-push"))]
    #[test]
    fn run_multicast_session_reassembles_a_fragmented_put_over_loopback() {
        use wz_session_core::driver_loop::DriverLoopOutcome;
        use wz_session_core::multicast_tx::multicast_put_literal;
        use wz_session_core::network_message::NetworkMessage;

        let (_serial, link) = lwip_test_link();
        let group = SESSION_MULTICAST_GROUP_DEFAULT;
        let port: u16 = 7456;
        let socket = bind_session_multicast_rx(&link, group, port).expect("bind + join group");

        // Pre-admit a peer at OUR loopback source (distinct zid -> not
        // own-filtered) advertising next_sn 0 on a fresh ring; injected before
        // wrapping the socket so the loop's first poll creates the peer entry the
        // echoed fragments attribute to (mirror of the Push round-trip test). Its
        // advertised batch_size MUST equal ours (64): validate_join admits a JOIN
        // only when its batch_size matches the receiver's params (multicast_join
        // §3.2), so a peer on the default 2_048 would be silently rejected and
        // the echoed fragments would hit an UnknownPeer drop.
        let mut other = params(&[0x01, 0x02, 0x03, 0x04]);
        other.batch_size = 64;
        let other_join = encode_join(
            &other,
            &MulticastTxConduits::new(sn::mask_from_res(other.seq_num_res)),
        );
        socket
            .send_to(group, port, &other_join)
            .expect("inject peer JOIN");

        let mut driver = LwipMulticastDriver::new(socket, group, port);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let runtime = CoopRuntime::new(FrozenClock);
        // A 64-byte batch budget forces the 200-byte payload to fragment (the
        // owned-push codec caps payloads, so 200 stays under the cap while
        // exceeding the batch — the AP fragmentation test's sizing).
        let mut self_params = params(&[0xAA, 0xBB, 0xCC, 0xDD]);
        self_params.batch_size = 64;
        let payload: std::vec::Vec<u8> = (0..200u32).map(|i| (i.wrapping_mul(13)) as u8).collect();

        // Prove the TX side actually fragments at this budget BEFORE the loop:
        // the shared SSOT splits the oversize frame into >1 datagram, so the
        // round trip below exercises the Fragment RX arm, not the whole-Frame
        // arm (a single frame would ride the admitted-Frame path instead).
        let mut probe_sn = MulticastTxConduits::new(sn::mask_from_res(self_params.seq_num_res));
        let probe = multicast_put_literal("demo/mc", &payload).expect("build put");
        let probe_frames = multicast_tx_emit(probe, &mut probe_sn, &self_params);
        std::assert!(
            probe_frames.datagrams.len() > 1,
            "the 200-byte payload must fragment at batch_size 64 (got {} datagrams)",
            probe_frames.datagrams.len()
        );

        // One queued Put on the reliable channel; the pull-seam yields it once,
        // then None. Frozen clock + bounded max_iters keep the round trip
        // deterministic; the fragments are received one-per-iteration in wire
        // order (lwIP loopback is FIFO), so the strict-in-order SN gate admits
        // the whole chain.
        let mut pending = Some(multicast_put_literal("demo/mc", &payload).expect("build put"));

        let mut saw_push = false;
        let mut saw_drop = false;
        let outcome = run_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &self_params,
                tick_ms: 5,
                max_iters: Some(32),
            },
            &runtime,
            &link,
            &mut driver,
            |event| match event {
                IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) => {
                    if messages
                        .iter()
                        .any(|m| matches!(m, NetworkMessage::Push(_)))
                    {
                        saw_push = true;
                    }
                }
                IterationEvent::ReassemblyDropped(_) => saw_drop = true,
                _ => {}
            },
            || pending.take(),
        );

        std::assert_eq!(outcome, MulticastOutcome::IterationLimit);
        std::assert!(
            !saw_drop,
            "the in-order fragment chain reassembles cleanly (no drop)"
        );
        std::assert!(
            saw_push,
            "the fragmented Put was split by multicast_tx_emit, multicast to the \
             group, echoed back, and reassembled by the Fragment RX arm into one Push"
        );

        link.leave_multicast_group(group).expect("leave group");
    }

    // ── R2375 — the graceful stop, the MCU half of the AP loop's R311y772 /
    //    R311y782 door (the AP module header carried this one as its residual) ──

    /// Drain the group socket looking for a departing Close, pumping lwIP
    /// between reads; `None` when 32 pumps produced none.
    ///
    /// A DRAIN rather than one read: our own JOIN beacons echo back on the same
    /// loopback group, so the Close is not necessarily the next datagram in the
    /// queue — and asserting on "the next one" would make the test depend on how
    /// many beacons the preceding phase happened to emit.
    fn drain_for_close<C: ClockSource>(
        link: &LwipLink,
        runtime: &CoopRuntime<C>,
        driver: &mut LwipMulticastDriver,
    ) -> Option<std::vec::Vec<u8>> {
        for _ in 0..32 {
            link.poll_loopback();
            link.check_timeouts();
            runtime.run_until_idle();
            while let Some(dg) = driver.try_recv() {
                let bytes = dg.data.as_slice();
                if bytes.first().map(|h| h & 0x1f) == Some(wz_session_core::wire_const::T_MID_CLOSE)
                {
                    return Some(bytes.to_vec());
                }
            }
        }
        None
    }

    /// Admit a peer, THEN stop: the loop returns [`MulticastOutcome::Stopped`],
    /// the peer table is cleared, and the departure is ANNOUNCED on the group.
    ///
    /// Two phases rather than one drive with an armed predicate, mirroring the
    /// AP twin's shape: phase one admits the peer through the pre-round entry
    /// point with no predicate at all; phase two re-enters the SAME dispatcher
    /// with one that is already true, so the only thing that can end it is the
    /// stop arm — and the peer that arm must clear is provably there when it
    /// runs.
    ///
    /// The last assertion is the half the AP twin proves in a separate test: the
    /// Close is observed coming BACK off the real lwIP group, so this is a WIRE
    /// claim (the datagram left) and not only an FSM one. That distinction is
    /// the whole reason the stop arm pumps before returning. A distinct port
    /// (7457) from the fragment round trip (7456).
    #[test]
    fn run_multicast_session_stops_on_the_signal_and_announces_the_departure() {
        let (_serial, link) = lwip_test_link();
        let group = SESSION_MULTICAST_GROUP_DEFAULT;
        let port: u16 = 7457;
        let socket = bind_session_multicast_rx(&link, group, port).expect("bind + join group");

        // The peer the stop must clear: a distinct zid (so it is not
        // own-zid-filtered), injected before the socket is wrapped so the loop's
        // first poll admits it — the peer-admit test's shape.
        let peer = params(&[0x01, 0x02, 0x03, 0x04]);
        let peer_join = encode_join(
            &peer,
            &MulticastTxConduits::new(sn::mask_from_res(peer.seq_num_res)),
        );
        socket
            .send_to(group, port, &peer_join)
            .expect("inject peer JOIN");

        let mut driver = LwipMulticastDriver::new(socket, group, port);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let runtime = CoopRuntime::new(FrozenClock);
        let self_params = params(&[0xAA, 0xBB, 0xCC, 0xDD]);

        // Phase 1 — no predicate at all: the pre-round entry point, pre-round
        // behaviour.
        let admitted = run_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &self_params,
                tick_ms: 5,
                max_iters: Some(12),
            },
            &runtime,
            &link,
            &mut driver,
            |_event| {},
            || None,
        );
        std::assert_eq!(admitted, MulticastOutcome::IterationLimit);
        std::assert_eq!(
            dispatcher.active_peers(),
            1,
            "the peer the stop must clear has to be there first"
        );

        // Phase 2 — the predicate is already true when the loop is entered.
        let stopped = run_multicast_session_with_shutdown(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &self_params,
                tick_ms: 5,
                max_iters: Some(12),
            },
            &runtime,
            &link,
            &mut driver,
            |_event| {},
            || None,
            || true,
        );

        std::assert_eq!(
            stopped,
            MulticastOutcome::Stopped,
            "a stop request must end the loop as Stopped, not by budget"
        );
        std::assert_eq!(
            dispatcher.session_state(),
            SessionFsmMulticastState::Stopped
        );
        std::assert_eq!(
            dispatcher.active_peers(),
            0,
            "stop() must run on the way out -- a Stopped session still holding \
             peers is the defect the link-loss path already avoids"
        );

        let close = drain_for_close(&link, &runtime, &mut driver)
            .expect("the departing Close must be observable on the group");
        std::assert_eq!(
            close.as_slice(),
            &[wz_session_core::wire_const::T_MID_CLOSE, 0x00],
            "the MCU departure must be the SAME datagram the AP loop sends: \
             reason GENERIC with the S flag CLEAR (zenoh's multicast shape, and \
             the reason encode_multicast_close records for choosing it)"
        );

        link.leave_multicast_group(group).expect("leave group");
    }

    /// ANTI-VACUITY. The identical fixture handed a predicate that NEVER fires
    /// runs to its budget, keeps the peer, and puts NO Close on the group.
    ///
    /// Without this the test above proves only that some drive returned
    /// Stopped and emitted a Close, which an unconditional `return` at the top
    /// of the loop would also do. The predicate is handed to the SAME entry
    /// point, so the difference between the two tests is the ANSWER and not the
    /// door. A distinct port (7458).
    #[test]
    fn the_same_fixture_without_a_stop_request_runs_to_its_budget() {
        let (_serial, link) = lwip_test_link();
        let group = SESSION_MULTICAST_GROUP_DEFAULT;
        let port: u16 = 7458;
        let socket = bind_session_multicast_rx(&link, group, port).expect("bind + join group");

        let peer = params(&[0x01, 0x02, 0x03, 0x04]);
        let peer_join = encode_join(
            &peer,
            &MulticastTxConduits::new(sn::mask_from_res(peer.seq_num_res)),
        );
        socket
            .send_to(group, port, &peer_join)
            .expect("inject peer JOIN");

        let mut driver = LwipMulticastDriver::new(socket, group, port);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let runtime = CoopRuntime::new(FrozenClock);
        let self_params = params(&[0xAA, 0xBB, 0xCC, 0xDD]);

        let outcome = run_multicast_session_with_shutdown(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &self_params,
                tick_ms: 5,
                max_iters: Some(12),
            },
            &runtime,
            &link,
            &mut driver,
            |_event| {},
            || None,
            || false,
        );

        std::assert_eq!(
            outcome,
            MulticastOutcome::IterationLimit,
            "a predicate that never answers true must not stop the loop"
        );
        std::assert_eq!(
            dispatcher.active_peers(),
            1,
            "and must not clear the peer table"
        );
        std::assert!(
            drain_for_close(&link, &runtime, &mut driver).is_none(),
            "no Close may reach the group when nothing asked the face to leave"
        );

        link.leave_multicast_group(group).expect("leave group");
    }

    /// A stop request BEATS an exhausted iteration budget.
    ///
    /// The loop polls the predicate before the `max_iters` check, and that
    /// ordering is a decision rather than an accident: when both terminals come
    /// due on the same iteration, a caller that ASKED to leave must leave
    /// announced, not fall out silently because the budget happened to run out
    /// first. `max_iters: Some(0)` is that coincidence in its smallest form —
    /// the budget is already spent when the first iteration starts.
    ///
    /// Without this test the ordering is asserted only by a comment, and moving
    /// the stop arm below the budget check would keep every other test in this
    /// module green. A distinct port (7459).
    #[test]
    fn a_stop_request_beats_an_exhausted_iteration_budget() {
        let (_serial, link) = lwip_test_link();
        let group = SESSION_MULTICAST_GROUP_DEFAULT;
        let port: u16 = 7459;
        let socket = bind_session_multicast_rx(&link, group, port).expect("bind + join group");

        let mut driver = LwipMulticastDriver::new(socket, group, port);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let runtime = CoopRuntime::new(FrozenClock);
        let self_params = params(&[0xAA, 0xBB, 0xCC, 0xDD]);

        let outcome = run_multicast_session_with_shutdown(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &self_params,
                tick_ms: 5,
                max_iters: Some(0),
            },
            &runtime,
            &link,
            &mut driver,
            |_event| {},
            || None,
            || true,
        );

        std::assert_eq!(
            outcome,
            MulticastOutcome::Stopped,
            "the stop arm is polled before the budget, so a spent budget must \
             not swallow a departure the caller asked for"
        );
        std::assert!(
            drain_for_close(&link, &runtime, &mut driver).is_some(),
            "and the departure it took must still have been announced"
        );

        link.leave_multicast_group(group).expect("leave group");
    }

    // ── R2390 transport-multicast: LINK LOSS, this atom's last named clause ──

    /// Admit a peer, THEN drop the CARRIER: the loop returns
    /// [`MulticastOutcome::LinkLost`], the peer table is cleared, and NO
    /// departing Close is put on the group.
    ///
    /// Two phases against ONE fixture, and phase 1 is the control rather than a
    /// separate test: it drives the SAME entry point with the SAME dispatcher,
    /// socket, params and budget, and the ONLY thing that differs in phase 2 is
    /// the carrier bit. A separate anti-vacuity test could not make that claim
    /// — it would vary the fixture too — and the module's own stop tests needed
    /// a second test only because the signal there is a parameter, which this
    /// one deliberately is not.
    ///
    /// The Close assertion is the half that distinguishes link loss from stop:
    /// a departure the caller ASKED for is announced, a link that went away
    /// cannot be, because the interface that would carry the datagram is the
    /// one that dropped. Asserting only the outcome would let a copy of the
    /// stop arm pass.
    ///
    /// R2561 — the face RE-JOINS after a lost carrier, which is the half
    /// R2390 left undone: it taught this loop to DETECT the drop and nothing
    /// acted on the answer.
    ///
    /// THE DISCRIMINATOR IS THE REBIND CALL, not the outcome. The loop already
    /// returned `LinkLost` before this round, so an outcome assertion alone
    /// would pass on the old behaviour. What could not happen before is the
    /// loop being RE-ENTERED: `rebinds` counts that, and the returned outcome
    /// is the SECOND run's terminal (`IterationLimit`), which the first run
    /// could never have produced because it ended on a dead carrier.
    ///
    /// The carrier is restored INSIDE `rebind`, which is also what makes the
    /// fixture honest: the re-join only succeeds because the interface came
    /// back, exactly as it would on a device, rather than because the test
    /// arranged for the loss to be cosmetic.
    ///
    /// `rejoin_delay_ms` is 0 because this fixture's clock is `FrozenClock` —
    /// the wait is a poll bounded by the clock advancing, so any other value
    /// would spin here forever. The function's own doc says so.
    #[test]
    fn a_lost_carrier_is_re_joined_and_the_loop_re_enters() {
        let (_serial, link) = lwip_test_link();
        let group = SESSION_MULTICAST_GROUP_DEFAULT;
        let port: u16 = 7461;
        let socket = bind_session_multicast_rx(&link, group, port).expect("bind + join group");
        let driver = LwipMulticastDriver::new(socket, group, port);
        let runtime = CoopRuntime::new(FrozenClock);
        let self_params = params(&[0xAA, 0xBB, 0xCC, 0xDD]);

        // Down BEFORE the first run, so it ends on the carrier rather than the
        // budget — the terminal this round is about.
        wz_link_lwip::set_all_netif_links(false);
        let mut rebinds = 0usize;
        let outcome = run_multicast_session_rejoining(
            || MulticastDispatcher::<4>::new(MulticastConfig::new(5_000)),
            MulticastDriveConfig {
                params: &self_params,
                tick_ms: 5,
                max_iters: Some(6),
            },
            &runtime,
            &link,
            driver,
            |_event| {},
            || None,
            || false,
            || {
                rebinds += 1;
                wz_link_lwip::set_all_netif_links(true);
                bind_session_multicast_rx(&link, group, port)
                    .ok()
                    .map(|s| LwipMulticastDriver::new(s, group, port))
            },
            0,
        );
        wz_link_lwip::set_all_netif_links(true);

        std::assert_eq!(
            rebinds,
            1,
            "a lost carrier must be RE-JOINED once; before R2561 the face ended \
             for the life of the process and nothing re-bound"
        );
        // THE SECOND RUN'S OWN TERMINAL, which only a loop that genuinely
        // re-entered AND ran can produce. The first run died on a dead carrier
        // and could never reach a budget.
        //
        // ⚠ THIS ASSERTION FAILED ON THE FIRST DRAFT AND THE FAILURE IS WHY THE
        // SIGNATURE TAKES A DISPATCHER FACTORY. That draft re-used one
        // dispatcher and got `Stopped` here: the loop's first act is
        // `session_state() != Running`, and `notify_link_lost` had already
        // driven the FSM into `Stopped`, a `<final>` in
        // `sources/session/session_fsm_multicast.scxml` that cannot carry an
        // outgoing transition. The obvious reading of that is "the statechart
        // needs a resume edge" — and it is wrong: the AP twin had already
        // settled it by starting a NEW session per join rather than resuming a
        // finished one. Re-using the dispatcher was the defect, not the FSM.
        std::assert_eq!(
            outcome,
            MulticastOutcome::IterationLimit,
            "the returned terminal must be the SECOND run's -- a fresh session \
             that ran to its budget over the re-bound socket"
        );
    }

    /// The carrier is restored BEFORE any assertion, deliberately: lwIP's netif
    /// state is process-global and `lwip_test_link` hands out its lock through
    /// `PoisonError::into_inner`, so a panic with the link down would run every
    /// later test in this binary against a dead stack. A distinct port (7460).
    #[test]
    fn run_multicast_session_reports_link_loss_when_the_carrier_drops() {
        let (_serial, link) = lwip_test_link();
        let group = SESSION_MULTICAST_GROUP_DEFAULT;
        let port: u16 = 7460;
        let socket = bind_session_multicast_rx(&link, group, port).expect("bind + join group");

        let peer = params(&[0x01, 0x02, 0x03, 0x04]);
        let peer_join = encode_join(
            &peer,
            &MulticastTxConduits::new(sn::mask_from_res(peer.seq_num_res)),
        );
        socket
            .send_to(group, port, &peer_join)
            .expect("inject peer JOIN");

        let mut driver = LwipMulticastDriver::new(socket, group, port);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let runtime = CoopRuntime::new(FrozenClock);
        let self_params = params(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let cfg = || MulticastDriveConfig {
            params: &self_params,
            tick_ms: 5,
            max_iters: Some(12),
        };

        // Phase 1 — CONTROL: carrier up, everything else identical.
        let admitted = run_multicast_session(
            &mut dispatcher,
            cfg(),
            &runtime,
            &link,
            &mut driver,
            |_event| {},
            || None,
        );
        std::assert_eq!(admitted, MulticastOutcome::IterationLimit);
        std::assert_eq!(
            dispatcher.active_peers(),
            1,
            "the peer the link-loss path must clear has to be there first"
        );
        std::assert!(
            link.any_link_is_up(),
            "the control phase must run with a live carrier, or it is not one"
        );

        // Phase 2 — the carrier is gone when the loop is entered.
        wz_link_lwip::set_all_netif_links(false);
        let lost = run_multicast_session(
            &mut dispatcher,
            cfg(),
            &runtime,
            &link,
            &mut driver,
            |_event| {},
            || None,
        );
        let state = dispatcher.session_state();
        let peers = dispatcher.active_peers();
        wz_link_lwip::set_all_netif_links(true);

        std::assert_eq!(
            lost,
            MulticastOutcome::LinkLost(LostCause::OsError),
            "a dropped carrier must end the loop as LinkLost, not by budget"
        );
        // R2560 — bind THIS loop's real terminal to the shared re-join
        // judgement, rather than asserting the judgement again in the abstract.
        // Until this round that decision lived in `wz-runtime-tokio`, a crate
        // this one does not depend on, so the MCU profile produced the terminal
        // and could not ask what it meant. The question is now askable HERE,
        // which is the seam the re-join wiring attaches to; that the answer is
        // `true` and nothing yet acts on it is exactly the residual that stays
        // open, and it is stated rather than implied.
        std::assert!(
            lost.warrants_rejoin(),
            "the carrier-loss terminal is the one a group face re-joins after"
        );
        std::assert_eq!(state, SessionFsmMulticastState::Stopped);
        std::assert_eq!(
            peers,
            0,
            "notify_link_lost() must run on the way out -- a Stopped session \
             still holding peers is the defect the AP path already avoids"
        );
        std::assert!(
            drain_for_close(&link, &runtime, &mut driver).is_none(),
            "a link that went away cannot announce a departure; only a stop \
             request the caller made is announced"
        );

        link.leave_multicast_group(group).expect("leave group");
    }

    /// The two ORDERING decisions the link-loss arm makes, asserted rather than
    /// only commented: a lost link BEATS an exhausted iteration budget, and a
    /// stop request BEATS a lost link.
    ///
    /// `max_iters: Some(0)` puts the budget's terminal on the same iteration as
    /// the carrier read, which is the coincidence in its smallest form. Without
    /// the first half, moving the carrier read below the budget check would
    /// keep every other test in this module green — the loop would report the
    /// TEST GUARD where a real link had died. Without the second, moving it
    /// above the stop poll would keep them green too, and a caller that asked
    /// to leave would be told the link failed instead.
    ///
    /// Fresh dispatchers per half: `notify_link_lost` leaves the first one
    /// Stopped, so reusing it would exit at the loop's state check and prove
    /// nothing about either ordering. A distinct port (7461).
    #[test]
    fn link_loss_beats_the_budget_and_a_stop_request_beats_link_loss() {
        let (_serial, link) = lwip_test_link();
        let group = SESSION_MULTICAST_GROUP_DEFAULT;
        let port: u16 = 7461;
        let socket = bind_session_multicast_rx(&link, group, port).expect("bind + join group");

        let mut driver = LwipMulticastDriver::new(socket, group, port);
        let runtime = CoopRuntime::new(FrozenClock);
        let self_params = params(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let cfg = || MulticastDriveConfig {
            params: &self_params,
            tick_ms: 5,
            max_iters: Some(0),
        };

        let mut spent_budget = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let mut also_asked_to_stop = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));

        wz_link_lwip::set_all_netif_links(false);
        let over_budget = run_multicast_session(
            &mut spent_budget,
            cfg(),
            &runtime,
            &link,
            &mut driver,
            |_event| {},
            || None,
        );
        let over_stop = run_multicast_session_with_shutdown(
            &mut also_asked_to_stop,
            cfg(),
            &runtime,
            &link,
            &mut driver,
            |_event| {},
            || None,
            || true,
        );
        wz_link_lwip::set_all_netif_links(true);

        std::assert_eq!(
            over_budget,
            MulticastOutcome::LinkLost(LostCause::OsError),
            "the carrier is read before the budget, so a spent budget must not \
             disguise a dead link as the test guard"
        );
        std::assert_eq!(
            over_stop,
            MulticastOutcome::Stopped,
            "the stop poll is read before the carrier, so a caller that asked \
             to leave is not told its link failed"
        );

        link.leave_multicast_group(group).expect("leave group");
    }

    /// The session machine's `open_multicast_link` is what makes the transport
    /// the session's link: a transport that cannot be opened (here one already
    /// released) ends the session as a lost link at bring-up, and NOTHING is
    /// sent, not even the first JOIN beacon a running session emits at once.
    ///
    /// The beacon assertion is the discriminator: a loop that brought the
    /// session up without performing the open would reach Running, beacon on
    /// its first iteration, and only then find out. The carrier is up, so the
    /// loss cannot come from the per-iteration carrier read. A distinct port
    /// (7462).
    #[test]
    fn a_group_transport_that_cannot_open_sends_nothing_and_ends_lost() {
        let (_serial, link) = lwip_test_link();
        let group = SESSION_MULTICAST_GROUP_DEFAULT;
        let port: u16 = 7462;
        let socket = bind_session_multicast_rx(&link, group, port).expect("bind + join group");
        let mut driver = LwipMulticastDriver::new(socket, group, port);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let runtime = CoopRuntime::new(FrozenClock);
        let self_params = params(&[0xAA, 0xBB, 0xCC, 0xDD]);
        std::assert!(link.any_link_is_up(), "the carrier is not the cause");

        let mut released = LwipGroupTransport::new(&link, &mut driver);
        released.close();
        let outcome = group::run_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &self_params,
                tick_ms: 5,
                max_iters: Some(12),
            },
            &runtime,
            &mut released,
            |_event| {},
            || None,
        );

        std::assert_eq!(
            outcome,
            MulticastOutcome::LinkLost(LostCause::OsError),
            "a link that could not be opened is a lost link, not a budget"
        );
        std::assert_eq!(
            dispatcher.session_state(),
            SessionFsmMulticastState::Stopped
        );
        std::assert!(!dispatcher.is_running());
        let mut beacons = 0usize;
        for _ in 0..32 {
            link.poll_loopback();
            link.check_timeouts();
            runtime.run_until_idle();
            while let Some(dg) = driver.try_recv() {
                if dg.data.as_slice().first().map(|h| h & 0x1f)
                    == Some(wz_session_core::wire_const::T_MID_JOIN)
                {
                    beacons += 1;
                }
            }
        }
        std::assert_eq!(
            beacons,
            0,
            "a session whose link never opened beacons nothing"
        );

        link.leave_multicast_group(group).expect("leave group");
    }
}
