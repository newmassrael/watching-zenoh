// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Round A — the multicast Router (dispatcher) that drives the one
//! session-level [`session_fsm_multicast`](crate::session_fsm_multicast)
//! Engine plus a fixed bounded pool of per-peer
//! [`multicast_peer`](crate::multicast_peer) Engines (the §3.2
//! `multicast_peer_table`).
//!
//! This is the handshake-free multicast sibling of
//! [`reassembly_dispatch`](crate::reassembly_dispatch): the two engine-free
//! statecharts own the protocol lifecycles, and this Rust Router owns
//! everything a native FSM guard cannot reference — the per-peer last_seen
//! + lease arithmetic, the inbound Join validation / classification, and
//! the lease-sweep clock.
//!
//! ## Division of labour (`docs/session-fsm.md` §3.1 / §3.2)
//!
//! - **Session lifecycle — the session FSM.** Idle -> LinkOpening ->
//!   Running -> Stopped is the [`session_fsm_multicast`] statechart; the
//!   Router drives its four lifecycle events ([`MulticastDispatcher::create`]
//!   / [`notify_link_ready`](MulticastDispatcher::notify_link_ready) /
//!   [`notify_link_lost`](MulticastDispatcher::notify_link_lost) /
//!   [`stop`](MulticastDispatcher::stop)).
//! - **The §3.1 Running parallel concerns — the Router.** Running is a leaf
//!   (the SCE surface has no `<parallel>`); the host owns JoinEmit /
//!   RxDispatch / PeerSweep. The Router realises RxDispatch
//!   ([`ingest_join`](MulticastDispatcher::ingest_join) for JOIN /
//!   [`refresh_by_src`](MulticastDispatcher::refresh_by_src) for Frame /
//!   KeepAlive / [`close_by_src`](MulticastDispatcher::close_by_src) for
//!   Close) + PeerSweep ([`sweep`](MulticastDispatcher::sweep)) as a no-I/O
//!   surface; the periodic JoinEmit cadence + the real socket are the
//!   `wz-runtime-tokio` drive loop.
//! - **Per-peer membership — the per-peer FSM.** Free -> Discovered ->
//!   Active -> Expired is the [`multicast_peer`] statechart, one Engine per
//!   pool slot. A peer is keyed by its transport SOURCE ADDRESS (the
//!   zenoh-pico multicast model — Frame / KeepAlive / Close carry no zid on
//!   the wire, so they are attributed by `_z_find_peer_entry(addr)`); the
//!   `zid` from its JOIN is the stored protocol identity. The Router
//!   pre-classifies (only a validated Join is admitted; a mismatch is
//!   dropped without a transition, §3.2) and owns last_seen; the FSM owns
//!   the lifecycle + its `init_rx_seq` / `emit_peer_lost` entry effects.
//!
//! ## Lease ownership (§3.1 PeerSweep)
//!
//! The per-peer FSM arms no timer (codegen'd `--no-std`, `type Hal =
//! NoOpHal`, so a `<send delay>` is a dead element). The Router owns the
//! clock: each live peer carries `last_seen_ms`, refreshed on every inbound
//! message; [`MulticastDispatcher::sweep`] drives `peer.lost` into only the
//! peers whose `last_seen + lease` has elapsed (a recycled slot is `Free`
//! and cannot see a stale lease). Mirrors the reassembly Router's deadline
//! split: value = spec ([`MulticastConfig::lease_ms`]), transition =
//! statechart, clock = runtime.
//!
//! ## Effect-point bindings (no-op)
//!
//! The generated `*Policy<A>`'s `actions` field is private, so a binding
//! buried in the `Engine` cannot reach the Router-owned link / peer table
//! and cannot be read back. The `<sce:action>` effect points are therefore
//! realised by the Router (which observes the FSM state), and the
//! [`SessionBinding`] / [`PeerBinding`] action bodies are honest no-ops —
//! zero-field markers of the SPEC's effect points (SSOT with §3.1 / §3.2),
//! not dead counters. Behaviour is verified through the FSM state
//! ([`session_state`](MulticastDispatcher::session_state) /
//! [`peer_state`](MulticastDispatcher::peer_state)) and the `ingest_*`
//! return values. (`reassembly_dispatch`'s `SlotBinding` still carries
//! similarly-unreadable counters — the same simplification applies there,
//! a separate cleanup.)

use crate::multicast_peer::{
    MulticastPeerActions, MulticastPeerEvent, MulticastPeerPolicy, MulticastPeerState,
};
use crate::session_fsm_multicast::{
    SessionFsmMulticastActions, SessionFsmMulticastEvent, SessionFsmMulticastPolicy,
    SessionFsmMulticastState,
};
use crate::sn;
use core::net::SocketAddr;
use sce_rust_runtime::Engine;

/// Maximum ZID byte length (zenoh ZID is up to 16 bytes; the wire form is
/// length-prefixed). The peer key copies the ZID into a fixed buffer so the
/// Router holds no allocation per peer.
const ZID_MAX: usize = 16;

/// Deploy-sourced multicast runtime knobs (§3.1 PeerSweep lease).
///
/// The pool DIMENSION (`MAX_PEERS`) is the [`MulticastDispatcher`] const
/// generic; this is the per-tick behavioural knob. No `Default`: a zero
/// `lease_ms` would expire every peer on the first sweep, so the caller
/// constructs explicitly (mirrors [`crate::reassembly_dispatch::ReassemblyConfig`]'s
/// no-`Default` policy). The deploy.yaml plumbing that sources this is a
/// follow-up; callers pass spec values today.
#[derive(Debug, Clone, Copy)]
pub struct MulticastConfig {
    /// Per-peer lease window in milliseconds. Refreshed on every inbound
    /// message; [`MulticastDispatcher::sweep`] evicts a peer whose
    /// `last_seen + lease_ms` has elapsed (§3.1 "evict PeerTable entries
    /// with last_seen > lease"). The §3.1 sweep CADENCE is `lease/3` — a
    /// host-loop concern (how often `sweep` is called), not a Router field.
    pub lease_ms: u64,
}

impl MulticastConfig {
    /// Construct an explicit config. See the field docs for the no-`Default`
    /// rationale.
    pub const fn new(lease_ms: u64) -> Self {
        Self { lease_ms }
    }
}

/// Why the Router refused a Join before admitting a peer (the Join is
/// dropped; no per-peer FSM is allocated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinRefuse {
    /// Every pool slot already holds a live peer (the §3.2
    /// `multicast_peer_table` bounded cap; the `max_sessions` reject).
    PeerTableFull,
}

/// The SN baseline a validated JOIN advertises (§3.2 "initialize RX
/// seq-num table" — the `init_rx_seq` effect point, realised by the
/// Router). `next_sn_*` is the next SN the announcer WILL send per
/// channel; the Router seeds the peer's last-seen SN one BEFORE it
/// (zenoh-pico `_z_conduit_sn_list_copy` + `_z_conduit_sn_list_decrement`,
/// multicast/rx.c) so the first data frame at exactly `next_sn` passes
/// the half-window gate. `sn_res` is the announcer's 2-bit `seq_num_res`
/// wire code — the RX classifier has already checked it is compatible
/// (§3.2 rejection rules); the Router derives the peer's ring mask from
/// it ([`sn::mask_from_res`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinSnBaseline {
    /// The announcer's `seq_num_res` wire code (a JOIN that omits the
    /// optional advertises the protocol default — the caller projects
    /// that default before constructing this).
    pub sn_res: u8,
    /// Next SN the announcer will send on the reliable channel.
    pub next_sn_reliable: u64,
    /// Next SN the announcer will send on the best-effort channel.
    pub next_sn_best_effort: u64,
}

/// Outcome of one [`MulticastDispatcher::ingest_frame_by_src`] admission
/// (§3.1 `Frame -> per-peer RxDispatch`, the §2.3 SN gate applied
/// per-peer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameIngest {
    /// The frame SN strictly follows the peer's last-seen SN on its
    /// channel; the baseline advanced and the peer's lease refreshed.
    /// The caller delivers the frame payload to the application layer.
    Admitted,
    /// The frame SN is stale / duplicated / outside the half-window
    /// (zenoh-pico "message dropped because it is out of order"). The
    /// payload must be dropped. The peer's lease WAS refreshed — pico
    /// marks `_received = true` before its SN gate, so even an
    /// out-of-order frame proves the peer is alive (liveness is
    /// independent of data validity).
    OutOfOrder,
    /// No live peer is keyed at the source address (zenoh-pico "Dropping
    /// _Z_FRAME from unknown peer" — a peer must JOIN before its data is
    /// admitted).
    UnknownPeer,
    /// The session FSM is not in `Running` (mirror of
    /// [`JoinOutcome::SessionNotRunning`]).
    SessionNotRunning,
}

/// Outcome of one [`MulticastDispatcher::ingest_join`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinOutcome {
    /// A validated Join from a new peer was admitted: a Free slot went
    /// Free -> Discovered (`init_rx_seq`) -> Active.
    Admitted,
    /// The Join was from a peer already in the table; its `last_seen` was
    /// refreshed (the peer stays Active).
    Refreshed,
    /// The Join was refused before slot allocation.
    Refused(JoinRefuse),
    /// The session FSM is not in `Running`, so no peer may be admitted (the
    /// host must `create` + `notify_link_ready` first).
    SessionNotRunning,
}

/// Host binding for the generated [`SessionFsmMulticastActions`]. The three
/// `<sce:action>` effect points (`open_multicast_link` / `enter_running` /
/// `release_multicast_link`) are realised by the Router OUTSIDE the FSM —
/// the engine-free split: a binding buried in the generated `Policy` cannot
/// reach the Router-owned link / peer table, so the Router does the work by
/// observing the FSM state (e.g. [`MulticastDispatcher::clear_peers_if_stopped`]
/// clears the table on Stopped). These bodies are therefore deliberate
/// no-ops: the `<sce:action>` is the SPEC's effect-point marker (SSOT with
/// §3.1), the Router is its realisation. Zero-field — the generated
/// `Policy.actions` is private so any per-action counter would be unreadable
/// (behaviour is verified through the FSM state, not dispatch counts), and a
/// dead counter is worse than an honest no-op.
struct SessionBinding;

impl SessionFsmMulticastActions for SessionBinding {
    fn open_multicast_link(&mut self) {}
    fn enter_running(&mut self) {}
    fn release_multicast_link(&mut self) {}
}

/// Host binding for the generated [`MulticastPeerActions`]; one per pool
/// slot. Like [`SessionBinding`], the two `<sce:action>` effect points
/// (`init_rx_seq` on Discovered entry, `emit_peer_lost` on Expired entry)
/// are Router-realised — a per-peer RX-seq table and the upward peer-lost
/// event are Router/host state the buried binding cannot reach (engine-free
/// split). No-op bodies: the SCXML marks WHERE the effect goes (SSOT with
/// §3.2), the Router realises it — `init_rx_seq` as
/// [`PeerSlot::seed_rx_sn`] on JOIN admission (A1a), `emit_peer_lost` as
/// the upward peer-lost surface (still deferred — see the module deferral
/// notes). Zero-field, no dead counters.
struct PeerBinding;

impl MulticastPeerActions for PeerBinding {
    fn init_rx_seq(&mut self) {}
    fn emit_peer_lost(&mut self) {}
}

/// One peer-table slot: the engine-free per-peer FSM plus the Router-owned
/// membership state (peer ZID + last_seen). `zid` is `Some` while the slot
/// holds a live peer (FSM != Free) and `None` when the slot is free.
struct PeerSlot {
    engine: Engine<MulticastPeerPolicy<PeerBinding>>,
    /// The peer's transport SOURCE ADDRESS — the slot's primary key. `Some`
    /// while allocated, `None` when Free. Multicast Frame / KeepAlive /
    /// Close carry no zid on the wire, so the peer is FOUND by its datagram
    /// source address (the zenoh-pico multicast model:
    /// `_z_find_peer_entry(addr)`, peer keyed by `_remote_addr`).
    src: Option<SocketAddr>,
    /// The peer's zenoh id, learned from its JOIN — the protocol identity
    /// (§3.2 "one per zid"), stored alongside the addr key. `Some` iff
    /// `src.is_some()`.
    zid: Option<([u8; ZID_MAX], u8)>,
    /// Absolute monotonic-ms instant of the peer's most recent inbound
    /// message (valid iff `src.is_some()`); the lease is measured from here.
    last_seen_ms: u64,
    /// The peer's SN ring mask, derived from its JOIN-advertised
    /// `seq_num_res` ([`sn::mask_from_res`]; zenoh-pico
    /// `entry->_sn_res = _z_sn_max(msg->_seq_num_res)`). Valid iff
    /// `src.is_some()`.
    sn_mask: u64,
    /// Last-seen SN per channel (reliable / best-effort), seeded one
    /// before the JOIN-advertised `next_sn` (§3.2 `init_rx_seq`) and
    /// advanced by each admitted frame. Valid iff `src.is_some()`.
    rx_sn_reliable: u64,
    rx_sn_best_effort: u64,
}

impl PeerSlot {
    fn new() -> Self {
        let mut engine = Engine::new(MulticastPeerPolicy::new(PeerBinding));
        // W3C SCXML 3.3: enter the initial `Free` leaf.
        engine.initialize();
        Self {
            engine,
            src: None,
            zid: None,
            last_seen_ms: 0,
            sn_mask: 0,
            rx_sn_reliable: 0,
            rx_sn_best_effort: 0,
        }
    }

    /// Seed the per-channel RX SN baselines from a JOIN's advertised
    /// `next_sn` (§3.2 `init_rx_seq`: baseline = one before, so the first
    /// frame at exactly `next_sn` passes the half-window gate).
    fn seed_rx_sn(&mut self, baseline: JoinSnBaseline) {
        self.sn_mask = sn::mask_from_res(baseline.sn_res);
        self.rx_sn_reliable = sn::decrement(self.sn_mask, baseline.next_sn_reliable);
        self.rx_sn_best_effort = sn::decrement(self.sn_mask, baseline.next_sn_best_effort);
    }

    fn is_free(&self) -> bool {
        self.src.is_none()
    }

    /// Does this slot hold the given source address (the primary key)?
    fn matches_src(&self, src: SocketAddr) -> bool {
        self.src == Some(src)
    }

    /// Does this slot hold the given peer ZID (the protocol-identity index,
    /// used by [`MulticastDispatcher::peer_state`])?
    fn matches_zid(&self, zid: &[u8]) -> bool {
        match &self.zid {
            Some((buf, len)) => {
                let n = core::cmp::min(zid.len(), ZID_MAX);
                *len as usize == n && buf[..n] == zid[..n]
            }
            None => false,
        }
    }

    /// Drive `peer.lost` (-> Expired, `emit_peer_lost`) then `peer.recycle`
    /// (-> Free) and clear the Router-side membership state for reuse. The
    /// caller has already established the peer should leave (Close or lease).
    fn evict(&mut self) {
        self.engine.process_event(MulticastPeerEvent::PeerLost);
        self.engine.process_event(MulticastPeerEvent::PeerRecycle);
        self.src = None;
        self.zid = None;
        self.last_seen_ms = 0;
        self.sn_mask = 0;
        self.rx_sn_reliable = 0;
        self.rx_sn_best_effort = 0;
    }
}

/// The multicast Router: one session-level FSM plus a fixed pool of
/// `MAX_PEERS` per-peer FSMs (the §3.2 `multicast_peer_table`). See the
/// module docs for the division of labour with the engine-free FSMs.
pub struct MulticastDispatcher<const MAX_PEERS: usize> {
    session: Engine<SessionFsmMulticastPolicy<SessionBinding>>,
    peers: [PeerSlot; MAX_PEERS],
    config: MulticastConfig,
}

impl<const MAX_PEERS: usize> MulticastDispatcher<MAX_PEERS> {
    /// Build a Router with an Idle session and `MAX_PEERS` free slots over
    /// `config`.
    pub fn new(config: MulticastConfig) -> Self {
        let mut session = Engine::new(SessionFsmMulticastPolicy::new(SessionBinding));
        // W3C SCXML 3.3: enter the initial `Idle` leaf.
        session.initialize();
        Self {
            session,
            peers: core::array::from_fn(|_| PeerSlot::new()),
            config,
        }
    }

    /// The session-level FSM state (§3.1 lifecycle observability).
    pub fn session_state(&self) -> SessionFsmMulticastState {
        self.session.get_current_state()
    }

    /// Number of pool slots currently holding a live peer (the
    /// `multicast_peer_table` occupancy gauge).
    pub fn active_peers(&self) -> usize {
        self.peers.iter().filter(|p| !p.is_free()).count()
    }

    /// The per-peer FSM state for the peer with `zid`, or `None` if no slot
    /// holds it (test / observability helper — the app asks by protocol
    /// identity; the wire RX path attributes by [`peer_state_by_src`]).
    ///
    /// [`peer_state_by_src`]: MulticastDispatcher::peer_state_by_src
    pub fn peer_state(&self, zid: &[u8]) -> Option<MulticastPeerState> {
        self.peers
            .iter()
            .find(|p| p.matches_zid(zid))
            .map(|p| p.engine.get_current_state())
    }

    /// The per-peer FSM state for the peer at source address `src`, or
    /// `None` if no slot holds it (the address-keyed observability mirror of
    /// [`peer_state`](MulticastDispatcher::peer_state)).
    pub fn peer_state_by_src(&self, src: SocketAddr) -> Option<MulticastPeerState> {
        self.peers
            .iter()
            .find(|p| p.matches_src(src))
            .map(|p| p.engine.get_current_state())
    }

    /// Bring the multicast session up: Idle -> LinkOpening
    /// (`open_multicast_link`). Returns the resulting session state. A
    /// `create` outside Idle is a no-op (the FSM has no `multicast.create`
    /// transition elsewhere).
    pub fn create(&mut self) -> SessionFsmMulticastState {
        self.session
            .process_event(SessionFsmMulticastEvent::MulticastCreate);
        self.session_state()
    }

    /// The host completed the multicast link bring-up: LinkOpening ->
    /// Running (`enter_running`). Returns the resulting session state.
    pub fn notify_link_ready(&mut self) -> SessionFsmMulticastState {
        self.session
            .process_event(SessionFsmMulticastEvent::LinkReady);
        self.session_state()
    }

    /// The multicast link dropped: -> Stopped (`release_multicast_link`).
    /// Reachable from LinkOpening or Running (§3.1). On reaching Stopped the
    /// peer table is cleared (the peers belonged to the now-dead session).
    /// Returns the resulting session state.
    pub fn notify_link_lost(&mut self) -> SessionFsmMulticastState {
        self.session
            .process_event(SessionFsmMulticastEvent::LinkLost);
        self.clear_peers_if_stopped();
        self.session_state()
    }

    /// Tear the multicast session down: Running -> Stopped
    /// (`release_multicast_link`, §3.3 — no close handshake). On reaching
    /// Stopped the peer table is cleared. Returns the resulting session
    /// state.
    pub fn stop(&mut self) -> SessionFsmMulticastState {
        self.session
            .process_event(SessionFsmMulticastEvent::MulticastStop);
        self.clear_peers_if_stopped();
        self.session_state()
    }

    /// When the session reaches Stopped, `release_multicast_link` clears the
    /// peer table (§3.1). The peers belonged to a now-dead session, so the
    /// fixed pool is reset wholesale — a session-level teardown, not N
    /// per-peer `peer.lost` events (those are the per-peer FSM's Close /
    /// lease paths, which do not apply once the whole link is gone).
    fn clear_peers_if_stopped(&mut self) {
        if self.session_state() == SessionFsmMulticastState::Stopped {
            self.peers = core::array::from_fn(|_| PeerSlot::new());
        }
    }

    /// Ingest a validated inbound Join from the peer at source address `src`
    /// announcing zenoh id `zid` (§3.1 RxDispatch).
    ///
    /// The caller (the RX classifier) has already validated the Join
    /// (version / resolution / batch / qos, §3.2); a mismatch is dropped
    /// before this call (no transition). The peer is keyed by `src` (the
    /// zenoh-pico multicast model — `_z_find_peer_entry(addr)`): a Join from
    /// a NEW address admits a peer (Free -> Discovered -> Active), records
    /// its `zid`, and seeds its RX SN baselines from `sn_baseline` (the
    /// §3.2 `init_rx_seq` effect point, realised here by the Router); a
    /// Join from a KNOWN address refreshes its lease, re-records the zid,
    /// and RE-seeds the SN baselines (zenoh-pico re-copies `_sn_rx_sns`
    /// from every JOIN — the announcer's `next_sn` is authoritative).
    /// `now_ms` is the runtime monotonic clock.
    pub fn ingest_join(
        &mut self,
        zid: &[u8],
        src: SocketAddr,
        sn_baseline: JoinSnBaseline,
        now_ms: u64,
    ) -> JoinOutcome {
        if self.session_state() != SessionFsmMulticastState::Running {
            return JoinOutcome::SessionNotRunning;
        }
        if let Some(idx) = self.find_by_src(src) {
            // Known address: a Join is just another inbound message (§3.2
            // "Active: any msg refresh last_seen"). The FSM stays Active;
            // the SN baselines re-seed from the fresh advertisement.
            self.peers[idx].last_seen_ms = now_ms;
            self.peers[idx].zid = Some(copy_zid(zid));
            self.peers[idx].seed_rx_sn(sn_baseline);
            return JoinOutcome::Refreshed;
        }
        let idx = match self.peers.iter().position(PeerSlot::is_free) {
            Some(i) => i,
            None => return JoinOutcome::Refused(JoinRefuse::PeerTableFull),
        };
        // A validated first Join admits the peer: Free -> Discovered
        // (init_rx_seq) -> Active. The two transitions are driven together
        // because a multicast peer has no further handshake — a validated
        // Join is a live member (§3.2 "first Join validated" -> steady
        // state Active).
        self.peers[idx].src = Some(src);
        self.peers[idx].zid = Some(copy_zid(zid));
        self.peers[idx].last_seen_ms = now_ms;
        self.peers[idx].seed_rx_sn(sn_baseline);
        self.peers[idx]
            .engine
            .process_event(MulticastPeerEvent::PeerDiscovered);
        self.peers[idx]
            .engine
            .process_event(MulticastPeerEvent::PeerActivated);
        JoinOutcome::Admitted
    }

    /// Admit one inbound data Frame from the peer at source address `src`
    /// against its per-channel SN gate (§3.1 `Frame -> per-peer RxDispatch`;
    /// the §2.3 half-window rule, zenoh-pico `_z_multicast_handle_frame`).
    ///
    /// On [`FrameIngest::Admitted`] the channel baseline advances to `sn`
    /// and the caller delivers the frame payload to the application layer.
    /// [`FrameIngest::OutOfOrder`] drops the payload but still refreshes
    /// the lease — pico sets `_received = true` BEFORE its SN gate
    /// (`_z_multicast_handle_frame`), so any frame from a known address is
    /// liveness even when its data is stale. An unknown peer (no JOIN yet)
    /// is not attributed at all.
    pub fn ingest_frame_by_src(
        &mut self,
        src: SocketAddr,
        reliable: bool,
        frame_sn: u64,
        now_ms: u64,
    ) -> FrameIngest {
        if self.session_state() != SessionFsmMulticastState::Running {
            return FrameIngest::SessionNotRunning;
        }
        let Some(idx) = self.find_by_src(src) else {
            return FrameIngest::UnknownPeer;
        };
        let slot = &mut self.peers[idx];
        // Liveness before validity (pico `_received = true` precedes the
        // SN gate): any frame from a known address refreshes the lease.
        slot.last_seen_ms = now_ms;
        let last = if reliable {
            slot.rx_sn_reliable
        } else {
            slot.rx_sn_best_effort
        };
        if !sn::precedes(slot.sn_mask, last, frame_sn) {
            return FrameIngest::OutOfOrder;
        }
        if reliable {
            slot.rx_sn_reliable = frame_sn;
        } else {
            slot.rx_sn_best_effort = frame_sn;
        }
        FrameIngest::Admitted
    }

    /// Refresh a live peer's lease on any non-Join inbound message attributed
    /// by source address (§3.1 RxDispatch Frame / Fragment / KeepAlive / OAM,
    /// which carry NO zid on the wire). Returns `true` if a live peer was at
    /// `src`. The FSM is not driven (last_seen is Router-side state); the
    /// peer stays Active.
    pub fn refresh_by_src(&mut self, src: SocketAddr, now_ms: u64) -> bool {
        match self.find_by_src(src) {
            Some(idx) => {
                self.peers[idx].last_seen_ms = now_ms;
                true
            }
            None => false,
        }
    }

    /// Ingest an explicit Close from the peer at `src` (§3.2 -> Expired; the
    /// Close carries no zid, so it is attributed by source address). Drives
    /// the peer `peer.lost` (`emit_peer_lost`) + recycle and frees the slot.
    /// Returns `true` if a live peer was at `src`.
    pub fn close_by_src(&mut self, src: SocketAddr) -> bool {
        match self.find_by_src(src) {
            Some(idx) => {
                self.peers[idx].evict();
                true
            }
            None => false,
        }
    }

    /// Evict every live peer whose lease (`last_seen + lease_ms`) has
    /// elapsed at `now_ms`, driving `peer.lost` (`emit_peer_lost`) + recycle
    /// into only those slots (a recycled slot is Free and cannot fire a
    /// stale lease). Returns the number of peers expired (§3.1 PeerSweep).
    pub fn sweep(&mut self, now_ms: u64) -> usize {
        let lease = self.config.lease_ms;
        let mut expired = 0;
        for slot in self.peers.iter_mut() {
            if slot.is_free() {
                continue;
            }
            if now_ms < slot.last_seen_ms.saturating_add(lease) {
                continue;
            }
            slot.evict();
            expired += 1;
        }
        expired
    }

    fn find_by_src(&self, src: SocketAddr) -> Option<usize> {
        self.peers.iter().position(|p| p.matches_src(src))
    }
}

/// Copy a peer ZID into the fixed `([u8; ZID_MAX], len)` key form, clamping
/// to `ZID_MAX` (a zenoh ZID is 1..=16 bytes).
fn copy_zid(zid: &[u8]) -> ([u8; ZID_MAX], u8) {
    let mut buf = [0u8; ZID_MAX];
    let n = core::cmp::min(zid.len(), ZID_MAX);
    buf[..n].copy_from_slice(&zid[..n]);
    (buf, n as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    const ZID_A: &[u8] = &[0xAA; 16];
    const ZID_B: &[u8] = &[0xBB; 16];
    const ZID_C: &[u8] = &[0xCC; 16];

    // Distinct peer source addresses (the addr-keyed peer table's primary
    // key); the port distinguishes them on a shared loopback host.
    const SRC_A: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1);
    const SRC_B: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 2);
    const SRC_C: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3);

    fn running_dispatcher<const N: usize>(lease_ms: u64) -> MulticastDispatcher<N> {
        let mut d = MulticastDispatcher::<N>::new(MulticastConfig::new(lease_ms));
        assert_eq!(d.create(), SessionFsmMulticastState::LinkOpening);
        assert_eq!(d.notify_link_ready(), SessionFsmMulticastState::Running);
        d
    }

    /// A fresh announcer's JOIN baseline (`next_sn` 0 on both channels at
    /// the wz unicast-default 28-bit resolution) — the membership tests
    /// only need SOME valid baseline.
    fn sn0() -> JoinSnBaseline {
        JoinSnBaseline {
            sn_res: 0x02,
            next_sn_reliable: 0,
            next_sn_best_effort: 0,
        }
    }

    /// The session lifecycle walks Idle -> LinkOpening -> Running ->
    /// Stopped (§3.1; no Closing state, §3.3).
    #[test]
    fn session_lifecycle_idle_to_running_to_stopped() {
        let mut d = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        assert_eq!(d.session_state(), SessionFsmMulticastState::Idle);
        assert_eq!(d.create(), SessionFsmMulticastState::LinkOpening);
        assert_eq!(d.notify_link_ready(), SessionFsmMulticastState::Running);
        assert_eq!(d.stop(), SessionFsmMulticastState::Stopped);
    }

    /// A link loss during LinkOpening goes straight to Stopped (§3.1).
    #[test]
    fn link_lost_during_opening_goes_stopped() {
        let mut d = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        assert_eq!(d.create(), SessionFsmMulticastState::LinkOpening);
        assert_eq!(d.notify_link_lost(), SessionFsmMulticastState::Stopped);
    }

    /// A link loss while Running goes to Stopped (§3.1).
    #[test]
    fn link_lost_while_running_goes_stopped() {
        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(d.notify_link_lost(), SessionFsmMulticastState::Stopped);
    }

    /// Stopping a running session clears the peer table (§3.1
    /// release_multicast_link "clear the peer table").
    #[test]
    fn stop_clears_peer_table() {
        let mut d = running_dispatcher::<4>(5_000);
        d.ingest_join(ZID_A, SRC_A, sn0(), 0);
        d.ingest_join(ZID_B, SRC_B, sn0(), 0);
        assert_eq!(d.active_peers(), 2);
        assert_eq!(d.stop(), SessionFsmMulticastState::Stopped);
        assert_eq!(d.active_peers(), 0);
    }

    /// A link loss while Running clears the peer table too (the peers
    /// belonged to the now-dead session, §3.1).
    #[test]
    fn link_lost_clears_peer_table() {
        let mut d = running_dispatcher::<4>(5_000);
        d.ingest_join(ZID_A, SRC_A, sn0(), 0);
        assert_eq!(d.active_peers(), 1);
        assert_eq!(d.notify_link_lost(), SessionFsmMulticastState::Stopped);
        assert_eq!(d.active_peers(), 0);
    }

    /// A validated first Join admits the peer to Active (§3.2). The peer is
    /// queryable by both its zid (protocol identity) and its src (addr key).
    #[test]
    fn join_admits_peer_to_active() {
        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);
        assert_eq!(d.active_peers(), 1);
        assert_eq!(d.peer_state(ZID_A), Some(MulticastPeerState::Active));
        assert_eq!(d.peer_state_by_src(SRC_A), Some(MulticastPeerState::Active));
        assert_eq!(d.peer_state(ZID_B), None);
        assert_eq!(d.peer_state_by_src(SRC_B), None);
    }

    /// A Join before the session is Running is refused (no peer admitted).
    #[test]
    fn join_refused_when_session_not_running() {
        let mut d = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        // Idle: not running.
        assert_eq!(
            d.ingest_join(ZID_A, SRC_A, sn0(), 0),
            JoinOutcome::SessionNotRunning
        );
        // LinkOpening: still not running.
        d.create();
        assert_eq!(
            d.ingest_join(ZID_A, SRC_A, sn0(), 0),
            JoinOutcome::SessionNotRunning
        );
        assert_eq!(d.active_peers(), 0);
    }

    /// A repeat Join from a known address refreshes its lease, not a new slot.
    #[test]
    fn duplicate_join_refreshes() {
        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);
        assert_eq!(
            d.ingest_join(ZID_A, SRC_A, sn0(), 100),
            JoinOutcome::Refreshed
        );
        assert_eq!(d.active_peers(), 1);
        assert_eq!(d.peer_state(ZID_A), Some(MulticastPeerState::Active));
    }

    /// The peer table is keyed by ADDRESS: the SAME zid from two distinct
    /// source addresses is two distinct peers (the zenoh-pico
    /// `_z_find_peer_entry(addr)` model — addr is the transport identity).
    #[test]
    fn same_zid_distinct_src_are_two_peers() {
        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);
        assert_eq!(d.ingest_join(ZID_A, SRC_B, sn0(), 0), JoinOutcome::Admitted);
        assert_eq!(d.active_peers(), 2);
    }

    /// The peer table is a bounded pool: a Join is refused once every slot
    /// holds a live peer (the §3.2 max_sessions cap).
    #[test]
    fn join_refused_when_peer_table_full() {
        let mut d = running_dispatcher::<2>(5_000);
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);
        assert_eq!(d.ingest_join(ZID_B, SRC_B, sn0(), 0), JoinOutcome::Admitted);
        assert_eq!(
            d.ingest_join(ZID_C, SRC_C, sn0(), 0),
            JoinOutcome::Refused(JoinRefuse::PeerTableFull)
        );
        assert_eq!(d.active_peers(), 2);
    }

    /// An explicit Close from a peer's address evicts it and frees the slot
    /// (§3.2 -> Expired -> recycle).
    #[test]
    fn close_by_src_evicts_peer() {
        let mut d = running_dispatcher::<4>(5_000);
        d.ingest_join(ZID_A, SRC_A, sn0(), 0);
        assert!(d.close_by_src(SRC_A));
        assert_eq!(d.active_peers(), 0);
        assert_eq!(d.peer_state(ZID_A), None);
    }

    /// Closing an unknown address is a no-op returning `false`.
    #[test]
    fn close_unknown_src_returns_false() {
        let mut d = running_dispatcher::<4>(5_000);
        d.ingest_join(ZID_A, SRC_A, sn0(), 0);
        assert!(!d.close_by_src(SRC_B));
        assert_eq!(d.active_peers(), 1);
    }

    /// The lease sweep evicts only peers past their lease; a recently-seen
    /// peer survives (§3.1 PeerSweep).
    #[test]
    fn sweep_expires_peers_past_lease_only() {
        let mut d = running_dispatcher::<4>(5_000);
        // Peer A last seen at t=0 -> lease deadline 5_000.
        d.ingest_join(ZID_A, SRC_A, sn0(), 0);
        // Peer B last seen at t=4_000 -> lease deadline 9_000.
        d.ingest_join(ZID_B, SRC_B, sn0(), 4_000);
        // Sweep at t=6_000: only A (deadline 5_000) expires.
        assert_eq!(d.sweep(6_000), 1);
        assert_eq!(d.active_peers(), 1);
        assert_eq!(d.peer_state(ZID_B), Some(MulticastPeerState::Active));
        // Sweep at t=10_000: B (deadline 9_000) expires too.
        assert_eq!(d.sweep(10_000), 1);
        assert_eq!(d.active_peers(), 0);
    }

    /// A src-attributed refresh (Frame / KeepAlive) extends a peer's lease so
    /// a later sweep does not evict it.
    #[test]
    fn refresh_by_src_extends_lease() {
        let mut d = running_dispatcher::<4>(5_000);
        d.ingest_join(ZID_A, SRC_A, sn0(), 0); // deadline 5_000
        assert!(d.refresh_by_src(SRC_A, 4_000)); // deadline now 9_000
                                                 // Sweep at t=6_000: A survives because of the refresh.
        assert_eq!(d.sweep(6_000), 0);
        assert_eq!(d.peer_state(ZID_A), Some(MulticastPeerState::Active));
    }

    /// Refreshing an unknown address returns `false`.
    #[test]
    fn refresh_unknown_src_returns_false() {
        let mut d = running_dispatcher::<4>(5_000);
        assert!(!d.refresh_by_src(SRC_A, 0));
    }

    /// After a peer expires, its slot is reusable for a new peer (the
    /// bounded pool recycles, mirroring the reassembly slot).
    #[test]
    fn slot_reuse_after_expiry() {
        // One slot: admit A, close it, then B reuses the slot.
        let mut d = running_dispatcher::<1>(5_000);
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);
        // Full while A is live.
        assert_eq!(
            d.ingest_join(ZID_B, SRC_B, sn0(), 0),
            JoinOutcome::Refused(JoinRefuse::PeerTableFull)
        );
        assert!(d.close_by_src(SRC_A));
        // Slot freed -> B is admitted into the reclaimed slot.
        assert_eq!(
            d.ingest_join(ZID_B, SRC_B, sn0(), 100),
            JoinOutcome::Admitted
        );
        assert_eq!(d.peer_state(ZID_B), Some(MulticastPeerState::Active));
        assert_eq!(d.peer_state(ZID_A), None);
    }

    // ── A1a — per-peer Frame SN admission (§3.1 Frame -> per-peer
    //    RxDispatch; zenoh-pico _z_multicast_handle_frame parity) ──

    /// A frame from an address that never JOINed is dropped (zenoh-pico
    /// "Dropping _Z_FRAME from unknown peer").
    #[test]
    fn frame_from_unknown_peer_is_dropped() {
        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(
            d.ingest_frame_by_src(SRC_A, true, 0, 0),
            FrameIngest::UnknownPeer
        );
    }

    /// A frame while the session is not Running is not admitted (mirror
    /// of the JOIN guard).
    #[test]
    fn frame_refused_when_session_not_running() {
        let mut d = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        assert_eq!(
            d.ingest_frame_by_src(SRC_A, true, 0, 0),
            FrameIngest::SessionNotRunning
        );
    }

    /// The first frame at exactly the JOIN-advertised `next_sn` is
    /// admitted (the §3.2 `init_rx_seq` decrement-seed contract), and the
    /// SN gate then walks forward: a duplicate of the same SN is stale.
    #[test]
    fn first_frame_at_advertised_next_sn_is_admitted() {
        let mut d = running_dispatcher::<4>(5_000);
        let baseline = JoinSnBaseline {
            sn_res: 0x02,
            next_sn_reliable: 42,
            next_sn_best_effort: 7,
        };
        assert_eq!(
            d.ingest_join(ZID_A, SRC_A, baseline, 0),
            JoinOutcome::Admitted
        );
        assert_eq!(
            d.ingest_frame_by_src(SRC_A, true, 42, 10),
            FrameIngest::Admitted
        );
        assert_eq!(
            d.ingest_frame_by_src(SRC_A, true, 42, 20),
            FrameIngest::OutOfOrder,
            "duplicate SN must be stale"
        );
        assert_eq!(
            d.ingest_frame_by_src(SRC_A, true, 43, 30),
            FrameIngest::Admitted
        );
    }

    /// The reliable and best-effort channels gate independently (two
    /// last-seen baselines per peer, zenoh-pico `_sn_rx_sns` plain pair).
    #[test]
    fn frame_sn_channels_are_independent() {
        let mut d = running_dispatcher::<4>(5_000);
        let baseline = JoinSnBaseline {
            sn_res: 0x02,
            next_sn_reliable: 10,
            next_sn_best_effort: 100,
        };
        d.ingest_join(ZID_A, SRC_A, baseline, 0);
        assert_eq!(
            d.ingest_frame_by_src(SRC_A, true, 10, 1),
            FrameIngest::Admitted
        );
        // The best-effort channel still expects 100 — the reliable advance
        // did not touch it.
        assert_eq!(
            d.ingest_frame_by_src(SRC_A, false, 10, 2),
            FrameIngest::OutOfOrder
        );
        assert_eq!(
            d.ingest_frame_by_src(SRC_A, false, 100, 3),
            FrameIngest::Admitted
        );
    }

    /// A stale (backward / replayed) frame is dropped but STILL refreshes
    /// the peer's lease — pico marks `_received = true` before its SN
    /// gate, so liveness is independent of data validity.
    #[test]
    fn out_of_order_frame_still_refreshes_lease() {
        let mut d = running_dispatcher::<4>(5_000);
        d.ingest_join(ZID_A, SRC_A, sn0(), 0); // lease deadline 5_000
        assert_eq!(
            d.ingest_frame_by_src(SRC_A, true, 0, 100),
            FrameIngest::Admitted
        );
        // Replay of SN 0 at t=4_900: payload dropped, lease refreshed
        // (deadline now 9_900).
        assert_eq!(
            d.ingest_frame_by_src(SRC_A, true, 0, 4_900),
            FrameIngest::OutOfOrder
        );
        assert_eq!(d.sweep(5_200), 0, "stale frame is still liveness");
        assert_eq!(d.sweep(10_000), 1, "lease from the replay then lapses");
    }

    /// An admitted frame refreshes the peer's lease (any inbound message
    /// is liveness, §3.2 Active).
    #[test]
    fn admitted_frame_refreshes_lease() {
        let mut d = running_dispatcher::<4>(5_000);
        d.ingest_join(ZID_A, SRC_A, sn0(), 0); // deadline 5_000
        assert_eq!(
            d.ingest_frame_by_src(SRC_A, true, 0, 4_000),
            FrameIngest::Admitted
        ); // deadline now 9_000
        assert_eq!(d.sweep(6_000), 0);
        assert_eq!(d.peer_state(ZID_A), Some(MulticastPeerState::Active));
    }

    /// A frame past the half-window is ambiguous-stale and dropped; one
    /// inside the window (a sender that skipped SNs) is admitted.
    #[test]
    fn frame_sn_half_window_rule() {
        let mut d = running_dispatcher::<4>(5_000);
        // 7-bit ring (mask 0x7F, half = 63) keeps the vectors readable.
        let baseline = JoinSnBaseline {
            sn_res: 0x00,
            next_sn_reliable: 0,
            next_sn_best_effort: 0,
        };
        d.ingest_join(ZID_A, SRC_A, baseline, 0);
        assert_eq!(
            d.ingest_frame_by_src(SRC_A, true, 0, 1),
            FrameIngest::Admitted
        );
        // Distance 64 > half(63): dropped.
        assert_eq!(
            d.ingest_frame_by_src(SRC_A, true, 64, 2),
            FrameIngest::OutOfOrder
        );
        // Distance 63 = half: admitted (gap-tolerant within the window).
        assert_eq!(
            d.ingest_frame_by_src(SRC_A, true, 63, 3),
            FrameIngest::Admitted
        );
        // Wrap across the ring seam: 63 -> 1 is distance 66 (stale), but a
        // re-JOIN re-seeds the baseline and recovers the stream.
        assert_eq!(
            d.ingest_frame_by_src(SRC_A, true, 1, 4),
            FrameIngest::OutOfOrder
        );
        let rejoin = JoinSnBaseline {
            sn_res: 0x00,
            next_sn_reliable: 1,
            next_sn_best_effort: 0,
        };
        assert_eq!(
            d.ingest_join(ZID_A, SRC_A, rejoin, 5),
            JoinOutcome::Refreshed
        );
        assert_eq!(
            d.ingest_frame_by_src(SRC_A, true, 1, 6),
            FrameIngest::Admitted,
            "a refresh JOIN re-seeds the SN baseline (pico re-copies _sn_rx_sns)"
        );
    }
}
