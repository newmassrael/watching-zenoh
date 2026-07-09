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
//! peers whose hold window has elapsed (a recycled slot is `Free` and
//! cannot see a stale lease). R311ks — the window is PER PEER: each peer
//! is held for the lease ITS OWN JOIN advertised (zenoh-pico stores
//! `entry->_lease = msg->_lease`, multicast/rx.c:393/456, and logs the
//! eviction against it, lease.c:124), capped by the local
//! [`MulticastConfig::lease_ms`] bound — the deadline-model equivalent of
//! pico's received-flag sweep, whose group-min cadence bounds every
//! peer's hold regardless of what it advertised (without the cap one
//! absurd advertisement would pin a bounded pool slot forever). Mirrors
//! the reassembly Router's deadline split: value = wire advertisement +
//! local cap, transition = statechart, clock = runtime.
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

// The observer event surface is alloc-gated (FramePayload carries Vec),
// so the full ingest pipeline gates on alloc too; the chain-key + eviction
// helpers below need only the dispatcher and stay reassembly-only (the
// no-alloc MCU composition keeps them).
#[cfg(all(feature = "reassembly", feature = "alloc"))]
use crate::driver_loop::{
    reassembled_frame_outcome, DriverLoopOutcome, IterationEvent, ReassemblyDropReason,
};
use crate::multicast_peer::{
    MulticastPeerActions, MulticastPeerEvent, MulticastPeerPolicy, MulticastPeerState,
};
#[cfg(all(feature = "reassembly", feature = "alloc"))]
use crate::reassembly_dispatch::Fragment as ReassemblyFragment;
#[cfg(feature = "reassembly")]
use crate::reassembly_dispatch::ReassemblyDispatcher;
use crate::session_fsm_multicast::{
    SessionFsmMulticastActions, SessionFsmMulticastEvent, SessionFsmMulticastPolicy,
    SessionFsmMulticastState,
};
use crate::sn;
use core::net::SocketAddr;
use sce_rust_runtime::Engine;
// §5.21 routing-namespace — the per-session egress prefix + the per-PEER stateful
// ingress decorator live ON the dispatcher (the only always-`&mut` per-session
// multicast handle, the multicast mirror of the unicast `SessionLinkActions`
// holder). `routing-namespace` implies `alloc`, so the `DriverLoopOutcome` the
// strip mutates (alloc-gated, FramePayload carries a `Vec`) is always available
// inside the gated method body; it is named by full path there to avoid a
// duplicate `use` against the `reassembly`-gated import above.
#[cfg(feature = "routing-namespace")]
use crate::keyexpr_prefix::OwnedNonWildKeyExpr;
#[cfg(feature = "routing-namespace")]
use crate::namespace::NamespaceIngress;

/// Maximum ZID byte length (zenoh ZID is up to 16 bytes; the wire form is
/// length-prefixed). The peer key copies the ZID into a fixed buffer so the
/// Router holds no allocation per peer.
const ZID_MAX: usize = 16;

/// §5.21 router-multicast-faces (I3b) — the on-group Designated-Router election
/// reads each peer's JOIN-advertised role; `WhatAmI` classifies Router members.
#[cfg(feature = "multicast-declarations")]
use wz_codecs::whatami::WhatAmI;

/// §5.21 router-multicast-faces (I3a) — the per-peer keyexpr-alias table cap.
/// A multicast peer is admitted on an UNAUTHENTICATED JOIN, so an adversarial
/// LAN host could otherwise flood distinct-id `DeclKexpr` over UDP to grow
/// [`PeerSlot::keyexpr_table`] without bound (memory exhaustion) — the reassembly
/// and peer-pool state are strictly bounded, and this table must be too. The cap
/// gates only NEW growth: removals (`UndeclKexpr`) and re-declares of a known id
/// never grow the table, so a full table stays drainable. 256 is generous for a
/// legitimate repeated-keyexpr publisher (a peer with more distinct keyexprs
/// would send literals, not aliases). The `namespace_ingress` twin carries the
/// same unbounded pattern (pre-existing, `routing-namespace`) — a follow-up
/// unifies the bound across both per-peer decorators.
#[cfg(feature = "multicast-declarations")]
const MAX_ALIASES_PER_PEER: usize = 256;

/// The per-peer `remote_subs` cap (§5.21 router-multicast-faces, sub plane) — the
/// `DeclareSubscriber` twin of [`MAX_ALIASES_PER_PEER`]. A multicast group is an
/// UNAUTHENTICATED broadcast medium, so a peer's declared-subscription table must
/// be bounded against a flood of distinct-id `DeclSubscriber` (memory exhaustion).
/// The cap gates ONLY new growth: an `UndeclSubscriber` removal or a re-declare of
/// a known id never grows the table, so a full table stays drainable. 256 matches
/// `MAX_ALIASES_PER_PEER` — a follow-up unifies the per-peer decorator bounds
/// (aliases / subs / namespace ingress). The AGGREGATE mesh-advertised set is
/// separately bounded by `MAX_PEERS * MAX_SUBS_PER_PEER` (the mesh-bloat concern
/// is a named S2 follow-up).
#[cfg(feature = "multicast-declarations")]
const MAX_SUBS_PER_PEER: usize = 256;

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
    /// The local MAXIMUM hold window in milliseconds (R311ks). A peer is
    /// held for the lease its own JOIN advertised
    /// ([`JoinBaseline::lease_ms`], §3.1 "evict PeerTable entries with
    /// last_seen > lease"), but never longer than this bound:
    /// [`MulticastDispatcher::sweep`] evicts a peer whose
    /// `last_seen + min(advertised, lease_ms)` has elapsed. The cap is
    /// the deadline-model equivalent of zenoh-pico's group-min sweep
    /// cadence (lease.c `_z_get_minimum_lease(peers, local_lease)`) —
    /// it keeps the bounded peer pool drainable when a peer advertises
    /// an absurd lease. The §3.1 sweep CADENCE is `lease/3` — a
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

/// The per-peer baselines a validated JOIN advertises and the Router
/// stores (R311ks rename from `JoinSnBaseline` — the lease joined the
/// SN pair; zenoh-pico copies both at the same admit/refresh sites,
/// multicast/rx.c:388-394 / 453-456).
///
/// `next_sn_*` is the next SN the announcer WILL send per channel; the
/// Router seeds the peer's last-seen SN one BEFORE it (zenoh-pico
/// `_z_conduit_sn_list_copy` + `_z_conduit_sn_list_decrement`,
/// multicast/rx.c) so the first data frame at exactly `next_sn` passes
/// the half-window gate (§3.2 "initialize RX seq-num table" — the
/// `init_rx_seq` effect point, realised by the Router). `sn_res` is the
/// announcer's 2-bit `seq_num_res` wire code — the RX classifier has
/// already checked it is compatible (§3.2 rejection rules); the Router
/// derives the peer's ring mask from it ([`sn::mask_from_res`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinBaseline {
    /// The announcer's `seq_num_res` wire code (a JOIN that omits the
    /// optional advertises the protocol default — the caller projects
    /// that default before constructing this).
    pub sn_res: u8,
    /// Next SN the announcer will send on the reliable channel.
    pub next_sn_reliable: u64,
    /// Next SN the announcer will send on the best-effort channel.
    pub next_sn_best_effort: u64,
    /// The lease window the announcer advertises, in milliseconds (the
    /// JOIN wire T-flag seconds form is already projected back by the
    /// decoder, R311kr). The Router holds the peer alive for
    /// `min(this, MulticastConfig::lease_ms)` after each inbound
    /// message (R311ks; zenoh-pico `entry->_lease = msg->_lease`,
    /// multicast/rx.c:393/456).
    pub lease_ms: u64,
    /// §5.21 router-multicast-faces (I3b) — the announcer's node role, from the
    /// JOIN's whatami wire field. `None` if the wire code is unrecognized. Read
    /// by [`MulticastDispatcher::router_member_zids`] to build the on-group
    /// Designated-Router election candidate set (Router members only).
    #[cfg(feature = "multicast-declarations")]
    pub whatami: Option<WhatAmI>,
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

/// Outcome of one [`MulticastDispatcher::ingest_fragment_by_src`] admission
/// (§3.1 `Fragment -> per-peer RxDispatch`; zenoh-pico
/// `_z_multicast_handle_fragment_inner`'s channel SN gate). The fragment
/// SN rides the SAME per-channel ring the data frames mint from — pico
/// gates fragments with the identical `_z_sn_precedes` check and advances
/// the identical `_sn_rx_sns` tracker — so this is the fragment twin of
/// [`FrameIngest`], extended with what the reassembly Router needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentIngest {
    /// The fragment SN passed the peer's per-channel half-window gate; the
    /// baseline advanced and the lease refreshed. `peer_idx` is the peer's
    /// pool-slot index — the multicast reassembly chain key
    /// ([`multicast_chain_key`]; unique among live peers, and eviction
    /// aborts the slot's chains before the index can be recycled).
    /// `sn_mask` is the peer's JOIN-advertised SN ring mask, which the
    /// reassembly continuation gate compares at.
    Admitted { peer_idx: usize, sn_mask: u64 },
    /// The fragment SN is stale / duplicated / outside the half-window.
    /// The fragment must be dropped AND the channel's in-progress
    /// reassembly chain aborted (pico clears the channel dbuf + state on
    /// an out-of-order fragment, multicast/rx.c). The lease WAS refreshed
    /// (liveness before validity, as [`FrameIngest::OutOfOrder`]).
    OutOfOrder { peer_idx: usize },
    /// No live peer is keyed at the source address (pico "Dropping
    /// Z_FRAGMENT from unknown peer").
    UnknownPeer,
    /// The session FSM is not in `Running`.
    SessionNotRunning,
}

/// Outcome of one [`MulticastDispatcher::ingest_join`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinOutcome {
    /// A validated Join from a new peer was admitted: a Free slot went
    /// Free -> Discovered (`init_rx_seq`) -> Active.
    Admitted,
    /// The Join was from a peer already in the table; its `last_seen` was
    /// refreshed and the advertised baselines (RX SN pair + lease window)
    /// re-stored from the fresh announcement (the peer stays Active;
    /// zenoh-pico re-copies both on every JOIN, multicast/rx.c:453-456).
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
/// [`PeerSlot::seed_from_join`] on JOIN admission (A1a), `emit_peer_lost` as
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
    /// The lease window this peer's JOIN advertised, in milliseconds
    /// (R311ks; zenoh-pico `entry->_lease = msg->_lease`,
    /// multicast/rx.c:393/456). Valid iff `src.is_some()`; the sweep
    /// holds the peer for `min(this, MulticastConfig::lease_ms)`.
    lease_ms: u64,
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
    /// §5.21 routing-namespace — this peer's stateful ingress decorator (the
    /// `ENamespace` mirror): strips the namespace from inbound keyexprs and
    /// correlates id-only undeclares against the declares it dropped. PER-PEER
    /// (not one per session) because the dispatcher applies the decorator at the
    /// RAW multicast mint point with NO router id-renormalization above it: the
    /// `blocked_{sub,qry,tok,interest}` + `incomplete` sets are keyed on the
    /// SENDER's wire ids, which collide across peers (interest/token ids are
    /// per-sender counters). zenoh's single per-session `ENamespace` is
    /// collision-safe ONLY because its router de-aliases per-peer ids first
    /// (`api/session.rs:688`); wz multicast has no such router, so the faithful
    /// adaptation keys the correlation per peer — the same `src`/slot key every
    /// other multicast correlation already uses (SN gate, lease, reassembly
    /// chains). Lazily seeded from [`MulticastDispatcher::namespace`] at the
    /// first strip for this peer and CLEARED on [`Self::evict`] so a recycled
    /// slot never inherits a dead peer's blocked-id state.
    #[cfg(feature = "routing-namespace")]
    namespace_ingress: Option<NamespaceIngress>,
    /// §5.21 router-multicast-faces (I3a) — this peer's `id -> literal` keyexpr
    /// alias table, populated from the `DeclKexpr` declarations it sends over
    /// the group and read to resolve its aliased `Push`es to literal BEFORE the
    /// observer fan ([`MulticastDispatcher::apply_declared_aliases`]). PER-PEER
    /// because a multicast group multiplexes many senders whose wire ids
    /// collide (peer A's id 5 != peer B's id 5) — the same `src`/slot key every
    /// other multicast correlation already uses (SN gate, lease, reassembly
    /// chains, namespace ingress). CLEARED on [`Self::evict`] so a recycled slot
    /// never inherits a dead peer's aliases. The keyexpr-alias twin of
    /// `namespace_ingress`; zenoh keeps the equivalent per-peer resource table
    /// on each `mcast_faces` `FaceState` (`router.rs` `new_peer_multicast`), but
    /// wz has no per-peer router face upstream of the RX dispatch, so — exactly
    /// as `namespace_ingress` documents — the faithful adaptation keys it per
    /// peer here.
    #[cfg(feature = "multicast-declarations")]
    keyexpr_table: hashbrown::HashMap<u64, alloc::string::String>,
    /// §5.21 router-multicast-faces (I3b) — this peer's node role, from its JOIN
    /// whatami. Read by [`MulticastDispatcher::router_member_zids`] so the
    /// router-hat's Designated-Router election counts only on-group ROUTER peers
    /// (a Client/Peer publisher on the group is not a bridge candidate). Set on
    /// admit/refresh from [`JoinBaseline::whatami`], cleared on [`Self::evict`].
    #[cfg(feature = "multicast-declarations")]
    whatami: Option<WhatAmI>,
    /// §5.21 router-multicast-faces (sub plane, S1) — this peer's
    /// `sub-id -> literal keyexpr` remote-subscription table, populated from the
    /// `DeclareSubscriber` / `UndeclareSubscriber` declarations it sends over the
    /// group ([`MulticastDispatcher::apply_declared_subscriptions`]) and unioned by
    /// [`MulticastDispatcher::group_sub_keyexprs`] into the group's aggregate
    /// subscriber interest advertised into the unicast mesh (S2). Keyed by the wire
    /// SUB id (NOT the keyexpr) because a wz `UndeclSubscriber` carries only the id
    /// (no keyexpr), so the removal must correlate by id — the id-keyed-withdraw
    /// discipline the unicast client-queryable withdraw plane also uses. PER-PEER
    /// because a multicast group multiplexes many senders whose wire sub ids
    /// collide (peer A's id 5 != peer B's id 5) — the same `src`/slot key every
    /// other multicast correlation uses (SN gate, lease, reassembly chains,
    /// namespace ingress, keyexpr aliases). The keyexpr is resolved to LITERAL
    /// against this peer's `keyexpr_table` at ingest (an aliased id-only sub
    /// declaration is stored as its literal). CLEARED on [`Self::evict`] so a
    /// recycled slot never inherits a dead peer's subscriptions — wz reclaims where
    /// zenoh LEAKS the `mcast_faces` shell (`router.rs:239`, write-only Vec).
    #[cfg(feature = "multicast-declarations")]
    remote_subs: hashbrown::HashMap<u64, alloc::string::String>,
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
            lease_ms: 0,
            sn_mask: 0,
            rx_sn_reliable: 0,
            rx_sn_best_effort: 0,
            #[cfg(feature = "routing-namespace")]
            namespace_ingress: None,
            #[cfg(feature = "multicast-declarations")]
            keyexpr_table: hashbrown::HashMap::new(),
            #[cfg(feature = "multicast-declarations")]
            whatami: None,
            #[cfg(feature = "multicast-declarations")]
            remote_subs: hashbrown::HashMap::new(),
        }
    }

    /// Store the per-peer state a JOIN advertises: the per-channel RX SN
    /// baselines (§3.2 `init_rx_seq`: baseline = one before, so the first
    /// frame at exactly `next_sn` passes the half-window gate) and the
    /// announcer's lease window (R311ks). One home, mirroring zenoh-pico's
    /// adjacent copies at both the admit and refresh sites
    /// (multicast/rx.c:388-394 / 453-456).
    fn seed_from_join(&mut self, baseline: JoinBaseline) {
        self.sn_mask = sn::mask_from_res(baseline.sn_res);
        self.rx_sn_reliable = sn::decrement(self.sn_mask, baseline.next_sn_reliable);
        self.rx_sn_best_effort = sn::decrement(self.sn_mask, baseline.next_sn_best_effort);
        self.lease_ms = baseline.lease_ms;
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
        self.lease_ms = 0;
        self.sn_mask = 0;
        self.rx_sn_reliable = 0;
        self.rx_sn_best_effort = 0;
        // §5.21 routing-namespace — drop this peer's blocked-id / incomplete-alias
        // correlation state with the slot so a recycled index can never inherit a
        // dead peer's namespace ingress state (the same recycle-safety the SN /
        // reassembly-chain reset above gives).
        #[cfg(feature = "routing-namespace")]
        {
            self.namespace_ingress = None;
        }
        // §5.21 router-multicast-faces (I3a) — drop this peer's keyexpr aliases
        // with the slot so a recycled index can never resolve a new peer's
        // id-only Push against a dead peer's declaration (the same recycle-safety
        // the SN / namespace reset above gives; wz reclaims where zenoh leaks the
        // mcast_faces shell).
        #[cfg(feature = "multicast-declarations")]
        {
            self.keyexpr_table.clear();
            self.whatami = None;
            // §5.21 router-multicast-faces (sub plane) — drop this peer's declared
            // subscriptions with the slot so a recycled index can never advertise a
            // dead peer's interest into the mesh, and the next `group_sub_keyexprs`
            // union no longer counts them (the derive-not-store withdraw path — the
            // forwarder union-refcount then withdraws a keyexpr no live peer holds).
            self.remote_subs.clear();
        }
    }
}

/// The multicast Router: one session-level FSM plus a fixed pool of
/// `MAX_PEERS` per-peer FSMs (the §3.2 `multicast_peer_table`). See the
/// module docs for the division of labour with the engine-free FSMs.
pub struct MulticastDispatcher<const MAX_PEERS: usize> {
    session: Engine<SessionFsmMulticastPolicy<SessionBinding>>,
    peers: [PeerSlot; MAX_PEERS],
    config: MulticastConfig,
    /// §5.21 routing-namespace — the per-session EGRESS prefix (the master
    /// namespace value). `None` until [`Self::set_namespace`] installs it at
    /// bring-up (mirrors the unicast `SessionLinkActions::set_namespace`
    /// config-at-bringup pattern). Read by the AP drive loop at its outbound
    /// chokepoint to namespace local-origin sends, and cloned to seed each
    /// peer's [`PeerSlot::namespace_ingress`] on its first inbound strip. The
    /// egress value + every per-peer ingress derive from THIS one value, so the
    /// egress/ingress prefix can never diverge.
    #[cfg(feature = "routing-namespace")]
    namespace: Option<OwnedNonWildKeyExpr>,
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
            #[cfg(feature = "routing-namespace")]
            namespace: None,
        }
    }

    /// §5.21 routing-namespace — install this session's per-participant keyexpr
    /// namespace at bring-up (call ONCE on the owned dispatcher BEFORE the drive
    /// loop spins; the multicast mirror of the unicast
    /// `SessionLinkActions::set_namespace`). Seeds the EGRESS master value; each
    /// peer's stateful ingress decorator is lazily derived from it on the peer's
    /// first inbound strip, so egress + every per-peer ingress share one prefix
    /// and cannot diverge. Not a post-spawn shared-cell setter — the dispatcher
    /// is single-owned by the loop, so no lock is needed (unlike the unicast
    /// bundle, which is `Arc`-shared at install and thus mutex-guarded).
    #[cfg(feature = "routing-namespace")]
    pub fn set_namespace(&mut self, namespace: OwnedNonWildKeyExpr) {
        self.namespace = Some(namespace);
    }

    /// §5.21 routing-namespace — the per-session egress prefix, read by the AP
    /// drive loop's outbound chokepoint to namespace local-origin sends. `None`
    /// when no namespace is installed (the off path: egress is a no-op).
    #[cfg(feature = "routing-namespace")]
    pub fn namespace(&self) -> Option<&OwnedNonWildKeyExpr> {
        self.namespace.as_ref()
    }

    /// §5.21 routing-namespace — apply the PER-PEER stateful ingress strip to one
    /// owned drive-loop outcome in place, BEFORE it is fanned to the observer.
    /// The multicast mirror of the unicast
    /// `SessionLinkActions::apply_namespace_ingress` (`drive.rs:649-660`), but
    /// keyed per peer: the inbound batch came from ONE peer (`src`), so it strips
    /// with THAT peer's decorator (lazily seeded from the session namespace),
    /// keeping each sender's blocked-id / incomplete-alias correlation isolated.
    /// This method AND both call sites — the whole-Frame seam (`multicast_rx.rs`)
    /// and the reassembled-Fragment seam (`ingest_multicast_fragment`) — are
    /// `#[cfg(routing-namespace)]`, so a non-namespace build (INCLUDING the MCU
    /// `multicast_drive.rs` loop, which never enables the feature) compiles
    /// neither this method nor its calls: no namespace state, no call cost (full
    /// cfg-gating, matching the unicast twin `SessionLinkActions::apply_namespace_ingress`
    /// at `session_actions.rs`). The `Some(ns) else return` early-out is the
    /// RUNTIME no-op for a feature-compiled session with NO namespace installed
    /// (`set_namespace` never called) — distinct from the feature-off case the
    /// cfg-gate handles. Only an `Admitted` Frame (or a completed fragment chain)
    /// reaches here, so a live peer slot matches `src`; a `src` with no matching
    /// slot passes through unstripped.
    #[cfg(feature = "routing-namespace")]
    pub fn apply_namespace_ingress(
        &mut self,
        src: SocketAddr,
        outcome: &mut crate::driver_loop::DriverLoopOutcome,
    ) {
        let Some(ns) = self.namespace.as_ref() else {
            return;
        };
        if let Some(slot) = self.peers.iter_mut().find(|p| p.matches_src(src)) {
            let ingress = slot
                .namespace_ingress
                .get_or_insert_with(|| NamespaceIngress::new(ns.clone()));
            crate::namespace::strip_outcome(ingress, outcome);
        }
    }

    /// §5.21 router-multicast-faces (I3a) — resolve this peer's inbound aliased
    /// keyexprs against its per-peer `id -> literal` declaration table, IN PLACE,
    /// BEFORE the batch is fanned to the observer. The keyexpr-alias twin of
    /// [`apply_namespace_ingress`](Self::apply_namespace_ingress): the inbound
    /// batch came from ONE peer (`src`), so a `DeclKexpr` / `UndeclKexpr` it
    /// carries mutates THAT peer's table (`absorb_keyexpr_into`, the shared
    /// unicast+multicast SSOT) and every `Push` in the batch has its (possibly
    /// id-only) keyexpr rewritten to the resolved literal — so the downstream
    /// router-ingress face (which holds NO per-peer alias table) routes an
    /// already-literal `Push`, exactly as the literal-only I1 plane required. An
    /// id-only `Push` whose alias this peer never declared resolves to `None` and
    /// is left untouched (the empty-table sentinel resolution then drops it,
    /// identical to I1). Declarations stay in the batch (the ingress fold ignores
    /// non-`Push` messages); only the `Push` keyexprs are rewritten.
    ///
    /// Feature-gated end to end (this method, the [`PeerSlot`] table field, and
    /// both call sites in `multicast_rx`) so a non-declarations build — INCLUDING
    /// the no-alloc MCU multicast loop, which never enables the feature —
    /// compiles neither the table nor this method: no per-peer alias state, no
    /// call cost. Only an already-admitted Frame (or a completed fragment chain)
    /// reaches here, so a live slot matches `src`; a `src` with no matching slot
    /// returns without touching the batch.
    #[cfg(feature = "multicast-declarations")]
    pub fn apply_declared_aliases(
        &mut self,
        src: SocketAddr,
        outcome: &mut crate::driver_loop::DriverLoopOutcome,
    ) {
        use crate::network_message::NetworkMessage;
        let crate::driver_loop::DriverLoopOutcome::FramePayload { messages, .. } = outcome else {
            return;
        };
        let Some(slot) = self.peers.iter_mut().find(|p| p.matches_src(src)) else {
            return;
        };
        for msg in messages.iter_mut() {
            match msg {
                NetworkMessage::Declare(declare) => {
                    // Bound the per-peer alias table against an unauthenticated
                    // multicast peer flooding distinct-id DeclKexpr (memory
                    // exhaustion). Reject ONLY new growth past the cap — a removal
                    // (UndeclKexpr) or a re-declare of a known id never grows the
                    // table, so it always flows (a full table must stay drainable).
                    let grows_past_cap = slot.keyexpr_table.len() >= MAX_ALIASES_PER_PEER
                        && matches!(
                            &declare.body,
                            wz_codecs::declare::DeclareOwnedVariant::CodecZenohDeclKexpr(d)
                                if !slot.keyexpr_table.contains_key(&d.id)
                        );
                    if !grows_past_cap {
                        crate::wireexpr_resolve::absorb_keyexpr_into(
                            &mut slot.keyexpr_table,
                            declare,
                        );
                    }
                }
                NetworkMessage::Push(push) => {
                    if let Some(literal) = crate::wireexpr_resolve::resolve_wireexpr(
                        &push.keyexpr.body,
                        &slot.keyexpr_table,
                    ) {
                        // Re-literalize the keyexpr AND the header's N
                        // (suffix-present, 0x20) bit IN SYNC. A pure-aliased Push
                        // carried the N bit CLEAR; rewriting only `keyexpr` to a
                        // suffix-bearing literal while leaving N clear forwards
                        // verbatim through `reliteralize_push`'s already-literal
                        // shortcut and drops the subscriber's decoder into an
                        // offset-shifted read. `set_push_keyexpr_literal` is the
                        // SSOT that sets both (the same the unicast forwarder uses
                        // on its literal egress). On a codec error the Push is left
                        // unchanged (id-only -> dropped by the sentinel resolution,
                        // as an undeclared alias would be).
                        let _ = crate::push_build::set_push_keyexpr_literal(push, &literal);
                    }
                }
                _ => {}
            }
        }
    }

    /// §5.21 router-multicast-faces (sub plane, S1) — ingest this peer's
    /// `DeclareSubscriber` / `UndeclareSubscriber` declarations from the batch into
    /// its per-peer `sub-id -> literal keyexpr` [`remote_subs`](PeerSlot::remote_subs)
    /// table, per peer via `src`. The subscription twin of
    /// [`apply_declared_aliases`](Self::apply_declared_aliases): the inbound batch
    /// came from ONE peer, so a `DeclSubscriber` records THAT peer's interest and an
    /// id-only `UndeclSubscriber` (wz undeclare bodies carry no keyexpr) is
    /// correlated by id and removed. The sub keyexpr is resolved to LITERAL against
    /// this peer's `keyexpr_table` (populated by the prior `apply_declared_aliases`
    /// pass in the SAME batch), so an aliased id-only sub declaration is stored as
    /// its literal; an unresolvable alias (one the peer never declared) is DROPPED —
    /// mirroring the literal-only Push ingress (a keyexpr the router cannot resolve
    /// is one it could never match, and storing it would advertise a garbage keyexpr
    /// into the mesh at S2). READ-ONLY on the batch: unlike `apply_declared_aliases`
    /// (which rewrites Push keyexprs) this only POPULATES the per-peer table that
    /// [`group_sub_keyexprs`](Self::group_sub_keyexprs) unions for the mesh-advertise
    /// plane — the declarations stay in the batch untouched.
    ///
    /// ORDERING: runs AFTER `apply_declared_aliases` (which absorbs the batch's
    /// `DeclKexpr` into `keyexpr_table`, so an aliased sub resolves) and BEFORE
    /// `apply_namespace_ingress`. The alias table is namespace-INCLUSIVE (absorbed
    /// pre-strip), so resolving here keeps the stored keyexpr consistent with the
    /// table. In a routing-namespace build the stored keyexpr is therefore
    /// namespace-inclusive; de-namespacing the ingested sub for the combined
    /// routing-namespace x router-multicast-faces advertise is a NAMED follow-up
    /// (the sub plane's reachability + cross-impl target is the no-namespace case).
    ///
    /// Feature-gated end to end (this method, the `PeerSlot.remote_subs` field, and
    /// both call sites) so a non-declarations build — INCLUDING the no-alloc MCU
    /// multicast loop, which never enables the feature — compiles neither the table
    /// nor this method: no per-peer sub state, no call cost. A `src` with no live
    /// slot returns without touching state.
    #[cfg(feature = "multicast-declarations")]
    pub fn apply_declared_subscriptions(
        &mut self,
        src: SocketAddr,
        outcome: &crate::driver_loop::DriverLoopOutcome,
    ) {
        use crate::network_message::NetworkMessage;
        let crate::driver_loop::DriverLoopOutcome::FramePayload { messages, .. } = outcome else {
            return;
        };
        let Some(slot) = self.peers.iter_mut().find(|p| p.matches_src(src)) else {
            return;
        };
        for msg in messages.iter() {
            let NetworkMessage::Declare(declare) = msg else {
                continue;
            };
            match &declare.body {
                wz_codecs::declare::DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => {
                    // Resolve the (possibly aliased) sub keyexpr against this peer's
                    // alias table. An id-only alias the peer never declared resolves
                    // to `None` -> DROP (an unresolvable keyexpr can never be
                    // matched; storing it would advertise garbage into the mesh).
                    let Some(literal) = crate::wireexpr_resolve::resolve_wireexpr(
                        &d.keyexpr.body,
                        &slot.keyexpr_table,
                    ) else {
                        continue;
                    };
                    // Bound the per-peer sub table against an unauthenticated peer
                    // flooding distinct-id DeclSubscriber. Reject ONLY new growth
                    // past the cap; a re-declare of a known id (overwrite) or a
                    // removal never grows it, so a full table stays drainable (the
                    // `MAX_ALIASES_PER_PEER` idiom).
                    let grows_past_cap = slot.remote_subs.len() >= MAX_SUBS_PER_PEER
                        && !slot.remote_subs.contains_key(&d.id);
                    if !grows_past_cap {
                        slot.remote_subs.insert(d.id, literal);
                    }
                }
                wz_codecs::declare::DeclareOwnedVariant::CodecZenohUndeclSubscriber(u) => {
                    slot.remote_subs.remove(&u.id);
                }
                _ => {}
            }
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

    /// The zids of the live on-group peers that announced `whatami=Router` — the
    /// I3b Designated-Router election candidate set the router-hat relays to its
    /// `RouterForwarder`. Router members ONLY: a Client/Peer publisher on the
    /// group is not a bridge candidate, so it never influences which router
    /// bridges the group <-> mesh. Owned `Vec<Vec<u8>>` (the peer table is
    /// bounded by `MAX_PEERS`) so the AP drive loop can snapshot-diff it across
    /// ticks and relay to the forwarder only on a real membership change.
    #[cfg(feature = "multicast-declarations")]
    pub fn router_member_zids(&self) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        self.peers
            .iter()
            .filter(|p| !p.is_free() && p.whatami == Some(WhatAmI::Router))
            .filter_map(|p| {
                p.zid
                    .as_ref()
                    .map(|(buf, len)| buf[..*len as usize].to_vec())
            })
            .collect()
    }

    /// §5.21 router-multicast-faces (sub plane, S1) — the DEDUPED union of every
    /// live peer's declared-subscription keyexprs
    /// ([`remote_subs`](PeerSlot::remote_subs)): the group's aggregate subscriber
    /// interest the router-hat relays to its `RouterForwarder` to advertise into the
    /// unicast mesh (S2), so a mesh-side publisher routes a matching Put toward this
    /// router and it reaches the on-group subscriber (resolving the cross-router
    /// reachability limit (a)). whatami-AGNOSTIC — UNLIKE
    /// [`router_member_zids`](Self::router_member_zids), which filters to Router for
    /// the DR election: a Client/Peer subscriber's interest MUST be advertised too
    /// (the DR-candidate set and the subscriber set are different sets). Owned
    /// `Vec<String>` (bounded by `MAX_PEERS * MAX_SUBS_PER_PEER`) so the AP drive
    /// loop can snapshot-diff it across ticks and relay only real membership
    /// changes; the forwarder union-refcounts the aggregate (advertise on first,
    /// withdraw on last), so the returned set is DEDUPED (a keyexpr subscribed by
    /// several peers is one entry — its mesh advertisement is one bubble).
    #[cfg(feature = "multicast-declarations")]
    pub fn group_sub_keyexprs(&self) -> alloc::vec::Vec<alloc::string::String> {
        let mut set: hashbrown::HashSet<alloc::string::String> = hashbrown::HashSet::new();
        for p in self.peers.iter() {
            if p.is_free() {
                continue;
            }
            for ke in p.remote_subs.values() {
                set.insert(ke.clone());
            }
        }
        set.into_iter().collect()
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
    /// its `zid`, and stores the advertised baselines from `baseline` (the
    /// §3.2 `init_rx_seq` effect point + the R311ks per-peer lease window,
    /// realised here by the Router); a Join from a KNOWN address refreshes
    /// its lease, re-records the zid, and RE-stores the baselines
    /// (zenoh-pico re-copies `_sn_rx_sns` AND `_lease` from every JOIN,
    /// multicast/rx.c:453-456 — the announcer's advertisement is
    /// authoritative). `now_ms` is the runtime monotonic clock.
    pub fn ingest_join(
        &mut self,
        zid: &[u8],
        src: SocketAddr,
        baseline: JoinBaseline,
        now_ms: u64,
    ) -> JoinOutcome {
        if self.session_state() != SessionFsmMulticastState::Running {
            return JoinOutcome::SessionNotRunning;
        }
        if let Some(idx) = self.find_by_src(src) {
            // Known address: a Join is just another inbound message (§3.2
            // "Active: any msg refresh last_seen"). The FSM stays Active;
            // the baselines re-store from the fresh advertisement.
            self.peers[idx].last_seen_ms = now_ms;
            // §5.21 routing-namespace — a re-JOIN from the SAME address but a
            // DIFFERENT zid is a NEW peer reusing the slot before the old peer's
            // lease expired: drop the dead peer's per-peer namespace correlation
            // state so the new peer cannot inherit its blocked-ids (the in-place
            // twin of the evict() reset, which covers only the lease/Close
            // recycle). It MUST be conditional on a zid CHANGE: a same-zid JOIN
            // (the periodic beacon from a live peer) keeps that peer's legitimate
            // in-flight correlation — an unconditional wipe would itself leak a
            // phantom undeclare (the inverse bug). Checked BEFORE the zid
            // overwrite below; `None` lazily re-seeds from the dispatcher
            // namespace on the next strip, like evict(). (R311y107b session-review
            // fix: SN state is JOIN-authoritative-reset by seed_from_join, so the
            // namespace correlation must follow the same identity-reset rule.)
            #[cfg(feature = "routing-namespace")]
            if !self.peers[idx].matches_zid(zid) {
                self.peers[idx].namespace_ingress = None;
            }
            // §5.21 router-multicast-faces — the SAME in-place recycle hazard for the
            // per-peer DECLARATION state (I3a keyexpr aliases + the S2 remote-sub
            // table): a re-JOIN from the SAME address with a DIFFERENT zid is a NEW
            // peer reusing the slot before the old peer's lease expired, so drop the
            // dead peer's aliases + subscriptions (the in-place twin of evict()'s
            // clear, which covers only the lease/Close recycle). Conditional on a zid
            // CHANGE, exactly like the namespace guard above (a same-zid beacon keeps
            // the live peer's legitimate declarations). WITHOUT this: the recycled
            // slot would resolve the new peer's aliased Pushes against the dead peer's
            // DeclKexpr table (mis-resolution / group blackhole), AND keep advertising
            // the dead peer's group subscription into the unicast mesh (a phantom
            // interest that never withdraws until the slot itself lease-evicts) — both
            // violating evict()'s "a recycled index can never inherit / advertise a
            // dead peer's ..." invariant on the in-place path (the keyexpr_table leak
            // predates S2 — the I3a R311y196 in-place gap — surfaced with remote_subs).
            #[cfg(feature = "multicast-declarations")]
            if !self.peers[idx].matches_zid(zid) {
                self.peers[idx].keyexpr_table.clear();
                self.peers[idx].remote_subs.clear();
            }
            self.peers[idx].zid = Some(copy_zid(zid));
            self.peers[idx].seed_from_join(baseline);
            // §5.21 router-multicast-faces (I3b) — refresh the peer's role from
            // its latest JOIN (a peer's whatami is stable, but this keeps the DR
            // candidate set correct even across a same-slot zid reuse).
            #[cfg(feature = "multicast-declarations")]
            {
                self.peers[idx].whatami = baseline.whatami;
            }
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
        self.peers[idx].seed_from_join(baseline);
        // §5.21 router-multicast-faces (I3b) — record the newly-admitted peer's
        // node role for the on-group Designated-Router election.
        #[cfg(feature = "multicast-declarations")]
        {
            self.peers[idx].whatami = baseline.whatami;
        }
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

    /// Admit one inbound transport Fragment from the peer at source address
    /// `src` against its per-channel SN gate (zenoh-pico
    /// `_z_multicast_handle_fragment_inner`: fragments ride the same
    /// per-channel SN ring as data frames — the identical `_z_sn_precedes`
    /// gate advances the identical `_sn_rx_sns` tracker).
    ///
    /// On [`FragmentIngest::Admitted`] the channel baseline advances to
    /// `frame_sn` and the caller feeds the fragment to the reassembly
    /// Router under the returned chain key / ring mask (the chain-internal
    /// consecutiveness gate is the Router's, [`crate::sn::consecutive`] —
    /// pico's `_z_sn_consecutive` dbuf-drop twin). On
    /// [`FragmentIngest::OutOfOrder`] the caller must abort the channel's
    /// in-progress chain (pico clears the dbuf on the rejected channel).
    /// Lease semantics mirror [`ingest_frame_by_src`]: any fragment from a
    /// known address refreshes the lease before the gate.
    ///
    /// [`ingest_frame_by_src`]: MulticastDispatcher::ingest_frame_by_src
    pub fn ingest_fragment_by_src(
        &mut self,
        src: SocketAddr,
        reliable: bool,
        frame_sn: u64,
        now_ms: u64,
    ) -> FragmentIngest {
        if self.session_state() != SessionFsmMulticastState::Running {
            return FragmentIngest::SessionNotRunning;
        }
        let Some(idx) = self.find_by_src(src) else {
            return FragmentIngest::UnknownPeer;
        };
        let slot = &mut self.peers[idx];
        // Liveness before validity (pico `_received = true` precedes the
        // SN gate): any fragment from a known address refreshes the lease.
        slot.last_seen_ms = now_ms;
        let last = if reliable {
            slot.rx_sn_reliable
        } else {
            slot.rx_sn_best_effort
        };
        if !sn::precedes(slot.sn_mask, last, frame_sn) {
            return FragmentIngest::OutOfOrder { peer_idx: idx };
        }
        if reliable {
            slot.rx_sn_reliable = frame_sn;
        } else {
            slot.rx_sn_best_effort = frame_sn;
        }
        FragmentIngest::Admitted {
            peer_idx: idx,
            sn_mask: slot.sn_mask,
        }
    }

    /// The pool-slot index of the live peer at source address `src` — the
    /// multicast reassembly chain key ([`multicast_chain_key`]). `None` if
    /// no live peer is keyed there. The index is stable for the peer's
    /// lifetime; the caller aborts the slot's chains at eviction
    /// ([`close_by_src`] / [`sweep_with`]) so a recycled index can never
    /// continue a dead peer's chain.
    ///
    /// [`close_by_src`]: MulticastDispatcher::close_by_src
    /// [`sweep_with`]: MulticastDispatcher::sweep_with
    pub fn peer_index_by_src(&self, src: SocketAddr) -> Option<usize> {
        self.find_by_src(src)
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

    /// Evict every live peer whose hold window
    /// (`last_seen + min(advertised lease, MulticastConfig::lease_ms)`)
    /// has elapsed at `now_ms`, driving `peer.lost` (`emit_peer_lost`) +
    /// recycle into only those slots (a recycled slot is Free and cannot
    /// fire a stale lease). R311ks — each peer is held per ITS OWN
    /// JOIN-advertised lease (zenoh-pico evicts against `peer->_lease`,
    /// multicast/lease.c:124), capped by the local config bound. Returns
    /// the number of peers expired (§3.1 PeerSweep).
    pub fn sweep(&mut self, now_ms: u64) -> usize {
        self.sweep_with(now_ms, |_| {})
    }

    /// [`sweep`](MulticastDispatcher::sweep) with an eviction observer:
    /// `on_evict` fires once per expired peer with its pool-slot index,
    /// BEFORE the slot is recycled. The reassembly-running host aborts the
    /// evicted peer's in-progress chains here (pico's per-entry dbufs die
    /// with the peer entry; the wz chains are keyed by slot index, so they
    /// must be aborted before the index can be re-issued to a new peer).
    pub fn sweep_with(&mut self, now_ms: u64, mut on_evict: impl FnMut(usize)) -> usize {
        let cap = self.config.lease_ms;
        let mut expired = 0;
        for (idx, slot) in self.peers.iter_mut().enumerate() {
            if slot.is_free() {
                continue;
            }
            let window = slot.lease_ms.min(cap);
            if now_ms < slot.last_seen_ms.saturating_add(window) {
                continue;
            }
            on_evict(idx);
            slot.evict();
            expired += 1;
        }
        expired
    }

    fn find_by_src(&self, src: SocketAddr) -> Option<usize> {
        self.peers.iter().position(|p| p.matches_src(src))
    }
}

/// The multicast reassembly chain key for the peer in pool slot
/// `peer_idx`. Multicast peers are keyed by SOURCE ADDRESS, not zid (the
/// same zid can be live at two addresses — two distinct peers, two
/// distinct fragment streams), and a `SocketAddr` does not fit the
/// reassembly chain key's fixed buffer (IPv6 + port = 18 bytes > 16) —
/// the slot index is the compact per-peer identity instead. It is unique
/// among live peers; eviction aborts the slot's chains
/// ([`MulticastDispatcher::sweep_with`] / the host's close hook) before
/// the index is re-issued, so a recycled index can never continue a dead
/// peer's chain. (Keying by the wire zid would let a peer at another
/// address graft fragments into a victim's chain — the zid is
/// attacker-chosen wire data; the source address is the transport
/// identity, exactly pico's per-`_remote_addr` dbuf.)
#[cfg(feature = "reassembly")]
pub fn multicast_chain_key(peer_idx: usize) -> [u8; 4] {
    (peer_idx as u32).to_le_bytes()
}

/// Ingest one decoded multicast `T_MID_FRAGMENT` — the multicast twin of
/// [`crate::drive::report_outcome_reassembling`], shared by the AP drive
/// loop and a future MCU multicast loop (one ingest SSOT).
///
/// Pipeline (zenoh-pico `_z_multicast_handle_fragment_inner` parity):
/// per-peer per-channel SN gate ([`MulticastDispatcher::ingest_fragment_by_src`])
/// -> on out-of-order, abort the channel's chain (pico dbuf clear) -> on
/// admission, feed the reassembly Router under the slot-index chain key;
/// a completed chain re-enters the frame-payload decode
/// ([`reassembled_frame_outcome`]) and fans to `on_event` as a
/// [`DriverLoopOutcome::FramePayload`] `Poll` — the SAME event shape the
/// admitted-Frame arm fans, so one observer routes whole and reassembled
/// messages alike. A terminal non-completion ingest surfaces as
/// [`IterationEvent::ReassemblyDropped`]. An unknown-peer / not-running
/// fragment is dropped silently (pico logs and moves on). Alloc-gated
/// like the observer surface it fans into ([`crate::driver_loop`]).
#[cfg(all(feature = "reassembly", feature = "alloc"))]
#[allow(clippy::too_many_arguments)] // the decoded fragment's wire fields ride flat, mirroring report_outcome_reassembling's outcome fields
pub fn ingest_multicast_fragment<const MAX_PEERS: usize, const SLOTS: usize, const CAP: usize, F>(
    dispatcher: &mut MulticastDispatcher<MAX_PEERS>,
    reasm: &mut ReassemblyDispatcher<SLOTS, CAP>,
    src: SocketAddr,
    reliable: bool,
    sn: u64,
    more: bool,
    payload: &[u8],
    now_ms: u64,
    on_event: &mut F,
) where
    F: FnMut(IterationEvent<'_>),
{
    let (peer_idx, sn_mask) = match dispatcher.ingest_fragment_by_src(src, reliable, sn, now_ms) {
        FragmentIngest::Admitted { peer_idx, sn_mask } => (peer_idx, sn_mask),
        FragmentIngest::OutOfOrder { peer_idx } => {
            // The rejected channel's in-progress chain must never complete
            // from mixed generations (pico clears the dbuf + state on an
            // out-of-order fragment, multicast/rx.c).
            // Multicast QoS conduits are deferred (R311y215 step 8), so the
            // chain key uses DEFAULT priority.
            reasm.abort_channel(
                &multicast_chain_key(peer_idx),
                crate::qos::Priority::DEFAULT,
                reliable,
            );
            return;
        }
        FragmentIngest::UnknownPeer | FragmentIngest::SessionNotRunning => return,
    };
    let key = multicast_chain_key(peer_idx);
    let mut completed: Option<DriverLoopOutcome> = None;
    let ingest_outcome = reasm.ingest(
        ReassemblyFragment {
            peer_key: &key,
            reliable,
            sn,
            more: u8::from(more),
            payload,
            // Multicast QoS conduits are deferred (R311y215 step 8): DEFAULT.
            priority: crate::qos::Priority::DEFAULT,
        },
        sn_mask,
        now_ms,
        |msg| {
            completed = Some(reassembled_frame_outcome(reliable, sn, msg));
        },
    );
    if let Some(o) = completed {
        // §5.21 router-multicast-faces (I3a) — resolve this peer's aliased Push
        // keyexprs on the REASSEMBLED batch too (per-peer via `src`), symmetric
        // with the whole-Frame seam in `multicast_rx::dispatch_multicast_inbound`
        // so a fragmented aliased push is not silently dropped for lack of
        // attribution. The table was populated by the peer's earlier whole-frame
        // DeclKexpr; here the completed chain carries only the resolvable Push.
        // Runs BEFORE the namespace strip (id-only -> literal, then prefix strip).
        #[cfg(feature = "multicast-declarations")]
        let o = {
            let mut o = o;
            dispatcher.apply_declared_aliases(src, &mut o);
            // §5.21 router-multicast-faces (sub plane, S1) — ingest a fragmented
            // DeclareSubscriber on the reassembled batch too, symmetric with the
            // whole-Frame seam, so a sub declaration split across fragments still
            // populates the peer's remote-sub table.
            dispatcher.apply_declared_subscriptions(src, &o);
            o
        };
        // §5.21 routing-namespace — strip the REASSEMBLED batch (per-peer via
        // `src`) BEFORE the observer fan, symmetric with the whole-Frame seam in
        // `multicast_rx::dispatch_multicast_inbound`. The shadow keeps `o`
        // immutable on the off path (no `unused_mut`); the `ingest_fragment_by_src`
        // borrow already ended at the match above, so `dispatcher` re-borrows free.
        #[cfg(feature = "routing-namespace")]
        let o = {
            let mut o = o;
            dispatcher.apply_namespace_ingress(src, &mut o);
            o
        };
        on_event(IterationEvent::Poll(&o));
    }
    if let Some(reason) = ReassemblyDropReason::from_ingest(ingest_outcome) {
        on_event(IterationEvent::ReassemblyDropped(reason));
    }
}

/// Abort both of a peer slot's reassembly chains (reliable + best-effort)
/// at eviction — the host's hook for [`MulticastDispatcher::sweep_with`] /
/// the Close arm, fired BEFORE the slot recycles. zenoh-pico parity: the
/// per-entry defragmentation buffers die with the peer entry; the wz
/// chains are keyed by slot index ([`multicast_chain_key`]), so they must
/// be aborted before the index can be re-issued to a new peer.
#[cfg(feature = "reassembly")]
pub fn abort_peer_chains<const SLOTS: usize, const CAP: usize>(
    reasm: &mut ReassemblyDispatcher<SLOTS, CAP>,
    peer_idx: usize,
) {
    let key = multicast_chain_key(peer_idx);
    // Multicast QoS conduits are deferred (R311y215 step 8): DEFAULT.
    reasm.abort_channel(&key, crate::qos::Priority::DEFAULT, true);
    reasm.abort_channel(&key, crate::qos::Priority::DEFAULT, false);
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
    /// only need SOME valid baseline. The advertised lease equals the
    /// fixture config cap (5_000), so `min()` leaves the pre-R311ks sweep
    /// arithmetic untouched for these tests.
    fn sn0() -> JoinBaseline {
        JoinBaseline {
            sn_res: 0x02,
            next_sn_reliable: 0,
            next_sn_best_effort: 0,
            lease_ms: 5_000,
            #[cfg(feature = "multicast-declarations")]
            whatami: None,
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

    /// R311y107 §5.21 routing-namespace — the per-PEER ingress proof: the
    /// stateful blocked-id correlation is isolated per sender, so one peer's
    /// out-of-namespace declare cannot eat another peer's same-id undeclare.
    /// This is WHY the decorator is per peer (in the `PeerSlot`), not one per
    /// session: wz applies the strip on RAW per-sender wire ids with no router
    /// to de-collide them, so a single per-session ingress would mis-correlate
    /// (the faithfulness gap the design panel surfaced — zenoh's per-session
    /// `ENamespace` is safe only because its router de-aliases peer ids first).
    /// Concrete: peer A multicasts an out-of-namespace `DeclareSubscriber id=3`
    /// (dropped + blocked in A's ingress); peer B multicasts an
    /// `UndeclareSubscriber id=3` (B's own id-space, no namespace) — per-peer
    /// state keeps B's undeclare; a single per-session ingress would consume A's
    /// block and wrongly drop it.
    #[cfg(all(feature = "routing-namespace", feature = "codec-declare"))]
    #[test]
    fn namespace_ingress_is_per_peer() {
        use crate::driver_loop::DriverLoopOutcome;
        use crate::keyexpr_prefix::OwnedNonWildKeyExpr;
        use crate::network_message::NetworkMessage;
        use crate::wireexpr_build::literal_wireexpr;
        use alloc::boxed::Box;
        use alloc::vec;
        use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant as DV};

        let mut d = running_dispatcher::<4>(5_000);
        d.set_namespace(OwnedNonWildKeyExpr::new("myns").expect("valid namespace"));
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);
        assert_eq!(d.ingest_join(ZID_B, SRC_B, sn0(), 0), JoinOutcome::Admitted);

        let frame = |msg| DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: vec![msg],
            has_ext: false,
            extensions: vec![],
        };
        let decl_sub_other = NetworkMessage::Declare(Box::new(DeclareOwned {
            header: 0,
            interest_id: None,
            extensions: None,
            body: DV::CodecZenohDeclSubscriber(wz_codecs::decl_subscriber::DeclSubscriberOwned {
                header: 0,
                id: 3,
                keyexpr: literal_wireexpr("other/x").unwrap(),
            }),
        }));
        let undecl_sub = NetworkMessage::Declare(Box::new(DeclareOwned {
            header: 0,
            interest_id: None,
            extensions: None,
            body: DV::CodecZenohUndeclSubscriber(
                wz_codecs::undecl_subscriber::UndeclSubscriberOwned {
                    header: 0,
                    id: 3,
                    extensions: None,
                },
            ),
        }));

        // Peer A's out-of-namespace DeclareSubscriber id=3 -> dropped + blocked
        // in A's per-peer ingress.
        let mut a = frame(decl_sub_other);
        d.apply_namespace_ingress(SRC_A, &mut a);
        let DriverLoopOutcome::FramePayload { messages, .. } = &a else {
            panic!("framepayload")
        };
        assert!(
            messages.is_empty(),
            "A's out-of-namespace declare is dropped"
        );

        // Peer B's UndeclareSubscriber id=3 -> KEPT (B's per-peer ingress has no
        // block for id 3). A single per-session ingress would wrongly drop it.
        let mut b = frame(undecl_sub);
        d.apply_namespace_ingress(SRC_B, &mut b);
        let DriverLoopOutcome::FramePayload { messages, .. } = &b else {
            panic!("framepayload")
        };
        assert_eq!(
            messages.len(),
            1,
            "B's undeclare survives — per-peer ingress isolation"
        );
    }

    /// R311y107 §5.21 routing-namespace — `apply_namespace_ingress` is a
    /// pass-through when no namespace is installed (the off path): even an
    /// out-of-namespace keyexpr survives unstripped, so a non-namespaced
    /// multicast session is byte-for-byte the pre-R311y107 behaviour.
    #[cfg(all(feature = "routing-namespace", feature = "codec-push"))]
    #[test]
    fn namespace_ingress_noop_when_unset() {
        use crate::driver_loop::DriverLoopOutcome;
        use crate::network_message::NetworkMessage;
        use alloc::boxed::Box;
        use alloc::vec;

        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);
        let mut o = DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(
                crate::push_build::build_push_literal("other/x", b"v").unwrap(),
            ))],
            has_ext: false,
            extensions: vec![],
        };
        d.apply_namespace_ingress(SRC_A, &mut o);
        let DriverLoopOutcome::FramePayload { messages, .. } = &o else {
            panic!("framepayload")
        };
        assert_eq!(
            messages.len(),
            1,
            "no namespace installed -> no strip, no drop"
        );
    }

    /// R311y107 §5.21 routing-namespace — the per-peer ingress state is CLEARED
    /// when a slot recycles (`evict()` resets `namespace_ingress` to `None`), so a
    /// new peer admitted into a recycled slot starts with empty blocked-id state.
    /// This GUARDS the load-bearing reset the per-peer design depends on: drop the
    /// reset and a recycled slot index inherits a dead peer's `blocked_*` set,
    /// silently dropping a fresh peer's valid same-id undeclare.
    #[cfg(all(feature = "routing-namespace", feature = "codec-declare"))]
    #[test]
    fn namespace_ingress_cleared_on_slot_recycle() {
        use crate::driver_loop::DriverLoopOutcome;
        use crate::keyexpr_prefix::OwnedNonWildKeyExpr;
        use crate::network_message::NetworkMessage;
        use crate::wireexpr_build::literal_wireexpr;
        use alloc::boxed::Box;
        use alloc::vec;
        use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant as DV};

        let mut d = running_dispatcher::<4>(5_000);
        d.set_namespace(OwnedNonWildKeyExpr::new("myns").expect("valid namespace"));
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);

        // Peer A blocks id=3 (an out-of-namespace DeclareSubscriber) in its ingress.
        let mut a = DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Declare(Box::new(DeclareOwned {
                header: 0,
                interest_id: None,
                extensions: None,
                body: DV::CodecZenohDeclSubscriber(
                    wz_codecs::decl_subscriber::DeclSubscriberOwned {
                        header: 0,
                        id: 3,
                        keyexpr: literal_wireexpr("other/x").unwrap(),
                    },
                ),
            }))],
            has_ext: false,
            extensions: vec![],
        };
        d.apply_namespace_ingress(SRC_A, &mut a);

        // Evict A (Close) -> the slot recycles, namespace_ingress reset to None.
        assert!(d.close_by_src(SRC_A));
        // A NEW peer reuses the recycled (lowest-free) slot — peer A's old slot.
        assert_eq!(d.ingest_join(ZID_C, SRC_C, sn0(), 0), JoinOutcome::Admitted);

        // The new peer's UndeclareSubscriber id=3 must SURVIVE: the recycled slot
        // carries no inherited block from the dead peer A. (A stale, un-reset
        // ingress would consume A's block and wrongly drop this -> len 0.)
        let mut c = DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Declare(Box::new(DeclareOwned {
                header: 0,
                interest_id: None,
                extensions: None,
                body: DV::CodecZenohUndeclSubscriber(
                    wz_codecs::undecl_subscriber::UndeclSubscriberOwned {
                        header: 0,
                        id: 3,
                        extensions: None,
                    },
                ),
            }))],
            has_ext: false,
            extensions: vec![],
        };
        d.apply_namespace_ingress(SRC_C, &mut c);
        let DriverLoopOutcome::FramePayload { messages, .. } = &c else {
            panic!("framepayload")
        };
        assert_eq!(
            messages.len(),
            1,
            "recycled slot has no inherited block -> the new peer's undeclare survives"
        );
    }

    /// R311y107b — a FramePayload carrying one out-of-namespace DeclareSubscriber
    /// `id` (blocks `id` in the per-peer ingress when stripped against a
    /// namespace it does not match).
    #[cfg(all(feature = "routing-namespace", feature = "codec-declare"))]
    fn ns_decl_sub_frame(keyexpr: &str, id: u64) -> crate::driver_loop::DriverLoopOutcome {
        use alloc::boxed::Box;
        use alloc::vec;
        use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant as DV};
        crate::driver_loop::DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: vec![crate::network_message::NetworkMessage::Declare(Box::new(
                DeclareOwned {
                    header: 0,
                    interest_id: None,
                    extensions: None,
                    body: DV::CodecZenohDeclSubscriber(
                        wz_codecs::decl_subscriber::DeclSubscriberOwned {
                            header: 0,
                            id,
                            keyexpr: crate::wireexpr_build::literal_wireexpr(keyexpr).unwrap(),
                        },
                    ),
                },
            ))],
            has_ext: false,
            extensions: vec![],
        }
    }

    /// R311y107b — a FramePayload carrying one id-only UndeclareSubscriber `id`
    /// (dropped iff `id` is still blocked in the per-peer ingress).
    #[cfg(all(feature = "routing-namespace", feature = "codec-declare"))]
    fn ns_undecl_sub_frame(id: u64) -> crate::driver_loop::DriverLoopOutcome {
        use alloc::boxed::Box;
        use alloc::vec;
        use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant as DV};
        crate::driver_loop::DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: vec![crate::network_message::NetworkMessage::Declare(Box::new(
                DeclareOwned {
                    header: 0,
                    interest_id: None,
                    extensions: None,
                    body: DV::CodecZenohUndeclSubscriber(
                        wz_codecs::undecl_subscriber::UndeclSubscriberOwned {
                            header: 0,
                            id,
                            extensions: None,
                        },
                    ),
                },
            ))],
            has_ext: false,
            extensions: vec![],
        }
    }

    /// R311y107b §5.21 routing-namespace — a re-JOIN to a KNOWN address with a
    /// DIFFERENT zid (a new peer reusing the slot before the old peer's lease
    /// expired) clears the per-peer namespace correlation, so the new peer does
    /// not inherit the dead peer's blocked-ids — the IN-PLACE twin of the
    /// evict()-recycle reset (the lifecycle gap the R311y107 session review
    /// found: SN state is JOIN-reset by seed_from_join, the namespace correlation
    /// was not). Without it the new peer's same-id undeclare is wrongly dropped.
    #[cfg(all(feature = "routing-namespace", feature = "codec-declare"))]
    #[test]
    fn namespace_ingress_reset_on_rejoin_with_new_zid() {
        use crate::driver_loop::DriverLoopOutcome;
        use crate::keyexpr_prefix::OwnedNonWildKeyExpr;

        let mut d = running_dispatcher::<4>(5_000);
        d.set_namespace(OwnedNonWildKeyExpr::new("myns").expect("valid namespace"));
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);
        // Old peer A blocks id=3 (an out-of-namespace declare).
        let mut a = ns_decl_sub_frame("other/x", 3);
        d.apply_namespace_ingress(SRC_A, &mut a);
        // A NEW peer (DIFFERENT zid) re-JOINs the SAME address before A's lease
        // expired -> the known-address branch must reset namespace_ingress.
        assert_eq!(
            d.ingest_join(ZID_B, SRC_A, sn0(), 0),
            JoinOutcome::Refreshed
        );
        // The new peer's UndeclareSubscriber id=3 must SURVIVE (no inherited block).
        let mut b = ns_undecl_sub_frame(3);
        d.apply_namespace_ingress(SRC_A, &mut b);
        let DriverLoopOutcome::FramePayload { messages, .. } = &b else {
            panic!("framepayload")
        };
        assert_eq!(
            messages.len(),
            1,
            "new-zid re-JOIN clears the dead peer's block -> the undeclare survives"
        );
    }

    /// R311y107b §5.21 routing-namespace — a SAME-zid re-JOIN (the periodic JOIN
    /// beacon of a LIVE peer) KEEPS the correlation, so a legitimate in-flight
    /// block is NOT discarded — the inverse bug an UNCONDITIONAL wipe would cause
    /// (leaking a phantom undeclare). The reset is conditional on a zid change.
    #[cfg(all(feature = "routing-namespace", feature = "codec-declare"))]
    #[test]
    fn namespace_ingress_kept_on_rejoin_same_zid() {
        use crate::driver_loop::DriverLoopOutcome;
        use crate::keyexpr_prefix::OwnedNonWildKeyExpr;

        let mut d = running_dispatcher::<4>(5_000);
        d.set_namespace(OwnedNonWildKeyExpr::new("myns").expect("valid namespace"));
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);
        let mut a = ns_decl_sub_frame("other/x", 3);
        d.apply_namespace_ingress(SRC_A, &mut a);
        // The SAME peer (same zid) re-JOINs (periodic beacon) -> correlation kept.
        assert_eq!(
            d.ingest_join(ZID_A, SRC_A, sn0(), 0),
            JoinOutcome::Refreshed
        );
        // The live peer's own UndeclareSubscriber id=3 is STILL correlated + dropped
        // (its block is legitimately in-flight; an unconditional wipe would leak it).
        let mut a2 = ns_undecl_sub_frame(3);
        d.apply_namespace_ingress(SRC_A, &mut a2);
        let DriverLoopOutcome::FramePayload { messages, .. } = &a2 else {
            panic!("framepayload")
        };
        assert_eq!(
            messages.len(),
            0,
            "same-zid re-JOIN keeps the live block -> the undeclare is still dropped"
        );
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

    /// R311ks — each peer is held for the lease ITS OWN JOIN advertised
    /// (zenoh-pico `entry->_lease`, multicast/rx.c:393; evicted against
    /// it, lease.c:124): two peers admitted at the same instant expire at
    /// different deadlines.
    #[test]
    fn sweep_holds_each_peer_per_its_advertised_lease() {
        let mut d = running_dispatcher::<4>(10_000); // cap above both
        d.ingest_join(
            ZID_A,
            SRC_A,
            JoinBaseline {
                lease_ms: 2_000,
                ..sn0()
            },
            0,
        );
        d.ingest_join(
            ZID_B,
            SRC_B,
            JoinBaseline {
                lease_ms: 8_000,
                ..sn0()
            },
            0,
        );
        // t=3_000: A (window 2_000) expires, B (window 8_000) survives.
        assert_eq!(d.sweep(3_000), 1);
        assert_eq!(d.peer_state(ZID_A), None);
        assert_eq!(d.peer_state(ZID_B), Some(MulticastPeerState::Active));
        // t=8_000: B's own deadline arrives.
        assert_eq!(d.sweep(8_000), 1);
        assert_eq!(d.active_peers(), 0);
    }

    /// R311ks — the local config bound caps the hold window: a peer
    /// advertising an absurd lease (u64::MAX) cannot pin its bounded
    /// pool slot past the cap (the deadline-model equivalent of pico's
    /// group-min sweep cadence).
    #[test]
    fn sweep_caps_advertised_lease_at_local_bound() {
        let mut d = running_dispatcher::<4>(5_000);
        d.ingest_join(
            ZID_A,
            SRC_A,
            JoinBaseline {
                lease_ms: u64::MAX,
                ..sn0()
            },
            0,
        );
        assert_eq!(d.sweep(4_999), 0, "inside the cap");
        assert_eq!(d.sweep(5_000), 1, "cap bounds the hold");
    }

    /// R311ks — a re-JOIN re-stores the advertised lease (zenoh-pico
    /// re-copies `_lease` on every JOIN, multicast/rx.c:456): the fresh
    /// advertisement governs the next deadline.
    #[test]
    fn rejoin_updates_advertised_lease() {
        let mut d = running_dispatcher::<4>(10_000);
        d.ingest_join(
            ZID_A,
            SRC_A,
            JoinBaseline {
                lease_ms: 2_000,
                ..sn0()
            },
            0,
        );
        // Re-JOIN at t=1_000 advertising a longer lease.
        assert_eq!(
            d.ingest_join(
                ZID_A,
                SRC_A,
                JoinBaseline {
                    lease_ms: 8_000,
                    ..sn0()
                },
                1_000
            ),
            JoinOutcome::Refreshed
        );
        // Old window would have expired at 3_000; the new one holds to 9_000.
        assert_eq!(d.sweep(4_000), 0);
        assert_eq!(d.sweep(9_000), 1);
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
        let baseline = JoinBaseline {
            sn_res: 0x02,
            next_sn_reliable: 42,
            next_sn_best_effort: 7,
            lease_ms: 5_000,
            #[cfg(feature = "multicast-declarations")]
            whatami: None,
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
        let baseline = JoinBaseline {
            sn_res: 0x02,
            next_sn_reliable: 10,
            next_sn_best_effort: 100,
            lease_ms: 5_000,
            #[cfg(feature = "multicast-declarations")]
            whatami: None,
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
        let baseline = JoinBaseline {
            sn_res: 0x00,
            next_sn_reliable: 0,
            next_sn_best_effort: 0,
            lease_ms: 5_000,
            #[cfg(feature = "multicast-declarations")]
            whatami: None,
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
        let rejoin = JoinBaseline {
            sn_res: 0x00,
            next_sn_reliable: 1,
            next_sn_best_effort: 0,
            lease_ms: 5_000,
            #[cfg(feature = "multicast-declarations")]
            whatami: None,
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

    // ── multicast Fragment SN gate (zenoh-pico
    //    _z_multicast_handle_fragment_inner channel-gate parity) ──

    /// A fragment from an address that never JOINed is dropped (pico
    /// "Dropping Z_FRAGMENT from unknown peer").
    #[test]
    fn fragment_from_unknown_peer_is_dropped() {
        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(
            d.ingest_fragment_by_src(SRC_A, true, 0, 0),
            FragmentIngest::UnknownPeer
        );
    }

    /// A fragment while the session is not Running is not admitted.
    #[test]
    fn fragment_refused_when_session_not_running() {
        let mut d = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        assert_eq!(
            d.ingest_fragment_by_src(SRC_A, true, 0, 0),
            FragmentIngest::SessionNotRunning
        );
    }

    /// Fragments ride the SAME per-channel SN ring as data frames (pico
    /// gates both through `_z_sn_precedes` over one `_sn_rx_sns` tracker):
    /// an admitted fragment advances the channel baseline, a replay of its
    /// SN is out of order, and a following data frame continues the ring
    /// the fragment advanced.
    #[test]
    fn fragment_gate_shares_the_frame_sn_ring() {
        let mut d = running_dispatcher::<4>(5_000);
        let baseline = JoinBaseline {
            sn_res: 0x02,
            next_sn_reliable: 42,
            next_sn_best_effort: 0,
            lease_ms: 5_000,
            #[cfg(feature = "multicast-declarations")]
            whatami: None,
        };
        assert_eq!(
            d.ingest_join(ZID_A, SRC_A, baseline, 0),
            JoinOutcome::Admitted
        );
        let admitted = d.ingest_fragment_by_src(SRC_A, true, 42, 10);
        assert!(
            matches!(admitted, FragmentIngest::Admitted { sn_mask, .. }
                if sn_mask == sn::mask_from_res(0x02)),
            "first fragment at the advertised next_sn is admitted with the peer ring mask"
        );
        assert!(
            matches!(
                d.ingest_fragment_by_src(SRC_A, true, 42, 20),
                FragmentIngest::OutOfOrder { .. }
            ),
            "duplicate fragment SN must be stale"
        );
        assert_eq!(
            d.ingest_frame_by_src(SRC_A, true, 43, 30),
            FrameIngest::Admitted,
            "a data frame continues the ring the fragment advanced"
        );
    }

    /// A stale fragment is dropped but STILL refreshes the peer's lease
    /// (pico `_received = true` precedes the SN gate — liveness is
    /// independent of data validity, same as the frame gate).
    #[test]
    fn out_of_order_fragment_still_refreshes_lease() {
        let mut d = running_dispatcher::<4>(5_000);
        d.ingest_join(ZID_A, SRC_A, sn0(), 0); // lease deadline 5_000
        assert!(matches!(
            d.ingest_fragment_by_src(SRC_A, true, 0, 100),
            FragmentIngest::Admitted { .. }
        ));
        // Replay at t=4_900: dropped, lease refreshed (deadline 9_900).
        assert!(matches!(
            d.ingest_fragment_by_src(SRC_A, true, 0, 4_900),
            FragmentIngest::OutOfOrder { .. }
        ));
        assert_eq!(d.sweep(5_200), 0, "stale fragment is still liveness");
        assert_eq!(d.sweep(10_000), 1, "lease from the replay then lapses");
    }

    /// The reliable and best-effort fragment gates are independent
    /// channels (two baselines per peer, like the frame gate).
    #[test]
    fn fragment_sn_channels_are_independent() {
        let mut d = running_dispatcher::<4>(5_000);
        let baseline = JoinBaseline {
            sn_res: 0x02,
            next_sn_reliable: 10,
            next_sn_best_effort: 100,
            lease_ms: 5_000,
            #[cfg(feature = "multicast-declarations")]
            whatami: None,
        };
        d.ingest_join(ZID_A, SRC_A, baseline, 0);
        assert!(matches!(
            d.ingest_fragment_by_src(SRC_A, true, 10, 1),
            FragmentIngest::Admitted { .. }
        ));
        assert!(matches!(
            d.ingest_fragment_by_src(SRC_A, false, 10, 2),
            FragmentIngest::OutOfOrder { .. }
        ));
        assert!(matches!(
            d.ingest_fragment_by_src(SRC_A, false, 100, 3),
            FragmentIngest::Admitted { .. }
        ));
    }

    /// `sweep_with` reports each expired peer's pool-slot index BEFORE the
    /// slot recycles — the hook the reassembly host aborts evicted peers'
    /// chains on (a recycled index must never continue a dead peer's
    /// chain).
    #[test]
    fn sweep_with_reports_evicted_slot_indices() {
        let mut d = running_dispatcher::<4>(5_000);
        d.ingest_join(ZID_A, SRC_A, sn0(), 0); // slot 0, deadline 5_000
        d.ingest_join(ZID_B, SRC_B, sn0(), 4_000); // slot 1, deadline 9_000
        let mut evicted = std::vec::Vec::new();
        assert_eq!(d.sweep_with(6_000, |idx| evicted.push(idx)), 1);
        assert_eq!(evicted, [0], "only the lapsed peer's slot is reported");
        assert_eq!(d.peer_index_by_src(SRC_B), Some(1));
        assert_eq!(d.peer_index_by_src(SRC_A), None, "evicted slot is freed");
    }

    // ── ingest_multicast_fragment — the shared multicast fragment-RX
    //    pipeline (SN gate -> chain key -> reassembly -> re-entry) ──

    #[cfg(all(feature = "reassembly", feature = "codec-push"))]
    mod fragment_pipeline {
        use super::*;
        use crate::driver_loop::{DriverLoopOutcome, IterationEvent, ReassemblyDropReason};
        use crate::frame_encode::encode_frame_with_push;
        use crate::inbound::{parse_inbound, InboundFrame};
        use crate::network_message::NetworkMessage;
        use crate::push_build::build_push_literal;
        use crate::reassembly_dispatch::{ReassemblyConfig, ReassemblyDispatcher};
        use std::vec::Vec;

        /// The serialized NetworkMessage batch a data frame would carry —
        /// the bytes TX-side fragmentation splits. Built through the
        /// production encoders (push -> frame -> parse back the payload)
        /// so the fixture cannot drift from the wire shape.
        fn push_batch_bytes(keyexpr: &str, payload: &[u8]) -> Vec<u8> {
            let push = build_push_literal(keyexpr, payload).expect("push fixture");
            let frame = encode_frame_with_push(0, push, true);
            let Ok(InboundFrame::Frame { payload, .. }) = parse_inbound(&frame) else {
                panic!("frame fixture must parse");
            };
            payload
        }

        fn reasm() -> ReassemblyDispatcher<4, 4096> {
            ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000))
        }

        /// Events captured from the pipeline: completed FramePayload
        /// batches (cloned out of the borrow) + drop reasons.
        #[derive(Default)]
        struct Captured {
            payloads: Vec<(bool, u64, usize)>,
            drops: Vec<ReassemblyDropReason>,
        }

        fn capture(cap: &mut Captured) -> impl FnMut(IterationEvent<'_>) + '_ {
            |event| match event {
                IterationEvent::Poll(DriverLoopOutcome::FramePayload {
                    reliable,
                    sn,
                    messages,
                    ..
                }) => cap.payloads.push((*reliable, *sn, messages.len())),
                IterationEvent::ReassemblyDropped(reason) => cap.drops.push(reason),
                _ => {}
            }
        }

        /// A two-fragment chain over multicast reassembles and re-enters
        /// the frame-payload decode: the observer sees ONE FramePayload
        /// carrying the Push batch, and the channel ring advanced across
        /// both fragment SNs (a following frame continues it).
        #[test]
        fn two_fragment_chain_delivers_frame_payload() {
            let mut d = running_dispatcher::<4>(5_000);
            let baseline = JoinBaseline {
                sn_res: 0x02,
                next_sn_reliable: 5,
                next_sn_best_effort: 0,
                lease_ms: 5_000,
                #[cfg(feature = "multicast-declarations")]
                whatami: None,
            };
            d.ingest_join(ZID_A, SRC_A, baseline, 0);
            let mut r = reasm();

            let batch = push_batch_bytes("demo/mc", b"reassembled-over-multicast");
            let (head, tail) = batch.split_at(batch.len() / 2);

            let mut cap = Captured::default();
            {
                let mut on_event = capture(&mut cap);
                ingest_multicast_fragment(
                    &mut d,
                    &mut r,
                    SRC_A,
                    true,
                    5,
                    true,
                    head,
                    0,
                    &mut on_event,
                );
                ingest_multicast_fragment(
                    &mut d,
                    &mut r,
                    SRC_A,
                    true,
                    6,
                    false,
                    tail,
                    1,
                    &mut on_event,
                );
            }
            assert_eq!(
                cap.payloads,
                [(true, 6, 1)],
                "exactly one reassembled FramePayload (1-message Push batch, final-fragment SN)"
            );
            assert!(cap.drops.is_empty());
            assert_eq!(r.active_chains(), 0, "slot reclaimed after completion");
            assert_eq!(
                d.ingest_frame_by_src(SRC_A, true, 7, 2),
                FrameIngest::Admitted,
                "the channel ring advanced across both fragment SNs"
            );
        }

        /// The reassembled bytes decode as the original Push network
        /// message (content check, not just counts).
        #[test]
        fn reassembled_payload_is_the_push_batch() {
            let mut d = running_dispatcher::<4>(5_000);
            d.ingest_join(ZID_A, SRC_A, sn0(), 0);
            let mut r = reasm();
            let batch = push_batch_bytes("demo/mc", b"content-pin");
            let (head, tail) = batch.split_at(3);

            let mut saw_push = false;
            {
                let mut on_event = |event: IterationEvent<'_>| {
                    if let IterationEvent::Poll(DriverLoopOutcome::FramePayload {
                        messages, ..
                    }) = event
                    {
                        assert!(matches!(&messages[0], NetworkMessage::Push(_)));
                        saw_push = true;
                    }
                };
                ingest_multicast_fragment(
                    &mut d,
                    &mut r,
                    SRC_A,
                    true,
                    0,
                    true,
                    head,
                    0,
                    &mut on_event,
                );
                ingest_multicast_fragment(
                    &mut d,
                    &mut r,
                    SRC_A,
                    true,
                    1,
                    false,
                    tail,
                    1,
                    &mut on_event,
                );
            }
            assert!(saw_push, "the reassembled batch decodes as the Push");
        }

        /// A non-consecutive continuation (gap inside the half-window:
        /// passes the channel gate, fails the chain gate) aborts the chain
        /// and surfaces ReassemblyDropped(OutOfOrder).
        #[test]
        fn gap_continuation_aborts_chain_with_drop_event() {
            let mut d = running_dispatcher::<4>(5_000);
            d.ingest_join(ZID_A, SRC_A, sn0(), 0);
            let mut r = reasm();
            let mut cap = Captured::default();
            {
                let mut on_event = capture(&mut cap);
                ingest_multicast_fragment(
                    &mut d,
                    &mut r,
                    SRC_A,
                    true,
                    0,
                    true,
                    b"head",
                    0,
                    &mut on_event,
                );
                // SN jumps 0 -> 2 (admitted by the half-window channel gate,
                // non-consecutive for the chain).
                ingest_multicast_fragment(
                    &mut d,
                    &mut r,
                    SRC_A,
                    true,
                    2,
                    false,
                    b"tail",
                    1,
                    &mut on_event,
                );
            }
            assert!(cap.payloads.is_empty(), "aborted chain must not deliver");
            assert_eq!(cap.drops, [ReassemblyDropReason::OutOfOrder]);
            assert_eq!(r.active_chains(), 0);
        }

        /// A channel-gate rejection (stale / replayed fragment SN) aborts
        /// the channel's in-progress chain silently (pico clears the dbuf
        /// and logs; the fragment never reaches the Router).
        #[test]
        fn stale_fragment_aborts_channel_chain() {
            let mut d = running_dispatcher::<4>(5_000);
            d.ingest_join(ZID_A, SRC_A, sn0(), 0);
            let mut r = reasm();
            let mut cap = Captured::default();
            {
                let mut on_event = capture(&mut cap);
                ingest_multicast_fragment(
                    &mut d,
                    &mut r,
                    SRC_A,
                    true,
                    0,
                    true,
                    b"head",
                    0,
                    &mut on_event,
                );
                assert_eq!(r.active_chains(), 1);
                // Replay of SN 0: channel-gate reject -> chain aborted.
                ingest_multicast_fragment(
                    &mut d,
                    &mut r,
                    SRC_A,
                    true,
                    0,
                    true,
                    b"head",
                    1,
                    &mut on_event,
                );
            }
            assert_eq!(r.active_chains(), 0, "channel reject clears the chain");
            assert!(cap.payloads.is_empty() && cap.drops.is_empty());
        }

        /// A fragment from an address that never JOINed opens no chain and
        /// fans no event.
        #[test]
        fn unknown_peer_fragment_opens_no_chain() {
            let mut d = running_dispatcher::<4>(5_000);
            let mut r = reasm();
            let mut cap = Captured::default();
            {
                let mut on_event = capture(&mut cap);
                ingest_multicast_fragment(
                    &mut d,
                    &mut r,
                    SRC_A,
                    true,
                    0,
                    true,
                    b"x",
                    0,
                    &mut on_event,
                );
            }
            assert_eq!(r.active_chains(), 0);
            assert!(cap.payloads.is_empty() && cap.drops.is_empty());
        }

        /// Two peers' chains are independent: the slot-index chain key
        /// separates same-channel chains from different source addresses
        /// (the same-zid-two-addresses hazard the zid key would collide).
        #[test]
        fn chains_are_keyed_per_peer_slot() {
            let mut d = running_dispatcher::<4>(5_000);
            // SAME zid at two addresses — two peers, two chains.
            d.ingest_join(ZID_A, SRC_A, sn0(), 0);
            d.ingest_join(ZID_A, SRC_B, sn0(), 0);
            let mut r = reasm();
            let mut cap = Captured::default();
            {
                let mut on_event = capture(&mut cap);
                ingest_multicast_fragment(
                    &mut d,
                    &mut r,
                    SRC_A,
                    true,
                    0,
                    true,
                    b"a",
                    0,
                    &mut on_event,
                );
                ingest_multicast_fragment(
                    &mut d,
                    &mut r,
                    SRC_B,
                    true,
                    0,
                    true,
                    b"b",
                    0,
                    &mut on_event,
                );
            }
            assert_eq!(r.active_chains(), 2, "one chain per peer slot");
            assert!(cap.drops.is_empty(), "no cross-peer chain interference");
        }
    }

    /// §5.21 router-multicast-faces (I3a) — a peer's `DeclKexpr` populates its
    /// per-peer alias table so a subsequent id-only `Push` is rewritten to the
    /// declared literal BEFORE the fan; the downstream literal-only sentinel
    /// face then resolves it against an EMPTY table. Lifts the I1 literal-only
    /// restriction, per peer.
    #[cfg(feature = "multicast-declarations")]
    #[test]
    fn declared_alias_resolves_inbound_push_to_literal() {
        use crate::declare_build::build_declare_kexpr;
        use crate::driver_loop::DriverLoopOutcome;
        use crate::network_message::NetworkMessage;
        use crate::push_build::build_push_aliased;
        use crate::wireexpr_resolve::resolve_wireexpr;
        use alloc::boxed::Box;
        use alloc::string::{String, ToString};
        use alloc::vec;

        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);

        // Peer A declares id 5 -> "demo/keyexpr", then publishes an id-only Push(5).
        let mut outcome = DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: vec![
                NetworkMessage::Declare(Box::new(build_declare_kexpr(5, "demo/keyexpr").unwrap())),
                NetworkMessage::Push(Box::new(build_push_aliased(5, None, b"payload").unwrap())),
            ],
            has_ext: false,
            extensions: vec![],
        };
        d.apply_declared_aliases(SRC_A, &mut outcome);

        let DriverLoopOutcome::FramePayload { messages, .. } = &outcome else {
            unreachable!()
        };
        let NetworkMessage::Push(push) = &messages[1] else {
            panic!("expected the Push at index 1");
        };
        let empty: hashbrown::HashMap<u64, String> = hashbrown::HashMap::new();
        assert_eq!(
            resolve_wireexpr(&push.keyexpr.body, &empty),
            Some("demo/keyexpr".to_string()),
            "declared alias must rewrite the id-only Push to its literal keyexpr",
        );
        // The header N (suffix-present) bit MUST be set in sync with the now
        // suffix-bearing literal keyexpr — else `reliteralize_push`'s
        // already-literal shortcut forwards a malformed Push (N clear, suffix
        // present) that desyncs the subscriber's decoder.
        assert_ne!(
            push.header & 0x20,
            0,
            "re-literalized Push must carry the header N bit (keyexpr/header in sync)",
        );
    }

    /// §5.21 router-multicast-faces (I3a) — an id-only `Push` with NO prior
    /// `DeclKexpr` from that peer is left untouched (unresolvable against an
    /// empty table), exactly as the I1 literal-only plane dropped it: aliasing
    /// lifts the restriction ONLY for genuinely-declared ids.
    #[cfg(feature = "multicast-declarations")]
    #[test]
    fn undeclared_alias_stays_unresolved() {
        use crate::driver_loop::DriverLoopOutcome;
        use crate::network_message::NetworkMessage;
        use crate::push_build::build_push_aliased;
        use crate::wireexpr_resolve::resolve_wireexpr;
        use alloc::boxed::Box;
        use alloc::string::String;
        use alloc::vec;

        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);

        let mut outcome = DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(
                build_push_aliased(7, None, b"payload").unwrap(),
            ))],
            has_ext: false,
            extensions: vec![],
        };
        d.apply_declared_aliases(SRC_A, &mut outcome);

        let DriverLoopOutcome::FramePayload { messages, .. } = &outcome else {
            unreachable!()
        };
        let NetworkMessage::Push(push) = &messages[0] else {
            panic!("expected a Push");
        };
        let empty: hashbrown::HashMap<u64, String> = hashbrown::HashMap::new();
        assert_eq!(
            resolve_wireexpr(&push.keyexpr.body, &empty),
            None,
            "an undeclared alias must stay id-only (dropped by the sentinel resolution, as in I1)",
        );
    }

    /// §5.21 router-multicast-faces (I3a) — evicting a peer (Close / lease)
    /// clears its alias table, so a recycled slot never resolves a new peer's
    /// id-only `Push` against a dead peer's declaration (wz reclaims where zenoh
    /// leaks the mcast_faces shell).
    #[cfg(feature = "multicast-declarations")]
    #[test]
    fn evict_clears_peer_aliases() {
        use crate::declare_build::build_declare_kexpr;
        use crate::driver_loop::DriverLoopOutcome;
        use crate::network_message::NetworkMessage;
        use crate::push_build::build_push_aliased;
        use crate::wireexpr_resolve::resolve_wireexpr;
        use alloc::boxed::Box;
        use alloc::string::String;
        use alloc::vec;

        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);

        // Peer A declares id 5, then departs (Close -> evict).
        let mut decl = DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Declare(Box::new(
                build_declare_kexpr(5, "demo/keyexpr").unwrap(),
            ))],
            has_ext: false,
            extensions: vec![],
        };
        d.apply_declared_aliases(SRC_A, &mut decl);
        assert!(d.close_by_src(SRC_A), "peer A must evict");

        // Peer A rejoins the recycled slot and publishes the SAME id 5 — with no
        // fresh DeclKexpr it must NOT resolve against the dead declaration.
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);
        let mut outcome = DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(
                build_push_aliased(5, None, b"payload").unwrap(),
            ))],
            has_ext: false,
            extensions: vec![],
        };
        d.apply_declared_aliases(SRC_A, &mut outcome);

        let DriverLoopOutcome::FramePayload { messages, .. } = &outcome else {
            unreachable!()
        };
        let NetworkMessage::Push(push) = &messages[0] else {
            panic!("expected a Push");
        };
        let empty: hashbrown::HashMap<u64, String> = hashbrown::HashMap::new();
        assert_eq!(
            resolve_wireexpr(&push.keyexpr.body, &empty),
            None,
            "the recycled slot must NOT inherit peer A's id-5 alias",
        );
    }

    /// §5.21 router-multicast-faces (I3a) — the per-peer alias table is capped:
    /// an unauthenticated multicast peer cannot flood distinct-id DeclKexpr to
    /// exhaust memory. Growth past the cap is rejected while an in-cap alias
    /// keeps resolving (the table stays usable + drainable).
    #[cfg(feature = "multicast-declarations")]
    #[test]
    fn per_peer_alias_table_is_capped() {
        use crate::declare_build::build_declare_kexpr;
        use crate::driver_loop::DriverLoopOutcome;
        use crate::network_message::NetworkMessage;
        use crate::push_build::build_push_aliased;
        use crate::wireexpr_resolve::resolve_wireexpr;
        use alloc::boxed::Box;
        use alloc::string::{String, ToString};
        use alloc::{format, vec};

        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);

        // Fill the cap with distinct-id DeclKexpr (ids 1..=MAX_ALIASES_PER_PEER).
        let mut fill = vec![];
        for id in 1..=MAX_ALIASES_PER_PEER as u64 {
            fill.push(NetworkMessage::Declare(Box::new(
                build_declare_kexpr(id, &format!("demo/{id}")).unwrap(),
            )));
        }
        let mut b0 = DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: fill,
            has_ext: false,
            extensions: vec![],
        };
        d.apply_declared_aliases(SRC_A, &mut b0);

        // One id PAST the cap (new growth) + Pushes for the over-cap id and an
        // in-cap id. Growth is rejected; the in-cap alias still resolves.
        let over = MAX_ALIASES_PER_PEER as u64 + 1;
        let mut b1 = DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 1,
            messages: vec![
                NetworkMessage::Declare(Box::new(
                    build_declare_kexpr(over, "demo/overflow").unwrap(),
                )),
                NetworkMessage::Push(Box::new(build_push_aliased(over, None, b"x").unwrap())),
                NetworkMessage::Push(Box::new(build_push_aliased(1, None, b"x").unwrap())),
            ],
            has_ext: false,
            extensions: vec![],
        };
        d.apply_declared_aliases(SRC_A, &mut b1);

        let DriverLoopOutcome::FramePayload { messages, .. } = &b1 else {
            unreachable!()
        };
        let empty: hashbrown::HashMap<u64, String> = hashbrown::HashMap::new();
        let NetworkMessage::Push(p_over) = &messages[1] else {
            panic!("expected the over-cap Push at index 1");
        };
        assert_eq!(
            resolve_wireexpr(&p_over.keyexpr.body, &empty),
            None,
            "an alias declared past the per-peer cap must be rejected (unresolved)",
        );
        let NetworkMessage::Push(p_in) = &messages[2] else {
            panic!("expected the in-cap Push at index 2");
        };
        assert_eq!(
            resolve_wireexpr(&p_in.keyexpr.body, &empty),
            Some("demo/1".to_string()),
            "an in-cap alias must still resolve after the cap is reached",
        );
    }

    // ---- §5.21 router-multicast-faces (sub plane, S1) — per-peer sub ingest ----

    /// A JOIN baseline carrying an explicit `whatami` (the sub-plane tests need a
    /// Client-role peer to prove the sub union is whatami-agnostic).
    #[cfg(feature = "multicast-declarations")]
    fn sn0_whatami(w: WhatAmI) -> JoinBaseline {
        JoinBaseline {
            whatami: Some(w),
            ..sn0()
        }
    }

    /// A literal `DeclareSubscriber(id, ke)` network message.
    #[cfg(feature = "multicast-declarations")]
    fn decl_sub_literal(id: u64, ke: &str) -> crate::network_message::NetworkMessage {
        use crate::network_message::NetworkMessage;
        use alloc::boxed::Box;
        use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant as DV};
        NetworkMessage::Declare(Box::new(DeclareOwned {
            header: 0,
            interest_id: None,
            extensions: None,
            body: DV::CodecZenohDeclSubscriber(wz_codecs::decl_subscriber::DeclSubscriberOwned {
                header: 0,
                id,
                keyexpr: crate::wireexpr_build::literal_wireexpr(ke).unwrap(),
            }),
        }))
    }

    /// An ALIASED `DeclareSubscriber(id)` whose keyexpr references the declared
    /// alias `alias_id` (Sender/Local mapping) with an optional trailing suffix.
    #[cfg(feature = "multicast-declarations")]
    fn decl_sub_aliased(
        id: u64,
        alias_id: u64,
        suffix: Option<&str>,
    ) -> crate::network_message::NetworkMessage {
        use crate::network_message::NetworkMessage;
        use alloc::boxed::Box;
        use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant as DV};
        use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};
        use wz_codecs::wireexpr_local::WireexprLocalOwned;
        let keyexpr = WireexprOwned {
            body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                id: alias_id,
                suffix_len: suffix.map(|s| s.len() as u64),
                suffix: suffix.map(|s| crate::codec_owned::owned_string::<128>(s).unwrap()),
            }),
        };
        NetworkMessage::Declare(Box::new(DeclareOwned {
            header: 0,
            interest_id: None,
            extensions: None,
            body: DV::CodecZenohDeclSubscriber(wz_codecs::decl_subscriber::DeclSubscriberOwned {
                header: 0,
                id,
                keyexpr,
            }),
        }))
    }

    /// An id-only `UndeclareSubscriber(id)` (wz undeclare bodies carry no keyexpr).
    #[cfg(feature = "multicast-declarations")]
    fn undecl_sub(id: u64) -> crate::network_message::NetworkMessage {
        use crate::network_message::NetworkMessage;
        use alloc::boxed::Box;
        use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant as DV};
        NetworkMessage::Declare(Box::new(DeclareOwned {
            header: 0,
            interest_id: None,
            extensions: None,
            body: DV::CodecZenohUndeclSubscriber(
                wz_codecs::undecl_subscriber::UndeclSubscriberOwned {
                    header: 0,
                    id,
                    extensions: None,
                },
            ),
        }))
    }

    /// Drive a message batch through the two ingress passes the RX seam runs (alias
    /// resolution then sub ingest), attributed to `src` — the whole-Frame seam
    /// mirror.
    #[cfg(feature = "multicast-declarations")]
    fn drive_batch<const N: usize>(
        d: &mut MulticastDispatcher<N>,
        src: SocketAddr,
        msgs: alloc::vec::Vec<crate::network_message::NetworkMessage>,
    ) {
        use crate::driver_loop::DriverLoopOutcome;
        let mut outcome = DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: msgs,
            has_ext: false,
            extensions: alloc::vec![],
        };
        d.apply_declared_aliases(src, &mut outcome);
        d.apply_declared_subscriptions(src, &outcome);
    }

    /// A literal `DeclareSubscriber` is recorded in the peer's remote-sub table and
    /// surfaces in the group aggregate.
    #[cfg(feature = "multicast-declarations")]
    #[test]
    fn mcast_sub_ingest_records_literal_sub() {
        use alloc::string::ToString;
        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);
        drive_batch(&mut d, SRC_A, alloc::vec![decl_sub_literal(3, "demo/data")]);
        assert_eq!(d.group_sub_keyexprs(), alloc::vec!["demo/data".to_string()]);
    }

    /// An ALIASED `DeclareSubscriber` resolves against the peer's `keyexpr_table`
    /// (populated by the prior alias pass in the same batch) and is stored as its
    /// literal — proving the ordering (sub ingest AFTER alias absorb).
    #[cfg(feature = "multicast-declarations")]
    #[test]
    fn mcast_sub_ingest_resolves_alias() {
        use crate::declare_build::build_declare_kexpr;
        use alloc::boxed::Box;
        use alloc::string::ToString;
        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);
        // DeclKexpr 7 -> "demo/data", then a sub aliased on id 7 (no suffix).
        drive_batch(
            &mut d,
            SRC_A,
            alloc::vec![
                crate::network_message::NetworkMessage::Declare(Box::new(
                    build_declare_kexpr(7, "demo/data").unwrap(),
                )),
                decl_sub_aliased(3, 7, None),
            ],
        );
        assert_eq!(
            d.group_sub_keyexprs(),
            alloc::vec!["demo/data".to_string()],
            "an aliased sub must be stored as its resolved literal",
        );
    }

    /// An id-only `UndeclareSubscriber` removes the correlated sub (the wz undeclare
    /// carries no keyexpr, so the id keying is load-bearing).
    #[cfg(feature = "multicast-declarations")]
    #[test]
    fn mcast_sub_undeclare_removes() {
        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);
        drive_batch(&mut d, SRC_A, alloc::vec![decl_sub_literal(3, "demo/data")]);
        assert_eq!(d.group_sub_keyexprs().len(), 1);
        drive_batch(&mut d, SRC_A, alloc::vec![undecl_sub(3)]);
        assert!(
            d.group_sub_keyexprs().is_empty(),
            "an id-only undeclare must remove the correlated sub",
        );
    }

    /// Evicting a peer drops its subs from the aggregate, and a recycled slot never
    /// inherits a dead peer's subscriptions (the derive-not-store withdraw path —
    /// wz reclaims where zenoh leaks the mcast_faces shell).
    #[cfg(feature = "multicast-declarations")]
    #[test]
    fn mcast_sub_evict_clears_and_recycles() {
        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);
        drive_batch(&mut d, SRC_A, alloc::vec![decl_sub_literal(3, "demo/data")]);
        assert_eq!(d.group_sub_keyexprs().len(), 1);
        assert!(d.close_by_src(SRC_A), "peer A must evict");
        assert!(
            d.group_sub_keyexprs().is_empty(),
            "evict drops the peer's subs from the aggregate",
        );
        // A new peer takes the recycled slot and declares nothing — it must not
        // inherit peer A's sub.
        assert_eq!(d.ingest_join(ZID_B, SRC_A, sn0(), 1), JoinOutcome::Admitted);
        assert!(
            d.group_sub_keyexprs().is_empty(),
            "a recycled slot inherits no dead peer's subscription",
        );
    }

    /// §5.21 router-multicast-faces (IMPL-review C-1/C-2) — the IN-PLACE recycle the
    /// `evict()` clear does NOT cover: a NEW peer reusing the SAME src with a
    /// DIFFERENT zid (before the old peer's lease expires) must not inherit the dead
    /// peer's group subscriptions (a phantom mesh advertisement that never withdraws)
    /// NOR its keyexpr aliases (a mis-resolution / group blackhole). The multicast
    /// mirror of the namespace `namespace_ingress = None` in-place guard.
    #[cfg(feature = "multicast-declarations")]
    #[test]
    fn mcast_in_place_rejoin_with_new_zid_drops_dead_peer_declarations() {
        use crate::declare_build::build_declare_kexpr;
        use alloc::boxed::Box;
        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);
        // Peer Z_A declares alias id 7 -> "demo/aliased" AND subscribes "demo/data".
        drive_batch(
            &mut d,
            SRC_A,
            alloc::vec![
                crate::network_message::NetworkMessage::Declare(Box::new(
                    build_declare_kexpr(7, "demo/aliased").unwrap(),
                )),
                decl_sub_literal(3, "demo/data"),
            ],
        );
        assert_eq!(d.group_sub_keyexprs().len(), 1);

        // Peer Z_B re-JOINs the SAME src (a DIFFERENT zid, NO evict — the in-place
        // recycle). It must not inherit Z_A's per-peer declaration state.
        assert_eq!(
            d.ingest_join(ZID_B, SRC_A, sn0(), 1),
            JoinOutcome::Refreshed
        );
        assert!(
            d.group_sub_keyexprs().is_empty(),
            "the recycled slot must not advertise the dead peer's subscription (C-1)"
        );
        // Z_A's alias id 7 must NOT resolve for Z_B: an id-7 aliased sub is now
        // unresolvable (empty table) -> dropped, not mis-resolved to "demo/aliased".
        drive_batch(&mut d, SRC_A, alloc::vec![decl_sub_aliased(9, 7, None)]);
        assert!(
            d.group_sub_keyexprs().is_empty(),
            "the dead peer's alias id 7 must not resolve for the recycled peer (C-2)"
        );
    }

    /// The sub union is whatami-AGNOSTIC: a Client-role peer's sub is advertised
    /// even though it is NOT a Designated-Router candidate — the DR-candidate set
    /// (`router_member_zids`, Router-only) and the subscriber set are different.
    #[cfg(feature = "multicast-declarations")]
    #[test]
    fn mcast_sub_union_is_whatami_agnostic() {
        use alloc::string::ToString;
        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(
            d.ingest_join(ZID_A, SRC_A, sn0_whatami(WhatAmI::Client), 0),
            JoinOutcome::Admitted
        );
        drive_batch(&mut d, SRC_A, alloc::vec![decl_sub_literal(3, "demo/data")]);
        assert_eq!(
            d.group_sub_keyexprs(),
            alloc::vec!["demo/data".to_string()],
            "a Client subscriber's sub is advertised (whatami-agnostic)",
        );
        assert!(
            d.router_member_zids().is_empty(),
            "a Client peer is NOT a DR candidate — the two sets differ",
        );
    }

    /// Two peers subscribing the SAME keyexpr collapse to ONE aggregate entry (the
    /// forwarder union-refcounts, so the relayed set is deduped).
    #[cfg(feature = "multicast-declarations")]
    #[test]
    fn mcast_sub_union_dedups_across_peers() {
        use alloc::string::ToString;
        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);
        assert_eq!(d.ingest_join(ZID_B, SRC_B, sn0(), 0), JoinOutcome::Admitted);
        drive_batch(
            &mut d,
            SRC_A,
            alloc::vec![decl_sub_literal(3, "demo/shared")],
        );
        drive_batch(
            &mut d,
            SRC_B,
            alloc::vec![decl_sub_literal(9, "demo/shared")],
        );
        assert_eq!(
            d.group_sub_keyexprs(),
            alloc::vec!["demo/shared".to_string()],
            "the same keyexpr from two peers is one aggregate bubble",
        );
    }

    /// The per-peer sub table is capped: an unauthenticated peer cannot flood
    /// distinct-id `DeclSubscriber` to exhaust memory; removals still flow.
    #[cfg(feature = "multicast-declarations")]
    #[test]
    fn mcast_sub_table_is_capped() {
        use alloc::format;
        use alloc::string::ToString;
        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);
        let mut fill = alloc::vec![];
        for id in 1..=MAX_SUBS_PER_PEER as u64 {
            fill.push(decl_sub_literal(id, &format!("demo/{id}")));
        }
        drive_batch(&mut d, SRC_A, fill);
        assert_eq!(d.group_sub_keyexprs().len(), MAX_SUBS_PER_PEER);
        // One id past the cap is rejected (new growth).
        drive_batch(
            &mut d,
            SRC_A,
            alloc::vec![decl_sub_literal(
                MAX_SUBS_PER_PEER as u64 + 1,
                "demo/overflow"
            )],
        );
        assert_eq!(
            d.group_sub_keyexprs().len(),
            MAX_SUBS_PER_PEER,
            "an over-cap sub is rejected",
        );
        assert!(
            !d.group_sub_keyexprs()
                .contains(&"demo/overflow".to_string()),
            "the over-cap keyexpr is not stored",
        );
        // A removal still flows even at the cap (the table stays drainable).
        drive_batch(&mut d, SRC_A, alloc::vec![undecl_sub(1)]);
        assert_eq!(
            d.group_sub_keyexprs().len(),
            MAX_SUBS_PER_PEER - 1,
            "a removal flows at the cap",
        );
    }

    /// A sub declared on an alias the peer NEVER declared resolves to `None` and is
    /// DROPPED (never stored / advertised) — mirroring the literal-only Push drop.
    #[cfg(feature = "multicast-declarations")]
    #[test]
    fn mcast_sub_unresolvable_alias_dropped() {
        let mut d = running_dispatcher::<4>(5_000);
        assert_eq!(d.ingest_join(ZID_A, SRC_A, sn0(), 0), JoinOutcome::Admitted);
        // Alias id 9 was never declared via DeclKexpr -> unresolvable -> dropped.
        drive_batch(&mut d, SRC_A, alloc::vec![decl_sub_aliased(3, 9, None)]);
        assert!(
            d.group_sub_keyexprs().is_empty(),
            "an unresolvable aliased sub is dropped, not stored id-only",
        );
    }
}
