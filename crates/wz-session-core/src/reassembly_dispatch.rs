// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311im — the reassembly Router (dispatcher) that drives N
//! engine-free slot FSMs (`reassembly-fsm--prose-sketch` §2.3).
//!
//! [`wz_session_core::reassembly_slot`](crate::reassembly_slot) is ONE
//! slot's protocol FSM (Empty -> Receiving -> Complete / Aborted /
//! TimedOut), codegen'd engine-free from
//! `sources/network/reassembly_slot.scxml`. This module is the Rust
//! *Router* the scxml header describes: it holds the N slot
//! [`Engine`] instances and owns everything the
//! engine-free FSM cannot — the stateful SN-consecutiveness arithmetic,
//! the per-peer quota, the staging arena, and the deadline clock.
//!
//! ## Division of labour (scxml header / §2.3 / §2.5)
//!
//! - **SN counting + classification — the Router.** A native FSM guard may
//!   reference `_event.data` fields and literals only, never stored state,
//!   so the chain's expected-next-SN comparison cannot be a guard. The
//!   Router resolves in-order-ness and routes a chain-starting fragment to
//!   a free (Empty) slot, an in-order continuation to that chain's
//!   Receiving slot, and aborts a non-consecutive continuation
//!   (`fragment.ooo`) — strict in-order parity, §2.5 / OQ-W21 option 2.
//!   The ring that "consecutive" is judged on is the caller's ([`SnRing`]):
//!   a reader that never saw the handshake passes none, and only a step of
//!   plain `+1` — consecutive on every ring — is then admitted.
//! - **The wire `more` bit — the event the Router raises.** An in-order
//!   fragment with M set is `fragment.more` and one with M clear is
//!   `fragment.last`, so the slot FSM splits Continue (stay Receiving) from
//!   Final (-> Complete) by its transitions, and no slot event carries a
//!   payload.
//! - **Storage — the Router; staging — the slot machine's duties.** The
//!   Router owns the arena ([`ChainStaging`]) and each slot's handle into
//!   it, because the payload never flows through the FSM. What the
//!   Router does with them is decided by the machine: every
//!   `<sce:action effect="duty">` of `reassembly_slot.scxml` is the one
//!   cause of its effect (below).
//!
//! ## Duties (docs/adr/0038 in SCE)
//!
//! The generated [`ReassemblySlotActions`] are bound to `SlotBinding`, whose
//! bodies post the duty they name into a one-byte outbox. The Router drives
//! the slot engine one event at a time and drains the outbox right after,
//! then performs exactly the duties the machine's transition ran, and derives
//! the [`IngestOutcome`] from them:
//!
//! | duty | the Router's act |
//! |---|---|
//! | `begin_chain` | bind the reserved staging, arm key / SN / deadline, stage the first payload (unless `finalize_message` of the same transition does) |
//! | `append_fragment_payload` | stage the payload, advance the chain's SN |
//! | `finalize_message` | stage the final payload, deliver, then raise `slot.release` |
//! | `abort_ooo` / `abort_peer_drop` / `abort_evicted` / `abort_codec` | raise `slot.release` |
//! | `reset_slot` | return the staging to the arena, clear key / SN / deadline |
//!
//! `record_timeout` is a notice and posts nothing: the deadline is the
//! Router's clock, and the sweep raises `slot.release` after it.
//!
//! What the Router checks before it drives the machine is only what decides
//! which event to send: the per-peer quota and a free slot (refusals that
//! never reach a slot, unless the pool's [`PoolOverflow`] policy makes room),
//! the arena's reservation for a chain that would start (`acquire`, refused
//! as [`RefuseReason::PoolExhausted`]), and whether the payload fits the
//! chain ([`ChainStaging::fits`]): a continuation that would not fit is sent
//! as `codec.error`, a first fragment that would not fit is
//! [`AbortReason::CapacityOverflow`] with the machine untouched.
//!
//! ## When the machine or the arena answers outside its contract
//!
//! Nothing the Router does after driving a slot is asserted. A slot machine
//! that does not answer an event as `reassembly_slot.scxml` does, or an arena
//! whose `append` refuses bytes its `fits` admitted, ends the chain it was
//! serving with an [`IngestOutcome`] the caller already handles (the cases
//! are on [`AbortReason::CapacityOverflow`] and [`RefuseReason::PoolExhausted`])
//! and puts the slot back in service with a fresh machine. A panic there would
//! end the process on an MCU, and its message and location would sit in every
//! image for a path no chart transition reaches.
//!
//! The outbox is an `AtomicU8` because the generated policy hands its host
//! back by shared reference only, so draining it is a store through `&`. The
//! drain is a plain load then a plain store, no read-modify-write: the target
//! set includes `thumbv6m`, which has no atomic RMW, and every access happens
//! under the Router's own `&mut self`, so the pair cannot race. A `Cell` would
//! do the same and make the slot table `!Sync`, which a statically placed MCU
//! table cannot be.
//!
//! ## Timeout ownership (§4)
//!
//! The slot FSM arms no timer (codegen'd `--no-std`, `type Hal =
//! NoOpHal`, so a `<send delay>` is a dead element). The Router owns the
//! clock: each active slot carries a `deadline` (armed at chain start to
//! `now + reassembly_timeout_ms`); [`ReassemblyDispatcher::sweep`] raises
//! `reassembly.timeout` into only the slots past deadline (a reused slot
//! never sees a stale deadline). Mirrors the session FSM's
//! [`crate::session_timeouts`] split: value = spec, transition =
//! statechart, clock = runtime.
//!
//! ## Profiles
//!
//! `const SLOTS` (`slot_count`) and `const CAP` (`slot_size`) are the
//! per-deploy pool dimensions (§4; §7.3 recommends `slot_size >=
//! max_fragments * mtu_bytes`). The runtime knobs `per_peer_quota` /
//! `reassembly_timeout_ms` are deploy-sourced ([`ReassemblyConfig`]); the
//! deploy.yaml plumbing is deferred (the caller passes spec values today,
//! mirroring [`crate::session_timeouts`]). Everything here is no-alloc:
//! the slot array is inline, the staging buffers are `BoundedVec`, and the
//! one `--no-std` codegen emit drives both the std (AP) and heapless (MCU)
//! `sce-rust-runtime`.

use crate::chain_staging::{BuildsOwnStorage, ChainStaging, HeapStaging};
use crate::qos::Priority;
use crate::reassembly_slot::{ReassemblySlotActions, ReassemblySlotEvent, ReassemblySlotPolicy};
use core::sync::atomic::{AtomicU8, Ordering};
use sce_rust_runtime::helpers::session_id::SessionId;
use sce_rust_runtime::Engine;

/// The id every reassembly slot machine is built under (SCE ADR 0045: the host gives a machine
/// its id, and the generated constructor refuses a text that is not an XML Nmtoken). A constant,
/// so that refusal is never met.
const REASSEMBLY_SLOT_SESSION_ID: SessionId = sce_rust_runtime::session_id!("wz-reassembly-slot");
// R311mh — `sweep_reporting` (below) raises an IterationEvent on a timed-out
// chain; the event surface is the `driver_loop` module's, which a storage profile
// (heap or per-session slot) compiles, so the reporting wrapper is gated on that
// within this reassembly-gated module.
#[cfg(feature = "storage-profile")]
use crate::driver_loop::IterationEvent;

/// A completed chain's bytes, as the Router delivers them (ARCHITECTURE
/// section 9.3: the event carries the stage buffer).
///
/// - [`ChainBytes::Borrowed`] is the chain where it was staged, BORROWED for
///   the length of the delivery call: the staging is reclaimed the moment the
///   call returns, so nothing decoded out of it may keep pointing there. This
///   is the synchronous dispatch's contract, and every arena can answer it.
/// - [`ChainBytes::Lent`] (only where frames can be shared, `rx-shared-bytes`)
///   is the staging itself handed up as shared storage: what is decoded out of
///   it is a range of it, and it goes home when the last range drops. An arena
///   answers it when it can ([`ChainStaging::lend`]); the pooled arena lends
///   its slot, the heap arena moves its buffer, so neither copies the chain.
/// - [`ChainBytes::Kept`] is the chain's buffer taken out of the staging and
///   handed to the delivery, which holds it for as long as it reads what was
///   decoded out of it: no chain stages into it until the delivery drops it.
///   An arena answers it when it can ([`ChainStaging::keep`]).
pub enum ChainBytes<'a> {
    /// Borrowed from the staging for the delivery call only.
    Borrowed(&'a [u8]),
    /// The staging itself, shared; it outlives the call.
    #[cfg(feature = "rx-shared-bytes")]
    Lent(crate::link::RxBytes),
    /// The chain's buffer, the delivery's until it drops it.
    Kept(crate::byte_cells::KeptBytes),
}

impl ChainBytes<'_> {
    /// The chain's bytes.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            ChainBytes::Borrowed(bytes) => bytes,
            #[cfg(feature = "rx-shared-bytes")]
            ChainBytes::Lent(bytes) => bytes.as_slice(),
            ChainBytes::Kept(bytes) => bytes.as_slice(),
        }
    }
}

/// How a completed chain is handed to its delivery ([`ChainBytes`]): what the ingest asks of the
/// arena, which answers borrowed when it cannot do what is asked.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Hand {
    /// Borrowed for the call.
    Borrow,
    /// Lent as shared storage ([`ChainStaging::lend`]); borrowed where frames are not shared.
    Lend,
    /// Kept by the delivery ([`ChainStaging::keep`]).
    Keep,
}

/// Maximum peer-key byte length: sized to the widest key a transport
/// feeds the chain key — the unicast peer ZID (a zenoh ZID is up to 16
/// bytes; the wire form is length-prefixed); the multicast pool-slot key
/// ([`crate::multicast_dispatch::multicast_chain_key`]) is 4 bytes. The
/// chain key copies the peer key into a fixed buffer so the Router holds
/// no allocation per chain.
pub(crate) const PEER_KEY_MAX: usize = 16;

/// Whose chains a Router holds: what a chain's key keeps of its peer, and whether a full pool is
/// made room in by ending another chain ([`PoolOverflow`]).
///
/// [`ManyPeers`] is a Router the links of several peers share: a chain is keyed by its peer as
/// well as its channel, each peer is held to [`ReassemblyConfig::per_peer_quota`] apart, and a
/// full pool's policy may end the oldest open chain for a new one. [`OnePeer`] is a Router every
/// chain of which is one peer's, as a session's is while it holds a single link: a chain is keyed
/// by its channel alone, the quota counts every open chain, and neither the peer nor the order the
/// chains began in is kept.
///
/// The two answer every fragment of one peer alike while the quota is no more than the slots, so
/// that a full pool is the peer at its quota. Past that, [`OnePeer`] refuses a start a full pool
/// has no slot for, under every policy, as [`PoolOverflow::Reject`] does.
pub trait ChainPeers {
    /// Whether a chain's key tells peers apart. A caller of a Router whose key does not need not
    /// read the peer key it hands in.
    const KEYED: bool;
    /// What a chain's key keeps of its peer.
    type Peer;
    /// What an open chain keeps of when it began: the order [`PoolOverflow::OldestWins`] picks the
    /// chain it ends by.
    type Opened: Copy + Ord;
    /// The [`Self::Opened`] of a Router's first chain.
    const FIRST: Self::Opened;
    /// What a chain's key keeps of `peer_key`.
    fn peer(peer_key: &[u8]) -> Self::Peer;
    /// Whether `peer_key` names the peer a chain's key kept as `peer`.
    fn is(peer: &Self::Peer, peer_key: &[u8]) -> bool;
    /// The [`Self::Opened`] of the chain begun after one that began at `opened`.
    fn after(opened: Self::Opened) -> Self::Opened;
}

/// A Router the links of several peers share ([`ChainPeers`]), what a Router is unless its type
/// names another.
#[derive(Debug, Clone, Copy)]
pub struct ManyPeers;

impl ChainPeers for ManyPeers {
    const KEYED: bool = true;
    type Peer = PeerKey;
    /// How many chains the Router had begun before this one: a count and not the deadline, which
    /// chains begun on the same millisecond share.
    type Opened = u64;
    const FIRST: u64 = 0;

    fn peer(peer_key: &[u8]) -> PeerKey {
        PeerKey::new(peer_key)
    }

    fn is(peer: &PeerKey, peer_key: &[u8]) -> bool {
        peer.is(peer_key)
    }

    fn after(opened: u64) -> u64 {
        opened.wrapping_add(1)
    }
}

/// A Router every chain of which is one peer's ([`ChainPeers`]): a session's while the session
/// holds a single link. Nothing of the peer is kept, so every chain is the peer's and
/// [`ReassemblyDispatcher::abort_peer`] ends them all.
#[derive(Debug, Clone, Copy)]
pub struct OnePeer;

impl ChainPeers for OnePeer {
    const KEYED: bool = false;
    type Peer = ();
    type Opened = ();
    const FIRST: () = ();

    fn peer(_peer_key: &[u8]) -> Self::Peer {}

    fn is(_peer: &(), _peer_key: &[u8]) -> bool {
        true
    }

    fn after(_opened: ()) -> Self::Opened {}
}

/// What a [`ManyPeers`] chain's key keeps of its peer: the first `PEER_KEY_MAX` bytes of the peer
/// key, held in a fixed buffer so the Router holds no allocation per chain.
#[derive(Debug, Clone, Copy)]
pub struct PeerKey {
    bytes: [u8; PEER_KEY_MAX],
    len: u8,
}

impl PeerKey {
    fn new(peer_key: &[u8]) -> Self {
        let kept = Self::kept(peer_key);
        let mut bytes = [0u8; PEER_KEY_MAX];
        if let Some(to) = bytes.get_mut(..kept.len()) {
            to.copy_from_slice(kept);
        }
        Self {
            bytes,
            // At most `PEER_KEY_MAX`, which a `u8` holds.
            len: kept.len() as u8,
        }
    }

    /// The bytes of `peer_key` a key holds: its first `PEER_KEY_MAX`.
    fn kept(peer_key: &[u8]) -> &[u8] {
        peer_key.get(..PEER_KEY_MAX).unwrap_or(peer_key)
    }

    /// Compared as slices, by length and bytes: a held prefix built to compare whole would cost
    /// an array copy at every lookup.
    fn is(&self, peer_key: &[u8]) -> bool {
        self.bytes.get(..usize::from(self.len)) == Some(Self::kept(peer_key))
    }
}

/// Deploy-sourced reassembly runtime knobs (§4 `buffer_pools.reassembly_pool`).
///
/// The pool DIMENSIONS (`slot_count` / `slot_size`) are the
/// [`ReassemblyDispatcher`] const generics; these are the per-tick
/// behavioural knobs. No `Default`: a zero `reassembly_timeout_ms` would
/// expire every chain on the first sweep and a zero `per_peer_quota` would
/// refuse every chain, so the caller constructs explicitly (mirrors
/// [`crate::session_timeouts::SessionTimeouts`]'s no-`Default` policy).
/// The deploy.yaml plumbing that sources these is a follow-up; callers
/// pass spec values today.
#[derive(Debug, Clone, Copy)]
pub struct ReassemblyConfig {
    /// Maximum concurrently-open chains per peer key. The §5.M
    /// malicious-peer pool-exhaustion defence: a peer opening a chain it
    /// never finishes cannot occupy more than this many slots. Quota
    /// rejection takes precedence over slot availability (§5.M
    /// "quota-first").
    pub per_peer_quota: u16,
    /// Per-chain reassembly deadline window in milliseconds. Armed at
    /// chain start; [`ReassemblyDispatcher::sweep`] aborts a chain that
    /// has not completed within the window (RFC 815 GC analogue, §4).
    pub reassembly_timeout_ms: u64,
    /// R311y578 — honour the Fragment chain-boundary markers
    /// ([`crate::extfragment`]: `0x2 First` / `0x3 Drop`). zenoh gates the
    /// identical block on the NEGOTIATED protocol patch level
    /// (`patch.has_fragmentation_markers()`,
    /// `io/zenoh-transport/src/unicast/universal/rx.rs:155`), so this is
    /// not a deploy preference — it is a per-session wire fact, resolved
    /// from the peer's Init ([`crate::extpatch::negotiate_patch`]) and
    /// pushed in with
    /// [`ReassemblyDispatcher::set_fragmentation_markers`] once the
    /// handshake settles.
    ///
    /// `false` is the pre-R311y578 behaviour and the correct behaviour
    /// against a patch-0 peer, which emits no markers: enforcing the rules
    /// against one would refuse every chain it sends.
    pub fragmentation_markers: bool,
    /// The largest message a chain may reach, in bytes: the deploy's
    /// `transport/link/rx/max_message_size`
    /// ([`crate::session_init_params::LinkRxConf`]). A fragment whose bytes
    /// would take its chain past it ends the chain as
    /// [`AbortReason::CapacityOverflow`], as upstream's defragmentation buffer
    /// ends one past its capacity
    /// (`io/zenoh-transport/src/common/defragmentation.rs` @
    /// `if new_len > self.capacity {`).
    ///
    /// A bound beside the slot's `CAP`, not instead of it: the smaller of the
    /// two holds, so a value above `CAP` is read as `CAP`. `usize::MAX`, what
    /// [`Self::new`] sets, leaves `CAP` the only bound.
    pub max_message_bytes: usize,
    /// What a chain start does when every slot holds an open chain
    /// (docs/reassembly-fsm.md §2.3 `on_overflow`). Consulted only after the
    /// per-peer quota admitted the start: quota refusal takes precedence over
    /// pool pressure (§5.M quota-first).
    pub pool_overflow: PoolOverflow,
}

impl ReassemblyConfig {
    /// Construct an explicit config. See the field docs for the
    /// no-`Default` rationale. Chain-boundary markers start OFF — the
    /// negotiated patch level is not known until the handshake completes,
    /// and the dispatcher is built before it (see
    /// [`Self::with_fragmentation_markers`] /
    /// [`ReassemblyDispatcher::set_fragmentation_markers`]). A full pool
    /// refuses a new chain ([`PoolOverflow::Reject`]).
    pub const fn new(per_peer_quota: u16, reassembly_timeout_ms: u64) -> Self {
        Self {
            per_peer_quota,
            reassembly_timeout_ms,
            fragmentation_markers: false,
            max_message_bytes: usize::MAX,
            pool_overflow: PoolOverflow::Reject,
        }
    }

    /// Builder form of [`Self::pool_overflow`].
    pub const fn with_pool_overflow(mut self, policy: PoolOverflow) -> Self {
        self.pool_overflow = policy;
        self
    }

    /// Builder form of [`Self::max_message_bytes`].
    pub const fn with_max_message_bytes(mut self, bytes: usize) -> Self {
        self.max_message_bytes = bytes;
        self
    }

    /// Builder form of [`Self::fragmentation_markers`], for a caller that
    /// already knows the negotiated level at construction time (a test, or
    /// a passive reader replaying a capture whose handshake it has already
    /// parsed).
    pub const fn with_fragmentation_markers(mut self, on: bool) -> Self {
        self.fragmentation_markers = on;
        self
    }
}

/// Why the Router aborted an in-progress chain (the slot FSM's `Aborted`
/// state, reached via one of the abort transitions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortReason {
    /// A continuation arrived whose SN was not the chain's expected next
    /// SN — strict in-order policy aborts the chain (§2.5, `fragment.ooo`).
    OutOfOrder,
    /// Staging the fragment would exceed the slot's `CAP` (`slot_size`) —
    /// the §7.1 reassembly-capacity hard error (`codec.error`).
    ///
    /// Also the word for a fragment the slot could not take at all: an arena
    /// that refused bytes its `fits` admitted, or a slot machine that did not
    /// answer the fragment as its chart does. Either is the slot failing to
    /// hold the chain, and neither moves
    /// [`ReassemblyDispatcher::capacity_refusals`], which counts the configured
    /// bound only.
    CapacityOverflow,
    /// R311y578 — the SENDER announced it abandoned the chain: a fragment
    /// carrying the `0x3 Drop` marker ([`crate::extfragment`]). The slot
    /// FSM's `fragment.drop` -> `Aborted` arm (`abort_peer_drop`) fires,
    /// which is the transition the statechart has declared since R311im
    /// and no Router code raised until this round.
    ///
    /// Distinct from [`Self::OutOfOrder`] on purpose: out-of-order is a
    /// receiver-side inference about SNs, whereas this is the sender
    /// SAYING SO on the wire. A passive reader needs the two apart —
    /// the first is a lossy link, the second is a healthy sender whose TX
    /// pipeline could not obtain a batch mid-fragmentation
    /// (`io/zenoh-transport/src/common/pipeline.rs:400-404`).
    SenderDropped,
    /// R311y578 — a fragment carrying the `0x2 First` marker arrived while
    /// a chain was already open on the same `(peer, reliable, priority)`
    /// key. The sender restarted; the staged bytes are a stranded prefix
    /// and are discarded before the new chain begins (zenoh
    /// `guard.defrag.clear()` on `ext_first.is_some()`).
    ///
    /// The `duplicate-first` reason of docs/reassembly-fsm.md §2.4.6, taken
    /// through the slot FSM's `slot.evict` arm (`abort_evicted`). It names
    /// the chain that was evicted, not the fragment that evicted it, whose
    /// ingest reports its own admission; the Router reports the evicted chain
    /// beside that admission as [`DisplacedChain::Superseded`].
    Superseded,
    /// A continuation arrived whose SN is not the chain's last SN plus one, and
    /// the caller does not know the SN ring ([`SnRing::Unknown`]), so the router
    /// cannot say whether the step is a wrap, a gap or a repeat.
    ///
    /// Distinct from [`Self::OutOfOrder`] on purpose: that is the router's
    /// judgement on a ring it knows, and this is its refusal to judge on one it
    /// does not. A reader that conflated the two would report a chain as lost
    /// to a lossy link when all it can say is that it cannot follow it. See
    /// [`SnRing::admits`] for the rule, and for why only a step of exactly `+1`
    /// is accepted without the ring.
    Unresolvable,
}

/// Why the Router refused a chain-starting fragment before allocating a
/// slot (the fragment is dropped; no slot FSM is involved).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefuseReason {
    /// The peer already holds `per_peer_quota` open chains (§5.M
    /// quota-first; the pool-exhaustion defence).
    PeerQuota,
    /// Every slot is occupied by another peer's in-progress chain, and the
    /// pool's [`PoolOverflow`] policy refuses rather than evicts; under
    /// [`OnePeer`], by the peer's own chains, past a quota above the slots.
    ///
    /// Also the word for a start the free slot it found could not take: the
    /// arena had no reservation left for it, or the slot's machine did not
    /// begin the chain as its chart does (the slot is then given a fresh
    /// machine and serves the next start).
    PoolExhausted,
    /// R311y578 — the fragment would START a chain but carries no `0x2
    /// First` marker, on a session whose negotiated patch level demands
    /// one ([`ReassemblyConfig::fragmentation_markers`]). zenoh drops it
    /// with "First fragment received without start marker"
    /// (`unicast/universal/rx.rs:158-163`).
    ///
    /// This is the rule that separates a PARTICIPANT from an OBSERVER. A
    /// participant that joined at session start sees every chain from its
    /// first fragment, so the case looks like corruption. A reader that
    /// attached to a live flow mid-chain sees it constantly, and staging
    /// the headless tail would hand the upstream decoder a message that
    /// begins in the middle of a network message.
    MissingStartMarker,
}

/// What a chain start does when every slot of the pool holds an open chain:
/// the `on_overflow` policy of docs/reassembly-fsm.md §2.3.
///
/// Upstream has no such branch: zenoh and zenoh-pico keep one defragmentation
/// buffer per peer and channel, so a new chain never waits on another peer's.
/// wz shares a bounded pool of `SLOTS` among all peers, and this is what the
/// deploy chooses for the moment it is full. Setting `SLOTS` to twice the peer
/// table's capacity keeps the moment from arising.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolOverflow {
    /// Refuse the new chain ([`RefuseReason::PoolExhausted`]); the open chains
    /// are untouched. What the Router has always done, and the default.
    Reject,
    /// Refuse the new chain as [`Self::Reject`] does, and log each refusal as
    /// a warning naming the policy (`reassembly/slot-pool-full`), for a deploy
    /// that wants the pressure in its log and not only in its counters.
    DiagnosticEvent,
    /// End the open chain that began earliest through its slot's `slot.evict`
    /// arm and begin the new chain in that slot. The ended chain is reported
    /// beside the new chain's outcome as [`DisplacedChain::Evicted`]. Favours
    /// the newest traffic: a chain that stalls is the one evicted first,
    /// before its deadline would have ended it.
    OldestWins,
}

impl PoolOverflow {
    /// The value a build's `reassembly-pool-overflow` policy
    /// ([`crate::policy::SessionPolicy::reassembly_pool_overflow`]) names. The
    /// hosts that build a Router from their buffer-pool constants pass the
    /// build's policy through this.
    pub const fn of_policy(policy: crate::policy::ReassemblyPoolOverflow) -> Self {
        use crate::policy::ReassemblyPoolOverflow;
        match policy {
            ReassemblyPoolOverflow::Reject => Self::Reject,
            ReassemblyPoolOverflow::DiagnosticEvent => Self::DiagnosticEvent,
            ReassemblyPoolOverflow::OldestWins => Self::OldestWins,
        }
    }
}

/// An open chain that an ingest ended for a fragment that was not of it.
///
/// The ingest's [`IngestOutcome`] is the fragment's own; this is the other
/// chain the same fragment ended, read with
/// [`ReassemblyDispatcher::displaced_by_last_ingest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplacedChain {
    /// A `0x2 First` restarted the chain open on its own key, whose staged
    /// prefix is discarded ([`AbortReason::Superseded`], §2.4.6
    /// duplicate-first).
    Superseded,
    /// The pool was full and its [`PoolOverflow::OldestWins`] policy ended
    /// the oldest open chain, of whichever peer, to take its slot (§2.4.6
    /// oldest-wins eviction).
    Evicted,
}

/// Outcome of one [`ReassemblyDispatcher::ingest`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    /// First fragment of a chain accepted into a fresh slot (Empty ->
    /// Receiving). More fragments expected.
    Begun,
    /// In-order continuation accepted; the chain stays open (Receiving ->
    /// Receiving).
    Continued,
    /// Final fragment accepted (Receiving -> Complete); the reassembled
    /// message was handed to the `deliver` closure and the slot reclaimed.
    Reassembled,
    /// The chain was aborted (-> Aborted) and the slot reclaimed.
    Aborted(AbortReason),
    /// The chain-starting fragment was refused before slot allocation.
    Refused(RefuseReason),
}

/// What the caller knows of the SN ring a chain's continuations are judged on.
///
/// "Consecutive" is a statement about a ring: `127 -> 0` is one step on a 7-bit
/// ring and a jump of `2^28 - 127` on the 28-bit one. A participant negotiated
/// its ring in the handshake and always knows it. A passive reader that attached
/// after the handshake read no InitAck, and does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnRing {
    /// The ring's mask is known, at the width the wire carries
    /// ([`crate::sn::wire::mask_from_res`]): a participant's own ring and the
    /// ring an observer read of a peer, which may be wider than any the build's
    /// sessions run. A continuation is admitted iff its SN is ring-consecutive
    /// to the chain's last ([`crate::sn::wire::consecutive`]).
    Known(u64),
    /// The ring is not known. A continuation is admitted iff its SN is exactly
    /// the chain's last plus one as plain integers; anything else ends the chain
    /// as [`AbortReason::Unresolvable`].
    Unknown,
}

impl SnRing {
    /// Judge the step from a chain's last SN to the next fragment's.
    ///
    /// # Why `+1` is accepted without a ring, and nothing else is
    ///
    /// A step of exactly one is consecutive on EVERY ring: for any mask of one
    /// or more bits `(last + 1 - last) & mask` is 1. Accepting it therefore says
    /// something about all the rings the reader might have missed, and is not a
    /// guess at one. Any other step is consecutive on some rings and not on
    /// others (`127 -> 0` is a wrap on the 7-bit ring), or on none (a gap, a
    /// repeat), and telling which takes the ring. The router does not make the
    /// finer judgement for the steps that no ring would accept: a chain it cannot
    /// follow is reported as one it cannot follow, and the reader is not told the
    /// link was lossy, which is a claim about a ring it never saw.
    pub fn admits(self, last: u64, next: u64) -> Result<(), AbortReason> {
        match self {
            // The chain keeps the SNs the wire carried, and a known ring is judged at the wire's
            // width, as a reader that knows no ring compares them whole.
            Self::Known(mask) if crate::sn::wire::consecutive(mask, last, next) => Ok(()),
            Self::Known(_) => Err(AbortReason::OutOfOrder),
            Self::Unknown if last.checked_add(1) == Some(next) => Ok(()),
            Self::Unknown => Err(AbortReason::Unresolvable),
        }
    }
}

/// A decoded inbound transport Fragment (`T_MID_FRAGMENT`, MID `0x06`)
/// ready for the Router. Groups the per-fragment inputs so
/// [`ReassemblyDispatcher::ingest`] takes one descriptor rather than a
/// long positional argument list.
#[derive(Debug, Clone, Copy)]
pub struct Fragment<'a> {
    /// Peer identity key from the link/session context (NOT the fragment
    /// body) — half of the §2.3 chain key, which a Router of one peer's chains
    /// ([`OnePeer`]) does not read. Unicast feeds the peer ZID;
    /// multicast feeds the pool-slot index key
    /// ([`crate::multicast_dispatch::multicast_chain_key`]) — there the
    /// wire zid is attacker-chosen and the source address owns identity,
    /// hence the transport-neutral name (R311kp rename from `zid`).
    pub peer_key: &'a [u8],
    /// Transport-header R bit (`FLAG_T_FRAGMENT_R`); the other half of the
    /// chain key (a peer's reliable and best-effort fragment streams are
    /// independent chains).
    pub reliable: bool,
    /// VLE sequence number from the fragment body; the Router checks
    /// consecutiveness against the chain's expected next SN.
    pub sn: u64,
    /// Transport-header M bit (`FLAG_T_FRAGMENT_M`): `0` = final fragment,
    /// non-zero = more follow. The slot FSM guards Continue vs Final on it.
    pub more: u8,
    /// The fragment body bytes (`sources/codecs/fragment.scxml` tail
    /// payload), staged into the chain's slot buffer.
    pub payload: &'a [u8],
    /// R311y215 — the QoS priority projected from the fragment's `ext_qos`
    /// (id `0x1`); the third component of the §2.3 chain key under
    /// `transport-qos`, so a peer's `high` and `low` fragment streams are
    /// independent chains (a QoS chain's fragments all carry the same
    /// priority). [`Priority::DEFAULT`] for a pre-QoS / multicast chain, which
    /// collapses the key to the pre-QoS (peer, reliable) form.
    pub priority: Priority,
    /// R311y578 — the chain-boundary markers projected from this fragment's
    /// own ext chain (`0x2 First` / `0x3 Drop`,
    /// [`crate::extfragment::project_markers`]). Two bits rather than the
    /// owned ext chain, so the descriptor stays `Copy` and alloc-free on the
    /// MCU profile.
    ///
    /// Read ONLY when [`ReassemblyConfig::fragmentation_markers`] is on —
    /// the negotiated patch level decides whether the peer emits them at
    /// all. [`crate::extfragment::FragmentMarkers::NONE`] is the
    /// marker-less descriptor a patch-0 peer, a multicast join, or a
    /// hand-built test fragment carries.
    pub markers: crate::extfragment::FragmentMarkers,
}

/// The duties a slot transition can post, one bit each. The four abort arms
/// share one bit: what the Router does for each is the same release, and the
/// reason it reports is its own classification of the event it raised.
mod duty {
    pub(super) const BEGIN: u8 = 1 << 0;
    pub(super) const APPEND: u8 = 1 << 1;
    pub(super) const FINALIZE: u8 = 1 << 2;
    pub(super) const ABORT: u8 = 1 << 3;
    pub(super) const RESET: u8 = 1 << 4;
}

/// Host binding for the generated [`ReassemblySlotActions`]: each duty body
/// posts its bit into `duties`, and the Router performs the duty when it
/// drains the outbox after driving the engine (the module's "Duties" table).
/// A body that does not post is a duty the Router never performs.
#[derive(Debug, Default)]
struct SlotBinding {
    duties: AtomicU8,
}

impl SlotBinding {
    fn post(&mut self, bit: u8) {
        *self.duties.get_mut() |= bit;
    }

    /// Drain the outbox. A load and a store rather than a swap: see the
    /// module docs for why no read-modify-write is used.
    fn take(&self) -> u8 {
        let duties = self.duties.load(Ordering::Relaxed);
        self.duties.store(0, Ordering::Relaxed);
        duties
    }

    /// What is posted and not yet drained.
    #[cfg(test)]
    fn pending(&self) -> u8 {
        self.duties.load(Ordering::Relaxed)
    }
}

impl ReassemblySlotActions for SlotBinding {
    // docs/adr/0038: every duty body below posts the effect its name states,
    // and the Router performs a duty only when its bit is drained.
    const REALIZATION: ::sce_rust_runtime::ActionRealization =
        ::sce_rust_runtime::ActionRealization::Performs;

    fn begin_chain(&mut self) {
        self.post(duty::BEGIN);
    }
    fn append_fragment_payload(&mut self) {
        self.post(duty::APPEND);
    }
    fn finalize_message(&mut self) {
        self.post(duty::FINALIZE);
    }
    fn abort_ooo(&mut self) {
        self.post(duty::ABORT);
    }
    fn abort_peer_drop(&mut self) {
        self.post(duty::ABORT);
    }
    fn abort_evicted(&mut self) {
        self.post(duty::ABORT);
    }
    fn abort_codec(&mut self) {
        self.post(duty::ABORT);
    }
    // A notice: the sweep that raised the timeout releases the slot itself,
    // so nothing waits on this.
    fn record_timeout(&mut self) {}
    fn reset_slot(&mut self) {
        self.post(duty::RESET);
    }
}

/// The chain key: a fragment chain is identified by (peer key, reliable
/// channel, priority) per §2.3. Two distinct reliability channels from the same
/// peer are independent chains (the R bit is part of the §5.M chain key
/// alongside the peer key); R311y215 adds the QoS priority as the third
/// component so a peer's `high` and `low` fragment streams — carried on separate
/// per-priority SN conduits (`[crate::sn::RxConduits]`) — reassemble
/// independently. Under a non-QoS session every fragment is
/// [`Priority::DEFAULT`], collapsing the key to the pre-QoS (peer, reliable)
/// form (identical behavior). What the key keeps of the peer is the Router's
/// [`ChainPeers::Peer`]: nothing, where every chain is one peer's.
struct ChainKey<P: ChainPeers> {
    peer: P::Peer,
    reliable: bool,
    priority: Priority,
}

impl<P: ChainPeers> ChainKey<P> {
    fn new(peer_key: &[u8], reliable: bool, priority: Priority) -> Self {
        Self {
            peer: P::peer(peer_key),
            reliable,
            priority,
        }
    }

    fn same_peer(&self, peer_key: &[u8]) -> bool {
        P::is(&self.peer, peer_key)
    }

    fn matches(&self, peer_key: &[u8], reliable: bool, priority: Priority) -> bool {
        self.reliable == reliable && self.priority == priority && self.same_peer(peer_key)
    }
}

/// The Router's half of the chain a slot holds: everything that exists only
/// while the slot's machine is out of `Empty`, held as one value so a slot
/// cannot hold a key without its staging, or the reverse.
struct OpenChain<C, P: ChainPeers> {
    key: ChainKey<P>,
    /// The last in-order SN staged into this chain. A continuation is
    /// admitted iff it is consecutive to this on the caller's [`SnRing`]
    /// ([`crate::sn::consecutive`] at the caller-passed mask when the ring is
    /// known, plain `+1` when it is not) — the zenoh-pico `_sn_rx_*` tracker shape
    /// (rx.c stores the accepted `msg->_sn` and compares
    /// `_z_sn_consecutive` against it), replacing the R311ka F-5 unmasked
    /// `next_sn` `==` that diverged at the ring seam.
    last_sn: u64,
    /// Absolute monotonic-ms instant this chain times out.
    deadline_ms: u64,
    /// When this chain began among the Router's: the order
    /// [`PoolOverflow::OldestWins`] picks its victim by ([`ChainPeers::Opened`]).
    opened: P::Opened,
    /// R311y589 — this chain's staging handle, vended by the Router's arena
    /// ([`crate::chain_staging::ChainStaging`]);
    /// [`ChainStaging::available`](crate::chain_staging::ChainStaging::available)
    /// is what catches a handle leaked or released twice.
    ///
    /// It used to be a `BoundedVec<u8, CAP>` inline. The bytes still land in a
    /// growable heap buffer under the default arena — what moved is WHO decides
    /// that, so a deterministic deploy can reserve the arena up front instead.
    chain: C,
}

/// One reassembly slot: the engine-free protocol FSM plus the Router-owned
/// chain state.
struct Slot<
    const SLOTS: usize,
    const CAP: usize,
    S: ChainStaging<SLOTS, CAP>,
    P: ChainPeers = ManyPeers,
> {
    engine: Engine<ReassemblySlotPolicy<SlotBinding>>,
    /// `Some` while the slot holds a chain (FSM in `Receiving`, or in
    /// `Complete` until the delivery's release); `None` when free (FSM ==
    /// Empty).
    open: Option<OpenChain<S::Chain, P>>,
}

/// A slot's machine.
type SlotEngine = Engine<ReassemblySlotPolicy<SlotBinding>>;

/// Build a slot machine in `cell` and enter its initial `Empty` leaf (W3C SCXML 3.3).
///
/// Not generic over the Router and out of line, so every Router type and every place a slot is
/// built or put back in service share one copy of the machine's start, and the machine is written
/// where the slot keeps it rather than built on a stack and moved there.
#[inline(never)]
fn start_slot_engine(cell: &mut core::mem::MaybeUninit<SlotEngine>) {
    Engine::new_in_place(
        cell,
        ReassemblySlotPolicy::new_with_checked_session_id(
            REASSEMBLY_SLOT_SESSION_ID,
            SlotBinding::default(),
        ),
    )
    .initialize()
    .unwrap_or_else(|never| match never {});
}

/// Post `event` to a slot machine, run the macrostep it starts, and drain the duties its
/// transition ran (none when the current state does not answer it).
///
/// The one way into a slot machine after its start: every input a slot sends comes through here,
/// so the machine's turn is compiled once for every Router type and every caller, as its start is
/// in [`start_slot_engine`]. A second way in would carry a second copy of the turn. No slot event
/// carries a payload (the chart's payload type is `()`): the wire `more` bit is which event is
/// posted. The chart has no `<final>` state, so a started machine runs until it is dropped and no
/// input meets a stopped one.
#[inline(never)]
fn turn_slot_engine(engine: &mut SlotEngine, event: ReassemblySlotEvent) -> u8 {
    engine.raise_external_typed(event, ());
    engine.step();
    engine.policy().actions().take()
}

impl<const SLOTS: usize, const CAP: usize, S: ChainStaging<SLOTS, CAP>, P: ChainPeers>
    Slot<SLOTS, CAP, S, P>
{
    /// A free slot, built in `cell` where the Router keeps it. Whatever `cell` held is not
    /// dropped.
    fn init_in(cell: &mut core::mem::MaybeUninit<Self>) -> &mut Self {
        use core::ptr::addr_of_mut;
        let at = cell.as_mut_ptr();
        // Names every field of the slot with no `..`, so a field added to the struct stops this from
        // compiling until it is written below too.
        let _every_field_is_written = |slot: &Self| {
            let Self { engine: _, open: _ } = slot;
        };
        // SAFETY: `at` points at storage for one slot that holds no value. The machine is written
        // in its field by `start_slot_engine` and the chain state beside it, every field the list
        // above names. With both written the slot is whole.
        unsafe {
            start_slot_engine(
                &mut *addr_of_mut!((*at).engine).cast::<core::mem::MaybeUninit<SlotEngine>>(),
            );
            addr_of_mut!((*at).open).write(None);
            &mut *at
        }
    }

    /// A free slot as a value, for the tests that drive one slot without its Router.
    #[cfg(test)]
    fn new() -> Self {
        let mut cell = core::mem::MaybeUninit::uninit();
        Self::init_in(&mut cell);
        // SAFETY: `init_in` wrote the whole slot.
        unsafe { cell.assume_init() }
    }

    fn is_free(&self) -> bool {
        self.open.is_none()
    }

    /// Send `event` to the slot engine and drain the duties its transition
    /// ran (none when the current state does not answer the event).
    fn drive(&mut self, event: ReassemblySlotEvent) -> u8 {
        turn_slot_engine(&mut self.engine, event)
    }

    /// Send an in-order fragment as the event its wire `more` bit names and drain the duties its
    /// transition ran.
    fn drive_chunk(&mut self, more: u8) -> u8 {
        self.drive(chunk_event(more))
    }

    /// Raise `slot.release` and perform `reset_slot` if the machine ran it:
    /// return the chain's staging to the arena and clear the chain state.
    /// Returns whether it ran; only the terminal states answer the event.
    ///
    /// R311y589 — takes the arena because releasing the staging is part of
    /// releasing the slot, and it has to be: on a reserved arena the handle IS
    /// the reservation, so a slot that went Empty while still holding one would
    /// shrink the arena permanently. Passing it in rather than reaching for it
    /// keeps `Slot` ignorant of the Router.
    fn release(&mut self, staging: &mut S) -> bool {
        if self.drive(ReassemblySlotEvent::SlotRelease) & duty::RESET == 0 {
            return false;
        }
        if let Some(open) = self.open.take() {
            staging.release(open.chain);
        }
        true
    }

    /// Put the slot back in service when its machine answered an event outside
    /// its chart: the chain's staging goes back to the arena and the machine is
    /// replaced by a fresh one at `Empty`.
    ///
    /// No transition of `reassembly_slot.scxml` leads here; `duty_tests` checks
    /// every answer the Router relies on, transition by transition. The path
    /// exists so that a machine and a Router that disagree cost the chain they
    /// were serving, not the process and not the slot for the rest of the
    /// session.
    fn replace(&mut self, staging: &mut S) {
        if let Some(open) = self.open.take() {
            staging.release(open.chain);
        }
        let cell =
            core::ptr::addr_of_mut!(self.engine).cast::<core::mem::MaybeUninit<SlotEngine>>();
        // SAFETY: the machine is whole, so dropping it is sound, and its field is then storage
        // that holds no value, which `start_slot_engine` fills with a whole machine before it
        // returns. Nothing between the drop and the write can unwind: the machine's start cannot
        // fail. The chain state was emptied above, as a fresh slot's is.
        unsafe {
            core::ptr::drop_in_place(cell.cast::<SlotEngine>());
            start_slot_engine(&mut *cell);
        }
    }

    /// Take the slot out of service as `ending` says, the chain's staging back to the arena
    /// whichever way: reset in place when the machine reaches a terminal state and answers
    /// `slot.release` there ([`Self::release`]), replaced ([`Self::replace`]) when it does not.
    ///
    /// The one way a slot leaves service, out of line: a delivery, a refused stage, an abort and
    /// a sweep all end a chain, and each that held the release and the replacement inline carried
    /// its own copy of both. The machine's turn stays behind [`turn_slot_engine`], so this adds
    /// no copy of it.
    #[inline(never)]
    fn end(&mut self, staging: &mut S, ending: SlotEnding) {
        let released = match ending {
            SlotEnding::Release => self.release(staging),
            SlotEnding::Abort(event) => {
                self.drive(event) & duty::ABORT != 0 && self.release(staging)
            }
            SlotEnding::Replace => false,
        };
        if !released {
            self.replace(staging);
        }
    }
}

/// What judging one fragment leaves to do: its outcome, and the chain it ends when it ends one.
///
/// Each judgement that ends a chain names the ending here rather than ending it, so the one
/// ingest walk ends every such chain at one site
/// ([`ReassemblyDispatcher::ingest_delivering`]).
#[derive(Clone, Copy, Debug)]
enum Judged {
    /// The fragment's outcome; no chain is ended by it.
    Outcome(IngestOutcome),
    /// The chain in slot `idx` ends as `ending` says, and the fragment's outcome is `outcome`.
    Ends {
        idx: usize,
        ending: SlotEnding,
        outcome: IngestOutcome,
    },
}

impl Judged {
    /// The chain in slot `idx` ended through the machine's abort arm `event`, reported as
    /// ended for `reason`, the Router's own word for why it sent `event`.
    fn abort(idx: usize, event: ReassemblySlotEvent, reason: AbortReason) -> Self {
        Self::Ends {
            idx,
            ending: SlotEnding::Abort(event),
            outcome: IngestOutcome::Aborted(reason),
        }
    }
}

/// How a slot gives up the chain it holds ([`Slot::end`]).
#[derive(Clone, Copy, Debug)]
enum SlotEnding {
    /// The chain is done with where it stands (delivered, timed out, or refused by the arena at
    /// its last stage): `slot.release`, which only a terminal state answers.
    Release,
    /// The chain is ended by this abort arm of the machine, then released.
    Abort(ReassemblySlotEvent),
    /// The machine and the Router disagree about the slot: it gets a fresh machine.
    Replace,
}

pub use crate::chain_loss::ChainLoss;

/// The reassembly Router: a fixed pool of `SLOTS` slot FSMs, each able to
/// reassemble a fragment chain of up to `CAP` bytes. See the module docs
/// for the division of labour with the engine-free slot FSM.
///
/// `P` is whose chains it holds ([`ChainPeers`]): several peers' unless the type names
/// [`OnePeer`].
pub struct ReassemblyDispatcher<
    const SLOTS: usize,
    const CAP: usize,
    S = HeapStaging<SLOTS, CAP>,
    P = ManyPeers,
> where
    S: ChainStaging<SLOTS, CAP>,
    P: ChainPeers,
{
    slots: [Slot<SLOTS, CAP, S, P>; SLOTS],
    config: ReassemblyConfig,
    /// R311y589 — the arena the chains stage into. Defaulted to
    /// [`HeapStaging`], which is byte-for-byte the pre-seam behaviour, so every
    /// `ReassemblyDispatcher<SLOTS, CAP>` in the tree keeps its exact semantics
    /// without naming it.
    staging: S,
    /// Chains ended because a fragment would have taken them past the bound
    /// ([`AbortReason::CapacityOverflow`]); see [`Self::capacity_refusals`].
    capacity_refusals: u64,
    /// When the next chain begins among this Router's ([`ChainPeers::Opened`]).
    opened: P::Opened,
    /// The chain the current ingest ended for a fragment not of it; see
    /// [`Self::displaced_by_last_ingest`].
    displaced: Option<DisplacedChain>,
    /// No open chain's deadline is before this ([`Self::due_ms`]): lowered as a chain opens,
    /// worked out again by a sweep that looked at every slot. A chain that ended otherwise leaves
    /// it where it was, which only brings a sweep that finds nothing forward.
    due_ms: u64,
}

impl<const SLOTS: usize, const CAP: usize, S, P> ReassemblyDispatcher<SLOTS, CAP, S, P>
where
    S: ChainStaging<SLOTS, CAP>,
    P: ChainPeers,
{
    /// Build a Router with `SLOTS` empty slots over `config`, staging into an
    /// arena that makes its own storage.
    pub fn new(config: ReassemblyConfig) -> Self
    where
        S: BuildsOwnStorage<SLOTS, CAP>,
    {
        Self::with_staging(config, S::new())
    }

    /// Build a Router with `SLOTS` empty slots over `config`, staging into
    /// `staging`: an arena built by its caller, which is how an arena whose
    /// storage is handed in (a slot table the image placed) reaches a Router.
    /// The arena must be EMPTY, with no chain of its own outstanding; the
    /// Router's accounting starts from all of `SLOTS` free.
    pub fn with_staging(config: ReassemblyConfig, staging: S) -> Self {
        let mut place = core::mem::MaybeUninit::uninit();
        Self::init_in(&mut place, config, staging);
        // SAFETY: `init_in` wrote every field of the Router.
        unsafe { place.assume_init() }
    }

    /// [`Self::with_staging`] built where `place` lies, and lent back: each slot is made in its
    /// own place in the array, so the Router (one slot machine per slot, kilobytes in all) is never
    /// a value on its maker's stack and is not copied into the place it ends in. What a session
    /// that keeps its Router inside a longer-lived value (its pump) builds it with.
    ///
    /// `place` is overwritten without dropping what it held. A panic in the middle leaves it
    /// partly written and not dropped: a leak, and on the profiles that build in place
    /// (`panic = "abort"` on a board) not even that.
    // Not inlined, for the stack: a slot is built in this frame before it is written, and inlined
    // that frame would be its caller's for as long as the caller runs.
    #[inline(never)]
    pub fn init_in(
        place: &mut core::mem::MaybeUninit<Self>,
        config: ReassemblyConfig,
        staging: S,
    ) -> &mut Self {
        use core::ptr::addr_of_mut;
        let at = place.as_mut_ptr();
        // A field added to the Router and not written below would be read uninitialised. This
        // names every field with no `..`, so adding one without naming it here (and so without
        // writing it below) does not compile.
        let _every_field_is_written = |router: &Self| {
            let Self {
                slots: _,
                config: _,
                staging: _,
                capacity_refusals: _,
                opened: _,
                displaced: _,
                due_ms: _,
            } = router;
        };
        // SAFETY: `at` is valid for writes of a `Self` (it is `place`). An array of `SLOTS`
        // slots has the layout of `SLOTS` consecutive slots, so each is written once through its
        // own address, as is every other field the list above names, so `place` is fully written
        // before it is lent back.
        unsafe {
            let slots = addr_of_mut!((*at).slots).cast::<Slot<SLOTS, CAP, S, P>>();
            for index in 0..SLOTS {
                Slot::<SLOTS, CAP, S, P>::init_in(
                    &mut *slots
                        .add(index)
                        .cast::<core::mem::MaybeUninit<Slot<SLOTS, CAP, S, P>>>(),
                );
            }
            addr_of_mut!((*at).config).write(config);
            addr_of_mut!((*at).staging).write(staging);
            addr_of_mut!((*at).capacity_refusals).write(0);
            addr_of_mut!((*at).opened).write(P::FIRST);
            addr_of_mut!((*at).displaced).write(None);
            addr_of_mut!((*at).due_ms).write(u64::MAX);
            place.assume_init_mut()
        }
    }

    /// The open chain the last ingest ended for a fragment that was not of
    /// it, if it ended one.
    ///
    /// One fragment can end a second chain besides deciding its own: a `0x2
    /// First` restart ends the chain open on its key before it begins its own
    /// ([`DisplacedChain::Superseded`]), and under [`PoolOverflow::OldestWins`]
    /// a chain start on a full pool ends the oldest open chain to take its
    /// slot ([`DisplacedChain::Evicted`]). The ingest returns the fragment's
    /// [`IngestOutcome`]; this is the other chain's ending, which a caller
    /// that reports the one reports beside it (the drive loops raise both as
    /// `IterationEvent::ReassemblyDropped`).
    ///
    /// Every ingest clears it first, so it never speaks of an earlier call;
    /// [`Self::abort_channel`] and the sweeps leave it as it is.
    pub fn displaced_by_last_ingest(&self) -> Option<DisplacedChain> {
        self.displaced
    }

    /// The largest message a chain may reach here: the smaller of the
    /// configured [`ReassemblyConfig::max_message_bytes`] and the slot's `CAP`.
    pub fn max_message_bytes(&self) -> usize {
        self.config.max_message_bytes.min(CAP)
    }

    /// How many chains this Router has ended because a fragment would have
    /// taken them past [`Self::max_message_bytes`].
    ///
    /// The count is what makes such a refusal visible to a host that does not
    /// watch the per-chain [`AbortReason::CapacityOverflow`] outcome: upstream
    /// only traces it (`io/zenoh-transport/src/unicast/universal/rx.rs` @
    /// `tracing::trace!("{}", e);`), so a too-small bound on a receiver reads,
    /// from the sender's side, as messages that never arrive.
    pub fn capacity_refusals(&self) -> u64 {
        self.capacity_refusals
    }

    /// Whether `len` more bytes may join `chain`: the arena has room for them
    /// and the chain stays within the configured bound.
    fn chain_admits(staging: &S, chain: &S::Chain, len: usize, max_message_bytes: usize) -> bool {
        staging.fits(chain, len)
            && staging
                .bytes(chain)
                .len()
                .checked_add(len)
                .is_some_and(|total| total <= max_message_bytes)
    }

    /// Count a chain ended for its size, and say so the first time: the
    /// first refusal is the one that tells an operator the bound is too small,
    /// and a peer that keeps sending such chains must not turn the log into
    /// its echo.
    fn note_capacity_overflow(&mut self, attempted: usize) {
        if self.capacity_refusals == 0 {
            crate::diag_warn!(
                "reassembly: a fragmented message reached {attempted} bytes, past this \
                 node's bound of {} (transport/link/rx/max_message_size, capped by the \
                 reassembly slot of {CAP}); the message is dropped, and later ones past \
                 the bound are counted without a log",
                self.max_message_bytes()
            );
        }
        self.capacity_refusals = self.capacity_refusals.saturating_add(1);
    }

    /// The staging arena itself, read-only.
    ///
    /// Exposed so a test can assert on the ARENA's own state rather than on
    /// this Router's bookkeeping: an arena that staged into a private buffer
    /// and decremented a counter would satisfy every assertion phrased in terms
    /// of [`Self::staging_available`], which is exactly the vacuous proof the
    /// pooled backing needs to rule out.
    pub fn staging(&self) -> &S {
        &self.staging
    }

    /// How many chains the staging arena can still serve.
    ///
    /// Pairs with [`Self::active_chains`]: their sum is `SLOTS` at every
    /// quiescent point, and a violation means a chain handle was leaked or
    /// double-released. Exposed rather than kept test-private because the
    /// reserved-arena backing makes this a DEPLOY number — it is how much
    /// reassembly the node can still take on.
    pub fn staging_available(&self) -> usize {
        self.staging.available()
    }

    /// Number of slots currently holding an in-progress chain (test /
    /// observability helper; the pool-occupancy gauge).
    pub fn active_chains(&self) -> usize {
        self.slots.iter().filter(|s| !s.is_free()).count()
    }

    /// Ingest one decoded transport [`Fragment`].
    ///
    /// `sn_mask` is the announcing channel's SN ring mask
    /// ([`crate::sn::mask_from_res`] over the negotiated / per-peer
    /// `seq_num_res`) — the continuation gate compares ring-consecutive
    /// at it, as zenoh-pico passes `entry->_sn_res` / `_common._sn_res`
    /// into `_z_sn_consecutive` per call. It is a channel property the
    /// caller resolves, not per-fragment wire data, so it rides beside
    /// the clock rather than inside [`Fragment`]. `now_ms` is the runtime
    /// monotonic clock (used to arm a new chain's deadline). On
    /// reassembly completion `deliver` is called once with the fully
    /// reassembled message bytes (zero-copy from the slot buffer) before
    /// the slot is reclaimed.
    ///
    /// The ring is KNOWN here; [`Self::ingest_in_ring`] is the form that can be
    /// told it is not.
    pub fn ingest<F: FnOnce(&[u8])>(
        &mut self,
        frag: Fragment<'_>,
        sn_mask: crate::sn::Sn,
        now_ms: u64,
        deliver: F,
    ) -> IngestOutcome {
        self.ingest_in_ring(
            frag,
            SnRing::Known(crate::sn::to_wire(sn_mask)),
            now_ms,
            deliver,
        )
    }

    /// [`Self::ingest`] over a ring the caller may not know ([`SnRing`]).
    ///
    /// The ring decides one thing only: whether a CONTINUATION is the next
    /// fragment of its chain. Where a chain starts takes no ring (a start is a
    /// fragment that finds no chain open on its key, or, under the marker rules,
    /// one carrying `First`), so a chain with no ring is followed from its start
    /// and, while every step is `+1`, to its close. With [`SnRing::Known`] this
    /// is exactly [`Self::ingest`].
    ///
    /// # What a chain's start is when the markers are not enforced
    ///
    /// [`ReassemblyConfig::fragmentation_markers`] arms the `First` rule, and a
    /// reader that has seen no Init has no patch level to arm it by. Then the
    /// first fragment seen on a `(peer, reliable, priority)` key with no chain
    /// open begins one, whatever it carries. A capture that joined mid-chain
    /// therefore begins a chain at the first fragment it holds, and its close
    /// delivers a message that does not begin at a message; so does the rest of a
    /// chain that ended [`AbortReason::Unresolvable`], which "starts fresh" at the
    /// next fragment. The reader that parses the delivered bytes is what drops
    /// such a remnant, as it does for a ring-known session that negotiated no
    /// patch.
    pub fn ingest_in_ring<F: FnOnce(&[u8])>(
        &mut self,
        frag: Fragment<'_>,
        ring: SnRing,
        now_ms: u64,
        deliver: F,
    ) -> IngestOutcome {
        self.ingest_delivering(frag, ring, now_ms, Hand::Borrow, |chain: ChainBytes<'_>| {
            deliver(chain.as_slice())
        })
    }

    /// [`Self::ingest`], delivering the completed chain as [`ChainBytes`]: lent
    /// out of the arena when the arena can lend it ([`ChainStaging::lend`]),
    /// so the bytes the application is handed ARE the staging and no copy of
    /// it is made, and borrowed for the call when it cannot. What the receive
    /// loops call; `ingest` stays the borrowed-only form for a reader that
    /// copies what it keeps.
    pub fn ingest_lending<F: FnOnce(ChainBytes<'_>)>(
        &mut self,
        frag: Fragment<'_>,
        sn_mask: crate::sn::Sn,
        now_ms: u64,
        deliver: F,
    ) -> IngestOutcome {
        let ring = SnRing::Known(crate::sn::to_wire(sn_mask));
        self.ingest_delivering(frag, ring, now_ms, Hand::Lend, deliver)
    }

    /// [`Self::ingest`], delivering the completed chain KEPT when the arena can give its buffer
    /// away ([`ChainStaging::keep`]): the delivery holds the buffer for as long as it reads what
    /// was decoded out of it, and the Router's slot is free for the next chain at once. Borrowed
    /// for the call when the arena cannot. What a host that reads a rejoined message's records
    /// after the call calls.
    pub fn ingest_keeping<F: FnOnce(ChainBytes<'_>)>(
        &mut self,
        frag: Fragment<'_>,
        sn_mask: crate::sn::Sn,
        now_ms: u64,
        deliver: F,
    ) -> IngestOutcome {
        let ring = SnRing::Known(crate::sn::to_wire(sn_mask));
        self.ingest_delivering(frag, ring, now_ms, Hand::Keep, deliver)
    }

    /// The one ingest walk. `hand` is what the arena is asked to hand a
    /// completed chain up as; it is delivered borrowed when the arena cannot.
    fn ingest_delivering<F: FnOnce(ChainBytes<'_>)>(
        &mut self,
        frag: Fragment<'_>,
        ring: SnRing,
        now_ms: u64,
        hand: Hand,
        deliver: F,
    ) -> IngestOutcome {
        self.displaced = None;
        match self.judge(frag, ring, now_ms, hand, deliver) {
            Judged::Outcome(outcome) => outcome,
            Judged::Ends {
                idx,
                ending,
                outcome,
            } => {
                self.end_slot(idx, ending);
                outcome
            }
        }
    }

    /// Judge `frag` by the marker rules, its admission and its slot's machine, delivering the
    /// chain it completes. A chain the judgement ends is named in the answer, not ended here.
    fn judge<F: FnOnce(ChainBytes<'_>)>(
        &mut self,
        frag: Fragment<'_>,
        ring: SnRing,
        now_ms: u64,
        hand: Hand,
        deliver: F,
    ) -> Judged {
        let mut active = self.find_active(frag.peer_key, frag.reliable, frag.priority);
        if self.config.fragmentation_markers {
            active = match self.apply_chain_boundary_markers(&frag, active) {
                Ok(active) => active,
                Err(judged) => return judged,
            };
        }
        let admitted = match active {
            Some(idx) => self.admit_continuation(idx, &frag, ring),
            None => self
                .admit_chain_start(&frag, now_ms)
                .map_err(Judged::Outcome),
        };
        match admitted {
            Ok((idx, starts)) => self.drive_open_chain(idx, frag, starts, hand, deliver),
            Err(judged) => judged,
        }
    }

    /// The `finalize_message` duty, the final payload staged: hand the completed chain in `idx`
    /// to `deliver` and raise `slot.release`, whose `reset_slot` reclaims the slot.
    ///
    /// Lent or kept when `hand` asks it and the arena can: the Router slot is
    /// released first (the chain's staging is no longer the Router's), then the
    /// bytes are delivered. Otherwise borrowed: delivered while the staging is
    /// still held, and released after, which is the only order a borrow allows.
    fn finish<F: FnOnce(ChainBytes<'_>)>(
        &mut self,
        idx: usize,
        hand: Hand,
        deliver: F,
    ) -> IngestOutcome {
        let Self { slots, staging, .. } = self;
        let Some(slot) = slots.get_mut(idx) else {
            // No slot holds the chain, so none is delivered and none released.
            return IngestOutcome::Aborted(AbortReason::CapacityOverflow);
        };
        let taken = if hand == Hand::Borrow {
            None
        } else {
            slot.open.take()
        };
        // A chain the arena cannot hand up is held here, out of its slot, and delivered borrowed
        // and released after, as a chain asked borrowed is: put back into the slot, its whole open
        // state was moved out and in again.
        let mut held = None;
        let handed_up = match taken {
            Some(open) => match Self::hand_up(staging, open.chain, hand) {
                Ok(bytes) => Some(bytes),
                Err(chain) => {
                    held = Some(chain);
                    None
                }
            },
            None => None,
        };
        let released_first = handed_up.is_some();
        if released_first {
            slot.end(staging, SlotEnding::Release);
        }
        // One call of `deliver` for both hands, so the delivery is compiled in here once.
        let bytes = handed_up.or_else(|| {
            held.as_ref()
                .or(slot.open.as_ref().map(|open| &open.chain))
                .map(|chain| ChainBytes::Borrowed(staging.bytes(chain)))
        });
        if let Some(bytes) = bytes {
            deliver(bytes);
        }
        if !released_first {
            slot.end(staging, SlotEnding::Release);
            if let Some(chain) = held {
                staging.release(chain);
            }
        }
        IngestOutcome::Reassembled
    }

    /// The completed `chain` handed up from `staging` as `hand` asks, or given back when the
    /// arena cannot hand it up so, or `hand` asks it be borrowed.
    fn hand_up(
        staging: &mut S,
        chain: <S as ChainStaging<SLOTS, CAP>>::Chain,
        hand: Hand,
    ) -> Result<ChainBytes<'static>, <S as ChainStaging<SLOTS, CAP>>::Chain> {
        match hand {
            Hand::Keep => staging.keep(chain).map(ChainBytes::Kept),
            #[cfg(feature = "rx-shared-bytes")]
            Hand::Lend => staging.lend(chain).map(ChainBytes::Lent),
            _ => Err(chain),
        }
    }

    /// R311y578 — the `0x2 First` / `0x3 Drop` chain-boundary rules, run
    /// ahead of the SN machinery on a session whose negotiated patch level
    /// carries them ([`ReassemblyConfig::fragmentation_markers`]).
    ///
    /// `Err(judged)` means the fragment is CONSUMED here and must not
    /// reach the staging path; `Ok(active)` means carry on to the normal
    /// start / continuation split with the slot of the fragment's key that is
    /// still open: `active` as it came, or none once this has evicted it, since
    /// a key has at most one open chain.
    ///
    /// The order is zenoh's, and the order is load-bearing
    /// (`io/zenoh-transport/src/unicast/universal/rx.rs:155-170`):
    ///
    /// ```text
    /// if ext_first.is_some()      { defrag.clear(); }
    /// else if defrag.is_empty()   { return; }        // no marker, no chain
    /// if ext_drop.is_some()       { defrag.clear(); return; }
    /// ```
    ///
    /// so a `Drop` arriving onto an idle key is swallowed by the
    /// missing-start-marker rule rather than reported as an abort — there
    /// is nothing to abort, and the sender is announcing the end of a
    /// chain this receiver never saw the start of.
    fn apply_chain_boundary_markers(
        &mut self,
        frag: &Fragment<'_>,
        active: Option<usize>,
    ) -> Result<Option<usize>, Judged> {
        if frag.markers.first {
            // A restart supersedes whatever is staged on this key: the open
            // chain is evicted before the marked fragment is admitted.
            if let Some(idx) = active {
                self.evict_duplicate_first(idx);
            }
            // Fall through: the marked fragment itself now starts a chain.
            return Ok(None);
        }
        let Some(idx) = active else {
            // No marker and no chain in progress: this is not a chain
            // start, whatever its SN says.
            return Err(Judged::Outcome(IngestOutcome::Refused(
                RefuseReason::MissingStartMarker,
            )));
        };
        if frag.markers.dropped {
            return Err(Self::abort_peer_drop(idx));
        }
        Ok(active)
    }

    /// R311y578 — the SINGLE producer of the slot FSM's `fragment.drop`
    /// -> `Aborted` arm (`abort_peer_drop`): the sender's `0x3 Drop` marker
    /// on an open chain, docs/reassembly-fsm.md §2.4.7a peer-drop.
    ///
    /// Driving the FSM is not bookkeeping. The chain is freed only by the
    /// `reset_slot` duty, which `slot.release` runs from the three TERMINAL
    /// states alone, so a chain the machine was not driven out of
    /// `Receiving` is not freed at all, and the Router's key can never read
    /// free over an engine still parked there
    /// (`the_drop_arm_leaves_the_slot_fsm_in_a_declared_state`).
    fn abort_peer_drop(idx: usize) -> Judged {
        Judged::abort(
            idx,
            ReassemblySlotEvent::FragmentDrop,
            AbortReason::SenderDropped,
        )
    }

    /// docs/reassembly-fsm.md §2.4.6 duplicate-first. A `0x2 First` arrived
    /// on a key whose chain is open, so by the one-active-per-key rule (§2.1)
    /// the open chain is evicted and its key freed before the new First is
    /// admitted, which is zenoh's `defrag.clear()` on `ext_first`. The evicted
    /// chain is reported as [`DisplacedChain::Superseded`]; the fragment's own
    /// outcome is the one its admission then gives.
    ///
    /// Only the marker rules can tell a duplicate First from a continuation,
    /// so without them a fragment on an open key is judged as a continuation.
    fn evict_duplicate_first(&mut self, idx: usize) {
        self.evict(idx, DisplacedChain::Superseded);
    }

    /// The SINGLE producer of the slot FSM's `slot.evict` -> `Aborted` arm
    /// (`abort_evicted`), docs/reassembly-fsm.md §2.4.6: the open chain in
    /// `idx` is ended for a fragment that is not of it, either a restart on
    /// its own key ([`Self::evict_duplicate_first`]) or a start that needs its
    /// slot ([`PoolOverflow::OldestWins`]). The ending is recorded for
    /// [`Self::displaced_by_last_ingest`], since the ingest's own outcome is
    /// the fragment's.
    fn evict(&mut self, idx: usize, why: DisplacedChain) {
        self.end_slot(idx, SlotEnding::Abort(ReassemblySlotEvent::SlotEvict));
        self.displaced = Some(why);
    }

    /// R311y578 — push the negotiated protocol patch level's verdict into
    /// the Router. zenoh reads `self.config.patch.has_fragmentation_markers()`
    /// off the established transport on every fragment; wz resolves it once
    /// (the handshake settles the level and it never moves for the session)
    /// and stores it, so the hot path stays a bool test.
    ///
    /// Separate from the constructor because the dispatcher outlives the
    /// handshake: the slot pool is built at session bring-up, before any
    /// Init has been exchanged, so the level is not knowable there.
    pub fn set_fragmentation_markers(&mut self, on: bool) {
        self.config.fragmentation_markers = on;
    }

    /// Whether the chain-boundary rules are currently armed. Observability
    /// twin of [`Self::set_fragmentation_markers`]; a passive consumer
    /// reads it to report which contract a decode ran under.
    pub fn fragmentation_markers(&self) -> bool {
        self.config.fragmentation_markers
    }

    /// Push the session's [`ReassemblyConfig::max_message_bytes`] into the
    /// Router. The unicast drive writes it from the session's own
    /// configuration on every fragment, beside the marker verdict above, so
    /// a host that builds the Router before it holds a session still applies
    /// the session's bound; a chain already open is judged by it from its next
    /// fragment.
    pub fn set_max_message_bytes(&mut self, bytes: usize) {
        self.config.max_message_bytes = bytes;
    }

    /// Abort and reclaim every chain whose deadline has elapsed at
    /// `now_ms`, raising `reassembly.timeout` into only the live slots
    /// (a reused slot's stale deadline cannot fire — released slots are
    /// `is_free`). Returns the number of chains timed out.
    ///
    /// R311y713 (§B7) — see [`Self::sweep_counting`] for the same act
    /// reporting the BYTES it dropped. This spelling remains for the callers
    /// that only ever wanted the count.
    pub fn sweep(&mut self, now_ms: u64) -> usize {
        self.sweep_counting(now_ms).chains
    }

    /// R311y713 (§B7) — the same sweep, reporting how much was IN the chains
    /// it gave up on.
    ///
    /// A count of lost chains cannot answer the question a reader actually
    /// has — how much of this capture is missing — and the staged bytes are in
    /// hand at exactly this instant and nowhere else: `release` hands them back
    /// to the arena, so a caller asking afterwards is asking a buffer that has
    /// been reused. Three rounds recorded that this number had no witness while
    /// the only place able to take it was this loop.
    pub fn sweep_counting(&mut self, now_ms: u64) -> ChainLoss {
        self.sweep_reporting(now_ms, |_, _| {})
    }

    /// The same sweep, naming each chain it releases by the two halves of its
    /// key a caller holding one router per peer can tell apart: whether it was
    /// on the reliable channel, and its priority. A passive observer keys the
    /// identities it hands out by the same key, and this is how it learns which
    /// of them ended here, where no fragment row says so.
    pub fn sweep_reporting(
        &mut self,
        now_ms: u64,
        mut released: impl FnMut(bool, Priority),
    ) -> ChainLoss {
        let mut loss = ChainLoss::default();
        // Split the borrow: `release` hands the chain's staging back to the
        // arena, and both live behind `&mut self`.
        let Self {
            slots,
            staging,
            due_ms,
            ..
        } = self;
        // The sweep looks at every slot, so the earliest deadline it leaves open is worked out here.
        let mut next_ms = u64::MAX;
        for slot in slots.iter_mut() {
            // Read BEFORE the release, which is what makes the number takeable
            // at all: the handle is the arena's again the moment after.
            let (staged, reliable, priority) = match slot.open.as_ref() {
                Some(open) if now_ms >= open.deadline_ms => (
                    staging.bytes(&open.chain).len() as u64,
                    open.key.reliable,
                    open.key.priority,
                ),
                Some(open) => {
                    next_ms = next_ms.min(open.deadline_ms);
                    continue;
                }
                None => continue,
            };
            // `record_timeout` is a notice and posts no duty; the release
            // below is the sweep's own act on its own clock.
            slot.drive(ReassemblySlotEvent::ReassemblyTimeout);
            slot.end(staging, SlotEnding::Release);
            released(reliable, priority);
            loss.bytes = loss.bytes.saturating_add(staged);
            loss.chains = loss.chains.saturating_add(1);
        }
        *due_ms = next_ms;
        loss
    }

    /// No open chain's deadline is before this: a sweep before it releases nothing, and a holder
    /// of the Router may pass it over. `u64::MAX` with no chain opened since the last sweep.
    pub fn due_ms(&self) -> u64 {
        self.due_ms
    }

    fn find_active(&self, peer_key: &[u8], reliable: bool, priority: Priority) -> Option<usize> {
        self.slots.iter().position(|s| {
            s.open
                .as_ref()
                .is_some_and(|open| open.key.matches(peer_key, reliable, priority))
        })
    }

    fn peer_chain_count(&self, peer_key: &[u8]) -> u16 {
        self.slots
            .iter()
            .filter(|s| {
                s.open
                    .as_ref()
                    .is_some_and(|open| open.key.same_peer(peer_key))
            })
            .count() as u16
    }

    /// Open a chain for `frag`, the first fragment of one: a slot found or made, the chain's
    /// staging reserved, and the chain set open in the slot before its machine is told of it, so
    /// that [`Self::drive_open_chain`] drives a first fragment and a continuation alike. The slot
    /// and that it starts a chain, or the outcome of a start refused before the machine is driven.
    fn admit_chain_start(
        &mut self,
        frag: &Fragment<'_>,
        now_ms: u64,
    ) -> Result<(usize, bool), IngestOutcome> {
        // §5.M quota-first: the per-peer cap is checked before slot
        // availability, so a flood from one peer is refused on quota even
        // while free slots remain for honest peers.
        if self.peer_chain_count(frag.peer_key) >= self.config.per_peer_quota {
            return Err(IngestOutcome::Refused(RefuseReason::PeerQuota));
        }
        let idx = match self.slots.iter().position(Slot::is_free) {
            Some(i) => i,
            None => match self.make_room() {
                Some(i) => i,
                None => return Err(IngestOutcome::Refused(RefuseReason::PoolExhausted)),
            },
        };

        // Reserve this chain's staging before the machine is told of it, since
        // the reservation can fail and a transition cannot be taken back. A
        // well-dimensioned arena cannot refuse here (the Router just found a
        // free slot of its own), but the arm is real rather than an `unwrap`:
        // the two dims are an invariant between two numbers, and reporting
        // exhaustion is the honest answer if they ever disagree.
        // `PoolExhausted` is already the Router's word for it. The reservation
        // is held by the open chain from here; a machine that does not begin
        // the chain gives it back with the slot ([`Slot::replace`]).
        let deadline_ms = now_ms.saturating_add(self.config.reassembly_timeout_ms);
        // Lowered before the chain is known to open: a start refused below brings a sweep that
        // finds nothing forward, and no more.
        self.due_ms = self.due_ms.min(deadline_ms);
        let max_message_bytes = self.config.max_message_bytes;
        let opened = self.opened;
        let Self { slots, staging, .. } = self;
        let Some(slot) = slots.get_mut(idx) else {
            return Err(IngestOutcome::Refused(RefuseReason::PoolExhausted));
        };
        let Some(chain) = staging.acquire() else {
            return Err(IngestOutcome::Refused(RefuseReason::PoolExhausted));
        };
        // A first fragment wider than the bound never reaches the machine: no
        // transition of `Empty` refuses a chunk, so the chain ends here.
        if !Self::chain_admits(staging, &chain, frag.payload.len(), max_message_bytes) {
            staging.release(chain);
            self.note_capacity_overflow(frag.payload.len());
            return Err(IngestOutcome::Aborted(AbortReason::CapacityOverflow));
        }
        slot.open = Some(OpenChain {
            key: ChainKey::new(frag.peer_key, frag.reliable, frag.priority),
            last_sn: frag.sn,
            deadline_ms,
            opened,
            chain,
        });
        Ok((idx, true))
    }

    /// A slot for a chain start that found none free, by the pool's
    /// [`PoolOverflow`] policy: the slot of the oldest open chain, evicted,
    /// under [`PoolOverflow::OldestWins`]; none otherwise, and the start is
    /// refused.
    ///
    /// None under [`OnePeer`], which keeps no order of its chains: its pool is
    /// full past its quota only when the quota is above its slots (see
    /// [`ChainPeers`]).
    fn make_room(&mut self) -> Option<usize> {
        if !P::KEYED {
            return None;
        }
        match self.config.pool_overflow {
            PoolOverflow::Reject => None,
            PoolOverflow::DiagnosticEvent => {
                crate::diag_warn!(
                    "reassembly/slot-pool-full: all {SLOTS} reassembly slots hold an open \
                     chain, so a new chain is refused (pool overflow policy diagnostic-event)"
                );
                None
            }
            PoolOverflow::OldestWins => {
                let victim = self
                    .slots
                    .iter()
                    .enumerate()
                    .filter_map(|(idx, slot)| slot.open.as_ref().map(|open| (open.opened, idx)))
                    .min()
                    .map(|(_, idx)| idx)?;
                self.evict(victim, DisplacedChain::Evicted);
                Some(victim)
            }
        }
    }

    /// Stage `payload` onto the open chain in `idx` and take `sn` as its last:
    /// the staging half of the `begin_chain`, `append_fragment_payload` and
    /// `finalize_message` duties.
    ///
    /// `false` when the arena refuses the bytes, which it said would fit
    /// before the machine was driven: an arena whose `fits` and `append`
    /// disagree. The caller ends the chain.
    fn stage(&mut self, idx: usize, sn: u64, payload: &[u8]) -> bool {
        let Self { slots, staging, .. } = self;
        let Some(open) = slots.get_mut(idx).and_then(|slot| slot.open.as_mut()) else {
            return false;
        };
        if staging.append(&mut open.chain, payload).is_err() {
            return false;
        }
        open.last_sn = sn;
        true
    }

    /// Admit `frag` as the next fragment of the chain open in `idx`: the slot and that it does
    /// not start a chain, or the outcome of a continuation the chain cannot take, the chain
    /// ended. A slot that holds no chain is refused.
    fn admit_continuation(
        &mut self,
        idx: usize,
        frag: &Fragment<'_>,
        ring: SnRing,
    ) -> Result<(usize, bool), Judged> {
        // The judge hands only the slot its key's open chain sits in. One that holds none is a
        // slot the Router lost track of, not a chain to continue or a place to start one, and
        // the fragment is refused with nothing opened.
        let Some(open) = self.slots.get(idx).and_then(|slot| slot.open.as_ref()) else {
            return Err(Judged::Outcome(IngestOutcome::Refused(
                RefuseReason::PoolExhausted,
            )));
        };
        let last_sn = open.last_sn;
        // A payload the chain cannot hold is a codec error for the machine,
        // decided before the chunk is sent: once a final chunk has driven the
        // slot to `Complete` no abort arm is left to take.
        let staged = self.staging.bytes(&open.chain).len();
        let fits = Self::chain_admits(
            &self.staging,
            &open.chain,
            frag.payload.len(),
            self.config.max_message_bytes,
        );

        // Strict in-order (§2.5): a non-consecutive continuation (a
        // duplicate, a gap, or a backward step — all ring distances != 1)
        // aborts the chain via `fragment.ooo`. Ring compare, not `==` on
        // `+1`: a sender minting on the ring wraps `mask -> 0`, where the
        // unmasked form falsely aborted (R311ka F-5). On a ring the caller does
        // not know only `+1` is consecutive on every ring, so only that is
        // admitted, and any other step ends the chain as `Unresolvable` rather
        // than as the judgement it cannot make; the slot FSM's one abort arm for
        // "this continuation cannot be admitted" serves both words.
        if let Err(reason) = ring.admits(last_sn, frag.sn) {
            return Err(Judged::abort(idx, ReassemblySlotEvent::FragmentOoo, reason));
        }
        if !fits {
            self.note_capacity_overflow(staged.saturating_add(frag.payload.len()));
            return Err(Judged::abort(
                idx,
                ReassemblySlotEvent::CodecError,
                AbortReason::CapacityOverflow,
            ));
        }
        Ok((idx, false))
    }

    /// Drive the chunk of `frag` into the chain open in `idx` and do what its transition asked.
    /// `starts` says the chain was opened for this fragment ([`Self::admit_chain_start`]).
    ///
    /// The one place a chunk is driven: a first fragment and a continuation differ only in
    /// the duty that stages a payload (`begin_chain`, `append_fragment_payload`) and in
    /// what a machine that answers neither costs.
    fn drive_open_chain<F: FnOnce(ChainBytes<'_>)>(
        &mut self,
        idx: usize,
        frag: Fragment<'_>,
        starts: bool,
        hand: Hand,
        deliver: F,
    ) -> Judged {
        // `Empty --fragment.more/last--> { Receiving | Complete }` for a first fragment and
        // `Receiving --fragment.more/last--> { Receiving | Complete }` for a continuation, the
        // wire `more` bit naming the event. A well-formed chain's first fragment has M=1 (a
        // single-fragment message rides T_MID_FRAME, not T_MID_FRAGMENT) and lands in
        // Receiving -> Begun. A lone M=0 first fragment — stranded when a duplicate mid-chain
        // fragment trips the channel SN gate ([`Self::abort_channel`] clears the chain) and the
        // trailing final fragment then arrives as a fresh start — completes in ONE step: deliver
        // it immediately and reclaim the slot (zenoh-pico rx.c `if (!more) decode` parity).
        // Completing it rather than parking a stuck Receiving orphan is what stops the next
        // in-order message from being appended onto the orphan's tail and delivered as one
        // merged blob (R311oo dup-fragment merge bug). The delivered lone tail is a chain
        // remnant, not a whole frame, so the upstream frame decode drops it — exactly pico's
        // outcome. No slot in `idx` is no machine to drive, and the chain is given up below as
        // one whose machine answered neither duty.
        let duties = self
            .slots
            .get_mut(idx)
            .map_or(0, |slot| slot.drive_chunk(frag.more));
        let finalizes = duties & duty::FINALIZE != 0;
        // `Empty` answers every chunk with `begin_chain`, and `Receiving` with one of
        // `append_fragment_payload` and `finalize_message`. A machine that did not was not in
        // the state the Router held its slot in: the two disagree, and the slot is given a
        // fresh machine (and the chain's staging back to the arena) rather than one bound to a
        // chain it never began or kept.
        let disagrees = if starts {
            duties & duty::BEGIN == 0
        } else {
            duties & (duty::APPEND | duty::FINALIZE) == 0
        };
        if disagrees {
            return Judged::Ends {
                idx,
                ending: SlotEnding::Replace,
                outcome: if starts {
                    IngestOutcome::Refused(RefuseReason::PoolExhausted)
                } else {
                    IngestOutcome::Aborted(AbortReason::CapacityOverflow)
                },
            };
        }
        if starts {
            self.opened = P::after(self.opened);
        }
        // Whether the chunk completed the message. A continuation whose transition appended its
        // payload did not, whatever else the transition posted, as the machine appends before it
        // finalizes; a first fragment did when the same transition finalized the chain.
        let completes = if starts {
            finalizes
        } else {
            duties & duty::APPEND == 0
        };
        // Each chunk the machine took stages its payload once, by whichever of `begin_chain`,
        // `append_fragment_payload` and `finalize_message` its transition ran.
        if !self.stage(idx, frag.sn, frag.payload) {
            // A completed chain's machine is in `Complete`, where no abort arm is left, and is
            // released there; one still receiving is ended through its codec-error arm.
            let ending = if completes {
                SlotEnding::Release
            } else {
                SlotEnding::Abort(ReassemblySlotEvent::CodecError)
            };
            return Judged::Ends {
                idx,
                ending,
                outcome: IngestOutcome::Aborted(AbortReason::CapacityOverflow),
            };
        }
        if !completes {
            return Judged::Outcome(if starts {
                IngestOutcome::Begun
            } else {
                IngestOutcome::Continued
            });
        }
        Judged::Outcome(self.finish(idx, hand, deliver))
    }

    /// End the chain in `idx` as `ending` says ([`Slot::end`]). An abort arm the machine does
    /// not take, or a release it does not answer, replaces it, so the chain the Router ended is
    /// ended either way.
    fn end_slot(&mut self, idx: usize, ending: SlotEnding) {
        let Self { slots, staging, .. } = self;
        // No slot in `idx` holds no chain to end.
        if let Some(slot) = slots.get_mut(idx) {
            slot.end(staging, ending);
        }
    }

    /// R311ke — abort the in-progress chain on (`peer_key`, `priority`,
    /// `reliable`) — R311y215 keys per priority conduit (SN-safety F4) so a
    /// rejection on one priority does not clear a sibling priority's chain —
    /// the zenoh-pico dbuf-clear a channel-level SN-gate rejection triggers
    /// (unicast/rx.c:112-113: an out-of-order FRAME on a channel clears
    /// that channel's defragmentation buffer — the dropped frame may have
    /// superseded the chain's continuation, so completing it would mix
    /// generations). Drives the slot FSM through its `fragment.ooo`
    /// abort arm before release, exactly as an in-chain abort does.
    /// Returns whether a chain was cleared (`false` = nothing in
    /// progress on that channel — the common case).
    pub fn abort_channel(&mut self, peer_key: &[u8], priority: Priority, reliable: bool) -> bool {
        match self.find_active(peer_key, reliable, priority) {
            Some(idx) => {
                self.end_slot(idx, SlotEnding::Abort(ReassemblySlotEvent::FragmentOoo));
                true
            }
            None => false,
        }
    }

    /// End every chain of `peer_key`, whatever its channel: its link is gone, and a Router that
    /// the links of a session share would otherwise hold the chains until their deadline, and
    /// splice a later link's fragments of the same peer onto them. Each is driven through the
    /// abort arm [`Self::abort_channel`] drives. Answers how many were ended. Under [`OnePeer`]
    /// every open chain is the peer's.
    pub fn abort_peer(&mut self, peer_key: &[u8]) -> usize {
        let mut ended = 0usize;
        for idx in 0..SLOTS {
            let of_peer = self
                .slots
                .get(idx)
                .and_then(|slot| slot.open.as_ref())
                .is_some_and(|open| open.key.same_peer(peer_key));
            if of_peer {
                self.end_slot(idx, SlotEnding::Abort(ReassemblySlotEvent::FragmentOoo));
                // At most `SLOTS`.
                ended = ended.saturating_add(1);
            }
        }
        ended
    }
}

/// The event an in-order fragment is sent to its slot as: `fragment.more` when its wire M bit is
/// set, `fragment.last` when it is clear. The body never flows through the FSM (the Router stages
/// it through the slot's arena handle), so the M bit is all the machine is told, and it is told
/// as the event.
fn chunk_event(more: u8) -> ReassemblySlotEvent {
    if more != 0 {
        ReassemblySlotEvent::FragmentMore
    } else {
        ReassemblySlotEvent::FragmentLast
    }
}

/// Run one reassembly deadline sweep and report the eviction count.
///
/// The shared SSOT both drive loops call once per iteration in place of a
/// bare [`ReassemblyDispatcher::sweep`]: it aborts + reclaims every chain
/// whose `reassembly_timeout_ms` deadline has elapsed at `now_ms`, then — if
/// any chain timed out — raises a single [`IterationEvent::ReassemblyTimeout`]
/// carrying the count so the observer sees the eviction (the sweep itself is
/// otherwise silent). A zero-eviction sweep reports nothing, so the steady
/// state stays event-free.
///
/// Generic over the pool dims so the AP (32 / 1 MiB) and MCU (4 / 4096)
/// profiles share one path. R311mh relocated it here from `crate::drive`: it
/// is a pure reassembly helper (no unicast actions / runtime generic), so it
/// belongs next to [`ReassemblyDispatcher`], not in the session-unicast-gated
/// drive module — that is what let the multicast sweep SSOT
/// ([`crate::multicast_rx::sweep_multicast_reassembling`]) reuse it without a
/// false `session-unicast` coupling.
#[cfg(feature = "storage-profile")]
pub fn sweep_reporting<const SLOTS: usize, const CAP: usize, S, P, F>(
    reasm: &mut ReassemblyDispatcher<SLOTS, CAP, S, P>,
    now_ms: u64,
    on_event: &mut F,
) where
    S: ChainStaging<SLOTS, CAP>,
    P: ChainPeers,
    F: FnMut(IterationEvent<'_, '_>),
{
    let timed_out = reasm.sweep(now_ms);
    if timed_out > 0 {
        on_event(IterationEvent::ReassemblyTimeout(timed_out));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // `std` and not `alloc`: `reassembly` builds without the `alloc` feature (the
    // crate links `alloc` only for it), and a test always links `std`.
    use std::{vec, vec::Vec};

    const PEER_A: &[u8] = &[0xAA; 16];
    const PEER_B: &[u8] = &[0xBB; 16];

    /// A chain's key holds a peer key by its first `PEER_KEY_MAX` bytes: a longer key is the
    /// same peer as that prefix, and a key that differs in its length or in a kept byte is not,
    /// a trailing zero included.
    #[test]
    fn a_chain_key_holds_a_peer_key_by_its_bounded_prefix() {
        let long = [0x11u8; PEER_KEY_MAX + 4];
        let key = ChainKey::<ManyPeers>::new(&long, true, Priority::DEFAULT);
        assert!(key.same_peer(&long));
        assert!(key.same_peer(&long[..PEER_KEY_MAX]));
        assert!(!key.same_peer(&long[..PEER_KEY_MAX - 1]));
        let short = ChainKey::<ManyPeers>::new(&[1, 2, 3], false, Priority::DEFAULT);
        assert!(short.same_peer(&[1, 2, 3]));
        assert!(
            !short.same_peer(&[1, 2, 3, 0]),
            "a zero past the kept bytes is a byte"
        );
        assert!(!short.same_peer(&[1, 2]));
        assert!(!short.same_peer(&[1, 2, 4]));
    }

    /// The default-resolution (0x02, 28-bit) ring every test compares at.
    const MASK: crate::sn::Sn = crate::sn::mask_from_res(0x02);

    fn dispatcher<const S: usize, const C: usize>() -> ReassemblyDispatcher<S, C> {
        ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000))
    }

    /// Terse [`Fragment`] constructor for the test calls (DEFAULT priority —
    /// the priority-keyed chains are exercised by
    /// `qos_priority_keys_distinct_chains`).
    fn frag<'a>(
        peer_key: &'a [u8],
        reliable: bool,
        sn: u64,
        more: u8,
        payload: &'a [u8],
    ) -> Fragment<'a> {
        Fragment {
            peer_key,
            reliable,
            sn,
            more,
            payload,
            priority: Priority::DEFAULT,
            // R311y578 — the pre-existing suite runs the markers-OFF
            // contract (`ReassemblyConfig::new`), so a marker-less
            // descriptor is exactly what those assertions describe. The
            // armed contract has its own helper + module below.
            markers: crate::extfragment::FragmentMarkers::NONE,
        }
    }

    /// A two-fragment chain reassembles its concatenated payload in order.
    #[test]
    fn two_fragment_chain_reassembles_in_order() {
        let mut d = dispatcher::<4, 64>();
        let mut out: Option<Vec<u8>> = None;

        let r0 = d.ingest(frag(PEER_A, true, 10, 1, b"hello "), MASK, 0, |_| {
            panic!("not final")
        });
        assert_eq!(r0, IngestOutcome::Begun);
        assert_eq!(d.active_chains(), 1);

        let r1 = d.ingest(frag(PEER_A, true, 11, 0, b"world"), MASK, 0, |msg| {
            out = Some(msg.to_vec())
        });
        assert_eq!(r1, IngestOutcome::Reassembled);
        assert_eq!(out.as_deref(), Some(&b"hello world"[..]));
        // Slot reclaimed after completion.
        assert_eq!(d.active_chains(), 0);
    }

    /// A three-fragment chain accumulates across two continuations.
    #[test]
    fn three_fragment_chain_accumulates() {
        let mut d = dispatcher::<4, 64>();
        let mut out: Option<Vec<u8>> = None;
        assert_eq!(
            d.ingest(frag(PEER_A, true, 1, 1, b"aaa"), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        assert_eq!(
            d.ingest(frag(PEER_A, true, 2, 1, b"bbb"), MASK, 0, |_| {}),
            IngestOutcome::Continued
        );
        assert_eq!(
            d.ingest(frag(PEER_A, true, 3, 0, b"ccc"), MASK, 0, |m| out =
                Some(m.to_vec())),
            IngestOutcome::Reassembled
        );
        assert_eq!(out.as_deref(), Some(&b"aaabbbccc"[..]));
    }

    /// A non-consecutive continuation aborts the chain (strict in-order).
    #[test]
    fn out_of_order_continuation_aborts() {
        let mut d = dispatcher::<4, 64>();
        assert_eq!(
            d.ingest(frag(PEER_A, true, 1, 1, b"aaa"), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        // SN jumps 2 -> 4: aborts.
        let r = d.ingest(frag(PEER_A, true, 4, 0, b"zzz"), MASK, 0, |_| {
            panic!("aborted, no deliver")
        });
        assert_eq!(r, IngestOutcome::Aborted(AbortReason::OutOfOrder));
        assert_eq!(d.active_chains(), 0);
    }

    /// A chain crossing the SN ring seam (`mask -> 0`) continues — the
    /// ring-consecutive gate (R311ka F-5; zenoh-pico `_z_sn_consecutive`)
    /// where the prior unmasked `next_sn` compare falsely aborted.
    #[test]
    fn chain_continues_across_ring_seam() {
        let mut d = dispatcher::<4, 64>();
        let mut out: Option<Vec<u8>> = None;
        assert_eq!(
            d.ingest(frag(PEER_A, true, MASK, 1, b"top "), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        assert_eq!(
            d.ingest(frag(PEER_A, true, 0, 0, b"wrap"), MASK, 0, |m| out =
                Some(m.to_vec())),
            IngestOutcome::Reassembled
        );
        assert_eq!(out.as_deref(), Some(&b"top wrap"[..]));
    }

    /// A duplicate SN (ring distance 0) is non-consecutive -> abort.
    #[test]
    fn duplicate_sn_aborts() {
        let mut d = dispatcher::<4, 64>();
        d.ingest(frag(PEER_A, true, 5, 1, b"aaa"), MASK, 0, |_| {});
        let r = d.ingest(frag(PEER_A, true, 5, 1, b"aaa"), MASK, 0, |_| {});
        assert_eq!(r, IngestOutcome::Aborted(AbortReason::OutOfOrder));
    }

    /// Reliable and best-effort channels from the same peer are distinct
    /// chains (the R bit is part of the chain key).
    #[test]
    fn reliable_and_best_effort_are_distinct_chains() {
        let mut d = dispatcher::<4, 64>();
        assert_eq!(
            d.ingest(frag(PEER_A, true, 1, 1, b"R"), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        assert_eq!(
            d.ingest(frag(PEER_A, false, 1, 1, b"B"), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        assert_eq!(d.active_chains(), 2);
    }

    /// Per-peer quota refuses a chain start once the peer holds
    /// `per_peer_quota` open chains, even with free slots remaining
    /// (§5.M quota-first). The (peer_key,reliable) key gives PEER_A two distinct
    /// keys (the quota=2 cap); a third peer still composes under its own
    /// quota, proving the cap is per-peer.
    #[test]
    fn per_peer_quota_is_per_peer() {
        let mut d = dispatcher::<4, 64>();
        d.ingest(frag(PEER_A, true, 1, 1, b"a"), MASK, 0, |_| {});
        d.ingest(frag(PEER_A, false, 1, 1, b"b"), MASK, 0, |_| {});
        assert_eq!(
            d.ingest(frag(PEER_B, true, 1, 1, b"c"), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        assert_eq!(d.active_chains(), 3);
        assert_eq!(d.peer_chain_count(PEER_A), 2);
        assert_eq!(d.peer_chain_count(PEER_B), 1);
    }

    /// Quota rejection takes precedence over slot availability (§5.M
    /// "quota-first"): a 1-quota dispatcher with many free slots refuses a
    /// peer's second chain on quota, not on pool state.
    #[test]
    fn quota_refusal_precedes_slot_availability() {
        let mut d: ReassemblyDispatcher<4, 64> =
            ReassemblyDispatcher::new(ReassemblyConfig::new(1, 5_000));
        assert_eq!(
            d.ingest(frag(PEER_A, true, 1, 1, b"a"), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        // Second chain for PEER_A (best-effort key) refused on quota even
        // though 3 slots are free.
        assert_eq!(
            d.ingest(frag(PEER_A, false, 1, 1, b"b"), MASK, 0, |_| {}),
            IngestOutcome::Refused(RefuseReason::PeerQuota)
        );
    }

    /// With quota high enough to allow it, pool exhaustion refuses a chain
    /// start when every slot is occupied.
    #[test]
    fn pool_exhaustion_refuses_when_all_slots_busy() {
        // 2 slots, generous quota: two peers each open one chain, the third
        // peer is refused on pool exhaustion.
        let mut d: ReassemblyDispatcher<2, 64> =
            ReassemblyDispatcher::new(ReassemblyConfig::new(8, 5_000));
        assert_eq!(
            d.ingest(frag(PEER_A, true, 1, 1, b"a"), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        assert_eq!(
            d.ingest(frag(PEER_B, true, 1, 1, b"b"), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        let third: &[u8] = &[0xCC; 16];
        assert_eq!(
            d.ingest(frag(third, true, 1, 1, b"c"), MASK, 0, |_| {}),
            IngestOutcome::Refused(RefuseReason::PoolExhausted)
        );
        assert_eq!(d.displaced_by_last_ingest(), None);
    }

    const PEER_C: &[u8] = &[0xCC; 16];
    const PEER_D: &[u8] = &[0xDD; 16];

    /// Two slots under `policy`, with a quota no test here reaches.
    fn two_slots(policy: PoolOverflow) -> ReassemblyDispatcher<2, 64> {
        ReassemblyDispatcher::new(ReassemblyConfig::new(8, 5_000).with_pool_overflow(policy))
    }

    /// A config states `Reject` unless told otherwise: the Router's behaviour
    /// before the policy existed.
    #[test]
    fn a_full_pool_rejects_unless_the_config_says_otherwise() {
        assert_eq!(
            ReassemblyConfig::new(2, 5_000).pool_overflow,
            PoolOverflow::Reject
        );
    }

    /// Each value of the build's `reassembly-pool-overflow` policy names the
    /// Router's own value of the same word.
    #[test]
    fn each_pool_overflow_policy_value_names_the_routers_own() {
        use crate::policy::ReassemblyPoolOverflow;
        for (policy, word, router) in [
            (
                ReassemblyPoolOverflow::Reject,
                "reject",
                PoolOverflow::Reject,
            ),
            (
                ReassemblyPoolOverflow::DiagnosticEvent,
                "diagnostic-event",
                PoolOverflow::DiagnosticEvent,
            ),
            (
                ReassemblyPoolOverflow::OldestWins,
                "oldest-wins",
                PoolOverflow::OldestWins,
            ),
        ] {
            assert_eq!(policy.id(), word);
            assert_eq!(PoolOverflow::of_policy(policy), router, "{word}");
        }
    }

    /// `Reject` and `DiagnosticEvent` both refuse the new chain and leave the
    /// open ones as they were; the second differs only in the warning it logs.
    #[test]
    fn reject_and_diagnostic_event_refuse_the_new_chain_and_keep_the_open_ones() {
        for policy in [PoolOverflow::Reject, PoolOverflow::DiagnosticEvent] {
            let mut d = two_slots(policy);
            d.ingest(frag(PEER_A, true, 1, 1, b"a"), MASK, 0, |_| {});
            d.ingest(frag(PEER_B, true, 1, 1, b"b"), MASK, 0, |_| {});
            assert_eq!(
                d.ingest(frag(PEER_C, true, 1, 1, b"c"), MASK, 0, |_| {}),
                IngestOutcome::Refused(RefuseReason::PoolExhausted),
                "{policy:?}"
            );
            assert_eq!(d.displaced_by_last_ingest(), None, "{policy:?}");
            assert_eq!(d.peer_chain_count(PEER_A), 1, "{policy:?}");
            assert_eq!(d.peer_chain_count(PEER_B), 1, "{policy:?}");
        }
    }

    /// `OldestWins` ends the chain that began first and begins the new one in
    /// its slot, reporting the ended chain as evicted. The evicted peer's next
    /// fragment finds no chain of its own: it starts one, and its bytes are
    /// not joined to the evicted prefix.
    #[test]
    fn oldest_wins_evicts_the_chain_that_began_first() {
        let mut d = two_slots(PoolOverflow::OldestWins);
        d.ingest(frag(PEER_A, true, 1, 1, b"a1"), MASK, 0, |_| {});
        d.ingest(frag(PEER_B, true, 1, 1, b"b1"), MASK, 0, |_| {});
        assert_eq!(
            d.ingest(frag(PEER_C, true, 1, 1, b"c1"), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        assert_eq!(d.displaced_by_last_ingest(), Some(DisplacedChain::Evicted));
        assert_eq!(d.peer_chain_count(PEER_A), 0, "the oldest chain is gone");
        assert_eq!(d.peer_chain_count(PEER_B), 1);
        assert_eq!(d.peer_chain_count(PEER_C), 1);
        assert_eq!(d.active_chains() + d.staging_available(), 2);

        let mut got: Option<Vec<u8>> = None;
        assert_eq!(
            d.ingest(frag(PEER_C, true, 2, 0, b"c2"), MASK, 0, |m| got =
                Some(m.to_vec())),
            IngestOutcome::Reassembled
        );
        assert_eq!(got.as_deref(), Some(&b"c1c2"[..]), "the new chain is whole");
    }

    /// "Oldest" is the order chains began in, not the order of the slots: a
    /// chain begun later in a lower slot outlives an older one in a higher
    /// slot.
    #[test]
    fn oldest_wins_picks_by_when_a_chain_began_not_by_its_slot() {
        let mut d = two_slots(PoolOverflow::OldestWins);
        // A in slot 0, B in slot 1; A completes and C takes slot 0.
        d.ingest(frag(PEER_A, true, 1, 1, b"a1"), MASK, 0, |_| {});
        d.ingest(frag(PEER_B, true, 1, 1, b"b1"), MASK, 0, |_| {});
        assert_eq!(
            d.ingest(frag(PEER_A, true, 2, 0, b"a2"), MASK, 0, |_| {}),
            IngestOutcome::Reassembled
        );
        d.ingest(frag(PEER_C, true, 1, 1, b"c1"), MASK, 0, |_| {});
        assert!(d.slots[0]
            .open
            .as_ref()
            .is_some_and(|open| open.key.same_peer(PEER_C)));

        assert_eq!(
            d.ingest(frag(PEER_D, true, 1, 1, b"d1"), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        assert_eq!(d.peer_chain_count(PEER_B), 0, "B began before C");
        assert_eq!(d.peer_chain_count(PEER_C), 1);
        assert_eq!(d.peer_chain_count(PEER_D), 1);
    }

    /// The quota is judged before the pool: a peer at its quota is refused on
    /// it, and no other peer's chain is evicted for a start that was never
    /// going to be admitted.
    #[test]
    fn oldest_wins_answers_to_the_peer_quota_first() {
        let mut d: ReassemblyDispatcher<2, 64> = ReassemblyDispatcher::new(
            ReassemblyConfig::new(1, 5_000).with_pool_overflow(PoolOverflow::OldestWins),
        );
        d.ingest(frag(PEER_A, true, 1, 1, b"a"), MASK, 0, |_| {});
        d.ingest(frag(PEER_B, true, 1, 1, b"b"), MASK, 0, |_| {});
        assert_eq!(
            d.ingest(frag(PEER_A, false, 1, 1, b"a"), MASK, 0, |_| {}),
            IngestOutcome::Refused(RefuseReason::PeerQuota)
        );
        assert_eq!(d.displaced_by_last_ingest(), None);
        assert_eq!(d.peer_chain_count(PEER_B), 1, "B's chain was not evicted");
    }

    /// Staging beyond the slot capacity aborts on the §7.1 hard error —
    /// enforced on the `alloc` (AP) backing too (where `BoundedVec::push`
    /// itself never fails), so reassembly is genuinely bounded on both
    /// profiles.
    #[test]
    fn capacity_overflow_aborts() {
        // CAP = 8: first fragment 6 bytes ok; continuation 5 bytes overflows.
        let mut d = dispatcher::<4, 8>();
        assert_eq!(
            d.ingest(frag(PEER_A, true, 1, 1, b"aaaaaa"), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        let r = d.ingest(frag(PEER_A, true, 2, 0, b"bbbbb"), MASK, 0, |_| {
            panic!("overflow, no deliver")
        });
        assert_eq!(r, IngestOutcome::Aborted(AbortReason::CapacityOverflow));
        assert_eq!(d.active_chains(), 0);
        assert_eq!(d.capacity_refusals(), 1);
    }

    /// A Router whose configured bound is `bytes`, below its slot's `CAP`.
    fn bounded<const S: usize, const C: usize>(bytes: usize) -> ReassemblyDispatcher<S, C> {
        ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000).with_max_message_bytes(bytes))
    }

    /// The configured bound ends a chain the slot could hold, and is
    /// inclusive as upstream's `new_len > capacity` is: a chain of exactly the
    /// bound reassembles, one byte more does not.
    #[test]
    fn the_configured_bound_ends_a_chain_the_slot_could_hold() {
        let mut d = bounded::<4, 64>(10);
        assert_eq!(d.max_message_bytes(), 10);
        d.ingest(frag(PEER_A, true, 1, 1, b"aaaaa"), MASK, 0, |_| {});
        let mut out = None;
        let r = d.ingest(frag(PEER_A, true, 2, 0, b"bbbbb"), MASK, 0, |m| {
            out = Some(m.to_vec())
        });
        assert_eq!(r, IngestOutcome::Reassembled);
        assert_eq!(out.as_deref(), Some(&b"aaaaabbbbb"[..]));

        d.ingest(frag(PEER_A, true, 3, 1, b"aaaaa"), MASK, 0, |_| {});
        let r = d.ingest(frag(PEER_A, true, 4, 0, b"bbbbbb"), MASK, 0, |_| {
            panic!("past the bound, no deliver")
        });
        assert_eq!(r, IngestOutcome::Aborted(AbortReason::CapacityOverflow));
        assert_eq!(d.active_chains(), 0);
        assert_eq!(d.capacity_refusals(), 1);
    }

    /// A table of `count` buffers of `size` bytes over memory the test process leaks, so it outlives
    /// every buffer claimed from it.
    fn lent_cells(size: usize, count: usize) -> crate::byte_cells::LentByteCells {
        use crate::bounded::{Arena, ARENA_ALIGN};

        #[derive(Clone, Copy)]
        #[repr(C, align(16))]
        struct Block([u8; ARENA_ALIGN]);

        let bytes = Arena::byte_cells_bytes(size, count).expect("within the address space");
        let blocks = bytes.div_ceil(ARENA_ALIGN).max(1);
        let region: &'static mut [Block] = vec![Block([0; ARENA_ALIGN]); blocks].leak();
        // SAFETY: the region is aligned to `ARENA_ALIGN`, as its blocks are, holds at least
        // `bytes` bytes, and is leaked, so nothing else uses it and it outlives every buffer.
        let mut arena =
            unsafe { Arena::over(core::ptr::NonNull::from(region).cast::<u8>(), bytes) };
        arena
            .lend_byte_cells(size, count)
            .expect("the arena is laid out for the table")
    }

    /// A Router over chains staged in lent buffers ends a chain at the buffer's length, the
    /// session's bound, though its slot's `CAP` would hold more: as pico ends a chain past its
    /// `FRAG_MAX_SIZE`. A chain of exactly the bound reassembles.
    #[test]
    fn a_chain_past_the_lent_bound_is_refused() {
        use crate::chain_staging::LentStaging;

        let cells = lent_cells(8, 2);
        let mut d: ReassemblyDispatcher<4, 64, LentStaging<4, 64>> =
            ReassemblyDispatcher::with_staging(
                ReassemblyConfig::new(2, 5_000),
                LentStaging::over(&cells, 2),
            );
        let mut out = None;
        d.ingest(frag(PEER_A, true, 1, 1, b"aaaa"), MASK, 0, |_| {});
        let r = d.ingest(frag(PEER_A, true, 2, 0, b"bbbb"), MASK, 0, |m| {
            out = Some(m.to_vec())
        });
        assert_eq!(r, IngestOutcome::Reassembled);
        assert_eq!(out.as_deref(), Some(&b"aaaabbbb"[..]));

        d.ingest(frag(PEER_A, true, 3, 1, b"aaaa"), MASK, 0, |_| {});
        let r = d.ingest(frag(PEER_A, true, 4, 0, b"bbbbb"), MASK, 0, |_| {
            panic!("past the bound, no deliver")
        });
        assert_eq!(r, IngestOutcome::Aborted(AbortReason::CapacityOverflow));
        assert_eq!(d.capacity_refusals(), 1);
        assert_eq!(d.active_chains(), 0);
        assert_eq!(d.staging_available(), 2, "both buffers are free again");
    }

    /// A Router built in its place serves as one built by value does: a chain of the lent bound
    /// reassembles, one past it is refused and counted, and the buffers it claimed go back to
    /// their table when it is dropped where it lies.
    #[test]
    fn a_router_built_in_place_serves_as_one_built_by_value() {
        use crate::chain_staging::LentStaging;
        use core::mem::MaybeUninit;

        let cells = lent_cells(8, 2);
        let mut place = MaybeUninit::<ReassemblyDispatcher<4, 64, LentStaging<4, 64>>>::uninit();
        let d = ReassemblyDispatcher::init_in(
            &mut place,
            ReassemblyConfig::new(2, 5_000),
            LentStaging::over(&cells, 2),
        );
        assert_eq!(
            (
                d.active_chains(),
                d.capacity_refusals(),
                d.staging_available()
            ),
            (0, 0, 2),
            "every slot free, nothing refused, both buffers on hand"
        );
        assert_eq!(d.max_message_bytes(), 64);
        let mut out = None;
        d.ingest(frag(PEER_A, true, 1, 1, b"aaaa"), MASK, 0, |_| {});
        let r = d.ingest(frag(PEER_A, true, 2, 0, b"bbbb"), MASK, 0, |m| {
            out = Some(m.to_vec())
        });
        assert_eq!(r, IngestOutcome::Reassembled);
        assert_eq!(out.as_deref(), Some(&b"aaaabbbb"[..]));
        d.ingest(frag(PEER_A, true, 3, 1, b"aaaa"), MASK, 0, |_| {});
        let r = d.ingest(frag(PEER_A, true, 4, 0, b"bbbbb"), MASK, 0, |_| {
            panic!("past the bound, no deliver")
        });
        assert_eq!(r, IngestOutcome::Aborted(AbortReason::CapacityOverflow));
        assert_eq!(d.capacity_refusals(), 1);
        assert_eq!(cells.in_use(), 0, "the ended chain gave it back");
        d.ingest(frag(PEER_A, true, 5, 1, b"aaaa"), MASK, 0, |_| {});
        assert_eq!(cells.in_use(), 1, "an open chain holds a buffer");
        // SAFETY: `init_in` wrote the whole Router into `place`, and it is dropped once.
        unsafe { place.assume_init_drop() };
        assert_eq!(cells.in_use(), 0, "dropped in place, it gives it back");
    }

    /// A lent staging claims a buffer of its table when a chain starts and gives it back when the
    /// chain ends: none is held while no chain is open, no more chains than its count are open at
    /// once, and a staging dropped with a chain open gives that buffer back.
    #[test]
    fn a_lent_staging_claims_a_buffer_when_a_chain_starts() {
        use crate::chain_staging::{ChainStaging, LentStaging};

        let cells = lent_cells(8, 3);
        let mut staging = LentStaging::<4, 64>::over(&cells, 2);
        assert_eq!((staging.available(), cells.in_use()), (2, 0));
        assert_eq!(staging.capacity(), 8, "a buffer's length, under CAP");
        let first = staging.acquire().expect("a buffer");
        assert_eq!(cells.in_use(), 1, "the first chain claimed one");
        let _second = staging.acquire().expect("the other buffer");
        assert!(staging.acquire().is_none(), "no third chain");
        assert_eq!(cells.in_use(), 2, "the refused chain claimed nothing");
        staging.release(first);
        assert_eq!((staging.available(), cells.in_use()), (1, 1));
        drop(staging);
        assert_eq!(
            cells.in_use(),
            0,
            "dropped, the staging gave the open chain's buffer back"
        );
        assert_eq!(LentStaging::<4, 64>::none().available(), 0);
    }

    /// A chain that starts after an earlier one ended takes the place that chain left, and the
    /// count of open chains is over every place: a place held after the free one still counts.
    #[test]
    fn a_lent_staging_counts_every_held_place_when_a_chain_starts() {
        use crate::chain_staging::{ChainStaging, LentStaging};

        let cells = lent_cells(8, 4);
        let mut staging = LentStaging::<4, 64>::over(&cells, 2);
        let first = staging.acquire().expect("a buffer");
        let _second = staging.acquire().expect("another buffer");
        staging.release(first);
        assert_eq!((staging.available(), cells.in_use()), (1, 1));
        let _third = staging.acquire().expect("the place the first left");
        assert_eq!(cells.in_use(), 2);
        assert!(
            staging.acquire().is_none(),
            "two chains open: the table has two buffers free and the staging takes no third chain"
        );
        assert_eq!(cells.in_use(), 2, "the refused chain claimed nothing");
        assert!(
            LentStaging::<4, 64>::none().acquire().is_none(),
            "a staging of no table refuses every chain"
        );
    }

    /// The stagings of two links over their session's one table share its buffers: a chain of one
    /// link that finds every buffer held by the other's is refused, and the buffer the other's
    /// chain gives back when it ends serves it.
    #[test]
    fn two_stagings_over_one_table_share_its_buffers() {
        use crate::chain_staging::{ChainStaging, LentStaging};

        let cells = lent_cells(8, 1);
        let mut one = LentStaging::<4, 64>::over(&cells, 2);
        let mut other = LentStaging::<4, 64>::over(&cells, 2);
        let held = one.acquire().expect("the table's buffer");
        assert_eq!(other.available(), 0, "the table has none free");
        assert!(other.acquire().is_none(), "the other link finds none");
        one.release(held);
        assert_eq!(other.available(), 1);
        let again = other.acquire().expect("the buffer given back");
        assert_eq!(cells.in_use(), 1);
        other.release(again);
        assert_eq!(cells.in_use(), 0);
    }

    /// Two links' Routers over their session's one table of one buffer: the second link's chain
    /// that begins while the first's is open is refused as pool exhaustion, which drops it, and
    /// the first's completes whole; once it has, a chain of the second link begins.
    #[test]
    fn a_chain_past_the_sessions_buffers_is_refused_as_pool_exhaustion() {
        use crate::chain_staging::LentStaging;

        let cells = lent_cells(8, 1);
        let mut first: ReassemblyDispatcher<4, 64, LentStaging<4, 64>> =
            ReassemblyDispatcher::with_staging(
                ReassemblyConfig::new(2, 5_000),
                LentStaging::over(&cells, 2),
            );
        let mut second: ReassemblyDispatcher<4, 64, LentStaging<4, 64>> =
            ReassemblyDispatcher::with_staging(
                ReassemblyConfig::new(2, 5_000),
                LentStaging::over(&cells, 2),
            );
        assert_eq!(
            first.ingest(frag(PEER_A, true, 1, 1, b"aaaa"), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        assert_eq!(
            second.ingest(frag(PEER_B, true, 1, 1, b"cccc"), MASK, 0, |_| {
                panic!("refused, no deliver")
            }),
            IngestOutcome::Refused(RefuseReason::PoolExhausted)
        );
        assert_eq!(second.active_chains(), 0, "it holds no slot");
        let mut out = None;
        assert_eq!(
            first.ingest(frag(PEER_A, true, 2, 0, b"bbbb"), MASK, 0, |m| {
                out = Some(m.to_vec())
            }),
            IngestOutcome::Reassembled
        );
        assert_eq!(out.as_deref(), Some(&b"aaaabbbb"[..]));
        assert_eq!(cells.in_use(), 0);
        assert_eq!(
            second.ingest(frag(PEER_B, true, 2, 1, b"cccc"), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        assert_eq!(cells.in_use(), 1);
    }

    /// A chain ingested to be kept is handed up as its own buffer, read where it was staged: the
    /// Router's slot and the staging's place are free at once, the buffer stays out of the table
    /// until the delivery drops it, and a chain that starts meanwhile stages into another buffer.
    /// An arena that cannot keep (the heap one) hands the chain up borrowed, as before. Turned red
    /// by a keep that copies the chain or gives its buffer back before the delivery drops it.
    #[test]
    fn a_kept_chain_holds_its_buffer_until_the_delivery_drops_it() {
        use crate::chain_staging::LentStaging;

        let cells = lent_cells(8, 2);
        let mut d: ReassemblyDispatcher<4, 64, LentStaging<4, 64>> =
            ReassemblyDispatcher::with_staging(
                ReassemblyConfig::new(2, 5_000),
                LentStaging::over(&cells, 2),
            );
        d.ingest_keeping(frag(PEER_A, true, 1, 1, b"aaaa"), MASK, 0, |_| {});
        let mut kept = None;
        let r = d.ingest_keeping(frag(PEER_A, true, 2, 0, b"bbbb"), MASK, 0, |chain| {
            kept = match chain {
                ChainBytes::Kept(bytes) => Some(bytes),
                _ => panic!("a lent staging keeps a completed chain"),
            }
        });
        assert_eq!(r, IngestOutcome::Reassembled);
        let kept = kept.expect("the chain completed");
        assert_eq!(kept.as_slice(), b"aaaabbbb");
        assert_eq!(d.active_chains(), 0, "the Router's slot is free");
        assert_eq!(cells.in_use(), 1, "the delivery holds the buffer");
        assert_eq!(
            d.ingest_keeping(frag(PEER_A, true, 3, 1, b"cccc"), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        assert_eq!(cells.in_use(), 2, "the next chain took the other buffer");
        drop(kept);
        assert_eq!(
            cells.in_use(),
            1,
            "dropped, the kept buffer is the table's again"
        );

        let mut heap = dispatcher::<4, 64>();
        heap.ingest_keeping(frag(PEER_A, true, 1, 1, b"aa"), MASK, 0, |_| {});
        let mut borrowed = false;
        heap.ingest_keeping(frag(PEER_A, true, 2, 0, b"bb"), MASK, 0, |chain| {
            borrowed = matches!(chain, ChainBytes::Borrowed(bytes) if bytes == b"aabb");
        });
        assert!(
            borrowed,
            "CONTROL: an arena that cannot keep lends for the call"
        );
        assert_eq!(
            heap.active_chains(),
            0,
            "the slot is free once the delivery returns"
        );
        assert_eq!(
            heap.staging_available(),
            4,
            "the chain the arena could not keep is released to it after the delivery"
        );
    }

    /// A reservation is staged as far as it was filled, and a commit past it is refused.
    #[test]
    fn a_lent_chain_stages_what_its_filler_wrote() {
        use crate::chain_staging::{ChainStaging, LentStaging, StagingError};

        let cells = lent_cells(8, 1);
        let mut staging = LentStaging::<1, 64>::over(&cells, 1);
        let mut chain = staging.acquire().expect("a buffer");
        staging.append(&mut chain, b"ab").expect("room");
        staging
            .buf(&mut chain, 4)
            .expect("room for four")
            .copy_from_slice(b"cdef");
        staging.commit(&mut chain, 3).expect("three of four filled");
        assert_eq!(staging.bytes(&chain), b"abcde");
        assert!(!staging.fits(&chain, 4), "five staged, eight the most");
        assert_eq!(
            staging.buf(&mut chain, 4).err(),
            Some(StagingError::ChainCapExceeded)
        );
        staging.buf(&mut chain, 1).expect("room for one");
        assert_eq!(
            staging.commit(&mut chain, 2),
            Err(StagingError::ChainCapExceeded)
        );
        staging.release(chain);
    }

    /// A first fragment already past the bound never opens a chain.
    #[test]
    fn a_first_fragment_past_the_bound_opens_no_chain() {
        let mut d = bounded::<4, 64>(4);
        let r = d.ingest(frag(PEER_A, true, 1, 1, b"aaaaa"), MASK, 0, |_| {});
        assert_eq!(r, IngestOutcome::Aborted(AbortReason::CapacityOverflow));
        assert_eq!(d.active_chains(), 0);
        assert_eq!(d.staging_available(), 4);
        assert_eq!(d.capacity_refusals(), 1);
    }

    /// `0` rejoins no chain, as upstream's zero-capacity buffer refuses every
    /// non-empty fragment.
    #[test]
    fn a_zero_bound_rejoins_no_chain() {
        let mut d = bounded::<4, 64>(0);
        for sn in 0..3 {
            let r = d.ingest(frag(PEER_A, true, sn, 1, b"a"), MASK, 0, |_| {});
            assert_eq!(r, IngestOutcome::Aborted(AbortReason::CapacityOverflow));
        }
        assert_eq!(d.capacity_refusals(), 3);
    }

    /// A bound above the slot is read as the slot.
    #[test]
    fn a_bound_above_the_slot_is_read_as_the_slot() {
        let mut d = bounded::<4, 8>(1 << 30);
        assert_eq!(d.max_message_bytes(), 8);
        d.ingest(frag(PEER_A, true, 1, 1, b"aaaaaa"), MASK, 0, |_| {});
        let r = d.ingest(frag(PEER_A, true, 2, 0, b"bbb"), MASK, 0, |_| {});
        assert_eq!(r, IngestOutcome::Aborted(AbortReason::CapacityOverflow));
    }

    /// The deadline sweep aborts a chain past its deadline and reclaims
    /// the slot; a fresh chain is unaffected.
    #[test]
    fn sweep_times_out_expired_chains_only() {
        let mut d = dispatcher::<4, 64>();
        // Chain armed at t=0 with the 5_000ms window -> deadline 5_000.
        d.ingest(frag(PEER_A, true, 1, 1, b"aaa"), MASK, 0, |_| {});
        // Chain armed at t=4_000 -> deadline 9_000.
        d.ingest(frag(PEER_B, true, 1, 1, b"bbb"), MASK, 4_000, |_| {});
        // Sweep at t=6_000: only PEER_A's chain (deadline 5_000) expires.
        assert_eq!(d.sweep(6_000), 1);
        assert_eq!(d.active_chains(), 1);
        assert_eq!(d.peer_chain_count(PEER_B), 1);
        // Sweep at t=10_000: PEER_B's chain expires too.
        assert_eq!(d.sweep(10_000), 1);
        assert_eq!(d.active_chains(), 0);
    }

    /// The watermark a holder passes the sweep over by falls to the deadline of each chain that
    /// opens and is worked out again by a sweep: the next deadline left open, none once none is.
    /// Turned red by an open that leaves it high (a chain past its deadline passed over) or a
    /// sweep that leaves it low.
    #[test]
    fn due_ms_falls_with_an_open_chain_and_rises_with_a_sweep() {
        let mut d = dispatcher::<4, 64>();
        assert_eq!(d.due_ms(), u64::MAX, "no chain, due never");
        d.ingest(frag(PEER_B, true, 1, 1, b"bbb"), MASK, 4_000, |_| {});
        assert_eq!(d.due_ms(), 9_000);
        d.ingest(frag(PEER_A, true, 1, 1, b"aaa"), MASK, 0, |_| {});
        assert_eq!(d.due_ms(), 5_000, "the earlier chain's deadline");
        assert_eq!(d.sweep(6_000), 1);
        assert_eq!(d.due_ms(), 9_000, "the chain left open");
        assert_eq!(d.sweep(10_000), 1);
        assert_eq!(d.due_ms(), u64::MAX, "none left open");
    }

    /// After a chain completes, its slot is reusable for a new chain.
    #[test]
    fn slot_reuse_after_completion() {
        let mut d = dispatcher::<1, 64>();
        // One slot: complete a chain, then a second chain reuses it.
        d.ingest(frag(PEER_A, true, 1, 1, b"aa"), MASK, 0, |_| {});
        let mut out: Option<Vec<u8>> = None;
        assert_eq!(
            d.ingest(frag(PEER_A, true, 2, 0, b"bb"), MASK, 0, |m| out =
                Some(m.to_vec())),
            IngestOutcome::Reassembled
        );
        assert_eq!(out.as_deref(), Some(&b"aabb"[..]));
        // Slot freed -> a new chain begins (would be PoolExhausted if not
        // reclaimed).
        assert_eq!(
            d.ingest(frag(PEER_B, true, 7, 1, b"cc"), MASK, 100, |_| {}),
            IngestOutcome::Begun
        );
    }

    /// A lone M=0 FIRST fragment completes in ONE step and is delivered
    /// immediately (the Empty state's `more == 0` arm -> Complete), reclaiming
    /// the slot — it does NOT park a stuck Receiving orphan. A well-formed
    /// sender never mints one (a single-fragment message rides T_MID_FRAME,
    /// not the fragment path), but a duplicate mid-chain fragment can clear a
    /// chain and strand its trailing final fragment as a fresh start;
    /// completing it here (zenoh-pico rx.c `if (!more) decode` parity) is what
    /// keeps the next in-order message from merging into a parked orphan (the
    /// R311oo dup-fragment merge bug — see
    /// `stranded_final_fragment_does_not_merge_into_next_message`).
    #[test]
    fn first_fragment_more_zero_completes_immediately() {
        let mut d = dispatcher::<4, 64>();
        let mut out: Option<Vec<u8>> = None;
        let r = d.ingest(frag(PEER_A, true, 1, 0, b"solo"), MASK, 0, |m| {
            out = Some(m.to_vec())
        });
        assert_eq!(r, IngestOutcome::Reassembled);
        assert_eq!(out.as_deref(), Some(&b"solo"[..]));
        // Slot reclaimed — no stuck orphan left to absorb the next message.
        assert_eq!(d.active_chains(), 0);
    }

    /// R311oo regression — a stranded lone M=0 fragment does NOT merge into
    /// the next in-order message.
    ///
    /// The dup-fragment bug: a duplicate mid-chain fragment trips the channel
    /// SN gate; the drive layer clears the in-progress chain via
    /// [`ReassemblyDispatcher::abort_channel`], leaving the chain's trailing
    /// final (M=0) fragment to arrive as a fresh chain start. Before the fix
    /// that M=0 fragment parked a stuck Receiving orphan whose `last_sn` was
    /// ring-consecutive to the NEXT message's first fragment (SNs run
    /// sequentially across messages on a channel), so the next message was
    /// appended onto the orphan's tail and delivered as one merged blob. Now
    /// the M=0 fragment completes + is reclaimed immediately, so the next
    /// message reassembles in isolation.
    #[test]
    fn stranded_final_fragment_does_not_merge_into_next_message() {
        let mut d = dispatcher::<4, 64>();
        let mut delivered: Vec<Vec<u8>> = Vec::new();

        // P1 opens a chain with its first fragment (sn=1, more).
        assert_eq!(
            d.ingest(frag(PEER_A, true, 1, 1, b"P1HEAD"), MASK, 0, |_| panic!(
                "P1 head is not final"
            )),
            IngestOutcome::Begun
        );
        // A duplicate mid-chain fragment trips the channel SN gate; the drive
        // layer clears the chain (drive.rs `abort_channel` on RxSnRejected).
        assert!(
            d.abort_channel(PEER_A, Priority::DEFAULT, true),
            "the in-progress P1 chain was cleared by the SN-gate rejection"
        );
        assert_eq!(d.active_chains(), 0);

        // P1's trailing FINAL fragment (sn=3 — the duplicated/aborted fragment
        // held sn=2) now arrives as a fresh chain start. It completes
        // immediately and is delivered ALONE; it does NOT park an orphan.
        assert_eq!(
            d.ingest(frag(PEER_A, true, 3, 0, b"P1TAIL"), MASK, 0, |m| delivered
                .push(m.to_vec())),
            IngestOutcome::Reassembled
        );
        assert_eq!(
            d.active_chains(),
            0,
            "no stuck orphan after the stranded final fragment"
        );

        // P2: a fresh two-fragment message whose first SN (4) is
        // ring-consecutive to the stranded fragment's SN (3) — exactly the
        // condition that, with a parked orphan, merged P2 onto P1's tail.
        assert_eq!(
            d.ingest(frag(PEER_A, true, 4, 1, b"P2a"), MASK, 0, |_| panic!(
                "P2 head is not final"
            )),
            IngestOutcome::Begun
        );
        assert_eq!(
            d.ingest(frag(PEER_A, true, 5, 0, b"P2b"), MASK, 0, |m| delivered
                .push(m.to_vec())),
            IngestOutcome::Reassembled
        );

        // The stranded fragment delivered ALONE, then P2 delivered CLEAN — the
        // pre-fix bug produced a single merged "P1TAILP2aP2b" delivery instead.
        assert_eq!(delivered, vec![b"P1TAIL".to_vec(), b"P2aP2b".to_vec()]);
    }

    /// R311y215 (SN-safety F4) — the QoS priority is part of the §2.3 chain key:
    /// same peer + same reliability but DIFFERENT priority are INDEPENDENT
    /// chains, so a `high` and a `low` fragment stream reassemble separately even
    /// when their SNs collide. Without the priority component the same-SN `low`
    /// first fragment would look like a duplicate of the `high` chain and abort
    /// it. (The priority key is unconditional — DEFAULT under a non-QoS session —
    /// so this holds in every build.)
    #[test]
    fn qos_priority_keys_distinct_chains() {
        let mut d = dispatcher::<4, 64>();
        let hi = |sn, more, p| Fragment {
            peer_key: PEER_A,
            reliable: true,
            sn,
            more,
            payload: p,
            priority: Priority::RealTime,
            markers: crate::extfragment::FragmentMarkers::NONE,
        };
        let lo = |sn, more, p| Fragment {
            peer_key: PEER_A,
            reliable: true,
            sn,
            more,
            payload: p,
            priority: Priority::Background,
            markers: crate::extfragment::FragmentMarkers::NONE,
        };
        assert_eq!(
            d.ingest(hi(1, 1, b"H1"), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        // Same peer/reliable/SN but a DIFFERENT priority starts its OWN chain,
        // not a duplicate of the high chain.
        assert_eq!(
            d.ingest(lo(1, 1, b"L1"), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        assert_eq!(d.active_chains(), 2, "high and low are independent chains");

        let mut out: Vec<Vec<u8>> = Vec::new();
        assert_eq!(
            d.ingest(hi(2, 0, b"H2"), MASK, 0, |m| out.push(m.to_vec())),
            IngestOutcome::Reassembled
        );
        assert_eq!(
            d.ingest(lo(2, 0, b"L2"), MASK, 0, |m| out.push(m.to_vec())),
            IngestOutcome::Reassembled
        );
        assert_eq!(
            out,
            vec![b"H1H2".to_vec(), b"L1L2".to_vec()],
            "each priority chain reassembled its own payload"
        );
    }

    /// A same-priority rejection clears ONLY that priority's chain, not a
    /// sibling priority's (SN-safety F4, the `abort_channel` priority arg).
    #[test]
    fn abort_channel_is_priority_scoped() {
        let mut d = dispatcher::<4, 64>();
        let mk = |sn, p| Fragment {
            peer_key: PEER_A,
            reliable: true,
            sn,
            more: 1,
            payload: b"x",
            priority: p,
            markers: crate::extfragment::FragmentMarkers::NONE,
        };
        d.ingest(mk(1, Priority::RealTime), MASK, 0, |_| {});
        d.ingest(mk(1, Priority::Background), MASK, 0, |_| {});
        assert_eq!(d.active_chains(), 2);
        // Abort only the high chain; the low chain survives.
        assert!(d.abort_channel(PEER_A, Priority::RealTime, true));
        assert_eq!(d.active_chains(), 1, "only the high-priority chain cleared");
        assert!(
            !d.abort_channel(PEER_A, Priority::RealTime, true),
            "high already gone"
        );
        assert!(
            d.abort_channel(PEER_A, Priority::Background, true),
            "low still present"
        );
        assert_eq!(d.active_chains(), 0);
    }
}

// ── The slot binding's outbox: each duty body posts the effect the Router then
//    performs, nothing else posts, and nothing stays posted after a drive. ──
#[cfg(test)]
mod duty_tests {
    use super::*;
    // Aliased so the event paths the source-scanning test in this file counts
    // are spelled by their producers alone.
    use crate::reassembly_slot::ReassemblySlotEvent as Event;
    use crate::reassembly_slot::ReassemblySlotState as State;
    use std::vec::Vec;

    const PEER: &[u8] = &[0xAA; 16];
    const MASK: crate::sn::Sn = crate::sn::mask_from_res(0x02);

    type TestSlot = Slot<1, 64, HeapStaging<1, 64>>;

    fn frag(sn: u64, more: u8, payload: &[u8]) -> Fragment<'_> {
        Fragment {
            peer_key: PEER,
            reliable: true,
            sn,
            more,
            payload,
            priority: Priority::DEFAULT,
            markers: crate::extfragment::FragmentMarkers::NONE,
        }
    }

    fn assert_drained<const S: usize, const C: usize, A: ChainStaging<S, C>>(
        d: &ReassemblyDispatcher<S, C, A>,
    ) {
        for slot in &d.slots {
            assert_eq!(
                slot.engine.policy().actions().pending(),
                0,
                "a duty was posted and never drained"
            );
        }
    }

    /// Send `event`, return the duties it posted, and check the outbox is
    /// empty again.
    fn drive(slot: &mut TestSlot, event: Event) -> u8 {
        let duties = slot.drive(event);
        assert_eq!(slot.engine.policy().actions().pending(), 0);
        duties
    }

    fn chunk(slot: &mut TestSlot, more: u8) -> u8 {
        let duties = slot.drive_chunk(more);
        assert_eq!(slot.engine.policy().actions().pending(), 0);
        duties
    }

    fn state(slot: &TestSlot) -> State {
        slot.engine.get_current_state()
    }

    /// A slot put back in service in the middle of a chain is a fresh one where it stands: its
    /// machine is at `Empty` with nothing posted, it holds no chain, and the next first fragment
    /// begins a chain as on a slot never used.
    #[test]
    fn a_replaced_slot_is_fresh_in_its_own_place() {
        let mut staging = <HeapStaging<1, 64> as BuildsOwnStorage<1, 64>>::new();
        let mut slot = TestSlot::new();
        assert_eq!(state(&slot), State::Empty);
        assert_eq!(chunk(&mut slot, 1), duty::BEGIN);
        assert_eq!(state(&slot), State::Receiving);

        slot.replace(&mut staging);
        assert_eq!(state(&slot), State::Empty, "the machine was started again");
        assert_eq!(slot.engine.policy().actions().pending(), 0);
        assert!(slot.is_free());
        assert_eq!(staging.available(), 1, "the arena lent nothing");
        assert_eq!(chunk(&mut slot, 1), duty::BEGIN);
        assert_eq!(state(&slot), State::Receiving);
    }

    /// Each way a slot leaves service ends where a slot never used starts: the machine at `Empty`
    /// with nothing posted, no chain held, and the chain's staging back in the arena. An abort
    /// the machine takes and a release from `Complete` reset it in place; a release it does not
    /// answer, an abort arm it does not have and a replacement start it again.
    #[test]
    fn every_ending_of_a_slot_frees_it_and_its_staging() {
        let mut staging = <HeapStaging<1, 64> as BuildsOwnStorage<1, 64>>::new();
        // A slot whose machine took a first chunk (`more`), holding the chain it began.
        let opened = |staging: &mut HeapStaging<1, 64>, more: u8| {
            let mut slot = TestSlot::new();
            let chain = staging.acquire().expect("the arena holds one buffer");
            slot.open = Some(OpenChain {
                key: ChainKey::new(PEER, true, Priority::DEFAULT),
                last_sn: 0,
                deadline_ms: 0,
                opened: 0,
                chain,
            });
            chunk(&mut slot, more);
            assert_eq!(staging.available(), 0);
            slot
        };
        let cases = [
            (1, SlotEnding::Abort(Event::FragmentOoo), State::Receiving),
            (0, SlotEnding::Release, State::Complete),
            (1, SlotEnding::Release, State::Receiving),
            (0, SlotEnding::Abort(Event::CodecError), State::Complete),
            (1, SlotEnding::Replace, State::Receiving),
        ];
        for (more, ending, before) in cases {
            let mut slot = opened(&mut staging, more);
            assert_eq!(state(&slot), before, "{ending:?}");
            slot.end(&mut staging, ending);
            assert_eq!(state(&slot), State::Empty, "{ending:?} from {before:?}");
            assert_eq!(slot.engine.policy().actions().pending(), 0, "{ending:?}");
            assert!(slot.is_free(), "{ending:?}");
            assert_eq!(staging.available(), 1, "{ending:?} gave the staging back");
        }
    }

    /// Every transition of `reassembly_slot.scxml` posts exactly the duties of
    /// the actions it names, and a state that does not answer an event posts
    /// nothing. This is the binding checked against the machine, transition
    /// by transition, without the Router in between.
    #[test]
    fn each_slot_transition_posts_the_duties_its_actions_name() {
        let mut slot = TestSlot::new();
        assert_eq!(chunk(&mut slot, 1), duty::BEGIN);
        assert_eq!(state(&slot), State::Receiving);
        assert_eq!(chunk(&mut slot, 1), duty::APPEND);
        assert_eq!(chunk(&mut slot, 0), duty::FINALIZE);
        assert_eq!(state(&slot), State::Complete);
        assert_eq!(drive(&mut slot, Event::SlotRelease), duty::RESET);
        assert_eq!(state(&slot), State::Empty);

        // A first fragment that is also the last: one transition, two actions.
        assert_eq!(chunk(&mut slot, 0), duty::BEGIN | duty::FINALIZE);
        assert_eq!(state(&slot), State::Complete);
        assert_eq!(drive(&mut slot, Event::SlotRelease), duty::RESET);

        for abort in [
            Event::FragmentOoo,
            Event::FragmentDrop,
            Event::SlotEvict,
            Event::CodecError,
        ] {
            assert_eq!(drive(&mut slot, abort), 0, "{abort:?} on an Empty slot");
            assert_eq!(chunk(&mut slot, 1), duty::BEGIN);
            assert_eq!(drive(&mut slot, abort), duty::ABORT, "{abort:?}");
            assert_eq!(state(&slot), State::Aborted, "{abort:?}");
            assert_eq!(
                drive(&mut slot, Event::SlotRelease),
                duty::RESET,
                "{abort:?}"
            );
        }

        // The timeout's action is a notice: it posts nothing, and the release
        // after it still resets the slot.
        assert_eq!(chunk(&mut slot, 1), duty::BEGIN);
        assert_eq!(drive(&mut slot, Event::ReassemblyTimeout), 0);
        assert_eq!(state(&slot), State::TimedOut);
        assert_eq!(drive(&mut slot, Event::SlotRelease), duty::RESET);

        assert_eq!(
            drive(&mut slot, Event::SlotRelease),
            0,
            "Empty has no release"
        );
        assert_eq!(state(&slot), State::Empty);
    }

    /// The wire `more` bit is the event a fragment is sent as, `fragment.more` for a set bit of
    /// any value and `fragment.last` for a clear one, and the one way into a slot machine posts
    /// it with no payload. From `Empty` a set bit begins a chain and a clear one begins and
    /// finalizes it; from `Receiving` a set bit appends and a clear one finalizes; `Complete`
    /// answers neither. Each turn leaves the outbox drained.
    #[test]
    fn the_more_bit_is_the_event_a_fragment_is_sent_as() {
        assert_eq!(chunk_event(1), Event::FragmentMore);
        assert_eq!(chunk_event(0x80), Event::FragmentMore);
        assert_eq!(chunk_event(0), Event::FragmentLast);
        assert_eq!(
            core::mem::size_of::<
                <ReassemblySlotPolicy<SlotBinding> as sce_rust_runtime::StatePolicy>::Payload,
            >(),
            0,
            "no slot event carries a payload"
        );

        let mut slot = TestSlot::new();
        let last = turn_slot_engine(&mut slot.engine, Event::FragmentLast);
        assert_eq!(last, duty::BEGIN | duty::FINALIZE, "a lone last fragment");
        assert_eq!(state(&slot), State::Complete);
        for event in [Event::FragmentMore, Event::FragmentLast] {
            assert_eq!(
                turn_slot_engine(&mut slot.engine, event),
                0,
                "{event:?} in Complete"
            );
            assert_eq!(state(&slot), State::Complete, "{event:?}");
        }
        assert_eq!(
            turn_slot_engine(&mut slot.engine, Event::SlotRelease),
            duty::RESET
        );

        assert_eq!(
            turn_slot_engine(&mut slot.engine, Event::FragmentMore),
            duty::BEGIN
        );
        assert_eq!(state(&slot), State::Receiving);
        assert_eq!(
            turn_slot_engine(&mut slot.engine, Event::FragmentMore),
            duty::APPEND
        );
        assert_eq!(state(&slot), State::Receiving);
        assert_eq!(
            turn_slot_engine(&mut slot.engine, Event::FragmentLast),
            duty::FINALIZE
        );
        assert_eq!(state(&slot), State::Complete);
        assert_eq!(
            turn_slot_engine(&mut slot.engine, Event::SlotRelease),
            duty::RESET
        );

        let timeout = {
            assert_eq!(chunk(&mut slot, 1), duty::BEGIN);
            turn_slot_engine(&mut slot.engine, Event::ReassemblyTimeout)
        };
        assert_eq!(timeout, 0, "the timeout's action is a notice");
        assert_eq!(state(&slot), State::TimedOut);
        assert_eq!(
            turn_slot_engine(&mut slot.engine, Event::SlotRelease),
            duty::RESET
        );
        assert_eq!(state(&slot), State::Empty);
        assert_eq!(slot.engine.policy().actions().pending(), 0);
    }

    /// No ingest path, and neither the channel abort nor the sweep, leaves a
    /// duty posted for the next drive to find.
    #[test]
    fn no_router_path_leaves_a_duty_in_the_outbox() {
        fn feed(
            d: &mut ReassemblyDispatcher<2, 8>,
            sn: u64,
            more: u8,
            payload: &[u8],
        ) -> IngestOutcome {
            let outcome = d.ingest(frag(sn, more, payload), MASK, 0, |_| {});
            assert_drained(d);
            outcome
        }
        let mut d: ReassemblyDispatcher<2, 8> =
            ReassemblyDispatcher::new(ReassemblyConfig::new(2, 100));
        assert_eq!(feed(&mut d, 1, 1, b"aa"), IngestOutcome::Begun);
        assert_eq!(feed(&mut d, 2, 1, b"bb"), IngestOutcome::Continued);
        assert_eq!(feed(&mut d, 3, 0, b"cc"), IngestOutcome::Reassembled);
        assert_eq!(feed(&mut d, 4, 0, b"dd"), IngestOutcome::Reassembled);
        assert_eq!(feed(&mut d, 5, 1, b"ee"), IngestOutcome::Begun);
        assert_eq!(
            feed(&mut d, 9, 1, b"ff"),
            IngestOutcome::Aborted(AbortReason::OutOfOrder)
        );
        assert_eq!(feed(&mut d, 10, 1, b"gg"), IngestOutcome::Begun);
        assert_eq!(
            feed(&mut d, 11, 1, b"hhhhhhh"),
            IngestOutcome::Aborted(AbortReason::CapacityOverflow)
        );
        assert_eq!(
            feed(&mut d, 12, 1, b"123456789"),
            IngestOutcome::Aborted(AbortReason::CapacityOverflow)
        );
        assert_eq!(feed(&mut d, 13, 1, b"ii"), IngestOutcome::Begun);
        assert!(d.abort_channel(PEER, Priority::DEFAULT, true));
        assert_drained(&d);
        assert_eq!(feed(&mut d, 14, 1, b"jj"), IngestOutcome::Begun);
        assert_eq!(d.sweep(1_000), 1);
        assert_drained(&d);
        assert_eq!(d.active_chains(), 0);
        assert_eq!(d.staging_available(), 2);
    }

    /// A first fragment wider than the slot ends where it arrived: the arena's
    /// reservation goes back and the slot machine never leaves `Empty`.
    #[test]
    fn a_first_fragment_wider_than_the_slot_never_reaches_the_machine() {
        let mut d: ReassemblyDispatcher<1, 8> =
            ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000));
        assert_eq!(
            d.ingest(frag(1, 1, b"123456789"), MASK, 0, |_| panic!(
                "a refused chain delivers nothing"
            )),
            IngestOutcome::Aborted(AbortReason::CapacityOverflow)
        );
        assert_eq!(d.active_chains(), 0);
        assert_eq!(d.staging_available(), 1, "the reservation was returned");
        assert_eq!(d.slots[0].engine.get_current_state(), State::Empty);
        assert_eq!(
            d.ingest(frag(2, 1, b"1234"), MASK, 0, |_| {}),
            IngestOutcome::Begun,
            "the one slot still serves a chain that fits"
        );
    }

    /// The bound is inclusive: a chain of exactly `CAP` bytes reassembles,
    /// whether one fragment carries it or two.
    #[test]
    fn a_chain_of_exactly_the_slot_width_reassembles() {
        let mut d: ReassemblyDispatcher<1, 8> =
            ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000));
        let mut got: Vec<Vec<u8>> = Vec::new();
        assert_eq!(
            d.ingest(frag(1, 0, b"12345678"), MASK, 0, |m| got.push(m.to_vec())),
            IngestOutcome::Reassembled
        );
        assert_eq!(
            d.ingest(frag(2, 1, b"abcd"), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        assert_eq!(
            d.ingest(frag(3, 0, b"efgh"), MASK, 0, |m| got.push(m.to_vec())),
            IngestOutcome::Reassembled
        );
        assert_eq!(got, [b"12345678".to_vec(), b"abcdefgh".to_vec()]);
    }

    /// A timed-out chain is reclaimed by the release the sweep raises after
    /// the timeout: counted once, with the bytes it had staged, its staging
    /// back in the arena and its slot machine at `Empty`.
    #[test]
    fn a_swept_chain_is_reclaimed_by_the_release_after_the_timeout() {
        let mut d: ReassemblyDispatcher<1, 64> =
            ReassemblyDispatcher::new(ReassemblyConfig::new(2, 100));
        d.ingest(frag(1, 1, b"abc"), MASK, 0, |_| {});
        d.ingest(frag(2, 1, b"de"), MASK, 0, |_| {});
        assert_eq!(
            d.sweep_counting(100),
            ChainLoss {
                chains: 1,
                bytes: 5
            }
        );
        assert_eq!(d.active_chains(), 0);
        assert_eq!(d.staging_available(), 1);
        assert_eq!(d.slots[0].engine.get_current_state(), State::Empty);
        assert_eq!(d.sweep_counting(1_000), ChainLoss::default());
    }

    /// A slot whose machine is not at `Empty` while the Router holds it free
    /// does not begin a chain: the start is refused, the reservation goes back
    /// and the slot gets a fresh machine that serves the next start.
    #[test]
    fn a_slot_machine_that_does_not_begin_the_chain_is_replaced() {
        let mut d: ReassemblyDispatcher<1, 64> =
            ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000));
        // Behind the Router's back: the machine opens a chain the Router never
        // bound, so it answers the next chunk with `append`, not `begin`.
        d.slots[0].drive_chunk(1);
        assert_eq!(d.slots[0].engine.get_current_state(), State::Receiving);

        assert_eq!(
            d.ingest(frag(1, 1, b"aa"), MASK, 0, |_| {}),
            IngestOutcome::Refused(RefuseReason::PoolExhausted)
        );
        assert_drained(&d);
        assert_eq!(d.slots[0].engine.get_current_state(), State::Empty);
        assert_eq!(d.active_chains(), 0);
        assert_eq!(d.staging_available(), 1, "the reservation went back");
        assert_eq!(
            d.ingest(frag(2, 1, b"bb"), MASK, 0, |_| {}),
            IngestOutcome::Begun,
            "the slot serves the next start"
        );
    }

    /// A continuation the slot's machine does not take ends the chain: the
    /// machine left `Receiving` behind the Router's back, so neither `append`
    /// nor `finalize` runs, and the slot is freed with a fresh machine.
    #[test]
    fn a_continuation_the_slot_machine_does_not_take_ends_the_chain() {
        let mut d: ReassemblyDispatcher<1, 64> =
            ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000));
        d.ingest(frag(1, 1, b"aa"), MASK, 0, |_| {});
        d.slots[0].drive(Event::ReassemblyTimeout);
        assert_eq!(d.slots[0].engine.get_current_state(), State::TimedOut);

        assert_eq!(
            d.ingest(frag(2, 0, b"bb"), MASK, 0, |_| panic!(
                "a chain the machine gave up is not delivered"
            )),
            IngestOutcome::Aborted(AbortReason::CapacityOverflow)
        );
        assert_eq!(d.slots[0].engine.get_current_state(), State::Empty);
        assert_eq!(d.active_chains(), 0);
        assert_eq!(d.staging_available(), 1);
        assert_eq!(
            d.capacity_refusals(),
            0,
            "the configured bound refused nothing"
        );
    }

    /// An abort the slot's machine does not take still ends the chain the
    /// Router gave up on.
    #[test]
    fn an_abort_the_slot_machine_does_not_take_still_frees_the_slot() {
        let mut d: ReassemblyDispatcher<1, 64> =
            ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000));
        d.ingest(frag(1, 1, b"aa"), MASK, 0, |_| {});
        // `TimedOut` answers `slot.release` only, so `fragment.ooo` posts
        // nothing.
        d.slots[0].drive(Event::ReassemblyTimeout);
        assert!(d.abort_channel(PEER, Priority::DEFAULT, true));
        assert_eq!(d.slots[0].engine.get_current_state(), State::Empty);
        assert_eq!(d.active_chains(), 0);
        assert_eq!(d.staging_available(), 1);
    }

    /// An arena that admits bytes with `fits` and refuses them in `append`:
    /// the heap arena with its `append` switched off by `refuse`. `refused`
    /// counts the appends it turned away, so a test tells the dispatcher's
    /// ending of the chain from a chain this arena never saw.
    struct RefusingStaging<const SLOTS: usize, const CAP: usize> {
        inner: HeapStaging<SLOTS, CAP>,
        refuse: bool,
        refused: usize,
    }

    impl<const SLOTS: usize, const CAP: usize> BuildsOwnStorage<SLOTS, CAP>
        for RefusingStaging<SLOTS, CAP>
    {
        fn new() -> Self {
            Self {
                inner: <HeapStaging<SLOTS, CAP> as BuildsOwnStorage<SLOTS, CAP>>::new(),
                refuse: false,
                refused: 0,
            }
        }
    }

    impl<const SLOTS: usize, const CAP: usize> ChainStaging<SLOTS, CAP>
        for RefusingStaging<SLOTS, CAP>
    {
        type Chain = crate::chain_staging::HeapChain<CAP>;

        fn acquire(&mut self) -> Option<Self::Chain> {
            self.inner.acquire()
        }

        fn release(&mut self, chain: Self::Chain) {
            self.inner.release(chain)
        }

        fn append(
            &mut self,
            chain: &mut Self::Chain,
            payload: &[u8],
        ) -> Result<(), crate::chain_staging::StagingError> {
            if self.refuse {
                self.refused += 1;
                return Err(crate::chain_staging::StagingError::ChainCapExceeded);
            }
            self.inner.append(chain, payload)
        }

        fn bytes<'a>(&'a self, chain: &'a Self::Chain) -> &'a [u8] {
            self.inner.bytes(chain)
        }

        fn buf<'a>(
            &'a mut self,
            chain: &'a mut Self::Chain,
            want: usize,
        ) -> Result<&'a mut [u8], crate::chain_staging::StagingError> {
            self.inner.buf(chain, want)
        }

        fn commit(
            &mut self,
            chain: &mut Self::Chain,
            filled: usize,
        ) -> Result<(), crate::chain_staging::StagingError> {
            self.inner.commit(chain, filled)
        }

        fn available(&self) -> usize {
            self.inner.available()
        }
    }

    type Refusing = ReassemblyDispatcher<1, 64, RefusingStaging<1, 64>>;

    /// The arena refuses a first fragment it said would fit: the chain ends as
    /// a capacity overflow, its staging back in the arena and its machine at
    /// `Empty`, and the next start is served.
    #[test]
    fn an_arena_that_refuses_a_first_fragment_it_admitted_ends_the_chain() {
        let mut d = Refusing::new(ReassemblyConfig::new(2, 5_000));
        d.staging.refuse = true;
        assert_eq!(
            d.ingest(frag(1, 1, b"aa"), MASK, 0, |_| {}),
            IngestOutcome::Aborted(AbortReason::CapacityOverflow)
        );
        assert_eq!(d.staging.refused, 1, "the arena was asked for the bytes");
        assert_drained(&d);
        assert_eq!(d.slots[0].engine.get_current_state(), State::Empty);
        assert_eq!(d.active_chains(), 0);
        assert_eq!(d.staging_available(), 1);
        assert_eq!(d.capacity_refusals(), 0);

        d.staging.refuse = false;
        assert_eq!(
            d.ingest(frag(2, 1, b"bb"), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
    }

    /// The arena refuses a continuation and, on another chain, a final
    /// fragment: each chain ends undelivered and frees its slot.
    #[test]
    fn an_arena_that_refuses_a_later_fragment_it_admitted_ends_the_chain() {
        for more in [1u8, 0] {
            let mut d = Refusing::new(ReassemblyConfig::new(2, 5_000));
            assert_eq!(
                d.ingest(frag(1, 1, b"aa"), MASK, 0, |_| {}),
                IngestOutcome::Begun
            );
            d.staging.refuse = true;
            assert_eq!(
                d.ingest(frag(2, more, b"bb"), MASK, 0, |_| panic!(
                    "a chain whose bytes were refused is not delivered"
                )),
                IngestOutcome::Aborted(AbortReason::CapacityOverflow),
                "more = {more}"
            );
            assert_eq!(
                d.staging.refused, 1,
                "the arena was asked for the second fragment's bytes, more = {more}"
            );
            assert_drained(&d);
            assert_eq!(
                d.slots[0].engine.get_current_state(),
                State::Empty,
                "more = {more}"
            );
            assert_eq!(d.active_chains(), 0, "more = {more}");
            assert_eq!(d.staging_available(), 1, "more = {more}");
        }
    }
}

// ── R311y578 — the Fragment chain-boundary markers (`0x2 First` /
//    `0x3 Drop`), the rules zenoh gates on the negotiated patch level
//    (`unicast/universal/rx.rs:155-170`). Before this round the Router
//    read neither marker: the statechart had declared a `fragment.drop`
//    -> Aborted transition since R311im with NO producer anywhere in the
//    tree, and a fragment that started a chain without the `First` marker
//    was accepted as a chain start. ──
#[cfg(test)]
mod chain_boundary_marker_tests {
    use super::*;
    use crate::extfragment::FragmentMarkers;
    use crate::reassembly_slot::ReassemblySlotState;
    use std::vec::Vec;

    const PEER: &[u8] = &[0xAA; 16];
    const MASK: crate::sn::Sn = crate::sn::mask_from_res(0x02);

    /// The dispatcher under the ARMED contract — what a session whose peer
    /// negotiated patch >= 1 actually runs. One slot on purpose in the
    /// reuse tests below, so a chain that fails to release its slot cannot
    /// hide behind a spare.
    fn armed<const S: usize, const C: usize>() -> ReassemblyDispatcher<S, C> {
        ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000).with_fragmentation_markers(true))
    }

    fn marked<'a>(sn: u64, more: u8, payload: &'a [u8], markers: FragmentMarkers) -> Fragment<'a> {
        Fragment {
            peer_key: PEER,
            reliable: true,
            sn,
            more,
            payload,
            priority: Priority::DEFAULT,
            markers,
        }
    }

    const FIRST: FragmentMarkers = FragmentMarkers {
        first: true,
        dropped: false,
    };
    const DROP: FragmentMarkers = FragmentMarkers {
        first: false,
        dropped: true,
    };
    const NONE: FragmentMarkers = FragmentMarkers::NONE;

    /// The OBSERVER case, and the whole reason the rule exists: a reader
    /// that attaches to a live flow sees a chain already in progress. Its
    /// fragments carry no `First` marker, so they are not a chain start —
    /// they are a headless tail, and staging them would hand the upstream
    /// decoder a message that begins in the middle of a network message.
    ///
    /// Both the continuation AND its final fragment are refused, so the
    /// `deliver` closure never fires. A panicking closure is the
    /// assertion: a delivery here is exactly the failure being excluded.
    #[test]
    fn a_marker_less_chain_start_is_refused() {
        let mut d = armed::<4, 256>();
        assert_eq!(
            d.ingest(marked(10, 1, b"tail-", NONE), MASK, 0, |_| panic!(
                "a headless tail must never be delivered"
            )),
            IngestOutcome::Refused(RefuseReason::MissingStartMarker)
        );
        assert_eq!(d.active_chains(), 0, "no slot was consumed by the refusal");
        assert_eq!(
            d.ingest(marked(11, 0, b"end", NONE), MASK, 0, |_| panic!(
                "a headless tail must never be delivered"
            )),
            IngestOutcome::Refused(RefuseReason::MissingStartMarker)
        );
        assert_eq!(d.active_chains(), 0);
    }

    /// The NEGATIVE arm the positive one needs: the identical marker-less
    /// sequence DOES reassemble with the rules disarmed. Without this the
    /// refusal above could be any decode failure; with it, the only
    /// difference between reassembling and refusing is the negotiated
    /// patch level — which is the claim.
    #[test]
    fn the_same_marker_less_chain_reassembles_when_the_rules_are_disarmed() {
        let mut d: ReassemblyDispatcher<4, 256> =
            ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000));
        assert!(!d.fragmentation_markers());
        assert_eq!(
            d.ingest(marked(10, 1, b"tail-", NONE), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        let mut got: Option<Vec<u8>> = None;
        assert_eq!(
            d.ingest(marked(11, 0, b"end", NONE), MASK, 0, |m| got =
                Some(m.to_vec())),
            IngestOutcome::Reassembled
        );
        assert_eq!(got.as_deref(), Some(&b"tail-end"[..]));
    }

    /// A marked chain start is accepted and the chain completes normally —
    /// the rules must not break the ordinary path they gate.
    #[test]
    fn a_marked_chain_start_reassembles() {
        let mut d = armed::<4, 256>();
        assert_eq!(
            d.ingest(marked(1, 1, b"hello ", FIRST), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        let mut got: Option<Vec<u8>> = None;
        assert_eq!(
            d.ingest(marked(2, 0, b"world", NONE), MASK, 0, |m| got =
                Some(m.to_vec())),
            IngestOutcome::Reassembled
        );
        assert_eq!(got.as_deref(), Some(&b"hello world"[..]));
    }

    /// The `First` marker SUPERSEDES a chain already open on the key, and
    /// the assertion is on the BYTES, not on the outcome enum: the sender
    /// restarted, so the stranded prefix must not survive into the
    /// delivered message.
    ///
    /// The restart SN is deliberately consecutive with the stranded
    /// chain's (`1 -> 2`), so a Router that ignored the marker would take
    /// the second fragment as an in-order continuation and deliver
    /// `AAABBBCCC`. Only a Router that reads the marker delivers `BBBCCC`.
    #[test]
    fn a_first_marker_discards_the_stranded_prefix() {
        let mut d = armed::<4, 256>();
        assert_eq!(
            d.ingest(marked(1, 1, b"AAA", FIRST), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        assert_eq!(
            d.ingest(marked(2, 1, b"BBB", FIRST), MASK, 0, |_| {}),
            IngestOutcome::Begun,
            "the restart opens a NEW chain rather than continuing the old one"
        );
        assert_eq!(d.active_chains(), 1, "one chain, not two");
        let mut got: Option<Vec<u8>> = None;
        assert_eq!(
            d.ingest(marked(3, 0, b"CCC", NONE), MASK, 0, |m| got =
                Some(m.to_vec())),
            IngestOutcome::Reassembled
        );
        assert_eq!(
            got.as_deref(),
            Some(&b"BBBCCC"[..]),
            "the superseded prefix must not ride along"
        );
    }

    /// A continuation is taken only onto a slot that holds a chain: a free slot where the judge
    /// looked is refused and nothing is opened on it. This is what keeps a restart that evicted
    /// its key's chain from reaching the evicted slot as a continuation: it starts afresh only
    /// because the marker rules hand the judge no slot once they evicted it.
    #[test]
    fn a_continuation_onto_a_free_slot_is_refused_and_opens_nothing() {
        let mut d = armed::<2, 256>();
        let frag = marked(2, 1, b"BBB", NONE);
        match d.admit_continuation(0, &frag, SnRing::Known(crate::sn::to_wire(MASK))) {
            Err(Judged::Outcome(IngestOutcome::Refused(RefuseReason::PoolExhausted))) => {}
            other => panic!("a free slot continues nothing, got {other:?}"),
        }
        assert_eq!(d.active_chains(), 0, "and no chain is opened");
    }

    /// The same sequence with the rules DISARMED delivers the merged
    /// blob — the exact wrong answer the marker exists to prevent, pinned
    /// so the previous test cannot pass for an unrelated reason.
    #[test]
    fn without_the_rules_the_restart_merges_into_the_stranded_prefix() {
        let mut d: ReassemblyDispatcher<4, 256> =
            ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000));
        d.ingest(marked(1, 1, b"AAA", FIRST), MASK, 0, |_| {});
        d.ingest(marked(2, 1, b"BBB", FIRST), MASK, 0, |_| {});
        let mut got: Option<Vec<u8>> = None;
        d.ingest(marked(3, 0, b"CCC", NONE), MASK, 0, |m| {
            got = Some(m.to_vec())
        });
        assert_eq!(
            got.as_deref(),
            Some(&b"AAABBBCCC"[..]),
            "disarmed, the marker is invisible and the two generations merge"
        );
    }

    /// The `Drop` marker aborts the open chain with its OWN reason. The
    /// distinction from `OutOfOrder` is the point: this is a healthy
    /// sender announcing the abandon on the wire (zenoh's TX pipeline
    /// mints it when it cannot obtain a batch mid-fragmentation), not a
    /// receiver-side inference from sequence numbers.
    #[test]
    fn a_drop_marker_aborts_the_open_chain() {
        let mut d = armed::<4, 256>();
        d.ingest(marked(1, 1, b"AAA", FIRST), MASK, 0, |_| {});
        assert_eq!(d.active_chains(), 1);
        assert_eq!(
            d.ingest(marked(2, 1, b"", DROP), MASK, 0, |_| panic!(
                "an abandoned chain must never be delivered"
            )),
            IngestOutcome::Aborted(AbortReason::SenderDropped)
        );
        assert_eq!(d.active_chains(), 0, "the slot was reclaimed");
    }

    /// The Router drove the slot FSM through a DECLARED transition rather
    /// than clearing its own chain state behind the engine's back.
    ///
    /// The discriminator is the engine's resting state, not slot reuse.
    /// `Slot::release` raises `slot.release`, which only the three
    /// TERMINAL states answer; a slot cleared without first being driven
    /// to `Aborted` therefore stays parked in `Receiving` while the
    /// Router-side key reads free — a desynchronised engine that every
    /// behavioural assertion still passes, because `Receiving` and `Empty`
    /// both accept a `fragment.more` and both complete on a `fragment.last`.
    /// A measured damage probe confirmed it: deleting the
    /// `process_event(FragmentDrop)` line left the whole suite green until
    /// this assertion was added.
    ///
    /// One slot, so the reused engine IS the engine under test.
    #[test]
    fn the_drop_arm_leaves_the_slot_fsm_in_a_declared_state() {
        let mut d = armed::<1, 256>();
        d.ingest(marked(1, 1, b"AAA", FIRST), MASK, 0, |_| {});
        assert_eq!(
            d.slots[0].engine.get_current_state(),
            ReassemblySlotState::Receiving,
            "the chain is open"
        );
        d.ingest(marked(2, 1, b"", DROP), MASK, 0, |_| {});
        assert_eq!(
            d.slots[0].engine.get_current_state(),
            ReassemblySlotState::Empty,
            "fragment.drop -> Aborted -> (slot.release) -> Empty; a slot cleared \
             without the abort transition is stranded in Receiving"
        );
        assert_eq!(d.active_chains(), 0);
        // ...and the released slot serves the next chain with no residue.
        assert_eq!(
            d.ingest(marked(3, 1, b"XX", FIRST), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        let mut got: Option<Vec<u8>> = None;
        assert_eq!(
            d.ingest(marked(4, 0, b"YY", NONE), MASK, 0, |m| got =
                Some(m.to_vec())),
            IngestOutcome::Reassembled
        );
        assert_eq!(got.as_deref(), Some(&b"XXYY"[..]));
    }

    /// Each marker abort raises its own arm of the slot FSM, and each arm has
    /// one producer: `fragment.drop` (§2.4.7a peer-drop) in
    /// [`ReassemblyDispatcher::abort_peer_drop`], `slot.evict` (§2.4.6
    /// duplicate-first and oldest-wins) in [`ReassemblyDispatcher::evict`].
    ///
    /// Asserted on the source because both arms post the same abort duty and
    /// the Router releases the slot the same way after either, so which arm
    /// ran is not visible from outside. That the arm ran at all is visible,
    /// and the behavioural tests around this one assert it.
    #[test]
    fn each_marker_abort_raises_its_own_arm() {
        // The needles are ASSEMBLED at compile time, so the joined forms do
        // not occur in this file's own source and cannot self-match.
        let src = include_str!("reassembly_dispatch.rs");
        for (needle, arm) in [
            (
                concat!("ReassemblySlotEvent", "::", "FragmentDrop"),
                "fragment.drop",
            ),
            (
                concat!("ReassemblySlotEvent", "::", "SlotEvict"),
                "slot.evict",
            ),
        ] {
            let raises = src.matches(needle).count();
            assert_eq!(raises, 1, "exactly ONE `{arm}` producer; found {raises}");
        }
    }

    /// A duplicate `First` evicts the open chain through `slot.evict` and the
    /// new chain takes the key (§2.4.6 duplicate-first). One slot, so the new
    /// chain can only begin on the slot the eviction released: had
    /// `abort_evicted` not run, the slot would still hold the old chain.
    #[test]
    fn a_duplicate_first_evicts_the_open_chain_through_slot_evict() {
        let mut d = armed::<1, 256>();
        assert_eq!(
            d.ingest(marked(1, 1, b"AAA", FIRST), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        assert_eq!(
            d.ingest(marked(2, 1, b"BBB", FIRST), MASK, 0, |_| panic!(
                "neither chain is complete"
            )),
            IngestOutcome::Begun,
            "the duplicate First is admitted once the open chain is evicted"
        );
        assert_eq!(d.active_chains(), 1);
        assert_eq!(d.staging_available(), 0, "one chain holds the one slot");
        assert_eq!(
            d.slots[0].engine.get_current_state(),
            ReassemblySlotState::Receiving
        );
        let mut got: Option<Vec<u8>> = None;
        assert_eq!(
            d.ingest(marked(3, 0, b"CCC", NONE), MASK, 0, |m| got =
                Some(m.to_vec())),
            IngestOutcome::Reassembled
        );
        assert_eq!(got.as_deref(), Some(&b"BBBCCC"[..]));
        assert_eq!(d.staging_available(), 1);
        assert_eq!(
            d.slots[0].engine.get_current_state(),
            ReassemblySlotState::Empty
        );
    }

    /// The chain a restart evicts is reported beside the restart's own
    /// admission, for that ingest only: the fragment's outcome is `Begun`, and
    /// the stranded chain is the ingest's displaced one.
    ///
    /// Two keys, so the restart on the reliable key is seen not to report the
    /// best-effort chain that stays open beside it.
    #[test]
    fn a_restart_reports_the_chain_it_superseded_beside_its_own_admission() {
        let mut d = armed::<4, 256>();
        assert_eq!(
            d.ingest(marked(1, 1, b"AAA", FIRST), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        assert_eq!(
            d.displaced_by_last_ingest(),
            None,
            "a start on an idle key ends nothing"
        );
        let best_effort = Fragment {
            reliable: false,
            ..marked(1, 1, b"bbb", FIRST)
        };
        assert_eq!(d.ingest(best_effort, MASK, 0, |_| {}), IngestOutcome::Begun);

        assert_eq!(
            d.ingest(marked(2, 1, b"BBB", FIRST), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
        assert_eq!(
            d.displaced_by_last_ingest(),
            Some(DisplacedChain::Superseded),
            "the restart ended the chain open on its key"
        );
        assert_eq!(d.active_chains(), 2, "the other key's chain is untouched");

        assert_eq!(
            d.ingest(marked(3, 1, b"CCC", NONE), MASK, 0, |_| {}),
            IngestOutcome::Continued
        );
        assert_eq!(
            d.displaced_by_last_ingest(),
            None,
            "the next ingest speaks only of itself"
        );
    }

    /// The same two fragments with the rules disarmed continue one chain, and
    /// nothing is reported displaced: only the `First` rule supersedes.
    #[test]
    fn without_the_rules_nothing_is_reported_superseded() {
        let mut d: ReassemblyDispatcher<4, 256> =
            ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000));
        d.ingest(marked(1, 1, b"AAA", FIRST), MASK, 0, |_| {});
        assert_eq!(
            d.ingest(marked(2, 1, b"BBB", FIRST), MASK, 0, |_| {}),
            IngestOutcome::Continued
        );
        assert_eq!(d.displaced_by_last_ingest(), None);
    }

    /// zenoh's ORDER, which is load-bearing: the missing-start-marker rule
    /// runs BEFORE the drop rule, so a `Drop` arriving onto an idle key is
    /// swallowed as "not a chain start" rather than reported as an abort.
    /// There is nothing to abort — the sender is announcing the end of a
    /// chain this receiver never saw the start of, which is precisely what
    /// a mid-flow attach sees.
    #[test]
    fn a_drop_onto_an_idle_key_is_not_an_abort() {
        let mut d = armed::<4, 256>();
        assert_eq!(
            d.ingest(marked(9, 1, b"", DROP), MASK, 0, |_| {}),
            IngestOutcome::Refused(RefuseReason::MissingStartMarker)
        );
        assert_eq!(d.active_chains(), 0);
    }

    /// The gate is a per-session runtime fact, not a construction-time
    /// one: the dispatcher is built at bring-up, before any Init settles
    /// the patch level, so arming it after the fact must take effect.
    #[test]
    fn the_gate_is_armable_after_construction() {
        let mut d: ReassemblyDispatcher<4, 256> =
            ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000));
        assert!(!d.fragmentation_markers());
        d.set_fragmentation_markers(true);
        assert!(d.fragmentation_markers());
        assert_eq!(
            d.ingest(marked(1, 1, b"tail", NONE), MASK, 0, |_| {}),
            IngestOutcome::Refused(RefuseReason::MissingStartMarker),
            "the rules apply from the moment the level is known"
        );
        d.set_fragmentation_markers(false);
        assert_eq!(
            d.ingest(marked(1, 1, b"tail", NONE), MASK, 0, |_| {}),
            IngestOutcome::Begun
        );
    }

    /// Every new terminal outcome reaches the observer mirror
    /// (`ReassemblyDropReason`) with its own variant. A drop reason that
    /// mapped onto an existing one would make the three cases
    /// indistinguishable in exactly the consumer that needs them apart.
    #[cfg(feature = "alloc")]
    #[test]
    fn the_new_outcomes_map_to_distinct_observer_reasons() {
        use crate::driver_loop::ReassemblyDropReason;
        let seen = [
            ReassemblyDropReason::from_ingest(IngestOutcome::Aborted(AbortReason::SenderDropped)),
            ReassemblyDropReason::from_ingest(IngestOutcome::Aborted(AbortReason::Superseded)),
            ReassemblyDropReason::from_ingest(IngestOutcome::Refused(
                RefuseReason::MissingStartMarker,
            )),
        ];
        assert_eq!(
            seen,
            [
                Some(ReassemblyDropReason::SenderDropped),
                Some(ReassemblyDropReason::Superseded),
                Some(ReassemblyDropReason::MissingStartMarker),
            ]
        );
        // ...and they are not silently equal to the pre-existing reasons.
        assert_ne!(
            ReassemblyDropReason::SenderDropped,
            ReassemblyDropReason::OutOfOrder
        );
    }

    /// A chain an ingest displaced reaches the observer mirror under the word
    /// for how it was displaced, the restart's apart from the eviction's.
    #[cfg(feature = "alloc")]
    #[test]
    fn a_displaced_chain_maps_to_its_own_observer_reason() {
        use crate::driver_loop::ReassemblyDropReason;
        assert_eq!(
            ReassemblyDropReason::from_displaced(DisplacedChain::Superseded),
            ReassemblyDropReason::Superseded
        );
        assert_eq!(
            ReassemblyDropReason::from_displaced(DisplacedChain::Evicted),
            ReassemblyDropReason::Evicted
        );
    }
}

// ── The router over a ring the caller does not know ([`SnRing::Unknown`]): a
//    passive reader that attached after the handshake read no InitAck. The ring
//    decides one thing about a chain, whether a step is consecutive across a
//    wrap; a step of plain `+1` is consecutive on every ring and is the only one
//    admitted without it. ──
#[cfg(test)]
mod unknown_ring_tests {
    use super::*;
    use crate::extfragment::FragmentMarkers;
    use crate::reassembly_slot::ReassemblySlotState;
    use std::vec::Vec;

    const PEER: &[u8] = &[0xAA; 16];
    /// The three rings the 2-bit `seq_num_res` can name below the widest, each
    /// as its mask: 7, 14 and 28 bits (`sn::mask_from_res`).
    const RING_7: crate::sn::Sn = crate::sn::mask_from_res(0x00);
    const RING_14: crate::sn::Sn = crate::sn::mask_from_res(0x01);
    const RING_28: crate::sn::Sn = crate::sn::mask_from_res(0x02);

    fn dispatcher<const S: usize, const C: usize>() -> ReassemblyDispatcher<S, C> {
        ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000))
    }

    fn frag(sn: u64, more: u8, payload: &[u8]) -> Fragment<'_> {
        Fragment {
            peer_key: PEER,
            reliable: true,
            sn,
            more,
            payload,
            priority: Priority::DEFAULT,
            markers: FragmentMarkers::NONE,
        }
    }

    /// Feed one fragment with no ring, returning what the router made of it and
    /// what it delivered.
    fn feed<const S: usize, const C: usize>(
        d: &mut ReassemblyDispatcher<S, C>,
        sn: u64,
        more: u8,
        payload: &[u8],
    ) -> (IngestOutcome, Option<Vec<u8>>) {
        let mut delivered = None;
        let outcome = d.ingest_in_ring(frag(sn, more, payload), SnRing::Unknown, 0, |m| {
            delivered = Some(m.to_vec())
        });
        (outcome, delivered)
    }

    /// A chain whose every step is `+1` is followed and delivered, with no ring.
    /// The sequence numbers are far past what a 7 or 14-bit ring could carry, as
    /// a real capture's are, so no guessed small ring would have admitted them.
    #[test]
    fn a_chain_of_plain_plus_one_steps_reassembles_with_no_ring() {
        let mut d = dispatcher::<4, 64>();
        let first = 109_926_136u64;
        assert_eq!(feed(&mut d, first, 1, b"aaa"), (IngestOutcome::Begun, None));
        assert_eq!(
            feed(&mut d, first + 1, 1, b"bbb"),
            (IngestOutcome::Continued, None)
        );
        let (outcome, delivered) = feed(&mut d, first + 2, 0, b"ccc");
        assert_eq!(outcome, IngestOutcome::Reassembled);
        assert_eq!(delivered.as_deref(), Some(&b"aaabbbccc"[..]));
        assert_eq!(d.active_chains(), 0);
    }

    /// A step that is not `+1` ends the chain as `Unresolvable`: a gap, a repeat,
    /// a step back, and `127 -> 0`, which is a wrap on one ring and a jump on
    /// every other. The router does not say which, and says no more than that.
    ///
    /// The control is the same steps with the ring known, which are judged:
    /// `OutOfOrder` for each of these on the default 28-bit ring (the seam of the
    /// 7-bit ring is a step of `2^28 - 127` there).
    #[test]
    fn a_step_that_is_not_plus_one_ends_the_chain_unresolvable_where_a_ring_would_judge_it() {
        for (last, next) in [(100u64, 102u64), (100, 100), (100, 99), (127, 0)] {
            let mut d = dispatcher::<4, 64>();
            assert_eq!(feed(&mut d, last, 1, b"aaa").0, IngestOutcome::Begun);
            assert_eq!(
                feed(&mut d, next, 1, b"zzz"),
                (IngestOutcome::Aborted(AbortReason::Unresolvable), None),
                "{last} -> {next}"
            );
            assert_eq!(d.active_chains(), 0, "{last} -> {next}: the chain is gone");

            let mut known = dispatcher::<4, 64>();
            known.ingest(frag(last, 1, b"aaa"), RING_28, 0, |_| {});
            assert_eq!(
                known.ingest(frag(next, 1, b"zzz"), RING_28, 0, |_| {
                    panic!("an aborted chain delivers nothing")
                }),
                IngestOutcome::Aborted(AbortReason::OutOfOrder),
                "{last} -> {next} on a ring the router knows"
            );
        }
    }

    /// A known ring judges a chain's SNs by their residue on it, whatever word the build holds a
    /// sequence number in: wire values past 32 bits one step apart on the ring continue the chain,
    /// and two steps apart end it.
    #[test]
    fn a_known_ring_judges_wire_sns_past_32_bits_by_their_residue() {
        let base = 0x1_0000_0000u64 + 5;
        let mut d = dispatcher::<4, 64>();
        assert_eq!(
            d.ingest(frag(base, 1, b"a"), RING_28, 0, |_| {}),
            IngestOutcome::Begun
        );
        assert_eq!(
            d.ingest(frag(base + 1, 0, b"b"), RING_28, 0, |_| {}),
            IngestOutcome::Reassembled
        );
        let mut gap = dispatcher::<4, 64>();
        gap.ingest(frag(base, 1, b"a"), RING_28, 0, |_| {});
        assert_eq!(
            gap.ingest(frag(base + 2, 0, b"b"), RING_28, 0, |_| {
                panic!("an aborted chain delivers nothing")
            }),
            IngestOutcome::Aborted(AbortReason::OutOfOrder)
        );
    }

    /// THE STEP ONLY A RING CAN JUDGE: `127 -> 0` is one step on the 7-bit ring,
    /// a jump on the 14 and 28-bit ones, and with no ring it is unresolvable. The
    /// three answers are the whole reason the router refuses to guess.
    #[test]
    fn the_seam_of_the_smallest_ring_is_a_step_only_the_ring_can_judge() {
        let seam = |ring: SnRing| {
            let mut d = dispatcher::<4, 64>();
            d.ingest_in_ring(frag(126, 1, b"a"), ring, 0, |_| {});
            d.ingest_in_ring(frag(127, 1, b"b"), ring, 0, |_| {});
            d.ingest_in_ring(frag(0, 0, b"c"), ring, 0, |_| {})
        };
        assert_eq!(
            seam(SnRing::Known(crate::sn::to_wire(RING_7))),
            IngestOutcome::Reassembled
        );
        assert_eq!(
            seam(SnRing::Known(crate::sn::to_wire(RING_14))),
            IngestOutcome::Aborted(AbortReason::OutOfOrder)
        );
        assert_eq!(
            seam(SnRing::Known(crate::sn::to_wire(RING_28))),
            IngestOutcome::Aborted(AbortReason::OutOfOrder)
        );
        assert_eq!(
            seam(SnRing::Unknown),
            IngestOutcome::Aborted(AbortReason::Unresolvable)
        );
    }

    /// The largest SN has no successor as an integer, and the router does not
    /// overflow to find out: `u64::MAX -> 0` is a step it cannot judge.
    #[test]
    fn the_step_past_the_largest_sequence_number_is_unresolvable_and_does_not_overflow() {
        let mut d = dispatcher::<4, 64>();
        assert_eq!(feed(&mut d, u64::MAX, 1, b"a").0, IngestOutcome::Begun);
        assert_eq!(
            feed(&mut d, 0, 1, b"b").0,
            IngestOutcome::Aborted(AbortReason::Unresolvable)
        );
    }

    /// Where the ring IS known the router is exactly what it was: the two entry
    /// points answer alike, fragment by fragment and byte for byte, over a run
    /// that holds a clean chain, a gap, a seam and a repeat.
    #[test]
    fn a_known_ring_through_the_new_door_is_the_old_door() {
        let run: [(u64, u8, &[u8]); 9] = [
            (crate::sn::to_wire(RING_7) - 1, 1, &b"a"[..]),
            (crate::sn::to_wire(RING_7), 1, &b"b"[..]),
            (0, 0, &b"c"[..]),
            (5, 1, &b"d"[..]),
            (7, 1, &b"e"[..]),
            (8, 0, &b"f"[..]),
            (20, 1, &b"g"[..]),
            (20, 1, &b"h"[..]),
            (21, 0, &b"i"[..]),
        ];
        for mask in [RING_7, RING_14, RING_28] {
            let (mut old, mut new) = (dispatcher::<4, 64>(), dispatcher::<4, 64>());
            for (sn, more, payload) in run {
                let (mut got_old, mut got_new): (Option<Vec<u8>>, Option<Vec<u8>>) = (None, None);
                let a = old.ingest(frag(sn, more, payload), mask, 0, |m| {
                    got_old = Some(m.to_vec())
                });
                let ring = SnRing::Known(crate::sn::to_wire(mask));
                let b = new.ingest_in_ring(frag(sn, more, payload), ring, 0, |m| {
                    got_new = Some(m.to_vec())
                });
                assert_eq!((a, got_old), (b, got_new), "mask {mask:#x}, sn {sn}");
            }
            assert_eq!(old.active_chains(), new.active_chains());
        }
    }

    /// A chain's START takes no ring: it is the fragment that finds no chain open
    /// (the markers are off here), so any sequence number begins one, and a lone
    /// closing fragment completes in one step, as it does where the ring is known.
    #[test]
    fn a_chain_starts_without_a_ring() {
        let mut d = dispatcher::<4, 64>();
        assert_eq!(feed(&mut d, 77_777, 1, b"a").0, IngestOutcome::Begun);
        let mut lone = dispatcher::<4, 64>();
        let (outcome, delivered) = feed(&mut lone, 5, 0, b"tail");
        assert_eq!(outcome, IngestOutcome::Reassembled);
        assert_eq!(delivered.as_deref(), Some(&b"tail"[..]));
    }

    /// After a chain ends unresolvable its slot is free and the staging is back in
    /// the arena, and the fragments that follow start fresh: the next fragment
    /// begins a chain of its own and a whole chain after that completes.
    ///
    /// One slot, so a chain that left its slot held, or its FSM parked in
    /// `Receiving`, could not begin the next.
    #[test]
    fn an_unresolvable_ending_releases_the_slot_and_the_next_fragments_start_fresh() {
        let mut d = dispatcher::<1, 64>();
        assert_eq!(feed(&mut d, 10, 1, b"aa").0, IngestOutcome::Begun);
        assert_eq!(
            feed(&mut d, 12, 1, b"zz").0,
            IngestOutcome::Aborted(AbortReason::Unresolvable)
        );
        assert_eq!(d.active_chains(), 0);
        assert_eq!(
            d.staging_available(),
            1,
            "the arena has the chain's staging back"
        );
        assert_eq!(
            d.slots[0].engine.get_current_state(),
            ReassemblySlotState::Empty,
            "the slot FSM left the chain by a declared transition"
        );
        // The fragment after the ending begins a chain of its own, which the
        // `more` flag then closes: nothing of the broken chain is in it.
        assert_eq!(feed(&mut d, 13, 1, b"yy").0, IngestOutcome::Begun);
        let (outcome, delivered) = feed(&mut d, 14, 0, b"xx");
        assert_eq!(outcome, IngestOutcome::Reassembled);
        assert_eq!(delivered.as_deref(), Some(&b"yyxx"[..]));
    }

    /// The marker rules do not need the ring and are unchanged by not having it:
    /// armed, a headless tail is refused and a `First`-marked chain is followed to
    /// its close, on a ring the router does not know.
    #[test]
    fn the_marker_rules_hold_over_an_unknown_ring() {
        let first = FragmentMarkers {
            first: true,
            dropped: false,
        };
        let mut d: ReassemblyDispatcher<4, 64> = ReassemblyDispatcher::new(
            ReassemblyConfig::new(2, 5_000).with_fragmentation_markers(true),
        );
        let mut marked = |sn: u64, more: u8, payload: &'static [u8], markers: FragmentMarkers| {
            let mut delivered: Option<Vec<u8>> = None;
            let outcome = d.ingest_in_ring(
                Fragment {
                    markers,
                    ..frag(sn, more, payload)
                },
                SnRing::Unknown,
                0,
                |m| delivered = Some(m.to_vec()),
            );
            (outcome, delivered)
        };
        assert_eq!(
            marked(40, 1, b"tail", FragmentMarkers::NONE).0,
            IngestOutcome::Refused(RefuseReason::MissingStartMarker)
        );
        assert_eq!(marked(50, 1, b"he", first).0, IngestOutcome::Begun);
        assert_eq!(
            marked(51, 1, b"ll", FragmentMarkers::NONE).0,
            IngestOutcome::Continued
        );
        let (outcome, delivered) = marked(52, 0, b"o", FragmentMarkers::NONE);
        assert_eq!(outcome, IngestOutcome::Reassembled);
        assert_eq!(delivered.as_deref(), Some(&b"hello"[..]));
    }

    /// Chains on different keys do not disturb one another when the ring is
    /// unknown, and the step that ends one is judged on that chain's own last
    /// sequence number.
    #[test]
    fn chains_on_different_keys_are_judged_each_on_its_own_last_number() {
        let mut d = dispatcher::<4, 64>();
        let on = |priority: Priority, reliable: bool, sn: u64, more: u8| Fragment {
            reliable,
            priority,
            ..frag(sn, more, b"x")
        };
        let mut ingest = |f: Fragment<'static>| d.ingest_in_ring(f, SnRing::Unknown, 0, |_| {});
        // Two chains, interleaved, with unrelated numbering.
        assert_eq!(
            ingest(on(Priority::RealTime, true, 10, 1)),
            IngestOutcome::Begun
        );
        assert_eq!(
            ingest(on(Priority::Background, true, 900, 1)),
            IngestOutcome::Begun
        );
        assert_eq!(
            ingest(on(Priority::RealTime, true, 11, 1)),
            IngestOutcome::Continued
        );
        // The other key's number is not this chain's last: 12 follows 11 here
        // whatever the other chain is at.
        assert_eq!(
            ingest(on(Priority::Background, true, 901, 1)),
            IngestOutcome::Continued
        );
        assert_eq!(
            ingest(on(Priority::RealTime, true, 12, 0)),
            IngestOutcome::Reassembled
        );
        // The other chain, still open, is ended by its own gap.
        assert_eq!(
            ingest(on(Priority::Background, true, 903, 1)),
            IngestOutcome::Aborted(AbortReason::Unresolvable)
        );
    }

    /// The observer mirror carries the word under its own variant, apart from
    /// `OutOfOrder`.
    #[cfg(feature = "alloc")]
    #[test]
    fn the_unresolvable_ending_reaches_the_observer_mirror_under_its_own_word() {
        use crate::driver_loop::ReassemblyDropReason;
        assert_eq!(
            ReassemblyDropReason::from_ingest(IngestOutcome::Aborted(AbortReason::Unresolvable)),
            Some(ReassemblyDropReason::Unresolvable)
        );
        assert_ne!(
            ReassemblyDropReason::Unresolvable,
            ReassemblyDropReason::OutOfOrder
        );
    }
}

#[cfg(test)]
mod one_peer_tests {
    //! A Router of one peer's chains ([`OnePeer`]) beside the Router of several
    //! ([`ManyPeers`]): alike on one peer's fragments while the quota is within the slots,
    //! and keeping neither the peer nor the order its chains began in.
    use super::*;
    use crate::extfragment::FragmentMarkers;
    use std::{vec, vec::Vec};

    const PEER: &[u8] = &[0xAA; 16];
    const OTHER: &[u8] = &[0xBB; 16];

    /// The default-resolution (0x02, 28-bit) ring every test compares at.
    const MASK: crate::sn::Sn = crate::sn::mask_from_res(0x02);

    type One = ReassemblyDispatcher<2, 64, HeapStaging<2, 64>, OnePeer>;
    type Many = ReassemblyDispatcher<2, 64>;

    /// What a Router answered a fragment: the ingest's outcome, the message it delivered and the
    /// chain it ended besides.
    type Step = (IngestOutcome, Option<Vec<u8>>, Option<DisplacedChain>);

    fn frag<'a>(
        peer_key: &'a [u8],
        reliable: bool,
        priority: Priority,
        sn: u64,
        more: u8,
        payload: &'a [u8],
    ) -> Fragment<'a> {
        Fragment {
            peer_key,
            reliable,
            sn,
            more,
            payload,
            priority,
            markers: FragmentMarkers::NONE,
        }
    }

    /// `quota` chains a peer, and the policy that ends the oldest chain when the pool is full.
    fn config(quota: u16) -> ReassemblyConfig {
        ReassemblyConfig::new(quota, 5_000).with_pool_overflow(PoolOverflow::OldestWins)
    }

    /// One peer's fragments through every rule a start and a continuation meet (a start, a
    /// second channel, a start past the quota, a completion, a start after it, a gap, a start
    /// after the gap), then a channel's abort and the sweep: each step's answer, whether the
    /// abort ended a chain and how many chains the sweep ended.
    fn one_peers_traffic<P: ChainPeers>(
        d: &mut ReassemblyDispatcher<2, 64, HeapStaging<2, 64>, P>,
    ) -> (Vec<Step>, bool, usize) {
        let fragments = [
            frag(PEER, true, Priority::DEFAULT, 1, 1, b"a"),
            frag(PEER, false, Priority::DEFAULT, 1, 1, b"b"),
            frag(PEER, true, Priority::RealTime, 1, 1, b"c"),
            frag(PEER, true, Priority::DEFAULT, 2, 0, b"A"),
            frag(PEER, true, Priority::RealTime, 5, 1, b"c"),
            frag(PEER, false, Priority::DEFAULT, 3, 1, b"x"),
            frag(PEER, false, Priority::DEFAULT, 7, 1, b"y"),
        ];
        let mut steps = Vec::new();
        for fragment in fragments {
            let mut delivered = None;
            let outcome = d.ingest(fragment, MASK, 0, |message| {
                delivered = Some(message.to_vec())
            });
            steps.push((outcome, delivered, d.displaced_by_last_ingest()));
        }
        let aborted = d.abort_channel(PEER, Priority::RealTime, true);
        let swept = d.sweep(10_000);
        (steps, aborted, swept)
    }

    /// With the quota at the slots, as a single-link session sets it, one peer's fragments are
    /// answered step for step as the Router of several peers answers them: the full pool is the
    /// peer at its quota, refused as such before any policy is read. Below the slots too.
    #[test]
    fn one_peers_fragments_are_answered_as_the_router_of_several_answers_them() {
        let expected: Vec<Step> = vec![
            (IngestOutcome::Begun, None, None),
            (IngestOutcome::Begun, None, None),
            (IngestOutcome::Refused(RefuseReason::PeerQuota), None, None),
            (IngestOutcome::Reassembled, Some(b"aA".to_vec()), None),
            (IngestOutcome::Begun, None, None),
            (IngestOutcome::Aborted(AbortReason::OutOfOrder), None, None),
            (IngestOutcome::Begun, None, None),
        ];
        assert_eq!(
            one_peers_traffic(&mut Many::new(config(2))),
            (expected.clone(), true, 1),
            "CONTROL: the Router of several peers"
        );
        assert_eq!(
            one_peers_traffic(&mut One::new(config(2))),
            (expected, true, 1)
        );
        for quota in [1, 2] {
            assert_eq!(
                one_peers_traffic(&mut One::new(config(quota))),
                one_peers_traffic(&mut Many::new(config(quota))),
                "quota {quota}"
            );
        }
    }

    /// A fragment continues the chain open on its channel whatever peer key it carries: the key
    /// keeps no peer. The CONTROL is the Router of several peers, where another peer's fragment
    /// begins a chain of its own.
    #[test]
    fn a_router_of_one_peer_keys_a_chain_by_its_channel_alone() {
        let first = frag(PEER, true, Priority::DEFAULT, 1, 1, b"a");
        let other = frag(OTHER, true, Priority::DEFAULT, 2, 1, b"b");
        let mut one = One::new(config(2));
        assert_eq!(one.ingest(first, MASK, 0, |_| {}), IngestOutcome::Begun);
        assert_eq!(one.ingest(other, MASK, 0, |_| {}), IngestOutcome::Continued);
        assert_eq!(one.active_chains(), 1);
        let mut many = Many::new(config(2));
        assert_eq!(many.ingest(first, MASK, 0, |_| {}), IngestOutcome::Begun);
        assert_eq!(
            many.ingest(other, MASK, 0, |_| {}),
            IngestOutcome::Begun,
            "CONTROL"
        );
        assert_eq!(many.active_chains(), 2, "CONTROL");
    }

    /// A quota above the slots leaves a pool of one peer's chains full, and the Router of one
    /// peer refuses the start there as a full pool, with the open chains kept and none displaced,
    /// whatever the policy says. The CONTROL is the Router of several peers, whose `OldestWins`
    /// ends the peer's oldest chain for the start.
    #[test]
    fn a_router_of_one_peer_makes_no_room_in_a_full_pool() {
        let starts = [
            frag(PEER, true, Priority::DEFAULT, 1, 1, b"a"),
            frag(PEER, false, Priority::DEFAULT, 1, 1, b"b"),
        ];
        let third = frag(PEER, true, Priority::RealTime, 1, 1, b"c");
        let mut one = One::new(config(8));
        let mut many = Many::new(config(8));
        for fragment in starts {
            assert_eq!(one.ingest(fragment, MASK, 0, |_| {}), IngestOutcome::Begun);
            assert_eq!(many.ingest(fragment, MASK, 0, |_| {}), IngestOutcome::Begun);
        }
        assert_eq!(
            one.ingest(third, MASK, 0, |_| {}),
            IngestOutcome::Refused(RefuseReason::PoolExhausted)
        );
        assert_eq!(one.displaced_by_last_ingest(), None);
        assert_eq!(one.active_chains(), 2);
        assert_eq!(
            many.ingest(third, MASK, 0, |_| {}),
            IngestOutcome::Begun,
            "CONTROL"
        );
        assert_eq!(
            many.displaced_by_last_ingest(),
            Some(DisplacedChain::Evicted),
            "CONTROL"
        );
    }

    /// Every open chain is the one peer's, so ending a peer's chains ends them all, whatever key
    /// names it, and gives their staging back.
    #[test]
    fn a_router_of_one_peer_ends_every_chain_for_its_peer() {
        let mut one = One::new(config(2));
        assert_eq!(
            one.ingest(
                frag(PEER, true, Priority::DEFAULT, 1, 1, b"a"),
                MASK,
                0,
                |_| {}
            ),
            IngestOutcome::Begun
        );
        assert_eq!(
            one.ingest(
                frag(PEER, false, Priority::DEFAULT, 1, 1, b"b"),
                MASK,
                0,
                |_| {}
            ),
            IngestOutcome::Begun
        );
        assert_eq!(one.abort_peer(OTHER), 2);
        assert_eq!(one.active_chains(), 0);
        assert_eq!(one.staging_available(), 2);
    }

    /// The Router of one peer keeps nothing of the peer in a chain's key and nothing of the order
    /// its chains began in, so its key is smaller by the peer key and the Router by both.
    #[test]
    fn a_router_of_one_peer_keeps_neither_a_peer_nor_an_order() {
        use core::mem::size_of;
        assert_eq!(size_of::<<OnePeer as ChainPeers>::Peer>(), 0);
        assert_eq!(size_of::<<OnePeer as ChainPeers>::Opened>(), 0);
        assert!(size_of::<ChainKey<OnePeer>>() + PEER_KEY_MAX <= size_of::<ChainKey<ManyPeers>>());
        assert!(size_of::<One>() < size_of::<Many>());
    }
}
