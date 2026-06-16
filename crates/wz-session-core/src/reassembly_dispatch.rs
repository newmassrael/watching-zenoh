// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311im — the reassembly Router (dispatcher) that drives N
//! engine-free slot FSMs (`reassembly-fsm--prose-sketch` §2.3).
//!
//! [`wz_session_core::reassembly_slot`](crate::reassembly_slot) is ONE
//! slot's protocol FSM (Empty -> Receiving -> Complete / Aborted /
//! TimedOut), codegen'd engine-free from
//! `sources/network/reassembly_slot.scxml`. This module is the Rust
//! *Router* the scxml header describes: it holds the N slot
//! [`Engine`](sce_rust_runtime::Engine) instances and owns everything the
//! engine-free FSM cannot — the stateful SN-consecutiveness arithmetic,
//! the per-peer quota, the staging buffers, and the deadline clock.
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
//! - **The wire `more` bit — the FSM.** `more` is a real per-fragment
//!   field (`fragment_chunk_schema.scxml`), so the slot FSM guards
//!   Continue (`more != 0`, stay Receiving) vs Final (`more == 0`,
//!   -> Complete) natively.
//! - **Staging — the Router.** `fragment_chunk_schema.scxml` documents
//!   "the dispatcher stages the payload here": the Router owns each slot's
//!   bounded staging buffer ([`BoundedVec`]). This is forced by two
//!   constraints and is the spec-intended split, not a shortcut: (a) the
//!   MCU reassembly profile is `--no-default-features --features
//!   reassembly,no_std` — NO `alloc`, so the scouting glue's
//!   `Arc<...>`-shared-state read-back pattern is unavailable; and (b) the
//!   generated `ReassemblySlotPolicy`'s `actions` field is private, so the
//!   binding's state is unreadable through the `Engine` regardless. The
//!   slot FSM therefore owns state + transitions + the `more` guard (the
//!   engine-free protocol logic, SSOT with the scxml); the Router owns the
//!   data plane. The generated [`ReassemblySlotActions`] are bound to a
//!   thin counter [`SlotBinding`] for test observability.
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

use crate::bounded::BoundedVec;
use crate::reassembly_slot::{
    ReassemblySlotActions, ReassemblySlotEvent, ReassemblySlotFragmentChunkPayload,
    ReassemblySlotInject, ReassemblySlotPolicy, ReassemblySlotState,
};
use sce_rust_runtime::Engine;
// R311mh — `sweep_reporting` (below) raises an IterationEvent on a timed-out
// chain; the event surface needs `alloc` (the driver_loop module), so the
// reporting wrapper is alloc-gated within this reassembly-gated module.
#[cfg(feature = "alloc")]
use crate::driver_loop::IterationEvent;

/// Maximum peer-key byte length: sized to the widest key a transport
/// feeds the chain key — the unicast peer ZID (a zenoh ZID is up to 16
/// bytes; the wire form is length-prefixed); the multicast pool-slot key
/// ([`crate::multicast_dispatch::multicast_chain_key`]) is 4 bytes. The
/// chain key copies the peer key into a fixed buffer so the Router holds
/// no allocation per chain.
const PEER_KEY_MAX: usize = 16;

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
}

impl ReassemblyConfig {
    /// Construct an explicit config. See the field docs for the
    /// no-`Default` rationale.
    pub const fn new(per_peer_quota: u16, reassembly_timeout_ms: u64) -> Self {
        Self {
            per_peer_quota,
            reassembly_timeout_ms,
        }
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
    CapacityOverflow,
}

/// Why the Router refused a chain-starting fragment before allocating a
/// slot (the fragment is dropped; no slot FSM is involved).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefuseReason {
    /// The peer already holds `per_peer_quota` open chains (§5.M
    /// quota-first; the pool-exhaustion defence).
    PeerQuota,
    /// Every slot is occupied by another peer's in-progress chain.
    PoolExhausted,
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

/// A decoded inbound transport Fragment (`T_MID_FRAGMENT`, MID `0x06`)
/// ready for the Router. Groups the per-fragment inputs so
/// [`ReassemblyDispatcher::ingest`] takes one descriptor rather than a
/// long positional argument list.
#[derive(Debug, Clone, Copy)]
pub struct Fragment<'a> {
    /// Peer identity key from the link/session context (NOT the fragment
    /// body) — half of the §2.3 chain key. Unicast feeds the peer ZID;
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
}

/// Thin host binding for the generated [`ReassemblySlotActions`]. The
/// Router owns the staging buffer and emits the reassembled message
/// itself (see the module "Division of labour" note), so these actions
/// carry no data state — they only count dispatches for test
/// observability and keep the engine-free FSM's `<sce:action>` contract
/// satisfied at compile time.
#[derive(Debug, Default, Clone, Copy)]
struct SlotBinding {
    begins: u32,
    appends: u32,
    finalizes: u32,
    aborts: u32,
    timeouts: u32,
    resets: u32,
}

impl ReassemblySlotActions for SlotBinding {
    fn begin_chain(&mut self) {
        self.begins = self.begins.saturating_add(1);
    }
    fn append_fragment_payload(&mut self) {
        self.appends = self.appends.saturating_add(1);
    }
    fn finalize_message(&mut self) {
        self.finalizes = self.finalizes.saturating_add(1);
    }
    fn abort_ooo(&mut self) {
        self.aborts = self.aborts.saturating_add(1);
    }
    fn abort_peer_drop(&mut self) {
        self.aborts = self.aborts.saturating_add(1);
    }
    fn abort_evicted(&mut self) {
        self.aborts = self.aborts.saturating_add(1);
    }
    fn abort_codec(&mut self) {
        self.aborts = self.aborts.saturating_add(1);
    }
    fn record_timeout(&mut self) {
        self.timeouts = self.timeouts.saturating_add(1);
    }
    fn reset_slot(&mut self) {
        self.resets = self.resets.saturating_add(1);
    }
}

/// The chain key: a fragment chain is identified by (peer key, reliable
/// channel) per §2.3. Two distinct reliability channels from the same peer
/// are independent chains (the R bit is part of the §5.M chain key
/// alongside the peer key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChainKey {
    peer_key: [u8; PEER_KEY_MAX],
    peer_key_len: u8,
    reliable: bool,
}

impl ChainKey {
    fn new(peer_key: &[u8], reliable: bool) -> Self {
        let mut buf = [0u8; PEER_KEY_MAX];
        let n = core::cmp::min(peer_key.len(), PEER_KEY_MAX);
        buf[..n].copy_from_slice(&peer_key[..n]);
        Self {
            peer_key: buf,
            peer_key_len: n as u8,
            reliable,
        }
    }

    fn same_peer(&self, peer_key: &[u8]) -> bool {
        let n = core::cmp::min(peer_key.len(), PEER_KEY_MAX);
        self.peer_key_len as usize == n && self.peer_key[..n] == peer_key[..n]
    }
}

/// One reassembly slot: the engine-free protocol FSM plus the Router-owned
/// chain state (key / expected next SN / deadline / staging buffer).
struct Slot<const CAP: usize> {
    engine: Engine<ReassemblySlotPolicy<SlotBinding>>,
    /// `Some` while the slot holds an in-progress chain (FSM == Receiving);
    /// `None` when free (FSM == Empty).
    key: Option<ChainKey>,
    /// The last in-order SN staged into this chain. A continuation is
    /// admitted iff it is ring-consecutive to this ([`crate::sn::consecutive`]
    /// at the caller-passed mask) — the zenoh-pico `_sn_rx_*` tracker shape
    /// (rx.c stores the accepted `msg->_sn` and compares
    /// `_z_sn_consecutive` against it), replacing the R311ka F-5 unmasked
    /// `next_sn` `==` that diverged at the ring seam.
    last_sn: u64,
    /// Absolute monotonic-ms instant this chain times out (valid iff
    /// `key.is_some()`).
    deadline_ms: u64,
    /// Router-owned staging buffer: the reassembled message accumulates
    /// here across the chain's fragments.
    buf: BoundedVec<u8, CAP>,
}

impl<const CAP: usize> Slot<CAP> {
    fn new() -> Self {
        let mut engine = Engine::new(ReassemblySlotPolicy::new(SlotBinding::default()));
        // W3C SCXML 3.3: enter the initial `Empty` leaf.
        engine.initialize();
        Self {
            engine,
            key: None,
            last_sn: 0,
            deadline_ms: 0,
            buf: BoundedVec::new(),
        }
    }

    fn is_free(&self) -> bool {
        self.key.is_none()
    }

    /// Drive the slot's terminal-state `slot.release` transition back to
    /// Empty and clear the Router-side chain state for reuse.
    fn release(&mut self) {
        // Only the terminal states (Complete / Aborted / TimedOut) have a
        // `slot.release` transition; the caller only releases from there.
        self.engine.process_event(ReassemblySlotEvent::SlotRelease);
        self.key = None;
        self.last_sn = 0;
        self.deadline_ms = 0;
        self.buf.clear();
    }
}

/// The reassembly Router: a fixed pool of `SLOTS` slot FSMs, each able to
/// reassemble a fragment chain of up to `CAP` bytes. See the module docs
/// for the division of labour with the engine-free slot FSM.
pub struct ReassemblyDispatcher<const SLOTS: usize, const CAP: usize> {
    slots: [Slot<CAP>; SLOTS],
    config: ReassemblyConfig,
}

impl<const SLOTS: usize, const CAP: usize> ReassemblyDispatcher<SLOTS, CAP> {
    /// Build a Router with `SLOTS` empty slots over `config`.
    pub fn new(config: ReassemblyConfig) -> Self {
        Self {
            slots: core::array::from_fn(|_| Slot::new()),
            config,
        }
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
    pub fn ingest<F: FnOnce(&[u8])>(
        &mut self,
        frag: Fragment<'_>,
        sn_mask: u64,
        now_ms: u64,
        deliver: F,
    ) -> IngestOutcome {
        match self.find_active(frag.peer_key, frag.reliable) {
            Some(idx) => self.ingest_continuation(idx, frag, sn_mask, deliver),
            None => self.ingest_chain_start(frag, now_ms, deliver),
        }
    }

    /// Abort and reclaim every chain whose deadline has elapsed at
    /// `now_ms`, raising `reassembly.timeout` into only the live slots
    /// (a reused slot's stale deadline cannot fire — released slots are
    /// `is_free`). Returns the number of chains timed out.
    pub fn sweep(&mut self, now_ms: u64) -> usize {
        let mut timed_out = 0;
        for slot in self.slots.iter_mut() {
            if slot.is_free() || now_ms < slot.deadline_ms {
                continue;
            }
            slot.engine
                .process_event(ReassemblySlotEvent::ReassemblyTimeout);
            slot.release();
            timed_out += 1;
        }
        timed_out
    }

    fn find_active(&self, peer_key: &[u8], reliable: bool) -> Option<usize> {
        self.slots.iter().position(|s| match &s.key {
            Some(k) => k.reliable == reliable && k.same_peer(peer_key),
            None => false,
        })
    }

    fn peer_chain_count(&self, peer_key: &[u8]) -> u16 {
        self.slots
            .iter()
            .filter(|s| match &s.key {
                Some(k) => k.same_peer(peer_key),
                None => false,
            })
            .count() as u16
    }

    fn ingest_chain_start<F: FnOnce(&[u8])>(
        &mut self,
        frag: Fragment<'_>,
        now_ms: u64,
        deliver: F,
    ) -> IngestOutcome {
        // §5.M quota-first: the per-peer cap is checked before slot
        // availability, so a flood from one peer is refused on quota even
        // while free slots remain for honest peers.
        if self.peer_chain_count(frag.peer_key) >= self.config.per_peer_quota {
            return IngestOutcome::Refused(RefuseReason::PeerQuota);
        }
        let idx = match self.slots.iter().position(Slot::is_free) {
            Some(i) => i,
            None => return IngestOutcome::Refused(RefuseReason::PoolExhausted),
        };

        // Arm the chain before driving the FSM so a staging overflow on the
        // very first fragment releases cleanly.
        self.slots[idx].key = Some(ChainKey::new(frag.peer_key, frag.reliable));
        self.slots[idx].last_sn = frag.sn;
        self.slots[idx].deadline_ms = now_ms.saturating_add(self.config.reassembly_timeout_ms);
        self.slots[idx].buf.clear();

        if stage(&mut self.slots[idx].buf, frag.payload).is_err() {
            return self.abort(idx, AbortReason::CapacityOverflow);
        }

        // Empty --fragment.chunk--> { Receiving | Complete }, the slot FSM's
        // `more` guard deciding. A well-formed chain's first fragment has
        // M=1 (a single-fragment message rides T_MID_FRAME, not
        // T_MID_FRAGMENT) and lands in Receiving -> Begun. A lone M=0 first
        // fragment — stranded when a duplicate mid-chain fragment trips the
        // channel SN gate ([`Self::abort_channel`] clears the chain) and the
        // trailing final fragment then arrives as a fresh start — completes
        // in ONE step: deliver it immediately and reclaim the slot
        // (zenoh-pico rx.c `if (!more) decode` parity). Completing it rather
        // than parking a stuck Receiving orphan is what stops the next
        // in-order message from being appended onto the orphan's tail and
        // delivered as one merged blob (R311oo dup-fragment merge bug). The
        // delivered lone tail is a chain remnant, not a whole frame, so the
        // upstream frame decode drops it — exactly pico's outcome.
        self.slots[idx]
            .engine
            .raise_fragment_chunk(chunk_event(frag.more));
        self.slots[idx].engine.step();

        match self.slots[idx].engine.get_current_state() {
            ReassemblySlotState::Complete => {
                deliver(&self.slots[idx].buf);
                self.slots[idx].release();
                IngestOutcome::Reassembled
            }
            _ => IngestOutcome::Begun,
        }
    }

    fn ingest_continuation<F: FnOnce(&[u8])>(
        &mut self,
        idx: usize,
        frag: Fragment<'_>,
        sn_mask: u64,
        deliver: F,
    ) -> IngestOutcome {
        // Strict in-order (§2.5): a non-consecutive continuation (a
        // duplicate, a gap, or a backward step — all ring distances != 1)
        // aborts the chain via `fragment.ooo`. Ring compare, not `==` on
        // `+1`: a sender minting on the ring wraps `mask -> 0`, where the
        // unmasked form falsely aborted (R311ka F-5).
        if !crate::sn::consecutive(sn_mask, self.slots[idx].last_sn, frag.sn) {
            self.slots[idx]
                .engine
                .process_event(ReassemblySlotEvent::FragmentOoo);
            return self.abort(idx, AbortReason::OutOfOrder);
        }

        if stage(&mut self.slots[idx].buf, frag.payload).is_err() {
            self.slots[idx]
                .engine
                .process_event(ReassemblySlotEvent::CodecError);
            return self.abort(idx, AbortReason::CapacityOverflow);
        }

        self.slots[idx].last_sn = frag.sn;
        self.slots[idx]
            .engine
            .raise_fragment_chunk(chunk_event(frag.more));
        self.slots[idx].engine.step();

        // The slot FSM's `more` guard decided Continue vs Final.
        match self.slots[idx].engine.get_current_state() {
            ReassemblySlotState::Complete => {
                deliver(&self.slots[idx].buf);
                self.slots[idx].release();
                IngestOutcome::Reassembled
            }
            _ => IngestOutcome::Continued,
        }
    }

    /// The slot FSM has already been driven into `Aborted` by the caller's
    /// abort event; record the reason and reclaim the slot.
    fn abort(&mut self, idx: usize, reason: AbortReason) -> IngestOutcome {
        self.slots[idx].release();
        IngestOutcome::Aborted(reason)
    }

    /// R311ke — abort the in-progress chain on (`peer_key`, `reliable`),
    /// the zenoh-pico dbuf-clear a channel-level SN-gate rejection triggers
    /// (unicast/rx.c:112-113: an out-of-order FRAME on a channel clears
    /// that channel's defragmentation buffer — the dropped frame may have
    /// superseded the chain's continuation, so completing it would mix
    /// generations). Drives the slot FSM through its `fragment.ooo`
    /// abort arm before release, exactly as an in-chain abort does.
    /// Returns whether a chain was cleared (`false` = nothing in
    /// progress on that channel — the common case).
    pub fn abort_channel(&mut self, peer_key: &[u8], reliable: bool) -> bool {
        match self.find_active(peer_key, reliable) {
            Some(idx) => {
                self.slots[idx]
                    .engine
                    .process_event(ReassemblySlotEvent::FragmentOoo);
                self.abort(idx, AbortReason::OutOfOrder);
                true
            }
            None => false,
        }
    }
}

/// Build the typed `fragment.chunk` event. The slot FSM's only guard
/// reads `more`, and the body never flows through the FSM (the Router
/// stages it in the slot's `BoundedVec`), so the event carries just the
/// wire M bit. R311in removed the schema's former `payload: bytes
/// max-size 1472` field — it inlined a 1472-byte buffer into every queued
/// event (x the per-slot queue depth x N slots) and was the no_std
/// MCU-footprint blocker; the body was never read through the FSM.
fn chunk_event(more: u8) -> ReassemblySlotFragmentChunkPayload {
    ReassemblySlotFragmentChunkPayload { more }
}

/// Append `payload` to the slot staging buffer, returning `Err` if the
/// chain would exceed the slot `CAP` (the §7.1 capacity hard error).
///
/// The capacity check is EXPLICIT (`len + payload > CAP`) rather than
/// relying on [`BoundedVec::push`] failing: on the `alloc` (AP) backing
/// `push` never fails (`CAP` is advisory there), so without this check the
/// AP reassembly buffer would grow unbounded past `slot_size` and defeat
/// the §5.M malicious-peer pool-exhaustion defence. The explicit bound
/// makes reassembly genuinely capacity-bounded on BOTH profiles.
fn stage<const CAP: usize>(buf: &mut BoundedVec<u8, CAP>, payload: &[u8]) -> Result<(), ()> {
    if buf.len().saturating_add(payload.len()) > CAP {
        return Err(());
    }
    for &b in payload {
        buf.push(b).map_err(|_| ())?;
    }
    Ok(())
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
/// Generic over the pool dims so the AP (32 / 65536) and MCU (4 / 4096)
/// profiles share one path. R311mh relocated it here from `crate::drive`: it
/// is a pure reassembly helper (no unicast actions / runtime generic), so it
/// belongs next to [`ReassemblyDispatcher`], not in the session-unicast-gated
/// drive module — that is what let the multicast sweep SSOT
/// ([`crate::multicast_rx::sweep_multicast_reassembling`]) reuse it without a
/// false `session-unicast` coupling.
#[cfg(feature = "alloc")]
pub fn sweep_reporting<const SLOTS: usize, const CAP: usize, F>(
    reasm: &mut ReassemblyDispatcher<SLOTS, CAP>,
    now_ms: u64,
    on_event: &mut F,
) where
    F: FnMut(IterationEvent<'_>),
{
    let timed_out = reasm.sweep(now_ms);
    if timed_out > 0 {
        on_event(IterationEvent::ReassemblyTimeout(timed_out));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    const PEER_A: &[u8] = &[0xAA; 16];
    const PEER_B: &[u8] = &[0xBB; 16];

    /// The default-resolution (0x02, 28-bit) ring every test compares at.
    const MASK: u64 = crate::sn::mask_from_res(0x02);

    fn dispatcher<const S: usize, const C: usize>() -> ReassemblyDispatcher<S, C> {
        ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000))
    }

    /// Terse [`Fragment`] constructor for the test calls.
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
            d.abort_channel(PEER_A, true),
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
}
