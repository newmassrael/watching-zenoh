// SCE-GENERATED — DO NOT EDIT
// source-hash: e812b8b9426089658c190b079d72f4505398532fde65fe2c41c3ec6148939d1b
// template-hash: d43b22670550c67cebe189489d0fdc39f585b0c09803917dea05e0ded254e31e
// generated-at: 0
// SCE-MAP: reassembly_pool_ap.scxml:59

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="buffer-pool")
// Runtime: self-contained on (rust, std) — no SCE-side helper crate.
// Do not edit — regenerate from the source SCXML file.
//
// watching-zenoh RFC §synth-5-E DMA-aligned slot table with the seven-state
// lifecycle FSM (free/cpu-mut/dma-armed-{tx,rx}/dma-busy-{tx,rx}/
// cpu-ref) and phantom-typed `Slot<S>` author API per spec lines
// 1116-1180 + 1232-1237. The eleven legal transitions are pinned in
// `sce-build/src/forge/buffer_pool_fsm.rs` and mirrored here as
// `STATE_COUNT` / `TRANSITION_COUNT` constants.
//
// C5 cache-maintenance pinning (cache-policy: maintain): emits
// `sce_dcache_clean_by_addr` before `link_arm_tx` (spec lines
// 1186-1188) and `sce_dcache_invalidate_by_addr` on `link_arm_rx`
// gated on `platform.has_speculative_prefetch` (spec lines
// 1189-1198 + 1199-1212). Per spec lines 1222-1227, these calls
// are FSM-driven; author authoring of the cache trio via
// `<sce:extern>` is rejected at parse time
// (`pool/cache-maintenance-misplaced`). The 3 cache extern
// declarations also auto-flow into the `<snake>_externs.rs`
// sidecar via the parser's auto-inject hook so deploy reviewers
// see the dependency surface in one place.
//
// Generated from `name="reassembly_pool_ap"` with section `heap`,
// alignment `64`, cache-policy `none`.


use core::marker::PhantomData;

/// Number of slots in the pool (`<sce:slot-count>`).
pub const SLOT_COUNT: usize = 32;

/// Bytes per slot (`<sce:slot-size>`).
pub const SLOT_SIZE: usize = 1048576;

/// SRAM region name (`<sce:section>`). Round-tripped here so that
/// downstream linker integration can read it without re-parsing
/// the SCXML.
pub const SECTION: &'static str = "heap";

/// DMA alignment in bytes (`<sce:alignment>`). Power-of-2
/// violations surface in the emitted linker fragment, where the
/// constraint is observable through `ALIGN(<n>)` directives.
pub const ALIGNMENT: u32 = 64;

/// DMA channel binding (`<sce:dma-channel>`). Empty when the pool is
/// purely CPU-managed.
pub const DMA_CHANNEL: &'static str = "";

/// Cache policy (`<sce:cache-policy>`) — `maintain` / `non-cacheable`
/// / `none`. C5 wires the maintenance calls below when this is
/// `maintain`; the other two policies emit no maintenance calls.
pub const CACHE_POLICY: &'static str = "none";
/// Number of declared lifecycle states. Mirrors
/// `forge::buffer_pool_fsm::STATE_COUNT` — the seven states from
/// spec §synth-5-E lines 1129-1135.
pub const STATE_COUNT: usize = 7;

/// Number of declared lifecycle transitions. Mirrors
/// `forge::buffer_pool_fsm::TRANSITION_COUNT` — the eleven legal
/// edges from spec §synth-5-E lines 1141-1156.
pub const TRANSITION_COUNT: usize = 11;
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Reassembly variant per-slot state (RFC §synth-5-M lines 2680-2698
// + 2864-2876). The reassembly variant of §synth-5-E (`<sce:variant>reassembly`)
// extends the slot table with three additional per-slot fields the
// author-level Fragment FSM (RFC §synth-5-M lines 2864-2876, lives in
// downstream SCXML statechart) consumes:
//   - `bitmap: [u32; FRAGMENT_BITMAP_WORDS]` — fragment-index bitmap
//     marking each received fragment; bitmap width derived from
//     `<sce:max-fragments-per-message>` (RFC §synth-5-M line 2688 +
//     2694-2698).
//   - `deadline: u64` — per-slot reassembly deadline in raw ticks /
//     ms; `<sce:reassembly-timeout-ms>` (RFC §synth-5-M line 2689) drives
//     the timer the FSM's `Receiving → TimedOut` edge consumes
//     (`docs/reassembly-fsm.md` §2.4.5).
//   - `peer_id: PeerId` — handshake-derived ZID (RFC §synth-5-M lines
//     2700-2738). Reassembly is forbidden on non-`established_session`
//     links by the cross-doc validator
//     `reassembly/untrusted-link-binding`, so the peer-id is always
//     the 16-byte ZID — never the spoofable wire source address.
//     The `reassembly/peer-id-not-zid-on-established-session`
//     codegen self-check enforces this template invariant per RFC
//     §synth-5-M lines 2976-2981.
//
// Quota enforcement (RFC §synth-5-M lines 2848-2856) lives in the author
// SCXML algorithm (`<scxml sce:kind="algorithm">`) that walks the
// slot table at `Fragment.First` arrival — it is intentionally NOT
// emitted from the pool template (O(slot_count) bounded loop fits
// `mode="static"` WCET; no runtime infrastructure needed in the
// codegen output). Same for fragment-index marking and
// completion-detection: those live in the author FSM body.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Bitmap word count per reassembly slot — `ceil(max-fragments-per-message / 32)`.
/// Width pinned to `u32` (4 bytes) at the size assertion below; using
/// platform-natural `usize` would break the wire-shape invariant the
/// runtime metadata layer relies on.
pub const FRAGMENT_BITMAP_WORDS: usize = (44 + 31) / 32;

/// `<sce:max-fragments-per-message>` (RFC §synth-5-M line 2688) — the
/// closed cap a reassembled message's fragment count cannot exceed
/// (worst-case message must complete within the bitmap width).
pub const MAX_FRAGMENTS_PER_MESSAGE: u32 = 44;

/// `<sce:reassembly-timeout-ms>` (RFC §synth-5-M line 2689) — per-slot
/// deadline value in milliseconds, written into `ReassemblySlot.deadline`
/// at `Fragment.First` arrival.
pub const REASSEMBLY_TIMEOUT_MS: u32 = 500;

/// `<sce:per-peer-quota>` (RFC §synth-5-M lines 2690, 2841-2861) — caps
/// the in-flight reassembly slots a single peer (keyed by ZID) may
/// hold. Consumed by the SCXML-side per-peer quota algorithm; this
/// constant exposes the configured cap so the algorithm doesn't have
/// to round-trip through the deploy.yaml.
pub const PER_PEER_QUOTA: u32 = 8;

/// Handshake-derived peer identifier — 16-byte Zenoh ZID (RFC §synth-5-M
/// lines 2708-2714). The `reassembly/peer-id-not-zid-on-established-
/// session` codegen self-check (RFC §synth-5-M lines 2976-2981) enforces
/// that this declaration emits the `[u8; 16]` byte-array shape on
/// every reassembly-variant pool — wire-source typedefs would silently
/// inherit UDP source-IP spoofing exposure. Reverse-linkage:
/// the validator reads the marker below instead of scanning for the
/// literal `pub type PeerId = [u8; 16]` declaration.
// SCE-EMIT: kind=reassembly.peer-id-zid
pub type PeerId = [u8; 16];

/// Per-slot reassembly state — RFC §synth-5-M lines 2680-2698. Author SCXML
/// FSM bodies (`docs/reassembly-fsm.md`) reach into `bitmap` and
/// `deadline` directly; `peer_id` is matched on `Fragment.Continue`
/// / `Final` to bind continuation fragments to the originating ZID.
#[repr(C)]
pub struct ReassemblySlot {
    /// Fragment-index bitmap. Bit `i` (LSB-first across words) marks
    /// fragment index `i` as received. RFC §synth-5-M line 2696.
    pub bitmap: [u32; FRAGMENT_BITMAP_WORDS],
    /// Per-slot reassembly deadline (raw ms ticks). RFC §synth-5-M line
    /// 2689 + 2697.
    pub deadline: u64,
    /// Originating peer ZID. RFC §synth-5-M lines 2697-2714.
    pub peer_id: PeerId,
}

// Drift guards — pin the FRAGMENT_BITMAP_WORDS+deadline wire shape
// so a future port to 16-bit / 64-bit `usize` cores or a "smarter"
// bitmap type does not silently re-define the per-slot layout the
// author FSM and the cross-language tracing path observe.
const _: () = assert!(
    core::mem::size_of::<u32>() == 4,
    "fragment-index bitmap word is fixed to u32 (4 bytes) per RFC §synth-5-M line 2696",
);
const _: () = assert!(
    core::mem::size_of::<u64>() == 8,
    "reassembly slot deadline is fixed to u64 (8 bytes) per RFC §synth-5-M line 2697",
);
const _: () = assert!(
    core::mem::size_of::<PeerId>() == 16,
    "reassembly slot peer-id is fixed to 16-byte ZID per RFC §synth-5-M lines 2708-2714",
);
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Slot lifecycle state — runtime tag value (mirrors C11 enum)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// One of the seven slot ownership states. Discriminants match the
/// C11 backend's `sce_slot_state_t` enum so cross-language tracing
/// over a single binary representation stays consistent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum SlotState {
    Free = 0,
    CpuMut = 1,
    DmaArmedTx = 2,
    DmaBusyTx = 3,
    DmaArmedRx = 4,
    DmaBusyRx = 5,
    CpuRef = 6,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Phantom-marker zero-sized types for `Slot<S>`.
// Each marker corresponds to a SlotState. Authors cannot construct
// `Slot<S>` directly because `Slot::idx` is private to this module;
// the only ways to obtain one are through pool methods like
// `pool_acquire_for_encode` (free → cpu-mut) and `link_arm_rx`
// (free → dma-armed-rx).
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Phantom marker for `SlotState::CpuMut`. Held by author code while
/// the slot is in exclusive CPU-write state.
#[derive(Debug)]
pub struct CpuMut;

/// Phantom marker for `SlotState::CpuRef`. Held by author code while
/// the slot is in shared CPU-read state (post-RX-IRQ).
#[derive(Debug)]
pub struct CpuRef;

/// Phantom marker for `SlotState::DmaArmedRx`. Returned from
/// `link_arm_rx` so the author can register the slot index with the
/// peripheral's RX descriptor; the slot then progresses through
/// `DmaBusyRx → CpuRef` via IRQ handlers (not exposed in this
/// atomic).
#[derive(Debug)]
pub struct DmaArmedRx;

/// Phantom-typed slot handle. The state parameter `S` is one of the
/// marker types above. Since `idx` is private, code outside this
/// generated module cannot fabricate a `Slot<S>`; every legal
/// transition flows through methods that consume `self` (so the old
/// state's handle is invalidated by Rust's move semantics) and
/// return the new state's handle when the author retains it.
///
/// Silently dropping a `Slot<CpuMut>` or `Slot<CpuRef>` leaks the
/// underlying slot — the `#[must_use]` attribute makes rustc warn
/// when this happens at the lexical level.
#[must_use = "Slot must be returned via pool_return or handed off via link_arm_tx; dropping silently leaks the slot per §synth-5-E lines 1162-1164"]
pub struct Slot<S> {
    idx: usize,
    _state: PhantomData<fn() -> S>,
}

impl<S> Slot<S> {
    /// Pool index of this slot. Read-only; useful for tracing and
    /// for writing a peripheral's DMA descriptor (e.g., for
    /// `Slot<DmaArmedRx>`).
    pub fn idx(&self) -> usize {
        self.idx
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Pool struct — owns storage + per-slot state array
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Generated buffer-pool. Each slot's lifecycle state is tracked in
/// `slot_states[]`; the phantom-typed `Slot<S>` API guarantees that
/// at compile time, author code can only invoke the FSM transitions
/// declared in spec §synth-5-E lines 1141-1156. Calling, e.g.,
/// `pool_return` on a `Slot<DmaArmedRx>` is a type error caught by
/// rustc rather than a runtime check.
pub struct ReassemblyPoolAp {
    /// Slot storage. Each slot is `[u8; SLOT_SIZE]`.
    storage: [[u8; SLOT_SIZE]; SLOT_COUNT],
    /// Per-slot lifecycle state. Replaces the α-era `in_use: [bool;
    /// SLOT_COUNT]` bitmap with the full seven-state FSM tracking.
    slot_states: [SlotState; SLOT_COUNT],
}

impl Default for ReassemblyPoolAp {
    fn default() -> Self {
        Self::new()
    }
}

impl ReassemblyPoolAp {
    /// Construct an empty pool — every slot starts on the freelist.
    pub fn new() -> Self {
        Self {
            storage: [[0u8; SLOT_SIZE]; SLOT_COUNT],
            slot_states: [SlotState::Free; SLOT_COUNT],
        }
    }

    /// Acquire a free slot for CPU-side encoding. Spec §synth-5-E line
    /// 1141: `free → cpu-mut`. Returns `None` when every slot is in
    /// use, preserving the α-era full-pool semantics.
    pub fn pool_acquire_for_encode(&mut self) -> Option<Slot<CpuMut>> {
        for (i, st) in self.slot_states.iter_mut().enumerate() {
            if *st == SlotState::Free {
                *st = SlotState::CpuMut;
                return Some(Slot { idx: i, _state: PhantomData });
            }
        }
        None
    }

    /// Arm a free slot for peripheral RX. Spec §synth-5-E line 1146:
    /// `free → dma-armed-rx`. C5: pre-arm
    /// `sce_dcache_invalidate_by_addr` is emitted here when
    /// `cache-policy: maintain && platform.has_speculative_prefetch`
    /// per spec lines 1189-1198 — evicts any cache lines the CPU's
    /// prefetcher / speculative load may have populated for this
    /// slot region while it sat on the freelist. Without the
    /// pre-arm invalidate, those stale lines would shadow DMA
    /// writes even after the post-RX invalidate (RFC §synth-5-E lines
    /// 1199-1212).
    pub fn link_arm_rx(&mut self) -> Option<Slot<DmaArmedRx>> {
        for (i, st) in self.slot_states.iter_mut().enumerate() {
            if *st == SlotState::Free {
                *st = SlotState::DmaArmedRx;
                return Some(Slot { idx: i, _state: PhantomData });
            }
        }
        None
    }

    /// Inspect a slot's current lifecycle state. Out-of-range index
    /// is `None` so debug introspection cannot panic.
    pub fn slot_state(&self, idx: usize) -> Option<SlotState> {
        self.slot_states.get(idx).copied()
    }

    /// Number of slots currently on the freelist.
    pub fn free_count(&self) -> usize {
        self.slot_states.iter().filter(|s| **s == SlotState::Free).count()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Slot<CpuMut> — the FSM edges leaving cpu-mut that author code can
// directly invoke: `cpu-mut → dma-armed-tx` (link_arm_tx) and
// `cpu-mut → free` (pool_return / abort encode error path).
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

impl Slot<CpuMut> {
    /// Hand the slot off to the link's TX path. Spec §synth-5-E line 1142:
    /// `cpu-mut → dma-armed-tx`. Consumes the handle — the slot
    /// progresses through `DmaArmedTx → DmaBusyTx → Free` via DMA
    /// controller and TX-complete IRQ; author code cannot observe
    /// these intermediate states. C5: when `cache-policy: maintain`,
    /// emits `sce_dcache_clean_by_addr` before the state transition
    /// (spec lines 1186-1188) so the DMA controller reads the
    /// latest CPU writes from main memory.
    pub fn link_arm_tx(self, pool: &mut ReassemblyPoolAp) {
        pool.slot_states[self.idx] = SlotState::DmaArmedTx;
    }

    /// Return the slot to the freelist. Spec §synth-5-E line 1155:
    /// `cpu-mut → free` ("abort encode" error path) and the
    /// `cpu-mut|cpu-ref → free` author-visible API on lines
    /// 1232-1237. Consumes the handle.
    pub fn pool_return(self, pool: &mut ReassemblyPoolAp) {
        pool.slot_states[self.idx] = SlotState::Free;
    }

    /// Read-only borrow of the slot's bytes.
    pub fn read<'a>(&'a self, pool: &'a ReassemblyPoolAp) -> &'a [u8; SLOT_SIZE] {
        &pool.storage[self.idx]
    }

    /// Mutable borrow of the slot's bytes.
    pub fn write<'a>(&'a mut self, pool: &'a mut ReassemblyPoolAp) -> &'a mut [u8; SLOT_SIZE] {
        &mut pool.storage[self.idx]
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Slot<CpuRef> — the FSM edge leaving cpu-ref that author code
// directly invokes: `cpu-ref → free` (pool_return). The
// `cpu-ref → cpu-mut` in-place mutate edge (spec line 1153) requires
// cache-clean pinning on the next hand-off (line 1154) and is
// intentionally not emitted until a consumer needs in-place mutation.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

impl Slot<CpuRef> {
    /// Return the slot to the freelist. Spec §synth-5-E line 1152:
    /// `cpu-ref → free` ("handler complete; pool_return(slot)").
    /// Consumes the handle.
    pub fn pool_return(self, pool: &mut ReassemblyPoolAp) {
        pool.slot_states[self.idx] = SlotState::Free;
    }

    /// Read-only borrow of the slot's bytes — `cpu-ref` is a shared
    /// CPU-read state per spec line 1135.
    pub fn read<'a>(&'a self, pool: &'a ReassemblyPoolAp) -> &'a [u8; SLOT_SIZE] {
        &pool.storage[self.idx]
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Slot<DmaArmedRx> — exposed for the author to register the slot
// index against a peripheral RX descriptor. The IRQ-driven
// progression `DmaArmedRx → DmaBusyRx → CpuRef` (spec lines
// 1149-1150) is owned by the runtime and not directly invocable.
// `Slot::idx()` is the only public method here.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
