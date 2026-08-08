// SCE-GENERATED — DO NOT EDIT
// source-hash: e812b8b9426089658c190b079d72f4505398532fde65fe2c41c3ec6148939d1b
// template-hash: e9541de728219e5b918752124cad2b5ba2950a5da7bb328f3588c49d2bba35c4
// generated-at: 0
// SCE-MAP: session_rx_pool_mcu.scxml:44

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="buffer-pool")
// Runtime: self-contained on (rust, std) — no SCE-side helper crate.
// Do not edit — regenerate from the source SCXML file.
//
// SCE Protocol-Synthesis RFC §synth-5-E DMA-aligned slot table with the seven-state
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
// Generated from `name="session_rx_pool_mcu"` with section `sram1`,
// alignment `32`, cache-policy `none`.


use core::marker::PhantomData;

/// Number of slots in the pool (`<sce:slot-count>`).
pub const SLOT_COUNT: usize = 16;

/// Bytes per slot (`<sce:slot-size>`).
pub const SLOT_SIZE: usize = 1536;

/// SRAM region name (`<sce:section>`). Round-tripped here so that
/// downstream linker integration can read it without re-parsing
/// the SCXML.
pub const SECTION: &'static str = "sram1";

/// DMA alignment in bytes (`<sce:alignment>`). Power-of-2
/// violations surface in the emitted linker fragment, where the
/// constraint is observable through `ALIGN(<n>)` directives.
pub const ALIGNMENT: u32 = 32;

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
// Slot lifecycle state — runtime tag value (mirrors C11 enum)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// One of the seven slot ownership states. Discriminants match the
/// C11 backend's `sce_slot_state_t` enum so cross-language tracing
/// over a single binary representation stays consistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Phantom marker for `SlotState::CpuMut`.
/// Held by author code while the slot is in exclusive
/// CPU-write state.
#[derive(Debug)]
pub struct CpuMut;

/// Phantom marker for `SlotState::DmaArmedRx`.
/// Returned from `link_arm_rx` so the author can register the
/// slot index with the peripheral's RX descriptor. Hand it to
/// `dma_start_rx` when the peripheral begins writing.
#[derive(Debug)]
pub struct DmaArmedRx;

/// Phantom marker for `SlotState::CpuRef`.
/// Held by author code while the slot is in shared CPU-read
/// state (post-RX-IRQ).
#[derive(Debug)]
pub struct CpuRef;


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
pub struct SessionRxPoolMcu {
    /// Slot storage. Each slot is `[u8; SLOT_SIZE]`.
    storage: [[u8; SLOT_SIZE]; SLOT_COUNT],
    /// Per-slot lifecycle state. Replaces the α-era `in_use: [bool;
    /// SLOT_COUNT]` bitmap with the full seven-state FSM tracking.
    slot_states: [SlotState; SLOT_COUNT],
}

impl Default for SessionRxPoolMcu {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionRxPoolMcu {
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
    pub fn link_arm_tx(self, pool: &mut SessionRxPoolMcu) {
        pool.slot_states[self.idx] = SlotState::DmaArmedTx;
    }

    /// Return the slot to the freelist. Spec §synth-5-E line 1155:
    /// `cpu-mut → free` ("abort encode" error path) and the
    /// `cpu-mut|cpu-ref → free` author-visible API on lines
    /// 1232-1237. Consumes the handle.
    pub fn pool_return(self, pool: &mut SessionRxPoolMcu) {
        pool.slot_states[self.idx] = SlotState::Free;
    }

    /// Read-only borrow of the slot's bytes.
    pub fn read<'a>(&'a self, pool: &'a SessionRxPoolMcu) -> &'a [u8; SLOT_SIZE] {
        &pool.storage[self.idx]
    }

    /// Mutable borrow of the slot's bytes.
    pub fn write<'a>(&'a mut self, pool: &'a mut SessionRxPoolMcu) -> &'a mut [u8; SLOT_SIZE] {
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
    pub fn pool_return(self, pool: &mut SessionRxPoolMcu) {
        pool.slot_states[self.idx] = SlotState::Free;
    }

    /// Read-only borrow of the slot's bytes — `cpu-ref` is a shared
    /// CPU-read state per spec line 1135.
    pub fn read<'a>(&'a self, pool: &'a SessionRxPoolMcu) -> &'a [u8; SLOT_SIZE] {
        &pool.storage[self.idx]
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Runtime seam — the six FSM edges the DMA controller, the
// peripheral, and the completion IRQs own (spec §synth-5-E lines
// 1144, 1145, 1149, 1150, 1153, 1156).
//
// These are not part of the author-visible API on spec lines
// 1232-1237, but they are emitted, because leaving them out does not
// make them unreachable — it makes the pool a one-way sink.
// `pool_acquire_for_encode` and `link_arm_rx` hand slots out;
// `dma-busy-tx → free` and `dma-busy-rx → cpu-ref` are the only
// edges that hand them back, and both live here. Without this block
// a slot armed for DMA never returns to the freelist and the pool
// drains permanently.
//
// Two shapes, decided by whether the edge's source state is one the
// API can hand back as a `Slot<S>`:
//
//   * source is holdable — the caller has the handle, so the method
//     consumes it and Rust's move semantics invalidate the old state.
//   * source is DMA-owned — no handle exists by construction. The
//     completion signal carries a channel/descriptor index and
//     nothing else, so the pool method takes `idx` and mints the
//     resulting handle.
//
// Every one is `unsafe`, and that is a real contract rather than a
// naming convention: calling one before the hardware event it names
// hands out a view of memory the peripheral is still writing.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

impl SessionRxPoolMcu {
    /// `dma-armed-tx → dma-busy-tx` — DMA controller signal.
    /// Spec §synth-5-E line 1144.
    ///
    /// Runtime-owned edge. `dma-armed-tx` hands out no handle, so
    /// the slot is named by index — which is what the completion
    /// signal actually carries.
    ///
    /// Refuses a slot that is not in `dma-armed-tx`, so a spurious
    /// or replayed interrupt cannot advance an unrelated slot.
    ///
    /// # Safety
    /// The caller must have observed DMA controller signal for this slot.
    /// Calling it early publishes memory the peripheral still owns.
    pub unsafe fn dma_start_tx(&mut self, idx: usize) -> bool {
        if self.slot_states.get(idx) != Some(&SlotState::DmaArmedTx) {
            return false;
        }
        self.slot_states[idx] = SlotState::DmaBusyTx;
        true
    }

    /// `dma-busy-tx → free` — TX-complete IRQ; pool_return(slot).
    /// Spec §synth-5-E line 1145.
    ///
    /// Runtime-owned edge. `dma-busy-tx` hands out no handle, so
    /// the slot is named by index — which is what the completion
    /// signal actually carries.
    ///
    /// Refuses a slot that is not in `dma-busy-tx`, so a spurious
    /// or replayed interrupt cannot advance an unrelated slot.
    ///
    /// # Safety
    /// The caller must have observed TX-complete IRQ; pool_return(slot) for this slot.
    /// Calling it early publishes memory the peripheral still owns.
    pub unsafe fn tx_complete(&mut self, idx: usize) -> bool {
        if self.slot_states.get(idx) != Some(&SlotState::DmaBusyTx) {
            return false;
        }
        self.slot_states[idx] = SlotState::Free;
        true
    }

    /// `dma-busy-rx → cpu-ref` — RX-complete IRQ.
    /// Spec §synth-5-E line 1150.
    ///
    /// Runtime-owned edge. `dma-busy-rx` hands out no handle, so
    /// the slot is named by index — which is what the completion
    /// signal actually carries.
    ///
    /// Refuses a slot that is not in `dma-busy-rx`, so a spurious
    /// or replayed interrupt cannot advance an unrelated slot.
    ///
    /// # Safety
    /// The caller must have observed RX-complete IRQ for this slot.
    /// Calling it early publishes memory the peripheral still owns.
    pub unsafe fn rx_complete(&mut self, idx: usize) -> Option<Slot<CpuRef>> {
        if self.slot_states.get(idx) != Some(&SlotState::DmaBusyRx) {
            return None;
        }
        self.slot_states[idx] = SlotState::CpuRef;
        Some(Slot { idx, _state: PhantomData })
    }

    /// `dma-armed-tx → cpu-mut` — un-arm before DMA start (error path).
    /// Spec §synth-5-E line 1156.
    ///
    /// Runtime-owned edge. `dma-armed-tx` hands out no handle, so
    /// the slot is named by index — which is what the completion
    /// signal actually carries.
    ///
    /// Refuses a slot that is not in `dma-armed-tx`, so a spurious
    /// or replayed interrupt cannot advance an unrelated slot.
    ///
    /// # Safety
    /// The caller must have observed un-arm before DMA start (error path) for this slot.
    /// Calling it early publishes memory the peripheral still owns.
    pub unsafe fn un_arm_tx(&mut self, idx: usize) -> Option<Slot<CpuMut>> {
        if self.slot_states.get(idx) != Some(&SlotState::DmaArmedTx) {
            return None;
        }
        self.slot_states[idx] = SlotState::CpuMut;
        Some(Slot { idx, _state: PhantomData })
    }

}

impl Slot<DmaArmedRx> {
    /// `dma-armed-rx → dma-busy-rx` — peripheral start.
    /// Spec §synth-5-E line 1149.
    ///
    /// Runtime-owned edge. Consumes the handle, so the
    /// `dma-armed-rx` view cannot outlive the transition.
    ///
    /// # Safety
    /// The caller must have observed peripheral start for this slot.
    /// Calling it early publishes memory the peripheral still owns.
    pub unsafe fn dma_start_rx(self, pool: &mut SessionRxPoolMcu) {
        pool.slot_states[self.idx] = SlotState::DmaBusyRx;
    }
}

impl Slot<CpuRef> {
    /// `cpu-ref → cpu-mut` — in-place mutate.
    /// Spec §synth-5-E line 1153.
    ///
    /// Runtime-owned edge. Consumes the handle, so the
    /// `cpu-ref` view cannot outlive the transition.
    ///
    /// # Safety
    /// The caller must have observed in-place mutate for this slot.
    /// Calling it early publishes memory the peripheral still owns.
    pub unsafe fn mutate_in_place(self, pool: &mut SessionRxPoolMcu) -> Slot<CpuMut> {
        pool.slot_states[self.idx] = SlotState::CpuMut;
        Slot { idx: self.idx, _state: PhantomData }
    }
}
