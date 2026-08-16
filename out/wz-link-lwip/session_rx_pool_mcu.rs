// SCE-GENERATED — DO NOT EDIT
// source-hash: e812b8b9426089658c190b079d72f4505398532fde65fe2c41c3ec6148939d1b
// template-hash: eef83a0380a6f32e69bd8e491d75a942150e8193a11c5aedb68d2fc11fa47b6e
// generated-at: 0
// SCE-MAP: session_rx_pool_mcu.scxml:44 :: _forge_body

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
// Generated from document `session_rx_pool_mcu` with section `sram1`,
// alignment `32`, cache-policy `none`.


use core::marker::PhantomData;

/// Number of slots in the pool (`<sce:slot-count>`).
pub const SLOT_COUNT: usize = 16;

/// Bytes per slot (`<sce:slot-size>`).
pub const SLOT_SIZE: usize = 1536;

/// SRAM region name (`<sce:section>`), round-tripped so downstream
/// tooling can read it without re-parsing the SCXML.
///
/// The Rust emit does not place the pool in this region, and the
/// constant is not a hook for doing so. The C11 emit places its
/// storage with `__attribute__((section))` because storage there is a
/// file-static array of bytes and nothing else; the Rust pool owns its
/// storage inline alongside `slot_states`, and the region the sidecar
/// linker fragment declares is `(NOLOAD)` — nothing initialises it.
/// Putting this whole struct there would leave the freelist reading
/// whatever SRAM held at reset.
///
/// Placing it correctly means splitting the storage out into its own
/// placed static, which makes the pool a singleton rather than a type
/// the caller instantiates. That is the "MCU Rust variant" the spec
/// names (§synth-5-E codegen contract), and it is a different author
/// API from this one — not something a consumer can bolt on with
/// `#[link_section]`.
pub const SECTION: &'static str = "sram1";

/// DMA alignment in bytes (`<sce:alignment>`). Carried into the slot
/// type's `#[repr(align)]` below, so it is the alignment of every
/// slot rather than a number the pool merely reports. Non-powers of
/// two and a `slot-size` that is not a multiple of this are rejected
/// at parse time.
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

/// One slot's bytes, carrying the pool's declared DMA alignment.
///
/// `<sce:alignment>` describes every slot, not the table that holds
/// them. A bare `[[u8; SLOT_SIZE]; SLOT_COUNT]` has alignment 1 no
/// matter what the pool declares, so slot 0 landed whereever the
/// containing static did and every later slot sat at a multiple of
/// `SLOT_SIZE` from it — on the boundary only when `SLOT_SIZE`
/// happened to be a multiple of the alignment. Two things ride on
/// getting this right: the address handed to a peripheral, and the
/// per-slot cache maintenance, which operates by cache line and so
/// reaches into a neighbouring slot whenever a slot does not start on
/// one.
///
/// The parser rejects a `slot-size` that is not a multiple of
/// `alignment`, so the padding here is always zero — the assertions
/// below say so where the compiler can check it rather than leaving
/// the reader to trust it.
#[derive(Clone, Copy)]
#[repr(C, align(32))]
struct SlotBytes([u8; SLOT_SIZE]);

const _: () = assert!(
    core::mem::align_of::<SlotBytes>() == ALIGNMENT as usize,
    "slot alignment must be the declared <sce:alignment> (RFC §synth-5-E lines 1024-1073)",
);
const _: () = assert!(
    core::mem::size_of::<SlotBytes>() == SLOT_SIZE,
    "slot stride must equal <sce:slot-size> — padding here would mean the pool \
     silently occupies more SRAM than the author budgeted",
);

/// Generated buffer-pool. Each slot's lifecycle state is tracked in
/// `slot_states[]`; the phantom-typed `Slot<S>` API guarantees that
/// at compile time, author code can only invoke the FSM transitions
/// declared in spec §synth-5-E lines 1141-1156. Calling, e.g.,
/// `pool_return` on a `Slot<DmaArmedRx>` is a type error caught by
/// rustc rather than a runtime check.
#[repr(C)]
pub struct SessionRxPoolMcu {
    /// Slot storage. Each slot is `SLOT_SIZE` bytes on the declared
    /// DMA boundary.
    storage: [SlotBytes; SLOT_COUNT],
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
            storage: [SlotBytes([0u8; SLOT_SIZE]); SLOT_COUNT],
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

    /// Which slot a buffer address names, if any.
    ///
    /// The return leg of address publication. Peripheral completion
    /// callbacks conventionally hand back the buffer address they were
    /// given (`rx_frame_cb(addr, len)`), while every edge back into
    /// the pool is keyed by slot index. Without this the driver keeps
    /// a shadow table of a layout the pool already knows, and a slip
    /// in that table advances the wrong slot.
    ///
    /// Only an exact slot base resolves. An interior or foreign
    /// pointer is `None` rather than being rounded down to the slot
    /// containing it: a completion naming an address the pool never
    /// published is a driver bug, and rounding would turn it into a
    /// plausible-looking index.
    pub fn slot_index_of_ptr(&self, ptr: *const u8) -> Option<usize> {
        let base = self.storage.as_ptr() as usize;
        let addr = ptr as usize;
        if addr < base {
            return None;
        }
        let stride = core::mem::size_of::<SlotBytes>();
        let offset = addr - base;
        if offset % stride != 0 {
            return None;
        }
        let idx = offset / stride;
        (idx < SLOT_COUNT).then_some(idx)
    }

    /// Address of a slot in `dma-armed-tx`, for the descriptor
    /// the bus master reads it from.
    ///
    /// `dma-armed-tx` hands out no handle — the caller reached it
    /// through `link_arm_tx`, which consumed one — so the slot is
    /// named by index, the same key the completion signal carries.
    /// `None` unless the slot really is in `dma-armed-tx`, so an
    /// address cannot be lifted out of a slot some other owner holds.
    ///
    /// Returning a raw pointer rather than a slice is the point. A
    /// `&[u8]` handed out here would be a live Rust reference to
    /// memory a peripheral is about to read, which is the aliasing
    /// the DMA states exist to deny; a raw pointer carries the address
    /// and no promise about the memory. Obtaining one is safe because
    /// nothing can be read or written through it without an `unsafe`
    /// block at the point of use, which is where the contract actually
    /// binds: the pointer is valid only while the slot stays in
    /// `dma-armed-tx`, and the CPU must not write through it while
    /// the transfer runs.
    pub fn dma_armed_tx_ptr(&self, idx: usize) -> Option<*const u8> {
        if self.slot_states.get(idx) != Some(&SlotState::DmaArmedTx) {
            return None;
        }
        Some(self.storage[idx].0.as_ptr())
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
        &pool.storage[self.idx].0
    }

    /// Mutable borrow of the slot's bytes.
    pub fn write<'a>(&'a mut self, pool: &'a mut SessionRxPoolMcu) -> &'a mut [u8; SLOT_SIZE] {
        &mut pool.storage[self.idx].0
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
        &pool.storage[self.idx].0
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Address publication for `dma-armed-rx` — where the slot passes
// into a bus master's hands and therefore has to be findable by it.
//
// The states that can produce an address through the CPU accessors
// are `cpu-mut` and `cpu-ref`, and those are exactly the two no bus
// master owns. Without this the arm edges hand back a handle that
// names a slot the peripheral is about to use and no way to say
// where it is.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

impl Slot<DmaArmedRx> {
    /// Address of this slot, for the descriptor the bus master reads
    /// it from. Spec §synth-5-E lines 1024-1073 (the slot table is
    /// DMA-aligned so that this address is one a peripheral accepts).
    ///
    /// Borrows rather than consumes: publishing the address is not a
    /// transition. The caller writes it into the peripheral's
    /// descriptor and then advances the slot with `dma_start_rx`,
    /// which is where the state actually changes.
    ///
    /// Returning a raw pointer rather than a slice is the point. A
    /// `&mut [u8]` handed out here would be a live Rust reference to
    /// memory the peripheral is about to write, which is the aliasing
    /// `dma-armed-rx` exists to deny; a raw pointer carries the
    /// address and no promise about the memory. Obtaining one is safe
    /// because nothing can be read or written through it without an
    /// `unsafe` block at the point of use, which is where the contract
    /// binds: valid only while the slot stays in `dma-armed-rx`,
    /// and the CPU must not read through it before the completion
    /// edge.
    ///
    /// Takes `&mut SessionRxPoolMcu` because a pointer valid for writes
    /// has to be derived from a mutable borrow.
    pub fn dma_armed_rx_ptr(&self, pool: &mut SessionRxPoolMcu) -> *mut u8 {
        pool.storage[self.idx].0.as_mut_ptr()
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
