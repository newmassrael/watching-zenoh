// SCE-GENERATED — DO NOT EDIT
// source-hash: 948711251ed9847856aea56a28827c9d7299a6ae13ff0fd770c8e86c189035e4
// source: session_rx_pool_ap_small.scxml
// SCE-MAP: session_rx_pool_ap_small.scxml:61 :: _forge_body

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
// Generated from document `session_rx_pool_ap_small` with section `heap`,
// alignment `64`, cache-policy `none`.
//
// Total outside `#[cfg(test)]`: no indexing, no unchecked arithmetic,
// no unwrap, expect or panic. A consumer denies `clippy::indexing_slicing`,
// `clippy::arithmetic_side_effects` and the rest of the panic-free lint
// set on the crate that holds this file, and a pool sits on the DMA path,
// where a panic is a stopped device. Slot tables are reached through
// `SlotIndex`, a type with no value out of range, rather than through a
// `usize` and a bounds check.


use core::marker::PhantomData;

/// Number of slots in the pool (`<sce:slot-count>`).
pub const SLOT_COUNT: usize = 258;

/// Bytes per slot (`<sce:slot-size>`).
pub const SLOT_SIZE: usize = 1472;

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
pub const SECTION: &'static str = "heap";

/// DMA alignment in bytes (`<sce:alignment>`). Carried into the slot
/// type's `#[repr(align)]` below, so it is the alignment of every
/// slot rather than a number the pool merely reports. Non-powers of
/// two and a `slot-size` that is not a multiple of this are rejected
/// at parse time.
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
    idx: SlotIndex,
    _state: PhantomData<fn() -> S>,
}

impl<S> Slot<S> {
    /// Pool index of this slot. Read-only; useful for tracing and
    /// for writing a peripheral's DMA descriptor (e.g., for
    /// `Slot<DmaArmedRx>`).
    pub fn idx(&self) -> usize {
        self.idx.index()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Slot index — the key of both per-slot tables, in range by its type
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// One slot of the table (§synth-5-E slot table), as a value that
/// cannot name a slot the table does not have.
///
/// A consumer compiles this file under `clippy::indexing_slicing` and
/// the rest of the panic-free lint set, denied. Indexing
/// `[_; SLOT_COUNT]` with a `usize` is a bounds check whose failing
/// arm is a panic, and `get` with an arm for "no such slot" would be a
/// branch that no handle can take. This type has one variant per slot
/// and nothing else, so [`Self::of`] and [`Self::of_mut`] reach an
/// entry by taking the table apart, with neither an index nor a dead
/// branch. A `usize` that arrives from outside (a completion signal,
/// a debug probe) is converted once, by [`Self::from_index`], where
/// "names no slot" is an answer rather than a panic.
///
/// Private: a handle's index is minted only by the pool.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
enum SlotIndex {
    S0 = 0,
    S1 = 1,
    S2 = 2,
    S3 = 3,
    S4 = 4,
    S5 = 5,
    S6 = 6,
    S7 = 7,
    S8 = 8,
    S9 = 9,
    S10 = 10,
    S11 = 11,
    S12 = 12,
    S13 = 13,
    S14 = 14,
    S15 = 15,
    S16 = 16,
    S17 = 17,
    S18 = 18,
    S19 = 19,
    S20 = 20,
    S21 = 21,
    S22 = 22,
    S23 = 23,
    S24 = 24,
    S25 = 25,
    S26 = 26,
    S27 = 27,
    S28 = 28,
    S29 = 29,
    S30 = 30,
    S31 = 31,
    S32 = 32,
    S33 = 33,
    S34 = 34,
    S35 = 35,
    S36 = 36,
    S37 = 37,
    S38 = 38,
    S39 = 39,
    S40 = 40,
    S41 = 41,
    S42 = 42,
    S43 = 43,
    S44 = 44,
    S45 = 45,
    S46 = 46,
    S47 = 47,
    S48 = 48,
    S49 = 49,
    S50 = 50,
    S51 = 51,
    S52 = 52,
    S53 = 53,
    S54 = 54,
    S55 = 55,
    S56 = 56,
    S57 = 57,
    S58 = 58,
    S59 = 59,
    S60 = 60,
    S61 = 61,
    S62 = 62,
    S63 = 63,
    S64 = 64,
    S65 = 65,
    S66 = 66,
    S67 = 67,
    S68 = 68,
    S69 = 69,
    S70 = 70,
    S71 = 71,
    S72 = 72,
    S73 = 73,
    S74 = 74,
    S75 = 75,
    S76 = 76,
    S77 = 77,
    S78 = 78,
    S79 = 79,
    S80 = 80,
    S81 = 81,
    S82 = 82,
    S83 = 83,
    S84 = 84,
    S85 = 85,
    S86 = 86,
    S87 = 87,
    S88 = 88,
    S89 = 89,
    S90 = 90,
    S91 = 91,
    S92 = 92,
    S93 = 93,
    S94 = 94,
    S95 = 95,
    S96 = 96,
    S97 = 97,
    S98 = 98,
    S99 = 99,
    S100 = 100,
    S101 = 101,
    S102 = 102,
    S103 = 103,
    S104 = 104,
    S105 = 105,
    S106 = 106,
    S107 = 107,
    S108 = 108,
    S109 = 109,
    S110 = 110,
    S111 = 111,
    S112 = 112,
    S113 = 113,
    S114 = 114,
    S115 = 115,
    S116 = 116,
    S117 = 117,
    S118 = 118,
    S119 = 119,
    S120 = 120,
    S121 = 121,
    S122 = 122,
    S123 = 123,
    S124 = 124,
    S125 = 125,
    S126 = 126,
    S127 = 127,
    S128 = 128,
    S129 = 129,
    S130 = 130,
    S131 = 131,
    S132 = 132,
    S133 = 133,
    S134 = 134,
    S135 = 135,
    S136 = 136,
    S137 = 137,
    S138 = 138,
    S139 = 139,
    S140 = 140,
    S141 = 141,
    S142 = 142,
    S143 = 143,
    S144 = 144,
    S145 = 145,
    S146 = 146,
    S147 = 147,
    S148 = 148,
    S149 = 149,
    S150 = 150,
    S151 = 151,
    S152 = 152,
    S153 = 153,
    S154 = 154,
    S155 = 155,
    S156 = 156,
    S157 = 157,
    S158 = 158,
    S159 = 159,
    S160 = 160,
    S161 = 161,
    S162 = 162,
    S163 = 163,
    S164 = 164,
    S165 = 165,
    S166 = 166,
    S167 = 167,
    S168 = 168,
    S169 = 169,
    S170 = 170,
    S171 = 171,
    S172 = 172,
    S173 = 173,
    S174 = 174,
    S175 = 175,
    S176 = 176,
    S177 = 177,
    S178 = 178,
    S179 = 179,
    S180 = 180,
    S181 = 181,
    S182 = 182,
    S183 = 183,
    S184 = 184,
    S185 = 185,
    S186 = 186,
    S187 = 187,
    S188 = 188,
    S189 = 189,
    S190 = 190,
    S191 = 191,
    S192 = 192,
    S193 = 193,
    S194 = 194,
    S195 = 195,
    S196 = 196,
    S197 = 197,
    S198 = 198,
    S199 = 199,
    S200 = 200,
    S201 = 201,
    S202 = 202,
    S203 = 203,
    S204 = 204,
    S205 = 205,
    S206 = 206,
    S207 = 207,
    S208 = 208,
    S209 = 209,
    S210 = 210,
    S211 = 211,
    S212 = 212,
    S213 = 213,
    S214 = 214,
    S215 = 215,
    S216 = 216,
    S217 = 217,
    S218 = 218,
    S219 = 219,
    S220 = 220,
    S221 = 221,
    S222 = 222,
    S223 = 223,
    S224 = 224,
    S225 = 225,
    S226 = 226,
    S227 = 227,
    S228 = 228,
    S229 = 229,
    S230 = 230,
    S231 = 231,
    S232 = 232,
    S233 = 233,
    S234 = 234,
    S235 = 235,
    S236 = 236,
    S237 = 237,
    S238 = 238,
    S239 = 239,
    S240 = 240,
    S241 = 241,
    S242 = 242,
    S243 = 243,
    S244 = 244,
    S245 = 245,
    S246 = 246,
    S247 = 247,
    S248 = 248,
    S249 = 249,
    S250 = 250,
    S251 = 251,
    S252 = 252,
    S253 = 253,
    S254 = 254,
    S255 = 255,
    S256 = 256,
    S257 = 257,
}

impl SlotIndex {
    /// Every slot, in table order: the order the freelist scans.
    const ALL: [SlotIndex; SLOT_COUNT] = [
        SlotIndex::S0,
        SlotIndex::S1,
        SlotIndex::S2,
        SlotIndex::S3,
        SlotIndex::S4,
        SlotIndex::S5,
        SlotIndex::S6,
        SlotIndex::S7,
        SlotIndex::S8,
        SlotIndex::S9,
        SlotIndex::S10,
        SlotIndex::S11,
        SlotIndex::S12,
        SlotIndex::S13,
        SlotIndex::S14,
        SlotIndex::S15,
        SlotIndex::S16,
        SlotIndex::S17,
        SlotIndex::S18,
        SlotIndex::S19,
        SlotIndex::S20,
        SlotIndex::S21,
        SlotIndex::S22,
        SlotIndex::S23,
        SlotIndex::S24,
        SlotIndex::S25,
        SlotIndex::S26,
        SlotIndex::S27,
        SlotIndex::S28,
        SlotIndex::S29,
        SlotIndex::S30,
        SlotIndex::S31,
        SlotIndex::S32,
        SlotIndex::S33,
        SlotIndex::S34,
        SlotIndex::S35,
        SlotIndex::S36,
        SlotIndex::S37,
        SlotIndex::S38,
        SlotIndex::S39,
        SlotIndex::S40,
        SlotIndex::S41,
        SlotIndex::S42,
        SlotIndex::S43,
        SlotIndex::S44,
        SlotIndex::S45,
        SlotIndex::S46,
        SlotIndex::S47,
        SlotIndex::S48,
        SlotIndex::S49,
        SlotIndex::S50,
        SlotIndex::S51,
        SlotIndex::S52,
        SlotIndex::S53,
        SlotIndex::S54,
        SlotIndex::S55,
        SlotIndex::S56,
        SlotIndex::S57,
        SlotIndex::S58,
        SlotIndex::S59,
        SlotIndex::S60,
        SlotIndex::S61,
        SlotIndex::S62,
        SlotIndex::S63,
        SlotIndex::S64,
        SlotIndex::S65,
        SlotIndex::S66,
        SlotIndex::S67,
        SlotIndex::S68,
        SlotIndex::S69,
        SlotIndex::S70,
        SlotIndex::S71,
        SlotIndex::S72,
        SlotIndex::S73,
        SlotIndex::S74,
        SlotIndex::S75,
        SlotIndex::S76,
        SlotIndex::S77,
        SlotIndex::S78,
        SlotIndex::S79,
        SlotIndex::S80,
        SlotIndex::S81,
        SlotIndex::S82,
        SlotIndex::S83,
        SlotIndex::S84,
        SlotIndex::S85,
        SlotIndex::S86,
        SlotIndex::S87,
        SlotIndex::S88,
        SlotIndex::S89,
        SlotIndex::S90,
        SlotIndex::S91,
        SlotIndex::S92,
        SlotIndex::S93,
        SlotIndex::S94,
        SlotIndex::S95,
        SlotIndex::S96,
        SlotIndex::S97,
        SlotIndex::S98,
        SlotIndex::S99,
        SlotIndex::S100,
        SlotIndex::S101,
        SlotIndex::S102,
        SlotIndex::S103,
        SlotIndex::S104,
        SlotIndex::S105,
        SlotIndex::S106,
        SlotIndex::S107,
        SlotIndex::S108,
        SlotIndex::S109,
        SlotIndex::S110,
        SlotIndex::S111,
        SlotIndex::S112,
        SlotIndex::S113,
        SlotIndex::S114,
        SlotIndex::S115,
        SlotIndex::S116,
        SlotIndex::S117,
        SlotIndex::S118,
        SlotIndex::S119,
        SlotIndex::S120,
        SlotIndex::S121,
        SlotIndex::S122,
        SlotIndex::S123,
        SlotIndex::S124,
        SlotIndex::S125,
        SlotIndex::S126,
        SlotIndex::S127,
        SlotIndex::S128,
        SlotIndex::S129,
        SlotIndex::S130,
        SlotIndex::S131,
        SlotIndex::S132,
        SlotIndex::S133,
        SlotIndex::S134,
        SlotIndex::S135,
        SlotIndex::S136,
        SlotIndex::S137,
        SlotIndex::S138,
        SlotIndex::S139,
        SlotIndex::S140,
        SlotIndex::S141,
        SlotIndex::S142,
        SlotIndex::S143,
        SlotIndex::S144,
        SlotIndex::S145,
        SlotIndex::S146,
        SlotIndex::S147,
        SlotIndex::S148,
        SlotIndex::S149,
        SlotIndex::S150,
        SlotIndex::S151,
        SlotIndex::S152,
        SlotIndex::S153,
        SlotIndex::S154,
        SlotIndex::S155,
        SlotIndex::S156,
        SlotIndex::S157,
        SlotIndex::S158,
        SlotIndex::S159,
        SlotIndex::S160,
        SlotIndex::S161,
        SlotIndex::S162,
        SlotIndex::S163,
        SlotIndex::S164,
        SlotIndex::S165,
        SlotIndex::S166,
        SlotIndex::S167,
        SlotIndex::S168,
        SlotIndex::S169,
        SlotIndex::S170,
        SlotIndex::S171,
        SlotIndex::S172,
        SlotIndex::S173,
        SlotIndex::S174,
        SlotIndex::S175,
        SlotIndex::S176,
        SlotIndex::S177,
        SlotIndex::S178,
        SlotIndex::S179,
        SlotIndex::S180,
        SlotIndex::S181,
        SlotIndex::S182,
        SlotIndex::S183,
        SlotIndex::S184,
        SlotIndex::S185,
        SlotIndex::S186,
        SlotIndex::S187,
        SlotIndex::S188,
        SlotIndex::S189,
        SlotIndex::S190,
        SlotIndex::S191,
        SlotIndex::S192,
        SlotIndex::S193,
        SlotIndex::S194,
        SlotIndex::S195,
        SlotIndex::S196,
        SlotIndex::S197,
        SlotIndex::S198,
        SlotIndex::S199,
        SlotIndex::S200,
        SlotIndex::S201,
        SlotIndex::S202,
        SlotIndex::S203,
        SlotIndex::S204,
        SlotIndex::S205,
        SlotIndex::S206,
        SlotIndex::S207,
        SlotIndex::S208,
        SlotIndex::S209,
        SlotIndex::S210,
        SlotIndex::S211,
        SlotIndex::S212,
        SlotIndex::S213,
        SlotIndex::S214,
        SlotIndex::S215,
        SlotIndex::S216,
        SlotIndex::S217,
        SlotIndex::S218,
        SlotIndex::S219,
        SlotIndex::S220,
        SlotIndex::S221,
        SlotIndex::S222,
        SlotIndex::S223,
        SlotIndex::S224,
        SlotIndex::S225,
        SlotIndex::S226,
        SlotIndex::S227,
        SlotIndex::S228,
        SlotIndex::S229,
        SlotIndex::S230,
        SlotIndex::S231,
        SlotIndex::S232,
        SlotIndex::S233,
        SlotIndex::S234,
        SlotIndex::S235,
        SlotIndex::S236,
        SlotIndex::S237,
        SlotIndex::S238,
        SlotIndex::S239,
        SlotIndex::S240,
        SlotIndex::S241,
        SlotIndex::S242,
        SlotIndex::S243,
        SlotIndex::S244,
        SlotIndex::S245,
        SlotIndex::S246,
        SlotIndex::S247,
        SlotIndex::S248,
        SlotIndex::S249,
        SlotIndex::S250,
        SlotIndex::S251,
        SlotIndex::S252,
        SlotIndex::S253,
        SlotIndex::S254,
        SlotIndex::S255,
        SlotIndex::S256,
        SlotIndex::S257,
    ];

    /// The slot `i` names, or `None` past the end of the table.
    fn from_index(i: usize) -> Option<Self> {
        Self::ALL.get(i).copied()
    }

    /// This slot's position in the table, `0..SLOT_COUNT`.
    fn index(self) -> usize {
        self as usize
    }

    /// This slot's entry in a per-slot table.
    fn of<T>(self, table: &[T; SLOT_COUNT]) -> &T {
        let [
            t0,
            t1,
            t2,
            t3,
            t4,
            t5,
            t6,
            t7,
            t8,
            t9,
            t10,
            t11,
            t12,
            t13,
            t14,
            t15,
            t16,
            t17,
            t18,
            t19,
            t20,
            t21,
            t22,
            t23,
            t24,
            t25,
            t26,
            t27,
            t28,
            t29,
            t30,
            t31,
            t32,
            t33,
            t34,
            t35,
            t36,
            t37,
            t38,
            t39,
            t40,
            t41,
            t42,
            t43,
            t44,
            t45,
            t46,
            t47,
            t48,
            t49,
            t50,
            t51,
            t52,
            t53,
            t54,
            t55,
            t56,
            t57,
            t58,
            t59,
            t60,
            t61,
            t62,
            t63,
            t64,
            t65,
            t66,
            t67,
            t68,
            t69,
            t70,
            t71,
            t72,
            t73,
            t74,
            t75,
            t76,
            t77,
            t78,
            t79,
            t80,
            t81,
            t82,
            t83,
            t84,
            t85,
            t86,
            t87,
            t88,
            t89,
            t90,
            t91,
            t92,
            t93,
            t94,
            t95,
            t96,
            t97,
            t98,
            t99,
            t100,
            t101,
            t102,
            t103,
            t104,
            t105,
            t106,
            t107,
            t108,
            t109,
            t110,
            t111,
            t112,
            t113,
            t114,
            t115,
            t116,
            t117,
            t118,
            t119,
            t120,
            t121,
            t122,
            t123,
            t124,
            t125,
            t126,
            t127,
            t128,
            t129,
            t130,
            t131,
            t132,
            t133,
            t134,
            t135,
            t136,
            t137,
            t138,
            t139,
            t140,
            t141,
            t142,
            t143,
            t144,
            t145,
            t146,
            t147,
            t148,
            t149,
            t150,
            t151,
            t152,
            t153,
            t154,
            t155,
            t156,
            t157,
            t158,
            t159,
            t160,
            t161,
            t162,
            t163,
            t164,
            t165,
            t166,
            t167,
            t168,
            t169,
            t170,
            t171,
            t172,
            t173,
            t174,
            t175,
            t176,
            t177,
            t178,
            t179,
            t180,
            t181,
            t182,
            t183,
            t184,
            t185,
            t186,
            t187,
            t188,
            t189,
            t190,
            t191,
            t192,
            t193,
            t194,
            t195,
            t196,
            t197,
            t198,
            t199,
            t200,
            t201,
            t202,
            t203,
            t204,
            t205,
            t206,
            t207,
            t208,
            t209,
            t210,
            t211,
            t212,
            t213,
            t214,
            t215,
            t216,
            t217,
            t218,
            t219,
            t220,
            t221,
            t222,
            t223,
            t224,
            t225,
            t226,
            t227,
            t228,
            t229,
            t230,
            t231,
            t232,
            t233,
            t234,
            t235,
            t236,
            t237,
            t238,
            t239,
            t240,
            t241,
            t242,
            t243,
            t244,
            t245,
            t246,
            t247,
            t248,
            t249,
            t250,
            t251,
            t252,
            t253,
            t254,
            t255,
            t256,
            t257,
        ] = table;
        match self {
            Self::S0 => t0,
            Self::S1 => t1,
            Self::S2 => t2,
            Self::S3 => t3,
            Self::S4 => t4,
            Self::S5 => t5,
            Self::S6 => t6,
            Self::S7 => t7,
            Self::S8 => t8,
            Self::S9 => t9,
            Self::S10 => t10,
            Self::S11 => t11,
            Self::S12 => t12,
            Self::S13 => t13,
            Self::S14 => t14,
            Self::S15 => t15,
            Self::S16 => t16,
            Self::S17 => t17,
            Self::S18 => t18,
            Self::S19 => t19,
            Self::S20 => t20,
            Self::S21 => t21,
            Self::S22 => t22,
            Self::S23 => t23,
            Self::S24 => t24,
            Self::S25 => t25,
            Self::S26 => t26,
            Self::S27 => t27,
            Self::S28 => t28,
            Self::S29 => t29,
            Self::S30 => t30,
            Self::S31 => t31,
            Self::S32 => t32,
            Self::S33 => t33,
            Self::S34 => t34,
            Self::S35 => t35,
            Self::S36 => t36,
            Self::S37 => t37,
            Self::S38 => t38,
            Self::S39 => t39,
            Self::S40 => t40,
            Self::S41 => t41,
            Self::S42 => t42,
            Self::S43 => t43,
            Self::S44 => t44,
            Self::S45 => t45,
            Self::S46 => t46,
            Self::S47 => t47,
            Self::S48 => t48,
            Self::S49 => t49,
            Self::S50 => t50,
            Self::S51 => t51,
            Self::S52 => t52,
            Self::S53 => t53,
            Self::S54 => t54,
            Self::S55 => t55,
            Self::S56 => t56,
            Self::S57 => t57,
            Self::S58 => t58,
            Self::S59 => t59,
            Self::S60 => t60,
            Self::S61 => t61,
            Self::S62 => t62,
            Self::S63 => t63,
            Self::S64 => t64,
            Self::S65 => t65,
            Self::S66 => t66,
            Self::S67 => t67,
            Self::S68 => t68,
            Self::S69 => t69,
            Self::S70 => t70,
            Self::S71 => t71,
            Self::S72 => t72,
            Self::S73 => t73,
            Self::S74 => t74,
            Self::S75 => t75,
            Self::S76 => t76,
            Self::S77 => t77,
            Self::S78 => t78,
            Self::S79 => t79,
            Self::S80 => t80,
            Self::S81 => t81,
            Self::S82 => t82,
            Self::S83 => t83,
            Self::S84 => t84,
            Self::S85 => t85,
            Self::S86 => t86,
            Self::S87 => t87,
            Self::S88 => t88,
            Self::S89 => t89,
            Self::S90 => t90,
            Self::S91 => t91,
            Self::S92 => t92,
            Self::S93 => t93,
            Self::S94 => t94,
            Self::S95 => t95,
            Self::S96 => t96,
            Self::S97 => t97,
            Self::S98 => t98,
            Self::S99 => t99,
            Self::S100 => t100,
            Self::S101 => t101,
            Self::S102 => t102,
            Self::S103 => t103,
            Self::S104 => t104,
            Self::S105 => t105,
            Self::S106 => t106,
            Self::S107 => t107,
            Self::S108 => t108,
            Self::S109 => t109,
            Self::S110 => t110,
            Self::S111 => t111,
            Self::S112 => t112,
            Self::S113 => t113,
            Self::S114 => t114,
            Self::S115 => t115,
            Self::S116 => t116,
            Self::S117 => t117,
            Self::S118 => t118,
            Self::S119 => t119,
            Self::S120 => t120,
            Self::S121 => t121,
            Self::S122 => t122,
            Self::S123 => t123,
            Self::S124 => t124,
            Self::S125 => t125,
            Self::S126 => t126,
            Self::S127 => t127,
            Self::S128 => t128,
            Self::S129 => t129,
            Self::S130 => t130,
            Self::S131 => t131,
            Self::S132 => t132,
            Self::S133 => t133,
            Self::S134 => t134,
            Self::S135 => t135,
            Self::S136 => t136,
            Self::S137 => t137,
            Self::S138 => t138,
            Self::S139 => t139,
            Self::S140 => t140,
            Self::S141 => t141,
            Self::S142 => t142,
            Self::S143 => t143,
            Self::S144 => t144,
            Self::S145 => t145,
            Self::S146 => t146,
            Self::S147 => t147,
            Self::S148 => t148,
            Self::S149 => t149,
            Self::S150 => t150,
            Self::S151 => t151,
            Self::S152 => t152,
            Self::S153 => t153,
            Self::S154 => t154,
            Self::S155 => t155,
            Self::S156 => t156,
            Self::S157 => t157,
            Self::S158 => t158,
            Self::S159 => t159,
            Self::S160 => t160,
            Self::S161 => t161,
            Self::S162 => t162,
            Self::S163 => t163,
            Self::S164 => t164,
            Self::S165 => t165,
            Self::S166 => t166,
            Self::S167 => t167,
            Self::S168 => t168,
            Self::S169 => t169,
            Self::S170 => t170,
            Self::S171 => t171,
            Self::S172 => t172,
            Self::S173 => t173,
            Self::S174 => t174,
            Self::S175 => t175,
            Self::S176 => t176,
            Self::S177 => t177,
            Self::S178 => t178,
            Self::S179 => t179,
            Self::S180 => t180,
            Self::S181 => t181,
            Self::S182 => t182,
            Self::S183 => t183,
            Self::S184 => t184,
            Self::S185 => t185,
            Self::S186 => t186,
            Self::S187 => t187,
            Self::S188 => t188,
            Self::S189 => t189,
            Self::S190 => t190,
            Self::S191 => t191,
            Self::S192 => t192,
            Self::S193 => t193,
            Self::S194 => t194,
            Self::S195 => t195,
            Self::S196 => t196,
            Self::S197 => t197,
            Self::S198 => t198,
            Self::S199 => t199,
            Self::S200 => t200,
            Self::S201 => t201,
            Self::S202 => t202,
            Self::S203 => t203,
            Self::S204 => t204,
            Self::S205 => t205,
            Self::S206 => t206,
            Self::S207 => t207,
            Self::S208 => t208,
            Self::S209 => t209,
            Self::S210 => t210,
            Self::S211 => t211,
            Self::S212 => t212,
            Self::S213 => t213,
            Self::S214 => t214,
            Self::S215 => t215,
            Self::S216 => t216,
            Self::S217 => t217,
            Self::S218 => t218,
            Self::S219 => t219,
            Self::S220 => t220,
            Self::S221 => t221,
            Self::S222 => t222,
            Self::S223 => t223,
            Self::S224 => t224,
            Self::S225 => t225,
            Self::S226 => t226,
            Self::S227 => t227,
            Self::S228 => t228,
            Self::S229 => t229,
            Self::S230 => t230,
            Self::S231 => t231,
            Self::S232 => t232,
            Self::S233 => t233,
            Self::S234 => t234,
            Self::S235 => t235,
            Self::S236 => t236,
            Self::S237 => t237,
            Self::S238 => t238,
            Self::S239 => t239,
            Self::S240 => t240,
            Self::S241 => t241,
            Self::S242 => t242,
            Self::S243 => t243,
            Self::S244 => t244,
            Self::S245 => t245,
            Self::S246 => t246,
            Self::S247 => t247,
            Self::S248 => t248,
            Self::S249 => t249,
            Self::S250 => t250,
            Self::S251 => t251,
            Self::S252 => t252,
            Self::S253 => t253,
            Self::S254 => t254,
            Self::S255 => t255,
            Self::S256 => t256,
            Self::S257 => t257,
        }
    }

    /// This slot's entry in a per-slot table, for writing.
    fn of_mut<T>(self, table: &mut [T; SLOT_COUNT]) -> &mut T {
        let [
            t0,
            t1,
            t2,
            t3,
            t4,
            t5,
            t6,
            t7,
            t8,
            t9,
            t10,
            t11,
            t12,
            t13,
            t14,
            t15,
            t16,
            t17,
            t18,
            t19,
            t20,
            t21,
            t22,
            t23,
            t24,
            t25,
            t26,
            t27,
            t28,
            t29,
            t30,
            t31,
            t32,
            t33,
            t34,
            t35,
            t36,
            t37,
            t38,
            t39,
            t40,
            t41,
            t42,
            t43,
            t44,
            t45,
            t46,
            t47,
            t48,
            t49,
            t50,
            t51,
            t52,
            t53,
            t54,
            t55,
            t56,
            t57,
            t58,
            t59,
            t60,
            t61,
            t62,
            t63,
            t64,
            t65,
            t66,
            t67,
            t68,
            t69,
            t70,
            t71,
            t72,
            t73,
            t74,
            t75,
            t76,
            t77,
            t78,
            t79,
            t80,
            t81,
            t82,
            t83,
            t84,
            t85,
            t86,
            t87,
            t88,
            t89,
            t90,
            t91,
            t92,
            t93,
            t94,
            t95,
            t96,
            t97,
            t98,
            t99,
            t100,
            t101,
            t102,
            t103,
            t104,
            t105,
            t106,
            t107,
            t108,
            t109,
            t110,
            t111,
            t112,
            t113,
            t114,
            t115,
            t116,
            t117,
            t118,
            t119,
            t120,
            t121,
            t122,
            t123,
            t124,
            t125,
            t126,
            t127,
            t128,
            t129,
            t130,
            t131,
            t132,
            t133,
            t134,
            t135,
            t136,
            t137,
            t138,
            t139,
            t140,
            t141,
            t142,
            t143,
            t144,
            t145,
            t146,
            t147,
            t148,
            t149,
            t150,
            t151,
            t152,
            t153,
            t154,
            t155,
            t156,
            t157,
            t158,
            t159,
            t160,
            t161,
            t162,
            t163,
            t164,
            t165,
            t166,
            t167,
            t168,
            t169,
            t170,
            t171,
            t172,
            t173,
            t174,
            t175,
            t176,
            t177,
            t178,
            t179,
            t180,
            t181,
            t182,
            t183,
            t184,
            t185,
            t186,
            t187,
            t188,
            t189,
            t190,
            t191,
            t192,
            t193,
            t194,
            t195,
            t196,
            t197,
            t198,
            t199,
            t200,
            t201,
            t202,
            t203,
            t204,
            t205,
            t206,
            t207,
            t208,
            t209,
            t210,
            t211,
            t212,
            t213,
            t214,
            t215,
            t216,
            t217,
            t218,
            t219,
            t220,
            t221,
            t222,
            t223,
            t224,
            t225,
            t226,
            t227,
            t228,
            t229,
            t230,
            t231,
            t232,
            t233,
            t234,
            t235,
            t236,
            t237,
            t238,
            t239,
            t240,
            t241,
            t242,
            t243,
            t244,
            t245,
            t246,
            t247,
            t248,
            t249,
            t250,
            t251,
            t252,
            t253,
            t254,
            t255,
            t256,
            t257,
        ] = table;
        match self {
            Self::S0 => t0,
            Self::S1 => t1,
            Self::S2 => t2,
            Self::S3 => t3,
            Self::S4 => t4,
            Self::S5 => t5,
            Self::S6 => t6,
            Self::S7 => t7,
            Self::S8 => t8,
            Self::S9 => t9,
            Self::S10 => t10,
            Self::S11 => t11,
            Self::S12 => t12,
            Self::S13 => t13,
            Self::S14 => t14,
            Self::S15 => t15,
            Self::S16 => t16,
            Self::S17 => t17,
            Self::S18 => t18,
            Self::S19 => t19,
            Self::S20 => t20,
            Self::S21 => t21,
            Self::S22 => t22,
            Self::S23 => t23,
            Self::S24 => t24,
            Self::S25 => t25,
            Self::S26 => t26,
            Self::S27 => t27,
            Self::S28 => t28,
            Self::S29 => t29,
            Self::S30 => t30,
            Self::S31 => t31,
            Self::S32 => t32,
            Self::S33 => t33,
            Self::S34 => t34,
            Self::S35 => t35,
            Self::S36 => t36,
            Self::S37 => t37,
            Self::S38 => t38,
            Self::S39 => t39,
            Self::S40 => t40,
            Self::S41 => t41,
            Self::S42 => t42,
            Self::S43 => t43,
            Self::S44 => t44,
            Self::S45 => t45,
            Self::S46 => t46,
            Self::S47 => t47,
            Self::S48 => t48,
            Self::S49 => t49,
            Self::S50 => t50,
            Self::S51 => t51,
            Self::S52 => t52,
            Self::S53 => t53,
            Self::S54 => t54,
            Self::S55 => t55,
            Self::S56 => t56,
            Self::S57 => t57,
            Self::S58 => t58,
            Self::S59 => t59,
            Self::S60 => t60,
            Self::S61 => t61,
            Self::S62 => t62,
            Self::S63 => t63,
            Self::S64 => t64,
            Self::S65 => t65,
            Self::S66 => t66,
            Self::S67 => t67,
            Self::S68 => t68,
            Self::S69 => t69,
            Self::S70 => t70,
            Self::S71 => t71,
            Self::S72 => t72,
            Self::S73 => t73,
            Self::S74 => t74,
            Self::S75 => t75,
            Self::S76 => t76,
            Self::S77 => t77,
            Self::S78 => t78,
            Self::S79 => t79,
            Self::S80 => t80,
            Self::S81 => t81,
            Self::S82 => t82,
            Self::S83 => t83,
            Self::S84 => t84,
            Self::S85 => t85,
            Self::S86 => t86,
            Self::S87 => t87,
            Self::S88 => t88,
            Self::S89 => t89,
            Self::S90 => t90,
            Self::S91 => t91,
            Self::S92 => t92,
            Self::S93 => t93,
            Self::S94 => t94,
            Self::S95 => t95,
            Self::S96 => t96,
            Self::S97 => t97,
            Self::S98 => t98,
            Self::S99 => t99,
            Self::S100 => t100,
            Self::S101 => t101,
            Self::S102 => t102,
            Self::S103 => t103,
            Self::S104 => t104,
            Self::S105 => t105,
            Self::S106 => t106,
            Self::S107 => t107,
            Self::S108 => t108,
            Self::S109 => t109,
            Self::S110 => t110,
            Self::S111 => t111,
            Self::S112 => t112,
            Self::S113 => t113,
            Self::S114 => t114,
            Self::S115 => t115,
            Self::S116 => t116,
            Self::S117 => t117,
            Self::S118 => t118,
            Self::S119 => t119,
            Self::S120 => t120,
            Self::S121 => t121,
            Self::S122 => t122,
            Self::S123 => t123,
            Self::S124 => t124,
            Self::S125 => t125,
            Self::S126 => t126,
            Self::S127 => t127,
            Self::S128 => t128,
            Self::S129 => t129,
            Self::S130 => t130,
            Self::S131 => t131,
            Self::S132 => t132,
            Self::S133 => t133,
            Self::S134 => t134,
            Self::S135 => t135,
            Self::S136 => t136,
            Self::S137 => t137,
            Self::S138 => t138,
            Self::S139 => t139,
            Self::S140 => t140,
            Self::S141 => t141,
            Self::S142 => t142,
            Self::S143 => t143,
            Self::S144 => t144,
            Self::S145 => t145,
            Self::S146 => t146,
            Self::S147 => t147,
            Self::S148 => t148,
            Self::S149 => t149,
            Self::S150 => t150,
            Self::S151 => t151,
            Self::S152 => t152,
            Self::S153 => t153,
            Self::S154 => t154,
            Self::S155 => t155,
            Self::S156 => t156,
            Self::S157 => t157,
            Self::S158 => t158,
            Self::S159 => t159,
            Self::S160 => t160,
            Self::S161 => t161,
            Self::S162 => t162,
            Self::S163 => t163,
            Self::S164 => t164,
            Self::S165 => t165,
            Self::S166 => t166,
            Self::S167 => t167,
            Self::S168 => t168,
            Self::S169 => t169,
            Self::S170 => t170,
            Self::S171 => t171,
            Self::S172 => t172,
            Self::S173 => t173,
            Self::S174 => t174,
            Self::S175 => t175,
            Self::S176 => t176,
            Self::S177 => t177,
            Self::S178 => t178,
            Self::S179 => t179,
            Self::S180 => t180,
            Self::S181 => t181,
            Self::S182 => t182,
            Self::S183 => t183,
            Self::S184 => t184,
            Self::S185 => t185,
            Self::S186 => t186,
            Self::S187 => t187,
            Self::S188 => t188,
            Self::S189 => t189,
            Self::S190 => t190,
            Self::S191 => t191,
            Self::S192 => t192,
            Self::S193 => t193,
            Self::S194 => t194,
            Self::S195 => t195,
            Self::S196 => t196,
            Self::S197 => t197,
            Self::S198 => t198,
            Self::S199 => t199,
            Self::S200 => t200,
            Self::S201 => t201,
            Self::S202 => t202,
            Self::S203 => t203,
            Self::S204 => t204,
            Self::S205 => t205,
            Self::S206 => t206,
            Self::S207 => t207,
            Self::S208 => t208,
            Self::S209 => t209,
            Self::S210 => t210,
            Self::S211 => t211,
            Self::S212 => t212,
            Self::S213 => t213,
            Self::S214 => t214,
            Self::S215 => t215,
            Self::S216 => t216,
            Self::S217 => t217,
            Self::S218 => t218,
            Self::S219 => t219,
            Self::S220 => t220,
            Self::S221 => t221,
            Self::S222 => t222,
            Self::S223 => t223,
            Self::S224 => t224,
            Self::S225 => t225,
            Self::S226 => t226,
            Self::S227 => t227,
            Self::S228 => t228,
            Self::S229 => t229,
            Self::S230 => t230,
            Self::S231 => t231,
            Self::S232 => t232,
            Self::S233 => t233,
            Self::S234 => t234,
            Self::S235 => t235,
            Self::S236 => t236,
            Self::S237 => t237,
            Self::S238 => t238,
            Self::S239 => t239,
            Self::S240 => t240,
            Self::S241 => t241,
            Self::S242 => t242,
            Self::S243 => t243,
            Self::S244 => t244,
            Self::S245 => t245,
            Self::S246 => t246,
            Self::S247 => t247,
            Self::S248 => t248,
            Self::S249 => t249,
            Self::S250 => t250,
            Self::S251 => t251,
            Self::S252 => t252,
            Self::S253 => t253,
            Self::S254 => t254,
            Self::S255 => t255,
            Self::S256 => t256,
            Self::S257 => t257,
        }
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
#[repr(C, align(64))]
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
pub struct SessionRxPoolApSmall {
    /// Slot storage. Each slot is `SLOT_SIZE` bytes on the declared
    /// DMA boundary.
    storage: [SlotBytes; SLOT_COUNT],
    /// Per-slot lifecycle state. Replaces the α-era `in_use: [bool;
    /// SLOT_COUNT]` bitmap with the full seven-state FSM tracking.
    slot_states: [SlotState; SLOT_COUNT],
}

impl Default for SessionRxPoolApSmall {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionRxPoolApSmall {
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
        for (idx, st) in SlotIndex::ALL.iter().copied().zip(self.slot_states.iter_mut()) {
            if *st == SlotState::Free {
                *st = SlotState::CpuMut;
                return Some(Slot { idx, _state: PhantomData });
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
        for (idx, st) in SlotIndex::ALL.iter().copied().zip(self.slot_states.iter_mut()) {
            if *st == SlotState::Free {
                *st = SlotState::DmaArmedRx;
                return Some(Slot { idx, _state: PhantomData });
            }
        }
        None
    }

    /// Inspect a slot's current lifecycle state. Out-of-range index
    /// is `None` so debug introspection cannot panic.
    pub fn slot_state(&self, idx: usize) -> Option<SlotState> {
        SlotIndex::from_index(idx).map(|slot| *slot.of(&self.slot_states))
    }

    /// The slot `idx` names, when it names one and that slot is in
    /// `state`. The one place an index-keyed edge or accessor turns the
    /// `usize` it was handed into a slot, so each reads the state once
    /// and every later table access is by `SlotIndex`.
    fn slot_in(&self, idx: usize, state: SlotState) -> Option<SlotIndex> {
        SlotIndex::from_index(idx).filter(|slot| *slot.of(&self.slot_states) == state)
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
    ///
    /// Checked arithmetic throughout, because the consumer denies
    /// `clippy::arithmetic_side_effects`: an address below the table is
    /// the subtraction's `None`, and the remainder and quotient divide
    /// by the stride, `size_of::<SlotBytes>()`, which is `slot-size`
    /// and positive by the parser. `is_multiple_of` would say the
    /// remainder test in one call, but the generated Rust compiles on
    /// Rust 1.81, which does not have it.
    pub fn slot_index_of_ptr(&self, ptr: *const u8) -> Option<usize> {
        let base = self.storage.as_ptr() as usize;
        let stride = core::mem::size_of::<SlotBytes>();
        let offset = (ptr as usize).checked_sub(base)?;
        if offset.checked_rem(stride)? != 0 {
            return None;
        }
        let idx = offset.checked_div(stride)?;
        SlotIndex::from_index(idx).map(SlotIndex::index)
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
        let slot = self.slot_in(idx, SlotState::DmaArmedTx)?;
        Some(slot.of(&self.storage).0.as_ptr())
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
    pub fn link_arm_tx(self, pool: &mut SessionRxPoolApSmall) {
        *self.idx.of_mut(&mut pool.slot_states) = SlotState::DmaArmedTx;
    }

    /// Return the slot to the freelist. Spec §synth-5-E line 1155:
    /// `cpu-mut → free` ("abort encode" error path) and the
    /// `cpu-mut|cpu-ref → free` author-visible API on lines
    /// 1232-1237. Consumes the handle.
    pub fn pool_return(self, pool: &mut SessionRxPoolApSmall) {
        *self.idx.of_mut(&mut pool.slot_states) = SlotState::Free;
    }

    /// Read-only borrow of the slot's bytes.
    pub fn read<'a>(&'a self, pool: &'a SessionRxPoolApSmall) -> &'a [u8; SLOT_SIZE] {
        &self.idx.of(&pool.storage).0
    }

    /// Mutable borrow of the slot's bytes.
    pub fn write<'a>(&'a mut self, pool: &'a mut SessionRxPoolApSmall) -> &'a mut [u8; SLOT_SIZE] {
        &mut self.idx.of_mut(&mut pool.storage).0
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
    pub fn pool_return(self, pool: &mut SessionRxPoolApSmall) {
        *self.idx.of_mut(&mut pool.slot_states) = SlotState::Free;
    }

    /// Read-only borrow of the slot's bytes — `cpu-ref` is a shared
    /// CPU-read state per spec line 1135.
    pub fn read<'a>(&'a self, pool: &'a SessionRxPoolApSmall) -> &'a [u8; SLOT_SIZE] {
        &self.idx.of(&pool.storage).0
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
    /// Takes `&mut SessionRxPoolApSmall` because a pointer valid for writes
    /// has to be derived from a mutable borrow.
    pub fn dma_armed_rx_ptr(&self, pool: &mut SessionRxPoolApSmall) -> *mut u8 {
        self.idx.of_mut(&mut pool.storage).0.as_mut_ptr()    }
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

impl SessionRxPoolApSmall {
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
        let Some(slot) = self.slot_in(idx, SlotState::DmaArmedTx) else {
            return false;
        };
        *slot.of_mut(&mut self.slot_states) = SlotState::DmaBusyTx;
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
        let Some(slot) = self.slot_in(idx, SlotState::DmaBusyTx) else {
            return false;
        };
        *slot.of_mut(&mut self.slot_states) = SlotState::Free;
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
        let slot = self.slot_in(idx, SlotState::DmaBusyRx)?;
        *slot.of_mut(&mut self.slot_states) = SlotState::CpuRef;
        Some(Slot { idx: slot, _state: PhantomData })
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
        let slot = self.slot_in(idx, SlotState::DmaArmedTx)?;
        *slot.of_mut(&mut self.slot_states) = SlotState::CpuMut;
        Some(Slot { idx: slot, _state: PhantomData })
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
    pub unsafe fn dma_start_rx(self, pool: &mut SessionRxPoolApSmall) {
        *self.idx.of_mut(&mut pool.slot_states) = SlotState::DmaBusyRx;
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
    pub unsafe fn mutate_in_place(self, pool: &mut SessionRxPoolApSmall) -> Slot<CpuMut> {
        *self.idx.of_mut(&mut pool.slot_states) = SlotState::CpuMut;
        Slot { idx: self.idx, _state: PhantomData }
    }
}
