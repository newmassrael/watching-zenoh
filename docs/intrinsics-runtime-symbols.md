# Intrinsics runtime — symbol surface

**Status.** Pre-implementation prose. Defines what
`sce_intrinsics_runtime` (the crate referenced in RFC §5.I as the
whitelist host) exposes as concrete symbols, and how that surface
relates to the §5.J.2 statechart `no_std` HAL trait. This document
is the canonical reference both Phase A C11 codegen and Phase D.1+
Rust codegen emit `extern` declarations against. It is the third
of three runtime-crate API stub documents (sibling of
`docs/runtime-crate-tokio.md` and `docs/runtime-crate-lwip.md`).

**Scope.** Two crate variants — `sce_intrinsics_runtime_c` for
`(c11, bare_metal)` MCU emission, `sce_intrinsics_runtime_rust`
for `(rust, linux | qnx)` AP emission — and the symbol categories
each exposes. The two variants share the same logical symbol
surface; the difference is the language form (C function vs Rust
extern fn) and per-OS body (e.g. cache maintenance is a CMSIS
intrinsic on MCU, a no-op on linux because the kernel keeps user-
space memory cache-coherent for normal pages). The §5.J.2
statechart `no_std` runtime calls into a small HAL trait that this
document maps onto the C / Rust symbol set.

**Inputs (normative).**
- RFC §5.I `sce:extern` whitelist — atomics (5 widths × {load /
  store / cas / fetch_*}), fences (acq / rel / acq_rel / seq_cst
  + DMA fence + compiler barrier), cache maintenance
  (`sce_dcache_clean_by_addr` / `invalidate_by_addr` /
  `clean_invalidate_by_addr`), interrupt control (`sce_irq_save`
  / `sce_irq_restore`).
- RFC §5.J.2 — statechart `no_std` runtime grows a HAL trait
  (ticks / wake / irq-save) provided by `sce_intrinsics_runtime`.
  This document fixes the trait shape and which crate variant
  supplies the body.
- RFC §5.K `target_plugin` extension shape (§5.I "Target-level
  extension") — per-SoC HMAC accelerator (`stm32h7_cryp_hmac_sha256`
  for STM32H7, software fallback for M0+/M3) and HW semaphores
  (HSEM / ESP32 cross-core spinlock / NXP MU mailbox) live in
  target plugins, NOT in the core whitelist. OQ-W14 (HW-sem
  symbol-name standardization) and OQ-W15 (HMAC + RNG primitive
  ownership) gate the final shape; this document presents the
  **initial proposal** per OQ-W15 (option 2 for HMAC, option 1
  for RNG).
- `docs/session-fsm.md` §2.7 G-SFM-5 — HMAC + RNG primitive
  ownership question (OQ-W15). This document encodes the initial
  proposal as the symbol-table policy column entries.
- `docs/reassembly-fsm.md` §6 — cache maintenance pinning. Those
  are the symbol *call sites* (the §5.E pool lifecycle FSM edges
  emit `sce_dcache_invalidate_by_addr` / `clean_by_addr` calls);
  this document declares the symbols themselves.
- ARCHITECTURE §9.5 5-row matrix — same symbol set, different
  bodies per row. MCU body uses ARM CMSIS cache ops; linux body
  is a no-op for cache maintenance (kernel-coherent); QNX body
  uses kernel pulse / dispatch primitives for IRQ-control
  equivalents (Phase D.2, namespace-reserved here).
- `deploy/mcu_target.yaml:382-383` — `extern_symbols.lib:
  sce_intrinsics_runtime_c` + `target_plugin:
  configs/target_extensions_stm32h747.yaml`.
- `deploy/ap_standalone.yaml:281` — `extern_symbols.lib:
  sce_intrinsics_runtime_rust`. `target_plugin: ~` (AP linux
  baseline does not require a plugin).

**Outputs.** (1) A categorized symbol table (atomics / fences /
cache / IRQ / RNG / HMAC / HW-sem) with each row marked `core
whitelist` or `target plugin`, with the OQ that decides unresolved
cells. (2) The §5.J.2 statechart `no_std` HAL trait mapped onto
these symbols. (3) Cross-reference back into RFC §5.I diagnostic
list (`extern/symbol-not-in-whitelist` etc.) so authoring
violations are traceable to specific symbols.

**Non-outputs.** Symbol body implementations (C source / Rust
source — those are runtime crate concerns, not this prose
contract). Per-SoC HMAC accelerator binding — that is a worked
example in target plugin docs (`configs/target_extensions_<soc>.yaml`).
SCXML authoring against `<sce:extern>` — blocked on Phase A.

---

## §2 Symbol categories

The symbol surface partitions into seven categories. Each category
is marked **core** (in the `sce_intrinsics_runtime_*` crate
whitelist; every deploy gets these for free) or **target plugin**
(per-SoC, declared in `configs/target_extensions_*.yaml`; deploy
without the plugin omits these).

### §2.1 Atomics — core whitelist

Per-width (u8 / u16 / u32 / u64 / usize), with explicit memory
ordering encoded in the symbol name (no integer ordering parameter
— the symbol *is* the ordering choice). RFC §5.I lists the symbols
verbatim:

```
sce_atomic_load_{acquire,relaxed}                 (per width)
sce_atomic_store_{release,relaxed}                (per width)
sce_atomic_cas_weak_{acq_rel,release,relaxed}     (per width)
sce_atomic_cas_strong_{acq_rel,release,relaxed}   (per width)
sce_atomic_fetch_add_{acq_rel,relaxed}            (per width)
sce_atomic_fetch_sub_{acq_rel,relaxed}            (per width)
sce_atomic_fetch_or_{acq_rel,relaxed}             (per width)
sce_atomic_fetch_and_{acq_rel,relaxed}            (per width)
```

**Ownership.** Core whitelist on both variants:
`sce_intrinsics_runtime_c` provides them as C11 wrappers over
`<stdatomic.h>`; `sce_intrinsics_runtime_rust` provides them as
extern wrappers over `core::sync::atomic`. Cross-platform symbol
name shape is identical so SCXML authors write
`<sce:extern name="sce_atomic_cas_strong_acq_rel_u32" .../>` once
and codegen wires it to the right body per
`(language, target_os)` 3-tuple.

**Diagnostic anchors.** `extern/ordering-unspecified` (RFC §5.I)
fires when an SCXML `<sce:extern>` references an atomic without
the ordering suffix. `extern/ordering-insufficient-for-cross-core`
fires when `relaxed` is used on cross-core shared state
(`platform.core_count > 1` deploy).

### §2.2 Fences — core whitelist

```
sce_atomic_fence_{acquire,release,acq_rel,seq_cst}
sce_compiler_barrier        (no runtime cost; blocks compiler reordering)
sce_dma_fence               (DSB on ARMv7-M+, no-op on linux)
```

`sce_dma_fence` lowers to `__DSB()` on ARM; on linux it is a
no-op (the kernel inserts the barrier on the syscall boundary).
On QNX (Phase D.2) it lowers to the appropriate barrier per the
QNX ABI (TBD — out of scope this document).

### §2.3 Cache maintenance — core whitelist on MCU, no-op on AP

```
sce_dcache_clean_by_addr(const void *start, size_t len)
sce_dcache_invalidate_by_addr(void *start, size_t len)
sce_dcache_clean_invalidate_by_addr(void *start, size_t len)
```

**Ownership.** Core whitelist on `sce_intrinsics_runtime_c` (MCU);
no-op on `sce_intrinsics_runtime_rust` for `os: linux` (kernel-
coherent normal pages); QNX behavior TBD Phase D.2.

**Pinning.** Per `docs/reassembly-fsm.md` §6 + RFC §5.E "Cache
maintenance pinning", these symbols are emitted *only* on §5.E
lifecycle FSM edges by codegen. Author code calling them directly
via `<sce:call>` triggers `pool/cache-maintenance-misplaced` (RFC
§5.E hard error). The whitelist *includes* the symbols so codegen
can emit them; SCXML authors do not invoke them.

**Per-platform body sketch:**

| Platform | `clean_by_addr` body | `invalidate_by_addr` body |
|---|---|---|
| Cortex-M7 / M85 / A-class | CMSIS `SCB_CleanDCache_by_Addr` | CMSIS `SCB_InvalidateDCache_by_Addr` |
| Cortex-M0 / M0+ / M3 / M4 (no D-Cache) | empty function (link-time elision) | empty function |
| linux | empty function (kernel-coherent) | empty function |
| qnx | TBD Phase D.2 | TBD Phase D.2 |

The "empty function" entries are emitted as actual functions
(rather than preprocessor `#define foo()`) so the `pool/cache-
maintenance-misplaced` diagnostic catches misuse on every platform
uniformly. Optimizer dead-code elimination removes the call
overhead at link time.

### §2.4 IRQ control — core whitelist (optional surface)

```
sce_irq_save() -> irq_state_t
sce_irq_restore(irq_state_t)
```

**Ownership.** Core whitelist; only emitted by codegen for workers
that declare `<sce:critical-section>` (RFC §5.D worker primitive
extension, not in MVP — Phase C+). MVP deploys do NOT use these
symbols — every MVP shared-state access uses atomics + the inbox
ordering rules of RFC §5.I "SPSC/MPSC inbox ordering contract".

`sce_intrinsics_runtime_c` body: `__disable_irq()` / restore
PRIMASK on ARM. `sce_intrinsics_runtime_rust` body: empty function
on linux (the kernel handles preemption); platform-specific on QNX.

### §2.5 RNG — **OQ-W15 (a) initial proposal: core whitelist**

```
sce_random_fill(void *buf, size_t len) -> int
```

Returns 0 on success, nonzero on failure (e.g. entropy pool not
yet initialized). Caller is responsible for retry.

**Ownership.** **Initial proposal: core whitelist on both
variants** per OQ-W15 (a) option 1 — every supported platform has
*some* entropy source (CMSIS RNG on Cortex-M, `/dev/urandom` /
`getrandom(2)` on linux, `/dev/random` equivalent on QNX), and the
symbol shape is universal. The body differs per platform, the
contract does not.

`sce_intrinsics_runtime_c` body sketch:

| Platform | Body |
|---|---|
| STM32H7 (has HW RNG IP) | `RNG_HandleTypeDef hrng` + `HAL_RNG_GenerateRandomNumber` loop |
| Cortex-M0/M0+ without HW RNG | target-plugin-provided fallback (e.g. ADC noise sampling); failure to provide → `extern/symbol-not-in-whitelist` (per-platform requirement) |

`sce_intrinsics_runtime_rust` body: thin wrapper over `getrandom`
crate.

**Consumers in MVP.** Only **`stateless_accept` cookie HMAC key
generation** (`docs/session-fsm.md` §2.7 (c)) calls
`sce_random_fill` directly. The cookie HMAC body (§2.6 below)
calls `sce_hmac_sha256` not RNG. Phase A–C MCU deploys without
public-internet listeners do not need RNG at all.

**Why core whitelist (not target plugin).** Three reasons:
1. **Universality.** Every MCU vendor ships some entropy source.
   The symbol shape `sce_random_fill(buf, len) -> int` is the
   smallest universal contract.
2. **No SoC-specific accelerator selection.** RNG implementations
   are *bundled* with SoC HAL — there is no "STM32H7 has HW RNG /
   STM32H7 has SW RNG" choice the deploy needs to make. (HMAC, by
   contrast, *does* have such a choice — see §2.6.)
3. **Cooperative-scheduler WCET**. RNG calls inside session FSM
   `Accepting.*` cookie-key rotation must fit in
   `worker_slot_budget_us`. Bounding to a per-platform default
   (with the diagnostic
   `algorithm/wcet-bound-missing` arming if absent) is cleaner
   when the symbol is canonical.

OQ-W15 (a) ratification at next SCE sync confirms or rejects this
proposal; the document column above *is* the proposal.

### §2.6 HMAC — **OQ-W15 (a) initial proposal: target plugin**

```
sce_hmac_sha256(const uint8_t *key, size_t key_len,
                const uint8_t *msg, size_t msg_len,
                uint8_t out[32])
```

**Ownership.** **Initial proposal: target plugin on MCU, optional
target plugin on AP** per OQ-W15 (a) option 2.

Reasons HMAC is per-SoC, not core whitelist:

1. **Hardware-accelerator selection is per-SoC.** STM32H7 has
   `CRYP` IP; ESP32 has `SHA` accelerator; Cortex-M0+ has neither
   and uses software fallback. The choice is genuinely deploy-
   specific, not portable-by-construction.
2. **Software fallback authorability.** When no HW accelerator is
   available, HMAC is *also* expressible as a regular `algorithm`
   kind in SCXML (RFC §5.A bounded loops). This is OQ-W15 (a)
   option 3 as a fallback path. Authoring `sources/algorithm/
   hmac_sha256.scxml` produces wire-equivalent output to a HW-
   accelerated extern.
3. **Bounded blast radius for whitelist.** Adding a 32-byte
   crypto primitive to the core whitelist would set precedent for
   adding more crypto primitives over time (BLAKE2s, SHA-3, AES-
   GCM) — every one of which has an SoC-accelerator selection
   problem of its own. Keeping HMAC in target plugins keeps the
   core whitelist surface small and the precedent contained.

**STM32H7 worked example:**

```yaml
# configs/target_extensions_stm32h747.yaml  (excerpt)
symbols:
  - name: sce_hmac_sha256
    sig: "(*const u8, usize, *const u8, usize, *mut u8) -> ()"
    abi: c
    purpose: cookie-mac
    backed_by: stm32h7_cryp_hmac_sha256   # plugin's vendor binding
```

Software-fallback worked example (M0+ deploy):

```yaml
# configs/target_extensions_m0plus_softhmac.yaml  (excerpt)
symbols:
  - name: sce_hmac_sha256
    sig: "(*const u8, usize, *const u8, usize, *mut u8) -> ()"
    abi: c
    purpose: cookie-mac
    backed_by: sources/algorithm/hmac_sha256.scxml   # SCE-authored
                                                      # (option 3)
```

Both paths pass the `extern/symbol-not-in-whitelist` check because
the target plugin extends the whitelist; both paths pass the
`extern/abi-mismatch` check because the signature is identical.

**Consumers in MVP.** Only `stateless_accept: cookie_hmac_sha256`
on listener links with `untrusted_source: true` (per
`docs/session-fsm.md` §2.7 (c)). MCU deploys without public-
internet listeners do not need HMAC at all; for those, the target
plugin omits the `sce_hmac_sha256` row.

OQ-W15 (a) and (b) decide: ratifies the proposal above (option 2
HMAC + option 1 RNG), and pins the MCU/AP defaults for the five
fields (`session_arming_quota` / `accept_rate_per_sec` /
`accept_rate_burst` / `cookie_lifetime_ms` / `key_rotation_s`).

### §2.7 HW semaphores / mailboxes — target plugin (OQ-W14)

```
sce_hw_sem_take(uint32_t sem_id) -> bool
sce_hw_sem_release(uint32_t sem_id)
sce_hw_mbox_send(uint32_t mbox_id, const uint8_t *data, size_t len) -> bool
```

**Ownership.** Target plugin on every deploy with
`platform.core_count > 1`. RFC §5.I "Target-level extension"
documents the worked example.

Phase A–C deploys today are single-core (`core_count: 1`); these
symbols are absent from MVP deploys. They become required at Phase
C cross-core MCU bring-up.

**OQ-W14** asks whether these three symbol names are *standardized*
(every multi-core MCU plugin implements `sce_hw_sem_*`) or *ad-hoc*
(each plugin picks its own names; deploy.yaml maps them via
`cross_core_sync.symbol_map`). Initial proposal in OQ-W14:
standardize the interface, let plugins map to vendor primitives
internally. This document follows that proposal.

---

## §3 Whitelist policy and target-plugin separation

The seven categories of §2 partition into a 2×2 matrix:

| | Core whitelist | Target plugin |
|---|---|---|
| **Universal symbol shape** | atomics, fences, IRQ, RNG | (empty) |
| **Per-SoC body selection** | (empty — but see cache maintenance which is platform-class-elided) | HMAC, HW semaphores, fuzz coverage transport |

**The discipline.** A symbol joins the *core* whitelist if and only
if (i) every supported platform has a body for it, AND (ii) the
choice of body is not deploy-author-meaningful. Cache maintenance
sits awkwardly — the body is platform-class-dependent (M0/M3/M4
have no D-Cache; M7+ does; AP is no-op) — but the *choice* is
mechanical (read from `platform.has_dcache` and
`platform.has_speculative_prefetch`), not author-meaningful, so
it stays core.

A symbol becomes a *target plugin* concern if and only if the
deploy author (or a SoC vendor on their behalf) needs to pick
between bodies that are not interchangeable. HMAC's HW-accelerator-
vs-software choice is the canonical example: the wire result is
identical, but the WCET / power / silicon-area trade-offs are
genuine deploy decisions.

**Diagnostic alignment.** RFC §5.I lists the existing diagnostics:

- `extern/symbol-not-in-whitelist` — `<sce:extern>` references a
  symbol not in core whitelist *and* not provided by the deploy's
  target plugin.
- `extern/abi-mismatch` — symbol signature differs between
  whitelist declaration and `<sce:extern>` reference.
- `extern/signature-mismatch` — declared signature differs from
  symbol's actual ABI in the target_plugin.
- `extern/target-plugin-symbol-conflict` — target plugin redefines
  a core whitelist symbol (forbidden — plugins extend, do not
  override).

This document does NOT introduce new diagnostics; it specifies
which symbols partition into which side of the existing diagnostics
boundary.

---

## §4 deploy.yaml `extern_symbols` connection

The `extern_symbols:` block in `deploy.yaml` (RFC §5.K) names which
runtime crate variant + which target plugin a deploy uses:

```yaml
extern_symbols:
  lib: sce_intrinsics_runtime_c       # MCU baseline
  target_plugin: configs/target_extensions_stm32h747.yaml
```

Mapped to this document:

| Field | Effect |
|---|---|
| `lib: sce_intrinsics_runtime_c` | Phase A activates `(c11, bare_metal)` 3-tuple per RFC §5.J.3. Codegen emits `extern` declarations against the C variant of every §2 core symbol |
| `lib: sce_intrinsics_runtime_rust` | Phase D.1+ activates `(rust, linux)` (or D.2+ `(rust, qnx)`). Codegen emits Rust extern fn declarations |
| `target_plugin: configs/target_extensions_<soc>.yaml` | Plugin file declares §2.6 HMAC + §2.7 HW-sem symbols + (Phase D+) `fuzz_coverage_transport` (RFC §5.I). Plugin extends the whitelist by union with core |
| `target_plugin: ~` | No plugin — deploy uses only core whitelist symbols. Valid for AP linux baseline (no SoC accelerator binding needed) and for MCU deploys without `stateless_accept` and without `core_count > 1` |

Three concrete deploy.yaml states:

1. **`deploy/mcu_target.yaml` (line 382-383)** — `lib:
   sce_intrinsics_runtime_c` + `target_plugin:
   configs/target_extensions_stm32h747.yaml`. Activates §2.1–§2.4
   core symbols + §2.5 RNG (initial proposal: core) + §2.6 HMAC
   (target plugin) + §2.7 HW-sem (target plugin, but inactive
   because `platform.core_count: 1`).
2. **`deploy/ap_standalone.yaml` (line 281-282)** — `lib:
   sce_intrinsics_runtime_rust` + `target_plugin: ~`. Activates
   §2.1–§2.5 core; §2.3 cache maintenance bodies are no-ops on
   linux; §2.6 HMAC absent (AP linux MVP does not require it);
   §2.7 HW-sem absent (single-host).
3. **`deploy/ap_mcu_pair.yaml` (lines 119, 220)** — both blocks
   present, one per machine. AP machine matches AP standalone;
   MCU machine matches MCU target. The two machines do not share
   intrinsics — each consumes its own platform's symbols.

---

## §5 §5.J.2 statechart `no_std` HAL trait

RFC §5.J.2 introduces a small HAL trait the statechart `no_std`
runtime calls into. The trait is provided by
`sce_intrinsics_runtime` and bottoms out on the symbols of §2.

### §5.1 Trait shape (Rust)

```rust
// Pseudocode — actual trait defined in sce_intrinsics_runtime crate.
// The statechart no_std runtime takes a generic `H: StatechartHal`
// parameter; concrete H is wired by deploy.yaml `lib:` selection.
trait StatechartHal {
    /// Monotonic tick counter in microseconds. Used by Timer kind
    /// (RFC §5.D) and by session FSM lease/keepalive timers.
    /// Resolution per platform; must be monotonic.
    fn now_us(&self) -> u64;

    /// Cooperative-scheduler wake hint. Called when a timer
    /// or external event arms a transition; the runtime crate
    /// schedules the FSM tick.
    fn wake(&self);

    /// Critical section enter/leave. For workers that share state
    /// across an ISR / cooperative-tick boundary. MVP avoids this
    /// path (atomics + inbox ordering instead); §5.D Phase C+
    /// `<sce:critical-section>` emits calls here.
    fn irq_save(&self) -> IrqState;
    fn irq_restore(&self, state: IrqState);
}
```

### §5.2 Mapping to §2 symbols

| HAL method | MCU body (`sce_intrinsics_runtime_c`) | AP linux body (`sce_intrinsics_runtime_rust`) |
|---|---|---|
| `now_us` | `DWT->CYCCNT / clock_freq_mhz` (Cortex-M7 with cycle counter) or `SysTick`-based fallback (M0+/M3/M4) | `std::time::Instant::now()` since process start |
| `wake` | Cooperative scheduler queue push (`sce_worker_wake(slot_id)`) | tokio reactor wake (handled by the link runtime crate) |
| `irq_save` / `irq_restore` | `sce_irq_save` / `sce_irq_restore` (§2.4) | empty (kernel-managed) |

The trait shape itself is **MCU-class** per RFC §5.J.4 (it bottoms
out on cooperative-scheduler / cycle-counter primitives that have
no Cpp/Kotlin/Go/Python equivalent). The `(rust, *)` and `(c11,
bare_metal)` 3-tuples that consume it are exactly the 3-tuples the
statechart `no_std` variant ships on.

### §5.3 Why this trait sits in `sce_intrinsics_runtime`, not in `sce_link_runtime_*`

The HAL is *statechart*-runtime concern; the link runtime is *I/O*
concern. They are independent abstractions:

- `sce_link_runtime_lwip` consumes `sce_intrinsics_runtime_c`
  symbols on the §5.E pool lifecycle FSM edges (cache maintenance,
  atomics for ISR-to-cooperative state handoff).
- The statechart `no_std` runtime consumes `sce_intrinsics_runtime_c`
  via the HAL trait for tick / wake / IRQ.

Both consumers share one symbol surface; this doc fixes the surface;
both consumers keep `sce_intrinsics_runtime` as a single
dependency. ARCHITECTURE §4.2 "no_std collection plan cross-
reference" already names `sce_intrinsics_runtime` as the bridge
crate; this document specifies its API contents.

---

## §6 Self-review against ARCHITECTURE §2.4 invariants

| Invariant | Check |
|---|---|
| 1. Static-first, dynamic-opt-in | ✓ Every symbol declared has a static linkage; no runtime symbol resolution; HAL trait is generic over a deploy-fixed `H` |
| 2. Link drivers extensible (open set) | ✓ Indirect — this doc covers intrinsics, not link drivers. But §2.6/§2.7 target-plugin extensibility *is* the same pattern applied to non-link primitives |
| 3. Kinds are additive | ✓ The §5.J.2 HAL trait + the symbol whitelist are additive over the existing `sce_forge_runtime` baseline (which is `no_std` already, RFC §4). MVP whitelist is small; future Phase additions extend without changing the existing rows |
| 4. Generated code exports as library | ✓ `sce_intrinsics_runtime_c` ships as static library (`libsce_intrinsics_runtime_c.a`) on MCU; `sce_intrinsics_runtime_rust` ships as `rlib` on AP |
| 5. Platform gating only when necessary | ✓ §2 categories with platform-class differences (§2.3 cache maintenance, §2.4 IRQ control) are *body-elided* per `platform.has_dcache` / cooperative-scheduler mode, not symbol-elided. Symbol surface is identical across platforms; Tom Pratt's "same shape, different body" pattern preserved |
| 6. `out/` is SSoT-downstream | ✓ This doc is `docs/`, not `out/` |

---

## §7 Next-step scaffolding

This document unblocks (when Phase A SCE codegen lands the new-kind
emitters):

1. `sce_intrinsics_runtime_c` crate skeleton — initial impl of §2.1
   atomics + §2.2 fences + §2.3 cache maintenance (M7+ HAL plus
   no-op for non-D-Cache cores) + §2.5 RNG + §5.J.2 HAL trait body
   for cooperative-scheduler MCU.
2. `sce_intrinsics_runtime_rust` crate skeleton — same symbol
   surface; bodies are `core::sync::atomic` + `getrandom` + linux
   no-op cache. Ships at Phase D.1 entry.
3. `configs/target_extensions_stm32h747.yaml` Phase A skeleton
   declares §2.6 HMAC backed by `stm32h7_cryp_hmac_sha256` (HAL
   binding deferred to OQ-W15 (a) ratification) and §2.7 HW-sem
   namespace (currently inactive — deploy `core_count: 1`).

This document does NOT unblock anything during pre-Phase-A. Like
the sibling docs, the contract is design-only until codegen
exists.

**Cross-references:**

- `docs/runtime-crate-tokio.md` — AP-side link runtime; consumes
  `sce_intrinsics_runtime_rust` symbols on §5.E pool lifecycle
  edges.
- `docs/runtime-crate-lwip.md` — MCU-side link runtime; consumes
  `sce_intrinsics_runtime_c` symbols on §5.E pool lifecycle edges.
  The §2.7 ISR-side `sce_link_rx_dispatch` is the MCU
  cooperative-scheduler↔ISR handoff that uses the §2.1 atomics
  inbox-ordering contract from this document.
- `docs/session-fsm.md` §2.7 — primary consumer of §2.5 RNG and
  §2.6 HMAC (cookie generation + key rotation under
  `stateless_accept`).
- OQ-W15 — primary blocker on the §2.5 / §2.6 ownership cells of
  this document. OQ-W14 — primary blocker on §2.7 standardization.
  OQ-W23 *not* a blocker once deferred (see below).

**Note on OQ-W23 deferral.** This session ratified OQ-W23 (a) as
*deferred to Phase D* (rolling-deploy ergonomics is a Phase D+
concern, not a parity-MVP concern). passive scouting mode would
have been the second consumer of §2.5 RNG (jitter draw); deferring
it leaves §2.5 with a single MVP consumer (`stateless_accept`
cookie key generation). The §2.5 `core whitelist` proposal stands
even with one consumer — entropy is universal infrastructure.

---

## §8 Change log

- **2026-05-01 후속** — initial draft. KICKOFF #2 of this session
  ("Runtime crate API stub design"). Third of three sibling docs
  (`runtime-crate-tokio.md`, `runtime-crate-lwip.md`,
  `intrinsics-runtime-symbols.md`). Symbol surface partitioned
  into 7 categories (§2.1 atomics / §2.2 fences / §2.3 cache /
  §2.4 IRQ / §2.5 RNG / §2.6 HMAC / §2.7 HW-sem) with a
  whitelist-vs-target-plugin policy column. OQ-W15 (a) initial
  proposal locked in: §2.5 RNG → core whitelist (option 1), §2.6
  HMAC → target plugin (option 2). §5.J.2 statechart `no_std`
  HAL trait shape (`now_us` / `wake` / `irq_save` /
  `irq_restore`) mapped onto §2 symbols. ARCHITECTURE §9.5
  5-row matrix preserves "same shape, different body" — symbol
  names are identical across all five rows; bodies vary per
  platform per §2 tables. OQ-W23 deferral noted in §7 (passive
  scouting was a potential second consumer of §2.5 RNG; deferring
  it does not change the §2.5 ownership decision).
