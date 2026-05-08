# Runtime crate — `sce_link_runtime_lwip` (C11 header shape)

**Status.** Pre-implementation prose; the **MCU priority track's
direct authoring blocker** for Phase A entry. Phase A SCE codegen
(RFC §5.J.1 new-kind C11 emitter for the §5.C `link` kind, §5.E
`buffer-pool` kind, §5.M reassembly variant) emits C11 source that
`#include`s the header specified in §2 below. This document is the
C11 equivalent of `docs/runtime-crate-tokio.md` — same six-event
link contract, expressed as a C11 header instead of a Rust trait.

**Scope.** The C11 runtime crate `sce_link_runtime_lwip` (per RFC
§5.J.3 naming convention `sce_link_runtime_<os>` with `os:
bare_metal`) and the canonical header (`sce_link_runtime.h`) it
exposes. Hosts the lwIP-driver bindings (`lwip_udp`, `lwip_tcp`,
`serial_uart`, `raw_eth`) per RFC §5.C link-class enumeration.
ARCHITECTURE §9.5 row 1 (`MCU bare_metal`) is the *only* row this
document targets; rows 2–5 are covered by sibling documents.

**Inputs (normative).**
- `docs/session-fsm.md` §6 — same six inbound + three outbound
  events as the Rust side. This document expresses each as a C
  function (outbound) or as a `sce_link_event_t` enum variant
  delivered through the cooperative-scheduler poll function
  (inbound).
- `docs/reassembly-fsm.md` §6 — pool ownership FSM `free →
  cpu-mut → dma-armed-rx → dma-busy-rx → cpu-ref → free`. The ISR
  `rx_dispatch` path hands a slot ownership token from MCU-mutated
  state to the network FSM. The header surfaces an opaque slot
  handle but **never** exposes raw `cache_clean`/`cache_invalidate`
  calls — those are pinned to RFC §5.E lifecycle FSM edges and
  emitted by codegen, not author code; `pool/cache-maintenance-
  misplaced` enforces this.
- [`docs/scouting-fsm.md`: Scouting link vs session link](scouting-fsm.md#13-scouting-link-vs-session-link--distinct-instances) — `trust_class: untrusted` flagged
  scouting links never expose the `Accepting.*` allocator nor the
  reassembly slot-handover function in the header. The C type is
  *compile-time absent* on those link instances (codegen elides
  the offending function declarations from the per-link header
  variant — see §4 below).
- RFC §5.C link kind, §5.J.3 (`sce_link_runtime_lwip` for `os:
  bare_metal`), §5.J.4 (`(c11, bare_metal)` is required cell for
  §5.C kind), §5.E pool ownership FSM, §5.I cache maintenance
  intrinsics (the lwIP runtime *calls* them, the SCXML author does
  not).
- ARCHITECTURE §9.5 row 1 (`MCU bare_metal`, current Phase A–C
  scope) and §3.4 (cache coherency invariants pinning).
- `deploy/mcu_target.yaml` `extern_symbols.lib:
  sce_intrinsics_runtime_c` (line 382) and `target_plugin:
  configs/target_extensions_stm32h747.yaml` (line 383). The lwIP
  runtime crate is the consumer of those intrinsics on the link
  edge actions.

**Outputs.** (1) A C11 header `sce_link_runtime.h` declaring: the
opaque `sce_link_t` lifecycle, the `sce_link_event_t` enum, the
RX dispatch entry the ISR-or-worker path calls, and an opaque
`sce_pool_slot_handle_t` used on the §5.E lifecycle ownership-
inheritance edge. (2) A deploy.yaml `links.<name>.driver` value
mapping (`lwip_udp`, `lwip_tcp`, `serial_uart`, `raw_eth`). (3)
Compile-time elision rules tying the header to per-link
`trust_class` (presence/absence of specific function declarations
per link instance).

**Non-outputs.** Header source (codegen target — codegen emits the
.h alongside the .c). Rust binding (sibling doc
`runtime-crate-tokio.md`). Per-driver lwIP integration code
(belongs in the runtime crate's .c implementation files, not in
this prose contract). SCXML authoring against the header — blocked
on Phase A.

---

## §2 C11 header shape

### §2.1 Opaque lifecycle handle

The `sce_link_t` type is opaque to author code. Codegen emits a
sized typedef inside the per-deploy `sce_link_runtime.h`; the
`sce_link_runtime_lwip` crate provides storage. Each `<sce:link>`
SCXML declaration becomes one statically allocated `sce_link_t`
instance in `.bss` per `deploy.machines.<m>.links.<name>` entry.

```c
/* Pseudocode — actual C11 emitted by codegen at Phase A landing.
   This document fixes the shape; codegen generates the concrete
   header per deploy. */

/* Opaque link handle. One static instance per deploy.yaml link.
   Lives in .bss; storage class set by codegen based on
   memory.sram_regions placement. */
typedef struct sce_link_s sce_link_t;

/* Driver enum — the deploy.yaml `links.<name>.driver` value. */
typedef enum {
    SCE_LINK_DRIVER_LWIP_UDP    = 1,
    SCE_LINK_DRIVER_LWIP_TCP    = 2,
    SCE_LINK_DRIVER_SERIAL_UART = 3,
    SCE_LINK_DRIVER_RAW_ETH     = 4,
} sce_link_driver_t;
```

### §2.2 The six-event enum

The six inbound events from `docs/session-fsm.md` §6 lift to enum
variants 1:1, plus a synthetic `OPEN_FAILED` for the outbound
`open()` resolution (mirrors the Rust `LinkEvent::Lost` /
`LinkEvent::Ready` split):

```c
typedef enum {
    /* session-fsm §6 link.ready */
    SCE_LINK_EVENT_READY = 1,
    /* session-fsm §6 link.lost(cause) — the cause discriminator
       lives in a sibling field of the event struct (§2.3). */
    SCE_LINK_EVENT_LOST = 2,
    /* session-fsm §6 link.rx(bytes) — payload is a pool-slot
       handle (§2.4), NOT a raw byte pointer. */
    SCE_LINK_EVENT_RX = 3,
    /* session-fsm §6 link.tx_drained */
    SCE_LINK_EVENT_TX_DRAINED = 4,
    /* session-fsm §6 link.backpressure(on|off) — on/off in
       sibling field. */
    SCE_LINK_EVENT_BACKPRESSURE = 5,
    /* session-fsm §6 link.framing_error */
    SCE_LINK_EVENT_FRAMING_ERROR = 6,
} sce_link_event_kind_t;

typedef enum {
    SCE_LINK_LOST_PEER_CLOSED  = 1,
    SCE_LINK_LOST_TIMEOUT      = 2,
    SCE_LINK_LOST_LINK_FAILURE = 3,  /* PHY down, USB unplug, ... */
} sce_link_lost_cause_t;
```

### §2.3 Event struct (tagged union)

```c
typedef struct {
    sce_link_event_kind_t kind;
    union {
        struct { sce_link_lost_cause_t cause; }   lost;
        struct { sce_pool_slot_handle_t slot; }   rx;
        struct { uint8_t on; /* 0 = off, 1 = on */ } backpressure;
        struct { uint8_t detail_code; }            framing_error;
        /* READY, TX_DRAINED carry no payload. */
    } as;
} sce_link_event_t;
```

`sce_link_event_t` is sized at codegen time and stays under 16
bytes on all supported targets (smallest pool-slot handle is 4
bytes on a 4-slot pool). `_Static_assert` guards the size invariant
in the emitted header.

### §2.4 Pool slot handle (the `cpu-mut → cpu-ref` edge)

Per `docs/reassembly-fsm.md` §6 mapping table, the RX path
transitions a pool slot through the §5.E lifecycle FSM. The header
exposes the slot as an opaque handle:

```c
/* Opaque pool slot handle. Codegen emits the concrete struct in
   the per-deploy header; runtime crate sees only the typedef. */
typedef struct sce_pool_slot_s *sce_pool_slot_handle_t;

/* Caller (network FSM) reads the slot's bytes via this borrow.
   Lifetime: until the caller invokes `sce_pool_slot_release(slot)`.
   While the borrow is live, the §5.E lifecycle FSM holds the slot
   in `cpu-ref` state. */
const uint8_t *sce_pool_slot_borrow(sce_pool_slot_handle_t slot,
                                    size_t *len_out);

/* Stage-copy primitive (§5.E `sce_sample_take` C analog). Copies
   slot bytes to `dst` (caller-owned), then releases the slot.
   Lifecycle: slot transitions `cpu-ref → free`. */
size_t sce_pool_slot_take(sce_pool_slot_handle_t slot,
                          uint8_t *dst, size_t dst_cap);

/* Caller must call exactly one of borrow+release or take. The
   §5.E Layer 1 typestate annotations (RFC §5.E "C section",
   `consumable` + `callable_when` + `set_typestate`) emit on the
   sce_pool_slot_handle_t parameter so Clang `-Wconsumed`
   catches use-after-take and double-take at compile time. */
void sce_pool_slot_release(sce_pool_slot_handle_t slot);
```

The §5.E typestate annotations are *generated* by codegen onto the
parameter declarations above. Author code that calls these functions
in the wrong order (`take` then `borrow`, etc.) fails to compile
under Clang `-Wconsumed -Wthread-safety` per RFC §5.E "GCC
ecosystem fallback (Clang-Tidy mandatory)". This is the C11
counterpart of the Rust `Sample<'pool>` borrow checker enforcement
in `runtime-crate-tokio.md` §2.3.

### §2.5 The three outbound functions

Mirror of the Rust trait methods (sibling doc §2.1):

```c
/* Outbound (initiator) open. Async via cooperative scheduler — the
   call returns immediately; resolution arrives as
   SCE_LINK_EVENT_READY or SCE_LINK_EVENT_LOST through
   sce_link_poll_event(). Returns 0 on accepted (open in flight),
   nonzero on synchronous reject (e.g. invalid endpoint). */
int sce_link_open(sce_link_t *link, const sce_endpoint_t *endpoint);

/* Async send. Reliability hint forwarded to driver per session-fsm
   §6 outbound table. Returns 0 on accepted (TX in flight),
   nonzero on synchronous reject (queue full / link not ready). */
int sce_link_send(sce_link_t *link, const sce_tx_frame_t *frame,
                  sce_reliability_t reliability);

/* Cooperative close. Caller is the session FSM `Closing` state;
   the driver flushes any pending TX, then closes the link. After
   close, sce_link_poll_event() will eventually deliver
   SCE_LINK_EVENT_LOST{cause=PEER_CLOSED} (or LINK_FAILURE on
   error). Idempotent. */
int sce_link_close(sce_link_t *link);
```

### §2.6 The poll function (cooperative-scheduler hook)

Inbound events are delivered via a single poll function the
cooperative scheduler calls per tick:

```c
/* Drains at most one event from the link's internal queue. Returns
   1 if `*event_out` was populated, 0 if the queue is empty. The
   queue itself is bounded (capacity = deploy.yaml
   `links.<name>.event_queue_depth`, default 8) and lives inside
   the sce_link_t.

   Cooperative scheduler invariant: this function MUST return
   within the per-link `worker_slot_budget_us` ceiling. The
   per-event work bounds are documented in §5.E per pool transition
   plus the framer's static WCET aggregate (§5.B). */
int sce_link_poll_event(sce_link_t *link, sce_link_event_t *event_out);
```

The function is called from the cooperative-scheduler tick path,
not from ISR context. The ISR side fills the queue (`rx_dispatch:
isr_to_pool` branch per RFC §5.K) without driving FSM transitions
directly. This separation matches RFC §5.E "Burst absorption
analysis (RX pools)" — the ISR's only job is to hand a filled pool
slot to the link's event queue and re-arm the next slot.

### §2.7 ISR-side entry (RX dispatch)

The lwIP runtime crate provides one ISR-callable function per
driver. This function is the `cpu-mut → dma-armed-rx` /
`dma-busy-rx → cpu-ref` edge mover. Author code never calls it
directly; codegen wires it from the link's deploy.yaml
`rx_dispatch: isr_to_pool` setting.

```c
/* ISR entry — called from the lwIP RX-complete callback (or USB
   ISR for serial_uart, etc.). Pulls a fresh pool slot from the
   link's RX pool, copies the freshly received bytes (or transfers
   ownership in zero-copy mode), advances the §5.E lifecycle FSM,
   and enqueues SCE_LINK_EVENT_RX into the link's event queue.

   The cache_invalidate call on the `free → cpu-mut` (or `cpu-mut
   → dma-armed-rx`) edge per ARCHITECTURE §3.4 (M7+ speculative
   prefetch) is emitted *inside* this function by codegen — author
   code does not see it. Symmetric `cache_clean` on the TX side is
   inside `sce_link_send`. */
void sce_link_rx_dispatch(sce_link_t *link,
                          const uint8_t *rx_bytes, size_t len);
```

The function is defined in the lwIP runtime crate and *called* by
the lwIP receive callback. Author code does not author callbacks;
codegen wires the lwIP `udp_recv` / `tcp_recv` callbacks to
`sce_link_rx_dispatch` at startup (per `lwip_udp_init` /
`lwip_tcp_init` codegen).

---

## §3 deploy.yaml `links.<name>.driver` mapping

Four driver values for the bare_metal lwIP runtime:

| `driver` value | lwIP API | Pool backing | Phase availability |
|---|---|---|---|
| `lwip_udp` | `udp_*` API | static `__attribute__((aligned))` array in linker section | A (current MCU baseline) |
| `lwip_tcp` | `tcp_*` API | same | B (MCU TCP authoring) |
| `serial_uart` | vendor UART driver via `target_plugin` | same | C (MCU serial) |
| `raw_eth` | lwIP raw L2 via `target_plugin` | same | C+ (MCU raw eth, plugin-provided) |

`deploy/mcu_target.yaml` declares `lwip_udp` for both scouting
(line 96) and session (line 112) UDP links. Lines 172
(`lwip_tcp`) and 186 (`serial_uart`) are the disabled-by-default
TCP and serial driver entries.

The `raw_eth` driver is target-plugin provided per RFC §5.I (raw
ethernet access requires vendor-specific MAC driver hookup — STM32
ETH HAL, ESP32 EMAC, etc.). The header signature is identical;
the driver impl ships in the plugin.

---

## §4 Trust-class header surface (compile-time elision)

Per [`docs/scouting-fsm.md`: Scouting link vs session link](scouting-fsm.md#13-scouting-link-vs-session-link--distinct-instances) + [`docs/session-fsm.md`: Trust-class interaction](session-fsm.md#26-trust-class-interaction-cross-ref-to-5m) +
[`docs/reassembly-fsm.md`: Trust-class interaction](reassembly-fsm.md#5-trust-class-interaction-cross-ref-rfc-5m), three trust classes gate which trait
methods are present per link instance. Codegen emits a per-link
header variant; absent methods are *not declared* at all (rather
than declared-and-stubbed), so author code calling an absent
method fails compilation with `error: implicit declaration of
function 'sce_link_bind_reassembly_pool'` rather than passing
compilation and failing at runtime.

| trust_class | Header surface present | Compile-time absent |
|---|---|---|
| `untrusted` | `sce_link_open` / `sce_link_send` / `sce_link_close` / `sce_link_poll_event` (the four core functions of §2) | accept-side hardening hooks; reassembly pool binding |
| `session_arming` | adds `sce_link_arm_accept_caps(quota, rate, burst, table_capacity)` for the §2.7 anti-flood configuration; if `stateless_accept: cookie_hmac_sha256` set, also `sce_link_arm_stateless_accept(hmac_key_handle, lifetime_ms)` | reassembly pool binding |
| `established_session` | adds `sce_link_bind_reassembly_pool(pool_handle)` per [`reassembly-fsm.md`: Trust-class interaction](reassembly-fsm.md#5-trust-class-interaction-cross-ref-rfc-5m) | accept-side hardening hooks (post-handshake links never accept) |

Codegen rejects any cross-binding (e.g. SCXML referencing
`sce_link_bind_reassembly_pool` on an `untrusted` link) with the
existing diagnostics:

- `reassembly/untrusted-link-binding` (hard error) — `untrusted` +
  reassembly bind attempt.
- `reassembly/trust-class-missing-on-fragmenting-link` (hard
  error) — fragmenting link without `established_session`.
- `link/link-class-incompatible-with-trust-class` family (under
  `link/link-class-unknown` parent diagnostic) for malformed
  cross-bindings.

The mechanical defense composes with RFC §5.M's runtime ZID-vs-
source-address discriminator: the build-time elision blocks the
*static* misuse; the runtime classifier (per session FSM
`Established` state's chain key derivation) blocks the *dynamic*
misuse.

**Listener-link two-instance emission (OQ-W22 resolution).** A
deploy.yaml listener entry whose `domain_attrs.trust_class:
session_arming` emits **two** rows of the table above, not one:
the `session_arming` row (carrying `sce_link_arm_accept_caps` and
optionally `sce_link_arm_stateless_accept`) plus a synthesized
`established_session` row (carrying
`sce_link_bind_reassembly_pool`). The two header variants share
a `bind` / `driver` / pool of underlying RX descriptor ring and
TX socket but expose **separate `sce_link_t*` opaque handles** —
codegen emits two `sce_link_t` storage instances, two
`sce_link_open` invocations from generated `main`, and a
peer-state-driven RX dispatch in the runtime crate that routes
each inbound buffer to the correct handle's event queue. Authors
of `sources/*.scxml` reference the listener once
(`<sce:link>udp_session</sce:link>`); reassembly-pool bindings
authored against that name resolve to the
`established_session` sibling at codegen time.

The compile-time elision discipline holds per instance: the
`session_arming` header variant has no
`sce_link_bind_reassembly_pool`; the `established_session`
sibling has no `sce_link_arm_accept_caps`. The
`reassembly/binding-on-unpaired-listener` and
`link/listener-link-not-paired-with-established-sibling`
diagnostics (RFC §5.M / §5.C) catch any codegen template
regression that would emit one variant without the other. See
[`docs/session-fsm.md`: Trust-class interaction](session-fsm.md#26-trust-class-interaction-cross-ref-to-5m) ("Listener-link logical split") and
RFC §5.C "Listener-link sibling emission" for the codegen
mechanics.

---

## §5 Self-review against ARCHITECTURE §2.4 invariants

| Invariant | Check |
|---|---|
| 1. Static-first, dynamic-opt-in | ✓ `sce_link_t` instances are static (one per deploy.yaml link); event queue is bounded (`event_queue_depth`); no malloc in any function declared in §2 |
| 2. Link drivers extensible (open set) | ✓ Driver enum is an *enum*, not a closed list — `target_plugin` adds new driver values (e.g. `raw_eth` Phase C+, hypothetical future `nrf_radio` Phase D+ plugin). Codegen picks the impl by deploy.yaml, header signature is driver-agnostic |
| 3. Kinds are additive | ✓ This document does not introduce a new kind — it specifies the runtime crate that hosts the existing `link` kind on `os: bare_metal`. The header functions are 1:1 with `docs/session-fsm.md` §6 events; no new event categories |
| 4. Generated code exports as library | ✓ `sce_link_runtime_lwip` is a static library (`libsce_link_runtime_lwip.a` in MCU build); the per-deploy header is generated alongside generated `.c` source from SCXML; no main loop |
| 5. Platform gating only when necessary | ✓ The header *itself* is platform-gated to `(c11, bare_metal)` per RFC §5.J.4 MCU-class matrix. Within `bare_metal`, the per-driver branches are deploy-attribute-gated, not platform-class-gated. M0/M0+/M3/M4 vs M7+ differences (cache invalidate edges) live in `sce_intrinsics_runtime_c` (sibling doc §2 cache-maintenance row), not in this header |
| 6. `out/` is SSoT-downstream | ✓ This document is `docs/`, not `out/` — the `sce_link_runtime.h` it specifies is generated, not authored |

---

## §6 Next-step scaffolding

This document unblocks (when Phase A SCE codegen lands the §5.J.1
new-kind C11 emitter):

1. `sce_link_runtime_lwip` crate skeleton authoring against the §2
   header shape. Initial impls: `lwip_udp` + `lwip_tcp` (Phase A/B
   scope per RFC §7).
2. Per-deploy `sce_link_runtime.h` generation by codegen — the
   typedefs and function declarations of §2 emitted with concrete
   sizes from `deploy.yaml`.
3. `serial_uart` and `raw_eth` driver impls land in target plugins
   per `deploy/mcu_target.yaml:383` (`target_plugin:
   configs/target_extensions_stm32h747.yaml`); the plugin file
   declares the driver-specific symbols and the MAC/UART HAL
   binding.

This document does NOT unblock anything during pre-Phase-A — the
header is design-only until the C11 emitter exists. However it is
the **direct authoring blocker** for Phase A entry: once the
emitter ships, this contract is the artifact codegen aims at.

**Cross-references for sibling work:**

- `docs/runtime-crate-tokio.md` — the `(rust, linux,
  sce_link_runtime_tokio)` analog. Same 6-event contract, expressed
  as a Rust trait. The two docs are intentionally structured 1:1
  to make the cross-language portability invariant of ARCHITECTURE
  §9.5 visible.
- `docs/intrinsics-runtime-symbols.md` — the
  `sce_intrinsics_runtime_c` companion. Provides the cache
  maintenance / atomics / IRQ symbols the lwIP runtime uses on
  the §5.E pool lifecycle FSM edges. The header shape here
  *consumes* those symbols inside the runtime crate `.c` files,
  but does *not* re-export them to author code.

---

## §7 Change log

- **2026-05-01 후속** — initial draft. KICKOFF #2 of this session
  ("Runtime crate API stub design"). Direct C11 sibling of
  `runtime-crate-tokio.md`. Header shape locked to four
  outbound functions + `sce_link_event_t` 6-variant enum +
  `sce_link_poll_event` cooperative-scheduler hook +
  `sce_link_rx_dispatch` ISR entry, plus opaque
  `sce_pool_slot_handle_t` for the §5.E lifecycle ownership-
  inheritance edge. Trust-class compile-time elision documented
  (untrusted / session_arming / established_session) — absent
  methods are *not declared* (rather than declared-and-stubbed)
  so violations fail compile rather than runtime. RFC §5.E
  Layer 1 typestate annotations (`consumable` / `callable_when` /
  `set_typestate`) propagate onto `sce_pool_slot_handle_t`
  parameters; Clang `-Wconsumed` enforces use-after-take /
  double-take at compile time. ARCHITECTURE §9.5 row 1
  (`MCU bare_metal`) is the document's only target row — Phase
  A–C scope.
