# ARCHITECTURE — watching-zenoh

**Status:** Pre-implementation design document (2026-04-24).

The project is blocked on SCE Phase A (see
`docs/rfc-sce-protocol-synthesis.md`). This document records the
planned architecture so that decisions made while waiting stay
consistent, and so the scope contract with SCE maintainers is legible.

When SCE Phase A lands and authoring begins, this file becomes the
living architecture reference and is updated in lockstep with code.

---

## 1. Vision

Synthesize a **Zenoh-protocol-compatible networking stack** from
SCXML + SCE Forge as the single source of truth. One authored source
set produces two interoperable artifacts:

- **AP backend** — Rust, `std`, tokio runtime, Linux x86_64 / aarch64
- **MCU backend** — C11, no_std-equivalent, no heap. Target
  architecture and SoC are TBD; selection is deferred until deploy
  authoring begins. Any target that offers a C11 toolchain, static
  SRAM placement via linker sections, and a DMA-capable network
  peripheral is a candidate.

Both backends interoperate on the wire with upstream `zenohd` for the
subset documented in §2.

The project is not a rewrite of zenoh/zenoh-pico. It is a
**demonstration that SCE can synthesize industrial wire protocols**,
with Zenoh as the first concrete target.

---

## 2. Scope

### 2.0 Long-term vision and MVP criterion

The long-term goal is that **every Zenoh feature eventually migrates
into this synthesis framework**. Nothing in the design should close
the door on a future feature. "Out of scope" is therefore split into
two distinct categories with fundamentally different meanings:

- **Deferred** (§2.2) — not in MVP, but structurally supportable; each
  deferred item has a documented migration path.
- **Permanent architectural constraint** (§2.3) — ruled out by the
  physical constraints of the target class (MCU class: no heap, no
  unbounded state, no dynamic loading), not by design preference.
  These are the only genuinely out-of-scope items.

**MVP criterion:** the peer + client backends produced by this project
MUST achieve **at least full zenoh-pico feature parity** on their
target class. That is, anything zenoh-pico does in peer or client
mode, this project does equivalently — with SCE synthesis replacing
the hand-written C. MCU backend is a zenoh-pico replacement; AP
backend is a peer/client-mode zenoh replacement. Both share one
SCXML source set.

### 2.1 MVP scope (zenoh-pico parity target)

| Area | Included |
|---|---|
| Protocol modes | Peer + client (bidirectional pub-sub, query/reply, declare/undeclare) |
| Protocol version | Zenoh 1.x (exact minor pinned at Phase-A freeze) |
| Message set | Full peer/client message set (every message a zenoh-pico peer or client emits or consumes — scout, hello, session INIT/OPEN/CLOSE, keepalive, put, del, declare sub/queryable/token, query, reply, ack/nack, fragment frames) |
| Transports | TCP, UDP unicast, UDP multicast, Serial, WebSocket. BLE / Raweth provided via target-plugin link drivers (§5.I of RFC), not baked into core |
| QoS dimensions | priority, reliability, express, congestion control |
| KeyExpr matching | Runtime wildcard matching over a **bounded** declared-subscription table (capacity declared in `deploy.yaml`, enforced at build time). The table is a new `bounded-collection` kind — not a heap-allocated dynamic structure |
| Subscription lifecycle | Runtime `declare_subscriber` / `undeclare_subscriber` within the bounded capacity |
| Fragmentation | TX fragmentation per QoS profile; RX reassembly through a declared `reassembly-pool`. First-class, not a diagnostic-only fallback |
| Message metadata | Attachments, timestamps, encoding info, liveliness tokens |
| Interop | Upstream `zenohd` as router, upstream `zenoh-pico` nodes as peers, mixed watching-zenoh + upstream deployments |
| Targets | Linux AP (Rust/std/tokio), MCU (C11/no_std; architecture and SoC TBD) |
| Zero-copy | TX encode: always. RX single-frame bounded payload: always. RX fragmented: through declared reassembly pool (one copy at frame-to-pool boundary, then in-place parse). |

This scope is **larger** than an earlier draft's "subset" framing; the
subset framing was insufficient because it would have made MCU output
less capable than zenoh-pico, failing the MVP criterion above.

### 2.2 Deferred (MVP non-goals with migration paths)

These are **not permanently excluded** — they are Phase D+ work items.
Every entry has a migration path so the current design does not lock
them out.

| Area | MVP reason | Migration path |
|---|---|---|
| Router mode (`zenohd` replacement) on AP | Requires unbounded dynamic topology state; significant new kinds (graph algorithm, dynamic aggregation); not required for zenoh-pico parity | Phase D+. Needs recursive/tree types (§5.H), bounded-collection generalization, and a new `graph-algorithm` kind. Uses the same synthesized session/codec/link machinery as a dependency |
| Subscription aggregation across network | Router-mode feature | Same path as router |
| BLE transport | Platform-specific HAL; deploy via target plugin when target is chosen | Already enabled by §5.I target plugin mechanism; add plugin file when first BLE target chosen |
| Raweth transport | Same | Same |
| `zenoh-c` / `zenoh-pico` API compatibility shim | Wire compat first, API shim is a thin runtime layer on top | Add `runtime/sce_zenoh_api_shim/` crate that calls into synthesized library. Wire parity achieved first, API shim is mechanical follow-up |
| Shared-memory transport | Advanced; not in zenoh-pico baseline | Phase E. Needs a new `shared-mem-pool` kind variant |
| Admin space / plugin ecosystem | AP-only runtime services; not in zenoh-pico baseline | Synthesized AP code ships as a Cargo library crate; admin/plugins are applications on top, not SCE-synthesized |
| Script engines on AP | Not in zenoh-pico baseline; orthogonal | Host-side integration, not SCE synthesis scope |

### 2.3 Permanent architectural constraints

These are ruled out by physical constraints of the MCU target class,
not by design preference. They do not migrate.

| Constraint | Reason |
|---|---|
| Router mode on MCU | Global topology state is unbounded across the network; forwarding tables require heap; scheduling requires unbounded queues. None of these fit no-heap / bounded-state requirements |
| Subscription aggregation on MCU | Same — aggregation state is unbounded across N peers |
| Dynamic heap allocation on MCU | No-heap invariant; all state must be statically placed or bounded-dynamic via declared collections |
| Script engines on MCU | `sce_scripting` forbidden when `platform.class = mcu`; runtime script execution requires unbounded interpreter state |
| Runtime-unbounded wildcard KeyExpr on MCU | MCU can match wildcards over the bounded declared-subscription table (§2.1), but cannot index a router-scale global keyspace. The bounded form IS supported on MCU; only unbounded aggregation is ruled out |
| Dynamic code loading on MCU | No filesystem, no loader; all code is statically linked |

**Note.** These constraints are **MCU-class only**. AP is a general-
purpose machine and has none of these limitations; AP can eventually
do everything upstream zenoh does.

### 2.4 Extensibility design invariants

To preserve the long-term vision (§2.0), the current design MUST
honor the following invariants. Violating any of these makes future
migration harder or impossible.

1. **Static-first, dynamic-opt-in** — not "static-only". A feature
   that is static on MCU SHOULD have an AP variant that can be made
   dynamic. Example: compile-time KeyExpr table (§5.F) is one
   option; runtime wildcard matching over bounded-collection is
   another; both are supported.

   **KeyExpr matching policy guidance.** The dual support above is
   not abstract; both backends pick concretely:

   - **Runtime bounded-collection (MVP baseline):** required because
     zenoh-pico parity (§2.1) assumes runtime
     `declare_subscriber`/`undeclare_subscriber`. Backed by RFC §5.L
     bounded-collection + an §5.A algorithm with `mode="measured"`
     WCET annotation against the declared capacity (RFC §5.A
     canonical case). This is the default path on both AP and MCU.
   - **Build-time static trie:** opt-in for deployments whose
     subscription set is fixed in `deploy.yaml`. Flat-array
     representation is buildable with §5.F today (`.flash`-placed
     `const` array, read-only access, zero RAM cost); the recursive
     node form awaits RFC §5.H (Phase 2).
   - **Hybrid:** static trie tried first, fall through to
     bounded-collection on miss. Useful when permanent system /
     diagnostic topics are deploy-pinned but user-declared subs
     vary at runtime.

   The choice is per-machine in `deploy.yaml`; a machine that opts
   into static trie still keeps the runtime path available unless
   the subscription set is empty. See RFC §5.F worked-example
   table for the decision matrix.
2. **Link drivers are extensible** — open set via target plugin,
   not closed enum. Downstream targets (new transports, new radios)
   add drivers without patching SCE core.
3. **Kinds are additive** — SCE's `ForgeKind` set grows over time;
   existing kinds are stable. New kinds (graph algorithm, dynamic
   lookup, reassembly pool) land without breaking existing ones.
4. **Generated code exports as library, not as monolith** —
   `out/ap/` and `out/mcu/` are library targets (Cargo library
   crate / static archive + header); applications and plugins
   consume them, preserving the path to router mode and plugin
   ecosystem on AP later.
5. **Platform gating only when necessary** — a feature should not
   be gated on `platform.class = mcu` unless there is a real
   physical reason. Keep pool/link/worker kinds platform-neutral;
   use individual attributes (e.g. `cache-policy`) for platform
   specialization.
6. **`out/` is SSoT-downstream** — manual edits are forbidden
   (§11.5). This stays true as features grow; new features land
   via SCE extensions, not post-generation patches.

### 2.5 Protocol version pinning

Zenoh 1.x wire format is the target. Extension chains in the wire
format allow additive evolution within 1.x without breaking 1.x
peers; upstream breaking changes (2.x hypothetically) are a separate
scope decision.

Pinning is enforced by `deploy.yaml`:

```yaml
protocol:
  family: zenoh
  wire_version: "1.x"    # declares interop contract
  extensions_accepted: [keepalive, qos_priority, attachments, timestamps]
  extensions_ignored: [compression]   # decoded but discarded
```

---

## 3. Design Invariants

The four invariants from the project charter. Every design decision
below is checkable against these.

### 3.1 Zero-Runtime Abstraction

No vtables, no runtime transport dispatch, no dynamic polymorphism in
the hot path. All binding decisions resolve at build time, emitted as
direct function calls and switch/case. SCE's AOT philosophy carried
through.

### 3.2 Location Transparency

SCXML sources reference logical identities (`#peer_motor`,
`#topic_temperature`). Physical transport realization
(UDP/TCP/serial) and addressing live in `deploy.yaml`. Same SCXML
deploys to AP or MCU by changing only the deploy file.

### 3.3 Strict SSoT

Wire format (codec), algorithms (CRC, VLE, KeyExpr matching), and
state machines (session FSM) are defined **once** in SCXML+Forge.
AP and MCU backends are descendants. Cross-backend drift is a bug in
the generator, not an expected condition.

Exceptions are bounded:
- `sce:extern` (RFC §5.I) for hardware intrinsics and atomic ops,
  whitelisted in `sce_intrinsics_runtime`.
- No other escape hatches.

### 3.4 Hardware-Aware Codegen

MCU code integrates with the target SoC's capabilities:
- SRAM section placement for pool slots (section names — e.g.
  `.dtcm`, `.sram1` — are target-specific and declared in
  deploy.yaml, not baked into the architecture)
- DMA descriptor pairing with pool slots (zero-copy TX/RX)
- Alignment requirements honored at build time, bidirectional:
  codec field alignment ≤ pool alignment, and DMA burst alignment
  requirements propagate back into codec field layout (automatic
  padding with compile-time `_Static_assert` checks; RFC §5.B).
  These constraints describe **wire-format field offsets** — the
  byte layout that both AP and MCU emit and parse — not host
  buffer allocation. AP and MCU share no memory; they communicate
  over the wire (§8.4). On AP, decoded bytes live in
  `bytes::BytesMut` and the AP allocator is **not required** to
  honor `dma-burst-align`: the codec's own padding satisfies the
  field-offset invariant. On MCU the same offsets additionally
  land inside a DMA-coherent pool slot whose base is aligned at
  link time (§5.E + §6.2 linker fragment).
- Cache coherency handled explicitly per pool via `cache-policy`
  (RFC §5.E): `maintain` emits `cache_clean`/`invalidate` calls
  around DMA boundaries using `sce_intrinsics_runtime` symbols;
  `non-cacheable` places the pool in an MPU-declared non-cacheable
  region; `none` is used on cores without a D-cache. The choice is
  validated against the target descriptor (`platform.has_dcache`,
  `dcache_line_size`) so misconfiguration fails at build time rather
  than silently corrupting data at runtime. Under `maintain`, three
  cache-line invariants are mechanically enforced: pool start aligned
  to a cache line (`mem/cache-line-alignment`), every slot sized in
  whole cache lines (`mem/slot-size-not-cache-line-multiple`), AND
  adjacent pool sections separated by an explicit
  `. = ALIGN(<line_size>);` sentinel in the linker fragment
  (`mem/inter-pool-padding-not-emitted`). The middle invariant
  prevents the partial-line `cache_invalidate` from corrupting an
  adjacent slot's bytes that share the boundary line; the third
  prevents the same corruption between *different pools* in the
  same memory region when a master linker script splices content
  between them. The maintenance call
  sites are pinned to specific edges of the pool slot lifecycle FSM
  (RFC §5.E "Slot lifecycle FSM"): `cache_clean` on
  `cpu-mut → dma-armed-tx`, `cache_invalidate` on
  `dma-busy-rx → cpu-ref`. Author code cannot place these calls
  manually; misuse is rejected as `pool/cache-maintenance-misplaced`.

  These invariants address **line-level cross-contamination during
  cache maintenance by VA**, not cache **set associativity
  contention**. Set contention (e.g. a high-priority RX pool and a
  low-priority log pool sharing the same N-way set, where heavy RX
  evicts log entries) is a separate problem with a separate answer:
  split the pools across `cache-policy: maintain` and `non-cacheable`
  regions, or place them in distinct memory banks via
  `memory.sram_regions`. Padding sentinels are line-level only; they
  do nothing for set contention and the docs don't pretend otherwise.
- Pool slot ownership transitions (free → cpu-mut → dma-armed-tx
  → dma-busy-tx → free, and the symmetric RX path) are tracked at
  IR build time as a borrow-check-style FSM, so a CPU write to a
  slot that DMA is currently reading, or a `pool_return` on an
  armed slot, is rejected before either backend's compiler runs
  (RFC §5.E `pool/ownership-violation`).
- Memory ordering across workers uses the intrinsics whitelist's
  acquire/release/seq_cst variants (RFC §5.I); inbox producer-
  consumer pairs are checked for sufficient ordering when the
  deploy descriptor declares `core_count > 1`.
- Cross-core synchronization beyond plain atomics — hardware
  semaphore units such as STM32H7 HSEM, ESP32 cross-core spinlock,
  or vendor-specific mailbox IP — is registered through the §5.I
  `target_plugin`, which extends `sce_intrinsics_runtime`'s
  whitelist with target-specific symbols (e.g. `sce_hw_sem_take`,
  `sce_hw_sem_release`). The mechanism is open-set and platform-
  neutral (§2.4 invariants 2 and 5); deploy.yaml declares which
  primitive a given inbox or shared resource uses, and codegen
  picks the matching extern.
- Cooperative scheduler timing budget: each worker slot honors a
  Worst-Case Execution Time (WCET) ceiling declared in
  `deploy.yaml` (`scheduler.worker_slot_budget_us`). The build
  refuses to emit an algorithm or procedure whose static WCET
  estimate (or registered measured value) exceeds the budget, so
  heavy paths — runtime KeyExpr matching over a large bounded-
  collection, fragment reassembly across many slots, CRC over a
  full pool slot — cannot starve Keepalive or other parallel-
  region timers (§8.2 `Established`). RFC §5.A formalizes the
  WCET annotation; RFC §5.K names the diagnostics.

AP code is conventional (bytes::BytesMut, tokio tasks). Hardware
awareness is MCU-specific and gated by `platform.class = mcu`.

---

## 4. Relationship to SCE

This project sits **on top of** SCE. It authors sources, invokes
SCE's codegen, links against SCE's runtime libraries, and adds its
own thin runtime crates for link drivers and intrinsics.

### 4.1 SCE provides (existing)

Verified against `/home/coin/scxml-core-engine/` on 2026-04-24.

- SCXML parser, IR, W3C algorithms
- Expression transpiler (bitwise ops, arithmetic, comparisons —
  already complete)
- **Eleven Forge kinds** (`sce-build/src/forge/model.rs:70` —
  `ForgeKind` enum, all eleven return `true` from `is_supported()`):

  | Kind | `RuntimeDep` tier | Notes |
  |---|---|---|
  | `Statechart` | `SceRuntime` | W3C SCXML state machine (default) |
  | `Transform` | `None` | Pure single-expression formula |
  | `Lookup` | `None` or `ForgeRuntime` (varies with output type) | Enumerated input → output mapping |
  | `Condition` | `None` | Named boolean guard |
  | `Codec` | `None` | Fixed-width bit-field encode/decode |
  | `Procedure` | `None` or `ForgeRuntime` (L1 vs L2) | Event-driven state machine |
  | `Validator` | `None` | Range / plausibility / rate-of-change |
  | `Filter` | `ForgeRuntime` | Moving average, low-pass, debounce |
  | `Interpolation` | `ForgeRuntime` | 1D/2D table interpolation |
  | `Timer` | `ForgeRuntimeHal` | Periodic / delayed task timing |
  | `Observer` | `ForgeRuntime` | Threshold monitoring with hysteresis |

  RFC §5.A/C/D/E/L propose new kinds (`algorithm`, `link`,
  `buffer-pool`, `worker`, `bounded-collection`) that extend this
  enum additively (ARCHITECTURE §2.4 invariant #3).

- **Multi-language codegen for Forge kinds**, dispatched via
  `generator::Language` (`sce-build/src/generator.rs:30`, five
  variants: `Rust`, `Cpp`, `Kotlin`, `Go`, `Python`). Per-language
  template trees at `tools/codegen/templates/forge/{rust,cpp,kotlin,
  go,python}/*.jinja2`. SCE Mesh is orthogonal and currently
  **C++-only** (`sce-build/src/mesh/codegen.rs:849` — `Language::Cpp`
  arm only; all other languages return `UnsupportedLanguage`) — not
  on this project's critical path; see RFC §5.K.
- **Rust Forge runtime is already `no_std`** — `sce-forge-runtime/
  rust/src/lib.rs:16` declares `#![no_std]` with "pure no_std + no
  alloc" as the baseline contract. Std / alloc are opt-in features.
  (The separate `sce-rust-runtime` crate, which backs `Statechart`,
  is `std`-based; see §4.2.)
- Diagnostic contract and schema
- XInclude + `sce:template` composition

### 4.2 SCE extensions required (requested via RFC)

See `docs/rfc-sce-protocol-synthesis.md` for full detail:

| Extension | Purpose |
|---|---|
| `sce:kind="algorithm"` | Pure functions with bounded loops (CRC, VLE, KeyExpr intersect) |
| Codec DSL additions | VLE, variant, flags, present-if, len-prefix, TLV chain, DMA alignment, attachments/timestamps/encoding-info shapes |
| `sce:kind="link"` | Byte-stream I/O endpoints; open-set drivers via target plugin |
| `sce:kind="buffer-pool"` | Static memory placement with DMA + cache policy (`maintain` / `non-cacheable` / `none`); `reassembly` variant for fragment RX |
| `sce:kind="worker"` | Independent execution contexts (RX loop, TX loop, keepalive, reassembly worker) |
| `sce:kind="bounded-collection"` (§5.L) | Capacity-bounded runtime containers — backs local sub/queryable/pending-query/in-flight-reassembly tables |
| Fragment / reassembly FSM pattern (§5.M) | Authored in SCXML using buffer-pool reassembly variant + bounded-collection; no new top-level kind |
| Multi-link concurrency codegen (§5.N) | Multiple concurrent link drivers per machine with starvation-free scheduling |
| Build-time const-fold | Compile-time CRC tables, optional KeyExpr tries |
| C11 backend | No C variant in `generator::Language`; MCU needs C11. RFC §5.J.1 |
| Statechart `no_std` Rust variant | `sce-forge-runtime` Rust crate is already `no_std` (see §4.1), so `Transform`/`Codec`/`Procedure` on MCU-capable Rust is already possible. The gap is the **statechart** runtime (`sce-rust-runtime`), which is `std`-only and backs session/declare/query/fragment FSMs. RFC §5.J.2 |
| `sce:extern` (whitelisted) | Concrete atomics with ordering (acquire/release/seq_cst), memory fences, cache maintenance, IRQ save/restore |
| `deploy.yaml` memory/platform/links sections | Hardware-aware codegen inputs, including `has_dcache` / `dcache_line_size` / `core_count` / `worker_stack_budget` / `worker_slot_budget_us` / `keepalive_jitter_budget_us` / `target_plugin` |

### 4.3 This project authors

Once SCE extensions land, this project authors:

- SCXML statechart sources: session FSMs split by **transport
  class** (`session_unicast.scxml`, `session_multicast.scxml`) —
  peer and client modes share the unicast FSM, since the session
  layer is wire-identical between the two (see
  `docs/session-fsm.md` §5); plus `scouting.scxml` and the
  network-layer FSMs (PUT/SUB/query/declare/fragment/liveliness)
- Forge codec sources for every zenoh-pico peer/client message
  (scout/hello/session control, data-plane, declarations,
  attachments, timestamps, encoding info)
- Forge algorithm sources (CRC16, VLE encode/decode,
  keyexpr_intersect, keyexpr_includes)
- Forge bounded-collection sources (local sub/queryable/pending-
  query tables, in-flight reassembly table)
- Forge link sources (UDP unicast/multicast, TCP, Serial, WebSocket)
- Forge buffer-pool sources (regular RX/TX pools + reassembly pool)
- Forge worker sources (RX/TX/keepalive/reassembly workers)
- `deploy.yaml` variants (AP standalone, MCU standalone, AP+MCU pair)
  including per-machine limits (local_subscriptions, fragmentation
  profile, link selection)
- Hand-written runtime crates: `sce_link_runtime_{tokio,lwip}`,
  `sce_intrinsics_runtime_{rust,c}` implementations
- Optional API shim crates (`crates/watching_zenoh_api/`) as a
  `zenoh-c`-like façade over the synthesized library

---

## 5. Source Organization

Planned layout (does not exist yet). The top-level repo is a
**Cargo workspace**; generated AP code is a **library crate**, and
application/example binaries depend on it. This preserves the
migration path to plugin ecosystem and router mode on AP (§2.4
invariant 4): new features land as additional crates in the
workspace, not by patching generated output.

```
watching-zenoh/
├── ARCHITECTURE.md                    # this file
├── README.md
├── Cargo.toml                         # workspace root
├── docs/
│   ├── rfc-sce-protocol-synthesis.md  # upstream SCE request
│   └── wire-spec-subset.md            # which Zenoh msgs we implement
├── sources/                           # SCE inputs (SCXML + Forge)
│   ├── session/
│   │   ├── session_unicast.scxml      # kind=statechart (unicast: TCP/UDP-unicast/Serial/WS;
│   │   │                              #   4-way Init/Open handshake; peer AND client share this)
│   │   ├── session_multicast.scxml    # kind=statechart (UDP multicast: no handshake,
│   │   │                              #   periodic Join + peer table)
│   │   ├── scouting.scxml             # kind=statechart (Scout/Hello on scouting link;
│   │   │                              #   active/passive/static modes from deploy)
│   │   └── session_msg_codec.scxml    # kind=codec
│   ├── network/
│   │   ├── put_fsm.scxml
│   │   ├── sub_fsm.scxml
│   │   ├── query_fsm.scxml
│   │   ├── declare_fsm.scxml          # declare/undeclare sub, queryable, token
│   │   ├── fragment_fsm.scxml         # TX fragmentation + RX reassembly
│   │   ├── liveliness_fsm.scxml
│   │   └── network_msg_codec.scxml    # full message set incl. attachments, timestamps
│   ├── algorithms/
│   │   ├── crc16_ccitt.scxml          # kind=algorithm
│   │   ├── vle_u64.scxml
│   │   ├── keyexpr_intersect.scxml    # used at runtime over bounded-collection
│   │   └── keyexpr_includes.scxml
│   ├── collections/
│   │   ├── local_sub_table.scxml      # kind=bounded-collection
│   │   ├── local_queryable_table.scxml
│   │   ├── pending_query_table.scxml
│   │   └── in_flight_reassembly.scxml
│   ├── links/
│   │   ├── udp_unicast.scxml          # kind=link
│   │   ├── udp_multicast.scxml
│   │   ├── tcp_stream.scxml
│   │   ├── serial.scxml
│   │   └── websocket.scxml            # (BLE/Raweth via target plugins, §5.I RFC)
│   ├── pools/
│   │   ├── rx_pool.scxml              # kind=buffer-pool
│   │   ├── tx_pool.scxml
│   │   └── rx_reassembly_pool.scxml   # kind=buffer-pool, variant=reassembly
│   └── workers/
│       ├── rx_worker.scxml            # kind=worker
│       ├── tx_worker.scxml
│       └── keepalive_worker.scxml
├── deploy/
│   ├── ap_standalone.yaml
│   ├── mcu_target.yaml
│   ├── ap_mcu_pair.yaml
│   └── plugins/                       # target plugins (BLE, Raweth, etc.)
│       └── example_target_ext.yaml
├── runtime/                           # hand-written runtime crates/libs
│   ├── sce_link_runtime_tokio/        # Rust, std — UDP/TCP/WS/Serial
│   ├── sce_link_runtime_lwip/         # C, for MCU
│   └── sce_intrinsics_runtime/        # atomics, fences, cache maintenance
├── crates/                            # hand-written AP-side Rust crates
│   ├── watching_zenoh_api/            # optional: thin zenoh-c-like API
│   │                                  #   shim on top of generated library
│   └── watching_zenoh_bin/            # default AP binary (uses library)
├── out/                               # codegen products (gitignored)
│   ├── ap/                            # generated Rust LIBRARY crate
│   │   ├── Cargo.toml                 #   crate-type = ["rlib", "cdylib"]
│   │   ├── src/lib.rs                 #   public API
│   │   └── src/*.rs                   #   generated FSMs, codecs, etc.
│   └── mcu/                           # generated C library
│       ├── inc/*.h                    #   public headers
│       ├── src/*.c                    #   implementation
│       ├── CMakeLists.txt             #   library target
│       ├── linker_fragment.ld
│       └── memory_map.h
├── tests/
│   ├── parity/                        # AP vs MCU byte-equivalence
│   ├── wire_replay/                   # pcap → expected events
│   ├── interop/                       # dockerized zenohd + zenoh-pico CI
│   └── parity_vs_pico/                # zenoh-pico feature parity gate (Phase C)
└── examples/
    ├── hello_pub/                     # AP publishes "hello" (depends on out/ap)
    ├── hello_sub/                     # MCU subscribes and blinks LED
    └── mixed_pair/                    # AP peer + MCU peer interop demo
```

**Key structural point.** `out/ap/` is a **library crate**
(`crate-type = ["rlib", "cdylib"]`), not an executable. Binaries
live in `crates/watching_zenoh_bin/` and `examples/*` and depend on
the generated library via workspace path. This means:

- Future AP-side plugins (storages, REST admin) can be added as new
  workspace crates without touching generated code
- API shim crates (`zenoh-c` / `zenoh-pico` drop-in) live alongside
  in `crates/` and consume the same library
- The drift-detection rule (§11.5) stays intact: only `out/` is
  off-limits for manual edits; the workspace crates are authored
  as usual

Similarly on MCU, `out/mcu/` produces a library archive; the user's
firmware links it as a dependency alongside lwIP and the HAL.

---

## 6. Build Pipeline

### 6.1 Stages

```
[SCXML sources]        [deploy.yaml]
       \                    /
        \                  /
         v                v
  +----------------------------+
  |   sce-codegen build        |    <- single invocation drives all
  |                            |
  |   1. Parse + XSD validate  |
  |   2. Kind-wise IR build    |
  |   3. Type check            |
  |   4. Const-fold (build-time evaluation)
  |   5. Per-machine per-backend emission
  |   6. Sidecar generation (Cargo.toml, CMakeLists, linker.ld)
  +----------------------------+
         |                |
         v                v
     out/ap/          out/mcu/
   (Rust sources)   (C sources + headers)
         |                |
         v                v
   cargo build        cmake --build
         |                |
         v                v
  [AP executable]   [MCU firmware]
```

### 6.2 Artifacts per target

**AP (`out/ap/`)**
- `src/*.rs` — generated state machines, codecs, algorithms
- `Cargo.toml` — dependencies on `sce_core`, `sce_link_runtime_tokio`,
  `sce_intrinsics_runtime`, `tokio`, `bytes`
- `build.rs` — optional; wire-id lock verification

**MCU (`out/mcu/`)**
- `inc/*.h` — public headers (codec structs, function prototypes)
- `src/*.c` — implementation
- `CMakeLists.txt` — targets, include paths
- `linker_fragment.ld` — `SECTIONS` block per declared pool, each
  carrying an explicit `ALIGN(x)` matching the pool's
  `<sce:alignment>` (RFC §5.E). Paired DMA descriptor sections
  (`.sram1_desc`, etc.) follow with their own `ALIGN()`. Emitted
  as defense-in-depth alongside the storage variable's
  `__attribute__((aligned(x)))` and the codec field's
  `_Static_assert` (§5.B), so a toolchain quirk that drops
  symbol-level alignment cannot silently break DMA. `INCLUDE`d by
  the user's master linker script.

  **Linker flavor matrix.** The `.ld` shape is GNU LD by default —
  compatible with arm-none-eabi-gcc, clang, esp-idf, MCUXpresso,
  and Zephyr (which all consume GNU LD `MEMORY`/`SECTIONS`).
  Targets using ARM Compiler / Keil scatter files (`.sct`) or IAR
  ILINK (`.icf`) declare an alternate flavor in their
  `target_plugin` (RFC §5.I `linker_flavor: scatter_arm | icf_iar
  | os_managed`); the generator produces the corresponding
  artifact. `scatter_arm` and `icf_iar` arrive in Phase C+; Phase
  A/B is GNU LD only. Zephyr / NuttX targets use `os_managed`
  (the OS owns the link stage; SCE emits a CMake target the OS
  imports, no standalone `.ld`).
- `memory_map.h` — `#define` constants mirroring deploy.yaml memory
  regions

---

## 7. Runtime Architecture

### 7.1 AP backend

```
        Application (optional)
              |
              v
     +------------------+
     |  Generated code  |    <- SCE output
     |  (session FSM,   |
     |   codecs, ...)   |
     +------------------+
              |
      +-------+-------+
      |               |
      v               v
 sce_core        sce_link_runtime_tokio
 (AOT engine)    (tokio UDP/TCP adapter)
      |               |
      v               v
 Rust std + bytes + tokio runtime
```

- Single-process, multi-task (tokio)
- Workers are `tokio::spawn` tasks
- Timers are `tokio::time::interval`
- Inboxes/outboxes are `tokio::sync::mpsc`
- Pools are `bytes::BytesMut`-backed, bounded by deploy.yaml config

### 7.2 MCU backend

```
        Application (main loop)
              |
              v
   +------------------------+
   |   Generated code       |    <- SCE output
   |   (session FSM,        |
   |    codecs, workers,    |
   |    pools, DMA desc)    |
   +------------------------+
              |
      +-------+-------+
      |               |
      v               v
  sce_forge_         sce_link_runtime_lwip
  runtime_c          (lwIP callback adapter)
  (cursor,               |
   Result,               v
   pool mgmt)      lwIP (user-provided)
              |
              v
  HAL (user-provided)
  - UART / Ethernet MAC / DMA controller
  - Timer peripherals
  - SoC-specific serial/DMA peripherals (names vary by target)
```

- Single-core per machine instance (core selection deploy-time
  on multi-core SoCs). When a machine spans cores
  (`platform.core_count > 1`), cross-core inboxes and shared
  pools route through a hardware sync primitive (HSEM / spinlock
  unit / mailbox IP) registered via the §5.I `target_plugin`;
  plain atomics alone are insufficient on cores with separate
  D-Caches (§3.4)
- Cooperative scheduler, tick-driven (period from deploy.yaml).
  Each worker slot honors a per-slot WCET budget
  (`scheduler.worker_slot_budget_us`); the per-tick sum of slot
  budgets must fit inside `scheduler.keepalive_jitter_budget_us`
  so Keepalive emission cannot drift past the lease window. The
  build refuses to emit slots whose static WCET estimate exceeds
  the budget — see RFC §5.A and §5.K
- Workers are cooperative-scheduler slots, not threads
- Timers are slots in a compile-time-sized static wheel
- No heap; all buffers statically placed via buffer-pool kinds
- DMA descriptors generated in `.sram1_desc` section, paired with
  pool slots in `.sram1`

### 7.3 Shared runtime crates/headers

| Runtime | AP (Rust) | MCU (C) | Responsibility |
|---|---|---|---|
| `sce_core` | existing | not used; equivalent inline in generated C | AOT engine |
| `sce_forge_runtime` | existing | new C header+lib | Cursor, Result, shared helpers |
| `sce_link_runtime_tokio` | new (this project) | n/a | tokio UDP/TCP adapter |
| `sce_link_runtime_lwip` | n/a | new (this project) | lwIP UDP/TCP adapter |
| `sce_intrinsics_runtime` | new, whitelisted | new, whitelisted | Atomics, fences |

---

## 8. Wire Format Stack

### 8.1 Layer diagram

```
  +--------------------------------------------------+
  |  Application                                     |
  |    publish(key, value) / subscribe(key, cb)      |
  +--------------------------------------------------+
                        |
                        v
  +--------------------------------------------------+
  |  Session FSM (statechart)                        |
  |    Init → Scouting → Opening → Established       |
  |    ↕ keepalive  ↕ error recovery                 |
  +--------------------------------------------------+
                        |
                        v
  +--------------------------------------------------+
  |  Network FSM (per-pattern)                       |
  |    PUT: encode → schedule → transmit             |
  |    SUB: subscribe → receive → deliver            |
  +--------------------------------------------------+
                        |
                        v
  +--------------------------------------------------+
  |  Codec layer (per message type)                  |
  |    ScoutMsg, HelloMsg, InitSyn, InitAck,         |
  |    OpenSyn, OpenAck, Close, Keepalive, Put, Del, |
  |    Declare, Query, Reply                         |
  |                                                  |
  |    Uses: vle, variant, flags, present-if,        |
  |          len-prefix, TLV extension chain         |
  +--------------------------------------------------+
                        |
                        v
  +--------------------------------------------------+
  |  Link layer                                      |
  |    UDP unicast | UDP multicast | TCP             |
  |    Framer: length-prefix (TCP) or datagram (UDP) |
  |    Pool slots for RX/TX                          |
  +--------------------------------------------------+
                        |
                        v
  +--------------------------------------------------+
  |  OS / HAL                                        |
  |    tokio (AP) | lwIP + Ethernet MAC + DMA (MCU)  |
  +--------------------------------------------------+
```

### 8.2 Session FSM

Authored as `sources/session/session_unicast.scxml` +
`sources/session/session_multicast.scxml`, kind=statechart.
Full state model in `docs/session-fsm.md`; the sketch below is
abbreviated for orientation and shows the unicast path only.

Key states (abbreviated):

```
Init
  ├─entry→ trigger link open
  └─on link.ready → Scouting

Scouting
  ├─entry→ send Scout multicast
  ├─on Hello received → Opening
  └─on scout.timeout → retry (bounded) → ErrorExit

Opening
  ├─entry→ send InitSyn
  ├─on InitAck → send OpenSyn → wait
  ├─on OpenAck → Established
  └─on open.timeout → ErrorExit

Established
  ├─parallel:
  │   ├─Keepalive region (timer kind, reset on any msg)
  │   ├─RX dispatch region
  │   └─TX scheduling region
  └─on Close received OR lease.expired → Closing

Closing → Closed
```

### 8.3 Codec layer

One SCXML file per message type, kind=codec, using RFC §5.B
extensions. Example shape for `ScoutMsg`:

```xml
<scxml sce:kind="codec" name="ScoutMsg">
  <sce:flags name="header" byte="0">
    <sce:flag name="z" bit="7"/>
    <sce:flag name="t" bit="6"/>
    <sce:flag name="w_present" bit="5"/>
  </sce:flags>
  <sce:field name="what" type="vle_u64" sce:present-if="header.w_present"/>
  <sce:field name="zid" type="bytes" sce:len-prefix="u8"/>
  <sce:test-vector hex="03 01 16" value="Scout{what:1, zid:0x16}"/>
</scxml>
```

Test vectors from upstream `zenoh-protocol` regression fixtures drive
cross-backend parity.

### 8.4 Link layer

Authored as kind=link. Example:

```xml
<scxml sce:kind="link" name="udp_multicast_scout">
  <sce:link-class>udp_multicast</sce:link-class>
  <sce:framer ref="scout_frame"/>
  <sce:rx-pool ref="scout_rx_pool"/>
  <sce:backpressure>drop</sce:backpressure>
</scxml>
```

`deploy.yaml` binds driver and address:

```yaml
machines:
  ap_node:
    links:
      udp_multicast_scout:
        driver: tokio_udp_multicast
        group: 224.0.0.224
        port: 7446
```

---

## 9. Zero-copy Strategy

Honest, specific, and verifiable. "Zero-copy zenoh on MCU" is true
for a documented profile, not everywhere.

### 9.1 TX path (always zero-copy)

```
Application: publish(key, value)
    |
    v
Codec::encode writes directly into a pool slot
    |
    v
Link::send_from_pool_slot(slot_id)
    |
    v
DMA controller reads slot via pre-built descriptor
    |
    v
Ethernet MAC transmits
```

No intermediate copy. Pool slot is placed in DMA-coherent SRAM. DMA
descriptor is generated in `.sram1_desc` section, statically paired
with pool slot range.

### 9.2 RX happy path (zero-copy, single-frame, bounded size)

```
Ethernet MAC delivers to DMA
    |
    v
DMA writes into RX pool slot (pre-programmed)
    |
    v
Codec::decode parses in place from slot
    |
    v
Event emitted with `&slot` borrow
    |
    v
Event handler runs synchronously (or enqueues)
    |
    v
Slot returned to pool freelist
```

### 9.3 RX oversized or fragmented (stage copy)

When a message exceeds `pool.slot_size`, or spans multiple DMA
transfers:

```
First DMA slot → copy into stage buffer
Next DMA slots → append to stage buffer
Codec parses from stage buffer
Event emitted carrying stage buffer handle
```

This is **one copy** from DMA slot to stage. It is the unavoidable
cost for payloads that don't fit the bounded profile. Operators see
`link/stage-copy-invoked` diagnostic in logs so they can monitor.

Pool slot sizing is governed by build-time analysis, not prose
guidance. Each link in `deploy.yaml` declares `mtu_bytes` and
optionally `expected_p99_bytes` (RFC §5.K); the build then
mechanically checks three rules (RFC §5.M "Build-time fragmentation
analysis"):

1. **Reassembly capacity** —
   `reassembly_pool.slot_size ≥ max-fragments-per-message ×
   link.mtu_bytes` must hold. Hard error
   (`reassembly/max-fragments-insufficient-for-mtu`).
2. **Stage-copy rate** — if
   `(expected_p99_bytes - rx_pool.slot_size) / expected_p99_bytes
   > 25%`, emit `reassembly/expected-fragmentation-rate-high`.
   Authors raise `slot_size`, lower `expected_p99_bytes`, or
   acknowledge via `<sce:accept-stage-copy-rate>` on the link.
3. **Slot-size recommendation** — informational note suggesting
   `slot_size_recommended = ceil(expected_p99_bytes /
   mtu_bytes) × mtu_bytes` so p99 messages avoid fragmentation
   entirely.

This shifts "stage path rare" from a runtime-observed property to a
build-time-enforced one.

**Stage-copy policy (deploy-wide).** The stage-copy-rate gate is a
warning by default — the philosophy is that one copy per oversized
RX is the documented unavoidable cost. But on embedded targets where
unexpected copy *is* the performance regression (every cycle of the
cooperative slot is accounted for, and a 1 ms memcpy on an M0+
costs 12 ms of CPU at 4 cycles/byte for 12 KB), authors must be
able to upgrade the warning to a build-stop. RFC §5.K
`pool_defaults.stage_copy_policy` provides three settings:

- `warn` (default) — current behavior; `<sce:accept-stage-copy-rate>`
  on a link source suppresses per-link. Fits prototype and AP-class
  deploys where a copy is acceptable.
- `error` — promotes `reassembly/expected-fragmentation-rate-high`
  to `pool/stage-copy-policy-error` (hard error). Per-link opt-out
  via `<sce:accept-stage-copy-rate>` still works with a
  justification reference. **Recommended for embedded production
  deploys** where stage-copy is allowed only with explicit
  acknowledgement on a per-link basis.
- `forbid` — same hard error AND rejects `<sce:accept-stage-copy-rate>`
  itself (`pool/stage-copy-accept-rejected-under-forbid`). Only
  structural fixes (raise `slot_size` or lower `expected_p99_bytes`)
  are accepted. **Recommended for safety-critical deploys** —
  medical, automotive, aerospace — where any stage-copy under any
  condition is unacceptable.

The choice is per machine in `deploy.yaml`, not per pool, because
the policy expresses *deploy-class trust* (what level of unexpected
runtime cost is permissible) rather than per-pool tuning. A single
deploy.yaml may declare `pool_defaults.stage_copy_policy: forbid`
on the MCU machine and `warn` on the AP machine — the AP can absorb
a copy, the MCU cannot.

### 9.4 Pool placement

```
.dtcm       (Tightly Coupled, single-cycle access, no DMA)
    ├─ session FSM scratch
    ├─ small control-path pools (keepalive, close)

.sram1      (DMA-coherent, larger)
    ├─ RX pools (scout, session, network)
    ├─ TX pools
    └─ .sram1_desc (DMA descriptors, immediately after pools)

.flash      (ROM)
    ├─ codec const tables (CRC table, VLE masks)
    └─ linker-placed static KeyExpr lookup
```

Placement declared per-pool in the kind source; memory regions
declared in deploy.yaml; linker fragment generated to tie them
together.

### 9.5 Platform-aware link substrate (design philosophy)

The buffer-pool lifecycle FSM (§5.E) is OS-agnostic; only its
*edge actions* are platform-specific. This is the unifying abstraction
that lets a single SCXML source emit DMA-driven MCU code today and
io_uring-driven Linux code or QNX-dispatch-driven QNX code later,
without the SCXML changing.

| Platform | Pool backing | RX trigger | Edge actions on `cpu-mut → dma-armed-rx` | Phase |
|---|---|---|---|---|
| MCU bare_metal | static `__attribute__((aligned))` arrays in `.sram1` | DMA controller IRQ | `cache_invalidate`, descriptor enqueue, hardware DMA arm | A–C (current) |
| AP linux + epoll | `bytes::BytesMut` (heap) | `epoll_wait` ready-event | (no cache maintenance — kernel coherent) | D.1 |
| AP linux + io_uring fixed buffers | kernel-registered `iovec` regions | `io_uring_enter` completion | sqe submission with `IORING_OP_READ_FIXED` | D.1 (opt-in) |
| AP qnx + io-sock | io-sock buffer, optionally backed by shared memory | `dispatch_block` channel pulse | POSIX `recvmsg` or `MsgReceive` for IPC framing | D.2 |
| AP qnx + qnx_shm | shared-memory region (`shm_open` + `mmap`) | pulse notification | shm region update + pulse signal | D.2+ |

The same lifecycle FSM applies in every row — `free → cpu-mut →
dma-armed-rx → dma-busy-rx → cpu-ref → free` — and the same
ownership-violation diagnostics (§5.E `pool/ownership-violation`,
`pool/double-arm`, `pool/return-on-dma-state`) catch authoring
mistakes regardless of OS. What changes per row is which
`sce_intrinsics_runtime` calls (or runtime-crate-provided primitives)
are emitted on the FSM edges. The §11.4 no-alloc guard remains MCU-
only; AP rows have their own resource discipline (io_uring fixed-
buffer registration count, QNX shm region count) but not a hard
no-heap rule.

**Why this matters even in Phase A–C.** Authors writing SCXML for
MCU today are *implicitly* writing portable substrate code. The
codec and link kinds they author against the buffer-pool lifecycle
FSM will run unchanged on AP linux when Phase D.1 lands and on AP
qnx when Phase D.2 lands. The OS-specific runtime crate handles
the edge-action differences. This is the "platform-aware
high-performance networking" framing — not a Phase D promise, a
Phase A invariant being maintained as the project grows.

**Phase A–C scope reminder.** Only the MCU bare_metal row is
implemented during the priority track (zenoh-pico parity at C14).
The other rows are namespace-reserved and design-considered;
attempting to author against them today fails with
`deploy/platform-os-not-implemented-in-current-phase`. The
substrate philosophy is the architectural invariant; the
implementation is phased.

---

## 10. QoS Model

### 10.1 deploy.yaml → typed config

QoS is per-binding in deploy.yaml:

```yaml
machines:
  ap_node:
    bindings:
      "#sensor/temp":
        link: udp_multicast_pub
        qos:
          priority: real_time
          reliability: best_effort
          express: true
          congestion_control: drop
```

### 10.2 AP (runtime) vs MCU (static const)

**AP (Rust):**

```rust
// SCE-generated
pub const QOS_SENSOR_TEMP: QosConfig = QosConfig {
    priority: Priority::RealTime,
    reliability: Reliability::BestEffort,
    express: true,
    congestion_control: CongestionControl::Drop,
};
```

**MCU (C):**

```c
/* SCE-generated */
__attribute__((section(".rodata")))
const sce_qos_config_t QOS_SENSOR_TEMP = {
    .priority = SCE_PRIO_REALTIME,
    .reliability = SCE_REL_BEST_EFFORT,
    .express = 1,
    .congestion = SCE_CONG_DROP,
};
```

Same shape, same values, different placement. On MCU the config is
in Flash; no RAM cost per binding.

---

## 11. Testing Strategy

### 11.1 Cross-backend parity (byte-equivalence)

Every `algorithm` and `codec` with a `<sce:test-vector>` is exercised
in both backends and diffed. A shared Python (or shell) harness:

1. Generates AP Rust and MCU C from same source
2. Runs AP Rust test → captures byte output
3. Runs MCU C test in host-mode (compile with host gcc) → captures byte output
4. Diffs

Failure → `codec/test-vector-drift` diagnostic in build, or test-suite
failure. Gate on merge.

### 11.2 Wire replay

pcap captures from upstream zenoh peers are replayed into generated
stack:

```
captures/
├── zenoh_1_12_scout_hello.pcap
├── zenoh_1_12_session_open.pcap
├── zenoh_1_12_put_sub.pcap
└── zenoh_1_12_close.pcap
```

Each has an `.expected.json` alongside declaring expected event
sequence. Test harness injects bytes, asserts events match.

### 11.3 Upstream interop

CI pipeline:

```
docker run -d --name zenohd eclipse/zenoh:1.12
cargo run --bin ap_node -- --connect zenohd:7447
# asserts:
#   - SCOUT sent
#   - HELLO received from zenohd
#   - OPEN handshake completes
#   - PUT delivered (observable via zenoh CLI in container)
#   - SUB receives echo
```

MCU interop uses host-mode build (lwIP replaced with OS socket
shim) + renode or QEMU in a later phase.

### 11.4 No-alloc guard (MCU)

Heap allocation is forbidden on MCU. The guard is **layered** because
direct `malloc` trapping alone misses libc functions that allocate
internally (full `printf` via `vasprintf`, `strdup`, exception
allocation in linked libstdc++, TLS dynamic init):

**Layer 1 — direct trap.** Stub `malloc`/`calloc`/`realloc`/`free`
emit `__builtin_trap()`:

```c
void* malloc(size_t)         { __builtin_trap(); }
void* calloc(size_t, size_t) { __builtin_trap(); }
void* realloc(void*, size_t) { __builtin_trap(); }
void  free(void*)            { __builtin_trap(); }
```

**Layer 2 — linker `--wrap`.** Build adds `-Wl,--wrap=malloc
-Wl,--wrap=calloc -Wl,--wrap=realloc -Wl,--wrap=free` so any
indirect call from libc lands on `__wrap_malloc` (also trapping).
This catches allocation paths that bypass the symbol resolution
in Layer 1 due to weak-symbol behavior in vendor libc.

**Layer 3 — libc variant pinning.** Build configuration enforces
`--specs=nano.specs` (newlib-nano) or equivalent (picolibc tiny
stdio) so the `printf` / `scanf` family does not pull in the
allocating formatter path. CMake fragment generated by codegen
encodes this pin; deviation is a build error.

**Layer 4 — call-graph reachability.** Post-link, codegen invokes
a small analyzer over the linked ELF (`nm` + objdump call-graph
extraction) and verifies that no symbol reachable from the
`out/mcu/` entry points calls into a known-allocating libc
function. The deny-list is shipped with SCE (covers `vasprintf`,
`asprintf`, `strdup`, `getline`, `posix_memalign`, etc.). Any
match fails the build.

**Layer 5 — exception/RTTI ban.** Build adds `-fno-exceptions
-fno-rtti -fno-unwind-tables` so libstdc++ exception machinery
never links. Exception-throwing code paths are a build error,
not a runtime trap.

Accidental allocation paths fail at link time (Layers 1, 2),
build configuration time (Layer 3), or post-link analysis
(Layer 4). Layer 5 prevents an entire class of indirect
allocation. Runtime trap (Layer 1's `__builtin_trap`) is the
final fallback, not the primary defense.

### 11.5 Generated source drift detection

Every emitted file carries a header with `source-hash` and
`template-hash` (sha256 of sorted inputs and of the sce-build
binary + template tree). `sce-build verify <out-dir>` recomputes
both and fails on mismatch. CI runs this as a gate; pre-commit
hook runs it locally.

Manual edits to `out/` are forbidden — when generated code falls
short, the path is an SCE RFC (or `sce:extern` for target-specific
concerns), never a direct patch. Exceptions live in
`docs/SCE_ACCEPTED_SUBSET.md` with a linked RFC and expiry date.
This turns the "SSoT" claim from aspirational into mechanically
enforced. See [RFC: Generated source drift detection](docs/rfc-sce-protocol-synthesis.md#626-generated-source-drift-detection).

The drift gate covers a fixed artifact set per backend:
`{out/{ap,mcu}/**/*.{rs,c,h}, Cargo.toml, CMakeLists.txt,
linker_fragment.{ld,sct,icf}, sce_sourcemap.json}`. The
`sce_sourcemap.json` artifact (RFC §5.O, generated-source
traceability) carries the same `source_hash`/`template_hash` as
the code it attributes; mismatch between the sourcemap and the
generated code's header surfaces as
`traceability/sourcemap-source-hash-mismatch`. This means
`sce-build verify` cannot pass with a stale sourcemap pointing at
old SCXML lines, even if the generated code itself is in sync.

### 11.6 Adversarial input (fuzz testing)

Synthesized codecs MUST NEVER panic, trap, hang, or return an
out-of-bounds slice on malformed input — they MUST return a typed
`CodecError::*` (Rust) or `SCE_RESULT_*` (C). This is a fuzzable
property, enforced as a gate, not a code-review concern.

**Targets.** Five canonical fuzz targets, one per high-risk codec
extension (RFC §5.B):

| Target | What it catches |
|---|---|
| `vle_decode_fuzz` | VLE continuation bit set without a follower byte; values overflowing the declared width; max-shift not enforced |
| `tlv_chain_decode_fuzz` | TLV chains exceeding `max-depth`; length fields > remaining buffer; truncation mid-extension; circular `next` chains |
| `length_prefix_decode_fuzz` | Declared length > available bytes; declared length wraps integer; len-prefix referencing non-int field |
| `variant_decode_fuzz` | Tag value not in any arm and no `<sce:default>`; tag forces decode of an arm whose payload is malformed |
| `borrow_mode_overrun_fuzz` | `parse-mode="borrow"` codecs returning slices that escape the input buffer bounds |

**Harness — cross-target matrix.** Host-built x86_64 fuzzing alone
is insufficient because target MCUs differ in word width, pointer
size, alignment requirements, and unaligned-access trap behavior.
A bug that requires a 32-bit `size_t` overflow, or a `uint32_t`-
aligned access via a `uint8_t*`, can pass an x86_64 fuzz run and
hard-fault on the target. The MCU fuzz path therefore runs in a
matrix of three environments, escalating in fidelity:

| Tier | Environment | What it catches | What it MISSES | Cost |
|---|---|---|---|---|
| F1 (mandatory) | Host x86_64 + libFuzzer / AFL + ASan + UBSan | Logic bugs, OOB slices, panic paths | 32-bit-only bugs; ARM-specific UB | nightly CI |
| F2 (mandatory) | Host **i686** (32-bit) cross-build + libFuzzer | 32-bit `size_t` overflow, pointer-size-dependent struct padding | ARM ISA bugs; cache/MPU effects | nightly CI |
| F3 (mandatory) | QEMU `qemu-system-arm` user-mode for Cortex-M3/M4/M7 + libFuzzer-style harness | Unaligned-access traps (M0/M0+/M3 strict-align), ARM ISA differences, ARM-specific UB | **D-Cache behavior; MPU regions; DMA + ISR interaction; peripheral state; vendor libc** — QEMU user-mode does not emulate the memory subsystem fidelity needed for those classes | nightly CI |
| F4 (strongly recommended for production; **mandatory for safety-critical**) | HIL on actual board (or Renode for richer simulation than QEMU user-mode) with on-device coverage feedback | Cache effects, real DMA + ISR interaction, vendor-libc behavior, MPU faults, peripheral state corruption | nothing structural — this is the closing tier | weekly, deploy-class hardware (or Renode VM) |

**F3 limits — important.** QEMU user-mode emulates ARM ISA semantics
faithfully (instruction decode, integer/branch behavior, alignment
trap on M0/M0+/M3) but **does not** emulate:
- D-Cache (so `cache_clean`/`invalidate` intrinsic effects are
  silently no-op — bugs in cache-policy handling escape F3)
- MPU regions (so `non-cacheable` policy errors escape F3)
- Interrupt + DMA timing (so ISR-driven RX path bugs escape F3)
- Peripheral models (so vendor HAL interaction bugs escape F3)

For these classes, F4 (HIL on actual board, or **Renode** which does
emulate cache and MPU at the cost of slower throughput) is the only
tier that catches them. F4 is therefore not optional for safety-
critical deployments — F3 alone gives a false sense of completeness
on cache/DMA/ISR-path bugs. The roadmap stages F4:

- Phase A/B/C: F4 absent; F3 is the ceiling, with F3 limits documented
  prominently in CI dashboards
- Phase D: F4 lands as a Renode-based nightly job covering the
  emulation gap; HIL added as a weekly job on physical reference
  boards
- Production deployment guidance: any deployment claiming "no panic
  on malformed input" must show F4 coverage, not F1–F3 alone

**F4 coverage feedback architecture.** "On-device coverage feedback"
in the matrix above is not a hand-wave — it commits the F4 tier to a
specific shape that this section pins down. Two structural decisions
follow from the requirement that F1 corpora and F4 corpora be
**byte-sequence interchangeable**: a finding from F1 must be
re-runnable on F4 unmodified, and an F4-only crash must minimize back
to a byte sequence that any tier replays as a regression vector
(§11.1).

*Decision 1: coverage signal source.* F4 uses the **same compiler
instrumentation** as F1–F3 (`-fsanitize-coverage=trace-pc-guard` or
`inline-8bit-counters`), exposing the `__start___sancov_guards` /
`__stop___sancov_guards` region as the canonical coverage map. ETM
(Embedded Trace Macrocell) and SWO/ITM branch-trace decoding,
attractive at first glance because they need no target instrumentation,
are **rejected as the gate signal** because they produce a different
edge-ID space that is not corpus-portable across tiers. Hardware
trace remains valuable as *post-hoc evidence* — confirming that an
F1-distilled corpus actually exercised cache/DMA/ISR paths on real
silicon — but it is observability, not the fuzzing gate.

*Decision 2: fuzzer engine.* F4 adopts **Centipede** (out-of-process
engine + remote executor) rather than libFuzzer-native (in-process
only). The fuzz target on the MCU runs as a "runner" exposing two
primitives over a `target_plugin`-declared transport (RFC §5.I
`fuzz_coverage_transport`); the engine on the host owns mutation,
corpus management, and minimization. F2/F3 migrate to the same
Centipede runner shape so all three MCU tiers share a single
mutator/corpus/minimization pipeline; F1 (AP-side, `cargo fuzz`)
keeps libFuzzer for ergonomics and adapts at the corpus boundary
(see OQ-W17 for the engine-uniformity trade-off).

*On-target coverage agent.* Linked into the fuzz build only (gated
behind `BUILD_FUZZ_HARNESS` / Cargo `[features] fuzz`), not present
in production. The agent owns:
- the `__sancov_*` edge-counter region (placed in a dedicated
  `.fuzz_cov` linker section so the host can locate it by symbol);
- the input intake buffer (mirrors libFuzzer's
  `LLVMFuzzerTestOneInput` shape, but reads from a transport-specific
  inbox instead of being called by a host-side `main`);
- per-iteration reset (zero the bitmap, drain RX state, reseed any
  RNG that affects parser behavior);
- §11.4 deny-list survival — the no-alloc guard is loosened for
  sanitizer instrumentation under fuzz, but the libc allocator
  deny-list (Layer 4) stays armed, so `vasprintf`-class regressions
  fail fuzzing immediately, not just production.

*Transport contract.* The on-target agent and the host runner agree
on two primitives, both declared by the transport plugin
(RFC §5.I `fuzz_coverage_transport`):
- `deliver_input(&[u8])` — host → target, hands one fuzz input to
  the runner and waits for completion or timeout;
- `read_coverage_bitmap(&mut [u8])` — host ← target, reads the edge
  counter region after `deliver_input` returns.

The plugin also names the iteration timeout (slow-input → fail per
the CI gates below), the bitmap size, and the symbol pair locating
the counter region. The transport matrix (`renode_sysbus`,
`segger_rtt`, `openocd_memmap`, `dma_uart`, `semihosting`) lives in
RFC §5.I; selection is per deploy.

*Renode vs HIL responsibility split.* Within F4, the two execution
environments answer different questions:
- **Renode** (deterministic simulation, fast, parallelizable across
  VM instances) is responsible for cache/MPU semantics correctness
  and for *FSM-timing* fuzzing — driving the unicast session FSM
  with arbitrary byte sequences while a controllable simulated clock
  schedules ISRs and keepalives. This is where transition races
  between `RxDispatch`, `LeaseMonitor`, and `TxSchedule`
  (`docs/session-fsm.md` §2.3) get exposed. HIL cannot reproduce a
  specific timing window precisely; Renode can.
- **HIL on physical reference boards** (slow, hardware-bound) is
  responsible for real DMA + ISR interaction, vendor-libc behavior,
  and peripheral state corruption — bugs that depend on actual
  silicon errata or real DMA controller scheduling. F4-only crashes
  appearing only on HIL retain the existing `memory-subsystem-specific`
  tag.

*Throughput-aware corpus pipeline.* HIL throughput
(roughly 500–1000 execs/s on SEGGER RTT, 50–200 execs/s on openocd
polling) is two to four orders of magnitude below F1, so the 24h
gate is unreachable if F4 grows the corpus from scratch. The F1 → F4
pipeline therefore is:

```
F1 (nightly, ~10⁹ execs)
  -> corpus minimize (cmin)
  -> distilled seed (~10⁴ inputs)
F4-Renode (weekly, ~10⁷ execs on simulated clock)
  -> catches FSM-timing + cache/MPU bugs
F4-HIL (weekly, ~10⁵ execs on real silicon)
  -> catches DMA/ISR/peripheral/libc bugs
```

F4-only crashes are the structural value of the tier; corpus growth
remains F1's job. Coverage maps are NOT portable across tiers (each
tier's `trace-pc-guard` IDs are compile-target-specific), but the
**byte-sequence corpus is** — a finding minimizes to a byte sequence
that any tier can replay.

AP path uses `cargo fuzz` (libFuzzer) against the generated Rust
library — only the F1 tier applies (Rust `usize` portability is a
compiler concern, not fuzz scope).

For each target tier the no-alloc guard (§11.4) is relaxed in the
fuzz build to allow sanitizer instrumentation. CI gates:

- 24-hour cumulative coverage per target per tier on a nightly schedule
- Crash → fail (any tier)
- Slow input (> 1ms decode wall time on F1) → fail (catches accidental
  O(n²) parse paths that would burn cooperative-scheduler slots)
- F2/F3 crashes that don't reproduce on F1 are flagged
  `architecture-specific` and prioritized — these are the bugs the
  matrix exists to find
- F4 crashes that don't reproduce on F3 are flagged
  `memory-subsystem-specific` and indicate cache/MPU/DMA/ISR
  interaction bugs that the lower tiers structurally cannot find
- F4 coverage transport unreachable (timeout on `deliver_input` or
  `read_coverage_bitmap`) → fail with a diagnostic referencing the
  declared `target_plugin.fuzz_coverage_transport` (RFC §5.I)
- F4 coverage instrumentation absent (no `__sancov_guards` region in
  the linked ELF) → fail; F4 cannot run as evidence-only

**Corpus.** Seeded from §11.2 wire-replay pcaps — every legitimate
captured frame becomes a starting corpus entry. Coverage-guided
mutators evolve from there. Crash-finding inputs are minimized and
checked into `tests/fuzz/regressions/<target>/` so re-introduction
is caught by §11.1 cross-backend parity (the regression vectors
become permanent test inputs).

**Failure-mode contract.** When the fuzzer produces an input that
yields a `CodecError`, that's a **pass** — the codec correctly
rejected malformed input. Only panic / trap / hang / OOB-slice is
a fail. This contract is what makes "MCU backend safely closes the
session on malformed peer data" mechanically verifiable rather
than aspirational.

**Session-level fuzzing.** Beyond per-codec fuzzing, a session-FSM
fuzz harness drives the unicast session FSM (`docs/session-fsm.md`)
with arbitrary byte sequences after the OPEN handshake completes,
verifying that no input sequence drives the FSM into a panicking
state — the worst legal outcome must be `Closing` with a typed
close reason. This catches transition-side issues that per-codec
fuzzing cannot reach (e.g. valid-but-out-of-order frames).

---

## 12. Dependency Boundaries

### 12.1 Generated code dependencies

**AP Rust generated code depends on:**
- `sce_core` (existing)
- `sce_forge_runtime` (existing)
- `sce_link_runtime_tokio` (new, this project)
- `sce_intrinsics_runtime` (new, whitelisted)
- `bytes`, `tokio`, `heapless` (external)

**MCU C generated code depends on:**
- `sce_forge_runtime_c` (new, from SCE RFC §5.J.1)
- `sce_link_runtime_lwip` (new, this project)
- `sce_intrinsics_runtime_c` (new, whitelisted)
- User-provided: `lwIP`, SoC HAL, linker script
- Host C runtime: `<stdint.h>`, `<stddef.h>`, `<string.h>` only

No dynamic linking. No heap. No exceptions.

### 12.2 Runtime crate versioning

All runtime crates follow SemVer. Generated code pins to exact minor
version at build time (via generated Cargo.toml / CMakeLists
version constraint) to avoid SSoT drift between codegen and runtime.

### 12.3 External (user-provided)

The user (downstream consumer of watching-zenoh) provides:
- MCU: SoC HAL, lwIP configuration, linker script (merging our
  generated fragment), clock/power init
- AP: nothing (binary ships self-contained)

---

## 13. Development Workflow (pre-SCE)

While SCE Phase A is pending, useful work:

1. **Wire subset document** — author `docs/wire-spec-subset.md`
   enumerating exactly which Zenoh 1.x messages are in MVP scope.
   Reference upstream `zenoh-protocol` crate as normative spec.
2. **Pcap corpus collection** — capture SCOUT/HELLO/OPEN/PUT/SUB
   traffic from upstream zenoh setup. Build golden fixtures.
3. **deploy.yaml skeletons** — draft the three deploy variants
   (`ap_standalone`, `mcu_target`, `ap_mcu_pair`) using RFC §5.K
   shape. Diagnostic gaps feed back to the RFC.
4. **Session FSM sketch** — author a prose-level state chart in
   `docs/session-fsm.md` (not SCXML yet — no authoring tooling).
   Catches gaps early.
5. **SCE RFC Q1–Q10 tracking** — record SCE maintainer responses in
   `docs/rfc-open-questions-log.md` as they come in.
6. **Runtime crate API sketches** — `sce_link_runtime_tokio` and
   `sce_link_runtime_lwip` APIs can be stub-designed (no impl) so
   that SCE generator authors know the target shape.
7. **Meta-source generator for parametric kinds (Phase A/B
   workaround).** RFC §5.G defers parametric kinds to Phase 2,
   which means VLE u16/u32/u64 and similar variants must be
   authored as three near-identical SCXML files in MVP. The
   SSoT-discipline-friendly workaround: author one Jinja2
   template at `tools/meta/vle.scxml.j2` and a small Python
   driver (`tools/meta/expand.py`) that emits
   `sources/algorithms/vle_u16.scxml` / `vle_u32.scxml` /
   `vle_u64.scxml`. The generated SCXML files are gitignored;
   the template + driver are the SSoT. Drift detection
   ([RFC: Generated source drift detection](docs/rfc-sce-protocol-synthesis.md#626-generated-source-drift-detection)) extends to this layer: each emitted SCXML carries
   `// META-GENERATED — DO NOT EDIT` + `template-hash` /
   `source-hash`, and `tools/meta/verify.py` is run in CI before
   `sce-codegen` to ensure the generated SCXML matches the
   current template + driver. Each generated state/transition in
   the emitted SCXML also carries an `<sce:source-line file="..."
   line="..."/>` marker pointing back at the Jinja2 template line
   it came from, so RFC §5.O traceability is preserved through
   meta-generation; `verify.py` validates marker presence
   (`traceability/meta-generated-source-line-marker-missing`).
   When RFC §5.H/§5.G land in Phase 2, the meta-generator is
   retired and the templates fold into parametric kind sources
   directly.

   **Trade-off considered.** The alternative is hardcoding the
   three VLE files (≈30 lines each, differing only in `<sce:type>`
   and `<sce:max-shift>`) and relying on §11.1 cross-backend
   parity test vectors to detect any drift between them. That
   approach has lower setup cost (no Jinja2, no verifier) but
   requires manual sync on every VLE change, and §11.1 catches
   semantic drift only — a stylistic divergence that compiles
   and round-trips test vectors would slip past. The meta-
   generator is preferred because the 6–12 month window until
   §5.G lands is long enough that manual sync is realistic to
   skip at least once, and the meta-generator is a self-
   contained `tools/meta/` directory that retires cleanly
   (single delete commit) when §5.G arrives. The 2-depth build
   pipeline cost is bounded by the SHA256 verify step, not a
   compiler invocation.

None of this writes code that has to be thrown away when Phase A
lands. All of it clarifies the authoring contract before the first
`sce-codegen generate` invocation. The meta-generator (#7) is the
one piece that DOES retire when SCE catches up — but it is
self-contained tooling under `tools/meta/`, not synthesized output,
and its retirement is a clean delete rather than a rewrite.

---

## 14. Living Document Notes

When Phase A lands and this document moves from "pre-implementation
design" to "implementation reference":

- Remove the Status disclaimer at the top
- Replace §13 with a "Development Workflow" describing actual
  sce-codegen invocation, test runner usage, CI setup
- Add §15 "Observability" once logging/metrics decisions are made
- Add §16 "Performance targets" once first benchmarks exist (latency
  budget for OPEN handshake on MCU, TX throughput on AP)
- Update §8 code examples from "planned shape" to actual source
  references (file paths + line numbers)

Updates to this file are tracked in the same PR that introduces the
architectural change it documents. Drift between this file and the
codebase is a bug.

## 15. Observability (placeholder)

Logging, metrics, and tracing decisions pending. This section will be
populated once the observability stack is decided. Placeholder so that
forward-references from §14 resolve.

## 16. Performance targets (placeholder)

Latency budget for OPEN handshake on MCU and TX throughput on AP —
pending first benchmarks. Placeholder so that forward-references from
§14 resolve.
