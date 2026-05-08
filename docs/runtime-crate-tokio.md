# Runtime crate — `sce_link_runtime_tokio`

**Status.** Pre-implementation prose, design-only during Phase A–C
(MCU-first invariant, RFC §7). This document fixes the Rust trait
surface that `sources/session/*.scxml` will compile-time bind via
`<sce:link>` once Phase D.1 (AP linux baseline) opens. Authoring
this trait surface *now* — Phase A–C — is justified by the OQ-W20
design pressure: the trait must stay small enough that a future
custom QNX-native runtime (`sce_link_runtime_qnx`, Phase D.2) can
re-implement it without leaking epoll-shaped abstractions.

**Scope.** The Rust runtime crate that hosts the `Link` trait
implementation for `platform.os: linux`. Drives one of two reactor
configurations: (i) `tokio` baseline over `mio` epoll (Phase D.1
entry default), (ii) `tokio_uring` opt-in over `io_uring` registered
fixed buffers (Phase D.1 opt-in, kernel ≥ 5.10). Both share the
same trait; the difference is the per-driver adapter selecting the
OS primitive. AP-Rust intrinsics (`sce_intrinsics_runtime_rust`)
are a sibling concern documented at
`docs/intrinsics-runtime-symbols.md`; this document covers the
*link* trait, not the platform intrinsics.

**Inputs (normative).**
- `docs/session-fsm.md` §6 — 6 inbound link events
  (`link.ready`/`link.lost`/`link.rx`/`link.tx_drained`/
  `link.backpressure(on|off)`/`link.framing_error`) and 3 outbound
  invocations (`link.open()`/`link.send()`/`link.close()`). Trait
  shape is exactly this contract.
- `docs/reassembly-fsm.md` §6 — pool ownership FSM edges
  (`free → cpu-mut → dma-armed-rx → dma-busy-rx → cpu-ref → free`)
  whose AP-side incarnations the runtime hosts. On linux the
  `cache_invalidate` / `cache_clean` edge actions are no-ops
  (kernel-coherent), but the lifecycle FSM stays identical per
  ARCHITECTURE §9.5 row 2 — that is the unifying abstraction.
- [`docs/scouting-fsm.md`: Scouting link vs session link](scouting-fsm.md#13-scouting-link-vs-session-link--distinct-instances) — scouting links (`trust_class:
  untrusted`) are compile-time tagged; the trait surface honors the
  tag by refusing to wire `Accepting.*` (per [session-fsm: Trust-class interaction](session-fsm.md#26-trust-class-interaction-cross-ref-to-5m)) and
  refusing reassembly pool binding (per reassembly-fsm §5).
- RFC §5.C link kind, §5.J.3 backend 3-tuple naming convention
  (`sce_link_runtime_<os>`), §5.J.4 MCU-class matrix (the `link`
  kind emits only on `(rust, linux | qnx)` + `(c11, bare_metal)`).
- ARCHITECTURE §9.5 row 2 (`AP linux + epoll`) and row 3 (`AP linux
  + io_uring fixed buffers`).
- OQ-W20 — design pressure to keep the trait surface small enough
  to allow a future custom QNX-native runtime to re-implement
  without leaking epoll-shaped abstractions.

**Outputs.** (1) A `LinkDriver` trait + `LinkEvent` enum that
`sources/session/session_unicast.scxml` and `session_multicast.scxml`
SCXML can bind via `<sce:link>` without the SCXML being aware of
OS. (2) deploy.yaml `links.<name>.driver` enum mapping (`tokio_udp`,
`tokio_tcp`, optional `tokio_uring`). (3) An `io_uring` fixed-buffer
opt-in path that re-uses the §5.E pool slot lifecycle FSM unchanged
— only the edge actions differ (sqe submission with
`IORING_OP_READ_FIXED` instead of epoll-ready dispatch).

**Non-outputs.** Rust source code (codegen target, not authored
here). QNX runtime — that lives in OQ-W20's resolution document
once Phase D.2 opens. SCXML authoring against the trait — blocked
on Phase A landing.

---

## §2 Trait surface

### §2.1 The two-primitive Link contract

`sce_link_runtime_tokio` exposes **one** trait per link kind. Codegen
binds the SCXML `<sce:link>` declaration to a concrete
implementation by deploy-time `links.<name>.driver` selection.

The trait is intentionally minimal — the smallest surface that
covers the session-fsm §6 contract. Two primitives:

```rust
// Pseudocode (prose-only — actual Rust authored at codegen-time
// against this contract). #![no_std] not relevant on linux; the
// AP build is std-flavored.
trait LinkDriver {
    /// Async open. Resolves to `LinkEvent::Ready` or
    /// `LinkEvent::OpenFailed { cause }`. Used only by the
    /// outbound (initiator) path; inbound (acceptor) path
    /// constructs the impl with the link already open and
    /// emits `LinkEvent::Ready` synchronously on first poll.
    async fn open(&mut self, endpoint: &Endpoint) -> Result<(), OpenError>;

    /// Async send. Resolves when bytes have been handed off to
    /// the kernel (epoll baseline) or the io_uring sqe has been
    /// submitted (io_uring path). Reliability hint
    /// (`RELIABLE`/`BEST_EFFORT`) is forwarded to the driver
    /// per session-fsm §6 outbound table.
    async fn send(&mut self, frame: &TxFrame, reliability: Reliability)
        -> Result<(), SendError>;

    /// Cooperative close. Caller is the session FSM `Closing`
    /// state; the driver flushes any pending TX, then closes
    /// the OS handle. Idempotent.
    async fn close(&mut self) -> Result<(), CloseError>;

    /// Single event source — driven by the runtime's reactor,
    /// returns one event at a time. Codegen-emitted session FSM
    /// loop is `loop { driver.poll_event().await -> dispatch }`.
    async fn poll_event(&mut self) -> LinkEvent;
}
```

The OQ-W20 design constraint is exactly satisfied here: four
methods, no method exposes epoll/`mio::Poll` types. A QNX-native
re-implementation maps `poll_event` onto `MsgReceivePulse` /
`dispatch_block` and `send` onto `MsgSend` without changing the
contract.

### §2.2 `LinkEvent` enum

The six inbound events from session-fsm §6 lift to enum variants
1:1, plus one synthetic variant for the outbound `open()` resolution:

```rust
enum LinkEvent {
    /// session-fsm §6 link.ready
    Ready,
    /// session-fsm §6 link.lost(cause)
    Lost { cause: LostCause },
    /// session-fsm §6 link.rx(bytes) — bytes is a pool-slot
    /// borrow (RFC §5.E `Sample<'pool>` semantics applied
    /// across the link/codec boundary). On linux the borrow is
    /// from a `bytes::BytesMut` arena; on linux+io_uring the
    /// borrow is from a kernel-registered fixed buffer.
    Rx(RxFrame<'pool>),
    /// session-fsm §6 link.tx_drained
    TxDrained,
    /// session-fsm §6 link.backpressure(on|off)
    Backpressure(BackpressureKind),
    /// session-fsm §6 link.framing_error — emitted when the
    /// link-level framer (see session-fsm §6 invocation table:
    /// "encoding happens in the codec sibling kinds") rejects
    /// inbound bytes. Distinct from codec-level error which
    /// reaches the FSM via the codec event channel.
    FramingError { detail: FramingDetail },
}

enum BackpressureKind { On, Off }

enum LostCause {
    PeerClosed,            // FIN / RST observed
    Timeout,               // local read/write timeout
    OsError(OsErrno),      // generic OS-reported failure
}
```

The `FramingDetail` shape is intentionally opaque at this layer —
the framer kind authored in SCXML (RFC §5.B) owns its own diagnostic
vocabulary; the link merely surfaces "framer rejected" so the
session FSM can transition to `Closing(INVALID)` per session-fsm
§2.4 close-paths table.

### §2.3 Why `Rx` borrows from a pool slot

Per RFC §5.E "Application-facing API contract", the AP build
exposes inbound bytes as `Sample<'pool>` borrows. Three
consequences for this trait:

1. **No copy by default.** `Rx(RxFrame<'pool>)` is a borrow;
   consumers (codec kind decoding the frame) read in place.
2. **Stage copy is opt-in via `take()`.** Network FSMs that need
   to outlive the borrow call `RxFrame::take(&mut self)`; the
   call returns an owned `Vec<u8>` and the underlying pool slot
   transitions `cpu-ref → free` per RFC §5.E lifecycle.
3. **The borrow ties slot ownership to control flow.** The Rust
   borrow checker enforces, at compile time, that no consumer
   holds an `RxFrame<'pool>` across an `await` point that yields
   to the reactor's slot-recycling loop. This is the AP analog
   of the C11 `consumable` typestate (RFC §5.E Layer 1) and is
   one reason this kind is `(rust, *)` only — Cpp/Kotlin/Go/Python
   have no equivalent.

### §2.4 Trust-class compile-time gating

The `untrusted` / `session_arming` / `established_session` trust
classes (RFC §5.M, [session-fsm: Trust-class interaction](session-fsm.md#26-trust-class-interaction-cross-ref-to-5m)) propagate to compile-time
trait selection. Codegen emits one of three flavors of the
`LinkDriver` impl per link instance based on
`links.<name>.domain_attrs.trust_class`:

| trust_class | Trait surface present | Compile-time absent |
|---|---|---|
| `untrusted` | `open` / `send` / `close` / `poll_event` minimal | `Accepting.*` allocator hooks; reassembly slot handover |
| `session_arming` | adds `Accepting.*` allocator hooks (3-cap anti-flood — `session_arming_quota` / `accept_rate_per_sec` / optional `stateless_accept`) | reassembly slot handover |
| `established_session` | adds reassembly slot handover (`bind_reassembly_pool`) | `Accepting.*` allocator hooks (post-handshake links never accept) |

Codegen rejects any cross-binding (e.g. SCXML referencing
`bind_reassembly_pool` on an `untrusted` link) at compile time
with the existing `reassembly/untrusted-link-binding` (hard error).
The trait surface is structured so the rejection is mechanical:
the absent method is *not in the trait* for that link instance.

**Listener-link two-instance emission (OQ-W22 resolution).** A
deploy.yaml listener entry whose `domain_attrs.trust_class:
session_arming` emits **two** trait impls, not one: the
`session_arming` impl (carrying the `Accepting.*` allocator
hooks) plus a synthesized `established_session` sibling impl
(carrying `bind_reassembly_pool`). The two impls share the
underlying tokio socket reactor (`UdpSocket` /
`TcpListener` / `tokio_uring` registered buffers) but each is
backed by a **distinct `LinkDriver` value** — codegen emits two
generic-position type parameters (or two trait-object slots
depending on the codegen flavor), two `open` invocations on the
generated AP entrypoint, and a peer-state-driven RX dispatch in
the runtime crate that routes each `recv_from` outcome to the
correct driver's `LinkEvent` channel. Authors reference the
listener once in SCXML; reassembly-pool bindings resolve to the
`established_session` sibling at codegen time.

Compile-time absence of trust-class-incompatible methods holds
per impl: the `session_arming` impl has no
`bind_reassembly_pool`; the `established_session` sibling has no
`Accepting.*` allocator. The
`reassembly/binding-on-unpaired-listener` and
`link/listener-link-not-paired-with-established-sibling`
diagnostics (RFC §5.M / §5.C) catch any codegen template
regression that would emit one impl without the other. See
[`docs/session-fsm.md`: Trust-class interaction](session-fsm.md#26-trust-class-interaction-cross-ref-to-5m) ("Listener-link logical split") and
RFC §5.C "Listener-link sibling emission" for the codegen
mechanics; the `io_uring` opt-in in §4 is orthogonal to this
split — both impls of a listener link can use either reactor
flavor independently of each other.

---

## §3 deploy.yaml `links.<name>.driver` mapping

Three driver values for the linux runtime:

| `driver` value | Reactor | Pool backing | Phase availability |
|---|---|---|---|
| `tokio_udp` | mio epoll | `bytes::BytesMut` heap arena | D.1 (entry default) |
| `tokio_tcp` | mio epoll | `bytes::BytesMut` heap arena | D.1 |
| `tokio_uring` | `io_uring` | kernel-registered fixed buffers | D.1 (opt-in, kernel ≥ 5.10) |

Each driver corresponds to one `LinkDriver` impl in the runtime
crate. Codegen wires `<sce:link><sce:link-class>udp</sce:link-class>`
+ `links.foo.driver: tokio_udp` to the `tokio_udp` impl path.

`deploy/ap_standalone.yaml` already declares `tokio_udp` for both
the scouting and session links (lines 88, 100). The
`tokio_uring` opt-in row in that file is currently commented out
(lines 156) pending Phase D.1 entry; the schema accepts the value
already.

**Driver selection determinism.** A given SCXML emits a driver-
parametric impl, but the *driver type* is locked at codegen time
from deploy.yaml — no runtime driver swap. This matches the
`(language, target_os, runtime_crate)` 3-tuple selectivity of
RFC §5.J.3: deploy.yaml is the authoritative source of which driver
is wired.

**Fallback policy.** If `links.<name>.driver` is absent and the
link's `<sce:link-class>` is in `{udp, tcp}`, codegen defaults to
`tokio_udp` / `tokio_tcp` respectively for `os: linux`. No fallback
to `tokio_uring` — that is opt-in only because of the kernel
version requirement.

---

## §4 `io_uring` fixed-buffer opt-in (Phase D.1)

ARCHITECTURE §9.5 row 3 documents the `io_uring + fixed buffers`
substrate as a Phase D.1 opt-in. The trait surface of §2 covers it
*without changes* — only the edge actions on the §5.E pool
lifecycle FSM transitions differ. This section documents the
mechanical mapping.

### §4.1 Pool slot lifecycle on `tokio_uring`

The same six-state pool lifecycle FSM (`free → cpu-mut →
dma-armed-rx → dma-busy-rx → cpu-ref → free`, RFC §5.E) applies.
Per-edge actions on `tokio_uring`:

| Edge | Action on MCU bare_metal | Action on linux+epoll | Action on linux+io_uring |
|---|---|---|---|
| `free → cpu-mut` | acquire static slot | `BytesMut::with_capacity` | take registered buffer index from free list |
| `cpu-mut → dma-armed-rx` | `cache_invalidate` (M7+) + DMA descriptor enqueue | (no action; BytesMut filled by `recv_from`) | submit `IORING_OP_READ_FIXED` sqe |
| `dma-armed-rx → dma-busy-rx` | DMA controller IRQ | (n/a — synchronous read) | (n/a — sqe in flight) |
| `dma-busy-rx → cpu-ref` | (no cache action — invalidate already done pre-arm) | (n/a — synchronous read) | cqe completion handler dispatches `Rx` event |
| `cpu-ref → free` | (no cache action — slot reused) | drop `BytesMut` | return registered buffer to free list |

The lifecycle FSM is *the* unifying abstraction: codegen emits the
same state-machine code; each row's runtime crate provides the
edge-action hooks. `pool/ownership-violation` and friends apply
identically to all three rows.

### §4.2 Registered buffer count check

`io_uring` requires fixed buffers to be registered up front (per
process). On the `tokio_uring` driver, codegen emits the
registration call from `deploy.yaml` `buffer_pools.<name>.slot_count`
× `slot_size` aggregated across all links bound to the runtime.

Build invariant (proposed for RFC §5.K, Phase D.1 entry):
`Σ pool.slot_count ≤ io_uring.max_registered_buffers` (default
1024 on kernel 5.10+, capped to runtime-detected ceiling).
Diagnostic `link/io-uring-buffer-registration-overflow` (hard
error). Phase A–C is unblocked on this — the diagnostic lands when
Phase D.1 opens.

### §4.3 Trait-surface invariance

Critically, neither §4.1 nor §4.2 changes the trait surface of §2.
Authors of `sources/*.scxml` write code that compiles *unchanged*
between epoll and io_uring rows. This is the design check that
ARCHITECTURE §9.5 promises: same SCXML, OS-native runtime crate
swaps the substrate.

---

## §5 Self-review against ARCHITECTURE §2.4 invariants

| Invariant | Check |
|---|---|
| 1. Static-first, dynamic-opt-in | ✓ Trait is fixed at codegen; driver is fixed by deploy.yaml; pool slot count is static per RFC §5.E |
| 2. Link drivers extensible (open set) | ✓ `LinkDriver` is a trait; new drivers (e.g. `tokio_uring` opt-in, future `tokio_quic` plugin) ship as additional impls. ARCHITECTURE §2.4 #2 directly satisfied |
| 3. Kinds are additive | ✓ This document does not introduce a new kind — it specifies the runtime crate that hosts the existing `link` kind (RFC §5.C) on `os: linux` |
| 4. Generated code exports as library | ✓ `sce_link_runtime_tokio` is a library crate; `out/ap/*.rs` consumes it via `Cargo.toml` dependency |
| 5. Platform gating only when necessary | ✓ Driver selection is `platform.os`-driven (RFC §5.J.3); SCXML body is OS-portable. The `tokio_uring` opt-in is the *only* MCU-class kind feature that requires a kernel-version gate, and that gate lives in the driver's runtime detection, not in codegen |
| 6. `out/` is SSoT-downstream | ✓ This document is `docs/`, not `out/` — produces no codegen artifacts |

---

## §6 Next-step scaffolding

This document unblocks (when Phase D.1 opens):

1. `sce_link_runtime_tokio` crate skeleton authoring against the
   §2 trait surface. Initial impls: `tokio_udp` + `tokio_tcp`.
   The `tokio_uring` impl ships behind a Cargo feature flag.
2. `out/ap/Cargo.toml` declares
   `sce_link_runtime_tokio = { path = "...", default-features = ["tokio_udp", "tokio_tcp"] }`.
3. SCE-side `(rust, linux, sce_link_runtime_tokio)` 3-tuple
   activation in the codegen `Language::Rust` arm (per RFC §5.J.3).

This document does NOT unblock anything during Phase A–C (MCU
priority track). The trait surface specified here is design-only
during MCU work; the OQ-W20 design pressure justifies authoring
the contract early so MCU-side decisions don't accidentally box
the AP runtime into an epoll-shaped corner.

**Cross-references for sibling Phase D.1 work** (when that phase
opens):

- `docs/runtime-crate-lwip.md` — the `(c11, bare_metal,
  sce_link_runtime_lwip)` analog. Same 6-event contract, expressed
  as a C11 header.
- `docs/intrinsics-runtime-symbols.md` — the
  `sce_intrinsics_runtime_rust` companion crate that provides
  platform intrinsics (atomics, fences, IRQ control if needed,
  RNG). On linux the cache-maintenance symbols collapse to no-ops;
  the rest are thin wrappers over `core::sync::atomic` and
  `getrandom`.

---

## §7 Change log

- **2026-05-01 후속** — initial draft. KICKOFF #2 of this session
  ("Runtime crate API stub design"). Companion docs:
  `runtime-crate-lwip.md` (C11 sibling), `intrinsics-runtime-
  symbols.md` (platform-intrinsics sibling). Trait surface fixed
  to four methods (`open` / `send` / `close` / `poll_event`) per
  OQ-W20 design pressure ("trait surface small enough that custom
  QNX-native runtime can re-implement"). `LinkEvent` enum locked
  to 6 variants matching `docs/session-fsm.md` §6 1:1. Trust-class
  compile-time gating mapped onto trait surface presence/absence
  (no runtime branches). io_uring opt-in shown to require zero
  trait-surface change (only pool lifecycle FSM edge actions
  differ — ARCHITECTURE §9.5 invariant maintained). Phase A–C
  authoring of MCU-side SCXML is unaffected; document is design-
  only during the priority track.
