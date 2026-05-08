# Scouting FSM — prose sketch

**Status.** Pre-implementation prose, derived from `docs/wire-spec-subset.md`
§3 (Scout/Hello row), `ARCHITECTURE.md` §2.1 (MVP scope), `docs/session-fsm.md`
§4 (scouting summary that this document expands), `docs/rfc-sce-protocol-
synthesis.md` §5.M (trust class machinery), and direct read of zenoh-pico
1.9.0 HEAD `3b3ab65` (`src/{session/scout.c, net/{session.c, primitives.c},
api/api.c, transport/multicast/{transport.c, lease.c, rx.c},
protocol/definitions/transport.c, session/interest.c,
transport/unicast/accept.c}` + `include/zenoh-pico/{api/{constants.h,
primitives.h}, config.h.in, protocol/definitions/transport.h,
session/interest.h}`). Mirrors the structure of `docs/reassembly-fsm.md`.
This document is the canonical prose stress-test of the scouting layer
before SCE Phase A authoring of `sources/session/scouting.scxml`.

**Scope.** Scout/Hello discovery layer that drives the `Init →
LinkOpening → Opening` outbound trigger of `docs/session-fsm.md` §2.2.
Three deploy-time modes (`active` / `passive` / `static`) and how each
maps onto zenoh-pico's single mechanism. Cross-references to the
network-layer Interest path closed in §3 (OQ-W3 answer). The multicast
*session* layer (Join + peer-table + per-peer state) is **not** in this
document — it lives in `session-fsm.md` §3 and is touched here only
where multicast scouting interacts with multicast session bring-up.

**Inputs (normative).**
- `docs/wire-spec-subset.md` §3 (Scout/Hello classified as Included),
  §8 (transport matrix; scouting on UDP multicast canonical / UDP unicast
  rare).
- `ARCHITECTURE.md` §2.1 (Transports row), §2.4 (extensibility
  invariants), §5 (source layout — `sources/session/scouting.scxml`).
- `docs/session-fsm.md` §2.2 (outbound `Init → LinkOpening → Opening`
  trigger), §2.6 (trust-class table), §3.4 (client+multicast OQ-W9 —
  closed by this document), §4 (scouting summary that this document
  supersedes), §5.2 (peer-vs-client divergence rooted in scouting).
- `docs/rfc-sce-protocol-synthesis.md` §5.K (deploy.yaml schema),
  §5.M (trust-class machinery applied here to scouting links).
- `deploy/{mcu_target,ap_standalone,ap_mcu_pair}.yaml` (the `scouting:`
  block + `links.udp_scout` block — already authored under OQ-W6/W8/W12
  closure).
- Upstream zenoh-pico 1.9.0 HEAD `3b3ab65` — authoritative reference
  for the *active* scouting body and for the absence of a
  *passive*/*static* zenoh-pico equivalent.

**Outputs.** (1) A legible state model for the three modes, with each
mode's body grounded in zenoh-pico file:line evidence (or explicitly
flagged as a watching-zenoh addition with rationale). (2) A concrete
answer to OQ-W3 (Interest semantics with no router present) — §3. (3)
A concrete answer to OQ-W9 (client+multicast session) — §6. (4) Two
new design gaps (G-SCT-1 passive mode justification, G-SCT-2
unsolicited Hello broadcaster) and one new open question (OQ-W23 —
passive mode deploy schema).

**Non-outputs.** SCXML source (blocked on Phase A), multicast session
peer-table state (covered by `session-fsm.md` §3), authoring of the
network-layer Interest FSM (declare_fsm.scxml is a sibling concern
sketched at arm's length here in §3.4).

---

## §1 Framing overview

### §1.1 Position and triggers

The scouting layer is **pre-session**. It has one job: turn an
abstract intention to join a Zenoh mesh ("I am a peer / client and I
need locators of other nodes I can session-handshake with") into a
concrete unicast endpoint that the session FSM (`session-fsm.md` §2.2)
can drive `Init → LinkOpening → Opening` against.

```
                    ┌──────────────────────────────────────────────┐
                    │ Application / SCE host                       │
                    │     "open session" call (or SCE startup)     │
                    └────────────────────┬─────────────────────────┘
                                         │ session-open requested
                                         ▼
                    ┌──────────────────────────────────────────────┐
                    │ ScoutingDispatcher (this document)           │
                    │   - mode = deploy.scouting.mode              │
                    │   - HelloPeerTable bounded-collection        │
                    │   - emits scout.hello.received(locators[])   │
                    └────────────────────┬─────────────────────────┘
                                         │ scout.hello.received
                                         ▼
                    ┌──────────────────────────────────────────────┐
                    │ Session FSM (session-fsm.md §2.2)            │
                    │   Init → LinkOpening → Opening (outbound)    │
                    └──────────────────────────────────────────────┘
```

**Inputs the scouting FSM consumes.**
- `deploy.scouting.{mode, timeout_ms, hello_max_peers}` — the mode
  enum and bounded-collection sizing (`deploy/mcu_target.yaml:260-265`,
  `deploy/ap_standalone.yaml:197-200`, `deploy/ap_mcu_pair.yaml:87-90,
  186-189`).
- `links.udp_scout` — the scouting link instance with
  `trust_class: untrusted` (`deploy/mcu_target.yaml:91-106`,
  `deploy/ap_standalone.yaml:86-96`, `deploy/ap_mcu_pair.yaml:52-60,
  151-159`).
- `connect=` / `listen=` deploy fields (where present) — used by the
  `static` mode to bypass scouting entirely.
- The local node's `zid` (16-byte ZenohID) and `whatami` (peer or
  client) — both compile-time constants from deploy at codegen time.

**Outputs the scouting FSM emits.**
- `scout.hello.received(zid, whatami, locators[])` — feeds session
  FSM's outbound `Init → LinkOpening` trigger. Mirrors the
  zenoh-pico path `_z_locators_by_scout` (`~/zenoh-pico/src/net/
  session.c:47-76`) → `_z_open_inner` (`~/zenoh-pico/src/net/
  session.c:138-155, 191-200`).
- `scout.timeout` — terminal "no peers found within
  `scouting.timeout_ms`"; the session-open caller decides whether to
  retry (passive mode), abort (active one-shot client), or fall through
  to `static` connect list (active-then-static fallback —
  watching-zenoh extension, see §1.4).
- `scout.hello.peer_table_full` — diagnostic; the
  `HelloPeerTable` bounded-collection rejected a Hello because it
  hit `hello_max_peers` capacity. Observability-only.

The scouting FSM never opens a session itself, never handshakes,
never participates in declaration routing. Those are the session FSM's
and the network-layer FSMs' concerns — the boundaries are clean by
construction.

### §1.2 Scout/Hello wire shape

Two messages, both classified Included in `wire-spec-subset.md` §3.

**Scout** (`_z_s_msg_make_scout(z_what_t what, _z_id_t zid)` at
`~/zenoh-pico/src/protocol/definitions/transport.c:419-428`).
Carries:
- `version: u8` — `Z_PROTO_VERSION` (the wire `0x09`, per
  [`wire-spec-subset.md`: Normative references](wire-spec-subset.md#0-normative-references)).
- `what: u8` bitmask — `Z_WHATAMI_ROUTER=0x01 | Z_WHATAMI_PEER=0x02 |
  Z_WHATAMI_CLIENT=0x04` (`~/zenoh-pico/include/zenoh-pico/api/
  constants.h:50-54`). Default `what=3` ("look for routers and peers,
  not clients") per `Z_CONFIG_SCOUTING_WHAT_DEFAULT` in
  `~/zenoh-pico/include/zenoh-pico/config.h.in:149`.
- `zid: 16 bytes` — sender's ZenohID. May be empty (`_z_id_empty()`)
  when the sender does not yet have a ZID (anonymous discovery).

**Hello** (`_z_s_msg_make_hello(z_whatami_t whatami, _z_id_t zid,
_z_locator_array_t locators)` at `~/zenoh-pico/src/protocol/
definitions/transport.c:431-445`). Carries:
- `version: u8` — same `Z_PROTO_VERSION`.
- `whatami: u8` — sender's role (single value, not a bitmask:
  `ROUTER=0x01` / `PEER=0x02` / `CLIENT=0x04`).
- `zid: 16 bytes` — sender's ZenohID.
- `locators: len-prefixed array<len-prefixed string>` — the
  endpoints at which the sender is reachable for unicast session.
  Empty allowed (the receiver may infer from the source UDP
  address — `~/zenoh-pico/src/session/scout.c:106-109` comments this
  as `@TODO`, currently inert).

**Default scouting transport.** UDP multicast group `224.0.0.224` port
`7446` (`Z_CONFIG_MULTICAST_LOCATOR_DEFAULT="udp/224.0.0.224:7446"` at
`~/zenoh-pico/include/zenoh-pico/config.h.in:133`). Unicast scouting
is also valid (the scout buffer is link-agnostic — see
`__z_scout_loop` `~/zenoh-pico/src/session/scout.c:29-140` which
opens a generic `_z_link_t`), but rare. `wire-spec-subset.md` §8
matrix marks scouting on UDP unicast as "rare", on UDP multicast as
"canonical".

**Default scout timeout.** `1000 ms`
(`Z_CONFIG_SCOUTING_TIMEOUT_DEFAULT="1000"` at
`~/zenoh-pico/include/zenoh-pico/config.h.in:141`); matches the
`deploy.scouting.timeout_ms: 1000` in all three deploy skeletons.

**Buffer size.** `SCOUT_BUFFER_SIZE = 32` bytes for Scout encoding
(`~/zenoh-pico/src/session/scout.c:27`), `Z_BATCH_UNICAST_SIZE` for
Hello reception (`scout.c:60`). `deploy/mcu_target.yaml:324` sets
`scout_rx_pool.slot_size: 256`, comfortably above the encoded Scout
upper bound (header + version + what + 16-byte zid ≈ 19 bytes).

### §1.3 Scouting link vs session link — distinct instances

The **scouting link** is a separate `link` kind instance from any
**session link**, even when both use UDP multicast on the same
address+port. The wire-spec table (`wire-spec-subset.md` §8) confirms
this: scouting framer ≠ session framer (`TransportMessageLowLatency`
on multicast session). zenoh-pico does not collapse them either —
`__z_scout_loop` opens a *temporary* `_z_link_t` for the scout call
and tears it down when the scout returns (`scout.c:54, 126`); the
multicast session transport opens its own `_z_link_t`
(`~/zenoh-pico/src/transport/multicast/transport.c:31-114`) lasting
for the session lifetime.

In watching-zenoh deploy, the two instances have **different
`trust_class` values**:

- `links.udp_scout.domain_attrs.trust_class: untrusted`
  (`deploy/mcu_target.yaml:106`, `deploy/ap_standalone.yaml:96`,
  `deploy/ap_mcu_pair.yaml:60, 159`).
- `links.udp_session.domain_attrs.trust_class: session_arming`
  (`deploy/mcu_target.yaml:120`, `deploy/ap_standalone.yaml:110`,
  `deploy/ap_mcu_pair.yaml:69-70, 168-169`).

This separation is mechanically defended by the `session-fsm.md` §2.6
trust-class table: `untrusted` links **never** spawn `Accepting.*`
states, so the scouting link cannot host a session handshake. Symmetric
defense on the reassembly side: `reassembly-fsm.md` §5 forbids
reassembly pool binding on `untrusted` links (a Scout/Hello message is
small and never fragments — the wire shape's len-prefixed locator
array is bounded by `hello_max_peers`).

### §1.4 Three modes and the zenoh-pico mapping

watching-zenoh's deploy.yaml `scouting.mode` enum has three values:
`active` / `passive` / `static`. zenoh-pico has **one** scouting
mechanism (active, single-shot), and two ways for sessions to skip
it (config-time `connect=` bypass; `listen=` accepts inbound). The
three-mode framing is therefore an **operational abstraction**, not a
parity requirement. Mapping:

| watching-zenoh mode | zenoh-pico mapping | Status |
|---|---|---|
| `active` | `_z_scout_inner(...exit_on_first=true|false, timeout)` 1-shot. `~/zenoh-pico/src/session/scout.c:142-165`, `~/zenoh-pico/src/net/session.c:69` (called with `exit_on_first=true` from `_z_open` no-locator fallback), or `~/zenoh-pico/src/api/api.c:822` (called with `exit_on_first=false` from public `z_scout()`). | **zenoh-pico parity (Included)** |
| `passive` | No direct equivalent — zenoh-pico has no daemon that listens for unsolicited Hello and feeds them to a peer-table. The closest analog is multicast peer Join (`~/zenoh-pico/src/transport/multicast/lease.c:184-199`, `Z_JOIN_INTERVAL=2500ms`), but Join is a session-layer concern, not scouting. | **deferred to Phase D+** (OQ-W23 closed 2026-05-01 후속 #5 — defer). Not in MVP `mode` enum. Rolling-deploy / late-arriving-peer scenarios are operator-ergonomics improvements, not zenoh-pico parity (ARCHITECTURE §2.0); they belong with the broader Phase D AP-platform work, not with the priority MCU parity track. See §2.4.2. |
| `static` | Scouting bypass — `connect=`/`listen=` config supplies locators directly, `_z_locators_by_config` returns non-empty, `_z_locators_by_scout` is never called (`~/zenoh-pico/src/net/session.c:174-189`, `87-118`). | **zenoh-pico parity (Included)**, but as a *non-event* — the scouting FSM is never instantiated when mode=static. |

**Why `passive` is deferred to Phase D rather than included in MVP.**
The reassembly-fsm.md §2.1 "Upstream-divergent generalization"
pattern establishes the discipline: when watching-zenoh extends
beyond zenoh-pico, the extension is **named, justified, and
segregated**. For `passive` mode the segregation goes one step
further — it is excluded from the MVP `mode` enum entirely. Three
reasons (ratified 2026-05-01 후속 #5):

1. **MVP = zenoh-pico parity** (ARCHITECTURE §2.0). zenoh-pico has
   no passive daemon (`scout.c:142-165` is single-shot active);
   adding one to MVP weakens the parity contract.
2. **YAGNI / scope discipline.** zenoh-pico applications handle
   rolling-deploy / late-peer scenarios by calling `z_scout()`
   again on a timer at the application layer. Documenting that
   pattern as the recommended workaround pre-Phase-D is honest
   and costs zero implementation.
3. **Reversibility asymmetry.** Adding `passive` later (additive
   enum row, additive deploy fields, additive SCXML region) is
   strictly cheaper than removing a shipped passive mode from a
   deployed schema. RFC review #14 already established the
   "pre-release forward-namespace 0" policy (`cookie_hmac_v2`
   reserved-state removal, `unix_socket`/`qnx_msg` namespace
   removal); `passive` follows the same discipline.

`mode` enum in MVP: **`{active, static}`**. `passive` lands when
a Phase D customer-driven need surfaces, alongside the broader
operator-ergonomics work (rolling deploys for AP fleets being a
Phase D AP-platform concern, not an MCU parity concern).

**Why `static` is parity even though zenoh-pico has no `mode=static`
config knob.** zenoh-pico's "I have explicit `connect=` URLs" config
is functionally identical to deploy.yaml `scouting.mode: static`;
the deploy field is just a more legible spelling of the same intent.
`session.c:87-118` `_z_locators_by_config` reads `connect`+`listen`
and short-circuits scouting when locators are present.

**`active` is the single mode where zenoh-pico file:line evidence
fully grounds the FSM body** — see §2.4.1 below for the literal trace
through `__z_scout_loop`. The other two modes derive their bodies
from `active` (passive = active-on-a-cadence) or from the scouting-
*absent* path (static = no FSM).

---

## §2 Scouting FSM

### §2.1 Hierarchy

ScoutingDispatcher composes one ModeSelector region with at most one
Active body region (instantiated only if mode ∈ {`active`, `passive`})
plus a HelloPeerTable bounded-collection. Codegen elides regions that
the deploy-time mode does not require — a `static` machine emits
ScoutingDispatcher as a near-empty stub, validating the
ARCHITECTURE §2.4 #5 "platform gating only when necessary" invariant
across modes too (mode-gating is the same discipline applied to deploy
attributes instead of platform.class).

```
ScoutingDispatcher (per scouting link, 1 instance)
  ├── ModeSelector       — reads deploy.scouting.mode at codegen time;
  │                        routes session-open requests per mode body.
  │                        Compile-time const, not runtime branch.
  │
  ├── Active             — instantiated iff mode ∈ {active, passive};
  │                        states Idle / Sending / AwaitingHello /
  │                        Cooldown. See §2.4.1.
  │
  └── HelloPeerTable     — bounded-collection<HelloEntry,
                           hello_max_peers>, keyed by zid.
                           Captures Hello replies for downstream
                           consumers (session-open chooses one;
                           passive mode caches across periods).
```

**Mode is a compile-time constant.** `deploy.scouting.mode` is read at
codegen time, not runtime. The emitted ScoutingDispatcher contains
only the regions the chosen mode requires. This matches zenoh-pico's
own discipline: the `Z_FEATURE_SCOUTING` macro
(`~/zenoh-pico/src/session/scout.c:25, 38`,
`~/zenoh-pico/src/net/primitives.c:78, 93`) is a compile-time gate;
when zero, `_z_scout_inner` becomes a stub that returns NULL
(`scout.c:166-178`). watching-zenoh emits the analogous selectivity at
the mode level.

**Why `HelloPeerTable` is per-dispatcher not per-mode.** All three
modes that produce Hello observations (active one-shot; passive
periodic; static synthesizes Hello-equivalents from deploy
`connect=`) feed the same downstream consumer (session FSM
`Init → LinkOpening`). Sharing the table avoids duplicating the
bounded-collection instance and keeps the consumer shape uniform.
Capacity is `deploy.scouting.hello_max_peers`
(`deploy/mcu_target.yaml:263 = 8`,
`deploy/ap_standalone.yaml:200 = 64`,
`deploy/ap_mcu_pair.yaml:90 = 8` MCU-half / `:189 = 64` AP-half).

**Why HelloPeerTable is not the multicast peer-table.** The
multicast *session* peer-table (`session-fsm.md` §3.1 PeerSweep,
backed by zenoh-pico's `_z_transport_peer_multicast_slist_t` per
`~/zenoh-pico/src/transport/multicast/transport.c:103, 178`) tracks
peers actively in a multicast *session* — Join sender, KeepAlive
refresher, lease victim. The scouting HelloPeerTable tracks peers
*observed during scouting* — it feeds session bring-up but does not
itself maintain liveness. They have different lifecycles (a peer can
be in HelloPeerTable but not in the multicast session peer-table if
the deploy is unicast-session-only) and different capacities
(`hello_max_peers` is typically smaller than `multicast_peer_table`
in deploy; MCU has 8 vs 8, AP has 64 vs 64 — equal sized today, but
they remain conceptually distinct so future asymmetric tunings work).

### §2.2 States — the union of all three modes

States actually used per mode are a subset of this list. The full set
is enumerated here so the SCXML hierarchy has a single reference.

| State | Used by mode(s) | Meaning | Entry action | Primary exit |
|---|---|---|---|---|
| `Idle` | active, passive | Waiting for session-open trigger (active) or for next period (passive) | None | `session_open.requested` (active) / `passive_period.elapsed` (passive) |
| `Sending` | active, passive | Encoding + transmitting one Scout frame on the scouting link | `scout_emit()` (encode + `link.send`) | `<immediate>` → `AwaitingHello` |
| `AwaitingHello` | active, passive | Polling the scouting link RX path for Hello replies until `scouting.timeout_ms` elapses | Arm `scout_timer = scouting.timeout_ms` | `hello.received` (loops back if `exit_on_first=false`) / `scout.timeout` |
| `Cooldown` | passive | Inter-period dwell — scouting is idle but the FSM is alive (vs Idle which means "no period scheduled") | Arm `cooldown_timer = scout_retry_interval_ms - scouting.timeout_ms` | `cooldown_timer.elapsed` → back to `Idle` (which immediately re-enters the period) |
| `Bypassed` | static | Mode marker — ScoutingDispatcher is alive but scouting-inert. Only emits synthetic `scout.hello.received` from deploy `connect[]` at startup | `synth_emit_from_deploy()` once | terminal (no transitions out) |

**`AwaitingHello` does not block session-open in active mode with
`exit_on_first=true`.** Per zenoh-pico `__z_scout_loop` `scout.c:121-
123`, the loop exits as soon as the first Hello is received when
`exit_on_first=true` — which is the path session-open takes
(`session.c:69` `_z_locators_by_scout` calls
`_z_scout_inner(..., exit_on_first=true)`). The public
`z_scout()` API path takes `exit_on_first=false`
(`api.c:822` `_z_scout(...)` → `primitives.c:79-92` → `_z_scout_inner`
indirectly with `exit_on_first=false` per the loop's `for` continuing
until timeout). The FSM models both: `exit_on_first` is a guard on
the `hello.received → Idle` transition vs the `hello.received →
AwaitingHello (loop)` transition.

### §2.3 Transitions

Active mode (mode ∈ {`active`, `passive`}, single Scout cycle):

```
Idle
  |-- event: session_open.requested  (active)
  |   OR  passive_period.elapsed     (passive)
  |       --------------------------> Sending

Sending
  |-- entry: encode Scout(what, zid)
  |          send on links.udp_scout
  |-- event: <immediate> ----------> AwaitingHello
  |-- event: link.tx_failed --------> Idle (diag: scout/tx-failed)

AwaitingHello
  |-- entry: arm scout_timer (scouting.timeout_ms)
  |-- event: hello.received(zid, whatami, locators)
  |     [guard: HelloPeerTable.has_capacity AND zid not in HelloPeerTable]
  |       --> HelloPeerTable.insert(...)
  |       --> emit scout.hello.received upward
  |       [guard: exit_on_first]
  |         --------------------------> Idle (active) / Cooldown (passive)
  |       [otherwise]
  |         (stay in AwaitingHello, continue receiving)
  |-- event: hello.received [guard: HelloPeerTable.full]
  |       --> drop, emit scout/hello.peer_table_full
  |       (stay in AwaitingHello)
  |-- event: hello.received [guard: zid already in table]
  |       --> refresh entry timestamp, drop duplicate emit
  |       (stay in AwaitingHello)
  |-- event: scout_timer.elapsed
  |       [guard: HelloPeerTable.is_empty]
  |         --> emit scout.timeout (no peers found)
  |         --------------------------> Idle (active) / Cooldown (passive)
  |       [otherwise]
  |         --------------------------> Idle (active) / Cooldown (passive)

Cooldown                                       (passive only)
  |-- entry: arm cooldown_timer (scout_retry_interval_ms - timeout_ms)
  |-- event: cooldown_timer.elapsed
  |       --------------------------> Idle (which re-emits passive_period.elapsed)
```

Static mode:

```
Bypassed                                       (mode=static)
  |-- entry (machine startup): for each locator in deploy.connect[]:
  |         emit scout.hello.received(zid=NULL, whatami=NULL, [locator])
  |         (NULL fields signal "synthesized; downstream skips zid match")
  |-- terminal: no transitions out
```

**Why `scout.hello.received` synthesis under `static`.** Downstream
consumers (session FSM `Init → LinkOpening`) expect a uniform event
shape regardless of how the locator was learned. Synthesizing keeps the
session FSM input contract stable across modes and matches zenoh-pico's
own treatment: `_z_locators_by_config` (`session.c:87-118`) returns a
`_z_string_svec_t locators[]` exactly like `_z_locators_by_scout`
(`session.c:47-76`), and `_z_open` (`session.c:157-200`) does not
branch on origin.

**Why `zid=NULL` is OK on synthesized events.** The session FSM's
outbound `Init` carries the *local* zid in the `InitSyn` per
session-fsm.md §2.2. The remote zid is learned during the handshake
(`InitAck` echoes the remote `whatami` and the cookie that becomes
the connection identity). The scouting-time zid is purely advisory —
useful for de-duplication in the HelloPeerTable but not load-bearing
for handshake correctness. Synthesizing `zid=NULL` cleanly signals
"de-dup is consumer's problem; treat each locator as fresh".

### §2.4 Mode-specific bodies

Each mode's body is grounded in upstream evidence (active) or
explicitly justified as a watching-zenoh addition (passive) or as a
non-event (static).

#### §2.4.1 Active

The Active body is **literally** zenoh-pico's `__z_scout_loop` body
(`~/zenoh-pico/src/session/scout.c:29-140`) lifted into states. The
mapping:

| Code line | FSM correspondence |
|---|---|
| `scout.c:35-48` (`_z_endpoint_from_string`, UDP scheme check) | Codegen-time validation of `links.udp_scout.bind`; not a runtime FSM action |
| `scout.c:51-54` (`_z_open_link`) | Codegen-time `link` kind binding to `udp_scout`; not runtime in our model (the scouting link is open for the lifetime of the scouting FSM, not per-scout) |
| `scout.c:57` (`_z_link_send_wbuf` of encoded Scout) | `Sending` state's entry action |
| `scout.c:60-62` (RX buffer setup, clock start) | `AwaitingHello` entry action (arm timer) |
| `scout.c:63` (`while elapsed < period`) | `AwaitingHello` self-loop until `scout_timer.elapsed` |
| `scout.c:65-72` (zbuf reset + recv) | RxDispatch on the scouting link's RX pool — handled by §5.E pool lifecycle, not by this FSM directly |
| `scout.c:73-78` (`_z_scouting_message_decode`) | codec kind on the scouting link (RFC §5.B); decode failure → drop + `scout/decode-failed` diagnostic, NOT terminate scouting |
| `scout.c:80-119` (`_Z_MID_HELLO` arm: extract `_version`, `_whatami`, `_zid`, `_locators`) | `AwaitingHello.hello.received` event with payload |
| `scout.c:121-123` (`exit_on_first` short-circuit) | Guard on the `AwaitingHello → Idle` transition |
| `scout.c:142-165` `_z_scout_inner` (`_z_wbuf_make`, `_z_s_msg_make_scout`, `_z_scouting_message_encode`) | Scout encoding; lives in the scouting codec (§5.B) — the FSM's `Sending` entry calls it as an `algorithm` (or `procedure`) and bytes are emitted via the link's TX pool |

**Public API split.** zenoh-pico has two callers of `_z_scout_inner`
with different `exit_on_first` values:

- `~/zenoh-pico/src/net/session.c:69` — called from `_z_locators_by_scout`
  with `exit_on_first=true`. This is the implicit-scout path during
  `_z_open` when no `connect=` / `listen=` locators exist.
- `~/zenoh-pico/src/api/api.c:822` (via `~/zenoh-pico/src/net/
  primitives.c:79-92` `_z_scout`) — called from public `z_scout()`
  with `exit_on_first=false`. The user wanted a callback fired for
  every Hello until timeout.

The watching-zenoh deploy.yaml `scouting.mode: active` expresses the
**implicit-scout** semantic (one Hello, take it, open session). A
future deploy field `scouting.exhaustive: true` would expose the
public-API semantic (collect all Hellos until timeout). Not in MVP —
this is captured under §8.2 as a watching-zenoh ergonomics question
distinct from OQ-W23 (passive mode).

#### §2.4.2 Passive — deferred to Phase D+

**Status.** **Deferred to Phase D+ (OQ-W23 closed 2026-05-01 후속
#5).** Not in MVP. The mode enum in MVP is `{active, static}`;
`passive` is *not* an accepted value and a deploy carrying
`scouting.mode: passive` fails with `deploy/scouting-mode-unknown`
(reusing the existing unknown-enum-value diagnostic family).

**Why deferred.** Three reasons (full rationale in §1.4 "Why
`passive` is deferred to Phase D rather than included in MVP"):

1. **MVP = zenoh-pico parity.** zenoh-pico has no passive daemon;
   adding one weakens parity (ARCHITECTURE §2.0).
2. **YAGNI.** Application-layer `z_scout()` retry is the
   zenoh-pico-equivalent pattern; documenting it as the
   recommended workaround pre-Phase-D is honest and zero-cost.
3. **Reversibility.** Adding `passive` later is additive (enum row
   + deploy fields + SCXML region). Removing a shipped passive
   mode would be a breaking schema change. Per RFC review #14
   "pre-release forward-namespace 0" policy, we land features
   when wired, not pre-reserve them.

**Workaround pre-Phase-D.** Applications that need rolling-deploy
or late-arriving-peer behavior call `session.open()` again on an
application-layer timer. The session-FSM `Init → LinkOpening →
Opening` retry path is unchanged; the scouting FSM stays
`mode: active` and gets re-triggered. This is the same pattern
zenoh-pico applications use today.

**Phase D+ scope (when this section lands).** When passive ships,
the body would be: identical to Active §2.4.1 except triggered by
`passive_period.elapsed` instead of `session_open.requested`,
followed by a `Cooldown` state (`scout_retry_interval_ms - scouting
.timeout_ms` dwell), with the `HelloPeerTable` persisting across
periods (entries age out via `hello_entry_lease_ms`). Three new
deploy fields would be required (`scout_retry_interval_ms`,
`scout_retry_jitter_pct`, `hello_entry_lease_ms`); jitter would
consume `sce_random_fill` (RNG primitive — see OQ-W15 (a) /
`docs/intrinsics-runtime-symbols.md` §2.5). The full schema lives
in OQ-W23 entry of the open-questions log for re-opening at Phase D
entry; at that time, this section's body is restored from that entry.

#### §2.4.3 Static

**Status.** zenoh-pico parity (Included), expressed as scouting-
absent. Body is one synthetic emission of `scout.hello.received` per
`deploy.connect[]` entry at machine startup; no further action.

**Mapping.** `_z_locators_by_config` (`~/zenoh-pico/src/net/session.c:
87-118`) returns the explicit `connect=` locator list verbatim;
`_z_open` (`session.c:157-189`) calls `_z_open_inner` against the
first locator, then (peer mode) `_z_new_peer` against the rest. The
locator origin is irrelevant once the list reaches `_z_open`.

**Why this is its own mode in deploy.yaml.** Three reasons:

1. **Diagnostic legibility.** A failed session-open under
   `mode: static` has different meaning ("the configured locators
   are wrong / unreachable") than under `mode: active` ("no peers
   were on the multicast group"). Distinct mode value distinct
   diagnostic.
2. **Codegen elision.** `mode: static` lets codegen omit the
   entire scouting link, the scout codec, and the scout buffer
   pool. On MCU this saves ≈1.5 KB SRAM (one bounded-collection +
   one buffer pool + one codec instance). For a static-only
   deploy (e.g. fixed AP↔MCU pair on a private LAN), this is
   real.
3. **Trust class clarity.** Under `static`, the locators come from
   the deploy file (trusted-by-construction). Under `active`/
   `passive`, locators come from the wire (untrusted source —
   §1.3, §6 trust composition). The mode value is the legible
   discriminator a deploy reviewer reads first.

**Interaction with `links.udp_session`.** Static mode does NOT skip
session-link setup — only scouting setup. `udp_session` is fully
authored, listens for incoming connections (peer mode, when
`listen=` is set), and opens outgoing connections (whenever
`connect[]` has unprocessed entries). The session FSM's
`Init → LinkOpening` runs identically under all three scouting
modes; only the *trigger* differs.

### §2.5 Timeouts and budgets

Single home for every scouting timer. Values come from
`deploy/{mcu_target,ap_standalone,ap_mcu_pair}.yaml`.

| Timer | Default | Source |
|---|---|---|
| `scouting.timeout_ms` | 1000 ms | `deploy.machines.<m>.scouting.timeout_ms` (matches `Z_CONFIG_SCOUTING_TIMEOUT_DEFAULT="1000"` `~/zenoh-pico/include/zenoh-pico/config.h.in:141`) |
| `link.scouting.open_timeout_ms` | 0 ms (always-on) | `deploy.machines.<m>.links.udp_scout.open_timeout_ms` already authored: `0` in all three deploy skeletons |

`scout_retry_interval_ms` / `scout_retry_jitter_pct` /
`hello_entry_lease_ms` are **deferred to Phase D+** with passive
mode (OQ-W23 closed 2026-05-01 후속 #5 — defer). They are not in
the MVP deploy schema; reintroducing them is part of the Phase D+
passive-mode landing.

### §2.6 Bounded-collection invariants

`HelloPeerTable` capacity = `deploy.scouting.hello_max_peers`. The
collection is keyed by `zid` (16 bytes); the value is `(whatami,
locators[], last_seen_ts)`.

**Invariant 1 (capacity vs peer_table).**
`hello_max_peers ≤ peer_table.capacity + multicast_peer_table.capacity`.
Rationale: every Hello-discovered peer eventually feeds either a
unicast session (peer_table consumer) or a multicast session entry
(multicast_peer_table consumer). Discovering more peers than the
session layer can hold is wasted work — the table will fill, the
overflow Hello will be dropped, and the discovered peer will never
reach session-open.

Verification:

- MCU: `hello_max_peers=8 ≤ peer_table=16 + multicast_peer_table=8 = 24`. ✓
- AP: `hello_max_peers=64 ≤ peer_table=256 + multicast_peer_table=64 = 320`. ✓

Build-time check: new diagnostic `scouting/hello-max-peers-exceeds-
peer-tables` (hard error). Authoring contract addition for
`deploy/` skeletons.

**Invariant 2 (slot_size vs Hello upper bound).**
`scout_rx_pool.slot_size ≥ HelloUpperBoundBytes(hello_max_peers)`.
The Hello message wire size is bounded by the locators field; with
`hello_max_peers=8` and a conservative per-locator length of 64
bytes, Hello upper bound ≈ `header(2) + version(1) + whatami(1) +
zid(16) + locators_len_prefix(2) + 8 × (locator_len_prefix(2) +
locator_str(64)) = 550 bytes`. MCU `scout_rx_pool.slot_size = 256`
(`deploy/mcu_target.yaml:324`) is **insufficient** under this
worst-case sizing — but realistically Hello carries 1–2 locators
per peer in MCU deploys, ≈ 100 bytes each, fitting 256 comfortably.

This is **G-SCT-3** (§8.1) — a sizing invariant that's not currently
authored as a build-time check. Conservative authors should bump
MCU `scout_rx_pool.slot_size` to 512 or 1024 if they expect peers
to advertise multiple locators (multi-homed AP). Tracked as
informational diagnostic `scouting/hello-slot-size-recommendation`,
not a hard error (the realistic case fits, only the worst case
breaks).

---

## §3 Interest와의 관계 — OQ-W3 closure

`wire-spec-subset.md` OQ-W3 asks: *"Peer A sends Interest{Future,
subscribers}; peer B has local DeclareSubscriber. Does B reply with
matched declares + DeclareFinal, or is this router-only in 1.x?"*

This document closes OQ-W3 because the same zenoh-pico read pass that
grounds the scouting body (§2.4.1) covers the Interest handler too,
and because the scouting layer is the *trigger chain* that decides
whether Interest will fire at all (active scouting → unicast
session-open → declaration push, or multicast scouting → multicast
session-open → Interest pull). Closing OQ-W3 here keeps the evidence
co-located.

### §3.1 Upstream evidence (file:line)

zenoh-pico distinguishes Interest handling by transport class. Three
mechanisms surfaced:

**Mechanism 1 — Unicast: Interest is a no-op; declaration sync
happens via unsolicited push at acceptor.**

`~/zenoh-pico/src/session/interest.c:531-535`:

```c
z_result_t _z_interest_process_interest(_z_session_t *zn,
        const _z_wireexpr_t *wireexpr, uint32_t id, uint8_t flags,
        _z_transport_peer_common_t *peer) {
    // Check transport type
    if (zn->_tp._type == _Z_TRANSPORT_UNICAST_TYPE) {
        return _Z_RES_OK;  // Nothing to do on unicast
    }
    ...
```

Under unicast, an inbound `Interest` is silently consumed — no
matched declares, no DeclareFinal. Symmetrically, an outbound
`Interest` from a unicast peer to its remote will land on the same
no-op (the remote returns `_Z_RES_OK` without sending any Declare).

Declaration knowledge instead crosses the unicast handshake via
**unsolicited push at session-establishment**:

`~/zenoh-pico/src/transport/unicast/accept.c:148-149`:

```c
if (new_peer != NULL) {
    (void)_z_interest_push_declarations_to_peer(
        _z_transport_common_get_session(&ztu->_common), (void *)new_peer);
    ...
```

The acceptor side, immediately after a successful 4-way handshake
admits a new peer, calls `_z_interest_push_declarations_to_peer`
(`~/zenoh-pico/src/session/interest.c:194-201`):

```c
z_result_t _z_interest_push_declarations_to_peer(_z_session_t *zn,
        void *peer) {
    _Z_RETURN_IF_ERR(_z_interest_send_decl_resource(zn, 0, peer, NULL));
    _Z_RETURN_IF_ERR(_z_interest_send_decl_subscriber(zn, 0, peer, NULL));
    _Z_RETURN_IF_ERR(_z_interest_send_decl_queryable(zn, 0, peer, NULL));
    _Z_RETURN_IF_ERR(_z_interest_send_decl_token(zn, 0, peer, NULL));
    _Z_RETURN_IF_ERR(_z_interest_send_declare_final(zn, 0, peer));
    return _Z_RES_OK;
}
```

All keyexpr / subscriber / queryable / token declarations + a
DeclareFinal are emitted toward the new peer, unsolicited. This is
the unicast **substitute for Interest**.

**Asymmetry note.** Only the *acceptor* pushes (the remote learns
the local's declares); the *initiator* does not symmetrically push
on its side. Mutual declaration knowledge in Z_FEATURE_UNICAST_PEER
deploys (where both ends listen) emerges because *each* role is the
acceptor on at least one of the two unicast peer flows.

**Mechanism 2 — Multicast: Interest is fully peer-handled.**

Continuing `~/zenoh-pico/src/session/interest.c:531-569`, after the
unicast no-op:

```c
    // Push a join in case it's a new node
    _Z_RETURN_IF_ERR(_zp_multicast_send_join(&zn->_tp._transport._multicast));
    ...
    // Current flags process
    if (_Z_HAS_FLAG(flags, _Z_INTEREST_FLAG_CURRENT)) {
        if (ret == _Z_RES_OK && _Z_HAS_FLAG(flags, _Z_INTEREST_FLAG_KEYEXPRS)) {
            ret = _z_interest_send_decl_resource(zn, id, NULL, restr_key_opt);
        }
        if (ret == _Z_RES_OK && _Z_HAS_FLAG(flags, _Z_INTEREST_FLAG_SUBSCRIBERS)) {
            ret = _z_interest_send_decl_subscriber(zn, id, NULL, restr_key_opt);
        }
        if (ret == _Z_RES_OK && _Z_HAS_FLAG(flags, _Z_INTEREST_FLAG_QUERYABLES)) {
            ret = _z_interest_send_decl_queryable(zn, id, NULL, restr_key_opt);
        }
        if (ret == _Z_RES_OK && _Z_HAS_FLAG(flags, _Z_INTEREST_FLAG_TOKENS)) {
            ret = _z_interest_send_decl_token(zn, id, NULL, restr_key_opt);
        }
        // Send final declare
        _Z_SET_IF_OK(ret, _z_interest_send_declare_final(zn, id, NULL));
    }
```

Under multicast, an inbound `Interest{CURRENT, <flags>}` triggers
matched-declare emission for each enabled flag plus a DeclareFinal.
This is **router-not-required** — the responding node is a peer.

The pull side: when a multicast peer joins (or when an existing
peer accepts a new transport), it sends an `Interest` to fetch
existing declares. `~/zenoh-pico/src/net/session.c:149-153`:

```c
#if Z_FEATURE_MULTICAST_DECLARATIONS == 1
    if (zn->_tp._type == _Z_TRANSPORT_MULTICAST_TYPE) {
        ret = _z_interest_pull_resource_from_peers(zn);
    }
#endif
```

`_z_interest_pull_resource_from_peers` at
`~/zenoh-pico/src/session/interest.c:203-214`:

```c
z_result_t _z_interest_pull_resource_from_peers(_z_session_t *zn) {
    uint32_t eid = _z_get_entity_id(zn);
    uint8_t flags = _Z_INTEREST_FLAG_KEYEXPRS | _Z_INTEREST_FLAG_CURRENT;
    _z_interest_t interest = _z_make_interest(NULL, eid, flags);
    _z_network_message_t n_msg;
    _z_n_msg_make_interest(&n_msg, interest);
    z_result_t ret = _z_send_n_msg(zn, &n_msg, Z_RELIABILITY_RELIABLE,
                                   Z_CONGESTION_CONTROL_BLOCK, NULL);
    ...
}
```

Reliable, blocking-congestion `Interest{CURRENT, KEYEXPRS}` to all
multicast peers. Each peer then runs Mechanism 2 above, replying
with its current keyexpr declares + DeclareFinal.

**Mechanism 3 — Client mode unicast to router: router-only path.**

Client mode opens a unicast session to a router (whatami=ROUTER).
Same `accept.c:148-149` push triggers on the router side (the
client learns the router's view, which aggregates declares from
the whole network). Without a router in the topology, a client
cannot use this mechanism — there is no acceptor that aggregates.

This is the *only* topology in which OQ-W3's "router-only" framing
applies. It is a deliberate Zenoh design choice: clients delegate
declaration aggregation to routers.

### §3.2 OQ-W3 answer

**Closed (2026-05-01).** *Not router-only* in 1.x. Three transport-
class-specific mechanisms achieve the same end-state (peer learns
remote declares):

| Topology | Mechanism | Trigger | Wire artifact |
|---|---|---|---|
| Unicast peer-peer | Mechanism 1: acceptor pushes ALL local declares + DeclareFinal at handshake completion | `accept.c:148-149` after successful Init/Open | DeclareKeyExpr / DeclareSubscriber / DeclareQueryable / DeclareToken / DeclareFinal (all unsolicited) |
| Multicast peer mesh | Mechanism 2 (pull): joining peer sends Interest{CURRENT, KEYEXPRS}; each remote peer replies with matched declares + DeclareFinal | `session.c:151` `_z_interest_pull_resource_from_peers` at session open; reply at `interest.c:546-566` | Interest → Declare* → DeclareFinal |
| Client unicast to router | Mechanism 1 (router-side) | router's `accept.c:148-149` on client connection | same as unicast peer-peer (router pushes its aggregated declares to client) |
| Client unicast no router | **Not supported** | — | Mechanism 1 absent (no acceptor); Mechanism 2 absent (client doesn't multicast); Interest message inbound on client → unicast no-op |

**Implication for watching-zenoh MCU.** The MCU's `Interest` handler
is **a real participant** (Included) on the multicast peer-mesh path
— Mechanism 2 above — and **a no-op** on the unicast path
(Mechanism 1 covers the same need without Interest). MCU peers in
multicast deploys must implement both directions (pull at session
open; reply on inbound Interest). MCU peers in unicast-only deploys
implement only the acceptor-side declaration push at handshake.

This is consistent with `wire-spec-subset.md` §5 row "Interest" being
classified Included (bounded form) and §5.2 calling out *aggregation*
across N peers as Permanent on MCU — the bounded form is each peer
matching against its own local declared-subscription bounded
collection (`bounded-collection<DeclareSubscriber, deploy.limits.
local_subscriptions>`).

### §3.3 Implication for the scouting FSM

The scouting FSM does **not** participate in Interest at all. The
Interest path is downstream of session-establishment. But the
scouting mode determines **which Interest mechanism fires**:

- `mode: active` → leads to a unicast session-open against a
  scouted peer → **Mechanism 1** (acceptor push at handshake).
- `mode: passive` → if multicast-session-capable peer, the discovered
  peer eventually joins the multicast session → **Mechanism 2**
  (pull at session join + multicast Interest reply).
- `mode: static` + `connect=` listed peers → same as `active` for
  the resulting unicast handshake (Mechanism 1).

So the scouting FSM is the *trigger chain*. Its mode choice flows
through to which Interest mechanism the runtime ends up exercising.
This is captured here so that future authors of `declare_fsm.scxml`
have a single doc to consult for the Interest-trigger boundary.

### §3.4 What declare_fsm.scxml must implement (for cross-ref)

Out of scope for this document; listed for completeness:

- **Outbound at session open (multicast only):** Send
  `Interest{CURRENT, KEYEXPRS}` per `session.c:149-153`.
- **Outbound at handshake-complete (unicast acceptor only):** Send
  all locally-declared resources + subscribers + queryables + tokens
  + DeclareFinal per `accept.c:148-149`.
- **Inbound on Interest receive (multicast only, transport-class
  guarded):** Match against local declared-* tables; emit matched
  declares with the inbound interest's id, plus DeclareFinal.
  Unicast Interest receive is a no-op per `interest.c:534-535`.

The transport-class guard at the top of the receive handler is the
mechanical knob that keeps watching-zenoh's `declare_fsm.scxml`
parity-correct. Surfacing it here so the author of that SCXML does
not re-derive it.

---

## §4 deploy.yaml scouting subsection cross-reference

### §4.1 Fields actually present (3 deploy files)

| Field | mcu_target | ap_standalone | ap_mcu_pair | Source / OQ |
|---|---|---|---|---|
| `scouting.mode` | `active` | `active` | mcu=`active`, ap=`active` | Authored under OQ-W6 closure (2026-05-01) |
| `scouting.timeout_ms` | 1000 | 1000 | 1000 / 1000 | Matches `Z_CONFIG_SCOUTING_TIMEOUT_DEFAULT="1000"` `config.h.in:141` |
| `scouting.hello_max_peers` | 8 | 64 | 8 / 64 | OQ-W8 (asymmetric MCU vs AP) |
| `links.udp_scout.bind` | `224.0.0.224:7446` | `224.0.0.224:7446` | same / same | Matches `Z_CONFIG_MULTICAST_LOCATOR_DEFAULT="udp/224.0.0.224:7446"` `config.h.in:133` |
| `links.udp_scout.driver` | `lwip_udp` | `tokio_udp` | `lwip_udp` / `tokio_udp` | Per-class (MCU lwIP, AP tokio) |
| `links.udp_scout.mtu_bytes` | 1472 | 1472 | 1472 / 1472 | IPv4 UDP over Ethernet |
| `links.udp_scout.expected_p99_bytes` | 256 | 256 | 256 / 256 | Scout/Hello are small |
| `links.udp_scout.burst_pps` | 50 | 500 | 50 / 500 | MCU 10× lower than AP |
| `links.udp_scout.rx_dispatch` | `isr_to_pool` | `worker_tick` | per-class | MCU vs AP scheduler |
| `links.udp_scout.open_timeout_ms` | 0 | 0 | 0 / 0 | always-on link |
| `links.udp_scout.domain_attrs.trust_class` | `untrusted` | `untrusted` | `untrusted` / `untrusted` | §1.3 / §6 |
| `buffer_pools.scout_rx_pool.slot_count` | 8 | 32 | 8 / 32 | Burst absorption (§5) |
| `buffer_pools.scout_rx_pool.slot_size` | 256 | 512 | 256 / 512 | ≥ Hello upper bound (§5, G-SCT-3) |

All 13 fields are mechanically present and pass codegen (build
proceeds without diagnostic) under the active-only deploy. The
symmetry across three deploy files is the canonical pattern for
sibling deploys (the asymmetric AP+MCU pair shares everything except
class-specific values).

### §4.2 Passive-mode deploy fields — deferred to Phase D+

OQ-W23 closed 2026-05-01 후속 #5 with **defer to Phase D+** (rationale
§1.4 + §2.4.2). The three deploy.yaml fields originally proposed for
passive mode (`scout_retry_interval_ms` / `scout_retry_jitter_pct` /
`hello_entry_lease_ms`) are **not** in the MVP schema. They land
together with the passive-mode SCXML body and the `mode: passive`
enum row when Phase D+ ergonomics work begins.

The proposed defaults (`30000 ms` / `25 %` / `5 × interval`) are
preserved in the OQ-W23 entry of `docs/rfc-open-questions-log.md`
for re-opening at Phase D+ entry.

### §4.3 Multicast locator overridability — already handled

Note: there is **no** `scouting.multicast_locator` field at the
`scouting:` block level. The override is via the `links.udp_scout.
bind` field, which all three deploy files set explicitly. This
matches zenoh-pico's `Z_CONFIG_MULTICAST_LOCATOR_KEY` config-bag
mechanism (`config.h.in:130-133`) — the locator is a property of the
scouting transport, not of the scouting algorithm. No new field
needed; the `bind` value already serves the override.

### §4.4 `scouting.what` (Scout's `what` bitmask) — not yet authored

The `what` bitmask Scout carries (`Z_WHATAMI_{ROUTER,PEER,CLIENT}`)
defaults to `3` per `Z_CONFIG_SCOUTING_WHAT_DEFAULT="3"`
(`config.h.in:149`) — peer searches for routers and peers, not for
clients. **No deploy.yaml field exposes this today.** For MVP this
is fine (the default is sensible: peer/MCU looks for routers + peers;
clients look for routers — but client-mode scouting is Phase B+
deferred). Tracked here as observation only, no OQ:

> If a future deploy needs to scout for clients (e.g. an AP node
> that tracks client liveness for diagnostic purposes), add
> `scouting.what` enum field. Until then, leave the default
> `what=3` hardcoded into the scouting codec at compile time.

---

## §5 Build-time analysis

Three quantitative checks the build runs against the scouting
deploy fields. Pattern matches `reassembly-fsm.md` §7 (four checks
on fragmentation invariants).

### §5.1 Burst absorption (RX pool sizing)

Per RFC §5.E "Burst absorption analysis (RX pools)" (RFC §5.K
`rx_dispatch` field gates the formula).

Under `rx_dispatch: isr_to_pool` (MCU): `slot_count ≥ burst_pps ×
max_handler_latency_us / 1M × 2.0`.

- MCU: `50 pps × 100 µs / 1M × 2.0 = 0.01` → ceil to 1; deploy has 8
  for headroom against bursts during initial discovery (multiple peers
  Hello-replying in the same `scouting.timeout_ms` window). ✓

Under `rx_dispatch: worker_tick` (AP): `slot_count ≥ burst_pps ×
tick_period_us / 1M × 2.0`.

- AP: `500 pps × 1000 µs / 1M × 2.0 = 1` → ceil; deploy has 32 for
  multi-peer discovery storms in larger meshes. ✓

The MCU value (8 vs computed minimum 1) is intentionally conservative
because Scout/Hello bursts during AP-restart-storm scenarios can
easily exceed the steady-state `burst_pps=50`. The build emits this
as informational `scouting/rx-pool-overprovisioned-vs-burst-pps`
when the ratio exceeds 4×; not a hard error.

### §5.2 hello_max_peers vs peer-table invariant

`hello_max_peers ≤ peer_table.capacity + multicast_peer_table.capacity`
(see §2.6 invariant 1).

- MCU: `8 ≤ 16 + 8 = 24`. ✓
- AP: `64 ≤ 256 + 64 = 320`. ✓

New diagnostic `scouting/hello-max-peers-exceeds-peer-tables` (hard
error) — proposed in this document, to be added to RFC §5.M's
diagnostic list under §9.2 below.

### §5.3 scout_rx_pool.slot_size ≥ Hello upper bound

`slot_size ≥ HelloUpperBoundBytes(hello_max_peers, max_locator_str_len)`.

The realistic-case Hello (1–2 locators per peer, ~80 bytes each):

- MCU: `expected = 19 (header+version+what+zid) + 2 (locators_len) +
  2 × (2 + 80) = 185 bytes`. `slot_size = 256` ≥ 185. ✓
- AP: same expected ≈ 185 bytes. `slot_size = 512` ≥ 185. ✓

The worst case (multi-homed AP with 8 advertised locators of 64
bytes each):

- MCU: `expected = 19 + 2 + 8 × (2 + 64) = 549 bytes`. `slot_size =
  256` < 549. ✗ (worst case fails)
- AP: `expected = 549`. `slot_size = 512` < 549. ✗ (worst case fails)

The current deploy values fit realistic peers but not adversarial-
sized locators. Tracked as **G-SCT-3** (§8.1) with a recommended
build-time informational diagnostic (`scouting/hello-slot-size-
recommendation`) — the realistic case is the documented assumption,
the worst case is a hardening upgrade if deploys experience
oversized Hello drops.

The choice between hard error and informational matches the policy
trade-off elsewhere in the codebase: realistic-case sizing is the
ergonomic default; authors who anticipate multi-homed peers raise
`scout_rx_pool.slot_size` themselves.

---

## §6 Trust-class composition (cross-ref RFC §5.M and session-fsm §2.6)

### §6.1 Per-link trust class table (extension of session-fsm.md §2.6)

| `trust_class` | Scouting role | Session role | Reassembly role |
|---|---|---|---|
| `untrusted` | **required on scouting links** (Scout/Hello-only; never spawns Accepting; never carries handshake) | forbidden (Accepting.* would expose unauthenticated FSM allocation to spoofed sources) | forbidden (`reassembly-fsm.md` §5) |
| `session_arming` | **forbidden on scouting links** (handshake bearing, anti-flood gates required; Scout/Hello has neither) | required on listener links | forbidden |
| `established_session` | forbidden on scouting links (post-handshake-only is incompatible with discovery's pre-session role) | required on data-plane links | required (`reassembly-fsm.md` §5) |

The mechanical defenses across the three layers compose:

1. **At the wire.** `links.udp_scout.domain_attrs.trust_class:
   untrusted` (`deploy/mcu_target.yaml:106`, etc.) is the deploy-time
   declaration. RFC §5.K validates the link kind on this field.
2. **At session-fsm.** §2.6 trust-class table refuses to attach
   `Accepting.*` to `untrusted` links — the build emits no
   accept-side hardening (`session_arming_quota` etc.) for the
   scouting link. Per `session-fsm.md` §2.6 row 1 ("Listener attaches
   `Accepting.*`? No"), this is the canonical refusal.
3. **At reassembly-fsm.** §5 row 1 forbids reassembly pool binding on
   `untrusted` links — diagnostic
   `reassembly/untrusted-link-binding` (hard error). Combined with
   the wire-level fact that Scout/Hello messages are small (≤ ~256
   bytes realistic, ≤ 549 worst-case-multi-locator) and never
   fragment, this is belt-and-braces: even if a malicious peer
   crafted a "fragmented" Scout, the reassembly path refuses to
   bind, and the codec layer would reject a Scout-typed message
   that arrived with a Fragment header anyway.

### §6.2 Why `untrusted_source: true` is irrelevant to scouting

`session-fsm.md` §2.6 introduces `domain_attrs.untrusted_source: true`
to flag listener links exposed to a network the deploy does not
control (public Internet, untrusted LAN). Under this flag,
`session_arming` links must enable `stateless_accept:
cookie_hmac_sha256`.

**Scouting links never carry this flag.** `untrusted_source: true`
applies to `session_arming` listeners; scouting links are
`untrusted` (a strictly weaker trust class — no FSM allocation
ever happens, so no flood vector exists). The deploy.yaml schema
should reject `untrusted_source: true` on `trust_class: untrusted`
links with `deploy/untrusted-source-on-untrusted-link` (proposed
diagnostic — minor RFC §5.K patch, see §9.3).

### §6.3 Scouting attack surface (concrete)

The scouting link's attack surface is well-bounded:

| Threat | Defense | Evidence |
|---|---|---|
| Spoofed Scout from arbitrary IP | Scout has no state effect on the receiver beyond "decode and reply with Hello"; reply is to the Scout's source address (UDP multicast group recipients all see the Scout, but the Hello reply is unicast back to the source — `_z_link_send_wbuf` at `scout.c:57` uses the scout's `_z_link_t` which captures the source). Attacker pays the cost of running a UDP listener at the spoofed address to receive the Hello. | `scout.c:57` send target; no state mutation in the receiver |
| Spoofed Hello from arbitrary IP | The receiver inserts into HelloPeerTable (bounded), then the session-open path `Init → LinkOpening` against the locator the spoofed Hello carried. Attacker can poison the HelloPeerTable up to its capacity (`hello_max_peers=8` MCU, `64` AP). The session handshake will fail against a non-listening attacker locator (`link.open_timeout` after `5 s`); the slot is freed when the locator is consumed. Cost to attacker: must keep N spoofed identities active; bounded by HelloPeerTable size. | session-fsm.md §2.5 `link.open_timeout: 5 s` |
| Hello flood (table fill) | HelloPeerTable rejects beyond `hello_max_peers`, emits diagnostic | §2.6 invariant 1, §2.3 `peer_table_full` branch |
| Scouting RX pool exhaustion | RX pool is sized per §5.1 burst absorption; overflow is a `link.rx_dropped` per §5.E lifecycle. The scout layer's reaction is "next iteration"; no FSM state corruption. | RFC §5.E pool ownership FSM |
| Malformed Scout/Hello (codec error) | Scouting codec rejects per RFC §5.B invariants; diagnostic `scout/decode-failed`; FSM stays in `AwaitingHello` (does not propagate codec error to session FSM) | `scout.c:73-78` `_z_scouting_message_decode` error path |

The combination — Scout/Hello stateless on the receiver, bounded
HelloPeerTable, session-fsm refuses Accepting.* on untrusted, and
`link.open_timeout` bounds the cost of pursuing a spoofed locator —
is the textbook composition: each layer rejects a specific class of
attack, and the build refuses to emit a deploy that disables any
layer (the trust_class field cannot be raised to `session_arming` on
a scouting link without authoring `accept_rate_per_sec` etc., which
makes no semantic sense for Scout/Hello).

### §6.4 OQ-W9 closure (client+multicast session)

`docs/session-fsm.md` §3.4 raised OQ-W9: *"Does zenoh-pico in client
mode ever join a multicast session?"* The answer is mechanically
in the same multicast transport file the scouting body cites:

`~/zenoh-pico/src/transport/multicast/transport.c:153-162`:

```c
z_result_t _z_multicast_open_client(_z_transport_multicast_establish_param_t *param,
        const _z_link_t *zl, const _z_id_t *local_zid) {
    _ZP_UNUSED(param);
    _ZP_UNUSED(zl);
    _ZP_UNUSED(local_zid);
    _Z_ERROR_LOG(_Z_ERR_CONFIG_UNSUPPORTED_CLIENT_MULTICAST);
    z_result_t ret = _Z_ERR_CONFIG_UNSUPPORTED_CLIENT_MULTICAST;
    // @TODO: not implemented
    return ret;
}
```

Symmetric peer-side at the same file `transport.c:116-151`
`_z_multicast_open_peer` — fully implemented, emits Z_JOIN with
`whatami=Z_WHATAMI_PEER`.

**OQ-W9 closed (2026-05-01).** zenoh-pico clients do NOT participate
in multicast *sessions*. Clients DO participate in multicast
*scouting* (the scouting layer is whatami-agnostic per `_z_s_msg_make_scout`
`transport.c:419-428` — the `what` bitmask filters which kinds of
peers the client wants to find, not how the client is addressed).
This locks in the deploy.yaml shape:

| Mode | scouting multicast | session multicast |
|---|---|---|
| `whatami=peer` | OK (active/passive/static all valid) | OK (`_z_multicast_open_peer`) |
| `whatami=client` | OK (active/passive/static all valid) | **Refused** (`_Z_ERR_CONFIG_UNSUPPORTED_CLIENT_MULTICAST`) |

watching-zenoh codegen must enforce: if `deploy.machines.<m>.whatami:
client` AND a `links.udp_session_multicast` (or any multicast link
with `role: session`) is declared, the build rejects with new
diagnostic `deploy/client-multicast-session-unsupported` (hard error).
This is a small RFC §5.K addition; see §9.4.

`session-fsm.md` §3.4 needs a one-line amendment moving OQ-W9 from
"open" to "answered, see scouting-fsm.md §6.4". Action item in §9.

---

## §7 Self-review of §6 trust composition

A focused check that §6 composition is internally consistent before
the design-gap section enumerates remaining holes.

- **Composition is conjunctive, not disjunctive.** The three defenses
  in §6.1 (wire trust_class field, session-fsm Accepting refusal,
  reassembly binding refusal) all fire independently. No single
  layer's failure compromises the others. ✓
- **No "scouting hardening" knob duplicates session-arming knobs.**
  Scouting has no `scout_arming_quota` or `scout_rate_per_sec` — it
  doesn't allocate FSM state per source, so the analogous threats
  are absent. The authoring contract refuses to mix the two
  hardening surfaces (see §6.2 schema-validation rule). ✓
- **Trust class is symmetric across local emit and remote receive.**
  Local emits Scout via `untrusted` link; remote receives Scout
  via its own `untrusted` link. Neither side allocates state past
  the bounded RX pool slot and the HelloPeerTable. ✓
- **OQ-W9 closure is decoupled from the scouting trust composition.**
  `_z_multicast_open_client` returning UNSUPPORTED is a *session*-
  layer fact (which whatami values can run a multicast session); it
  does not change scouting's trust class on the same `udp_scout`
  link. A client-mode peer running active scouting is still
  legitimate — the build refuses only the multicast session, not
  the multicast scout. ✓
- **One residual asymmetry to track.** The deploy.yaml schema does
  not currently emit a diagnostic when a `whatami=client` deploy
  pairs with a multicast scouting link that *advertises* Scout-
  client-only (`what & Z_WHATAMI_CLIENT` set). The wire is not
  meaningfully different — Scout's `what` is a filter on what the
  *replier* should be — but a client looking for clients is
  topologically suspicious (peer-to-peer client mesh has no
  declaration aggregator). This is below the bar for a hard error
  (the wire is well-formed, just unusual); informational diagnostic
  `scouting/client-looking-for-clients` proposed under §9.

---

## §8 Design gaps + new open questions

### §8.1 Authoring-contract gaps

- **G-SCT-1 — Passive mode justification + deploy schema.**
  **Resolved (2026-05-01 후속 #5).** OQ-W23 (a) closed with
  *defer to Phase D+*. Rationale: MVP = zenoh-pico parity
  (ARCHITECTURE §2.0); zenoh-pico has no passive scouting; adding
  it in MVP weakens parity with no offsetting Phase A–C benefit.
  Application-layer `z_scout()` retry is the parity-equivalent
  workaround, costless to document. Adding `passive` later is
  additive (RFC review #14 "pre-release forward-namespace 0"
  policy). G-SCT-1 marked resolved; OQ-W23 marked answered/deferred.
  Phase A SCXML authoring of `sources/session/scouting.scxml`
  proceeds for `mode: {active, static}` only.

- **G-SCT-2 — Unsolicited Hello broadcaster.** zenoh-pico has no
  daemon that emits Hello unsolicited (only as reply to a received
  Scout — `scout.c:80-119` is the receive path; `_z_s_msg_make_hello`
  is called only from there). Multicast peer announcement is
  Z_JOIN, not Hello — different wire shape. Question: does
  watching-zenoh need an unsolicited-Hello broadcaster, e.g. for a
  scouting-only deploy where a node wants to be discoverable
  without participating in a multicast session?
  - **Why:** The deploy `scouting.mode` enum currently maps
    `passive` to "periodic Scout emit" (the *querier* role), not to
    "periodic Hello emit" (the *announcer* role). A symmetric
    announcer mode would be a third axis. With multicast Z_JOIN
    handling the announcer role for multicast-session-capable
    peers, the residual case is *unicast-session-only nodes that
    want to be discoverable*. This is operationally rare (such a
    node would normally use a static deploy with
    well-known ports), but not impossible.
  - **How to apply:** Defer until a deploy scenario requires it.
    Authoring-contract gap: noted, no OQ filed (insufficient
    evidence that a real deploy needs this; speculative addition
    would violate ARCHITECTURE §2.4 invariant #1's spirit).
  - **Blocks:** Nothing concretely; speculative.

- **G-SCT-3 — `scout_rx_pool.slot_size` worst-case sizing.** §5.3
  shows realistic Hello fits comfortably but worst-case (8 locators
  × 64 bytes) overflows the 256-byte MCU `slot_size` and the
  512-byte AP `slot_size`. Currently no build-time check.
  - **Why:** Multi-homed AP peers (typical edge node with both
    Ethernet and Wi-Fi) can advertise 4+ locators legitimately,
    bringing the realistic case to 300-400 bytes. The threshold
    margin is uncomfortably tight on MCU.
  - **How to apply:** Informational diagnostic
    `scouting/hello-slot-size-recommendation` emitting when
    `slot_size < HelloUpperBound(hello_max_peers, 8 locators × 64
    bytes)`. The realistic case stays the documented assumption;
    deploys facing oversized peers raise `slot_size` with the
    diagnostic as guide.
  - **Blocks:** Informational only — no blocker. Recommended as
    a §5.K patch (see §9.3 below).

### §8.2 New open questions

- **OQ-W23 — Passive scouting mode justification + schema.**
  **Answered, deferred to Phase D+ (2026-05-01 후속 #5).** Decision
  rationale: MVP = zenoh-pico parity (ARCHITECTURE §2.0); passive
  has no zenoh-pico equivalent; application-layer `z_scout()` retry
  is the parity-aligned workaround; reversibility asymmetry favors
  defer-then-add over ship-then-remove. The proposed (b) defaults
  (`30000` / `25` / `5 × interval`) are preserved in the OQ-W23
  entry of `docs/rfc-open-questions-log.md` for re-opening at Phase
  D+ entry. No remaining authoring blocker on the scouting side
  for MVP modes (`active`, `static`).

- **OQ-W3 — closed in §3.2 of this document.** Cross-ref pointer
  added to `docs/rfc-open-questions-log.md` OQ-W3 entry with status
  `open → answered`. Resolution: not router-only in 1.x; three
  transport-class-specific mechanisms achieve declaration sync
  (unicast acceptor push, multicast Interest reply, client-router
  push). Evidence: `interest.c:531-535` (unicast no-op), `interest.c:546-566`
  (multicast reply), `interest.c:194-201` (push body), `accept.c:148-149`
  (push trigger), `session.c:149-153` + `interest.c:203-214`
  (multicast pull at session open).

- **OQ-W9 — closed in §6.4 of this document.** Cross-ref pointer
  added to `docs/rfc-open-questions-log.md` OQ-W9 entry with status
  `open → answered`. Resolution: zenoh-pico clients do NOT do
  multicast sessions (`transport.c:153-162` returns
  `_Z_ERR_CONFIG_UNSUPPORTED_CLIENT_MULTICAST`); they DO do
  multicast scouting (whatami-agnostic). Build-time enforcement
  needed: new diagnostic
  `deploy/client-multicast-session-unsupported` (hard error). See §9.4.

---

## §9 Feedback to RFC

### §9.1 OQ-W3 close — declare_fsm.scxml authoring contract

§3 above produces the authoring contract for `declare_fsm.scxml`:

- **Outbound at multicast session open:** Send `Interest{CURRENT,
  KEYEXPRS}` to the multicast group.
- **Outbound at unicast acceptor handshake-complete:** Send all
  declared resources/subscribers/queryables/tokens + DeclareFinal.
- **Inbound on Interest receive:** Transport-class-guarded body —
  unicast = no-op, multicast = match against local declared-* tables
  + emit declares + DeclareFinal.

This goes into `sources/network/declare_fsm.scxml` whenever that
sibling doc is authored (likely the next prose stress-test target,
after the deploy schema for passive mode is settled).

### §9.2 OQ-W9 close — scouting-fsm.md §6.4 evidence

`docs/session-fsm.md` §3.4 to be amended (one paragraph) to point
at this document's §6.4 for the OQ-W9 resolution. Concrete diff:

> § 3.4 last sentence: *"**Open question OQ-W9** (§8.2)."*
>
> Replaces with: *"**OQ-W9 closed** in `docs/scouting-fsm.md` §6.4 —
> zenoh-pico clients refuse multicast sessions
> (`_Z_ERR_CONFIG_UNSUPPORTED_CLIENT_MULTICAST` at
> `~/zenoh-pico/src/transport/multicast/transport.c:153-162`); they
> DO participate in multicast scouting. Deploy-time enforcement via
> `deploy/client-multicast-session-unsupported` diagnostic."*

`docs/session-fsm.md` §8.2 OQ-W9 row also marked answered with
cross-ref.

### §9.3 RFC §5.K — three new deploy.yaml fields (passive mode, conditional on OQ-W23 (a))

**Withdrawn (2026-05-01 후속 #5).** OQ-W23 (a) closed with
*defer to Phase D+*. The 3-field schema extension and 4 build
diagnostics originally proposed here are **not** recommended for
MVP. The MVP `scouting:` block stays:

```yaml
scouting:
  mode: active | static
  timeout_ms: <int>                    # existing
  hello_max_peers: <int>               # existing
```

`mode: passive` enum row + the three deploy fields land together
when Phase D+ ergonomics work begins. The proposed defaults
(`30000` / `25` / `5 × interval`) are preserved in the OQ-W23 entry
of `docs/rfc-open-questions-log.md` for re-opening at Phase D+
entry. Per RFC review #14 "pre-release forward-namespace 0"
policy, the schema does not pre-reserve passive's namespace; an
attempted `mode: passive` deploy fails with `deploy/scouting-mode-
unknown` (existing unknown-enum diagnostic family).

### §9.4 RFC §5.K — `whatami × multicast-session` invariant

Build-time enforcement of OQ-W9 closure. New diagnostic in RFC §5.K's
list:

- `deploy/client-multicast-session-unsupported` (hard error). Fires
  when `deploy.machines.<m>.whatami: client` AND any link in
  `deploy.machines.<m>.links` has `role: session` AND `class:
  udp_multicast` (or any future multicast link class).

Already-deployed `udp_session` links remain `role: session` +
`class: udp_unicast` (`bind: 0.0.0.0:7447`); the new diagnostic is
only triggered if a multicast session link is added to a client
deploy. Today the deploy skeletons do not have multicast session
links at all; this is forward-protection.

### §9.5 RFC §5.K — `untrusted_source` × `untrusted` schema reject

§6.2 above: `domain_attrs.untrusted_source: true` only makes sense
on `session_arming` links. Reject on `untrusted` links with new
diagnostic `deploy/untrusted-source-on-untrusted-link` (hard error).
Minor schema-validation patch.

### §9.6 RFC §5.M — diagnostic catalog additions

§5 + §8.1 add three diagnostics to RFC §5.M's list (currently 18
after the reassembly-fsm.md additions):

- `scouting/hello-max-peers-exceeds-peer-tables` (hard error;
  build-time invariant per §5.2)
- `scouting/rx-pool-overprovisioned-vs-burst-pps` (informational;
  build-time observation per §5.1 — not blocking)
- `scouting/hello-slot-size-recommendation` (informational;
  build-time per §5.3 / G-SCT-3)

Plus runtime diagnostics enumerated in §2.3 transition diagrams:

- `scout/tx-failed`
- `scout/decode-failed`
- `scout/timeout` (informational; maps to current `scout.timeout`
  event, surfaced as a diagnostic for operator visibility under
  `mode=active` failure)
- `scout/hello.peer_table_full`
- `scout/peer-aged-out` (passive mode — Phase D+ only, withdrawn from MVP)
- `scout/client-looking-for-clients` (informational, §7 residual)

### §9.7 ARCHITECTURE §2.4 — invariant 5 footnote on mode-gating

ARCHITECTURE §2.4 invariant #5 says "Platform gating only when
necessary." Mode-gating (codegen elides ScoutingDispatcher regions
based on `scouting.mode`) is an extension of the same discipline to
deploy attributes. Recommended as a footnote on invariant #5:

> *Mode-gating (e.g. codegen elides regions a deploy.yaml mode does
> not require) is the same discipline applied to deploy attributes
> instead of `platform.class`. The result must remain coherent: a
> deploy's chosen mode is a compile-time constant, not a runtime
> branch in the FSM.*

---

## §10 Next-step scaffolding

What this document unblocks now (in dependency order):

1. **Phase A SCXML authoring of active + static modes.** §2.4.1 +
   §2.4.3 are fully grounded; the active body has a literal mapping
   to zenoh-pico `__z_scout_loop` lines, and static is a
   single-state synthesis. This unblocks `sources/session/
   scouting.scxml` for the two modes that don't depend on OQ-W23.
2. **`declare_fsm.scxml` authoring contract.** §3.4 lists the
   three behaviors `declare_fsm.scxml` must implement; the
   transport-class guard at the top of the receive handler is
   surfaced as the mechanical knob.
3. **`session-fsm.md` §3.4 amendment.** §9.2 has the concrete diff;
   the amendment is one paragraph + the OQ-W9 row update.
4. **RFC §5.K diagnostic list extension.** §9.4 / §9.5 / §9.6
   list `deploy/client-multicast-session-unsupported` (OQ-W9
   enforcement), `deploy/untrusted-source-on-untrusted-link`
   (schema-validation), and three informational §5.M diagnostics
   (`scouting/hello-max-peers-exceeds-peer-tables`, `scouting/rx-
   pool-overprovisioned-vs-burst-pps`, `scouting/hello-slot-size-
   recommendation`). §9.3 passive-mode 3-field schema and 4
   diagnostics are **withdrawn** (OQ-W23 deferred to Phase D+).

What this document does NOT unblock (still waits):

- **Passive mode SCXML authoring.** Deferred to Phase D+ per
  OQ-W23 closure (2026-05-01 후속 #5). Re-opens at Phase D+ entry
  with the deploy.yaml schema additions and operational validation
  deploy.
- **`declare_fsm.scxml` SCXML body.** Waits on Phase A (SCE C11
  emitter for `algorithm` + `bounded-collection` + `statechart`
  kinds at MCU class).
- **G-SCT-2 unsolicited Hello broadcaster.** Speculative; waits
  for a concrete deploy scenario.

What was throw-away in this document: nothing. Every prose claim is
either (a) backed by zenoh-pico file:line, (b) backed by an existing
deploy.yaml field reference, or (c) explicitly framed as a
watching-zenoh addition with rationale.

---

## §11 Self-review against ARCHITECTURE §2.4 invariants

| Invariant | Check |
|---|---|
| 1. Static-first, dynamic-opt-in | ✓ All scouting state is statically declared at codegen time. `HelloPeerTable` is a `bounded-collection` with capacity from deploy. `mode` is a compile-time constant. The single dynamic structure (HelloPeerTable) has explicit capacity and an aging policy bounded by deploy timer (passive only). |
| 2. Link drivers extensible (open set) | ✓ The scouting FSM consumes only `link.send` / `link.rx` events (RFC §5.C `link` kind contract). Any future link class — multicast over BLE, multicast over Raweth — emits the same vocabulary; the scouting FSM is link-class-agnostic. |
| 3. Kinds are additive | ✓ The doc uses only existing RFC §5 kinds (`statechart`, `bounded-collection`, `link`, `codec`, `buffer-pool`). No new kind invented. The new diagnostics added to §5.K and §5.M are extensions of existing diagnostic classes, not new kinds. |
| 4. Library output | ✓ ScoutingDispatcher emits as a callable library API (one `start_scout()` + one event consumer for `scout.hello.received`). No binary-shape assumption. |
| 5. Platform gating only when necessary | ✓ The FSM body is identical on AP and MCU; only deploy values (`burst_pps`, `slot_count`, `hello_max_peers`, `rx_dispatch`) differ. The `rx_dispatch: isr_to_pool` vs `worker_tick` selection is a per-class scheduler concern handled by RFC §5.K, not by the scouting FSM body. The §9.7 footnote captures mode-gating as a sibling discipline. |
| 6. `out/` is SSoT-downstream | ✓ This document is `docs/`, not `out/`. It feeds SCXML authoring; SCXML feeds codegen; codegen produces `out/`. No manual-edit path to `out/`. |

---

## §12 Change log

- **2026-05-01** — initial draft. Mirrors `docs/reassembly-fsm.md` /
  `docs/session-fsm.md` structure. Grounded on zenoh-pico 1.9.0 HEAD
  `3b3ab65` (`src/{session/scout.c, net/{session.c, primitives.c},
  api/api.c, transport/{multicast/{transport.c, lease.c, rx.c},
  unicast/accept.c}, session/interest.c, protocol/definitions/
  transport.c}`, `include/zenoh-pico/{api/{constants.h, primitives.h},
  config.h.in, protocol/definitions/transport.h}`).

  **Key findings**:
  - **Three-mode framing is a watching-zenoh operational
    abstraction over zenoh-pico's single (active, one-shot)
    mechanism.** §1.4 maps each mode to its zenoh-pico equivalent
    (or absence thereof). `passive` is honest as a watching-zenoh
    addition; `static` is parity expressed as scouting-bypass.
  - **OQ-W3 closed** with three transport-class-specific Interest
    mechanisms (§3.2): unicast acceptor push at handshake
    (`accept.c:148-149`), multicast Interest reply
    (`interest.c:546-566`), client-router push (router-side).
    Interest is **not router-only in 1.x**.
  - **OQ-W9 closed** (§6.4): zenoh-pico clients refuse multicast
    sessions (`transport.c:153-162`); they participate in multicast
    scouting (`scout.c:142-165` is whatami-agnostic). Deploy-time
    diagnostic `deploy/client-multicast-session-unsupported`
    proposed.
  - **G-SCT-1 / OQ-W23** filed: passive mode justification + deploy
    schema (three new fields conditional on (a) closure).
  - **G-SCT-2** noted: unsolicited Hello broadcaster (speculative,
    no OQ filed).
  - **G-SCT-3** noted: `scout_rx_pool.slot_size` realistic vs
    worst-case Hello sizing; informational diagnostic
    `scouting/hello-slot-size-recommendation` proposed.

  **RFC patches recommended** (§9.3-§9.6): three new conditional
  deploy fields, four new build diagnostics
  (`deploy/scouting-retry-*-missing-on-passive-mode`,
  `deploy/client-multicast-session-unsupported`,
  `deploy/untrusted-source-on-untrusted-link`,
  `deploy/scouting-passive-fields-on-non-passive-mode`), six new
  runtime/build informational diagnostics
  (`scouting/hello-max-peers-exceeds-peer-tables`,
  `scouting/rx-pool-overprovisioned-vs-burst-pps`,
  `scouting/hello-slot-size-recommendation`,
  `scout/{tx-failed, decode-failed, peer-aged-out, client-looking-for-clients}`),
  and one ARCHITECTURE §2.4 footnote on mode-gating as deploy-
  attribute-level platform gating.

  **Cross-doc amendments**: `docs/session-fsm.md` §3.4 (OQ-W9 close
  cross-ref), `docs/session-fsm.md` §8.2 OQ-W9 row (status
  downgrade `open → answered`).

  **Outcome**: Phase A SCXML authoring of `sources/session/
  scouting.scxml` is unblocked for `mode ∈ {active, static}`.
  `mode: passive` authoring waits on OQ-W23 (a)+(b) closure.

- **2026-05-01 후속 #5 (OQ-W23 close — defer)** — passive scouting
  mode deferred to Phase D+. §1.4 mode table `passive` row →
  "deferred to Phase D+"; §2.4.2 → short deferral paragraph
  with rationale (MVP=parity, YAGNI, reversibility asymmetry);
  §2.5 timer table → 3 passive timers removed (replaced by
  cross-reference); §4.2 → "deferred" replaces "missing"; §8.1
  G-SCT-1 → resolved; §8.2 OQ-W23 → answered/deferred; §9.3
  RFC §5.K 3-field + 4-diagnostic patch **withdrawn**;
  §10 next-step → passive removed from "blocked" list (now
  "deferred"); cross-doc updates not required (sibling FSMs
  do not reference passive). MVP `mode` enum locked at
  `{active, static}`. Decision rationale fully captured in
  §1.4 + §8.1 G-SCT-1 entry.
