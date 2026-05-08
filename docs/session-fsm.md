# Session FSM — prose-level sketch

**Status.** Draft (2026-04-25). Pre-SCXML. This document sketches the
session-layer state machines in plain prose + ASCII so that design
gaps surface before authoring tooling exists (SCE Phase A is not yet
landed).

**Scope.** **Peer** and **client** mode session FSMs over the full
zenoh-pico-parity transport set (TCP, UDP unicast, UDP multicast,
Serial, WebSocket). Scouting is described where it drives session
entry; full scouting FSM is a sibling concern and will be authored as
its own SCXML.

**Inputs (normative).**
- `docs/wire-spec-subset.md` §3 (Scout/Hello), §4 (session control,
  framing, low-latency variant), §5 (network-layer carried after
  `Established`), §7 (extension chain) — message enumeration.
- `ARCHITECTURE.md` §2.1 (MVP criterion), §2.4 (extensibility
  invariants), §8.2 (preliminary session FSM sketch — superseded by
  this document).
- `docs/rfc-sce-protocol-synthesis.md` §8 Q13 — the specific open
  question this document feeds back to.
- Upstream zenoh 1.5.0 (`io/zenoh-transport/src/unicast/
  establishment/{open.rs,accept.rs}` and
  `io/zenoh-transport/src/multicast/{establishment.rs,link.rs,
  transport.rs,rx.rs}`) — authoritative reference for state shapes
  and transition order.

**Outputs.** (1) A legible state model that the three
`session_peer.scxml` / `session_client.scxml` (or parametric
equivalent) statecharts will implement. (2) A concrete answer to
RFC Q13 (§9.1 here). (3) A list of design gaps surfaced in §8 that
feed the RFC open-questions log.

**Non-outputs.** SCXML source (blocked on Phase A), authoring of the
network-layer FSMs (PUT / SUB / Query / Declare / Fragment /
Liveliness — each a sibling SCXML, sketched at arm's length here).

---

## §1 Framing overview

The session FSM sits between the **link layer** (a byte-stream /
datagram endpoint, RFC §5.C) and the **network layer** (Push /
Request / Response / Interest / Declare, wire-spec-subset §5). Its
job is to bring a transport session from *link-ready* to
*network-ready* and keep it alive.

```
           +--------------------------------------------------+
           |  Network-layer FSMs (PUT/SUB/Query/Declare/...)  |
           |      emit + consume NetworkMessage               |
           +--------------------------------------------------+
                              ^          |
                              | emitted  | received
                              |          v
           +--------------------------------------------------+
           |                SESSION FSM  (this doc)           |
           |  Scouting -> Opening -> Established -> Closing   |
           +--------------------------------------------------+
                              ^          |
                              | link     | send(bytes) /
                              | events   | recv(bytes)
                              v          v
           +--------------------------------------------------+
           |      Link layer (TCP / UDP / Serial / WS)        |
           +--------------------------------------------------+
```

**Two session classes.** The wire distinguishes them statically:

| Class | Link examples | Handshake | Framing on wire |
|---|---|---|---|
| **Unicast** | TCP, UDP unicast, Serial, WebSocket | 4-way Init/Open (wire-spec §4.1) | Full `TransportMessage` (TCP/Serial/WS) or `TransportMessageLowLatency` (UDP unicast) |
| **Multicast** | UDP multicast | **None** — periodic `Join` only | `TransportMessageLowLatency` always |

This is why we author **two session-layer statecharts per mode**:
`session_unicast_peer.scxml` and `session_multicast_peer.scxml`
(and the client variants) — they are structurally different, not
just parameter-different. Prior drafts conflated them; this
document corrects that (see §9.1).

---

## §2 Unicast session FSM

Upstream implementation (open side): `open.rs:559 open_link` driving
`send_init_syn → recv_init_ack → send_open_syn → recv_open_ack`.
Accept side is the mirror. Our FSM lifts this four-step async
pipeline into explicit states so that timeouts, retries, and extension
rejections have declared transitions.

### §2.1 States

Eight states, plus `Closed` as the terminal.

| State | Meaning | Entry action | Exit event (primary) |
|---|---|---|---|
| `Init` | Freshly constructed; link not yet open | — | `link.open_requested` |
| `LinkOpening` | Link driver is attempting to open (TCP connect, WS upgrade) | Call `link.open()` | `link.ready` / `link.failed` |
| `Scouting` | Active scout loop before any unicast target is known (only when deploy instructs `scouting.mode=active`) | Send `Scout` on scouting multicast link; start scout timer | `hello.received` / `scout.timeout` |
| `Opening` — **initiator** | We are driving the 4-way handshake | Send `InitSyn` | see §2.2 |
| `Accepting` — **acceptor** | Remote is driving the handshake; we respond | Arm inbound-timer on `RecvInitSyn` | see §2.2 |
| `Established` | Handshake done; session carries Network-layer messages | Arm lease timer; arm keepalive timer; enable RX/TX regions (§2.3) | `close.received` / `lease.expired` / `link.lost` |
| `Closing` | Graceful close in progress | Send `Close` with appropriate reason; stop keepalive | `close.acked` / `close.timeout` |
| `Closed` | Terminal | Release link, release pool slots | — |

**Rationale.** Splitting `Opening` and `Accepting` makes the handshake
direction explicit on the state chart. Upstream conflates them
behind an `OpenLink` / `AcceptLink` struct choice; we lift that to
the state level so the diagnostic surface is obvious (a handshake
timeout in `Opening` is a different diagnostic than a handshake
timeout in `Accepting`).

**`Init → LinkOpening` vs `Init → Accepting`.** A session is
created in one of two directions:

- **Outbound** (we initiate, typical for peer connecting to a known
  endpoint or to a scouted `Hello`): `Init → LinkOpening → Opening`.
- **Inbound** (we are a listener and a connection arrives):
  `Init → Accepting` directly — the link is already open when the
  FSM is instantiated. Upstream mirrors this: `accept_link()` is
  called by the link-listener task *after* `link.accept()`.

### §2.2 Transitions (happy path + error variants)

Outbound, happy path:

```
Init
  |-- event: create(outbound, endpoint) -------------> LinkOpening

LinkOpening
  |-- event: link.ready ----------------------------> Opening.SentInitSyn
  |-- event: link.failed(cause) --------------------> Closed (diag: link.open-failed)
  |-- event: link.timeout --------------------------> Closed (diag: link.open-timeout)

Opening.SentInitSyn
  |-- action on entry: send_init_syn()
  |-- event: recv(InitAck) -------------------------> Opening.GotInitAck
  |-- event: recv(Close{reason}) -------------------> Closed (diag: peer-rejected, reason)
  |-- event: init_ack_timeout ----------------------> Closing(reason=GENERIC)
  |-- event: recv(framing_error) -------------------> Closing(reason=INVALID)

Opening.GotInitAck
  |-- action on entry: validate_init_ack, send_open_syn(cookie)
  |-- event: recv(OpenAck) -------------------------> Established
  |-- event: recv(Close{reason}) -------------------> Closed (diag: peer-rejected)
  |-- event: open_ack_timeout ----------------------> Closing(reason=GENERIC)
```

Inbound, happy path (mirror of open.rs / accept.rs pairing):

```
Init
  |-- event: create(inbound, link_already_open)
  |     [guard: half_open_cap_available(link) AND
  |             accept_rate_token_available(link, src_addr)] (§2.7)
  |     -------------------------------------------> Accepting.AwaitingInitSyn
  |   [otherwise]
  |     -------------------------------------------> Closed
  |       (diag: session/half-open-cap-exceeded
  |              OR session/accept-rate-exceeded;
  |        no Close frame emitted — silent drop, see §2.7)

Accepting.AwaitingInitSyn
  |-- event: recv(InitSyn) -------------------------> Accepting.SentInitAck
  |-- event: init_syn_timeout ----------------------> Closed (diag: inbound-stall)
  |-- event: recv(framing_error) -------------------> Closing(reason=INVALID)

Accepting.SentInitAck
  |-- action on entry: validate_init_syn, send_init_ack(cookie)
  |-- event: recv(OpenSyn)
  |     [guard: cookie_valid(echoed, src_addr, now)] (§2.7)
  |     -------------------------------------------> Accepting.SentOpenAck
  |   [cookie invalid OR expired]
  |     -------------------------------------------> Closed (diag: session/cookie-rejected)
  |-- event: open_syn_timeout ----------------------> Closing(reason=GENERIC)

Accepting.SentOpenAck
  |-- action on entry: validate_open_syn(cookie, lease), send_open_ack()
  |-- event: <immediate> ---------------------------> Established
```

When `stateless_accept: cookie_hmac_sha256` is set on the link
(§5.K), the `Accepting.AwaitingInitSyn → Accepting.SentInitAck`
edge does **not** allocate an FSM instance — it computes the
cookie statelessly and emits `InitAck` directly. The FSM
instance and the half-open slot are claimed only on the
`recv(OpenSyn) [cookie valid]` edge above. Stateless mode and
half-open cap are complementary: one bounds the per-packet
unauthenticated work to O(1), the other bounds the
post-handshake-progress work to a finite number.

**Cookie handling.** `InitAck` carries an opaque cookie that
`OpenSyn` must echo (upstream `cookie.rs`). On the inbound side this
is the only stateful continuity between `Accepting.SentInitAck` and
`Accepting.SentOpenAck`; authoring in SCXML needs either (a) a
scoped datamodel field that holds the cookie across states, or
(b) explicit passing through the `Accepting` parent state's
datamodel. **Design gap G-SFM-1** (§8.1).

**Half-open accept hardening (anti-flood).** `Accepting.*` is the
only state class that can be entered by an unauthenticated remote
party, and it allocates a session-FSM instance plus a cookie before
any peer identity (ZID) is established. Without explicit caps a
remote attacker can spam `InitSyn` from spoofed source addresses,
filling every available `Accepting.*` slot and locking out
legitimate inbound connections — a textbook SYN-flood pattern.
The §5.M trust-class machinery does **not** cover this: `trust_class:
session_arming` only forbids reassembly bindings on these links;
it does not bound how many concurrent half-open accepts a link may
hold or how fast they may arrive.

The unicast FSM therefore enforces three caps on `Accepting.*`,
detailed in §2.7:

1. **Half-open capacity** per listener link (`session_arming_quota`),
2. **Accept rate** per (link, source address) (`accept_rate_per_sec`,
   `accept_rate_burst`), and
3. Optional **stateless accept** (`stateless_accept: cookie_hmac_sha256`)
   that defers FSM-instance allocation until `OpenSyn` echoes a
   validated HMAC cookie — borrowing the SYN-cookie pattern from
   TCP. With stateless accept enabled, the half-open capacity
   bounds *post-cookie* `Accepting.SentOpenAck` instances only,
   not the unauthenticated `Accepting.AwaitingInitSyn` /
   `Accepting.SentInitAck` work which becomes O(1) per packet.

These three caps live in `deploy.yaml` per listener link
(RFC §5.K) and are emitted by codegen as `bounded-collection`
checks plus a token-bucket guard at `Init → Accepting` entry.

**Extension negotiation.** The handshake negotiates QoS, MultiLink,
LowLatency, PatchType, SHM (advertised absent MVP), Auth, Compression
(accept-ignore). Each extension has upstream `StateOpen` / `StateAccept`
structs (`open.rs:52 StateTransport`, `accept.rs:55 StateTransport`).
In our FSM each extension is a **guard + side-effect on the
corresponding transition**, not its own state — adding eight states
per extension bloats the chart without protocol benefit. The guard
yields `Close{reason=UNSUPPORTED}` on negotiation failure ([wire-spec: Transport-layer extensions](wire-spec-subset.md#44-transport-layer-extensions-attached-to-initopenjoin)
row `ext::Shm` critical-bit failure; §7.2 unknown-critical
extension path).

### §2.3 `Established` sub-regions

`Established` is a **parallel** SCXML region with four concurrent
sub-machines. Each is small; the value is in their independence.

```
Established
  ├── RxDispatch    — classifies incoming TransportMessage body
  │       Frame        → NetworkMessage[] fanned out to network FSMs
  │       Fragment     → reassembly FSM (sibling SCXML, prose at docs/reassembly-fsm.md)
  │       KeepAlive    → resets Lease.last_seen
  │       Close        → parent transition to Closing(reason, peer-sent)
  │       OAM          → diagnostic event (OQ-W5)
  │
  ├── TxSchedule    — drains outbound Frame / Fragment batches per QoS band
  │       state: Idle, Batching, Flushing
  │       triggered by: network-layer push event OR batch-timer OR flush-on-high-prio
  │
  ├── Keepalive     — periodic KeepAlive emission
  │       state: Armed, Sending
  │       timer: deploy.yaml/lease * keepalive_ratio (default 1/3)
  │
  └── LeaseMonitor  — detects peer silence
          state: Healthy, Warning, Expired
          timer: lease; warning at lease*2/3; transition Expired → parent → Closing(EXPIRED)
```

**RxDispatch vs network FSMs.** RxDispatch extracts a
`NetworkMessage` and emits it as an event onto the internal event
bus. The sibling network FSMs (`put_fsm.scxml`, `sub_fsm.scxml`,
`query_fsm.scxml`, `declare_fsm.scxml`) consume those events; they
are NOT children of `Established`. This is consistent with
ARCHITECTURE §5 layout (`sources/network/*`).

**TxSchedule invariants.** One batch per (reliability, priority)
pair (wire-spec §4.2 Frame row). §5.N multi-link concurrency applies
here: if the session has multiple link drivers (`ext::MultiLink`
negotiated), TxSchedule becomes a small dispatcher choosing which
link to use. **Design gap G-SFM-2** (§8.1): authoring the dispatcher
in SCXML may need §5.N codegen contract details that are still
being drafted.

**LeaseMonitor `Warning` state.** Not a wire-level construct —
introduced so we can emit a `session/lease-warning` diagnostic for
operators before hard expiry. It does NOT transition on its own; it
records an observability event.

### §2.4 Close paths

Transitions out of `Established` (ordered by frequency):

| Trigger | Close reason sent | Terminal state |
|---|---|---|
| Application calls `session.close()` | `GENERIC` (S=1) | `Closed` |
| `LeaseMonitor` → `Expired` | `EXPIRED` | `Closed` |
| RxDispatch receives `Close` from peer | none (we are closed by peer) | `Closed` |
| Framing error (codec decode fail, unknown critical extension) | `INVALID` or `UNSUPPORTED` | `Closed` |
| Link layer raises `link.lost` | none (link gone; peer will observe via their lease) | `Closed` |
| TX path exhausts its congestion budget on RELIABLE batch | `UNRESPONSIVE` | `Closed` |

Upstream close reasons (`close.rs:22–29`): `GENERIC, UNSUPPORTED,
INVALID, MAX_SESSIONS, MAX_LINKS, EXPIRED, UNRESPONSIVE`. `MAX_SESSIONS`
and `MAX_LINKS` are emitted only by the *acceptor* during handshake
when per-manager limits are exceeded — so they appear in `Accepting`
transitions, not in `Established` exits. We surface them as
transition labels in §2.2 above (omitted from the happy-path
diagrams; covered under `Closing(reason=…)`).

**`Closing` state semantics.** Upstream does not model `Closing`
explicitly — it writes `Close` and shuts down the link
synchronously. We model `Closing` because the SCXML runtime is
event-driven and we need a landing state for the `send(Close)`
action plus an optional short timer before tearing the link down
(so the TCP FIN isn't emitted before the `Close` frame is flushed).
Default `Closing` timeout: 100 ms; deploy-configurable.

### §2.5 Timeouts and budgets

All timeouts are named here so they have a single home in
`deploy.yaml`. Values are placeholders — actual defaults land in
`deploy/*.yaml` authoring (forthcoming, §10).

| Timer | Default | Source |
|---|---|---|
| `link.open_timeout` | 5 s | deploy.links[].open_timeout |
| `init_ack_timeout` | 2 s | deploy.session.handshake_timeout |
| `open_ack_timeout` | 2 s | deploy.session.handshake_timeout |
| `scout_timeout` | 1 s | deploy.scouting.timeout |
| `lease` | 10 s (peer), 10 s (client) — negotiated | `OpenSyn/OpenAck.lease` field; deploy.session.lease |
| `keepalive_interval` | `lease / 3` | derived; deploy.session.keepalive_ratio |
| `closing_timeout` | 100 ms | deploy.session.closing_timeout |
| `batch_timer` (TxSchedule) | 1 ms (AP), 5 ms (MCU profile) | deploy.qos.batch_linger |
| `reassembly_timeout` | 500 ms per (peer, priority, reliability, sn_base) | deploy.session.reassembly_timeout |
| `accept_rate_window` | 1 s (token-bucket replenish window) | deploy.links[].accept_rate_per_sec (§5.K, §2.7) |
| `accepting_inactivity_timeout` | 1 s (drop unprogressed `Accepting.*` slot to free quota) | deploy.links[].accepting_inactivity_timeout (§2.7) |
| `cookie_hmac_lifetime` | 30 s (validity window of a stateless-accept cookie) | deploy.links[].stateless_accept.cookie_lifetime (§5.K, §2.7) |
| `cookie_hmac_key_rotation` | 1 h (HMAC key roll; old key honored one extra lifetime to avoid mid-handshake invalidation) | deploy.links[].stateless_accept.key_rotation_s (§5.K, §2.7) |

### §2.6 Trust-class interaction (cross-ref to §5.M)

The `trust_class` declared on each link (RFC §5.M) gates which
hardening rules are mandatory:

| `trust_class` | Listener attaches `Accepting.*`? | `session_arming_quota` required? | `accept_rate_per_sec` required? | `stateless_accept` recommended? |
|---|---|---|---|---|
| `untrusted` | No (Scout/Hello-only links never spawn `Accepting`) | n/a | n/a | n/a |
| `session_arming` | **Yes** (this is the canonical handshake-bearing link class) | **required (hard error)** | **required (hard error)** | strongly recommended for public-facing links; required for `untrusted_source: true` links |
| `established_session` | No (the link only carries traffic for a session that was previously armed elsewhere) | n/a | n/a | n/a |

`untrusted_source: true` (new sub-attribute on `links.<name>.
domain_attrs`, see §5.K) flags listener links exposed to a network
the deployment does not control (public Internet, untrusted LAN
segment, multi-tenant Wi-Fi). When set, `stateless_accept:
cookie_hmac_sha256` is required, not just recommended — the build
refuses to emit otherwise.

**Listener-link logical split (OQ-W22 resolution).** A deploy.yaml
listener entry (e.g. `links.udp_session` with
`trust_class: session_arming`) emits **two logical SCXML
link-instances** sharing a single physical socket — the
`session_arming` instance hosts the `Accepting.*` cluster of this
section, and a synthesized `established_session` sibling instance
hosts post-handshake Frame/Fragment traffic (eligible for
reassembly-pool binding per `docs/reassembly-fsm.md` §5). The
`Established` entry action in §2.3 is the moment a peer's traffic
ownership migrates from the `session_arming` instance to its
`established_session` sibling. Authors declare one listener block;
codegen emits the sibling. See RFC §5.M "Listener-link trust-class
lifecycle" + §5.C "Listener-link sibling emission" for the patch.

### §2.7 Accept-side hardening detail

This section specifies the three caps introduced in §2.2 and lists
the `bounded-collection` / token-bucket / HMAC primitives the
codegen emits.

**(a) Half-open capacity (`session_arming_quota`).** Per
listener link, the FSM holds a `bounded-collection` of size
`session_arming_quota` keyed by `(src_addr, src_port)`. Every
`Init → Accepting.AwaitingInitSyn` transition reserves an entry;
every terminal `Accepting.* → Closed` (success transition to
`Established` OR timeout OR rejection) releases it. When the
collection is full, the transition guard fails and the inbound
link attempt is dropped silently — no `Close` emitted, no link
read consumed beyond the InitSyn that triggered the attempt.

The default value is small (proposal: 8 on MCU, 32 on AP) and
**must** be sized so that
`session_arming_quota × max_handshake_time_s ≤ peer_table.capacity`,
otherwise a slow legitimate peer can be evicted by an attacker
who churns through the quota faster than handshakes complete.

`accepting_inactivity_timeout` (§2.5) bounds the worst-case
hold time: any `Accepting.AwaitingInitSyn` or
`Accepting.SentInitAck` slot that has not progressed within the
timeout is forcibly released to `Closed (diag: inbound-stall)`.
This converts "attacker opens TCP, never sends InitSyn" from an
indefinite slot lock into a bounded one.

**(b) Accept rate (`accept_rate_per_sec`, `accept_rate_burst`).**
Per (link, source-address) pair, a token bucket with capacity
`accept_rate_burst` and refill rate `accept_rate_per_sec` per
second. Each `Init → Accepting.*` attempt costs one token.
Empty bucket → guard fails → silent drop with diagnostic
`session/accept-rate-exceeded`.

The token-bucket table itself is a `bounded-collection` keyed
by `src_addr` with capacity `accept_rate_table_capacity`
(default: `4 × session_arming_quota`). When the table is full,
new source addresses fall through to a single shared bucket
(degraded mode) and emit `session/accept-rate-table-saturated`
diagnostic. This bounds the memory cost of per-source tracking
under address-randomized attack while keeping per-source fairness
for normal traffic.

Tokens are released on the cooperative scheduler tick; the
refill arithmetic is bounded-loop-free (single multiply +
clamp), `algorithm` kind compatible, `mode="static"` WCET.

**(c) Stateless accept (`stateless_accept: cookie_hmac_sha256`).**
When enabled, the FSM does NOT allocate a half-open slot on
`recv(InitSyn)`. Instead:

1. Compute `cookie = HMAC(key, src_addr || src_port || timestamp
   || negotiated_params)`. Truncate to wire-format cookie size
   (upstream supports up to 64 bytes; we use 32 bytes / HMAC-SHA-256
   truncated).
2. Emit `InitAck(cookie)`. **No FSM state allocated.** Per-packet
   cost is one HMAC computation (≈200 cycles on Cortex-M4 with
   SHA-256 acceleration; ≈4 kcycles software fallback). The
   `algorithm` kind for HMAC carries `<sce:wcet-bound mode="measured"
   target="..."/>` (§5.A) and the build verifies it fits inside
   `worker_slot_budget_us`.
3. On `recv(OpenSyn(echoed_cookie))`:
   - Recompute the cookie from the echoed `(src_addr, src_port,
     timestamp, params)` and compare. Mismatch → silent drop +
     `session/cookie-rejected`.
   - Check `now - timestamp ≤ cookie_hmac_lifetime`. Expired →
     same drop.
   - Check both the current HMAC key AND the previous key (one
     rotation back) — bounds key-rotation race.
   - **Only on valid cookie**: claim a half-open slot from the
     `session_arming_quota` collection and transition to
     `Accepting.SentOpenAck`. Quota full at this point → drop +
     `session/half-open-cap-exceeded`.

Stateless mode reduces the unauthenticated work to O(1) HMAC per
inbound packet, regardless of attacker source-address fan-out.
The half-open capacity now bounds only attackers who are willing
and able to complete a round-trip from the spoofed address —
which requires receiving the `InitAck` reply, raising the cost
of the attack from "send N packets" to "control N reachable
addresses."

**HMAC key handling.**
- Key material is generated at session-FSM-instance startup
  (per listener link, not per session) from a `sce_intrinsics_runtime`
  symbol `sce_random_fill(buf, len)`. The symbol is part of the
  intrinsics whitelist (RFC §5.I) — see G-SFM-5 (§8.1) for the
  outstanding decision on whether HMAC + RNG join the core
  whitelist or live in a target plugin.
- Two keys are kept live (current + previous). Rotation interval
  `cookie_hmac_key_rotation` (default 1 h); on rotation, the
  previous key is honored for one additional `cookie_hmac_lifetime`
  window so handshakes that started just before rotation still
  complete.
- HMAC construction itself is an `algorithm` kind authored in
  `sources/algorithm/hmac_sha256.scxml` (or HMAC-BLAKE2s on
  targets without SHA-256 acceleration; deploy.yaml selects).
  Both have `<sce:wcet-bound mode="measured">` derived from
  per-target benchmark.

**Drop-vs-reject policy.** All three guards (a)/(b)/(c) silently
drop the offending packet — no `Close` emitted, no error returned
to the link. The diagnostic events
(`session/half-open-cap-exceeded`,
`session/accept-rate-exceeded`,
`session/cookie-rejected`,
`session/accept-rate-table-saturated`) are observability-only.
Sending `Close` to a spoofed source would amplify attacker
bandwidth (DoS reflector) and is therefore explicitly forbidden
in this state — distinct from the post-Established `Closing`
path which always emits `Close` because at that point the peer
has authenticated via cookie or post-handshake state.

**Interaction with multicast.** §3 multicast sessions have no
handshake; there is no `Accepting.*` to harden. Per-peer rate
limiting on `Join` reception is a separate concern handled by
the multicast peer-table sweep (§3.1 PeerSweep) and is not
covered by this section.

Upstream: **no handshake**. `multicast/establishment.rs:35 open_link`
immediately starts tx/rx. Session identity per-peer emerges from
`handle_join_from_peer` in `multicast/rx.rs:60`. `Join` is emitted on
a `join_interval` timer from `multicast/link.rs:476`.

This is **structurally different** from the unicast FSM. We model it
as a separate statechart with two levels:

- **Session-level** (one per multicast link): `Idle → Running → Stopped`
- **Peer-level** (one per discovered peer, stored in a
  bounded-collection): `Discovered → Active → Expired`

### §3.1 Session-level states

```
Idle
  |-- event: create(multicast_link) ----> LinkOpening

LinkOpening
  |-- event: link.ready ----------------> Running
  |-- event: link.failed ---------------> Stopped (diag: link.open-failed)

Running (parallel region)
  ├── JoinEmit
  │     state: Idle, Sending
  │     timer: deploy.multicast.join_interval (upstream default: 2500 ms)
  │     action: send(Join{ version, whatami, zid, resolution, batch_size,
  │                        lease, next_sn, ext_qos, ext_patch })
  ├── RxDispatch
  │     classifies inbound TransportMessageLowLatency:
  │       Join{zid}     → PeerTable.learn_or_refresh(zid, params)
  │       Frame         → per-peer RxDispatch (§2.3 RxDispatch rules)
  │       Fragment      → per-peer reassembly
  │       KeepAlive     → refresh PeerTable entry
  │       Close         → PeerTable.remove(zid); emit peer-closed event
  │       OAM           → diagnostic (OQ-W5)
  └── PeerSweep
        timer: lease/3 (coarsest peer lease)
        action: evict PeerTable entries whose last_seen > lease

Stopped
  |-- terminal
```

### §3.2 Per-peer states

Each entry in the `multicast_peer_table` (a `bounded-collection`
keyed by `zid`, RFC §5.L, capacity from deploy) carries a small FSM:

```
Discovered
  |-- entry: first Join received; validated params (version, resolution,
  |          batch_size, qos-enabled match); initialize RX seq-num table
  |-- event: first NetworkMessage received --> Active
  |-- event: <no follow-up within discovery_grace> --> Expired

Active
  |-- event: Join/KeepAlive/any msg -------> stays Active, refresh last_seen
  |-- event: Close{zid} -------------------> Expired
  |-- event: last_seen + lease expired ----> Expired

Expired
  |-- entry action: emit peer-lost event to network-layer FSMs
  |-- terminal; PeerTable removes entry at next sweep
```

**Rejection rules (upstream `rx.rs:72–133`).** A `Join` that:
- fails version check → ignored + `multicast/peer-version-mismatch` diag
- exceeds `max_sessions` (bounded-collection full) → ignored +
  `multicast/peer-table-full` diag (not the unicast
  `Close{MAX_SESSIONS}`; upstream chose silent ignore for multicast)
- carries mismatched SN resolution / batch size → ignored + diag
- carries `is_qos=true` when we don't support QoS → ignored + diag

These are **not transitions** on the peer FSM (the peer never
reaches `Discovered`); they are diagnostic events on the session's
`RxDispatch`.

### §3.3 No close handshake

Multicast has no `Closing`. When we stop, we simply cease emitting
`Join`s and KeepAlives; peers time us out via their own lease
monitors. Symmetrically, we time out silent peers. This is
consistent with upstream — there is no `multicast/close.rs` with
special logic.

### §3.4 Client mode and multicast

`WhatAmI::Client` nodes participate in **scouting multicast** (to
discover peers/routers for unicast connection) but typically do NOT
run a multicast **session**. zenoh-pico clients are unicast-only by
baseline config. MVP follows suit: the multicast session FSM runs
only when `deploy.yaml machines[].mode` includes `peer` and the
machine has a `link` with `class: udp_multicast, role: session`
(not `role: scouting`). **OQ-W9 closed (2026-05-01 후속)** —
zenoh-pico clients refuse multicast sessions
(`_z_multicast_open_client` at
`~/zenoh-pico/src/transport/multicast/transport.c:153-162` returns
`_Z_ERR_CONFIG_UNSUPPORTED_CLIENT_MULTICAST`); they DO participate
in multicast scouting (the scouting layer is `whatami`-agnostic per
`~/zenoh-pico/src/protocol/definitions/transport.c:419-428`
`_z_s_msg_make_scout`). Build-time enforcement via new diagnostic
`deploy/client-multicast-session-unsupported` (hard error) when a
`whatami=client` deploy declares a `class: udp_multicast,
role: session` link. See [`docs/scouting-fsm.md`: OQ-W9 closure](scouting-fsm.md#64-oq-w9-closure-clientmulticast-session) for the full
OQ-W9 resolution prose and §9.4 for the RFC §5.K patch detail.

---

## §4 Scouting (pre-session)

Scouting is a sibling statechart (`sources/session/scouting.scxml`),
summarized here because it produces the events that drive `Init →
LinkOpening → Opening`.

Three modes (per deploy.yaml):

| Mode | States | Notes |
|---|---|---|
| `active` | `Listening → Sending → WaitHello → Connect` | Send `Scout` periodically; on `Hello`, pick a locator and trigger unicast session create. Used by clients, and by peers on initial bring-up |
| `passive` | `Listening` only | Only receives unsolicited `Hello`; used by peers after initial scouting when a mesh is stable |
| `static` | N/A — no scouting | Endpoints are configured directly in deploy.yaml; `session.create(outbound, endpoint)` is called at boot. Covers routers and MCU deployments with fixed peer lists |

Scouting is idempotent with session creation: receiving a `Hello`
from an already-established peer is a no-op (matched by zid).

**Scouting message flow (wire-spec §3):**

```
  Scouter                          Listener
     |                                  |
     |--- Scout{what, zid?} ----------->|    (UDP multicast 224.0.0.224:7446
     |                                  |     by convention)
     |                                  |
     |<-- Hello{zid, whatami,           |
     |         locators[]} ------------ |
     |                                  |
  [session.create(outbound, locators[0]) ...]
```

The **scouting link** is distinct from **session links** even when
both use UDP multicast with the same group/port — they are different
`link` kind instances with different framer (scouting framer ≠
`TransportMessageLowLatency`). wire-spec §8 table confirms this.

---

## §5 Peer vs client differences (answer to Q13)

RFC Q13 asks: two sibling SCXML files, one parametric file, or a
mode-attribute variant? This section gives the evidence-grounded
answer.

### §5.1 Inside the session FSM itself — differences are minimal

Reading `open.rs`/`accept.rs` against `whatami.rs`, at the session
(= transport) layer **peer and client are wire-identical**:
- The same 4-way handshake.
- The same extension set negotiable (both sides advertise their
  `whatami` in `InitSyn`; the remote's `whatami` is recorded but
  does not branch the FSM).
- The same `Close` reason handling.
- The same `Established` parallel regions.

Upstream confirms this: there is no `ClientOpenLink` vs `PeerOpenLink`
distinction in `establishment/`; the same `OpenLink` struct drives
both, parameterized only by `manager.config.whatami`.

### §5.2 Differences are outside the session FSM

Where peer and client diverge is:

1. **Scouting** (§4): clients default to `active`, peers default to
   `passive`-after-bringup. This is a scouting-FSM choice, not a
   session-FSM choice.
2. **Multicast session participation** (§3.4): clients typically
   don't run one; peers do.
3. **Declaration topology** (network layer): clients send
   declarations *to* a router; peers may participate in peer-mesh
   declaration propagation. This belongs to `declare_fsm.scxml`,
   not the session FSM.
4. **Interest semantics with no router** (OQ-W3, wire-spec §10):
   again a network-layer concern.

### §5.3 Q13 answer

**Recommendation: one unicast session SCXML, one multicast session
SCXML. No peer/client split at the session-FSM layer.**

- `sources/session/session_unicast.scxml` — handles both peer and
  client unicast sessions. Reads `whatami` from the deploy
  descriptor at compile time (via `sce_constant` or equivalent);
  that value is embedded in emitted `InitSyn`, not branched on.
- `sources/session/session_multicast.scxml` — only instantiated on
  machines with a multicast session link. Clients simply won't
  instantiate it.

This changes the earlier "two sibling files `session_peer.scxml`
and `session_client.scxml`" framing in:
- ARCHITECTURE §5 source layout diagram — path names need update
- RFC §7 Phase C item C8 (*"Client-mode session FSM variant"*) —
  no longer a separate authoring task; the client/peer distinction
  collapses at session layer and lives in scouting + network FSMs.
- RFC §8 Q13 — closes with "two files, BUT split by transport
  class (unicast vs multicast), not by mode (peer vs client)".

**Why not one parametric file across unicast and multicast?**
Because their structure differs (§3 vs §2 — handshake vs no
handshake). §5.G parametric kinds can eventually collapse along
other axes (e.g. QoS on/off) but not along this one without
pulling in conditional composition, which §5.G does not intend to
support.

---

## §6 Interaction with the link layer

The link layer (RFC §5.C) emits these events the session FSM
consumes:

| Event | Meaning | Typical session reaction |
|---|---|---|
| `link.ready` | Underlying TCP connect / WS upgrade done; byte channel open | `LinkOpening → Opening.SentInitSyn` (outbound) or attach to existing `Accepting` (inbound) |
| `link.lost(cause)` | Underlying link broken | Parent transition to `Closed(diag: link-lost)` |
| `link.rx(bytes)` | Bytes arrived | Pass to codec; codec emits `recv(MsgType)` events |
| `link.tx_drained` | TX pool slot freed | Wake TxSchedule |
| `link.backpressure(on|off)` | TX queue watermark crossed | TxSchedule may pause enqueue |
| `link.framing_error` | Codec decode failed | Parent transition to `Closing(INVALID)` |

Conversely the session FSM invokes on the link:

| Invocation | Meaning |
|---|---|
| `link.open()` | Initiate connect (outbound only) |
| `link.send(bytes, reliability)` | Ship encoded `TransportMessage` |
| `link.close()` | Tear down byte channel (after `Close` is flushed) |

The session FSM never touches the byte layer directly; all
encoding happens in the codec sibling kinds (wire-spec §4.1
messages → `codec` kind sources). **Design gap G-SFM-3** (§8.1):
the boundary between "session FSM emits event" and "codec writes
bytes" needs a concrete contract once RFC §5.B is drafted enough
for codec IR.

---

## §7 Extension negotiation summary

For §2.2 / §3.1 completeness. Each row maps an extension
([wire-spec: Transport-layer extensions](wire-spec-subset.md#44-transport-layer-extensions-attached-to-initopenjoin)) to the handshake transition where it is settled.
Extensions are read+written in the same transition where the
carrier message (`InitSyn`, `InitAck`, `OpenSyn`, `OpenAck`,
`Join`) is produced / consumed.

| Extension | Carrier | Outbound state that sets it | Failure mode |
|---|---|---|---|
| `ext::QoS` | InitSyn/InitAck, Join | `Opening.SentInitSyn` (outbound) | Close(UNSUPPORTED) if incompatible |
| `ext::QoSLink` | InitSyn/InitAck | same | — (always compatible; link-level hint) |
| `ext::Auth` | InitSyn/InitAck/OpenSyn/OpenAck (multi-step within handshake) | Opening.* (per method) | Close(GENERIC) on auth fail; OQ-W2 |
| `ext::MultiLink` | InitSyn/InitAck | `Opening.SentInitSyn` | graceful downgrade to single-link |
| `ext::LowLatency` | InitSyn/InitAck | `Opening.SentInitSyn` | session refused if mismatch with link class |
| `ext::Shm` | InitSyn/InitAck, Join | always advertised absent in MVP | Close(UNSUPPORTED) if peer critical-required |
| `ext::Compression` | InitSyn/InitAck | accept-and-ignore (deploy.yaml `extensions_ignored`) | Close(UNSUPPORTED) if peer marks critical (OQ-W4) |
| `ext::PatchType` | InitSyn/InitAck, Join | `Opening.SentInitSyn` | Close(UNSUPPORTED) if peer patch > ours (OQ-W7) |

`ext::Auth` is the one that may span multiple handshake steps
(challenge/response in USRPWD); it remains within the existing
`Opening.*` / `Accepting.*` states but may need an internal
sub-state like `Opening.AwaitingAuthChallenge` — deferred to OQ-W2
resolution.

---

## §8 Design gaps discovered (new this document)

Numbered as `G-SFM-N` so they can be cross-linked. §8.1 are gaps in
this project's authoring contract; §8.2 are new open questions that
should be added to `docs/rfc-open-questions-log.md`.

### §8.1 Authoring contract gaps

- **G-SFM-1.** Cookie continuity across `Accepting.SentInitAck →
  Accepting.SentOpenAck`. Needs either a parent-state datamodel
  field or explicit event-carried data. SCXML `<datamodel>` scoping
  should handle this but the choice affects how `codec` kinds deliver
  parsed fields into state-machine scope. Blocked on §5.B codec IR
  details.

- **G-SFM-2.** `Established.TxSchedule` interaction with §5.N
  multi-link dispatcher. If MultiLink is negotiated, which link a
  given Frame goes out on is a policy decision (round-robin? by
  priority band? sticky per-stream?). §5.N currently describes
  codegen shape but not policy. **Requires an RFC clarification or
  a `deploy.yaml` policy attribute.**

- **G-SFM-3.** Boundary between "session FSM emits
  `send(TransportMessage)` event" and "codec kind writes bytes into
  a buffer-pool slot, hands the slot to the link". Concretely: does
  the FSM see `TransportMessage` as an opaque `send()` action and
  the codec runs *outside* the FSM event loop, or does the FSM
  invoke the codec as a synchronous `sce:call` (§5.A) with the
  slot handle? **Needs decision once §5.B codec IR lands.**

- **G-SFM-4.** `LeaseMonitor.Warning` is non-normative — it exists
  only for diagnostics. Should it be authored at all, or left to
  observability hooks on the `Healthy → Expired` transition? If
  authored, it needs a deploy-configurable threshold. Low priority.

- **G-SFM-5.** Stateless-accept primitive ownership (§2.7). The
  cookie HMAC primitive (`sce_hmac_sha256(key, msg, out)` /
  `sce_hmac_blake2s(...)`) and the RNG primitive
  (`sce_random_fill(buf, len)`) are required to land somewhere
  before `stateless_accept: cookie_hmac_sha256` can be authored.
  Three options:
  1. Add to `sce_intrinsics_runtime` core whitelist (RFC §5.I) —
     small, well-defined surface; needs SCE maintainer ratification.
  2. Provide via target plugin per SoC — flexible (HW crypto
     accelerator on STM32H7, software fallback on M0+) but every
     deploy that uses public-Internet listeners must carry a plugin.
  3. Author HMAC as a regular `algorithm` kind (no extern), use
     RNG-only intrinsic. Loses access to crypto accelerators;
     keeps the wire result identical.
  - **Proposal:** option 2 (target plugin) for HMAC — crypto
    accelerator selection is inherently per-SoC; option 1 for RNG
    (every MCU has *some* entropy source, and the symbol shape is
    universal).
  - **Action:** ratify in next SCE sync; tracked as OQ-W15.
  - **Blocks:** authoring of `stateless_accept` deploys; does NOT
    block half-open-cap (a) and accept-rate (b), which are pure
    `algorithm` + `bounded-collection` and need no extern.

### §8.2 New open questions (add to rfc-open-questions-log.md)

- **OQ-W9.** Client mode and multicast session (§3.4). **Closed
  2026-05-01 후속 ([`docs/scouting-fsm.md`: OQ-W9 closure](scouting-fsm.md#64-oq-w9-closure-clientmulticast-session)).** zenoh-pico
  clients refuse multicast sessions
  (`_z_multicast_open_client` at
  `~/zenoh-pico/src/transport/multicast/transport.c:153-162`
  returns `_Z_ERR_CONFIG_UNSUPPORTED_CLIENT_MULTICAST`), DO
  participate in multicast scouting. Build-time diagnostic
  `deploy/client-multicast-session-unsupported` (hard error)
  proposed; see §3.4 amend.

- **OQ-W10.** `ext::Auth` multi-step negotiation shape. Does the
  USRPWD method need its own intra-`Opening` sub-states, or does
  the current "Init/Open alternation" cover it? **Owner:** upstream
  Zenoh verification + RFC author judgement. **Blocks:** OQ-W2
  resolution.

- **OQ-W11.** Multi-link TX dispatch policy. Round-robin, priority-
  banded, or something else? (G-SFM-2.) **Owner:** RFC maintainer;
  feeds RFC §5.N. **Blocks:** Phase C10 codegen contract.

- **OQ-W12.** Closing timeout default and linger behavior. Is 100 ms
  (this doc §2.4) enough on slow links (Serial at 115200 baud)?
  **Owner:** watching-zenoh author, validate when Serial link
  authoring begins. **Blocks:** deploy.yaml `closing_timeout`
  default.

---

## §9 Feedback to RFC

### §9.1 Q13 closes with refined answer

Per §5.3: two session SCXML files, **split by transport class**
(unicast vs multicast), **not by node mode** (peer vs client). Mode
is a compile-time constant read from deploy, embedded but not
branched.

**Concrete changes requested to other docs:**
- `ARCHITECTURE.md` §5 source layout: rename
  `sources/session/session_peer.scxml` →
  `sources/session/session_unicast.scxml`; add
  `sources/session/session_multicast.scxml`; remove
  `sources/session/session_client.scxml`.
- `docs/rfc-sce-protocol-synthesis.md` §7 Phase C C8: retarget from
  "Client-mode session FSM variant" to "Multicast session FSM
  authoring" (different structural work, comparable effort).
- `docs/rfc-open-questions-log.md` Q13: downgrade `open →
  answered`; record the unicast/multicast split rationale.

### §9.2 Q2 (Timer) evidence update

Upstream `lease` / `keepalive_interval` / `batch_timer` /
`join_interval` / `reassembly_timeout` confirm a minimum set of five
timer use cases on the session+multicast path alone (no network
FSMs counted). All are periodic-or-one-shot with a reset event.
`ForgeKind::Timer`'s `RuntimeDep::ForgeRuntimeHal` classification
is consistent with this set. This raises confidence that existing
Timer kind covers §5.D timer needs (RFC Q2) — still `needs-
verification` on the model-fit side (what `TimerType` variants the
code actually exposes).

### §9.3 OQ-W5 sharpened

Transport OAM and network OAM dropping: this doc recommends
**diagnostic-only, no application callback**, matching the existing
OQ-W5 proposal (wire-spec §10). Recording here so the decision has
a second vote behind it when OQ-W5 is ratified.

---

## §10 Next-step scaffolding

What this document *unblocks* now, in order of dependency:

1. **`deploy/*.yaml` skeletons** (prior next-step #2) can be authored
   with all timer / lease / handshake-timeout / closing-timeout
   fields concretely named — §2.5 gives the full list.
2. **Runtime crate API stubs** (prior next-step #3) can be authored
   against a concrete link event set (§6 table) — no more hand-
   waving about "link events".
3. **Scouting FSM sketch** (`docs/scouting-fsm.md`) — §4 is only a
   summary; a sibling prose doc would fully specify active /
   passive / static variants before SCXML authoring.
4. **Reassembly FSM sketch** (`docs/reassembly-fsm.md`) — feeds
   RFC §5.M canonical example. §2.3 RxDispatch + wire-spec §4.2
   Fragment row name the inputs.

What this document does *not* unblock (still waits for SCE Phase A):
- actual `.scxml` authoring
- concrete state-machine code emission
- any testing of FSM logic

---

## §11 Self-review against ARCHITECTURE §2.4 invariants

- **Static-first (#1).** All states and sub-states are declared;
  no runtime discovery of states. `multicast_peer_table` is the
  only dynamic structure and it is a `bounded-collection` (RFC
  §5.L), capacity from deploy. ✓
- **Link drivers extensible (#2).** §6 link-event contract is
  driver-agnostic; any new link class (BLE, Raweth, QUIC via target
  plugin) emits the same event vocabulary. ✓
- **Kinds are additive (#3).** This doc uses only RFC-proposed
  kinds already in §5; no new kinds invented here. ✓
- **Library output (#4).** No binary-shape assumption. ✓
- **Platform gating only when necessary (#5).** Timer defaults
  differ between AP and MCU profiles (§2.5 table) but the FSM
  structure is identical on both. No state is gated on
  `platform.class`. ✓
- **`out/` is SSoT-downstream (#6).** This document is input to
  SCXML authoring, which is input to codegen. ✓

---

## §12 Change log

- **2026-04-25** — initial draft. Grounded on zenoh 1.5.0
  `io/zenoh-transport/src/{unicast/establishment,multicast}` direct
  read. Key refinement vs prior sketches: session FSM splits by
  transport class (unicast vs multicast), NOT by node mode (peer vs
  client). Q13 resolution proposed (§5.3). Four new open
  questions filed (OQ-W9..W12).
- **2026-04-25 (review #9)** — Accept-side anti-flood hardening
  added. §2.2 Cookie-handling paragraph extended with three caps
  introduction; §2.2 inbound transition diagram now shows the
  guard expressions. New §2.6 trust-class interaction table
  (which caps are mandatory per `trust_class`). New §2.7 full
  spec for half-open capacity, accept-rate token bucket, and
  optional stateless-accept (`cookie_hmac_sha256`) — silent-drop
  policy, no DoS reflector amplification. §2.5 timer table gains
  four rows (`accept_rate_window`, `accepting_inactivity_timeout`,
  `cookie_hmac_lifetime`, `cookie_hmac_key_rotation`). G-SFM-5
  filed (§8.1) on HMAC + RNG primitive ownership; tracked as
  OQ-W15. Triggered by reviewer pointing out that §5.M's
  "rate-limited by the session FSM" assertion was unbacked —
  this section now backs it.
