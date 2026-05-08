# Wire Spec Subset — watching-zenoh MVP

**Status:** Draft (2026-04-24). Pre-implementation enumeration; field-level
shape will be refined when codec authoring begins (Phase B).

**Relationship to other docs:**
- `ARCHITECTURE.md` §2 defines the MVP criterion (zenoh-pico parity) and
  the split between *Included* / *Deferred* / *Permanent* categories.
- `rfc-sce-protocol-synthesis.md` §5 defines the SCE Forge kinds that will
  back each message category.
- This document enumerates, message-by-message, which Zenoh 1.x wire
  elements fall in which category, and which RFC §5 kind is responsible.

The unit of classification is **one upstream `zenoh-protocol` type**
(enum variant or struct) — not a whole "feature". This keeps the contract
legible against the upstream crate.

---

## §0 Normative references

| Reference | Role | Pinned |
|---|---|---|
| `zenoh-protocol` crate in `eclipse-zenoh/zenoh` | Authoritative wire format definitions (structs, enum variants, extension types) | Zenoh 1.5.0, `zenoh-protocol/src/{scouting,transport,network,zenoh}` |
| Protocol `VERSION` constant | Wire version byte | `0x09` (from `zenoh-protocol/src/lib.rs`) |
| `zenoh-pico` peer/client implementation | MVP parity target — what the MCU backend must match feature-for-feature | Same 1.x family; exact zenoh-pico release pinned at Phase-A freeze |
| Test vectors | Upstream `zenoh-protocol` regression fixtures + pcap corpus captured from a live `zenohd` 1.x | Captured in `tests/wire_replay/` (Phase A deliverable) |

**Wire-version pin.** `deploy.yaml → protocol.wire_version: "1.x"`
(ARCHITECTURE §2.5). Exact minor is frozen at the moment Phase A lands;
upstream evolution within 1.x is absorbed through additive extensions (§7
here). 2.x is explicitly out of this document's scope.

---

## §1 Protocol stack and layering

Every byte on the wire belongs to exactly one layer. Classification is
done per-layer so that the corresponding SCE kind is unambiguous.

```
  ┌─────────────────────────────────────────────────────────────┐
  │  Scouting layer         (Scout, Hello)                      │ §3
  │    transport: typically UDP multicast 224.0.0.224:7446      │
  ├─────────────────────────────────────────────────────────────┤
  │  Transport (session) layer                                  │ §4
  │    InitSyn/Ack, OpenSyn/Ack, Close, KeepAlive,              │
  │    Frame, Fragment, Join, OAM                               │
  │    transport: TCP / UDP unicast / UDP multicast / Serial /  │
  │               WebSocket                                     │
  ├─────────────────────────────────────────────────────────────┤
  │  Network (routing) layer      — carried inside Frame/Fragment│ §5
  │    Push, Request, Response, ResponseFinal,                  │
  │    Interest, Declare, OAM                                   │
  ├─────────────────────────────────────────────────────────────┤
  │  Zenoh payload layer          — carried inside Push/Req/Resp│ §6
  │    Put, Del, Query, Reply, Err                              │
  ├─────────────────────────────────────────────────────────────┤
  │  Extension chain              — attached to any layer above │ §7
  │    QoS, Timestamp, Attachment, Encoding, NodeId, SourceInfo,│
  │    LowLatency, MultiLink, Shm, Compression, Auth, ...       │
  └─────────────────────────────────────────────────────────────┘
```

Transport-layer messaging comes in two framings in upstream 1.x:

- `TransportMessage` — full framing with priority-tagged sequence
  numbers. Used on reliable link classes (TCP, QUIC, WebSocket) and
  supports priority-aware reliability.
- `TransportMessageLowLatency` — trimmed framing carrying only Close,
  KeepAlive, or a raw `NetworkMessage`. Used when the underlying link
  is already low-latency / best-effort (UDP unicast, UDP multicast).

MVP must handle both framings on the RX and TX paths; the choice is a
link-class attribute resolved at deploy time, not a runtime negotiation.

---

## §2 Classification legend

Three buckets, aligned with ARCHITECTURE §2.1/§2.2/§2.3:

- **Included** — in MVP on both AP and MCU backends. Every zenoh-pico
  peer/client does this, so we must too.
- **Deferred (D)** — structurally supportable; not authored in MVP but
  the synthesized stack must not make it impossible. Each Deferred row
  names the migration path (new RFC kind, new target plugin, etc.).
- **Permanent (P)** — ruled out on MCU by physical constraints (no
  heap, no unbounded state) per ARCHITECTURE §2.3. Not in MVP on AP
  either, because AP's router-class work is Phase D+ and not part of
  "peer/client parity". P items on AP are Deferred at the framework
  level, Permanent only on MCU.

Per-row **Backing kind** column points at the SCE RFC §5 kind that
houses the authored source. `codec`/`algorithm`/`statechart` are the
main three; `bounded-collection`, `link`, `buffer-pool`, `worker` are
used per their respective sections.

---

## §3 Scouting layer

Discovery phase. Sent before any session exists.

| Message | Status | Backing kind | Notes |
|---|---|---|---|
| `Scout` | **Included** | codec (RFC §5.B) | Sent by a node looking for peers. Contains `version`, `what` (bitmask of desired peer roles), optional ZenohID filter. Encoded as a variant-in-envelope (RFC §5.B variant + flags) |
| `Hello` (`HelloProto`) | **Included** | codec (RFC §5.B) | Sent in reply, or unsolicited for gratuitous advertisement. Contains `version`, `whatami`, `zid`, `locators[]`. Locators are a len-prefixed vector of len-prefixed strings — RFC §5.B's len-prefix + repeat covers this |

**Transport.** Scouting is per-convention UDP multicast (default group
`224.0.0.224:7446`); unicast is also valid. The link kind is a
`link` (RFC §5.C) with framer `datagram`, open-set via target plugin so
that e.g. a link-local IPv6 variant can be added without core edits.

**Out of scope in scouting layer.** There is no separate OAM/admin
discovery path that we must implement in MVP.

---

## §4 Transport (session) layer

Post-scouting, per-peer session state. Authored as
`session_unicast.scxml` (handshake-based: TCP / UDP unicast /
Serial / WebSocket) and `session_multicast.scxml` (no handshake,
periodic Join) statecharts, both as W3C SCXML statechart kind.
Split is by transport class — peer and client modes share the
unicast FSM because the session layer is wire-identical between
them (RFC Q13, resolved 2026-04-25; see `docs/session-fsm.md` §5).

### §4.1 Control messages

| Message | Status | Backing kind | Notes |
|---|---|---|---|
| `InitSyn` | **Included** | codec (RFC §5.B) + statechart | Initiator side of 4-way handshake. Fields: `version`, `whatami`, `zid`, `resolution`, `batch_size`, plus extension chain (see §7) |
| `InitAck` | **Included** | codec + statechart | Responder side, adds `cookie` (opaque ZSlice — len-prefixed bytes) |
| `OpenSyn` | **Included** | codec + statechart | Carries `lease`, `initial_sn`, echoes cookie. VLE-encoded lease duration |
| `OpenAck` | **Included** | codec + statechart | Finalizes handshake. Carries `lease`, `initial_sn` |
| `Close` | **Included** | codec + statechart | Carries `reason` byte and `session` flag (graceful vs link-only) |
| `KeepAlive` | **Included** | codec + statechart | Resets peer's lease timer. Empty body aside from framing |

### §4.2 Data-carrying framing

| Message | Status | Backing kind | Notes |
|---|---|---|---|
| `Frame` | **Included** | codec + statechart | Batch of `NetworkMessage`s sharing one reliability/priority band. Has `reliability` bit, `priority` (3 bits), `sn` (u64 VLE), `payload: Vec<NetworkMessage>`. Zero-copy decode per RFC §5.B in-place parse |
| `Fragment` | **Included** | codec + statechart + buffer-pool (reassembly variant, RFC §5.E) + reassembly FSM (RFC §5.M, prose sketch in `docs/reassembly-fsm.md`) | Single slice of an oversize `NetworkMessage`. Header bits: `reliability` (`_Z_FLAG_T_FRAGMENT_R`), `more` (`_Z_FLAG_T_FRAGMENT_M`, 0x40); body: `sn: u64` VLE, `payload: ZSlice`. Optional `FRAGMENT_FIRST` (id 0x02) + `FRAGMENT_DROP` (id 0x03) extensions gated by `_Z_PATCH_HAS_FRAGMENT_MARKERS(patch >= 1)`; legacy peers (patch 0) infer chain-start from "buffer empty AND consecutive SN". Chain key is `(peer_zid, reliability)` 2-tuple — see `docs/reassembly-fsm.md` §1 for rationale (no priority, no sn_base) |
| `Join` | **Included** | codec + statechart | Multicast-mode peer announcement on UDP multicast transports. Fields mirror InitSyn plus per-priority initial SN table. Required for zenoh-pico multicast parity |
| `OAM` | **Included on transport layer** | codec (RFC §5.B) | Transport-level out-of-band admin (link-local, per-session). zenoh-pico handles a subset; MVP accepts + ignores (pass through or drop per `deploy.yaml → extensions_ignored`). Generating OAM is not in MVP |

### §4.3 Low-latency framing variant

| Element | Status | Backing kind | Notes |
|---|---|---|---|
| `TransportMessageLowLatency` | **Included** | codec + statechart | Used on UDP unicast & UDP multicast transports. Union of `Close \| KeepAlive \| NetworkMessage`. Selected statically per-link in deploy (`link.framing: low_latency \| full`) |

### §4.4 Transport-layer extensions (attached to Init/Open/Join)

See §7 for the extension chain mechanism. Per-extension classification:

| Extension (from upstream InitSyn/InitAck) | Status | Notes |
|---|---|---|
| `ext::QoS` | **Included** | Priority + reliability negotiation |
| `ext::QoSLink` | **Included** | Link-level priority preferences |
| `ext::Auth` | **Included-negotiate-only** | Handshake MAY present auth credentials. Full auth method catalog (USRPWD, pubkey) deferred to Phase D; MVP implements "none" + one baseline method TBD (Q3 below) |
| `ext::MultiLink` | **Included** | Multiple concurrent links per session — RFC §5.N backs the codegen contract for this |
| `ext::LowLatency` | **Included** | Signals a link will use the low-latency framing |
| `ext::Shm` | **Permanent on MCU / Deferred on AP** | Shared-memory transport negotiation. Not in zenoh-pico baseline. Migration: new `shared-mem-pool` kind variant, Phase E. Advertised as absent by MCU; AP MVP also advertises absent |
| `ext::Compression` | **Deferred (accept + ignore per deploy)** | ARCHITECTURE §2.5 pins this in `extensions_ignored`. Decoded to confirm compatibility, payload not expanded in MVP |
| `ext::PatchType` | **Included** | Wire-format patch level; negotiated and honored |

---

## §5 Network (routing) layer

Carried inside `Frame`/`Fragment`. One logical message per
`NetworkMessage`.

| Message | Status | Backing kind | Notes |
|---|---|---|---|
| `Push` | **Included** | codec + `PushBody` union (§6) | Unidirectional publish. Carries a `wire_expr` (KeyExpr reference, either resolved-id or literal), `ext_qos`, `ext_tstamp`, `ext_nodeid`, and a `PushBody` payload |
| `Request` | **Included** | codec + statechart (query FSM) | Solicited RPC-style interaction. Carries `rid` (request id), `wire_expr`, payload `RequestBody::Query`, targeting/consolidation extensions |
| `Response` | **Included** | codec + statechart (query FSM) | Reply chunk to a prior Request. Carries `rid`, `ResponseBody` payload (Reply or Err) |
| `ResponseFinal` | **Included** | codec + statechart | Marks end-of-reply-stream for a Request. Carries `rid` only |
| `Interest` | **Included (bounded form)** | codec + statechart + bounded-collection (RFC §5.L) | Peer declares interest in a key pattern. Modes: `Current`, `Future`, `CurrentFuture`, `Final`. Options: aggregate, tokens, queryables, subscribers, restricted. MVP supports the peer/client subset: emit Interest, receive matched Declare stream terminated by DeclareFinal; emit DeclareFinal in response to an inbound Interest against our bounded local tables. **Aggregation across the network** (router-scale) is P — see §5 permanent row below |
| `Declare` | **Included** | codec + statechart (declare FSM) + bounded-collection | Envelope for the DeclareBody sub-variants in §5.1 |
| `OAM` | **Included on network layer** | codec | Router admin channel. Same stance as transport OAM: decode + forward/drop per `deploy.yaml`, generation deferred |

### §5.1 Declare sub-variants

| Sub-variant | Status | Notes |
|---|---|---|
| `DeclareKeyExpr` / `UndeclareKeyExpr` | **Included** | Bind a numeric id to a literal key expression for bandwidth-saving replacement. Id allocation table is a bounded-collection |
| `DeclareSubscriber` / `UndeclareSubscriber` | **Included** | Creates a local subscription entry. Table capacity per ARCHITECTURE §2.1 `KeyExpr matching` row — `bounded-collection`, capacity from deploy |
| `DeclareQueryable` / `UndeclareQueryable` | **Included** | Same shape for queryables |
| `DeclareToken` / `UndeclareToken` | **Included** | Liveliness tokens (ARCHITECTURE §2.1 "liveliness tokens" row). Same bounded-collection mechanism |
| `DeclareFinal` | **Included** | End-of-stream marker for a reply to an Interest. Must be emitted to correctly terminate peer Interest flows |

### §5.2 Permanent-on-MCU network features

| Feature | Status | Rationale |
|---|---|---|
| Wildcard Interest aggregation across N peers | **Permanent on MCU (P), Deferred on AP** | Aggregating subscription patterns over the whole network requires unbounded state. MCU's Interest is matched against its local bounded tables only. AP router mode is Phase D+ (ARCHITECTURE §2.2 "Router mode" row) |
| Forwarding-table maintenance (router role) | **Permanent on MCU (P), Deferred on AP** | Same rationale |
| Global key-space indexing | **Permanent on MCU (P), Deferred on AP** | MCU matches over declared table only |

---

## §6 Zenoh payload layer

The innermost layer — actual user payload. Carried inside Push,
Request, or Response.

### §6.1 `PushBody` variants

| Variant | Status | Backing kind | Notes |
|---|---|---|---|
| `Put` | **Included** | codec | Publish a value. Carries `timestamp` (optional), `encoding` (id + schema), `ext_sinfo` (source info), `ext_attachment`, `ext_shminfo` (deferred), `payload: ZBuf` |
| `Del` | **Included** | codec | Delete a key. Carries `timestamp`, `ext_sinfo`, `ext_attachment` |

### §6.2 `RequestBody` variants

| Variant | Status | Backing kind | Notes |
|---|---|---|---|
| `Query` | **Included** | codec + statechart | Carries optional `parameters` string, optional `consolidation`, `ext_sinfo`, `ext_body` (encoding + payload), `ext_attachment` |

### §6.3 `ResponseBody` variants

| Variant | Status | Backing kind | Notes |
|---|---|---|---|
| `Reply` | **Included** | codec + statechart | Carries `timestamp`, `encoding`, `ext_sinfo`, `ext_attachment`, `ext_consolidation`, `payload` |
| `Err` | **Included** | codec + statechart | Carries `encoding`, `ext_sinfo`, `payload`. Reply-channel error, not session error |

---

## §7 Extension chain mechanism

Zenoh 1.x attaches optional extensions to most messages as a TLV chain
with a `more` bit in the header byte. RFC §5.B's "TLV chain with bounds"
codec feature is exactly this. Per-extension budgets (max extensions per
message, max TLV body length) are declared in `deploy.yaml` and enforced
at decode time with a diagnostic on overflow.

### §7.1 Common application-visible extensions

| Extension | Scope | Status | Backing kind |
|---|---|---|---|
| Timestamp (`ext_tstamp`) | Push, Reply, Put, Del | **Included** | codec |
| Attachment (`ext_attachment`) | Push, Request, Response, Put, Del, Query, Reply, Err | **Included** | codec (bounded; length capped per deploy) |
| NodeId (`ext_nodeid`) | Push, Request, Response, Interest, Declare | **Included** | codec |
| SourceInfo (`ext_sinfo`) | Put, Del, Query, Reply, Err | **Included** | codec |
| Consolidation (`ext_consolidation`) | Request, Reply | **Included** | codec |
| Encoding (`ext_body` → encoding id + schema) | Query body, Put, Reply, Err | **Included** | codec + bounded string |
| QoS (`ext_qos`) | Push, Request, Response, Interest, Declare | **Included** | codec (priority + reliability + express + congestion_control bits) |
| SHM info (`ext_shminfo` on Put, `ext_shm` on transport) | Put / transport | **Permanent on MCU, Deferred on AP** | — |

### §7.2 Unknown extensions policy

ARCHITECTURE §2.5 `extensions_ignored` governs forward compatibility:
an unknown extension with the ignorable bit set is decoded into its
TLV envelope (so framing is preserved) and the body is discarded.
RFC §5.B's bounds enforcement applies. Generating ignorable-but-unknown
extensions is never allowed.

An unknown extension without the ignorable bit set is a framing error
and terminates the session with `Close{reason=unsupported_extension}`.

---

## §8 Transport / link matrix

Which messages flow on which link class. "✓" = emitted and consumed by
a peer/client-mode node in MVP. Driven by ARCHITECTURE §2.1 "Transports"
row.

| Message class | TCP | UDP unicast | UDP multicast | Serial | WebSocket |
|---|---|---|---|---|---|
| Scout / Hello | — | ✓ (rare) | ✓ (canonical) | — | — |
| Init/Open/Close | ✓ | ✓ | ✓ (via Join multicast variant) | ✓ | ✓ |
| KeepAlive | ✓ | ✓ | ✓ | ✓ | ✓ |
| Frame (full) | ✓ | — | — | ✓ | ✓ |
| TransportMessageLowLatency | — | ✓ | ✓ | — | — |
| Fragment | ✓ | ✓ | ✓ | ✓ | ✓ |
| Join | — | — | ✓ | — | — |
| Transport OAM | ✓ | ✓ | ✓ | ✓ | ✓ |
| Network-layer messages (§5) | via Frame/Fragment | via LowLatency/Fragment | via LowLatency/Fragment | via Frame/Fragment | via Frame/Fragment |

Per-link framer selection is a deploy.yaml attribute on the `link` kind
(RFC §5.C). Each link class maps to one driver in
`sce_link_runtime_{tokio,lwip}`; additional link classes (BLE, Raweth,
QUIC) attach via target plugin (RFC §5.I open-set invariant from
ARCHITECTURE §2.4 #2).

---

## §9 Scope classification summary

### §9.1 Message-type roll-up

| Layer | Included count | Deferred count | Permanent count |
|---|---:|---:|---:|
| Scouting (§3) | 2 | 0 | 0 |
| Transport (§4) — control + data + variants | 10 | 0 | 0 |
| Network (§5) — top-level + declare sub-variants | 16 | 0 | 3 (router-scale aggregation features, §5.2) |
| Zenoh payload (§6) | 5 | 0 | 0 |
| Extensions (§7) — app-visible | 7 | 1 (SHM) | 0 |

Every Included row is committed to both AP and MCU backends. Deferred
rows are not authored in MVP but must not be blocked by design
choices (ARCHITECTURE §2.4 invariant #3 "Kinds are additive"). Permanent
rows are MCU-only; AP will gain these in Phase D+ via router-mode work.

### §9.2 Cross-reference to RFC §5 kinds

| RFC kind | Used by |
|---|---|
| §5.A `algorithm` | CRC16-CCITT, VLE u64 encode/decode, keyexpr_intersect, keyexpr_includes |
| §5.B `codec` DSL | Every message in §3–§6 + every extension in §7 |
| §5.C `link` | Every link class in §8 |
| §5.D Timer/worker | KeepAlive timer, OPEN timeout, reassembly GC timer, per-link RX/TX workers |
| §5.E buffer-pool (+ reassembly variant) | RX pool per link, TX pool per link, reassembly pool for Fragment |
| §5.F Build-time const-fold | CRC table, optional KeyExpr tries |
| §5.I `sce:extern` | Cache maintenance, atomics, IRQ save/restore, fences — all hit on RX/TX hot paths |
| §5.J C11 + Rust no_std codegen | Every emitted artifact |
| §5.K Deploy model | All wire-subset limits (batch_size, max_fragment_count, extension budgets) |
| §5.L bounded-collection | Local sub/queryable/pending-query/in-flight-reassembly/keyexpr-id-binding tables |
| §5.M Fragment / reassembly | Fragment RX path |
| §5.N Multi-link concurrency | `ext::MultiLink`, parallel RX/TX per link driver |

Every MVP message must be covered by at least one kind above. Any gap
is a hole in the RFC and should be filed against the RFC's open
questions (§8 of the RFC).

---

## §10 Open questions (this document)

Tagged with OQ-W<N>; they feed back into
`rfc-sce-protocol-synthesis.md` §8 when they overlap with SCE-side
questions.

- **OQ-W1:** Exact zenoh-pico release to pin against at Phase-A freeze.
  Candidates: current tagged 1.x, or 1.x latest at the freeze moment.
  Decision deferred until Phase A lands.
- **OQ-W2:** Which Auth methods are baseline MVP beyond "none"? zenoh-pico
  historically supports USRPWD; pubkey is AP-heavy. Proposal: MVP =
  `{none, usrpwd}`, pubkey deferred. Needs confirmation against current
  zenoh-pico default config.
- **OQ-W3:** Interest semantics on a peer with no router present —
  specifically: peer A sends Interest{Future, subscribers}, peer B has
  local DeclareSubscriber. Does B reply with matched declares + Final,
  or is this router-only in 1.x? zenoh-pico behavior is the answer;
  needs direct verification against zenoh-pico source when it's
  available locally.
- **OQ-W4:** `ext::Compression` — decode-and-discard is documented as
  "ignored"; verify that the ignorable bit is always set upstream, i.e.
  that no upstream peer will send compressed payload with the critical
  bit. If critical compression is possible on the wire, MVP must reject
  the session cleanly (Close{unsupported_extension}) rather than silently
  corrupt.
- **OQ-W5:** Transport OAM and network OAM: "accept + forward/drop" is
  the MVP stance. Concrete behavior — does "drop" mean the message is
  consumed and not surfaced to the application, or that it's surfaced as
  a diagnostic event? Proposal: diagnostic event only, no application
  callback in MVP.
- **OQ-W6:** Batch size and max fragment count defaults. Upstream has
  historical defaults (~64 KiB batch, ~2^16 fragments); MCU-friendly
  defaults will be smaller. These live in `deploy.yaml` and are
  enforced at build time via RFC §5.K. First-pass values TBD when
  `deploy/mcu_target.yaml` is authored.
- **OQ-W7:** `ext::PatchType` negotiation — patch level is a small
  integer; a peer on a higher patch level MAY emit messages we don't
  know how to parse. MVP stance: advertise our patch level; refuse
  sessions where the negotiated level exceeds ours. Needs confirmation
  against upstream negotiation rules (they may mandate min-clamp).
- **OQ-W8:** Bounded-collection capacities: what are sensible defaults?
  zenoh-pico configures these via compile-time macros. We should mirror
  zenoh-pico's recommended defaults for the canonical "small MCU" and
  "AP node" profiles in `deploy/` skeletons. Values become normative in
  the `deploy/*.yaml` examples, not in this document.

---

## §11 Self-review checklist (ARCHITECTURE §2.4 invariants)

Before this document is promoted out of Draft, each invariant must be
checkable true against the tables above.

- **Static-first, dynamic-opt-in (#1).** Every Included row uses either
  a statically sized codec (RFC §5.B) or a capacity-bounded collection
  (RFC §5.L). No row requires unbounded dynamic allocation. ✓ by
  construction.
- **Link drivers extensible (#2).** §8 transports are all addressed
  through the `link` kind; new link classes (BLE, Raweth, QUIC) can be
  added via target plugin without changing any Included row. ✓
- **Kinds are additive (#3).** Deferred rows (§7 SHM, router-mode
  items in §5.2) each name a future kind variant or plugin. Adding
  them later does not break any existing kind. ✓
- **Library output (#4).** This document does not commit to any
  binary layout; all authored sources land in `sources/…` and are
  consumed by `out/ap/`, `out/mcu/` as library targets. ✓
- **Platform gating only when necessary (#5).** The only Permanent-on-
  MCU rows are router-scale aggregation features in §5.2. No MVP
  Included row is gated on `platform.class`. ✓
- **`out/` is SSoT-downstream (#6).** This document is input to
  codegen, not output. No manual-edit path. ✓

Failing any of these checks during Phase B authoring is a design bug
and must be filed as either a RFC open question or a document revision
with a linked rationale.

---

## §12 Change log

- **2026-04-24** — initial draft. Enumeration grounded on
  `zenoh-protocol` 1.5.0 `commons/zenoh-protocol/src/{scouting,
  transport,network,zenoh}` and the upstream `VERSION = 0x09` byte.
  Open questions OQ-W1..W8 filed. Classification totals in §9.1 to be
  re-verified when zenoh-pico source is available for side-by-side.
