# Reassembly FSM — prose sketch

**Status.** Pre-implementation prose, derived from RFC §5.M
(Fragment / reassembly kinds), §5.E (buffer-pool lifecycle FSM),
`docs/wire-spec-subset.md` §4.2 (Fragment row), and `docs/session-
fsm.md` §2.3 (RxDispatch Fragment branch). Mirrors the structure
of `docs/session-fsm.md`. This document is the canonical example
that stress-tests RFC §5.M's design before SCE Phase A landing —
discovered gaps feed back as RFC patches under §8.

**Scope.** This FSM owns the RX side of fragmented messages on
`trust_class: established_session` links: classify incoming
Fragment codec events by `(peer_zid, reliability)` (chain key
2-tuple per §1), accumulate fragments into a `reassembly-pool`
slot, emit a complete `NetworkMessage` upward when the chain
closes, and defend the slot count against malicious flood /
unfinished chain scenarios via timeout + per-peer quota. TX-side
fragmentation is sketched in §3 but is structurally simpler (no
slot table, no quota, no timeout) and lives in a sibling SCXML.

---

## §1 Framing overview

The reassembly FSM sits between the codec layer (RFC §5.B
Fragment codec) and the network layer (per `docs/session-fsm.md`
§2.3, `Established.RxDispatch` routes `Fragment` to this FSM and
`Frame` directly to the network FSMs).

```
┌───────────────────────────────────────────────────────────────┐
│ Application / network FSMs (sub_fsm, query_fsm, ...)          │
│                              ▲                                │
│                              │  message-complete event        │
│                              │  carrying full NetworkMessage  │
│ ┌────────────────────────────┴──────────────────────────────┐ │
│ │ ReassemblyDispatcher (this document)                      │ │
│ │   - bounded-collection<Slot, N> indexed by chain key      │ │
│ │   - per-peer-quota enforcement                            │ │
│ │   - per-slot timeout                                      │ │
│ └────────────────────────────▲──────────────────────────────┘ │
│                              │  Fragment.First/Continue/Final │
│                              │  events carrying ZSlice payload│
│ ┌────────────────────────────┴──────────────────────────────┐ │
│ │ Established.RxDispatch (session-fsm.md §2.3)              │ │
│ └────────────────────────────▲──────────────────────────────┘ │
│                              │  decoded TransportMessage      │
│ ┌────────────────────────────┴──────────────────────────────┐ │
│ │ Fragment codec (RFC §5.B); reads from RX buffer-pool slot │ │
│ └───────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────┘
```

**Chain key.** `(peer_zid, reliability)` — two components, all
required. Aligned to zenoh-pico 1.9.0 wire shape: the Fragment
struct `_z_t_msg_fragment_t = {_payload, _sn, first, drop}`
(`~/zenoh-pico/include/zenoh-pico/protocol/definitions/transport.h:494-499`)
carries no priority field and no per-chain `sn_base`; the per-peer
struct holds at most two reassembly buffers, one per reliability
band (`_z_transport_peer_common_t._dbuf_reliable` /
`_dbuf_best_effort` at `transport.h:50-68`).

- `peer_zid` (16 bytes) — the **trusted** peer identifier per RFC
  §5.M (NOT the wire source IP/port; see §5 below for why).
- `reliability` (1 bit) — RELIABLE vs BEST_EFFORT. Different
  reliability bands cannot share a chain (different transport
  contracts); selects which of the two per-peer buffers receives
  the payload, mirroring upstream's `_z_wbuf_t` selection in
  `~/zenoh-pico/src/transport/unicast/rx.c:155-192`.

**Why no priority in the chain key.** Upstream `Frame` messages
carry priority (used by the network-layer scheduler), but
`Fragment` messages do not. A fragmented `NetworkMessage` is sent
at exactly one priority band — fragments cannot interleave across
bands at the wire level because the receiver has no per-priority
demultiplexing for Fragment. Priority-aware QoS applies to whole
`NetworkMessage`s, not to fragment slices.

**Why no sn_base in the chain key.** Upstream tracks chain progress
with a `last_sn` cursor on the per-(peer, reliability) buffer plus
a "buffer empty?" check; consecutive-SN validation
(`_z_sn_consecutive` at `~/zenoh-pico/src/transport/utils.c:85-88`)
gates each Continue. The `idx = sn - sn_base` model from the
initial sketch is a watching-zenoh extrapolation with no upstream
counterpart; it is incompatible with the streaming-cursor Receiving
body that §2.5 already adopts.

**Fragment wire shape (from wire-spec §4.2).** Header bits
`reliability` (`_Z_FLAG_T_FRAGMENT_R`) and `more`
(`_Z_FLAG_T_FRAGMENT_M`, 0x40); body `sn: u64` VLE,
`payload: ZSlice`. Optional extensions (patch-gated):
`FRAGMENT_FIRST` (id 0x02) — explicit "this fragment opens a new
chain" marker; `FRAGMENT_DROP` (id 0x03) — explicit "abort the
current chain" marker. Both extensions are gated by
`_Z_PATCH_HAS_FRAGMENT_MARKERS(patch >= 1)`
(`~/zenoh-pico/include/zenoh-pico/protocol/definitions/transport.h:102`,
extensions defined at `~/zenoh-pico/include/zenoh-pico/protocol/ext.h:49-50`).

Legacy peers (patch 0) carry no FIRST/DROP extensions; "first" is
inferred by the receiver as "the per-(peer, reliability) buffer is
empty AND SN is consecutive with the last seen". This is upstream's
implicit chain framing and is the baseline FSM input model — the
patch-1 extensions are additive optimizations that lift the burden
from receiver inference to explicit wire tagging.

Fragment classification (FSM input shape, common to patch 0 and
patch ≥ 1):

| Wire shape | Event | FSM input |
|---|---|---|
| `more=1` AND (FIRST ext present OR buffer empty) | `Fragment.First` | open new chain (Router admits) |
| `more=1` AND no FIRST ext AND chain already open | `Fragment.Continue` | append to existing chain |
| `more=0` AND chain open | `Fragment.Final` | close chain, emit message |
| `more=1` AND no FIRST ext AND chain NOT open | (dropped at Router) | unmatched-continue, see §2.3 |
| `more=0` AND chain NOT open AND payload size ≤ MTU | `Frame` | reclassified by upstream codec; never reaches this FSM |
| DROP ext present (patch ≥ 1) | `Fragment.Drop` | abort current chain (Router routes to Slot's Aborted edge with reason `peer-drop`) |

The codec validates extension combinations and rejects malformed
pairs at decode time (e.g. FIRST + DROP in the same Fragment is a
codec-error). Patch-level mismatch is handled by the
`ext::PatchType` negotiation at session establishment (see
[`docs/wire-spec-subset.md`: Transport-layer extensions](wire-spec-subset.md#44-transport-layer-extensions-attached-to-initopenjoin) OQ-W7); receivers MUST NOT receive
FIRST/DROP from a peer that did not advertise patch ≥ 1.

---

## §2 Reassembly FSM

### §2.1 Hierarchy

ReassemblyDispatcher composes one Router region with N parallel
Slot regions, where N is independent of peer count and bounded by
the deploy-time `reassembly_pool.slot_count`:

```
ReassemblyDispatcher (per fragmenting link, 1 instance)
  ├── Router          — classifies inbound Fragment.* events by
  │                     chain key `(peer_zid, reliability)`,
  │                     holds the chain-key → slot-index map,
  │                     enforces per-peer quota
  │
  ├── Slot[0]         — parallel sub-region
  ├── Slot[1]         — parallel sub-region
  ├── ...                                          (N = pool.slot_count)
  └── Slot[N-1]       — parallel sub-region
```

The Router has no useful state of its own beyond the slot table
(stored as `bounded-collection<SlotEntry, N>`, slots indexed
`0..N-1`); it routes events to the matching Slot region by chain
key or refuses them. Each Slot is a small four-state machine
(§2.2). Codegen generates N parallel regions because N is a
build-time constant (`reassembly_pool.slot_count`); this fits the
`<parallel>` SCXML construct without runtime instantiation.

**Slot allocation invariant (one-active-per-key).** At most one
active slot per `(peer_zid, reliability)` pair. Router refuses a
second `Fragment.First` for the same key while a prior chain is
live (the existing slot must reach a terminal state — Complete /
TimedOut / Aborted — before the same key is admissible again).
This mirrors upstream zenoh-pico's "one buffer per (peer,
reliability)" inline structure
(`_z_transport_peer_common_t._dbuf_reliable` /
`_dbuf_best_effort` at
`~/zenoh-pico/include/zenoh-pico/transport/transport.h:50-68`).
A duplicate `Fragment.First` for an already-open key is treated
as a streaming protocol violation and aborts the existing chain
with reason `duplicate-first` (the Slot transitions to `Aborted`,
freeing the key); the new First does NOT silently take over,
which would mask peer bugs.

**Upstream-divergent generalization (slot pool size).**
zenoh-pico holds the two reassembly buffers inline in every peer
struct, so capacity is `2 × |connected peers|` and a peer's chain
is never refused due to pool exhaustion. watching-zenoh keeps a
shared bounded slot pool of size N, decoupling slot count from
peer count to fit ARCHITECTURE §2.4 invariant #1 (static-first):
inline 2 × `peer_table.capacity` buffers would force MCU to
allocate ~128 KB of reassembly memory regardless of fragment
activity, which the static-first invariant rejects in favor of
on-demand slot allocation from a shared pool. The divergence:
when `slot_count < 2 × peer_table.capacity` AND many peers
fragment concurrently across both reliability bands, some peers'
`Fragment.First` will be refused with `reassembly/slot-pool-full`
(under `on_overflow=reject` / `diagnostic-event`) or evict an
older slot (under `on_overflow=oldest-wins`). Upstream never has
this branch.

**Parity invariant.** Setting
`slot_count ≥ 2 × peer_table.capacity` reproduces upstream
behavior exactly — no peer ever sees `slot-pool-full` regardless
of concurrent fragmentation. The MCU / AP defaults intentionally
over-commit (`slot_count = 4 < 2 × peer_table.capacity = 32`
on MCU; `slot_count = 32 < 2 × 256 = 512` on AP), trading the
strict-parity guarantee for a deploy-time assumption that
fragmentation is a minority of peer traffic. Authors who want
strict upstream parity set `slot_count = 2 × peer_table.capacity`
and accept the memory cost.

**Parity gate posture (Phase C C14).** The zenoh-pico parity gate
tests normal-traffic equivalence. Pool-exhaustion scenarios are
**out of scope** for the parity gate — the gate's traffic
generators are configured to keep
`active_chains ≤ slot_count` so `slot-pool-full` never fires,
and the gate's pool-exhaustion sub-test is **disabled**. The
exhaustion divergence is covered by a separate adversarial test
under §5 attack-cost analysis (an attacker who completes N
handshakes and pins all slots is the documented threat model;
upstream's "no exhaustion" is heap-bounded, not exhaustion-free
under attack). The disabled parity sub-test re-enables when an
end-to-end equivalence harness is added, OR is permanently
documented as a security-feature divergence — that decision lands
with the parity-gate authoring (Phase C C14), not here.

The slot count N is bounded by `deploy/{mcu_target,ap_standalone,
ap_mcu_pair}.yaml` `buffer_pools.reassembly_pool.slot_count`. MCU
profile = 4; AP profile = 32 (per OQ-W8 resolution).

### §2.2 Slot states

```
        (allocate from Router)
         │
         ▼
       Empty ────────────────────────────────────► Empty
         │                                            ▲
         │ Fragment.First                             │ on slot release
         ▼                                            │  (returned to pool)
     Receiving ──────────────────────────────────────┤
       │   ▲                                          │
       │   │ Fragment.Continue                        │
       │   │  (matching key, SN consecutive)          │
       │   └──────────────                            │
       │                                              │
       ├──── Fragment.Final (matching key,            │
       │      SN consecutive) ──► Complete ───────────┤
       │                                              │
       ├──── reassembly-timeout-ms expired ─► TimedOut┤
       │                                              │
       ├──── Fragment.Continue (OOO or non-consec) ┐  │
       ├──── Fragment.Drop ext (peer-drop) ────────┤  │
       ├──── duplicate Fragment.First on open key ─┤  │
       ├──── slot evicted by oldest-wins overflow ─┤  │
       ├──── codec error on payload ───────────────┼─►Aborted ─┘
       └──── unmatched key bumped by Router ───────┘
```

Four states. Three terminal states (`Complete` / `TimedOut` /
`Aborted`) all funnel back to `Empty` via slot release; the funnel
edge is where the `buffer-pool` lifecycle FSM (§5.E) transitions
the underlying pool slot from `cpu-mut` (or `cpu-ref`) back to
`free` — the reassembly slot's terminal transition is the
natural pin point per §5.E "exclusively on FSM transition edges".

**Why `Complete` and `TimedOut` and `Aborted` are separate states**
(rather than collapsing into one terminal). Each emits a different
upstream event: `Complete` emits `reassembly.message-complete`
carrying the assembled `NetworkMessage`; `TimedOut` emits
`reassembly/per-peer-quota-exhausted` — wait, no — emits
`reassembly/timeout-fired` informational diagnostic; `Aborted`
emits `reassembly/aborted` with a reason code (`out-of-order` /
`evicted` / `duplicate-first` / `peer-drop` / `codec-error` /
`unmatched-key`). Three distinct upstream signals are useful for
operational visibility (the SCE diagnostic event channel surfaces
each separately). **`TimedOut` is a defense-in-depth signal beyond
upstream parity** — see §2.4.5 for the rationale.

### §2.3 Router states

```
Router (always-on; never blocks the FSM)
  ├── on Fragment.First (key K):
  │     if slot_table.find(K) exists:
  │       abort existing slot with reason `duplicate-first`
  │       (releases K), then continue admission below
  │     if peer_quota(K.peer_zid) exhausted:
  │       drop, emit reassembly/per-peer-quota-exhausted
  │     elif slot_table.has_free_slot:
  │       allocate slot, set slot.key = K, transition slot Empty → Receiving,
  │       start reassembly-timeout timer, store slot index in router map
  │     elif on_overflow == "oldest-wins":
  │       evict oldest slot (transition that slot → Aborted),
  │       allocate freed slot, init as above
  │     elif on_overflow == "reject" | "diagnostic-event":
  │       drop, emit reassembly/slot-pool-full (with policy reason)
  │
  ├── on Fragment.Continue (key K):
  │     if slot_table.find(K) exists:
  │       forward event to that Slot region
  │     else:
  │       drop, emit reassembly/unmatched-continue
  │
  ├── on Fragment.Final (key K):
  │     if slot_table.find(K) exists:
  │       forward event to that Slot region
  │     else:
  │       drop, emit reassembly/unmatched-final
  │
  ├── on Fragment.Drop (key K, patch ≥ 1 only):
  │     if slot_table.find(K) exists:
  │       transition that Slot to Aborted with reason `peer-drop`
  │     else:
  │       drop, emit reassembly/unmatched-drop
  │
  └── on slot-release (from any Slot region's terminal transition):
        slot_table.remove(slot.key), peer_count[slot.peer_zid]--,
        slot returned to pool free state per §5.E lifecycle
```

The Router's only persistent state is the slot table itself (a
`bounded-collection<SlotEntry, N>` per RFC §5.L). Lookup by chain
key is a bounded loop ≤ N — fits the `algorithm` kind with
`mode="static"` WCET (RFC §5.A). The per-peer count is a parallel
`bounded-collection<PeerCount, peer_table.capacity>` indexed by
`peer_zid`; quota check is one lookup.

### §2.4 Transitions in detail

#### §2.4.1 Empty → Receiving

Trigger: `Fragment.First` (key K) AND Router allocated this slot.

Actions:
1. `slot.key ← K` (where K = `(peer_zid, reliability)` per §1)
2. `slot.last_sn ← sn` (the SN carried by this Fragment.First)
3. `slot.cursor ← 0`
4. Stage-copy First's payload from RX pool slot to this reassembly
   pool slot at offset 0 (per RFC §5.E lifecycle: source RX slot
   transitions `cpu-ref → free` after copy; this slot transitions
   `free → cpu-mut` for the duration). Advance `slot.cursor` by the
   payload length.
5. `slot.deadline ← now() + reassembly_timeout_ms` (defense-in-depth
   per §2.4.5).
6. Start the per-slot timeout timer.

Each step's cost is included in the `reassembly_slot.wcet_us`
budget computed at build time per §5.M's 4th quantitative check.
For Cortex-M7 with 1.0 cycles/byte memcpy and a 1472-byte MTU,
step 4 is ≈ 1.5 µs; the full per-Fragment WCET is dominated by
that.

#### §2.4.2 Receiving → Receiving (Continue)

Trigger: `Fragment.Continue` (key K matching slot.key) AND
SN-precedence + consecutive checks pass per §2.5 Resolution.

Actions:
1. Validate SN: `_z_sn_precedes(slot.last_sn, sn) AND
   _z_sn_consecutive(slot.last_sn, sn)` (per
   `~/zenoh-pico/src/transport/utils.c:85-88`). On failure,
   transition to `Aborted` with reason `out-of-order` (§2.4.4).
2. `slot.last_sn ← sn`
3. Stage-copy Continue's payload at `slot.cursor` (per RFC §5.E
   lifecycle; cursor-bounds check against
   `reassembly_pool.slot_size` is a separate codec-level guard —
   on overflow, transition to `Aborted` with reason `codec-error`
   per §2.4.7).
4. `slot.cursor += payload.len()`

#### §2.4.3 Receiving → Complete (Final)

Trigger: `Fragment.Final` (key K matching slot.key) AND
SN-precedence + consecutive checks pass.

Actions:
1. Validate SN: `_z_sn_precedes(slot.last_sn, sn) AND
   _z_sn_consecutive(slot.last_sn, sn)`. On failure, transition
   to `Aborted` with reason `out-of-order`.
2. `slot.last_sn ← sn`
3. Stage-copy Final's payload at `slot.cursor`. `slot.cursor`
   finalizes at the assembled message length.
4. Emit `reassembly.message-complete` carrying a borrow of this
   slot's bytes (RFC §5.E `Sample<'pool>` borrow semantics —
   network FSMs that consume the message do so within the
   borrow's lifetime; if a network FSM needs to outlive the
   borrow, it stage-copies via `sce_sample_take`).
5. Slot transitions to `Complete`.

#### §2.4.4 Receiving → Aborted (out-of-order continue)

Trigger: `Fragment.Continue` or `Fragment.Final` (key K matching
slot.key) AND SN validation fails — either
`_z_sn_precedes(slot.last_sn, sn)` is false (SN regressed) OR
`_z_sn_consecutive(slot.last_sn, sn)` is false (forward gap).

This is the upstream parity path per §2.5 Resolution: any OOO or
non-consecutive arrival drops the in-flight chain. Both RELIABLE
and BEST_EFFORT bands apply this rule (single policy).

Actions:
1. Emit `reassembly/aborted` with reason `out-of-order`.
2. Transition to `Aborted` (release-via-funnel).

#### §2.4.5 Receiving → TimedOut (timer)

Trigger: `reassembly_timeout_ms` elapsed since `Fragment.First`.

**Posture: defense-in-depth beyond upstream.** zenoh-pico has no
per-chain timer (`_z_transport_peer_common_t` carries no deadline
field for the dbuf — see `~/zenoh-pico/include/zenoh-pico/transport/
transport.h:50-68`); upstream cleanup is bounded only by (i) the
next out-of-order arrival, (ii) `Z_FRAG_MAX_SIZE` overflow
(default 4096, `~/zenoh-pico/CMakeLists.txt:306`), (iii) Final
completion, (iv) peer disconnect
(`~/zenoh-pico/src/transport/peer.c:58-59`). watching-zenoh adds
the per-chain timer as a **defense-in-depth** layer against
post-handshake slot-pinning by an authenticated attacker (see §5)
— it is NOT part of zenoh-pico parity and is excluded from the
Phase C C14 parity gate's invariants. Normal traffic never trips
the timer (default `reassembly_timeout_ms = 500` ≫ wire RTT of
any fragment chain over a working network), so the defense is
invisible on the parity-gate path.

Actions:
1. Emit `reassembly/timeout-fired` (informational; the operator
   sees a sustained signal as a potential attack signature, see
   §5 below).
2. Transition to `TimedOut` (release-via-funnel).

#### §2.4.6 Receiving → Aborted (Router-driven eviction)

Trigger: Router decided to abort this slot. Two sub-causes:
- `oldest-wins eviction`: Router needed slot space for an
  incoming `Fragment.First` and chose this slot as the eviction
  victim under `on_overflow=oldest-wins`.
- `duplicate-first`: A new `Fragment.First` arrived for the same
  chain key (`(peer_zid, reliability)`) while this slot's chain
  was open. Per §2.1 slot allocation invariant
  ("one-active-per-key"), the existing slot is aborted and the
  key freed before the new First is admitted.

Actions:
1. Emit `reassembly/aborted` with reason `evicted` (oldest-wins)
   or `duplicate-first` (key collision).
2. Transition to `Aborted` (release-via-funnel).

#### §2.4.7 Receiving → Aborted (codec error)

Trigger: codec error on a Continue or Final payload (e.g. cursor
overrun within the network message decode).

Actions:
1. Emit `reassembly/aborted` with reason `codec-error`.
2. Transition to `Aborted` (release-via-funnel).

#### §2.4.7a Receiving → Aborted (peer-drop)

Trigger: `Fragment.Drop` extension received (patch ≥ 1; key K
matching slot.key). Peer is signaling that it has abandoned the
chain on its TX side (e.g. encoder error, application cancel).

Actions:
1. Emit `reassembly/aborted` with reason `peer-drop`.
2. Transition to `Aborted` (release-via-funnel).

This path is unreachable on legacy peers (patch 0); for those
peers, an abandoned chain manifests as a stalled Receiving state
that exits via `reassembly_timeout_ms` (§2.4.5) or peer
disconnect (§2.4.6 eviction or session termination).

#### §2.4.8 Terminal → Empty (release funnel)

Trigger: any of `Complete` / `TimedOut` / `Aborted`.

Actions:
1. Notify Router (`slot-release` event).
2. Pool slot transitions `cpu-mut` (or `cpu-ref` if Complete and
   the consumer is mid-borrow) back to `free` per §5.E lifecycle.
3. Slot region transitions to `Empty`, ready to be reallocated.

The `Complete → Empty` edge has an extra wrinkle: if a network
FSM is borrowing the bytes (`Sample<'pool>`), the slot stays in
`cpu-ref` until the borrow ends. The SCXML emits a guard
`borrow_count == 0` on the `Complete → Empty` transition; release
is automatic when the last borrower exits. RFC §5.E's pool
ownership FSM provides this counter.

### §2.5 Out-of-order arrival policy

**Resolution (2026-05-01 후속, OQ-W21 close — verified against
zenoh-pico 1.9.0 HEAD `3b3ab65`).** Upstream policy is **strict
in-order, identical for RELIABLE and BEST_EFFORT**: any out-of-order
or non-consecutive `Fragment.Continue` drops the entire in-flight
defragmentation buffer. No bitmap, no reorder buffer, no holding the
out-of-order fragment. The watching-zenoh §1/§2.5 initial proposal
(reliability-conditional, bitmap for BEST_EFFORT) is **rejected for
MVP** — it diverges from zenoh-pico parity. Upstream evidence:

- **Both reliability bands apply the same SN-precedence + consecutive
  check** at `~/zenoh-pico/src/transport/unicast/rx.c:155-192`
  (unicast) and `~/zenoh-pico/src/transport/multicast/rx.c:251-287`
  (multicast). The if/else on `_Z_FLAG_T_FRAGMENT_R` only selects
  *which* dbuf (`_dbuf_reliable` vs `_dbuf_best_effort`); the
  drop-on-OOO action is symmetric.
- **OOO with regressing SN** (`!_z_sn_precedes(latest, msg_sn)`):
  buffer is cleared with diagnostic "...message dropped because it
  is out of order" — `unicast/rx.c:166-168, 180-182`,
  `multicast/rx.c:262-266, 276-280`.
- **OOO with forward gap** (`_z_sn_precedes` true but
  `!_z_sn_consecutive`): buffer is cleared with diagnostic
  "Defragmentation buffer dropped because non-consecutive fragments
  received" — `unicast/rx.c:187-191`, `multicast/rx.c:282-287`.
- `_z_sn_consecutive` requires `(sn_right - sn_left) == 1` modulo
  resolution (`~/zenoh-pico/src/transport/utils.c:85-88`); anything
  else is treated as out-of-order.

**Implication for this FSM (Receiving body).** The Receiving region's
Continue handler is **streaming-cursor only**, not bitmap. On
`Fragment.Continue` (key K matching slot.key):

1. If `sn` does not strictly succeed `slot.last_sn` (i.e.
   `_z_sn_precedes(slot.last_sn, sn)` false) OR is not consecutive
   (`_z_sn_consecutive(slot.last_sn, sn)` false) → transition
   `Receiving → Aborted` with reason `out-of-order` (single reason
   for both reliability classes; replaces the proposed
   `reliable-out-of-order` distinction).
2. Otherwise: `slot.last_sn ← sn`; stage-copy payload at
   `slot.cursor`; advance `slot.cursor += payload.len()`. No
   per-index validation (no bitmap to look up).

**Cascading amendments (folded into the body 2026-05-XX).** The
four upstream divergences originally listed here as deferred items
have been absorbed into the document body:

- **Chain key shape** — §1: chain key is `(peer_zid, reliability)`,
  matching upstream's `_z_t_msg_fragment_t` (no priority, no sn_base).
- **Slot count model** — §2.1: shared bounded slot pool of size N
  preserved as an upstream-divergent generalization; parity
  invariant + parity-gate posture documented.
- **Per-chain timeout** — §2.4.5: `reassembly_timeout_ms` retained
  as defense-in-depth beyond upstream (not part of parity surface).
- **Patch-gated wire markers** — §1 wire shape: `FRAGMENT_FIRST`
  (id 0x02) + `FRAGMENT_DROP` (id 0x03) extensions gated by
  `_Z_PATCH_HAS_FRAGMENT_MARKERS(patch >= 1)`; legacy peers
  (patch 0) use implicit chain framing.

§8.1 G-RFM-1 follow-up no longer blocks Phase A SCXML authoring on
these items; the remaining reassembly-side blocker is OQ-W22
(listener-link trust-class lifecycle), which requires an RFC §5.M
or §5.C patch.

The build sets the per-link policy at codegen time based on the
SCXML's `<sce:link-class>` framer settings; the runtime branch on
the chain key's `reliability` bit selects which slot is used (one
active slot per `(peer_zid, reliability)` per §2.1's allocation
invariant), but the OOO action is identical on both bands.

### §2.6 Mapping to RFC §5.M's three-state sketch

RFC §5.M presents a minimal sketch:
```
Idle → Assembling → Complete
                  → FreeSlot (timeout / pool-full)
```

This document's four-state `Empty / Receiving / Complete / TimedOut
/ Aborted` is the explicit form:

| RFC §5.M | this document | rationale |
|---|---|---|
| `Idle` | `Empty` | clearer naming — slot is not idle, it is unallocated |
| `Assembling` | `Receiving` | clearer naming — verbing the state |
| `Complete` | `Complete` | identical |
| `FreeSlot` (timeout) | `TimedOut` | distinct upstream diagnostic |
| `FreeSlot` (pool-full) | `Aborted` | distinct upstream diagnostic |
| (not modeled) | `Aborted` (`out-of-order` / `evicted` / `duplicate-first` / `peer-drop` / `codec-error` / `unmatched-key`) | additional terminal causes surfaced from elaboration |

The expansion is conservative — every RFC §5.M edge maps to a
state in this document, and the additional states all funnel
through the same release transition. SCE Phase A C11 emitter
implements this elaboration; the sketch is the contract surface.

---

## §3 TX fragmentation (sibling FSM)

TX-side fragmentation is structurally simpler — no slot table, no
timeout, no quota. A `procedure` or `algorithm` walks the outbound
payload and emits `Fragment.First` / `Continue` / `Final` codec
events. The receiver's reassembly FSM (this document) handles all
the bookkeeping.

```
TxFragmenter (per outbound message)
  ├── compute fragment_count = ceil(payload.len / mtu_bytes)
  ├── emit Fragment.First with payload[0..mtu_bytes]
  ├── for i in 1..fragment_count - 1: emit Fragment.Continue with
  │     payload[i*mtu_bytes .. (i+1)*mtu_bytes]
  └── emit Fragment.Final with payload[(fragment_count-1)*mtu_bytes ..]
```

Bounded loop (≤ `qos.max_fragment_count`); fits `algorithm` kind
with `mode="static"` WCET. Each emitted fragment goes through the
TX pool / link layer per RFC §5.E's lifecycle FSM.

The TX side has **no equivalent slot/quota state machine** — it
is a fan-out, not a fan-in. The author writes it as an
`algorithm` body that calls `link_emit_fragment(...)` per
iteration. Per-iteration WCET is dominated by the one stage-copy
into the TX pool slot.

---

## §4 Timer / quota / pool config (cross-ref deploy.yaml)

All values come from `deploy/{mcu_target,ap_standalone,ap_mcu_
pair}.yaml`. Table mirrors session-fsm.md §2.5 shape so authors
have one mental model across both FSMs.

| Field | MCU default | AP default | Source |
|---|---|---|---|
| `reassembly_pool.slot_count` | 4 | 32 | `deploy.machines.<m>.buffer_pools.reassembly_pool.slot_count` |
| `reassembly_pool.slot_size` | 4096 | 65536 | `deploy.machines.<m>.buffer_pools.reassembly_pool.slot_size` |
| `reassembly_pool.max_fragments_per_message` | 16 | 256 | `deploy.machines.<m>.buffer_pools.reassembly_pool.max_fragments_per_message` |
| `reassembly_pool.reassembly_timeout_ms` | 500 | 500 | `deploy.machines.<m>.buffer_pools.reassembly_pool.reassembly_timeout_ms` (defense-in-depth; not part of upstream parity — see §2.4.5) |
| `reassembly_pool.per_peer_quota` | 2 | 8 | `deploy.machines.<m>.buffer_pools.reassembly_pool.per_peer_quota` |
| `peer_table.capacity` | 16 | 256 | `deploy.machines.<m>.limits.peer_table` (used in build-time invariant check) |

**Build-time invariant** (RFC §5.M):
`peer_table.capacity × per_peer_quota ≥ slot_count`. Verified for
both profiles:

- MCU: 16 × 2 = 32 ≥ 4. ✓
- AP: 256 × 8 = 2048 ≥ 32. ✓

If an author overrides values, the build re-checks
(`reassembly/per-peer-quota-build-invariant-violated` hard error).

**Stage-copy WCET budget** (per §5.M 4th quantitative check):
`stage_copy_wcet_us = expected_p99_bytes × memcpy_cycles_per_byte
/ clock_freq_mhz`. For MCU profile (M7 @ 400 MHz, expected_p99 =
1024 bytes, memcpy 1.0 cycles/byte): ≈ 2.6 µs per Fragment, well
under `worker_slot_budget_us = 200 µs`. The build emits the
computed value as `reassembly/stage-copy-wcet` informational and
gates as hard error only when it exceeds the budget.

---

## §5 Trust-class interaction (cross-ref RFC §5.M)

The Router's per-peer-quota enforcement uses **`peer_zid`** as the
peer identifier, NOT the wire source address. This is enforced by
the build-time gate on the **link instance**'s `domain_attrs.
trust_class` per RFC §5.M:

| Link instance trust_class | Reassembly pool binding | Why |
|---|---|---|
| `untrusted` | **forbidden** | UDP source spoofable; no zid available pre-handshake. Diagnostic `reassembly/untrusted-link-binding` (hard error) |
| `session_arming` | **forbidden** | INIT/OPEN frames are small; zenoh wire format does not allow them to fragment. Same hard error |
| `established_session` | **required** | Post-handshake; zid bound to the link's source address by the handshake |

**Listener links emit two instances** (RFC §5.M "Listener-link
trust-class lifecycle", RFC §5.C "Listener-link sibling emission",
OQ-W22 resolution). The `udp_session` block in
`deploy/mcu_target.yaml` declares `trust_class: session_arming`
once, but codegen synthesizes two logical link-instances sharing
the single physical socket:

- A `session_arming` instance hosting `Accepting.*` (pre-handshake).
  No reassembly-pool binding is permitted on this instance — the
  `reassembly/untrusted-link-binding` gate stands.
- An `established_session` sibling instance receiving each peer's
  Frame/Fragment traffic *after* the unicast session FSM
  transitions that peer to `Established` (`docs/session-fsm.md`
  §2.3). Reassembly-pool bindings authored against the listener
  link kind resolve to this sibling at codegen time and pass the
  gate.

deploy.yaml schema is unchanged — the split is automatic and
not author-declared. The build-time gate is therefore
**link-instance-scoped, not socket-scoped**, and remains a fully
static check.

The defense composition: an attacker faking N source IPs to
exhaust the per-peer quota would have to first complete N
handshakes through the listener's anti-flood gate
(`session_arming_quota` + `accept_rate_per_sec` +
`accept_rate_burst` + optional `stateless_accept`). Each
handshake yields one zid that consumes
`per_peer_quota = 2` (MCU) reassembly slots — so to fill the
4-slot MCU pool, the attacker needs at least 2 distinct
handshakes. Round-trips: `2 × handshake_time` + the per-slot
fragment chain submission. This is the "raise cost from N
packets to N handshakes" argument from RFC §5.M, made concrete
with deploy-skeleton numbers.

**Slot-pinning under cooperative attacker.** A handshake-paying
attacker who sends `Fragment.First + one Continue` per chain and
then stalls would, in upstream zenoh-pico, hold its dbuf
indefinitely until disconnect — upstream's only post-handshake
cleanup paths are next-OOO arrival, `Z_FRAG_MAX_SIZE` overflow
(both attacker-controlled or attacker-avoidable), Final
completion, and peer disconnect. watching-zenoh's
`reassembly_timeout_ms` (§2.4.5) caps the per-chain hold time
at a deploy-time constant; this is **defense-in-depth** beyond
upstream and is not part of the parity surface. Without the
timer, the attack cost is `N_handshakes × per_peer_quota` slots
held until the session leases out (`lease_seconds`, typically
seconds to minutes). With the timer, the same slots release
every `reassembly_timeout_ms` (default 500 ms), forcing the
attacker to re-pay the chain-injection cost at that cadence. The
timer is neutral on parity-gate traffic (legitimate chains finish
well below 500 ms) and invisible to upstream-equivalent test
harnesses.

---

## §6 Buffer-pool interaction (cross-ref RFC §5.E lifecycle FSM)

This FSM is a *consumer* of the §5.E pool ownership FSM — its
state changes drive transitions on the underlying pool slot.
Mapping:

| Reassembly slot state | Pool slot state | Allowed pool ops |
|---|---|---|
| `Empty` | `free` | (slot returned to pool freelist) |
| `Receiving` | `cpu-mut` | `pool_acquire_for_encode` taken; multi-write bytes via stage-copy |
| `Complete` (no borrow) | `free` | (released immediately back to pool) |
| `Complete` (borrow active) | `cpu-ref` | `Sample<'pool>` outstanding; consumer reads bytes |
| `TimedOut` / `Aborted` | `cpu-mut` → `free` | bytes discarded; slot returned to freelist |

The `Receiving` state holds the slot as `cpu-mut` for the duration
of the assembly because each Continue stage-copy is a multi-write
event. Only at `Complete` does the slot transition to `cpu-ref`,
making the bytes readable by the consumer (network FSM) via the
`Sample<'pool>` borrow.

**Cache maintenance pinning.** The §5.E lifecycle FSM places
cache_clean / cache_invalidate calls on specific pool transition
edges. For reassembly, the relevant edges are:

- `free → cpu-mut` at `Empty → Receiving`: emits
  `cache_invalidate_by_addr(slot, slot_size)` on speculative cores
  (M7+, A) per §5.E "Why two-sided RX invalidate" — pre-arm
  invalidate clears any speculatively prefetched lines.
- `cpu-mut → cpu-ref` at `Receiving → Complete`: no cache action;
  the slot stays in CPU-coherent state.
- `cpu-mut → free` (or `cpu-ref → free`) at terminal funnel: no
  cache action.

Author code in this FSM **MUST NOT** call `cache_clean` /
`cache_invalidate` directly via `<sce:call>` to §5.I intrinsics —
those are pinned to lifecycle FSM edges per RFC §5.E and the
diagnostic `pool/cache-maintenance-misplaced` catches violations.

---

## §7 Build-time fragmentation analysis

The four checks RFC §5.M defines are exercised concretely by the
deploy skeleton numbers:

### §7.1 Reassembly capacity check (hard error)

Invariant: `slot_size ≥ max_fragments_per_message × mtu_bytes`.

Deploy skeleton values (post-2026-05-01 revision per §9.1):

- MCU: `4096 ≥ 2 × 1472 = 2944`. ✓
- AP: `65536 ≥ 44 × 1472 = 64768`. ✓

Both profiles pass after the deploy revision. Build-time
diagnostic `reassembly/max-fragments-insufficient-for-mtu` is
unarmed for current values; it re-arms if either factor is
raised without the matching adjustment.

**Slot pool parity check (informational, §2.1).** Strict upstream
parity requires `slot_count ≥ 2 × peer_table.capacity`. Both
deploy skeletons intentionally over-commit:

- MCU: `slot_count = 4 < 2 × 16 = 32` (over-commit ratio 8×).
- AP: `slot_count = 32 < 2 × 256 = 512` (over-commit ratio 16×).

Over-commit is documented in §2.1 ("Upstream-divergent
generalization") and is informational only — no build error.
Authors who want strict parity raise `slot_count` to
`2 × peer_table.capacity`.

### §7.2 Stage-copy rate warning

Computed against `expected_p99_bytes` of the link feeding the
reassembly pool:

- MCU `udp_session.expected_p99_bytes = 1024`,
  `session_rx_pool.slot_size = 1536`.
  Stage-copy rate = max(0, 1024 - 1536) / 1024 = 0 (no stage
  copy for p99 within the 1536 RX slot). ✓
- AP `udp_session.expected_p99_bytes = 4096`,
  `session_rx_pool.slot_size = 4096`.
  Stage-copy rate = max(0, 4096 - 4096) / 4096 = 0. ✓ (right at
  the boundary; raising p99 by 1 byte triggers the warning).

### §7.3 Reassembly slot sizing recommendation (informational)

`slot_size_recommended = ceil(expected_p99_bytes / mtu_bytes) × mtu_bytes`.

- MCU: `ceil(1024 / 1472) × 1472 = 1 × 1472 = 1472`. So a 1472-byte
  reassembly slot would suffice for p99; current 4096 is an
  oversize buffer for above-p99 outliers. Informational-only.
- AP: `ceil(4096 / 1472) × 1472 = 3 × 1472 = 4416`. Current 65536
  is *much* larger than recommended; that is intentional for AP
  large-message scenarios. Informational-only.

### §7.4 Stage-copy WCET vs slot budget (hard error)

`stage_copy_wcet_us = expected_p99_bytes × memcpy_cycles_per_byte
/ clock_freq_mhz`.

- MCU: `1024 × 1.0 / 400 = 2.56 µs ≤ 200 µs`. ✓
- AP: preemptive scheduler — gate inactive (no
  `worker_slot_budget_us` declared).

---

## §8 Design gaps discovered (new this document)

### §8.1 Authoring-contract gaps

**G-RFM-1 — out-of-order Continue policy under BEST_EFFORT.**
**Resolved (2026-05-01 후속 OQ-W21 close + 2026-05-XX cascading
revision pass).** Verified against zenoh-pico 1.9.0 HEAD `3b3ab65`:
upstream applies **strict in-order, identical for RELIABLE and
BEST_EFFORT** (drop the in-flight defragmentation buffer on any
OOO or non-consecutive SN). The initial proposal
(reliability-conditional, bitmap for BEST_EFFORT) is rejected for
MVP — see §2.5 for upstream code citations. The four cascading
FSM-shape amendments (chain key 4→2-tuple, slot count N parallel
preserved as upstream-divergent generalization with parity
invariant, per-chain timeout retained as defense-in-depth, `start`
flag → `FRAGMENT_FIRST` / `FRAGMENT_DROP` patch-gated extensions)
have been folded into the document body — see §1 (chain key + wire
shape), §2.1 (slot pool), §2.4.5 (timeout posture).

**G-RFM-2 — link-level vs session-level trust class.**
**Resolved (2026-05-01 후속 #6 — OQ-W22 close).** Option (c) was
ratified: codegen splits every listener link into two logical
link-instances (`session_arming` + `established_session` sibling)
sharing one physical socket. RFC §5.M now contains the
"Listener-link trust-class lifecycle" subsection specifying the
trust-class semantic, and RFC §5.C contains the "Listener-link
sibling emission" subsection specifying the codegen mechanics;
deploy.yaml schema is unchanged. The build-time gate
`reassembly/untrusted-link-binding` is link-instance-scoped (not
socket-scoped) and remains a fully static check. Two new
diagnostics back the resolution:
`link/listener-link-not-paired-with-established-sibling` (§5.C
codegen self-check) and `reassembly/binding-on-unpaired-listener`
(§5.M, defense against orphaned bindings). See §5 above for the
revised trust-class composition prose; see RFC §5.M / §5.C for
the patches; see `docs/rfc-open-questions-log.md` OQ-W22 entry
for the closure record.

**G-RFM-3 — deploy capacity invariant violation.** As surfaced in
§7.1, both `mcu_target.yaml` and `ap_standalone.yaml` carry
`slot_size < max_fragments_per_message × mtu_bytes`. The values
were chosen for "reasonable MCU memory budget" without the math;
the build-time `reassembly/max-fragments-insufficient-for-mtu`
hard error would catch this on first build. RFC §5.M's check is
correct; the deploy values need correction. See §9 below.

### §8.2 New open questions (add to rfc-open-questions-log.md)

**OQ-W21 — out-of-order Continue under BEST_EFFORT.**
**Answered (2026-05-01 후속) + cascading items folded into body
(2026-05-XX).** Strict in-order, identical for both reliability
classes — see §2.5 for upstream citations. Bitmap-based reorder
is rejected for MVP (parity gate). The four cascading FSM-shape
amendments are now part of the document body (§1 chain key +
wire shape, §2.1 slot pool parity, §2.4.5 timeout posture); see
`rfc-open-questions-log.md` OQ-W21 entry for closure record.

**OQ-W22 — listener-link trust class lifecycle.**
**Answered (2026-05-01 후속 #6).** Option (c) ratified — codegen
splits every listener link into two logical link-instances
(`session_arming` + `established_session` sibling) sharing one
physical socket. Trust-class semantic patch landed in RFC §5.M
"Listener-link trust-class lifecycle"; codegen mechanics patch
landed in RFC §5.C "Listener-link sibling emission".
deploy.yaml schema unchanged. Build-time gate
`reassembly/untrusted-link-binding` is link-instance-scoped and
fully static. Two new diagnostics:
`link/listener-link-not-paired-with-established-sibling` (§5.C
template regression guard) +
`reassembly/binding-on-unpaired-listener` (§5.M defense against
orphan binding resolution). See `docs/rfc-open-questions-log.md`
OQ-W22 entry for closure record + cross-doc amend list.

---

## §9 Feedback to RFC

### §9.1 §5.M slot_size invariant gap surfaced

§7.1 of this document originally identified that the deploy
skeleton values
`(slot_size: 4096, max_fragments_per_message: 16, mtu_bytes: 1472)`
violated RFC §5.M's `slot_size ≥ max_fragments × mtu_bytes`
invariant on both MCU and AP profiles. **Resolved in deploy
revision (2026-05-01 후속).** `max_fragments_per_message` was
lowered to fit the existing `slot_size`:

- **MCU** (`mcu_target.yaml` + `ap_mcu_pair.yaml` mcu_node):
  `max_fragments_per_message: 16 → 2`. Worst case becomes
  2 × 1472 = 2944 ≤ 4096 ✓. A single fragmented message on MCU is
  at most 2 fragments (~3 KB), consistent with MCU memory budgets
  and with `qos.max_fragment_count` being the TX-side cap matching
  the RX-side reassembly cap.
- **AP** (`ap_standalone.yaml` + `ap_mcu_pair.yaml` ap_node):
  `max_fragments_per_message: 256 → 44`. Worst case becomes
  44 × 1472 = 64768 ≤ 65536 ✓. AP retains ~64 KB fragmented-message
  capacity, matching `qos.batch_size: 65536`.

The fix landed in the deploy/ files, not RFC §5.M (which has the
correct invariant). RFC §5.M is unchanged.

### §9.2 §5.M missing diagnostic

The four-state expansion in §2.6 + cascading revision pass surface
upstream events that RFC §5.M's diagnostic list does not enumerate:

- `reassembly/timeout-fired` — informational, on `TimedOut` entry
  (defense-in-depth signal per §2.4.5; not part of upstream parity).
- `reassembly/aborted` — informational with reason code
  (`out-of-order` / `evicted` / `duplicate-first` / `peer-drop` /
  `codec-error` / `unmatched-key`). The `out-of-order` reason
  replaces the earlier `reliable-out-of-order` (§2.5 Resolution
  flattened the policy across reliabilities); `incomplete-final`
  / `out-of-bounds-index` / `duplicate-index` from the bitmap-era
  draft are removed (streaming-cursor model has no bitmap to
  validate against). `peer-drop` is patch-gated (only emitted when
  peer advertises `_Z_PATCH_HAS_FRAGMENT_MARKERS`).
- `reassembly/unmatched-continue` — Router-side; Continue arrived
  with no matching slot.
- `reassembly/unmatched-final` — Router-side; Final arrived with
  no matching slot.
- `reassembly/unmatched-drop` — Router-side (patch ≥ 1); Drop
  extension arrived with no matching slot.
- `reassembly/slot-pool-full` — Router-side; First arrived but
  pool exhausted and `on_overflow != oldest-wins`.
- `reassembly/message-complete` — informational; carries assembly
  duration + fragment count for observability.

RFC §5.M has 11 diagnostics today; adding the seven above (with
the six reason codes for `reassembly/aborted` enumerated as a
single diagnostic with a `reason=` field) yields a complete set.
Recommended as a §5.M patch in the next review round.

---

## §10 Next-step scaffolding

When SCE Phase A lands the C11 emitter for §5.E buffer-pool +
§5.M reassembly variant + §5.L bounded-collection + §5.A
algorithm, the SCXML authored from this prose lives at:

- `sources/reassembly/reassembly_dispatcher.scxml` — the parent
  with N parallel slot regions. Imports the slot SCXML via
  XInclude.
- `sources/reassembly/reassembly_slot.scxml` — the four-state slot
  machine. Parametrized over the slot index N so all instances
  share the body.
- `sources/reassembly/tx_fragmenter.scxml` — the §3 TX-side
  fragmenter (algorithm-shaped, no slot table).

**Authoring is unblocked.** OQ-W21 (out-of-order policy) was
resolved (strict in-order, §2.5 Resolution); the cascading
FSM-shape amendments are folded into the body (§1, §2.1, §2.4.5).
Deploy capacity revision is landed (§9.1). OQ-W22 (listener-link
trust class lifecycle) was resolved (option (c), codegen split;
RFC §5.M "Listener-link trust-class lifecycle" + RFC §5.C
"Listener-link sibling emission"; deploy.yaml schema unchanged).
The dispatcher binds to a `<sce:rx-pool>` reference whose
resolution lands on the listener's `established_session` sibling
instance at codegen time.

The dispatcher SCXML is authored against `mcu_target.yaml` first,
then ported with no changes to `ap_standalone.yaml` (only the
slot count differs; FSM body is identical). This validates the
"static-first, dynamic-opt-in" invariant at the SCXML level.

---

## §11 Self-review against ARCHITECTURE §2.4 invariants

| Invariant | Check |
|---|---|
| 1. Static-first, dynamic-opt-in | ✓ Slot count is static (deploy.yaml), parallel regions emit at codegen time. No runtime instantiation |
| 2. Link drivers extensible (open set) | ✓ Reassembly does not depend on link class beyond `mtu_bytes`/`trust_class` — same FSM works for udp_session, tcp_session, future plugin-defined fragmenting links |
| 3. Kinds are additive | ✓ New behavior lands as additive edges on the existing four-state slot FSM (e.g. crypto-armed pool states would extend §5.E lifecycle, not this slot FSM) |
| 4. Generated code exports as library | ✓ The dispatcher emits as a callable library API (one entry per Fragment.* event); no main loop |
| 5. Platform gating only when necessary | ✓ Out-of-order policy is single-policy across reliabilities (§2.5 Resolution) and across platforms; cache maintenance pinning is platform-aware via §5.E. The defense-in-depth `reassembly_timeout_ms` is deploy-tunable but not platform-gated — same code path on MCU and AP |
| 6. `out/` is SSoT-downstream | ✓ This document is `docs/`, not `out/` — produces no codegen artifacts |

---

## §12 Change log

- **2026-05-01** — document created. Mirrors `docs/session-fsm.md`
  structure. Surfaces three design gaps (G-RFM-1 out-of-order
  policy, G-RFM-2 listener-link trust class lifecycle, G-RFM-3
  deploy capacity invariant violation), two new open questions
  (OQ-W21, OQ-W22), and six new recommended diagnostics for
  RFC §5.M (§9.2; one of them — `reassembly/aborted` — carries
  seven reason codes). Inputs: RFC §5.M / §5.E / §5.A / §5.L,
  `wire-spec-subset.md` §4.2, `session-fsm.md` §2.3,
  `deploy/{mcu_target,ap_standalone,ap_mcu_pair}.yaml`. Validates
  that the four-state expansion of RFC §5.M's three-state sketch
  preserves the contract surface (§2.6).
- **2026-05-01 (later) — OQ-W21 close.** §2.5 amended with
  upstream verification (zenoh-pico 1.9.0 HEAD `3b3ab65`,
  `src/transport/{unicast,multicast}/rx.c`,
  `include/zenoh-pico/transport/transport.h`,
  `src/transport/utils.c`, `src/transport/peer.c`,
  `include/zenoh-pico/protocol/{definitions/transport.h,ext.h}`,
  `CMakeLists.txt:306`). Resolution: **strict in-order, identical
  for RELIABLE and BEST_EFFORT** — initial reliability-conditional
  proposal rejected for MVP parity. G-RFM-1 marked resolved; OQ-W21
  marked answered. Cascading FSM-shape amendments (chain key
  4→2-tuple, slot count N parallel→2 per peer, no per-chain
  timeout, `start` → `FRAGMENT_FIRST` ext nomenclature) are
  documented in §2.5 as deferred revision items pending the next
  pass. They do NOT block OQ-W21 closure; they DO block Phase A
  SCXML authoring of `sources/reassembly/reassembly_slot.scxml`.
- **2026-05-01 (cascading revision pass) — 4 deferred items
  folded into body.** OQ-W21 follow-up.
  - **§1 chain key**: 4-tuple `(peer_zid, priority, reliability,
    sn_base)` → 2-tuple `(peer_zid, reliability)`. Priority and
    sn_base were watching-zenoh extrapolations with no upstream
    counterpart (`_z_t_msg_fragment_t = {_payload, _sn, first,
    drop}` at `transport.h:494-499`).
  - **§1 wire shape**: header bits `more` (`_Z_FLAG_T_FRAGMENT_M`)
    + `reliability` (`_Z_FLAG_T_FRAGMENT_R`) only; `FRAGMENT_FIRST`
    (id 0x02) + `FRAGMENT_DROP` (id 0x03) lifted to patch-gated
    extensions (`_Z_PATCH_HAS_FRAGMENT_MARKERS(patch >= 1)`); legacy
    peer chain-start inference ("buffer empty AND consecutive SN")
    documented as the baseline FSM input model.
  - **§2.1 slot pool**: shared bounded pool of size N kept as an
    upstream-divergent generalization (per ARCHITECTURE §2.4 #1
    static-first; inline 2 × peer_table.capacity buffers would
    force ~128 KB on MCU regardless of activity). Parity invariant
    `slot_count ≥ 2 × peer_table.capacity` documented; one-active-
    slot-per-(peer, reliability) allocation rule + `duplicate-first`
    Aborted reason added. Phase C C14 parity gate's pool-exhaustion
    sub-test marked **disabled** until end-to-end equivalence harness
    lands.
  - **§2.4.5 timeout**: `reassembly_timeout_ms` retained as
    **defense-in-depth beyond upstream**, not part of parity surface.
    §5 attack-cost section gained a "slot-pinning under cooperative
    attacker" sub-paragraph documenting upstream's disconnect-only
    cleanup vs watching-zenoh's deploy-time bound on slot hold time.
  - **§2.4 transitions**: bitmap-based body replaced with
    streaming-cursor body (`slot.bitmap` → `slot.last_sn`,
    `_z_sn_precedes` + `_z_sn_consecutive` validation,
    `~/zenoh-pico/src/transport/utils.c:85-88`). §2.4.4 redefined
    from "incomplete bitmap" to "out-of-order continue" (single
    abort path for streaming model). §2.4.6 expanded with
    `duplicate-first` sub-cause. §2.4.7a new (peer-drop on
    `Fragment.Drop` extension, patch ≥ 1).
  - **§2.3 Router**: `Fragment.Drop` branch added; `Fragment.First`
    branch gained duplicate-key check.
  - **§2.5**: Cascading deferred-list collapsed to a short
    self-reference (4 bullets folded; §8.1 G-RFM-1 follow-up no
    longer blocks SCXML authoring).
  - **§7.1**: capacity check refreshed (post-deploy-revision values
    pass); slot-pool parity check (informational) added.
  - **§8.1 / §8.2 / §9.1 / §9.2 / §10 / §11 row 5**: status
    refreshed for cascading-folded shape; §9.2 reason codes
    updated (`out-of-order` single-policy, `duplicate-first`,
    `peer-drop` added; `incomplete-final` / `out-of-bounds-index`
    / `duplicate-index` removed); §10 authoring blocker reduced
    to OQ-W22.
  - **`wire-spec-subset.md` §4.2 Fragment row** amended in the same
    pass (header bits / patch-gated extensions / 2-tuple chain key /
    cross-ref to §1).

  **Outcome**: Phase A SCXML authoring blocker on the reassembly
  side reduced to OQ-W22 (listener-link trust class lifecycle,
  requires RFC §5.M or §5.C patch). The four cascading items no
  longer require external dependencies — all upstream evidence is
  cited inline.
- **2026-05-01 후속 #6 — OQ-W22 close.** Option (c) ratified —
  codegen splits every listener link into two logical
  link-instances (`session_arming` + `established_session`
  sibling) sharing one physical socket. Trust-class semantic
  patch landed in RFC §5.M "Listener-link trust-class lifecycle";
  codegen mechanics patch landed in RFC §5.C "Listener-link
  sibling emission". deploy.yaml schema unchanged. Build-time
  gate `reassembly/untrusted-link-binding` is link-instance-scoped
  (not socket-scoped) and remains a fully static check.
  - **§5** rewritten: trust-class table preface clarified as
    keyed on *link instance* trust_class; "Listener links emit
    two instances" subparagraph added with cross-refs to RFC
    §5.M / §5.C and `session-fsm.md` §2.3.
  - **§8.1 G-RFM-2** → resolved (option (c) citation +
    diagnostic list).
  - **§8.2 OQ-W22** → answered (close summary + cross-refs).
  - **§10** authoring-blocker section flipped to "unblocked"
    — dispatcher SCXML can now bind to the listener's
    established_session sibling at codegen time.

  **Outcome**: Phase A SCXML authoring on the reassembly side is
  fully unblocked. Remaining cross-doc Phase A blocker = OQ-W15
  (HMAC + RNG primitive ownership ratification, SCE maintainer
  sync), which gates only `stateless_accept` SCXML on
  public-Internet-facing listener-bearing MCUs.
