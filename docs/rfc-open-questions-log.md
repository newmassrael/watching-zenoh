# RFC Open Questions Log

**Purpose.** Single place to track every unresolved question the
watching-zenoh design raises — both SCE-side (addressed to SCE
maintainers, land with SCE changes) and wire-side (answerable
inside this project via upstream verification).

**Two id spaces.**
- **Q1–Q14** — SCE-side; canonical home is `rfc-sce-protocol-synthesis.md`
  §8. This log mirrors them so status can be tracked without editing
  the RFC on every update.
- **OQ-W1–OQ-W23** — wire-subset and deploy-side; canonical home is
  `wire-spec-subset.md` §10 (W1–W8) and this log (W9–W23). Same
  mirroring rationale.

**Status values.**
- `open` — no answer yet; blocks something downstream
- `answered` — resolved; action item captured and tracked elsewhere
- `needs-verification` — proposed answer exists but must be
  confirmed against source/spec before treating as answered
- `superseded` — replaced by a later question or a design pivot

**Owner.** Who is expected to resolve the question: `SCE maintainer`,
`watching-zenoh author` (this project), `upstream Zenoh` (requires
reading/running upstream), or `either`.

---

## SCE-side questions (Q1–Q14)

### Q1 — `algorithm` kind naming

- **Status:** open
- **Owner:** SCE maintainer
- **Question:** Is `algorithm` the right kind name? Alternatives:
  `routine`, `function`, `pure`. `function` overlaps with `FuncSig`
  in the type-context layer.
- **Impact if open:** Cosmetic but touches every RFC §5.A example
  and every downstream SCXML source.
- **Last update:** 2026-04-24 (initial).

### Q2 — Existing `Timer` kind vs RFC §5.D

- **Status:** needs-verification
- **Owner:** SCE maintainer
- **Question:** Does the existing `Timer` kind already cover §5.D
  timer needs? If yes, §5.D collapses to worker-only.
- **Evidence gathered 2026-04-24:**
  - `ForgeKind::Timer` exists (`sce-build/src/forge/model.rs:90`).
  - Classified as `RuntimeDep::ForgeRuntimeHal` — implies HAL
    coupling already present.
  - `TimerModel` / `TimerEntry` / `TimerType` shape exists but
    hasn't been reviewed against the periodic/one-shot/cancelable
    requirements §5.D enumerates (keepalive timer, OPEN timeout,
    reassembly GC, fragment per-peer timeout).
- **Action:** reviewer reads `sce-build/src/forge/model.rs::TimerModel`
  and decides: reuse-as-is / extend / keep §5.D split.
- **Last update:** 2026-04-24 — downgraded from `open` to
  `needs-verification` because Timer demonstrably exists; only the
  "does it cover §5.D" judgement remains.

### Q3 — `algorithm` calling `algorithm`

- **Status:** open
- **Owner:** SCE maintainer
- **Question:** Should `algorithm` allow calls to other `algorithm`
  kinds (`sce:call` stmt in §5.A)? Useful (CRC reuses byte-fold
  primitive) but opens call-graph/cycle detection scope.
- **Proposal:** MVP forbids; Phase 2 allows non-recursive.
- **Last update:** 2026-04-24 (initial).

### Q4 — `compute-at="build"` on `Transform`

- **Status:** open
- **Owner:** SCE maintainer
- **Question:** Should `<sce:compute-at="build">` be available on
  existing `Transform`, or strictly `algorithm` / `const`? Opening
  to `Transform` enables build-time expression evaluation broadly
  but has larger implications (const-folding every `Transform`
  input).
- **Last update:** 2026-04-24 (initial).

### Q5 — §5.B codec DSL PR granularity

- **Status:** open
- **Owner:** SCE maintainer
- **Question:** Land all of §5.B at once (one PR) or split by feature
  (VLE / variant / flags / present-if / len-prefix / TLV chain /
  DMA-align → ~seven PRs)? Split reduces review risk, stretches
  schedule.
- **Proposal (this project):** split by feature, with VLE + flags +
  len-prefix as the first landing since they unblock Phase A CRC
  parity gate (RFC §7 Phase A).
- **Last update:** 2026-04-24 (initial).

### Q6 — C11 vs C99 for the C backend

- **Status:** open
- **Owner:** SCE maintainer
- **Question:** Target C11 strictly or C99 + `<stdint.h>` for wider
  reach? C11 adds `_Static_assert` but loses some legacy toolchains.
- **Constraint from this project:** ARCHITECTURE §2.1 already pins
  `C11`. If SCE elects C99 we must shim `_Static_assert` via
  `typedef` trick; still feasible, but a spec-level decision.
- **Last update:** 2026-04-24 (initial).

### Q7 — `sce:extern` whitelist location

- **Status:** open
- **Owner:** SCE maintainer
- **Question:** Separate repo/crate for the intrinsics whitelist, or
  in-tree at `sce-build/runtime/sce_intrinsics_runtime/`?
- **Preference (this project):** in-tree to keep versioning locked
  with `sce-build`. Downstream targets add plugins via §5.I target
  plugin mechanism rather than forking the whitelist.
- **Last update:** 2026-04-24 (initial).

### Q8 — `link` kind driver extensibility

- **Status:** answered
- **Answer:** Yes. Drivers are an open set via the **target-plugin**
  mechanism in RFC §5.I. Core ships `tokio_udp`, `tokio_tcp`,
  `lwip_udp`, `lwip_tcp`, `serial_uart`, `websocket_tcp`.
  Additional drivers (BLE, Raweth, QUIC, custom) enter via a
  target-plugin YAML referenced by `deploy.yaml →
  extern_symbols.target_plugin`.
- **Captured as:** ARCHITECTURE §2.4 invariant #2 ("Link drivers are
  extensible"). Diagnostic additions tracked in §5.I:
  `extern/target-plugin-symbol-conflict`,
  `link/driver-not-in-core-or-plugin`.
- **Last update:** 2026-04-24 (answered at RFC authoring time).

### Q9 — `deploy.yaml` `memory.sram_regions` format

- **Status:** open
- **Owner:** SCE maintainer
- **Question:** Bytes with suffix (`64K`) or explicit integer
  (`65536`)? Which is less error-prone?
- **Data point:** `zenoh-pico` config historically uses integer
  byte counts. Matching upstream ergonomics argues for integer.
- **Last update:** 2026-04-24 (initial).

### Q10 — Parametric kinds XSD shape

- **Status:** open
- **Owner:** SCE maintainer
- **Question:** `sce:type-param` as a new XSD element, or a magic
  prefix `$W` on existing attributes?
- **Preference (this project):** element form — XSD validation
  cleanliness, Phase D concern only.
- **Last update:** 2026-04-24 (initial).

### Q11 — `bounded-collection` capacity source

- **Status:** open
- **Owner:** SCE maintainer
- **Question:** Always deploy-sourced, or allow
  `<sce:capacity const="N"/>` for truly fixed structures (timer
  wheels, etc.)?
- **Proposal (RFC):** allow both, deploy-source preferred when the
  same capacity appears across multiple machines so sizing can vary
  per deployment.
- **Last update:** 2026-04-24 (initial).

### Q12 — Fragment / reassembly: author-level vs shipped template

- **Status:** open
- **Owner:** SCE maintainer
- **Question:** Reassembly FSM as author-level SCXML (current RFC
  proposal), or ship a canonical `fragment-reassembly` template in
  SCE?
- **Proposal (RFC):** author-level, with a template library shipped
  under `examples/`. No new SCE-side kind.
- **Last update:** 2026-04-24 (initial).

### Q13 — Client vs peer session FSM variants

- **Status:** answered
- **Owner:** SCE maintainer (no SCE-side action; this resolves
  inside watching-zenoh authoring).
- **Question:** Two sibling SCXML files (`session_peer.scxml`,
  `session_client.scxml`, MVP) or one parametric FSM via §5.G
  (Phase D) or a mode-attribute on a single FSM?
- **Answer (2026-04-25):** The question was miscast. Reading zenoh
  1.5.0 `io/zenoh-transport/src/unicast/establishment/{open.rs,
  accept.rs}` shows that the session (transport) layer is
  **wire-identical for peer and client**: one `OpenLink` struct
  drives both, parameterized only by `manager.config.whatami`.
  No peer-vs-client branching in the handshake, extensions, or
  `Established` regions. Peer/client differences live in scouting
  (active vs passive default) and in the network layer (declaration
  topology, interest semantics) — not in the session FSM.
- **What differs structurally at the session layer is unicast vs
  multicast**: unicast does a 4-way Init/Open handshake; multicast
  has no handshake and learns peers via periodic `Join` (upstream
  `multicast/establishment.rs` starts tx/rx immediately;
  `multicast/rx.rs:60 handle_join_from_peer` is where peer identity
  enters).
- **Resolution.** Two sibling SCXML files, split by **transport
  class** (`session_unicast.scxml`, `session_multicast.scxml`), not
  by **node mode**. `whatami` is a compile-time constant from
  deploy, embedded in emitted `InitSyn`/`Join`, not branched on.
  No §5.G parametric dependency.
- **Captured as:** [`docs/session-fsm.md`: Q13 answer](session-fsm.md#53-q13-answer); source-layout rename
  in ARCHITECTURE §5; RFC §7 C8 retarget (was "Client-mode session
  FSM variant", becomes "Multicast session FSM authoring" — roughly
  comparable effort, different structural work).
- **Last update:** 2026-04-25 — downgraded from `open` to `answered`
  after upstream evidence (`docs/session-fsm.md` — [Inside the session FSM itself — differences are minimal](session-fsm.md#51-inside-the-session-fsm-itself--differences-are-minimal) through [Q13 answer](session-fsm.md#53-q13-answer)).

### Q14 — `algorithm` calling `bounded-collection` ops

- **Status:** open
- **Owner:** SCE maintainer
- **Question:** Direct `sce:call` (treat collection ops as
  algorithm-callable methods), or expose collections through a
  procedure-kind interface?
- **Proposal (RFC):** allow both; `sce:call` for synchronous
  lookups (KeyExpr table probe), procedure-kind for event-driven
  patterns ("new subscriber arrived").
- **Last update:** 2026-04-24 (initial).

---

## Wire-subset questions (OQ-W1–OQ-W8)

### OQ-W1 — zenoh-pico release pin for Phase-A freeze

- **Status:** open
- **Owner:** watching-zenoh author
- **Question:** Exact zenoh-pico release to pin against at Phase-A
  freeze. Current upstream zenoh pinned in local corpus is 1.5.0
  (`.cargo/git/checkouts/zenoh-*/`); zenoh-pico release at freeze
  time to be chosen.
- **Action:** read zenoh-pico tag listing when Phase A entry is
  imminent; pick latest stable that matches upstream zenoh minor.
- **Last update:** 2026-04-24 (initial).

### OQ-W2 — Auth baseline methods

- **Status:** answered (2026-05-01 후속 #5) — **MCU parity baseline =
  `{none}` only.** USRPWD deferred to Phase D+ alongside OQ-W10
  re-opening.
- **Owner:** upstream Zenoh / watching-zenoh author (verified
  against zenoh-pico source).
- **Question:** Which Auth methods are MVP baseline beyond "none"?
  zenoh-pico historically supports USRPWD; pubkey is AP-heavy.
- **Resolution (2026-05-01 후속 #5).** Verified against zenoh-pico
  1.9.0 HEAD `3b3ab65`: zenoh-pico 1.9.0 has **no transport-layer
  Auth implementation** (no `Z_FEATURE_AUTH`/`Z_FEATURE_USRPWD`
  feature gate, no Auth extension ID in
  `~/zenoh-pico/include/zenoh-pico/protocol/ext.h:46-50`,
  `Z_CONFIG_USER_KEY` / `PASSWORD_KEY` at `config.h.in:110, 117`
  defined but unconsumed in `src/`). The original OQ-W2 proposal
  `{none, usrpwd}` is therefore **not parity-aligned**; the
  parity-correct baseline is `{none}` only. USRPWD multi-step
  handshake shape (OQ-W10) deferred together to Phase D+ when
  Auth surfaces. Pubkey remains deferred Phase D++ as originally
  framed. See OQ-W10 entry below for full evidence + Phase D+
  re-opening contract.
- **Last update:** 2026-05-01 후속 #5 (OQ-W2 close — `{none}`
  baseline; `{usrpwd}` and `{pubkey}` deferred to Phase D+).

### OQ-W3 — Interest semantics with no router present

- **Status:** answered (2026-05-01 후속, scouting-fsm.md authoring) —
  not router-only; three transport-class-specific mechanisms.
- **Owner:** watching-zenoh author (verified against zenoh-pico source).
- **Question:** Peer A sends `Interest{Future, subscribers}`; peer B
  has a local `DeclareSubscriber`. Does B reply with matched
  declares + `DeclareFinal`, or is this router-only in 1.x?
- **Why it matters:** determines whether the MCU's `Interest`
  handler must be a real participant (Included, bounded form) or
  pass-through (Deferred).
- **Resolution (2026-05-01 후속, verified against zenoh-pico
  1.9.0 HEAD `3b3ab65`).** **Not router-only in 1.x.** Three
  transport-class-specific mechanisms achieve declaration sync;
  the MCU's Interest handler is a real participant on the
  multicast peer-mesh path (Included, bounded form per
  `wire-spec-subset.md` §5) and a no-op on the unicast path (where
  Mechanism 1 below covers the same need without Interest).
  Evidence — see `docs/scouting-fsm.md` §3.1 / §3.2 for full
  prose, file:line citations:
  1. **Unicast peer-peer (Mechanism 1, acceptor push).**
     `_z_interest_process_interest` short-circuits on unicast at
     `~/zenoh-pico/src/session/interest.c:531-535`
     (`if (zn->_tp._type == _Z_TRANSPORT_UNICAST_TYPE) return
     _Z_RES_OK; // Nothing to do on unicast`). Instead, the
     acceptor pushes ALL local declares + DeclareFinal at
     handshake completion — `_z_interest_push_declarations_to_peer`
     (`~/zenoh-pico/src/session/interest.c:194-201`) called from
     `~/zenoh-pico/src/transport/unicast/accept.c:148-149`
     immediately after a successful 4-way handshake admits the
     new peer.
  2. **Multicast peer mesh (Mechanism 2, peer Interest reply).**
     `_z_interest_process_interest` lines 538-566 reply to inbound
     `Interest{CURRENT, <flags>}` with matched declares for each
     enabled flag (KEYEXPRS / SUBSCRIBERS / QUERYABLES / TOKENS) +
     a DeclareFinal — peer-handled, **no router required**.
     Joining peer triggers the pull side at session open:
     `~/zenoh-pico/src/net/session.c:149-153`
     (`Z_FEATURE_MULTICAST_DECLARATIONS == 1` guard) calls
     `_z_interest_pull_resource_from_peers`
     (`~/zenoh-pico/src/session/interest.c:203-214`) which sends
     `Interest{CURRENT, KEYEXPRS}` reliably to the multicast group.
  3. **Client unicast to router.** Mechanism 1 from the
     router's side (router pushes its aggregated declares to
     client). The "router-only" framing in the original question
     applies *only* to this topology — clients without a router
     have neither an acceptor that aggregates nor a multicast
     mesh to interrogate.
- **Implication for `declare_fsm.scxml` authoring contract.**
  Transport-class guard at the top of the receive handler is the
  mechanical knob. Three behaviors:
  - Outbound at multicast session open: send Interest.
  - Outbound at unicast acceptor handshake complete: send all
    local declares + DeclareFinal (unsolicited).
  - Inbound on Interest receive: unicast = no-op; multicast =
    match against local declared-* tables, emit declares + Final.
- **Last update:** 2026-05-01 후속 (resolved — see
  `docs/scouting-fsm.md` §3 + §9.1).

### OQ-W4 — `ext::Compression` critical-bit safety

- **Status:** answered (2026-05-01 후속 #5) — *transport-level
  Compression extension is absent in zenoh-pico 1.9.0; MCU parity
  scope therefore omits it. Unknown-mandatory extension handling is
  refuse-with-error, matching MVP intent.*
- **Owner:** upstream Zenoh / watching-zenoh author (verified
  against zenoh-pico source).
- **Question:** Does any upstream peer ever emit a compression
  extension **without** the ignorable bit set? If yes, MVP must
  reject such sessions cleanly with
  `Close{reason=unsupported_extension}` instead of silently
  corrupting.
- **Resolution (2026-05-01 후속 #5, verified against zenoh-pico
  1.9.0 HEAD `3b3ab65`).** Two-layer answer:

  **(a) Compression at transport layer.** zenoh-pico 1.9.0 does
  **not** implement a transport-level Compression extension at
  all. Evidence:
  - The transport extension ID enumeration at
    `~/zenoh-pico/include/zenoh-pico/protocol/ext.h:46-50` declares
    only five extension IDs:
    `_Z_MSG_EXT_ID_JOIN_QOS` (0x01 | M),
    `_Z_MSG_EXT_ID_JOIN_PATCH` (0x07),
    `_Z_MSG_EXT_ID_INIT_PATCH` (0x07),
    `_Z_MSG_EXT_ID_FRAGMENT_FIRST` (0x02),
    `_Z_MSG_EXT_ID_FRAGMENT_DROP` (0x03).
    No Compression extension ID is defined.
  - `grep -rn "compression" ~/zenoh-pico/src` returns zero
    matches; `grep -rn "Compression" ~/zenoh-pico/include` matches
    only `~/zenoh-pico/include/zenoh-pico/api/encoding.h` (which
    is *payload* encoding — `application/x-compressed` MIME-style
    encoding hints — not a transport extension).
  - The Init/Open extension iterators (`_z_init_decode_ext` at
    `~/zenoh-pico/src/protocol/codec/transport.c:221-235`) handle
    only `_Z_MSG_EXT_ID_INIT_PATCH`; everything else falls through
    to the unknown-extension default.

  **(b) Unknown-extension policy (defends against future or
  upstream peers that emit Compression).** If any peer ever sends
  a transport extension zenoh-pico does not understand, the policy
  is keyed on the mandatory bit:
  - **Mandatory unknown** (M-flag set, `_Z_MSG_EXT_FLAG_M = 0x10`):
    `_z_init_decode_ext` returns
    `_Z_ERR_MESSAGE_EXTENSION_MANDATORY_AND_UNKNOWN`
    (`transport.c:230-233`). The handshake fails; no `InitAck` /
    `OpenAck` is sent. Upstream's mandatory-bit semantics are
    correctly honored.
  - **Non-mandatory unknown** (M-flag clear): silently ignored
    (no else branch — the extension is consumed by the iterator
    and discarded).

  **MVP implication.** Compression is *not* in the MVP wire
  surface (`docs/wire-spec-subset.md` §7.2 "ext::Compression"
  row was already accept-and-ignore). The watching-zenoh policy
  matches: codec ignores non-mandatory unknown extensions; refuses
  the session via `Close{UNSUPPORTED}` on mandatory unknown. This
  is identical to zenoh-pico parity *and* defensive against any
  upstream zenoh router that might emit a mandatory Compression in
  a future release.

  **Action: none required for MVP.** If a future upstream release
  adds mandatory Compression at the transport layer, this OQ
  re-opens with the watching-zenoh task being to author
  `sources/algorithm/lz4.scxml` (or whichever compression upstream
  picks) and bind it to the Compression extension chain.
- **Last update:** 2026-05-01 후속 #5 (OQ-W4 close — Compression
  absent in zenoh-pico 1.9.0; unknown-mandatory refuse-policy
  honored).

### OQ-W5 — OAM drop semantics

- **Status:** open
- **Owner:** watching-zenoh author
- **Question:** For transport and network OAM messages outside the
  MVP generation scope — on decode, is "drop" a silent discard or a
  diagnostic event?
- **Proposal:** diagnostic event (`transport/oam-ignored`,
  `network/oam-ignored`), no application callback. Records for
  operator visibility, no surface area obligation.
- **Action:** ratify when deploy.yaml diagnostic sections are
  authored.
- **Last update:** 2026-04-24 (initial).

### OQ-W6 — Batch and fragment defaults

- **Status:** answered (committed in `deploy/`).
- **Owner:** watching-zenoh author
- **Question:** Default `batch_size` and `max_fragment_count` in the
  deploy skeletons. Upstream defaults (~64 KiB batch, ~2^16
  fragments) are too generous for MCU; MCU-friendly defaults TBD.
- **Resolution (2026-05-01).** MCU profile: `batch_size: 4096`,
  `max_fragment_count: 16`, `batch_linger_ms: 5`. AP profile:
  `batch_size: 65536`, `max_fragment_count: 256`,
  `batch_linger_ms: 1`. Numbers committed in
  `deploy/mcu_target.yaml` (`qos:` block) and
  `deploy/ap_standalone.yaml`; the asymmetric pair pattern is in
  `deploy/ap_mcu_pair.yaml`. MCU `batch_size: 4096` fits one SRAM2
  quarter-slot; MCU `max_fragment_count: 16` is the upstream `2^16`
  cap dropped two orders of magnitude for the cooperative-scheduler
  reassembly invariant. Authors override per-deploy with awareness
  of the SRAM budget.
- **Last update:** 2026-05-01 (resolved at deploy/ skeleton authoring).

### OQ-W7 — `ext::PatchType` mismatch policy

- **Status:** answered (2026-05-01 후속 #5) — **direction-asymmetric:
  unicast initiator refuses higher-patch InitAck; acceptors min-clamp.**
- **Owner:** watching-zenoh author (verified against zenoh-pico
  source).
- **Question:** Peer on higher patch level may emit messages we
  can't parse. MVP proposal: refuse sessions where the negotiated
  patch level exceeds ours. Upstream may mandate min-clamp instead.
- **Resolution (2026-05-01 후속 #5, verified against zenoh-pico
  1.9.0 HEAD `3b3ab65`).** Upstream policy is **direction-asymmetric**:

  **Unicast initiator (open side) on InitAck reception — REFUSE**
  if peer's patch > ours.
  `~/zenoh-pico/src/transport/unicast/transport.c:141-149`:
  ```c
  #if Z_FEATURE_FRAGMENTATION == 1
      if (iam._body._init._patch <= ism._body._init._patch) {
          param->_patch = iam._body._init._patch;
      } else {
          // TODO: Use a better error code?
          _Z_ERROR_LOG(_Z_ERR_GENERIC);
          ret = _Z_ERR_GENERIC;
      }
  #endif
  ```
  When an `InitAck.patch` exceeds the initiator's advertised
  patch, the open path errors out (currently with
  `_Z_ERR_GENERIC`; the `// TODO` comment notes a better error
  code is pending). The session is *not* established. This is a
  refusal, not a clamp.

  **Acceptor side (Join handler / peer-table ingestion) —
  MIN-CLAMP** to `min(peer_patch, _Z_CURRENT_PATCH)`.
  - `~/zenoh-pico/src/transport/peer.c:225`:
    `peer->common._patch = param->_patch < _Z_CURRENT_PATCH ? param->_patch : _Z_CURRENT_PATCH;`
  - `~/zenoh-pico/src/transport/multicast/rx.c:407`:
    `entry->common._patch = msg->_patch < _Z_CURRENT_PATCH ? msg->_patch : _Z_CURRENT_PATCH;`

  When an inbound peer (via Join on multicast or via InitSyn on
  unicast acceptor side) advertises a higher patch, the local
  side simply records the lower of the two. The peer's higher
  patch features are ignored; communication continues at the
  capability floor.

  **Constants.** `_Z_NO_PATCH = 0x00`, `_Z_CURRENT_PATCH = 0x01`
  at `~/zenoh-pico/include/zenoh-pico/protocol/definitions/transport.h:100-101`.
  The patch enum is currently 2-valued (0 and 1), where `1 =
  _Z_PATCH_HAS_FRAGMENT_MARKERS` (line 102). The patch field
  itself is gated on `Z_FEATURE_FRAGMENTATION == 1`; when
  fragmentation is compile-time disabled, the patch field is not
  encoded (`transport.c:67, 92-93, 207-216`).

  **Why the asymmetry is correct.** The initiator's `InitSyn`
  has already declared the initiator's patch ceiling. An
  `InitAck` with a *higher* patch means the acceptor is offering
  a feature the initiator did not advertise — that violates the
  protocol's own min-clamp principle (the acceptor should have
  clamped on read). A protocol-violating `InitAck` is a hard
  error. By contrast, the acceptor reading an `InitSyn` (or
  multicast `Join`) with a higher patch correctly clamps to its
  own ceiling — the peer is offering more, the local accepts the
  intersection.

  **MVP implication.** watching-zenoh `session_unicast.scxml`
  Opening sub-state graph implements:
  - On `InitAck` reception: guard `peer.patch <= local.patch`;
    fail to `Closing(reason=UNSUPPORTED)` per session-fsm §2.4
    close-paths table on guard violation.
  - On `InitSyn` reception (acceptor): set
    `session.patch = min(peer.patch, local.patch)` per
    session-fsm §2.2 `Accepting.SentInitAck` entry action.
  Both behaviors mirror upstream byte-for-byte and pass the
  Phase C C14 parity gate.

  The MVP "refuse" proposal in the original OQ-W7 question
  framing was *partially* correct — it refuses on the
  *initiator* path, but the acceptor path is min-clamp. The
  resolution combines both; the SCXML body honors direction.
- **Last update:** 2026-05-01 후속 #5 (OQ-W7 close — direction-
  asymmetric: initiator refuses, acceptor min-clamps;
  mechanically backed by zenoh-pico file:line at
  `unicast/transport.c:141-149`, `peer.c:225`, `multicast/rx.c:407`).

### OQ-W8 — Bounded-collection default capacities

- **Status:** answered (committed in `deploy/`).
- **Owner:** watching-zenoh author
- **Question:** Default capacities for local sub / queryable /
  pending-query / in-flight-reassembly tables on "small MCU" vs
  "AP node" profiles.
- **Reference:** zenoh-pico uses compile-time macros for these; we
  mirror into `deploy.yaml`.
- **Resolution (2026-05-01).** Both profiles' `limits:` blocks
  committed. MCU profile (`peer_table: 16` /
  `multicast_peer_table: 8` / `local_subscriptions: 16` /
  `local_queryables: 8` / `pending_queries: 8` /
  `in_flight_reassembly: 4` / `tx_queue: 16`) is sized so the total
  SRAM footprint of all `bounded-collection` instances combined fits
  in one SRAM region alongside the statechart instance. AP profile
  scales each value an order of magnitude higher
  (`peer_table: 256` etc.). Numbers committed in
  `deploy/mcu_target.yaml` and `deploy/ap_standalone.yaml`. Per-deploy
  overrides expected as authors add SCXML.
- **Last update:** 2026-05-01 (resolved at deploy/ skeleton authoring).

### OQ-W9 — Client mode and multicast session

- **Status:** answered (2026-05-01 후속, scouting-fsm.md authoring) —
  clients DO scout multicast, do NOT run multicast sessions.
- **Owner:** watching-zenoh author (verified against zenoh-pico source).
- **Question:** Does a `WhatAmI::Client` node ever run a multicast
  **session** (periodic `Join` + peer table + low-latency
  `NetworkMessage` exchange over UDP multicast)? Clients
  definitely use multicast for **scouting** (send `Scout`, listen
  for `Hello`), but a scouting link is a different `link` kind
  instance than a session multicast link (wire-spec-subset §8
  confirms framer differs).
- **Why it matters:** decides whether `session_multicast.scxml` is
  ever instantiated in a client-mode deploy. If clients never
  participate in multicast sessions, the deploy matrix simplifies
  (`mode: client` → only `session_unicast.scxml`).
- **Resolution (2026-05-01 후속, verified against zenoh-pico
  1.9.0 HEAD `3b3ab65`).** Clients refuse multicast *sessions*;
  they participate in multicast *scouting*. Evidence:
  - `_z_multicast_open_client` at
    `~/zenoh-pico/src/transport/multicast/transport.c:153-162`
    explicitly returns `_Z_ERR_CONFIG_UNSUPPORTED_CLIENT_MULTICAST`
    with a `// @TODO: not implemented` comment. No code path opens
    a multicast session for `whatami=client`.
  - Symmetric peer path at `transport.c:116-151`
    (`_z_multicast_open_peer`) is fully implemented and emits
    `Z_JOIN` with `whatami=Z_WHATAMI_PEER` —
    `_z_t_msg_make_join(Z_WHATAMI_PEER, Z_TRANSPORT_LEASE, ...)`
    at `transport.c:130`.
  - Scouting layer is `whatami`-agnostic — `_z_s_msg_make_scout`
    at `~/zenoh-pico/src/protocol/definitions/transport.c:419-428`
    encodes the `what` filter bitmask but does not encode the
    sender's role; the sender's role is conveyed only in `Hello`
    replies (`_z_s_msg_make_hello` at
    `transport.c:431-445`). Client mode scouting works the same
    as peer mode scouting at the wire layer.
- **Build-time enforcement (proposed in [`docs/scouting-fsm.md`: OQ-W9 closure](scouting-fsm.md#64-oq-w9-closure-clientmulticast-session)
  + §9.4).** New diagnostic `deploy/client-multicast-session-
  unsupported` (hard error) fires when
  `deploy.machines.<m>.whatami: client` AND any link in
  `deploy.machines.<m>.links` carries `role: session` AND
  `class: udp_multicast`. RFC §5.K patch.
- **Cross-doc amendment.** `docs/session-fsm.md` §3.4 to be
  amended to point at [`docs/scouting-fsm.md`: OQ-W9 closure](scouting-fsm.md#64-oq-w9-closure-clientmulticast-session) (one-paragraph
  diff, in `docs/scouting-fsm.md` §9.2).
- **Raised by:** `docs/session-fsm.md` §3.4 / §8.2.
- **Last update:** 2026-05-01 후속 (resolved — see
  [`docs/scouting-fsm.md`: OQ-W9 closure](scouting-fsm.md#64-oq-w9-closure-clientmulticast-session) + §9.4).

### OQ-W10 — `ext::Auth` multi-step handshake shape

- **Status:** answered (2026-05-01 후속 #5) — **moot for MCU parity:
  zenoh-pico 1.9.0 has no transport-layer Auth implementation.**
- **Owner:** watching-zenoh author (verified against zenoh-pico
  source).
- **Question:** `ext::Auth` (notably USRPWD) may require multiple
  round-trips (challenge/response). Does it fit into the existing
  `InitSyn/InitAck/OpenSyn/OpenAck` alternation — i.e. challenge
  piggybacked on `InitAck`, response on `OpenSyn` — or does it
  need an intra-`Opening` sub-state like
  `Opening.AwaitingAuthChallenge`?
- **Resolution (2026-05-01 후속 #5, verified against zenoh-pico
  1.9.0 HEAD `3b3ab65`).** zenoh-pico 1.9.0 does **not** implement
  transport-level Auth at all. The MCU parity scope therefore
  *omits* Auth entirely; the USRPWD multi-step shape question is
  moot for MVP.

  **Evidence.**
  - Config keys exist but are **unconsumed**:
    - `Z_CONFIG_USER_KEY = 0x43` at
      `~/zenoh-pico/include/zenoh-pico/config.h.in:110`
    - `Z_CONFIG_PASSWORD_KEY = 0x44` at
      `~/zenoh-pico/include/zenoh-pico/config.h.in:117`
    Both have docstrings ("The user name to use for
    authentication", "The password to use for authentication")
    but `grep -rn "Z_CONFIG_USER_KEY\|Z_CONFIG_PASSWORD_KEY"
    ~/zenoh-pico/src` returns zero matches. The keys are *defined
    but never referenced* — leftover scaffolding from a planned
    feature.
  - No `Z_FEATURE_AUTH` or `Z_FEATURE_USRPWD` compile gate exists.
    `grep -rn "Z_FEATURE_AUTH\|Z_FEATURE_USRPWD" ~/zenoh-pico`
    returns zero matches.
  - The transport extension ID enumeration at
    `~/zenoh-pico/include/zenoh-pico/protocol/ext.h:46-50`
    declares no Auth extension ID. The Init/Open extension
    iterators (`_z_init_decode_ext` at `transport.c:221-235` and
    its sibling `_z_init_encode_ext` at `transport.c:67-95`)
    handle only `_Z_MSG_EXT_ID_INIT_PATCH`. Unknown extensions
    fall through to the OQ-W4 (b) policy: refuse on mandatory,
    silently ignore on non-mandatory.
  - No file matching `*usrpwd*` or `*auth*` exists in the
    transport tree (`~/zenoh-pico/src/transport/`).

  **MVP implication.** Auth methods baseline = `{none}` for
  MCU parity. **OQ-W2 (auth baseline methods) closes alongside
  OQ-W10**: the original OQ-W2 proposal was `{none, usrpwd}`,
  but only `none` is parity-aligned. Authoring
  `session_unicast.scxml` proceeds with no Auth sub-states —
  flat `Opening.*` per session-fsm §2.2 is the correct shape for
  MVP.

  **Phase D+ landing path (when Auth surfaces).** When the
  watching-zenoh project wants to add Auth (likely Phase D+ when
  AP linux baseline opens, motivated by interop with upstream
  zenohd which *does* implement USRPWD):
  1. Re-open OQ-W10 against upstream `zenoh-transport/src/
     unicast/establishment/ext/auth/usrpwd.rs` (this is the
     authoritative reference for multi-step auth shape).
  2. Author `Opening.AwaitingAuthChallenge` sub-state in
     `session_unicast.scxml` per the upstream alternation.
  3. Add `_Z_MSG_EXT_ID_INIT_AUTH` (or whatever upstream calls
     it) to the watching-zenoh codec extension table; bind to a
     new `algorithm` kind for password hashing.
  4. Re-open OQ-W2 with the new methods enum.
  Authoring is in scope at Phase D+ entry, not before. Defer-
  then-add policy applies (RFC review #14 "pre-release
  forward-namespace 0").

  **OQ-W2 cross-update.** OQ-W2 status: **answered (2026-05-01
  후속 #5) — `{none}` baseline; `{usrpwd}` deferred to Phase D+
  alongside OQ-W10 re-opening.**

- **Last update:** 2026-05-01 후속 #5 (OQ-W10 close — Auth absent
  in zenoh-pico 1.9.0; baseline `{none}` for MCU parity; USRPWD
  multi-step shape deferred to Phase D+ Auth landing). Sibling
  effect: OQ-W2 baseline shrinks to `{none}` from `{none, usrpwd}`.

### OQ-W11 — Multi-link TX dispatch policy

- **Status:** open
- **Owner:** watching-zenoh author (feeds RFC §5.N clarification).
- **Question:** When `ext::MultiLink` is negotiated, by what
  policy does `Established.TxSchedule` choose which link carries
  a given Frame / Fragment? Candidates: round-robin,
  priority-banded (one link per priority class), sticky-per-stream
  (keyed by source_info or zid), deploy-configured mapping.
- **Why it matters:** §5.N currently describes codegen *shape* for
  multi-link but not *policy*. Authoring `Established.TxSchedule`
  in SCXML cannot proceed without a policy target.
- **Action:** propose a `deploy.yaml → session.multilink_policy`
  attribute with enum values; surface to RFC maintainer; settle
  before Phase C10 codegen contract is frozen.
- **Raised by:** `docs/session-fsm.md` §2.3 / §8.1 G-SFM-2 / §8.2.
- **Blocks:** RFC §7 C10 (multi-link concurrent codegen).
- **Last update:** 2026-04-25 (initial).

### OQ-W12 — `Closing` timeout default

- **Status:** answered (committed in `deploy/`); empirical
  validation on Serial pending Phase C+ link driver authoring.
- **Owner:** watching-zenoh author.
- **Question:** `Closing` state lingers briefly so that the `Close`
  frame is flushed before the link FIN. `docs/session-fsm.md` §2.4
  proposes 100 ms default. Is that enough on Serial at 115200 baud
  (~11.5 KB/s), where a Close frame's byte emission + arbitration
  with an in-flight Frame might exceed 100 ms?
- **Why it matters:** default lives in `deploy.yaml` but needs one
  chosen value for each link class; a wrong default silently
  truncates goodbye frames on slow links.
- **Resolution (2026-05-01).** Session-level default
  `closing_timeout_ms: 100` committed in `deploy/mcu_target.yaml`
  and `deploy/ap_standalone.yaml` per session-fsm.md §2.4. Per-link
  override on the MCU `serial_console` link raised to `250` ms to
  bound the worst-case 64-byte Close flush at 115200 baud
  (≈5.6 ms/byte) under arbitration with an in-flight Frame. The
  override pattern (per-link `closing_timeout_ms` on slow links)
  is the canonical answer to the Serial concern; faster links
  (UDP/TCP) inherit the 100 ms session default.
- **Pending follow-up:** empirical validation when Serial driver
  authoring begins (Phase C+). If 250 ms proves insufficient on a
  specific board the per-link override raises further; the
  session default stays at 100 ms.
- **Raised by:** `docs/session-fsm.md` §2.4 / §8.2.
- **Last update:** 2026-05-01 (resolved at deploy/ skeleton
  authoring; empirical confirmation deferred to driver phase).

### OQ-W13 — `worker_slot_budget_us` default and KeyExpr WCET source

- **Status:** answered (committed in `deploy/mcu_target.yaml`);
  KeyExpr WCET measurement harness deferred to Phase A SCXML
  authoring.
- **Owner:** watching-zenoh author.
- **Question:** What is the default `scheduler.worker_slot_budget_us`
  for the MCU deploy skeleton, and how is the WCET for runtime
  KeyExpr matching over `local_sub_table` (capacity declared in
  deploy) sourced — `mode="static"` derived from
  `capacity × max_segments`, or `mode="measured"` from a host-mode
  benchmark on the declared SoC?
- **Why it matters:** RFC §5.A `<sce:wcet-bound>` and §5.K
  `worker_slot_budget_us` are now hard build gates; without
  defaults the MCU deploy skeleton cannot build. KeyExpr matching
  is the canonical "data-driven bound" case the WCET annotation
  was added for.
- **Proposal (initial):**
  - default `worker_slot_budget_us: 200` (5× safety vs 1 ms tick)
  - default `keepalive_jitter_budget_us: 5000`
    (0.5 × the 10 s zenoh default lease, recomputed when
    `session.lease_seconds` is overridden)
  - KeyExpr matching MUST be `mode="measured"`; per-target host-
    mode bench harness lives at `tests/wcet/keyexpr_match_*.c`
    and emits a number consumed by codegen.
- **Resolution (2026-05-01).** Numbers committed in
  `deploy/mcu_target.yaml`: `scheduler.worker_slot_budget_us: 200`
  (5× safety vs the 1 ms tick); `keepalive_jitter_budget_us: 5000`
  (0.5 × the 10 s zenoh default lease, recomputed when
  `session.lease_seconds` is overridden); KeyExpr matching is
  authored as `mode="measured"` with the per-target host benchmark
  living at `tests/wcet/keyexpr_match_*.c` (path defined; harness
  itself authored when the first KeyExpr-matching SCXML lands in
  Phase A — no value to write the harness in advance of the source
  it measures). `deploy/ap_standalone.yaml` declares neither
  `worker_slot_budget_us` nor `keepalive_jitter_budget_us` because
  `scheduler.kind: tokio` is preemptive (the build does not gate on
  these on tokio).
- **Bundling:** resolved together with **OQ-W17** (F4 fuzz coverage
  transport engine choice and per-target default), **OQ-W18**
  (`vle_decode_cycles_per_byte` and `tlv_chain_per_entry_overhead_us`
  defaults per platform class), and **OQ-W19**
  (`pool_defaults.stage_copy_policy` default per deploy class) at
  `deploy/mcu_target.yaml` authoring time — all four surfaced their
  numbers in the same skeleton commit (2026-05-01).
- **Raised by:** review of 2026-04-25 (cooperative scheduler WCET
  concern) — see ARCHITECTURE.md §3.4 / §7.2.
- **Blocks:** unblocked. Phase A entry on cooperative-scheduler
  targets is no longer gated on this default.
- **Last update:** 2026-05-01 (resolved at deploy/ skeleton authoring).

### OQ-W15 — Stateless-accept primitive ownership and defaults

- **Status:** answered (question (a)); (b) carries via post-Phase-A empirical validation
- **Owner:** SCE maintainer (whitelist decision) + watching-zenoh
  author (defaults).
- **Question (a) primitive ownership:** The cookie HMAC primitive
  (`sce_hmac_sha256(key, msg, out)` / `sce_hmac_blake2s(...)`) and
  the RNG primitive (`sce_random_fill(buf, len)`) are required to
  land somewhere before `stateless_accept: cookie_hmac_sha256` can be
  authored (RFC §5.K, [`docs/session-fsm.md`: Accept-side hardening detail](session-fsm.md#27-accept-side-hardening-detail)). Three options:
  1. Add to `sce_intrinsics_runtime` core whitelist (§5.I) — small,
     well-defined surface; needs SCE maintainer ratification.
  2. Provide via target plugin per SoC — flexible (HW crypto
     accelerator on STM32H7, software fallback on M0+) but every
     deploy that uses public-Internet listeners must carry a plugin.
  3. Author HMAC as a regular `algorithm` kind (no extern), use
     RNG-only intrinsic. Loses HW accelerator access; identical
     wire result.
- **Proposal (initial):** option 2 (target plugin) for HMAC — crypto
  accelerator selection is per-SoC; option 1 for RNG (every MCU has
  some entropy source, symbol shape is universal).
- **Question (b) defaults:** What are MCU and AP defaults for
  `session_arming_quota` / `accept_rate_per_sec` /
  `accept_rate_burst` / `cookie_lifetime_ms` / `key_rotation_s`?
  Initial proposal in §5.K examples (8 / 4 / 8 / 30000 / 3600 for
  MCU; 32 / 16 / 32 / 30000 / 3600 for AP) but these need
  empirical validation against (i) a normal AP-reboot reconnect
  storm scenario (must succeed), (ii) a low-rate spoofed-source
  flood scenario (must NOT exhaust the quota), and (iii) MCU
  scheduler `worker_slot_budget_us` headroom for HMAC
  computations under burst (per OQ-W13).
- **Why it matters:** without (a), `stateless_accept` cannot be
  declared at all; without (b), MCU deploy skeletons cannot
  pin numbers and Phase A entry on listener-bearing MCUs is
  blocked.
- **Action:** raise (a) in next SCE sync. **Ratification artifact
  prepared (2026-05-01 후속 #6):** `docs/oq-w15-ratification-
  summary.md` — 1-page sync agenda artifact. Distilled from
  `docs/intrinsics-runtime-symbols.md` §2.5 / [HMAC](intrinsics-runtime-symbols.md#26-hmac--oq-w15-a-initial-proposal-target-plugin) / §3 +
  [`docs/session-fsm.md`: Accept-side hardening detail](session-fsm.md#27-accept-side-hardening-detail) (c). Six-section structure:
  (1) Decision needed, (2) Why now, (3) Initial proposal with
  three reasons each for RNG and HMAC, (4) Counter-options
  (option 2 RNG-as-plugin / option 3 HMAC-as-algorithm /
  option 1 HMAC-as-whitelist), (5) Blast radius
  (forward-compatibility implications of each cell of the 2x2
  RNG×HMAC matrix), (6) Action requested. Settle (b) when
  `deploy/mcu_target.yaml` skeleton is authored — measure HMAC
  cycles per byte on Cortex-M0+/M4/M7 (with and without crypto
  accelerator), pick numbers that keep stateless-accept HMAC inside
  one `worker_slot_budget_us`. (b) is **not** part of the
  ratification artifact's ask — it settles via empirical
  validation post-Phase-A, not via SCE sync.
- **Raised by:** review of 2026-04-25 (session-arming DoS gap) —
  see [`docs/session-fsm.md`: Accept-side hardening detail](session-fsm.md#27-accept-side-hardening-detail) / G-SFM-5 and RFC §5.K
  (`stateless_accept` block) / §5.M (anti-flood gate cross-ref).
- **Blocks:** authoring of any `stateless_accept` deploy; partially
  blocks Phase A on cooperative-scheduler MCU listeners (the
  half-open-cap and accept-rate caps work without it, but
  public-Internet-facing deploys cannot proceed without HMAC).
  Private-LAN MCU listeners (no `untrusted_source: true`) are NOT
  blocked.
- **Resolution (Round 11, 2026-05-14):** SCE maintainer answer
  received. Question (a) closed:
  - **Q1 (RNG → core whitelist):** **No.** SCE `BASELINE_SYMBOLS`
    boundary is "architecture-fixed primitives" (atomics / fences /
    cache / IRQ — closed implementation choice per
    `sce-build/src/forge/intrinsic_registry.rs:258` + drift-guard
    test `:455-457`). RNG has multiple valid implementations (HW
    TRNG / ADC+Yarrow / getrandom / arc4random) with quality +
    seeding policy surface, which is precisely the `target_plugin`
    category (`sce-build/src/forge/target_plugin.rs:9-16`
    Q-Call-6 (a) additive composition). Precedent-risk rationale:
    ratify RNG would invite SHA-256 / AES-GCM / ECDSA under the
    same "public-Internet requires it" framing — baseline drift
    toward crypto authority, which SCE is not.
  - **Q2 (HMAC → target plugin):** **Yes, ratified** — aligns with
    initial proposal. Per-SoC accelerator selection (STM32H7
    `CRYP` / ESP32 `SHA` / Cortex-M0+ software fallback) is
    plugin-meaningful; software fallback also authorable as an
    `algorithm` kind. Crypto-free baseline precedent preserved.
  - **Fallback path (Q1 = No):** validated by SCE C13-β anti-flood
    integration tests (`sce-build/tests/c13_beta_antiflood.rs:173-308`,
    8 tests over baseline ∪ plugin) — RNG declared as a
    `target_plugin` row or `<sce:extern>` declaration is accepted
    by `validate_stateless_accept_externs` (commit `4570a389`,
    `sce-build/src/lib.rs:1894`). public-Internet-facing MCU
    deploys unblock by adding a 4-line plugin yaml row, not by SCE
    spec change.
  - **Counter-offer (long-term boundary hardening):** SCE
    maintainer proposed that, should watching-zenoh define RFC §5.I
    "Architectural-tier" vs "Peripheral-tier" explicit separation,
    future ratify requests can be auto-classified (RNG / SHA /
    AES-GCM as Peripheral-tier by construction). Tracked as
    **OQ-W24** below; spec restructure deferred to a separate
    round.
  - Atomic-store cascade: `intrinsics-runtime--symbol-surface/2-5-rng`
    + `/2-6-hmac` atomic intent ratified to plugin path;
    `oq-w15-a--ratification-summary-for-sce-maintainer-sync/6-action-requested`
    carries Decision Outcome citation.
- **Last update:** Round 11, 2026-05-14 (SCE maintainer answer
  reflected — (a) closed Q1=No / Q2=Yes; (b) remains open per
  empirical-validation post-Phase-A path).

### OQ-W14 — Hardware sync primitive standardization in target_plugin

- **Status:** open
- **Owner:** watching-zenoh author (proposes), SCE maintainer (ratifies
  the symbol-name standard).
- **Question:** Should the `sce_hw_sem_take` / `sce_hw_sem_release` /
  `sce_hw_mbox_send` symbol names introduced in RFC §5.I be promoted
  to **standard** target-plugin symbols (every plugin for a multi-core
  MCU implements them), or remain ad-hoc per plugin (each plugin picks
  its own names; deploy.yaml picks which one to wire)?
- **Why it matters:** standardized names let SCE codegen emit the
  same call sites regardless of SoC; ad-hoc names give plugin authors
  freedom but require a per-plugin name-binding section in deploy.yaml
  (`cross_core_sync.symbol_map: { take: vendor_hsem_take, ... }`).
- **Proposal (initial):** standardize the three symbol shapes shown in
  §5.I as the *interface* every multi-core MCU plugin implements; the
  plugin maps them to the SoC-specific hardware operation internally.
  This keeps codegen target-neutral while letting vendors keep their
  driver names. Ad-hoc additional symbols (e.g. for special mailbox
  modes) are allowed alongside.
- **Action:** propose in next SCE sync; capture the answer here. Affects
  the worked example in `deploy/mcu_target.yaml` skeleton.
- **Raised by:** review of 2026-04-25 (multi-core MCU HW semaphore
  consideration) — see ARCHITECTURE.md §3.4 and RFC §5.I.
- **Blocks:** Phase C cross-core multi-core MCU bring-up; not Phase A.
- **Last update:** 2026-04-25 (initial).

### OQ-W16 — Generated-source traceability: state-path delimiter and Rust SCE-MAP preservation

- **Status:** open
- **Owner:** SCE maintainer (delimiter contract); SCE maintainer
  + watching-zenoh author (Rust mapping mechanism, requires
  empirical preservation testing).
- **Question (a) state-path delimiter.** RFC §5.O symbol naming
  is `<machine>__<state_path>__<artifact>`, but `<state_path>`
  itself contains hierarchy that needs its own delimiter inside
  the canonical name. Three options:
  1. **Single underscore `_`** — collides with SCXML state names
     containing underscores (zenoh upstream already uses
     snake_case for events like `init_ack`, `open_syn`; some peer
     implementations may use the same for state names). Round-trip
     from symbol → state path becomes ambiguous.
  2. **Double underscore `__`** — C/C++ standards reserve `__` for
     implementation use (C99 sec. 7.1.3, C++11 sec. 17.6.4.3.2). Pragmatically
     every codegen in the wild uses `__` despite the reservation;
     no real-world toolchain rejects it. Disambiguation is clean
     because authoring SCXML state names cannot contain `__`
     (rejected by `traceability/state-id-collision` if attempted).
  3. **Literal escape `__s_`** — verbose but unambiguous. Symbols
     become `session_unicast__s_Established__s_Keepalive__s_entry`
     which is awkward to read in coredumps.
- **Initial proposal:** option 2 (`__`) with the rule that
  underscores inside an SCXML state name are escaped to `_u_`.
  Aligns with prevailing codegen practice; keeps symbols readable;
  pushes ambiguity into a precise escape rather than a per-name
  workaround.
- **Question (b) Rust SCE-MAP preservation.** Rust does not have
  C's `#line` directive. The mapping back to SCXML must travel
  alongside emitted code in a form that survives `cargo build
  --release`. Three options:
  1. **`#[doc = "SCE-MAP: ..."]` attribute** — preserved through
     compilation, retrievable via `cargo doc --output-format json`.
     Zero build-time dependency; `addr2sce` parses the rustdoc
     JSON. Risk: `-Zstrip=symbols` or future toolchain optimizations
     could elide doc-attribute payloads.
  2. **Custom `#[sce_map(scxml = "...", line = ...)]` proc-macro
     attribute** — typesafe and parseable without rustdoc, but
     adds a `proc-macro` build dependency to every generated crate
     and complicates `no_std` story (proc-macro crates currently
     require `proc_macro` which is host-side only — actually fine,
     but adds workspace complexity).
  3. **Comment-only `// SCE-MAP: ...`** — simplest; risk is that
     `rustfmt` or future toolchains strip comments from emitted
     binaries (already true — comments do not survive compilation;
     they survive only if a pre-build step extracts them).
- **Initial proposal:** option 1 (`#[doc]`). Survives release
  builds; standard tooling support; no build-graph impact. Until
  empirically validated, codegen MUST emit BOTH the `#[doc]`
  attribute and a fallback `// SCE-MAP:` comment so neither
  preservation path is foreclosed.
- **Why it matters.** RFC §5.O codegen contract is mandatory; the
  `#line` half (C side) is unambiguous, but the Rust mechanism
  and the delimiter are still degrees of freedom that downstream
  tooling (`addr2sce`) must commit to. Without resolution, Phase
  A5 (C11 backend skeleton) and the parallel Rust backend reuse
  for §5.O cannot ship a stable interface.
- **Action.** Raise (a) in next SCE sync alongside Q1 (algorithm
  kind name) — both are naming-convention questions and benefit
  from a single-sync resolution. Raise (b) once first generated
  Rust output exists for empirical preservation testing — schedule
  this for Phase A5 acceptance gate (CRC16 byte-equivalent test;
  add an `addr2sce session_unicast__... → SCXML` resolution check
  to the same gate).
- **Raised by:** review #10 of 2026-04-25 (generated-source
  traceability gap) — see RFC §5.O and ARCHITECTURE §11.5.
- **Blocks:** Phase A5 (C11 backend skeleton) acceptance gate.
- **Last update:** 2026-04-25 (initial).

### OQ-W17 — F4 fuzz coverage transport: engine choice and per-target default

- **Status:** partially answered. (b) — per-target default
  documented (renode_sysbus, deferred to target_plugin file at
  Phase D entry). (a) — engine choice (Centipede F2/F3/F4 +
  libFuzzer F1) is initial-proposal, awaiting SCE sync ratification.
- **Owner:** watching-zenoh author (proposes the engine choice and
  the per-target default), SCE maintainer (ratifies the
  `fuzz_coverage_transport` schema landing in §5.I).
- **Question (a) engine choice.** ARCHITECTURE §11.6 commits to
  Centipede (out-of-process engine + remote executor) for F4. The
  same architectural argument extends to F1/F2/F3 if all four tiers
  share a single mutator/corpus/minimization pipeline, but doing so
  means dropping the `cargo fuzz` (libFuzzer) entry path on the
  AP-side Rust fuzz harness and migrating to Centipede there as
  well. Two options:
  1. **Migrate F1–F4 to Centipede uniformly.** Single pipeline,
     single corpus DB, single minimization tool. Cost: drops the
     well-trodden `cargo fuzz` workflow; requires writing a
     Centipede runner shim for Rust (Centipede's first-class
     runners are C++).
  2. **Centipede for F2/F3/F4 only; F1 stays on libFuzzer/`cargo
     fuzz`.** Cheaper to land; preserves the standard Rust workflow.
     Cost: F1 coverage maps and Centipede coverage maps diverge in
     representation, so corpus interchange between F1 and F4 needs
     an adapter. Byte-sequence corpus interchange still works (the
     §11.6 architectural invariant); only edge-map analytics get
     split.
- **Question (b) per-target default transport.** §5.I lists five
  transports (`renode_sysbus`, `segger_rtt`, `openocd_memmap`,
  `dma_uart`, `semihosting`). Which is the default `mcu_target.yaml`
  ships with, and is it gated by the deploy's reference board?
  Three options:
  1. **No default; every deploy declares.** Forces explicit choice;
     surfaces `fuzz/coverage-transport-not-declared-on-f4-target` at
     first F4 build attempt. Most defensible.
  2. **`renode_sysbus` as default for all MCU deploys.** Renode is
     vendor-neutral and parallelizable; HIL transports added per
     board. Treats Renode as the F4 "easy on-ramp" and makes HIL an
     opt-in upgrade.
  3. **Per-MCU-class default.** STM32 family → `segger_rtt`, ESP32 →
     `openocd_memmap`, etc. Maximally helpful but couples the SCE
     defaults to specific vendor probe ecosystems.
- **Initial proposal.** Option (a)2 — Centipede for F2/F3/F4,
  libFuzzer for F1 — because the AP `cargo fuzz` workflow is too
  valuable to drop early, and the AP path is anyway constrained to
  F1 (RFC §11.6 paragraph). Adapter cost is one-time and bounded.
  Option (b)2 — `renode_sysbus` default — because Renode is the
  only vendor-neutral full-MMU/cache simulator available pre-HIL,
  and Phase D F4 first lands as Renode (per ARCHITECTURE §11.6
  roadmap).
- **Why it matters.** Without (a) ratified, the per-tier harness
  generation pattern in planned RFC section 6.2.5 cannot freeze its codegen contract;
  without (b), every Phase-D deploy carries a hand-picked transport
  with no narrative guidance.
- **Bundling.** Resolved together with **OQ-W13**
  (`worker_slot_budget_us` defaults and KeyExpr WCET source) when
  the `deploy/mcu_target.yaml` skeleton is authored — both are
  quantitative-defaults questions whose empirical numbers depend
  on the chosen reference board and on whether the deploy carries
  a fuzz harness build. Bundling avoids a second round-trip to the
  same skeleton file.
- **Resolution (2026-05-01) — (b) per-target default.**
  `mcu_target.yaml` `extern_symbols.target_plugin` points at
  `configs/target_extensions_stm32h747.yaml`; the Phase A–C deploy
  skeleton does NOT declare `fuzz_coverage_transport` directly
  because the transport block lives inside the target_plugin file
  (per RFC §5.I) and Phase A–C deploys would trigger
  `fuzz/coverage-transport-on-pre-D-tier` if it were declared.
  When Phase D entry happens, the target_plugin file gains a
  `fuzz_coverage_transport: { kind: renode_sysbus, ... }` block
  per the proposal — Renode is the vendor-neutral first-mover
  per ARCHITECTURE §11.6. Authors override per-board (e.g.
  `kind: segger_rtt` for STM32H7 with J-Link probe).
- **Pending follow-up — (a) engine choice.** Initial proposal
  unchanged: Centipede for F2/F3/F4, libFuzzer for F1. Final
  ratification requires SCE-side planned RFC section 6.2.5 codegen-contract freeze
  raised at the next SCE sync.
- **Raised by:** review #11 of 2026-04-25 (F4 coverage feedback
  mechanism gap) — see ARCHITECTURE §11.6 "F4 coverage feedback
  architecture" subsection and RFC §5.I `fuzz_coverage_transport`.
- **Blocks:** Phase A–C unblocked (transport not authored at this
  phase). Phase D entry still pending the target_plugin file
  authoring; (a) ratification still pending the planned RFC section 6.2.5 codegen
  contract freeze.
- **Last update:** 2026-05-01 ((b) resolved at deploy/ skeleton
  authoring; (a) still awaiting SCE sync).

### OQ-W18 — `vle_decode_cycles_per_byte` and `tlv_chain_per_entry_overhead_us` defaults per platform class

- **Status:** initial-proposal committed (M7 numbers in
  `mcu_target.yaml`); empirical measurement on M0+/M3-M4/M7
  reference boards still pending — measurement is the only
  external dependency in the OQ-W6/8/12/13/17/18/19 bundle.
- **Owner:** watching-zenoh author (proposes per-class defaults),
  SCE maintainer (ratifies whether the §5.K platform field shape
  belongs in core schema or stays watching-zenoh-specific).
- **Question (a) per-class default values.** RFC §5.B codec
  aggregate WCET requires `platform.vle_decode_cycles_per_byte` and
  `platform.tlv_chain_per_entry_overhead_us` whenever a codec on the
  deploy contains a `vle_*` field or a `tlv-chain` AND the
  scheduler is cooperative. Initial proposal in §5.K examples:
  - `vle_decode_cycles_per_byte`: M0/M0+ = 12.0, M3/M4 = 8.0,
    M7 = 6.0, A-class = 3.0
  - `tlv_chain_per_entry_overhead_us`: M0/M0+ = 1.5, M3/M4 = 0.8,
    M7 = 0.5, A-class = 0.2
  These are first-pass estimates derived from the CMSIS reference
  implementation of VLE decode (continuation-bit branch + shift +
  accumulate per byte) and the typical TLV chain entry overhead
  (id-byte read + length VLE + dispatch table indirection). They
  must be **empirically validated** against real measurements on a
  reference board per class before becoming `mcu_target.yaml`
  defaults.
- **Question (b) measurement workflow.** §5.A `<sce:wcet-bound
  mode="measured">` already has a defined measurement workflow
  (`sce-bench --target ...`). The §5.B aggregate uses these
  per-byte / per-entry coefficients as *primitive* inputs, not as
  per-codec measurements — so the workflow is different: one
  `sce-bench --measure-vle-coefficients --target <board>` invocation
  per platform class produces both numbers, and they get pinned in
  the platform descriptor that ships with `mcu_target.yaml`. Should
  this benchmark live in `tests/wcet/vle_coefficients_*.c` (per
  platform) or in a single parametric harness that runs across all
  declared platforms in a deploy? Initial proposal: parametric, one
  harness, dispatched per platform — keeps the codec aggregate
  formula's two coefficients colocated.
- **Why it matters.** Without (a) ratified, every cooperative-
  scheduler MCU deploy that contains a `vle_*` field or `tlv-chain`
  fails the build with `codec/wcet-aggregate-vle-cycles-missing` or
  `codec/wcet-aggregate-tlv-overhead-missing`. Since the Zenoh wire
  format uses VLE everywhere (`zint`, `bytes` length prefix, etc.),
  this blocks Phase A entry on cooperative-scheduler MCU targets
  the moment the codec aggregate gate lands. Without (b), authors
  guess.
- **Resolution (2026-05-01) — initial-proposal numbers committed.**
  `deploy/mcu_target.yaml` ships the M7 estimate pair
  (`vle_decode_cycles_per_byte: 6.0`, `tlv_chain_per_entry_overhead_us:
  0.5`) per RFC §5.K's CMSIS-derived defaults. Codec aggregate WCET
  builds against these numbers today; until they are replaced with
  measured values the build emits
  `algorithm/wcet-measurement-class-untrusted-without-margin` for
  any consuming codec, surfacing the unverified status to authors.
  `deploy/ap_standalone.yaml` carries A-class estimates
  (`3.0` / `0.2`) for parity but they are advisory on `tokio`
  (preemptive scheduler does not gate on them).
- **Pending follow-up — empirical measurement.** Run
  `sce-bench --measure-vle-coefficients` on STM32H7 (M7), STM32F4
  (M4), and RP2040/STM32G0 (M0+) reference boards. Commit numbers
  with `target=<soc>_<core>_<freq>` and `source-hash=` of the
  benchmark source per §5.A workflow. The parametric harness at
  `tests/wcet/vle_coefficients.c` lands in the same commit. This is
  the **only external dependency** in the OQ-W6/8/12/13/17/18/19
  resolution bundle — everything else is closed by the
  `deploy/` skeletons.
- **Bundling:** resolved together with **OQ-W13** (`worker_slot_budget_us`
  defaults), **OQ-W17** (F4 fuzz coverage transport), and **OQ-W19**
  (`stage_copy_policy` default) at `deploy/mcu_target.yaml`
  authoring time (2026-05-01). The four together pin the
  cooperative-scheduler MCU baseline numbers; W18's measured
  values can replace the estimate values without touching W13/W17/W19.
- **Raised by:** review #12 of 2026-04-25 (codec aggregate WCET
  gap) — see RFC §5.B "Codec aggregate WCET" subsection and RFC
  §5.K platform `vle_decode_cycles_per_byte` /
  `tlv_chain_per_entry_overhead_us` fields.
- **Blocks:** Phase A entry on cooperative-scheduler MCU targets
  is *unblocked at estimate-quality* — build proceeds with the
  diagnostic warning. Production-ready Phase A still requires the
  measured pair; this is a pre-prod gate, not a build-stop.
- **Last update:** 2026-05-01 (estimates committed; measurement pending).

### OQ-W19 — `pool_defaults.stage_copy_policy` default per deploy class

- **Status:** answered (committed in `deploy/`).
- **Owner:** watching-zenoh author.
- **Question.** RFC §5.K `pool_defaults.stage_copy_policy` is `warn`
  by default in the schema, but the authored skeletons
  (`ap_standalone.yaml`, `mcu_target.yaml`, `ap_mcu_pair.yaml`)
  must each pick a setting that matches the deploy's class. Three
  decisions:
  1. **`ap_standalone.yaml`**: AP target with no MCU peer. Stage-copy
     is ergonomic and rare. Proposal: `warn` (current default;
     ergonomic prototype path).
  2. **`mcu_target.yaml`**: MCU-only target. Cooperative scheduler;
     every cycle accounted; stage-copy is the canonical
     unanticipated-cost path. Proposal: `error` — surface stage-copy
     as a build-stop, force per-link `<sce:accept-stage-copy-rate>`
     for any tolerated case. Stronger setting (`forbid`) is left to
     downstream safety-critical deploys to opt in; the skeleton
     ships at `error`, which is the right "embedded production
     default."
  3. **`ap_mcu_pair.yaml`**: hybrid. `pool_defaults.stage_copy_policy`
     is per-machine, so AP stays at `warn` and the MCU machine sets
     `error`. The skeleton documents this asymmetry as the canonical
     pattern.
- **Why it matters.** Without an opinion in the skeletons, the
  policy field reads as bureaucratic noise; with an opinion, every
  embedded watching-zenoh deploy starts at `error` and any author
  who wants `warn` makes a deliberate downgrade with a justification
  comment. This is the policy default that drives downstream
  hygiene.
- **Bundling:** resolved together with **OQ-W13** (worker slot
  budget), **OQ-W17** (F4 fuzz transport), and **OQ-W18** (VLE /
  TLV per-platform coefficients) at `deploy/mcu_target.yaml`
  authoring time.
- **Resolution (2026-05-01).** All three settings adopted as
  proposed: `deploy/ap_standalone.yaml` = `warn`,
  `deploy/mcu_target.yaml` = `error`, `deploy/ap_mcu_pair.yaml` =
  asymmetric (AP `warn` + MCU `error`). The asymmetric pattern is
  documented in `ap_mcu_pair.yaml`'s `pool_defaults` blocks as the
  canonical hybrid-deploy posture. If the MCU `error` default proves
  too aggressive in practice (hits triggered for pcap-replay test
  deploys), authors downgrade per-link with `<sce:accept-stage-copy-
  rate>` rather than flipping the machine-level policy.
- **Bundling:** resolved together with **OQ-W13** (worker slot
  budget), **OQ-W17** (F4 fuzz transport), and **OQ-W18** (VLE /
  TLV per-platform coefficients) at `deploy/mcu_target.yaml`
  authoring time (2026-05-01).
- **Raised by:** review #12 of 2026-04-25 (stage-copy strict policy
  request) — see ARCHITECTURE §9.3 "Stage-copy policy (deploy-wide)"
  paragraph and RFC §5.K `pool_defaults.stage_copy_policy`.
- **Blocks:** unblocked.
- **Last update:** 2026-05-01 (resolved at deploy/ skeleton authoring).

### OQ-W20 — `sce_link_runtime_qnx` reactor: mio QNX backend vs custom QNX-native runtime

- **Status:** open (Phase D.2 blocker; not blocking Phase A–C).
- **Owner:** watching-zenoh author.
- **Question.** When Phase D.2 (AP QNX baseline, RFC §7) begins, the
  Rust async ecosystem has no first-class QNX support: `mio` (the
  reactor library tokio uses) ships epoll (Linux), kqueue
  (BSD/macOS), and IOCP (Windows) backends — **no QNX**. Three
  options for `sce_link_runtime_qnx`:
  1. **`mio` QNX backend community port.** Land a QNX backend in
     `mio` (or fork) and reuse the entire tokio ecosystem on QNX.
     Cost: upstream coordination + ongoing maintenance of a niche
     OS port. Benefit: maximum ecosystem reuse (any tokio crate
     would work on QNX).
  2. **Custom QNX-native runtime crate.** Build `sce_link_runtime_qnx`
     directly on QNX `dispatch_create()` + `MsgReceivePulse` +
     `select`-on-fd primitives. Present the same `Link` trait as
     `sce_link_runtime_tokio` so generated code is OS-agnostic.
     Cost: re-implement scheduling and channel/pulse multiplexing.
     Benefit: idiomatic QNX (priorities, adaptive partitioning,
     hard realtime story); zero upstream coordination.
  3. **Hybrid.** Use mio if the QNX port is available at Phase D.2
     entry; fall back to custom otherwise. Defers the choice but
     leaves `sce_link_runtime_qnx`'s internals indeterminate.
- **Initial proposal.** Option 2 (custom QNX-native runtime).
  Rationale: QNX's value proposition is hard realtime + adaptive
  partitioning; mio's epoll-shaped abstractions don't expose those
  primitives even when ported. The `Link` trait surface is small
  enough that re-implementation is bounded (estimated ~1.5K LOC),
  and the project's MCU-side `sce_link_runtime_lwip` already
  demonstrates the same per-OS trait-shaped pattern. The custom
  runtime can also wire QNX `scheduler.kind: rt` (OQ-W21 scope)
  more cleanly than a tokio-shaped layer would.
- **Why it matters.** Phase D.2 cannot ship `sce_link_runtime_qnx`
  without committing to one of these. The schema namespace is
  reserved (review #13 §5.K `os: qnx`, §5.J backend 3-tuple), but
  the reactor implementation choice gates Phase D.2 entry.
- **Bundling.** Independent of the OQ-W13/W17/W18/W19 deploy-defaults
  bundle (those resolve at MCU `deploy/mcu_target.yaml` authoring
  time, Phase A–C). This question resolves at Phase D.2 entry,
  potentially years later. The link is design-only: choosing
  custom-runtime now (option 2) ensures the runtime-crate API
  trait stays small enough to re-implement, which constrains the
  Phase B `sce_link_runtime_tokio` and Phase B MCU
  `sce_link_runtime_lwip` API surface to remain QNX-friendly.
- **Action.** Defer ratification to Phase D.2 entry. Until then:
  - Document option 2 as the working assumption in
    ARCHITECTURE §9.5 "Platform-aware link substrate" (already
    present from review #13).
  - Keep the `Link` trait surface in `sce_link_runtime_*` minimal
    (one rx primitive, one tx primitive, no implicit
    epoll/kqueue/IOCP shape leaking through) so option 2 remains
    cheap to land.
  - Re-evaluate at Phase D.1 completion (AP Linux baseline) when
    the trait surface has stabilized empirically.
- **Raised by:** review #13 of 2026-04-25 (QNX as design-considered
  AP target, not deferred non-goal) — see RFC §5.J 3-tuple
  backend convention and ARCHITECTURE §9.5.
- **Blocks:** Phase D.2 entry (AP QNX baseline). Does NOT block
  Phase A / B / C / D.1.
- **Last update:** 2026-04-25 (initial).

### OQ-W21 — Out-of-order Continue policy under BEST_EFFORT

- **Status:** answered (2026-05-01 후속) — option 2 (strict in-order
  for both reliability classes), per zenoh-pico 1.9.0 HEAD `3b3ab65`.
- **Owner:** watching-zenoh author (verify against zenoh-pico source).
- **Question.** RFC §5.M's three-state sketch
  (`Idle/Assembling/Complete`) does not specify whether
  `Fragment.Continue` arriving with `idx > next_expected` (i.e.
  out-of-order within a chain on a UDP best-effort transport) is:
  1. **Tolerated** — the reassembly slot uses a fragment-index
     bitmap (rather than a streaming cursor) and accepts arrivals
     in any order; completion check is `bitmap fills exactly
     [0, max_seen_idx]` on the Final fragment. Cost: per-slot
     bitmap of size `max_fragments_per_message` bits + slightly
     more complex stage-copy offset computation.
  2. **Rejected** — slot transitions to `Aborted` with reason
     `out-of-order` regardless of reliability class. Cost: peer
     misbehavior sometimes shows up as benign UDP reordering on
     lossy links.
  3. **Reliability-conditional** (proposed in
     `docs/reassembly-fsm.md` §2.5): tolerate under
     `reliability=BEST_EFFORT`, reject under
     `reliability=RELIABLE` (since reliable transport guarantees
     in-order delivery; reordering signals transport-contract
     violation).
- **Initial proposal:** option 3 — reliability-conditional.
  Matches the wire-level reality that BEST_EFFORT chains over UDP
  may reorder while RELIABLE chains over TCP do not. Bitmap cost
  is bounded (≤ `max_fragments_per_message` bits, e.g. 2 bits on
  MCU, 44 bits on AP) and acceptable.
- **Why it matters:** the four-state slot FSM
  (`Empty / Receiving / Complete / Aborted`) cannot be authored
  until this is settled — the body of `Receiving` is materially
  different between option 1 (bitmap) and option 2 (strict cursor),
  and option 3 needs both branches.
- **Action.** Verify against upstream zenoh-pico's reassembly
  implementation (likely `_z_transport_unicast_handle_fragment` or
  similar) before Phase A SCXML authoring.
- **Resolution (2026-05-01 후속, verified against zenoh-pico
  1.9.0 HEAD `3b3ab65cadbb10a8d7f32ba04cb15c26b8435dd5`).**
  **Option 2 — strict in-order for BOTH reliability classes.**
  Upstream applies the identical drop-on-OOO policy across
  RELIABLE and BEST_EFFORT bands. Evidence:
  - `_z_unicast_handle_fragment_inner` at
    `~/zenoh-pico/src/transport/unicast/rx.c:145-273` — symmetric
    if/else on `_Z_FLAG_T_FRAGMENT_R` selecting `_dbuf_reliable`
    vs `_dbuf_best_effort`; the action on out-of-order is
    identical in both branches.
  - SN regression (`!_z_sn_precedes(latest, msg_sn)`) →
    `_z_wbuf_clear` + diagnostic "...message dropped because it
    is out of order" at `unicast/rx.c:166-168, 180-182`.
  - SN forward-gap (`_z_sn_precedes` true but
    `!_z_sn_consecutive`) → `_z_wbuf_clear` + diagnostic
    "Defragmentation buffer dropped because non-consecutive
    fragments received" at `unicast/rx.c:187-191`.
  - Multicast handler structurally identical at
    `~/zenoh-pico/src/transport/multicast/rx.c:233-369` (lines
    251-287 mirror unicast 155-191).
  - `_z_sn_consecutive` requires `(sn_right - sn_left) == 1`
    modulo resolution at
    `~/zenoh-pico/src/transport/utils.c:85-88`; nothing else
    qualifies as in-order.
  - State shape: `_z_transport_peer_common_t` carries exactly two
    inline `_z_wbuf_t` buffers (one per reliability) plus two
    state bytes — no bitmap, no per-chain timer field — at
    `~/zenoh-pico/include/zenoh-pico/transport/transport.h:50-68`.
  - Cleanup paths: (i) consecutive/precedes failure on next
    arrival, (ii) overflow vs `Z_FRAG_MAX_SIZE` (default 4096 per
    `~/zenoh-pico/CMakeLists.txt:306`), (iii) Final completion
    (`unicast/rx.c:225-258`), (iv) peer disconnect via
    `_z_transport_peer_common_clear` at
    `~/zenoh-pico/src/transport/peer.c:58-59`.
  - Wire-level chain key shape:
    `_z_t_msg_fragment_t = {_payload, _sn, first, drop}` at
    `~/zenoh-pico/include/zenoh-pico/protocol/definitions/transport.h:494-499`
    — no priority, no sn_base. Effective chain key is
    `(peer, reliability)` 2-tuple, NOT the 4-tuple
    `(peer_zid, priority, reliability, sn_base)` initially
    proposed.
  - Patch markers (`_Z_CURRENT_PATCH = 0x01`): `FRAGMENT_FIRST`
    (ext id 0x02) and `FRAGMENT_DROP` (ext id 0x03) at
    `~/zenoh-pico/include/zenoh-pico/protocol/ext.h:49-50`,
    gated by `_Z_PATCH_HAS_FRAGMENT_MARKERS(patch)` at
    `~/zenoh-pico/include/zenoh-pico/protocol/definitions/transport.h:102`.
    Legacy peers (patch 0) have implicit chain framing only.
  Initial proposal (option 3, reliability-conditional) is
  rejected — divergence from upstream would violate the MVP
  zenoh-pico parity invariant (ARCHITECTURE.md §2). The
  bitmap-based BEST_EFFORT tolerance design remains a viable
  Phase D++ enhancement once parity is achieved, but is out of
  scope for MVP.
- **Cascading FSM-shape items (do NOT reopen OQ-W21; tracked in
  `docs/reassembly-fsm.md` §2.5 as deferred revision pass):**
  chain key 4-tuple → 2-tuple, slot count N parallel → 2 per
  peer, removal of per-chain `reassembly_timeout_ms`, rename
  `start` flag → `FRAGMENT_FIRST` extension. These block Phase A
  SCXML authoring of `sources/reassembly/reassembly_slot.scxml`
  but not OQ closure.
- **Raised by:** `docs/reassembly-fsm.md` §8.1 G-RFM-1 (2026-05-01).
- **Blocks:** Phase A SCXML authoring of `sources/reassembly/
  reassembly_slot.scxml`.
- **Last update:** 2026-05-01 후속 (resolved — option 2).

### OQ-W22 — Listener-link trust class lifecycle

- **Status:** answered (2026-05-01 후속 #6)
- **Owner:** watching-zenoh author (settled — RFC §5.M / §5.C
  patch landed in this session).
- **Question.** RFC §5.M's trust-class table is keyed on the *link
  instance*'s `trust_class` value (a deploy.yaml field). But a
  listener link declares `trust_class: session_arming` (the value
  that gates `Accepting.*` hardening), and **that same link
  instance** carries `established_session` traffic *post-handshake*
  for any peer that completed the handshake. The build-time gate
  `reassembly/untrusted-link-binding` is link-instance-scoped and
  cannot tell whether the runtime peer is in `Accepting.*` or
  `Established`. Three options were considered:
  1. **Trust class becomes runtime per-peer.** The build-time gate
     becomes informational; reassembly enforcement happens at the
     Router (per `docs/reassembly-fsm.md` §2.3) by checking the
     peer's session state. Cost: gate is honor-system at compile,
     enforced at runtime; needs a runtime check at every
     `Fragment.First` arrival.
  2. **Reassembly pools bind only to dedicated data-plane links.**
     Listener link does not carry post-handshake fragments; a
     separate link binding (e.g. a different UDP port) carries
     established traffic. Cost: doubles the link-instance count,
     diverges from zenoh-pico's actual deployment shape (one UDP
     socket carries handshake AND data).
  3. **Codegen splits listener link into two link-instances at
     handshake completion.** The session FSM, on transition to
     `Established`, hands the peer's traffic to a sibling
     `link_instance_established` whose `trust_class` is
     `established_session`. The original listener stays
     `session_arming`. Cost: extra link-instance shape in §5.C
     codegen contract; the *physical* socket is shared but the
     *logical* SCXML link instances are two.
- **Resolution (2026-05-01 후속 #6).** **Option 3 ratified.** The
  build-time gate stays fully static (link-instance-scoped, not
  socket-scoped); no runtime trust-class check is required at
  `Fragment.First` arrival; deploy.yaml schema is unchanged
  (the split is automatic at codegen time, not author-declared);
  zenoh-pico's one-physical-socket deployment shape is preserved.
  The bounded cost (extra link-instance shape) is paid by codegen,
  not by author SCXML.

  Patch summary (this session):
  - **RFC §5.M** — new "Listener-link trust-class lifecycle"
    subsection between "Trust class requirement (UDP spoofing
    hardening)" and "Per-peer quota (DoS hardening)". Specifies
    the trust-class semantic: listener emits two logical
    link-instances (`session_arming` + `established_session`
    sibling) sharing one physical socket. New diagnostic
    `reassembly/binding-on-unpaired-listener` (hard error,
    defense against orphan binding resolution).
  - **RFC §5.C** — new "Listener-link sibling emission"
    subsection between "Codegen contract" and "Diagnostics:".
    Specifies the codegen mechanics: sibling synthesized with
    inherited `bind` / `driver` / `mtu_bytes` /
    `expected_p99_bytes` / `burst_pps` / `rx_dispatch`; accept-
    side hardening fields NOT inherited; reassembly-pool
    bindings resolve to sibling at codegen time. New diagnostic
    `link/listener-link-not-paired-with-established-sibling`
    (hard error, codegen self-check / template regression
    guard).
  - **`docs/reassembly-fsm.md`** — §5 trust-class composition
    rewritten with the two-instance model and the
    `link-instance-scoped` clarification; §8.1 G-RFM-2 →
    resolved; §8.2 OQ-W22 → answered; §10 authoring-blocker
    section flipped to "unblocked"; change log "2026-05-01
    후속 #6" entry.
  - **[`docs/session-fsm.md`: Trust-class interaction](session-fsm.md#26-trust-class-interaction-cross-ref-to-5m)** — "Listener-link logical
    split" subparagraph appended to the trust-class table,
    cross-ref to RFC §5.M / §5.C.
  - **`docs/runtime-crate-lwip.md` §4** — "Listener-link
    two-instance emission" paragraph added; clarifies that
    `sce_link_t` storage emits twice for a listener (separate
    handles, shared socket, peer-state-driven RX dispatch in
    the runtime crate).
  - **`docs/runtime-crate-tokio.md` §2.4** — "Listener-link
    two-instance emission" paragraph added; clarifies two
    `LinkDriver` impls per listener with separate handles.
- **Why it matters:** without this, the deploy skeleton's MCU
  `udp_session` link (declared `trust_class: session_arming`) was
  technically forbidden from binding to a reassembly pool —
  but **must** carry post-handshake fragments to be useful. The
  contradiction surfaced when reassembly-fsm.md §5 was written;
  this resolution unblocks Phase A SCXML authoring of all
  listener links (including the canonical `udp_session`).
- **Raised by:** `docs/reassembly-fsm.md` §8.1 G-RFM-2 (2026-05-01).
- **Blocks:** none remaining. (Phase A SCXML authoring of any
  listener link is now unblocked on this question.)
- **Last update:** 2026-05-01 후속 #6 (option 3 ratified, RFC
  §5.M / §5.C patch landed, 5 cross-doc amends).

### OQ-W23 — Passive scouting mode justification + deploy schema

- **Status:** answered (2026-05-01 후속 #5) — **deferred to Phase D+**.
- **Owner:** watching-zenoh author.
- **Question (a) — Should `scouting.mode: passive` ship in MVP?**
  zenoh-pico has no daemon that periodically re-scouts; its
  scouting (`~/zenoh-pico/src/session/scout.c:142-165`
  `_z_scout_inner`) is one-shot, triggered by either the public
  `z_scout()` API (`~/zenoh-pico/src/api/api.c:773-829`) or by
  `_z_open()`'s no-locator fallback
  (`~/zenoh-pico/src/net/session.c:69`). watching-zenoh's
  `passive` mode would re-trigger active scouting on a deploy-
  configured period (proposal `30 s ± 25 % jitter`), addressing
  rolling-deploy and late-arriving-peer scenarios that today
  applications must solve themselves. Trade-off: ergonomic
  improvement on operator side vs scope expansion beyond
  zenoh-pico parity (the MVP criterion per ARCHITECTURE §2.0).
- **Question (b) — If yes, deploy.yaml field defaults?**
  Three new fields would be conditionally required when
  `mode: passive`:
  - `scout_retry_interval_ms` (proposal `30000`)
  - `scout_retry_jitter_pct` (proposal `25`)
  - `hello_entry_lease_ms` (proposal `5 × scout_retry_interval_ms`)
  Validation would require (i) a representative rolling-deploy
  scenario (AP restarts, MCU rediscovers within window) and (ii)
  a 24-hour observation of spurious-Scout cost on a steady mesh.
- **Resolution (2026-05-01 후속 #5).** **Defer to Phase D+.** Three
  reasons:
  1. **MVP = zenoh-pico parity** (ARCHITECTURE §2.0). zenoh-pico
     has no passive daemon (`scout.c:142-165` is single-shot
     active). Adding one to MVP weakens parity. The reassembly-side
     reliability-conditional-bitmap proposal (OQ-W21 initial
     proposal) was rejected on the same parity discipline; OQ-W23
     applies the identical jurisdiction.
  2. **YAGNI / scope discipline** (RULES.md). zenoh-pico
     applications handle rolling-deploy / late-peer scenarios by
     calling `z_scout()` again on an application-layer timer.
     Documenting that pattern as the recommended workaround is
     honest and zero-cost. Adding `passive` is a feature beyond
     parity-MVP that has no Phase A–C critical-path consumer.
  3. **Reversibility asymmetry.** Adding `passive` later is
     additive (enum row + 3 deploy fields + 1 SCXML region — no
     breaking schema change). Removing a shipped passive mode
     would be a breaking schema change. Per RFC review #14
     "pre-release forward-namespace 0" policy, watching-zenoh
     lands features when wired, not pre-reserved.
  Couple side-effects: passive's RNG dependency (`sce_random_fill`
  for jitter) is removed from MVP — `docs/intrinsics-runtime-
  symbols.md` §2.5 keeps the *single* MVP RNG consumer
  (`stateless_accept` cookie key) which simplifies OQ-W15 (a)
  ratification (RNG → core whitelist remains the proposal even
  with one consumer; entropy is universal infrastructure).

  **MVP `mode` enum locked at `{active, static}`.** A deploy
  carrying `mode: passive` fails with `deploy/scouting-mode-unknown`
  (existing unknown-enum-value diagnostic family). The 3-field
  schema extension and 4 build diagnostics originally proposed in
  `docs/scouting-fsm.md` §9.3 are **withdrawn**.

  **Phase D+ re-opening contract.** When passive ships in Phase D+,
  the body restoration uses (i) the [scouting-fsm: Passive — deferred to Phase D+](scouting-fsm.md#242-passive--deferred-to-phase-d) prose preserved in this
  log entry above (mode body shape), (ii) the (b) defaults
  preserved here (`30000` / `25` / `5 × interval`, subject to
  empirical validation at re-opening time), (iii) the 4 RFC §5.K
  diagnostics that were withdrawn (re-introduced as Phase D+ patch),
  and (iv) the `sce_random_fill` consumer added to
  `docs/intrinsics-runtime-symbols.md` §2.5 second-consumer row.

- **Cross-doc effects of this deferral.**
  - [`docs/scouting-fsm.md`: Three modes and the zenoh-pico mapping](scouting-fsm.md#14-three-modes-and-the-zenoh-pico-mapping) mode table `passive` row →
    "deferred to Phase D+" label.
  - [`docs/scouting-fsm.md`: Passive — deferred to Phase D+](scouting-fsm.md#242-passive--deferred-to-phase-d) → short deferral paragraph
    replacing the previous body proposal.
  - `docs/scouting-fsm.md` §2.5 timer table → 3 passive timers
    removed.
  - `docs/scouting-fsm.md` §4.2 → "deferred to Phase D+"
    replaces the previous "missing fields" framing.
  - `docs/scouting-fsm.md` §8.1 G-SCT-1 → resolved (defer).
  - `docs/scouting-fsm.md` §8.2 OQ-W23 row → answered/deferred.
  - `docs/scouting-fsm.md` §9.3 → 3 fields + 4 diagnostics
    **withdrawn** for MVP.
  - `docs/scouting-fsm.md` §10 → passive removed from "blocked"
    list (now "deferred").
  - `docs/intrinsics-runtime-symbols.md` §7 — note that passive
    deferral does not change the §2.5 RNG ownership decision.

- **Raised by:** `docs/scouting-fsm.md` §8.1 G-SCT-1 / §8.2
  (2026-05-01 후속).
- **Blocks:** Nothing in MVP (Phase A–C). Re-opens at Phase D+
  entry as a passive-mode landing patch.
- **Last update:** 2026-05-01 후속 #5 (OQ-W23 close — defer to
  Phase D+).

### OQ-W24 — RFC §5.I Architectural-tier vs Peripheral-tier explicit separation

- **Status:** open (SCE counter-offer; long-term boundary hardening).
- **Owner:** watching-zenoh author (RFC §5.I restructure) + SCE
  maintainer (ratify the structural separation).
- **Question.** Current RFC §5.I defines a single baseline whitelist
  (101 symbols, atomics / fences / cache / IRQ) with an implicit
  inclusion criterion: "architecture-fixed primitives where the
  implementation choice is closed". The criterion lives in SCE's
  `sce-build/src/forge/intrinsic_registry.rs:258` constant + drift
  guard at `:455-457`, not in the RFC body. Should RFC §5.I
  introduce an explicit two-tier decomposition:
  - **Architectural-tier** (current baseline): primitives whose
    implementation is fixed by the CPU / SoC architecture (atomics,
    fences, cache maintenance, IRQ control). One valid
    implementation per `(arch, ordering, width)` triple.
  - **Peripheral-tier** (current `target_plugin`): primitives with
    multiple valid implementations and a quality / configuration
    surface (RNG, HMAC, future crypto primitives, hardware
    semaphores).
- **Why it matters.** SCE maintainer answer to OQ-W15 (a) Q1
  cited precedent risk: ratifying RNG into the baseline would
  invite SHA-256 / AES-GCM / ECDSA under the same "public-Internet
  requires it" framing — baseline drift toward crypto authority,
  which SCE is not the spec owner of. Today the defense rests on a
  single OQ rejection plus implicit SCE maintainer judgment. With
  explicit tiers, future ratify requests auto-classify (RNG →
  Peripheral-tier by construction; no per-symbol debate). The
  tier definition itself becomes the spec authority that holds the
  boundary.
- **Proposal (initial).** Adopt the two-tier definition above as a
  new RFC §5.I.0 subsection ("Tier definitions") preceding the
  existing baseline whitelist table. The 101 current symbols are
  re-labelled Architectural-tier without surface change. The
  `<sce:extern>` resolution flow against baseline ∪ target_plugin
  (validated by `validate_stateless_accept_externs`, SCE
  `4570a389`) is unchanged; the tier labels are spec-side
  classification metadata, not a new validator surface. SCE-side
  change estimate: zero code, one `BASELINE_SYMBOLS` doc-comment
  header update.
- **Counter-options.**
  1. **Keep tiers implicit (status quo).** Each future ratify
     request decided ad-hoc with maintainer judgment + OQ entry.
     Cost: O(N) ratify debates for N future peripheral primitives.
  2. **Per-primitive carve-out rule.** Codify "no crypto in
     baseline" as a single inclusion-veto rule. Cheaper than full
     tier separation but less general (does not cover non-crypto
     peripheral primitives like hardware RNG accelerators or
     vendor-specific time sources).
  3. **Document criterion in SCE-side only.** Place the boundary
     in `sce-build` README or `intrinsic_registry.rs` module
     comment, not RFC. Cost: keeps RFC §5.I silent on inclusion
     criterion; downstream consumers cannot audit-trace the
     boundary without reading SCE source.
- **Action.** Draft RFC §5.I.0 subsection in a follow-up round
  (separate from OQ-W15 (a) closure; the spec restructure has
  enough surface to warrant its own atomic ChangelogEntry).
  Coordinate with SCE maintainer to ratify the tier labels in the
  same exchange as the `BASELINE_SYMBOLS` doc-comment update.
- **Raised by:** SCE maintainer counter-offer in OQ-W15 (a)
  resolution (Round 11, 2026-05-14). See OQ-W15 Resolution block
  above.
- **Blocks:** nothing. Future crypto / peripheral primitive ratify
  requests benefit from this being in place but are not blocked
  by its absence — the implicit boundary works today, just at
  higher debate cost per future request.
- **Resolution (light form, Round 16, 2026-05-14).** RFC §5.I body
  gains two caveats encoding the tier separation:
  - Architectural-tier — arch-fixed primitives (atomics / fences /
    cache / IRQ; the 101 BASELINE_SYMBOLS), one valid implementation
    per `(arch, ordering, width)` triple.
  - Peripheral-tier — multi-impl primitives (RNG / HMAC / HSEM /
    crypto / vendor time sources) routed via `target_plugin` only.

  The spec-authority surface now lives in the RFC §5.I atomic
  caveats field rather than as implicit SCE maintainer judgment.
  Future ratify requests auto-classify against the published tier
  definitions: any non-arch-fixed primitive lands in
  `target_plugin`, never the baseline whitelist. The
  baseline-drift veto OQ-W24 codified is mechanically enforceable.
- **Status:** open → in-progress (light closure landed at the
  caveat layer; a full RFC §5.I.0 subsection heading is carried
  to a follow-up round that lands an `add_section` mnemosyne
  primitive — `set_section_*` only updates existing sections, so
  authoring a new sibling-section requires either a typed `add`
  primitive or the raw-Edit carve-out, the latter blocked by
  this doc's atomic-decompose status).
- **Status:** in-progress → answered (Round 17, 2026-05-14:
  RFC §5.I.0 'Tier definitions' subsection landed as atomic
  section via R287/R289 `add_section` primitive; full spec
  restructure now spec-authoritative at the atomic-store layer).
- **SCE-side carry:** unchanged — `BASELINE_SYMBOLS` doc-comment
  header update + tier ratify exchange still pending (original
  OQ-W24 Proposal: "one `BASELINE_SYMBOLS` doc-comment header
  update").
- **Last update:** Round 17, 2026-05-14 (§5.I.0 'Tier
  definitions' subsection landed via `add_section`
  primitive; full closure).

---

## Change log

- **2026-04-24** — log created. Mirrors RFC §8 (Q1–Q14) and
  `wire-spec-subset.md` §10 (OQ-W1–OQ-W8). Q2 moved from `open` to
  `needs-verification` based on direct inspection of
  `sce-build/src/forge/model.rs`. Q8 recorded as `answered` per RFC
  text.
- **2026-04-25** — Q13 closed with refined split (unicast vs
  multicast, not peer vs client) based on upstream zenoh 1.5.0
  `unicast/establishment` + `multicast/` evidence. Four new wire-
  subset questions added (OQ-W9 client+multicast, OQ-W10 auth
  multi-step, OQ-W11 multilink dispatch policy, OQ-W12 closing
  timeout). Triggered by `docs/session-fsm.md` authoring.
- **2026-04-25** (later) — review feedback on cooperative-scheduler
  WCET and multi-core MCU hardware sync ingested. RFC §5.A gains
  `<sce:wcet-bound>` annotation and three new diagnostics; RFC §5.K
  gains `worker_slot_budget_us` + `keepalive_jitter_budget_us` and
  five new diagnostics; RFC §5.I gains a worked HW-semaphore target-
  plugin example. ARCHITECTURE §3.4 / §7.2 / §4.2 updated to
  reference the new fields. Two new questions logged: OQ-W13
  (default budgets and KeyExpr WCET source) and OQ-W14 (HW-sem
  symbol-name standardization).
- **2026-04-25** (review #9) — session-arming DoS gap closed.
  Reviewer flagged that RFC §5.M's "rate-limited by the session
  FSM" assertion was unbacked: `Accepting.*` had no half-open
  capacity, no per-source rate limit, and no SYN-cookie-style
  stateless accept option, so an `InitSyn` flood from spoofed
  source addresses could exhaust the listener. `docs/session-fsm.md`
  gains §2.6 (trust-class × hardening matrix) and §2.7 (full spec
  for half-open capacity, accept-rate token bucket, and
  `cookie_hmac_sha256` stateless accept), plus G-SFM-5. RFC §5.K
  `links` block gains `domain_attrs.untrusted_source`,
  `session_arming_quota`, `accept_rate_per_sec`, `accept_rate_burst`,
  `accept_rate_table_capacity`, `accepting_inactivity_timeout_ms`,
  and the `stateless_accept` sub-block, with eight new build-time
  diagnostics and four runtime diagnostics. RFC §5.M anti-spoofing
  argument now cross-refs the concrete §5.K fields and
  `docs/session-fsm.md` §2.7 — the assertion is mechanically
  backed by build gates rather than a textual promise. One new
  question logged: OQ-W15 (HMAC + RNG primitive ownership and
  default values).
- **2026-04-25** (review #10) — generated-source traceability
  gap addressed. Reviewer flagged that ARCHITECTURE / RFC have
  no mechanism linking generated C/Rust symbols back to SCXML
  authoring locations, making hard-fault and panic root-cause
  analysis a manual reverse-engineering task. RFC gains §5.O
  (Generated-source traceability): three layers — `#line` for C,
  `#[doc]`-based SCE-MAP for Rust, structured `sce_sourcemap.json`
  for tooling — plus an `addr2sce` decoder, a canonical symbol
  naming convention `<machine>__<state_path>__<artifact>`, six
  build-time diagnostics, and integration with §5.A WCET, §5.B
  test-vector, §5.E pool ownership, §6.2.5 fuzz harness, and
  §6.2.6 drift detection. ARCHITECTURE §11.5 cross-refs the
  sourcemap as a verified artifact; ARCHITECTURE §13 #7 (meta-
  generator) gains `<sce:source-line/>` marker preservation
  through Jinja2 expansion. One new question logged: OQ-W16
  (state-path delimiter and Rust SCE-MAP preservation
  mechanism).
- **2026-04-25** (review #11) — F4 fuzz coverage feedback
  mechanism specified. Reviewer flagged that ARCHITECTURE §11.6's
  F4 row commits to "on-device coverage feedback" but never names
  the engine, transport, or corpus pipeline that delivers it.
  ARCHITECTURE §11.6 gains an "F4 coverage feedback architecture"
  subsection: Centipede (out-of-process engine) over libFuzzer-
  native, compiler `trace-pc-guard` instrumentation as the
  canonical signal (ETM/SWO demoted to evidence-only), an
  on-target coverage agent linked behind `BUILD_FUZZ_HARNESS`,
  a two-primitive transport contract (`deliver_input` /
  `read_coverage_bitmap`), Renode-vs-HIL responsibility split
  (FSM-timing + cache/MPU on Renode; DMA/ISR/peripheral/libc on
  HIL), and a throughput-aware F1 → F4-Renode → F4-HIL corpus
  pipeline. Two new CI gates added (transport unreachable;
  instrumentation absent). RFC §5.I gains a new
  `fuzz_coverage_transport` field with five canonical transports
  (`renode_sysbus`, `segger_rtt`, `openocd_memmap`, `dma_uart`,
  `semihosting`) and five build-time diagnostics. One new
  question logged: OQ-W17 (engine choice — uniform Centipede vs
  hybrid; per-target default transport), bundled with OQ-W13 for
  resolution at `deploy/mcu_target.yaml` authoring time.
- **2026-04-25** (review #13) — OS-axis added to design with
  MCU-first invariant preserved. User clarified: MCU zenoh-pico
  full replacement (Phase A–C) is the priority track; AP work is
  Phase D, with Linux first (D.1) and QNX next (D.2); QNX must
  be design-considered now to avoid Linux-shaped assumptions
  becoming refactor debt. RFC §5.K platform gains `os: linux |
  qnx | macos | freebsd | windows | bare_metal | rtos` enum with
  per-OS phase availability and class × os compatibility rules,
  plus four diagnostics (`deploy/platform-os-missing`,
  `deploy/platform-os-class-mismatch`,
  `deploy/platform-os-not-implemented-in-current-phase`,
  `deploy/runtime-crate-mismatch-with-os`). RFC §2.2 MVP
  deferrals table gains explicit "AP on Linux" / "AP on QNX" /
  "AP on macOS/FreeBSD/Windows" entries with phase markers and
  migration paths. RFC §3 target end-state shows OS-parameterized
  runtime-crate dispatch in the `out/ap/` description. RFC §5.C
  link-class enum reserves `unix_socket`, `unix_seqpacket`,
  `qnx_msg`, `qnx_shm` namespace with phase-gate diagnostic
  `link/link-class-deferred-to-phase` and OS-incompatibility
  diagnostic `link/link-class-incompatible-with-os`. RFC §5.J
  backend coverage redefined as `(language, target_os,
  runtime_crate)` 3-tuple with formal `sce_link_runtime_<os>`
  naming convention; two new diagnostics. RFC §7 Phase D split
  into D.1 (AP Linux, blocks D.2) / D.2 (AP QNX) / D.3
  (migration enablers); Phase E added for additional AP targets
  (macOS/FreeBSD/Windows/RTOS). MCU-first invariant explicitly
  reaffirmed in §7. ARCHITECTURE.md §9.5 "Platform-aware link
  substrate (design philosophy)" subsection added — five-row
  matrix showing MCU DMA / linux+epoll / linux+io_uring /
  qnx+io-sock / qnx+shm as instances of the same buffer-pool
  lifecycle FSM with OS-specific edge actions. One new question
  logged: OQ-W20 (`sce_link_runtime_qnx` reactor choice — mio
  QNX backend vs custom QNX-native runtime; Phase D.2 blocker,
  initial proposal: custom).
- **2026-04-25** (review #12) — three reviewer concerns ingested
  (VLE/codec-level WCET aggregation gap, inter-pool padding
  explicitization, stage-copy strict policy). RFC §5.B gains a
  "Codec aggregate WCET" subsection that computes a static
  per-codec parse WCET from per-field contributions (fixed,
  `vle_*`, `len-prefix`, TLV chain, repeat, variant, algorithm
  invocation) and compares it to `worker_slot_budget_us` at build
  time, plus seven new diagnostics (`codec/wcet-aggregate-exceeds-
  slot-budget` hard error, `codec/wcet-aggregate-undeclared-on-rx-
  codec` warning promotable to error, `codec/wcet-aggregate-vle-
  cycles-missing`, `codec/wcet-aggregate-tlv-overhead-missing`,
  `codec/wcet-aggregate-repeat-unbounded`, `codec/tlv-chain-
  aggregate-wcet-exceeds-slot-budget`, `codec/wcet-measured-
  override-stale`) and a derived `<sce:codec-wcet-bound>` annotation
  with optional `mode="measured"` override mirroring §5.A. RFC §5.K
  platform gains `vle_decode_cycles_per_byte` and
  `tlv_chain_per_entry_overhead_us` fields with per-architecture
  defaults (M0+:12.0/1.5, M3-M4:8.0/0.8, M7:6.0/0.5, A:3.0/0.2).
  RFC §5.A gains an algorithm-to-codec aggregation cross-reference.
  RFC §5.E gains explicit inter-pool `. = ALIGN(line_size);`
  sentinel in the linker fragment example, a "Scope: line-level
  cross-contamination only" note clarifying that set-associativity
  contention is a separate problem (answered via `cache-policy`
  separation, not padding), plus diagnostic
  `mem/inter-pool-padding-not-emitted`. ARCHITECTURE §3.4 gains a
  matching set-associativity clarification paragraph. RFC §5.K
  gains `pool_defaults.stage_copy_policy: warn | error | forbid`
  field with three diagnostics (`pool/stage-copy-policy-error`,
  `pool/stage-copy-accept-rejected-under-forbid`,
  `deploy/stage-copy-policy-unknown`); ARCHITECTURE §9.3 gains a
  "Stage-copy policy (deploy-wide)" paragraph with per-deploy-class
  recommendations (warn for AP, error for embedded production,
  forbid for safety-critical). RFC §5.M cross-refs the upgrade
  path. Two new questions logged: OQ-W18 (VLE / TLV per-platform
  coefficient defaults and measurement workflow), OQ-W19
  (`stage_copy_policy` per-skeleton default), both bundled with
  OQ-W13 / OQ-W17 for resolution at `deploy/mcu_target.yaml`
  authoring time.
- **2026-04-30** (review #14) — corrected external review ingested
  after KICKOFF / SCE state cross-verification. **No new open
  questions** — this round is corrections, namespace removals, and
  parity recommitment. Verdict: Reject-but-rework-possible after
  reviewer's own corrections (5 self-corrections retracted Phase 0
  #1 and softened §5.J.3 / §1.1.b / cookie_hmac variant criticism).
  Five workstreams applied: (1) **§5.J.1 phrasing patch** — "There
  is no C backend in `generator::Language`" stale claim corrected.
  SCE `758aea3f` shipped `Language::C11` and closed 11 kinds × 6
  backends parity; the RFC's gap is *new kinds × C11 emitter*, not
  the existing matrix. (2) **§5.J.4 / §5.J.5 added — kind ×
  language matrix and per-language emitter contracts** for new
  generic-class kinds (§5.A / §5.B-generic / §5.F / §5.L / §5.O),
  committing all six backends (Rust/Cpp/Kotlin/Go/Python/C11) and
  marking MCU-class kinds (§5.C link / §5.D worker / §5.E
  buffer-pool / §5.M reassembly + §5.B `dma-burst-align` and
  codec-aggregate-WCET sub-features) as `(rust, *) + (c11,
  bare_metal)` only with `codegen/mcu-class-kind-on-non-mcu-language`
  hard error if bound to cpp/kotlin/go/python. Two new diagnostics
  (`codegen/mcu-class-kind-on-non-mcu-language`, `codegen/generic-
  kind-backend-emit-missing`). §5.A / §5.B / §5.F / §5.L / §5.O
  codegen contract paragraphs expanded from Rust+C-only text to
  six-backend prose + §5.J.5 cross-reference. §5.C / §5.D / §5.E /
  §5.M gain "Backend coverage (MCU-class kind)" opening paragraphs
  cross-referencing §5.J.4. (3) **Three forward-namespace
  reservations removed**: cookie_hmac variant rename `cookie_hmac_v1`
  → `cookie_hmac_sha256` + removal of `cookie_hmac_v2_blake2s
  reserved` line (false back-compat-shim signal); §5.E "Reserved
  states for hardware accelerators" subsection (lines 1039–1088
  pre-edit) deleted, four crypto states + transition shape gone,
  replaced with "FSM extension policy" paragraph stating future
  states land additively at land-time, never preemptively; §5.C
  link-class enum's `unix_socket` / `unix_seqpacket` / `qnx_msg` /
  `qnx_shm` reservation rows + their phase-gate diagnostic
  (`link/link-class-deferred-to-phase`) removed, replaced with
  unknown-value handling via `link/link-class-unknown` and a note
  that OS-specific classes land additively at the relevant phase
  with their driver and runtime crate. §5.J.3 / §7 / §2.2 cross-
  references synced. The `cookie_hmac_v1` rename propagated to
  `docs/session-fsm.md` (6 occurrences), this log (2 occurrences,
  including the OQ-W15 description), and `docs/SESSION_KICKOFF.md`
  (1 retrospective occurrence). (4) **GCC Layer 1 silently inert
  closed**: `pool/clang-tidy-not-configured` promoted from warning
  to **hard error at configure time**, with explicit Layer 2
  substitute escape via `build.static_analyzer: pc_lint | coverity
  | polyspace`. The "GCC, no Clang-Tidy" row of the toolchain
  posture matrix is now labeled "**not accepted**" rather than
  "warns at build". The "Authors are encouraged to ship release
  builds with Clang..." paragraph rewritten from advisory to
  enforcement statement. (5) **`docs/SESSION_KICKOFF.md` line 22 /
  86–89 stale claims corrected** — `enum Language` line + Forge
  emitter description + "C11 backend: 없음" line all rewritten to
  reflect the post-`758aea3f` reality. SESSION_KICKOFF "이번 세션
  ... review #14 반영" entry added at end with full bullet list.
- **2026-05-01** — `deploy/` skeleton authoring round.
  `deploy/mcu_target.yaml` (STM32H747 M7 baseline, 400 MHz, lwIP),
  `deploy/ap_standalone.yaml` (x86_64 Linux + tokio, Phase D.1
  schema-stable), and `deploy/ap_mcu_pair.yaml` (asymmetric hybrid)
  authored. Seven OQ-W entries closed in the same commit: **W6**
  (batch/fragment defaults — MCU 4096/16, AP 65536/256), **W8**
  (bounded-collection capacities — MCU 16/8/8/4, AP 256/64/64/32),
  **W12** (closing timeout — 100 ms session default with per-link
  override on Serial = 250 ms), **W13** (worker_slot_budget_us =
  200, keepalive_jitter_budget_us = 5000, KeyExpr matching =
  `mode="measured"` with harness path documented), **W17(b)**
  (renode_sysbus default for the Phase D+ target_plugin file;
  Phase A–C deploys do not declare the field), **W19** (asymmetric
  stage_copy_policy — AP=warn, MCU=error, hybrid pair shows
  per-machine asymmetry as the canonical pattern). **W18** is
  partially answered (M7 estimate pair committed: VLE 6.0
  cycles/byte, TLV 0.5 µs/entry); empirical measurement on
  M0+/M3-M4/M7 reference boards via `sce-bench
  --measure-vle-coefficients` is the only external dependency from
  the bundle, deferred to HIL benchmark availability. **W17(a)**
  (Centipede vs libFuzzer engine choice for F1 vs F2/F3/F4) still
  pending SCE sync ratification. No new OQ-W entries.
- **2026-05-01** (later) — `docs/reassembly-fsm.md` prose sketch
  authored. RFC §5.M three-state sketch (`Idle/Assembling/Complete`)
  expanded into a four-state slot FSM
  (`Empty/Receiving/Complete/Aborted` plus `TimedOut` as a
  distinct terminal) under a Router + N parallel slot regions
  hierarchy. Three design gaps surfaced + two new questions
  logged: **OQ-W21** (out-of-order Continue policy under
  BEST_EFFORT — proposed reliability-conditional, awaiting
  zenoh-pico verification) and **OQ-W22** (listener-link trust
  class lifecycle — proposed codegen split into accepting +
  established link instances at handshake completion). Six new
  diagnostics added to RFC §5.M — `reassembly/timeout-fired`,
  `reassembly/aborted` (single diagnostic carrying seven reason
  codes via a `reason=` field), `reassembly/unmatched-continue`,
  `reassembly/unmatched-final`, `reassembly/slot-pool-full`,
  `reassembly/message-complete`.
  Deploy capacity invariant violation (G-RFM-3) found in all
  three skeletons and corrected: `qos.max_fragment_count` 16→2
  (MCU) and 256→44 (AP), with matching `buffer_pools.
  reassembly_pool.max_fragments_per_message` values, so RFC §5.M's
  `slot_size ≥ max_fragments × mtu_bytes` invariant holds (MCU
  4096 ≥ 2 × 1472 = 2944; AP 65536 ≥ 44 × 1472 = 64768). The
  capacity revision is a deploy-side fix; RFC §5.M is unchanged.
- **2026-05-01** (OQ-W21 close) — out-of-order Continue policy
  verified against zenoh-pico 1.9.0 HEAD `3b3ab65`. Resolution:
  **strict in-order, identical for RELIABLE and BEST_EFFORT**
  (option 2 in this log's enumeration). The reliability-conditional
  initial proposal (option 3) is rejected for MVP because it
  diverges from upstream zenoh-pico parity. Evidence cites
  `src/transport/{unicast,multicast}/rx.c`,
  `include/zenoh-pico/transport/transport.h`,
  `src/transport/utils.c`, `src/transport/peer.c`,
  `include/zenoh-pico/protocol/{definitions/transport.h,ext.h}`,
  and `CMakeLists.txt:306`. **OQ-W21** marked answered;
  `docs/reassembly-fsm.md` §2.5 amended with the resolution and
  upstream code citations; G-RFM-1 marked resolved. Cascading
  FSM-shape amendments (chain key 4-tuple → 2-tuple, slot count
  N parallel → 2 per peer, removal of per-chain
  `reassembly_timeout_ms`, `start` flag → `FRAGMENT_FIRST`
  extension nomenclature) tracked in `docs/reassembly-fsm.md`
  §2.5 as a deferred revision pass — they block Phase A SCXML
  authoring of `sources/reassembly/reassembly_slot.scxml` but do
  NOT reopen OQ-W21. No new OQ entries; OQ-W22 remains open.
- **2026-05-01 후속** (scouting-fsm.md authoring) —
  `docs/scouting-fsm.md` prose sketch authored
  (1458 lines; mirrors `reassembly-fsm.md` /
  `session-fsm.md` shape). The same zenoh-pico 1.9.0 HEAD
  `3b3ab65` read pass closes two OQs, registers one new, and
  surfaces three design gaps:
  - **OQ-W3 closed** (Interest semantics not router-only in 1.x).
    Three transport-class-specific mechanisms achieve declaration
    sync between peers: unicast acceptor push at handshake
    (`~/zenoh-pico/src/transport/unicast/accept.c:148-149` →
    `~/zenoh-pico/src/session/interest.c:194-201`
    `_z_interest_push_declarations_to_peer`); multicast peer
    Interest reply (`interest.c:531-569`, transport-class-guarded
    at line 534-535); multicast pull at session open
    (`~/zenoh-pico/src/net/session.c:149-153` →
    `interest.c:203-214`). MCU's Interest handler is a real
    participant on multicast, no-op on unicast — bounded form per
    `wire-spec-subset.md` §5. Authoring contract for
    `declare_fsm.scxml` materialized at `docs/scouting-fsm.md` §3.4.
  - **OQ-W9 closed** (clients refuse multicast sessions, do
    multicast scouting). `_z_multicast_open_client` at
    `~/zenoh-pico/src/transport/multicast/transport.c:153-162`
    explicitly returns `_Z_ERR_CONFIG_UNSUPPORTED_CLIENT_MULTICAST`;
    symmetric `_z_multicast_open_peer` at `transport.c:116-151`
    fully implemented. Scouting layer is whatami-agnostic
    (`~/zenoh-pico/src/protocol/definitions/transport.c:419-428`
    `_z_s_msg_make_scout`). Build-time enforcement
    `deploy/client-multicast-session-unsupported` (hard error)
    proposed for RFC §5.K. Cross-doc amendment to
    `docs/session-fsm.md` §3.4 / §8.2 OQ-W9 row pending.
  - **OQ-W23 new** (passive scouting mode justification + schema).
    Two-part question: (a) should `scouting.mode: passive` ship in
    MVP given zenoh-pico has no equivalent (the watching-zenoh
    proposed body re-triggers active scouting on a period, with
    jittered re-emission), (b) if yes, the three deploy fields
    `scout_retry_interval_ms`, `scout_retry_jitter_pct`,
    `hello_entry_lease_ms` need defaults. Blocks Phase A SCXML
    authoring of *passive mode only*; active and static mode
    bodies authorable now from `docs/scouting-fsm.md` §2.4.1 / §2.4.3.
  - **G-SCT-1 / G-SCT-2 / G-SCT-3** filed in
    `docs/scouting-fsm.md` §8.1: passive mode justification +
    schema (G-SCT-1 → OQ-W23); unsolicited Hello broadcaster
    (G-SCT-2, speculative, no OQ); `scout_rx_pool.slot_size`
    realistic-vs-worst-case Hello sizing (G-SCT-3, informational
    diagnostic `scouting/hello-slot-size-recommendation`
    proposed).
  - **Three-mode framing as a watching-zenoh operational
    abstraction** (`docs/scouting-fsm.md` §1.4) — `active` is
    1:1 to zenoh-pico parity; `passive` is honest as a
    watching-zenoh addition (G-SCT-1 / OQ-W23); `static` is
    parity expressed as scouting-bypass via `connect=` config.
    The mode is a compile-time constant; codegen elides regions
    the mode does not need (mode-gating as a deploy-attribute
    extension of ARCHITECTURE §2.4 invariant #5; recommended as
    a footnote per `docs/scouting-fsm.md` §9.7).
  - **RFC patches recommended** (`docs/scouting-fsm.md` §9):
    six new build diagnostics
    (`deploy/scouting-{retry-interval,retry-jitter,hello-lease}-
    missing-on-passive-mode`,
    `deploy/scouting-passive-fields-on-non-passive-mode`,
    `deploy/client-multicast-session-unsupported`,
    `deploy/untrusted-source-on-untrusted-link`); three new
    informational diagnostics
    (`scouting/hello-max-peers-exceeds-peer-tables`,
    `scouting/rx-pool-overprovisioned-vs-burst-pps`,
    `scouting/hello-slot-size-recommendation`); four new runtime
    diagnostics (`scout/{tx-failed, decode-failed, peer-aged-out,
    client-looking-for-clients}`); ARCHITECTURE §2.4 invariant
    #5 footnote on mode-gating as deploy-attribute platform
    gating.
  - **id-space** header `OQ-W22` → `OQ-W23`.
  - **Outcome.** Phase A SCXML authoring of `sources/session/
    scouting.scxml` is unblocked for `mode ∈ {active, static}`.
    OQ-W22 (listener-link trust class lifecycle) remains the
    only open question on the reassembly+session+scouting prose-
    triplet; OQ-W23 (passive mode) remains open but is itself
    a binary include/defer decision rather than a parity
    verification.

- **2026-05-01 후속 #5** (runtime crate API stub design + OQ batch
  close) — KICKOFF candidate #2 ("Runtime crate API stub design")
  + OQ-W23 (a) binary decision + OQ-W4/W7/W10 batch verification
  against zenoh-pico 1.9.0 HEAD `3b3ab65`. Five OQ closures in
  one round.

  **Three new prose docs landed** (≈900 lines combined):
  - `docs/runtime-crate-tokio.md` — Rust trait surface for
    `(rust, linux, sce_link_runtime_tokio)` 3-tuple per RFC
    §5.J.3. `LinkDriver` 4-method trait (`open`/`send`/`close`/
    `poll_event`) + `LinkEvent` 6-variant enum mapping 1:1 to
    `docs/session-fsm.md` §6 inbound events. Trust-class
    compile-time gating maps onto trait surface presence/absence
    (untrusted / session_arming / established_session). io_uring
    fixed-buffer opt-in shown to require zero trait change —
    only §5.E pool lifecycle FSM edge actions differ
    (ARCHITECTURE §9.5 row 3). Phase A–C scope: design-only.
  - `docs/runtime-crate-lwip.md` — C11 sibling of tokio doc.
    `(c11, bare_metal, sce_link_runtime_lwip)` 3-tuple. Same
    6-event contract expressed as `sce_link_event_t` enum +
    `sce_link_t` opaque + `sce_pool_slot_handle_t` opaque
    (the §5.E lifecycle ownership-inheritance edge handle) +
    cooperative-scheduler poll function + ISR-side dispatch
    entry. RFC §5.E Layer 1 typestate annotations
    (`consumable`/`callable_when`/`set_typestate`) propagate
    onto the slot handle for use-after-take / double-take
    catch under Clang `-Wconsumed`. **Phase A direct authoring
    blocker** (header is the codegen target).
  - `docs/intrinsics-runtime-symbols.md` — symbol surface for
    `sce_intrinsics_runtime_{c,rust}` (RFC §5.I whitelist host).
    Seven symbol categories (atomics / fences / cache / IRQ /
    RNG / HMAC / HW-sem) with whitelist-vs-target-plugin policy
    column. **OQ-W15 (a) initial proposal locked**: §2.5 RNG →
    core whitelist (option 1, universal entropy primitive);
    §2.6 HMAC → target plugin (option 2, per-SoC accelerator
    selection). §5.J.2 statechart `no_std` HAL trait shape
    (`now_us`/`wake`/`irq_save`/`irq_restore`) mapped onto §2
    symbols. ARCHITECTURE §9.5 5-row matrix preserves "same
    shape, different body" — symbol names identical across all
    five rows; bodies vary per platform.

  **OQ-W23 (a) closed — defer to Phase D+** (full Resolution
  block in OQ-W23 entry above). Three reasons: MVP=zenoh-pico
  parity (passive has no upstream equivalent); YAGNI/scope
  discipline (application-layer `z_scout()` retry is the
  parity-aligned workaround); reversibility asymmetry
  (additive enum extension at Phase D+ vs breaking schema
  removal). Ratifies the long-term-correct discipline framing
  established in RFC review #14 ("pre-release forward-namespace
  0"). Cross-doc effects: 7 places in `docs/scouting-fsm.md`
  amended (§1.4 row label, §2.4.2 body shrunk to deferral
  paragraph, §2.5 timer table 3 rows removed, §4.2 reframed,
  §8.1 G-SCT-1 resolved, §8.2 OQ-W23 row answered/deferred,
  §9.3 RFC §5.K passive-mode patch *withdrawn*, §10
  next-step updated, §12 change log entry); MVP `mode` enum
  locked at `{active, static}`.

  **OQ-W4 closed — Compression absent in zenoh-pico 1.9.0**
  (full Resolution block in OQ-W4 entry above). Verified
  against ext.h:46-50 (5-extension-ID enumeration, no
  Compression); transport.c:230-233 (unknown-mandatory →
  refuse, unknown-non-mandatory → silently ignore — defends
  against any future upstream Compression that arrives with
  M-flag set). MVP wire surface omits Compression
  (already accept-and-ignore per `docs/wire-spec-subset.md`
  §7.2); the watching-zenoh policy mechanically matches
  upstream.

  **OQ-W7 closed — direction-asymmetric PatchType policy**
  (full Resolution block in OQ-W7 entry above). Initiator
  refuses higher-patch InitAck
  (`unicast/transport.c:141-149`); acceptor min-clamps
  (`peer.c:225`, `multicast/rx.c:407`). `_Z_NO_PATCH=0x00`,
  `_Z_CURRENT_PATCH=0x01` (transport.h:100-101), 2-valued
  patch enum gated on `Z_FEATURE_FRAGMENTATION`. The MVP
  proposal "refuse" was partially right — refuses on
  initiator only; acceptor min-clamps. SCXML body honors
  direction.

  **OQ-W10 closed — Auth absent in zenoh-pico 1.9.0**
  (full Resolution block in OQ-W10 entry above). No
  `Z_FEATURE_AUTH`/`USRPWD` gate exists; `Z_CONFIG_USER_KEY`/
  `PASSWORD_KEY` (config.h.in:110, 117) defined but
  unconsumed in src/; ext.h:46-50 has no Auth extension ID;
  no `*usrpwd*`/`*auth*` files in transport tree. MCU
  parity baseline = `{none}`; USRPWD multi-step shape
  question moot for MVP. `Opening.*` sub-states stay flat
  per session-fsm §2.2.

  **OQ-W2 closed (sibling effect of OQ-W10)** — Auth
  baseline shrunk to `{none}` from the original
  `{none, usrpwd}` proposal; USRPWD and pubkey both deferred
  to Phase D+ landing alongside OQ-W10 re-opening.

  **id-space** header unchanged (OQ-W23 still highest;
  no new OQs filed this round). 5 OQ status changes
  (W2/W4/W7/W10/W23 all moved `open → answered`).

  **Cross-doc effects (this round only).**
  - `docs/scouting-fsm.md`: 7 sections amended for OQ-W23
    deferral (see above).
  - `docs/runtime-crate-tokio.md` / `runtime-crate-lwip.md` /
    `intrinsics-runtime-symbols.md`: 3 new docs landed.
  - `docs/SESSION_KICKOFF.md`: new "이번 세션(2026-05-01
    후속 #5)" entry — see the kickoff doc itself.
  - `docs/wire-spec-subset.md` OQ-W4/W7/W10/W23 row labels
    *not* required to amend (the open-questions log is the
    authoritative status; `wire-spec-subset.md` §10 already
    cross-refs by OQ id, and the OQ entry text now carries
    the resolutions).

  **Outcome.** Five OQ closures (W2/W4/W7/W10/W23) + three
  new prose docs that fix the runtime crate API contract
  (Rust trait + C11 header + intrinsics symbol surface) for
  Phase A–D codegen targets. **Phase A SCXML authoring's
  remaining cross-doc blocker is OQ-W22** (listener-link
  trust class lifecycle, RFC §5.M / §5.C patch needed) +
  OQ-W15 ratification (RNG → core whitelist; HMAC → target
  plugin proposals stand). All other OQs are either
  answered or design-only-during-Phase-A-C (Phase D+ work
  has its own blockers — OQ-W11/W17/W20 — but those don't
  impede the priority MCU track).

- **2026-05-01 후속 #6 (OQ-W22 close).** Option 3 ratified
  (codegen splits listener link into two logical
  link-instances sharing one physical socket). Resolution
  block + cross-doc amend list logged in OQ-W22 entry above.
  RFC §5.M gained "Listener-link trust-class lifecycle"
  subsection (semantic); RFC §5.C gained "Listener-link
  sibling emission" subsection (codegen mechanics).
  deploy.yaml schema unchanged. Two new diagnostics:
  `link/listener-link-not-paired-with-established-sibling`
  (§5.C self-check) +
  `reassembly/binding-on-unpaired-listener` (§5.M defense).

  Cross-doc amends:
  - `docs/reassembly-fsm.md` — §5 rewritten, §8.1 G-RFM-2
    resolved, §8.2 OQ-W22 answered, §10 unblocked, §12
    change log entry.
  - `docs/session-fsm.md` §2.6 — "Listener-link logical
    split" subparagraph appended.
  - `docs/runtime-crate-lwip.md` §4 — "Listener-link
    two-instance emission" paragraph added.
  - `docs/runtime-crate-tokio.md` §2.4 — same shape paragraph
    added.

  **id-space** header unchanged (no new OQs filed; W22 moved
  `open → answered`).

  **Outcome.** Phase A SCXML authoring on the reassembly + session
  side is fully unblocked. Remaining cross-doc blocker = OQ-W15
  (HMAC + RNG primitive ownership ratification, SCE maintainer
  sync), which gates only `stateless_accept` SCXML on
  public-Internet-facing listener-bearing MCUs. A 1-page
  ratification summary for OQ-W15 (a) is prepared in this same
  session — see OQ-W15 ratification artifact below.

- **2026-05-01 후속 #6 (OQ-W15 ratification artifact).**
  `docs/oq-w15-ratification-summary.md` new doc — 1-page
  SCE-maintainer-facing summary distilled from
  `docs/intrinsics-runtime-symbols.md` §2.5 / §2.6 / §3 +
  `docs/session-fsm.md` §2.7 (c). Six sections (Decision needed /
  Why now / Initial proposal with reasons / Counter-options /
  Blast radius / Action requested). The summary is *audience-
  segregated* as a separate doc rather than appended as §A to
  `docs/intrinsics-runtime-symbols.md` because (a) the source
  doc's audience is internal (developers consuming the symbol
  surface), the summary's audience is external (SCE maintainer
  ratifying the proposal), and (b) future similar artifacts
  (e.g. OQ-W14 HW-sem standardization) get a parallel
  `docs/oq-w14-ratification-summary.md` sibling under the same
  pattern.

  OQ-W15 (a) status remains `open` pending SCE sync — the
  summary is a *preparation* artifact, not a closure. OQ-W15 (b)
  defaults are out of scope for this artifact (settle via HIL
  measurement, not via sync).

  **Outcome (full session).** OQ-W22 closed with codegen split
  (option 3); OQ-W15 (a) ratification artifact prepared.
  **Phase A SCXML authoring on watching-zenoh's prose side is
  *completely unblocked* for all listener bindings except
  public-Internet-exposed MCU listeners** (those still wait on
  OQ-W15 (a) ratification, but the ask is fully prepared as a
  1-page artifact). Phase A SCE-side blocker (RFC §5.J.1 new
  kinds × C11 emitter + statechart `no_std` runtime feature)
  remains the gating dependency for actual SCXML authoring —
  prose-side work is at a natural terminus.
