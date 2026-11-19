# Can wz's hand-written protocol logic be written as SCE kinds?

The question: wz wants one SCE source set to generate Rust, C11 and C++, with only
a thin platform seam left hand-written. Before any logic moves, the order is (1)
this census, (2) add the kinds SCE lacks, (3) migrate. This document is step 1
for the logic that is not wire layout; the wire layout has its own census,
`docs/zenoh-as-sce-codec-documents.md`.

The per-item tables are in `docs/zenoh-logic-as-sce-kinds/S1.md` to `S6.md`.
This document joins them: it states the method, the totals, one gap catalogue
whose codes replace the slice-local ones, the order SCE work would take, and
what the census found on the wz side.

## 1. Answer

About 565k production lines of hand-written Rust were classified in twelve
slices. 7.2k already run through generated SCE code (A), 85k are expressible
with a kind SCE has today (K), and 202k are blocked (G). The rest is platform
seam (S, 79k), diagnostics (D, 36k) and glue (X, 155k), which do not move or
move by a separate decision. Slices S1 to S6 were taken first (369k lines); S7
to S10 added the C ABI crates, the MCU runtimes and network stacks, and the
crates and files the first six left out; S11 and S12 added the application
frame layer, its replay and the application transport. `crates.md` names a
slice or a reason for every crate, and `files.md` does the same for every file
of the crates a slice reads (section 2, Coverage).

The blocked lines do not need 202k lines' worth of new language. They meet a
small set of missing elements, and one of them dominates: a machine cannot own a
table keyed by a runtime value (U1, 143 rows, in every slice). After it come
text as data (U2a, 63 rows), unbounded data (U10, 54 rows), shared state with a
stated memory ordering (U8, 39 rows in S1 to S6, a request now withdrawn,
section 5), in-flight request tables (U9, 36 rows, most of which reduce to U1),
and JSON documents (U12, 26 rows).

The first SCE change is SCE ADR 0108, a statechart that holds a table by key as
a bounded map; its Rust part landed on 2026-11-19 and its C11 part is next
(section 5).

The C build reaches the zenoh-pico preset's C ABI first (S7). On the
cooperative path (`wz-capi-pico` over `wz-capi-port` over `wz-capi-coop`) about
11.8k lines are protocol logic, 8.7k of them blocked. Their completion, cancel,
undeclare and close semantics rest on the count of an `Arc` or the order of a
`Drop`; the S7 and S8 Summaries list each place, and the target structure needs
each as an explicit event. The pico doors S12 adds (end-to-end protection,
instance keys, the message catalogue, replay, stream supervision, the
application transport) select `std`, which an `os-zephyr` build refuses
(`crates/wz-capi-pico/src/lib.rs:113`); of them only 137 lines reach the Zephyr
image.

## 2. Method

- **Yardstick.** The kind catalog SCE emits (`sce-codegen kinds`, SCE
  `d44b0fb8`, which contains the wz pin `9ae6a6b6`), with `SCE_FORGE.md` and
  `docs/SCE_ACCEPTED_SUBSET.md` read from SCE `origin/main` (`b7c2558`). A K or
  G row cites the SCE text it rests on.
- **Slices.**

  | Slice | Scope | Rows |
  |---|---|---|
  | S1 | `wz-session-core`: transport, links, scouting, multicast, session lifecycle, `session_actions.rs` | 73 |
  | S2 | `wz-session-core`: query/reply, pub/sub, declarations, keyexpr | 62 |
  | S3 | `wz-session-core`: the rest (passive, dissect, observer, stats, policy, JSON5) | 66 |
  | S4 | `wz-runtime-tokio`: router, routing, session API; `wz-routing-graph` | 95 |
  | S5 | `wz-runtime-tokio`: the rest (link pipelines, shm, storage services, config); `wz-session-mcu`; `wz-runtime-coop` | 93 |
  | S6 | the `wz-zenoh*` crates; `wz-storage`, `wz-admin`, `wz-ext-pubsub`, `wz-auth`, `wz-access-control` | 93 |
  | S7 | the zenoh-pico preset's C ABI: `wz-capi-pico`, `wz-capi-port`, `wz-capi-coop`, `wz-capi-core` | 106 |
  | S8 | the zenoh-c preset's C ABI: `wz-capi-c` | 73 |
  | S9 | MCU and hosted runtimes, links, network stacks, TLS, time: 22 crates | 87 |
  | S10 | application framing, bridges, the demo, and the files S1 to S6 left out | 85 |
  | S11 | the application frame layer (`.proto` schemas, instance keys, the message catalogue, end-to-end receive and send, segment joining) and its replay, with the SCE documents written for them | 38 |
  | S12 | the application transport, stream supervision and key ids in the session core and both runtimes, and the zenoh-pico doors to S11's code | 43 |

  S7 to S10 were added on 2026-11-20, after the owner ruled that all protocol
  logic is to be in SCE and that the C build is the zenoh-pico preset, and read
  SCE's text at `origin/main` `e7640cec53`. S10's
  rows for files S5 and S6 already counted inside larger rows (A 151, K 902,
  S 606, X 538 lines) are left out of the totals. S11 and S12 were added the
  same day, against SCE `origin/main` `4d3c9309e02`, and the file-level pass
  below added S6 rows 94-95 and S10 row 85 and cited each file in S6's coarser
  rows.

- **Coverage.** `docs/zenoh-logic-as-sce-kinds/crates.md` has a row for every
  crate: the slices that read it, or an exclusion with its kind and reason.
  `docs/zenoh-logic-as-sce-kinds/files.md` has a row for every tracked `.rs`
  file under `src/` of a crate a slice reads: the slices one of whose rows cites
  it, or an exclusion (`test`, `generated`, `scope`) with its reason.
  `scripts/lib/logic_census_coverage_gate.py` holds both tables to the tree, so
  a new crate or a new file is a red until it is placed. The file level was
  added when the crate level was found passing over about 45k lines no row
  cited: S7 named `wz-capi-pico` and never reached its newer doors, S6 cited a
  few files of rows that count whole crates, and the application transport had
  no row at all.
- **Not classified.** The analyzer (`wz-capture` and the crates that follow it),
  whose place in the migration is a separate decision; test, build, binding and
  example crates (each named in the table); test code and `#[cfg(test)]`
  modules; codec layout.
- **Classes.** A: already generated SCE code that wz uses. K: expressible with
  an existing kind. G: blocked, with a gap code. S: platform seam by design.
  D: diagnostics. X: glue, re-exports, configuration plumbing.
- **Unit.** One row per responsibility (a table, a decision procedure, a state
  machine, an algorithm), with its wz `path:line`. Rows that hold a deliberate
  fix (an ordering rule, a race, an upstream divergence) say so; those are the
  places a migration can lose behaviour.
- **Checks on the census itself.** All 187 distinct `crates/...rs:N` citations
  in the six tables point at an existing file and line; two sampled rows were
  read against their source. The SCE claims most rows rest on were read in SCE's
  own text: a `sce-static` statechart has no bounded-collection variable; a
  lookup keyed by a text is refused; `list<T>` holds fixed-width numbers and
  `bool`; a record's string has one write (from a literal or another record's
  field) and one comparison, and a `bytes` field is refused (`SCE_FORGE.md`,
  §4.12 records); only algorithms are called from an algorithm body; `sce:extern`
  appears nowhere in SCE's documents (it is a proposal in this repository's
  `docs/rfc-sce-protocol-synthesis.md` §5.I).
- **Counting.** Line counts are approximate. S2 counts code lines only; the
  other slices count production lines including comments. One G row may carry
  several gap codes, so lines are not summed per gap; rows are counted.

## 3. Totals

| Class | Lines | Share |
|---|---|---|
| A | 7,172 | 1 % |
| K | 85,163 | 15 % |
| G | 202,355 | 36 % |
| S | 78,928 | 14 % |
| D | 36,220 | 6 % |
| X | 155,415 | 27 % |
| Total | 565,253 | |

| Slice | A | K | G | S | D | X |
|---|---|---|---|---|---|---|
| S1 | 45 | 10,871 | 40,472 | 6,581 | 2,697 | 10,424 |
| S2 | 0 | 7,006 | 9,049 | 1,662 | 463 | 3,368 |
| S3 | 184 | 4,174 | 4,058 | 281 | 16,588 | 9,035 |
| S4 | 3,513 | 5,352 | 46,356 | 6,609 | 4,610 | 9,431 |
| S5 | 870 | 11,800 | 24,180 | 30,100 | 980 | 9,750 |
| S6 | 0 | 16,930 | 25,946 | 6,829 | 5,133 | 34,322 |
| S7 | 0 | 3,889 | 22,273 | 5,565 | 1,587 | 25,534 |
| S8 | 0 | 10,624 | 3,438 | 2,766 | 1,294 | 24,631 |
| S9 | 2,452 | 4,147 | 6,393 | 13,655 | 1,497 | 4,986 |
| S10 | 108 | 7,976 | 10,132 | 2,744 | 1,371 | 17,923 |
| S11 | 0 | 1,477 | 8,219 | 322 | 0 | 349 |
| S12 | 0 | 917 | 1,839 | 1,814 | 0 | 5,662 |

S11's and S12's A rows are SCE documents (447 and 185 SCXML lines) that wz's
Rust calls through `out/`; the table counts Rust, so their A is 0 here, and the
Rust that calls the generated code is counted in the rows around it.

S7's G is mostly `wz-capi-core` (13.6k), the tokio engine that zenoh-pico's
default build and the zenoh-c ABI share; it is not on the cooperative path. Of
S9's G, 4.9k lines are `wz-tls-record`, the analyzer's offline TLS and QUIC
decryption, which belongs with the analyzer's decision. S8's and S7's X is the
marshalling of the C structures, by value in pico's case.

S1's A count is the hand-written binding around eight generated statecharts
(1,296 SCXML lines); the statecharts' behaviour is carried by host actions,
of which `session_actions.rs` alone is about 16.8k lines. Of S6's K, 9,176 lines
are `wz-zenoh-codec`, a hand copy of upstream `zenoh-codec` that does not use the
generated `out/wz-codecs`.

## 4. Gap catalogue

Each slice named its gaps with letters of its own, and two letters collided (R
means a codec call in S3 and text operations in S6). The codes below replace
them; section 4.1 maps each slice's letters.

| Code | Missing element | Rows | SCE evidence |
|---|---|---|---|
| U1 | A table keyed by a runtime value (id, zid, keyexpr, name) that a machine owns and mutates: bind, replace, unbind, lookup by key, a counted refusal when full | 143 (S1 12, S2 18, S3 1, S4 34, S5 14, S6 18, S7 28, S8 3, S9 6, S10 3, S11 3, S12 3) | a `sce-static` statechart has no bounded-collection variable; statechart `list<T>` variables append, clear and read by index only; `bounded-collection` addresses entries by handle. SCE ADR 0108 answers it (Rust landed, C11 next) |
| U2a | Text as data: parse, produce, slice and compare texts (locators, keys, selectors, ACL subjects) | 63 (S1 8, S6 15, S7 20, S9 3, S10 6, S11 5, S12 6) | a record's string has one write and one comparison; `list<T>` refuses a string element |
| U2b | A table keyed by a text | 22 (S5 4, S7 3, S8 2, S9 1, S10 4, S11 6, S12 2) | a lookup keyed by a text is refused; ADR 0108's map admits a text key |
| U3 | A record or list element that holds bytes, a list or a collection | 20 (S1 5, S4 8, S7 1, S8 3, S11 3) | a record's fields are fixed-width numbers, `bool`, `enum:` or a bounded string. A bounded `bytes` field is accepted (SCE `docs/SCE_ACCEPTED_SUBSET.md`, "A byte string"), which S1 to S6 read as refused; section 8 |
| U4 | A statechart or algorithm step that encodes or decodes a codec value and branches on the result | 11 (S1 9, S3 1, S10 1) | calls are defined between algorithms only; no text lets an algorithm call a codec. Answered by the boundary binding (section 5) |
| U5 | Recursive data: keyexpr trie, JSON5 value tree, persistent-map trie, shm `AllocPolicy` tree | 21 (S3 1, S4 3, S5 6, S6 7, S8 1, S11 3) | no tree kind exists; `docs/rfc-sce-protocol-synthesis.md` §5.H deferred it |
| U6 | A general graph: shortest-path trees, reachability, removal of detached nodes | 9 (S4 7, S11 2) | no kind holds a graph |
| U7 | A bounded pool of statechart instances routed by a runtime key | 10 (S1 4, S7 5, S12 1) | the reassembly, multicast and peer-table routers stay in Rust for this |
| U8 | State shared across execution contexts with a stated memory ordering: locks, RCU snapshots, atomics protocols, fences between lanes | 39 (S1 7, S2 1, S4 20, S5 6, S6 5) | `queue` and `broadcast-log` state their guarantee for their own element only; no `sce:extern` for atomics or fences. Withdrawn as a request (section 5); S7 to S10 classify such state by what it is, behind a door |
| U9 | Many requests in flight, each with its own deadline and cancellation; executor `select` loops | 36 (S1 2, S4 14, S5 2, S6 6, S7 12) | see 4.2: a single deadline is expressible; the table of in-flight requests is U1 |
| U10 | Unbounded data: growable buffers, payload arenas, caches, reorder buffers | 54 (S2 2, S3 1, S4 10, S5 11, S6 8, S7 2, S8 3, S9 5, S10 4, S11 6, S12 2) | AP may hold it; on MCU it is a permanent constraint (`ARCHITECTURE.md` §2.3) |
| U11 | A value-returning host or library function inside a step: HMAC, SHAKE/keccak, lz4, RSA, xxh3, SipHash, RFC 3339, float formatting, a logarithm | 20 (S1 6, S3 1, S4 2, S5 1, S6 5, S9 4, S10 1) | only a procedure's `<sce:helper>` returns a host value; `sce:extern` is absent. SCE ADR 0109 D5 to D7 answer part of it |
| U12 | A JSON / JSON5 document used as data (configuration, admin replies, profiles) | 26 (S5 10, S7 1, S8 1, S10 11, S11 3) | no codec encoding is JSON; `text-template` has no list or record hole |
| U13 | A step that reads a value another component computed in the same macrostep (Q), or a host effect per element of a collection (I) | 6 (S3 5, S9 1) | `<sce:action>` returns only whether it ran; `<sce:action>` inside `<foreach>` is refused |
| U14 | A document generic over the application's types | 1 (S3) | `docs/rfc-sce-protocol-synthesis.md` §5.G deferred it |
| U15 | A wire layout known only at run time: a header whose widths, byte order, masks, marks and CRC model arrive as a profile on every call, or a `.proto` schema a deployment hands over at run time | 7 (S10 4, S11 3) | a codec fixes each field's offset, size and order in the document; nothing in SCE reads a layout description at run time |
| U16 | A queue or pool whose capacity is a run-time value (a C program states a channel's capacity when it makes it; W4's lend book) | 7 (S7 1, S11 5, S12 1), and W4 | a `queue` is bounded at build, segmented or intrusive |
| U17 | A full queue that drops the newest or evicts the oldest, with one consumer that removes and several producers | 3 (S7 1, S8 1, S11 1) | a `queue` gives back only its oldest element, and `overwrite-oldest` was refused on it; `broadcast-log` forgets its oldest but is read without removal, with one producer |
| U18 | A post from a thread that is not the machine's owner whose effects must be applied before the posting call returns (zenoh-c runs a session's delivery to itself inside the call) | 1 (S8) | ADR 0084: "no input waits for a macrostep"; only start, stop and the destructor wait |
| P | Expressible, but the generated form would break a measured or stated performance property | 22 (S1 2, S2 7, S3 1, S4 7, S5 1, S6 1, S7 2, S10 1) | each row cites the measurement or `docs/query-answer-path.md` |
| L1 | The codec census's L1 (a body chosen by an extension's identity) | 1 (S2) | `docs/zenoh-as-sce-codec-documents.md` |

### 4.1 Slice letters to catalogue codes

| Slice | Letters |
|---|---|
| S1 | M→U1, H→U2a, R→U3, W→U4, N→U7, C→U8, A→U9, F→U11, P→P |
| S2 | M→U1, H→U10, C→U8, P→P, L1→L1 |
| S3 | M→U1, H→U10, T→U5, R→U4, Q/I→U13, N→U14, F→U11, P→P |
| S4 | M→U1, L→U3, T→U5, N→U6, C→U8, A→U9, H→U10, F→U11, P→P |
| S5 | M→U1, L→U2b, T→U5, C→U8, A→U9, H→U10, F→U11, J→U12, P→P |
| S6 | M→U1, R→U2a, T→U5, C→U8, A→U9, H→U10, F→U11, P→P |

S7 to S12 use the catalogue codes. The elements they found missing are U15 to
U18.

### 4.2 What is not a gap

- **A single deadline.** A delayed `<send>` waits in the machine's own
  scheduler and a `<cancel sendidexpr>` removes it; a host that owns the clock
  drives it with `<machine>_init_with_clock` and `<machine>_advance_time_ms`
  (`docs/SCE_ACCEPTED_SUBSET.md`). The host-owned clock is present at the wz pin
  (C templates `state_machine.h.jinja2`, Rust runtime `clock.rs`). wz arms no
  statechart timer today because its no-std `NoOpHal` clock never advances
  (S1); that is a wz wiring choice, so S1 rows 19-20 are K. What remains of U9
  is the table of in-flight requests, which is U1.
- **`<parallel>`.** `crates/wz-runtime-tokio/src/multicast_glue.rs:16-17` says
  the SCE surface has no `<parallel>`. The pinned subset lists it as a core
  construct, so the three parallel regions that file realises in a host loop
  are not blocked by the language.

## 5. The target structure and the order of the SCE work

The owner ruled on 2026-11-19 that all protocol logic is to be in SCE documents,
and that the C build has to be the zenoh-pico preset only, for now. The
structure below was recommended for that goal with cost ignored, accepted by the
owner, and agreed by the SCE session the same day. The census rows are read
against it.

1. **A sans-I/O core.** The protocol is a deterministic, single-threaded set of
   machines and algorithms, generated for Rust and for C11 from one source set.
   It performs no I/O and reads no clock of its own.
2. **Parsing at the boundary.** Bytes that arrive through a door are decoded by
   a bound codec into a typed schema event before any machine sees them, and a
   `<send>` of a bound schema is encoded on the way out. Text (locators,
   selectors, configuration keys, `.proto` files) is read by a text-grammar
   codec in the same place.
3. **Concurrency in the seam only.** Every input reaches a machine through
   SCE's inbox and processor door (SCE ADR 0084). No lock or atomic guards
   protocol state; a lock whose only job is to guard it disappears with this
   structure, and what stays is the door.
4. **Lifecycles as explicit events.** A completion, an undeclare order and a
   close are events a machine receives, not the count of an `Arc` or the order
   of `Drop`. The C ABI's semantics today rest on both (S7, S8).
5. **N-version testing.** The Rust and C11 emissions run the same traces, with
   zenoh-pico as the oracle for the preset. The C header is generated from one
   interface description, with its layout pinned.

What this changes in the catalogue of section 4:

- **U4** is answered by a boundary binding (item 2), not by letting a step call
  a codec. The binding reuses the declaration of SCE ADR 0102 §1.3 and the door
  of ADR 0084; the lend-in-place encode W4 and W5 need is decided with it.
- **U2a and U2b** are answered by a text-grammar codec: a format of its own,
  ABNF-like and refusing by rule, not an extension of the content-line encoding.
- **U8** is no longer a request for the language. Its rows move behind a door
  (item 3); the state the lock guarded is classified by what it is, usually U1.
- **U11** is SCE ADR 0109's host operations: random values (D5), a keyed digest,
  HMAC-SHA-256 with its verification (D6), and a key's lifecycle (D7). wz asked
  for SHAKE128 (the initial sequence number) and unkeyed SHA-256 (the credential
  identity) as standard algorithms beside them.
- **U1** is SCE ADR 0108: a statechart holds a table by key as a bounded map,
  and a full table answers `full`.

The order, as the SCE session set it and the owner confirmed it (the boundary
binding before ADR 0100):

1. **ADR 0108 step 6, then step 7.** Step 5, the Rust bounded map and set,
   landed on SCE main on 2026-11-19. Step 6 is C11. At step 7 wz moves its pin,
   once, and U1's rows open.
2. **The literal-shift fix.** `(1 << m)` typed as the literal's width in every
   backend; the keyexpr dynamic programmes carry a local `one` until then.
3. **A freestanding C11 gate.** Every fixture is compiled and linked for a
   Cortex-M target with no host library, with a per-fixture size ratchet and a
   run under qemu. Until it exists, nothing says the C11 emission is a C build.
4. **The boundary-binding ADR, with the lend contract.** U4, W4 and W5.
5. **ADR 0100.** The codec census's L1 to L5: a masked tag, refusal by rule,
   fixed values, value ranges, and where a list ends.
6. **The text-grammar codec ADR.** U2a and U2b.
7. **ADR 0109's C11 lane and SHAKE128.** U11. ADR 0109 builds for Rust and C++
   first (its D0), and opens C11 on wz's request.

Not yet scheduled with the SCE session: U3 (a record that holds a list), U5, U6
and U7 (trees, graphs and pools of instances), U13 and U14, and the four
elements S7 to S10 found: U16 and U17 (a queue's run-time capacity and its full
policy, which the C ABIs' channels need), U18 (a delivery applied inside the
call that posted it, which zenoh-c's contract needs), and U15. U15 is first a
decision for the owner: either a deployment writes its profile as a codec
document in its own repository and generates from it, and its rows become K,
or SCE gains a kind whose input is a layout description. U9 is
U1 once a single deadline is a statechart timer (section 4.2). U10 and U12 are
per preset: on MCU, `ARCHITECTURE.md` §2.3 excludes them, and whether they move
for AP is a decision. P rows are measured one by one when their slice moves.

Of the slices, S7 (the zenoh-pico preset's C ABI on the cooperative engine) and
the MCU rows of S5 and S9 are what the C build reaches first.

## 6. Behaviour a migration must carry

Each slice's Summary lists the rows that hold a deliberate fix. The densest are
S4 rows 19-22, 27-29 and 89-90 (the last-out final gate, the bounded self-echo
queue, sends held until the lock is released, the deregister grace period,
batched writes, writer-first after 10 ms, RCU publish, drain-not-discard, the
control fence behind staged data). A migrated slice keeps the Rust
implementation as its oracle until those rows have a test that judges the
generated form.

## 7. What this census found on the wz side

Recorded here, not changed: this document changes no code.

- **W1.** `sources/algorithms/keyexpr_includes.scxml` and
  `keyexpr_intersect.scxml` compare two `uint32` ids (`entry_id === target_id`).
  Nothing in `out/` is generated from them and no Rust calls them. Wildcard
  matching is hand-written twice: `wz-session-core` `keyexpr_match.rs` and the
  dynamic programs of `wz-zenoh-keyexpr` (S2 row 1, S6 row 1).
- **W2.** `docs/query-answer-path.md:73` names the KeyFacts scan as an SCE
  algorithm, `sources/algorithms/key_facts.scxml`. No such file has existed in
  this repository's history; the scan is hand-written (S2 row 2).
- **W3.** `wz-zenoh-codec` (9,176 lines) is a hand copy of upstream
  `zenoh-codec` and does not read through the generated `out/wz-codecs` (S6).
- **W4.** The cooperative engine's TX lend book re-implements buffer-pool logic
  by hand instead of using the generated `session_tx_pool_mcu` (S5 row C6).
- **W5.** `sources/links/lwip_udp_scout.scxml` and `lwip_udp_session.scxml`
  generate nothing: `out/wz-link-lwip/` holds only buffer pools. The `link` kind
  has not been exercised in wz (S5 row C5).
- **W6.** `multicast_glue.rs:16-17` states SCE has no `<parallel>`; it has
  (section 4.2).
- **W7.** The `_time` grammar is implemented twice (S6 rows 25 and 80).
- **W8.** `vendor/sce/target/release/sce-codegen` on the build machine that ran
  this census was built at SCE `d3db11c4`, thousands of commits before the pin;
  it refuses every codec with an unbounded `tlv-chain`. A measurement must name
  the binary's revision (`sce-codegen --version`).

### 7.1 What has been done about them (2026-11-19, Rounds 4527 and after)

The list above is the census as taken. This list records what changed since.

- **W2, fixed.** The scan is `sources/algorithms/key_facts.scxml`, returning the
  record of `key_facts_schema.scxml`; `KeyFacts::of` calls the generated
  function, held to the hand-written rule by the existing oracle test on both
  backings. `docs/query-answer-path.md` L0 says what was built.
- **W6, fixed in the prose.** The three places that said SCE has no
  `<parallel>` (`multicast_glue.rs`, `multicast_dispatch.rs`,
  `session_fsm_multicast.scxml`) now say that the document keeps Running a leaf
  by choice. Moving the regions into it is S5 row 47, a K row.
- **W8, a hand run, and a defect found beside it.** No wz script runs
  `sce-codegen` without its provenance check, so the census ran the stale binary
  by hand. Reading the check found that the shell gate
  (`scripts/lib/sce-codegen-oracle.sh`) and `scripts/verify-codegen.sh` named
  the binary at `vendor/sce/target/release` while `scripts/build-sce.sh` and the
  Rust door place it by the artifact-root rule: under a `WZ_ARTIFACT_ROOT` the
  gate read a binary the build never wrote. The library now states the place
  once and the two scripts read it. A hand run uses the binary
  `scripts/build-sce.sh` leaves and names its `--version`.
- **W7, fixed.** The grammar, the RFC3339 reader (humantime's, with its three
  refusals), the resolution and the membership test are
  `crates/wz-session-core/src/time_range.rs`, `no_std` and generic over the
  caller's instant type (a `Clock`), so every sum is that type's own checked
  arithmetic. `wz-ext-pubsub` reads it in wall-clock time; `wz-zenoh-util` keeps
  upstream's types and rebuilds upstream's error texts from the grammar's
  refusal, and the E18 differential test against upstream zenoh-util passes on
  every string of its grid and its seeded draws. The two had differed on a fixed
  start with a negative `;` duration (upstream panics): it now moves the start
  back, as upstream moves a `now()` start, and the range holds nothing. In a
  query that form cannot arrive, since a parameter list splits on `;`.
- **W1, fixed.** The keyexpr matcher is SCE documents
  (`sources/algorithms/keyexpr_*.scxml`): intersects, includes and matches
  read the two key texts, a greedy walk with one backtrack frame where `**`
  stands on one side at most, a dynamic programme with `uint64` rows where it
  stands on both. wz-session-core's `keyexpr_match` and the upstream-shaped
  wz-zenoh-keyexpr both answer through it, so S2 row 1 and S6 row 1 are one
  implementation; the uint32 placeholders are gone. The generated relations
  answer what the hand-written descent answered on every pair of one to three
  chunks over every chunk kind, and the E18 differential tests against
  upstream zenoh-keyexpr pass. Every caller holds the key text now (no chunk
  views), and a Put delivered in place costs the growable backing no
  allocation. A host instrument times it at 1.10 of the hand-written descent
  in one process; the kit reading is the next step.
- **W4 and W5, gaps of SCE, not wz edits.** The lend book needs of a pool what
  the `buffer-pool` kind does not state: a slot count fixed at run time, a
  headroom the lender writes before the slot (the stream length prefix), a
  handle rebuilt from the slot index that crosses the link trait, and shared
  (`&self`) access. The `link` kind's Rust form sends a frame by copy
  (`TxFrame<&[u8]>`), where wz's links lend the transmit slot in place. Both are
  candidates for the catalogue of section 4, for the SCE session to judge.
- **W3, open.** Not yet scoped beyond the census row.

### 7.2 What S7 to S10 found (2026-11-20)

Recorded, not changed.

- **W5, in detail.** Generating the two `sources/links/lwip_udp_*.scxml`
  documents as written would not give the hand-written link (S9). Both name the
  transport Frame body as their framer, where a session datagram is a batch of
  whole transport messages and a scouting datagram is a bare scouting message.
  The session document says `block` where the code drops and counts in both
  directions. The documents bind none of the six generated pools the link uses,
  and the `link` kind's Rust form sends by copy where wz lends in place.
- **W9, a race to check.** With `history`, zenoh-c's event listener lists the
  connected faces and only then installs its watch (S8 row 44). A face that
  comes up between the two is reported by neither, and one that goes down there
  is reported up and never down. Not yet compared with upstream's order.
- **W10, a hand copy.** `wz-ap-demo-app`'s `register_bindings` restates the two
  binding rows of the generated sidecar for the dynamic registry (S10 row 29).
- **W11, a divergence from pico.** Where the system gives the cooperative C ABI
  no thread, it panics; zenoh-pico returns `_Z_ERR_SYSTEM_TASK_FAILED` (S7 row
  17).

### 7.3 What S11 and S12 found (2026-11-20)

Recorded, not changed.

- **W12, two counter rules.** The end-to-end stream sender's
  `Rollover::Wrap` returns to 0 and the segment sender's `Rollover::Restart`
  returns to its first value; both are hand-written beside each other (S11,
  S10 row 8). The receiver's step and verdict are generated
  (`e2e_counter_step.scxml`, `e2e_counter_verdict.scxml`, S11 row 7), so the
  judge S10 row 2 read as hand-written now calls them for that part.
- **W13, the catalogue three times.** A deployment's message catalogue is
  stated as a JSON schema, generated into static tables by
  `scripts/lib/message_catalog.py`, and read again by the Rust reader
  (`crates/wz-app-frame/src/message_catalog.rs`); SCE generates none of the
  three (S11).
- **W14, a stale count.** `xtask regen` says it emits "12 statecharts + 2
  algorithms" (`xtask/src/main.rs:556`); it emits 13 statecharts and 24
  algorithms (S11).
- **W15, callbacks under a door's lock.** The stream supervisor's loss callback
  and the replay subscriber's delivery run inside the C door's own lock, where
  the engine never runs a C callback under its lock (S7 row 6). Both doors
  state it as their contract (S12 rows 13 and 41).

## 8. Open points

- U4 rests on the absence of any text that lets an algorithm call a codec. If
  such a call exists, U4's rows move to K.
- S6: whether one algorithm may call another that takes a `bytes` parameter,
  and whether `lookup` accepts a text key for a closed set (row 48), were not
  settled.
- S3 rows 34, 51 and 53, and S6 keyexpr rows, are K only once a bound on the
  text length is declared.
- The classification of the analyzer (`wz-capture` and the crates that follow
  it, `docs/zenoh-logic-as-sce-kinds/crates.md`) is outside this census.
  `wz-tls-record` is classified in S9 although it is the analyzer's.
- U3's rows in S1 and S4 were read with a `bytes` field refused. SCE accepts a
  bounded one, so the rows whose record holds bytes and no list are to be
  re-read; some move to K.
- S9 reads the chip drivers' protocols (bring-up, PHY negotiation, OA-TC6;
  about 2.4k lines) as K. If a whole chip driver is read as seam, they are S.
- S8 row 37: zenoh-c's FIFO channel is K only if the producer's end of stream
  travels as a queue element; the `queue` kind states no close.
- S12 rows 18-23 (the runtimes' links over a C program's stack) are S as link
  seams; if a link adapter's decisions are protocol, they are K. S12 row 4 is K
  only once the writable counter moves into `app_link.scxml`.
- S11 reads a `.proto` schema handed over at run time as U15 and its wire
  decode (row 26) as part of this census, although a fixed protobuf layout
  would be codec layout; it follows U15's owner decision.

## 9. How much reaches C11 today

Measured on the tree of 2026-11-20 (`main` `d8e96f368`). The SCE sources under
`sources/` number 123:

| Sources | Count | Emitted as C11 by a wz lane |
|---|---|---|
| Codecs (`sources/codecs/`) | 65 | Emitted; Layer B checks the emit exits 0 and writes a file |
| Algorithms (`sources/algorithms/`) | 32 | Emitted, as the codecs |
| Statecharts (`sources/session/` 7, `reassembly_slot`) | 8 | No |
| Buffer pools (`sources/network/*_pool_*`) | 13 | No |
| Links (`sources/links/`) | 2 | No; the Rust form is not generated either (W5) |
| Event schemas (`hello_received_schema`, `fragment_chunk_schema`) | 2 | No |
| Feature manifest (`sources/features/`) | 1 | No |

The emitted C11 is not compiled, linked or run by any lane:
`scripts/verify-codegen.sh` emits it, and its Layer 1 judges that the emit
succeeded. `out/` holds Rust only (117 files). The zenoh-pico preset's C ABI
(`wz-capi-pico` on `wz-capi-coop`) is Rust compiled to a library, and none of
its protocol behaviour runs through a C11 emission. The freestanding gate of
section 5, step 3, is what turns the second column into a claim about a C
build.
