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

About 369k production lines of hand-written Rust were classified. 4.6k already
run through generated SCE code (A), 56k are expressible with a kind SCE has
today (K), and 150k are blocked (G). The rest is platform seam (S, 52k),
diagnostics (D, 30k) and glue (X, 76k), which do not move or move by a separate
decision.

The blocked lines do not need 150k lines' worth of new language. They meet a
small set of missing elements, and one of them dominates: a machine cannot own a
table keyed by a runtime value (U1, 97 rows in all six slices). After it come
shared state with a stated memory ordering (U8, 39 rows), unbounded data (U10,
32 rows), in-flight request tables (U9, 24 rows, most of which reduce to U1),
text as data (U2, 27 rows), and recursive data (U5, 17 rows).

So the first SCE change is the one SCE itself names as the reopener of a
refused construct: letting a statechart hold a `bounded-collection`
(`docs/SCE_ACCEPTED_SUBSET.md`, the paragraph on an algorithm looping over a
bounded-collection import), with lookup by key.

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

- **Not classified.** The analyzer (`wz-capture`, about 89k production lines),
  whose place in the migration is a separate decision; the C ABI crates
  (`wz-capi-*`, about 58k), which a C build re-implements or generates rather
  than migrates; test code and `#[cfg(test)]` modules; codec layout.
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
| A | 4,612 | 1 % |
| K | 56,133 | 15 % |
| G | 150,061 | 41 % |
| S | 51,851 | 14 % |
| D | 30,471 | 8 % |
| X | 75,940 | 21 % |
| Total | 369,068 | |

| Slice | A | K | G | S | D | X |
|---|---|---|---|---|---|---|
| S1 | 45 | 10,871 | 40,472 | 6,581 | 2,697 | 10,424 |
| S2 | 0 | 7,006 | 9,049 | 1,662 | 463 | 3,368 |
| S3 | 184 | 4,174 | 4,058 | 281 | 16,588 | 9,035 |
| S4 | 3,513 | 5,352 | 46,356 | 6,609 | 4,610 | 9,431 |
| S5 | 870 | 11,800 | 24,180 | 30,100 | 980 | 9,750 |
| S6 | 0 | 16,930 | 25,946 | 6,618 | 5,133 | 33,932 |

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
| U1 | A table keyed by a runtime value (id, zid, keyexpr, name) that a machine owns and mutates: bind, replace, unbind, lookup by key, a counted refusal when full | 97 (S1 12, S2 18, S3 1, S4 34, S5 14, S6 18) | a `sce-static` statechart has no bounded-collection variable; statechart `list<T>` variables append, clear and read by index only; `bounded-collection` addresses entries by handle |
| U2a | Text as data: parse, produce, slice and compare texts (locators, keys, selectors, ACL subjects) | 23 (S1 8, S6 15) | a record's string has one write and one comparison; `list<T>` refuses a string element |
| U2b | A table keyed by a text | 4 (S5) | a lookup keyed by a text is refused |
| U3 | A record or list element that holds bytes, a list or a collection | 13 (S1 5, S4 8) | a record's fields are fixed-width numbers, `bool`, `enum:` or a bounded string; a `bytes` field is refused |
| U4 | A statechart or algorithm step that encodes or decodes a codec value and branches on the result | 10 (S1 9, S3 1) | calls are defined between algorithms only; no text lets an algorithm call a codec |
| U5 | Recursive data: keyexpr trie, JSON5 value tree, persistent-map trie, shm `AllocPolicy` tree | 17 (S3 1, S4 3, S5 6, S6 7) | no tree kind exists; `docs/rfc-sce-protocol-synthesis.md` §5.H deferred it |
| U6 | A general graph: shortest-path trees, reachability, removal of detached nodes | 7 (S4) | no kind holds a graph |
| U7 | A bounded pool of statechart instances routed by a runtime key | 4 (S1) | the reassembly, multicast and peer-table routers stay in Rust for this |
| U8 | State shared across execution contexts with a stated memory ordering: locks, RCU snapshots, atomics protocols, fences between lanes | 39 (S1 7, S2 1, S4 20, S5 6, S6 5) | `queue` and `broadcast-log` state their guarantee for their own element only; no `sce:extern` for atomics or fences |
| U9 | Many requests in flight, each with its own deadline and cancellation; executor `select` loops | 24 (S1 2, S4 14, S5 2, S6 6) | see 4.2: a single deadline is expressible; the table of in-flight requests is U1 |
| U10 | Unbounded data: growable buffers, payload arenas, caches, reorder buffers | 32 (S2 2, S3 1, S4 10, S5 11, S6 8) | AP may hold it; on MCU it is a permanent constraint (`ARCHITECTURE.md` §2.3) |
| U11 | A value-returning host or library function inside a step: HMAC, SHAKE/keccak, lz4, RSA, xxh3, SipHash, RFC 3339, float formatting | 15 (S1 6, S3 1, S4 2, S5 1, S6 5) | only a procedure's `<sce:helper>` returns a host value; `sce:extern` is absent |
| U12 | A JSON / JSON5 document used as data (configuration, admin replies) | 10 (S5) | no codec encoding is JSON; `text-template` has no list or record hole |
| U13 | A step that reads a value another component computed in the same macrostep (Q), or a host effect per element of a collection (I) | 5 (S3) | `<sce:action>` returns only whether it ran; `<sce:action>` inside `<foreach>` is refused |
| U14 | A document generic over the application's types | 1 (S3) | `docs/rfc-sce-protocol-synthesis.md` §5.G deferred it |
| P | Expressible, but the generated form would break a measured or stated performance property | 19 (S1 2, S2 7, S3 1, S4 7, S5 1, S6 1) | each row cites the measurement or `docs/query-answer-path.md` |
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

## 5. Order of the SCE work

The order follows the rows each element unblocks and the C11 build that the
migration is for.

1. **U1: a statechart holds a `bounded-collection`, addressed by key.** 97
   rows. SCE already names this change as the one that reopens the refused loop
   of an algorithm over a bounded-collection import. A full table's refusal is
   counted, as wz counts it now.
2. **U3 and U2: composite records and bounded text.** Extension chains,
   locators, selectors and the ACL decision need a record that holds bytes and
   lists, bounded text operations, and a text key. The ACL logic itself is
   already what `sce:std/acl/acl_granted` expresses (S6 row 92); it is blocked
   only by the keyexpr text it matches.
3. **U4: a step that calls a codec.** With it, S1 rows 10 and 26 become K, and
   the host stops being the only caller of the generated codecs.
4. **U5, U6, U7: trees, graphs, instance pools.** The keyexpr trie and the
   router's link-state graph. `docs/rfc-sce-protocol-synthesis.md` §5.H is the
   place this was deferred.
5. **U8 and U11: memory ordering and host functions.** Either the
   `sce:extern` of the RFC (§5.I) or a stated ordering on `queue` /
   `broadcast-log` plus a typed host-function call. Until then these rows stay
   host-side, inside the seam.
6. **U10, U12, U14: per preset.** Unbounded data and JSON are AP concerns; on
   MCU they are excluded by `ARCHITECTURE.md` §2.3. Whether they move for AP is a
   decision, not a missing element.
7. **P rows** are measured one by one when their slice moves; the query answer
   path is hand-written on purpose (`docs/query-answer-path.md`).

Of the slices, S5's MCU and cooperative-engine rows are the first a C11 build
reaches: they use the MCU-class kinds (`link`, `buffer-pool`, `worker`,
`queue`) that SCE emits for Rust and C11 only.

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

### 7.1 What has been done about them (2026-11-19)

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
- **W7, open.** One implementation of the grammar belongs with the other
  selector parameters in `wz-session-core` (`selector_params.rs` holds the
  `_time` name), which is `no_std`, so the instant is held as seconds and
  nanoseconds and resolved against a `now` the caller gives;
  `wz-ext-pubsub` and the upstream-shaped `wz-zenoh-util` type read through it.
  The two differ today on a fixed start with a negative `;` duration
  (`wz-zenoh-util` accepts it with an end before the start, `wz-ext-pubsub`
  refuses it, upstream panics).
- **W1, open.** S2 row 1 and S6 row 1 are K: the matcher becomes an algorithm
  over chunk offsets with a bottom-up table. Its frames are under the stack gate
  and it is on the query path the kit measures, so it lands with those readings.
- **W4 and W5, gaps of SCE, not wz edits.** The lend book needs of a pool what
  the `buffer-pool` kind does not state: a slot count fixed at run time, a
  headroom the lender writes before the slot (the stream length prefix), a
  handle rebuilt from the slot index that crosses the link trait, and shared
  (`&self`) access. The `link` kind's Rust form sends a frame by copy
  (`TxFrame<&[u8]>`), where wz's links lend the transmit slot in place. Both are
  candidates for the catalogue of section 4, for the SCE session to judge.
- **W3, open.** Not yet scoped beyond the census row.

## 8. Open points

- U4 rests on the absence of any text that lets an algorithm call a codec. If
  such a call exists, U4's rows move to K.
- S6: whether one algorithm may call another that takes a `bytes` parameter,
  and whether `lookup` accepts a text key for a closed set (row 48), were not
  settled.
- S3 rows 34, 51 and 53, and S6 keyexpr rows, are K only once a bound on the
  text length is declared.
- The classification of the analyzer (`wz-capture`) and of the C ABI crates is
  outside this census.
