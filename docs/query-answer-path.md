# The query answer path: decided once, walked once, copied once

Status: design, 2026-10-27. Nothing below is built except S0. Owner order the same day: the
longest-lived, textbook structure, cost ignored, Kconfig and SCE used actively.

## 1. The question, measured

The fixed client answers a GET about 14 us slower than single-threaded pico on the T2G kit (CYT4BF,
Cortex-M7 at 350 MHz): turnaround ratio 1.062 in `deploy/upstream_parity.json`, a loss. Three
explanations were tried and refuted with the kit before this design:

- The idle pass sleeps a tick: `CONFIG_WZ_IDLE_WAIT_MS=1000` left the turnaround at 0.215 ms.
- The polling path falls out of the instruction cache: placing it in the ITCM steadied the batching
  client's GET median and moved the turnaround at the wire by nothing (section 5.8 of
  `docs/storage-policy-and-link-layer.md`).
- The 64-bit tick division: removed (S0), 3% of the application's time, not the gap.

The cycle-counter stamps of the zeth driver (`CONFIG_WZ_ZETH_STAMPS`, the same instrument for wz
and pico) split the software round trip, mean us over 500-query lines that agree to 0.1 us:

| gap | wz fixed | pico single-threaded |
|---|---|---|
| rx to recvfrom (stack receive path) | 30.7 | 33.1 |
| recvfrom to sendto (the application) | 53.2 | 45.6 |
| sendto to wire (stack send path) | 45.4 | 45.7 |
| rx to tx | 129.4 | 124.3 |

The gap is the application's part: 7.6 us. A program-counter profile taken by the firmware
between recvfrom and sendto (400 samples, +-5%) puts the wz time in: reply staging and copies
20% (`ReplyStage::stage_parts` 10.8, `memcpy` 8.8), key-expression matching 17%
(`keyexpr_intersects_text`, `memchr`, `from_utf8`, `memcmp`, `has_star`), extension walking 13%
(`ExtEntryView::decode_into`, `read_z64_of`), the VLE reader 8%, a 64-bit division 3%.

## 2. Why the code does this (the read of the path)

The path is hand-written from the datagram to the send, and runs no SCE microstep per query
(`process_event` runs for role activation, deadlines and errors only). SCE generates the codecs
(`sources/codecs/*.scxml` to `out/wz-codecs/`) and the session machine. What the path does per
query that was already known:

1. **The key is checked again and again.** `from_utf8` at the decode (`out/wz-codecs/wireexpr_local.rs`
   line 93) and again at `row_parts` (`reply_stage.rs` line 384); `Queryable::matches` runs
   `has_star` on the candidate and on the target and `text_is_a_key` on a match; `admit` repeats the
   compare, `has_star` and `text_is_a_key` for the reply's key against the query's. For the kit's
   two keys (34 and 26 bytes) nothing here can change between queries.
2. **The request's extensions are decoded and then walked again** by `has_sliced_value`,
   `read_target_of`, `read_qos_of` (twice, the Final asks again): each walk re-decodes the list.
3. **A reply is staged to be sent.** The key and the payload are copied into the stage's arena
   (97 and 98 bytes), a `Row` of spans is pushed, and the drain reads it back to encode it into the
   transmit slot. The stage exists for replies that are given later or from elsewhere; a document
   answered inside the dispatch, with bytes that are constants, needs none of it.
4. **The event is fanned to every table** (`dispatch_event_among`), though a Request concerns the
   queryable table only.

## 3. Principles

- **P1. Parse, do not validate.** A fact established at a boundary is kept in a type that proves
  it, and nothing downstream asks again. A key that has been checked is a different type from text.
- **P2. Decide at declare time what is known at declare time.** A queryable's key does not change
  after it is declared: its length, wildness and validity are computed once.
- **P3. One pass over the input.** The request's extension list is folded once into the facts every
  later step reads.
- **P4. One copy of the payload.** Constant bytes go from where they lie to the transmit slot.
- **P5. Every lever is a switch, and the original is a preset.** Each change below is a Kconfig
  symbol that selects a cargo feature or a generated artifact; with it off, the build is today's.
  The zenoh-pico-equivalent presets keep the levers off and are measured against pico as before; a
  lever is on in the MCU preset only when the kit measures it faster (apply every measured gain,
  refuse an unmeasured one).

## 4. Structure

**L0. `CheckedKey` and `KeyFacts` (P1, P2).** `KeyFacts { len, wild, canonical }` is computed in one
scan fused with the UTF-8 check. The scan is an SCE algorithm (`sources/algorithms/key_facts.scxml`,
`sce:kind="algorithm"`), so the Rust, the C drop-in and the tokio runtime run the same generated
definition and the cross-language byte-equivalence gate (RFC A6) already applied to the repository's
other algorithms covers it. A queryable holds the facts of its pattern from `install_entities`; the
decode of a Request returns a `CheckedKey<'_>`; `Queryable::matches` and `admit` take two
`CheckedKey`s, compare lengths, then bytes, and walk chunks only when a fact says wild. The two
`from_utf8` calls, the `has_star` scans and the `text_is_a_key` scans of section 2 item 1 go.
Switch: `CONFIG_WZ_KEY_FACTS` selects cargo feature `key-facts`; off, the matcher is today's.

**L1. One fold of the extensions (P3).** `RequestFacts { sliced_value, target, qos, .. }` is built
by one walk during decode. The right place is the codec generator: an SCXML codec declares the
fields of a list that a fold keeps, and SCE emits the fold beside the view. That is a request to
scxml-core-engine. Until it lands the fold is hand-written at the single call site
(`dispatch_request_in_place`) behind the same switch, and is replaced by the generated one without
a change to its callers. Switch: `CONFIG_WZ_REQUEST_FACTS`, feature `request-facts`.

**L2. A declared document is a constant (P2, P4).** The node's documents are `const`s
(`STATUS_KEY`, `CONFIG_KEY`, their bodies: `deploy/zephyr-admin-node/rust/src/lib.rs`,
`DOCUMENTS` in `fixed_client.rs`). A queryable of kind `Static { key, encoding, body }` is held in
the registry with its facts and answers without a sink closure. The declaration of such documents
comes from `deploy/wz-config.toml`, and `wz_config.py` emits the const table beside
`caps_generated.rs`, which is how the limits already reach the code from `deploy/Kconfig.limits`.
Switch: `CONFIG_WZ_STATIC_QUERYABLES`, feature `static-queryables`.

**L3. A direct reply (P4).** A `Static` queryable answered inside the dispatch encodes its
`Response` straight into the transmit slot with the borrowed key and body; the stage, its arena, the
`Row` and the drain are used for replies that are deferred or owned and are unchanged. The
`Final` keeps its place by the existing burst (`begin_burst`/`end_burst`). The behavior-preserving
test is byte identity: the datagrams of the direct path equal those of the staged path for every
query of the capture corpus and of the kit's two documents, with and without batching. This
removes the 20% of section 1. Switch: `CONFIG_WZ_DIRECT_REPLY`, feature `direct-reply`, which
requires `static-queryables` (a `compile_error!` guard, and a Kconfig `depends on`).

**L4. Events go to the tables that want them.** A Request reaches the queryable table only, by a
`const` mask of the tables a build has. The set of tables is the set of capabilities the build
carries, already derived from `deploy/wz-config.toml` into cargo features; the SCE feature model
(`sources/features/`) names the same features for the machines. The query path has no state
machine, so no `sce:requires` gate is claimed for it: the gate is the cargo feature set. Switch:
none of its own; a build that has no subscriber table does not visit it.

**What SCE is used for, and what is asked of it.** (a) L0's scan as a generated algorithm;
(b) L1's fold as a codec feature, to be requested; (c) the gating of states and transitions of the
session machine by `sce:requires`, which exists for the accept path since d809de495 and is
extended by step K2 of `docs/upstream-parity.md`, not by this design. What Kconfig is used for: one
symbol per lever, each documented with its measurement table, as `WZ_POLL_PATH_IN_ITCM` is.

## 5. Order, and what each step must show

| step | lever | expected effect on recvfrom to sendto | cost |
|---|---|---|---|
| S0 | tick division as a multiplication (done, `b08400acd`) | about 1 us, text -216 B | none |
| S1 | L0 key facts | up to 17% of 53 us | one generated algorithm, one type |
| S2 | L3 with L2 | up to 20% | the static kind, the direct encoder |
| S3 | L1 fold | up to 13% | needs SCE |
| S4 | L4 mask | small | a const |

Each step reports the same four numbers before it is kept, from the same instrument: the stamps'
recvfrom to sendto mean (500-query lines), the text of the three fixed images, the stack gate, and
the matrix turnaround cell against single-threaded pico. A step that does not move the stamps is
not kept. The target is recvfrom to sendto at or under pico's 45.6 us, which makes the software
round trip about 116 us against pico's 124. About 9 us of the turnaround at the wire lies outside
what the stamps see (the MAC's DMA and the host's capture), so a tie of the turnaround cell is not
promised by this design; it is promised that the application's part stops being the loss.

## 6. Not decided here

- Whether `Static` answers are wanted by the host nodes: the lever is MCU-first, and the host
  presets keep it off until measured.
- The size of a `Row` (not measured): if it is large, the cost of S2 is partly a move of that
  struct, and a smaller row would help the staged path for every build.
- Whether the router sends the key with id 0 (a composed key copies into `KeyexprBuf`, up to
  256 bytes): read from a capture before S1.
