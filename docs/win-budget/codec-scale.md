# Codec scale: why the wire codec grows with each feature, and the structure that does not

Status: diagnosis and design, 2026-11-28. Step W1 is implemented with this note; every other step
is designed and not implemented. The readings are the size ledger's (`scripts/lib/size_ledger_gate.py`,
Layer C1cs): its `--explain` reports of `pico-client-coop-nostd`, `pico-peer-coop` and
`pico-api-coop-nostd` (the Linux twin of the Windows release's like-for-like library) on the
integration tree `cbc0f6ecb3` (2026-11-28), and its `--per-feature` report of 2026-11-27 (read before
`6b0c6278f7`, the reply's direct layout, landed). The ledger's rows (`deploy/size_ledger.json`) give
the codec area 31,798 against 35,440 in the client (won) and 77,975 against 36,707 in the api twin
(2.12); the reports below read 28,180 and 77,953, within a day's moves of those rows.

## 1. The readings

### 1.1 Three bundles, both sides

| case | wz codec | zenoh-pico codec | ratio |
|---|---:|---:|---:|
| `pico-client-coop-nostd` | 28,180 | 35,440 | 0.80 |
| `pico-peer-coop` | 33,099 | 35,547 | 0.93 |
| `pico-api-coop-nostd` | 77,953 | 36,707 | 2.12 |

### 1.2 Feature by feature (`--per-feature`, 2026-11-27)

What each feature added to the codec area on each side, stepping from the client's features
(`os-host`, `link-udp`) one feature at a time to the api twin's:

| step | wz added | zenoh-pico added | wz after | zenoh-pico after |
|---|---:|---:|---:|---:|
| (client) | | | 28,360 | 35,440 |
| `scout` | +3,766 | +107 | 32,126 | 35,547 |
| `peer` | +3,576 | 0 | 35,702 | 35,547 |
| `multicast-transport` | +31,117 | +24 | 66,819 | 35,571 |
| `query` | +22,552 | +86 | 89,371 | 35,657 |
| `queryable` | +15,146 | +29 | 104,517 | 35,686 |
| `liveliness` | +4,492 | +196 | 109,009 | 35,882 |
| `liveliness-get` | +23 | 0 | 109,032 | 35,882 |
| `advanced` | +910 | +684 | 109,942 | 36,566 |
| `connectivity` | +13 | +134 | 109,955 | 36,700 |
| `multi-thread` | +2 | +7 | 109,957 | 36,707 |

Between that report and the explain of 1.1 the api twin's codec fell from 109,957 to 77,953. The
commits between the two include the reply and the get written and counted by their direct layout
(`6b0c6278f7`) and a group's items written by one writer (`daf97fb722`, `b106f42e6a`); which of
them took how much was not read apart. The files that fell most are the runtime's `bounded.rs`
(-4,786) and `codec.rs` (-3,980), `ext_view.rs` (-3,049) and the generated put, entry, reply and
response. The step table's shape is what this note reads; its numbers are the main
session's to read again at `df994d7913` (the report it is drawing), and section 6's estimates move
with them.

## 2. Why one side grows and the other does not

zenoh-pico compiles the encoder and the decoder of every message in every build: its codec area is
35,440 bytes in the client and 36,707 in the full library, 3.6 percent more, because its switches
(`Z_FEATURE_*`) gate the session's code, not `src/protocol/codec*`. wz compiles a message's codec
only where a feature reads or sends it (`wz-codecs`' `codec-*` features, the session's `rx-*` and
`tx-*`), so its codec grows with its features by construction, and the client's win is that:
it holds fewer kinds than zenoh-pico does.

So the question is not that the codec grows; it is what a kind costs. The api twin is the bundle in
which both sides hold the same kinds, and there a kind costs wz 2.12 times what it costs zenoh-pico.

### 2.1 By kind of message, the api twin

wz's bytes by the source file they are in (each byte goes to the file its line names, as the ledger
places it), grouped by the kind of message the file is the codec of; zenoh-pico's by the functions'
names. The runtime row is wz's only: zenoh-pico's helpers are functions of their own, in the
`shared fields` and `extensions` rows.

| kind | wz | zenoh-pico | ratio |
|---|---:|---:|---:|
| the forge runtime, inlined at each field (`vendor/sce/backends/rust/forge-runtime`) | 24,323 | (in the rows below) | |
| declarations (generated 7,696, `lent_control` 1,863) | 9,559 | 4,175 | 2.29 |
| transport (generated 5,611, `inbound`'s in-place reader 3,555) | 9,166 | 6,799 | 1.35 |
| reply, err, response final (generated and `lent_response`) | 8,277 | 3,771 | 2.19 |
| extensions (entries, zint, zbuf, `ext_view`, `ext_chain`) | 5,742 | 1,459 | 3.94 |
| data: push, put, del (generated, `push_read`, `lent_push`) | 4,676 | 4,015 | 1.16 |
| query, request (generated and `lent_request`) | 4,598 | 4,878 | 0.94 |
| shared fields: wireexpr, encoding, timestamp, zbuf, VLE | 3,184 | 4,989 | 0.64 |
| the envelope's dispatch (`network_message`, `pull`) | 3,140 | 1,996 | 1.57 |
| bytes of no source line | 3,054 | | |
| scouting | 1,039 | 2,175 | 0.48 |
| interest | 816 | 877 | 0.93 |
| OAM | 379 | 974 | 0.39 |
| other | | 599 | |
| total | 77,953 | 36,707 | 2.12 |

zenoh-pico's 36,707 holds 10,942 bytes of constructors, copies and clears
(`src/protocol/definitions`, `_z_n_msg_make_*`, `_z_*_copy`, `_z_*_clear`) that wz has no
counterpart of in this area; its encoders are 10,507 bytes and its decoders 13,707.

### 2.2 By form, the three bundles

Each body's codec bytes, by what the body is (its symbol):

| form | client | peer | api | api - client |
|---|---:|---:|---:|---:|
| F1 a generated view's decode, out of line | 589 | 1,440 | 7,008 | +6,419 |
| F2 a generated owned decode (`read_into`) | 2,528 | 3,065 | 3,596 | +1,068 |
| F3 wz's in-place readers and the envelope's dispatch, with the generated reads inlined | 14,911 | 15,043 | 22,035 | +7,124 |
| F4 a generated encoder (`write_source`, `write_parts_in`) | 1,573 | 1,596 | 4,907 | +3,334 |
| F5 wz's direct writers (`lent_*`, `frame_encode`, `handshake_encode`, the send closures) | 5,111 | 5,776 | 22,558 | +17,447 |
| F6 a count of a message beside its write (`direct_len`, `encoded_len`, `measured`) | 0 | 0 | 4,142 | +4,142 |
| F7 the runtime's own bodies, out of line | 1,319 | 1,511 | 2,270 | +951 |
| F8 codec code inlined into a body of another area (the scout window, a group's records) | 2,149 | 4,668 | 11,437 | +9,288 |
| total | 28,180 | 33,099 | 77,953 | +49,773 |

The send side (F4 to F6) is 31.6 KB of the api twin against zenoh-pico's 10.5 KB of encoders; the
receive side (F1 to F3) is 32.6 KB against 13.7 KB of decoders. About 15 KB of the api twin's
codec bytes (47 bodies) are in the group path's bodies: its own writers (`multicast_tx`, the
stage's), its record reader (`MemberRecords::record`, `MulticastPump::step_reading`) and the join.

## 3. Same work, and the same rule printed again

The same work is what a kind's own fields cost once: zenoh-pico's encoder and decoder of the kind is
the yardstick, since it pays them in every build. What is printed again is a rule of the wire
(read a ZInt, read an extension entry, write a declaration's envelope) compiled once more for each
place it is written at. The table says which, where it is made, and how much it holds; the bytes are
the api twin's.

| | shape | where it is made | bytes | evidence |
|---|---|---|---:|---|
| R1 | the runtime's read or write of one field, printed at every field of every codec | the generator's output and the forge runtime | about 21,000 of 24,323 | `reader.rs` lines in 57 bodies, `codec.rs` in 39, `bounded.rs` in 65, `storage.rs` in 26, `view.rs` in 25; by function (`objdump -d -l --inlines` of the same build): `SceReader::take_array::<1>` in 25 bodies, `read_vle_u64` in 30, the extension walk's `next` in 13, `SliceSink::put::<1>` in 10, `Bounded::next` in 11, `from_fitting::<16>` and `from_slice::<16>` in 8. zenoh-pico: `_z_zint64_decode` (202) and `_z_msg_ext_decode_iter` (165), called |
| R2 | an extension chain read per kind: a chain rule type per chain, the entry read in 29 bodies, and wz's own readers of the same entries beside it | the generator (ADR 0136's amendment made the rule a type) and `ext_view.rs` (2,432), `ext_chain.rs` (622), `ext_admit::judge_entry` (535) | about 4,300 of 5,742 | extensions 3.94 times zenoh-pico's |
| R3 | kinds of one layout compiled apart | the documents (`sources/codecs/decl_{subscriber,queryable,token}.scxml`, the four `undecl_*`) | about 1,500 | the three generated declaration files differ in names only; `DeclQueryableWire::write_source` and `DeclTokenWire::write_source` are 286 bytes each, both linked. zenoh-pico: `_z_decl_commons_encode`, `_z_undecl_trivial_decode` |
| R4 | a send that builds the lent `Declare` and encodes it through the walk over all nine kinds of declaration | wz: the token reply (`declare::local_token::build_token_reply` encoded at four sites) | about 2,700 | `multicast_tx_token_reply`'s writer 2,229, `send_declare_token_reply`'s 493; every other declaration is sent through `lent_control::DeclarationOf`, its kind's writer alone |
| R5 | a kind's layout written by hand beside the generated encoder of the same kind | wz: `lent_response` (6,376), `lent_request` (2,843), `frame_encode` (2,711), `lent_control` (1,863), `lent_push` (1,468), `handshake_encode` (742) | about 8,000 | the generated reply encoder is kept as the tests' reference (`lent_response::reference`); the hand layouts are each one kind's, which is the same work, and they stand beside a generated writer still linked for other paths |
| R6 | a count of a message beside its write | wz: `ResponseWriter::direct_len` (1,711) and `direct_bounds` (396), `RequestWriter::encoded_len` (939), `checked_body` (648), `measured` (448) | 4,142 | the layout is spelled twice, once summed and once stored; `encode_tx` already writes into the buffer's whole room with no count where the buffer has an end (`TxBuf::reserve_rest`) |
| R7 | two decoders of one kind: the generated view and the owned read, and wz's in-place reader | the set's options (`views` beside the owned form) and `inbound.rs` (3,555), `push_read.rs` (2,234) | about 2,500 | the join read as `JoinIn::read_into` (531), `TransportJoinView::decode` (381) and `join_decode` (146); the extension entry and the wire expression as both forms |
| R8 | the group's own transmit and receive path beside the link's | wz: `multicast_tx`, `multicast_dispatch`, `wz-session-mcu`'s `group_drive` | part of about 15,000 | the `multicast-transport` step added 31,117 bytes of codec against zenoh-pico's 24; `docs/c-abi-migration/mcast-tx1.md` designs one transmit path for a group and a link |

F8's 11,437 bytes are a placement, not a copy by themselves: a body read from one site is inlined
there (SCE ADR 0137), and the bytes are counted where they land. They are a copy where the same
body is also inlined elsewhere; R1 to R8 count those.

So of the api twin's 77,953 bytes, roughly 40 KB are the same work (zenoh-pico's 36,707 less its
constructors and clears, plus one out-of-line copy of wz's runtime, about 3 KB, plus wz's
admission and routing reads that zenoh-pico does not make) and roughly 38 KB are rules printed
again. The split is an estimate from the readings, not a measurement; each step of section 6 names
the reading that measures its share.

## 4. The structure that does not grow

A textbook wire codec states each message's layout once and keeps the compiled forms of a rule to
the places where the time it saves is spent:

- **S-ONE. One statement of a layout.** A kind's layout is its document (`sources/codecs`); every
  read and every write of the kind an image holds is generated from it. No layout is written by
  hand, and no kind is counted by a second spelling of it.
- **S-DATA. A kind is data.** A cold kind is a static table of its fields, read by one walker and
  written by one walker, each one function for every table, out of line and generic over nothing.
  A new kind costs a table, not a body. This is SCE ADR 0135's shape for a document of the static
  class, the table-driven parsers of the protobuf family, and nanopb's descriptors.
- **S-HOT. The hot path is printed.** The codecs a received data message is read through, and the
  put's write, keep the straight-line bodies the generator prints today, from the same document
  (SCE ADRs 0139 and 0140: the build names the hot roots and their reads are hot by their sites).
  No hot read calls the table walker.
- **S-TLV. One extension body.** An extension is one TLV entry (identifier, mandatory bit, unit,
  ZInt or ZBuf, the chain bit), read and written by one function; a kind's extensions are a table of
  its known identifiers (the slot each is held in, or the refusal of a mandatory one it does not
  know). A hot kind reads its few identifiers in place.
- **S-ONCE. A message is written once.** A send writes into the room the buffer has and rolls back
  on a short write (`TxBuf::reserve_rest`, `truncate`); where a length must be asked of a link
  before the write, the count is the one writer run over a counting sink (`CountTxBuf`), never a
  second layout.
- **S-KIND. A send names its kind.** A sender writes the declaration of the kind it sends
  (`DeclarationOf`), so an image holds the writers of the kinds it sends; a layout shared by kinds
  is one table (S-DATA) whatever the kinds' names.

## 5. The boundary of the receive Ir

The receive window (`docs/win-budget/ir-receive.md`) reads 4,836.7 instructions a received put on
wz against 4,042.4 on zenoh-pico (1.20), and no step here may raise it. The rule that holds it: the
table walker reads no codec a received data message is read through. Those are the hot roots
`xtask/src/main.rs` names (`HOT_DECODE_CODECS`: the transport frame header, the frame and the push)
and every codec their bodies read by ADR 0140's sites (the put, the del, the extension entry and its
unit, ZInt and ZBuf bodies, the timestamp, the encoding, the wire expression); the query plane's
per-reply reads (the response, the reply, the request, the query) are held hot too, since the get's
row of `docs/win-budget/ir-send-query.md` is per operation and reads one reply each. Every other
codec is read once per entity, session or link event: a declaration, an interest, an OAM, the
handshake, a join, a close, a keep-alive, a scout and its hello, a response final.

Why the boundary is there and not elsewhere: SCE ADR 0138 measured that inlining one field's read
bought 5.4 instructions a message and cost about 1.6 KB of image, and ADR 0140 that naming the hot
set took the receive back to its baseline from +22 while a hot attribute put on a codec instead of
its sites copied hot bodies into the cold ones. A table walker's cost is a few instructions a field
(the row's load, the match on its kind, the store), which is nothing per entity and too much per
message.

What holds it: a generator test that no hot codec's body calls the walker (the proposal), and the
receive window row of the perf matrix, read after each step that regenerates the codecs.

## 6. Steps

Bytes are estimates for the codec area (`client`, `peer`, `api`: the three ledger cases) from the
readings of section 1; the main session's reading after each step is the measurement.

| step | side | change | client | peer | api | receive Ir | turns red |
|---|---|---|---:|---:|---:|---|---|
| **W1 (this note)** | wz | the token reply is written as a declaration of its one kind (`lent_control::token_reply_declaration`, a `DeclarationOf<DeclToken>` with no chain), at the sends of the link that encoded the lent `Declare` of every kind (the session's with no allocator and its lend-only form, and the count with no allocator); the group's writer writes the same declaration since the group's step T2 (`docs/c-abi-migration/mcast-tx1.md`) | 0 | 0 | -0.2 to -0.5 KB (the link's part of R4; the group's part is T2's) | none: a send | `lent_control::tests::a_token_reply_of_one_kind_is_the_borrowed_reply_of_the_responder`; `multicast_tx`'s `a_token_reply_written_from_the_borrowed_reply_is_the_owned_replys_bytes`; the group stage's token reply tests |
| W2 | wz (regenerate) | name the hot roots: `InlineDecode::Codecs(HOT_DECODE_CODECS)` in `xtask`, measured on the receive window | +0 to +1 KB | +0 to +1 KB | +0 to +1.5 KB | equal or lower: the frame's sequence number and the push read in place | the regen-diff lane; the receive window row |
| S1 | SCE | the cold codecs as field tables, one reader and one writer (`docs/sce-proposals/codec-field-tables.md`, items 1 and 2) | -2 to -4 KB | -3 to -6 KB | -12 to -18 KB | none on data; a few instructions a field of a cold read | the documents' vectors, `wz-codecs`' suites, the generator's hot-body test, the receive window row, the declare row of the operation budget |
| S2 | SCE and wz's documents | identical layouts as one table, and one declared-entity and one undeclared-entity document whose kind is the header's identifier | -0.2 to -0.5 KB | -0.2 to -0.5 KB | -0.5 to -1.5 KB | none | `network_message`'s declaration body tests (`declare_body_ext_chain_tests`), `lent_control`'s byte-equality tests |
| S3 | SCE | one extension body and a cold chain's identifiers as data (proposal item 4); wz's `ext_view` and `ext_chain` read through it | -1 to -2 KB | -1 to -2 KB | -2 to -4 KB | none: a hot chain keeps its typed rule | `mandatory_extension_rule_tests`, `repeated_extension_tests` |
| W3 | wz | a message written once: the counts of section 3 R6 replaced by the one writer over `CountTxBuf`, or by no count where the buffer has an end | 0 to -0.3 KB | 0 to -0.3 KB | -2 to -4 KB | none; the send one pass | `lent_response`'s and `lent_request`'s direct-equals-generic tests, `tx_buf`'s count tests |
| W4 | wz, after S1 and S3 | the hand layouts (R5) replaced by the generated writer of each kind over the parts it is given (`{Codec}Source`), the put's under the hot encode | -1 to -2 KB | -1 to -2 KB | -5 to -9 KB | none; the put's send no slower (the put's row of the operation budget) | every `*_is_written_as_*` byte-equality test of `lent_*`, the operation budget's put and get rows |
| W5 | wz, after S3 | the in-place readers (R7) replaced by the generated views, the push's last and only once a generated hot view reads it in no more instructions | -1 to -3 KB | -1 to -3 KB | -3 to -6 KB | none, held by the window row | `record_walk_tests`, `best_effort_batch_tests`, the receive window row |
| W6 | wz | the group's transmit and receive through the link's writers and readers (`mcast-tx1.md`) | 0 | 0 | -5 to -10 KB | none | that lane's tests |

Taken together the estimates put the api twin's codec at about 32 to 45 KB, against zenoh-pico's
36,707. That is not a claim that it wins: the ranges are wide, the steps overlap (S1 makes S2's
saving small, W4 takes part of R1's runtime with the hand layouts), and only the ledger's readings
say. The order is by dependency: W1 is the wz half that needs nothing else; W2 fixes the boundary S1
needs; S1 and S3 are the generator's; W3 to W6 follow them.

## 7. Step W1

`declare::local_token::build_token_reply` built the lent `Declare` (the variant of every kind of
declaration) and each send encoded it, so each of those sends held the generated walk over the nine
kinds, with the arms read from one site inlined into it. Every other declaration a session sends was
already a declaration of its own kind (`lent_control::DeclarationOf`, through `LentDeclaration` on
the link and `DeclarationReply` on the group).

The one-kind form has one statement, `lent_control::token_reply_declaration` (the envelope with no
extension chain, since this reply carries no `ext_qos`), and the group's one writer of its
declarations (`GroupDeclare::TokenReply`) writes it as well. The link's two sends that write into a
lent slot write it, and the count with no allocator (`local_token::token_reply_len`) measures it;
`build_token_reply` stays for the owned paths and the tests. The bytes are unchanged:
`lent_control`'s test holds the one-kind form's bytes and measure to the lent `Declare`'s, and both
refuse a key past the `u16` bound.

What the main session reads after the merge:

- `cargo test -p wz-session-core --lib --features liveliness-token,codec-response-final a_token_reply_of_one_kind_is_the_borrowed_reply_of_the_responder`: 1 test (`lent_control`'s tests need `declare-final` and `codec-response-final`).
- `cargo test -p wz-session-core --lib --features session-multicast,codec-push,liveliness-token a_token_reply_written_from_the_borrowed_reply_is_the_owned_replys_bytes`: 1 test, the group writer's.
- `cargo test -p wz-session-mcu --lib --features transport-multicast,codec-push,liveliness-token a_token_reply_is_framed_as_its_owned_reply`: 1 test, the stage's (`group_drive::stage` is compiled with the group, `codec-push` and the heap profile; with `liveliness-token` alone it is not, and the filter runs none).
- Builds of `wz-session-core` with `liveliness-token` and `alloc` (with and without
  `tx-lend-only`), and with no allocator and a session that compiles `session_actions`
  (`session-slot`, `session-unicast`, `liveliness-token`): the import of `build_token_reply` in
  `session_actions` is compiled only with an allocator, where its two readers are. Without
  `session-unicast` the link's sends are not compiled at all.
- Layer C1cs: `pico-api-coop-nostd`'s codec lower, `pico-client-coop-nostd` and `pico-peer-coop`
  unchanged; in the api twin's explain, the writer of `send_declare_token_reply` small and no
  instance of the `Declare` walk over the lent `Declare` left for it (the group's token reply is an
  arm of `<GroupDeclare as WireWrite>::write_wire`, T2's reading).
