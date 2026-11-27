# Cold codecs read and written by one walker over a field table

Status: proposal to the SCE session (generator and forge runtime change), 2026-11-28. Measured on
the pico C library's Linux twin of the Windows release (`pico-api-coop-nostd`) and its client and
peer cases, by the size ledger's `--explain` reports. The diagnosis it answers is wz's
`docs/win-budget/codec-scale.md`; this note is the part of its design that only the generator can
make.

## What is compiled today

wz's wire codec area, in the like-for-like library, is 77,953 bytes against zenoh-pico's 36,707
(2.12). zenoh-pico compiles every message's encoder and decoder in every build (its codec area is
35,440 in the client and 36,707 in the full library); wz compiles a message's codec only where a
feature reads or sends it (28,180 in the client), so the full library is where the two hold the
same kinds and the cost of a kind is compared.

Of wz's 77,953 bytes, 24,323 are lines of the forge runtime (`backends/rust/forge-runtime/src`)
inlined into the generated and the consumer's bodies: `codec.rs` 7,514 bytes in 39 bodies,
`reader.rs` 6,617 in 57, `bounded.rs` 3,707 in 65, `storage.rs` 2,005 in 26, `view.rs` 1,869 in
25, `algorithm.rs` 996, `membership.rs` 863, `fixed_list.rs` 440, `chain.rs` 184, `law.rs` 128.
Read function by function from the line tables of the same build (`objdump -d -l --inlines`), the
largest are `SceReader::take_array::<1>` (in 25 bodies), the extension entry walk's `next` (13),
`SliceSink::put::<1>` (10), `SceReader::read_vle_u64` (20 bodies, and the cursor's in 10 more),
`Bounded::next` over the extension entries (11), `take_slice` (15), `settle` (12),
`from_fitting::<16>` and `from_slice::<16>` (8 each). They are the reads and writes of one field
each, printed again at every field of every codec that the build links. zenoh-pico reads a ZInt by
one function (`_z_zint64_decode`, 202 bytes) and an extension chain by one iterator with a
callback (`_z_msg_ext_decode_iter`, 165 bytes) for every message.

ADRs 0136 to 0141 took the loops out of the fields (one chain routine per rule, one VLE encoder,
one ZInt reader, one fixed-list push). What is left is the field's own straight-line code, and it is
the right shape for a hot codec and the wrong one for a cold one: a declaration, an interest, an
OAM, the handshake, the join, a close, a keep-alive, scouting, a response final are read once per
entity, session or link event, and their bodies are most of the codec area's kinds.

Two more shapes the generator decides:

- **Structurally identical documents compile apart.** `decl_subscriber`, `decl_queryable` and
  `decl_token` differ in their names only (`diff` of the three generated files), and so do the four
  undeclarations; the like-for-like library holds `DeclQueryableWire::write_source` and
  `DeclTokenWire::write_source` at 286 bytes each, side by side. zenoh-pico writes the three through
  `_z_decl_commons_encode` and reads the trivial undeclarations through `_z_undecl_trivial_decode`.
- **A chain's rule is a type** (ADR 0136's amendment), so each chain of each codec is an instance of
  `read_chain_into` and of the walk, and the extension entry is read in 29 bodies of the library.
  The extension area is 5,742 bytes against zenoh-pico's 1,459 (3.9).

## What the generator could do

1. **A cold codec is a table.** For every codec not on the build's hot path (ADR 0140's sites: the
   roots `--inline-decode-for` names and every read a hot body makes), emit a `static` field table
   in place of the straight-line `read_into` and `write_source`:
   one row per field, its kind (a header byte and the bit ranges read off it, a ZInt of a width, a
   fixed array, a length-prefixed byte string or text under its bound, an embedded codec by its
   table, a variant on a tag by the tables of its arms, a repeat, an extension chain by its table of
   known identifiers), its gate (the header bit or the field it is present under) and its place in
   the value (an offset in the `repr(C)` view, or a setter index). The runtime gains one reader and
   one writer, each one function for every table, generic over nothing, out of line:

       pub fn read_table(reader: &mut SceReader<'_>, table: &'static FieldTable, out: *mut u8);
       pub fn write_table(sink: &mut dyn SceSink<Error = CodecError>, table: &'static FieldTable,
                          src: *const u8) -> Result<(), CodecError>;

   The view and the owned forms keep their public types; only where their reads and writes are
   compiled moves, as ADR 0141 moved the list push. This is ADR 0135's shape for the codec kind: a
   document of the static class run by one walker that reads its tables. The same split is the
   table-driven parsers of the protobuf family (upb's mini-tables, the C++ table-driven parser) and
   of the embedded ones (nanopb's field descriptors, its default and only form).
2. **A hot codec stays printed.** The roots and their transitive reads keep today's bodies, held in
   place (ADR 0140). No hot read calls the table walker; a test of the generated set says so.
3. **Identical layouts are one table.** Two documents whose fields, gates and bounds are the same
   share one table; their types stay theirs. With (1) the cost of a declaration kind is its table
   row, and a set's identical kinds cost one table.
4. **A cold chain's rule is data.** A cold codec's extension chain is a table of its known
   identifiers (each: the slot it is held in, or a refusal for a mandatory one it does not know)
   read by one chain routine over the one extension entry; a hot codec's chain keeps its typed rule.

## Expected effect

Measured cells come after the landing; the figures here are estimates from the readings above.

| case | codec today | expected after 1 to 4 | how it is estimated |
|---|---:|---:|---|
| `pico-client-coop-nostd` | 28,180 | 24,000 to 26,000 | its cold kinds (the handshake, declarations, interest, OAM) and their share of the inlined runtime, about 6 KB, to the walker (3 to 4 KB) and its tables |
| `pico-peer-coop` | 33,099 | 27,000 to 30,000 | the same and the scouting kinds |
| `pico-api-coop-nostd` | 77,953 | 60,000 to 66,000 | the declaration family (7,696), interest (816), OAM (379), the transport's cold kinds and scouting (about 4 KB) and their share of the inlined runtime (about 9 KB), 20 to 22 KB, to the walker and about 2 KB of tables |

The receive of a data message is unchanged: its codecs are hot. A cold read costs the walker's
dispatch, a few instructions a field, once per entity or session event; the declaration's row of
wz's operation budget (`docs/win-budget/ir-send-query.md`, declare and retract a subscriber,
15,384 instructions) holds the cost.

## What turns red if it is wrong

- The codec vectors of every document (`<sce:test-vector>`, held on the Rust and the C11 emission)
  and wz's round-trip suites (`crates/wz-codecs/tests`), whose bytes are unchanged.
- A generator test that no body of a hot codec calls `read_table` or `write_table`.
- wz's receive window row (`docs/win-budget/ir-receive.md`), which a table read on the data path
  would raise.
