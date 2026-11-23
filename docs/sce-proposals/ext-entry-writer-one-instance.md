# One compiled extension-entry writer per sink

Status: proposal to the SCE session (codegen template change). Measured on the pico C library's
release form at int9 and on the l2-transport branch.

## What is compiled today

The generated writer of every message with an extension chain (`ExtEntryWire::write_source_in`
in `out/wz-codecs/ext_entry.rs`) is generic over the chain's entry source `S: ExtEntrySource`, so
one copy is compiled for each entry type a build writes chains from. The release form of the pico
library had three, each 395 to 427 bytes of text:

| entry source | written by |
|---|---|
| `&ExtEntryIn<Heap>` | the handshake Init and Open (staged owned entries) |
| `&ExtEntryIn<Lent<Node>>` | the declarations' chains (`lent_control`, through the generated `DeclarationOf` writers) |
| `&ExtEntryParts` | the lent Request, Response and Join writers |

wz removed the first by presenting the staged entries as `ExtEntryParts` before writing
(`handshake_encode::with_parts`, commit 8b0542a51 on l2-transport). The second cannot be removed in
wz: the copy is instantiated inside the generated declaration writers, which `out/**` forbids
editing.

## What the template could do

1. Make the parts form hold its bodies by value rather than by reference:
   `ExtEntryPartsBody::CodecZenohExtZint(ExtZintParts)` and `CodecZenohExtZbuf(ExtZbufParts<'a>)`,
   both already `Copy` (`ExtZbufParts` is a byte view). A source can then be projected into parts
   with no storage of its own.
2. Generate `fn as_parts(&self) -> ExtEntryParts<'_>` on `ExtEntrySource` (a provided method over
   `header()` and `body()`), and have every generated list writer of an extension chain call one
   non-generic `ExtEntryWire::write_parts(parts, overrides, w)` per entry instead of
   `write_source_in::<S>`.

The writer is then compiled once per sink type, whatever storage the entries are held in, and a
caller like wz's handshake needs no holder arrays to present its entries.

## Expected effect

- The pico release form: one fewer copy of the entry writer, about 395 bytes of text, and the
  holder arrays and the projection loop of `handshake_encode::with_parts` (about 150 bytes of text
  and up to 48 bytes of stack per staged entry) become unnecessary.
- Every other build that writes chains from more than one storage profile loses one copy per extra
  profile.
- No wire change: the bytes come from the same field walk.
