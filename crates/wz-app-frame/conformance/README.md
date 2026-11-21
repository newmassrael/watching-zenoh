# Conformance corpus of the fixed records of a protected frame

`fixed_records.json5` holds hand-written vectors of the two fixed records an end-to-end
protected frame is read into and judged by, and of the word-mask rule the header layouts use:

- `e2e_opened`: the record a receiver opens from the bytes of one frame (CRC, length, counter,
  header values, message cell, identifier);
- `e2e_policy`: the rules a receiver judges a stream of frames by (largest counter step, silence,
  how counter errors are reported, whether a length disagreement fails integrity).

The corpus is the differential baseline of a generated codec. Every vector runs through the
hand-written builder and opener of `wz_app_frame::e2e_frame` and the receiver of
`wz_app_frame::e2e_receiver` (`src/fixed_records_tests.rs`), and the same runner holds a codec
SCE generates from the same layouts to the same expected bytes and records, unchanged, behind the
crate feature `sce-generated-codec`.

Every layout, width, mask, constant and name in the corpus is made up for it and unlike any
deployment's. The CRCs are published catalogue entries (CRC-8/DVB-S2, CRC-32/ISCSI, CRC-16/ARC).

## Format `wz-fixed-records/1`

The file is JSON5, read by the workspace's one JSON reader. Every object is closed: an unknown
member, or a member stated twice, fails the run at its place.

```text
{
  format: 'wz-fixed-records/1',
  layouts: { <layout name>: <layout>, ... },
  vectors: [ <vector>, ... ],
}
```

### Values

- An integer is a plain decimal JSON number, or a string of decimal digits or `0x` and hex
  digits. Wide values are written in hex.
- Bytes are a string of two-digit hex pairs apart by spaces (`'FC 06 05 1E'`), or an array of
  such strings, joined in order. `''` is no bytes.
- A pointer (`at`) is an RFC 6901 JSON pointer; `''` is the object itself.

### Layout

```text
<layout> = {
  profile: <profile>,                         // required
  runs: { <value name>: {field: <word>, parts: [<part>, ...]}, ... },   // optional
  expected: <values>,                         // optional
}
```

- `profile` defines the layout, in the language of `wz_app_frame::e2e_profile` (its module
  documentation states it): fields in wire order, each a big-endian unsigned integer 1 to 8 bytes
  wide; a field's `xor` and `split` parts; the CRC's Rocksoft parameters and its feeding order
  `cover`; the length rule; the counter and its limits; the judging rules; the message cell; the
  parts derived from the node's address. A generated codec of the layout is generated from a codec
  document stating the same layout.
- A field with a `split` is a WORD. Its `xor` is the word's mask: on build the parts are placed
  at their bits, every other bit of the word is 0, and the whole word is XORed with the mask, so a
  bit no part owns carries the mask's bit on the wire. On open the word is XORed with the mask and
  only the parts' bits are read: a bit no part owns is read by nothing, whatever it carries. The
  CRC is taken over the bytes on the wire, so those bits are covered like any other.
- `runs` names a VALUE OVER SEVERAL RUNS of one word: `parts` lists the parts of the word
  `field` that hold its runs, the most significant run first. The value's bits are the
  concatenation of the runs in that order. In `values` and in a record the value appears under
  its own name, and its parts do not appear.
- `expected` is the values a receiver expects of the identifier the profile judges
  (`judge.ident`), as a sender would state them. Absent when the profile judges none.

### Vector

Every vector has `name` (unique, `<layout>/<what it shows>`), `kind` and `layout`, and the
members of its kind:

| kind | members | what a codec does |
|---|---|---|
| `frame` | `values`, `payload`, `wire`, `opened` | build `values` and `payload` into exactly `wire`; open `wire` into exactly `opened` |
| `open` | `wire`, and `opened` or `refused` | open `wire`, bytes no build of the layout makes |
| `build` | `values`, `payload`, `refused` | refuse to build |
| `policy` | `stated`, and `policy` or `refused` | read the policy `stated` for a receiver of the layout |

`values` is an object keyed by field name: a number for a plain field, an object keyed by part
name (or run value name) for a word, and `'@address'`, the node's address, which the derived
parts are computed from as `(address & mask) ^ xor`. The counter is a field among the others;
the CRC and the length are computed and never stated.

### `e2e_opened`

```text
opened: {
  crc_found, crc_computed, crc_ok,                       // the CRC field as received, recomputed
  length_found, length_expected, length_matches_frame,   // the length field, the layout's rule
  counter, payload_offset, payload_bytes,
  fields: { <field>: <value> | {<part or run value>: <value>, ...}, ... },
  cell: {kind, result, sender},                          // the parts the layout's cell names
  ident_matches,                                         // when the layout judges an identifier
}
```

- `fields` holds every field but the CRC, the length and the counter: a plain field's value with
  the `xor` undone, a word's parts (and run values) with the mask undone.
- A CRC that does not match and a length that disagrees with the frame are FACTS of the record,
  never refusals. The CRC is recomputed over the bytes as received, the length field included as
  it stands, and the body's extent is the frame less the header, never the length field's value.
- `ident_matches` compares the identifier in the bits its parts own with `expected`.
- `cell` holds only the members the layout's cell names; it is absent when the layout names no
  cell.

### `e2e_policy`

```text
stated: {max_gap, timeout_ms, max_gap_ceiling?, counter_errors?, out_of_range?, length?}
policy: {max_gap, timeout_ms, max_gap_ceiling, counter_errors, out_of_range, length}
```

`stated` replaces the layout's own policy. A member it leaves out takes its default:
`max_gap_ceiling` none (`null` in the record, the counter's largest step), `counter_errors`
`'apart'`, `out_of_range` `'moves_baseline'`, `length` false. `max_gap` and `timeout_ms`
are required; a `timeout_ms` of 0 states no limit on the silence.

### Refusals

```text
refused: {kind: 'values', at: <pointer into values>}
refused: {kind: 'payload_too_long'}
refused: {kind: 'short_frame'}
refused: {kind: 'policy', at: <pointer into stated>}
```

- `values`: a value missing, of the wrong shape, too wide for its field, part or runs, stated
  for a computed field or a derived part, or a derived part with no `'@address'`. A value over
  runs is refused at its own name, never at one of its parts.
- `payload_too_long`: the length the body needs does not fit the length field.
- `short_frame`: fewer bytes than the header. The only refusal of an open.
- `policy`: a member out of its range or of an unknown word, or a required member missing.

## The vectors

| kind | count |
|---|---|
| frame | 7 |
| open | 11 |
| build | 8 |
| policy | 12 |

Three layouts: `mask-word` (the word with unowned bits 28 to 31 under the mask `0xFF0F0F0F`, a
CRC fed in another order than the wire, a length that counts the frame), `multi-run` (one value
over two runs of a word, a derived part, a mask on a plain field, a length less two fields) and
`minus-length` (the CRC first and fed the body first, a one-byte length less two fields, at its
largest and one byte past it).

## Running a generated codec against it

1. Generate the codecs of the three layouts from codec documents that state them.
2. In `src/fixed_records_tests.rs`, list each layout's codec in `GENERATED`: an implementation
   of the runner's `Codec` (build, open, policy) that calls the generated adapter and fills the
   records above.
3. Run `cargo test -p wz-app-frame --features sce-generated-codec --lib fixed_records_tests`:
   `generated_codec_matches_the_corpus` fails naming every layout with no codec listed, and
   otherwise holds the generated codecs to every vector.

## Changing the corpus

A vector is added, never edited: an expectation that changes is a new format, with its own
version string, read by a runner that knows it. Adding a vector moves the count above and the
runner's `KINDS` in the same commit.
