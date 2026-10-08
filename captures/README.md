# Sample captures

Packet captures a consumer can read without producing one first. Each file
here exists because the traffic it holds is traffic the consumer's own
environment cannot generate, and each is a **function of this workspace's
encoders** rather than a byte string somebody typed — the oracle that keeps it
so is named beside the file below, and it is what makes the provenance claim
checkable instead of merely written down.

Read them through the published C door — `wz_dissect_pcap_summary`,
`wz_dissect_pcap_census`, `wz_dissect_pcap_fields` and their `_bounded` /
`_limited` siblings all take the bytes of a capture file
(`crates/wz-capi-dissect/include/wz_dissect.h`) — or through
`wz_capture::Dissection::from_capture` from Rust.

## `raweth-transport-messages.pcap`

zenoh-pico's **raweth (L2) transport**: zenoh transport messages framed in
pico's own Ethernet header, which is not a standard one — it is 16 bytes rather
than 14 because pico appends an explicit `data_length` after the ethertype, and
20 bytes in the VLAN form.

| | |
|---|---|
| link type | 1 (`LINKTYPE_ETHERNET`) |
| packets | one per transport message in `wz-capture`'s MID census — **7** as measured 2026-09-08 |
| size | 296 bytes |
| MACs | pico's own defaults: `30:03:c8:37:25:a1` → `aa:bb:cc:dd:ee:ff` |
| ethertype | `0x72e0`, pico's `_ZP_RAWETH_DEFAULT_ETHTYPE` |
| header widths | both — even-indexed packets 16 bytes, odd-indexed 20 with VLAN tag `0x0102` |
| timestamps | 0.000000 onward, 1 ms apart |

### Where the bytes came from

Nothing in this file was written by hand. Three layers, three sources:

* **payloads** — each transport message is built by **its own codec's**
  `encode_to_vec`, taken from `wz-capture`'s MID census
  (`crates/wz-capture/src/lib.rs`, `transport_census`). Drawing the sample from
  the same list the census tests walk means a MID added there joins this file
  by construction, so the sample cannot fall behind the vocabulary it
  advertises;
* **framing** — `wz_session_core::raweth_link::frame`
  (`crates/wz-session-core/src/raweth_link.rs`), the same function the live
  raweth link uses, with pico's default MACs and ethertype as declared there;
* **container** — `wz_capture::pcap::write`
  (`crates/wz-capture/src/pcap.rs`), whose file header is asserted byte by byte
  against `pcap-savefile(5)` by that module's own tests.

### Why hand-laid bytes were refused

`crates/wz-integration-tests/tests/raweth_framing_pico_layout.rs` exists
because pico's header is a C struct `memcpy`'d onto the wire, so its shape is a
property of a C compiler's layout of a type in `vendor/zenoh-pico` and not of
anything this tree decides:

* `ethtype`, `vlan_type` and `tag` ride the **sender's** byte order, while
  `data_length` goes through `htons` and does not;
* the header is 16 bytes, and a reader assuming the standard 14 takes two
  payload bytes for header and is wrong about everything after;
* the VLAN form is 20 bytes, and pico spells its VLAN type `0x0081` precisely
  so that a little-endian `memcpy` lands the real `81 00`.

A frame typed out by hand can be wrong on any of those, and would then be read
back by this workspace's own parser, agree with itself, and ship. So the
provenance is not a note — it is graded, by three tests in
`crates/wz-capture/src/raweth_capture_fixture.rs`:

| test | what it settles |
|---|---|
| `the_tracked_raweth_capture_is_byte_identical_to_what_wz_emits` | the whole file equals what the encoders emit, byte for byte. It reads no layout, so it cannot be satisfied by a fixture that merely agrees with the reader |
| `the_tracked_raweth_capture_carries_both_header_widths` | both widths are specimened, derived from the frames rather than from a count written anywhere |
| `the_tracked_raweth_capture_reaches_the_consumer_surface` | every message reaches `Dissection::from_capture` **named**, on a flow marked `raweth` — a byte-perfect file that dissected to `Unknown { mid }` would be worthless |

`.githooks/pre-push` gate 2x runs them before every push, because the file is a
function of code in a *different* crate and the changed-crate test gate would
otherwise never reach it.

### The recorded frames are a little-endian host's

That follows from the byte-order rule above and it is not a defect: pico on a
big-endian host would put `72 e0` where this file has `e0 72`, both are correct
for their sender, and `wz_capture`'s reader accepts either — the sender's
endianness is not observable from a capture. This file records what the
little-endian deployments the sample is for emit. Regenerating it on a
big-endian host produces a different and equally correct file, and the
byte-identity test above fails there **loudly**, naming the endianness, rather
than standing down.

### Regenerating

Only when a census entry or the framing changes on purpose:

```sh
cargo test -p wz-capture --lib refresh_the_tracked_raweth_capture -- --ignored
cargo test -p wz-capture --lib raweth_capture
```

The refresher is `#[ignore]`d so that no CI run can rewrite the artifact it is
meant to be checking, and it asserts nothing — the second command is what
believes it. Commit the rewritten `.pcap` in the same commit as the change that
moved it.

## `compressed-session-refused-body.pcap`

A session that **negotiated compression**, with two batches on it, of which the
lz4 decoder opens one and refuses the other. It is the specimen of the field
document's `carried_state: "undecompressible"`: the word says the batch's body
could not be opened, and this is the only file here in which a body really is
refused.

| | |
|---|---|
| link type | 1 (`LINKTYPE_ETHERNET`) |
| packets | **6**: four handshake datagrams, then two batches |
| flow | one UDP flow, `10.0.0.1:43210` → `10.0.0.2:7447` for the initiator's packets |
| handshake | both Inits carry the compression offer (establishment extension `0x6`), so the batch header is on the wire from the first batch on |
| timestamps | 0.000000 onward, 1 ms apart |

| packet | what it is | read as |
|---|---|---|
| 0, 1 | Init, InitAck, each offering compression | handshake rows |
| 2, 3 | Open, OpenAck | handshake rows |
| 4 | the compressor's output for a `Frame` (sequence number 0) carrying a literal `Push` of 240 bytes, unchanged | `carried_state` **`batch`** |
| 5 | the same construction at sequence number 1, with **two bytes overwritten** | `carried_state` **`undecompressible`** |

### The one broken spot, by name

Packet 5's datagram payload is `[BatchHeader][lz4 block]`. The header is `0x01`
(the body is lz4) and is intact. The damage is in the block: the **match offset
of its first sequence**, the 2-byte little-endian field that follows the first
run of literals, is overwritten with `ff ff`. An offset is the distance back
into the output decoded so far, so `0xffff` reaches before the start of
everything the block can have produced; no lz4 decoder can satisfy it, which
makes the refusal a property of the format and not of this workspace's decoder.
The position is read off the block's own first token (literal length, its
extension bytes, the literals) rather than written as a constant; it falls at
payload bytes 27 and 28 of this file. Nothing else differs from the intact twin
at the same sequence number.

### Why there are two batches

A sample with only the damaged one cannot tell a reader that recognises a refused
body from one that says `undecompressible` to anything after a compression offer.
Packet 4 is the control: the same session, the same construction, undamaged, and
it must read `batch`.

### What a reader reports on it

Read with a build that has lz4 (`wz-capi-dissect` does):

* the field document has one row with `carried_state` `batch` and one with
  `undecompressible`;
* the census document's `undecompressible_batches` is **1**, and so is the
  summary's, which is the number of rows that say `undecompressible`;
* the summary's `unaccounted_batch_bytes` is the damaged batch's length (37),
  because no message inside a refused batch can be located.

⚠ A build **without** lz4 reads packet 4 as `undecompressible` as well. That is
the honest answer for a reader that cannot open a compressed body, and it is why
the word's definition above says "the lz4 decoder refused", not "compressed".

### Where the bytes came from

Nothing was written by hand: the handshake is the codecs' own Init and Open, the
batches are `wz_session_core::compression::compress_batch` over
`frame_encode::encode_frame_with_push` of `push_build::build_push_literal`, the
damage is applied to the compressor's output at the position found above, and the
container is `wz_capture::pcap::write`. Three tests in
`crates/wz-capture/src/compressed_capture_fixture.rs` grade it:

| test | what it settles |
|---|---|
| `the_tracked_compressed_capture_is_byte_identical_to_what_wz_emits` | the whole file equals what the encoders emit, byte for byte |
| `the_tracked_compressed_capture_breaks_exactly_one_named_spot` | packet 4 opens to exactly the frame the encoder produced; packet 5 differs from its undamaged twin only inside the match offset, and is refused |
| `the_tracked_compressed_capture_reaches_the_consumer_surface` | the two batches read as `batch` then `undecompressible`, and the three counts above agree |

`scripts/lib/capture_provenance_gate.sh` runs them (under `--features
compression,dissect`) on every push, beside the raweth set.

### Regenerating

```sh
cargo test -p wz-capture --features compression,dissect --lib \
  refresh_the_tracked_compressed_capture -- --ignored
cargo test -p wz-capture --features compression,dissect --lib compressed_capture
```

## `fragmented-push-midsession-and-established.pcap`

One fragmented message, seen twice: in a flow whose handshake the capture
**missed**, and in a flow whose handshake it holds. It is the specimen of a
fragment chain read by a reader with no InitAck, and its control.

A reader that never saw the session's InitAck does not know the size of the
sequence-number ring, and will not guess a mask (a wrap and a gap look the same
without it). The ring decides one thing about a chain, whether a step from one
fragment to the next is consecutive across a wrap, and a step of plain `+1` is
consecutive on every ring. So that reader follows a chain whose steps are all
`+1`, and the message in this file is reassembled in both flows. Only a step it
cannot judge ends a chain, and the fragment that showed it reads
`carried_state: "fragment_without_resolution"`; no tracked capture holds one yet,
and the tests that build them are in
`crates/wz-capture/src/unresolved_chain_tests.rs`. Before the router was told the
ring was unknown, flow A read `fragment_without_resolution` on both fragments.

| | |
|---|---|
| link type | 1 (`LINKTYPE_ETHERNET`) |
| packets | **8**: flow A is 2, flow B is 6 |
| timestamps | 0.000000 onward, 1 ms apart |

| packets | flow | what they are | read as |
|---|---|---|---|
| 0 | A: `10.0.0.1:43210` → `10.0.0.2:7447` | the first fragment of the message, no handshake | `fragment`, sequence verdict `without_resolution` |
| 1 | A | the second fragment | `reassembled`, its record a `Push`, verdict `without_resolution` |
| 2–5 | B: `10.0.0.3:43211` ↔ `10.0.0.4:7447` | Init, InitAck, Open, OpenAck | handshake rows |
| 6 | B | the **same** first fragment, byte for byte | `fragment`, verdict `baseline` |
| 7 | B | the **same** second fragment, byte for byte | `reassembled`, its record a `Push`, verdict `continuous` |

The two flows differ in exactly one fact, the handshake, and in what follows
from it and nothing else: the sequence-number verdict, which a reader that missed
the handshake may not claim. The message is a literal `Push` of a 120-byte value,
cut at its middle; the fragments are reliable, the first with the more flag,
sequence numbers 0 and 1.

### What a reader reports on it

* the field document has `fragment` on 2 rows and `reassembled` on 2, and none
  that say `fragment_without_resolution`;
* its `sn.verdict` is `without_resolution` on both rows of flow A, and
  `baseline` then `continuous` on flow B;
* the census document's `unresolvable_fragments` is **0**, and the keyexpr the
  message was published on counts **2** puts, one for each flow.

### Where the bytes came from

The message is `push_build::build_push_literal` written by its codec. A Fragment
is hand-walked by the reader and has no body codec (the MID vocabulary in
`datagram_tests` records the same), so each is the transport header byte, built
from `wire_const` names with the reliable and more flags, a one-byte sequence
number and its piece. The handshake is the codecs' own Init and Open, and the
container is `wz_capture::pcap::write`. Three tests in
`crates/wz-capture/src/midsession_capture_fixture.rs` grade it:

| test | what it settles |
|---|---|
| `the_tracked_midsession_capture_is_byte_identical_to_what_wz_emits` | the whole file equals what the encoders emit |
| `the_tracked_midsession_capture_differs_between_its_flows_only_in_the_handshake` | the two flows carry the same fragment datagrams, flow A holds nothing but them, flow B's four datagrams before them are the handshake, and the two pieces join to the encoded message |
| `the_tracked_midsession_capture_reaches_the_consumer_surface` | both flows read `fragment` then `reassembled` with a `Push`, the one with no ring says `without_resolution` and the other reads its own verdicts, and the counts above agree |

### Regenerating

```sh
cargo test -p wz-capture --features dissect --lib \
  refresh_the_tracked_midsession_capture -- --ignored
cargo test -p wz-capture --features dissect --lib midsession_capture
```
