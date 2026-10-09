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

## `scout-and-hello-ipv4-ipv6.pcap`

Discovery: a **Scout** sent to the scouting group and the **Hello** that answers
its sender, once over IPv4 and once over IPv6. It is the specimen of the two
transport message words `Scout` and `Hello`, of the namespace decision that
makes them readable, and of the census document's `ends` rows (new at census
revision 20) for a node that only ever sent a discovery message.

| | |
|---|---|
| link type | 1 (`LINKTYPE_ETHERNET`) |
| packets | **4**, 60 / 96 / 73 / 97 bytes on the wire (the short Scout is padded to the 60-byte minimum a NIC emits) |
| size | 414 bytes |
| timestamps | 0.000000 onward, 1 ms apart |

| packet | flow | what it is | read as |
|---|---|---|---|
| 0 | `192.168.1.5:43210` → `224.0.0.224:7446` | Scout, asking for routers and peers (`what` 3), naming its zid | `Scout`; sender is the **low** end |
| 1 | `192.168.1.9:38117` → `192.168.1.5:43210` | Hello answering packet 0: a peer, its zid, two locators | `Hello`; sender is the **high** end |
| 2 | `[fe80::5]:43210` → `[ff02::224]:7446` | the same Scout, another node, over IPv6 | `Scout`; sender is the **low** end |
| 3 | `[fe80::9]:38117` → `[fe80::5]:43210` | Hello answering packet 2, one locator | `Hello`; sender is the **high** end |

### Why one file holds both a multicast and a unicast packet

`0x01` is a Scout in the scouting namespace and an Init in the transport one;
`0x02` is a Hello and an Open, and a Hello that carries locators has the flag
bit that is an Open's ack bit, so its first byte is `0x22`. The bytes cannot say
which namespace they are in. The capture settles it from where the datagram went:

* a multicast destination carries no handshake, so a `0x01` there is a Scout
  (packets 0 and 2: the namespace decision in `wz_capture`'s `lib.rs` is walked
  on both families);
* a Hello travels back unicast, so the destination says nothing; what says it is
  a Hello is that its destination was seen sending a Scout (packets 1 and 3).

The consumer-surface test below reads the two Hellos **without** their Scouts and
requires them to come back as transport messages. A file whose Hellos read as
Hellos on their own would not exercise that memory at all.

### What a reader reports on it

* the field document has four rows, named `Scout`, `Hello`, `Scout`, `Hello`,
  each in the scouting MID space and none named `Init` or `Open`; each walks its
  zid as a `zid` field, and the Hellos walk their locators as `text`;
* the census document has four nodes. The Hello senders carry `whatami` **1**,
  which is a peer in the handshake's own two-bit packing (a Scout states no role
  of its own, so the two asking nodes read `null`), and their locators;
* its `ends` array has **four** rows, in packet order: the Scout's sender at
  `low`, the Hello's sender at `high`, twice. The receiving end of each flow (the
  group, and the asker) has no row, because no message names it;
* the checksum tallies are all clean: the two IPv4 header checksums verify, IPv6
  has none to judge, and all four UDP checksums verify. The IPv6 ones are
  mandatory (RFC 8200 section 8.1) and are computed, not left zero.

### Where the bytes came from

* the **Scout** is the SCOUT codec's `encode_to_vec` behind the header byte, in
  the order `scouting_glue`'s `scout_emit` does it (version, `what`, then the
  `I` flag, the length nibble and the zid). That action lives in
  `wz-runtime-tokio`, which depends on `wz-capture`, so it cannot be called from
  here: the recipe is **repeated**, and the layout test in that module
  (`scout_emit_stages_framed_datagram`) is the layout the oracle pins the bytes
  against;
* the **Hello** is not laid out in the fixture at all. It is
  `wz_session_core::scout_responder::answer_scout_from` run over the Scout, with
  the asker's address, which is how the responder loop answers;
* the **frames** are an Ethernet header, an IP header and a UDP header with
  computed checksums. The multicast MACs are derived (RFC 1112 section 6.4 for
  IPv4, RFC 2464 section 7 for IPv6) and the unicast ones are locally
  administered placeholders;
* the **container** is `wz_capture::pcap::write`.

Three tests in `crates/wz-capture/src/discovery_capture_fixture.rs` grade it:

| test | what it settles |
|---|---|
| `the_tracked_discovery_capture_is_byte_identical_to_what_wz_emits` | the whole file equals what the encoders emit, byte for byte |
| `the_tracked_discovery_capture_holds_the_exchanges_it_claims` | read off the bytes with no help from the dissection: each Scout goes to the group, each Hello goes back to its Scout's sender from a non-group source, the Scout is `[mid, version, flags, zid]`, and the Hello equals the responder's answer **recomputed from the Scout the file holds** |
| `the_tracked_discovery_capture_reaches_the_consumer_surface` | the four rows are scouting messages named in order, the zids, locators, `ends` rows and checksum tallies above, and the control: the Hellos alone are not Hellos |

`scripts/lib/capture_provenance_gate.sh` runs them (under `--features dissect`)
on every push, beside the other sets.

### What it does not prove

* **That a stock zenoh or zenoh-pico node emits these bytes.** The Scout and the
  Hello are wz's own encoders'. zenoh 1.10.1's scouting initiator builds its
  Scout with `zid: None` (`net/runtime/orchestrator.rs:1010-1014`); this file's
  Scouts do carry one, because wz's scouting window sets it, and a Scout without
  a zid seats nobody in `ends`. A capture of the other shape is not here. The
  version byte `0x09` is zenoh's (`zenoh-protocol` 1.10.1, `src/lib.rs:31`).
* **An IPv6 scouting address zenoh uses.** zenoh ships no IPv6 default (searched
  in `zenoh-config` and `zenoh` 1.10.1); `ff02::224` is the link-local group the
  crate's IPv6 fixtures already use.
* **Extensions, or a Hello from a router or a client.** Neither is in the file.
* **A reply socket's real port.** `38117` is a choice that is neither the
  group's nor the asker's, which is what the two ends of a host-to-host flow need.

### Regenerating

```sh
cargo test -p wz-capture --features dissect --lib \
  refresh_the_tracked_discovery_capture -- --ignored
cargo test -p wz-capture --features dissect --lib discovery_capture
```

## `publisher-priority-encoding-timestamp.pcap`

A publish that sets what the two-node demo never sets, beside a control publish
that sets none of it. It is the specimen of three things a reader reports about
a `Push`: the **transport priority** of the Frame that carries it, the **encoding**
of its body and the **timestamp** of its body.

| | |
|---|---|
| link type | 1 (`LINKTYPE_ETHERNET`) |
| packets | **6**: four handshake datagrams, then two Frames |
| size | 539 bytes |
| flow | one UDP flow, `10.0.0.1:43210` → `10.0.0.2:7447` for the initiator's packets |
| handshake | both Inits carry the QoS offer (establishment extension `0x1`, the presence-only form), so the session is QoS-negotiated |
| timestamps | 0.000000 onward, 1 ms apart |

| packet | what it is | read as |
|---|---|---|
| 0, 1 | Init, InitAck, each offering QoS | handshake rows; the flow's `qos` is `true` |
| 2, 3 | Open, OpenAck | handshake rows |
| 4 | the **control**: a reliable `Frame` (sequence number 0) on the default conduit, no extension chain, carrying a plain `Push` | `sn.conduit.priority` `Data`; no `priority`, `timestamp` or `encoding` field; entry `payload.encoding` **`null`** |
| 5 | a reliable `Frame` (sequence number 0) on the `InteractiveHigh` conduit, carrying a `Push` with the QoS byte, a timestamp and an encoding | `sn.conduit.priority` **`InteractiveHigh`**; see below |

### What a reader reports on packet 5

* the Frame's own `ext_qos` has `priority` `InteractiveHigh` (its `value` is the
  conduit number, 2), and `sn.conduit.priority` says the same: the priority is
  that of the Frame, not of the session;
* the Push's QoS byte is the second `priority` field of the row, again
  `InteractiveHigh`, with `congestion` `Drop` and `express` `false`;
* the Put has its `t` and `e` bits set. Its `timestamp` group holds `time`
  `81985529216486895` (an NTP64 word past 2^53, so a string: `0x0123456789abcdef`),
  a `zid_len` of 4 and a `zid` of `1142577e`, which is the bytes `7e 57 42 11`
  the way zenoh prints a zenoh id (reversed, as hex);
* its `encoding` group holds `packed_id` 10, no schema and an `id` of 5, and the
  entry's `payload.encoding` is `application/json`;
* the census's payload plane counts one body declared `application/json` and one
  `zenoh/bytes (undeclared)`.

### Why the QoS handshake is in the file

Without a negotiated QoS the priority of a message lives in the link layer
alone, and a Frame has no conduit to name: a peer must not send a non-default
priority on a session that did not negotiate QoS, and `wz-session-core`'s
receiver ends such a link (`LostCause::UnknownPriority`, in `drive.rs`). So a
prioritised Frame means something only beside the offer that licenses it, and
this file has the offer on both Inits, ahead of the Frame.

### Why there is a control

A reader that drops any of the three branches reads every other capture in this
directory exactly as before, so none of them could fail it. Packet 4 is the same
session, the same key and the same body with none of the three set, and it must
read with no priority beyond the default conduit, no timestamp and an encoding of
`null` (the wire's way of saying the default, which is a different fact from a
body that names `zenoh/bytes`). A reader that reports a field where there is none
fails on it; one that drops the field fails on packet 5.

### Where the bytes came from

Nothing was written by hand. Both `Push`es are
`wz_session_core::push_build::build_push_literal_with_meta`, the function
`Session::publish` calls with the metadata its `PublishOptions` projects
(`with_priority`, `with_encoding`, `with_timestamp`). The oracle fills that
metadata directly and not through `PublishOptions`, which lives in the runtime
crate: `wz-capture` is a dependency of that crate, so naming it here would be a
cycle. Each Frame is `frame_encode::encode_frame_with_push_qos`, the QoS offer is
`extqos::encode_qos_ext` written by the ext codec, the Init and Open datagrams
are the codecs' own, and the container is `wz_capture::pcap::write`. The send-side
gates for the QoS byte, the encoding and the timestamp are features of
`wz-session-core`; `wz-capture` turns them on for its own tests only, in its
dev-dependencies. Three tests in
`crates/wz-capture/src/publisher_fields_capture_fixture.rs` grade it:

| test | what it settles |
|---|---|
| `the_tracked_publisher_fields_capture_is_byte_identical_to_what_wz_emits` | the whole file equals what the encoders emit, byte for byte |
| `the_tracked_publisher_fields_capture_is_a_qos_session_with_a_control_and_a_full_publish` | both Inits carry the offer, the control Frame has no extension chain, the other has exactly the `ext_qos` entry whose body is the conduit, and the two Pushes are the ones their metadata builds |
| `the_tracked_publisher_fields_capture_reaches_the_consumer_surface` | the rows above, read from the field document, and the same values read from the decoded records without it |

`scripts/lib/capture_provenance_gate.sh` runs them (under `--features dissect`)
on every push, beside the other sets.

### Regenerating

```sh
cargo test -p wz-capture --features dissect --lib \
  refresh_the_tracked_publisher_fields_capture -- --ignored
cargo test -p wz-capture --features dissect --lib publisher_fields_capture
```
