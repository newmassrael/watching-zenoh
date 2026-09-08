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
