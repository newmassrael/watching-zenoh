# Can the whole zenoh wire be written as SCE codec documents?

The question, asked by the SCE side as the first input to a new ADR: can every
zenoh frame be written as an SCE positional codec document (SCE_FORGE.md §4.6,
`sce:bit-size="vle"` included), and if the extension chain blocks it, where
exactly?

wz already generates its zenoh codecs from `sources/codecs/*.scxml`
(`out/wz-codecs`). This document starts from that, classifies every wire
element of upstream zenoh 1.10.2, says for each one why it is or is not a
document today, and names the SCE language element each blocked place needs.

## 1. Answer

Every message SKELETON of zenoh 1.10.2 can be written in the SCE codec
language as it stands: header flags, fields gated on a flag, a flag the parent
passes in, lengths and `length-1` lengths, VLE integers with zenoh's 9-byte
form, the Z-bit continuation of an extension chain, and the payload whose shape
depends on whether a shared-memory marker is in the chain. Where wz still
writes a skeleton by hand (the transport messages past the handshake, the
scouting messages, the dispatch by message id, their extension chains), the
reason is on the wz side; the handshake messages are whole documents
(rows 6-11).
The language blocks at five places, all on the extension and refusal side:
(L1) choosing an extension's body codec by its identity (`id | M | enc`) while
an unknown identity is still read by its encoding, which every one of the 41
typed extensions needs; (L2) refusing a value, which the upstream decoder does
for an unknown mandatory extension, the reserved encoding `0b11` and an unknown
message id, and which a variant cannot express because it must reach an arm for
every tag; (L3) a bit range with a fixed value, the message id, which today is
a value field every builder writes by hand; (L4) a Z-terminated chain that may
be empty when its enclosing scope is (the authentication extension's method
list); and (L5) a list that ends where the next byte names no arm (the network
messages of a `Frame`, followed in the same batch by another transport
message). Six small language elements, proposed in §7, close all five; none of
them changes an existing document.

## 2. What was read, and how it is cited

- Upstream zenoh at the version wz pins (`UPSTREAM_VERSION`, 1.10.2). A path is
  relative to that repository and is cited as `` `path` @ `needle` ``; every
  needle in this file was checked to occur in that file at the pin.
- SCE at `origin/main` `7e396e7ecc`, and the SCE wz pins in `vendor/sce`,
  `06f8147241`. Lines are `origin/main`'s; a pin line is added where it was
  looked up, and a difference in content is stated where there is one.
  The language is defined by `SCE_FORGE.md` §4.6, `schemas/sce-forge-ext.xsd`
  and the ADRs it cites.
- wz at `c2-int` `3408af7a0e`, cited as `file:line`. A `.rs` file named without a
  directory is in `crates/wz-session-core/src/`, a `.scxml` file in
  `sources/codecs/`.
- Nothing was built or run for this document. "Expressible" below is a reading
  of the language definition, not a document that was generated and tested.

## 3. The SCE codec elements the verdicts use

| Element | What it states | Where (main; pin when different) |
|---|---|---|
| `sce:bit-size="vle"` | zenoh's ZInt: up to 9 bytes, the ninth carries 8 bits | `backends/rust/forge-runtime/src/codec.rs:498`; upstream `commons/zenoh-codec/src/core/zint.rs` @ `const VLE_LEN_MAX: usize = vle_len(u64::MAX);` |
| `<sce:flags>` / `<sce:flag>` | named bit ranges of one carrier, no two overlapping; a carrier may be a VLE (`sources/codecs/encoding.scxml:64`) | `schemas/sce-forge-ext.xsd:1479` (pin 1117) |
| `<sce:flag value=>` | a constant for the carrier's `Default` only | xsd:1501 (pin 1139) |
| `sce:present-if` | `carrier.flag`, `<chain>.has(v)`, a bare flag-input, `!`, `\|\|`; no `&&` | xsd:668-682; `SCE_FORGE.md:1410` (pin 1302) |
| `length-ref`, `sce:length-arith`, `tail` | a length field before the bytes, optionally `±1`; the rest of the frame | `SCE_FORGE.md:947-988`; xsd:695-704 |
| `<sce:embed>` | an imported body, gated, optionally scoped by `sce:length-from` | xsd:1755-1773 |
| `<sce:repeat>` | `count=` a field, or `until-eof`; `max-count`; two lists may share a count | xsd:1550-1576 |
| `<sce:tlv-chain>` | one entry codec for every entry; ends on an entry flag or with the frame; `entry-id`, `entry-id-except`, `<sce:entry-flag-bind>` | `SCE_FORGE.md:1349-1514` (pin 1241-1406); xsd:1624-1709 |
| `<sce:variant>` | tag = a field or a multi-bit flag of the codec; or the next byte (`<sce:peek-byte>`, `uint8` only); or the caller's (`<sce:variant-dispatch>` on the import); a `<sce:default>` arm; an arm under a build feature | xsd:1354-1465 (pin 992-1103) |
| exhaustiveness | without `<sce:default>` the arms must cover the tag's whole domain | `sce-build/src/forge/parser.rs:5873` (pin 4336); `backends/rust/forge-runtime/src/codec.rs:30` |
| `<sce:flag-inputs>` | inputs one bit wide (v1) | xsd:1227 (pin 865) |
| derived on encode | lengths, counts, a known arm's tag, a one-flag gate, a chain's continuation flag; every other element, header bits included, is presented by the value | `docs/adr/0058-a-codec-encodes-any-value-that-presents-its-fields-and-a-list-is-presented-by-walking-it.md:66-80` (main = pin) |
| sub-byte fixed fields | a fixed field of 1 to 64 bits at any bit offset | `SCE_FORGE.md:955` (ADR 0095); main only, the pin allows whole bytes |

The xsd still calls `sce:length-from` "author-trust on encode" (xsd:710,
xsd:1770). ADR 0058 lists it among the declarations whose element the encoder
derives (line 74), which is the newer statement; this document reads it as
derived.

## 4. Classes and causes

- **(A)** The whole item, as upstream reads it, is in an SCE codec document wz
  generates, and wz reads it through that codec.
- **(B)** wz has hand-written code for the item or for part of it.
- **(C)** Nothing in wz reads or writes the item's typed structure.

Each (B) and (C) row names its cause:

| Code | Cause | Kind |
|---|---|---|
| L1 | choosing a body codec by an extension's identity, with an unknown identity read by its encoding | language |
| L2 | refusing a tag or a value the protocol refuses | language |
| L3 | a bit range with a fixed value that the decode checks and the encode writes | language |
| L4 | a Z-terminated chain that is empty when its scope is empty | language |
| L5 | a list that ends before the first byte whose tag no arm names | language |
| L6 | a value constraint that is not a layout (a value that must not be zero) | language, minor |
| L7 | a list with a constant count | language, minor (unrolling works) |
| W | expressible with today's elements; wz writes it by hand | wz |
| S | not a layout: state across messages, a transform, a unit | outside a codec |

## 5. Every wire element

### 5.1 Link framing and the batch

| # | Item | Upstream | Class | wz | Cause |
|---|---|---|---|---|---|
| 1 | Stream link: a u16 little-endian length before each batch | `commons/zenoh-protocol/src/transport/init.rs` @ `16 bits (2 bytes) may be prepended to the serialized message indicating the total length`; little-endian: `io/zenoh-transport/src/common/batch.rs` @ `length.copy_from_slice(&len.to_le_bytes());` | A | `sources/codecs/stream_envelope.scxml` | |
| 2 | Serial link frame (header, u16 length, payload, CRC32, then COBS) | the zenoh-pico serial frame; upstream Rust's serial link (`io/zenoh-links/zenoh-link-serial`) was not compared here | A | `serial_envelope.scxml`, `cobs_encode.scxml`, `cobs_decode.scxml`, `crc32.scxml` | |
| 3 | Batch header byte, present only when compression was negotiated, then an LZ4 body | `io/zenoh-transport/src/common/batch.rs` @ `const COMPRESSION: u8 = 1; // 1 << 0` | B | `crates/wz-session-core/src/compression.rs:52,78` | S (LZ4 is a transform); W (the header byte is a flag-input of the batch codec) |
| 4 | A batch is transport messages back to back | `commons/zenoh-codec/src/transport/mod.rs` @ `impl<W> WCodec<&TransportMessage, &mut W> for Zenoh080` | B | `crates/wz-session-core/src/inbound.rs:1097` (dispatch by `header & 0x1F`) | W (`until-eof` repeat of a peek-byte variant); L2 for an unknown id |
| 5 | Low-latency unit: one KeepAlive, Close or network message, not batched | `commons/zenoh-codec/src/transport/mod.rs` @ `id::KEEP_ALIVE => TransportBodyLowLatency::KeepAlive(codec.read(&mut *reader)?),` | B | `crates/wz-session-core/src/network_message.rs:2018` | W |

### 5.2 Transport messages

The handshake messages (rows 6-11) are whole documents: a flags carrier, the
body embedded with the header's flags bound to its flag-inputs, then
`<sce:tlv-chain ... sce:present-if="header.Z" terminate-on="entry-flag">`
(`transport_init.scxml`, `transport_open.scxml`, `transport_close.scxml`,
`transport_keep_alive.scxml`), and the session reads and writes them through
those documents (`inbound.rs` `parse_init`, `handshake_encode.rs`
`encode_init_into`). Every other row has a document for its body and none for
its header byte or its extension chain: the body codecs take the header's flags
as flag-inputs (`join.scxml:60`), and wz reads the header, the chain and, for
`Frame` and `Fragment`, the SN by hand. The network messages (§5.4) show the
whole shape is expressible (`sources/codecs/push.scxml:92`).

Two places of the moved rows stay hand-written, both on the wz side. The
lend-only Open writes its head and its chain under two session mutexes, one
after the other, so its header byte is computed by `handshake_encode.rs`
`open_head_byte` from the document's own derivation of A and T, the chain not
being there to derive Z from. The upstream refusals of an unknown mandatory
extension and of the reserved encoding stay where they are judged (L2, rows
100-101).

| # | Item | Upstream | Class | wz | Cause |
|---|---|---|---|---|---|
| 6 | InitSyn | `commons/zenoh-codec/src/transport/init.rs` @ `impl<W> WCodec<&InitSyn, &mut W> for Zenoh080` | A | `transport_init.scxml` (body `init_body.scxml`) | |
| 7 | InitAck | `commons/zenoh-codec/src/transport/init.rs` @ `impl<W> WCodec<&InitAck, &mut W> for Zenoh080` | A | as 6 | |
| 8 | OpenSyn | `commons/zenoh-codec/src/transport/open.rs` @ `impl<W> WCodec<&OpenSyn, &mut W> for Zenoh080` | A | `transport_open.scxml` (body `open_body.scxml`); the lend-only head's header byte by hand | S (the T flag's lease unit) |
| 9 | OpenAck | `commons/zenoh-codec/src/transport/open.rs` @ `impl<W> WCodec<&OpenAck, &mut W> for Zenoh080` | A | as 8 | S (as 8) |
| 10 | Close | `commons/zenoh-codec/src/transport/close.rs` @ `impl<W> WCodec<&Close, &mut W> for Zenoh080` | A | `transport_close.scxml` (body `close.scxml`) | |
| 11 | KeepAlive | `commons/zenoh-codec/src/transport/keepalive.rs` @ `impl<W> WCodec<&KeepAlive, &mut W> for Zenoh080` | A | `transport_keep_alive.scxml` | |
| 12 | Frame | `commons/zenoh-codec/src/transport/frame.rs` @ `impl<W> WCodec<&FrameHeader, &mut W> for Zenoh080` | B | `frame.scxml:38-39` (SN, payload as `tail`); decode reads SN and chain by hand, `inbound.rs:902` | W; L5 (the payload is not the batch's tail, row 25) |
| 13 | Fragment | `commons/zenoh-codec/src/transport/fragment.rs` @ `impl<W> WCodec<&FragmentHeader, &mut W> for Zenoh080` | B | `fragment.scxml:36-37`; header, SN and chain by hand | W; S (reassembly is state across messages) |
| 14 | Join | `commons/zenoh-codec/src/transport/join.rs` @ `impl<W> WCodec<&Join, &mut W> for Zenoh080` | B | body `join.scxml`; header, T unit and chain `join_decode.rs:20`, `inbound.rs:1235` | W; S (T: `commons/zenoh-codec/src/transport/join.rs` @ `if lease.as_millis() % 1_000 == 0 {`) |
| 15 | Transport OAM | `commons/zenoh-codec/src/transport/oam.rs` @ `impl<W> WCodec<&Oam, &mut W> for Zenoh080` | B | `inbound.rs:1561` by hand; `oam.scxml` has the same layout with the network id as its default | W |

### 5.3 Scouting messages

| # | Item | Upstream | Class | wz | Cause |
|---|---|---|---|---|---|
| 16 | Scout | `commons/zenoh-codec/src/scouting/scout.rs` @ `impl<W> WCodec<&Scout, &mut W> for Zenoh080` | B | body `scout.scxml`; header and chain `scouting_message.rs:123-126` | W |
| 17 | Hello | `commons/zenoh-codec/src/scouting/hello.rs` @ `impl<W> WCodec<&HelloProto, &mut W> for Zenoh080` | B | body `hello.scxml` (L as flag-input); header and chain `scouting_message.rs:146-150` | W |

### 5.4 Network messages and the list a Frame holds

| # | Item | Upstream | Class | wz | Cause |
|---|---|---|---|---|---|
| 18 | Push | `commons/zenoh-codec/src/network/push.rs` @ `impl<W> WCodec<&Push, &mut W> for Zenoh080` | A | `push.scxml` | (L3 on encode, §6.2.3) |
| 19 | Request | `commons/zenoh-codec/src/network/request.rs` @ `impl<W> WCodec<&Request, &mut W> for Zenoh080` | A | `request.scxml` | (L3) |
| 20 | Response | `commons/zenoh-codec/src/network/response.rs` @ `impl<W> WCodec<&Response, &mut W> for Zenoh080` | A | `response.scxml` | (L3) |
| 21 | ResponseFinal | `commons/zenoh-codec/src/network/response.rs` @ `impl<W> WCodec<&ResponseFinal, &mut W> for Zenoh080` | A | `response_final.scxml` | (L3) |
| 22 | Interest (mode in two flags, options byte, restricted key) | `commons/zenoh-protocol/src/network/interest.rs` @ `pub struct InterestOptions {` | A | `interest.scxml:70` (`header.C \|\| header.F`), `interest_body.scxml` | (L3) |
| 23 | Declare | `commons/zenoh-codec/src/network/declare.rs` @ `impl<W> WCodec<&Declare, &mut W> for Zenoh080` | A | `declare.scxml` | (L3) |
| 24 | Network OAM | `commons/zenoh-codec/src/network/oam.rs` @ `impl<W> WCodec<&Oam, &mut W> for Zenoh080` | A | `oam.scxml` | (L3) |
| 25 | The network messages of a Frame, ending at the first byte that is not one | `commons/zenoh-codec/src/transport/frame.rs` @ `reader.rewind(mark);` | B | `network_message.rs:2001` (`RecordsEnd::AtTransportMessage`) | L5 |
| 26 | Dispatch of a network message by id (seven ids) | `commons/zenoh-codec/src/network/mod.rs` @ `impl<W> WCodec<&NetworkMessage, &mut W> for Zenoh080` | B | `network_message.rs:1490` | W (peek-byte variant); L2 for an unknown id |

### 5.5 Declaration bodies

| # | Item | Upstream | Class | wz |
|---|---|---|---|---|
| 27 | DeclareKeyExpr | `commons/zenoh-codec/src/network/declare.rs` @ `impl<W> WCodec<&keyexpr::DeclareKeyExpr, &mut W> for Zenoh080` | A | `decl_kexpr.scxml` |
| 28 | UndeclareKeyExpr | `commons/zenoh-codec/src/network/declare.rs` @ `impl<W> WCodec<&keyexpr::UndeclareKeyExpr, &mut W> for Zenoh080` | A | `undecl_kexpr.scxml` |
| 29 | DeclareSubscriber | `commons/zenoh-codec/src/network/declare.rs` @ `impl<W> WCodec<&subscriber::DeclareSubscriber, &mut W> for Zenoh080` | A | `decl_subscriber.scxml` |
| 30 | UndeclareSubscriber | `commons/zenoh-codec/src/network/declare.rs` @ `impl<W> WCodec<&subscriber::UndeclareSubscriber, &mut W> for Zenoh080` | A | `undecl_subscriber.scxml` (its key extension is row 91) |
| 31 | DeclareQueryable | `commons/zenoh-codec/src/network/declare.rs` @ `impl<W> WCodec<&queryable::DeclareQueryable, &mut W> for Zenoh080` | A | `decl_queryable.scxml` |
| 32 | UndeclareQueryable | `commons/zenoh-codec/src/network/declare.rs` @ `impl<W> WCodec<&queryable::UndeclareQueryable, &mut W> for Zenoh080` | A | `undecl_queryable.scxml` |
| 33 | DeclareToken | `commons/zenoh-codec/src/network/declare.rs` @ `impl<W> WCodec<&token::DeclareToken, &mut W> for Zenoh080` | A | `decl_token.scxml` |
| 34 | UndeclareToken | `commons/zenoh-codec/src/network/declare.rs` @ `impl<W> WCodec<&token::UndeclareToken, &mut W> for Zenoh080` | A | `undecl_token.scxml` |
| 35 | DeclareFinal | `commons/zenoh-codec/src/network/declare.rs` @ `impl<W> WCodec<&common::DeclareFinal, &mut W> for Zenoh080` | A | `decl_final.scxml` |

### 5.6 Zenoh bodies and the OAM body

| # | Item | Upstream | Class | wz |
|---|---|---|---|---|
| 36 | Put, the payload sliced after the shared-memory marker | `commons/zenoh-codec/src/zenoh/put.rs` @ `let codec = Zenoh080Sliced::<u32>::new(ext_shm.is_some());` | A | `msg_put.scxml:160-173` (`extensions.has(0x12)`) |
| 37 | Del | `commons/zenoh-codec/src/zenoh/del.rs` @ `impl<W> WCodec<&Del, &mut W> for Zenoh080` | A | `msg_del.scxml` |
| 38 | Query | `commons/zenoh-codec/src/zenoh/query.rs` @ `impl<W> WCodec<&Query, &mut W> for Zenoh080` | A | `query.scxml` |
| 39 | Reply | `commons/zenoh-codec/src/zenoh/reply.rs` @ `impl<W> WCodec<&Reply, &mut W> for Zenoh080` | A | `reply.scxml` |
| 40 | Err (its payload is never sliced) | `commons/zenoh-codec/src/zenoh/err.rs` @ `let payload: ZBuf = bodec.read(&mut *reader)?;` | A | `err.scxml` |
| 41 | LinkState list, the body of the link-state OAM | `zenoh/src/net/protocol/linkstate.rs` @ `pub(crate) struct LinkState {` | A | `linkstate.scxml`, `linkstate_list.scxml`, `linkstate_link.scxml`, `linkstate_weight.scxml` (links and weights share `links_len`, `linkstate.scxml:139-141`) |

### 5.7 Common types

| # | Item | Upstream | Class | wz | Cause |
|---|---|---|---|---|---|
| 42 | VLE integer (ZInt) | `commons/zenoh-codec/src/core/zint.rs` @ `const VLE_LEN_MAX: usize = vle_len(u64::MAX);` | A | every `sce:bit-size="vle"` | |
| 43 | WireExpr (scope, suffix if N, mapping by M) | `commons/zenoh-codec/src/core/wire_expr.rs` @ `impl<W> WCodec<&WireExpr<'_>, &mut W> for Zenoh080` | A | `wireexpr.scxml`, `wireexpr_local.scxml`, `wireexpr_nonlocal.scxml` | (scope width, §9 F4) |
| 44 | ZenohId, its length less one in four bits, or length-prefixed | `commons/zenoh-codec/src/core/zenohid.rs` @ `impl<W> WCodec<&ZenohIdProto, &mut W> for Zenoh080` | A | `init_body.scxml:78-81` (`length-arith="+1"`), `timestamp.scxml`, `linkstate.scxml` | |
| 45 | Timestamp | `commons/zenoh-codec/src/core/timestamp.rs` @ `impl<W> WCodec<&Timestamp, &mut W> for Zenoh080` | A | `timestamp.scxml` | (L6: upstream refuses an all-zero id, §6.2.6) |
| 46 | Encoding (`id << 1 \| S`, schema) | `commons/zenoh-codec/src/core/encoding.rs` @ `impl<W> WCodec<&Encoding, &mut W> for Zenoh080` | A | `encoding.scxml:64-69` | (schema typed `string`, §9 F3) |
| 47 | ZBuf, a z32-bounded byte run | `commons/zenoh-codec/src/core/zbuf.rs` @ `impl<W> WCodec<&ZBuf, &mut W> for Zenoh080` | A | `ext_zbuf.scxml`, the payload fields | |
| 48 | Sliced ZBuf (count, then kind and bytes per slice) | `commons/zenoh-codec/src/core/zbuf.rs` @ `const SHM_PTR: u8 = 1;` | A | `zbuf_slice.scxml` | |
| 49 | ShmBufInfo, the bytes of a slice whose kind is `SHM_PTR` | `commons/zenoh-codec/src/core/shm.rs` @ `impl<W> WCodec<&ShmBufInfo, &mut W> for Zenoh080` | B | `extshm.rs:104` | W (variant on the slice's kind, body scoped by its length); L6 (`data_len` non-zero) |
| 50 | Locator | `commons/zenoh-codec/src/core/locator.rs` @ `impl<W> WCodec<&Locator, &mut W> for Zenoh080` | A | `locator.scxml` | |
| 51 | EntityGlobalId (zid length in a flags byte, zid, entity id) | `commons/zenoh-protocol/src/network/mod.rs` @ `pub struct EntityGlobalIdType<const ID: u8> {` | B | `source_info_ext.rs:68`, `dissect.rs:1945` | W as a type; every place it occurs is an extension body (L1) |
| 52 | PrioritySn (reliable, best-effort) | `commons/zenoh-codec/src/transport/join.rs` @ `impl<W> WCodec<&PrioritySn, &mut W> for Zenoh080` | A | `join.scxml` (the base pair) | |
| 53 | Extension entry: header, then unit, z64 or zbuf by `enc` | `commons/zenoh-protocol/src/common/extension.rs` @ `pub mod iext {` | A | `ext_entry.scxml`, `ext_unit.scxml`, `ext_zint.scxml`, `ext_zbuf.scxml` | (accepts `0b11`, row 101) |
| 54 | Extension chain of a network or zenoh message (Z continuation) | `commons/zenoh-codec/src/common/extension.rs` @ `pub fn skip_all<R>(reader: &mut R, s: &str) -> Result<(), DidntRead>` | A | `<sce:tlv-chain terminate-on="entry-flag" entry-flag-name="Z">` in every network and zenoh document | |
| 55 | Extension chain of a transport or scouting message | as 54 | B | in the documents of rows 6-11; the other transport and scouting messages `ext_chain.rs` `decode_ext_chain` | W |

### 5.8 Extensions of transport messages

The class of every row is decided by the same fact: the chain decodes each
entry with the generic `ext_entry` codec, and wz picks the entry by its
identity (`ext_view.rs:66`) and reads its body by hand. The typed body of each
row is expressible once the entry can be dispatched by identity (L1); the
column "typed body" says what that body needs beyond L1.

| # | Carrier and extension | Upstream | Class | wz | Typed body; cause |
|---|---|---|---|---|---|
| 56 | Init QoS (unit 0x1) | `commons/zenoh-protocol/src/transport/init.rs` @ `pub type QoS = zextunit!(0x1, false);` | B | `extqos.rs:77` | none; L1 |
| 57 | Init QoSLink (z64 0x1, same id) | `commons/zenoh-protocol/src/transport/init.rs` @ `pub type QoSLink = zextz64!(0x1, false);` | B | `extqos.rs:135` | flags over a VLE carrier; L1 (same id as 56, told apart by encoding) |
| 58 | Init Shm (zbuf 0x2) | `commons/zenoh-protocol/src/transport/init.rs` @ `pub type Shm = zextzbuf!(0x2, false);` | B | `extshm.rs:349`, `dissect.rs:1908` | VLE fields that differ between Syn and Ack (the A flag bound in); L1 |
| 59 | Init Auth (zbuf 0x3) | `commons/zenoh-protocol/src/transport/init.rs` @ `pub type Auth = zextzbuf!(0x3, false);` | B | `extauth.rs:51,67`, `dissect.rs:1686` | a chain of method entries inside the zbuf (`io/zenoh-transport/src/unicast/establishment/ext/auth/mod.rs` @ `let mut exts: Vec<ZExtUnknown> = codec`); L1, L4 |
| 60 | Init MultiLink (zbuf 0x4) | `commons/zenoh-protocol/src/transport/init.rs` @ `pub type MultiLink = zextzbuf!(0x4, false);` | B | `extmultilink.rs:339` | public key bytes; L1 |
| 61 | Init LowLatency (unit 0x5) | `commons/zenoh-protocol/src/transport/init.rs` @ `pub type LowLatency = zextunit!(0x5, false);` | B | `extlowlatency.rs:58` | none; L1 |
| 62 | Init Compression (unit 0x6) | `commons/zenoh-protocol/src/transport/init.rs` @ `pub type Compression = zextunit!(0x6, false);` | B | `extcompression.rs:41` | none; L1 |
| 63 | Init Patch (z64 0x7) | `commons/zenoh-protocol/src/transport/init.rs` @ `pub type Patch = zextz64!(0x7, false);` | B | `extpatch.rs:62` | a plain value; L1 |
| 64 | Init RegionName (zbuf 0x8) | `commons/zenoh-protocol/src/transport/init.rs` @ `pub type RegionName = zextzbuf!(0x8, false);` | B | `extregion.rs:59` | text; L1 |
| 65 | Open QoS (unit 0x1) | `commons/zenoh-protocol/src/transport/open.rs` @ `pub type QoS = zextunit!(0x1, false);` | B | `extqos.rs:77` | none; L1 |
| 66 | Open Shm (zbuf 0x2) | `commons/zenoh-protocol/src/transport/open.rs` @ `pub type Shm = zextzbuf!(0x2, false);` | B | `extshm.rs:406` (the Open bodies) | VLE fields by direction; L1 |
| 67 | Open Auth (zbuf 0x3) | `commons/zenoh-protocol/src/transport/open.rs` @ `pub type Auth = zextzbuf!(0x3, false);` | B | as 59 | as 59; L1, L4 |
| 68 | Open MultiLinkSyn (zbuf 0x4) | `commons/zenoh-protocol/src/transport/open.rs` @ `pub type MultiLinkSyn = zextzbuf!(0x4, false);` | B | `extmultilink.rs:339` | bytes; L1 |
| 69 | Open MultiLinkAck (unit 0x4, same id) | `commons/zenoh-protocol/src/transport/open.rs` @ `pub type MultiLinkAck = zextunit!(0x4, false);` | B | `extmultilink.rs:339` | none; L1 (same id as 68, told apart by encoding) |
| 70 | Open LowLatency (unit 0x5) | `commons/zenoh-protocol/src/transport/open.rs` @ `pub type LowLatency = zextunit!(0x5, false);` | B | `extlowlatency.rs:58` | none; L1 |
| 71 | Open Compression (unit 0x6) | `commons/zenoh-protocol/src/transport/open.rs` @ `pub type Compression = zextunit!(0x6, false);` | B | `extcompression.rs:41` | none; L1 |
| 72 | Open RemoteBound (z64 0x7) | `commons/zenoh-protocol/src/transport/open.rs` @ `pub type RemoteBound = zextz64!(0x7, false);` | B | `extbound.rs:58` | a plain value; L1 |
| 73 | Join QoS (zbuf 0x1, mandatory): eight PrioritySn | `commons/zenoh-codec/src/transport/join.rs` @ `let mut ext_qos = Box::new([PrioritySn::DEFAULT; Priority::NUM]);` | B | `multicast_join.rs:283`, `dissect.rs:1849` | eight pairs; L1, L7 |
| 74 | Join Shm (zbuf 0x2, mandatory) | `commons/zenoh-protocol/src/transport/join.rs` @ `pub type Shm = zextzbuf!(0x2, true);` | C | none (`dissect.rs:8673` keeps it apart from the Init one) | L1 |
| 75 | Join Patch (z64 0x7) | `commons/zenoh-protocol/src/transport/join.rs` @ `pub type Patch = zextz64!(0x7, false);` | B | `multicast_join.rs:63` | a plain value; L1 |
| 76 | Frame QoS (z64 0x1, mandatory) | `commons/zenoh-protocol/src/transport/frame.rs` @ `pub type QoS = zextz64!(0x1, true);` | B | `inbound.rs:560`, `dissect.rs:1438` | flags over a VLE carrier; L1 |
| 77 | Fragment QoS (z64 0x1, mandatory) | `commons/zenoh-protocol/src/transport/fragment.rs` @ `pub type QoS = zextz64!(0x1, true);` | B | as 76 | as 76; L1 |
| 78 | Fragment First (unit 0x2) | `commons/zenoh-protocol/src/transport/fragment.rs` @ `pub type First = zextunit!(0x2, false);` | B | `extfragment.rs:69` | none; L1 |
| 79 | Fragment Drop (unit 0x3) | `commons/zenoh-protocol/src/transport/fragment.rs` @ `pub type Drop = zextunit!(0x3, false);` | B | `extfragment.rs:73` | none; L1 |
| 80 | Transport OAM QoS (z64 0x1, mandatory) | `commons/zenoh-protocol/src/transport/oam.rs` @ `pub type QoS = zextz64!(0x1, true);` | B | `dissect.rs:1438` | as 76; L1 |
| 81 | Auth method usrpwd (unit, z64 or zbuf by handshake step) | `io/zenoh-transport/src/unicast/establishment/ext/auth/usrpwd.rs` @ `pub(super) type InitAck = zextz64!(USRPWD, false);` | B | `dissect.rs` `walk_auth_usrpwd_body`, `auth_dispatch.rs` | user and hash bytes; L1, the step's flag forwarded down |
| 82 | Auth method pubkey (zbuf, unit on OpenAck) | `io/zenoh-transport/src/unicast/establishment/ext/auth/pubkey.rs` @ `pub(super) type InitSyn = zextzbuf!(PUBKEY, false);` | B | `dissect.rs` `walk_pubkey_challenge_body` | key and nonce bytes, different per step; L1, the step's flag forwarded down |

`Close` and `KeepAlive` declare no extension of their own; any entry they carry
falls under §5.11.

### 5.9 Extensions of network messages

| # | Extension and its carriers | Upstream | Class | wz | Typed body; cause |
|---|---|---|---|---|---|
| 83 | QoS (z64 0x1): Push, Request, Response, ResponseFinal, Interest, Declare, OAM | `commons/zenoh-protocol/src/network/push.rs` @ `pub type QoS = zextz64!(0x1, false);`; bits `commons/zenoh-protocol/src/network/mod.rs` @ `const P_MASK: u8 = 0b00000111;` | B | `sample.rs:936`, `declare_ext_qos.rs:141`, `push_build.rs:464` | flags over a VLE carrier; L1 |
| 84 | Timestamp (zbuf 0x2): the same seven | `commons/zenoh-protocol/src/network/push.rs` @ `pub type Timestamp = zextzbuf!(0x2, false);` | B | `request_build.rs:1026`, `dissect.rs:2132` | an embedded `timestamp.scxml` scoped by the length; L1, L6 |
| 85 | NodeId (z64 0x3, mandatory): Push, Request, Interest, Declare | `commons/zenoh-protocol/src/network/push.rs` @ `pub type NodeId = zextz64!(0x3, true);` | B | `ext_nodeid.rs:41` | a plain value; L1 |
| 86 | TsStack (zbuf 0x7): Push, Request, Response | `commons/zenoh-protocol/src/network/push.rs` @ `pub type TsStack = zextzbuf!(0x7, false);` | B | `ts_stack.rs:33` | flags byte, count, interceptions (`max-count`); L1, L6 (`commons/zenoh-codec/src/network/timestamp_stack.rs` @ `if conf_flags == 0 {`) |
| 87 | Target (z64 0x4, mandatory): Request | `commons/zenoh-protocol/src/network/request.rs` @ `pub type Target = zextz64!(0x4, true);` | B | `request_routing_context.rs:82` | an enum; L1 |
| 88 | Budget (z64 0x5): Request | `commons/zenoh-protocol/src/network/request.rs` @ `pub type Budget = zextz64!(0x5, false);` | B | `request_build.rs:879` | a non-zero value; L1, L6 |
| 89 | Timeout (z64 0x6): Request | `commons/zenoh-protocol/src/network/request.rs` @ `pub type Timeout = zextz64!(0x6, false);` | B | `request_routing_context.rs:133` | a plain value; L1 |
| 90 | ResponderId (zbuf 0x3): Response | `commons/zenoh-protocol/src/network/response.rs` @ `pub type ResponderId = zextzbuf!(0x3, false);` | B | `dissect.rs:1945` (read only) | EntityGlobalId (row 51); L1 |
| 91 | WireExpr (zbuf 0x0f, mandatory): UndeclareSubscriber, UndeclareQueryable, UndeclareToken | `commons/zenoh-protocol/src/network/declare.rs` @ `pub type WireExprExt = zextzbuf!(0x0f, true);`; suffix unprefixed `commons/zenoh-codec/src/network/declare.rs` @ `zriter.write_exact(wire_expr.suffix.as_bytes())?;` | B | `declare_ext_keyexpr.rs:58`, `dissect.rs:1983` | flags byte, scope, suffix as `tail` of the scope; L1 |
| 92 | QueryableInfo (z64 0x01): DeclareQueryable | `commons/zenoh-protocol/src/network/declare.rs` @ `pub type QueryableInfo = zextz64!(0x01, false);` | B | `queryable_info.rs:37` | flags over a VLE carrier (complete, distance); L1 |

### 5.10 Extensions of zenoh bodies

| # | Extension and its carriers | Upstream | Class | wz | Typed body; cause |
|---|---|---|---|---|---|
| 93 | SourceInfo (zbuf 0x1): Put, Del, Query, Err | `commons/zenoh-protocol/src/zenoh/put.rs` @ `pub type SourceInfo = zextzbuf!(0x1, false);`; layout `commons/zenoh-codec/src/zenoh/mod.rs` @ `let flags: u8 = (id.zid.size() as u8 - 1) << 4;` | B | `source_info_ext.rs:68`, `dissect.rs:1930` | flags byte, zid, entity id, SN; L1 |
| 94 | Shm marker (unit 0x2, mandatory): Put | `commons/zenoh-protocol/src/zenoh/put.rs` @ `pub type Shm = zextunit!(0x2, true);` | A | `msg_put.scxml:165-173` (`extensions.has(0x12)` decides the payload) | |
| 95 | Shm marker (unit 0x2, mandatory): Err | `commons/zenoh-protocol/src/zenoh/err.rs` @ `pub type Shm = zextunit!(0x2, true);` | B | `extshm.rs:136` | none; L1 |
| 96 | Attachment (zbuf; 0x3 Put, 0x2 Del, 0x5 Query) | `commons/zenoh-protocol/src/zenoh/put.rs` @ `pub type Attachment = zextzbuf!(0x3, false);` | B | `attachment.rs:38` | plain bytes (the generic zbuf arm); L1 for the choice of entry |
| 97 | QueryBody (zbuf 0x3): encoding, then the payload to the end of the extension | `commons/zenoh-protocol/src/zenoh/query.rs` @ `pub type QueryBodyType = crate::zenoh::ext::ValueType<{ ZExtZBuf::<0x03>::id(false) }, 0x04>;`; `commons/zenoh-codec/src/zenoh/mod.rs` @ `let Some(len) = header.len.checked_sub(start - end) else {` | B | `query_value_zbuf.scxml` reads it sliced after the marker; the plain form by hand, `query_value_ext.rs:114` | embedded encoding, payload as `tail` of the scope; L1 |
| 98 | Shm marker before the QueryBody (unit 0x4) | `commons/zenoh-codec/src/zenoh/mod.rs` @ `let ext_shm = if iext::eid(self.header) == SID {` | A | `query.scxml:146` (`<sce:entry-flag-bind ... previous-entry-id="0x4"/>`) | |

### 5.11 Extensions nobody declared

| # | Item | Upstream | Class | wz | Cause |
|---|---|---|---|---|---|
| 99 | Unknown identity, M clear: kept, body read by `enc` | `commons/zenoh-codec/src/common/extension.rs` @ `impl<R> RCodec<(ZExtUnknown, bool), &mut R> for Zenoh080Header` | A | `ext_entry.scxml` default arm | |
| 100 | Unknown identity, M set: the whole message is refused | `commons/zenoh-codec/src/common/extension.rs` @ `if u.is_mandatory() {` | B | `ext_admit.rs:329`, one layer above the decode by design (`ext_admit.rs:31`) | L2 |
| 101 | Encoding `0b11`, reserved: refused | `commons/zenoh-codec/src/common/extension.rs` @ `let body = match self.header & iext::ENC_MASK {` | C | refused only in the transport OAM body (`inbound.rs:1605`); a chain entry reads it as unit (`ext_entry.scxml:77`) | L2 |

wz also carries an extension upstream does not have, a hop limit
(`push_routing_context.rs:80`); it is outside this census.

### 5.12 Counts

| Section | Rows | A | B | C |
|---|---|---|---|---|
| 5.1 framing and batch | 5 | 2 | 3 | 0 |
| 5.2 transport messages | 10 | 6 | 4 | 0 |
| 5.3 scouting | 2 | 0 | 2 | 0 |
| 5.4 network messages | 9 | 7 | 2 | 0 |
| 5.5 declaration bodies | 9 | 9 | 0 | 0 |
| 5.6 zenoh and OAM bodies | 6 | 6 | 0 | 0 |
| 5.7 common types | 14 | 11 | 3 | 0 |
| 5.8 transport extensions | 27 | 0 | 26 | 1 |
| 5.9 network extensions | 10 | 0 | 10 | 0 |
| 5.10 zenoh body extensions | 6 | 2 | 4 | 0 |
| 5.11 unknown extensions | 3 | 1 | 1 | 1 |
| **Total** | **101** | **44** | **55** | **2** |

By cause, over the 57 rows of (B) and (C) (a row may have more than one):

| Cause | Rows | Which |
|---|---|---|
| L1 | 41 | 56-82, 83-93, 95-97 (every typed extension) |
| L2 | 4 | 4, 26, 100, 101 |
| L4 | 2 | 59, 67 |
| L5 | 2 | 12, 25 |
| L6 | 4 | 49, 84, 86, 88 (and row 45 among the (A) rows) |
| L7 | 1 | 73 |
| W | 13 | 3, 4, 5, 12-17, 26, 49, 51, 55 |
| S | 3 | 3, 13, 14 (and rows 8, 9 among the (A) rows) |

L3 is the cause of no (B) row: it shows on the encode side of 21 (A) rows
(18-24, 27-35, 36-40), §6.2.3.

## 6. The causes

### 6.1 The candidates the question named

| Candidate | Verdict | Why |
|---|---|---|
| A field present or absent by a condition | expressible | `sce:present-if` on a carrier flag, a flag-input, a disjunction (xsd:668-682); Interest's two-flag mode is `header.C \|\| header.F` (`interest.scxml:70`) |
| A length or a flag deciding a later field | expressible | `length-ref`, `length-arith="+1"` (the zid), a flags carrier over a VLE (`encoding.scxml:64`), a flag the parent binds (`<sce:flag-bind>`), `<chain>.has(v)` (`msg_put.scxml:165`), an input the previous entry decides (`query.scxml:146`) |
| The chain's Z bit repeated | expressible | `<sce:tlv-chain terminate-on="entry-flag" entry-flag-name="Z">`, the flag derived on encode (ADR 0058:66-80); the one shape it does not cover is an empty chain in a scope, L4 |
| Skip or refuse an unknown extension by its M bit | blocked, L2 | skipping is the default arm (row 99); refusing has no element (§6.2.2) |
| The body's encoding (unit, z64, zbuf) depending on the id | blocked, L1 | the generic decode by `enc` is expressible (`ext_entry.scxml`); a typed body chosen by the identity, with the generic one for the rest, is not (§6.2.1) |

### 6.2 Where the language blocks

#### 6.2.1 L1: a body chosen by the extension's identity

Upstream tells one extension from another by its identity, the header without
the continuation flag (`commons/zenoh-protocol/src/common/extension.rs` @
`pub const fn eid(header: u8) -> u8 {`): id, M and encoding together. Two
extensions of one carrier may share an id and differ by encoding (rows 56/57,
68/69), and the same identity means different things on different carriers
(`0x3` is NodeId on a Push and ResponderId on a Response). A document that
types the bodies therefore needs, per carrier, an entry codec that

1. reads one header byte whose flags are `ext_id` (4 bits), `M`, `enc` (2 bits)
   and `Z`;
2. selects a typed body by the seven low bits;
3. reads every other identity by `enc`, as row 99 does today;
4. ends the chain on its own `Z` flag.

The language cannot state 2 and 3 together:

- A variant's tag is one field or one flag of the codec (xsd:1339-1347). A flag
  over bits 0-6 cannot coexist with flags `ext_id`, `M` and `enc` over the same
  bits, since flags may not overlap (xsd:1479). Without an `enc` flag the
  fallback of step 3 cannot be dispatched.
- A peek-byte variant over the entry keeps the header for every arm
  (xsd:1414-1421), but the chain then has no carrier of its own to read `Z`
  from: the chain looks the continuation flag up among the entry codec's own
  fields (`sce-build/src/forge/encode_plan.rs:1412`, pin 1408).
- Dispatching on `header.ext_id` and then, inside the arm, on `enc` needs the
  arm to receive a two-bit value from its parent. A flag-input is one bit
  (xsd:1227); two one-bit flags would need `e0 && !e1`, and the predicate
  grammar has no `&&` (`SCE_FORGE.md:1410`). `<sce:variant-dispatch>`, which
  hands a parent's flag to a caller-tag variant, is validated on embedded
  fields (`sce-build/src/forge/generator.rs:17118`, pin 14012); this reading
  found no statement that it applies to a codec used as a variant arm.

wz therefore decodes every entry with the generic codec and does the rest by
hand three times over: picks the entry by identity (`ext_view.rs:66`, over the
walk of `ext_view.rs:120`), names it from a per-carrier table
(`ext_name.rs:299-441`), and reads its body in a participant module (§5.8-5.10)
and again in a dissector walker (`dissect.rs:1166`, `dissect.rs:1318`). The
typed bodies themselves need nothing new except L4, L6 and L7: a z64 body with
sub-fields is a flags carrier over a VLE, and a zbuf body is a length then an
embed scoped by it (`sce:length-from`).

#### 6.2.2 L2: refusing

A variant without `<sce:default>` must cover its tag's whole domain
(`sce-build/src/forge/parser.rs:5873`), and the runtime has no unknown-tag
error for that reason (`backends/rust/forge-runtime/src/codec.rs:30`). An arm
left out by a build feature is refused (ADR 0072), but only where its tag is
named. So no document can say:

- an extension with M set whose identity no arm names is refused (row 100);
- encoding `0b11` is refused (row 101), which upstream does for every
  extension, M or not;
- a message id no arm names is refused (rows 4, 26): with a default arm
  required, the dispatch accepts what upstream rejects.

wz keeps decode lenient on purpose and judges admissibility one layer up,
because the analyzer must show a message the participant refuses
(`ext_admit.rs:31`). The language element should therefore let one document
serve both builds, the way an arm's build feature already does.

#### 6.2.3 L3: a fixed bit range

`<sce:flag value=>` sets only the carrier's `Default` (xsd:1501), and ADR 0058
makes every element the encoder does not derive a presented one, header bits
included (lines 74-80). The generated Push derives N, M and Z and takes the
message id from the value (`out/wz-codecs/push.rs:543`), defaulting it to
`0x1d` (`out/wz-codecs/push.rs:129`); its decode reads the byte without
checking the id (`out/wz-codecs/push.rs:225-230`). The builders write the id
(for example `push_build.rs:109`), and an extension's id and M bit
(`push_build.rs:464`). Measured on this tree, `grep -rn --include=*.rs -E
'\bheader:\s' --exclude-dir=target crates` gives 687 lines, 602 outside the
`wz-zenoh-*` crates and 363 in `crates/wz-session-core/src`; not every one is
a codec header, so the count is an upper bound, and the derived flags these
sites still spell are redundant rather than wrong.

#### 6.2.4 L4: a chain that may be empty

The authentication extension's body is a list of method entries, read while
bytes remain and then until an entry's Z is clear
(`commons/zenoh-codec/src/common/extension.rs` @ `let mut has_ext = reader.can_read();`).
An entry-flag chain holds one entry or more (`SCE_FORGE.md:1436`, pin 1328),
so an empty body fails it; an exhaust-or-depth chain reads the empty body but
ignores Z, and so reads past an entry upstream ends on.

#### 6.2.5 L5: a list that ends at a byte it does not know

A Frame's network messages run until one fails to decode, and the reader then
rewinds and hands the rest of the batch to the transport loop
(`commons/zenoh-codec/src/transport/frame.rs` @ `reader.rewind(mark);`,
`io/zenoh-transport/src/unicast/universal/rx.rs` @ `while !batch.is_empty() {`).
The network ids are `0x19`-`0x1f` (`commons/zenoh-protocol/src/network/mod.rs`
@ `pub const INTEREST: u8 = 0x19;`) and the transport ids `0x00`-`0x07`
(`commons/zenoh-protocol/src/transport/mod.rs` @ `pub const JOIN: u8 = 0x07; // For multicast communications only`),
so the list ends exactly where the next byte's id names no network arm. A
`<sce:repeat>` ends on a count or at the end of its scope (xsd:1560-1564), and
`frame.scxml:39` reads the payload as the batch's `tail`, which is wrong for a
batch with a second transport message; wz ends the list by hand
(`network_message.rs:2001`). A malformed network message is refused either
way: upstream's transport loop fails on it (`io/zenoh-transport/src/unicast/universal/rx.rs`
@ `let msg: TransportMessage = batch`), which is this document's reading and was
not run.

#### 6.2.6 L6 and L7, minor

Upstream refuses a few values that are layouts in every other respect: an
all-zero timestamp id (`commons/zenoh-codec/src/core/timestamp.rs` @
`let id = uhlc::ID::try_from(&id[..size])`, which refuses an id that is zero in
uhlc 0.8.2, the version upstream's lockfile resolves), a timestamp stack
whose flags are zero (row 86), a zero budget (row 88), a zero ShmBufInfo length
(row 49). A small field can be typed as an enum, which already refuses an
undeclared value; a VLE or a byte string has no such check. The Join QoS body
is exactly eight pairs (row 73), which eight named embeds express today.

### 6.3 What is on the wz side (W)

Every row marked W is expressible with the elements of §3: a transport or
scouting message is the same shape as a network message (flags carrier, body,
Z-gated chain); a batch is an `until-eof` repeat of a peek-byte variant; the
low-latency unit is a peek-byte variant with a network-message default; a
compressed batch's header byte is a flag-input of the batch codec. wz's
transport documents predate the chain and peek-byte elements and were never
extended (`inbound.rs:1235` says the Join codec "has no ext awareness"); the
hand code that replaced them is also where the in-place receive path lends
records (`network_message.rs:1490`). Moving them into documents is a wz task
and asks nothing of SCE, except L2 for the exact refusal of an unknown id.

### 6.4 Outside a codec (S)

Fragment reassembly is state across messages. LZ4 is a transform, an
`algorithm` and not a layout. The T flag of Open and Join chooses the unit of
the lease (`commons/zenoh-codec/src/transport/join.rs` @ `if lease.as_millis() % 1_000 == 0 {`):
the wire is a VLE and a flag, both expressible; the unit is a projection.

## 7. Proposals: the least the language needs

| # | Closes | Element | Effect |
|---|---|---|---|
| P1 | L1 | `<sce:variant tag="header" tag-except="header.Z">`: the tag is a whole carrier with named flags cleared, as `entry-id-except` already does for a chain (`SCE_FORGE.md:1385`, pin 1277) | the entry keeps its flags `ext_id`, `M`, `enc`, `Z`, dispatches on the identity, and the chain still ends on `header.Z` |
| P2 | L1 | `<sce:variant-dispatch flag="header.enc"/>` honoured where the import is a variant arm or the `<sce:default>`, not only an embed | the fallback for an unknown identity is a caller-tag variant on `enc`: today's `ext_entry` body, reused |
| P3 | L2 | `<sce:refuse mask="0x10" value="0x10"/>` in a `<sce:variant>`, read after the arms and before `<sce:default>`: a tag no arm names and that matches `tag & mask == value` is refused by the decode with a typed error, and no value can hold it; `feature=` as on an arm (ADR 0072) | with P1's tag, M-set unknowns (`0x10`/`0x10`) and the reserved encoding (`0x60`/`0x60`); on a message dispatch, unknown ids (`0x00`/`0x00`, every tag no arm names); refused in the strict build and kept in the lenient one, from one document |
| P4 | L3 | `<sce:flag ... fixed="0x1D"/>`: the decode refuses another value, the encode writes it, the value has no member for it | the message id leaves every builder; a top-level decode refuses a byte of another message |
| P5 | L4 | `<sce:tlv-chain terminate-on="entry-flag" empty-at-end="true">`: no entry when the scope ends where the chain starts | the authentication method list |
| P6 | L5 | `<sce:repeat until="unmatched">` over an element that is a peek-byte variant with no default: the repeat stops, consuming nothing, before a byte whose tag no arm names; the exhaustiveness rule does not apply to such an element | a Frame's network messages, with the transport message after them left to the batch |
| P7 | L7, optional | `count="8"`, a literal count | the Join QoS body in one repeat |
| P8 | L6, optional | a value constraint on a VLE or byte field (`sce:refuse-value="0"`) | the non-zero rules of §6.2.6 |

P1 with P2 is the alternative to multi-bit flag-inputs (the xsd defers them to
"a reachable consumer", xsd:1227): either lets the fallback read `enc`, and P2
reuses an element that exists. No proposal changes how an existing document
reads.

## 8. Conclusion

The skeleton of every zenoh 1.10.2 message is writable now; wz's hand-written
transport, scouting and dispatch code is wz's to move into documents. The
language blocks at five places, all named in §6.2: the typed body of an
extension chosen by its identity (41 rows, L1), refusal (L2), a fixed bit range
(L3), a possibly empty Z-terminated chain (L4) and a list that ends at a byte
it does not know (L5). P1 to P6 close them; P7 and P8 remove the two
workarounds that remain.

## 9. What this census found on the wz side

Recorded here, not changed: this document changes no code.

- **F1.** A chain entry with encoding `0b11` and M clear is read as a unit
  (`ext_entry.scxml:77`) and admitted (`ext_admit.rs:329-340` judges M only),
  while upstream refuses the message (row 101); no refusal of it was found
  outside the transport OAM body (`inbound.rs:1605`). The comment at
  `ext_entry.scxml:48-49` says upstream only logs it; at 1.10.2 it returns an
  error.
- **F2.** The per-carrier name table, which the mandatory rule reads too
  (`ext_name.rs:288-296`), disagrees with 1.10.2: Open's Shm is listed as z64
  (`ext_name.rs:314`) where upstream declares a zbuf (row 66); Init has no
  RegionName row (row 64), Open no RemoteBound row (row 72), and Push, Request
  and Response no TsStack row (row 86). All four are optional extensions, so
  admission is unaffected and naming is.
- **F3.** `encoding.scxml:69` types the schema as `string`, so a schema that is
  not UTF-8 is refused; upstream holds it as bytes
  (`commons/zenoh-codec/src/core/encoding.rs` @ `let zodec = Zenoh080Bounded::<u8>::new();`).
- **F4.** wz reads expression scopes and request ids as `uint64`; upstream
  bounds them to 16 and 32 bits (`commons/zenoh-codec/src/core/wire_expr.rs` @
  `let zodec = Zenoh080Bounded::<ExprId>::new();`,
  `commons/zenoh-codec/src/network/request.rs` @ `let id: RequestId = bodec.read(&mut *reader)?;`).
  wz accepts more than upstream; `sce:type="uint16"` with `vle` would match.

## 10. Not established

- No document proposed here was written, generated or built.
- Whether `<sce:variant-dispatch>` already works on a variant arm was judged
  from the validator's comment only (§6.2.1).
- Whether a peek-byte variant may be the element of a `<sce:repeat>` was not
  checked against the generator; §6.3 assumes it, as a chain's entry may be a
  variant (`ext_entry.scxml`).
- The equivalence claimed for L5 on a malformed network message is a reading
  of upstream's loop, not a run.
