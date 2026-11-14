# The shared-memory transport

How a payload in shared memory crosses a link of wz without its bytes being copied: the contract
upstream's transport keeps at the pin, the state machine and the wire wz carries it with, the rules
by which it falls back to the bytes, the build switches, what is built today, and the stages left.
The summary of the slice in the API seam is `docs/zenoh-api-on-the-engine.md`, Z7t; this note is the
design it points at. Every upstream reference is written `path` @ `needle` against the pinned tree.

## 1. The contract, at the pin

### 1.1 Negotiation (unicast)

Shared memory is agreed per transport, in the establishment, by the `Shm` extension of the four
messages (`io/zenoh-transport/src/unicast/establishment/ext/shm/auth.rs` @ `pub(crate) struct InitSyn {`):

| message | what the extension carries |
|---|---|
| InitSyn | the initiator's (Alice's) auth segment id |
| InitAck | the challenge Bob read from Alice's segment, and Bob's auth segment id |
| OpenSyn | the challenge Alice read from Bob's segment, and Alice's handoff counters |
| OpenAck | Bob's handoff counters |

Each side proves it can map the other's segment by echoing a value only the segment holds. Both
commit only at the Open phase: an OpenSyn whose challenge does not match is refused
(`io/zenoh-transport/src/unicast/establishment/ext/shm/auth.rs` @
`bail!("{} Challenge mismatch: refusing the SHM proposal", S);`), an OpenAck that answers no offer is
ignored (`io/zenoh-transport/src/unicast/establishment/ext/shm/auth.rs` @ `async fn recv_open_ack(`),
and a segment that cannot be opened at the Init phase leaves the step plain. The handoff counters are
a back-pressure ledger per priority: a sender counts the buffers it handed a receiver and the
receiver counts them back as it maps them
(`io/zenoh-transport/src/unicast/establishment/ext/shm/handoff.rs` @
`pub struct TxHandoffStorage(HandoffConfig<TxHandoff>);`).

### 1.2 Multicast

A group negotiates nothing. Upstream builds its Join with no shared-memory extension
(`io/zenoh-transport/src/multicast/link.rs` @ `ext_shm: None,`) and treats every member as able to
read any protocol (`io/zenoh-transport/src/common/shm/interop.rs` @
`pub struct MulticastTransportShmConfig;`). A member whose session has a shared-memory context (its
configuration enables shared memory) maps every message it sends for that partner, a buffer to its
descriptor and a large payload to a copy, with the handoff counters disabled
(`io/zenoh-transport/src/multicast/tx.rs` @ `&TxHandoffStorage::new_disabled(),`), and maps every
descriptor it receives back into a buffer
(`io/zenoh-transport/src/multicast/rx.rs` @
`&RxHandoffChannel::Disabled, // Multicast transport is unreliable, so it don't support SHM handoff`).
A member with no context maps nothing on either side: it sends a buffer as its bytes, and a
descriptor it receives is handed up unmapped, in the place of the data. wz's member refuses such a
message instead, as it refuses a descriptor on any link that did not negotiate shared memory
(section 4, rule 5): neither crate hands the data to that member, and wz does not hand it the
descriptor as data either. This is the one difference the differential holds by name.

### 1.3 The wire

A buffer in shared memory is a slice of a payload `ZBuf` whose kind is a pointer into shared memory.
On the wire that slice is `ShmBufInfo` (`commons/zenoh-shm/src/lib.rs` @ `pub struct ShmBufInfo {`):
the length of the data, the metadata segment and the slot in it that names the chunk, and the slot's
generation, each as a variable-length integer
(`commons/zenoh-codec/src/core/shm.rs` @ `impl<W> WCodec<&ShmBufInfo, &mut W> for Zenoh080`). The body
of a Put, a Query, a Reply or an Err that carries such a slice says so with the unit extension `Shm`,
id 2 with the mandatory bit, so that a node that does not read shared memory refuses the message
rather than reading a descriptor as data (`commons/zenoh-protocol/src/zenoh/put.rs` @
`pub type Shm = zextunit!(0x2, true);`).

### 1.4 Sending

At the link, per transport that negotiated shared memory, each message is mapped for its partner
(`io/zenoh-transport/src/common/shm/interop.rs` @
`pub fn map_zmsg_to_partner<ShmCfg: PartnerShmConfig>(`, called from
`io/zenoh-transport/src/unicast/universal/tx.rs` @ `crate::common::shm::interop::map_zmsg_to_partner(`):

- a slice that is a buffer of shared memory goes as its descriptor when the partner reads its
  protocol, and as its bytes when it does not;
- a slice of plain bytes at least `message_size_threshold` long is copied into the provider of the
  transport and sent as a descriptor (the implicit optimisation,
  `io/zenoh-transport/src/common/shm/interop.rs` @ `fn wrap_in_place<const ID: u8>(`), for the
  categories the configuration lists (`io/zenoh-transport/src/common/shm/interop.rs` @
  `pub struct ShmOptimizationPolicy {`: put, query, reply; an Err reply follows `reply`), and only
  when the provider is ready;
- anything else goes as it is.

A message delivered inside the node (to a subscriber or a queryable of the same session) passes no
link and is not mapped: the application gets what was given.

### 1.5 Receiving

Before a message is routed, every slice that is a descriptor is mapped back into a buffer by the
reader of the process and the receipt is counted on the handoff
(`io/zenoh-transport/src/common/shm/interop.rs` @ `pub fn map_zmsg_to_shmbuf(`, called from
`io/zenoh-transport/src/unicast/universal/rx.rs` @
`if let Err(e) = crate::common::shm::interop::map_zmsg_to_shmbuf(`). The application receives the
buffer itself (`ZBytes::as_shm` is `Some`).

### 1.6 Configuration

`transport/shared_memory`: `enabled` (true), `mode` (`lazy`; `init` initialises the subsystem at the
open), and `transport_optimization`: `enabled` (true), `pool_size` (16 MiB), `message_size_threshold`
(3072) and `messages` (`["put", "query", "reply"]`). The provider of the implicit optimisation is the
transport manager's (`io/zenoh-transport/src/common/shm/shm_context.rs` @ `pub struct ShmContext {`),
and it is the one `Session::get_shm_provider` hands out.

## 2. What wz has

| piece | where | what it is |
|---|---|---|
| descriptor, body marker, establishment codecs, `ShmAuthDispatch` | `wz_session_core::extshm` | the no_std half: the wire and the state machine of section 3, and the seams `ShmSendBuffer`, `ShmReservation`, `ShmResolver`, `ShmHandoff` |
| receive state of a registry | `wz_session_core::extshm::ShmReceiveState` | the negotiated flag, the resolver, the handoff, the drop counters, the un-swap of a Put, a value and a reply |
| auth segment and handoff counters | `wz_runtime_tokio::shm_auth_segment`, `shm_watchdog` | the transport's own segment, the counters, and their poll |
| the engine's POSIX provider and reader | `wz_runtime_tokio::shm_provider`, `shm_backend`, `shm_posix_backend`, `posix_shm`, `shm_clients` | what the C ABI allocates from and reads with |
| the router's relay pass | `wz_runtime_tokio::shm_relay` | holds the chunks of a message while it is routed and re-expresses them per face |
| `zenoh-shm` | `crates/wz-zenoh-shm` | upstream's crate, by its name and surface: the Rust API's provider, buffers and reader |
| the top crate's adapter | `zenoh::api::shm::transport` (`crates/wz-zenoh/src/api/shm.rs`) | a `ZBytes` slice as the engine's send buffer, `ShmReader` as its resolver, and `Promoter`, the implicit optimisation of a put, a query value and a reply |

What crosses a link without a copy, by path (registry = the registry of faces, node = a router node):

| path | send | receive |
|---|---|---|
| put, unicast | registry and node | registry and node |
| put, multicast group | registry (`publish_shm_on_group`) | registry |
| value of a get | registry and node | registry and node |
| reply | registry and node | registry and node |
| error reply | its bytes (section 4, rule 7) | its inline bytes |
| implicit optimisation | put, value of a get, reply; registry and node | - |

Upstream's own `shm` test file passes 10 of 10 against the patched graph (`docs/z8-expected.tsv`).

## 3. The state machine of the establishment, as wz runs it

`ShmAuthDispatch` (`crates/wz-session-core/src/extshm.rs`) is installed on a session that offers
shared memory; a session that does not install it offers nothing and answers an offer plain.

Initiator:

1. `send_init_syn`: the extension with its auth segment id.
2. `recv_init_ack`: with no extension the acceptor made no offer and the session goes on plain. An
   extension is an offer, and the offer is recorded before it is checked; a body that does not
   decode, a challenge that is not the initiator's own, or a segment of the acceptor's that cannot
   be mapped leave the initiator with nothing to propose.
3. `send_open_syn`: the acceptor's challenge and the counters the initiator leased (`Disabled` on a
   link that is not reliable, where a lost datagram would never be counted back), only when the
   initiator has something to propose.
4. `recv_open_ack`: an extension from an acceptor that made no offer is ignored. After an offer, an
   OpenAck the initiator cannot honour refuses the link (`ShmAuthError`): it proposed nothing (the
   segment was not mapped), the body does not decode, or the counters cannot be opened. Otherwise
   the session is negotiated and its receive state is stamped so.

Acceptor:

1. `recv_init_syn`: an extension that does not decode, or a segment that cannot be mapped, is
   ignored and the session goes on plain; this step never refuses the link.
2. `send_init_ack`: the initiator's challenge and the acceptor's segment, only when the initiator's
   segment was mapped.
3. `recv_open_syn`: an OpenSyn with no extension, or one over a segment the acceptor never mapped, is
   ignored. Otherwise a body that does not decode, a challenge that is not the acceptor's own, or
   counters that cannot be opened refuse the link.
4. `send_open_ack`: the acceptor's counters, only when it accepted the OpenSyn (upstream sends it
   whenever the extension is engaged; wz's acceptor that refused stays silent); the session is
   negotiated.

The negotiated flag is restamped on the receive state of every registry of the session
(`ShmReceiveState::set_negotiated`), and a descriptor that arrives on a session that did not
negotiate is refused and counted, never mapped and never handed up as data.

## 4. When a buffer goes as its bytes

The rules, each of which is a copy and never a loss:

1. The link did not negotiate shared memory: a buffer goes as its bytes (`ShmSendHandle::bytes`).
2. The partner's reader does not take the buffer's protocol (`shm_admits`): its bytes.
3. The implicit optimisation finds the provider not ready, the payload under the threshold, or its
   category not listed: the payload goes as it is.
4. A router routes a descriptor it holds no chunk for: the message is dropped and counted, as
   upstream drops one it cannot map; a face that does not read shared memory is sent the bytes of
   the chunk the pass holds.
5. On receipt, a descriptor that does not resolve drops the message and is counted; the descriptor
   is never handed up in place of the data.
6. A subscriber or a getter of the same session is handed the buffer the application gave, and for
   a payload the implicit optimisation copied, the bytes it was given, as upstream (which maps at the
   link) does.
7. An error reply goes as its bytes, whatever its payload is. Upstream's codec writes the payload of
   an Err flat (`commons/zenoh-codec/src/zenoh/err.rs` @ `let bodec = Zenoh080Bounded::<u32>::new();`),
   so a buffer that upstream maps into an Err leaves as its data in line, with the marker set and
   the buffer counted on the sender's handoff
   (`io/zenoh-transport/src/common/shm/interop.rs` @ `handoff_transaction.on_tx(shmb.into());`),
   and the receiver, which reads a slice in line, maps nothing and counts nothing back
   (`io/zenoh-transport/src/common/shm/interop.rs` @ `if zs.kind == ZSliceKind::ShmPtr {`). wz
   sends the bytes without the marker: the receiver reads the same value, upstream's or wz's, and no
   count is left owed on the ledger of the link. An Err that arrives with the marker is read in line.

wz promotes per session and not per link: `Promoter` copies a put, the value of a get or a reply
into the provider when some peer of the session could read it (`has_shm_peer`), and the engine then
sends the descriptor to each face that negotiated shared memory and the bytes to the others, which is
upstream's result per link. A reply to a query of the session itself is not copied. The copy is the
transport's and not the application's (`Holder::Transport` in the adapter): its
`ShmSendBuffer::receiver_view` answers none, and every place the engine hands a receiver of the
sending session a buffer (its own subscribers, queryables and getters, on the registry and on a
node) hands the bytes instead, which is rule 6 by one mechanism. What per session costs is a copy
that a face without shared memory is then sent the bytes of, where upstream would not have copied
for that link.

## 5. Build switches

| crate | feature | what it carries |
|---|---|---|
| `zenoh` (wz-zenoh) | `shared-memory` | `zenoh-shm`, the adapter, the engine's handshake (`wz-capi-core/session-extshm`) |
| `zenoh` (wz-zenoh) | `unstable` with `shared-memory` | the provider of the session (`get_shm_provider`) and `Promoter`; the two keys of the optimisation it acts on |
| `wz-capi-core` | `transport-shm`, `session-extshm` | the data path, and the handshake with the reader of the host |
| `wz-runtime-tokio` | `transport-shm`, `session-extshm` | the POSIX segments, the relay pass, the auth segment and counters |
| `wz-session-core` | `transport-shm`, `session-extshm` | the descriptors and the receive state, and the establishment codec |

A build without them offers nothing in the handshake, answers an offer plain, and refuses a message
that carries the mandatory marker. A configuration that sets `message_size_threshold` or `messages`
to other than the default is refused by name in a build that does not act on them (decision D6 of
the seam note); the top crate with `shared-memory` and `unstable` acts on them
(`acted_on_by_the_session`), for each of the three messages the list can name.

## 6. One shared-memory system per process

The process holds two implementations of upstream's segment protocol: the family crate `zenoh-shm`,
whose types the application holds, and the engine's (`shm_provider`, `shm_backend`,
`shm_posix_backend`, `posix_shm`, `shm_clients`, the segment watchdog of `shm_watchdog`), which the C
ABI allocates from. They agree on the segments, the metadata slots, the reference counts and the
descriptor, so a buffer of either is carried by the engine through the seams of section 2 and never
converted. That is correct, and it is still two of everything: two metadata storages and two
watchdogs in a process that uses both APIs, two readers with two client storages, and every repair of
the protocol (a reference count, a generation check, a watchdog race) to be made twice.

The structure this ends in is upstream's own: one implementation of segments, metadata, watchdog,
provider, reader and client storage in the process, and it is `zenoh-shm`, because that crate carries
upstream's name and surface and is the one an application and an ecosystem crate link (one crate per
package name in a graph). The transport keeps what upstream keeps in its transport and not in
`zenoh-shm`: the auth segment, the handoff counters and the relay pass. The engine's seams
(`ShmSendBuffer`, `ShmResolver`) then have one implementation each, over `ShmBufInner` and
`ShmReader`, owned by the engine behind `transport-shm`; the top crate's adapter becomes that
implementation, and the C ABI's provider (`z_shm_provider_*`) becomes `ShmProvider` over the POSIX
backend, as zenoh-c's is. The cooperative and MCU engines carry no shared memory and are untouched.

The order, each step landing whole with its tests:

1. Measure what each system holds in a process (threads, segments created, lines, the C images'
   sizes with shared memory), so that the result can be compared.
2. The reader: the engine's resolver becomes `ShmReader` over `ShmClientStorage`; `shm_clients` goes.
3. The provider: the C ABI allocates from `ShmProvider`; `shm_provider`'s allocator, `shm_backend`,
   `shm_posix_backend` and `posix_shm` go.
4. The watchdog: the segment watchdog of `shm_watchdog` goes in favour of `zenoh-shm`'s confirmator
   and validator; the poll of the handoff counters stays, it is the transport's.
5. The adapter of the top crate folds into the engine's implementation.

`wz-runtime-tokio` then depends on `crates/wz-zenoh-shm`, which the layer gates allow (it is a crate
below the top crate, not the top crate), and the capability-cost budgets of the C images with shared
memory are measured again in the step that moves them.

## 7. Stages

| stage | what | state |
|---|---|---|
| S1 | establishment, put (unicast and group), value of a get, a router node's session, the implicit optimisation of a put | landed (seam note, Z7t) |
| S2 | a reply in shared memory through the Rust API: the registry stages a reply whose payload is a buffer as the buffer (`ReplyMeta::with_shared`), and a getter is handed it as one (`payload_shared`); a router node reads the chunk of a reply to its own get as it routes it (`LocalFaceEvent::ReplyRead`, `ReplyRegistry::dispatch_response_read`), where its face, which negotiates nothing, used to refuse the descriptor | landed |
| S3 | a reply of a queryable a node hosts as the buffer (`send_hosted_replies`): the chunk is adopted into the relay pass and the response names its descriptor (`QueryReply::into_response_naming`), as `publish_shm_with` does for a put, so that each face is sent the descriptor or the bytes; the node's own get is handed the buffer (`ReplyRead`) | landed |
| S4 | the implicit optimisation of a query's value and of a reply, by `messages` (`Promoter::lists`), with the copy the transport's so that a receiver of the session itself is handed the bytes (section 4); a put takes the same path, in one publication where it took two | landed |
| S5 | an error reply in shared memory | decided: its bytes, section 4, rule 7 |
| S6 | one shared-memory system per process (section 6) | owed |
| S7 | the cross-implementation differential over TCP (`conformance/differential-shm/tests/zenoh_transport_shm.rs`): sessions of both crates in one process, each pair of crates with either one listening, as a peer and as a router (a wz listener is a node, a wz dialler the registry), each direction, for a put, the value of a get and a reply, held equal to what two upstream sessions hand each other, with shared memory off on the dialler as the control (the bytes) | landed |
| S7g | the same differential over a multicast group, for a put between two members that join it, two peers and a router with a peer each way (a wz router there is a node, a wz peer the registry): each pair of crates held equal to two upstream members with the sender's shared memory on and off, and the member without shared memory (section 1.2) held by name, upstream's handed no data and wz's handed nothing | landed |
| S8 | a session in router mode with shared memory: it offers shared memory and reads a descriptor as its configuration says, as every other session of the top crate does (`Engine::open`), since upstream's transport manager makes its shared-memory context whatever the mode (`io/zenoh-transport/src/manager.rs` @ `let shm_context = ShmContext::new(self.shm, self.shm_reader)?;`) | landed |
| S8g | a router node that joins a multicast group carries shared memory there as its configuration says, as an upstream router with a context maps both ways (section 1.2): the group is attached as a shared-memory one (`attach_mcast_group`, from `GroupJoin::is_shm`, which `Engine::open` now reports for a node too); a chunk the relay pass holds goes to such a group as a descriptor with one reference for the group and to any other as its bytes (`ShmRelay::for_group`, the relay of the unicast faces); and a descriptor a member sends is held and mapped where the group is a shared-memory one and refused where it is not (`open_shm_relay_message`) | landed |
