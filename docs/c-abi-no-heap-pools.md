# The C ABI with no heap: inventory, pools and the conversion units

Status: design note, the pool design of decision E3 of `docs/c-abi-engine-and-memory.md`. It
states where the C ABI path the cooperative engine links takes heap memory today, what bounds each
kind of object, the form its memory takes once it is reserved at open, what is refused when a pool
is exhausted, and the order the work is done in. It is not a specification and the atomic store
does not parse it.

## 1. The method, and what the counts are

The path is what a cooperative pico library links: `crates/wz-capi-pico/src`,
`crates/wz-capi-coop/src`, `crates/wz-capi-port/src`, and the session code `wz-capi-coop` names
in its `Cargo.toml` (`wz-session-core`, `wz-runtime-coop`, `wz-session-mcu` with `alloc`,
`dial`, `transport-keepalive` and `reassembly`, and each capability's features). Test files
and a file's trailing test module are left out.

A site is a source line that names a heap type or makes one (`Vec`, `String`, `Box`, `Arc`,
`Rc`, the maps, sets and deques, `to_vec`, `to_owned`, `to_string`, `format!`, `collect`).
That over-counts (a type in a signature counts as an allocation does, and a file that holds both
storage policies counts its heap half) and it is a map of where to look, not a measurement. The
measurement is the allocator count of the P2 ratchet (`no_heap_ratchet_gate.py`), which counts
what a call allocates and not what a file names.

Read on the tree of this note (base `c72460b306`): **2,595 site lines in 186 files.** By crate:
`wz-session-core` 1,520 in 90 files, `wz-capi-pico` 443 in 47, `wz-capi-coop` 323 in 15,
`wz-runtime-coop` 162 in 15, `wz-capi-port` 79 in 13, `wz-session-mcu` 68 in 6. Left out as
modules a cooperative pico build does not compile: 850 lines of `wz-session-core` (the dissector,
the transport counters, shared memory, the raw-Ethernet and serial links, the passive reader, the
parity tables, namespaces, the scout responder, the logs of the analysis plane, among others),
`bounded.rs` and `slot_observer.rs` (the fixed-memory mechanism itself), and `wz-session-mcu`'s
in-memory test network and heap admin node.

## 2. The mechanism is the one the MCU images already use

Nothing here invents a second fixed-memory mechanism. What exists, and is reused:

- **The storage policy** (`crates/wz-session-core/src/bounded.rs`): a container names its backing
  as a type parameter, `Heap` (growable `Vec`, `String`) or `Static` (fixed arrays, a push past
  the capacity refused with `CapacityFull`), so a registry's algorithm exists once and the
  backing is the instantiation. The selectors `bounded-heapless`, `tx-lend-only` and
  `session-slot` (`crates/wz-session-core/Cargo.toml`) make a session's state fixed in size, its
  frames encoded into slots a link lends, and its tables per session.
- **The forms with no copy**: decoding in place (`query/in_place.rs`, `pubsub/in_place.rs`),
  frames encoded into a slot the link lends (`crates/wz-runtime-coop/src/link_storage.rs`,
  `TxStore`), a link's buffers handed in as parameters (`IpDriver`, shared by both profiles), the
  reassembly pool generated with a fixed size (`out/wz-runtime-coop/reassembly_pool_mcu.rs`).
- **The static runtime** (`static_executor.rs`, `static_timer.rs`, `static_local.rs` of
  `wz-runtime-coop`): tasks and timers from fixed tables (`MAX_TASKS`, `MAX_TIMERS`).
- **The ABI's object pools** (`crates/wz-capi-pico/src/object_pool.rs`, `object_slot.rs`): one
  pool per kind of handle object, slot classes from 16 bytes to 16 KiB, a full pool answering
  `_Z_ERR_SYSTEM_OUT_OF_MEMORY` having declared or opened nothing, the counts held to the session
  limit that bounds each kind.
- **The limits and their bindings** (`deploy/wz-config.toml`, `[[limit]]`): 69 limits, each with
  its storage (`capacity`, `quota`, `both`) and when it binds on each profile
  (`binding_heap`, `binding_fixed`: `build`, `open`, `live`, `none`); the document's
  `wz/limits` states them by id (`crates/wz-session-core/src/policy_document.rs`).
- **The worst-memory rows** on the unlanded branch `poc-q4-worst-memory` (commits `f44a06b0a`,
  `3487efa2d`, `17dc471ea`; referred to, not merged here): `session_tables` computes rows per
  table from `SessionLimits` and each registry's `ROW_BYTES`, and `memory_basis` in
  `wz-capi-pico`'s `session.rs` adds the handle and each link's queue, buffer and reassembly.

**The one addition: storage lent at open.** The `Static` policy sizes a table at build (const
`N`); a C library whose limits come from the configuration document at `z_open` needs the size
at open. A third policy of `bounded.rs`, `Lent`: the same container over a slice of the session's
arena whose length is the limit the open resolved, with the build's `N` as the ceiling where the
limit has one. The algorithm, the refusal and its error are those of `Static`; only where the
array lives differs. In the limits' declaration this is `binding_fixed = "open"` for every limit
that sizes a pool of the C ABI: 36 limits bind `build` on the fixed profile today, 8 bind
`open`. The MCU images keep `Static`, and a later unit may express `Static` as `Lent` over a
static array if the measurement shows no cost.

## 3. The inventory, by kind of object

Sites are the site lines of section 1, files in the order of their count. A limit in backticks is
in `deploy/wz-config.toml` today; a NEW one is written in plain text and is added by the unit that
first needs it, with its pico-preset default (open question Q3 of the record).

| kind | site lines | files | where most of them are |
|------|----------:|------:|------------------------|
| pending queries and replies | 468 | 18 | `session-core` `query.rs`, `reply.rs`; `capi-pico` `query.rs`, `get.rs`, `querier.rs`, `cancellation.rs`; `capi-coop` `engine/query.rs`, `engine/get.rs`; `capi-port` `cancellation.rs` |
| session, faces, handshake | 374 | 21 | `capi-coop` `engine.rs`; `session-core` `session_actions.rs`, `reconnect.rs`, `face.rs`, `link_admission.rs`; `capi-pico` `session.rs` |
| entity tables | 361 | 17 | `session-core` `pubsub.rs`, `observer.rs`, `declare/*`; `capi-pico` `connectivity.rs`, `liveliness.rs`, `write_filter.rs`, `matching.rs`; `session-mcu` `client_node.rs`, `app_layer.rs` |
| batch buffers and links | 281 | 19 | `runtime-coop` `app_link.rs`, `ip_stack.rs`, `session_drive.rs`, `stream_link.rs`, `udp_link.rs`; `session-core` `link.rs`, `frame_encode.rs`, `drive.rs`, `inbound.rs` |
| configuration, document, locators | 229 | 9 | `session-core` `locator.rs`, `json5.rs`, `facilities.rs`, `limit_corpus.rs`, `policy_document.rs`; `capi-pico` `config.rs`, `device_requires.rs` |
| multicast group | 187 | 13 | `capi-coop` `engine/group.rs`, `host_group.rs`; `session-mcu` `group_drive.rs`, `group_drive/stage.rs`; `session-core` `multicast_*` |
| wire messages (owned forms) | 140 | 15 | `session-core` `network_message.rs`, `response_build.rs`, `put_payload.rs`, `ext_chain.rs`, `request_build.rs` |
| key expressions | 97 | 7 | `session-core` `shared_key_ids.rs`, `wireexpr_resolve.rs`; `capi-pico` `keyexpr.rs` |
| owned objects handed to the program | 86 | 11 | `capi-pico` `bytes.rs`, `string_array.rs`, `encoding.rs`; `session-core` `sample.rs` |
| history and replay caches | 64 | 6 | `capi-pico` `advanced.rs`, `replay_subscriber.rs`, `replay_publisher.rs` |
| runtime: tasks, timers, wakers | 54 | 9 | `runtime-coop` `local.rs`, `executor.rs`, `session_runtime.rs`, `runtime_impl.rs` |
| scouting | 50 | 6 | `session-core` `scouting_host.rs`; `capi-coop` `scout.rs`; `capi-pico` `scout.rs` |
| callbacks' closures, handlers, latches | 42 | 7 | `capi-pico` `ffi.rs`, `handlers.rs`; `session-core` `reply_sink.rs`, `decl_sink.rs`, `sink.rs` |
| admin space | 40 | 1 | `capi-pico` `admin_space.rs` |
| the port's vocabulary | 37 | 3 | `capi-port` `engine.rs`, `lib.rs` |
| catalog tables | 25 | 4 | `capi-pico` `message_payload.rs`, `message_catalog.rs`, `instance_key.rs`, `proto_file.rs` |
| end-to-end protection state | 20 | 5 | `capi-pico` `stream_supervision.rs`, `segment_sender.rs`, `e2e_receiver.rs`, `e2e_sender.rs` |
| peer-written tables | 20 | 7 | `session-core` `id_map.rs`, `declaration_sync.rs`, `peer_table.rs`, `declare/subscriber.rs` |
| observation (clock, snapshot, time base) | 16 | 6 | `capi-pico` `time_base.rs`; `capi-port` `observation/*` |
| fragment reassembly | 4 | 2 | `runtime-coop` `reassembly_rx.rs`; `session-core` `chain_staging.rs` |
| **total** | **2,595** | **186** | |

## 4. Each kind: bound, form, lifetime, refusal, lock

The concurrency rule is one for every kind and is stated once: **the session's arena and every
pool in it are touched only under the session's lock** (decision D8 of
`docs/capi-pico-on-coop-engine.md`: `host-lock` on a host, the image's critical section on an
MCU), and no C callback runs under it; **the process pools of section 4.1 are under the port's
`sync::Lock`**, as `object_pool.rs` already is. A slot is reached through a handle that carries
its generation, so a handle kept past its object's release is refused, never read.

### 4.1 Owned objects handed to the program

Samples, replies and queries the program holds (`z_sample_clone`, `z_reply_clone`, a query kept
past its callback), payload bytes (`bytes.rs`: `ByteBuf` over `Arc<Backing>`), strings and
string arrays, encodings and their schema, owned key expressions not declared on a session.

- Bound: the counts of `wz_ext_object_pool_counts_t` become limits: NEW HELD_SAMPLES,
  HELD_REPLIES, HELD_QUERIES, HELD_OBJECTS (strings, encodings, string arrays, key expressions,
  configs), and NEW HELD_PAYLOAD_BYTES for the bytes they carry; one payload is at most
  `PICO_FRAG_MAX_BYTES`, one key at most `MAX_KEYEXPR_BYTES`. The C struct stays the door that
  states them in C.
- Form: the existing per-kind object pools for the objects; the payload bytes in a block pool of
  the same slot classes (16 bytes to 16 KiB), a payload taking the smallest class that holds it.
  A payload is shared by reference count inside its block, not by `Arc`.
- Lifetime: process pools reserved at the library's first call (open question Q1 of the record);
  a slot is returned by the drop of the owned object, from any thread.
- Exhausted: the call that would make or copy the object answers `_Z_ERR_SYSTEM_OUT_OF_MEMORY` and
  leaves the source untouched. A sample delivered to a callback is a loan of the delivery lane
  (4.10) and takes no slot unless the program clones it.

### 4.2 Key expressions

`DeclaredKeyexpr` (a `String` and an `Arc<WireDeclaration>`), the key of every entity, the
port's `keyexpr: String` arguments, `format!` joins and concatenations, the peer's aliases
(`wireexpr_resolve.rs`), the shared key ids (`shared_key_ids.rs`).

- Bound: `MAX_KEYEXPR_BYTES` per key; `MAX_PEER_KEYEXPR_ALIASES` per face;
  `MAX_SHARED_KEY_IDS`; NEW MAX_DECLARED_KEYEXPRS per session (`z_declare_keyexpr`).
- Form: a key is a bounded string inline in the row that owns it (the entity's, the alias's), as
  the fixed profile's registries already hold it; the port takes `&str` and the engine copies into
  the row; a join or a concatenation writes into the destination's bounded string.
- Lifetime: the owning row's.
- Exhausted: a key longer than `MAX_KEYEXPR_BYTES` is refused with `Z_EINVAL` (a value this build
  cannot take); a table past its count with `_Z_ERR_SYSTEM_OUT_OF_MEMORY`; a peer's alias
  past its table is refused and counted, as the session core does today.

### 4.3 Entity tables

The cooperative engine's `Core` tables (`subscribers`, `keyexprs`, `filters`, `interests`,
`matches`, `queryables`, `tokens`, `live_subs`, all `Vec`), the observer's registries, the
ABI's write filters, matching listeners, declaration watchers and connectivity listeners.

- Bound: `MAX_SUBSCRIPTIONS`, `MAX_QUERYABLES`, `MAX_LOCAL_TOKENS`,
  `MAX_LIVELINESS_SUBSCRIPTIONS`, `MAX_DECL_OBSERVERS`, `MATCH_MEMO_SLOTS` (with
  `MATCH_MEMO_KEY_BYTES`); NEW MAX_PUBLISHERS, MAX_QUERIERS (each holds a write filter and its
  interest), MAX_MATCHING_LISTENERS, MAX_CONNECTIVITY_LISTENERS.
- Form: `Lent` tables in the session arena; an entity's id is its slot and generation.
- Lifetime: declare to undeclare; the session's close releases every row.
- Exhausted: the declaration answers `_Z_ERR_SYSTEM_OUT_OF_MEMORY` having sent nothing (the
  registries already refuse with `TableFull` past a stated quota, `crates/wz-session-core/src/limits.rs`).

### 4.4 Pending queries and replies

Requester side: a get's legs, the reply gate, the reply callback (`Arc<CReplyClosure>`), the
cancellation token's handlers (`BTreeMap<u64, Box<dyn FnOnce>>`), the observer's pending entries.
Answering side: every query is held on the cooperative engine (`OwnedQuery`: key, parameters,
payload, attachment), its Final owed until the hold is dropped; the replies a queryable stages.

- Bound: `MAX_PENDING_QUERIES`, `QUERIER_MAX_PENDING_QUERIES`, `MAX_PENDING_LIVELINESS_GETS`,
  `MAX_PENDING_FINALS` (held queries), `MAX_PENDING_REPLIES`, `MAX_REPLY_PAYLOAD_BYTES`,
  `QUERY_PARAMETERS_MAX_BYTES`, `QUERY_ATTACHMENT_MAX_BYTES`, `MAX_MULTICAST_REPLIES`; a query's
  payload at most `PICO_FRAG_MAX_BYTES`. The three whose 0 is no bound need a finite value
  (record, section 3).
- Form: `Lent` tables; a held query's bytes in a per-session block pool of the query's own rows
  (each row sized by the parameter, attachment and payload limits); a cancellation token is a slot
  of the get's row with a fixed number of handlers (one leg on the cooperative engine).
- Lifetime: a get from `z_get` to its last reply's drop or its deadline; a held query from its
  dispatch to the drop of the program's hold.
- Exhausted: `z_get` answers `_Z_ERR_SYSTEM_OUT_OF_MEMORY` having sent nothing; a query that
  finds no held-query row is answered with its Final at once and counted (the request is not left
  without an end); a reply past `MAX_PENDING_REPLIES` is refused to the replier, as the session
  core does today.

### 4.5 Peer-written tables

What a face's peer declares: its subscribers, queryables and tokens, its aliases, its interests,
the declarations owed it (`id_map.rs`, `declaration_sync.rs`, `peer_table.rs`,
`declare/subscriber.rs`, `declare/queryable.rs`).

- Bound: `MAX_REMOTE_DECLS`, `MAX_PEER_KEYEXPR_ALIASES`, `MAX_INBOUND_SUB_INTERESTS`,
  `MAX_PENDING_DECLARES`, `LINK_NOTED_REQUESTS`, each per face.
- Form: the fixed profile's split already holds them per session (`PeerTables`,
  `docs/no-heap-multi-session.md` section 2); here, `Lent` tables in the face's part of the arena.
- Lifetime: the face's; a lost link takes them with it (the observer's link-loss flush).
- Exhausted: the peer's declaration is refused and counted; no call of the program sees it.

### 4.6 Session, faces, handshake

The engine's `Core` (faces, listeners, groups, admission), `McuActions` behind `Rc`, the link
admission registry, reconnect state, the handshake's cookie and signing key, the zid, the
`Arc<CoopEngine>` the ABI holds, the `Box<dyn SessionDrive>`.

- Bound: one dial face; NEW MAX_FACES for a listening session (today `CoopConfig::max_faces`,
  default 1000) and NEW MAX_ACCEPT_PENDING (today `DEFAULT_ACCEPT_PENDING`, 100);
  `MAX_STATIC_CONNECT` endpoints, each at most `MAX_LOCATOR_LEN`; `HANDSHAKE_COOKIE_BYTES`.
- Form: the session object is a slot of the process session pool (`object_pool.rs` already has
  the kind); its arena holds the faces in a `Lent` table; references between the session's parts
  are indices into it, not `Rc`.
- Lifetime: `z_open` to `z_close`; the arena is returned when the session is closed and no
  object lent from it is held (a sample loaned to a callback is not held past it).
- Exhausted: `z_open` answers `_Z_ERR_SYSTEM_OUT_OF_MEMORY` when the arena cannot be reserved,
  having dialled nothing; a connection past MAX_FACES or MAX_ACCEPT_PENDING is closed unread, as
  `a_connection_past_max_faces_is_closed_unread` holds today.

### 4.7 Batch buffers and links

Each link's receive buffer (`vec![0u8; rx_capacity]`), its transmit storage (`HeapTx`), the
frames built on the heap (`frame_encode.rs`), the received frame copied out (`RxFrame::new(batch.to_vec())`
in `stream_link.rs`), the program-supplied transport's queues (`app_link.rs`), the TLS channel.

- Bound: `PICO_UNICAST_BATCH_BYTES` (the batch), `PICO_TX_QUEUE_SIZE` (batches per priority),
  `APP_LINK_QUEUE_BYTES`, `DATAGRAM_FRAGMENT_BURST`; the TLS channel keeps its own arena
  (`wz-tls-mbedtls`), sized by its build.
- Form: the link's buffers are slices of the face's part of the arena, handed to `IpDriver` as
  its parameters already are; every frame is encoded into a lent slot (`tx-lend-only`, named by
  the C ABI's final build and never by a library's dependency line, as the feature's own note in
  `crates/wz-session-core/Cargo.toml` requires); a received batch is read in place.
- Lifetime: the face's.
- Exhausted: a send that finds no slot is refused and counted (`tx-lend-only`), and `z_put`
  answers the code this ABI gives a failed send today.

### 4.8 Wire messages

Owned message forms: `NetworkMessage::Push(Box<Push>)`, payloads and extensions as `Vec`
(`put_payload.rs`, `ext_chain.rs`), the request and response builders.

- Bound: the batch, `PICO_FRAG_MAX_BYTES`.
- Form: none of its own: a message is read in place from the batch it arrived in and written into
  the slot it leaves in. This kind goes to zero by the in-place forms, not by a pool.
- Lifetime: one step of the engine.
- Exhausted: nothing to exhaust.

### 4.9 Fragment reassembly

- Bound: `PICO_FRAG_MAX_BYTES`, for each of the two reliabilities a link rejoins apart (the
  memory rows of `poc-q4-worst-memory` count it so).
- Form: the generated pool (`reassembly_pool_mcu.rs`), its storage lent from the face's arena
  instead of `Box<ReassemblyPoolMcu>`.
- Exhausted: a chain longer than the bound is dropped and counted, as today.

### 4.10 The delivery lane

The engine queues what it hands out after its lock (D8): `samples`, `matching`, liveliness
samples, held queries, get events, handed publish legs (`VecDeque` each, with owned keys and
payloads).

- Bound: `DELIVERY_LANE_EVENTS`, `DELIVERY_LANE_BYTES` (the session's lane rather than an
  offloaded subscriber's: the scope moves from entity to session for this use).
- Form: one byte ring per session, the delivery lane's own form (a sample that does not fit
  before the end skips to the start and stays in one piece), each event a header and its bytes; a
  callback gets a view of its event in the ring.
- Lifetime: from the dispatch that queued it to the return of the callback it was handed to.
- Exhausted: the event is refused and counted (open question Q4 of the record: or the reader is
  held).

### 4.11 Runtime: tasks, timers, wakers

`LocalSet`'s boxed futures (`local.rs`), `Arc<AtomicBool>` wake and cancel flags
(`executor.rs`), the group face's task, the ticker's jobs.

- Bound: `MAX_TASKS`, `MAX_TIMERS`, per session.
- Form: the static runtime's tables (`static_executor.rs`, `static_timer.rs`), lent from the
  arena; a waker points at its task's slot.
- Exhausted: cannot happen after open: the tasks a session runs are known at open (the
  session, each group face, the ticker) and are placed then; an open that needs more answers
  `_Z_ERR_SYSTEM_OUT_OF_MEMORY`.

### 4.12 Callbacks' closures, handlers, latches

The port's sink factories (`Arc<dyn Fn() -> Box<dyn FnMut(..)>>`), `Arc<CClosure>`, `RcBlock`,
the FIFO and ring channels (`handlers.rs`), `ReleaseLatch` and `LatchList`, the sets of threads
inside a callback (`IN_CALLBACK`, `delivering`).

- Bound: a C closure is three words (context, call, drop); a channel's capacity is stated by the
  program at its creation, from NEW CHANNEL_SLOTS (process); the latches follow their entities.
- Form: the closure triple stored by value in its entity's row, its kinds a closed enum instead of
  a boxed trait object (the fixed profile's `Requesters` already names this: "a closed enum makes
  them allocation-free"); a channel's ring in the process block pool; a latch in its entity's row;
  the in-callback mark a thread-local of the OS layer instead of a shared `Vec`.
- Exhausted: a channel past CHANNEL_SLOTS answers `_Z_ERR_SYSTEM_OUT_OF_MEMORY` at its creation.

### 4.13 Configuration, document, locators

`ConfigState` (`BTreeMap<u8, String>`), the JSON5 reader building a tree of `String`s, the
policy document's statements (`Vec<LimitStatement>`), locator parsing into owned forms, the
device-requirements door's facilities, TLS material.

- Bound: pico's numbered keys are a fixed set; NEW CONFIG_VALUE_BYTES per value; NEW
  CONFIG_DOCUMENT_DEPTH for the document; `MAX_LOCATOR_LEN`.
- Form: a config is a process-pool object with a fixed table of its keys; the document is read
  by a pull reader that keeps a stack of at most CONFIG_DOCUMENT_DEPTH frames and builds no tree,
  reporting each `wz/*` member it meets; a locator is parsed into borrowed fields.
- Lifetime: a config from `z_config_default` to its move into `z_open` or its drop.
- Exhausted: `zp_config_insert` with a value past CONFIG_VALUE_BYTES answers
  `Z_ERR_CONFIG_INVALID_VALUE`; a document deeper than its bound is refused at open with the same.

### 4.14 Multicast group

The group face's state (`Rc<RefCell<Vec<MulticastMember>>>`, the announced declarations, the
keyexpr answers), the group transport, the members' reassembly.

- Bound: NEW MAX_GROUPS, NEW MAX_GROUP_MEMBERS (the tokio engine's `GROUP_FACE_ROWS`, 32, is the
  pico preset's value, `docs/upstream-parity.md` section 7), `MAX_MULTICAST_REPLIES`,
  `PICO_MULTICAST_BATCH_BYTES`; per member the per-peer bounds of `multicast_dispatch.rs`.
- Form: the fixed profile's group (`slot_group.rs`, its members a const `MEMBERS`) with its
  tables `Lent`.
- Exhausted: a Join past MAX_GROUP_MEMBERS is refused and counted, as the tokio engine's is.

### 4.15 History and replay caches; end-to-end state; catalogs; scouting; admin; observation

The planes of the unstable API and scouting, each its own unit (section 6, U15):

- **History and replay** (advanced publisher's cache, subscriber's miss detection):
  `REPLAY_DEPTH_MAX` samples per publisher, NEW REPLAY_CACHE_BYTES for their bytes, NEW
  MAX_ADVANCED_SOURCES per subscriber; a ring per publisher; the oldest sample leaves when the
  ring is full, as a cache of that depth does.
- **End-to-end protection**: `E2E_SENDER_SLOTS`, `E2E_SUPERVISED_STREAMS`,
  `SUPERVISION_CHECKPOINTS`; fixed tables; a stream past them is refused at its door with
  `_Z_ERR_SYSTEM_OUT_OF_MEMORY`.
- **Catalogs**: `MESSAGE_CATALOG_ENTRIES`, `INSTANCE_KEY_FIELDS`, `INSTANCES_PER_MESSAGE`; a
  schema text read into the process block pool; past them, refused at the door.
- **Scouting**: NEW MAX_SCOUT_HELLOS per window and each Hello's locators at most
  `MAX_ADMIN_LOCATORS`; a Hello is handed to the callback from a buffer of the window and not kept.
- **Admin space**: `MAX_ADMIN_REPLY_BYTES`, `MAX_ADMIN_LOCATORS`, `MAX_ADMIN_SESSION_LINKS`; the
  fixed profile's admin rows (`adminspace-fixed`, `wz-session-mcu`'s `admin_fixed`) replace the
  growable node; a reply past its buffer is an error reply, as there.
- **Observation**: `EVENT_RING_SLOTS`, `EVENT_RECORD_ARGS`, `SNAPSHOT_HISTOGRAM_BUCKETS`,
  `CLOCK_SOURCES`; the rings and records of `wz-node-time` (17 site lines, outside the counted
  scope of section 1) are read by this unit; the doors' copies go to the caller's buffer.

### 4.16 Text of errors and diagnostics

Not a kind of object but a rule over all of them: `OpenError::Unreachable(format!(..))`,
`Listen(String)`, `Group(String)` and their kin carry text built on the heap. They become typed
reasons with static text; the C ABI returns codes and never showed the text.

## 5. The reservation at open, and the worst-memory report

A session's arena is one block reserved by `z_open` before it dials, from the OS layer (a page
reservation on a host, a region the image places on an MCU), never from a global allocator. Its
size is a function of the limits the open resolved and nothing else:

```
arena = handle
      + F x face
      + entities + pending + lane + runtime + groups

face     = batch_rx + PICO_TX_QUEUE_SIZE(all priorities) x PICO_UNICAST_BATCH_BYTES
         + 2 x PICO_FRAG_MAX_BYTES
         + MAX_REMOTE_DECLS x row(decl) x tables
         + MAX_PEER_KEYEXPR_ALIASES x (row(alias) + MAX_KEYEXPR_BYTES)
         + MAX_INBOUND_SUB_INTERESTS x row(interest) + MAX_PENDING_DECLARES x row(declare)
         + LINK_NOTED_REQUESTS x row(noted) + HANDSHAKE_COOKIE_BYTES + machine
entities = sum over each entity table T of count(T) x (row(T) + MAX_KEYEXPR_BYTES)
         + MAX_DECLARED_KEYEXPRS x (row + MAX_KEYEXPR_BYTES)
         + MATCH_MEMO_SLOTS x (row + MATCH_MEMO_KEY_BYTES)
pending  = MAX_PENDING_QUERIES x row(get) + MAX_PENDING_LIVELINESS_GETS x row(lget)
         + MAX_PENDING_FINALS x (row(held) + MAX_KEYEXPR_BYTES + QUERY_PARAMETERS_MAX_BYTES
                                 + QUERY_ATTACHMENT_MAX_BYTES + PICO_FRAG_MAX_BYTES)
         + MAX_PENDING_REPLIES x (row(reply) + MAX_REPLY_PAYLOAD_BYTES)
lane     = DELIVERY_LANE_BYTES + DELIVERY_LANE_EVENTS x row(event)
runtime  = MAX_TASKS x cell(task) + MAX_TIMERS x row(timer)
groups   = MAX_GROUPS x (MAX_GROUP_MEMBERS x member + MAX_MULTICAST_REPLIES x row
                         + 2 x PICO_MULTICAST_BATCH_BYTES)
F        = 1 for a session that only dials; 1 + MAX_FACES + MAX_ACCEPT_PENDING for one that listens
```

`row(T)` is the registry's own `ROW_BYTES` (the branch states it per registry) and the capacity
of a table is its limit, so the function is exact by construction: the arena is the worst case,
not an estimate of it. The process pools (4.1, 4.12, 4.13) are a second sum of the same shape,
reserved once, at the library's first call or by the reservation door (open question Q1).

**The report is the reservation.** The branch `poc-q4-worst-memory` computes the same rows to
report them (`wz_ext_session_memory`, `MemoryBasis`, `session_tables`), with a flag
`enforced` that is 0 on a growable build. One function serves both: `z_open` reserves its
total, and `wz_ext_session_memory` reports the rows it reserved, `enforced` 1 by construction. A
test opens a session, fills every table to its limit and holds the arena's high-water mark to the
reservation, and another holds the report's total to the reserved bytes. The branch is not merged
by this note; unit U1 takes its rows.

## 6. The conversion units

One unit at a time, each a worker's commit set, each moving one family of the P2 ratchet
(`deploy/no_heap_ratchet.json`) to zero or laying what the next needs. The families are those of
`allocation_faults.rs` (`z_open`, `z_declare_subscriber`, `z_declare_queryable`,
`z_declare_publisher`, `z_put`, `z_get`), the traffic between open sessions (a put received, a
reply received, a query answered, an idle step), and the objects the program makes (owned values,
liveliness, group, close); the gate's worker fixes their keys. Every unit's tests include: each
table it moves filled to its limit and refused at one more with the code of section 4, nothing
left behind by the refusal, and the family's count in the ratchet's instrument; the behaviour
suites (C1co, Layer Z) unchanged.

1. **U0. The `Lent` policy and open binding.** `wz-session-core` `bounded.rs` (the policy),
   `limit_binding.rs` and the limits' declaration (`binding_fixed = "open"`, the generator run by
   the main session), the arena type with its high-water mark. No family moves. Tests: every
   container's algorithm run on `Heap`, `Static` and `Lent`; a `Lent` table refuses at its
   open-time length below its build ceiling.
2. **U1. The arena and the reservation.** `wz-capi-coop` `engine.rs` (open computes and reserves),
   the rows of `poc-q4-worst-memory` (`session_memory.rs` in both crates), `wz-capi-pico`
   `session.rs`. Family: `z_open` (nothing beyond the reservation). Tests: the reservation
   equals the report; an open whose arena cannot be reserved answers the code and dials nothing.
3. **U2. Link buffers from the arena, frames into lent slots.** `wz-runtime-coop` `udp_link.rs`,
   `stream_link.rs`, `ip_stack.rs`, `link_storage.rs`, `session_drive.rs`; `tx-lend-only` for
   the C ABI build. Families: idle step, `z_put` (the send). Tests: a send with no free slot is
   refused and counted; the link reads into the arena's buffer.
4. **U3. Messages in place.** `wz-session-core` `network_message.rs`, `put_payload.rs`,
   `ext_chain.rs`, `response_build.rs`, `request_build.rs` and the `in_place` readers on the
   cooperative path; the query plane's `decode_one_record` conversions. Families: put received,
   reply received. Tests: a push and a reply dispatched with no allocation; the query case's text
   read before and after (record section 5).
5. **U4. The delivery lane.** `wz-capi-coop` `engine.rs` (`samples`, `matching`, `handed`),
   `engine/query.rs`, `engine/get.rs`, `engine/liveliness.rs`. Families: put received, reply
   received, query answered. Tests: a burst past the lane refused and counted; a callback that
   steps the session from inside itself still sees its event.
6. **U5. Entity tables.** `wz-capi-coop` `engine.rs` (`Core`'s tables), `engine/registry.rs`,
   `wz-session-core` `observer.rs`, `pubsub.rs`, `declare/*`, `wz-session-mcu`
   `client_node.rs`. Families: `z_declare_subscriber`, `z_declare_queryable`,
   `z_declare_publisher`. Tests: each table at its limit and one past it.
7. **U6. Key expressions inline.** `wz-capi-pico` `keyexpr.rs`, `reply_keyexpr.rs`,
   `wz-capi-port` `lib.rs` (`WireKey`), `engine.rs` (`&str` arguments), `wz-session-core`
   `wireexpr_resolve.rs`, `shared_key_ids.rs`. Families: the declarations, `z_put`, `z_get`.
   Tests: a key one byte past `MAX_KEYEXPR_BYTES` refused; a join that would exceed it refused.
8. **U7. Closures by value.** `wz-capi-port` `lib.rs` (the sink factories), `wz-capi-pico`
   `ffi.rs`, `handlers.rs`, `matching.rs`, `write_filter.rs`, `wz-session-core` `sink.rs`,
   `reply_sink.rs`, `decl_sink.rs`, `query_sink.rs`. Families: the declarations. Tests: the drop
   of every closure runs exactly once on undeclare, on close and on a refused declaration.
9. **U8. Pending queries.** `wz-capi-pico` `get.rs`, `query.rs`, `querier.rs`,
   `cancellation.rs`, `wz-capi-port` `cancellation.rs`, `query.rs`, `wz-capi-coop`
   `engine/query.rs`, `engine/get.rs`, `wz-session-core` `query.rs`, `reply.rs`,
   `owed_replies.rs`. Families: `z_get`, query answered. Tests: a get past its table refused
   having sent nothing; a query with no held-query row answered with its Final at once.
10. **U9. Handle objects and payloads from the process pools.** `wz-capi-pico` `object_slot.rs`
    (no heap fallback), `object_pool.rs` (reserved at the first call, open question Q1),
    `bytes.rs`, `string_array.rs`, `encoding.rs`, `config.rs`. Family: owned values. Tests:
    `z_bytes_copy_from_buf` past HELD_PAYLOAD_BYTES answers the code and leaves the source; every
    pool's count after a drop.
11. **U10. The port without heap types.** `wz-capi-port` `engine.rs`, `drive.rs`, `lib.rs`:
    methods returning `Vec` write into a caller's buffer, `Arc<dyn SessionEngine>` becomes the
    session's slot and generation, `Box<dyn SessionDrive>` the session object itself. Families:
    `z_open`, close. Tests: a handle kept past `z_close` is refused, not read.
12. **U11. The static runtime under the engine.** `wz-runtime-coop` `local.rs`, `executor.rs`,
    `runtime_impl.rs`, `session_runtime.rs`, `wz-capi-coop` `engine/ticker.rs`. Family: idle
    step. Tests: the session's tasks placed at open; a timer table at its limit.
13. **U12. The group.** `wz-capi-coop` `engine/group.rs`, `host_group.rs`, `wz-session-mcu`
    `group_drive.rs`, `group_drive/stage.rs`, `wz-session-core` `multicast_*`. Family: group.
    Tests: a Join past MAX_GROUP_MEMBERS refused and counted.
14. **U13. Typed errors.** `wz-capi-coop` `engine.rs` (`OpenError`), `scout.rs`, `tls.rs`;
    `wz-session-core` `locator.rs`. Family: `z_open` on its failure paths. Tests: each failure
    answers its code with no allocation.
15. **U14. Configuration and the document.** `wz-capi-pico` `config.rs`, `config_policy.rs`,
    `wz-session-core` `policy_document.rs`, `json5.rs`. Family: owned values (the config).
    Tests: a value past CONFIG_VALUE_BYTES and a document past CONFIG_DOCUMENT_DEPTH refused with
    `Z_ERR_CONFIG_INVALID_VALUE`; every policy and limit read as before.
16. **U15. The remaining planes, one commit set each.** Liveliness (`wz-capi-pico`
    `liveliness.rs`, `wz-capi-coop` `engine/liveliness.rs`), scouting (`scout.rs` of both,
    `scouting_host.rs`), connectivity, the admin space (`admin_space.rs` over `adminspace-fixed`),
    history and replay (`advanced*.rs`, `replay_*.rs`, `engine/replay.rs`), end-to-end, catalogs,
    observation. Family: each plane's own.
17. **U16. The flip.** `allocation_faults.rs`: `MEMORY_TAKEN_AT_OPEN` set from the build, so a
    failed allocation must be a named error and traffic must allocate nothing; every ratchet row
    locked at 0. The phase P2 ends here.

The order: U0 and U1 lay the ground; U2 to U4 are the traffic path, where the allocations per
message are and where a performance gain is expected; U5 to U8 the declarations and queries; U9 and
U10 the ABI's own objects; U11 to U15 the rest; U16 closes the phase.

## 7. Open questions

The product decisions this design needs are Q1 to Q4 of `docs/c-abi-engine-and-memory.md`
section 7: where the objects made before any session live, whether the document may raise a limit
above the build's, the pico preset's finite values for the unbounded and the new limits, and
whether a full delivery lane drops or holds the reader.
