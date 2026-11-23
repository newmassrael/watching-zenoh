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
- **The task and timer tables** (`executor.rs`, `timer.rs`, `local.rs` of `wz-runtime-coop`):
  one executor for both profiles, its tasks and timers in tables that lie in a `static` the image
  declares (`RuntimeCell`), are reserved when the runtime is made (`CoopRuntime::reserved`,
  `RuntimeRows`) or grow on demand (`CoopRuntime::new`); a waker is a reference to its task's
  cell.
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
first needs it, with its pico-preset default (decision Q3 of the record: zenoh-pico's own constant
where pico has one, else a value stated with its reason).

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
past its callback), payload bytes (`bytes.rs`: `ByteBuf` over a shared `Block`), strings and
string arrays, encodings and their schema, owned key expressions not declared on a session, and
what a program makes before any session: its configs and the hellos it keeps.

- Bound: the counts of `wz_ext_object_pool_counts_t` are limits: `HELD_SESSIONS`,
  `HELD_SAMPLES`, `HELD_REPLIES`, `HELD_QUERIES` and `HELD_PAYLOADS` (the payload handles; the
  entities take their session limits times `HELD_SESSIONS`), `HELD_CONFIGS`, `HELD_HELLOS` and
  `HELD_PAYLOAD_BYTES` for the bytes the payloads, strings and slices carry; NEW HELD_OBJECTS for
  the handles of strings, slices, string arrays and encodings and owned key expressions. One
  payload is at most the area's largest block, one key at most `MAX_KEYEXPR_BYTES`. The C struct
  stays the door that states them in C.
- Form: the per-kind object pools for the objects (`crate::process_pool`), each slot the
  smallest of the reported sizes (16 bytes to 16 KiB) that holds its object, or for an object past
  them (a config of the build's text) the object's own size; the bytes in one area beside the
  pools, a buddy allocator of power-of-two blocks from 32 bytes, a payload taking the smallest
  that holds its bytes and a 16-byte head. A payload is shared by the count in its block's head,
  not by `Arc`; a hello the program keeps holds its locators' text inline in its slot.
- Lifetime: process pools reserved at the library's first call (decision Q1 of the record);
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
- Form: `Lent` tables; one table of pending gets for each face the session may hold, lent at open
  and taken by a face when it comes (a face dialled past the faces the config admits reserves its
  own from the session's memory); the held queries' Finals in a fixed table of the query plane,
  `MAX_PENDING_FINALS` rows resolved at open, as the plane is shared outside the session's lock; a
  held query's bytes in a per-session block pool of the query's own rows (each row sized by the
  parameter, attachment and payload limits); a cancellation token is a slot of the get's row with
  a fixed number of handlers (one leg on the cooperative engine).
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
  `MAX_PENDING_DECLARES`, `LINK_NOTED_REQUESTS`, each per face; and what the faces together hold
  of the first three, `SESSION_MAX_REMOTE_DECLS`, `SESSION_MAX_PEER_KEYEXPR_ALIASES`,
  `SESSION_MAX_INBOUND_SUB_INTERESTS` (section 9.6).
- Form: the fixed profile's split already holds them per session (`PeerTables`,
  `docs/no-heap-multi-session.md` section 2). Here what is owed to a peer (the answers staged to
  its interests and the `Final`s owed to its queries) is `Lent` tables in the face's part of the
  arena; its reply stage is lent no row, as this engine's queryable answers into a stage of its
  own. What a peer writes by its own choice (its aliases, its subscribers, queryables and tokens
  and the repeats of them, its interests) is laid out by how many faces the session holds
  (`crates/wz-session-core/src/row_pool.rs`). A session of many faces lends one pool of each row
  kind: a slab of rows, a free list through the rows no face holds, each row carrying a `u16` link
  and a `u16` generation beside its item's fields, so a handle kept past its row's return names
  nothing, and the pool's state `u16` counters; a pool names at most 0x7FFE rows, which the open
  holds its limits to. A face's table is a list of the rows its peer holds, at most the bound of
  one peer (`PooledIdMap`, `PooledRows`), and a lookup walks that face's rows as the scan of an
  inline table did. A session of one face (a client, dial-only) shares with no one: each of its
  tables takes a span of its own of that face's bound, laid out as the inline table laid its rows
  out, with no link and no pool state. An own span is not copied: the session's pools hand it to
  the first face's tables that ask and to no others, so no two tables lay rows over each other.
  What a pool and a table do to their rows (the free list, the links, a walk, a removal and the
  compaction of an own span, a clear, carving spans) is one untyped core that knows a row kind
  only as values (its bytes and alignment in either layout, where a pool's row keeps its link, how
  its item is dropped), compiled once for every kind and every bound and kept out of line; a row
  kind is a thin typed wrapper that writes, reads and lends its item, and every `unsafe` of the
  pools lies in that one module. The pools are a build's choice (`wz-session-core`'s
  `peer-row-pools`, named by the engine's `listen` and `group`): a build that holds one face
  (pico's client) keeps those tables inline at one peer's bound in the face's tables, lends no
  pool and no span, and links none of the pools' code.
- Lifetime: the face's; a lost link takes them with it (the observer's link-loss flush), and a face
  that goes gives its rows back to the pools, one step each and no other face's.
- Exhausted: the peer's declaration is refused and counted, whether its face's table is at the
  bound of one peer or the session's pool has no row left (which the pool counts too); no call of
  the program sees it.

### 4.6 Session, faces, handshake

The engine's `Core` (faces, listeners, groups, admission), `McuActions` behind `Rc`, the link
admission registry, reconnect state, the handshake's cookie and signing key, the zid, the
`Arc<CoopEngine>` the ABI holds (its drive, a `Box<dyn SessionDrive>` until U10, is that `Arc`).

- Bound: one dial face; `MAX_FACES` for a listening session (default 1,000, zenoh's
  `max_sessions`; 10 at the pico preset) and `MAX_ACCEPT_PENDING` (default 100; 1 at the pico
  preset), which `CoopConfig::max_faces` and `accept_pending` are held to (section 9.6);
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
- Exhausted: as the event's congestion control says (decision Q4 of the record): for reliable,
  blocking traffic the engine stops reading the link until the lane drains, so the transport's
  flow control holds the sender; drop-policy and best-effort traffic is dropped and counted.
- Where it stands: the subscribers' samples are in the lane (`crates/wz-capi-coop/src/lane.rs`,
  a span of the arena, `DELIVERY_LANE_BYTES` under the build's), and each link is read only while
  the lane can take a whole batch of it (`LaneGate`); the matching changes are a fixed table of one
  row per listener. A sample that holds its sender and still finds no room (a batch whose samples
  take more than its own length: a key resolved longer than it travelled, a sample many
  subscribers take) is counted apart (`LaneCounts::held_over`). Still queued on the heap: the
  liveliness samples, the held queries, the get events and the handed publish legs, which take
  their own records of the same lane next. Until the reassembly of 4.9 is bounded, a sample longer
  than `DELIVERY_LANE_BYTES` that a link rejoins is refused at the lane; the pico preset states a
  lane at least as long as the longest message its links rejoin.

### 4.11 Runtime: tasks, timers, wakers

The session's tasks (one for each face, each group face), the deadlines they wait on, the ticker's
jobs. Before U11 the heap profile boxed each task's future and gave it an `Rc` join state and
two `Arc<AtomicBool>` flags, and its timers grew a `BinaryHeap`; the executor is now one for both
profiles (`executor.rs`, `timer.rs`), and a spawn writes the future into a cell of the table.

- Bound: `MAX_TASKS` and `MAX_TIMERS`, per session (`RuntimeRows`); the bytes of a link's cell
  are those of the task a link's session runs as (`RouterSessionTask`), a constant of its types
  and no limit; `MAX_TICKERS` for the ticker's jobs.
- Form: a table of task cells and one of timer entries, reserved when the runtime is made
  (`CoopRuntime::reserved`), one block for the cells; a waker points at its task's cell and holds
  a count on the table (no allocation), so a waker kept past the session still points at memory.
  A grown table (`CoopRuntime::new`) keeps each cell's bytes for the next task that fits them, so
  it allocates only when the session holds more tasks or deadlines at once than it ever did.
- Exhausted: the engine reserves its runtime at open (`CoopRuntime::opening`): a cell for each
  link its config admits (the dial role's, each face `max_faces` admits, each handshake
  `accept_pending` admits) in the bytes of a link's session task, and a cell added while the open
  lasts for each group it joins, together at most `MAX_TASKS`; the open seals the table once it
  is over. An open whose link or group finds no cell answers `_Z_ERR_SYSTEM_OUT_OF_MEMORY`
  (`OpenError::NoTask`); a link accepted after it is closed unread, as one past `max_faces` is;
  a sleep past `MAX_TIMERS` is refused an entry, counted, and ends by polling; a periodic job
  past `MAX_TICKERS` is refused, as an engine with no periodic jobs refuses it.

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

- Bound: `CONFIG_ENTRIES` numbered keys and `CONFIG_TEXT_BYTES` of value text per config
  (pico preset 8 and 256; the defaults, 32 and 16,384, hold every key zenoh-pico defines and the
  five inline certificates and keys of its TLS example); NEW CONFIG_DOCUMENT_DEPTH for the
  document; `MAX_LOCATOR_LEN`.
- Form: a config is one object of the build's size: a table of its keys and one text their values
  lie in, NUL-terminated, written in place by `z_config_default` and `z_config_clone`
  (`crates/wz-capi-pico/src/config.rs`, `ConfigEntries`). A key's new value is written over its
  old place when it fits there (zenoh-pico frees the value it replaces), the last place grows into
  the free text, and otherwise the value goes after the last place; a value's place never moves, so
  the pointer `zp_config_get` lends stays valid while the config lives and the key is not inserted
  again. The policy statements of `wz_ext_config_policy` and `wz_ext_config_profile` are the
  build's own ids (`PolicyStatements`, a row per policy), found by the door, so they hold no text
  of their own. The document is walked once by the no-heap lexer (`json5_lex::Lexer`), at most
  `CONFIG_DOCUMENT_DEPTH` deep (default 16; zenoh's reference document nests 7), and its `wz`
  member is written straight into rows of the build's ids (`DocumentRows`: the profile, a row per
  policy, a row per limit of a session), which `policy_document::resolve_layers_under` composes as
  `resolve_document_under` composes a tree; `wz/key-ids` is read where it lies by the same lexer
  into the rows of its entries (`shared_key_ids::read_member_in`), by the rules of the tree reader
  the other ABIs read it with, which a test holds the two to. The dictionary those rows make is
  the one an open is handed (`KeyIdsAtOpen`), shared by the session's links behind an `Arc` and
  made before the open. A locator is parsed into borrowed fields. The object itself is a slot of
  the process pools (`Kind::Config` of `object_slot.rs`, `HELD_CONFIGS` of them, each the
  config's own size), which a pico program's first config reserves, so the config allocates
  nothing; a full pool refuses `z_config_default` and `z_config_clone` with
  `_Z_ERR_SYSTEM_OUT_OF_MEMORY` and leaves the config null.
- Lifetime: a config from `z_config_default` to its move into `z_open` or its drop.
- Exhausted: `zp_config_insert` of a new key past the rows or a value past the text answers
  `_Z_ERR_CONFIG_FAILED_INSERT` (-95), zenoh-pico's code for an insert it could not make
  (`vendor/zenoh-pico/src/protocol/config.c` @ `ret = _Z_ERR_CONFIG_FAILED_INSERT;`), and the
  config keeps what it held; a policy, value or profile the build does not have is refused at its
  door with `Z_ERR_CONFIG_INVALID_VALUE`, the code the open's resolution gives it; a document
  deeper than its bound is refused at its door with the same.

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
  `SUPERVISION_CHECKPOINTS`; fixed tables. The last two are limits of the process's runtime
  (`wz_ext_runtime_limits_document`, stated before the first such machine is made), lent under the
  build's values (`ProcessRows`, `wz-session-core` `process_limits.rs`); a stream past them is
  refused at its door with `_Z_ERR_SYSTEM_OUT_OF_MEMORY`.
- **Catalogs**: `MESSAGE_CATALOG_ENTRIES` (the process's runtime, as above), `INSTANCE_KEY_FIELDS`,
  `INSTANCES_PER_MESSAGE`; a schema text read into the process block pool; past them, refused at
  the door.
- **Scouting**: NEW MAX_SCOUT_HELLOS per window and each Hello's locators at most
  `MAX_ADMIN_LOCATORS`; a Hello is handed to the callback from a buffer of the window and not kept.
  The ABI's half is done: the hello the callback reads lends the scouted Hello's own strings
  through a table of `MAX_ADMIN_LOCATORS` views on the delivering frame (`lend_hello`,
  `StringArrayState::lent`), so a delivery copies nothing, and the scout reads its config's keys
  in place; a Hello with more locators than the table is handed through copies, and
  `z_hello_clone` owns copies. The window's half: a cooperative window records its Hellos in a
  table of `MAX_SCOUT_HELLOS` rows (`HelloTable`, pico preset 1), each row its locators, at most
  `SCOUT_HELLO_LOCATORS` of `MAX_LOCATOR_LEN` bytes, in a text of its own (`HelloRow`), decoded
  into the row in place (`HelloRow::decode_into`); a Hello past the table is counted
  (`hellos_refused`), and the rows are lent to the callback (`deliver_rows_in_upstream_order`).
  The table is never on a stack: the window holds a pointer to it
  (`ScoutingActions::over_table`), and the pico C ABI keeps the one table in the library's static
  memory, held by one window at a time. A window that finds it held by another thread's window
  waits on a condition variable the holder signals when it lets go, at most its own budget
  (`Condvar::wait_timeout_ms` of `wz-capi-port`), and runs on what is left; a budget spent
  waiting is a window nobody answered (`Z_OK` with no Hello, or the open's
  `_Z_ERR_SCOUT_NO_RESULTS`), so no scout fails because another thread scouts. A scout asked on
  the holding thread, from inside a scout's callback, is refused at once with
  `WZ_EXT_ERR_SCOUT_REENTERED`. The holder's mutex and condition variable are the kernel's, made
  by the first scout of the process (U11's kernel objects). The Rust
  preset's window (`ScoutingActions::new`, the tokio engine) keeps zenoh's collection on the
  heap, with no bound. A cooperative window allocates nothing: its state (`ScoutingActions`)
  lies in the place it is built in beside its machine, which reaches it by pointer and not
  through an `Arc` (`ScoutWindowPlace::build_over`); the Scout it stages is a frame of its own
  (`ScoutFrame`); what it discovered is read from the table's rows; the datagrams it drops are
  counted by verdict (`IgnoredCounts`) and not listed; and each datagram is read into a buffer
  its holder lends, which the pico C ABI keeps in static memory beside the table, as long as
  the session limits' `PICO_MULTICAST_BATCH_BYTES` (zenoh-pico reads a scout into its multicast
  batch; a datagram past it is read cut short and is no Hello). What still allocates is
  `scout_first`'s owned Hello, which `z_open`'s lookup takes its locators from.
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
reserved once, at the library's first call (decision Q1; a reservation door is an addition,
never required).

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
   `z_declare_publisher`. Tests: each table at its limit and one past it. The lent observer's
   watcher lists of what a peer declares (`remote_subscribers`, `remote_queryables`,
   `liveliness`) are lent at open too, `MAX_DECL_OBSERVERS` rows each (`binding_fixed = "open"`),
   one row of their spans in the arena's plan (`declaration watchers`).
7. **U6. Key expressions inline.** `wz-capi-pico` `keyexpr.rs`, `reply_keyexpr.rs`,
   `wz-capi-port` `lib.rs` (`WireKey`), `engine.rs` (`&str` arguments), `wz-session-core`
   `wireexpr_resolve.rs`, `shared_key_ids.rs`. Families: the declarations, `z_put`, `z_get`.
   Tests: a key one byte past `MAX_KEYEXPR_BYTES` refused; a join that would exceed it refused.
   Done in part: an object of the ABI keeps its key's text in the session's key arena, a block it
   holds through the port (`HeldKey`, `SessionKeys`, `SessionEngine::key_arena` in
   `wz-capi-port` `held_key.rs`), shared and let go of under the session's lock and read with
   none; a key a row of the engine's record keeps already is shared with it, so a publisher's key,
   its write filter's, its Interest's and the program's object take one block; a declared key's
   literal and a write filter's key are no copies of their own (`KeyText` in `wz-capi-pico`
   `keyexpr.rs`), and an Interest's row reads its form's rest of the key from its own key. A key
   the arena has no room for answers `_Z_ERR_SYSTEM_OUT_OF_MEMORY` having sent nothing, one past
   the session's `MAX_KEYEXPR_BYTES` `Z_EINVAL`. Tests: `held_key.rs` of the port,
   `tests/held_keys.rs` of `wz-capi-coop` (a cycle of holds and of declarations ten times past
   the arena gives every block back), `arena_key_tests` of `keyexpr.rs`. What is left is
   section 7's.
8. **U7. Closures by value.** `wz-capi-port` `lib.rs` (the sink factories), `wz-capi-pico`
   `ffi.rs`, `handlers.rs`, `matching.rs`, `write_filter.rs`, `wz-session-core` `sink.rs`,
   `reply_sink.rs`, `decl_sink.rs`, `query_sink.rs`. Families: the declarations. Tests: the drop
   of every closure runs exactly once on undeclare, on close and on a refused declaration.
9. **U8. Pending queries.** `wz-capi-pico` `get.rs`, `query.rs`, `querier.rs`,
   `cancellation.rs`, `wz-capi-port` `cancellation.rs`, `query.rs`, `wz-capi-coop`
   `engine/query.rs`, `engine/get.rs`, `wz-session-core` `query.rs`, `reply.rs`,
   `owed_replies.rs`. Families: `z_get`, query answered. Tests: a get past its table refused
   having sent nothing; a query with no held-query row answered with its Final at once. Its
   remainder done: a query's replies are staged nowhere. Each is written, as its queryable makes
   it, into the transmit slot of the link the query came in on under the session's lock
   (`Onward` in `engine/query.rs`, the link's `ResponseSink::send_reply_parts`), as zenoh-pico's
   `z_query_reply` sends at the call; a held query keeps its row of held Finals and no buffer of
   replies. The payload bound (`MAX_REPLY_PAYLOAD_BYTES`) still refuses a longer reply to its
   queryable; the count of replies to one query is bounded by nothing, as zenoh-pico's is not.
10. **U9. Handle objects and payloads from the process pools.** `wz-capi-pico` `object_slot.rs`
    (no heap fallback), `object_pool.rs` (reserved at the first call, decision Q1),
    `bytes.rs`, `string_array.rs`, `encoding.rs`, `config.rs`. Family: owned values. Tests:
    `z_bytes_copy_from_buf` past HELD_PAYLOAD_BYTES answers the code and leaves the source; every
    pool's count after a drop.
    Taken for the session: on the cooperative engine its handle lies in its own arena, not in a
    process pool (a table of HELD_SESSIONS places would be a count the program states nowhere for
    a library without the pool doors). `ArenaPlan::holding` adds the handle's place as the plan's
    last two rows, `CoopEngine::open_made_in` is handed its layout and lends it
    (`CoopDrive::handle_place`), `z_open` writes the handle there (`crate::session_place`) and
    `z_session_drop` moves it out before letting it go, the memory going back with the arena. A
    word beside the handle says whether the place holds it, so a copy of the owned session kept
    past its drop is refused, not read, for as long as the session's memory stands (a declared
    entity keeps it standing; past the last holder the copy names freed memory, as a copy of
    zenoh-pico's does). The tokio engine keeps `Slot::take`, and a build with the pool doors
    still reserves its session pool, which the cooperative engine does not use.
    Taken for the rest: the pools are apart from their doors. `src/process_pool.rs` holds them and
    is in every library without the tokio engine (`wz_process_pools`, set by `build.rs`), so a
    build without `unstable-api`, the speed matrix's and the release set's, has them and makes no
    allocation for its objects after its first; `object-pool` is only the doors
    (`wz_ext_object_pool_*`), which still imply `unstable-api`, and on the tokio engine bring
    the pools with them. `Slot::take` has no heap fallback where the pools are. The config
    (`Kind::Config`, `HELD_CONFIGS`, a slot of its own size since the build's config is past
    the largest class) and a hello the program keeps (`Kind::Hello`, `HELD_HELLOS`: the hello, its
    lent array, `SCOUT_HELLO_LOCATORS` views and their text in one slot) are kinds of the pools.
    The bytes of payloads, strings and slices are blocks of one area beside them
    (`HELD_PAYLOAD_BYTES`, a buddy allocator, `bytes.rs` `Block` with its count in its head in
    place of `Arc<Backing>`); every constructor and copy is fallible and answers
    `_Z_ERR_SYSTEM_OUT_OF_MEMORY` with its output null, an alias's release run at once. A reply's and
    a query's payload and attachment are read where the view holds them, as a sample's were
    (the borrowed marshal), and copied only when kept past the callback. The doors' counts
    gained `configs`, `hellos` and `payload_bytes`; the doors report no class for the area or for
    a slot past the largest class. Tests: `process_pool::tests` (the area's split, join and refusal,
    a slot past the classes), `bytes::block_tests`, `object_pool_doors` ARM 4b (a copy past the
    area answers the code and leaves the source).
11. **U10. The port without heap types.** `wz-capi-port` `engine.rs`, `drive.rs`, `lib.rs`:
    methods returning `Vec` write into a caller's buffer, `Arc<dyn SessionEngine>` becomes the
    session's slot and generation, `Box<dyn SessionDrive>` the session object itself. Families:
    `z_open`, close. Tests: a handle kept past `z_close` is refused, not read.
    Taken: the cooperative engine hands its own `Arc` as the handle's drive (`CoopDrive`, kept by
    value in `PicoSessionHandle`, its drop the close), so the open makes no box for it; and every
    key a `SessionEngine` method takes is `&str`, so a declaration hands the engine its own text
    and the engine copies it into its key arena, where it was copied already. The tokio engine
    keeps its boxed drive, which holds its session's drop glue in its own crate. The peers are
    read one at a time (`next_peer`, `next_group_member`, walked by `each_peer` and
    `each_group_member`): each read takes the session and lets it go, and the identity is copied
    out before the C callback of `z_info_peers_zid` runs, so no callback runs under the lock and
    no list is made (a buffer of every face would be MAX_FACES rows on the stack); a Rust caller
    collects them through `PeerLists`. Left: the methods returning `Vec` that only the
    connectivity and admin planes and the Rust API read (`face_snapshots`, whose rows own their
    links' text, `listen_locators`, `linkstate_regions`, `keyexpr_declarations`).
    The dispatch is static where the build has one engine: the ABI's `Engine` is
    `CoopEngine<HostLinks, SessionClockOf>`, the links named as the open composes them
    (`ComposedLinks` over the host's, a secure channel and groups), and the handle's drive is
    `CoopDrive<L, C>`, whose operations call the engine's by name, so no table of the engine's
    functions is made and what the build never calls is not linked. A build with `app-transport`
    opens over the host's links or the program's: its drive is an enum of the two (`PicoDrive`),
    and its entities still keep the engine as the port's trait object, because the engine is made
    in its own `Arc` and an enum of two engines would be a second allocation; one engine type
    there needs the links to be one type (an enum of the two at `SessionLinks` and its pump, in
    `wz-runtime-coop`'s traits). What serves any engine keeps the trait object, an open set: the
    advanced plane's host and its periodic job (`port_engine`), and the admin space's weak hold.
12. **U11. The static runtime under the engine.** `wz-runtime-coop` `local.rs`, `executor.rs`,
    `runtime_impl.rs`, `session_runtime.rs`, `wz-capi-coop` `engine/ticker.rs`. Family: idle
    step. Tests: the session's tasks placed at open; a timer table at its limit.
    Done in part. One executor for both profiles (`executor.rs`, `local.rs`, `join_handle.rs`):
    the slot profile's static table, a table reserved when the runtime is made
    (`CoopRuntime::reserved` over `RuntimeRows`: tasks, the bytes of a task's cell, timers) and
    a grown one (`CoopRuntime::new`); a spawn writes the future into a cell and its output after
    it, a waker is a reference to the cell, and none allocates where a cell or an entry is free.
    One timer table for both (`timer.rs`), reserved or grown the same way. The Zephyr OS layer's
    `k_mutex`, `k_condvar` and read-task record and stack come from pools the image sizes
    (`CONFIG_WZ_OS_MUTEXES`, `CONFIG_WZ_OS_CONDVARS`, `CONFIG_WZ_OS_THREADS`), none from the
    kernel heap. Tests: `wz-runtime-coop` `table_tests` (a grown table spawns again with no
    allocation, a reserved runtime allocates when made and never after, each table refuses one
    past its rows, counted) and `static_tests`, unchanged, for the slot profile. The engine makes
    its runtime at open with `CoopRuntime::opening` over `RuntimeTables` (`MAX_TASKS`,
    `MAX_TIMERS`), a link's cell in the bytes of the session's named task (`RouterSessionTask`
    over `FaceDispatch`), and seals it when the open is over; the ticker's jobs are a table of
    `MAX_TICKERS` rows reserved at open. A local set's tasks go with its last handle, so a task
    that holds a handle of the runtime does not keep the runtime through its table. Remaining,
    each a seam of another unit: the link's readiness box and the read task's boxed body are the
    port's and the links' (U10, U2).
13. **U12. The group.** `wz-capi-coop` `engine/group.rs`, `host_group.rs`, `wz-session-mcu`
    `group_drive.rs`, `group_drive/stage.rs`, `wz-session-core` `multicast_*`. Family: group.
    Tests: a Join past MAX_GROUP_MEMBERS refused and counted.
14. **U13. Typed errors.** `wz-capi-coop` `engine.rs` (`OpenError`), `scout.rs`, `tls.rs`;
    `wz-session-core` `locator.rs`. Family: `z_open` on its failure paths. Tests: each failure
    answers its code with no allocation.
15. **U14. Configuration and the document.** `wz-capi-pico` `config.rs`, `config_policy.rs`,
    `wz-session-core` `policy_document.rs`, `json5.rs`. Family: owned values (the config),
    `config-document`. Done: the config's keys and values in a table and a text of the build's
    size (`CONFIG_ENTRIES`, `CONFIG_TEXT_BYTES`), written in place, an insert allocating nothing
    and a full one refused with zenoh-pico's `_Z_ERR_CONFIG_FAILED_INSERT`; the policy statements
    and the profile kept as the build's ids, so the open's composition borrows them and makes no
    list. Tests: an insert written over its old place, the last place grown in place, a value past
    the text and a key past the rows refused with the config kept, a clone apart from its source,
    the doors keeping the build's own ids. Done since: the document read with no tree into rows, at most
    `CONFIG_DOCUMENT_DEPTH` deep (the `config-document` row expected from 4 to 1, the config
    object; an estimate), `wz/key-ids` among it (`shared_key_ids::read_member_in`, held to the
    tree reader's verdicts by a test). Left: the config's slot in the process pools (U9).
16. **U15. The remaining planes, one commit set each.** Liveliness (`wz-capi-pico`
    `liveliness.rs`, `wz-capi-coop` `engine/liveliness.rs`), scouting (`scout.rs` of both,
    `scouting_host.rs`), connectivity, the admin space (`admin_space.rs` over `adminspace-fixed`),
    history and replay (`advanced*.rs`, `replay_*.rs`, `engine/replay.rs`), end-to-end, catalogs,
    observation. Family: each plane's own. Where each stands:
    - Scouting: both halves done (section 4.15): the window's table of rows and the lent hello,
      and the window's own state held in its place with the buffer its holder lends. Left: the
      locators `z_open` takes from a scout (`locators_by_scout`, a `Vec<String>` handed to the
      open, from `scout_first`'s owned Hello).
    - Liveliness: nothing of the `liveliness-token` and `liveliness-get` rows lies in
      `liveliness.rs` alone. A token's declaration takes the key's declaration
      (`DeclaredKeyexpr`, U6), the port's `String` key (`declare_liveliness_token_on_wire`, U10),
      the engine's row (U5) and the slot (U9); a liveliness subscriber adds the sink factory and its
      closures (`sample_sink`, `make_liveliness_callback`, `engine/liveliness.rs`, U7); a
      liveliness get adds the reply gate's key and the fan's legs (`crate::get`, U8). The plane
      follows those units; a liveliness get copies its key twice (`ke.to_owned()` and the gate's
      `clone`), once of which goes with U8's gate.
    - History and replay: done for the answer. The program's storage, sized by
      `wz_ext_replay_publisher_storage_size`, holds past the rings an answer area (`AnswerArea`:
      the order of the cells, each frame's length, a copy of every frame and one frame's room for
      the release), aligned wherever the storage starts; one answer at a time copies into it under
      the cache's lock and replies after it, so an answer allocates nothing. zenoh-pico answers
      its cache the same way (one outbox held for the whole answer, the cache's lock only for the
      copy); zenoh-ext replies under a read lock of its cache, so its answers run side by side and
      a send waits for them. A query asked of the cache from inside a callback of its own answer,
      on the answering thread, would wait on that answer. The `replay` row's rounds put and do not answer, so the row does not move with it.
    - End-to-end and catalogs: the supervision's streams and the catalogs' entries are lent under
      the process's rows already (`ProcessRows`). In this crate their doors allocate the state's
      `Box<Mutex<..>>` when it is made (U9) and a refusal's text (`format!` and `to_string`
      before the copy into a `z_owned_string_t`, section 4.16, U13); the 24 allocations a round of
      the `e2e` row reads are not traced by this note.
    - Observation: the doors copy to the caller's buffer; the program time base's wait is the
      session's one wait, made with its open, which each read borrows and whose mark each look
      at the clock moves (`time_base.rs` `TimeBaseMoves::moved`), so a read makes none. What
      allocates after the open is the snapshot's JSON for the admin space (`latest_json`, a
      `String`, the admin space's row).
17. **U16. The flip.** `allocation_faults.rs`: `MEMORY_TAKEN_AT_OPEN` set from the build, so a
    failed allocation must be a named error and traffic must allocate nothing; every ratchet row
    locked at 0. The phase P2 ends here.

The order: U0 and U1 lay the ground; U2 to U4 are the traffic path, where the allocations per
message are and where a performance gain is expected; U5 to U8 the declarations and queries; U9 and
U10 the ABI's own objects; U11 to U15 the rest; U16 closes the phase.

## 7. The heap the C ABI build still links

What a cooperative C library still instantiates with the `Heap` policy, or on the heap, after the
units on the track so far (U0, U1, U2, U4 in part, U5 with the observer's watcher lists, U6 in part, U8, U9 in part,
U14 with the document's key ids, U15's scouting window and the time base's wait, the peer-written
tables of section 4.5, the links' reassembly of section 4.9 and U11, the Zephyr kernel objects and the hosts' half), read from the source and to be confirmed by the symbol diff of the library, and the
unit that takes each away. The process pools are in every such library, with or without their doors
(`object-pool`), so what U9 took is gone from a build without the unstable surface as well:

| what | where | taken away by |
|------|-------|---------------|
| the reply stage a held query is answered into (`ReplyStage::held_to`, the build's profile) | `wz-capi-coop` `engine.rs`, `engine/query.rs` | U8's remainder: the held query's row of the query plane |
| the keys canonized for the ABI's own key expressions (`canonize_keyexpr`, a `Heap` string) | `wz-capi-pico` `keyexpr.rs` | U6 |
| the held queries, get events and handed publish legs (`VecDeque`, owned keys and payloads) | `wz-capi-coop` `engine.rs`, `engine/query.rs`, `engine/get.rs` | U4's remainder |
| the faces' list, the keys the sample, reply and query marshals copy and the query marshal's parameters (their payloads and attachments are read where the view holds them), the closures | `engine/registry.rs` (`Vec<FaceTables>`), `wz-capi-pico` `pubsub.rs` (`SampleMarshal`), `get.rs` (`ReplyMarshal`), `query.rs` (`QueryMarshal`), the port's sink factories | 4.6, U9's borrowed marshal for the keys and parameters, U7 |
| the segment ends of a payload a writer appends whole payloads to (`ByteBuf::bounds`, a `Vec` that allocates on the first append), and the attachment a put's or an advanced put's options carry, copied into the `Vec` the options take (`take_moved_bytes_to_vec`) | `wz-capi-pico` `bytes.rs`, `serde.rs`, `pubsub.rs`, `advanced.rs`; `wz-session-core` `PublishOptions` | U9's remainder: the ends in the payload's block; options that read the attachment where it lies |
| what is left of an entity's own copies of its key: a declaration's `Arc<WireDeclaration>`, which every share of the key clones, and the anchor a subscriber's wire key keeps (an `Arc` of two shares of the keys, no copies of them now); a key that opens wild, held twice (the program's object's block and the record's row's, as the object is made before the row); a key the program builds with no session (`z_keyexpr_from_str`, `z_keyexpr_concat`, a clone of a view). The port's arguments are `&str` since U10, so no call makes a copy for the engine | `wz-capi-pico` `keyexpr.rs`, `pubsub.rs` | U6's remainder: the record's rows hold the declarations they name by count (the row of `MAX_DECLARED_KEYEXPRS` counts its holders already), which the publish leg handed to the next holder of a held session (`HandedLeg`) must take too though it is queued outside the session's lock, and the liveliness rows (`engine/liveliness.rs`) with them; U9 for a key of no session |
| each callback's `Arc<Mutex<..>>` in the engine's `targets`, and the `Vec` that holds them | `wz-capi-coop` `engine.rs` | U7 |
| a get's list of the faces it asks (`up_faces`, a `Vec` for each get) | `wz-capi-coop` `engine.rs` | U8's remainder |
| the handles of strings, slices, string arrays, encodings and payload writers (`Box<StringState>`, `Box<SliceState>`, `Box<StringArrayState>` and its entries, the writer's `Box<ByteBuf>`), and a hello lent to a scout's callback with more locators than `MAX_ADMIN_LOCATORS` | `wz-capi-pico` `bytes.rs`, `string_array.rs`, `encoding.rs`, `serde.rs`, `scout.rs` | U9's remainder: their kinds in the process pools, counted by NEW HELD_OBJECTS; the lent hello's views in a table of `SCOUT_HELLO_LOCATORS` |
| the Hello a scout hands `z_open`'s lookup (`scout_first`'s `ScoutedHello`, its locators a `Vec<String>`), and the list a host window makes of a member it lost | `wz-capi-coop` `scout.rs`, `scout_datagram.rs`; `wz-capi-pico` `scout.rs` (`locators_by_scout`); `wz-runtime-posix` `scouting.rs` (`ScoutMembers::drain`) | U15's remainder: the open's locators borrowed from the table's row |
| the OS layer of a host library without `std` (`os-posix`, `os-windows`): a thread's start record, its boxed body and its end flag (the read task's and a reception supervisor's polling task's), the start record of each `z_task_init` on Windows, and the list of sockets each wait over several links named to the system | `wz-host-sync` `lib.rs` (`spawn_fn`), `wz-capi-port` `os.rs` (`sys::spawn`), `wz-capi-pico` `os/windows.rs` (`task_spawn`), `wz-runtime-posix` `net.rs` and `windows/mod.rs` (`wait_ready_among`) | done (U11, the hosts' half, one structure on both systems): a thread's body and the word its end sets lie in a record of a static pool of `wz_host_sync::THREADS`, given back at the join or, for a thread dropped unjoined, when its body returns, a spawn past them refused as one the system refuses; a program's task takes its function and argument from the spawning frame, which waits until it has; a wait's set lies on the waiting stack, `WAIT_SET_SOCKETS` sockets as zenoh-pico's Windows wait is an `fd_set` of 64 there, a wait over more the bounded look. The locks and condition variables were one word of their owner's already, with no system object of their own, and a thread's stack is the system's, as zenoh-pico's tasks' are |
| a host link's waits handed to the session: the boxed duplicate of its socket (`FdReadiness`, `SocketReadiness`) that each dial and each accepted link makes, the `Arc` the engine makes of it, and a wait for room as well (`AndRoom::of`) for each wait on a link that owes a write; the scouting window's list of its members' sockets for each wait (`ScoutMembers::wait`, `wait_readable_any`) | `wz-runtime-posix` `net.rs`, `windows/mod.rs`, `scouting.rs`; `wz-runtime-coop` `session_drive.rs`; `wz-capi-coop` `engine.rs` | U10's and U11's remainder: the wait a value the link lends (`SessionDatagramLink::readiness`) and not a box, the set of the session's waits kept in its arena; the window's under U15 |

## 8. The decisions this design rests on

The product decisions this design needed are Q1 to Q4 of `docs/c-abi-engine-and-memory.md`
section 7, decided by the owner on 2026-11-21: the objects made before any session live in
process pools the library reserves at its first call (Q1); the document's `wz/limits` only
lowers a build value, so an arena never exceeds what the build fixes (Q2); every limit that sizes
a pool is finite in the pico preset, zenoh-pico's own constant where pico has one (Q3); and a full
delivery lane holds the reader for reliable, blocking traffic and drops and counts the rest (Q4).

## 9. What the speed matrix's image allocates

The image of `docs/mcu-speed-matrix.md` (`deploy/zephyr-mcu-speed`, arm W) links this ABI without
`std` (`os-zephyr`, with `queryable`, `liveliness` and `scout-mcu`; no `query` and no
`object-pool`), and its `heap_peak_bytes` is the peak of the kernel heap, which `k_malloc` serves to
the global allocator (`wz_runtime_zephyr::zephyr_image!`) and to the OS layer
(`deploy/zephyr-common/wz_os_zephyr.c`) alike. The rows are read from the source of the calls the
program makes (`z_open`, `z_declare_publisher`, `z_declare_background_subscriber`,
`z_bytes_copy_from_buf`, `z_bytes_clone`, `z_publisher_put`, `z_publisher_get_matching_status`,
`zp_spin_once`, `zp_start_read_task`). The bytes are estimates for a 32-bit core without the
heap's own header of each block, not a measurement.

| site | when | bytes | unit |
|------|------|------:|------|
| the session's arena (`ArenaPlan`, reserved through `AllocatorMemory`) | open | about 190 KB at the build's defaults, the measured peak less what lies outside it (a lane of 64 KiB, 224 rows of the engine's record each with a key of 256 bytes, eight reply rows of 1 KiB, two reassembly chains of 4 KiB, a batch and two slots); about 40 KB at the pico preset (section 9.1); about 22 KB under the limits `arm_w.conf` states | U1; the size is the image's limits |
| the engine (`Arc::new_cyclic`) and its lane (`SharedLane`), with the lane's storage of its event slots (`DELIVERY_LANE_EVENTS`, the build's: a bookkeeping entry, its rehearsal's copy, a place in the list handed on and a record for each) and its two queues of 64 handles, and the planes beside it (`QueryPlane`, `LinkRooms`, `MatchFlips`) | open | a few KB, and about 150 a lane event slot: about 9,600 at the build's 64, about 1,200 at the 8 `arm_w.conf` states | U4 (the records), U1 |
| the registry (`Rc<RefCell<Registry>>`) and a face's peer tables, whose rows of peer declarations and aliases are inline at the build's `MAX_REMOTE_DECLS` and `MAX_PEER_KEYEXPR_ALIASES`, each the id and the place of its key in the key arena (section 9.4) | open | about 1,500 bytes of rows at the build's defaults, about 400 under `arm_w.conf` (16 KB and 1.3 KB while each row held its key inline) | U5 |
| a `k_mutex` for each lock of the engine and of each entity that holds one, a `k_condvar` for each condition variable | open, and each declaration | none from the heap: blocks of two memory slabs of `CONFIG_WZ_OS_MUTEXES` and `CONFIG_WZ_OS_CONDVARS` in `.noinit` (20 to 30 bytes a block, estimate) | done (U11) |
| the session's handle, in a place of the session's arena, and its drive, the engine's own `Arc` kept in the handle | open | none beyond the arena | done (U9, U10) |
| the config (`ConfigState`: `CONFIG_ENTRIES` rows of 16 bytes and `CONFIG_TEXT_BYTES` of text, one block written in place; `arm_w.conf` states 2 and 72) | before the open, dropped by it | about 110, alive while the arena is reserved (about 200 while it was a `BTreeMap<u8, String>` of the mode and the locator, and about 400 at the pico preset's 8 and 256) | U14 done; its pool slot U9 |
| a link's setup: the entropy source's `Arc` (`SharedEntropy`; the box inside holds a source of no size, which allocates nothing), the link's own key space (`LinkOwnSpace`), the lane's gate (`LaneGate`), the socket's `Closer` and its readiness box (`wz-runtime-zephyr` `fd.rs`) | open, each dial | about 200 | U10, U11 |
| the read task: its stack of `CONFIG_WZ_OS_THREAD_STACK_SIZE` and its `struct wz_os_thread` are a static array of `CONFIG_WZ_OS_THREADS` (1 in `arm_w_mt.conf`, 0 in the st cells), as zenoh-pico places its tasks' stacks (`vendor/zenoh-pico/src/system/zephyr/system.c` @ `K_THREAD_STACK_ARRAY_DEFINE(thread_stack_area, Z_THREADS_NUM, Z_PTHREAD_STACK_SIZE_DEFAULT);`); `start_reader`'s flag and boxed body | `zp_start_read_task` (the mt cells) | the flag and the body, some tens (estimate) | the stack and the record done (U11); the flag and the body U10 |
| a publisher: its handle's `Box`, its key's `Arc<WireDeclaration>` and the `k_mutex` of its write filter's listeners (its key's literal and its filter's key are one block of the key arena, which the record's rows of the key share); `acquire_keyexpr` and `declare_write_filter` take the key as a borrow (U10); dropped within the call, the Interest form's rest of the key | each declaration | about 200 kept (estimate) | U9, U6's remainder, U11 |
| a background subscriber: the closure's `Arc<CClosure>` and its `ReleaseLatch`, its key's declaration, the wire key's anchor (an `Arc` of two shares of the keys, whose text is the key arena's), the sink factory's `Arc`, the engine's `BoxedSink`, the callback's boxes, its `Arc<Mutex<..>>` and `k_mutex` in `targets`; and, dropped within the call, the key canonized as a `String`, which the port takes as a borrow (U10) | each declaration | about 300 kept (estimate) | U7, U6's remainder, U5 |
| a query a queryable answers: each reply written into the link's transmit slot as it is made (`Onward`), with no stage | each query answered | none in this ABI's half, read from the source (the session's own get still builds its owned reply) | done (U8) |
| `z_bytes_clone`: the payload's place (`box_bytes`) | each put of the put cell | 24, freed by the put | U9 |
| `z_bytes_copy_from_buf`: the place, the `Arc<Backing>` and the copied bytes | each round trip of the rtt cell | 56 and the payload, freed by the put | U9 |
| `z_publisher_put` on a publisher declared with no options of its own beyond the congestion control: `publish_plain`, `put_plain_filtered`, `send_plain_put_qos` into a slot the arena lent | each put | none, read from the source | done (U2) |
| a droppable publish that finds the session held (`HandedLeg`: the key, the wire key, the payload, the options, the faces it was dropped on) | not in these cells: their publishers block | the key, the payload and about 80 | U4's remainder |
| a read step and its delivery: the batch read into the arena's buffer, the sample into the lane, the callback handed `SampleMarshal::lent` | each sample | none in this ABI's half, read from the source; the host reading of C1nh counts what the receiving thread allocates as `subscriber-receive-*` | U3, U4 |
| `z_publisher_get_matching_status` | each poll of the wait for a match | none, read from the source | done |

**The peak is the open.** What a message or a declaration takes is a place freed by the put that
follows, or a few hundred bytes for each of the program's three entities at most; what the open
takes stays until the close and coincides with the config the open drops. So the image's
`heap_peak_bytes` is, within some hundreds of bytes, the arena and the objects of the open, and
the order this note's units are done in does not move it until the arena is the image's size:
the rows the image's limits state (`arm_w.conf`), not a host session's.

**The floor at zenoh-pico's constants.** Under the limits `arm_w.conf` states, the arena's buffers
are a receive buffer of the batch (2,048), two transmit slots of it (4,096), two reassembly chains of
the largest rejoined message (8,192) and a lane that holds one record of that message (4,180 at the
least): 18,516 bytes before any table, where zenoh-pico's client holds a receive and a transmit
buffer (`vendor/zenoh-pico/src/transport/unicast/transport.c` @
`ztu->_common._wbuf = _z_wbuf_make(wbuf_size, false);`), allocates a reassembly buffer when a
fragment first arrives (`vendor/zenoh-pico/src/transport/unicast/rx.c` @
`dbuf = &peer->common._dbuf_reliable;`), keeps no lane, and peaked at 8,360 bytes in the put cell.
A reservation of the worst case, which decision E3 asks for, is above a heap that grows only to
what a run uses until the run uses it: zenoh-pico's own worst case in these cells adds its two
reassembly buffers, 8,192 bytes. What would bring the reservation under zenoh-pico's peak is a
change of the engine's form and not of a limit: one transmit slot, as zenoh-pico's batching keeps
one buffer; one reassembly buffer for a link whose peer sends one reliability; and a single-threaded
session that hands a sample to its callback from the receive buffer, as zenoh-pico does, with no
lane. Each is a decision for the record of `docs/c-abi-engine-and-memory.md`, and none is taken
here.

### 9.1 The pico preset of the limits

zenoh-pico bounds its entity tables, its pending gets and its staged replies by no constant: it
holds them in lists on the heap. A wz limit that sizes the same table has a default that sizes a
host's session (sixteen of each entity, 224 rows of the engine's record), which the arena reserves
whole. The declaration now states, for each such limit, the value of the pico preset in
`[limit.pico_preset]` of `deploy/wz-config.toml`, with what of zenoh-pico's own build it holds; the
generated Kconfig makes each the limit's default under one switch, `WZ_LIMITS_ZENOH_PICO`, which
zenoh-pico's defconfig (`configs/zenoh-pico_defconfig`) turns on and every other build leaves off,
so the zenoh and zenoh-c presets and the Rust nodes keep their defaults. A limit an image states is
its own either way, and the build still refuses a document that raises a value (decision Q2).

| limit | default | pico preset | what it holds |
|-------|--------:|------------:|---------------|
| `MAX_SUBSCRIPTIONS` | 16 | 3 | the most subscribers pico's API tests hold on one session |
| `MAX_QUERYABLES` | 16 | 4 | the most queryables pico's API tests hold on one session |
| `MAX_LOCAL_TOKENS` | 8 | 2 | the most tokens pico's API tests hold on one session |
| `MAX_LIVELINESS_SUBSCRIPTIONS` | 8 | 1 | one at a time, in pico's examples and API tests |
| `MAX_PUBLISHERS` | 16 | 2 | the speed matrix's program, which holds two |
| `MAX_QUERIERS` | 16 | 2 | pico's queryable API test, which holds two |
| `MAX_MATCHING_LISTENERS` | 16 | 1 | one at a time, on the entity under test |
| `MAX_DECLARED_KEYEXPRS` | 80 | 14 | a key for each entity the preset admits, as the default is |
| `MAX_PENDING_QUERIES` | 16 | 2 | a get and a querier's get pending at once, in pico's cancellation test |
| `MAX_PENDING_LIVELINESS_GETS` | 8 | 1 | one at a time |
| `MAX_PENDING_DECLARES` | 32 | 4 | the answer to a match-all interest: each subscriber and a final |
| `MAX_PENDING_REPLIES` | 8 | 2 | two queries replied to, in pico's queryable API test |
| `MAX_PENDING_FINALS` | 8 | 2 | two queries held, in the same test |
| `DELIVERY_LANE_BYTES` | 65,536 | 4,380 | the least lane the build accepts (`holds_a_read`), below |
| `MAX_FACES` | 1,000 | 10 | zenoh-pico's `Z_LISTEN_MAX_CONNECTION_NB`, a constant no switch sets (section 9.6) |
| `MAX_ACCEPT_PENDING` | 100 | 1 | zenoh-pico's accept task, which handshakes one link at a time |
| `SESSION_MAX_REMOTE_DECLS` | 16,016 | 32 | a peer's own bound for the one face of a client, twice it for a listener's faces together (section 9.6) |
| `SESSION_MAX_PEER_KEYEXPR_ALIASES` | 16,016 | 32 | as `SESSION_MAX_REMOTE_DECLS` |
| `SESSION_MAX_INBOUND_SUB_INTERESTS` | 16,016 | 16 | a peer's own bound: zenoh-pico remembers no interest of a peer |

The limits zenoh-pico has a constant for already default to it (`PICO_UNICAST_BATCH_BYTES` 2,048,
`PICO_MULTICAST_BATCH_BYTES` 2,048, `PICO_FRAG_MAX_BYTES` 4,096) and have no preset.
`MAX_KEYEXPR_BYTES` keeps 256: zenoh-pico bounds no key, and a shorter bound would refuse keys a
router declares and samples it delivers that zenoh-pico takes. The limits of what the peer writes
(`MAX_INBOUND_SUB_INTERESTS`, `MAX_REMOTE_DECLS`, `MAX_PEER_KEYEXPR_ALIASES`) keep theirs too: the
peer, not the program, decides how many it sends, and zenoh-pico allocates each as it comes with no
bound, so a lower preset would refuse declarations zenoh-pico accepts. Their memory is cut by the
form of their rows instead: one pool of each kind the faces share, bounded by what the session's
faces hold together (the three `SESSION_MAX_` limits above), whose preset is at least one peer's
bound, so a client of the preset holds what it held (section 9.6).

The lane's preset is one record's room: the larger of the batch and the largest rejoined message
(4,096), a key of 256 bytes, a clock id of 16 and a 4-byte id for each of the 3 subscribers. Both
threading arms deliver from the call that reads (`CoopEngine::read`: a step, then the delivery
after the lock), so the room one record takes is what either needs; a link is read only while the
lane has that room, so at exactly the floor a pass hands on one record of a full lane, which is what
`arm_w.conf` states at its own limits, 4,180 bytes (section 9.5).

### 9.2 The heap each cell is expected to peak at

Estimates for a 32-bit core from the rows of section 9, a row of the engine's record about 52
bytes and every other keyed row its key's place in the key arena, 12 bytes, where a key of
`MAX_KEYEXPR_BYTES` and its length were inline before section 9.4 (260 bytes at 256, 68 at the 64
`arm_w.conf` states); not a measurement. `arm_w.conf` states every limit the preset
sets, so for the speed image as committed the preset changes nothing: its own limits are smaller
still. The preset is what an image of the pico C ABI that states no limit gets.

| part of the arena | build's defaults | pico preset alone | `arm_w.conf` |
|-------------------|------------------:|------------------:|---------------:|
| a receive buffer and one transmit slot of the batch (two slots before section 9.4) | 4,096 | 4,096 | 4,096 |
| the delivery lane | 65,536 | 4,380 | 4,180 |
| the session's two reassembly buffers of the largest rejoined message, which its links share (section 9.5) | 8,192 | 8,192 | 8,192 |
| the application's tables (48, 10 and 4 rows), each row its key's place | about 1,900 | about 420 | about 180 |
| the pending gets, each row its key's place | about 630 | about 100 | about 140 |
| the face's peer tables (its interests, declares, replies, finals), an interest's row its key's place | about 19,900 | about 4,200 | about 600 |
| the engine's record of declarations (224, 34 and 16 rows), each row holding its key's place (about 52 bytes a row) | about 11,700 | about 1,800 | about 900 |
| the key arena every keyed row keeps its key in (`KEY_ARENA_BYTES`: 97,152, 4,096 and the 1,024 `arm_w.conf` states, and its state) | about 97,200 | about 4,150 | about 1,060 |
| **the arena** | **about 209,100** | **about 27,300** | **about 19,400** |

Outside the arena the open takes the registry's rows of what the peer declares and its aliases,
inline at their build capacities and each the id and place of a key (24 bytes), the engine with its
lane's event records, the kernel objects and the handle (section 9's rows), and each declaration a
few hundred bytes: about 6,000 to 14,000 bytes at the defaults (the measured peak less the arena,
less the 15,900 bytes of key text the registry's 64 rows held inline), unchanged by the preset,
which lowers no limit of the peer's, and about 5,100 under `arm_w.conf`, whose peer tables hold
four rows of each.

| cell (threads, sizes) | zenoh-pico, measured | arm W, build's defaults, measured | arm W, pico preset alone | arm W, `arm_w.conf` |
|------------------------|---------------------:|----------------------------------:|-------------------------:|----------------------:|
| st, 8 and 64 bytes | 8,360 to 9,960 | 218,768 to 219,464 | about 34,000 to 42,000 | about 24,900 to 26,900 |
| st, 1,024 bytes | 8,360 to 9,960 | 218,768 to 219,464 | the same, and a copied payload of about 1,100 in the rtt cell | about 25,900 to 27,900 |
| mt, every size | 8,360 to 9,960 | 218,768 to 219,464 | st's, and about 250 for the read task's thread (its stack is the static pool `arm_w_mt.conf` places) | st's, and about 250 |

The arm W cells measured 42,800 to 43,500 bytes once the engine's record kept its keys in the key
arena (QEMU, `mps2-an385`), about 16,000 over the `arm_w.conf` column of the table before
the application's and the peers' rows followed. Section 9.5 says what of it is known: no thread,
and the lane's event slots at the build's 64.

### 9.3 What the reservation still holds that zenoh-pico's heap does not

Of the floor above, the receive buffer and one transmit slot are what zenoh-pico's client holds too.
The rest, and what each form of section 9 would take:

- **A second transmit slot, 2,048 bytes a link: taken (section 9.4); what follows is why it was
  kept.** Every cooperative build batches
  (`transport-batching` is in `wz-capi-coop`'s base), and the session core holds a batch frame open
  in a slot its link lent across the window's calls, one for each conduit with a frame open
  (`open_lent_batch` in `crates/wz-session-core/src/session_actions.rs`). A transport message sent
  while it is open (a KeepAlive, a Close: `send_control_lent`), a frame of another priority under
  `transport-qos`, and the next frame of a stream link that has not finished writing the last
  (`TxLender::frame_prefixed`) each take a slot of their own, and under `tx-lend-only`, which the C
  library selects, a frame that finds none is refused and counted (`LinkDropCause::NoTxSlot`), not
  queued. zenoh-pico keeps one buffer because a transport message sends the open batch first
  (`vendor/zenoh-pico/src/transport/common/tx.c` @
  `static z_result_t _z_transport_tx_send_t_msg_inner(_z_transport_common_t *ztc, const _z_transport_message_t *t_msg,`).
  One slot is that change to the session core's send path: close the open frame before another frame
  takes the link's slot, and wait on a stream link's write rather than refuse; it is not a limit,
  and no build of the engine can take it as the send path stands.
- **The second reassembly buffer, 4,096 bytes a session: already zenoh-pico's own.** zenoh-pico keeps
  one defragmentation buffer for each reliability of a transport
  (`vendor/zenoh-pico/include/zenoh-pico/transport/transport.h` @ `_z_wbuf_t _dbuf_best_effort;`),
  each `Z_FRAG_MAX_SIZE` long when a fragment first arrives
  (`vendor/zenoh-pico/src/transport/unicast/rx.c` @
  `*dbuf = _z_wbuf_make(Z_FRAG_MAX_SIZE, false);`): two at its worst, which is what the arena lends
  each session (`LENT_CHAINS`, the per-peer quota of `reassembly_pool_mcu`, 2). One buffer would
  drop the chain of one reliability while the other's is open, which zenoh-pico rejoins. The
  difference left is only where they lie: a chain claims one when its first fragment comes, as
  zenoh-pico takes one, but from a table the open reserved (decision E3), which the session's links
  share (section 9.5); the two stage any two chains, where zenoh-pico's are one of each reliability.
- **Key text in every row, about 22,000 bytes at the preset: taken (section 9.4); what follows is
  the cost as it stood.** The lent
  policy holds a key inline in the row that owns it (`Lent`'s text is `heapless::String` of
  `MAX_KEYEXPR_BYTES`), so every row that keeps a key pays 260 bytes whatever the key's length. At
  the preset that is the engine's 34 rows, the application's 10, a face's 22 and the registry's 32
  rows of what the peer declares and its aliases, about 98 rows and 25,500 bytes, of which keys of
  30 bytes and their lengths would use about 3,300; under `arm_w.conf`'s 64-byte keys, 35 rows and
  about 2,400 bytes, of which such keys would use about 1,200. One shared arena of key bytes would
  need a limit of its own for the total (none is declared), an allocator of spans that frees and
  compacts under the session's lock, and each keyed row of the engine
  (`crates/wz-capi-coop/src/engine.rs`) and of the session core's registries to hold a span of it
  instead of a string. Section 9.4 took it, the engine's record first and then the session core's
  tables through the storage policy.

### 9.4 The key arena and the one transmit slot

**One key arena (`KEY_ARENA_BYTES`).** The rows of the engine's record of the session's own
declarations (`crates/wz-capi-coop/src/engine.rs`: its subscribers, queryables, tokens,
liveliness subscribers, declared keys, write filters, matching listeners and Interests) hold their
key as a `KeyRef` (`crates/wz-session-core/src/key_arena.rs`): the place of a block in one key
arena the open lends from the session's arena after the record, and the key's length, 12 bytes on
a 32-bit core where the row held 260. A block is a header of 8 bytes (its length and how many rows
hold it) and the key's bytes, rounded up to 4. A key takes the free block of the lowest address
that holds it, the rest of a longer block staying free, or else the next bytes above every block; a
block given back is merged with a free neighbour on either side, and one that ends where the
untouched bytes start is given back to them, so no two free blocks lie side by side and keys of the
lengths a program declares and undeclares reuse the same bytes. A clone shares the block. A key
the arena has no room for is refused as a full table refuses a row: the declaration is refused
before an id is taken or anything is sent, and the C program reads `Z_ERR_SYSTEM_OUT_OF_MEMORY`
(`crates/wz-capi-pico/src/pubsub.rs`), the refusal zenoh-pico returns for a declaration its heap has
no room for. The arena's state is cells reached under the session's
one lock, as the rest of the engine's state is.

**The session core's tables, through the storage policy.** The tables of
`crates/wz-session-core` are generic over the storage policy, and the policy now names the key a
row keeps and where the table makes it (`Storage::Key` and `Storage::Keys` in
`crates/wz-session-core/src/bounded.rs`): on the growable policy a `String` made by nothing, on
the static one a buffer of `MAX_KEYEXPR_BYTES` inline in the row, both unchanged, and on the lent
one a `KeyRef` made in the session's key arena, which each table is handed with its rows
(`LentKeys`). So every keyed row the C library lends keeps its key's place: the application's
subscribers, queryables, tokens and liveliness subscribers, each face's pending gets (the key a
get is asked under, none for one that accepts any key), each face's peer interests, and, inline
at their build capacities in the registry, each face's rows of the aliases, subscribers,
queryables and tokens its peer declares (`PeerTables::lend_rows` hands them the key space). A
registration of the program's whose key finds no room is refused as a full table refuses it
(`RegisterError::TableFull`), and the engine refuses the declaration before anything is sent. A
key a peer sends that finds no room is dropped and counted with its table's refusals
(`IdMap::count_refused`), and the arena counts it too (`KeyCounts::refused`); an interest whose
key finds none is answered by its `Final` alone. zenoh-pico answers a remote declaration its heap
cannot hold by dropping it. Every face's tables are handed the session's key arena, the
sets the open lent and a set of no rows for a face past them alike, and a side's interest rows lent
after it keep it (`SubscriberPeer::lend_rows`): a group's face, whose peers are the members, keeps
what they declare as a unicast face does.

The limit's default holds, with a key of `MAX_KEYEXPR_BYTES` in a block of 264 bytes, every
keyed row the build's defaults lend for one face: the record's 224, the application's 48, the
face's 16 pending gets and the 80 of what its peer declares and asks, 97,152 bytes, so a build that
states nothing refuses no key it took before. The pico preset is 4,096: the record's 34 rows, the
application's 10 and the face's 2 pending gets at the preset's other values with a key of up to 52
bytes, about twice the longest key of zenoh-pico's examples
(`vendor/zenoh-pico/examples/unix/c11/z_pub.c` @ `char *keyexpr = "demo/example/zenoh-pico-pub";`),
2,760 bytes, and 22 such keys of what the peers declare. `arm_w.conf` states 1,024: its 21 rows
with keys of nine bytes, 420 bytes, and 30 keys of that length that the router declares. A local
declaration's key is held twice, by the engine's record and by the application's table, each in a
block of its own.

**One transmit slot (`LINK_TX_SLOTS`, `crates/wz-capi-coop/src/arena.rs`).** A link is lent one
slot of the batch, as zenoh-pico keeps one write buffer. The batch a session holds open is sent
before anything else takes the slot: a transport message drains it first (`send_close_with_reason`
and `send_keep_alive` in `crates/wz-session-core/src/session_actions.rs`, as zenoh-pico's
`vendor/zenoh-pico/src/transport/common/tx.c` @
`static z_result_t _z_transport_tx_send_t_msg_inner(_z_transport_common_t *ztc, const _z_transport_message_t *t_msg,`
does), and a frame of the other reliability closes it. A datagram link has the slot back as soon as
it is sent. A stream link keeps it while the stream owes part of the frame: the next frame asks the
link for room within its message's wait, which writes what is owed (`wait_for_room` in
`crates/wz-runtime-coop/src/stream_link.rs`), each fragment of a chain does the same, and a message
that asks for a slot meanwhile writes what is owed first, as far as the stream takes it without
waiting (`tx_slot_acquire`); one the stream frees nothing for is refused and counted
(`LinkDropCause::NoTxSlot`), as a droppable message is dropped by the congestion policy. A build
that negotiates more than one conduit (`transport-qos`, which the C library does not select) would
hold a batch open on each, and one slot would refuse the second; it is not a build of this ABI.

**What each cell is expected to peak at.** With all of it, section 9.2's estimates: the pico
preset's arena about 27,300 bytes and its cells about 34,000 to 42,000 (about 21,000 less than with
the session core's keys inline, 15,900 of it the registry's rows of what the peer declares),
`arm_w.conf`'s arena about 19,800 and its cells about 24,900 to 27,900 (about 700 less: its keys
were already 64 bytes and its peer tables four rows), against zenoh-pico's 8,360 to 9,960. At the
build's defaults the arena is about 18,000 bytes larger and the registry about 15,900 smaller,
which no host measures as a peak. What is left above zenoh-pico's peak is section 9.5.

### 9.5 What each cell's heap still holds, against zenoh-pico's

The arm W cells as `arm_w.conf` builds them, for a 32-bit core; estimates read from the source, not a
measurement. zenoh-pico's put cell peaked at 8,360 bytes: its receive and transmit buffers and its
session's lists.

**The 16,000 bytes the measurement held beyond the estimate are not a thread.** The st cells start
no task: the open's start of the read task and `zp_start_read_task` are compiled only with
`multi-thread` (`crates/wz-capi-pico/src/session.rs`), which the st image's staticlib is built
without (`deploy/zephyr-mcu-speed/CMakeLists.txt` passes it for `mt` alone), `start_reader` is the
engine's one caller of `wz_os_thread_spawn` (`crates/wz-capi-coop/src/engine.rs`), and the st
cells' report (`MCU-SPEED STACK`) lists the kernel's, the network stack's and `main` and no other
thread, where the mt cells list `wz-os`. What the estimate left out that the source shows is the
lane's event slots: the lane's storage of them is the build's (`DELIVERY_LANE_EVENTS`, 64 unless the
image states fewer), on the heap beside the engine and not in the arena, about 150 bytes a slot (an
entry of the lane's bookkeeping and one of its rehearsal's copy, a place in the list handed on, and
the record of what a sample is besides its bytes), about 9,600 bytes at 64. `arm_w.conf` states
8: the samples of a datagram are one record, and a link is read only while the lane has a slot free
(`a_lent_batch_takes_one_event_slot_however_many_samples_it_holds` in
`crates/wz-capi-coop/src/tests/lane.rs`). About 7,000 bytes of the measurement are left that this
reading does not attribute; what they are is a measurement's to say (the heap after `z_open` and
after each declaration), not a further estimate's.

**The reassembly buffers are the session's, each claimed when a chain starts.** A link's Router
claims a buffer of the session's one table when a chain's first fragment arrives and gives it back
when the chain ends, completed, aborted or timed out (`LentStaging` in
`crates/wz-session-core/src/chain_staging.rs`), and the table holds `LENT_CHAINS` buffers however
many links the session may hold, one for each reliability a peer has a chain open in, as zenoh-pico
keeps one for each (`vendor/zenoh-pico/include/zenoh-pico/transport/transport.h` @
`_z_wbuf_t _dbuf_best_effort;`). A chain that finds none free is refused as pool exhaustion: the
Router drops it and the session counts it (`RefuseReason::PoolExhausted`, reported as
`ReassemblyDropReason::PoolExhausted`), as zenoh-pico drops a chain whose buffer it cannot allocate
(`vendor/zenoh-pico/src/transport/unicast/rx.c` @ `*dbuf = _z_wbuf_make(Z_FRAG_MAX_SIZE, false);`).
The table is still reserved at the open (decision E3), so a session of one link, which these cells
are, reserves the 8,192 bytes it did; one that listens no longer reserves two for each link it may
hold.

**The lane is one record's room.** Each call that reads hands what it read to the callbacks before it
returns, in both threading arms (`CoopEngine::read`: a step, then the delivery after the session's
lock), so the st arm delivers in the call that reads, as zenoh-pico does. What the lane holds a
call's records across is the lock: the callbacks run after it, so a callback may call into its
session (decision D8). `arm_w.conf` states the least lane the build accepts, one record of the
largest message at the image's limits, 4,180 bytes
(`the_speed_images_lane_is_the_room_of_one_record`), and a pass reads one datagram, as zenoh-pico's
read takes one batch. A lane of none would need the records the lane writes whole to be read where
they lie as well (a rejoined message in its reassembly buffer, held until its callbacks return as a
datagram is held), and a sample offered from inside a callback kept in a small area of its own; that
is the next cut, not taken here.

| what | bytes | zenoh-pico | the next structural cut |
|------|------:|------------|--------------------------|
| what the measurement held beyond the estimate and this reading does not attribute | about 7,000 | none | measure the heap after the open and after each declaration |
| the session's reassembly buffers, claimed by a chain while it is open | 8,192 | none until a fragment arrives, then one per reliability | a count of them the image states, none for an image whose messages fit a batch, its chains then refused and counted |
| the delivery lane | 4,180 | none: a sample is handed to its callback from the receive buffer | the records written whole read where they lie, and a re-entered callback's samples in a small area of their own |
| the lane's event slots (8) and its two queues of 64 handles | about 1,200 and about 1,150 | none | the queues' capacity is their document's (`sources/session/delivery_lane_queue.scxml`): one of the image's event slots needs the document to take it from the limit |
| a receive buffer and one transmit slot of the batch | 4,096 | the same, a read and a write buffer | none: this is zenoh-pico's own floor |
| the objects of the open outside the arena: the engine and its planes, the kernel objects, the handle, the registry's face tables | about 5,100 | its session and transport structs | the registry's face tables (their rows of what the peer declares, inline at the build's capacities, about 400) lent from the arena as the other tables are (section 4.5); the kernel objects one per lock the engine keeps, not one per entity |
| the tables lent from the arena: the record, the application's, the gets, a face's peer tables, and the key arena | about 2,900 | lists of what is declared, allocated per entity | the key held twice by a local declaration (the record's and the application's table's) shared as one block, by handing the record's `KeyRef` to the registration, about 100 here and 600 at the pico preset; the record's own rows and the program's objects already share one block for a key (U6) |
| each declaration and each message | some hundreds, freed by the put | the same order | the places the owned objects of section 9 still allocate (U6, U7, U9) |

What each cell is expected to peak at with the event slots `arm_w.conf` states (about 8,400 bytes
fewer than at 64) and its lane at the floor (428 fewer), from the cells measured before them; the
reassembly buffers move no cell, each holding one link:

| cell (threads, workload, size) | zenoh-pico, measured | arm W, measured before | arm W, expected |
|--------------------------------|---------------------:|-----------------------:|----------------:|
| st, put, 8 bytes | 8,360 | 42,792 | about 34,000 |
| st, sub, 8 bytes | 8,216 | 43,008 | about 34,200 |
| st, rtt, 8 bytes | 9,960 | 43,488 | about 34,700 |
| st, 64 and 1,024 bytes | 8,216 to 9,960 | not measured since section 9.4 | the 8-byte cell's, and a copied payload of about 1,100 in the rtt cell at 1,024 |
| mt, every workload and size | 8,312 to 10,072 | not measured since section 9.4 | st's, and about 250 for the read task's thread (its stack is the static pool `arm_w_mt.conf` places) |

### 9.6 The faces a session holds, and the pico preset of them

A session of the cooperative engine holds the dial role's face, a face for each group it joins and
as many faces besides as its config's `max_faces` admits: the links it accepts, a link still in its
handshake among them (`Core::accept_face` counts it), and those it attaches. Its open lends each of
those faces one set of a face's tables, and each link the buffers of one link; a listener's arena
also holds the buffers of `accept_pending` links more (`ArenaPlan::of` in
`crates/wz-capi-coop/src/arena.rs`).

**What it was.** The open lent a set for every link it might hold, the handshakes included, and the
pico interface stated zenoh's numbers for a listener with nothing to lower them by: 1,000 faces and
100 handshakes, so a listening session lent 1,101 sets and the buffers of 1,101 links, and a client
one of each.

**The two limits.** `MAX_FACES` (default 1,000, zenoh's `transport/unicast/max_sessions`) and
`MAX_ACCEPT_PENDING` (default 100, zenoh's `transport/unicast/accept_pending`) are limits of the
session, bound at the open and read from its snapshot, so a document's `wz/limits` states them; the
arena holds the config's two numbers to the session's values under the build's, and a config or a
document over either is refused by the limit's name (`ArenaRefused::Limit`), as a stage after the
build only lowers the memory the build fixes. The pico interface states the session's values for a
listener (`admitted_faces`, `admitted_handshakes`) and no face besides the dial for a session that
listens on nothing, as zenoh-pico's client holds its one transport. The sets are lent for the faces
alone: the dial role's, `max_faces` and the groups. The Rust and zenoh-c nodes run on the tokio
engine, which keeps zenoh's own `max_sessions` and `accept_pending` and reads neither limit.

**The pico preset.** zenoh-pico refuses an inbound link once its unicast transport holds
`Z_LISTEN_MAX_CONNECTION_NB` peers, a constant of its configuration template that no build switch
sets (`vendor/zenoh-pico/include/zenoh-pico/config.h.in` @ `#define Z_LISTEN_MAX_CONNECTION_NB 10`,
`vendor/zenoh-pico/src/transport/unicast/accept.c` @
`if (_z_transport_peer_unicast_slist_len(ztu->_peers) >= Z_LISTEN_MAX_CONNECTION_NB) {`), and its
accept task runs the whole handshake of one link before it takes the next
(`vendor/zenoh-pico/src/transport/unicast/accept.c` @
`ret = _z_unicast_handshake_listen(&param, ztu->_common._link,`). The preset is those: `MAX_FACES` 10
and `MAX_ACCEPT_PENDING` 1 (section 9.1).

**What one set holds.** A face's set is `FaceTables` (`crates/wz-capi-coop/src/engine/registry.rs`):
the face's pending gets and `PeerTables` of what its peer writes and is owed. What the peer is owed
is rows the arena lends each set at the open, sized by limits a document lowers; the reply stage is
lent none, as nothing stages there (this engine's queryable answers into a stage of its own, and the
sink it registers leaves the face's untouched). What the peer writes by its own choice is in the
session's pools or the face's own spans (below): the set holds a head for each of those tables, a
pointer and three counters, in the registry. Estimates, not a measurement; the arena's parts are
its row `peer tables` and its row `pending gets`:

| part | where | sized by | build's defaults | pico preset |
|------|-------|----------|-----------------:|------------:|
| the answers staged to the peer's interests, and the `Final`s owed | arena | `MAX_PENDING_DECLARES`, `MAX_PENDING_FINALS` | 32 and 8 rows | 4 and 2 |
| the face's pending gets | arena | `MAX_PENDING_QUERIES`, `MAX_PENDING_LIVELINESS_GETS` | 16 and 8 rows | 2 and 1 |
| the heads of the peer's aliases, subscribers, queryables, tokens, the two repeats and interests | registry | none: the rows lie in the pools or the face's spans | 7 heads, about 110 on a 64-bit host and 70 on a 32-bit core | the same |

A set is about 7,600 bytes on a 64-bit host at the build's defaults and about 1,400 at the pico
preset, besides its 110 of registry heads, and a link's buffers about 4,100 at a batch of 2,048
bytes. Before the pools a set also held a reply stage (8 replies of a key and a payload, about 10,500
bytes at the defaults, 2,600 at the preset), its peer's interests (16 rows, about 640 bytes) and,
inline in the registry, its peer's declarations at the build's capacities (about 2,200 bytes on a
64-bit host, 2,100 on a 32-bit core), whatever its peer declared.

**What the peers write, by how many faces hold them.** `PeerPools` in
`crates/wz-session-core/src/peer_tables.rs`, the plan's rows `peer alias pool`, `peer declaration
pools` and `peer interest pool`, one area each.

- A session of many faces lends one pool of each kind, holding the fewer of its `SESSION_MAX_` limit
  and what the faces could hold at one peer's bound. A row is its item and a link of two `u16`s,
  declared beside the item's fields: on a 32-bit core a row of an id and a key's place keeps the
  item's 24 bytes, the link in the room the id's alignment leaves; a row whose item leaves none
  (a queryable's, a repeat, an interest, and on a 64-bit host every one) is 8 bytes longer. A pool's
  state is a pointer and six `u16`s, one span of 16 bytes on a 32-bit core and 32 on a 64-bit host.
- A session of one face lends each table a span of its own of that face's bound (the session's
  limit, where lower), with no link and no state: the aliases' span, one span the declaration
  tables share, each table's rows after the one before's, and the interests' span. A face past
  such a plan is handed none of them and holds what its peer writes in nothing.

Estimates, not a measurement, on a 64-bit host:

| kind | one face at the pico preset (16 of each, its own spans) | a listener at the pico preset (pools of 32, 32, 16) | a listener at the build's defaults (pools of 16,016 of each) |
|------|---------------------------------------------------------:|-----------------------------------------------------:|-------------------------------------------------------------:|
| aliases | 384 | 1,056 | 512,544 |
| subscribers, queryables, tokens, the subscribers' and the queryables' repeats | 1,792 | 5,024 | 2,434,592 |
| interests | 640 | 800 | 768,800 |
| together | 2,816 | about 6,880 | about 3,716,000 |

The heads and the spans of one face together take no more than the inline tables of the same
bounds did, checked by `one_faces_own_spans_take_no_more_than_the_inline_tables`
(`crates/wz-session-core/src/peer_tables.rs`): on a 64-bit host the same bytes (a head is the room
the inline table's length, count and padding took; the repeats' heads are 8 bytes longer each and
the interests' 16 shorter), on a 32-bit core 24 fewer at the speed image's bounds. What the spans
may add is their rounding to an arena's spans, under 16 bytes for each of the three, none at bounds
whose rows fill 16 bytes. A row of a pool no face has ever held is never written (the pool hands
out the rows past those written last), so on a host only the rows the peers declared become
resident.

**What a session reserves.** The arena of a client, and of a peer, at the pico preset is checked by
`the_pico_presets_arena_for_a_client_and_a_peer_is_the_notes_sum`
(`crates/wz-capi-coop/src/tests/arena.rs`): a client lends one set, the buffers of one link and the
spans of its one face; a peer lends the client's rows, with a set and a link's buffers for each of
its 10 faces and a link's buffers for its one handshake, and pools at the preset's limits in place of
the spans, every other row item for item the client's. So a peer reserves about
10 × (1,400 + 4,100) + 4,100 + (6,880 − 2,816), about 63,200 bytes, beyond the client's arena, and
10 sets of registry heads, about 1,100 bytes, beside it.

| session | sets | links | reserved by the faces (64-bit host, estimate) |
|---------|-----:|------:|----------------------------------------------:|
| a listener at the build's defaults, a set per handshake | 1,101 | 1,101 | about 25,100,000 in the arena and 2,400,000 of registry rows |
| a listener at the build's defaults, a set per face | 1,001 | 1,101 | about 23,200,000 and 2,200,000 |
| a listener at the build's defaults, with the pools | 1,001 | 1,101 | about 15,840,000 and 110,000, the pools' rows written only as peers declare |
| a listener at the pico preset, a set per face | 11 | 12 | about 100,000 and 24,000 |
| a listener at the pico preset, with the pools | 11 | 12 | about 71,500 and 1,200 |
| a client, a set per face | 1 | 1 | about 8,700 and 2,200 at the preset, 22,800 and 2,200 at the defaults |
| a client, with its own spans | 1 | 1 | about 8,300 and 110 at the preset, 14,500 and 110 at the defaults |

A client's tables take what its inline tables took; what it no longer reserves is the reply stage
nothing staged in. A listener's faces share the pools: a peer of the preset reserves about 51,000
bytes fewer than with a set of every table per face, about 28,600 of them the reply stages.

**On a host.** Only the pages a session writes are resident, so a listener's resident memory falls by
what its open wrote of the sets and links it no longer lends: up to the 12,000,000 bytes the
measured listener held above zenoh-pico's (38.9 MB against 26.9 MB), expected near zenoh-pico's for a
build of the preset, which is to be measured. The parity harness (`scripts/pico-compare.sh`) builds
wz's side with `wz_config.py --original-features zenoh-pico`, the capabilities of zenoh-pico's
defconfig and not its limits (the `WZ_LIMIT_*` environment `--resolve-env` gives), so as committed
its build keeps the defaults and moves only by the 100 sets of the handshakes, about 1,900,000 bytes
of reservation, until it states the preset's environment.

**On an MCU.** The speed image is a client that states its own limits (`arm_w.conf`: four
declarations of each kind, four aliases, two interests) and none of the session's, so its tables
take spans of their own of those bounds: on a 32-bit core 592 bytes of rows and 72 of heads, where
its inline tables and its interests' table took about 688, and its set lends no reply stage. One
that listens at the preset reserves its 10 faces and one handshake, about 57,000 bytes of arena and
800 of registry heads on a 32-bit core, where before the pools it reserved about 87,000 and 21,000,
and states fewer where its memory is smaller. Estimates the speed matrix is to measure.
