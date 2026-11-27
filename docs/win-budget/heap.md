# Winning the heap: the shipped preset's open against zenoh-pico

Status: design, lane "heap" of the win budget (owner, 2026-11-26: "design all of it"). Nothing in
this file is built yet. It covers the heap a pico C ABI program holds through wz in the shipped
form (no_std, no heap after open, `configs/zenoh-pico_defconfig`); the std-and-heap form's own
heap is `docs/win-budget/std-heap.md`, and the read path that removes the round is
`docs/c-abi-architecture.md` section 8, on which several rows below depend.

## 1. What is measured

Massif, 2026-11-25, the parity arm W of `scripts/pico-compare.sh` (`libwz_capi_pico` built from
`configs/zenoh-pico_defconfig`), the same program sources as the pico arm:

| program | wz peak heap | of which session arena (`lend_session`) | process pools (`Reserved::built`) | other | zenoh-pico peak |
|---|---:|---:|---:|---:|---:|
| `z_sub -m peer -l tcp/...` | 381,080 B | 290,304 B | 78,160 B | 7,568 B `LinkSupervisor::new`, 4,096 B stdio | about 17 KB |
| `z_put -m peer -e tcp/...` | 262,800 B | 185,488 B | 78,160 B | 4,096 B stdio | about 15 KB |
| pubsub, both processes | 643,880 B | | | | about 32 KB |

wz holds about 20 times pico's heap. The 4,096 B stdio buffer is the program's own `puts` in both
arms. Every byte of wz's is reserved once, at the first object (pools) or at the open (arena), and
nothing is allocated after: the measured peak is the reservation. pico allocates as it is used
(section 2), so its peak is what the run touched.

The arena's rows, read from the open of a listening and a dialling session (the row report of
`object_slot::tests::the_arena_a_listening_session_opens_by_row_measured`, 2026-11-25, a build
with more capabilities than the preset: advanced, connectivity and the declaration watch rows are
in it and are 0 in the preset): listener 317,904 B (rows 265,056 B, the engine's own holds
52,848 B), dialer 197,408 B of rows. The per-row values in section 5 are that report's; the rows of
the preset's exact feature set are measurement cell M1.

## 2. Why pico is small, and why wz can be smaller with no heap after open

zenoh-pico allocates each thing when it first exists and frees it when it ends:

- the session: `vendor/zenoh-pico/src/api/api.c` @ `_z_session_t *s = (_z_session_t *)z_malloc(sizeof(_z_session_t));`
- one write and one read buffer per transport, of the batch size:
  `vendor/zenoh-pico/src/transport/unicast/transport.c` @ `ztu->_common._zbuf = _z_zbuf_make(zbuf_size);`
- a peer when it is accepted, and a stream peer's flow buffer only while a batch is partly read:
  `vendor/zenoh-pico/src/transport/peer.c` @ `ztu->_peers = _z_transport_peer_unicast_slist_push_empty(ztu->_peers);`,
  `vendor/zenoh-pico/src/transport/unicast/read.c` @ `static z_result_t _z_unicast_handle_remaining_data(_z_transport_unicast_t *ztu, _z_transport_peer_unicast_t *peer,`
- the defragmentation buffer only when a first fragment arrives, moved into the decoded message
  without a copy: `vendor/zenoh-pico/src/transport/unicast/rx.c` @ `*dbuf = _z_wbuf_make(Z_FRAG_MAX_SIZE, false);`
- a subscription when it is declared: `vendor/zenoh-pico/src/session/subscription.c` @ `_z_subscription_rc_t out = _z_subscription_rc_new_from_val(s);`

Its limits are build constants that bound nothing until used:
`vendor/zenoh-pico/include/zenoh-pico/config.h.in` @ `#define Z_LISTEN_MAX_CONNECTION_NB 10`,
`vendor/zenoh-pico/cmake/feature_config.cmake` @ `set(FRAG_MAX_SIZE 4096`. Upstream zenoh is the
same in kind, with its counts in the config (`commons/zenoh-config/src/defaults.rs` @ `max_sessions: 1_000,`)
and its batch buffers from a recycling pool sized when the link starts
(`io/zenoh-transport/src/unicast/universal/link.rs` @ `async fn rx_task_non_uring(`).

wz reserves at open for the worst case its build allows: ten faces, a hundred subscribers, a
hundred queryables, 306 key expressions, three 4 KB reassembly chains, a 64-record delivery lane.
pico never pays for a worst case. wz keeps its contract (nothing allocated after open, every refusal
named) and wins by these principles, each a separate kind of change:

- **P1, counts from the open's config (owner ruling, 2026-11-26).** Capacity is set the way DDS
  RESOURCE_LIMITS sets it. A build constant (the preset's limit) is the static ceiling a type can
  hold. The count an open reserves is what that session's config states, through the wz keys of
  section 3, each at most its ceiling. A config that states nothing gets the preset contract's
  small default. One reservation at open; a declaration past its count is refused with
  `_Z_ERR_SYSTEM_OUT_OF_MEMORY`, the code pico returns when its malloc fails. Process pools take
  their counts from the first open's config or from an explicit init config (section 6).
- **P2, smaller rows.** No pointer where a 16-bit index into a table of the same open will do; a key
  held as a handle into the key arena, never as text in the row; no inline buffer in a row whose
  buffer can be lent from a pool.
- **P3, share across kinds and faces (fewer rows).** One pool where per-owner tables each reserve
  for the worst case: pending declarations of every face in one pool, read buffers decoupled from
  the face count, every entity kind in one slab with a quota per kind.
- **P4, one thing reserved once (dedup).** The reassembly buffer is the payload block the sample
  is handed in (pico's `_z_wbuf_moved_as_zbuf` does the same, rx.c); the reply legs' places are
  payload blocks; the place the ABI hands a program is the session's table row; a declared key
  expression object lies in its session's arena, not also in a process pool.
- **P5, a row the open will not use is no row.** A kind the build compiles out has none (already
  so); a kind the config gives 0 has none; the round's rows go with the round (section 8 of the
  architecture document).
- **P6, one reservation.** Everything the open makes is in the plan: the 7,568 B
  `LinkSupervisor::new` allocation of the measured run is a second allocation and goes into the
  plan or away with the round.
- **P7, resident only when written.** Rows are laid out as untouched memory taken by a high-water
  mark (the process pools' `Pool::fresh` already do it), so on a host with paging the resident set
  follows what the run touched, not what was reserved (section 7).

## 3. The configuration keys (P1)

**Form.** A pico program configures through `zp_config_insert(config, key, text)`. wz adds numbered
keys in a range of its own past pico's (pico's end at `Z_CONFIG_LISTEN_EXIT_ON_FAILURE_KEY 0x5A`);
the value is a decimal count, parsed once at the insert into a typed table of counts in the config
(`OpenCounts`, one `u32` per countable limit, indexed by the limit's id), never stored as text, so
the config's text bytes (`CONFIG_TEXT_BYTES`, 256 at the preset) and entry rows
(`CONFIG_ENTRIES`, 8) are not spent on them. A count past its ceiling, or text that is not a count,
is refused at the insert with `_Z_ERR_CONFIG_FAILED_INSERT` and the config keeps what it had. Where
the config document capability is on, `zext/limits` sets the same table (one table, two writers).
A typed door (`wz_config_set_count(config, id, value)`) sets it without text for a program written
for wz. The open reads the table, fills each count the config did not state with the preset's
default, and lays the plan out from it (`ArenaPlan::count` already takes a config; it reads
`OpenCounts` instead of the build values).

**Keys, ceilings and defaults** (defaults are owner decision D2; the basis proposed is the count the
most demanding of pico's own examples holds at once, the method `deploy/Kconfig.limits` already uses
for `WZ_LIMITS_ZENOH_PICO`; the counts are measurement cell M2):

| key (limit id) | ceiling (build) | default (proposed) | rows it sizes |
|---|---:|---:|---|
| `MAX_FACES` (accepted) | 10 (pico `Z_LISTEN_MAX_CONNECTION_NB`) | 1 | face rows, link rows |
| `MAX_ACCEPT_PENDING` | 1 | 1 | accept row |
| `RX_POOL_BUFFERS` | faces + 1 | 1 | read buffers |
| `TX_POOL_SLOTS` | 2 | 1 | write buffers |
| `MAX_SUBSCRIPTIONS` | 100 | 2 | entity slab quota |
| `MAX_PUBLISHERS` | 100 | 2 | entity slab quota |
| `MAX_QUERYABLES` | 100 | 1 | entity slab quota |
| `MAX_QUERIERS`, `MAX_LOCAL_TOKENS`, `MAX_LIVELINESS_SUBSCRIPTIONS`, `MAX_MATCHING_LISTENERS` | 2 | 1 each | entity slab quota |
| `MAX_PENDING_QUERIES`, `MAX_PENDING_LIVELINESS_GETS` | 2, 1 | 1, 1 | get rows |
| `MAX_PENDING_REPLIES` | 2 | 1 | held reply rows |
| `MAX_DECLARED_KEYEXPRS` | 306 | 4 | keyexpr rows |
| `KEY_ARENA_BYTES` | 4,320 | 256 | key arena |
| `MAX_PENDING_DECLARES` | 101 | 4 | shared pending-declare pool |
| `MAX_REMOTE_DECLS`, `MAX_PEER_KEYEXPR_ALIASES`, `MAX_INBOUND_SUB_INTERESTS` | 16, 16, 16 | 4, 4, 2 | peer pools |
| `MAX_DECL_OBSERVERS`, `MAX_DECL_WATCHES` | 8, 4 | 0 | watcher rows |
| `REASSEMBLY_CHAINS` | 3 | 1 (D5) | large payload blocks taken for reassembly |
| `HELD_SAMPLES`, `HELD_REPLIES`, `HELD_QUERIES`, `HELD_ENCODINGS`, `HELD_HELLOS` | 5, 3, 3, 2, 1 | 1 each | process pools |
| `HELD_SMALL/MEDIUM/LARGE_PAYLOAD_BLOCKS` | 128, 8, 4 | 2, 0, 1 | process pools |
| `HELD_CONFIGS` | 2 | 1 | config pool (before any open) |

A default of 0 is safe only where no pico example reaches the kind without stating it; the watch
rows are wz doors outside pico's API. The `TableRows` the session's tables take
(`wz-session-core/src/session_tables.rs`) and the `Counts` of the process pools
(`crates/wz-capi-pico/src/process_pool.rs`) are already per limit; what changes is where their values
come from.

## 4. Targets

pico's z_sub (about 17 KB) and z_put (about 15 KB) each include the same 4,096 B stdio buffer, so
wz's own heap must be at most about 12.9 KB in z_sub and 10.9 KB in z_put (measurement cell M3
reads pico's own split by site). Write B for the batch bytes (`PICO_UNICAST_BATCH_BYTES`, 2,048,
pico's `BATCH_UNICAST_SIZE`), F for the reassembly bytes (`PICO_FRAG_MAX_BYTES`, 4,096) and h for a
payload block's head. At the defaults of section 3:

    z_sub own = rx(1 x B) + tx(1 x B) + large block(F + h) + S_sub
    z_put own = rx(1 x B) + tx(1 x B) + large block(F + h) + S_put

where S is every other row. With B = 2,048 the three buffers take 8.2 KB, leaving S_sub <= 4.7 KB
and S_put <= 2.7 KB. Section 5's row targets sum to S of about 5.3 KB (z_sub) and 5.2 KB (z_put):
z_sub misses by about 0.6 KB and z_put by about 2.5 KB. The difference is the one term pico does
not pay in these runs: the 4 KB reassembly buffer it allocates only when a fragment arrives. Two
levers close it, both owner decisions:

- **D4**: the preset's default batch is 1,024 (wz states it in its InitSyn; the batch both sides
  use is the smaller one, so a pico peer follows). rx + tx drop by 2,048: z_sub 11.4 KB, z_put
  11.4 KB. Larger messages take more batches, a cost the Ir lane (`docs/win-budget/ir-receive.md`)
  must weigh.
- **D5**: `REASSEMBLY_CHAINS` defaults to 0, a fragmented message then refused and counted as pico
  refuses one whose buffer it cannot allocate (rx.c, `_Z_ERR_SYSTEM_OUT_OF_MEMORY`). z_put drops by
  4,112 B to about 9.3 KB at B = 2,048. A pico program that receives messages longer than a batch
  without stating the key then behaves as pico on a heap that cannot hold 4 KB.

Recommended: D5 = 1 (reception parity by default) with D4 = 1,024, and S held to section 5's
targets; then z_sub about 11.4 KB, z_put about 11.4 KB, pubsub about 22.8 KB + 8 KB stdio = 30.8
KB against pico's 32 KB. z_sub then wins alone; z_put misses pico by about 0.5 KB and needs S_put
cut by that much more (the entity and get defaults of a program that only puts: cell M2).

## 5. The rows of the session arena

Columns: current (listener / dialer, bytes; formula), pico (what it holds for the same thing),
target formula and target bytes (z_sub / z_put at section 3's defaults), the structure, the files,
and the lane (section 9). "e" marks an estimate of a row size the change has not built yet
(measurement cell M4).

### 5.1 Transport

| row | current | pico | target formula | target | structure | files | lane |
|---|---|---|---|---|---|---|---|
| link receive buffers | 4,096 / 2,048; `RX_POOL_BUFFERS` x B | one zbuf per transport + a flow buffer per stream peer while a batch is partial | `RX_POOL_BUFFERS`(config) x B | 2,048 / 2,048 (1,024 with D4) | the read pool is not per face: a face's read waits for readiness holding no buffer, takes one to read, gives it back when the batch is decoded; a stream face keeps one only while a batch is partly read, as pico's flow buffer | `wz-capi-coop/src/arena.rs` (`TransportRows`), `wz-runtime-coop` link read | H3 |
| link transmit slots | 4,096 / 2,048; `TX_POOL_SLOTS` x B | one wbuf per transport, under its tx lock | `TX_POOL_SLOTS`(config) x B | 2,048 / 2,048 (1,024 with D4) | one slot per session written under the send hold of section 8; a second only where the config asks for two concurrent writers | same | H3 |
| link places, flags | 11 / 1 + 4 | none | faces + accept | 2 / 1 | unchanged | arena.rs | H1 |
| endpoint texts | 80 | the config's strings | stated endpoints x text | 80 / 80 | unchanged | arena.rs | none |
| udp port rows | 0 (tcp alone) | | | 0 | unchanged | | none |

### 5.2 Delivery lane (section 8 removes it)

| row | current | pico | target | structure | files | lane |
|---|---|---|---|---|---|---|
| delivery records | 8,704; 64 x 136 | none: the callback is called in the read | 0 | the read hands each record to its callback where it is decoded (section 8.2) | `wz-capi-coop/src/round.rs`, `engine.rs` | section 8 step 5 |
| delivery callbacks | 1,024; 64 x 16 | none | 0 | same | same | section 8 |
| delivery keys | 512; `MAX_KEYEXPR_BYTES` x 2 | none | 0 | the key is read where the batch holds it | same | section 8 |
| delivery round | 344 | none | 0 | same | same | section 8 |

### 5.3 Reassembly, query legs and payload (dedup, P4)

| row | current | pico | target formula | target | structure | files | lane |
|---|---|---|---|---|---|---|---|
| reassembly buffers | 12,288; 3 x F | one F buffer per peer and reliability, made at the first fragment, moved into the message | 0 in the arena; `REASSEMBLY_CHAINS` large blocks of the payload pool | 0 (the block is counted in section 6) | a first fragment takes a large payload block; the chain writes into it; the complete message is decoded over it and the sample's payload is that block, handed on with no copy; a chain found with no free block drops the message and counts it | `wz-session-core` reassembly, `wz-capi-pico/src/bytes.rs`, `process_pool.rs` (`take_payload`), `wz-capi-coop/src/arena.rs` | H5 |
| reassembly flags | 3 | | 0 | same | same | H5 |
| handed leg places | 4,096; 2 x `HANDED_LEG_BYTES` | a reply's payload malloc'd when it arrives | 0 in the arena | a reply's payload lies in a payload block taken when it is decoded; the leg keeps the block's handle | `wz-capi-coop/src/engine/query.rs`, `bytes.rs` | H5 |
| handed legs | 544 | | legs x 16 e | 32 | a leg row holds a block handle and its state | same | H5 |
| held replies | 2,944; 2 x 1,472 | a reply list per query, malloc'd | `MAX_PENDING_REPLIES` x 64 e | 64 / 64 | a held reply is a row of its key handle, its block handle and its timestamp, not a copied reply | `wz-session-core/src/reply_hold.rs` | H5 |

### 5.4 Faces and links (after section 8)

| row | current | pico | target formula | target | structure | files | lane |
|---|---|---|---|---|---|---|---|
| face tables | 6,160 / 560; (faces + 1) x 560 | one `_z_transport_peer_unicast_t` per accepted peer | faces x 384 e | 384 / 384 | the face row keeps the peer's zid, its sn pair, its lease and last-heard time, its link handle and its pool indices (u16), and nothing lent to it inline | `wz-capi-coop/src/engine/direct.rs` (`DirectFace`), `arena.rs` | H3 |
| held faces, room places | 352 / 32; (faces + 1) x 32 | | faces x 32 | 32 / 32 | unchanged | arena.rs | H3 |
| link cells | 6,688 (11 x 608) | the link struct | faces x 96 e | 96 / 96 | with no link task (section 8.2) a link is its socket, its address and its state; the task cell goes | `wz-runtime-coop` link cells, `engine.rs` (`link_task_bytes`) | H3 after section 8 |
| link halves | 21,120 (11 x 1,920) | none | 0 | the halves held a task's read and write sides; the read slot and send place of section 8.3 hold them in the face row | same | H3 after section 8 |
| link gates, actions | 3,168 (11 x 288) | none | faces x 32 e | 32 / 32 | one gate word per face; the actions are the timers' (5.7) | same | H3 |
| accept (admission) | 72 | | 72 | 72 / 0 | unchanged | | none |

### 5.5 Peer-written tables (P3)

| row | current | pico | target formula | target | structure | files | lane |
|---|---|---|---|---|---|---|---|
| peer tables | 51,520 / 5,152; faces x (`MAX_PENDING_DECLARES` + `MAX_PENDING_FINALS`) rows | the declarations a peer sends, malloc'd per declaration | `MAX_PENDING_DECLARES`(config) x 32 e, one pool for every face | 128 / 128 | one pool of pending declarations, each row naming its face (u8) and its declaration id; a face holds a directory index, not a table | `wz-session-core` peer tables, `arena.rs` (`FacePeers`) | H4 |
| peer alias pool | 1,040 / 384 | per alias, malloc'd | aliases x 32 e | 128 / 128 | already shared; rows at the config's count | same | H1 |
| peer declaration pools | 4,944 / 1,792 | per declaration | remote decls x 64 e | 256 / 256 | already shared; a remote declaration holds a key handle, not text | same | H1, H4 |
| peer interest pool | 784 / 640 | per interest | interests x 48 e | 96 / 96 | already shared | same | H1 |
| owed tokens | 1,280; 32 x 40 | per token | remote decls of tokens x 16 e | 64 / 64 | a bit per remote declaration row instead of a row of its own | same | H4 |
| peer row directory | 112 | | 112 | 112 / 112 | unchanged | | none |

### 5.6 Entities and keys (P2, P3, P4)

| row | current | pico | target formula | target | structure | files | lane |
|---|---|---|---|---|---|---|---|
| session tables | 49,744 (36,832 at the preset); separate slot maps for 306 keyexprs, 100 subscribers, 100 queryables, write filters for 100 publishers, ... | one rc'd struct per declared entity in a list | sum of the config's entity counts x 64 e, one slab | 640 / 640 (10 rows) | one entity slab: a row is a tagged union of the kinds, its kind's quota counted at declare; the row holds the key handle (u16), the id (u32), the closure (call, context, drop) and the kind's state; the matching and write-filter rows are rows of the same slab | `wz-session-core/src/session_tables.rs` (`TableRows`, `SessionTables::arena_bytes`), `arena.rs` | H2 |
| publisher, subscriber, queryable places | 75,200 (100 x 240-264 each) | the owned handle's pointee | 0 | the place a program's handle points at is the slab row (P4): an owned handle is the row index and a generation, so no second record of the entity is made | `wz-capi-pico/src/pubsub.rs`, `query.rs`, `liveliness.rs`, `wz-capi-coop/src/object_slot`, `arena.rs` (`PlaceRows`) | H2 |
| token, liveliness, querier, get, matching places | 2,360 | same | 0 | same | same | H2 |
| lodging places | 8,232 (3 x 2,744) | none | 0 e | what a lodging holds moves into the slab row or the face row; cell M5 names it | `wz-capi-coop/src/lodging.rs` | H2 |
| keyexpr rows (in session tables) | 306 rows | one malloc'd string per declared key | `MAX_DECLARED_KEYEXPRS`(config) x 32 e | 128 / 128 | a row is a key handle and the wire id | session_tables.rs | H2 |
| key arena | 4,384 | each key's exact bytes | `KEY_ARENA_BYTES`(config) + 64 | 320 / 320 | unchanged form, config-sized | arena.rs, `region.rs` | H1 |
| pending gets, legs | 6,720 / 672 | a query struct per get | gets x (96 + 3 x 32) e | 192 / 192 | the legs are rows of the get, not tables per face | `wz-session-core/src/slot_observer.rs`, engine/query.rs | H5 |
| declaration watchers | 1,152 | none (a wz door) | 0 by default | 0 / 0 | config-counted | arena.rs | H1 |
| held finals, refused finals | 112 | | finals x 56 | 56 / 56 | unchanged | | none |
| advanced, connectivity places, cache ring | 11,021 in the test build | not in pico's build | 0 in the preset | 0 | already compiled out by the preset's caps | | none |

### 5.7 Session, engine, runtime

| row | current | pico | target | structure | files | lane |
|---|---|---|---|---|---|---|
| engine state | 4,128 | the `_z_session_t` | 1,024 e | what is per face moves to the face row; what is per kind to the slab; cell M6 lists its fields | `wz-capi-coop/src/engine.rs` | H7 |
| runtime state | 6,080 | the lease and read tasks' stacks (not heap) | `RUNTIME_TIMERS` x 16 + 64 e = 320 | with no link task (section 8.2) the executor keeps timers alone: one table of deadlines | `wz-runtime-coop` (`CoopRuntime::placed_layout`), engine.rs (`RuntimeTables`) | H7 after section 8 |
| session handle | 568 | the owned session's pointee | 128 e | the handle's place holds the engine row and its generation | `wz-capi-pico/src/session.rs` | H7 |
| registry, router lend, arena keep, link rooms | 104 | | 104 | unchanged | | none |
| `LinkSupervisor::new` (outside the arena) | 7,568 | | 0 | gone with the link tasks; were any of it to stay it is a row of the plan (P6) | `wz-runtime-coop/src/faces.rs` | section 8, H3 |

### 5.8 Totals of the arena

| | current | target (B = 2,048) | target (D4, B = 1,024) |
|---|---:|---:|---:|
| z_sub (listener, one accepted face) | 290,304 (massif) | 8.6 KB e | 6.5 KB e |
| z_put (dialer) | 185,488 (massif) | 8.5 KB e | 6.5 KB e |

## 6. The process pools (78,160 B)

`BUILT_PLAN` (`crates/wz-capi-pico/src/process_pool.rs`) reserves at the first object a program
makes, from the build's counts. In the cooperative engine its pools are the payload blocks, the
held values, the configs, the hellos, the declared key expressions and the encodings (the entity
pools are the arena's there).

| pool | current formula | current bytes | pico | target formula | target | structure | lane |
|---|---|---:|---|---|---:|---|---|
| small payload blocks | 128 x 64 | 8,192 | a malloc per payload | config count x 64 | 128 | config-counted | H6 |
| medium payload blocks | 8 x 1,040 | 8,320 | same | config count x 1,040 | 0 | a payload above a small block takes a large one; medium only where the config asks | H6 |
| large payload blocks | 4 x (max(F, B, keys) + h) | 16,448 e | the defragmentation buffer and long payloads | (`REASSEMBLY_CHAINS` + held large) x (F + h) | 4,112 | shared with reassembly (5.3) | H5, H6 |
| declared key expressions | 306 x `HELD_SESSIONS`(2) x slot | about 39,000 e | a malloc'd string per key | 0 here | 0 | the object lies in its session's slab (5.6); a key expression a program declares belongs to one session | H2 |
| samples, replies, queries, encodings | 5, 3, 3, 2 x slot | about 4,000 e | a malloc each when a program clones | config count x slot | about 300 e | config-counted; slot sizes cut as P2 | H6 |
| configs | 2 x `ConfigState` | about 1,500 e | the config's list, malloc'd | 1 x `ConfigState` | about 400 e | reserved by itself at the first config (below) | H6 |
| hellos | 1 x slot | small | per hello | reserved at the scout from its config | 0 until a scout | | H6 |
| total | | 78,160 | | | about 4.9 KB e | | |

**Staged reservation (D6).** A config is a program's first object and comes before any open, so
the process pools are reserved in groups by the door that first needs each, from the config that
door is handed: the config pool at `z_config_default` (the preset's count, 1); the hello pool at
`z_scout`; everything else at the first `z_open`, or earlier through an explicit init door
(`wz_init_pools(config)`). A later open whose config asks for more than the pools hold is refused at
open, by name. Nothing is reserved after the first open, so the no-heap-after-open contract holds for
the process as for each session. The split of the 78,160 B by pool is measurement cell M7
(`process_pool::report` per class).

## 7. Resident memory

On a host with paging, resident memory follows the bytes written, not the bytes reserved: an
allocation of at least the C library's mmap threshold (128 KiB by default in glibc) is fresh
zero pages, and the fresh top of the brk heap is too. Today's 290 KB arena is mmap'd and its
untouched rows are not resident; the process pools already take untouched slots by a high-water
mark (`Pool::fresh`). Once the arena is at section 5's targets it falls under the threshold and
comes from the brk heap, where a reused chunk is zeroed by `calloc` and so written. Rules:

- every row is `ZeroEmpty` and laid out by a high-water mark: the open writes a row's fields only
  when the row is first taken, never a pass over all rows;
- on a host, the session's arena is fresh pages of the system, never a chunk of the C allocator.
  Read 2026-11-26 (the main session): once the heap lanes brought the arena under the mmap
  threshold, `calloc` served each later open from the chunk the last close freed and zeroed all of
  it with `memset`, which raised the open and close from 0.82 of pico's instructions to 1.37 and
  wrote every page of the arena. The lane rss-zero (`7a6292658`) maps the arena's block itself
  (`wz_host_sync::pages::reserve` over `mmap` and `VirtualAlloc`, `wz_capi_pico::os::HostPages`),
  tells the arena its memory is zero (`ArenaMemory::reserves_zeroed`, `Arena::over_zeroed`), so
  an empty row is written by no one, and keeps the allocator's block only where the build has no page mapping (an image keeps its
  heap, and its static region is `.bss`, already zero).
  Its open Ir and resident pages: measure, harness f5f8ce646 (cell M8).

Text pages are resident when executed, so resident memory also follows the text lane
(`docs/win-budget/text.md`). On a microcontroller with no paging, resident is reserved: heap and
static are what count there, and section 5's targets are the bound. Cell M8 reads both arms'
`/proc/<pid>/smaps_rollup` (anonymous and file resident) at the same point of each run.

## 8. Refusals and tests

Each lane lands with tests that assert, for the shipped preset and for a build without the kind's
feature:

- a config that states no count opens with exactly the defaults' plan (bytes equal to the plan's
  sum, read by `ArenaPlan::reserved`);
- a count stated above its ceiling is refused at the insert by `_Z_ERR_CONFIG_FAILED_INSERT`, and
  the config keeps its earlier value;
- a declaration past its count returns `_Z_ERR_SYSTEM_OUT_OF_MEMORY`, takes nothing and leaves the
  next declaration of another kind its quota;
- a fragmented message completed in a large block is handed to the callback over that block (the
  payload's address lies in the pool), and a second chain with no free block drops its message and
  counts it;
- no allocation after the open (the existing `crates/wz-capi-pico/tests/no_heap_after_open.rs`
  family extended to the config-counted plan);
- the massif peaks of the parity arm at most pico's, judged by the pico-compare heap mode.

## 9. Lanes, boundaries and order

| lane | what | files | depends on |
|---|---|---|---|
| H1 | the config's count table, the keys, the defaults in the preset contract; the plan read from the table | `wz-session-core/src/limits.rs`, `wz-capi-pico/src/config.rs`, `config_policy.rs`, `deploy/Kconfig.limits`, `deploy/wz-config.toml` (`configs/zenoh-pico_defconfig` regenerated), `wz-capi-coop/src/arena.rs` | D2, D3 |
| H2 | the entity slab; the handle is the row; key expression objects in the slab; lodgings gone | `session_tables.rs`, `wz-capi-coop/src/object_slot`, `lodging.rs`, `wz-capi-pico/src/pubsub.rs`, `query.rs`, `liveliness.rs`, `keyexpr.rs`, `process_pool.rs` | H1 |
| H3 | the face row and the link row after the link tasks go; the read pool decoupled from faces | `engine/direct.rs`, `wz-runtime-coop` (link cells, faces), `arena.rs` | section 8 steps 2 to 4 |
| H4 | one pending-declaration pool for every face; owed tokens as bits | `wz-session-core` peer tables, `arena.rs` | H1 |
| H5 | reassembly into the payload block; reply legs and held replies over payload blocks | `wz-session-core` reassembly, `reply_hold.rs`, `engine/query.rs`, `wz-capi-pico/src/bytes.rs`, `process_pool.rs` | H1 (counts), D5 |
| H6 | staged process pools, config-counted | `process_pool.rs`, `config.rs`, `session.rs` | H1, D6 |
| H7 | engine, runtime and handle state cut | `engine.rs`, `wz-runtime-coop`, `session.rs` | section 8 step 5 |
| H8 | the measuring: the row report of the preset's own feature set, the heap and resident readings of both arms | `wz-capi-coop/src/tests/arena.rs`, `scripts/pico-compare.sh` | none |

Order: H8 and H1 first (H1 alone moves the arena from 290 KB to the defaults' sum of today's row
sizes, about 60 KB e, and the pools from 78 KB to about 30 KB e); then H2, H4, H5, H6 in parallel
(disjoint files but `arena.rs` and `process_pool.rs`, which H2/H5/H6 touch in separate functions
and merge in that order); H3 and H7 after section 8's steps. Section 8 removes 10,584 B of
delivery rows and the 7,568 B `LinkSupervisor` allocation by itself.

## 10. Owner decisions

- **D1** (decided 2026-11-26): capacity in the form of DDS RESOURCE_LIMITS, section 2 P1. Recorded
  here as the basis of every row.
- **D2**: the default counts of section 3, proposed as the most one of pico's own examples holds at
  once (cell M2 counts them). The trade: a smaller default wins more heap; a pico program that holds
  more than its example without stating the key is refused where pico would have allocated.
- **D3**: the numbered key range for the wz counts in `zp_config_insert` and the typed door's name.
- **D4**: the preset's default batch, 2,048 (pico's) or 1,024. 1,024 makes z_sub win and brings
  z_put within about 0.5 KB of pico at the reassembly default of 1 (section 4); it costs more
  batches for long messages.
- **D5**: `REASSEMBLY_CHAINS` default 1 (recommended: reception parity) or 0.
- **D6**: process pools staged by door and fixed after the first open (a later open that asks for
  more is refused), or a later open may add a pool segment of its own that lives as long as its
  session (then a held sample of that session cannot outlive it).
- **D7** (decided 2026-11-26 under the owner's delegation): no crate is a size boundary
  (`text.md` O1). The code that sizes and lays out the arena from the configuration's counts is one
  non-generic body over `ArenaLayout`'s numbers (`text.md` P5, S3), which is also what P6's counts
  at open need: no row type carries a capacity, and no layout function a type parameter.
- **D8** (decided 2026-11-26 under the owner's delegation): a get's ResponseFinal waits in its
  face's `TxBatch` until the read stage ends (`ir-send-query.md` D6). It reserves no row: the
  batch is the link transmit slot of section 5.1, and between writes it holds no lock, so another
  writer (a put from the application's thread) appends to it or flushes it under the same short
  hold of the send place; no second slot is reserved for the wait.

## 11. Measurement cells

- **M1**: the row report of an open at the preset's own feature set (the W arm's features), the
  listener's and the dialer's, so the "current" column reads the shipped build's rows.
- **M2**: the counts each of pico's examples holds at once (subscribers, publishers, queryables,
  gets, tokens, keys, faces), the basis of D2.
- **M3**: pico's massif peak by allocation site for z_sub and z_put: its own bytes apart from the
  4,096 B stdio buffer.
- **M4**: each "e" row size of section 5 after its lane lands (`size_of` in the row report).
- **M5**: what a lodging place holds and who reads it.
- **M6**: the fields of the engine state and the runtime state by size.
- **M7**: the process pools' 78,160 B by pool.
- **M8**: resident memory (anonymous and file) of both arms of z_sub and z_put at the same point,
  before and after H1, and after rss-zero (the arena in fresh pages); with it the open and close's
  instructions on the window harness: measure, harness f5f8ce646.

## 12. Rejected alternatives

- **Grow on demand after open** (pico's way): breaks the contract that a running program allocates
  nothing; a refusal could then come from the allocator at any call instead of at a stated count.
- **Static storage in place of the heap**: moves the bytes to `.bss`, where they are still
  reserved and resident when written; it changes the meter, not the cost.
- **Keeping the build's values and lowering them by a Kconfig profile per program**: the count is
  a property of a session's use, which one library serves many of; a program that needs more could
  not have it without a rebuild.
- **A read buffer per face**: ten faces would hold ten batch buffers while waiting on idle sockets;
  pico holds a stream peer's buffer only while a batch is partial, and so does H3.
- **Reassembly from the read buffers kept in place** (upstream's `ZSlice` chain,
  `io/zenoh-transport/src/common/defragmentation.rs` @ `self.buffer.push_zslice(zslice);`): a
  4 KB message over 2 KB batches would hold three read buffers to the end and need a fourth to keep
  reading, more than one F block.

## 13. 보강 (reinforcement): the publisher program's last kilobytes

Status: design, 2026-11-26, the reinforcement the review of section 9 of
`docs/c-abi-architecture.md` asked for. Section 4 leaves the publisher program (z_put, the dialer)
about 0.5 KB over zenoh-pico's own bytes at D4 = 1,024 and D5 = 1. This section takes every row
the dialer still holds, one by one, and fixes a structure for each that can shrink, so that wz's
own bytes in z_put are at most pico's own (about 10.9 KB, cell M3) with at least 1 KB to spare.
Nothing here lowers a default count of section 3 (D2 stands): every lever is a smaller row, a row
that is not needed, or a row shared with one that cannot be held at the same time.

### 13.1 The dialer's rows at the defaults, before and after

Columns: the target of sections 5 and 6 at D4 (B = 1,024) and D5 = 1, the reinforced target, and
the lever of 13.2 that moves it. "e" marks an estimate (cell M4 reads it after the lane lands).

| row | section 5/6 target | reinforced | lever |
|---|---:|---:|---|
| link receive buffer (`RX_POOL_BUFFERS` x B) | 1,024 | 1,024 | none: a dialer's one face reads into it all the time |
| link transmit slot (`TX_POOL_SLOTS` x B) | 1,024 | 320 e | R1 |
| face table, held face, link cell, link gate, link places | 384 + 32 + 96 + 32 + 5 = 549 | 400 e | R3 |
| endpoint texts | 80 | 0 | R8 |
| handed legs, held replies | 32 + 64 | 96 | none |
| peer plane: pending declarations, aliases, remote declarations, interests | 128 + 128 + 256 + 96 | 608 | none |
| owed tokens | 64 | 0 | R4 |
| peer row directory | 112 | 16 | R4 |
| entity slab (10 rows) | 640 | 480 e | R5 |
| keyexpr rows, key arena | 128 + 320 | 448 | none |
| pending gets and legs | 192 | 128 e | R6 |
| held and refused finals | 56 | 56 | none |
| engine state | 1,024 e | 512 e | R7 |
| runtime state | 320 e | 128 e | R7 |
| session handle | 128 e | 32 e | R7 |
| registry, router lend, arena keep, link rooms | 104 | 104 | none |
| **arena** | **6,469** | **4,352 e** | |
| small payload blocks (2 x 64) | 128 | 128 | none |
| large payload block (one, F + h) | 4,112 | 4,112 | R2 (one block, never two) |
| samples, replies, queries, encodings | 300 e | 300 e | none |
| configs (one `ConfigState`) | 400 e | 330 e | R8 |
| hellos | 0 | 0 | none (reserved at a scout) |
| **process pools** | **4,940** | **4,870 e** | |
| **z_put, wz's own** | **11,409** | **9,222 e** | |

Against pico's own of about 10.9 KB the reinforced dialer is about 1.7 KB under; the 1 KB margin
holds while cell M3 reads pico's own at 10.2 KB or more. The listener (z_sub) takes R1 to R8 too
and falls from about 11.4 KB to about 9.3 KB e against pico's 12.9 KB.

### 13.2 The levers

**R1. A put is gathered, not copied into a transmit slot.** The stream link already sends a length
and its batch in one call (`crates/wz-runtime-posix/src/stream.rs @ a length and its batch go out in one`,
and the Windows link one `WSASend`, `crates/wz-runtime-posix/src/windows/stream.rs @ ws::WSASend(`).
The seam grows from two pieces to a gather list of at most four (`LinkSocket::write_gather(&[IoPiece])`,
one `sendmsg` with an `iovec` array, one `WSASend` with a `WSABUF` array: no new import on either
host, which keeps the nostd Windows DLL's import table as it is). A put under its face's send
place writes, on the caller's stack, a head of at most 16 bytes (the stream's length, the Frame
header, the SN, the Push header when the plan does not hold it), and hands the link four pieces:
that head, the plan's Put head (the bytes the publisher's declaration wrote into its slab row,
ir-send-query S1), the payload length and the payload block itself. Nothing of the message is
copied into the arena. What still needs a slot:

- **Messages the session writes itself** (KeepAlive, Declare, Interest, DeclareFinal, Close,
  InitSyn, OpenSyn) go into one **control slot** per session, sized at open to the largest of
  them: a Declare with a key of `MAX_KEYEXPR_BYTES` (256 at the preset) and its headers, 320 B.
  OpenSyn's cookie is not copied into it: the handshake holds the read batch that carries the
  InitAck until the OpenSyn is sent, and the cookie is a gather piece over that batch.
- **A batching window** (`zp_batch_start` to `zp_batch_flush`) takes the session's large block
  (R2) as its batch while the window is open and the block is free; when the block is held (a
  chain in progress, a program's large payload) the window writes each message at once, as a
  build without batching does. No message is refused for want of a batch: batching changes when
  bytes leave, never whether they do, which is what pico's flag means too
  (`vendor/zenoh-pico/src/transport/common/tx.c` @ `if (ztc->_batch_state == _Z_BATCHING_ACTIVE) {`).
- **A message larger than a batch** is sent as fragments, each a gather of its fragment head and a
  slice of the payload block; nothing is staged. pico allocates an expandable buffer of the whole
  message for it (`vendor/zenoh-pico/src/transport/common/tx.c` @ `_z_wbuf_t frag_buff = _z_wbuf_make(_Z_FRAG_BUFF_BASE_SIZE, true);`).
- **A link kind with no gather write** (a serial or raw link whose driver writes one buffer)
  states `GATHERS = false` and its open reserves a transmit slot of B for it, counted in the plan
  by the link kind, so the capacity follows the link and a build of the preset's links pays none.

Ownership: the head is the put's stack; the plan's head is the slab row's, read under the face's
send place (ir-send-query S1, which guarantees the row is not rewritten while the place is held);
the payload block is the caller's until the gather returns (a stream write returns when the kernel
has taken every byte, `stream.rs` as cited). Ir: the put loses the slot's acquire and release and
the copy of head and payload (ir-send-query 9.4). Files: `wz-runtime-coop/src/stream_link.rs`
(`tx_slot_*` become `write_gather` and the control slot), `link_storage.rs` (`TxStore` keeps the
control slot and the link-kind slot), `wz-runtime-posix/src/stream.rs`, `net.rs`,
`windows/stream.rs`, `wz-session-core/src/session_actions.rs` (the writers of S-WRITE produce
pieces). Lane: S-WRITE of ir-send-query carries it; H3 takes the slot rows out of the plan.

**R2. One large block, shared, never reserved twice.** Section 6's formula
`(REASSEMBLY_CHAINS + held large) x (F + h)` with the defaults of section 3 (1 and 1) gives two
blocks, 8,224 B, where the targets of 5.3 and 6 count one. The reinforced rule: the large class
of the payload pool holds `LARGE_BLOCKS` blocks, by default `max(REASSEMBLY_CHAINS, HELD_LARGE)`
= 1, reserved with the process pools at the first open (D6) and taken by whichever needs it
first: a chain at its first fragment (so the reassembly buffer is never taken before a fragment
arrives, as pico's is not), a program's payload too long for a small block, or a batching window
(R1). The reassembled message is decoded over the block and the sample's payload is that block,
handed on with no copy (P4). Refusals: a first fragment that finds no free block drops its chain
and counts it (`ChainDropped::NoBlock`), the same outcome as pico's failed allocation of the
defragmentation buffer; a program payload that finds none is `_Z_ERR_SYSTEM_OUT_OF_MEMORY`; a
batching window that finds none writes each message at once. A program that must hold a
fragmented sample and receive the next one at the same time states `LARGE_BLOCKS` 2. Files:
`wz-capi-pico/src/process_pool.rs` (the large class's count and its taker), `wz-session-core`
reassembly (`take_payload` at the first fragment). Lane H5.

**R3. One face row.** For a dialer the face table row (384 e), the held face (32), the link cell
(96 e), the link gate (32 e) and the link places (5) describe one peer reached over one socket.
After section 8 they are one record: the socket and its address, the link state and the gate word,
the peer's zid, the SN pair, the lease and last-heard time, and the pool indices (u16). 400 B e,
of which the zid and SN pair are 32 and the socket and address 32. Files: `engine/direct.rs`
(`DirectFace`), `wz-runtime-coop` link cells, `arena.rs`. Lane H3.

**R4. The peer plane's bookkeeping in the rows it describes.** A token owed to a peer is a bit of
the remote declaration row it is owed for (one bit in the row's flags byte), not a table of its
own (64 to 0). The row directory, which today has a fixed width, is `faces x 16` (one face: 16).
Files: `wz-session-core` peer tables, `arena.rs` (`FacePeers`). Lane H4.

**R5. A 48-byte entity row.** The slab row of section 5.6 holds: the kind (u8), flags (u8), the
key handle (u16), the entity id (u32), the closure's call, context and drop (24 on a 64-bit host,
12 on a 32-bit MCU), and 16 bytes of the kind's own state (a publisher's plan reference and epoch,
a subscriber's matching word, a querier's target and timeout). A kind whose state is larger keeps
it in a row of its own kind table addressed from those 16 bytes; at the preset none is. 10 rows x
48 = 480 e. Files: `session_tables.rs`. Lane H2.

**R6. A get's legs are its faces'.** Section 5.6 sizes a get at `96 + 3 x 32`. A get has one leg
per face it is sent on; the dialer has one face, so `gets x (96 + faces x 32)` = 128 e. Files:
`slot_observer.rs`, `engine/query.rs`. Lane H5.

**R7. Engine, runtime and handle state: each field where it belongs.** `CoopEngine`
(`crates/wz-capi-coop/src/engine.rs @ pub struct CoopEngine`) holds, besides its core and its faces,
`wait_before_drop_us` (a configured value: read from the plan where it is used), `arena_bytes`
(the plan's sum: read from the plan), `handle_place` and `lodgings` (H2 makes the handle the row
and removes the lodgings), `deliveries` and `releases` (section 8 removes the round; what a row's
release needs is a flag of the row), `decl_watches` (config-counted, 0 by default: a reference to
an empty table), and under `listen` or `group` `handed`, `owed` and `handed_limits` (per face:
into R3's row). What stays is the core, the zid, the closed flag, the send word and the next local
id. Target 512 B e; cell M6 lists the fields by size and decides. The runtime keeps one deadline
per timer kind per face (lease, keep-alive, batch flush, fragment expiry: 4 x 8 B) and the head of
the gets' deadline index (ir-send-query Q-DEADLINE), with no link task: 128 B e. The session handle
is the engine row's index and generation, 32 B e with its alignment. Files: `engine.rs`,
`wz-runtime-coop` (`CoopRuntime::placed_layout`), `wz-capi-pico/src/session.rs`. Lane H7.

**R8. The config is moved into the session.** `z_open` takes the config by move, as pico's does;
the open keeps the config's process-pool slot as the session's endpoint storage until the close,
so the arena's endpoint rows (80) are not a second copy of the same text. The count table of
section 3 (`OpenCounts`) holds a `u16` per countable limit (every ceiling of section 3 is below
65,536), not a `u32`: about 70 B less. A process with one session holds one config slot and
nothing else of its config; a scout's hello pool is reserved at the scout, beside it. Files:
`wz-capi-pico/src/config.rs` (`ConfigState`), `session.rs`, `wz-capi-coop/src/arena.rs`. Lane H6.

### 13.3 What was weighed and not done

- **Sharing the read buffer with the reassembly block.** A dialer reads into its one buffer all
  the time (the read of section 8 waits holding it), and a fragment is copied out of it into the
  chain: both are held at once whenever a chain is in progress, so sharing saves nothing.
- **A pool of batch-sized pages for read, write and reassembly.** Reassembly over non-contiguous
  pages needs a reader across pages for every generated decoder, and the pages must still cover
  the read buffer and a whole chain at once: the same bytes as today's two buffers.
- **Lowering the default counts** (D2): it would win bytes by refusing what pico allocates; the
  rows above win them without changing what a program may declare.
- **A smaller reassembly block** (F below 4,096): it changes the largest message a pico peer may
  send without a refusal, which is the preset's contract with pico.

### 13.4 Tests

Each lever lands with tests that assert, at the preset's feature set and in a build without the
lever's feature where it has one:

- R1: a put of 8 B to one face moves the arena's free bytes by nothing and leaves the control slot
  untouched (its watermark unchanged); a put of 3 x B bytes is sent as three fragments and the
  peer reassembles it equal to the payload; a link kind that states `GATHERS = false` opens with a
  transmit slot of B in its plan and one that gathers with none; a Declare with a key of
  `MAX_KEYEXPR_BYTES` fits the control slot and one byte more is refused at the declaration by the
  key's own limit, never by the slot.
- R2: the plan holds exactly one large block at the defaults; a chain started while a program
  holds the block is dropped and counted, and the next chain after the program drops it completes;
  a batching window opened while a chain holds the block writes each message at once and every
  message arrives.
- R3 to R8: the row report (`ArenaPlan::reserved`) of the dialer at the defaults equals the sum of
  13.1's reinforced column for the rows each lane owns; `no_heap_after_open` holds.
- The verdict: the massif peak of the W arm's z_put at most pico's z_put less 1 KB, by the
  pico-compare heap mode.

### 13.5 Lanes

R1 is carried by ir-send-query's S-WRITE (it owns the writers and `stream_link.rs`), R2 and R6 by
H5, R3 by H3, R4 by H4, R5 by H2, R7 by H7, R8 by H6. None needs an owner decision beyond those of
section 10; R2 replaces the formula of section 6's large-block row and needs none.
