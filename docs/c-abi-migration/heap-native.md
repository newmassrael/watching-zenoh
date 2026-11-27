# Migration lane heap-native: the storage policy is the storage shape

Status: design of the lane and its first steps. Landed on the lane's branch: N0 (one table
contract held on every policy), N1 (where a policy's rows lie and when its tables take their
memory are facts of `Storage`), N2 (the policy `OnUse`, its column `FirstUse` and its keys
`HeapKey` over a `KeyBudget`, held to the same contract) and N3a (the session's tables made
counted on `OnUse`), then N3b (every other table a face and the application hold, counted on
`OnUse`, and the two places where a table of that policy is asked for room before the push that
takes its memory). The owner's ruling of 2026-11-27 chose the form of section 6 (c), per
preset: the cooperative engine's on-use form (N3c to N3e), the doors' (N4) and the switch with its
guards (section 9) are designed here and not written yet, because the engine has no form on
`OnUse` to select and a switch that cannot be built is not declared; section 11 reads what N3c has
to give a home to, and why it is the next step and not a part of N3b. Nothing here was built or
measured by this lane: a byte figure is either **read** from the size ledger's explain document or
from `nm -S` of the case's library named below, or an **estimate** read off the code; a count of
instructions is a reading of the code, not a run. Line references are to the tree this lane
branched from (`568c90f500`).

## 1. The reading

### 1.1 What "the heap profile" is in this case

- The size case `pico-client-coop-nostd` (`os-host,link-udp`, profile `capi-nostd`) links an
  allocator, so `wz_session_core::bounded::Profile` is `Heap` (`crates/wz-session-core/src/bounded.rs:802-803`;
  `session-row.md` section 5 read it with `cargo tree -e features -i wz-session-core`).
- Its session's tables are not of the `Heap` policy. The cooperative engine names its tables'
  policy apart from `Profile`: `RowPolicy` is `Region`, or `Lent` with `runtime-plan`
  (`crates/wz-capi-coop/src/lib.rs:133-137`). Every table, key and row of the session lies in the
  one block its open reserves, the build's `StateRegion` at its head and the arena the open plans
  after it (`lend_session`, `crates/wz-capi-coop/src/engine.rs:898`), taken from the host's
  fresh pages (`HostPages`); the objects a program holds lie in the process pools
  (`crates/wz-capi-pico/src/process_pool.rs`, module documentation).
- That is the contract, not an accident of the profile: D12 (`docs/upstream-parity.md:549`, owner,
  2026-11-21): every byte a session needs is reserved at open from its configured limits and
  nothing is allocated after, held per operation family at 0 by `deploy/no_heap_ratchet.json`
  (Layer C1nh). The owner's ruling of 2026-11-23 ships this form, with "allocation after open 0"
  among the release bar, and orders the work: win in this form first.
- So the build states two facts that today's names keep in one place: whether an allocator is
  linked (`Profile`), and **when** a session takes its memory (D12: at its open). Every piece of
  machinery this lane counts exists for the second fact. A heap-native form changes the second fact
  for a preset; that is the owner's choice (section 6). This note designs the form so that the
  choice is one switch and its price in code, instructions and memory is stated before it is made.

### 1.2 The machinery, owner by owner

Bytes: the explain document of the case dated 2026-11-27 (schema 5, pin `6a881c21dad1`), case
total 205,921 against zenoh-pico's 170,500; an owner's bytes are its lines wherever they were
inlined. Bodies: `nm -S --size-sort` of the case's library from a lane build of the same day
(`shipped/pico-client-coop-nostd/libwz_capi_pico.so`, `.text` 213,451); a body's size differs
from the explain document's reading by build (`lend_session` 4,290 here, 3,351 in
`base-sessions.md`).

| group | owners (explain, lines) | bodies (nm) | exists because | in a heap form |
|-------|-------------------------|-------------|----------------|----------------|
| A. the open's lay-out | `wz_capi_coop::arena` 1,662, `::region` 372, `::lodging` 228, `::engine::lend_session` 254, `wz_session_core::placed` 224, `::step_lend` 102; of `bounded`'s lines, those in `lend_session` 789, `registry::let_go` 535, `assemble` 505, `Arena::cell_spans` 225, `TableLender::lend_stride` 121, `drop_row::<FaceTables>` 160; `engine.rs`'s lines in `lend_session` 1,143 (`base-sessions.md` 3.1). About 6,300 read; the share of `assemble`'s 3,055 `engine.rs` lines that places the region is not read | `assemble` 4,598, `lend_session` 4,290, `registry::let_go` 559, `drop_row::<FaceTables>` 324, `SessionArena::kept_span` 269, `Arena::cell_spans` 233, `TableLender::lend_stride` 142, `TableLender::cell_spans` 103, `HostPages::reserve` 76, `lent_under` 53 | one reservation at open, planned and lent to every table | goes |
| B. keys | `wz_session_core::key_arena` 3,201 | `SessionKeys::key` 636 (the engine's), `KeySpace::key` 437 (first fit, bump, split), `KeyRef::drop` 289 (the count and the merge walk), `lent_key` 273, `LentKeys::key` 91 | a key made after open cannot take memory, so it takes a block of a budget reserved at open | the allocator holds the text; the count of holders and the budget stay |
| C. entity tables | `wz_session_core::slot_map` 6,040 | `RawSlots::take` 226, `Core::unpin` 156, `add_free_lent_slot` 141, `Core::nth_live` 126, `RawSlots::remove` 98, `Core::take_free` 95 | the generational slot map is every policy's (`docs/c-abi-architecture.md` P10, P11; W4 of `base-sessions.md`); only `add_free_lent_slot` and the lent columns are the open's | the core stays; the column changes |
| D. the tables' algorithms | `session_tables` 7,304, `id_map` 725, `row_pool` 107, `held_list` 124 | | written once over `P: Storage` | stays |
| E. sequences | the rest of `bounded`'s lines, 3,932: `LentSeq`'s operations inlined into the table bodies (`declare_write_filter` 168, `undeclare_write_filter_quietly` 159, `replay::told` 133, ...) and `BoundedString`'s text (`z_encoding_to_string` 203, `check_outbound_keyexpr_pico_safe` 178, `push_str` 130, `EndpointTexts::write` 100) | | a lent sequence is a span the open lent; a text is every policy's | the sequence's shape changes; the text stays |
| F. link memory and counted cells | `wz_runtime_coop::kept` 1,521, `::link_cells` 1,522, `::link_storage` 1,506, `wz_session_core::byte_cells` 531 | `Shared::<CoopEngine>::last_placed` 999, `head_in` 132, `heap_head` 60, `place_head` 43, `copied_send` 188 | a link's cell and buffers are claimed from the arena's tables; `heap_head` is the heap arm, compiled beside the lent one (`crates/wz-runtime-coop/src/link_cells.rs:345`, `:388`) | the heap arm alone |
| G. the doors' pools and places | `wz_capi_pico::process_pool` 1,998, `::object_slot` 1,097, `::session_place` 145, `wz_capi_port::lodge` 65, and of `bytes` the block bodies | `give_back` 408, `lay_stage` 378, `take_slot` 206, `Pools::counted` 160, `Reserved::stage` 99, `Lender::lend_into` 234, `Lender::give_back` 164, `retire_lent` 131, `Block::with_room` 538, `Block::drop` 65 | an object a program makes after open takes a slot of a pool reserved at its first need | objects from the allocator; payload blocks by Ir (3.7) |
| H. engine rows | `wz_capi_coop::engine::reach` 446 | | | `session-row.md` R1 |

### 1.3 zenoh-pico's same tables (1.10.2, the submodule's `6a881c21da`)

| wz | zenoh-pico | where |
|----|------------|-------|
| the session's state | one `z_malloc(sizeof(_z_session_t))` at open, in a counted handle | `vendor/zenoh-pico/src/api/api.c` @ `_z_session_t *s = (_z_session_t *)z_malloc(sizeof(_z_session_t));`, `vendor/zenoh-pico/src/api/api.c` @ `_z_session_rc_t zsrc = _z_session_rc_new(s);` |
| the session's declared keys | `_z_resource_slist_t *_local_resources`, a list; each key a copy of its own length | `vendor/zenoh-pico/include/zenoh-pico/net/session.h` @ `_z_resource_slist_t *_local_resources;`, `vendor/zenoh-pico/src/session/resource.c` @ `_z_keyexpr_copy(&dst->_key, &src->_key);`, `vendor/zenoh-pico/src/session/resource.c` @ `return _z_string_copy(&ret->_keyexpr, &expr->_suffix);`, `vendor/zenoh-pico/src/session/resource.c` @ `*resources = _z_resource_slist_push_empty(*resources);` |
| a peer's declared keys | `_remote_resources`, a list per peer | `vendor/zenoh-pico/include/zenoh-pico/transport/transport.h` @ `_z_resource_slist_t *_remote_resources;` |
| subscribers | `_z_subscription_rc_slist_t *_subscriptions`, a counted struct per declaration pushed on a list | `vendor/zenoh-pico/include/zenoh-pico/net/session.h` @ `_z_subscription_rc_slist_t *_subscriptions;`, `vendor/zenoh-pico/src/session/subscription.c` @ `_z_subscription_rc_t out = _z_subscription_rc_new_from_val(s);`, `vendor/zenoh-pico/src/session/subscription.c` @ `zn->_subscriptions = _z_subscription_rc_slist_push_empty(zn->_subscriptions);` |
| tokens, pending liveliness gets | `_z_*_intmap_t`, a map of lists | `vendor/zenoh-pico/include/zenoh-pico/net/session.h` @ `_z_declared_keyexpr_intmap_t _local_tokens;` and the maps after it |
| queryables, pending queries, interests, a peer's declarations | lists | `vendor/zenoh-pico/include/zenoh-pico/net/session.h` @ `_z_session_queryable_rc_slist_t *_local_queryable;` and the lists after it |
| a transport's buffers | one write and one read buffer of the batch, at the transport's open | `vendor/zenoh-pico/src/transport/unicast/transport.c` @ `ztu->_common._wbuf = _z_wbuf_make(wbuf_size, false);` and the read buffer after it |
| an object a program holds | a `z_malloc` each | |

Its collections in the case's reading: `collections/list.c` 2,525, `vec.c` 1,867, `string.c` 1,899,
`hashmap.c` 1,614 with its template 2,811, `intmap.h` 1,201, `refcount.c` 773. A lookup by id walks
a list; a stale handle is not refused (W4 of `base-sessions.md`).

## 2. The target

### 2.1 The policy is the shape, named by its facts

A storage policy (`bounded::Storage`, `bounded.rs:148`) is the answer to three facts about a
build, and its associated types are the shape that answer gives each table:

| policy | allocator | memory taken | rows laid out by | table rows | keys | peer ids | used by |
|--------|-----------|--------------|------------------|-----------|------|----------|---------|
| `Static` | none | at build | the build, inline | inline array of `N` | inline buffer of `MAX_KEYEXPR_BYTES` | `FixedIdMap`, a scan | an image without an allocator |
| `Region` | an image's region or the allocator | at open | the build (`StateRegion`) | a span beside the table | a block of the key arena | `FixedIdMap` | the cooperative engine |
| `Lent` | the allocator | at open | the open's plan | a span of the arena | a block of the key arena | `PooledIdMap` or `FixedIdMap` | the cooperative engine, `runtime-plan` |
| **`OnUse`** (N2) | the allocator | at a table's first row, a key's making, an object's making | the table | its count's rows in one allocation at its first row, never moved | one allocation of its own, counted against the session's key budget | `FixedIdMap` | the cooperative engine of a preset whose `table-memory` is `on-use` (section 9) |
| `Heap` | the allocator | as it grows | the table | `Chunked`, 32 rows at a time | `String` | `GrowableIdMap` (`hashbrown`) | the AP side (the tokio engine, `std`) |

`OnUse` and `Heap` take the same memory and are two shapes because they serve two scales. The
cooperative engine's tables are counted (each limit binds at the open on the heap profile too,
`binding_heap = "open"` in `deploy/wz-config.toml`), small, and read in place on the receive, so
a row never moves and is reached by one multiply-add. The AP side's are advisory and router-sized,
so its rows grow by chunks and its peer ids hash. Neither takes the other's shape: `Chunked` costs
the receive a chunk step per row reached and `hashbrown` costs a few kilobytes of code per value
type (3.3, 3.4).

The cooperative engine's `RowPolicy` becomes the resolution of those facts and not of
`runtime-plan` alone: with `tables-on-use` (the `on-use` value of the `table-memory` axis,
section 9), `OnUse`; otherwise `Region` or `Lent` as today. The moment the memory is taken is
an axis of its own, apart from `Profile`, as `session-row.md` section 2 keeps where an engine row
comes from apart from where a session lays its tables. N1 states it as a fact of every policy,
`Storage::TAKEN` (`Taken::AtBuild`, `AtOpen`, `AtFirstUse`, `AsItGrows`), and the engine holds
its `RowPolicy` to the moment it lays its tables out at by a compile-time assertion
(`crates/wz-capi-coop/src/lib.rs`, after `RowPolicy`): today `AtOpen`, which every build of it is.
`OnUse` exists only where `alloc` does, so no build names it without an allocator; the
cooperative engine links one in every form (`extern crate alloc`), and needs no refusal of its own.

### 2.2 `OnUse`, type by type

| associated item | `OnUse` | why |
|-----------------|---------|-----|
| `ENFORCES_CAPACITY` | `true` | the counts bind, as on `Region` and `Lent` |
| `LENT_AT_OPEN` | `false`; `row_may_lie_in` and the engine's assertion of where its rows lie read a fact of their own instead (N1, `Storage::ROWS_STAY_APART`): a row lies apart from the table and never moves while it stands, true of `Region`, `Lent` and `OnUse`; `LENT_AT_OPEN` keeps its other question, whether a table made by `Default` has no rows (the match memory's `memo_slots`) | the constant answered two questions |
| `ROWS_STAY_APART`, `TAKEN` | `true`, `Taken::AtFirstUse` | N1's facts |
| `Seq<T, N>`, `Rows<T, N>` | `FirstUse<T, N>` (`crates/wz-session-core/src/on_use.rs`; `Rows` is `BoundedVec<T, N, OnUse>` over it): a column made with its count and no memory (`BoundedVec::counted`, `SlotMap::counted`; `Default` makes one of `N`), which takes all its count's rows in one allocation at its first push, by one untyped body for every row type (as `add_free_lent_slot` is), and never grows; a push past the count, or one the allocator refuses, is `CapacityFull` with the value handed back | the rows never move, so every holder of a row's place (`KeyexprHead`, a pinned row read in place) is sound as on `Lent`; a table never used takes nothing |
| `Text<N>` | `heapless::String<N>` | a working text is on the stack, as on `Lent` |
| `Key`, `Keys` | `HeapKey`: one allocation holding the count of its holders, its length, the budget it is counted against and its bytes; `BudgetKeys`: the handle a table holds on the session's `KeyBudget` (the bytes its keys may take together, `KEY_ARENA_BYTES`, and the bound on a key's length, `MAX_KEYEXPR_BYTES`), a key counted as the block the key arena would give it (`key_arena::block_bytes`) | a key is never cut short; a key past the bound is `TooLong`, one past the budget or refused by the allocator `NoRoom`, nothing taken, as today; a clone is one more holder and never fails |
| `KeyLen`, `Offset` | `caps::KeyLen`, `u32` | as `Lent` |
| `Ids<V, N>` | `FixedIdMap<V, N>` | a scan of a few rows, inline in the state (3.4) |
| `Pooled<T, N>` | `BoundedVec<T, N, Static>` | as `Region` |
| `Epoch`, `HeapForm` | `()`, `Infallible` | the AP side's forms are not compiled in |
| `Compose` | `ComposeInline` | as `Region` |

What a program sees does not change but for D12's moment: a declaration past its count is refused
as today, and one the allocator refuses is answered as a count's refusal
(`_Z_ERR_SYSTEM_OUT_OF_MEMORY`), which is what zenoh-pico answers when its `z_malloc` fails.

### 2.3 One contract, every shape

What a policy changes is where a table's rows lie. What a table answers is one contract, held on
every policy by the same test bodies:

1. A table made to hold n rows takes n and refuses the next, handing the value back whole and
   taking nothing.
2. A row stays where it was put while it stands, whatever is put after it.
3. A handle names nothing once its row left, before and after its slot is taken again.
4. A row removed while pinned leaves every lookup and walk at once, holds its slot until its last
   unpin, and is handed back by that unpin.
5. A limit lowered under the rows held refuses every insert until enough leave, free slots or not.
6. Dropping a table drops each live and retired row once.

N0 lands 1 to 5 as one body generic over the policy, run on `Static`, `Lent`, `Region` and
`Heap` held to a count, and 6 on `Heap` beside the `Lent` and `Static` cases there were (section
7). `OnUse` joins the same bodies in N2, with the key contract beside them: a key reads back whole;
one past the length bound is `TooLong`; one past the budget is `NoRoom` and takes nothing; a shared
key lives until its last holder, and its bytes go back to the budget then. N3a runs the session's
tables on it: a declaration past a table's count and a key past the budget are refused as a full
table, and a row a call reads in place is let go of by the call's end, as on `Lent`.

## 3. Table by table

### 3.1 The session's state and the open's lay-out (group A)

- Today: the open plans the arena (`ArenaPlan`), reserves it once with the zeroed `StateRegion`
  at its head, places the region's tables over their rows by one walk of its lines
  (`StateRegion::place`, `crates/wz-capi-coop/src/region.rs`), and lends the rest by one
  `TableLender`; a refusal after part was lent gives it back with the arena.
- zenoh-pico: one allocation of the session, its lists empty; a transport's buffers at the
  transport's open.
- `OnUse`: the engine's state is one allocation at open, refused rather than aborting when the
  heap is full (as `try_box` makes one, `crates/wz-runtime-coop/src/kept.rs:25`), each table in it
  made with its count from the limits
  the open resolved and no memory; a link's buffers taken by the link at its dial; a reassembly
  buffer at a chain's first fragment. No plan, no region, no lender, no arena.
- Bytes: group A's 6,300 read lines go, less what writes each table's count and the state's
  allocation and drop: **-3,500 to -5,500**.
- Receive Ir: none of it is on the receive.
- Stack: the open's deepest chain loses most of `lend_session`'s frame (6,272 B) and part of
  `assemble`'s (8,464 B) (`base-rss.md` section 3, main thread's stack).

### 3.2 Keys (group B)

- Today: `KeySpace::key` takes the first free block that holds the key, splits it, or bumps
  (`crates/wz-session-core/src/key_arena.rs:246`, `:432`); the last holder's drop merges the block
  with its free neighbours (`:278`); `kept` finds a block of the same text (`:484`).
- zenoh-pico: each holder copies the key into an allocation of its length.
- `OnUse`: `HeapKey`, one allocation of a header (the holders' count, the length) and the bytes;
  the session's `KeyBudget` counts the bytes held against `KEY_ARENA_BYTES`, so a declaration
  past it is refused exactly as today. No first fit, no split, no merge walk, no text lookup: a
  row that copies another's key clones it, and `shared` of a text no row holds takes a new key.
- Bytes: **-1,700 to -2,300** of the 3,201.
- Receive Ir: a key's text is read at its place, not at the arena's base plus an offset: 0 to -2
  a key read, 0 to -6 a sample.

### 3.3 Entity tables (group C)

- Today: the generational slot map, its columns lent (`add_free_lent_slot`,
  `crates/wz-session-core/src/slot_map.rs:1048`).
- zenoh-pico: a list of counted structs per kind, a lookup a walk.
- The heap shape that was weighed: `Chunked` (`slot_map.rs:807`), the `Heap` policy's column.
  Its row reach is `RowsAt::run_of` (`slot_map.rs:500`): the list of chunks loaded, the place
  shifted and masked, the chunk loaded, three to four instructions more than a flat column's
  multiply-add for every row reached. The receive's walk of the subscribers
  (`pin_subscribers`, `session_tables.rs:3485`) reaches every live row of the table on every
  sample, so the receive's Ir would rise by about 4 a subscriber: the table keeps the array form.
- `OnUse`: the core as it is; the column `FirstUse` (2.2), flat, so the reach is the region's.
- Bytes: **-100 to +100** (`add_free_lent_slot` 141 goes, the first row's allocation comes).
- Receive Ir: 0.

### 3.4 A peer's tables by id (group D)

- Today on `Region`: `FixedIdMap`, a scan of an inline array; `Heap`'s is `GrowableIdMap`, a
  `hashbrown` map (`crates/wz-session-core/src/id_map.rs:763`), whose code is not in the case
  (`nm` names no `hashbrown` body).
- zenoh-pico: a list per peer, a walk.
- `OnUse`: `FixedIdMap`, unchanged: a hash costs more instructions than a scan of a few rows,
  and its code is a few kilobytes per value type.
- Bytes: 0. Receive Ir: 0.

### 3.5 Sequences (group E)

- Today: `LentSeq` operations inlined in every table body.
- `OnUse`: `FirstUse` operations. A read of a column with no memory finds no row, as a read of
  an empty lent one does; only a push asks whether the column has its memory, one compare inlined
  and the allocation out of line in one untyped body.
- Bytes: **-300 to +600**: the compare at every push site is the risk, and the out-of-line body
  is what holds it down. Receive Ir: 0 to +3 where the receive pushes into a session column.

### 3.6 Link memory and counted cells (group F)

- Today: a link's cell is claimed from a `LentByteCells` table of the arena, its receive buffers
  from a pool lent at open, held while a batch is partly read (`crates/wz-capi-coop/src/arena.rs`,
  module documentation).
- zenoh-pico: the transport's two buffers for its life.
- `OnUse`: the heap arm the cells have already (`heap_head`), alone; a link's buffers taken at
  its dial and held for its life.
- Bytes: **-1,000 to -2,000**. Receive Ir: 0 to -30 a batch where today's read claims and gives
  back a pool buffer (to be read on the perf matrix).

### 3.7 The doors' objects and payloads (group G)

- Today: a pool per kind and three payload classes, reserved at the first need of each stage.
- zenoh-pico: `z_malloc` for each.
- `OnUse`: an object (a config, a declared key's object, an encoding, a held sample) from the
  allocator, counted against its kind's count. A payload block stays pooled, the pool taken at the
  first payload, unless the put's Ir with the allocator's call is read no higher than with the
  pool's take: the put builds a payload a message, and a pool take is a free-list pop where
  `malloc` is a call.
- Bytes: **-2,000 to -3,000**. Receive Ir: 0 (a sample is handed to its callback as a view). Put
  Ir: to be read.

### 3.8 Engine rows (group H)

`session-row.md` R1 takes an engine row of the heap at open on the `Heap` profile and keeps it for
the next open; R2 deletes the seat, R4 makes the kernel's token places follow the policy. They are
this lane's principle applied to the one table whose source the profile alone decides: an `OnUse`
session takes its row at its open, as every policy's does.

## 4. Steps

| step | what | where | bytes, the case (estimate) | receive Ir | resident memory |
| step | what | where | bytes, the case (estimate) | receive Ir | resident memory |
|------|------|-------|---------------------------:|-----------|-----------------|
| **N0 (landed, `73d15f135e`)** | the table contract of 2.3 as one body run on every policy | `crates/wz-session-core/src/slot_map/tests.rs` | 0 | 0 | 0 |
| **N1 (landed, `5acca4fdfd`)** | `Storage::ROWS_STAY_APART` ("a row lies apart and never moves") read by `row_may_lie_in` and by the engine's assertion of where its rows lie; `Storage::TAKEN` (`Taken`) states when each policy's tables take their memory, and the engine asserts its `RowPolicy` takes it at open | `bounded.rs`, `session_tables.rs`, `crates/wz-capi-coop/src/lib.rs`, `engine.rs` | 0 (constants and a compile-time assertion) | 0 | 0 |
| **N2 (landed, `64609f48a3`)** | `OnUse`, `FirstUse`, `HeapKey`, `KeyBudget` and its handle `BudgetKeys`; `SeqBacking::make_room`, so a table that grows two columns as one makes both their rooms before it pushes to either; the N0 bodies, the sequence bodies of `bounded.rs` and the key contract run on it | `bounded.rs`, `slot_map.rs`, `on_use.rs` (new) | 0 (nothing in a case names it) | 0 | 0 |
| **N3a (landed, `1243d2623f`)** | the session's tables made counted on `OnUse` (`SessionTables::counted`, `Presence::counted`, `CountedTable`, `HeldReplies::counted`) | `session_tables.rs`, `reply_hold.rs` | 0 (no engine makes them yet) | 0 | 0 |
| **N3b (landed, `ffde81a72e`, `b83c368fbd`, `3da7536dde`)** | the session core's other tables a face and the application hold, counted on `OnUse`, each a constructor as N3a's from the limits the open resolved: `PeerTables::counted` and `count_rows` (the in-place form, as `lend_rows`), `SubscriberPeer::counted`, `ReplyStage::counted`, `FinalStage::counted`, `Requesters::counted` (`ReplyRegistry`, `LivelinessGetRegistry`), `SlotObserverOf::counted` over `CountedTables` (the watcher lists, `LocalTokenRegistry`); `LentRoom` and `PeerTokens` need none (on `OnUse` the composing room is inline, `ComposeInline`, and a peer's tokens a `FixedIdMap` whose keys `keep_keys_in` hands). `ReplyStage::stage_parts` makes both its columns' rooms before it writes either, and the query dispatch asks `FinalStaging::make_room` before a query runs, on a first-use policy (each arm folds away on every other) | `peer_tables.rs`, `slot_observer.rs`, `pubsub.rs`, `reply_stage.rs`, `reply.rs`, `decl_sink.rs`, `declare/{subscriber,queryable,liveliness,liveliness_get,local_token}.rs`, `query.rs`, `query/{in_place,pinned}.rs` | 0 (no case names them; the two room arms fold away on the D12 policies) | 0 | 0 |
| N3c | the cooperative engine on `OnUse` under `tables-on-use`: `RowPolicy = OnUse`, the registry made by value (a third form beside `RegistryRegion` and the arena's), the open with no plan, no region and no lender (3.1), the session's `KeyBudget` in the boxed engine state (3.2); the moment assertion of N1 reads `AtFirstUse` in that form | `crates/wz-capi-coop` (`lib.rs`, `engine.rs` `lend_session` and `assemble`, `engine/registry.rs`, `registry/placed.rs`; `arena.rs` and `region.rs` not compiled in the form) | -4,500 to -8,200 (3.1, 3.2, 3.3, 3.5) | 0 to -6 (3.2); +3 at worst (3.5) | section 5 |
| N3d | link memory on the heap arm alone (3.6) | `crates/wz-runtime-coop` (`link_cells.rs` `heap_head`, `kept.rs`, `link_storage.rs`) | -1,000 to -2,000 | 0 to -30 | section 5 |
| N3e | a key held apart from every row (an object outside the lock: `KeyRef::hold_apart`, `KeysLocked::adopt`, `SampleView::keyexpr_held`) as a `HeapKey` clone taken and let go of under the lock, read by its text outside it | `key_arena.rs` beside `on_use.rs`, `sink.rs`, the engine's object paths | -200 to +200 | 0 | 0 |
| N4 | the doors: 3.7 | `crates/wz-capi-pico` (`process_pool.rs`, `object_slot.rs`, `bytes.rs`) | -2,000 to -3,000 | 0; the put's to be read | -0 to -8 KiB a pair |
| N5 | the switch and its guards (section 9): the `table-memory` axis, the zenoh-pico defconfig's `on-use`, the release profiles' `at-open`, the size cases of both forms (section 10) and C1nh's second reading | `deploy/wz-config.toml` and what it generates, `configs/zenoh-pico_defconfig`, `configs/profiles/host-peer-ext.conf`, `host-peer.conf`, `scripts/lib/capability_cost_gate.py`, `deploy/size_ledger.json`, `deploy/pico_host_ceiling.json`, `scripts/run-ci.sh` (C1nh) | 0 for the release form; the on-use case reads N3 and N4's figures | 0 | 0 |

N3c to N4 together (N3 of the first reading, split by where the code lies): **about -7,500 to
-13,200** in the on-use case (section 10), against a gap of 32,525 (the case at 203,025)
or 35,421 (the explain document's 205,921): between a quarter and two fifths of it, the largest
single lever read so far, and not the whole. The largest unknown is how much of `assemble`'s 4,598 bytes the
region's placement is; `objdump -d -l --inlines` on the case reads it before N3 is written, as
`base-sessions.md` 3.1 asks of the open.

## 5. Resident memory

| part, a pubsub pair (KiB) | today (`base-rss.md` R0) | D12 kept, the heap lanes' targets (`docs/win-budget/heap.md` 5.8) | `OnUse` (estimate) | zenoh-pico |
|---|---:|---:|---:|---:|
| session arena (anonymous) | 160 | about 17 | 0 | 0 |
| what the sessions hold, on the brk heap | | | +12 to +24 (the state, the rows of the tables used, two batch buffers a link, the keys, the allocator's headers) | its session, two 2,048 B buffers a transport, a sample and a cache entry a message |
| the read thread's own malloc arena | 0 | 0 | +8 to +16, where the read thread allocates (a peer's key, a first fragment's buffer) | 12 |
| main thread's stack | 76 | 76 | about 56 to 64 (the open's frames, 3.1) | 48 |

The arena's 160 KiB is reachable inside D12: the heap lanes and `base-rss.md` L3 bring it to about
17 KiB with the contract kept. `OnUse`'s gain over that is within a few kilobytes either way, and
the read thread's allocations can cost more than they save: memory is not a reason for `OnUse`;
code is.

## 6. The decision, and the alternative inside D12

### 6.1 What `OnUse` changes of D12

The amount is bounded as today, by the same counts; the moment is not. Under `OnUse` the ratchet
of D12 reads the steady families (a put, its receive, a delete) at 0 a round once their first use
is past, its `grown` counting the first use's blocks; the declaration families (a key expression,
a publisher, a subscriber declared and undeclared each round) allocate in every round, as
zenoh-pico's do. So the choice for the zenoh-pico preset is one of:

- (a) keep D12 for the shipped form: `OnUse` is a form a deployer chooses, the size case does not
  move, and section 4's figures are what D12 costs the case in code;
- (b) scope D12 to the send and the receive: nothing allocated on either after their first use, a
  declaration allocating as zenoh-pico's does;
- (c) state `first-use` for the zenoh-pico preset, as zenoh-pico allocates on use.

The owner's ruling of 2026-11-27 (delegated) is (c), stated per preset: the storage policy is an
axis apart from the API, and a preset chooses it. The release of 12-01 (no `std`, no heap after
open) keeps D12: its profiles (`configs/profiles/host-peer-ext.conf`, the Windows package's, and
`host-peer.conf`, its like-for-like) state `at-open`, and Layer C1nh, which reads
`host-peer-ext.conf`, holds its families at 0 against `deploy/no_heap_ratchet.json` unchanged. The
zenoh-pico preset follows zenoh-pico's own contract, a declaration allocating: its defconfig states
`on-use`. The table abstraction stays one, `bounded::Storage`, and every policy is held to the
same contract bodies (2.3). N0 to N3a are the same under every choice; N3b to N4 build the on-use
form; N5 writes the choice and its guards (section 9).

### 6.2 Each table allocated at open (weighed, not chosen)

Inside D12, each table could take its rows from the allocator at the open instead of from one
planned arena. It replaces one reservation and its lender with one allocation per table and a
refusal arm for each, while the counts the plan resolves stay; the region already took the
planning out of the registry's lay-out. Expected -500 to +500 bytes, the same resident memory as
`base-rss.md` L3: not a lever.

## 7. What the landed steps test, and what turns each red

In `crates/wz-session-core/src/slot_map/tests.rs`, `keeps_the_table_contract`, one body over
`P: Storage` for a table made to hold 40 rows (past one chunk of `Chunked`'s 32), run by
`a_fixed_table_keeps_the_table_contract`, `a_lent_table_keeps_the_table_contract`,
`a_region_table_keeps_the_table_contract` and, with `alloc`,
`a_growable_table_held_to_a_count_keeps_the_table_contract`:

- the count: 40 taken, the 41st refused with its value back, the length unchanged. Red if
  `Core::take_free` takes past the limit, or a column adds a slot past its count;
- a row stays where it was put: the first row's address after the 40th insert. Red if a column
  moves its rows when it grows (a `Vec` of rows in place of `Chunked`);
- generations: a removed row's handle finds nothing before and after its slot is taken again, and
  the new handle is not the old. Red if `Core::free` leaves the slot's generation;
- retirement: a pinned row removed is found by no lookup and no walk, holds its slot (the table
  refuses an insert), and its last unpin hands it back and frees the slot. Red if `Core::retire_at`
  frees a pinned slot, or `find_row` reads a retired row as live;
- a lowered limit: under the rows held, an insert is refused with two slots free, and taken once a
  third row leaves. Red if `Core::take_free` does not compare the rows held with the limit.

`dropping_a_growable_table_drops_its_live_and_retired_rows_once` (with `alloc`) runs the drop
body there was for `Lent` and `Static` on `Heap`: three rows, one removed, one retired while
pinned, each dropped once. Red if `Chunked`'s drop skips a written row or drops one twice.

### 7.1 N1

- `bounded::tests::each_policy_states_when_its_tables_take_their_memory`: `Static` at build and
  inline, `Lent` and `Region` at open and apart, `Heap` as it grows and not apart, `OnUse` at
  first use, apart and bounded. Red if a policy's `const TAKEN` or `const ROWS_STAY_APART` line
  in `bounded.rs` answers another policy's fact.
- At the build, not as a test: `row_may_lie_in` (`session_tables.rs`) reads
  `P::ROWS_STAY_APART` in the `const` assertions of every `begin_*` that hands a call a row read in
  place, the engine asserts the same of its `RowPolicy` (`crates/wz-capi-coop/src/engine.rs`, the
  `const _` on `ROWS_STAY_APART`), and `crates/wz-capi-coop/src/lib.rs` asserts `RowPolicy::TAKEN` is `AtOpen`. A
  `RowPolicy` that keeps its rows inline, or that takes its memory at another moment, does not
  build.

### 7.2 N2

- `bounded::tests::on_first_use::*`: the seven sequence bodies every policy runs (fill to `N`
  and one more, free slots, order and the take-out scan, removal by place, the byte filler, the
  text, `Default`) on `OnUse`. Red if `FirstUse::room_for` admits a value past `count`, or a bulk
  form (`resize`, `extend_from_slice`) writes before its room is made.
- `bounded::tests::an_on_use_table_takes_its_rows_at_its_first_value_and_holds_its_count`. Red if
  `FirstUse::counted` ignores its `rows`, or a table takes its memory when it is made.
- `on_use::tests` (ten): the column takes its rows at its first value and never moves them
  (red if `take_memory` is reached before a value asks, or takes one row at a time); its count is
  held to `N` and a column of no rows takes nothing (red if `counted` does not clamp); order is kept
  and a bulk form is refused whole; every value is dropped once, by a truncation, the drop and the
  iterator (red if `FirstUse::drop` or `FirstUseIntoIter::drop` skips or repeats a row); rows past
  the address space or of no bytes are not taken (red if `rows_layout` wraps); a key reads back
  whole and is counted as its arena block (red if `HeapKey::make` charges other bytes than
  `block_bytes`); a key past the bound is `TooLong` and past the budget `NoRoom`, counted, taking
  nothing, and the bytes a key gave back are taken again (red if `KeyBudget::refund` is not
  reached from the last holder's drop); the bound a budget was made with, lowered under the build's,
  holds; a shared key lives until its last holder (red if `Clone` copies, or `Drop` gives back
  while `holders > 1`); the empty key takes nothing and a table with no budget keeps nothing.
- `slot_map::tests::an_on_use_table_keeps_the_table_contract`: the N0 body. Red if the on-use
  column moves a row when it is written, or a count does not bound it.
- `slot_map::tests::an_on_use_table_takes_its_rows_at_its_first_insert_and_holds_its_count`. Red
  if `SlotMap::counted` makes its core or its columns of `N` rather than `rows`, or a lookup, a
  walk or `is_full` takes memory.
- `slot_map::tests::dropping_an_on_use_table_drops_its_live_and_retired_rows_once`. Red if a row
  of the on-use column is dropped twice or not at all.

### 7.3 N3a

- `session_tables::tests::on_use_tables_hold_the_rows_their_counts_give_them`: two subscribers
  of a count of two, the third refused as a full table with its callback back, each key counted
  against the budget, nothing held before the first declaration. Red if
  `SessionTables::counted` makes a table of the build's bound (`SlotMap::new` in place of
  `SlotMap::counted`), or the tables are handed a `BudgetKeys` of no budget.
- `session_tables::tests::a_key_the_budget_has_no_room_for_is_refused_as_a_full_table`. Red if a
  refused key is counted against the budget, or the refusal is answered as anything but a full
  table.
- `session_tables::tests::an_on_use_subscriber_undeclared_while_its_callback_runs_is_let_go_by_the_last_call`:
  a row whose call reads it in place (`CClosure`), retired while the call runs and let go of by its
  end. Red at the build if `OnUse::ROWS_STAY_APART` is `false` (the `const` assertion of
  `begin_subscriber`), and at the run if a retired row leaves its slot before its last call ends.

### 7.4 N3b

- `reply_stage::tests::on_first_use::*`: the fifteen stage bodies every policy runs (the `Final`s'
  fill, drain, backing and clear; the replies' fill, payload bound, exchange, arena, drain and the
  fields each build keeps) on `OnUse`. Red if `FirstUse` moves the rows a drain kept, or a bulk
  write of the stage's bytes lands before its room is made.
- `reply_stage::tests::an_on_use_stage_takes_its_memory_at_its_first_reply_and_holds_its_counts`.
  Red if `ReplyStage::counted` makes its rows of the build's bound (`BoundedVec::default()` in
  place of `BoundedVec::counted(replies)`), or a column takes its memory when the stage is made.
- `reply_stage::tests::an_on_use_stage_refuses_a_reply_past_its_count_of_bytes`. Red if the bytes
  are counted by the build's bound (`arena: BoundedVec::counted(bytes)` dropped).
- `reply_stage::tests::an_on_use_final_stage_takes_its_rows_at_its_first_final_and_holds_its_count`.
  Red if `FinalStage::counted` ignores `rows`.
- `peer_tables::on_use_tests::on_use_peer_tables_refuse_past_their_counts_and_keep_their_rows_across_a_drain`.
  Red if `count_rows` makes the reply stage, the `Final`s or the liveliness staging of the
  build's bound.
- `peer_tables::on_use_tests::an_on_use_peers_keys_are_counted_against_the_budget_and_given_back`
  (`codec-declare`, `declare-subscriber`). Red if `count_rows` does not hand the tables the
  budget (`keep_keys_in`), or a key's bytes are not given back with the forgotten peer.
- `slot_observer::on_use_tests::an_on_use_observer_holds_the_subscriptions_its_count_gives_it`.
  Red if `SlotObserverOf::counted` makes the table set by `Default` rather than
  `CountedTables::counted`, or does not hand it the budget.
- `slot_observer::on_use_tests::on_use_watcher_lists_hold_the_sessions_count_and_refuse_one_more`
  (`declare-subscriber`). Red if `DeclObserverPair::counted` ignores `rows`.
- `slot_observer::on_use_tests::on_use_requesters_refuse_a_get_past_their_count_and_count_its_key`.
  Red if `ReplyRegistry::counted` ignores `rows` or `keys`.
- `slot_observer::on_use_tests::on_use_liveliness_gets_hold_their_count` (`liveliness-get`). Red
  if `LivelinessGetRegistry::counted` ignores `rows`.
- `reply_stage::tests::making_room_for_a_final_takes_the_on_use_rows_before_anything_is_owed`.
  Red if `FinalStage::make_room` answers `has_room` without taking the rows on `OnUse`; the four
  dispatch sites (`query.rs`, `query/in_place.rs` twice, `query/pinned.rs`) ask it in place of
  `has_room`.
- Not tested: the arms that refuse a reply or a query whose row the allocator would not give
  (`stage_parts`, `make_room`); only a refusing allocator reaches them, and the crate's tests run
  on the process's.

## 8. What the main session runs

Nothing of N1, N2, N3a or N3b was built or run by this lane.

- N3b, with the crate's default features: `cargo test -p wz-session-core --lib reply_stage::tests`
  51 (32 before: fifteen `on_first_use` bodies and four tests of the counted stages added);
  `cargo test -p wz-session-core --lib on_use_tests`: 3 (one in `peer_tables`, two in
  `slot_observer`). With `--features declare-subscriber,liveliness-get` the same filter runs 6
  (the key budget of a peer's tables, the watcher lists, the liveliness gets).

- `cargo test -p wz-session-core --lib slot_map::tests`: 49 tests with the crate's default
  features (46 after N0, three added by N2).
- `cargo test -p wz-session-core --lib on_use::tests`: 10.
- `cargo test -p wz-session-core --lib bounded::tests`: nine more than before N1 (one N1, eight N2:
  the seven of `on_first_use` and one more).
- `cargo test -p wz-session-core --lib session_tables::tests`: three more than before.
- A build of `wz-session-core` without `alloc` (`--no-default-features`, and the slot profile's
  `--no-default-features --features session-slot`) compiles neither `OnUse` nor `on_use`, and
  `each_policy_states_when_its_tables_take_their_memory` there checks the three policies it has.
- `cargo clippy -p wz-session-core --all-targets -- -D warnings` and the same of `wz-capi-coop`
  (N1's assertions); a build of `wz-capi-pico` in both of its forms
  (`--no-default-features --features os-host,link-udp`, `Region`, and `...,peer`, `Lent`)
  confirms the moment assertion holds in each.
- `python3 scripts/lib/logic_census_coverage_gate.py`: `on_use.rs` has its row in `files.md` and
  is cited by row 61 of `S3.md`.
- Size: no landed step changes a case's bytes (constants, an assertion, a provided method whose
  answer is the check it replaced, and code no case instantiates). C1cs's reading of
  `pico-client-coop-nostd` and of `pico-api-coop-nostd` should be unchanged; a move there is a
  finding.
- For N3b to N4, on each step: the size ledger's explain document of
  `pico-client-coop-nostd-on-use` against `pico-client-coop-nostd` (section 10, `--per-feature`),
  the perf matrix's arm W receive Ir (about 3,066) and put Ir in the on-use form, `base-rss.md` M1
  on the pubsub pair (the anonymous, `[heap]` and `[stack]` rows of section 5), and C1nh's two
  readings: the release form's, unchanged at 0, and the on-use form's against its own table
  (section 9.2).

## 9. The switch and its guards

### 9.1 The axis

The moment is a choice of form, not a capability: no plane comes or goes with it, and a case that
differs from another only by it is divided by the same zenoh-pico, as a profile twin is. So it is a
global axis of `deploy/wz-config.toml`, as `engine` is, declared in N5 with the form it selects
(the file's own rule: an option that cannot be built is not declared):

```toml
[[axis]]
id = "table-memory"
kconfig = "WZ_TABLE_MEMORY"
prompt = "When a session of the cooperative engine takes the memory of its tables"
default = "at-open"

[[axis_option]]
id = "at-open"
axis = "table-memory"
kconfig = "WZ_TABLE_MEMORY_AT_OPEN"
prompt = "At the open, from the configured limits, and nothing after (D12)"

[[axis_option]]
id = "on-use"
axis = "table-memory"
kconfig = "WZ_TABLE_MEMORY_ON_USE"
prompt = "At each table's first row and each declaration's key, as zenoh-pico allocates"
requires = "WZ_ENGINE_COOP"
upstream_on = ["zenoh-pico"]
features = ["tables-on-use"]
```

- The default is `at-open`: every build that states nothing (the crates' own tests, a lane that
  resolves no preset) keeps D12.
- `upstream_on = ["zenoh-pico"]` writes `CONFIG_WZ_TABLE_MEMORY_ON_USE=y` into
  `configs/zenoh-pico_defconfig` when it is generated (`wz_config.py --emit defconfig:zenoh-pico`),
  as the role axis writes `CONFIG_WZ_ROLE_CLIENT=y` there.
- `configs/profiles/host-peer-ext.conf` and `host-peer.conf` state `CONFIG_WZ_TABLE_MEMORY_AT_OPEN=y`
  with the reason (the release keeps D12, the owner's ruling of 2026-11-27): their base is the
  zenoh-pico defconfig, which would otherwise hand them `on-use`.
- The resolver adds an option's `features` to the base list as it does for the engine axis
  (`wz_config.py` `engine_features`), and `wz_config.pico_reference` leaves `tables-on-use` out of
  the reference's switches as it leaves `os-host` out.
- Cargo: `wz-capi-pico` `tables-on-use = ["wz-capi-coop?/tables-on-use"]`, `wz-capi-coop`
  `tables-on-use = []`, which makes `RowPolicy` `OnUse` and compiles the on-use open (N3c). Unified
  into a graph it changes the moment of every session there, so the C library, a cdylib built by
  itself, is the only graph that names it, and the guards below read what it resolved to.

### 9.2 What keeps the release at D12

1. At the build: `crates/wz-capi-coop/src/lib.rs` asserts `RowPolicy::TAKEN` is `AtOpen` (N1,
   landed); N3c puts it under `#[cfg(not(feature = "tables-on-use"))]` beside its `AtFirstUse`
   twin, so no form builds whose policy disagrees with its moment.
2. At the resolution: `layer_c1nh_no_heap_after_open` (`scripts/run-ci.sh`) resolves
   `configs/profiles/host-peer-ext.conf` and, before it builds, fails by name when the resolved
   arguments name `tables-on-use` ("the release form resolved to on-use"), so a profile that lost
   its `at-open` line fails the lane rather than reading the on-use form's allocations against the
   D12 table. `wz_config.py --selftest` holds the same of both release profiles, and the reverse of
   the zenoh-pico defconfig.
3. The table: `deploy/no_heap_ratchet.json` and `no_heap_ratchet_gate.py` are not touched; the
   release's families stay locked at 0. The on-use form is a second reading (a leg
   `measure_on_use` of C1nh, the client built from the zenoh-pico defconfig) judged against a
   table of its own (`deploy/no_heap_on_use.json`, the same schema with a `form` key): its steady
   families (put, receive, delete) locked at 0 once their first use is past, its declaration
   families held to their allocations a round as a ratchet (6.1).
4. In the binary: the size cases of section 10.2 forbid in the D12 form a body only the on-use form
   links and require it in the on-use one, and the reverse for the open's lay-out.

### 9.3 The receive keeps its array

`OnUse`'s `Rows` is a flat `BoundedVec` over `FirstUse` (`RowsAt::flat`: a row reached by one
multiply-add, as on `Region`), and its `Ids` is `FixedIdMap` (a scan of an inline array): the
receive's lookups keep the shape of tables C and D (3.3, 3.4), and neither `Chunked` nor
`hashbrown` is in the on-use form. A push into an untaken column is one compare inlined and a call
of the out-of-line `take_memory` at the column's first value only (3.5).

## 10. The size cases and the storage policy each is built with

### 10.1 Today

`case_build` (`scripts/lib/capability_cost_gate.py`) builds a case with `--no-default-features
--features <its list>` (`None`: the crate's defaults; `pico-api-coop-nostd` reads the
`host-peer` profile's, `features_from`), under the limits and policies of its ABI's own preset as
environment (`case_limits`, `original_limits`: the original's defconfig, for the pico cases
zenoh-pico's). The policy follows from the features: `os-host` is the cooperative engine with
`wz-session-core/limits-lent-at-open` (`crates/wz-capi-pico/Cargo.toml`), whose tables are `Region`
unless a feature brings `wz-capi-coop/runtime-plan` (`peer`, `multicast-transport` through
`group-host`, `config-policy`), which makes them `Lent`; `wz-capi-c` runs the tokio engine
(`wz-capi-core`), whose session tables are the AP side's `Heap`.

| case | features | engine | policy | memory taken |
|------|----------|--------|--------|--------------|
| `pico-client`, `pico-client-small`, `pico-client-udp` | `PICO_BASE` (`os-host`), `+link-udp` | cooperative | `Region` | at open (D12) |
| `pico-client-coop-nostd` and its `-unstable`, `-local`, `-connectivity`, `-admin-space`, `-query`, `-local-queryable`, `-scout` | `os-host,link-udp` and the one capability each names | cooperative | `Region` | at open (D12) |
| `pico-peer-coop` | `os-host,link-udp,peer` | cooperative | `Lent` | at open (D12) |
| `pico-peer` | `PICO_BASE,peer` | cooperative | `Lent` | at open (D12) |
| `pico-default` | the crate's defaults (`peer`, `multicast-transport`, `config-policy`, ...) | cooperative | `Lent` | at open (D12) |
| `pico-api-coop-nostd` | the `host-peer` profile's (the peer role, zenoh-pico's multicast transport, the advanced plane, the unstable API, connectivity) | cooperative | `Lent` | at open (D12) |
| `capic-client` to `capic-default-lean` | `wz-capi-c`'s lists and defaults | tokio | `Heap` | as it grows, each limit bound at open (`binding_heap = "open"`) |

Every pico case is the D12 form, and so is every case of the size ledger (C1cs:
`pico-client-coop-nostd` its `base_case`, `pico-peer-coop`, `pico-api-coop-nostd`).

### 10.2 Both forms in the ledger

- Every case above stays as it is: the D12 form, the release's, its budget, ceiling row and history
  valid as they are; `pico-api-coop-nostd` is the release library's own like-for-like.
- One case is added with N3c, `pico-client-coop-nostd-on-use`: `pico-client-coop-nostd`'s package,
  profile, configuration files and pins, its features `os-host,link-udp,tables-on-use`. It is the
  zenoh-pico preset's client in the form that preset ships, divided by the same zenoh-pico reference
  as its D12 twin (the moment is no capability). It has no budget until its first reading, which the
  gate's own rule fails `--check` with and `--measure` prints, and its row of
  `deploy/pico_host_ceiling.json` is set from that reading.
- Presence and absence: a body only the on-use form links (`wz_session_core::on_use::take_rows`,
  out of line by `#[inline(never)]`) is REQUIRED of the on-use case and FORBIDDEN in every D12 pico
  case; a body of the D12 open's lay-out (`wz_capi_coop::region::StateRegion::place` for the
  client form) is REQUIRED of `pico-client-coop-nostd` and FORBIDDEN in the on-use case. Each is the
  other's live control, as the gate's PRESENCE rule asks.
- The size ledger: the on-use case joins `cases` with a row for each area, `base_case` staying
  `pico-client-coop-nostd`, so `--per-feature` steps from the D12 client to the on-use one by the
  one feature `tables-on-use` and prints what the moment costs each area on each side, the measured
  form of section 4's estimates. The gate's selftest names its set of cases
  (`size_ledger_gate.py`, the assertion on `{"pico-client-coop-nostd", "pico-peer-coop",
  "pico-api-coop-nostd"}`) and moves with it.
- The statement: a library states the form it is, so `wz_config.conformance_statement` includes
  the axis's value, and the statement case of the pico ABI gains its on-use twin.
- A peer twin (`pico-peer-coop-on-use`) waits for N3c to cover `runtime-plan`, where a listening
  session's faces come and go: on `OnUse` each face's tables are counted at its attach (N3b's
  constructors), with no pool lent at open.

## 11. What N3c has to give a home to

N3b ends where the session core's tables end. N3c is the open of the cooperative engine on
`OnUse`, and the open places far more in the one block it reserves than those tables: "no plan, no
region, no lender, no arena" (3.1) means each tenant below gets a home of its own before `arena.rs`
and `region.rs` leave the form. Read off `lend_session` and `assemble` at `6cded4d63b`
(`crates/wz-capi-coop/src/engine.rs:898`, `:6672`); line references in this section are to that
tree.

| tenant | today | the on-use form |
|--------|-------|-----------------|
| the registry and its rows | `RegistryRegion`, a field of `StateRegion` placed by the region's walk (`engine/registry/placed.rs`, bound at `engine.rs:1126`), or `Registry::new` over the arena (`runtime-plan`) | a third form made by value: `App` by `SlotObserverOf::counted`, each `FaceTables` by `PeerTables::count_rows` and `Requesters::counted` (N3b), the sets a `BoundedVec::<FaceTables, MAX_FACE_SETS, OnUse>::counted` |
| the key arena | a `KeySpace` of the region (`StateRegion::place`, `engine.rs:974`) or of the arena (`lend.keys`), then `SessionState::keys` | a `KeyBudget` in the boxed state; every reader of `session.keys` changes with it: `keys_locked` (`engine.rs:1683`, `:2662`, `KeysLocked::vouched` over a `KeySpace`), `key_counts` (`:7353`), `key_arena`, which answers the port's `SessionKeys` (`:11052`), `Round::reads_keys_in(KeySpace)` (`crates/wz-session-core/src/round.rs:1564`), and the registry's `keys: KeySpace` parameters (`engine/registry.rs:263`, `:811`, `:2253`, `:2269`, `:2293`) |
| the region's other places (`StatePlaces`, `engine/state_places.rs:82`) | the registry's and the Router's lend cells, the round and its rows, the gets' and the queries' planes, the face plane, the rooms' places, the plain tables' rows (`StatePlaces::tables`, `rooms`, `gets`, `round`, `steps`, `queries`, `faces`, `engine.rs:1002` to `:1085`, `:6801`) | a value each in the boxed state, the round's rows and the plain tables counted |
| the transport's tables | the links' buffers and cells, the reassembly chains and the endpoints' texts, lent by the plan (`plan.transport().lent_from`) and handed to the stack (`lend_buffers`, `lend_cells`, `write_into`) | N3d: a link's buffers taken at its dial (`heap_head`), a chain's buffer at its first fragment, the endpoints' texts by value |
| the runtime, the engine and the rooms | `runtime_place`, `engine_place` and `LinkRooms::init_at` in the arena (`engine.rs:6733`) | boxed: the engine (`Shared::<CoopEngine>`), the runtime's task and timer tables, the rooms |
| the ABI's places | the handle place, the entity places and the lodgings, held after every table (`ArenaPlan::holding`) | N4: each object from the allocator, counted against its kind |

The order that builds at each step:

1. The registry and the key arena out of the region: an on-use twin of `StateRegion` whose
   registry is made by value and whose keys are a `KeyBudget`, every other tenant still the
   arena's; `RowPolicy` is `OnUse` under `tables-on-use` and its moment assertion `AtFirstUse`
   (9.2, 1). The size case of section 10 is not read yet: the region's other places and the arena
   are still linked.
2. The region's other places into the boxed state; `region.rs` leaves the form.
3. N3d, then the runtime, the engine and the rooms boxed; `arena.rs` leaves the form and the
   size case reads group A's figure.
4. N4, then N5: the switch is declared once the form it selects builds.

A table that answers whether it has room before the push that would take its memory cannot take
the memory when it answers (`FinalStaging::has_room`, `&self`): the query dispatch asks before the
queryables run and owes the `Final` after (`crates/wz-session-core/src/query/in_place.rs:216`,
`:234`), so on `OnUse` a `Final` the allocator refused at the table's first row would have been
counted as a refused request after the callbacks ran, with no `Final` sent. N3b's last commit makes
the dispatch ask `FinalStaging::make_room`, which takes the row on a first-use policy and answers
as `has_room` on every other. The engine's own checks of room before a push are read the same way
when N3c names `OnUse`.
