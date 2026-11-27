# Migration lane heap-native: the storage policy is the storage shape

Status: design of the lane, with its first step (N0, one table contract held on every policy)
landed beside it. Nothing here was built or measured by this lane: a byte figure is either **read**
from the size ledger's explain document or from `nm -S` of the case's library named below, or an
**estimate** read off the code; a count of instructions is a reading of the code, not a run. Line
references are to the tree this lane branched from (`568c90f500`).

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
| the session's state | one `z_malloc(sizeof(_z_session_t))` at open, in a counted handle | `vendor/zenoh-pico/src/api/api.c:896`, `:908` |
| the session's declared keys | `_z_resource_slist_t *_local_resources`, a list; each key a copy of its own length | `vendor/zenoh-pico/include/zenoh-pico/net/session.h:148`, `vendor/zenoh-pico/src/session/resource.c:40`, `:104`, `:172` |
| a peer's declared keys | `_remote_resources`, a list per peer | `vendor/zenoh-pico/include/zenoh-pico/transport/transport.h:54` |
| subscribers | `_z_subscription_rc_slist_t *_subscriptions`, a counted struct per declaration pushed on a list | `net/session.h:159`, `vendor/zenoh-pico/src/session/subscription.c:169`, `:179` |
| tokens, pending liveliness gets | `_z_*_intmap_t`, a map of lists | `net/session.h:167-171` |
| queryables, pending queries, interests, a peer's declarations | lists | `net/session.h:177-189` |
| a transport's buffers | one write and one read buffer of the batch, at the transport's open | `vendor/zenoh-pico/src/transport/unicast/transport.c:51-52` |
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
| **`OnUse`** (new) | the allocator | at a table's first row, a key's making, an object's making | the table | its count's rows in one allocation at its first row, never moved | one allocation of its own, counted against the session's key budget | `FixedIdMap` | the cooperative engine, `alloc-on-use` |
| `Heap` | the allocator | as it grows | the table | `Chunked`, 32 rows at a time | `String` | `GrowableIdMap` (`hashbrown`) | the AP side (the tokio engine, `std`) |

`OnUse` and `Heap` take the same memory and are two shapes because they serve two scales. The
cooperative engine's tables are counted (each limit binds at the open on the heap profile too,
`binding_heap = "open"` in `deploy/wz-config.toml`), small, and read in place on the receive, so
a row never moves and is reached by one multiply-add. The AP side's are advisory and router-sized,
so its rows grow by chunks and its peer ids hash. Neither takes the other's shape: `Chunked` costs
the receive a chunk step per row reached and `hashbrown` costs a few kilobytes of code per value
type (3.3, 3.4).

The cooperative engine's `RowPolicy` becomes the resolution of those facts and not of
`runtime-plan` alone: with an allocator and `alloc-on-use`, `OnUse`; otherwise `Region` or
`Lent` as today; `alloc-on-use` without an allocator is refused by name (`compile_error!`). The
moment the memory is taken is an axis of its own, apart from `Profile`, as `session-row.md`
section 2 keeps where an engine row comes from apart from where a session lays its tables.

### 2.2 `OnUse`, type by type

| associated item | `OnUse` | why |
|-----------------|---------|-----|
| `ENFORCES_CAPACITY` | `true` | the counts bind, as on `Region` and `Lent` |
| `LENT_AT_OPEN` | `false`; its one use, `row_may_lie_in` (`session_tables.rs:4085`), reads a fact of its own instead (N1): a row lies apart from the table and never moves while it stands, true of `Region`, `Lent` and `OnUse` | the constant answers two questions today |
| `Seq<T, N>`, `Rows<T, N>` | `FirstUse<T>`: a column made with its count and no memory, which takes all its count's rows in one allocation at its first push, by one untyped body for every row type (as `add_free_lent_slot` is), and never grows; a push past the count, or one the allocator refuses, is `CapacityFull` with the value handed back | the rows never move, so every holder of a row's place (`KeyexprHead`, a pinned row read in place) is sound as on `Lent`; a table never used takes nothing |
| `Text<N>` | `heapless::String<N>` | a working text is on the stack, as on `Lent` |
| `Key`, `Keys` | `HeapKey`: one allocation holding the count of its holders, its length and its bytes; `KeyBudget`: the bytes the session's key budget has left and the bound on a key's length | a key is never cut short; a key past the bound is `TooLong`, one past the budget or refused by the allocator `NoRoom`, nothing taken, as today; a clone is one more holder and never fails |
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
key lives until its last holder, and its bytes go back to the budget then.

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
|------|------|-------|---------------------------:|-----------|-----------------|
| **N0 (landed with this note)** | the table contract of 2.3 as one body run on every policy | `crates/wz-session-core/src/slot_map/tests.rs` | 0 | 0 | 0 |
| N1 | the fact "a row lies apart and never moves" in `Storage`, read by `row_may_lie_in`; `RowPolicy` resolved from the allocator, the moment and `runtime-plan`, `alloc-on-use` refused without an allocator | `bounded.rs`, `session_tables.rs`, `crates/wz-capi-coop/src/lib.rs`, its `Cargo.toml` | 0 | 0 | 0 |
| N2 | `OnUse`, `FirstUse`, `HeapKey`, `KeyBudget`; the N0 bodies and the key contract run on it | `bounded.rs`, `slot_map.rs`, `key_arena.rs` or a module beside it | 0 (nothing in the case names it) | 0 | 0 |
| N3 | the cooperative engine on `OnUse` under `alloc-on-use`: 3.1, 3.2, 3.3, 3.5, 3.6 | `crates/wz-capi-coop` (`engine.rs`, `registry.rs`; `arena.rs` and `region.rs` not compiled in the form), `crates/wz-runtime-coop` (`link_cells.rs`, `kept.rs`, `link_storage.rs`) | -5,500 to -10,200 | 0 to -36 (3.2, 3.6); +3 at worst (3.5) | section 5 |
| N4 | the doors: 3.7 | `crates/wz-capi-pico` (`process_pool.rs`, `object_slot.rs`, `bytes.rs`) | -2,000 to -3,000 | 0; the put's to be read | -0 to -8 KiB a pair |
| N5 | the preset's choice: a policy key for the moment (`open` or `first-use`) and the ratchet's reading of each form | `deploy/wz-config.toml` and what it generates, `configs/zenoh-pico_defconfig`, `deploy/no_heap_ratchet.json` | 0 | 0 | 0 |

N3 and N4 together: **about -7,500 to -13,200**, against a gap of 32,525 (the case at 203,025)
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

The ruling of 2026-11-23 (win in the form with no allocation after open first) is (a) until the
owner says otherwise. N0 to N2 are the same under all three; N3 and N4 build the form; N5 is where
the choice is written.

### 6.2 Each table allocated at open (weighed, not chosen)

Inside D12, each table could take its rows from the allocator at the open instead of from one
planned arena. It replaces one reservation and its lender with one allocation per table and a
refusal arm for each, while the counts the plan resolves stay; the region already took the
planning out of the registry's lay-out. Expected -500 to +500 bytes, the same resident memory as
`base-rss.md` L3: not a lever.

## 7. What N0 tests, and what turns each red

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

## 8. What the main session runs

- N0: `cargo test -p wz-session-core --lib slot_map::tests`: 46 tests with the crate's default
  features, 41 before; a build of the crate without `alloc` compiles neither `Heap` test.
- For N3 and N4, on each step: the size ledger's explain document of `pico-client-coop-nostd`
  (the total and the sessions, doors and driver areas against section 4), the perf matrix's arm W
  receive Ir (about 3,066) and put Ir, `base-rss.md` M1 on the pubsub pair (the anonymous, `[heap]`
  and `[stack]` rows of section 5), and Layer C1nh's reading under `alloc-on-use` (which families
  read above 0, against 6.1).
