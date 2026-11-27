# Migration lane heap-native: the storage policy is the storage shape

Status: design of the lane and its first steps. Landed on the lane's branch: N0 (one table
contract held on every policy), N1 (where a policy's rows lie and when its tables take their
memory are facts of `Storage`), N2 (the policy `OnUse`, its column `FirstUse` and its keys
`HeapKey` over a `KeyBudget`, held to the same contract) and N3a (the session's tables made
counted on `OnUse`), then N3b (every other table a face and the application hold, counted on
`OnUse`, and the two places where a table of that policy is asked for room before the push that
takes its memory), then the first step of N3c (section 11, 1): the cooperative engine on `OnUse`
under its feature `tables-on-use`, its registry made by value and its keys counted against a
`KeyBudget`, guarded by the session's lock as the key arena is; then its second step (section
11, 2): the places of the state's own values and the key budget in a state of the session's own,
one allocation the open takes from the allocator apart from its arena, `region.rs` no longer in
the form; and that step's second half: the state's plain tables and the round's tables counted on
`OnUse`, their policy the one the engine's calls name, each refusal of a first row answered as a
value (section 11, the audit); then the first part of its third step (section 11, 3a): the
engine and the faces' rooms of an on-use session each in an allocation of its own, the engine's
claimed before anything is reserved and keeping the arena's memory by a count as its place in the
arena did. The owner's ruling of 2026-11-27 chose the form of section 6 (c), per preset: the rest
of the cooperative engine's on-use form (3b to 3d, N3e), the doors' (N4) and the switch with its
guards (section 9) are designed here and not written yet, because a switch that cannot be built is
not declared; section 11 reads what N3c has to give a home to, and why it is the next step and not
a part of N3b, and 11.1 reads why the zenoh-pico preset's own library is the form laid out from
its config (`runtime-plan`), which the on-use form does not reach yet, so the switch waits for
that form's first step (11.2). Then R1 began (11.1): the policy of the session's tables is named
once, by the engine crate's build script, as the cfg of its name (`wz_lent`, `wz_on_use`), so every
item reads the policy apart from where its counts come from (`runtime-plan`) (R1, step 0); and
`tables-on-use` takes the tables on use in a build laid out from its config too, but where the
session takes faces beside its dial role's (R1a). The preset's own library takes such faces
(`peer`, `multicast-transport`), so it is the lent form until R1b, and the switch waits for R1b
(11.2). R1b began with the session core: a peer's tokens split off on `OnUse` as on `Lent`
(`PeerTokens::split_off`, 7.10); what the rest of R1b has to decide first, the bound of the owed
table where no pool bounds the tokens, is read in 11.1 (R1b, 3); then the owed tokens as a relation of tokens keyed by face
and id, its bound kept by the faces' admission (7.11), which left the on-use split reached by no
form, so it was dropped; and then R1b's switch: the listening and grouped forms' registry counted
(its table of sets, its index of held sets, the sets of the faces that come), and
`tables-on-use` naming `OnUse` whatever faces the session takes (7.12). 11.3 lays out the commit
of the switch and its size case. Nothing here was built or
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
| **N3c, step 3a (landed on the lane: `f104d31bc8`, `81cebf0f4c`, `b0afa53110`)** | the engine and the faces' rooms of an on-use session each in an allocation of its own, the engine's claimed before anything is reserved and keeping the arena's memory by a count (11, 3a) | `crates/wz-runtime-coop/src/kept.rs` (`SharedClaim`), `crates/wz-capi-coop` (`engine.rs` `assemble`, `engine_of`, `lay_out_open`; `engine/state_places.rs` `OwnPlaced`; `arena.rs`) | the on-use case +100 to +300 (the claim and the rooms' block, until 3d); D12 0 | 0 | the on-use arena smaller by the engine's and the rooms' bytes, the same bytes from the allocator |
| N3d (11, 3c) | link memory on the heap arm alone (3.6), its source a type the engine names, not a feature | `crates/wz-runtime-coop` (`link_cells.rs` `heap_head`, `kept.rs`, `link_storage.rs`) | -1,000 to -2,000 | 0 to -30 | section 5 |
| N3e | a key held apart from every row (an object outside the lock: `KeyRef::hold_apart`, `KeysLocked::adopt`, `SampleView::keyexpr_held`) as a `HeapKey` clone taken and let go of under the lock, read by its text outside it | `key_arena.rs` beside `on_use.rs`, `sink.rs`, the engine's object paths | -200 to +200 | 0 | 0 |
| N4 | the doors: 3.7 | `crates/wz-capi-pico` (`process_pool.rs`, `object_slot.rs`, `bytes.rs`) | -2,000 to -3,000 | 0; the put's to be read | -0 to -8 KiB a pair |
| **R1, step 0 (landed on the lane: `6b6041bf09`)** | the policy of the session's tables stated once, by `build.rs` (`TablePolicy`), as the cfg of its name (`wz_lent`, `wz_on_use`): an item that differs by the policy reads its name, one that differs by where the counts come from reads `runtime-plan` (7.9) | `crates/wz-capi-coop` (`build.rs`, `lib.rs`, `arena.rs`, `engine.rs`, `engine/{registry,registry/held,state_places,query,decl_watch}.rs`, `round.rs`, the tests) | 0 (every predicate is the one it replaced) | 0 | 0 |
| **R1a (landed on the lane: `01cf14693c`)** | `tables-on-use` names `OnUse` in a build laid out from its config too, but where the session takes faces beside its dial role's (`listen`, `group`); its registry, keys, state and plain tables are the client form's, their counts the config's (7.9) | `crates/wz-capi-coop` (`build.rs`, `lib.rs`, `tests/on_use.rs`), `scripts/lib/nondefault-tests-gate.sh` | no case builds the planned on-use form yet (`config-policy` beside `wz-capi-coop/tables-on-use`); D12 0 | 0 | as N3c's client form |
| **R1b, step 1 (landed on the lane: `1063768725`; dropped by `12e8da2c40`)** | the owed tokens' split on `OnUse`: `FixedIdMap::split_off` moves a fixed table's rows whole and keeps its refusals; `PeerTokens::<OnUse>::split_off` hands a face's tokens over as a table of their own, their keys still counted against the session's budget, and `None` for a table of no token (11.1, R1b, 3; 7.10). The relation of step 2 moves tokens, not tables, so both splits and their tests were dropped | `crates/wz-session-core` (`id_map.rs`, `declare/liveliness_subscriber.rs`) | 0 | 0 | 0 |
| **R1b, step 2 (landed on the lane: `8988bd43f3`, `3963ecf41d`)** | the tokens of the faces that went owed on `OnUse` as a relation of tokens keyed by face and id (`OwedTokens`, `FaceToken`), its bound kept by the faces' admission (`admits_face`); the engine names both forms by one type (`engine/registry/owed.rs`, `Owed`) (7.11) | `crates/wz-session-core` (`declare/liveliness_subscriber.rs`, `slot_observer.rs`), `crates/wz-capi-coop` (`engine/registry.rs`, `registry/{owed,adding}.rs`) | 0 (the lent arm is the code it replaced) | 0 | 0 |
| **R1b, step 3 (landed on the lane: `d269055bd4`)** | the listening and grouped forms' registry on `OnUse`: `Registry::counted` generic over `Holders` and over the plan's `GetTables` and `FacePeers`, `ManyHolders` of `RowPolicy` with `Holders::counted`, `SpareSets`' on-use form (a set built at a place's first face, counted in its row), the rooms' places at `MAX_FACE_SETS` in the state, the plan's rows of the held index and the owed tokens the lent form's alone; `build.rs` names `OnUse` whatever faces the session takes (7.12) | `crates/wz-capi-coop` (`build.rs`, `lib.rs`, `arena.rs`, `engine.rs`, `engine/registry.rs`, `registry/{counted,held,adding}.rs`, `tests/{arena,on_use}.rs`), `scripts/lib/nondefault-tests-gate.sh` | 0 for every D12 case (no D12 build names `tables-on-use`); no case builds the listening on-use form until N5 | 0 | the on-use listening session: its sets' rows from the allocator at the open instead of the arena |
| R2 to R4 | the zenoh-pico preset's own library (`peer`, `multicast-transport`, so `runtime-plan`) on use: the listening and grouped forms' holders, sets and owed tokens on use and `build.rs`'s `!takes_faces` dropped (R1b, landed), the admission and the direct faces' slots per face (R2), the listening and grouped stacks' memory (R3), its arena out (R4) (11.1) | `crates/wz-capi-coop` (`lib.rs`, `engine.rs`, `engine/registry/counted.rs`, `engine/state_places.rs`, `engine/direct.rs`), `crates/wz-runtime-coop` (the stacks' ports and groups) | the preset's library, read once N5 resolves it so | 0 | section 5 |
| N5, after R2 to R4 (11.2, 11.3) | the switch and its guards (section 9): the `table-memory` axis, the zenoh-pico defconfig's `on-use`, the release profiles' `at-open`, the size cases of both forms (section 10) and C1nh's second reading | `deploy/wz-config.toml` and what it generates, `configs/zenoh-pico_defconfig`, `configs/profiles/host-peer-ext.conf`, `host-peer.conf`, `scripts/lib/capability_cost_gate.py`, `deploy/size_ledger.json`, `deploy/pico_host_ceiling.json`, `scripts/run-ci.sh` (C1nh) | 0 for the release form; the on-use case reads N3 and N4's figures | 0 | 0 |

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

### 7.5 N3c, step 1

- `on_use::tests` in the session core, four more, two of them in a build with debug assertions
  alone: `a_value_written_in_place_takes_the_rows_and_holds_the_count` (red if
  `FirstUse::push_in_place` writes before it makes its room, `room_for`);
  `a_key_let_go_of_outside_its_budgets_lock_fails` and
  `a_key_let_go_of_beside_the_thread_that_holds_its_budgets_lock_fails` (red if `HeapKey`'s drop
  does not ask its budget's guard, or the guard reads the owner's mark and not its answer for the
  calling thread); `keys_under_their_budgets_lock_or_with_the_owner_alone_pass`, their control (red
  if the guard fails a key touched under the lock, or a budget its owner holds alone is checked).
- With `tables-on-use`, every test whose path names `on_use`:
  `region::tests::an_on_use_region_holds_the_sessions_key_budget` (red if `StateRegion::place`
  writes a budget of other bytes than the limits' `KEY_ARENA_BYTES`, or hands back a handle of no
  budget; step 2 moves it with the budget, 7.6); `engine::registry::counted::tests::an_on_use_registry_holds_the_plans_rows_and_has_taken_none`
  (red if an application's table is made of the build's bound, `SlotMap::new` for `counted`, or
  takes its rows when made, if the registry holds no set, or, without `queryable`, if the set's
  peer tables are not counted); `tests::on_use::`, three: a declaration's key counted against the
  budget as its arena block and given back with its last hold (red if the budget's bytes are not
  the limits', or a key is not counted or not given back); an object's key a copy of its own, held,
  shared and let go of through the engine's `SessionKeys` and refused past the session's
  `MAX_KEYEXPR_BYTES` (red if a hold is counted against the budget, is not a copy, or is kept past
  the bound); and a subscriber declared after the open told to the router and handed what it pushes
  (red if the subscribers' table refuses its first row).
- At the build: `crates/wz-capi-coop/src/lib.rs` asserts `RowPolicy::TAKEN` is `AtOpen` outside
  the on-use form and `AtFirstUse` in it (9.2, 1). Beside `runtime-plan` the feature yields (9.1):
  every item of the on-use form outside `region.rs` (which a build with `runtime-plan` does not
  compile) reads the feature beside `not(feature = "runtime-plan")`, and its twin the negation of
  both, so a build of both, `--all-features` among them, is the form that plans at the open, item
  for item. `form_precedence_tests::a_build_of_both_forms_lays_its_tables_out_at_the_open`, in that
  build alone, holds it (red if a build of both names `OnUse`, or any policy but `Lent`, as its
  `RowPolicy`, the `runtime-plan` arm of `lib.rs` read only without `tables-on-use`).
  What holds the key budget asserts it has no drop, which that holder's drop would leave undone
  (`region.rs` at this step, `engine/state_places.rs` from step 2).
- Not tested: the open refused when the allocator has no room for the dial face's set
  (`ArenaRefused::NoMemory`); only a refusing allocator reaches it.

### 7.6 N3c, step 2

- With `tables-on-use`, the tests whose path names `on_use` are six, one of step 1's replaced and
  one added: `engine::state_places::tests::an_on_use_state_holds_the_sessions_key_budget_and_its_places`,
  in place of the region's (red if `OwnState::place` writes a budget of other bytes than the
  limits' `KEY_ARENA_BYTES` or hands back a handle of no budget, or if `OwnState::places_at`
  projects anywhere but the state); and
  `tests::on_use::an_on_use_open_asks_its_memory_for_the_arena_alone_and_holds_its_state_apart`
  (red if `lend_session` lays the state at the head of the arena's block again,
  `SessionArena::reserve_after`, which asks the session's memory for the state's span too, or, in
  a build with `query`, `queryable` or `connectivity`, if a plane is written anywhere but the
  state).
- `tests::arena::a_sessions_planes_lie_in_its_own_arena` reads `CoopEngine::state_holds`
  (`region_holds` before) in both forms without `runtime-plan`: the region's in the crate's
  default suite, the state's in an on-use build.
- At the build: `region.rs`, `tests/region.rs`, `SessionArena::reserve_after` and its test
  compile only without both features; `SessionArena::reserve` is the on-use form's too. The
  engine names the state by `StateLayout` and its holder by `StateHold` (`StateRegion` in a
  `RegionBlock`, or `OwnState` in an `OwnBlock`), so the region's form calls the bodies it
  called before.
- Not tested: the open refused when the allocator has no room for the state
  (`OwnBlock::take`, `ArenaRefused::NoMemory`); only a refusing allocator reaches it.

### 7.7 N3c, step 2, second half

- The policy: the session core's planes and round read the policy of their tables from the
  engine's calls, `RoundCalls::TablePolicy` (`crates/wz-session-core/src/round.rs`).
  `EndedLegs<P>` and `FinalHolds<P>` (`HeldFinals<P>`, `RefusedFinals<P>`) take it as a parameter;
  `LegRows`, the get plane's `HeldReplies<u64, _>` and `RoundRows` (whose records are
  `RecordForm::Records<T, P>`) read it. The engine names it once, `StatePolicy`
  (`crates/wz-capi-coop/src/lib.rs`): `Lent` in every form but the on-use one, where the open
  lends or the region places those rows as before, and `OnUse` there; its note of each pending
  leg (`Rows`, `engine.rs`) follows it. In the on-use form the state's places keep none of those
  rows: `PlacedTables::counted` and `RoundRows::counted` count each table from what the plan
  resolved, and each takes its rows at its first row.
- The two defects. `EndedLegs::note` pushes where nothing can answer a refusal (the drop of the
  leg's entry), and on `OnUse` its first push asked the allocator there: the end was lost and the
  leg's callback never let go of. `GetPlane::open_leg` now has the ends take their rows before it
  keeps a leg, and a refusal is `None`, which the engine answers as a get no row holds
  (`hold_leg`'s `LegHeld::NoRoom`, a liveliness snapshot's `LegTurn::Skipped`); the push left in
  `note` can no longer be refused (its rows taken at the open and never given back, the ends never
  more than the legs' rows, which `GetPlane::init_at` checks in a debug build), and its debug
  assertion states that. `FinalHolds::admit` dropped a refusal its list could not note
  (`let _ =`): it now answers `Admitted` (`Held`, `Refused`, `Unnoted`), and on a first-use
  policy has the list take its rows before it asks the first hold (`rows_for_refusals`), so a
  refusal after one request was held is always noted; `Unnoted` (the allocator refused the list's
  rows, or the list is past its count) is counted and begins no call (`QueryPlane::admit_call`),
  and with nothing noted its dispatch owes its Final as one that reached no queryable.
- The round: an offer that found room by count has its records' and its callbacks' rows taken
  (`Round::take_rows`) before it writes, and a refusal of the allocator is counted as a record with
  a part that found no place (`RoundCounts::unplaced`), not as a record the gate let through past
  its room. Each arm added reads `Storage::TAKEN` as a constant and folds away on `Lent` and
  `Region`.
- Tests, in the session core's unit tests, which run on an allocator that refuses every
  allocation of a thread that asks it to (`crates/wz-session-core/src/test_heap.rs`, `refused`):
  - `get_plane::tests::a_leg_whose_ends_rows_the_heap_refuses_is_refused_at_its_open` (red if
    `open_leg` keeps a leg before the ends took their rows, `EndedLegs::make_room` left out) and
    `a_legs_end_finds_the_row_its_open_had_taken_whatever_the_heap_holds` (red the same way: the
    end then asks the heap at the entry's drop); `an_end_past_the_rows_is_a_defect` reads the
    assertion's new words.
  - `query_plane::tests::a_refusal_with_no_row_to_be_noted_in_is_unnoted_and_owes_its_final`
    (count 0; red if `admit` answers a refusal it could not note as noted),
    `a_refusal_finds_the_row_the_first_hold_had_taken_whatever_the_heap_holds` (red if
    `rows_for_refusals` is left out of `admit`),
    `a_request_whose_refusals_rows_the_heap_refuses_is_refused_unnoted` (red if a request is held
    while its refusal could not be noted, or the heap's refusal is answered as noted) and
    `a_query_refused_unnoted_begins_no_call_and_is_counted` (red if `admit_call` begins a call for
    `Unnoted` or counts none); the three tests that read `admit` read `Admitted`.
  - `round::tests::a_round_counted_on_use_takes_its_rows_at_its_first_record` (red if
    `RoundRows::counted` makes tables that take their rows when made, or holds the build's bound in
    place of the count) and `a_record_whose_rows_the_heap_refuses_is_counted_unplaced` (red if an
    offer writes before `Round::take_rows`: the record is then lost uncounted, or a debug build
    stops at the round's check of its room).
  - `on_use::tests::what_the_heap_has_no_room_for_is_handed_back_and_takes_nothing` (red if a
    refused `take_memory` is answered as rows taken, or a refused key's bytes stay counted).
  - In the engine's on-use form with `query` or `queryable`,
    `engine::state_places::tests::the_plain_tables_on_use_hold_the_plans_counts_and_no_row` (red
    if a table is counted with the build's bound in place of the plan's count, or takes its rows
    when made); the region's test of its places compiles in the region's form alone.
- Not tested: the engine's answers to a leg refused at its open and to an unnoted query on
  `OnUse` end to end (the session core's tests reach both values; the engine's arms are the ones a
  full table takes); and the round in the engine's on-use form, which only a build with
  `WZ_COOP_VALUE_LOCKS=off` or an image without host locks compiles (`wz_round`).
- D12: every arm added reads the policy's `TAKEN` as a constant or is a type the D12 forms name
  as `Lent`, as before; `admit`'s answer is an enum whose two refusals take one arm in
  `admit_call`. The D12 cases' bytes are not expected to move: C1cs's reading of them is the check,
  and a move there is a finding.

### 7.8 N3c, step 3a

- In `wz-runtime-coop`'s `kept::tests`, with its default features, two:
  `a_claimed_value_keeps_the_memory_it_was_made_with_until_its_last_holder` (red if
  `SharedClaim::made_with` writes the value elsewhere than the claim's memory, takes no count of
  the memory it is handed, or the value's last holder gives none back: `Shared::last_boxed` in
  place of `last_kept_boxed` in `SharedClaim::try_new`) and
  `a_claim_let_go_of_before_its_value_is_made_drops_no_value` (red if the claim's drop drops the
  value it never held; its CONTROL, a made value, is dropped by its last holder).
- With `tables-on-use`, `tests::on_use::an_on_use_engine_and_its_rooms_lie_apart_from_its_arena`
  (red if the open writes the engine at a place the arena lends, `SessionArena::engine_place` and
  `Shared::placed_with` in `CoopEngine::engine_of`, or the rooms, `Arena::vacant` in
  `CoopEngine::assemble`), and `tests::on_use::an_on_use_plan_lays_out_no_place_for_the_engine_or_the_rooms`
  (red if `lay_out_open` lays the engine's place, `ArenaPlan::lay_engine`, or the rooms',
  `ArenaPlan::lay_rooms`, in the on-use form; its CONTROL rows, the runtime's span and the count
  the arena is kept by, are laid out). `tests::arena::a_sessions_engine_lies_in_its_own_arena_and_is_reached_until_it_closes`
  reads where the engine lies in the D12 forms alone and its row in every form: in those forms it
  is the live control of the accessor the on-use test reads.
- At the build: `EnginePlace` and `SessionArena::engine_place` compile outside the on-use form
  alone, and `lay_out_open` lays the engine's and the rooms' places out there alone, so the on-use
  arena is smaller by both and
  `tests::on_use::an_on_use_open_asks_its_memory_for_the_arena_alone_and_holds_its_state_apart`
  reads the plan's bytes as it did. The rooms have one owner in the form, `OwnPlaced`
  (`engine/state_places.rs`, `Core::rooms`), which drops them where they lie and gives their
  allocation back after: no field is held for its drop alone. What only the arena's rooms read
  compiles where the arena holds them: `OpenHolds::rooms`, `link_rooms_bytes`, and
  `SessionArena::arena_mut` outside the tests (the on-use open lends the arena nothing past its
  lender's tables); `tests::arena::the_plan_lays_out_the_faces_rooms_and_their_places` reads
  the rooms' row in the D12 forms and its absence in the on-use one.
- Not tested: the open refused when the allocator has no room for the engine
  (`ArenaRefused::NoMemory` with the engine's bytes, before anything is reserved) or for the
  rooms (`OwnPlaced::vacant`); only a refusing allocator reaches either.
- D12: every item added reads `all(feature = "tables-on-use", not(feature = "runtime-plan"))` or
  is the claim, which no D12 build instantiates; `SessionArena::keep` is `pub(crate)` with the
  body it had. The D12 cases' bytes are not expected to move: C1cs's reading of them is the check,
  and a move there is a finding.

### 7.9 R1, step 0 and R1a

- Step 0 (`6b6041bf09`) renames terms: `crates/wz-capi-coop/build.rs` states the policy
  (`TablePolicy`) and emits `wz_lent` or `wz_on_use`; every item that read `runtime-plan` for a
  table the open lends from its arena reads `wz_lent`, every item spelled `tables-on-use` beside
  `not(runtime-plan)` reads `wz_on_use`, and the items of the config's plan (`OpenFrom::Config`,
  `PlanFrom::Config`, `OpenPlan`, the listed rows, `ArenaRegion::lay_out_on`, the opens by config,
  `resolve_policy`) keep `runtime-plan`. Under step 0's policy (`runtime-plan` chooses `Lent`)
  each predicate is the one it replaced: no test is added and none moves.
- R1a (`01cf14693c`): `table_policy` names `OnUse` wherever `tables-on-use` is named but where
  `listen` or `group` is. Tests:
  `form_precedence_tests::a_build_of_both_forms_takes_its_tables_memory_on_use`, in a build of
  `runtime-plan,tables-on-use` (red if `table_policy` lets `runtime-plan` choose `Lent` again);
  `form_precedence_tests::a_build_of_both_that_takes_faces_lends_its_tables_at_the_open`, in a build
  of both beside `listen` or `group`, `--all-features` among them (red if `OnUse` is named while
  the faces' sets are lent); and
  `tests::on_use::an_on_use_plan_from_the_config_lays_out_no_row_of_the_tables_it_counts`, in both
  on-use forms (red if a row of a counted table is put by `feature = "runtime-plan"` rather than by
  `wz_lent`, `ArenaPlan::put_entities` the first of them; its CONTROL rows, the endpoints' texts and
  the links' receive buffers, are laid out). Every other on-use test runs in the planned form too:
  the tests open by config whatever the build (`Engine::open`).
  `tests::arena::a_build_that_puts_nothing_in_the_round_lays_out_none_of_it` reads the lent form
  alone, its CONTROL (the Router's lend) a lent row.
- The gate: `scripts/lib/nondefault-tests-gate.sh` gains the leg `runtime-plan,tables-on-use|on_use`.
- D12: no D12 build names `tables-on-use`, so no predicate of one moves; `--all-features` stays the
  lent form (it names `listen` and `group`). C1cs's readings are not expected to move.
- Not tested: the C library in the planned on-use form (`config-policy` beside
  `wz-capi-coop/tables-on-use`), which no case builds yet.

### 7.10 R1b, step 1

- `id_map::tests::a_split_off_fixed_table_takes_its_rows_whole`: two ids bound in a table of two,
  a third refused and counted (the CONTROL), the split holding both in the order bound with no
  refusal, the table it came from holding none, its refusal kept, and binding again. Red if
  `FixedIdMap::split_off` leaves the rows behind (`core::mem::take` of the rows dropped) or hands
  the count of refusals to the table split off.
- `declare::liveliness_subscriber::tests::an_on_use_peers_tokens_split_off_whole_and_stay_counted`
  (`storage-profile`): a table of no token splits off nothing (the CONTROL); two tokens taken
  against a key budget split off whole, in the order declared, the budget's count unmoved; the
  table they came from takes a third token against the same budget; the table split off retracts
  the lowest id first (`take_lost`); dropping both gives every key's bytes back. Red if
  `PeerTokens::<OnUse>::split_off` leaves the tokens behind, drops their keys, or hands the new
  table another budget than the one its keys are counted against.
- D12: both are items no D12 build reaches (`FixedIdMap::split_off` is called by the on-use split
  alone, which no engine form calls yet). C1cs's readings are not expected to move.
- Dropped (`12e8da2c40`): the relation of 7.11 moves a face's tokens one row each, so no form
  splits an on-use table; `PeerTokens::<OnUse>::split_off`, `FixedIdMap::split_off` and the two
  tests above went, and the lent split (`PeerTokens::<Lent>::split_off`) is the one left.

### 7.11 R1b, step 2: the owed relation

- The decision: on `OnUse` the tokens of the faces that went are a relation whose rows are
  tokens keyed by face and id (`FaceToken`, `OwedTokens`,
  `crates/wz-session-core/src/declare/liveliness_subscriber.rs`), not a table of whole
  `PeerTokens` tables. It is the relational form `peer-rows.md` section 5.4 and step R3 give every
  peer declaration (the holding and the owing face a column over the face table), and it keeps no
  table of tables. R3 generalises it: the row is `(face, id, key)`, and a face's own token table
  becomes the rows of the same relation whose face holds them, owing being a face column that
  names a face that went.
- The bound: a row for each token the faces other than the dial role's may hold together
  (`FacePeers::sets() - 1` faces at the per-face `MAX_REMOTE_DECLS` the session resolved,
  `engine/registry/owed.rs` `Owed::counted`), taken whole when the first such face is admitted.
  No pool bounds the faces' tokens on `OnUse`, so the bound is kept by the admission: a face is
  admitted only while the rows left hold the tokens of every face held that may go and of the new
  one (`OwedTokens::admits_face`, asked by `RegistryOf::add_face` before it builds anything); a
  refusal is answered as a face past `max_faces` is (`FacesFull`). So `owed + held * per_face <=
  rows` holds at every step (a face that goes moves at most `per_face` tokens and frees its
  `per_face`; a retraction only shrinks `owed`), `owe` always finds its rows, and no
  retraction is dropped. The residue: while retractions wait for room in the round, a face the
  lent form would admit can be refused; without a pool that is the price of never losing one.
- The lent form keeps its table of split tables, their rows in the session's token pool, which
  bounds what the faces hold and owe together: D12's code, bytes and order do not move. R3 makes
  it the pool's relation with the same face column.
- The engine names both forms by one type (`Owed`, `crates/wz-capi-coop/src/engine/registry/owed.rs`),
  so the registry's retraction, take and clear are one code over both
  (`RegistryOf::retract_owed`, `take_lost_token`, `remove_accepted_faces`); the observer
  retracts either through `LostTokens` (`SlotObserverOf::flush_tokens_on_link_loss_while`).
- Tests: `declare::liveliness_subscriber::tests::the_tokens_of_faces_that_went_are_owed_as_one_relation_of_tokens`
  (`storage-profile`): the admission of two faces of two tokens each and the refusal of a third
  (the CONTROL), a face's tokens moved whole in ascending id after an earlier face's with their
  keys still counted, the admission refused while those tokens hold the rows, a table that does
  not fit moving none, and the retraction in the relation's order by `take_lost` and by a flush
  that stops where `room` says no. Red if `admits_face` reads `held` for `held + 1`, if
  `owe` leaves a token behind or moves part of a table that does not fit, if the rows come back
  in another order, or if a key is let go of before its row. The lent arm is held by the
  registry's `a_face_that_goes_owing_retractions_gives_its_set_back_at_once` and its neighbours,
  unchanged. The engine's on-use arm compiles only where `listen` or `group` stands beside
  `tables-on-use`, which `table_policy` does not name `OnUse` yet: its first build is R1b's
  switch (`build.rs`, 11.1 R1b 7).
- D12: the lent arm is the code it replaced, moved into `Owed`; C1cs's readings are not expected
  to move. `PeerTokens::<OnUse>::split_off` (7.10) is called by no engine form now: the relation
  moves tokens, not tables.

### 7.12 R1b, step 3: the listening and grouped registry on use, and the switch

- What it does (`d269055bd4`): `RegistryOf::counted` (`engine/registry/counted.rs`) is generic
  over `Holders` and takes the plan's `GetTables` and `FacePeers`, as `Registry::new` does: its
  table of sets is counted to `FacePeers::sets` and takes every set's row at its first push; a
  session that dials nothing writes its dial face a set of no rows first; the dial face's set is
  counted at the open (`count_set`, out of line as `lend_set` is); where faces are added, the
  rest are built as each place's first face comes (`SpareSets::counted`, its `build` the same
  `count_set`), and `Owed::counted`, the aliases' quota and the spares are the struct's fields
  as on `Lent`. `ManyHolders` is of `RowPolicy`, with `Holders::counted`, which takes its rows
  at the open. `FACE_SETS`, the places of the faces' rooms the state keeps, is `MAX_FACE_SETS`
  where the build takes faces: `LinkRooms::init_at` writes a place for every set at the open, so
  a counted table would take the same memory at the same moment, in one more allocation. The
  plan's rows of the held index and of the owed tokens (`ArenaPart::HeldFaces`, `OwedTokens`,
  `FACE_ROWS`, `OWED_ROWS`, `HELD_SET_BYTES`) are the lent form's alone.
  `SessionArena::arena_mut` is compiled on use where the open still lends the arena the direct
  faces' slots or the admission's place (R2 moves both). `build.rs` names `OnUse` wherever
  `tables-on-use` is, so `--all-features` builds this form.
- The admission (`Core::_admission`) keeps one owner on use: placed in the arena by the open, a
  field of `Core` after the transport, the session's state and the tasks, which hold every lease
  of it, and before `_state` and `arena`; nothing to change before R2 takes it out of the arena.
- Tests (`engine::registry::counted::tests`, each `listen` or `group`):
  `an_on_use_face_builds_its_set_at_its_places_first_face_and_gives_it_back`: the dial face's set
  alone built at the open (the CONTROL), a face's set built at its place's first face, its peer's
  subscriber held and its key counted, the set left where it lies for the next face, a face past
  every place refused; red if `SpareSets::build` does not count the set's rows, if every set is
  built at the open, or if a set given back is built again elsewhere.
  `an_on_use_session_that_dials_nothing_keeps_a_rowless_set_for_its_dial_face`: a set of no rows
  first, the face that comes at the next place, counted; red if `counted` counts the dial face's
  set where `FacePeers::dial` is false, or builds it none.
  `an_on_use_registry_owes_the_tokens_of_faces_that_went_and_admits_faces_while_they_fit`
  (`liveliness`, `MAX_REMOTE_DECLS` stated at two): two faces admitted with nothing owed (the
  CONTROL), four tokens owed as four rows with their keys counted, a third face refused while
  they hold the rows, the retraction in the faces' order and each face's ascending id, every key
  given back, and the face admitted again; red if `add_face` does not ask `Owed::admits_face`,
  if tokens are dropped as their face goes, or if the order moves.
  `an_on_use_registry_holds_the_plans_rows_and_has_taken_none` now takes the plan's `GetTables`
  and `FacePeers` and asserts one set. `tests::on_use::an_on_use_plan_from_the_config_lays_out_no_row_of_the_tables_it_counts`
  names "held faces" and "owed tokens" too. `form_precedence_tests` keeps the on-use test alone,
  now whatever faces the build takes (red if `table_policy` keeps `!takes_faces`).
  The lent form's plan tests of those rows read `wz_lent` (`tests::arena`,
  `the_tokens_owed_apart_are_bounded_by_the_sessions_token_pool` and two assertions).
- The gate: `scripts/lib/nondefault-tests-gate.sh` gains `liveliness,listen,tables-on-use|on_use`.
- Residues, each a later step's: on `OnUse` a peer's aliases are inline at
  `MAX_PEER_KEYEXPR_ALIASES`, so a group's face held to its members' aliases
  (`hold_member_aliases`, `multicast-declarations`) holds no more than that bound, where on
  `Lent` the session's pool holds them (R3's relation of a peer's declarations); the session's
  `SESSION_MAX_REMOTE_DECLS` is not held across faces on `OnUse` (7.11); the admission, the direct
  faces' slots, the transport's tables and the kept publishes are still lent from the arena
  (R2 to R4).
- D12: no D12 build names `tables-on-use`, so no predicate of one moves but the plan's
  `FACE_ROWS` (the same value on `Lent`) and `SpareSets::build`'s refusal, now `FacesFull`
  where the caller mapped it before. C1cs's readings are not expected to move.

## 8. What the main session runs

- R1b, step 3 (`d269055bd4`) and the drop of the on-use split (`12e8da2c40`), not built or run
  by this lane. The on-use listening form: `cargo test --manifest-path crates/Cargo.toml -p
  wz-capi-coop --features liveliness,listen,tables-on-use --lib on_use` 13 (four of
  `engine::registry::counted`, seven of `tests::on_use`, one of `engine::state_places`, the
  precedence test); the on-use client legs as before (`--features tables-on-use --lib on_use`,
  the second leg's features, `--features runtime-plan,tables-on-use`), each one count the same;
  `cargo clippy --manifest-path crates/Cargo.toml -p wz-capi-coop --all-features --all-targets --
  -D warnings` (now the on-use form), the same with `--features liveliness,listen,tables-on-use`,
  with `--features app-transport,group,multicast-declarations,liveliness,tables-on-use` and with
  `--features link-admission,udp-listen,tables-on-use`; `cargo test --manifest-path crates/Cargo.toml -p wz-capi-coop --all-features --lib
  engine::registry` now runs the on-use form's four of `engine::registry::counted` and none of the
  lent `engine::registry::tests`; the lent form, unchanged, is read by `--features
  app-transport,group,listen,liveliness,multicast-declarations,query,queryable --lib
  engine::registry` and the crate's legs that name `listen` or `group` without
  `tables-on-use`; `cargo test --manifest-path crates/Cargo.toml -p wz-session-core --features
  codec-declare --lib liveliness_subscriber` and `--lib id_map` (two tests fewer) and `cargo
  clippy --manifest-path crates/Cargo.toml -p wz-session-core --all-targets -- -D warnings`, the
  same with `--no-default-features`. The non-default tests' census (C1cn) and the public surface
  census of `wz-capi-coop` read the `--all-features` build, which changes form here.

- R1b, step 2 (`8988bd43f3`, `3963ecf41d`), not built or run by this lane: `cargo test
  --manifest-path crates/Cargo.toml -p wz-session-core --features codec-declare --lib
  the_tokens_of_faces_that_went_are_owed_as_one_relation_of_tokens` 1; `cargo clippy
  --manifest-path crates/Cargo.toml -p wz-session-core --all-targets -- -D warnings` and the same
  with `--no-default-features` (no `alloc`: the relation is not compiled); the lent arm of
  `Owed`: `cargo test --manifest-path crates/Cargo.toml -p wz-capi-coop --all-features --lib
  engine::registry` (the count of before) and `cargo clippy --manifest-path crates/Cargo.toml -p
  wz-capi-coop --all-features --all-targets -- -D warnings`, the same with the crate's default
  features and with `--features tables-on-use` (`Owed` is not compiled there, and
  `flush_tokens_on_link_loss_while` now takes any `LostTokens`).

- R1b, step 1 (`1063768725`), not built or run by this lane: `cargo test --manifest-path
  crates/Cargo.toml -p wz-session-core --lib a_split_off_fixed_table_takes_its_rows_whole` 1,
  `cargo test --manifest-path crates/Cargo.toml -p wz-session-core --features codec-declare --lib
  an_on_use_peers_tokens_split_off_whole_and_stay_counted` 1 (the module's tests need
  `codec-declare`, which no default names; the gate's wide `wz-session-core` leg names it, so the
  census finds the test claimed; a run of 0 is no pass), and `cargo clippy --manifest-path crates/Cargo.toml -p wz-session-core
  --all-targets -- -D warnings`, the same with `--no-default-features` (no `alloc`: the on-use
  split is not compiled).

Nothing of N1, N2, N3a, N3b or N3c's first two steps was built or run by this lane.

- The rooms' one owner (`7f05e7df93`, the fix of 3a's two reds), R1 step 0 (`6b6041bf09`) and
  R1a (`01cf14693c`), not built or run by this lane. 3a's list below again, which stopped at those
  reds, with the counts of now: `cargo test -p wz-capi-coop --features tables-on-use --lib on_use`
  9, the same with `--features liveliness,liveliness-get,local-queryable,query,queryable,tables-on-use`
  10, and the new leg `cargo test -p wz-capi-coop --features runtime-plan,tables-on-use --lib on_use`
  9; `--features runtime-plan,tables-on-use --lib form_precedence_tests` 1 (the on-use one) and
  `--features listen,tables-on-use --lib form_precedence_tests` 1 (the lent one); `cargo clippy -p
  wz-capi-coop --all-targets -- -D warnings` with `--features tables-on-use`, the second leg's
  features, `--features runtime-plan,tables-on-use` and `--all-features`, and
  `WZ_COOP_VALUE_LOCKS=off` with `--features query,queryable,tables-on-use` and with
  `--features query,queryable,runtime-plan,tables-on-use`; `cargo build -p wz-capi-pico
  --no-default-features --features os-host,link-udp,wz-capi-coop/tables-on-use`, and the planned
  on-use library with `os-host,link-udp,config-policy,wz-capi-coop/tables-on-use`. The D12 suites
  of both crates and C1cs's three readings, unchanged: step 0 moves no predicate of a D12 build.

- N3c, step 3a (7.8; `f104d31bc8`, `81cebf0f4c`, `b0afa53110`, `44d25ac4b9` on the lane), not
  built or run by this lane either. `cargo test -p wz-runtime-coop --lib
  kept::tests` two more than before, and `cargo clippy -p wz-runtime-coop --all-targets -- -D
  warnings`. The engine's on-use legs: `cargo test -p wz-capi-coop --features tables-on-use --lib
  on_use` 8 (6 before), the same with `--features
  liveliness,liveliness-get,local-queryable,query,queryable,tables-on-use` 9 (7 before), and
  `cargo clippy` of both legs with `--all-targets -- -D warnings`; the round's form,
  `WZ_COOP_VALUE_LOCKS=off cargo clippy -p wz-capi-coop --features query,queryable,tables-on-use
  --all-targets -- -D warnings`; the client library in the on-use form, `cargo build -p
  wz-capi-pico --no-default-features --features os-host,link-udp,wz-capi-coop/tables-on-use`. The
  D12 forms as before: the crate's suites of `wz-capi-coop` and `wz-capi-pico`, `cargo clippy -p
  wz-capi-coop --all-features --all-targets -- -D warnings` (a build of both features, the
  `runtime-plan` form, which this step does not reach), and C1cs's reading of
  `pico-client-coop-nostd`, `pico-peer-coop` and `pico-api-coop-nostd`, unchanged.

- N3c, step 2, second half (7.7). The session core with its default features: `cargo test -p
  wz-session-core --lib get_plane::tests` 16 (14 before), `--lib query_plane::tests` 16 (12
  before), `--lib round::tests` two more than before (31 in a debug build), `--lib on_use::tests`
  15 in a debug build (13 without debug assertions); `cargo clippy -p wz-session-core --all-targets
  -- -D warnings`, and the same with `--no-default-features`, which compiles neither the planes nor
  `test_heap`. The engine's on-use legs: `cargo test -p wz-capi-coop --features tables-on-use --lib
  on_use` 6 (the test added needs `query` or `queryable`), the same with `--features
  liveliness,liveliness-get,local-queryable,query,queryable,tables-on-use` 7, and `cargo clippy` of
  both legs with `--all-targets -- -D warnings`; the round of that form, `WZ_COOP_VALUE_LOCKS=off
  cargo clippy -p wz-capi-coop --features query,queryable,tables-on-use --all-targets -- -D
  warnings`. The D12 forms as for step 2's first half below (`StatePolicy` is `Lent` there,
  `--all-features` among them), and `python3 scripts/lib/logic_census_coverage_gate.py`
  (`test_heap.rs` has its row in `files.md`).

- N3c, step 2, the D12 form, whose behaviour and bytes it does not change (the region's form
  calls the same bodies through `StateLayout` and `StateHold`): the crate's suites of
  `wz-capi-coop` and `wz-capi-pico` as before, `tests::arena::a_sessions_planes_lie_in_its_own_arena`
  reading `state_holds`. The on-use form: `cargo test -p wz-capi-coop --features tables-on-use
  --lib on_use` 6, the same with `--features
  liveliness,liveliness-get,local-queryable,query,queryable,tables-on-use` 6 (7.6); `cargo clippy
  -p wz-capi-coop --features tables-on-use --all-targets -- -D warnings` and the same with the
  second leg's features; the client library in that form, `cargo build -p wz-capi-pico
  --no-default-features --features os-host,link-udp,wz-capi-coop/tables-on-use`, whose `nm` should
  name no `wz_capi_coop::region` body. The precedence leg and `--all-features` as for step 1 below.

- N3c, step 1, the D12 form, whose behaviour and bytes it does not change:
  `cargo test -p wz-session-core --lib on_use::tests` 14 in a debug build (10 before, four added;
  12 in a build without debug assertions), and the crate's suites of `wz-capi-coop` and
  `wz-capi-pico` as before. The on-use form: `cargo test -p wz-capi-coop --features tables-on-use
  --lib on_use` 5, the same with `--features
  liveliness,liveliness-get,local-queryable,query,queryable,tables-on-use` 5 (the two legs of
  `scripts/lib/nondefault-tests-gate.sh`); `cargo clippy -p wz-capi-coop --features tables-on-use
  --all-targets -- -D warnings`; the client library in that form, `cargo build -p wz-capi-pico
  --no-default-features --features os-host,link-udp,wz-capi-coop/tables-on-use`. The precedence of
  the two forms (9.1): `cargo test -p wz-capi-coop --features runtime-plan,tables-on-use --lib
  form_precedence_tests` 1 (a leg of that gate beside the two above), and the two gates that
  build the crate with `--all-features` again: `cargo clippy -p wz-capi-coop --all-features
  --all-targets -- -D warnings` (pre-push gate 7, `scripts/lib/nondefault-features-gate.sh`)
  and the census of `nondefault-tests-gate.sh --census` (Layer C1cn), whose only new test of the
  crate is that one. The client library beside `peer` builds, as the peer's D12 form.

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
  `tables-on-use = []`, which makes `RowPolicy` `OnUse` and compiles the on-use open (N3c) where
  `runtime-plan` is off. Features add (The Cargo Book, Features: a feature turns code on and never
  off), so two forms are not written to exclude each other; where both are named, one wins:
  `runtime-plan`, the session laid out at the open from its config. A build of both,
  `--all-features` and a graph that unifies `peer`, `listen` or `group` with `tables-on-use`
  among them, is the `runtime-plan` form whole, its policy `Lent` and its moment the open's
  (`crates/wz-capi-coop/src/lib.rs`, where `RowPolicy` is named, and the feature's note in its
  `Cargo.toml`). Unified into a graph without `runtime-plan` it changes the moment of every session
  there, so the C library, a cdylib built by itself, is the only graph that names it, and the guards
  below read what it resolved to.

### 9.2 What keeps the release at D12

1. At the build: `crates/wz-capi-coop/src/lib.rs` asserts `RowPolicy::TAKEN` is `AtOpen` (N1,
   landed); N3c compiles it outside the on-use form (`tables-on-use` without `runtime-plan`)
   beside its `AtFirstUse` twin, so no form builds whose policy disagrees with its moment. A build
   that names both features is outside the on-use form (9.1) and asserts `AtOpen`.
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
- A peer twin (`pico-peer-coop-on-use`) waits for R1 (11.1; until then a build of `peer` beside
  `tables-on-use` is the D12 peer, 9.1), where a listening session's faces come and go: on
  `OnUse` each face's tables are counted at its attach (N3b's constructors), with no pool lent at
  open.

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
   are still linked. Written (7.5): the twin is `StateRegion` under the feature, its key budget a
   field where the key arena lay; the registry is `engine/registry/counted.rs`; the session's
   state names its key store with its policy (`SessionParts::Keys`), and the budget takes the key
   arena's marks of the session's lock, so every reader of `session.keys` reads it unchanged but
   the C ABI's held keys (`SessionKeys`, `KeysLocked`): on the on-use form each is a copy of its
   own the engine makes, refused past the session's `MAX_KEYEXPR_BYTES` as the arena refuses it,
   and not counted against the budget until N3e makes it a holder of the row's `HeapKey`.
2. The region's other places into the boxed state; `region.rs` leaves the form. Written (7.6):
   the state is `OwnState` (`engine/state_places.rs`), the places of the state's own values
   (`StatePlaces`) and the key budget, taken zeroed from the allocator by `OwnBlock` at the open,
   apart from the arena, which is reserved alone (`SessionArena::reserve`); the engine names the
   state by `StateLayout` and its holder by `StateHold`. Its places keep the rows of the plain
   tables and of the round at the build's bound, taken with the state at the open. Counting them on
   `OnUse` is the second half of this step, a commit of its own, because those tables are the
   session core's lent ones and each push into them was written for rows the open lent:
   `EndedLegs` and `LegRows` (`crates/wz-session-core/src/get_plane.rs:213`, `:143`), the get
   plane's `HeldReplies<u64, Lent>` (`:288`), `HeldFinals` and `RefusedFinals`
   (`query_plane.rs:118`, `:121`) and the round's `RoundRows` (`round.rs:775`). Each needs the
   policy as a parameter, and each push a first row the allocator may refuse:
   `EndedLegs::note` asserts its push is kept (`get_plane.rs:224`), `FinalHolds::admit` lets a
   refused request's push go (`query_plane.rs:223`), and the round pushes on the receive. Each is
   given its room before the push, as `FinalStaging::make_room` is (below), or a refusal its
   caller answers.
   Written (7.7): the policy is the engine's calls' (`RoundCalls::TablePolicy`, the engine's
   `StatePolicy`), the state's places keep none of those rows in the on-use form
   (`PlacedTables::counted`, `RoundRows::counted`), the ends take their rows at the leg's open,
   `FinalHolds::admit` answers `Admitted`, and an offer to the round takes its rows before it
   writes. Every push of those tables is read in the audit below.
3. The engine's own values out of the arena, then N3d. Three parts, each of which builds alone,
   in this order: the first two lie in the engine's crate and the heap arms they need are there or
   one maker away, while the links' memory reaches every link of `wz-runtime-coop`.
   - 3a, the engine and the faces' rooms. Written (7.8): the engine lies in an allocation of its
     own the open claims beside its row, before it reserves anything (`SharedClaim`,
     `crates/wz-runtime-coop/src/kept.rs`), so an open the allocator refuses reserves nothing;
     the engine keeps a count of the arena's memory as the place the arena lent it did
     (`SessionArena::keep`, `SharedClaim::made_with`), so what the engine holds that lies in the
     arena (the lodgings, the handle's place) stands while the engine is held, and the arena's
     memory goes back after the engine's last holder, as before. The rooms lie in an allocation of
     their own (`OwnPlaced`, `engine/state_places.rs`), whose one owner drops them in place and
     gives the allocation back. The plan lays out neither place in the form (`lay_out_open`). No
     body of the open's lay-out leaves yet: the arena still lends the transport's tables, the
     ABI's places and the runtime's span, and the form's code grows by the claim (one maker and one
     drop, instantiated for the engine alone) until 3d.
   - 3b, the runtime: the heap makers the runtime has (`CoopRuntime::try_reserved`,
     `try_reserved_for_one`, `try_opening`, `crates/wz-runtime-coop/src/runtime_impl.rs`), and a
     fourth for the form the one-link read runs on (`RuntimeForm::Taskless`), which has none: an
     `ExecutorState::try_taskless` over a `TaskStore` of no cell, as `taskless_in` is over a
     placed one, with the local set made over the runtime (`CoopLocalSet::try_new`). The count of
     the arena the engine keeps is then laid out alone (`ArenaPart::ArenaKeep`, which
     `ArenaPlan::lay_runtime` lays beside the runtime's span today), until 3d takes the arena out.
   - 3c, N3d: the links' memory, chosen by a type and not by a feature. A feature of
     `wz-runtime-coop` cannot yield to `runtime-plan` as `tables-on-use` does (one crate's
     feature cannot read another's), so a feature that compiled the heap arm alone would take the
     lent arm from the runtime-plan form of a build that unifies both. The engine names its links'
     memory as it names `LinkCount` (`crates/wz-capi-coop/src/lib.rs`): a source the cells are
     made through, the lent tables' or the heap's, in place of the `Option<&LentByteCells>` that
     `head_in` reads today (`crates/wz-runtime-coop/src/link_cells.rs:345`), so a form whose
     source is the heap's links neither `table_head` nor a cell table, and `Owner::Table` has no
     maker in it. The same for the links' buffers (`LinkTables`): a link's buffers taken at its dial
     and held for its life, as zenoh-pico's transport holds its two; a reassembly chain's buffer at
     its first fragment; the endpoints' texts by value. Each stack's `lend_buffers` and
     `lend_cells` (`ip_stack.rs`, `app_link.rs`, `serial_link/links.rs`, `unixpipe_link.rs`,
     `ws_link/links.rs`, `either_links.rs`, `session_drive.rs`) reads the source.
4. N4 (3.7): the doors' objects from the allocator, counted against their kinds, so the places the
   ABI holds in the arena today (the handle's, the entities', the lodgings) are the ABI's own.
5. 3d, the arena: with every tenant housed, the on-use form reserves no arena. `SessionArena`,
   `TableLender` and the lend bodies of `arena.rs` (`TransportRows::lent_from`,
   `PlaceRows::lent_from`, `SessionRows::lent_from`) are not compiled in it; the counts the plan
   reads off the limits (`ArenaPlan::count`, `tables`, `peers`, `gets`, `session`) stay, the
   on-use constructors' only input. The size case reads group A's figure here.
6. The zenoh-pico preset's own library on use (11.1, R1 to R4), and N5 once R1 builds (11.2).

The pushes of the tables step 2's second half counts, and of the tables beside them in the same
planes, each with what a refusal reaches (read at the step's own commits):

| table | push | a refusal | answered |
|-------|------|-----------|----------|
| `EndedLegs` | `GetPlane::open_leg` asks `EndedLegs::make_room` on a first-use policy | `None`: the get is refused as one no row holds (`LegHeld::NoRoom`, `LegTurn::Skipped`), nothing minted | yes, added |
| `EndedLegs` | `EndedLegs::note`, from the drop of the leg's entry | none can come: its rows were taken at the open and are kept, and the ends waiting, each holding a leg's row, are never more than the legs' rows (`GetPlane::init_at` checks it in a debug build); the debug assertion states that | yes; before, on `OnUse` the first end asked the heap here and a refusal lost the end and the callback |
| `LegRows` | `LegRows::open` | `None`, as the row above | yes |
| `HeldReplies<u64, _>` (the get plane's) | `HeldReplies::hold` | `HoldRefused::Full`, counted; `consolidate` hands the reply on at once | yes |
| `HeldFinals` | `FinalHolds::take` | `false`: `admit` notes the refusal (`Admitted::Refused`); `OwnFinalHold::take` is `None` and the session's own get is refused before a leg is issued | yes |
| `RefusedFinals` | `FinalHolds::rows_for_refusals` on a first-use policy, before the first hold | `Admitted::Unnoted`: counted, no call begun, its Final owed as one that reached no queryable | yes, added |
| `RefusedFinals` | `FinalHolds::admit`'s note of a refusal | `Admitted::Unnoted` past the list's count | yes; before, `let _ =` dropped it |
| `RoundRows`, records and callbacks | the first write of a record, in each of the five offers | `Round::take_rows` is `false`: `refuse_unplaced` counts it (`unplaced`, and `dropped` or `held_over`) and ends its call | yes, added; before, a debug build stopped and a release build lost the record uncounted |
| `RoundRows`, callbacks | a later call joining a record | the rows were taken by the record's first write; past the count, `refuse` and the call settled | yes |
| `RoundRows`, keys | `Table::place_key` | `None`: counted unplaced | yes |
| the engine's pending legs (`Rows<PendingGet>`) | `SessionState::note_pending` | the leg is unregistered, which says its end, and counted (`unheld`) | yes; on `OnUse` the first row is asked after the Request went out, so that get ends with no reply |
| `GetPlane::held` (a `VecDeque`, every policy) | `GetPlane::keep_held`, `push_back` | the infallible push: the allocator's refusal ends the process | **no**: outside this step's tables, an owned reply's path; a debt of its own |
| `LocalAsking::asked` (`Static`) | `QueryPlane::arrive`, `arrive_own` | no allocator: `arrive` hands a call past the list to the round; `arrive_own` reads the room first under the session's lock | yes |
| the round's captured calls (`Static`) | `Round::offer_sample_ref` under a capture | no allocator: past the session's subscribers the call is ended uncounted, and a debug build stops | by the table's bound |

One window stays open on a first-use policy: a request whose refusal found no row (`Unnoted`) is
not remembered, so if the allocator refuses the list's rows at one queryable's admission and gives
them at the next queryable of the same request in the same dispatch, that queryable is answered
where the first was not. It is reachable only before the session's first held request, after
which the list keeps its rows.

A table that answers whether it has room before the push that would take its memory cannot take
the memory when it answers (`FinalStaging::has_room`, `&self`): the query dispatch asks before the
queryables run and owes the `Final` after (`crates/wz-session-core/src/query/in_place.rs:216`,
`:234`), so on `OnUse` a `Final` the allocator refused at the table's first row would have been
counted as a refused request after the callbacks ran, with no `Final` sent. N3b's last commit makes
the dispatch ask `FinalStaging::make_room`, which takes the row on a first-use policy and answers
as `has_room` on every other. The engine's own checks of room before a push are read the same way
when N3c names `OnUse`.

### 11.1 The preset's own library is laid out from its config

The zenoh-pico preset turns on, beside the client role, the peer capability and zenoh-pico's
multicast transport: `peer` and `multicast-transport` name zenoh-pico in their `upstream_on`
(`deploy/wz-config.toml`, the two capabilities), so `configs/zenoh-pico_defconfig`, which lists
only what differs from the Kconfig default, names neither, and the crate's default build, which
is the preset, names both (`crates/wz-capi-pico/Cargo.toml`, `default`). Each turns
`runtime-plan` on: `peer` names `wz-capi-coop?/listen` and `wz-capi-coop?/runtime-plan`
(`crates/wz-capi-pico/Cargo.toml:229`), `multicast-transport` names `wz-capi-coop?/group-host`
(`:244`), whose `group` names `runtime-plan` (`crates/wz-capi-coop/Cargo.toml:310`), as
`listen` does (`:238`). Where both forms are named, `runtime-plan` wins (9.1). So the switch of
section 9, declared as written, would write `CONFIG_WZ_TABLE_MEMORY_ON_USE=y` into the zenoh-pico
defconfig and resolve `tables-on-use` into the preset's own library, and that library would build
the D12 form whole: a statement the build does not keep, which the file's rule (an option that
cannot be built is not declared) refuses. The on-use form reaches the client builds alone today
(`os-host,link-udp` and the capabilities that bring no `runtime-plan`).

What the runtime-plan form lends from its arena that the client form does not, tenant by tenant
(`lend_session` and `assemble` at this branch):

| tenant | the runtime-plan form today | on use |
|--------|-----------------------------|--------|
| the registry's tables and the faces' sets | `Registry::new` over the arena; the faces' sets in the pools it lends (`peer-row-pools`), a set given back to its pool when its face goes | made by value as `Registry::counted` is (`engine/registry/counted.rs`), its table of sets counted to the sets the plan counts, a face's set made at its attach by `FaceTables::rowless_in` and `count_rows` (N3b's constructors) and dropped when the face goes, its rows' memory back to the allocator; no pool is lent |
| the key arena | `lend.keys`, a `KeySpace` of the arena | the `KeyBudget` in the state, as the client form |
| the state's places (the planes, the round, the step places, the rooms' places) | each placed in the arena (`place_with`, `StepPlaces::placed_in`, `FacePlane::place_in`) | `OwnState` (`engine/state_places.rs`, compiled without `runtime-plan` alone today) |
| the plain tables and the round's rows | lent (`StateTables`, `RoundRows::lent`, `HeldReplies::lent`) | `PlacedTables::counted`, `RoundRows::counted` |
| the admission (`listen`) | its rows from the heap at the open, its value placed in the arena | its value in an allocation of its own beside its owner, its rows as today |
| the read slots and send places of the faces past the dial role's (`direct::DirectFaces::taken_in`, a build without `wz_round`) | lent for `max_faces` at the open | taken at the face's attach; a refusal answered as a face past `max_faces` is, the link closed before it has a face |
| the links' buffers, a port's rows (`udp-listen`), a group's receive buffers, the kept publishes (`HandedTable`) | lent by the plan for each admitted link, port and group | 3c's sources: at a link's accept or dial, a port's bind, a group's join |
| the runtime | `RuntimeForm::Opening` placed in the arena, its added cells of the heap | `CoopRuntime::try_opening` (3b) |

The steps, each a build of its own, the D12 forms' bytes and behaviour unchanged:

- R1, the policy named apart from where the counts come from, in three steps, each a build of its
  own:
  - step 0 (landed on the lane, `6b6041bf09`): the policy is stated once, by
    `crates/wz-capi-coop/build.rs` (`TablePolicy`), as the cfg of its name; every item spelled
    `all(feature = "tables-on-use", not(feature = "runtime-plan"))` reads `wz_on_use`, every item
    that read `runtime-plan` for a table its open lends reads `wz_lent`, and the config's plan keeps
    `runtime-plan` (7.9). The form is no longer chosen at each item but once, by the policy's type
    (`RowPolicy`, `StatePolicy`) and the cfg of its name: where the counts come from and when the
    memory is taken are two facts any build may name both of;
  - R1a (landed on the lane, `01cf14693c`): `tables-on-use` names `OnUse` in a build of both
    features whose session takes no face beside its dial role's, and the moment assertion reads
    `AtFirstUse` there: the registry, the key budget, the state's places, the plain tables and
    the round's are the client form's (`Registry::counted`, `OwnState`, `PlacedTables::counted`,
    `RoundRows::counted`), counted from the config's plan, which lays out none of their rows. That
    is `config-policy`'s library on use (`crates/wz-capi-pico/Cargo.toml`, `config-policy` names
    `wz-capi-coop?/runtime-plan`), not yet the preset's;
  - R1b (landed on the lane: `8988bd43f3`, `3963ecf41d`, `12e8da2c40`, `d269055bd4`; 7.11, 7.12):
    the listening and grouped forms, whose faces come and go. What it moved, read at R1a's tree
    (item 4 took the field at the bound in the state, 7.12):
    1. `engine/registry/held.rs` `ManyHolders` (`BoundedVec<FaceId, MAX_FACE_SETS, Lent>`) on
       `RowPolicy`, with a `Holders::counted(sets)` beside `lent`;
    2. `engine/registry/adding.rs` `SpareSets` of the on-use policy: no arena split and no
       pools; a set made at a place's first face by `FaceTables::rowless_in` and `count_rows`, in
       the row of the sets' table (`BoundedVec::<FaceTables, MAX_FACE_SETS, OnUse>::counted`, whose
       rows are taken whole with the dial face's set, so an attach takes nothing but its tables'
       first rows); `Registry::counted` (`engine/registry/counted.rs`) generic over `Holders`, over
       the plan's `GetTables` and `FacePeers`, a dial-less session's first set unpeered as
       `Registry::new` makes it;
    3. the owed tokens: `PeerTokens::split_off` exists for `Lent` over the pools alone
       (`crates/wz-session-core/src/declare/liveliness_subscriber.rs`). On `OnUse` a face's tokens
       are an inline `FixedIdMap` (`Storage::Ids`), so owing them apart moves the whole table, a
       decision of R1b's: an `OnUse` `split_off` that takes the table and leaves an empty one with
       the quotas and the keys' handle (each owed row then one peer's tokens at the build's bound,
       taken at the first face owed), or the set kept apart, its place held as a tomb's is
       (`KEPT`), until its tokens are retracted, which keeps the owed table out of the form.
       Decided and written (7.10): the split, as on `Lent`; a tomb would hold a place, and so a
       face, for as long as a retraction waits for room. What is not decided yet is the owed
       table's count on `OnUse`. On `Lent` it is a row for each row of the session's token pool
       (`FacePeers::owed_tokens`, `crates/wz-capi-coop/src/arena.rs:1220`), sound because a face
       owes apart only while its tokens hold a row of the pool, so the faces owing at once are
       never more, and `owe_tokens_of` asserts the push is kept
       (`crates/wz-capi-coop/src/engine/registry.rs:2136`). On `OnUse` no pool bounds the tokens
       of all faces together, each face's table is held to its own `MAX_REMOTE_DECLS` alone, so
       a face that comes and goes while the round has no room can owe more tables than that count,
       and the push can be refused; and `FirstUse` takes every row of the count at the first face
       owed, each row a whole `PeerTokens<OnUse>` (an inline table of `MAX_REMOTE_DECLS` rows).
       The textbook answer keeps the lent form's argument: a count of the tokens the faces hold
       together, held by the registry as the pool's rows hold it on `Lent` (a token refused past
       it as a full table refuses it), which bounds the faces owing at once again; or an owed
       table of tokens rather than of tables (a row a token, its face's order kept), counted to
       that same count, which also takes the memory of the tokens owed and no more. Decided and
       written (7.11): the relation of tokens, keyed by face and id, its bound kept by the faces'
       admission rather than by a count of the tokens kept beside the tables;
    4. the rooms' places: `StatePlaces::room_places` holds `FACE_SETS` (one) places; a listening
       session holds one for each set (`plan.peers().sets()`), at most `MAX_FACE_SETS`: the field
       at that bound in the state, or a counted table of them;
    5. the plan's rows of the index of held sets and of the owed tokens (`ArenaPart::HeldFaces`,
       `ArenaPart::OwedTokens`, `OWED_ROWS`, `HELD_SET_BYTES`, the `Lent` import of `arena.rs`)
       read `wz_lent` beside `listen` and `group`, so the on-use listening plan lays out none;
    6. the registry's tests (`engine/registry.rs` `mod tests`, `all(test, wz_lent)`) stay the lent
       form's, and their on-use twins (a face added and removed, a set built at a place's first
       face, the tokens owed) are written over `Registry::counted`;
    7. `build.rs`: `table_policy` drops `!takes_faces`, and `form_precedence_tests` keeps its
       on-use test alone. From then `--all-features` builds this form, so pre-push gate 7's clippy
       and the census of the non-default tests (C1cn) read it, and a graph that unifies `peer`,
       `listen` or `group` with `tables-on-use` takes every session's memory on use: the C library
       stays the one graph that names the feature (9.1), and the resolver's guard (9.2, 2) is what
       keeps the release out of it.
  What the arena still lends after R1b: the transport's tables, the admission's place, the direct
  faces' slots, the kept publishes and the ABI's places (R2 to R4, N4).

- R2, the admission's value and the direct faces' slots taken per face (the table's fifth and
  sixth rows); a face refused for want of memory at its attach is answered as one past
  `max_faces` is.
- R3, the links' memory of the listening and grouped stacks: 3c's sources for a port's rows, a
  group's receive buffers and the kept publishes, and the runtime's `try_opening` (3b).
- R4, the arena of the form leaves with 3d.

### 11.2 The switch after R1b

N5 (section 9) declares `on-use` once R1b builds (R1b landed on the lane, `d269055bd4`; the main
session orders R2 to R4 before N5): from then the preset's library, built with
`tables-on-use`, takes its tables' memory at their first rows, which is what the option states,
while R2 to R4 change where the rest of its memory comes from and not when its tables take theirs.
Until R1b the option would name a form the preset's library does not build: R1a reaches a library
laid out from its config that takes no face beside its dial role's, and the preset's names `peer`
and `multicast-transport` (11.1). What N5 writes
is section 9's: the axis and its two options in `deploy/wz-config.toml`, `wz-capi-pico`'s
feature `tables-on-use = ["wz-capi-coop?/tables-on-use"]` (the census of public features and
the prose names read a new feature name, as every new one), the release profiles' `at-open`
lines with their reason (`configs/profiles/host-peer-ext.conf`, `host-peer.conf`; their base is
the zenoh-pico defconfig), the resolver's features and the reference's leaving the feature out
(`wz_config.py` `engine_features`, `pico_reference`), C1nh's refusal of a release form that
resolved to on-use and its second reading (9.2), and the generated files, which the main session
regenerates (`wz_config.py --emit`). The guards of 9.2 stand as written but for the first: from
R1a the build-time assertion reads `AtFirstUse` in a build of both features whose session takes no
other face, and from R1b in every build of both.

The size case of the client's on-use form (`pico-client-coop-nostd-on-use`, 10.2) needs no axis,
but it needs the pico crate's own feature: `case_build` names a case's features through the C
library's dependency on the ABI crate (`abi/<feature>`, `artifact_features` in
`scripts/lib/capability_cost_gate.py`), which reaches no feature of the engine's crate, so
`wz-capi-pico`'s `tables-on-use` lands with the case, before N5, its list
`os-host,link-udp,tables-on-use`. It is the one reading of what the moment costs in code before
the preset's library is on use. Its first `--measure` is the main session's: the gate's own rule
fails `--check` on a case with no budget, so the case and its first budget land in one commit.

What this lane can win, stated against the gap of section 4 (32,525 bytes, the case at 203,025):
the on-use form of the client takes off the open's lay-out (3d, group A, about 6,300 read), the
link memory's lent arm (3c, 1,000 to 2,000) and the doors' pools (N4, 2,000 to 3,000), about 7,500
to 13,200 together (section 4), between a quarter and two fifths of the gap. The lane alone does
not close it, and no figure here is measured: the case of 10.2, read at each of 3d, 3c and N4, is
what says how much of that range is real.

### 11.3 The size case and N5 as one commit, prepared

What the commit holds once R1b builds, in the order the gates read it; the first `--measure` and
every budget and ceiling row it fixes are the main session's:

1. `crates/wz-capi-pico/Cargo.toml`: `tables-on-use = ["wz-capi-coop?/tables-on-use"]` with its
   note (a form, not a capability: off in every build that names nothing, on where the axis of 9.1
   resolves `on-use`); the census of public features (`feature_public_surface_census.py`) and the
   prose names read the new name, as every new feature.
2. `scripts/lib/capability_cost_gate.py`, beside `pico-client-coop-nostd` (its `Case` at this tree's
   line 930): `Case("pico-client-coop-nostd-on-use", "wz-capi-pico", "libwz_capi_pico.so",
   "os-host,link-udp,tables-on-use", <the measured budget>, forbid=<pico-client-coop-nostd's>,
   require=<its> + (ON_USE_ROWS,), exports=443, **NOSTD_RELEASE_FORM, note=...)`, the client of the
   zenoh-pico preset in the form that preset ships, divided by the same reference (10.2). Its
   patterns: `ON_USE_ROWS = r"wz_session_core::on_use::take_rows"` (`#[inline(never)]`,
   `crates/wz-session-core/src/on_use.rs`), REQUIRED of the on-use case and FORBIDDEN in every D12
   pico case; and a body of the D12 open's lay-out, REQUIRED of `pico-client-coop-nostd` and
   FORBIDDEN in the on-use case. Neither `StateRegion::place` nor `RegistryRegion::bind` is out of
   line, so which body survives LTO in the D12 library is read off its `nm` first, and that one is
   the witness. `HEAP_ABORT` stays forbidden in the on-use case: each allocation of the form answers
   a refusal as a value (`SharedClaim::try_new`, `OwnBlock::take`, `OwnPlaced::written`,
   `FirstUse`'s `take_rows`, `HeapKey`'s), and `handle_alloc_error` linked there is a finding.
3. `deploy/size_ledger.json`: the case joins `cases`, `base_case` stays `pico-client-coop-nostd`, so
   `--per-feature` steps from the D12 client to the on-use one by `tables-on-use` alone;
   `size_ledger_gate.py`'s selftest set (`{"pico-client-coop-nostd", "pico-peer-coop",
   "pico-api-coop-nostd"}`, line 3381) gains it; `deploy/pico_host_ceiling.json` gains its row from
   the first reading.
4. N5 as 11.2 lists it. A case of the preset's own library as it is (its features resolved from
   `configs/zenoh-pico_defconfig`, as `pico-api-coop-nostd` reads the host-peer profile's by
   `features_from`) changes form with N5, so it is read in the same commit: its budget and row move
   by the main session's first reading of it, and section 4's figures are what that reading checks.
   The crate's default build (`pico-default`) names no `tables-on-use` and keeps its form.
5. The first `--measure`: `--check` fails a case with no budget, so the commit carries the budget
   the main session measured. What it is read against: section 4 (the on-use client +100 to +300
   until 3d, group A's about -6,300 at 3d, 3c's -1,000 to -2,000, N4's -2,000 to -3,000) and C1nh's
   second reading (9.2, 3).

The client case alone needs no axis and builds at R1a's tree (`os-host,link-udp` takes no face
beside its dial role's): landed before N5, as 11.2's last paragraph lays out, it is read at each of
3b to 3d and N4; landed with N5, it is the commit above. Either way its features and patterns are
the same.
