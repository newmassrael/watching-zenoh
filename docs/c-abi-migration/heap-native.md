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
| `Ids<V, N>` | `CountedIdMap<V, N>` (7.15): `N` rows, or the count its owner states while it holds none (`PeerIds::recount`), taken at its first id; lent its owner's `BudgetKeys`, a NEW id takes a row of its kind from the session's `KeyBudget` too | a peer that never writes takes nothing, and the session's peers hold what they write to `SESSION_MAX_*` together, as the lent pools hold them (3.4) |
| `Pooled<T, N>` | `CountedSeq<T, N>` (`row_pool.rs`, 7.16): `N` rows taken at its first value; lent its owner's `BudgetKeys`, a value takes a row of its kind from the session's `KeyBudget` too, and each value taken out gives it back | a peer's interests and repeats are held to `SESSION_MAX_*` together across the faces, as the ids are (`Ids` above) and as the lent pools hold them |
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
| N3d (11, 3c; step (a) landed on the lane: `a5a7f0c8bf`, `23ff61faf7`, `46c8fd37e8`) | link memory on the heap arm alone (3.6), its source a type the engine names, not a feature; (a): the cells by `CountKind::Cells`, `OnHeap` and `LinksOnHeap` on use (7.18); (b) the buffers by `CountKind::Buffers`, `HeapBuffers` sized to the batch on use (`99cc01afed`, `ff65049f24`; 7.19, 7.20); (c) the ports (`5c5f545604`; 7.22), the groups (`339c959c64`; 7.23) and the kept publishes (`1d5b2e25d0`, `a405ec1189`; 7.25) | `crates/wz-runtime-coop` (`link_cells.rs` `heap_head`, `kept.rs`, `link_storage.rs`) | -1,000 to -2,000 | 0 to -30 | section 5 |
| N3e | a key held apart from every row (an object outside the lock: `KeyRef::hold_apart`, `KeysLocked::adopt`, `SampleView::keyexpr_held`) as a `HeapKey` clone taken and let go of under the lock, read by its text outside it | `key_arena.rs` beside `on_use.rs`, `sink.rs`, the engine's object paths | -200 to +200 | 0 | 0 |
| N4 | the doors: 3.7 | `crates/wz-capi-pico` (`process_pool.rs`, `object_slot.rs`, `bytes.rs`) | -2,000 to -3,000 | 0; the put's to be read | -0 to -8 KiB a pair |
| **R1, step 0 (landed on the lane: `6b6041bf09`)** | the policy of the session's tables stated once, by `build.rs` (`TablePolicy`), as the cfg of its name (`wz_lent`, `wz_on_use`): an item that differs by the policy reads its name, one that differs by where the counts come from reads `runtime-plan` (7.9) | `crates/wz-capi-coop` (`build.rs`, `lib.rs`, `arena.rs`, `engine.rs`, `engine/{registry,registry/held,state_places,query,decl_watch}.rs`, `round.rs`, the tests) | 0 (every predicate is the one it replaced) | 0 | 0 |
| **R1a (landed on the lane: `01cf14693c`)** | `tables-on-use` names `OnUse` in a build laid out from its config too, but where the session takes faces beside its dial role's (`listen`, `group`); its registry, keys, state and plain tables are the client form's, their counts the config's (7.9) | `crates/wz-capi-coop` (`build.rs`, `lib.rs`, `tests/on_use.rs`), `scripts/lib/nondefault-tests-gate.sh` | no case builds the planned on-use form yet (`config-policy` beside `wz-capi-coop/tables-on-use`); D12 0 | 0 | as N3c's client form |
| **R1b, step 1 (landed on the lane: `1063768725`; dropped by `12e8da2c40`)** | the owed tokens' split on `OnUse`: `FixedIdMap::split_off` moves a fixed table's rows whole and keeps its refusals; `PeerTokens::<OnUse>::split_off` hands a face's tokens over as a table of their own, their keys still counted against the session's budget, and `None` for a table of no token (11.1, R1b, 3; 7.10). The relation of step 2 moves tokens, not tables, so both splits and their tests were dropped | `crates/wz-session-core` (`id_map.rs`, `declare/liveliness_subscriber.rs`) | 0 | 0 | 0 |
| **R1b, step 2 (landed on the lane: `8988bd43f3`, `3963ecf41d`)** | the tokens of the faces that went owed on `OnUse` as a relation of tokens keyed by face and id (`OwedTokens`, `FaceToken`), its bound kept by the faces' admission (`admits_face`); the engine names both forms by one type (`engine/registry/owed.rs`, `Owed`) (7.11) | `crates/wz-session-core` (`declare/liveliness_subscriber.rs`, `slot_observer.rs`), `crates/wz-capi-coop` (`engine/registry.rs`, `registry/{owed,adding}.rs`) | 0 (the lent arm is the code it replaced) | 0 | 0 |
| **R1b, step 3 (landed on the lane: `d269055bd4`)** | the listening and grouped forms' registry on `OnUse`: `Registry::counted` generic over `Holders` and over the plan's `GetTables` and `FacePeers`, `ManyHolders` of `RowPolicy` with `Holders::counted`, `SpareSets`' on-use form (a set built at a place's first face, counted in its row), the rooms' places at `MAX_FACE_SETS` in the state, the plan's rows of the held index and the owed tokens the lent form's alone; `build.rs` names `OnUse` whatever faces the session takes (7.12) | `crates/wz-capi-coop` (`build.rs`, `lib.rs`, `arena.rs`, `engine.rs`, `engine/registry.rs`, `registry/{counted,held,adding}.rs`, `tests/{arena,on_use}.rs`), `scripts/lib/nondefault-tests-gate.sh` | 0 for every D12 case (no D12 build names `tables-on-use`); no case builds the listening on-use form until N5 | 0 | the on-use listening session: its sets' rows from the allocator at the open instead of the arena |
| **R2 (landed on the lane: `c4105747a2`, `657b23623c`)** | the admission in an allocation of its own (`OwnPlaced`, as the rooms are) and each read slot of a face past the dial role's made at its place's first face (`OnceRows`, `DirectFaces::made_at`), a refusal answered as a face past `max_faces`; the plan lays out neither, and `SessionArena::arena_mut` is the D12 forms' and the tests' again (7.13) | `crates/wz-capi-coop` (`arena.rs`, `engine.rs`, `engine/direct.rs`, `engine/direct/once_rows.rs` (new), `engine/faces_added.rs`, `engine/state_places.rs` (a test's name), the tests), `scripts/lib/nondefault-tests-gate.sh` | 0 for every D12 case (each predicate added reads `not(wz_on_use)` over the code it guarded) | 0 for D12; on use a walk of the faces reads one pointer a row | the on-use listening session: a face's slot, its Router among it, from the allocator at its place's first face; the admission at the open |
| **R2, the rooms (landed on the lane: `e5ee0e0d5a`)** | the places of the faces' rooms on use as the faces' read slots are (`OnceRows`, moved to `engine`): rows counted to the plan's sets at the open, each face's place made at its first hold of a wait and kept; `FACE_SETS` the region form's alone (7.14) | `crates/wz-capi-coop` (`engine.rs`, `engine/once_rows.rs` (moved), `engine/direct.rs`, `engine/registry.rs`, `engine/state_places.rs`, `tests/{congestion,on_use}.rs`) | 0 for every D12 case | 0 | the on-use session: its rooms' places one row a set and one place a face it held, in place of `MAX_FACE_SETS` places in its state |
| **R3's residues (landed on the lane: `17511020b8`, `92347c4f82`, `f59630b1bd`)** | the session's bounds of what its peers write held on use by the key budget (`KeyBudget::holding_peer_rows_to`, `take_peer_row`), a peer's ids a `CountedIdMap` taking its rows at its first id and a row of its kind from the budget for each NEW id, and a group's aliases counted to `GROUP_FACE_ALIASES` (`PeerIds::recount`) (7.15) | `crates/wz-session-core` (`on_use.rs`, `id_map.rs`, `bounded.rs`, `pubsub.rs`), `crates/wz-capi-coop` (`engine/state_places.rs`, `engine/registry/counted.rs`) | 0 for every D12 case; on use each face's set smaller by its peer's inline id rows | 0 | the on-use session: a peer's id rows from the allocator at its first write of each kind |
| **R3's residues, the sequences (landed on the lane: `225c3f0b0e`)** | a peer's interests and repeats on use a `CountedSeq` (`Storage::Pooled`), each value a row of its kind of the session's key budget, so `SESSION_MAX_INBOUND_SUB_INTERESTS` and the repeats' share of `SESSION_MAX_REMOTE_DECLS` bind across faces; `RowList::take_rows`, so a repeat whose alias finds no memory is refused before its key is made or its id bound (7.16) | `crates/wz-session-core` (`row_pool.rs`, `bounded.rs`, `id_map.rs`, `declare/{subscriber,queryable}.rs`, `pubsub.rs`, `peer_tables.rs`) | 0 for every D12 case (`Lent` and `Region` keep their `Pooled`; `take_rows` answers `true` on them, a constant the check folds to); on use each face's set smaller by its inline interest and repeat rows | 0 | the on-use session: a peer's interest and repeat rows from the allocator at its first of each |
| **R3, 3b: the runtime (landed on the lane: `a0a99b28b6`, `26217c7d5b`)** | the on-use session's runtime and local set of the allocator in the form the D12 forms place in the arena (`CoopRuntime::try_formed`, `try_taskless`; `RuntimeTables::made`); its plan lays out the count the arena is kept by alone (`ArenaPlan::lay_keep`), no runtime span; `OpenHolds::runtime`, `OpenPlaces::runtime`, `SessionLent::runtime`, `RuntimeTables::{runtime, placed_bytes, of_shape}`, `SessionArena::{runtime_place, kept_span}` are the D12 forms' alone (7.17) | `crates/wz-runtime-coop` (`executor.rs`, `runtime_impl.rs`, `table_tests.rs`), `crates/wz-capi-coop` (`arena.rs`, `engine.rs`, the tests of `arena`, `direct_runtime`, `on_use`, `runtime_tables`) | 0 for every D12 case (each predicate added reads `not(wz_on_use)` over the code it guarded); on use: `CoopRuntime::placed` and its span's reckoning (`PlacedParts`) leave the form, one heap maker of the build's form and `CoopLocalSet::try_new` come in | 0 | the on-use session: the runtime's state, task table and timer entries from the allocator at the open in place of the arena's span |
| R3 and R4 | the zenoh-pico preset's own library (`peer`, `multicast-transport`, so `runtime-plan`) on use: the listening and grouped forms' holders, sets and owed tokens on use and `build.rs`'s `!takes_faces` dropped (R1b, landed), the admission and the direct faces' slots per face (R2, landed), the listening and grouped stacks' memory (R3), its arena out (R4) (11.1) | `crates/wz-capi-coop` (`lib.rs`, `engine.rs`, `engine/registry/counted.rs`, `engine/state_places.rs`, `engine/direct.rs`), `crates/wz-runtime-coop` (the stacks' ports and groups) | the preset's library, read once N5 resolves it so | 0 | section 5 |
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
  at the open. `FACE_SETS`, the places of the faces' rooms the state keeps, was `MAX_FACE_SETS`
  where the build takes faces, about a thousand places at the open whatever the config; 7.14
  makes each face's place on use and keeps `FACE_SETS` the region form's. The
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
  `SESSION_MAX_REMOTE_DECLS` is not held across faces on `OnUse` (7.11) (both repaid for a peer's ids by 7.15); the admission, the direct
  faces' slots, the transport's tables and the kept publishes are still lent from the arena
  (R2, landed: 7.13; R3, R4).
- D12: no D12 build names `tables-on-use`, so no predicate of one moves but the plan's
  `FACE_ROWS` (the same value on `Lent`) and `SpareSets::build`'s refusal, now `FacesFull`
  where the caller mapped it before. C1cs's readings are not expected to move.


### 7.13 R2: the admission and the faces' read slots on use

- What it does (`657b23623c`): where the tables take their memory on use, the admission the
  links ask (`Core::_admission`, `link-admission`) lies in an allocation of its own the open
  reserves and fills (`OwnPlaced`, as the rooms are), and the read slot, send place and Router of
  each face past the dial role's (`DirectFace`) is made at its place's first face, in an
  allocation of its own, and kept where it lies for the session's life and the next face of its
  place, as the place's set of tables is (7.12). The rows are a counted table of write-once
  pointers (`engine/direct/once_rows.rs`, `OnceRows`), taken whole at the open from the plan's
  count (`sets - 1`); a row's face is published once by a compare-exchange and never moved or let
  go of while the table stands, so the read walks the rows with no lock, as it walked the lent
  table, and a reader that sees a row made reads a face that stays (`OnceRows: Sync` asks
  `T: Send + Sync`, as `OnceLock` does). The face is made under the session's lock at both
  places a face is given a row: an attach (`CoopEngine::attach_face`, before anything is
  dialled; a refusal is `Refusal::FacesFull`, the registry's set given back) and a port's
  connection (`CoopEngine::accept_links`, after `Core::take_face`; a refusal closes the link
  unread, the face removed). The Router is made over the session's chain buffers the open kept
  for it (`Core::face_chains`, `Core::face_router`). The walk's bound counts rows, a row of no
  face skipped (`DirectFaces::taken_walked`, `hold_face`). The plan lays out neither
  (`ADMISSION_ROWS`, `DIRECT_FACE_ROWS`, `lay_admission`, `lay_direct_faces`,
  `OpenHolds::admission`, `direct_face` are the D12 forms'), and `SessionArena::arena_mut` is
  compiled outside the on-use form and in the tests alone again.
- Why not lazily per face and given back when the face goes: the read walks the rows with no
  lock, so a face given back while a read holds it would need a reclamation scheme (epochs or
  hazard pointers) the receive would pay on every walk; a face kept for its place is the set's
  rule (7.12) and bounds the memory by the faces the session ever held at once.
- The census of the non-default tests (C1cn): the all-features build is the on-use form since
  R1b's switch, so every test compiled only there is in its population and claimed only by a leg
  of `tables-on-use` whose filter, `on_use`, its path names. One was not:
  `engine::state_places::tests::an_own_vacant_allocation_holds_nothing_until_it_is_filled` (3a),
  now `an_on_use_vacant_allocation_holds_nothing_until_it_is_filled` (`c4105747a2`; its record
  in `sz-open.md` renamed with it). The new tests carry `on_use` in their names, and the
  admission's test, compiled with `link-admission` alone, has a leg of its own
  (`link-admission,tables-on-use|on_use`). The public surface census
  (`feature_public_surface_census.py`) reads `#[cfg(feature = ...)]` sites on public items in the
  source, not a build: no public item changed its gate, so it does not move.
- Tests:
  - `engine::direct::once_rows::tests` (`listen`, on use), three:
    `an_on_use_rows_value_is_made_at_its_first_use_and_kept_there` (red if `counted` makes its
    rows' values, if `made` makes a second value for a made row, or if `OnceRow`'s drop skips a
    made value or drops an empty row's); `an_on_use_row_made_twice_at_once_keeps_the_first_value_published`
    (the inner make reached from the outer one's write; red if `made` stores over a published
    value, a plain store in place of the exchange, or the losing value is kept or dropped twice);
    `an_on_use_table_of_no_row_holds_none` (red if `counted` pushes past `rows`).
  - `tests::on_use::an_on_use_face_takes_its_read_slot_at_its_places_first_face` (`listen`, not
    `wz_round`): no slot at the open (the CONTROL), one once a face is attached, which comes up.
    Red if the open makes every row's face, or if `attach_face` leaves `made_at` out (the face
    then has no slot a read turns and never comes up).
  - `tests::on_use::an_on_use_sessions_link_admission_lies_apart_from_its_arena`
    (`link-admission`). Red if the open places the admission in the arena (`Arena::place`).
  - `tests::arena::each_face_read_where_it_lies_is_lent_a_share_of_chain_buffers_of_its_own`
    reads no row of the faces' slots on use and keeps its D12 reading; the shares of the chain
    buffers are the same in both forms. `tests::face_routers` makes every row's face first on use
    (`CoopEngine::make_every_face`), as each row's first face would, and `direct_faces` counts
    the table's rows, made or not, so `tests::listen`'s walk tests read the same counts in both
    forms.
- Not tested: an attach or a connection refused because the allocator has no room for the face,
  or the open for the rows or the admission; only a refusing allocator reaches them.
- D12: `TakenFaces` is the lent table, `taken_in`, `lay_direct_faces` and `lay_admission` the
  code they were, the two walks' lent arms the lines they were; C1cs's readings are not expected
  to move.

### 7.14 R2, the rooms' places on use

- What it does (`e5ee0e0d5a`): 7.12 put the places of the faces' rooms (`LinkRooms`, what a
  droppable publish that finds the session held asks each face for) in the on-use session's own
  state at `MAX_FACE_SETS`, `1 + MAX_FACES + GROUP_FACES`, about a thousand places taken at the
  open whatever the config. They are now the faces' read slots' form (7.13): a table of
  write-once rows counted at the open to the plan's sets (`RoomPlaces` is
  `OnceRows<Option<RoomPlace>>`), each face's place made at its first hold of a wait
  (`LinkRooms::hold`, through `RoomTable::taken` and `OnceRows::made_mut`) and kept for the
  session's life and the next face of its place. `OnceRows` moved from `engine::direct` to
  `engine` (every on-use build has rooms), and gained the forms a table under a lock of its own
  asks: `made_mut` and `row_mut`, with the table held alone, so no exchange. `StatePlaces`
  keeps no rooms' field on use, and `FACE_SETS` is the region form's alone again, at 1 (`listen`
  and `group` each name `runtime-plan`, so no region build takes faces).
- Why not the face's own owner: a face's place is read by the publish that finds the session
  held under the rooms' lock alone, at every place in turn, the dial role's and a group's among
  them; the rooms are the one layer that holds those facts for every face, as section 5 asks.
- Why at the first hold and not at the face's admission: a place no face made reads as a place
  no face holds, which the table already answers for (a face whose link gives no wait never holds
  one). A place the allocator has no room for leaves its face naming no wait: no publish asks it
  for room, `skips` sends it every publish, and `dropped_on` names every face, each the answer
  the table gives a face of no wait; nothing else is refused or lost.
- D12: `RoomPlaces` is the lent table, `RoomTable::over` the push of a free place for every row
  that `LinkRooms::init_at` made, and `taken`, `held`, `place` and `free_all` the slice calls
  each call site made; C1cs's readings are not expected to move.
- Tests:
  - `engine::once_rows::tests::an_on_use_row_held_alone_is_made_at_its_first_make_and_changed_in_place`
    (every on-use build): red if `made_mut` makes a second value for a made row or none, or if
    `row_mut` reads a row not made as past the rows. `an_on_use_table_of_no_row_holds_none` now
    asks `row_mut` and `made_mut` too and runs without `listen`; the other two keep `listen`.
  - `tests::congestion::an_on_use_rooms_place_is_made_at_its_faces_first_hold`: four rows and
    no place at the making (the CONTROL), one place once a face holds a wait, still one when it is
    let go of and its place held again, none past the table, and the place made is the one a
    publish asks (`tx-held-wait`). Red if `RoomTable::over` makes every row's place, if
    `RoomTable::held` makes one, or if `RoomTable::taken` reads through `row_mut`.
  - `tests::on_use::an_on_use_session_with_one_face_holds_one_room_place`: a session with its one
    face up holds one place. Red if the open makes every row's place, or if a face that comes up
    makes none.
  - `engine::state_places::tests::the_rooms_places_take_the_regions_sets_at_most` is the region
    and lent forms' alone.
- Not tested: a hold the allocator refuses; only a refusing allocator reaches it.

### 7.15 R3's residues: the session's bounds of what its peers write, and a group's aliases

- What it does (`17511020b8`, `92347c4f82`, `f59630b1bd`): on `Lent` the rows a peer writes by
  its own choice lie in pools the session's faces share, so `SESSION_MAX_PEER_KEYEXPR_ALIASES`
  and `SESSION_MAX_REMOTE_DECLS` bind across faces; on `OnUse` each face's table was a
  `FixedIdMap` at the build's bound, inline, which held neither, and could not hold a group's
  face to `GROUP_FACE_ALIASES` above `MAX_PEER_KEYEXPR_ALIASES` (7.12's residues).
  - `KeyBudget` is the one value every table of an on-use session reaches (through
    `BudgetKeys`, its `Storage::Keys`, lent to every `PeerIds::lend`): it now keeps, beside the
    key bytes, the rows of each `PeerSlot` kind the session's peers hold together and the
    session's bound of each (`holding_peer_rows_to`, from `SessionLimits`: the aliases'
    `SESSION_MAX_PEER_KEYEXPR_ALIASES`, the declarations' and their repeats'
    `SESSION_MAX_REMOTE_DECLS`, the interests' `SESSION_MAX_INBOUND_SUB_INTERESTS`, as
    `PeerPoolRows` sizes the lent pools). `take_peer_row` refuses past the bound, taking
    nothing; `give_peer_rows` gives back. `OwnState::place` writes the budget so held.
  - `OnUse::Ids` is `CountedIdMap<V, N>` (`id_map.rs`): a `FirstUse` column of `(id, value)`
    rows counted to `N`, taken at the first id, a scan as `FixedIdMap`'s. It answers `IdMap`
    only lent its owner's handle (`CountedIds`, so no path binds past the budget); a NEW id takes
    a row of the slot's kind from the budget after the table's own count and quota admit it, and
    gives it back if the allocator refuses the column; `unbind`, `reset` and `PeerIds::release`
    (which every owner calls before it drops a table or changes its keys, as a pooled table's
    owner does) give the rows back. A handle of no budget holds the table to its own count alone.
  - `PeerIds::recount` (a provided method, `false` for every other backing): a counted table
    that holds no id takes a new count, its rows given back. `SubscriberPeer::limit_aliases_to`
    recounts the alias table to its quota, so `PeerTables::limit_to` counts it to the config's
    `MAX_PEER_KEYEXPR_ALIASES`, `hold_member_aliases` to `GROUP_FACE_ALIASES` (the set is fresh)
    and a set given back (`let_go`, `remove_accepted_faces`, after `forget_peer` reset the
    aliases) to a peer's again.
- Not covered by these three commits, closed by 7.16: the interests and the repeats of a peer's
  declarations were `Storage::Pooled`, inline at the build's bound on `OnUse`, and reached
  through `PeerSeq`, not `PeerIds`, so `SESSION_MAX_INBOUND_SUB_INTERESTS` and the repeats'
  share of `SESSION_MAX_REMOTE_DECLS` were per face there.
- D12: `Lent` and `Region` keep their `Ids`; `PeerIds::recount` answers `false` on them, so
  `limit_aliases_to` stores the quota alone, as before. C1cs's readings are not expected to move.
- Size, on use: a peer's table is a `CountedIdMap` head (about 24 bytes) in place of
  `N` inline rows (`MAX_PEER_KEYEXPR_ALIASES` rows of an alias, `MAX_REMOTE_DECLS` of each
  declaration kind), so every face's set shrinks by those rows, and they are taken from the
  allocator at the peer's first write of each kind; `KeyBudget` grows by seven counts.
- Tests:
  - `on_use::tests::a_budget_holds_the_rows_its_peers_write_together_to_the_sessions_bounds`:
    red if a kind is counted against another's count or bound, if a refused row is counted, or
    if a row given back stays held.
  - `id_map::tests::an_on_use_table_holds_its_faces_ids_to_the_sessions_bound_together`: two
    faces' tables held to a session bound of two together, a replaced id needing no row, an
    unbind and a release giving rows back. Red if `bind_within` asks no row of the budget, or if
    `unbind`, `reset` or `release` give none back, or if the table takes rows when made.
  - `id_map::tests::an_on_use_table_is_recounted_only_while_it_holds_no_id`: red if a table that
    holds ids is recounted, or if a recount keeps the rows taken.
  - `pubsub::on_use_alias_tests::an_on_use_alias_table_is_counted_to_its_quota`: red if
    `limit_aliases_to` stores the quota alone.
  - `engine::state_places::tests::an_on_use_state_holds_the_sessions_key_budget_and_its_places`
    now takes the session's `SESSION_MAX_REMOTE_DECLS` of tokens and is refused the next: red if
    `OwnState::place` leaves `holding_peer_rows_to` out.
  - `engine::registry::counted::tests::an_on_use_groups_face_counts_its_aliases_to_every_members`
    (`multicast-declarations`): red if the group's face keeps a peer's rows, or if a set given
    back keeps the group's count.

### 7.16 R3's residues, the sequences: a peer's interests and repeats held per session

- What it does (`225c3f0b0e`): `OnUse::Pooled` is `CountedSeq<T, N>` (`row_pool.rs`), the
  sequence form of 7.15's `CountedIdMap`: a `FirstUse` column counted to `N`, taken at its
  first value, that answers `RowList` only lent its owner's handle (`CountedSeqMut`, so no path
  writes past the budget). A pushed value takes a row of the slot's kind from the session's
  `KeyBudget` after the column's own count admits it, and gives it back if the allocator refuses
  the column; `remove_first`, `retain` (by the count it dropped), `clear` and
  `PeerSeq::release` give rows back. A handle of no budget holds the sequence to its own count
  alone. The budget already held the bounds of both kinds (`holding_peer_rows_to`: the interests'
  `SESSION_MAX_INBOUND_SUB_INTERESTS`, each repeat kind's `SESSION_MAX_REMOTE_DECLS`), and
  `OwnState::place` already wrote it so: the engine needs no change.
- A refusal the inline form never met: a peer's repeat is bound in its declarations' table and
  recorded as an alias, and the alias's push could not fail inline. On use the alias column takes
  its memory at the first alias, so the allocator can refuse it. A repeat bound with its alias
  lost would stand in the table under an id the application was never told of, and its withdrawal
  would report that id. `RowList::take_rows` (provided, `true` for a table whose rows were laid
  out when it was made) takes a first-use column's memory before its first value;
  `apply_declared` of the subscriber and the queryable side asks it of the aliases (`LentAliases::take_rows`)
  before the repeat's key is made or its id bound, and refuses the repeat as a declaration the
  table has no room for (`count_refused`). The budget cannot refuse the alias's row: every alias
  is an id its kind's table holds, and both kinds have the same session bound, so the repeats a
  session holds stay under the declarations it holds. The ids of a peer's tables keep their count
  (no recount: no quota of either kind is above the build's).
- D12: `Lent` and `Region` keep their `Pooled`; `take_rows` is the provided `true` there, so
  the check folds away and the order of `told_as` before the key, which reads the table only, is
  the one change on those paths. C1cs's readings are not expected to move.
- Size, on use: a face's set no longer holds `MAX_INBOUND_SUB_INTERESTS` interest rows (each
  an `InboundSubInterest`, its key a `HeapKey`) nor `MAX_REMOTE_DECLS` alias rows of each repeat kind (16 bytes each)
  inline; it holds a `CountedSeq` head (16 bytes) of each, and the rows come from the allocator
  at the peer's first interest or repeat.
- Tests:
  - `row_pool::tests::an_on_use_sequence_holds_its_faces_rows_to_the_sessions_bound_together`:
    two faces' sequences held to a session bound of two interests together. Red if `push` asks
    no row of the budget, if `remove_first`, `retain` or `release` give none back, or if a
    sequence takes its rows when made.
  - `row_pool::tests::an_on_use_sequence_the_allocator_refuses_takes_nothing`: red if
    `CountedSeqMut::take_rows` is the provided `true`, or if a push the allocator refused keeps
    its row of the budget.
  - `row_pool::tests::an_inline_sequence_and_a_pooled_one_answer_alike` runs the on-use
    sequence beside the inline and the pooled ones: red if `CountedSeqMut` answers `RowList`
    otherwise than they do.
  - `peer_tables::on_use_tests::an_on_use_subscriber_repeat_with_no_alias_row_is_refused_whole`
    and `..._queryable_repeat_...`: a repeat dispatched with every allocation refused is not
    bound, is counted, and its key was never made (the budget counts no refused key). Red if the
    `take_rows` check is left out (the key's refusal would be counted by the budget) or moved
    after the bind (the repeat would stand).

### 7.17 R3, 3b: an on-use session's runtime of the allocator

- What it does (`a0a99b28b6`, `26217c7d5b`): the runtime has had a heap maker of each form but
  the taskless one; `CoopRuntime::try_taskless` (over `ExecutorState::try_taskless`, a table of
  no cell laid as one cell that holds none, as the placed one is) is the fourth, and
  `CoopRuntime::try_formed` the heap's twin of `placed`: the maker of the form named, then the
  local set (`CoopLocalSet::try_new`). It is always inlined, and the engine names its form by
  constants of the build (`RuntimeTables::form`), so a build links the one maker of its form.
- The engine's on-use form makes its runtime by `RuntimeTables::made` at the point the D12 forms
  place theirs, refused as the heap's (`heap_refused` of the tables' `reserved_bytes`).
  `lay_out_open` lays out no runtime span there (`ArenaPlan::lay_runtime` is the D12 forms'),
  and lays out the count the arena is kept by alone (`ArenaPlan::lay_keep`), which the engine
  still takes (`SessionArena::keep`, 3a) for what of the arena it holds until 3d. Every item
  that carried the span (`OpenHolds::runtime`, `OpenPlaces::runtime`, `SessionLent::runtime`,
  `RuntimeTables::{runtime, placed_bytes, of_shape}`, `SessionArena::{runtime_place,
  kept_span}`, the `RuntimePlace` imports) reads `not(wz_on_use)`; `open_holds` takes the span's
  bytes only there (a parameter under the same predicate).
- D12: unchanged; each predicate added reads `not(wz_on_use)` over the code it guards.
- Size, on use: `CoopRuntime::placed`, `PlacedParts::of` and the placed constructors of the
  task store, the timer table and the local set's owner leave the form; one heap maker and
  `CoopLocalSet::try_new` come in. The arena is smaller by the runtime's span; the allocator
  gives the same bytes at the open, in three allocations (the state, the cells, the set's owner)
  and the timer entries' where the build has timers.
- Tests:
  - `table_tests::a_runtime_made_of_the_heap_by_its_form_holds_that_forms_table`: red if
    `try_formed` makes the taskless form with the rows' cells (the spawn would be taken), or the
    form of one task with none (the CONTROL spawn would be refused).
  - `table_tests::a_runtime_the_heap_has_no_room_for_is_not_made` asks `try_taskless` and
    `try_formed` too: red if either ends the process on a refused allocation.
  - `tests::on_use::an_on_use_plan_lays_out_no_place_for_the_engine_the_rooms_or_the_runtime`
    (renamed from `..._for_the_engine_or_the_rooms`, 7.8): red if `lay_out_open` lays the
    runtime's span in the on-use form, or leaves the arena's count out with it.
  - `tests::runtime_tables` (`wz_round`) and `tests::direct_runtime` (the direct read) make
    their runtime by `RuntimeTables::made` in an on-use build, so each on-use leg holds the made
    runtime to the cells the D12 form's placed one holds.

### 7.18 R3, 3c, step (a): a link's cells made through its kind's source

- What it does (`a5a7f0c8bf`, `23ff61faf7`, `46c8fd37e8`): where a link's parts are made is the
  handle's kind's to say, `CountKind::Cells`, a `CellSource` (`crates/wz-runtime-coop/src/link_cells.rs`):
  `Option<LentByteCells<F>>` for the kinds a session may lend a table to (a table while one is
  lent, refused past its cells; the heap while none is), `HeapCells` for `OnHeap<N>`, a kind
  counted as `N` counts whose every cell is the heap's. `CellRc::{in_cells_of, claim_of,
  halves_in_of}` take the source by reference and reach the cell through `head_of`, which calls
  the out-of-line `head_in` for a source that lends (`CellSource::LENDS`) and `heap_head` alone
  for one that does not, so a build whose kind is `OnHeap` instantiates neither `head_in` nor
  `table_head` and makes no `Owner::Table`. `try_on_heap` and the two entropy holders and the
  ports' book, which were placed through `None`, name `HeapCells`; the one task's conveniences
  (`in_cells`, `claim`, `halves`, `halves_in`) keep their `Option<&LentByteCells>`, the source
  of the kinds that lend.
- The stacks (`ip_stack`, `app_link`, `serial_link`, `unixpipe_link`, `ws_link`, `either_links`)
  and the transport (`TransportState::{gate,actions,halves}_cells`, `LinkCalls::gate`) hold
  `N::Cells`, and `SessionLinks::lend_cells` hands the source itself, so a heap kind's stack is
  never lent a table: the type has none to take. The kind reaches the stacks by the type every
  program already names (`counted_by::<wz_capi_coop::LinkCount>()`), and the runtime by its lock
  kind: `sync::LinksOnHeap<K>` is `K` in every item but `LinkCount`, which is
  `OnHeap<K::LinkCount>`. A feature of `wz-runtime-coop` could not say it (3c above).
- The engine (`46c8fd37e8`): on `wz_on_use` `LinkCount` is `OnHeap` of the form's kind and
  `SessionLock` is `LinksOnHeap<FormLock>` (`form.rs`; `FormLock` is `LockForm::SessionLock`, which
  the direct read's assertion of a lock of each value's own now reads). `lay_out_open` lays out
  no table of cells, `OpenHolds::cells`, `TransportTables::cells`, `TransportRows::cells_from`,
  `OpenRegion::cell_bytes`, `cells_of`, `link_cells` and `LinkHalves` are the D12 forms' alone, and
  the open hands the stack and the transport `HeapCells`. `ArenaPlan::holding_cells` stays the
  plan's public word in every form.
- D12: the kinds and their sources are the ones they were (`Option<LentByteCells>` is what each
  stack held), `lend_cells` is called with the arena's `Option` once instead of behind an
  `if let`, and `try_on_heap` calls `heap_head` directly rather than `head_in(None)`.
- Size, on use: `table_head`, `head_in`, the table arm of every cell's maker and the lend of four
  tables of cells leave the form; the arena is smaller by the four tables (a flag and a cell for
  each link of each); each link's parts are three or four blocks of the allocator at its open.
  Receive Ir: none (cells are made at a link's open, not per batch).
- Tests:
  - `link_cells::tests::each_source_makes_its_cells_where_it_says`: red if `head_of` calls the
    heap's maker for a source that lends (a full lent table would hand back a heap cell), or a
    source of no table claims none.
  - `link_cells::tests::a_handle_whose_cells_are_the_heaps_counts_as_its_kind_does`: red if
    `OnHeap` counts apart from the kind it wraps (two handles counted otherwise, the value let go
    early) or its source makes no cell.
  - `ip_stack::tests::links_whose_cells_are_the_heaps_open_each_link_on_the_heap`: red if a stack
    of a heap kind refuses a link for want of a cell, or its sink and pump are not one cell.
  - `sync::tests::a_kind_whose_links_cells_are_the_heaps_is_its_kind_in_all_else`: red if an item
    of `LinksOnHeap` is not the wrapped kind's.
  - `tests::on_use::an_on_use_plan_lays_out_no_place_for_the_engine_the_rooms_or_the_runtime`
    asserts no table of cells too; `tests::on_use::an_on_use_sessions_link_parts_lie_on_the_heap`:
    red if the on-use open lends its transport a table of cells.
  - On use, `tests::arena::a_links_halves_lie_in_its_cell_across_a_redial` and
    `arena::tests::the_cells_of_each_kind_held_are_lent_past_the_kinds_with_none` are not compiled:
    the form lends no cell.

### 7.19 R3, 3c: the ports' slots and the groups' buffers lent apart, and the reds of hn9 and hn10

- What it does (`99cc01afed`): `LinkTables` holds the links' receive and outbound tables and
  their places and nothing else; the slots a session's udp ports read into and the buffers its
  groups receive into reach the stack by seams of their own, `SessionLinks::lend_port_rows(rows,
  slots)` and `SessionLinks::lend_group_rx` (a default that ignores them; `IpLinks` and
  `AppLinks` keep them, the stacks that wrap one forward them). `TransportTables` gains
  `group_rx` and `port_slots`, lent after the links' tables in the order the plan lays them out
  (`TransportRows::group_rx_from`, `port_slots_from`). Why first: a source of the heap (7.20)
  holds no table, and a build whose udp ports are lent-only (`udp-port-lent-only`, which
  `wz-capi-coop/udp-listen` names) must still reach its ports' slots, so they could no longer
  ride inside the links' tables.
- The reds of hn9, three tests this lane added that had not run green before (earlier legs did
  not compile):
  - `1e47d9d865`: an on-use session that dials nothing counts its dial set to no row
    (`count_set`), since an on-use table's default is counted to the build's `N` and a set
    pushed rowless kept finals' room. The code was wrong; `counted.rs`'s test is unchanged.
  - `7e09c2c4ed`: `hold_member_aliases` returned early when the quota already admitted
    `GROUP_FACE_ALIASES`, but an on-use `CountedIdMap` holds no more ids than its count,
    whatever its quota admits. `SubscriberPeer::hold_aliases_at_least` raises the quota and the
    count each where it falls short (`PeerIds::counted_rows` says the count). D12 unchanged.
  - `e335e9a48d`: the router stand-in is a udp peer, whose driver answers no room wait, so no
    face holds a room and no room place is made; the test's claim was wrong and is now
    `an_on_use_session_makes_no_room_place_its_faces_do_not_hold`, `made == 0`.
- The reds of hn10 (leg `app-transport,group,multicast-declarations,liveliness,tables-on-use
  --lib`, which runs the whole on-use suite):
  - `461f658b2a`: `limit_aliases_to` counted an alias table anew only for a quota with a most,
    so where the peer quota bounds nothing a group face's place kept `GROUP_FACE_ALIASES` rows for
    its next face. A quota of no most now counts the table back to the rows it was made with
    (`PeerIds::recount_as_made`, `CountedIdMap`'s `N`; nothing for a table with no count). The
    code was wrong; `counted.rs`'s `an_on_use_groups_face_counts_its_aliases_to_every_members`
    is unchanged and `id_map`'s `an_on_use_table_is_recounted_only_while_it_holds_no_id` reads
    the count as made (red if it is anything but `N`, or if a fixed table claims one).
  - `dbac74a3ed`: `the_pools_hold_the_fewer_of_the_sessions_limit_and_what_its_faces_could`
    read the row of the declarations' pools, which the plan lays out only where the arena lends
    the pools (`wz_lent`); on use they are counted. The test's premise was the lent form's: it
    reads the row under `wz_lent` and asserts its absence under `wz_on_use`.
- Tests of `99cc01afed`: `ip_stack`'s `a_port_reads_into_the_slots_its_session_lent` and its
  lent-only test (rows with no slots refused, rows and slots open), the group buffers' tests of
  `ip_stack` and `app_link` (each group one buffer of what was lent), and `tests::arena`'s port
  and group tests, which lend the slots and the buffers after the links' tables. Removed:
  `link_storage`'s `the_group_receive_table_is_the_one_the_tables_were_lent`, whose table no
  longer exists.

### 7.20 R3, 3c, step (b): a link's buffers taken through its kind's source

- What it does (`ff65049f24`): where a link's buffers come from is the handle's kind's to say, as
  its cells are (7.18): `CountKind::Buffers`, a `BufferSource`
  (`crates/wz-runtime-coop/src/link_storage.rs`) with the types a link receives into and encodes
  into (`RxOf<N>`, `TxOf<N>`). `Option<LinkTables<F>>` is the source of the kinds a session may
  lend tables to (a claim of the tables while some are lent, refused past them; the link's own
  while none are), over `RxBuffer`/`TxBuffer` as before. `HeapBuffers` is `OnHeap`'s: every
  link a `Vec<u8>` and a `HeapTx` of its own, so a heap kind's drivers name no store of a
  table and the enums' table arms, `LinkTables::claim`, `PooledRx` and `PooledTx` have no
  instance in the form. `HeapBuffers::sized(bytes, slots)` is the session's shape: each link a
  receive buffer of `bytes` and `slots` slots of it whatever the stack asks, as a session's tables
  lend each link buffers of their own length; unsized (the default, what a stack holds before a
  session lends it), the stack's own shape (`HeapTx::for_link`).
- The stacks (`ip_stack`, `app_link`, `serial_link`, `unixpipe_link`, `ws_link`,
  `either_links`) hold `N::Buffers` and take each link's through it;
  `SessionLinks::lend_buffers` hands the source itself. `heap_link_buffers` is private to
  `link_storage`, behind the lent source.
- The engine: `TransportTables::links` is the kind's source (`LinkSource`), so the open hands
  `links.lend_buffers(lent.transport.links)` in every form. Where the tables take their memory on
  use it is `HeapBuffers::sized(link_bytes, LINK_TX_SLOTS)`: each link a buffer and one slot of
  the session's batch, made as it opens and given back with it, as zenoh-pico's transport holds
  one buffer of each. The plan lays out none of the links' rows (`link receive`, `link transmit`,
  `link places`), `TransportRows::{rx_buffers, tx_slots}` and `links_from` are the D12 forms'
  alone, `tx_pool_short` is `false` (no link waits on another's slot), and `LINKS_SHARE_POOLS`
  is `false`, so the report an ABI reads (`link_buffers`) counts a buffer and a slot for each
  link. `ArenaPlan::link_bytes` says the batch in every form.
- Why sized and not the stack's shape: a stream link's own shape is `STREAM_RX_CAPACITY` and
  `SESSION_TX_SLOTS` slots of it, several times what the plan's batch and `LINK_TX_SLOTS` lend
  each link today; the heap form would have grown each link's memory.
- D12: the kinds' source is `Option<LinkTables>`, the stacks held `Option<LinkTables>` before,
  and `lend_buffers` is called with `Some` of the arena's tables; the drivers' types are the same.
- Residues: on use no pool bounds the links that open (no places): the faces a session holds are
  bounded by its counted face tables, the admission and the runtime's cells, as they are for a
  link's cells since (a). The pools' limits (`RX_POOL_BUFFERS`, `TX_POOL_SLOTS`) bound nothing on
  use and are not refused there. The listening tests of `tests::arena` that read the links' rows
  read other lent rows too (`peer tables`) and are the lent form's; no leg runs them on use.
- Size, on use: the arena smaller by the links' tables (the batch and a flag for each receive
  buffer and slot, the places); each link's buffers are two blocks of the allocator at its open,
  the same bytes. The table arms of every link's buffers leave the form's text. Receive Ir: on use
  a link reads into a `Vec` with no enum to match and no pool to claim from, so not more; D12's
  receive path is unchanged (the same `RxBuffer`, reached through an `#[inline(always)]` source).
- Tests:
  - `link_storage::tests::each_buffer_source_opens_a_link_where_it_says`: red if a lent source
    allocates past its tables, or the heap's claims a table, or hands buffers of another length
    than its size says (sized `(32, 1)`: a 32-byte buffer and one 32-byte slot whatever is asked).
  - `ip_stack::tests::links_whose_cells_are_the_heaps_open_each_link_on_the_heap`: red if a heap
    kind's stack opens a link otherwise than its sources say; unsized, a datagram link reads into
    `UDP_RX_CAPACITY`, sized by its session into 512.
  - `tests::on_use::an_on_use_sessions_links_take_their_batch_of_the_heap` (new): red if the
    on-use transport is lent tables, or a source of another size than the plan's batch, or the
    report reads pools; `an_on_use_plan_from_the_config_lays_out_no_row_of_the_tables_it_counts`
    asserts no link row (its CONTROL is the endpoints' texts alone now).
  - `tests::arena::the_links_batch_is_held_to_the_snapshots` reads `link_bytes` in every form and
    the row where the arena lays it out; the port and group tests lend the links' tables only
    where they are laid out; `the_link_buffers_a_report_reads_are_the_plans_rows`,
    `the_links_rows_are_lent_first_and_the_reservation_is_still_the_plan` and
    `a_link_reads_into_the_buffer_its_sessions_arena_lent` are the D12 forms' alone.

### 7.21 R3, 3c: an on-use listener's links held to its faces, and the reds of hn12

- The bound (`de6a30cf2f`, a test alone): on use no table of buffers refuses a link any more
  (7.20), so the links a listening session holds are bounded where a face is admitted, not where
  a link's buffers are taken. Each accept path asks `Core::takes_a_face` first
  (`crates/wz-capi-coop/src/engine/faces_added.rs:91`), which refuses a link past
  `accept_pending` handshakes or past `Core::faces_full` (`:97` to `:102`, the face table
  holding the dial role's and `max_faces` places); behind it `RegistryOf::add_face`
  (`engine/registry/adding.rs:157` to `:161`) refuses a face when the index of held faces,
  counted at the open to the plan's sets (`Holders::counted`), has no free row. The stack's
  accept takes the link's heap buffers before the engine asks; a link refused is dropped in the
  same accept, so at most one link past the faces holds buffers, and only for that call. No new
  limit was needed.
- Test: `tests::on_use::an_on_use_listener_closes_a_link_past_its_faces_unread` (`listen`; the
  listener stepped on the test's thread by `step_once`, raw connections, two handshakes admitted
  so only the faces' count refuses): with `max_faces` 1 the second connection is closed unread and
  the first kept; CONTROL, with `max_faces` 2 both are kept. Red only when neither `faces_full`
  nor `add_face`'s index refuses: the two hold the same count in two layers, either alone keeps
  it green.
- The reds of hn12, both left by `ff65049f24`'s gating of the links' tables to the D12 forms:
  - `3689670ef3`: `arena.rs`'s `LinkCellFlag` and its `SessionLock` import are read on use only
    by the udp ports' rows and slots, so they read `any(not(wz_on_use), feature = "udp-listen")`.
  - `ce7e699b2c`: `engine.rs` imports `LentByteCells` for a build that listens and reads each
    face itself; on use its one reader in the library, `Core::face_chains`, spelled the full path,
    which left the import unused. The field names the import.

### 7.22 R3, 3c (c): a udp port's memory through its kind's source

- `5c5f545604`: the ports' memory is the links' kind's (`CountKind::Ports`,
  `crates/wz-runtime-coop/src/link_cells.rs`), a `PortSource` (`udp_link.rs`):
  `Option<LentPorts<F>>` for `OneTask`, `Atomic` and `OneFace` (the rows and the slots a session
  lent, `None` giving no port), `HeapPorts` for `OnHeap` (rows `PortRows<OnUse, Vec<u8>>` counted
  to the session's peers and datagrams and taken at the first of each, each port a read buffer of
  the session's batch and the spare buffers it held datagrams in). A source is read once into the
  stack's book (`shared_book`), which keeps the rows and what makes each port's reads
  (`PortSource::Reads`: the slot table, or the bytes of a read buffer); a port opened takes its
  reads there (`UdpPort::in_book`). `PortRx`, `Held`, `BookRows` and `with_rows!` became one
  type each source names (`PortStore`: `LentRx` and `LentHeld`, `OwnRx` and `Vec<u8>`), so a form
  compiles one walk of the rows and one read, chosen by type. The port, a peer's share and the book
  take the source beside the count kind (`UdpPort<S, N, P>`, `PortPeer<S, N, P>`,
  `SharedBook<N, P>`), `P` read off the links' kind because `OnHeap<N>` counts what its links
  share as `N` does. `SessionLinks::lend_port_rows(rows, slots)` became `lend_ports(N::Ports)`;
  links given nothing open no `udp/` port (`IpLinks::open_listener`, asked before the socket is
  bound). `udp-port-lent-only`, its feature set `heap-lent-ports` and its gate leg went: the lent
  form's instances are the D12 build's alone, as the selector made them (S1 of `feat-peer.md`),
  and the heap's the on-use build's.
- The heap form answers a refusal as a value: `PortRows::take` makes both tables' room before it
  writes either, so a peer is never taken without its first datagram; `OwnRx::keep` reserves
  before it copies and `give_back` before it keeps a spare buffer; a datagram refused memory is
  dropped and counted as an overflow.
- The plan (`crates/wz-capi-coop/src/arena.rs`): the counts are kept in both forms
  (`TransportRows::port_rx`, `port_peers`); D12 lays out and lends the rows and the slots
  (`TransportRows::ports_from`), on use none is laid out and the source is
  `HeapPorts::sized(links, UDP_PORT_SLOTS, batch)` (`TransportRows::ports_sized`); the engine
  hands either to its links with `lend_ports` (`engine.rs`). `LinkCellFlag`, the `SessionLock`
  import and the `Lent` import are back to their D12 cfgs (`not(wz_on_use)`, `wz_lent`), which
  `3689670ef3` had widened for the ports' rows on use.
- Tests, wz-runtime-coop (`alloc,session-unicast,udp-listen`, and the heap set). `udp_link`:
  `a_port_holds_each_datagram_in_a_buffer_a_read_gave_back` (the heap form),
  `a_book_the_heap_has_no_room_for_is_refused_and_named`,
  `a_port_counted_across_threads_is_shared_by_handles_that_cross_threads` (both sources),
  `a_port_over_lent_slots_drops_a_datagram_it_has_no_slot_for`,
  `a_peers_row_counts_what_waits_for_it` (rows on use),
  `a_port_over_lent_memory_sorts_a_peers_datagrams_without_the_heap`,
  `ports_share_their_rows_and_take_no_peer_past_them` (both sources), and three new:
  `a_source_no_session_sized_or_lent_gives_no_port` (red if `HeapPorts::book` gives rows for an
  unsized source), `heap_rows_take_their_counts_at_the_first_peer_and_no_more` (red if
  `PortRows::counted` takes memory with the book or the rows grow past their counts),
  `a_datagram_the_heap_has_no_room_for_is_dropped_and_counted` (red if `OwnRx::keep` copies
  without `try_reserve_exact`, which ends the process). `ip_stack`: the `udp_listener` module
  over a lent port (`udp_link::leaked_ports`), `a_port_reads_into_the_slots_its_session_lent`
  with the refused case of links lent nothing, and
  `an_on_use_stack_listens_on_udp_over_the_ports_its_session_sized_alone` (new; red if
  `open_listener` makes a book of its own). The two lent-only tests went with the feature.
  wz-capi-coop `tests::arena`: the D12 tests read `ports_from` and are `not(wz_on_use)`;
  `an_on_use_listening_session_sizes_its_ports_and_lays_out_none` (new, `udp-listen` with
  `tables-on-use`; red if the plan lays a port row out on use or sizes the source to other
  counts).

### 7.23 R3, 3c (c): a group's receive buffer through its kind's source

- `339c959c64`: read first, each joiner's own buffer when its session lends none: the host's
  (`HostGroupTransport`, `wz-runtime-posix`) `UDP_RX_CAPACITY` (65,535 bytes), `app_link`'s
  `DATAGRAM_MAX`, `raweth_group`'s `MAX_ETH_FRAME_SIZE`, where the arena lends each group the
  plan's group batch. Not lending on use would have each group take the widest datagram's buffer,
  so the on-use source hands the joiner the batch instead. The source is the links' kind's
  (`CountKind::Groups`, a `GroupSource` in `group_transport.rs`): `Option<LentByteCells>` for
  the kinds that lend (a claim of the table, a group past it `Exhausted` before the joiner is
  asked, `None` the transport's own as before), `HeapGroups::sized(batch)` for `OnHeap`.
  `SessionLinks::lend_group_rx(table)` became `lend_groups(N::Groups)`; a joiner is handed a
  `GroupBuffer` (`Lent`, `Sized(bytes)`, `Unsized`) in place of `Option<ByteBuf>`, and makes
  its buffer by `GroupRx::given` (`GroupRx::of_heap` for a `Vec`), which answers a heap's refusal
  as a value: the join is `Exhausted` before a socket is bound or the program asked
  (`HostGroups::join` in capi-coop over `HostGroupTransport::with_rx`, `AppGroupTransport`,
  `RawEthGroup::new` now `Option`). `HostGroupTransport::new` keeps its `Option<ByteBuf>` form
  for hosts outside a session. The stacks' `counted_by` reset the source with the kind and assert
  none was lent before.
- The plan: the group count and batch are kept in both forms (`TransportRows::group_rx`); D12
  lays out and lends the buffers (`group_rx_from`), on use none is laid out and the source is
  `HeapGroups::sized(batch)` (`groups_sized`); the engine hands it with `lend_groups`.
- Tests: `group_transport::a_group_buffer_is_the_one_its_session_gave` (red if a `Sized` buffer is
  made at the widest length, or an own buffer the maker refused is held) and
  `a_heap_source_hands_each_group_its_sized_length` (red if `HeapGroups` hands no length);
  `ip_stack::on_use_links_hand_each_group_the_length_its_session_sized` (red if `open_group`
  hands the joiner no length on use); the lent paths' tests (`heap_links_lent_group_buffers_...`,
  `app_link::links_lent_group_buffers_give_each_group_one`, the lent-buffer tests of `app_link`,
  `raweth_group` and capi-coop `host_group`) read the new seam unchanged in what they assert.
  capi-coop `tests::arena`: the D12 test of the groups' table is `not(wz_on_use)`, and
  `an_on_use_session_sizes_its_groups_buffers_and_lays_out_none` (new, `group` with
  `tables-on-use`; red if the plan lays a group buffer out on use or sizes another length).

### 7.24 The reds of hn14

- `78aef50565`: `PortSource::book` names what it gives by a type, `BookParts<S, R, Reads>`
  (`crates/wz-runtime-coop/src/udp_link.rs`), the book's rows and what makes each port's reads,
  which clippy's `type_complexity` refused spelled inline.
- `3d6b72f7c5`: `ip_stack::tests::udp_listener::a_stack_listens_on_udp_where_it_carries_datagrams`
  lends its links a port's row and slot (`udp_link::leaked_ports(1, 1, 64)`) before it opens the
  listener: since `5c5f545604` links given no port memory open no `udp/` port, so the test bound
  nothing. What it asserts is unchanged.
- `6015e9551a`: `LINK_ROWS`, `GROUP_RX_ROWS` and `PORT_RX_ROWS` (`crates/wz-capi-coop/src/arena.rs`)
  count no row on use, where the plan lays none of them out, so `ARENA_ROWS` is the rows an on-use
  plan holds (`tests::arena::a_plan_with_every_row_holds_exactly_arena_rows`).
- `1d7bac1532`: the `tests::arena` tests that read a link's rows read the count every form keeps
  (`ArenaPlan::links`) through `link_places`, which asserts the row of places in D12 alone, and
  `link_receive_buffers` (the pool's row in D12, one for each link on use);
  `a_listener_lays_out_the_gets_of_each_face_it_admits` reads the tables' rows under `wz_lent` and
  their counts in every form;
  `the_dial_roles_link_and_face_are_laid_out_only_for_a_session_that_dials` compares the arenas'
  bytes only where the arena lays a face's tables out; the CONTROL of
  `a_session_that_sends_each_face_its_own_leg_reserves_no_handed_places` and the plan of
  `a_face_past_max_faces_is_not_attached` read `link_receive_buffers`.

### 7.25 R3, 3c (c): the kept publishes through their table's storage, and the on-use arena tests

- `1d5b2e25d0`: `HandedLegs<WORDS, P: LegStorage = Lent>` and `HandedLeg<WORDS, P>`
  (`crates/wz-runtime-coop/src/handed.rs`) take the storage of their rows, which names where the
  places lie (`LegStorage::Places`, `Place`, `claim`, `give_back`): `Lent` the places a session
  lent (`Option<LentByteCells>`, a `ByteBuf` each, given back as it drops), `OnUse` its own
  (`OwnPlaces`: each place a buffer of the batch, taken by `zeroed_bytes` when a publish finds
  every place taken before held, at most the count, kept spare once its publish is sent).
  `HandedLegs::counted(place_bytes, legs)` makes the on-use table, its rows
  `BoundedVec::counted(legs)` taken at the first publish kept. The heap's refusal is a value: a
  place the heap refuses is a publish not kept, before any row is taken; a place claimed for a
  publish not kept (longer than a place, or no row) is given back; `clear` gives every place back.
  The own form is `not(session-slot)`, as the runtime's other heap forms are. The parameter is the
  storage policy itself, not a source of the links' kind: the kept publishes are the session's
  state, not a link's, so capi-coop names `HandedLegs<FACE_SLOT_WORDS, crate::StatePolicy>`, the
  policy `build.rs` states once.
- `a405ec1189`: the plan counts `handed_legs` in both forms and lays the three handed rows out in
  D12 alone (`HANDED_ROWS`, `not(wz_on_use)`); `TransportRows::lent_from` makes
  `HandedTable::counted(link_bytes, handed_legs)` on use. The engine's uses (`hand_off`,
  `send_handed_now`, the close's `mem::take`, the drop's `clear`) read the table's methods only
  and are unchanged.
- Tests, wz-runtime-coop `handed`: `a_kept_publish_reads_back_whole_and_its_place_comes_back` runs
  its body (`reads_back_whole`) over the lent table, and three new:
  `a_publish_kept_in_its_own_place_reads_back_whole_and_its_place_comes_back` (the same body over
  the own table), `an_own_table_takes_its_rows_at_its_first_publish_and_no_place_past_its_count`
  (red if `counted` takes rows when made, `claim` takes a place past `count`, or `give_back` lets
  a place go), `a_place_the_heap_refuses_keeps_nothing_and_takes_no_row` (red if a place is made by
  a path that ends the process when the heap refuses it, or the rows are taken before the place).
  wz-capi-coop `tests::arena`: `a_listening_session_reserves_places_for_the_publishes_it_keeps` is
  `not(wz_on_use)`; `an_on_use_session_counts_the_publishes_it_keeps_and_lays_out_none` (new,
  `listen` in the round's form on use; red if the plan lays a handed row out on use, or the table
  keeps other than `HANDED_LEG_BYTES / batch` publishes of a batch each).
- The on-use leg of `tests::arena` read whole (`749284f74f`): every test the on-use legs compile
  was read for a row the on-use plan lays none of out (the links', the groups', the ports', the
  direct faces', the admission's, the handed publishes', and, in a test of a build that takes
  faces, the rows `wz_lent` alone lays out). One more read such rows unguarded:
  `the_pico_presets_arena_for_a_client_and_a_peer_is_the_notes_sum` reads the client's receive
  buffers through `link_receive_buffers`, and the peer's pools and its reservation against the
  build's in D12 alone; on use the arena holds neither the links' nor the faces' rows, and the
  counts it asserts in every form are what the preset bounds. The rest already read each such row
  under the cfg that lays it out.
- `4ea1507eb9`: no leg compiled the round's form (`WZ_COOP_VALUE_LOCKS=off`) with `tables-on-use`,
  the one build that makes the own table; a `lane` row of `scripts/lib/nondefault-tests-gate.sh`
  runs `tests::arena::` there (`listen,tables-on-use`). The rest of that form (`StatePolicy` of
  `OnUse` under `wz_round`) is compiled there for the first time too.

### 7.26 The reds of hn15

- The pico peer's arena test on use
  (`tests::arena::the_pico_presets_arena_for_a_client_and_a_peer_is_the_notes_sum`,
  `udp-listen,tables-on-use` and `listen,tables-on-use`): fixed by `749284f74f` (7.25).
- `e480c04fd2`: `arena::tests::each_kinds_places_take_its_own_rows_and_part` (`tables-on-use`)
  gave rows to every kind of entity, though a plan holds places for the build's kinds alone
  (`ENTITY_PLACE_ROWS`): it fit on the slack of rows the on-use plan no longer counts
  (`6015e9551a`), and `put` refused the rest (`TooLarge`). It gives rows to the kinds the
  build's limits count (`entity_rows`), and asserts a kind of no row is laid out nothing.
- `52368494dd`: `ArenaPlan::links` is a listening build's (`feature = "listen"`), and
  `1d7bac1532`'s `link_places` called it in a build that only dials (the crate's defaults and
  `group-host`, E0599). A build that only dials counts its links by its transmit rows
  (`laid_link_places`), as before; a listening build reads the count, and in D12 asserts the row.

### 7.27 3d, step 1: the endpoints' texts through the state's policy

- `5b46c5a67b`: `EndpointTexts<P: Storage = Lent>` (`crates/wz-runtime-coop/src/faces.rs`) takes the
  storage of the session's own state, which the transport names (`TransportFaces::Policy`,
  `transport/state.rs`; the engine's `crate::StatePolicy`, now stated for every build, since the
  transport reads it in each). `EndpointTexts::<OnUse>::counted(dials, listens)` counts each role's
  table to the endpoints the config names, held to `ENDPOINT_TEXT_ROWS`, and takes no memory before
  the role's first text; `write` answers `Full` where no row is free and `NoMemory { bytes }` where
  a free row's memory the allocator refused, which the open answers as
  `ArenaRefused::NoMemory` (`open_source.rs` `unwritten`). The plan lays the endpoint row out in
  D12 alone (`ENDPOINT_ROWS`, the put in `lay_out`); `TransportRows::lent_from` makes the counted
  texts on use. Every reader (`DialEndpoint::text`, the transport's dials and ports, the zid's
  derivation) is generic over the policy or names the engine's.
- Tests: wz-runtime-coop `faces`
  `on_use_texts_take_their_rows_at_the_first_written_and_no_more` (new; red if the rows are taken
  when the texts are made or by the other role's text, a text is written past the count, or a
  refused text takes the rows). wz-capi-coop `open_source::tests` run over the rows of the build's
  policy (`session_rows`: lent in D12, counted on use), so the on-use legs run the six of them on
  the counted rows. `tests::on_use::an_on_use_plan_from_the_config_lays_out_no_row_of_the_tables_it_counts`
  asserts no endpoint row on use (red if the plan lays one out), its CONTROL now the reassembly
  buffers. The heap's refusal (`NoMemory`) has no test: no allocator of the tests refuses a table
  of at most `ENDPOINT_TEXT_ROWS` texts.
- What the on-use arena still lays out after this step: the reassembly flags and buffers, the
  links' cells where the plan holds them (none on use), the ABI's handle, entity places and
  lodgings, the advanced cache's ring, and the count the engine keeps the arena by. The next steps
  of 3d take them in that order; the arena leaves with the last.

## 8. What the main session runs

- 3d, step 1, the endpoints' texts (`5b46c5a67b`), not built or run by this lane. `cargo test
  --manifest-path crates/Cargo.toml -p wz-runtime-coop --features alloc,session-unicast --lib
  faces` (one more), `cargo test --manifest-path crates/Cargo.toml -p wz-capi-coop --lib
  open_source` and `--features tables-on-use --lib open_source` (counts unchanged),
  `--features tables-on-use --lib tests::on_use` and `--features listen,tables-on-use --lib
  tests::arena` (counts unchanged). Clippy of wz-runtime-coop (`--features alloc,session-unicast`)
  and of wz-capi-coop in its default set, `--features tables-on-use`, `--features
  udp-listen,tables-on-use` and `--features group-host`. Size: D12 a few bytes more in
  `EndpointTexts::write` (one read of the free rows before the push); the on-use client smaller by
  the endpoint row's lay-out and lend, larger by the counted table's first-row take (`FirstUse`'s
  out-of-line body, already linked). Receive Ir: unchanged (the texts are read at a dial and an
  accept, never on the receive).

- The reds of hn15 (`e480c04fd2`, `52368494dd`; `749284f74f` for the pico peer's test), not built
  or run by this lane. `cargo test --manifest-path crates/Cargo.toml -p wz-capi-coop --features
  tables-on-use --lib` (the one failure green, count unchanged), `cargo test --manifest-path
  crates/Cargo.toml -p wz-capi-coop` (compiles), and `cargo clippy --manifest-path crates/Cargo.toml
  -p wz-capi-coop --features group-host --all-targets -- -D warnings`. Size: none (tests).

- R3, 3c (c), the kept publishes and the on-use arena tests (`1d5b2e25d0`, `a405ec1189`,
  `749284f74f`, `4ea1507eb9`), not built or run by this lane. `cargo test --manifest-path
  crates/Cargo.toml -p wz-runtime-coop --features alloc,session-unicast --lib handed` (three more);
  wz-capi-coop `--features listen --lib tests::arena` unchanged in count, `--features
  udp-listen,tables-on-use --lib tests::arena` unchanged in count (the pico peer's test green), and
  with `WZ_COOP_VALUE_LOCKS=off` in the environment `--features listen --lib tests::arena`
  unchanged and `--features listen,tables-on-use --lib tests::arena` one more and one fewer.
  Clippy of wz-runtime-coop (its sets `heap` and `slot`), and of wz-capi-coop with `--features
  listen`, `--features udp-listen,tables-on-use` and, with `WZ_COOP_VALUE_LOCKS=off`, `--features
  listen` and `--features listen,tables-on-use`. Size: D12 a few bytes either way (the lent
  table's calls go through a trait of static calls; `clear` gives each place back in turn); the
  zenoh-pico preset cases unchanged (their `threads` builds have the host's value locks, so no
  round and no handed table); an on-use build of the round with faces smaller by the three handed
  rows of its arena. Receive Ir: unchanged (the table is the send's, read by a publish that found
  the session held).

- The reds of hn14 (`78aef50565`, `3d6b72f7c5`, `6015e9551a`, `1d7bac1532`), not built or run by
  this lane. `cargo test --manifest-path crates/Cargo.toml -p wz-runtime-coop --features
  alloc,session-unicast,udp-listen --lib ip_stack` and `cargo test --manifest-path crates/Cargo.toml
  -p wz-capi-coop --features udp-listen,tables-on-use --lib tests::arena` green, the counts
  unchanged; clippy of wz-runtime-coop with `--features alloc,session-unicast,udp-listen` and of
  wz-capi-coop with `--features udp-listen`, `--features udp-listen,tables-on-use` and `--features
  threads,udp-listen,tables-on-use`, and the non-default features gate of the two crates. Size:
  none in D12; an on-use plan's table of rows shorter by the rows it no longer counts. Receive Ir:
  unchanged.

- R3, 3c (c), the groups (`339c959c64`), not built or run by this lane. `cargo test
  --manifest-path crates/Cargo.toml -p wz-runtime-coop --features alloc,session-unicast --lib
  group_transport` (two more), `... --lib ip_stack` (one more), `--features app-link,host-lock --lib
  app_link::` and `--features raweth,reassembly,keyexpr-wildcard-double --lib raweth_group::`
  unchanged in count; `cargo test --manifest-path crates/Cargo.toml -p wz-runtime-posix --lib
  multicast` unchanged; wz-capi-coop `--features group --lib tests::arena` unchanged, `--features
  group,tables-on-use --lib tests::arena` one more and one fewer, `--features group-host --lib
  host_group` unchanged. Clippy of wz-runtime-coop (its sets `heap`, `slot`), wz-runtime-posix
  (the defaults and `host-multicast`), and wz-capi-coop with `--features group`, `--features
  group,tables-on-use`, `--features app-transport,group,multicast-declarations,liveliness,tables-on-use`
  and `--features group-host`; the Windows build of wz-runtime-posix is untouched (its group test
  calls `HostGroupTransport::new`, kept). Size: D12 a few bytes either way (the joiner's own arm
  takes a length; the stack's claim is one call); an on-use build with groups smaller by the
  groups' buffers of its arena. Receive Ir: unchanged (the group's read is the same over a buffer
  of any origin).

- R3, 3c (c), the ports (`5c5f545604`), not built or run by this lane. `cargo test
  --manifest-path crates/Cargo.toml -p wz-runtime-coop --features alloc,session-unicast,udp-listen
  --lib udp_link` (three more, none fewer: the lent-only test of `udp_link` ran only under the
  removed selector) and `... --lib ip_stack` (one more); the crate's first gate row (every feature
  but the slot selector) the same. wz-capi-coop: `--features udp-listen --lib tests::arena`
  unchanged in count, `--features udp-listen,tables-on-use --lib tests::arena` one more and two
  fewer (the D12 tests of the ports' rows are `not(wz_on_use)`). Clippy of wz-runtime-coop with
  its sets `heap` and `slot`, and of wz-capi-coop with `--features udp-listen`, `--features
  udp-listen,tables-on-use` and `--features threads,udp-listen,tables-on-use`. Size: D12
  unchanged to a few bytes (the lent form alone, by type as by the selector; the slot table moved
  into the book); the client cases unchanged (no port); a listening on-use build smaller by the
  ports' rows and slots of its arena. Receive Ir: unchanged (the client reads no port; a port's
  read keeps one arm).

- The listener's bound and the reds of hn12 (`de6a30cf2f`, `3689670ef3`, `ce7e699b2c`), not
  built or run by this lane. `cargo test --manifest-path crates/Cargo.toml -p wz-capi-coop
  --features liveliness,listen,tables-on-use --lib on_use` and `--features
  link-admission,tables-on-use --lib on_use`, one more each; `--features tables-on-use --lib
  on_use` unchanged in count. `cargo clippy --manifest-path crates/Cargo.toml -p wz-capi-coop
  --all-targets -- -D warnings` with `--features tables-on-use`, `--features
  threads,tables-on-use`, `--features liveliness,listen,tables-on-use`, `--features
  app-transport,group,multicast-declarations,liveliness,tables-on-use` and `--features
  udp-listen,tables-on-use` (where the flag is still read). Size: none.

- R3, 3c (b) and the seam before it (`99cc01afed`, `ff65049f24`), and the reds' fixes
  (`1e47d9d865`, `7e09c2c4ed`, `e335e9a48d`, `461f658b2a`, `dbac74a3ed`), not built or run by
  this lane. `cargo test --manifest-path crates/Cargo.toml -p wz-runtime-coop --features
  alloc,session-unicast --lib link_storage` and `... --lib ip_stack`; `cargo test
  --manifest-path crates/Cargo.toml -p wz-session-core --lib id_map`; wz-capi-coop:
  `--features app-transport,group,multicast-declarations,liveliness,tables-on-use --lib` (the
  whole on-use suite, one more test), `--features tables-on-use --lib on_use` one more,
  `--features udp-listen --lib tests::arena` and `--features group --lib tests::arena` unchanged
  in count; clippy of wz-runtime-coop with its feature sets and of wz-capi-coop with the on-use
  legs and the defaults. Size: D12 unchanged; the on-use case smaller by the links' tables' rows
  and their table arms.

- R3, 3c (a) (`a5a7f0c8bf`, `23ff61faf7`, `46c8fd37e8`), not built or run by this lane. `cargo test
  --manifest-path crates/Cargo.toml -p wz-runtime-coop --features alloc,session-unicast --lib
  link_cells` two more than before, `... --lib ip_stack` one more, `... --lib sync::tests` one
  more; `cargo clippy --manifest-path crates/Cargo.toml -p wz-runtime-coop --all-targets -- -D
  warnings` with the crate's feature sets (heap, heap-lent-ports, slot). wz-capi-coop:
  `--features tables-on-use --lib on_use` one more, `--features tables-on-use --lib tests::arena`
  one fewer, the defaults' `--lib tests::arena` and `--lib arena::tests` unchanged; clippy of
  wz-capi-coop with the legs of 3b's bullet below, and `--features threads,tables-on-use` (the
  form of several threads over `LinksOnHeap<ManyThreads>`). Size: D12 unchanged or a few bytes
  smaller; the on-use case smaller by the cell tables' code and rows.

- R3, 3b (`a0a99b28b6`, `26217c7d5b`), not built or run by this lane. `cargo test --manifest-path
  crates/Cargo.toml -p wz-runtime-coop --lib table_tests` one more than before; `cargo clippy
  --manifest-path crates/Cargo.toml -p wz-runtime-coop --all-targets -- -D warnings`. The on-use
  legs of wz-capi-coop, each count unchanged (one test renamed): `cargo test --manifest-path
  crates/Cargo.toml -p wz-capi-coop --features tables-on-use --lib on_use`, `--features
  liveliness,listen,tables-on-use --lib on_use`, `--features link-admission,tables-on-use --lib
  on_use`, `--features runtime-plan,tables-on-use --lib on_use`; `--features tables-on-use --lib
  tests::runtime_tables` and `--features liveliness,listen,tables-on-use --lib tests::direct_runtime`
  (whichever of the two the leg's read compiles); the D12 forms' `--lib tests::runtime_tables`,
  `--lib tests::direct_runtime` and `--lib arena::tests` with the crate's defaults. `cargo clippy
  --manifest-path crates/Cargo.toml -p wz-capi-coop --all-targets -- -D warnings` with the
  crate's defaults, `--all-features`, `--features tables-on-use`, `--features
  liveliness,listen,tables-on-use`, `--features link-admission,tables-on-use`, `--features
  runtime-plan,tables-on-use` and `--features app-transport,group,multicast-declarations,liveliness,tables-on-use`
  (the opening form, `RuntimeForm::Opening`); `cargo build --manifest-path crates/Cargo.toml -p
  wz-capi-pico --no-default-features --features os-host,link-udp,wz-capi-coop/tables-on-use`.
  Size: C1cs's D12 readings unchanged; the on-use case should not grow (the placed runtime's
  makers leave, one heap maker comes in).

- R3's residues, the sequences (`225c3f0b0e`), not built or run by this lane. `cargo test
  --manifest-path crates/Cargo.toml -p wz-session-core --lib row_pool::tests` two more than
  before (the crate's defaults have `alloc`); `--features declare-subscriber --lib
  peer_tables::on_use_tests` two more (one needs `codec-declare` alone, one `declare-subscriber`);
  the crate's whole suite with `--features declare-subscriber,declare-queryable,liveliness-get`
  (every on-use test of `pubsub`, `peer_tables` and `slot_observer` now runs a `CountedSeq`).
  `cargo clippy --manifest-path crates/Cargo.toml -p wz-session-core --all-targets -- -D warnings`,
  the same with `--no-default-features` (no `alloc`: no `CountedSeq`, `take_rows` provided alone)
  and with `--all-features`. `cargo test --manifest-path crates/Cargo.toml -p wz-capi-coop
  --features liveliness,listen,tables-on-use --lib on_use` and `--features tables-on-use --lib
  on_use`, their counts unchanged (the engine's tables change shape, not their tests).

- R3's residues (`17511020b8`, `92347c4f82`, `f59630b1bd`), not built or run by this lane.
  `cargo test --manifest-path crates/Cargo.toml -p wz-session-core --lib on_use::tests` one
  more; `--lib id_map::tests` two more; `--lib pubsub::on_use_alias_tests` 1; the crate's whole
  suite (every on-use test of `peer_tables`, `slot_observer`, `session_tables` and
  `liveliness_subscriber` now runs a `CountedIdMap`). `cargo test --manifest-path
  crates/Cargo.toml -p wz-capi-coop --features app-transport,group,multicast-declarations,liveliness,tables-on-use --lib on_use`
  one more (`engine::registry::counted`); the R2 legs as listed below, their counts as there.
  `cargo clippy --manifest-path crates/Cargo.toml -p wz-session-core --all-targets -- -D warnings`,
  the same with `--no-default-features` (no `alloc`: no `CountedIdMap`, `recount` provided
  alone), and wz-capi-coop's legs below.

- R2, the rooms (`e5ee0e0d5a`), not built or run by this lane. `cargo test --manifest-path
  crates/Cargo.toml -p wz-capi-coop --features liveliness,listen,tables-on-use --lib on_use` 21
  (18 before: one of `engine::once_rows`, one of `tests::congestion`, one of `tests::on_use`);
  `--features link-admission,tables-on-use --lib on_use` three more than before; `--features
  tables-on-use --lib on_use` four more (`engine::once_rows` now runs two there); `cargo test
  --manifest-path crates/Cargo.toml -p wz-capi-coop --lib tests::congestion` with the crate's
  defaults (the D12 form, unchanged) and with `--all-features` (one more). `cargo clippy
  --manifest-path crates/Cargo.toml -p wz-capi-coop --all-targets -- -D warnings` with the legs
  R2 lists below, and `--no-default-features --features std,tables-on-use` (no `tx-held-wait`:
  `RoomTable::place` is then compiled only where the round and faces are).

- R2 (`c4105747a2`, `657b23623c`), not built or run by this lane. The renamed test of
  `engine::state_places` now matches `on_use`, so every on-use leg runs one test more than
  before. `cargo test --manifest-path crates/Cargo.toml -p wz-capi-coop --features
  liveliness,listen,tables-on-use --lib on_use` 18 (13 before: the renamed test, the three of
  `once_rows` and the attach's slot test added); the new leg `cargo test --manifest-path
  crates/Cargo.toml -p wz-capi-coop --features link-admission,tables-on-use --lib on_use` (the
  listening leg's tests less those that need `liveliness`, the owed tokens' of
  `engine::registry::counted` among them, plus the admission's); `cargo test --manifest-path
  crates/Cargo.toml -p wz-capi-coop --all-features --lib tests::face_routers` and the same with
  `--lib tests::listen` (the on-use form of both, their counts unchanged); the D12 legs as before.
  `cargo clippy --manifest-path crates/Cargo.toml -p wz-capi-coop --all-targets -- -D warnings`
  with `--all-features`, with `--features liveliness,listen,tables-on-use`, `--features
  link-admission,tables-on-use`, `--features link-admission,udp-listen,tables-on-use`, `--features
  tables-on-use` and the crate's defaults, and `WZ_COOP_VALUE_LOCKS=off` with `--features
  query,queryable,link-admission,tables-on-use` (the round's on-use form: an admission, no direct
  faces). `bash scripts/lib/nondefault-tests-gate.sh --census` for `wz-capi-coop`.

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
   - 3b, the runtime (written, 7.17: `CoopRuntime::try_formed` and `try_taskless`, the on-use
     plan's count laid alone by `ArenaPlan::lay_keep`): the heap makers the runtime has (`CoopRuntime::try_reserved`,
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
     Written, step (a) (7.18): the cells' source is the handle's kind's (`CountKind::Cells`), so
     it reaches every stack by the type the programs already hand them (`LinkCount`), and the
     runtime by its lock kind (`LinksOnHeap`). Written, step (b) (7.20): the buffers' source is
     the kind's too (`CountKind::Buffers`), the heap's sized by the session to its batch and
     `LINK_TX_SLOTS`, after the ports' slots and the groups' buffers were lent apart (7.19); the
     ports, groups and kept publishes (c) are next.
     Read for (c), not written yet. The ports: `udp-port-lent-only` is a feature of
     `wz-runtime-coop` that `wz-capi-coop/udp-listen` names, so a build that unifies it with
     `tables-on-use` compiles no port of the heap's memory, and the on-use plan still lays out and
     lends the ports' rows and slots (`TransportRows::port_slots_from`, `PortRows::over`). The
     form: `CountKind::Ports`, a `PortSource` (`udp_link.rs`) with the storage of the book's rows
     and what a port reads into; `Option<LentPorts<F>>` (the rows and the slots a session lent,
     `None` refusing the listener) for the kinds that lend, `HeapPorts::sized(peers, slots,
     bytes)` for `OnHeap`, its rows `PortRows<OnUse, _>` counted to the session's links and
     `UDP_PORT_SLOTS`, its reads the port's own buffer and spares (today's `PortRx::Own`).
     `PortRx`, `Held` and `BookRows` become one type each source names (a `PortStore` trait),
     `with_rows!` goes, `UdpPort`, `PortPeer` and `SharedBook` take the source as a parameter
     beside the count kind (`N::Shared` counts the port, but `OnHeap<N>::Shared` is `N::Shared`,
     so the source is read off the links' kind), `SessionLinks::lend_port_rows(rows, slots)`
     becomes `lend_ports(N::Ports)` (a source of rows with no slots is no longer a value), and the
     feature, its feature set (`heap-lent-ports`), its gate leg
     (`scripts/lib/nondefault-tests-gate.sh`) and its tests go. A port no session sized is
     refused, as a lent kind's port lent nothing is: every port's memory is bounded by a session's
     statement. Written for the ports (7.22), as read, the lent form's and the heap's each
     compiled for the kinds that name it. The groups: on use the plan lays out a receive buffer for each group it counts and
     lends them; not lending leaves each joiner to make its own (`GroupRx::lent_or_own`), whose
     length each joiner (`host_group`, `app_link`) must be read for before the plan drops the
     rows, so the on-use source hands the joiner the plan's group batch. Written for the groups
     (7.23): the joiners' own lengths read, the source the kind's (`HeapGroups` on use). Written for
     the kept publishes (7.25): `HandedLegs` takes the storage of its table (`LegStorage`), the
     session's state's (`StatePolicy`), counted on use to `handed_legs` with no row laid out.
4. N4 (3.7): the doors' objects from the allocator, counted against their kinds, so the places the
   ABI holds in the arena today (the handle's, the entities', the lodgings) are the ABI's own.
5. 3d, the arena: with every tenant housed, the on-use form reserves no arena. `SessionArena`,
   `TableLender` and the lend bodies of `arena.rs` (`TransportRows::lent_from`,
   `PlaceRows::lent_from`, `SessionRows::lent_from`) are not compiled in it; the counts the plan
   reads off the limits (`ArenaPlan::count`, `tables`, `peers`, `gets`, `session`) stay, the
   on-use constructors' only input. The size case reads group A's figure here. Written, step 1
   (7.27): the endpoints' texts by the state's policy, counted on use; the reassembly chains, the
   ABI's places, the cache's ring and the arena's count are next.
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
| the engine's pending legs (`Rows<PendingGet>`) | none: the table is gone (`arch-l3-rows.md` H7a), a leg being its entry in its face's table alone | nothing to refuse | yes; the window it left on `OnUse`, a first row asked after the Request went out, went with it |
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

- R2 (landed on the lane, `657b23623c`; 7.13), the admission's value and the direct faces' slots
  taken per face (the table's fifth and sixth rows); a face refused for want of memory at its
  attach is answered as one past `max_faces` is.
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
