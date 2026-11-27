# Migration lane session-row: one session, one row

Status: design of the lane. R1 landed beside it; R2 (the seat goes, the doors' count held by the
row table, the row table's locking bodies out of line) and R4 (the kernel's token places) are
written after it, unbuilt; R3 is design only (section 4, the generated files it needs). Nothing
here was built or measured by this lane: every byte figure is an **estimate** read off the types
in the source or off size reports of other trees, and every count of instructions is a reading of
the code, not a run. Line references are to the tree this lane branched from (`a9126d3242`)
unless they name `reach.rs` after R1.

## 1. The reading: one session is counted twice

### 1.1 The seat pool (the cooperative engine with the pools' doors)

- `SessionSeat` (`crates/wz-capi-pico/src/session.rs:1025-1032`) is an uninhabited enum: "a slot
  of it holds nothing and is never filled". It exists so that the `sessions` a program states
  through the pools' doors bound something on the cooperative engine, whose session lies in its own
  arena and not in a slot.
- `z_open` takes a seat after the process pools are reserved and before anything is scouted, bound
  or dialled (`session.rs:1461-1468`), carries it in `OpenRequest.seat` (`session.rs:1843-1849`)
  and keeps it in `SessionTail.seat` (`session.rs:1040-1047`, written by `SessionTail::write_at`,
  `session.rs:1067-1086`) until the session's place goes back.
- The pool is laid by `Plan::listed` (`crates/wz-capi-pico/src/process_pool.rs:766-775`) for
  `objects.sessions` seats: the program's count (`zext_object_pool_counts_t.sessions`,
  `crates/wz-capi-pico/src/object_pool.rs:88`) or the build's `HELD_SESSIONS` (`OPEN_FRAME`,
  `process_pool.rs:1561-1566`). `Kind::Session` exists on the cooperative engine only for it
  (`crates/wz-capi-pico/src/object_slot.rs:33-36`), and the size report has a row for it
  (`process_pool.rs:2666-2671`).
- Bytes (estimate): a slot of a zero-size object is `SLOT_ALIGN`, 16 bytes
  (`process_pool.rs:456-469`), so the pool is `sessions` x 16 bytes of the process pools' one
  allocation (64 at the default 4, 32 at the pico preset's 2); one slot handle (one word) in each
  session's tail and one in the open's request; the take and give-back are the pools' shared code,
  so the seat's own text is its call sites and its plan entry, on the order of 100 to 200 bytes. It
  is compiled only with `object-pool`, so the size case `pico-client-coop-nostd` carries none of it.

### 1.2 The engine row (every build of the cooperative engine)

- Before R1, `crates/wz-capi-coop/src/engine/reach.rs` held `static ROWS: Lock<[Row;
  ENGINE_ROWS]>` (one word a row, the engine's place) and `static MARKS: [AtomicU32;
  ENGINE_ROWS]` (the generation, the claim and the end): 12 bytes a row on a 64-bit host, 3,072
  bytes of `.bss` at the default 256 rows and 24 at the preset's 2, whatever the build's storage
  policy. A reach (`EngineAt`, `crates/wz-capi-port/src/cancellation.rs:262-267`) was the row's
  index and its generation, and every reach, clear, end and `is_current` checked the index
  against the table's length.
- The open claims a row before it reserves anything (`crates/wz-capi-coop/src/engine.rs:6620`); a
  full table answers `OpenError::NoEngineRow`, which `z_open` answers as
  `_Z_ERR_SYSTEM_OUT_OF_MEMORY` (`session.rs:2889`).
- `ENGINE_ROWS` sizes one more table: the cancellation tokens' places of a kernel's build,
  `TOKEN_PLACES = ENGINE_ROWS x (MAX_PENDING_QUERIES + MAX_PENDING_LIVELINESS_GETS)`
  (`cancellation.rs:557-562`), static only where neither `std` nor `os-sys` is (the Zephyr image);
  a host boxes each token.

So with `object-pool` on the cooperative engine one session takes a seat (counted by
`HELD_SESSIONS` or the program's `sessions`) and a row (counted by `ENGINE_ROWS`), two tables
of the same thing, each refusing the one more open on its own.

### 1.3 The tokio engine

Its session handle lies in a slot of `Kind::Session` sized `SessionPlace`
(`process_pool.rs:768-771`), counted by the same `sessions` or `HELD_SESSIONS`; it has no
engine row. `HELD_SESSIONS` is also the multiplier of the per-session objects that lie in the
process pools on either engine (`pooled_entities(limits, HELD_SESSIONS)`, `process_pool.rs:1539`):
that is a count of the pools' room, not a count of sessions open.

### 1.4 zenoh-pico (read at 1.10.2, the submodule's `6a881c21da`)

`_z_session_rc_init` allocates each session on the heap at its open
(`vendor/zenoh-pico/src/api/api.c:896`, `z_malloc(sizeof(_z_session_t))`) and wraps it in a
counted handle (`api.c:908`, `_z_session_rc_new`): no table, no bound but the heap. Its entities
keep a weak handle of the session (`_z_session_weak_t _zn` in
`vendor/zenoh-pico/include/zenoh-pico/net/publish.h:33`, `subscribe.h:32`, `query.h:38`, and
`session/keyexpr.h:31`) and reach it with `_z_session_weak_upgrade_if_open`
(`vendor/zenoh-pico/src/net/session.c:708-714`), which answers none once the session is closed.

## 2. The target

- One control block for each session: the engine row, which holds the engine's place and a mark
  of 32 bits (the generation, the claim, the end). A reach is where the row lies and the
  generation; the close moves the generation on, so a reach kept past the close is refused by
  generation, as zenoh-pico's upgrade of a closed session's weak handle is.
- Where the row comes from is one storage policy, the build's `wz_session_core::bounded::Profile`:
  - **fixed** (`Static`): a static array of rows, whose count is the only bound; the one more
    open is refused at its open;
  - **heap** (`Heap`): an open that finds no vacant row takes one of the heap; the table keeps it,
    generation and all, for the next open, and nothing bounds the sessions but the heap, as
    zenoh-pico's contract.
- The seat pool and its second count go. Where a session lays its own tables (lent from its arena
  at the open, `limits-lent-at-open`, or in a region the build laid out) is another axis and
  decides nothing of where the rows come from: the row table reads `Profile` and nothing else. A
  constant that grows the process's tables only where the tables are not lent at the open ties
  the two axes, which is the confusion this lane avoids.
- One number of sessions for every engine: the cooperative engine's rows on the fixed policy, the
  tokio engine's slots of handles, and the `sessions` a program states through the pools' doors
  are the same count, under one Kconfig name (R3).

## 3. Steps

| step | what | where |
|------|------|-------|
| R1 (landed with this note) | The row table takes its rows by the storage policy: `RowSource` of `Profile`, `Heap` naming a table of no static row that takes rows of the heap and keeps them, `Static` naming `ENGINE_ROWS` static rows. A reach names its row by where it lies (no row is ever given back on either policy), so no index is checked. | `crates/wz-capi-coop/src/engine/reach.rs`, the open's refusal text in `engine.rs`, `tests/engine_rows.rs`, `ENGINE_ROWS`'s help |
| R2 (written, section 7) | The seat goes. On the cooperative engine the doors' `sessions` count becomes the row table's: the door that reserves the pools takes that many rows (of the heap on the heap policy, after which the table grows no more; on the fixed policy the count is held to the table's rows, as a count past its limit's bound is held to it today), and the open past them is refused by the row claim, `NoEngineRow` answered as `_Z_ERR_SYSTEM_OUT_OF_MEMORY` as the seat's refusal was. `SessionSeat`, `SessionTail.seat`, `OpenRequest.seat`, the seat's take in `z_open`, its plan entry, `Kind::Session` on the cooperative engine and its size row are deleted. The row table's bodies that take its lock and are asked from more than one place (the claim, a claim let go of unfilled, the close) go out of line, the claim with one taking of the lock. | `wz-capi-pico`: `session.rs`, `process_pool.rs`, `object_slot.rs`, `object_pool.rs`; `reach.rs` |
| R3 | One Kconfig name (section 4). | `deploy/wz-config.toml` and what it generates, `caps.rs`, the conformance vectors |
| R4 (written, section 7) | The kernel build's token places follow the storage policy: boxed on the heap policy as a host's are, static places of the one count on the fixed policy. | `crates/wz-capi-port/src/cancellation.rs` |

## 4. One name for the count (R3, design only)

Keep `HELD_SESSIONS` (`WZ_LIMIT_HELD_SESSIONS`, default 4, pico preset 2) and delete
`ENGINE_ROWS` (`WZ_LIMIT_ENGINE_ROWS`, default 256, preset 2). `HELD_SESSIONS` is the name the
public header and the documents already give the program's count, and it is one of the `HELD_*`
family the pools' doors state; `ENGINE_ROWS` names an implementation of the cooperative engine.
After R1 the 256 rows bind only a build on the fixed policy, and no host build is one (every host
links an allocator), so the merged default of 4 changes no host; a fixed image holds the 4 (or the
preset's 2) its pools are sized for already. The kernel build's token places, sized by
`ENGINE_ROWS` today, move to the one count with R4.

What the deletion of `ENGINE_ROWS` touches that a deployer or a program sees:

- `deploy/Kconfig.limits`: the symbol `WZ_LIMIT_ENGINE_ROWS` (generated from
  `deploy/wz-config.toml`, `[[limit]] id = "ENGINE_ROWS"`); an image configuration that sets it
  names an unknown symbol.
- The build environment `WZ_LIMIT_ENGINE_ROWS` (`crates/wz-session-core/src/caps_generated.rs:49`)
  stops being read.
- `wz_session_core::caps::ENGINE_ROWS` (`crates/wz-session-core/src/caps.rs`), a public constant,
  and its binding (`caps_binding_generated.rs:301`), its spec (`limits_generated.rs:4296`) and
  its conformance item (`crates/wz-conformance-build/src/items_generated.rs:156`).
- `crates/wz-conformance-build/statement_vectors.json`: the digest of "every limit and policy
  stated at its default" of each of the three ABIs (lines 8, 79, 131), the case "ENGINE_ROWS one
  above its default" (line 197) and the random cases that state it are derived again, so the
  conformance digest every build reports changes.
- Documents: `docs/zenoh-logic-as-sce-kinds/S7.md` row 139, `docs/win-budget/heap.md` (lines
  242 and 539, the handle's row and generation).
- `HELD_SESSIONS` keeps its name; its meaning widens from the pools' room to the sessions open at
  once, so its help, `crates/wz-capi-core/include/zext.h:2127` (the RESERVING paragraph),
  `docs/c-abi-no-heap-pools.md` (lines 122-124, 594) and S12 row 50 say so. No defconfig of the
  tree names either symbol, and a config document cannot state `HELD_SESSIONS` (its statement is
  refused by name, `crates/wz-capi-pico/src/config_limits.rs:319`), so no program's document
  changes.

R3 is not written on this lane's branch. Its source is the `[[limit]]` of `deploy/wz-config.toml`,
and every file above but `caps.rs` and the documents is derived from it by
`scripts/lib/wz_config.py`, which holds each to the source; the digests of
`statement_vectors.json` are computed by it, and a digest written by hand would be a guess. The
step is the source edit and one run of the generator, with the Rust that reads the count:
`RowSource for Static` in `reach.rs` and its size test, `TOKEN_PLACES` and its test in
`cancellation.rs`, `tests/engine_rows.rs` and the eleven-session test in `src/tests.rs`, each
reading `caps::HELD_SESSIONS` where it reads `caps::ENGINE_ROWS`.

## 5. The size case `pico-client-coop-nostd` under this structure

The case is `os-host,link-udp` with the `capi-nostd` profile: it links an allocator (the heap
links of `wz_runtime_coop::with_heap_link_seams!`, the arena from the allocator), lends each
session's tables from its arena at the open (`limits-lent-at-open`), has no pools' doors and one
thread. Its storage policy is the heap's: `wz-session-core` has `alloc` and not
`bounded-heapless` in its graph (read with `cargo tree -e features -i wz-session-core`), so
`Profile` is `Heap`. Under R1 its rows come from the heap: no row lies in static memory, a
session's open takes a row of the heap when none is vacant, and the table keeps the row for the
next open. Lending the tables at the open changes nothing of this.

Expected bytes, all estimates:

| what | before | after R1 | change |
|------|-------:|---------:|-------:|
| `.bss`, the rows and their marks (256 rows) | 3,072 | 8 (the table's one word) | about -3,064 |
| heap, per session open at once at the peak, kept | 0 | 16 (a row) | +16 a session |
| text, the claim | an indexed scan of 256 rows | a walk of the kept rows and, on a miss, one call of the allocator and the new row written | about +60 to +120 |
| text, reach, clear, end, `is_current`, fill | an index checked against 256 at each | the row's place, checked against null | about -40 |

The text is expected to move by about -40 to +80 bytes: it may grow, by up to about 80 bytes,
and only the gate's reading settles it. What shrinks for certain is the static memory, about
3 KiB, which the size gate counts only if it reads `.bss`. The receive of a sample calls none of
these in this case (the reach is read by a query's holder, a kept key's close and the keep of a
query, none of which the client without `query` has on its receive), so the receive Ir (about
3,066) is expected to stay where it is; where a build reaches a row on a reply, each read is one
compare fewer.

## 6. What R1 tests, and what turns each red

In `crates/wz-capi-coop/src/engine/reach.rs` (tables of their own, so the process's is untouched):

- `a_fixed_table_refuses_the_open_past_its_rows_until_a_close_vacates_one`: three rows, the fourth
  claim refused, a close vacates a row the next open takes a generation on. Red if `claim` grows a
  fixed table (`if !GROWS`), or `clear` leaves the generation.
- `a_heap_table_opens_eleven_at_once_and_lends_a_closed_ones_row_to_the_next_open`: eleven at once,
  eleven rows of the heap; a close's row is the next open's, a generation on, and no twelfth row is
  taken. Red if `claim` skips the kept rows (`first`), or `clear` leaves the generation.
- `a_reach_kept_past_its_close_reaches_nothing_on_the_fixed_policy` and `..._on_the_heap_policy`:
  the closed session's reach is refused, and its clear and end touch the next engine of its row
  not at all. Red if `reach` reads the engine before the generation, or `clear` ignores it.
- `a_claim_let_go_of_unfilled_leaves_its_row_vacant`, `a_vacant_reach_reaches_nothing`,
  `an_ended_session_is_reached_but_not_current_until_its_row_is_cleared`,
  `a_policy_names_its_table_and_a_row_is_its_engine_and_its_mark` (red if `Heap` names static
  rows, or `ENGINES` is not of the build's policy), and the fan cancel test, kept.

In `crates/wz-capi-coop/src/tests.rs`:
`sessions_open_past_the_builds_rows_on_the_heap_policy_and_closed_ones_are_reached_no_more`: with
`ENGINE_ROWS` rows held, eleven real sessions open to eleven router stand-ins; each closed
session's handle is not open and reaches nothing. Red if the heap table refuses past the count.

In `crates/wz-capi-coop/tests/engine_rows.rs` (the process's table, a binary of its own): with
`ENGINE_ROWS` rows held, a fixed build refuses the open (`NoEngineRow`, no arena reserved) and a
heap build's opens go on past the rows. Red if the open's claim is refused past the count on the
heap policy, or a failed open keeps its row.

## 7. R2 and R4 as written (unbuilt)

### 7.1 The doors' count is the row table's

- `RowClaim::hold_to(sessions)` (`reach.rs`) holds the process's table to a count. It is refused
  (`RowsRefused::Open`) while a row holds an engine or is claimed. On the heap policy the rows the
  table lacks are taken of the heap at once, in one block (`GrownRow::vacant_block`, all or
  nothing: `RowsRefused::NoMemory` takes nothing), and the table's flag `held` is set, after which
  a claim that finds no vacant row takes none of the heap. The rows past the count are marked
  `WITHHELD` (a third bit of the mark; the generation now moves by 8), which `is_vacant` reads
  beside `CLAIMED`. On the fixed policy a count past the table's rows withholds none: it is held to
  them.
- `RowClaim::let_go_of_count()` answers `false` while a row is open, and otherwise clears every
  `WITHHELD` and the flag.
- `process_pool::install` (under both doors, `zext_object_pool_reserve` and `_place`) holds the
  table under the pools' lock, once it found no pools reserved and before it lays them: the pools'
  lock, then the rows', an order no other path reverses. `Open` answers `Z_EINVAL`, as counts
  stated over pools held do; `NoMemory` answers `_Z_ERR_SYSTEM_OUT_OF_MEMORY`.
- `process_pool::release` asks `let_go_of_count` where pools are reserved and hold no object, so a
  session open keeps the pools and its count, as its seat did.
- The build's own pools (the first object's, the first open's) hold no count. On the heap policy a
  program that states none opens sessions with no bound but the heap, as zenoh-pico's; before, a
  build with the doors held such a program to `HELD_SESSIONS` seats. On the fixed policy the
  table's rows bound it as before.
- The open past the count is refused by the engine's claim, after the scout of an open that names
  no locator: the seat was taken before it. Nothing is bound or dialled either way.

### 7.2 The row table's locking bodies out of line

Read from the size ledger's explain reports of `pico-client-coop-nostd` dated 2026-11-27, one of a
tree before R1 and one of a tree with R1 and other lanes' commits; bytes each body holds of
`reach.rs`'s lines and of the lock's (`wz-host-sync`'s):

| body (what of `reach.rs` it holds) | `reach.rs`, before R1 | with R1 | lock, before R1 | with R1 |
|------|-----:|-----:|-----:|-----:|
| `assemble` (the claim, the let-go of a claim on each failure after it) | 119 | 193 | 264 | 362 |
| `close` (the clear) | 88 | 45 | 60 | 65 |
| `last_placed` (the clear of the engine's last drop) | 88 | 45 | under 60 | under 60 |
| `link_turn` (the end) | 85 | 44 | under 60 | 80 |
| `engine_of` (the fill) | 66 | 21 | 60 | 76 |

The lock of `assemble` holds its other locks too. R1's growth is the claim inlined into `assemble`
with two takings of the lock and the row of the heap: one taking of the lock costs about 60 to 80
bytes where it is inlined. R2 makes the claim one body out of line with one taking of the lock (the
heap's row taken under it: the allocator takes no lock of the rows), and the let-go of an unfilled
claim and the clear one body each (`let_go_unfilled`, `clear_row`), called from where they were
inlined. The end and the fill have one caller each in this case and stay inline.

### 7.3 Expected bytes, all estimates

| case | what moves | expected |
|------|-----------|---------:|
| `pico-client-coop-nostd` | `assemble` keeps two calls of the claim's (about -370); the claim and the let-go out of line (about +240, the count's flag read once among it); the clear once for two callers (about -80) | about -210 against R1, so about -110 against the tree before it (from -60 to -170) |
| `pico-api-coop-nostd`, `pico-peer-coop` | the same bodies, with the same callers | the same order |
| a build with `object-pool` (no case of the gate has it) | the seat's take, field and give-back go (about -100); `hold_to`, `let_go_of_count` and the doors' glue come (about +250 to +350) | about +150 to +250 of text; the pools' allocation `sessions` x 16 bytes less, the heap `sessions` x 24 more at the reservation on the heap policy |

The receive of a sample calls none of these bodies, so its Ir is expected to stay where it is.

### 7.4 R4

A kernel's build (neither `std` nor `os-sys`) places its tokens by `TokenSource` of the build's
`Profile`: `Heap` boxes each, as a host does; `Static` lodges each in `TOKEN_PLACES` places of a
static of its own, the static's one reader, so the heap policy's image carries none of it. A host's
build boxes each token on either policy, as before. `TOKEN_PLACES` is still `ENGINE_ROWS` times the
pending gets of a session until R3.

### 7.5 Tests, and the line whose change turns each red

In `crates/wz-capi-coop/src/engine/reach.rs` (tables of their own):

- `a_fixed_table_held_to_a_count_refuses_the_open_past_it_until_the_count_is_let_go_of`: red if
  `is_vacant` stops reading `WITHHELD`, or `let_go_of_count` stops asking `is_open`.
- `a_heap_table_held_to_a_count_takes_its_rows_at_once_and_none_past_them`: red if `claim` grows a
  held table (`self.held` in `claim`), or `hold_to` takes no block.
- `a_count_withholds_the_kept_rows_past_it`: red if the withholding walk skips the kept rows.
- `a_count_the_heap_cannot_give_rows_for_is_refused_and_holds_nothing`: red if `held` is set
  before the block is taken.
- `a_count_asked_while_a_session_is_open_is_refused_and_withholds_nothing`: red if `hold_to` stops
  asking `is_open`.
- `a_count_past_a_fixed_tables_rows_is_held_to_them_and_a_count_of_none_refuses_every_open`: red if
  a fixed table grows for a count, or a count of none lets an open take a row.
- `a_policy_names_its_table_and_a_row_is_its_engine_and_its_mark`: the heap table is now two words
  (its rows' word and the flag).

In `crates/wz-capi-pico/tests/object_pool_doors.rs`: ARM 7 (the second open refused, on the
cooperative engine by its claim), ARM 9 (the release refused while the session is open and the
pools hold no object; red if `release` stops asking `let_go_of_count`) and ARM 10 (two sessions open
after the release; red if the release leaves the table held to one row).

In `crates/wz-capi-port/src/cancellation.rs`:
`a_kernels_token_lies_where_the_storage_policy_places_it` (`TOKEN_PLACES + 1` tokens of `Heap`;
`TOKEN_PLACES` of `Static` and the next refused): red if either impl lodges in the other's source.
