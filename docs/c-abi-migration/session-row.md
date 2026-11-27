# Migration lane session-row: one session, one row

Status: design of the lane, with its first step (R1) landed beside it. Nothing here was built or
measured by this lane: every byte figure is an **estimate** read off the types in the source, and
every count of instructions is a reading of the code, not a run. Line references are to the tree
this lane branched from (`a9126d3242`) unless they name `reach.rs` after R1.

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
| R2 | The seat goes. On the cooperative engine the doors' `sessions` count becomes the row table's: the door that reserves the pools takes that many rows (of the heap on the heap policy, after which the table grows no more; on the fixed policy the count is held to the table's rows, as a count past its limit's bound is held to it today), and the open past them is refused by the row claim, `NoEngineRow` answered as `_Z_ERR_SYSTEM_OUT_OF_MEMORY` as the seat's refusal was. `SessionSeat`, `SessionTail.seat`, `OpenRequest.seat`, the seat's take in `z_open`, its plan entry, `Kind::Session` on the cooperative engine and its size row are deleted. | `wz-capi-pico`: `session.rs`, `process_pool.rs`, `object_slot.rs`, `object_pool.rs`; `reach.rs` |
| R3 | One Kconfig name (section 4). | `deploy/wz-config.toml` and what it generates, `caps.rs`, the conformance vectors |
| R4 | The kernel build's token places follow the storage policy: boxed on the heap policy as a host's are, static places of the one count on the fixed policy. | `crates/wz-capi-port/src/cancellation.rs` |

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
