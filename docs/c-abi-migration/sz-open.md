# Structural lane sz-open: the session's open, line by line

Status: the reading and the design of the lane, with its steps carried in beside it as section 5
onwards records them (O1, O2, O4, O5, O6; O3 held, section 7).
Nothing here was built or measured by this lane: every byte figure is either **read** (from the
size ledger's explain document of the case, from the case's shipped library, or from a line table
named below) or an **estimate** from the code, to be read on the explain document after the merge.

## 1. The reading

The case is `pico-client-coop-nostd` (`wz-capi-pico-lib`, `os-host,link-udp`, profile
`capi-nostd`): 205,921 against zenoh-pico's 170,500 in the explain document of 2026-11-27 (schema
5, pin `6a881c21dad1`). The sessions lane (`base-sessions`) left the open undesigned: `assemble`
3,528 and `lend_session` 3,351 of its area, to be read line by line first. This is that reading,
over every area: the open's bodies reach the doors, driver, codec and language areas too, and the
case's total is what a step is judged on.

Three sources, each used for what it holds:

- **The explain document**: each body's bytes and the owners (source modules) of its bytes.
- **The case's shipped library** of the same day: its symbol sizes equal the explain document's
  bodies (`assemble` 4,598, `lend_session` 4,290, `z_open` 2,876, `open_request` 1,765,
  `open_links` 983, `session_zid` 815, `engine_of` 762), so its instructions (`objdump -d`,
  no line table) are the case's own. Offsets below are into those bodies.
- **A line table**: the only `capi-nostd` build in the build cache that keeps one is the
  `pico-api-coop-nostd` case's, read with `objdump -d -l --inlines`. Its bodies are the same
  source with `listen`, `group`, `query`, `queryable`, `connectivity` and `runtime-plan`
  on, so its figures are marked **API build** and are used for the lines the case shares
  (`assemble` is 5,657 there against the case's 4,598). Its `lend_session` lays out its plan
  at run time and is not read as the case's.

The open runs once a session. It is not the receive or the put: no step below adds or moves an
instruction on either, and each is read on the case's total, the receive's instructions a sample
(perf matrix arm W) unchanged.

## 2. The open, job by job

Bytes are each body's bytes over all areas.

| job | wz bodies (bytes) | wz | zenoh-pico functions (bytes) | pico | wz - pico | kind |
|-----|-------------------|---:|------------------------------|-----:|----------:|------|
| the door | `z_open` 2,876 (`open_on_coop` inlined), `open_session_handle` 65, `z_open_options_default` 9 | 2,950 | `z_open` 549, `_z_open` 430, `z_open_options_default` 8 | 987 | +1,963 | shape (moved: the request and the engine's config, O8); the door's own session state (`PicoSessionExt`), to be read |
| the config read | `open_request` 1,765, `config_limits::state_over` 609, `group_endpoint` 233 | 2,607 | `_z_config_get_all` 169, `_z_config_get` 66, `_z_config_get_i32_default` 57, `_z_config_get_bool_default` 57 (what `_z_open` and `_z_open_locators` read the config with) | 349 | +2,258 | the process pools reserved at the first open (`process_pool` 493 of `open_request`) are the no-heap contract's, decided; repeated reads (O6); the rest to be read |
| the endpoint texts | `endpoint::kept_text` 742, `PicoEndpoint::write_text` 344, `OpenEndpoints::write_into` 423, `open_source::write_text` 356 | 1,865 | `_z_locator_from_string` 453, `_z_endpoint_from_string` 97 | 550 | +1,315 | shape: each text read twice, judged by the door and written into its row by the engine (O7) |
| the zid | `session_zid` 815 | 815 | `_z_session_generate_zid` 24, `z_random_fill` 50 | 74 | +741 | shape: inline copies (O1) |
| the assembly | `assemble` 4,598, `lend_session` 4,290, `engine_of` 762, `RuntimeTables::runtime` 405, `SessionArena::kept_span` 269, `UnicastLink::new` 215, `LinkSupervisor::new` 183, `lent_under` 53 | 10,775 | `_z_session_init` 881, `_z_new_transport` 647 (`_z_new_transport_client` inlined), `_z_unicast_transport_create` 469, `_zp_start_transport_tasks` 219 | 2,216 | +8,559 | about 4,000 the no-heap contract's lay-out (decided, kept: `base-sessions`); the rest shape (O2 to O5, O9) |
| the dial | `open_links` 983 | 983 | `_z_open_locators` 447, `_z_open_locators_client` 180, `_z_open_connect_locator` 1,418, `_z_unicast_open_client` 17 | 2,062 | -1,079 | won |
| a listener at the open | none: the case builds no `listen` | 0 | `_z_open_locators_peer` 367, `_z_open_bind_listener` 488 | 855 | -855 | won |
| **all** | | **19,995** | | **7,093** | **+12,902** | |

The handshake itself (`send_open_syn`, the codec's open bodies against `_z_unicast_handshake_open`
and `_z_open_encode`/`_z_open_decode`) is the transport's and codec's, not read here.

## 3. The lines

### 3.1 `assemble`

| job (`engine.rs` lines) | API build | in the case |
|---------------------------|----------:|-------------|
| admits, the engine's row, the runtime's tables, the plan's source | 752 | the row's claim takes the process table's lock (`RowClaim::take`); `open_holds` is the API build's alone |
| `lend_session` called and its `Result<SessionLent, _>` moved out | 437 | one copy of the value and about 260 bytes of moves (offsets 0x197 to 0x2ac) |
| the texts written into their rows | 32 | |
| the entropy source's cell, the zid, the rooms (one closure) | 507 | the source's cell is taken from the heap (`SessionEntropy::try_held`); the rooms' place and their making are in line (`Arena::lend_rows` and what follows it, about 430 bytes) |
| the faces past the dial role's (`listen`) | 161 | none |
| the links lent their buffers and cells | 135 | |
| the runtime placed and confined, the session's time | 197 | |
| the wait room, the clock's wake, the face plane, the admission | 571 | the wait room alone |
| the face table and the dial face (`LinkSupervisor::new`, `Face`, `UnicastLink::new`) | 619 | 205 of the API build's build one refusal's value in line (`LendRefused::Exhausted { asked: Some(..), left: 0 }`), which the pico ABI answers as `Z_ERR_SYSTEM_OUT_OF_MEMORY` alone (`coop_open_refusal`) |
| `Core` built in the frame | 838 | with the row below, about 1,050 bytes (0xc68 to 0x1081): four copies of 896, 880, 448 and 584 bytes and about 110 single moves; `engine_of` (762) then writes `Core` again where the engine lies |
| `LentApart` and the call of `engine_of` | 234 | (in the row above) |
| the closing brace: the drops of what is held, on each refusal after the lend | 1,173 | drop ladders of about 900 to 1,150 bytes in all (an estimate from the control flow; their calls: `Kept::release`, `let_go::<OneTask>` three times, three lock and unlock pairs of `wz_host_sync::RawLock`, `drop_rows` twice, `registry::let_go`): each refusal after the first table leaves `SessionLent` drops a different remainder of it, field by field |

### 3.2 `lend_session` (the case's, 4,290)

By owner: `arena` 1,204, `engine` 1,143, `bounded` 789 (the table lender, language area), its
closures 254, `lodging` 228, `chain_staging` 151, `slot_map` 124, `key_arena` 91, `byte_cells`
86, `reassembly_dispatch` 64. In its instructions: the region's rows laid on the plan (`lay_out_on`,
with one `bcmp`), two `memset`, six `cell_spans` and two `lend_stride` of the lender, two `kept_span` (the runtime's and the engine's places, each with
a count of the arena), and `SessionLent` written out at its end (about 745 bytes from 0xdd4, with
two copies). The caller moves it out of its `Result` (3.1) and then moves its fields into `Core`,
which `engine_of` writes again: the same tables are moved three times between the arena's lend
and the engine's place.

### 3.3 The door

API build lines of `open_on_coop` (inlined in `z_open`): `PicoSessionExt::new` 1,501 (with
`connectivity`), the engine's `CoopConfig` built in the frame 561 and moved into `OpenInput` 448,
`PicoSessionHandle::new` 347, the request moved out of `open_request`'s `Result` 520,
`group_endpoint` 265. In the case: `wz_capi_pico::session` is 2,012 of `z_open`; `open_request`
is `session` 692, `process_pool` 493, `endpoint` 92, `config` 85. `ConfigEntries::get` is called
four times in `z_open` and five in `open_request`: the connect and listen keys are read by
`open_config`, again at the head of `open_on_coop`, and again for the texts the engine writes.

## 4. Steps, by kind

Kinds as in `base-sessions`: **shape** (the same job written larger: an inline copy, a value
moved through layers, an over-generalization the case never takes), **work** (a behaviour wz has
and zenoh-pico does not: a switch the zenoh-pico preset turns off). No step adds a call to the
receive, the delivery or the put. Each is read on the case's total and reverted when the total
does not move by its expectation.

| step | change | expected (estimate) | receive | basis |
|------|--------|--------------------:|---------|-------|
| **O1 S-ZID (carried here)** | one out-of-line body, `wire_zid`, puts every zid the open takes or makes in its wire form: the configured one (`wire_form`), a drawn one (`fresh_zid`) and a derived one; the drawn zid's own all-zero walk goes, its refusal read off `wire_zid`'s | -150 to -350 | 0 | `session_zid` 815 holds two walks to the last non-zero byte (one an arm), two copies of the bytes into a `SessionZid`, and an all-zero walk before the second |
| O2 one refusal after the lend | every fallible step after `lend_session` runs before the first table leaves `SessionLent`, or takes it by reference: the rooms' place reserved by size and written after (`place_with` takes `room_places` today), the runtime's place held to `RuntimeTables::placed_bytes` before `runtime` takes it, the face table's wait room reserved before `links` is handed over; what was lent is then dropped whole, by one out-of-line drop, on every refusal | -400 to -800 | 0 | the drop ladders of 3.1 (about 900 to 1,150); the API build's closing brace, 1,173 |
| O3 the lent groups moved whole | `Core`'s transport and state fields are the groups `lend_session` lends (`TransportTables`, the region's places, the step places), held as those values and not taken apart; `lend_session` writes `SessionLent` where its caller holds it, not through a `Result` | -400 to -800 | 0 | `Core` built in the frame (about 1,050), `SessionLent`'s tail (about 745) and its move out (about 280). `docs/win-budget/rss.md` A2 found field-by-field writes in place cost text: this moves groups whole, and is read on the case before it stays |
| O4 the refusal's value where it is read | the open's refusals carry the class the ABI answers, and their sizes (`LendRefused::Exhausted { asked, left }`, `ArenaRefused::NoMemory { bytes }`) are built in O2's one cold body, not in line at each refusal | -100 to -300 | 0 | 205 bytes at the face table's refusal alone (API build); `coop_open_refusal` reads the class only. Over-generalization |
| O5 the engine row where a reach is read | the process's table of engines (`RowClaim`, `ReachEngine`, `ROWS`, `MARKS`) only in a build with a reader of it: `query` (a get fan's canceller), `queryable` (the holder of a query its callback keeps), and the pico ABI's `connectivity`, `advanced` and `admin-space`, which name `EngineHandle`; elsewhere the open claims no row, `engine_of` fills none, the step that ends a session marks none and the close clears none | -600 to -950 | 0: the row's end is on the session's last step, a cold arm, and goes | the row's lines, 446 (`assemble` 119, `close` 88, the engine's drop 88, `link_turn` 85, `engine_of` 66), and the table's lock taken in each (`wz_host_sync` 264 of `assemble`, 60 of `engine_of`). **Work**: the bound of `ENGINE_ROWS` sessions open at once in a process (`OpenError::NoEngineRow`) goes with it in such builds; zenoh-pico bounds none. Touch points: `CoopEngine::reach`, `assemble`, `engine_of`, the two `reach.end()` (`engine.rs`'s step and `engine/direct.rs`), `close` and the drop's `reach.clear()`, `engine/hold.rs` (`EngineHandle`, `downgrade`, the `EngineHolder` impl `wz-ext-pubsub`'s advanced subscriber takes), `tests/engine_rows.rs` |
| O6 the door reads connect and listen once | `open_on_coop` holds the config from its head and reads the two keys once, for the group, the lists and the texts | -50 to -90 | 0 | two of `z_open`'s four `ConfigEntries::get` are repeats |
| O7 an endpoint's text read once | the door's check of each unicast endpoint (`checked_endpoint`: `kept_text`, `PicoEndpoint::write_text`) and the engine's write of the same text into its row (`OpenEndpoints::write_into`, `write_text`) become one reading: the write refuses what the check refuses, with the code the door answers | -300 to -600 | 0 | 1,865 against pico's 550; the two grammars are read side by side before a step is written |
| O8 the request and the config not moved through the door | `open_request` writes the request where `z_open` holds it, not through a `Result` (its frame still returns before the open), and the engine's config is built where `OpenInput` holds it | -200 to -450 | 0 | API build: 520 moving the request out, 561 building the config, 448 moving it into `OpenInput`, which `assemble` moves into `Core` |
| O9 the open's heap cells | the entropy source's cell (`SessionEntropy::try_held`) and the face table's wait room (`LinkSupervisor::new`'s `try_reserve_exact`) lent from the plan, so the case's open takes no heap | 0 to -150 | 0 | the no-heap contract; `RawVecInner::finish_grow` stays, its other callers being `BoundedString::push_str`, the IP stack and three doors |

The steps together: about -2,200 to -4,500 of the open's +12,902. Of the rest, about 4,000 is the
no-heap contract's lay-out (decided, kept) and the dial and the listener are won (-1,934); what is
left unread is the door's session state (`PicoSessionExt::new`, `PicoSessionHandle::new`) and the
config's limits read (`state_over` 609, `open_request`'s own 692).

## 5. O1 as carried

`crates/wz-capi-coop/src/engine.rs`: `wire_zid` (`#[inline(never)]`) judges the length of the
bytes as given (past sixteen is `ZidError::LengthOutOfRange`), keeps them up to their last
non-zero byte, and makes the `SessionZid` once; bytes with no non-zero byte are kept whole, so
`SessionZid::new` refuses them with their own length as before. `wire_form` is `wire_zid` of
the zid, which never refuses one. `fresh_zid` fills sixteen bytes and answers `wire_zid`'s zid,
or `OpenError::EntropyUnavailable` for sixteen zero bytes, as it did. Every input answers what it
answered before.

The test `a_drawn_zid_is_trimmed_and_a_draw_of_zero_bytes_is_the_entropy_refusal` (`tests.rs`)
draws a zid with a zero byte inside it, one of sixteen non-zero bytes, and one of zero bytes, and
hands `wire_zid` seventeen bytes whose last is zero. The existing
`made_bytes_of_zero_or_seventeen_are_refused_as_a_zid` and
`the_wire_form_of_a_zid_ends_at_its_last_non_zero_byte` hold the refusals and the trimming.

What the main session reads to land it: the case's total, and `session_zid` and `wire_zid` in the
explain document (`session_zid` 815 before); the receive at arm W, which should not move.

## 6. O2 as carried

`crates/wz-capi-coop/src/engine.rs` (`CoopEngine::assemble`): every step after `lend_session`
that can refuse now runs while `SessionLent` is whole, in this order: the texts, the entropy's
cell, the zid and the rooms' place (one refusal, as before), the faces past the dial role's
(`listen`), the connectivity plane, the admission (`listen`), the wait room and the runtime. Only
then do the tables leave it: the links are lent their buffers and cells, the rooms are written in
their place, and the face table is made. So each refusal lets go of what was lent by the drop of
`SessionLent` as a whole, nested under the drops of what the open made before it, and none drops a
different remainder of it field by field.

- The rooms' place is reserved by size and written after: `Arena::vacant` lends a span for one
  value and writes nothing (`wz_session_core::placed::Vacant`), and `Vacant::fill` writes the
  rooms there once nothing after them refuses; `Arena::place_with` is that pair. Where the tables
  take their memory on use the rooms lie in an allocation of their own, reserved and filled at the
  same two points: `OwnPlaced::vacant` takes it and writes nothing (`OwnVacant`, given back
  unwritten if a step before the fill refuses), and `OwnVacant::fill` writes the rooms there and
  hands back their owner (`Core::rooms`).
- The wait room is reserved before the links are handed over: `wz_runtime_coop::faces::WaitRoom`
  is reserved by the open and handed to `LinkSupervisor::with_room`, which cannot refuse;
  `LinkSupervisor::new` is the two together.
- The runtime is made from `SessionLent::runtime`, a span with nothing to drop, so the move of it
  leaves the drop of the rest whole; it is made after every other step that refuses.
- What stays: a build with `udp-listen` hands its ports' rows to the stack, whose book of them is a
  cell of the heap (`lend_port_rows`), after the links' buffers; that refusal drops what is left
  apart. The case builds no `udp-listen`.

No refusal changed its value, and every input answers what it answered before. The test
`an_open_refused_at_its_drawn_zid_gives_its_arena_back_once` (`tests/arena.rs`) refuses an open
inside the one refusal of the three, once the entropy's cell is held, and reads the arena given back
once and whole; `an_open_refused_after_its_lend_gives_its_arena_back_once` holds the text's
refusal. `a_vacant_span_holds_nothing_until_it_is_filled` (`placed.rs`) and
`a_supervisor_made_over_a_reserved_wait_room_holds_that_room` (`faces.rs`) and, with
`tables-on-use`, `an_own_vacant_allocation_holds_nothing_until_it_is_filled`
(`engine/state_places.rs`) hold the new makers.

What the main session reads to land it: the case's total and `assemble` in the explain document
(4,598 before), the receive at arm W, which should not move.

## 7. O3 held: the lent groups have more than one owner

The step assumed that `Core` could hold the groups `lend_session` lends as those values. The code
holds no such group whole after the open, so the step is not carried, and is written again once the
owners below are one:

- `TransportTables` is handed to three holders: the stack takes the links' buffers, the drivers'
  cells and the ports' rows by value (`SessionLinks::lend_buffers`, `lend_cells`,
  `lend_port_rows`); `Core`'s transport takes the endpoints' rows and the gate, action and halves
  cells; the engine takes the handed table (`LentApart`). The reassembly cells are read by reference
  (`SessionChains::over` in `lend_session`, `DirectFaces::taken_in`) and held by none of them.
  Holding the group whole in `Core` would take the buffers back from the stack, whose links read
  and encode in them.
- The state's tables are not one group either: the registry, the keys, the planes, the gets and the
  round are fields of `SessionState` beside values the open makes from the config and the policy
  (the watchers, the key ids, the replay's pace), and `Core` already holds the step places and the
  state's block whole (`_steps`, `_state`). A `SessionState` that held them as one lent value would
  rename every reach of them through the session, and `docs/win-budget/rss.md` A2 found that
  writing fields in place costs text: this is a design to measure, not a rename to make unread.
- Writing `SessionLent` where its caller holds it, not through a `Result`, leaves the caller a place
  it can only read fields out of by copy (`MaybeUninit::assume_init`) or by `ptr::read` of each
  field, unchecked by the compiler; either keeps the copy the step was to remove, or trades it for
  unchecked moves.

What would carry it: a `Core` built where the engine lies (`engine_of` writes it there today, after
`assemble` built it in the frame), each group written there once by its lender. That is the
structure of the place the engine is written at, and it is read on the case before it is written.

## 8. O4 as carried

`crates/wz-capi-coop/src/engine.rs`: the open's refusals of memory are built by three bodies, each
out of line and cold: `lend_refused` (`OpenError::Arena(ArenaRefused::Lend(..))`, the lend's own
refusal), `lend_exhausted` (`LendRefused::Exhausted { asked: Some(asked), left: 0 }`, the runtime's
span and the wait room) and `heap_refused` (`ArenaRefused::NoMemory { bytes }`, the entropy's cell,
the admission's rows, the ports' book). Each step of `assemble` that may be refused so hands its
refusal or its size to one of them (`map_err`, `ok_or_else`), and builds no value of the open's
refusal in line; the two refusals that were built eagerly (`ok_or`) on the path that succeeds are
built only when they are taken.

The values keep their sizes: the Rust surface and the tests read them (`OpenError` is `PartialEq`),
so the class alone, which is all `coop_open_refusal` reads, is not what the open answers. The test
`the_opens_refusals_of_memory_are_the_values_its_steps_answered` (`tests.rs`) holds each body's
value. What the main session reads: `assemble` and the case's total; the three bodies appear apart.

## 9. O5 as carried, with a reader the reading missed

The reading named the table's readers as the requesting end, the answering end and the pico ABI's
`connectivity`, `advanced` and `admin-space`. The code has one more: the pico ABI's `object-pool`,
whose doors hold the table to the count of sessions the program states (`process_pool::install`,
`RowClaim::hold_to`) and give it up with the pools (`RowClaim::let_go_of_count`). The step is
carried with it.

- `crates/wz-capi-coop/Cargo.toml`: the feature `engine-rows` keeps the process's table of engines;
  `query`, `queryable` and `connectivity` turn it on (the pico ABI's `advanced` and `admin-space`
  reach it through those), and so does the pico ABI's `object-pool` (`wz-capi-coop?/engine-rows`).
  It is in the crate's default build, as in the zenoh-pico preset.
- Without it (`any(feature = "engine-rows", test)` false): `engine::reach`, `RowClaim`,
  `RowsRefused` and `EngineHandle` are not built, the engine has no `reach` field, `assemble` claims
  no row, `engine_of` fills none, a step that ends the session (`engine.rs` and `engine/direct.rs`)
  marks none, and the close and the drop clear none. `OpenError::NoEngineRow` stays and is never
  answered. The unit tests keep the table whatever the feature says, as they read it.
- Work: a build without a reader bounds the sessions open at once by nothing but its memory, as
  zenoh-pico does; the fixed policy's `ENGINE_ROWS` bounds a build with one.

The test `engines_past_the_builds_rows_are_held_at_once_where_no_table_keeps_them`
(`tests/no_engine_rows.rs`, built only without `engine-rows`) makes and holds one engine past
`ENGINE_ROWS` and reads every arena given back after; on the fixed policy a build that claims a row
refuses the last one. `tests/engine_rows.rs` is built only with the feature. What the main session
reads: the case's total (the case builds none of the readers), `assemble`, `engine_of` and `close`
in the explain document, and the receive at arm W.

## 10. O6 as carried

`crates/wz-capi-pico/src/session.rs`: `endpoint_keys` reads the connect and the listen key of a
config, in that order, where the config holds them, and is the one reading of them: `open_config`
(what the config tells `z_open` and `zext_config_device_requires`) reads them through it, and
`open_on_coop` takes the config out of the request at its head and reads them through it once, for
the group, the endpoints' lists and the texts the engine writes (`stated_texts`), where it read them
twice before. The config's place is given back where it was, once the engine has written the texts.
The test `the_endpoint_keys_are_read_where_the_config_holds_them_connect_first` holds the order
and that the texts are the config's own. What the main session reads: `z_open` in the explain
document (2,876 before).
