# Structural lane sz-open: the session's open, line by line

Status: the reading and the design of the lane, with its first step (O1) carried in beside it.
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
