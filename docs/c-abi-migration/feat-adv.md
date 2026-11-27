# Feature lane feat-adv: what `advanced` costs, and which part of it is form

Status: design of the lane. Its first step (A1 and A2, section 5), its second (A3 to A10 but
A8, and the switches of section 6) and its third (A8, and A11 to A13 of section 9) and its fourth (A14 to A19 of section 9) are
committed beside it, and so is the plane's retraction (section 11.1); section 8 reads what remains and section 9 steps it. Nothing here was built by this lane. Every byte figure is either **read** or an **estimate**:
read figures come from the libraries the size ledger's `--per-feature` run left on
2026-11-27 (case `pico-api-coop-nostd`, pin 6a881c21dad1): the shipped library of the step
before `advanced` and of the step that turns it on (symbol sizes), and the unstripped library of
the run's last step (`+connectivity+multi-thread`, which carries the same advanced bodies) for
the line tables. The per-feature report holds areas only, no owners or bodies, so the pairing
below was read from those libraries; `--explain pico-api-coop-nostd` is the reading to repeat it
with once the per-feature branch lands.

## 1. The reading

The step `advanced` (it turns on `unstable-api` too; zenoh-pico's switches
`Z_FEATURE_ADVANCED_PUBLICATION`, `Z_FEATURE_ADVANCED_SUBSCRIPTION` and
`Z_FEATURE_UNSTABLE_API`) on top of scout, peer, multicast, query, queryable, liveliness and
liveliness-get (read, the ledger's line reading):

| area | wz adds | zenoh-pico adds | excess |
|------|--------:|----------------:|-------:|
| doors | 79,001 | 25,725 | 53,276 |
| sessions | 18,106 | 2,966 | 15,140 |
| language | 14,375 | 3,983 | 10,392 |
| driver | 8,090 | 389 | 7,701 |
| transport, codec, keyexpr, unplaced | 2,054 | 685 | 1,369 |
| **total** | **121,626** | **33,748** | **87,878** |

The symbol reading of the same two libraries adds 122,142 bytes over 396 bodies (within 0.4%
of the line reading). The doors area holds `wz_capi_pico`, `wz_capi_port` and the whole of
`wz_ext_pubsub` (the ledger's owner rules), so the advanced plane's rules sit in doors on the wz
side as zenoh-pico's `src/api/advanced_*.c` and `src/collections/advanced_cache.c` do.

## 2. The same work, paired

Bodies sorted by the work they do, read by symbol (a body inlined into another counts in its
caller). zenoh-pico's are its symbols that the step adds; wz's are the bodies whose size the step
changes.

| work | zenoh-pico | wz | wz - pico |
|------|-----------:|---:|----------:|
| subscriber: declare, its gets, its jobs, teardown | 12,195 (`ze_declare_advanced_subscriber` 3,104, `_ze_advanced_subscriber_populate_query_params` 1,201, `_run_query` 737, the query drop handlers, `_clear`/`_undeclare`) | 27,952 (`wz_capi_pico::advanced::declare_subscriber_state` 13,469 with the host's `declare_in`/`declare_over` inlined, `PicoSubscriberForms::form` 2,978, `ze_declare_background_advanced_subscriber` 2,524, host `Finish::run`, `issue_*`, drop glue of the host's types) | 15,757 |
| subscriber: order a sample, hold it, hand it on | 4,665 (`__unsafe_ze_advanced_subscriber_handle_sample` 2,769, `_subscriber_callback` 556, sequenced state, the sorted maps) | 16,901 (`State::admit` 3,870, `drain_timestamped` 2,045, `flush_sequenced` 1,093, `Outlet::hold/first/find/hand_on` 3,321, `reclaim_expired_sources` 1,429, `hand_adv_sample` 899) | 12,236 |
| subscriber: late publishers and heartbeats | 2,713 (`_liveliness_callback` 1,108, `_parse_liveliness_keyexpr` 638, `_heartbeat_callback` 825) | 8,697 (`on_late_publisher` 3,524, `on_heartbeat` 2,196, `parse_heartbeat_source` 1,034, `zenoh_hex_to_zid` 802) | 5,984 |
| miss listeners | 1,195 | 4,477 (`MissRooms`, `fire_adv_miss` 1,015, `MissHandlers` and its drop glue) | 3,282 |
| publisher: declare its four entities, undeclare | 5,022 (`ze_declare_advanced_publisher` 2,641, `_heartbeat_handler` 519, clear) | 12,863 (`ze_declare_advanced_publisher` 7,125, `PicoPlane::declare_publisher` 1,148, `declare_on` closures, drop glue) | 7,841 |
| publisher: put and delete | 1,910 | 5,818 (`ze_advanced_publisher_put` 2,126, `_delete` 1,283, `next_timestamp` 739, `NodeHlc::for_node_by` 985) | 3,908 |
| cache: keep a sample | 933 | 8,007 (`RecordRing` 4,222, `CacheStore::retain` 1,834, `Ring::keep`) | 7,074 |
| cache: answer a query (`_sn`, `_max`, `_time`, replies) | 1,479 (`_ze_advanced_cache_query_handler`) | 8,053 (the queryable's closure 3,665, `answer_from_ring` closures, `for_each_held`, `param_value`) | 6,574 |
| `_time` grammar and its numbers | 0 (in its base build: `src/utils/time_range.c`, 2,078; numbers by libc's `strtod`) | 8,315 (`f64::from_str` 3,287 and `dec2flt` 1,538, `time_range::parse_edge` 1,649, `add_secs` 877, `parse_duration` 382) | 8,315 |
| the unstable surface (entity ids, cancellation token, source info) | 3,381 | 3,043 | -338 |
| the session, the engine and the plain doors around the plane | 255 | 18,016 (see below) | 17,761 |
| **total** | **33,748** | **122,142** | **88,394** |

The last row is the step's growth outside the plane's own code: bodies that went out of line
because the plane is a second caller of the doors' internals (`get_on_wire` +4,403 against
`issue_get` -4,184, `declare_liveliness_subscriber_on_wire` and `declare_queryable_on` against
the bodies they left), the session's open laying out the advanced places and the ring
(`z_open` +980, `PicoSessionHandle::new` +994, `lend_session` +344), and the receive path
reading a push's source info and timestamp (`hand_lent_push` +1,530, `read_direct` +1,358).
zenoh-pico reads the source info in every build (`src/protocol/codec/message.c` @
`_z_source_info_decode`, ungated), so part of this row is a cost it pays in its base and wz pays
in this step; the explain report of the case splits it.

## 3. Where the difference is form

Read from the line tables: each figure is the bytes whose innermost wz frame is the named line,
summed over the bodies named.

| id | form | where | bytes (read) | kind | step |
|----|------|-------|-------------:|------|------|
| F1 | the subscriber's table of gets made by value: 16 rows' stores unrolled into the declaration | `advanced_subscriber/host.rs` `Shared::write_in` (`core::array::from_fn`), in `declare_subscriber_state` | 2,000 | unrolled table | A1 (done) |
| F2 | core's integer reader inlined at each selector value the cache reads | `advanced_cache.rs` `answer_from_ring` (`_max`) and `parse_sn_range` (three), in the cache queryable's closure | 1,639 | inline copy | A2 (done) |
| F3 | the record ring's word reads and writes, each with its own bounds check, inlined at every field | `advanced_cache/ring.rs` `read_u32`, `write_u32`, `read_u64` (lines 128 to 136, 272), over 15 bodies | about 4,100 | inline copy | A3 |
| F4 | the subscriber's state, options and handle moved by value through `declare_in`, `declare_over` and the door, and the error paths' drops | `host.rs` 184 (712), 746 (742), 894 (552); `wz-capi-pico/src/advanced.rs` 1564 (600) | about 2,600 | inline copy (moves) | A4 |
| F5 | the source table's lookup inlined at each caller | `advanced_subscriber/state/sources.rs` 51 (515, 4 bodies), 91 (632, 2 bodies) | about 1,150 | inline copy | A5 |
| F6 | two sets of miss listeners: the C ABI's `MissRooms` behind one lent listener of the machine's `MissHandlers` | `state.rs` `MissHandlers::fire` 558 and its drop glue 775, `wz-capi-pico/src/advanced.rs` `fire_adv_miss` 1,015, the drop of its lodged `Strong<MissRooms>` 229 | about 2,600 | overlapped layer | A6 |
| F7 | the plane's refusals formatted into a `String`, which the door turns into one code | `wz-capi-pico/src/advanced_plane.rs` 73 (`format!`), `alloc::fmt::format_inner` 335, `String` as `Write` 363, `i8` as `Display` 170 | about 1,000 | over-generalisation | A7 |
| F8 | the publisher's plane built by value into its `Arc` and the composite moved out of `declare_on` | `wz-capi-pico/src/advanced.rs` 604 to 605, in `ze_declare_advanced_publisher` | 1,820 | inline copy (moves) | A8 (done) |
| F9 | the heartbeat's key split into a `Vec` to read four of its chunks | `advanced_subscriber/plans.rs` 545 | 540 | over-generalisation | A9 |
| F10 | two periodic jobs, each its own closure and its own inlined ticker start | `host.rs` `declare_over` (the retention and the periodic job) | about 400 (estimate) | generic copy | A10 |
| F11 | the lock's fast path inlined at every lock and unlock | `wz-host-sync` `in_place.rs` 84, 186, `lib.rs` 177 to 239, over 21 bodies (driver area) | about 3,360 | inline copy | the multi-thread lane |

F11 is the larger part of the driver area's excess, and zenoh-pico's lock is a call into the
platform (`_z_mutex_lock`, outside its library). It is not stepped here: the lock's inlining is
the same in every build, so moving it out of line moves the receive path of the minimal case too,
which this lane may not. The row went to the multi-thread lane, which owns `wz-host-sync`.

## 4. Work that differs (owner decisions)

| id | what | zenoh-pico | wz | bytes (read) | off, it loses |
|----|------|------------|----|-------------:|---------------|
| O1 | the numbers of a `_time` selector | parses them with libc's `strtod` (`src/utils/time_range.c` @ `_z_time_range_parse_duration`), outside its library | parses them with core's `f64::from_str`, upstream's grammar (exponents, `inf`, `nan`), inside the library | 4,825 (language) | (a) keep: none; (b) the platform's `strtod` where it has one, as zenoh-pico does: the library loses the bytes, an image that links `strtod` carries them still; (c) an exact decimal reader (about 400): a `_time` with an exponent or `inf` reads as no range, so every sample answers |
| O2 | the retention sweep of sources that went away | none: a source stays in its heap maps until the subscriber goes | upstream's `gc_task` (`reclaim_expired_sources`, `set_source_alive`, its periodic job) | about 2,100 | the source table is fixed, so a table filled by sources that left refuses every new source until the subscriber is declared again |
| O3 | what stamps a put | `z_timestamp_new`, the system clock | the node's HLC (`NodeHlc`, upstream's `uhlc`) with the clock-quality policy (`trusted-only`) | about 2,500 (driver, sessions) | off for the pico preset: stamps from the wall clock as zenoh-pico's; two puts in one tick are no longer ordered by the stamp, and the `trusted-only` refusal goes |
| O4 | where a cache keeps its samples | copies on the heap (`_z_sample_copy` into a `z_malloc` outbox) | records in the session's ring of cached samples, refused when longer than the ring | (row "cache: keep") | the no-heap contract of the C library; not proposed off. Its form part is F3 |
| O5 | one neutral host for both engines | the advanced code calls its own entry points (`z_declare_subscriber`, `z_get`, `z_liveliness_*`) | the host over the engine port (`docs/advanced-pubsub-on-a-neutral-core.md`), with the declaration forms (`PicoSubscriberForms` 3,378) naming each entity as pico's own entry points do | (rows "subscriber: declare", "publisher: declare") | off for the pico ABI: its plane would call the doors directly, as zenoh-pico does; the tokio engine and the cooperative one would run two hosts |
| O6 | the receive path's source info and timestamp | read in every build | read in builds with `pubsub-source-info`, which `unstable-api` turns on | up to 2,900 (sessions: the growth of `hand_lent_push` and `read_direct`; the explain report splits it) | a parity of accounting, not of code: wz's minimal build does not carry what zenoh-pico's base does |

## 5. The steps

Each step removes one form row, leaves the bytes of the minimal case `pico-client-coop-nostd`
and the code its receive path runs unchanged (`wz-ext-pubsub` is not linked there), and adds no
call on a path a sample takes, the advanced subscriber's included, unless the row says so.

| step | row | what changes | estimate on `pico-api-coop-nostd` | path |
|------|-----|--------------|------------------------------------:|------|
| A1 | F1 | the table of gets written row by row in place through one out-of-line body (`GetSlot::write_empty`) | -1,800 | declaration |
| A2 | F2 | one out-of-line reader of a selector's `u32` (`selector_u32`) for `_sn`'s two bounds and `_max`; `_max` read as upstream reads it, a `u32` (a cap past one caps no ring's samples, as no cap does) | -1,100 | a query's answer |
| A3 | F3 | the ring's state as a fixed 32-byte array and a record's header read once as a fixed 88-byte view, so a field's offset needs no check of its own | -2,500 | the advanced put and the pending ring: fewer instructions, no call added |
| A4 | F4 | the state written in its place (`State::write_in`), `declare_over` over `&AdvancedSubscriberOptions`, the subscriber written into the door's state where it is known empty, the partly declared entities dropped through one value | -1,500 | declaration |
| A5 | F5 | the source table's lookup out of line for the cold callers (heartbeat, late publisher, a source's liveliness), inline in `admit` | -600 | cold callers only |
| A6 | F6 | one set of miss listeners: the machine fires the C ABI's set directly, `MissHandlers` kept for the tokio engine's own listeners | -1,500 | a miss |
| A7 | F7 | the plane's refusals carry the door's code and a static text, no `String` | -900 | refusals |
| A8 | F8 | the publisher's plane made in place in its session's place, `declare_on` handed it by reference | -1,000 | declaration |
| A9 | F9 | the heartbeat's key read by walking its chunks | -400 | a heartbeat |
| A10 | F10 | one periodic job body for the retention and the periodic re-ask | -400 | declaration |

A1 to A10 together: about -11,700 of the 87,878 (estimate). The rest of the excess is the work
of section 4 and the row "the session, the engine and the plain doors", whose split the explain
report of the case reads.

Step 1 (A1 and A2) is committed beside this document. Its tests:
`every_row_of_the_table_of_gets_is_written_free` (`advanced_subscriber/host/tests.rs`),
`a_selector_value_is_read_as_a_u32_is` and
`a_max_past_u32_caps_nothing_and_a_signed_one_caps_by_its_number`
(`advanced_cache/tests.rs`). What to read after it lands: the doors area of
`pico-api-coop-nostd` (expected about -2,900), `declare_subscriber_state` (13,469 now) and the
cache queryable's closure (3,665 now) in its explain report, and the receive instructions of
`pico-client-coop-nostd` (unchanged).

## 6. The owner's ruling: a switch for each behaviour zenoh-pico does not have

Ruling of 2026-11-27: each behaviour of the advanced plane that zenoh-pico does not have is a
capability of its own (`deploy/wz-config.toml`, `upstream_off = ["zenoh-pico"]`), on in a build
that names nothing and off in the zenoh-pico preset, as the send's behaviours are (`tx-probe` and
its siblings). The no-heap contract (O4) is not one of them. Each row of section 4, read against
the ruling:

| id | switch | why |
|----|--------|-----|
| O1 | none | zenoh-pico reads the same grammar (`strtod` takes exponents, `inf` and `nan`), so a `_time` selector means the same in both; what differs is where the reader's code lies, a form and not a behaviour |
| O2 | `advanced-source-retention` | zenoh-pico's subscriber keeps a source until the subscriber goes. Off: no retention job is started, a source carries no sweep bookkeeping, and a source keeps its row until the subscriber goes or a new source takes the row met longest ago among those that hold nothing back (`wz-ext-pubsub`'s `advanced-retention`) |
| O3 | `advanced-node-clock` | zenoh-pico's publisher stamps a sample with `z_timestamp_new`, the system clock. Off: the session holds no node clock (`wz-node-time`'s `time-hlc` is not linked), a sample takes the system clock's time ordered by the session's last time given, and `trusted-only` holds nothing back |
| O4 | none | the no-heap contract of the C library (owner) |
| O5 | none | one host for both engines is the structure the plane is written over, not a behaviour a build can leave out; a plane of the pico ABI's own would be a second implementation |
| O6 | none | a parity of accounting: the receive path's source info is already behind `pubsub-source-info` |

Both switches are off in the zenoh-pico defconfig and named by neither `host-peer` nor
`host-peer-ext`, so the like-for-like library (`pico-api-coop-nostd`) leaves them out and the
release library with it: `--size-features` holds the two profiles to the same features but the
doors. The tokio engine's runtime keeps both whatever is named.

## 7. Where the steps stand

| step | commit | what was done | estimate on `pico-api-coop-nostd` |
|------|--------|---------------|------------------------------------:|
| A3 | `refactor(ext-pubsub): Read the cache ring's headers as fixed arrays` | as planned; a header that does not lie whole in the span is no record | -2,500 |
| O3 | `feat(config): Make the advanced publisher's node clock a capability` | section 6 | -2,500 (with the clock's standing; the clock-quality machine of the session core may go with it, not counted) |
| O2 | `feat(config): Make the advanced subscriber's source sweep a capability` | section 6 | -2,100 |
| A4 | `refactor(ext-pubsub): Write the subscriber's machine in its place` | the machine written in its lock's place (`State::write_in`), `declare_over` over borrowed options, the door's subscriber written into its known-empty place; the partly declared entities are still dropped one by one | -1,100 |
| A6 | `refactor(ext-pubsub): Reach registered miss listeners through a table` | the registry's map is made by the first registration and reached through a table of its operations, so a host lent one listener (the pico ABI's set) links no code of the map; the lent listener still fires the set | -1,300 |
| A7 | `refactor(ext-pubsub): Name a plane's refusal by entity and door code` | `AdvancedPublisherError::Plane { entity, code }`, in both C ABIs | -900 |
| A5 | `refactor(ext-pubsub): Look up a source out of line off the sample path` | one out-of-line lookup for the cold callers, and the search for a new source's row out of line over the caller's test as an object | -600 |
| A9 | `refactor(ext-pubsub): Walk a heartbeat key's chunks instead of a Vec` | as planned | -400 |
| A10 | `refactor(ext-pubsub): Run both of a subscriber's jobs over one body` | `start_job` over a plain function per job | -400 |
| A8 | `refactor(ext-pubsub): Declare an advanced publisher in its host's place` | the ownership changed first: the beacon is sent through itself (`AdvancedPublisherPlane::send_beacon`, an associated function), so the heartbeat's tick holds no plane and the composite is its plane's one holder, by value (`plane: P`); `AdvancedPublisherOn::declare_in` writes the publisher field by field into a place the host gives, `declare_on` is it over a local place; the pico door declares into its slot (`Slot::try_fill_in_place`), and its plane reads the session's clock instead of holding a second handle of it. The tokio and C planes, which send the beacon on the key, declare a handle on their session as the beacon | -1,000, and the plane's heap allocation gone |

Together about -11,800 on `pico-api-coop-nostd` (estimate). None of it touches the minimal case
`pico-client-coop-nostd`, which links neither `wz-ext-pubsub` nor `wz-node-time`'s clock: its
bytes and its receive instructions are to read unchanged.

What to read after they land: `size_ledger_gate.py --measure pico-api-coop-nostd` and its
`--explain` (the doors area, `declare_subscriber_state`, `RecordRing`'s bodies, the cache
queryable's closure, `NodeHlc`'s and `reclaim_expired_sources` gone), and the bytes and receive
instructions of `pico-client-coop-nostd`. The generated files the switches add rows to
(`deploy/Kconfig.capabilities`, `configs/zenoh-pico_defconfig`, `items_generated.rs`) were written
by hand in the generator's form; `crates/wz-conformance-build/statement_vectors.json` was not, and
is to be written by `wz_config.py --write`.

## 8. What remains, read again

Read on 2026-11-28 from the unstripped library the capability-cost run left for
`pico-api-coop-nostd` (`libwz_capi_pico.so`, its line tables walked to the innermost wz frame of
each instruction). That library carries A1 to A7, A9 and A10 (the subscriber's state is written in
place there), and still links the source sweep and the node clock, so it predates the two switches
or names them; it does not carry A8 or section 9. Each row of section 2, what wz holds of it now,
and where its excess lies:

| work | zenoh-pico | wz now (read) | form (step) | contract |
|------|-----------:|--------------:|-------------|----------|
| subscriber: declare, gets, jobs, teardown | 12,195 | about 22,300 (`declare_subscriber_state` 11,696, `PicoSubscriberForms::form` 2,965, `ze_declare_background_advanced_subscriber` 1,835, the subscriber's drop 1,372, `issue_recovery_query` 1,182, `Finish::run` 1,173, `issue_get` 1,106, `GetParameters::history` 992) | the declared subscriber moved into the door's state (`advanced.rs` 1566 574, `host.rs` 882 492, 771 to 772 505): A14; the options cloned and rebuilt by value (`options.rs` 329 233, 622 211, 572 109): A15; the anchor rooms' table unrolled (`advanced_forms.rs` 95 388): A16; the get options' builder chain copied into each of five gets (`query_options.rs` 694, 397 in `on_late_publisher` alone): A12 (done); the background subscriber's array iterator (`host.rs` 942 to 965, about 730): A13 (done) | the forms (O5, none); the table of gets and the source rows are fixed tables, whose removal is a `retain` over a bounded table (`bounded.rs` 1009, 498 in the drop) where zenoh-pico frees a heap map (O4) |
| subscriber: order, hold, hand on | 4,665 | about 10,000 (`State::admit` 2,922, `drain_timestamped` 1,632, `Outlet::hold` 1,161, `hold_sequenced` 948, `flush_sequenced` 906, `hand_adv_sample` 906, `hold_timestamped` 611, `Outlet::find` 543, `hand_on` 387) | the sample handed on through two arms, a host's boxed closure and a lent C callback (`state.rs` 277 to 279, 300 in `admit` alone), where the pico library hands only the lent one: A19 | the samples held back in the session's record ring and not in a heap sorted map (`ring.rs` reads in `drain_timestamped`, O4) |
| subscriber: late publishers and heartbeats | 2,713 | about 5,400 (`on_late_publisher` 3,053, `on_heartbeat` 1,520, `parse_heartbeat_source` 795) and the sweep (O2, off in the preset) | the get options' copy (A12, done); the source lookup still inline in both callbacks in this reading (`sources.rs` 51, 91, 92), which A5 moved out of line: to confirm on the next reading | none |
| miss listeners | 1,195 | about 1,500 (`fire_adv_miss` 1,015, `MissRooms::remove` 471) | none left after A6 | none |
| publisher: declare | 5,022 | about 9,800 before A8 (`ze_declare_advanced_publisher` 7,595, its closure 778, its drop glue 758, `declare_publisher` 674) | A8 (done) | none |
| publisher: put and delete | 1,910 | about 4,100 (`ze_advanced_publisher_put` 2,090, `_delete` 1,302, `next_timestamp` 739) | the delete's own copy of the put's stamping: A11 (done) | the node clock (O3, off in the preset) |
| cache: keep a sample | 933 | about 5,200 (`CacheStore::retain` 1,834, `Ring::keep` 971, `RecordRing::write` 928, `held` 849, `in_ring` 621) | the heap backing (`Samples`, a `VecDeque`) linked beside the ring in a library whose sessions on the cooperative engine always keep a ring: `retain`'s heap arm (`advanced_cache.rs` 501 357, 338 167, 542 143, 344 111) and `Samples::for_each_held` (940 and its closure 468), about 2,200: A18 | the ring itself (O4) |
| cache: answer a query | 1,479 | about 4,000 (the queryable's closure 2,091, `param_value` 603, `selector_u32` 429, the ring's answer closures) | the `_time` grammar inlined into the closure (`time_range.rs` 231 to 292, about 700): with A17 | none |
| `_time` grammar and its numbers | 0 (its base: `src/utils/time_range.c` 2,078, `strtod` in libc) | about 7,700 (`f64::from_str` 3,287, `dec2flt` 1,538, `parse_edge` 1,649, `add_secs` 877, `parse_duration` 382) | the numbers' reader is core's in the library where zenoh-pico's is the platform's: A17 | zenoh-pico takes the leading number of a malformed value (see C-adv-4) |
| unstable surface | 3,381 | 3,043 | none | none |
| session, engine, plain doors | 255 | about 18,000 | second callers of the doors' internals (form of the doors' lanes, not this one) | the receive path's source info (O6) |

## 9. The steps after A10

| step | row | what changes | estimate on `pico-api-coop-nostd` | path | state |
|------|-----|--------------|------------------------------------:|------|-------|
| A11 | put and delete | `delete` is `put_sample` with the Del kind and no value, so the stamping, numbering, folding and keeping of a sample are one body for a put, a chunk and a Del | -700 | a delete: no call added | `refactor(ext-pubsub): Send an advanced delete through the put's body` |
| A12 | late publishers, declare | `get_options` out of line (`#[inline(never)]`): the five gets of a subscriber share one body of the builder's stores | -800 | a get: one call added, off the sample path | `refactor(ext-pubsub): Build an advanced subscriber's get options once` |
| A13 | declare (background) | the background subscriber lets its late-publisher and heartbeat entities stand by one arm each, not through an array iterator that moves both | -400 | declaration | `refactor(ext-pubsub): Let a background subscriber's entities stand apart` |
| A14 | declare | the subscriber declared in the door's state (`EngineSubscriber::declare_in` over a place, as A8 made the publisher's), the state's `subscriber` place written once | -1,500 | declaration | `refactor(ext-pubsub): Declare an advanced subscriber in its host's place` |
| A15 | declare | the options read where the caller holds them through `declare_over` and the forms, no clone and no builder returning `self` by value on the declaration's path | -500 | declaration | `refactor(ext-pubsub): Read a subscriber's options in its host's frame` |
| A16 | declare | the anchor rooms written row by row in the kept part's place through one out-of-line body, as A1 writes the table of gets (a constant repeated would be an interior-mutable constant) | -300 | declaration | `refactor(capi-pico): Write an advanced subscriber's rooms in its place` |
| A17 | `_time` | the value's text checked against upstream's grammar by wz (a few hundred bytes) and converted by the platform's `strtod` where the C library has one (its OS layer, as zenoh-pico reads it); core's reader stays for a build without a platform reader | -4,500 | a query with `_time` | `refactor(capi-pico): Read a time's numbers with the C library's strtod` |
| A18 | cache: keep | the heap backing of a cache linked only in a build with an engine that keeps no ring (the tokio engine); the cooperative engine's library holds the ring arm alone | -2,200 | a put with a cache: one branch fewer | `refactor(ext-pubsub): Link a cache's heap form only beside no ring` |
| A19 | order, hold | the boxed-closure arm of the sample's hand-on linked only with a host that hands a closure; the pico library calls the lent callback alone | -300 | the sample path: one branch fewer, one call | `refactor(ext-pubsub): Hand a subscriber's sample on through one form` |

A11 to A13 together about -1,900 on `pico-api-coop-nostd` (estimate); A14 to A19 about -9,300.
None touches `pico-client-coop-nostd`, which links no `wz-ext-pubsub`.

Tests of the third step: `the_beacons_timer_holds_no_plane` (red with a tick that keeps a hold of
the plane), `a_publisher_is_declared_in_the_place_its_host_gives` (red with a refusal that keeps
the plane, or a field `declare_in` leaves unwritten),
`a_delete_is_sent_and_kept_as_a_del_through_the_puts_body` (red with a delete that leaves the
put's kind; all three in `advanced_publisher/tests.rs`). A12 and A13 change no behaviour and are
held by the existing host tests. What to read after they land: `ze_declare_advanced_publisher`,
`ze_advanced_publisher_delete`, `on_late_publisher` and `ze_declare_background_advanced_subscriber`
in the explain report of `pico-api-coop-nostd`, and the receive instructions of
`pico-client-coop-nostd` (unchanged).

What the fourth step did, where it differs from the row, and its tests (all of them written for
the merge to run; none was run here):

- A14. `EngineSubscriber::declare_in` takes the place the subscriber is written in
  (`&mut MaybeUninit<Self>`) and answers it; `declare_over` writes the fields one by one after the
  last step that can refuse, as A8's `declare_in` does, and `declare_with` is it over a local
  place. The pico state's `subscriber` is a `MaybeUninit` written by the declaration and read for
  every state a handle names; the release drops it there and the background door reads it out.
  Test `a_subscriber_is_declared_in_the_place_its_host_gives` (`advanced_subscriber/host/tests.rs`):
  red with a subscriber made elsewhere and moved in (the answer is not the place), or a refusal
  after the subscription (an engine with no periodic jobs) that writes the place (its bytes are
  read back as the pattern written before).
- A15. `declare_in` reads the options by reference and takes the host's forms by value beside them
  (`options.forms` is `declare_with`'s, and a debug build refuses both); `declare_over` keeps the
  forms with no clone; an entity's form gives its keep to the entity (`EntityForm::into_kept`), and
  the pico forms name a form in place (`name_on_retraction`, `name_key_on_token_retraction`, `keep`)
  where a chain of builders moved it. Tests
  `a_form_named_in_place_reads_as_its_builders_and_gives_up_its_keep` (red with a setter that
  writes another field, or a keep handed on as a copy) and
  `a_subscriber_declared_in_a_lent_place_refuses_forms_in_its_options` (debug builds).
- A16. `AnchorRooms::write_vacant` writes each room through one out-of-line body
  (`AnchorRoom::write_vacant`), and the advanced subscriber's place is written where it lies
  (`Answering::write_at`, now also built with `advanced`), its kept part field by field
  (`AdvSubKept::write_in`), so no room is made on the stack and moved. Test
  `advanced_forms::room_tests::every_room_is_written_vacant_in_its_place`: red with a row left
  unwritten (the place is zeroed first, so such a row reads as held).
- A17. The grammar's numbers are read by a reader its caller names (`FloatRead`;
  `parse_range_with`, `parse_duration_with`), and a refusal is wz's `FloatError` in core's words,
  so `wz-zenoh-util` prints upstream's message whichever reader read it.
  As first landed, `time_range::decimal_text` wrote the number as an integer of at most 48
  significant digits and a power of ten, and a literal within a part in 10^48 of a halfway point
  between two `f64`s could round one ulp the other way. Main ruled that out, and the reader was
  remade as zenoh-pico's (`fix(capi-pico): Hand strtod a time's literal as its own bytes`):
  `decimal_text` checks `f64::from_str`'s grammar and copies the literal's own bytes and a NUL into
  a stack buffer (`DECIMAL_TEXT`, 778 bytes), so `strtod` reads exactly the literal and rounds it
  correctly, as zenoh-pico's copy is read (`src/utils/time_range.c` @
  `double value = strtod(bound->start, &err);`; zenoh-pico reads its argument and not the copy
  it makes, so it reads past the duration in the caller's text, which wz does not). Infinities,
  NaNs and zeros are answered without a reader. Two cases are written as `decimal_digits` writes
  them, with no radix character: a literal too long for the buffer, as its first 768 significant
  digits and a sticky `1` for any nonzero digit past them, which round exactly as the literal does
  (a halfway point between two `f64`s has at most 767 significant digits; core's reader keeps the
  same 768); and a literal `strtod` stopped short of, which is a C library reading another radix
  character in the locale the program set (zenoh-pico reads such a literal short). The buffer is a
  frame of the query handler on a unix host only; the kernels and Windows keep core's reader, as
  neither the DLL's C runtime nor an image's C library is a fact this lane established, and the
  stack frame gates measure the MCU images, which take that path. Tests
  `the_halfway_literals_round_to_even_and_away_from_the_halfway_point` (`1 + 2^-53`, which rounds
  to even, the literals a last digit either side of it, and the halfway point followed by 778
  zeros, with and without a last `1`: red with fewer digits kept than decide the rounding),
  `a_literal_that_fits_is_handed_over_as_its_own_bytes` (red with a copy that changes a byte or
  leaves off the NUL), `a_decimal_written_for_a_platform_reader_reads_as_core_reads_the_literal`
  (the halfway literals added) and `a_durations_number_is_read_by_the_reader_named`
  (`wz-session-core/src/time_range.rs`), `answer_from_ring_reads_the_time_with_the_reader_named`
  (`advanced_cache/tests.rs`), and `time_number_tests::the_c_librarys_reader_reads_a_time_as_core_does`
  (`advanced_plane.rs`, unix: the same halfway literals read by `strtod` to the bits core reads,
  red with a reading short of their digits).
  The bytes go only if nothing else of the library calls `f64::from_str`: the explain report
  says.
- A18. `wz-ext-pubsub`'s `cache-heap` (on by default; `wz-capi-pico`'s `engine-tokio` names it)
  gates the heap form of a cache (`Samples::Heap`, `CacheStore::new`, the plane's default
  `cache_store`); the cooperative library, whose sessions always keep a ring, refuses a cache on a
  session with none rather than keep it on the heap. Not a capability: no behaviour of a build
  changes, as the cooperative engine's sessions answer a ring at every open. Test
  `a_sample_pushed_into_a_cache_in_the_ring_is_kept_as_a_record`.
- A19. `OnSample` is one form, a function over a context and its drop: a lent callback is that, and
  a program's closure is boxed behind it (`call_boxed`, `drop_boxed`), linked only where a host
  hands one. The pico library's sample path is one indirect call with no branch; a Rust host's is
  one call more than before (the trampoline), a closure an allocation more at its declaration.
  Test `a_boxed_closure_is_called_through_the_lent_form_and_dropped_once`
  (`advanced_subscriber/state/tests.rs`). Measure-sensitive: main reads the receive instructions
  of the tokio engine's sample path (the advanced subscriber of a Rust host) beside the pico
  library's. If they grow, the step is cut back to the pico library: the lent form stays the one
  form of the cooperative library, and the tokio host keeps its direct closure arm.

What to read after they land: `declare_subscriber_state` and `ze_declare_advanced_subscriber`,
`PicoSubscriberForms::form`, the cache queryable's closure and the language area (`f64::from_str`,
`dec2flt` gone), `CacheStore::retain` and `Samples::for_each_held`, `State::admit` in the explain
report of `pico-api-coop-nostd`, and the receive instructions of `pico-client-coop-nostd`
(unchanged: it links no `wz-ext-pubsub`).

## 11. The plane's retraction (taken over from the facade lane)

`arch-l4-facade.md` section 4.2 (on `l4-facade-1128`, its F2) left the advanced plane's
entities each holding a count of the engine (`advanced_plane::KeptPublisher`, `KeptToken`,
`query::PlainQueryable`), because the composite holds them by value and lets go of them by
dropping them. A8 made the composite the plane's one holder (`plane: P`), so the plane can retract
what it declared: `AdvancedPublisherPlane` gains `retract_publisher`, `retract_queryable` and
`retract_token` (by default a drop, which the tokio and zenoh-c planes keep), the composite's
drop hands each entity to its plane in the retraction order, and the pico entities keep no engine
and are used and retracted on the plane's one count. Two facts decide its shape and are not on this
branch's base: F2's types (`KeptPublisher`, `KeptToken`, `WriteFilter::retract`) live on
`l4-facade-1128`, which this branch does not contain, and the beacon publisher is shared with its
timer's tick (`Arc`), so its retraction has to wait for the last tick in flight (the timer stopped
first, then `Arc::into_inner` on the composite's count). The admin space's two `PlainQueryable`s
are held by its own state and retract on the engine its place reaches. The step lands on
`l4-facade-1128` merged, as one commit across both ABIs.

### 11.1 Landed

`l4-facade-1128` was merged into this branch (the conflicts were the plane's fields, which F3
made the engine, the role, the clock and the time, and A8's beacon sent through itself), and the
retraction is one commit across both ABIs
(`refactor(ext-pubsub): Retract an advanced publisher's entities by plane`):

- `AdvancedPublisherPlane` has `retract_publisher`, `retract_queryable` and `retract_token`, by
  default a drop, which the tokio runtime's plane and both zenoh-c planes keep. The composite
  holds its publisher in a `ManuallyDrop` and its drop hands every entity to its plane through
  one body (`Declared::retract_on`) in zenoh-pico's order: the publisher, the key no cached
  sample took, the token, the beacon, the cache's queryable and then its store. A declaration
  refused after the publisher stood hands what stands back through the same body, so a refusal
  and a drop cannot retract in two orders. `AdvancedPublisherOn::plane` lends the plane.
- The pico plane's publisher is `PlainPublisher`, its token a `TokenId` and its queryable a
  `PlainQueryable` that keeps no engine: each is used and retracted on the plane's one count.
  `KeptPublisher` and `KeptToken` are gone; `AdvPubState` keeps no engine of its own either and
  reaches it through its plane (`AdvPubState::engine`), for the key it lends, the write filter
  the matching doors read and the publisher's id.
- The beacon's publisher (`BeaconPublisher`) keeps a count, because the timer's tick sends it
  with no plane, and it retracts itself when its last holder lets it go. Its timer is stopped
  first, after which no tick starts (`Tickers::stop_ticker`); the composite then lets go of its
  hold. A tick running at that moment holds the publisher to its end and retracts it there, so
  the retraction never precedes the last tick; the drop does not block on that tick, because the
  tick may be the very caller (a beacon delivered to a subscriber of the session whose callback
  undeclares the publisher) and no engine of this lane offers a wait for a running tick.
  zenoh-pico's heartbeat state is cleared, its beacon publisher with it, by its last holder in
  the same way (`src/api/advanced_publisher.c` @ `_ze_advanced_publisher_state_rc_drop(&state_rc);`
  in the heartbeat handler). This is where the step differs from the plan above (`Arc::into_inner`
  after an awaited tick).
- The admin space's two queryables are retracted on the engine the session handle reaches, by
  `zp_stop_admin_space` and by a start whose second declaration is refused. A session that
  closes takes them with it, as zenoh-pico's close flushes the session's queryables and forgets
  `_admin_space_queryable_id`; the handle's drive closes the session before its state, the admin
  space with it, is let go of.

Tests: `a_plane_sees_the_entities_declared_and_retracted_in_the_reference_order` and
`a_plane_sees_the_beacon_publisher_declared_after_the_token_and_retracted_before_the_cache`
(each entity is now handed back, `retract X` before `drop X`),
`a_refused_declaration_hands_what_stands_back_to_the_plane_in_order` and
`a_refused_beacon_hands_back_what_stands_before_it` (red with a refusal that lets an entity go
without handing it to the plane, or in another order; `advanced_publisher/tests.rs`);
`the_publishers_entities_are_retracted_on_the_planes_one_count` (`advanced_plane.rs`, tokio
engine: the declaration adds the plane's one count, and after the drop no key the entities
declared stands; red with an entity that keeps a count, or a plane that does not retract);
`an_advanced_publisher_holds_its_engine_through_its_place_and_its_plane` (`advanced.rs`,
cooperative engine through the C doors: two counts while declared, none after; red with a state,
a publisher or a token that keeps a count again).

Expected, unmeasured: `pico-api-coop-nostd` -200 to -500 (three counts' clones at the declaration
and their releases with their last-holder tests at the undeclaration, and `KeptPublisher`'s and
`KeptToken`'s drop glue, against one body that hands the entities back); the A17 correction
+200 to +400 (the copy, and the second reading for another radix). Receive Ir 0: no receive path
is touched; an advanced put reads the engine from the plane where it read it from
`KeptPublisher`, one load either way. `pico-client-coop-nostd` links neither.

What remains of the plane's holders: the cache's ring (`SessionCacheBytes`) keeps a count of its
own, as its store holds no plane, and the place's lender and the plane hold one each, as every
entity of the session and its declaring task do.

### 11.2 Two reds of the merge, repaid

The merge's verification found two reds of this lane, each repaid in its own commit:

- `fix(session-core): Write a time's decimal form with no index or overflow`. A17's
  `decimal_text` and `decimal_digits` indexed their buffer and summed with the plain operators,
  which `wz-session-core` denies in release code (its totality lints, `lib.rs`), so every crate
  linted over it was red. The form is now written through a sink (`Sink`) that writes a byte only
  where the buffer has one and refuses past it, so a `Decimal::Written` length has its NUL after it
  by construction and not by the buffer's arithmetic; the literal is split into its sign, its
  integer and fraction digits and its exponent by slices (`split_sign`, `split_digits`,
  `read_exponent`), and every sum saturates, which is exact here: `scale` moves one step a byte
  of the literal and the exponent is held at `u32::MAX`. The copy of a literal that fits is taken
  through `get_mut(..=len)`. Tests: `the_longest_form_fills_the_buffer_to_its_nul` (a sign, 800
  digits and a power under `-DECIMAL_EXPONENT`, which writes `DECIMAL_TEXT - 1` bytes and the
  NUL: red with a buffer a byte short, or a writer that cuts the form), and two exponents past
  `i64` in the corpus of
  `a_decimal_written_for_a_platform_reader_reads_as_core_reads_the_literal` (red with an exponent
  that wraps).
- `fix(capi-pico): Import Arc in the advanced tests only beside its users`. A8 imported `Arc` in
  `advanced.rs`'s tests for the tests that share a session, all of which run on the tokio engine;
  the default build (the cooperative engine) had the import unused. It is gated as they are.

A19's measurement is main's: no harness in the tree counts an advanced subscriber's receive.
`pico-compare.sh subprofile` counts `count_sub`, a plain subscriber, which does not reach
`OnSample`, so its receive Ir is unchanged by A19 on either engine by construction; the advanced
subscriber's sample path is read in the explain report (`State::admit`, `hand_on`) of
`pico-api-coop-nostd`.

## 10. Rows for `contract-switches.md`

The behaviours of this lane read as contract. `docs/c-abi-migration/contract-switches.md` is not on
this branch's base; these rows go there under the next free ids when the file is merged (the
`C-adv-` names are this document's only).

| id | behaviour | wz | zenoh-pico (the line that shows it) | switch |
|----|-----------|----|-------------------------------------|--------|
| C-adv-1 | the sweep of the sources that went away | upstream's `gc_task`, per subscriber | none: a source's state leaves only with the subscriber's (`src/api/advanced_subscriber.c` @ `_z_id__ze_advanced_subscriber_timestamped_state_hashmap_clear(&state->_timestamped_states);`, in the state's clear) | `advanced-source-retention`, off in the preset |
| C-adv-2 | what stamps an advanced put, and the `trusted-only` refusal | the node's HLC under the clock-quality policy | the session's `z_timestamp_new` (`src/api/advanced_publisher.c` @ `_Z_CLEAN_RETURN_IF_ERR(z_timestamp_new(timestamp, &sess_rc), _z_session_rc_drop(&sess_rc));`) | `advanced-node-clock`, off in the preset |
| C-adv-3 | where samples are kept: the cache and the subscriber's held-back samples | the session's ring and fixed tables, no heap after open | the heap (`_z_sample_copy` into `z_malloc`'d entries, sorted maps) | none: the C library's no-heap contract (owner) |
| C-adv-4 | a `_time` value whose number is malformed | refused as upstream refuses it, so the query takes no time filter; the grammar checked by wz and the number read by the C library's `strtod` on a unix host (A17) | its leading number is read and the rest ignored (`src/utils/time_range.c` @ `if (value == 0 && *err != '\0') {`, which refuses only a zero) | none: upstream's grammar; A17 keeps it |
| C-adv-5 | the receive path's source info and timestamp | read with `pubsub-source-info` | read in every build (`src/protocol/codec/message.c` @ `_z_source_info_decode`) | none: a parity of accounting (O6) |

