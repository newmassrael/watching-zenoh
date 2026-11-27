# Feature lane feat-adv: what `advanced` costs, and which part of it is form

Status: design of the lane. Its first step (A1 and A2, section 5) and its second (A3 to A10 but
A8, and the switches of section 6) are committed beside it. Nothing here was built by this lane. Every byte figure is either **read** or an **estimate**:
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
| F8 | the publisher's plane built by value into its `Arc` and the composite moved out of `declare_on` | `wz-capi-pico/src/advanced.rs` 604 to 605, in `ze_declare_advanced_publisher` | 1,820 | inline copy (moves) | A8 |
| F9 | the heartbeat's key split into a `Vec` to read four of its chunks | `advanced_subscriber/plans.rs` 545 | 540 | over-generalisation | A9 |
| F10 | two periodic jobs, each its own closure and its own inlined ticker start | `host.rs` `declare_over` (the retention and the periodic job) | about 400 (estimate) | generic copy | A10 |
| F11 | the lock's fast path inlined at every lock and unlock | `wz-host-sync` `in_place.rs` 84, 186, `lib.rs` 177 to 239, over 21 bodies (driver area) | about 3,360 | inline copy | not stepped |

F11 is the larger part of the driver area's excess, and zenoh-pico's lock is a call into the
platform (`_z_mutex_lock`, outside its library). It is not stepped here: the lock's inlining is
the same in every build, so moving it out of line moves the receive path of the minimal case too,
which this lane may not.

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
| A8 | not taken | the composite holds its plane by `Arc` for its heartbeat job, in three crates' callers; placing it in the session's place needs that ownership changed first | (-1,000) |

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
