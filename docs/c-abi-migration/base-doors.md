# Migration lane base-doors: the doors area of the minimal case

Status: a reading of the `doors` area of the size ledger's case `pico-client-coop-nostd`
(`wz-capi-pico-lib`, `os-host,link-udp`, profile `capi-nostd`), each wz body paired with what
zenoh-pico 1.10.2 does the same work with, the steps that take the area's bytes in byte order, and
the first step that needs no decision built (section 5). Nothing here was built, run or measured
by this lane: every figure is read from the explain document of the case (main at the arch-put
landing, 2026-11-27: the case 205,921 B against 170,500 B, 1.21; the area 40,715 B against
19,034 B, +21,681), and every figure a step is expected to move is an **estimate** from the code.

## 1. How the area is counted

The rules place every file of `wz-capi-pico` in `doors`. zenoh-pico's doors are thin: its owned
types' doors are `_Z_OWNED_FUNCTIONS_VALUE_IMPL` jumps to `_z_<type>_copy`, `_z_<type>_move`
and `_z_<type>_clear` in `src/collections` (`language`); `zp_config_insert` is
`_zp_config_insert` (`language`); `z_bytes_writer_append` is `_z_bytes_writer_append_z_bytes`
(`language`); `z_open` is `_z_open` and `_z_session_init` (`sessions`); the write filter a
publisher declares is `_z_write_filter_create` (`sessions`). wz's doors hold that work
themselves. So the area's 2.14 mostly reads WHERE the same work is counted, not how much there is:
the zenoh-pico functions named below outside `doors` hold about 33.7 KB (an upper bound: the
collections among them serve other areas too), against wz's 40.7 KB in the area.

Verdicts: **form** (the same work, written larger): *overlapping layer* (the door does what
zenoh-pico's session or collection layer does, counted here), *generic copy*, *inline copy*,
*over-generalisation*, *moved by value* (a value written twice or copied where it could be written
once), *unread bookkeeping* (state written that nothing in the build reads). **Work** (wz does
something zenoh-pico does not): *switch* (the owner's ruling of 2026-11-27: a capability in
`deploy/wz-config.toml` with `upstream_off = ["zenoh-pico"]`), *no-heap* (the C library takes no
memory after its open, which zenoh-pico's heap does not need).

## 2. By group

Bytes are the area's (`doors`) for wz and zenoh-pico's doors, and the whole function for the
zenoh-pico counterparts in other areas.

| group | wz bodies (largest) | zenoh-pico counterparts | wz | pico doors | pico elsewhere | verdict |
|---|---|---|---:|---:|---:|---|
| open, close, drive doors | `z_open` 2,216, `open_request` 1,488, `release_handle` 113, `z_close` 82 | `z_open` 478, `zp_read` 97, `zp_spin_once` 81; `_z_session_init` 881, `_z_new_transport` 647, `_z_session_clear` 549, `_z_open` 430, `_z_config_client` 239 | 4,964 | 982 | 2,813 | form, overlapping layer; work: the stated limits (W1) and the pools' reservation at the open (no-heap) |
| config, endpoints | `ConfigEntries::insert` 704, `kept_text` 487, `state_over` 476, `write_text` 344, `zp_config_insert` 155, `position_named` 145, `trimmed` 109 | `_z_str_intmap_*` ~1,600, `_z_locator_from_string` 453, `_z_endpoint_*` ~1,100, `_zp_config_insert` 202, `_z_uuid_to_bytes` 190 | 2,991 | 416 | 4,605 | form, overlapping layer (a fixed table where zenoh-pico's intmap allocates); work: the limits key (W1, 730 B of bodies) |
| zid, info | `enumerate_peers` 322, `z_id_to_string` 125 | `z_info_peers_zid` 93, `z_info_routers_zid` 90, `z_id_to_string` 98 | 709 | 492 | 97 | same work |
| key expressions | `z_declare_keyexpr` 903, `kept_with` 882, `key_from` 728, `extended_from` 425, `store_canonized` 345, `key_compose` 337, `up_to` 298, `wire_key_of` 235, `KeyText::kept` 209, `outbound_keyexpr` 200 | `_z_register_resource_inner` 888, `_z_keyexpr_declare_prefix` 469, `_z_declare_resource` 310, `_z_undeclare_resource` 209, `_z_keyexpr_append_*` 423, view and owned constructors ~900 | 6,465 | 2,046 | 3,314 | form, overlapping layer; no-heap (the text kept in the session's key arena); work: the outbound gate (W2) |
| put, delete, publisher | `z_declare_publisher` 1,569, `publisher_write` 758, `session_write` 755, `PutCarried::fold` 418, `WriteFilter` drop 279 | `_z_write_filter_create` 1,054, `_z_write_filter_callback` 516, `_z_write` 361, `_z_write_filter_session_unregister` 311, `_z_publisher_put_impl` 302, `_z_declare_publisher` 266, `z_declare_publisher` 223, `z_put` 207, `_z_publisher_delete_impl` 203, `z_delete` 155 | 4,496 | 1,431 | 3,422 | form, overlapping layer (the write filter's rules in the door) |
| matching | `declare_on_filter` 592, `z_undeclare_matching_listener` 260 | `z_publisher_declare_matching_listener` 213, `_z_matching_listener_undeclare` 153, `_declare` 132, `_register` 125 | 1,100 | 572 | 590 | same work |
| subscribe, delivery | `declare_subscriber_with` 1,313, the sample views 422, `marshal_sample` 125 | `_z_undeclare_subscriber` 483, `_z_sample_steal_data` 332, `z_declare_subscriber` 222, `_z_declare_subscriber` 178, `_z_subscription_*` ~470 | 2,732 | 667 | 1,534 | form, overlapping layer; the receive path, left as it is |
| kept sample | `clone_sample_marshal` 1,150, `z_sample_clone` 133 | `_z_sample_copy_data` 329, `_z_sample_copy` 306, `_z_sample_move` 282, `_z_sample_duplicate` 252, `z_sample_take` 175 | 1,398 | 268 | 1,442 | form, overlapping layer; moved by value (F2) |
| bytes, slices, strings | `z_bytes_writer_append` 723, `slice_from` 645, `ByteBuf::reserve` 639, `Block::with_room` 441, `z_string_array_clone` 398, `store_slice` 329 | `_z_arc_slice_*`, `_z_bytes_*`, `_z_slice_*`, `_z_string_*`, `_z_svec_*` in `src/collections` | 7,522 | 4,698 | ~10,100 | form, overlapping layer (zenoh-pico's collections); the pools' take inlined (no-heap) |
| serialisation | `one_shot` 227, `write_into` 224, `deserialize_record` 210 | `ze_serialize_*`, `ze_deserialize_*` 150 to 200 each | 1,653 | 4,619 | 0 | wz smaller (one body for every width) |
| encoding | `z_encoding_set_schema_from_substr` 241, `z_encoding_to_string` 193 | `_z_encoding_convert_from_substr` 168, `_z_encoding_make` 164, `z_encoding_set_schema_from_substr` 141 | 1,611 | 1,343 | 635 | same work |
| time, clock, random, ids | `z_timestamp_new` 179, `interval` 139, `advance` 105, `z_time_now_as_str` 104 | `z_time_*`, `z_clock_*`, `z_sleep_*`, `z_random_*` in `src/system` (`driver`) | 1,433 | 471 | 2,038 | same work, wz smaller in all |
| channel substrate | `handlers::push` 409, `take_one` 181, `install` 180, `clear` 166, `_z_rc_*` | `_z_rc_*`, `_z_fifo_*`, `_z_ring_*`, `_z_sync_group_*` in `src/collections` | 1,366 | 0 | 3,078 | same work: `handlers.rs` defines zenoh-pico's own collection symbols |
| closures, callback guard | `callback_table::enter` 119, `CountIn::let_go` 95 | `z_closure_*` of five kinds | 329 | 531 | 0 | wz smaller |
| process pools, object places | `lay_stage` 378, `give_back` 322, `Pools::counted` 160, `take_slot` 146, `lend_into` 110 | none: `z_malloc` and `z_free` | 1,396 | 0 | 0 | no-heap; unread bookkeeping (F1, built) |
| ABI glue | `refusal_code` 119, `obj_drop` 60, `obj_move` 58 | `z_internal_*`, `*_loan`, `*_move` | 550 | 498 | 0 | same work |
| **total** | | | **40,715** | **19,034** | **~33,700** | |

## 3. By body

The forty largest wz bodies of the area (26,519 B, 65 %).

| # | wz body | wz B | zenoh-pico doing the same work (B, area) | verdict |
|---:|---|---:|---|---|
| 1 | `z_open` | 2,216 | `z_open` 478; `_z_open` 430 (sessions); `_z_session_init` 881 (sessions) | form, overlapping layer: the config's reading into the engine's open, which zenoh-pico does in `net/session.c`, is the door's (`open_on_coop`, inlined, one caller) |
| 2 | `z_declare_publisher` | 1,569 | `z_declare_publisher` 223; `_z_declare_publisher` 266; `_z_write_filter_create` 1,054 (sessions) | form, overlapping layer: the write filter's rules (`write_filter.rs`, 597 B inlined) |
| 3 | `open_request` | 1,488 | `_z_config_client` 239; `_z_uuid_to_bytes` 190 | work: the stated limits (W1, `resolve_open`) and the pools' reservation (no-heap, 493 B inlined) |
| 4 | `declare_subscriber_with` | 1,313 | `z_declare_subscriber` 222; `_z_declare_subscriber` 178; `_z_declared_keyexpr_declare_non_wild_prefix` 133 | form, overlapping layer |
| 5 | `clone_sample_marshal` | 1,150 | `z_sample_clone` 9 jumps to `_z_sample_copy` 306, `_z_sample_copy_data` 329 (sessions) | form, moved by value: the kept sample's marshal is written unbound and then written again over its parts (F2) |
| 6 | `z_declare_keyexpr` | 903 | `z_declare_keyexpr` 9; `_z_declare_resource` 310; `_z_register_resource_inner` 888 | form, overlapping layer; no-heap (the arena's place) |
| 7 | `DeclaredKeyexpr::kept_with` | 882 | `_z_declared_keyexpr_*` copy and move (keyexpr, language) | no-heap: the key's text shared in the session's arena |
| 8 | `publisher_write` | 758 | `_z_publisher_put_impl` 302+130; `_z_publisher_delete_impl` 203+60 | same work, one body for put and delete |
| 9 | `session_write` | 755 | `z_put` 207; `z_delete` 155; `_z_write` 361 (sessions) | same work; work: the canon refusal of the key (W2) |
| 10 | `key_from` | 728 | `z_view_keyexpr_from_substr` 140, `_autocanonize` 137, `z_keyexpr_from_*` | same work, one body for twelve doors |
| 11 | `z_bytes_writer_append` | 723 | `z_bytes_writer_append` 9 jumps to `_z_bytes_writer_append_z_bytes` 84, `_z_bytes_append_bytes` 169, `_z_bytes_writer_ensure_cache` 342 (language) | form, overlapping layer |
| 12 | `ConfigEntries::insert` | 704 | `_zp_config_insert` 202, `_zp_config_insert_string` 146 (language) | same work over a fixed table |
| 13 | `slice_from` | 645 | `z_slice_copy_from_buf` 91, `_z_slice_copy_from_buf` 114 | same work |
| 14 | `ByteBuf::reserve` | 639 | `_z_bytes_writer_ensure_cache` 342, `_z_svec_expand` 245 (language) | same work |
| 15 | `declare_on_filter` | 592 | `z_publisher_declare_matching_listener` 213; `_z_matching_listener_declare` 132, `_register` 125 | same work |
| 16 | `endpoint::kept_text` | 487 | `_z_endpoint_from_string` 97, `_z_locator_from_string` 453 (driver) | same work |
| 17 | `config_limits::state_over` | 476 | none | work, switch (W1) |
| 18 | `Block::with_room` | 441 | `_z_arc_slice` and `z_malloc` | no-heap: the payload pool's take inlined; F1 takes its count |
| 19 | `extended_from` | 425 | `_z_keyexpr_append_suffix` 287, `_append_substr` 87, `_append_str_array` 148 | same work |
| 20 | `PutCarried::fold` | 418 | the options read in `_z_publisher_put_impl` | same work, one body for both put doors |
| 21 | `handlers::push` | 409 | `_z_fifo_mt_push` 54, `_z_ring_mt_push` 54, `_z_fifo_push_drop` 74, `_z_ring_push_force_drop` 74 (language) | same work |
| 22 | `z_string_array_clone` | 398 | `z_string_array_clone` 9 jumps to `_z_svec_copy` 204 (language) | same work; form: two places for each entry (F3) |
| 23 | `process_pool::lay_stage` | 378 | none | no-heap |
| 24 | `store_canonized` | 345 | `_z_keyexpr_join` 150, `_z_keyexpr_concat` 107 | same work |
| 25 | `PicoEndpoint::write_text` | 344 | `_z_endpoint_config_from_string` 325 (driver) | same work |
| 26 | `key_compose` | 337 | `_z_declared_keyexpr_join` 115 and concat | same work |
| 27 | `store_slice` | 329 | the slice value doors | same work |
| 28 | `process_pool::give_back` | 322 | `z_free` | no-heap; F1 takes its count |
| 29 | `zid::enumerate_peers` | 322 | `z_info_peers_zid` 93, `z_info_routers_zid` 90 | form, over-generalisation (one walk for both, small) |
| 30 | `EntityKey::up_to` | 298 | `_z_keyexpr_declare_prefix` 469 | same work |
| 31 | `WriteFilter` drop | 279 | `_z_write_filter_clear` 241, `_z_write_filter_session_unregister` 311 | same work |
| 32 | `z_undeclare_matching_listener` | 260 | `z_undeclare_matching_listener` 37, `_z_matching_listener_undeclare` 153 | same work |
| 33 | `z_encoding_set_schema_from_substr` | 241 | the same door 141 | same work |
| 34 | `wire_key_of` | 235 | `_z_declared_keyexpr_alias_to_wire` (keyexpr) | same work |
| 35 | `z_bytes_slice_iterator_next` | 232 | the same door 99 | same work |
| 36 | the engine's `declare_subscriber_on_wire` | 231 | the sink's code inlined into the engine's body | same work |
| 37 | `serde::one_shot` | 227 | `ze_serialize_*` 150 to 200 each | wz smaller |
| 38 | `serde::write_into` | 224 | as above | wz smaller |
| 39 | `string_array_push` | 212 | `z_string_array_push_by_copy` 68, `_by_alias` 39 | same work |
| 40 | `serde::deserialize_record` | 210 | `ze_deserialize_*` | wz smaller |

Below the forty: `outbound_keyexpr` 200, `judge_canon` 93 and `proof_of_canon` 101 (W2);
`Pools::counted` 160 (F1); `position_named` 145 and `trimmed` 109 (W1); `take_slot` 146 (no-heap).

## 4. The shares and the steps

| share | bytes of the +21,681 | what |
|---|---:|---|
| same work counted in another area by zenoh-pico (form, overlapping layer) | ~17,900 | not a step of this area: the case total does not move with it |
| no-heap work | ~1,800 | pools, object places, the key arena; the owner's no-heap ruling holds them |
| work a switch takes (W1, W2) | ~1,500 | each a capability off in the zenoh-pico preset |
| form a step takes (F1 to F3) | ~450 | |

Of the same-work share, serialisation and the closures read 3.2 KB under zenoh-pico's; the rest is
work zenoh-pico counts in `language` (its collections and the `_z_rc_*` / `_z_fifo_mt_*` symbols
`handlers.rs` defines), `sessions` (open, write filter, sample copies) and `driver` (endpoints,
clocks). The area reaches 1.0 only if those moved, which is a rule of the ledger and not code.

The steps, largest first. Estimates are of the case's bytes, read off the bodies above.

| step | kind | what | estimate | needs |
|---|---|---|---:|---|
| W1 | work, switch `config-limits` | `ZEXT_CONFIG_LIMITS_KEY` read only with the capability: `state_over`, `position_named`, `trimmed`, `Stated::select`, `Held::select_at`, the judgement in `ConfigState::insert`, the read in `resolve_open`; without it the open's statement is the constant `Stated::OPENING` | -1,100 to -1,600 | a decision, below |
| W2 | work, switch | the outbound gate on a key a door sends or declares (`outbound_keyexpr`, the canon refusal in `session_write`) | -300 to -450 | a decision, below |
| F1 | form, unread bookkeeping | the pools' class counts kept only where the doors that report them are | -250 to -300 | none: built here |
| F2 | form, moved by value | a kept sample's marshal written once, over its parts in place, not unbound first | -80 to -150 | none |
| F3 | form, overlapping layer | a string array entry in one place, its view beside its bytes | -50 to -100 | none |

W1 decides what a session of a build without the key opens at. `config_limits.rs` and `zext.h` hold
that the zenoh-pico preset has the key, because a session that is not laid out by a region
(`OPENS_BY_REGION` false: `peer`, `multicast-transport` or `config-policy`) opens its tables at
`SessionLimits::PICO_PRESET` and the key is the only way to raise them to `PICO_PRESET_BOUND`. Off,
such a session either stays at the preset (a program holding more than zenoh-pico's examples
declare is refused; the perf probe states two subscribers, two publishers and four keys through the
key) or opens at the bound (every session's arena and the pools sized for it: the RSS the case
already loses). The minimal case is a region build, where the key only lowers quotas and states the
held counts, so the bytes are the same either way; the choice is for the preset's peer builds. The
change also names the capability in `crates/wz-capi-pico/Cargo.toml`, `crates/wz-capi-core/Cargo.toml`,
`crates/wz-fuzz/pico-ext/Cargo.toml`, the host profiles and the tokio legs of
`scripts/lib/nondefault-tests-gate.sh`, and regenerates the files `wz_config.py --emit` writes.

W2 is wire-visible both ways: zenoh-pico sends whatever text its key holds, and the pico-safe half
of the gate keeps a zenoh-pico peer's canonizer from aborting on a key in canon form. A switch would
take the canon refusal alone or both; that is the owner's to say.

## 5. Step F1, built

`crates/wz-capi-pico/src/process_pool.rs`: `ClassCount`, `count_of`, the `counts` field of
`Pools`, its write in `Pools::unlaid`, the out-of-line `Pools::counted` and the decrement in
`Pools::give_back` are compiled where `report` and `held` read them (`any(test, feature =
"object-pool")`, the predicate those two already carry). A library without the doors has a
`counted` that hands the take back as it was, inlined, so `take`, `take_payload` and
`give_back` write the pool's list and nothing else. What a take and a give-back answer is the same
in every build: `counted` never changed a slot, only where it was counted.

Expected: `Pools::counted` (160 B) leaves the case, and its call and the class arithmetic leave
`take_slot`, `Block::with_room`, `process_pool::give_back` and `lay_stage` (the zeroing of
twelve counts): about 250 to 300 B of `doors`. Each stage's `Pools` in the static
`RESERVED` is 288 B smaller (`.bss`). No receive path is touched: a delivered sample is lent and
takes no block; a take or a give-back runs fewer instructions, never more.

Verification for the main session: `cargo build -p wz-capi-pico-lib --no-default-features --features
abi/os-host,abi/link-udp --profile capi-nostd --config .cargo/capi-nostd.toml`; `cargo clippy -p
wz-capi-pico --no-default-features --features os-host,link-udp -- -D warnings` and the same with
`object-pool`; `cargo test -p wz-capi-pico --lib process_pool` (the reports' tests still read the
counts); the size ledger of the case (`doors` expected below 40,715 B, the total below 205,921 B)
and the perf matrix's arm W.
