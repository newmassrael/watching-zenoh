# Structural lane base-sessions: the sessions area of the smallest case, body by body

Status: the reading and the design of the lane, with its first step (S-KEY) carried in beside it.
Nothing here was built or measured by this lane: every byte figure is either **read** from the size
ledger's explain document named below or an **estimate** from the code, to be read on that
document after the merge.

## 1. The reading

The explain document of `pico-client-coop-nostd` (`wz-capi-pico-lib`, `os-host,link-udp`,
profile `capi-nostd`) dated 2026-11-27 (schema 5, pin `6a881c21dad1`), read on `main` with the
put lane (`arch-put.md`) landed: the case is 205,921 against zenoh-pico's 170,500 (1.21), and the
sessions area is **61,712 against 27,508 (+34,204, 2.24)**. Bytes are each body's bytes in this area
(the area rule of `deploy/size_ledger.json`: every line of `wz_capi_coop` and `wz_session_core`,
and pico's `src/net`, `src/session` and their headers). Generic copies are 312 bytes in all
(`SlotMap::add_free_slot` four times, `OneThreadLock::lock` twice, `BoundedString`'s key writer);
lines inlined from other functions are 19,800 of the 61,712.

The case builds no `listen`, `group`, `threads`, `query`, `queryable`, `liveliness`,
`local-subscriber`, `connectivity` or `advanced`, and every policy holds its default alone
(`DEFAULTS_ONLY`), so the code of a wz behaviour that a capability or a policy domain carries is
already out of it: the paced replay (`ReplayPacing::REACHABLE` is false), the derived zid
(`zid-derivation` holds `random` alone), the send switches (`tx-probe`, `tx-expiry-run`,
`tx-fragment-credit`, `tx-held-wait`), the key-matching listener's engine side
(`key-matching-listener`), the shared sinks (`shared-sinks`). What is left is read below.

## 2. The bodies, job by job

Kinds: **shape** (the same job, written larger: *layers* held twice, a *generic copy*, an *inline
copy* of one body in many callers, an *over-generalization* the case never takes, a value *moved*
by value through layers), **work** (wz does something zenoh-pico does not; under the owner's ruling
of 2026-11-27 each such behaviour is a switch the zenoh-pico preset turns off), **area** (the job
is pico's too, but its rules count it in another area), **hot** (on the receive or the put, judged
on their instructions too: no step adds a call to them), **won**.

| job | wz bodies (bytes) | wz | zenoh-pico functions (bytes) | pico | wz - pico | kind |
|-----|-------------------|---:|------------------------------|-----:|----------:|------|
| open, arena, assembly, zid, endpoints | `assemble` 3,528, `lend_session` 3,351, `open_links` 902, `engine_of` 655, `session_zid` 517, `z_open` 485, `OpenEndpoints::write_into` 423, `Shared::last_placed` 380, `write_text` 307, `kept_text` 251, `kept_span` 220, `group_endpoint` 159, `state_over` 133, `rowless_over_zero` 130 | 11,963 | `_z_open_connect_locator` 1,138, `_z_open_locators` 427, `_z_session_init` 369, `_z_open` 353, `_z_open_locators_peer` 349, `_z_open_bind_listener` 338, `_z_config_client` 215, `_zp_start_transport_tasks` 202, `_z_open_locators_client` 180, `_z_info` 178 | 4,351 | +7,612 | shape (moved: the `Core` built in the frame and moved into `engine_of`; layers: each layer's tables placed by its own call), of which about 4,000 is the no-heap contract's lay-out (decided, kept) |
| close | `SessionDrive::close` 931, `Core::end_links` 95 | 1,034 | `_z_session_clear` 98, `_z_session_close` 62, the cancellation tokens 853, `z_session_drop` 50 | 1,320 | -286 | won |
| a subscriber's declaration and undeclaration | `CoopEngine::undeclare_subscriber` 1,563, `Declaring::declare::<Subscriber>` 1,497, `declare_subscriber_on_wire` 1,260, `Declaring::keyed` 1,032, `SessionTables::undeclare_subscriber` 779, `SessionTables::declare_subscriber` 209, `prefix_retraction` 77 | 6,417 | `_z_register_subscriber` 657, `_z_register_subscription` 623, `_z_undeclare_subscriber` 473, `_z_unregister_subscription` 183, `_z_declare_subscriber` 178, the list bodies and `_z_send_(un)declare` | 3,057 | +3,360 | shape (layers: engine, tables, `Declaring`, `keyed`; moved: the callback row through `Result<_, Refused<C>>`; the id walk and the key's second count, H2 and H3 of `arch-l3-rows`) |
| a key expression's declaration and its holds | `declare_keyexpr_where` 1,190, `SessionKeys::key` 614, `KeySpace::key` 437, `KeyRef::drop` 289, `acquire_keyexpr` 252, `retain_keyexpr` 183, `release_keyexpr` 171 and 115, `lent_key` 156, `keyexpr_row_at` 147, `keyexpr_row_by_id` 108 | 3,949 | `_z_register_resource_inner` 621, `_z_declare_resource` 273, `_z_unregister_resource` 220, `_z_undeclare_resource` 209, the lookups by id and key 171 | 1,858 | +2,091 | shape (inline copy: a key's last-holder release and its merge walk in each body that drops a key: S-KEY) |
| write filters and matching listeners | `declare_write_filter` 2,003, `undeclare_write_filter_quietly` 820, `read_matching` 632, `declare_filter_matching_listener` 587, `SessionTables::undeclare_matching_listener` 511, `CoopEngine::undeclare_matching_listener` 351, `write_filter_row_open` 304, `keep_write_filter_plain` 299, `undeclare_write_filter` 290, `local_declares` 182, `z_publisher_get_matching_status` 130 | 6,166 | `_z_write_filter_create` 895, `_z_write_filter_callback` 487, `_z_add_interest` 451, `__z_get_interest_by_key_and_flags` 344, `_z_write_filter_session_unregister` 311, `_z_register_interest` 282, `_z_declare_publisher` 266, `_z_remove_interest` 263, `_z_write_filter_clear` 241, the matching listener's bodies 600 | 4,852 | +1,314 | shape; work: the listener declared on a key with no entity, whose rows and branches stay in the session core's tables (`for_listener`, `owns_filter`) though the engine refuses it in this build (W1) |
| a peer's declarations and Interests, the replay | `RemoteSubscriberTable::dispatch_iteration_event_with_local` 1,032, `replay::told` 996, `take_control_of_event` 763, `apply_undeclared` 405, `declared_at` 208, the dispatch beside the samples 317, `Retract::tell` 135, `bind_within` 135, `announce_on` 99, `retract_at` 79 | 4,206 | `_z_client_reopen_task_fn` 798, `_z_interest_send_decl_subscriber` 770, `_z_interest_send_decl_resource` 756, `_z_interest_process_declares` 693, `_z_interest_process_undeclares` 540, `_z_interest_replay_declare` 324, the rest of `interest.c` and the declaration cache | 5,355 | -1,149 | won |
| the receive and the delivery | `DirectSink::event` 2,012, `deliver` closure 917, `hand_row_by_row` closure 828, `pin_subscribers` 438, `resolve_parts` 347, `encoding_hint::ref_from_bytes` 320, `PinnedFanOut::new` 319, `read_direct` 312, `own_append` 309, `lent_body` 267 | 6,843 | `_z_trigger_subscriptions_impl` 1,527, `_z_handle_network_message` 635, `_z_handle_request` 538, the sample bodies 1,424, `_z_get_keyexpr_from_wireexpr` 236, `_z_trigger_push` 203, the liveliness triggers 333 | 5,986 | +857 | hot |
| the put | `put_on_links` 2,830, `decide_alone` 481, `send_on_links` 387, `plain_put_params` 241, `live_to_publish` 141, `push_metadata` 126, `PutCarried::fold` 122, `publish_on_wire_all` 115, `write_push` 114 | 4,891 | `_z_write` 328, `_z_publisher_put_impl` 130, `_z_publisher_delete_impl` 60 | 535 | +4,356 | hot (`arch-put.md`) |
| a face's link life and dial, in the engine | `link_turn` 2,683, `drive_link` 1,006, `place_link_session` 736, `DirectSlot::dial_row` 517, `take_dial_answer` 266, `keep_refusal` 196, `next_peer` 171, `hold_dial` 141, `batch_door` 112, `has_router_peer` 98, `drop_link` 97 | 6,221 | `_z_session_has_router_peer` 90, `_zp_unicast_failed_result` 47 (the read and lease tasks are pico's transport area) | 180 | +6,041 | shape (layers: L0 holds L2's facts, `arch-l0-driver.md` section 2); over-generalization: the walk's refusal kept with its endpoint's text, which the pico ABI reads only as `Z_ERR_TRANSPORT_OPEN_FAILED` (`coop_open_refusal`) |
| transport jobs whose lines are the session core's | `UnicastLink::input` 1,173 and its other bodies 498, `fragment_in_place` 739, `read_control_in_place` 316, `UdpDriver::admit` 218, `record_established_at` 191, `service_due` 169, `due_ms` 161, the handshake's and the send's small bodies | 4,234 | (`src/transport`: pico's transport area) | 0 | +4,234 | area |
| key expression matching | `keyexpr_match::relate` 726, `keyexpr_walk` 489, `keyexpr_relation_dp` 232 | 1,447 | (`_z_keyexpr_intersects` and its kin: pico's keyexpr area) | 0 | +1,447 | area |
| extension admission | `ext_admit::judge_entry` 989, `push_read::read_chain` 404, `read_declare` 347, `read_push` 230, `read_folded` 201, `read_interest` 181, `read_oam` 181, `read_walk` 77 | 2,610 | (pico reads extensions in its codec: 911 there) | 0 | +2,610 | area, and shape (2,610 against 911); work to be read: the body rules (`BodyRule`) follow upstream zenoh's reader, and a rule zenoh-pico's reader does not have is a refusal the preset does not make (W3) |
| the slot map's own bodies and the rest | `RawSlots::take` 226, `Core::unpin` 156, `nth_live` 126, `NamedKey::under_or_whole` 169, `remove` 98, `take_free` 95, the rest under 80 | 1,731 | | 14 | +1,717 | shape (the generational slots of P10, against pico's lists) |
| **all** | | **61,712** | | **27,508** | **+34,204** | |

### 2.1 Sums

| kind | wz - pico |
|------|----------:|
| shape (open, subscriber, key, filter, face, slot map rows; less the work below) | about +21,300 to +21,800, of which about 4,000 is the no-heap contract's lay-out at the open |
| work (W1, W2 by bytes; W3 to be read) | about +350 to +800 |
| area (pico's job counted in its transport, keyexpr and codec areas) | +8,291 |
| hot (receive +857, put +4,356) | +5,213 |
| won (close, a peer's declarations and the replay) | -1,435 |

The area rows move nothing of the case's total: a rule of `deploy/size_ledger.json` that names
`keyexpr_match` for keyexpr, `link_life` and the session drive's read for transport and
`ext_admit` for codec would read sessions at about 53,400 (1.94) and the case unchanged. That is
the ledger's decision, not a step of this lane.

### 2.2 The 2026-11-25 reading of this area, read again

That reading measured 91,252 by symbol (a body inlined into an engine method was the engine's),
against today's 61,712 by line: its ratios are not comparable to these. Its items:

| item | then | now |
|------|------|-----|
| S1 a build-time region | designed | landed: an open by a region lays out no row (`arena.rs`, the preset's region a const of `wz-capi-pico`) |
| S2 one face for a dial-only build | designed | landed (`faces::OneFace`) |
| S3 one link state, one dial, one init | designed | partly: `arch-l0-driver.md` 6b-1 landed; 6b-2 to 6b-6 open (section 3, other lanes) |
| S4 the session's state one value of the region, no count inside | designed | landed in the region form (`StateRegion`, `RegistryRegion`, `LinkRooms` placed in the arena); what is left of the open is the `Core`'s moves (T-OPEN, section 3) |
| S5 the write filter and the listeners in zenoh-pico's form | designed | landed: one Interest a filter, in its row (`cb9ea0afa0`). The listeners' own table stays: without a heap a filter's row cannot hold its listeners without a bound per filter, which multiplies the rows; not a shape |
| S6 one sample representation | designed | not in this area's bodies: the sample views are the doors' and the receive's |
| S7 an unpaced replay in one lap | designed | landed (`ReplayPacing::REACHABLE`) |
| S8 a key held once | designed | partly: H3 and H4 of `arch-l3-rows` remain (B3, B4 below) |
| C2 callbacks outside the lock | | landed in the single-thread form (`pin_subscribers`, `PinnedFanOut`) |
| C3 the session's lock in a one-thread build | | landed (`OneThreadLock`, 344 bytes in this area) |
| C8 a row's latch | | kept (P11) |
| C9 generation-checked handles | | an owner's decision (W4): leaving them out leaves a stale handle undefined, as in zenoh-pico |

## 3. Steps, by expected bytes

"Receive" is the receive's instructions a sample (about 3,066, perf matrix arm W); no step adds a
call to the receive, the delivery or the put. Each step is read on the case's total and sessions
row and reverted when they do not move by its expectation.

### 3.1 Shape, this lane

| step | change | expected (estimate) | receive | basis |
|------|--------|--------------------:|---------|-------|
| **B1 S-KEY (carried here)** | a key's last-holder release (`used` and the merge walk of `give_back`) is one cold body, `KeyStore::release`; `KeyRef`'s drop keeps only the count's exchange in line. Cherry-picked from branch `sz-sessions2` (`2e3073bc1f`, Change-Id `Icc89ee80e84a`), which was not on `main` | -300 to -800 | expected 0: a drop whose block keeps a holder takes no call, and a sample's receive is not expected to drop a block's last holder | `key_arena`'s lines in 25 bodies, 3,142 bytes, against its own bodies of about 840 |
| B2 W1's residue | the session core's tables keep the key listener (`WriteFilterRow::for_listener`, `MatchingRow::owns_filter`, `declare_matching_listener_on`, the owned filter's undeclaration and its rank in the engine) only under a session-core feature that `wz-capi-coop/key-matching-listener` names | -150 to -300 | 0 | `undeclare_matching_listener` 511 and 351, `plane_has_room`, `PlaneBounds::of_filter` |
| B3 D3 (H3) | the subscriber's undeclaration names its retraction from the key the removed row hands back, not from a second count of its block | -60 to -200 | 0 | `undeclare_subscriber`'s 188 `key_arena` bytes |
| B4 D5 (H4) | `KeyAnchor` of no size where no ABI keeps an anchor (the pico ABI fills one only on its advanced plane) | -100 to -200, and 32 bytes a row | 0 | the anchor's field and drop in each callback row |
| B5 E5 | the close's and the drop's shared part one body | -50 to -150 | 0 | `close` 931, the engine's drop |

Before a design: the open (T-OPEN). `assemble`'s 3,528 bytes are 3,055 of `engine.rs`'s lines,
`lend_session`'s 3,351 are 1,204 of `arena.rs`'s and 1,143 of `engine.rs`'s: which lines (the
`Core`'s moves, the drops of a partly moved `SessionLent` on each refusal after `lend_session`,
the inlined makers) is read with `objdump -d -l --inlines` on the case before a step is written.
`docs/win-budget/rss.md` A2 found writing the values field by field where they live cost text,
so no step is claimed here before that read.

### 3.2 Shape, other lanes' designs on this area's bytes

| step | design | expected | note |
|------|--------|---------:|------|
| 6b-6 | `arch-l0-driver.md`: the face's life in the transport value | -1,000 to -2,000 | the largest on this area's bytes; the look at an up link must not rise |
| 6b-4 | `arch-l0-driver.md`: the walk's refusal is L2's, `OpenError` built once | -200 to -500 | carries W2 |
| D7 | `arch-l3-rows` (branch): the registry into the session core, with 6d | -300 to -800 | |
| D4 | `arch-l3-rows` (branch): an undeclaration by the row's handle, with the façade lane | -150 to -300 | |
| D1 | `arch-l3-rows` (branch `90e0deffd6`): the subscriber's id read once | -15 to -40 | not on `main` |

### 3.3 Work, the switches

| id | behaviour wz has and zenoh-pico does not | bytes | the switch |
|----|------------------------------------------|------:|------------|
| W1 | a matching listener declared on a key with no publisher or querier | 150 to 300 (B2) | the engine's side is `wz-capi-coop/key-matching-listener` already, off in the pico ABI; B2 carries it into the session core. No pico-ABI door declares one, so no `[[capability]]` is asked until an ABI of the preset family does |
| W2 | the walk's refusal kept with its endpoint's text | 200 to 500 | not a behaviour the pico ABI shows (`coop_open_refusal` answers the code alone): an over-generalization, gone with 6b-4 |
| W3 | extension body rules that zenoh-pico's reader lacks | at most `judge_entry`'s 989, to be read | read each `BodyRule` against `vendor/zenoh-pico/src/protocol/codec`; a rule pico's reader does not refuse becomes a `[[capability]]` with `upstream_off = ["zenoh-pico"]` |
| W4 | a stale handle refused, not undefined | 1,600 to 2,100 over sessions and doors (2026-11-25 estimate) | an owner's decision: not proposed as a switch without one |

## 4. B1 as carried

`crates/wz-session-core/src/key_arena.rs`: `KeyStore::release(&self, at)` (`#[cold]`,
`#[inline(never)]`) gives a block whose last holder went back to the free list and takes its
bytes off `used`; `impl Drop for KeyRef` is `#[inline]` and calls it only when the count it
lowered was the last. The test `only_the_last_holder_of_a_block_gives_it_back` holds a block kept
by a dropped and a let-go holder, freed by the last, and the bump area given back whole.

What the main session reads to land it: the case's total and the sessions row against section 1;
`KeyRef::drop` and the `key_arena` lines of `declare_write_filter`, `SessionKeys::key`,
`declare_keyexpr_where`, `Declaring::keyed`, `undeclare_subscriber` and `put_on_links` in the
explain document; the receive at arm W, which should not move.
