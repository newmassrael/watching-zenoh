# One table set (L3): the cooperative engine's rows in the session core's

Lane `arch-l3-rows`: section 5, step 4 of `docs/c-abi-architecture.md` ("the cooperative engine's
registry, targets and key table fold into the session core's rows; the delivery lane is removed").
Read against `origin/main` at `6199fa0d40` and the size ledger's explain report of
`pico-client-coop-nostd` dated 2026-11-27 (pin `6a881c21dad1`). One entity kind at a time,
subscribers first.

## 1. What of step 4 has landed

| fact | where it lies now | what went |
|---|---|---|
| a subscriber | one row of `SessionTables::subscribers` (`wz-session-core/src/session_tables.rs`, `SubscriberRow<Key, Cb>`: id, key in the key arena, key facts, origin, callback) whose `Cb` is the engine's callback record (`wz-capi-coop/src/engine.rs`, `SubscriberRow`: anchor, sink, timestamp choice, latch) | the registry's own entry and its copy of the key; the door keeps the id and a loan of the row's key (`wz-capi-pico/src/pubsub.rs`, `DeclaredSubscriber`) |
| a callback's life (P11) | the row's latch (`RowCallback` for the engine's row; `SessionTables::release_drained_subscriber`) | the per-door wait |
| the delivery of a sample | the read pins the rows its key reaches under the session's lock (`SessionTables::pin_subscribers`) and calls each row's callback after it (`engine/pinned.rs`, `hand_row_by_row`) | `wz-capi-coop/src/lane.rs`; `wz-session-core/src/delivery_lane.rs` is read only by the tokio engine (`wz-runtime-tokio/src/session/offload.rs`) |
| a queryable, a liveliness subscriber, a token | rows of the same table set (`QueryableRow` in `engine/query.rs`, `LivelinessRow`, `HeldTokens for SessionTables`) | their registries' entries |

The round of deliveries (`wz-capi-coop/src/round.rs`, `RoundDelivery::round`) is the one queue
left between a read and a callback. It is built only under `wz_round` (`wz-capi-coop/build.rs`:
`threads` where the form has no lock per value: a target without 8- and 64-bit atomics, or the
`WZ_COOP_VALUE_LOCKS=off` test leg). No build of the pico preset on a host with 64-bit atomics
has it.

## 2. The subscriber plane in the measured case

`pico-client-coop-nostd` builds neither `query`, `queryable`, `liveliness`, `listen`, `group`
nor `threads`: its L3 tables are the subscribers, the key expressions, the write filters and the
matching listeners. Sessions area: wz 66,398, zenoh-pico 27,508. The subscriber's bodies:

| wz body | bytes | zenoh-pico, same job | bytes |
|---|---:|---|---:|
| `CoopEngine::undeclare_subscriber` | 1,666 | `_z_undeclare_subscriber`, `_z_unregister_subscription` | 656 |
| `Declaring::declare::<Subscriber>` | 1,514 | `_z_register_subscription` | 623 |
| `CoopEngine::declare_subscriber_on_wire` | 1,324 | `_z_declare_subscriber`, `_z_register_subscriber` | 835 |
| `SessionTables::undeclare_subscriber` | 779 | (with the undeclaration above) | |
| `hand_row_by_row` | 1,117 | `_z_trigger_subscriptions_impl` (with `_z_trigger_push`) | 1,730 |
| `SessionTables::pin_subscribers` | 438 | (with the trigger above) | |
| `SessionTables::declare_subscriber` | 209 | (with the registration above) | |

Owners of the area: `wz_capi_coop::engine` 15,577 in 70 bodies, `session_tables` 7,233 in 42,
`slot_map` 5,910 in 49, `engine::direct` 5,906 in 34, `key_arena` 3,201 in 25,
`engine::registry` 413 in 15. The delivery (the last two rows of the first table) is on the
receive, whose instructions a message are under zenoh-pico's; the declaration and the
undeclaration are not.

## 3. What is still held twice

| # | fact | first holder | second holder | in the measured case |
|---|---|---|---|---|
| H1 | the id a declaration is numbered by | `SessionTables`'s `next_entity`, minted by `Declaring::mint` after the room and the key | the engine's read of `next_entity_id()` ahead of the declaration, checked equal by a `debug_assert` (`declare_subscriber_on_wire`; the queryable's and the liveliness subscriber's declarations the same) | yes, the subscriber's |
| H2 | which row a subscriber is | the row's handle (`Declared::handle`, generation-checked, P10) | the entity id the port hands the door (`Declared<SubId>`), by which `undeclare_subscriber` walks the liveliness subscribers and then the subscribers, enumerated, comparing ids | yes |
| H3 | the key's text while its retraction is written | the row's `EntityKey` | a second count of the same block (`row.key().backing().clone()` in `undeclare_subscriber`), taken so the retraction can name the key after the tables let the row go | yes |
| H4 | what keeps a key's declaration alive | the tables' count of the declaration (`KeyexprCount`) | the ABI's anchor in every callback row (`KeyAnchor` in `SubscriberRow`, `QueryableRow`, `LivelinessRow`), which the pico ABI fills only on its advanced plane (`wz-capi-pico/src/advanced_forms.rs`) | the field and its drop, never filled |
| H5 | the callback protocol of a row | the subscriber's record | the queryable's and the liveliness subscriber's records, each `{anchor, sink, latch}` with the same `RowCallback` body | one instance |
| H6 | the session's L3 tables as a value | `SessionTables` and `PeerTables` in `wz-session-core` | `RegistryOf<H>` in `wz-capi-coop/src/engine/registry.rs`: the application's observer (`SlotObserverOf`, whose `tables` is the `SessionTables`), the faces' `FaceTables` (`peer`, `gets`, the due row), the holders' index and the written count; every operation reaches the tables through it (`tables(&core.session.registry)`) | one face (`OneHolder`), 413 bytes of its own |
| H7 | a pending get | `SessionTables::pending_gets` | each face's `FaceTables::gets` (`Requesters<ConsolidatingSink<LegSink, LegHold>>`) and the due index (`DueIndex`, `DueRow`) | no |
| H8 | a query kept past its callback | the queries' plane (`wz-session-core/src/query_plane.rs`, `QueryPlane`'s Final holds) | the engine's held queries (`engine/query.rs`, `keep_query`, `HeldQueryId`) | no |
| H9 | the session's own tokens | `SessionTables`'s tokens (`HeldTokens`) | `SlotObserverOf::local_tokens` (`LocalTokenRegistry`), empty where the tables keep tokens but still a field, and the tokens a lost face owes kept apart (`OwedTokens`) | no |
| H10 | a sample between a read and a callback | the read's frame | the round, under `wz_round` | no |

## 4. Target

Every row of section 3 has one holder, in L3: the session core's `SessionTables` and the faces'
peer tables, held by the engine under its one lock and reached by no wrapper of the engine's. A
row is named across every boundary by its handle (P10); the entity id is a field of the row, read
only where the wire names it. A declaration is numbered by the tables and refused in their one
order (room, key, id). An undeclaration names its retraction from the row it removes. A row keeps
an ABI's anchor only in a build whose ABI makes one. The engine (L0, step 6 of the architecture)
keeps the wait set, the timers and the read task, and calls L3.

## 5. Steps

Each lands on its own, is read on the case's sessions row and on the bodies its line names, and is
reverted when its row does not move by its expectation. None of D1 to D5 is on the receive or the
put; their receive instructions a message are expected unchanged (about 3,073 in the lane's
reading; `docs/win-budget/size.md` section 8 reads 3,078).

| step | holds once | files | expected, `pico-client-coop-nostd` | receive Ir | tests |
|---|---|---|---:|---|---|
| D1 (landed with this note) | H1, the subscriber's | `wz-capi-coop/src/engine.rs` (`declare_subscriber_on_wire`) | -15 to -40 (`declare_subscriber_on_wire` 1,324) | 0 | `entity_tables::a_subscriber_is_answered_the_id_its_row_was_numbered_by`, `entity_tables::a_full_subscribers_table_is_answered_before_an_id_is_asked_for`, and `a_subscriber_that_finds_no_id_left_is_refused_and_lets_its_sink_go` unchanged |
| D2 | H1, the queryable's and the liveliness subscriber's | the same file (`declare_queryable`, the liveliness subscriber's declaration) | 0 (neither is built); `pico-client-coop` -30 to -80 | 0 | the same two tests written for each kind |
| D3 | H3 | `wz-session-core/src/session_tables.rs` (`undeclare_entity`, `Undeclared`), the engine's `undeclare_subscriber` | -60 to -200 (the clone and the drop of the second count) | 0 | `a_subscriber_past_its_table_is_refused_and_sends_nothing`; a retraction named by the key of a removed row and of a row a call of which runs |
| D4 | H2 | with lane `arch-l4-facade`: the port's `Declared`, the door's `DeclaredSubscriber`; L3's `undeclare_subscriber(handle)` is there already | -150 to -300 (the walk of two tables by id), more where liveliness is built | 0 | an undeclaration by a handle of an earlier generation finds nothing; one of a liveliness subscriber reaches its own table |
| D5 | H4 | the port's `KeyAnchor` as a type of no size where no ABI keeps an anchor, with the S-SINK design of `docs/win-budget/size.md` (section 3.1), whose seam it shares | -100 to -200 text, 32 bytes a row of the region | 0 | the anchor test of `tests/liveliness.rs` kept on the build that keeps anchors; a size assertion of the row on one that does not |
| D6 | H5 | `wz-capi-coop/src/engine.rs`, `engine/query.rs`: one latched record over the sink type | 0 (one instance) | 0 | `closure_drops` |
| D7 | H6 | the registry becomes the session core's (`wz-session-core`: the table set and the faces' sets, a face named by its set's handle); with lane `arch-l0-driver`, step 6d | -300 to -800 (the per-face wrappers and the split of the sets), measured before it is claimed | to be read: the receive's one look at its face's set is kept, and no call is added | the registry's tests move with it; `direct_receive`, `in_place` |
| D8 | H7, H8 | the gets' legs as rows of the pending get; the held query as a row of the queries' plane | 0; `pico-client-coop` to be read | 0 | `get`, `local_query`, `queryable` |
| D9 | H9 | `slot_observer`: `local_tokens` by `Presence` where the tables keep tokens; the owed tokens as rows of the lost face's set | 0 | 0 | `liveliness` |
| D10 | H10 | a lock per value on a target without 64-bit atomics (the kernel's), so no `threads` form keeps the round | 0 on a host; the MCU images' to be read | to be read on the MCU matrix | `one_thread`, `round` until they go |

Order: D1 to D3 take no other lane's file; D4 waits for the façade lane's port change and D7 for
the driver lane's 6d; D5 goes with S-SINK; D8 to D10 are of builds the measured case does not
make, and are read on `pico-client-coop` and the MCU matrix.

## 6. Read and not designed here

- A face's class is read in a second look at its set on each record the read hands out
  (`RegistryOf::peer_class` after `lend_push`, `take_subscriber_record`, `plain_put_key`). In a
  build of the open key gate `ClassId` has no value (`key_gate_open.rs`), so the look folds to a
  constant and costs nothing; only a closed key set pays it. Not a step of the measured case.
- The shape of the declaration and the undeclaration (the parts moved by value, the refusal paths)
  is design S1 of `docs/win-budget/size.md`; the write filter's row is S-FILTER there.
