# One table set (L3): the cooperative engine's rows in the session core's

Lane `arch-l3-rows`: section 5, step 4 of `docs/c-abi-architecture.md` ("the cooperative engine's
registry, targets and key table fold into the session core's rows; the delivery lane is removed").
Read against `origin/main` at `df994d7913` and the size ledger's explain reports
(`crates/target/size-ledger/explain-<case>.json`, schema 5, zenoh-pico pin `6a881c21dad1`) of
`pico-client-coop-nostd`, `pico-peer-coop` and `pico-api-coop-nostd`, built on the integration
branch of 2026-11-27 (`cbc0f6ecb3`). One entity kind at a time, subscribers first.

## 1. What of step 4 has landed

| fact | where it lies now | what went |
|---|---|---|
| a subscriber | one row of `SessionTables::subscribers` (`wz-session-core/src/session_tables.rs`, `SubscriberRow<Key, Cb>`: id, key in the key arena, key facts, origin, callback) whose `Cb` is the engine's callback record (`wz-capi-coop/src/engine.rs`, `SubscriberRow`: anchor, sink, timestamp choice, latch) | the registry's own entry and its copy of the key; the door keeps the id and a loan of the row's key (`wz-capi-pico/src/pubsub.rs`, `DeclaredSubscriber`) |
| the id a subscriber is numbered by (H1, step D1) | minted by the tables after the room and the key (`Declaring::mint`); the declaration answers the row's id | the engine's read of `next_entity_id()` ahead of the declaration and its `debug_assert` |
| the id a queryable and a liveliness subscriber are numbered by (H1, step D2) | as the subscriber's: `declare_queryable_on_wire` and `declare_liveliness_subscriber_on_wire` answer `declared.id` | the engine's read of `next_entity_id()` ahead of each declaration and its `debug_assert`; no entity of the engine reads an id ahead of its row now |
| the key a subscriber's retraction names (H3, step D3) | read off the row the undeclaration removes, while the declarations the row held still stand, with the row's own key moved out with it (`Undeclared::retraction`, `Retracting`); a row a call keeps in its slot is held once more for the length of the retraction | the engine's `retraction_of` ahead of the undeclaration and its second count of the key (`row.key().backing().clone()`) on every undeclaration |
| the key a queryable's and a token's retraction names (H3, steps D3q, D3t) | one undeclaration for every kind whose retraction is read off its row (`undeclare_retracted` over the private `RetractedEntity`, which the subscriber's, the queryable's and the token's rows implement); `undeclare_queryable` and `undeclare_token` answer `RetractedUndeclared`, the token's with no callback (`()`) | the engine's `retraction_of` and second count of the key ahead of the queryable's undeclaration; the engine's read of the token's names ahead of its undeclaration and the whole `TokenRow` it took back; `EntityKey::backing`, whose one use was that second count |
| a callback's life (P11) | the row's latch (`RowCallback` for the engine's row; `SessionTables::release_drained_subscriber`) | the per-door wait |
| the delivery of a sample | the read pins the rows its key reaches under the session's lock (`SessionTables::pin_subscribers`) and calls each row's callback after it (`engine/pinned.rs`, `hand_row_by_row`) | `wz-capi-coop/src/lane.rs`; `wz-session-core/src/delivery_lane.rs` is read only by the tokio engine (`wz-runtime-tokio/src/session/offload.rs`) |
| a queryable, a liveliness subscriber, a token | rows of the same table set (`QueryableRow` in `engine/query.rs`, `LivelinessRow`, `HeldTokens for SessionTables`) | their registries' entries |

The round of deliveries (`wz-capi-coop/src/round.rs`, `RoundDelivery::round`) is the one queue
left between a read and a callback. It is built only under `wz_round` (`wz-capi-coop/build.rs`:
`threads` where the form has no lock per value: a target without 8- and 64-bit atomics, or the
`WZ_COOP_VALUE_LOCKS=off` test leg). No build of the pico preset on a host with 64-bit atomics
has it.

## 2. Where each fact lies, by layer

Every wz body of the reports' symbol lists (each list sums to its area, so the lists are whole) is
summed over the areas it spans and placed in the layer of the crate whose function it is: the
session core (`wz-session-core`: L3, with L2 beside it), the cooperative engine (`wz-capi-coop`),
the port (`wz-capi-port`) and the doors (`wz-capi-pico` and the `z_*` / `zp_*` exports). A
body counts what it inlined, so this reads what each layer's own functions cost, not whose source
lines they hold. It is placed in the fact its function's path names (the declaration or retraction
of an entity, a key's hold, a face's set, a pending get's leg, a turn of the replay, the face
choice of a put); a held operation of the engine is placed by the operation it runs. The port
holds no body of its own in this reading: its operations are the engine's
(`<CoopEngine as SessionEngine>::...`); by the line tables its source holds 1,783, 1,867 and
13,996 bytes in the three cases.

Bytes as L3 / engine / port / doors, and in brackets the number of those layers that hold the fact:

| fact | client nostd | peer | api nostd |
|---|---:|---:|---:|
| entity tables (declarations, retractions, rows, delivery to their callbacks) | 6,968 / 8,653 / 0 / 5,922 (3) | 6,664 / 10,055 / 0 / 6,225 (3) | 20,573 / 31,262 / 1,239 / 21,815 (4) |
| counters (entity, key and request ids) | 37 / 0 / 0 / 0 (1) | 40 / 0 / 0 / 0 (1) | 40 / 0 / 0 / 0 (1) |
| keys (the key arena, the key expression declarations and their holds) | 2,734 / 1,598 / 0 / 7,475 (3) | 2,744 / 1,894 / 0 / 7,475 (3) | 2,744 / 3,560 / 0 / 7,586 (3) |
| shared key ids | not built | not built | not built |
| query plane (a peer's query to the queryables, the replies, a query kept) | not built | 0 / 0 / 0 / 0 | 11,202 / 12,441 / 0 / 15,970 (3) |
| pending gets (the get, its legs, its due time) | not built | 0 / 618 / 0 / 0 (1) | 7,016 / 19,412 / 0 / 14,847 (3) |
| round and deliveries | 0 / 994 / 0 / 0 (1) | 0 / 994 / 0 / 0 (1) | 0 / 5,952 / 0 / 0 (1) |
| declaration watches | not built | not built | not built |
| face reports (what a connectivity listener is told of the faces) | 0 / 193 / 0 / 480 (2) | 0 / 773 / 0 / 480 (2) | 0 / 5,257 / 0 / 22,531 (2) |
| replay (what a face that comes up is told again) | 0 / 2,624 / 0 / 0 (1) | 0 / 4,613 / 0 / 0 (1) | 0 / 7,104 / 0 / 0 (1) |
| which faces a publish goes to | 283 / 5,165 / 0 / 4,481 (3) | 283 / 8,061 / 0 / 4,710 (3) | 42 / 16,114 / 0 / 4,734 (3) |
| what each peer declared (the faces' sets) | 2,759 / 130 / 0 / 0 (2) | 5,301 / 1,195 / 0 / 0 (2) | 13,015 / 2,793 / 0 / 0 (2) |
| the registry around the tables (H6) | 336 / 765 / 0 / 0 (2) | 336 / 7,602 / 0 / 0 (2) | 4,760 / 13,782 / 0 / 0 (2) |
| everything else of the four layers (L0, L2, the open, the doors' objects) | 59,537 / 28,141 / 150 / 24,735 | 82,789 / 66,055 / 150 / 34,318 | 147,860 / 135,032 / 5,103 / 53,596 |

What the rows say:

- The replay, the round and the face choice are held once, in the engine: step 6 of the
  architecture moves them to L3 (6c, 6d); moving them removes nothing by itself.
- The doors' bytes of a fact are their own work on it (a key's canonization and its holds, a
  declaration's options and place, a sample's marshal), which section 3.2 of
  `docs/win-budget/size.md` designs; they are a second holder only where a door keeps a copy of
  what L3 keeps, which the subscriber's door does not.
- The facts held in three or four layers are the entity tables (every case), the keys (every
  case), the pending gets and the query plane (api). The registry is the one L3 fact whose second
  layer is nothing but a second holder.

## 3. What one feature costs, and what holding it once leaves

### 3.1 The steps between the cases

The four-layer sums of the explain reports (every area):

| case | wz | zenoh-pico | wz over zenoh-pico |
|---|---:|---:|---:|
| `pico-client-coop-nostd` | 198,987 | 170,500 | 28,487 |
| `pico-peer-coop` | 323,098 | 179,142 | 143,956 |
| `pico-api-coop-nostd` | 850,626 | 280,287 | 570,339 |

From the client case to the peer case wz grows by 124,111 bytes and zenoh-pico by 8,642. Of the
124,111, the rows of section 2's L3 facts are 18,466: the registry around the tables 6,837, what
each peer declared 3,607, the face choice of a publish 3,125, the replay 1,989, the entity tables
1,401, the gets 618, the face reports 580. The rest of the four layers is 70,749, and the runtime,
the codec and the language support 34,896: the read of several faces (`face_turn` +4,842,
`read_direct` +3,808, `wait_on_faces` +1,947, `open_links` +2,108), the scouting window
(`window_hellos` +14,427, `z_scout` +3,148, `z_hello_clone` +1,752), the accept side of the
handshake (`decode_accept_cookie` +2,286, `send_init_ack` +1,880), the receive of fragments and
control in place (`fragment_in_place` +3,967, `read_control_in_place` +2,812), the runtime's
multicast plan (+3,662). The peer step is L0 and L2, the driver lane's and the transport's; L3's
share of it is about a seventh. `peer-proportion.md` reads the same step owner by owner, and
parts its scouting from the `peer` step proper.

From the client case to the api case wz grows by 651,639 and zenoh-pico by 109,787. The L3 facts'
rows grow by 214,194 (entity tables 53,346, pending gets 41,275, query plane 39,613, face reports
27,115, the registry 17,441, what each peer declared 12,919, the face choice 10,961), the rest of
the four layers by 229,028.

### 3.2 Per feature

A feature's bodies, read in the sessions and doors areas of both libraries (the codec's are
apart), by layer, against zenoh-pico's bodies of the same job. "At most" is what holding the
feature in one layer can remove at the very most, every layer but its largest; "expected" is what
the rows of section 4 the feature has remove, each by its step's own expectation.

| case | feature | L3 | engine | doors | wz | zenoh-pico | at most | expected |
|---|---|---:|---:|---:|---:|---:|---:|---|
| client | subscriber | 3,329 | 4,056 | 2,787 | 10,172 | 5,978 | 6,116 | 300 to 700 (H2, H3, H4) |
| client | publish | 241 | 4,167 | 4,325 | 8,733 | 4,873 | 4,408 | none: the face choice is held once |
| peer | subscriber | 3,356 | 4,819 | 2,787 | 10,962 | 5,978 | 6,143 | 300 to 700, and a share of H6 |
| peer | publish | 241 | 6,538 | 4,555 | 11,334 | 4,873 | 4,796 | none |
| api | subscriber | 3,362 | 9,463 | 14,160 | 26,985 | 23,116 | 12,825 | 200 to 500 (H2, H3; the advanced plane keeps anchors) |
| api | queryable | 5,709 | 9,285 | 9,859 | 24,853 | 9,575 | 14,994 | H1, H2, H3, H5 of the kind, and H8 |
| api | liveliness | 8,792 | 9,687 | 5,581 | 24,701, the port's 641 among them | 10,824 | 15,014 | H9 |
| api | get | 5,035 | 11,660 | 11,424 | 28,119 | 7,429 | 16,459 | H7: the faces' legs and the due index beside the pending gets |
| api | publish | 0 | 12,935 | 2,835 | 15,770 | 12,587 | 2,835 | none |

What it shows:

- For the subscriber in the measured case the duplicated holders are a few hundred bytes of a
  4,194-byte excess. The rest is the size of bodies each layer runs once: L3's declaration
  (`Declaring::declare` 1,678 against `_z_register_subscription` 623), the door's declaration
  (`declare_subscriber_with` 1,409 and `z_declare_subscriber` 83 against `z_declare_subscriber`
  222), the engine's announcement and retraction (`declare_subscriber_on_wire` 1,522 and
  `undeclare_subscriber` 1,721 against `_z_declare_subscriber` and `_z_register_subscriber`
  849, `_z_undeclare_subscriber` and `_z_unregister_subscription` 666). The delivery is at par
  (`hand_row_by_row` 989, `pin_subscribers` 590 and `PinnedFanOut::new` 377, 1,956, against
  `_z_trigger_subscriptions_impl` and `_z_trigger_push` 2,046). Holding the subscriber once is
  right, and leaves most of its excess where S1 and section 3.2 of `docs/win-budget/size.md` find it.
- The features of three and four layers whose second holders are large are the api case's gets,
  query plane and liveliness, and the registry (H6) in the peer and api cases (7,938 and 18,542).
  Those are where folding into one layer is expected to remove kilobytes; each is measured before
  it is claimed.
- A feature added at the peer step costs wz mostly in L0 and L2 (section 3.1), which the thin
  driver (step 6) and the transport's lanes own, not L3.

## 4. What is still held twice

| # | fact | first holder | second holder | in the measured case | status |
|---|---|---|---|---|---|
| H1 | the id a declaration is numbered by | `SessionTables`'s `next_entity`, minted by `Declaring::mint` after the room and the key | none | no | gone (D1, D2) |
| H2 | which row a subscriber is | the row's handle (`Declared::handle`, generation-checked, P10) | the entity id the port hands the door (`Declared<SubId>`), by which `undeclare_subscriber` walks the liveliness subscribers and then the subscribers, enumerated, comparing ids | yes | D4 |
| H3 | the key's text while a retraction is written | the row's `EntityKey` | none | no | gone (D3, D3q, D3t) |
| H4 | what keeps a key's declaration alive | the tables' count of the declaration (`KeyexprCount`) | the ABI's anchor in every callback row (`KeyAnchor` in `SubscriberRow`, `QueryableRow`, `LivelinessRow`), which the pico ABI fills only on its advanced plane (`wz-capi-pico/src/advanced_forms.rs`) | the field and its drop, never filled | D5 |
| H5 | the callback protocol of a row | the subscriber's record | the queryable's and the liveliness subscriber's records, each `{anchor, sink, latch}` with the same `RowCallback` body | one instance | D6 |
| H6 | the session's L3 tables as a value | `SessionTables` and `PeerTables` in `wz-session-core` | `RegistryOf<H>` in `wz-capi-coop/src/engine/registry.rs`: the application's observer (`SlotObserverOf`, whose `tables` is the `SessionTables`), the faces' `FaceTables` (`peer`, `gets`, the due row), the holders' index and the written count; every operation reaches the tables through it | 1,101 bytes; 7,938 in the peer case, 18,542 in the api case | D7 |
| H7 | a pending get | `SessionTables::pending_gets` | each face's `FaceTables::gets` (`Requesters<ConsolidatingSink<LegSink, LegHold>>`) and the due index (`Dues`) | no | D8 |
| H8 | a query kept past its callback | the queries' plane (`wz-session-core/src/query_plane.rs`, `QueryPlane`'s Final holds) | the engine's held queries (`engine/query.rs`, `keep_query`, `HeldQueryId`) | no | D8 |
| H9 | the session's own tokens | `SessionTables`'s tokens (`HeldTokens`) | `SlotObserverOf::local_tokens` (`LocalTokenRegistry`), empty where the tables keep tokens but still a field, and the tokens a lost face owes kept apart (`OwedTokens`) | no | D9 |
| H10 | a sample between a read and a callback | the read's frame | the round, under `wz_round` | no | D10 |

## 5. Target

Every row of section 4 has one holder, in L3: the session core's `SessionTables` and the faces'
peer tables, held by the engine under its one lock and reached by no wrapper of the engine's. A
row is named across every boundary by its handle (P10); the entity id is a field of the row, read
only where the wire names it. A declaration is numbered by the tables and refused in their one
order (room, key, id). An undeclaration names its retraction from the row it removes. A row keeps
an ABI's anchor only in a build whose ABI makes one. The engine (L0, step 6 of the architecture)
keeps the wait set, the timers and the read task, and calls L3.

## 6. Steps

Each lands on its own, is read on the case's sessions row and on the bodies its line names, and is
reverted when its row does not move by its expectation.

| step | holds once | status | files | expected, `pico-client-coop-nostd` | receive Ir | tests |
|---|---|---|---|---:|---|---|
| D1 | H1, the subscriber's | landed | `wz-capi-coop/src/engine.rs` (`declare_subscriber_on_wire`) | -15 to -40 (`declare_subscriber_on_wire` 1,522) | 0 | `entity_tables::a_subscriber_is_answered_the_id_its_row_was_numbered_by`, `entity_tables::a_full_subscribers_table_is_answered_before_an_id_is_asked_for` |
| D3 | H3, the subscriber's | landed | `wz-session-core/src/session_tables.rs` (`undeclare_entity`, `Undeclared`, `Retracting`), the engine's `undeclare_subscriber` | -20 to -150 (the engine's clone of the key and the drop of its count; the clone a kept row takes is the rare branch), read on `undeclare_subscriber` 1,721 and `SessionTables::undeclare_subscriber` 824 together | 0 | `session_tables::tests::a_subscribers_undeclaration_names_its_retraction_off_the_row_it_removes`, `a_subscriber_undeclared_while_its_callback_runs_names_its_retraction_past_the_row`; the retraction tests of `tests/held_keys.rs` and `tests/replay.rs` unchanged |
| D2 | H1, the queryable's and the liveliness subscriber's | landed | `declare_queryable_on_wire`, `declare_liveliness_subscriber_on_wire` | 0 (neither is built); -15 to -40 a kind where it is (`pico-client-coop`, the api case: the read of `next_entity` and its refusal branch) | 0 | `entity_tables::a_queryable_is_answered_the_id_its_row_was_numbered_by`, `a_full_queryables_table_is_answered_before_an_id_is_asked_for` and the two of the liveliness subscriber, one shared body each with the subscriber's (`CalledKind`) |
| D3q | H3, the queryable's | landed | `undeclare_retracted`, `RetractedEntity` (`wz-session-core/src/session_tables.rs`); the engine's `undeclare_queryable` | 0 (not built); the api case -20 to -150, as D3 read it for the subscriber | 0 | `session_tables::tests::a_queryables_undeclaration_names_its_retraction_off_the_row_it_removes`, `a_queryable_undeclared_while_its_callback_runs_names_its_retraction_past_the_row` |
| D3t | H3, the token's | landed | `RetractedEntity for TokenRow`, `undeclare_token`; the engine's `undeclare_liveliness_token` | 0 (not built); the api case 0 to -60 (the names are read once, in the tables; the row is no longer handed back whole) | 0 | `session_tables::tests::a_tokens_undeclaration_names_its_retraction_off_the_row_it_removes`; `tests/liveliness.rs` unchanged |
| D4 | H2, every kind at once | with step 5 (`arch-l4-facade` F7) | the port's `Declared` answers the row (`EntityRow`, the handle's bits on this engine, the id on an engine that has no rows); `undeclare_subscriber`, `undeclare_queryable` and the liveliness kinds take it; the doors keep it; L3's undeclarations by handle are there already | -150 to -300 (the walk of two tables by id), more where liveliness is built | 0 | an undeclaration by a row of an earlier generation finds nothing; one of a liveliness subscriber reaches its own table |
| D5 | H4 | with S-SINK (`docs/win-budget/size.md` section 3.1) | the port's `KeyAnchor` as a type of no size where no ABI keeps an anchor | -100 to -200 text, 32 bytes a row of the region | 0 | the anchor test of `tests/liveliness.rs` kept on the build that keeps anchors; a size assertion of the row on one that does not |
| D6 | H5 | the queryable stage | `wz-capi-coop/src/engine.rs`, `engine/query.rs`: one latched record over the sink type | 0 (one instance) | 0 | `closure_drops` |
| D7 | H6 | with the driver lane, step 6d | the registry becomes the session core's (`wz-session-core`: the table set and the faces' sets, a face named by its set's handle) | -300 to -800; `pico-peer-coop` and the api case to be read (7,938 and 18,542 held now) | to be read: the receive's one look at its face's set is kept, and no call is added | the registry's tests move with it; `direct_receive`, `in_place` |
| D8 | H7, H8 | the gets' and queries' stage | the gets' legs as rows of the pending get; the held query as a row of the queries' plane | 0; the api case to be read | 0 | `get`, `local_query`, `queryable` |
| D9 | H9 | the tokens' stage; read in 6.1: the answering's bound moves out of the registry first | `local_token.rs`: the answering apart from the holder; `slot_observer`: `local_tokens` by `Presence` where the tables keep tokens; the owed tokens as rows of the lost face's set, with D7 | 0 | 0 | `liveliness` |
| D10 | H10 | the MCU matrix | a lock per value on a target without 64-bit atomics (the kernel's), so no `threads` form keeps the round | 0 on a host; the MCU images' to be read | to be read on the MCU matrix | `one_thread`, `round` until they go |

With D1 and D3 the subscriber holds in L3 what L3 can hold without another lane's file: its id,
its row, its key, its retraction, its callback's life and its delivery. What is left of it is H2,
the port's identity of an entity; H4, the ABI's anchor; and H6, the registry around the tables.
With D2, D3q and D3t the queryable, the liveliness subscriber and the token hold their ids and
their retractions the same way: no kind's id is read ahead of its row, and every kind whose
retraction names its key reads it off the row it removes, by one undeclaration
(`undeclare_retracted`), so a kind added later implements `RetractedEntity` and costs nothing
more. The liveliness subscriber's retraction is its Interest's Final, which names no key.

### 6.1 D9, read

The premise of D9 as its row states it (`local_tokens` by `Presence`) holds for one of the two
facts the field holds, not for the other. `LocalTokenRegistry`
(`wz-session-core/src/declare/local_token.rs`) holds the session's own tokens, which is H9's
second holder: the cooperative engine lends it no row (`ObserverRows { local_tokens: 0 }` in
`wz-capi-coop/src/engine.rs` and `engine/registry/counted.rs`), as its tables keep the tokens.
It also holds the bound of the staging of a peer's liveliness Interest's answers, of which it is
the one writer (`reply_quota`, `MAX_PENDING_DECLARES`, `limit_interest_replies_to`,
`has_room`), and the answering itself (`stage_answer`, `answer_interest`,
`answer_interest_view`, `answer_messages`, `answer_iteration_event`), which every build that
answers a peer reads whoever holds the tokens (`slot_observer.rs`: `answer_iteration_event(held,
..)` with `held` the tables' tokens). A field made absent by `Presence` takes the staging's
bound with it. So D9 is two moves:

1. The answering and its bound become a value of their own beside the observer's planes, handed
   `&dyn HeldTokens` as they are now; the registry keeps the tokens, their bound and their keys.
2. The registry becomes `<_ as Presence>::Table<LocalTokenRegistry<P>>`, its presence chosen by
   the sinks (`ObserverSinks`) and absent where `K::Tables` keep tokens; the drain's
   `held_tokens().unwrap_or(&self.local_tokens)` reads the one holder there is.

Move 2 reaches the observer's in-place init (the `ptr::write` of the field), its region rows
and lines (`ObserverRegionRows::local_tokens`, `SLOT_OBSERVER_LINES`), its lent and counted
forms, and the heap profile's view of the application half (`observer.rs`, `&mut
LocalTokenRegistry`), which the tokio engine and the lwip drive register through. It is designed
against those files before it is written. Expected: 0 in the measured case (no liveliness); in
the api case the registry's state (a lent sequence's header and its key arena's handle), its
lend of no row, and the `HeldTokens` of `LocalTokenRegistry<Lent>` (`each_token`,
`keyexpr_for`, its vtable) that the `unwrap_or` names, read on those bodies before it is
claimed. The tokens a lost face owes (`OwedTokens`) are read with D7, whose faces' sets they
would be rows of.

D4 is the façade lane's because the port's identity of an entity is one contract for every kind
and every engine: the cooperative engine, the tokio engine's port (`wz-capi-core/src/engine_port.rs`),
the router node's (`wz-capi-core/src/drive/router_node/engine.rs`) and the advanced subscriber's
test host each answer `Declared`, and each door keeps what it answers. Changed for the
subscriber alone it would be changed again for the queryable, the token and the liveliness
subscriber, each time in every engine; changed once with step 5, which takes the port out of the
release build (`arch-l4-facade` F7: the façade names L3's handles), the door keeps the L3 handle
itself.

## 7. The receive

None of D1 to D6, D3q and D3t is on the receive or the put; their receive instructions a message
are expected unchanged (about 3,073 in the lane's reading; `docs/win-budget/size.md` section 8
reads 3,078). D2 changes two declarations, D3q and D3t two undeclarations, none of which a read
calls; the queryable's receive bodies (`next_queryable_reached`, `QueryableCall`) take none of
their code.
D3 changes the undeclaration only: `undeclare_entity`, `Undeclared` and the engine's
`undeclare_subscriber`. `wire_of` and `retraction_of` became calls of one free function each,
which the receive reaches through neither: the receive's subscriber bodies (`hand_lent_push`,
`hand_plain_puts`, `hand_copied_records`, `hand_row_by_row`, `pin_subscribers`,
`PinnedFanOut::new`, `SubscriberRow::hand`, `SubscriberSink::call_ref`) take none of the code
D3 moved.

The receive already calls the program's callback from the row: the rows a key reaches are pinned
in one hold of the session (`pin_subscribers` into the frame's `PinnedSubscribers`), the lock is
let go of, and each call reads its sink where the row lies. No lane lies between the row and the
callback in a host build, so this lane has no copy to take off the receive. What lies there still
is per row reached: the latch's begin and end (P11) and the call's place in the frame's array,
against zenoh-pico's list of the subscriptions a key reaches (`_z_subscription_get_infos`), which
it takes under its lock as well. A walk that called each row as it found it would take the lock
once a row (`pin_next_subscriber`), which is more instructions with two subscribers or more, so
the array stays. The receive-side items of section 4 are H6 (the second look at the face's set
for its class, after `lend_push`, a constant where the key gate is open; section 8) and H10, each
read on the receive before it is claimed.

## 8. Read and not designed here

- A face's class is read in a second look at its set on each record the read hands out
  (`RegistryOf::peer_class` after `lend_push`, `take_subscriber_record`, `plain_put_key`). In a
  build of the open key gate `ClassId` has no value (`key_gate_open.rs`), so the look folds to a
  constant and costs nothing; only a closed key set pays it. Not a step of the measured case.
- The shape of the declaration and the undeclaration (the parts moved by value, the refusal paths)
  is design S1 of `docs/win-budget/size.md`; the write filter's row is S-FILTER there.
- The per-body sizes section 3.2 finds (L3's declaration, the door's declaration pipeline, the
  engine's announcement) are S1's and section 3.2 of `docs/win-budget/size.md`'s, read on the
  same bodies.
