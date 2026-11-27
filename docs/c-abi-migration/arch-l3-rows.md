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
| the session's own tokens (H9, steps D9a, D9b) | the application's tables, one holder for every bundle (`ObserverTables::held_tokens`): the session's one table set's rows on the cooperative engine, the registry the tables of the storage policies keep (`RegistryTables::local_tokens`) on the others; a peer's Interest is answered into that peer's staging (`TokenAnswers` in `PeerTables::token_answers`), under the staging's own bound and with its own count of refused chains | the observer's own `LocalTokenRegistry` field beside the tables, its region rows and line, its lend of no row on the lent and counted forms, the choice between two holders on every answer and drain (`held_tokens().unwrap_or(&self.local_tokens)`); the registry's bound of a staging it did not hold (`reply_quota`) and the observer's sum of the refusals it was handed |

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
| H2 | which row an entity is | the row's handle (`Declared::handle`, generation-checked, P10), named across the port by the row's word (`EntityRow`) | none: the door keeps the row, and the entity id is read off the row (`SessionEngine::entity_id_of`) | no | gone (D4) |
| H3 | the key's text while a retraction is written | the row's `EntityKey` | none | no | gone (D3, D3q, D3t) |
| H4 | what keeps a key's declaration alive | the tables' count of the declaration (`KeyexprCount`) | none where no ABI makes an anchor: `KeyAnchor` is of no size without the port's `key-anchors`, which only the ABIs that retract by an object of their own name (the advanced subscriber's host, the Rust API) | no | gone (D5) |
| H5 | the callback protocol of a row | one record for every kind (`LatchedRow<S, A>` in `wz-capi-coop/src/engine.rs`) | none | no | gone (D6) |
| H6 | the session's L3 tables as a value | `SessionTables` and `PeerTables` in `wz-session-core` | `RegistryOf<H>` in `wz-capi-coop/src/engine/registry.rs`: the application's observer (`SlotObserverOf`, whose `tables` is the `SessionTables`), the faces' `FaceTables` (`peer`, `gets`, the due row), the holders' index and the written count; every operation reaches the tables through it | 1,101 bytes; 7,938 in the peer case, 18,542 in the api case | D7, read (6.6): what peer-rows R3 leaves of it |
| H7 | a pending get | each leg's entry in its face's table of pending gets (`FaceTables::gets`, `Requesters<ConsolidatingSink<LegSink, LegHold>>`); the tables' `PendingGetRow` is not built on this engine (6.3) | the get's own facts (mode, accepted key, deadline) once for each leg; the session's note of each leg went with H7a, the callback for each leg with H7b | no | D8: H7a, H7b, H7c1, H7c2a landed; H7c2b in part (the tables' row, the plane's queue); the rest of H7c2b, H7c2c (6.7), H7d (6.3) |
| H8 | a query kept past its callback | the queries' plane (`wz-session-core/src/query_plane.rs`, `FinalHold::kept`) | none: the engine keeps no copy, only the query's name across the port (`HeldQueryId`), read in 6.2 | no | not held twice |
| H9 | the session's own tokens | the application's tables (`ObserverTables::held_tokens`) | none; the tokens a lost face owes are kept apart (`OwedTokens`), read with D7 | no | gone (D9a, D9b) |
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
| D4 | H2, every kind at once | landed (6.4) | the port's `Declared` answers the row (`EntityRow`, the handle's bits on this engine, the id on an engine that has no rows); `undeclare_subscriber`, `undeclare_queryable` and the liveliness kinds take it; the doors keep it; L3's undeclarations by handle are there already | -150 to -300 (the walk of two tables by id), more where liveliness is built | 0 | an undeclaration by a row of an earlier generation finds nothing; one of a liveliness subscriber reaches its own table |
| D5 | H4 | landed (6.5) | the port's `KeyAnchor` as a type of no size where no ABI keeps an anchor | -100 to -200 text, 32 bytes a row of the region | 0 | the anchor test of `tests/liveliness.rs` kept on the build that keeps anchors; a size assertion of the row on one that does not |
| D6 | H5 | landed | `wz-capi-coop/src/engine.rs` (`LatchedRow<S, A>`, `RowCall<S, A>`, one `RowCallback` impl), `engine/query.rs` and `engine/liveliness.rs` (`QueryableRow`, `LivelinessRow` its instances); the subscriber's timestamp choice is the row's `shown` field, so its row is laid out as before | 0: the measured case builds the subscriber's instance alone, whose layout, constructor (out of line) and calls are unchanged; the api case 0 (each kind is still its own instance) | 0 | `closure_drops`, `queryable`, `liveliness`, `round` unchanged |
| D7 | H6 | read (6.6): its premise does not hold on this tree; read again on one that holds peer-rows R3b | the registry becomes the session core's (`wz-session-core`: the table set and the faces' sets, a face named by its set's handle) | -300 to -800; `pico-peer-coop` and the api case to be read (7,938 and 18,542 held now) | to be read: the receive's one look at its face's set is kept, and no call is added | the registry's tests move with it; `direct_receive`, `in_place` |
| D8 | H7 (H8 read as not held twice, 6.2) | designed (6.3, 6.7); H7a, H7b, H7c1, H7c2a landed, H7c2b in part; the rest of H7c2b, H7c2c, H7d to come | the note of each leg, then a callback for each leg, then the faces' copies of the get, then the snapshot's | 0; the api case by step (6.3) | 0; H7c read on the reply's receive | `get`, `local_query`, `queryable`, `snapshot`, `cancel` |
| D9a | H9: the answering apart from the holder | landed | `local_token.rs` (`TokenAnswers`), `peer_tables.rs` (`PeerTables::token_answers`), the observer's answer and drain | 0 (no liveliness); the api case 0 to -100 (the observer's sum of refusals and its `try_from`, read on `dispatch_event_among` and `answer_iteration_event`) | 0 (an Interest's path only) | `local_token::tests` (the staging's tests now stage through `TokenAnswers`, and `a_chain_that_does_not_fit_whole_is_refused_and_stages_nothing` reads the refusal it counts), `peer_tables::lent_tests::a_lent_peer_holds_a_liveliness_answer` (the refusal counted by the lent row's staging), `limits::tests::max_pending_declares_stated_refuses_the_next_chain_whole` (the quota reaches the staging through `PeerTables::limit_to`, and the observer reads the refusal off it) |
| D9b | H9: one holder | landed | `slot_observer.rs` (`RegistryTables::local_tokens`, `RegistryRows::local_tokens`, `ObserverTables::held_tokens` and `init_empty_at`; `ObserverRows` and the observer's field, region rows and line gone), `observer.rs` (the heap view reads the tables' registry), `local_token.rs` (the registry's region and counted forms gone), the coop engine's three callers of the observer's lent and counted forms and its region rows | 0 (no liveliness); the api case -100 to -400 (the observer's `LocalTokenRegistry<Region>` state, its region line, its lend of no row, its two `limit_*` calls, and the `HeldTokens` of `LocalTokenRegistry<Lent>`, whose vtable the `unwrap_or` named) | 0 | `slot_observer::lent_tests::a_lent_observers_tokens_are_a_registry_of_its_tables_lent_their_own_rows`; `limits::tests::max_local_tokens_*` (the token quota reaches the registry through `RegistryTables::hold_to`); `liveliness` |
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

What landed departs from the two moves above in where each fact went, read against the code as it
was written:

- D9a. The staging and its bound are one value, `TokenAnswers`, and it is the peer's: a field of
  `PeerTables` in place of `pending_declares` and `token_interest_chains_refused`, as
  `FinalStage` holds its rows, its quota and its refusals, and as the subscriber plane's answers
  are held with their bound in `SubscriberPeer`. A value beside the observer's planes would have
  held one bound for the stagings of every peer, which is a bound of none of them. The staging is
  the one writer of its count of refused chains, so the observer no longer sums what the answer
  returns; `answer_iteration_event` and `answer_messages` return nothing, and the tests read the
  count off the staging. `PeerTables::limit_to` states the quota, as it states the subscriber
  plane's.
- D9b. Move 2 is not a `Presence`. Whether the session's tables keep its tokens is already a type,
  the bundle the sinks name (`ObserverSinks::Tables`); a presence chosen beside it answers the same
  question a second time, and the session's one table set without a tokens' table
  (`LivelinessPresence = Absent`) would have had no holder at all, the registry absent and the
  tables keeping none. The registry is a table of the storage policies' bundle instead
  (`RegistryTables::local_tokens`, lent by `RegistryRows::local_tokens`, held to its limits by
  `hold_to`), and `ObserverTables::held_tokens` names the one holder for every bundle, the table
  set answering for itself whether or not it keeps tokens. The observer's field goes, and with it
  its in-place write, its region rows and line (`ObserverRegionRows` loses its `LOCAL_TOKENS`
  parameter, `SLOT_OBSERVER_LINES` its line), its lent and counted forms (`ObserverRows`, which
  then wrapped the tables' rows alone, is gone: `lent` and `counted` take the tables' rows), and
  the registry's region and counted forms, which no bundle makes. The heap view reads
  `tables.local_tokens`; the tokio engine and the lwip drive register through it unchanged. The
  bundle of the storage policies is written field by field where it lies
  (`ObserverTables::init_empty_at`), so the observer's in-place write still holds one table at a
  time on its frame, the token registry among them.

### 6.2 D8, read

H8's premise does not hold in the code. The query a program keeps past its callback is a row of
the queries' plane already: `CoopEngine::keep` (`engine/query.rs`) asks the plane's holds
(`FinalHolds::keep`, `keep_again`, `release_kept`) and writes what the replies are built from
into the plane's row of that query's Final (`FinalHold::kept`, `KeptQuery`). What the engine
keeps is `HeldQueryId`, the link generation and the request id the row is found by, which is the
port's name of the kept query (`wz_capi_port::QueryHolder`), not a second record of it. Whether
that name should be the row's handle rather than a lookup by generation and id is H2's question,
one contract for every entity across the port, and goes with D4.

H7 holds, though not as first read: the tables' row (`SessionTables::pending_gets`,
`PendingGetRow`: the request id, the gate, the legs still owing their Final, the deadline, the
callback) is not built on this engine (6.3). A get is recorded in the engine's note of each leg pending
(`CoopEngine::pending_gets`, `Rows<PendingGet>`, lent with the legs' rows); and each face's
requesters (`FaceTables::gets`, `Requesters<ConsolidatingSink<LegSink, LegHold>>`), with the
index of the earliest deadline over the faces' sets (`Dues`, a `DueRow` per set). Folding the
legs into one row of the get reaches the get's send, its replies' consolidation per leg, the
deadline index, the round's reply calls and the faces' sets; 6.3 designs it against them.

D4 is the façade lane's because the port's identity of an entity is one contract for every kind
and every engine: the cooperative engine, the tokio engine's port (`wz-capi-core/src/engine_port.rs`),
the router node's (`wz-capi-core/src/drive/router_node/engine.rs`) and the advanced subscriber's
test host each answer `Declared`, and each door keeps what it answers. Changed for the
subscriber alone it would be changed again for the queryable, the token and the liveliness
subscriber, each time in every engine; changed once with step 5, which takes the port out of the
release build (`arch-l4-facade` F7: the façade names L3's handles), the door keeps the L3 handle
itself.

### 6.3 H7, designed

H7's premise as 6.2 states it holds for the cooperative engine in part. Its tables keep no get:
`GetPresence` is `Absent` for its callbacks (`wz-capi-coop/src/engine.rs`, `RowCallbacks for
CoopRows`), so `SessionTables::pending_gets`, `PendingGetRow` and the tables' held replies are
built by the session core's tests alone. What a get is recorded in on this engine, for each leg (a
link's face, a group's, or the session's own queryables'):

| record | where | what it holds |
|---|---|---|
| the leg's entry | the face's table of pending gets (`FaceTables::gets`, `Requesters`): `ReplyRegistry`'s `Pending` for a query, `LivelinessGetRegistry`'s for a snapshot | the request id, which carries the entry's row; the Finals owed; the deadline; the accepted key; the sink: the consolidation of the get's mode (`ConsolidatingSink`), the leg's id (`LegSink`), its hold (`LegHold`) and the guard that says the leg's end (`LegEnd`) |
| the session's note of the leg | `SessionState::pending_gets` (`PendingGet { face, leg, kind, fan }`), a row for each entry the faces' tables hold | the face and the entry's key, again; the leg's id, again; the fan that cancels it, held nowhere else |
| the leg's callback | the get plane's rows (`LegRows`, `LegRow`), held by count | the callback the port minted for the leg, whether it shows timestamps |
| what the leg holds of its replies | the plane's held table (`HeldReplies<u64>`, tagged with the leg) and its ends (`EndedLegs`) | the consolidation's held replies; the leg's end, with the timeout that ended it |
| the deadline index | a `DueRow` for each face's set and the session's own gets (`Dues`) | a leaf for each table, keyed by the table's own earliest deadline: an index over tables, not a record of a get |

Read against the four things the fold reaches:

- The send. A leg's entry is held before its request goes out, so no answer arrives before it, under
  a request id of the face's serial and the entry's row (`LegRid::at`, `wire_id::request_id_at`), so a
  reply finds its entry at the row its id carries (`ReplyRegistry::row_of`) with no walk. The
  note is written after the send, under the same hold.
- The consolidation. Each leg consolidates on its own: its sink holds the get's mode and its own
  held replies, flushed at that leg's end. A get of two legs in `Latest` hands its callback a
  reply of a key from each leg. zenoh consolidates over every Final of the query and flushes once,
  at the last (`api/session.rs:3025-3029`, as `reply_sink.rs` reads it), and zenoh-pico holds one
  pending query with its remaining Finals (`_z_pending_query_t._remaining_finals`). Per-leg
  consolidation is right only for a get of one leg: a client's get of its one link, its own
  queryables not asked.
- The deadline index. A leaf per table, each table keeping its earliest deadline as entries come
  and go (`ReplyRegistry::due_ms`); an end is not told, a read raises a stale key (`DueIndex`).
  Every leg of a get repeats the get's one deadline in its own table.
- The round. A reply no thread captured is a record holding a count of the leg's callback row
  (`Round::offer_reply`); the leg's end is handed out after every reply held before it, and the
  callback is dropped by the last count, with no lock held.

The facts held twice are the face and the entry's key, and the leg's id, in the entry and in the
note; the facts of the get itself (its mode, its accepted key, its deadline, its timestamp choice,
its callback) are held once for each of its legs. The target is zenoh's: a get is one row, the
tables' `PendingGetRow` (its request id, its accepted key, the Finals its legs owe, its deadline,
its callback), with its consolidation mode, its fan and its held replies (`SessionTables::held`,
by the get's handle); a face holds of a leg only what a face must, the get its Final counts against
and how many it owes, so a lost face ends its legs and the round of deliveries never meets a leg.
Four steps, each landing on its own:

| step | removes | reaches | expected | receive Ir |
|---|---|---|---|---|
| H7a | the session's note of each leg: the fan is a field of the leg's callback row (the get as its asker holds it: its callback, its timestamp choice, the fan that cancels it); a cancellation ends the first entry, over the faces' tables, whose sink's row is in the fan; a lost face's table is emptied as a set given back is; the close and the last handle empty every table | `pending_get.rs` (`PendingGet`, `PendingLegs`, `GetKind`, `SessionFaces::end_leg`, `LegTables::end_leg` go), `session_state.rs` (`SessionParts::PendingGets`, `note_pending` go), `get_plane.rs` (`GetCalls::Fan`, `LegRow::fan`, `GetPlane::in_fan`), `reply.rs` and `liveliness_get.rs` (`unregister_first`), the engine's four notes and their refusals, its close, its drop, its cancellation and the end's walk of the notes in every delivery that hands an end out, the arena's `pending legs` part and the region's rows of it | 0 (no get); the api case -200 to -600 text (the note's writes and refusals in `get_on_wire` and `liveliness_get_on_wire`, the walk in `deliver`, the close's and the drop's loops, `PendingLegs`' bodies) and 32 bytes a leg row of the arena (a note's 56 less the fan's 24 in the callback row) | 0: a reply is handed to its entry as before; the walk of the notes ran only where an end was handed out |
| H7b | a callback for each leg: the engine mints the get's callback once and every leg's sink holds a count of its row, so the leg rows are a row for each get, and the get is over when its one callback is dropped (the port's contract: "a get is over when the last callback it minted is dropped") | `get_on_wire`, `liveliness_get_on_wire`, `hold_leg` (`LegAsk` holds the opened row), `GetPlane::open_leg` and a hold of an opened row; the doors' count of legs read first | the api case: one mint for each get; the leg rows' table sized by gets, not by legs | 0 |
| H7c | the faces' copies of the get: the get is the tables' row (`GetPresence = Present` on this engine), its request id minted by the tables and carried by every leg, as zenoh and zenoh-pico carry one; its replies consolidated in the tables' held replies and flushed at its last Final, over every leg; its deadline in the row and the tables' watermark the one leaf of the index for queries (`Dues` keeps the snapshots' alone, or goes with H7d); a face's entry the get's handle and the Finals that face owes; the plane's held table and its leg rows go, the round's reply records holding the row's latch (P11) as a subscriber's do | `reply.rs` (the face's table of queries, its dispatch of a Response and a Final), `registry.rs` (`dispatch_reply`, `lend_reply`, `project_reply`, `take_reply`, `fire_reply`, `sweep_due_gets`, `Dues`), `get_plane.rs`, `round.rs`' reply records, the arena's gets parts | the api case: the faces' copies of the gate's key and of the deadline, the plane's held table and leg rows; kilobytes, to be read | must not grow: the request id carries the get's row as it carries the entry's now, and the Response's find is one look as now; read on the reply's receive before it lands |
| H7d | the snapshot's copies: a liveliness get's row in the same table, its Interest's id per face (an Interest id is the link's) and its DeclFinal counted as a query's Final | `liveliness_get.rs`, the registry's `claim_token`, `fire_token` | the api case, to be read | 0 |

What landed of it:

- H7a. A leg is its entry in its face's table and its callback's row, and nothing besides. The fan
  its get was asked under is a field of that row (`LegRow::fan`, written by
  `GetPlane::open_leg`, read by `GetPlane::in_fan`), so the row is the get as its asker holds it.
  A cancellation ends, one at a time, the first entry over the faces' tables and the session's own
  whose sink's row names the fan (`RegistryOf::end_first_leg`, over `ReplyRegistry::unregister_first`
  and `LivelinessGetRegistry::unregister_first`, the sink read through `ConsolidatingSink::inner`
  and `LegSink::row`), and drops its callback after the lock as before (`end_leg_now`). A lost
  face's tables are emptied where the registry is told of the loss (`SessionFaces::lose_face`),
  as a set given back is; the close and the last handle empty every table (`end_every_get`).
  Gone: `PendingGet`, `PendingLegs`, `GetKind`, `SessionFaces::end_leg`, `LegTables::end_leg`,
  `SessionParts::PendingGets`, `SessionState::pending_gets` and `note_pending`, the engine's
  four notes and their refusal branches (unreachable, the rows matching the entries), the walk of
  the notes in every delivery that hands an end out, the arena's `pending legs` part (`GET_ROWS`
  4) and the region's rows of it. Tests: `get_plane::tests::a_legs_row_names_the_fan_its_get_was_asked_under`
  (red if the row keeps no fan, or keeps it past its last count),
  `reply::tests::the_first_entry_its_sink_names_is_dropped_and_the_deadline_moves_on` and
  `liveliness_get::tests::the_first_get_its_sink_names_is_removed_and_the_deadline_moves_on` (red
  if the removal keeps the deadline of the entry gone, or takes every entry the pick names),
  `tests::get::a_get_ends_with_its_link` (red if a loss leaves the face's entries standing),
  `session_state::tests::a_lost_face_is_the_faces_to_end_and_the_deadline_is_read_off_them`; the
  cancellation tests (`a_cancelled_get_ends_without_a_step`, `a_cancelled_snapshot_ends_without_a_step`,
  `a_cancellable_get_allocates_nothing_and_its_fan_ends_it`) and `a_snapshot_ends_with_its_link`
  unchanged. The `pending legs` row of `heap-native.md`'s table of first-use refusals goes with it.
- H7b. A get's callback is minted once, at its first leg, into a row of the plane's, and every
  later leg's entry takes a count of that row: the get as its asker holds it
  (`get_plane::AskedGet`, which `LegAsk` carries through `hold_leg` and the snapshot's issue
  holds beside its walk of the faces). The asker holds a count of its own from the first leg until
  the issue returns, so a leg that ends while the next is issued neither drops the callback nor
  frees its row for another get. The rows of the callbacks were what bounded the legs held at once,
  a row each; with one row a get, the ends bound them instead: each leg's open sets a row of the
  ends aside (`EndedLegs::set_aside`, its count of the legs whose ends are not yet written), which
  the end is written into, so the drop of an entry still finds its row with nothing to answer. The
  port's contract reads as both engines keep it: a callback is dropped once every leg it served
  ended, minted once a get or once a leg. The doors count callbacks, not legs, and need no change.
  Size: the api case one mint a get where it issued two legs or more, against the join's count and
  the asker's hold and release; about level, and the step is H7c's footing (one row a get) rather
  than a gain of its own. Receive: 0 (a reply's sink, its capture and the round's records are
  unchanged). Tests: `get_plane::tests::a_gets_legs_share_the_callback_its_first_leg_minted` (red
  if a later leg mints again, or the asker holds no count),
  `the_ends_bound_the_legs_of_a_get_that_share_one_row` (red if a later leg is held with no row of
  the ends set aside), `a_leg_past_the_rows_mints_no_callback_and_a_row_given_back_is_reused` (the
  row now given back by the leg's end); `tests::local_query::a_get_for_any_destination_waits_for_the_peer_and_the_session`
  (one callback for the peer's leg and the session's) and `tests::get::a_get_is_answered_and_ends_with_its_final`
  (one mint).

- H7c, read against the code, is two steps, not one. Its consolidation over the get and its one
  end lie in the get plane and do not need the get on the tables' row; its request id and the
  faces' entries of (handle, Finals) move the find of a Response from the face's table
  (`request_id_at` puts the entry's row in the id) to the tables, in `ReplyRegistry`, which the
  tokio engine and the router node share. The first lands alone as H7c1; the second is H7c2, read
  on the reply's receive before it is written.
- H7c1. The get consolidates and ends as one. Its held replies and what its entries give up whole
  are keyed by its row (`HeldReplies<LegId>`, the held table's `(LegId, InboundReply)`), so every
  leg's `LegHold` holds into one consolidation, and a leg's Final makes nothing due by itself
  (`LegHold::drain` is empty, its drop lets nothing go). The row counts what stands of the get
  (`LegRow::standing`: its legs' entries and its asker), and whichever stands last writes the get's
  one end (`GetPlane::stand_down`, from `LegEnd`'s drop or `AskedGet`'s): a leg that ends while
  another stands gives its count back where it ends, which is never the last. The end hands the
  held replies, the whole ones and the timeout of the leg that stood last, once; the legs share one
  deadline (`LegAsk::deadline_ms`, read under the first leg's hold; the snapshot's likewise), so
  they time out in one sweep and the last says it. The ends are a row a get again, set aside at its
  first leg, which undoes H7b's row a leg. A get whose legs all ended while it was issued ends with
  its asker, and its end is handed out before the call returns (`hand_out_asked_ends`, after
  `ask_get_legs` and `ask_snapshot_legs`). A leg needs no id (`LegEntry::leg`, `Ended::leg`,
  `LegSink::leg`, `LegTurn::Ended`, `end_leg_now` go; `next_local` is the tickers' alone); a
  cancellation lets go of what the get held (`end_get_now`, by the row `end_first_leg` answers).
  Size: the api case loses the leg ids, the per-leg end path and the hold's drop; to be read.
  Receive: 0 (a reply's sink and hold read the same rows by another key). Tests:
  `get_plane::tests::a_gets_legs_hold_back_into_one_consolidation` (red if each leg holds apart, or
  a Final flushes before the get's end), `a_gets_end_says_the_timeout_of_the_leg_that_stood_last`,
  `a_gets_legs_share_the_callback_its_first_leg_minted` (red if an end is written each leg, or the
  asker does not stand), `the_ends_bound_the_gets_held_at_once_whatever_their_legs`;
  `tests::local_query::a_latest_get_of_two_legs_hands_one_reply_of_a_key_over_both` (the
  correction below, on the engine).
- H7c2, designed on the receive in 6.7: three steps, H7c2a, H7c2b and H7c2c.

H7c changes what a program of a peer with two links sees of a `Latest` or `Monotonic` get: one
reply of a key over both legs, where it is handed one from each now. That is the reference's
behaviour, and the change is stated in its commit and held by a test of a get of two legs.

### 6.4 D4, landed

An entity of the session's tables of declarations is named across the port by its row. The port's
`EntityRow` (`wz-capi-port/src/lib.rs`) is a word only the engine that wrote it reads: the
cooperative engine writes the row's word in its tables (`DeclaredRow::to_bits`, its table's code
above its handle's bits, `wz-session-core/src/session_tables.rs`), and an engine that keeps no rows
(the tokio engine's port, the router node, a test host) writes the entity id
(`EntityRow::by_id`, `Declared::by_id`). `declare_subscriber_on_wire`,
`declare_queryable_on_wire`, `declare_liveliness_subscriber_on_wire` and their link-set forms
answer `Declared<EntityRow>`, `declare_liveliness_token_on_wire` answers `EntityRow`, and
`undeclare_subscriber`, `undeclare_queryable` and `undeclare_liveliness_token` take it. The doors
keep the row (`DeclaredSubscriber::row`, `DeclaredQueryable::row`, `TokenState::row`,
`PlainQueryable::row`, the advanced subscriber's `Subscription` and `Token`, the zenoh-c plane's
cache queryable and token, the group node's held entities). The entity id is read off the row where
an ABI names it (`SessionEngine::entity_id_of`: `z_subscriber_id`, `z_queryable_id`, an advanced
subscriber's identity), so the door holds no copy of it; a closed session holds no row, and answers
the null id there, which is zenoh-pico's answer under its session check
(`vendor/zenoh-pico/src/api/api.c` @ `z_entity_global_id_t z_subscriber_id(`).

It departs from `arch-l4-facade.md` F5 in one point: the row is a value type of the port, not an
associated type of `SessionEngine`. The ABIs hold the engine as `Arc<dyn SessionEngine>` (the
zenoh-c plane, the group node, the advanced subscriber's host, the router node's port tests), and an
associated type would split that object type by engine; the word keeps one object type, and the
façade that names L3's handles with step 5 reads the same word.

On the cooperative engine an undeclaration reads its handle off the row's word
(`entity_handle::<K>`), with no walk of a table: the subscriber's and the queryable's walks of their
tables by id, enumerated for the row's rank, and the liveliness subscribers' walk ahead of the
subscribers' in `undeclare_subscriber` are gone, the rank read at the handle
(`Core::place_of`). A row of an earlier generation stands in no slot and retracts nothing; a row of
another table is no handle of the kind asked (`DeclaredRow::handle`), so the liveliness
subscriber's row reaches its own table (`CoopEngine::undeclare_liveliness_subscriber`) and no
other. The write filters were named by their rows' bits already (`row_id`, `row_of`).

Expected: client and peer -150 to -300 (the two enumerated walks of `undeclare_subscriber`, 1,721,
for a decode of the word and one look); the api case -300 to -600 (the queryable's and the token's
walks with them). Receive Ir 0: no read takes any of it. Tests:
`session_tables::tests::a_rows_word_names_its_handle_in_its_own_table_alone` (red if the word leaves
out its table, or a handle is read off a row of another table);
`entity_tables::answers_the_id_its_row_was_numbered_by`, run for the subscriber, the queryable and
the liveliness subscriber (now also red if a row of an earlier generation retracts the entity that
took its slot, or the undeclared row still names an id);
`entity_tables::a_liveliness_subscribers_row_reaches_its_own_table_alone` (red if the liveliness
subscriber's row undeclares the subscriber holding the same handle's bits, or a queryable's
undeclaration takes a row of another table); `liveliness::a_history_subscriber_undeclared_from_its_history_is_let_go_of_before_its_declaration_returns`
(the callback finds its own row by the id the session hands out next); the router node's and the
tokio port's tests unchanged in what they hold, their ids read through `EntityRow::as_id`.

### 6.5 D5, landed

What a key keeps alive past its declaration is a capability of the port, `key-anchors`
(`wz-capi-port/Cargo.toml`), as the shared sinks are `shared-sinks`: it gates `WireKey::keeping`,
`WireKey::aliased_in`, the rest a key lends from what it keeps (`Suffix::Lent`) and the key's
`Keeps`. Without it `KeyAnchor` has no field, so the anchor every subscriber's, queryable's and
liveliness subscriber's row holds is of no size and has no drop, and a `WireKey` holds its name
alone. It is named where an anchor is made: `wz-ext-pubsub`'s `engine-host` (the advanced
subscriber's host, which the pico ABI's advanced plane and the zenoh-c ABI run), `wz-zenoh`'s port
dependency (the Rust API's keeps), and the cooperative engine's tests (`liveliness`'s kept name).
The pico preset without `advanced` builds none of it. The rest of `WireKey`'s forms another ABI
alone makes (`Suffix::Owned`) are `arch-l4-facade.md` F9's, on the same seam.

Expected: client and peer -100 to -200 text (`Keeps`' drop in every row's drop and in each
`WireKey`'s, `into_anchor`'s move) and the anchor's bytes in each row of the three kinds; the api
case 0 where `advanced` is built. Receive Ir 0: the anchor is touched by the declaration and the
row's drop alone. Tests: `wz-capi-port` `tests::an_anchor_is_of_no_size_where_no_abi_keeps_one`
(a build without `key-anchors`; red if the anchor or the key keeps an object's place);
`tests::a_kept_rest_is_lent_to_the_key` and `tests::a_kept_anchor_lives_until_what_the_key_kept_is_dropped`
with `key-anchors` (a row of `scripts/lib/nondefault-tests-gate.sh`); the cooperative engine's
`liveliness::a_tokens_kept_name_is_let_go_of_by_its_declaration_with_no_lock_held` unchanged, its
dev-dependency naming `key-anchors`.

### 6.6 D7, read

D7's premise as its row states it (the registry becomes the session core's: the table set and the
faces' sets, a face named by its set's handle) does not hold for this lane on this tree. Read
against the code and the lanes beside it:

1. The faces' sets are `peer-rows.md` R3's. R3 takes the registry's sets out as a second table
   beside the face table: a face is a row of the face table and is named by that row, not by a
   set's handle; what the peers declare becomes relations with the face as a column, whose peer
   side is a trait of the session core; and what a set holds of the face's own (its staged replies,
   its Finals, its interests' answers, its queries' judge, its pending gets and their due) becomes
   a part of the face's row (`peer-rows.md` 7.6). R3a landed on `peer-rows-table-1128`
   (`acc6c12841`: `Holders`, `ManyHolders`, `OneHolder` and `RegistryOf<H>` gone, one
   `Registry` body, the places marked in `HeldPlaces`), which this branch does not hold; R3b
   waits on heap-native's relation. Moved into the session core here, the sets would carry into L3
   the shape R3 removes, named by the handle R3 replaces, over every line R3a changed in
   `registry.rs`, `held.rs` and `adding.rs`.
2. The sets are most of H6's bytes. In the peer and api cases (7,938 and 18,542) the registry's
   bodies are mostly its composition of a face's set (`RegistryOf<ManyHolders>::new` 4,925,
   `add_face`, `give_back`, `hold_table`, `entity_rows`; `peer-rows.md` section 2.2), which
   R3's expectation counts. What D7 would move besides is the rest.
3. Of that rest, the index of the gets' deadlines (`Dues`, a leaf a set) is H7's: its queries'
   leaves go into the tables' one watermark with H7c2 (6.7), its snapshots' with H7d.

What is left of D7 is the application's half of the registry (the observer whose `tables` is the
`SessionTables`, the round's delivery, the written count), through which every operation reaches
the tables. It is read again on a tree that holds R3b, as the move of that half into the session
core; its expectation in the client case (-300 to -800 of 1,101) stands until then. No file of the
registry changed with this reading.

### 6.7 H7c2, designed on the reply's receive

**The receive as it is.** A peer's Response to a get, on the read that hands each record out as it
is read (`engine/replies.rs`, `hand_lent_reply`), mode `None`:

1. Under the session's lock the reply is read where its frame lies (`Registry::lend_reply`: the
   face's place, its peer's mapping spaces, `reply::lend_response`).
2. The get plane's capture is turned on (`GetPlane::capture`, its lock).
3. `Registry::fire_reply` finds the face's place again and hands the reply to its table of
   pending gets through `ReplyRegistry::dispatch_borrowed`: the key gate, then a walk of every
   entry of the table comparing the id, the entry's accepted key, its sink
   (`ConsolidatingSink`, then `LegSink::on_reply`, which takes the capture under its lock and a
   count of the get's row under the rows' lock).
4. `hand_captured` reads the capture (its lock), lets the session go, reads the row's place (the
   rows' lock), calls, and gives the count back (the rows' lock).

The copying read (`engine/pinned.rs`, `take_reply`) is the same from step 2. A Final is
dispatched under the lock alone (`Registry::dispatch_reply`, `ReplyRegistry::dispatch_lent_reply`),
and finds the one entry its id names (`final_to_one`).

Two things the H7c row of 6.3 assumed are not so. The find is one look on the Final's path only:
the reply handed past the lock walks the face's entries (`dispatch_borrowed` is the dispatch of a
table whose ids its callers chose, two of which may share one), where this engine's ids each name
one entry (`request_id_at`). And a reply takes five sections of the plane's locks besides the
session's, one inside another: none of them is the reply's own work; each is the price of a get
held apart from the tables, whose callback is found by a capture rather than by the code that holds
the lock.

**The receive as it is to be.** Under the session's lock: the reply read as now; the get found by
its id in the tables (`SessionTables::pending_get`, the row the id carries, the id compared whole:
one look); its gate (`PendingGetRow::admits`); in mode `None`, or for an Err, a call begun on the
row's latch (`begin_reply`, P11, as a subscriber's); otherwise the tables' consolidation
(`consolidate_reply`, held by the get's handle), which begins the call of a reply it lets through.
The lock is let go of, the call made, and its end given back. No capture and no lock of a plane:
the code that holds the session's lock is the code that calls. A reply's receive is expected to
lose the walk, the face's second look for its place and the plane's five sections; a Push's is
untouched.

**Where each fact of a get lands.**

| fact | now | with H7c2 |
|---|---|---|
| its request id | a serial of the face's or the group's counter over the row of the leg's entry in that face's table (`LegRid::Serial`), or the session's own (`local_requests`, `LegRid::Taken`): one id a leg | one id a get, minted by the tables over its row's index (`request_id_at(serial, index)`), carried by every leg and by the query the session's own queryables are asked; `mint_request`'s walk for an id no get holds, and `pending_get`'s walk, go |
| the key a reply must intersect | each entry's `ReplyAcceptanceStored`, a key a leg in the key arena | the row's `gate`, one key |
| its deadline | each entry's `deadline_ms`, each table's `due_ms`, a leaf of `Dues` a set | the row's `deadline`; the tables keep their earliest as gets come and go, as `ReplyRegistry::due_ms` is kept, the queries' one leaf; `Dues` keeps the snapshots' until H7d |
| its consolidation | each entry's `ConsolidatingSink` | a field of the row (`PendingGetRow::mode`), as zenoh keeps the reception mode in the query's state |
| what it holds back | the plane's `HeldReplies<LegId>`, and its `VecDeque` of what an entry gave up whole | the tables' `held` (`HeldReplies<PendingGetHandle>`); the queue goes unreplaced: no sink is handed a reply owned (`ReplySink::on_reply_owned` has no caller), so it is never written, and a reply `Latest` has no room for is handed on at once (`reply_hold::consolidate`'s `Refused`) |
| its callback, timestamp choice and fan | the plane's `LegRow`, held by count and by what stands | the row's callback record (`RowCallbacks::Reply` of `CoopRows`, a `LatchedRow` instance: the callback, `shown`, the fan), its life the latch's (P11) |
| the Finals it is owed | each entry's `remaining_finals`, and the row's count of what stands | the row's `legs`, and each face's count of the Finals it owes |
| a leg | an entry `Pending { rid, remaining_finals, deadline_ms, sink, accept }` | the get's handle and the Finals its face owes (a table of the session core's, `GetLegs`): what a lost face ends and nothing else |
| its end | `LegEnd`'s drop, `stand_down`, `EndedLegs` | the row's last leg (`end_leg`), its deadline or its cancellation (`end_get`) marks the row ended and lets no reply begin; the deliveries hand out what it held and its timeout (`timeout_reply` of the row's one id), then retire the row and drop the callback with no lock held |
| a reply of the session's own queryables | a capture of the plane's | the replier finds the row by its id under the lock and calls after it, as a peer's reply is called |
| a reply the round holds (`wz_round`) | a record with a count of the plane's row | a record with a begun call of the row, as a subscriber's records hold it |

**Steps.**

- H7c2a. The reply handed past the lock finds its entry in one look: `Registry::fire_reply` hands
  it to the one entry its id names (`ReplyRegistry::reply_to_one`, the Final's look). Receive: a
  reply's walk of the face's entries less one look; equal with one get pending. Size: about 0;
  the walk (`fire_replies_for`) is no longer reached from the engine where `reply_to_one` is built
  already. Landed (below).
- H7c2b. The get in the tables' row: `GetPresence = Present` on this engine, its callback record,
  mode, gate, deadline and Finals in the row, its consolidation in the tables' `held`, its end a
  state of the row handed out by the deliveries; the plane's rows of callbacks, its ends, its held
  table, its capture and `AskedGet` go (`get_plane.rs` keeps nothing an engine reads). A face's
  entry keeps its own id and names the get's handle (`ReplyRegistry` of a sink that is the handle,
  no deadline, every key accepted), and its dispatch answers the handle the reply reaches for the
  caller to hand to the tables, so this step lands without the id's change. Reaches
  `session_tables.rs` (the row's mode, its ended state, the tables' due watermark), `reply.rs`
  (an entry's find answered, not fired), `get_plane.rs`, `round.rs`' reply records, the engine's
  `get.rs`, `replies.rs`, `queries.rs`, `query.rs`, `ask_get_legs`, `hold_leg`, `hand_held`,
  `end_get_now`, `registry.rs` (`Gets`, `fire_reply`, `sweep_due_gets`, `Dues`'s queries,
  `end_first_leg`, `end_every_get`), `state_places.rs` and `arena.rs` (the plane's parts out, the
  tables' gets and held rows in). Expected: the api case -1,500 to -4,000 (the plane's bodies, a
  key and a deadline a leg, the queries' leaves of `Dues`), to be read on those bodies; the client
  and peer cases 0 (`query` not built). Receive: down, as above.
- H7c2c. One id a get, and a face's entry its handle and its Finals: the tables mint the id over
  the row's index, every leg and the session's own query carry it, the face's `ReplyRegistry` goes
  for `GetLegs` (the handle, the Finals; the key gate and the read of a Response, which the registry
  holds now, become a value both hold), and a Response is found in the tables by its id, before any
  face's table. Reaches `wire_id.rs` (the tables' serial), `session_tables.rs` (`mint_request`,
  `pending_get`), `reply.rs`, a new `get_legs.rs`, the engine's issue of the legs (the face's and
  the group's counters and `local_requests` no longer read by a get) and `registry.rs`'s `Gets`.
  Expected: the api case a few hundred bytes (the per-face table's rows, an id a leg); receive: the
  Response's find in the tables is the one look the face's table made.

**H7c2a, landed.** `Registry::fire_reply` (`wz-capi-coop/src/engine/registry.rs`) hands a reply
read past the lock, by the direct read (`hand_lent_reply`) or the copying one (`take_reply`), to
`ReplyRegistry::reply_to_one`, as the Final's dispatch hands its id to `final_to_one`: the row
the id carries is read first, the id compared whole, and the walk is left for an entry an earlier
end moved toward the front. What a reply is handed is unchanged: the key gate, the entry's accepted
keys and the sink are the same, and a face's table holds no two entries of one id on this engine
(each id is `request_id_at` of the face's serial and the entry's row). Held by
`reply::tests::a_row_held_again_is_not_named_by_the_id_of_its_earlier_entry` (red if the carried
row is taken without the whole id compared) and
`an_entry_moved_by_an_earlier_end_is_found_and_ends_at_its_last_final` (red if the walk is left
out of `row_of`), which now read the engine's path for every peer's reply, and by `tests::get`
and `tests::local_query` unchanged. No test tells the two finds apart by what they hand: the
step is read on the receive of a reply, where a face with `n` gets pending loses the walk over
them for one look. Size: about 0 (the call changes; both bodies are built already).

**H7c2b, in part.** Two of its commits landed, each on its own:

- The get's row in the tables (`wz-session-core/src/session_tables.rs`). `PendingGetRow` keeps
  the get's consolidation (`mode`) and its end (`GetEnd`: `Standing`, `Answered`,
  `TimedOut`), and `begin_get` takes the mode. A caller that issues the legs one at a time
  begins the get with one leg, its own, adds each leg it holds (`add_leg`) and ends its own once
  it issued them: `AskedGet`'s standing asker as a count of the row. A reply is admitted in one
  call under the tables' hold (`admit_reply`): the get stands, its gate admits the reply, its
  mode's consolidation holds it, drops it as stale or lets it through, and a call is begun on the
  row's latch for what it lets through; `consolidate_reply`, which took the mode from its caller,
  goes. The last leg (`end_leg`) or the deadline (`time_out_get`) ends the row in place; the
  deliveries find it (`next_ended_get`), hand out what it held (`take_held`) and its timeout by
  calls begun on the row, and retire it (`retire_get`, what `end_get` was), which a
  cancellation does at once. The tables keep the standing gets' earliest deadline (`get_due`,
  past by one so that the region's zero bytes hold none), lowered as a get begins and worked out
  again only when the get that held it stops standing, so `next_get_deadline` reads it with no
  walk; a deadline of `u64::MAX` is none. Size: 0 in every case (the engine's `GetPresence` is
  still `Absent`, so none of it is built there). Receive: 0. Tests:
  `session_tables::tests::a_get_is_found_by_its_request_and_ended_by_its_last_leg_or_its_deadline`
  (red if an ended row is found expired again, the watermark keeps the deadline of a get that
  stopped standing, or an ended get takes a leg),
  `a_get_counts_the_legs_added_to_it_and_ends_at_the_last` (red if a leg added is not counted, or
  a get with no deadline is due), `a_latest_get_holds_its_replies_until_they_are_taken_and_retires_with_the_rest`,
  `a_reply_is_admitted_by_its_gets_gate_mode_and_standing` (red if an ended get takes a reply, an
  Err is held, a reply off the gate's key passes, or what an ended get held goes before its end).
- The plane's queue of what an entry gave up whole (`GetPlane::held`, `keep_held`,
  `take_held`, `take_all_held`, `LegSink::on_reply_owned`) goes: no sink is handed a reply
  owned (`ReplySink::on_reply_owned` has no caller), so it was never written. A get's end hands
  what it held back and its timeout, as before (`hand_held`, `end_get_now`, the close). Size:
  the api case loses the queue's lock and `VecDeque`, its read at every end and the close's
  drain; to be read. Receive: 0. Tests: `tests::get` and `tests::local_query` unchanged.

What is left of H7c2b is the engine's move onto the row, and two facts found reading it:

- The snapshot's legs (`ask_snapshot_legs`) mint into the plane's rows through the same
  `AskedGet` and `LegSink` as a query's, so the plane's rows, ends and capture go only when the
  snapshot's callback, deadline and end are a row of the same table (mode `None`, its key the
  gate). That part moves with H7c2b; H7d keeps what is the snapshot's own (its Interest id per
  face, its DeclFinal counted as a query's Final).
- Until H7c2c a leg carries an id of its face's, not the row's: the timeout the deliveries hand
  out names the row's id (`timeout_reply`), which no leg carried. Whether an ABI shows a reply's
  request id is read before the move lands; where one does, the timeout keeps the id of the leg
  that stood last until H7c2c makes the two one.

H7c2b and H7c2c write `registry.rs`' `Gets` and `FaceTables`, which `peer-rows.md` R3b makes a
part of the face's row: the merge of the two lanes is the main session's to order, and H7c2c's
`GetLegs` is the part of the face's row R3b names (its pending gets).

**Whether an ABI shows a reply's request id: none does.** Read before the timeout takes the row's
id. zenoh's `Reply` (`zenoh/src/api/query.rs` at the pin) holds its result and, behind
`unstable`, its replier's id; zenoh-c's accessors, as `crates/wz-capi-c/src/get.rs` implements
them, are `z_reply_is_ok`, `z_reply_ok`, `z_reply_err`, `z_reply_replier_id` and the
clone, loan, take and drop of a reply; zenoh-pico's `_z_reply_t` holds a `_z_reply_data_t` of
`_result`, `replier_id` and `_tag` (`vendor/zenoh-pico/include/zenoh-pico/net/reply.h`), and
`crates/wz-capi-pico/src/get.rs` keeps the same accessors. `ReplyView::rid` is read inside wz
alone, by the tables that find a reply's get. So the timeout the deliveries hand out may name the
row's id before any leg carries it, and H7c2b need not move the id: H7c2c makes it the one id every
leg carries.

**H7c2c's table, built ahead of H7c2b.** H7c2b's face entry is not a `ReplyRegistry` of a sink that
is the handle, which H7c2c would take out again: it is H7c2c's table, built now and used by H7c2b.

- The read of a peer's Response (`wz-session-core/src/reply.rs`, `ReplyReceive`): the key gate
  and the receive side of shared memory, with `take_response` and `project_response`, out of
  `ReplyRegistry`, which holds one and hands its setters on. The engine reads a Response through
  the face registry's `receive_mut` until its face holds the legs' table. Size: 0 (the same
  fields and bodies, one level down). Receive: 0. Test:
  `reply::tests::a_receive_alone_gates_a_peers_reply_by_its_key` (red if `admits_key` takes a
  key outside a closed set, refuses an Err, or does not count the refusal), and the registry's
  key-gate and shared-memory tests unchanged.
- The legs of a face (`wz-session-core/src/get_legs.rs`, `GetLegs<H, P>`): for each leg the id
  the face's peer answers it under and the get's handle, and the face's `ReplyReceive`. A reply
  finds its get through the key gate and one look at the row its id carries, the walk left for a
  leg an earlier end moved (`reply_to`, `get_of`); a Final ends the leg and hands the get back
  for the caller's `end_leg` on the row (`end_leg`); a get its row retired is let go of
  (`forget`); a lost face ends every leg, each get handed back once (`end_every_leg`). A leg
  keeps no count of Finals: on this engine a face's entry owes one, and the session's own
  queryables are a leg of the row, not of a face. No key, deadline or sink a leg: those are the
  row's. The table states no quota: a get has at most one leg a face, so the gets' table bounds it.
  Size: 0 until the engine holds it (no caller yet). Tests (`get_legs::tests`):
  `a_reply_finds_the_get_its_id_names_and_its_final_ends_the_leg_once` (red if a reply reaches
  another leg's get or a Final ends a leg twice),
  `a_leg_is_found_by_its_whole_id_wherever_an_earlier_end_moved_it` (red if the carried row is
  taken without the whole id compared, or the walk is left out),
  `a_retired_get_is_forgotten_and_a_lost_face_ends_every_leg` (red if `forget` takes another
  get's leg, or the loss leaves a leg or hands one twice),
  `a_table_lent_one_row_refuses_a_second_leg_until_the_first_ends` (red if the table holds past
  its rows or keeps a row its leg left), and, with `key-set-closed`,
  `a_closed_key_set_keeps_a_reply_outside_it_from_its_get` (red if a reply skips the face's gate).

The snapshot's legs are answered under an Interest id, not a request id, and its registry keeps
what is the snapshot's own (the Interests whose answer ended, pruned from the reconnect cache; the
count of keys past the bound the slot profile reads into). Whether its legs are a second
`GetLegs` over Interest ids is read when the snapshot's callback, deadline and end move into the
row, with H7c2b.

What is left of H7c2b is unchanged otherwise: the engine's `GetPresence = Present`, the row's
callback record (`LatchedRow` of the callback, `shown`, the fan), the face's `Gets` as
`GetLegs<PendingGetHandle>`, the receive and the local queryable's reply through
`admit_reply`, the deliveries walking `next_ended_get`, the sweep through `next_expired_get`,
the cancellation and the close through `retire_get` and `forget`, the issue through
`begin_get` and `add_leg`, and the plane deleted.

**Where a face's replies and Finals reach its legs, read before the switch.** `GetLegs` cannot take
`ReplyRegistry`'s place in the face's `Gets` as a drop-in: the session core's fan reaches a face's
table of gets through `RequesterTables` and `SlotObserverOf::dispatch_reply`
(`wz-session-core/src/slot_observer.rs`, the trait at 321, the fan's calls at 2046 and 2048), with
`&mut self` of the observer that holds the tables, so nothing handed there can reach
`SessionTables::end_leg` or `admit_reply`. How each form of the engine hands them now:

| record | the direct form (`not(wz_round)`) | the round's form (`wz_round`) |
|---|---|---|
| a lent Response | the engine's own (`replies.rs`, `hand_lent_reply`) | the fan (`dispatch_event_among`) |
| an owned Response | the engine's own, ahead of the fan (`pinned.rs`, `take_reply`) | the fan |
| a lent ResponseFinal | the observer, on the engine's call (`Registry::dispatch_reply`) | the fan |
| an owned ResponseFinal | the fan, after the engine took the Responses (`dispatch_finals_of`) | the fan |

Decided: the engine hands every reply and every Final of its faces itself, in both forms, as the
direct form already hands the Responses, so the face's legs and the tables' row meet under one
hold with no fan between them. A Final ends its leg (`GetLegs::end_leg`) and the get's
(`SessionTables::end_leg`) where the engine reads it: the lent one in `Registry::dispatch_reply`,
the owned one in a walk of the frame's ResponseFinals in the face's dispatch, after its Responses
were taken, as `dispatch_finals_of` runs now. The round's form reads a frame's Responses and
Finals off the event after the fan, in their order (`Registry::dispatch_event_to`), so the fan
of both forms carries no reply: the face's `Gets` answers `RequesterTables` for the snapshots
alone until H7d moves them onto the row, and then is `NoRequesters` to the fan. No mark of an
answered leg is kept in `GetLegs` for a caller that did not see its Final.

The round's reply record holds a count of the plane's row (`Owed::Reply(C::Leg)`, held and let go
of through `LegHolders`, `wz-session-core/src/round.rs` 1242 and 2225). With the get on the
tables' row it holds a call begun on that row's latch, as a queryable's record does
(`Owed::Query`): `RoundCalls::Leg` becomes the reply call, `Round::offer_reply` takes the call
`admit_reply` passed, and `LegHolders`, `Round::calls_legs_of` and the released half's `legs`
go. That change cannot land ahead of the switch: the plane is what `LegHolders` is, and a call
type the plane made for it would be written only to be taken out.

So the switch lands as three commits, each built whole:

1. The queries onto the row. `CoopRows`' `GetPresence` is `Present` under `query` and its
   `Reply` a `LatchedRow` of the reply callback showing the timestamp choice and the fan; the
   plan lends the tables `pending_gets` and `held_replies` rows (`ArenaPlan::tables`, now 0
   and 0) in every form (lent, region, on use). A face's `Gets` holds `GetLegs` of the row's
   handle beside the snapshots' registry, and the session's own queryables' leg is a `GetLegs`
   of the registry's own (`Registry::local`), answered under `LOCAL_QUERY` as now. The issue
   begins the row at its first leg, adds a leg for each face held and ends the asker's at the
   end of the issue; a reply is admitted under the hold and called after it; a Final, a lost
   face and the deadline (`next_expired_get`, the `Dues` leaf of the queries replaced by the
   tables' watermark) end the row in place; the deliveries walk `next_ended_get` when an end is
   owed, hand out what the row held and its timeout under the row's id, retire it and forget its
   legs; a cancellation and the close retire every row they name. The round's records take the
   row's calls. The snapshot keeps the plane's rows, ends and capture.
2. The snapshot onto the row: mode `None`, its key the gate, its legs a second `GetLegs` over
   Interest ids or the one table, read then.
3. The plane deleted (`get_plane.rs`, `engine/get.rs`, the plane's places and arena parts,
   `LegHolders`), and the face's `Gets` the legs alone.

Decided after: the snapshot moves in the same commit as the queries, so no call type is ever
written for the plane only to be taken out, and the session's own queryables' leg is a `GetLegs`
answering `LOCAL_QUERY`, found by the one look every leg is. The plane's session-core half
(`get_plane.rs`, `LegHolders`, `Round::calls_legs_of`, `PlaneCalls::Captures`) cannot outlive
the round's change to a call, so it goes in that one commit too; what is left for a commit after
it is only what the engine no longer reaches.

**The tables' walks the switch reads, landed ahead of it** (`wz-session-core/src/session_tables.rs`).
A get retired while a call of it ran (a reply the round of deliveries holds, or one the read
handed past the lock) is let go of by the session's walk once its last call ended
(`release_drained_get`, as `release_drained_subscriber` is for a subscriber; the walk is the one
`release_drained` keeps, over a row that is not a declared entity), and a cancellation or the
close finds every get its asker's fan names, standing or ended, in one walk of the table
(`next_get_of`), where today it walks every face's table for an entry of the fan. Size: 0 in
every case (the engine's `GetPresence` is still `Absent`). Receive: 0. Tests:
`session_tables::tests::a_get_retired_while_its_call_ran_is_let_go_by_the_walk_once_the_call_ended`
(red if the walk takes a get whose call still runs, takes one twice, or leaves its slot held) and
`a_walk_finds_each_get_its_pick_names_standing_or_ended` (red if the walk skips an ended get,
finds one of another fan, or finds a retired get again).

**Two rulings on the switch.** A get's row keeps no anchor: a get holds no key of the ABI's, so
`LatchedRow` takes what its row keeps of the key as a parameter (`LatchedRow<S, A, K = KeyAnchor>`)
and a get's row is `LatchedRow<ReplyCallback, GetShown, ()>`: one row type, and no anchor paid
per get where the ABI keeps keys. And a cancellation ends delivery: once a get's cancel returns its
callback is handed nothing more, held, owed by a round or begun and not yet made, and only its drop
runs, as zenoh and zenoh-pico end a get its asker undeclares; an end by answer or by deadline still
hands what the get held back and its timeout. The two ends differ where a call is made, with no
lock held and after the tables' row was retired: the call reads only the get's record (a call is
where the record lies), so the record says how the get ended (`GetShown::cancelled`, set under the
lock before the cancellation retires the row and read as each call is made), and the tables' row
keeps the ends that leave it in place to be handed out (`GetEnd::Answered`, `TimedOut`). The
cancellation then waits, as an undeclaration does, until no call of the get runs
(`wait_for_get_release`); the session's close ends each get as a cancellation.

**The tables' count of ended gets, landed ahead of the switch.** The tables count the gets their
answer or their deadline ended and that are not retired yet (`SessionTables::owes_ended_get`), so
the engine marks under the hold that ended one that a delivery owes it, and a delivery that reads
the mark clear takes no lock. Size: 0 in every case (`GetPresence` is still `Absent` on the
engine). Receive: 0. Test:
`session_tables::tests::the_tables_count_the_ended_gets_until_each_is_retired` (red if
`end_leg` or `time_out_get` leaves an end uncounted, or `retire_get` takes a standing get off
the count or leaves an ended one on it).

**Three parts of the switch, landed ahead of it.**

- A group's leg owes a Final of each member it holds when the get is asked
  (`QueryOptions::remote_finals` over the group's members), so "a leg keeps no count of Finals: on
  this engine a face's entry owes one" (above) holds for a link and for the session's own
  queryables, not for a group. The count is the face's, as the table of facts says (each face's
  count of the Finals it owes): `GetLegs` keeps for each leg the Finals still owed
  (`hold_owing`; `hold` owes one), `end_leg` ends the leg at the last and hands the get back
  then, a Final past the last finds nothing, and the row counts legs, not Finals. Size: a leg's
  row grows from 8 to 12 bytes in every form (a `u32`, the row's alignment), against the plane's
  rows and a face's entry of sink, key and deadline it replaces. Receive: 0. Test:
  `get_legs::tests::a_leg_owing_several_finals_ends_at_its_last` (red if `end_leg` ends a leg at
  its first Final, or a leg owing none is held).
- The legs' table in the other forms: `GetLegs::counted` (on use, taking its rows at its first
  leg) and `GetLegs<_, Region>::places` over `GetLegsRows` (`GET_LEGS_LINES`, one line, no
  handle to the key arena: a leg keeps no key). The table states no quota, so a face's legs need
  nothing of `limit_to`: the gets' table bounds them. Size: 0 until the engine holds them.
  Tests: `a_table_counted_one_row_refuses_a_second_leg_until_the_first_ends` (red if a counted
  table holds past its count) and `region_legs_describe_their_rows_inside_their_rows` (red if
  the line has the wrong bound or rows lie outside `GetLegsRows`).
- A cancellation's and the close's walk (`SessionTables::retire_next_get_of`): the next get the
  pick names, marked (the cancellation's mark, under the same hold) and retired, handed back with
  how its row left, `Removal` and not an `Option`; the cursor moves past every get it reads, so
  a walk the engine carries across its holds of the session ends whatever a retirement answers.
  A retirement is never refused for a live get: a get's slot is pinned by its retirement alone
  (the gets' table is lent out of the tables only as `&`: `kept_pending_gets_mut` is private),
  and a retired get is found by no lookup, so the one pin a running call needs is taken over a
  count of none. The deliveries' walk of the ended gets carries its cursor alike. Size: 0 until
  the engine walks it. Receive: 0. Test:
  `session_tables::tests::a_walk_retires_each_get_its_pick_names_once_and_marks_it_first` (red
  if the walk reads a get twice, leaves one unmarked, or refuses one a call of which runs).

**The switch, landed** (`refactor(capi-coop): Hold each get as a row of the session's tables`).
`GetPresence` is `Present` under `query`; a get, a query's or a liveliness snapshot's, is a row of
the tables (`ReplyRow`, `LatchedRow<ReplyCallback, GetShown, ()>`), its calls `GetCall`s begun on
the row's latch. `get_plane.rs`, `LegHolders`, `Round::calls_legs_of`, `PlaneCalls::Captures`,
the engine's plane, its `EndedLegs`, `LegRows` and `HeldReplies<LegId>`, the registry's `Dues`,
`DueRow`, `write_gets` and `sweep_due_gets`, and the arena's parts of them go.

- A face's `Gets` is two `GetLegs<PendingGetHandle>`: its queries' under their request ids and
  its snapshots' under their Interest ids (`snapshot_leg`). It answers the observer's fan as a
  session that asks nothing does but for `claims`, which keeps a pending snapshot's token from
  the liveliness subscribers.
- The engine hands every reply, token and Final its faces read, in both forms: the fan is
  followed by a walk of the event in its order (`RegistryOf::take_answers_of`), which ends a
  ResponseFinal's leg and a DeclFinal's snapshot leg (`end_get_leg`, `end_snapshot_leg`) and,
  in the round's form, admits each Response and each claimed token to its row and offers the
  round the call admission began (`offer_lent_reply`, `offer_token`, `offer_reply`). The
  direct form hands Responses and tokens before the fan as it did (`replies`, `pinned`).
- A snapshot's row has mode `None` and gate `ReplyAcceptance::Any`, as its old table had no key
  gate, so it keeps no key in the key arena; its timeout is the row's, swept with the queries'.
  Its DeclFinal stages no prune: the engine keeps no cache of the Interests it asked. The token's
  key is resolved by `claim_answering_token` and `claim_answering_token_view`
  (`declare/liveliness_get.rs`), which the registry's `claim_token` methods now call too.
- The plan lends the tables a row of `pending_gets` for every query and snapshot the limits
  admit and a row of `held_replies` for every held reply (`ArenaPlan::tables`, 0 and 0
  before); a face's legs are laid out by `face_leg_bytes` (lent), `Gets::places` over
  `GetRows` (region) and `Gets::counted` (on use).

Tests: `get::tests::a_get_ended_by_its_answer_hands_the_calls_begun_before_its_row_was_retired`
(red if a call reads the latch's retirement as the end of the delivery),
`a_reply_racing_a_cancellation_never_reaches_the_callback_after_it` (red if `GetCall::hand` does
not read the cancellation, or `ReplyRow::cancel` does not mark it),
`tests::get::a_get_cancelled_before_its_answer_is_handed_nothing_after_the_cancel` (red if a
cancellation keeps the row or the legs, so the reply read later reaches its callback),
`tests::round::a_replys_record_holds_its_call_until_its_delivery_ends_it` and
`a_reply_is_read_where_it_lies_and_one_lying_elsewhere_is_refused` (red if the round ends a
record's call before its delivery, never ends it, or keeps a refused reply's call running),
`tests::arena::the_tables_hold_a_row_for_each_get_and_each_held_reply` (red if the tables get
no row of a snapshot, or a part of a get's own is laid out again), and `tests::get`,
`tests::local_query` and `tests::snapshot` unchanged. The registry's test of the index of the
deadlines goes with the index; the watermark is held by the session tables' tests.

Expected: the api case down by the plane's bodies, its locks and capture, a key and a deadline a
leg, `Dues`' leaves and the per-get rows apart from the tables; the client and peer cases 0
(`query` not built). Receive: down by the plane's five lock sections per reply. Nothing was
built or run; still owed: a test of the direct read whose delivery hands out a get ended by its
Final (red if `note_ended_gets` after `dispatch_reply` is removed), and
`crates/wz-capi-pico/link/run-text.ld` regenerated (`scripts/pico-compare.sh run-text`): its
seven lines naming `get_plane` were taken out, and the legs' functions are not yet listed.

**The switch, built in every form** (`fix(capi-coop): Build the switch of the gets in every
form`, `test(capi-coop): Hand out a get its Final ends in the read of the Final`). The switch as
landed did not compile `wz-capi-coop` in any build that asks queries:

- `engine/get.rs` named `RowCallback` through `session_tables`, whose import of it is private;
  it is named from `row_callback`, which makes it public, as the other rows' modules name it.
  The `begin` and `retire` the tests of `get.rs` found missing on `LatchedRow<S, A, K>` were
  that trait out of scope, not a bound lost with the anchor parameter.
- `make_get_call` lay in `replies.rs`, which the direct form alone builds, while the hand-out of
  the ended gets and the local queryable's reply call it in both forms. It lies beside
  `end_get_call` in `engine.rs`; the tests' count of the replies the read handed itself
  (`pinned_replies`) moves to the read's two callers (`hand_reply`, `hand_token`), so it counts
  those alone, as before the switch, and not the ended gets' hand-out or the local replies.
- `PlacedTables` holds the queryables' Finals alone since the get plane left it, so its import
  is gated on `queryable`, as the struct is; the registry's `let mut`, which the index of the
  deadlines needed, goes with that index.

Test: `tests::direct_receive::a_get_its_final_ends_is_handed_out_by_the_read_that_read_the_final`
(direct form: a `Latest` get holds its reply to its end, and the read that dispatched its Final
hands out the reply and the end; red if `note_ended_gets` after `dispatch_reply` in `direct.rs`
is removed, which leaves both to a later read's sweep). Expected size and Ir: unchanged by the
fix, which moves one body and changes no path. Still owed: `crates/wz-capi-pico/link/run-text.ld`
regenerated once the lane is green.

## 7. The receive

None of D1 to D6, D3q and D3t is on the receive or the put; their receive instructions a message
are expected unchanged (about 3,073 in the lane's reading; `docs/win-budget/size.md` section 8
reads 3,078). D2 changes two declarations, D3q and D3t two undeclarations, none of which a read
calls; the queryable's receive bodies (`next_queryable_reached`, `QueryableCall`) take none of
their code. D9a and D9b are on the receive of an Interest only, which the measured receive (a
Push) does not reach: `dispatch_event_among` calls the tokens' staging for every record as it
did, with the holder read off the tables instead of chosen between two, so a Push's path through it
is the event match that finds no Interest, unchanged.
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
