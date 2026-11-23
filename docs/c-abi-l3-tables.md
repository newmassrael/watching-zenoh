# The session's one table set (L3)

Status: design for phase 4 of `docs/c-abi-architecture.md` (section 5, "One table set"), 2026-11-23.
It names where every fact of the session's application layer lives today, the one table set of
`wz-session-core` that will own each of them (P1, P3, P10, P11), the API the engines drive it
through, the order in which the cooperative engine is reduced to a driver of it, the path of the
tokio engine onto the same tables, and the saving expected. The tables themselves are
`wz_session_core::slot_map` and `wz_session_core::session_tables`; no engine uses them yet.

## 1. What is measured

The release form (`os-posix`, no `std`, `capi-nostd`), text 363,212 B against zenoh-pico's
329,664 B for the same build, function bytes with aliases of one address counted once:

| part of `wz-capi-coop` | bytes |
|---|---:|
| `CoopEngine` (declare, undeclare, deliveries, targets) | 37,000 |
| `Core` (entity rows, announce, replay, links) | 21,800 |
| delivery lane (`lane`) | 18,300 |
| registry (`engine/registry`: application tables, face tables) | 14,200 |
| arena plan (`arena`) | 6,400 |
| total | 101,700 |

zenoh-pico's whole sessions area (declare, subscribe, query, reply, interest, its resource and
entity lists) is 31,700 B. The engine alone is three times that, on top of the session core it
drives, because it keeps a second set of the same tables over the session core's.

## 2. Where each fact lives today

Read from `crates/wz-capi-coop/src/engine.rs`, `engine/registry.rs`, `engine/liveliness.rs`,
`engine/get.rs`, `engine/query.rs`, `arena.rs` and from `wz-session-core`'s `slot_observer`,
`pubsub`, `declare/*` and `peer_tables`. "Copies" counts the places that hold the fact itself
(a key's text, an id, a callback), not the places that read it.

| fact | where it is held today | copies | L3 owner |
|---|---|---:|---|
| declared key expression (its id, key, holders) | `Core::keyexprs` (`KexprEntry`), read by every link through `SessionKeyexprs`; the mapping id and an owned suffix `String` again in every entity's `WireKey`, whose `Arc` keeps the declaration alive | 2, and 1 per entity naming it | `keyexprs` |
| subscriber key and origin | `Registry::app.subscribers` (`SubscriberTable` row, the pattern in the key arena) | 1 | `subscribers` |
| subscriber id | the entity id (`CoopEngine::next_entity`) in `SubscriberRow`, and the table's own `SubscriptionId` | 2 | `subscribers` (one entity id) |
| subscriber callback | `SubscriberRow::callback`, `CoopEngine::targets` (`TargetKey::Subscriber`), `Resolved` (up to four kept between samples) | 3 | the row (P11) |
| queryable key, origin, completeness | `Core::queryables` (`QblEntry`) and `Registry::app.queryables` (`QueryableRegistry`) | 2 | `queryables` |
| queryable id | `QblEntry::id` (entity id) and `QblEntry::registration` (`QueryableId`) | 2 | `queryables` |
| queryable callback | `CoopEngine::targets` (`TargetKey::Queryable`), reached from the registry's sink through `QueryPlane` | 1, two hops | the row |
| liveliness token | `Core::tokens` (`TokenEntry`) and `Registry::app.local_tokens` (`LocalTokenRegistry`) | 2 | `tokens` |
| liveliness subscriber | `Core::live_subs` (`LiveSubEntry`), `Registry::app.liveliness_subscribers` (pattern, history, sink), callback in `targets` | 2, callback 1 | `liveliness_subscribers` |
| matching listener | `Core::matches` (`MatchEntry`), the `MatchingWatchList` inside `RemoteSubscriberTable` / `RemoteQueryableTable` (criterion with its own key, last verdict, sink; a growable list), the sink again in `targets`, the flips in `CoopEngine::matching` | 2, callback 2 | `matching` |
| write filter | `Core::filters` (`FilterEntry`, with the peers' verdict cached) | 1, its key again in its Interest | `write_filters` (key read from its Interest) |
| Interest the session holds open | `Core::interests` (`InterestHold`) | 1 | `interests` |
| what a face's peer declared | `FaceTables::peer` (`PeerTables`, rows in `PeerPools`) | 1 | stays in `PeerTables` (section 5) |
| pending get | `FaceTables::gets` (`Requesters`: request id, key, deadline, consolidating sink), `Core::pending_gets` (`PendingGet`), the callback in `targets` (`TargetKey::Reply`), its end in `GetPlane::ended` | 3 | `pending_gets` |
| query held for its callback | `QueryPlane` (`FinalHolds` and a queue of `OwnedQuery` copies), the Final in `PeerTables::finals` | a copy of every query | not in this phase: the query is answered from its view under a hold (phase 5) |
| id counters | `next_entity`, `next_local`, `Core::next_mapping`, `next_filter`, `next_match`, `next_local_request`, plus the ids `SubscriberTable` and `QueryableRegistry` mint | 8 | `SessionTables` mints entity, key expression and request ids; a filter and a listener are named by their handle and need no number |
| a sample on its way to a callback | the delivery lane (`SharedLane`): key, payload, attachment and timestamp copied into the lane's bytes | 1 copy of every sample | none: the delivery iterates the rows and calls in place (P4) |

The tokio engine (`wz-capi-core::faces`) has the same shape one level up: `SharedSession` keeps
`SubEntry`, `QblEntry`, `KexprEntry` and `TokenEntry` lists as the program's record, and each face
holds its own `TokioSession` whose observer registers every subscriber, queryable, token and
listener again (`FaceEntry::subs`, `qbls`, `tokens`, `live_subs`, `matches`, `filters`): one
declaration is held once plus once per face.

## 3. The table set

One `SessionTables<F, P>` per session, in the session's region (P3):

| table | row | bound (`caps`) |
|---|---|---|
| `keyexprs` | `KeyexprRow`: expr id, key, holders | `MAX_DECLARED_KEYEXPRS` |
| `subscribers` | `SubscriberRow`: entity id, key form, origin, callback | `MAX_SUBSCRIPTIONS` |
| `queryables` | `QueryableRow`: entity id, key form, origin, complete, callback | `MAX_QUERYABLES` |
| `tokens` | `TokenRow`: entity id, key form | `MAX_LOCAL_TOKENS` |
| `liveliness_subscribers` | `LivelinessSubscriberRow`: entity id (its Interest's), key form, history, callback | `MAX_LIVELINESS_SUBSCRIPTIONS` |
| `interests` | `InterestRow`: entity id, kind, key, holders | `MAX_PUBLISHERS + MAX_QUERIERS + MAX_MATCHING_LISTENERS` |
| `write_filters` | `WriteFilterRow`: plane, its Interest, count-local, cached peers' verdict | `MAX_PUBLISHERS + MAX_QUERIERS` |
| `matching` | `MatchingRow`: plane, its Interest, count-local, last verdict, callback | `MAX_MATCHING_LISTENERS` |
| `pending_gets` | `PendingGetRow`: request id, face, key, deadline, callback | `MAX_PENDING_QUERIES` |

- **Slot maps.** Each table is a `SlotMap<K, T, N, P>`: a fixed-capacity map whose rows are named
  by a `Handle<K>`, a slot index (`NonZeroU16`, so `Option<Handle<K>>` is four bytes) and the
  generation the row was taken at. The generation moves when a slot is freed, so a handle kept
  past its row names nothing rather than the slot's next row. `K` is a marker per table, so a
  subscriber's handle is not accepted where a queryable's is. The free list, generations and pins
  are one non-generic core over a metadata column; what is typed is a column of `Option<T>` and
  the few lines that move a value in and out of it (P5). The two columns are lent from the
  session's arena at its open on the lent policy (`SlotMap::lent`), or are fixed (`Static`) or
  growable to the bound (`Heap`) on the other policies. A full table refuses at the call that asks
  and hands the value back (P3).
- **Keys.** Every row keeps its key in the session's key arena (`KeyRef` on the lent policy). An
  entity names the key expression declaration its key starts with by the handle of that row, not
  by a copy of its id and suffix: the wire form (`SessionTables::wire_of`) is the declaration's
  id and the rest of the entity's own key. Holding the declaration is a count in its row, released
  when the entity is undeclared; the last release retracts the declaration. A filter and a
  listener keep no key: they read the key of the Interest they hold.
- **Interests.** A write filter and a matching listener hold one Interest each, shared by every
  filter and listener on the same kind and key; a new holder of an existing Interest sends
  nothing, the last release sends its Final. The Interest table's bound is the sum of the two, so
  a filter or a listener the table has room for always finds room for its Interest.
- **Ids.** One entity id space (the wire's `EntityId`, from 1, refused once spent rather than
  wrapped); key expression ids from 1, skipping any still declared; request ids skipping any
  still pending.
- **Refusals (P10).** Every declaration answers `Result<Declared<K>, Refused<C>>`; `Refused`
  carries the cause as the session core's `RegisterError` (`TableFull`, `KeyexprTooLong`,
  `IdsExhausted`), which the port already maps to its `Refusal`, and hands the callback back so
  the caller drops it where it holds no lock. The order is fixed: table room, then the key, then
  the id, so a refused declaration spends no id and keeps no key.
- **Callbacks (P11).** A row owns its callback (`F::Subscriber` and its kin: a C triple or a
  shared Rust `Fn`, chosen once per build by `RowCallbacks`). A delivery pins the row it calls
  (`pin_subscriber`); undeclaring a pinned row retires it: the row leaves every lookup and
  iteration at once, keeps its slot and its generation, and is handed back by the last
  `unpin_*`, which is where its `drop` runs, after the last call. The undeclaring caller returns
  only once `holds_slot(handle)` of the row's table is false, so after the last call and the
  drop, as zenoh-pico's undeclare waits for the entity's lock.

## 4. The API

```rust
// Declare and undeclare: one call each, the wire's ids in the answer.
fn declare_keyexpr(&mut self, key: &str) -> Result<KeyexprDeclared, RegisterError>;
fn undeclare_keyexpr(&mut self, handle: KeyexprHandle) -> Option<ExprId>;
fn declare_subscriber(&mut self, key: &str, origin: Locality, form: KeyForm, cb: F::Subscriber)
    -> Result<Declared<kind::Subscriber>, Refused<F::Subscriber>>;
fn undeclare_subscriber(&mut self, h: SubscriberHandle) -> Option<Undeclared<Subscriber<F, P>>>;
// ... the same pair for queryables, tokens and liveliness subscribers.
fn declare_write_filter(&mut self, plane: Plane, key: &str, count_local: bool)
    -> Result<Watching<kind::WriteFilter>, RegisterError>;
fn declare_matching_listener(&mut self, plane: Plane, key: &str, count_local: bool, cb: F::Matching)
    -> Result<Watching<kind::MatchingListener>, Refused<F::Matching>>;
fn begin_get(&mut self, face: FaceId, key: &str, deadline: u64, cb: F::Reply)
    -> Result<GetBegun, Refused<F::Reply>>;

// Look up and match: total functions over the rows.
fn wire_of<'a, Key>(&'a self, key: &'a EntityKey<Key>) -> WireForm<'a>;
fn matches(&self, plane: Plane, key: &str, count_local: bool, peers: &impl PeerDeclarations) -> bool;
fn write_filter_open(&self, h: WriteFilterHandle, peers: &impl PeerDeclarations) -> Option<bool>;
fn next_matching_change(&mut self, cursor: &mut usize, peers: &impl PeerDeclarations)
    -> Option<(MatchingListenerHandle, bool)>;
fn pending_get(&self, face: FaceId, request: RequestId) -> Option<(PendingGetHandle, &PendingGet<F, P>)>;
fn next_expired_get(&self, now: u64, cursor: &mut usize) -> Option<PendingGetHandle>;
fn next_get_on_face(&self, face: FaceId, cursor: &mut usize) -> Option<PendingGetHandle>;

// Deliver: iterators over the rows a key reaches, and the pins a call outside the lock takes.
fn subscribers_for<'a>(&'a self, key: &'a str, local: bool) -> impl Iterator<Item = (SubscriberHandle, &'a Subscriber<F, P>)>;
fn queryables_for<'a>(&'a self, key: &'a str, local: bool) -> impl Iterator<...>;
fn liveliness_subscribers_for<'a>(&'a self, key: &'a str) -> impl Iterator<...>;
fn tokens_for<'a>(&'a self, key: &'a str) -> impl Iterator<...>;
fn pin_subscriber(&mut self, h: SubscriberHandle) -> Option<Pinned<kind::Subscriber>>;
fn unpin_subscriber(&mut self, p: Pinned<kind::Subscriber>) -> Option<Subscriber<F, P>>;
fn holds_slot(&self, h: Handle<K>) -> bool; // on each table: the undeclare's wait
```

`PeerDeclarations` is what the tables ask of the faces: whether any face's peer declared an
entity of a plane on a key, and a count that moves whenever a face's peer tables change, which
the write filter's cached verdict is kept against. The cooperative engine's `Registry` answers
both today (`peers_declare`, `faces_written`).

The cursors (`&mut usize`) let a driver walk a table while it changes it, with no allocation and
no borrow held across the change, as `BoundedVec::take_next_where` does.

## 5. What does not move in this phase

- **What a peer declared** stays in `PeerTables`: it is already one owner per face, its rows in
  the session's pools (`peer_tables`, `row_pool`). The tables read it only through
  `PeerDeclarations`. Folding its pools into the same region as slot maps is a later change of
  storage, not of ownership.
- **Reply consolidation and acceptance** (`reply_sink::ConsolidatingSink`, `reply_acceptance`)
  stay functions the driver applies before it calls a get's callback; the pending get's row holds
  only what identifies it and its callback.
- **The link state** (sequence numbers, batches, reassembly) is L2's.

## 6. How the cooperative engine becomes a driver of the tables

The engine files are under change by the delivery work (`wz-capi-coop`, L3 delivery and L0
links); each step below lands when that work allows, coordinated by the main session. Every step
keeps every test green and is measured against the size ledger (P9).

1. **Ids and key expressions.** `Core::keyexprs` and the five counters go; `SessionKeyexprs`
   reads `SessionTables::keyexprs`; `WireKey`'s suffix and keep-alive become a `KeyForm`.
2. **Subscribers.** `SubscriberTable`'s registration for the application goes: a sample's
   subscribers are `subscribers_for`. `targets` and `Resolved` lose their subscriber kind; the
   callback is the row's.
3. **Queryables, then tokens and liveliness subscribers.** `QblEntry`, `TokenEntry`,
   `LiveSubEntry` and the application half of `SlotObserverOf` (`queryables`, `local_tokens`,
   `liveliness_subscribers`) go; the replay walks the tables in the order `engine/replay.rs`
   names (key expressions, subscribers and Interests, queryables, tokens, liveliness Interests).
4. **Write filters, matching listeners, Interests.** `FilterEntry`, `MatchEntry`,
   `InterestHold`, the `MatchingWatchList`s and the `matching` queue go: a change of what the
   peers declare is followed by `next_matching_change`.
5. **Pending gets.** `Requesters` per face, `PendingGet`, `EndedLegs` and the reply targets go:
   a reply finds its get by `pending_get(face, request)`, a lost face ends its gets by
   `next_get_on_face`, a deadline by `next_expired_get`.
6. **The delivery lane.** With every callback in a row, a delivery pins the rows it reaches and
   calls them from the received bytes (P4); `SharedLane`, `targets`, `Resolved`, `TryCell` and
   `LiveCallback` go. Backpressure becomes the transport's flow control alone: the session takes
   the next batch when the calls of the last have returned.

After step 6 the engine keeps the links, the wait set, the timers and the read task (L0) and the
transport sessions (L2); every row of section 2 has one owner.

## 7. The tokio engine on the same tables

Each face of `wz-capi-core`'s `SharedSession` is a `TokioSession`, and each `TokioSession` holds
an `ApplicationLayerObserver`: the application's tables (its subscribers, queryables, local tokens,
liveliness subscribers, the listeners on what a peer declares) and the tables its peer writes (its
key aliases, its declarations, its interests) in one value. A subscriber of the program is
therefore registered once in `SharedSession`'s list and once more in every face's observer, and
those rows are not only for delivery: the face's drive loop answers a peer's subscriber Interest
from them (`observer.rs`, `sub_interest_reply`), the face re-judges its matching listeners from
them, and a retraction is ordered against those answers (`subscriber.rs`, `teardown`). A face
cannot simply stop registering.

The split the cooperative engine already makes is the one the tokio engine takes:

- the application half once per session, shared by every face: `slot_observer::SlotObserverOf`
  of the heap profile, which is the same registries as the observer's, apart from any peer;
- for each face, what its peer writes (`peer_tables::PeerTables`) and the session's gets
  pending on it (`slot_observer::Requesters`), as the cooperative engine's `FaceTables` are.

Every dispatch and every answer to a peer is made with both halves in hand: the slot observer's
calls take the face's tables as an argument (`SlotObserverOf::dispatch`, `flush_pending`). The
steps, each a unit that compiles and keeps every test:

1. **The face observer.** `wz-runtime-tokio`'s `Session` holds, in place of its
   `ApplicationLayerObserver`, a face observer: a shared handle to the application half and its
   own peer tables and requesters. A session opened alone makes a handle of its own, so a session
   that is not a face of `SharedSession` behaves as it does now.
2. **One application half for the faces.** `TokioSession` gains the constructor that is handed
   the handle; `SharedSession` opens every face with its one handle.
3. **One registration.** `SharedSession` registers a subscriber once in the shared half and sends
   its declaration on each face's link; `FaceEntry::subs` goes. Then queryables, tokens,
   liveliness subscribers, matching listeners and write filters, in that order.
4. **The table set.** The shared half's registries become the rows of `SessionTables`
   (section 3), the step the cooperative engine takes too (section 6).

### Lock order

A face's observer is taken first, the shared application half second, and never the other way
round: every path that reaches the application half today does it from inside its face's
observer (a dispatch, an answer to an Interest, a matching re-judgement), and keeping that order
changes none of them. A path that holds no face (a declaration of `SharedSession`) takes the
application half alone and lets it go before it takes any face. Both locks are
`wz_runtime_tokio::sync::PlainMutex`, whose debug build records the order every thread takes its
locks in and stops at the first acquisition that inverts an order seen before (`sync::lock_order`).
`SharedSession`'s own registry lock comes before both.

Two fields `SharedSession` keeps that the rows do not hold yet: the link restriction of a
declaration (`LinkRestriction`, `entity-link-restriction`) and the declaration options of a
token; each becomes a field of the row behind the feature that names it, with the step that moves
its kind. The router's routing table is a further table of the same set behind its feature
(`docs/c-abi-architecture.md`, section 3).

## 8. Expected saving

An estimate from the measured parts, to be replaced by the ledger's measurement at each step:

| removed | today | estimate after |
|---|---:|---:|
| delivery lane | 18,300 | about 1,000 (the pin protocol) |
| `targets`, `Resolved`, `TryCell`, `LiveCallback`, `Target` dispatch in `CoopEngine` | part of 37,000 | 0 |
| entity rows, announce and replay per kind in `Core` | part of 21,800 | one walk over the tables |
| application half of the registry and its monomorphised session-core registries | part of 14,200 | the tables' code, once |
| arena plan rows for the engine's own tables | part of 6,400 | one row set from `TableRows` |

The engine's 101.7 KB is expected to fall to 45 to 55 KB, and the sessions area of the release
library towards zenoh-pico's 31.7 KB; no number in this section is measured. The tables' own code
is one non-generic slot core and, per row type, the move in and out of a column, so it does not
grow with the number of tables the way a registry per kind does.
