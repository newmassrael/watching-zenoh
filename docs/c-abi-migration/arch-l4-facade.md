# Migration lane arch-l4-facade: the thin façade (L4), section 5 step 5

Step 5 of `docs/c-abi-architecture.md` section 5: the doors call L3 directly, the marshals lend
views, and the port trait leaves the release build. This note counts how many times each fact is
held between the C ABI's doors (`wz-capi-pico`), the port (`wz-capi-port`), the cooperative engine
(`wz-capi-coop`) and the session core (`wz-session-core`, L3) in the three cases of the size ledger
(section 2); sets out the form a door takes once step 4 (`arch-l3-rows.md`) has made L3 one table
set, what taking out the port's vocabulary and its trait does to the release and the test builds,
and how the two lanes' steps interlock (section 3); orders the steps, each landing on its own, with
the bytes and the receive's instructions each is expected to move (section 4); and reads what adding
a feature (`peer`, `query`, `queryable`) costs once steps 4 and 5 are done (section 5).

It replaces the first version of this note, whose step F1 has landed (`89d7916c9b`); that version's
F2 to F7 are restated in section 4 with their basis. Nothing here was built or measured by this
lane: the figures are read from the reports named in section 1, and every figure a step is expected
to move is an **estimate**, given with the bodies it is read from.

## 1. Readings

| reading | source | what is read |
|---|---|---|
| the explain reports of the three cases | `scripts/lib/size_ledger_gate.py --explain`, its JSON (`size-ledger/explain-<case>.json`), the latest verification run of each case: tree `7866d585a4`, the integration branch that carries main `a36726c93c` and the peer capabilities W1, W2 and W6 of `peer-proportion.md`; ledger date 2026-11-27, zenoh-pico `6a881c21dad1`, cc 13.3.0 | areas, owners, source files and bodies of `pico-client-coop-nostd` (below: client), `pico-peer-coop` (peer) and `pico-api-coop-nostd` (api) |
| main's reading of the same cases | the same gate on `a36726c93c` | the area rows, to see which figures the integration branch moves |
| the per-feature steps | `--per-feature` of `pico-peer-coop` and `pico-api-coop-nostd`, 2026-11-27, as `feat-query.md` and `peer-proportion.md` read them | what each feature adds to each area, on both sides |
| the code | `origin/main` at `df994d7913` | the types, the call paths and the tests named |

"Body view" below is a body's bytes in every area (the L3 code inlined into it counted with it);
"owner view" is the bytes the line tables give a module, wherever they were inlined.

### 1.1 The areas

| area | client wz | zenoh-pico | peer wz | zenoh-pico | api wz | zenoh-pico |
|---|---:|---:|---:|---:|---:|---:|
| sessions | 61,097 | 27,508 | 99,907 | 30,392 | 298,812 | 55,128 |
| doors | 39,391 | 19,034 | 48,498 | 19,616 | 180,126 | 61,195 |
| transport | 26,268 | 13,951 | 31,217 | 16,863 | 64,973 | 27,246 |
| driver | 25,944 | 16,049 | 52,370 | 16,560 | 142,213 | 26,087 |
| keyexpr | 8,013 | 13,490 | 7,982 | 13,490 | 9,248 | 14,439 |
| codec | 28,180 | 35,440 | 33,099 | 35,547 | 77,953 | 36,707 |
| language | 10,047 | 45,028 | 26,082 | 46,674 | 76,046 | 59,485 |
| total | 198,940 | 170,500 | 299,155 | 179,142 | 849,383 | 280,287 |

(The api total holds 12 unclassified bytes.) Main at `a36726c93c` reads the client 198,987, the
peer 323,098 and the api 850,626, their doors 39,391, 48,678 and 180,165: the integration branch
moves the peer case alone, by the commits that made W1, W2 and W6 capabilities, and almost none
of its doors.

### 1.2 The layers between a door and L3

By source file, every area:

| crate | layer | client | peer | api |
|---|---|---:|---:|---:|
| `wz-capi-pico` | L4, the doors | 35,664 | 44,470 | 117,072 |
| `wz-capi-port` | the port | 1,732 | 1,746 | 13,867 |
| `wz-capi-coop` | the cooperative engine | 26,114 | 44,655 | 130,741 |
| `wz-session-core` | L3 and L2 | 72,253 | 100,675 | 275,731 |
| `wz-capi-core` | the tokio engine | 0 | 0 | 0 |

The port's files, client / peer / api: `lib.rs` 1,196 / 1,213 / 4,087 (the sinks' calls and drops,
the key's wire form), `held_key.rs` 276 / 276 / 372, `peers.rs` 100 / 100 / 233, `lodge.rs`
65 / 61 / 3,783 (in api the advanced plane's kept keys and values), `refusal.rs` 55 / 56 / 115, and
`os.rs`, `sync.rs` and `engine.rs` 40 / 40 / 611; in api alone `cancellation.rs` 1,548, `query.rs`
1,500, `told.rs` 1,187, `group.rs` 390 and `face_rows.rs` 41.

The engine's half of the port, by body: the cooperative engine's implementations of
`SessionEngine`, `KeyHolds` and `SessionKeys` are 16 bodies and 10,609 B in client, 17 and 11,061
in peer, 53 and 40,660 in api (in client `declare_write_filter` 2,197, `undeclare_subscriber` 1,721,
`declare_subscriber_on_wire` 1,522 and the declaration `acquire_keyexpr` makes, 1,284, lead; in api
`get_on_wire` 4,618 and the held operation of `declare_write_filter` 3,241). They are where the
port's vocabulary is read back into L3's, around the L3 work each does.

`wz-capi-core` is linked by none of the three. It is the tokio engine that the `engine-tokio` leg of
the pico ABI and the zenoh-c ABI (`wz-capi-c`) run on, and it implements the same port
(`crates/wz-capi-core/src/engine_port.rs` @ `impl SessionEngine for SharedSession {`); in those
builds it holds the session's facts once more (its face registry and its record of the
declarations). Phase P5 of `docs/c-abi-engine-and-memory.md` removes its place under the C
libraries. Nothing below counts it as a cost of the release library.

Most of the doors area's excess (+20,357 in client, +28,882 in peer, +118,931 in api) is not a
second holder: `base-doors.md` reads the client's as the same work counted in the doors where
zenoh-pico counts it in its sessions and collections (the open, the config, the bytes, the
encodings, the object families: about 33.7 KB of zenoh-pico functions outside its doors area). The
second holders this lane removes are those of section 2.

## 2. How many times each fact is held

### 2.1 Object places

| | fact | holders today | n | zenoh-pico | n |
|---|---|---|---:|---|---:|
| A1 | the engine a session's handle reaches | `PicoSessionHandle::drive` (`CoopDrive`, the count every door reads through `engine_held`); `PicoSessionHandle::pico` (`PicoSession::engine`, a second count, lent to the declaring doors); `SessionTail::arena` (the count of the handle's place, which outlives the handle) | 3 | the session's count the handle is | 1 |
| A2 | the session's role (with `advanced`, its clock and its time too) | `PicoSessionExt::mode` and `PicoSession::mode` (and `hlc`, `time`) | 2 | `zn->_mode` | 1 |
| A3 | the engine an entity's object reaches | its place's lender (`object_slot::Lender::engine`, written by the take); and for a publisher, a querier, a matching listener, a token and a queryable a count in the object (`WriteFilter::shared`, `MatchingListenerState::shared`, `TokenState::shared`, `QueryableState::engine`) | 2; 1 for a subscriber since F1 | the entity's weak session (`vendor/zenoh-pico/src/net/primitives.c` @ `subscriber->_zn = _z_session_rc_clone_as_weak(zn);`) | 1 |
| A4 | which row of L3 an entity is | the door's id (`DeclaredSubscriber::id`; the write filter's `FilterId`, a `u64` the engine finds its filter by) beside L3's handle (`Declared::handle`, generation-checked); an undeclaration walks the tables comparing ids (`arch-l3-rows.md` H2) | 2 | the entity id, by which the session's list is searched | 1 |
| A5 | a publisher's QoS and its plain way | the door's `PublisherQos` (`PlainPublisher::declared`) and the write filter row's plain way (`keep_write_filter_plain`; `arch-engine-own.md` O4) | 2 | the publisher's fields (`vendor/zenoh-pico/src/net/primitives.c` @ `publisher->_congestion_control = congestion_control;`) | 1 |
| A6 | a pending get | the door's `GetPlace` (the closure, the reply gate and its key, the cancellation fan, the legs' count), L3's `SessionTables::pending_gets`, each face's `FaceTables::gets` (`arch-l3-rows.md` H7) | 3 | the pending query (`vendor/zenoh-pico/src/net/primitives.c` @ `_z_pending_query_t *pq = _z_unsafe_register_pending_query(zn);`) | 1 |
| A7 | an entity's callback | the L3 row's record (`SubscriberRow` of `crates/wz-capi-coop/src/engine.rs`: its anchor, its sink, its timestamp choice, its latch) | 1 | `_z_subscription_t`'s callback | 1 |

What the extra holders cost is paid per entity and per open, never per message: a retain and a
release with its last-holder test per count (A1, A3), a walk by id per undeclaration (A4), a second
store of the QoS (A5), two more tables written per get (A6). The bodies that carry them, body view,
client / peer / api:

| body | client | peer | api | holds |
|---|---:|---:|---:|---|
| `z_open` (with `PicoSessionHandle::new` inlined in client and peer) | 2,903 | 3,415 | 6,711 | A1, A2 among the open's work |
| `PicoSessionHandle::new`, the drop glue of `PicoSessionExt` and of `PicoSession` | inlined | inlined | 994, 564, 162 | A1, A2 |
| `WriteFilter`'s drop | 410 | 410 | 568 | A3 (with the listeners and the filter) |
| the engine's `undeclare_subscriber` | 1,721 | 1,843 | 2,489, 683, 139 | A4's walk among the undeclaration's work |
| the engine's `keep_write_filter_plain` | 571 | 564 | 730 | A5's second store |
| `GetMoved::take` and `adopt` | | | 947 | A6's door half |

The places themselves (`object_slot`, owner view 1,078, 1,261 and 3,490) have one holder each, the
lender.

### 2.2 Key copies

The text of a key lies once, in the session's key arena: a door reads the caller's key where it
lies, and an entity's object lends the record's text (`KeyView`). What is held more than once is the
naming of the declaration a key goes on the wire under, and the hold of it.

| layer | the types that name "the declaration a key is named by" |
|---|---|
| L3 | `KeyexprHandle` (the row), `KeyexprRef { id, row }`, `KeyexprCount` (its holders), an entity row's `EntityKey<Key>` (the text in the arena and the declarations the row holds) |
| port | `KeyHold { mapping_id, row, head }`; `WireKey { mapping_id, suffix, keeps, own, row }`; `KeyView { start, len, own }` with `OwnKey { row, mapping, prefix_len, count }`; `KeyAnchor`; `SessionKeys` and `HeldKey` (`held_key.rs`) |
| engine | `lent_key` (an entity row's key read back into a `KeyView`); `key_form(..).owning(keyexpr_by_id(..))` (a declaration the door named by its id alone, searched for) |
| L4 | `keyexpr::EntityKey` (the door's hold for the length of a declaration), `DeclaredKeyexpr` (`z_declare_keyexpr`'s object), `RecordKey` (what a loan of a record's key names), `WireDeclaration`, `KeyText` (a get's gate); and the C loan `z_loaned_keyexpr_t` |

One fact, L3's `KeyexprRef` and its count, is described again by five port types and five door
types, of which only the C loan is the ABI's own (zenoh-pico's layout). zenoh-pico has one type for
it, `_z_declared_keyexpr_t`: a key and its declaration's count.

The hold of a subscriber's own key, in one declaring call today:

1. the door takes a hold (`EntityKey::non_wild_prefix` calls `acquire_keyexpr`: a take of the
   session and L3's `declare_keyexpr_where`);
2. it names that declaration to the engine by its id alone (`subscriber_wire`,
   `WireKey::with_own(ExprId)`);
3. under a second take the engine searches L3 for the id (`keyexpr_by_id`) and the record takes a
   hold of its own (`KeyForm::owning` in `declare_subscriber_on_wire`);
4. the door gives its hold back (`drop(key)`, `release_keyexpr`, a third take).

Three takes of the session and two holds for the one that stays. zenoh-pico declares the key into
the subscription it registers, once (`vendor/zenoh-pico/src/net/primitives.c` @
`_Z_CLEAN_RETURN_IF_ERR(_z_declared_keyexpr_declare_non_wild_prefix(zn, &s._key, keyexpr),`). The
publisher, the querier, the queryable, the token and the liveliness subscriber take the same steps
(`FilteredKey::declare_at`: `EntityKey::whole`, `declare_write_filter`, `drop(key)`).

| bodies, body view | client | peer | api |
|---|---:|---:|---:|
| the translations: `EntityKey::up_to` 310, `lent_key` 273, `wire_key_of` 238, `WireDeclaration::held` 182, `WireKey::names_in` 148 (inlined into its callers in api), `EntityKey`'s drop 88 | 1,239 | 1,239 | 1,091 |
| the engine's implementation of the port's key arena (`SessionKeys::key`) | 636 | 636 | 637 |
| the engine's `retain_keyexpr` and `release_keyexpr` (the second hold and the given-back one) | 376 | 381 | 528 |
| the port's `held_key.rs` and `lodge.rs` (by source file) | 341 | 337 | 4,155 |

The rest of `wz_capi_pico::keyexpr` (owner view 5,190 in client, 7,597 in api) is the ABI's key API
(`z_keyexpr_*`: canonization, relations, concatenation), which zenoh-pico's doors and key
expressions do too: work, not a copy.

### 2.3 Option structures

| operation | the C options (the ABI's) | the door | the session core | the engine's row | zenoh-pico |
|---|---|---|---|---|---|
| a session's put or delete | `z_put_options_t`, `z_delete_options_t` | `PutCarried` (four moved or lent fields), `QosLevels` (five), `PutHeld` | `PublishOptions` (thirteen fields, written whole by `put_options`) | read by `publish_on_wire_all` | the struct copied once, its fields `_z_write`'s arguments (`vendor/zenoh-pico/src/api/api.c` @ `ret = _z_write(_Z_RC_IN_VAL(zs), keyexpr, payload_bytes, encoding, Z_SAMPLE_KIND_PUT, opt.congestion_control,`) |
| a publisher | `z_publisher_options_t` | `PublisherQos { encoding, levels }`, kept | `PlainPutParams` (five fields) and a `KeyexprRef` | the write filter's plain way, kept | the publisher's own fields, kept once |
| a publisher's put with options | `z_publisher_put_options_t` | `PutCarried`, `PublisherQos::apply` | `PublishOptions` | `publish_filtered` | `_z_write`'s arguments |
| a subscriber | `z_subscriber_options_t` | a `Locality`, and a `RetractionKey` the role decides | | the row's origin | the subscription's `_allowed_origin` |
| a get | `z_get_options_t`, `z_querier_options_t` | `GetMoved`, `GetHeld`, `GetAsk` with `GetShape`, `PicoQueryQos` and `PicoQueryValueMeta` | `QueryOptionsOf` (fourteen fields) | the pending get, each face's leg | `_z_query`'s arguments, then the pending query's fields (`vendor/zenoh-pico/src/api/api.c` @ `ret = _z_query(zs, _z_optional_id_make_none(), keyexpr, parameters, parameters_len, opt.target,`) |

A put's options are read into three forms where zenoh-pico's are two, a get's into six. They are
values on the call's stack, each read once, so they cost bytes (each form written whole, which is
why `put_options` is out of line), not a second holder of a fact, and the put keeps its form
(`docs/win-budget/size.md` 3.2.1 keeps the put out of any request). The one second holder is A5,
which `arch-engine-own.md` E4 removes ("`PlainWay.params` is the only copy and the door's publisher
state keeps the filter id"); F6 below makes the door's fold the one reader of a declaration's C
options.

| bodies, body view | client | peer | api |
|---|---:|---:|---:|
| `PutCarried::fold` | 540 | 540 | 600 |
| `PublishOptions::plain_put_params` | 241 | 241 | inlined |
| `PublisherQos::apply`, `QosLevels::apply` and `stated`, `put_options` | 368 | 368 | 382 |
| the engine's `keep_write_filter_plain` (A5) | 571 | 564 | 730 |
| `GetMoved::take` and `adopt` | | | 947 |

### 2.4 Marshal copies

The receive of a sample today:

1. L3 reads the Push where it lies into a `SampleRef`, the session's view, and pins the rows its key
   reaches (`SessionTables::pin_subscribers`);
2. for each row, `hand_row_by_row` calls the record's sink, a
   `SubscriberSink::Plain(PlainCallback<SampleMarshal>)`: an indirect call of the door's marshal
   (`marshal_sample`), through the function pointer every row keeps;
3. the marshal builds the ABI's view on the callback's stack (`SampleMarshal::lent`: zenoh-pico's
   layout up to its `payload`, the payload's borrowed view, the `SampleRef`'s address and the key's
   loan, nothing copied; `crates/wz-capi-pico/src/pubsub.rs` @
   `const PICO_SAMPLE_PAYLOAD_OFFSET: usize = 6 * core::mem::size_of::<*const c_void>();`);
4. an indirect call of the C function.

Two views and two indirect calls. The second view is the ABI's: a program reads
`sample->payload` as a field (upstream's `z_pong.c` does), and the view lives for the call, holding
and copying nothing, so it is no second holder. The second indirect call is the port's form, a
function pointer where the build has one marshal (step F7). zenoh-pico fills one `_z_sample_t` from
what it decoded and calls once (`vendor/zenoh-pico/src/session/subscription.c` @
`_z_sample_steal_data(&sample, &sub_infos.ke, payload, timestamp, encoding, sample_kind, qos, attachment,`).

Queries and replies (api): L3 hands the port's sinks trait objects (`&dyn QueryView`,
`&dyn ReplyView`; `crates/wz-capi-pico/src/get.rs` @
`pub(crate) fn fire_reply(closure: &CReplyClosure, gate: &ReplyGate, view: &dyn ReplyView) {`), and
the doors' marshals (`QueryMarshal`, `ReplyMarshal`) read the parts back through the traits'
methods. Thirteen types implement the three view traits in api, in 157 out-of-line bodies:
`SampleView` over four types (`SampleRef`, `Sample` and the advanced plane's recovered and cached
samples), `QueryView` over four (three of L3's and `QueryMarshal`), `ReplyView` over five (the lent,
the held, the inbound and the borrowed reply, and the one that hides its timestamp). zenoh-pico
hands its callbacks the query and the reply as structs, one view each.

| bodies, body view | client | peer | api |
|---|---:|---:|---:|
| `marshal_sample` and the `SampleMarshal` views it writes on demand | 673 | 673 | 879 |
| the view traits' methods: `SampleView`, `QueryView`, `ReplyView` (157 bodies) | 0 | 0 | 1,410 + 675 + 1,847 = 3,932 |
| the query's and the reply's marshals (`QueryMarshal` 14 bodies, `QueryMarshal::reply` 2,520 of them) | 0 | 0 | 3,662 |
| the reply writer's nineteen `ReplyOut` methods (`feat-query.md` Q7) | 0 | 0 | 5,631 |
| kept copies: `clone_sample_marshal`; in api also `SampleParts::kept` 858, `ReplyMarshal::deep_copy` 533, `clone_query_marshal` 1,742 | 1,172 | 1,172 | 3,539 |

The kept copies are made because a program keeps the object; section 4 of the architecture keeps
them ("a copy only when the program keeps the object").

### 2.5 The count

| fact | holders today | zenoh-pico | after steps 4 and 5 | taken by |
|---|---|---|---|---|
| a session's engine (A1) | 3 | 1 | 2: the drive's, and the place's, which outlives the handle | F3 |
| a session's role (A2) | 2 | 1 | 1 | F3 |
| an entity's engine (A3) | 2 (1 for a subscriber) | 1 | 1, the place's | F1 (landed), F2 |
| which row an entity is (A4) | 2 | 1 | 1, the handle; the id a field of the row | F5, with `arch-l3-rows.md` D4 |
| a publisher's QoS (A5) | 2 | 1 | 1, the row's | `arch-engine-own.md` E4 |
| a pending get (A6) | 3 | 1 | 1, L3's, its legs rows of it | `arch-l3-rows.md` D8, F6 |
| the naming of a key's declaration | L3's, five port types, five door types | 1 | L3's, and the C loan | F4, F9, F10 |
| the holds of a declaring call | 2 holds, 3 takes | 1 hold | 1 hold, 1 take | F4, F6 |
| a put's options | 3 forms, for the call | 2 | as today: values for one call, not state | none |
| a sample's delivery | 2 views, 2 indirect calls | 1, 1 | 2 views (the C layout's is the ABI's), 1 indirect call | F7 |
| a query's or a reply's delivery | 2 views, through trait objects | 1 | 2 views, each one plain type | F8 |

## 3. The form after step 4

### 3.1 What step 4 leaves

Step 4 (`arch-l3-rows.md` section 4) leaves every row of its section 3 with one holder in L3, a row
named across every boundary by its handle, a declaration numbered and refused in L3's one order
(room, key, id), and the engine holding the lock, the faces (until step 6) and the callbacks'
records in L3's rows, reached by no wrapper of its own (its D7). Between a door and those rows there
is then only the port: its vocabulary (`WireKey`, `KeyHold`, `Declared`, `KeyView`, the sinks), the
engine's translation of it, and the door's descriptions of what L3 already holds. Step 5 takes
those out.

### 3.2 One door's call path

A subscriber's declaration today (one line a body, or a step inside one):

```
z_declare_subscriber                                          L4, export
  declare_subscriber_with                                     L4
    open_session_handle, outbound_keyexpr                     L4: a closed session, the key's gate
    Slot::take_entity, PlaceLender::claim_place               L4 -> engine: the place
    subscriber_sink                                           L4 -> port: PlainCallback<SampleMarshal>
    EntityKey::non_wild_prefix -> acquire_keyexpr             take 1: L3's declare_keyexpr_where
    subscriber_wire: wire_key_of, WireKey::with_own(ExprId)   L4 -> port: the key described again
    declare_subscriber_on_wire                                take 2
      next_entity_id                                          L3 (H1)
      key_form(..).owning(keyexpr_by_id(own))                 engine: the id searched for
      SubscriberRow::new(wire.into_anchor(), sink, expose)    engine: the record
      SessionTables::declare_subscriber                       L3: the row
      lent_key                                                engine -> port: KeyView
      announce                                                L3 -> L2
    drop(key) -> release_keyexpr                              take 3
    settle_subscriber, bind_subscriber, RecordKey::lent       L4: the loan
```

After steps 4 and 5:

```
z_declare_subscriber                                          L4, export
  declare_entity                                              L4: one body for every declaring door
    open_session_handle, outbound_keyexpr, the place          L4: each check once, as today
    DeclareRequest { Subscriber, key, declared_of(keyexpr),
                     origin, retraction, the closure's parts } a value on the stack, lending the key
    session.declare(request)                                  one take
      the key's declaration, the id, the row and its
      callback, the announce                                  L3: one body
    -> Declared { handle, key: KeyView }
  the handle and the key's loan written into the place        L4
```

One take of the session where there are three, one hold where there are two, and two vocabularies
(the C ABI's and L3's) where there are four. zenoh-pico's path is three bodies, the subscription
registered under its session's lock: `z_declare_subscriber`
(`vendor/zenoh-pico/src/api/api.c` @
`return _z_declare_subscriber(&sub->_val, zs, keyexpr, closure.call, closure.drop, closure.context,`),
`_z_declare_subscriber` and `_z_register_subscriber` (`vendor/zenoh-pico/src/net/primitives.c` @
`_z_subscription_rc_t sp_s = _z_register_subscription(_Z_RC_IN_VAL(zn), _Z_SUBSCRIBER_KIND_SUBSCRIBER, &s);`).

The put keeps its shape: one body, its options folded once where they lie, no request (the put and
the receive stay out of the request, `docs/win-budget/size.md` 3.2.1). What changes is how its key
is named (F10): L3's `KeyexprRef` and the rest's length, where the port's `WireKey` is made for each
put (`wire_key_of`).

The receive, after F7:

```
L3   pin_subscribers; for each row, on its latch:
       row.callback.call(&sample)                             the façade's type: a static call
         SampleMarshal::lent(&sample)                         the C layout's view, on the stack
         (call)(sample_ptr, context)                          the one indirect call: the C function
```

### 3.3 Views lent, both ways

- A door lends L3, for the call: the key's text where the caller holds it (as today: the key is
  read off the loan and judged by `outbound_keyexpr`), the payload where the moved bytes lie (as
  today), and the options folded once into L3's value on the door's stack. It moves into L3 what L3
  keeps: the C closure's parts, into the row.
- L3 lends a door: a declaration's row handle and its key as the row keeps it (`KeyView`, moved into
  L3 with `OwnKey`), valid until the row goes, which the door's loan of the key
  (`z_subscriber_keyexpr`, `z_publisher_keyexpr`) names; and for one call the sample
  (`&SampleRef`) and, after F8, the query and the reply, each as one plain view of its parts.
- A copy is made only where the program keeps the object (`z_sample_clone`, `z_query_clone`,
  `z_reply_clone`), into the process's or the session's pools.

Decision D3 of `docs/win-budget/ir-receive.md` ("the loaned sample handed to a subscriber callback
is the session's `SampleRef` behind the opaque C type") and the C layout's prefix are one form here:
`SampleMarshal` stays the opaque type's one form, built where the callback is called and read off
the `SampleRef` by its fields; L3 keeps no copy and the door keeps nothing past the call.

### 3.4 The callback's type

The engine's records hold the port's sinks, enums over the forms every ABI makes (`SubscriberSink`,
`MatchingSink`, `LivelinessSink`, `QueryableSink`, `ReplyCallback`). S-SINK (`a3cc16ef5f`,
`shared-sinks`) compiles only the plain form into a C library, but the plain form still keeps its
marshal as a function pointer and erases the C function's type (`CCall`). L3's rows are generic over
their callback already (`crates/wz-session-core/src/session_tables.rs` @
`pub struct SubscriberRow<Key, Cb> {`). Step 5 finishes it the way principle P5 of the architecture
says: the cooperative engine is generic over the ABI's set of callback types (one per kind: a
sample's, a query's, a reply's, a matching status's, a liveliness sample's), instantiated once by
the façade's `Engine` alias, so the pico library's row holds the C closure's parts and calls its
marshal as a function item; the port's sinks are the set of the tokio engine and of the Rust ABIs.
Principle P11 holds as it does: the latch is L3's (`arch-l3-rows.md` D6), the callback the façade's.

### 3.5 The port trait in the release and the test builds

"The port trait leaves the release build" has three senses, which land at three times.

(a) **No dynamic dispatch between a door and the engine.** True today in the cooperative build:
`crates/wz-capi-pico/src/session.rs` @
`pub(crate) type Engine = wz_capi_coop::CoopEngine<PicoLinks, SessionClockOf>;`, held by
`session::static_dispatch_tests::a_build_of_one_engine_reaches_it_as_its_own_type`. Every call is resolved when the
build is made, a method no door calls is not linked, and the explain reports hold no table of
`SessionEngine`, `KeyHolds` or `Tickers`.

(b) **No port vocabulary on the cooperative path.** What F4 to F10 do, and where the bytes are
(sections 2.2 to 2.4 and 4).

(c) **No trait in the pico library's crate graph.** Only after phase P5 of
`docs/c-abi-engine-and-memory.md` ("The tokio engine path of the C libraries is deleted"). Until
then `engine-tokio` builds the same doors over
`pub(crate) type Engine = dyn wz_capi_port::SessionEngine;`, and its legs run the pico crate's tests
on it (`scripts/run-ci.sh` @
`The tokio leg is removed in phase P5, with the tokio engine's`,
and Layer C1co's `engine-tokio` legs). The advanced plane (`wz-ext-pubsub`) is shared with the Rust
ABIs and stays generic over the engine it is hosted on
(`crates/wz-ext-pubsub/src/advanced_subscriber/host.rs` @
`pub struct EngineSubscriber<E: EngineHolder = Arc<dyn SessionEngine>> {`), instantiated once with
the cooperative engine's hold: principle P5's form, a generic parameter and no object.

In the release build (a) holds now, (b) is the gain (section 4), and (c) moves no byte, since the
trait is a set of statically resolved methods there; what (c) removes is the rule that every change
of the door path compiles against two engines.

In the test builds, until phase P5, each change of the vocabulary (F4, F5, F7 to F10) is made in
the same commit on the port's every implementor: `CoopEngine` (`crates/wz-capi-coop/src/engine.rs` @
`impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> SessionEngine for CoopEngine<L, C> {`),
`SharedSession` (`crates/wz-capi-core/src/engine_port.rs`), the router node
(`crates/wz-capi-core/src/drive/router_node/engine.rs` @ `impl SessionEngine for RouterState {`)
and the advanced host's test double (`crates/wz-ext-pubsub/src/advanced_subscriber/host/tests.rs` @
`impl SessionEngine for Script {`). Both engines read L3's types already (`engine_port.rs` names
`wz_session_core::session_tables::KeyexprHandle`), so the new vocabulary is L3's on both; where only
the cooperative engine can answer a form (F5's handle), the trait gets an associated type each
engine sets, never a `cfg` fork of the doors. The tokio leg (the second leg of Layer C1pc) is the
first a change of the vocabulary turns red, and it is part of each step's verification until phase
P5. F11 removes (c) with phase P5, and the tokio legs with it.

### 3.6 Order with step 4

| `arch-l3-rows.md` step | what it gives step 5 | the step of this lane that waits for it |
|---|---|---|
| D1 (landed on its branch), D2: H1 | the id minted by L3 and read off the row | none |
| D3: H3 | a retraction named from the row it removes (`Undeclared` in `session_tables.rs`) | F4, which writes the same file's `KeyForm` |
| D4: H2 | the undeclaration by handle, and its tests | F5: one step, that lane's tests and this lane's files (the port's `Declared`, the door's `DeclaredSubscriber`) |
| D5: H4 | `KeyAnchor` of no size where no ABI keeps one | F9, the same seam |
| D6: H5 | one latched record over the sink type | F7 |
| D7: H6, with step 6d | the registry the session core's: L3's tables reached with no wrapper of the engine's | F10 |
| D8: H7, H8 | a get's legs rows of its pending get; a held query a row of the queries' plane | F6 for the get and the querier, F8 |
| D9, D10 | | none |

Beside those: T-DECL's declaration (S1 of `docs/win-budget/size.md`, the engine body F6's request
lands on) before F6; `feat-query.md` Q7 (the reply writer's one method, the family F8 changes)
before F8; `arch-engine-own.md` E4 (A5) beside F6; phase P5 of `docs/c-abi-engine-and-memory.md`
before F11. F2 and F3 wait on nothing, F9 only on D5 or lands with it.

## 4. Steps

Each step lands on its own; compiles alone in every feature set its crates'
`package.metadata.wz-docs` names, the tokio leg included until phase P5; changes nothing a program
can see; and is read on the three cases' areas and on the bodies its row names, and reverted when
they do not move as its row expects. "Receive Ir" is the count of instructions a message of
`docs/win-budget/ir-receive.md` (about 3,073 in the lane notes' reading, 3,078 in
`docs/win-budget/size.md` section 8), which no step raises. Bytes are the case's total, an estimate;
a minus is a fall.

| step | holds once | change | files | lands | turns red if it is wrong | client | peer | api | receive Ir |
|---|---|---|---|---|---|---:|---:|---:|---|
| F1 (landed, `89d7916c9b`) | A3, the subscriber's | the subscriber's state holds no count of the engine and reaches it through its place's lender (`object_slot::lent_engine`, `pubsub::subscriber_engine`); the tokio engine's state keeps its own, its places being its pools' | `wz-capi-pico/src/object_slot.rs`, `pubsub.rs`, `session.rs` | landed | `pubsub::tests::a_subscriber_reaches_its_engine_through_its_places_one_count` | in section 1's readings | in them | in them | 0 |
| F2 | A3, the rest | the write filter (a publisher's, a querier's), the matching listener, the token, the queryable and the liveliness subscriber reach the engine through their place's lender. The filter names no engine: its owner hands it the engine its place reaches on each call and gives the filter back with it in its own release, as an object that keeps a `KeyHold` gives it back (`KeyHold::release(session)`), so the plain publishers an advanced publisher keeps in its place need no reach of their own. The tokio engine's states keep their count, as F1's does | `write_filter.rs`, `pubsub.rs`, `querier.rs`, `matching.rs`, `liveliness.rs`, `query.rs`, `advanced_plane.rs` of `wz-capi-pico` | alone: the doors' crate, both engine legs | an F1-shaped test per kind (the take adds one count, the fill none, the release gives the one back); `pubsub::tests::a_publishers_lent_key_is_the_records_and_a_copy_holds_its_declaration`, `matching::tests::a_listeners_place_stands_while_its_filter_holds_it`, `query::tests::a_queryables_place_goes_back_when_its_row_lets_go_of_the_closure` unchanged | -60 to -150 (a publisher and a listener: a retain at the declaration, a release and its last-holder test, `WriteFilter`'s drop 410) | -60 to -150 | -200 to -450 (six kinds and the advanced publisher's filters) | 0; a put reads the engine through the lender at a fixed offset from the publisher's state, one load, as `WriteFilter::shared` is one now |
| F3 | A1, A2 | `PicoSession` is lent from the handle (the drive's engine and `&PicoSessionExt`) and not stored in it; the advanced plane, which keeps one on a task, keeps an owned copy where it keeps it | `write_filter.rs`, `session.rs`, `session_ext.rs`, the declaring doors, `advanced_plane.rs` | alone | `write_filter::tests::a_door_borrows_the_view_its_session_was_opened_with` (rewritten: the view is the handle's own fields), `session::session_place_tests::the_engine_held_for_a_call_is_the_one_its_entities_keep` | -40 to -100 (the second count's clone at the open and its drop at the close) | -40 to -100 | -150 to -350 (`PicoSessionHandle::new` 994 and `PicoSession`'s drop glue 162, with the clock's and the time's clones) | 0 |
| F4 | the holds of a declaring call (2.2) | the record adopts the door's hold: the door's `KeyHold` is handed on (`WireKey::with_own` names the declaration by its `KeyexprRef`, row and all), and the engine's record takes it by value, with no search by id, no second hold and no release on the way that succeeds; a refusal hands the hold back with the sink | `wz-capi-pico` (`keyexpr.rs`, `pubsub.rs`, `write_filter.rs`, `query.rs`, `liveliness.rs`), `wz-capi-port/src/lib.rs`, `wz-capi-coop/src/engine.rs` (the declaring methods), `wz-session-core/src/session_tables.rs` (`KeyForm`), `wz-capi-core/src/engine_port.rs` | after `arch-l3-rows.md` D3 and T-DECL's change of `Declaring`, which write `session_tables.rs` | `keyexpr::arena_key_tests::an_entity_key_keeps_no_text_and_holds_only_while_the_door_does` (rewritten: the hold is handed on, not given back), `keyexpr::tests::a_declaration_lives_as_long_as_its_last_holder`, `pubsub::tests::a_subscribers_lent_key_is_the_sessions_record_and_a_copy_holds_its_declaration`; a new test: a declaration takes the session twice, not three times (`Takes::core`), and leaves its key's count at one | -150 to -300 (`EntityKey`'s drop 88 and its release; the search in `declare_subscriber_on_wire` and `declare_write_filter`; `release_keyexpr` 115) | -150 to -300 | -400 to -800 (seven declaring kinds) | 0; a declaration two takes of the lock, not three |
| F5 | A4 | an entity is named across the boundary by its row's handle (principle P10): the port's `Declared` answers L3's handle, an associated type of the port's trait that the tokio engine sets to its id until phase P5; the door's object keeps it, and an undeclaration names the row (`SessionTables::undeclare_subscriber(handle)` is there already); the entity id is read off the row where the wire or `z_subscriber_id` names it | `wz-capi-port` (`lib.rs`, `engine.rs`), `wz-capi-pico` (`pubsub.rs`, `write_filter.rs`, `query.rs`, `liveliness.rs`, `matching.rs`), `wz-capi-coop/src/engine.rs` (the undeclarations), `wz-capi-core/src/engine_port.rs` | one step with `arch-l3-rows.md` D4: that lane's tests, this lane's files | D4's tests (an undeclaration by a handle of an earlier generation removes nothing; one of a liveliness subscriber reaches its own table); `pubsub::tests::both_subscriber_doors_take_the_closure_and_refuse_alike` | -150 to -300 (the walk of two tables by id in `undeclare_subscriber`, 1,721; D4's estimate) | -150 to -300 | -400 to -900 (subscribers, liveliness subscribers, queryables, tokens, write filters) | 0 |
| F6 | the declaration's composition (`docs/win-budget/size.md` 3.2.1) | one declaring request: each declaring door reads its C arguments into one `DeclareRequest` (the kind, the key the gate admitted, the caller's declaration, the options' fold, the closure's parts, the place, the door its refusal is answered at) and makes one call, in which L3 declares the key, mints the id, writes the row with its callback and announces it under one take | the declaring doors, `refusal.rs`, the engine's declaring methods | on T-DECL's engine body (S1), after F4 and F5 | one take a declaration (`Takes::core`); `entity_tables`'s order of refusal (room, key, id); the doors' refusal tests (the subscriber's above, the queryable's and the token's twins); the Layer C1co legs at their exact counts | net -900 to -1,200 (doors -1,600, sessions +700; size.md 3.2.1) | as client | net -1,500 to -3,000 (twelve declaring bodies of 9,087 B in the doors against zenoh-pico's of about 220 each) | 0; a declaration one take of the lock |
| F7 | a sample's second indirect call (2.4) | the row's callback is the façade's type: the cooperative engine is generic over the ABI's set of callback types (section 3.4), whose pico set holds the C closure's parts and calls its marshal as a function item; the port's sinks are the set of the tokio engine and of the Rust ABIs | `wz-capi-coop/src/engine.rs` (`SubscriberRow`, the queryable's and the liveliness subscriber's records, `MatchingCall`), `wz-capi-port/src/lib.rs` (the sinks as one set), `wz-capi-pico` (`session.rs`'s `Engine`, `pubsub.rs`, `query.rs`, `liveliness.rs`, `matching.rs`, `get.rs`) | after `arch-l3-rows.md` D5 and D6 | `pubsub::tests::a_subscriber_rows_callback_calls_the_c_closure_it_holds_and_drops_it_once` and its queryable, liveliness and listener twins, `pubsub::tests::a_marshal_told_to_hide_the_timestamp_hands_none`, `wz-capi-coop`'s `closure_drops`; a size assertion: a callback record one pointer smaller | 0 to -300; one pointer less a callback row in the region | 0 to -300 | -300 to -800 (five sink kinds) | lower: one indirect call fewer a delivery (an estimate: 2 to 8 instructions a message for one subscriber) |
| F8 | a query's and a reply's views (2.4) | L3 hands a query and a reply each as one plain view of its parts, as `SampleRef` is a sample's, which each source (a lent, a held, an inbound reply; the advanced plane's recovered and cached samples into `SampleRef`) projects into; the doors' marshals read its fields, as `SampleMarshal` reads `SampleRef`'s; the view traits stay where the tokio engine and the Rust ABIs call them | `wz-session-core` (`query_sink.rs`, `reply_sink.rs`, the reply's sources), `wz-capi-coop/src/engine/queries.rs`, `replies.rs`, `wz-capi-pico` (`query.rs`, `get.rs`), `wz-ext-pubsub`'s two sample views | after F7 and `feat-query.md` Q7 | `query::tests::bind_points_the_cached_views_at_this_marshals_own_fields`, `get::tests::a_reply_reads_its_payload_in_place_and_a_kept_one_copies_it`, `get::tests::a_reply_timestamp_is_read_from_its_parts`; the zenoh-pico API tests of the query plane on the release library | 0 (no query) | 0 | -1,500 to -3,000 (the 157 view bodies' 3,932 B, less one projection for each source) | 0 for a sample; a query's and a reply's delivery lower (no call for each part read) |
| F9 | `WireKey`'s forms | the forms only another ABI makes (`Suffix::Owned`, `Suffix::Lent`, `Keeps::Anchor` over `lodge::Kept`) behind a capability of the port that the ABIs which make them name, as S-SINK did for the sinks | `wz-capi-port` (`lib.rs`, `lodge.rs`, `Cargo.toml`), the manifests that name it (`wz-zenoh`, `wz-capi-core`, `wz-runtime-tokio`, `wz-capi-pico`'s `advanced`), the public-surface census row | after `arch-l3-rows.md` D5, or with it | `keyexpr::arena_key_tests::a_wire_key_holds_no_declaration`, `keyexpr::tests::a_wire_key_names_the_rest_of_its_key_and_takes_no_memory`; a size assertion of `WireKey` in a build without the capability; the C1h matrix compiling the port without it | -150 to -250 (`names_in` with one arm, the rows' drops with one form, `lodge` 65) | -150 to -250 | 0 to -100 (`advanced` keeps the anchors) | 0 or lower |
| F10 | the naming of a key's declaration (2.2) | the port's vocabulary leaves the cooperative door path: a key on the wire is L3's `KeyexprRef` and the rest's length; a declaration answers L3's handle and a `KeyView` moved into L3 with `OwnKey`; a refusal is L3's, mapped to the C codes by the façade's one table (principle P10); `lent_key`, `wire_key_of`, `WireDeclaration::held`, `RecordKey` and the door's key holds over the port go | `wz-capi-port`, `wz-capi-pico` (`keyexpr.rs`, `write_filter.rs`, `pubsub.rs`, `query.rs`, `get.rs`), `wz-capi-coop/src/engine.rs`, `wz-session-core/src/session_tables.rs`, `wz-capi-core/src/engine_port.rs` | after F4 to F9, `arch-l3-rows.md` D7 and step 6d (`arch-l0-driver.md`) | every key test of `keyexpr.rs` (each loan names its row, a copy holds the declaration past the original); `wz-capi-coop`'s `shared_key_ids` | -300 to -600 (`lent_key` 273, `wire_key_of` 238, `WireDeclaration::held` 182, the port's shape of `SessionKeys::key`, the `Declared` and `KeyView` glue) | -300 to -600 | -800 to -1,600 (with the query plane's port vocabulary: the port's `query.rs` 1,500 and `cancellation.rs` 1,548 in part) | 0 or lower: a put names its key in one form |
| F11 | the trait itself (3.5, c) | with phase P5: `Engine` is the cooperative engine alone, the doors call its own methods, and `SessionEngine` leaves `wz-capi-pico`'s graph; the advanced plane keeps its generic bound | `wz-capi-pico` (`session.rs` and every `engine-tokio` arm, `Cargo.toml`), `scripts/run-ci.sh` (C1pc's tokio leg, C1co's `engine-tokio` legs) | with phase P5 of `docs/c-abi-engine-and-memory.md` | `session::static_dispatch_tests::a_build_of_one_engine_reaches_it_as_its_own_type`, whose comparison with the trait object goes with the trait | 0 (the calls are static already) | 0 | 0 | 0 |

Sum of F2 to F10, estimates: client -1,750 to -3,200 (0.9 to 1.6 % of 198,940), peer the same
(the same doors and declarations), api -5,750 to -11,500 (0.7 to 1.4 % of 849,383). Step 5 by
itself is a small part of each case's excess over zenoh-pico (28,440, 120,013 and 569,096): it takes
the second holders out of the doors' path, and the doors keep the ABI's own work (section 1.2). Its
value is the form section 5 relies on: a feature's door is then a reading of C arguments into one
call of L3, and its row is one row.

### 4.1 F1, landed

`object_slot::lent_engine` reads the engine where the take wrote the lender, `LENDER_AT` bytes past
the object, through the pointer the place was filled at. `SubscriberState` holds the engine only
with `engine-tokio`; `pubsub::subscriber_engine` answers either, and the undeclaration, the record's
naming of the session (`bind_subscriber`) and `z_subscriber_id` (`subscriber_at`) read it there.
The liveliness subscriber shares the state and the change. Held by
`pubsub::tests::a_subscriber_reaches_its_engine_through_its_places_one_count` (the take adds one
count, the fill none, the engine reached is the session's, the release gives the one count back);
`pubsub::tests::a_subscribers_place_goes_back_with_its_owner_while_its_row_holds_the_closure` and
`pubsub::tests::a_subscribers_lent_key_is_the_sessions_record_and_a_copy_holds_its_declaration`
hold the release and the record's key, which names the lender's engine.

## 5. A feature's cost after steps 4 and 5

### 5.1 The claim, and what the per-feature steps say of it

The structural reading of the architecture (its section 1) is that wz keeps a feature's tables and
their handling in each of four layers (the session core's tables, the cooperative engine's
registry, the port, the doors' copies) where zenoh-pico keeps them once, so that a feature adds its
code once a layer; the remedy is one owner for each fact, not a diet for each feature. The
per-feature steps read that against bytes: they say how much of a feature's excess lies in those
layers, and so how much steps 4 and 5 can take. The rows below are `peer-proportion.md`'s and
`feat-query.md`'s (same ledger, same zenoh-pico); the column for steps 4 and 5 is this lane's
estimate, made from the bodies each row names.

### 5.2 `peer`

The `peer` step proper (the scout step's 33,472 apart) is 90,861 B against zenoh-pico's 3,792, 24.0
times (`peer-proportion.md` sections 1 and 2, on its tree):

| group | B | layer | what takes it | steps 4 and 5 (estimate) |
|---|---:|---|---|---:|
| G1 faces: the read, the turn, the supervisor, the task table | 19,889 | the engine (`engine::direct` 8,248) and L0 (`runtime_coop::faces` 6,077, the executor) | step 6 (6b, 6c), `peer-proportion.md` F1 (landed), F5, W6 | 0 |
| G2 the open's plan and the faces' pools | 20,406 | the engine's arena and registry, the session core's pools | the storage axis (on-use, `heap-native.md` N3c), `peer-proportion.md` F3; the registry's share is `arch-l3-rows.md` D7 | -300 to -800 (D7) |
| G3 the accepting cookie | 6,181 | L2 | W1, a switch | 0 |
| G4 the admission of crossing links | 1,478 | the engine | W2 | 0 |
| G5 the accepting handshake and its machine | 8,998 | L2 | `peer-proportion.md` F4; counting (zenoh-pico's client build compiles its acceptor) | 0 |
| G6 the listener and the links | 9,747 | L0, the doors' open (`capi_pico::session` 950) | lane T-LINK | 0 |
| G7 the codec runtime | 6,081 | L1 | W1's share, SCE | 0 |
| G8 what a new face is told | 4,114 | L3 (`session_tables`, `key_arena`, `wireexpr_resolve`) and the engine's replay 797 | the replay is L3's (D7, step 6d) | -200 to -500 |
| G9 the receive of each face | 2,158 | L2 | work | 0 |
| G10 the engine, other | 5,352 | the engine (`next_peer` 773, `fan_out_in` 545, the callers of the held operations) | W6, `peer-proportion.md` F2; `next_peer`'s cursor over the port (`peers.rs` 100) is this lane's | -200 to -500 (F10's reading of L3's face rows) |
| G11 language | 6,465 | | falls with the bodies it is inlined in | 0 |

Steps 4 and 5 take about 700 to 1,800 B of the 90,861, 1 to 2 %: the four layers' copies are not
where `peer`'s cost is. It is in each face being a session of its own, the acceptor and the open's
plan, which are L2, L0 and the storage axis (step 6, the switches, `peer-proportion.md`'s form
steps; its section 6 reaches about 56,800 B, 15 times, and names what is left). On the integration
branch read in section 1, where W1, W2 and W6 became capabilities of the pico preset (the peer case
reads 23,943 B under main's), the peer case less the client case is 100,215 B against 8,642; with
the scout step's 33,472 apart, about 66,700 against 3,792, 17.6 times (an estimate: the scout step
was read on the earlier tree).

### 5.3 `query`

The `query` step is +85,690 B against zenoh-pico's +8,704 by the ledger, 9.8 times; by body,
+77,971 over zenoh-pico's (`feat-query.md` section 2.1):

| row | wz less zenoh-pico | layer | steps 4 and 5 take (estimate) | the rest is |
|---|---:|---|---:|---|
| Q-a the get's doors and the reply object | +12,643 | L4 and the port: `issue_get` reads the options, resolves the key and fans out over the faces in one body; the port's cancellation fan; `ReplyMarshal` | -4,000 to -7,000 (F6 for the get: the fan-out L3's, the door a reading of its arguments; F8; F10) | the reply object's doors (`z_reply_clone` and its twins, 1,204), the C arguments' reading |
| Q-b the querier and its matching status | +8,211 | L4 (`z_declare_querier` 1,376, `free_querier` 1,593, `FilteredKey::declare_at` 988) and L3's table of the peers' queryables (2,961) | -1,000 to -2,000 (F2, F4, F5, F6) | gates wider than the role (`feat-query.md` Q6) |
| Q-c the pending gets and the delivery of their replies | +13,647 | the engine (the legs, the reply registry) and L3 (`lent_reply`): two delivery forms of one reply | -2,000 to -3,500 (D8: one holder of a pending get, one delivery form) | O1 (`query-face-legs`, about 6,200), consolidation's ring |
| Q-d to Q-g the Request's and the Response's codecs, a group's reply stage | +25,966 | L1, L2 | 0 | `feat-query.md` Q3 to Q6, SCE |
| Q-h the cancellation without `unstable-api` | +1,590 | the port and L4 | 0 | a gate (Q6) |
| Q-i the engine's own growth | +12,117 | the engine (`deliver`'s reply arm 3,526, the registry's `new`, `add_face` and `declares` 2,504, `face_turn`, `close`) | -3,000 to -6,000 (D7, D8; the rows are unread, so the estimate is from their names) | step 6 (`face_turn`, `close`) |

Steps 4 and 5 take about 10,000 to 18,500 B (about 14,000 at the middle; step 4 about 5,000 to
9,500, step 5 about 5,000 to 9,000): the `query` step after them is about 71,700 against 8,704, 8.2
times. The four layers hold about two fifths of this step's excess by body (Q-a 12,643, the door's
part of Q-b 3,957, Q-c's second delivery form, `lent_reply` 2,887, and Q-i 12,117: about 31,600 of
77,971), and steps 4 and 5 take somewhat under half of that; what they leave of it is the ABI's own
reading of a get and the engine's face form, which is step 6's.

### 5.4 `queryable`

The `queryable` step is +61,827 B against +9,787, 6.3 times; by body +52,324 over zenoh-pico's
(`feat-query.md` section 2.2):

| row | wz less zenoh-pico | layer | steps 4 and 5 take (estimate) | the rest is |
|---|---:|---|---:|---|
| R-a the Response's encoder | +15,069 | L1, L2: three writers of one reply, each in a counting and a writing copy | 0 | Q3, Q4 |
| R-b the reply doors | +12,723 | L4 (`QueryMarshal::reply` 2,444, the doors), L3 (`ReplyOut`'s nineteen methods 5,631, the reply stage) | -800 to -1,500 (F8: the marshal reads one view's fields) | Q7 (one reply method, -3,000 to -4,500, `feat-query.md`'s) |
| R-c the queryable doors and the query object | +5,064 | L4 (`declare_queryable_in` 2,299, `queryable_sink_at` 1,255) | -1,300 to -2,400 (F6, F7) | the kept query (`clone_query_marshal` 1,742) |
| R-d the queryables' tables and their declarations | +8,476 | L3 and the engine (the session tables 2,951, the slot observer 1,775, the held operations 3,210, the group's announce 3,307) | -1,000 to -2,000 (step 4: one holder of a queryable's record) | the held operations (W6, `peer-proportion.md` F2), the group's path (L2) |
| R-e a peer's query handed to the queryables, and its Final | +12,107 | L3 and the engine: the walk generic over the kind of face | -300 to -600 (F8: the lent query one plain view) | `feat-query.md` Q1, Q2, O2 |
| R-f the rest | -1,115 | | | |

Steps 4 and 5 take about 3,400 to 6,500 B (about 5,000): the `queryable` step after them is about
56,800 against 9,787, 5.8 times. Its excess is mostly the Response's writers and the reply methods,
which are the codec's and the reply writer's forms.

### 5.5 What a feature costs after steps 4 and 5

| feature | the step today, wz against zenoh-pico | steps 4 and 5 take (estimate) | after them | where the rest is |
|---|---|---:|---|---|
| `peer` | 90,861 against 3,792 (24.0) | 700 to 1,800 | about 89,600 (23.6) | each face a session of its own, the acceptor, the open's plan: step 6, the switches W1, W2, W6, the storage axis (`peer-proportion.md` section 6: about 56,800, 15.0) |
| `query` | 85,690 against 8,704 (9.8) | 10,000 to 18,500 | about 71,700 (8.2) | the codecs (Q-d to Q-g, 25,966 over zenoh-pico's), O1, the wide gates (Q6), the face form (step 6) |
| `queryable` | 61,827 against 9,787 (6.3) | 3,400 to 6,500 | about 56,800 (5.8) | the Response's writers (R-a, 15,069), the reply methods (Q7), the walk over the kinds of face (Q1, Q2) |

So the claim holds for the asking end of the query plane in part, and hardly for `peer`. Once
steps 4 and 5 are done a feature's door is a reading of its C arguments into one call of L3 and its
state is one row, as zenoh-pico's is; what a feature still costs over zenoh-pico is then: its
messages' codecs (the generated readers and writers in two forms, and a counting and a writing copy
of each: `feat-query.md` Q3 to Q5, SCE), the behaviours zenoh-pico lacks (each a switch, off in the
preset), the gates that compile more than the role needs (Q6), and, for a feature that adds faces,
the face's form (step 6). The holders left in the door's path after step 5 are the ABI's own: the
reading of the C arguments, the C layout's views, and the copies a program keeps.

## 6. What the main session reads

- This commit is the note alone: nothing is built or run for it.
- For each step as it lands: the three cases' areas and the bodies its row names, on
  `scripts/lib/size_ledger_gate.py --explain`; the receive's instructions a message on the window
  harness (arm W of the perf matrix), which no step raises; the tests its row names, on the
  cooperative host build and, until phase P5, on the tokio leg of Layer C1pc; clippy of each crate
  the step touches, alone, for the host, tokio and zephyr feature sets of its
  `package.metadata.wz-docs`.
