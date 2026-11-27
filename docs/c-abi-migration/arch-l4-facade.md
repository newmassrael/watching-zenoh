# Migration lane arch-l4-facade: the thin facade (L4), section 5 step 5

Step 5 of `docs/c-abi-architecture.md` section 5: the doors call L3 directly, marshals lend views,
and the port's trait objects leave the release build. This note reads what of that step has
landed, names every layer that still holds a fact another layer holds, and orders the steps that
remove them. It is one of five lane notes written side by side (`arch-l3-rows` step 4,
`arch-l0-driver` step 6, `arch-engine-own`, `arch-win-ext`); the files each step touches are
named so the lanes do not write the same file at once.

## 1. The reading

The size ledger's explain report of `pico-client-coop-nostd` dated 2026-11-27 (schema 5): wz
214,351 bytes against zenoh-pico's 170,500; doors 41,867 against 19,034. The port crate
(`wz-capi-port`) places 2,155 bytes, all of them in the doors area:

| port file | bytes | what they are |
|---|---:|---|
| `lib.rs` | 1,594 | the sinks' call and drop (`hand_row_by_row` 222, `deliver` 102, the subscriber's declaration 204, the rows' drops 72), the key's wire form (`WireKey::names_in` 148, `wire_key_of` 59, `lent_key` 86, `WireDeclaration::held` 55) |
| `held_key.rs` | 276 | the key arena's hold, share and release in the key doors |
| `peers.rs` | 112 | `enumerate_peers`'s cursor |
| `lodge.rs` | 75 | the drop of what a key keeps alive (`Kept`), in seven bodies |
| `refusal.rs`, `os.rs`, `sync.rs`, `engine.rs` | 98 | the refusal's code, the lock |

What of step 5 is already true in this build:

- **No `dyn SessionEngine`.** Outside `engine-tokio` the doors name the engine as its own type
  (`crates/wz-capi-pico/src/session.rs` @ `pub(crate) type Engine = wz_capi_coop::CoopEngine<PicoLinks, SessionClockOf>;`),
  so every method is a call resolved when the build is made and a method no door calls is not
  linked. The report has no vtable of `SessionEngine`, `SessionDrive`, `KeyHolds` or `Tickers`.
- **The key arena and the place lender are reached as the engine's own type**
  (`crates/wz-capi-pico/src/keyexpr.rs` @ `fn key_arena(engine: &crate::session::EngineHold) -> Option<&Engine> {`,
  `crates/wz-capi-pico/src/object_slot.rs` @ `let place = wz_capi_port::PlaceLender::claim_place(`),
  not through the trait's `Option<&dyn SessionKeys>` and `Option<&dyn PlaceLender>`, which only
  the tokio engine's build calls.
- **A lent place carries its lender from the take** (`docs/win-budget/size.md` section 7), the put
  and delete doors are jumps to one body, and an engine refusal is answered from one body.

What is still dynamic at the boundary, and whose it is:

- The shared closure forms of the sinks (`SubscriberSink::Shared`, `MatchingSink::Shared`): the
  report still carries `Arc<dyn Fn(&dyn SampleView)>::drop_slow` and `Arc<dyn Fn(bool)>::drop_slow`.
  Design S-SINK (`docs/win-budget/size.md` 3.1), in flight on the branch `s-sink`; not this lane's.
- The sample view between L3's delivery and the engine's rows (`SampleDelivery::deliver` takes
  `&dyn SampleView`; `RoundDelivery::deliver` reads it back into a `SampleRef`): the seventeen
  `<SampleRef as SampleView>` methods are out of line, about 600 bytes in sessions. It is the
  delivery lane step 4 removes (`arch-l3-rows`); the door's marshal already reads the session's
  own `SampleRef` by its fields (`SampleMarshal` of `wz-capi-port/src/lib.rs`).

## 2. The layers that still hold one fact twice

| | fact | holders | files and types |
|---|---|---|---|
| O1 | an entity's object keeps its session's engine standing and reaches it | the place's lender (one count, written by the take) and the object's own field (a second count) | `object_slot.rs` `Lender::engine`; beside it `pubsub.rs` `SubscriberState::shared`, `write_filter.rs` `WriteFilter::shared` (publisher, querier), `matching.rs` `MatchingListenerState::shared`, `liveliness.rs` `TokenState::shared`, the queryable's place in `query.rs` |
| O2 | the session handle reaches its engine and its role | `CoopDrive::engine`, `PicoSession::engine` (a second count, in `PicoSessionHandle::pico`), `SessionTail::arena` (the place's, which is a lifetime of its own and stays); the role in `PicoSessionExt::mode` and again in `PicoSession::mode` | `session.rs` `PicoSessionHandle`, `write_filter.rs` `PicoSession` |
| O3 | the declaration of an entity's own key, and the row it lies in | the door takes a hold (`EntityKey::taken` through `acquire_keyexpr`), names it to the engine by id alone (`WireKey::with_own(ExprId)`), the engine searches the declarations for that id (`KeyForm::owning(tables.keyexpr_by_id(..))`) and takes the record's own hold, and the door gives its hold back: three entries for one hold, and a search for a row the door already had | `keyexpr.rs` `EntityKey`, `pubsub.rs` `subscriber_wire`, `wz-capi-port/src/lib.rs` `WireKey::own`, `wz-capi-coop/src/engine.rs` `declare_subscriber_on_wire` (and the queryable's, the token's and the liveliness subscriber's) |
| O4 | how a key goes on the wire | the port's `WireKey` (id, rest, row, own, what it keeps) beside L3's declared key expressions; its forms only another ABI makes (`Suffix::Owned`, `Suffix::Lent`, `Keeps::Anchor` over `lodge::Kept`, whose shared form is an `Arc<dyn Send + Sync>`) are compiled into every row's drop and `names_in` of the C library | `wz-capi-port/src/lib.rs` `WireKey`, `KeyAnchor`; `wz-capi-port/src/lodge.rs` `Kept` |
| O5 | the declaring work | the doors compose the key's declaration, the slot, the options and the record (`z_declare_publisher` 1,890, `declare_subscriber_with` 1,395, `z_declare_keyexpr` 903, `declare_on_filter` 653) where zenoh-pico's doors (about 220 bytes each) call one function of the session layer | `docs/win-budget/size.md` 3.2.1, `docs/win-budget/text.md` D1 |
| O6 | the engine's operations as the doors name them | `SessionEngine` (about seventy methods) is the coop engine's interface to the doors: free of cost as dispatch, but its arguments are the port's vocabulary (`WireKey` by value, `SubscriberSink`, `FilterId` as `u64`), which the engine translates back into L3's (`KeyexprRef`, `KeyForm`, row handles) | `wz-capi-port/src/engine.rs`, `wz-capi-coop/src/engine.rs` |

The closed state is also read twice (the door's `open_session_handle` and the engine's `live`),
which is kept: the door's read is zenoh-pico's order, a closed session consuming the closure the
call moved before any slot is taken.

## 3. The target

- An entity's object lies in a place of its session's arena and reaches the engine through that
  place's one count (O1); the handle reaches it through the drive's one count and borrows the
  role where the handle keeps it (O2).
- A declaring door reads its arguments into one request and makes one call; the engine declares
  the key, records the entity and announces it under one entry of the session, the record taking
  the one hold of the key's declaration (O3, O5).
- A key on the wire is L3's `KeyexprRef` and the rest's length; forms only another ABI makes are
  behind the capability that makes them (O4).
- In the coop build the doors name L3 through the engine's own type; `SessionEngine` remains for
  the tokio engine, as a parameter instantiated once where a build selects it (O6, P5).

## 4. Steps

Each step lands on its own, keeps every test green, and is judged on `pico-client-coop-nostd`'s
total and doors row and on the receive's instructions a message (about 3,073; no step adds a call
on the receive or the put).

| step | what | files | expected bytes | receive Ir |
|---|---|---|---|---|
| F1 | the subscriber's state holds no count of the engine: it reaches it through its place's lender (`object_slot::lent_engine`, `pubsub::subscriber_engine`); the tokio engine's state keeps its own, as its places are its pools' | `wz-capi-pico/src/object_slot.rs`, `pubsub.rs`, `session.rs` (`z_subscriber_id`) | doors -30 to -60 (a retain at the declaration, a release and its last-holder test at the undeclaration); each subscriber's place 8 bytes smaller | 0: no receive reads the state |
| F2 | the same for the publisher and the querier (the write filter reaches the engine through its owner's place, the filter's offset in the owner a constant of the build), the matching listener, the token and the queryable | `write_filter.rs`, `pubsub.rs`, `querier.rs`, `matching.rs`, `liveliness.rs`, `query.rs` | doors -80 to -150 | 0; the put reads the engine at a fixed offset from the publisher's state, one load as now |
| F3 | `PicoSession` borrowed from the handle (`drive.engine_hold()`, `ext.mode`) and not stored in it; the advanced plane keeps an owned form | `write_filter.rs`, `session.rs`, the declaring doors | doors -40 to -80 | 0 |
| F4 | the record adopts the door's hold: `WireKey::with_own` names the declaration's row (`KeyexprRef`), the record takes the door's `KeyHold` by value, no search by id, no second hold and no release | `keyexpr.rs`, `pubsub.rs`, `wz-capi-port/src/lib.rs`, `wz-capi-coop/src/engine.rs` declare methods, `wz-session-core/src/session_tables.rs` (`KeyForm`) | -150 to -300, doors and sessions | 0; declarations cheaper |
| F5 | `WireKey`'s forms only another ABI makes behind a port capability the ABIs that make them name, as S-SINK did for the sinks | `wz-capi-port`, the Cargo manifests that name it, the public-surface census row | -150 to -250 | 0 or lower (a drop with one form) |
| F6 | one declaring request (`DeclareRequest`, size.md 3.2.1): the door reads its C arguments, the engine does the declaration's work in one body | the declaring doors, the engine's declare methods | doors -1,600, sessions +700, net -900 to -1,200 | 0 |
| F7 | the port's vocabulary leaves the coop build: the façade names L3's handles and key forms, the translations (`names_in`, `lent_key`, `wire_key_of`) go | `wz-capi-port`, the doors, the engine | -300 to -600 after F4 to F6 | 0 or lower |

Order and coupling: F1 to F3 touch the doors' crate alone and land first. F4 writes
`session_tables.rs`, which `arch-l3-rows` (step 4) and the T-DECL lane own, so it lands after
them or as their step. F5 waits for `s-sink` (the same manifest section and census row). F6 lands
on the engine method step 4 makes. F7 is what is left when step 4 and step 6 have moved the
engine's tables into L3.

## 5. The step landed with this note: F1

`object_slot::lent_engine` reads the engine where the take wrote the lender, `LENDER_AT` bytes
past the object, through the pointer the place was filled at. `SubscriberState` holds the engine
only with `engine-tokio`; `pubsub::subscriber_engine` answers either, and the undeclaration, the
record's naming of the session (`bind_subscriber`) and `z_subscriber_id` (`subscriber_at`) read
it there. The liveliness subscriber shares the state and the change.

Held by `pubsub::tests::a_subscriber_reaches_its_engine_through_its_places_one_count`: the take
adds one count, the fill none, the engine reached is the session's, and the release gives the one
count back. The existing `a_subscribers_place_goes_back_with_its_owner_while_its_row_holds_the_closure`
and `a_subscribers_lent_key_is_the_sessions_record_and_a_copy_holds_its_declaration` hold the
release and the record's key, which now names the lender's engine.

## 6. What the main session reads

- The case's total and doors row, and the bodies `declare_subscriber_with`, `free_subscriber`
  (inlined into `z_undeclare_subscriber` and `z_subscriber_drop`) and
  `release_entity::<SubscriberState>`, on `scripts/lib/size_ledger_gate.py --explain`.
- The receive's instructions a message on the window harness, which F1 should not move.
- `cargo test -p wz-capi-pico --lib -- pubsub::tests::a_subscriber` on the coop host build
  (`peer` on), and the crate's clippy for the host, tokio and zephyr feature sets of its
  `package.metadata.wz-docs`.
