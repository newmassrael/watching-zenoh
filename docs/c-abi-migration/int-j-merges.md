# Integration J: merge resolutions

Each section is one lane merged into integration J, with the files whose
conflicts needed a decision and why the result reads as it does. A merge that
applied cleanly is not listed. Nothing here was built; main verifies.

## Generated outputs

- conn-scout: `deploy/wz-config.toml` and
  `sources/features/wz-session-core.scxml` merged textually with the
  earlier lanes' edits. Main regenerates both (`wz_config --write`,
  `sce_feature_model --write`) rather than trusting the textual merge.

## l3-queryable (673db8c8f7) over peer-prop and feat-adv

The two lanes reshaped the same seam: peer-prop lends every table set by
walking its description (`places` lines and `RowCount`s), l3-queryable
moves the session's own tokens out of the observer and the staging of token
answers into the peer's tables, and names entities by their row. Both are
kept: the description walk is the lend, and it walks l3-queryable's layout.

- `crates/wz-session-core/src/slot_observer.rs`: the observer has no
  registry of tokens of its own (l3-queryable), so `ObserverRegionRows` lost
  its `LOCAL_TOKENS` parameter and keeps peer-prop's policy parameter; the
  observer's description is the three watcher pairs
  (`SLOT_OBSERVER_LINES`), lent by `lend_seqs` since no key line is left;
  `list_counts`, `counts` and `arena_bytes` take the watchers alone. The
  description test asserts no key line, and the count of tokens past the
  build's bound is now refused by the tables (`RegistryRows::local_tokens`).
- `crates/wz-session-core/src/bounded.rs`: `RowCount::LocalTokens` removed,
  as no line counts the observer's tokens any more.
- `crates/wz-session-core/src/declare/local_token.rs`: l3-queryable's
  removal of `LocalTokenRows` and the observer's `places` kept;
  `TokenAnswers::place` is generic over the laid-out policy so the peer's
  description names it for a region and a plan alike, and
  `TokenAnswers<Lent>::lend_rows` / `arena_bytes` go, the walk lending the
  staging. The staging tests take l3-queryable's `TokenAnswers::stage` with
  debt-repay's keys that every keyexpr dialect reads, and keep the
  table-order assertion.
- `crates/wz-session-core/src/peer_tables.rs`: peer-prop's description lend
  and `arena_bytes`; its token line is `TokenAnswers::place` counted by
  `RowCount::PendingDeclares`.
- `crates/wz-session-core/src/session_tables.rs`: peer-prop's lend by
  description; l3-queryable's `get_due` and `ended_gets` are set by
  `SessionTables::of`, which the rowless tables start from.
- `crates/wz-capi-coop/src/engine/registry.rs`, `registry/placed.rs`,
  `registry/described.rs`: peer-prop's registry walk with l3-queryable's
  `TableRows` in place of `ObserverRows`. The test that refused an open
  counting a token on the observer's line of no room now refuses one counting
  a subscription past the table's bound, the same walk refusal on a line that
  still exists.
- `crates/wz-capi-pico/src/{query,pubsub,liveliness,session,advanced_plane}.rs`:
  feat-adv's reach of an entity's engine through its place, with
  l3-queryable's `EntityRow` for what is retracted and `entity_id_of` for an
  identity; the advanced plane's token is an `EntityRow`.

## group-link-writer (8794590753)

- `crates/wz-session-core/src/session_actions.rs`: the lane moves
  `LentDeclaration` into `lent_control` as the one writer a link and a group
  send declarations with, which supersedes debt-repay's token-reply arm and
  `qos` in the session's own copy (`798f8720aa`); the lane's version is
  kept. Debt-repay's `lent_declaration_tests` is kept and reads the shared
  writer: `write_wire` (`WireWrite`) in place of the copy's `encode`.

## base-td (fcf3273d01)

- `crates/wz-capi-coop/src/engine.rs`, `engine/replay.rs`: the lane gives a
  link's actions and transmit handle the stack's sink type
  (`LinkActions<C, SinkOf<L>>`, `LinkTx<'_, C, SinkOf<L>>`, `Wire<C, D>`).
  The get and snapshot legs l3-queryable moved into `ask_get_legs` and
  `ask_snapshot_legs`, and the single-link publish path
  (`alone_run`, `send_leg_alone`), take the same types; the
  `wz_interest_answer` gates of the integration are kept.
- `crates/wz-session-core/src/session_actions.rs`,
  `crates/wz-session-core/src/transport_tx.rs`: group-link-writer moved the
  transmit walk into `transport_tx.rs`; the lane's change to that walk (a
  joined message is written where the open frame lies, through
  `OpenSlot::frame_mut`, and the slot is picked up only to be sent; a lease
  is written through `TxLease::frame_mut`, no longer a `TxBuf` itself) is
  applied there, line for line.
- `crates/wz-runtime-coop/src/ip_stack.rs`, `ip_link.rs`: the lane makes a
  stack's links one closed type (`IpLink`), with a variant for a `udp/`
  port's peer; peer-prop made a dialled socket and a port's peer one driver
  (`LinkSocket`, F6 of `peer-proportion.md`). Both are kept: in a build
  that listens on `udp/` the `Udp` variant is a driver over `LinkSocket`
  and a port's peer opens as that variant (`LinkSocket::Port`), so the
  enum has no `Peer` variant and the driver is one body. `IpLink` and
  `ClosedLink` forward `owes_write_if_free`, which an earlier lane added to
  `SessionDatagramLink`.

## heap-native (ce7e699b2c)

The lane states the tables' policy once, in the build script (`wz_lent`,
`wz_on_use`), and renames every item that differs by the policy from
`runtime-plan` to the policy's cfg; the config's plan keeps `runtime-plan`.

- `crates/wz-capi-coop` (`arena.rs`, `engine.rs`, `engine/registry.rs`,
  `registry/held.rs`, `registry/described.rs`, `registry/adding.rs`,
  `engine/state_places.rs`, `tests/arena.rs`, `tests/sim.rs`): the items
  the earlier lanes added under `runtime-plan` (peer-prop's description
  walk of the registry and the sets, the plan's parts read off it,
  l3-queryable's leg rows) take the policy's cfg the same way: the lent form
  `wz_lent`, "not the on-use form" `not(wz_on_use)`, the on-use form
  `wz_on_use`.
- `crates/wz-capi-coop/src/engine/registry/owed.rs`, `described.rs`: the
  lane holds the tokens owed by the faces that went in one type
  (`owed::Owed`); peer-prop lends that table through the registry's
  description. Both are kept: the lent form is described by
  `Owed::place` and starts rowless (`Owed::rowless`), so `Owed::lent`
  goes, and the on-use form is the lane's relation. `counted.rs` counts the
  application's tables with l3-queryable's `App::counted(keys, tables, ..)`.
- `crates/wz-runtime-coop` (`ip_stack.rs`, `ip_link.rs`,
  `unixpipe_link.rs`, `ws_link/links.rs`, `transport.rs`): the lane takes a
  link's cells and buffers through its kind's sources (`N::Cells`,
  `RxOf<N>`, `TxOf<N>`); base-td's closed link type and its in-place
  makers take them the same way, and the gate takes the cells as the lane
  states them. Both lanes' stack tests are kept.

## Fixes after main's build of c780b02348

- `crates/wz-session-core/src/declare/local_token.rs`: the l3-queryable
  resolution dropped the imports of `LocalTokenRegistry::lent` with
  peer-prop's region form. The lent form stays: l3-queryable's D9b
  (`arch-l3-rows.md`) moves the session's tokens into
  `RegistryTables::local_tokens`, lent by `RegistryRows::local_tokens`
  through `LentTables::lend` as the subscriber, queryable and liveliness
  subscriber tables are, and removes only the observer's field and the
  registry's region and counted forms. The imports (`Arena`, `LendRefused`,
  `Lent`, `KeySpace`, `LentKeys`) are restored as l3-queryable had them.
