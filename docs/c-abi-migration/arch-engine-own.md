# Migration lane arch-engine-own: the engine's own code and the session core's send side

Status: design of the lane, with its first step (E1) landed beside it. It reads
`docs/c-abi-architecture.md` (principles P1 to P12, layers L0 to L4, sections 4 and 5),
`docs/c-abi-size-diet.md` (round 6, "the next list", item 2) and `docs/win-budget/size.md`
(sections 3.1.1, 6.1 and 8), and does not change them: four other lanes write beside it
(arch-l3-rows: section 5 step 4; arch-l4-facade: step 5; arch-l0-driver: step 6; arch-win-ext:
Windows). Nothing here was built or measured by this lane; every byte figure is either **read**
from the size ledger's explain document named below or an **estimate** from the code.

## 1. The reading

The explain document of `pico-client-coop-nostd` dated 2026-11-27 (schema 5, the report a
verification worktree left under `size-ledger/explain-pico-client-coop-nostd.json`): wz 214,351
against zenoh-pico's 170,500 (1.26), the bytes of each function placed at the source lines its
line table names. The cooperative engine's crate places 29,499 of them by line
(`wz_capi_coop::engine` 15,577, `engine::direct` 5,906, `arena` 2,938, the rest under 1,000
each); the "75 KB" of the diet note is the older reading by symbol, in which every body inlined
into an engine method was the engine's.

### 1.1 The engine's bodies by the layer whose fact they hold

The largest bodies that carry `wz_capi_coop::engine` lines, each with its total over every area
(read), and the layer that owns the fact the body works on (section 5 step 6's table):

| body | bytes | fact | layer | lane |
|------|------:|------|-------|------|
| `lend_session` | 4,522 + 767 | the region's tables lent at the open | L0 (6a) | arch-l0-driver, T-OPEN |
| `CoopEngine::assemble` | 3,662 + 484 | the `Core` built and placed | L0 (6a) | arch-l0-driver, T-OPEN |
| `CoopEngine::link_turn`, `drive_link`, `place_link_session`, `open_links`, `DirectSlot::dial_row` | about 9,000 | a face's link lifecycle | L2 (6b) | arch-l0-driver |
| `declare_subscriber_on_wire`, `undeclare_subscriber`, `deliver::{closure}`, `hand_row_by_row` | about 5,100 | the entity rows and their delivery | L3 (4) | arch-l3-rows |
| `declare_write_filter`, `undeclare_write_filter`, `read_matching`, matching listeners | about 4,100 | the write filter's rows | L3 (4, S-FILTER) | arch-l3-rows, T-DECL |
| every `<CoopEngine as SessionEngine>::*` shape | (the trait's calls) | the port between doors and engine | L4 (5) | arch-l4-facade |
| **the put**: `put_through_filter` 2,223, `send_on_links` 1,490, `publish_to_link` 1,252, `live_to_publish` 583, `publish_filtered` 358, `publish_everywhere` 138 | **6,044** | how a publication is written, named and sent | L3 routing, L2 writer | **this lane** |
| `keep_write_filter_plain` 649, `PublishOptions::plain_put_params` 241 | 890 | the publisher's plain way | L3 row | **this lane** |
| `SessionDrive::close` 1,017, the engine's `Drop` | about 1,300 | what the session lets go of at its end | L3 rows, L0 tasks | **this lane** |
| `session_zid` 532, `engine_of` 655 (its fact copies) | (part) | facts the engine copies out of `Core` | L0 | **this lane** (E6) |

On the session core's send side (transport area, read): `write_n_msg` 1,649,
`dispatch_network_message_in::<false>` 1,611, `write_push` 1,615 (codec), the fragment chain
1,302, `send_control_lent` 376. `docs/win-budget/size.md` 6.1 reads these as one writer each
whose bytes are behaviours the parity contract states (the Control barrier, the probe, the expiry
run, the chain's credit); they are not layers held twice, and this lane leaves them.

The put is the lane's: about 6.9 KB of engine bodies (844 bytes of them the session core's send
entries inlined into `send_on_links`), against zenoh-pico's `_z_write` and `_z_publisher_put_impl` (458) above the
same `_z_transport_tx_send_n_msg_inner` (1,261) that `dispatch_network_message_in` matches.

## 2. The layers held twice

Each row is one fact and the places that hold or decide it today, read from the code at
`origin/main` 6199fa0d40.

| id | fact | held or decided by | why it is twice |
|----|------|--------------------|-----------------|
| O1 | which form a Push is written in (from its publisher's head, as a plain Put, as a publication with its fields) | `wz-capi-coop` `LinkLeg::send_to` (`plain`, `head.filter(names)`), then `wz-session-core` `SessionLinkActions::send_plain_put_at` (`head.filter(names && qos)`); and two session-core entries for the one writer `lent_push::write_push` (`send_plain_put_at`, `send_publication_at`) | the engine (L3 routing) chose among three session-core calls, each inlined with its own copy of the dispatch's call, the express flush and the outcome; the head's check ran in both layers, and the head was written with its own QoS byte whatever the put carried |
| O2 | whether a write filter lets a put through | `put_through_filter_in` (`write_filter_row_open`, by row) and, for a put with options, `publish_filtered` -> `write_filter_holds_back` (`write_filter_open`, by handle) | the put with options takes the session twice: once for the filter's answer, once for the send |
| O3 | the body that sends a publisher's put | `put_through_filter` (a put with no options: `live_on_link`, the plan, the plain way) and `publish_to_link` (a put with options: `live_to_publish`, `leg_of`, which reads the same row for the same head) | two take-the-session bodies, two row lookups (`row_of` then `write_filters().get`) and two namings of the key (`named_at`) for one put |
| O4 | the publisher's plain way (its QoS, reliability, priority, express flag, its key's declaration, the Put's head) | the door's publisher state (`wz-capi-pico` `write_filter`), `WriteFilterRow::plain` (`PlainWay { params, key, head }`), the head's bytes, and each put's `PublishOptions` -> `PushMetadata` | the row keeps a copy of what the door keeps and re-derives at each put with options |
| O5 | what the session lets go of at its end | `SessionDrive::close` and `Drop for CoopEngine`, each with `end_links`, the pending gets' unregister loop and the round's let-go | one teardown written twice, the second for a session never closed |
| O6 | the session's zid and the queue facts a publish reads without the lock | `TransportState::wire_zid`, `CoopEngine::zid`, each link's `SessionInitParams`; `CoopEngine::{wait_before_drop_us, held_drop}` beside `Core::config.tx_queue` | copies made in `engine_of` so a reader takes no lock; the copy is right, the second holder is not |

Not in this lane: the face send state a dropped publish is handed off by (`sending_on`,
`held_drop`, `HandedTable`, `LinkRooms`) is section 5's 6c, arch-l0-driver's; the rows of the
write filter and its Interest are S-FILTER's (arch-l3-rows, T-DECL); the port trait the put is
reached through (`SessionEngine::publish_filtered`, `publish_on_wire_all`) is arch-l4-facade's.

## 3. Target form

One put, as zenoh-pico's `_z_write` is one function over its transmit path:

- **L2 decides the Push's form alone.** The link's session is handed the parts
  (`session_actions::PushParts`: kind, payload, metadata, the publisher's head if any) and
  writes them in the one form they call for, through one body and one encoder
  (`SessionLinkActions::send_push_at`). The engine names the key on the link and the face; it
  knows nothing of the wire's forms. (E1, landed.)
- **L3 holds the publisher's way once.** `WriteFilterRow` keeps the way (its send facts and its
  head) as the one owner; the door keeps the filter's id and reads the way back where a program
  asks for it; a put with options is folded over the way at the door (`PutCarried::fold`) and
  handed as parts, not re-derived into a `PlainPutParams` and a `PushMetadata` beside it.
- **One put body in the engine** (`put_on_links`): one take of the session with the droppable
  rule of `live_to_publish`, one row read giving the filter's answer, the way, the plan and the
  named key, one `LinkLeg`, one walk of the faces. The plan at the send epoch stays the row's.
- **One teardown** called by the close and by the drop.
- **Facts read without the lock written once** at the open into the engine's immutable part,
  which the transport and the links read; `Core` holds no second copy.

## 4. Steps

Each lands alone, with its tests, and is read on the case's total and on the bodies named.
"Put Ir" is the instructions of one put on the opprofile line (`docs/win-budget/ir-send-query.md`);
"receive Ir" is the receive's slope (about 3,073 a message), which no step here touches.

| step | change | bodies read | expected (estimate) | receive Ir | put Ir | tests that hold it |
|------|--------|-------------|--------------------:|-----------|--------|--------------------|
| E1 | the Push's form decided once, in L2: `PushParts` and `send_push_qos` / `try_send_push_qos`; `send_plain_put_at` and `send_publication_at` become one `send_push_at`; `send_put_with_head`, `send_publication_qos` and both `try_send_*` go | `send_on_links` (1,490, of which 844 session-core lines), the two encoder closures (331 and 63) | -300 to -600 | 0 (no receive code) | equal or lower: one form decision and one head check where there were two | `session_actions::bundle_tests::lent_frame_refusal::{a_put_written_from_its_head_is_the_frame_its_parts_make, a_head_of_another_qos_is_not_written, a_del_is_not_written_from_a_puts_head}`; `wz-capi-coop` `tests::plain_put` (the `planned` counts) and `tests::shared_key_ids::a_publishers_bare_put_is_planned_where_its_link_names_its_key_by_the_declaration` |
| E2 | a put with options asks its filter under the publish's own take: `publish_filtered` hands the filter id to `publish_to_link`, whose take reads the row's answer; `write_filter_holds_back` goes where nothing else calls it | `publish_filtered` 358, `write_filter_holds_back` | -150 to -300 | 0 | lower: one take of the session fewer per put with options | `tests::plain_put::a_plain_publish_of_a_publisher_is_written_from_its_plan`; a new test: a suppressed filter sends nothing for a put with options, counted by `takes.core` (one take) |
| E3 | one put body: `put_through_filter` and `publish_to_link` become `put_on_links`; `live_on_link` for a bare put is replaced by `live_to_publish`'s rule (a single-threaded build cannot tell them apart; a threaded one drops a droppable bare put on a held face as a publish already is) | `put_through_filter` 2,223, `publish_to_link` 1,252, `live_to_publish` 583 | -1,500 to -2,500 | 0 | equal: the planned path is kept as the row's | the `plain_put` and `shared_key_ids` tests above, the tests of a droppable publish on a held session (`takes.spins`); a new test that a bare droppable put on a held face is dropped and counted as a publish is |
| E4 | the publisher's way held once (O4): `keep_write_filter_plain` takes the door's folded way; `PlainWay.params` is the only copy and the door's publisher state keeps the filter id; a put with options is handed as parts over the way | `keep_write_filter_plain` 649, `plain_put_params` 241, `z_declare_publisher`'s `write_filter` lines, `publisher_write` 812 | -300 to -700 | 0 | equal | the `plain_put` tests; the doors' put tests (`pubsub::put_options_tests`) |
| E5 | one teardown (O5): the close's and the drop's shared part is one out-of-line body, the drop calling it only for a session never closed | `SessionDrive::close` 1,017, the engine's drop | -200 to -500 | 0 | 0 | the close tests that count `links_let_go` (once by the close, whatever calls it) |
| E6 | one owner of the zid and the queue facts (O6) | `engine_of` 655, `session_zid` 532 | -50 to -150 | 0 | 0 | the open's zid tests (a stated, a drawn and a derived zid) |

Together about -2.5 KB to -4.8 KB on the case, against the put's 6.9 KB over zenoh-pico's 1.7 KB.
E2 and E3 read the write filter's rows, which S-FILTER (arch-l3-rows) changes: E2 needs only the
row's answer (`write_filter_row_open`), E3 lands after S-FILTER's row form or rebases on it;
E4 touches `wz-capi-pico`'s publisher and `write_filter.rs`, which arch-l4-facade may also
write, and is taken after its door step.

## 5. E1 as landed

`crates/wz-session-core/src/session_actions.rs`:

- `PushParts<'a> { kind, value, meta, head }` (public): what a Push is written from. Its
  `form(key)` (private) is the one decision: a publication with its fields unless the kind is Put
  and the metadata is plain apart from its QoS; the publisher's head where the head names the key
  by its declaration alone and carries the Put's QoS byte (`push_qos(meta.qos)`); the plain Put
  otherwise. `takes_head(key)` answers the same, for a counter outside the crate. A build without
  `transport-tx-lend` writes no publication from its parts (`form` answers `None`), as before.
- `send_push_at`: the one body, with one encoder over the three writers (`PutHead::write`,
  `lent_push::write_plain_put`, `lent_push::write_publication`), one size hint, one dispatch, one
  express flush. Under `transport-stats` a publication is left to the owned send, and a plain
  Put is counted from its parts, as each was.
- `send_plain_put_qos` keeps its signature (the tokio engine's sends use it); `send_push_qos`
  and `try_send_push_qos` are the parts' entries; `send_put_with_head`,
  `try_send_plain_put_qos`, `send_publication_qos` and `try_send_publication_qos` had no
  caller left and went.

`crates/wz-capi-coop/src/engine.rs`: `LinkLeg::send_to` hands `PushParts` to one call (and to
`try_send_push_qos` where a face is probed); its test counter `planned` reads
`PushParts::takes_head`, the session core's own answer.

One behaviour moves with it: a plain Put handed a head whose QoS byte is not the put's is now
written from its parts with the put's QoS. Before, `send_put_with_head` sent the head's QoS
whatever the put carried, while the same put on a link that named its key otherwise went with
its own; a put now carries its own QoS on every link
(`a_head_of_another_qos_is_not_written`).

What the main session reads to land it: the case's total and `send_on_links` in the explain
document against the reading of section 1; the put at 8 B on the opprofile line, which may not
rise; the receive's slope, which does not move.
