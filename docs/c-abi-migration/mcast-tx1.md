# Structure lane mcast-tx1: one transmit path for a group and a link

Status: the reading of what a group sends with, beside what a link sends with and beside
zenoh-pico's one transmit path; the design that makes the group a destination of the links' writer;
its steps, each with the bytes it is expected to move on `pico-api-coop-nostd`; and steps T1 and
T2, which land beside this note. Nothing here was built or measured by this lane. Every figure is **read**
from the library the cost gate's run of 2026-11-27 kept for `pico-api-coop-nostd`
(`shipped/pico-api-coop-nostd/libwz_capi_pico.so` under the gate's target directory: `nm
--defined-only -S -C` for the bodies, `objdump -d` for who calls each body by its address), or is
an **estimate** from the code, and says which. It extends `feat-mcast.md` (rows D and E, steps F2,
F4 to F7) and changes none of it.

`pico-client-coop-nostd` compiles no group (its row forbids `MULTICAST`; its kept library holds no
symbol of `multicast_tx`, `multicast_reply_sink` or `group_drive`), so no step here moves its
bytes or its receive Ir, and none adds a call on any receive path. The gain of this lane is the api
twin's, and through it the Windows release's.

## 1. zenoh-pico: one transmit path

A message is serialized into the transport's buffer, fragmented when it does not fit, and written
with the link's send by one function, whatever the transport
(`vendor/zenoh-pico/src/transport/common/tx.c` @ `static z_result_t _z_transport_tx_send_n_msg_inner(`);
a batch is flushed by one function for a unicast and a multicast transport alike
(`vendor/zenoh-pico/src/transport/common/tx.c` @
`ret = _z_transport_tx_send_n_batch(&zn->_tp._transport._multicast._common, cong_ctrl, NULL);`).
A group adds no send code of its own (`feat-mcast.md` row E: 0 bytes).

## 2. wz: a second path beside the links' writer

A link's messages are written by the session's writer: each message by its lent writer straight
into the slot its link lends (`SessionLinkActions::dispatch_network_message_in`, 1,729 and 810
bytes for its two forms; `frame_encode::write_fragment` 617; `encode_frame_envelope` 232; the
declarations' one writer `dispatch_declare_lent::{closure#1}` 4,320). A group's messages go through a
pipeline of their own, all of it read from the api twin's library:

| part | what it is | bodies (read) |
|---|---|---:|
| owned-item entry | a reply handed as an owned item or record: `GroupTxStage as MulticastReplyEnqueue>::enqueue` 5,389 (the walk of every item kind's measure), `ItemBody::write_wire` 1,909 (every kind's owned writer), `MulticastTxReply::with_body`'s declaration closure 2,744, and the heap encoders nothing else reaches (`DeclareWire::write_source` over `DeclareIn<Heap>` 2,835 counting and 2,694 writing, `QueryWire` 1,172 and 1,042, `MsgPutWire` counting 1,470, `MsgDelWire` counting 459, `ReplyWire` 198, 282 and 268, `ResponseWire` envelopes 275 and 260, `WireexprWire` 144 and 109, `ExtEntryWire` 166), `build_declare_kexpr_reply` 388 | 21,804 |
| the group's own lent writers | `multicast_tx_token_reply`'s closure 2,561 (the link's token reply: 738), `enqueue_reply_parts` 393 and 428, the declarations' closures 147 each | about 3,800 |
| framer | `multicast_tx::push_frame` over the stage's queue and its closures, `MulticastBatch::flush_open`, the envelope over a staged body | 6,559 |
| stage | `push_deferred` 6,326, `take_front` 4,499, `StageQueue::wait_for_room` 1,815, `Lanes::queue` 1,445, `push_encoded_through` 882, `stage` 738, `admit_reply_body` 664, two `offer`s 1,056, `batch_flush` 531, and the rest | 19,458 |
| legs under the held faces | every `HeldOperation` body, of which `feat-mcast.md` F6 reads the group's leg at about 5,078 | 23,241 |
| the group's session (row D) | `Core::join_group` 18,325, `MulticastPump::step_reading` 11,739, `GroupPump::step` 5,538, `HeldSession::build` 3,974, `read_groups` 3,182, `end_links` 1,744, `step_groups` 1,698, `seat_group` 788, `MulticastSessionPlace::leave` 675 | 47,712 |

Who reaches the owned-item entry, by address: `enqueue` is called by the final of a query's replies
alone (`MulticastReplySink::send_response_final`, inlined into a held operation's answer, a
`CoopEngine` body and the group's `FaceRecords::owe_finals`); the declaration closure and the
counting `DeclareWire` copy by the group's declaration replies (`SlotObserverOf::drain_declare_replies`
over the group's sink, 3,347 where the links' instance is 1,266) and its keyexpr answers
(`engine::group::answer_asks`, 2,909). The pump's pull seam, which takes owned items too, is
`|| None` on the engine: the table of `ItemBody` is loaded by `enqueue` alone, that of the
declaration closure by the two bodies above alone, and no `multicast_tx_emit` body is linked.

## 3. The design: the group is a destination of the links' writer

The target is zenoh-pico's shape: one writer, and a group one more place it writes to. What stays
the group's own is what a group does that a link does not, and nothing else:

- its conduits (`MulticastTxConduits`), minted on as a link's `TxConduits` are, and the conduits
  as written, which its JOIN advertises (`GroupTxStage::on_wire`);
- the datagram a full socket refused and the order behind the beacon (`feat-mcast.md` D2);
- the reply quota (`MAX_MULTICAST_REPLIES`), which bounds what a member's asks stage.

Everything else is the links' writer's: the message writers (lent, counted by a run of the same
writer, `tx_buf::try_encoded_len`), the frame and fragment walk and its batch window, and the lent
slot. The seams, in the order they can be taken:

- **S1, one encoder form.** Every message the group sends is written from its parts by the writer a
  link uses for it; nothing of the group's is an owned item, so the owned-item entry and the heap
  encoders behind it leave the library. Steps T1 and T2.
- **S2, one frame walk.** The group's framer (`multicast_tx::push_frame` over `StageQueue`) and
  the link's (`dispatch_network_message_in`, `send_fragment`, the window of `TxConduits`) are the
  same walk: room, mint, envelope, fragments, drop marker. The link's walk already runs over a
  driver behind `dyn BoxedLinkDriver` in this library, so the group's stage presented as such a
  driver (its lane storage the slot it lends, its writer the send) takes the link's walk without a
  second copy of it. Step T3, designed with the line reading in hand: the link's walk must not gain
  a call on its own path for it.
- **S3, the stage keeps D2 alone.** Once the walk is the link's, the stage's re-entrant keep of a
  push made while the conduits are held (`push_deferred`, `Staged`) is the link's own
  serialization of its writer, and what is left is the held datagram, the order behind the beacon
  and the quota. Step T4.
- **S4, the group's leg out of line** (`feat-mcast.md` F6). Step T5.
- **S5 and S6, one shell and the open in place** (`feat-mcast.md` F4 and F5), the row D bodies
  above. Steps T6 and T7, after T3 and T4, since the group's face then holds a writer and no task.

## 4. Steps

Each step keeps every byte the group puts on the wire (its tests hold the lent form to the owned one,
or the new walk to the old, wire by wire) and moves nothing on `pico-client-coop-nostd`.

| step | change | bytes, expected (`pico-api-coop-nostd`) | basis | held by |
|---|---|---|---|---|
| **T1 (landed)** | every reply the group stages written from its parts by the links' writer of its kind: the declarations that answer a member's interest (final, subscriber, queryable, an aggregate's retraction, the session's keyexprs) as `multicast_tx::DeclarationReply`, the final of a query's replies from its two numbers; the stage's owned-item entry is reached by no path of the engine | -15,000 to -20,000 | read: 21,804 of bodies every caller of which is in the owned-item entry (section 2), and the group's drain and answer bodies above the links' (2,081 and part of 2,909); less, estimated, 2,000 to 4,000 for the one writer of the five reply kinds, the stage's two admits and the kind writers it outlines | `group_declarations_written_from_parts` and `push_tests` (the lent reply and final are the owned ones' bytes, framing, size and tally), `multicast_reply_sink::tests` (the sink hands parts; the default builds the builders' replies), `lent_control::tests` (the keyexpr answer is its builder's bytes), the stage's tests (framed as the owned reply at once and kept, the slot, the refusal) |
| **T2 (landed)** | the group's remaining writers of the all-kinds `Declare`: the token reply as a declaration of one kind (`DeclarationOf`), and the announcements, retractions and keyexpr declarations through the one reply writer of T1 rather than one `multicast_tx_declaration` instance each (section 6) | -1,500 to -3,000 | read: `multicast_tx_token_reply`'s closure 2,561 against the link's 738, and the eight instances of `multicast_tx_declaration` (`feat-mcast.md` row E, 1,202 together); estimate: the token reply's arm and the four instances left, 300 to 600 | the existing `group_declarations_written_from_parts` tests, unchanged, and `a_keyexpr_declared_to_the_group_is_its_builders_bytes`, `a_kind_without_its_plane_is_refused_before_it_is_written`; `lent_control::tests::a_token_reply_of_one_kind_is_the_borrowed_reply_of_the_responder` |
| T3 | the group's stage as a `BoxedLinkDriver` of a writer of its own, so its messages take the links' walk (S2) | -4,000 to -7,000 | read: the framer 6,559; estimate: the driver's lend and send over the lanes, 1,500 to 2,500 | the group's wire held to the link's for the same items; `push_tests` moved onto the driver |
| T4 | the stage keeps D2 alone (S3) | -10,000 to -15,000 | read: the stage 19,458; estimate: what D2 keeps, 3,000 to 6,000 | the stage's tests of a held datagram, the beacon's order and the quota |
| T5 | F6, the group's leg out of line | -3,000 to -4,500 | `feat-mcast.md` F6 | `direct::held_operation_tests` |
| T6 | F4, one shell for a group | -15,000 to -25,000 | `feat-mcast.md` F4; read today: the shell's bodies of row D other than the open, 29,387 | the engine's group tests |
| T7 | F5, the open in place | -5,000 to -12,000 | `feat-mcast.md` F5; read today: `Core::join_group` 18,325 | the engine's open tests with a group |

T1 is first because it is certain without a measurement: the owned-item entry has, by address, no
caller left once the replies are written from their parts, and the parts' writers are the links'
own (`lent_control`), held byte for byte to the owned builders by tests that existed before it. T2 is
the same seam's remainder. T3 and T4 are the large ones and are designed with
`size_ledger_gate.py --explain pico-api-coop-nostd` in hand; T6 and T7 are `feat-mcast.md`'s.

## 5. Step T1, as landed

- `multicast_tx::DeclarationReply` is an answer to a member's interest as the arguments of its writer.
  Its one writer (`impl WireWrite`) composes each kind with `lent_control` and writes it with
  `DeclareWire::encode_source`, the writers the link's lend-only session uses; it is not generic, so
  it is compiled once and its count (`encoded_size`) runs the same body. `DeclarationReply::owned`
  builds the owned `Declare` of the same bytes for a backing that queues owned items.
  `multicast_tx_declaration_reply` and `multicast_tx_response_final` hand either to the backing as a
  message lent for the call, framed and counted as the owned reply or item is.
  `lent_control::kexpr_reply_declaration` is the keyexpr answer of one kind it needed.
- `MulticastReplyEnqueue` gains `enqueue_declaration_reply` and `enqueue_response_final`, whose
  defaults are the owned forms the sink built before (so the tokio engine's backing and the MCU
  queues are unchanged), and `MulticastReplySink` hands each answer and each final to them.
  `GroupKeyexprAnswers::take_declarations` walks the owed keyexpr answers as parts;
  `take_answers` is that walk with the owned form, for the tokio engine. A declared id of zero, which
  no caller declares, is skipped where the owned builder would have panicked.
- `GroupTxStage` writes both from their parts into the lane or the staged storage
  (`admit_lent_reply`, which the token reply uses too), and the engine's `answer_asks` hands it the
  keyexpr answers as parts.
- Gates: the stage's declaration writer is compiled under `wz-session-mcu`'s `liveliness-token`, as
  its token reply is, and its final under that crate's `codec-response-final`, which
  `wz-capi-coop`'s `queryable` now forwards beside `codec-response`. A build that joins groups
  and answers interests without `liveliness-token` keeps the owned declaration replies; the api twin
  and the Windows release have it.

## 6. Step T2, as landed

- `multicast_tx::GroupDeclare` is every declaration a group sends, as the arguments of its writer:
  an answer to a member's interest (T1's `DeclarationReply`, one arm of it), the answer to a
  member's interest in tokens, an entity announced or retracted, and a keyexpr declared or
  undeclared. Its one writer (`impl WireWrite`) is the body T1's reply writer was, with the arms of
  the other kinds beside them; each arm writes a declaration of its one kind
  (`lent_control::DeclarationOf`), so the encoder of each kind is compiled once into it.
  `multicast_tx_declaration` takes this value and is generic over its caller's closure alone,
  where it was generic over the declaration's type too (one instance per kind and caller: three
  for the announcements, three for the retractions, two for the keyexprs);
  `multicast_tx_declaration_reply`, `multicast_tx_token_reply`, `multicast_tx_group_announcement`
  and `multicast_tx_group_retraction` keep their signatures and hand it their value, and the
  engine's `GroupFace::announce_keyexpr` and `retract_keyexpr` hand it theirs.
- The token reply is a declaration of one kind (`lent_control::token_reply_declaration`): the bytes
  of the token responder's borrowed reply (`declare::local_token::build_token_reply`), whose
  envelope carries no extension, in the type the token announcement is written in
  (`DeclarationOf<DeclToken>`), so the two share one encoder and the group's writer reaches the
  all-kinds `Declare` encoder from no reply.
- Refusals are as before: a keyexpr past the protocol's bound is `None` (`LengthOutOfRange` from
  the announcement and the retraction) with `f` not called; a kind with no declaration plane is
  `FeatureDisabled`, read after the retraction's key as before; the writer handed such a kind
  directly refuses it (`UndeclaredEnumValue`). `announce_keyexpr` holds a keyexpr for the members
  that ask only when its writer takes it, as before.
- Residue on the same seam, not this lane's: the link's token reply
  (`SessionLinkActions::send_declare_token_reply`, its lend-only and its no-allocator arms) still
  writes the all-kinds borrowed `Declare` (`build_token_reply(..).encode`). Written as
  `lent_control::token_reply_declaration`, no token reply of a lend-only library would reach the
  all-kinds encoder; whether that encoder then leaves the library is an `nm -C` reading. It is
  the link's writer (`session_actions.rs`), planned with that lane.

## 7. Verification (the main session's)

- `cargo test -p wz-session-core --lib --features
  session-multicast,codec-frame,alloc,codec-push,codec-declare,declare-final,declare-subscriber,declare-queryable,declare-undeclare,liveliness-token,codec-response,codec-response-final,transport-stats`
  for `lent_control::tests`, `multicast_tx::` (`group_declarations_written_from_parts`,
  `push_tests`) and `multicast_reply_sink::tests`; and again with `liveliness-token` alone of the
  declaration planes, and with `declare-subscriber` alone, for the gated arms.
- `cargo test -p wz-session-mcu --lib --features
  transport-multicast,codec-push,codec-response,codec-response-final,liveliness-token
  group_drive::stage`; and without `codec-response-final`, and without `liveliness-token`.
- `wz-capi-coop`'s group tests with `group,query,queryable,liveliness` (`tests::group`: the get
  answered by a member's queryable and its final, the write filter a member's answer opens, the
  keyexpr asks).
- Clippy of each of the three crates with those feature sets.
- `python3 scripts/lib/size_ledger_gate.py --measure pico-api-coop-nostd`: lower by T1's range; and
  `nm -C` of its library holds none of `GroupTxStage as ...MulticastReplyEnqueue>::enqueue`,
  `ItemBody`, `MulticastTxReply>::with_body`, `DeclareWire>::write_source<...DeclareIn<...Heap>`,
  `QueryWire>::write_source<...QueryIn<...Heap>`, `build_declare_kexpr_reply`.
- `pico-client-coop-nostd` unchanged to the byte, and the perf matrix's receive Ir of it (arm W)
  unchanged.
- T2: `cargo test -p wz-session-core --lib --features
  session-multicast,codec-frame,alloc,codec-push,codec-declare,declare-final,declare-subscriber,declare-queryable,declare-undeclare,liveliness-token,codec-response,codec-response-final,transport-stats
  group_declarations_written_from_parts`: 6 tests (5 that were, 1 new); the same with
  `declare-subscriber` alone of the declaration planes (no `declare-queryable`, no
  `liveliness-token`): 6 (`a_kind_without_its_plane_is_refused_before_it_is_written` in place of
  the token reply's); `lent_control::tests::a_token_reply_of_one_kind_is_the_borrowed_reply_of_the_responder`
  with the first set: 1. Build and clippy of `wz-session-core` with the first set, with
  `declare-subscriber` alone, and with `codec-declare` and none of the three planes;
  `wz-session-mcu`'s `group_drive::stage` and `wz-capi-coop`'s group tests as for T1, unchanged;
  clippy of `wz-capi-coop` with `group`.
- T2: `python3 scripts/lib/size_ledger_gate.py --measure pico-api-coop-nostd` lower by T2's range,
  `multicast_tx_token_reply` and every `multicast_tx_declaration::<...DeclarationOf...>` gone from
  `nm -C`, one `<GroupDeclare as WireWrite>::write_wire`; `pico-client-coop-nostd` unchanged to
  the byte.
