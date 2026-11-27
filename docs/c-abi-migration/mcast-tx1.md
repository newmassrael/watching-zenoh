# Structure lane mcast-tx1: one transmit path for a group and a link

Status: the reading of what a group sends with, beside what a link sends with and beside
zenoh-pico's one transmit path; the design that makes the group a destination of the links' writer;
its steps, each with the bytes it is expected to move on `pico-api-coop-nostd`; and steps T1 and
T2, which land beside this note. Steps T3 and T4 as first designed are not taken: the code does not
hold the premise S2 was designed on (section 7); section 9 designs the structure that makes it true
(one transmit component over one conduit set), and section 10 records the one writer of each control
message for a link and a group, which lands beside it. Nothing here was built or measured by this lane. Every figure is **read**
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
  same walk: room, mint, envelope, fragments, drop marker. The link's walk is a method of a unicast
  session's link actions over that session's own conduits, with the driver below it taking bytes
  already numbered (section 7), so a group does not take it by presenting its stage as a driver:
  one walk for both needs one conduit set for both. Step T3, designed with the line reading in
  hand: the link's walk must not gain a call on its own path for it.
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
| T3 (as first designed, not taken: section 7; designed again as T3a to T3c, section 9) | the group's stage as a `BoxedLinkDriver` of a writer of its own, so its messages take the links' walk (S2) | -4,000 to -7,000 | read: the framer 6,559; estimate: the driver's lend and send over the lanes, 1,500 to 2,500 | the group's wire held to the link's for the same items; `push_tests` moved onto the driver |
| T4 (with T3b, section 9.3) | the stage keeps D2 alone (S3) | -10,000 to -15,000 | read: the stage 19,458; estimate: what D2 keeps, 3,000 to 6,000 | the stage's tests of a held datagram, the beacon's order and the quota |
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

## 7. Steps T3 and T4, as the code reads them: not taken

T3 assumed that the link's walk runs over a driver behind `dyn BoxedLinkDriver`, so that the
group's stage presented as such a driver would take the walk without a second copy of it. The code
does not hold that:

- The walk is `SessionLinkActions::dispatch_network_message_in`
  (`crates/wz-session-core/src/session_actions.rs` @ `fn dispatch_network_message_in<const STAGED: bool>(`),
  a method of a unicast session's link actions. Before and while it frames it reads that session's
  own state: the deferral of its owner's sends, the availability gate and the limits its handshake
  negotiated (`negotiated_tx_limits_for`), and it mints and batches in the session's conduits
  (`crates/wz-session-core/src/session_actions.rs` @ `pub struct TxConduits<R: SessionRuntime> {`):
  one `R::Mutex<BatchTx>` per conduit, the windows in one `R::Word`, a sender flag per conduit.
- The driver is below all of it: `emit_on_link` hands it bytes already framed and numbered
  (`crates/wz-session-core/src/link.rs` @ `pub trait BoxedLinkDriver {`), and no seam of it carries a
  conduit set. A group's sequence numbers are its own (`crates/wz-session-core/src/sn.rs` @
  `pub struct MulticastTxConduits {`), the ones its JOIN advertises (`GroupTxStage::on_wire`); a
  group has no `SessionLinkActions` (lease, handshake, deferred sends) whose conduits could number
  its frames, and a stage under some link's walk would carry that link's numbers.

One walk for a group and a link therefore needs one transmit component over one conduit set, and
the forms it can take are a choice this lane cannot make without the measurements S2 names:

- the walk lifted out of `SessionLinkActions` and made generic over its conduit set: the link's and
  the group's are two instances of it, which is the second copy S2 is to remove;
- the same over a conduit set behind a trait object: one copy, but an indirect call for each mint
  and batch decision on the link's own path, which S2's condition refuses and the send Ir of the
  perf matrix's arm W would read;
- one conduit set for both: the group's conduits a `TxConduits<R>` of the group's runtime, the
  JOIN's advertisement read off the conduits as written. One copy and no call added; it changes the
  link's conduits (their locks, windows and sender flags), and where a link's sender takes its
  conduit's lock (`R::try_with_mutex_mut`, then `R::with_mutex_mut`), the group's stage keeps a
  push made while its conduits are held, encoded, and frames it when they are let go
  (`GroupTxStage::push_deferred`). It is the one form that keeps both of S2's conditions, and
  it is a design of the links' transmit lane and this one together, read with
  `size_ledger_gate.py --explain pico-api-coop-nostd` and the send Ir of arm W before it is
  written.

T4 (S3) is stated once the walk is the link's. With T3 not taken, the stage's re-entrant keep
(`push_deferred`, `Staged`) is still what holds a push made while the conduits are held in the
order it was made, behind the beacon, inside the reply quota; taking it out alone would lose that
order. D2 stays as `feat-mcast.md` section 4.1 decides it: one change with F7, whose first step
is T3. Nothing of T3 or T4 is in the code. Section 9 takes the third form above as the design.

## 8. Verification (the main session's)

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
- The one writer of each control message (section 10): `cargo test -p wz-session-core --lib
  --features
  session-multicast,codec-frame,alloc,codec-push,codec-declare,declare-final,declare-subscriber,declare-queryable,declare-undeclare,liveliness-token,codec-response,codec-response-final,transport-stats
  lent_control` and `group_declarations_written_from_parts`; the same with `declare-subscriber`
  alone of the planes; `wz-session-core` built and linted with that set, with `tx-lend-only`
  added, with no default features and `session-slot,session-unicast,liveliness-token,declare-subscriber`
  (the allocator-free link), and with `codec-declare` and none of the planes;
  `wz-session-mcu`'s `group_drive::stage` and `wz-capi-coop`'s group tests unchanged; size ledger
  as section 10 expects, one `<LentDeclaration as WireWrite>::write_wire` and one
  `<ResponseFinalOf as WireWrite>::write_wire` in `nm -C` of `pico-api-coop-nostd`.

## 9. The structure that makes T3's premise true: one transmit component, one conduit set

Section 7 found that the link's walk is not below a seam a group could stand behind: it is a method
of a unicast session's link actions, and its state is that session's. The structure that removes the
second path is zenoh-pico's own: one transmit state a unicast and a multicast transport both hold
(`_z_transport_common_t`: the write buffer, the transmit lock, the two sequence numbers and the
link), and one function that sends a message with it whatever the transport
(`vendor/zenoh-pico/src/transport/common/tx.c` @ `static z_result_t _z_transport_tx_send_n_msg_inner(`).
In wz terms that is section 7's third form, read from the code:

### 9.1 The transmit component

`TransportTx<R>` (a module of its own in `wz-session-core`) holds what the walk reads and changes
and nothing of the session around it:

- the conduits as they are today (`session_actions.rs` @ `pub struct TxConduits<R: SessionRuntime> {`):
  one `R::Mutex<BatchTx>` per conduit with its open frame and its lend counts, the windows in one
  `R::Word`, the sender flags;
- the frame sequence numbers the walk mints, unmints and reserves (the session's
  `outbound_frame_sn`, read through `next_outbound_frame_sn`, `unmint` and `reserve_next`);
- the limits a frame is cut by, per reliability class: the frame budget and the ring
  (`negotiated_tx_limits_for`), and the reassembly cap a chain is refused past;
- the links the conduits route to: what `with_conduit_link`, `lease_on`, `emit_on_link`,
  `send_wire` and the batch slots' records (`batch_slots`) read. Read before T3a, these are a
  binding's and a link's and cannot be the component's own: the walk reaches them through a
  borrow made for each send (section 9.6).

Its methods are the walk, moved and not rewritten: `write_n_msg`, `emit_frame_or_fragments`,
`emit_fragments_encoded`, `emit_fragment_chain`, `send_fragment`, the flush and drain of the
conduits and `congested_within`. It is generic over `R` alone, which is one type a build, so the
walk is one body a build. Its destination is the link it routes to, a `dyn BoxedLinkDriver` as it is
today, so a frame's lend, emit and wait for room are the calls they are now: the link's path gains no
call, which was S2's condition.

The unicast session keeps what is a session's and not a transmitter's, and calls the component
after it: the deferral of its owner's sends, the availability gate and the congestion close, the
block-first schedule, the low-latency path, the network message's statistics and the express flush
(`dispatch_network_message_in` above its conduit lock). What `dispatch_network_message_in` does
from the lock on (`stage_and_emit`) becomes the component's `write`.

### 9.2 A group holds the same component

A group holds a `TransportTx<R>` of the session's `R`: the same walk, compiled once. What differs is
what a group's transmit state is made of, and each is a value the component is given, not code:

- its limits are the group's (`MulticastParams::frame_budget`, the group's ring), settled when the
  group is joined, where a link's are settled by its handshake;
- its sequence numbers are the group's own, the ones its JOIN advertises; the group's
  `MulticastTxConduits` becomes the component's numbers, so no link's numbers are on a group's
  frame (the objection of section 7);
- its one link is the group's send socket presented as a datagram driver (a `BoxedLinkDriver` of
  the group, in `wz-session-mcu` beside `GroupLink`): it lends a slot of one batch, sends what it
  is handed with `try_send_to_group`, and keeps D2.

### 9.3 What the group's stage keeps: D2, the beacon's order and the quota

D2 is a property of the group's driver and nothing else: a datagram the socket refused
(`GroupSend::Full`) is held in the driver's one slot, and the driver answers the walk's
`wait_for_room_for` as a link with a full queue does, a droppable message congested at once and a
blocking one waiting on the host's pace (`GroupTxPace`), offering the held datagram first. The JOIN
is written by the pump through the same component, as a control frame of its own, so it is behind
the held datagram by the driver's order; what it advertises is the component's numbers less the
held datagram's, which the driver reads off that datagram's frame head when it holds it. The reply
quota (`MAX_MULTICAST_REPLIES`) stays the sink's admission, before the component.

The lanes (`Lanes`, `LaneRing`, `Record`, `next_out`), the stage's framer (`StageQueue`,
`push_frame`, `MulticastBatch`) and the second path's entries (`push_encoded_through`,
`admit_reply_body`, `admit_lent_reply`, `stage`, `push_on`, `take_front`) then have no
caller in a build whose group holds the component; what the lanes did beyond D2 (queue datagrams
for a later write by the pump) is what the link's batch window and its driver's slot do.

D2 by the owner's ruling of 2026-11-27 (`feat-mcast.md` section 4.1): zenoh-pico's group send
blocks on the socket, so D2 is a capability of its own, off in the zenoh-pico preset. Off, the
group's driver waits for the socket inside the send (`GroupTxPace::wait_writable`) and holds
nothing; on, it holds the refused datagram as above. Either way it is the driver's answer to
`wait_for_room_for` and no line of the walk.

### 9.4 What was read before each step, and what it settles

- **A push made while the conduits are held: settled, the group waits without stepping its own
  dispatch.** The stage keeps one today (`push_deferred`, `Staged`): a reply the group's own
  dispatch stages while a producer waits for room inside the host's pass. Read in the engine: a
  wait for room on a group runs the session's tasks only in the round form
  (`crates/wz-capi-coop/build.rs` @ `let round = threads && !value_locks;`), whose pace is the
  local set (`crates/wz-capi-coop/src/engine/group.rs` @ `self.local.run_until_idle();`), and
  the group's own task is one of those tasks. In every other form the pace is the clock
  (`ClockPace`, whose `pass` is empty): the wait's pass writes the stage and waits on the stack
  (`LinkWaits::wait_room`, which runs no task), a member's input is dispatched only by a read,
  which is a call of its own on the program's thread, and a read task on another thread
  (`threads` with value locks) reaches a group's values under the group's lock, which it waits
  for and does not enter twice. So the pico builds, which have no `threads`, never push while
  the conduits are held; the round form does, from the group's own task. On one component that
  push would take the conduit's lock a second time on one task, which no lock kind of the coop
  runtime allows (`wz-runtime-coop/src/runtime_impl.rs` @ `fn try_with_mutex_mut<T, U>(`:
  under a critical section or an owner's lock there is never another holder).
  The group takes the lend-only link's answer and not the heap link's deferral
  (`send_deferral::DeferredSends`, which needs a heap and an owner that defers): there is no
  pass that dispatches a group's input while a sender of that group holds one of its conduits.
  The group's task reads the component's sender flags (`TxConduits::sender_flag`, the flags a
  droppable sender reads already) before it reads its socket and, while one is up, leaves the
  input where the socket holds it for its next step. That is one load a step, compiled in the
  round form alone; nothing of the deferral enters the component. A reply then leaves after the
  push it was asked under, as it does today; it waits in the socket and not in `Staged`, the
  `VecDeque<StagedMessage>` T3b removes. Held by a round-form test with T3b: a member's ask that
  arrives while a put waits for room is answered after the put's frame.
- **D2's name: settled.** Capability `multicast-send-hold` (`WZ_CAP_MULTICAST_SEND_HOLD`), the
  shape of `advanced-source-retention`: a behaviour and not a door, so it implies nothing; on in a
  build that names nothing, which keeps today's send; `upstream_off = ["zenoh-pico"]`, as
  zenoh-pico's group send blocks on the socket; `abis = ["core", "pico"]` (the zenoh-c ABI's
  groups are the tokio engine's, whose group writer is a task of its own, T3c). Its Cargo feature
  has the same name in `wz-capi-pico` and `wz-capi-coop`, and gates the hold in
  `wz-session-mcu`'s group driver. Written with T3b, whose driver is what it gates; the
  configuration and the manifests land with that code, and `wz_config.py --write` regenerates
  what is derived from them.
- **The tokio engine's group** (`wz_runtime_tokio::multicast_pipeline`) pushes through
  `multicast_tx_push` onto its own lanes. It moves to the component in a step of its own (T3c);
  until then `push_frame` stays compiled in the host builds that link it, and leaves the pico
  builds with T3b.
- **The send Ir of the perf matrix's arm W** before and after each step of T3a, which moves the
  walk and must keep every `#[inline]` decision it has: the main session's reading.
- **What the walk reads besides the conduits and the numbers** (section 9.6): read before T3a,
  and it refines 9.1's component into owned state and a borrow of it.

### 9.5 Steps

| step | change | bytes, expected (`pico-api-coop-nostd`) | receive Ir | held by |
|---|---|---|---|---|
| T3a | `TransportTx<R>` out of `SessionLinkActions` (section 9.6): T3a-1 the conduits and the frame numbers as one owned field of the core; T3a-2 onwards the walk, as methods of a borrow of it with the link it routes to and the emit's facts; the session's prelude calls it | 0 to +500 (a field read through one more reference); client the same | none: the read is not the walk; the send's Ir held by arm W | every link test of the walk unchanged (`session_actions`' `conduit_tx_sn_tests`, `window_word_tests`, `window_join_tests`, `sender_inside_tests`; the frame, fragment and reopen tests of `wz-runtime-tokio`'s `session_glue`) |
| T3b | the group holds a `TransportTx` over its datagram driver; the stage keeps D2, the quota's admission and the JOIN's numbers (T4 with it); `push_frame`, `MulticastBatch`, `StageQueue`, the lanes and the staged storage leave the pico builds | -20,000 to -30,000: section 2's framer 6,559 and stage 19,458, less the driver, 2,000 to 4,000 | none: the group's read is not touched; a group's put the link's one walk | the group's wire held to the link's for the same messages (one test feeding both a link and a group the same sends and comparing the frames); the stage's tests of a held datagram, the beacon's order and the quota moved onto the driver |
| D2 | the capability of section 9.3, off in the zenoh-pico preset | 500 to 1,500 off | none | a group send on a full socket held (on) and waited (off) |
| T3c | the tokio engine's group onto the component; `push_frame` and the owned items leave every build | host builds only | none | `wz-runtime-tokio`'s group pipeline tests |
| F8b | the stage's remaining cells (`Rc<Inner>`, `RefCell`) in the session's arena, after T3b took `VecDeque<StagedMessage>` with `Staged` | -1,000 to -2,000 | none | the stage's tests |

T3a is first and alone: it changes the link's code and none of its behaviour, and it is the one
step whose effect on the link's send Ir must be read before anything stands on it. T3b is the gain.

### 9.6 T3a as the code reads it: owned state, and the walk over a borrow

Section 9.1 put the routed links in the component. The code does not let a component the core
holds own them:

- The binding's own link is the binding's field (`SessionLinkActions::link`), not the core's,
  and an aggregated session's other links are the core's set (`SessionCore::links`, under
  `transport-multilink`) chosen per conduit by `select_link`. A core shared by several
  bindings cannot hold one binding's link.
- The walk's destination is a link's state and not its driver alone: the lent batch slots are
  recorded on the link (`LinkState::batch_slots`, which `with_batch_holder` finds by where the
  record is), the emit marks the link's keepalive (`spoke`), closes its send gate on a writer
  that is gone (`transport_available`) and counts on its registry cell
  (`crates/wz-session-core/src/session_actions.rs` @ `fn emit_on_link(`).
- The emit reads facts of the session that are not a transmitter's state: the compression
  outcome (`compresses_batches`), the counters (`stats`, `record_on_link`), the refusal
  count (`refuse_tx`), and the walk reads the queue's waits (`params.tx_queue`), the fragment
  pacing credit (`take_fragment_tx_credit`) and the reassembly cap.

So the component is two things, both concrete in `R`, so the walk stays one body a build and no
call is added on the link's path:

- **`TransportTx<R>`, owned**: the conduits (`TxConduits<R>`) and the frame numbers
  (`FrameTxConduits<R::Word>`), what zenoh-pico's `_z_transport_common_t` holds of a
  transmitter. A field of the session's core, and of a group with T3b. Step T3a-1.
- **The walk, over a borrow**: a value made for one send of the component, the link it routes to
  (`&LinkState<R>`; the core's set under `transport-multilink`) and the emit's facts, whose
  methods are the walk. A group makes the same value of its own component, its datagram driver's
  `LinkState<R>` (its `R::LinkSink`, held as a link holds one) and its own facts, compression
  off. Steps T3a-2 onwards, one method family a commit: the numbers and the flush, then
  `write_n_msg`, then the fragment walk, then the emit. Whether the group's counters are the
  session's counter type, or the facts carry a counter of each, is read before the emit's
  commit.

Read before T3a-2, the order is the other way: every method of the walk ends in the emit (the
flush in `send_wire` and `close_lent_batch`, the frame in `emit_on_link`), so the emit and its
facts move first. Those facts are the session's, reached through its locked rows
(`fact_metrics` for the registry cells, `fact_tx_refusals` for the lend-only refusals) and its
counters (`stats`), and `compresses_batches` reads the handshake's outcome. Three forms keep one
body of the walk, and they differ in what the link's send pays:

- the facts as a value of the transmit state: the transmitter's counters and refusal counts move
  out of the session's rows into `TransportTx`, the registry's cell stays the link's
  (`LinkState::stats_slot`), and compression is a flag the establishment sets on the state. No
  call is added; the session's JSON and registry readers read the counters there. The textbook
  form (zenoh-pico's common transport keeps what its send counts), and the largest change;
- the facts behind one trait object the borrow carries: one indirect call on each emit where
  `transport-stats` or `transport-compression` is compiled, none on a build without both;
- the walk generic over the facts: no call added, and one more instance of the walk in a build
  that sends on a group, which S2 is to remove.

The choice is the main session's, with `size_ledger_gate.py --explain pico-api-coop-nostd` and
arm W's send Ir: whether the pico cases compile `transport-stats` or `transport-compression`
decides what the second form costs them. T3a-2 waits for it; T4's first half (section 12), which
does not depend on it, lands before.

## 10. The one writer of each control message, as landed

Section 3.4 of `arch-mono.md` (on its branch) read the bodies that still write one message twice
as two closures, not one instance twice: the final of a query's replies (the link's
`send_response_final` closure, 188 bytes, and the group's `multicast_tx_response_final` closure,
324) and the declarations (the link's `dispatch_declare_lent` closure, 2,324, the group's
`GroupDeclare::write_wire`, 3,194, and the link's token reply, 572). Each message is now written by
one writer for a link and a group, in `lent_control`, the layer that holds every lent writer:

- `lent_control::LentDeclaration` is every declaration a lend-only or allocator-free link sends and
  every one a group sends, as the arguments of its writer; its `WireWrite` is one body, out of
  line, composing each kind with the writer of that kind (`DeclarationOf`). The link's
  `dispatch_declare_lent` hands it on through its closure (a call of the one body, which the stack
  bound's `tx-encoder` rule still claims) and reads its QoS off it (`qos`: the declare QoS, the
  default for the token reply). The link's token reply goes through the same send
  (`LentDeclaration::TokenReply`), so its two writers and `local_token::token_reply_len` are gone.
  The group's `GroupDeclare` stays the group's naming of what it sends and becomes the one writer's
  arguments (`GroupDeclare::parts`); a kind with no plane is refused there, before anything is
  written, where the writer refused it before.
- `lent_control::ResponseFinalOf` is the final as its two numbers, with one out-of-line writer;
  the link's send and the group's both write it.
- Each kind is compiled where a sender of it is: a link's kinds under the link's planes as before,
  a group's under `session-multicast` with a heap. The client case, which links no group, compiles
  no kind it did not.

Expected: `pico-api-coop-nostd` -2,500 to -3,500 (one declaration writer for the two and the token
reply's, one final writer for two closures; the link's closures become calls); `pico-client-coop-nostd`
0 to -600 (its token reply's writer, where it answers tokens); receive Ir none (a send).

Held by: `lent_control::tests::the_one_writer_of_a_final_writes_the_borrowed_finals_bytes` (red if
the writer writes another id or QoS), `the_one_writer_of_a_declaration_writes_its_kind_alone` (red
if an arm writes another kind or the QoS is not the envelope's), and the group's tests that already
held every group declaration and final to the owned builders
(`group_declarations_written_from_parts`, `push_tests`), now through the one writer.

## 11. Step T3a-1, as landed

- `transport_tx::TransportTx<R>` holds the conduits (`TxConduits<R>`) and the frame numbers
  (`FrameTxConduits<R::Word>`). `SessionCore` holds it as one field, `tx`, where it held
  `tx_conduits` and `outbound_frame_sn`; every read of the walk is the read it was, through that
  field. `TransportTx::reset` puts both back for a reopen, after the caller has given the frames
  open in lent slots back to their links (`abort_lent_batches`), which this state does not hold.
  `TxConduits::new` and its reopen `reset` are the crate's, for the new module.
- No method moved and no `#[inline]` changed: the step names the state the walk's methods move
  onto (T3a-2 onwards, section 9.6).
- The module's gate is `session_actions`' (`storage-profile` and `session-unicast`), the types it
  holds being defined there. A group holds one with T3b without a unicast session; the types and
  the gate move to this module in that step.

Expected: 0 bytes on every case, a field's path; receive Ir none; arm W's send Ir unchanged.

Held by every test that reads the conduits or the numbers, unchanged: `session_actions`'
`conduit_tx_sn_tests`, `window_word_tests`, `window_join_tests`, `sender_inside_tests`;
`wz-runtime-tokio`'s `next_outbound_frame_sn_seeds_at_initial_sn_then_increments`,
`next_outbound_frame_sn_wraps_at_ring_seam`,
`outbound_frame_sn_splits_reliable_and_best_effort_channels` and, with `transport-multilink` and
`session-reconnect`, `reset_for_reopen_preserves_shared_sn_while_a_link_is_live` (red if the
reset reaches the numbers while a link is live, or misses them once none is).

## 12. T4's first half: the group's input waits for its conduits, as landed

Section 9.4 settled that the group's session reads no input while a push holds the group's
conduits. The round form's input gate also asks the stage (`GroupTxStage::sending`, whether a
push or a flush of the batch window holds the conduits): `GroupFace::made` builds the session's
gate as `!stage.sending() && round_gate.takes()`, so inside a put's wait for room the group's own
task leaves what the members sent in the socket, as it does when the round has no room. Held by
`group_drive::stage::tests::the_stage_is_sending_while_a_push_holds_its_conduits` (red if
`sending` reads anything but the conduits' borrow).

A second step dropped every push that found the conduits held and took `Staged` and
`push_deferred` out. It is reverted: a push that reaches that path with congestion control
`Block`, or a reply, would have been lost, where the link's path makes a blocking sender wait. No
caller reaches the path in the engine's forms (the gate above in the round form; no task runs
inside a wait in the others), but the stage is the one place that decides what happens if one
does, and losing a blocking message is not its answer. The keep stays until T3b, where the
group's driver holds a refused datagram (D2) and a push re-entering the one component is
answered once for a link and a group. Held by
`a_blocking_put_pushed_while_the_conduits_are_held_arrives` (red if a `Block` put pushed while
the conduits are held is refused or not framed behind the holder's message), beside the keep's
tests that were there before.

Expected: `pico-api-coop-nostd` 0 to +200 (the gate's flag read is the round form's alone);
`pico-client-coop-nostd` 0; receive Ir none.

## 13. The emit's facts: decided

Of section 9.6's three forms, the main session chose the first: the counters, the refusal counts,
the registry cells' recording and the compression choice the emit reads move into
`TransportTx`, which owns them as zenoh-pico's `_z_transport_common_t` does; no facts behind a
trait object and no walk generic over them. T3a-2 moves them first, then the emit, the flush,
`write_n_msg` and the fragment walk.

## 14. Step T3a-2, first commits: the emit's facts and the emit, as landed

- **Compression is the link's.** Section 13 put the compression choice on
  `TransportTx`. Read in the code, it is not a transport's fact: the predicate the emit and the
  receive's un-wrap read had an established conjunct, and establishment is stamped per link
  (`LinkState`'s `established_at`), as upstream's batch configuration is a link's. A link that
  joins an aggregate writes its handshake bare while another link of the session compresses, and
  one flag on the shared transmit state would have compressed that handshake. So the link keeps
  it (`LinkState::compresses`, an `R::Flag`), settled by `enter_established` from the
  negotiated capability less a lowlatency link (`negotiated_batch_compression`), before the send
  limits are settled from it, and withdrawn by `reset_for_reopen`. The emit reads the link it
  writes on; `SessionLinkActions::compresses_batches` reads the binding's link. Held by
  `bundle_tests::a_link_compresses_from_its_establishment_what_its_session_negotiated` (red if
  the establishment settles anything but the negotiated capability, if a link compresses before
  it is established, or if a reopen leaves it compressing) and by the compression end-to-end
  tests of `wz-runtime-tokio` (`compression_e2e`, `transport_compose_e2e`,
  `transport_mode_pairs_e2e`).
- **The counters are the transmit state's.** The wire counters (`stats`), the
  registry partition (`metrics`, under a lock of its own instead of the session's facts lock)
  and the lend-only refusals (one `R::Word` per cause, where they were a row of the facts) move
  into `TransportTx`, with `record_on_link` and `refuse` (was `refuse_tx`). The receive's
  counters ride with the transmit's, `TransportStats` being one value of both directions; the
  readers (`stats_report`, `stats_metrics`, `tx_refusals`, the receive's counting in
  `drive`) read them at `tx`. A reopen keeps them. Held by the tests that count through them,
  unchanged: the lend-only refusal tests of `bundle_tests` (`lent_handshake`,
  `lent_frame_refusal`: red if `refuse` does not count its cause),
  `a_datagram_dropped_before_the_session_read_it_is_a_receive_drop`, `wz-session-lwip`'s
  `tx_allocations` and `wz-runtime-tokio`'s `transport_stats_e2e`.
- **The emit is the transmit state's.** `emit_on_link` moves onto
  `TransportTx` unchanged in what it does and in its `#[inline(never)]`; the session's sends
  (`send_wire`, the per-link keepalive and close, the lent batch and fragment sends) call
  `self.tx.emit_on_link` with the link they route to. The driver is called by its trait's path,
  the module importing no trait a bound already names. Held by every test that sends, and
  directly by `bundle_tests`' tests that emit on the bundle's link.

Expected: `pico-api-coop-nostd` -50 to -200 (a refusal is a word's add where it held the facts
lock; the pico cases compile neither `transport-stats` nor `transport-compression`, so the
other two moves are a field's path there), +8 bytes of RAM a session (two words for two 32-bit
counts); `pico-client-coop-nostd` the same; receive Ir none; arm W's send Ir unchanged (the
emit's body and its call are the ones they were).

Next in T3a-2, one family a commit: the routing of a send over a borrow of the transmit state and
the links (`send_wire`, `with_conduit_link`, `lease_on`), the lent batch's holder
(`with_batch_holder`, `close_lent_batch`, `send_lent_batch`), the flush (`flush_conduit`,
`drain_conduits`), `write_n_msg`, the fragment walk.
