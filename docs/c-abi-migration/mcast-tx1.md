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
| **T6 (landed, `feat-mcast.md` section 7)** | F4, one shell for a group | -15,000 to -25,000 | `feat-mcast.md` F4; read today: the shell's bodies of row D other than the open, 29,387 | the engine's group tests |
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

## 15. Step T3a-2, the walk over a borrow, as landed

- **The borrow.** `transport_tx::TxRoute<'a, R>` is the transmit state with the links a send
  leaves by: `tx` (the `TransportTx`), `own` (the binding's own `LinkState`) and, under
  `transport-multilink`, `links` (the core's set). Its fields are public and it has no
  constructor: no invariant binds the three, and a group builds one of its own state and its
  datagram driver's link with T3b. The session makes it in `SessionLinkActions::route`
  (`#[inline]`), gated as `TransportTx::emit_on_link` is, since every build that sends routes
  a send through it.
- **Moved onto it, bodies and `#[inline]` decisions unchanged**, in three commits: the routing
  (`select_link`, `send_wire`, `send_wire_this_link`, `send_wire_urgent_this_link`,
  `with_conduit_link`, `conduit_routes_to`); the lent batch and the flush (`with_batch_holder`,
  `close_lent_batch`, `send_lent_batch`, `flush_conduit`, `drain_conduits`,
  `send_open_lent_batches`, `lease_on`, `send_lent_on`, `send_lent`); the message's frame and
  its fragments (`write_n_msg`, `congested_within`, `emit_frame_or_fragments`,
  `emit_fragments_encoded`, `emit_fragment_chain`, `send_fragment`). The walk mints its numbers
  on `tx.frame_sn` directly; the session keeps its public `next_outbound_frame_sn` for readers.
- **The walk's last two session facts are the transmit state's.** The fragment credit
  (`tx-fragment-credit`) leaves the session's facts row for a lock of its own on `TransportTx`
  (`set_fragment_credit`, `fragment_credit`, `take_fragment_credit`); the session's public
  `set_fragment_tx_budget` and `fragment_tx_budget` read it there. The lane bound a probe reads
  before it begins a chain is the queue shape recorded on `TransportTx` when the send limits are
  settled (`shape_lanes`, read by `lane_bytes`), where it was the session's parameters asked
  again at each such probe; the check is compiled under `tx-probe`, where it ran before (under
  `alloc` it read a probe flag that is constant `false` without `tx-probe`). Before the limits
  are settled no lane is bounded; no data frame is sent then.
- What the walk names of `session_actions` (the conduits' stage, the lend records, `Lend`,
  `LentWrite`, `FrameEmit`, `UnicastPush`, `FrameLend`, `HeapStage`) is `pub(crate)` for it;
  those types move into `transport_tx` with T3b, regated for a group.

Expected: `pico-api-coop-nostd` and `pico-client-coop-nostd` 0 to +200 bytes (a borrow of two
pointers made at each send and passed by reference to the out-of-line bodies, where they took the
session; no body and no call added); receive Ir none (a send); arm W's send Ir: one or two stores
a send, the main session's reading.

Held by every test that sends, unchanged: `session_actions`' `conduit_tx_sn_tests`,
`window_word_tests`, `window_join_tests`, `sender_inside_tests` and `bundle_tests`;
`wz-runtime-tokio`'s frame, fragment and reopen tests, `layer3_reassembly_tx` (the fragment
credit: red if a draw does not count down or a refill does not take) and the multilink tests (the
routing). New: `bundle_tests::a_probe_reads_the_lane_the_established_queue_took` (red if a lane
is bounded before the limits are settled, or the settle records another shape than the session's
parameters give the link's queue).

Next: the transmit types into `transport_tx`, regated for a group; then T3b with D2.

## 16. The transmit types in `transport_tx`, and the write, as landed

- **The types are the module's.** What the transmit state is made of is defined beside it: the
  conduits (`TxConduits`, `BatchTx`, `BatchStage`), the windows over them (`WINDOW_*`, the
  window word's `set_window`, `close_and_drain` and the drain count), the sender's mark
  (`SenderInside`), the frame numbers (`ConduitTxSn`, `FrameTxConduits`), the counts of where
  frames were written (`BatchLendCounts`, `FragmentLendCounts`, `FrameLendCounts`,
  `TxRefusalCounts`) and the values the walk hands between its steps (`FrameEmit`,
  `UnicastPush`, `FrameLend`, `HeapStage`, `Lend`, `LentWrite`). Moved, bodies and
  `#[inline]` decisions unchanged. What the session no longer names is the module's own again
  (`TxConduits::new`, its reopen `reset`, `control_taken`, the heap count, the sums' adds);
  what the session's prelude still reads is `pub(crate)` (the window bits it opens and closes,
  the conduit accessors). The three lend sums are `TxConduits`' (`batch_lend_counts`,
  `fragment_lend_counts`, `frame_lend_counts`), and the session's public accessors of the
  same names answer them, their signatures as they were. The public counts are reached at
  `wz_session_core::transport_tx::` (`wz-capi-coop`, `wz-runtime-tokio`'s `lent_slot_send`,
  `wz-session-lwip`'s `tx_allocations` follow), and `sn.rs`' links to `FrameTxConduits`
  with them (the reduced-docs ledger line of `sn.rs` names the new path).
- **The write is the module's.** What the session's dispatch did from its conduit's lock on is
  `TxRoute::write` (`#[inline]`): the sender's mark, the one load of the windows that decides
  whether the message joins the open frame (a held reply does) and whether a frame it does not
  join may be open, that frame's flush, then `write_n_msg`. The session's closure hands it the
  conduit it locked, whether the message is a held reply, and the frame's facts; everything
  before the lock (the deadline, the barrier of a control message, the fence) and after it (the
  link's writer told, the congestion decision) is the session's, as section 9.1 has it. The mark,
  `window_joins`, `window_may_hold_open`, the windows' load and `BatchStage::is_open` are
  private to the module again.

Expected: 0 bytes on every case (a move, and the session's closure calls one `#[inline]` body
where it held the same lines); receive Ir none; arm W's send Ir unchanged.

Held by the tests that moved with their subjects, unchanged: `transport_tx`'s
`conduit_tx_sn_tests`, `sender_inside_tests`, `window_word_tests`, `window_join_tests`;
`session_actions`' `bundle_tests` (every send goes through `write`); the lend counts, which
they read through the sums, by `wz-runtime-tokio`'s `lent_slot_send` and `wz-capi-coop`'s
`arena` tests, the refusals by `wz-session-lwip`'s `tx_allocations`.

### 16.1 The gate for a group, read: not a move

The module stays gated as `session_actions` (`storage-profile` and `session-unicast`). The
types moved compile without a unicast session, but the module does not: `TxRoute` (`own`,
`links`), `TransportTx::emit_on_link` and `record_on_link` name `LinkState`, and the lent
batch's holder names `LentRecord`, both `session_actions`'. A build with `session-multicast`
and no `session-unicast` exists (`wz-session-core`'s own `alloc,session-multicast,...` and
`session-slot,session-multicast,...` subsets, and `wz-runtime-tokio`'s `transport-multicast`
without its defaults), and the module would not compile there.

That gate does not hold T3b: its group is `wz-session-mcu`'s, which takes `session-unicast`
unconditionally (its dependency on `wz-session-core`), and every build of it that compiles has a
storage profile (`wz-runtime-coop` refuses `session-unicast` without `alloc` or
`session-slot`). It holds T3c, whose host builds can link a group without a unicast session.

What the walk reads of a link is its transmit half: the driver, the lent batch records
(`batch_slots`), the speech bit (`spoke`), the send gate (`transport_available`), the
compression flag and the registry slot (`stats_slot`); the multilink choice reads the set's
reliability and band besides. The structure that frees the module of the unicast link is that
half as a type of this module (`LinkTx<R>`), which `LinkState` holds and `TxRoute::own`
borrows; the set of an aggregate stays `LinkState`'s, `transport-multilink` being a unicast
feature, and a group's set is empty there. With it the module is gated on the storage profile and
either transport.

### 16.2 What T3b reads before its first commit

- **A group cannot make a `LinkState`.** It is made only with the session it belongs to
  (`SessionLinkActions::new_generic`, `HalvesMaking`), and most of it is a unicast link's (the
  stamps, the lease and keepalive duties, the close reason, the shared-memory handoffs, the
  admission place). With `LinkTx` the group makes the transmit half of its datagram driver (its
  `R::LinkSink`) and nothing of a unicast link. So the split of 16.1 is T3b's first step.
- **Where a group's message enters the walk.** It enters `wz-session-core`'s multicast layer
  through `MulticastTxQueue` (`wait_for_room`, `enqueue`, `enqueue_lent`, `push_frame`),
  which the stage implements over its lanes. T3b's stage implements it as a link's dispatch does
  from the lock on: the group's conduit locked, `TxRoute::write` with a `FrameEmit` of the
  group's limits (`MulticastParams::frame_budget`, its ring, its queue's waits), so the group's
  frame numbers are `TransportTx::frame_sn` and its JOIN advertises them.

Next, in order: `LinkTx` out of `LinkState` (`transport_tx`, every reader of the six fields),
the module's gate widened to a group, then T3b with D2.

## 17. The link's transmit half, as landed

- **The type.** `transport_tx::LinkTx<R>` is what a send reads and writes of the link it leaves
  by: the driver (`driver`, `link_driver`), the send gate (`transport_available`), the speech
  bit (`spoke`), the compression flag (`compresses`, `compresses_batches`,
  `settle_compression`), the registry slot (`stats_slot`), the shared-memory handoff as a sender
  (`shm_tx`) and the lent batch records (`batch_slots`, with `LentRecord`). `LinkState` holds
  it as `tx`, made by `LinkTx::new` in `init_link`, and the drop that gives a link's held slots
  back is the half's, where it was `LinkState`'s. `LinkTx::new` is public: a group makes the half
  of its datagram driver with no session, as zenoh-pico's transport keeps its link and its
  `_transmitted` bit beside its common state.
- **The sender's shared-memory handoff is the seventh field.** Section 16.1 counted six. The
  session's send reads `shm_tx` of the conduit's link through `TxRoute::with_conduit_link`
  (`open_shm_tx`), so a route that lends the transmit half must find it there; it is written by
  the Open message the link sends and read by the link's sends, a transmit fact of the link.
  The receiver's half (`shm_rx`) stays on `LinkState`.
- **The walk borrows the half.** `TxRoute::own` is `&LinkTx`, and so are the links
  `emit_on_link`, `record_on_link`, `conduit_routes_to`, `send_lent_batch`,
  `send_open_lent_batches`, `lease_on` and `send_lent_on` take and the closures of
  `with_conduit_link` and `with_batch_holder` are lent; the session's `count_network_message`,
  `drop_for_congestion` and `move_lent_batches_off` likewise. An aggregate's set stays
  `Vec<Shared<LinkState>>` (`select_link` reads the declared reliability and the band), and a link
  chosen from it is lent as its `tx`. `own_link` is gone: its three readers asked the driver,
  which the session's `link_driver` answers.
- **A compile fault of the walk's move is repaired with it.** `write_n_msg`, moved into
  `transport_tx` with the walk (section 15), records a lent slot with `LentRecord::hold`, which
  was private to `session_actions`; with `LentRecord` in `transport_tx` the call is the module's
  own.
- The readers outside the crate read the fields at `link.tx`: `wz-runtime-tokio`'s
  `session_glue`, session tests, `shm_auth_segment` tests and the keepalive and multilink
  integration tests, and `wz-session-lwip`'s `session_slot_allocations`.

Expected: 0 code bytes on every case (a regroup of fields; the constructor is `#[inline]` and
builds what `init_link` built field by field; the drop is the one `LinkState` had); RAM 0 to one
word a link (the half is padded as a unit, so its two flags no longer share padding with
`LinkState`'s); receive Ir none; arm W's send Ir unchanged (the same loads at other offsets).

Held by every test that sends, unchanged, and by
`bundle_tests::a_link_transmit_half_is_made_without_a_session` (red if `LinkTx::new` opens the
send gate, marks the line or compresses before an establishment settles them, if `link_driver`
answers another driver than the one the half was made over, or if the half keeps its driver past
its drop).

### 17.1 The gate for a group, read again: with T3c, not before

Section 16.1 put the widening of the module's gate (the storage profile and either transport)
after the split. Read in the code, the split is not all it needs:

- Every `pub(crate)` item the module compiles in a build needs a reader in that build, and in a
  build with `session-multicast`, a sending codec and no `session-unicast` none of the walk's
  items has one (`TxRoute::write`, `emit_on_link`, the flush, the lend): the session is their
  only caller. Widened alone, the module is dead code under `-D warnings` there. The reader is a
  group that sends through the walk in such a build, which is T3c's; the items a group never calls
  (`send_wire_this_link`, `send_wire_urgent_this_link`, the control arm of `send_lent_on`) then
  take a `session-unicast` conjunct of their own.
- `transport-multilink` does not imply `session-unicast` (it takes `session-extauth`), so
  `TxRoute::links` and `select_link`, which name `LinkState`, take `session-unicast` too.
- The module's doc links into `session_actions` (`SessionLinkActions::batch_stop`,
  `hold_replies`, the three lend counts, `set_fragment_tx_budget`, `tx_refusals`) resolve only
  with `session-unicast`; the reduced documentation configurations without it (Layer C1bzr)
  would count each as a finding, so they become words where a group's build documents them.

T3b does not need the widening (16.1: its group is `wz-session-mcu`'s, which takes
`session-unicast`), so the widening lands with T3c, whose group is the reader that makes it whole.

Next: T3b with D2.

## 18. Step T3b, first commits: the group's transmit state and its driver, as landed

- **The door is one type of the session core, not the walk made public.** `TxRoute::write`,
  `FrameEmit` and the conduits stay `pub(crate)`. What a transport that is not a unicast
  session sends with is `transport_tx::GroupTx<R>`: a `TransportTx`, the `LinkTx` of its one
  link and the group's limits (`GroupTxLimits`: the frame budget, the SN ring, the reassembly
  cap, QoS, compression, the queue's waits), settled when it is made, so its send gate opens at
  once. `GroupTx::send` is what a session's dispatch does from its conduit's lock on: the
  conduit locked (a droppable message that finds a sender holding it is `PushOutcome::Held`, as
  zenoh-pico's try of the transmit lock fails), `TxRoute::write` with a `FrameEmit` of the
  group's limits, an express message's drain of its band; a body the codec refuses is
  `PushOutcome::Refused`, a closed gate `SendWireError::TransportUnavailable`.
  `GroupTx::next_sn` reads what the JOIN advertises (`FrameTxConduits::next`, new), and the
  batch window is the conduits' own (`batch_start`, `batch_flush`, `batch_stop`). Under
  `transport-multilink` the route's set is an empty one the group holds, so every frame leaves
  by its link.
- **One walk a build holds where the engine's runtime names the driver by a trait object.**
  `wz-capi-coop`'s links run on `CoopRuntime<C, dyn BoxedLinkDriver, SessionLock>`
  (`engine.rs` @ `type LinkRuntime<C>`), so a group of that runtime is the same instance of the
  walk. A runtime that names a concrete driver (the slot profile's) would compile a second one
  for a group's driver; no group runs there (`group_drive`'s stage is the heap profile's).
- **Without `transport-qos` a group has one conduit and one SN ring a channel**, as zenoh-pico's
  multicast transport does; `MulticastParams::is_qos` is inert in such a build already.
- **The driver** is `wz-session-mcu`'s `group_drive::GroupDriver<T>`, over the `GroupLink` the
  group's task shares: it lends the walk slots of one batch (`wz-runtime-coop`'s `TxLender` over
  `HeapTx`, `SESSION_TX_SLOTS` of them, one more with the hold), copies bytes built apart into one
  (`copied_send`), and offers a handed-over slot to the socket from where it was encoded. A link
  the session does not hold open, and a send the stack fails, are a drop (`NoTxSlot`) and not a
  writer gone: a group's next datagram may leave, and `WriterGone` would close its gate for good.
- **D2 is the driver's** (`multicast-send-hold`, a feature of `wz-session-mcu` for now). Off, a
  full socket is waited on inside the send until it takes the frame (`GroupTransport::wait_for_room`).
  On, the frame's slot is held and the send returns; `wait_for_room` offers the held frame first
  and waits on the socket while it is refused, and a frame handed over with no room asked (a
  window's flush) while one is held is a drop.

Held by `bundle_tests::group_tx_tests` (`codec-push`, not `tx-lend-only`):
`a_group_frames_a_message_on_its_link_and_its_join_reads_past_it` (red if the send mints on
another channel, the gate is closed at the making, or `next_sn` answers the last number minted),
`a_group_whose_writer_is_gone_refuses_its_next_send` (red if the send does not read the gate),
`a_group_window_holds_its_messages_in_one_frame_until_the_stop` (`transport-batching`); and by
`group_drive::driver::tests`: `a_frame_leaves_on_the_socket_as_it_was_written`,
`a_frame_on_a_link_not_open_is_a_drop`, `a_full_socket_is_waited_on_inside_the_send` (without
the hold) and `a_frame_a_full_socket_refused_is_held_and_offered_first` (with it).

Expected: 0 bytes on every case (no build calls either type yet); receive Ir none.

Next, in order:
- the stage over `GroupTx<LinkRuntime>` and `GroupDriver`: `GroupTxStage::push_encoded` and the
  reply admission call `GroupTx::send` (the quota's admission before it), the JOIN reads
  `next_sn`, less the held frame's number with the hold (read off its frame head, which the
  driver will answer), the counters move to `GroupTx`'s `TransportStats`; the lanes, `Staged`,
  `StageQueue`, `Writer` and `MulticastBatch` leave the pico builds;
- the round form's group task reads `TxConduits::sender_flag` (a reader on `GroupTx`) before it
  reads its socket (section 9.4), with the round-form test of a member's ask answered after the
  put's frame;
- D2's capability (`deploy/wz-config.toml`, `WZ_CAP_MULTICAST_SEND_HOLD`, the features of
  `wz-capi-pico` and `wz-capi-coop` forwarding `wz-session-mcu/multicast-send-hold`; main runs
  `wz_config.py --write`);
- then T3c (with the gate widening of 17.1), F8b.

## 19. Step T3b, the driver's waits and the readers the stage needs, as landed

Main's rulings on section 18's open questions: the stage is generic over the runtime `R` (the
stage is transport machinery and names no C ABI type, so layering points down only); with the
hold, the JOIN reads the held frame's number off the driver; the group's counters are
`GroupTx`'s, one home a counter.

- **The driver waits on the host, never on the transport's own wait.** `GroupDriver<T, P>`
  takes the host's pace (`P: GroupTxPace`, the wait the stage's producers wait with). Without
  the hold a frame the socket refused is followed by one pass of the host and one wait on the
  socket's writability (`GroupTxPace::wait_writable`) before it is offered again, as
  zenoh-pico's blocking send waits inside the socket (`vendor/zenoh-pico/src/link/link.c` @
  `z_result_t _z_link_send_wbuf(`); a group whose session ended drops the frame
  (`NoTxSlot`). With the hold the ask for room runs the same pass and wait once and answers
  how long it waited by the host's clock. The transport's `wait_for_room` is not asked: a stack
  whose socket can be full but which gives no wait of its own (the raw Ethernet group, whose
  writability is a `room_wait` handle the host's `LinkWaits` waits on) answers it at once,
  and the loop over it was a spin. `GroupLink::wait_room` had no other reader and is gone.
- **The held frame's lane is read where frames are read.** `inbound::frame_lane` reads the
  priority, channel and number of a `Frame` or `Fragment` by the head decodes of the receive
  path (`parse_frame_in_place`, `parse_fragment_in_place`), so the frame layout has one
  reader. `GroupDriver::held_lane` (with the hold) answers it for the frame it holds; the
  feature takes the core's `storage-profile`, which carries the decode.
- **The readers the stage switch calls.** `GroupTx::sending` answers whether a sender holds
  one of the group's conduits (the round form's task reads it before its socket, section 9.4);
  `MulticastTxMeta::group_message` is a framing's `GroupTxMessage`, so a message sent through
  the walk is framed as the stage framed it.

Held by `group_drive::driver::tests`: without the hold
`a_full_socket_is_waited_on_before_each_offer_inside_the_send` (red if an offer follows an
offer with no wait between, if the send returns on a full socket, or if it waits on the
transport's wait, which never frees room there) and `a_full_socket_of_an_ended_group_is_a_drop`;
with it `a_frame_a_full_socket_refused_is_held_and_offered_first`,
`a_held_frame_a_wait_did_not_free_leaves_the_link_congested` and
`a_held_frame_answers_its_lane_until_it_leaves`; by `inbound::frame_lane_tests` (a frame, a
fragment with `reassembly`, a QoS extension with `transport-qos`, and the units that are no
frame); by `bundle_tests::group_tx_tests::a_group_reads_a_sender_inside_its_conduit` and
`multicast_tx::push_tests::a_framing_is_the_group_message_it_reads_as`.

Expected: 0 bytes on every case (no build calls the driver or the readers yet; the hold build
compiles the core's storage profile, which every group build carries already); receive Ir none.

### 19.1 The stage switch, as read before it is written

The switch is one change across three crates, and these are its parts as the code reads them:

- **The stage over the component.** `GroupTxStage<R>` holds a `GroupTx<R>` whose link is the
  group's driver. `push_encoded` sends `MulticastTxMeta::of_encoded(..).group_message(size)`
  with the message's body; `admit_reply` and the lent replies admit by the quota and send the
  same way. A reply is then written at once or refused at once, so the quota bounds the replies a
  hold keeps out (one, the held frame) and `MAX_MULTICAST_REPLIES`'s admission is the sink's,
  as section 9.3 says; the stage's tests of a reply held past the quota become tests of the
  sink's admission.
- **What the pump reads of the stage.** The pump (`MulticastPump`) is not generic over `R`
  and should not become so: it reads the stage through an object of the few answers it needs (the
  JOIN's numbers, whether a frame is held, the losses, the reply admission, the window's flush),
  which `GroupTxStage<R>` implements. The JOIN's numbers are `GroupTx::next_sn` per conduit
  and channel, with the held frame's lane (`held_lane`) answering its own number.
- **A typed handle on the driver.** `GroupTx::new` takes the driver erased
  (`R::LinkSink`, `CellRc<dyn BoxedLinkDriver, K::LinkCount>` in the coop engine); the stage
  keeps a clone of the typed handle made before the unsizing (`CellRc::into_sink`) to read
  `held_lane`, so the stage is generic over the driver's transport and pace as well, or reads
  them through the same object as the pump.
- **The round form in the same change.** A reply admitted while a sender holds its conduit
  would take the conduit's lock a second time on one task; the group's task reads
  `GroupTx::sending` before it reads its socket (section 9.4), so this lands with the switch and
  not after it.
- **The engine.** `GroupFace` makes the driver over its `GroupLink<Watched>` with a pace made of
  what its own `GroupTxPace` reads (`pace`, `waits`, `room`, the end), held apart from the
  face so the driver does not hold the face that holds it; `write_staged` and the stage's own
  writer go.
- **The counters.** `GroupTx::new` makes its `TransportTx` with its own `TransportMetrics`;
  the group's `TransportStats` the face shares with its task is to be the one the walk's emit
  counts into, read before the switch's commit as section 9.6 asked of the link's emit.

Next: the switch above, then the D2 capability rows (they claim the driver's behaviour, so they
land after the driver is what sends), T3c with the gate widening of 17.1, F8b.

## 20. The switch's first pieces, as landed, and the stage as it is to be written

- **A send that may not wait.** `GroupTx::send_at_once` asks for room with a wait of zero and
  drops a message at once behind a sender that holds its conduit, whatever its congestion
  control; `send` and it are one body (`send_within`). A reply the group's own step answers
  runs inside the wait a sender of the group waits with, so the stage sends replies with it.
- **The counters' home is readable.** `GroupTx::stats` (`transport-stats`) answers the
  `TransportStats` the walk's emit counts into; the stage counts its network messages there,
  and the pump's receive and beacon counts are to move there through the stage's object, so the
  face's `Rc<TransportStats>` goes with the switch.
- **The JOIN's numbers are written from outside.** `MulticastTxConduits::set_next` sets the
  next number of a conduit's channel on its ring, so the stage writes `GroupTx::next_sn` of each
  conduit and channel, and the held frame's number on its lane, into the announcer the JOIN is
  encoded from.
- **The driver's answers past the walk.** `group_drive::HeldFrame` (`holds`, `offer_held`,
  `lost`, `held_lane` with the hold) is implemented by `GroupDriver` and by a
  `CellRc` of anything that implements it, the counted handle the engine keeps before
  `into_sink`. The step's `offer_held` waits on nothing. A send the stack failed is counted
  (`lost`), a full socket's refusal is not.
- **A dead variant in a leg without `tx-probe`.** `UnicastPush::Chain` is made only by a probe,
  which only `tx-probe` has; it and `Dispatched::Chain` are gated on `transport-fragmentation`
  and `tx-probe`, and so are their two match arms.

Held by `bundle_tests::group_tx_tests::a_message_sent_at_once_asks_for_room_with_no_wait` (red
if the at-once send asks with the message's own wait, or is answered pushed on a full link),
`sn::tests::mcast_tx_conduits_advertise_a_next_set_from_outside` (red if the set writes the
other channel or leaves a number past the ring), and `group_drive::driver::tests`:
`a_frame_a_send_failed_is_lost_and_counted` (red if a failure is not counted, counted twice, or
held) and, with the hold, `a_held_frame_is_offered_again_by_the_step_without_a_wait` (red if the
step's offer waits, lets a refused frame go, or the counted handle answers another driver).

Expected: 0 bytes on every case (no build calls the new items); receive Ir none.

### 20.1 The stage, as it is to be written

`GroupTxStage<R: SessionRuntime, D: HeldFrame>` in place of today's, `Rc` of `GroupTx<R>` (made
by the stage from the sink, numbered from 0, its limits read off `MulticastParams`:
`frame_budget()`, `mask_from_res(seq_num_res)`, `is_qos`, `compression`, `tx_queue`, and no
bound on a chain, as the group's walk set none), the driver handle `D`, the parameters, a drop
count per conduit and the replies' drop count:

- `push_encoded(message)` is `GroupTx::send` of `MulticastTxMeta::of_encoded(..).group_message`
  with the message's body: pushed is counted as a network message; congested or held is a drop
  of its conduit; refused is answered; an error of the link (a link the task has not opened) is
  answered pushed, lost with the link, as today's stage answers a push on an ended group. The
  pace parameter goes: the driver waits with its own.
- A reply is admitted while `quota.admits(holds + 1)` (the held frame is the one datagram a
  hold keeps out) and sent with `send_at_once`; one refused for want of a slot or of room is
  counted in `dropped`. The `MulticastReplyEnqueue` forms stay as they are, over that body.
- The pump's object (`GroupTxAnswers`): `offer_held`, `holds`, `lost`, `advertised`
  (`set_next` of every conduit and channel, then the held lane's number), `has_reply_slot`,
  `admit_reply`, the window's flush and the counters. The pump holds it as `Rc<dyn ..>`; its
  `write` and `offer_held(transport)` calls go, since the driver sends at once.
- The batch window is `GroupTx`'s (`transport-batching` of the core). `wz-session-mcu` gets a
  `transport-batching` feature forwarding the core's, which `wz-capi-coop` names (it always
  enables the core's), gating the stage's `batch_*` and the pump's flush at the beacon and the
  Close; a new feature name runs the census, no-allocator and prose-name gates.
- What goes with the switch: `Lanes`, `LaneRing`, `Record`, `next_out`, `StageQueue`,
  `Staged`, `Writer`, `Through`, `SendNow`, `GroupLink::write_staged` and `push_encoded`,
  the face's `write_staged` and its callers (`engine.rs` `group.write_staged()`), and the
  stage's tests of lanes and staging; the tests of the JOIN's numbers, the quota and the counters
  are written again over the driver.
- The driver honours the send's own deadline, ruled by the main session: no build combination is
  refused. A frame whose ask for room allowed no wait (`send_at_once`, a reply) waits inside the
  driver in no build. Without the hold the ask records what it allowed and the send takes it: a
  full socket refusing such a frame is a congestion drop, counted by the driver
  (`HeldFrame::congested`), the answer `send_at_once` gives behind a sender that holds its
  conduit; a frame whose ask allowed a wait, or that was handed over with no ask (a window's
  flush), waits through the host's pace as before. With the hold the ask is answered congested
  at once while the held frame is refused, and a frame handed over with no ask while one is held
  is the same counted drop. So the round form without the hold never runs the session's tasks
  from inside the group's own task for a reply. The frame had its number when the socket refused
  it, so the drop is the driver's count and not the walk's answer; the stage adds it to the
  group's drops.

  Held by `group_drive::driver::tests::a_frame_asked_at_once_is_not_waited_for_on_a_full_socket`
  (without the hold; red if an at-once frame passes or waits, is not counted, or an ask's zero
  wait outlives its frame); with the hold by
  `a_frame_handed_over_while_one_is_held_is_a_counted_drop` (red if the drop is not counted, or
  lets the held frame go or overtakes it). Expected: 0 bytes on
  every case (no build calls the driver yet).

Next: the stage of 20.1 with the pump's object and the engine in one change, then the D2
capability rows, T3c with the gate widening of 17.1, F8b.

### 20.2 The reply sent at once, read before the switch: a premise that does not hold

20.1 sends a reply with `send_at_once` from where it is admitted. Read in the code, a reply is
admitted from inside the read that delivered what it answers, and in two of the engine's forms
that read holds the cell the driver sends through:

- The pump dispatches each datagram inside `GroupTransport::recv_with`'s callback
  (`group_drive.rs`, the receive loop of `MulticastPump::step_reading`), and the engine answers
  a member's ask there: `engine/group.rs` @ `fn answer_asks(` puts the keyexpr answers on the
  group (`enqueue_declaration_reply`) before the event is dispatched, and the dispatch hands
  the replies sink to what it answers.
- In the round form the session's transport is the face's `GroupLink<Watched>` itself
  (`type SessionLink = GroupLink<Watched>;`), whose `recv_with` holds the shared cell's
  `RefCell` borrowed for the callback; without the round form a transport that splits no
  receive half reads through the same cell (`ThroughCell`).
- The driver sends through its own clone of that cell (`GroupLink::send_now`), which answers
  `None` while the cell is borrowed, and the driver drops such a frame as one on a link not
  open (`LinkDropCause::NoTxSlot`), uncounted.

So every reply answered inside a read of those forms would be lost, where today's stage puts it
on a lane its writer takes after the read. The switch is not written on that premise. Two
structures answer it, and the choice is the main session's:

- **The receive apart from the send** (zenoh-pico's: its read task holds the receive lock and a
  reply's send takes the transmit lock, `vendor/zenoh-pico/src/transport/common/tx.c` @
  `static z_result_t _z_transport_tx_send_n_msg_inner(`): the cell's send and receive borrowed
  apart, which every `GroupTransport` would split (`split_receive` for every stack, the round
  form reading its half as the other form does), so a reply sent at once reaches the socket from
  inside the read. It touches each stack's transport and the round form's `Watched`.
- **A reply queue the step sends after its reads**: the reply admitted by the quota is encoded
  into bounded storage (what `Staged` is now: the bodies in one ring, the framing beside them)
  and sent with `send_at_once` by the pump after the read loop and by the holder after its call;
  the lanes, `LaneRing` as lanes, `Record`, `next_out`, `StageQueue` and the stage's writer
  still go. It keeps one owned store the first structure removes, and leaves the stacks alone.

Expected of either: the switch's bytes as 20.1 states them, less the reply queue's code in the
second. Until the ruling the stage stays as it is, and the steps after it that read the switch
(the D2 rows, F8b) wait with it.
