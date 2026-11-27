# Migration lane arch-l0-driver: section 5 step 6 of the target architecture

Lane of `docs/c-abi-architecture.md` section 5, step 6 (**Thin driver, L0**): the engine crate keeps
only the wait set, the timers and the read task, and each fact the cooperative engine holds goes to
the layer that owns it. This file is the lane's design; the architecture document is not edited
here (five lanes work beside each other). The size case is `pico-client-coop-nostd`
(`deploy/size_ledger.json`), whose engine is the direct read (`cfg(not(wz_round))`: no
`threads`, `crates/wz-capi-coop/build.rs`), so what only the round compiles moves no byte of it.

## 1. What of step 6 has landed

| step | state | where |
|---|---|---|
| 6a region | landed (`8ddd057e3a`, "Lend each layer's tables from its own rows") | `crates/wz-capi-coop/src/arena.rs`: `TransportRows`, `SessionRows`, `PlaceRows`, each with `lent_from`; `SessionArena::lender` opens the one `TableLender` (`wz-session-core/src/bounded.rs`); `lend_session` in `engine.rs` lends the three in turn and asks the one refusal at `lend.finish()` |
| 6a residue | open, no bytes | the rows' types and the lend are in `wz-capi-coop`, not in the L0 crate (`wz-runtime-coop`); moving them is a file move, held for after 6b, which changes `TransportRows`' users least when done last |
| 6b face lifecycle | partly in the tree before this lane | the life of a link is a sans-I/O value already: `UnicastLink` (`wz-session-core/src/link_life.rs`, machine `unicast_link.scxml`, `6b0a9f6d7e`) answers each input with `Effects`; `UnicastTransport` (`unicast_transport.rs`, `bd54e874cb`) holds a life, a receive and the timers as one value, but the cooperative engine builds it over `MadeLink` (no life) and keeps each face's life in the face record |
| 6b-1 | this lane's first step, committed with this file | section 4 |
| 6c sending, 6d session state | not this lane's first steps | 6d goes with phase 4 (lane arch-l3-rows) |

## 2. The layers that overlap in a face's lifecycle now

Each row is a fact of a face's link and every place that holds or recomputes it. "Owner" is the
layer section 5 step 6 gives it.

| fact | held by | owner | overlap |
|---|---|---|---|
| where the link stands | `UnicastLink` in `Face<C, L>::life` (`wz-capi-coop/src/engine.rs`, reached through `FaceRecord::life` of `wz-runtime-coop/src/faces.rs`) | L2 | each interpreter of `Effects` read `life.phase()` before every input to know which endpoint an ended handshake was dialled to (`CoopEngine::drive_link` in `engine/direct.rs`; `Core::poll_face`, `give_face`, `carry_out`'s `was` in `engine.rs`): a copy of L2's state kept by L0 to carry out L2's answer. Removed by 6b-1 |
| a dial under way given up | `UnicastLink`'s `DialStage::Pending` and its deadline (L2); the stack's dial in `Link::Dialing(Dial)` of the face record (L0, the I/O handle) | L2 decides, L0 drops the handle | the direct read inferred the give-up from three other effects (`dial() \|\| backs_off() \|\| ends_session()`) and asked `LinkSupervisor::end_dial` whether a dial was there. Removed by 6b-1 (`Effects::gives_up_dial`) |
| the endpoint a dial reached | the life's row (L2); `DialEndpoint` in `Dial` (`faces.rs`), in `DirectSlot::opened` (`direct.rs`) and in the round's `ReadDial::dialled` (`engine.rs`) | L2 | in a build without `listen` every `DialEndpoint` is `Listed(row)` with the life's row: one fact in three places. 6b-3 |
| the made link before its handshake | the life's `DialStage::Made` (L2); `DirectSlot::opened` / `ReadDial::answer` (L0, the socket) | L0 holds the handle | the handle crosses one turn of the carrier's loop only because the protocol is two inputs (`DialMade`, then `begin_handshake`); kept, its endpoint goes with 6b-3 |
| why the walk over the endpoints ended | `DirectSlot::last: Option<OpenError>` (`direct.rs`), the round's `last: &mut OpenError`; each holds an `EndpointRefusal` with a `LocatorText` of `MAX_LOCATOR_LEN` bytes | L2 (the endpoint row and the cause), L4 (the text the door prints) | written at every refusal (`keep_refusal`, `dial_row`, `answered`, `begin_handshake`), read once when the life ends the session. 6b-4 |
| when the life is next looked at | `UnicastLink::wake_at` (L2); `DirectSlot::life_due_us`, `DirectFace::due_us` (with `listen` or `group`) | L0 (the timer table), written only from L2's answer | the cache is L0's wait-set entry and stays; L0 also writes it itself (a pump that ended: now; an attach's dial: 0). 6b-5 hands the wake back with `Effects` |
| the handshake completed, the link ended | the link session's machine (`LinkActions::is_established`, L2), `FaceFacts::ended` and `facts` (`engine.rs`, L3), the life's `Handshaking` to `Up` (L2), `EndFlags` (`direct.rs`) | L2 | L0's `DirectSlot::next_input` translates one L2 machine's state into another's input every look. 6b-6 |
| the order the effects are carried out in | `CoopEngine::drive_link` (direct) and `Core::carry_out` (round): two copies of the same loop (feed the I/O's answer back as the next input, read the clock after the I/O) | L2 | 6b-2 |
| the face's row | `LinkSupervisor` (`faces.rs`: life, link, dials, ports), `DirectFaces` / `DirectSlot` (`direct.rs`: pump, router, opened, last, dues), `Face<C, L>` (`engine.rs`: id, link, life, replay, facts, told) | L2 (life, endpoints), L0 (pump, waits), L3 (replay, facts, told) | three rows a face in three crates; the target keeps one row per layer, each the only holder of its facts |

## 3. Target form

- **L2** (`wz-session-core`): one face life value per face: `UnicastLink` with the walk over the
  endpoints, the dial stage, the deadlines and the refusal of the walk (endpoint row and cause, a
  `Copy` value of a few bytes). Each input is answered by `Effects` that name what they are about
  (the endpoint whose dial or handshake ended, the endpoint to dial, whether a dial is given up, the
  next wake), so the driver holds no copy of the life. One carrier of the effects, written once in
  L2, over an I/O trait the driver implements (dial, begin the handshake, end it, lose the link,
  bring it up, take the face out, read the clock).
- **L0** (`wz-runtime-coop` and the engine's driver half): the stack's dial handles, the made
  socket until its handshake is begun, the pump's place, the wait-set entry (the face's due), the
  task. No phase, no refusal, no endpoint of its own.
- **L3**: what a face's peer was told and declared (replay, facts, told), as now.
- **L4**: the refusal's text, built from L2's endpoint row and cause once the session ends.

## 4. Steps, each landing on its own

Bytes are estimates on the size case, area of the owner lines (`link_life` is read in the
driver's "link's turn" row of `docs/win-budget/size.md` section 2; `engine::direct` in sessions).
"Receive" is the count of instructions a message of `docs/win-budget/ir-receive.md` (about 3,073
on main); a life is told an input only where its link brings something or its own time came
(`life_turn`'s `moves_link`, false for an up link that brings nothing), so no step below is on a
sample's path. A step whose rows do not move by its estimate is reverted.

| step | change | bytes (estimate) | receive | holds it |
|---|---|---:|---|---|
| **6b-1** (landed with this file) | `Effects` names the endpoint of an ended handshake (`end_handshake() -> Option<usize>`, the row the input found the link at) and says when a dial under way is given up (`gives_up_dial()`, set only in `dialing`'s deadline arm); the interpreters read no `phase()` before an input, and the round's `carry_out` loses its `was` parameter; `UnicastLink::input` raises its event from one call of `drive` (the close was a second one) | -200 to -300 if the link machine's event push and turn were inlined at both `drive` sites of `input`, as the reading suggests (`size.md` 6.2: 519 bytes of `process_event` in `UnicastLink::input`, against about 260 a copy for the session machine's in 6.3), about 0 if they were one copy already; `drive_link` -10 to -40 for the phase read and the three-way test; `Effects` grows from 16 to 32 bytes, free where `input` is inlined into its one caller of the case, +10 to +20 if it is not | 0 | `link_life::tests::the_end_of_a_handshake_names_the_endpoint_it_was_dialled_to_not_the_next`, `only_an_unanswered_dial_at_its_deadline_is_given_up`, the existing `link_life` tests (now asserting the row), `wz-capi-coop` `tests::dial_in_flight`, `tests::redial_heap`, the redial example of `ff624fa978` |
| **6b-2** one carrier | `link_life::carry(life_at, input, now, io: &mut impl LinkIo) -> Result<Carried, Ended>` holds the loop and the order; `drive_link` and `carry_out` become `LinkIo` impls (the life reached by `io.life()` each turn, as the face's row is re-read now) | case: -50 to +50 (one instance, the same work); round build about -1.5K (`carry_out`'s loop goes) | 0 | the `link_life` tests over a recording `LinkIo` (the order of every effect, the input fed back, the clock read after the I/O), the direct and round engine tests |
| **6b-3** the dial's endpoint is the life's row | without `listen`, `Dial` and `DirectSlot::opened` carry no `DialEndpoint`; the refusal's text is read by the life's row | -50 to -150; one word less a face slot | 0 | `faces` tests of `answer_face_dial` on both forms; a build without `listen` |
| **6b-4** the walk's refusal is L2's | the life keeps `WalkRefusal { row, cause }` (`Copy`); `DirectSlot::last` and the round's `last` go; `OpenError` is built once, when the life ends the session | -200 to -500 (the `OpenError` writes and moves at each refusal); `MAX_LOCATOR_LEN` plus about 16 bytes less a face slot | 0 | the session-end refusals of `tests.rs` (`NoAnswerInTime`, a refused dial, a lost link, no task, no entropy), each read off the refusal the open or the read returns |
| **6b-5** the wake with the answer | `Effects` carries `wake_at`'s answer; `life_turn` writes `life_due_us` from it instead of a second call | -50 to -100 | 0 (written after `drive_link`, which an up link that brings nothing does not reach) | `link_life` tests comparing the answer with `wake_at` for every state |
| **6b-6** the life in the transport value | the face's link sessions run over `UnicastTransport<_, UnicastLink>`, persistent a face, so the transport tells its life `Established` and `Ended` itself; `DirectSlot::next_input`'s translation and `FaceFacts::ended` go | -1K to -2K | must not rise: `next_input` runs at every look; the design keeps the look of an up link that brings nothing at what it is (the face's row, a state compare, one atomic load) | `unicast_transport` tests; the direct engine's receive tests; the receive count read before landing |

6b-1 to 6b-5 touch `link_life.rs`, `engine/direct.rs` (`drive_link`, `DirectSlot`), `engine.rs`
(`poll_face`, `give_face`, `carry_out`) and `faces.rs` (`Dial`, its tests); 6b-6 touches
`session_drive.rs` and `unicast_transport.rs`. `engine/direct.rs` is shared with the lanes of
`docs/win-budget` section 9.3 (S-PLAN, H3, T-READ): each step here changes `drive_link`,
`DirectSlot` and its `next_input` alone.

## 5. What 6b-1 changes in behaviour

- A taken face (`listen`) whose attached dial is given up at its deadline has the dial let go of
  and its refusal kept before the face is taken out; before, the face was taken out with the dial
  still in its record, which the removal dropped. The session's refusal is the dial role's, so
  nothing a program reads changes.
- Everything else is the same answer read from another place: the row the life stood at, and the
  deadline arm that alone gives a dial under way up.
