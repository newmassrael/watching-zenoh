# Formal models of wz: the promises are written here, and SCE's judge checks them once wz pins it

Status: plan and first model, 2026-11-27. No configuration here has been run by TLC yet (section 4).

wz is to be generated from SCE documents for Rust and C, and checked with TLA+ as SCE ADR 0115 lays
out (`vendor/sce/docs/adr/0115-*.md`): a promise module (level 1) says what a user may rely on, a
protocol model refines it (level 2), each part of the protocol has a configuration that takes it
out and must fail, and progress is stated with the fairness it stands on. Levels 4 and 5 (a model
generated from a document, a recorded run read against it) are SCE's to build; wz writes the
promises those levels will be held to.

## 1. What is here

| File | Level | What it says |
|---|---|---|
| `QueryFinalService.tla` | 1, promise | A query that reached a session is refused whole (no callback ran, nothing sent, not even a Final) or answered: each queryable's callback at most once, replies only after a callback ran, then exactly one Final and nothing after it |
| `QueryFinals.tla` | 2, protocol | How the session keeps that promise: the table of held Finals (`FinalHolds`, `crates/wz-session-core/src/query_plane.rs`), the Final the dispatch owes, a query a program keeps, the own get's row. `Refines` checks it against the promise |
| `QueryFinals*.cfg` | bounded exploration | Two queries (one in the two live runs), two queryables, one row; one configuration per part taken out |
| `ResetOnceService.tla` | 1, promise | A peer's reset ends its session only when its generation is later than every one that ended a session of that peer; a retransmission or an older reset ends nothing and is a duplicate of the last; a peer is refused for want of room only when none of its resets was taken |
| `ResetGenerations.tla` | 2, protocol | How a node keeps it: the table of reset generations (`sources/algorithms/take_generation.scxml`, `crates/wz-session-core/src/reset_generations.rs`), which both profiles run. `Refines` checks it against the promise |
| `ResetGenerations*.cfg` | bounded exploration | Two peers, generations 0 to 2, a table of one; one configuration per part taken out |
| `SecondLinkService.tla` | 1, promise | Two nodes that dial each other at once: each link carries or is closed before it carried anything, at most one carries, and once both are decided one does |
| `SecondLinks.tla` | 2, protocol | The two nodes' link books (S1 55): the initiator's and the acceptor's reservations, the initiator's confirmation, the zid rule. `Refines` checks it against the promise |
| `FaceCollisionService.tla` | 1, promise | The faces a loop holds to one node: at most one, and the routing graph holds a link to the node exactly while one is held |
| `FaceCollisions.tla` | 2, protocol | The tokio loop's collision tables (S4 26): a kept link parked behind the face it replaces until that face's departure is processed, a third link refused meanwhile |
| `SecondLinks*.cfg`, `FaceCollisions*.cfg` | bounded exploration | Two crossing links, every order of their six steps; three links to one node, each kept or refused |
| `E2eCounterService.tla` | 1, promise | A receiver of one stream of end-to-end protected frames judges each frame by what it is: the baseline's message again a repetition, 1 to `max_gap` messages on in range with the exact count of messages lost, further on out of range; a message the sender refused is never counted as lost |
| `E2eCounters.tla` | 2, protocol | How the two ends keep it: the sender's counter and its rollover (`sources/algorithms/counter_after.scxml`), and the receiver's step and verdict (`e2e_counter_step`, `e2e_counter_verdict`). `Refines` checks it against the promise |
| `E2eCounters*.cfg` | bounded exploration | A two-bit counter made with 1, nine messages (twice round the ring), a gap of two, under `Wrap` and under `Refuse`; one configuration per part taken out |
| `FragmentPacingService.tla` | 1, promise | A paced writer's fragments: at most `Burst` in a row each less than `Gap` after the one before, none delayed past the gap after the last write, a datagram that is not a fragment never delayed, and `Burst` fragments let through between two waits |
| `FragmentPacing.tla` | 2, protocol | The pacer (S1 29): the rule `sources/algorithms/fragment_pacing_wait.scxml`, its run taken and given back. `Refines` checks it against the promise |
| `FragmentPacing*.cfg` | bounded exploration | A burst of two, a gap of three, six datagrams of either kind over five ticks; one configuration per part taken out |
| `PicoApiService.tla` | 1, promise | What a program written to zenoh-pico's API may rely on: a session opened and closed, declarations and their undeclaration, the samples a put or a delete delivers by reliability and congestion control, a get's replies and its one end (`QueryFinalService` instantiated whole as the queryable's clause), what a liveliness subscriber is told; the network's faults as environment |
| `PicoApiService*.cfg` | bounded exploration | One of each over one session; three samples of one publisher on two keys in every class; two tokens and two liveliness subscribers; two gets reaching two queryables; one configuration per assumption taken out |
| `models.json` | manifest | Every module and configuration, in the format of SCE's `schemas/sce-formal-models.v1.schema.json` (`"v": 1`, no tool pin) |

## 2. Each part of the query's Final has a configuration that fails without it

The mechanism is S7 13 of `docs/zenoh-logic-as-sce-kinds.md` (W16): the table of held
`ResponseFinal`s, bounded by `MAX_PENDING_FINALS` since 2026-11-22. It is chosen because it is
to move into an SCE document (`map<record:FinalKey, record:FinalHold>[N]`), its order of a
reply and a Final runs across threads, and both upstream presets state the same promise: zenoh
sends the Final when the last `Query` is dropped, zenoh-pico when the last reference to its query
is dropped, and sends nothing for a query it cannot build (the citations are in the module's
head).

| Part (constant) | What it keeps | Without it TLC is to find | Promise |
|---|---|---|---|
| `Hold` | the Final waits for the last hold | a reply after the Final (`NothingAfterFinal`) | broken |
| `ReplyKeeps` | a reply to a kept query holds a keep of its own | a reply after the Final, the program letting go from another thread | broken |
| `Sticky` | a query refused at one queryable stays refused in its dispatch | a refused query whose callback ran (`RefusedSilent`), a row having come free meanwhile | broken |
| `OweRefused` | a refused query is sent no Final | a refused query sent a Final (`RefusedSilent`) | kept |
| `RefuseFull` | a query with no row left is refused before its callback | a table past its rows (`Bounded`) | kept |
| `GiveBack` | a hold whose call was not begun is given back | a state from which no query's row can be freed (`NoRowHeld`, D9) | kept |

`Ends` (every query that arrived is answered or refused) holds under `LiveSpec` and fails
without its fairness (`QueryFinals_live_without_fairness.cfg`).

Not modelled: a query's link lost, under which nothing is sent (`query_plane.rs` lines 32-37); a
second keep of a kept query; the own get's answers, of which only its row is modelled.

## 2a. Each part of the reset's duplicate suppression has a configuration that fails without it

The mechanism is S5 M5 and S2 30 of `docs/zenoh-logic-as-sce-kinds.md` (section 7.1): the table
of reset generations, whose rule is the SCE algorithm `take_generation`, run by the heap profile
over a map in `Heap` storage (S2 30); the fixed-memory profile's connect manager keeps the same rule
over its own table (S5 M5), so the model is of both. Neither upstream preset has a lifecycle reset; the promise is that of at-most-once
calls (Birrell and Nelson, 1984), decision D6 of `docs/session-lifecycle-intent.md`.

| Part (constant) | What it keeps | Without it TLC is to find | Promise |
|---|---|---|---|
| `Remember` | a later generation is written over the one held | a later generation taken twice (`AtMostOnce`) | broken |
| `Latest` | a reset is a duplicate when the generation held is as late, not only equal | an older reset ending a session after a later one (`AtMostOnce`) | broken |
| `NeverEvict` | a full table refuses a new peer and evicts none it holds | an evicted peer's retransmission taken again (`AtMostOnce`) | broken |
| `RefuseFull` | a full table takes no new peer | a table past its room (`Bounded`) | kept |

Not modelled: progress, since a reset is asked by a peer and answered in the same step; the
lifecycle permit, which `lifecycle_verdict` judges before the table is asked.

### The second link and the faces to one node (2026-11-28)

Written for the rule S1 55 holds and the tables S4 26 holds, ahead of their move into SCE
documents, which waits until the move keeps their size.

| Module | Part (constant) | What it keeps | Without it TLC is to find | Promise |
|---|---|---|---|---|
| `SecondLinks` | `ZidRule` | two crossing links are judged by the zids | both links refused (`OneWhenSettled`) | broken |
| `SecondLinks` | `EstablishedHolds` | an established row keeps its place | both links carrying (`AtMostOne`) | broken |
| `FaceCollisions` | `Park` | a kept link waits for the face it replaces to leave | two faces to the node (`OneFace`) | broken |
| `FaceCollisions` | `ThirdRefused` | a link to a node whose face is closing is refused | a kept link parked behind no face (`NoneLost`) | kept |

Not modelled there: links that went the same way and a superseded row's own refusal at the
confirmation, which with two crossing links decides no order (the loser is refused at its
acceptor first); the release of a closed link's rows; a face that cannot be closed alone; the
progress of a parked link, which waits on the departure of a face asked to close.

### The end-to-end counter: the sender's rollover and the receiver's verdict (2026-11-28)

Written with the move of the two senders' rollover rules into one SCE algorithm (W12, S11 3 and
S10 8): `counter_after`, asked by the end-to-end stream sender with `Wrap` restarting at 0 and by
the segment sender with `Restart` at its first number. Neither upstream preset has an end-to-end
counter; the frame is the application's payload.

| Part (constant) | What it keeps | Without it TLC is to find | Promise |
|---|---|---|---|
| `RefusalKeeps` | a refused message does not ask `counter_after`, so consumes no value | the next frame judged one message further on than it is, a loss that never happened (`Exact`) | broken |
| `WrapToZero` | past the largest value the stream sender restarts at 0, the bottom of the ring the receiver takes its step in | the frame after the wrap judged two messages on (`Exact`): a restart at the first number, the segment sender's rule, is right only for a reader that tells transfers apart by the number changing | broken |
| `RepeatAtZero` | a step of 0 is a repetition (`e2e_counter_verdict`'s first guard) | the baseline's frame again judged in range (`Exact`) | broken |
| `GapBound` | a step is in range only up to `max_gap` (its second guard) | a frame past the gap judged in range (`Exact`) | broken |

Not modelled: a stream that loses a whole ring of frames in a row, which no counter of that width
can tell from one that lost none (the promise's `Horizon`); a reordered stream; `set`, which puts
the value a caller names on the next frame; the profile's rule that keeps the baseline on a step
out of range, the joined report of a repetition and a step out of range, the CRC and the timeout.
The test `across_the_wrap_the_receiver_reads_every_loss_and_repetition_the_sender_made` of
`crates/wz-app-frame/src/e2e_rules_tests.rs` runs the same sequence on the code.

### A writer's fragment pacing (2026-11-28)

The mechanism is S1 29 of `docs/zenoh-logic-as-sce-kinds.md`: the `datagram-fragment-pacing`
policy's pacer, whose rule moved into the SCE algorithm `fragment_pacing_wait` the same day.
Neither upstream preset paces fragments; the promise is what a sender over a paced link relies on.

| Part (constant) | What it keeps | Without it TLC is to find | Promise |
|---|---|---|---|
| `Hold` | a fragment past the burst waits for the gap | three fragments written at one time (`Spaced`) | broken |
| `EndRun` | a datagram that is not a fragment ends the run | a fragment held just after one that is not a fragment (`LetsBurst`) | broken |
| `Restart` | the run starts again at one after a held fragment | two held fragments in a row (`LetsBurst`) | broken |
| `Subtract` | a held fragment waits the gap less the time already passed | a fragment written later than the gap after the last write (`BoundedDelay`) | broken |

Run by hand with TLC 1.7.4 on 2026-11-28, outside the judge: the holding configuration found no
violation in 57162 distinct states and refines the promise, and each configuration with a part
taken out found the violation the table names. Not modelled: a timer that wakes late, a clock
that goes back, and the time a write takes (the module's "Taken as given").

### The API of the zenoh-pico preset (2026-11-28)

`PicoApiService` is the top of the owner's goal of 2026-11-28, that the whole library refines a TLA+
statement of its API: what a program written to zenoh-pico 1.10.2's API may rely on, with no
mechanism in it, each clause read against the upstream source it cites in its head. The network
is environment, with the faults of a channel of SCE ADR 0115 D7 (amended 2026-11-23), and the
module says what a user sees of each: a duplicated frame nothing, a reordered frame a loss, a
lost frame a loss, a link lost whole a `Break`.

What it promises by a sample's class, while the link to the subscriber's session holds:

| Class | May be lost | Order | Repetition |
|---|---|---|---|
| best effort | any sample | the order put, per publisher and channel | none |
| reliable, congestion control DROP (a put's default) | any sample | the same | none |
| reliable, congestion control BLOCK | none (`ReliableNoGap`), given a stream link | the same | none |

A loss of the link may lose every sample in flight, of every class.

Its manifest entry is not `abstract`: the judge refuses an abstract module that nothing refines,
and the model that is to refine this one is the system model SCE's D7 generates and D12 composes,
which is not built. Until then the module is run by itself, to show what each of its checks stands
on. Its "parts" are its assumptions and the one clause of the API that a check stands on, each a
constant a configuration takes out; none of them is a mechanism. When the system model exists, the
entry becomes `abstract` and these runs move to the model that refines it.

| Assumption or clause (constant) | What it keeps | Without it TLC is to find |
|---|---|---|
| `WaitsForCallbacks` | close and an undeclaration return after the last run of the callbacks they end (the clause of close and undeclare) | a sample given to a subscriber after its undeclaration returned (`NothingAfterGone`) |
| `OneRoute` | the samples of a publisher reach a subscribing session over one chain of links; zenoh-pico judges order and repetition per peer | a later sample given before an earlier one (`InOrder`), and a sample given twice (`AtMostOnce`), one configuration each |
| `StreamLink` | the link under a reliable channel loses only whole (TCP, TLS); zenoh-pico takes a reliable frame by its order alone and asks for none again | a reliable BLOCK sample lost while the link held (`ReliableNoGap`) |
| `TimelyLink` | a link that holds delivers within the lease | a DELETE told of a token alive while its link held (`NoFalseDeath`) |
| the fairness of `LiveSpec` | a get's timeout comes | a get left waiting for ever (`GetsEnd`): no Final need come, and a query refused at its queryable is sent none |

Run by hand with TLC 1.7.4 on 2026-11-28, outside the judge (exit 0 holds, 12 an invariant
violated, 13 a temporal property violated):

| Configuration | Exit | Distinct states | Found |
|---|---|---|---|
| `PicoApiService.cfg` | 0 | 974934 | no violation |
| `PicoApiService_samples.cfg` | 0 | 492734 | no violation |
| `PicoApiService_liveliness.cfg` | 0 | 10284 | no violation |
| `PicoApiService_queries_live.cfg` | 0 | 21484 | no violation, `GetsEnd` holds |
| `PicoApiService_samples_without_waits.cfg` | 12 | 3234 | `NothingAfterGone` |
| `PicoApiService_samples_without_one_route_order.cfg` | 12 | 12492 | `InOrder` |
| `PicoApiService_samples_without_one_route_once.cfg` | 12 | 3030 | `AtMostOnce` |
| `PicoApiService_samples_without_stream_link.cfg` | 12 | 2678 | `ReliableNoGap` |
| `PicoApiService_liveliness_without_timely_link.cfg` | 12 | 199 | `NoFalseDeath` |
| `PicoApiService_queries_live_without_fairness.cfg` | 13 | 21484 | `GetsEnd` |

The states of a violating run are those TLC had found when it stopped, and depend on its workers.

What the mechanism promises above refine of it. Each is a hand model today; the system model that
would compose them under this promise is SCE ADR 0115 D7's, generated from the documents, and not
built.

| Mechanism promise | The part of the API promise it refines | Protocol model that refines it |
|---|---|---|
| `QueryFinalService` | QUERIES at the queryables' session, whole: `PicoApiService` instantiates it (`QF == INSTANCE QueryFinalService`) and takes each of its steps under the session's guards, so every behaviour of the API promise is one of it on that clause | `QueryFinals` (`Refines`) |
| `ResetOnceService` | `Break`: a peer's reset ends its session at most once per generation, so a retransmitted or older reset is a duplicated frame, which a user sees as nothing, and not a second loss of the link | `ResetGenerations` |
| `SecondLinkService` | `OneRoute` between two nodes that dial each other at once: one link carries, so samples and declarations between them travel one chain and none is seen twice | `SecondLinks` |
| `FaceCollisionService` | `OneRoute` at a router: at most one face to a node, and the routing graph holds a link to it exactly while one is held | `FaceCollisions` |
| `FragmentPacingService` | `TimelyLink`, in part: `BoundedDelay` bounds the delay a paced writer adds to a datagram by the gap, a part of what a link must keep within the lease | `FragmentPacing` |
| `E2eCounterService` | none: end-to-end protection is past the pico preset; it makes the losses SAMPLES allows countable to the application that reads the payload | `E2eCounters` |

Not modelled: a liveliness subscriber's history and the liveliness get; consolidation, except
that with `LATEST` the replies are given at the Final and none at a timeout, which the promise
allows; the key expression algebra past equality and one subscriber every key intersects; a
query's target and the keys of queryables; payloads, encodings, attachments, timestamps; matching
listeners and the advanced publisher and subscriber; the close of a publisher's or a token's own
session, which is their undeclaration here; a publisher and a subscriber of the same session,
whose delivery is within the session and is one the promise allows.

## 3. The judge is SCE's, and the SCE revision wz pins cannot run it on this manifest

- At wz's pin (`vendor/sce` at 2d736122d01, SCE's main on 2026-11-27) the judge is
  `scripts/formal/models.py`. It reads one manifest, its own tree's
  (`ROOT = Path(__file__).resolve().parents[2]`, `MANIFEST = FORMAL / "models.json"`, lines 58-60),
  and has no option for another (`--self-test`, `--record`, `--only`, `--shard`, `--workers`).
  Running it by its path from the vendored tree is the plan SCE ADR 0146 rejected: a path and keys
  that no contract states, and a second runner of TLC beside the generator's.
- The judge wz runs is `sce-codegen formal models --manifest <file>` (SCE ADR 0146, D1 and D7). It
  reads the modules beside the manifest, pins TLC 1.7.4 by digest in
  `sce-build/src/formal/toolchain.json`, fetches nothing (`sce-codegen formal install` does),
  refuses a manifest that names a tool, and leaves with 15 when a tool is missing. It is on SCE's
  branch `adr0144-formal-judge` (92dee02bf86), item 446 of SCE's landing queue, and not yet on
  SCE's main.
- What SCE has to land for wz: that branch on its main. Levels 1 and 2 need nothing more.

## 4. Order of work

1. Done: the promise and the protocol of the query's Final (sections 1 and 2).
2. When item 446 is on SCE's main: move `vendor/sce` to it; build `sce-codegen` from the pin
   (`cargo build --bin sce-codegen --features cli -p sce-build`); `sce-codegen formal install
   --tool tlc`; `sce-codegen formal models --manifest docs/formal/models.json --record`, which
   writes the two holding runs' counts of distinct states that `models.json` does not record yet
   (the judge refuses a holding run without one), and read the diff; then the same command without
   `--record` must exit 0. Then register it as a lane: exit 1 is a verdict, 15 is "could not run"
   and no pass.
3. Promises of the next mechanisms, level 1 first: the declaration sync (S2 44 of
   `docs/zenoh-logic-as-sce-kinds.md`) and the unicast link (`sources/session/unicast_link.scxml`).
   The link is an SCE document already, so its protocol model is the one D7 generates; only its
   promise is written by hand.
4. When SCE builds D7 (`sce-codegen model`): the table of held Finals moves into an SCE document,
   and the model generated from it must refine `QueryFinalService`, as `QueryFinals` does now.
5. When SCE builds D4 and D8 (`sce-codegen formal traces`): runs recorded from the Rust engine
   (`crates/wz-capi-coop`) and from the C11 lane are read against the generated model.

## 5. What the models stand on

- TLC 1.7.4, as SCE's judge pins it, and the Java that runs it.
- The bounds of a configuration: two queries, two queryables, one row, one reply. An error past
  them is not found.
- The lines under "Taken as given" in `QueryFinals.tla`: which lock each step holds, read from the
  code at this revision. A change of the code that moves a lock moves the model's ground, and no
  check says so until level 5 reads runs of the code.
- That the promise is what a querier and a queryable rely on. A person reads it.
