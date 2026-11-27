# Deterministic tests: a flake the test cannot express

Status: design note, 2026-11-27. It states the cause of the flake that started it, the census of
where tests touch nondeterminism, the target structure, the layer rule and the gate that holds
it, and the order of the migration. The first step (the simulated world and the step tests on
it) is built; the rest is the plan. Like the other notes under `docs/`, the atomic store does not
parse it.

The owner's instruction: a flake is to be made impossible by the structure of the test, not
lowered by retries, longer timeouts or settling sleeps. A unit test is a function of its script
and its seed. A run that fails fails on every run with that seed, and the seed is in the message.

## 1. What the step test found

`tests::step::a_session_without_its_read_task_round_trips_by_its_steps_alone` failed 3 to 4 runs
in 10 on main, in the build form of the `WZ_COOP_VALUE_LOCKS=off` lane (`wz_round`, with `listen`
and `group`). It ran over the host's UDP loopback against the router stand-in on a thread of
its own, waited on the wall clock (five seconds) and used a 100 ms sleep as its CONTROL.

### The path

A step bounded at nothing, `SessionDrive::step_once(engine, 0)`:

1. `CoopEngine::read_within` (`crates/wz-capi-coop/src/engine.rs:12251`, the round's form) asks
   `Core::idle_wait(0)` (`engine.rs:6230`). The bound is `idle_wait_ms.min(most_ms)`, zero, so
   it returns `IdleWait::None` before any wait is made (`engine.rs:6286`).
2. `step_after` (`engine.rs:9706`) hands that to `LinkSupervisor::waited`
   (`crates/wz-runtime-coop/src/faces.rs:2984`), which tells each link what a wait found only for
   `IdleWait::Input`: after a step that made no wait, no link is told anything.
3. In a build with `listen` or `group`, each link of the round sits behind a `RoundGate`
   (`crates/wz-capi-coop/src/round.rs:222`) that keeps what it knows of the link's stack
   (`Stack`, `round.rs:235`). A read that finds nothing turns `Look` into `Quiet`
   (`gave_nothing`, `round.rs:310`), and a step passes over a `Quiet` link that holds nothing
   (`passes_over`, `round.rs:303`; `try_recv`, `round.rs:360`).
4. Only two things make a `Quiet` link `Look` again: a wait that found its handle ready
   (`faces.rs:2993`) and a move of the links (`links_moved`, `faces.rs:3016`, called by
   `poll_links`, `engine.rs:5242`). `poll_links` runs from `move_links` (`engine.rs:5094`)
   only when the bookkeeping is owed (`engine.rs:9626`) and the links are not settled; an up
   link with no replay turn due settles at `u64::MAX` (`links_settle`, `engine.rs:5121`), and a
   settled session owes no bookkeeping until a count it follows moves.

So once the links have settled and one step bounded at nothing found the link empty, no step
bounded at nothing reads that link again: what arrives after is passed over for as long as the
program steps that way. A read task, or any step with a bound above zero, waits, and the wait
re-arms the gate; that is why the lease test (bound 10) and the two-thread test (bound 5) were
never seen to fail, and why the direct read (`not(wz_round)`) and a round without `listen` and
`group` (whose gate keeps no `Stack`) are not affected.

### The race in the test

The open returns with the link `Look` (its last move). The first step after the declaration reads
the empty link (`Quiet`), then runs the bookkeeping a new ledger owes (`ledger.rs`,
`Ledger::new`), which moves and settles the links (`Look`). If the stand-in's thread counted the
declaration before the test thread's second step, the loop ends with the link `Look` and the push
is read: green. If the stand-in had not, the second step reads the empty link (`Quiet`), nothing
moves the links again, and the push waits unread until the five seconds end: red, "timed out
waiting for the push". The window is one step of the test thread against the stand-in thread's
schedule, which the lane's parallel tests widen.

This is a defect of the engine, not of the test: a program that drives its session with steps
bounded at nothing (a cooperative main loop that never blocks) stops receiving in that build form.

### How the main session confirms it (bx, 50 runs each)

All on main's tree, in the lane's form (`WZ_COOP_VALUE_LOCKS=off`, features
`app-transport,group,listen,liveliness,local-subscriber,query,queryable`), filter
`tests::step::a_session_without_its_read_task_round_trips_by_its_steps_alone`, unless stated:

| Run | Change to the old test | Expected |
|---|---|---|
| A | none | about a third red, every red "timed out waiting for the push" |
| B | the push's wait bounded at 1 ms (`steps_until(&engine, 1, "the push", ..)`) | 0 red: the wait re-arms the gate |
| C | `for _ in 0..4 { SessionDrive::step_once(&*engine, 0).unwrap(); }` before `router.send(Command::Push(..))` | 50 red: the gate is `Quiet` before the push on every run |
| D | none, default features (value locks, no round) | 0 red |

The same mechanism is one deterministic test,
`tests::step::a_step_bounded_at_nothing_reads_what_came_after_a_step_found_nothing`: red on its
first run in the round's form with `listen` or `group` without the fix below, and run in every
form.

The same holds for a port a session listens on, in either form: once a wait has named the port
(the open's own wait does, for a session that dials as well), the port is asked for a connection
only after a wait found it ready (`LinkSupervisor::accept_at`), so a program that steps only
bounded at nothing never asks it again.

### The fix

A wait of no time is still a wait: bounded at nothing, a read waits for no input, but it still
looks at the links and ports, and what the look finds ready is told to them as any wait's is.

- `LinkSupervisor::idle_wait` (`crates/wz-runtime-coop/src/faces.rs`) makes a wait bounded at
  nothing `IdleWait::Input { on, ms: 0 }` over the same entries, one poll of no time whatever
  their count; with nothing to wait on it is `IdleWait::None`, as before.
- `Core::idle_wait` (`crates/wz-capi-coop/src/engine.rs`) hands a bound of nothing on where a
  step reads only what a wait found ready: `listen` (the ports), and `group` in the round's
  form (the gate). Elsewhere a step reads every link and group as it is, and the read makes no
  wait, as before. A group's burst (`group_took`) still makes none: the move that ends it has
  each link read again.

Only a wait bounded at nothing changes. A read whose bound is above nothing (the read task's
wait, the arm the receive measurements wait in) takes the same path as before, and a read that
finds input held makes no wait before the bound is looked at, as before.

### What the lane's form found next

Run in the lane's form with the fix, the three step tests that receive a push from the stand-in
(the round trip, the lease, and the step bounded at nothing) were red on every run, whatever the
bound of their steps (the lease test steps bounded at 10 ms). The cause was the simulated world,
not the engine. The round's form reads a record's parts only where its link lent them (`place` in
`wz_session_core::round`, which keeps no area to copy a part into), and the first simulated ends
copied each datagram out of the network and let the copy go, so every sample with a payload was
refused there. Every link the engine opens on a host lends its datagram from a buffer of its own
until its next receive (`lends_until_next_receive`: the UDP, stream and serial drivers) and keeps
one its session stopped in (`keeps_input`); the simulated ends now do the same (section 3).

The engine's part holds as above: in the lane's form a step bounded at nothing makes a look of no
time (no early return under `listen`, nor under `group` in the round's form), and what the look
finds reaches each link's gate (`LinkSupervisor::waited`, `FaceSession::input_seen`,
`RoundGate::input_seen`). A group's burst (`group_took`) still makes no look; the bookkeeping,
owed at every step while the session holds a group (`links_settle`), moves the links once the
burst ends.

## 2. Census: where tests reach nondeterminism

Counted on origin/main `a9126d3242`, over the tracked `.rs` files whose path is a test's (a
`tests/` directory, `tests.rs`, `*_tests.rs`, `benches/`): 871 files, 826 in the crates below.
Each figure is the number of lines that match (`git grep -c -E`):

- clock: `Instant::now|SystemTime|thread::sleep|tokio::time::sleep|PosixClock`
- socket: `TcpListener|TcpStream|UdpSocket|PosixLinks|host_links\(|PosixTcpDial|\.bind\(|tokio::net::`
- thread: `thread::spawn|thread::Builder|tokio::spawn|spawn_blocking|#\[tokio::test`
- random: `rand::|thread_rng|getrandom|OsRng|PosixEntropy`
- process: `Command::new|process::Command`

| Crate | Test files | Files that match | Clock | Socket | Thread | Random | Process |
|---|---|---|---|---|---|---|---|
| `wz-integration-tests` | 342 | 291 | 648 | 191 | 143 | 0 | 757 |
| `wz-runtime-tokio` | 133 | 107 | 238 | 245 | 533 | 0 | 0 |
| `wz-capi-coop` | 48 | 37 | 345 | 142 | 26 | 62 | 0 |
| `wz-capi-pico` | 84 | 55 | 357 | 19 | 45 | 7 | 3 |
| `wz-capi-c` | 44 | 39 | 309 | 25 | 13 | 0 | 8 |
| `wz-ap-demo` | 23 | 21 | 70 | 5 | 16 | 0 | 29 |
| `wz-tls-mbedtls` | 10 | 9 | 29 | 65 | 6 | 2 | 2 |
| `wz-analyze` | 1 | 1 | 0 | 0 | 0 | 0 | 96 |
| `wz-replay` | 4 | 2 | 0 | 5 | 3 | 0 | 24 |
| `wz-capture` | 48 | 5 | 5 | 26 | 0 | 0 | 0 |
| `wz-capi-core` | 1 | 1 | 23 | 0 | 2 | 0 | 0 |
| `wz-rest` | 3 | 3 | 5 | 12 | 6 | 0 | 0 |
| `wz-link-lwip` | 2 | 2 | 0 | 12 | 1 | 0 | 0 |
| `wz-session-lwip` | 22 | 5 | 0 | 11 | 1 | 0 | 0 |
| `wz-session-core` | 32 | 6 | 1 | 4 | 2 | 0 | 3 |
| `wz-runtime-coop` | 5 | 1 | 0 | 7 | 0 | 0 | 0 |
| `wz-codegen-build` | 2 | 1 | 2 | 0 | 0 | 0 | 4 |
| `wz-host-net` | 2 | 1 | 3 | 3 | 0 | 0 | 0 |
| `wz-host-interop-tests` | 2 | 2 | 0 | 0 | 0 | 0 | 4 |
| `wz-capi-dissect` | 9 | 3 | 1 | 2 | 0 | 0 | 0 |
| `wz-zenoh-keyexpr` | 3 | 2 | 0 | 0 | 0 | 2 | 0 |
| `wz-ext-pubsub` | 6 | 1 | 0 | 0 | 1 | 0 | 0 |
| total | 826 | 595 | 2036 | 774 | 798 | 73 | 930 |

In `wz-capi-coop` the host's sockets are mostly behind the router stand-in of `tests.rs`
(`Router::start*`, `open(&router)`), which the socket column does not see: 31 of its 44 test
modules (`src/tests.rs` and `src/tests/*.rs`) start it, 307 starts in all. Per module, clock / socket / thread / random:

| Module (`crates/wz-capi-coop/src/`) | Clock | Socket | Thread | Random |
|---|---|---|---|---|
| `tests.rs` | 42 | 29 | 4 | 16 |
| `scout/tests.rs` | 28 | 15 | 1 | 0 |
| `tests/listen.rs` | 25 | 9 | 3 | 0 |
| `crates/wz-capi-coop/tests/tls_provider.rs` | 18 | 8 | 2 | 0 |
| `tests/dial_in_flight.rs` | 18 | 9 | 0 | 4 |
| `tests/group.rs` | 23 | 0 | 3 | 4 |
| `tests/arena.rs` | 11 | 14 | 0 | 5 |
| `tests/redial_heap.rs` | 11 | 12 | 0 | 7 |
| `tests/congestion.rs` | 18 | 0 | 2 | 0 |
| `tests/tx_pool.rs` | 14 | 5 | 1 | 2 |
| `tests/runtime_tables.rs` | 16 | 0 | 0 | 0 |
| `tests/host_group.rs` | 6 | 8 | 0 | 2 |
| `tests/direct_receive.rs` | 13 | 0 | 0 | 0 |
| `tests/one_thread.rs` | 6 | 6 | 1 | 2 |
| `crates/wz-capi-coop/tests/tls_sessions.rs` | 9 | 3 | 1 | 0 |
| `tests/program_clock.rs` | 8 | 4 | 0 | 2 |
| `tests/redial_wait.rs` | 4 | 7 | 0 | 2 |
| `tests/step.rs` | 9 | 0 | 1 | 0 |
| `tests/group_congested.rs` | 8 | 0 | 1 | 2 |
| `tests/queryable.rs` | 8 | 0 | 0 | 0 |
| `tests/ticker.rs` | 8 | 0 | 0 | 0 |
| `tests/local_query.rs` | 5 | 0 | 2 | 0 |
| `tests/replay.rs` | 5 | 2 | 0 | 2 |
| `crates/wz-capi-coop/tests/engine_rows.rs` | 3 | 4 | 0 | 2 |
| `tests/local.rs` | 2 | 0 | 4 | 0 |
| `tests/get.rs` | 4 | 0 | 0 | 0 |
| `tests/region.rs` | 2 | 2 | 0 | 2 |
| `tests/shared_key_ids.rs` | 2 | 2 | 0 | 2 |
| `tests/timestamps.rs` | 2 | 2 | 0 | 2 |
| `tests/decl_watch.rs` | 3 | 0 | 0 | 0 |
| `tests/direct_runtime.rs` | 3 | 0 | 0 | 0 |
| `tests/group_stack.rs` | 3 | 0 | 0 | 2 |
| `tests/advanced.rs` | 2 | 0 | 0 | 0 |
| `tests/app_listen.rs` | 2 | 0 | 0 | 2 |
| `tests/face_table.rs` | 2 | 0 | 0 | 0 |
| `tests/one_face.rs` | 1 | 1 | 0 | 0 |
| `tests/snapshot.rs` | 1 | 0 | 0 | 0 |

What the count does not see, to be audited per crate as it migrates:

- inline `#[cfg(test)] mod tests` inside product files (counted nowhere above);
- the iteration order of a hash map with a random hasher (`wz-session-core` names `HashMap` or
  `HashSet` in 35 files: each is either a fixed hasher or a map whose order no output reads);
- the engine's own real sleeps (`sleep_ms` of an `IdleWait::Sleep`), which cost wall time and
  decide nothing in the simulated world, since its clock does not move with them.

## 3. Target structure: the simulated world

The engine is already generic over everything a test needs to own: `CoopEngine<L, C>` over any
`SessionLinks<LinkCount>` and any `ClockSource` (`tests::tx_pool` opens
`CoopEngine<SlowLinks, PosixClock>`; `tests::program_clock` a clock the test sets), its entropy is
a parameter of the open, and its waits are the stack's (`SessionLinks::waits`, `LinkWaits`).
`crates/wz-capi-coop/src/tests/sim.rs` puts one world behind those seams:

- **Network**: an in-memory network of datagram ends (`Net`, `SimEnd`, `SimLinks`), keyed by
  address and port, with the peer binding of a real datagram link
  (`wz_session_core::datagram_peer`) and the outbound slots a lend-only session needs. A
  datagram for an end nobody bound is lost, as UDP loses it. An end receives as the host's
  datagram link does: it lends each datagram from a buffer of its own, where the datagram lies
  until the end's next receive, and lends one its session asked it to keep again
  (`lends_until_next_receive`, `keeps_input`).
- **Waits**: the session's ends are waited on by their owner (`input_wait`), as the host's links
  the engine opens are (`waited_by_owner`). A wait (`SimWaits`) takes no time: it turns the world,
  then finds ready exactly the ends that hold a datagram.
- **Clock**: `SetClock`, which moves only when the test moves it (`Sim::advance_ms`); the session
  and the stand-in read the same one.
- **Entropy**: drawn from the test's seed (splitmix64), a second stream for the stand-in.
- **Peer**: the router stand-in (`StandIn`) is a plain acceptor session on a local set of the
  test's own thread. It runs when the session waits, or when the test turns the world
  (`Sim::turn`); a turn passes its local set until eight passes in a row move nothing.
- **Guards**: counts, never time. A wait for an outcome makes 4,096 steps at most, a turn 1,024
  passes, and 100,000 waits in a row on a world that never moved fail the test: a script that
  never brings its outcome about fails rather than hangs.

So the order of everything is the script's: the session sends, the stand-in reads only when the
session waits or the test turns, and nothing arrives between two calls the test makes unless one
of them moved the world. The test reads the world directly where the host test had to sleep: the
round trip's CONTROL now asserts that the push waits at the session's end before it asserts that
nothing was handed out, where the old 100 ms sleep proved nothing on a run in which the push had
not landed yet.

**A seam must model what the engine relies on.** `wz_session_mcu::memory` already has an in-memory
network, and it was the first candidate. It serves one count kind (`SessionLinks<OneTask>`, while
the default build counts a link's handles per face) and its ends name no owner wait, so the
gate of section 1 never runs over it: a harness on it would have passed the very defect this note
found. The simulated ends give the owner's wait because the host's links the engine opens do.
The same holds for the receive: the round's form reads a record's parts where its link lent them,
and ends that handed out a copy had every pushed sample refused in that form (section 1, "What
the lane's form found next").
`tests::sim::an_end_lends_what_it_received_where_it_lies_until_its_next_receive` holds the ends
to the host link's lend.

**Seeds.** Today the seed decides the entropy, so cookies and nonces are the seed's. The next
step gives it the schedule: how many steps a wait makes before the world turns, which stand-in
turns first, the order of the datagrams queued at one end, a datagram dropped. A test then runs a
fixed list of seeds, every one a function of itself, and the failing seed is in the message. A
seeded schedule is what reaches the interleaving of section 1 without a second thread.

**What the world does not cover**: the host's sockets and their buffers, the scheduling of
threads the engine starts, the wall clock, and other implementations of the protocol. Those are
the system layer's.

## 4. The layer rule

**Unit layer** (the default for a module): runs in the simulated world. It names none of

- the wall clock: `Instant::now`, `SystemTime`, `thread::sleep`, `PosixClock`;
- the host's sockets: `UdpSocket`, `TcpListener`, `TcpStream`, `PosixLinks`, `host_links(`,
  `PosixTcpDial`, and the host stand-in `Router::start`;
- threads of its own: `thread::spawn`, `thread::Builder` (a thread the subject starts itself,
  such as `start_read_task`, is the subject's and not the test's);
- the host's randomness: `PosixEntropy`, `rand::`, `OsRng`, `getrandom`;
- processes: `Command::new`.

**System layer**: a module that needs one of those (real I/O, the host's scheduler, another
implementation of the protocol) is declared, with the reason, in the gate's table. Within it:

- **Register before arrival.** Wait for the event that makes the next step valid (the
  declaration seen, the token held, the interest answered) before sending what depends on it.
  Most of the flake history of this tree was a step taken before its precondition had arrived.
- **No fixed tolerance on two reads of a clock.** Bracket the event (`before <= sample <= after`).
- **No sleep-then-assert-absence.** Assert what is waiting (the sim's `waiting_for_the_session`),
  or wait for an acknowledgement, and only then assert that nothing was delivered.
- **A deadline is a stall guard only**, named as one (`STALL` in `tests::step_host`), and no
  outcome is judged by whether it came before it.

## 5. The gate

`scripts/lib/deterministic_test_layer_gate.py`, `--check` and `--selftest`, Python 3.10 at the
lowest, a text read with no build:

- **Population**, derived: every tracked `.rs` test module of the crates the gate covers (first
  `wz-capi-coop`: `src/tests.rs`, `src/tests/*.rs`, `src/**/tests.rs`, `tests/*.rs`), read with
  comments and string literals blanked.
- **Table**: `docs/deterministic-tests/system-layer.tsv`, one row per system-layer module:
  path, the sources it reaches (`clock`, `socket`, `thread`, `random`, `process`), the reason.
- **Findings**: a module outside the table that names a source of section 4; a row whose file is
  not tracked; a row with no reason; a row that names a source its module no longer reaches (the
  row is stale: the module moved to the unit layer, and the row goes); a population of zero
  modules or a table read as empty (the gate lost its subject).
- **Ratchet**: the first table lists every module that reaches a source today, so the gate is
  green on the day it lands and every migration deletes a row; a row is never added for a module
  that is unit-layer today.
- **Wiring**, beside the census coverage gate: the pre-push list
  (`.githooks/pre-push`, next to `"logic_census_coverage_gate.py --check"`), and in
  `scripts/run-ci.sh` the two legs
  `_runci_leg deterministic_test_layer_gate.selftest -- python3 scripts/lib/deterministic_test_layer_gate.py --selftest`
  and `_runci_leg deterministic_test_layer_gate --after deterministic_test_layer_gate.selftest -- python3 scripts/lib/deterministic_test_layer_gate.py --check`.
- **Selftest**: a fixture tree holding one unit module that names `Instant::now` (red), the same
  module in the table (green), a table row for a missing file (red), a row with no reason (red), a
  stale row (red), a source named only in a comment or a string (green), an empty population
  (red).

## 6. Migration order

1. **`tests::step`** (this step): the flake above. The two-thread test stays on the host
   (`tests::step_host`, system layer).
2. **The modules whose waits are the wall clock's** and whose verdict is a deadline:
   `tests::program_clock` (its CONTROL is a lease on the wall clock), `tests::redial_wait`,
   `tests::dial_in_flight`, `tests::listen`, `tests::congestion`, `tests::direct_receive`,
   `tests::runtime_tables`, `tests::ticker`, `tests::queryable`, then every module that starts
   the host stand-in, the most starts first (`tests::direct_receive`, `tests::entity_tables`,
   `tests::arena`, `tests::get`, `tests::faces`, `tests::held_keys`, ...). The stand-in's
   commands (`Command`) move to the simulated stand-in as each module needs them.
3. **System layer by nature**, kept there and brought to the rules of section 4: the slow-reader
   pool test (`tests::tx_pool`, the kernel's stream buffers are its subject), the host's groups
   (`tests::host_group`), the TLS provider, `scout/tests.rs`, and outside this crate the
   interoperation suites (`wz-integration-tests`, `wz-runtime-tokio`'s end-to-end tests), whose
   past flakes were each a step taken before its precondition arrived.
4. **The gate** of section 5 lands with its ratchet table once the first modules have moved.

Each migration changes test code only (`#[cfg(test)]` modules, `tests/` targets, this note and
`docs/zenoh-logic-as-sce-kinds/files.md`): no byte of the shipped text and no instruction count
moves. `git diff --stat` of each step names no file outside those, and the size and instruction
lanes read the same as on its base.

## 7. What the migrated step tests keep

| What the original held | Original (host, `tests::step` on main) | Now | The line whose change turns it red |
|---|---|---|---|
| The open starts no read task | `read_task_is_running` after the open | same, in the world | an open that starts the read task |
| A round trip by the program's steps alone, each bounded at nothing | `steps_until(.., 0, ..)` against the stand-in thread, five seconds | `Sim::steps_until(.., 0, ..)`: a step, then a turn, 4,096 steps at most | a delivery or a send that needs a read task |
| Nothing is handed out between two steps | 100 ms sleep, then `received == 0` | the push asserted waiting at the session's end, then `received == 0` | a delivery made outside a step |
| A step bounded at nothing waits for no input | at least 60 steps in 600 ms of the wall clock (`threads`) | every wait a step bounded at nothing asks is bounded at 0 (round trip, every build; and the `threads` test) | a step that waits past its bound |
| A read of no bound waits up to the config's 100 ms (CONTROL) | at most 8 reads in 600 ms | the read asks a wait bounded at 100 ms | a read that does not wait for the config's bound |
| A lease that runs out between steps is kept by the steps, and the session dials again | lease 600 ms on the wall clock, frozen stand-in thread, restarted on its port | lease 600 ms on the test's clock, moved 10 ms a step; frozen stand-in let go of and made again at its address | a lease kept by anything but the steps; a session that ends with its link |
| What the session holds is declared again over the new link, and the new link carries the push | `declares >= 1`, `received == 1` | same | a redial that declares nothing |
| A step is refused while the read task runs, and as closed after the close | `threads` test | same, in the world | a step beside a running read task |
| A step of a closed session is refused, one thread too | test of every build | same | a closed session that steps |
| Two steps at once hand each sample out once | host test | unchanged, moved to `tests::step_host` (system layer: two threads of the host) | a sample handed twice or lost |
| (new) A step bounded at nothing reads what came after a step found nothing | not tested: it was the flake | `a_step_bounded_at_nothing_reads_what_came_after_a_step_found_nothing`, in every form (the fix of section 1) | a step that passes over a link its last read found empty |
