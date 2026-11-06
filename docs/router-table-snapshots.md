# The router's tables as published snapshots

Structure B of `docs/router-task-per-face.md` section 4, the second value of the table-sharing axis that
section names and leaves undeclared. This is the design and its correctness argument, written before the
first line of the change, so that each phase is judged against it. Sections 1 to 5 were written before any
measurement; what was measured, and what it decided, is in sections 6.1 to 6.3.

## 1. Why

Structure A, the one the router has today, is upstream's: one reader-writer lock round the tables
(`zenoh/src/net/routing/dispatcher/tables.rs` @ `pub struct TablesLock`), the data path under its read half,
every declaration, face transition, topology list and tick under its write half. Four costs of A are
recorded in this repository, each paid for by code that exists only because readers and writers exclude
each other:

- **A writer can be kept out for as long as the faces route.** The read is recursive (a method that reads
  calls another that reads), a recursive read does not queue behind a waiting writer, and eight faces'
  threads routing without pause never left the lock without a reader: a face could not leave for a minute
  (`docs/router-task-per-face.md` section 7). The repair is a bound, `TABLES_WRITER_FIRST_AFTER` (10 ms) and
  `PlainRwLock::read_behind_a_writer_waiting` (`crates/wz-runtime-tokio/src/sync.rs`), which the same section
  measured at about eight per cent of the starved router's throughput against the unbounded read, and which
  still lets a writer wait for every read already under way.
- **Every write stops every face for its length.** A face coming up sends its replay and floods under the
  write guard (`RouterForwarder::register`), and the tick takes the write guard every `trees_delay`
  (100 ms by default) whether or not a tree is dirty.
- **A user callback reached inside a read guard cannot declare.** The router queues hosted deliveries until
  the guard is gone (`local_publish::DeliveryScope`), but two paths still call a handler inside the guard:
  the multicast ingress (`RouterForwarder::route_mcast_ingress`, `route_mcast_ingress_request`, which open no
  scope) and the inline fallback of `run_query_job`. A handler there that declares takes the write guard
  under its own read guard, and the thread waits for itself.
- **The data path writes through the read guard.** The route memos fill under a lock of their own, the
  egress queues and the declaration numbering under per-face mutexes. These are correct, and they are the
  part of the design A and B share (section 3).

The textbook answer to a table that many threads read on every message and few threads write is
read-copy-update: readers take an immutable version with no lock at all, a writer makes the next version
and publishes it with one store. Under it the first and third costs above do not exist (no reader excludes
a writer, so no writer waits for one, and a callback reached by a reader holds no lock it could deadlock
on), and the second becomes the cost of the writers alone. What B costs instead is copying, and that is the
measured question this note sets up.

B is a policy value and not a replacement. A stays the value of every upstream preset (C2 of
`docs/build-configuration.md`); B enters with its code and its pair of behaviour tests (C8), as section 4 of
`docs/router-task-per-face.md` requires.

## 2. The form, and the literature it follows

- **Read-copy-update** (McKenney and Slingwine, 1998; McKenney, "Is Parallel Programming Hard", chapter 9):
  readers dereference one published pointer and never write shared memory; writers are serialised among
  themselves, copy what they change, and publish with a release store. A version is reclaimed after every
  reader that could hold it is gone (a grace period).
- **Reclamation by reference count.** A reader holds the version it loaded by an `Arc`; the version is freed
  when the last holder drops it. The published pointer is an `arc_swap::ArcSwap` (crate `arc-swap` 1.7,
  MIT OR Apache-2.0), whose load is lock-free and does not touch the version's count on the fast path.
  Epoch-based reclamation (Fraser, 2004) is the alternative; it buys nothing here because a version must
  outlive a reader's whole message anyway, which is what a count says directly.
- **Path copying** (Okasaki, "Purely Functional Data Structures", 1998; Driscoll, Sarnak, Sleator and
  Tarjan, 1989): a write copies only the path from the root to what it changes and shares the rest with the
  version before. At field granularity this is `Arc::make_mut` on each field the write touches; inside a
  large keyed map it is a persistent hash array mapped trie (Bagwell, 2001), so that a write to one face or
  one key copies O(log n) and not the map.
- **Linearizability** (Herlihy and Wing, 1990) is the correctness criterion: every operation appears to take
  effect at one instant between its call and its return. Under A the instant of a write is when it takes the
  write guard and of a read when it takes the read guard. Under B the instant of a write is the publishing
  store and of a read the load. Both are linearizable; section 5 says what a peer can and cannot tell
  apart.
- **Combining** (Hendler, Incze, Shavit and Tarjan, "Flat combining", 2010): writers that queue behind one
  another can have their updates applied by whichever holds the writer lock and published once. This is a
  later phase and only if declarations in bursts are measured to dominate the writers' cost.

## 3. What the tables hold, sorted by who writes it

Read from the tree as of round 4279 (`crates/wz-runtime-tokio/src/router_forward.rs`, `struct Tables` and
the types it holds). Everything reachable from `Tables` falls into one of three kinds, and the design is
the sorting:

**(a) Routing state.** Written only through `WrittenTables` (the write guard), read by everything:
the hats' graphs and interest tables (`MeshHat::{net, subs, qabls, tokens}`, `BrokerHat::{subs, qabls,
tokens}`), the face set and each face's routing facts (tier, zid, link, alias table `keyexpr_table`,
`initial_final`), `joined_links`, the future-interest stores, `mesh_ids`, `own_interests`, the hosted
entity lists and `next_hosted_id`, `partition`, `north_is_client`, `node_mode`, `local_face_sink`,
`advertised_tokens` and `receive_ledger`. This is what becomes the snapshot. Two of its members carry a
lock only so that a writer could reach them through `&self` (`advertised_tokens: PlainMutex`,
`MeshHat::trees_dirty: PlainCell`); in a snapshot they are plain values written through `&mut`.

**(b) Per-face runtime.** Written on the data path, under a lock of each face's own: the egress queues
(`RouterFaceState::held`, `egress::Queues`), the gate's waker (`gate_wake`), the declaration numbering
(`declaration_ids`) and the session behind `actions`. These are not versions of anything: a face has one
queue, whichever version of the tables routed the message into it. They move out of the routing state into
one `Arc<FaceRuntime>` per face, created when the face registers, shared by every version that holds the
face, and closed when it deregisters (section 5).

**(c) Memos.** `MeshHat::{data_routes, query_routes}` and `BrokerHat::{client_routes,
client_query_routes}` (`crates/wz-runtime-tokio/src/route_cache.rs`, `RouteCache`): a route is a function of
the graph and the interest table, cached by the versions of both (`RouteInputs`) and recomputed on a
mismatch. A memo of a pure function of immutable data is safe to share between versions, provided that a
reader of an older version cannot destroy what a reader of a newer one stored. Today a store with new
inputs clears the cache; under B an older reader's store would clear a newer reader's entries, a loss of
work and not of correctness. The memo therefore records the newest inputs it has served and refuses a
clear from older ones (`RouteInputs` already orders: both members are monotone counters bumped by every
write).

The hosted handlers are already shared (`Arc<Hosted<..>>`), and the interceptor caches, the pending-query
table, the multicast members and the counters already live outside `Tables` with their own locks.

## 4. The two values, behind one seam

The router reaches its tables through `OnTables<'a, T>`, generic over what holds them: a read guard for the
readers, `WrittenTables` for the writers, with `where T: DerefMut` separating them by type. That seam is
kept, and the cell behind it gets two forms selected by the policy at build time:

| | Reader holds | Writer does | Commit |
|---|---|---|---|
| `rwlock` (A, upstream's) | `PlainReadGuard<Tables>` | takes the write guard, mutates in place | dropping the guard |
| `snapshot` (B) | `Arc<Tables>` loaded from an `ArcSwap`: an `Arc<Tables>` pinned per thread, loaded once by the outermost read, so that the reads nested in it see the version it loaded | takes the writer mutex, works on a draft that shares every unchanged field with the published version (path copying), mutates the draft | `WrittenTables::drop` stores the draft, then lets the mutex go |

`WrittenTables::drop` is already the one place a write ends (it tells the local face and the face watchers
after the guard is gone), so it is where B publishes. Under A the same restructured `Tables` is used: an
`Arc` field whose count is one is written in place by `make_mut`, so A pays no copy for the split.

The policy is `routing-table-sharing` in `deploy/wz-config.toml`, `kind = "choice"`, choices
`["rwlock", "snapshot"]`, default `rwlock`, `upstream` stating upstream's `RwLock<Tables>`.

## 5. The contract, and what B keeps of A's

What a peer of the zenoh preset can observe must not change under A, which is untouched. What B keeps:

1. **A face's own order.** A declaration a face brings is applied, and published, by that face's thread
   before it routes the next message it brings: the writer is synchronous. A Push that follows a
   DeclareSubscriber on the same face is routed by tables that hold it, as under A.
2. **Across faces.** A message whose routing begins after a write returned is routed by tables that hold
   the write (the load follows the publishing store). A message whose routing began before may be routed by
   the version before, which is A's behaviour too for a read that took its guard before the writer did.
3. **Nothing is sent to a face after it left.** Under A, `deregister` waits for every fan-out that found the
   face, and no fan-out after finds it (held by
   `a_face_that_leaves_in_the_middle_of_a_fan_out_is_given_nothing_after_it_left`). Under B a reader of an
   older version still finds the face, so `deregister` waits for a grace period: it publishes the version
   without the face, lets the writer mutex go, and returns only once every reader that loaded an earlier
   version has dropped it. That is RCU's `synchronize`, and it costs the data path nothing. Closing the face's
   runtime under a lock every send takes would also hold the guarantee, but a direct send
   (`try_send_network_message_qos` in `credited_send`) takes no lock of the face today, so it would add one to
   every send of every message. A thread that holds a version must not wait for a grace period (it would
   wait for itself); the reader keeps a per-thread depth, and the wait asserts it is zero. The same test
   holds the guarantee under both values.
4. **What B does not keep.** Under A a writer waits for the reads under way, so a send a read makes to a
   face precedes any send the following write makes to the same face. Under B the write may send first. No
   rule of the protocol orders a routed Push or Request against a declaration or a final the router sends
   about another entity on the same face, and the help text of the policy states this departure. If a
   counterexample is found, it is a defect of B and blocks the phase that found it.
5. **Callbacks.** A handler called by a reader under B holds a version and no lock, so it may declare,
   which takes the writer mutex. A handler called by a writer (the local face sink for token pushes) must
   still not re-enter the router, under both values, as its documentation says today.

## 6. Phases

Each phase lands whole, compiles and passes under both values that exist at that point, and moves no
behaviour under A.

0. **This note and the instrument.** A test in `wz-runtime-tokio` that runs N faces' threads forwarding
   without pause while a writer churns declarations and faces, and prints the writers' waits (median, 99th
   percentile, longest) and the readers' messages per second. It is a measurement and asserts only its
   population (every message routed, every write applied), as Layer E7s does. Run on pc2 under A before
   any structural change: the baseline.
1. **Per-face runtime out of the routing state** (section 3 (b)): `FaceRuntime`, closed by `deregister`
   under its send lock. Behaviour under A unchanged; the fan-out test above stays green.
2. **The memos' monotone clear** (section 3 (c)), with a test where an older inputs' store does not clear a
   newer one's entry.
3. **`Tables: Clone` by path copying at field granularity**: `Arc` round the hats' graphs, interest tables
   and stores and round each face's routing facts, each written through `Arc::make_mut`; the memos behind
   an `Arc` shared by every clone and never copied. The two writer-only locks go: the recompute flag is a
   plain `bool`, and the record of advertised tokens a map behind an `Arc` like the stores, written only
   by methods that hold the tables for writing.
4. **The cell and the policy**: `routing-table-sharing` declared, the `snapshot` cell, the admin views
   holding the cell instead of `Arc<PlainRwLock<Tables>>`, and the pair of behaviour tests: under
   `snapshot` a writer completes while a reader holds a version, and that reader still routes by the
   version it loaded; under `rwlock` the writer waits for it. The multicast ingress opens a
   `DeliveryScope` under both values. As built (`router_forward/tables_cell.rs`): the build's
   value is the router's unless a test or a host names one with `with_table_sharing` before any
   face registers; `deregister` is the one entry point that waits for a grace period
   (`TablesCell::synchronize`), after its write is published and the writer mutex let go; a write
   that panics is abandoned and not published; the fan-out test above runs under both values.
   The tick is still a write, so under `snapshot` it publishes a version every `trees_delay`
   whether or not a tree is dirty; splitting it (section 7) waits for phase 5's reading.
5. **Measurement of both values**: the phase 0 instrument and Layer E7s, built with each value of the policy,
   on pc2, alternating runs, recorded here with the build and the host.
6. **What the measurement asks for, and only that**: persistent maps for a keyed table whose copy is
   measured to dominate a write, combining for writers if declaration bursts are measured to queue.

### 6.1 The phase 0 reading (round 4286)

`router_forward::table_sharing_tests::the_faces_and_the_writers_of_the_tables_measured_together`, release
build with `routing-router-hat`, on the build machine of 22 cores and 30 GB with nothing else running, four
runs on the tree of round 4281 (structure A, the only one there is). Eight publisher faces route Puts to four
subscribers without pause for three seconds while one writer declares and undeclares subscriptions on its
own face and every 32 declarations brings a face up and takes it down.

| Run | Puts routed per second | Declarations: n, p50, p99, longest | Face transitions: n, p50, longest |
|---|---|---|---|
| 1 | 923 720 | 290, 10 040, 10 219, 10 605 us | 10, 10 032, 10 049 us |
| 2 | 1 278 285 | 292, 10 028, 10 360, 10 485 us | 10, 10 034, 10 044 us |
| 3 | 1 176 733 | 292, 10 028, 10 251, 10 479 us | 10, 10 057, 10 435 us |
| 4 | 1 175 844 | 290, 10 028, 10 142, 10 179 us | 10, 10 035, 10 103 us |

Every write took the bound and a little more: with eight faces' threads reading without pause, the lock is
never without a reader, a writer gets in only when it has waited `TABLES_WRITER_FIRST_AFTER` (10 ms) and the
readers that come after it queue behind it, and the work of the write itself is the tens of microseconds
above 10 000. Under A on a busy router a write therefore costs the bound, about a hundred writes a second
from one writer, whatever the write is. This is the figure phase 5 compares B against; it says what A pays
and not yet what B would.

### 6.2 The phase 5 reading (round 4316)

Both values built from the tree of round 4311 (release, `routing-router-hat`; the value set by
`WZ_POLICY_ROUTING_TABLE_SHARING` at build time, each value in a target directory of its own), run on one
build machine of 22 cores and 30 GB, alternating A and B. The phase 0 instrument, four runs of each:

| Run | Value | Puts routed per second | Declarations: n, p50, p99, longest | Face transitions: n, p50, longest |
|---|---|---|---|---|
| 1 | rwlock | 1 254 128 | 298, 10 027, 10 909, 11 787 us | 10, 10 056, 10 111 us |
| 1 | snapshot | 1 086 330 | 5 570, 566, 1 079, 2 532 us | 176, 75, 1 808 us |
| 2 | rwlock | 1 238 853 | 314, 10 025, 10 148, 11 532 us | 10, 10 030, 10 054 us |
| 2 | snapshot | 1 088 871 | 5 528, 561, 1 100, 4 235 us | 174, 83, 3 566 us |
| 3 | rwlock | 1 266 896 | 296, 10 025, 10 448, 11 059 us | 10, 10 028, 10 093 us |
| 3 | snapshot | 1 103 244 | 5 584, 521, 1 057, 2 760 us | 176, 72, 1 196 us |
| 4 | rwlock | 1 260 585 | 298, 10 029, 10 449, 11 847 us | 10, 10 030, 10 100 us |
| 4 | snapshot | 1 106 757 | 5 568, 516, 1 053, 2 448 us | 174, 72, 2 387 us |

Under B a writer no longer waits for the readers: a declaration takes about half a millisecond at the median
where A's took the 10 ms bound, a face comes up or goes in about 75 us, and one writer completes eighteen
times the writes in the same window. The readers routed 12 to 14 per cent fewer Puts a second under B while
that writer published eighteen times as often; the instrument does not separate what the readers pay for a
load from what they pay for the routes the writes retire.

Layer E7s, one run of each before the run of B stopped the sequence (the second pair did not run):

| | rwlock | snapshot |
|---|---|---|
| us per message, 256 / 1024 / 2048 subscribers, no churn | 26.0 / 30.3 / 30.8 | 26.9 / 30.9 / 31.3 |
| us per message, 256 / 1024 subscribers, churn | 27.5 / 34.0 | 29.3 / 35.5 |
| starved router: 2048 sessions up within the deadline | all, 0 faces down, 11 % of the offered load forwarded | 1 735 and 1 700 of 2 048: the three tests that wait for every session to come up fail |
| told 1.32 % of a core, 32 hogs | 288 msg/s forwarded, 1 face down, 8 table waits of 250 ms or more | 489 msg/s forwarded, 4 faces down, no table wait of 250 ms or more |

Per message B costs 2 to 6 per cent more in this one pair of runs, within the spread E7s has shown on one
host before (`docs/router-task-per-face.md` records 18.3 and 23.2 for the same router at 256). What is not
within any spread is the starved router: under B every face that comes up is a write, and every write copies
the face map's spine and every store it reaches, so bringing up n faces costs O(n squared) on a core that has
little to give. That is the measurement section 6 item 6 waited for: B as built does not hold the
admission the router promises when it is short of CPU, so it is not yet a value a deployment should choose.
Phase 6 is therefore not optional for B. It finds, by profile, which copies a write pays, and makes those
tables persistent (section 2, path copying inside a keyed map), and it removes the per-message count of the
outermost read if the profile shows it. The default stays `rwlock` until a reading of B holds every test of
E7s and costs no more per message.

Section 6.3 corrects the attribution above: the copies were real and are gone, but the starved router's
bring-up failed under A as well once A was run more than once, and the cause was the test's harness.

### 6.3 The phase 6 reading (this round)

**The profile.** A second instrument, `the_writes_of_an_admission_measured_against_the_faces_already_up`,
brings 2,048 client faces up one at a time as the starved router's population does (register, a
subscriber, an interest), times each write by band of 256 faces already up, and times the copy and the
release of each store of the tables. On the tree of phase 5 (hkl001, the same build of each value):

| Faces already up | Value | Register p50 | Subscribe p50 | Interest p50 |
|---|---|---|---|---|
| 0 to 256 | rwlock | 0 us | 54 us | 12 us |
| 0 to 256 | snapshot | 2 us | 88 us | 36 us |
| 1,792 to 2,048 | rwlock | 0 us | 521 us | 130 us |
| 1,792 to 2,048 | snapshot | 19 us | 1,313 us | 602 us |

At 2,048 faces a copy of the future subscriptions' store took 202 to 398 us and of the broker hat's client
subscriptions 191 to 214 us, each released in 117 to 177 us by whichever reader let the last version go;
the face map's spine took 9 us. Those two stores were hash maps of hash maps of strings, copied whole by
every write under B. They are now persistent maps, a hash array mapped trie written for the router
(`crates/wz-runtime-tokio/src/persistent_map.rs`, Bagwell 2001, held by model tests against `HashMap` under
three degenerate hashers and by a test that a write to a copy of 100,000 keys owns at most eight nodes),
and the writers that walk them read first and write only the entries that change. The face map stays a
hash map: it is read on every message, and its copy is the 10 us measured. On pc3 after the change:

| Faces already up | Value | Register p50 | Subscribe p50 | Interest p50 |
|---|---|---|---|---|
| 1,792 to 2,048 | rwlock | 0 us | 935 us | 227 us |
| 1,792 to 2,048 | snapshot | 20 us | 968 us | 256 us |

and every store's copy is 0 us but the face map's. Under both values a subscription still costs O(faces),
since every face's interests are matched against it; that is the router's and not the sharing's, and an
index of the interests by what they match would serve both values.

**The starved router.** The phase 5 failure did not move: 1,697 and 1,734 of 2,048 sessions came up. The
harness was given a timeline of the bring-up (every 10 s, the sessions up, the messages forwarded, the
router's CPU, and its CPU by thread), and three runs of each value, alternating, on pc3:

| Run | Host load | rwlock: up | snapshot: up |
|---|---|---|---|
| 1 | 1.9, 3.9 | 2,048 | 1,773 |
| 2 | 8.3, 4.6 | 1,451 | 1,056 |
| 3 | 9.0, 6.5 | 1,350 | 1,324 |

In every failed run every session that came up had come up within the first 10 s, and none came up in the
150 s after, including the last 60 s, when the publishers had finished and the router was idle. 10 s is
the accept timeout: a handshake not done by then is dropped, and the clients do not try again. The router
was started under `taskset` and `nice 10`, so it brought its 2,048 sessions up on one core it shared with
whatever else the host ran, at a tenth of that core's weight, while its own comment said its CPU was taken
away only once every session was in. The bring-up therefore measured the host's load, under both values.

The harness now does what its comment says (`starve_router` in
`crates/wz-integration-tests/tests/it/files/wz_router_hat_data_plane_scaling.rs`): the router starts on
the host, and once its sessions are in, every thread of it is moved onto the one core at nice 10, and the
hogs start. Its thread layout does not depend on where it starts, since its runtime names its worker count.

**Layer E7s, the corrected harness**, two runs of each value alternating, on pc3 at host loads of 3 to 30:
every test passed in every run, under both values, and 2,048 sessions came up in 1.6 to 1.8 s.

| | rwlock, runs 1 and 2 | snapshot, runs 1 and 2 |
|---|---|---|
| us per message, 256 / 1,024 / 2,048 subscribers, no churn | 17.9 / 26.8 / 27.0; 19.7 / 24.7 / 27.2 | 18.6 / 24.4 / 27.4; 19.8 / 25.9 / 27.8 |
| us per message, 256 / 1,024 subscribers, churn | 19.3 / 27.2; 21.3 / 29.3 | 21.2 / 28.2; 20.7 / 30.3 |
| starved router, churn: admitted of 320 in the window | 196; 168 | 188; 148 |
| starved router: messages forwarded a second, faces down | 4,707, 0; 3,366, 0 | 4,863, 0; 4,588, 0 |
| told 1.32 % of a core, 32 hogs: forwarded, faces down, table waits of 250 ms or more | 481, 1, 8; 356, 14, 5 | 548, 7, 0; 436, 11, 1 |
| told 1.32 % of a core, 64 hogs: forwarded, faces down, table waits | 261, 2, 3; 285, 2, 4 | 319, 4, 1; 349, 0, 0 |

Per message the two values differ by less than either differs from itself between two runs (rwlock at
1,024 subscribers read 26.8 and 24.7), and the sign of the difference changes from row to row.

**The outermost read's count.** The phase 0 instrument now first routes for one window with no writer,
which separates what a read costs from what the writes cost the readers. Four runs of each, alternating,
on pc3:

| | rwlock | snapshot |
|---|---|---|
| Puts routed a second, no writer | 1,255,886; 1,133,461; 1,098,874; 1,071,651 | 1,204,801; 1,048,329; 1,105,701; 1,083,184 |
| Puts routed a second, with the writer | 1,191,451; 1,214,003; 1,145,651; 1,192,479 | 983,024; 982,978; 1,044,669; 1,083,831 |
| Declarations in the window | 294 to 322 | 173,246 to 210,182 |

With no writer the means are 1,139,968 and 1,110,504, 2.6 % apart, within the spread of either value. With
the writer B's readers route 14 % fewer Puts while B's writer completes about 600 times A's writes, each of
which retires the routes it touches. The count of the outermost read is not what the readers pay, so it
stays: a read through the load's guard without a count would make a nested read's version a borrow of a
guard the thread must keep, which is not worth 2.6 % that the spread already covers.

**The verdict.** B holds every test of E7s and costs no more per message than A, which is what section 6.2
asked before B could be recommended. A stays the default, as C2 of `docs/build-configuration.md` requires
of every policy, and the help text of `routing-table-sharing` now says that `snapshot` is the value to
choose for a router whose sessions come and go while it routes.

## 7. What is not decided, and what could make this wrong

- **The graph's copy.** `LinkstateNetwork` holds one shortest-path tree per node, O(N squared) for N nodes
  of a mesh. A write that changes the topology copies it under B; a declaration does not. Whether topology
  writes are frequent enough on a large mesh for this to matter is a phase 5 reading.
- **The face map's copy.** Every write under B copies the face map's spine (one pointer per face): 10 us
  at 2,048 faces, measured in phase 6. It stays a hash map because every message reads it; a router of
  many more faces is where a persistent face map would be measured against that read.
- **A subscription costs O(faces) under both values.** Every face's interests are matched against it
  (section 6.3, 935 us at 2,048 faces under A). An index of the interests by what they match is the
  router's to build, and serves A and B alike.
- **The tick.** Under B the tick that finds nothing dirty need not publish; whether to split it into a read
  that decides and a write that acts is decided in phase 4 by what it writes (queries and interests timed
  out, egress swept: the last is per-face runtime and needs no version).
- **Sends under the writer.** `register` sends its replay while holding the write guard. Under B it holds
  only the writer mutex, so readers are not stopped, but other writers are; moving the sends after the
  publish is possible because a later version cannot lose what the replay was computed from, and is not
  done until a measurement asks for it.
- **The gain is a prediction until phase 5 runs.** If B costs more per message than A, B stays a value for
  the deployments whose writers are what they pay for, and the reading is recorded here as such. Phase 5
  ran (section 6.2): B's writers no longer wait. Phase 6 ran (section 6.3): B holds every test of E7s and
  costs no more per message, and is the recommended value for a router whose sessions come and go; the
  default stays A (C2).
