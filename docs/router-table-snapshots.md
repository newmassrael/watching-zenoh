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
write). Section 6.8 replaced that with the form read-copy-update itself takes: each version holds the
memos of its own inputs, made by its writer before it publishes, and no reader moves one.

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

### 6.3 The phase 6 reading (round 4336)

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
index of the interests by what they match would serve both values. Section 6.4 builds it.

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

### 6.4 The index by keyexpr (round 4346)

Section 6.3 left a subscription and an interest each costing as much as the faces up, under both
values. Two walks made it so, and neither was the sharing's:

- **The future interests.** A subscription tried every face's interests for one that meets its key,
  and an interest every face's subscriptions. Every interest is now held under its target, every
  pushed reply under its keyexpr and every key a client subscribes to under itself in
  `KeyexprIndex` (`crates/wz-runtime-tokio/src/keyexpr_index.rs`), a persistent trie of the chunks
  of a keyexpr, path-copied like the maps of section 6.3. A question walks only the branches its
  keyexpr can meet, with `*`, `**` and `$*` on either side, and each candidate is then decided by
  the exact matcher the scan used: filter and refine (Orenstein 1986), so the answer is the scan's.
  Model tests hold it to the scan over every chunk form, and the interest store's walkers to the
  walkers that try every face.
- **The broker hat's exact-key questions.** Whether self advertises a subscription into a mesh
  counted the client faces whose ids name the key by trying every face, before and after each
  declaration (`sub_contributions`), and the re-advertisement listed every face's keys. The store
  already held its subscriptions by key; both now read that.

The tree of round 4337 against this one, on pc2 (32 cores, 125 GB, shared with other work at host
loads of 14 to 48), the phase 6 instrument, p50 by band of faces already up. Four runs of each value
before, two after the index alone, two after both:

| Faces already up | Value | Tree | Register | Subscribe | Interest |
|---|---|---|---|---|---|
| 0 to 256 | rwlock | before | 0 us | 33 to 36 us | 7 to 8 us |
| 1,792 to 2,048 | rwlock | before | 0 us | 601 to 713 us | 148 to 171 us |
| 1,792 to 2,048 | rwlock | the index alone | 0 to 1 us | 473 to 753 us | 3 to 4 us |
| 0 to 256 | rwlock | after | 0 us | 4 to 7 us | 2 us |
| 1,792 to 2,048 | rwlock | after | 0 us | 4 to 9 us | 1 to 3 us |
| 0 to 256 | snapshot | before | 2 to 3 us | 37 to 69 us | 9 to 17 us |
| 1,792 to 2,048 | snapshot | before | 15 us | 694 to 758 us | 178 to 195 us |
| 1,792 to 2,048 | snapshot | the index alone | 15 to 16 us | 497 to 510 us | 20 to 21 us |
| 0 to 256 | snapshot | after | 2 to 3 us | 7 to 14 us | 4 to 7 us |
| 1,792 to 2,048 | snapshot | after | 15 to 16 us | 23 to 26 us | 18 to 20 us |

Under A a subscription and an interest no longer grow with the faces up. Under B what still grows is
the copy of the face map's spine, which every write pays (section 7): 2 to 3 us of a registration at
256 faces and 15 us at 2,048, and the same part of a subscription and an interest.

Layer E7s on the tree after both, one run of each value, at host loads of 21 (rwlock) and 42
(snapshot); every test passed under both values, as it did after the index alone:

| | rwlock | snapshot |
|---|---|---|
| us per message, 256 / 1,024 / 2,048 subscribers, no churn | 26.5 / 27.1 / 28.8 | 28.9 / 31.3 / 30.1 |
| us per message, 256 / 1,024 subscribers, churn | 29.9 / 30.3 | 29.5 / 30.3 |
| starved router, churn: admitted of 320 in the window | 308 | 312 |
| starved router: messages forwarded a second, faces down | 6,342, 0 | 8,551, 0 |
| told 1.32 % of a core, 32 hogs: forwarded, faces down, table waits of 250 ms or more | 466, 94, 7 | 606, 45, 0 |
| told 1.32 % of a core, 64 hogs: forwarded, faces down, table waits | 242, 51, 4 | 365, 12, 0 |

The starved router admitted 308 and 312 of the 320 sessions that knocked in its window, where section
6.3 read 148 to 196 on pc3 and the index alone 244 and 269 here: each admission is a subscription and
an interest, and on one shared core at nice 10 their cost is the admission rate. The per-message
cost and the rows told 1.32 % of a core moved with the host's load as they did in section 6.3 and say
nothing of the index; the faces down under 32 hogs (94 and 45, against 14 and 19 after the index
alone at lower load) are that load's.

### 6.5 The queryables' and the tokens' stores (round 4361)

Section 6.4 left the broker hat's queryables and tokens held per face in hash maps. The phase 6
instrument now also times a queryable, an interest in queryables and a token for each admitted
client, and its first reading found two more costs that grow with the faces up, neither the
sharing's:

- **The client stores.** The subscriptions', the queryables' and the tokens' client stores are one
  generic store, `ClientStore` (by face, by key, the `KeyexprIndex` of section 6.4, a version and
  the change log), its value merged per key by a `Held` trait: a subscription holds nothing beside
  its id, a queryable its info, a token nothing. The questions about one key
  (`merged_qabl_info_in`, `any_qabl_matches_in`, `token_contributions`, `dump_interest_qabls`)
  read the store's key index and no longer try every face.
- **The token reconciliation on every registration.** Admitting a face reconciled every token it
  should be told against what each mesh link had been told, a walk of the tokens times the faces,
  for a client face too, whose admission moves no graph. `register` and `deregister` of the
  linkstate tables now say whether the face moved a graph, and only such a face reconciles. What
  the forwarder told each region of tokens (`advertised_tokens`) was a hash map of hash sets, so a
  token's declaration under B copied it whole; it is now a persistent map of persistent sets,
  read before it is written, since a write copies its path even when it changes nothing.

On pc2, p50 by band of faces already up. Before is the tree of round 4350 with the instrument, two
runs of each value; the store alone is that tree with the store, two runs of each; the other rows are three runs interleaved on one tree
(the reconciliation gated, then the persistent tokens map), built side by side and run in turn:

| Faces up | Value | Tree | Register | Queryable | Queryable interest | Token |
|---|---|---|---|---|---|---|
| 0 to 256 | rwlock | before | 165 to 316 us | 9 to 12 us | 7 to 12 us | 4 to 6 us |
| 1,792 to 2,048 | rwlock | before | 93,888 to 99,076 us | 428 to 437 us | 172 to 173 us | 190 to 203 us |
| 1,792 to 2,048 | rwlock | the store alone | 853 to 892 us | 4 to 6 us | 1 to 2 us | 9 to 13 us |
| 1,792 to 2,048 | rwlock | gated | 0 to 1 us | 4 to 11 us | 1 to 3 us | 9 to 20 us |
| 1,792 to 2,048 | rwlock | after | 0 us | 5 to 9 us | 1 to 3 us | 10 to 19 us |
| 0 to 256 | snapshot | before | 157 to 158 us | 19 to 20 us | 10 to 11 us | 23 to 24 us |
| 1,792 to 2,048 | snapshot | before | 81,278 to 83,509 us | 652 to 654 us | 201 to 205 us | 627 to 638 us |
| 1,792 to 2,048 | snapshot | the store alone | 893 to 898 us | 25 to 26 us | 18 us | 119 us |
| 0 to 256 | snapshot | gated | 3 to 4 us | 15 to 17 us | 7 to 8 us | 27 to 31 us |
| 1,792 to 2,048 | snapshot | gated | 15 to 18 us | 25 to 29 us | 18 to 22 us | 125 to 150 us |
| 0 to 256 | snapshot | after | 6 to 7 us | 17 to 20 us | 7 to 8 us | 15 to 18 us |
| 1,792 to 2,048 | snapshot | after | 15 us | 24 us | 18 us | 30 to 31 us |

The first of the three runs of the tree after, under snapshot, read 42 to 70 us in every column at
2,048 faces, the registration's included, which neither change touches; the two runs after it agree
with each other, and the row gives those. The registration of a client is now 0 us under A and the
face map's spine under B (section 7); a queryable and an interest in queryables no longer grow with
the faces under either value; a token under B costs that spine and the path of one region's set.
Under B, at 0 to 256 faces, a registration read 6 to 7 us after against 3 to 4 us gated in every
run, and not at 2,048 faces; no write of a registration reaches the tokens map, and the difference
is not attributed.

Layer Z8 passes on the tree after both, and the store's model tests
(`crates/wz-runtime-tokio/src/client_store.rs`) hold its index to a scan of every face.

### 6.6 The face table (round 4388)

Section 6.5 left one cost of a declaration that grows with the faces under B: the face map's
spine, copied by every write. The map is now a `PersistentMap` like the stores, so a write copies
the path to one face: with that change alone, the copy of the tables at 2,048 faces, 7 to 9 us,
and its release, 7 us, read 0, and under B a registration went from 15 to 1 us and an interest
from 19 to 3 or 4. Under A the same reading found a token slower than before, 10 to 11 us become
14 to 15: iterating a trie costs more than iterating a hash map, and the token's write was
iterating every face. `fan_out_tier_qos`, which every control flood goes through and every Put a
client sends that the router re-forwards into a mesh, tried every face the router held and kept
those of one tier, and `gateway_faces` and the regions' admin text did the same for the north
tier. A message's cost followed the faces the router held and not the faces it reached, against
the contract of section 5.

The faces are now a `FaceTable` (`crates/wz-runtime-tokio/src/router_forward/face_table.rs`): the
map by id, and for each tier the persistent set of its faces' ids, written together by `insert`
and `remove`, the only writers of the sets. A fan-out into a tier walks that tier's set. Two tests
hold it: a Put from a client visits the same faces whether the router holds 64 clients or 1,024,
and after faces of every tier come and go, each tier's set is exactly the faces the map holds in
it.

On pc2, the phase 6 instrument, p50 at 1,792 to 2,048 faces already up, three runs interleaved,
the tree before (the hash map, each fan-out walking every face) and after, each built with each
value:

| Value | Write | Before | After |
|---|---|---|---|
| snapshot | register | 14 to 43 us | 2 us |
| snapshot | subscribe | 22 to 68 us | 9 to 11 us |
| snapshot | interest | 17 to 52 us | 3 to 4 us |
| snapshot | queryable | 22 to 70 us | 10 to 11 us |
| snapshot | token | 28 to 79 us | 9 to 10 us |
| rwlock | token | 10 to 11 us | 3 to 8 us |

The second run before was noisy, hence the wide ranges before.

**The read side.** A third instrument, `the_puts_routed_measured_against_the_faces_up`, routes
Puts from eight client faces to four subscribers for a window, then brings 256 idle client faces
up, and again, to 2,048, and last takes every idle face down and routes one window more. Its first
readings fell from about 1.5 million Puts a second with no idle face to 0.5 million at 2,048, in
both trees and under both values. Under callgrind the instructions per Put did not grow (19,442
and 17,479 Puts a second under the tool at 0 and 2,048 faces), so no walk was left. The window
after every idle face had left read where the last band did, 0.49 to 0.59 million: the fall was
the sequence of windows, not the faces. The subscribers' links were recorders that keep every
frame, some 18 million in one window. With links that count the frames and keep none, three runs
of each value:

| Value | Idle faces 0 | 256 to 2,048 | After all left |
|---|---|---|---|
| rwlock | 2,238,693 to 2,411,245 | 1,813,329 to 2,482,373 | 2,345,254 to 2,542,642 |
| snapshot | 2,026,448 to 2,429,332 | 2,231,435 to 2,526,024 | 2,297,564 to 2,534,777 |

A run of each under `perf stat` read the same (1.88 to 2.38 million and 2.40 to 2.60 million) at
1.08 to 1.29 instructions per cycle, 0.28 to 0.40 % of cache references missed and 1,700 page
faults in 30 s. The faces up do not move a Put's cost under either value.

**What the persistent face map costs a message.** Every Put looks its faces up by id, the face it
came from and each face it goes to, and a lookup in the trie walks a level per five bits of hash
where the hash map probed one group. The same instrument on the tree before (the hash map) and
after, over the counting links, three runs interleaved, the mean of every window:

| Value | Before | After |
|---|---|---|
| rwlock | 2,654,330 | 2,453,396 |
| snapshot | 2,442,243 | 2,551,446 |

The same lookups read 8 % slower under A and 4 % faster under B, so the difference between two
builds is mostly where the linker put the code, not what it does. Two runs of each under
`perf stat` count what moves less with the layout, the process's instructions over the Puts it
routed (the spinning of contended locks included): 35,537 to 36,304 instructions per Put
before and 36,737 to 37,382 after, 3 % more under both values, and 28,840 to 31,573 cycles per
Put before against 30,101 to 31,308 after, within each other's spread. `perf record` puts the
trie's lookup at 2.4 % of the cycles after, where the hash map's was inlined into its callers.
A persistent face map costs a message about 3 % more instructions and no time a run can tell
from its own spread; what it buys is the write under B, which no longer copies a pointer per
face.

**The phase 0 instrument over the counting links.** Every instrument of this note now counts. The
readings of sections 6.1 to 6.3 were taken over the recorder, and the phase 0 instrument routes
its window with no writer before its window with one, so its two figures were also two windows
in sequence. Over the counting links the windows no longer drift (the window after every idle
face left reads as the first), so the order no longer biases them. On the tree after, four runs
of each value alternating, on pc2 at a host load of 31 to 38:

| | rwlock | snapshot |
|---|---|---|
| Puts routed a second, no writer | 2,205,581; 2,347,121; 2,417,163; 2,358,707 | 2,420,152; 2,420,070; 2,493,340; 2,272,535 |
| Puts routed a second, with the writer | 2,152,892; 2,329,346; 1,970,961; 2,279,049 | 2,066,945; 2,128,950; 1,951,140; 1,804,886 |
| Declarations in the window, p50, p99 | 284 to 290, 10,037 to 10,054 us, 10,351 to 13,212 us | 183,282 to 206,338, 12 to 13 us, 19 to 24 us |
| Face transitions, p50 | 10,026 to 10,084 us | 8 to 10 us |

A declaration under B, 516 to 566 us at the median in section 6.2, is now 12 to 13 us: the stores
of sections 6.3 to 6.5 and the face table leave a write only the paths it changes. With no writer
the two values route 2.3 and 2.4 million Puts a second, the difference within either's spread.
With the writer B's readers route 17 % fewer than with none, and 9 % fewer than A's with the
writer, while B's writer completes about 670 times A's writes, each a new version the readers load
and each retiring the routes it touches; A's readers lose 6 % to a writer that gets in a hundred
times a second.

### 6.7 What a busy writer costs the readers (round 4400)

Section 6.6 left the readers' loss under a busy writer unseparated between the versions they load
and what the writes change. The instrument
`the_readers_under_a_busy_writer_measured_by_what_the_writes_change` routes the phase 0 Puts through
windows of five kinds: no writer; the declaring writer of phase 0 without face transitions; the
same writer declaring into a second router nobody routes through (the host is shared with the
writer's work, the tables are not); a writer publishing versions that change nothing, paced to a
rate; and that writer unpaced. The cell counts the writes it publishes
(`TablesCell::writes_published`), since one message can be one write or several.

The Puts a second moved with the load of the shared hosts by more than the effects (pc2 at 35 to
105, pc3 at 4 to 22), and so did the time the readers ran a core per Put. What does not move with
the share of the host a thread is given is what the thread executes, so the reading is the
readers' instructions and cycles per Put (`perf record -e instructions:u,cycles:u`, the publishers'
threads only, `--comm wz-publisher`), one window kind to a process, three windows each, on pc2:

| Window (writes a second) | Puts a second | Instructions a Put | Cycles a Put |
|---|---|---|---|
| no writer | 2.38 M; 2.25 M | 18,431; 18,461 | 16,059; 16,233 |
| declaring (70,500 to 81,000) | 2.08 M; 1.95 M | 18,850; 18,886 (+2.3 %, +2.3 %) | 17,657; 18,208 (+10.0 %, +12.2 %) |
| declaring elsewhere (143,000 to 170,000) | 2.18 M | 18,472 (+0.2 %) | 16,976 (+5.7 %) |
| unchanged, paced to 20,000 | 2.37 M | 18,517 (+0.5 %) | 15,893 (-1.0 %) |
| unchanged, paced to 75,000 | 2.33 M | 18,425 (-0.2 %) | 16,037 (-1.2 %) |
| unchanged, unpaced (516,000 to 544,000) | 1.96 M | 18,559 (+0.5 %) | 17,832 (+9.9 %) |

- **Loading versions is not the cost.** At the declaring writer's rate a version that changes
  nothing costs the readers nothing a run tells; at seven times that rate it costs 10 % more cycles
  for the same instructions.
- **The writer's own work on the host is half of it at most.** Declaring twice as often into a
  router the readers do not read costs them 5.7 % more cycles and no instructions.
- **The rest is what the readers do because the tables they read changed:** 2.3 % more
  instructions and some 5 % more cycles. A profile of the readers names three parts of it. They
  freed the retired versions' path copies (`drop_glue` of the persistent maps' slots and `cfree`,
  0.8 to 2.6 % of their cycles), because a version was freed by the last reader to let it go. The
  route caches moved their inputs at every version (`lock_shared_slow` of their lock, about 1 %).
  And a reader whose version is older than the inputs the cache was brought to computes its route
  and does not keep it: 1,300 to 30,000 routes a window, more the less of a core the readers are
  given, against none under a writer that changes nothing.

The first is not RCU's form, in which a reader never reclaims: the updater does, after the grace
period (`call_rcu`). `TablesCell` now keeps the versions a publish replaces among the retired ones
by their count, and the writer frees those no reader holds at its next publish and at each grace
period, after its lock; a reader only lets its count go. The readers' profile under the declaring
writer no longer has the slots' drops or `cfree`, and the writer's has them
(`persistent_map::Node::drop_slow`, 1.1 to 1.5 % of its cycles). What it gives the readers in Puts
a second was not told apart from the hosts' load and is not claimed. A retired version no reader
holds lives until the next write or grace period: one version's own paths, as many as the readers
held at the last publish.

### 6.8 The route memos as part of each version (this round)

Section 6.7 left two of the readers' costs under a busy writer where they were: the route caches
moved their inputs at every version, under a write lock a reader took, and a reader whose version
was older than the inputs the cache had been brought to computed its route and did not keep it.
Both come from one shape: one memo shared by every version, whose inputs the first reader of a new
version moved. That is a cache beside the versions, not part of them. Read-copy-update has no such
thing: what a version derives from its own data is made by the updater before the version is
published, and a reader only reads it.

The memos are now part of the versions (`route_cache.rs`, `RouteCache`):

- A memo's inputs are fixed. The writer gives each version the memos of its own inputs when it
  ends a write (`Tables::bring_route_memos`, called by `TablesWrite::publish` under either value,
  and on the tables a cell starts with). A hat whose graph and tables did not move keeps the memo it
  shares with the version before; one whose inputs moved gets a memo of its own. A client leg's new
  memo starts as the old one less the routes the changed keys reach (the store's change log, which
  `refresh` read before); a mesh leg's, and one whose log no longer reaches back, starts empty.
- A reader never moves a memo and finds none of other inputs: a reader of an older version is
  served from that version's memo. A caller at inputs other than its memo's is a writer reading its
  own draft (or, under `rwlock`, tables a writer left as it unwound); its route is computed and not
  kept. `RouteInputs::precedes` and `RouteCache::refresh` are gone: a memo that belongs to one
  version has no order of versions to keep.
- The routes are one persistent map (`persistent_map.rs`) keyed by keyexpr and source together, read
  by a key borrowed from the caller, behind the memo's own reader-writer lock. The persistent map is
  what lets the new memo start from the old one's routes at the cost of one count, and leaving out
  a route copy its path alone; a map copied whole would make every write that moves a store cost as
  much as the routes kept.

Two forms of the routes were measured before this one and dropped, by the per-symbol instructions
of the readers against the version before this change (no writer):

| Form of the routes | What it cost the readers a Put |
|---|---|
| keyexpr to source map, nested, behind an `ArcSwap` | the `ArcSwap` loads 347 instructions more (about 100 a load) |
| the same behind the lock | two trie walks and two hashes a read: 586 instructions in the maps' lookups, where the functions the hash maps' lookups were inlined into lost 401 |
| one map by keyexpr and source, behind the lock (kept) | one walk and one hash a read |

The kept form, on pc2, under `snapshot`, perf `instructions:u` and `cycles:u` of the `wz-publisher`
threads a Put, each window kind in a process of its own, three windows of three seconds each, two
runs of each tree taken one after the other (host load 14 to 45):

| Window | Instructions a Put, before | after | Cycles a Put, before | after | Routes computed and not kept a window, before | after |
|---|---|---|---|---|---|---|
| no writer | 18,423; 18,469 | 18,346; 18,236 | 16,462; 16,032 | 16,039; 16,106 | none | none |
| declaring (103,000 to 195,000 writes a second) | 18,653; 18,514 | 18,308; 18,302 | 16,953; 16,887 | 16,128; 16,228 | 6,595 to 70,113 | 0 or 1 |

- The readers no longer compute what they cannot keep: under the declaring writer each window
  computes the one route of its first Put, where the version before computed thousands to tens of
  thousands of routes a window and kept none.
- What a busy writer costs the readers over no writer at all fell from 45 to 230 more instructions
  and 491 to 855 more cycles a Put to between 38 fewer and 66 more instructions and 89 to 122 more
  cycles, within the runs' spread.
- With no writer, the readers' instructions a Put are 0.4 to 1.3 % fewer, and their cycles within
  the spread: the reads are not dearer for being kept per version.
- What it costs the writer is a memo for each hat whose inputs moved, at each publish, and for a
  client leg a pass over the routes kept. The declaring writer published as fast as it did before
  (107,000 to 195,000 writes a second against 103,000 to 139,000), on hosts too loaded for more to
  be said.

## 7. What is not decided, and what could make this wrong

- **The graph's copy.** `LinkstateNetwork` holds one shortest-path tree per node, O(N squared) for N nodes
  of a mesh. A write that changes the topology copies it under B; a declaration does not. Whether topology
  writes are frequent enough on a large mesh for this to matter is a phase 5 reading.
- **A message's lookups of its faces.** The face map is persistent since section 6.6, so a write
  under B copies one face's path, and every message pays for it in its lookups: about 3 % more
  instructions per Put, no time a run tells from its spread. A route names its faces by id and
  each message looks each one up; a route that held its faces' state would take the lookups off
  the message, but a route outlives the version it was computed from, so it would read a face's
  facts as they were, and what may be read stale is not yet stated. Not done until a reading asks
  for it.
- **The memo of a route a writer reads.** A writer that routes through its own draft (a replay,
  an interest answered while it declares) reads at inputs no memo has yet, and computes its route
  without keeping it (section 6.8). How often a write does so, and whether the draft should carry a
  memo of its own while it is written, is not measured.
- **Which routes a change reaches.** A client leg's new memo leaves out the routes the changed
  keys reach by trying every route kept against every changed key, the cost `refresh` had on the
  first reader. On the writer now, it grows with the routes kept times the keys a write changes;
  the keyexpr index of section 6.4 could find the reached routes instead. Not done until a reading
  asks for it.
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
