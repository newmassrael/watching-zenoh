# The router's tables as published snapshots

Structure B of `docs/router-task-per-face.md` section 4, the second value of the table-sharing axis that
section names and leaves undeclared. This is the design and its correctness argument, written before the
first line of the change, so that each phase is judged against it. Nothing here is measured yet: where this
note says B costs less or more than A, it says what will be measured and how, not what the result is.

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
| `snapshot` (B) | `Arc<Tables>` loaded from an `ArcSwap` | takes the writer mutex, works on a draft that shares every unchanged field with the published version (path copying), mutates the draft | `WrittenTables::drop` stores the draft, then lets the mutex go |

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
   older version still finds the face. The guarantee moves to the face's runtime: `deregister` closes its
   `FaceRuntime` under the lock a send takes, and a send to a closed runtime is dropped and counted. The same
   test holds it under both values.
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
   and stores and round each face's routing facts; the two writer-only locks become plain fields.
4. **The cell and the policy**: `routing-table-sharing` declared, the `snapshot` cell, the admin views
   holding the cell instead of `Arc<PlainRwLock<Tables>>`, and the pair of behaviour tests: under
   `snapshot` a writer completes while a reader holds a version, and that reader still routes by the
   version it loaded; under `rwlock` the writer waits for it. The multicast ingress opens a
   `DeliveryScope` under both values.
5. **Measurement of both values**: the phase 0 instrument and Layer E7s, built with each value of the policy,
   on pc2, alternating runs, recorded here with the build and the host.
6. **What the measurement asks for, and only that**: persistent maps for a keyed table whose copy is
   measured to dominate a write, combining for writers if declaration bursts are measured to queue.

## 7. What is not decided, and what could make this wrong

- **The graph's copy.** `LinkstateNetwork` holds one shortest-path tree per node, O(N squared) for N nodes
  of a mesh. A write that changes the topology copies it under B; a declaration does not. Whether topology
  writes are frequent enough on a large mesh for this to matter is a phase 5 reading.
- **The face map's copy.** A face transition copies the face map's spine (one pointer per face) until phase
  6 makes it persistent; at 2,048 faces that is 16 KiB per transition.
- **The tick.** Under B the tick that finds nothing dirty need not publish; whether to split it into a read
  that decides and a write that acts is decided in phase 4 by what it writes (queries and interests timed
  out, egress swept: the last is per-face runtime and needs no version).
- **Sends under the writer.** `register` sends its replay while holding the write guard. Under B it holds
  only the writer mutex, so readers are not stopped, but other writers are; moving the sends after the
  publish is possible because a later version cannot lose what the replay was computed from, and is not
  done until a measurement asks for it.
- **The gain is a prediction until phase 5 runs.** If B costs more per message than A, B stays a value for
  the deployments whose writers are what they pay for, and the reading is recorded here as such.
