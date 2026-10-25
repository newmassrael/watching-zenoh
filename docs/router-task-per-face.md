# The router with a task per face

Step 3 of the plan that began in `docs/router-data-plane-scaling.md` (7.5 to 7.7). This is the design and
its measured starting point, written before the first line of the change, so that the change is judged against
it.

## 1. Why

The router drives every face from ONE loop task (`accept_loop`, `Step::Driven`) and calls
`RouterForwarder::forward` inline from it. Everything that can wait therefore stops every face:

- A send that waits for room stopped the loop for as long as it waited (up to `wait_before_close`, 5 s). The
  credit stage of rounds 3541 to 3568 holds the message instead, and the chain fix of round 3578 sends a chain
  that cannot be held waiting, which still stops the loop for that wait (Layer E7m measured the stall, a 5.0 s
  gap, when the first form of that fix sent 64 KiB chains that way; the form that landed sends only a chain
  longer than the lane).
- The keepalives are served by the control runtime, not by this loop, since round 3482; the loop's own monitor
  tick on a starved router was two to four seconds (7.7), which is why the capacity control has a thread of
  its own.
- A held message is retried when the loop reaches the destination (`drain_egress` on the loop's wake), so one
  loop does the work of every destination's writer-side bookkeeping.

A task per face makes each of these one face's. It is also what the room reservation (7.6) needs a consumer
for: a reservation spares a thread the park only where a TASK is what waits.

## 2. What the data path touches

Measured on `crates/wz-runtime-tokio/src/router_forward.rs` as of round 3603: 8 926 lines outside its test
module, with 58 `RefCell`, 84 `Cell`, 51 `Rc`, 66 `borrow_mut()` and 140 `.borrow()`. `RouterForwarder` has
about fifty interior-mutable fields. A Push (`route_push`) reads:

| State | Where it is | Mutated on the data path? |
|---|---|---|
| Per-region hats: the mesh net, the subscription tables | `hats: RegionMap<Hat>` | no, by declarations and topology only |
| The routes cache of each hat (`data_routes`, `client_routes`) | inside each `Hat`, passed as `Cached { routes, .. }` | YES: a memo, filled on a miss |
| The inbound face's alias table (`keyexpr_table`) | `faces: Rc<RefCell<HashMap<FaceId, RouterFaceState>>>` | no (declarations write it) |
| The inbound face's zid and graph link | `faces` | no |
| Each destination's send seam, and its held queue | `faces`, `RouterFaceState::held` | YES: the held queue |
| The credit (held, bytes, gates, counters) | `credit: Rc<egress::Credit>` | YES: `Cell`s and a `RefCell` |
| The node's hybrid logical clock | `node_hlc` | YES: stamps every Push |
| The ingress and egress interceptor chains and their per-keyexpr caches | `RefCell`s | the caches, YES |
| Local (host) subscribers, multicast groups | `RefCell<Vec<..>>` | no |
| Counters (`data_seen`, `data_sent`, `fan_out_face_visits`, ...) | `Cell<usize>` | YES |

So the data path writes four things (the route memo, the held queues and credit, the HLC, the counters) and
reads the rest. That is the shape that makes a reader-writer split possible, and it is the whole of the
design problem: what must be concurrent on the read side is those four.

## 3. Upstream's shape (read from the pinned source)

`zenoh/src/net/routing/dispatcher/tables.rs` @ `pub struct TablesLock`: `tables: RwLock<Tables>`,
`ctrl_lock: Mutex<()>`, `queries_lock: RwLock<()>`. The data path takes the READ lock
(`zenoh/src/net/routing/dispatcher/pubsub.rs` @ `let rtables = zread!(tables_ref.tables);`); declarations and
topology take the write lock. The routes cache is not behind the tables lock: each resource's context holds its
own route memo (`zenoh/src/net/routing/dispatcher/resource.rs` @ `pub(crate) data_routes: RwLock<DataRoutes>,`),
so a reader that misses fills the memo under that small lock and stays on the shared one.

## 4. The choice

Three structures were weighed.

| | What it is | For | Against |
|---|---|---|---|
| A. Reader-writer tables | `Arc<RouterTables>` with `RwLock<Tables>`; the data path under `read`; the memo, the held queues, the HLC and the counters each behind their own small lock or an atomic | Upstream's structure, so parity is the argument and not a hope; the conversion is `Rc<RefCell<T>>` to `Arc<RwLock<T>>` field by field, in steps that each compile and run | A write (a declaration, a link change) stops the readers for its length; a long fan-out under `read` holds a writer off |
| B. Epoch snapshots (RCU) | A control task owns the tables and publishes an immutable `Arc<Snapshot>`; faces read their snapshot with no lock at all | No reader ever waits; the lock-free read is the textbook form | A snapshot is rebuilt or patched per declaration, which has not been costed here; the memo needs a concurrent map keyed by epoch; a face sees its own declaration only once the epoch it caused is published (read-your-writes needs a wait) |
| C. Shard by loop | N loops, each owning the faces hashed to it, with cross-loop messages for a destination on another | No shared tables | Every Push to a destination on another loop is a message; the tables are copied N times |

**Recommended: A, with B held back for the day the lock is measured to cost.** The argument is the goal of this
repository (a replacement of zenoh): A is the structure it replaces, and the behaviour a peer observes (a
declaration made before a Push is applied before it, across faces) is upstream's by construction, which B
weakens to per-face read-your-writes. Whether A's read lock is a cost is a measurement and not an opinion, and
the instrument is Step 6 of the plan, built in round 3607 as a count of heap allocations and bytes per forward
(`crates/wz-runtime-tokio/tests/router_hot_path_cost.rs`, section 6), together with Layer E7s's microseconds
per message; B is the answer only if those say the lock is what is being paid for.

## 5. Phases

Each phase ends with the tree green and the numbers of Layer E7s (microseconds per message at 256, 1024 and
2048 subscribers, with and without churn) no worse than before it.

0. **Group (done, round 3619).** `struct Tables` holds nine fields: `hats`, `partition`, `faces`,
   `joined_links`, the local subscribers and queryables and the three future stores (`future_subs`,
   `future_qabls`, `future_tokens`), each the type it was; the forwarder has one `tables: Tables` and the
   routing code reads `self.tables.<field>`. No behaviour change, held by the router_forward tests (226 in the
   default set, 228 and 273 in two others, the same counts as before) and by the hot path budget, which did not
   move by a byte (a grouping that allocated would have). Left out on purpose, because the data path writes
   them and so each needs a lock or an atomic of its own (phases 1 and 2), not a place under one: `pending`,
   `group_subs`, the interceptor chains and their caches, the counters. What went wrong in doing it, so that
   phase 3 does not repeat it: a textual `self.faces` to `self.tables.faces` also rewrote three other types in
   the file that have a `faces` field of their own (`RouterSessionsView`, `RouterSessionDirectory`,
   `RouterDeclarationsView`, which hold a shared handle to it, not the forwarder), and `cargo fmt` had wrapped
   some accesses across lines (`self` and `.field` on separate lines), which a replace of the one-line text does
   not reach; four of the feature sets (token tables, shared memory, the lifecycle, all together) each showed a
   different leftover, because the code that uses a field exists only behind its feature. Check every feature
   combination that gates a moved field, not the default set alone.
1. **Counters and HLC (done, round 3623).** The 21 witnesses the router counts with (`data_seen`,
   `data_sent`, `ingested`, `queries_seen`, `timed_out`, `fan_out_face_visits`, the shared-memory drops, the
   interceptor drops and cache recomputes, the future-store pushes, the face-up replays, the multicast ingress
   and peak witnesses, `recomputes`) are `Counter`s (`router_forward/counter.rs`), each an `AtomicUsize` with
   `Relaxed` ordering: a counter publishes nothing and no decision on its value has to agree with another memory
   location, so what it must keep is only that no increment is lost, which every read-modify-write does at any
   ordering. Three tests: the three ways a count rises, eight threads of a hundred thousand bumps lose none, a
   peak from many threads is the greatest offered. `NodeHlc` needed no lock of its own: it holds an
   `Arc<NodeClock>` over `uhlc::HLC`, which serialises itself, and a compile-time test now holds it to
   `Send + Sync`. What it cost, measured on the same host with the same command before and after (least of 25
   repetitions of 20000 forwards, ns per forward; before | after, two runs): one subscriber, drop 498 |
   456, 442; one subscriber, block 590 | 553, 529; sixteen, drop 4135 | 3971, 3898; sixteen, block 4780 |
   4604, 4386. No increase: about eighteen atomic adds per forward are below the run-to-run spread of the host
   (the two after-runs differ from one another by as much as either does from the before), and the faster figures
   are noise, not a gain. Bytes and allocations per forward did not move (569, 708, 7454, 8718; 9, 11, 69, 86).
   The other `Cell`s of the forwarder (the autoconnect policy, the query timeout, the interceptor version, the
   multicast governance flag, the dirty flags of the hats) are state, not counts, and move with the tables in
   phase 3; the forwarder is therefore still not `Sync` after this phase. Every `--lib router_forward` guard
   moved by the three counter tests (229 231 252 234 237 276 229 231) and `node_clock::` by one (15).
2. **The memo (done, round 3627).** `RouteCache` (`route_cache.rs`), the one type behind the four route
   memos of the forwarders (`DataRoutes`, `ClientRoutes`, `ClientQueryRoutes`, `QueryRoutes`; `data_routes` and
   `client_routes` of a hat are two of them), is behind its own reader-writer lock, `PlainRwLock` (`sync.rs`,
   `parking_lot`'s, the counterpart of the crate's `PlainMutex`: not poisoned, and a read guard is one atomic
   add), and counts what it computed with a `Counter`. A hit takes the read lock, clones the route out and lets
   go; a miss computes OUTSIDE the lock and stores under the write lock, so a route that is slow to compute
   holds no reader. The soundness argument is written on the type: every version a route is fresh against is
   moved by a mutation of the tables, and a mutation takes the tables for writing (phase 3), so the inputs
   cannot move while a reader holds the tables; two threads that miss the same key compute the same route at the
   same inputs and the second store replaces the first with an equal value. What a route is made of had to
   change with it: `Rc<[T]>` of the four route types is `Arc<[T]>` (the allocation is the same, the count is
   atomic), because a cache of `Rc`s is not `Sync`. `Counter` moved from the forwarder to the crate
   (`counter.rs`) since the memo uses it too. Two tests: a cache of shareable routes is `Send + Sync`, and eight
   threads asking for one key all get its route and it is kept once. Bytes and allocations per forward did not
   move (569, 708, 7454, 8718; 9, 11, 69, 86). Time per forward (least of 25 repetitions of 20000, two runs,
   ns; the phase 1 runs in brackets): one subscriber drop 494, 485 (442, 456), block 576, 575 (529, 553);
   sixteen drop 3860, 3846 (3898, 3971), block 4594, 4463 (4386, 4604). The one-subscriber drop reads about 40
   above phase 1 and equal to the figure before phase 1 (498); the spread between runs of one tree on this
   host is that large (442 to 498), so this is not read as a cost and not as a gain.
3. **Tables behind `RwLock`.** `Rc<RefCell<..>>` becomes `Arc<RwLock<..>>`; the forwarder is `Send + Sync`. Held
   queues and the credit move with it (`Cell` to atomic; the held queue to a `Mutex` per destination, so that
   two faces feeding one destination do not meet on the tables lock). It is the largest phase (the forwarder's
   non-test code is about 273 methods and 6 000 lines of `impl`, with 58 `RefCell`, 84 `Cell`, 51 `Rc`, plus the
   handlers of local subscribers and queryables, which are `Rc<RefCell<dyn FnMut>>` and must become `Send`), so
   it lands in steps each of which compiles, passes and is measured, and none of which makes the forwarder
   `Sync` before the last:
   - **3a. The credit stage (done, round 3633).** `Credit` and its view are `Send + Sync`; see below.
   - **3b. The rest of the state the data path writes** that is not tables: the pending-query table, the
     interceptor chains and their per-keyexpr caches, the `Cell`s that are state (`autoconnect`,
     `query_timeout`, `interceptor_version`, `mcast_governed`, the dirty flags of the hats), `clock`
     (`Box<dyn Fn() -> Instant>`, not `Send`), `dial_tx` and the multicast state.
   - **3c. The tables** under one `RwLock<Tables>`: the nine fields of phase 0 lose their cells, a method that
     reads takes `&Tables`, one that writes `&mut Tables`, and the three views that share `faces` hold the
     shared handle instead of an `Rc`. Locks taken in one order (tables, then the leaf locks), as the credit
     stage's order below.
   - **3d. The handlers** of local subscribers and queryables (`Send`), and the forwarder's `Send + Sync`
     proof, with the test of many faces' threads into one router that the earlier steps could not write.

   **3a, what it did.** `Credit`'s fields are each a lock or an atomic: `gated` and `holding` are
   `PlainMutex`es, the held and held-bytes counts are a new `Gauge` (`counter.rs`: added to and subtracted from,
   `Relaxed`), the released, abandoned and closed counts are `Counter`s, `credit` is an `Arc`, and a
   destination's held queue (`RouterFaceState::held`) is a `PlainMutex<EgressQueue>`. The locks have one
   order, written on the type: a destination's queue, then `holding` (a leaf under it), then `gated`, and no
   thread holds `gated` while it takes a queue. That excluded a cycle the old code had no way to show: `hold`
   took `gated` with its queue in hand, and `release_gates` read the queues with `gated` in hand. `hold` now
   lets the queue go and asserts the gate from what it read there; `release_gates` reads the destinations'
   bytes first and takes `gated` after, and a gate that a stale reading releases is asserted again by the next
   message that finds the budget reached, so it costs one frame its face had already read. A gauge is added to
   before the message is pushed, inside the queue's lock, so no pass that drains the queue can subtract what
   has not been added. The face being routed (`Credit::source`, which the gate asks whom to gate) was a field
   set by `forward` and cleared when it returned; with two faces' tasks it would name whichever frame was
   routed last. It is now a thread-local scoped by the guard `forward` already held, keyed by the credit stage
   it was set for, and the guard puts back what it interrupted. A thread-local is right here and not a shortcut:
   `forward` is a synchronous call that runs to its end on the thread that made it, so the face it routes is
   a property of that call; passing it as an argument would thread a value fixed for the whole call through some
   thirty sends, several inside fan-out closures. What it did not change: `drain_egress` still holds the
   destination's queue while a chain, which has to wait for room between its fragments, is sent (phase 6 makes
   that wait a task), so a face that feeds that destination waits at its queue for as long as the chain does,
   which is what the loop did for every face. Tests: the stage, its view and the queue are `Send + Sync`; the
   face being routed is the thread's own for this stage and is put back; a gauge added to and subtracted from by
   eight threads returns to where it started. The test that holds into one queue from many threads has to go
   through the forwarder and waits for 3d. Measured: bytes and allocations per forward did not move (569, 708,
   7454, 8718; 9, 11, 69, 86); time per forward, least of 25 repetitions of 20000, two runs (the phase 2 runs in
   brackets, ns): one subscriber drop 519, 506 (494, 485), block 592, 591 (576, 575); sixteen drop 3983, 3872
   (3860, 3846), block 4562, 4420 (4594, 4463). The blocking cases are the ones that take a destination's queue
   lock for every message (an uncontended `parking_lot` lock, tens of nanoseconds), and the one-subscriber
   blocking figure reads about 15 ns above phase 2 in both runs: probably that lock, and not distinguishable
   from the host's spread (the same tree read 442 to 519 on the one-subscriber drop). Layer E7s on pc2 before
   (the phase 2 head) and after, microseconds per message at 256, 1024, 2048 subscribers with no churn and at
   256, 1024 with churn: 23.2, 19.1, 21.4, 21.7, 18.9 and 18.3, 20.4, 19.5, 21.3, 21.9, no direction beyond the
   run-to-run spread of the table (the same router read 18.3 and 23.2 at 256); the starved-router tests pass
   with no face down, 963 admitted sessions ended by the router at 32 hogs both times, the longest keepalive
   timer 1863 ms before and 1940 ms after.
4. **A task per face.** The accept loop already spawns a face's drive onto the runtime when its forwarder is
   `Send + Sync` (`SpawnedFaces`, `drive_face_shared`); the router takes that path. The closure watcher
   (`watch_room`) becomes the wake list of a destination, and a gated face awaits its destination's room.
5. **The reservation.** A face task awaits `poll_reserve` for the destination's lane and sends under the
   conduit's lock with the permit (7.6), which is the first consumer of the session core's opaque permit; the
   thread park (`ParkBudget`, `wait_for_room`) leaves the router's path.
6. **Chains.** The conduit's lock becomes async so that a chain waits as a task and not as a thread; the
   chain fix of 3578 (send waiting, one message) then stops one face.

## 6. The instrument (Step 6), and what it first read

An instruction count was the plan, and the build hosts forbid it: `perf_event_paranoid` is 4 on the
development machine and on the build host, and the build host has no `valgrind`. A wall clock cannot stand in
(the host swings by a third between runs). What can is a count of heap allocations and the bytes they ask for,
read by a counting global allocator around the forwards of a Put: it is EXACT, the same number in debug and in
release and on every host (read both on the build host, identical), it moves when the path gains or loses an
allocation, and an allocation is what a lock or a shared structure changes. It does not see a loop that got
longer; `perf stat` over the same test (the module doc gives the two lines) does, where a host allows it.

The test is a gate (Layer C1AY, a guarded step of exactly one test): each of four cases asserts its exact
figures against `BUDGET`. A deliberate `push.clone()` at the head of `route_push` turned all four red, naming
the new figures (two to three allocations and 24 to 88 bytes more a forward); it was removed.

The uncongested path, per forward of one Put, as first read and after the buffer was sized from the message
(section 6.1):

| Case | Allocations | Bytes first read | Bytes now |
|---|---|---|---|
| droppable, 1 subscriber | 9 | 2 939 | 569 |
| blocking, 1 subscriber | 11 | 3 067 | 708 |
| droppable, 16 subscribers | 69 | 45 374 | 7 454 |
| blocking, 16 subscribers | 86 | 46 462 | 8 718 |

The first reading: each further delivered copy cost about 2.8 KiB and four allocations (69 minus 9 over
fifteen more subscribers; the first copy cost 2.9 KiB), for a Put whose payload is eighteen bytes. The sizes
of the allocations of one forward, recorded by a temporary instrument in the allocator (not kept), read per
delivered copy `6 18 336 2469` bytes: the key expression, the payload, the cloned carrier, and a frame buffer
of 2 469 bytes, which is `Push::MAX_ENCODED_BYTES` (2 456, the generated codec's reserve hint, not a bound)
plus the 13 bytes of frame header and extension slack the frame writer reserves
(`1 + 10 + 2 + worst_case_payload`; `dispatch_push_at` passed the constant as `worst_case_payload`). So 2.4 KiB
of every 2.8 was a buffer an eighteen-byte Put does not fill.

### 6.1 Sizing the buffer from the message (round 3617)

`frame_encode::push_capacity_hint` reads the bound off the message's own fields (every variable-width
integer at ten bytes, text and byte fields at their length, each extension entry at the widest body its kind
carries) and replaces the constant in `dispatch_push`, `dispatch_push_at` and the multicast group send. It is an
UPPER bound, not an estimate, because the lend path asks a link for a slot of that size and a slot a byte too
small is a refused send. A unit test holds it never under what `push_body` writes, for eight shapes (literal,
empty, a 201 byte key, a 2 KiB payload, aliased, delete, and a Put and a Delete carrying every metadata slot),
and far under the constant for the four plain ones.

Allocations did not move (9, 11, 69, 86): the buffer is still one allocation per copy. Bytes fell by 3.4 to
6.2 times (569 against 2 939 for one subscriber, 7 454 against 45 374 for sixteen), and a further copy now
costs about 460 bytes in place of 2.8 KiB. What the figure does not say is what that is worth in time: the
nanoseconds printed beside it swing by a factor of four between two runs on the same host and are not evidence.
Where the allocation is now served from (glibc's thread cache holds sizes to about 1 KiB, and 569 bytes is under
it, 2 469 was not) is the likely mechanism and was not measured.

It is also the figure phase 3's lock will be paid against: the lock has to cost less than the allocator it sits
beside.

## 7. What is not decided, and what could make this wrong

- **Whether a fan-out holds the read lock while it sends.** Upstream computes the route under `read` and
  sends after; wz's fan-out calls `send_one_to_face` per target, each a non-blocking enqueue (the probe) or a
  hold. If it holds `read` across the sends, a writer waits for the slowest of them; if it takes the target list
  under `read` and sends after, a face that left in between is sent to and finds it gone, which `deregister`
  already tolerates. The second is the plan, to be confirmed by a test that deregisters mid-fan-out.
- **The multicast ingress plane** (`route_mcast_ingress`, the DR election over `mcast_group_members`) reaches the
  forwarder through a channel into the same loop (`Step::McastIngress`). Under a task per face it becomes one
  more producer, and the member set it elects from has to be read consistently with the tables it routes by.
- **The shared-memory relay** (`shm_relay`) holds chunk references for the length of a routed Push
  (`open_shm_relay_pass`) and has its own counters; the counters move in phase 1, and the pass guard must not be
  held across an await.
- **The gain is a prediction until phase 4 runs.** Layer E7s measures one loop's cost per message; a task per
  face is expected to move the knee of the 32-hog table and the size of the worst keepalive lateness, and it is
  not known by how much. If phase 3 (the lock) already costs more per message than it recovers, B is the
  fallback and phases 4 to 6 are unchanged by it.
