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

0. **Group.** Move the control-plane-owned fields (`hats`, `faces`, `partition`, `joined_links`, the local
   subscribers and queryables, the future stores, `pending`, the interceptors) into a `Tables` struct inside
   the forwarder. Mechanical, no behaviour change; the routing code reads `self.tables()`.
1. **Counters and HLC.** The `Cell` counters (about thirty of the 84 `Cell`s) become atomics; `NodeHlc` takes its own lock (it already
   serialises a clock).
2. **The memo.** `data_routes` and `client_routes` get their own `RwLock`, as upstream's `data_routes` does.
3. **Tables behind `RwLock`.** `Rc<RefCell<..>>` becomes `Arc<RwLock<..>>`; the forwarder is `Send + Sync`. Held
   queues and the credit move with it (`Cell` to atomic; the held queue to a `Mutex` per destination, so that
   two faces feeding one destination do not meet on the tables lock).
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
