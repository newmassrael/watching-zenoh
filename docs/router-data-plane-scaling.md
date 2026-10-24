# Router data plane: scaling design

Status: proposed. A design note, not a registered document (see CLAUDE.md, "SSOT contract").

This note says why the AP router's per-message cost grows with the number of connected subscribers,
what the data plane has to guarantee instead, and the order in which to change it. Every number below
was measured with the tools named in section 6; nothing here is a claim about hardware other than the
host it was measured on, and each measurement is one run per cell.

## 1. What was measured

Setup: `wz-ap-demo --router-hat` (release profile, thin LTO, one codegen unit, `preset-ap-client` plus
`router-hat-router`) pinned to two cores of one host; clients are `wz-ap-demo --sessions` processes on
other cores of the same host, each session subscribing to its own key and publishing to its neighbour's.
CPU time is the router process's user plus system time from `/proc/<pid>/stat`; the number of messages
forwarded is the router's own `forwarded mesh data (N push(es))` counter. The offered load is 12.8k
messages per second in every row, so the rows differ in the number of subscribers and in nothing else.

| Subscribers | CPU per forwarded message, steady | With 16 sessions/s joining and leaving |
|---|---|---|
| 256 | 22.1 us | 25.9 us (+17%) |
| 1024 | 38.5 us | 55.7 us (+45%) |
| 4096 | 129.4 us | not measurable (see below) |

A fit of the steady column is roughly `17 us + 0.03 us * subscribers`: the cost of one message depends on
how many subscribers exist, not on how many it is delivered to (one, in this workload).

At 4096 subscribers the router thread reached 91% of one core and forwarded 7.0k messages per second of
the 12.8k offered. Within about twelve seconds 4347 faces went DOWN (lease expiry), after which the
steady population was gone. The router degraded by dropping its links, not by shedding load.

Two settings decided the rest of what was seen and are recorded because they are not the defaults a
reader would guess:

- `max_sessions` is 1000 by default (upstream's default as well). The 1001st session is refused; a
  run with more subscribers than that measures the refusal, not the router.
- With `runtime-tokio-uring` (part of `preset-ap-full`) each face holds a 32 MiB registered buffer
  region, measured as 33.8 MiB resident per face. Without it a face costs about 87-100 KiB. The router
  numbers above use the build without it.

## 2. Why the cost grows: findings

Each finding is a function at commit `f65af9717` of `crates/wz-runtime-tokio/src`.

F1. Delivery visits every face. `deliver_to_client_subscribers` (router_forward.rs) obtains the faces a
message goes to from the cached `client_route`, as a sorted list, in constant time. It then delivers
through `fan_out_tier_qos`, which iterates every face the router holds, filters by tier, and for each
one calls `peer_zid_routing` before asking the per-face closure whether the face is a target. The
closure used for client delivery ignores the zid and only tests membership of the list it already has.
`peer_zid_routing` (peer_identity.rs) takes the session's mutex, clones a `Vec<u8>`, and converts it
with `Zid::try_from`. With one target and N faces that is N-1 wasted lock, copy, convert and free
sequences per message. A profile with call chains (frame pointers on, 1024 subscribers) put
`peer_zid` at 13.3%, `Zid::try_from` at 6.5%, `memmove` at 7.5% and the loop body of `forward` at
18.8% of cycles, every one of them called from `RouterForwarder::forward`.

F2. A face's identity is read from the session each time. `RouterFaceState` has a `peer_zid` field,
but only under `adminspace-introspection-handlers`, where a single reader (the admin `Sources` body)
uses it. Identity is a fact about a face in every build; the data plane is a reader in every build.

F3. A change to the subscription table discards every cached route. `RouteCache::get_or_compute`
(route_cache.rs) clears the whole map when the table version differs from the one it was filled at.
After one subscribe or unsubscribe, the next message for each key recomputes its route from scratch
(`client_route` scans the subscriptions; on a miss, `names_a_resource` compares keys across every
client). The cost of one flush is proportional to (keys in use) x (subscriptions), and a service where
devices come and go flushes continuously. The churn rows above are consistent with this; they do not
prove it, because the cost of accepting and tearing down a session is in the same number.

F4. The forwarder is single-threaded by construction (`Rc`, `RefCell`). A second core does not help the
data plane; throughput is bounded by `1 / (cost of one message)`.

F5. Nothing protects the control plane from the data plane. When the one thread is saturated, keepalive
and lease handling wait behind data, so links expire and the load that caused it is replaced by a
reconnect storm.

## 3. Invariants the data plane has to hold

I1. The cost of forwarding a message whose route is cached does not depend on the number of faces or
subscriptions the router holds. It depends on the number of faces the message is delivered to.

I2. Computing a route costs in proportion to the subscriptions that match the key, not to all of them.

I3. A subscribe or unsubscribe invalidates only the cached routes whose key intersects the declared key.

I4. Keepalive and lease processing is never delayed by data. Under overload the router sheds data
(counted, observable) and keeps its links.

I5. What is on the wire does not change: interoperability with the reference router and with the
embedded client, ordering per (face, key), reliability and priority handling, and every access-control
decision stay as they are. These changes are internal to how a route is represented and found.

I6. Each invariant above is held by a test that can fail for exactly one reason (section 5).

## 4. Design

### 4.1 A route is a list of targets, and identity is stored (I1)

- A face's routing zid is stored in `RouterFaceState` unconditionally and set once, when the face is
  registered, as a `Zid` (a small `Copy` value). `peer_zid_routing` stays the one place that derives it
  and is called from register, not from the per-message path.
- Delivery takes the target list and looks each target up in the face table by id. The loop body that
  checks egress access control, sends, and counts is moved out of `fan_out_tier_qos` into a helper both
  paths call, so the access-control and accounting rules exist once.
- `fan_out_tier_qos` keeps its contract for the callers that really do ask every face (topology floods).
  The client-delivery and tree-forward callers move to the targeted path.
- A face that has gone is absent from the table, so a cached target that outlives its face is skipped.
  Face removal also bumps the version of the routes that held it (4.2), so it is not skipped for long.
- Landed: the stored zid, the shared egress helper, and the targeted fan-out for client delivery. The
  tree-forward path (`forward_push_tier`) still walks the faces of its tier, now reading the stored zid
  instead of deriving it; its targets are zids, so moving it to the targeted path needs a zid-to-face
  index, which is not built until a measurement of a router-heavy mesh asks for it. The router tier
  holds a handful of faces; the clients are the population that grows.

### 4.2 Subscription index and incremental invalidation (I2, I3)

- Subscriptions with no wildcard are kept in a hash map from key to the set of faces; a message whose key
  is a literal finds its literal subscribers in constant time. Subscriptions with a wildcard are kept in
  a trie over the key's chunks, whose traversal cost depends on the wildcard subscriptions that could
  match, as the upstream resource tree's does. The wildcard and intersection semantics are the existing
  ones (`keyexpr_intersects_target`); this changes how candidates are found, not what matches.
- A cached route is attached to the key it was computed for. A declaration for key K marks stale the
  cached keys that intersect K, found through the same index. Nothing else is recomputed.
- The resource test (`names_a_resource`) becomes a lookup in the index rather than a scan.
- Landed for the client subscriptions, which are the population that grows: `ClientSubStore` indexes
  them by key (literal keys by hash, keys with a wildcard kept apart), is writable only through methods
  that record the key they moved, and keeps a bounded log of those keys under the version each produced.
  `RouteCache::refresh` reads that log and retires the routes the changed keys intersect; a topology
  move, or a reader the log no longer reaches, retires everything as before. The mesh tables
  (`LinkstatepeerInterest`) keep the whole-cache invalidation and the linear scan: they hold the
  router-tier and peer-tier faces, a handful, and their routes also depend on the topology graph, so
  per-key retirement there needs the graph's own change record first.
- Not landed: the wildcard trie. A literal key's route is a lookup plus a scan of the wildcard
  subscriptions only; a trie matters when there are many wildcard subscriptions, which section 7 says
  to wait for a measurement of.

### 4.3 Control plane before data (I4)

- Keepalive and lease handling for a face does not wait behind that face's, or any face's, data.
- A face is served at most a fixed number of messages per scheduling round, so one busy face cannot
  starve the rest. (Built, as a quantum of work units with deficit round robin: section 7.2.)
- When the per-face or router-wide queue passes a bound, data messages are dropped and counted
  (reliable and best-effort treated as the protocol defines them); links are kept. The counter is
  exposed on the admin space next to the existing ones.

### 4.4 Using more than one core

The data plane stays single-threaded per router process. The deployment shards instead: the service
already assigns each group to a slot and each slot to an instance, and a router process per slot range
serves that range's devices. This uses every core without changing any ordering guarantee, bounds the
number of subscriptions per process, and is the same table the application needs for horizontal
scaling. A multi-threaded data plane is not planned; section 7 says what would make it necessary.

## 5. How each invariant is held

This repository's own record is that a time threshold on a shared runner generates flakes (the
decode-cost lane in `scripts/run-ci.sh` asserts none, for that reason). So the invariants are held in
two different ways, and a timing number is never what fails a build.

Structural invariants are asserted on counters, which are exact. A counter is what a router already
keeps for the same purpose (`client_route_computes` is one) or a new one beside it.

| Invariant | Test | Asserts |
|---|---|---|
| I1 | a router holding 64 client faces forwards one Push to one subscriber | faces visited equals 1; only that subscriber was sent a frame |
| I1 | the same with 1024 faces | the same numbers, so the count does not depend on the table |
| I1 | a face's zid after register | the stored zid equals what the session reports, so the path reads it and does not derive it |
| I1 | a targeted fan-out over a vanished face and a face of another tier | only the target of the tier is asked; every target is counted as visited |
| I2 | a literal key's route is computed by a lookup | routes computed equals 1 after one publish and stays 1 after more |
| I3 | after a subscribe for an unrelated key, a cached route is served | `client_route_computes` unchanged by the next publish to the cached key |
| I3 | after a subscribe for an intersecting key, that route is recomputed once | `client_route_computes` increases by one |
| I4 | a router past its queue bound under a data flood | data dropped is counted; faces going DOWN is zero |
| I5 | the existing interoperability tests against the reference router and the embedded client | unchanged |

Timing is measured, not asserted. One opt-in lane runs the real binaries (`wz-ap-demo --router-hat`
and `--sessions`) at the subscriber counts and churn rate of section 1 and prints the table of that
section. What it does assert is the population, as the decode-cost lane does: every session
connected, none refused, no face went DOWN in the measurement window, and the router forwarded at
least 80% of what was offered. A run in which any of that fails measures something other than the data
plane, and says so.

The structural tests land with the change that makes each of them pass, so the repository never
contains a red gate; most of them fail today for the reasons in section 2. The measurement lane lands
first, so the starting point is a number committed with the tool that produced it and not a number
remembered.

## 6. Tools

The measurements used `wz-ap-demo --router-hat <addr> --max-sessions <n>` and
`wz-ap-demo --sessions <file>` (`subscribe` and `publish` driver roles). The router was started under
`taskset` and read through `/proc`. The profile used `perf record -g` on a build with
`-C force-frame-pointers=yes`; without frame pointers the call chains are cut at the first frame.

## 7. Not decided, and what would decide it

- Whether the wildcard trie is needed at all for the service this router carries. Subscriptions there
  may all be literal. Section 4.2 builds the literal path first and the trie only if a measured workload
  with wildcard subscriptions shows the scan.
- Whether a multi-threaded data plane is ever needed. It would be if one slot range cannot be served by
  one core after 4.1 and 4.2 and cannot be split further. The measurement that would show it is the
  single-process throughput after those changes, on the host class the service runs on.
- The queue bounds and the per-round message count of 4.3. They are tuned against the I4 test, not
  chosen in advance.

### 7.1 What was measured about 4.3 after 4.1 and 4.2 landed

The premise of 4.3 was F5: under overload the links expire. It did not reproduce. Same host, same
build, offered load raised until the router could not forward it all (loopback, four client processes):

| Subscribers | Offered | Forwarded | Faces that went DOWN |
|---|---|---|---|
| 256 | 128k/s | 65% (about 83k/s) | 0 |
| 256 | 256k/s | 48% (about 123k/s) | 0 |
| 2048 | 200k/s | 91% (182k/s) | 0 |

Two corrections to section 2 follow from reading the code for this check. The per-face outbound queue
is not unbounded: it has one lane per priority, bounded in bytes at zenoh's defaults, drops what
congestion control says may be dropped and counts it (`writer_queue.rs`, `session_actions.rs`). And the
router is not one core: the forwarder is single-threaded (F4) but each face's writer task is not, so
the process used more than one core at 182k/s.

The loopback runs above have the router the whole host. The case 4.3 was written for is a router
that is overloaded AND short of CPU, which is what a burstable micro VM under steal is. The harness
now reproduces it without a VM: the router is pinned to one core at a lower priority, and three busy
processes share that core from the moment every session is in (`taskset`, `nice`; the scheduler
shares a core between threads, and the router has several busy ones, so without the lower priority
the three hogs left it most of the core and the first attempt measured nothing):

| Condition | Result |
|---|---|
| 2048 subscribers, 40k/s offered, router on a shared core at lower priority | forwarded 7.7k/s (19% of offered), 0 faces DOWN over 20 s |
| the same, and 16 new sessions/s knocking | 161 of 320 attempted admitted within the window |

(`wz_router_hat_keeps_its_links_when_overloaded_and_short_of_cpu` and
`wz_router_hat_admission_when_overloaded_and_short_of_cpu`, run by Layer E7s. The first asserts that no
face goes DOWN; the second prints and asserts nothing.) The window is 20 s and the lease is 10 s, so
a face whose keepalive was starved would have shown.

(Section 7.2 corrects this paragraph: the count of faces that went DOWN was the router's own, and a
starved router sees a face go down only when its loop comes back to that face, so the count was
a race and not the invariant.)

So the invariant I4 states holds on this measurement: links are kept while data is shed, and the
data is shed by the senders' own flow control, not by the router dropping links. What does degrade
is admission: a starved, overloaded router takes in new sessions at about half the rate they knock.
That is a trade between serving the faces it has and admitting new ones, and where it should sit is
a decision about the service (a reconnect storm after an outage is exactly the case where many
sessions knock at once), not something to fix by default. 4.3 as written (a new priority scheme,
per-round fairness, a router-wide shed counter) is therefore not built. What would reopen it is a
face going DOWN under these conditions on the real micro VM, or an admission rate the service cannot
live with.

### 7.2 What 7.1 missed, and what was built (measured 2026-10-23 and 24)

7.1 counted the faces the router saw go DOWN. A starved router sees one only when its loop comes
back to that face, and the loop did that once per pass over all its faces, which under starvation was
up to 18 s. So the count inside a 20 s window was a race with the window, and the test passed or failed
by it. The property is the CLIENTS' side: in every starved run about 1400 to 2000 of the 2048 clients
closed on their own lease expiry (their staged close reason was `Expired`; the unstarved control had
none, measured in round 3467). On a build host with four cores the test failed five runs of five at the last commit
the hosted runner had passed.

**Cause.** The session loop took its next event with no await that suspends, and a read served from
bytes already buffered does not spend tokio's cooperative budget, so a face with a backlog kept the
thread until the backlog was gone. The thread's return to any other face was the sum of those turns.
Counters on the router: about 25000 inbound events a second, and about 120 lease checks and 100
keepalive writes a second where 600 were due. Ruled out by experiment: yielding after every write of
the writer task (no change), the lifecycle and `rx/max_message_size` commits (the same failure at the
green commit).

**What holds the property now (`session_glue.rs`, `Turn`).** The loop's turn is a quantum of
`TURN_UNIT_BUDGET` (8) work units; an event costs one unit for each record it carries, and an event
that costs more than the quantum pays the excess by yielding that many rounds, which is deficit round
robin with the run queue as the round. A task that becomes ready meanwhile, another face's timer
included, runs within one turn, whatever the size of the frames. Two tests hold it without a clock or a
loaded machine (`session_keepalive_tx.rs`, `a_task_that_wakes_during_a_backlog_runs_within_one_turn`
and its control, which shows the same flood keeps the thread without the loop's yield).

**The bound, and what is measured about it.** A session returns after at most
`faces x quantum x cost of a unit / share of the CPU`. The cost of a unit is an upper bound that needs
no split of an event's cost into a fixed part and a part per record (`a + k b <= k (a + b)`), so it is
what an event of one record costs. Measured on a build host with the clients on the same four cores
(Layer E7s, five unloaded runs): 6.5 to 11 us of wall clock per event, of which a keepalive emission is
4.5 us, and the small write behind it 4 to 11 us. So for 2048 faces on a twentieth of a core the return
is 2.1 to 3.6 s against the 10 s lease, and the keepalives alone (2048 per 3.3 s at about 9 to 16 us)
take about 1% of a core. The first figure given for this bound, 0.7 s, used an assumed 2 us an event
and is withdrawn.

**Result** (whole E7s binary, 4 cores): clients that closed on `Expired` in the 20 s window, 1400 to
2000 before and none after; faces DOWN 3 before, none after; new sessions admitted by the starved
router 12 of 320 before and 320 of 320 after; the cost table 13.2 us a message before and 12.5 after;
the starved router forwards 25 to 35% of what is offered, and there is no figure for it before
because those runs collapsed.

**Not built, and why it is still wanted.** The quantum bounds the return in proportion to the number
of faces and inversely to the CPU share, and nothing yet states the share and the number of faces
below which the bound is promised. What remained of 4.3 when this was written (the keepalive half of the
first item is built, 7.3): keepalive and lease work in an executor of its
own with strict priority over data (a stage measured on a saturated shared runtime put a 100 ms timer
late by up to 2.4 s, and on a dedicated one-thread runtime by at most 31 ms), a capacity model that
admits a session only while the control work it adds fits the configured budget, a stated drop policy
for data with counters on the admin space, and a test that asserts the latest a timer was served
and not the count of faces that went DOWN.

### 7.3 What the control-plane change adds, measured by taking its parts away (2026-10-24)

The control-plane change of the lifecycle line (ledger 3482) has three parts: keepalive timers on a
runtime of their own (`ctl`, `WzRuntime::Control`), the keepalive frame sent as an urgent frame that
passes every lane and is written from the calling thread when the link can
(`BoxedLinkDriver::send_urgent`), and the keepalive baseline stamped when a write finishes and not when a
frame is queued. It landed with E7s passing over the loop's yield and no reading of what each part
adds on its own. Each was switched off alone and in combination on one binary, E7s on four cores of a build host, offered 40000 messages a second, 2048
subscribers, the router on one core at nice 10 beside N CPU hogs. What is read is the longest silence a
client session saw from the router, between two receptions on one session, against the 10 s lease, and
the count of client sessions that ended on their own.

- Up to 16 hogs neither the loop alone nor the whole change ends a session (6, 10 and 16 hogs were run
  for those two only): the quantum keeps the return of the loop inside the lease. At 3 hogs the longest
  silence is 3.1 to 3.3 s in all six variants, and no part moves it.
- At 32 hogs the loop alone ends sessions (0, 2, 2 in three runs; longest silence 9.9 to 10.1 s). Each of
  `ctl` alone (8.2 to 8.9 s) and the urgent frame alone (8.0 to 9.7 s) ended none, and both together
  gave 6.9 to 7.9 s and none. The router's own longest silence from its peers, 12 to 14 s here, is the
  loop's return time and none of them moves it: it is what the capacity model has to state.
- The write-end stamp alone matched the loop alone (0, 2, 5 sessions ended) and, with the other two,
  did not beat them. No reading here shows what it adds. The reasoning for it (zenoh's tracker resets
  after the write) stands, so it is kept; a scenario in which it matters, and a test of it, are not
  found yet, and until one is its share of the guarantee is not demonstrated.

So `ctl` and the urgent frame are the part that holds a lease past the point where the loop's return
time alone does not, which for this population is around 32 hogs; beyond that the router's reception of
its peers is what fails (its longest silence is already past the lease at 24 hogs), and that is a
capacity question. The share of a core that 32 hogs leave the router is not stated here: the router's
threads and the hogs are weighted by the scheduler, and no figure was read. Samples are three runs a
variant on a host whose load was 10 to 30, so the figures show the order of the effect and not its size.
The measurement is a test now: the E7s test counts the client sessions that ended on their own (the
client prints `ended (` for one) and asserts none, beside the router's own DOWN count.
