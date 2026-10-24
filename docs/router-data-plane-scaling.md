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

**What the yield costs a request-reply (bounded 2026-10-24, not a before-and-after).** The earlier plan was to
read it as the difference of two builds' round trips (86 to 92 us in the harness), and the harness's own spread
(82 to 104 us) is wider than any effect the yield could have, so that comparison could not have answered. The
bound comes from the other side: one `tokio::task::yield_now` with nothing else runnable costs 58 ns on a current-thread
runtime and 357 ns (341 to 404) on a four-worker multi-thread runtime, medians of nine runs of 200000 on the
developer machine with its cores idle (a release build of a ten-line program, since removed; not the build host). The loop yields once per `TURN_UNIT_BUDGET` = 8 units and a reply is one or two units, so the
yield adds at most `357 ns x 2 / 8` = 0.09 us to a request, a thousandth of the round trip and a hundredth of the
spread. Not measured: the same cost with the runtime's workers busy, where a yield costs the wait for a worker and
not the call, which is the case 7.4 is about and is not a latency of the unloaded client.

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

### 7.4 Capacity: what the router promises, and for how many sessions

7.2 and 7.3 keep leases alive by making the control work cheap to schedule. None of it says for how many
sessions, at what CPU, the promise holds, and a router asked past that point degrades every session at
once instead of refusing the one that does not fit. This section states the promise, the number, and what
the router does at the number. Built: the bound (`wz-session-core`, `capacity`), the declaration
(`WzConfig::with_capacity_contract`, the demo's `--cpu-share` and `--max-data-wait`), the refusal at the
bound (the existing `max_sessions` refusal, now fed the smaller number) and the test of the promise.
Also built: the keepalive timer lateness meter and its assertion, the router's own measurement of what a
keepalive costs on its host and the bound calibrated with it, the separate refusal counter, and two tests that
re-derive this section's numbers from the model. The drop policy is upstream's and was already built (read
below). Not built: the admin-space export of the lateness and of the cost, which waits on the owner's decision
about a wz key in upstream's admin space.

**The promise.** While the process receives at least the CPU share `s` that its operator declared, each
session of up to `N_max(s)` keeps its lease. It is conditional on `s` on purpose: a router cannot promise
a lease to a host that takes its CPU away, and a promise that does not name its condition is not testable.

**Two inequalities: one is a condition of the promise, the other of the service.** With `T` the lease (10 s, a keepalive every `T/3`),
`N` the sessions, `q` the loop's turn quantum (8 units), `c_u` the cost of one loop event of one record,
`c_k` the cost of one keepalive emission:

- (A) Emission. The keepalives are written by one thread (`ctl`), and the scheduler divides the process's
  share among the threads that are runnable together, `b` of them, so that thread has about `s / b`. All
  `N` keepalive timers can fall due together, and serving them takes `N c_k b / s`. For the emission to be
  late by less than `2T/3` (the invariant a keepalive sent every `T/3` needs, so that one lost interval
  is still inside the lease) the burst has to finish within `T/3`: `N <= s T / (3 b c_k)`. With
  `c_k` = 10 us, `T` = 10 s, `b` = 4 and `s` = 1.32% (the router at 32 hogs) this is 1100 sessions,
  and 1466 at 24 hogs (`s` = 1.76%).
- (B) Service. The loop returns to a face after `R = N q c_u / s` (7.2), and a frame waits in its buffer
  that long. It does not cost a lease: before the loop judges a peer silent it reads what is waiting
  (`take_what_is_waiting`, `session_glue.rs`), and a frame decoded there stamps the peer's activity, so a
  peer with a frame in the buffer is alive to the check. Measured: at 32 hogs `R` is 13 s against a lease
  of 10 s, no face of the router went DOWN and no client session ended. What `R` costs is how stale the
  data a face is given is, and how late the router finds a peer that really is gone (by up to `R` past
  its lease). That is a limit of the service: for a frame to wait at most `L`, the longest wait the
  operator accepts, `N <= s L / (q c_u)`. With `c_u` = 11 us, `s` = 1.3% and `L` = 5 s this is about 740
  sessions.

The promise needs (A) alone: `N_max(s) = s T / (3 c_k)`. An operator who declares `L` as well gets
`min(N_A, N_B(L))`; with no `L` declared there is no limit from (B), as there is none today.

**What (A) says about the runs, and the measurement that corrected it.** The first form of this section
used `c_k` = 4.5 us, read once on an unloaded host, which put (A) at 2440 sessions at 32 hogs and said
2048 sessions were inside it. Another session then measured the router at 32 hogs on the tip of ledger
3486 (host load 5 to 31, 20 s window, instrumentation reverted):

| sessions `N` | runs | client sessions that ended on their own |
|---|---|---|
| 1024 | 5 | 0, 0, 0, 0, 0 |
| 1536 | 5 | 0, 0, 0, 0, 0 |
| 2048 | 5 | 375, 373, 676, 1158, 565 |
| 2560 | 5 | 1350, 1538, 1667, 1145, 1432 |

The loss starts between 1536 and 2048, not near 2440. One emission with its urgent write cost 6 to 10 us
at the median and 12 to 48 us at the 99th percentile, not 4.5. The keepalive's lateness against its due
time peaked at 6.4 s at 1536 (the plateau just under `2T/3` = 6.67 s) and at 8 to 12 s and still growing
at 2048 and above: losses begin where the lateness passes `2T/3`, which is the condition (A) is written
for. With `c_k` = 7 us (inside the measured 6 to 10) the bound is 1570, inside the bracket; with 10 us it
is 1100, at 0.72 of the largest population that lost nothing, and that is the number recorded. Not
measured: the share of the `ctl` thread (0.33% is from the scheduler's weights, not read from the
thread's own counters), the cost of a whole pacer cycle (only the emission and the sleep overshoot were
timed), and the steady state above the threshold, which a 20 s window is too short to show.

**Evidence for the form of (B).** The router's longest silence from its peers in the E7s runs of 7.3 against `R`
computed from the scheduler's weights (the router's threads at nice 10, weight 110, against the hogs at
1024, four busy router threads, `c_u` = 11 us, 2048 sessions):

| hogs | share `s` | predicted `R` | observed |
|---|---|---|---|
| 6 | 6.7% | 2.7 s | 2.8 to 3.3 s |
| 10 | 4.1% | 4.4 s | 4.3 to 5.0 s |
| 16 | 2.6% | 6.9 s | 7.1 to 8.2 s |
| 24 | 1.8% | 10.3 s | 10.2 to 11.0 s |
| 32 | 1.3% | 13.6 s | 12.0 to 13.8 s |

Four threads is a fit: three or five busy threads miss by 15% to 40%. So the table supports the form of
the bound, `R` inversely proportional to the share and proportional to the sessions, and not an absolute
number that holds on another host.

**The share is declared, and what is measured is the lateness.** The operator states `s`, the CPU share
the process may count on. A share measured while running is not an input to admission: admitting by an
observed share admits more sessions when the host is idle and refuses when it is not, which is the
feedback that makes the number swing. With no `s` declared there is no cap, as upstream, and no promise.

What the process can measure of the promise is not its share. Reading the router's threads at 32 hogs
with 1100 sessions (`/proc/<pid>/task/*/schedstat`, two runs of the test of the promise, the 20 s window):

| thread | CPU in the window | waited for a core | wakes | wait per wake | run per wake |
|---|---|---|---|---|---|
| `wz-ctl` (keepalive timers) | 24 and 26 ms (0.12% and 0.13% of a core) | 7.2 and 8.2 s | 49 and 60 | 147 and 136 ms | 489 and 426 us |
| `wz-tx` (link writers) | 29 ms | 9.1 and 9.2 s | 20 and 23 | 461 and 396 ms | 1.2 to 1.4 ms |
| the process | 0.84% and 3.0% of a core | | | | |

Three things follow. A thread's CPU time is its demand, not its entitlement: `wz-ctl` used about two fifths of the
0.33% the scheduler's weights allow it, so `s / b` is not what limits it and the model of (A) is a fit
to the measured loss and not a mechanism. What the scheduler decides is how long a woken thread waits
for a core, 140 ms here for the keepalive thread, and a keepalive is late by that wait plus the wait of
whatever it needs after it (the writer waits 400 ms). And the whole quantity the lease depends on can be
read inside the process, without the scheduler's counters: how long after its time each keepalive timer
was served.

That is what the router measures and reports. `keepalive_timer_lateness_max_ms` (the pacer, per wake: now
minus the time it planned to wake) is the longest so far in the process; the router-hat loop logs it when
it grows by 100 ms, and warns once when it passes `2T/3`
(`capacity::keepalive_lateness_limit_ms`), saying that the sessions are at risk and that the declared
share is not being met. The test of the promise asserts it: in three runs at 32 hogs with 1100 admitted
it was 775 to 1060 ms against the 6667 ms a 10 s lease allows, a margin of about six. An export of it to
the admin space is not built.

**The costs are recorded, against the measured loss.** `c_u`, `c_k` and `b` are constants of the build,
recorded as `RECORDED_HOST_MODEL` in `wz-session-core`'s `capacity` module (integers, so every profile
computes the same number from the same inputs): `c_k` 10 us, `c_u` 11 us, `b` 4, with no further margin,
because the room a margin is for is already measured (1100 against 1536 with no loss and 2048 with loss).
A unit test holds that room: the bound at 32 hogs must stay under 1536 and above two thirds of it. They
are the costs of this host and this runtime, which a hosted run showed (next paragraph). Two tests in
`capacity::tests` read this document and fail when it drifts from the code: one that the costs and the
headroom stated here are the constants of the model, and one that every row of the table above is what the
model gives (the share from the scheduler's weights, the return time from `c_u`, and within a tenth of the
observed range); both were run against a changed figure and went red.

**The first hosted run of the promise failed, and what it showed.** On the hosted runner (CI run of
`2ea53d076`, E7s job) the test of the promise ended 308 admitted client sessions: the router's cost per
forwarded message there was 46 to 52 us at 8000 messages/s where this host reads 12 to 13, about four times,
and the recorded `c_k` of 10 us was a figure for another machine. A constant recorded on one host is not a
promise about another, so the router now measures the cost on its own host. Every keepalive emission of the
process is timed (`wz-runtime-tokio`, `emission_cost`: the session loop's and the pacer's, one population, the
last 256 kept), and the first 64 sessions of a process make one on purpose at establishment, so that the
figure exists within milliseconds and not a third of a lease after the first session (a burst of peers that
arrives in that time would be admitted on the recorded cost alone). The figure compared is the LOWER DECILE of
the window, not the median, and that was learned by running it: the first version used the median, and on
the build host under 32 hogs the median swings between 4 and 19 us with the load of the moment (a duration
holds how long the thread waited for a core, which the declared share already accounts for), so the router
admitted 516 to 816 sessions in runs where the recorded cost admits 1100 and the test could not tell a
calibrating router from a refusing one. The lower decile, what an emission costs when nothing interrupts it,
reads 3.3 to 5.9 us after the first seconds in the same runs, and is the speed of the host. It is compared
with the recorded cost after it is given the room the recorded cost has over it, `FLOOR_HEADROOM_PERCENT` =
220 (10 us against about 4.5), so a lower decile of 18 us on a host four times dearer is bound at 39.6 us and
`N_max` there is 277, with the same room under the loss that 1100 has here. The larger of the two is the cost
the bound uses: a measurement can only tighten the bound, never loosen it, because a few emissions read on a
quiet moment are not evidence for a larger promise. The ceiling is worked out at each admission
(`FaceSources::ceiling`), the router logs the figure and the limit when either moves, and the test prints
what the router said with a failure; it waits for every session to be answered, admitted or refused, and
asserts the router admitted at least a quarter of the recorded number, so a router that refuses where it
should calibrate fails. Measured: on the build host (pc2) three runs at the lower decile before the room was
raised to 220, no client ended, no face DOWN; on pc3 (slower, lateness 0.9 to 1.8 s) three runs on the final
code, the limit sampled between 850 and 1100, no client ended, no face DOWN. NOT measured: a host that is dearer than these; the hosted run of this change is the
first reading of the calibration where it matters, and the headroom of 220 is one host's ratio.

**The lateness against the sessions held (measured 2026-10-24, pc2, 32 hogs, a router told nothing, 20 s window,
three runs per row; `wz_router_hat_lateness_against_the_sessions_it_holds_at_32_hogs`).** The longest keepalive
timer lateness the router reported, in ms, with the clients that ended on their own:

| sessions | run 1 | run 2 | run 3 |
|---|---|---|---|
| 1024 | 889 | 881 | 1263 |
| 1536 | 3397 | 1853 | 1900 |
| 2048 | 10806 (864 clients ended) | 3799 | 5446 |

Read: no client was lost in any run where the lateness stayed under `2T/3` = 6667 ms (8 of 9 runs), and 864 were lost
in the one run where it passed it (10806 ms). So the lateness is the quantity the loss follows, as the model assumed,
and it is the better predictor of the two: at 2048 sessions two runs of three kept every lease. What it does not do
is take the place of the bound. It grows faster than the session count (about 0.9 s at 1024, 1.9 to 3.4 s at 1536,
3.8 to 10.8 s at 2048) and varies by a factor of three between runs at the same count, so a number of sessions read
off it would be a number the next run contradicts; and the figure the router keeps is a maximum over the process's
life, which can only rise, so a router that used it to refuse sessions would refuse them for ever after one bad
second. NOT built: an admission that follows a windowed lateness (admit while the lateness of the last minute is
under a fraction of `2T/3`, such as one half), which would be a feedback control on the very quantity the lease
depends on and would bound what the model's constant cannot. It needs the lateness per window and not per process,
and a rule for how fast the ceiling rises again; neither is measured. The model's number stays the first line of
defence, and 1100 gives 0.9 to 1.3 s, about a seventh of the limit.

**What the router does at the number.** One value, the effective `max_sessions`, is the smaller of the
configured `transport/unicast/max_sessions` (upstream's key, enforced in the accept loop already, default
1000) and `N_max(s)` (`WzConfig::effective_max_sessions`, read by the accept loop in place of the bare
configured number). A session past it is refused at accept and the sessions already admitted are kept:
refuse the new one, not degrade the old. The router says once at startup that it admits fewer than
configured and which bound did it. The refusal by the configured number is counted as it was
(`refused_over_max_sessions`) and the refusal by the calibrated one apart from it
(`refused_over_capacity`), so an operator can tell whether the limit was theirs or the model's; the demo does
not yet print either in its shutdown summary.

**What the router sheds.** Read in the code on 2026-10-24, and not new: the shedding policy is upstream's and
is built. Each face's outbound queue is bounded per priority lane at upstream's defaults (two batches,
`writer_queue.rs`, `DEFAULT_QUEUE_SIZE`). A message that asked for `Drop` congestion control meets the lane's
congested mark and is dropped at once, counted as `zenoh_tx_network_message_dropped_payload` with the reason
`congestion` (`stats_registry.rs`, `ReasonLabel::Congestion`, fed from `session_actions.rs`); one that asked
to `Block` waits for room whatever the mark says, up to `wait_before_close`, and the session whose room does not
come is closed as unresponsive (`link.rs`, `RoomWait`; `session_congestion_close.rs`). Control frames do not go through that path: the keepalive takes the
urgent write (`send_urgent`). So the question 7.2 left open, what the router does with data for a face that
does not read, is answered by upstream's pipeline and wz follows it; what is NOT measured is the thing (B)
asks: whether a face that stops reading, with publishers that `Block`, holds a router worker long enough
to cost the other faces their keepalives. The wait is a condition-variable wait on a runtime worker
(`wait_for_room`), bounded by `wait_before_close` (5 s by default, half a lease) and by the close, which is
the cost to measure; the keepalives do not run there, but the session loops of the other faces do. The counters
are the node's existing metrics and not a wz-only admin key: a wz key in upstream's admin space would be an
extension of a surface this repository holds to upstream's, which is the owner's decision and is not made here.

**How it is held.** Clockless tests of the arithmetic (`capacity::tests`, and the config's effective bound
from a declared share and a lease). The promise itself is
`wz_router_hat_keeps_every_lease_it_admits_at_its_declared_share`: the router told 1.32% of a core,
32 hogs, 2048 sessions knocking; it asserts that no more than the model's number were admitted, that the
rest were refused, that no face went DOWN and that no admitted client session ended. Measured: 8 of 8 runs
at the first recorded costs (1222 admitted) and 3 of 3 at the recorded ones (1100), host load 13 to 30.
It also asserts the keepalive timer lateness against `2T/3`. Not yet held: a loose bound for the hosted
runner, and the lane that re-derives the tables.
