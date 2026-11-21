# Layer S: the pico C ABI under load, faults, close and reopen

Layer S asks whether the pico C ABI (`crates/wz-capi-pico`) holds under load and faults: no
thread stops, no lock is taken in two orders, no closure or allocation is left behind, and the
sessions carry traffic again once the faults stop. It is a stress run, bounded in time and driven
by a seed. It is opt-in: a full sweep of `scripts/run-ci.sh` skips it unless it is asked for.

## Running it

```
WZ_RUN_LAYER_S=1 bash scripts/run-ci.sh --layer S
bx --host pc2 -- bash scripts/run-ci.sh --layer S        # the build host, the long run
WZ_S_REQUIRE=1 bash scripts/run-ci.sh --layer S          # fail where valgrind is absent
```

| Variable | Default | What it bounds |
|---|---|---|
| `WZ_STABILITY_SEED` | the clock | the mix of calls and of faults; printed by every run |
| `WZ_STABILITY_SECONDS` | 20 | how long each storm lasts |
| `WZ_STABILITY_WORKERS` | 4 | how many threads call during a storm (1 to 64) |
| `WZ_STABILITY_CYCLES` | 40 | how many pairs the sequential test opens and closes |
| `WZ_STABILITY_STALL_SECONDS` | 30 | how long a thread may make no progress before the watchdog stops the run |
| `WZ_STABILITY_TIME_SCALE` | 1 | every wait of the suite is this many times longer |
| `WZ_STABILITY_VALGRIND_CYCLES` | 6 | how many pairs the valgrind leg runs |
| `WZ_ALLOC_FAULT_JOBS` | the machine's parallelism | how many runs of a memory leg's sweep go at once (1 to 64) |

The hosted run (job `pico-client-only`) is the short bound: ten seconds a storm, no valgrind. The
build host runs it as long as the question asks, for example
`WZ_STABILITY_SECONDS=600 WZ_STABILITY_WORKERS=16`.

## What it runs

The suite is `crates/wz-capi-pico/tests/stability.rs`, an executable of its own because it counts
the process's allocations with a global allocator. Its three tests are `#[ignore]`d, and the lane
runs them with `--ignored`.

Two sessions of the pico ABI in one process, a listening one and a dialling one, are joined by a
transport the program supplies (`app-transport`, the `wz_ext_transport_*` doors) whose other side
is an in-memory pipe. No socket is opened.

1. **The stream storm.** Over byte-stream links. Worker threads put (one in a hundred large enough
   to be fragmented), get, and declare and undeclare subscribers, queryables and liveliness tokens,
   on either session. A chaos thread closes a session while the workers call on it, frees it and
   opens another (the listening one one time in eight, which drops every dial until the next one is
   up), and every tenth time cuts every link of the pipe. The pipe answers sends with seeded faults:
   a send that would block (told writable later from the pipe's own thread), a send that takes part
   of what it is offered, and a link cut in the middle of a send. A receiver that refuses bytes for
   being full makes the send wait for the transport's `drained` call, as a stack's backpressure
   does.
2. **The datagram storm.** The same over datagram links, whose faults are a send that would block
   and a datagram lost whole (a full receiver drops one too).
3. **The sequence.** Pairs opened and closed one after another without faults: a put and a get
   between them, a subscriber, a queryable and a token declared and undeclared, everything closed.

After each storm the faults stop, and a put and a get must cross between the session the storm
left listening and a fresh dialling one. Each storm asserts that every kind of call was made, that
sessions were reopened, and that each fault of its shape was injected, so a run that exercised
nothing fails.

## The link legs, against the real zenoh-pico

The second leg (`crates/wz-integration-tests/tests/it/files/pico_link_qos_on_wz_capi.rs`) asks
what a pico program's QoS settings do on a link that is full, lossy or cut. One C program is
compiled twice,
against the real `libzenohpico.so` and against `libwz_capi_pico.so`; a run starts a subscriber
that listens and a publisher that dials it through a relay in the test, and the relay injects
the fault on the system's own sockets, so the real zenoh-pico and wz meet the same fault from the
same code. The real zenoh-pico runs first in every test: a control that fails says the harness or
the host cannot carry the measurement, and nothing about wz.

| Test | Fault | Control | wz is held to |
|---|---|---|---|
| `link_qos_drop_and_block_on_a_full_stream_in_client_mode` | the relay stops reading the publisher's stream until a `Block` put has waited 300 ms, and for a second of `Drop` puts after it | the real zenoh-pico in client mode, held to the same | a `Drop` put returns within 250 ms and not every one is delivered; a `Block` put waits (one for at least a second) and every one is delivered, in order |
| `link_qos_drop_and_block_on_a_full_stream_in_peer_mode` | the same, the publisher in peer mode | the client run of the real zenoh-pico; its peer run is printed as the reference and not held | the same, in peer mode |
| `link_qos_reliable_samples_over_a_lossy_group_arrive_in_order_or_are_reported_missed` | each member on a multicast group of its own on the loopback interface; the relay between them loses 5 % of the publisher's frames and holds the rest 1 to 7 ms (so reorders them), then a fence goes through it clear | the real zenoh-pico, the same runs with the same relay seeds | reliable samples in order and never twice, each received or reported to the advanced subscriber's miss listener; best-effort samples in order; both fences delivered |
| `link_qos_reliable_delivery_across_a_cut_and_redialled_stream` | a client publisher dials the subscriber through the relay, which closes both sockets of the stream mid-run; the client dials again | the real zenoh-pico, the same runs | reliable samples in order and never twice, each lost one reported missed, nothing put once the link carries again lost, and the client dialling again |

zenoh's transport does not retransmit: a frame that does not follow the last one taken is
dropped and any forward jump is taken, so on a datagram link reliable samples can be lost, and
what zenoh defines is that they arrive in order, never twice, and that a loss is reported to an
advanced subscriber. A broken stream takes its transport with it and a session that dials again
opens a new one; the same holds across it. The datagram path between two zenoh-pico sessions is a
multicast group because zenoh-pico has no UDP unicast listener. The test file cites upstream and
zenoh-pico for each of these.

| Variable | Default | What it bounds |
|---|---|---|
| `WZ_LINK_QOS_REPEATS` | 3 | how many runs each library gets in the two reliability tests; the rate a departure reproduced is printed |
| `WZ_LINK_QOS_SEED` | the clock | the relay's first seed (run `i` uses it plus `i`, the same for both libraries); printed |

The peer mode of the real zenoh-pico is a reference and not a control because its congestion
control does not hold on a full link: a peer takes the peers' mutex before the transmit mutex's
try-lock, and its socket is non-blocking, so a `Block` put on a full link fails instead of
waiting. The test file cites the lines.

A red reads as the finding it names: `full` false, `Block` did not wait for the full link; a long
`Drop` put, a dropping put waited for room; every `Drop` sample delivered, nothing was dropped; a
`Block` sample missing, failed or out of order, a waiting put did not deliver; a reliable sample
neither received nor reported missed, the loss went unreported; a sample out of order or twice,
the receiver took a stale frame; the fence or the samples after the re-dial missing, delivery did
not resume; "measured nothing", the relay found no frame of the publisher's to impair.

## The memory legs

The third suite (`crates/wz-capi-pico/tests/allocation_faults.rs`) asks what the library does when
memory runs out, and how much memory its traffic takes. It is an executable of its own, because its
global allocator counts every allocation and fails one on request, and it runs on each engine: the
tokio engine (the default build with `app-transport`) and the cooperative one
(`--no-default-features --features engine-coop,app-transport,peer,query,queryable,multi-thread`).
The two sessions are joined by an in-memory pipe as in the storm, one stream pair, without faults;
nothing the pipe or the test's closures do on a message's path allocates, so every allocation a
window counts is the library's.

1. **A failed allocation at every point of a call.** For `z_open` (the dialling session, with the
   listening one up), `z_declare_subscriber`, `z_declare_queryable`, `z_declare_publisher`, `z_put`
   and `z_get` (the dialling session open, its route to the listener made and a get answered
   first): a run with no failure counts the allocations the process makes while the call runs. Then
   every point from 1 fails in a run of its own, until a run past that count makes fewer
   allocations than its point (the count moves a little from run to run, with the threads). A run
   is a process of its own, this executable started again on one test with `WZ_ALLOC_FAULT_RUN` set
   to `<call>:<point>`, because a failed allocation may end the process and the process is then
   judged from outside. Runs go `WZ_ALLOC_FAULT_JOBS` at a time (the machine's parallelism by
   default); one may take a minute.
2. **Traffic between open sessions.** After twenty puts (and, in the second test, twenty gets) have
   made the routes and grown the buffers, two hundred more are counted: the allocations the process
   made for them and the bytes those asked for.

A run ends one of three ways: the call returned, and it prints its code, whether the failing
allocation was reached, and, once both sessions are closed, whether every closure the library was
handed was dropped, both transports were let go and how many allocations the process still holds;
the process ended in Rust's allocation-failure handler (its abort is caught in the run and ends the
process at once, so thousands of runs leave no core dump); or anything else, a signal, a failed
assertion, no verdict or no end within a minute. A run is started with the tokio runtime's
lock-order checker off (`WZ_LOCK_ORDER=off`) and no backtrace: the checker captures a stack for
each lock order new to the process, under std's backtrace lock and on the global allocator, so a
failure injected there would send the allocation-failure handler after the lock its own thread
holds and leave the run waiting for itself; and what it allocates is not the library's. The
traffic counts are runs of their own for the same reason.

| Build | The sweep is held to | The traffic is held to |
|---|---|---|
| any | no run ends in any third way; no panic; a call that returned after its failure answered `Z_OK` or a named allocation error (`Z_ERR_SYSTEM_OUT_OF_MEMORY`), and left every closure dropped, both transports let go and no more allocations held than the run with no failure; a run that never reached its point returned `Z_OK` | no panic; every closure dropped and both transports let go |
| a heap build (both engines today) | the run with no failure counts at least one allocation, so the counter is known to see them; a run that ends in the handler is counted and printed | at least one allocation is counted; the count is printed |
| a build that takes a session's memory at `z_open` | no run ends in the handler | no allocation at all |

Which row a build is held to is the constant `MEMORY_TAKEN_AT_OPEN` at the top of the file, which a
fixed-memory build sets from its feature. A heap build's answer to every point it reaches is the
handler, since Rust's allocator API aborts on a failure the caller does not take as a result; the
sweep shows where those points are and how many, call by call and engine by engine.

## What it detects

| Defect | How |
|---|---|
| a thread stops (deadlock, lost wakeup, a call that never returns) | every thread of the suite marks a heartbeat; a watchdog thread that finds one without progress for the stall bound writes each thread's last call and its age, the runtime's loops (`liveness::loops_now`), every thread's kernel state and wait channel (`liveness::threads_now`) and the panics so far to stderr, and aborts the process |
| two locks taken in both orders | the runtime's lock-order checker (`wz-runtime-tokio`'s `sync::lock_order`, on in a debug build; the lane sets `WZ_LOCK_ORDER` to stop the thread) panics in the thread that closes the cycle; a panic hook counts every panic of every thread, and the run fails on any |
| a closure the library never drops | each callback context is counted when it is made and when its drop runs; the counts must meet once the sessions are gone, a get still pending when its session closed included |
| a program transport never released | the transport's `drop` must run once for each of the two, after the sessions and the program let go |
| memory that grows | the process counts the allocations it holds; a storm may leave fewer than 4,096 behind (a leak per call or per reopened session is many times that), and the sequence may grow by less than one allocation for every two pairs over its second half |
| a definitely lost block, an invalid read or write | the sequence again under valgrind's memcheck (`--leak-check=full --errors-for-leak-kinds=definite`) |

## Reading a red

- The seed is the first line of each test's output; set `WZ_STABILITY_SEED` to it to run the same
  mix again. The seed fixes the calls and the faults, not how the threads interleave, so a red that
  depends on an interleaving may need a few runs to come back.
- A watchdog abort ends the run with a signal and a report headed `stability watchdog:`. The thread
  named there stopped; the `threads:` line says what each thread of the process was waiting in.
- A lock-order report names both orders and where each was first taken.
- A count that does not meet names the kind (sample, query or reply closures) and the three
  counts, made, called and dropped.

## What it does not cover

- **Allocation failure outside the six calls.** The memory legs fail an allocation inside one call
  at a time. A failure on a session's own threads between calls (a sample received, a timer) is
  reached only when it falls inside a call's window. `z_malloc` is the host's `malloc`, which the
  suite does not fail.
- **The cooperative engine, in the storm.** The storm runs the tokio engine, the default build's;
  the memory legs run both.
- **Real sockets, in the storm.** The storm's faults are the program transport's. The link legs
  put a stall, a loss and a cut on the system's sockets, between two processes, but for the
  default build's tokio engine only, and with no fault on the program's own transport there, which
  zenoh-pico has no counterpart of to control it with.
