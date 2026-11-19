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

- **Allocation failure.** The pico ABI has no allocation hook to fail. `z_malloc` is the host's
  `malloc`, and the library's own allocations go through Rust's global allocator, which aborts the
  process when an allocation fails rather than returning an error to the caller. A failing allocator
  installed by this suite would therefore only show that abort. Exercising the failure as a handled
  case needs two things the library does not have: a door that lets the program supply the
  allocator the library allocates from, and allocation on the session's paths (the session tables,
  the receive and transmit queues, the closures) that reports failure as a named error and leaves
  the session usable. Until both exist the suite does not inject allocation failure.
- **The cooperative engine.** The suite runs the tokio engine, the default build's. The cooperative
  engine's client (`engine-coop`) is a separate build of the same ABI.
- **Real sockets.** The faults are the program transport's. What the system's sockets do under loss
  is the transport links' own lanes.
