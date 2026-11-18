# Execution model axis: `coop-single` and `split-tasks`

Status: design, not built. Written 2026-11-18 for the `exec` axis of the build-switch catalog and
open-debt item 830 (no native multi-task profile on FreeRTOS). Every claim below about what the
tree does is read from the file it cites; every claim about what a target does when it runs is
marked **unmeasured** unless a measurement is named.

## What the axis is for

zenoh-pico's FreeRTOS default build (`Z_FEATURE_MULTI_THREAD == 1`) runs the session's read and
lease work on tasks of its own, and the application calls the API from its own task, outside them.
wz on FreeRTOS has one shape: one task that runs the cooperative executor and everything the
session does. A deployment written for the first shape cannot be moved onto wz by configuration.
The axis names the two shapes, so a build states which one it is and the rest of the configuration
(capabilities, limits, the platform's lock) follows from it.

## What `coop-single` is today

### The FreeRTOS images

- **One task.** `board::start` creates ONE application task at priority 1 and starts the scheduler
  (`deploy/mcu-freertos-demo/src/board.rs:33-51`). Both images use it: the acceptor end-to-end
  (`deploy/mcu-freertos-demo/src/main.rs:68`, `wz_task`) and the two-session witness
  (`deploy/mcu-freertos-demo/src/two_session/main.rs:64`). The crate states the profile as
  zenoh-pico's single-thread mode and the native multi-task one as a future profile
  (`crates/wz/src/lib.rs:150-168`, `crates/wz-runtime-freertos/src/lib.rs:1-35`).
- **The loop never yields to the kernel.** The acceptor drive is `run_until_idle` then `step`, then
  the reactive peer, repeated until the run ends (`crates/wz-mcu-session-acceptor/src/lib.rs:738-756`);
  there is no `vTaskDelay` in either image, in `wz-runtime-freertos` or in `wz-runtime-coop`. The
  executor's own documentation gives the bare-metal loop shape, which sleeps with `wfi()` between
  interrupts (`crates/wz-runtime-coop/src/runtime_impl.rs:27-37`); `block_on` re-polls without
  sleeping while a timer is pending (`runtime_impl.rs:322-355`). So on FreeRTOS the one task is
  always runnable. The kernel is configured for preemption with time slicing and no tickless idle
  (`deploy/mcu-freertos-demo/FreeRTOSConfig.h:34-37`).
- **The kernel surface wz binds is task create, scheduler start, delay, delete, tick count, the
  heap and the stack high-water mark** (`crates/freertos-sys/src/lib.rs:50-110`). Task
  notifications and mutexes are compiled into the kernel (`FreeRTOSConfig.h:43-44`) and bound by
  nothing; software timers are off (`FreeRTOSConfig.h:57`).
- **The network stack is lwIP with `NO_SYS=1`**, polled by the one task, with no `sys_arch`
  (`crates/wz-runtime-freertos/src/lib.rs:30-35`); lwIP's single-context contract is the caller's
  (`crates/wz-link-lwip/src/lib.rs:565-572`).

### The locks

- The runtime's cells are `critical_section::Mutex<RefCell<T>>`, and every borrow goes through
  `cs::with`, which is one of three things by build (`crates/wz-runtime-coop/src/cs.rs:31-50`):
  the image's `critical-section` implementation (the MCU default), a reentrant process lock
  (`host-lock`), or no lock at all (`single-context`, an image's promise that one context touches
  the runtime). `Runtime::Mutex` on this profile is the same primitive
  (`crates/wz-runtime-coop/src/sync.rs:16-31`), and the session runs I/O inside it
  (`cs.rs:23-27`).
- The FreeRTOS image links `cortex-m`'s `critical-section-single-core`
  (`deploy/mcu-freertos-demo/Cargo.toml:66-68`), which masks every interrupt with PRIMASK for the
  length of the section (`cortex-m` 0.7.7, `src/critical_section.rs`). With PRIMASK set neither
  SysTick nor PendSV runs, so no task switch happens inside a section: a cell borrowed only inside
  `cs::with` is exclusive between tasks on one core. That is a reading of the code, not a
  measurement.
- **What the single-task rule carries instead of a lock.** The tree has 34 `unsafe impl Send` or
  `Sync` in the crates of the MCU profiles: `wz-runtime-coop` 3, `wz-capi-coop` 5, `wz-session-mcu`
  16, `wz-session-lwip` 1, `wz-link-lwip` 9 (counted with `grep -rn '^unsafe impl.*\(Send\|Sync\)'`
  on this tree). Most state "one thread drives the node and reaches the cells" as their argument
  (for one, `crates/wz-session-mcu/src/latest.rs:161-164`). Those of `wz-capi-coop` are different:
  they rest on the engine's session lock (`crates/wz-capi-coop/src/engine.rs:313-340`).

### What already exists beside it

The cooperative engine already has a multi-task arm, for the pico ABI:

- `wz-capi-port`'s `os` module is the seam an engine asks of its operating system: a blocking mutex
  held while a session is stepped, a condition variable, the current thread's identity, a thread of
  the engine's own, and a sleep (`crates/wz-capi-port/src/os.rs:1-40`). The host answers it with
  `std`; a Zephyr image answers it with the kernel (`deploy/zephyr-common/wz_os_zephyr.c`, a
  `k_mutex`, not a critical section, because a session holds it while it reads and dispatches).
- `CoopEngine::start_read_task` runs `read` in a loop on a thread of its own
  (`crates/wz-capi-coop/src/engine.rs:3247-3279`). `read` waits on the link's readiness, or sleeps
  until the next dial, before it takes the session lock, so a publisher on another thread is not
  held up by the wait (`engine.rs:3287-3305`, `IdleWait` at `engine.rs:532-552`).
- The session state is behind one lock and a callback runs with it released (decision D8 of
  `docs/capi-pico-on-coop-engine.md`), so a program may call a session from any thread.
- The pico ABI's `multi-thread` capability selects that arm (`crates/wz-capi-pico/Cargo.toml:323-333`),
  and the Zephyr pico image builds it (`deploy/zephyr-capi-pico/rust/Cargo.toml:33-35`).

So `split-tasks` is built for the pico ABI on a host and on Zephyr. What has only `coop-single` is
FreeRTOS (no `wz_os_*` answer, no pico ABI image: the crate's MCU target is `os-zephyr` only,
`crates/wz-capi-pico/Cargo.toml:105-114`) and the Rust images over lwIP and the slot profile.

## What `split-tasks` must provide

1. **The application calls the API from its own task.** A put, a declaration or an undeclaration
   made outside the executor's task is serialised with the executor by a lock the platform gives,
   and a callback never runs with that lock held.
2. **The executor sleeps until it has work.** It waits on its links' input, on a notification a
   caller sends when it has queued something for the executor (an outbound message, a declaration
   to replay), or on the next timer deadline, whichever comes first, and not on the next tick.
3. **Callbacks may run on a task of their own.** The `rx-callback-offload` lane
   (`docs/rx-delivery-lane.md`) is the consumer: the executor copies a sample into the lane and
   notifies the callback task. On the cooperative engine the lane is that document's phase 5,
   which is not built.
4. **The library makes no task.** The runtime gives the task bodies and their attributes, and the
   image creates them, as the FreeRTOS board creates its one task today (`board.rs:33-51`); on
   Zephyr the engine's thread comes from the kernel's pool through `wz_os_thread_spawn`.
5. **One state machine.** Both values drive the same session code; what differs is who calls the
   step and which lock serialises it.

## What must be measured first

Each of these is **unmeasured**. The first stage of the work is to measure them, on QEMU
mps2-an385 (the board both FreeRTOS images run on) and on a board.

- **M1. Is a cooperative session callable from a second FreeRTOS task?** From the code: the
  runtime's cells are exclusive under `critical-section-single-core` (above), but the 34 single-task
  claims are not guarded by a section, and lwIP with `NO_SYS=1` must be called from one context.
  The measurement: an image with an executor task and an application task that puts N samples
  while the executor steps a session to a peer, counting panics (a `RefCell` already borrowed),
  lwIP assertions, lost and reordered samples. Expected from the reading: failures until the cells
  the application path touches are moved under a lock.
- **M2. Does the executor sleep, and how late does a notification wake it?** From the code: today
  the one task never sleeps. Measure, with an idle session: executor passes per second, and the
  CPU left to a lower-priority task; with an application put: the time from the call to the first
  byte on the wire, for (a) the loop as it is, (b) `vTaskDelay(1)` between passes, (c) a wait on a
  task notification bounded by the next timer deadline.
- **M3. How long are interrupts masked?** `Runtime::Mutex` is a critical section and the session
  does I/O inside it. With two tasks the masked windows are entered from two places. Measure the
  longest masked span (DWT cycle counter around `cs::with`) and the network interrupt's latency.
- **M4. Which application API is on FreeRTOS?** The FreeRTOS images run an acceptor end-to-end and
  a witness; neither is an application put/subscribe surface. Before measuring M1 with an
  application task, the surface is chosen: the pico ABI over the cooperative engine (which needs
  the `os` seam and a socket layer on FreeRTOS), or the slot node's Rust API.

## The switch

- **Axis `exec`, global** (no image owns it, as `role` is in `deploy/wz-config.toml`), Kconfig
  `WZ_EXEC`, options `coop-single` (`WZ_EXEC_COOP_SINGLE`, the default, today's code) and
  `split-tasks` (`WZ_EXEC_SPLIT_TASKS`). On the tokio engine the axis has no value to choose: its
  sessions run on threads in every build.
- **What `split-tasks` implies.** On the pico ABI it is the `multi-thread` capability: the option
  implies it, so a build states one name and the header arm follows. It refuses `single-context`
  (`cs.rs:43-49`), whose promise it breaks. It requires a platform that answers the `os` seam
  (host, Zephyr today; FreeRTOS after stage S2).
- **What it does not imply.** `rx-callback-offload` is a capability on top of it, not part of it: a
  build may split the executor from the application and still run callbacks on the executor.
- **Limits** (names to be fixed with the declaration, values measured, not chosen): the priority
  and the stack of the executor task and of the callback task, as integers the image reads when it
  creates them; a core where the platform has more than one, declared only for such a platform.
  The callback lane's depth and its answer when full are the existing `DELIVERY_LANE_*` limits and
  the `subscriber-overload` policy.

## Stages

Each stage is its own change and is tested where it lands.

- **S0. Measure M1 to M4.** A two-task variant of the FreeRTOS witness image; no product code.
  Output: the numbers, and the list of cells M1 found touched by two tasks.
- **S1. The table of the 34 claims.** For each `unsafe impl`, which task touches the cell under
  `split-tasks`; a cell touched by two moves under the session lock (the D8 pattern) or under
  `Runtime::Mutex` given a kernel-mutex form. Test: the existing host tests of each crate, plus a
  host test that drives one session from two threads under `host-lock` and checks order and
  completeness.
- **S2. FreeRTOS answers the `os` seam.** A `wz_os_freertos.c` beside `wz_os_zephyr.c`: a mutex
  (`xSemaphoreCreateMutex`, with priority inheritance), a condition variable, a task
  (`xTaskCreate`, joined by a notification), a sleep. Task notifications are macros in FreeRTOS, so
  they are reached through the C file and not bound in `freertos-sys`. Test: the seam's
  conformance (lock, wait, notify, spawn, join) on QEMU.
- **S3. The executor waits for work.** The read task's wait takes a notification beside link
  readiness and the next deadline. Test: an idle session makes at most a bounded number of passes
  in a window (the host engine's test of 2026-10-24 has this shape), and a put from another task
  is on the wire within a bound.
- **S4. An application task.** The image whose surface M4 chose, with the application task putting
  and subscribing while the executor task runs. Test: the same scenario green in `coop-single`
  (the application steps the engine) and in `split-tasks`.
- **S5. The callback task.** The delivery lane on the cooperative engine, consumed by a task.
  Test: a callback that blocks for longer than the lease does not end the session, and a control
  with the callback inline does.
- **S6. The declaration.** The `exec` axis, its options, the `multi-thread` implication and the
  task limits in `deploy/wz-config.toml`, with the generated Kconfig.

## Risks

- **lwIP with `NO_SYS=1`** has no locking. Splitting tasks over it needs every lwIP call on one
  task or under one lock; moving to `NO_SYS=0` changes the port. Which is cheaper is unmeasured.
- **Masked interrupts.** A critical section around session I/O already masks the network
  interrupt for the length of a write; two tasks entering it make that window more frequent (M3).
  A kernel mutex for `Runtime::Mutex` on this profile, as the `os` seam already has, removes it.
- **Priority.** A busy executor at the application's priority takes the core whenever it is ready.
  `split-tasks` without S3 is worse than `coop-single`, because the application task then waits
  for a time slice to run at all.
- **Stacks and heap.** Each task has its own stack out of heap_4 (256 KiB in the demo,
  `FreeRTOSConfig.h:53`); the stack bound gates of the single-task images measure one task, and
  each new task needs its own bound.
- **Reentrancy.** A callback that calls the session from the callback task while the executor
  holds a `RefCell` borrow panics unless the lock is the one the callback waits on (D8 holds this
  on the pico ABI; S1 has to hold it everywhere else).

## Open for the owner

- Whether the axis option `split-tasks` should select the pico ABI's `multi-thread` capability
  (one name), or the two stay separate switches that the declaration checks for agreement.
- Which application surface comes first on FreeRTOS (M4).
- Whether the FreeRTOS network stack for this profile is lwIP `NO_SYS=1` behind one lock, lwIP
  `NO_SYS=0`, or FreeRTOS+TCP, which zenoh-pico's FreeRTOS examples use.
