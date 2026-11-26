# The std and heap forms: winning the four budgets against zenoh-pico

Status: design of the owner's instruction of 2026-11-26 («전부 구조 설계해»), the std lane of the
win budget (`docs/c-abi-architecture.md` section 9). It states only what differs from the nostd
form: the standard library's runtime, its threads, its use of the allocator, and the costs only a
`std` build carries (the backtrace symbolizer, the unwind tables, `catch_unwind` at the doors).
What the nostd form fixes for every form (the rows the open reserves, the size of each area, the
instructions of one received message) is [heap](heap.md), [text](text.md),
[ir-receive](ir-receive.md) and [ir-send-query](ir-send-query.md), and section 8 of
`docs/c-abi-architecture.md` (every face read where it lies, no round). Nothing here is built or
measured by this lane; a cell marked **measure** is a reading still to be taken, never a figure to
be filled by hand.

The forms this document covers:

| form | what it is today | reference it is held to |
|---|---|---|
| pico preset, std | `wz-capi-pico` with its default features: `std`, `engine-coop`, `multi-thread` | zenoh-pico, the same C library on libc |
| pico preset, tokio | `engine-tokio` named without the default features | none: it leaves the C library in phase P5 (`docs/c-abi-engine-and-memory.md`) and is given no budget |
| zenoh-c preset | `wz-capi-c` over `wz-capi-core`, the tokio engine | zenoh-c (contract); zenoh-pico for the features both have (goal) |
| zenoh preset (Rust API) | `wz-zenoh`, default `engine-tokio` | upstream zenoh 1.10.2 (contract); zenoh-pico for pub/sub (goal) |
| heap form of any of them | the open's arena taken from the system allocator (`GlobalAlloc`, `malloc`) instead of a static region | as its preset |

## 1. What is measured

All readings below are of the pico preset with zenoh-pico's own default build beside it.

| budget | wz std form | wz nostd form | zenoh-pico | reading |
|---|---:|---:|---:|---|
| text | about 1.46 MB, of which the backtrace symbolizer about 177 KB and the unwind tables about 204 KB | 864,298 | 505,302 | std: the earlier size reading of the std preset; nostd and pico: the parity run of 2026-11-25 (`size`, text column) |
| heap peak, subscriber | 1.29 MB (a build without the preset's limits) | 382,008 (massif, after the parity image took its defconfig's limits) | 32,124 (`heap_peak_pubsub`, median of 6 boots) | the massif reading and the parity run use different probes: **measure** zenoh-pico under massif |
| RSS, pub/sub | **measure** | 5,774 KiB | 4,888 KiB | parity run of 2026-11-25, before the limits fix: **measure** again |
| instructions per received message | 6,522 | 6,097; 4,836.7 net on the window harness | 2,941; 4,042.4 net on the window harness | callgrind, 10,000 messages by the difference of two runs; the std reading is the earlier one (std preset). The two-run slope took zenoh-pico's idle wake-ups off its count (`ir-receive.md` section 1); the window harness of `f5f8ce646` (the connected window, net of an idle run) is the reading: std form, measure, harness f5f8ce646 |
| RSS and CPU per message, std form, by `perf` | 1.42 of zenoh-pico's RSS; 1.32 of its CPU per message | | 1.00 | the main session's perf reading of the std form, 2026-11-26 (ratios, wz over zenoh-pico) |

The nostd reading of the heap is one allocation of the session's arena at the open (290,304 bytes,
`wz_capi_coop::engine::lend_session`), the process pools (78,160 bytes,
`wz_capi_pico::process_pool::Reserved::built`), the face supervisor (7,568 bytes,
`LinkSupervisor::new`) and the example's own stdio buffer (4,096 bytes, which zenoh-pico's example
pays too). Nothing is allocated per message.

### 1.1 What only the std form pays

**Text.** About 1.46 MB against 864,298: the unwind tables (about 204 KB), the symbolizer that
`std`'s default panic hook reaches (`backtrace_rs`, `gimli`, `addr2line`, `miniz_oxide`,
`rustc_demangle`, about 177 KB), and about 0.21 MB more, derived as the remainder of two readings
of different trees (`std::thread`, `std::io`, the formatting the hook prints with, the landing
pads of `catch_unwind` at every door). `panic = "abort"` alone removes the unwind tables but keeps
the symbolizer: the default hook still runs before the abort and reads `RUST_BACKTRACE` at run time,
so the code that prints a backtrace stays reachable from every panic site.

**Instructions.** 6,522 against 6,097, 425 per message, by the exclusive costs of the two readings:

| function | std | nostd | difference | what it is |
|---|---:|---:|---:|---|
| `cs::host_std::Section::enter` | 135 | absent | +135 | the process's critical section on `std`'s thread-locals (`crates/wz-runtime-coop/src/cs.rs`, `mod host_std`) |
| its `Drop` | 135 | absent | +135 | the same section left |
| `__memcpy_avx_unaligned_erms` | 212 | 106 | +106 | one more copy whose caller is not in the reading: **measure** (callgrind with `--dump-instr=yes`, caller tree of `memcpy`) |
| `network_message::read_push`, `Core::idle_wait`, `hand_out`, `step_after` and the rest | | | about +49 | inlining that differs between the two builds |

zenoh-pico pays, per message, about 553 instructions in `malloc` and `free` (`malloc` 177,
`free` 116, `_int_free` 216, the arena's `free` 44) and about 205 in its mutex
(`pthread_mutex_lock` 116, `pthread_mutex_unlock` 89): its read thread builds and clears a sample
and the subscription cache's entry for every message
(`vendor/zenoh-pico/src/session/subscription.c` @ `_z_sample_steal_data(&sample, &sub_infos.ke, payload, timestamp, encoding, sample_kind, qos, attachment,`
and @ `_z_subscription_cache_data_clear(&sub_infos);`), and `z_malloc` is `malloc`
(`vendor/zenoh-pico/src/system/unix/system.c` @ `void *z_malloc(size_t size) { return malloc(size); }`).
wz pays neither: that is the structural margin every form keeps.

**Heap and RSS.** The std form adds, beside the nostd form's rows: each thread's `std::thread`
handle (an `Arc` of the thread's record and its name, taken when the read task is spawned,
`crates/wz-capi-port/src/os.rs` @ `let thread = std::thread::Builder::new().spawn(body).ok()?;`),
the thread-local blocks of `std` (the critical section's `DEPTH` and `HELD`, the thread's
`Thread` handle, its panic count), and the text pages of 1.46 MB of which a run touches part. None
of these is measured apart: **measure** the std form's RSS and heap under the preset's limits.

## 2. The structure

### S1. The C ABI libraries have no std form

A C program asks a C library for sockets, threads, locks, a clock and memory; every one of them is
already answered without `std` by the port the nostd form stands on: `wz-capi-port`'s `os` made of
the host's calls (`os-sys`), the locks of `wz-host-sync` on the futex or Win32's slim lock, the
runtime's critical section on the thread's number (`wz-runtime-coop`'s `host-lock-sys`), the
allocator `CHeap` (`calloc`/`malloc`) or `ProcessHeap` and an aborting `#[panic_handler]`
(`crates/wz-capi-pico/src/os/no_std_host.rs`). The std form gives the C caller nothing the nostd
form does not, and charges it a symbolizer it cannot call, unwind tables it cannot use and a
thread-local critical section per message. So the C libraries are `no_std` on every host and the
std form is removed, not optimised:

- **Types.** `wz-capi-pico` is `#![cfg_attr(not(test), no_std)]` in every build. Its `std`
  feature and `engine-coop` (which selects `std`) are deleted; one host feature `os-host` stands
  for `os-posix` on `cfg(unix)` and `os-windows` on `cfg(windows)`, the dependencies each needs
  declared under `[target.'cfg(...)'.dependencies]`, and the default list names `os-host` with the
  preset's capabilities. `os-zephyr` is unchanged.
- **Flow.** The modules of `wz-capi-pico` still written against `std` (those that reach
  `std::thread` or `std::sync`: `scout.rs`, `query.rs`, `handlers.rs`, `advanced_plane.rs`,
  `time_base.rs`, `last_timestamp.rs`, `stream_supervision.rs`, and `wz-capi-coop`'s
  `host_group.rs`) take the port's `os` (`spawn`, `sleep`, the clock) and `wz-host-sync`'s
  `Mutex`/`Condvar` instead. That is the precondition P3 and P4 of
  `docs/c-abi-engine-and-memory.md` already name; this document makes their end the deletion of the
  form, not a second form kept beside it.
- **Ownership.** No `std` object exists in the library: no `Thread` handle, no thread name, no
  thread-local destructor registered with the C runtime.
- **Copy and branch.** Nothing is added on any path. `ffi::catch` is the nostd body (`Some(body())`,
  `crates/wz-capi-pico/src/ffi/boundary.rs`) in every build, so no door carries a landing pad.
- **Tests** run with `std` (`cfg(test)` brings `extern crate std` to the test harness only), so the
  library's own test code keeps `std::thread::spawn` where it races two callers.

Removes: the whole of section 1.1's text (to the nostd form's 864,298, which [text](text.md) takes
on), its 425 instructions (S3 below, and the copy found by the **measure** cell), and its heap and
RSS (S4).

### S2. A panic aborts at every C boundary

zenoh-pico is C: nothing it does unwinds. Upstream zenoh ships its release profile with
`panic = "abort"` (`Cargo.toml` @ `panic = "abort"`, the `[profile.release]` of the workspace).
wz's `ship` profile keeps unwinding so that a door can turn a panic into an error code
(`crates/Cargo.toml`, the comment of `[profile.ship]` and `[profile.capi-small]`). Under S1 there is
no unwinder to keep: the C libraries build with `capi-nostd` (`panic = "abort"`, `lto = "fat"`)
and a panic is a defect the no-panic gate (decision Q5 of `docs/c-abi-engine-and-memory.md`) must
find before it ships. A C callback that unwinds (a C++ exception thrown through a C function
pointer) is undefined in C itself and zenoh-pico does not catch it either; the `InCallback` mark
of `hand_sample` stays (`crates/wz-capi-pico/src/pubsub.rs`, re-entry is a semantic of the ABI, not
a panic matter) and the `catch` around the call becomes a plain call.

### S3. No process-wide section on the message path

`host_std` takes a process lock behind two thread-locals at the outermost section (`DEPTH`,
`HELD`): 270 instructions per message in the std reading. S1 removes `host_std` (`host-lock-sys`
answers the same doors with the thread's number), and section 8 of `docs/c-abi-architecture.md`
removes the section from the read: each face's read takes that face's lock only, the process
section is taken by what changes a table (a declaration, an undeclaration, the open and the close),
never per message. Target: the count of `cs::with` calls per received message is 0 in every form,
held by a test that counts entries of the section under `cfg(test)` across one received message.

### S4. Threads, stacks and the allocator's arenas

- **Threads.** zenoh-pico creates its read and lease tasks with `pthread_create` and the caller's
  attribute, null by default (`vendor/zenoh-pico/src/system/unix/system.c` @
  `_Z_CHECK_SYS_ERR(pthread_create(task, attr, fun, arg));`; the read task is
  `vendor/zenoh-pico/src/transport/unicast/read.c` @
  `_z_fut_fn_result_t _zp_unicast_read_task_fn(void *ztu_arg, _z_executor_t *executor) {`, the
  background tasks `vendor/zenoh-pico/src/runtime/background_executor.c` @
  `z_result_t _z_background_executor_inner_run_forever(`). wz's threads are the port's `spawn` over
  `pthread_create` (Win32 `CreateThread`) with an attribute whose stack size is the stack-bound
  gate's figure for that task rounded up to a page, plus the guard page: the virtual size is the
  proven bound, not the platform's default. The count is section 8's: one read task per face with
  `threads` (zenoh-pico: one per transport) and one task for the timers (zenoh-pico's lease task).
- **The allocator's arenas.** glibc gives a thread its own malloc arena the first time that thread
  allocates. zenoh-pico's read thread allocates per message (section 1.1), so it holds a second
  arena with its own top chunk. wz allocates nothing after the open on any thread (the P2 ratchet,
  `crates/wz-capi-pico/tests/allocation_faults.rs`), so its read and timer threads never make one;
  the open allocates on the caller's thread, once. Target: zero allocations on any thread the
  library starts, asserted by the allocation test with the read task running (a counting
  `GlobalAlloc` that records the thread of each call), and **measure** the number of malloc arenas
  and their resident bytes for both libraries (`malloc_info`, or the anonymous mappings of
  `/proc/self/smaps`).
- **Pages the open touches (heap form).** RSS counts the pages written, not the pages allocated.
  The open today zeroes the state region by writing it (`crates/wz-capi-coop/src/arena.rs` @
  `base.as_ptr().write_bytes(0, head.size());`) and lends every row, which writes each. Zeroed
  memory from the allocator is not the answer: under glibc's mapping threshold `calloc` serves a
  chunk a close freed and `memset`s all of it, which the main session read on 2026-11-26 as the
  open and close rising from 0.82 of zenoh-pico's instructions to 1.37 once the heap lanes made the
  arena small. On a host the arena is therefore fresh pages of the system (lane rss-zero,
  `7a6292658`: `wz_host_sync::pages::reserve` over `mmap`, `VirtualAlloc` on Windows), the arena
  is told its memory is zero (`ArenaMemory::reserves_zeroed`, `Arena::over_zeroed`), and a row's
  empty state is its all-zero bytes, so a row is written when it is first used, not at the open. A static region of the no-heap form is
  `.bss` and has the same property. The bytes the open reserves are [heap](heap.md)'s; this rule
  decides how many of them are resident.

### S5. The heap form: one allocation at the open, counts from the configuration

The owner's ruling of 2026-11-26 on heap capacity (counts from the open's configuration, the
preset's limits as the static ceiling, a small default the preset's contract states, nothing
allocated after the open, a declaration past the count refused with zenoh-pico's allocation-failure
code, the process pools from the first open's or an initialisation's configuration) is the same in
every form; [heap](heap.md) owns it. What the std and heap forms add is only where the memory comes from: on a host, one reservation
of fresh pages for the arena at the open on the caller's thread (S4, never a reused allocator
chunk), one allocation for the process pools at their first use, and their release at the close. The allocator is the C runtime's in every
host build; a Rust program using the Rust API (S7) brings its own `#[global_allocator]`, which wz
uses as it is.

### S6. The zenoh-c preset on the same engine

`wz-capi-c` is a second ABI over the engine `wz-capi-pico` stands on, not a second engine: it makes
the cooperative engine's P1 to P4 with its own coverage rows (the precondition P5 of
`docs/c-abi-engine-and-memory.md` already names), then S1 to S5 hold for it unchanged. Its doors keep
no tables of their own (principle P1 of `docs/c-abi-architecture.md`, one fact, one owner): an owned
zenoh-c object (`z_owned_sample_t`, `z_owned_bytes_t`) is a handle to a held row of the arena (the
held samples and payload blocks the preset's limits count), not a heap copy. Its four budgets are
then the pico preset's core plus its door layer, which is what is held to zenoh-c.

### S7. The zenoh preset: std stays, std's cost is the program's

The Rust API is a `std` library: its types are `String`, `Vec` and futures, and the program that uses
it already links `std`, its panic hook and its symbolizer. So:

- **Accounting.** wz's text, heap and RSS in a Rust program are the difference between the program
  built with wz and the same program built without it (the same `main`, the same `std`); the
  reference is measured the same way with upstream zenoh. `std`'s symbolizer is in both and in
  neither difference.
- **Threads.** Upstream zenoh runs its session on five tokio runtimes of its own, `app`, `acc`,
  `tx`, `rx` and `net`, one worker each but `rx` with two
  (`commons/zenoh-runtime/src/lib.rs` @ `#[param(worker_threads = 2)]`), each read loop a task of
  `rx` (`io/zenoh-transport/src/unicast/universal/link.rs` @ `zenoh_runtime::ZRuntime::RX.spawn(async move {`).
  wz's Rust API runs on the cooperative engine through the driver section 8 describes: one read
  task per face and one timer task, plain threads of the port, and its `async` methods are futures
  completed by the engine's wakers, so they run on whatever executor the program has and no tokio
  runtime is started by wz. `engine-tokio` stays an adapter feature of `wz-zenoh` until the driver
  runs the Z8 examples (P5's precondition), then leaves.
- **Heap per message.** Upstream reads each link into buffers of a pool sized when the link opens,
  `rx_buffer_size / mtu` buffers of one MTU
  (`io/zenoh-transport/src/unicast/universal/link.rs` @ `let pool = RecyclingObjectPool::new(n, move || vec![0_u8; mtu].into_boxed_slice());`),
  and a reader that finds the pool empty waits (`commons/zenoh-sync/src/object_pool.rs` @
  `let obj = self.inner.pull();`). wz takes the same shape without the heap: the receive buffers
  are rows of the arena counted by the configuration (S5), a `Sample` handed to a callback by value
  holds its payload as a `ZBytes` lending a slice of that buffer, counted in the buffer row's
  header (a count in the arena, not an `Arc` on the heap), and a sample kept past its callback holds
  the buffer: when every buffer of a face is held, that face's read waits, as upstream's `pull`
  does. No copy and no allocation per message; a sample the program clones into its own `Vec`
  allocates in the program's allocator, as with upstream.

### S8. What does not change

The pico preset's tokio form gets no budget: it leaves the C library in P5. The nostd form's
rows, areas and per-message stages are the other documents'; under S1 the std form of the C
library is the nostd form, so its four targets are theirs.

## 3. The budgets

Each row: wz now, zenoh-pico, the target, the structure that meets it, the files it touches, and the
lane that takes it (section 4).

### 3.1 Pico preset, std form

| budget | wz now | zenoh-pico | target | structure | files | lane |
|---|---:|---:|---|---|---|---|
| text, unwind tables | about 204 KB | 0 | 0 | S1, S2: no unwinder in the C library, `capi-nostd` profile | `crates/Cargo.toml` (profiles), `crates/wz-capi-pico/Cargo.toml` | SH2, SH3 |
| text, symbolizer and panic hook | about 177 KB | 0 | 0 | S1: `std` not linked, the panic handler of `no_std_host.rs` aborts | `crates/wz-capi-pico/src/os/no_std_host.rs`, `Cargo.toml` | SH2 |
| text, the rest of `std` and the doors' landing pads | about 0.21 MB (derived) | 0 | 0 | S1: `catch` is a plain call, threads and locks from the port | `crates/wz-capi-pico/src/ffi/boundary.rs`, the modules of S1 | SH1, SH2 |
| text, total | about 1.46 MB | 505,302 | at most 505,302 | S1 brings it to the nostd form; [text](text.md) takes that to the target | as above | SH1 to SH3, then the text lanes |
| heap, `std`'s own | **measure** (thread handles and names) | 0 | 0 | S1: threads from the port, no `Thread` handle | `crates/wz-capi-port/src/os.rs` | SH1 |
| heap, peak | 1.29 MB without limits; 382,008 with them (nostd) | 32,124 | at most 32,124 (same probe on both sides) | S5 and [heap](heap.md); nothing after the open | [heap](heap.md)'s | heap lanes |
| RSS, `std`'s own | **measure** | 0 | 0 | S1, S4: no `std` pages, stacks of the proven bound | `crates/wz-capi-port/src/os.rs`, `crates/wz-host-sync` | SH1, SH4 |
| RSS, malloc arenas | 1 (the caller's), **measure** | 2 or more (its read thread allocates), **measure** | no arena beyond the caller's | S4: zero allocations on the library's threads | `crates/wz-capi-pico/tests/allocation_faults.rs` | SH4 |
| RSS, pages the open touches | the arena written whole at the open (and by `calloc`'s `memset` of a reused chunk) | its heap as it grows | the rows in use | S4: fresh pages of the system, all-zero empty rows, written on first use | `crates/wz-host-sync/src/pages.rs`, `crates/wz-capi-pico/src/os/pages.rs`, `crates/wz-capi-coop/src/arena.rs`, `no_std_host.rs` | SH5 (rss-zero) |
| RSS, total | 1.42 of zenoh-pico's by `perf` (2026-11-26); **measure** after rss-zero (nostd 5,774 KiB) | 4,888 KiB | at most 4,888 KiB | S1, S4 and the text and heap targets | as above | all |
| Ir, process section | 270 | 0 (its mutex: 205) | 0 | S3: no `cs::with` per message; section 8 | `crates/wz-runtime-coop/src/cs.rs` | SH6 |
| Ir, the extra copy | 106 | | 0 | S1 removes the form; **measure** its caller first, and if it is on the nostd path too, [ir-receive](ir-receive.md) owns it | **measure** | SH6 |
| Ir, total | 6,522 (biased run); window: measure, harness f5f8ce646; CPU per message 1.32 by `perf` | 2,941 (biased); 4,042 on the window | at most 4,042 (gate); design 2,000 ([ir-receive](ir-receive.md)) | S1 to the nostd form's 4,837 on the window, then section 8 and [ir-receive](ir-receive.md) | theirs | SH6, then section 8 |

### 3.2 Zenoh-c preset

| budget | wz now | zenoh-c | zenoh-pico | target | structure | files | lane |
|---|---|---|---:|---|---|---|---|
| text | **measure** | **measure** | 505,302 | at most zenoh-c; at most zenoh-pico for the features both have | S6, then S1, S2 | `crates/wz-capi-c` | SH7 |
| heap peak | **measure** | **measure** | 32,124 | as above | S6: owned objects are held rows; S5 | `crates/wz-capi-c`, the door modules | SH7 |
| RSS | **measure** | **measure** | 4,888 KiB | as above | S4, S6 | `crates/wz-capi-c` | SH7 |
| Ir per received message | **measure** | **measure** | 4,042 (window harness) | as above | S6 on the engine of section 8 | `crates/wz-capi-c` | SH7 |

### 3.3 Zenoh preset (Rust API)

| budget | wz now | upstream zenoh | zenoh-pico | target | structure | files | lane |
|---|---|---|---:|---|---|---|---|
| text, difference against the same program without it | **measure** | **measure** | 505,302 | at most upstream; at most zenoh-pico for pub/sub | S7: one engine, no tokio linked by wz | `crates/wz-zenoh`, `crates/wz-zenoh-runtime` | SH8 |
| heap peak and heap per message | **measure** | **measure** (its per-message allocations are a reading, not asserted here) | 32,124 | as above, and 0 per message | S5, S7: buffers as arena rows, samples lend them | `crates/wz-zenoh` | SH8 |
| RSS, threads | **measure** (tokio engine) | six workers of its five runtimes and their stacks | its two tasks | at most zenoh-pico's thread count with `threads` | S7: read task per face, one timer task | `crates/wz-zenoh`, `crates/wz-capi-port/src/os.rs` | SH8 |
| Ir per received message | **measure** | **measure** | 4,042 (window harness) | at most zenoh-pico | S7 on section 8's read | `crates/wz-zenoh` | SH8 |

## 4. Lanes and order

| lane | what it does | boundary | depends on |
|---|---|---|---|
| SH1 | each module of S1 off `std`: `scout`, `query`, `handlers`, `advanced_plane`, `time_base`, `last_timestamp`, `stream_supervision`, `host_group` onto the port's `os` and `wz-host-sync` | one module per lane; a lane lands when its module builds under `os-posix` and `os-windows` with its tests | none |
| SH2 | the feature collapse: `std` and `engine-coop` deleted from `wz-capi-pico`, `os-host` the default, the refusals of `src/lib.rs` rewritten for one host feature | one change; the size gate's std cases and their ceiling rows leave in it | every SH1 lane |
| SH3 | the panic policy: `ffi::catch` a plain call, `ship`'s comment and the C libraries' packages on `capi-nostd` | one change | SH2, and the no-panic gate (Q5) holding |
| SH4 | threads with the stack bound, the allocation test counting per thread, the arena-count reading | test first, then the port's `spawn` | SH1 |
| SH5 | zeroed pages and all-zero empty rows in the open | `ArenaMemory::reserve_zeroed`, then one row family per change, each with a test that the open leaves it unwritten | [heap](heap.md)'s row lanes (they change the same rows: the row lane goes first) |
| SH6 | no process section per message | a counting test, then the removal | section 8's steps |
| SH7 | `wz-capi-c` on the cooperative engine (P1 to P4), then S1 to S5 | its own coverage rows | SH2, and P3 of the pico library |
| SH8 | the Rust API on the cooperative engine through section 8's driver | the Z8 examples graded on it | section 8, SH4 |

The measurement lane takes every **measure** cell first: the std form's RSS and heap under the
preset's limits; the std form's text by symbol group on the current tree (the 1.46 MB is older than
the limits fix); zenoh-pico under massif with the same options as wz; the caller of the std form's
extra `memcpy`; the malloc arenas of both libraries; the four cells of zenoh-c and of upstream zenoh
with `wz-capi-c` and `wz-zenoh`; and zenoh-pico's read task in the same multi-threaded build wz is read in. The std reading's
per-thread view gave its read task 3,780 inclusive against 2,941 for the whole process by the
difference of two runs; the window harness (`f5f8ce646`) brought them together, nearer the
per-thread view: the two-run slope had taken the idle wake-ups off, and the window's 4,042 is the
gate (measure, harness f5f8ce646, for the std form).

## 5. The owner's decisions

1. **The C libraries have no std form** (S1). The pico and zenoh-c presets build `no_std` on every
   host; `std` stays only in the Rust API and the tools. Recommended: a std form cannot reach
   zenoh-pico's text while it links the symbolizer, and it gives a C caller nothing the port does
   not. The residue: a Rust program that links the C library as a static archive beside its own
   `std` meets two panic handlers and two allocators; the Rust API is its door, and the static
   archive is refused for that use by documentation.
2. **A panic aborts at every C boundary** (S2), and `ship` stops promising an error code for a panic
   in a C library. Recommended, with upstream zenoh's release profile and zenoh-pico's C as
   precedent; the no-panic gate is the guarantee.
3. **The Rust API's budgets are differences against the same program without wz** (S7), so `std`'s
   own code and pages are counted for neither side.
4. **The Rust API's engine is the cooperative one with executor-neutral futures** (S7); tokio becomes
   an adapter and leaves with P5.
5. **Thread stacks are sized by the stack-bound gate** (S4), not left at the platform's default as
   zenoh-pico leaves them.
6. **An empty row is all-zero bytes and the open writes no row it does not use** (S4). Recommended:
   it is what makes the reserved heap and the resident memory differ, and it binds every row type
   [heap](heap.md) changes.
7. **No crate is a size boundary** (decided 2026-11-26 under the owner's delegation, [text](text.md)
   O1). The std form gets no crate at another level either: its cold code is one non-generic body
   at the root's level ([text](text.md) P5), and what only `std` adds leaves by S1, not by a level.
8. **A get's ResponseFinal waits in its face's `TxBatch` and the batch is flushed once when the
   read stage ends** (decided 2026-11-26 under the owner's delegation,
   [ir-send-query](ir-send-query.md) D6). In the std form too no send place is held while a
   callback runs, so a callback on the read thread that calls the session meets no held lock.

## 6. Rejected alternatives

- **Keep the std form and shrink it** with `panic = "abort"` and a hook set at run time: the hook is
  replaced only after the default one is linked, so the symbolizer stays; measured on the tokio
  client, `panic = "abort"` removed 18.2 percent of the text, and the same reading states that
  `panic = "abort"` alone keeps the symbolizer (`docs/c-abi-engine-and-memory.md`, section 5).
- **Build `std` from source with an immediate-abort panic** (`-Zbuild-std`): a nightly toolchain for
  every shipped library, against a stable pin, to keep a form that serves a C caller nothing.
- **Count `std`'s text in the Rust API's budget**: it charges wz for a cost the program pays with or
  without it, and upstream zenoh would be charged the same, so the comparison says nothing about
  either.
- **Per-thread allocator caches in wz** to match glibc's arenas: wz allocates nothing on its threads,
  so there is nothing to cache.
