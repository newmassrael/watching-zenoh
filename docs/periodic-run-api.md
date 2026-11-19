# The periodic run API of the pico C ABI

A host program that runs its own scheduler (a cyclic task of a fixed period, an event loop,
a real-time executor) drives a session of the pico C ABI from that scheduler: it sends what
each cycle produced, takes what arrived since the last one, and keeps the session alive. This
page states the calls it makes, in the order it makes them, and what each answers on each of
the two engines and in each of zenoh-pico's two threading arms. The example that runs it is
`crates/wz-capi-pico/examples/c/periodic.c`; the same order is written as a comment section
of `crates/wz-capi-core/include/wz_ext.h` ("the periodic run API").

## The two arms are two builds

zenoh-pico has a multi-threaded arm and a single-threaded one, chosen when the library is
built (`Z_FEATURE_MULTI_THREAD`), and the program is compiled against the header of the arm
its library has. The two declare different functions and lay some structs out differently, so
one library serves one arm. The wz library follows: the `multi-thread` feature of
`wz-capi-pico` (on by default) is the first arm, a build without it the second.

- **Multi-threaded.** The library runs a read task beside the program: it reads the links,
  dispatches the callbacks, checks the lease and sends the keep-alives. The program starts and
  stops it and never steps the session itself; `zp_read`, `zp_send_keep_alive`, `zp_send_join`
  and `zp_spin_once` are not in this arm.
- **Single-threaded.** There is no task. The program steps the session from its own loop with
  `zp_spin_once` (or the older `zp_read`, `zp_send_keep_alive` and `zp_send_join`), and the
  work happens in those calls.

## The call order

1. **Open.** `z_open`. In the multi-threaded arm the read task starts with the session unless
   the open options say otherwise; `zp_read_task_is_running` says whether it runs.
2. **Tasks, or not.** Multi-threaded: `zp_start_read_task` if the open did not start it. A
   program that declares its entities before any traffic may open without the task, declare,
   and then start it, so that nothing reaches an entity that did not exist yet.
   `zp_start_lease_task` and `zp_stop_lease_task` do nothing and answer `Z_OK`, as in
   zenoh-pico 1.10: the read task checks the lease. Single-threaded: nothing to start.
3. **Declare.** A subscriber whose samples the program takes on its own thread hands them to
   a channel (`z_ring_channel_sample_new` keeps the newest and drops the oldest when full,
   `z_fifo_channel_sample_new` keeps them in order and holds the sender while it is full), and
   the program pulls with the channel's try-receive, which
   answers `Z_CHANNEL_NODATA` when nothing is waiting. A callback subscriber is the other
   choice: its callback then runs on the read task in the multi-threaded arm, and inside the
   program's step in the single-threaded arm on the cooperative engine.
4. **Each cycle.**
   1. *Send.* `zp_batch_start`, the cycle's puts, `zp_batch_flush`: the puts are gathered into
      the session's batches and leave together at the flush, and the window stays open for the
      next cycle. A batch also leaves when it is full, when a message must leave at once, and
      when the session sends a keep-alive.
   2. *Step* (single-threaded arm only). `zp_spin_once` on the session.
   3. *Receive.* Try-receive on each channel until `Z_CHANNEL_NODATA`.
   4. *Wait.* Until the cycle's deadline, an absolute reading of the monotonic clock
      (`z_clock_now`, `z_clock_advance_ms`), with `z_condvar_wait_until` (multi-threaded; a
      callback may end the wait early with `z_condvar_signal`) or a sleep for what is left.
5. **End.** `zp_batch_stop` sends what the window still holds and closes it; undeclare;
   `zp_stop_read_task` if the program wants the read task stopped before the close; `z_close`.

## What each call answers

| Call | Tokio engine | Cooperative engine |
|---|---|---|
| `zp_start_read_task` | starts the session's drive; idempotent | starts a thread that steps the session; idempotent |
| `zp_stop_read_task` | stops it and returns once no callback runs; while stopped nothing is read and no keep-alive is sent | stops and joins the thread |
| either, from one of the session's callbacks | refused, `Z_EINVAL`, nothing changes | the same |
| `zp_start_lease_task`, `zp_stop_lease_task` | `Z_OK`, nothing | `Z_OK`, nothing |
| `zp_read` (single-threaded) | `Z_OK` for a live session; does nothing: this engine reads continuously on a thread of its own | waits for input up to the socket timeout, steps the session once and runs the callbacks on the caller's thread |
| `zp_send_keep_alive` (single-threaded) | `Z_OK` for a live session; the engine keeps the lease on its own schedule | sends a keep-alive on every link that is up |
| `zp_send_join` (single-threaded) | `Z_OK` for a live session; a session that joined a group sends its Join now | `Z_OK` for a live session; nothing to send (no group) |
| `zp_spin_once` (single-threaded) | `true` while the session is open | one step, as `zp_read`; `false` once the session is closed |
| `zp_batch_start`, `_flush`, `_stop` | opens, flushes or closes the window on every face of the session | the same on the session's link |
| `zp_read`, `zp_send_keep_alive`, `zp_send_join` on a closed or NULL session | `_Z_ERR_SESSION_CLOSED` | the same |
| the batch calls on a NULL session | `_Z_ERR_SESSION_CLOSED` | the same |
| the batch calls on a session with no transport | `_Z_ERR_TRANSPORT_NOT_AVAILABLE` | the same |

## What a program with its own scheduler should know

- **On the tokio engine the single-threaded calls do no work.** The engine reads, keeps the
  lease and dispatches on a thread of its own whatever the program calls, so a callback runs
  on that thread and not inside the program's `zp_read` or `zp_spin_once`. A program written
  for the single-threaded arm's promise that its callbacks run only inside its own calls must
  either lock what its callbacks share or take its samples through channels, which the
  example does. The cooperative engine keeps the promise; it runs over the host's sockets on
  Linux, Android and QNX, so on Windows a session runs on the tokio engine.
- **The multi-threaded arm has no call that steps the session on the program's thread**, on
  either engine and in zenoh-pico. The program's thread sends (puts, batch flush) and pulls
  (channels); the read task does the rest.
- **The period is the program's.** Nothing in the library paces the cycle. In the
  multi-threaded arm, and on the tokio engine in either arm, the library keeps the session's
  lease whatever the program's period. In the single-threaded arm on the cooperative engine the
  lease is kept only while the program steps the session more often than its keep-alive
  interval, as in zenoh-pico's single-threaded arm.

## The Windows platform layer under it

The program's timer, lock, thread and event wait are zenoh-pico's own platform exports, which
the wz library provides on Windows with the bytes and the answers of zenoh-pico's Windows
backend (`vendor/zenoh-pico/src/system/windows/system.c` @ `z_clock_t z_clock_now(void) {` and
the functions beside it; `crates/wz-capi-pico/src/os/windows.rs`):

| Family | Exports | Windows primitive |
|---|---|---|
| clock | `z_clock_now`, `z_clock_elapsed_us` / `_ms` / `_s`, `zp_clock_elapsed_us_since` / `_ms_since` / `_s_since`, `z_clock_advance_us` / `_ms` / `_s` | the performance counter |
| wall time | `z_time_now`, `z_time_now_as_str`, `z_time_elapsed_us` / `_ms` / `_s` | the system time as `struct timeb` |
| sleep | `z_sleep_us`, `z_sleep_ms`, `z_sleep_s` | an at-least-this-long sleep |
| memory, random | `z_malloc`, `z_realloc`, `z_free`, `z_random_u8` / `_u16` / `_u32` / `_u64`, `z_random_fill` | the C runtime's allocator, the system's random source |
| mutex | `z_mutex_init`, `_drop`, `_lock`, `_try_lock`, `_unlock`, `_loan`, `_loan_mut`, `_move`, `_take` | `SRWLOCK` |
| condition variable | `z_condvar_init`, `_drop`, `_signal`, `_wait`, `_wait_until`, `_loan`, `_loan_mut`, `_move`, `_take` | `CONDITION_VARIABLE` |
| task | `z_task_init`, `_join`, `_detach`, `_drop`, `_loan`, `_loan_mut`, `_move`, `_take` | a thread `HANDLE` |

The mutex, condition variable and task families are the multi-threaded arm's, as in
zenoh-pico. `crates/wz-capi-pico/tests/c/pico_host_layer.c` holds the layout of each type on
the host, and `crates/wz-capi-pico/tests/c/pico_platform_surface.c` calls every export of the
table, so that on Windows each is shown to resolve through the DLL's import library and to
answer as zenoh-pico's Windows backend answers. What zenoh-pico's header also declares and the wz library does not export is its
internal `_z_*` system layer (`_z_task_init` and the rest of the task, mutex and condition
variable families, the recursive mutex `_z_mutex_rec_*`, `_z_condvar_signal_all`,
`_z_get_time_since_epoch`): those are zenoh-pico's own and not its API, the drop-in owes them
to no program, and the census of the drop-in counts only the public plane
(`crates/wz-integration-tests/tests/it/files/pico_abi_symbol_census.rs`). A program that needs
a recursive lock or a broadcast wake builds it on the public mutex and condition variable.

## Not here yet

Examples of the replay cache and of the message catalog belong to the work that adds those
capabilities, and land with it.
