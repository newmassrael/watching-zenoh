# A get over the program's transport on the cooperative engine

Layer S's count of the allocations of gets between two open sessions
(`crates/wz-capi-pico/tests/allocation_faults.rs`,
`gets_between_open_sessions_are_counted_for_their_allocations`) took 42 to 50 s on the cooperative
engine for its `WARM_UP` and `COUNTED` gets, some 200 ms a get, against a round trip that should
take well under a millisecond, and under load the run passed its `RUN_BOUND`. The tokio engine's
run of the same test, and the puts of the same file, are fast. Both sessions are in one process,
joined by the program's own transport (an in-memory pipe, `tests/support/pipe_pair.rs`), each
with its read task.

This note follows each leg of one get, names the wait, and says what was changed. Nothing here was
built or run: it is a reading of the code, and section 5 says what a run has to show.

## 1. The legs of one get

| Leg | Who writes or reads it | Waits for a tick? |
|---|---|---|
| The asking thread's Request | `CoopEngine::get_held` takes the session (`live`) once to list the faces and once for the leg, and sends the Request through the link's actions on the calling thread: outside a `zp_batch_start` window this engine emits each message as a frame (`dispatch_network_message_at`, the window is the caller's alone, `set_auto_batching` is the tokio runtime's), and the program's `send` hands the bytes to the other session's `wz_ext_transport_received`, which wakes that link's waker | No, once the session is taken |
| The answering read task | its step reads the Request; the query is copied out and its Final held (`QueryPlane::arrive`); `deliver` runs the queryable's callback and `CoopEngine::answer` sends the replies and then the Final through the link's actions, on the read task's thread. On a link `Core::answer_route` is the link's actions, which write; only a group's sink stages, and `Core::write_answers` writes that one | No |
| The asking read task | its step reads the reply and the Final, the registry drops the entry, and the `deliver` after the step drops the get's closure, which is the get's end in the C ABI | No |

Every leg is written by the thread that makes it, as zenoh-pico sends a query's replies and its
final from the call that answers it
(`vendor/zenoh-pico/src/session/queryable.c` @ `z_result_t _z_trigger_queryables(`). What is left
is how each read task waits for its link, and what the asking thread waits for before it can send.

## 2. The cause

A link over the program's transport gave its session's owner no wait for its input: none of
`AppStreamSocket`, `AppDatagramSocket` or the two listeners of `crates/wz-runtime-coop/src/app_link.rs`
answered `readiness`, and the pico C ABI opened the links without `waited_by_owner`, so no link of
theirs was one its owner waits on. `Core::idle_wait` (`crates/wz-capi-coop/src/engine.rs`) then
finds nothing to wait on with the session free: the asking session's one face waits in its own
loop, so the read waits for nothing, and the answering session's port gives no wait, so it sleeps
a millisecond. The wait is the link's own, made inside the step: `StreamDriver::service` waits
`SERVICE_WAIT_MS` for input (`Held::wait_readable`), and the step runs under the session's lock.
The read task's loop (`CoopEngine::start_reader`) calls `read` back to back, and each `read`
takes the lock twice, for its wait and for its step, with a few microseconds between: the session
is held nearly all the time.

A thread that takes the session with `live` waits on the host's mutex, which hands the lock to
whoever takes it first when it is let go: the read task, running, takes it again before the woken
waiter has been scheduled, turn after turn. The get waits for the session twice before its Request
leaves, and the answer cannot come before the Request does; a put takes it once. How long a
waiter loses is the scheduler's; nothing here measured it, and the 200 ms is the run's figure, not
one this reading derives.

## 3. The fix

* Every link over the program's transport gives its owner a wait on a host (`host-lock`): the
  table's readable answer for the link (`LinkInput`, the wait a group link already gave, now each
  link's), which the program's `received`, `accepted` and `event` wake through the link's one
  waker. It also answers ready while the link holds bytes for a program that takes bytes (it took
  part of a write and said nothing since), so the step that follows offers them again, as the
  link's own loop did on each of its turns. A program that would block wakes it when it says the
  link is writable. An image, which has no thread to park, gives no such wait and is unchanged.
* `AppLinks::waited_by_owner` opens every link of the links so, the dialled, the begun and the
  accepted ones alike, as `IpLinks::waited_by_owner` opens a host's sockets. The pico C ABI's
  open over the program's transport asks for it (`crates/wz-capi-pico/src/session.rs`).
* The read task then waits in `Core::idle_wait`'s `IdleWait::Input` with the session free, up to
  `PICO_SOCKET_TIMEOUT_MS` or the next thing due, and the link's loop reads what is queued and does
  not wait. The asking thread takes the session at once; its Request wakes the answering read task,
  and the answer wakes the asking one.

What is left: a session that waits on more than one link (the answering session's face and its
port) waits on the first and looks at the others each millisecond, the provided
`wait_readable_among` of a stack whose waits cannot be joined into one; the face is the first, so
a Request still wakes it at once.

## 4. Tests

* `app_link::tests::links_waited_by_their_owner_give_a_wait_and_do_not_wait_in_their_loop`
  (`wz-runtime-coop`): a dialled stream, a dialled datagram link, an accepted stream and a begun
  dial of links `waited_by_owner` each give a wait, and a hundred turns of each loop take under
  50 ms; CONTROL: the same links of links not opened so give none, and twenty turns of a stream's
  loop wait at least 20 ms.
* `app_link::tests::a_streams_wait_for_its_owner_ends_on_input_and_on_bytes_owed_to_the_program`:
  the wait is waited out with nothing queued, ended by bytes handed in from another thread, ended at
  once while bytes are owed to a program that takes bytes, and waited out while the program would
  block until it says writable.
* `app_link::tests::a_listeners_wait_ends_on_an_accept_and_a_datagram_links_on_a_datagram`.
* `files::app_transport_doors::a_get_between_two_open_sessions_over_the_programs_transport_ends_at_once`
  (`wz-capi-pico`, both engines): the median of 21 gets between two open sessions over the pipe,
  timed from the call to the drop of the get's closure, is under 20 ms.

## 5. Confirming it

```text
cargo test -p wz-runtime-coop --features app-link,host-lock --lib app_link::
cargo test -p wz-capi-pico --no-default-features --features engine-coop,app-transport,peer,query,queryable,multi-thread --test it files::app_transport_doors::
cargo test -p wz-capi-pico --features app-transport --test it files::app_transport_doors::
```

And Layer S's gets count on the cooperative engine
(`cargo test -p wz-capi-pico --no-default-features --features engine-coop,app-transport,peer,query,queryable,multi-thread --test allocation_faults -- --ignored gets_between_open_sessions_are_counted_for_their_allocations`):
expected to end in seconds, far inside `RUN_BOUND`. Its count of allocations may move with it, and
`tests/no_heap_after_open.rs` (Layer C1nh) reads the same sessions: a read that waits with the
session free allocates nothing for its wait, so its `idle` family is expected to stay at 0.
