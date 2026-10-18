# Parallel faces: one thread per link for the C ABI node

Status: built (stages 1 and 2, with the model revised in stage 2b), measured. Owner decision: cost
ignored, the long-term correct shape.

## 1. Why

A C ABI node (`z_open` with a listener or several dials) used to drive EVERY connection on one
thread (`wz-capi-drive`). Measured on a quiet host with the reference subscriber and the same
publishers, 8 B payloads, one P core per side:

| connections | callback | wz subscriber (one thread) | reference subscriber |
|---|---|---|---|
| 1 | trivial | 3.57 M/s | 3.65 M/s |
| 2 and more | trivial | 6.3 to 9.0 M/s | about 3.0 M/s |
| 2 and more | 1 microsecond of work | 0.88 M/s | 1.33 M/s |

With a trivial callback wz was ahead on one thread. With a callback that does real work wz was bound
to one thread and the reference is not: it runs a receive task per link. The node's capacity must not
be one core, and a callback that blocks must hold up its own link and no other.

## 2. Single-thread assumptions retired

1. Face drive futures were polled on a `LocalSet` and, for accepted faces, inside ONE future
   (`face_drive_loop`). The drive of a face is now `Send` and spawned: the SCE `Engine` callbacks are
   `+ Send` at the pin (the old module comment saying otherwise was stale), and the forwarder of the C
   ABI (`CApiForwarder`) is `Send + Sync`.
2. `ReadGate` is a barrier over every gated future of a session (the top-level drive and each face):
   each registers by its first poll, a stop waits until all are parked or gone, and "inside a
   callback" is a thread-local stack of the gates whose futures this thread is polling.
3. The accept loop gained `accept_loop_offering_spawned`, which spawns each face through a
   `FaceExecutor`; `accept_loop_offering` keeps the single task for forwarders that are not `Sync`
   (the routing forwarders: `Rc`/`RefCell`, a concurrent routing core is a separate design).

## 3. Model: a thread per face, not a pool

The first model put each face's drive on the session runtime's workers (`tokio::spawn`). It scaled
(with a 1 microsecond callback, 1.76 M/s on 2 workers and 3.30 M/s on 4, against 1.31 M/s for the
reference), and it is wrong: a pool cannot keep a blocked callback from holding the face beside it.
A test whose two peers' first callbacks wait for each other failed 16 of 20 runs with 2 workers and
with 4: the drive of both faces ran on one worker thread, one after the other, the second starting
only when the first callback returned. (Tokio keeps a woken task in its worker's LIFO slot, which
other workers do not steal; that is read from the behaviour and the source, not shown.)

So each face's drive runs on a thread of its own (`run_on_own_thread`, `drive.rs`):

* a current-thread runtime with a clock and no reactor: the socket belongs to the session runtime,
  whose workers wake the face thread when it is readable;
* the drive is polled only while the read task may run (`Pausable`), as before;
* dropping the waiting task cancels the drive on its own thread and WAITS for the thread, because the
  C `drop(context)` that follows a `z_close` must not race a callback. The wait is skipped from the
  face's own thread (a callback that closes its session cannot wait for itself);
* if a thread cannot be had, the drive runs as a task of the runtime instead.

The session runtime's workers keep the reactor, the writers and the control tasks (a dial and its
waiting); `WZ_CAPI_WORKER_THREADS` (default 2) is no longer the receive parallelism.

## 4. Contract, per ABI

`FaceDrive` (on `OpenStance`, carried by the `ReadGate`):

* `PerFace`, zenoh-c's: a thread per face. Per face (link) messages arrive in the order they were
  sent, one at a time; across faces one subscriber's callback MAY run concurrently, as zenoh's
  does (`CClosure` is `Sync`, and each face has its own callback and `MarshalCache`, so the
  per-source tickets and per-call marshals of the first plan are not needed for this ABI).
* `Serial`, zenoh-pico's: every face on the drive thread, one at a time. pico's callbacks all run
  on the session's one read task and a stop of that task stops every callback; a program written for
  it shares state between callbacks without a lock. Stage 2 had applied the parallel model to pico as
  well, which broke that contract for a pico node with more than one peer; this is the repair.

## 5. Measured (pc3, pinned cores, 8 B, `z_sub_mt`)

Messages per second at 4 publishers, default 2 workers:

| callback | reference | pool, 2 workers | pool, 4 workers | thread per face |
|---|---|---|---|---|
| none | 2.88 M | 12.4 M | 12.6 M | 12.7 M |
| 1 microsecond | 1.35 M | 1.75 M | 3.30 M | 3.29 M |

One connection is a tie with the reference (3.82 M against 3.93 M, inside the spread).

Round trip of `z_ping` against `z_pong`, median, 3000 samples, pong on cores 0 and 1:

| ping / pong | round trip |
|---|---|
| reference / reference | 37.2 to 38.2 us |
| reference / pool | 34.6 to 35.0 us |
| reference / thread per face | 38.0 to 38.6 us |
| thread per face / reference | 40.4 to 40.6 us |

The thread per face costs about 3.5 us of round trip against the pool, which puts it at the
reference's latency on the receive side and about 9% above it on the send side. It is the price of
the isolation, and it is the price of a thread hand-off: the reactor wakes the face thread, and the
callback's put wakes the writer task on a worker. A busy-poll after each wake (30 us) was tried and
gave 1.8 us on one side and nothing on the other, and was removed.

## 6. Verification

`crates/wz-capi-c/tests/parallel_faces_roundtrip.rs`, through the exported `z_*` symbols: callbacks
of different peers overlap (the first callback of each of two peers waits for the other's to start);
each of four peers keeps its put order under load; closing the session while peers put leaves no
callback running and starts none. 20 runs on the build host, 20 passed. The read-gate unit tests
(`a_stop_waits_for_every_gated_task`, `a_callback_of_one_session_may_stop_another`) cover the
barrier.

## 7. Open

* Latency: the hand-off to the writer is the larger part of the 3.5 us. A put that writes the socket
  from the calling thread when the writer is idle (the pico shape) would remove it for every caller,
  and is a change of the transmit path, not of this node.
* A thread per face is a thread per link: a node that holds hundreds of links holds hundreds of
  threads, each with a reserved 16 MiB stack (virtual until used).
* Concurrent routing tables for the router and peer hats; the open handshakes as tasks of their own
  (they are control, and run in the accept task).
