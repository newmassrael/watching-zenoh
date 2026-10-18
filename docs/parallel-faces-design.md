# Parallel faces: one task per link for the C ABI node

Status: design, Stage 0 of 5. Owner decision: cost ignored, the long-term correct shape.

## 1. Why

A C ABI node (`z_open` with a listener or several dials) drives EVERY connection on one thread
(`wz-capi-drive`). Measured on a quiet host with the reference subscriber and the same publishers,
8 B payloads, one P core per side:

| connections | callback | wz subscriber | reference subscriber |
|---|---|---|---|
| 1 | trivial | 3.57 M/s | 3.65 M/s |
| 2 and more | trivial | 6.3 to 9.0 M/s | about 3.0 M/s |
| 2 and more | 1 microsecond of work | 0.88 M/s | 1.33 M/s |

With a trivial callback wz is ahead on one thread (about 9 M/s, where the reference degrades as links
are added). With a callback that does real work wz is bound to one thread and the reference is not:
it runs a receive task per link. The node's capacity must not be one core.

## 2. Single-thread assumptions the design has to retire

Each of these is true today because everything is polled on one thread.

1. Face drive futures are polled on a `LocalSet` (`wz-capi-core/src/drive.rs`, nine `spawn_local`
   sites) and, for accepted faces, inside ONE future: `face_drive_loop` holds every face's drive in
   a `FuturesUnordered` (`wz-runtime-tokio/src/accept_loop.rs`). The module comment says a spawned
   face is impossible because the SCE `Engine` owns callbacks with no `+ Send`. That is stale: the
   pinned `sce-rust-runtime` declares both with `+ Send` (`engine.rs`), and a probe that replaced
   every `spawn_local` by `tokio::spawn` left the dial legs compiling. What still is not `Send`:
   `Rc` state shared by scouted legs, `dyn FaceForwarder` (not `Sync`), and the boxed `dyn Future`
   of the open set.
2. `ReadGate` (`zp_start_read_task` / `zp_stop_read_task`) is one switch over one future, and a
   stop is SYNCHRONOUS as pico's is: it waits until the drive thread has parked, so no callback runs
   afterwards. A start or stop made from inside a callback is refused by comparing the caller with
   `drive_thread`. Both need N tasks.
3. `DeferredListenerCell` gives every listener one total order across all sources (a ticket taken
   where a call is staged) and runs its callback one call at a time. That is stronger than the
   reference, which orders per link and may call one subscriber's callback from several links at
   once.
4. `MarshalCache` (wz-capi-c) keeps one marshalled sample per subscriber and reloads it in place,
   which assumes a callback is not running twice at once.
5. `drive_local_plane` runs on the same thread "so its deliveries cannot overlap a face's"
   (R311y557).
6. The drive thread has a 16 MiB stack because the futures polled on it are large in a debug build;
   a tokio worker has 2 MiB.
7. One `ApplicationLayerObserver` behind one mutex serves every face; each frame of plain Puts takes
   it once, so it is a shared cost, not a serial one.

## 3. Target model

* A control task per listener (the accept loop as it is): accept, handshake, `max_sessions`, zid
  dedup, re-dial, ticks. Not a data path.
* A data task per face, on the node's multi-thread runtime: `drive_face` spawned through a
  `FaceExecutor` that wraps it in the read gate. The forwarder is `Arc<dyn FaceForwarder + Send +
  Sync>`; `CApiForwarder` already is (an `Arc<SharedSession>` and mutexes). The routing forwarders
  (peer and router hats, `Rc`/`RefCell` throughout) keep the single-task loop: a concurrent routing
  core is a separate design and is not in scope.
* The runtime's worker count and stack follow the machine, not a constant two.
* `ReadGate` becomes a barrier over the gated tasks: each registers, a stop waits until every one
  is parked or gone, and "inside a callback" is a thread-local set while a gated task is polled.

## 4. Contract

Per face (link): messages are delivered in the order they arrived, one at a time.
Across faces: the same subscriber's callback MAY run concurrently, as zenoh's does. A callback must
therefore be safe to call from two threads, which is what a C closure over a context pointer already
has to be for the reference library.

Implementation: a cell keeps tickets per SOURCE (face) instead of one sequence, and a concurrent
cell holds its callback as shared (`Fn + Send + Sync`) instead of taking it out and putting it back.
The cell that serializes (a Rust `FnMut` listener) stays as it is. `MarshalCache` hands each running
call its own marshalled sample from a small per-subscriber free list.

## 5. Stages

0. This note, and the stale comments corrected.
1. `wz-runtime-tokio`: `drive_face` generic over the forwarder, `FaceExecutor`, and an accept
   entry that spawns each face's drive (`JoinSet`, task id to face). Exit: a test with N peers shows
   N drives on distinct threads, `FaceDown` and `deregister` unchanged, shutdown cancels all.
2. `wz-capi-core`: accept legs through the new entry, dial legs spawned, `Rc` to `Arc`, the gate as
   a barrier, worker count and stack. Exit: the existing read-task tests (stop is synchronous, a
   stop from a callback is refused) pass unchanged.
3. Delivery: per-source tickets and the concurrent cell. Exit: per-face order is preserved under N
   concurrent faces; undeclare mid-flight suppresses later calls.
4. `MarshalCache` per running call. Exit: the existing marshal tests and a two-thread test.
5. Measure: the 1 microsecond callback table above with the new library, and the trivial one. The
   claim is only what the table then shows.

## 6. Not in scope

Concurrent routing tables for the router and peer hats; making the open handshakes tasks of their
own (they are control, and run in the accept task).
