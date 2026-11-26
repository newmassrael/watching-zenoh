# Winning budget: the Ir of receiving one message

Status: design, 2026-11-26. Scope: the instructions one received PUT costs a subscriber, from the
socket to the return of the application's callback, in the shipped nostd form (the
`zenoh-pico_defconfig` preset: `os-posix`, `link-udp`, `scout`, `peer`, `multicast-transport`,
`query`, `queryable`, `liveliness`, `liveliness-get`, `multi-thread`) and in the std and heap form.
It builds on [c-abi-architecture.md section 8](../c-abi-architecture.md) (every face read where it
lies, no round) and designs what section 8 leaves: every stage that remains once the executor's
pass and the round are gone. Nothing here is implemented; every number marked *to measure* is a
cell the main session fills.

## 1. What is measured

callgrind, 2026-11-25, `pico-compare` harness, one publisher, one subscriber, the cost per
received message taken as the slope between a run of 2,000 and a run of 12,000 messages (so the
open, the declarations and the close cancel out):

| form | wz (W) | zenoh-pico (P) | excess |
|---|---:|---:|---:|
| shipped nostd | 6,097 | 2,941 | 3,156 |
| std and heap | about 6,500 (read thread inclusive, *to measure* as a slope) | 2,941 (same library) | about 3,600 |
| shipped nostd, window harness (main `cf6ca0963`, 2026-11-26) | 4,855.9; net 4,836.7 | 4,049.2; net 4,042.4 | 794 net (1.20) |
| std and heap, window harness | measure, harness f5f8ce646 | 4,042.4 (same library) | measure |

**The first two rows are biased on the pico arm; the window row is the reading.** A zenoh-pico
peer with no peer yet wakes its read task every 100 ms
(`vendor/zenoh-pico/src/transport/unicast/read.c @ return _z_fut_fn_result_wake_up_after(100);`),
and its background executor does not sleep for a wake-up 1 ms or less away
(`vendor/zenoh-pico/src/runtime/background_executor.c @ if (zp_clock_elapsed_ms_since(&res.next_wake_up_time, &now) > 1) {  // sleep until next task is ready`),
so each wake-up spins on the clock for 1 to 2 ms. How many such wake-ups a run holds depends on
how long it waits unconnected, which depends on the host's speed, so the slope of two runs took
idle work off the per-message cost: the 2,941 (2,840.6 on main `cf6ca0963`, W 4,843 there, 1.70)
was about 1,200 low. The harness of `f5f8ce646` counts only the subscriber's connected window
(`scripts/host-bench/bench_window.h`, callgrind's `--zero-before=bench_window_open*` and
`--dump-before=bench_window_close*`) and runs the same window a third time with no message, so
"net" is the larger run past that idle run. The gate below is the window's pico, 4,042.

The exclusive costs per message name 3,651 of W's 6,097 instructions in its 25 dearest functions
and 2,375 of P's 2,941 in its (the biased runs of 2026-11-25). The rest (W 2,446, P 566 there; P
1,667 against the window's 4,042) is spread over functions below 67 Ir each and is attributed per
stage only by the measurements of section 14 (M1, M2, M7). The 1,101 the window adds to P is not
yet given to a stage: the pico column of section 2 is the biased run's named costs, so each pico
stage is at least what it shows, and a target set under it is under the window's figure too. The stage values below
are therefore *lower bounds* built from the named functions; the targets are set so that the
whole, not only the named part, ends at or under pico.

What pico pays that wz does not: the heap. `malloc`, `free`, `_int_free` and `arena.c:free` are
553 Ir per message in P (the key expression copied into the subscription cache entry, the
reference-counted vector of matches cloned and dropped, the sample's arc slices), and two mutex
pairs (`pthread_mutex_lock`/`unlock`, 205 Ir). wz's nostd form takes no heap per message; it
loses on the executor and round (removed by section 8) and on the length of every other stage.

## 2. The stages and their budget

Ir per received message, shipped nostd form. "wz now" sums the named exclusive costs of the
stage; "pico" the same for zenoh-pico (the biased run's, a lower bound of each stage; M7 reads
them on the window); "target" is the stage's budget after the change, every one at or under
pico's. The whole-message row is the window harness's (section 1).

| # | stage | wz now | pico | target | structure that meets the target (detail in the section named) | files | lane |
|---|---|---:|---:|---:|---|---|---|
| 1 | socket and wait | 356 (`poll_on` 99, `wait_ready` 88, `waited` 97, `now_us` 72) + part of `Core::idle_wait` 262 | 270 (`_z_socket_wait_readable` 127, `select` 91, `_z_unicast_wait_iter_next` 52) + part of `_zp_unicast_read_task_fn` 128 | <= 120 | with `threads`, a face's read is one blocking `recv` on its own socket, no poll and no clock read; without, one persistent wait set and a drain of each ready link until it would block (section 3) | `wz-runtime-posix/src/net.rs`, `wz-runtime-coop/src/session_drive.rs`, `wz-runtime-coop/src/faces.rs` | R1 |
| 2 | stream framing | 297 (`StreamDriver::recv_with` 191, `memcpy` 106) | the rest of `_zp_unicast_read_task_fn` 128 and `_z_zbuf_compact` (*to measure*) | <= 100 | every whole batch in the buffer handed out in one call, the read slot's concrete link (no `dyn`), the partial tail moved only when the free room is under one batch (section 4) | `wz-runtime-coop/src/stream_link.rs`, `wz-runtime-coop/src/link_storage.rs` | R1 |
| 3 | batch and frame header | 223 (`UnicastRx::dispatch_datagram`) + `dispatch_units`, `frame_in_place`, `walk_records_in_place` (*to measure*) | 169 (`_z_unicast_handle_frame` 108, `_z_unicast_process_messages` 61) | <= 100 | one generated frame-header read, the SN check on the read slot's own receive state, no resume of a stopped datagram and no path counter in the shipped form (section 5) | `wz-session-core/src/drive.rs`, `wz-session-core/src/unicast_rx.rs`, `wz-session-core/src/session_actions.rs` | R2 |
| 4 | record decode | 620 (`read_push` 225, `read_vle_inner` 102, `walk_records` 79, `ExtEntryView::decode_into` 78, `lend_pulled` 69, `lent_body` 67) | 583 (`_z_zint64_decode` 167, `_z_uint8_decode` 88, `_z_network_message_decode` 86, `_z_bytes_decode` 66, `_z_push_decode` 51, `_z_msg_ext_decode_iter` 47, `_z_wireexpr_decode` 40, `_z_zsize_decode` 38) | <= 350 | one pass of generated code from the record header to a flat `PushRef`: one-byte ZInt read inline, the extension chain read once into known slots with its admission judged in the same pass, no default-then-overwrite of a variant, a generic record walk (section 6; generator design in section 7) | `wz-session-core/src/network_message.rs`, `network_message/pull.rs`, `network_message/push_read.rs`, `pubsub/in_place.rs`, `ext_admit.rs`; SCE `forge-runtime/src/codec.rs` and the codec templates; `out/wz-codecs/` | R3 (SCE), then R2 |
| 5 | key resolution | 83 (`resolve_wireexpr_viewed_held_over`) + the composition through `dyn KeyexprOut` (*to measure*) | 116 (`_z_get_keyexpr_from_wireexpr` 75, `_z_string_concat_substr` 41) + one mutex pair | <= 40 | a wire expression with a declared id and no suffix resolves to the peer's resource row by index, with no string built; a string is composed only for a suffix, into the read slot's room (section 8) | `wz-session-core/src/wireexpr_resolve.rs`, `wz-session-core/src/key_arena.rs` | R4 |
| 6 | finding the subscribers | 311 (`SubscriberPeer::dispatch_iteration_event`, with `scan_subscribers` and `admit_from_peer` inlined) | 177 (`_z_trigger_subscriptions_impl` with its LRU cache) + one mutex pair (about 100 of the 205) | <= 80 | the match set kept on the resource row (a fixed bit set of subscriber slots) and on a direct-mapped cache for suffix keys, both valid while the subscriber epoch is unchanged; no session lock on the data path (section 9) | `wz-session-core/src/session_tables.rs`, `wz-session-core/src/pubsub.rs`, `pubsub/in_place.rs` | R4 |
| 7 | delivery and callback marshal | 443 (`RoundDelivery::deliver_ref` 227, `subscriber_sink_at::call` 111, `Round::writable` 105) | 727 (`_z_sample_steal_data` 96, `_z_svec_reset` 78, the heap 553) | <= 100 | a direct call through the row's latch; the loaned sample is the `SampleRef` itself, read by the accessors, with no marshal copy; the in-callback mark is the read slot's owner word (section 10) | `wz-capi-coop/src/engine.rs`, `wz-session-core/src/sink.rs`, `wz-capi-pico/src/pubsub.rs`, `wz-capi-pico/src/ffi.rs` | R5 |
| 8 | timers and remainder | 257 (`keepalive_deadlines` 116, the `all_gets` deadline `reduce` 141) + part of `Core::idle_wait` | 0 per message (the lease task is a thread of its own and reads one flag) | <= 10 | the read sets a heard flag; the timers own their deadlines, recomputed when a timer is armed, not gathered per wait (section 3.3) | `wz-session-core/src/drive.rs`, `wz-session-core/src/pending_get.rs`, `wz-capi-coop/src/engine/registry.rs`, `wz-runtime-coop/src/time.rs` | R6 |
| 9 | executor pass and round | about 1,170 (`step_after` 242, `run_among` 231, `hand_out` 179, `poll_erased` 147, `Round::writable` 105, the round's share of `deliver_ref`) | 0 | 0 | removed by section 8 of the architecture | section 8.11 | section 8 |
| | named total | 3,651 | 2,375 | <= 900 | | | |
| | whole message | 6,097; window 4,836.7 net | 2,941; window 4,042.4 net | <= 2,000 (gate: <= 4,042) | | | |

The whole-message target leaves the unattributed remainder its share: if W's 2,446 unnamed Ir
fall with their stages in the proportion the named ones do, the whole lands near 1,500. The gate
is pico's window figure, 4,042; W's 4,837 is over it by 794 today, and section 8's removal of the
executor's pass and the round (about 1,170) alone takes W under it. The design target stays 2,000,
half of pico's: it is set by the structure, not by the gate, so the margin against the gate, about
2,000, is what a stage landing over its target spends before the verdict moves. Landed: t-ext
(`c829f01a5`, text S5) read W -26.9 Ir per message, in stage 4's extension admission.

## 3. Socket and wait (stage 1) and the timers (stage 8)

### 3.1 What pico and upstream do

- zenoh-pico's read task waits on the peers' sockets each turn (`vendor/zenoh-pico/src/transport/unicast/read.c` @ `return _z_socket_wait_readable(&iter, Z_CONFIG_SOCKET_TIMEOUT);`),
  which is a `select` built anew over the peer list on every turn: 270 Ir per message.
- Neither pico nor upstream reads a clock per message. pico's read marks the peer heard with one
  store (`vendor/zenoh-pico/src/transport/unicast/read.c` @ `peer->common._received = true;`) and
  the lease task reads and clears it (`vendor/zenoh-pico/src/transport/unicast/lease.c` @ `curr_peer->common._received = false;`).
  Upstream resets its lease tracker per batch (`io/zenoh-transport/src/unicast/universal/link.rs` @ `lease_tracker.reset();`),
  which does read the clock under a mutex (`io/zenoh-transport/src/unicast/universal/link.rs` @ `*self.0.latest_reset.lock().unwrap() = Instant::now();`):
  the shape to beat, not to copy.

### 3.2 The structure

- **With `threads`.** A face's read task (section 8.2) owns one link. Its wait is the link's own
  blocking read: `recv` into the read slot's free room, no `poll`, no wait set, no timeout computed.
  The task ends when the face ends: the close (or the lease timer that ends the face) shuts the
  socket down (`shutdown(SHUT_RDWR)`), the blocked `recv` returns 0 or an error, and the task sees
  the face's end (section 8.5). A group face does the same with `recvfrom` on the group socket.
  Per wake-up: one system call. `LinkWaits::wait_ready`, `poll_on` and `LinkSupervisor::waited` are
  not on this path.
- **Without `threads`.** The program's read keeps one wait set (`pollfd` array, or the target's
  equivalent) that changes only when a face or port is added or removed (a debt of the face,
  section 8.6), never rebuilt per wait. After a wake-up every ready link is drained: its read is
  repeated, and every whole batch handed out, until the read would block; only then is the set
  waited on again. One wait is paid per burst, not per message.
- **Heard, not timed.** The read stores `heard = true` in the face's lease word (an `AtomicBool`
  with `threads`, a `Cell<bool>` without). The lease timer, on its own period, reads and clears it,
  as pico's lease task does. No clock is read on the read path: `now_us` leaves stage 1 entirely.

### 3.3 Timers own their deadlines (stage 8)

Today every wait gathers every deadline: the keep-alive and lease deadlines of every link
(`keepalive_deadlines`, `wz-session-core/src/drive.rs:4054`) and every pending get's
(`RegistryOf::all_gets` reduced with `next_deadline_ms`, `wz-session-core/src/pending_get.rs:125`).
The structure instead:

- One `TimerSet` per session, owned by the executor that section 8.2 leaves with the timers alone:
  a fixed array of `(deadline_ms: u64, job: TimerJob)` rows (capacity from the session's open
  configuration, bounded by the preset's limit, as the heap ruling of 2026-11-26 sets every count)
  and a cached `next: u64`, recomputed only when a row is armed, re-armed or cancelled.
- Arming a get's deadline, sending a keep-alive, or admitting a link re-arms its row. The read
  path arms nothing: the keep-alive owed by a send is the send's (the send path's lane), and the
  lease is the heard flag above.
- With `threads` the timer task sleeps until `next`; without, `next` is the wait's timeout and is
  read once per wake-up.

Target: 0 Ir per message from stage 8 (the 10 of the budget is the heard store).

## 4. Stream framing (stage 2)

Measured: `StreamDriver::receive` (`wz-runtime-coop/src/stream_link.rs:972`) hands out one batch per
call (`Front::Batch` sets `lent`, and the next turn of the loop breaks), so a burst of N batches
costs N calls through `dyn SessionDatagramLink` and N trips through the executor; it borrows the
buffer through a `RefCell` and reads `lost` on each call; and it moves the partial tail to the
front whenever a read leaves one (`part.copy_within(start.., 0)`), 106 Ir of `memcpy` per message.

pico's stream read compacts its buffer too (`vendor/zenoh-pico/src/transport/unicast/read.c` @ `_z_zbuf_compact(&ztu->_common._zbuf);`);
upstream reads each batch into a pooled buffer (`io/zenoh-transport/src/unicast/universal/link.rs` @ `transport.read_messages(batch, link,`)
and hands its frames on where they are.

The structure:

- **The read slot owns its link concretely.** The face row of section 8.3 is `Face<L: FaceLink>`;
  the read calls `L::read_batches(&mut self, each: impl FnMut(&[u8]) -> Flow)`, monomorphic. The
  `CellRc<dyn SessionDatagramLink>` hop and the `&mut dyn FnMut` of `recv_with` leave the read path
  (they may stay for the configuration-time paths that need a trait object).
- **Every whole batch in one call.** `read_batches` loops over the receive buffer: read the
  two-byte length, if the batch is whole hand it out and advance, else stop. It returns when no
  whole batch remains; the caller's next step is the socket read (stage 1).
- **Move only what must move.** The partial tail is moved to the front only when the room after
  it is smaller than the largest batch the link negotiated; otherwise the next read appends after
  it. When the buffer is emptied (`start == held`) both indices reset to 0 with no copy. A burst of
  whole batches costs no copy at all.
- **No `RefCell`, no per-call loss check.** The receive buffer is the read slot's (`&mut` through
  the slot's hold); the loss is seen where the read fails, once.
- A batch kept by a callback past its return (`keeping`) is the case section 8 removes with the
  round: a direct callback returns before the next batch is read, so the shipped form has no kept
  batch. The `keeping` cell goes with the round (architecture step 8.11.5).

Target <= 100 Ir per message: the length read, two index updates and the call.

## 5. Batch and frame header (stage 3)

Measured: `UnicastRx::dispatch_datagram` (`wz-session-core/src/unicast_rx.rs:549`) goes through
`Router::dispatch_in_place` and `drive::dispatch_datagram` (`wz-session-core/src/drive.rs:2000`),
whose `dispatch_units` carries the round's resume machinery: whether the sink holds the datagram
(`holds_datagram`), whether it takes another unit (`takes_another`), and a `DatagramResume` stored in
the session's actions to continue a datagram the round stopped. It counts the path taken
(`self.paths.count(path)`) on every datagram.

pico (`vendor/zenoh-pico/src/transport/unicast/rx.c` @ `static z_result_t _z_unicast_handle_frame(`) checks the SN
(`vendor/zenoh-pico/src/transport/unicast/rx.c` @ `if (_z_sn_precedes(ztu->_common._sn_res, peer->_sn_rx_best_effort, msg->_sn)) {`)
and decodes and handles each network message in turn
(`vendor/zenoh-pico/src/transport/unicast/rx.c` @ `_Z_RETURN_IF_ERR(_z_handle_network_message(&ztu->_common, &curr_nmsg, &peer->common));`).
Upstream does the same over a frame reader (`io/zenoh-transport/src/unicast/universal/rx.rs` @ `if !self.verify_sn("Frame", frame.sn, &mut guard)? {`,
`io/zenoh-transport/src/unicast/universal/rx.rs` @ `for mut msg in frame {`).

The structure:

- **One frame-header read, generated.** `FrameHeaderRef { reliable: bool, sn: u32, qos: Option<u8> }`
  read by the frame codec's generated header reader (section 7), the SN with the one-byte fast path.
- **The SN on the read slot's state.** The receive SN pair is the face's pump state (section 8.3),
  reached by `&mut`, no lock. A frame out of order is dropped as pico drops it.
- **No resume in the shipped form.** With section 8, a record's callbacks run before the walk reads
  the next record, so a datagram is never stopped part-way: `dispatch_units` is one loop over
  units, and `DatagramResume`, `holds_datagram`, `takes_another` and `set_datagram_resume` go with
  the round (architecture step 8.11.5). The units loop is generic over the sink, not `?Sized` behind
  `dyn EventSink`.
- **The path counter is a diagnostic.** `RxPathCounts` is kept behind the feature that already
  gates the in-place path (`rx-in-place`) in test and diagnostic builds and is not in the shipped
  preset.
- **One carrier shape.** `RecordCarrier` is one struct in every build (the `alloc` and non-`alloc`
  destructurings of `walk_records_in_place`, `wz-session-core/src/drive.rs:2919`, become one).

Target <= 100 Ir per message.

## 6. Record decode (stage 4)

Measured path: `walk_records` (`wz-session-core/src/network_message.rs:2144`) chooses a form, then
`hand_pulled_records` pulls a `RecordView` from `Records` (`network_message/pull.rs`), whose cells
(`at`, `unread`, `failed`) are re-read for every record; `lend_pulled` (`network_message.rs:2277`)
defaults a body view and reads into it; `read_push` (`network_message.rs:2589`) calls
`read_push_view` (`network_message/push_read.rs:221`), which reads the envelope, defaults a
`MsgPutView` inside a `PushViewVariant`, matches the variant again to read the body, and for each
extension entry calls `judge_ext_entries` over a one-element iterator; `lent_body`
(`pubsub/in_place.rs:129`) then walks the put's extension chain a second time to find the encoding,
timestamp, source info and attachment. Every ZInt goes through `read_vle_inner`, whose loop calls
`peek_u8` and `advance` per byte, each with its own bound check and `Result`.

pico decodes the same push in one pass (`vendor/zenoh-pico/src/protocol/codec/network.c` @ `z_result_t _z_push_decode(`),
its ZInt with a loop per byte (`vendor/zenoh-pico/src/protocol/codec.c` @ `z_result_t _z_zint64_decode(uint64_t *zint, _z_zbuf_t *zbf) {`),
167 Ir per message on that alone. The one-byte ZInt is the common case (a scope id, a length, a
flag word under 128) and is where both can be beaten.

The structure:

- **`PushRef<'f>`, flat and read once.** One generated function reads a push record, from its
  header byte to the end of its body, into
  `PushRef { header: u8, key: WireKeyRef<'f>, qos: Option<u8>, body: PushBodyRef<'f> }`, with
  `PushBodyRef::Put(PutRef<'f>)` / `Del(DelRef<'f>)` decided by the body tag before anything is
  written, and `PutRef { encoding: Option<EncodingRef<'f>>, timestamp: Option<TimestampRef<'f>>,
  source_info: Option<SourceInfoRef<'f>>, attachment: Option<&'f [u8]>, payload: &'f [u8] }`. Every
  field borrows the batch; nothing is copied. `lent_body` reads these fields instead of walking the
  chain again.
- **Extensions in one pass into known slots.** The chain is read once; an entry whose id the
  carrier knows fills its slot, an unknown entry without the mandatory bit is skipped by its
  length, an unknown mandatory entry sets the record's verdict to refused. The admission rule of
  `ext_admit` is compiled into the generated reader as a per-carrier table of known ids (a `u32`
  bit mask per carrier), so the judge is one mask test per entry, not a call over an iterator.
  The shared-memory marker keeps its slot.
- **ZInt with a one-byte fast path.** `if b < 0x80 { pos += 1; return b }` inline at the call site,
  the multi-byte loop out of line and `#[cold]`; one bound check (`buf.get(pos)`) per byte, not two.
- **The walk is generic.** `EachRecord` is a type parameter of the walk, not `&mut dyn EachRecord`,
  and `Records` is a plain struct owned by the walk (`&mut self`), not cells shared through `&`.
- **The forms collapse to one in the shipped preset.** `RecordForm::Owned` and `RecordForm::Lent`
  remain for the builds that hold records past the walk (the router's namespace path); the shipped
  form compiles `LentControl` alone, as now, and the match in `walk_records` is resolved at compile
  time.

Target <= 350 Ir per message. The SCE part is section 7; the wz part (the walk, the admission
table, `lent_body`) is lane R2 and lands after R3's regenerated codecs.

## 7. The generator's side: draft ADR for SCE

The codecs are generated by SCE from `sources/codecs/*.scxml` and committed under `out/wz-codecs/`;
SCE is pinned and read-only from a wz session, so this section is a draft for an SCE session to
take, with the number the SCE ADR index gives it.

**Title.** A codec's view decoder reads a record in one pass into a value whose fields borrow the
input, with its extension chain resolved into the slots its document names.

**Context.** The generated view decoders today (`ExtEntryView::decode`, the `*View::decode_into`
family, `out/wz-codecs/ext_entry.rs`) decode into a value the caller defaulted, one field at a time
through `SceCursor::peek_u8` and `advance`, each returning `Result`; a choice is a variant the
caller defaults and the decoder overwrites; an extension chain is a `ListView` the consumer walks
again to find the entries it needs. The cursor's ZInt read (`read_zint`,
`vendor/sce/backends/rust/forge-runtime/src/codec.rs` @ `fn read_vle_inner(&mut self, max_bits: u32)`)
pays two bound checks per byte and no fast path for the one-byte value. A consumer that needs
to beat a hand-written C decoder per message pays for each of these.

**Decision.**

1. *Return, do not fill.* Each view codec gets `fn read(cursor: &mut SceCursor<'a>) -> Result<XRef<'a>, CodecError>`
   that constructs its value once. A choice reads its tag first and constructs only the chosen
   arm. `decode_into` stays for the callers that fill a place they own.
2. *Extension slots.* A codec whose document declares an extension chain with named entries (the
   `ext_entry` children it lists) gets a generated `XExts<'a>` struct with one `Option` slot per
   named entry and a `refused: bool`; the reader fills it in the same pass. The known-id set per
   carrier is a constant the generator emits from the document (a `u32` mask), and the rule for
   an unknown entry (skip if not mandatory, refuse if mandatory) is the one rule of the Zenoh
   extension encoding; a document may name its own rule for a carrier that differs.
3. *ZInt fast path in the runtime.* `SceCursor::read_zint` becomes an `#[inline(always)]` one-byte
   test with the loop in an `#[inline(never)] #[cold]` continuation; each byte is read with one
   `get`. The width check of `read_vle_inner` is folded into the continuation (a one-byte value
   is never past any width).
4. *Errors cold.* Every error return of a generated reader goes through a `#[cold]` constructor, so
   the success path is straight-line code.

**Consequences.** The generated text grows by the slot structs and the masks (counted by the text
lane); the per-record instructions fall by the default-then-overwrite, the second chain walk and
the second bound check. The committed `out/wz-codecs/` changes in one regeneration commit after
the SCE pin moves; the regen-diff lane holds committed equal to regenerated.

**Tests (SCE).** For every codec with a view reader: the new reader and `decode_into` agree on
every corpus input, accepted and refused (a differential over the existing codec corpus and a
fuzz target); the ZInt fast and slow paths agree on every 1- to 9-byte encoding, the padded ones
and the width overflow included; a chain with an unknown mandatory entry is refused and one with
an unknown optional entry is skipped with its slots unchanged.

**Tests (wz).** `push_read` over `PushRef` accepts and refuses exactly what `read_push_view` does
over the receive corpus (`wz-fuzz`'s ingress inputs); the subscriber receives the same samples
(key, payload, encoding, timestamp, source info, attachment) in the differential tests against
pico and upstream.

## 8. Key resolution (stage 5)

Measured: `resolve_wireexpr_viewed_held_over` (`wz-session-core/src/wireexpr_resolve.rs:1100`)
clones the wire expression's arm into an owned-shaped variant and resolves it through
`&mut dyn KeyexprOut`, composing the key's text into a room even when the expression is a
declared id with no suffix, the common case of a publisher that declared its key.

pico locks the session for every lookup (`vendor/zenoh-pico/src/session/resource.c` @ `z_result_t _z_get_keyexpr_from_wireexpr(`)
and concatenates a suffix into a new string. Upstream, for a scope with no suffix, reaches the
resource node and reads its subscribers from it without forming a key string
(`zenoh/src/api/session.rs` @ `Some(Resource::Node(res)) => {`,
`zenoh/src/api/session.rs` @ `for sub in res.subscribers(kind).iter() {`); only a suffix makes it
build a key and intersect it with every subscriber
(`zenoh/src/api/session.rs` @ `&& key_expr.intersects(&sub.key_expr)`).

The structure:

- **`ResolvedKey<'k> { row: Option<KeyRow<'k>>, suffix: &'k str }`.** A declared id with no suffix
  resolves to the resource row of the mapping that named it, by index into the face's remote
  resource table (the peer's declarations) or the session's own (ours); nothing is composed.
- **The peer's declarations belong to its face's read slot.** A peer's declarations arrive on that
  peer's face and are applied by that face's read, so the face's remote resource table is the read
  slot's and is reached without the session's lock. The session's own resource table is changed by
  the application's threads and is read under the subscriber epoch of section 9.
- **A string only when asked.** The key text of a declared row is its `KeyRef` (`key_arena.rs`);
  with a suffix the text is composed once into the read slot's key room, bounded by the preset's
  key length. The sample handed to the callback carries the row and the suffix; `z_sample_keyexpr`
  composes the text in the read slot's room on first use (and the matching of section 9 never needs
  it for a declared row).
- The `dyn KeyexprOut` stays for the paths that resolve into a caller's place (replies, the
  router); the data path is concrete.

Target <= 40 Ir per message for a declared key, *to measure* for a suffixed one.

## 9. Finding the subscribers (stage 6)

Measured: `SubscriberPeer::dispatch_iteration_event` (`wz-session-core/src/pubsub.rs:1930`) reaches
`deliver_from_peer` (`wz-session-core/src/session_tables.rs:3822`), which admits the key through
`admit_from_peer` and then, in the shipped form (`no_allocation` and a capacity-enforcing storage),
scans every subscriber row and intersects its pattern with the key (`scan_subscribers`,
`pubsub.rs:2712`); the match memory `fire_into_memoized` (`pubsub.rs:2597`) is used only by the other
forms. All of it runs under the session's lock (section 8.4 of the architecture).

pico keeps an LRU cache keyed by the key expression and takes the session's mutex around it
(`vendor/zenoh-pico/src/session/subscription.c` @ `cache_entry = _z_subscription_lru_cache_get(&zn->_subscription_cache, out);`),
and pays the heap to copy the key into a new entry and to clone the match vector
(`vendor/zenoh-pico/src/session/subscription.c` @ `_z_subscription_cache_data_clear(&sub_infos);`).
Upstream keeps the matches on the resource node (section 8 above).

The structure:

- **`SubscriberSet`: a fixed bit set over subscriber slots.** Its width is the session's subscriber
  count from the open configuration (bounded by the preset's limit, the 2026-11-26 heap ruling);
  in the shipped form a few words of `u64`.
- **The match set lives on the resource row.** Each resource row (ours and each peer's) carries
  `matches: SubscriberSet` and `matched_at: u32` (the subscriber epoch it was computed at). A record
  on a declared key reads the session's subscriber epoch; if it equals `matched_at` the set is the
  answer, else the set is recomputed once by the existing intersection and stored. A declaration
  or undeclaration of a subscriber, or a change of a key gate's admission, bumps the epoch. This is
  upstream's shape, with the rows fixed and the set a bit set instead of a vector of references.
- **Suffixed keys: a direct-mapped cache.** The existing match memory (`fire_into_memoized`) becomes
  the one path for a suffixed key in every form: `MATCH_MEMO_FIXED_SLOTS` entries of
  `(hash: u32, len: u16, text in the key room, matches: SubscriberSet, epoch: u32)`, the entry count
  from the open configuration. A miss pays one intersection pass, as now.
- **The admission is in the set.** `admit_from_peer`'s verdict for a key is part of what the set
  records (a refused key's set is empty), so the gate is not re-run per message.
- **No session lock on the data path.** The read (holding its face's read slot, section 8.3)
  reads the epoch with an acquire load, reads the row's set, and enters each matched subscriber
  slot through the slot's latch: the latch word holds the slot's generation and its in-flight
  count, and entering is one compare-and-swap that fails if the generation moved or the slot is
  closing; leaving is one decrement. An undeclare marks the slot closing, bumps the epoch and waits
  for the in-flight count (section 8.5 unchanged). Without `threads` the latch is a `Cell` and the
  epoch a plain read. This replaces the per-record take of the session's lock in section 8.4
  (owner decision D1).

Target <= 80 Ir per message for one matched subscriber on a declared key: one epoch load, one
compare, one bit scan, one latch enter and leave.

## 10. Delivery and the callback's marshal (stage 7)

Measured: `RoundDelivery::deliver_ref` (`wz-capi-coop/src/engine.rs:3174`) offers the sample to the
round (`offer_sample_ref`), and the round writes it (`Round::writable`) to be handed out later;
`subscriber_sink_at::call` (`wz-capi-pico/src/pubsub.rs:741`) reaches `hand_sample`
(`wz-capi-pico/src/pubsub.rs:703`), which builds a `SampleMarshal` from the `SampleRef` and binds it,
enters `InCallback` (a thread-local mark, `wz-capi-pico/src/ffi.rs:344`) and calls the C closure
inside `ffi::catch`.

pico moves the decoded parts into a `_z_sample_t` (`vendor/zenoh-pico/src/session/subscription.c` @ `_z_sample_steal_data(&sample, &sub_infos.ke, payload,`)
and passes its address to the callback (`vendor/zenoh-pico/src/session/subscription.c` @ `sub_info->_callback(&sample, sub_info->_arg);`),
then frees what it moved.

The structure:

- **A direct call.** The delivery is `DirectDelivery`, the section 8 replacement of
  `RoundDelivery`: for each matched slot, enter the latch (section 9), call the row's sink, leave.
  `deliver_ref` and `writable` leave stage 7 with the round.
- **The loaned sample is the `SampleRef`.** `z_loaned_sample_t` is the opaque C name of a
  `SampleRef` (the pointer passed to the callback is `&SampleRef as *const _ as *const z_loaned_sample_t`);
  the accessors (`z_sample_keyexpr`, `z_sample_payload`, `z_sample_encoding`, `z_sample_timestamp`,
  `z_sample_attachment`, ...) read its fields and build their loaned views on demand, which is where
  the marshal's work goes (paid only for what the callback reads). `SampleMarshal` leaves the
  callback path; `z_sample_clone` keeps the owned copy it makes today. (owner decision D3: the
  layout behind the opaque type changes; the C header's size for a *loaned* type is not part of
  the ABI, an *owned* sample's is.)
- **The in-callback mark is the read slot's.** Section 8.5 already gives the read slot an owner
  word (the thread holding it); a call from inside a callback is recognised by that word, and the
  separate thread-local `InCallback` mark goes. `ffi::catch` is compiled out where the build
  aborts on panic, as the shipped nostd form does.

Target <= 100 Ir per message for one subscriber: the latch, the sink's indirect call, the closure's
indirect call.

## 11. The std and heap form

The same structure in every form: the read task per face, the read slot's concrete link, the
generated readers, the match sets and the direct delivery have one implementation, the form
changing only what section 8 lets it change (the lock kind, the link types). The heap form's
differences:

- the counts (subscriber slots, resource rows, match-memory entries, timer rows) come from the open
  configuration with no preset bound smaller than the type's; the storage is still taken once at
  open (no heap per message in either form);
- the std form's measured extra over the nostd form (`memcpy` 212 against 106, and a guard's
  `enter` and `drop` of 135 each per message in the earlier std measurement) are the stream copy of
  section 4 and the per-record lock of section 9, both removed by the same structure.

Target: <= 2,000 Ir per message in the std and heap form too; gate <= 4,042 (the window
harness's pico, the same library).

## 12. Lanes

| lane | owns | depends on | judged by |
|---|---|---|---|
| R1 socket, wait, framing | `wz-runtime-posix/src/net.rs`, `wz-runtime-coop/src/stream_link.rs`, `link_storage.rs`, `session_drive.rs`, `faces.rs` | architecture step 8.11.4 (the read task per face) | stages 1 and 2 under 220 Ir; a burst of N whole batches handed out in one call with no copy; a close ends a blocked read |
| R2 frame header and record walk | `wz-session-core/src/drive.rs`, `unicast_rx.rs`, `network_message.rs`, `network_message/pull.rs`, `network_message/push_read.rs`, `pubsub/in_place.rs`, `ext_admit.rs` | R3's regenerated codecs; architecture step 8.11.5 for the resume removal | stages 3 and 4 under 450 Ir; the receive corpus accepted and refused as before |
| R3 SCE generator (draft ADR, section 7) | SCE templates and `forge-runtime`; then the wz pin move and `out/wz-codecs/` regeneration | an SCE session's review | the SCE differential and ZInt tests; the regen-diff lane |
| R4 key and match | `wz-session-core/src/wireexpr_resolve.rs`, `key_arena.rs`, `session_tables.rs`, `pubsub.rs` | D1; architecture step 8.11.1 (the locks) | stages 5 and 6 under 120 Ir; the epoch invalidation tests below |
| R5 direct delivery and marshal | `wz-capi-coop/src/engine.rs`, `wz-session-core/src/sink.rs`, `wz-capi-pico/src/pubsub.rs`, `wz-capi-pico/src/ffi.rs` | architecture step 8.11.5; D3 | stage 7 under 100 Ir; the C examples and the pico differential tests unchanged |
| R6 timers | `wz-session-core/src/drive.rs` (`keepalive_deadlines`), `pending_get.rs`, `wz-capi-coop/src/engine/registry.rs`, `wz-runtime-coop/src/time.rs` | architecture step 8.11.4 | stage 8 at 0 Ir; a get's deadline and the lease still fire on time |

R1 and R2 both edit the receive path but not the same files; R2 and R6 share `drive.rs` in
different functions and are merged in the order R6, R2. Order: R3 starts at once (SCE side);
R1, R4 and R6 after architecture steps 8.11.1 and 8.11.4; R2 after R3's pin; R5 last, with the
round's removal.

### 12.1 Tests each lane adds

- R1: a stream buffer holding three whole batches and a partial fourth hands out three in one call
  and keeps the fourth's bytes in place; a buffer emptied resets with no copy; a read task blocked
  on its link ends when the face is closed; the heard flag is set by a read and cleared by the lease
  timer, and a face with no read for a lease ends.
- R2: a datagram whose second record's callback calls the session reads the third record after
  the callback returns; an SN out of order drops the frame as pico does.
- R4: a subscriber declared after a key's set was computed receives the next message on that key;
  an undeclared one does not; a suffixed key past the memo's entry count still delivers (a miss);
  a key refused by a gate delivers nothing and stays refused until the gate changes; with
  `threads`, an undeclare racing a delivery either delivers whole or not at all, and the slot is
  reused only after the in-flight count is zero.
- R5: a callback that reads only the payload does not compose the key; `z_sample_clone` inside a
  callback yields an owned sample equal to the loaned one.
- R6: with N pending gets, a wait computes no deadline (the timer set's `next` is read once); a get
  whose deadline passes is ended on time.

## 13. Owner decisions

- **D1.** The data path takes no session lock: a record is matched against an epoch-stamped
  match set and enters each subscriber through its slot's latch. This amends section 8.4 ("takes
  the session's lock once for each record it dispatches").
- **D2.** With `threads`, a face's read is a blocking read on its own link with no poll and no clock
  read; a close and a lease end shut the socket down to end it; liveness is a heard flag. This
  amends section 8.9 ("one wait, one reading of the clock" per datagram becomes one system call).
- **D3.** The loaned sample handed to a subscriber callback is the session's `SampleRef` behind the
  opaque C type, and its accessors build their views on demand.
- **D4.** The SCE generator change of section 7 is taken by an SCE session; wz moves its pin when
  it lands.
- **D5** (decided 2026-11-26 under the owner's delegation). No crate is a size boundary: a cold
  arm moved out of the read (`text.md` S4's `control_in`, X2's `transport_control`) is one
  non-generic `#[inline(never)]` body over plain references, at the root's level, not a crate at
  `opt-level = "s"` (`text.md` P5, O1). The hot path of section 2 stays concrete; rule 1 of
  `text.md` section 7 holds it.
- **D6** (decided 2026-11-26 under the owner's delegation). What a read stage writes to a face (a
  get's Response and ResponseFinal, a control message) waits in that face's `TxBatch` and is
  flushed once when the read stage ends; no send window is open while a callback runs
  (`ir-send-query.md` D6). On a subscriber's read it costs one test of each read face's batch
  length; a read that wrote nothing sends nothing. The lane t-tx implements it.

## 14. Measurement cells

| cell | what | how |
|---|---|---|
| M1 | W's per-stage inclusive cost, nostd, now and after each lane (2,446 Ir unattributed today) | callgrind slope (2,000 against 12,000 messages), inclusive cost at each stage's entry function, with `#[inline(never)]` kept on the entries named in section 2 |
| M2 | P's per-stage inclusive cost (566 Ir unattributed in the biased run, 1,667 against the window's 4,042) | the same slope over `_z_unicast_handle_frame`, `_z_network_message_decode`, `_z_get_keyexpr_from_wireexpr`, `_z_trigger_subscriptions_impl` |
| M3 | the std and heap form, W and P, as a slope | the same harness, std build |
| M4 | messages per batch and batches per read system call in the harness | count in the harness; decides how much of stages 1 to 3 is per batch rather than per message |
| M5 | a member of a group: the per-message cost of the group read | the same harness over the multicast face |
| M6 | a suffixed key (no declared id): stages 5 and 6 | the harness with an undeclared publisher key |
| M7 | every stage of both arms again in the connected window, net of the idle run; W and P per message after each lane | measure, harness f5f8ce646 (`scripts/pico-compare.sh` subprofile under callgrind) |
