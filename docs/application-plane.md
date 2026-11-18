# Application plane

Status: design, not built. Written 2026-11-18. Nothing here is a switch yet; every name below is
the one the first change that builds it declares in `deploy/wz-config.toml`, and every switch is
OFF by default: a build that names none of them is the upstream preset it was before.

## What it is

Above a zenoh session, a vehicle network commonly runs a thin layer that every node of one
deployment shares: each message is protected end to end, a message may carry several independent
instances told apart by fields of its payload, a late subscriber asks the publishers for what
they last sent, and a receiver supervises that a periodic message keeps arriving. Deployments
build this layer above zenoh-pico in C, per deployment, generated from a message database. wz
provides it once, as switches, so that a deployment states its layer as data and wz runs it.

| Plane | Question it answers | What wz has | What is missing |
|---|---|---|---|
| Protection | Is this frame the one its sender built, and is it the next one? | A profile described as data (`wz-capture` `e2e_profile`: field widths, xor, bit splits, any CRC by its parameters, a CRC feed order, a length rule); a frame builder and opener; a stateless counter judge; a C sender door (`e2e-sender`, c ABI only) | The judge as receiving state behind a door; values a sender derives (an identifier composed of catalog values, a sender field derived from the node's address); the rules a deployment judges by (below); a door on the pico ABI |
| Sender demultiplexing | Which sender's counter does this frame continue? | Nothing | Judging state kept per sender, keyed by a field of the protected header |
| Instance key | Which instance of the message is this? | Typed payload fields from a schema (`wz-capture` `proto_schema`, `proto_decode`) | An instance index read from up to a fixed number of payload fields, and state (judge, cache, last value) per instance |
| Supervision | Has a periodic message stopped arriving? | A clock the application registers (`clock-source`), supervision of a deadline the application feeds (`supervision`) | A per-stream reception deadline with a start delay, an activation condition, a notification given once per loss, and a saturating error count |
| Replay cache | What did each publisher last send, for a subscriber that arrives now? | zenoh's advanced publisher and subscriber (`advanced`: cache, history query, miss detection); targeted queries (`targeted-query`); remote declaration events (`remote-declaration-watch`, core only); a declared segment profile and a segment sender (`segment-sender`, c ABI only) | A per-instance ring of the frames as sent, answered on a fixed key suffix in the shape a deployed peer reads; the subscriber side that asks each publisher as it appears and merges the answer with live data |
| Message catalog | Which messages exist, and with what period, protection, keys and depth? | `deploy/wz-config.toml` for build switches; a JSON5 reader | One declaration of a deployment's messages, read at run time by a host library and turned into static tables by a generator for a fixed-memory image |

They are one design because they share one axis: the STREAM. A stream is one message, of one
instance, from one sender. The judge, the supervision deadline, the replay ring and the last value
are all per stream, and a deployment that turns on instances or sender demultiplexing multiplies
the same state rather than adding new state. Built separately, each would decide its own keying
and its own storage; built once, the key is decided once.

## Principles

1. **The layer is data, the mechanism is wz's.** Header shapes, constants, identifiers, key
   fields, periods and depths are a deployment's and arrive as data (the catalog and the profile).
   wz holds no deployment's constants in code or tests: tests run on synthetic profiles whose
   widths, orders and constants are deliberately unlike any real one, as `e2e_profile` already
   does. A real profile is checked only by an oracle lane outside the repository.
2. **Wire shape is a contract, measured against a deployed peer.** Where a deployment already
   runs this layer, wz's frames and answers are byte-identical to that peer's, and the claim is a
   lane that exchanges frames with a build of that peer, not a reading of its documents.
3. **Off is zero.** A switch that is off adds no field to a session slot, no symbol to an image
   and no text beyond the capability budgets, exactly as the observation plane states
   (`docs/observation-plane.md`, principle 5).
4. **Storage is given.** Every table is sized by a limit and backed by storage the application or
   the generator supplies. A host build may allocate it once at catalog load; a fixed-memory build
   never allocates.
5. **Lifecycles are statecharts.** The replay round of a subscriber (asked, answering, abandoned,
   live), the serving of a replay by a publisher, and the activation of supervision are
   lifecycles, so they are SCXML under `sources/` and generated, as the session machines are.
   Arithmetic with a wrap (counter deltas, deadlines) is a pure function with a model test.
6. **A payload is always delivered.** A judgement is a fact reported beside the sample; dropping
   a sample is a separately named policy, never a side effect of a judgement.

## The switches

All default off. Kinds as in `deploy/wz-config.toml`: capability (C), policy (P), limit (L).

| id | Kind | What it adds |
|---|---|---|
| `e2e-sender` (exists) | C | Widened from the c ABI to the pico ABI. |
| `e2e-receiver` | C | The receiving judge as a door: per-stream state, the judging rules below, a status per sample. |
| `e2e-sender-demux` | C + L `E2E_SENDER_SLOTS` | Judging state per sender, keyed by a header field; slots bound by declaration or by arrival. |
| `e2e-supervision` | C + L `E2E_SUPERVISED_STREAMS` + P `e2e-supervision-notify` (`status-only`, `last-value`) | Reception deadlines per stream, started after a delay, gated by a condition the application supplies. |
| `instance-key` | C + L `INSTANCE_KEY_FIELDS`, `INSTANCES_PER_MESSAGE` | An instance index from payload fields; per-instance state. |
| `replay-cache` | C + L `REPLAY_DEPTH_MAX` + P `replay-reply-shape` (`frame-per-sample`, `segmented`), P `replay-serve-holds-sends`, P `replay-live-before-answer` (`deliver`, `hold-back`) | The publisher's ring and responder, and the subscriber's asking and merging. |
| `message-catalog` | C | The catalog reader (host, run time) and generator (fixed-memory image). |

Prerequisites on the pico ABI, each its own change: `remote-declaration-watch` and
`declarations-synced-event` (core only today), `segment-sender` (core and c), and the
`targeted-query` door.

## A1 Protection: the rules a deployment judges by

The profile already describes where the fields are and how the CRC is taken. A deployment also
states how a receiver judges, and these are profile data, each with a default equal to the
current judge:

- **Integrity.** Which fields, besides the CRC, make a frame intact: an identifier that must equal
  the expected one, a length that must equal the frame's length. A frame that fails any of them is
  reported as an integrity error, and changes no state.
- **First frame.** Accepted as the baseline without a counter judgement.
- **Counter.** A step of zero (repetition) and a step above the largest accepted gap are each
  judged; whether the two are reported apart or as one counter error is stated; whether a step
  above the gap moves the baseline is stated. The largest gap has a ceiling the profile states.
- **Derived values.** A field's value may be composed from catalog values (bit fields), xored with
  a constant, or derived from the node's address under a mask; the sender writes it, the receiver
  expects it.
- **Message cell.** A header field that carries a kind, a result and a sender identity is split
  by the profile's bit ranges; the receiver reads the sender identity for demultiplexing and
  reports the rest.

A sender may cache the CRC of an unchanged payload; the cache must give the bytes the full
computation gives, and the full computation is the reference the tests compare it with.

## A2 Sender demultiplexing

Off, one judge per (message, instance). On, a message whose catalog entry names several senders
keeps one judge per sender, selected by the sender identity read from an intact frame's header.
A slot is either bound by the catalog (an identity not listed is dropped and counted) or taken in
arrival order (only by an intact frame; a frame whose identity matches a taken slot is judged in
it even if it is not intact). A full table drops and counts. Instance keys and sender
demultiplexing are exclusive on one message, as the stream is one or the other.

## A3 Instance key

A catalog entry names up to `INSTANCE_KEY_FIELDS` fields of the payload (integer, enumeration or
bounded string) and the values each may take, per publisher and per subscriber. The instance index
is the position of the field values in the product of those lists, numbered per node and per
direction; it is never on the wire, and the key expression does not change with the instance. A
sample whose values fall outside the list is dropped and counted (a rate-limited diagnostic event,
`event-ring`), never judged.

## A4 Supervision

A stream with a period in the catalog has a reception deadline of `period x factor`. Supervision
is active only while an application-supplied condition holds and after a start delay from the
first poll that has a clock. When it becomes active the deadline is re-based for every stream
that can time out, so a stream that never arrived times out one deadline after activation. A
loss is reported once (edge, not level), the per-stream and per-node error counts saturate, and a
sender the application marks absent is excluded until marked present again. The notification is a
status with the stream's identity; with `e2e-supervision-notify = last-value` it also carries the
stream's last value, as a deployment that expects one in its receive callback needs.

The poll is driven by the host runtime on a task where the runtime has tasks, and by the
application's own call on the cooperative engine, as the observation plane's sampler is.

## A5 Replay cache

**Publisher.** Each (message, instance) keeps a ring of `depth` frames exactly as they were sent,
protection header included, recorded before the send and whether the send succeeds. A queryable
on the message's key expression plus a suffix the catalog names answers a query with the ring:
one reply per sample in ascending (time, instance, sequence) order over all instances, taken from
a snapshot at the start of the answer, then the final. With `replay-reply-shape = segmented`, a
sample larger than one frame is answered as the pieces of the message's declared segment profile.
With `replay-serve-holds-sends`, periodic sends of that message pause while an answer is served and
event sends are deferred to a bounded queue, so no newer frame reaches a subscriber before the
replay that precedes it.

**Subscriber.** Each publisher's appearance (a remote declaration event of the suffixed
queryable) starts one targeted query to that publisher. Each reply re-arms a progress deadline;
when it passes the round is abandoned and the subscriber is live. In-flight queries are bounded by
the querier quota. Replies enter the same receive path as live samples and are judged by the same
judge; a reply behind the judge's baseline by less than the depth is dropped without moving it,
and a reply that repeats the last counter with the same CRC is dropped as a duplicate. With
`replay-live-before-answer = hold-back`, live samples are not delivered until the first query to
some publisher has been accepted.

## A6 Message catalog

One declaration, JSON5, lists the deployment's messages: key expression, message id, direction
per node, period or event, protection profile and its values, instance keys and their values,
sender list, replay depth, and the supervision factor and start delay. A host library reads it at
run time, which is also how one library serves two profiles: the catalog selects. A fixed-memory
image runs a generator over the same file and links static tables, and the build fails when a
table exceeds its limit. The schema is checked by one reader in both paths.

## Order and acceptance

| Step | Builds | Accepted when |
|---|---|---|
| 0 | The pure protection code (CRC, profile, frame, judge, segment profile) moved from `wz-capture` into a runtime crate both use; pico ABI reach of the prerequisites | `wz-capture` tests unchanged; the moved crate builds `no_std` without `alloc` for the judge and CRC |
| 1 | A1 + A2 (`e2e-receiver`, `e2e-sender-demux`, `e2e-sender` on pico) | Synthetic-profile model tests for every rule; the oracle lane exchanges frames with a deployed peer's build in both directions |
| 2 | A6 catalog reader and generator | One catalog drives a host library and a fixed-memory image to the same tables |
| 3 | A3 instance key | Per-instance judge and last value; out-of-list samples counted |
| 4 | A4 supervision | Edge notification, re-basing on activation, exclusion, saturation, each with a test on a model clock |
| 5 | A5 replay cache | Byte-identical answers to the deployed peer's on the oracle lane; a late subscriber receives every instance's ring before newer data |

## Decisions for the owner

1. Whether a query request is ever protected. The deployed shape protects samples and replies,
   not requests; this design follows it and leaves requests plain.
2. Whether a supervision loss reaches the application through its receive callback (the deployed
   shape) or through a status callback of its own. The policy above offers both; the default is
   the status callback.

## Not part of this

- Message encoding. The payload is bytes to this plane, except where an instance key reads typed
  fields through the schema.
- Fragmentation below the message. A message larger than a frame is cut by its declared segment
  profile; zenoh's own fragmentation is unchanged.
- An adapter for any deployment's C API. A deployment states its layer as a catalog and profile;
  wz does not reproduce another library's function names.
