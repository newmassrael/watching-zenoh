# Dissect handle: a row index, and rows decoded when asked

Status: design note. It states what is measured, what is decided and what is
still open; it is not a specification and the atomic store does not parse it.
Decisions here follow the standing criterion of this tree (the long-term
correct design, cost not counted); the reason for each is next to it. It is
the plan behind open-debt item 924.

## 1. The question

A consumer that opens a capture file through `wz_dissect_pcap_replay` and keeps
the handle open needs the handle's memory to stay in proportion to the file. An
open handle holds several times the file, and the multiple grows with the row
count. The question is what the handle must hold so that a file of any length
can be opened, scrolled, filtered and counted, with every door of the live
family answering what it answers today.

## 2. What is measured (2026-10-23, `origin/main` f6d908d44)

Instrument: a C program against the C ABI, in the consumer's order
(`wz_dissect_pcap_replay(WZ_DISSECT_LIMITS_NONE)`, drain, `fields_since_window`
of 8192 until the cursor stops, `census("")`), printing RSS and the heap in use
(`mallinfo2`) after each step. Input: the consumer's own generator, payload
64 B, 16 TCP flows, so every row is one transport message on a stream.

| rows | file | heap after replay | multiple | added by fields windows | added by census |
|---|---|---|---|---|---|
| 409,064 | 60.9 MiB | 328 MiB | 5.4x | 20 MiB | 0.1 MiB |
| 1,386,564 | 206 MiB | 1,287 MiB | 6.2x | 67 MiB | 0.1 MiB |

The handle reaches its size during replay; the doors read later add little.
Where the replay heap goes (massif, 40,000 packets):

| share | holder |
|---|---|
| 62% | the per-flow `VecDeque<PassiveFrame>` buffers |
| 8% | the reassembled TCP stream (`StreamAssembler::absorb`) |
| 7% | a per-segment map grown in the same assembler |
| 7% | heap owned by decoded frames (`parse_unit`) |

`size_of::<PassiveFrame>()` is 424 B (`InboundFrame` 104, `Carried` 96,
`Option<StreamResync>` 48, the rest offsets, lengths and two timestamps). A
`VecDeque` doubles, so up to half of each buffer is capacity no row uses; most
of it is never touched and shows in the heap more than in RSS.

## 3. Why the present shape holds it

Every row the handle has produced is kept as the decoded `PassiveFrame` that
`PassiveSession::decode_framing_unit` returned
(`crates/wz-session-core/src/passive.rs` @ `fn decode_framing_unit(`), in the
list's `held: VecDeque<PassiveFrame>`
(`crates/wz-session-core/src/passive_messages.rs` @ `pub struct MessageList {`).
Every reader of a row (drain, the fields walk, census, selection,
`message_bytes`, `reassembled_bytes`) reads that held value. A stream's bytes
are kept a second time, reassembled, because `message_bytes` answers from them
(`crates/wz-capture/src/lib.rs` @ `pub fn message_bytes<'a>(`).

So the cost per row is the decoded value, whatever the row's size on the wire.
A 64 B publication costs 424 B inline before anything it owns. No ceiling can
change that without dropping rows, and dropping rows is what a viewer of a
whole file cannot accept: `frames_total` and `frames_per_flow` exist and are
the wrong door for this consumer.

## 4. Decision: two passes, a row index, and re-dissection on demand

This is the structure of the reference dissector, Wireshark's epan. The first
pass reads the capture once, in order, and keeps one small `frame_data` per
frame (its file offset, length, timestamp and flags) plus, per frame, only the
results of stateful analysis that a later read cannot recompute alone (the
per-packet protocol data a dissector stores on its first visit). Any later
look at a frame seeks to its bytes and dissects it again, statelessly, with
that stored data. Memory is the index plus the stored results; the bytes stay
in the file.

The decisions below apply that structure to this handle. Each names what it
replaces.

### D1. One byte source, and the handle never keeps a second copy

The handle reads bytes through one source: the packet bytes it was given. For
a live handle (`push`, `follow`) the source is a handle-owned arena of packet
records, appended in chunks and released from the front under the same
ceilings that release rows. For a replayed file the source is the container
itself: owned by the handle as one copy by default, or LENT by the caller
through a new door whose contract is that the buffer outlives the handle (so
a memory-mapped file costs no copy at all).

It replaces the reassembled stream copy. A stream is re-gathered on demand
from a per-direction segment map (stream offset to packet index and offset in
the packet, one entry per segment). The doors that already take the capture
(`fields_where`, `fields_since`) keep their signature; the bytes they are
handed must be the source's bytes, which is what their contracts already say.

Why: `message_bytes`, census and selection take no capture argument, so the
handle must reach bytes on its own; a reference into the file is the only
way to do that without a copy, and an owned copy is the safe default. Keeping
the reassembled stream as well would be a second copy of the same bytes.

### D2. A row is a fixed-size index entry

A row is the record drain already hands out (`WzDissectRecord`, 56 B in the
ABI) plus its row sequence number: the packet coordinate, the stream anchor,
the unit length and the message's place in it, the timestamp, the list and
flow ids, direction, kind and flags. Drain answers from the index alone and
decodes nothing.

The index is stored in fixed-size chunks (an append-only list of chunks of a
power-of-two row count, released from the front). There is no doubling slack
and no reallocation that copies every row the handle holds.

Why: the record is already the row's identity across the C boundary; making
the stored row the same value removes a translation and makes "drain is
cheap" structural. A chunked store is the textbook structure for an unbounded
log with front truncation.

### D3. What a re-read cannot recompute is stored once, sparsely

`walk_framing_unit` produces each frame from the unit's bytes and the
session's state. Read against that function, the state splits in two:

- **Recomputable from the unit's bytes and the flow context:** the parsed
  `InboundFrame`, `unit_offset`, `batch_index`, `batch_offset`, the reserved
  header bits, the undefined mandatory extension, the lz4 body, the carried
  batch of a `Frame`, `wire_end`.
- **Not recomputable from one unit:** the `FlowContext` at the row, the SN
  verdict (it depends on the previous SN of the same conduit), the outcome of
  a fragment chain (it depends on the fragments before it), a stream resync,
  `inadmissible_on_link`, `unit_read_whole`, and the per-session counters.

The flow context changes only at handshake messages, so it is stored as a
per-flow list of change points, not per row. An SN verdict is stored only
when it is not `Continuous`. A chain outcome and a resync are stored for the
rows that have one. These side tables are keyed by row sequence number.

Why: this is the per-packet data of the reference design, cut to what the
walk actually depends on. Storing the exceptional cases only keeps the common
row at the size of its index entry.

### D4. One pure re-decoder, held equal to the first pass by a gate

`decode_row(source, entry, context, side facts) -> PassiveFrame` rebuilds the
row the first pass produced. The first pass and the re-decoder share the
parse: `walk_framing_unit` is split into a pure part (bytes and context in,
frames out) and the stateful judgments around it, and both passes call the
same pure part.

A differential gate decodes every row of the fixture captures both ways and
requires them equal, field by field. It is built before anything stops
keeping rows, because every later step depends on that equality.

### D5. A bounded cache of decoded rows

Recently decoded rows are kept in a cache with a row ceiling, so the window a
viewer shows and repeated field windows over the same rows do not decode twice.
The ceiling is the caller's (a door), with a default; it bounds memory, not
correctness.

### D6. Folds read re-decoded rows

Census, the fields walk and selection iterate rows through the re-decoder. Their
resumable memories already exist (`CensusMemory`, `FieldsMemory`,
`SelectionMemories`), so a walk from the start happens only where it happens
today.

### D7. A memory gate

A gate opens the generator's capture through the C ABI and fails when the
handle's heap per row, after replay, exceeds a ceiling set from the measured
value with stated slack. It is what keeps the structure from drifting back.

## 5. Expected cost, not yet measured

Per row: the index entry (about 64 B), one segment-map entry per packet (about
16 B), and the sparse side tables. For the capture in section 2 (about 156 B per
row on disk), that is about 0.5x the file with a lent buffer and about 1.5x with
an owned copy, against 5.4x to 6.2x today. The price is CPU: a row read again is
decoded again, about 1 microsecond per row on the consumer's bench, so a full
re-walk of 1.39M rows costs about 1.5 s more than it does now.

## 6. Order of work

1. Split `walk_framing_unit` into the pure parse and the stateful judgments;
   build the differential gate (D4). No memory changes yet.
2. Chunked row storage (D2's store) with the rows unchanged: removes the
   doubling slack and the large copies.
3. Segment map and byte source (D1): the reassembled stream copy goes.
4. Index rows, side tables, re-decoder in the read path, cache (D2, D3, D5, D6).
5. The memory gate (D7) and the lent-buffer door.

Each step lands on its own and keeps every live door's answer unchanged.

## 7. Open

- The lent-buffer door's exact shape (a flag on replay or a new function) is
  decided in step 5.
- QUIC streams and the serial line produce rows outside the TCP segment map;
  their byte source is decided when step 3 reaches them.
- The cache default is set from a measurement in step 4.
