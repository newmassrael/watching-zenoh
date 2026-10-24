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

### D5. One walk per call, and no cache between calls

Decided after step 4b, on its measurement (owner, 2026-10-24: the long-term
correct structure, cost not counted). Each reader that reads the same messages
in the same order within one call reads them from ONE walk, and nothing decoded
outlives the call that decoded it.

- The repeated reads 4b measured are all SCANS: the exchange pairing, the
  declaration absorption and the census planes each walk every new message in
  capture order. A bounded cache of decoded rows gets no hit on a scan longer
  than it is, whatever its policy (the sequential flooding a database buffer
  pool meets under LRU or CLOCK), and one long enough to hold the scan holds the
  capture decoded, which is what this design removes. The textbook answer to
  repeated scans is a shared scan, which is the reference dissector's tap
  model: one pass, every listener fed.
- Shared where the readers already agree: the census planes are one fold
  (`CensusFold`), and the field document's declaration absorption rides on the
  exchange pairing's walk whenever that walk takes exactly the messages it wants
  (`ordered_fold::Share`). Each reader keeps its own rule for when it continues
  and when it begins again; a walk is shared only when both rules pick the same
  messages, and otherwise each walks, as before.
- Inside one document the renderer hands the rows its first pass decoded to its
  second, up to a window (`ROWS_HANDED_ON`).
- No cache between calls. A row is immutable, so a row read again is always the
  row it was; a lookup by position decodes one unit; and a cache shared between
  calls would put a lock in a `no_std` store, take `Sync` from `Dissection`, and
  need a separate form for targets without atomics, for no hit on a scan.

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
   Landed: `walk_unit` is the one walk, a `UnitJudge` answers what a unit's
   bytes cannot (the session on the first reading, `UnitFacts` on a second),
   and `redecode_unit` is the second reading. The gate
   (`crates/wz-capture/src/redecode_gate.rs`) reads every stream and
   datagram unit of the tracked captures and of built captures for batches,
   gaps, duplicates, resynchronisation, compression and fragment chains
   again, and compares each record. Units sent in packet space over a stream
   (WebSocket) and QUIC payloads are counted as out of its reach; step 3
   gives them a byte source.
2. Chunked row storage (D2's store) with the rows unchanged: removes the
   doubling slack and the large copies.
   Landed: `MessageList` keeps its rows in a `ChunkLog` (1024-row chunks, each
   one run) and hands readers rows (`len`, `get`, `iter`, `rows_from`,
   indexing) instead of a slice, so no reader depends on how rows are stored
   any more; `Dissection::frame_lists`, `message_lists`, `serial_frames` and
   the two plaintext sink records changed type accordingly. Measured with the
   section 2 instrument: heap after census 348 to 303 MiB (409,064 rows) and
   1,355 to 1,075 MiB (1,386,564 rows); peak RSS unchanged, because the slack
   removed was capacity no page of had been touched; time within noise of the
   baseline (median of six alternating pairs). The resident cost is the row
   itself, which steps 3 and 4 remove.
3. Segment map and byte source (D1): the reassembled stream copy goes.
4. Index rows, side tables, re-decoder in the read path, cache (D2, D3, D5, D6).
5. The memory gate (D7) and the lent-buffer door.

Each step lands on its own and keeps every live door's answer unchanged.

Reordered after step 2 (2026-10-24), on what the code showed. The folds that
walk a capture in packet order take one `Vec` of references to EVERY row and
sort it (`Dissection::message_frames_in_capture_order`, `OrderedFrames`), and
eight planes consume it. A row decoded on demand cannot be borrowed that way:
the walk would decode every row at once, and the peak would be what is held
today. And step 4 does not need step 3 first: a stream row's bytes are still
in the reassembled stream, which is what the step 1 gate already reads them
from. So the order is now:

- 4a. A row is handed out as `Row` (a reference that either borrows a held
  frame or owns one decoded for the reader), and the capture-order walk sorts
  KEYS (packet, list, position) and resolves each row inside its loop. No
  behaviour change; every plane stops keeping references to rows.
  Landed: `passive_messages::Row` and `RowIter`; `MessageList::row` replaces
  indexing; `Dissection::message_frames_in_capture_order` and
  `capture_order_since` return `CaptureOrder` (sorted keys, the flow held per
  list); `MessageBytes::Retained` and the live handle's
  `ReassembledBytes::Joined` carry `Cow`, owned where the bytes live in the
  decoded frame. Every fields document and the census of the consumer
  generator's 40k and 409k captures hash the same before and after, with the
  same walk work.
- 4b. Stream rows become index entries with their sparse facts, decoded again
  on demand under a bounded cache, their bytes read from the reassembled stream.
  This is the step where resident memory falls.
  Landed: a list reads through `Messages` (the list and a `UnitBytes` source,
  the flow's reassembled streams), keeps a TCP flow's own units as 40-byte
  entries (D2) with SN verdicts other than continuous, fragment fates and
  resynchronisations kept apart by produced-index and the context once per
  change (D3), and keeps whole what it cannot read again (a datagram, a
  WebSocket message, a decrypted record, a unit whose bytes a byte ceiling
  released before it completed, and a row whose bytes are about to be released,
  which `keep_whole_before` turns whole first). Every row's `RowHead` (the
  record drain hands out, kind included) is answered without decoding, so drain,
  the capture-order keys, the oldest-message probes and the node census decode
  nothing but the Init and Join rows. The four selector-narrowed census planes
  are one fold over one walk (`CensusFold`, D6). The gate holds a dissection
  that keeps entries equal to one that keeps every message whole, row for row
  and head for head, including under message and byte ceilings, and was
  mutation-checked three ways. Measured with the section 2 instrument (median
  of six alternating runs at 409,064 rows, three at 1,386,564): peak RSS 404 to
  177 MB and 1,364 to 590 MB; heap after census 348 to 117 MiB and 1,355 to 444
  MiB; replay 308 to 257 ms and 1,047 to 874 ms; census 210 to 166 ms and 803 to
  551 ms; fields windows 2,185 to 2,590 ms (+19%) and 7,699 to 9,368 ms (+22%),
  the price section 5 states, and what D5 then took to +12% and +11% (section 7).
- 3. The byte source, and the reassembled stream copy goes.
- 4c. Datagram, serial and QUIC rows become index entries too, their bytes read
  from the source.
- 5. The memory gate and the lent-buffer door.

## 7. Open

- The lent-buffer door's exact shape (a flag on replay or a new function) is
  decided in step 5.
- QUIC streams and the serial line produce rows outside the TCP segment map;
  their byte source is decided when step 3 reaches them.
- Closed: D5 is decided (section 4). After the declaration absorption rode on
  the pairing's walk, a capture read the way the consumer reads it decodes each
  row three times: the census walk, the field document's shared walk and the
  renderer. Measured with the section 2 instrument against 270780967 (median of
  six at 409,064 rows, three at 1,386,564): fields windows 2,169 to 2,421 ms
  (+12%) and 7,876 to 8,772 ms (+11%), census 207 to 155 ms and 795 to 562 ms,
  peak RSS unchanged at 177 and 590 MB.
