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

Corrected in step 3 (2026-10-24), on what the bytes are. A stream's payload is
the smallest form of its bytes a handle can OWN: a packet arena holds the link,
IP and TCP headers too, so replacing the reassembled stream with an owned arena
of packets would grow the handle, not shrink it. What the handle owns stays the
payload stream; what changes is how it is held and what replaces it:

- the stream is held as kept payload bytes behind a compact run map (one
  32-byte run per segment, in 1024-run chunks), and is read by range
  (`StreamAssembler::bytes(from, to, container)`), borrowed when one place holds
  the range and gathered otherwise;
- a run whose payload sits in a capture container the caller LENDS
  (`Dissection::follow_lent`, `LentCapture`; the C doors
  `wz_dissect_pcap_replay_lent` and `wz_dissect_live_follow_lent`) remembers
  where it sits and keeps no copy. A TCP segment borrows its payload from its
  packet, so that place is where the slice is.

So the second copy goes exactly where the caller keeps the first: a replayed
file the caller holds anyway. A handle handed bytes it cannot keep a reference
to (`push`, the copying replay and follow doors) still owns the payload stream.

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

### D7. A handle reports what it holds, and a gate holds the report to the allocator

A gate that reads one total from the allocator can say that a handle grew and
not which structure did, and a consumer that budgets by what a handle holds has
nothing to read. So the structure is three things, each answering a different
question.

- THE REPORT. A handle says what it holds that follows its row count, by
  structure: `wz_dissect_live_memory`, the `memory` document. Every value is a
  number of bytes allocated, in groups named for the structure that holds them
  (the lists' entries, their logged bytes, the facts few rows have, the TCP run
  maps, what the census and the field walk keep for the next call). A buffer is
  counted by its capacity, which is exact, and an ordered map is a
  `SortedChunks`, whose chunks are buffers, so every figure in it is a capacity
  times an element and no figure is a model. (An ordered map from the standard
  library would be a model, because its node holds seven entries of eleven
  slots and a header, and a model a few percent off cannot tell a structure that
  grew from a model that is wrong; the report holds none.) A new structure is a
  new key and not a new symbol, which is why it is a document and not a fixed
  record. The report
  names the structures that follow rows; what is fixed, or follows the count of
  distinct things, is not in it, and it says so (`scope`).
- THE ORACLE. The allocator is the one reading that is not the report, so the
  gate compares the two, to the byte: the bytes a dissection holds more of at
  twice the rows are the bytes it reports holding more of, and there is no
  tolerance. A report that omits a structure growing with the rows is a
  difference there, and the failure prints which allocation sizes grew and which
  shrank between the two captures (a sixteenth of a power of two from 4 KiB up):
  a size names its structure (a node of one map, a record's ciphertext of one
  length, a buffer that doubled), which is how each unreported structure of this
  step was found. The last two were a chunk list's own capacity (the unit log
  counted its buffers and not the list holding them) and the session's stream
  buffer, which a decrypted flow grows to its whole plaintext and which then kept
  that capacity after every frame was read out of it; it is counted now and
  gives back what it does not hold, as the stream's kept bytes do.
- THE POPULATION. The matrix reads every kind of message list (TCP, UDP,
  serial, WebSocket, TLS, scouting, both QUIC kinds, fragment chains), handed
  and lent where the door differs, and the case list is derived: an exhaustive
  `match` over `MessageListOrigin` fails to compile when a kind has no case.
  Two sizes are read and the slope between them is judged, so what is fixed is
  not charged to a row. Each kind has a ceiling (the measured value plus 10%),
  and the report of every kind equals the allocator's figure.

What a row costs is read off the kinds, not argued: 49 to 130 bytes after the
replay on the two transports the C gate reads (UDP and TCP, handed and lent),
and 41 to 181 across every kind after every read a consumer makes. The cost per
row of one kind does not change with the size of the capture. An encrypted
flow's kept records are views of its stream (an offset and a length, 32 bytes
each, at most 4096 a direction), so the ciphertext they cover is held once, by
the stream, and the stream's byte ceiling stops at the oldest kept record.

### D8. Every list reads its units from a byte source; a datagram list's is a unit log

Decided before step 4c (owner, 2026-10-24: the long-term correct structure,
cost not counted). After step 3 only a TCP flow's messages are index entries;
every other list keeps each message decoded, because its units' bytes were in
no place the list could read them again. D8 gives each of them that place.

- A row names its bytes by a LOCATOR in its list's source, kept apart from its
  anchor. A stream row's locator is a range of its direction's stream, which is
  where its anchor already points. A datagram row's anchor is the index of the
  packet that carried it, a coordinate no bytes can be read by, so its locator
  is the place its unit was logged. One row layout carries both, with a flag
  for which space, and a row kept whole is a flag on the same layout rather
  than an enum around it.
- A list whose units arrive whole (a UDP or raweth datagram, a serial frame, a
  recovered QUIC datagram, a WebSocket message) reads them from a UNIT LOG:
  the units' payloads in arrival order, each logged once. A unit whose payload
  sits in a container the caller lends is logged by its place there and keeps
  no copy, as a TCP run is. This is the reference design's frame table (each
  frame's file offset and length), holding the payload rather than the frame
  for the reason D1's correction gives.
- A discard that takes the last row of a logged unit releases that unit's
  bytes in the same call, so a list and its log cannot come apart and no
  holder has to remember to do it.
- A stream a layer below produced (a recovered QUIC stream, TLS plaintext) is
  in no container: what the handle keeps of it is the plaintext stream, behind
  the same run map a TCP stream uses, which is the smallest form of it the
  handle can own. The reference dissector keeps decrypted data for the same
  reason (it stores the plaintext of a record on its first visit).
- The per-message origins the serial line keeps beside its rows, and the
  scouting rows, follow the same rule: what one unit's bytes decide is read
  again from the log, and only what they cannot decide is stored.

Why: the alternative, a second arena of whole packets for these lists, is the
form D1's correction already rejected (it holds headers too), and a decoded
message per row is what this design removes. The locator is the one field the
datagram space lacks, and making it explicit lets one re-decoder and one gate
serve every list.

### D9. A row's field document is read from the row and from tables by position

Decided after step 4c's first landing (owner, 2026-10-24: the long-term correct
structure, cost not counted), on the consumer's measurement: a window of one
row costs about 160 ms at 409,064 rows wherever it stands, against a 100 ms
budget for showing the row a viewer picked.

Measured (callgrind, three one-row windows at 40,064 rows): the cost is the
fold of the rows before the window, not the row. A window behind the walk's
position begins the walk again and absorbs every declaration of the capture
(40%); a window ahead of it walks every row between the two to carry the chain
fold, the request index and the running packet (33%); the capture-order keys of
the whole capture are sorted on the way (9%). Writing the row is a small part.

The reference design has no such fold: its first pass stores, per frame, what
the frame's stateful analysis concluded, and a later look at one frame dissects
that frame with the stored data. D9 applies that to the field document:

- Everything a row's document says that its unit's bytes do not is a FACT of
  the row, decided once on the first pass and kept with its entry (D3's side
  tables): the identity of the fragment chain a row touched, and the row of the
  request a final closes.
- What depends on the whole capture and not on a window is a TABLE read by
  position: the keyexpr bindings, each stamped with the packet it went past at
  (already position-independent since R2513), and the order of rows by packet.
  It is extended as the capture grows and never rebuilt because a window moved.
- What depends on the caller's declaration text (an end-to-end verdict, whose
  counters run over the frames before a row) is a judgment kept per text for
  every row it has judged, with a frontier that only moves forward: a window
  behind the frontier reads it, and one ahead of it walks only from the
  frontier.
- A window finds its first row by its sequence number and reads its own rows
  and no others.

Why not checkpoints of the walk every K rows: the walk's state includes tables
that grow with the capture (the request index, the pairing), so a snapshot per
K rows copies them each time, or needs persistent maps to share them; and a
checkpoint still refolds up to K rows per look. Facts on the row are what the
reference design keeps, cost one look per row, and add nothing to a row that
has none (most rows touch no chain and close no request).

### D10. What a row still costs, and which of it is a fact and which a habit

A consumer measured the handle at pin 0ec3e2ff7 (release build, heap peak,
16 TCP flows, 60,000 and 240,000 rows, only what follows the row count) and
found about 92 bytes a row in three places: 46 in the index entries, 38 in the
TCP run map, 8 in the field walk's digests. They are three report keys, and the
consumer's name for the first was one off: the entries are `lists.rows`
(`ChunkLog<UnitRow>`, 48 B), not `lists.unit_log`, which is the datagram units'
bytes and is zero for TCP; the run map is `streams.runs` (`ChunkLog<Run>`,
40 B a payload segment); the digests are `fields.row_digests` (8 B a row).

What each holds, and what of it a later reader could not recompute:

- An entry holds eleven values, and most of them follow from the one before.
  The anchors of one direction rise, the capture instants rise, the body of a
  stream unit starts a prefix past its anchor, `wire_len` equals `unit_len`
  unless the unit was an lz4 batch, and `unit_offset` and `batch_index` are zero
  unless it was. What is not recomputable is the position of each row's unit
  (a 64-bit offset or place, but only as a distance from where the rows near it
  lie), its capture instant (exact, to the nanosecond), its length and its
  context.
- A run holds five words and a flag. `stream_offset` is the end of the run
  before it (the stream is contiguous, a forced gap included), so it is a
  prefix sum, and a run's length is the next run's offset. The packet index,
  the instant and the place each rise from one run to the next.
- A digest is the least that says WHICH row moved, which is what `revised`
  promises (the column's own module says why a block digest is not enough). It
  is not smaller than 64 bits without a row reported unchanged that moved, so
  its cost is lowered by not holding it: a consumer that does not ask for
  `revised` has no use for it.

Decision. The first two are stored by frame of reference, the textbook
column-store layout for a sorted integer log: a chunk of at most 1024 items
carries a base for each of its columns and an item carries its columns as 32-bit
distances from that base. An item that does not fit (a distance over 2^32, or a
value below the base) begins a new chunk, so the encoding has no escape code,
no exception table to search, and no value it cannot hold, and a chunk is
shorter only where the data is unlike anything a capture does. The capture
instant is the one column kept whole: it moves a billion a second, so as a
distance it would end a chunk every fourth row of a flow that sends one segment
a second (a keepalive does), and the first version of the run map, which rebased
it, held 87 bytes a row on the matrix's fixture, whose packets are a second
apart, where 70 were expected. The run map is 20 bytes a run (three distances
and the instant), from 40. Chunks are found
by bisecting their first positions, so a position is still found without
reading the items before it, and a release from the front is still free. The
sparse columns (`segment_offset`, `unit_offset`, `batch_index`, a `wire_len`
unlike the unit's) are the existing sparse tables of the index, keyed by row.
Every figure stays an allocation count: a chunk's capacity times its item size,
so the report remains exact and the gate that holds it to the allocator holds
the new structure with no new case. The digests get a choice and a door, step
by step below.

Order: (1) the log itself, in `wz-session-core`, with the run map on it, which
is private to the TCP assembler and so a change of one module; (2) the index
entry on it; (3) the digests' door, which changes the C ABI (a revision, and
the consumer's pin). Each lowers the figure that its report key names, and each
is judged at 60,000 and 240,000 rows, because a value that falls at one size
only is a fixed cost that fell.

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
  Landed, as D1 now reads: the run map is compact and chunked, the stream is
  read by range, and a lent container replaces the copy of every TCP payload in
  it (ABI 50). A `Segment` borrows its payload from its packet, which removed a
  copy on both paths and the second header walk the lent path first used. The
  gate holds a dissection lent a capture equal to one handed the same bytes
  (every list row for row and head for head, every message's bytes, the drops
  and the census of what was discarded), read whole, grown through cuts into
  containers at new addresses, and under message and byte ceilings, and checks
  that the lent one kept no payload while the handed one kept every retained
  byte; a C consumer drives both doors, the second over a container that moves
  and whose first home is overwritten and freed. Measured with the section 2
  instrument, handed against lent on the same build (three runs each, every
  run equal): peak RSS 176 to 141 MB (409,064 rows, file 61 MB) and 577 to 461
  MB (1,386,564 rows, file 206 MB), the handle's heap after replay 88.8 to 34.7
  MiB and 333.4 to 117.4 MiB, so peak RSS, the file included, is 2.3x and 2.2x
  the file, against 6.6x at 270780967. Instructions at 40,064 rows (replay,
  drain, census): handed 612.9 to 604.5 M, lent 632.9 to 603.0 M once the
  segment borrowed its payload.
- 4c. Every other list's rows become index entries too, their bytes read from
  the source (D8). Four landings, each with the gate extended to the lists it
  moves: (1) the row layout with its locator, the unit log, and the UDP and
  raweth datagram lists, handed and lent; (2) the serial line and its origins;
  (3) recovered QUIC datagrams and streams; (4) WebSocket messages, TLS
  plaintext and the scouting rows.
  Landed (1): one 48-byte row layout (the step-4b entry and its enum tag took
  48 bytes too) with a locator and a held flag; the unit log is a chunked byte
  log in the message list (chunks double to 64 KiB and are never reallocated,
  so a unit reads as one slice), and a discard that takes a unit's last row
  releases its bytes; a `Datagram` borrows its payload, so a lent one is logged
  by its place. The gate holds every datagram list equal to the reading that
  kept it whole, under per-flow and total message ceilings and lent against
  handed; a list's own tests read every row after every discard, which caught a
  release made one row early. Measured with the section 2 instrument on a UDP
  capture of the same generator (409,064 rows, file 55.4 MiB, three runs each,
  every run equal): the handle's heap after replay 204.9 to 52.1 MiB handed and
  19.1 MiB lent (the entries alone), peak RSS 307 to 150 MB handed and 117 MB
  lent; replay 180 to 137 ms, census 57 to about 145 ms and fields windows about
  2,030 to 2,300 ms (+13%), the price of reading rows again.
  Landed (2): the serial line's messages are entries read again from each
  frame's payload, logged once per frame; beside each message the line keeps
  the frame's envelope (interface and control byte, `serial::SerialOrigin` with
  the packet from the row's anchor) instead of a copy of the frame per message,
  and a message's bytes are read from the log (`Messages::unit_bytes`). The gate
  reads a two-wire line of frames batching one to three messages against the
  reading that kept them whole, row, head and origin, and every message's bytes
  against the payload the frame was built from. Not measured: no serial capture
  of the consumer's size exists.
  Landed (3), its datagram half: the recovered RFC 9221 datagrams' plaintext,
  which exists only in the call that hands it in, is logged by their list, and
  the byte door hands back a recovered message's bytes from that log (its
  packet holds ciphertext, so the caller does not hold them). A cleartext
  datagram message is still named as the caller's packet, as the C door's
  contract says: the list's copy is its means of reading, not a second home of
  the bytes. The gate feeds batching plaintexts
  in both directions and holds the list to the reading that kept it whole and
  every message's bytes to the plaintext.
  Landed (3), its stream half: a recovered QUIC stream keeps each direction's
  plaintext from the first byte a held message is read from, its messages are
  entries read again from it, a frame ceiling's discard lets the plaintext before
  the oldest held message go, and the byte door hands its messages' bytes back
  (the structural `RecoveredPlaintextNotRetained` answer went with the reason for
  it). The plaintext sink was handed rows rewritten into the offer's space for
  the call and restored after it, which only a row kept whole allows; it is now
  handed the stream offset of the offer's first byte (`DecryptedStream::base`,
  `plaintext_offset`) and its consumers slice at the difference. The gate feeds
  both directions in offers of odd lengths that split units, plain and under a
  frame ceiling, against the reading that kept every message whole, every
  message's bytes against the stream, and the plaintext kept against what was
  fed; a release four bytes early fails it.
  Landed (4), its WebSocket part: a ws message's payload is unmasked and joined
  out of its frames by the deframer and stands nowhere in the TCP stream, so the
  flow's list logs it as a datagram list logs a unit. Its rows are anchored at
  the stream offset of the first frame's header and end where the last frame
  does, an end the payload cannot say; the list keeps that end once per unit
  beside the entries (a flag on the row, a table by locator, released with the
  unit's last row), since the 48-byte row has no field to spare. The byte door
  answered a ws message with a slice of the TCP stream at its anchor, which is
  the frame header and a masked prefix; it now reads the logged payload, and
  `FlowDissection::message_bytes` takes the row, whose place names that payload,
  instead of a frame. The gate reads a capture with a batch in one message, a
  masked message, a frame split across two segments and a message fragmented
  into two frames, plain, under the stream ceilings and lent, against the
  reading that kept every message whole, and every message's bytes against its
  payload; dropping the end on reading again fails it, and so does releasing it
  at a unit's first row.
  Landed (4), its TLS part: a decrypted flow keeps the plaintext each direction
  opened into (moved out of the pass that built it, not copied) and its
  messages are entries read again from it. A unit is framed in the plaintext
  and stated where the record carrying its first byte begins and the record
  carrying its last byte ends; the pass rewrote decoded frames into those
  coordinates, which only a message kept whole allows, and now RESTATES the
  rows (`MessageList::restate_from`): an entry keeps its locator in the
  plaintext, takes the record's offset as its anchor, and keeps its end beside
  the entries as a WebSocket unit does (an end-table row with no entry has
  none). The restatement is by each row's own direction; the rewrite applied
  the fed direction's records to every row the call added, including rows of
  the other direction a context released. A trim of the TCP stream keeps
  nothing whole for such a flow, and a message ceiling's release lets the
  plaintext before the oldest held message go, found by the list
  (`oldest_source_offset`) because a restated anchor is in the other space. The
  byte door answered a decrypted message with a slice of ciphertext at the
  record; it reads the plaintext now. The analyser's own copy of the byte door
  sliced a ws message's stream at its anchor too, and gave no sample from a ws
  capture; it calls `FlowDissection::message_bytes` now. The gate decrypts a
  capture whose units cross record boundaries both ways and batch messages,
  plain and under a capture-wide ceiling that discards the decrypted rows,
  against the reading that kept every message whole, every message's bytes
  against its unit's plaintext, and the plaintext kept under the ceiling; a
  restatement that does not flag the stated end fails it, and so does a release
  one byte early.
  Landed (4), its scouting part, which closes 4c: the scouting list kept every
  SCOUT and HELLO decoded, a slice behind `Deref`. It now keeps each payload in a
  unit log (a copy, or its place in a lent container) beside a row of what the
  payload cannot say (direction, packet, instant), and a reader decodes it
  again (`Scoutings`, from `DatagramDissection::scouting`); a discard lets the
  copy go, and the ceilings order the lists by the row's packet without
  decoding. The unit log is session-core's one (`byte_log::UnitLog`), which the
  message lists now use too, so the placement in a lent container is written
  once. The gate reads a capture of SCOUTs, HELLOs answering them and SCOUTs
  whose datagram holds more than the message, handed and lent, plain and under
  message ceilings, against decoding each packet's payload; a discard that keeps
  the copy fails it, and so does a lent payload copied.
- 5. The memory gate (D7).
  Landed (5): the report, the oracle and the matrix, and what they found.
  Four structures cost a row more than its entry and were not reported, and each
  was shrunk where it was found and not argued down. What the selector said of
  each row (about 100 bytes a row as a map entry with its own vector) is a
  coordinate and the number of an interned answer pattern, 12 bytes
  (`verdict_column`). The field walk's digest of each row it wrote (about 49
  bytes, a map entry) is one word at the row's number (`digest_column`), and the
  selection door's word per row (about 40) is a nibble (`word_column`). A frame's
  sequence verdict, which every row of a capture that began after the handshake
  has (there is no ring to measure a step against), was a map entry at about 180
  bytes and is a class in the row's flags; only a `Gap`, which has a number,
  keeps one. Last, the facts few rows have and the chain facts were B-tree maps,
  which hold seven entries of an eleven-slot node and a header around each node:
  they are `SortedChunks` now, sorted chunks of at most 64 entries with a
  bisected key (a run of ascending keys fills its chunks, and the front leaves a
  chunk at a time, as `ChunkLog` does for the rows), and a fragment's fate is a
  class there with the joined message in a log of its own, because only that fate
  owns a buffer. The selector's overlay map and the verdict column's delta are
  the same structure, so no figure of the report is a model of a standard-library
  map. A fragment row went from 323 and 366 bytes to 135 and 179. Every
  redecode gate passes unchanged over all of it, and the report equals the
  allocator, to the byte, for every kind and for the C ABI's handle.
  The TLS flow's kept encrypted records were a second copy of the ciphertext the
  TCP stream holds; they are views now. `EncryptedRecord` keeps `stream_offset`
  and `len`, `RecordOpener::open` is handed the bytes beside the record (read
  from the assembler, or the container a lent flow reads from), and
  `FlowDissection::encrypted_record_bytes` reads one for a caller that holds the
  snapshot. The stream's trim stops at the oldest kept record, so what a decryptor
  can open is exactly what it could before (the last 4096 records a direction) and
  the ciphertext is held once. This surfaced a wrong coordinate: a record after a
  hole carried its offset with the hole added, a position the contiguous stream
  does not have, so its instant and packet were looked up where something else
  stood; the offset is the stream's now and the hole is `lost_before`. A TLS row
  went from 144.7 to 128.7 bytes.
  The sweep of a unit's size found the TCP assembler's kept bytes holding 1.37
  times the stream at 4 KiB segments (one buffer that doubles: up to half unused,
  every byte copied at each doubling, and the front released by moving the rest).
  They are a `ByteLog` now, the chunked log the datagram units already used: a
  segment is one run and lies in one chunk, so a read is a slice, nothing is
  copied after it is logged, and a trim gives back whole chunks. A TCP row at 4 KiB
  went from 5710 to 4462 bytes (1.07 times the stream), and a trimmed stream
  keeps at most the chunk its position falls in.
  The same sweep found a WebSocket message's payload logged as a copy on both
  doors, though a message that is one unmasked frame has its payload in the
  stream. Such a unit is a `LogPlace::Stream` now: the list keeps where it stands
  (a locator with a bit of its own) and reads it through its source as it does a
  streamed unit, and a byte ceiling that releases the stream under it keeps the
  message whole first, as for a TCP row (its bytes then answer that they are
  gone, where the log's copy used to outlive the stream). A masked frame (every
  client frame) is the same with its key: the four bytes that end the frame's
  header stand just before the payload, so the place is `LogPlace::StreamMasked`,
  the dependence reaches back over the key, and the list unmasks as it reads (a
  copy that lives for the read, not for the row). A message joined out of
  fragments is the payloads of its frames one after another, so its place is
  `LogPlace::Frames` and the index keeps the stretches (a `StreamSpan` of sixteen
  bytes per frame, once for the unit, counted under `sparse`, with each frame's
  own mask flag); the list joins them as it reads, the dependence is the first
  stretch's, and the unit's last row lets the stretches go with it. Control frames
  between the fragments are none of the stretches. So no WebSocket flow keeps a
  copy of a payload. A row on the lent door costs the same at 16 and 4096 bytes,
  masked or not (139.4 bytes), and 285.0 bytes for a message of two frames (its
  second frame's run in the stream map is the difference), and the matrix measures
  all three kinds. The deframer's offsets were the stream's own
  across a hole (the TLS keeper's were not, above), which is what lets a place in
  the stream be trusted.
- 6. Random access to a row's field document (D9), taken before 4c's remaining
  landings because it is what the consumer's budget waits on: (a) the tables
  that do not depend on a window survive a walk that begins again; (b) the
  chain identity and the request a final closes become row facts; (c) a window
  finds its first row by number and walks only its own rows; (d) end-to-end
  judgments kept per declaration text behind a forward frontier; with a gate
  that every one-row window, asked in any order, writes the row the whole
  document writes, and a work counter that a one-row window reads one unit.
  Landed (a) to (c): the keyexpr table and the request index are one set of
  capture tables (`CaptureTables`), filled from every message once (by the
  exchange pairing's walk where it takes the same messages) and kept while the
  capture is a prefix-extension; the container's own walk is kept while the
  bytes are its container; a list folds the chain identity of each row as it is
  appended (`MessageList::chain_of`) and a row knows its produced-index
  (`Row::produced`); a since-window without an end-to-end rule, a revised row or
  a cap finds its first row by halving on the sequence numbers and walks only
  its own, with the packet a skipped row would have carried read back from the
  rows before it. The gate picks every row, alternating between the two ends,
  in windows of one and three rows, on interleaved flows (plain, under a byte
  ceiling, under a frame ceiling), an exchange, and stream and datagram fragment
  chains, against the document from cursor 0, and holds each window to at most
  its own rows visited. The chain identity and the request a final names are
  held by the tests that already name them (a shifted identity and an empty
  request index each fail three and one of them); the packet read back is held
  by a test that compares it with the walk's at every position under byte
  ceilings, since no fixture's document shows it. Measured with the pick probe
  at 409,064 rows, cursor at the end: one-row windows at the first, middle and
  last row 159, 148 and 149 ms before, 0.0 to 0.1 ms after, TCP and UDP alike;
  windows read in order and peak RSS unchanged.
  Landed (d): the end-to-end ledger keeps, per declaration text, the outcome
  of every frame it judged by row (list, produced-index, place among the row's
  judgments) and, per list, a frontier (the first row not judged, and the
  largest capture-order key judged). A row behind the frontier is read back and
  moves no counter; a window begins no later than the frontier, so every row
  past it is judged in order. A walk that begins again keeps the ledger when the
  capture only grew and every row not judged sorts after the frontier's key;
  otherwise, and when a slot is judged from two lists, it judges afresh as
  before. The gate's capture of end-to-end frames whose counters repeat, skip
  past the profile's gap and go back (plain and under a frame ceiling) holds
  every window to the document's rows and to its own rows visited, and a ledger
  that judges again instead of reading back fails it. The cost is what the
  reference design pays: one kept outcome per judged frame.

## 7. Open

- Closed: the lent-buffer door is a pair of new functions, not a flag on
  replay, because what the caller promises differs (bytes read during the call
  against bytes kept for the life of the handle). Decided and landed in step 3.
- QUIC streams and the serial line produce rows outside the TCP segment map;
  step 3 did not reach them. Closed: D8 decides their byte source.
- Closed: D5 is decided (section 4). After the declaration absorption rode on
  the pairing's walk, a capture read the way the consumer reads it decodes each
  row three times: the census walk, the field document's shared walk and the
  renderer. Measured with the section 2 instrument against 270780967 (median of
  six at 409,064 rows, three at 1,386,564): fields windows 2,169 to 2,421 ms
  (+12%) and 7,876 to 8,772 ms (+11%), census 207 to 155 ms and 795 to 562 ms,
  peak RSS unchanged at 177 and 590 MB.
