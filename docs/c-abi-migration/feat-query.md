# Feature cost lane (feat-query): `query` and `queryable` against zenoh-pico

The size ledger's per-feature reading (`scripts/lib/size_ledger_gate.py --per-feature`, on the
`size-per-feature` branch) steps the API twin `pico-api-coop-nostd` up from the client case
`pico-client-coop-nostd` one feature at a time, each step against zenoh-pico built with the switch
that feature answers. Two steps cost wz the most over zenoh-pico after the transports:
`query` (+85,690 against +8,704) and `queryable` (+61,827 against +9,787). This note pairs what
zenoh-pico compiles for each of the two with what wz compiles for it, says for each pair whether
the bytes differ because the work differs (a contract or preset decision) or because of its form
(layers that overlap, generic copies, inline copies, gates and structures wider than the role),
and states the steps that take the form's share out. The first step landed with this note; the
owner's ruling of 2026-11-27 makes each item of section 4 a switch.

## 1. Where the readings come from

| reading | what | how |
|---|---|---|
| ledger steps | `pico-api-coop-nostd` per-feature JSON, tree `079c7a2a0a`, zenoh-pico `6a881c21dad1`, cc 13.3.0, cmake 4.4.2, 2026-11-27 | areas by line table (the ledger's own attribution) |
| symbol steps | the libraries that run shipped for each step (`<case>+<features>/libwz_capi_pico.so`) and the zenoh-pico reference built for it (`libzenohpico.so`) | `nm -C -S --defined-only`, text symbols, each name's bytes, the step's difference by name |

The ledger gives the areas; the per-feature JSON names no bodies, and `--explain` reads one case at
a time and has no reading of the API twin yet. The rows below are by symbol, which places an inlined
body in its caller where the ledger places it in its source file, so a row's area may differ from
the ledger's; the totals agree to within 1.2 %:

| step | wz, ledger | wz, by symbol | zenoh-pico, ledger | zenoh-pico, by symbol |
|---|---:|---:|---:|---:|
| `query` | +85,690 | +86,675 | +8,704 | +8,704 |
| `queryable` | +61,827 | +62,111 | +9,787 | +9,787 |

| area (ledger) | `query` wz | pico | excess | `queryable` wz | pico | excess |
|---|---:|---:|---:|---:|---:|---:|
| sessions | +32,312 | +5,298 | +27,014 | +29,360 | +7,121 | +22,239 |
| codec | +22,552 | +86 | +22,466 | +15,146 | +29 | +15,117 |
| doors | +15,055 | +2,133 | +12,922 | +10,586 | +1,828 | +8,758 |
| driver | +6,695 | +75 | +6,620 | +1,858 | 0 | +1,858 |
| language | +6,569 | +983 | +5,586 | +3,040 | +611 | +2,429 |
| transport | +2,298 | 0 | +2,298 | +876 | 0 | +876 |
| keyexpr, unclassified | +209 | +129 | +80 | +961 | +198 | +763 |

Two things to read before the rows:

- **zenoh-pico's codec for these messages is in its base.** `_z_request_encode`, `_z_query_encode`,
  the Response, Reply, Err and ResponseFinal decoders and encoders are compiled whatever
  `Z_FEATURE_QUERY` and `Z_FEATURE_QUERYABLE` say: they are in the reading of
  `pico-client-coop-nostd` (its codec, 35,440) and its two steps add 86 and 29 bytes of codec. wz
  gates its codecs by feature, so the area excess of codec overstates the difference. The fair pair
  is the codec rows below, which name zenoh-pico's base functions: 5,065 bytes for the four codecs
  (Request encode 1,403, Request decode 1,210, Response decode 1,184, Response encode 1,268) against
  wz's rows Q-d, Q-e, Q-f and R-a.
- **The tree read is 41 commits behind the main this note is written on.** Between the two the
  monomorphization lane landed its steps M1 and M2 (`docs/c-abi-migration/arch-mono.md`): the group
  item's closures (`multicast_tx_item_body`, 1,133 bytes of the `query` step) are one writer on
  main already. `engine/queries.rs`, which step Q1 changes, is the same file in both trees.

## 2. The same work, side by side

Kinds: **work** (wz does something zenoh-pico does not, or the other way round: a contract or preset
decision, section 4), **layers** (two forms of one thing, both linked), **generic** (one body
compiled for each type a parameter takes, where the parameter does not change what it does),
**inline** (a body inlined whole into a caller that has another copy), **wide** (a gate or a
structure that compiles more than the role needs). "Unread" marks a row whose bodies were not read
line by line; its kind is a reading of the names, to be confirmed by step Q8.

### 2.1 `query`: the asking end

| row | work | zenoh-pico | bytes | wz | bytes | wz - pico | where the difference comes from | kind |
|---|---|---|---:|---|---:|---:|---|---|
| Q-a | the get's doors and the reply object | `z_get`, `z_get_with_parameters_substr`, `z_get_options_default`, `z_reply_take` and the reply's accessors | 787 | `get::issue_get` 6,020, `get_inner` 1,746, `leg_callback` 1,293, `GetMoved` 842, `ReplyMarshal::deep_copy` 533, `z_reply_clone` / `z_reply_take_from_loaned` and their Err twins 1,204, `selector_params::has_param` 513, the rest | 13,430 | +12,643 | `issue_get` alone is four times zenoh-pico's get doors and `_z_query` together: the options' readers, the key's resolution and the fan-out over the faces in one body | inline, unread |
| Q-b | the querier and its matching status | `z_declare_querier`, `_z_declare_querier`, `_z_undeclare_querier`, `z_querier_get_with_parameters_substr`, `z_querier_take`, `z_querier_declare_matching_listener` | 2,433 | `z_declare_querier` 1,376, `querier::free_querier` 1,593, `z_querier_get_with_parameters_substr` 1,786, `FilteredKey::declare_at` 988, `RemoteQueryableTable::dispatch_iteration_event_with_local` 2,961, the queryable declaration's encoder 296, the declaration writer 960 and the slot observer's requester arms 514 | 10,644 | +8,211 | the asking build keeps the session's table of its peers' queryables, where zenoh-pico's write filter keeps the targets of its one key (`src/net/filtering.c`); `query` turns on `declare-queryable` (`wz-capi-coop/Cargo.toml`), so the queryable declaration's encoder and table dispatch are in a build with no queryable | wide (whether the table is read by more than the matching is to confirm) |
| Q-c | the pending gets and the delivery of their replies | `_z_query` (the Request built and sent) 1,065, `_z_trigger_query_reply_partial`, `_final`, `_err`, the local delivery, the pending-query table and its timeout, the reply's copy, move and clear | 5,484 | the legs (`hold_leg` 1,801, `end_leg_now` 1,380, `LegSink` 328, `Core::lose_link` +458, the get plane's place and drop 890), the reply registry (`dispatch_iteration_event`, `deliver_lent`, `unregister`, `next_deadline_ms`), `reply::in_place::lent_reply` 2,887, `ConsolidatingSink` 2,595 and its ring (`VecDeque` 657), `hand_reply` 1,546, `hand_lent_reply` 484, `dispatch_reply` 637 | 19,131 | +13,647 | a get is one leg per face with a Final of its own, and a lost face's legs end (section 4, O1), where zenoh-pico counts the Finals of one pending query; a reply read where it lies is projected (`lent_reply`) beside the registry's own delivery of it, two delivery forms of one reply; consolidation holds replies in a ring where zenoh-pico holds them in its pending-reply list | work (O1), layers, wide |
| Q-d | the Request's encoder | `_z_request_encode`, `_z_query_encode` (in its base) | 1,403 | the lent `RequestWriter::encode` 2,070, `measured` 453, `BodyExtension::write_body` 319; the owned `QueryWire::write_source::<QueryIn<Heap>, _>` counted 1,172 and written 1,042, `drop_glue<QueryIn>` 272; the get under the held faces 1,324 and its send closure 349, `WireexprWire` 109 | 7,153 | +5,750 | two forms of one Request: the lent writer the session sends with, and the owned encoder over `Heap` that the encoding of an owned network message still reaches (`NetworkMessage::Request`); the owned one in a counting and a writing copy | layers, generic |
| Q-e | the Response's and the ResponseFinal's readers | `_z_response_decode` and its extension, `_z_reply_decode`, `_z_err_decode` and theirs, `_z_response_final_decode` (in its base; the Put by `_z_push_body_decode`, the Push's) | 1,184 | `network_message::read_response` 3,792, `read_response_final` 695, `ReplyView::read_with` 560, `MsgPutView::read_with` 1,905, the records' lend arms 194, `WireexprView` 163 | 7,309 | +6,125 | a Reply's Put is read by the generated `MsgPutView::read_with` while a Push's is read by `push_read::read_push_view`: two readers of one Put body, where zenoh-pico's Reply calls the Push's; the generated view reader is in `read_response` whole | layers, inline (unread) |
| Q-f | the Request's reader, in a build that only asks | `_z_request_decode`, `_z_query_decode` and their extensions (in its base); at `Z_FEATURE_QUERYABLE` 0 a Query is dropped (`src/session/rx.c`) | 1,210 | `network_message::read_request` 2,641, `QueryView`, `QueryExtEntryView` and the chain walk 1,679, `SkipAt::nth` 330, the admission's `judge_entries` closure 901, the lend arm 81 | 5,632 | +4,422 | `query` turns on `codec-request`, so a build that only asks reads every Request in full; a Request carrying a Put or a Del is answered by zenoh-pico too (`_Z_REQUEST_PUT`), the Query half is a queryable's (section 4, O3) | wide, work (O3) |
| Q-g | the group's reply stage, in a build that only asks | none: zenoh-pico's replies are `_z_send_reply`'s, under `Z_FEATURE_QUERYABLE` | 0 | `GroupTxStage::enqueue` 4,061, the group item closures 1,133 (one writer on main since M2), the owned Response encoders over `Heap` the stage reaches (the Put counted 1,470, the Reply's and the Response's envelopes 1,283, the Del 824, `ReplyIn`'s drop 279), `set_z64_ext` 619 | 9,669 | +9,669 | `codec-response` gates the reading and the writing of a Response, so the stage that writes replies on a group is in a build with no queryable; and that stage writes the owned Response (`QueryReply::into_response`, `multicast_reply_sink.rs`) where a link's reply is written by the lent `ResponseWriter` | wide, layers |
| Q-h | a get's cancellation, `unstable-api` off | none: the token's field is under `Z_FEATURE_UNSTABLE_API` | 0 | `CancellableFan`'s drop and key, `cancel_fan`, `fan_ended` | 1,590 | +1,590 | `take_cancellation_token` is `None` in that build (`get.rs`), but the fan the get's place holds is compiled and dropped | wide |
| Q-i | the engine's own growth | | 0 | `deliver`'s closure 3,526 (the hand-out, with the replies' arm), `face_turn` 1,435, `close` 1,290, the registry's `new`, `add_face` and `declares` 2,504, `kept::Shared::last_placed` 1,466, the rest | 12,117 | +12,117 | not read | unread |
| | **total** | | **8,704** | | **86,675** | **+77,971** | zenoh-pico's base codec rows Q-d, Q-e, Q-f: 3,797 more | |

### 2.2 `queryable`: the answering end

| row | work | zenoh-pico | bytes | wz | bytes | wz - pico | where the difference comes from | kind |
|---|---|---|---:|---|---:|---:|---|---|
| R-a | the Response's encoder | `_z_response_encode`, `_z_reply_encode`, `_z_err_encode`, `_z_response_final_encode` (in its base, 1,268; the Put by `_z_push_body_encode`, the Push's) | 0 | `lent_response` 7,415 (the direct window writer and its length, `encode_generic` and `write_response` each in a counting and a writing copy), the generated Put, Reply and Response writers over parts in both copies and the extension entries' 5,336, `lent_reply` 1,153, the group's reply parts 977 net, the Final's writer 188 | 15,069 | +15,069 | three writers of one reply: the direct window writer, and behind it the codec's encoder over parts, which a reply with a timestamp, an attachment or a source info and a buffer with no window reach (`GENERIC_REACHABLE`), compiled for the counting sink and the writing one | layers, generic |
| R-b | the reply doors | `z_query_reply`, `z_query_reply_del`, `z_query_reply_err`, `_z_send_reply`, `_z_query_reply_sample`, `_z_send_reply_err` | 1,976 | `QueryResponder`'s 19 `ReplyOut` methods 5,631 (`reply_keyed`, `_sourced`, `_stamped`, `_meta`, `_attached`, `_encoded`, `_encoded_parts`, `_del`, `_del_meta`, `_del_sourced`, `reply`, `try_reply`, `reply_err`, ...), `QueryMarshal::reply` 2,444, `z_query_reply` 1,363, `_del` 717, `_err` 525, `flush_one` 1,035, the reply stage's `row_parts` 846, the reply under the held faces 634, the query views 675, the rest | 14,699 | +12,723 | a reply method for each combination of what a reply carries, each a body of 150 to 470 bytes, all of them kept by the trait's table, where zenoh-pico has one `_z_send_reply` that reads its options; the doors' own bodies not read | wide, unread |
| R-c | the queryable doors and the query object | `z_declare_queryable`, `z_declare_background_queryable`, `z_queryable_keyexpr`, `z_query_take_from_loaned`, `z_query_clone`, `z_query_drop`, `_z_declare_queryable`, `_z_undeclare_queryable` | 2,226 | `declare_queryable_in` 2,299, `clone_query_marshal` 1,742, `queryable_sink_at` 1,255, `QueryMarshal`'s drop 524, `free_queryable` 439, the doors | 7,290 | +5,064 | not read | unread |
| R-d | the queryables' tables and their declarations | `_z_register_queryable`, `_z_register_session_queryable`, `_z_interest_send_decl_queryable`, the session queryable's lookup, flush and clear | 2,798 | the session tables 2,951, the slot observer 1,775, the declaration and the undeclaration under the held faces 2,031 and 1,179 (the subscriber's twins shrank by 2,519 in the same step), the group's announce and retract 3,307, the key matcher's branch 344 | 11,274 | +8,476 | each operation under the held faces is a body of its own (arch-mono 2.1); the group announces a declaration through a path of its own | generic (arch-mono), unread |
| R-e | a peer's query handed to the queryables, and its Final | `_z_trigger_queryables` 2,504, `_z_handle_request` | 2,787 | `hand_query`'s callback loop 1,186 twice, `hand_lent_query`, `pin_lent_query` 1,395, `run_queryable` 1,496, `pin_queryable` 1,079, the session's query projection and plane, `owe_finals`, `owe_final` and `dispatch` of the face's records, `answer_asks` 1,507 | 14,894 | +12,107 | the walk is generic over the kind of face the query came from (`RecordActions`: a link's actions, a group's replies), and compiled for both where the build joins groups, though only three calls of it read the face (hold the replies, owe the Final, let them go): `hand_query`'s loop reads none (step Q1); replies are held to leave with their Final (section 4, O2) | generic, work (O2) |
| R-f | the rest | | 0 | | -1,115 | -1,115 | the subscriber's operations, out of line once their queryable twins were | |
| | **total** | | **9,787** | | **62,111** | **+52,324** | zenoh-pico's base codec row R-a: 1,268 more | |

### 2.3 The form's families in the full case

The families the rows name, read on the last step's library (`pico-api-coop-nostd` with every
feature, 941,421 bytes of text symbols):

| family | bodies | bytes | step |
|---|---:|---:|---|
| the query walk per kind of face: `hand_query`'s loop (1,282, 1,266), `hand_lent_query` (1,018, 1,211), `FaceRecords::owe_finals` (473, 876), `FaceRecords::dispatch` (337, 414) | 8 | 6,877 | Q1, Q2 |
| the counting copies of the Query, Response, Reply, Put and Del encoders (`CountSink`) | 11 | 8,341 | Q3 (arch-mono M5) |
| the owned forms over `Heap` of Query, Reply, Response, Del and the counted Put, beside the lent writers | 10 | 5,791 | Q4 |
| the Reply's own Put reader (`MsgPutView::read_with`) | 1 | 1,905 | Q5 |
| the reply methods of `QueryResponder` (`ReplyOut`) | 19 | 5,631 (the `queryable` step's) | Q7 |

The second and the third family share the owned forms' counting copies (five bodies, 3,658
bytes): Q3 and Q4 together take 10,474, not their sum.

## 3. Steps

| step | change | bytes, expected | client case | receive Ir (about 3,066 a message) | held by |
|---|---|---|---|---|---|
| **Q1 (landed)** | `hand_query`'s callback loop moves out of the face-kind generic into `CoopEngine::call_queryables`, generic over the engine's links and clock alone: one loop for a link's face and a group's | `pico-api-coop-nostd` -1,150 to -1,300 (one loop of 1,266 or 1,282 bytes, less the call's arguments); `pico-peer-coop` 0 (no `queryable`) | 0: `engine/queries.rs` is compiled under `queryable` | none: the client has no queryable; on a queryable's path the loop was an out-of-line closure and stays one, called once a query | `tests::direct_receive::a_query_is_handed_to_its_queryables_by_the_read_with_the_session_free` (a link's face: two queryables in order, the session free, the Final after both replies, two calls counted); `tests::group::asked::a_get_of_the_group_is_answered_by_a_members_queryable_and_ends_with_its_final` (a group's face) |
| Q2 | the rest of the walk out of the face kind: the lent query's pin, its owned projection and the first queryable's pin in engine methods, the face kind keeping the three calls that read it (`hold_replies`, `owe_final`, `release_replies`) and `owe_finals`' loop over the registry's Finals | -1,500 to -2,500 | 0 | none: the read's dispatch of a record that is not a Request is not touched | the two tests of Q1; `tests::queryable`'s Final tests |
| Q3 | arch-mono M5 for these messages: a reply's length from the direct layout for every reply (the window writer writes a timestamp, an attachment and a source info too, and `GENERIC_REACHABLE` is `transport-fragmentation` alone), a Request counted by `RequestWriter::measured` alone | -4,000 to -8,300 | 0 | none: nothing of the receive changes, and a reply's count is arithmetic where it was a pass of the encoder | `lent_response`'s direct-against-generic tests, which keep `encode_generic` as their reference |
| Q4 | one form of each sent message: the group's reply stage writes through the lent `ResponseWriter`, as a link's does, and no path of a cooperative build sends an owned `Request`; the owned encoders over `Heap` stay the tests' reference | -4,000 to -5,800 (the 5,791 of owned forms, less what the stage's window writer adds) | 0: the client's own `MsgPutWire::write_source::<MsgPutIn<Heap>, TxSink>` is its put's and stays | none: a put does not take the stage's path | `tests::group::asked` (both tests); `lent_response`'s owned-against-lent tests |
| Q5 | one Put body reader: a Reply's Put and Del read by the reader a Push's body is read with (`push_read`), as zenoh-pico's `_z_reply_decode` calls `_z_push_body_decode` | -600 to -1,500, to measure: the saving is `MsgPutView::read_with` less the out-of-line instance the Reply calls | 0 bytes and 0 Ir: the Push keeps its reader where `read_push` has it, and the Reply's is a second instance only if the Push's is inlined | none on a Push | `network_message`'s tests of the lent Response (`a_reply_put_payload_is_a_range_of_the_lent_frame`, `a_response_and_its_err_read_a_repeated_extension_by_its_last_entry`) |
| Q6 | gates by role: `query` alone does not turn on `declare-queryable`, the Query half of the Request's reader (pending O3) or the group's reply stage; `codec-request` and `codec-response` split into a read and a write half; the get's cancellation fan under `unstable-api` | `pico-api-coop-nostd` 0 (every role is on); a build that only asks (`query` without `queryable`, zenoh-pico's `Z_FEATURE_QUERY` 1 and `Z_FEATURE_QUERYABLE` 0) -12,000 to -16,000 | 0 | none | the C1h feature matrix compiling each half alone; a requester-only build's test that a peer's Query is answered as O3 decides |
| Q7 | one reply method: `ReplyOut` takes one record of the reply's parts (key, payload, encoding, timestamp, attachment, source info, Put or Del) where it has a method for each combination, the C doors filling the record as zenoh-pico's fill `_z_send_reply`'s arguments | -3,000 to -4,500 | 0 | none: a reply is built once a call either way | `query_sink::reply_out_contract_covers_del_err_and_responder_roundtrip` and the doors' reply tests, each combination one case |
| Q8 | read the unread rows (Q-a, Q-i, R-b's doors, R-c) body by body from the line tables, as arch-mono read `run`, on the API twin's explain report once `--explain pico-api-coop-nostd` reads one | none | | | |

## 4. Owner decisions: each behaviour zenoh-pico does not have is a switch

The owner's ruling of 2026-11-27: a behaviour of wz's that zenoh-pico does not have is a switch of
its own, a capability of `deploy/wz-config.toml` with `upstream_off = ["zenoh-pico"]`: on in a
build that names nothing and in the host profiles, off in the zenoh-pico preset, whose library then
links none of it. The send's four behaviours are the first such switches (`tx-probe`,
`tx-expiry-run`, `tx-fragment-credit`, `tx-held-wait`); the three items of the query planes follow
them, one switch each. A switch is a behaviour of every session and no door, so `host-peer` and
`host-peer-ext` keep each on, as they keep the send's: `pico-api-coop-nostd` is read with them
on, and moves by the steps of section 3 alone; the zenoh-pico preset is read with them off.

| item | switch | on: what wz does | off: what the build does, as zenoh-pico does | bytes (`query` / `queryable` steps) | lands |
|---|---|---|---|---|---|
| O1 | `query-face-legs` (`WZ_CAP_QUERY_FACE_LEGS`) | a get is one leg per face it went out on, each with its own Final, and the legs of a face that goes end with it (`SessionState::lose_face`, `pending_gets.drop_face`), so a get ends when its last face does | one pending get with a count of the Finals it waits for, as zenoh-pico's `_remaining_finals` (set in `src/net/primitives.c`, decremented only by a Final in `src/session/query.c`): a face that goes ends none of its gets, and each ends at its last Final or at its timeout | about 6,200 of Q-a and Q-c (`hold_leg`, `end_leg_now`, `leg_callback`, `LegSink`, `lose_link`'s growth, the get plane) | a step of its own: the get plane keeps a count of Finals beside its legs, and the legs' bodies are gated |
| O2 | `query-replies-with-final` (`WZ_CAP_QUERY_REPLIES_WITH_FINAL`) | the replies a queryable's callbacks make wait in the face's open frame and leave with the Final in one send (`ResponseSink::hold_replies`, `release_replies`, `engine/queries.rs`) | each reply is sent as the callback makes it, as `_z_send_reply` sends it, and the Final after the callbacks, possibly in a later frame: no reply is held and the face's hold is not compiled | not separated (inside R-e and the reply sinks): read on the zenoh-pico preset's library by the switch | with this lane |
| O3 | `query-final-unanswered` (`WZ_CAP_QUERY_FINAL_UNANSWERED`) | a build that only asks reads a peer's Query in full (Q-f) and owes it what a query no queryable answers is owed (`QueryPeer::answers_unresolved_queries`, the `query-unanswerable-final` policy) | a build without `queryable` drops a peer's Query unread, as zenoh-pico does at `Z_FEATURE_QUERYABLE` 0 (`src/session/rx.c`), and sends no Final: the asker's get ends at its timeout | 5,632 of Q-f, in a build without `queryable` only | with Q6: the switch is what Q6 reads to leave the Query half of the Request's reader out of a build without `queryable`; until Q6 it removes nothing |

A build with a switch off states nothing it would read: a test of each switch holds the build
without it to the zenoh-pico behaviour (the get that ends at its last Final, the reply that leaves
before its Final), as the send's switches are held (`scripts/lib/nondefault-tests-gate.sh`).

## 5. Verification (the main session's)

- Build and clippy of `wz-capi-coop` with `queryable`, with `queryable,group,app-transport,threads`
  and without `queryable` (where `engine/queries.rs` is absent).
- `cargo test -p wz-capi-coop --lib --features query,queryable a_query_is_handed_to_its_queryables_by_the_read_with_the_session_free`: 1 test.
- `cargo test -p wz-capi-coop --lib --features query,queryable tests::queryable`: the module's tests, as before.
- `cargo test -p wz-capi-coop --lib --features group,app-transport,query,queryable tests::group::asked`: 2 tests.
- The cost gate's `pico-api-coop-nostd`: lower by Q1; in its library one
  `call_queryables::{closure#0}` body and no `hand_query::<_>::{closure#0}` (`nm -C -S`).
  `pico-client-coop-nostd` and `pico-peer-coop` byte for byte as before.
- The perf matrix's arm W: receive Ir a message of `pico-client-coop-nostd` as its last reading.
