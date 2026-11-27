# Monomorphization lane (arch-mono): one body a build, read copy by copy

The Windows lane's note (`docs/c-abi-migration/arch-win-ext.md`, section 2.3, on its branch) names
two generic bodies of the release DLL that multiplied between the readings of 2026-11-25 and
2026-11-27: `wz_capi_coop::engine::direct::...::run` in 22 copies (24,999 bytes) and
`wz_session_core::tx_buf::...::write_wire` in 20 (11,273). This note counts the same families on
the two Linux cases that have them or not, reads what each copy is made of and which type parameter
makes it, and states the steps that leave one body where a parameter does not change what the body
does. It extends `docs/c-abi-architecture.md` and the driver lane's `docs/win-budget/size.md`
section 9 (on its branch); it changes neither.

## 1. Where the readings come from

| case | build | how it was read |
|---|---|---|
| Windows release DLL x64 | run 45923879841 | the Windows lane's note, section 2.3 (`llvm-pdbutil`, each body once by its address) |
| `pico-default` (Linux) | the cost gate's case on the tree `35632021a2`, `capi-nostd` | `nm -C -S` of the library; line tables and inline frames by `objdump -d -l --inlines` |
| `pico-client-coop-nostd` (Linux) | the size ledger's explain report of 2026-11-27, tree `7c2d085fb4` (main `6199fa0d40` and two commits of the engine lane) | the report's bodies, each body's bytes summed over its areas |

`pico-default` is the Linux build nearest the Windows release DLL: it listens, joins groups and
answers queries, so it has both families; the client case dials one face and joins no group.

## 2. The two families, copy by copy

| family | Windows x64 | pico-default | pico-client-coop-nostd |
|---|---:|---:|---:|
| `HeldOperation<F, U> as UnderHeldFaces` `run` | 22, 24,999 B | 22, 24,237 B | 0 |
| `<F as WireWrite>::write_wire` | 20, 11,273 B | 21, 11,471 B | 3, 3,567 B |

### 2.1 What makes the copies of `run`

The parameter is `F`, the operation: each of the engine's operations that runs with every face's
send place held (`CoopEngine::live_on_link` of a build with `listen` or `group`) is a closure of
its own, and its body is inlined into its own `run`. The 22 copies are 22 operations, each
compiled once: declaring a subscriber, a queryable, a write filter, a token, a liveliness subscriber,
a matching listener and a key, undeclaring most of them, a get, a liveliness get, a reply, an
answer, a put through a filter, a batch, a redeclaration and a replay's turn. The hold of the faces is already one body for all of them (`hold_faces_from`, reached through
the one-method table of `UnderHeldFaces`). The client case has no copy: a build whose only face is
the dial role's runs the operation in its caller under one hold (`live_on_link` of
`not(any(listen, group))`).

What each copy holds besides its operation, `pico-default`, from the line tables of the 22 bodies:

| part of the 22 copies | bytes | depends on `F` |
|---|---:|---|
| the operations' own code | 21,579 | yes: it is the operation |
| the copy's own lines (frame, the call's setup) | 1,654 | no, but each out-of-line operation needs a frame |
| the take of the operation out of its slot | 606 | no |
| the drop of the answer slot the answer is written over | 398 | no: the slot never holds an answer then |

The drop is in the operations whose answer has a destructor: undeclaring a subscriber (180), a
queryable (169) and a matching listener (49). One enum over the 22 operations, matched in one
`run`, would keep every operation's body, add a record of each one's arguments and gather unrelated
operations into one module: it is not this lane's form. What does not depend on `F` is removed
instead (step M1).

### 2.2 What makes the copies of `write_wire`

The parameter is `F`, the encoder of one network message: every closure handed to a send as
`&dyn WireWrite` is one, and the blanket impl adds no line of its own (`self(sink)`). The client
case's three are three messages (a declaration 2,385, an interest 771, a push 411). Of
`pico-default`'s 21, one is the same closure compiled twice: `frame_encode::push_body`'s, 514 bytes
in `wz-session-core` and 195 in `wz-session-mcu`. The group's stage calls
`multicast_tx_item_body`, generic over the stage's own closure, so that crate compiled the function's
closure for each kind of item and, under the push's, the Push encoder again with the encoders it
reaches (step M2).

## 3. Every family with more than one body

### 3.1 The client case

962 bodies; 23 families of more than one body, 6,683 bytes, 3,285 of them beyond each family's
largest body. Each is a type parameter that changes what the body does:

| family | bodies | bytes | parameter | one body? |
|---|---:|---:|---|---|
| `kept::Shared<T>::last_placed` | 4 | 1,424 | the held type, whose drop is inlined; the rest is one body already (`give_back`, `free_boxed`) | no |
| `core::ptr::drop_glue` | 10 | 833 | the dropped type | no |
| `bounded::drop_row` | 8 | 664 | the row type | no |
| `network_message::pull::lend_body` | 4 | 622 | the record's kind: its decoder and its view | no, and it is the read |
| `sce_rust_runtime::Engine` `run_turn`, `new_in_place` | 3, 3 | 821 | the machine | SCE's |
| `ExtEntryWire::write_source_in` | 2 | 290 | the source; generated | the codec's |
| `BoundedString` `push_str` | 2 | 227 | the storage | no |
| `Arc::drop_slow` | 2 | 212 | the shared callback type | std's |
| `TxSink` `write_vle_u64` | 2 | 149 | a slice buffer against the lent buffer | no, the slice form is the direct writer's |
| `SlotMap::add_free_slot` | 4 | 112 | the row's size and the table's bound | 28 bytes each |
| `OneThreadLock::lock` | 2 | 74 | the locked value; the flag's offset | 37 bytes each |

The client case holds no copy whose parameter leaves its behaviour as it is, beyond the last two
rows (under 200 bytes). The steps below do not move its total; it is named so that its reading after
them is read as unchanged, not as a regression or a gain.

### 3.2 `pico-default`: one instance compiled in two crates

A generic instance is compiled in each crate that instantiates it, and the two are kept apart under
fat LTO: `pico-default` holds 16 such instances twice or more (9,451 bytes with every copy). wz's
own: `MsgPutWire::write_source::<MsgPutIn<Heap>, TxSink>` (1,273 and 1,257), the push writer (514,
195), three `ExtEntryWire::write_source_in` instances (166, 149, 141, twice each), two
`WireexprWire::write_source` instances (109 twice, 107 three times), `drop_glue` of
`Placed<GetPlane<CoopCalls>>` (253, 352), of `Sample` (75 twice), `drop_row` of `PeerTokens` (57
twice), `SliceTxBuf::append_byte` (29 twice). The client case has one, `alloc`'s `finish_grow`.

### 3.3 `pico-default`: the count's copy of each encoder

A build with `alloc` counts a message it sends through the codec's counting sink
(`sce_forge_runtime::codec::CountSink`) and writes it through `TxSink`: every encoder so counted is
compiled twice, 14 bodies and 11,867 bytes of counting copies (the declaration's 2,989, the put's
1,545 and 1,521, the query's 1,173, the response writer's 1,110 and 957, the reply's 516, ...). The
client case counts through the one encoder over `CountTxBuf` (`tx_buf::try_encoded_len`) and has
none. Counting a put through `dyn TxBuf` adds an indirect call a field to the put, so the put's
count stays as it is; the declaration's, the query's and the reply's are the step M5 candidates.

## 4. With the driver lane's links (size.md section 9)

The link type is one per build: the client case's every link-generic body is instantiated once,
over `CellRc<dyn SessionDatagramLink>`. Step 2 of that section makes the stack's links one enum and
step 3 carries it to the read and the send (`SessionLinks::Link`, `LinkOf<T> = CellRc<L::Link>`,
`LinkPump<_, CellRc<L::Link>>`): the read's and the send's bodies become generic over
`CellRc<L::Link>` instead of the trait object, still one type a build, so still one copy each. Two
bodies of `pico-default` are a copy per link type, `UdpDriver::recv_with` over the unicast socket
(685) and over the `udp/` port's peer (1,419); they read different things, and the enum keeps both as
its arms. The steps here add no type parameter to a link-generic body and take none from one, so
they cross neither step; a step that later outlines part of the read keeps the enum's static
dispatch and adds no call to it.

## 5. Steps

| step | change | bytes, expected | receive Ir (about 3,070 a message, W/P about 0.76) | held by |
|---|---|---|---|---|
| **M1 (landed)** | `HeldOperation` is one state, waiting, running or answered: the answer is written over the running state the run wrote, which holds nothing, so no operation drops an answer slot; the take is one tag write | `pico-default` -400 to -700 (the 398 of drops, part of the 606 of takes); Windows x64 the same and the drops' unwind records; client 0 | none: an operation under the held faces is a declaration, an undeclaration, a query or a reply, never the read; a publish's legs do not run through it (`on_faces`) | `direct::held_operation_tests` (two); the engine's tests of declarations and undeclarations on faces |
| **M2 (landed)** | `multicast_tx_item_body` hands on `ItemBody`, one writer of every kind of item, not generic, compiled in `wz-session-core` alone | `pico-default` -1,500 to -3,200 (the stage's crate loses the four kinds' closures, 1,599, the push writer's copy, 195, and the Heap encoders only it reached, 1,532, for one writer); Windows the same where the build joins groups; client 0 | none; a group's push and reply are matched on their kind inside the writer, one compare a pass of the encoder, through the same one `&dyn WireWrite` call the closure was | `multicast_tx::push_tests::an_items_encoder_writes_its_own_messages_bytes` |
| M3 | `wait_until_let_go` over one enum of the row an undeclaration waits for (subscriber, liveliness subscriber, queryable), out of line: its two closures are the table read, and `settled` is the same for every kind | `pico-default` about -800 (3 copies of 430 to one); client 0 | none | an engine test per kind that undeclares while a call runs, each returning after the row's drop; `liveliness.rs`'s history case and `queryable.rs`'s kept query today |
| M4 | each wz instance of section 3.2 compiled in one crate: a non-generic writer or drop in the owning crate where a second crate instantiates it | `pico-default` -1,000 to -1,500 beyond M2 | none on the read; no call added to a put | the owning crate's tests of each writer's bytes |
| M5 | the cold messages counted through the encoder that writes them (`try_encoded_len`), the put's count kept static | `pico-default` -4,000 to -7,000; client 0 | none on the read or the put; a declaration's, a query's and a reply's count take indirect calls | the counted-equals-written tests of each message |

M1 and M2 leave the number of `run` copies at the number of operations (22): those copies are the
operations, compiled once each. `write_wire` goes from 21 to 17 in `pico-default` (the four item
closures and the push writer's second copy out, `ItemBody` in).

## 6. Verification (the main session's)

- Build and clippy of `wz-capi-coop` with `listen`, with `group` and with neither (where
  `HeldOperation` is absent), and of `wz-session-core` with the group's set
  (`session-multicast,codec-frame,storage-profile,codec-push`), with and without
  `transport-tx-lend`, `codec-request`, `codec-response`, `codec-response-final`, `codec-declare`.
- `cargo test -p wz-capi-coop --lib --features listen held_operation_tests`: 2 tests.
- `cargo test -p wz-session-core --lib --features session-multicast,codec-frame,storage-profile,codec-push,codec-response-final an_items_encoder_writes_its_own_messages_bytes`: 1 test.
- Layer C1cs: `pico-client-coop-nostd` unchanged (no family of this lane is in it); `pico-default`
  lower by M1 and M2; in its library one `push_body` writer and one
  `MsgPutWire::write_source::<MsgPutIn<Heap>, TxSink>` (`nm -C -S`), and no `drop_glue` inlined
  at `direct.rs`'s `run` (`objdump -d -l --inlines` of the `undeclare_subscriber` copy).
- The perf matrix's arm W: receive Ir a message and W/P as their last reading.
- Platform's Windows package job: `pico-api-windows-*` and `pico-release-windows-*` lower.
