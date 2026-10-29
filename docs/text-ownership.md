# The text of an image, by owner

`deploy/text_budget.json` holds, for each gated MCU image, its text and the bytes of every owner of
its symbol table; `scripts/lib/text_owner_gate.py` reads them out of the linked ELF in the kit lane's
build step and refuses an image that moved by more than a tolerance. This is the text twin of the
resource budget (`deploy/resource_budget.json`): a change that moves a row moves it in the same
commit, with the reason.

## Why it exists

The parity matrix says the fixed client's text is 1.20 of single-threaded zenoh-pico's. That is a
total. Which of the 31 KB of difference is whose was not written anywhere, so a lever on size was
chosen by a guess about where the bytes were, and its worth could be read only as a change of the
total. Measured: the machine outliner saves 2.2 KB and costs 5.1 us in the answer to a query
(`recvfrom` to `sendto` 41.7 to 46.8 us); the Declare dispatch merge saved 2.2 KB and cost 24 B of
stack. Neither could be weighed against the other without knowing what the rest of the 31 KB is.

## How an owner is read

`nm -S -C` of the ELF; every symbol of code or read-only data is given to an owner. A Rust symbol
belongs to the first crate its demangled path names; a C symbol to its prefix, written as the
prefix (`c:_z_`), because a prefix is a fact about a name and not a claim about a library (`z_` is
Zephyr's internals and zenoh-pico's API alike).

What this is not: provenance. With link-time inlining the symbol that carries a function's code is
its caller's, so what `wz_app_main` inlines is counted under `c:wz_` (10.5 KB in the fixed image,
the largest unnamed part of the wz code). The rows fence the total and show where a change landed.
Finding whose source a byte came from takes a build without LTO, which has other sizes.

## The first reading (run 20261028T005644's compare builds)

The platform (the Zephyr network stack, the board's drivers, the toolchain) is the same size in the
fixed image and in the single-threaded pico image: the 31 KB is not there. What is left is the two
libraries' own code.

| | own code |
|---|---|
| zenoh-pico (`c:_z_` and the wz harness it is linked with) | about 55 KB |
| wz fixed client | about 92 KB |

wz's 92 KB is `wz_session_core` 41.6 KB, the inlined `wz_app_main` 10.5 KB, `wz_session_mcu` 9.4 KB,
`wz_codecs` 8.5 KB, `sce_rust_runtime` 7.9 KB, `wz_runtime_coop` 6.1 KB, `keccak` 2.2 KB, `core`
1.8 KB, `compiler_builtins` 1.6 KB (0.9 KB in the pico image) and `wz_runtime_zephyr` 0.7 KB. Zenoh-pico
carries about 6 KB of C library code wz does not, which is why the difference is 31 and not 37 KB.

## Levers this ranks

- TAKEN: `keccak` (2.2 KB, one symbol) was the SHAKE128 permutation of the initial sequence number
  (`src/initial_sn.rs`): zenoh derives it from the two zids so that a re-attempt of a multilink
  session lands on the same origin, and zenoh-pico draws it from entropy. `initial-sn-compact`
  (`CONFIG_WZ_INITIAL_SN_COMPACT`, which the fixed overlay turns on) is a compact pure function of
  the two zids: the same properties (the same origin for a pair, a different one at each end and for
  another peer), not zenoh's value, no permutation. The three fixed images fell 2.4 KB of text and
  their worst chain 428 to 500 bytes (the permutation's frame was on it); the kit's readings did not
  move.
- TAKEN: the subscribing half of the client. The single-threaded zenoh-pico it is compared with has
  `Z_FEATURE_SUBSCRIPTION` off (`deploy/zephyr-pico-compare/prj.conf`); the wz client declared a
  subscriber and kept the registry of subscriptions all the same, with a limit of zero of them. The
  declaration is now `wz-session-mcu`'s `client-subscriber`, which `client-core` no longer carries
  (`client-slot` and `client-node` still do, so no other consumer changed), and the Zephyr node takes
  it from `CONFIG_WZ_SUBSCRIBE` (on by default, off in the fixed overlay). The three fixed images
  fell 2.3 to 2.5 KB of text (`wz_session_core` 2.0 KB of it) and 960 bytes of bss; the kit's stack
  readings and the answers did not change.
- TAKEN: the codec's builder path of the reply writer. A line table of the shipped image (a build with
  `CARGO_PROFILE_RELEASE_DEBUG=line-tables-only`, whose text is the same) puts 6.2 KB in
  `heapless::Vec`, 2.7 KB of it `push_unchecked`: whole extension entries copied by value into the
  chains of `ResponseWriter::encode_generic`. A reply with the responder's identity and an Err are now
  written by the direct writer as well (the tests hold each to the codec's bytes), and
  `encode_generic` is called only where a timestamp, an attachment or a source info can be staged or a
  sink hands out no window (`GENERIC_REACHABLE`); elsewhere it is not linked. The fixed images fell
  1.5 to 2.2 KB. The responder and Err replies were not run on the kit (its queries get a Put).
- TAKEN: the connect manager's planner call. The line table put `connect_manager.rs` at 4.0 KB, the
  largest wz source file of the image, and the largest lines were `drive` and `ask`, generic over
  the closure each of thirteen callers passes. They take the call as a trait object now (a few
  cycles in the path that dials a router), so each is one copy. The fixed images fell 2.6 KB of
  text (the main function and what it inlines, `c:wz_`, 2.6 KB of it), and the worst chain 384
  bytes (the main frame 1,792 to 1,256). On the kit the get image's stack reading fell 440 bytes;
  the others did not move. The lesson, in the shape of the first not-taken lever below: a generic
  function with many callers is a copy for each, and the optimizer shares it only when it is small.
- TAKEN: the session's link driver named by its type. The session read its driver through a trait
  object (`dyn BoxedLinkDriver`) on every image, so each call to the link was a register call the
  optimizer could not see through, and the transmit lease, the session slot and the pump carried that
  object type through every layer. `SessionRuntime::Driver` is now an associated type: the run-time
  profiles (tokio, and the coop runtime by default) keep the trait object, and the fixed-memory
  profile, whose stack the Kconfig choice names, passes the concrete driver down, so the calls into
  the link are direct calls and the generic code is one copy for the one driver. The fixed image fell
  1,704 bytes of text, the batching image 2,280 and the get image 1,808; the register calls on the
  fixed path fell 12 to 9. On the kit the stack peaks of the fixed (5,904) and batching (5,908) images
  and the query's in-to-out time (41.3 us, noise 0.6 to 1.2) did not move, and the get image's peak
  fell 48 bytes. The worst chain read by `stack_frame_gate.py` fell 5,512 to 5,480 (fixed) and
  5,520 to 5,480 (batching); it is a reading, not a bound: it follows direct calls only, so a callee
  behind a register call is not on it (the connect manager's trait object above hid one in `ask`).
- TAKEN: the receive's records handed to their own callee. The receive path reported everything to one
  `FnMut(IterationEvent)`, the record a frame lends included, so a layer that sent a query or a put of
  its own did it on top of the frame it was handed. `EventSink` has two methods now: `event` for the
  turn's own events and `record` for a lent record. The layers answer a record beside it and send what
  they own on `event` only, after asking the loop to wake (`AppWake`, raised before the next datagram
  is read). A call graph tells the two apart because they are two slots of one trait object. The
  fixed image fell 568 bytes of text (wz_runtime_coop 796 of them), the batching image's total did
  not move, the get image's grew 72. The get image's worst chain by the register-call reading fell
  7,640 to 6,768 bytes; the fixed and batching images stay at 6,216. Of the 75 percent rule's limits
  (6,912 for the fixed image's 9,216 bytes of stack, 7,680 for the batching image's 10,240, 9,216 for
  the get image's 12,288) every one of the three readings was inside its own before and after, so
  the fall is margin and not a repair: Rounds 3845 and 3846 said the get image's 7,640 was over the
  rule, which read the fixed image's limit against the get image.
- TAKEN: the main stack as a function of the bound. The three fixed images held 9,216, 10,240 and
  12,288 bytes of main stack, sized from the kit's reading and a quarter free; `stack_bound_gate.py`
  now holds each to what its bound needs, in units of 64 and at most 512 above: 8,320, 8,320 and 9,024.
  RAM (bss) fell by exactly that, 896, 1,920 and 3,264 bytes (109,714 to 108,818, 110,786 to 108,866,
  121,482 to 118,218); text is unchanged, and the three images boot, answer and read the same stack
  peaks on the kit (5,904, 5,908 and 6,020), inside 75 percent of the smaller stacks.
- TAKEN: the session's parameters as a function. The dial built the 328 bytes of `SessionInitParams`
  and passed them by value through the host's `dial`, `open`, `new_session_in_slot` and the slot's
  `open`, each keeping a copy in its frame. The slot now takes `impl FnOnce() -> SessionInitParams`
  and calls it in its own frame (`SlotClaim::open`, never inlined), so `dial_expecting` fell from
  1,224 to 688 bytes, the worst chain of direct calls 5,480 to 4,980 (fixed), 5,004 (batching) and
  5,224 (get), and the bound of the fixed and batching images 6,216 to 6,084; the get image stays at
  6,768, its worst path being the lend of a declaration. The main stack follows the bound, 8,320 to
  8,128 bytes (192 of RAM each); the text moved by 176 bytes or less and the kit's peaks did not move.
  They did not move because the kit's reading was on another path, the connect manager's planner
  (see the next entry), which the direct chain does not follow: the reading is the worst of the paths
  the kit takes, and the dial was not it.
- NOT TAKEN, measured: the connect manager's peer entry built in place (`PeerEntry::new` written
  through a pointer into the table's next row). The entry is about a kilobyte; the compiler kept
  its copy in the planner's frame, and the bound read 6,116 (function never inlined, 32 more) and
  6,036 (inlined, the machine built in the planner's frame beside a second copy: 48 less, which is
  64 bytes of stack by the derivation). The 48 was not taken: it came from an inlining choice the
  next change to the function moves, and it cost an `unsafe` write and a different row order when
  the table is full.
- TAKEN: the peer entry as the call's own result. `PeerEntry::new` started its machine in a local
  (`engine.initialize()`) and moved the local into the entry, so the planner's `open` held the entry
  (1,000 bytes) and `new` held the local (1,080) on the kit's own path. `new` now returns the machine
  as the call's result, written into the entry as it is returned, and the table starts it once the
  entry is in its row (`PeerEntry::start`): no unsafe code and no change of row order. The kit's
  reading fell 5,904 to 5,248 bytes (fixed and batching) and 6,020 to 5,360 (get), the bound 6,084
  to 5,972 (get stays 6,768), the main stacks to 8,000, 8,000 and 9,024; text +72 bytes. The worst
  path of the bound is now the receive's lend of a declaration (`lend_declare`, 2,064 bytes) under a
  query's answer, 5,972 bytes: the next 700 bytes of the bound are there, not in the planner. The
  entry is still copied from the call's result into the table, which the kit's reading falling 656
  bytes and not the 1,080 of the local suggests; a table of cells written once, as the session slots
  are, would remove that copy (the frame was not measured after this change).
- TAKEN: the connect manager's frames. What stays on the main thread's stack is the node's own
  frames, and the kit's thread table shows every other thread of the image equal to the single-threaded
  zenoh-pico image's (`wz_zeth_rx` 1,948, `rx_q` 200 to 500, `net_mgmt` 248, `sysworkq` 248, idle 64,
  the report thread 220 to 300), so the 2,488 bytes the image reads over it in the matrix are the main
  thread's alone: 5,248 against 2,888 at the time. `drive` held the planner's actions (six, about 300
  bytes) as the result of `ask`, again in its own frame and a third time as the argument of `take`;
  they are one buffer now, filled by `ask` and read by `take` in place (`drive` 800 to 536 bytes, `ask`
  out of the chain). `reconcile` took the table of rows out and built it again to put the rows in the
  list's order, two copies of a table in one frame; the rows are rotated into place instead (the
  frame left the chain, `wz_session_mcu` 1,068 bytes less of text). The kit's reading fell to 4,280
  bytes (fixed and batching) and 5,104 (get), the direct chain to 4,172, 4,172 and 4,756, the bound
  stays 5,972 (6,768). The worst path is the receive's, under the 1,256 bytes of the main frame:
  `dispatch_unit_borrowed` 756, `decode_unit_in` 312, and `lend_declare` 2,064 under a query's answer.
- TAKEN: the loop's state in the storage's arena. `ClientNode::run` held the node (448 bytes: the
  connect manager 352, the timeouts, the pacing), its factory (68) and the session host (36) as
  locals, and a local of the main function is under every call the loop makes. They are built, out of
  line, in `NodeStorage::run` (`RunArena`, a bump arena in the all-zero `static` like the peers'
  store and the observer cell), and the loop holds three references: the main function fell from
  1,256 to 704 bytes, the direct chain from 4,172 to 3,620, the bound from 5,972 to 5,420 (get 6,768
  to 6,216), the kit's reading from 4,280 to 3,728 (get 5,104 to 4,552), and the main stacks to
  7,232, 7,232 and 8,320. The arena is 576 bytes of `.bss` (704 for the getter, 1,536 for the
  secure channel's stack type); text is +244 bytes. An image states its arena's size and the loop
  checks it when it is compiled (`run_bytes_needed`): a layer or a stack that grows past it is a
  build error that names the line, as the TLS image's was the first time it was built.
- TAKEN: four copies of a large value removed on the first dial and on the receive, found by the
  kit's own sequence (`READY`, then `stack: peak` before `session established`: the peak is the
  first tick, which dials). (1) The dial's link is made in the slot's claim (`SessionSlots::claim_with`,
  never inlined): the driver, 176 bytes on the UDP link, was held in several copies in
  `dial_expecting`, now 688 to 256 bytes; the order is the contract of the dial's tests (a bind
  refused for want of a socket is answered before any session table is touched), so `claim_with`
  makes the link first and only then counts a full table. (2) The receive's records are decoded in the
  binding that lends them: `lend_declare` was 2,064 bytes and `lend_push` 1,776, three copies of the
  largest message a record can be (a default, the value `decode` returns, the `?` that unwraps it);
  the generated `decode_into` writes it once, as `lend_response` already did. (3) The key matcher's
  view of a key, `KeyChunks`, is one array of 32 on the fixed profile (264 bytes) and not an array
  of 16 and a spill vector (over 400), which was two of them on the stack under a wildcard walk.
  (4) The peer table builds an entry in its row: `PeerEntry::init_in` over the machine's
  `new_in_place` (the engine of SCE has one), so the planner's `open` no longer holds the machine's
  kilobyte as a temporary, 1,008 bytes of frame to 200. Together: the bound 5,420 to 4,240, the
  main stacks 7,232, 7,232 and 8,320 to 5,696, 5,696 and 6,720, the kit's reading 3,640 to 3,208
  (fixed), text 160,692 bytes on the fixed image, within the gate's tolerance of the committed row.
  The first of these did not move the reading (3,640 to 3,584) and the second did not either: the
  planner's path was above them both, and was not the one the direct chain follows.
- TAKEN for the stack, text +32 bytes (160,692 to 160,724 on the fixed image): the session's bundle
  is written in its slot field by field (`SessionLinkActions::build_in`, over `write_fields!`, whose
  field list is destructured without `..` so a field left out does not compile). The four
  handshake ext chains (200 bytes each) were four slots of the frame of the function that built
  the bundle, and the bundle was a value of that function; the chains are each written by a
  function of their own (`init_ext_chain`), the slot's `open` is 520 bytes and `init_core` 32.
  The dial's frames under `wz_app_main` fell from 1,068 bytes to about 570 and the first tick's
  reading from 3,208 to 3,048. The kit's reading is 3,192 now and is set by the handshake's parse.
- TAKEN for the stack, text +104 bytes (160,724 to 160,828 on the fixed image): a received handshake
  message keeps the header byte of every entry of its extension chain (eight bytes, what the
  admission rule judges by) and the entries only of the extensions this build reads
  (`reads_received_ext`: the patch level, the region name, the remote bound, and one for each
  feature that compiles a reader), where it kept up to eight entries of 65 bytes. The inbound
  frame the decoder is lent fell by some 330 bytes, and `dispatch_unit_borrowed`, `parse_init` and
  the chain reader with it; the kit's reading fell from 3,192 to 3,048 bytes. The admission rule
  sees the same headers in the same order and the readers find an extension by its id, so a
  message is judged and read as before; an entry of an extension no module of the build reads
  is no longer owned.
- TAKEN for the stack, text +64 bytes (160,828 to 160,892 on the fixed image), `.bss` +256 bytes
  (106,770 to 107,026): the connect manager's actions (248 bytes) are a field of the manager,
  which lives in the node's storage (the run arena `RUN` 576 to 832 bytes; the loop checks it at
  compile time and refused the first build), where they were a local of `drive`, on the stack of
  the thread that ticks the manager; and a new row is built in the table's row
  (`BoundedVec::push_with`) where `reconcile` held the 152-byte row twice. The dial is off the
  longest chain, and the kit's reading fell from 3,048 to 2,888 bytes. The main stack's size
  follows the bound (4,240, set by the key matching under a query's answer) and does not move;
  the stack used falls by 160 bytes and the RAM image grows by 256, which the matrix grades as
  two rows (`stack_used` and `ram`).
- NOT TAKEN, measured: the loop's log lines (`port.log(&[...])`, arrays of parts) said by one
  out-of-line function: the frame of `wz_app_main` stayed 704 bytes (the compiler had given the
  arrays one slot) and the text grew 232 bytes.
- NOT TAKEN, measured: the four chains as an empty constant (`EMPTY_EXT_CHAIN`) given the patch
  entry after the bundle is placed: each `new_mutex(CONST)` was still a 204-byte slot, and the
  slot's `open` grew from 856 to 1,080 bytes.
- NOT TAKEN, measured: taking `judge_ext_chain`'s two helpers out of line (7 instances) moved the
  text by +16 bytes; the link-time optimizer already shares them.
- `wz_session_core` is a long tail (525 symbols in a build without LTO, none over 1.6 KB) and the
  line table is the way to rank it: the largest source files are `session_actions.rs` (3.1 KB),
  `drive.rs` (1.7 KB) and `peer_planner.rs` (1.3 KB, the planner of a client with one endpoint).
- The machine outliner and `opt-level=z` are weighed per tier (the answer path against the connect
  and declare paths), not on the whole image.

## Updating a row

Build the image (`bash scripts/kit-lane.sh build KEY`), print its row with
`python3 scripts/lib/text_owner_gate.py --emit KEY --elf ELF`, put it in `deploy/text_budget.json`
and say in `measured` what moved the text.
