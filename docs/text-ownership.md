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
- TAKEN for the stack, text -112 bytes (160,892 to 160,780 on the fixed image): the key matcher's
  view of a key (`KeyChunks`) keeps its 32 slots uninitialised and writes each as its chunk is
  found, where `empty()` built an array of 32 fat pointers (a loop of stores, and a second copy of
  the view, 256 bytes, in the frame of `keyexpr_intersects_target`). The bound fell from 4,240 to
  3,816 bytes (the longest path under the observer is a query's reply through the network
  stack's send now) and the main stack, which follows it, from 5,696 to 5,120: 576 bytes of
  `stack_reserved` on the fixed image; 5,376 and 6,336 on the batching and get images.
- TAKEN for the stack, text -424 bytes (160,780 to 160,356 on the fixed image; -472 on the batching
  image and -664 on the get image): the node's set-up and its loop are two functions. The main
  function (`wz_app_main`, with `fixed_client::run`, `ClientNode::run` and what they inlined) was
  one frame of 704 bytes for the life of the node, because the set-up's values (the 152-byte
  node, the identity, the key, the stack, the zid in two forms) and the loop's were one function's
  slots; the set-up is `ClientNode::start`, inlined into the image's own `start` (out of line, its
  frame gone before the first round), and the loop is `RunningNode::drive` over what `start`
  hands back (the tasks' pool, the node by reference, the plane, the application, the clock, the
  watch: a few words). `ClientNode::run`, which the host node calls, is both in sequence. The main
  function is 176 bytes of frame and the loop 400. The chain 2,784 to 2,616 bytes, the bound 3,816
  to 3,352 (the dial is the longest path again), the main stack 5,120 to 4,480, the kit's reading
  2,888 to 2,696 (the single-thread zenoh-pico image's main thread reads 2,888). The text fell
  with it, and the symbol table says where: `check_outbound_keyexpr_pico_safe`,
  `TimerQueue::pop_expired` and `run_until_idle` (946 bytes) stood on their own and are inlined
  into the loop now, which calls each from one site. Why the compiler inlines them into the loop
  and did not into the old main function was not looked at. The text-owner rows moved with it: the 3,594
  bytes of the main function were `c:wz_` (the owner of a symbol is read off its name, and the
  main function's is a C name), and are `wz_session_mcu` and `wz_zephyr_admin_node` now.
- TAKEN, text -6,488 bytes (160,356 to 153,868 on the fixed image; -6,480 on the batching image and
  -1,688 on the get image), bss -640 bytes: a node reads off the wire only the kinds it asked for.
  The slot profile decodes each record where it lies, one decoder for each kind of message, and
  the Zephyr client that only answers carried the decoders of a Push (it declares no subscriber:
  `Z_FEATURE_SUBSCRIPTION` is off in the pico it is compared with), a Response and a ResponseFinal
  (it asks no query) beside the Request it is there for; a router sends none of them to it. They are
  `rx-push` and `rx-response` of `wz-session-core` now, selectors that pull no codec (the codec of a
  kind writes it too: a queryable writes Responses), turned on by what makes a node read the kind:
  `declare-subscriber` and `adminspace-write` (a config write is a Put on an admin key) for the Push,
  `query-get` (in `wz-session-mcu` too) for the Response, `session-unicast-accept` and
  `session-multicast` for both (a node a peer opens a session to, or a group member, is written to and
  asked). A build without them reads such a kind as a MID it has no decoder for, which ends the walk
  of that frame as an unknown MID does; `InPlaceRecord::push()`, `response()` and `response_final()`
  answer `None` there. A router does not send a kind the node did not ask for, so the answers on the
  kit are the same (2,000 queries of each document, answered). The first run of the get image, with
  `wz-session-mcu`'s `query-get` not yet turning `rx-response` on, never got a Response and the kit
  lane said so (no getter line in 150 s); that is the check this change leans on.
- TAKEN, text -4,920 bytes (153,868 to 148,948 on the fixed image; -5,016 on the batching image and
  -4,488 on the get image): the same for the control records of a peer, `rx-control`: the Declare, the
  Interest and the Oam. The answering client sends no Interest and holds no token, and a router
  declares a key expression to a face only when the face is on its north side or sent a key-expression
  interest, and a subscriber only to a face with a matching interest (read in the pinned zenoh:
  `zenoh/src/net/routing/dispatcher/resource.rs` @ `pub fn decl_key`, `zenoh/src/net/routing/hat/broker/pubsub.rs`
  @ `.filter(|(_, i)| i.options.subscribers() && i.matches(res))`), so none reaches it; the node
  keeps the limits of the remote tables at zero (`MAX_REMOTE_DECLS`, `MAX_INBOUND_SUB_INTERESTS`)
  for the same reason. Turned on by `declare-subscriber`, `declare-token`, `liveliness-token`,
  `liveliness-subscriber`, `liveliness-get`, `session-unicast-accept` and `session-multicast`; `query-get`
  does not (a client that asks is answered, and told nothing it did not ask). `wz_session_core` fell
  3,488 bytes and `wz_codecs` 1,354; the stack call contracts lost the sites of the Declare and the
  Interest (`record` 3 to 1, `own-mapping` 1 to 0). The kit answered 2,000 queries of each document
  and the get image's getter reported on its queries, as before. An experiment that stopped at taking
  the three arms out of the walk measured 3,560 bytes, less than the 4,920 of the change, because the
  verdict function they share and the sink arms were still linked.
- TAKEN, text -680 bytes (148,948 to 148,268 on the fixed image; -672 on the batching and the get
  image): the retry schedule's growth in integer arithmetic. `(delay as f64 * factor) as u64`, the
  one floating-point expression of the image, is a call to the soft-float multiply, two conversions
  and two comparisons on a target with no double-precision unit: `__muldf3` 778 bytes, `__aeabi_d2ulz`
  116, `__aeabi_ul2d` 112, `__aeabi_dcmpge` 114, `__aeabi_dcmpgt` 106 and `__aeabi_dmul` 12, 1,238
  bytes, all called from the planner's `perform` and nothing else. `retry_period::grown_ms` returns
  the expression's value for every input, with its two roundings (the delay to the nearest `f64`,
  the product to 53 significant bits, ties to even), the truncation and the saturation, and no
  floating-point operation; two tests hold it equal to the expression, over a grid of the edges
  (delays around 2^53 and 2^64; factors exact, inexact, tiny, huge, subnormal, infinite, NaN and
  negative) and over 250,000 random pairs of bit patterns. It costs 558 bytes (`round_to_significant`
  372, the rest inlined at the manager's two calls), which is what the 680 is net of. Taking
  `grown_ms` out of line, one copy for the two calls, cost 40 bytes more. The schedule is one
  implementation for every profile, so the host and the board cannot differ in it.
- TAKEN, text -496 bytes (148,268 to 147,772 on the fixed image; 152,564 to 152,060 on the batching
  and 165,876 to 165,372 on the get image): the endpoint text read in one byte scan.
  `dial::parse_endpoint` was `str::strip_prefix`, a search for either of two characters, `rsplit_once`,
  `split('.')` and the generic `str::parse::<T>` for the u8 of each octet and the u16 of the port,
  which the compiler writes once for each width: 886 bytes for the one function the slot dialer calls
  at two places. Now `dial::decimal` reads the digits of both the port and the octets against a
  maximum, and the scan is over bytes: 386 bytes. The tests keep the old refusals (a `+` sign, a
  port of 0, 256, a fifth field, a name, a bracketed address, `?` and `#`) and add the empty
  fields, a number wider than any integer, leading zeros, and the widest of each number.
- TAKEN, text -216 bytes (147,772 to 147,556 on the fixed image; -376 on the batching image, 152,060
  to 151,684, and -208 on the get image, 165,372 to 165,164): the Arm EABI's zeroing call is the
  libc `memset`. The Rust code generator calls `__aeabi_memclr` for every cleared struct and array;
  the image's libc has no such symbol, so the link took the compiler runtime's, 208 bytes of its own
  byte loop beside the `memset` the image carries (the single-thread pico image has no
  `__aeabi_memclr` at all: its C code calls `memset`). `wz_board_hooks.c` defines it as
  `memset(dest, 0, n)`; the runtime's copy is weak, so this one is kept, and `__aeabi_memclr4` and
  `__aeabi_memclr8` stay the runtime's (174 bytes each, in the pico image too). Found by listing the
  C-named symbols the graded wz image has and the graded pico image has not (13, 886 bytes: this one,
  `clock_settime` and `z_impl_k_usleep`, which are the board's wall clock and the finer tick,
  `bind` and `getsockname`, which are the link's local port, and the two address hooks).
- TAKEN, text -1,352 bytes (147,556 to 146,204 on the fixed image; -2,280 on the batching image,
  151,684 to 149,404, and -1,304 on the get image, 165,164 to 163,860), the stack chain 2,616 to
  2,560, the bound 3,352 to 3,296 and the kit's peak 2,696 to 2,672: the runtime takes no interrupt
  lock (`CONFIG_WZ_SINGLE_CONTEXT`, `wz-runtime-coop`'s `single-context`). The line table put the
  largest line of the image's own code at `glue.rs` `irq_lock` and `irq_unlock`: 127 calls of
  `wz_irq_lock` and 142 of `wz_irq_unlock` in the linked image, 33 in `SessionActionsBinding`, 20 in
  `SessionLinkActions`, 14 in `decide_unit_in`, 12 in the dialler, 9 in the node's loop; each is a
  borrow of a `critical_section::Mutex<RefCell<T>>` cell, a call to the kernel and back with the
  `RefCell`'s flag around it. The guard is for an interrupt handler or another thread that reaches
  the same cell; this image has none (its Rust has no interrupt handler, timer or thread, and the
  Ethernet driver's threads call the MAC in `zeth_exports.rs` and nothing of the runtime), so the
  borrow takes no lock. It is a contract the image states and not a default: off, the build is the
  one before; the board's overlay turns it on. A board whose driver feeds the loop from an interrupt
  through the runtime's cells leaves it off. The same cell types, the same borrows and the same
  `RefCell` flag checks remain, so a re-entrant borrow still stops the node as it did.
- NOT AVOIDED, measured 2026-10-30: the pin `b1ede72108` that another session took (ADR 0065, the
  codecs that may refuse an encode return a `Result`) holds ADR 0064's shared engine core below it,
  so it carries what the measurement below read: against Round 3944's rows the fixed image's text
  is +3,132 bytes (146,204 to 149,336), the batching's +3,108 and the get image's +4,764; the
  stack chain 2,560 to 2,740, the bound 3,296 to 3,764 (over three quarters of the 4,480-byte stack,
  so the fixed and batching overlays' stack is 5,056 now) and the kit's peak 2,672 to 3,000. The
  rows, the contract (`engine-host` and `engine-behaviour`, one rule for the file of each of the
  engine's two traits behind a reference, with the number of sites pinned for each image, and the
  lines of `engine-clock` and the two `tx_buf.rs` rules moved with the pin) and the stack are moved
  to those readings with the reason; the cost is SCE's to take out, and the rows follow it down.
- TAKEN, measured 2026-10-30: the pin `f167223931` (SCE ADRs 0066 to 0071: packed table rows, the
  engine taking events and states as numbers, its constructor and its exit walk out of line, the
  workspace's buffers uninitialised until written), on the three images at the same wz tree. Against
  `b1ede72108` the text is -3,124 (fixed, 146,212), -3,108 (batching, 149,404) and -3,100 (get,
  165,524); against 49e40c9a72, before the shared core, +8, 0 and +1,664. `sce_rust_runtime` is
  7,398 bytes (9,512 at `b1ede72108`, 7,908 for the two machines' copies). The stack chain of the
  fixed and batching images is 2,536 (2,740; 2,560 before the shared core): the dial's `build_in`
  is 80 bytes where it was 600 and `take_microstep` 120 where it was 232. The bound is 3,604
  (3,764; 3,296 before) and the kit's peak 2,912 (3,000; 2,672), so their overlays' stack is 4,864.
  The get image's chain and bound are what they were before the shared core, 3,372 and 4,564. The
  `engine-host` and `engine-behaviour` rules now claim 42 and 17 sites. What is left of the cost is
  the core's `enter_states` frame (200 bytes, copies of the entry set's handles) and the two
  machines' own tables; SCE works on the first.
- TAKEN, measured 2026-10-30: the Request body's Put and Del arms out of the zenoh-preset images
  (`CONFIG_WZ_REQUEST_PUT_DEL=n` in `t2g_client_fixed.conf`, default `y` in Kconfig; `wz-codecs` and
  `wz-session-core` feature `request-put-del`, SCE ADR 0072 at `44e6d3083b`). Pinned zenoh 1.10.1
  accepts only a Query as a request body (`commons/zenoh-codec/src/zenoh/mod.rs` @
  `id::QUERY => RequestBody::Query`);
  zenoh-pico takes all three, and the arms are its contract, so every other build keeps them. The
  decode of a Put or Del tag under a Request is refused (`CodecError::VariantArmNotBuilt`) and
  `MsgPutView`'s and `MsgDelView`'s decoders (the symbols are not in the fixed image), which only the
  Request reached, are not linked, nor is the code that judges their extension chains. Against the
  same tree with the arms: -1,488 bytes (fixed, 144,724), -1,488 (batching, 147,916) and -2,096 (get,
  163,428; the Reply's own Put and Del arms stay). Against 49e40c9a72: -1,480, -1,488 and -432. The
  stack chain, the bound and the kit's peak did not move.
- TAKEN, measured 2026-10-30: the pin `6ba84c3f37` (the entry walk bounded by two steps a level for a
  document with no `<parallel>`, where it was three): the text did not move (144,724; 147,916;
  163,428), `run_turn` is 148 bytes where it was 164, the bound of the fixed and batching images 3,588
  (3,604) and their main stack 4,800 bytes (4,864, 64 bytes of `.bss`). The chain (2,536) and the
  kit's peak (2,912) did not move.
- TAKEN, measured 2026-10-30: `__aeabi_memclr4`, `__aeabi_memclr8` and `__aeabi_memset8` (and the two
  `memset` variants this image does not call) answered by the libc `memset` in
  `deploy/zephyr-common/wz_board_hooks.c`, as `__aeabi_memclr` already was. The compiler runtime's
  copies were three loops of 174, 174 and 184 bytes; they are stubs of 8, 8 and 10 now. -504 bytes
  on each of the three images (144,220; 147,412; 162,924), the stack and the other rows unmoved. It
  is not a gain against zenoh-pico: the pico compare image links the same board hooks and calls the
  same Arm EABI variants (GCC emits them for a cleared object), so its text fell by the same 504
  bytes (145,364 to 144,860 in run 20261030T193533) and the ratio stayed 1.0031 (145,312 against
  144,860). Both images are smaller; the gap, 452 bytes, is what it was.
- TAKEN, measured 2026-10-30: the stack contract stops counting the edge from the entry walk to
  the Behaviour hooks (`deploy/stack_call_contracts.json`, rule `walk-entry-tables`): `walk_entry`,
  `effective_target_states_on` and `is_in_final_state` take no Behaviour, and their four calls
  through a register are the history and parallel procedures read from the document's tables, which
  a document without a `<history>` and a `<parallel>` does not carry and so does not link (the rule's
  premise, which the gate checks: no function of the image is named for either). The hooks are
  called from `enter_states`, beside them. The bound of the fixed and batching images fell from
  3,588 to 3,476 bytes and their main stack from 4,800 to 4,672 (128 bytes of `.bss`); the text, the
  chain and the kit's peak, which are what the image holds and runs, did not move. The SCE owner's
  own probe resolves each call by what its source can reach (`STACK_DYN` in its footprint budget).
- TAKEN, measured 2026-10-30: three frames of the node, found by reading what the kit's stack reading
  is made of. The console prints `stack: peak N` when the high-water mark rises, and the second
  line of a run (after "session established") is the deepest path of the run: it was the
  handshake's, not a query's, and no change to the answer path moved it (a deferral of the
  reply send to the end of the datagram's receive took 628 bytes off that path, and was dropped:
  the reading did not move and the text rose 300 bytes). What moved it: (1) the receive's reading
  of a handshake message is `read_unit_in`, out of line from `dispatch_unit_in`, which gives the
  engine the event of the admitted message once the 400-byte decoded-message slot is gone (the
  engine's answer writes and sends the next message, and the slot was under it): the reading 2,928
  to 2,720; (2) `reconcile` orders the rows by swaps of neighbours and not by `rotate_right(1)`
  (the library's rotation held a row and a buffer in the frame): 448 bytes of frame to 328, the
  reading at READY 2,608 to 2,488, the chain 2,536 to 2,416, the bound 3,476 to 3,356 and the main
  stack 4,672 to 4,480 bytes; (3) `log_parts` and `log_args` fill one buffer and do not take one back
  by value (832 bytes of frame, the largest of the image, to under 736). Text: -48 (fixed and
  batching) and -64 (get) bytes; the kit's reading 2,896 to 2,720.
- TAKEN, measured 2026-10-30: the send's dispatch is one copy on the slot profile
  (`dispatch_network_message_at`, with `as_encoder` handing the message's encoder over as a trait
  object, as the host build already did). The profile had kept the closure itself, a copy of the
  dispatch for each kind of message with the encoder inlined in it, because the stack gate
  followed only direct calls; the bound gate follows a call through a register by the rule that
  claims its site (`tx-encoder`, the call's place in `core::ops::function`, with its sites pinned
  for each image), so that reason is gone. Three copies of 1,334, 810 and 632 bytes are one now:
  -816 (fixed, 143,356), -2,272 (batching, 145,092: each copy carries the batching window's code) and
  -1,216 (get, 161,644). The get image's stack came down with it, the reply's dispatch having been
  a frame of 2,448 bytes with its encoder: the chain 3,372 to 2,972, the bound 4,564 to 4,284, its
  main stack 6,144 to 5,760 bytes and the kit's reading 4,328 to 4,168; the fixed and batching
  images' stack did not move. One call through a pointer per message sent.
- NOT TAKEN, measured 2026-10-30: SCE ADR 0064 (the engine's Appendix D once per program over each
  document's tables, `vendor/sce` 6f72d5975e), on the three images at the same wz tree. Against the
  commit before it (49e40c9a72) the text was +2,444 (fixed), +2,428 (batching) and +2,456 (get), and
  the stack peak of the kit run 2,696 to 3,040 bytes. The `sce_rust_runtime` symbols went from 7,908
  (the two machines, 3,586 and 3,946) to 9,512 (one core of 6,502 and two shells of 1,286 and
  1,724). With two machines the shared core costs more than the copy it removes; the SCE side
  works on the shells (`first_enabled_transition`, `take_internal_event`, `end_run`) and on the
  core under `opt-level=s`, and sends a commit when its probe shows two machines below the old
  size. The pin stays at 6dbfa6a521.
- NOT TAKEN, measured: `ClientNode::start` out of line (a call from the image's own `start`): the
  text was 161,700 bytes, 920 more than the image before, for the same frames: the node (152
  bytes) was passed by value across the call and the two functions each paid a prologue.
- NOT TAKEN, measured: the loop's log lines (`port.log(&[...])`, arrays of parts) said by one
  out-of-line function, in the loop (after the set-up was out of the main function, so the loop was a
  frame of its own): the loop stayed 392 bytes (its slots are the tick's, inlined) and the text grew
  136 bytes. Before that split, in the main function: it stayed 704 and the text grew 232.
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
