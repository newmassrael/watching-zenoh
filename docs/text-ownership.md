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
