# Stack depth of the cooperative pico C ABI on an MCU

The MCU speed matrix (`docs/mcu-speed-matrix.md`, `scripts/mcu-speed.sh`) runs one pico API
program on QEMU `mps2-an385` over zenoh-pico (arm P) and over wz's pico C ABI on the cooperative
engine with `os-zephyr` (arm W). Its run of 2026-11-22 (8-byte cells) read the stacks of the two
arms, every thread's high-water mark summed:

| cell | arm P | arm W | W/P |
|---|---|---|---|
| st sub | 4,016 (main 3,128) | 12,616 (main 11,504) | 3.14 |
| mt sub | 5,532 (main 3,184, read task 1,420) | 19,368 (main 11,512, read task `wz-os` 6,744) | 3.50 |

Every thread but the two the library drives (`rx_q`, `net_mgmt`, `sysworkq`, `idle`) reads within
a few hundred bytes in both arms, so the whole gap is two threads: the program's main thread, which
opens the session, and the read task. The main thread reads 11.5 KB in both threading arms, so its
peak is reached inside `z_open`, which both arms run on it, and not in the steady read the
single-threaded arm adds there.

This page names the frames that make those two depths, what each holds, and what was done about it.

## How the frames were read

From the images that run booted (`W-st.elf`, `W-mt.elf` under the speed matrix's artifact
directory), by the method of `scripts/lib/stack_frame_gate.py`: each function's frame is what its
prologue lowers the stack pointer by (`push`/`stmdb sp!`, `sub sp`), and a chain is the sum of the
frames on a path of direct calls. Calls through a register (the task waker, `dyn` sinks, the
`SessionDrive` object) are not followed by the reader; where a chain crosses one it is joined by
hand at the function the register reaches, and those joins are marked below.

The images were built from the speed matrix's tree, which predates the base these changes were
made on by the no-heap track (the lent reassembly chains, the lent-only receive). The track changes
what some frames hold (it removes the owned projections of a lent record from the receive's
build), so the figures below are the image's, and the figures after the changes are estimates until
the matrix is run again.

## The two chains

The read task (`wz-os`, 6,744 B) is the cooperative engine's read step down to the observer's fan:

| frame | bytes |
|---|---|
| `CoopEngine::read` (`SessionDrive`) | 104 |
| `Core::poll_links` | 72 |
| `Core::poll_face` | 456 |
| `CoopLocalSet::run_until_idle` | 200 |
| the session task's poll (`SessionPump::step` inlined), through the waker | 440 |
| `dispatch_holding_finals` closure (`EventSink::event`) | 168 |
| `SlotObserverOf::dispatch_event_among` | 4,896 |

6,336 bytes, with the thread's entry and the plane leaf beneath the fan making up the rest of the
6,744 read.

The main thread (11.5 KB) runs the same task poll inside the open: `main` 320, `z_open` 1,960 (the
open on the cooperative engine and `CoopEngine::open_in` inlined in it), `Core::dial_from` 1,792
(`open_wire` inlined), `run_until_idle` 200 and the task's poll 440. Under that poll lie two paths of
about the same depth: the first poll builds the pump (`SessionPump::new`, 4,968, then the engine's
initial transition and the InitSyn's send), and every later poll during the handshake and the
initial declarations reaches the observer's fan (168 + 4,896). Either is about 11.5 KB.

## Findings

| # | frame (image) | bytes | path | cause | fix | state |
|---|---|---|---|---|---|---|
| 1 | `SessionPump::new` | 4,968 | open (main) | The 4-slot reassembly Router (4 x 608 B: one slot machine and its chain key each) built by value: the slot array made by `core::array::from_fn` in one place and moved into the Router in another, then handed to `build_in` by value. On the base the cooperative engine builds its lent Router in `open_wire` and passes it by value through `spawn_session_with_router`, the task's future and `SessionPump::with_router`, so the same 2.4 KB value lies in a frame at each step. | `ReassemblyDispatcher::init_in` writes each slot where the Router lies; `SessionPump::with_router_in` builds the pump in a place and has a maker write the Router in its field; `spawn_session_with_router` takes the maker and builds the pump in the task's own future (a place that drops the pump with the task). `open_wire` claims the chains' buffers as before and hands the maker. | commit 1 |
| 2 | `SlotObserverOf::dispatch_event_among` | 4,896 | read task, open (main) | Every plane's fan (subscribers, queryables, the peer's subscribers and queryables, liveliness, tokens, liveliness subscribers and gets, replies) inlined into one frame, with the records and views each decodes: copies of 1,672, 1,104, 272 and 264 B in its body. The frame is held on every event, however few planes the event concerns. | The nine plane entries the fan calls are `#[inline(never)]`, so the stack under the fan is the fan's own frame and the one plane running. | commit 2 |
| 3 | `z_open` | 1,960 | open (main) | The open on the cooperative engine and `CoopEngine::open_in` inlined into the export: the engine's config (about 472 B) is copied twice, and 504, 316 and 312 B values are moved, in one frame. | The open is two frames that never lie on the stack together (`CoopEngine::open_made_in`): `assemble`, never inlined, makes the config from the ABI's maker, reserves the arena and builds the engine's state, moved into the engine's own allocation in that frame; `open_links`, never inlined, binds, joins and dials over the built engine holding only its guard. The pico ABI hands the config's maker instead of the config, and `z_open` reads its request (the config's state, its snapshots, a scout) in `open_request`, never inlined, which has returned before the open. An open that fails once the engine is built ends what it began through the engine's drop (`end_links`), as a dropped session does. | done |
| 4 | `Core::dial_from` | 1,792 | open (main) | `open_wire` inlined: `SessionInitParams` (about 330 B) built and moved into the session's actions, an 872 B move, the link and its gates. | `open_wire` steps the task only after `start_wire`, never inlined, has built the session (its parameters moved into its actions), its gates and its task, spawned the task and returned: the frame the session's first steps run under (the dial's, or a face's poll for a dial answered later) holds only the wire handed back. The parameters are still a value inside `start_wire`, whose frame is off the chain. | done |
| 5 | `wz_capi_pico::session::resolve_policy` + `policy_document::compose` | 1,288 + 936 | open (main), beside the dial | The policy document resolved into values on the stack. A sibling of the dial under `z_open` (4,184 with it), below the dial's chain. | `policy_document::resolve_under_into` reads the statements one at a time and writes the policies and the session's limits into the two snapshots where they lie: no `Resolved` (the origin of every policy and limit) and no `Refusals` (room for eight), the first refusal answered. The pico ABI's open, its policy doors, its scout and its device-requires door resolve through it (`resolve_snapshots`); the resolution that records origins (`resolve_policy`) is kept as the tests' oracle. It runs under `open_request`, off the dial's chain. A config handed a document (`config-document`, a host build with a JSON5 reader) still resolves through the document's reader; that tree is the config's, on the heap. | done |
| 6 | `scout_datagram::window` | 3,184 | an open with no locator | The scouting window (an SCXML engine and its actions) built by value. Not in the matrix (its cells name a locator), but with 1 and 2 done it would set the main thread's peak for an open that scouts: `z_open` + 192 + 3,184 + the machine's turn. | `ScoutWindowPlace` holds the window where its holder lies, built once by `ScoutWindow::write_in`, never inlined, which makes the machine and writes it into its field and has returned before the window is pumped. Both windows of the engine, the datagram one and the host's, scout from a place. | done |
| 7 | `network_message::decode_one_record` | 2,720 | the copying receive (a refused frame's batch, a reassembled chain, a frame payload read out of line) | An owned `NetworkMessage` decoded on the stack. | The lent-only receive of the no-heap track leaves most of it out of the build; read again on the next image. | open |
| 8 | `make_subscriber_callback` closure | 560 | read task, beside the fan | The C sample view (`SampleMarshal`) built, then moved through `with_metadata(self)`, then bound. | Candidate: the metadata filled in place. Not on the deepest chain (`read` 104 + `deliver` 384 + 560 + the program's callback). | open |
| 9 | `reassembly_dispatch::Slot::replace` | 624 | a slot whose machine answered outside its chart | A fresh slot built by value. Rare. | none | open |

## What 1 and 2 should give

An estimate from the frames above, not a measurement. The read task becomes the chain down to the
fan (1,440 bytes), the fan's own frame and the deepest plane: about 2.5 to 3.5 KB against 6,744. The main
thread's two paths under the open's poll both lose their large frame; what is left is `main`,
`z_open` and `dial_from` (about 4.1 KB) and the poll's own chain, about 6 to 7 KB against 11.5 KB.
What stays between that and arm P is mostly findings 3 and 4.

## What 3 to 6 should give

Estimates from the frames above and what each change takes out of them, not a measurement; the
images are to be read again (see Verifying). Every frame named `never inlined` below is a frame of
its own in the image, so it is found by its symbol.

| frame | image | expected | what it holds after the change |
|---|---|---|---|
| `z_open` | 1,960 | 0.5 to 0.8 KB | The request `open_request` handed back and the open's own locals over the dial (the links, the clock, the config's maker), and no config, no core and no engine. |
| `open_request` | in `z_open` | about 1 KB, off the open's chain | The config's state, its snapshots and the request built from them. A scout for a locator runs under it. |
| `CoopEngine::assemble` | in `z_open` | 1.5 to 2.5 KB, off the open's chain | The config, the core and the engine, each moved once into the next. |
| `CoopEngine::open_links` | in `z_open` | under 0.1 KB | The guard of the engine's state and the dial's loop. |
| `Core::dial_from` | 1,792 | 0.2 to 0.3 KB | The endpoint, the dial under way and the wire handed back. |
| `Core::start_wire` | in `dial_from` | about 1.6 KB, off the chain | The session's parameters, its actions, its gates and the task's closure. |
| `resolve_snapshots`, `compose_into`, `resolve_under_into` | 1,288 + 936 | a few hundred bytes, under `open_request` | The two snapshots, the statements' list (on the heap) and one refusal. |
| `scout_datagram::window` | 3,184 | the image's less one copy of the window and the machine's making | One window, written in place, and the socket and the read's locals; `ScoutWindow::write_in` holds the making, off the pumping chain. |

The main thread's open chain after 1 to 4: `main` 320, `z_open` about 0.6 KB, `open_links` about
0.1 KB, `dial_from` about 0.25 KB, then `run_until_idle` 200 and the task's poll 440 and what lies
under it, where before it was `main`, `z_open` and `dial_from` (about 4.1 KB) and the same poll's
chain: about 2.8 KB less, so about 3.5 to 4.5 KB against 11.5 KB, as against 6 to 7 KB after 1 and 2
alone. A dial the network answers later runs its handshake's first steps under `open_links`,
`Core::poll_links` (72) and `Core::poll_face` (456 in the image, with `start_wire` now out of it)
instead of under `dial_from`; the sum is about the same. The open with no locator adds
`open_request`, the window and the machine's turn, and has returned before the dial.

## Gates and images the changes touch

Commit 1 changes the cooperative engine's open path only: `SessionPump::build_in` now takes the
Router through a maker, and the slot profile's `PumpSlots::claim` and the by-value constructors
hand it one that writes the value they built, so the fixed-memory images build their Router as
before. Commit 2 changes every image whose sessions fan events through `SlotObserverOf`, the
fixed-memory clients and nodes among them: their frames under the fan move, so the committed
chains of `scripts/lib/stack_frame_gate.py` and the bounds and site pins of
`scripts/lib/stack_bound_gate.py` (`deploy/stack_call_contracts.json`) for those images are to be
read again, and moved only after a reading. Neither gate has a row for the pico C ABI image.

The changes for 3 to 6 touch the cooperative engine's open (`open_made_in`, `assemble`,
`open_links`, `start_wire`), the pico C ABI's `z_open` and its resolution of a config, and two
modules of the session core that other images link: `policy_document` (`resolve_under` and the
document's reader now select through the same two functions, `select_policy` and
`select_stated_limit`, as `resolve_under_into` does) and `scouting_host` (`ScoutWindow::new`
writes the window through `write_in`). An image whose chains the two gates hold and that resolves
policies or scouts may see those frames move.

## Verifying

- `bash scripts/mcu-speed.sh --sizes 8`: the stack line of each cell (`stack_bytes`, per thread in
  the cell's console), against the figures in the first table.
- The frames of the image it built: `arm-none-eabi-objdump -d --no-show-raw-insn -C <image>`,
  the prologue of `SessionPump::with_router_in`'s caller, of `dispatch_event_among` and of each
  plane's `dispatch_iteration_event*`.
- The unit tests of the changes: `cargo test -p wz-session-core --features reassembly --lib
  a_router_built_in_place` and `cargo test -p wz-runtime-coop --features
  session-unicast,alloc,reassembly --lib -- in_place a_lent_router_built_in_place
  a_session_spawned_over_a_router`.
- The frames of 3 to 6 in the image: the prologues of `z_open`, `open_request`,
  `CoopEngine::assemble`, `CoopEngine::open_links`, `Core::dial_from`, `Core::start_wire`,
  `resolve_snapshots` and, in an image that scouts, `scout_datagram::window` and
  `ScoutWindow::write_in`.
- The unit tests of 3 to 6: `cargo test -p wz-session-core --lib
  a_resolution_written_into_the_snapshots_answers_what_resolve_under_answers`, `cargo test -p
  wz-capi-coop --features listen,scout-datagram --lib -- a_config_made_inside_the_open
  an_open_whose_dial_is_refused a_window_built_in_its_place` and `cargo test -p wz-capi-pico --lib
  the_open_resolves_the_snapshots_the_record_of_origins_resolves`.
