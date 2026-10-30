#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R3320 (no register item) -- no stack frame of a final MCU image may be larger
than half the stack the image declares for its task.

## What was missing

A task's stack is a number the image declares, and a function's frame is a number
only the compiler knows. Nothing compared them. Round 3318 is the case: the lwIP
socket state (24.7 KB, the receive queue) went through a `MaybeUninit` local and a
copy out, and the FreeRTOS demo's task function, whose frame was 4,816 bytes,
became a 28,056-byte frame on a 16 KiB task stack. The image printed its first
line and never booted. The runtime check that exists for a stack (the peak a
QEMU lane reads back) cannot see this: the overflow happens before the lane has a
peak to read, and the symptom is a 30 s timeout that names nothing.

## What is held

For each image in `IMAGES` this reads the declared stack out of the image's own
source (the constant the task is created with, not a number restated here), reads
the frame of every function out of the linked ELF's disassembly, and fails when
any single frame exceeds `BUDGET_NUM / BUDGET_DEN` of the stack: a frame that
takes half the stack leaves the rest for its whole call chain, which no
measurement of the callees can make up. The entry function of the task must be
found with a frame, so a renamed task is a finding and not a pass.

## The worst chain (storage-policy D5)

A frame bound does not see a deep chain of small frames. For an image that commits a `peak`
this also reads the call graph of the same disassembly and takes the deepest chain of direct
calls under the thread's entry, the polled tasks of the executor included ([`worst_chain`]).
It fails when that chain is over the declared stack, and when it is further from the committed
figure than [`PEAK_TOLERANCE`], so a change that moves the stack is a recorded change and not a
number nobody looked at. It is not a bound: a call through a register is not followed (the count
on the path is printed), and a path the graph has that no run takes is counted.

## How a frame is read

The compiler lowers the stack pointer in a function's first few instructions, and
this adds what it finds there: the registers a `push` saves, `sub sp, #N`, and the
`movw`/`movt` pair behind `sub sp, sp, rN` that a frame too large for an immediate
needs. It is a reading of the prologue, not an analysis of the call graph: it does
not follow a callee's frame, and a frame built by an instruction pattern it does
not know reads as 0. The selftest holds each pattern it does know, and the
population check holds the other side, an image that yields almost no frames is
refused (a disassembly this does not understand is not an image with small
frames).

## Modes

`--check KEY` judges one image whose ELF has been built; `--population` is the part
that needs no build (every image's source constant is found, once); `--selftest`
drives the frame reader and the rule; `--list` prints the keys.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

#: A frame may take at most this fraction of the declared stack.
BUDGET_NUM = 1
BUDGET_DEN = 2

#: An image whose disassembly yields fewer functions with a frame than this is one
#: this reader did not understand, not one with small frames.
MIN_FRAMED_FUNCTIONS = 50

#: The committed worst chain may differ from the one an ELF yields by this much before the gate
#: asks for the figure to be re-committed with its reason. A compiler's inlining moves a chain
#: by a few frames' worth of spill; a change to the code moves it by more.
PEAK_TOLERANCE = 128

#: A function name that is the end of the program (a panic). A chain that runs into one
#: is a path no run takes to its end, so what lies beneath it is not part of the peak.
_COLD = re.compile(
    r"panic|unwrap_failed|expect_failed|rust_begin_unwind|index_fail|slice_(?:start|end)_index"
)

#: The name of the functions an executor calls through a function pointer, one per task type: no
#: `bl` names them, so each is a root of its own, called from the frame of the thread's entry.
POLLED_TASK = "poll_erased"


@dataclass(frozen=True)
class Image:
    key: str
    elf: str | None  # relative to the repository root; None where the build dir is the caller's
    source: str  # the file that declares the task's stack
    pattern: str  # one capture group: the stack, in `unit` bytes
    unit: int
    entry: str  # a substring of the demangled name of the task's entry function
    #: The worst chain of direct calls under the entry, in bytes, as last committed; None where
    #: no figure is committed yet and the gate only reports it.
    peak: int | None = None


IMAGES = (
    Image(
        key="frt",
        elf="deploy/mcu-freertos-demo/target/thumbv7m-none-eabi/release/mcu-freertos-demo",
        source="deploy/mcu-freertos-demo/src/main.rs",
        pattern=r"const WZ_TASK_STACK_WORDS: u16 = (\d+);",
        unit=4,
        entry="mcu_freertos_demo::wz_task",
    ),
    Image(
        key="frt2",
        elf=(
            "deploy/mcu-freertos-demo/target-two-session/thumbv7m-none-eabi/release/"
            "mcu-freertos-two-session"
        ),
        source="deploy/mcu-freertos-demo/src/two_session/main.rs",
        pattern=r"const WZ_TASK_STACK_WORDS: u16 = (\d+);",
        unit=4,
        entry="wz_task",
    ),
    # The Zephyr node on the fixed-memory profile: its main thread's stack is the overlay's
    # `CONFIG_MAIN_STACK_SIZE`, and the image is built by west into a directory Layer Qzb
    # owns, so the caller names the ELF and the objdump of the SDK that linked it.
    # The node's loop (`fixed_node::run`) is inlined into `start`, the function the board's
    # `wz_app_main` calls, so `start` is the frame the loop's own locals lie in (4,680 bytes
    # in the image of 2026-10-22). It was a function of its own once, and the gate named it
    # then; a name that has no frame is a gate that judged nothing, which it now says.
    #
    # Since the peer tables went to a static (round 3618) the hosted image names no frame for
    # `start`: the three hosted images before it read 4,664 bytes for it, the three after it
    # none (runs of 2026-10-25, 05:13 UTC and 06:35 UTC). What it held was the tables, which are
    # not on the stack now, so what is left of it is inlined into `wz_app_main`, the thread's
    # entry symbol, as the client's `run` is. The entry is that symbol, which is the frame the
    # loop's own locals lie in whichever way `start` is compiled.
    Image(
        key="zephyr-fixed",
        elf=None,
        source="deploy/zephyr-admin-node/overlays/t2g_fixed.conf",
        pattern=r"(?m)^CONFIG_MAIN_STACK_SIZE=(\d+)\s*$",
        unit=1,
        entry="wz_app_main",
    ),
    # The Zephyr CLIENT on the fixed-memory profile: the same rule, over the overlay of its own.
    # Its `run` is inlined into the board's `wz_app_main`, which is the thread's entry symbol.
    #
    # `peak` is the worst chain of direct calls the reader follows (the handshake path:
    # `wz_app_main`, the polled pump task, `dispatch_copied`, the observer's drain and
    # `dispatch_network_message_at`), read from the image of 2026-10-23 whose node is
    # `wz_session_mcu::slot_node`, shared with the host node: 6,904 bytes, 64 more than the
    # image of the same tree with the node written in `fixed_client.rs` (6,840), all of it in
    # `wz_app_main`'s own frame (1,552 against 1,488). The kit's own reading of that image over a
    # dial, a handshake and 4000 answered queries is 6,000 bytes of the main stack, so the chain
    # is above what a run reaches: it counts a call no run makes in that order. It is the figure a
    # change to the code moves, and is held for that.
    #
    # 7,128 bytes in the hosted image of 2026-10-25 (10 frames, 13 calls through a register not
    # followed), 224 above the figure above: 208 of it is `wz_app_main`'s own frame (1,760 against
    # 1,552), which holds the whole node's construction because `run` is inlined into it, and 16 is
    # the frames beneath. What the node's construction gained since is the declared node's entities
    # (a subscription's answer from a cell, the liveliness tokens), the listening acceptor and the
    # group plane, each a value `ClientNode` holds and `run` takes apart; the two this image has
    # (`Listening::NONE` and `NoPlane`) are zero-sized, so the growth is the code around them and
    # not their storage. Read off the failing run's own report, not derived: the first run to show
    # 7,064 (frame 1,688) is the one before the listener and the plane landed, and the commits in
    # between are not separated further than that.
    #
    # 7,540 bytes in the hosted image of run 40180823025 (head 4b60f87e5, 15 frames, 10 calls
    # through a register not followed), 412 above the figure above. The worst chain is no longer
    # the handshake path: it runs through the connect manager, which the node ticks from
    # `wz_app_main` (1,856): `ConnectManager::tick` 1,824, two frames of its own beneath it (392
    # and 120), `SlotDialer::dial` 1,216, the pump's `PumpSlots` 64 and what is under it. The
    # manager holds its peers by the shared planner since round 3613, and by a 17-byte key since
    # round 3629 (it was a 64-byte endpoint text in every table, action and sort, and the chain
    # read 8,900 then, in the hosted image of 2026-10-25 07:21 UTC). It is 1,676 bytes under the
    # stack. Read off the failing run's own report, not derived.
    #
    # 7,280 bytes in the hosted image of run 40197999107 (head 4d9543fcb, 10 frames, 9 calls
    # through a register not followed), 260 BELOW the figure above. The same job read 7,644 over 15
    # frames at the head of run 40187337746 (5fe6b421c), so the chain moves by a few hundred bytes
    # between trees that change nothing this node's loop calls: it is the frames of the manager's
    # tick, `SlotDialer::dial` and the pump (1,200 to 1,900 bytes each) as the compiler inlines
    # them. The tolerance of 128 is smaller than that spread, so the row follows what the hosted
    # run reads and not what a change should have caused; the cause of the fall from 15 frames to
    # 10 was not separated.
    #
    # 6,940 bytes in the bench host's build of 2026-10-27 over 15 frames, which is what the hosted
    # image reads for the same tree: the host read 7,152 where the hosted job read 7,296 before the
    # console line's buffer left `wz_app_main` (-144), the two were equal at that tree. The
    # not-a-Frame dispatch of `wz-session-core` is three steps now (`decode_unit_in`,
    # `decide_unit_in`, then the engine's event in `dispatch_unit_in`), so the 720-byte decoded
    # message is the only copy held across them, and the worst chain is no longer the engine's
    # answer to a handshake under that dispatch (2,432 bytes of frame) but the connect manager's
    # dial path: `wz_app_main` 1,784, `ConnectManager::reconcile` 1,280 and two frames of its own
    # (416, 112), `SlotDialer::dial_expecting` 1,216, the pump's `PumpSlots` 64.
    #
    # 6,372 bytes after the SCE pin moved to `6dbfa6a521` (576 less, the bench host's build, 15
    # frames, 10 calls through a register not followed). The engine's microstep buffers are sized
    # to each document's state tree there, which took `decide_unit_in` from 3,024 to 936 bytes, and
    # the worst chain is still the dial path, now through the pump into the engine's open step:
    # `wz_app_main` 1,784, `ConnectManager::reconcile` 1,280 with its two frames (416, 112),
    # `SlotDialer::dial_expecting` 1,216, `PumpSlots` 64, `SessionPump` 216, four engine frames
    # (40, 56, 40, 112), `enter_entry_set` 40, `SessionActionsBinding` 544 and the initial-SN hash
    # (`Shake128::absorb` 20, `keccak::f1600` 432).
    #
    # `peak` is 5,896 bytes with `CONFIG_WZ_INITIAL_SN_COMPACT` (the fixed overlay turns it on):
    # the initial-SN hash is a function of no frame of its own, so the two frames above are not
    # on the chain, 476 bytes less, at 17 frames and 12 calls through a register not followed.
    # The kit's reading did not move (5,904 in the resource budget's row).
    #
    # `peak` is 5,512 bytes once the connect manager's `drive` and `ask` take the planner's call as a
    # trait object: each of the manager's thirteen calls had its own copy of both, and the main frame
    # that held them fell from 1,792 to 1,256 bytes (the manager's frame 1,280 to 1,056, and the one
    # under it 416 to 800, the loop of `drive` now being its own frame). The kit's reading did not
    # move, so it is 392 bytes over the chain: the row carries `chain_misses`.
    #
    # `peak` is 5,480 bytes with the session's link driver named by its type
    # (`SessionRuntime::Driver`): the calls the session makes through the link are direct calls,
    # 3 fewer through a register on the path (9), and 32 bytes less. The kit's reading did not move
    # (5,904), so it is 424 bytes over the chain. The 5,512 before was not a bound either: the
    # connect manager's trait object had put a register call in `ask`, which hid its callee's
    # frame from this reader, so part of the fall to it was a call this reader cannot follow.
    #
    # `peak` is 4,980 bytes once the dial hands the slot the function that makes the session's
    # parameters, and no longer the parameters: they were copied into the frame of each call they
    # passed through (328 bytes), and `dial_expecting` fell from 1,224 to 688 bytes. The slot's
    # `open` is a frame of 856 bytes beneath it, which holds them while the bundle is built. The
    # kit's reading did not move, 5,904, so it is 924 bytes over the chain: the path that sets it
    # is not this one (the bound, 6,084, follows the calls through a register).
    #
    # `peak` is 4,172 bytes once the connect manager's actions are one buffer that `drive` fills
    # through `ask` and `take` reads in place (`drive` 800 to 536 bytes, `ask` gone from the chain)
    # and `reconcile` puts the rows in the list's order in place (it held two copies of the table,
    # and left the chain). The worst chain is now the receive's: `poll_erased`,
    # `dispatch_datagram_unit`, `dispatch_copied`, `dispatch_unit_borrowed` (756), `decode_unit_in`
    # under the main frame, 13 frames and 3 calls through a register. The kit's reading is 4,280,
    # 108 over the chain (it was 5,248 while the dial and the planner were the worst paths).
    #
    # `peak` is 3,620 bytes once the loop's node, factory and host are built in the storage's arena
    # (`NodeStorage::run`, 576 bytes of `.bss`) and not held as locals of the main function, which
    # is 704 bytes of frame and was 1,256: they were under every call the loop makes. The same
    # receive chain, 13 frames; the kit's reading is 3,728, 108 over.
    #
    # `peak` is 3,564 bytes once the receive decodes a transport message into a slot its caller
    # lends and no frame between the parser and the judgement holds a copy of it: `parse_init`
    # (1,008 bytes, a local frame of 712 beside the caller's) is no longer the deepest path, and
    # the dial is: `wz_app_main` 704, `reconcile` 456, `drive` 536, `dial_peer` 112,
    # `dial_expecting` 688, the slot's `open` 856, `ext_chain_of` 212, 7 frames and 7 calls through
    # a register. The kit's reading is 3,640, 76 over.
    #
    # `peak` is 3,192 bytes once the dial's link is made in the slot's claim (`claim_with`: the
    # 176-byte driver is no longer a copy in `dial_expecting`'s frame) and the receive's records are
    # decoded in the binding that lends them (`lend_declare` 2,064 bytes and `lend_push` 1,776 were
    # a default, the decode's return value and the unwrapped copy of the largest message a record
    # can be; the generated `decode_into` writes it once): the largest frame is now the eager
    # `Response` record, 1,280 bytes, and the chain is 12 frames.
    #
    # `peak` is 3,132 bytes once the peer table builds an entry in its row (`PeerEntry::init_in`;
    # the planner's `open` was 1,008 bytes of frame, the machine's kilobyte as a temporary) and the
    # key matcher's view of a key is one array on this profile: the dial is the longest direct
    # chain, 7 frames: `wz_app_main` 704, `reconcile` 456, `drive` 536, `dial_peer` 112,
    # `dial_expecting` 256, the slot's `open` 856, `ext_chain_of` 212, and 9 calls through a
    # register on the path. The kit's reading was 3,208, 76 over.
    #
    # `peak` is 3,088 bytes once the session's bundle is written in its slot field by field
    # (`SessionLinkActions::build_in`, the four handshake ext chains each written by a function of
    # its own): the slot's `open`, `init_core` and the chain writer are about 570 bytes where
    # `open` and `ext_chain_of` were 1,068, and the longest direct chain is the handshake's parse
    # now, 13 frames: `wz_app_main` 704, the executor's poll 112, `dispatch_datagram_unit` 168,
    # `dispatch_copied` 80, `dispatch_unit_borrowed` 768 (it holds the 720-byte inbound frame),
    # `decode_unit_in` 320, `parse_unit_into` 56, `parse_init` 432, `decode_handshake_ext_chain_into`
    # 304 and the codec's four, 3 calls through a register. The kit's reading is 3,192, 104 over; the
    # first tick, which dials, reads 3,048.
    #
    # `peak` is 3,024 bytes once a received handshake message keeps the entries of the extensions the
    # build reads and the header of every entry (`ReceivedExtChain`, in place of eight entries of 65
    # bytes: the inbound frame the decoder is lent is some 330 bytes smaller), and the dial is the
    # longest chain again, 16 frames: `wz_app_main` 704, `reconcile` 456, `drive` 536, `dial_peer`
    # 112, `dial_expecting` 256, the session pump's `build_in` 216, the engine's five frames
    # (`run_main_event_loop` to `enter_entry_set`) 288, `send_open_syn` 304, `emit_on_link` 64 and
    # the 64-bit division 88, 9 calls through a register. The kit's reading was 3,048, 24 over.
    #
    # `peak` is 2,812 bytes once the connect manager's actions are a field of the manager (they
    # were 248 bytes of `drive`'s frame; the manager is in the node's storage) and a new row is
    # built in the table's row (`push_with`; `reconcile` held the 152-byte row twice): the dial is
    # off the longest chain, which is the key matching under a query's answer now, 12 frames:
    # `wz_app_main` 704, the executor's poll 112, `dispatch_datagram_unit` 168, `dispatch_copied`
    # 80, the session events 28, `dispatch_event_among` 576, `keyexpr_intersects_text` 552,
    # `keyexpr_intersects_target` 560 and three small ones, 4 calls through a register. The kit's
    # reading is 2,888, 76 over.
    #
    # `peak` is 2,784 bytes once the key matcher's view of a key is not built before it is used
    # (`KeyChunks` keeps its 32 slots uninitialised, and `keyexpr_intersects_target` no longer holds
    # a second copy of the view, 256 bytes): the longest chain is the same path, 13 frames, and the
    # bound (3,816, 4,016 and 4,744 on the three images) is a query's reply through the network
    # stack's send. The kit's reading is unchanged, 2,888.
    #
    # `peak` is 2,616 bytes once the node's set-up and its loop are two functions (`start` in the
    # image's own `fixed_client.rs`, over `ClientNode::start`, whose frame is gone before the first
    # round, and `RunningNode::drive`, the loop): the main function is 176 bytes where it held the
    # whole set-up as values (704), the loop under it is 400, and the dial is the longest chain
    # again, 17 frames: `wz_app_main` 176, `drive` 400, `reconcile` 448, the manager's `drive` 264,
    # `dial_peer` 112, `dial_expecting` 256, the pump's `build_in` 216, the engine's five frames
    # 288, `send_open_syn` 304, `emit_on_link` 64 and the 64-bit division 88, 12 calls through a
    # register. The kit's reading is 2,696, 80 over.
    #
    # `peak` is 2,560 bytes once the runtime takes no interrupt lock (`CONFIG_WZ_SINGLE_CONTEXT`,
    # which this image's overlay turns on): 56 bytes less over the same 17 frames. The kit's reading
    # is 2,672, 112 over.
    #
    # `peak` is 2,740 bytes with the engine's Appendix D linked once for the program (SCE pin
    # b1ede72108): the worst chain of direct calls is 14 frames with 41 calls through a register on
    # the path not followed, where it was 17 frames. The frames of the engine's procedures
    # are frames of their own now (`Engine::run_main_event_loop` 188, the turn's 40, `take_event`
    # 16, `take_microstep` 232, `enter_states` 232), where the engine of each machine was five
    # frames of 288 bytes in all. The kit's reading is 3,000, 260 over.
    #
    # `peak` is 2,536 bytes at SCE pin f167223931 (packed rows, the engine taking events as numbers,
    # the engine's constructor and exit walk out of line): the worst chain is 13 frames, the dial's
    # `build_in` is 80 bytes where it was 600, and `take_microstep` is 120 where it was 232. The
    # kit's reading is 2,912, 376 over.
    #
    # `peak` is 2,416 bytes once the connect manager's `reconcile` puts the rows in order by swaps
    # of neighbours and not by `rotate_right(1)` (the library's rotation held a row and a buffer of
    # its own in the frame: 448 bytes of frame, 328 now). The kit's reading is 2,720, 304 over: it
    # is the handshake's parse now, the receive of an Init (`read_unit_in`, `decode_unit_in`,
    # `parse_init`), where it was the engine's answer to the message under a decoded-message slot
    # that nothing read any more.
    Image(
        key="zephyr-client-fixed",
        elf=None,
        source="deploy/zephyr-admin-node/overlays/t2g_client_fixed.conf",
        pattern=r"(?m)^CONFIG_MAIN_STACK_SIZE=(\d+)\s*$",
        unit=1,
        entry="wz_app_main",
        peak=2416,
    ),
    # The same client with the session coalescing a send window into one datagram
    # (`overlays/t2g_client_batching.conf`). The batch writer and its flush path are two more
    # frames under the observer's drain, which the overlay says: 7,204 bytes in the image of
    # 2026-10-23 on the shared node, against 6,904 for the client without them (and 7,140 with
    # the node written in `fixed_client.rs`). Its stack is the overlay's own.
    #
    # `peak` is 6,940 bytes in the image of 2026-10-27 after the not-a-Frame dispatch was split
    # into three steps (the kit lane's build, 2 runs of the same kit reading, 6,060 bytes), against
    # 7,460 before the split, the same chain as the client without batching: the worst chain is
    # the connect manager's dial path (see the fixed client's row). The 7,460 had been read since
    # 2026-10-23: the slot node keeps the latest sample of a subscription (+136) and holds
    # sessions a peer opened beside the dialled ones (+64), the connect manager is held by the
    # shared planner and by nodes' zids (+88), a few smaller steps, and the log lines are not
    # inlined into the main frame (-144).
    #
    # 6,372 bytes after the SCE pin moved to `6dbfa6a521`, the same chain as the client without
    # batching (see the fixed client's row); the kit's reading, 5,904 bytes, is 24 over that
    # client's.
    #
    # 5,480 bytes with the session's link driver named by its type: the same chain as the client
    # without batching (see the fixed client's row), 40 less than the 5,520 before.
    #
    # 5,004 bytes with the dial handing the slot the function that makes the session's parameters
    # (see the fixed client's row): 476 less, the slot's `open` 880 bytes here.
    #
    # 4,172 bytes with the connect manager's actions as one buffer and its rows reordered in place
    # (see the fixed client's row): the same chain as the client without batching; the kit's
    # reading is 4,280.
    #
    # 3,620 bytes with the loop's node, factory and host built in the storage's arena (see the
    # fixed client's row): the same chain as the client without batching.
    #
    # 2,560 bytes with the runtime taking no interrupt lock (see the fixed client's row): the same
    # chain as the client without batching.
    #
    # 2,740 bytes with the engine's Appendix D linked once for the program (see the fixed client's
    # row): the same chain as the client without batching.
    #
    # 2,536 bytes at SCE pin f167223931 (see the fixed client's row): the same chain as the client
    # without batching.
    #
    # 2,416 bytes with `reconcile` ordering the rows by swaps (see the fixed client's row): the same
    # chain as the client without batching.
    Image(
        key="zephyr-client-fixed-batching",
        elf=None,
        source="deploy/zephyr-admin-node/overlays/t2g_client_batching.conf",
        pattern=r"(?m)^CONFIG_MAIN_STACK_SIZE=(\d+)\s*$",
        unit=1,
        entry="wz_app_main",
        peak=2416,
    ),
    # The fixed client that ASKS (`overlays/t2g_client_get.conf`): the getter of
    # `wz_session_mcu::slot_getter` is the application layer the observer's drain runs inside, and
    # its query path (`get`, the request written into the slot the link lends) is under that drain
    # too. Its stack is the overlay's own.
    #
    # `peak` is 7,092 bytes in the image of 2026-10-27 after the not-a-Frame dispatch was split
    # into three steps (one query in flight; it was 7,784 before the split and 7,672 on
    # 2026-10-23, and 8,588 with four then, whose worst path is another and which was not
    # re-measured). It is now ABOVE what the kit's own reading of the same image reaches over
    # 2,050 answered queries, 6,648 bytes (it was 8,328 before the split and 8,144 on 2026-10-23,
    # when the reading was over the chain): the reply sink the getter hands the session is still
    # called through a register (`ReplySink::on_reply`/`on_final`, which write the plan) and the
    # reader does not follow it, but the path under that dispatch is the engine's answer to a
    # handshake no longer, and the worst chain is the connect manager's dial path (see the fixed
    # client's row). The resource budget's row for this image no longer carries `chain_misses`:
    # the chain is a bound again, for as long as the reading stays under it.
    #
    # 6,524 bytes after the SCE pin moved to `6dbfa6a521` (568 less, 15 frames, 10 calls through a
    # register not followed), the fixed client's chain with the getter's larger main frame (1,856
    # against 1,784) and `dial_expecting` at 1,296 (1,216 there). ⚠ The kit's reading did not move
    # with it: it is still 6,648 bytes, 124 OVER the chain again, so the resource budget's row
    # carries `chain_misses` once more and the chain is not a bound on this image. The path that
    # sets the reading is not the one the pin shortened, and the reader cannot follow it; it was
    # not identified.
    #
    # 6,492 bytes in the build that writes the numbers and the console lines without `core::fmt`
    # (the zid hex and the locator through `TextOut`, the lines as `LogPart`s): the chain fell 32
    # bytes and the kit's reading, 6,600, fell 48.
    #
    # 6,064 bytes with `CONFIG_WZ_INITIAL_SN_COMPACT` (see the fixed client's row): 428 less. The
    # kit's reading did not move, 6,600, so it is 536 over the chain and the row still carries
    # `chain_misses`.
    #
    # 5,768 bytes with the connect manager's planner call taken as a trait object (see the fixed
    # client's row): 296 less, and the kit's reading fell with it, 6,600 to 6,160, so it is 392 over
    # the chain.
    #
    # 5,224 bytes with the dial handing the slot the function that makes the session's parameters
    # (see the fixed client's row): 544 less. The kit's reading, 6,020, is 796 over the chain.
    #
    # 4,756 bytes with the connect manager's actions as one buffer and its rows reordered in place
    # (see the fixed client's row), 13 frames and 4 calls through a register, the receive's chain
    # under the getter's larger main frame (1,368). The kit's reading is 5,104.
    #
    # 4,204 bytes with the loop's node, factory and host built in the storage's arena (see the
    # fixed client's row): the main frame 816 bytes, from 1,368. The kit's reading is 4,552.
    #
    # 3,388 bytes with the node's set-up and its loop as two functions (see the fixed client's row):
    # the main frame is 176 bytes, the loop under it. The kit's reading is 4,328.
    #
    # 3,372 bytes with the runtime taking no interrupt lock (see the fixed client's row), 16 less.
    Image(
        key="zephyr-client-fixed-get",
        elf=None,
        source="deploy/zephyr-admin-node/overlays/t2g_client_get.conf",
        pattern=r"(?m)^CONFIG_MAIN_STACK_SIZE=(\d+)\s*$",
        unit=1,
        entry="wz_app_main",
        peak=3372,
    ),
    # The fixed client over the secure channel (`overlays/t2g_client_tls.conf`, decision D9):
    # the dial completes a TLS 1.3 handshake in Mbed TLS before the session sees a byte, and every
    # record the link reads or writes passes through the channel. Its stack is the overlay's own.
    #
    # `peak` is 7,016 bytes in the image of 2026-10-24: the same dispatch path as the client
    # without the channel (`dispatch_copied`, the observer's drain), 112 bytes deeper, with 14
    # calls through a register not followed (the channel's transport callbacks among them). The
    # kit's own reading of that image over a dial, a handshake and a session is 6,864 bytes, under
    # the chain.
    #
    # 7,432 bytes in the bench host's build of 2026-10-27 over 23 frames, 416 over the figure
    # above, and the same with and without the split of the not-a-Frame dispatch of
    # `wz-session-core` into three steps: the worst chain is the connect manager's dial path
    # (`wz_app_main` 1,920, `ConnectManager::reconcile` 1,280 and two frames of its own, 416 and
    # 112, `SlotDialer::dial_expecting` 1,440, `wz_tls_session_handshake` under it), which the
    # connect manager's changes since 2026-10-24 deepened and which was not bisected. The kit's
    # reading of the image, 6,752 bytes, fell 112 with the split. The hosted Qzb lane runs this
    # gate for the fixed client's overlay only, so this figure is the bench host's.
    Image(
        key="zephyr-client-fixed-tls",
        elf=None,
        source="deploy/zephyr-admin-node/overlays/t2g_client_tls.conf",
        pattern=r"(?m)^CONFIG_MAIN_STACK_SIZE=(\d+)\s*$",
        unit=1,
        entry="wz_app_main",
        peak=7432,
    ),
)

_HEAD = re.compile(r"^([0-9a-f]{8}) <(.*)>:$")
_SUB_IMM = re.compile(r"\bsub(?:w|\.w)?\s+sp,\s*(?:sp,\s*)?#(\d+)")
_PUSH = re.compile(r"\b(?:push|stmdb)(?:\.w)?\s+(?:sp!,\s*)?\{([^}]*)\}")
_MOVW = re.compile(r"\bmovw\s+(r\d+|ip),\s*#(\d+)")
_MOVT = re.compile(r"\bmovt\s+(r\d+|ip),\s*#(\d+)")
_SUB_REG = re.compile(r"\bsub(?:\.w)?\s+sp,\s*sp,\s*(r\d+|ip)")

#: How many instructions of a function's start are read for its frame.
PROLOGUE = 14


def frames(disassembly: str) -> list[tuple[int, str]]:
    """`(frame bytes, demangled name)` for each function whose prologue lowers sp."""
    lines = disassembly.splitlines()
    found: list[tuple[int, str]] = []
    i = 0
    while i < len(lines):
        head = _HEAD.match(lines[i])
        if not head:
            i += 1
            continue
        frame = 0
        regs: dict[str, int] = {}
        seen = 0
        j = i + 1
        while j < len(lines) and not _HEAD.match(lines[j]) and seen < PROLOGUE:
            line = lines[j]
            j += 1
            if "\t" not in line:
                continue
            seen += 1
            push = _PUSH.search(line)
            if push:
                frame += 4 * len([r for r in push.group(1).split(",") if r.strip()])
            sub = _SUB_IMM.search(line)
            if sub:
                frame += int(sub.group(1))
            movw = _MOVW.search(line)
            if movw:
                regs[movw.group(1)] = int(movw.group(2))
            movt = _MOVT.search(line)
            if movt and movt.group(1) in regs:
                regs[movt.group(1)] = (int(movt.group(2)) << 16) | (regs[movt.group(1)] & 0xFFFF)
            sub_reg = _SUB_REG.search(line)
            if sub_reg and sub_reg.group(1) in regs:
                frame += regs[sub_reg.group(1)]
        if frame:
            found.append((frame, head.group(2)))
        i = j
    return found


_CALL = re.compile(r"\t(?:bl|b|b\.w)\t([0-9a-f]+) <")
_INDIRECT = re.compile(r"\tblx\t(?:r\d+|ip)")


@dataclass(frozen=True)
class Chain:
    """The deepest chain of direct calls the reader could follow."""

    total: int  # bytes: the sum of the frames along it
    path: tuple[tuple[int, str], ...]  # `(frame, name)` from the root down
    indirect: int  # call sites through a register in the functions on the path


def worst_chain(disassembly: str, entry: str) -> Chain | None:
    """The deepest chain of direct calls under the thread's entry, in bytes.

    The call graph is the one `objdump -d` prints: a `bl`, `b` or `b.w` to an address is an edge
    to the function that holds it, and a `blx` through a register is an edge this cannot follow
    (counted per path so the break is visible, not assumed away). A task the executor polls is
    called through a function pointer, so every [`POLLED_TASK`] function is a root as well, below
    the entry's own frame (the executor's loop is inlined into the entry). Edges into a function
    that ends the program ([`_COLD`]) are not followed.

    It is a statement about the code's direct calls, not a bound on the stack: a call through a
    register, such as the closure a walk hands each record to, is not followed, and a path the
    graph has that no run takes is counted. The figure is held where it was measured so a change
    that moves it is seen; it is not a proof that the stack is enough.
    """
    import bisect

    blocks: list[tuple[int, str, list[str]]] = []
    for line in disassembly.splitlines():
        head = _HEAD.match(line)
        if head:
            blocks.append((int(head.group(1), 16), head.group(2), [line]))
        elif blocks:
            blocks[-1][2].append(line)
    starts = [b[0] for b in blocks]
    frame_of: dict[int, int] = {}
    edges: dict[int, set[int]] = {}
    indirect: dict[int, int] = {}
    for start, _name, lines in blocks:
        found = frames("\n".join(lines))
        frame_of[start] = found[0][0] if found else 0
        targets: set[int] = set()
        for line in lines[1:]:
            call = _CALL.search(line)
            if call:
                at = bisect.bisect_right(starts, int(call.group(1), 16)) - 1
                if at >= 0 and starts[at] != start:
                    targets.add(starts[at])
        edges[start] = targets
        indirect[start] = sum(1 for line in lines[1:] if _INDIRECT.search(line))
    name_of = {b[0]: b[1] for b in blocks}
    cold = {s for s, n in name_of.items() if _COLD.search(n)}

    memo: dict[int, tuple[int, tuple[int, ...]]] = {}
    on_path: set[int] = set()

    def deepest(s: int) -> tuple[int, tuple[int, ...]]:
        if s in memo:
            return memo[s]
        if s in on_path:
            return 0, ()
        on_path.add(s)
        best: tuple[int, tuple[int, ...]] = (0, ())
        for t in edges[s]:
            if t not in cold:
                below = deepest(t)
                if below[0] > best[0]:
                    best = below
        on_path.discard(s)
        memo[s] = (frame_of[s] + best[0], (s, *best[1]))
        return memo[s]

    sys.setrecursionlimit(max(sys.getrecursionlimit(), 20000))
    entries = [s for s, n in name_of.items() if entry in n and frame_of[s] > 0]
    if not entries:
        return None
    root = max(entries, key=lambda s: frame_of[s])
    total, path = deepest(root)
    for s, n in name_of.items():
        if POLLED_TASK in n and frame_of[s] > 0:
            below_total, below_path = deepest(s)
            if frame_of[root] + below_total > total:
                total, path = frame_of[root] + below_total, (root, *below_path)
    return Chain(
        total=total,
        path=tuple((frame_of[s], name_of[s]) for s in path),
        indirect=sum(indirect[s] for s in path),
    )


def judge_chain(
    key: str, stack: int, chain: Chain | None, committed: int | None
) -> tuple[bool, list[str]]:
    """The rule over a worst chain: it fits the declared stack, and it has not moved unseen."""
    if chain is None:
        return False, [f"stack-chain: FAIL {key}: no function with a frame names the task's entry"]
    ok = True
    lines: list[str] = []
    if chain.total > stack:
        lines.append(
            f"stack-chain: FAIL {key}: the worst chain of direct calls is {chain.total} bytes, "
            f"over the {stack}-byte stack"
        )
        ok = False
    if committed is None:
        lines.append(
            f"stack-chain: {key}: no figure is committed for this image; the chain reads "
            f"{chain.total} bytes (commit it as `peak` with the reason it is what it is)"
        )
    elif abs(chain.total - committed) > PEAK_TOLERANCE:
        lines.append(
            f"stack-chain: FAIL {key}: the worst chain of direct calls is {chain.total} bytes, "
            f"the committed figure is {committed} (tolerance {PEAK_TOLERANCE}); a change moved "
            f"the stack, so commit the new figure with the reason"
        )
        ok = False
    lines.append(
        f"stack-chain: {'OK' if ok else 'FAIL'} {key}: worst chain {chain.total} bytes over "
        f"{len(chain.path)} frame(s) against a {stack}-byte stack"
        + (f", committed {committed}" if committed is not None else "")
        + f"; {chain.indirect} call(s) through a register on the path are not followed"
    )
    for frame, name in chain.path[:6]:
        lines.append(f"stack-chain:   +{frame:5d} {name[:100]}")
    return ok, lines


def declared_stack(image: Image, root: Path) -> int:
    """The image's task stack in bytes, read from its source; SystemExit if not found once."""
    path = root / image.source
    if not path.is_file():
        raise SystemExit(f"stack-frame: {image.key}: {image.source} is not a file")
    found = re.findall(image.pattern, path.read_text())
    if len(found) != 1:
        raise SystemExit(
            f"stack-frame: {image.key}: {image.source} declares the task stack {len(found)} "
            f"times by `{image.pattern}`, and the gate reads it once"
        )
    stack = int(found[0]) * image.unit
    if stack <= 0:
        raise SystemExit(f"stack-frame: {image.key}: the declared stack is {stack} bytes")
    return stack


def judge(
    key: str, stack: int, entry: str, found: list[tuple[int, str]]
) -> tuple[bool, list[str]]:
    """The rule over a list of frames; `(ok, report lines)`."""
    budget = stack * BUDGET_NUM // BUDGET_DEN
    lines: list[str] = []
    ok = True
    if len(found) < MIN_FRAMED_FUNCTIONS:
        lines.append(
            f"stack-frame: FAIL {key}: {len(found)} function(s) with a frame (need "
            f"{MIN_FRAMED_FUNCTIONS}); the disassembly was not understood, which is not "
            f"the same as small frames"
        )
        return False, lines
    entries = [f for f in found if entry in f[1]]
    if not entries:
        lines.append(
            f"stack-frame: FAIL {key}: no function named `{entry}` has a frame, so the task's "
            f"own frame was not judged"
        )
        ok = False
    ranked = sorted(found, reverse=True)
    biggest, name = ranked[0]
    over = [f for f in ranked if f[0] > budget]
    for frame, fname in over:
        lines.append(
            f"stack-frame: FAIL {key}: a frame of {frame} bytes ({fname[:120]}) is over the "
            f"budget {budget} bytes, half of the {stack}-byte task stack"
        )
        ok = False
    lines.append(
        f"stack-frame: {'OK' if ok else 'FAIL'} {key}: largest frame {biggest} bytes "
        f"({name[:90]}) against a {stack}-byte stack, budget {budget}"
        + (f"; task entry {max(e[0] for e in entries)} bytes" if entries else "")
        + f"; {len(found)} function(s) with a frame"
    )
    return ok, lines


def objdump(chosen: str | None) -> str:
    if chosen:
        return chosen
    for name in ("arm-none-eabi-objdump", "llvm-objdump", "rust-objdump"):
        path = shutil.which(name)
        if path:
            return path
    raise SystemExit("stack-frame: no objdump on PATH (arm-none-eabi-objdump, llvm-objdump)")


def check(key: str, elf_arg: str | None, objdump_arg: str | None) -> int:
    image = next((i for i in IMAGES if i.key == key), None)
    if image is None:
        raise SystemExit(f"stack-frame: unknown image `{key}` (have {[i.key for i in IMAGES]})")
    if image.elf is None and not elf_arg:
        raise SystemExit(f"stack-frame: {key}: its ELF is built where the caller says; pass --elf")
    elf = Path(elf_arg) if elf_arg else ROOT / str(image.elf)
    if not elf.is_file():
        raise SystemExit(f"stack-frame: {key}: {elf} is not built")
    proc = subprocess.run(
        [objdump(objdump_arg), "-d", "-C", str(elf)], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise SystemExit(f"stack-frame: {key}: objdump failed: {proc.stderr[-300:]}")
    stack = declared_stack(image, ROOT)
    ok, report = judge(key, stack, image.entry, frames(proc.stdout))
    chain_ok, chain_report = judge_chain(
        key, stack, worst_chain(proc.stdout, image.entry), image.peak
    )
    print("\n".join(report + chain_report))
    return 0 if ok and chain_ok else 1


def population() -> int:
    for image in IMAGES:
        stack = declared_stack(image, ROOT)
        print(f"stack-frame: {image.key}: declared stack {stack} bytes ({image.source})")
    print(f"stack-frame: population OK -- {len(IMAGES)} image(s), each stack read once from its source")
    return 0


# A prologue of each shape the reader knows, as `objdump -d` prints it.
_FIXTURE = """\
00001000 <big_sub_w>:
    1000:\te92d 4ff0 \tstmdb\tsp!, {r4, r5, r6, r7, r8, r9, sl, fp, lr}
    1004:\tf5ad 6d80 \tsub.w\tsp, sp, #1024\t@ 0x400
    1008:\t4770      \tbx\tlr

00002000 <movw_movt_sub>:
    2000:\tb5f0      \tpush\t{r4, r5, r6, r7, lr}
    2002:\tf24 0c40 \tmovw\tip, #16448\t@ 0x4040
    2006:\tf2c0 0c01 \tmovt\tip, #1
    200a:\tebad 0d0c \tsub.w\tsp, sp, ip
    200e:\t4770      \tbx\tlr

00003000 <small_sub>:
    3000:\tb580      \tpush\t{r7, lr}
    3002:\tb082      \tsub\tsp, #8
    3004:\t4770      \tbx\tlr

00004000 <no_frame>:
    4000:\t4770      \tbx\tlr
"""


# A small program as `objdump -d -C` prints it: `entry` (frame 24) calls `mid` (frame 40, which
# calls `leaf`, frame 16), calls `std::panicking::panic_fmt` (frame 520, the end of the
# program) and makes one call through a register; `poll_erased::<task>` (frame 72) is called by
# nothing and calls `leaf`.
_CHAIN_FIXTURE = """\
00001000 <entry>:
    1000:\tb580      \tpush\t{r7, lr}
    1002:\tb084      \tsub\tsp, #16
    1004:\tf000 f8fc \tbl\t2000 <mid>
    1008:\tf000 f8fc \tbl\t4000 <std::panicking::panic_fmt>
    100c:\t4790      \tblx\tr2
    100e:\tbd80      \tpop\t{r7, pc}

00002000 <mid>:
    2000:\tb580      \tpush\t{r7, lr}
    2002:\tb08a      \tsub\tsp, #32
    2004:\tf000 f8fc \tbl\t3000 <leaf>
    2008:\tbd80      \tpop\t{r7, pc}

00003000 <leaf>:
    3000:\tb580      \tpush\t{r7, lr}
    3002:\tb082      \tsub\tsp, #8
    3004:\tbd80      \tpop\t{r7, pc}

00004000 <std::panicking::panic_fmt>:
    4000:\tb580      \tpush\t{r7, lr}
    4002:\tf5ad 7d00 \tsub.w\tsp, sp, #512
    4006:\tbd80      \tpop\t{r7, pc}

00005000 <executor::poll_erased::<task>>:
    5000:\tb580      \tpush\t{r7, lr}
    5002:\tb090      \tsub\tsp, #64
    5004:\tf000 f8fc \tbl\t3000 <leaf>
    5008:\tbd80      \tpop\t{r7, pc}
"""


def selftest() -> int:
    failures: list[str] = []

    def expect(label: str, got: object, want: object) -> None:
        if got != want:
            failures.append(f"{label}: got {got!r}, want {want!r}")

    read = dict((name, frame) for frame, name in frames(_FIXTURE))
    expect("sub.w after a nine-register push", read.get("big_sub_w"), 36 + 1024)
    expect("movw/movt behind sub sp, sp, ip", read.get("movw_movt_sub"), 20 + 65536 + 16448)
    expect("a small sub", read.get("small_sub"), 8 + 8)
    expect("a function with no frame is absent", "no_frame" in read, False)

    many = [(100, f"f{i}") for i in range(MIN_FRAMED_FUNCTIONS)]
    ok, _ = judge("t", 16384, "f0", many + [(4816, "task_entry")])
    expect("a frame at 29 percent of the stack passes", ok, True)
    ok, report = judge("t", 16384, "task_entry", many + [(28056, "task_entry")])
    expect("the Round 3318 frame (28056 on 16384) fails", ok, False)
    expect("the failing frame is named", any("28056" in line for line in report), True)
    ok, _ = judge("t", 16384, "task_entry", many + [(8192, "task_entry")])
    expect("a frame at exactly half passes", ok, True)
    ok, _ = judge("t", 16384, "task_entry", many + [(8193, "task_entry")])
    expect("a frame one byte over half fails", ok, False)
    ok, report = judge("t", 16384, "wz_task", many)
    expect("a task entry that has no frame fails", ok, False)
    expect("and says so", any("no function named" in line for line in report), True)
    ok, report = judge("t", 16384, "f0", many[:3])
    expect("an image with almost no frames is refused", ok, False)
    expect("and not read as small frames", any("not understood" in line for line in report), True)

    chain = worst_chain(_CHAIN_FIXTURE, "entry")
    expect("the fixture has a chain", chain is not None, True)
    if chain is not None:
        expect(
            "the polled task below the entry's frame is the worst chain (24 + 72 + 16)",
            chain.total,
            112,
        )
        expect(
            "and the path names the task, not the direct callee",
            [name for _, name in chain.path],
            ["entry", "executor::poll_erased::<task>", "leaf"],
        )
        expect("a call through a register on the path is counted", chain.indirect, 1)
        ok, _ = judge_chain("t", 4096, chain, 112)
        expect("a chain at its committed figure fits", ok, True)
        ok, _ = judge_chain("t", 4096, chain, 112 + PEAK_TOLERANCE)
        expect("a figure within the tolerance fits", ok, True)
        ok, report = judge_chain("t", 4096, chain, 112 + PEAK_TOLERANCE + 1)
        expect("a figure one byte past the tolerance is a finding", ok, False)
        expect("and says to commit the new one", any("commit" in line for line in report), True)
        ok, report = judge_chain("t", 111, chain, 112)
        expect("a chain over the stack fails", ok, False)
        ok, _ = judge_chain("t", 4096, chain, None)
        expect("an image with no committed figure is reported and passes", ok, True)
    ok, _ = judge_chain("t", 4096, worst_chain(_CHAIN_FIXTURE, "no_such_entry"), 112)
    expect("an entry with no frame is refused", ok, False)

    if failures:
        for failure in failures:
            print(f"stack-frame: selftest FAIL -- {failure}")
        return 1
    print(
        "stack-frame: selftest OK -- reads a nine-register push with a large sub.w, the "
        "movw/movt pair behind a register sub, a small sub, and a function with no frame; "
        "refuses the Round 3318 frame, a frame one byte over half, a task entry without a "
        "frame and an image with almost none, past two clean controls (4,816 bytes on "
        "16 KiB, and exactly half); follows a chain through a polled task past a panic, "
        "counts a call through a register, and refuses a chain over the stack and a figure "
        "past the tolerance"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", metavar="KEY", help="judge one built image")
    mode.add_argument("--population", action="store_true", help="read every declared stack")
    mode.add_argument("--selftest", action="store_true", help="drive the reader and the rule")
    mode.add_argument("--list", action="store_true", help="print the image keys")
    parser.add_argument("--elf", help="the built ELF, for an image whose build dir is the caller's")
    parser.add_argument("--objdump", help="the objdump of the toolchain that linked the ELF")
    args = parser.parse_args()
    if args.list:
        print("\n".join(i.key for i in IMAGES))
        return 0
    if args.selftest:
        return selftest()
    if args.population:
        return population()
    return check(args.check, args.elf, args.objdump)


if __name__ == "__main__":
    sys.exit(main())
