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
    Image(
        key="zephyr-fixed",
        elf=None,
        source="deploy/zephyr-admin-node/overlays/t2g_fixed.conf",
        pattern=r"(?m)^CONFIG_MAIN_STACK_SIZE=(\d+)\s*$",
        unit=1,
        entry="wz_zephyr_admin_node::start",
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
    Image(
        key="zephyr-client-fixed",
        elf=None,
        source="deploy/zephyr-admin-node/overlays/t2g_client_fixed.conf",
        pattern=r"(?m)^CONFIG_MAIN_STACK_SIZE=(\d+)\s*$",
        unit=1,
        entry="wz_app_main",
        peak=7128,
    ),
    # The same client with the session coalescing a send window into one datagram
    # (`overlays/t2g_client_batching.conf`). The batch writer and its flush path are two more
    # frames under the observer's drain, which the overlay says: 7,204 bytes in the image of
    # 2026-10-23 on the shared node, against 6,904 for the client without them (and 7,140 with
    # the node written in `fixed_client.rs`). Its stack is the overlay's own.
    Image(
        key="zephyr-client-fixed-batching",
        elf=None,
        source="deploy/zephyr-admin-node/overlays/t2g_client_batching.conf",
        pattern=r"(?m)^CONFIG_MAIN_STACK_SIZE=(\d+)\s*$",
        unit=1,
        entry="wz_app_main",
        peak=7204,
    ),
    # The fixed client that ASKS (`overlays/t2g_client_get.conf`): the getter of
    # `wz_session_mcu::slot_getter` is the application layer the observer's drain runs inside, and
    # its query path (`get`, the request written into the slot the link lends) is under that drain
    # too. Its stack is the overlay's own.
    #
    # `peak` is 7,672 bytes in the image of 2026-10-23 (one query in flight; 8,588 with four, whose
    # worst path is another). ⚠ It is BELOW what the kit's own reading of the same image reaches
    # over 2,050 answered queries, 8,144 bytes: the reader does not follow a call through a register
    # (12 on this path), and the reply sink the getter hands the session is called through one
    # (`ReplySink::on_reply`/`on_final`, which write the plan). So for this image the chain is a
    # figure a change moves and not a bound on the stack: the stack is sized from the kit's reading
    # (12,288 bytes leaves a third free at 8,144), and the resource budget's row for it says so
    # (`chain_misses`) and holds the reading to a quarter of the stack free.
    Image(
        key="zephyr-client-fixed-get",
        elf=None,
        source="deploy/zephyr-admin-node/overlays/t2g_client_get.conf",
        pattern=r"(?m)^CONFIG_MAIN_STACK_SIZE=(\d+)\s*$",
        unit=1,
        entry="wz_app_main",
        peak=7672,
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
    Image(
        key="zephyr-client-fixed-tls",
        elf=None,
        source="deploy/zephyr-admin-node/overlays/t2g_client_tls.conf",
        pattern=r"(?m)^CONFIG_MAIN_STACK_SIZE=(\d+)\s*$",
        unit=1,
        entry="wz_app_main",
        peak=7016,
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
