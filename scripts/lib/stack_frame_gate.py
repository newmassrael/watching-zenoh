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


@dataclass(frozen=True)
class Image:
    key: str
    elf: str | None  # relative to the repository root; None where the build dir is the caller's
    source: str  # the file that declares the task's stack
    pattern: str  # one capture group: the stack, in `unit` bytes
    unit: int
    entry: str  # a substring of the demangled name of the task's entry function


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
    Image(
        key="zephyr-fixed",
        elf=None,
        source="deploy/zephyr-admin-node/overlays/t2g_fixed.conf",
        pattern=r"(?m)^CONFIG_MAIN_STACK_SIZE=(\d+)\s*$",
        unit=1,
        entry="fixed_node::run",
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
    ok, report = judge(key, declared_stack(image, ROOT), image.entry, frames(proc.stdout))
    print("\n".join(report))
    return 0 if ok else 1


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

    if failures:
        for failure in failures:
            print(f"stack-frame: selftest FAIL -- {failure}")
        return 1
    print(
        "stack-frame: selftest OK -- reads a nine-register push with a large sub.w, the "
        "movw/movt pair behind a register sub, a small sub, and a function with no frame; "
        "refuses the Round 3318 frame, a frame one byte over half, a task entry without a "
        "frame and an image with almost none, past two clean controls (4,816 bytes on "
        "16 KiB, and exactly half)"
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
