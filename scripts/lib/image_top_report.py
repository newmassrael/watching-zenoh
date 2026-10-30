#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""The largest stack frames and the largest symbols of one built image, as lines a diff reads.

`stack_frame_gate.py` says which frame is the worst and whether it is over its budget; it does not
say what the frames under it are, and `check-footprint.sh` says how many bytes of text an image
has, not which symbols they are. A regression in either needs the other half of the question
before it can be answered: which function grew, and which ones are new. This prints both for one
ELF, one line each and sorted, so two runs of it (the tree before a change and the tree after)
compare with `diff` or a join on the name.

    image_top_report.py ELF [--frames N] [--symbols N]

Needs `arm-none-eabi-objdump` and `arm-none-eabi-nm` (or the LLVM ones) on PATH, as the lane
that builds the image does.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import stack_frame_gate  # noqa: E402


def tool(*names: str) -> str:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    raise SystemExit(f"image-top-report: none of {names} is on PATH")


def run(command: list[str]) -> str:
    proc = subprocess.run(command, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise SystemExit(f"image-top-report: {command[0]} failed: {proc.stderr[-300:]}")
    return proc.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("elf")
    parser.add_argument("--frames", type=int, default=30)
    parser.add_argument("--symbols", type=int, default=60)
    args = parser.parse_args()
    elf = Path(args.elf)
    if not elf.is_file():
        raise SystemExit(f"image-top-report: {elf} is not built")

    disassembly = run([tool("arm-none-eabi-objdump", "llvm-objdump", "rust-objdump"), "-d", "-C", str(elf)])
    for frame, name in sorted(stack_frame_gate.frames(disassembly), reverse=True)[: args.frames]:
        print(f"FRAME {frame:6d} {name[:160]}")

    sized = []
    for line in run([tool("arm-none-eabi-nm", "llvm-nm"), "-S", "-C", str(elf)]).splitlines():
        parts = line.split(maxsplit=3)
        if len(parts) == 4 and parts[2].lower() in {"t", "w"}:
            try:
                sized.append((int(parts[1], 16), parts[3]))
            except ValueError:
                continue
    for size, name in sorted(sized, reverse=True)[: args.symbols]:
        print(f"SYMBOL {size:6d} {name[:160]}")
    print(f"TEXT-SYMBOLS {len(sized)} functions, {sum(size for size, _ in sized)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
