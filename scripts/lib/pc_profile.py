# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3781 (no register item) -- where the time of a GET went, from the program-counter samples of a profile run.

    python3 pc_profile.py <elf> <samples file> [--top N] [--patterns]

`scripts/kit-lane.sh` with `KIT_PROFILE_OUT=<file>` writes the samples (scripts/lib/pc_sample.tcl). This
maps each sample to the function of the image that holds it (`arm-none-eabi-nm -S`), and prints

* the functions by their share of the samples, with their sizes,
* how many distinct 32-byte cache lines the samples touched, which is the working set the
  instruction cache has to hold (the M7's is 16 KiB: 512 lines), and
* with `--patterns`, one linker input-section pattern per function that carries at least 0.3 percent
  of the samples, in the order of their first appearance by address, which is the list
  `deploy/zephyr-common/hot_text.ld` is made from.

It is an analysis, not a gate: a sample is a count, and the lines it names are the ones a run happened
to execute.
"""
import argparse
import bisect
import collections
import re
import subprocess
import sys

LINE_BYTES = 32


def symbols(elf: str) -> tuple[list[int], list[tuple[int, str]]]:
    """The functions of the image, sorted by address: `(start, size, name)` split into two lists."""
    out = subprocess.run(
        ["arm-none-eabi-nm", "-S", "-C", "--defined-only", elf],
        capture_output=True, text=True, check=True,
    ).stdout
    rows = []
    for line in out.splitlines():
        m = re.match(r"^([0-9a-f]+) ([0-9a-f]+) [tTwW] (.*)$", line)
        if m and int(m.group(2), 16) > 0:
            rows.append((int(m.group(1), 16) & ~1, int(m.group(2), 16), m.group(3)))
    rows.sort()
    return [r[0] for r in rows], [(r[1], r[2]) for r in rows]


def pattern_of(name: str) -> str | None:
    """The linker input-section pattern of a Rust function, by its last path segment.

    The compiler puts each function in a section `.text.<mangled name>`; the mangled name of a path
    ends in the length-prefixed last segment and `17h<hash>E`, so the segment with its length is a
    pattern that does not move with the hash. C functions are in `.text.<name>`."""
    base = re.sub(r"::<.*?>$", "", name)
    last = re.split(r"::", re.sub(r"<[^<>]*>", "", base))[-1].strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", last):
        return None
    if "::" in base:
        return f"*(.text.*{len(last)}{last}17h*)"
    return f"*(.text.{last})"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("samples")
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--patterns", action="store_true")
    args = ap.parse_args()

    starts, sized = symbols(args.elf)
    counts: collections.Counter = collections.Counter()
    lines: set[int] = set()
    unmapped = 0
    total = 0
    with open(args.samples, encoding="utf-8") as f:
        for text in f:
            text = text.strip()
            if not re.fullmatch(r"[0-9a-f]{8}", text):
                continue
            pc = int(text, 16)
            total += 1
            at = bisect.bisect_right(starts, pc) - 1
            if at < 0 or pc >= starts[at] + sized[at][0]:
                unmapped += 1
                continue
            counts[(starts[at], sized[at][1], sized[at][0])] += 1
            lines.add(pc // LINE_BYTES)

    print(f"samples {total}, in no function of the image {unmapped}, cache lines touched {len(lines)} "
          f"({len(lines) * LINE_BYTES} bytes; the instruction cache holds 16384)")
    print(f"functions seen {len(counts)}, bytes of those {sum(size for (_, _, size) in counts)}")
    covered = 0
    print(f"== the {args.top} functions with the most samples")
    for (start, name, size), n in counts.most_common(args.top):
        covered += n
        print(f"  {100 * n / total:5.1f}%  {size:>6} B  {start:08x}  {name[:100]}")
    if args.patterns:
        print("== linker patterns, functions with at least 0.3 percent of the samples, by address")
        chosen = sorted((s, name, size) for (s, name, size), n in counts.items() if n / total >= 0.003)
        seen: set[str] = set()
        hot_bytes = 0
        for _, name, size in chosen:
            pat = pattern_of(name)
            if pat and pat not in seen:
                seen.add(pat)
                hot_bytes += size
                print(f"  {pat}    /* {size} B  {name[:70]} */")
        print(f"== {len(seen)} patterns, {hot_bytes} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
