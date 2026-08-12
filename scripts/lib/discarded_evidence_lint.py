#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y606 (no register item) — reject a child process whose stdout is captured and stderr binned.

## The defect this closes

Layer E failed twice in six sweeps with nothing to read but an exit code:

    real zenoh-pico z_pub exited ExitStatus(unix_wait_status(65280))

65280 is 255, which is what upstream's `z_pub.c` returns when `z_open` fails --
and pico says WHY on stderr. The harness had built a capture file, wired the
child's stdout to it, printed it in the panic, and sent stderr to `/dev/null`.
So the one stream carrying the answer was the one thrown away, in 53 places.

The asymmetry is what makes this mechanical rather than editorial. A leg that
captures NEITHER stream has made a choice; a leg that captures one and bins the
other has a reader and is feeding it half the story.

## What it flags

Inside one `Command` builder chain: `.stdout(Stdio::from(..))` together with
`.stderr(Stdio::null())`. Order does not matter -- the chain is scanned as a
unit, bounded by the `.spawn()` / `.status()` / `.output()` that ends it.

## What it deliberately does NOT flag

**The reverse asymmetry** -- `.stdout(Stdio::null())` with a captured stderr --
is the deliberate shape in 138 places here, and it is correct for the binaries
it is used on: `wz-ap-demo` and `zenohd` are Rust programs whose readiness
needles and errors are `tracing` lines on stderr, and whose stdout carries
nothing. Flagging it would be 138 findings and one real one.

**Both streams nulled.** That leg has no reader at all, so nothing is being
told half a story. It is a coverage question -- the failure will be an exit code
with no context -- and it is registered as debt rather than answered by a lint
that cannot tell a fire-and-forget child from an asserted one.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CRATES = ROOT / "crates"

# `Command::new(..)` chains span many lines and are ended by the call that
# actually runs the child. Scanning between those two anchors keeps two adjacent
# chains from being read as one.
CHAIN_START = re.compile(r"Command::new\(")
CHAIN_END = re.compile(r"\.(?:spawn|status|output)\(\)")
STDOUT_CAPTURED = re.compile(r"\.stdout\(Stdio::from\(")
STDERR_BINNED = re.compile(r"\.stderr\(Stdio::null\(\)\)")


def findings_in(path: Path) -> list[tuple[int, str]]:
    """Every chain in `path` that captures stdout and bins stderr."""
    lines = path.read_text(encoding="utf-8").splitlines()
    out: list[tuple[int, str]] = []
    start: int | None = None
    captured = binned = False
    for i, line in enumerate(lines, start=1):
        if CHAIN_START.search(line):
            start, captured, binned = i, False, False
        if start is None:
            continue
        if STDOUT_CAPTURED.search(line):
            captured = True
        if STDERR_BINNED.search(line):
            binned = True
        if CHAIN_END.search(line):
            if captured and binned:
                out.append((start, lines[start - 1].strip()))
            start = None
    return out


def main() -> int:
    sources = sorted(CRATES.rglob("*.rs"))
    sources = [p for p in sources if "target" not in p.parts]
    if not sources:
        # A version that scanned nothing would exit 0 forever and read as
        # coverage. Same rule as count_guard_lint.py's empty-scope failure.
        print(
            f"discarded-evidence lint: found NO rust source under {CRATES} -- "
            "the scan is broken, not the tree",
            file=sys.stderr,
        )
        return 1

    findings: list[str] = []
    for path in sources:
        for line, text in findings_in(path):
            rel = path.relative_to(ROOT).as_posix()
            findings.append(f"  {rel}:{line}: {text}")

    print(
        f"discarded-evidence lint: {len(sources)} rust source(s) scanned, "
        f"{len(findings)} finding(s)"
    )
    if findings:
        print(
            "\nLayer C0 FAIL: a child process has its stdout CAPTURED and its "
            "stderr binned.\nThe capture exists because something reads it on "
            "failure, and a C program under\ntest (zenoh-pico, openssl) reports "
            "why it refused on stderr -- so the stream with\nthe answer is the "
            "one being dropped. Layer E lost two failures this way before the\n"
            "shape was found (R311y606).\n\nFix: clone the capture handle for "
            "both ends.\n\n    .stderr(Stdio::from(out.try_clone().expect(\"dup "
            "stderr handle\")))\n    .stdout(Stdio::from(out))\n\nOrder matters "
            "-- `Stdio::from` MOVES the handle, so clone before you move.\n",
            file=sys.stderr,
        )
        for finding in findings:
            print(finding, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
