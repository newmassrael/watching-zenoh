#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y889 (debt-build-evidence) — a BUILD this repo's CI runs must not have
its output thrown away.

## The failure this ends

Hosted run 32314626012 went red on Layer Qz with one line:

    Qz build deploy/zephyr-app (west) FAIL

and nothing else, in zero seconds. The `west build` behind it was written
`>/dev/null 2>&1`, so the log held the verdict and none of the evidence. There
was no way to tell a missing toolchain from a broken CMakeLists from a
compile error without provisioning Zephyr by hand and running it again — which
is a whole round spent reproducing something the failing run already knew.

Measured across `run-ci.sh` when this was written: THREE builds discarded their
output. The Zephyr one above, the `sce-codegen` rebuild inside Layer B (four
words on failure), and the xtask build inside Layer B2 — that last one worse
than the others in its way, because it SKIPS rather than fails and prints
"libxml2/sce-build toolchain absent?" as a diagnosis when it is a guess. A real
break in the xtask read exactly like a box without libxml2.

R311y756 had already fixed a fourth site, in the same file, for the same
reason. Four is not a habit anybody is going to remember; it is a rule that
needed a gate.

## What it checks

A line in `run-ci.sh` that runs a BUILD — `west build`, `cargo build/test/run`,
a `scripts/build-*.sh`, `cmake --build`, `make` — must not send both streams to
`/dev/null`. Redirect to a file under the run's own log directory and print the
tail on the failure path, which is what all three repaired sites now do.

## What it deliberately does NOT check

Every other `>/dev/null 2>&1` in the file, of which there are ~55. Almost all
are `command -v` probes or the gates' own selftests, which run a script with
deliberately bad input and legitimately care about nothing but the exit status.
A rule that flagged those would need an exemption table longer than the
findings, and a table nobody maintains is worse than no gate — the population
here is small BECAUSE the rule is narrow, and that is the design.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
TARGETS = [ROOT / "scripts" / "run-ci.sh"]

BUILD = re.compile(
    r"\b(?:west build"
    r"|cargo\s+(?:build|test|run)\b"
    r"|bash\s+scripts/build-[a-z-]+\.sh"
    r"|cmake\s+--build"
    r"|\bmake\b)"
)
DISCARD = re.compile(r">\s*/dev/null\s+2>&1|2>&1\s*>\s*/dev/null|&>\s*/dev/null")


def main() -> int:
    findings: list[str] = []
    scanned = 0
    for path in TARGETS:
        if not path.exists():
            findings.append(f"{path} is not there, so this gate read nothing")
            continue
        lines = path.read_text().splitlines()
        scanned += len(lines)
        for i, line in enumerate(lines):
            if not DISCARD.search(line) or not BUILD.search(line):
                continue
            findings.append(
                f"{path.relative_to(ROOT)}:{i + 1}: a BUILD discards both "
                f"streams, so its failure will carry no evidence and reading "
                f"it means running the build again by hand. Redirect to a file "
                f"under ${{RUNCI_LOG_DIR:-crates/target/run-ci-logs}} and "
                f"`tail` it on the failure path.\n      {line.strip()[:120]}"
            )

    if not scanned:
        print(
            "build-evidence: FAIL -- read 0 line(s). An empty population is "
            "indistinguishable from total compliance, so it cannot pass.",
            file=sys.stderr,
        )
        return 1

    if findings:
        print("build-evidence: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(
        f"  build-evidence: {scanned} line(s) read, 0 build(s) discarding their "
        f"own output"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
