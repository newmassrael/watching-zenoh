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

## The second spelling: a build piped into `grep -q`

The same defect written another way. `cargo test ... 2>&1 | grep -qE '^test
result: ok. N passed'` throws the stream away too: `grep -q` keeps nothing, so
a red prints no test output, and under `set -o pipefail` the reader's early
exit races its upstream's SIGPIPE into a false red. `_runci_guarded_test` was
written to end this and says so in its own doc; R2074 converted "the LAST" of
the bare form. It was not the last. Measured when this spelling was added: 18
`cargo test` calls across six layer functions (C1t, C1aa, C1ac, C1aj, C1al,
C1w) still carried it, and a hosted red in C1aa printed `104 passed` from its
one unpiped step and then nothing, so the failing test had to be read out of a
different lane's log. A population counted by hand and declared complete had
leaked the class twice; this is the gate.

It reads LOGICAL lines (a trailing backslash joins the next one, so a pipe on the
line after the build still counts), splits each on `&&`, `||` and `;`, and flags a
segment that holds a build AND a lone `|` into `grep -q`. A comment is not a
command. Its detector is run on a fixture before it is run on the file.

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

# `| grep -q`, `| grep -qE`, `| grep -Eq`: a pipe whose reader keeps nothing. A
# lone `|` only: `||` is split away before this is looked for.
PIPED_GREP_Q = re.compile(r"\|\s*grep\s+-[A-Za-z]*q")


def logical_lines(lines: list[str]) -> list[tuple[int, str]]:
    """`(first physical line, text)` with `\\` continuations joined, so a pipe
    on the line after the build is still the build's pipe."""
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    start = 0
    for i, line in enumerate(lines):
        if not buf:
            start = i
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buf.append(stripped[:-1])
            continue
        buf.append(line)
        out.append((start, " ".join(buf)))
        buf = []
    if buf:
        out.append((start, " ".join(buf)))
    return out


def piped_builds(lines: list[str]) -> list[tuple[int, str]]:
    """The BUILDs whose output is piped into `grep -q`.

    The reader stops at its first match and keeps nothing, so a red carries no
    evidence, and under `set -o pipefail` its upstream races a SIGPIPE against
    that early exit. A command list is split on `&&`, `||` and `;` first, so
    only a pipe INSIDE one command counts, and a comment is not a command.

    A `tee` between the build and the reader keeps the stream, so that shape
    does not lose the evidence and is NOT this gate's subject: what it still
    risks is the SIGPIPE race alone, a different defect with its own count.
    """
    found: list[tuple[int, str]] = []
    for at, text in logical_lines(lines):
        if text.lstrip().startswith("#"):
            continue
        for segment in re.split(r"&&|\|\||;", text):
            build = BUILD.search(segment)
            reader = PIPED_GREP_Q.search(segment)
            if not build or not reader or reader.start() < build.start():
                continue
            if re.search(r"\btee\b", segment[build.start() : reader.start()]):
                continue
            found.append((at, segment.strip()))
    return found


def selftest() -> None:
    """The detector is checked on a fixture before it is trusted on the file: a
    gate that cannot see the shape it exists for reports a clean surface."""
    flagged = [
        "        && cargo test -p x --quiet 2>&1 | grep -qE '^test result: ok\\. 5 passed' \\",
        "    cargo test -p x --quiet 2>&1 \\\n        | grep -qE '^test result: ok\\. 5 passed'",
        "    cargo test -p x --quiet | grep -q passed",
    ]
    clean = [
        "    _runci_guarded_test C1x 5 cargo test -p x --quiet \\\n        || return 1",
        '    out="$(cd crates && cargo test -p x --quiet 2>&1)" || return 1',
        "    grep -qE '^test result: ok\\. 5 passed' <<<\"$out\" || return 1",
        "    # cargo test -p x 2>&1 | grep -qE 'passed' is the shape this forbids",
        "    cargo test -p x --quiet 2>&1 | tee /dev/stderr",
        "    cargo test -p x --quiet 2>&1 | tee /dev/stderr | grep -qE 'passed'",
        "    cargo test -p x --quiet || echo x | grep -q x",
    ]
    for text in flagged:
        assert piped_builds(text.split("\n")), f"selftest: not flagged: {text!r}"
    for text in clean:
        assert not piped_builds(text.split("\n")), f"selftest: flagged: {text!r}"


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        selftest()
        print("build-evidence: selftest ok")
        return 0
    selftest()
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
        for at, segment in piped_builds(lines):
            findings.append(
                f"{path.relative_to(ROOT)}:{at + 1}: a BUILD is piped into "
                f"`grep -q`, which keeps nothing, so a red carries no evidence "
                f"and, under `set -o pipefail`, its upstream races a SIGPIPE "
                f"against the reader's early exit. Run it through "
                f"`_runci_guarded_test <label> <N> cargo test ...`, which streams "
                f"the output and asserts the captured copy.\n      "
                f"{segment[:120]}"
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
