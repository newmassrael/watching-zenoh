#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2084 (no register item) — a test that waits FOREVER for a process it spawned.

## The measurement that asked for this gate

R2082 added a Layer Z leg that opens its own TCP listener, spawns `wz-ap-demo`
at it, and reads the first frame the demo writes. `TcpListener::accept` has no
deadline and `#[tokio::test]` imposes none, so the leg's whole liveness rested
on the demo actually dialling.

It did not. A separate defect (a missing Layer E skip token) sent that leg into
a lane whose demo is built WITHOUT `zenoh-config`; such a build exits on
`--config` and never connects. The hosted `demo-spawning e2e` job did not
report a failed test — it was CANCELLED on its timeout, which means it reported
NOTHING, and the two real failures in that run were found only because a
different job happened to red. A test that waits forever does not fail. It
spends the job's budget and takes every verdict after it down with it.

## Why this is a gate and not a fix

The fix is one deadline. The CLASS is that nothing forces the next one. And the
tree already agrees with the rule: of the 29 accept sites in test files that
spawn an external process, 21 were already under `tokio::time::timeout`. The
convention exists; it just had no gate, so eight had drifted off it.

## The boundary, and why it is drawn there

IN SCOPE: an `accept()` in `crates/**/tests/*.rs`, in a file that spawns an
external process (`Command::new` / `CARGO_BIN_EXE`). The partner is then
OUTSIDE the test — a foreign binary that can die, mis-parse its argv, or be
built without the feature under test — and nothing in the process will ever
make that `accept` return.

OUT OF SCOPE: accepts whose partner is in-process. A test that dials itself has
a different failure mode and a different fix; sweeping 50 of them into this
gate would make it a ceiling to be ratcheted rather than a rule to be kept.
That is a boundary, so it is COUNTED and PRINTED, not silently dropped.

A site passes when `timeout` or `deadline` appears within the six lines above
it (inclusive) — the two shapes this tree actually uses: the async
`tokio::time::timeout(D, listener.accept())`, and the blocking non-blocking
poll loop that compares against an `Instant` deadline.
"""

from __future__ import annotations

import pathlib
import sys

WINDOW = 6
SPAWN_MARKERS = ("Command::new", "CARGO_BIN_EXE")
DEADLINE_MARKERS = ("timeout", "deadline")

# Anti-vacuity floors. A lint that silently matches nothing is a lint that
# reports green forever; these are the shapes that would produce that here — a
# moved test tree, a renamed extension, a glob that stops globbing.
MIN_TEST_FILES = 100
MIN_ACCEPT_SITES = 20
MIN_SPAWNING_SITES = 10


def has_deadline(lines: list[str], index: int) -> bool:
    window = "\n".join(lines[max(0, index - WINDOW) : index + 1])
    return any(marker in window for marker in DEADLINE_MARKERS)


def scan(root: pathlib.Path):
    files = sorted(root.glob("crates/**/tests/*.rs"))
    total_sites = 0
    in_scope = 0
    out_of_scope = 0
    violations: list[tuple[str, int, str]] = []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        spawns = any(marker in text for marker in SPAWN_MARKERS)
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if ".accept()" not in line:
                continue
            total_sites += 1
            if not spawns:
                out_of_scope += 1
                continue
            in_scope += 1
            if has_deadline(lines, index):
                continue
            violations.append((str(path.relative_to(root)), index + 1, line.strip()))
    return files, total_sites, in_scope, out_of_scope, violations


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[2]
    files, total_sites, in_scope, out_of_scope, violations = scan(root)

    print(
        f"accept-deadline: {len(files)} test file(s), {total_sites} accept site(s) "
        f"-- {in_scope} in scope (the test spawns an external process), "
        f"{out_of_scope} out of scope (in-process partner)"
    )

    for what, count, floor in (
        ("test files", len(files), MIN_TEST_FILES),
        ("accept sites", total_sites, MIN_ACCEPT_SITES),
        ("in-scope sites", in_scope, MIN_SPAWNING_SITES),
    ):
        if count < floor:
            print(
                f"accept-deadline FAIL: only {count} {what} found, floor is {floor}. "
                "This gate is measuring less than it was built to measure -- read it "
                "before lowering the floor.",
                file=sys.stderr,
            )
            return 1

    if violations:
        print(
            f"accept-deadline FAIL: {len(violations)} accept(s) wait forever for a "
            "process the test spawned:",
            file=sys.stderr,
        )
        for path, line, src in violations:
            print(f"  {path}:{line}: {src}", file=sys.stderr)
        print(
            "\nIf the spawned partner never dials -- it died, it mis-read its argv, it "
            "was built without the feature under test -- this accept never returns. The "
            "test does not fail; the JOB is cancelled on its timeout and every verdict "
            "after it is lost. That is not hypothetical: it is how R2082's hosted "
            "`demo-spawning e2e` job reported nothing at all.\n"
            "Fix: wrap it -- `tokio::time::timeout(D, listener.accept()).await` for the "
            "async shape, or a non-blocking poll loop against an `Instant` deadline for "
            "the blocking one. Say WHY the partner might be missing in the panic text; "
            "that message is the whole point of the deadline.",
            file=sys.stderr,
        )
        return 1

    print("accept-deadline: OK -- every in-scope accept is under a deadline")
    return 0


def selftest() -> int:
    """Prove the gate FAILS on the shape it exists to reject.

    A lint is only worth its runtime if it has been seen to go red. This builds
    both halves in memory -- a spawning file with a bare accept, and the same
    file with a deadline -- and asserts the verdict differs. It drives the same
    `has_deadline` the scan drives, so a change to the rule cannot pass here and
    fail there.
    """

    def verdict(text: str, spawns: bool) -> bool:
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if ".accept()" not in line:
                continue
            if not spawns:
                continue
            if not has_deadline(lines, index):
                return False
        return True

    bare = 'Command::new("x");\nlet (s, _) = listener.accept().await.unwrap();\n'
    fixed = (
        'Command::new("x");\n'
        "let a = tokio::time::timeout(D, listener.accept()).await;\n"
        "let (s, _) = a.unwrap().unwrap();\n"
    )
    far = (
        'Command::new("x");\n'
        "let d = Instant::now() + D;\n"
        + "// filler\n" * WINDOW
        + "let (s, _) = listener.accept().unwrap();\n"
    )

    ok = True
    if verdict(bare, True):
        print("selftest FAIL: a bare accept in a spawning file was accepted", file=sys.stderr)
        ok = False
    if not verdict(fixed, True):
        print("selftest FAIL: a deadlined accept was rejected", file=sys.stderr)
        ok = False
    if not verdict(bare, False):
        print("selftest FAIL: an in-process accept was pulled into scope", file=sys.stderr)
        ok = False
    if verdict(far, True):
        print(
            "selftest FAIL: a deadline further than the window was counted -- the "
            "window is the rule, so it has to bind",
            file=sys.stderr,
        )
        ok = False
    print("accept-deadline selftest:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(selftest())
    raise SystemExit(main())
