#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2707 (open-debt item 783) — a buffered subscription's DRAIN is wired, not
dropped.

## The class

`Session::declare_subscriber_buffered` returns three values, and the third is an
obligation: a `BufferedDrainStage` whose `drain()` the drive loop must await, or
the subscription stalls the moment its consumer falls behind. R2705 made the
common case not need it -- the callback delivers straight through while the
consumer keeps up -- so what is left is the quiet half: a host that never wires
a drain is correct until the first slow reader and then stops, silently.

Two things guard that. `#[must_use]` on the returned stage, which this
workspace's `-D warnings` turns into an error for a caller that simply drops it;
and this gate, which catches the escape `#[must_use]` cannot -- binding it to
`_` and moving on.

## Why a gate at all, when the type already says it

Because `_` is legal and invisible. The measured history is the argument: the
invariant was carried by a `log::error!` that named the cause EXACTLY, and a
hosted lane still went red over it for two runs (`docs/hosted-red-acks.md`,
R2705). A sentence that is right and unread is the shape this workspace files as
debt rather than trusts.

## The population, and what "wired" means

DERIVED, never listed: every call site of `declare_subscriber_buffered` across
`crates/`, found by name. For each, the CRATE that contains it must also reach a
drain -- `drain_buffered`, or `BufferedDrainStage` used as more than a discard.
Per crate rather than per call site, and that is a deliberate looseness the seam
itself justifies: one stage drains the whole session's registry, so a crate with
three buffered subscriptions wires one drain and is correct.

⚠ WHAT THIS DOES NOT DO. It cannot tell a drain that is wired into a loop that
RUNS from one wired into a loop that is never driven, and it does not follow the
obligation across a crate boundary -- a library that declares and hands its
receiver to an embedder (`wz-rest`'s SSE bridge is exactly that) is judged by
whether its own tests drive it. Both are named here rather than left for a
reader to discover, and both are why the type-level `#[must_use]` is the first
line and this is the second.

Usage:
    python3 scripts/lib/buffered_drain_wiring_gate.py
    python3 scripts/lib/buffered_drain_wiring_gate.py --selftest
"""

from __future__ import annotations

import pathlib
import re
import sys
import tempfile

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

DECLARE = "declare_subscriber_buffered"
# What counts as reaching a drain. `drain_buffered` is the session's own walk;
# `BufferedDrainStage` names the value, and a crate that names the TYPE is
# holding it for something.
DRAIN_MARKERS = ("drain_buffered", "BufferedDrainStage", ".drain()")
# The discard that `#[must_use]` cannot see: the third binding is `_`.
DISCARDED_RE = re.compile(r"let\s*\(\s*[^)]*,\s*_\s*\)\s*=\s*[^;]*" + DECLARE)


def crate_of(path: pathlib.Path, root: pathlib.Path) -> str:
    """The crate directory a file belongs to, or "" when it is outside one."""
    try:
        rel = path.relative_to(root / "crates")
    except ValueError:
        return ""
    return rel.parts[0] if rel.parts else ""


def scan(root: pathlib.Path) -> tuple[dict[str, list[str]], dict[str, bool], list[str]]:
    """Call sites per crate, whether each crate reaches a drain, and discards."""
    sites: dict[str, list[str]] = {}
    drains: dict[str, bool] = {}
    discards: list[str] = []
    crates = root / "crates"
    if not crates.is_dir():
        return sites, drains, discards
    for path in sorted(crates.rglob("*.rs")):
        crate = crate_of(path, root)
        if not crate:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if DECLARE not in text and not any(m in text for m in DRAIN_MARKERS):
            continue
        rel = str(path.relative_to(root))
        # NEITHER THE DEFINITION NOR A MENTION OF IT. The definition is the one
        # place the name is introduced, and counting it would make the seam's
        # own crate a caller of itself; a doc comment that LINKS the name is
        # prose, and counting it would report a population larger than the one
        # that can stall -- the misreport this workspace files as a defect in
        # its own right. Measured on this tree: 6 lines carry the name and 3 of
        # them are comments.
        for i, line in enumerate(text.splitlines(), 1):
            if DECLARE not in line:
                continue
            if "pub fn " in line:
                continue
            if line.lstrip().startswith(("//", "*", "/*")):
                continue
            sites.setdefault(crate, []).append(f"{rel}:{i}")
        if any(m in text for m in DRAIN_MARKERS):
            drains[crate] = True
        for m in DISCARDED_RE.finditer(text.replace("\n", " ")):
            discards.append(f"{rel}: {m.group(0)[:70]}")
    return sites, drains, discards


def report(root: pathlib.Path, out=sys.stdout) -> int:
    sites, drains, discards = scan(root)
    total = sum(len(v) for v in sites.values())
    print(
        f"  buffered-drain-wiring: {total} call site(s) of {DECLARE} in "
        f"{len(sites)} crate(s)",
        file=out,
    )
    # A POPULATION OF ZERO IS NOT A PASS. The seam exists and its declaration is
    # public; a scan that finds no caller has lost its subject -- a rename, a
    # moved crate root, or this gate pointed at the wrong tree.
    if total == 0:
        print(
            "  buffered-drain-wiring FAIL: no call site found at all. The seam is "
            "public and has callers; a population of zero means this gate is "
            "reading the wrong tree or the name moved.",
            file=out,
        )
        return 1
    failed = 0
    for crate in sorted(sites):
        where = ", ".join(sites[crate])
        if drains.get(crate):
            print(f"  buffered-drain-wiring: ok    {crate} ({where})", file=out)
        else:
            failed += 1
            print(
                f"  buffered-drain-wiring FAIL: {crate} declares a buffered "
                f"subscription at {where} and nothing in the crate reaches a "
                f"drain. Its samples stage and stop the moment the consumer "
                f"falls behind. Wire the third return value as "
                f"`LoopStages::after_dispatch`, or await "
                f"`Session::drain_buffered` there.",
                file=out,
            )
    for d in discards:
        failed += 1
        print(
            f"  buffered-drain-wiring FAIL: the drain obligation is discarded "
            f"into `_` at {d}. `#[must_use]` cannot see that binding, which is "
            f"why this gate exists.",
            file=out,
        )
    return 1 if failed else 0


def selftest() -> int:
    """Drive the report over trees whose answer is known.

    Four cases, and the third is the one `#[must_use]` cannot reach. The fourth
    is the anti-vacuity arm: a gate whose population can go empty and still
    report ok would pass on a renamed seam forever.
    """
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)

        def crate(name: str, body: str) -> None:
            d = root / "crates" / name / "src"
            d.mkdir(parents=True, exist_ok=True)
            (d / "lib.rs").write_text(body, encoding="utf-8")

        # 1. WIRED: declares and drains.
        crate(
            "wired",
            "fn a(){ let (s, rx, st) = x.declare_subscriber_buffered(); }\n"
            "fn b(){ session.drain_buffered().await; }\n",
        )
        rc = report(root, out=open(root / "out1", "w"))
        if rc != 0:
            failures.append(f"a wired crate must pass, got rc={rc}")

        # 2. UNWIRED: declares and nothing drains.
        crate("unwired", "fn a(){ let (s, rx, st) = x.declare_subscriber_buffered(); }\n")
        rc = report(root, out=open(root / "out2", "w"))
        if rc != 1:
            failures.append(f"an unwired crate must fail, got rc={rc}")
        text = (root / "out2").read_text()
        if "unwired" not in text:
            failures.append("the refusal must NAME the crate")

        # 3. DISCARDED: the obligation goes into `_`, which `#[must_use]` allows.
        import shutil

        shutil.rmtree(root / "crates" / "unwired")
        crate(
            "discarded",
            "fn a(){ let (s, rx, _) = x.declare_subscriber_buffered(); }\n"
            "fn b(){ session.drain_buffered().await; }\n",
        )
        rc = report(root, out=open(root / "out3", "w"))
        if rc != 1:
            failures.append(f"a discarded obligation must fail even when the crate drains, got rc={rc}")

        # 4. ANTI-VACUITY: no call site anywhere is a FAILURE, not a pass.
        shutil.rmtree(root / "crates" / "discarded")
        shutil.rmtree(root / "crates" / "wired")
        crate("empty", "fn a(){}\n")
        rc = report(root, out=open(root / "out4", "w"))
        if rc != 1:
            failures.append(f"an empty population must fail, got rc={rc}")

    for f in failures:
        print(f"  buffered-drain-wiring SELFTEST FAIL: {f}", file=sys.stderr)
    if failures:
        return 1
    print("  buffered-drain-wiring: selftest ok (4 case(s))")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--selftest":
        return selftest()
    if len(argv) > 1:
        print(f"unknown argument: {argv[1]}", file=sys.stderr)
        return 2
    return report(REPO_ROOT)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
