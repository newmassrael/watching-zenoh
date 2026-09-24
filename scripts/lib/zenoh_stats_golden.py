#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2821 (no register item) -- regenerate, or check, the golden documents the
wz stats registry is compared against, by running the REAL `zenoh-stats` at the
pin.

The item this serves is open-debt item 715 in the agent-memory register (the
adminspace metrics body had no per-transport / per-link / per-key partitions),
which has no store id for `gate_provenance_lint.py` to resolve -- hence the
escape hatch above, with the item named here in prose.

WHY A GENERATOR AND NOT A HAND-WRITTEN EXPECTATION. The wz encoder
(`crates/wz-session-core/src/stats_registry.rs`) claims to write what upstream
writes. A test whose expected text was typed from reading upstream's source
would test the reading, not upstream -- and upstream's output here is shaped by
a third-party encoder (`prometheus-client`) whose choices (a `.` appended to a
registered help string but not to a collector's, `le` written BEFORE the family
labels, `None` written as `""`, a per-key histogram with no `+Inf` bucket) are
exactly what a reader gets wrong. So the expectation is PRODUCED by upstream's
code and committed with the versions it came from, and this script is how
anyone reproduces it.

WHAT IT DOES. It runs `oracles/zenoh-stats-golden` -- a member of the
wz-authored oracle workspace, which pins zenoh by the same tag as its siblings
and resolves `prometheus-client` to the version upstream's own lock names --
and normalises its stdout (below) under a provenance header read from
`oracles/Cargo.lock`. That text IS the golden.

MODES -- required, no default, and an unknown argument is refused by name
(`relicense_spdx.py`'s rule: read and write are opposites here, so the program
does not guess which was meant):
  --check  regenerate into memory and FAIL if the committed golden differs.
  --write  regenerate and overwrite the committed golden.

A build that cannot run is exit 2 with the reason, never a comparison that was
not made.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
ORACLES = REPO / "oracles"
PACKAGE = "wz-oracle-zenoh-stats-golden"
GOLDEN = REPO / "crates" / "wz-session-core" / "src" / "stats_registry" / "zenoh_1_10_1.golden"


def locked_version(lock: str, crate: str) -> str | None:
    m = re.search(
        r'^name = "' + re.escape(crate) + r'"\nversion = "([^"]+)"', lock, re.MULTILINE
    )
    return m.group(1) if m else None


def normalise(stdout: str) -> str:
    """Sort each descriptor block's SAMPLE lines, keeping every `#` line in place.

    Upstream collects through `HashMap`s, so two runs of the same events write a
    block's samples in different orders -- measured: the first `--check` after a
    `--write` differed on this alone. Order inside a block is not a property of
    the format, so the golden stores one canonical order and the Rust test
    compares each block as a multiset. The descriptor sequence, which IS a
    property of the document, is untouched.
    """
    out: list[str] = []
    samples: list[str] = []
    for line in stdout.splitlines():
        if line.startswith("#") or line.startswith("====="):
            out.extend(sorted(samples))
            samples = []
            out.append(line)
        else:
            samples.append(line)
    out.extend(sorted(samples))
    return "\n".join(out) + "\n"


def generate() -> str:
    lock = (ORACLES / "Cargo.lock").read_text()
    stats_version = locked_version(lock, "zenoh-stats")
    prometheus_version = locked_version(lock, "prometheus-client")
    if stats_version is None or prometheus_version is None:
        raise SystemExit(
            "zenoh-stats-golden: INPUT ERROR -- oracles/Cargo.lock names no "
            "zenoh-stats or prometheus-client; is the oracle a workspace member?"
        )
    run = subprocess.run(
        ["cargo", "run", "--release", "--quiet", "-p", PACKAGE],
        cwd=ORACLES,
        capture_output=True,
        text=True,
    )
    if run.returncode != 0:
        sys.stderr.write(run.stderr)
        raise SystemExit(
            f"zenoh-stats-golden: INPUT ERROR -- the oracle did not run (cargo exit {run.returncode})"
        )
    header = (
        f"# zenoh-stats {stats_version} with prometheus-client {prometheus_version}: "
        f"the documents oracles/zenoh-stats-golden makes the pinned registry write.\n"
        "# Regenerate with `python3 scripts/lib/zenoh_stats_golden.py --write`; never edit by hand.\n"
    )
    return header + normalise(run.stdout)


def main(argv: list[str]) -> int:
    modes = {"--check", "--write"}
    unknown = [a for a in argv if a not in modes]
    if unknown:
        print(f"zenoh-stats-golden: unknown argument(s): {' '.join(unknown)}", file=sys.stderr)
        return 2
    chosen = [a for a in argv if a in modes]
    if len(chosen) != 1:
        print("zenoh-stats-golden: exactly one of --check / --write is required", file=sys.stderr)
        return 2
    text = generate()
    scenarios = text.count("\n===== END\n")
    if scenarios == 0:
        print("zenoh-stats-golden: FAIL -- the oracle wrote no scenario", file=sys.stderr)
        return 1
    if chosen[0] == "--write":
        GOLDEN.write_text(text)
        print(f"zenoh-stats-golden: wrote {scenarios} scenario(s) to {GOLDEN.relative_to(REPO)}")
        return 0
    committed = GOLDEN.read_text() if GOLDEN.exists() else ""
    if committed != text:
        print(
            f"zenoh-stats-golden: FAIL -- {GOLDEN.relative_to(REPO)} differs from what the "
            "pinned zenoh-stats writes; regenerate with --write and review the diff",
            file=sys.stderr,
        )
        return 1
    print(f"zenoh-stats-golden: OK -- {scenarios} scenario(s) match the pinned zenoh-stats")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
