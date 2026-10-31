#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
  --header read only the golden's provenance line and the oracle's lock, and FAIL
           when they name different versions (no build; Layer C0 and pre-push).
  --header-selftest  the comparison against fixtures.

A build that cannot run is exit 2 with the reason, never a comparison that was
not made.
"""

from __future__ import annotations

import difflib
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
ORACLES = REPO / "oracles"
PACKAGE = "wz-oracle-zenoh-stats-golden"
# Named for what it holds, not for a version: the file's first line carries the
# versions it was made at, and a name that carried one went stale beside the pin
# (the golden said 1.10.2 under a 1_10_1 name, and Layer E17 was red for it).
GOLDEN = REPO / "crates" / "wz-session-core" / "src" / "stats_registry" / "zenoh_stats.golden"


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


HEADER_RE = re.compile(r"^# zenoh-stats (\S+) with prometheus-client (\S+):")


def header_findings(golden_text: str, lock_text: str) -> list[str]:
    """What the golden's provenance line says that the oracle's lock does not.

    The line names the versions the document was made at, and the lock names the
    versions the oracle builds at. A pin bump moves the lock and leaves the
    golden until someone regenerates it: round 3976 moved the pin and the golden
    kept saying 1.10.1, which only Layer E17 (a build of the oracle, on a hosted
    job) could see. Text only, so a bump meets it where it is made.
    """
    found = HEADER_RE.match(golden_text.splitlines()[0] if golden_text else "")
    if not found:
        return ["the golden's first line is not a provenance line"]
    out = []
    for crate, said in (("zenoh-stats", found.group(1)), ("prometheus-client", found.group(2))):
        locked = locked_version(lock_text, crate)
        if locked is None:
            out.append(f"oracles/Cargo.lock names no {crate}")
        elif locked != said:
            out.append(f"the golden says {crate} {said}, the lock builds {locked}")
    return out


def header_selftest() -> int:
    lock = (
        'name = "zenoh-stats"\nversion = "1.2.3"\n\n'
        'name = "prometheus-client"\nversion = "0.9.0"\n'
    )
    good = "# zenoh-stats 1.2.3 with prometheus-client 0.9.0: x\nbody\n"
    assert header_findings(good, lock) == []
    stale = "# zenoh-stats 1.2.2 with prometheus-client 0.9.0: x\n"
    assert len(header_findings(stale, lock)) == 1
    both = "# zenoh-stats 1.2.2 with prometheus-client 0.8.0: x\n"
    assert len(header_findings(both, lock)) == 2
    assert header_findings("", lock) and header_findings("not a header\n", lock)
    assert header_findings(good, "") == [
        "oracles/Cargo.lock names no zenoh-stats",
        "oracles/Cargo.lock names no prometheus-client",
    ]
    print("zenoh-stats-golden: header selftest OK")
    return 0


def header_check() -> int:
    findings = header_findings(
        GOLDEN.read_text() if GOLDEN.exists() else "", (ORACLES / "Cargo.lock").read_text()
    )
    if findings:
        for f in findings:
            print(f"zenoh-stats-golden: FAIL -- {f}; regenerate with --write", file=sys.stderr)
        return 1
    print("zenoh-stats-golden: OK -- the golden's provenance line matches oracles/Cargo.lock")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--header"]:
        return header_check()
    if argv == ["--header-selftest"]:
        return header_selftest()
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
        # The first lines of the difference, so a red on a machine nobody can reach says WHAT
        # differs (a version in the provenance header, a metric's name, an ordering) and not
        # only that something does.
        shown = list(
            difflib.unified_diff(
                committed.splitlines(),
                text.splitlines(),
                "committed",
                "regenerated",
                lineterm="",
                n=1,
            )
        )
        for line in shown[:60]:
            print(f"  {line}", file=sys.stderr)
        if len(shown) > 60:
            print(f"  ... {len(shown) - 60} more line(s)", file=sys.stderr)
        return 1
    print(f"zenoh-stats-golden: OK -- {scenarios} scenario(s) match the pinned zenoh-stats")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
