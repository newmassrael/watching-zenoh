#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y922 (no register item) — the GATE TEST-PIN lint.

Closes item 232 of the unregistered register, filed R311y858 and paid twice;
that register lives outside this repository, which is why the citation above
reads "no register item" rather than naming a store row that does not exist.

Several run-ci lanes do not merely run a crate's tests -- they pin a SET of
test names that must be PRESENT in a particular feature build, because a
`#[cfg]`-gated test that vanishes reports `ok. N passed` with N silently
smaller. That pin is the only thing standing between a lean build and a
witness quietly leaving it.

A pin is a statement about code, and it goes stale the same way any other
statement does: the test gets renamed, or deleted, or -- the shape that has
actually happened twice -- MOVED to another crate.

  * R311y856 moved the protobuf decoder from `wz-analyze` to `wz-capture`
    while Layer C1bw kept calling `payload_formats::tests::*` in wz-analyze's
    lib target. Five local lanes were green; none of them could answer,
    because a per-crate suite asks "does this pass" and a pin asks "is this
    still HERE", and the subject had left the crate.
  * R311y921 moved the RFC character table out of `wz-capture::report` into
    `wz_session_core::json` and left a comment reading "a pin travels with
    the code it pins" -- about the in-code pin. Layer C1bt's pin did not
    travel. The lane went red on the name of a test that had not been
    deleted, only rehoused, and it STAYED red for six pushes because a
    push's verdict is read a round later.

Item 232 measured the population at the time (231 pins, 0 stale beyond the
five it was filed for) and said the real gate needed its own round because
resolving a Rust module path from a shell script is not a one-liner. This
is that round, and the resolution problem is sidestepped rather than solved:

  THE LEAF IS WHAT IS CHECKED, NOT THE PATH.

A pin `report::tests::this_crate_has_one_json_escaper` is required to have a
`fn this_crate_has_one_json_escaper` somewhere in the crate the surrounding
lane tests. The module path is NOT verified. That is a deliberate weakening,
and it is the difference between a gate that fires and one that cries wolf:
item 232's own second pass, which did try to resolve module paths by a
"file stem == first segment" heuristic, raised 13 findings of which 13 were
false (`quic::connection` is a directory module, and there are more shapes
where that came from). A pin whose leaf exists but whose path is wrong makes
the lane red on the next full run; a pin whose leaf is GONE makes the lane
red too, but only after the build, which is minutes and a round away.

What this catches, then, is exactly the class that has cost rounds: a test
that no longer exists under that name in that crate. What it does not catch
is a pin that names a real test through the wrong module path.

The crate a block belongs to is read from the nearest preceding
`cargo test -p <crate>` in the same file, which is how the lanes are
actually written -- the listing the block greps is produced by that command.
An unattributable block is a FAILURE, not a skip: a gate that cannot read
its input must not report green. So is an empty population.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RUN_CI = REPO / "scripts" / "run-ci.sh"
CRATES = REPO / "crates"

BLOCK_OPENER = "for name in \\"
CARGO_TEST = re.compile(r"cargo test -p ([a-z0-9_-]+)")
FN_DECL = re.compile(r"\bfn\s+([a-z0-9_]+)\s*\(")

# How far back a block may look for the cargo invocation that produced the
# listing it greps. Generous enough for the longest lane as written, small
# enough that a block whose lane was deleted cannot silently borrow the
# crate of an unrelated lane above it.
LOOKBACK = 120


def package_dirs() -> dict[str, Path]:
    """Package name -> crate directory, read from each Cargo.toml.

    The directory name and the package name agree everywhere in this tree
    today, which is exactly why this is read rather than assumed: the day
    they stop agreeing, a lint that guessed would look at the wrong sources
    and report a clean sheet.
    """
    out: dict[str, Path] = {}
    for manifest in sorted(CRATES.glob("*/Cargo.toml")):
        for line in manifest.read_text(encoding="utf-8").splitlines():
            m = re.match(r'\s*name\s*=\s*"([^"]+)"', line)
            if m:
                out[m.group(1)] = manifest.parent
                break
    return out


def declared_fns(crate_dir: Path) -> set[str]:
    """Every `fn <name>(` under a crate's src/ and tests/.

    Over-inclusive on purpose: a name that appears as any function in the
    crate is not evidence of a stale pin, and this lint only claims to find
    names that are ABSENT.
    """
    names: set[str] = set()
    for sub in ("src", "tests", "benches"):
        root = crate_dir / sub
        if not root.is_dir():
            continue
        for path in root.rglob("*.rs"):
            names |= set(FN_DECL.findall(path.read_text(encoding="utf-8")))
    return names


def pin_blocks(lines: list[str]) -> list[tuple[int, str | None, list[str]]]:
    """Every pinned-name block, with the crate its lane tests."""
    blocks: list[tuple[int, str | None, list[str]]] = []
    for i, line in enumerate(lines):
        if line.strip() != BLOCK_OPENER:
            continue
        crate: str | None = None
        for j in range(i, max(-1, i - LOOKBACK), -1):
            m = CARGO_TEST.search(lines[j])
            if m:
                crate = m.group(1)
                break
        names: list[str] = []
        k = i + 1
        while k < len(lines) and lines[k].strip() != "do":
            name = lines[k].strip().rstrip("\\").strip()
            if name:
                names.append(name)
            k += 1
        blocks.append((i + 1, crate, names))
    return blocks


def main() -> int:
    # An optional path so the FAILURE arms below can be driven by a fixture.
    # A guard whose failure cannot be reached is not a guard, and the three
    # that matter here -- an unattributable block, a package that does not
    # exist, an empty population -- all report a false GREEN if they are
    # wrong, which is the one direction a lint must never fail in.
    run_ci = Path(sys.argv[1]) if len(sys.argv) > 1 else RUN_CI
    if not run_ci.is_file():
        print(f"gate-test-pin: cannot read {run_ci}", file=sys.stderr)
        return 1
    if not CRATES.is_dir():
        print(f"gate-test-pin: cannot read {CRATES}", file=sys.stderr)
        return 1

    lines = run_ci.read_text(encoding="utf-8").splitlines()
    where = run_ci.name
    blocks = pin_blocks(lines)
    packages = package_dirs()

    failures: list[str] = []

    if not blocks:
        failures.append(
            f"  gate-test-pin FAIL: no pinned-name block found in {where} -- "
            "either the lanes lost their pins or this lint lost its anchor"
        )

    total = 0
    fns: dict[str, set[str]] = {}
    for line_no, crate, names in blocks:
        if crate is None:
            failures.append(
                f"  gate-test-pin FAIL: the pin block at {where}:{line_no} has no "
                f"`cargo test -p <crate>` within {LOOKBACK} lines above it, so the "
                "crate its names live in cannot be decided"
            )
            continue
        if not names:
            failures.append(
                f"  gate-test-pin FAIL: the pin block at {where}:{line_no} is empty"
            )
            continue
        crate_dir = packages.get(crate)
        if crate_dir is None:
            failures.append(
                f"  gate-test-pin FAIL: {where}:{line_no} pins names in `{crate}`, "
                "which is not a package under crates/"
            )
            continue
        if crate not in fns:
            fns[crate] = declared_fns(crate_dir)
        for name in names:
            total += 1
            leaf = name.rsplit("::", 1)[-1]
            if leaf not in fns[crate]:
                failures.append(
                    f"  gate-test-pin FAIL: {where}:{line_no} pins `{name}`, but "
                    f"`{crate}` declares no `fn {leaf}` -- the test was renamed, "
                    "deleted, or moved to another crate, and the pin did not travel "
                    "with it"
                )

    if total == 0 and not failures:
        failures.append(
            "  gate-test-pin FAIL: 0 pinned names were read, so this lint measured "
            "nothing and must not report green"
        )

    if failures:
        print("\n".join(failures))
        return 1

    print(
        f"  gate-test-pin: {total} pinned test name(s) across {len(blocks)} block(s) "
        f"in {len(fns)} crate(s) still name a function that crate declares"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
