#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y740 (N37) -- every keyexpr-resolution PLANE must carry an own-space
witness pair.

(The `R311y<round> (<item>)` opening is the convention carry N43 is about: a
gate that does not name what it closes leaves the register unable to tell,
mechanically, whether that item is still open. 10 of 33 gate scripts in
`scripts/lib` follow it as of this round.)

## What it closes

R311y739 wired BOTH id spaces (the peer's and ours) into the observer fan and
made the type enforce it: a consumer that takes a bare `&HashMap` no longer
compiles, because the fan hands over `MappingSpaces`. What the type CANNOT say
is that each plane then *reads the space the M bit named*. A registry is free
to accept `MappingSpaces` and resolve through some other route -- the weaker
`SubscriberRegistry::peer_keyexpr_table()` accessor is still in reach (N38) --
and the compiler would be satisfied. Round R311y739 measured exactly one plane
end-to-end (Push) and *argued* the other eight from their sharing
`resolve_wireexpr_in`; that argument was the whole of the evidence, which is
what carry item N37 recorded.

This lint turns the argument into an obligation. It reads the plane population
OUT OF THE CODE -- every module that takes `impl Into<MappingSpaces<'a>>`, plus
the registry that owns the pair and reaches it via `mapping_spaces()` -- and
requires each one to carry:

  * a POSITIVE witness  -- a test whose name contains `an_own_space`, and
  * an ANTI-VACUITY twin -- a test whose name starts `without_an` and mentions
    an own space.

The pair is the point. A positive witness alone passes just as well when the
fixture cannot tell the two spaces apart, and this workspace has shipped that
shape before; the twin is what proves the fixture is measuring the install.

## Why the population is computed, not listed

A hand-written list of planes is a list that goes stale the moment a tenth
plane lands -- which is precisely how N37 came to exist. Deriving it from the
parameter type means a new consumer arrives already counted: it appears in the
population, has no witness, and this lint reds.

Emits the expected witness SET (not a count) on stdout so the run-ci lane can
compare it against the tests cargo actually EXECUTED. A count would be
satisfied by two witnesses on one plane and none on another.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# The parameter type that MAKES something a plane: the observer fan hands this
# over, and taking it is what says "I resolve keyexprs against the pair".
FAN_PARAM = re.compile(r"impl\s+Into<MappingSpaces<")

# The registry that OWNS the pair reaches it through its own accessor rather
# than taking it as a parameter, so it would otherwise be invisible here --
# and it is the one plane R311y739 did witness.
OWNER_ACCESSOR = re.compile(r"self\.mapping_spaces\(\)")

# `wireexpr_resolve.rs` DEFINES `MappingSpaces`; it is the resolver under test,
# not a plane that consumes it. Its own suite pins the resolver's arms.
NOT_A_PLANE = {"wireexpr_resolve.rs"}

TEST_FN = re.compile(r"^\s*fn\s+([a-z0-9_]+)\s*\(", re.MULTILINE)
# Both patterns are ANCHORED. Unanchored, `an_own_space` is a substring of
# `without_an_own_space_...`, so every anti-vacuity twin also scored as a
# positive -- which would let a plane satisfy the pair with two negatives and
# no positive at all. Anchoring is what keeps the two halves disjoint.
POSITIVE = re.compile(r"^an_own_space")
ANTI_VACUITY = re.compile(r"^without_an.*own_space")


def plane_files(src_root: Path) -> list[Path]:
    """Every module that consumes the space pair, sorted for stable output."""
    found = []
    for path in sorted(src_root.rglob("*.rs")):
        if path.name in NOT_A_PLANE:
            continue
        text = path.read_text(encoding="utf-8")
        if FAN_PARAM.search(text) or OWNER_ACCESSOR.search(text):
            found.append(path)
    return found


def witnesses(text: str) -> tuple[list[str], list[str]]:
    names = TEST_FN.findall(text)
    positive = [n for n in names if POSITIVE.search(n)]
    anti = [n for n in names if ANTI_VACUITY.search(n)]
    return positive, anti


def check_executed(expected: set[str], log_path: Path) -> list[str]:
    """The N42 half: a witness that EXISTS but never RUNS is not a witness.

    Every one of these suites sits behind its module's own feature gate, and a
    lane that names the wrong features selects zero tests and reports green --
    this workspace has done exactly that (R311y739 ran a strip-prefix suite
    under the wrong feature, got `0 filtered out`, and read it as a pass). So
    the lane feeds cargo's own executed-test list back in and this compares
    SETS, not counts: two witnesses on one plane and none on another would
    satisfy a count.
    """
    text = log_path.read_text(encoding="utf-8")
    # `test <path>::<name> ... ok` -- take the leaf name.
    ran = {
        m.group(1).rsplit("::", 1)[-1]
        for m in re.finditer(r"^test ([\w:]+) \.\.\. ok$", text, re.MULTILINE)
    }
    if not ran:
        return [
            f"{log_path}: cargo executed ZERO tests. Either the filter matched "
            f"nothing or the feature union does not open the suites -- both "
            f"report green without measuring anything."
        ]
    missing = sorted(expected - ran)
    return [
        f"witness `{name}` exists in the source but did NOT run under this "
        f"lane's feature union -- add the feature that opens its module"
        for name in missing
    ]


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    src_root = repo_root / "crates" / "wz-session-core" / "src"
    if not src_root.is_dir():
        print(f"own-space-witness: FAIL -- {src_root} is not a directory", file=sys.stderr)
        return 1

    planes = plane_files(src_root)

    # A collector that finds nothing must never report green: an empty
    # population is indistinguishable from total coverage, and this workspace
    # has been bitten by exactly that (a gate whose own population was narrow
    # passed while the thing it guarded was broken).
    if not planes:
        print(
            "own-space-witness: FAIL -- found ZERO keyexpr-resolution planes. "
            "The population regex has drifted from the code; a gate that "
            "cannot see its subject must not pass.",
            file=sys.stderr,
        )
        return 1

    failures = []
    expected: set[str] = set()
    for path in planes:
        text = path.read_text(encoding="utf-8")
        positive, anti = witnesses(text)
        rel = path.relative_to(repo_root)
        if not positive:
            failures.append(
                f"{rel}: takes the MappingSpaces pair but has NO own-space witness "
                f"(a test named `*an_own_space*` that resolves an M=0 alias and "
                f"asserts OUR literal, with a colliding id in both spaces)"
            )
        if not anti:
            failures.append(
                f"{rel}: has no ANTI-VACUITY twin (a test named "
                f"`without_an_*own_space*` proving the same fixture resolves "
                f"NOTHING when only the peer's space is supplied)"
            )
        expected.update(positive)
        expected.update(anti)

    # `--executed <cargo-test-log>` turns the static check into a measured one.
    if len(sys.argv) == 3 and sys.argv[1] == "--executed":
        failures.extend(check_executed(expected, Path(sys.argv[2])))
    elif len(sys.argv) != 1:
        print(
            "usage: own_space_witness_lint.py [--executed <cargo-test-log>]",
            file=sys.stderr,
        )
        return 2

    if failures:
        print("own-space-witness: FAIL", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        print(
            "\n  Every plane the observer fan feeds must MEASURE that it reads "
            "the space the M bit named -- sharing `resolve_wireexpr_in` is an "
            "argument, not a measurement (R311y740, carry N37).",
            file=sys.stderr,
        )
        return 1

    print(f"own-space-witness OK -- {len(planes)} plane(s), {len(expected)} witness(es)")
    for name in sorted(expected):
        print(f"WITNESS {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
