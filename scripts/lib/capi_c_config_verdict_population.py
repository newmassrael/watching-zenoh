#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2300 (no register item) — EVERY CONFIG-DEFECT VARIANT IS REACHED THROUGH
THE C DOORS, with the population DERIVED from the enums that define them.

Answers the done-when the consumer wrote for item 631 of the unregistered
register, which lives OUTSIDE this repository -- the reason the citation above
reads "no register item", the position `capi_c_config_surface.py` records for
548 and `analysis_surface_config_free.py` for 564. Their words, and they name
the failure exactly: *"if you only feed inputs with no defects, the `Vec` is
always empty and it passes"*. A test asserting "some defects came back" would
survive one working rule and eight broken ones.

## What is derived, and from where

  VARIANTS  the members of `ConfigDefect` and `TopologyDefect`, read from the
            ONE tracked file that defines each. Not a list here: a list here
            would be a second copy of the enum and would go stale in the
            direction that reports green -- a variant added upstream and
            forgotten would simply not be asked about.

  REACHED   the variant names the C-door tests assert on, read out of the
            `wz-capi-c` test sources. These are what the doors were actually
            driven to produce.

The check is a plain difference with NOTHING TO EXCUSE, and that is a property
R2300 had to BUILD rather than discover. Three `TopologyDefect` variants are
raised only from the external-listener loop, which the closed topology door
passes empty -- so with only that door they would have been unreachable and
this gate would have needed a table saying "those three are out of scope". A
reason table survives being wrong (R2194). The door was widened instead
(`wz_capi_c_config_validate_topology_with_external`) until the exemption was
unnecessary. If a future variant is genuinely unreachable, widen the surface or
delete the variant; do not add a list here.

## Why REACHED is read from the tests rather than from a run

A run would be stronger and is also already happening: the tests themselves
assert reachability, and they FAIL if a door stops producing what a case says
it must. What no test can see is a variant NO CASE MENTIONS -- that is an
absence, and an absence is exactly what a test suite cannot notice. This gate
is aimed at that absence and at nothing else, which is why it reads source and
does not run anything.

## Both populations must be non-empty

Zero variants means the enum reader broke; zero reached means the test reader
did. Either reports a perfect empty-set agreement, which is the shape this file
exists to make impossible.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

# The enums whose members are the population, and the crate whose tests must
# reach them. Both are PATHS TO SEARCH, not paths to a file: the file that
# defines an enum may move, and a gate aimed at a moved file matches nothing.
ENUMS = ("ConfigDefect", "TopologyDefect")
ENUM_SEARCH = "crates/wz-runtime-tokio/src"
TEST_SEARCH = "crates/wz-capi-c"


class Fatal(Exception):
    """A derivation that cannot be made. Never a silent pass."""


def tracked(pathspec: str) -> list[pathlib.Path]:
    """Tracked `.rs` files under `pathspec`."""
    out = subprocess.run(
        ["git", "ls-files", "-z", pathspec],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [ROOT / p for p in out.split("\0") if p.endswith(".rs")]


def variants_of(enum: str) -> tuple[set[str], pathlib.Path]:
    """The members of `enum`, from the one tracked file that defines it.

    More than one definition would be the second copy this repository refuses;
    zero means the enum moved and this derivation is aimed at nothing.
    """
    pattern = re.compile(rf"pub enum {enum}\s*\{{(.*?)\n\}}\n", re.S)
    found: list[tuple[pathlib.Path, str]] = []
    for path in tracked(ENUM_SEARCH):
        m = pattern.search(path.read_text(errors="replace"))
        if m is not None:
            found.append((path, m.group(1)))
    if len(found) != 1:
        raise Fatal(
            f"expected exactly ONE tracked definition of `{enum}`, found "
            f"{len(found)}. Zero means it moved and this gate is aimed at "
            "nothing; more than one is a second copy of the population."
        )
    path, body = found[0]
    # Comments stripped first: every variant here carries a doc comment, and a
    # variant NAMED in one would otherwise enter the population twice or, worse,
    # a name mentioned in prose would enter it without existing.
    body = re.sub(r"///[^\n]*", "", body)
    body = re.sub(r"//[^\n]*", "", body)
    names = set(re.findall(r"^\s{4}([A-Z][A-Za-z0-9]*)\s*[\{\(,]", body, re.M))
    if not names:
        raise Fatal(
            f"`{enum}` is defined in {path.relative_to(ROOT)} but no variant "
            "parsed out of its body. A population read from nothing is not a "
            "population."
        )
    return names, path


def reached() -> set[str]:
    """Variant names the C-door tests assert on.

    Read as STRING LITERALS, because that is how a test names the variant it
    demands: the door emits `<Name>: <message>` and the case says which name it
    wants. A literal is therefore the evidence that a case exists for it.
    """
    names: set[str] = set()
    for path in tracked(TEST_SEARCH):
        text = path.read_text(errors="replace")
        if "config_verdict" not in str(path) and "config_verdict" not in text:
            continue
        for literal in re.findall(r'"([A-Z][A-Za-z0-9]*)"', text):
            names.add(literal)
    return names


def run() -> int:
    findings: list[str] = []
    total = 0
    reached_names = reached()
    if not reached_names:
        findings.append(
            "no variant name found in any `wz-capi-c` test source. The test "
            "reader has stopped working, so its agreement with the enums means "
            "nothing."
        )

    for enum in ENUMS:
        names, path = variants_of(enum)
        total += len(names)
        missing = sorted(names - reached_names)
        for name in missing:
            findings.append(
                f"{enum}::{name} ({path.relative_to(ROOT)}) is reached by no "
                "C-door test. A caller can be handed this verdict and nothing "
                "here has ever seen the door produce it. Add a case that drives "
                "it, or -- if it is genuinely unreachable through the C surface "
                "-- WIDEN THE SURFACE until it is, the way R2300 added the "
                "external-listener door rather than an exemption."
            )

    if total == 0:
        findings.append("no variant parsed from any enum, so there is no population")

    if findings:
        print("capi-c-config-verdict-population: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        return 1

    print(
        f"capi-c-config-verdict-population: OK -- {total} defect variant(s) "
        f"across {len(ENUMS)} enum(s), each reached by a C-door test"
    )
    return 0


def selftest() -> int:
    """Drive the reader against bodies the real enums cannot produce."""
    # A doc comment NAMING another variant must not enter the population, and a
    # variant must be found through every declaration shape.
    body = """
pub enum Probe {
    /// Mentions OnlyInProse and must not add it.
    WithFields {
        thing: String,
    },
    Tuple(String),
    Unit,
}
"""
    body = re.sub(r"///[^\n]*", "", re.search(r"pub enum Probe\s*\{(.*?)\n\}\n", body, re.S).group(1))
    names = set(re.findall(r"^\s{4}([A-Z][A-Za-z0-9]*)\s*[\{\(,]", body, re.M))
    if names != {"WithFields", "Tuple", "Unit"}:
        print(f"selftest: variant parse gave {names!r}", file=sys.stderr)
        return 1

    # And the real thing must resolve: an enum that cannot be located is the
    # failure this gate is most likely to acquire silently.
    for enum in ENUMS:
        found, path = variants_of(enum)
        if not found:
            print(f"selftest: {enum} resolved to no variants", file=sys.stderr)
            return 1
        print(f"  selftest: {enum} -> {len(found)} variant(s) in {path.relative_to(ROOT)}")

    print("capi-c-config-verdict-population: selftest OK")
    return 0


if __name__ == "__main__":
    try:
        if "--selftest" in sys.argv[1:]:
            sys.exit(selftest())
        sys.exit(run())
    except Fatal as e:
        print(f"capi-c-config-verdict-population: FAIL -- {e}", file=sys.stderr)
        sys.exit(1)
