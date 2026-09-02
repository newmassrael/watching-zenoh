#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2282 (no register item) — A PER-ARM CEILING NO LANE RUNS IS A NUMBER NOBODY RE-MEASURES.

## The citation

This answers the numeric open-debt register's item 620, which lives in the
operator's notes rather than in the store, so `gate_provenance_lint`'s item
grammar cannot resolve it; `zenoh_c_archive_arm.py` set the precedent for
declaring the escape hatch on the first line and naming the item in the body.

## The defect

`zenoh_c_abi_symbol_census.rs::BASELINES` holds one committed ceiling PER zenoh-c
ABI ARM, and the test hard-FAILs on an arm it has no row for -- deliberately, so
a ceiling from a neighbouring arm can never be used as a guess. Four rows exist.
Only ONE of them was ever executed: the census runs in Layer C1cc alone, whose
oracle is `~/.local`, which is the published archive, which is `unstable-shm`.
The other three were measured BY HAND (R311y614, R2256, R2258) and nothing has
re-measured them since. That is open-debt item 47's shape -- a number that
outlives what it describes -- and the register's own filing of it was wrong in
the same way: it said TWO rows were unreached, because it reused
`zenoh_c_oracle_arms.py`'s "2 of 4 arms covered", which counts arms that have an
ORACLE PREFIX, not arms whose CEILING is executed. C1ce has an `unstable` oracle
and did not run the census.

## What this gate derives, and from where

  rows      the `("<arm>", <n>, "<version>", <reach>)` tuples of BASELINES. Their
            arm ids must equal `zenoh_c_archive_arm.ARMS` exactly -- an
            independent derivation of the same set, so a row this parser failed
            to see is a FAIL rather than a silently smaller population.

  reached   the lanes in `run-ci.sh` that invoke `--test
            zenoh_c_abi_symbol_census`, each mapped through its own
            `WZ_ZENOH_C*PREFIX:-` default to an arm by `zenoh_c_oracle_arms`.
            Structural on both ends: which lane runs the test, and which oracle
            that lane points at.

## The declaration, and why it is judged in BOTH directions

Two of the four arms have no lane and no reason to get one: `nounstable` and
`nounstable-shm` are neither what upstream publishes nor what `wz-capi-c`'s
default features model, and provisioning either costs a full zenoh dependency
graph build for a ceiling no consumer reads. So the honest state is a
DECLARATION, not coverage -- and a declaration nothing judges is an escape
hatch (R2194). Each row's fourth field is therefore either the LANE NAME that
executes it or `none -- <why>`, and this gate reds on both mistakes:

  * a row naming a lane that does not run the census, or whose oracle is a
    different arm -- the declaration claims coverage it does not have;
  * a row declaring `none` for an arm a census-running lane actually reaches --
    the declaration is stale in the direction that hides coverage, which is
    exactly what the `unstable` row became the moment R2281 re-aimed C1ce.

Anything that is neither shape is unclassified, and unclassified is RED.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts" / "lib"))

import zenoh_c_archive_arm as _archive  # noqa: E402
import zenoh_c_oracle_arms as _arms  # noqa: E402

ARMS = _archive.ARMS
CENSUS_RS = "crates/wz-integration-tests/tests/zenoh_c_abi_symbol_census.rs"
RUNCI = "scripts/run-ci.sh"
CENSUS_TEST = "--test zenoh_c_abi_symbol_census"

# The trailing comma is OPTIONAL and that is not cosmetic: a row long enough to
# carry a `none -- <why>` is one rustfmt breaks across lines, and the multi-line
# form it emits ends `...",\n    ),`. The first draft of this pattern required
# `"` then `)`, so the moment `cargo fmt` touched the file the gate saw TWO rows
# instead of four and failed on the arm-id set -- correctly, but for the wrong
# reason. `\s` already spans newlines, so nothing else had to change.
ROW_RE = re.compile(
    r'\(\s*"(?P<arm>[a-z-]+)"\s*,\s*(?P<n>\d+)\s*,\s*"(?P<ver>[0-9.]+)"\s*,'
    r'\s*"(?P<reach>[^"]*)"\s*,?\s*\)')
NONE_RE = re.compile(r"^none\s+--\s+\S")
LANE_FN_RE = re.compile(r"^(layer_[a-z0-9_]+)\(\) \{", re.M)
LANE_LABEL_RE = re.compile(r'_runci_guarded_test\s+"([A-Za-z0-9]+) ')


def joined(reach: str) -> str:
    """A reach field with Rust's line continuations resolved, as rustc sees it.

    A reason long enough to be worth reading is written `\\`-continued, and the
    raw source of one carries a backslash, a newline and the next line's indent.
    Reporting that verbatim makes a two-line FAIL message six, and matching
    `none -- <why>` against it would depend on where the author wrapped.
    """
    return re.sub(r"\s+", " ", re.sub(r"\\\s*\n\s*", " ", reach)).strip()


def rows(text: str) -> list[tuple[str, str]]:
    """`(arm, reach)` for every BASELINES row, in file order."""
    start = text.find("const BASELINES")
    if start < 0:
        return []
    end = text.find("\n];", start)
    return [(m.group("arm"), joined(m.group("reach")))
            for m in ROW_RE.finditer(text[start:end if end > 0 else len(text)])]


def census_lanes(runci: str, files: dict[str, str], published: str) -> dict[str, str]:
    """`lane label -> arm` for every run-ci lane that runs the census test."""
    fns = [(m.start(), m.group(1)) for m in LANE_FN_RE.finditer(runci)]
    installed = _arms.installer_arms(files, published)
    out: dict[str, str] = {}
    for hit in re.finditer(re.escape(CENSUS_TEST), runci):
        candidates = [(s, n) for s, n in fns if s < hit.start()]
        if not candidates:
            continue
        body_start, fn = max(candidates)
        body = runci[body_start:runci.find("\n}\n", body_start)]
        prefixes = {_arms.normalise(p)
                    for p in _arms.PREFIX_DEFAULT_RE.findall(body)}
        label = LANE_LABEL_RE.search(body)
        # The LABEL is what the lane calls itself in its own output and in
        # `run-ci.sh --layer <x>`; the function name is an implementation detail
        # that R2281 renamed without the lane changing identity.
        name = label.group(1) if label else fn
        for prefix in prefixes:
            arm = _arms.resolve(prefix, installed)
            if arm:
                out[name] = arm
    return out


def check(census_rs: str, runci: str, files: dict[str, str],
          published: str) -> tuple[bool, list[str]]:
    lines: list[str] = []
    ok = True

    declared = rows(census_rs)
    if not declared:
        return False, ["census-arm-reach FAIL: no BASELINES row was parsed. That "
                       "is the parser having stopped parsing, not the gate "
                       "having nothing to check."]
    if {a for a, _ in declared} != set(ARMS):
        return False, [
            "census-arm-reach FAIL: the BASELINES arm ids "
            f"{sorted({a for a, _ in declared})} are not the four this tree "
            f"knows, {sorted(ARMS)}. The census hard-FAILs on an arm with no "
            "row, so a missing one is a gate that cannot run, and an extra one "
            "is a row nothing can select."]

    reached = census_lanes(runci, files, published)
    if not reached:
        return False, ["census-arm-reach FAIL: no run-ci lane was found running "
                       f"`{CENSUS_TEST}`. The ceilings are then executed by "
                       "nothing at all, and this gate could not tell that from "
                       "a broken scan."]

    by_arm = {arm: lane for lane, arm in reached.items()}
    for arm, reach in declared:
        if NONE_RE.match(reach):
            if arm in by_arm:
                ok = False
                lines.append(
                    f"census-arm-reach FAIL: the `{arm}` row declares `{reach}` "
                    f"but lane {by_arm[arm]} runs the census against exactly "
                    f"that arm. The declaration is stale in the direction that "
                    f"hides coverage -- name the lane in the row instead.")
            else:
                lines.append(f"  census-arm-reach: {arm} -> no lane, declared "
                             f"({reach})")
        elif reach in reached:
            if reached[reach] != arm:
                ok = False
                lines.append(
                    f"census-arm-reach FAIL: the `{arm}` row names lane "
                    f"{reach}, which runs the census against `{reached[reach]}` "
                    f"instead. A ceiling measured on one arm says nothing about "
                    f"another -- that is why the test refuses a missing row.")
            else:
                lines.append(f"  census-arm-reach: {arm} -> {reach}")
        else:
            ok = False
            lines.append(
                f"census-arm-reach FAIL: the `{arm}` row's reach field is "
                f"`{reach}`, which is neither `none -- <why>` nor a lane that "
                f"runs the census (those are {sorted(reached)}). Unclassified "
                f"is not a pass.")

    lines.append(f"  census-arm-reach: {len(declared)} arm ceiling(s), "
                 f"{len(by_arm)} executed by a lane, "
                 f"{len(declared) - len(by_arm)} declared unreached")
    return ok, lines


# ─── selftest ───────────────────────────────────────────────────────────────
#
# Both verdicts, and the four wrong shapes are the ones this arrangement can
# actually take: a stale `none` (which is what R2281's re-aim created), a row
# pointing at a lane on another arm (a ceiling that measures nothing), an
# unclassified field, and a population that lost a row or a lane.

_INSTALLERS = {
    "scripts/install-zenoh-c.sh": 'PREFIX="${WZ_ZENOH_C_PREFIX:-$HOME/.local}"\n',
}


def _runci_fixture(lanes: list[tuple[str, str, bool]]) -> str:
    """A run-ci.sh fixture: (fn name, prefix expr, does it run the census?)."""
    out = []
    for fn, prefix, runs in lanes:
        out.append(f"{fn}() {{\n"
                   f'    local p="${{WZ_ZENOH_C_PREFIX:-{prefix}}}"\n'
                   f'    _runci_guarded_test "{fn[6:].upper()} leg" 1 \\\n'
                   + (f"        cargo test {CENSUS_TEST} -- --ignored\n"
                      if runs else "        cargo test --test other -- --ignored\n")
                   + "}\n")
    return "\n".join(out)


def _rs_fixture(rows_: list[tuple[str, str]]) -> str:
    """A BASELINES fixture, half of it in the shape `cargo fmt` emits.

    A row whose reason is long enough to be worth reading is one rustfmt breaks
    across lines, with a trailing comma the one-line form does not have. The
    first draft of `ROW_RE` could not read that shape, so every long-reasoned row
    vanished from the population the moment the file was formatted -- which is
    exactly the row this gate exists to adjudicate. Alternating the two spellings
    here means a reader that handles only one of them cannot pass.
    """
    out = []
    for i, (a, r) in enumerate(rows_):
        if i % 2:
            out.append(f'    (\n        "{a}",\n        0,\n        "1.10.0",\n'
                       f'        "{r}",\n    ),\n')
        else:
            out.append(f'    ("{a}", 0, "1.10.0", "{r}"),\n')
    return ("const BASELINES: &[(&str, usize, &str, &str)] = &[\n"
            + "".join(out) + "];\n")


_ALL = ["nounstable", "unstable", "nounstable-shm", "unstable-shm"]
_LANES_OK = [("layer_c1cc", "$HOME/.local", True),
             ("layer_c1ce", "$repo_root/target/zenoh-c-unstable", True)]
_NONE = "none -- no lane, and provisioning one buys a ceiling nobody reads"

_CASES = [
    ("every row classified, both shapes", True, _rs_fixture([
        ("nounstable", _NONE), ("unstable", "C1CE"),
        ("nounstable-shm", _NONE), ("unstable-shm", "C1CC")]), _LANES_OK),
    ("a `none` on an arm a lane reaches", False, _rs_fixture([
        ("nounstable", _NONE), ("unstable", _NONE),
        ("nounstable-shm", _NONE), ("unstable-shm", "C1CC")]), _LANES_OK),
    ("a row naming a lane on the wrong arm", False, _rs_fixture([
        ("nounstable", _NONE), ("unstable", "C1CC"),
        ("nounstable-shm", _NONE), ("unstable-shm", "C1CE")]), _LANES_OK),
    ("an unclassified reach field", False, _rs_fixture([
        ("nounstable", "later"), ("unstable", "C1CE"),
        ("nounstable-shm", _NONE), ("unstable-shm", "C1CC")]), _LANES_OK),
    ("a missing arm row", False, _rs_fixture([
        ("unstable", "C1CE"), ("unstable-shm", "C1CC")]), _LANES_OK),
    ("no lane runs the census", False,
     _rs_fixture([(a, _NONE) for a in _ALL]),
     [("layer_c1cc", "$HOME/.local", False)]),
]


def selftest() -> bool:
    ok = True
    for name, want, rs, lanes in _CASES:
        files = dict(_INSTALLERS)
        runci = _runci_fixture(lanes)
        files[RUNCI] = runci
        got, lines = check(rs, runci, files, "unstable-shm")
        if got != want:
            ok = False
            print(f"  census-arm-reach SELFTEST `{name}`: got {got}, expected "
                  f"{want}", file=sys.stderr)
            for ln in lines:
                print(f"      {ln}", file=sys.stderr)
    if ok:
        print(f"  census-arm-reach: selftest passed ({len(_CASES)} cases, both "
              f"verdicts)")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if not (args.check or args.selftest):
        ap.error("pass exactly one of --check / --selftest")

    if args.selftest and not selftest():
        return 1
    if args.check:
        files = _arms.scan_files()
        census_rs = (REPO_ROOT / CENSUS_RS).read_text()
        runci = (REPO_ROOT / RUNCI).read_text()
        ok, lines = check(census_rs, runci, files, _archive.ARCHIVE_ARM)
        for ln in lines:
            print(ln, file=None if ok else sys.stderr)
        if not ok:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
