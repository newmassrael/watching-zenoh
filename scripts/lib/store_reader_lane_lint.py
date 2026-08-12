#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y751 (N54) — the STORE-READER LANE gate.

## The class

Four gates in this tree read the atomic store through `mnemosyne-cli`. Hosted CI
runs most lanes on a job that deliberately does NOT install that tool -- the
install is ~88s and was split out in R311y428 -- so a gate that grows a store
read silently acquires a dependency the job it runs on cannot satisfy.

R311y743 did exactly that to `gate_provenance_lint.py` and it reddened every
hosted run from that commit until R311y747 armed the two halves separately. The
local runs stayed green throughout, because a dev box has the tool on PATH: this
is the failure mode where "verified here" and "runs there" come apart, and no
local sweep can see it.

R311y747 armed all four. What it could not do is stop the FIFTH: nothing
enumerates which gates read the store, so the next one to grow a store read
inherits nothing. That is carry N54, and this is it.

## What it asserts

Store readers are found by CONTENT, not from a list -- a script that reads the
store is one that names `mnemosyne-cli`, the sidecar path, or the shared
`inventory_kinds` predicate. For each, the lane that runs it is resolved through
`run-ci.sh`, and then:

  1. that lane must appear in `.github/workflows/ci.yml` inside a job that
     actually RUNS `install-mnemosyne-cli.sh`; and
  2. its step there must set a `WZ_*_REQUIRE` env, because a lane that SKIPs
     where the job provisions its input is a provisioning regression wearing a
     green badge (the rule `WZ_A3_REQUIRE` / `WZ_A5_REQUIRE` already follow).

## Edges are INVOCATIONS, not mentions

The lane map is built from lines that actually run a script (`bash x.sh`,
`python3 x.py`, `source x.sh`) with comment lines excluded. Matching bare script
NAMES instead was tried first and is unusable: these files cite each other in
prose constantly, and the resulting graph made every lane reach every gate --
`domain_census.py` came out as belonging to ten lanes, which is a map that
cannot be wrong about anything. With invocation edges the four gates resolve to
A5, A3, A4 and C0, which is what they are.

## Two legitimate ways to read the store outside a lane

Both are mechanical, neither is an exemption list:

  * a MODULE another script imports (`inventory_kinds.py`) -- the importer
    carries the lane, and this gate checks the importer;
  * a GIT HOOK gate (`schema-pin-gate.sh`) -- run by `.githooks/`, which is not
    the lane space at all.

A store reader that is neither, and that no lane invokes, is a finding: a gate
nothing runs cannot fail, and this workspace has shipped one before.

Exit 0 with the map when clean; exit 1 listing every finding otherwise.
"""

from __future__ import annotations

import pathlib
import re
import sys

# What makes a script a store reader. `inventory_kinds` is included because it is
# the shared predicate every store-reading gate goes through since R311y743 --
# naming it IS reading the store, one level up.
#
# MEASURED, and the first version was wrong in an instructive way: a bare
# substring search over the whole file matched this gate's OWN prose and its own
# marker list, and reported it as an unwired store reader. Two tightenings
# followed, both independently right -- the module docstring and comment lines
# are stripped before matching (a gate that talks about the store does not read
# it), and `mnemosyne-cli` does not count inside `install-mnemosyne-cli`, where
# the relation is the opposite one.
STORE_MARKERS = ("mnemosyne-cli", "workspace.atomic.json", "inventory_kinds")

# And this file is skipped, because a scanner that names its own vocabulary
# matches itself for a reason that has nothing to do with what it scans for. The
# cost is stated rather than hidden: if this gate ever genuinely grows a store
# read, it is the one gate that will not notice.
SELF = pathlib.Path(__file__).name

# `mnemosyne-cli` inside these is the installer naming what it installs.
NOT_A_READ = ("install-mnemosyne-cli", "verify-mnemosyne")

# The drivers. `run-ci.sh` names every gate by construction, so expanding it
# would connect everything to everything; `round-runner.sh` drives whole
# sessions. Neither is a gate.
DRIVERS = frozenset({"run-ci.sh", "round-runner.sh"})

# An installer names the tool because it INSTALLS it, which is the opposite
# relation from reading the store with it.
INSTALLER_PREFIXES = ("install-mnemosyne", "verify-mnemosyne")

# A line that RUNS another script, with comments excluded. See the docstring for
# what matching bare names instead produced.
INVOCATION = re.compile(
    r"(?m)^(?!\s*#).*\b(?:bash|sh|python3|source|\.)\s+\S*?"
    r"([A-Za-z0-9_.-]+\.(?:sh|py))\b"
)
RUN_LAYER = re.compile(r"(?m)^run_layer ([A-Za-z0-9]+) ([a-zA-Z0-9_]+)")
SHELL_FN_OPEN = re.compile(r"^([a-zA-Z0-9_]+)\(\)\s*\{")
# A YAML env KEY, not the token anywhere in the step. MEASURED: the first
# version matched the bare token, and disarming Layer A5 by deleting its `env:`
# block did not red -- the same step's comment EXPLAINS why `WZ_A5_REQUIRE` is
# set there, so the gate read the explanation as the setting. A step that only
# talks about being armed is exactly the step this is looking for.
REQUIRE_ENV = re.compile(r"(?m)^\s*(WZ_[A-Z0-9]+_REQUIRE):\s")
# A ci.yml job header: exactly two spaces of indent under `jobs:`.
CI_JOB = re.compile(r"(?m)^  (?=[a-zA-Z0-9_-]+:\s*$)")


def scripts_by_name(root: pathlib.Path) -> dict[str, pathlib.Path]:
    out: dict[str, pathlib.Path] = {}
    for pattern in ("scripts/*.sh", "scripts/*.py", "scripts/lib/*"):
        for p in sorted(root.glob(pattern)):
            if p.is_file():
                out[p.name] = p
    return out


def shell_functions(text: str) -> dict[str, str]:
    fns: dict[str, str] = {}
    name: str | None = None
    body: list[str] = []
    for line in text.splitlines():
        opened = SHELL_FN_OPEN.match(line)
        if opened:
            name, body = opened.group(1), []
            continue
        if name is None:
            continue
        if line.startswith("}"):
            fns[name] = "\n".join(body)
            name = None
        else:
            body.append(line)
    return fns


def code_only(text: str) -> str:
    """The file with its module docstring and comment lines removed.

    Deliberately crude — a real parse would be per-language and this rule only
    has to separate "talks about the store" from "reads it". Both halves of the
    crudeness are safe in this direction: a marker inside an inline string still
    counts (that is how `mnemosyne-cli` is actually invoked), and a marker only
    ever discussed in prose does not.
    """
    lines = text.splitlines()
    out: list[str] = []
    fence: str | None = None
    for line in lines:
        stripped = line.strip()
        if fence is None:
            if stripped.startswith(('"""', "'''")):
                quote = stripped[:3]
                rest = stripped[3:]
                if rest.endswith(quote) and len(rest) >= 3:
                    continue  # a one-line docstring
                fence = quote
                continue
            if stripped.startswith("#"):
                continue
            out.append(line)
        elif stripped.endswith(fence):
            fence = None
    return "\n".join(out)


def reads_the_store(text: str) -> bool:
    body = code_only(text)
    for marker in STORE_MARKERS:
        if marker != "mnemosyne-cli":
            if marker in body:
                return True
            continue
        for line in body.splitlines():
            if marker not in line:
                continue
            if any(compound in line for compound in NOT_A_READ):
                continue
            return True
    return False


def invoked(text: str, known: dict[str, pathlib.Path]) -> set[str]:
    return {n for n in INVOCATION.findall(text) if n in known}


def reachable(text: str, known: dict[str, pathlib.Path]) -> set[str]:
    """Every script this text runs, transitively, through invocation edges."""
    seen: set[str] = set()
    frontier = invoked(text, known)
    while frontier:
        name = frontier.pop()
        if name in seen or name in DRIVERS:
            continue
        seen.add(name)
        frontier |= invoked(known[name].read_text(), known)
    return seen


def main() -> int:
    root = pathlib.Path(".")
    runci = root / "scripts" / "run-ci.sh"
    ciyml = root / ".github" / "workflows" / "ci.yml"
    hooks = root / ".githooks"
    for path in (runci, ciyml):
        if not path.is_file():
            # A gate that cannot read its input must not report green.
            print(
                f"store-reader lane gate FAIL: {path} not found (wrong cwd?)",
                file=sys.stderr,
            )
            return 1

    known = scripts_by_name(root)
    run_text = runci.read_text()
    fns = shell_functions(run_text)
    lanes = dict(
        (lane, fn) for lane, fn in RUN_LAYER.findall(run_text) if fn in fns
    )
    if not lanes:
        print(
            "store-reader lane gate FAIL: no `run_layer` lines resolved to a "
            "function; the run-ci.sh patterns have drifted and this check "
            "asserted nothing",
            file=sys.stderr,
        )
        return 1

    readers = [
        name
        for name, path in sorted(known.items())
        if name not in DRIVERS
        and name != SELF
        and not name.startswith(INSTALLER_PREFIXES)
        and reads_the_store(path.read_text())
    ]
    if not readers:
        print(
            "store-reader lane gate FAIL: no store-reading script matched. "
            "Either the markers have drifted or the population is empty, and "
            "both are broken rather than clean.",
            file=sys.stderr,
        )
        return 1

    lane_reach = {lane: reachable(fns[fn], known) for lane, fn in lanes.items()}

    ci_text = ciyml.read_text()
    jobs = {}
    for block in CI_JOB.split(ci_text)[1:]:
        jobs[block.split(":", 1)[0]] = block
    provisioning = {
        name: block
        for name, block in jobs.items()
        # A `run:` of the installer, not a comment ABOUT it -- job `ci` mentions
        # the installer in a comment about rust-toolchain.toml and provisions
        # nothing.
        if re.search(r"(?m)^\s*run:.*install-mnemosyne-cli\.sh", block)
    }
    if not provisioning:
        print(
            "store-reader lane gate FAIL: no ci.yml job runs "
            "install-mnemosyne-cli.sh. Nothing could satisfy a store read, so "
            "this is a provisioning regression rather than a clean tree.",
            file=sys.stderr,
        )
        return 1

    hook_text = ""
    if hooks.is_dir():
        for hook in sorted(hooks.iterdir()):
            if hook.is_file():
                hook_text += hook.read_text()
    importers = {
        name: path.read_text()
        for name, path in known.items()
        if name.endswith(".py")
    }

    findings: list[str] = []
    mapped: list[tuple[str, str]] = []
    off_lane: list[str] = []

    for reader in readers:
        owning = sorted(lane for lane, reached in lane_reach.items() if reader in reached)
        if not owning:
            stem = reader[:-3] if reader.endswith(".py") else reader
            imported = any(
                re.search(rf"\bimport {re.escape(stem)}\b", text)
                for other, text in importers.items()
                if other != reader
            )
            hooked = reader in hook_text
            if imported or hooked:
                why = "imported as a module" if imported else "run by a git hook"
                off_lane.append(f"{reader} ({why})")
                continue
            findings.append(
                f"{reader}: reads the store and NO run-ci lane invokes it, and "
                f"it is neither imported as a module nor run by a git hook. A "
                f"gate nothing runs cannot fail"
            )
            continue
        for lane in owning:
            mapped.append((reader, lane))
            hosted = [
                name
                for name, block in provisioning.items()
                if re.search(rf"--layer {re.escape(lane)}\b", block)
            ]
            if not hosted:
                findings.append(
                    f"{reader}: runs in lane {lane}, which no ci.yml job that "
                    f"installs mnemosyne-cli runs. Hosted CI would reach its "
                    f"store read with no store reader provisioned -- the "
                    f"R311y743 shape"
                )
                continue
            armed = False
            for name in hosted:
                for step in re.split(r"(?m)^      - name:", provisioning[name]):
                    if re.search(rf"--layer {re.escape(lane)}\b", step) and REQUIRE_ENV.search(step):
                        armed = True
            if not armed:
                findings.append(
                    f"{reader}: lane {lane} runs on provisioning job(s) "
                    f"{', '.join(hosted)} but that step sets no WZ_*_REQUIRE. A "
                    f"lane that SKIPs where its input IS provisioned is a "
                    f"provisioning regression wearing a green badge"
                )

    if findings:
        print("Layer C0 FAIL: store-reading gate(s) not provisioned:", file=sys.stderr)
        for f in sorted(findings):
            print(f"    - {f}", file=sys.stderr)
        return 1

    print(
        f"  store-reader lane gate: {len(readers)} store-reading script(s), "
        f"{len(mapped)} lane binding(s), all provisioned and armed"
    )
    for reader, lane in sorted(mapped):
        print(f"    {reader} -> lane {lane}")
    for entry in sorted(off_lane):
        print(f"    {entry} -- off the lane space by construction")
    return 0


if __name__ == "__main__":
    sys.exit(main())
