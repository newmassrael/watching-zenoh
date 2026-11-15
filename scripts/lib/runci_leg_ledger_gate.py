#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4490 (no register item) -- a run-ci lane declares its legs and what each
leans on, so that one red no longer hides the rest of its lane.

The item this answers, open-debt item 938, lives in the agent-memory half of the
register, which has no store id for `gate_provenance_lint.py` to resolve; this
sentence and `no register item` in the citation are the honest pair.

## The defect, measured

`run_layer` judges a lane by its function's exit code, and a lane function
guards each step with `|| return 1`, so a lane stops at its first red and says
nothing about the steps after it. Each hidden step costs a hosted run once the
first is repaired:

  * hosted run 42505060630: Layer C1bo stopped at its C consumer's compile, and
    `capi_bound_names.py`, which reads only the header, was seen refusing two
    doors only on the run after that compile was repaired;
  * Layer C0 has stopped at one of its legs while the leg at position 91
    (`depth_axis_census.py`) went unread for thirty rounds, and a provenance
    citation the lint could not parse masked 97 more (`framing_refusal_...`).

Stopping is often right, because a later step reads an earlier step's build.
What was missing is the DECLARATION of which step leans on which.

## The mechanism this holds (in `scripts/run-ci.sh`)

    _runci_legs_open <lane> || return 1
    _runci_leg <leg> [--after <leg>[,<leg>...]] -- <command> [<arg>...]
    _runci_legs_close

The ledger runs the legs in the order written, skips a leg whose dependency did
not pass (and names it `skipped: depends on <dep>`), runs every other leg, and
fails the lane once at the close with every failed and skipped leg named.
`run_layer` refuses a lane that returned with its ledger open, or returned 0
after the ledger closed red. This gate holds the same rules on the text, where a
reader can see them before a run does.

## What it holds

For every lane of the dispatch table (`run_layer <id> <fn> || overall=1`) whose
body opens a ledger:

  OPEN      exactly one `_runci_legs_open <id> || return 1`, naming the lane's own
            id (the id `run_layer` reads the verdict under)
  CLOSE     the body's last command is a bare `_runci_legs_close`
  LEG       every `_runci_leg` sits after the open and reads
            `_runci_leg <name> [--after <dep>[,<dep>...]] -- <command>`, the name in
            [a-z0-9][a-z0-9._-]*, declared once, every dependency an EARLIER leg
  SELFTEST  a leg that runs `python3 scripts/lib/<m>.py` and is not `<m>.selftest`
            leans on `<m>.selftest`, directly or through other legs, whenever the
            lane declares that leg before it: a gate that fails its own fixtures
            grades nothing
  NO-STOP   no `python3 scripts/lib/<m>.py ... || return 1`; inside a ledger a gate
            is a leg, and a gate never needs to stop its lane

For every other lane:

  STRAY     no `_runci_leg` (it would run with no ledger to record it)
  CENSUS    a lane whose stop-at-first legs run static gates of two or more
            DISTINCT modules is a lane whose independent legs hide each other. It
            fails unless it is in BASELINE, and BASELINE is held both ways: a lane
            there that no longer matches (moved to the ledger, or down to one
            gate) fails until it is taken out, so the list can only shrink.

And the runtime half: the ledger's three entry points are defined in the script,
and `run_layer` settles the ledger after each lane.

## What the census does not see

It counts static gate lines because their independence is a fact of the text:
each reads the tree. Two `cargo test` legs are usually independent too, but a
cargo leg may read a binary an earlier leg built, and the text does not say
which; a census of them would be a guess. Those lanes move to the ledger when
someone who reads them declares their dependencies, not when this gate guesses.

## The population is derived, and zero is a failure

The lanes come from the dispatch table and their bodies from the same span
`_runci_lane_span` uses (from `<fn>() {` to the first `}` in column 0). A
dispatch table with no lane, or a tree with no ledger lane, fails: either the
reader drifted from the script or the mechanism left it.

Modes (one required):
    --check      grade scripts/run-ci.sh
    --selftest   every rule driven through a fixture that breaks it, and a clean
                 control
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUN_CI = ROOT / "scripts" / "run-ci.sh"

DISPATCH = re.compile(r"^run_layer ([A-Za-z0-9]+) (layer_[a-z0-9_]+) \|\| overall=1$", re.M)
LEG_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
GATE_CMD = re.compile(r"^\s*python3\s+scripts/lib/([A-Za-z0-9_]+)\.py\b")
STOP_GUARD = re.compile(r"\|\|\s*return\s+1\b")
OPEN = re.compile(r"^\s*_runci_legs_open\b")
LEG = re.compile(r"^\s*_runci_leg\s")
CLOSE_BARE = "_runci_legs_close"
SCRIPT_GATE = re.compile(r"^scripts/lib/([A-Za-z0-9_]+)\.py$")

#: Lanes whose independent gates still stop at the first red, each with what it
#: takes to move it. Shrinks only: the census fails a lane here that stopped
#: matching. Measured on 2026-11-14 over the whole dispatch table.
BASELINE: dict[str, str] = {
    "C1cc": (
        "960 lines over the zenoh-c oracle arms; its four gates read what the "
        "oracle build and the per-arm loops produce, and the loops' own "
        "dependencies are what has to be declared first"
    ),
    "C1st": (
        "its packaging legs are already rc-chained (`[ \"$rc\" -eq 0 ] &&`); the "
        "host, node, profile and raw-link chains are independent of each other "
        "and each leans on the builds and the two selftests"
    ),
    "Z": (
        "2300 lines over the zenohd interop legs; the two gates sit among 94 cargo "
        "legs whose dependencies on the zenohd builds are not written down yet"
    ),
}


def lanes(text: str) -> dict[str, str]:
    """{function: lane id} from the dispatch table, in the script's own words."""
    return {m.group(2): m.group(1) for m in DISPATCH.finditer(text)}


def body_of(lines: list[str], fn: str) -> list[tuple[int, str]] | None:
    """The physical lines strictly inside `fn`'s body, numbered from 1."""
    opener = re.compile(r"^" + re.escape(fn) + r"\(\)\s*\{\s*$")
    start = None
    for i, line in enumerate(lines, 1):
        if start is None:
            if opener.match(line):
                start = i
            continue
        if re.match(r"^\}\s*$", line):
            return [(n, lines[n - 1]) for n in range(start + 1, i)]
    return None


def logical(body: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Continuations joined, comment lines dropped, blank lines dropped."""
    out: list[tuple[int, str]] = []
    buf: str | None = None
    at = 0
    for n, line in body:
        if buf is None and line.lstrip().startswith("#"):
            continue
        if buf is None:
            at = n
            buf = line
        else:
            buf = buf + " " + line.strip()
        if buf.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1]
            continue
        if buf.strip():
            out.append((at, buf))
        buf = None
    if buf is not None and buf.strip():
        out.append((at, buf))
    return out


def parse_leg(line: str) -> tuple[str, list[str], list[str], str]:
    """(name, deps, command words, problem) for one `_runci_leg` line."""
    words = line.split()
    if len(words) < 2:
        return "", [], [], "names no leg"
    name = words[1]
    i = 2
    deps: list[str] = []
    if i < len(words) and words[i] == "--after":
        if i + 1 >= len(words) or words[i + 1] == "--":
            return name, [], [], "`--after` names no leg"
        deps = [d for d in words[i + 1].split(",")]
        i += 2
    if i >= len(words) or words[i] != "--":
        return name, deps, [], "has no `--` before its command"
    cmd = words[i + 1:]
    if not cmd:
        return name, deps, [], "names no command"
    return name, deps, cmd, ""


def gate_module(cmd: list[str]) -> str | None:
    if len(cmd) >= 2 and cmd[0] == "python3":
        m = SCRIPT_GATE.match(cmd[1])
        if m:
            return m.group(1)
    return None


def stop_gate_modules(code: list[tuple[int, str]]) -> list[tuple[int, str]]:
    found = []
    for n, line in code:
        m = GATE_CMD.match(line)
        if m and STOP_GUARD.search(line):
            found.append((n, m.group(1)))
    return found


def check_ledger(lane: str, code: list[tuple[int, str]]) -> tuple[list[str], int]:
    """Findings for one ledger lane, and its leg count."""
    out: list[str] = []
    opens = [(n, l) for n, l in code if OPEN.match(l)]
    if len(opens) != 1:
        out.append(
            f"Layer {lane}: {len(opens)} `_runci_legs_open` lines; a lane opens its "
            "ledger once"
        )
    open_at = opens[0][0] if opens else 0
    for n, l in opens[:1]:
        words = l.split()
        if len(words) < 2 or words[1] != lane:
            got = words[1] if len(words) > 1 else "nothing"
            out.append(
                f"Layer {lane} (line {n}): the ledger is opened for `{got}`; "
                f"`run_layer` reads the verdict under `{lane}`"
            )
        if not re.search(r"\|\|\s*return\s+1\s*$", l):
            out.append(
                f"Layer {lane} (line {n}): `_runci_legs_open` without `|| return 1`; "
                "a refused open would leave the legs writing into another ledger"
            )
    if not code or code[-1][1].strip() != CLOSE_BARE:
        last = code[-1][1].strip() if code else "nothing"
        out.append(
            f"Layer {lane}: its last command is `{last[:60]}`, not `{CLOSE_BARE}`; "
            "the lane returns what the close returns"
        )
    declared: list[str] = []
    deps_of: dict[str, list[str]] = {}
    for n, l in code:
        if not LEG.match(l):
            continue
        name, deps, cmd, problem = parse_leg(l)
        where = f"Layer {lane} (line {n}) leg `{name}`"
        if n < open_at or not opens:
            out.append(f"{where}: runs before the ledger is open")
        if problem:
            out.append(f"{where}: {problem}")
            declared.append(name)
            continue
        if not LEG_NAME.match(name):
            out.append(f"{where}: the name is not [a-z0-9][a-z0-9._-]*")
        if name in declared:
            out.append(f"{where}: the name is declared twice")
        for d in deps:
            if d not in declared:
                out.append(
                    f"{where}: depends on `{d}`, which is not a leg declared before it"
                )
        module = gate_module(cmd)
        selftest = f"{module}.selftest" if module else None
        if selftest and name != selftest and selftest in declared:
            if not _reaches(deps, selftest, deps_of):
                out.append(
                    f"{where}: runs `{module}.py` and does not lean on `{selftest}`, "
                    "declared above it; a gate that fails its own fixtures grades "
                    "nothing"
                )
        declared.append(name)
        deps_of[name] = deps
    for n, module in stop_gate_modules(code):
        out.append(
            f"Layer {lane} (line {n}): `{module}.py ... || return 1` inside a ledger "
            "lane; make it a leg"
        )
    if not declared:
        out.append(f"Layer {lane}: opens a ledger and declares no leg")
    return out, len(declared)


def _reaches(deps: list[str], target: str, deps_of: dict[str, list[str]]) -> bool:
    seen: set[str] = set()
    stack = list(deps)
    while stack:
        d = stack.pop()
        if d == target:
            return True
        if d in seen:
            continue
        seen.add(d)
        stack.extend(deps_of.get(d, []))
    return False


def grade(text: str, baseline: dict[str, str]) -> tuple[list[str], str]:
    """(findings, summary) for one run-ci.sh text."""
    findings: list[str] = []
    table = lanes(text)
    if not table:
        return (["the dispatch table has no `run_layer <id> <fn> || overall=1` line; "
                 "this gate has no population"], "")
    lines = text.split("\n")
    for fn in ("_runci_legs_open", "_runci_leg", "_runci_legs_close", "_runci_legs_settle"):
        if not re.search(r"^" + re.escape(fn) + r"\(\)\s*\{", text, re.M):
            findings.append(f"`{fn}()` is not defined in the script")
    run_layer = body_of(lines, "run_layer")
    settles = run_layer is not None and sum(
        1 for _, l in run_layer if re.search(r'_runci_legs_settle\s+"\$name"', l)
    )
    if not settles or settles < 2:
        findings.append(
            "`run_layer` does not settle the leg ledger on both of its paths; a lane "
            "that returned with its ledger open, or returned 0 over a red one, "
            "would pass"
        )
    ledger_lanes = 0
    legs = 0
    positive: dict[str, list[str]] = {}
    ids = set(table.values())
    for fn, lane in sorted(table.items(), key=lambda kv: kv[1]):
        body = body_of(lines, fn)
        if body is None:
            findings.append(f"Layer {lane}: `{fn}` is dispatched and not defined")
            continue
        code = logical(body)
        if any(OPEN.match(l) for _, l in code):
            ledger_lanes += 1
            got, count = check_ledger(lane, code)
            findings.extend(got)
            legs += count
            continue
        for n, l in code:
            if LEG.match(l):
                findings.append(
                    f"Layer {lane} (line {n}): `_runci_leg` in a lane with no ledger; "
                    "nothing records its verdict"
                )
        mods = sorted({m for _, m in stop_gate_modules(code)})
        if len(mods) >= 2:
            positive[lane] = mods
    if ledger_lanes == 0:
        findings.append(
            "no dispatched lane opens a leg ledger; either the reader drifted from "
            "the script or the mechanism left it"
        )
    for lane, mods in sorted(positive.items()):
        if lane not in baseline:
            findings.append(
                f"Layer {lane}: its stop-at-first legs run {len(mods)} independent "
                f"gates ({', '.join(mods)}), so the first red hides the rest; put "
                "the lane on the leg ledger"
            )
    for lane in sorted(baseline):
        if lane not in ids:
            findings.append(f"BASELINE names `{lane}`, which the dispatch table does not")
        elif lane not in positive:
            findings.append(
                f"BASELINE names `{lane}`, which no longer stops between independent "
                "gates; take it out of the list"
            )
    summary = (
        f"{len(table)} lane(s), {ledger_lanes} on the leg ledger with {legs} leg(s), "
        f"{len(positive)} stopping between independent gates "
        f"({len(set(positive) & set(baseline))} in BASELINE)"
    )
    return findings, summary


def check() -> int:
    try:
        text = RUN_CI.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"  runci-leg-ledger: FAIL -- cannot read {RUN_CI}: {exc}", file=sys.stderr)
        return 1
    findings, summary = grade(text, BASELINE)
    for f in findings:
        print(f"  runci-leg-ledger: FAIL -- {f}", file=sys.stderr)
    if findings:
        return 1
    print(f"  runci-leg-ledger: OK ({summary})")
    return 0


# ─── selftest ─────────────────────────────────────────────────────────────────

_RUNTIME = (
    "_runci_legs_open() {\n    :\n}\n"
    "_runci_leg() {\n    :\n}\n"
    "_runci_legs_close() {\n    :\n}\n"
    "_runci_legs_settle() {\n    :\n}\n"
    "run_layer() {\n"
    "    if \"$@\"; then\n"
    "        _runci_legs_settle \"$name\" 0 || return 1\n"
    "    else\n"
    "        _runci_legs_settle \"$name\" \"$rc\" || true\n"
    "    fi\n"
    "}\n"
)

_LEDGER = (
    "layer_a() {\n"
    "    command -v python3 >/dev/null 2>&1 || return 1\n"
    "    _runci_legs_open A || return 1\n"
    "    # a comment between legs\n"
    "    _runci_leg one.selftest -- python3 scripts/lib/one.py --selftest\n"
    "    _runci_leg one --after one.selftest -- python3 scripts/lib/one.py --check\n"
    "    _runci_leg build -- _a_build\n"
    "    _runci_leg one.measure --after one.selftest,build -- \\\n"
    "        python3 scripts/lib/one.py measure\n"
    "    _runci_leg one.settle --after one.measure -- python3 scripts/lib/one.py settle\n"
    "    _runci_leg two -- python3 scripts/lib/two.py >/dev/null\n"
    "    _runci_legs_close\n"
    "}\n"
)

_STOPPER = (
    "layer_b() {\n"
    "    python3 scripts/lib/three.py --selftest || return 1\n"
    "    python3 scripts/lib/three.py || return 1\n"
    "    return 0\n"
    "}\n"
)

_DISPATCH = (
    "run_layer A layer_a || overall=1\n"
    "run_layer B layer_b || overall=1\n"
)


def _tree(ledger: str = _LEDGER, stopper: str = _STOPPER, dispatch: str = _DISPATCH,
          runtime: str = _RUNTIME) -> str:
    return runtime + ledger + stopper + dispatch


def selftest() -> int:
    bad = 0
    ran = 0

    def expect(label: str, text: str, needle: str | None,
               baseline: dict[str, str] | None = None) -> None:
        nonlocal bad, ran
        ran += 1
        findings, _ = grade(text, {} if baseline is None else baseline)
        if needle is None:
            ok = not findings
        else:
            ok = any(needle in f for f in findings)
        print(f"  {'ok ' if ok else 'BAD'}  {label}")
        if not ok:
            print(f"        want {'no finding' if needle is None else repr(needle)}; got {findings}")
            bad += 1

    clean = _tree()
    expect("a clean ledger lane and a one-gate stopper pass", clean, None)
    # The transitive SELFTEST arm is part of the clean control: `one.settle`
    # reaches `one.selftest` only through `one.measure`.

    expect("the open names another lane",
           clean.replace("_runci_legs_open A ||", "_runci_legs_open B ||"),
           "the ledger is opened for `B`")
    expect("the open is not guarded",
           clean.replace("_runci_legs_open A || return 1", "_runci_legs_open A"),
           "without `|| return 1`")
    expect("the ledger is opened twice",
           clean.replace("    _runci_legs_close\n}\n",
                         "    _runci_legs_open A || return 1\n    _runci_legs_close\n}\n", 1),
           "2 `_runci_legs_open` lines")
    expect("the lane does not end on the close",
           clean.replace("    _runci_legs_close\n}\n", "    _runci_legs_close\n    return 0\n}\n", 1),
           "not `_runci_legs_close`")
    expect("a leg before the open",
           clean.replace("    _runci_legs_open A || return 1\n",
                         "    _runci_leg early -- true\n    _runci_legs_open A || return 1\n"),
           "runs before the ledger is open")
    expect("a leg name outside the alphabet",
           clean.replace("_runci_leg build --", "_runci_leg Build --"),
           "the name is not")
    expect("a leg name declared twice",
           clean.replace("_runci_leg two --", "_runci_leg build --"),
           "declared twice")
    expect("a dependency that is not declared",
           clean.replace("--after one.measure --", "--after one.measured --"),
           "depends on `one.measured`")
    expect("a dependency declared after its dependent",
           clean.replace("_runci_leg build -- _a_build\n", "")
                .replace("    _runci_legs_close\n", "    _runci_leg build -- _a_build\n    _runci_legs_close\n"),
           "depends on `build`")
    expect("no `--` before the command",
           clean.replace("_runci_leg build -- _a_build", "_runci_leg build _a_build"),
           "has no `--`")
    expect("no command",
           clean.replace("_runci_leg build -- _a_build", "_runci_leg build --"),
           "names no command")
    expect("a grade that does not lean on its own selftest",
           clean.replace("--after one.selftest -- python3 scripts/lib/one.py --check",
                         "-- python3 scripts/lib/one.py --check"),
           "does not lean on `one.selftest`")
    expect("a stop-at-first gate inside a ledger lane",
           clean.replace("    _runci_legs_close\n",
                         "    python3 scripts/lib/four.py || return 1\n    _runci_legs_close\n", 1),
           "`four.py ... || return 1` inside a ledger lane")
    expect("a leg in a lane with no ledger",
           clean.replace("    return 0\n}\n", "    _runci_leg x -- true\n    return 0\n}\n", 1),
           "in a lane with no ledger")
    two_gates = clean.replace("python3 scripts/lib/three.py || return 1",
                              "python3 scripts/lib/five.py || return 1")
    expect("two independent gates that stop at the first red", two_gates,
           "run 2 independent gates")
    expect("the same lane, carried in BASELINE", two_gates, None, {"B": "why"})
    expect("a BASELINE lane that stopped matching", clean,
           "no longer stops between independent", {"B": "why"})
    expect("a BASELINE lane that is not dispatched", clean,
           "which the dispatch table does not", {"Q": "why"})
    expect("a ledger with no leg",
           _tree(ledger="layer_a() {\n    _runci_legs_open A || return 1\n    _runci_legs_close\n}\n"),
           "declares no leg")
    expect("run_layer that does not settle the ledger",
           clean.replace('_runci_legs_settle "$name" 0 || return 1', "true"),
           "does not settle the leg ledger")
    expect("the ledger's entry point missing",
           clean.replace("_runci_leg() {\n    :\n}\n", ""),
           "`_runci_leg()` is not defined")
    expect("a dispatched lane that is not defined",
           clean + "run_layer C layer_c || overall=1\n",
           "`layer_c` is dispatched and not defined")
    expect("an empty dispatch table (population zero)",
           _tree(dispatch=""), "has no population")
    expect("no ledger lane at all (population zero)",
           _tree(ledger="layer_a() {\n    true\n}\n"), "no dispatched lane opens")

    print(f"runci-leg-ledger selftest: {ran - bad}/{ran} arm(s) behaved as claimed")
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    if argv == ["--check"]:
        return check()
    if argv == ["--selftest"]:
        return selftest()
    print("usage: runci_leg_ledger_gate.py --check | --selftest", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
