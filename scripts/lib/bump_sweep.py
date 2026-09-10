#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2538 (no register item) — SWEEP a pin bump's re-measurement surface in ONE
run and report EVERY failure, instead of meeting them one red at a time.

The citation is `no register item` for the reason `upstream_release_distance.py`
gives for its own: the item this answers — unregistered open-debt item 717 —
lives in the operator's agent-memory register, which has no store `debt-` id for
`gate_provenance_lint` to resolve. Naming it in prose here and `no register
item` in the citation is the honest pair.

## The request, and the defect behind it

The owner, 2026-09-10: "when the version goes up, can you make something that
checks it all at once? Instead of doing this every time — run it once and just
look at what failed."

What that is asking for is not speed. Moving three zenoh pins to 1.10.1 was
CHEAP once each risk was measured (R2529 settled all three with one command
apiece). What was expensive was DISCOVERY ORDER: the re-measurement surface
surfaced one red per hosted run, and each fix opened the next. Three consecutive
runs on the same bump failed DIFFERENT subsets — 5 jobs, then 3, then 3 — and
R2534 walked the same staircase locally, watching Layer C0 climb 58 -> 74 -> 91
-> 142 of its 160 legs across four edit-and-rerun cycles.

## ⛔ THE SUBJECT IS THE LEG LOOP, NOT THE LAYER LOOP

Read `run-ci.sh` before assuming otherwise: it already ACCUMULATES between
layers ("R311y415 — accumulate rather than fail-fast", collecting
`FAILED_LAYERS`). What still stops early is WITHIN a layer, and the tree already
measures that honestly — the line a stopped layer prints about itself is
`reached 142 of 160 guarded leg(s); 18 did not run`.

So this does not re-run CI. It runs the checks that GRADE AGAINST A PIN, all of
them, accumulating, and reports the lot. A layer that dies at its first leg
hides the rest; this one cannot, because nothing here returns early.

## ⛔⛔ THE POPULATION IS DERIVED FROM THE LIVE PINS, NEVER FROM A VERSION LITERAL

Item 717 proposed `git grep -lF '1.10.0'` as the surface. That proxy is wrong in
two directions and both were measured before this was written:

  * it names the OLD pin, so it decays to prose the moment the bump lands. When
    R2538 re-ran it, every zenoh pin had already moved and that grep found no
    live constant at all — an instrument that goes blank exactly when the bump
    it was built for succeeds;
  * its numbers had already drifted from the item's own note (769 occurrences
    and 18 measured lines when filed; 979 and 22 when this round re-derived
    them), which is what a hand-held count does.

`upstream_release_distance` already derives the PINS themselves from structure —
submodule gitlinks and `git clone --branch "$VAR"` shapes — so the surface here
is "tracked files carrying a CURRENT pin literal", recomputed every run. Bump a
pin and the surface follows it with no edit here.

## What is graded, and what is only reported

The surface includes generated files, the append-only atomic store, and the pin
SSOTs themselves. None of those is a measurement anyone can re-take, so the
surface is REPORTED as context and the graded population is narrower and
structural: the executable gates in it, invoked in the modes their OWN argparse
declares, plus the static readings this module can perform over a surface file
that is not executable.

There is no exclusion table. A file is graded because it is runnable, not
because it survived a list — an exemption table is the escape hatch this tree
keeps paying for.

## ⚠ WHAT THIS DOES NOT REACH, stated rather than discovered

Offline and seconds, on purpose, so it can run in Layer C0 and by hand mid-bump.
That buys two absences:

  * anything needing the network. `upstream_release_distance`'s own table is
    graded by Layer U, which reads the releases API;
  * anything needing a built oracle or a cargo build. The zenoh-c symbol census
    is one of those — but its VERSION COLUMN is readable statically, and that is
    the half this catches: R2535 paid a hosted red whose whole content was a
    lane-reached BASELINES row still saying 1.10.0, which the probe below would
    have named in milliseconds.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

import upstream_release_distance as urd  # noqa: E402
import zenoh_c_archive_arm as zca  # noqa: E402
import zenoh_c_census_arm_reach as zcr  # noqa: E402

# The modes a gate is asked for, when its own argparse declares them. Not a
# per-gate table: the file says which it has and this reads that.
MODES = ("--selftest", "--check")

ARG_RE = re.compile(r'add_argument\(\s*"(--[a-z-]+)"')


@dataclasses.dataclass(frozen=True)
class Member:
    """One thing the sweep grades, and how.

    `text` / `pin` are the probe's INPUT OVERRIDE, and they exist for the
    control rather than for the product: without them a probe member reads the
    live tree, so the selftest could only drive `census_version_probe` directly
    — and a damage probe proved that is not the same thing. Collapsing the
    sweep's own `extend` to a single finding left every "two findings" arm
    green, because none of them went through `sweep`.
    """

    name: str
    kind: str  # "gate" | "probe"
    argv: tuple[str, ...] = ()
    text: str | None = None
    pin: str | None = None


def pins() -> dict[str, str]:
    """Every upstream ref this tree pins, derived by the sibling gate."""
    paths = urd.tracked_paths()
    return {**urd.submodule_pins(), **urd.script_pins(paths)}


def pin_literals(pinned: dict[str, str]) -> list[str]:
    """The distinct ref strings, longest first so a prefix cannot shadow one."""
    return sorted({v for v in pinned.values() if v}, key=len, reverse=True)


def surface(literals: list[str]) -> list[str]:
    """Tracked files carrying at least one current pin literal.

    `git grep -lF` per literal rather than one regex: a ref can contain regex
    metacharacters (`STABLE-2_2_1_RELEASE` does not, a tag with a `+` would) and
    a fixed-string search cannot be surprised by one.
    """
    found: set[str] = set()
    for lit in literals:
        got = subprocess.run(
            ["git", "grep", "-lF", lit],
            cwd=ROOT, capture_output=True, text=True,
        )
        # rc=1 is "no match", which is a result. Anything else is a broken call.
        if got.returncode not in (0, 1):
            raise RuntimeError(f"git grep failed for {lit!r}: {got.stderr[:200]}")
        found.update(line for line in got.stdout.splitlines() if line)
    return sorted(found)


def gate_modes(path: pathlib.Path) -> list[str]:
    """The subset of `MODES` this file's OWN argparse declares."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    declared = set(ARG_RE.findall(text))
    return [m for m in MODES if m in declared]


def members(files: list[str]) -> list[Member]:
    """The graded population, derived from the surface.

    A surface file becomes a member when it is an executable gate under
    `scripts/lib/`; the static probes are added unconditionally because their
    subject is a file the surface may not name (a census row can go stale
    without the file carrying the CURRENT pin — that is exactly the defect).
    """
    out: list[Member] = []
    for rel in files:
        if not (rel.startswith("scripts/lib/") and rel.endswith(".py")):
            continue
        if pathlib.Path(rel).name == pathlib.Path(__file__).name:
            continue  # this file, which the sweep must not sweep into itself
        for mode in gate_modes(ROOT / rel):
            out.append(Member(name=f"{rel} {mode}", kind="gate",
                              argv=(sys.executable, str(ROOT / rel), mode)))
    out.append(Member(name="census BASELINES version column", kind="probe"))
    return out


def run_gate(member: Member) -> tuple[bool, str]:
    """`(ok, detail)` — one gate, run to completion, never raising.

    ⚠ PYTHONPATH carries `scripts/lib`, and that is not decoration: these gates
    import each other, and a copy invoked without it dies in the import rather
    than grading anything. R2537 lost four damage probes to exactly that and
    read their exit status as if an arm had fired.
    """
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    lib = str(ROOT / "scripts" / "lib")
    env["PYTHONPATH"] = f"{lib}{os.pathsep}{existing}" if existing else lib
    got = subprocess.run(list(member.argv), cwd=ROOT, capture_output=True,
                         text=True, env=env)
    if got.returncode == 0:
        return (True, "")
    tail = (got.stderr.strip() or got.stdout.strip()).splitlines()
    return (False, tail[-1][:220] if tail else f"exit {got.returncode}")


def census_version_probe(census_rs: str | None = None,
                         pin: str | None = None) -> tuple[bool, list[str], int]:
    """`(ok, detail, graded)` — every LANE-REACHED baseline row is at the pin.

    The zenoh-c symbol census records, per ABI arm, the version its ceiling was
    measured against, and REFUSES to grade when the installed oracle is a
    different one. A row nothing reaches may legitimately lag — it says when it
    was measured, and no lane executes it. A row a LANE reaches may not: hosted
    CI provisions that lane's oracle at the pin, so the row reds there and only
    there.

    The row parser is IMPORTED from `zenoh_c_census_arm_reach`, which already
    owns it. A second copy here is the drift item 47 is made of.
    """
    text = (census_rs if census_rs is not None
            else (ROOT / "crates" / "wz-integration-tests" / "tests"
                  / "zenoh_c_abi_symbol_census.rs").read_text(
                      encoding="utf-8", errors="replace"))
    want = pin if pin is not None else zca.installer_pin()

    start = text.find("const BASELINES")
    if start < 0:
        return (False, ["no `const BASELINES` in the census source"], 0)
    end = text.find("\n];", start)
    body = text[start:end if end > 0 else len(text)]

    stale: list[str] = []
    graded = 0
    for m in zcr.ROW_RE.finditer(body):
        reach = zcr.joined(m.group("reach"))
        if zcr.NONE_RE.match(reach):
            continue  # declared unreached; its version is a record, not a claim
        graded += 1
        if m.group("ver") != want:
            stale.append(f"{m.group('arm')} row says {m.group('ver')}, "
                         f"lane {reach} runs at the pin {want}")
    if graded == 0:
        return (False, ["no BASELINES row names a lane, so this probe graded "
                        "nothing — a population of zero must not report clear"], 0)
    # A LIST, not a joined string, and that is the item's done-when (3): staling
    # two baselines must surface TWO findings, and a caller handed one sentence
    # cannot tell two from one.
    return (not stale, stale, graded)


def sweep(pop: list[Member]) -> list[str]:
    """Every finding, in member order. NEVER returns early.

    That sentence is the whole item: a loop that stops at its first failure is
    what made a bump take four rounds to surface four independent breakages.
    """
    findings: list[str] = []
    for member in pop:
        if member.kind == "probe":
            _ok, details, _graded = census_version_probe(member.text, member.pin)
            findings.extend(f"{member.name}: {d}" for d in details)
        else:
            ok, detail = run_gate(member)
            if not ok:
                findings.append(f"{member.name}: {detail}")
    return findings


def run(pop: list[Member] | None = None) -> int:
    pinned = pins()
    literals = pin_literals(pinned)
    files = surface(literals)
    population = members(files) if pop is None else pop

    print(f"bump-sweep: {len(pinned)} pinned upstream(s), "
          f"{len(literals)} distinct ref literal(s): {literals}")
    print(f"  surface: {len(files)} tracked file(s) carry a current pin literal")
    print(f"  graded:  {len(population)} member(s)")
    for member in population:
        print(f"    {member.kind:5s} {member.name}")

    if not population:
        print("bump-sweep: FAIL — the graded population is EMPTY. Every derived")
        print("    pin resolved to no runnable member, so this run examined")
        print("    nobody; a sweep of zero must never report all clear.")
        return 1

    findings = sweep(population)
    print(f"  ran {len(population)} member(s); {len(findings)} finding(s)")
    if findings:
        print("bump-sweep: FAIL — the pin moved and these have not been re-taken:")
        for line in findings:
            print(f"    {line}")
        print("    Every one of these is reported from a SINGLE run. Fix them")
        print("    together; meeting them one hosted red at a time is the cost")
        print("    open-debt item 717 was filed against.")
        return 1
    print("bump-sweep: OK — every member grades against the current pins.")
    return 0


# ── selftest ────────────────────────────────────────────────────────────────


def _exiting(tmp: pathlib.Path, label: str, code: int) -> Member:
    """A member that is a real subprocess with a known exit status.

    ⚠ THIS IS NOT A COPY OF A GATE, and the first draft's attempt to make it one
    is a finding worth keeping. Every gate here resolves its tree as
    `__file__.parents[2]`, so a copy placed anywhere else grades a repository
    that does not exist and dies in `FileNotFoundError` — non-zero, and for a
    reason with nothing to do with the pin it was supposed to have staled. Both
    "stale baseline" arms passed that way, on a path error. The NARROWING half
    (an undamaged copy must produce no finding) is what exposed it, and the
    obvious repair — copy under `<repo>/target/` instead — fails too, because
    `target` is a SYMLINK to a build cache on this machine and `resolve()`
    follows it straight back out of the tree.
    #
    So the two halves are driven by the subjects that can actually carry them:
    the STALE-BASELINE arms damage real `BASELINES` rows through
    `census_version_probe`, which takes its text as an argument and needs no
    copy at all; and the ACCUMULATION arm uses these, whose whole contract with
    the sweep is `argv -> exit status`, which is exactly what they exercise.
    """
    script = tmp / f"{label}.py"
    script.write_text(
        "import sys\n"
        f"print('fixture {label} speaking', file=sys.stderr)\n"
        f"sys.exit({code})\n",
        encoding="utf-8",
    )
    return Member(name=f"fixture::{label}", kind="gate",
                  argv=(sys.executable, str(script)))


def selftest() -> int:
    bad = 0

    def case(name: str, ok: bool) -> None:
        nonlocal bad
        if not ok:
            bad += 1
            print(f"  bump-sweep selftest FAIL: {name}", file=sys.stderr)

    # ── the POPULATION is derived and non-empty ──────────────────────────
    pinned = pins()
    literals = pin_literals(pinned)
    case("the tree pins at least one upstream", bool(pinned))
    case("every pin yields a literal", bool(literals))
    files = surface(literals)
    case("the surface is non-empty", bool(files))
    pop = members(files)
    case("the graded population is non-empty", bool(pop))
    case("the sweep never grades itself",
         not any("bump_sweep" in m.name for m in pop))
    case("a probe is in the population",
         any(m.kind == "probe" for m in pop))

    # An EMPTY population must FAIL rather than report clear. Driven through
    # `run` itself, because that is where the guard lives.
    case("an empty population FAILs", run(pop=[]) == 1)

    # ── THE TWO-ARMED CONTROL (item 717's done-when 3), ON REAL BASELINES ─
    #
    # "Stale one baseline and that line must appear; stale TWO and BOTH must."
    # An instrument reporting only the first does not pay this item, and that
    # is the sentence the item ends on.
    #
    # The subject is the LIVE census source with its real rows, damaged in
    # memory — no copy, so nothing here can pass on a path error.
    live_rs = (ROOT / "crates" / "wz-integration-tests" / "tests"
               / "zenoh_c_abi_symbol_census.rs").read_text(encoding="utf-8")
    live_pin = zca.installer_pin()
    ok, details, graded = census_version_probe(live_rs, live_pin)
    case("the shipped tree passes this probe", ok and not details)
    case("the shipped tree has MORE THAN ONE lane-reached row, so two can be "
         "staled at all", graded >= 2)

    # The damage is DERIVED from the live pin, never spelled: a fixture that
    # writes today's version stops mutating the moment the pin moves, which is
    # the defect R2534 found in a sibling gate's own selftest.
    impossible = "0.0.0"
    first_row = live_rs.replace(f'"{live_pin}", "C1ce"',
                                f'"{impossible}", "C1ce"', 1)
    case("the ONE-row mutation actually mutated", first_row != live_rs)
    ok, details, _ = census_version_probe(first_row, live_pin)
    case("staling ONE baseline surfaces exactly one finding",
         not ok and len(details) == 1)

    both_rows = first_row.replace(f'"{live_pin}", "C1cc"',
                                  f'"{impossible}", "C1cc"', 1)
    case("the TWO-row mutation actually mutated a second row",
         both_rows != first_row)
    ok, details, _ = census_version_probe(both_rows, live_pin)
    case("staling TWO baselines surfaces BOTH — the whole item",
         not ok and len(details) == 2)
    case("the second finding is not swallowed by the first",
         len({d.split(" row")[0] for d in details}) == 2)

    # ⛔ AND THE SAME CLAIM THROUGH `sweep` ITSELF, which is not the same test.
    # A damage probe that collapsed the sweep's own `extend` to a single line
    # left every arm above GREEN, because all of them call the probe function
    # directly. One member reporting TWO findings has to survive the sweep, and
    # this is where that is graded.
    through = sweep([Member(name="probe::two-staled", kind="probe",
                            text=both_rows, pin=live_pin)])
    case("two findings from ONE member survive the sweep", len(through) == 2)
    case("the sweep names the member on each of them",
         all(f.startswith("probe::two-staled: ") for f in through))
    case("a clean member through the sweep yields nothing",
         sweep([Member(name="probe::clean", kind="probe",
                       text=live_rs, pin=live_pin)]) == [])

    # ── ACCUMULATION ACROSS MEMBERS, which is the other half of "one run" ─
    #
    # The probe above proves one member can report two findings. This proves
    # the sweep does not stop at the first FAILING MEMBER — the leg-loop
    # behaviour item 717 is actually about.
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        bad_a = _exiting(tmp, "alpha", 1)
        bad_b = _exiting(tmp, "beta", 1)
        good = _exiting(tmp, "gamma", 0)
        got = sweep([bad_a, good, bad_b])
        case("a failing member does not stop the sweep", len(got) == 2)
        case("the member AFTER a failure is still run",
             any("beta" in f for f in got))
        case("a passing member contributes no finding",
             not any("gamma" in f for f in got))
        # The narrowing half: all-passing members must yield nothing, or the
        # accumulation arm would fire on everything and mean nothing.
        case("three passing members yield no finding",
             sweep([_exiting(tmp, "d1", 0), _exiting(tmp, "d2", 0)]) == [])
        # And the fixtures must genuinely RUN: a member that cannot start also
        # exits non-zero, which would make the arms above pass for the wrong
        # reason. The passing arm above is what rules that out.

    # ── the census probe, both verdicts, over fixtures ───────────────────
    # ⚠ The fixture versions are DELIBERATELY NOT the tree's pin. A fixture that
    # spells today's pin reads as a fact about this tree, and the next person to
    # grep for the pin finds a test constant; both sides here are the fixture's
    # own, so these never rot and this file stays out of its own surface.
    fx_pin, fx_old = "7.7.7", "7.7.6"
    reached = ('const BASELINES: &[(&str, usize, &str, &str)] = &[\n'
               f'    ("unstable", 0, "{fx_pin}", "C1ce"),\n'
               '    ("nounstable", 1, "0.1.0", "none -- no lane points an '
               'oracle at this arm"),\n'
               '];\n')
    ok, details, graded = census_version_probe(reached, fx_pin)
    case("a lane-reached row at the pin passes", ok and graded == 1)
    case("an unreached row's older version is not a finding",
         not any("nounstable" in d for d in details))

    stale_rs = reached.replace(f'"{fx_pin}", "C1ce"', f'"{fx_old}", "C1ce"')
    case("the stale mutation actually mutated", stale_rs != reached)
    ok, details, graded = census_version_probe(stale_rs, fx_pin)
    case("a lane-reached row behind the pin is a finding",
         not ok and any("unstable" in d for d in details) and graded == 1)

    none_reached = ('const BASELINES: &[(&str, usize, &str, &str)] = &[\n'
                    '    ("nounstable", 1, "0.1.0", "none -- nothing runs it"),\n'
                    '];\n')
    ok, details, graded = census_version_probe(none_reached, fx_pin)
    case("a table no lane reaches FAILs rather than reporting clear",
         not ok and graded == 0)

    ok, details, graded = census_version_probe("fn main() {}", fx_pin)
    case("a source with no BASELINES FAILs", not ok)

    if bad:
        print(f"bump-sweep selftest: FAIL ({bad})")
        return 1
    print("bump-sweep selftest: OK (population derivation, the empty-population "
          "guard, the two-armed stale control on REAL baseline rows, the same "
          "claim driven THROUGH the sweep, member accumulation with its "
          "narrowing half, and the census probe in both verdicts)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="sweep a pin bump's surface")
    ap.add_argument("--check", action="store_true",
                    help="run every member and report EVERY failure")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if not (args.check or args.selftest):
        ap.error("one of --check / --selftest is required")
    rc = 0
    if args.selftest:
        rc |= selftest()
    if args.check:
        rc |= run()
    return rc


if __name__ == "__main__":
    sys.exit(main())
