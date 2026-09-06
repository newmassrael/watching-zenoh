#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
r"""R2380 (no register item) -- a LIVE atom reason that calls a run-ci lane
LOCAL-ONLY must agree with the workflow that runs it.

The citation is `no register item` in the sense `gate_provenance_lint` means it,
and for the same reason `multicast_stop_wiring_gate` gives: the item this
answers for -- unregistered open-debt item 15, the PARTIAL atom track -- lives
in an agent-memory register outside this repository, which has no store id to
resolve. The item is named here in prose instead.

## The defect this closes

"LOCAL-ONLY: lane C1v absent from ci.yml" was TRUE when `transport-link-ws`
wrote it. The lane was wired into the hosted workflow some rounds later, by a
round that had no reason to read a registry entry about websockets, and the
entry never heard. Measured at R2380: **27 such claims across ~14 atoms, and
NOT ONE of them was still true** -- every lane they named was a hosted job step.

That is not a documentation nit. A "LOCAL-ONLY lane" clause sits inside an
atom's RESIDUAL paragraph, which this workspace treats as a clause like any
other, so each false claim was holding its atom below its real grade. Four atoms
(`transport-link-tls`, `-ws`, `-quic`, `-quic-datagram`) carried it as their
ONLY surviving residual, and were PARTIAL for no other reason.

It is the debt-47 shape at its purest -- a registry reason outliving the code it
describes -- and the reason it needs a GATE rather than a sweep is that a sweep
fixes today's 27 and the next lane to be wired starts the count again. Nothing
in this tree could previously notice: the claim is prose in a JSON store, the
fact it asserts lives in a YAML workflow, and no reader crosses the two.

## The population is DERIVED from both sides, and an empty one FAILS

* The CLAIMS are every `LOCAL-ONLY` / `local-only` occurrence in a live
  inventory reason, with the lane tokens read out of the surrounding window.
  Nothing is listed here by name.
* The HOSTED SET is every `--layer <X>` the workflow actually invokes, read out
  of `.github/workflows/ci.yml`. So the day a lane is wired -- or unwired --
  this gate's verdict moves with it and no one has to remember.
* A claim naming NO lane is not graded: "local-only" said of something other
  than a lane is not this gate's subject, and guessing would manufacture
  findings.

An empty population FAILS, for the reason this tree has paid for repeatedly: a
gate whose subject has silently moved otherwise reports green forever. Note the
population is the CLAIMS, not the violations -- the fix drives violations to
zero while claims that are still TRUE keep the gate's subject alive.

## The budget, and why it is a count rather than a list

The violations are retired over several rounds, so the gate ships with a ratchet
rather than blocking every push until all 27 are gone. It is a COUNT that may
only DECREASE -- deliberately not a per-atom allowance table, because an
allowance table with a reason beside each row is an escape hatch that grows, and
a count cannot hide a NEW leak behind an old one: wire a lane hosted without
correcting its claim and the count rises, which is a FAIL.

A count BELOW the budget is also a FAIL, and that is the half that keeps the
ratchet honest: it means a round corrected a claim without lowering the number,
so the budget would otherwise sit there admitting violations that no longer
exist.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
STORE = pathlib.Path("docs/.atomic/workspace.atomic.json")
WORKFLOW = pathlib.Path(".github/workflows/ci.yml")

# R2380 -- the remaining FALSE claims, to be driven to zero. Lowered by the
# round that corrects an entry, in the same commit. See the module doc for why
# this is a count and not a table of names.
#
# R2381 RE-BASELINE, 24 -> 52, and it is recorded here rather than quietly
# edited because raising this number is exactly what the gate's own failure
# message forbids. The tree did NOT regress: the DETECTOR widened. R2380 keyed
# the claim to `LOCAL-ONLY`, the wording the four atoms it was written against
# happened to use, and graded everything else green. Widening it to the
# ASSERTION -- `absent from ci.yml`, `rides NO hosted lane`, `unhosted` -- found
# 28 more claims that were always false and always there, in atoms the gate had
# been reporting clean, `query-get` and `query-queryable` among them.
#
# One of those 28 was found by the widening and the other by reading the
# widened gate's OWN output: a fixed-offset window had been truncating
# `--layer C1al` to `C1a`, a lane no workflow runs, so the gate reported that
# claim TRUE and its true/false split was wrong. `claim_window` now cuts only
# at token boundaries. The lesson is the one this workspace already holds about
# grading your own gate -- the defect was visible only in the listing, never in
# the verdict.
#
# A ratchet cannot survive a detector change by pretending the count is
# comparable across it. The rule this establishes: a round that WIDENS the
# detector re-baselines in the same commit and says so; a round that does not
# touch the detector may only lower the number.
FALSE_LOCALITY_CLAIMS = 52

# A lane token as the reasons and the workflow both spell it: `Layer C1u`,
# `C1aj`, or a bare single-letter layer (`Z`, `M`, `F`) when introduced by the
# word Layer. The bare-letter form is deliberately NOT matched loose -- a lone
# `Z` in prose is not a lane reference.
LANE = re.compile(r"\bLayer\s+([A-Z][A-Za-z0-9]{0,4})\b|\b(C[0-9][a-z]{0,3})\b")
# R2381 -- the claim is the ASSERTION, not one phrasing of it.
#
# R2380 shipped this keyed to `LOCAL-ONLY`, which is the wording the four atoms
# it was written against happened to use. Testing the gate against wordings it
# had not anticipated found the same fossil spelled `absent from ci.yml`,
# `rides NO hosted lane` and `unhosted` in atoms it graded GREEN -- `query-get`
# and `query-queryable` among them, whose C1j / C4c / C4d / C4e are every one a
# hosted job step. A detector keyed to the examples its author saw reports green
# over the rest of the class, which is this workspace's own warning about
# grading your own gate.
#
# `not hosted` is deliberately NOT here: it occurs overwhelmingly inside
# CORRECTIONS ("C1j IS hosted, the claim that it was not hosted is false"), and
# a detector that reads a retraction as a claim would demand the retraction be
# retracted.
CLAIM = re.compile(
    r"LOCAL-ONLY|local-only|LOCAL ONLY"
    r"|absent from ci\.yml"
    r"|rides? NO hosted lane|no hosted lane"
    r"|\bunhosted\b"
)

# How far around the claim to look for the lane it is about. Wide enough for
# "LOCAL-ONLY: lane C1v absent from ci.yml" and for "the LOCAL-ONLY C1u lane",
# narrow enough that an unrelated lane named a sentence later is not swept in.
WINDOW_BEFORE = 60
WINDOW_AFTER = 140

PRESET_PREFIX = "preset-"
DEBT_PREFIX = "debt-"


def hosted_lanes(root: pathlib.Path) -> set[str]:
    """Every lane the hosted workflow actually invokes.

    Read from the `run:` lines rather than from job NAMES: a job name is prose
    that can say anything, while `--layer X` is what the runner executes.
    """
    text = (root / WORKFLOW).read_text(encoding="utf-8")
    return set(re.findall(r"--layer\s+([A-Za-z0-9]+)", text))


def live_reasons(root: pathlib.Path) -> dict[str, str]:
    """The LIVE impl-axis verdict per atom.

    Reached through `inventory_entries`, so the frozen changelog is out by
    construction: grading it would demand repairs to entries that must not
    change (`store_reason_citation_gate` makes the same split for the same
    reason).
    """
    data = json.loads((root / STORE).read_text(encoding="utf-8"))
    entries = data.get("inventory_entries")
    if not isinstance(entries, dict):
        raise SystemExit(f"{STORE} holds no `inventory_entries` mapping.")
    out = {}
    for eid, entry in entries.items():
        if eid.startswith(PRESET_PREFIX) or eid.startswith(DEBT_PREFIX):
            continue
        reason = (entry or {}).get("reason") or ""
        if reason.strip():
            out[eid] = reason
    return out


def claim_window(reason: str, at: int) -> str:
    """The text around a claim, cut only at TOKEN boundaries.

    R2381 -- a fixed-offset slice truncates whatever token it lands in, and a
    truncated lane is a DIFFERENT lane: cutting `--layer C1al` at the edge
    yielded `C1a`, which no workflow runs, so the gate reported a false claim
    as TRUE and its own true/false split was wrong. Measured on
    `transport-link-unixpipe`, whose C1al is a hosted job step.

    Extending outward to the nearest non-word character costs nothing and makes
    the window's content independent of where the offsets happen to fall.
    """
    lo = max(0, at - WINDOW_BEFORE)
    hi = min(len(reason), at + WINDOW_AFTER)
    while lo > 0 and (reason[lo - 1].isalnum() or reason[lo - 1] == "_"):
        lo -= 1
    while hi < len(reason) and (reason[hi].isalnum() or reason[hi] == "_"):
        hi += 1
    return reason[lo:hi]


def lanes_near(window: str) -> set[str]:
    return {a or b for a, b in LANE.findall(window)}


def audit(root: pathlib.Path):
    hosted = hosted_lanes(root)
    if not hosted:
        return [], [], hosted
    claims: list[tuple[str, str]] = []
    violations: list[tuple[str, str]] = []
    for atom, reason in sorted(live_reasons(root).items()):
        for m in CLAIM.finditer(reason):
            window = claim_window(reason, m.start())
            for lane in sorted(lanes_near(window)):
                claims.append((atom, lane))
                if lane in hosted:
                    violations.append((atom, lane))
    return claims, violations, hosted


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=str(ROOT))
    ap.add_argument("--list", action="store_true", help="print every graded claim")
    args = ap.parse_args()
    root = pathlib.Path(args.repo).resolve()

    claims, violations, hosted = audit(root)

    if args.list:
        for atom, lane in claims:
            mark = "HOSTED (false)" if lane in hosted else "not hosted (true)"
            print(f"  {atom}: claims {lane} local-only -- {mark}")

    if not hosted:
        print(
            "lane-locality: FAIL -- the workflow invokes NO lane, so the hosted "
            "set is empty and every claim would grade as true. The derivation "
            "has lost its subject; re-aim it.",
            file=sys.stderr,
        )
        return 1

    if not claims:
        print(
            "lane-locality: FAIL -- no live reason names a lane as local-only, "
            "so this gate is measuring nothing. Either the claims are gone (retire "
            "the gate and its budget together) or the reader stopped matching them; "
            "a population of zero must never read as a pass.",
            file=sys.stderr,
        )
        return 1

    n = len(violations)
    if n > FALSE_LOCALITY_CLAIMS:
        for atom, lane in violations:
            print(
                f"lane-locality: {atom} calls {lane} local-only, but ci.yml runs it",
                file=sys.stderr,
            )
        print(
            f"lane-locality: FAIL -- {n} false locality claim(s), budget "
            f"{FALSE_LOCALITY_CLAIMS}. A claim ROSE above the budget: either a "
            f"lane was wired hosted without its atom's reason being corrected, or "
            f"a new reason repeated the old fossil. Correct the reason; do not "
            f"raise the budget.",
            file=sys.stderr,
        )
        return 1

    if n < FALSE_LOCALITY_CLAIMS:
        print(
            f"lane-locality: FAIL -- {n} false locality claim(s) but the budget "
            f"still says {FALSE_LOCALITY_CLAIMS}. A round corrected a reason and "
            f"left the ratchet up, which would admit violations that no longer "
            f"exist. Lower FALSE_LOCALITY_CLAIMS to {n} in that same commit.",
            file=sys.stderr,
        )
        return 1

    print(
        f"lane-locality: OK -- {len(claims)} locality claim(s) graded against "
        f"{len(hosted)} hosted lane(s); {n} still false, at budget."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
