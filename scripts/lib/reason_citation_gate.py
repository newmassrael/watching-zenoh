#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2313 (no register item) - an inventory `reason` may not outlive the code it cites.

The citation is `no register item` for the reason `config_key_fixture_gate.py`
and `debt_plane_census.py` give for theirs: the item this closes --
unregistered open-debt item 47 -- lives in the operator's register file
outside this repository, not under the store's `debt-` prefix, so there is no
id here for `--emit` to resolve. The item is named in prose throughout.

## What item 47 said, and what measuring it found

Item 47 is the oldest unpaid entry in that register: "nobody measures that a
reason outlives the code it cites". It names THREE shapes and is explicit that
only the first is mechanizable:

  1. the citation points at a path or symbol that no longer exists;
  2. the citation resolves but the MECHANISM described is wrong -- its example
     is `hat/router/token.rs:127`, which existed and was a propagation path;
  3. the clause is true UPSTREAM but describes a state wz's structure cannot
     reach at all.

Shapes 2 and 3 are out of reach of any path checker, which the item says in so
many words, and it calls shape 1 "a lower bound, not a proof". This gate is
that lower bound, built and measured rather than sketched.

MEASURED when this gate was written: 999 citations across 144 of 312 inventory
rows. 382 resolve to exactly one tracked file and NONE of them points past that
file's end. 513 name a path this repository's history has never contained --
upstream zenoh and zenoh-pico, cited correctly. 0 name a path git once had and
no longer has. So shape 1 is CLEAN today, and item 47's fear of eight rounds of
accumulating rot is, for that shape, not what the tree actually holds.

A gate that finds nothing today is still worth its keep here, for the reason
the item itself gives: nobody was measuring, so nobody could have known. What
makes it non-vacuous is the POPULATION -- 999 citations, and zero of them is a
FAILURE, not a pass.

## The third rule, which is the one with something to catch

A citation nobody can resolve can never go red. `lib.rs:389` names 49 tracked
files; there is no reading of it that a checker can verify, and it will keep
looking like a fact forever. That is item 47's complaint wearing different
clothes, and 104 citations are in that state.

Fixing 104 store reasons is not this round's work and would be a worse use of
it than the ratchet: the count is BASELINED, and a push that raises it reds.
Above the baseline is a citation this change made unverifiable; below it, the
baseline moves down in the same commit. The baseline is DECLARED and the
population is DERIVED, which is the split R2301 settled.
"""

from __future__ import annotations

import collections
import json
import os
import re
import subprocess
import sys

# DECLARED, not derived: how many citations currently name a path that matches
# more than one tracked file. Lower it in the same commit that resolves one.
#
# `WZ_REASON_AMBIGUOUS_BASELINE` replaces the BASELINE and nothing else, so the
# selftest's one-row fixtures can drive the other three rules without the
# ratchet firing on a population of one. It cannot loosen a real run: the count
# it is compared against is still derived from the inventory.
AMBIGUOUS_BASELINE = 104


def ambiguous_baseline() -> int:
    override = os.environ.get("WZ_REASON_AMBIGUOUS_BASELINE")
    return int(override) if override else AMBIGUOUS_BASELINE

# A file:line citation. The extensions are the ones the corpus actually uses;
# widening the list widens the population, which is the safe direction.
CITE = re.compile(
    r"([A-Za-z0-9_./-]+\.(?:rs|py|sh|c|h|toml|json5|yaml|yml)):(\d+)(?:-(\d+))?"
)


def inventory() -> list[dict]:
    """The store's inventory rows, or a fixture when one is named."""
    fixture = os.environ.get("WZ_REASON_INVENTORY")
    if fixture:
        with open(fixture, encoding="utf-8") as fh:
            return json.load(fh)
    run = subprocess.run(
        ["mnemosyne-cli", "query", "--list-inventory", "--json"],
        capture_output=True,
        text=True,
    )
    if run.returncode != 0:
        raise SystemExit(
            f"reason-citation: FAIL - mnemosyne-cli exited {run.returncode}. A gate "
            f"that cannot read its input must not report green.\n{run.stderr[:400]}"
        )
    return json.loads(run.stdout)


def suffix_index(paths: list[str]) -> dict[str, set[str]]:
    """Every `/`-boundary suffix of every path, to the paths carrying it.

    Citations are written as SUFFIXES (`interceptor/access_control.rs`), never
    repo-relative, so resolving one means asking which tracked files end that
    way -- and how MANY, which is the whole of rule 3.
    """
    idx: dict[str, set[str]] = collections.defaultdict(set)
    for path in paths:
        if not path:
            continue
        parts = path.split("/")
        for i in range(len(parts)):
            idx["/".join(parts[i:])].add(path)
    return idx


def git_paths(args: list[str]) -> list[str]:
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, check=True
    ).stdout.split()


def audit() -> tuple[list[str], dict[str, int]]:
    rows = inventory()
    now = suffix_index(git_paths(["ls-files"]))
    # Every path this history has ever ADDED, DELETED or RENAMED. A citation
    # whose path is here but not in `now` is one wz used to carry and dropped;
    # a path in neither is upstream's, cited correctly.
    ever = suffix_index(
        git_paths(["log", "--all", "--pretty=format:", "--name-only", "--diff-filter=ADR"])
    )

    findings: list[str] = []
    counts = {"total": 0, "unique": 0, "ambiguous": 0, "foreign": 0}
    for row in rows:
        for m in CITE.finditer(row.get("reason") or ""):
            path, lo, hi = m.group(1), int(m.group(2)), m.group(3)
            counts["total"] += 1
            hits = now.get(path)
            if not hits:
                counts["foreign"] += 1
                if path in ever:
                    findings.append(
                        f"{row['id']}: `{path}:{lo}` names a path this repository "
                        f"HAD and no longer has. The reason has outlived the code "
                        f"it cites -- re-read what it claims and re-cite it, or "
                        f"drop the clause"
                    )
                continue
            if len(hits) > 1:
                counts["ambiguous"] += 1
                continue
            counts["unique"] += 1
            real = next(iter(hits))
            try:
                with open(real, "rb") as fh:
                    length = sum(1 for _ in fh)
            except OSError as exc:
                findings.append(f"{row['id']}: `{real}` is tracked but unreadable ({exc})")
                continue
            top = int(hi) if hi else lo
            if top > length:
                findings.append(
                    f"{row['id']}: `{path}:{top}` points past the end of {real}, "
                    f"which has {length} lines. The file survived and the line did "
                    f"not -- re-read it and re-cite"
                )
    return findings, counts


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    findings, counts = audit()

    if counts["total"] == 0:
        print(
            "reason-citation: FAIL - no inventory reason carries a file:line "
            "citation at all, so this gate lost its subject. A population of "
            "zero must not read as a pass.",
            file=sys.stderr,
        )
        return 1

    print(
        f"reason-citation: {counts['total']} citation(s) -- "
        f"{counts['unique']} resolve to one tracked file, "
        f"{counts['ambiguous']} ambiguous, {counts['foreign']} foreign to this tree"
    )

    baseline = ambiguous_baseline()
    if counts["ambiguous"] > baseline:
        findings.append(
            f"{counts['ambiguous']} citation(s) name a path matching more than one "
            f"tracked file, above the baseline of {baseline}. A citation nobody "
            f"can resolve can never go red, which is the defect this gate is for. "
            f"Write enough of the path to be unique -- do NOT raise the baseline"
        )
    elif counts["ambiguous"] < baseline:
        findings.append(
            f"{counts['ambiguous']} ambiguous citation(s), BELOW the baseline of "
            f"{baseline}. Lower AMBIGUOUS_BASELINE to {counts['ambiguous']} in "
            f"this same commit, or the ratchet stops holding the ground you just "
            f"took"
        )

    if findings:
        print("reason-citation: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("reason-citation: ok - every resolvable citation still points at code")
    return 0


# Each fixture is a shape the gate must tell apart. `want` is the substring the
# output has to carry; None means the arm must pass.
SELFTEST: tuple[tuple[str, list[dict], int, str | None], ...] = (
    # The cited file is a LONG-TRACKED sibling, deliberately not this gate:
    # `git ls-files` cannot see a file the round has not added yet, so a
    # fixture citing itself fails for a reason that has nothing to do with the
    # rule under test. That is how the first draft of these arms failed.
    (
        "a citation into a live file at a live line passes",
        [{"id": "ok", "reason": "see scripts/lib/debt_plane_census.py:1"}],
        0,
        None,
    ),
    (
        "a citation past the end of a live file fails",
        [{"id": "past", "reason": "see scripts/lib/debt_plane_census.py:999999"}],
        1,
        "points past the end of",
    ),
    (
        "a citation into a path this tree never had is FOREIGN, not a finding",
        [{"id": "up", "reason": "see net/routing/dispatcher/queries.rs:1464"}],
        0,
        None,
    ),
    # THE RULE WITH NOTHING REAL TO CATCH, walked anyway. Nought of the 999
    # live citations names a deleted path, so without this arm rule 2 would
    # never execute and could not be told from one that always passes.
    # `wz-ap-demo/src/link_driver.rs` is a real deletion in this history.
    (
        "a citation into a path wz DELETED is a finding",
        [{"id": "dead", "reason": "see wz-ap-demo/src/link_driver.rs:40"}],
        1,
        "no longer has",
    ),
    (
        "no citation anywhere is a FAILURE, not a pass",
        [{"id": "bare", "reason": "no citation here at all"}],
        1,
        "lost its subject",
    ),
    (
        "an ambiguous suffix is counted, never resolved",
        [{"id": "amb", "reason": "see lib.rs:1 and lib.rs:2"}],
        1,
        "above the baseline of 1",
    ),
    (
        "the ratchet reds when the count FALLS below its baseline",
        [{"id": "one", "reason": "see lib.rs:1"}],
        1,
        "BELOW the baseline",
    ),
)

# Each arm declares the ambiguity baseline it is judged against, so the ratchet
# is exercised in BOTH directions instead of being switched off for the others.
SELFTEST_BASELINE = {
    "an ambiguous suffix is counted, never resolved": "1",
    "the ratchet reds when the count FALLS below its baseline": "2",
}


def selftest() -> int:
    import tempfile

    failures = 0
    for label, rows, want_rc, want_text in SELFTEST:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(rows, fh)
            fixture = fh.name
        env = dict(os.environ)
        env["WZ_REASON_INVENTORY"] = fixture
        env["WZ_REASON_AMBIGUOUS_BASELINE"] = SELFTEST_BASELINE.get(label, "0")
        run = subprocess.run(
            [sys.executable, __file__], capture_output=True, text=True, env=env
        )
        got = run.stdout + run.stderr
        ok = run.returncode == want_rc and (want_text is None or want_text in got)
        if ok:
            print(f"  ok    {label}  (rc={run.returncode})")
        else:
            failures += 1
            print(f"  FAIL  {label}")
            print(f"        want rc={want_rc} and {want_text!r}; got rc={run.returncode}")
            for line in got.splitlines():
                print(f"        | {line}")
        os.unlink(fixture)
    print(f"reason-citation selftest: {len(SELFTEST) - failures}/{len(SELFTEST)} arm(s) pass")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
