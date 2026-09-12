#!/usr/bin/env python3
"""A facade feature must reach EVERY runtime that can carry it.

R2572 (§5.20 `switchboard`). `crates/wz` is a facade: its features forward to
the runtime crates with cargo's optional-dep syntax, `wz-runtime-tokio?/<f>`
and `wz-runtime-coop?/<f>`. That `?` is the hazard this gate exists for -- it
yields the EMPTY SET when the named dep is absent rather than erroring, so a
forward that names only one runtime is silently inert on the other profile.
The facade goes on advertising the capability and a consumer enabling it gets
NOTHING, with no diagnostic anywhere.

MEASURED, and it is why this file exists: `switchboard` read
`["wz-runtime-tokio?/switchboard"]` while wz-runtime-coop carried the
capability's whole MCU route, so `wz --features runtime-coop,switchboard`
activated nothing. That sat as the §5.20 atom's residual for many rounds. The
sibling forwards one screen up in the same manifest -- `codec-close`,
`codec-frame`, the keyexpr family -- all name BOTH arms, so the defect was a
line that had drifted out of a shape its own neighbours kept.

## The population is DERIVED, and that is the point

A hand-written list of "features that should be dual" would be the same class
of artefact as the line it is meant to police: it drifts, and nobody sees it
drift. So the rule reads cargo's own metadata instead:

    for each facade feature f that forwards to `<runtime>?/f`,
    every OTHER runtime crate that DECLARES a feature named f
    must also be forwarded by f.

"Declares a feature named f" is the derivation. A runtime that cannot carry a
capability simply does not declare the feature, and the rule does not reach it
-- no excuse list, no exemption clause to rot. A capability that is genuinely
AP-only stays a single forward and this gate stays silent about it, which is
the correct silence: the claim "MCU could carry this" belongs to the atom, not
to a manifest reader.

## Why `cargo metadata` and not a manifest parse

R2573 -- the first cut read the manifests with `tomllib`, which is stdlib only
from python 3.11 while the runner floor is 3.10, so Layer C0's python-floor
lint redded the push and took every step behind it (jobs "C0, C1cf" and
"A + B" BOTH died here, one cause wearing two job names). The lint's own
prescription is the better design anyway: cargo already knows what features a
package declares, and asking it removes a second reading of the manifest
format that could disagree with the first. The acquisition is separated from
the RULE below so the selftest drives the rule directly, with no fabricated
manifests on disk and nothing to keep in step with cargo's schema.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

FACADE = "wz"
#: The runtime crates the facade forwards into. Named rather than derived
#: because "is a runtime crate" is not a fact any manifest states -- but a
#: name that no longer matches a workspace member is caught below, so a rename
#: cannot leave this list quietly stale.
RUNTIMES = ("wz-runtime-tokio", "wz-runtime-coop")


def workspace_features(root: Path) -> dict[str, dict[str, list[str]]]:
    """package name -> its `[features]` table, from cargo's own metadata.

    `--no-deps` keeps this to the workspace members, which is the whole
    population the rule is about.
    """
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=str(root / "crates"),
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    meta = json.loads(out)
    return {p["name"]: dict(p.get("features") or {}) for p in meta.get("packages", [])}


def findings_from(feats: dict[str, dict[str, list[str]]]) -> tuple[list[str], int]:
    """(findings, population). Population is the number of forwards CHECKED.

    Pure: the rule takes the feature tables and nothing else, so the selftest
    can drive both verdicts without a tree.
    """
    facade = feats.get(FACADE, {})
    present = [r for r in RUNTIMES if r in feats]

    out: list[str] = []
    for missing_pkg in [r for r in RUNTIMES if r not in feats]:
        out.append(
            f"`{missing_pkg}` is named as a runtime crate but is not a workspace "
            "member, so this gate would silently stop checking its forwards."
        )

    population = 0
    for feat, body in sorted(facade.items()):
        forwarded_by = {r for r in present if f"{r}?/{feat}" in body}
        if not forwarded_by:
            continue
        carriers = {r for r in present if feat in feats[r]}
        population += len(carriers)
        for r in sorted(carriers - forwarded_by):
            out.append(
                f"`{FACADE}`'s `{feat}` does not forward to `{r}?/{feat}`, but "
                f"`{r}` declares that feature. The optional-dep `?` makes this "
                f"silently inert on that profile rather than an error: a "
                f"consumer enabling `{feat}` on the {r} profile activates "
                f"nothing and is told nothing."
            )
        for r in sorted(forwarded_by - carriers):
            out.append(
                f"`{FACADE}`'s `{feat}` forwards to `{r}?/{feat}`, but `{r}` "
                f"declares no such feature, so that arm can never activate."
            )
    return out, population


def selftest() -> int:
    """Drive both verdicts on synthetic feature tables, plus the vacuity arm."""
    cases: list[tuple[str, dict[str, dict[str, list[str]]], int]] = [
        (
            "both arms present -> clean",
            {
                "wz": {"f": ["wz-runtime-tokio?/f", "wz-runtime-coop?/f"]},
                "wz-runtime-tokio": {"f": []},
                "wz-runtime-coop": {"f": []},
            },
            0,
        ),
        (
            "coop declares it, facade forwards tokio only -> the R2572 shape",
            {
                "wz": {"f": ["wz-runtime-tokio?/f"]},
                "wz-runtime-tokio": {"f": []},
                "wz-runtime-coop": {"f": []},
            },
            1,
        ),
        (
            "tokio declares it, facade forwards coop only",
            {
                "wz": {"f": ["wz-runtime-coop?/f"]},
                "wz-runtime-tokio": {"f": []},
                "wz-runtime-coop": {"f": []},
            },
            1,
        ),
        (
            "genuinely AP-only (coop does not declare it) -> silent, by design",
            {
                "wz": {"f": ["wz-runtime-tokio?/f"]},
                "wz-runtime-tokio": {"f": []},
                "wz-runtime-coop": {"other": []},
            },
            0,
        ),
        (
            "forward naming a runtime that declares nothing -> dead arm",
            {
                "wz": {"f": ["wz-runtime-coop?/f"]},
                "wz-runtime-tokio": {"f": []},
                "wz-runtime-coop": {"other": []},
            },
            2,
        ),
        (
            "a facade feature that forwards nowhere is not this gate's subject",
            {
                "wz": {"f": ["dep:something"]},
                "wz-runtime-tokio": {"f": []},
                "wz-runtime-coop": {"f": []},
            },
            0,
        ),
        (
            "a RUNTIMES name that is not a member is a finding, not a skip",
            {
                "wz": {"f": ["wz-runtime-tokio?/f"]},
                "wz-runtime-tokio": {"f": []},
            },
            1,
        ),
    ]

    failed = 0
    for name, feats, want in cases:
        got, _pop = findings_from(feats)
        ok = len(got) == want
        print(f"  [{'ok' if ok else 'FAIL'}] {name}: {len(got)} finding(s), want {want}")
        if not ok:
            failed += 1
            for g in got:
                print(f"        {g}")

    # The vacuity arm: a population of zero must never read as a pass.
    _got, pop = findings_from(
        {
            "wz": {"f": ["dep:x"]},
            "wz-runtime-tokio": {"g": []},
            "wz-runtime-coop": {"h": []},
        }
    )
    ok = pop == 0
    print(f"  [{'ok' if ok else 'FAIL'}] a population of zero is detectable: pop={pop}")
    if not ok:
        failed += 1

    print(f"facade-forward selftest: {'OK' if not failed else f'{failed} FAILURE(S)'}")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()

    out, population = findings_from(workspace_features(REPO_ROOT))

    # A gate that cannot name its own population cannot be trusted when quiet:
    # a silent rc=0 makes "passed" and "never ran" indistinguishable. This tree
    # has paid for that shape more than once, so the count is always printed
    # and a population of zero is a FAILURE, not a pass.
    if population == 0:
        print(
            "  facade-forward FAIL: read ZERO runtime forwards out of "
            f"`{FACADE}`'s feature table. Either the facade stopped forwarding "
            "or this reader did -- both make a green run meaningless.",
            file=sys.stderr,
        )
        return 1

    if out:
        print(f"  facade-forward FAIL -- {len(out)} finding(s):")
        for f in out:
            print(f"    {f}")
        return 1

    print(
        f"  facade-forward: {population} runtime forward(s) checked across "
        f"{len(RUNTIMES)} runtime crate(s); every facade feature reaches every "
        "runtime that declares it"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
