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
drift. So the rule reads the manifests instead:

    for each facade feature f that forwards to `<runtime>?/f`,
    every OTHER runtime crate that DECLARES a feature named f
    must also be forwarded by f.

"Declares a feature named f" is the derivation. A runtime that cannot carry a
capability simply does not declare the feature, and the rule does not reach it
-- no excuse list, no exemption clause to rot. A capability that is genuinely
AP-only stays a single forward and this gate stays silent about it, which is
the correct silence: the claim "MCU could carry this" belongs to the atom, not
to a manifest reader.

## What this gate does NOT claim

It does not say which capabilities OUGHT to be MCU-capable -- that is a spec
judgement and it lives in the atom catalog. Before R2572 wz-runtime-coop did
not declare `switchboard` at all, so this rule would have been silent on the
original hole. It binds the invariant going FORWARD: once a runtime declares
the feature, the facade must reach it, and removing either half reds.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

FACADE = "wz"
#: The runtime crates the facade forwards into. Named rather than derived
#: because "is a runtime crate" is not a fact any manifest states -- but the
#: list is checked against the tree below, so a rename cannot leave it stale.
RUNTIMES = ("wz-runtime-tokio", "wz-runtime-coop")


def features_of(pkg: str, root: Path) -> dict[str, list[str]]:
    """The `[features]` table of `crates/<pkg>/Cargo.toml`."""
    manifest = root / "crates" / pkg / "Cargo.toml"
    if not manifest.is_file():
        raise FileNotFoundError(manifest)
    with manifest.open("rb") as fh:
        data = tomllib.load(fh)
    return {k: list(v) for k, v in (data.get("features") or {}).items()}


def findings(root: Path) -> tuple[list[str], int]:
    """(findings, population). Population is the number of forwards CHECKED."""
    facade = features_of(FACADE, root)
    runtime_features = {r: features_of(r, root) for r in RUNTIMES}

    out: list[str] = []
    population = 0
    for feat, body in sorted(facade.items()):
        forwarded_by = {r for r in RUNTIMES if f"{r}?/{feat}" in body}
        if not forwarded_by:
            continue
        # Every runtime that DECLARES this feature must be forwarded.
        carriers = {r for r in RUNTIMES if feat in runtime_features[r]}
        population += len(carriers)
        missing = sorted(carriers - forwarded_by)
        for r in missing:
            out.append(
                f"`{FACADE}`'s `{feat}` does not forward to `{r}?/{feat}`, but "
                f"`{r}` declares that feature. The optional-dep `?` makes this "
                f"silently inert on that profile rather than an error: a "
                f"consumer enabling `{feat}` on the {r} profile activates "
                f"nothing and is told nothing."
            )
        # A forward naming a runtime that does NOT declare the feature is dead
        # text -- it can never activate, so it misreports the facade's reach.
        for r in sorted(forwarded_by - carriers):
            out.append(
                f"`{FACADE}`'s `{feat}` forwards to `{r}?/{feat}`, but `{r}` "
                f"declares no such feature, so that arm can never activate."
            )
    return out, population


def selftest() -> int:
    """Drive both verdicts on synthetic manifests, including the vacuity arm."""
    import tempfile

    def build(tmp: Path, facade: str, tokio: str, coop: str) -> None:
        for pkg, body in (
            (FACADE, facade),
            ("wz-runtime-tokio", tokio),
            ("wz-runtime-coop", coop),
        ):
            d = tmp / "crates" / pkg
            d.mkdir(parents=True, exist_ok=True)
            (d / "Cargo.toml").write_text(
                f'[package]\nname = "{pkg}"\n\n[features]\n{body}\n'
            )

    cases: list[tuple[str, str, str, str, int]] = [
        # name, facade, tokio, coop, expected finding count
        (
            "both arms present -> clean",
            'f = ["wz-runtime-tokio?/f", "wz-runtime-coop?/f"]',
            "f = []",
            "f = []",
            0,
        ),
        (
            "coop declares it, facade forwards tokio only -> the R2572 shape",
            'f = ["wz-runtime-tokio?/f"]',
            "f = []",
            "f = []",
            1,
        ),
        (
            "tokio declares it, facade forwards coop only",
            'f = ["wz-runtime-coop?/f"]',
            "f = []",
            "f = []",
            1,
        ),
        (
            "genuinely AP-only (coop does not declare it) -> silent, by design",
            'f = ["wz-runtime-tokio?/f"]',
            "f = []",
            "other = []",
            0,
        ),
        (
            "forward naming a runtime that declares nothing -> dead arm",
            'f = ["wz-runtime-coop?/f"]',
            "f = []",
            "other = []",
            2,
        ),
        (
            "a facade feature that forwards nowhere is not this gate's subject",
            'f = ["dep:something"]',
            "f = []",
            "f = []",
            0,
        ),
    ]

    failed = 0
    for name, facade, tokio, coop, want in cases:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            build(tmp, facade, tokio, coop)
            got, _pop = findings(tmp)
            ok = len(got) == want
            print(f"  [{'ok' if ok else 'FAIL'}] {name}: {len(got)} finding(s), want {want}")
            if not ok:
                failed += 1
                for g in got:
                    print(f"        {g}")

    # The vacuity arm: a population of zero must never read as a pass.
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        build(tmp, 'f = ["dep:x"]', "g = []", "h = []")
        _got, pop = findings(tmp)
        ok = pop == 0
        print(f"  [{'ok' if ok else 'FAIL'}] a population of zero is detectable: pop={pop}")
        if not ok:
            failed += 1

    print(f"facade-forward selftest: {'OK' if not failed else f'{failed} FAILURE(S)'}")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()

    out, population = findings(REPO_ROOT)

    # A gate that cannot name its own population cannot be trusted when quiet:
    # a silent rc=0 makes "passed" and "never ran" indistinguishable. This tree
    # has paid for that shape more than once, so the count is always printed
    # and a population of zero is a FAILURE, not a pass.
    if population == 0:
        print(
            "  facade-forward FAIL: read ZERO runtime forwards out of "
            f"crates/{FACADE}/Cargo.toml. Either the facade stopped forwarding "
            "or this parser did -- both make a green run meaningless.",
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
