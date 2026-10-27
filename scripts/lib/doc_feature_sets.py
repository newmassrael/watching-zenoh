#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""Which feature configurations Layer C1bz documents a crate under.

THE PROBLEM. C1bz documents a crate with every feature on, because a module behind a feature that
is off is not compiled and its doc links are never checked. That is right for a crate whose
features are compatible and wrong for one that refuses a combination: `wz` stops, by
`compile_error!`, when the AP runtime meets an MCU platform, when the two RTOS platforms meet, and
when the two C ABIs meet. `--all-features` on it ends at the first refusal, so its four refusals
were carried as a budget of four, a number no edit to a doc could move and that said nothing about
the docs.

THE STRUCTURE. A crate that cannot hold every feature at once says so in its manifest, under
`[package.metadata.wz-docs]`, as a list of sets. A set names the features it gives up (`except`)
and holds every other feature of the crate, with one rule that makes "gives up" mean what it says:
a feature that REACHES a given-up feature through the manifest's own implications is given up
with it. Without the rule a preset that implies a given-up platform would bring the platform back
in through the front. Cargo has no spelling for "every feature but these", so the set is computed
and handed to `--features`.

THE GUARD. A set is a claim about coverage, and an unchecked claim is the failure this lane
exists to prevent. The sets of a crate must together hold every feature the crate has; one that
lies in no set has docs nobody builds, and the script refuses the manifest and names it. The one
legitimate way to lie in no set is to BE the refused combination: an aggregate such as `wz`'s
`domain-api`, which turns on both C ABIs, can be enabled by no build and is documented through its
members. Such a feature is named under `refused`, and the check runs both ways: a feature in no set
and not named is a hole, and one named but held by a set is a stale entry.

A crate with no `[package.metadata.wz-docs]` is documented once, under `--all-features`, which is
what the lane always did.

Usage:
    doc_feature_sets.py <crate>      one line per set, each a single cargo argument
    doc_feature_sets.py --selftest
Exit: 0 sets printed; 1 usage or the workspace could not be read; 2 the manifest is wrong.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ALL_FEATURES = "--all-features"
METADATA_KEY = "wz-docs"


class ManifestError(Exception):
    """The sets a manifest declares do not describe a documentable crate."""


def implied_features(features: dict[str, list[str]], name: str) -> set[str]:
    """`name` and every feature of the same crate it turns on, through the manifest.

    An entry is another feature of this crate only when it is a bare name that the map holds.
    `dep:x`, `x/f` and `x?/f` reach into a dependency and cannot turn on a feature of this crate.
    """
    seen: set[str] = set()
    stack = [name]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        for entry in features.get(current, []):
            if entry in features:
                stack.append(entry)
    return seen


def feature_set(features: dict[str, list[str]], except_: list[str]) -> list[str]:
    """Every feature that does not reach one of `except_`, in the manifest's order."""
    unknown = [e for e in except_ if e not in features]
    if unknown:
        raise ManifestError(
            f"a set gives up {unknown}, which the crate does not have as a feature"
        )
    given_up = set(except_)
    return [
        name
        for name in features
        if not (implied_features(features, name) & given_up)
    ]


def documentation_sets(package: dict) -> list[tuple[str, list[str]]]:
    """`[(set name, [feature, ...])]` for a package, or `[]` when it documents once."""
    config = (package.get("metadata") or {}).get(METADATA_KEY)
    if config is None:
        return []
    features: dict[str, list[str]] = package["features"]
    declared = config.get("feature-sets")
    if not declared:
        raise ManifestError(f"[package.metadata.{METADATA_KEY}] declares no feature-sets")

    sets: list[tuple[str, list[str]]] = []
    names: set[str] = set()
    for entry in declared:
        name = entry.get("name")
        if not name or name in names:
            raise ManifestError(f"a feature set is unnamed or named twice: {name!r}")
        names.add(name)
        sets.append((name, feature_set(features, list(entry.get("except", [])))))

    # A feature in no set is either named as refused or is a hole. Both directions are checked,
    # as the budget of this lane is: a refusal that a set now holds is stale, and says so.
    refused = list(config.get("refused", []))
    covered = set().union(*(set(members) for _, members in sets))
    missing = [name for name in features if name not in covered]
    holes = [name for name in missing if name not in refused]
    if holes:
        raise ManifestError(
            f"{len(holes)} feature(s) lie in no set and are not named in `refused`, so their "
            f"docs are built by nobody: {holes[:12]}{' ...' if len(holes) > 12 else ''}"
        )
    stale = [name for name in refused if name not in missing]
    if stale:
        raise ManifestError(
            f"`refused` names {stale}, which a set holds or the crate lacks; drop them"
        )
    return sets


def cargo_arguments(package: dict) -> list[str]:
    """One cargo argument per documentation of the crate."""
    sets = documentation_sets(package)
    if not sets:
        return [ALL_FEATURES]
    return [f"--features={','.join(members)}" for _, members in sets]


def workspace_package(crate: str) -> dict:
    crates_dir = Path(__file__).resolve().parents[2] / "crates"
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=crates_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        print(f"doc-feature-sets: cargo metadata failed: {out.stderr.strip()}", file=sys.stderr)
        raise SystemExit(1)
    for package in json.loads(out.stdout)["packages"]:
        if package["name"] == crate:
            return package
    print(f"doc-feature-sets: {crate} is not a workspace member", file=sys.stderr)
    raise SystemExit(1)


def selftest() -> int:
    features = {
        "default": [],
        "tokio": ["dep:tokio"],
        "mcu-a": [],
        "mcu-b": [],
        "ap-preset": ["tokio", "extra"],
        "mcu-preset": ["mcu-a"],
        "mixed-preset": ["tokio", "mcu-a"],
        "extra": ["dep:x", "x/feat"],
    }

    # A set holds what does not reach a given-up feature, and the implication rule is real:
    # `ap-preset` and `mixed-preset` reach `tokio`.
    ap = feature_set(features, ["mcu-a", "mcu-b"])
    assert "tokio" in ap and "ap-preset" in ap and "extra" in ap, ap
    assert "mcu-a" not in ap and "mixed-preset" not in ap and "mcu-preset" not in ap, ap
    mcu = feature_set(features, ["tokio"])
    assert "mcu-preset" in mcu and "mcu-a" in mcu and "mcu-b" in mcu, mcu
    assert "ap-preset" not in mcu and "mixed-preset" not in mcu and "tokio" not in mcu, mcu

    # An entry that reaches into a dependency does not imply a feature of this crate.
    assert implied_features(features, "extra") == {"extra"}

    package = {
        "features": features,
        "metadata": {
            METADATA_KEY: {
                "feature-sets": [
                    {"name": "ap", "except": ["mcu-a", "mcu-b"]},
                    {"name": "mcu", "except": ["tokio"]},
                ]
            }
        },
    }
    # `mixed-preset` reaches both sides: it is in no set, and the manifest is refused.
    try:
        documentation_sets(package)
    except ManifestError as error:
        assert "mixed-preset" in str(error), error
    else:
        raise AssertionError("a feature in no set was accepted")

    # Naming it as refused accepts the manifest; naming one a set holds is a stale entry.
    config = package["metadata"][METADATA_KEY]
    config["refused"] = ["mixed-preset"]
    sets = documentation_sets(package)
    assert [name for name, _ in sets] == ["ap", "mcu"], sets
    config["refused"] = ["mixed-preset", "extra"]
    try:
        documentation_sets(package)
    except ManifestError as error:
        assert "extra" in str(error), error
    else:
        raise AssertionError("a stale refused entry was accepted")
    config["refused"] = ["mixed-preset"]
    arguments = cargo_arguments(package)
    assert all(a.startswith("--features=") for a in arguments), arguments

    # No metadata is one build with every feature, as before.
    assert cargo_arguments({"features": features}) == [ALL_FEATURES]

    # A set that gives up a feature the crate lacks, an unnamed set and a repeated one are refused.
    for bad in (
        [{"name": "x", "except": ["nope"]}],
        [{"except": []}],
        [{"name": "x"}, {"name": "x"}],
        [],
    ):
        broken = {"features": features, "metadata": {METADATA_KEY: {"feature-sets": bad}}}
        try:
            documentation_sets(broken)
        except ManifestError:
            pass
        else:
            raise AssertionError(f"accepted {bad}")

    print("doc-feature-sets selftest: OK")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if len(argv) != 1 or argv[0].startswith("-"):
        print(__doc__, file=sys.stderr)
        return 1
    try:
        for argument in cargo_arguments(workspace_package(argv[0])):
            print(argument)
    except ManifestError as error:
        print(f"doc-feature-sets: {argv[0]}: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
