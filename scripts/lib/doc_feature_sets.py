#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3768 (no register item) -- which feature configurations Layers C1bz and C1bzr document a crate
under. The reduced configurations (C1bzr) are R3802's.

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

THE OTHER DIRECTION. Those sets are the LARGEST configurations, and a doc link can only break in a
smaller one: a link from an item that is compiled to an item that is not. `slot_plane`'s docs
linked `slot_group`, which needs `transport-multicast`; the crate root's linked `connect_manager`,
which needs `dial`. Both resolved with every feature on and failed in a build without that one.

The REDUCED configurations find that class by giving up one feature at a time. For every set
above and every feature `g` it holds, the set without `g` (and without what reaches `g`, by the
same rule) is a configuration in which every item whose cfg does not need `g` is still compiled
and every item that needs `g` is gone. A link from the first kind to the second fails there and
nowhere else, whatever else the referring item's cfg asks for, because everything else is on.
That is what makes giving one up the right family rather than turning one on: a build with one
feature over a bare crate does not compile a referrer gated on two.

A configuration matters only through what it changes, so two that compile the same items of the
crate are one. Which items the crate compiles depends on the features its own sources and build
script name (a `feature = "x"` cfg, or the variable cargo gives a build script for a feature),
so a configuration is identified by that set,
and one with the identity of a largest set measures nothing the largest set has not. The scan
over-reads (a name in a comment counts), which costs a build and never a configuration.

What this does not reach, stated: a link into a DEPENDENCY's item that a forwarded feature
(`dep/x`) gates, when the crate names no cfg of its own on that feature. Telling those apart
would make a forwarded feature part of the identity, and measured when this was written that is
1188 configurations across the workspace instead of 525, `wz` alone 587 instead of 25. The links a dependency's own
docs carry are measured in the dependency; the residue is a crate's links INTO it.

Usage:
    doc_feature_sets.py <crate>            one line per largest set: `<label> <cargo argument>...`
    doc_feature_sets.py --reduced <crate>  the same, one line per reduced configuration
    doc_feature_sets.py --selftest
Exit: 0 sets printed; 1 usage or the workspace could not be read; 2 the manifest is wrong.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ALL_FEATURES = "--all-features"
NO_DEFAULT_FEATURES = "--no-default-features"
METADATA_KEY = "wz-docs"
# The cargo targets `cargo doc` documents.
DOCUMENTED_KINDS = {"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro", "bin"}
CFG_FEATURE = re.compile(r'feature\s*=\s*"([^"]+)"')
BUILD_SCRIPT_FEATURE = re.compile(r"CARGO_FEATURE_([A-Z0-9_]+)")


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


def largest_sets(package: dict) -> list[tuple[str, list[str]]]:
    """The declared sets, or the one set of every feature when the crate declares none."""
    return documentation_sets(package) or [("all", list(package["features"]))]


def features_argument(members: list[str]) -> list[str]:
    """Cargo arguments that enable exactly `members`.

    `--no-default-features`, because `default` is a feature like any other here: a set that gives
    it up (it reaches a given-up feature) must not get it back from cargo.
    """
    return [NO_DEFAULT_FEATURES, f"--features={','.join(members)}"]


def cargo_arguments(package: dict) -> list[tuple[str, list[str]]]:
    """`[(label, cargo arguments)]`, one per largest configuration of the crate."""
    sets = documentation_sets(package)
    if not sets:
        return [("all", [ALL_FEATURES])]
    return [(name, features_argument(members)) for name, members in sets]


def documented_sources(package: dict) -> list[Path]:
    """The Rust sources of the targets `cargo doc` documents, and the build script."""
    files: set[Path] = set()
    for target in package["targets"]:
        src = Path(target["src_path"])
        if "custom-build" in target["kind"]:
            files.add(src)
        elif DOCUMENTED_KINDS & set(target["kind"]):
            files.update(src.parent.rglob("*.rs"))
    return sorted(files)


def named_features(features: dict[str, list[str]], texts: list[str]) -> set[str]:
    """The features of `features` that the source `texts` name, as a cfg or as a build script's
    `CARGO_FEATURE_` variable."""
    by_env = {name.upper().replace("-", "_"): name for name in features}
    named: set[str] = set()
    for text in texts:
        named.update(n for n in CFG_FEATURE.findall(text) if n in features)
        named.update(by_env[n] for n in BUILD_SCRIPT_FEATURE.findall(text) if n in by_env)
    return named


def reduced_sets(
    package: dict, named: set[str]
) -> list[tuple[str, list[str]]]:
    """Every largest set without one feature it holds, one per distinct compiled crate.

    `named` is what decides which items the crate compiles; a reduced set whose named features are
    those of a largest set, or of a reduced set already listed, is dropped.
    """
    features: dict[str, list[str]] = package["features"]
    largest = largest_sets(package)

    def identity(members: list[str]) -> frozenset[str]:
        return frozenset(named.intersection(members))

    seen = {identity(members) for _, members in largest}
    reduced: list[tuple[str, list[str]]] = []
    for set_name, members in largest:
        for given_up in members:
            if given_up not in named:
                continue
            kept = [f for f in members if given_up not in implied_features(features, f)]
            key = identity(kept)
            if key in seen:
                continue
            seen.add(key)
            reduced.append((f"{set_name}-without-{given_up}", kept))
    return reduced


def reduced_arguments(package: dict) -> list[tuple[str, list[str]]]:
    """`[(label, cargo arguments)]`, one per reduced configuration of the crate."""
    texts = [
        path.read_text(encoding="utf-8", errors="replace")
        for path in documented_sources(package)
    ]
    named = named_features(package["features"], texts)
    return [(name, features_argument(kept)) for name, kept in reduced_sets(package, named)]


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
    assert [label for label, _ in arguments] == ["ap", "mcu"], arguments
    assert all(
        args[0] == NO_DEFAULT_FEATURES and args[1].startswith("--features=")
        for _, args in arguments
    ), arguments

    # No metadata is one build with every feature, as before.
    assert cargo_arguments({"features": features}) == [("all", [ALL_FEATURES])]

    # The reduced configurations. `slot` and `group` are named by the sources, `group` needs
    # `slot`, and `preset` and `forward` are named by none.
    reduce = {
        "default": ["slot"],
        "slot": [],
        "group": ["slot"],
        "preset": ["group"],
        "forward": ["dep:x", "x/feat"],
    }
    texts = [
        '#[cfg(feature = "slot")] mod a;',
        '#[cfg(all(feature = "group", not(feature = "nope")))] mod b;',
    ]
    named = named_features(reduce, texts)
    assert named == {"slot", "group"}, named
    # A build script's variable names the feature it spells.
    assert named_features(reduce, ['env::var("CARGO_FEATURE_FORWARD")']) == {"forward"}

    lone = {"features": reduce}
    sets = reduced_sets(lone, named)
    assert [label for label, _ in sets] == ["all-without-slot", "all-without-group"], sets
    # Giving up `slot` gives up everything that reaches it, `default` included, and cargo is
    # told so: `default` must not come back.
    without_slot = dict(sets)["all-without-slot"]
    assert without_slot == ["forward"], without_slot
    assert features_argument(without_slot) == [NO_DEFAULT_FEATURES, "--features=forward"]
    assert dict(sets)["all-without-group"] == ["default", "slot", "forward"], sets
    # A feature the sources do not name compiles no other item; with no name at all there is
    # nothing to give up.
    assert reduced_sets(lone, set()) == []

    # Two largest sets whose reduced forms compile the same items are measured once, and a
    # reduced form equal to a largest set is not measured again.
    twin = {
        "features": {"a": [], "b": [], "c": []},
        "metadata": {
            METADATA_KEY: {
                "feature-sets": [
                    {"name": "no-a", "except": ["a"]},
                    {"name": "no-b", "except": ["b"]},
                ]
            }
        },
    }
    labels = [label for label, _ in reduced_sets(twin, {"a", "b", "c"})]
    assert labels == ["no-a-without-b", "no-a-without-c", "no-b-without-c"], labels
    labels = [label for label, _ in reduced_sets(twin, {"a", "b"})]
    assert labels == ["no-a-without-b"], labels
    # `no-b` without `a` compiles what `no-a` compiles when only `a` is named.
    assert reduced_sets(twin, {"a"}) == [], reduced_sets(twin, {"a"})

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
    configurations = cargo_arguments
    if argv[:1] == ["--reduced"]:
        configurations = reduced_arguments
        argv = argv[1:]
    if len(argv) != 1 or argv[0].startswith("-"):
        print(__doc__, file=sys.stderr)
        return 1
    try:
        for label, arguments in configurations(workspace_package(argv[0])):
            print(" ".join([label, *arguments]))
    except ManifestError as error:
        print(f"doc-feature-sets: {argv[0]}: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
