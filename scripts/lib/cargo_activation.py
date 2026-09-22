#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2801 — which dependencies a build ACTIVATES, read off `cargo metadata`.

## The defect this exists for, measured

`cargo metadata --all-features` answers two questions in one document and
they are not the same question. Its `resolve` graph is the LOCK-level
resolve: it carries an edge to an optional dependency whenever a feature so
much as MENTIONS it -- including a weak feature, `dep?/feat`, whose whole
meaning is "only if something else turned `dep` on". The build does not
compile that dependency; `cargo tree -i <dep> --all-features` prints nothing
for it.

R2801 met this the first time a crate in this graph carried such a feature.
`rocksdb` enables `librocksdb-sys/static`, which is
`["libz-sys?/static", "bzip2-sys?/static"]`, and the metadata then listed
`librocksdb-sys -> libz-sys` and `-> bzip2-sys` although zlib and bzip2 were
never turned on. Two gates read those edges as "the build demands this":

- `apt_package_census.py` asked every CI job to apt-install zlib and bzip2
  development packages for build scripts that never run;
- `prose_build_closure_gate.py` took `libz-sys`'s `links = "z"` into its
  vocabulary and read `z_id_to_string` in a doc comment as a claim that a
  crate pulls libz.

Installing the packages would have satisfied the first and been a workaround:
a CI image made to carry libraries nothing compiles, so that a gate could keep
a population it had defined wrongly. The population is what was wrong.

## The rule, which is cargo's

An edge from a package to a NON-optional dependency is active. An edge to an
OPTIONAL dependency is active only when one of the package's ENABLED features
(the resolve node's `features`, already closed under feature implication)
activates it: the implicit feature of that name is enabled, or an enabled
feature's definition names `dep:<name>`, `<name>` or `<name>/<feat>`. A
`<name>?/<feat>` entry never does -- that is the weak form, and it is the
whole of the difference.

`<name>` is the dependency's name as the manifest spells it: its `rename` when
it has one, which is also what its features say.
"""

from __future__ import annotations

import sys


def _activates(definition: list[str], name: str) -> bool:
    """Whether one feature's definition turns the optional dependency on."""
    for entry in definition:
        if entry in (f"dep:{name}", name) or entry.startswith(f"{name}/"):
            return True
    return False


def _edge_is_active(pkg: dict, enabled: set[str], dep_name: str) -> bool:
    """Whether `pkg`, with `enabled` features, activates its dependency on the
    package named `dep_name` (the package name, not the rename)."""
    decls = [d for d in pkg["dependencies"] if d["name"] == dep_name]
    if not decls:
        # The lock knows an edge the manifest does not declare. Nothing here
        # can say it is inactive, and silently dropping it would shrink a
        # population on a guess.
        return True
    for decl in decls:
        if not decl.get("optional", False):
            return True
        spelled = decl.get("rename") or decl["name"]
        if spelled in enabled:
            return True
        features = pkg.get("features", {})
        if any(_activates(features.get(f, []), spelled) for f in enabled):
            return True
    return False


def activated_edges(meta: dict) -> dict[str, set[str]]:
    """package id -> the ids of the dependencies its build activates."""
    by_id = {p["id"]: p for p in meta["packages"]}
    out: dict[str, set[str]] = {}
    for node in meta["resolve"]["nodes"]:
        pkg = by_id[node["id"]]
        enabled = set(node.get("features", []))
        out[node["id"]] = {
            dep["pkg"]
            for dep in node["deps"]
            if _edge_is_active(pkg, enabled, by_id[dep["pkg"]]["name"])
        }
    return out


def activated_packages(meta: dict) -> set[str]:
    """Ids of every package a build of some workspace member compiles: the
    workspace members and everything they reach over ACTIVE edges."""
    edges = activated_edges(meta)
    seen = set(meta["workspace_members"])
    stack = list(seen)
    while stack:
        for nxt in edges.get(stack.pop(), ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def _fixture() -> dict:
    """`app` depends on `lib`; `lib` has five optional dependencies and turns
    four of them on four different ways -- or, for two, does not."""

    def pkg(name, deps=(), features=None):
        return {
            "id": f"{name} 1.0",
            "name": name,
            "dependencies": [
                {"name": d, "optional": opt, "rename": ren} for d, opt, ren in deps
            ],
            "features": features or {},
        }

    packages = [
        pkg("app", [("lib", False, None)]),
        pkg(
            "lib",
            [
                ("weak", True, None),
                ("viadep", True, None),
                ("implicit", True, None),
                ("renamed-pkg", True, "alias"),
                ("off", True, None),
            ],
            {
                "static": ["weak?/static"],
                "use-viadep": ["dep:viadep"],
                "use-alias": ["alias/extra"],
            },
        ),
        pkg("weak"),
        pkg("viadep"),
        pkg("implicit"),
        pkg("renamed-pkg"),
        pkg("off"),
    ]

    def node(name, deps, features=()):
        return {
            "id": f"{name} 1.0",
            "deps": [{"pkg": f"{d} 1.0"} for d in deps],
            "features": list(features),
        }

    return {
        "packages": packages,
        "workspace_members": ["app 1.0"],
        "resolve": {
            "nodes": [
                node("app", ["lib"]),
                # The lock lists all five, as `cargo metadata` does.
                node(
                    "lib",
                    ["weak", "viadep", "implicit", "renamed-pkg", "off"],
                    ["static", "use-viadep", "implicit", "use-alias"],
                ),
                node("weak", []),
                node("viadep", []),
                node("implicit", []),
                node("renamed-pkg", []),
                node("off", []),
            ]
        },
    }


def selftest() -> int:
    got = {i.split(" ")[0] for i in activated_packages(_fixture())}
    want = {"app", "lib", "viadep", "implicit", "renamed-pkg"}
    if got != want:
        print(
            f"cargo-activation: SELFTEST FAIL -- expected {sorted(want)}, got "
            f"{sorted(got)}. `weak` is named only by a `weak?/static` entry and "
            f"`off` by nothing, so neither is compiled; `viadep` (dep:), "
            f"`implicit` (its implicit feature) and `renamed-pkg` (through its "
            f"rename `alias/extra`) are."
        )
        return 1
    print(
        "cargo-activation: selftest OK -- a weak `dep?/feat` activates nothing; "
        "`dep:x`, an implicit feature and a renamed `alias/feat` each activate "
        "their dependency; an optional dependency nothing names stays out"
    )
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    print("usage: cargo_activation.py --selftest  (a library for the gates)")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
