#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3009 (no register item) -- the cargo workspaces this repository builds, as
ONE definition for the gates that ask what a build pulls.

## Why this exists

This repository has two cargo workspaces, not one: `crates/` (the wz stack) and
`xtask/` (the codegen driver, kept out of the first on purpose so that a plain
build of the wz stack needs no libxml2). Every gate that read `cargo metadata`
read `crates/` alone, and that was exact for as long as the codegen toolchain
sat inside `crates/`'s own closure, because the forge runtime's build script
pulled it there.

The SCE pin of R3009 took the toolchain out of that build script. `libxml` and
`sce-build` then left the `crates/` graph and live only in the `xtask/` graph,
and three gates changed behaviour without a line of theirs changing:

* `apt_package_census.py`'s shortfall arm found no build script probing
  pkg-config and reported an EMPTY population;
* `prose_build_closure_gate.py` lost the vocabulary its denials resolve
  against (`libxml` was no longer a build-time package it could see), so every
  denial of the toolchain went unadjudicated and its floor read zero;
* `prose_dep_graph_gate.py` could no longer resolve a sentence naming
  `sce-build`, which exists, because it looked only where it no longer is.

Each of those is the same defect: the question was about THIS REPOSITORY's
builds and the answer was read from one of its workspaces. A new workspace is
added here, once, and every reader sees it.

## What it offers

`metadata(name)` is one workspace's `cargo metadata --all-features`, cached.
`merged_active()` is a metadata-shaped document over all of them, each
workspace first cut to the packages ITS build activates (the feature
unification differs between workspaces, so activation must be decided inside
each before the packages are unioned, never after).
"""

from __future__ import annotations

import functools
import json
import subprocess
import sys
from pathlib import Path

import cargo_activation

ROOT = Path(__file__).resolve().parents[2]

# name -> manifest. The ONE place the list is written.
MANIFESTS: dict[str, Path] = {
    "crates": ROOT / "crates" / "Cargo.toml",
    "xtask": ROOT / "xtask" / "Cargo.toml",
}


@functools.lru_cache(maxsize=None)
def metadata(name: str) -> dict:
    """`cargo metadata --all-features` of workspace `name`.

    All features because the callers' questions are about what ANY build may
    demand or pull, and a denial has to hold under every feature selection.
    """
    proc = subprocess.run(
        [
            "cargo", "metadata", "--all-features", "--format-version", "1",
            "--manifest-path", str(MANIFESTS[name]),
        ],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"`cargo metadata` failed for the `{name}` workspace "
            f"(rc={proc.returncode}): {proc.stderr[:400]}"
        )
    return json.loads(proc.stdout)


def merged_active() -> dict:
    """One metadata-shaped document: the packages every workspace's build
    ACTIVATES, unioned by package id, and every workspace's members.

    Only `packages` and `workspace_members` are meaningful in the result. The
    `resolve` section is deliberately dropped: it is per-workspace feature
    unification, and a union of two unifications describes no build.
    """
    packages: dict[str, dict] = {}
    members: list[str] = []
    for name in MANIFESTS:
        meta = metadata(name)
        active = cargo_activation.activated_packages(meta)
        for pkg in meta["packages"]:
            if pkg["id"] in active:
                packages.setdefault(pkg["id"], pkg)
        members.extend(m for m in meta["workspace_members"] if m not in members)
    return {"packages": list(packages.values()), "workspace_members": members}


def selftest() -> int:
    """Every declared workspace resolves, and the merge sees what only one of
    them carries: `xtask` as a member, and a package present in `xtask` and
    absent from `crates`."""
    names = {n: {p["name"] for p in metadata(n)["packages"]} for n in MANIFESTS}
    merged = merged_active()
    merged_names = {p["name"] for p in merged["packages"]}
    member_names = {
        p["name"] for p in merged["packages"] if p["id"] in set(merged["workspace_members"])
    }
    only_xtask = names["xtask"] - names["crates"]
    if not only_xtask:
        print(
            "cargo-workspaces: SELFTEST FAIL -- the `xtask` workspace carries no "
            "package `crates` lacks, so the merge would be indistinguishable from "
            "reading `crates` alone and this module would prove nothing"
        )
        return 1
    if "xtask" not in member_names:
        print("cargo-workspaces: SELFTEST FAIL -- the merge lost `xtask` as a member")
        return 1
    if not (only_xtask & merged_names):
        print(
            "cargo-workspaces: SELFTEST FAIL -- no package only `xtask` carries "
            "survived the merge's activation cut"
        )
        return 1
    print(
        f"cargo-workspaces: selftest OK -- {len(MANIFESTS)} workspace(s), "
        f"{len(only_xtask)} package(s) only `xtask` carries, all reachable "
        f"through the merged document"
    )
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    print("usage: cargo_workspaces.py --selftest")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
