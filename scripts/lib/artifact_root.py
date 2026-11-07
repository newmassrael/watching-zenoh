#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4400 (no register item) -- where a product of this checkout is.

This is the Python reading of the one rule.

`scripts/lib/artifact-root.sh` states the rule and is the place to read it.
In short: a product of the tree path `<rel>` is at `<checkout>/<rel>` when
`WZ_ARTIFACT_ROOT` is unset, and at `$WZ_ARTIFACT_ROOT/<rel>` when it is set;
the layout under the root mirrors the tree, and nothing is written into the
checkout. The shell and Rust readings (`wz_artifact_dir`,
`wz_codegen_build::artifact_dir`) answer the same question the same way.

A gate that READS a product (an oracle, a cdylib, a build directory) asks
`artifact(<rel>)`; a gate that reads SOURCE keeps reading the checkout.
"""

from __future__ import annotations

import os
import pathlib
import sys
import tempfile

#: The checkout this file belongs to.
CHECKOUT = pathlib.Path(__file__).resolve().parents[2]

#: The variable the rule reads. Named once, here, for every Python reader.
ENV = "WZ_ARTIFACT_ROOT"


def artifact_root(env: dict[str, str] | None = None, checkout: pathlib.Path = CHECKOUT) -> pathlib.Path:
    """The directory products are under: the root when set, else the checkout."""
    value = (os.environ if env is None else env).get(ENV, "")
    if not value:
        return checkout
    root = pathlib.Path(value)
    if not root.is_absolute():
        raise ValueError(f"{ENV} must be an absolute path, got {value!r}")
    return pathlib.Path(os.path.normpath(root))


def artifact(rel: str | os.PathLike[str], env: dict[str, str] | None = None,
             checkout: pathlib.Path = CHECKOUT) -> pathlib.Path:
    """The product location of the tree path `rel` (relative to the checkout)."""
    rel = pathlib.PurePath(rel)
    if rel.is_absolute():
        raise ValueError(f"a tree path is relative to the checkout, got {str(rel)!r}")
    return artifact_root(env, checkout) / rel


def artifact_dir(path: str | os.PathLike[str], env: dict[str, str] | None = None,
                 checkout: pathlib.Path = CHECKOUT) -> pathlib.Path:
    """The product location of an absolute path; one outside the checkout is unchanged."""
    path = pathlib.Path(os.path.normpath(os.path.abspath(path)))
    for base in (checkout, pathlib.Path(os.path.normpath(os.path.abspath(checkout)))):
        try:
            rel = path.relative_to(base)
        except ValueError:
            continue
        return artifact(rel, env, checkout)
    return path


def selftest() -> int:
    failures = 0

    def expect(ok: bool, what: str) -> None:
        nonlocal failures
        if not ok:
            failures += 1
            print(f"artifact_root selftest FAIL: {what}", file=sys.stderr)

    with tempfile.TemporaryDirectory() as tmp:
        tree = pathlib.Path(tmp) / "tree"
        root = pathlib.Path(tmp) / "out"
        unset: dict[str, str] = {}
        empty = {ENV: ""}
        on = {ENV: str(root)}
        expect(artifact_root(unset, tree) == tree, "an unset root is not the checkout")
        expect(artifact_root(empty, tree) == tree, "an empty root is not the checkout")
        expect(artifact_root(on, tree) == root, "a set root is not used")
        expect(artifact("target/zenohd", unset, tree) == tree / "target/zenohd",
               "an unset root moved a product")
        expect(artifact("target/zenohd", on, tree) == root / "target/zenohd",
               "a set root does not mirror the tree path")
        expect(artifact_dir(tree / "crates" / "target", on, tree) == root / "crates" / "target",
               "an absolute tree path is not mirrored")
        expect(artifact_dir("/etc", on, tree) == pathlib.Path("/etc"),
               "a path outside the checkout was relocated")
        for bad, what in (({ENV: "rel/out"}, "a relative root"),):
            try:
                artifact_root(bad, tree)
                expect(False, f"{what} was accepted")
            except ValueError:
                pass
        try:
            artifact("/abs", on, tree)
            expect(False, "an absolute tree path was accepted by artifact()")
        except ValueError:
            pass
    if failures:
        return 1
    print("artifact_root selftest: ok")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    if len(sys.argv) == 2:
        print(artifact(sys.argv[1]))
        sys.exit(0)
    print("usage: artifact_root.py --selftest | <tree path>", file=sys.stderr)
    sys.exit(2)
