#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y606 — reject a gate script the HOSTED runner's python cannot run.

## The defect this closes

`dissect_feature_census.py` landed at R311y605 with `import tomllib`, which is
stdlib only from Python 3.11. The hosted lanes run `ubuntu-22.04`, whose
python3 is 3.10. Layer C0 therefore died in `import` on the first hosted run
after the gate landed, took the 29 steps behind it down with it (C1, C2, the
whole E family, Layer D, Layer L), and stayed GREEN on the 3.12 workstation
that wrote it -- which is where the round's own verification ran.

Nothing in the tree could see it. The lint layer type-checks nothing about the
interpreter, and the hosted lane is the ONLY place the floor interpreter is
exercised, so it is also the last place the answer arrives.

## What the gate asserts

Every python source the CI lanes execute must PARSE and IMPORT on the oldest
python any workflow runner provides. Two independent arms:

1. **Syntax** -- `ast.parse(..., feature_version=FLOOR)`. This needs no table:
   CPython's own parser knows which grammar arrived when, and rejects `except*`
   (3.11), PEP 695 type parameters and `type` aliases (3.12) against a 3.10
   floor while accepting `match` (3.10) and the walrus (3.8).

2. **Stdlib imports** -- a table, because nothing in the stdlib records when a
   module was added. `POST_FLOOR_STDLIB` is short by nature (new top-level
   stdlib modules are rare) and is SELF-CHECKED: every entry at or below the
   running interpreter's version must actually exist in
   `sys.stdlib_module_names`, so a typo cannot make an entry silently inert.

## Why the floor is derived, not written down

A hardcoded `(3, 10)` is a second copy of a fact whose original lives in
`runs-on:`. Bump the image to `ubuntu-24.04` and the constant is silently
pessimistic; the reverse direction is silently WRONG. So the floor is read out
of the workflows: every runner image named anywhere in `.github/workflows/`
(literal `runs-on:` plus matrix `os:` arrays) is looked up in `RUNNER_PYTHON`,
and the floor is the minimum. An image this table does not know is a FAIL that
demands its python3 be recorded -- the gate must not guess an interpreter.

Taking the minimum over ALL images, rather than only over the jobs that
actually run python, is deliberate: telling those two sets apart needs a YAML
parse, and `python3-yaml` is installed by a LATER step than this one. The
minimum is conservative in the safe direction -- an image that runs no python
can only make the floor stricter, never blind -- and the cost of that
conservatism is a comment, not a silent gap.

## What it deliberately does NOT check

- **Third-party imports.** A gate script that needs `yaml` has a provisioning
  question, not a version question, and the lanes answer it with an install
  step. Only stdlib names are in scope.
- **Runtime behaviour.** A stdlib function whose SIGNATURE gained a keyword in
  3.12 passes here. The arms above cover the two failure modes that have
  actually shipped -- a module that does not exist and grammar that does not
  parse. The backstop for the rest stays where it was: the hosted lane.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"

# Python source the CI lanes execute. `scripts/**` is the whole surface today;
# the glob is recursive so a new subdirectory is in scope the day it lands.
SCAN_ROOTS = (ROOT / "scripts",)

# The default `python3` each GitHub-hosted runner image ships, from the image
# manifests (actions/runner-images). Recorded rather than probed because the
# gate has to know the answer for images it is not currently running on.
RUNNER_PYTHON: dict[str, tuple[int, int]] = {
    "ubuntu-22.04": (3, 10),
    "ubuntu-24.04": (3, 12),
    "macos-latest": (3, 13),
    "windows-latest": (3, 13),
}

# Top-level stdlib modules that do NOT exist at every floor this gate can
# derive. Only names newer than the OLDEST entry in RUNNER_PYTHON can matter,
# which is why this table is short -- and it is checked against the running
# interpreter's own stdlib below so a misspelling cannot go inert.
POST_FLOOR_STDLIB: dict[str, tuple[int, int]] = {
    "tomllib": (3, 11),
    "annotationlib": (3, 14),
}

RUNS_ON = re.compile(r"^\s*runs-on:\s*(?P<image>[A-Za-z0-9._-]+)\s*$")
MATRIX_OS = re.compile(r"^\s*os:\s*\[(?P<images>[^\]]*)\]\s*$")


def runner_images() -> tuple[set[str], list[str]]:
    """Every runner image the workflows name, plus any name not in the table."""
    images: set[str] = set()
    for wf in sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml")):
        for line in wf.read_text(encoding="utf-8").splitlines():
            m = RUNS_ON.match(line)
            if m:
                images.add(m.group("image"))
                continue
            m = MATRIX_OS.match(line)
            if m:
                for name in m.group("images").split(","):
                    name = name.strip().strip("'\"")
                    if name:
                        images.add(name)
    unknown = sorted(i for i in images if i not in RUNNER_PYTHON)
    return images, unknown


def table_self_check() -> list[str]:
    """Every POST_FLOOR entry this interpreter is new enough to have must exist."""
    running = sys.version_info[:2]
    stdlib = getattr(sys, "stdlib_module_names", None)
    if stdlib is None:  # pragma: no cover — 3.10+ always has it
        return []
    return [
        f"POST_FLOOR_STDLIB names {name!r} as arriving in "
        f"{ver[0]}.{ver[1]}, but this interpreter ({running[0]}.{running[1]}) "
        "has no such stdlib module -- the entry is inert, so nothing it was "
        "meant to reject would be rejected"
        for name, ver in sorted(POST_FLOOR_STDLIB.items())
        if ver <= running and name not in stdlib
    ]


def imported_top_level(tree: ast.AST) -> list[tuple[str, int]]:
    """Every top-level module name imported anywhere in the file, with its line."""
    names: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend((alias.name.split(".", 1)[0], node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            # `from . import x` has module=None; a relative import is ours.
            if node.level == 0 and node.module:
                names.append((node.module.split(".", 1)[0], node.lineno))
    return names


def main() -> int:
    images, unknown = runner_images()
    if not images:
        print(
            "python-floor lint: found NO runner image in "
            f"{WORKFLOWS} -- the read is broken, not the workflows",
            file=sys.stderr,
        )
        return 1
    if unknown:
        print(
            "python-floor lint: unrecognised runner image(s): "
            + ", ".join(unknown),
            file=sys.stderr,
        )
        print(
            "\nLayer C0 FAIL: the floor cannot be derived, and this gate must "
            "not guess an\ninterpreter. Record each image's default python3 in "
            "RUNNER_PYTHON.\n",
            file=sys.stderr,
        )
        return 1
    floor = min(RUNNER_PYTHON[i] for i in images)

    findings: list[str] = table_self_check()

    sources = sorted(
        {p for root in SCAN_ROOTS for p in root.rglob("*.py")},
        key=lambda p: p.as_posix(),
    )
    if not sources:
        # A version that scanned nothing would exit 0 forever and read as
        # coverage. Same rule as count_guard_lint.py's empty-scope failure.
        print(
            f"python-floor lint: found NO python source under {SCAN_ROOTS} -- "
            "the scan is broken, not the tree",
            file=sys.stderr,
        )
        return 1

    for path in sources:
        rel = path.relative_to(ROOT).as_posix()
        src = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(src, filename=rel, feature_version=floor)
        except SyntaxError as e:
            findings.append(
                f"  {rel}:{e.lineno}: does not parse on python "
                f"{floor[0]}.{floor[1]}: {e.msg}"
            )
            continue
        for name, lineno in imported_top_level(tree):
            added = POST_FLOOR_STDLIB.get(name)
            if added is not None and added > floor:
                findings.append(
                    f"  {rel}:{lineno}: imports {name!r}, which is stdlib only "
                    f"from python {added[0]}.{added[1]} -- the floor is "
                    f"{floor[0]}.{floor[1]}"
                )

    print(
        f"python-floor lint: {len(sources)} script(s) scanned against python "
        f"{floor[0]}.{floor[1]} (min of {len(images)} runner image(s)), "
        f"{len(findings)} finding(s)"
    )
    if findings:
        print(
            "\nLayer C0 FAIL: a script the CI lanes execute cannot run on the "
            "oldest python\nany runner provides. This fails HOSTED, in a step "
            "whose failure hides every step\nbehind it, and it stays green on a "
            "newer workstation -- which is where the round\nthat writes it "
            "verifies (R311y605 shipped exactly that, and Layer C0's death took "
            "29\nsteps with it).\n\nFix: use a construct the floor has, or ask a "
            "tool that already knows the answer\n(`cargo metadata` for "
            "manifests, `json` for anything cargo emits).\n",
            file=sys.stderr,
        )
        for finding in findings:
            print(finding, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
