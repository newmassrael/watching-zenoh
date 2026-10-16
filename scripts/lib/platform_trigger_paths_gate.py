#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3355 (no register item) -- THE PLATFORM LANE MUST RUN WHEN A CRATE IT BUILDS CHANGES.

## The defect

`.github/workflows/platform.yml` runs on a push to main only when a file under
its `on.push.paths` list changes. The list was written by hand, as the crates the
lane is ABOUT. The lane also builds everything those crates depend on, and a
change there reached no Windows or macOS runner. Measured: a repair to the port
picker the lane's own test depends on (`wz-runtime-tokio-test-support`) was
pushed, the Platform workflow never started for it, and the Windows red it
repaired could not be re-graded by the push that repaired it. A walk of the real
dependency trees found 19 workspace packages the lane compiles that no listed
path covered: 16 crates under `crates/`, among them `wz-codecs`, `wz-runtime-core`,
`wz-routing-graph`, `wz-capture` and the facade `wz`, and the three sce runtime
crates under `vendor/sce`.

## What this holds

The population is DERIVED, not listed here: the lane's own crates are the
`crates/<dir>/**` entries of the workflow's path list, and the set that must be
covered is every workspace package in their normal, build and dev dependency
trees (`cargo tree -e normal,build,dev`, the same trees `cargo test -p` resolves).
A required directory with no covering path is a finding naming the crate and the
line to add. A submodule carrying a crate is covered by its root (`vendor/sce`).
A population of zero lane crates, or a tree walk that fails, is a FAILURE: that is
the gate having stopped reading, not the lane having nothing to run on.

## What this does NOT claim

That the lane's feature set pulls every optional dependency (it does not: this is
the default-feature tree, which is what the lane builds under `cargo test -p`, so
an optional crate only a feature reaches is out of this reading and says nothing
about the lane), nor that a path listed here is run on the right host. A path
under `crates/` that is not a dependency of a lane crate is allowed to be listed:
over-triggering costs a hosted run, under-triggering costs a red nobody re-graded.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ".github/workflows/platform.yml"

# The path list under `on: push: paths:`; a quoted entry per line.
PATH_ENTRY = re.compile(r'^\s*-\s*"([^"]+)"\s*$')


def push_paths(text: str) -> list[str]:
    """The entries of `on.push.paths`, read as text: this gate runs where no YAML
    reader is installed, so the block is cut by indentation."""
    lines = text.splitlines()
    out: list[str] = []
    in_push = in_paths = False
    paths_indent = -1
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if re.match(r"^on:\s*$", line):
            in_push = False
            continue
        if stripped == "push:":
            in_push, in_paths = True, False
            continue
        if in_push and stripped == "paths:":
            in_paths, paths_indent = True, indent
            continue
        if in_paths:
            if indent <= paths_indent:
                break
            m = PATH_ENTRY.match(line)
            if m:
                out.append(m.group(1))
    return out


def covers(entries: list[str], directory: str) -> bool:
    """Whether some path entry makes a change under `directory` trigger the lane."""
    for entry in entries:
        base = entry[:-3] if entry.endswith("/**") else entry
        if directory == base or directory.startswith(base + "/"):
            return True
    return False


def lane_crate_dirs(entries: list[str]) -> list[str]:
    """`crates/<dir>` for every `crates/<dir>/**` entry: the crates the lane is about."""
    return sorted({e[: -len("/**")] for e in entries
                   if re.fullmatch(r"crates/[^/*]+/\*\*", e)})


def required_dirs(root: Path, lane_dirs: list[str]) -> tuple[dict[str, str], list[str]]:
    """Directory -> package name for every workspace package in the lane crates' trees,
    plus the errors met while reading them."""
    errors: list[str] = []
    meta = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps",
         "--manifest-path", str(root / "crates" / "Cargo.toml")],
        capture_output=True, text=True)
    if meta.returncode != 0:
        return {}, [f"cargo metadata failed: {meta.stderr.strip()[:300]}"]
    name_of_dir: dict[str, str] = {}
    for pkg in json.loads(meta.stdout)["packages"]:
        manifest = Path(pkg["manifest_path"])
        try:
            name_of_dir[manifest.parent.relative_to(root).as_posix()] = pkg["name"]
        except ValueError:
            continue
    found: dict[str, str] = {}
    for directory in lane_dirs:
        name = name_of_dir.get(directory)
        if name is None:
            errors.append(f"{directory}: no workspace package lives there")
            continue
        run = subprocess.run(
            ["cargo", "tree", "--manifest-path", str(root / "crates" / "Cargo.toml"),
             "-p", name, "-e", "normal,build,dev", "--prefix", "none", "--color", "never"],
            capture_output=True, text=True)
        if run.returncode != 0:
            errors.append(f"cargo tree -p {name} failed: {run.stderr.strip()[:300]}")
            continue
        for line in run.stdout.splitlines():
            m = re.match(r"^(\S+) v\S+ \((" + re.escape(str(root)) + r"/[^)]*)\)", line.strip())
            if m:
                found[Path(m.group(2)).relative_to(root).as_posix()] = m.group(1)
    return found, errors


def findings(entries: list[str], required: dict[str, str]) -> list[str]:
    out = []
    for directory, name in sorted(required.items()):
        if not covers(entries, directory):
            root = "vendor/sce" if directory.startswith("vendor/sce/") else f"{directory}/**"
            out.append(f"`{name}` ({directory}) is built by the lane and no `paths:` entry "
                       f"covers it; add `- \"{root}\"`")
    return out


def check() -> int:
    text = (REPO_ROOT / WORKFLOW).read_text(encoding="utf-8")
    entries = push_paths(text)
    lane = lane_crate_dirs(entries)
    if not lane:
        print(f"platform-trigger-paths: FAIL -- no `crates/<dir>/**` entry read from {WORKFLOW}; "
              "the gate lost its subject and must not pass over an empty population",
              file=sys.stderr)
        return 1
    required, errors = required_dirs(REPO_ROOT, lane)
    if errors or not required:
        for e in errors or ["the dependency trees held no workspace package"]:
            print(f"platform-trigger-paths: FAIL -- {e}", file=sys.stderr)
        return 1
    bad = findings(entries, required)
    if bad:
        print("platform-trigger-paths: FAIL -- the Platform workflow would not run for a change "
              "to a crate it builds:", file=sys.stderr)
        for b in bad:
            print(f"  - {b}", file=sys.stderr)
        return 1
    print(f"platform-trigger-paths: ok -- {len(lane)} lane crate(s), {len(required)} workspace "
          f"package(s) in their dependency trees, every one covered by a `paths:` entry")
    return 0


WORKFLOW_SAMPLE = """\
name: Platform
on:
  push:
    branches: [main]
    paths:
      - ".github/workflows/platform.yml"
      - "crates/alpha/**"
      - "crates/beta/**"
      - "vendor/sce"
      - "rust-toolchain.toml"
  workflow_dispatch:
    inputs:
      host:
        description: "Which host to run"
"""


def selftest() -> int:
    failures: list[str] = []

    def expect(name: str, got, want) -> None:
        ok = got == want
        print(f"  selftest -- {name}: {'ok' if ok else f'FAIL got {got!r} want {want!r}'}")
        if not ok:
            failures.append(name)

    entries = push_paths(WORKFLOW_SAMPLE)
    expect("the path list is cut at the end of its block", entries, [
        ".github/workflows/platform.yml", "crates/alpha/**", "crates/beta/**",
        "vendor/sce", "rust-toolchain.toml"])
    expect("workflow_dispatch descriptions are not paths",
           any("Which host" in e for e in entries), False)
    expect("lane crates are the crates/<dir>/** entries",
           lane_crate_dirs(entries), ["crates/alpha", "crates/beta"])
    expect("a listed crate is covered", covers(entries, "crates/alpha"), True)
    expect("a file under a listed crate is covered", covers(entries, "crates/alpha/src"), True)
    expect("a sibling with a longer name is NOT covered by a prefix",
           covers(entries, "crates/alpha-test-support"), False)
    expect("a submodule crate is covered by its root",
           covers(entries, "vendor/sce/backends/rust/runtime"), True)
    expect("an unlisted crate is not covered", covers(entries, "crates/gamma"), False)
    bad = findings(entries, {"crates/alpha": "alpha", "crates/gamma": "gamma",
                             "vendor/other/x": "other"})
    expect("the finding names the crate and the line to add",
           [b for b in bad if "gamma" in b][0].endswith('add `- "crates/gamma/**"`'), True)
    expect("a covered crate is not a finding", any("`alpha`" in b for b in bad), False)
    expect("an uncovered vendor path is a finding", any("`other`" in b for b in bad), True)
    expect("a workflow with no path list reads as empty, which the check refuses",
           lane_crate_dirs(push_paths("name: x\non:\n  push:\n    branches: [main]\n")), [])
    print(f"platform-trigger-paths selftest: {'OK' if not failures else 'FAILED: ' + ', '.join(failures)}")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    return selftest() if args.selftest else check()


if __name__ == "__main__":
    sys.exit(main())
