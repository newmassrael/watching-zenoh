#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y879 (no register item) and R2603 (no register item) are the rounds that measured the two
instances this gate answers for: items 339 and 730 in the UNREGISTERED set, which have no store
`debt-` id. It is the reduced-POINT half of the reduced-feature gate (pre-push gate 6, beside
`reduced-features-gate.sh`, which grades the bare point).

THE CLASS. A `cfg` that is wider or narrower than the items that use what it gates: an import
gated on `transport-link-udp` behind a signature that `transport-link-quic` compiles (R2603: the
build with quic on and udp off died on `SocketAddr`), or a binding whose `mut` outlived the one
consumer that mutated it (R311y879: default features plus `codec-keep-alive` died on
`unused_mut`). Both live in a configuration that is reduced but not empty. The bare build
compiles neither side, the all-features build compiles both, the default build turns the other
side on: three local gates, and the defect lies between them.

THE POINTS. A crate's points are the ones it declares it can hold: its largest sets
(`[package.metadata.wz-docs]`, the sets Layers C1bf and C1bz read; every feature at once when it
declares none), each without one feature it holds. That is `doc_feature_sets.reduced_points`,
the family Layer C1bzr documents, and its docstring says why giving one feature up is the family
that finds the class and turning one on over a bare crate is not: the referrer can be gated on two
features, and only "everything else on" compiles it. The family also never asks a crate for a
configuration it refuses by construction (one feature alone where the crate needs a partner, a
runtime with no memory profile), because the largest sets are the crate's own statement of what
it holds; a reduced point a crate does refuse is recognised by its `compile_error!` guard and
reported as refused, not graded.

THE COST BOUND. A push is graded on the points that give up a feature its changed files NAME: a
`feature = "x"` cfg anywhere in a changed Rust source of the crate, or `x` on a changed line of
the crate's manifest. R2603's import and the signature were in one file, R311y879's binding and
its consumers in one function: a `use` is file-scoped, so the gate of a symbol and the item that
uses it are named in the same file. The points are then capped at `--max` (`WZ_REDUCED_POINTS_MAX`,
default `DEFAULT_MAX`) in a fixed order, and the ones past the cap are PRINTED as deferred, never
read as passed. Cost, measured by the verifying run: not yet measured; the line
`reduced-points cost: <crate> <label> <seconds>` is printed per point so that it can be.

WHAT A FINDING IS. Each point is clippied (`-D warnings`, the targets its largest set declares,
`--all-targets` otherwise) and every error is read with its place. An error in a file the push
changed is graded: it fails unless Layer C1bzr's ledger already carries the same message at the
same file, which is how a known reduced-configuration defect stays the ledger's and not every
later pusher's. An error elsewhere in the crate is outside this push and is counted, not graded.
An error in another crate means the crate under grade was not compiled at that point; the
point is then "not judged", and it fails unless the ledger carries that error too. An error with
no place cannot be attributed and fails.

WHAT THIS DOES NOT REACH, stated: a defect that only two features given up together expose (the
family gives up one); a change in one file that breaks a reduced point in a file the push did not
touch (a symbol whose gate narrows in one module while another module uses it); a deleted source
file, whose features nothing names any more; and the lint-only class (`unused_mut`, `dead_code`)
in the crates a push does not change, which no lane clippies at reduced points.

Usage:
    reduced_points_gate.py plan  --range A..B [--max N] PKG...   the points, nothing built
    reduced_points_gate.py check --range A..B [--max N] PKG...   clippy the points and grade
    reduced_points_gate.py --selftest
Exit: 0 graded clean; 1 a finding, or a point that could not be read; 2 usage, or the workspace,
the diff or a manifest could not be read.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import allfeat_clippy_plan  # noqa: E402
import doc_feature_sets  # noqa: E402
import reduced_docs_gate  # noqa: E402
from no_allocator_link_gate import ZEPHYR_BUILD_VALUES  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
CRATES = REPO / "crates"
CRATES_PREFIX = "crates/"
DEFAULT_MAX = 12
MAX_ENV = "WZ_REDUCED_POINTS_MAX"
# A word as a feature is spelled in a manifest.
MANIFEST_WORD = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]*")

# `(crate, label, given up, cargo arguments)`
Point = tuple[str, str, list[str], list[str]]


class GateError(Exception):
    """The workspace, the diff or a manifest could not be read."""


def git(args: list[str]) -> str:
    out = subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, check=False)
    if out.returncode != 0:
        raise GateError(f"git {' '.join(args)} failed: {out.stderr.strip()}")
    return out.stdout


def workspace_packages() -> dict[str, dict]:
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=CRATES,
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        raise GateError(f"cargo metadata failed: {out.stderr.strip()}")
    packages = {p["name"]: p for p in json.loads(out.stdout)["packages"]}
    if not packages:
        raise GateError("cargo metadata listed no workspace member")
    return packages


def crate_dir(package: dict) -> str:
    """The package's directory relative to `crates/`, with a trailing slash: the prefix cargo's
    short messages give its files, run from `crates/`."""
    manifest = Path(package["manifest_path"]).resolve()
    return manifest.parent.relative_to(CRATES.resolve()).as_posix() + "/"


def all_target_sources(package: dict) -> list[Path]:
    """The Rust sources of every target clippy builds under `--all-targets`, and the build
    script: a feature that only a test names still changes what that point compiles."""
    files: set[Path] = set()
    for target in package["targets"]:
        src = Path(target["src_path"])
        if "custom-build" in target["kind"]:
            files.add(src)
        else:
            files.update(src.parent.rglob("*.rs"))
    return sorted(files)


def manifest_line_features(diff: str, features: dict[str, list[str]]) -> set[str]:
    """The features of the crate a `-U0` manifest diff names on a changed line."""
    named: set[str] = set()
    for line in diff.splitlines():
        if line.startswith(("+++", "---")) or not line.startswith(("+", "-")):
            continue
        named.update(word for word in MANIFEST_WORD.findall(line[1:]) if word in features)
    return named


def touched_features(
    package: dict, changed: list[str], read_text, manifest_diff
) -> set[str]:
    """The features of `package` that the push's changed files name.

    `changed` holds paths relative to `crates/`. A Rust source names the features its cfgs and
    build-script variables spell (`doc_feature_sets.named_features`); the manifest names those
    on its changed lines. A file the push deleted names nothing.
    """
    features: dict[str, list[str]] = package["features"]
    prefix = crate_dir(package)
    texts: list[str] = []
    named: set[str] = set()
    for path in changed:
        if not path.startswith(prefix):
            continue
        if path.endswith(".rs"):
            text = read_text(path)
            if text is not None:
                texts.append(text)
        elif path == prefix + "Cargo.toml":
            named |= manifest_line_features(manifest_diff(path), features)
    return named | doc_feature_sets.named_features(features, texts)


def points_of(package: dict, named: set[str], touched: set[str]) -> list[Point]:
    """The reduced points of `package` that give up a feature in `touched`, with their clippy
    arguments: the targets the largest set declares, then the features."""
    try:
        targets = allfeat_clippy_plan.declared_targets(package)
        reduced = doc_feature_sets.reduced_points(package, named)
    except (doc_feature_sets.ManifestError, allfeat_clippy_plan.PlanError) as error:
        raise GateError(f"{package['name']}: {error}") from error
    selected: list[Point] = []
    for label, set_name, given_up, kept in reduced:
        hit = [g for g in given_up if g in touched]
        if not hit:
            continue
        arguments = targets.get(set_name, [allfeat_clippy_plan.ALL_TARGETS]) + (
            doc_feature_sets.features_argument(kept)
        )
        selected.append((package["name"], label, hit, arguments))
    return selected


def bounded(points: list[Point], limit: int) -> tuple[list[Point], list[Point]]:
    """The points this push grades and the ones it defers, in the fixed order."""
    return points[:limit], points[limit:]


def grade(
    crate_prefix: str,
    found: list[tuple[str, str, str]],
    changed: set[str],
    carried: set[tuple[str, str]],
) -> tuple[list[str], list[str], int]:
    """`(failures, not-judged notes, findings outside the push)` for one point's findings."""
    failures: list[str] = []
    unjudged: list[str] = []
    outside = 0
    for path, position, message in found:
        place = f"{path}:{position}: {message}"
        if path == reduced_docs_gate.NOWHERE:
            failures.append(f"an error with no place, which nothing can attribute: {message}")
        elif not path.startswith(crate_prefix):
            if (path, message) in carried:
                unjudged.append(f"another crate failed first, as C1bzr's ledger carries: {place}")
            else:
                failures.append(f"another crate failed first, and no ledger carries it: {place}")
        elif path not in changed:
            outside += 1
        elif (path, message) not in carried:
            failures.append(place)
    return failures, unjudged, outside


def carried_findings() -> set[tuple[str, str]]:
    """`(file, message)` of every finding Layer C1bzr's ledger carries, whichever crate it was
    documented under: the same error in the same file of the same family of configurations."""
    ledger = reduced_docs_gate.read_ledger(reduced_docs_gate.LEDGER.read_text(encoding="utf-8"))
    return {(path, message) for _, path, message in ledger}


def clippy(crate: str, arguments: list[str]) -> list[tuple[str, str, str]]:
    """The findings of one clippy of `crate`; a failure with none readable is one itself. The
    Zephyr stand-ins are Layer C1bzr's, for the same reason its docstring gives."""
    out = subprocess.run(
        [
            "cargo", "clippy", "-p", crate, "--quiet", "--message-format=short", *arguments,
            "--", "-D", "warnings",
        ],
        cwd=CRATES,
        env={**os.environ, **dict(ZEPHYR_BUILD_VALUES)},
        capture_output=True,
        text=True,
        check=False,
    )
    found = reduced_docs_gate.parse_findings(out.stdout + out.stderr)
    if out.returncode != 0 and not found:
        found.append(
            (
                reduced_docs_gate.NOWHERE,
                reduced_docs_gate.NOWHERE,
                f"error: cargo clippy exited {out.returncode} with no error it could read",
            )
        )
    return reduced_docs_gate.refusals(found, CRATES) or found


def changed_paths(rng: str) -> list[str]:
    """The paths under `crates/` the range changes, relative to `crates/`."""
    return [
        line.strip()[len(CRATES_PREFIX) :]
        for line in git(["diff", "--name-only", rng, "--", CRATES_PREFIX]).splitlines()
        if line.strip().startswith(CRATES_PREFIX)
    ]


def read_worktree(path: str) -> str | None:
    try:
        return (CRATES / path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def select(
    packages: dict[str, dict], rng: str, crates: list[str], limit: int
) -> tuple[list[Point], list[Point], list[str]]:
    """`(graded, deferred, changed paths)` for the crates a push changes."""
    unknown = [c for c in crates if c not in packages]
    if unknown:
        raise GateError(f"not workspace members: {unknown}")
    changed = changed_paths(rng)

    def manifest_diff(path: str) -> str:
        return git(["diff", "-U0", rng, "--", CRATES_PREFIX + path])

    points: list[Point] = []
    for crate in crates:
        package = packages[crate]
        touched = touched_features(package, changed, read_worktree, manifest_diff)
        if not touched:
            print(f"  reduced-points: {crate}: its changed files name no feature")
            continue
        texts = [p.read_text(encoding="utf-8", errors="replace") for p in all_target_sources(package)]
        named = doc_feature_sets.named_features(package["features"], texts)
        mine = points_of(package, named, touched)
        if not mine:
            print(
                f"  reduced-points: {crate}: the features its changed files name "
                f"({', '.join(sorted(touched))}) give up to no point its largest sets do not "
                "already compile"
            )
        points.extend(mine)
    graded, deferred = bounded(points, limit)
    return graded, deferred, changed


def show(point: Point) -> str:
    crate, label, hit, arguments = point
    return f"{crate} {label} (gives up {', '.join(hit)}): {' '.join(arguments)}"


def run(args: argparse.Namespace) -> int:
    try:
        packages = workspace_packages()
        graded, deferred, changed = select(packages, args.range, args.crates, args.max)
        carried = carried_findings() if args.command == "check" else set()
    except (GateError, OSError, ValueError) as error:
        print(f"  reduced-points FAIL: {error}", file=sys.stderr)
        return 2
    for point in deferred:
        print(f"  reduced-points DEFERRED (past --max {args.max}, not graded): {show(point)}")
    if args.command == "plan":
        for point in graded:
            print(show(point))
        return 0

    changed_set = set(changed)
    failed = 0
    for point in graded:
        crate, label, _, arguments = point
        start = time.monotonic()
        found = clippy(crate, arguments)
        print(f"  reduced-points cost: {crate} {label} {time.monotonic() - start:.0f}")
        refused = [m for _, _, m in found if m.startswith(reduced_docs_gate.REFUSED)]
        if refused:
            print(f"  reduced-points: {show(point)} is refused by its crate's guard: {refused[0]}")
            continue
        failures, unjudged, outside = grade(crate_dir(packages[crate]), found, changed_set, carried)
        for note in unjudged:
            print(f"  reduced-points NOT JUDGED: {show(point)}: {note}")
        if outside:
            print(f"  reduced-points: {crate} {label}: {outside} finding(s) outside this push's files")
        for failure in failures:
            print(f"  reduced-points FAIL: {show(point)}\n      {failure}")
        failed += bool(failures)
    if failed:
        print(
            f"  reduced-points: {failed} of {len(graded)} point(s) fail. A finding in a file this "
            "push changed is a cfg wider or narrower than what uses it: fix the cfg."
        )
        return 1
    print(f"  reduced-points: {len(graded)} point(s) clean in the files this push changed")
    return 0


def selftest() -> int:
    # The R2603 shape: udp gates the import, quic the signature, and the manifest is unchanged.
    features = {"default": ["udp"], "udp": [], "quic": [], "unicast": []}
    package = {
        "name": "wz-x",
        "manifest_path": str(CRATES / "wz-x" / "Cargo.toml"),
        "features": features,
        "targets": [],
    }
    source = (
        '#[cfg(feature = "udp")]\nuse std::net::SocketAddr;\n'
        '#[cfg(feature = "quic")]\nfn dial(addr: SocketAddr) {}\n'
    )
    texts = {"wz-x/src/session_open.rs": source}
    no_manifest = lambda _p: ""  # noqa: E731
    touched = touched_features(
        package, ["wz-x/src/session_open.rs", "wz-y/src/lib.rs"], texts.get, no_manifest
    )
    assert touched == {"udp", "quic"}, touched
    named = {"udp", "quic", "unicast"}
    labels = [label for _, label, _, _ in points_of(package, named, touched)]
    # The point that dies is "everything but udp": quic on, the import gone.
    assert "all-without-udp" in labels and "all-without-unicast" not in labels, labels
    without_udp = dict((label, args) for _, label, _, args in points_of(package, named, touched))
    assert without_udp["all-without-udp"] == [
        "--all-targets",
        "--no-default-features",
        "--features=quic,unicast",
    ], without_udp
    # A deleted file names nothing; another crate's file is not this crate's.
    assert touched_features(package, ["wz-x/src/gone.rs"], texts.get, no_manifest) == set()
    assert touched_features(package, ["wz-xy/src/session_open.rs"], {
        "wz-xy/src/session_open.rs": source}.get, no_manifest) == set()

    # A manifest names the features on its changed lines, not the ones it merely holds.
    diff = "--- a/wz-x/Cargo.toml\n+++ b/wz-x/Cargo.toml\n@@ -3 +3 @@\n-quic = []\n+quic = [\"udp\"]\n"
    assert manifest_line_features(diff, features) == {"quic", "udp"}
    touched = touched_features(package, ["wz-x/Cargo.toml"], texts.get, lambda _p: diff)
    assert touched == {"quic", "udp"}, touched

    # A set that declares its targets is clippied with them.
    declared = dict(package)
    declared["features"] = {"alloc": [], "slot": [], "tls": []}
    declared["metadata"] = {
        doc_feature_sets.METADATA_KEY: {
            "feature-sets": [
                {"name": "heap", "except": ["slot"]},
                {"name": "lean", "except": ["alloc"], "clippy-targets": ["--lib"]},
            ]
        }
    }
    args = {label: a for _, label, _, a in points_of(declared, {"alloc", "slot", "tls"}, {"tls"})}
    assert args == {
        "heap-without-tls": ["--all-targets", "--no-default-features", "--features=alloc"],
        "lean-without-tls": ["--lib", "--no-default-features", "--features=slot"],
    }, args

    # The cap keeps the fixed order and hands the rest back, never drops them.
    points = [("c", f"p{i}", ["f"], []) for i in range(5)]
    kept, rest = bounded(points, 3)
    assert [p[1] for p in kept] == ["p0", "p1", "p2"] and [p[1] for p in rest] == ["p3", "p4"]

    # Grading: a changed file's new finding fails, a carried one does not, an untouched file of
    # the crate is outside, another crate's error leaves the point unjudged or failing.
    changed = {"wz-x/src/session_open.rs"}
    carried = {("wz-x/src/session_open.rs", "error: old"), ("wz-y/src/lib.rs", "error[E1]: dep")}
    found = [
        ("wz-x/src/session_open.rs", "4:15", "error[E0425]: cannot find type `SocketAddr`"),
        ("wz-x/src/session_open.rs", "9:1", "error: old"),
        ("wz-x/src/other.rs", "1:1", "error: variable does not need to be mutable"),
    ]
    failures, unjudged, outside = grade("wz-x/", found, changed, carried)
    assert len(failures) == 1 and "SocketAddr" in failures[0] and not unjudged and outside == 1
    failures, unjudged, _ = grade("wz-x/", [("wz-y/src/lib.rs", "1:1", "error[E1]: dep")], changed, carried)
    assert not failures and len(unjudged) == 1
    failures, unjudged, _ = grade("wz-x/", [("wz-y/src/lib.rs", "1:1", "error[E2]: new")], changed, carried)
    assert len(failures) == 1 and not unjudged
    nowhere = reduced_docs_gate.NOWHERE
    failures, _, _ = grade("wz-x/", [(nowhere, nowhere, "error: exited 101")], changed, carried)
    assert len(failures) == 1
    # A crate whose name extends another's is not inside it.
    failures, unjudged, _ = grade("wz-x/", [("wz-xy/src/a.rs", "1:1", "error: e")], changed, carried)
    assert len(failures) == 1 and "another crate" in failures[0]

    # A short clippy line is read by C1bzr's parser, and a guard is a refusal.
    lines = "wz-x/src/a.rs:3:9: error: variable does not need to be mutable\n" \
        "error: could not compile `wz-x` (lib) due to 1 previous error\n"
    assert reduced_docs_gate.parse_findings(lines) == [
        ("wz-x/src/a.rs", "3:9", "error: variable does not need to be mutable")
    ]
    with tempfile.TemporaryDirectory() as scratch:
        src = Path(scratch) / "wz-x" / "src"
        src.mkdir(parents=True)
        (src / "lib.rs").write_text('compile_error!("wz-x: needs a partner");\n')
        refused = reduced_docs_gate.refusals(
            [("wz-x/src/lib.rs", "1:1", "error: wz-x: needs a partner")], Path(scratch)
        )
        assert refused and refused[0][2].startswith(reduced_docs_gate.REFUSED), refused

    print("reduced-points selftest: OK")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    parser = argparse.ArgumentParser(prog="reduced_points_gate.py")
    parser.add_argument("command", choices=["plan", "check"])
    parser.add_argument("--range", required=True)
    parser.add_argument("--max", type=int, default=None)
    parser.add_argument("crates", nargs="+")
    args = parser.parse_args(argv)
    if args.max is None:
        raw = os.environ.get(MAX_ENV, str(DEFAULT_MAX))
        if not raw.isdigit() or int(raw) < 1:
            print(f"  reduced-points FAIL: {MAX_ENV}={raw!r} is not a positive count", file=sys.stderr)
            return 2
        args.max = int(raw)
    elif args.max < 1:
        print(f"  reduced-points FAIL: --max {args.max} is not a positive count", file=sys.stderr)
        return 2
    return run(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
