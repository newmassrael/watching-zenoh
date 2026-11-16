#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y736 (N30, N31, N32) -- the exact reap: keep what cargo declared, by UNIT.

`scripts/sweep-target.sh reap` takes this path when a gate run left an artefact
log (`WZ_ARTIFACT_LOG`, written through `artifact_filenames.py`). The log names
FILES; what cargo builds and reuses is a UNIT, and a unit is more than the files
it declares. This module turns the declared files into the set of units they
belong to and keeps every file and directory of those units.

## A unit is its hash

Every per-unit name cargo writes in a profile directory ends in the unit's
16-hex hash: `deps/libfoo-<h>.rlib`, `deps/libfoo-<h>.rmeta`, `deps/foo-<h>.d`,
`build/<pkg>-<h>/` and `.fingerprint/<pkg>-<h>/`. Measured on a cargo target
of this machine: the fingerprint directory of a library carries the same hash
as its rlib, and a build script's compile and run units each have a build
directory and a fingerprint directory of one hash. So the keep-set is a set of
hashes, read from the declared paths, and a file or directory is kept when its
hash is in it.

Three places a declared path does not show its unit's hash directly, each
answered rather than assumed:

* An UPLIFTED output (`<profile>/foo`, `<profile>/libfoo.rlib`) is what cargo
  declares for a root unit, and it is a hard link of `deps/foo-<h>`. Matching
  the declared files' inodes against `deps/` recovers `<h>`. Where the link
  was a copy instead (a file system without hard links), the unit is not
  recovered, is reaped, and is rebuilt: the cost of that miss is a build.
* A build script's RUN is declared only by its `out_dir`, which
  `artifact_filenames.py` reads from the `build-script-executed` message.
* A name with no hash (`deps/libfoo.so` of a cdylib) is never reaped: this
  cannot say which unit owns it.

## What is reaped

In every profile directory under the target (`debug`, `release`,
`<triple>/<profile>`, recognised by holding both `deps/` and `.fingerprint/`):
the files of `deps/`, the directories of `build/` and the directories of
`.fingerprint/` whose hash is not kept. Every lookup is a set lookup, so the
cost is linear in the files plus the declared paths, not their product.

## Refusals

* a log that names nothing under the target: an exact reap from it would
  condemn the whole tree;
* a reap larger than the share of the tree the caller allows: an artefact log
  that covers only part of a gate condemns everything the rest of it built.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

import artifact_filenames

#: A per-unit name: `<stem>-<16 hex>` with an optional extension.
HASH_RE = re.compile(r"-([0-9a-f]{16})(?:\.|$)")
#: The directories of a profile whose entries are named per unit.
UNIT_DIRS = ("deps", "build", ".fingerprint", "examples")


def unit_hash(name: str) -> str | None:
    m = HASH_RE.search(name)
    return m.group(1) if m else None


def _rel_parts(targets: tuple[Path, ...], path: str) -> tuple[str, ...] | None:
    """The components of `path` below the target, or None when it is elsewhere.
    `targets` holds the target as given and as resolved: the checkout's target
    may be a link to a cache, and cargo names it the way it reached it."""
    for target in targets:
        try:
            return Path(path).relative_to(target).parts
        except ValueError:
            continue
    return None


def declared_hash(rel: tuple[str, ...]) -> str | None:
    """The unit hash a path below the target shows, read from the entry that
    sits directly in a per-unit directory."""
    for i in range(1, len(rel)):
        if rel[i - 1] in UNIT_DIRS:
            h = unit_hash(rel[i])
            if h:
                return h
    return None


def profile_dirs(target: Path) -> list[Path]:
    """Every directory up to two levels below `target` that holds both
    `deps/` and `.fingerprint/`: what cargo makes a profile directory of."""
    found: list[Path] = []
    level = [target]
    for _ in range(2):
        nxt: list[Path] = []
        for d in level:
            try:
                entries = list(os.scandir(d))
            except OSError:
                continue
            for e in entries:
                if not e.is_dir(follow_symlinks=False):
                    continue
                p = Path(e.path)
                if (p / "deps").is_dir() and (p / ".fingerprint").is_dir():
                    found.append(p)
                else:
                    nxt.append(p)
        level = nxt
    return sorted(found)


def _size(path: Path) -> int:
    """Apparent bytes of a file, or of everything under a directory."""
    try:
        if not path.is_dir() or path.is_symlink():
            return path.lstat().st_size
    except OSError:
        return 0
    total = 0
    for base, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(base, f)).st_size
            except OSError:
                pass
    return total


class Refusal(Exception):
    """A reap this module will not plan, with the reason to print."""


def plan(target: Path, declared: set[str]) -> list[Path]:
    """The files and directories of `target` that belong to no declared unit."""
    keep: set[str] = set()
    inodes: set[tuple[int, int]] = set()
    under = 0
    targets = (target, target.resolve())
    for path in declared:
        rel = _rel_parts(targets, path)
        if rel is None:
            continue
        under += 1
        h = declared_hash(rel)
        if h:
            keep.add(h)
        try:
            st = os.stat(path)
        except OSError:
            continue
        inodes.add((st.st_dev, st.st_ino))
    if not under:
        raise Refusal(
            f"the artefact log names nothing under {target}, so an exact reap would "
            "delete every unit there. Collect with WZ_ARTIFACT_LOG during a FULL gate."
        )

    profiles = profile_dirs(target)
    for prof in profiles:
        for e in os.scandir(prof / "deps"):
            if e.is_file(follow_symlinks=False):
                st = e.stat(follow_symlinks=False)
                if (st.st_dev, st.st_ino) in inodes:
                    h = unit_hash(e.name)
                    if h:
                        keep.add(h)

    doomed: list[Path] = []
    for prof in profiles:
        for sub, want_dir in (("deps", False), ("build", True), (".fingerprint", True)):
            d = prof / sub
            if not d.is_dir():
                continue
            for e in os.scandir(d):
                if e.is_dir(follow_symlinks=False) != want_dir:
                    continue
                h = unit_hash(e.name)
                if h is not None and h not in keep:
                    doomed.append(Path(e.path))
    return sorted(doomed)


def _human(kb: int) -> str:
    size = float(kb)
    for unit in ("KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}GiB"


def reap(
    target: Path,
    log: Path,
    tree_kb: int,
    max_share: int,
    apply: bool,
    out=sys.stdout,
) -> int:
    try:
        with log.open(encoding="utf-8", errors="replace") as fh:
            declared = {line.strip() for line in fh if line.strip()}
    except OSError as exc:
        print(f"sweep-target: FAIL — cannot read the artefact log {log}: {exc}", file=out)
        return 1
    try:
        doomed = plan(target, declared)
    except Refusal as why:
        print(f"sweep-target: FAIL — {why}", file=out)
        return 1
    kb = sum(_size(p) for p in doomed) // 1024
    share = kb * 100 // tree_kb if tree_kb > 0 else 100
    print(
        f"  exact mode: {len(declared)} declared path(s); would remove {len(doomed)} "
        f"unit file(s) or director(ies), {_human(kb)} — {share}% of the tree",
        file=out,
    )
    if share > max_share:
        print(
            f"sweep-target: REFUSING — {share}% is over the {max_share}% limit. An artefact "
            "log that covers only part of the gate condemns everything the rest of it "
            "built. Collect with WZ_ARTIFACT_LOG across a FULL run-ci run.",
            file=out,
        )
        return 1
    if not apply:
        print("  (dry run; pass --apply to remove)", file=out)
        return 0
    for p in doomed:
        if p.is_dir() and not p.is_symlink():
            shutil.rmtree(p, ignore_errors=True)
        else:
            try:
                p.unlink()
            except FileNotFoundError:
                pass
    print(f"sweep-target: exact reap removed {len(doomed)} entr(ies), {_human(kb)}", file=out)
    return 0


def selftest() -> int:
    failures = 0

    def expect(ok: bool, what: str) -> None:
        nonlocal failures
        if not ok:
            failures += 1
            print(f"artifact-reap selftest FAIL: {what}")

    a, b, c, d, e, f, x = (ch * 16 for ch in "abcdef1")

    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "t"
        dbg = target / "debug"
        cross = target / "thumbv7em-none-eabihf" / "debug"

        def touch(p: Path, size: int = 1024) -> Path:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"x" * size)
            return p

        def build_tree() -> None:
            if target.exists():
                shutil.rmtree(target)
            touch(dbg / "deps" / f"libkeep-{a}.rlib")
            touch(dbg / "deps" / f"libkeep-{a}.rmeta")
            touch(dbg / "deps" / f"libgone-{b}.rlib", 64 * 1024)
            touch(dbg / "deps" / f"binx-{c}")
            touch(dbg / "deps" / f"binx-{c}.d")
            touch(dbg / "deps" / "libnohash.so")
            os.link(dbg / "deps" / f"binx-{c}", dbg / "binx")
            touch(dbg / "build" / f"keep-{d}" / "build-script-build")
            touch(dbg / "build" / f"keep-{e}" / "out" / "gen.rs")
            touch(dbg / "build" / f"gone-{f}" / "out" / "gen.rs")
            for h, name in ((a, "keep"), (c, "binx"), (d, "keep"), (e, "keep")):
                touch(dbg / ".fingerprint" / f"{name}-{h}" / "lib-keep")
            touch(dbg / ".fingerprint" / f"gone-{b}" / "lib-gone")
            touch(dbg / ".fingerprint" / f"gone-{f}" / "run-build-script")
            touch(cross / "deps" / f"libcross-{x}.rlib")
            touch(cross / ".fingerprint" / f"cross-{x}" / "lib-cross")
            touch(target / "run-ci-logs" / f"lane-{b}.log")

        # The log is written through the collector, as run-ci.sh writes it, so the
        # path from cargo's messages to the reap is graded end to end.
        def artifact(filenames: list[Path], executable: Path | None) -> str:
            return json.dumps(
                {
                    "reason": "compiler-artifact",
                    "filenames": [str(p) for p in filenames],
                    "executable": None if executable is None else str(executable),
                    "fresh": True,
                }
            )

        messages = [
            artifact([dbg / "deps" / f"libkeep-{a}.rlib"], None),
            artifact([dbg / "binx"], dbg / "binx"),
            artifact([dbg / "build" / f"keep-{d}" / "build-script-build"], None),
            json.dumps(
                {
                    "reason": "build-script-executed",
                    "out_dir": str(dbg / "build" / f"keep-{e}" / "out"),
                }
            ),
        ]
        declared, count = artifact_filenames.collect(messages)
        expect(count == 3, f"the collector read {count} artifact message(s), want 3")
        log = Path(tmp) / "artifact.log"
        log.write_text("".join(f"{p}\n" for p in sorted(declared)))

        build_tree()
        want = {
            dbg / "deps" / f"libgone-{b}.rlib",
            dbg / "build" / f"gone-{f}",
            dbg / ".fingerprint" / f"gone-{b}",
            dbg / ".fingerprint" / f"gone-{f}",
            cross / "deps" / f"libcross-{x}.rlib",
            cross / ".fingerprint" / f"cross-{x}",
        }
        got = set(plan(target, declared))
        expect(got == want, f"plan {sorted(map(str, got - want))} extra, "
               f"{sorted(map(str, want - got))} missing")
        expect(
            profile_dirs(target) == sorted([dbg, cross]),
            f"profile directories {profile_dirs(target)}",
        )

        try:
            plan(target, {"/elsewhere/debug/deps/libkeep-0000000000000000.rlib"})
            expect(False, "a log naming nothing under the target was planned")
        except Refusal:
            pass
        try:
            plan(target, set())
            expect(False, "an empty log was planned")
        except Refusal:
            pass

        with open(os.devnull, "w", encoding="utf-8") as sink:
            expect(
                reap(target, log, tree_kb=1, max_share=60, apply=True, out=sink) == 1,
                "a reap over the share limit was not refused",
            )
            expect(all(p.exists() for p in want), "a refused reap removed something")
            expect(
                reap(target, log, tree_kb=10**6, max_share=60, apply=False, out=sink) == 0,
                "a dry run failed",
            )
            expect(all(p.exists() for p in want), "a dry run removed something")
            expect(
                reap(target, Path(tmp) / "absent.log", 10**6, 60, True, out=sink) == 1,
                "an unreadable log was not refused",
            )
            expect(
                reap(target, log, tree_kb=10**6, max_share=60, apply=True, out=sink) == 0,
                "an applied reap failed",
            )
        expect(not any(p.exists() for p in want), "an applied reap left a doomed entry")
        kept = [
            dbg / "deps" / f"libkeep-{a}.rlib",
            dbg / "deps" / f"libkeep-{a}.rmeta",
            dbg / "deps" / f"binx-{c}",
            dbg / "deps" / f"binx-{c}.d",
            dbg / "deps" / "libnohash.so",
            dbg / "binx",
            dbg / "build" / f"keep-{d}",
            dbg / "build" / f"keep-{e}" / "out" / "gen.rs",
            dbg / ".fingerprint" / f"keep-{a}",
            dbg / ".fingerprint" / f"binx-{c}",
            dbg / ".fingerprint" / f"keep-{d}",
            dbg / ".fingerprint" / f"keep-{e}",
            target / "run-ci-logs" / f"lane-{b}.log",
        ]
        expect(all(p.exists() for p in kept), "an applied reap removed a declared unit")

    if failures:
        return 1
    print("artifact-reap selftest: ok")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    ap = argparse.ArgumentParser(description="the exact reap of sweep-target.sh")
    ap.add_argument("--target", required=True, type=Path)
    ap.add_argument("--log", required=True, type=Path)
    ap.add_argument("--tree-kb", required=True, type=int)
    ap.add_argument("--max-share", required=True, type=int)
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args(argv)
    return reap(args.target, args.log, args.tree_kb, args.max_share, args.apply)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
