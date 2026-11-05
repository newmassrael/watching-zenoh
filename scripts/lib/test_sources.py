#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4296 (no register item) -- the test source files of a crate, wherever the crate keeps them.

A crate's integration tests are `tests/<name>.rs`, one executable each, or, once
`scripts/lib/merge_tests.py` has merged them, `tests/<target>/files/<name>.rs`, modules of one
executable (`tests/<target>/main.rs` is its root and `tests/<target>/files/mod.rs` the list of its
modules, neither a test file). The gates that read the sources of the tests (what a file spawns,
what it claims, which reason it carries) walked `tests/*.rs`; walking only that would see a merged
crate as an empty one, and a gate that finds no file reports green about nothing. They ask this
module instead, so they read the same files in either layout and a file is the same file after the
move: it keeps its stem, which is its name in `--test <name>` and in every table the gates keep.

    files(tests_dir)           every test source, sorted by stem (then path)
    locate(tests_dir, stem)    the path of the file called `stem`, or None
    resolve(root, rel)         the file a table names by `crates/<c>/tests/<name>.rs`, either layout
    require(tests_dir, what)   `files`, refusing an empty population
    test_sources.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path


def files(tests_dir: Path) -> list[Path]:
    """The test sources under `tests_dir`: its own `*.rs` and the `files/*.rs` of each merged
    target (a directory with a `main.rs` and a `files/` folder), without the root and the list."""
    found: list[Path] = []
    if not tests_dir.is_dir():
        return found
    for path in tests_dir.glob("*.rs"):
        found.append(path)
    for target in tests_dir.iterdir():
        merged = target / "files"
        if target.is_dir() and (target / "main.rs").is_file() and merged.is_dir():
            found.extend(p for p in merged.glob("*.rs") if p.name != "mod.rs")
    return sorted(found, key=lambda p: (p.stem, str(p)))


def workspace_files(root: Path) -> list[Path]:
    """The test sources of every crate under `root/crates` (a crate is a folder holding `tests/`)."""
    found: list[Path] = []
    crates = root / "crates"
    if crates.is_dir():
        for crate in sorted(crates.iterdir()):
            found.extend(files(crate / "tests"))
    return sorted(found, key=lambda p: (str(p.parent.parent), p.stem, str(p)))


_MERGED = re.compile(r"^(crates/[^/]+/tests)/[^/]+/files/([^/]+\.rs)$")


def canonical(rel_posix: str) -> str:
    """The path a test file had as `tests/<name>.rs`, for a path in either layout: a table that
    keys a file by path (a baseline, an allowlist) keeps its key when the file is merged."""
    m = _MERGED.match(rel_posix)
    return f"{m.group(1)}/{m.group(2)}" if m else rel_posix


def under(root: Path, tests_glob: str) -> list[Path]:
    """The test sources of every folder `root.glob(tests_glob)` names, such as
    `crates/**/tests`: each such folder read as `files` reads one."""
    found: list[Path] = []
    for tests_dir in sorted(root.glob(tests_glob)):
        if tests_dir.is_dir():
            found.extend(files(tests_dir))
    return sorted(found, key=lambda p: (str(p.parent.parent), p.stem, str(p)))


def tracked_pathspecs(crate: str = "*") -> list[str]:
    """The `git ls-files` pathspecs that list the test sources of `crate` in either layout."""
    return [f"crates/{crate}/tests/*.rs", f"crates/{crate}/tests/*/files/*.rs"]


_PLAIN = re.compile(r"^(crates/[^/]+/tests)/([^/]+)\.rs$")


def resolve(root: Path, rel_posix: str) -> Path | None:
    """The file a table names by the path `rel_posix` (relative to `root`), in either layout: the
    path itself when it is a file, and for a `crates/<c>/tests/<name>.rs` that has been merged the
    module `tests/<target>/files/<name>.rs`. A table that cites a test file keeps its citation."""
    direct = root / rel_posix
    if direct.is_file():
        return direct
    m = _PLAIN.match(rel_posix)
    return locate(root / m.group(1), m.group(2)) if m else None


def locate(tests_dir: Path, stem: str) -> Path | None:
    """The path of the test file called `stem`, in whichever layout the crate is in."""
    direct = tests_dir / f"{stem}.rs"
    if direct.is_file():
        return direct
    for path in files(tests_dir):
        if path.stem == stem:
            return path
    return None


def require(tests_dir: Path, what: str = "the test sources") -> list[Path]:
    """`files(tests_dir)`, or an exit with a refusal when there are none: a population of zero is
    a failure, not a pass."""
    found = files(tests_dir)
    if not found:
        raise SystemExit(f"{what}: {tests_dir} holds no test source (not even a merged target)")
    return found


def selftest() -> int:
    failures = 0

    def check(label: str, ok: bool) -> None:
        nonlocal failures
        if not ok:
            failures += 1
            print(f"test_sources selftest FAIL: {label}")

    with tempfile.TemporaryDirectory() as tmp:
        tests = Path(tmp) / "tests"
        (tests / "it" / "files").mkdir(parents=True)
        (tests / "other").mkdir()
        (tests / "plain.rs").write_text("")
        (tests / "it" / "main.rs").write_text("mod files;\n")
        (tests / "it" / "files" / "mod.rs").write_text("mod b;\n")
        (tests / "it" / "files" / "b.rs").write_text("")
        (tests / "it" / "files" / "a.rs").write_text("")
        (tests / "other" / "stray.rs").write_text("")
        got = [p.stem for p in files(tests)]
        check("both layouts, sorted by stem", got == ["a", "b", "plain"])
        check("a root and a list are not tests", "main" not in got and "mod" not in got)
        check("a folder that is not a merged target is not read", "stray" not in got)
        check("locate finds a merged file", locate(tests, "b") == tests / "it" / "files" / "b.rs")
        check("locate finds a plain file", locate(tests, "plain") == tests / "plain.rs")
        check("locate says none", locate(tests, "nope") is None)
        root = Path(tmp) / "root"
        (root / "crates" / "c" / "tests" / "it" / "files").mkdir(parents=True)
        (root / "crates" / "c" / "tests" / "it" / "main.rs").write_text("")
        (root / "crates" / "c" / "tests" / "it" / "files" / "m.rs").write_text("")
        (root / "crates" / "c" / "tests" / "p.rs").write_text("")
        check("resolve reads a merged file by its old path",
              resolve(root, "crates/c/tests/m.rs") == root / "crates/c/tests/it/files/m.rs")
        check("resolve reads a plain file", resolve(root, "crates/c/tests/p.rs") == root / "crates/c/tests/p.rs")
        check("resolve says none for a missing file and for another kind of path",
              resolve(root, "crates/c/tests/zz.rs") is None and resolve(root, "crates/c/src/x.rs") is None)
        check("a missing directory is empty", files(Path(tmp) / "absent") == [])
        check("a merged path keeps its old key",
              canonical("crates/c/tests/it/files/a.rs") == "crates/c/tests/a.rs"
              and canonical("crates/c/tests/it_x/files/a.rs") == "crates/c/tests/a.rs")
        check("a plain path is its own key",
              canonical("crates/c/tests/a.rs") == "crates/c/tests/a.rs"
              and canonical("crates/c/src/a.rs") == "crates/c/src/a.rs")
        try:
            require(Path(tmp) / "absent")
            check("an empty population is refused", False)
        except SystemExit:
            pass
    if failures == 0:
        print("test_sources: selftest OK")
    return 1 if failures else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    print(__doc__)
    sys.exit(2)
