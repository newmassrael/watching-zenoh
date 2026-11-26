#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4654 (no register item) -- a commit's tree, read from git's objects.

RFC 0001 (`docs/rfc/0001-a-lane-lands-alone-and-a-verdict-is-keyed-by-what-it-read.md`,
section 4.2) keys a lane's verdict by the content of what the lane reads, and that content is the
commit's tree object, never a working directory: a checkout can hold an untracked file the commit
lacks or an edit it does not carry, and a key computed from it would name a tree that does not
exist. The modules of stage M1 (`lane_decl.py`, `lane_graph.py`, `lane_digest.py`,
`lanes_gate.py`, `lane_input_closure.py`) read a tree through this one.

Interface (stable; the modules above and the receipt store of stage M2 call it):

    GitTree(root, rev)         the tree of commit `rev` in the repository at `root`
      .commit, .tree           the commit id and its tree id
      .entries                 {path: Entry(mode, kind, oid)} for every blob ("blob") and every
                               submodule gitlink ("commit") of the tree, recursively
      .read(path)              the blob's bytes, or None for a path that is no blob of the tree
      .text(path)              the same decoded as UTF-8
      .glob(pattern)           the sorted paths `pattern` matches (see `glob_regex`)
    WorkTree(root)             the same reading surface over the checkout: the index's paths, the
                               files' bytes on disk; a gate run in a checkout judges what is there
    glob_regex(pattern)        `**/` any number of whole segments, `**` anything, `*` and `?`
                               inside one segment, every other character itself
    git(root, *args)           git run with the caller's repository-locating variables removed
    Fixture()                  a throwaway repository a selftest commits trees into

`git` drops GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE and the other variables that locate a
repository before it runs anything: a hook exports them, and a selftest that commits into its own
temporary repository from inside a hook would otherwise write into the repository being pushed.

  python3 scripts/lib/git_tree.py --selftest
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple

# The variables git reads to find a repository, an index or an object store. A hook sets several.
_LOCATING = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_PREFIX",
    "GIT_NAMESPACE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
)


class GitError(RuntimeError):
    """A git command failed; the message carries its arguments, directory and stderr."""


def clean_env() -> dict[str, str]:
    """The process environment without the repository-locating variables."""
    return {k: v for k, v in os.environ.items() if k not in _LOCATING}


def git(root: Path, *args: str) -> bytes:
    """`git -C root args...`'s stdout, or GitError naming what failed."""
    done = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, env=clean_env(), check=False
    )
    if done.returncode != 0:
        said = done.stderr.decode("utf-8", "replace").strip()
        raise GitError(f"git {' '.join(args)} in {root} failed (rc={done.returncode}): {said}")
    return done.stdout


class Entry(NamedTuple):
    mode: str
    #: "blob", or "commit" for a submodule gitlink
    kind: str
    oid: str


def glob_regex(pattern: str) -> re.Pattern[str]:
    """The regular expression a declaration glob matches a whole path with."""
    if not pattern or pattern.startswith("/") or "\\" in pattern or "//" in pattern:
        raise ValueError(f"glob {pattern!r}: a pattern is a non-empty path relative to the root")
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:[^/]+/)*")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out))


class _Tree:
    """What GitTree and WorkTree share: the path table and the readers over it."""

    root: Path
    entries: dict[str, Entry]

    def read(self, path: str) -> bytes | None:
        raise NotImplementedError

    def text(self, path: str) -> str | None:
        raw = self.read(path)
        return None if raw is None else raw.decode("utf-8", "replace")

    def glob(self, pattern: str) -> list[str]:
        rx = glob_regex(pattern)
        return sorted(p for p in self.entries if rx.fullmatch(p))

    def under(self, directory: str) -> list[str]:
        """Every path below `directory` ("" is the root), sorted."""
        if not directory:
            return sorted(self.entries)
        prefix = directory.rstrip("/") + "/"
        return sorted(p for p in self.entries if p.startswith(prefix))

    def gitlinks(self) -> dict[str, str]:
        """{path: commit} of every submodule gitlink."""
        return {p: e.oid for p, e in self.entries.items() if e.kind == "commit"}


def _ls(raw: bytes) -> dict[str, Entry]:
    """`ls-tree -r -z` / `ls-files -s -z` records as entries (both print mode, a word, the oid)."""
    out: dict[str, Entry] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        meta, path = record.split(b"\t", 1)
        fields = meta.decode().split()
        mode = fields[0]
        # ls-tree writes `mode type oid`, ls-files -s writes `mode oid stage`.
        oid = fields[2] if fields[1] in ("blob", "commit", "tree") else fields[1]
        kind = "commit" if mode == "160000" else "blob"
        out[path.decode("utf-8", "surrogateescape")] = Entry(mode, kind, oid)
    return out


class GitTree(_Tree):
    """The tree of one commit (see the module docstring)."""

    def __init__(self, root: Path, rev: str) -> None:
        self.root = Path(root)
        self.rev = rev
        self.commit = git(self.root, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}").decode().strip()
        self.tree = git(self.root, "rev-parse", f"{self.commit}^{{tree}}").decode().strip()
        self.entries = _ls(git(self.root, "ls-tree", "-r", "-z", "--full-tree", self.commit))
        self._blobs: dict[str, bytes] = {}

    def read(self, path: str) -> bytes | None:
        entry = self.entries.get(path)
        if entry is None or entry.kind != "blob":
            return None
        if entry.oid not in self._blobs:
            self._blobs[entry.oid] = git(self.root, "cat-file", "blob", entry.oid)
        return self._blobs[entry.oid]


class WorkTree(_Tree):
    """The checkout: the index's paths and oids, and each file's bytes as they are on disk."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.entries = _ls(git(self.root, "ls-files", "-s", "-z"))

    def read(self, path: str) -> bytes | None:
        entry = self.entries.get(path)
        if entry is None or entry.kind != "blob":
            return None
        try:
            return (self.root / path).read_bytes()
        except OSError:
            return None


class Fixture:
    """A repository in a temporary directory. `commit(files, gitlinks)` makes the next commit: a
    file or gitlink given None is removed, any other is written; the commit id is returned."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="wz-git-tree-")
        self.root = Path(self._tmp.name)
        git(self.root, "init", "-q")

    def commit(self, files: dict[str, str | None], gitlinks: dict[str, str | None] | None = None) -> str:
        for path, text in files.items():
            target = self.root / path
            if text is None:
                git(self.root, "rm", "-q", "--cached", "--", path)
                target.unlink()
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            git(self.root, "add", "--", path)
        for path, oid in (gitlinks or {}).items():
            if oid is None:
                git(self.root, "update-index", "--force-remove", "--", path)
            else:
                git(self.root, "update-index", "--add", "--cacheinfo", f"160000,{oid},{path}")
        git(
            self.root,
            "-c", "user.name=fixture",
            "-c", "user.email=fixture@invalid",
            "-c", "commit.gpgsign=false",
            "-c", "core.hooksPath=/dev/null",
            "commit", "-q", "--allow-empty", "-m", "fixture",
        )
        return git(self.root, "rev-parse", "HEAD").decode().strip()

    def close(self) -> None:
        self._tmp.cleanup()

    def __enter__(self) -> "Fixture":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def selftest() -> int:
    cases = 0

    def expect(name: str, ok: bool, detail: object = "") -> None:
        nonlocal cases
        if not ok:
            raise AssertionError(f"git_tree selftest: {name} FAILED {detail}")
        cases += 1

    rx = glob_regex("docs/**/x?.md")
    # Red if `**/` stops matching zero segments or `?` crosses a slash.
    expect("**/ matches zero and several segments", bool(rx.fullmatch("docs/x1.md")) and bool(rx.fullmatch("docs/a/b/x2.md")))
    expect("? stays in one segment", not rx.fullmatch("docs/x/.md"))
    # Red if `*` is translated to `.*`.
    expect("* stays in one segment", not glob_regex("crates/*.toml").fullmatch("crates/a/b.toml"))
    for bad in ("", "/abs", "a//b"):
        try:
            glob_regex(bad)
        except ValueError:
            cases += 1
        else:
            raise AssertionError(f"git_tree selftest: glob {bad!r} was accepted")
    # A hook's GIT_DIR must not reach the fixture's git (red if `clean_env` keeps it).
    saved = os.environ.get("GIT_DIR")
    os.environ["GIT_DIR"] = "/nonexistent/wz-git-tree-selftest"
    try:
        with Fixture() as fx:
            first = fx.commit({"a/one.txt": "1\n", "b.txt": "b\n"}, {"vendor/sub": "1" * 40})
            second = fx.commit({"a/one.txt": "2\n", "b.txt": None})
            t1, t2 = GitTree(fx.root, first), GitTree(fx.root, second)
            expect("a commit's blobs are read from the object store", t1.text("a/one.txt") == "1\n", t1.text("a/one.txt"))
            expect("an earlier commit is read after a later one", t2.text("a/one.txt") == "2\n" and t1.text("a/one.txt") == "1\n")
            expect("a removed file is no entry", "b.txt" in t1.entries and "b.txt" not in t2.entries)
            expect("a gitlink is an entry of kind commit", t1.entries["vendor/sub"] == Entry("160000", "commit", "1" * 40), t1.entries.get("vendor/sub"))
            expect("a gitlink has no blob to read", t1.read("vendor/sub") is None)
            expect("glob reads the table", t1.glob("a/**") == ["a/one.txt"], t1.glob("a/**"))
            (fx.root / "a" / "one.txt").write_text("dirty\n", encoding="utf-8")
            wt = WorkTree(fx.root)
            # Red if WorkTree reads the index's blob instead of the file on disk.
            expect("the work tree reads the file on disk", wt.text("a/one.txt") == "dirty\n", wt.text("a/one.txt"))
            expect("the work tree keeps the index's gitlink", wt.gitlinks() == {"vendor/sub": "1" * 40}, wt.gitlinks())
    finally:
        if saved is None:
            os.environ.pop("GIT_DIR", None)
        else:
            os.environ["GIT_DIR"] = saved
    print(f"git_tree selftest: {cases} cases pass")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    print("usage: git_tree.py --selftest", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
