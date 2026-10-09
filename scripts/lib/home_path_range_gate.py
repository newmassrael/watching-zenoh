#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3190 (no register item) -- A HOME PATH IN A COMMIT IS PUBLISHED EVEN WHEN THE TIP IS CLEAN.

The citation says `no register item` because open-debt item 791 lives in the
operator's agent-memory register, which has no store `debt-` id for
`gate_provenance_lint` to resolve; the honest pair is this sentence and the
citation above.

## The defect (item 791, measured at R2729)

Pre-push gate 0b (`wz_home_path_scan`) reads `git ls-files`: the CHECKOUT, which
is the tip. A push sends every commit between the remote's tip and the local
one, and each of them carries its own blobs. So a commit that adds a line naming
the pusher's home directory and a later commit that removes it leave the tip
clean, the gate green, and the leaking blob on a public origin. R2729 met the
store-shaped form of it: a frozen ledger entry spelled the home directory, a
correcting commit on top made the tip pass, and 17 commits' blobs were still
about to be sent. A gate that is green about the tip says nothing about the
history it is about to publish, and the green is the harm: it reassures.

## What this measures

For every commit in the pushed range, and for every file that commit changes
relative to a parent, the number of LINES naming the term in the commit's blob
against the same count in the parent's blob. A commit whose count is HIGHER than
every parent's ADDED a home-path line, which is the thing that cannot be
un-published. The delta is the right measure for the same reason
`wz_home_path_pending` uses it at commit time: the append-only ledger already
carries 137 such lines inside published history, so an absolute per-commit count
would refuse every push this repository will ever make, while an INCREASE is
exactly what is still preventable. It also makes the range's base the ceiling,
which is what the register asked for, without a second constant that could drift
from gate 0b's.

* A merge is graded against EACH parent and flagged only when it raised the
  count over all of them: a clean merge that carries a side branch's blob is not
  that merge's own addition (the side branch's commits are in the range, or in
  the base, and are graded as themselves).
* A root commit is graded against the empty tree.
* A gitlink (submodule) entry has no blob and is skipped.
* The count is of LINES containing the term, the unit `grep -c` and gate 0b use.

## What it will not do

It does not grade a range with no base. A first push of a ref has the whole
history as its range, and that history legitimately includes the commits that
brought the ledger's 137 lines in; per-commit deltas over it would refuse a
history nobody is publishing now. The hook says so out loud when it has no base,
as gate 0 does, rather than printing a green for work not done.

It does not rewrite anything. The remedy for a finding is the one item 792 took
at R2730: rewrite the unpushed commits so none of them adds the line, then push.
That is the owner's call when the commits are the ledger's.

Usage:
    python3 scripts/lib/home_path_range_gate.py --term <home> --range <base>..<tip>
    python3 scripts/lib/home_path_range_gate.py --selftest
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple

GITLINK_MODE = "160000"


class Finding(NamedTuple):
    commit: str
    path: str
    before: int
    after: int


def git(repo: Path, *args: str) -> bytes:
    """`git <args>` in `repo`, raising on a non-zero exit (a gate must not read
    a failed listing as an empty one)."""
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed ({proc.returncode}): "
            f"{proc.stderr.decode(errors='replace').strip()}"
        )
    return proc.stdout


class LineCounter:
    """Lines naming the term in a blob, memoised by object id.

    The memo is what keeps this cheap: commit N's new blob is commit N+1's old
    one, and the ledger store is tens of megabytes, so it is read once per
    version rather than twice per commit.
    """

    def __init__(self, repo: Path, term: bytes) -> None:
        self.repo = repo
        self.term = term
        self.memo: dict[str, int] = {}
        self.blobs_read = 0

    def count(self, oid: str) -> int:
        if set(oid) == {"0"}:
            return 0
        if oid not in self.memo:
            data = git(self.repo, "cat-file", "blob", oid)
            self.blobs_read += 1
            self.memo[oid] = self._lines_naming(data)
        return self.memo[oid]

    def _lines_naming(self, data: bytes) -> int:
        """Distinct lines holding the term, without splitting the whole blob:
        the ledger is tens of megabytes and names the term on ~137 lines, so the
        walk is over the matches and not over every line."""
        lines = 0
        last_start = -1
        pos = data.find(self.term)
        while pos != -1:
            start = data.rfind(b"\n", 0, pos) + 1
            if start != last_start:
                lines += 1
                last_start = start
            end = data.find(b"\n", pos)
            if end == -1:
                break
            pos = data.find(self.term, end)
        return lines


def changed_blobs(repo: Path, parent: str | None, commit: str) -> list[tuple[str, str, str]]:
    """`(path, old_oid, new_oid)` for each blob `commit` changes against `parent`."""
    if parent is None:
        out = git(
            repo, "diff-tree", "-r", "-z", "--root", "--no-renames", "--no-commit-id",
            "--diff-filter=ACMRT", commit,
        )
    else:
        out = git(
            repo, "diff-tree", "-r", "-z", "--no-renames", "--no-commit-id",
            "--diff-filter=ACMRT", parent, commit,
        )
    fields = out.split(b"\0")
    rows: list[tuple[str, str, str]] = []
    i = 0
    while i + 1 < len(fields):
        meta = fields[i].decode()
        path = fields[i + 1].decode(errors="surrogateescape")
        i += 2
        if not meta.startswith(":"):
            continue
        old_mode, new_mode, old_oid, new_oid = meta[1:].split()[:4]
        if GITLINK_MODE in (old_mode, new_mode):
            continue
        rows.append((path, old_oid, new_oid))
    return rows


def grade_range(repo: Path, term: str, rev_range: str) -> tuple[int, int, list[Finding]]:
    """`(commits, blobs_read, findings)` for `rev_range`."""
    counter = LineCounter(repo, term.encode())
    lines = git(repo, "rev-list", "--reverse", "--parents", rev_range).decode().splitlines()
    findings: list[Finding] = []
    for line in lines:
        commit, *parents = line.split()
        # A path is this commit's OWN addition only if the count rose over EVERY
        # parent: the intersection of the per-parent raised sets. A path equal
        # to one parent's blob is absent from that parent's diff and drops out.
        per_parent: list[dict[str, tuple[int, int]]] = []
        for parent in parents or [None]:
            raised_here: dict[str, tuple[int, int]] = {}
            for path, old_oid, new_oid in changed_blobs(repo, parent, commit):
                before, after = counter.count(old_oid), counter.count(new_oid)
                if after > before:
                    raised_here[path] = (before, after)
            per_parent.append(raised_here)
        raised = {
            path: (max(r[path][0] for r in per_parent), per_parent[0][path][1])
            for path in per_parent[0]
            if all(path in r for r in per_parent)
        }
        for path, (before, after) in sorted(raised.items()):
            findings.append(Finding(commit, path, before, after))
    return len(lines), counter.blobs_read, findings


def check(repo: Path, term: str, rev_range: str) -> int:
    if not term or term == "/":
        print("home-path-range FAIL: the term is empty or /, so there is nothing to scan for",
              file=sys.stderr)
        return 1
    try:
        commits, blobs, findings = grade_range(repo, term, rev_range)
    except RuntimeError as exc:
        print(f"home-path-range FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        f"  home-path-range: {commits} commit(s) in {rev_range}, {blobs} blob version(s) "
        f"counted, {len(findings)} added home-path file(s)"
    )
    if not findings:
        return 0
    for f in findings:
        print(f"    {f.commit[:12]} {f.path}: {f.before} -> {f.after} line(s) naming this home",
              file=sys.stderr)
    print(
        "  home-path-range FAIL: a pushed commit ADDS a line naming this home directory.\n"
        "    A later commit that removes it does not help: the blob of this commit is sent\n"
        "    too, origin is public, and a push does not un-publish. Rewrite the unpushed\n"
        "    commits so that none of them carries the line, then push.",
        file=sys.stderr,
    )
    return 1


# --------------------------------------------------------------------------
# selftest: real repositories, real commits -- the property is about what git
# stores, so a fixture that does not run git would test nothing.

FIXTURE_TERM = "/home/fixture-user"


def _run(repo: Path, *args: str) -> str:
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid",
               GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          env=env, check=True)
    return proc.stdout.strip()


def _commit(repo: Path, msg: str, files: dict[str, str | None]) -> str:
    for rel, body in files.items():
        p = repo / rel
        if body is None:
            p.unlink()
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
    _run(repo, "add", "-A")
    _run(repo, "commit", "-q", "-m", msg)
    return _run(repo, "rev-parse", "HEAD")


def selftest() -> int:
    failures: list[str] = []
    leak = f"path = {FIXTURE_TERM}/checkout\n"

    def fresh(td: str) -> tuple[Path, str]:
        repo = Path(td)
        _run(repo, "init", "-q", "-b", "main")
        # The ledger shape: a file that ALREADY names the term in published
        # history, so an absolute per-commit count would refuse everything.
        base = _commit(repo, "base", {"ledger.json": leak * 3, "a.txt": "clean\n"})
        return repo, base

    def verdict(repo: Path, base: str) -> tuple[int, list[Finding]]:
        _, _, found = grade_range(repo, FIXTURE_TERM, f"{base}..HEAD")
        return (1 if found else 0), found

    with tempfile.TemporaryDirectory() as td:
        # 1. THE DEFECT: an intermediate commit adds the line, the tip removes
        #    it. The tip is clean, so a checkout scan is green; the range is not.
        repo, base = fresh(td)
        mid = _commit(repo, "adds", {"a.txt": "clean\n" + leak})
        _commit(repo, "removes", {"a.txt": "clean\n"})
        tip_dirty = FIXTURE_TERM in (repo / "a.txt").read_text()
        rc, found = verdict(repo, base)
        if tip_dirty:
            failures.append("fixture error: the tip should be clean")
        if rc != 1 or [(f.commit, f.path) for f in found] != [(mid, "a.txt")]:
            failures.append(f"intermediate add then remove: wanted exactly {mid[:12]} a.txt, got {found}")

    with tempfile.TemporaryDirectory() as td:
        # 2. A clean range, over a file that already names the term, is green.
        repo, base = fresh(td)
        _commit(repo, "edit", {"a.txt": "still clean\n"})
        _commit(repo, "unrelated ledger edit", {"ledger.json": leak * 3 + "extra\n"})
        rc, found = verdict(repo, base)
        if rc != 0:
            failures.append(f"a range adding no home-path line must pass, got {found}")

    with tempfile.TemporaryDirectory() as td:
        # 3. The ledger shape: appending one more home-path line to a file that
        #    already has three is a raise (3 -> 4), not tolerated by the three.
        repo, base = fresh(td)
        bad = _commit(repo, "ledger raise", {"ledger.json": leak * 4})
        rc, found = verdict(repo, base)
        if [(f.commit, f.before, f.after) for f in found] != [(bad, 3, 4)]:
            failures.append(f"a raise over the base count must be named 3 -> 4, got {found}")

    with tempfile.TemporaryDirectory() as td:
        # 4. A commit that LOWERS the count is fine (a rewrite repaired it).
        repo, base = fresh(td)
        _commit(repo, "lowers", {"ledger.json": leak * 2})
        rc, found = verdict(repo, base)
        if rc != 0:
            failures.append(f"lowering the count must pass, got {found}")

    with tempfile.TemporaryDirectory() as td:
        # 5. A new file, a rename-free deletion and a count on a changed line.
        repo, base = fresh(td)
        added = _commit(repo, "new file", {"b.txt": leak})
        _commit(repo, "delete it", {"b.txt": None})
        rc, found = verdict(repo, base)
        if [(f.commit, f.path) for f in found] != [(added, "b.txt")]:
            failures.append(f"a file added then deleted inside the range must be named, got {found}")

    with tempfile.TemporaryDirectory() as td:
        # 6. A merge is not charged for a side branch's blob that is in the range
        #    as its own commit: the side commit is flagged once, the merge not.
        repo, base = fresh(td)
        _run(repo, "checkout", "-q", "-b", "side")
        side = _commit(repo, "side adds", {"s.txt": leak})
        _run(repo, "checkout", "-q", "main")
        _commit(repo, "main edit", {"a.txt": "main\n"})
        _run(repo, "merge", "-q", "--no-ff", "-m", "merge", "side")
        rc, found = verdict(repo, base)
        names = sorted((f.commit, f.path) for f in found)
        if names != [(side, "s.txt")]:
            failures.append(f"a clean merge must not be charged for the side branch, got {found}")

    with tempfile.TemporaryDirectory() as td:
        # 7. An EVIL merge (the resolution itself adds the line) IS charged.
        repo, base = fresh(td)
        _run(repo, "checkout", "-q", "-b", "side")
        _commit(repo, "side edit", {"s.txt": "side\n"})
        _run(repo, "checkout", "-q", "main")
        _commit(repo, "main edit", {"a.txt": "main\n"})
        _run(repo, "merge", "-q", "--no-commit", "--no-ff", "side")
        (repo / "a.txt").write_text("main\n" + leak)
        _run(repo, "add", "-A")
        _run(repo, "commit", "-q", "-m", "evil merge")
        merge = _run(repo, "rev-parse", "HEAD")
        rc, found = verdict(repo, base)
        if [(f.commit, f.path) for f in found] != [(merge, "a.txt")]:
            failures.append(f"an evil merge must be charged for its own addition, got {found}")

    with tempfile.TemporaryDirectory() as td:
        # 8. The command line: a bad range is a FAIL (not an empty green), and an
        #    empty term is a FAIL; a good range prints its population.
        repo, base = fresh(td)
        _commit(repo, "edit", {"a.txt": "x\n"})
        if check(repo, FIXTURE_TERM, "no-such-ref..HEAD") != 1:
            failures.append("an unresolvable range must fail, not pass as empty")
        if check(repo, "", f"{base}..HEAD") != 1:
            failures.append("an empty term must fail")
        if check(repo, FIXTURE_TERM, f"{base}..HEAD") != 0:
            failures.append("a clean range must pass through the command line entry")

    for f in failures:
        print(f"home-path-range: SELFTEST FAIL -- {f}", file=sys.stderr)
    if failures:
        return 1
    print(
        "home-path-range: selftest passed -- a commit that adds a home-path line is "
        "named even when a later commit removes it (clean tip); a raise over a base "
        "that already carries lines is named with its counts; a clean range, a "
        "lowered count, and a clean merge pass; an evil merge, a file added then "
        "deleted, an unresolvable range and an empty term are refused"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--term", help="the home directory to look for (the shell passes $HOME)")
    ap.add_argument("--range", dest="rev_range", help="<base>..<tip>")
    ap.add_argument("--repo", default=".", help="repository to read (default: cwd)")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.term or not args.rev_range:
        ap.error("--term and --range are required (or --selftest)")
    return check(Path(args.repo), args.term, args.rev_range)


if __name__ == "__main__":
    sys.exit(main())
