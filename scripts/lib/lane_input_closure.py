#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4654 (no register item) -- the traced audit: a lane read a tracked file its key does not hold.

RFC 0001 (`docs/rfc/0001-a-lane-lands-alone-and-a-verdict-is-keyed-by-what-it-read.md`,
section 4.4, stage M1). A lane's digest (`lane_digest.py`) is sound when inputs(L, t) holds every
tracked file the lane reads; the derivation reads the lane's commands, and a file reached through a
path computed at run time is found only by running the lane. This module is the audit that does:
it takes the files a run of the lane opened for reading and names every tracked one the lane's
record does not hold -- an UNDECLARED INPUT, the lane and the path. The repair is the lane's
`decl` in `scripts/lib/lanes.toml`, or a reading of the command that finds it.

## Where the reads come from

RFC 0001 names bx's read tracing as the tracer (bx RFC 0003 9a for an action; bx RFC 0084 records
what a check unit's run read). The audit takes a run's reads from either:

    --reads FILE     one path a line, absolute or relative to the root (a bx record's list)
    --strace DIR     the per-process files of
                     `strace -ff -y -qq -e trace=open,openat,openat2 -e signal=none -o DIR/t ...`
    --run            runs the lane's unit (`python3 scripts/lib/runci_plan.py --layer <lane>`)
                     under that strace, in this checkout, which must be HEAD and unmodified

A read is an open that succeeded (`= <fd><path>` with `-y`), for reading (`O_RDONLY` or
`O_RDWR`), of no directory. A path outside the checkout or untracked (a build product, a cache),
or the dispatch script, the planner, a workflow the planner reads or a script the lane's spec holds
(all keyed by the spec) is no undeclared input. A read inside a submodule is covered when the
lane's inputs hold that submodule's gitlink. An opaque lane's inputs are the whole tree, so its
audit has nothing to find, and says so.

The dispatch script is the one exception to "keyed by the spec": a lane's key holds only the
definitions of it the lane runs (`lane_digest.py`, "The dispatch script"), so a lane that reads it
as data, any open but the one by the shell that runs it, needs the file in its inputs. A trace
tells the two apart (`runci_read_as_data`: the shell that runs it is the process whose execve
names it, and it opens it once); a read list cannot, and the audit says so.

## Interface

    reads_from_strace(lines) -> list[str]            absolute paths opened for reading
    runci_read_as_data(lines, paths) -> bool          one process opened the dispatch script
                                                     other than to run it
    undeclared(rec, reads, root, tree, runci_data=False) -> list[str]
                                                     the tracked paths `rec` does not hold

    python3 scripts/lib/lane_input_closure.py --lane ID (--reads FILE | --strace DIR | --run)
    python3 scripts/lib/lane_input_closure.py --selftest
"""

from __future__ import annotations

import argparse
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lane_digest  # noqa: E402
import lane_graph  # noqa: E402
from git_tree import Fixture, GitTree, git  # noqa: E402

#: One traced open with its result decorated by `-y`: `openat(AT_FDCWD, "x", O_RDONLY) = 3</abs/x>`.
_OPEN = re.compile(r"^(?:\[pid\s+\d+\]\s+)?(?:\d+\s+)?(?:open|openat|openat2)\((?P<args>.*)\)\s+=\s+\d+<(?P<path>[^>]*)>\s*$")
#: A program a traced process started: `execve("/usr/bin/bash", ["bash", "scripts/run-ci.sh"], ...) = 0`.
_EXEC = re.compile(r'^(?:\[pid\s+\d+\]\s+)?(?:\d+\s+)?execve\("(?P<prog>[^"]*)", \[(?P<argv>.*?)\].*\)\s+=\s+0\s*$')
#: The programs whose open of a script is how they run it.
SHELLS = frozenset({"bash", "sh", "dash"})
STRACE = ["strace", "-ff", "-y", "-qq", "-e", "trace=execve,open,openat,openat2", "-e", "signal=none"]


def reads_from_strace(lines) -> list[str]:
    """The absolute paths a trace shows opened for reading, in order, each once."""
    out: list[str] = []
    seen: set[str] = set()
    for line in lines:
        m = _OPEN.match(line.rstrip("\n"))
        if m is None:
            continue
        args = m.group("args")
        if "O_DIRECTORY" in args or not ("O_RDONLY" in args or "O_RDWR" in args):
            continue
        path = m.group("path")
        if path not in seen:
            seen.add(path)
            out.append(path)
    return out


def runci_read_as_data(lines, paths: set[str]) -> bool:
    """Whether one process's trace (one file of `strace -ff`) opened the dispatch script, any of
    `paths`, for any reason but running it. The shell that runs it is the process whose execve
    names it, and that open comes once; any other open, in that process or another, is a read of
    the file as data. A process with no execve in its file is a fork, which runs no script anew."""
    runs = False
    for line in lines:
        line = line.rstrip("\n")
        m = _EXEC.match(line)
        if m:
            runs = posixpath.basename(m.group("prog")) in SHELLS and lane_digest.RUNCI in m.group("argv")
            continue
        for path in reads_from_strace([line]):
            if path not in paths:
                continue
            if not runs:
                return True
            runs = False
    return False


def _relative(path: str, roots: list[str]) -> str | None:
    if not os.path.isabs(path):
        return os.path.normpath(path)
    for root in roots:
        if path.startswith(root + os.sep):
            return path[len(root) + 1 :]
    return None


def undeclared(rec: dict, reads: list[str], root: Path, tree, runci_data: bool = False) -> list[str]:
    """The tracked paths of `reads` the record does not hold (see the module docstring); with
    `runci_data`, a read of the dispatch script as data counts when the key holds only the
    definitions of it the lane runs."""
    if rec["opaque"]:
        return []
    roots = sorted({str(Path(root)), str(Path(root).resolve())}, key=len, reverse=True)
    held = {f[0] for f in rec["inputs"]["files"]}
    out: list[str] = []
    if runci_data and lane_digest.RUNCI not in held:
        out.append(f"{lane_digest.RUNCI} (read as data; the key holds only the definitions of it the lane runs)")
    held |= {s[0] for s in rec["spec"]["scripts"]}
    held |= {lane_digest.RUNCI, lane_digest.PLANNER, *lane_digest.WORKFLOWS}
    links = {g[0] for g in rec["inputs"]["gitlinks"]}
    all_links = tree.gitlinks()
    for raw in reads:
        rel = _relative(raw, roots)
        if rel is None or rel.startswith(".."):
            continue
        link = next((g for g in all_links if rel == g or rel.startswith(g + "/")), None)
        if link is not None:
            if link not in links:
                out.append(f"{rel} (in submodule {link}, whose pin the lane's inputs do not hold)")
            continue
        if rel in tree.entries and rel not in held:
            out.append(rel)
    return sorted(set(out))


def _report(lane: str, found: list[str], rec: dict) -> int:
    if rec["opaque"]:
        print(f"lane_input_closure: lane {lane} is opaque ({'; '.join(rec['opaque'])}); its inputs are the "
              f"whole tree and the audit has nothing to find")
        return 0
    for path in found:
        print(f"lane_input_closure: UNDECLARED INPUT lane {lane}: {path}", file=sys.stderr)
    if found:
        print(f"lane_input_closure: FAIL -- lane {lane} read {len(found)} tracked file(s) its key does not "
              f"hold; declare them in its `decl` (scripts/lib/lanes.toml)", file=sys.stderr)
        return 1
    print(f"lane_input_closure: OK -- every tracked file lane {lane} read is in its key")
    return 0


def run_traced(root: Path, lane: str, out_dir: Path) -> int:
    """Run the lane's unit under strace into `out_dir`; the lane's own exit status."""
    argv = [*STRACE, "-o", str(out_dir / "t"), sys.executable, "scripts/lib/runci_plan.py", "--layer", lane]
    return subprocess.call(argv, cwd=root)


def main() -> int:
    ap = argparse.ArgumentParser(description="RFC 0001 4.4: the traced audit of a lane's declared inputs")
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    ap.add_argument("--rev", default="HEAD")
    ap.add_argument("--lane")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--reads", type=Path)
    src.add_argument("--strace", type=Path)
    src.add_argument("--run", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.lane or not (args.reads or args.strace or args.run):
        ap.error("give --lane and one of --reads, --strace, --run")
    if args.run:
        if shutil.which("strace") is None:
            print("lane_input_closure: FAIL -- strace is not on PATH; the run cannot be traced", file=sys.stderr)
            return 2
        if git(args.root, "status", "--porcelain", "--untracked-files=no").strip() or args.rev != "HEAD":
            print("lane_input_closure: FAIL -- --run audits HEAD in an unmodified checkout; a read of "
                  "an edit no commit holds proves nothing about a key", file=sys.stderr)
            return 2
    try:
        rec = lane_digest.record(args.root, args.rev, args.lane)
    except (lane_digest.DigestError, lane_graph.GraphError) as err:
        print(f"lane_input_closure: {err}", file=sys.stderr)
        return 2
    tree = GitTree(args.root, args.rev)
    runci_paths = {str(args.root / lane_digest.RUNCI), str(args.root.resolve() / lane_digest.RUNCI)}
    runci_data = False
    if args.reads:
        reads = [line.strip() for line in args.reads.read_text(encoding="utf-8").splitlines() if line.strip()]
        if rec["spec"]["runci"]["unit"] == "definitions" and any(
                r in runci_paths or r == lane_digest.RUNCI for r in reads):
            print(f"lane_input_closure: a read list does not say which process opened {lane_digest.RUNCI}; "
                  f"whether lane {args.lane} reads it as data is audited from a trace (--strace, --run)")
    else:
        with tempfile.TemporaryDirectory(prefix="wz-lane-trace-") as tmp:
            trace_dir = args.strace
            if args.run:
                trace_dir = Path(tmp)
                rc = run_traced(args.root, args.lane, trace_dir)
                print(f"lane_input_closure: lane {args.lane} ran under strace and exited {rc}")
            reads = []
            for f in sorted(trace_dir.iterdir()):
                with f.open(encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
                reads.extend(reads_from_strace(lines))
                runci_data = runci_data or runci_read_as_data(lines, runci_paths)
    return _report(args.lane, undeclared(rec, reads, args.root, tree, runci_data), rec)


def selftest() -> int:
    cases = 0

    def expect(name: str, ok: bool, detail: object = "") -> None:
        nonlocal cases
        if not ok:
            raise AssertionError(f"lane_input_closure selftest: {name} FAILED {detail}")
        cases += 1

    trace = [
        'openat(AT_FDCWD, "a", O_RDONLY|O_CLOEXEC) = 3</r/a>\n',
        '[pid  42] openat(AT_FDCWD, "b", O_RDWR|O_CREAT, 0644) = 4</r/b>\n',
        'openat(AT_FDCWD, "c", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 5</r/c>\n',
        'openat(AT_FDCWD, "d", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 6</r/d>\n',
        'openat(AT_FDCWD, "e", O_RDONLY) = -1 ENOENT (No such file or directory)\n',
        'openat2(AT_FDCWD, "f", {flags=O_RDONLY|O_CLOEXEC, resolve=0}, 24) = 7</r/f>\n',
        'openat(AT_FDCWD, "a", O_RDONLY) = 8</r/a>\n',
        '+++ exited with 0 +++\n',
    ]
    # Red if a write, a directory or a failed open counts as a read, or a read is listed twice.
    got = reads_from_strace(trace)
    expect("a trace's reads are its successful opens for reading", got == ["/r/a", "/r/b", "/r/f"], got)

    machine = {"rustc": "r", "cargo": "c", "cc": "cc", "python": "p", "machine": "m"}
    with Fixture() as fx:
        rev = fx.commit(lane_digest.FIXTURE, lane_graph.FIXTURE_LINKS)
        tree = GitTree(fx.root, rev)
        rec = lane_digest.record(fx.root, rev, "C", env_reader=lambda c: dict(machine))
        root = str(fx.root)
        reads = [
            f"{root}/crates/core/src/lib.rs",
            f"{root}/crates/leaf/src/lib.rs",
            f"{root}/vendor/sub/subcrate/src/lib.rs",
            f"{root}/build-products/libcore.rlib",
            "/etc/hostname",
            f"{root}/scripts/run-ci.sh",
            "README.md",
        ]
        found = undeclared(rec, reads, fx.root, tree)
        # Red if `undeclared` stops comparing a read with the record's files.
        expect("a tracked file outside the lane's inputs is undeclared",
               found == ["README.md", "crates/leaf/src/lib.rs"], found)
        no_pin = dict(rec, inputs=dict(rec["inputs"], gitlinks=[]))
        found = undeclared(no_pin, reads[2:3], fx.root, tree)
        # Red if a read inside a submodule is judged without its gitlink.
        expect("a submodule read without its pin in the key is undeclared", len(found) == 1 and "vendor/sub" in found[0], found)
        opaque = lane_digest.record(fx.root, rev, "O", env_reader=lambda c: dict(machine))
        expect("an opaque lane has nothing undeclared", undeclared(opaque, reads, fx.root, tree) == [])
        # Red if a read of the dispatch script as data is excused for a lane whose key holds only
        # the definitions it runs, or charged to one that holds the file.
        found = undeclared(rec, [], fx.root, tree, runci_data=True)
        expect("the dispatch script read as data is undeclared where the key holds its definitions",
               len(found) == 1 and found[0].startswith(lane_digest.RUNCI), found)
        audit = lane_digest.record(fx.root, rev, "A", env_reader=lambda c: dict(machine))
        expect("and declared where the key holds the file", undeclared(audit, [], fx.root, tree, runci_data=True) == [])

    paths = {"/r/scripts/run-ci.sh"}
    shell = 'execve("/usr/bin/bash", ["bash", "scripts/run-ci.sh", "--layer", "C"], 0x7ffd /* 30 vars */) = 0\n'
    opened = 'openat(AT_FDCWD, "scripts/run-ci.sh", O_RDONLY) = 3</r/scripts/run-ci.sh>\n'
    python = 'execve("/usr/bin/python3", ["python3", "scripts/lib/x.py", "--audit"], 0x7ffd /* 30 vars */) = 0\n'
    # Red if the shell's own open of its script counts as data, or any other open does not.
    expect("the shell that runs the dispatch script does not read it as data",
           not runci_read_as_data([shell, opened], paths))
    expect("a second open by that shell does", runci_read_as_data([shell, opened, opened], paths))
    expect("another program's open does", runci_read_as_data([python, opened], paths))
    expect("a fork's open does", runci_read_as_data([opened], paths))
    print(f"lane_input_closure selftest: {cases} cases pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
