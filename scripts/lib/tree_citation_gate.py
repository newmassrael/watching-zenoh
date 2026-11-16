#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4500 (no register item) -- a `path:LINE` citation of THIS tree must name a
line the tree has.

The items this answers, open-debt items 221 and 255, live in the agent-memory
half of the register, which has no store id for `gate_provenance_lint.py` to
resolve; they are named in prose instead.

## The defect

This tree's comments and its ledger prose cite its own files by line, and
nothing resolved those citations. `reason_citation_gate.py` reads inventory
reasons and `upstream_citation_anchor_gate.py` reads citations of the pinned
upstream; a repo-relative citation in a source comment, or in the carry of a
round about to freeze, was graded by nobody. A line moved by the very edit
that wrote the citation was caught once only because its author happened to
notice, and a carry pointed the next round at a range that was not the code it
described. Measured when this was written: two comments in two crates cited a
file that had moved to another crate eight hundred rounds earlier.

## What is graded

A citation is a path whose first segment is a top-level directory of this
tree's tracked files, then `:LINE` or `:FIRST-LAST`. It must name a tracked
file, and its last line must be inside that file. Not graded, by rule rather
than by list:

* a path inside a submodule -- that tree is pinned and is another
  repository's, and its citations are the upstream gates' to grade;
* a path whose first TWO segments name nothing this tree tracks: that is a
  path of another repository written in this tree's layout (the mnemosyne
  crates are cited from here), or a fixture. The cost is that a crate renamed
  as a whole leaves its citations unread; a file moved inside a crate does not;
* a bare file name (`lib.rs:4061`): it cannot be told from a citation of the
  upstream file of the same name, which is the reason `reason_citation_gate.py`
  indexes suffixes and this does not.

`--check` reads the COMMENTS of the tracked sources and scripts (`//` and
`/* */` lines in Rust and C, `#` lines and docstrings in Python and shell, the
hooks), not their code: a selftest fixture is a string literal that cites a
line past the end on purpose. Markdown is not read: its tables are dated
records (`docs/hosted-red-acks.md`) whose citations were true of their round.

`--prose FILE...` reads every line of a round's ledger prose before it
freezes, and is what `scripts/append-round.sh` runs. It also lists backticked
qualified symbols (`Type::method`) whose last segment appears nowhere in the
tracked crates, as ADVICE and not a refusal: a carry names the symbols the
next round will add, so a missing one is not by itself an error.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

CITE = re.compile(
    r"(?<![A-Za-z0-9_./-])([A-Za-z0-9_.][A-Za-z0-9_.-]*/[A-Za-z0-9_./-]*\.[A-Za-z0-9]+)"
    r":(\d+)(?:-(\d+))?"
)
SYMBOL = re.compile(r"`((?:[A-Za-z_][A-Za-z0-9_]*::)+([A-Za-z_][A-Za-z0-9_]*))(?:\(\))?`")

#: Comment syntax by file: `//` languages and `#` languages.
SLASH_EXT = frozenset({".rs", ".c", ".h", ".cc", ".cpp", ".hpp"})
HASH_EXT = frozenset({".py", ".sh", ".toml", ".yaml", ".yml", ".cmake"})
HASH_NAMES = frozenset({"CMakeLists.txt"})
#: Generated output and other projects' trees kept in this repository.
NOT_OURS = ("out/", "third-party/", "docs/.atomic/")


@dataclass
class Tree:
    """What the tracked tree holds: files, the directories above them, the
    submodules, and each file's line count (read on first ask)."""

    root: Path
    files: set[str]
    gitlinks: set[str]
    lines: dict[str, int] = field(default_factory=dict)
    dirs: set[str] = field(default_factory=set)
    tops: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        for path in self.files | self.gitlinks:
            parts = path.split("/")
            self.tops.add(parts[0])
            for i in range(1, len(parts)):
                self.dirs.add("/".join(parts[:i]))

    def line_count(self, path: str) -> int:
        if path not in self.lines:
            data = (self.root / path).read_bytes()
            n = data.count(b"\n")
            if data and not data.endswith(b"\n"):
                n += 1
            self.lines[path] = n
        return self.lines[path]


def judge(tree: Tree, path: str, first: int, last: int) -> str | None:
    """`None` when the citation is not this tree's to grade or resolves; else
    why it does not. Raises nothing for a path outside the tree."""
    path = path[2:] if path.startswith("./") else path
    parts = path.split("/")
    if parts[0] not in tree.tops:
        return None
    if any("/".join(parts[:i]) in tree.gitlinks for i in range(1, len(parts) + 1)):
        return None
    if len(parts) > 2:
        second = "/".join(parts[:2])
        if second not in tree.dirs and second not in tree.files:
            return None
    if path not in tree.files:
        return f"`{path}` is not a tracked file"
    if last < first:
        return f"the range {first}-{last} runs backwards"
    n = tree.line_count(path)
    if last > n:
        return f"line {last} is past the end of `{path}` ({n} lines)"
    return None


def citations(text: str) -> list[tuple[str, int, int]]:
    out = []
    for m in CITE.finditer(text):
        first = int(m.group(2))
        last = int(m.group(3)) if m.group(3) else first
        path = m.group(1)
        out.append((path[2:] if path.startswith("./") else path, first, last))
    return out


def comment_lines(rel: str, text: str) -> list[tuple[int, str]]:
    """`(line number, comment text)` of a source or script file."""
    name = rel.rsplit("/", 1)[-1]
    ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    out: list[tuple[int, str]] = []
    lines = text.splitlines()
    if ext in SLASH_EXT:
        for i, line in enumerate(lines, 1):
            at = line.find("//")
            stripped = line.lstrip()
            if at >= 0:
                out.append((i, line[at:]))
            elif stripped.startswith(("*", "/*")):
                out.append((i, line))
    elif ext in HASH_EXT or name in HASH_NAMES or rel.startswith(".githooks/"):
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                out.append((i, line))
            else:
                at = line.find(" #")
                if at >= 0:
                    out.append((i, line[at:]))
        if ext == ".py":
            out.extend(docstrings(text))
    return out


def docstrings(text: str) -> list[tuple[int, str]]:
    """Each line of every module, class and function docstring, numbered."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", [])
        if not body or not isinstance(body[0], ast.Expr):
            continue
        value = body[0].value
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            continue
        for k, line in enumerate(value.value.splitlines()):
            out.append((value.lineno + k, line))
    return out


def comment_population(tree: Tree) -> list[str]:
    out = []
    for rel in sorted(tree.files):
        if rel.startswith(NOT_OURS):
            continue
        name = rel.rsplit("/", 1)[-1]
        ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
        if ext in SLASH_EXT or ext in HASH_EXT or name in HASH_NAMES or rel.startswith(".githooks/"):
            out.append(rel)
    return out


def real_tree() -> Tree:
    listed = subprocess.run(
        ["git", "ls-files", "-s", "-z"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if listed.returncode != 0:
        raise SystemExit(
            f"tree-citation: FAIL -- `git ls-files` exited {listed.returncode}: {listed.stderr.strip()}"
        )
    files: set[str] = set()
    gitlinks: set[str] = set()
    for entry in listed.stdout.split("\0"):
        if not entry:
            continue
        meta, _, path = entry.partition("\t")
        (gitlinks if meta.startswith("160000") else files).add(path)
    return Tree(ROOT, files, gitlinks)


def grade(tree: Tree, sources: list[tuple[str, list[tuple[int, str]]]]) -> tuple[list[str], int]:
    """Findings, and how many in-tree citations were graded."""
    findings: list[str] = []
    graded = 0
    for rel, lines in sources:
        for number, text in lines:
            for path, first, last in citations(text):
                why = judge(tree, path, first, last)
                if why is None and not _in_tree(tree, path):
                    continue
                graded += 1
                if why is not None:
                    findings.append(f"{rel}:{number}: {path}:{first}{'' if first == last else f'-{last}'} -- {why}")
    return findings, graded


def _in_tree(tree: Tree, path: str) -> bool:
    """Whether `judge` graded this path rather than skipping it."""
    parts = path.split("/")
    return path in tree.files and parts[0] in tree.tops


def advise_symbols(texts: list[tuple[str, str]]) -> list[str]:
    """Backticked qualified symbols whose last segment no tracked crate names."""
    out: list[str] = []
    seen: set[str] = set()
    for rel, text in texts:
        for m in SYMBOL.finditer(text):
            full, last = m.group(1), m.group(2)
            if full in seen:
                continue
            seen.add(full)
            found = subprocess.run(
                ["git", "grep", "-q", "-w", "-F", last, "--", "crates"],
                cwd=ROOT,
                capture_output=True,
                check=False,
            )
            if found.returncode == 1:
                out.append(f"{rel}: `{full}` -- `{last}` appears nowhere under crates/")
    return out


def selftest() -> None:
    fixture = Tree(
        ROOT,
        files={"crates/a/src/lib.rs", "scripts/x.sh", "docs/notes.md"},
        gitlinks={"vendor/sub"},
        lines={"crates/a/src/lib.rs": 10, "scripts/x.sh": 3, "docs/notes.md": 4},
    )
    cases = {
        ("crates/a/src/lib.rs", 5, 5): None,
        ("crates/a/src/lib.rs", 1, 10): None,
        ("docs/notes.md", 4, 4): None,
        ("./scripts/x.sh", 3, 3): None,
        ("crates/zz/src/lib.rs", 3, 3): None,
        ("vendor/sub/src/x.c", 9, 9): None,
        ("upstream/src/hello.rs", 62, 66): None,
        ("crates/a/src/lib.rs", 11, 11): "past the end",
        ("crates/a/src/lib.rs", 4, 12): "past the end",
        ("crates/a/src/gone.rs", 3, 3): "not a tracked file",
        ("crates/a/src/lib.rs", 7, 3): "runs backwards",
    }
    for (path, first, last), want in cases.items():
        got = judge(fixture, path, first, last)
        if want is None:
            assert got is None, f"selftest: {path}:{first}-{last} refused: {got}"
        else:
            assert got is not None and want in got, f"selftest: {path}:{first}-{last} gave {got!r}"

    assert citations("see lib.rs:4061 and crates/a/src/lib.rs:4-6.") == [("crates/a/src/lib.rs", 4, 6)]

    gone = "crates/a/src/" + "gone.rs:3"
    rust = f'let s = "{gone}";\n// see {gone}\n/// and crates/a/src/lib.rs:2\n'
    found, graded = grade(fixture, [("f.rs", comment_lines("f.rs", rust))])
    assert len(found) == 1 and found[0].startswith("f.rs:2:"), f"selftest: rust {found}"
    assert graded == 2, f"selftest: rust graded {graded}"

    py = f'"""Module.\n\nSee {gone}.\n"""\nX = "{gone}"\n# {gone}\ny = 1  # {gone}\n'
    found, _ = grade(fixture, [("f.py", comment_lines("f.py", py))])
    assert sorted(f.split(":")[1] for f in found) == ["3", "6", "7"], f"selftest: python {found}"

    sh = f'echo "{gone}"\n# {gone}\n'
    found, _ = grade(fixture, [(".githooks/pre-x", comment_lines(".githooks/pre-x", sh))])
    assert len(found) == 1, f"selftest: hook {found}"

    md = f"| R1 | {gone} |\n"
    assert comment_lines("docs/notes.md", md) == [], "selftest: markdown was read"

    assert comment_population(fixture) == ["crates/a/src/lib.rs", "scripts/x.sh"], (
        f"selftest: population {comment_population(fixture)}"
    )


def main() -> int:
    args = sys.argv[1:]
    if args == ["--selftest"]:
        selftest()
        print("tree-citation: selftest ok")
        return 0
    selftest()
    tree = real_tree()
    if args == ["--check"]:
        population = comment_population(tree)
        sources = []
        for rel in population:
            text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
            sources.append((rel, comment_lines(rel, text)))
        findings, graded = grade(tree, sources)
        what = f"{len(population)} source and script file(s)"
    elif len(args) >= 1 and args[0] == "--prose":
        files = args[1:]
        if not files:
            print("tree-citation: FAIL -- --prose was given no file", file=sys.stderr)
            return 1
        texts = [(f, Path(f).read_text(encoding="utf-8", errors="replace")) for f in files]
        sources = [(f, list(enumerate(t.splitlines(), 1))) for f, t in texts]
        findings, graded = grade(tree, sources)
        for line in advise_symbols(texts):
            print(f"  tree-citation: advice: {line}")
        what = f"{len(files)} prose file(s)"
    else:
        print("usage: tree_citation_gate.py --check | --prose FILE... | --selftest", file=sys.stderr)
        return 2

    if findings:
        print(f"tree-citation: FAIL -- {len(findings)} citation(s) of this tree name no such line:", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        print("  Re-point each at the line it means now; a citation that cannot be kept true", file=sys.stderr)
        print("  names the symbol instead of the line.", file=sys.stderr)
        return 1
    if args == ["--check"] and graded == 0:
        print(
            f"tree-citation: FAIL -- read {what} and graded 0 citations; a reader that "
            f"lost its subject reports a clean surface",
            file=sys.stderr,
        )
        return 1
    print(f"  tree-citation: {what}, {graded} citation(s) of this tree resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
