#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4745 (no register item) -- a Python selftest reaches no wall clock, no host socket, no thread
of its own, no host randomness and no process; a script whose selftest must is a row of the Python
system layer's table, with its reason.

The design is `docs/deterministic-tests.md` (sections 4, 5 and 10): a selftest is a function of its
fixtures, as a unit test is of its script and its seed; what needs the host is declared script by
script.

## The defect

A gate's selftest is what tells a gate that judges right from one that passes over everything.
One that runs git, reads the wall clock or draws the host's entropy is a function of the host as
well as of its fixtures: its verdict can change with the machine, the hour or the checkout, with
nothing in the tree changed, and a red it gives on one host is not read the same on the next.
Nothing held a selftest to its fixtures, and nothing said which selftests had not been brought to
them.

## What is derived

The POPULATION is every tracked `.py` file under `scripts/` that has a selftest entry: a top-level
function named `selftest` or `_selftest`; the branch of `main` (or of the `__main__` block) whose
test names `--selftest` or a `.selftest` flag, and the value a mode table keys by `--selftest`,
read as one entry; and, in a file named `test_*.py`, each top-level function named `test_*`. Each
file is read by `ast`, so a source named in a comment or a string is not a reach.

A selftest REACHES a source when, from its entries, it calls one of the source's functions
(`SOURCES`, matched on the call's dotted name with every import alias resolved), following to a
fixed point what each unit it reaches names: a function or class of its own file, a method of its
own file or of a file it imports, by the method's name, and a function or class of a module it
imports from its own directory or from `scripts/lib` (`from m import f`, `import m` then `m.f`,
`from m import *`). A class reaches what its class body and its dunder methods call, and a
subclass of a thread class is a thread; a file reached runs its top level, read as a unit of its
own. A name a function binds itself (a parameter, an assignment, a nested function) hides the
file's item of that name.

The read through imports is not decoration: a selftest that drives its own judge on fixture text
is unit, and one whose fixture tree is made by a helper of `scripts/lib` that runs git is not,
while neither file names a process itself.

## The table

`docs/deterministic-tests/python-system-layer.tsv`: a header, then one row per system-layer
script: its path, its kind (`pending`: owed the split of its judgement from its fact-gathering, so
that the selftest hands the judgement fixtures behind a seam; `system`: the host is its subject,
such as a selftest that runs git or a shell script over a fixture tree it made), the sources it
reaches and the reason. A finding is

- a script that reaches a source and has no row;
- a row for a path that is not a tracked script with a selftest entry, or a second row;
- a row whose kind is not one of `KINDS`, which names a source that is not one, or no source, or
  which gives no reason;
- a row that declares a source its script no longer reaches (the row is stale: take the source
  out, and the row once its script reaches nothing), or that leaves out a source it reaches;
- a tracked file that does not parse, whose reach cannot be read;
- a population of no script, or a table of no row: the gate lost its subject.

The first table lists every script that reached a source on the day it landed (`--rows` prints
the rows the table lacks). A move behind a seam deletes a row; a row is added only for a script
whose subject is the host.

## What this does not claim

- That a unit-layer selftest is deterministic: a dynamic call (`getattr`, a function looked up in
  a table built at run time, `importlib`), `exec` and `eval`, a source bound to a plain name by
  assignment or handed on as a value, a read of the environment and a write to the file system
  are not seen.
- Name resolution beyond the file and its local imports: a method is joined by its name alone,
  so a call of a method of the same name on another type joins it too and the read errs to
  reaching; a module outside `scripts/` is read for its sources only.
- That the code of `main` outside its `--selftest` branch runs before the selftest: it is not read.
"""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
from collections import deque
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TABLE = "docs/deterministic-tests/python-system-layer.tsv"
SCOPE = "scripts"
LIB = "scripts/lib"

HEADER = ("path", "kind", "sources", "reason")
KINDS = ("pending", "system")
CENSUS_REASON = "census 2026-11-28: reached before the gate"

# What a unit-layer selftest may not call, by source: each pattern matches the whole dotted name
# of a call, its import aliases resolved. Of subprocess only what starts a process counts: its
# types and constants (CompletedProcess, PIPE) are what a fixture builds a seam's answer from.
SOURCES: dict[str, tuple[str, ...]] = {
    "clock": (r"time\.(?:sleep|time|time_ns|monotonic|monotonic_ns|perf_counter|perf_counter_ns)",
              r"datetime\.datetime\.(?:now|utcnow|today)", r"datetime\.date\.today"),
    "socket": (r"socket\.\w+", r"urllib\.request\.\w+", r"http\.client\.\w+",
               r"requests(?:\.\w+)+"),
    "thread": (r"threading\.(?:Thread|Timer)", r"multiprocessing(?:\.\w+)+",
               r"asyncio\.(?:run|get_event_loop|new_event_loop)",
               r"concurrent\.futures\.(?:\w+\.)?\w*Executor"),
    "random": (r"random\.\w+", r"secrets\.\w+", r"os\.(?:urandom|getrandom)", r"uuid\.uuid[14]"),
    "process": (r"subprocess\.(?:run|Popen|call|check_call|check_output|getoutput|"
                r"getstatusoutput)",
                r"os\.(?:system|popen|fork|forkpty|exec\w*|spawn\w*|posix_spawnp?)"),
}
PATTERNS = {source: [re.compile(p) for p in patterns] for source, patterns in SOURCES.items()}
# A generator the test seeds is its own; one built with no argument seeds itself from the host.
SEEDED = "random.Random"

ENTRY_NAMES = ("selftest", "_selftest")
BRANCH = "<--selftest>"
TOP = "<top>"

Unit = tuple[str, str]


class LostSubject(Exception):
    """A population of no script or a table of no row: the gate has nothing to judge, which is
    never a pass."""


def source_of(qual: str, call: ast.Call | None) -> str | None:
    """The source a call of a dotted name is, or None."""
    if qual == SEEDED and call is not None and (call.args or call.keywords):
        return None
    for source, patterns in PATTERNS.items():
        if any(p.fullmatch(qual) for p in patterns):
            return source
    return None


def bound_in(fn: ast.AST) -> set[str]:
    """The names a function binds itself: its parameters, what it assigns, what it defines."""
    names: set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.arg):
            names.add(n.arg)
        elif isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            names.add(n.id)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n is not fn:
            names.add(n.name)
    for n in ast.walk(fn):
        if isinstance(n, ast.Global):
            names.difference_update(n.names)
    return names


def is_main_guard(stmt: ast.stmt) -> bool:
    return (isinstance(stmt, ast.If) and isinstance(stmt.test, ast.Compare)
            and isinstance(stmt.test.left, ast.Name) and stmt.test.left.id == "__name__"
            and len(stmt.test.comparators) == 1
            and isinstance(stmt.test.comparators[0], ast.Constant)
            and stmt.test.comparators[0].value == "__main__")


def names_selftest(test: ast.AST) -> bool:
    """Whether a branch's test reads the selftest mode: the argument or an argparse flag."""
    for n in ast.walk(test):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and "--selftest" in n.value:
            return True
        if isinstance(n, ast.Attribute) and n.attr == "selftest":
            return True
    return False


def selftest_branch(root: ast.AST) -> list[ast.AST]:
    """What runs in the --selftest mode of a dispatch: the test and the branch of each if or
    conditional expression whose test reads the mode (the else branch under a `not`), and the
    value a mode table keys by `--selftest`."""
    out: list[ast.AST] = []
    for n in ast.walk(root):
        if isinstance(n, (ast.If, ast.IfExp)) and names_selftest(n.test):
            negated = isinstance(n.test, ast.UnaryOp) and isinstance(n.test.op, ast.Not)
            taken = n.orelse if negated else n.body
            out.append(n.test)
            out.extend(taken if isinstance(taken, list) else [taken])
        elif isinstance(n, ast.Dict):
            for key, value in zip(n.keys, n.values):
                if isinstance(key, ast.Constant) and key.value == "--selftest":
                    out.append(value)
    return out


class Script:
    """One tracked file under scripts/, as the reach reads it."""

    def __init__(self, path: str, text: str) -> None:
        self.path = path
        self.dir = path.rpartition("/")[0]
        self.error: str | None = None
        try:
            tree = ast.parse(text, filename=path)
        except SyntaxError as exc:
            tree = ast.Module(body=[], type_ignores=[])
            self.error = f"line {exc.lineno}: {exc.msg}"
        except ValueError as exc:
            tree = ast.Module(body=[], type_ignores=[])
            self.error = str(exc)
        self.aliases: dict[str, str] = {}
        self.star: list[str] = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.asname:
                        self.aliases[a.asname] = a.name
                    else:
                        head = a.name.partition(".")[0]
                        self.aliases[head] = head
            elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
                for a in n.names:
                    if a.name == "*":
                        self.star.append(n.module)
                    else:
                        self.aliases[a.asname or a.name] = f"{n.module}.{a.name}"
        self.fns: dict[str, ast.AST] = {}
        self.classes: dict[str, ast.ClassDef] = {}
        self.meths: dict[str, list[ast.AST]] = {}
        self.top: list[ast.stmt] = []
        self.branch: list[tuple[ast.AST, set[str]]] = []
        guards: list[ast.stmt] = []
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.fns[stmt.name] = stmt
            elif isinstance(stmt, ast.ClassDef):
                self.classes[stmt.name] = stmt
                for item in stmt.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.meths.setdefault(item.name, []).append(item)
            elif is_main_guard(stmt):
                guards.append(stmt)
            elif not isinstance(stmt, (ast.Import, ast.ImportFrom)):
                self.top.append(stmt)
        main = self.fns.get("main")
        if main is not None:
            local = bound_in(main)
            self.branch.extend((node, local) for node in selftest_branch(main))
        for guard in guards:
            self.branch.extend((node, set()) for node in selftest_branch(guard))
        self.local_mods: list[Script] = []

    def entries(self) -> list[Unit]:
        """The selftest entries of the file; none for a file outside the population."""
        out = [(self.path, f"fn:{name}") for name in ENTRY_NAMES if name in self.fns]
        if self.branch:
            out.append((self.path, BRANCH))
        if self.path.rpartition("/")[2].startswith("test_"):
            out.extend((self.path, f"fn:{name}") for name in sorted(self.fns)
                       if name.startswith("test_"))
        return out

    def qualname(self, node: ast.AST, local: set[str]) -> str | None:
        """The dotted name an expression is through the file's imports; None for anything that
        does not start at an imported name its scope leaves visible."""
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name) or node.id in local or node.id not in self.aliases:
            return None
        return ".".join([self.aliases[node.id], *reversed(parts)])


class World:
    """Every tracked file under scripts/ and the units the reach walks, each read once."""

    def __init__(self, files: dict[str, str]) -> None:
        self.scripts = {path: Script(path, text) for path, text in files.items()}
        for script in self.scripts.values():
            heads = {q.partition(".")[0] for q in script.aliases.values()} | set(script.star)
            for head in sorted(heads):
                other = self.module(script, head)
                if other is not None and other not in script.local_mods:
                    script.local_mods.append(other)
        self.units: dict[Unit, tuple[dict[str, str], set[Unit]]] = {}

    def module(self, at: Script, name: str) -> Script | None:
        """The file an import of a name finds: the importing file's directory first, as Python
        puts a script's directory first on its path, then scripts/lib."""
        for directory in (at.dir, LIB):
            found = self.scripts.get(f"{directory}/{name}.py")
            if found is not None:
                return found
        return None

    def population(self) -> dict[str, Script]:
        return {path: s for path, s in self.scripts.items() if s.entries()}

    def unreadable(self) -> list[tuple[str, str]]:
        return sorted((path, s.error) for path, s in self.scripts.items() if s.error)

    def item_edges(self, t: Script, rest: list[str], edges: set[Unit], depth: int = 0) -> None:
        name = rest[0]
        if name in t.fns:
            edges.add((t.path, f"fn:{name}"))
        elif name in t.classes:
            edges.add((t.path, f"class:{name}"))
            if len(rest) > 1 and rest[1] in t.meths:
                edges.add((t.path, f"meth:{rest[1]}"))
        elif name in t.aliases and depth < 8:
            # A name the module imports itself and hands on.
            self.path_edges(t, t.aliases[name], edges, depth + 1)

    def path_edges(self, s: Script, qual: str, edges: set[Unit], depth: int = 0) -> None:
        segs = qual.split(".")
        t = self.module(s, segs[0])
        if t is not None and len(segs) > 1:
            self.item_edges(t, segs[1:], edges, depth)

    def name_edges(self, s: Script, name: str, edges: set[Unit]) -> None:
        if name in s.fns:
            edges.add((s.path, f"fn:{name}"))
        elif name in s.classes:
            edges.add((s.path, f"class:{name}"))
        elif name in s.aliases:
            self.path_edges(s, s.aliases[name], edges)
        else:
            for star in s.star:
                t = self.module(s, star)
                if t is not None:
                    self.item_edges(t, [name], edges)

    def scan(self, s: Script, root: ast.AST, local: set[str], direct: dict[str, str],
             edges: set[Unit]) -> None:
        """What a node calls of the sources, and the units it names."""
        for n in ast.walk(root):
            if isinstance(n, ast.Call):
                qual = s.qualname(n.func, local)
                source = source_of(qual, n) if qual else None
                if qual and source:
                    direct.setdefault(source, qual)
            elif isinstance(n, ast.ClassDef):
                self.bases(s, n, local, direct)
            elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id not in local:
                self.name_edges(s, n.id, edges)
            elif isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load):
                qual = s.qualname(n, local)
                if qual is not None:
                    self.path_edges(s, qual, edges)
                else:
                    for t in [s, *s.local_mods]:
                        if n.attr in t.meths:
                            edges.add((t.path, f"meth:{n.attr}"))

    @staticmethod
    def bases(s: Script, cls: ast.ClassDef, local: set[str], direct: dict[str, str]) -> None:
        for base in cls.bases:
            qual = s.qualname(base, local)
            if qual and source_of(qual, None) == "thread":
                direct.setdefault("thread", qual)

    def unit(self, key: Unit) -> tuple[dict[str, str], set[Unit]]:
        """The sources a unit calls itself, each with the dotted name it calls, and the units
        it names."""
        if key in self.units:
            return self.units[key]
        path, label = key
        s = self.scripts[path]
        direct: dict[str, str] = {}
        edges: set[Unit] = set()
        if label == TOP:
            for stmt in s.top:
                self.scan(s, stmt, set(), direct, edges)
            edges.update((t.path, TOP) for t in s.local_mods)
        elif label == BRANCH:
            for node, local in s.branch:
                self.scan(s, node, local, direct, edges)
        else:
            kind, _, name = label.partition(":")
            if kind == "fn":
                self.scan(s, s.fns[name], bound_in(s.fns[name]), direct, edges)
            elif kind == "meth":
                for node in s.meths[name]:
                    self.scan(s, node, bound_in(node), direct, edges)
            else:
                cls = s.classes[name]
                self.bases(s, cls, set(), direct)
                for stmt in [*cls.bases, *cls.decorator_list]:
                    self.scan(s, stmt, set(), direct, edges)
                for stmt in cls.body:
                    if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.scan(s, stmt, set(), direct, edges)
                    elif stmt.name.startswith("__") and stmt.name.endswith("__"):
                        self.scan(s, stmt, bound_in(stmt), direct, edges)
        self.units[key] = (direct, edges)
        return direct, edges

    def reach(self, s: Script) -> dict[str, str]:
        """The sources a file's selftest reaches, each with the trail from an entry to its call,
        in the order of the sources' table."""
        parent: dict[Unit, Unit | None] = {}
        queue: deque[Unit] = deque()
        for start in [*s.entries(), (s.path, TOP)]:
            if start not in parent:
                parent[start] = None
                queue.append(start)
        found: dict[str, str] = {}
        while queue:
            u = queue.popleft()
            direct, edges = self.unit(u)
            for source, qual in direct.items():
                found.setdefault(source, f"{self.trail(u, parent, s.path)} -> {qual}")
            for v in sorted(edges | {(u[0], TOP)}):
                if v not in parent:
                    parent[v] = u
                    queue.append(v)
        return {source: found[source] for source in SOURCES if source in found}

    @staticmethod
    def trail(u: Unit, parent: dict[Unit, Unit | None], home: str) -> str:
        steps: list[str] = []
        at: Unit | None = u
        while at is not None:
            path, label = at
            if label == TOP:
                name = "the top level"
            elif label == BRANCH:
                name = "the --selftest branch"
            elif label.startswith("meth:"):
                name = "." + label.partition(":")[2]
            else:
                name = label.partition(":")[2]
            steps.append(name if path == home else f"{name} of {path}")
            at = parent[at]
        return " -> ".join(reversed(steps))


def parse_table(text: str) -> tuple[list[tuple[str, str, str, str]], list[str]]:
    """The rows of the table, and a finding for each line that could not be read as one: a row
    that does not read is never dropped from the judgement unseen."""
    rows: list[tuple[str, str, str, str]] = []
    bad: list[str] = []
    header_seen = False
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        cells = tuple(cell.strip() for cell in line.split("\t"))
        if not header_seen:
            header_seen = True
            if cells != HEADER:
                bad.append(f"the table's header is not {' | '.join(HEADER)} (tab-separated): "
                           f"{line.strip()[:120]}")
            continue
        if len(cells) != len(HEADER):
            bad.append(f"a row not read as {len(HEADER)} tab-separated cells: "
                       f"{line.strip()[:120]}")
            continue
        rows.append((cells[0], cells[1], cells[2], cells[3]))
    return rows, bad


def judge(files: dict[str, str], table_text: str) -> tuple[list[str], dict[str, int]]:
    """Every finding of the scripts (path to text) against the table's text, and the counts of
    what is placed. Raises LostSubject on a population or a table that reads as empty."""
    rows, found = parse_table(table_text)
    world = World(files)
    population = world.population()
    if not population or not rows:
        raise LostSubject(f"read {len(population)} script(s) with a selftest and {len(rows)} "
                          "table row(s); the gate lost its subject and must not pass over an "
                          "empty population")
    for path, error in world.unreadable():
        found.append(f"`{path}` does not parse ({error}): its selftest's reach cannot be read")
    reach = {path: world.reach(s) for path, s in population.items()}
    seen: dict[str, int] = {}
    for path, _, _, _ in rows:
        seen[path] = seen.get(path, 0) + 1
    for path, sources in sorted(reach.items()):
        if sources and path not in seen:
            trails = "; ".join(f"{source}: {trail}" for source, trail in sources.items())
            found.append(f"`{path}` reaches {', '.join(sources)} and has no row: hand its "
                         "selftest the facts behind a seam, or give it a row whose reason says "
                         f"why the host is its subject ({trails})")
    for path, n in sorted(seen.items()):
        if n > 1:
            found.append(f"`{path}` has {n} rows; give it one")
        if path not in reach:
            found.append(f"`{path}` has a row but is not a tracked script under {SCOPE}/ with a "
                         "selftest entry")
    for path, kind, cell, reason in rows:
        if kind not in KINDS:
            found.append(f"`{path}`: kind `{kind}` is not one of {', '.join(KINDS)}")
        if not reason:
            found.append(f"`{path}`: a row with no reason")
        declared = [s.strip() for s in cell.split(",") if s.strip()]
        unknown = [s for s in declared if s not in SOURCES]
        if unknown or not declared:
            found.append(f"`{path}`: sources `{cell}` are not a list of {', '.join(SOURCES)}")
        if path not in reach:
            continue
        reached = reach[path]
        stale = [s for s in declared if s in SOURCES and s not in reached]
        if stale:
            found.append(f"`{path}` no longer reaches {', '.join(stale)}: take it out of the "
                         "row, and the row out once the script reaches nothing")
        missing = [s for s in reached if s not in declared]
        if missing:
            found.append(f"`{path}` reaches {', '.join(missing)}, which its row does not "
                         "declare")
    counts = {
        "scripts": len(reach),
        "unit": sum(1 for sources in reach.values() if not sources),
        "rows": len(rows),
        "pending": sum(1 for _, kind, _, _ in rows if kind == "pending"),
        "system": sum(1 for _, kind, _, _ in rows if kind == "system"),
    }
    return found, counts


def tracked_scripts(root: Path) -> dict[str, str]:
    """Every tracked .py file under scripts/, by path, with its text."""
    run = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--", SCOPE],
                         capture_output=True, text=True, check=True)
    return {path: (root / path).read_text(encoding="utf-8", errors="replace")
            for path in run.stdout.split("\0") if path.endswith(".py")}


def check(root: Path = REPO_ROOT) -> int:
    table = root / TABLE
    if not table.is_file():
        print(f"python-selftest-layer: FAIL -- {TABLE} is missing", file=sys.stderr)
        return 1
    try:
        found, counts = judge(tracked_scripts(root), table.read_text(encoding="utf-8"))
    except LostSubject as exc:
        print(f"python-selftest-layer: FAIL -- {exc}", file=sys.stderr)
        return 1
    if found:
        print("python-selftest-layer: FAIL -- a selftest is outside the layer its table says:",
              file=sys.stderr)
        for f in found:
            print(f"  - {f}", file=sys.stderr)
        print(f"  The layer rule and the table are docs/deterministic-tests.md section 10; a "
              f"selftest brought to its fixtures takes its row out of {TABLE}.", file=sys.stderr)
        return 1
    print(f"python-selftest-layer: ok -- {counts['scripts']} script(s) with a selftest under "
          f"{SCOPE}/: {counts['unit']} in the unit layer, {counts['rows']} system-layer row(s) "
          f"({counts['pending']} pending a seam, {counts['system']} whose subject is the host)")
    return 0


TABLE_HEAD = """\
# The system layer of the Python selftests the Python selftest layer gate covers
# (scripts/lib/python_selftest_layer_gate.py; docs/deterministic-tests.md section 10).
# One row per script whose selftest reaches a source a unit selftest may not: kind pending is
# owed a seam between its judgement and its fact-gathering, and its row goes when it has one;
# kind system has the host as its subject. The gate holds each row to the sources its script
# reaches, both ways. A row is added only for a script whose subject is the host.
"""


def rows(root: Path = REPO_ROOT) -> int:
    """Print the row of each script that reaches a source and has none: kind pending, the census
    reason. With no table yet the table's head comes first, so the output is the first table."""
    table = root / TABLE
    have: set[str] = set()
    if table.is_file():
        have = {row[0] for row in parse_table(table.read_text(encoding="utf-8"))[0]}
    else:
        print(TABLE_HEAD + "\t".join(HEADER))
    world = World(tracked_scripts(root))
    for path, error in world.unreadable():
        print(f"python-selftest-layer: `{path}` does not parse ({error}); no row for it",
              file=sys.stderr)
    for path, s in sorted(world.population().items()):
        sources = world.reach(s)
        if sources and path not in have:
            print(f"{path}\tpending\t{','.join(sources)}\t{CENSUS_REASON}")
    return 0


HELPER = """\
import socket


def dial():
    return socket.create_connection(("host", 1))


def quiet():
    return 1


class Box:
    def open(self):
        return dial()
"""

FIXTURES = {
    "scripts/lib/fx_helper.py": HELPER,
    "scripts/lib/fx_stamp.py": "import time\n\nSTAMP = time.time()\n",
    "scripts/lib/fx_unit.py": (
        "import argparse\nimport time\n\n\ndef check():\n    time.sleep(1)\n\n\n"
        "def selftest():\n    text = \"time.sleep(1)\"  # time.sleep(2)\n    return len(text)\n\n\n"
        "def main():\n    args = argparse.ArgumentParser().parse_args()\n"
        "    if args.selftest:\n        return selftest()\n    return check()\n"),
    "scripts/lib/fx_shadow.py": (
        "import subprocess\n\n\ndef check():\n    subprocess.run([\"git\", \"status\"])\n\n\n"
        "def selftest():\n    def check(label):\n        return label\n\n"
        "    return check(\"x\")\n"),
    "scripts/lib/fx_direct.py": "import time\n\n\ndef selftest():\n    return time.monotonic()\n",
    "scripts/lib/fx_alias.py": ("import subprocess as sp\n\n\ndef run():\n"
                                "    return sp.run([\"git\"])\n\n\ndef selftest():\n"
                                "    return run()\n"),
    "scripts/lib/fx_from_name.py": ("from datetime import datetime\n\n\ndef selftest():\n"
                                    "    return datetime.now()\n"),
    "scripts/lib/fx_from.py": "from fx_helper import dial\n\n\ndef selftest():\n    dial()\n",
    "scripts/lib/fx_module.py": "import fx_helper as h\n\n\ndef selftest():\n    h.dial()\n",
    "scripts/lib/fx_star.py": "from fx_helper import *\n\n\ndef selftest():\n    dial()\n",
    "scripts/lib/fx_quiet.py": "from fx_helper import quiet\n\n\ndef selftest():\n    quiet()\n",
    "scripts/lib/fx_method.py": (
        "import threading\n\n\nclass Runner:\n    def go(self):\n"
        "        threading.Thread(target=print).start()\n\n\n"
        "def selftest():\n    Runner().go()\n"),
    "scripts/lib/fx_imported_method.py": ("from fx_helper import Box\n\n\ndef selftest():\n"
                                          "    Box().open()\n"),
    "scripts/lib/fx_dunder.py": (
        "import time\n\n\nclass Clocked:\n    def __init__(self):\n"
        "        self.at = time.time()\n\n\ndef selftest():\n    Clocked()\n"),
    "scripts/lib/fx_subclass.py": (
        "import threading\n\n\nclass Worker(threading.Thread):\n    pass\n\n\n"
        "def selftest():\n    Worker()\n"),
    "scripts/lib/fx_branch.py": (
        "import os\nimport random\nimport sys\n\n\ndef drive():\n    return random.random()\n\n\n"
        "def check():\n    os.system(\"true\")\n\n\ndef main(argv):\n"
        "    if argv == [\"--selftest\"]:\n        return drive()\n    return check()\n\n\n"
        "if __name__ == \"__main__\":\n    sys.exit(main(sys.argv[1:]))\n"),
    "scripts/lib/fx_table.py": (
        "import subprocess\nimport uuid\n\n\ndef fixture():\n    return uuid.uuid4()\n\n\n"
        "def check():\n    subprocess.run([\"git\"])\n\n\ndef main():\n"
        "    modes = {\"--check\": check, \"--selftest\": fixture}\n    return modes\n"),
    "scripts/lib/fx_guard.py": (
        "import secrets\nimport sys\n\n\ndef drive():\n    return secrets.token_hex()\n\n\n"
        "if __name__ == \"__main__\":\n    if \"--selftest\" in sys.argv:\n        drive()\n"),
    "scripts/lib/fx_seeded.py": (
        "import random\nfrom random import Random\n\n\ndef selftest():\n"
        "    return random.Random(7).random() + Random(seed=3).random()\n"),
    "scripts/lib/fx_unseeded.py": ("from random import Random\n\n\ndef selftest():\n"
                                   "    return Random().random()\n"),
    "scripts/lib/fx_top.py": "import fx_stamp\n\n\ndef selftest():\n    return 1\n",
    "scripts/lib/test_fx.py": (
        "import time\nfrom concurrent import futures\n\n\ndef helper():\n    time.sleep(1)\n\n\n"
        "def test_pool():\n    with futures.ThreadPoolExecutor() as pool:\n"
        "        return pool\n"),
    "scripts/host-bench/fx_sibling.py": "import os\n\n\ndef draw():\n    return os.urandom(4)\n",
    "scripts/host-bench/fx_bench.py": ("import fx_sibling\n\n\ndef selftest():\n"
                                       "    return fx_sibling.draw()\n"),
}
OUTSIDE = ("fx_helper.py", "fx_stamp.py", "fx_sibling.py")


def selftest() -> int:
    failures: list[str] = []

    def expect(name: str, got, want) -> None:
        ok = got == want
        print(f"  selftest -- {name}: {'ok' if ok else f'FAIL got {got!r} want {want!r}'}")
        if not ok:
            failures.append(name)

    world = World(FIXTURES)
    reach = {path.rpartition("/")[2]: list(world.reach(s))
             for path, s in world.population().items()}
    expect("only a file with a selftest entry is in the population", sorted(reach),
           sorted(leaf for leaf in (p.rpartition("/")[2] for p in FIXTURES)
                  if leaf not in OUTSIDE))
    expect("CONTROL: a selftest that calls no source is unit, a source in a comment or a string "
           "is no reach, and the other branch of main is not read", reach["fx_unit.py"], [])
    expect("a nested function hides the file's function of its name", reach["fx_shadow.py"], [])
    expect("a call of a source is a reach", reach["fx_direct.py"], ["clock"])
    expect("a module alias resolves (import subprocess as sp)", reach["fx_alias.py"],
           ["process"])
    expect("a name alias resolves (from datetime import datetime)", reach["fx_from_name.py"],
           ["clock"])
    expect("a function imported from scripts/lib brings what it reaches", reach["fx_from.py"],
           ["socket"])
    expect("a function of an imported module brings what it reaches (import m as h; h.f)",
           reach["fx_module.py"], ["socket"])
    expect("a star import brings what its names reach", reach["fx_star.py"], ["socket"])
    expect("CONTROL: an imported function that reaches nothing is no reach",
           reach["fx_quiet.py"], [])
    expect("a method reaches what it calls", reach["fx_method.py"], ["thread"])
    expect("a method of an imported class reaches what it calls",
           reach["fx_imported_method.py"], ["socket"])
    expect("a class brings what its dunder methods call", reach["fx_dunder.py"], ["clock"])
    expect("a subclass of a thread class is a thread", reach["fx_subclass.py"], ["thread"])
    expect("the --selftest branch of main is an entry, its other branch is not",
           reach["fx_branch.py"], ["random"])
    expect("a mode table's --selftest value is an entry", reach["fx_table.py"], ["random"])
    expect("the --selftest branch of the __main__ block is an entry", reach["fx_guard.py"],
           ["random"])
    expect("CONTROL: a generator the test seeds is no reach", reach["fx_seeded.py"], [])
    expect("a generator built with no seed draws the host's", reach["fx_unseeded.py"],
           ["random"])
    expect("an imported module's top level runs", reach["fx_top.py"], ["clock"])
    expect("a test_ function of a test_*.py file is an entry, a helper it does not call is not",
           reach["test_fx.py"], ["thread"])
    expect("an import finds the importing file's directory first", reach["fx_bench.py"],
           ["random"])
    expect("the source of a dotted name",
           [source_of(q, None) for q in ("time.sleep", "subprocess.CompletedProcess",
                                         "os.execvp", "uuid.uuid5",
                                         "concurrent.futures.ProcessPoolExecutor",
                                         "datetime.datetime.fromisoformat", "os.path.join")],
           ["clock", None, "process", None, "thread", None, None])

    header = "\t".join(HEADER)
    declared = {
        "fx_direct.py": "pending\tclock\treads the wall clock",
        "fx_alias.py": "system\tprocess\truns git over a fixture tree",
        "fx_from_name.py": "pending\tclock\treads the wall clock",
        "fx_from.py": "pending\tsocket\tdials through the helper",
        "fx_module.py": "pending\tsocket\tdials through the helper",
        "fx_star.py": "pending\tsocket\tdials through the helper",
        "fx_method.py": "pending\tthread\tstarts a thread",
        "fx_imported_method.py": "pending\tsocket\tdials through the helper",
        "fx_dunder.py": "pending\tclock\treads the wall clock",
        "fx_subclass.py": "pending\tthread\tstarts a thread",
        "fx_branch.py": "pending\trandom\tdraws the host entropy",
        "fx_table.py": "pending\trandom\tdraws the host entropy",
        "fx_guard.py": "pending\trandom\tdraws the host entropy",
        "fx_unseeded.py": "pending\trandom\tdraws the host entropy",
        "fx_top.py": "pending\tclock\tthe module it imports reads the wall clock",
        "test_fx.py": "pending\tthread\tstarts a pool",
        "fx_bench.py": "pending\trandom\tdraws the host entropy",
    }
    where = {path.rpartition("/")[2]: path for path in FIXTURES}

    def table(change: dict[str, str | None] | None = None, head: str = header) -> str:
        merged = dict(declared)
        for name, row in (change or {}).items():
            if row is None:
                merged.pop(name, None)
            else:
                merged[name] = row
        lines = ["# a comment line", head]
        lines += [f"{where.get(name, 'scripts/lib/' + name)}\t{row}"
                  for name, row in merged.items()]
        return "\n".join(lines) + "\n"

    def has(text: str, fragment: str, files: dict[str, str] = FIXTURES) -> bool:
        return any(fragment in f for f in judge(files, text)[0])

    expect("the declared tree is green", judge(FIXTURES, table())[0], [])
    expect("a script that reaches a source with no row is a finding, with its trail",
           has(table({"fx_from.py": None}),
               "fx_from.py` reaches socket and has no row: hand its selftest the facts behind "
               "a seam, or give it a row whose reason says why the host is its subject (socket: "
               "selftest -> dial of scripts/lib/fx_helper.py -> socket.create_connection)"),
           True)
    expect("a row for a file with no selftest entry is a finding",
           has(table({"fx_helper.py": "pending\tsocket\tthe helper"}),
               "fx_helper.py` has a row but is not a tracked script"), True)
    expect("a row for a file that is not tracked is a finding",
           has(table({"gone.py": "pending\tclock\tgone"}),
               "gone.py` has a row but is not a tracked script"), True)
    expect("a second row is a finding",
           has(table() + f"{where['fx_direct.py']}\tpending\tclock\tagain\n",
               "fx_direct.py` has 2 rows"), True)
    expect("a row with no reason is a finding",
           has(table({"fx_direct.py": "pending\tclock\t"}), "a row with no reason"), True)
    expect("a stale source is a finding",
           has(table({"fx_direct.py": "pending\tclock,socket\tr"}),
               "fx_direct.py` no longer reaches socket"), True)
    expect("a row for a script that reaches nothing is a finding",
           has(table({"fx_unit.py": "pending\tclock\tr"}), "fx_unit.py` no longer reaches clock"),
           True)
    expect("a source the row leaves out is a finding",
           has(table({"fx_method.py": "pending\tclock\tr"}),
               "fx_method.py` reaches thread, which its row does not declare"), True)
    expect("an unknown kind is a finding",
           has(table({"fx_direct.py": "later\tclock\tr"}), "kind `later` is not one"), True)
    expect("an unknown source is a finding",
           has(table({"fx_direct.py": "pending\twall\tr"}), "sources `wall` are not"), True)
    expect("a row of three cells is a finding, not dropped",
           has(table({"fx_direct.py": "pending\tclock"}), "a row not read as 4"), True)
    expect("a header that is not the table's is a finding",
           has(table(head="path\tsources\treason"), "the table's header is not"), True)
    expect("a file that does not parse is a finding",
           has(table(), "fx_broken.py` does not parse",
               {**FIXTURES, "scripts/lib/fx_broken.py": "def selftest(:\n"}), True)
    lost = []
    for name, (files, text) in {
        "an empty population": ({"scripts/lib/fx_helper.py": HELPER}, table()),
        "a table of no row": (FIXTURES, header + "\n"),
    }.items():
        try:
            judge(files, text)
        except LostSubject:
            lost.append(name)
    expect("an empty population or table is refused, never a pass", lost,
           ["an empty population", "a table of no row"])
    print(f"python-selftest-layer selftest: "
          f"{'OK' if not failures else 'FAILED: ' + ', '.join(failures)}")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--selftest", action="store_true")
    group.add_argument("--rows", action="store_true",
                       help="print the row of each reaching script the table lacks")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    return rows() if args.rows else check()


if __name__ == "__main__":
    sys.exit(main())
