#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4730 (no register item) -- a unit test module reaches no wall clock, no host socket, no
thread of its own, no host randomness and no process; a module that must is a row of the system
layer's table, with its reason.

The design is `docs/deterministic-tests.md` (sections 4 and 5): a unit test is a function of its
script and its seed, and runs in the simulated world of `tests::sim`; what needs the host is the
system layer, declared module by module.

## The defect

A test that reads the wall clock, binds the host's sockets or starts a thread of its own is a
function of the host's schedule as well as of its script, and its verdict can change from run
to run with nothing in the tree changed. The step test whose flake started the design was one: it
waited five seconds of the wall clock for a stand-in on a thread of its own, and a third of its
runs in one build form ended red. Nothing held a module to the unit layer once it had moved, and
nothing said which modules had not moved yet.

## What is derived

The POPULATION is every tracked `.rs` file of a crate in `COVERED` whose path is a test's: in a
`tests/` or `benches/` directory, or named `tests.rs` or `*_tests.rs`. Each is read with its
comments and the bodies of its literals blanked (`rust_comments.py`), so a source named in prose
or in a message is not a reach.

A module REACHES a source when its text names one of the source's needles (`SOURCES`), or when it
takes from another module of the population (a `use super::..` or `use crate::tests::..` import,
or such a path in its code) an item that reaches it. An item's text is its definition and, for a
type, every impl block of that type in its file; an item reaches what its text names, what the
items of its own module it names reach, and what the items its module imports and its text names
reach, to a fixed point. A `super` inside an inline module stays in its file.

The read through imports is not decoration. Read on the tree this was written against: the module
of the open's admission heap names no source and opens the host's links through the test root's
helper that opens a session; a read of what a module names alone put it in the unit layer.

## The table

`docs/deterministic-tests/system-layer.tsv`: a header, then one row per system-layer module: its
path, its kind (`pending`: owed a move to the simulated world; `system`: the host is its
subject), the sources it reaches and the reason. A finding is

- a module that reaches a source and has no row;
- a row for a path that is not a tracked test module of a covered crate, or a second row;
- a row whose kind is not one of `KINDS`, which names a source that is not one, or no source, or
  which gives no reason;
- a row that declares a source its module no longer reaches (the row is stale: take the source
  out, and the row once its module reaches nothing), or that leaves out a source it reaches;
- a population of no module, or a table of no row: the gate lost its subject.

The first table listed every module that reached a source on the day it landed. A migration
deletes a row; a row is added only for a module whose subject is the host.

## What this does not claim

- That a unit-layer module is deterministic. The simulated world's own order (a hash map's,
  the engine's real sleeps) is the design's audit, not a needle here.
- Name resolution beyond the text: a source reached through a macro, a re-export, a type whose
  impl block is in another file, or code outside the population (a product item) is not seen,
  and an integration test target is a crate of its own, read for what it names alone.
- That a `cfg` builds the module: a source under a `cfg` no lane builds still counts.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rust_comments import strip_comments  # noqa: E402  -- after the path insert that finds it

REPO_ROOT = Path(__file__).resolve().parents[2]
TABLE = "docs/deterministic-tests/system-layer.tsv"

# The crates whose test modules are held to the layer rule.
COVERED = ("wz-capi-coop",)

HEADER = ("path", "kind", "sources", "reason")
KINDS = ("pending", "system")

# What a unit test module may not reach, by source; each needle is read in text with comments and
# literal bodies blanked.
SOURCES: dict[str, tuple[str, ...]] = {
    "clock": (r"\bInstant::now\b", r"\bSystemTime\b", r"\bthread::sleep\b", r"\bPosixClock\b"),
    "socket": (r"\bUdpSocket\b", r"\bTcpListener\b", r"\bTcpStream\b", r"\bPosixLinks\b",
               r"\bhost_links\b", r"\bPosixTcpDial\b", r"\bRouter::start"),
    "thread": (r"\bthread::spawn\b", r"\bthread::Builder\b"),
    "random": (r"\bPosixEntropy\b", r"\brand::", r"\bOsRng\b", r"\bgetrandom\b"),
    "process": (r"\bCommand::new\b",),
}
NEEDLES = {source: [re.compile(p) for p in patterns] for source, patterns in SOURCES.items()}

IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
# A top-level item of a file: rustfmt puts each at the first column, and an item of an inline
# module or of an impl block is indented.
ITEM_HEAD = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?(?:(?:async|unsafe|const|extern)\s+)*"
                       r"(?:fn|type|const|static|struct|enum|union|trait)\s+(" + IDENT + ")", re.M)
IMPL_HEAD = re.compile(r"^(?:unsafe\s+)?impl\b", re.M)
INLINE_MOD = re.compile(r"\bmod\s+" + IDENT + r"\s*\{")
USE_DECL = re.compile(r"\buse\s+([^;]*);")
PATH_EXPR = re.compile(r"(?<![A-Za-z0-9_:])((?:super|crate|self)(?:::" + IDENT + ")+)")


class LostSubject(Exception):
    """A population of no module or a table of no row: the gate has nothing to judge, which is
    never a pass."""


def direct(text: str) -> list[str]:
    """The sources whose needles the text names, in the order of the sources' table."""
    return [source for source, needles in NEEDLES.items() if any(n.search(text) for n in needles)]


def is_test_path(rel: str) -> bool:
    """Whether a path below a crate's directory is a test module's."""
    parts = rel.split("/")
    leaf = parts[-1]
    return leaf.endswith(".rs") and ("tests" in parts[:-1] or "benches" in parts[:-1]
                                     or leaf == "tests.rs" or leaf.endswith("_tests.rs"))


def module_path(rel: str) -> tuple[str, ...] | None:
    """The module a file below a crate's directory is, as its path from the crate's root; None
    outside src/, where an integration test is a crate of its own that nothing here imports
    from."""
    if not rel.startswith("src/") or not rel.endswith(".rs"):
        return None
    segs = rel[len("src/"):-len(".rs")].split("/")
    if segs[-1] == "mod":
        segs.pop()
    if segs in (["lib"], ["main"]):
        segs = []
    return ("crate", *segs)


def span_end(text: str, start: int) -> int:
    """Where the item starting at a position ends: after the brace that closes its body, or after
    a semicolon outside every bracket, whichever comes first."""
    depth = 0
    for i in range(start, len(text)):
        ch = text[i]
        if ch in "{[(":
            depth += 1
        elif ch in "}])":
            depth -= 1
            if depth == 0 and ch == "}":
                return i + 1
        elif ch == ";" and depth == 0:
            return i + 1
    return len(text)


def impl_self(head: str) -> str | None:
    """The last segment of the type an impl block's head (up to its body) is for."""
    rest = re.sub(r"^(?:unsafe\s+)?impl\s*", "", head)
    if rest.startswith("<"):
        depth, end = 0, len(rest)
        for j, ch in enumerate(rest):
            if ch == "<":
                depth += 1
            elif ch == ">" and (j == 0 or rest[j - 1] != "-"):
                depth -= 1
                if depth == 0:
                    end = j + 1
                    break
        rest = rest[end:]
    rest = re.split(r"\bwhere\b", rest)[0]
    rest = re.split(r"\bfor\b", rest)[-1]
    rest = re.sub(r"^[\s&]*(?:'" + IDENT + r"\s+)?(?:mut\s+|dyn\s+)?", "", rest)
    m = re.match(IDENT + "(?:::" + IDENT + ")*", rest)
    return m.group(0).split("::")[-1] if m else None


def items_of(text: str) -> dict[str, list[tuple[int, int]]]:
    """Each top-level item of a file by name: the span of its definition and, for a type, of each
    impl block for it."""
    items: dict[str, list[tuple[int, int]]] = {}
    for m in ITEM_HEAD.finditer(text):
        items.setdefault(m.group(1), []).append((m.start(), span_end(text, m.start())))
    for m in IMPL_HEAD.finditer(text):
        end = span_end(text, m.start())
        body = text.find("{", m.start())
        name = impl_self(text[m.start():end if body < 0 else body])
        if name:
            items.setdefault(name, []).append((m.start(), end))
    return items


def inline_mods(text: str) -> list[tuple[int, int]]:
    return [(m.start(), span_end(text, m.end() - 1)) for m in INLINE_MOD.finditer(text)]


def depth_at(mods: list[tuple[int, int]], pos: int) -> int:
    """How many inline modules of its file hold a position."""
    return sum(1 for a, b in mods if a <= pos < b)


def split_top(text: str) -> list[str]:
    """The text cut at each comma outside braces; empty parts dropped."""
    parts: list[str] = []
    depth, cur = 0, []
    for ch in text:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return [p for p in parts if p.strip()]


def expand_use(tree: str) -> list[list[str]]:
    """The paths a use tree names, each as its segments; a rename keeps the path it renames."""
    tree = tree.strip()
    brace = tree.find("{")
    if brace < 0:
        path = re.sub(r"\s+as\s+" + IDENT + "$", "", tree)
        return [[seg for seg in re.sub(r"\s+", "", path).split("::") if seg]]
    prefix = [seg for seg in re.sub(r"\s+", "", tree[:brace]).split("::") if seg]
    out: list[list[str]] = []
    for part in split_top(tree[brace + 1:tree.rfind("}")]):
        for sub in expand_use(part):
            out.append(prefix if sub == ["self"] else prefix + sub)
    return out


class Module:
    """One file of the population, as the reach reads it."""

    def __init__(self, rel: str, source: str) -> None:
        self.module = module_path(rel)
        self.text = strip_comments(source, blank_literals=True)
        self.items = items_of(self.text)
        self.mods = inline_mods(self.text)
        self.imports: list[tuple[tuple[str, ...], str]] = []


def resolve(segs: list[str], at: tuple[str, ...] | None, depth: int,
            modules: dict[tuple[str, ...], Module]) -> tuple[tuple[str, ...], str] | None:
    """The module of the population and the item a path names from a file that is the module
    at, depth inline modules deep; None for a path that stays in its file or leaves the
    population."""
    if at is None or not segs:
        return None
    if segs[0] == "crate":
        base, rest = ("crate",), segs[1:]
    elif segs[0] == "super":
        k = 0
        while k < len(segs) and segs[k] == "super":
            k += 1
        if k <= depth:
            return None
        up = k - depth
        if up >= len(at):
            return None
        base, rest = at[:len(at) - up], segs[k:]
    else:
        return None
    for n in range(len(rest) - 1, -1, -1):
        module = base + tuple(rest[:n])
        if module in modules:
            return module, rest[n]
    return None


def refs_in(mod: Module, a: int, b: int,
            modules: dict[tuple[str, ...], Module]) -> list[tuple[tuple[str, ...], str]]:
    """What the imports and paths of a span of a file take from other modules of the
    population."""
    out: list[tuple[tuple[str, ...], str]] = []
    if mod.module is None:
        return out
    part = mod.text[a:b]
    for m in USE_DECL.finditer(part):
        depth = depth_at(mod.mods, a + m.start())
        for segs in expand_use(m.group(1)):
            hit = resolve(segs, mod.module, depth, modules)
            if hit:
                out.append(hit)
    for m in PATH_EXPR.finditer(part):
        hit = resolve(m.group(1).split("::"), mod.module, depth_at(mod.mods, a + m.start()),
                      modules)
        if hit:
            out.append(hit)
    return out


def named(text: str, names: set[str]) -> set[str]:
    """The names a text refers to: not as a method, nor as a later segment of a path."""
    if not names:
        return set()
    alternatives = "|".join(re.escape(n) for n in sorted(names, key=lambda n: (-len(n), n)))
    pattern = re.compile(r"(?<![A-Za-z0-9_:])(?<![^.]\.)(" + alternatives + r")\b")
    return set(pattern.findall(text))


def taken(refs: list[tuple[tuple[str, ...], str]], text: str,
          modules: dict[tuple[str, ...], Module]) -> list[tuple[tuple[str, ...], str]]:
    """The references with each glob replaced by the items of its module the text refers to,
    and every name no item of its module carries dropped."""
    out: list[tuple[tuple[str, ...], str]] = []
    for module, item in refs:
        items = modules[module].items
        if item == "*":
            out.extend((module, n) for n in sorted(named(text, set(items))))
        elif item in items:
            out.append((module, item))
    return out


def crate_of(path: str) -> str:
    return path[len("crates/"):].partition("/")[0]


def reach_of(files: dict[str, str]) -> dict[str, list[str]]:
    """The sources each module of the population reaches, by path."""
    crates: dict[str, dict[tuple[str, ...], Module]] = {}
    mods: dict[str, Module] = {}
    for path, source in files.items():
        mod = Module(path[len("crates/"):].partition("/")[2], source)
        mods[path] = mod
        if mod.module is not None:
            crates.setdefault(crate_of(path), {})[mod.module] = mod
    for path, mod in mods.items():
        modules = crates.get(crate_of(path), {})
        mod.imports = taken(refs_in(mod, 0, len(mod.text), modules), mod.text, modules)

    reach: dict[tuple[str, tuple[str, ...], str], set[str]] = {}
    edges: dict[tuple[str, tuple[str, ...], str], set[tuple[str, tuple[str, ...], str]]] = {}
    for crate, modules in crates.items():
        for module, mod in modules.items():
            imported = {item for _, item in mod.imports}
            for name, spans in mod.items.items():
                key = (crate, module, name)
                text = "\n".join(mod.text[a:b] for a, b in spans)
                reach[key] = set(direct(text))
                out: set[tuple[str, tuple[str, ...], str]] = set()
                for a, b in spans:
                    out.update((crate, m, i) for m, i in
                               taken(refs_in(mod, a, b, modules), text, modules))
                out.update((crate, module, n) for n in named(text, set(mod.items) - {name}))
                refer = named(text, imported)
                out.update((crate, m, i) for m, i in mod.imports if i in refer)
                out.discard(key)
                edges[key] = out
    changed = True
    while changed:
        changed = False
        for key, out in edges.items():
            have = reach[key]
            for other in out:
                more = reach[other] - have
                if more:
                    have |= more
                    changed = True

    result: dict[str, list[str]] = {}
    for path, mod in mods.items():
        got = set(direct(mod.text))
        for module, item in mod.imports:
            got |= reach[(crate_of(path), module, item)]
        result[path] = [source for source in SOURCES if source in got]
    return result


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
    """Every finding of a population (path to text) against the table's text, and the counts of
    what is placed. Raises LostSubject on a population or a table that reads as empty."""
    rows, found = parse_table(table_text)
    if not files or not rows:
        raise LostSubject(f"read {len(files)} test module(s) and {len(rows)} table row(s); the "
                          "gate lost its subject and must not pass over an empty population")
    reach = reach_of(files)
    seen: dict[str, int] = {}
    for path, _, _, _ in rows:
        seen[path] = seen.get(path, 0) + 1
    for path, sources in sorted(reach.items()):
        if sources and path not in seen:
            found.append(f"`{path}` reaches {', '.join(sources)} and has no row: move it to the "
                         "simulated world, or give it a row whose reason says why the host is "
                         "its subject")
    for path, n in sorted(seen.items()):
        if n > 1:
            found.append(f"`{path}` has {n} rows; give it one")
        if path not in reach:
            found.append(f"`{path}` has a row but is not a tracked test module of "
                         f"{', '.join(COVERED)}")
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
                         "row, and the row out once the module reaches nothing")
        missing = [s for s in reached if s not in declared]
        if missing:
            found.append(f"`{path}` reaches {', '.join(missing)}, which its row does not "
                         "declare")
    counts = {
        "modules": len(reach),
        "unit": sum(1 for sources in reach.values() if not sources),
        "rows": len(rows),
        "pending": sum(1 for _, kind, _, _ in rows if kind == "pending"),
        "system": sum(1 for _, kind, _, _ in rows if kind == "system"),
    }
    return found, counts


def tracked_population(root: Path) -> dict[str, str]:
    """Every tracked test module of the covered crates, by path, with its text."""
    run = subprocess.run(["git", "-C", str(root), "ls-files", "--"]
                         + [f"crates/{crate}" for crate in COVERED],
                         capture_output=True, text=True, check=True)
    files: dict[str, str] = {}
    for path in run.stdout.split():
        if crate_of(path) in COVERED and is_test_path(path[len("crates/"):].partition("/")[2]):
            files[path] = (root / path).read_text(encoding="utf-8")
    return files


def check(root: Path = REPO_ROOT) -> int:
    table = root / TABLE
    if not table.is_file():
        print(f"deterministic-test-layer: FAIL -- {TABLE} is missing", file=sys.stderr)
        return 1
    try:
        found, counts = judge(tracked_population(root), table.read_text(encoding="utf-8"))
    except LostSubject as exc:
        print(f"deterministic-test-layer: FAIL -- {exc}", file=sys.stderr)
        return 1
    if found:
        print("deterministic-test-layer: FAIL -- a test module is outside the layer its table "
              "says:", file=sys.stderr)
        for f in found:
            print(f"  - {f}", file=sys.stderr)
        print(f"  The layer rule and the table are docs/deterministic-tests.md sections 4 and 5; "
              f"a module moved to the simulated world takes its row out of {TABLE}.",
              file=sys.stderr)
        return 1
    print(f"deterministic-test-layer: ok -- {counts['modules']} test module(s) of "
          f"{', '.join(COVERED)}: {counts['unit']} in the unit layer, {counts['rows']} "
          f"system-layer row(s) ({counts['pending']} pending a move to the simulated world, "
          f"{counts['system']} whose subject is the host)")
    return 0


ROOT_FIXTURE = """\
use std::time::Instant;

pub(crate) fn host_open() -> u32 {
    let _ = Instant::now();
    0
}

fn plain() -> u32 {
    1
}

fn through_plain() -> u32 {
    host_open() + plain()
}

struct Stand;

impl Stand {
    fn start() {
        std::thread::spawn(|| {});
    }
}

mod unit;
"""

FIXTURES = {
    "src/tests.rs": ROOT_FIXTURE,
    "src/tests/unit.rs": "use super::plain;\n\n#[test]\nfn t() {\n    let _ = plain();\n}\n",
    "src/tests/clocked.rs": "#[test]\nfn t() {\n    let _ = std::time::Instant::now();\n}\n",
    "src/tests/through.rs": "use super::host_open;\n\n#[test]\nfn t() {\n    host_open();\n}\n",
    "src/tests/chained.rs": "use super::through_plain;\n\nfn t() {\n    through_plain();\n}\n",
    "src/tests/typed.rs": "use super::Stand;\n\nfn t() {\n    Stand::start();\n}\n",
    "src/tests/nested.rs": ("mod inner {\n    use super::super::host_open;\n\n"
                            "    fn t() {\n        host_open();\n    }\n}\n"),
    "src/tests/own.rs": ("fn here() {}\n\nmod inner {\n    use super::*;\n\n"
                         "    fn t() {\n        here();\n    }\n}\n"),
    "src/tests/pathed.rs": "fn t() {\n    super::host_open();\n}\n",
    "src/tests/quoted.rs": ("// Instant::now() in prose\n#[test]\nfn t() {\n"
                            "    let _ = \"std::thread::spawn\";\n}\n"),
    "tests/integration.rs": ("use std::net::UdpSocket;\n\nfn t() {\n"
                             "    let _ = UdpSocket::bind;\n}\n"),
}


def selftest() -> int:
    failures: list[str] = []

    def expect(name: str, got, want) -> None:
        ok = got == want
        print(f"  selftest -- {name}: {'ok' if ok else f'FAIL got {got!r} want {want!r}'}")
        if not ok:
            failures.append(name)

    crate = f"crates/{COVERED[0]}/"
    files = {crate + rel: text for rel, text in FIXTURES.items()}
    reach = {path[len(crate):]: sources for path, sources in reach_of(files).items()}
    expect("a module that names a needle reaches its source", reach["src/tests/clocked.rs"],
           ["clock"])
    expect("an item imported from the test root brings what it reaches",
           reach["src/tests/through.rs"], ["clock"])
    expect("an item reaches what the items of its own module it names reach",
           reach["src/tests/chained.rs"], ["clock"])
    expect("a type brings what its impl blocks reach", reach["src/tests/typed.rs"], ["thread"])
    expect("super::super inside an inline module is the test root", reach["src/tests/nested.rs"],
           ["clock"])
    expect("a path in code takes the item it names", reach["src/tests/pathed.rs"], ["clock"])
    expect("a glob inside an inline module stays in its file", reach["src/tests/own.rs"], [])
    expect("a needle in a comment or a string is no reach", reach["src/tests/quoted.rs"], [])
    expect("CONTROL: an import from the root is no reach by itself", reach["src/tests/unit.rs"],
           [])
    expect("an integration target reaches what it names", reach["tests/integration.rs"],
           ["socket"])

    header = "\t".join(HEADER)
    rows = {
        "src/tests.rs": "system\tclock,thread\tthe root",
        "src/tests/clocked.rs": "pending\tclock\treads the wall clock",
        "src/tests/through.rs": "pending\tclock\tthrough the root",
        "src/tests/chained.rs": "pending\tclock\tthrough the root",
        "src/tests/typed.rs": "pending\tthread\tthe stand-in's thread",
        "src/tests/nested.rs": "pending\tclock\tthrough the root",
        "src/tests/pathed.rs": "pending\tclock\tthrough the root",
        "tests/integration.rs": "system\tsocket\tthe host's sockets are its subject",
    }

    def table(change: dict[str, str | None] | None = None, head: str = header) -> str:
        merged = dict(rows)
        for path, row in (change or {}).items():
            if row is None:
                merged.pop(path, None)
            else:
                merged[path] = row
        lines = ["# a comment line", head] + [f"{crate}{p}\t{r}" for p, r in merged.items()]
        return "\n".join(lines) + "\n"

    def has(text: str, fragment: str) -> bool:
        return any(fragment in f for f in judge(files, text)[0])

    expect("the declared tree is green", judge(files, table())[0], [])
    expect("a module that reaches a source with no row is a finding",
           has(table({"src/tests/clocked.rs": None}), "clocked.rs` reaches clock and has no row"),
           True)
    expect("a row for a file that is not tracked is a finding",
           has(table({"src/tests/gone.rs": "pending\tclock\tgone"}),
               "gone.rs` has a row but is not a tracked test module"), True)
    expect("a row with no reason is a finding",
           has(table({"src/tests/clocked.rs": "pending\tclock\t"}), "a row with no reason"), True)
    expect("a stale source is a finding",
           has(table({"src/tests/clocked.rs": "pending\tclock,socket\tr"}),
               "clocked.rs` no longer reaches socket"), True)
    expect("a row for a module that reaches nothing is a finding",
           has(table({"src/tests/quoted.rs": "pending\tclock\tr"}),
               "quoted.rs` no longer reaches clock"), True)
    expect("a source the row leaves out is a finding",
           has(table({"src/tests/typed.rs": "pending\tclock\tr"}),
               "typed.rs` reaches thread, which its row does not declare"), True)
    expect("an unknown kind is a finding",
           has(table({"src/tests/clocked.rs": "later\tclock\tr"}), "kind `later` is not one"),
           True)
    expect("an unknown source is a finding",
           has(table({"src/tests/clocked.rs": "pending\twall\tr"}), "sources `wall` are not"),
           True)
    expect("a row of three cells is a finding, not dropped",
           has(table({"src/tests/clocked.rs": "pending\tclock"}), "a row not read as 4"), True)
    expect("a header that is not the table's is a finding",
           has(table(head="path\tsources\treason"), "the table's header is not"), True)
    lost = []
    for name, (population, text) in {
        "an empty population": ({}, table()),
        "a table of no row": (files, header + "\n"),
    }.items():
        try:
            judge(population, text)
        except LostSubject:
            lost.append(name)
    expect("an empty population or table is refused, never a pass", lost,
           ["an empty population", "a table of no row"])

    expect("a use tree expands to its paths",
           expand_use("super::{a, b::{c, d as e}, self}"),
           [["super", "a"], ["super", "b", "c"], ["super", "b", "d"], ["super"]])
    expect("an impl head names the type it is for",
           [impl_self(h) for h in ("impl Drop for Router ", "impl<F: Fn() -> bool> Foo<F> ",
                                   "impl<'a> X for &'a Y<'a> ")], ["Router", "Foo", "Y"])
    expect("a test path is a test module's",
           [is_test_path(r) for r in ("src/tests.rs", "src/tests/x.rs", "tests/x.rs",
                                      "src/a_tests.rs", "src/engine.rs", "benches/b.rs")],
           [True, True, True, True, False, True])
    print(f"deterministic-test-layer selftest: "
          f"{'OK' if not failures else 'FAILED: ' + ', '.join(failures)}")
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
