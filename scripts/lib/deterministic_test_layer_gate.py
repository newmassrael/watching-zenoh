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

The COVERED crates are every crate with a tracked manifest below `crates/`: a `Cargo.toml` that
declares a `[package]`, at any depth; a file belongs to the deepest of them whose directory holds
it. The POPULATION is every tracked `.rs` file of a covered crate whose path is a test's: in a
`tests/` or `benches/` directory, or named `tests.rs` or `*_tests.rs`. Each is read with its
comments and the bodies of its literals blanked (`rust_comments.py`), so a source named in prose
or in a message is not a reach.

A module's PLACE is the target it is compiled into and its path from that target's root. The
targets are cargo's: `src/lib.rs`, `src/main.rs`, each `src/bin/*`, `tests/*`, `benches/*` and
`examples/*` (a file, or a directory's `main.rs`), each a crate of its own, and every target path
a manifest names. Each target's module tree is walked from its root through the `mod name;`
declarations of its files, product files too, by the compiler's rule: a `#[path]` is read from
the declaring file's directory; a root or a `mod.rs` holds its children in its own directory and
any other file in the directory of its name; an inline module adds its name. A file the walk
reaches from several targets (a support module two test targets declare) has a place in each; a
test file no walk reaches is placed by its path alone, where the compiler would look for it.

A module REACHES a source when its text names one of the source's needles (`SOURCES`), or when it
takes from another module of the population placed in the same target an item that reaches it: a
`use` of a `crate::`, `super::` or `self::` path, or of a path whose first segment is a file
module it declares (`mod common; use common::..`), or such a path in its code. An item's text is
its definition and, for a type, every impl block of that type in its file; an item reaches what
its text names, what the items of its own module it names reach, and what the items its module
imports and its text names reach, to a fixed point. A `super`, a `self` or a declared module's
name inside an inline module stays in its file.

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
  impl block is in another file, or code outside the population (a product item) is not seen;
  a module an `include!` brings, or a `path` given by `cfg_attr`, is not walked.
- That a `cfg` builds the module: a source under a `cfg` no lane builds still counts.

## R4745 (no register item) -- every crate

The gate first covered `wz-capi-coop` alone, whose test modules sit under `src/tests` of one
library target, and placed a module by its path. Every crate is covered now, and a module is
placed by the module tree of its target: a file under `tests/it/files/` takes its helpers from
`crate::..` of the `tests/it` target, and one a `#[path]` brings from another directory or
another crate is the module its declaration names. `--rows` prints a row for each module that
reaches a source and has none: the census that put every crate in the table at once.
"""

from __future__ import annotations

import argparse
import functools
import posixpath
import re
import subprocess
import sys
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rust_comments import strip_comments  # noqa: E402  -- after the path insert that finds it

REPO_ROOT = Path(__file__).resolve().parents[2]
TABLE = "docs/deterministic-tests/system-layer.tsv"

# The crates whose test modules are the interoperation suites: another implementation of the
# protocol over the host is their subject, so the census gives their modules kind `system` and
# every other crate's kind `pending`.
SYSTEM_CRATES = ("crates/wz-integration-tests", "crates/wz-host-interop-tests")
CENSUS_REASON = "census 2026-11-28: reached before the crate joined the gate"

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
INLINE_MOD = re.compile(r"\bmod\s+(" + IDENT + r")\s*\{")
# A `mod name;` declaration: rustfmt puts each on a line of its own, after any attribute on it.
MOD_DECL = re.compile(r"^[ \t]*(?:#\[[^\]\n]*\][ \t]*)*(?:pub(?:\([^)]*\))?[ \t]+)?mod[ \t]+("
                      + IDENT + r")[ \t]*;", re.M)
MOD_DECL_HINT = re.compile(r"\bmod\s+" + IDENT + r"\s*;")
PATH_ATTR = re.compile(r'#\[\s*path\s*=\s*"([^"\\]*)"\s*\]')
PACKAGE = re.compile(r"^\s*\[package\]\s*$", re.M)
# A target root cargo finds by itself, as a path below its crate's directory.
TARGET_ROOT = re.compile(r"^(?:src/(?:lib|main)\.rs|(?:src/bin|tests|benches|examples)/"
                         r"(?:[^/]+\.rs|[^/]+/main\.rs))$")
TARGET_TABLES = ("[lib]", "[[bin]]", "[[test]]", "[[bench]]", "[[example]]")
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


def owner(path: str, crates: Iterable[str]) -> str:
    """The deepest covered crate whose directory holds a path; the first directory below
    `crates/` for a path no covered crate holds."""
    best = ""
    for crate in crates:
        if path.startswith(crate + "/") and len(crate) > len(best):
            best = crate
    return best or "/".join(path.split("/")[:2])


def covered_crates(manifests: Mapping[str, str]) -> list[str]:
    """The directory of each manifest below `crates/` that declares a package: the workspace's
    own manifest and a virtual one are no crate."""
    return sorted(posixpath.dirname(path) for path, text in manifests.items()
                  if path.startswith("crates/") and path.count("/") >= 2
                  and PACKAGE.search(text))


def target_paths(manifest: str) -> list[str]:
    """The `path` of each target table of a manifest, relative to its crate's directory."""
    out: list[str] = []
    in_target = False
    for line in manifest.splitlines():
        cell = line.strip()
        if cell.startswith("["):
            in_target = cell in TARGET_TABLES
            continue
        m = re.match(r'path\s*=\s*"([^"]*)"', cell)
        if in_target and m:
            out.append(m.group(1))
    return out


def derived_place(path: str, crate: str,
                  tree: Mapping[str, str]) -> tuple[str, tuple[str, ...]] | None:
    """The target root and the module a file is by its path alone, where the compiler would look
    for its declaration; None outside the directories of a crate's targets."""
    rel = path[len(crate) + 1:]
    if not rel.endswith(".rs"):
        return None
    parts = rel[:-len(".rs")].split("/")
    if parts[0] in ("tests", "benches", "examples") or parts[:2] == ["src", "bin"]:
        k = 3 if parts[0] == "src" else 2
        if len(parts) <= k:
            root, segs = rel, []
        else:
            root, segs = "/".join(parts[:k]) + "/main.rs", parts[k:]
        if segs == ["main"]:
            segs = []
    elif parts[0] == "src":
        lone_main = f"{crate}/src/lib.rs" not in tree and f"{crate}/src/main.rs" in tree
        root = "src/main.rs" if lone_main else "src/lib.rs"
        segs = parts[1:]
        if segs in (["lib"], ["main"]):
            segs = []
    else:
        return None
    if segs and segs[-1] == "mod":
        segs = segs[:-1]
    return f"{crate}/{root}", ("crate", *segs)


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


def attrs_before(text: str, pos: int) -> int:
    """Where the outer attributes that end at a position start: the position itself when none
    does."""
    start = pos
    while True:
        j = start
        while j > 0 and text[j - 1].isspace():
            j -= 1
        if j == 0 or text[j - 1] != "]":
            return start
        depth, k = 0, j - 1
        while k >= 0:
            if text[k] == "]":
                depth += 1
            elif text[k] == "[":
                depth -= 1
                if depth == 0:
                    break
            k -= 1
        if k <= 0 or text[k - 1] != "#":
            return start
        start = k - 1


def depth_at(mods: list[tuple[int, int]], pos: int) -> int:
    """How many inline modules of its file hold a position."""
    return sum(1 for a, b in mods if a <= pos < b)


def declared(source: str, blanked: str | None = None) -> list[tuple[str, tuple[str, ...],
                                                                 str | None]]:
    """Each `mod name;` a file declares: its name, the inline modules that hold it, outermost
    first, and the value of its `#[path]`. The declarations are found in the text with comments
    and literal bodies blanked, and a `#[path]` is read at the same place in the text with only
    the comments taken out, which has the same length."""
    if not MOD_DECL_HINT.search(source):
        return []
    text = strip_comments(source, blank_literals=True) if blanked is None else blanked
    inline = [(m.start(), span_end(text, m.end() - 1), m.group(1))
              for m in INLINE_MOD.finditer(text)]
    kept: str | None = None
    out: list[tuple[str, tuple[str, ...], str | None]] = []
    for m in MOD_DECL.finditer(text):
        names = tuple(name for a, b, name in inline if a < m.start() < b)
        head = attrs_before(text, m.start())
        attr = None
        if "path" in text[head:m.start(1)]:
            kept = strip_comments(source) if kept is None else kept
            values = PATH_ATTR.findall(kept[head:m.start(1)])
            attr = values[-1] if values else None
        out.append((m.group(1), names, attr))
    return out


def placements(tree: Mapping[str, str], crates: Iterable[str], roots: Iterable[str] = (),
               blanked: Mapping[str, str] | None = None
               ) -> dict[str, list[tuple[str, tuple[str, ...]]]]:
    """The places of every file the module trees of the targets reach, by path: the root of each
    target that reaches it, and its module there."""
    known = list(crates)
    blanked = blanked or {}
    starts = set(roots)
    for path in tree:
        crate = owner(path, known)
        if path.endswith(".rs") and TARGET_ROOT.match(path[len(crate) + 1:]):
            starts.add(path)
    found: dict[str, set[tuple[str, tuple[str, ...]]]] = {}
    # The modules each file already is in a target: a file that would be in one of them again, or
    # below one of them (a `#[path]` that leads back up its own tree), is not walked twice.
    seen: dict[tuple[str, str], list[tuple[str, ...]]] = {}
    decls: dict[str, list[tuple[str, tuple[str, ...], str | None]]] = {}
    stack = [(root, root, ("crate",), True) for root in sorted(starts) if root in tree]
    while stack:
        path, unit, module, owns = stack.pop()
        been = seen.setdefault((unit, path), [])
        if any(module[:len(m)] == m for m in been):
            continue
        been.append(module)
        found.setdefault(path, set()).add((unit, module))
        if path not in decls:
            decls[path] = declared(tree[path], blanked.get(path))
        here = posixpath.dirname(path)
        own = here if owns else posixpath.join(here, posixpath.basename(path)[:-len(".rs")])
        for name, inline, attr in decls[path]:
            if attr is not None:
                base = posixpath.join(own, *inline) if inline else here
                candidates = [(posixpath.normpath(posixpath.join(base, attr)), True)]
            else:
                base = posixpath.join(own, *inline)
                candidates = [(posixpath.join(base, name + ".rs"), False),
                              (posixpath.join(base, name, "mod.rs"), True)]
            for candidate, child_owns in candidates:
                if candidate in tree:
                    stack.append((candidate, unit, module + inline + (name,), child_owns))
                    break
    return {path: sorted(places) for path, places in found.items()}


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

    def __init__(self, source: str) -> None:
        self.text = strip_comments(source, blank_literals=True)
        self.items = items_of(self.text)
        self.mods = inline_mods(self.text)


class Place:
    """A module of the population where one target puts it: the target's root, the module's path
    from it, and the modules of the population placed in the same target."""

    def __init__(self, path: str, mod: Module, unit: str, module: tuple[str, ...],
                 modules: dict[tuple[str, ...], Module]) -> None:
        self.path = path
        self.mod = mod
        self.unit = unit
        self.module = module
        self.modules = modules
        n = len(module)
        children = sorted({m[n] for m in modules if len(m) == n + 1 and m[:n] == module})
        # A path in code that starts at a file module this one declares.
        self.child_path = (re.compile(r"(?<![A-Za-z0-9_:.])((?:"
                                      + "|".join(re.escape(c) for c in children)
                                      + r")(?:::" + IDENT + ")+)") if children else None)
        self.imports: list[tuple[tuple[str, ...], str]] = []


def resolve(segs: list[str], at: tuple[str, ...], depth: int,
            modules: Mapping[tuple[str, ...], Module]) -> tuple[tuple[str, ...], str] | None:
    """The module of the population and the item a path names from a file that is the module
    at, depth inline modules deep; None for a path that stays in its file or leaves the
    population."""
    if not segs:
        return None
    head = segs[0]
    if head == "crate":
        base, rest = ("crate",), segs[1:]
    elif head == "super":
        k = 0
        while k < len(segs) and segs[k] == "super":
            k += 1
        if k <= depth:
            return None
        up = k - depth
        if up >= len(at):
            return None
        base, rest = at[:len(at) - up], segs[k:]
    elif depth:
        return None
    elif head == "self":
        base, rest = at, segs[1:]
    elif at + (head,) in modules:
        base, rest = at, segs
    else:
        return None
    for n in range(len(rest) - 1, -1, -1):
        module = base + tuple(rest[:n])
        if module in modules:
            return module, rest[n]
    return None


def refs_in(place: Place, a: int, b: int) -> list[tuple[tuple[str, ...], str]]:
    """What the imports and paths of a span of a file take from other modules of the population
    placed in its target."""
    out: list[tuple[tuple[str, ...], str]] = []
    mod = place.mod
    part = mod.text[a:b]
    for m in USE_DECL.finditer(part):
        depth = depth_at(mod.mods, a + m.start())
        for segs in expand_use(m.group(1)):
            hit = resolve(segs, place.module, depth, place.modules)
            if hit:
                out.append(hit)
    for pattern in (PATH_EXPR, place.child_path):
        if pattern is None:
            continue
        for m in pattern.finditer(part):
            hit = resolve(m.group(1).split("::"), place.module,
                          depth_at(mod.mods, a + m.start()), place.modules)
            if hit:
                out.append(hit)
    return out


NAME_REF = re.compile(r"(?<![A-Za-z0-9_:])(?<![^.]\.)(" + IDENT + r")")


@functools.lru_cache(maxsize=None)
def referred(text: str) -> frozenset[str]:
    """Every identifier a text refers to: not as a method, nor as a later segment of a path. An
    identifier is matched whole, so a name is referred to exactly when one of these equals it."""
    return frozenset(NAME_REF.findall(text))


def named(text: str, names: set[str]) -> set[str]:
    """The names a text refers to: not as a method, nor as a later segment of a path."""
    if not names:
        return set()
    plain = {n for n in names if re.fullmatch(IDENT, n)}
    found = set(referred(text)) & plain
    other = names - plain
    if other:
        alternatives = "|".join(re.escape(n) for n in sorted(other, key=lambda n: (-len(n), n)))
        pattern = re.compile(r"(?<![A-Za-z0-9_:])(?<![^.]\.)(" + alternatives + r")\b")
        found |= set(pattern.findall(text))
    return found


def taken(refs: list[tuple[tuple[str, ...], str]], text: str,
          modules: Mapping[tuple[str, ...], Module]) -> list[tuple[tuple[str, ...], str]]:
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


def known_crates(files: Iterable[str], crates: Iterable[str] | None) -> list[str]:
    """The covered crates given, or for a population given alone, the directory below
    `crates/` of each of its files."""
    if crates is not None:
        return sorted(crates)
    return sorted({owner(path, ()) for path in files})


def reach_of(files: dict[str, str], tree: Mapping[str, str] | None = None,
             crates: Iterable[str] | None = None,
             roots: Iterable[str] = ()) -> dict[str, list[str]]:
    """The sources each module of the population reaches, by path. The tree is every file the
    walk of the targets may read (the population when none is given), the crates are the
    covered ones, and the roots are the target paths the manifests name."""
    lookup: Mapping[str, str] = files if tree is None else tree
    known = known_crates(files, crates)
    mods = {path: Module(source) for path, source in files.items()}
    walked = placements(lookup, known, roots, {path: mod.text for path, mod in mods.items()})

    # A place the walk found comes before one read from a path, so a file placed by its path
    # alone never takes the module of one a declaration placed.
    units: dict[str, dict[tuple[str, ...], str]] = {}
    spots: list[tuple[str, str, tuple[str, ...]]] = []
    for walk in (True, False):
        for path in sorted(files):
            if walk:
                found = walked.get(path, [])
            else:
                fallback = None if path in walked else derived_place(path, owner(path, known),
                                                                     lookup)
                found = [fallback] if fallback else []
            for unit, module in found:
                if units.setdefault(unit, {}).setdefault(module, path) == path:
                    spots.append((path, unit, module))
    modules_of = {unit: {module: mods[path] for module, path in held.items()}
                  for unit, held in units.items()}
    places: dict[str, list[Place]] = {}
    for path, unit, module in spots:
        place = Place(path, mods[path], unit, module, modules_of[unit])
        place.imports = taken(refs_in(place, 0, len(place.mod.text)), place.mod.text,
                              place.modules)
        places.setdefault(path, []).append(place)

    Key = tuple[str, tuple[str, ...], str]
    reach: dict[Key, set[str]] = {}
    edges: dict[Key, set[Key]] = {}
    for held in places.values():
        for place in held:
            mod, unit = place.mod, place.unit
            imported = {item for _, item in place.imports}
            for name, spans in mod.items.items():
                key = (unit, place.module, name)
                text = "\n".join(mod.text[a:b] for a, b in spans)
                reach[key] = set(direct(text))
                out: set[Key] = set()
                for a, b in spans:
                    out.update((unit, m, i) for m, i in
                               taken(refs_in(place, a, b), text, place.modules))
                out.update((unit, place.module, n) for n in named(text, set(mod.items) - {name}))
                refer = named(text, imported)
                out.update((unit, m, i) for m, i in place.imports if i in refer)
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
        for place in places.get(path, []):
            for module, item in place.imports:
                got |= reach[(place.unit, module, item)]
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


def judge(files: dict[str, str], table_text: str, tree: Mapping[str, str] | None = None,
          crates: Iterable[str] | None = None,
          roots: Iterable[str] = ()) -> tuple[list[str], dict[str, int]]:
    """Every finding of a population (path to text) against the table's text, and the counts of
    what is placed. Raises LostSubject on a population or a table that reads as empty."""
    rows, found = parse_table(table_text)
    if not files or not rows:
        raise LostSubject(f"read {len(files)} test module(s) and {len(rows)} table row(s); the "
                          "gate lost its subject and must not pass over an empty population")
    known = known_crates(files, crates)
    reach = reach_of(files, tree, known, roots)
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
            found.append(f"`{path}` has a row but is not a tracked test module of a crate "
                         "under crates/")
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
        "crates": len({owner(path, known) for path in reach}),
        "modules": len(reach),
        "unit": sum(1 for sources in reach.values() if not sources),
        "rows": len(rows),
        "pending": sum(1 for _, kind, _, _ in rows if kind == "pending"),
        "system": sum(1 for _, kind, _, _ in rows if kind == "system"),
    }
    return found, counts


def census_rows(reach: dict[str, list[str]], table_text: str,
                crates: Iterable[str]) -> list[str]:
    """A table row for each module that reaches a source and has none, by path: kind `system`
    in an interoperation suite and `pending` elsewhere, the census as its reason."""
    rows, _ = parse_table(table_text)
    have = {row[0] for row in rows}
    known = list(crates)
    out: list[str] = []
    for path, sources in sorted(reach.items()):
        if sources and path not in have:
            kind = "system" if owner(path, known) in SYSTEM_CRATES else "pending"
            out.append("\t".join((path, kind, ",".join(sources), CENSUS_REASON)))
    return out


class TrackedTree(Mapping):
    """The tracked `.rs` files below `crates/`, each read the first time it is asked for: the
    walk of the targets reads the product files that declare modules, and no other."""

    def __init__(self, root: Path, paths: Iterable[str]) -> None:
        self.root = root
        self.paths = sorted(paths)
        self.known = set(self.paths)
        self.texts: dict[str, str] = {}

    def __getitem__(self, path: str) -> str:
        if path not in self.known:
            raise KeyError(path)
        if path not in self.texts:
            self.texts[path] = (self.root / path).read_text(encoding="utf-8")
        return self.texts[path]

    def __contains__(self, path: object) -> bool:
        return path in self.known

    def __iter__(self) -> Iterator[str]:
        return iter(self.paths)

    def __len__(self) -> int:
        return len(self.paths)


def tracked(root: Path) -> tuple[dict[str, str], TrackedTree, list[str], list[str]]:
    """Every tracked test module of the covered crates, by path, with its text; the tracked tree
    the walk reads; the covered crates; and the target paths their manifests name."""
    run = subprocess.run(["git", "-C", str(root), "ls-files", "--", "crates"],
                         capture_output=True, text=True, check=True)
    paths = run.stdout.splitlines()
    manifests = {path: (root / path).read_text(encoding="utf-8") for path in paths
                 if path.endswith("/Cargo.toml")}
    crates = covered_crates(manifests)
    covered = set(crates)
    tree = TrackedTree(root, [path for path in paths if path.endswith(".rs")])
    files: dict[str, str] = {}
    for path in tree:
        crate = owner(path, crates)
        if crate in covered and is_test_path(path[len(crate) + 1:]):
            files[path] = tree[path]
    roots = sorted({posixpath.normpath(posixpath.join(posixpath.dirname(manifest), target))
                    for manifest, text in manifests.items()
                    if posixpath.dirname(manifest) in covered for target in target_paths(text)})
    return files, tree, crates, roots


def check(root: Path = REPO_ROOT) -> int:
    table = root / TABLE
    if not table.is_file():
        print(f"deterministic-test-layer: FAIL -- {TABLE} is missing", file=sys.stderr)
        return 1
    files, tree, crates, roots = tracked(root)
    try:
        found, counts = judge(files, table.read_text(encoding="utf-8"), tree, crates, roots)
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
          f"{counts['crates']} crate(s): {counts['unit']} in the unit layer, {counts['rows']} "
          f"system-layer row(s) ({counts['pending']} pending a move to the simulated world, "
          f"{counts['system']} whose subject is the host)")
    return 0


def print_census(root: Path = REPO_ROOT) -> int:
    """Print the census rows of the tree to stdout; the table itself is not written."""
    files, tree, crates, roots = tracked(root)
    if not files:
        print("deterministic-test-layer: FAIL -- read no test module; the census lost its "
              "subject", file=sys.stderr)
        return 1
    table = root / TABLE
    text = table.read_text(encoding="utf-8") if table.is_file() else ""
    lines = census_rows(reach_of(files, tree, crates, roots), text, crates)
    for line in lines:
        print(line)
    print(f"deterministic-test-layer: {len(lines)} row(s) for module(s) that reach a source and "
          f"have none in {TABLE}", file=sys.stderr)
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


# Other layouts: a test target with a module tree (`tests/it`), test targets that share a support
# module, one that takes it from another crate by `#[path]`, and test files a library declares
# under `src/`. The two files of `src/` that are not a test's are the walk's only.
LAYOUTS = {
    "crates/wz-integration-tests/tests/it/main.rs": ("mod files;\n\n"
                                                     "#[path = \"../shared/net.rs\"]\nmod net;\n"),
    "crates/wz-integration-tests/tests/it/files/mod.rs": "mod dial;\nmod hears;\nmod quiet;\n",
    "crates/wz-integration-tests/tests/it/files/dial.rs": (
        "use crate::net::bind;\n\npub(crate) fn helper() -> u16 {\n    bind()\n}\n\n"
        "pub(crate) fn plain() -> u16 {\n    7\n}\n"),
    "crates/wz-integration-tests/tests/it/files/hears.rs": ("use super::dial::helper;\n\n"
                                                            "fn t() {\n    helper();\n}\n"),
    "crates/wz-integration-tests/tests/it/files/quiet.rs": ("use super::dial::plain;\n\n"
                                                            "fn t() {\n    plain();\n}\n"),
    "crates/wz-integration-tests/tests/shared/net.rs": ("pub fn bind() -> u16 {\n"
                                                        "    let _ = std::net::UdpSocket::bind;\n"
                                                        "    0\n}\n"),
    "crates/wz-integration-tests/tests/spawned.rs": ("mod common;\n\nuse common::spawn;\n\n"
                                                     "fn t() {\n    spawn();\n}\n"),
    "crates/wz-integration-tests/tests/pathed.rs": ("mod common;\n\n"
                                                    "fn t() {\n    common::spawn();\n}\n"),
    "crates/wz-integration-tests/tests/idle.rs": ("mod common;\n\n"
                                                  "fn t() {\n    common::idle();\n}\n"),
    "crates/wz-integration-tests/tests/common/mod.rs": ("pub fn spawn() {\n"
                                                        "    std::thread::spawn(|| {});\n}\n\n"
                                                        "pub fn idle() {}\n"),
    "crates/wz-host-interop-tests/tests/zenohd.rs": (
        "fn t() {\n    let _ = std::process::Command::new;\n}\n"),
    "crates/wz-session-core/tests/tls.rs": (
        "#[path = \"../../wz-tls-mbedtls/tests/common/mod.rs\"]\nmod common;\n\n"
        "use common::{library, End};\n\nfn t() {\n    let _ = library();\n}\n"),
    "crates/wz-tls-mbedtls/tests/common/mod.rs": ("pub fn library() -> u64 {\n"
                                                  "    let _ = std::time::SystemTime::now();\n"
                                                  "    0\n}\n\npub struct End;\n"),
    "crates/wz-session-core/src/lib.rs": ("pub mod engine;\n\n#[cfg(test)]\nmod tests {\n"
                                          "    mod wire;\n}\n"),
    "crates/wz-session-core/src/engine.rs": ("pub fn run() {}\n\n#[cfg(test)]\nmod tests;\n\n"
                                             "#[cfg(test)]\n#[path = \"engine_frame_tests.rs\"]\n"
                                             "mod frame;\n"),
    "crates/wz-session-core/src/engine/tests.rs": ("use std::time::Instant;\n\n"
                                                   "pub(crate) fn stamp() -> u64 {\n"
                                                   "    let _ = Instant::now();\n    0\n}\n\n"
                                                   "mod sim;\n"),
    "crates/wz-session-core/src/engine/tests/sim.rs": ("use super::stamp;\n\n"
                                                       "fn t() {\n    stamp();\n}\n"),
    "crates/wz-session-core/src/engine_frame_tests.rs": ("use super::tests::stamp;\n\n"
                                                         "fn t() {\n    stamp();\n}\n"),
    "crates/wz-session-core/src/tests/wire.rs": ("use super::super::engine::tests::stamp;\n\n"
                                                 "fn t() {\n    stamp();\n}\n"),
}
LAYOUT_CRATES = ["crates/wz-host-interop-tests", "crates/wz-integration-tests",
                 "crates/wz-session-core", "crates/wz-tls-mbedtls"]


def selftest() -> int:
    failures: list[str] = []

    def expect(name: str, got, want) -> None:
        ok = got == want
        print(f"  selftest -- {name}: {'ok' if ok else f'FAIL got {got!r} want {want!r}'}")
        if not ok:
            failures.append(name)

    crate = "crates/wz-capi-coop/"
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
    layout = {path: text for path, text in LAYOUTS.items()
              if is_test_path(path[len(owner(path, LAYOUT_CRATES)) + 1:])}
    expect("a product file is not a test module", sorted(set(LAYOUTS) - set(layout)),
           ["crates/wz-session-core/src/engine.rs", "crates/wz-session-core/src/lib.rs"])
    placed = placements(LAYOUTS, LAYOUT_CRATES)
    it, session = "crates/wz-integration-tests/tests/", "crates/wz-session-core/"
    expect("a `#[path]` is read from the declaring file's directory",
           placed[it + "shared/net.rs"], [(it + "it/main.rs", ("crate", "net"))])
    expect("a support module two test targets declare has a place in each",
           placed[it + "common/mod.rs"],
           [(it + name, ("crate", "common")) for name in ("idle.rs", "pathed.rs", "spawned.rs")])
    expect("a `#[path]` into another crate places the file in the declaring target",
           placed["crates/wz-tls-mbedtls/tests/common/mod.rs"],
           [(session + "tests/tls.rs", ("crate", "common"))])
    expect("a `#[path]` of a file module is its declaration's module",
           placed[session + "src/engine_frame_tests.rs"],
           [(session + "src/lib.rs", ("crate", "engine", "frame"))])
    expect("a declaration inside an inline module adds its name",
           placed[session + "src/tests/wire.rs"],
           [(session + "src/lib.rs", ("crate", "tests", "wire"))])
    expect("a file that is not a root holds its children in the directory of its name",
           placed[session + "src/engine/tests/sim.rs"],
           [(session + "src/lib.rs", ("crate", "engine", "tests", "sim"))])
    expect("a target path a manifest names is a root",
           placements({"crates/x/check/entry.rs": "mod util;\n", "crates/x/check/util.rs": ""},
                      ["crates/x"], ["crates/x/check/entry.rs"]).get("crates/x/check/util.rs"),
           [("crates/x/check/entry.rs", ("crate", "util"))])
    expect("a file no walk reaches is placed by its path",
           [derived_place("crates/x/" + rel, "crates/x", {}) for rel in
            ("tests/it/files/a.rs", "tests/it/main.rs", "src/a/tests.rs", "benches/b.rs",
             "src/bin/tool/x/mod.rs")],
           [("crates/x/tests/it/main.rs", ("crate", "files", "a")),
            ("crates/x/tests/it/main.rs", ("crate",)),
            ("crates/x/src/lib.rs", ("crate", "a", "tests")),
            ("crates/x/benches/b.rs", ("crate",)),
            ("crates/x/src/bin/tool/main.rs", ("crate", "x"))])

    far = reach_of(layout, LAYOUTS, LAYOUT_CRATES)
    expect("a module of a test target takes a `crate::` item a `#[path]` module holds",
           far[it + "it/files/dial.rs"], ["socket"])
    expect("a `super::` of a file under a test target's tree is its parent there",
           far[it + "it/files/hears.rs"], ["socket"])
    expect("CONTROL: an item of the same tree that reaches nothing brings nothing",
           far[it + "it/files/quiet.rs"], [])
    expect("CONTROL: a root that declares a module that reaches a source is no reach by itself",
           far[it + "it/main.rs"], [])
    expect("a `use` of a file module the target root declares takes its item",
           far[it + "spawned.rs"], ["thread"])
    expect("a path in code that starts at a declared file module takes its item",
           far[it + "pathed.rs"], ["thread"])
    expect("CONTROL: a declared file module's item that reaches nothing brings nothing",
           far[it + "idle.rs"], [])
    expect("an item of another crate's support module brings what it reaches",
           far[session + "tests/tls.rs"], ["clock"])
    expect("`super::` from a `#[path]` file is the module that declares it",
           far[session + "src/engine_frame_tests.rs"], ["clock"])
    expect("`super::super` from a file an inline module declares climbs past it",
           far[session + "src/tests/wire.rs"], ["clock"])
    expect("a child of a `tests.rs` takes from it by `super::`",
           far[session + "src/engine/tests/sim.rs"], ["clock"])

    census = census_rows(far, f"{header}\n{it}common/mod.rs\tsystem\tthread\tr\n",
                         LAYOUT_CRATES)
    expect("the census gives an interoperation suite kind system and another crate pending",
           [line for line in census if line.split("\t")[0] in (
               "crates/wz-host-interop-tests/tests/zenohd.rs", it + "spawned.rs",
               session + "src/engine/tests.rs")],
           ["crates/wz-host-interop-tests/tests/zenohd.rs\tsystem\tprocess\t" + CENSUS_REASON,
            f"{it}spawned.rs\tsystem\tthread\t{CENSUS_REASON}",
            f"{session}src/engine/tests.rs\tpending\tclock\t{CENSUS_REASON}"])
    expect("CONTROL: a module with a row, or that reaches nothing, takes no census row",
           [line for line in census
            if line.split("\t")[0] in (it + "common/mod.rs", it + "it/files/quiet.rs")], [])
    expect("the covered crates are the manifests below crates/ that declare a package",
           covered_crates({"crates/Cargo.toml": "[package]\n", "crates/a/Cargo.toml": "[package]\n",
                           "crates/a/sub/Cargo.toml": "[package]\nname = \"sub\"\n",
                           "crates/v/Cargo.toml": "[workspace]\nmembers = []\n"}),
           ["crates/a", "crates/a/sub"])
    expect("a file belongs to the deepest crate that holds it",
           [owner(p, ["crates/a", "crates/a/sub"]) for p in
            ("crates/a/sub/tests/x.rs", "crates/a/tests/x.rs", "crates/b/tests/x.rs")],
           ["crates/a/sub", "crates/a", "crates/b"])
    expect("a manifest's target paths are its target tables' alone",
           target_paths("[package]\nname = \"x\"\n\n[dependencies.y]\npath = \"../y\"\n\n"
                        "[[test]]\nname = \"it\"\npath = \"tests/it/main.rs\"\n"),
           ["tests/it/main.rs"])
    print(f"deterministic-test-layer selftest: "
          f"{'OK' if not failures else 'FAILED: ' + ', '.join(failures)}")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--selftest", action="store_true")
    group.add_argument("--rows", action="store_true",
                       help="print a row for each module that reaches a source and has none")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    return print_census() if args.rows else check()


if __name__ == "__main__":
    sys.exit(main())
