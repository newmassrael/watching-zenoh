#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4619 (debt-pico-host-size-ceiling) -- the size ledger of the pico C ABI's release library: its
function bytes and zenoh-pico's, built as the same build, by AREA, each area's ratio held under a
ratchet (docs/c-abi-architecture.md, principle P9 and step 1 of its migration).

The citation is the open-debt item the pico ceiling is registered under: this gate is how that
debt is read area by area, and every row of its ledger is registered under it.

## Why this exists

The pico ceiling (deploy/pico_host_ceiling.json, read by capability_cost_gate.py) holds a case's
whole text to a ratio of zenoh-pico's. A total does not say where the bytes are: on 2026-11-23 the
release form read 2.22 times zenoh-pico in total while its areas read from 1.04 (the wire codec)
to 4.56 (the C ABI doors), and a change that grows one area while another shrinks moves the total
by their difference only. The architecture is judged area by area, so this gate is too: a change
that grows an area is refused in that area.

## What is read, and where it comes from

One case of capability_cost_gate.py, the one the ledger names (`case`, the release form), and its
zenoh-pico reference, built by that gate's own functions (`build`, `pico_reference_build`,
`pico_reference_tree`) in its environment (`build_env`): the same commands, the same target
directory and the same reference directory, so in Layer C1cs, after the cost gate built the case,
nothing is built a second time. A library that holds a build path, or that another linker wrote,
is no figure here, as it is no figure there.

Of each library, the text symbols with a size (`nm --defined-only -S`, kinds t, T, w and W). LLVM
merges identical functions into aliases of one body, and the linker keeps every name of an
address, so the names of one address are ONE body: it is counted once, at its largest size, and
goes to the area most of its names are placed in (a tie to the area the ledger lists first).

## Who wrote a symbol

wz: the owner of a Rust symbol is read from its v0 mangling (RFC 2603), not from its demangled
text. It is the path of the item, and for an item of an impl block the module that wrote the
impl, which the mangling records and the demangled `<T as Trait>::f` does not: an impl written in
`wz_runtime_coop::session_drive` for `alloc::rc::Rc<..>` is the runtime's code, not alloc's. A
trait item with no impl (a default method's body, a compiler shim) is the trait's. Generic
arguments own nothing: `core::ptr::drop_glue::<wz_runtime_posix::stream::StreamReader>` is drop
glue, language support. A name that is not v0 (the C exports, and a symbol a toolchain mangled
another way) has no owner, and only a name rule places it.

zenoh-pico: the owner of a symbol is the source file that defines it. The definitions are read
from the export of the submodule the reference was built from: every header under include/ and
src/, and every .c file the build compiled, which the object files of its CMake target name. A
definition is a function head at column 0 whose parameter list is followed by its body (the
sources are clang-formatted, so a head is never indented). A name no head defines (one a macro
writes) is owned by the object file of the build that defines it, and a name several files define
narrows to the files the build compiled it in. A compiler clone (`.isra.0`, `.constprop.0`,
`.part.0`, `.cold`) is its function's.

## The rules are data

deploy/size_ledger.json holds, per side, `names` (regular expressions over a symbol's name with its
clone suffix removed; the first that matches, in the file's order, places it) and `owners`
(prefixes of an owner path, `crate::module` for wz and a file or directory for zenoh-pico; the
longest that matches at a segment boundary places it). A name rule comes first, and a symbol with
several owners is placed only when the rules of all of them name one area. A body no rule places is
UNCLASSIFIED, and either library's unclassified bytes over `unclassified_bytes_at_most` fail,
naming the largest: a crate, module or file a change brings is given an area in that commit. A rule
that placed nothing in a run is printed, so a renamed module is seen.

## The ratchet

Each area has a row, with the rule of a row of the pico ceiling (pico_host_ceiling.py, the one
implementation): locked at WIN, or `ratio_at_most`, the ratio of the reading it was set from rounded
up to four places, under the open-debt item it is registered under. A reading over its row by more
than the tolerance fails; one under it by more prints the tighter row to commit; an area that reads
WIN fails until its row is locked, and a locked area reads WIN or fails. A row whose ratio is null
is unfilled and fails with the row this run reads. An area that reads no byte on one side has no
ratio and fails: its rules give that side none of its code.

## Where it runs

Layer C1cs, as the leg after the cost gate. With `--shards N --shard K` the case is read only on
the shard the cost gate deals it to, and every shard checks the ledger itself, which needs no
build. Layer C0 runs `--selftest`, which holds the readers, the rules and the ratchet on synthetic
input and the committed ledger to its own rules.

Usage:
    size_ledger_gate.py --check [--shards N --shard K]
                               read the case and grade every area against its row
    size_ledger_gate.py --measure [--shards N --shard K]
                               read the case and print the table and the rows to commit
    size_ledger_gate.py --selftest

Exit codes: 0 the ledger holds, 1 a finding, 2 a usage error or a host that cannot build.
"""

from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import re
import subprocess
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import capability_cost_gate as cost  # noqa: E402  (the builds this gate reads, one copy)
import census_shard_plan  # noqa: E402  (the shard plan of Layer C1cs)
import wz_config  # noqa: E402  (the declaration a reference is derived from)
from pico_host_ceiling import (  # noqa: E402  (the one rule of a ratio row)
    ceiling_reading, ceiling_row, format_row, grade_ceiling, row_findings,
)

ROOT = pathlib.Path(__file__).resolve().parents[2]
LEDGER = ROOT / "deploy" / "size_ledger.json"
LEDGER_SCHEMA = 1
TABLE_KEYS = frozenset(("about", "schema", "case", "unclassified_bytes_at_most", "areas", "rows",
                        "rules"))
SIDES = ("wz", "pico")
RULE_KINDS = ("names", "owners")
# The segment separator of an owner path on each side: a Rust path and a source path.
SEPARATOR = {"wz": "::", "pico": "/"}
OWNER_SHAPE = {
    "wz": re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*"),
    "pico": re.compile(r"[A-Za-z0-9_+.-]+(?:/[A-Za-z0-9_+.-]+)*"),
}
AREA_ID = re.compile(r"[a-z][a-z0-9-]*")
# The symbol kinds of code: local and global text, and weak definitions.
TEXT_KINDS = frozenset("tTwW")
# Where the reference build keeps the objects of zenoh-pico's shared library target, under its
# CMake tree, and the library itself, under the reference directory (pico_reference_tree).
PICO_TARGET_OBJECTS = pathlib.Path("build") / "CMakeFiles" / "zenohpico_shared.dir"
PICO_LIBRARY = pathlib.Path("build") / "lib" / "libzenohpico.so"
# The source trees of the export whose headers can define a function.
PICO_HEADER_TREES = ("include", "src")
# How many unclassified bodies a finding names, largest first.
UNCLASSIFIED_NAMED = 12
MEASURE = "python3 scripts/lib/size_ledger_gate.py --measure"


# ── who wrote a wz symbol: the v0 mangling ─────────────────────────────────────────────────────


class ManglingError(ValueError):
    """A name that does not read as the Rust v0 mangling."""


# RFC 2603: the one-letter basic types (`p` is the placeholder `_`), and the tags of a path.
_BASIC_TYPES = frozenset("abcdefhijlmnopstuvxyz")
_PATH_TAGS = frozenset("CMXYNI")
_HEX_DIGITS = frozenset("0123456789abcdef")


class _V0Reader:
    """One v0 symbol, the text after `_R`. Each production takes the index it starts at and returns
    the index after it; `path` returns the owner too. A back-reference names text before itself,
    so its target is read with the end of the text moved to the reference: a malformed one cannot
    loop."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.end = len(text)

    def at(self, i: int) -> str:
        if i >= self.end:
            raise ManglingError("the name ends inside a production")
        return self.text[i]

    def base62(self, i: int) -> tuple[int, int]:
        if self.at(i) == "_":
            return 0, i + 1
        value = 0
        while (c := self.at(i)) != "_":
            if "0" <= c <= "9":
                digit = ord(c) - ord("0")
            elif "a" <= c <= "z":
                digit = ord(c) - ord("a") + 10
            elif "A" <= c <= "Z":
                digit = ord(c) - ord("A") + 36
            else:
                raise ManglingError(f"{c!r} is no base-62 digit")
            value = value * 62 + digit
            i += 1
        return value + 1, i + 1

    def disambiguator(self, i: int) -> int:
        return self.base62(i + 1)[1] if self.at(i) == "s" else i

    def identifier(self, i: int) -> tuple[str, int]:
        punycode = self.at(i) == "u"
        if punycode:
            i += 1
        start = i
        if self.at(i) == "0":
            i += 1
        else:
            while i < self.end and "0" <= self.text[i] <= "9":
                i += 1
        if i == start:
            raise ManglingError("an identifier without its length")
        length = int(self.text[start:i])
        if i < self.end and self.text[i] == "_":
            i += 1
        if i + length > self.end:
            raise ManglingError("an identifier runs past the name")
        name = self.text[i:i + length]
        return (f"punycode:{name}" if punycode else name), i + length

    def backref(self, i: int) -> tuple[int, int]:
        target, after = self.base62(i + 1)
        if target >= i:
            raise ManglingError("a back-reference that does not point back")
        return target, after

    def path(self, i: int) -> tuple[tuple[str, ...], int]:
        tag = self.at(i)
        if tag == "C":
            name, i = self.identifier(self.disambiguator(i + 1))
            return (name,), i
        if tag == "M":
            owner, i = self.path(self.disambiguator(i + 1))
            return owner, self.type(i)
        if tag == "X":
            owner, i = self.path(self.disambiguator(i + 1))
            return owner, self.path(self.type(i))[1]
        if tag == "Y":
            return self.path(self.type(i + 1))
        if tag == "N":
            namespace = self.at(i + 1)
            owner, i = self.path(i + 2)
            name, i = self.identifier(self.disambiguator(i))
            # A closure or a shim (an upper-case namespace) is its parent's code.
            return (owner + (name,) if namespace.islower() and name else owner), i
        if tag == "I":
            owner, i = self.path(i + 1)
            while self.at(i) != "E":
                i = self.generic_arg(i)
            return owner, i + 1
        if tag == "B":
            target, after = self.backref(i)
            saved, self.end = self.end, i
            try:
                owner = self.path(target)[0]
            finally:
                self.end = saved
            return owner, after
        raise ManglingError(f"{tag!r} begins no path")

    def generic_arg(self, i: int) -> int:
        tag = self.at(i)
        if tag == "L":
            return self.base62(i + 1)[1]
        if tag == "K":
            return self.const(i + 1)
        return self.type(i)

    def type(self, i: int) -> int:
        tag = self.at(i)
        if tag in _BASIC_TYPES:
            return i + 1
        if tag in _PATH_TAGS:
            return self.path(i)[1]
        if tag == "B":
            return self.backref(i)[1]
        if tag in ("S", "P", "O"):
            return self.type(i + 1)
        if tag in ("R", "Q"):
            i += 1
            if self.at(i) == "L":
                i = self.base62(i + 1)[1]
            return self.type(i)
        if tag == "A":
            return self.const(self.type(i + 1))
        if tag == "T":
            i += 1
            while self.at(i) != "E":
                i = self.type(i)
            return i + 1
        if tag == "F":
            return self.fn_sig(i + 1)
        if tag == "D":
            return self.dyn_bounds(i + 1)
        raise ManglingError(f"{tag!r} begins no type")

    def fn_sig(self, i: int) -> int:
        if self.at(i) == "G":
            i = self.base62(i + 1)[1]
        if self.at(i) == "U":
            i += 1
        if self.at(i) == "K":
            i += 1
            i = i + 1 if self.at(i) == "C" else self.identifier(i)[1]
        while self.at(i) != "E":
            i = self.type(i)
        return self.type(i + 1)

    def dyn_bounds(self, i: int) -> int:
        if self.at(i) == "G":
            i = self.base62(i + 1)[1]
        while self.at(i) != "E":
            i = self.path(i)[1]
            while self.at(i) == "p":
                i = self.type(self.identifier(i + 1)[1])
        i += 1
        if self.at(i) != "L":
            raise ManglingError("a dyn type without its lifetime")
        return self.base62(i + 1)[1]

    def const(self, i: int) -> int:
        tag = self.at(i)
        if tag == "p":
            return i + 1
        if tag == "B":
            return self.backref(i)[1]
        i = self.type(i)
        if self.at(i) == "n":
            i += 1
        while self.at(i) in _HEX_DIGITS:
            i += 1
        if self.at(i) != "_":
            raise ManglingError("a constant without its terminator")
        return i + 1


def v0_owner(symbol: str) -> tuple[str, ...]:
    """The path of what wrote a v0 symbol (module doc, "Who wrote a symbol"): the item's path, an
    impl item's impl module, a trait item's trait. A suffix after the first `.` (`.llvm.<n>`) is
    the toolchain's, and the instantiating crate after the path is not an owner."""
    text = symbol.split(".", 1)[0]
    if not text.startswith("_R"):
        raise ManglingError("not a v0 name")
    reader = _V0Reader(text[2:])
    i = 0
    while i < reader.end and "0" <= reader.text[i] <= "9":
        i += 1  # the encoding version, which no toolchain writes yet
    try:
        owner, i = reader.path(i)
        if i < reader.end:
            i = reader.path(i)[1]
    except RecursionError as e:
        raise ManglingError("nested deeper than this reader follows") from e
    if i != reader.end:
        raise ManglingError("text after the instantiating crate")
    return owner


# ── who wrote a zenoh-pico symbol: the source that defines it ──────────────────────────────────

_C_KEYWORDS = frozenset(("if", "for", "while", "switch", "return", "sizeof", "defined", "do",
                         "else", "case"))
# A function head at column 0: the declarator's name and the parenthesis after it.
_C_HEAD = re.compile(r"^(?![\s#])[^;{}()=\n]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.M)
_C_ATTRIBUTE = re.compile(r"\b(?:__attribute__|__declspec)\s*\(")
_NOT_NEWLINE = re.compile(r"[^\n]")


def strip_c(text: str) -> str:
    """C text with its comments blanked, its string and character literals emptied and its
    preprocessor lines removed, newlines kept, so what stood at column 0 still does."""
    out: list[str] = []
    i, n, line_start = 0, len(text), True
    while i < n:
        if line_start:
            j = i
            while j < n and text[j] in " \t":
                j += 1
            if j < n and text[j] == "#":
                while j < n and text[j] != "\n":
                    if text.startswith("\\\n", j):
                        j += 2
                    elif text.startswith("/*", j):
                        close = text.find("*/", j + 2)
                        j = n if close < 0 else close + 2
                    else:
                        j += 1
                out.append("\n")
                i = j + 1
                continue
        c = text[i]
        if text.startswith("//", i):
            close = text.find("\n", i)
            i = n if close < 0 else close
            line_start = False
            continue
        if text.startswith("/*", i):
            close = text.find("*/", i + 2)
            end = n if close < 0 else close + 2
            out.append(_NOT_NEWLINE.sub(" ", text[i:end]))
            i = end
            line_start = False
            continue
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            out.append(c + c)
            i = j + 1
            line_start = False
            continue
        out.append(c)
        line_start = c == "\n"
        i += 1
    return "".join(out)


def strip_attributes(code: str) -> str:
    """`code` with every `__attribute__((..))` and `__declspec(..)` removed, with the blanks after
    it, so a head that opened with one starts at column 0 like any other."""
    out: list[str] = []
    i = 0
    while (m := _C_ATTRIBUTE.search(code, i)) is not None:
        out.append(code[i:m.start()])
        j, depth = m.end(), 1
        while j < len(code) and depth:
            if code[j] == "(":
                depth += 1
            elif code[j] == ")":
                depth -= 1
            j += 1
        while j < len(code) and code[j] in " \t":
            j += 1
        out.append("\n" * code.count("\n", m.start(), j))
        i = j
    out.append(code[i:])
    return "".join(out)


def _opens_body(code: str, i: int) -> bool:
    """Whether the parameter list whose `(` ends before `i` closes and is followed by a body."""
    depth = 1
    while i < len(code) and depth:
        c = code[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c in "{};":
            return False
        i += 1
    while i < len(code) and code[i].isspace():
        i += 1
    return depth == 0 and i < len(code) and code[i] == "{"


def c_definitions(text: str) -> set[str]:
    """The functions a C file defines at column 0."""
    code = strip_attributes(strip_c(text))
    return {m.group(1) for m in _C_HEAD.finditer(code)
            if m.group(1) not in _C_KEYWORDS and _opens_body(code, m.end())}


def pico_definitions(src: pathlib.Path, compiled: Iterable[str]) -> dict[str, set[str]]:
    """Each function name the export at `src` defines -> the files that define it: the headers of
    its include/ and src/ trees and the .c files of `compiled` (paths relative to `src`)."""
    files = set(compiled)
    for tree in PICO_HEADER_TREES:
        if (src / tree).is_dir():
            files |= {p.relative_to(src).as_posix() for p in (src / tree).rglob("*.h")}
    owners: dict[str, set[str]] = {}
    for rel in sorted(files):
        path = src / rel
        if path.is_file():
            for name in c_definitions(path.read_text(encoding="utf-8", errors="replace")):
                owners.setdefault(name, set()).add(rel)
    return owners


def clone_base(name: str) -> str:
    """The function a symbol is a part or a clone of: its name before the first `.`."""
    return name.split(".", 1)[0]


def object_owners(listing: str, objects_dir: str) -> dict[str, set[str]]:
    """Each text symbol of an `nm -A --defined-only` listing of the objects under `objects_dir` ->
    the sources whose objects define it (`src/api/api.c` for `<objects_dir>/src/api/api.c.o`)."""
    prefix = objects_dir.rstrip("/") + "/"
    owners: dict[str, set[str]] = {}
    for line in listing.splitlines():
        where, sep, rest = line.rpartition(":")
        parts = rest.split()
        if not sep or len(parts) != 3 or parts[1] not in TEXT_KINDS:
            continue
        rel = where[len(prefix):] if where.startswith(prefix) else where
        if rel.endswith(".o"):
            rel = rel[:-2]
        owners.setdefault(clone_base(parts[2]), set()).add(rel)
    return owners


def pico_owners(base: str, definitions: Mapping[str, set[str]],
                built: Mapping[str, set[str]]) -> set[str]:
    """The files that wrote `base`: those that define it and the build compiled it in, else those
    that define it (a header's inline function, which no object names as its file), else the
    objects that define it (a name a macro writes)."""
    parsed = definitions.get(base, set())
    objects = built.get(base, set())
    return (parsed & objects) or set(parsed) or set(objects)


# ── the symbols of a library ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Symbol:
    address: int
    size: int
    name: str
    owners: tuple[str, ...] = ()


def text_symbols(listing: str) -> list[tuple[int, int, str]]:
    """(address, size, name) of each sized text symbol of an `nm --defined-only -S` listing."""
    out: list[tuple[int, int, str]] = []
    for line in listing.splitlines():
        parts = line.split(None, 3)
        if len(parts) != 4 or parts[2] not in TEXT_KINDS:
            continue
        try:
            address, size = int(parts[0], 16), int(parts[1], 16)
        except ValueError:
            continue
        if size:
            out.append((address, size, parts[3]))
    return out


def wz_symbols(listing: str) -> tuple[list[Symbol], list[str]]:
    """The text symbols of the wz library with their owners, and the `_R` names that do not
    read."""
    symbols: list[Symbol] = []
    unread: list[str] = []
    for address, size, name in text_symbols(listing):
        owners: tuple[str, ...] = ()
        if name.startswith("_R"):
            try:
                owners = ("::".join(v0_owner(name)),)
            except ManglingError:
                unread.append(name)
        symbols.append(Symbol(address, size, name, owners))
    return symbols, unread


def pico_symbols(listing: str, definitions: Mapping[str, set[str]],
                 built: Mapping[str, set[str]]) -> list[Symbol]:
    return [Symbol(address, size, name,
                   tuple(sorted(pico_owners(clone_base(name), definitions, built))))
            for address, size, name in text_symbols(listing)]


# ── the rules and the tally ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Rules:
    names: tuple[tuple[str, re.Pattern[str], str], ...]
    owners: Mapping[str, str]
    separator: str


def side_rules(table: dict, side: str) -> Rules:
    spec = table["rules"][side]
    return Rules(tuple((key, re.compile(key), area) for key, area in spec["names"].items()),
                 dict(spec["owners"]), SEPARATOR[side])


def owner_rule(rules: Rules, owner: str) -> str | None:
    """The longest owner prefix that matches `owner` at a segment boundary, or None."""
    best: str | None = None
    for prefix in rules.owners:
        if owner == prefix or owner.startswith(prefix + rules.separator):
            if best is None or len(prefix) > len(best):
                best = prefix
    return best


def classify(rules: Rules, symbol: Symbol) -> tuple[str | None, tuple[str, ...]]:
    """The area that places `symbol`, or None, and the rules that placed it."""
    base = clone_base(symbol.name)
    for key, pattern, area in rules.names:
        if pattern.search(base):
            return area, (f"names {key}",)
    prefixes = [owner_rule(rules, owner) for owner in symbol.owners]
    if not prefixes or any(p is None for p in prefixes):
        return None, ()
    areas = {rules.owners[p] for p in prefixes if p is not None}
    if len(areas) != 1:
        return None, ()
    return areas.pop(), tuple(f"owners {p}" for p in prefixes)


@dataclass
class Tally:
    by_area: dict[str, int]
    total: int = 0
    # (bytes, names) of each body no rule placed, largest first.
    unclassified: list[tuple[int, tuple[str, ...]]] = field(default_factory=list)
    used: set[str] = field(default_factory=set)

    @property
    def unclassified_bytes(self) -> int:
        return sum(size for size, _ in self.unclassified)


def tally(symbols: Iterable[Symbol], rules: Rules, areas: list[str]) -> Tally:
    """The bytes of each area: each address one body, at its largest size, in the area most of
    its names are placed in, a tie to the area listed first."""
    bodies: dict[int, list[Symbol]] = {}
    for symbol in symbols:
        bodies.setdefault(symbol.address, []).append(symbol)
    result = Tally({area: 0 for area in areas})
    for address in sorted(bodies):
        names = bodies[address]
        size = max(s.size for s in names)
        result.total += size
        votes: dict[str, int] = {}
        for symbol in names:
            area, used = classify(rules, symbol)
            result.used.update(used)
            if area is not None:
                votes[area] = votes.get(area, 0) + 1
        if not votes:
            result.unclassified.append((size, tuple(sorted({s.name for s in names}))))
            continue
        winner = min(votes, key=lambda a: (-votes[a], areas.index(a)))
        result.by_area[winner] += size
    result.unclassified.sort(key=lambda body: (-body[0], body[1]))
    return result


def unused_rules(table: dict, side: str, used: set[str]) -> list[str]:
    spec = table["rules"][side]
    return [f"{kind} {key}" for kind in RULE_KINDS for key in spec[kind]
            if f"{kind} {key}" not in used]


# ── the ledger ─────────────────────────────────────────────────────────────────────────────────


def load_ledger(path: pathlib.Path = LEDGER) -> object:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def area_ids(table: object) -> list[str]:
    areas = table.get("areas") if isinstance(table, dict) else None
    if not isinstance(areas, list):
        return []
    return [a["id"] for a in areas if isinstance(a, dict) and isinstance(a.get("id"), str)]


def pico_case_ids() -> list[str]:
    return [c.id for c in cost.CASES if c.package == "wz-capi-pico"]


def rule_findings(table: object, case_ids: Iterable[str]) -> list[str]:
    """What keeps the ledger from being read: its shape, its case, its areas and its rules. Static,
    so every shard and the selftest run it."""
    where = LEDGER.relative_to(ROOT)
    if not isinstance(table, dict):
        return [f"{where} is missing or is no object: the release library's areas are held there"]
    if table.get("schema") != LEDGER_SCHEMA:
        return [f"{where} is not schema {LEDGER_SCHEMA}"]
    out = [f"{where} has the unknown key {key!r}" for key in sorted(set(table) - TABLE_KEYS)]
    if not isinstance(table.get("case"), str) or table["case"] not in set(case_ids):
        out.append(f"{where}: case {table.get('case')!r} is no pico case of "
                   f"capability_cost_gate.py, whose builds this gate reads")
    limit = table.get("unclassified_bytes_at_most")
    if type(limit) is not int or limit < 0:
        out.append(f"{where}: unclassified_bytes_at_most is no byte count")
    areas = table.get("areas")
    ids: list[str] = []
    if not isinstance(areas, list) or not areas:
        out.append(f"{where}: areas is no list of areas")
    else:
        for n, area in enumerate(areas):
            if not isinstance(area, dict) or set(area) != {"id", "title"}:
                out.append(f"{where}: area {n} must state exactly its id and its title")
                continue
            if not isinstance(area["id"], str) or not AREA_ID.fullmatch(area["id"]):
                out.append(f"{where}: area {n} has no id of the form {AREA_ID.pattern}")
                continue
            if area["id"] in ids:
                out.append(f"{where}: the area {area['id']!r} is declared twice")
                continue
            if not isinstance(area["title"], str) or not area["title"].strip():
                out.append(f"{where}: the area {area['id']!r} has no title")
            ids.append(area["id"])
    rules = table.get("rules")
    if not isinstance(rules, dict) or set(rules) != set(SIDES):
        return out + [f"{where}: rules must hold exactly the sides {', '.join(SIDES)}"]
    for side in SIDES:
        spec = rules[side]
        if not isinstance(spec, dict) or set(spec) != set(RULE_KINDS):
            out.append(f"{where}: the {side} rules must hold exactly {', '.join(RULE_KINDS)}")
            continue
        named: set[str] = set()
        for kind in RULE_KINDS:
            entries = spec[kind]
            if not isinstance(entries, dict):
                out.append(f"{where}: the {side} {kind} rules are no object")
                continue
            for key, area in entries.items():
                if isinstance(area, str) and area in ids:
                    named.add(area)
                else:
                    out.append(f"{where}: the {side} {kind} rule {key!r} names {area!r}, which is "
                               f"no declared area")
                if kind == "names":
                    try:
                        re.compile(key)
                    except re.error as e:
                        out.append(f"{where}: the {side} name rule {key!r} is no regular "
                                   f"expression ({e})")
                elif not OWNER_SHAPE[side].fullmatch(key) or ".." in key.split("/"):
                    shape = "crate::module path" if side == "wz" else "relative source path"
                    out.append(f"{where}: the {side} owner rule {key!r} is no {shape}")
        for area in ids:
            if area not in named:
                out.append(f"{where}: no {side} rule names the area {area!r}, so its {side} side "
                           f"would read no byte")
    return out


def row_population_findings(table: object) -> list[str]:
    """What keeps every declared area from having exactly one well-formed row. A row whose
    ratio_at_most is null is well formed here (the unfilled form), and the grade refuses it."""
    where = LEDGER.relative_to(ROOT)
    if not isinstance(table, dict):
        return []
    rows = table.get("rows")
    if not isinstance(rows, dict):
        return [f"{where} has no rows object"]
    ids = area_ids(table)
    out = [f"{area}: no row in {where}: an area is held from the commit that declares it; "
           f"{MEASURE} prints its row" for area in ids if area not in rows]
    for area, row in rows.items():
        if area not in ids:
            out.append(f"{area}: a row in {where} for no declared area")
        else:
            out += row_findings(area, row)
    return out


def ledger_findings(table: object, case_ids: Iterable[str]) -> list[str]:
    return rule_findings(table, case_ids) + row_population_findings(table)


def unclassified_findings(side: str, tallied: Tally, limit: int) -> list[str]:
    if tallied.unclassified_bytes <= limit:
        return []
    shown = "; ".join(f"{size} B {' = '.join(names)}"
                      for size, names in tallied.unclassified[:UNCLASSIFIED_NAMED])
    return [f"{side}: {tallied.unclassified_bytes} bytes of text in {len(tallied.unclassified)} "
            f"bodies that no rule of {LEDGER.relative_to(ROOT)} places, over the {limit} it "
            f"allows; give each an area by a rule, largest first: {shown}"]


def area_readings(areas: list[str], wz: Tally, pico: Tally, pin: str, toolchain: str,
                  date: str) -> tuple[dict[str, dict], list[str]]:
    """Each area's reading, and the findings of the areas that have no ratio."""
    readings: dict[str, dict] = {}
    findings: list[str] = []
    for area in areas:
        mine, theirs = wz.by_area[area], pico.by_area[area]
        if mine == 0 or theirs == 0:
            side = "zenoh-pico" if theirs == 0 else "wz"
            findings.append(f"{area}: {side} has no byte in this area ({mine} of wz, {theirs} of "
                            f"zenoh-pico), so it has no ratio: the {side} rules give it none of "
                            f"{side}'s code")
            continue
        readings[area] = ceiling_reading(mine, theirs, pin, toolchain, date)
    return readings, findings


def grade_areas(rows: Mapping[str, object],
                readings: Mapping[str, dict]) -> tuple[list[str], list[str]]:
    """The findings and the notes of each area's reading against its well-formed row; a missing
    or malformed row is `row_population_findings`' to name."""
    findings: list[str] = []
    notes: list[str] = []
    for area, reading in readings.items():
        row = rows.get(area)
        if not isinstance(row, dict) or row_findings(area, row):
            continue
        found, said = grade_ceiling(area, row, reading, MEASURE, table=LEDGER,
                                    win_closes_debt=False)
        findings += found
        notes += said
    return findings, notes


def row_debt(row: object) -> str | None:
    debt = row.get("debt") if isinstance(row, dict) else None
    return debt if isinstance(debt, str) else None


def held_at(row: object) -> str:
    if not isinstance(row, dict):
        return "no row"
    if "verdict" in row:
        return "win (locked)"
    if row.get("ratio_at_most") is None:
        return "unfilled"
    return f"at most {row['ratio_at_most']}"


def table_lines(table: dict, wz: Tally, pico: Tally) -> list[str]:
    rows = table["rows"] if isinstance(table.get("rows"), dict) else {}
    lines = [f"  size-ledger:   {'area':<10} {'wz':>9} {'zenoh-pico':>11} {'ratio':>8}  row"]
    for area in table["areas"]:
        aid = area["id"]
        mine, theirs = wz.by_area[aid], pico.by_area[aid]
        ratio = f"{mine / theirs:.4f}" if theirs else "-"
        lines.append(f"  size-ledger:   {aid:<10} {mine:>9} {theirs:>11} {ratio:>8}  "
                     f"{held_at(rows.get(aid))}; {area['title']}")
    total = f"{wz.total / pico.total:.4f}" if pico.total else "-"
    lines.append(f"  size-ledger:   {'total':<10} {wz.total:>9} {pico.total:>11} {total:>8}  "
                 f"(the case's text is held by deploy/pico_host_ceiling.json)")
    lines.append(f"  size-ledger:   unclassified: {wz.unclassified_bytes} bytes of wz, "
                 f"{pico.unclassified_bytes} of zenoh-pico, at most "
                 f"{table['unclassified_bytes_at_most']} each")
    return lines


# ── reading the case ───────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CaseRead:
    wz: list[Symbol]
    pico: list[Symbol]
    unread: list[str]
    pin: str
    toolchain: str


def nm_text(lib: pathlib.Path) -> str:
    return subprocess.run(["nm", "--defined-only", "-S", str(lib)], capture_output=True, text=True,
                          check=True).stdout


def object_symbols(objects_dir: pathlib.Path) -> dict[str, set[str]]:
    objects = sorted(objects_dir.rglob("*.o")) if objects_dir.is_dir() else []
    if not objects:
        return {}
    listing = subprocess.run(["nm", "-A", "--defined-only", *(str(o) for o in objects)],
                             capture_output=True, text=True, check=True).stdout
    return object_owners(listing, str(objects_dir))


def read_case(case: cost.Case, env: Mapping[str, str],
              prefixes: object) -> tuple[CaseRead | None, list[str]]:
    """Build the case and its zenoh-pico reference as Layer C1cs does (both are the cost gate's
    builds, so a run after it builds nothing again) and read their symbols, or say why a figure
    read from them would be none."""
    got = cost.build(case, env, prefixes)
    asked = wz_config.pico_reference(wz_config.load_decl(), cost.case_features(case))
    link, cflags = cost.reference_build(got.link_args)
    ref = cost.pico_reference_build(asked, env, prefixes, link, cflags)
    work, _, _ = cost.pico_reference_tree(asked, env, link, cflags)
    reference = f"{case.id} (its zenoh-pico reference)"
    findings = (cost.purity_findings(case.id, got.leaked) + cost.link_findings(case.id, got)
                + cost.purity_findings(reference, ref.leaked) + cost.link_findings(reference, ref))
    built = object_symbols(work / PICO_TARGET_OBJECTS)
    if not built:
        findings.append(f"{reference}: no object file under {work / PICO_TARGET_OBJECTS}, so no "
                        f"zenoh-pico symbol has a source")
    if findings:
        return None, findings
    compiled = {rel for files in built.values() for rel in files if rel.endswith(".c")}
    definitions = pico_definitions(work / "src", compiled)
    wz, unread = wz_symbols(nm_text(cost.case_build(case, env).lib))
    pico = pico_symbols(nm_text(work / PICO_LIBRARY), definitions, built)
    return CaseRead(wz, pico, unread, ref.pin, ref.toolchain), []


def shard_case_ids(shards: int, shard: int) -> list[str]:
    weights = census_shard_plan.read_weights(cost.CASE_WEIGHTS.read_text(encoding="utf-8"))
    notes: list[str] = []
    ids = cost.shard_cases(shards, shard, weights, notes)
    for note in notes:
        print(f"  size-ledger: {note}", file=sys.stderr)
    return ids


def cmd_run(measure_only: bool, shard: tuple[int, int] | None) -> int:
    table = load_ledger()
    blocking = rule_findings(table, pico_case_ids())
    rows_found = [] if blocking else row_population_findings(table)
    for finding in blocking:
        print(f"  size-ledger FAIL: {finding}", file=sys.stderr)
    if blocking or not isinstance(table, dict):
        return 1
    rc = 0
    for finding in rows_found:
        if measure_only:
            print(f"  size-ledger: note: {finding}")
        else:
            print(f"  size-ledger FAIL: {finding}", file=sys.stderr)
            rc = 1
    case = next(c for c in cost.CASES if c.id == table["case"])
    if shard is not None:
        try:
            planned = shard_case_ids(*shard)
        except (OSError, ValueError) as e:
            print(f"  size-ledger: {cost.CASE_WEIGHTS.name}: {e}", file=sys.stderr)
            return 2
        if case.id not in planned:
            print(f"  size-ledger: {case.id} is built on another shard of {shard[0]}; this shard "
                  f"checked the ledger itself")
            return rc
    try:
        env, prefixes = cost.build_env()
        linker = cost.gnu_ld_version(env)
    except (ValueError, RuntimeError) as e:
        print(f"  size-ledger: {e}", file=sys.stderr)
        return 2
    try:
        read, refused = read_case(case, env, prefixes)
    except (subprocess.CalledProcessError, OSError, RuntimeError) as e:
        print(f"  size-ledger FAIL: {case.id}: the case or its reference could not be read: {e}",
              file=sys.stderr)
        return 1
    for finding in refused:
        print(f"  size-ledger FAIL: {finding}", file=sys.stderr)
    if read is None:
        return 1
    areas = area_ids(table)
    rules = {side: side_rules(table, side) for side in SIDES}
    wz = tally(read.wz, rules["wz"], areas)
    pico = tally(read.pico, rules["pico"], areas)
    print(f"  size-ledger: {case.id}: function bytes by area, one count per address, against "
          f"zenoh-pico {read.pin} as the same build ({read.toolchain}; both linked by {linker})")
    for line in table_lines(table, wz, pico):
        print(line)
    notes: list[str] = []
    if read.unread:
        notes.append(f"{len(read.unread)} wz symbol(s) begin _R and do not read as v0, so no "
                     f"owner places them: {', '.join(read.unread[:UNCLASSIFIED_NAMED])}")
    for side, tallied in (("wz", wz), ("pico", pico)):
        idle = unused_rules(table, side, tallied.used)
        if idle:
            notes.append(f"the {side} rules that placed no symbol of this case: {', '.join(idle)}")
    limit = table["unclassified_bytes_at_most"]
    findings = (unclassified_findings("wz", wz, limit)
                + unclassified_findings("zenoh-pico", pico, limit))
    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    readings, missing = area_readings(areas, wz, pico, read.pin, read.toolchain, today)
    findings += missing
    rows = table["rows"] if isinstance(table.get("rows"), dict) else {}
    if not measure_only:
        graded, said = grade_areas(rows, readings)
        findings += graded
        notes += said
    for note in notes:
        print(f"  size-ledger: {note}")
    if readings:
        print(f"  size-ledger: the rows this run reads for {LEDGER.relative_to(ROOT)} rows (each "
              f"replaces the row of its area):")
        for n, (area, reading) in enumerate(readings.items(), 1):
            row = ceiling_row(reading, row_debt(rows.get(area)))
            print(f"    {format_row(area, row)}{',' if n < len(readings) else ''}")
    for finding in findings:
        if measure_only:
            print(f"  size-ledger: note: {finding}")
        else:
            print(f"  size-ledger FAIL: {finding}", file=sys.stderr)
            rc = 1
    if rc == 0 and not measure_only:
        print(f"  size-ledger: {case.id}: {len(readings)} area(s) under their rows against "
              f"zenoh-pico, unclassified text within {limit} bytes on each side")
    return rc


# ── selftest ───────────────────────────────────────────────────────────────────────────────────

_SELFTEST_C = """\
/* a comment with a body { in it } */
#include <stddef.h>
#define _Z_MAKE(x) static int x##_made(void) { return 0; }
static const char *_z_text = "{ not a body }";
int _z_plain(int a, char *b) {
    return a;
}
z_result_t _z_multi(const void *zs,
                    int (*cb)(void *)) {
    if (zs) { return 0; }
    return 1;
}
static inline void _z_inline(void) { }
void _z_declared(void);
__attribute__((unused)) static void _z_attributed(void) {
}
#if A
int _z_twice(void) {
#else
int _z_twice(void) {
#endif
    return 0;
}
typedef struct {
    int x;
} _z_type_t;
static const int _z_table[] = {1, 2};
    int _z_indented(void) { return 0; }
char _z_quote(void) { return '{'; }
"""


def cmd_selftest() -> int:
    ok = 0
    bad = 0

    def expect(name: str, cond: bool) -> None:
        nonlocal ok, bad
        if cond:
            ok += 1
        else:
            bad += 1
            print(f"  size-ledger selftest FAIL: {name}", file=sys.stderr)

    def owner(symbol: str) -> tuple[str, ...] | None:
        try:
            return v0_owner(symbol)
        except ManglingError:
            return None

    # The v0 reader, on names read from the release library of the case.
    expect("an item's owner is its path",
           owner("_RNvNtCs4aQLcTZGdSB_15wz_session_core16handshake_encode17encode_keep_alive")
           == ("wz_session_core", "handshake_encode", "encode_keep_alive"))
    expect("a trait impl's owner is the module that wrote the impl, through a back-reference",
           owner("_RNvXs0_NtCs4aQLcTZGdSB_15wz_session_core4sinkNtB5_11PlainSampleNtB5_"
                 "10SampleView4kind") == ("wz_session_core", "sink", "kind"))
    expect("an impl for another crate's type is the impl's module's, not the type's crate's",
           owner("_RNvXs4_NtCs6cZY5cGSJiU_15wz_runtime_coop13session_driveINtNtCs40k4W9msRzi_"
                 "5alloc2rc2RcINtNtB7_8ip_stack8IpDriverNtNtCsgbwRwihG2QS_16wz_runtime_posix3net"
                 "14PosixUdpSocketNtNtB1Q_6stream14PosixTcpSocketNtNtB7_11stream_link8NoStream"
                 "NtNtB7_12link_storage8RxBufferNtB3G_8TxBufferEENtB5_19SessionDatagramLink"
                 "11keeps_inputCsh5MnEZfGlYB_12wz_capi_pico")
           == ("wz_runtime_coop", "session_drive", "keeps_input"))
    expect("a trait item with no impl (a default method) is the trait's",
           owner("_RNvYINtNtCs6cZY5cGSJiU_15wz_runtime_coop8ip_stack8IpDriverNtNtCsgbwRwihG2QS_"
                 "16wz_runtime_posix3net14PosixUdpSocketNtNtBY_6stream14PosixTcpSocketNtNtB7_"
                 "11stream_link8NoStreamNtNtB7_12link_storage8RxBufferNtB2N_8TxBufferENtNtCs4aQ"
                 "LcTZGdSB_15wz_session_core4link15BoxedLinkDriver14shape_tx_queueCsh5MnEZfGlYB_"
                 "12wz_capi_pico")
           == ("wz_session_core", "link", "BoxedLinkDriver", "shape_tx_queue"))
    expect("a generic function is its own path's, whatever its arguments",
           owner("_RINvNtCs6cZY5cGSJiU_15wz_runtime_coop8executor11drop_erasedNtNtCs4aQLcTZGdSB_"
                 "15wz_session_core11driver_loop13DriverOutcomeECsh5MnEZfGlYB_12wz_capi_pico")
           == ("wz_runtime_coop", "executor", "drop_erased"))
    expect("drop glue is core's, whatever type it drops",
           owner("_RINvNtCscI6d9CVNmLh_4core3ptr9drop_glueNtNtCsgbwRwihG2QS_16wz_runtime_posix"
                 "6stream12StreamReaderEBF_") == ("core", "ptr", "drop_glue"))
    expect("an inherent impl over a placeholder type reads",
           owner("_RNvNvMs_NtCs40k4W9msRzi_5alloc3vecINtB6_3VecppE6remove13assert_failed")
           == ("alloc", "vec", "remove", "assert_failed"))
    expect("a closure's shim is the trait item's, and the closure and shim add no segment",
           owner("_RNSNvYNCINvNtCs4aQLcTZGdSB_15wz_session_core15network_message19try_for_each_"
                 "recordNCNvNtBb_5drive20frame_records_extent0E0INtNtNtCscI6d9CVNmLh_4core3ops8"
                 "function6FnOnceuE9call_once6vtableBb_")
           == ("core", "ops", "function", "FnOnce", "call_once"))
    expect("an identifier that starts with an underscore keeps it",
           owner("_RNvCs9hJ03s5DiqP_7___rustc35___rust_no_alloc_shim_is_unstable_v2")
           == ("__rustc", "__rust_no_alloc_shim_is_unstable_v2"))
    expect("a toolchain suffix after the name is not read",
           owner("_RNvNtCs4aQLcTZGdSB_15wz_session_core16handshake_encode17encode_keep_alive"
                 ".llvm.4242") == ("wz_session_core", "handshake_encode", "encode_keep_alive"))
    expect("a name that ends inside a production does not read", owner("_RNvC") is None)
    expect("a legacy-mangled name is not v0",
           owner("_ZN4core3ptr13drop_in_place17h0123456789abcdefE") is None)
    expect("a back-reference that does not point back does not read", owner("_RNvB9_3foo") is None)
    expect("a back-reference into its own text ends instead of looping",
           owner("_RNSNvYNCINvNtCs4aQLcTZGdSB_15wz_session_core15network_message19try_for_each_"
                 "recordNCNvNtB6_5drive20frame_records_extent0E0INtNtNtCscI6d9CVNmLh_4core3ops8"
                 "function6FnOnceuE9call_once6vtableBb_") is None)

    # The C reader: a head at column 0 followed by a body, and nothing else.
    defined = c_definitions(_SELFTEST_C)
    expect("the C reader finds every definition at column 0",
           {"_z_plain", "_z_multi", "_z_inline", "_z_attributed", "_z_twice",
            "_z_quote"} <= defined)
    expect("the C reader takes no declaration, type, table, macro body or indented head",
           not defined & {"_z_declared", "_z_type_t", "_z_table", "_z_text", "x", "_z_made",
                          "_z_indented", "if", "_Z_MAKE"})
    expect("comments, literals and preprocessor lines are blanked with their newlines kept",
           strip_c('a /* x\ny */ b "c{" \'}\'\n#define D(x) { x }\ne').count("\n") == 3
           and "{" not in strip_c('"{" /* { */ \'{\'\n#if X {\n'))

    # The owners of a zenoh-pico symbol.
    parsed = {"_z_both": {"src/a.c", "src/b.c"}, "_z_inline": {"include/x.h"}}
    objects = {"_z_both": {"src/a.c"}, "_z_inline": {"src/a.c", "src/b.c"},
               "_z_made_elem_clear": {"src/a.c", "src/c.c"}}
    expect("a name two files define narrows to the one the build compiled it in",
           pico_owners("_z_both", parsed, objects) == {"src/a.c"})
    expect("a header's inline function is the header's, not its includers'",
           pico_owners("_z_inline", parsed, objects) == {"include/x.h"})
    expect("a name only a macro writes is owned by the objects that define it",
           pico_owners("_z_made_elem_clear", parsed, objects) == {"src/a.c", "src/c.c"})
    expect("an object listing reads as sources",
           object_owners("/b/o/src/api/api.c.o:0000000000000010 T z_open\n"
                         "/b/o/src/api/api.c.o:0000000000000000 t _z_helper.isra.0\n"
                         "/b/o/src/x.c.o:0000000000000000 d _z_data\n"
                         "/b/o/src/x.c.o:0000000000000000 T z_open\n", "/b/o")
           == {"z_open": {"src/api/api.c", "src/x.c"}, "_z_helper": {"src/api/api.c"}})
    expect("a listing keeps only sized text symbols",
           text_symbols("0000000000000010 0000000000000020 T a\n0000000000000040 t b\n"
                        "0000000000000050 0000000000000008 d c\n"
                        "0000000000000060 0000000000000004 W d\n"
                        "0000000000000070 0000000000000000 t e\n")
           == [(0x10, 0x20, "a"), (0x60, 0x4, "d")])

    # The rules.
    rules = Rules(names=(("^z_", re.compile("^z_"), "door"),
                         ("_elem_[a-z]+$", re.compile("_elem_[a-z]+$"), "lang")),
                  owners={"a": "x", "a::b": "y"}, separator="::")
    expect("the longest owner prefix places a symbol, at a segment boundary only",
           classify(rules, Symbol(0, 1, "_R1", ("a::b::c",)))[0] == "y"
           and classify(rules, Symbol(0, 1, "_R2", ("a::bc",)))[0] == "x"
           and classify(rules, Symbol(0, 1, "_R3", ("ab",)))[0] is None)
    expect("a name rule comes before the owners, on the name without its clone suffix",
           classify(rules, Symbol(0, 1, "z_open", ()))[0] == "door"
           and classify(rules, Symbol(0, 1, "_z_q_elem_clear.isra.0", ("a::b",)))[0] == "lang")
    expect("several owners place a symbol only when their rules agree",
           classify(rules, Symbol(0, 1, "f", ("a::b", "a::b::c")))[0] == "y"
           and classify(rules, Symbol(0, 1, "f", ("a::b", "a::q")))[0] is None
           and classify(rules, Symbol(0, 1, "f", ("a::b", "zz")))[0] is None)
    expect("a symbol with no owner and no name rule is unclassified",
           classify(rules, Symbol(0, 1, "memcpy", ()))[0] is None)
    expect("a source path matches at a directory boundary",
           classify(Rules((), {"src/session": "s", "src/session/keyexpr.c": "k"}, "/"),
                    Symbol(0, 1, "f", ("src/session/keyexpr.c",)))[0] == "k"
           and classify(Rules((), {"src/session": "s"}, "/"),
                        Symbol(0, 1, "f", ("src/sessionx.c",)))[0] is None)
    counted = tally([Symbol(0x10, 8, "_R1", ("a::b",)), Symbol(0x10, 8, "_R2", ("a::b",)),
                     Symbol(0x20, 4, "_R3", ("a",)),
                     Symbol(0x30, 2, "_R4", ("a",)), Symbol(0x30, 2, "_R5", ("a::b",)),
                     Symbol(0x40, 16, "_R6", ("a",)), Symbol(0x40, 16, "_R7", ("a::b",)),
                     Symbol(0x40, 12, "_R8", ("a::b::c",)),
                     Symbol(0x50, 32, "memcpy", ())], rules, ["door", "lang", "x", "y"])
    expect("the names of one address are one body, counted once at its largest size",
           counted.total == 8 + 4 + 2 + 16 + 32)
    expect("a body goes to the area most of its names are in, a tie to the area listed first",
           counted.by_area == {"door": 0, "lang": 0, "x": 4 + 2, "y": 8 + 16})
    expect("an unplaced body is unclassified with its names",
           counted.unclassified == [(32, ("memcpy",))] and counted.unclassified_bytes == 32)
    expect("the rules a run used are recorded",
           counted.used == {"owners a", "owners a::b"})
    expect("unclassified bytes at the limit pass and over it fail, naming the largest",
           unclassified_findings("wz", counted, 32) == []
           and len(unclassified_findings("wz", counted, 31)) == 1
           and "memcpy" in unclassified_findings("wz", counted, 31)[0])

    # The ratchet, with the pico ceiling's rule.
    debt = "debt-pico-host-size-ceiling"

    def rd(wz: int, pico: int) -> dict:
        return ceiling_reading(wz, pico, "6a881c21dad1", "cc 1", "2026-11-23")

    ratchet = ceiling_row(rd(200_000, 100_000), debt)
    unfilled = {"ratio_at_most": None, "debt": debt, "reading": None}
    locked = ceiling_row(rd(90_000, 100_000), debt)
    graded, said = grade_areas(
        {"up": ratchet, "down": ratchet, "blank": unfilled, "lost": locked, "won": ratchet},
        {"up": rd(230_000, 100_000), "down": rd(150_000, 100_000), "blank": rd(120_000, 100_000),
         "lost": rd(120_000, 100_000), "won": rd(90_000, 100_000)})
    expect("an area over its ratchet fails", any(f.startswith("up:") for f in graded))
    expect("an area under its ratchet passes and prints the tighter row",
           not any(f.startswith("down:") for f in graded)
           and any(n.startswith("down:") and '"ratio_at_most": 1.5' in n for n in said))
    expect("an unfilled area fails, naming the ledger and the command that prints its row",
           any(f.startswith("blank:") and str(LEDGER.relative_to(ROOT)) in f and "--measure" in f
               for f in graded))
    expect("a locked area that reads no WIN fails", any(f.startswith("lost:") for f in graded))
    expect("an area that reaches WIN fails until locked, and closes no debt of its own",
           any(f.startswith("won:") and '"verdict": "win"' in f and "close" not in f
               for f in graded))
    expect("a malformed row is left to the population check",
           grade_areas({"bad": {"ratio_at_most": 2.0}}, {"bad": rd(300_000, 100_000)}) == ([], []))
    readings, missing = area_readings(
        ["a", "b", "c"], Tally({"a": 10, "b": 0, "c": 5}), Tally({"a": 5, "b": 5, "c": 0}),
        "p", "cc 1", "2026-11-23")
    expect("an area with no byte on either side has no ratio and fails",
           list(readings) == ["a"] and len(missing) == 2
           and any(m.startswith("b:") and "wz has no byte" in m for m in missing)
           and any(m.startswith("c:") and "zenoh-pico has no byte" in m for m in missing))

    # The ledger: the committed one is well formed, and each refusal is reached.
    committed = load_ledger()
    cases = pico_case_ids()
    expect("the committed ledger is well formed and names a pico case of the cost gate",
           isinstance(committed, dict) and ledger_findings(committed, cases) == [])
    if isinstance(committed, dict):
        def broken(change) -> list[str]:
            table = json.loads(json.dumps(committed))
            change(table)
            return ledger_findings(table, cases)

        first = area_ids(committed)[0]
        expect("an area without a row is refused",
               any("no row" in f for f in broken(lambda t: t["rows"].pop(first))))
        expect("a row for no area is refused",
               any("for no declared area" in f
                   for f in broken(lambda t: t["rows"].update({"ghost": unfilled}))))
        expect("a rule naming no declared area is refused",
               any("no declared area" in f
                   for f in broken(lambda t: t["rules"]["wz"]["owners"].update({"zz": "ghost"}))))
        expect("a name rule that is no regular expression is refused",
               any("no regular expression" in f
                   for f in broken(lambda t: t["rules"]["pico"]["names"].update({"(": first}))))
        expect("an owner rule of the wrong shape is refused",
               any("no relative source path" in f
                   for f in broken(lambda t: t["rules"]["pico"]["owners"].update({"../x": first}))))

        def lonely(t: dict) -> None:
            t["areas"].append({"id": "lonely", "title": "l"})
            t["rows"]["lonely"] = unfilled
            t["rules"]["wz"]["owners"]["zz"] = "lonely"

        expect("an area no rule of a side names is refused",
               any("no pico rule names the area 'lonely'" in f for f in broken(lonely)))
        expect("a case that is no pico case of the cost gate is refused",
               any("no pico case" in f for f in broken(lambda t: t.update({"case": "ghost"}))))
        expect("an area declared twice is refused",
               any("declared twice" in f
                   for f in broken(lambda t: t["areas"].append(dict(t["areas"][0])))))
        expect("a negative unclassified limit is refused",
               any("no byte count" in f
                   for f in broken(lambda t: t.update({"unclassified_bytes_at_most": -1}))))
        expect("a side missing from the rules is refused",
               any("exactly the sides" in f for f in broken(lambda t: t["rules"].pop("pico"))))

        # The committed rules decide the areas the architecture names.
        sides = {side: side_rules(committed, side) for side in SIDES}

        def placed(side: str, name: str, *owners: str) -> str | None:
            return classify(sides[side], Symbol(0, 1, name, owners))[0]

        expect("the committed wz rules place the engine, the doors, the transport, the codec, the "
               "key expressions, the driver and the language support",
               placed("wz", "_R", "wz_capi_coop::engine::Engine::step") == "sessions"
               and placed("wz", "z_open") == "doors"
               and placed("wz", "_R", "wz_capi_pico::pubsub::declare") == "doors"
               and placed("wz", "_R", "wz_session_core::session_actions::open") == "transport"
               and placed("wz", "_R", "wz_session_core::inbound::parse_inbound") == "codec"
               and placed("wz", "_R", "wz_codecs::msg_put::encode") == "codec"
               and placed("wz", "_R", "wz_session_core::keyexpr_match::intersects") == "keyexpr"
               and placed("wz", "_R", "wz_runtime_coop::executor::run") == "driver"
               and placed("wz", "_R", "core::ptr::drop_glue") == "language"
               and placed("wz", "rust_eh_personality") == "language")
        expect("the committed zenoh-pico rules place the same areas by source",
               placed("pico", "_z_transport_rx", "src/transport/unicast/rx.c") == "transport"
               and placed("pico", "_z_keyexpr_intersects", "src/session/keyexpr.c") == "keyexpr"
               and placed("pico", "_z_subscribe", "src/net/primitives.c") == "sessions"
               and placed("pico", "z_open", "src/api/api.c") == "doors"
               and placed("pico", "_z_push_encode", "src/protocol/codec/network.c") == "codec"
               and placed("pico", "_z_bytes_len", "include/zenoh-pico/collections/bytes.h")
               == "language"
               and placed("pico", "_z_open_tcp", "src/system/unix/network.c") == "driver"
               and placed("pico", "_z_arc_slice_elem_clear", "src/api/api.c",
                          "src/net/sample.c") == "language")

    print(f"  size-ledger selftest: {ok}/{ok + bad} arm(s) pass")
    return 0 if bad == 0 else 1


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in ("--check", "--measure", "--selftest") or (
        argv[1] == "--selftest" and len(argv) != 2
    ):
        print(__doc__, file=sys.stderr)
        return 2
    if argv[1] == "--selftest":
        return cmd_selftest()
    parser = argparse.ArgumentParser(prog=f"size_ledger_gate.py {argv[1]}", add_help=False)
    parser.add_argument("--shards", type=int)
    parser.add_argument("--shard", type=int)
    try:
        args = parser.parse_args(argv[2:])
    except SystemExit:
        return 2
    shard = None
    if args.shards is not None or args.shard is not None:
        if args.shards is None or args.shard is None or not 0 <= args.shard < args.shards:
            print("  size-ledger: give --shards N and --shard K with 0 <= K < N", file=sys.stderr)
            return 2
        shard = (args.shards, args.shard)
    sys.stdout.reconfigure(line_buffering=True)
    return cmd_run(measure_only=argv[1] == "--measure", shard=shard)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
