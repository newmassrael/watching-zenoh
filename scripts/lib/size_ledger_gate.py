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
neither is built a second time. A library that holds a build path, that another linker wrote, or
whose strip moved its code (below) is no figure here, as it is no figure there.

Each is ONE build with its line tables, as the shipping entry builds a release
(`wz_package.ship_debug_env`; the reference with GCC's level 1, `LINE_TABLES_CFLAGS` of
`reference_build`). The cost gate measures that build with its debug information taken off
(`wz_package.strip_debug`), the file a deployer receives, and this gate reads the areas from the
line tables of the same build, so they describe the code measured and no other: a second build with
line tables beside one without them was measured to differ in its executable sections. Taking debug
sections off moves no code, and that is not taken on trust: the cost gate holds every executable
section of the stripped file (its name, its address and a digest of its bytes) to the build's
(`link_findings`).

What is code is what it was: the text symbols with a size (`nm --defined-only -S`, kinds t, T, w
and W). LLVM merges identical functions into aliases of one body, and the linker keeps every name
of an address, so the names of one address are ONE body, counted once at its largest size.

## Who wrote a byte

Fat LTO inlines a helper into its callers, so the bytes of a symbol are the code of every function
inlined into it. Read by symbol, the change that removed the GOT reads on 2026-11-25 took 13.6 KB
from the total and still showed the doors 5.2 KB larger: the helpers it let the compiler inline
into the `z_*` doors had moved there. So a body's bytes are read the way bloaty reads inlines:
each address goes to the innermost source location the line table (`.debug_line`) gives it, which
for inlined code is the file of the inlined function, and the FILE is placed by the owner rules.
The copies of a generic go to the file that defines it, as they go to its owner in the symbol
reading.

The line tables are read from the build's bytes, DWARF 2 to 5, with `.debug_info` giving each
unit's compilation directory, which a relative path is read from. A sequence that starts outside
the library's executable sections is the table of a function the linker discarded (GNU ld writes
its address as 0) and is left out. A row of line 0, and a byte no row covers (an object built
without line tables, the C runtime's), is UNATTRIBUTED: counted apart, in no area, and either
library's unattributed bytes over `unattributed_bytes_at_most` fail, naming the bodies that hold
most. LLVM gives line 0 to more code than GCC does, so the limit is what keeps that difference from
taking bytes out of wz's areas unseen.

wz: the owner of a file is a crate::module path, as an owner rule names it. A file in a crate's
source tree (the directory of its library's root, found by the `Cargo.toml` above it under the
checkout or the cargo home the build normalization maps) is the module its path names: `a/b.rs`
and `a/b/mod.rs` are `crate::a::b`. The standard library's files
(`/rustc/<hash>/library/<crate>/src/..`) and those of the crates it vendors are read the same way
from their paths. A file outside every source tree is code a crate includes (the SCE output under
`out/`): it is the module its own functions are named in, the longest module path the v0 names of
the bodies that begin in it share, and one none of whose functions is a body of its own is the
crate whose directory under `out/` holds it (`out/<dir>` mirrors `crates/<dir>`).

zenoh-pico: the owner of a file is its path in the export of the submodule the reference was built
from (`src/..`, `include/..`). A file outside the export is the C toolchain's,
`toolchain/<its path>`: the compiler's and the C library's headers, whose inline functions (the
fortified string functions) are language support.

## The symbol reading, beside it

Before the line tables, a whole body went to the area its NAMES were placed in (the area most of
them are placed in, a tie to the area the ledger lists first; a name rule first, and a symbol with
several owners placed only when the rules of all of them name one area). `--explain` still prints
what that reading gives each area beside the line reading. It costs nothing, the symbols being read
anyway, and it is kept: the difference between the two readings of an area is the code inlining
moved across its border. The owner of a symbol in it:

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
longest that matches at a segment boundary places it). A byte goes to the owner rule of its file,
but a byte of a body's OWN file (the file of the body's first row, where its function is written)
goes to the area a name rule gives the body when one does: a function a C macro writes, which the
line table places at the macro's expansion, and a symbol the toolchain requires keep the area their
name gives them, while what was inlined into them still goes by its own file. A byte whose file no
rule places is UNCLASSIFIED, and either library's unclassified bytes over
`unclassified_bytes_at_most` fail, naming the largest owners: a crate, module or file a change
brings is given an area in that commit. A rule that placed nothing in a run is printed, so a
renamed module is seen.

## The ratchet

Each area has a row, with the rule of a row of the pico ceiling (pico_host_ceiling.py, the one
implementation): locked at WIN, or `ratio_at_most`, the ratio of the reading it was set from rounded
up to four places, under the open-debt item it is registered under. A reading over its row by more
than the tolerance fails; one under it by more prints the tighter row to commit; an area that reads
WIN fails until its row is locked, and a locked area reads WIN or fails. A row whose ratio is null
is unfilled and fails with the row this run reads. An area that reads no byte on one side has no
ratio and fails: its rules give that side none of its code.

## What holds an area's bytes

`--explain` reads the same case as `--measure` (the same builds, so after a measure it builds
nothing again) and says, for each area, what holds its bytes, and how many bytes the symbol reading
gives it: on the wz side the owner modules and the source files by bytes, the bodies by their bytes
in the area with the name each is shown by and how many other names its address carries, and the
generic functions with more than one copy (a demangled name with every generic argument list
removed is one function); on the zenoh-pico side the source files by bytes. The unclassified and
the unattributed bytes are explained as two areas of their own. The tables print the head of each
list; the whole lists go to `size-ledger/explain-<case>.json` under the cost gate's target
directory, with every source file of each side, its owner and how the owner was read, and the
report it replaces is kept beside it as `explain-<case>.previous.json`, so two measurements diff.
Names are demangled by `c++filt` (binutils, beside the `nm` this gate reads with), and shown
mangled when it cannot.

## Where it runs

Layer C1cs, as the leg after the cost gate, whose builds it reads; it builds nothing of its own.
With `--shards N --shard K` the case is read only on the shard the cost gate deals it to, and every
shard checks the ledger itself, which needs no build. Layer C0 runs `--selftest`, which holds the
readers, the rules and the ratchet on synthetic input and the committed ledger to its own rules.

Usage:
    size_ledger_gate.py --check [--shards N --shard K]
                               read the case and grade every area against its row
    size_ledger_gate.py --measure [--shards N --shard K]
                               read the case and print the table and the rows to commit
    size_ledger_gate.py --explain [--shards N --shard K]
                               --measure, then what holds each area's bytes, kept as JSON
    size_ledger_gate.py --selftest

Exit codes: 0 the ledger holds, 1 a finding, 2 a usage error or a host that cannot build.
"""

from __future__ import annotations

import argparse
import bisect
import datetime
import json
import pathlib
import posixpath
import re
import struct
import subprocess
import sys
import tempfile
import zlib
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build_normalization  # noqa: E402  (the prefixes a build's paths are mapped by)
import capability_cost_gate as cost  # noqa: E402  (the builds this gate reads, one copy)
import census_shard_plan  # noqa: E402  (the shard plan of Layer C1cs)
import elf_facts  # noqa: E402  (the one reader of an ELF's sections)
import wz_config  # noqa: E402  (the declaration a reference is derived from)
from pico_host_ceiling import (  # noqa: E402  (the one rule of a ratio row)
    ceiling_reading, ceiling_row, format_row, grade_ceiling, row_findings,
)

ROOT = pathlib.Path(__file__).resolve().parents[2]
LEDGER = ROOT / "deploy" / "size_ledger.json"
LEDGER_SCHEMA = 2
TABLE_KEYS = frozenset(("about", "schema", "case", "unclassified_bytes_at_most",
                        "unattributed_bytes_at_most", "areas", "rows", "rules"))
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
# --explain: how many rows each of its tables prints (the JSON keeps every row), the width a name
# is cut to there, the tool that demangles, and where the report goes under the target directory.
EXPLAIN_OWNERS = 30
EXPLAIN_SYMBOLS = 40
EXPLAIN_GENERICS = 30
EXPLAIN_FILES = 20
EXPLAIN_NAME_WIDTH = 140
EXPLAIN_SCHEMA = 2
DEMANGLER = "c++filt"
EXPLAIN_DIR = "size-ledger"
UNCLASSIFIED_AREA = "(unclassified)"
UNATTRIBUTED_AREA = "(unattributed)"
# How --explain names the bytes of a body no line row gives a source, and a source with no owner.
NO_LINE = "(no source line)"
NO_OWNER = "(no owner)"
# The tree the SCE output is committed in, whose directories mirror those of `crates/`.
OUT_TREE = "out"
# The owner of a zenoh-pico reference's source outside the export: the C toolchain's headers.
TOOLCHAIN_OWNER = "toolchain"
# How a source file's owner was read (module doc, "Who wrote a byte").
BY_PATH = "path"
BY_FUNCTIONS = "functions"
BY_OUT_TREE = "out directory"


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


# ── the line tables of a library: which source each byte of code came from ───────────────────

SHF_EXECINSTR = elf_facts.SHF_EXECINSTR
SHF_COMPRESSED = 0x800
ELFCOMPRESS_ZLIB = 1
# The sections the line reader reads: the tables, the units that name their directories, and the
# strings either can point into.
DWARF_SECTIONS = (".debug_line", ".debug_info", ".debug_abbrev", ".debug_str", ".debug_line_str",
                  ".debug_str_offsets")
DW_AT_STMT_LIST = 0x10
DW_AT_COMP_DIR = 0x1B
DW_AT_STR_OFFSETS_BASE = 0x72
DW_LNCT_PATH = 1
DW_LNCT_DIRECTORY_INDEX = 2
# The forms whose value is a fixed number of bytes (DWARF 5, section 7.5.6).
_FIXED_FORMS = {0x05: 2, 0x06: 4, 0x07: 8, 0x0B: 1, 0x0C: 1, 0x11: 1, 0x12: 2, 0x13: 4, 0x14: 8,
                0x1C: 4, 0x1E: 16, 0x20: 8, 0x24: 8, 0x29: 1, 0x2A: 2, 0x2B: 3, 0x2C: 4}
_STRX_FORMS = {0x25: 1, 0x26: 2, 0x27: 3, 0x28: 4}


class DwarfError(ValueError):
    """Line tables this reader cannot read; the message says where."""


class _Cursor:
    """A read position in one DWARF section, which no read takes past `end`."""

    def __init__(self, data: bytes, little: bool, at: int = 0) -> None:
        self.data = data
        self.little = little
        self.pos = at
        self.end = len(data)

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > self.end:
            raise DwarfError(f"a field at {self.pos:#x} runs past its unit")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u(self, n: int) -> int:
        return int.from_bytes(self.take(n), "little" if self.little else "big")

    def s8(self) -> int:
        value = self.u(1)
        return value - 256 if value >= 128 else value

    def uleb(self) -> int:
        value = shift = 0
        while True:
            byte = self.u(1)
            value |= (byte & 0x7F) << shift
            shift += 7
            if byte < 0x80:
                return value

    def sleb(self) -> int:
        value = shift = 0
        while True:
            byte = self.u(1)
            value |= (byte & 0x7F) << shift
            shift += 7
            if byte < 0x80:
                return value - (1 << shift) if byte & 0x40 else value

    def cstr(self) -> str:
        stop = self.data.find(b"\x00", self.pos, self.end)
        if stop < 0:
            raise DwarfError(f"a string at {self.pos:#x} runs past its unit")
        text = self.data[self.pos:stop].decode("utf-8", "replace")
        self.pos = stop + 1
        return text

    def unit(self) -> tuple[int, int]:
        """Read a unit's length, bound the cursor to the unit, and return the unit's end and the
        size of its offsets (4, or 8 in the 64-bit format)."""
        length, size = self.u(4), 4
        if length == 0xFFFFFFFF:
            length, size = self.u(8), 8
        elif length >= 0xFFFFFFF0:
            raise DwarfError(f"a unit at {self.pos - 4:#x} has the reserved length {length:#x}")
        end = self.pos + length
        if end > len(self.data):
            raise DwarfError(f"a unit at {self.pos - size:#x} runs past its section")
        self.end = end
        return end, size


def _string_at(sections: Mapping[str, bytes], name: str, offset: int) -> str:
    data = sections.get(name, b"")
    stop = data.find(b"\x00", offset)
    if not 0 <= offset < len(data) or stop < 0:
        raise DwarfError(f"a string at {offset:#x} lies outside {name}")
    return data[offset:stop].decode("utf-8", "replace")


def _form_value(cur: _Cursor, form: int, offsets: int, address: int,
                sections: Mapping[str, bytes], implicit: int = 0) -> object:
    """The value of one attribute: an int, a str, ("strx", n) for the n-th string of the unit's
    string offsets, or None for a value this reader does not keep (a block, a supplementary
    string)."""
    if form == 0x16:  # indirect: the form comes first
        return _form_value(cur, cur.uleb(), offsets, address, sections, implicit)
    if form == 0x08:
        return cur.cstr()
    if form == 0x0E:
        return _string_at(sections, ".debug_str", cur.u(offsets))
    if form == 0x1F:
        return _string_at(sections, ".debug_line_str", cur.u(offsets))
    if form == 0x1A:
        return ("strx", cur.uleb())
    if form in _STRX_FORMS:
        return ("strx", cur.u(_STRX_FORMS[form]))
    if form == 0x01:
        return cur.u(address)
    if form in (0x10, 0x17, 0x1D):  # ref_addr, sec_offset, strp_sup
        return cur.u(offsets)
    if form in _FIXED_FORMS:
        return cur.u(_FIXED_FORMS[form])
    if form == 0x0D:
        return cur.sleb()
    if form in (0x0F, 0x15, 0x1B, 0x22, 0x23):  # udata, ref_udata, addrx, loclistx, rnglistx
        return cur.uleb()
    if form == 0x19:  # flag_present
        return 1
    if form == 0x21:  # implicit_const: the value is the abbreviation's
        return implicit
    if form in (0x09, 0x18):  # block, exprloc
        cur.take(cur.uleb())
        return None
    if form in (0x0A, 0x03, 0x04):  # block1, block2, block4
        cur.take(cur.u({0x0A: 1, 0x03: 2, 0x04: 4}[form]))
        return None
    raise DwarfError(f"the form {form:#x} at {cur.pos:#x} is no form of DWARF 2 to 5")


def _abbreviations(data: bytes, offset: int) -> dict[int, list[tuple[int, int, int]]]:
    """The abbreviation table at `offset` of `.debug_abbrev`: each code -> its (attribute, form,
    implicit constant) list."""
    cur = _Cursor(data, True, offset)
    table: dict[int, list[tuple[int, int, int]]] = {}
    while (code := cur.uleb()) != 0:
        cur.uleb()  # the tag
        cur.u(1)  # whether it has children
        attributes: list[tuple[int, int, int]] = []
        while True:
            name, form = cur.uleb(), cur.uleb()
            implicit = cur.sleb() if form == 0x21 else 0
            if name == 0 and form == 0:
                break
            attributes.append((name, form, implicit))
        table[code] = attributes
    return table


def unit_directories(sections: Mapping[str, bytes], little: bool) -> dict[int, str]:
    """Each line table's offset in `.debug_line` -> the compilation directory of the unit of
    `.debug_info` that names it (DW_AT_stmt_list, DW_AT_comp_dir), read from each unit's first
    entry."""
    info = sections.get(".debug_info", b"")
    abbrev = sections.get(".debug_abbrev", b"")
    tables: dict[int, dict[int, list[tuple[int, int, int]]]] = {}
    out: dict[int, str] = {}
    at = 0
    while at < len(info):
        cur = _Cursor(info, little, at)
        end, offsets = cur.unit()
        version = cur.u(2)
        if version >= 5:
            kind, address, table_at = cur.u(1), cur.u(1), cur.u(offsets)
            if kind in (2, 6):  # a type unit: its signature and its type's offset
                cur.take(8 + offsets)
            elif kind in (4, 5):  # a skeleton or split unit: its id
                cur.take(8)
        elif version >= 2:
            table_at, address = cur.u(offsets), cur.u(1)
        else:
            raise DwarfError(f"the unit at {at:#x} of .debug_info is DWARF version {version}")
        code = cur.uleb()
        if code:
            if table_at not in tables:
                tables[table_at] = _abbreviations(abbrev, table_at)
            if code not in tables[table_at]:
                raise DwarfError(f"the unit at {at:#x} of .debug_info uses the abbreviation "
                                 f"{code}, which its table does not have")
            values = {name: _form_value(cur, form, offsets, address, sections, implicit)
                      for name, form, implicit in tables[table_at][code]}
            directory = values.get(DW_AT_COMP_DIR)
            if isinstance(directory, tuple):
                base = values.get(DW_AT_STR_OFFSETS_BASE)
                directory = (_strx(sections, base, directory[1], offsets, little)
                             if isinstance(base, int) else None)
            stmt = values.get(DW_AT_STMT_LIST)
            if isinstance(stmt, int) and isinstance(directory, str):
                out[stmt] = directory
        at = end
    return out


def _strx(sections: Mapping[str, bytes], base: int, index: int, offsets: int, little: bool) -> str:
    cur = _Cursor(sections.get(".debug_str_offsets", b""), little, base + index * offsets)
    return _string_at(sections, ".debug_str", cur.u(offsets))


@dataclass(frozen=True)
class LineRow:
    """A row of a line table: the address it starts at, the source it names (None for a row of line
    0 or a file index the table has no file for) and its line."""
    address: int
    source: str | None
    line: int


def _full_path(name: str, directory: str | None, base: str | None) -> str:
    """A table's file name made absolute where its directory and the unit's directory allow, with
    `..` resolved: an `include!` of `crates/x/../../out/y.rs` is `out/y.rs`."""
    path = name
    if not posixpath.isabs(path) and directory:
        path = posixpath.join(directory, path)
    if not posixpath.isabs(path) and base:
        path = posixpath.join(base, path)
    return posixpath.normpath(path)


def line_table(data: bytes, at: int, little: bool, base: str | None,
               sections: Mapping[str, bytes]) -> tuple[list[tuple[list[LineRow], int]], int]:
    """The sequences of the line table at `at` of `.debug_line`, each its rows and the address it
    ends at, and the offset of the next table. `base` is the unit's compilation directory."""
    cur = _Cursor(data, little, at)
    end, offsets = cur.unit()
    if end == cur.pos:
        return [], end
    version = cur.u(2)
    if not 2 <= version <= 5:
        raise DwarfError(f"the line table at {at:#x} is DWARF version {version}")
    address_size = 8
    if version >= 5:
        address_size = cur.u(1)
        cur.u(1)  # the segment selector's size
    program = cur.u(offsets)
    program += cur.pos
    unit_length = cur.u(1)
    ops_per_unit = cur.u(1) if version >= 4 else 1
    cur.u(1)  # whether a row is a statement by default, which says nothing of its source
    line_base, line_range, opcode_base = cur.s8(), cur.u(1), cur.u(1)
    if line_range == 0 or ops_per_unit == 0 or opcode_base == 0:
        raise DwarfError(f"the line table at {at:#x} has a zero line range, operation count or "
                         f"opcode base")
    operands = [cur.u(1) for _ in range(opcode_base - 1)]
    files: list[tuple[str, str | None]] = []  # (name, directory) in the table's own numbering
    include: list[str] = []  # the directories of DWARF 2 to 4, numbered from 1
    if version >= 5:
        directories: list[str | None] = []
        for entry in _entries(cur, offsets, address_size, sections):
            path = entry.get(DW_LNCT_PATH)
            directories.append(path if isinstance(path, str) else None)
        if base is None and directories and directories[0]:
            base = directories[0]
        for entry in _entries(cur, offsets, address_size, sections):
            path, index = entry.get(DW_LNCT_PATH), entry.get(DW_LNCT_DIRECTORY_INDEX, 0)
            directory = (directories[index] if isinstance(index, int)
                         and 0 <= index < len(directories) else None)
            files.append((path if isinstance(path, str) else "", directory))
        first_file = 0
    else:
        while text := cur.cstr():
            include.append(text)
        while name := cur.cstr():
            index = cur.uleb()
            cur.uleb()  # the modification time
            cur.uleb()  # the length
            files.append((name, include[index - 1] if 0 < index <= len(include) else None))
        first_file = 1
    paths: dict[int, str | None] = {}

    def source(index: int) -> str | None:
        if index not in paths:
            at_ = index - first_file
            paths[index] = (_full_path(files[at_][0], files[at_][1], base)
                            if 0 <= at_ < len(files) and files[at_][0] else None)
        return paths[index]

    sequences: list[tuple[list[LineRow], int]] = []
    rows: list[LineRow] = []
    address, op_index, file_index, line = 0, 0, 1, 1

    def advance(operation: int) -> None:
        nonlocal address, op_index
        if ops_per_unit == 1:
            address += unit_length * operation
        else:
            address += unit_length * ((op_index + operation) // ops_per_unit)
            op_index = (op_index + operation) % ops_per_unit

    def emit() -> None:
        rows.append(LineRow(address, source(file_index) if line else None, line))

    cur.pos = program
    while cur.pos < end:
        op = cur.u(1)
        if op >= opcode_base:
            step = op - opcode_base
            advance(step // line_range)
            line += line_base + step % line_range
            emit()
        elif op == 0:
            length = cur.uleb()
            stop = cur.pos + length
            sub = cur.u(1) if length else 0
            if sub == 1:  # the end of a sequence: its end address, then the state is reset
                sequences.append((rows, address))
                rows = []
                address, op_index, file_index, line = 0, 0, 1, 1
            elif sub == 2:
                address, op_index = cur.u(length - 1), 0
            elif sub == 3:  # a file defined in the program (DWARF 2 to 4)
                name = cur.cstr()
                index = cur.uleb()
                files.append((name, include[index - 1] if 0 < index <= len(include) else None))
            cur.pos = stop
        elif op == 1:
            emit()
        elif op == 2:
            advance(cur.uleb())
        elif op == 3:
            line += cur.sleb()
        elif op == 4:
            file_index = cur.uleb()
        elif op == 8:
            advance((255 - opcode_base) // line_range)
        elif op == 9:
            address += cur.u(2)
            op_index = 0
        else:  # the column, the statement and block flags, the ISA: nothing of the source
            for _ in range(operands[op - 1]):
                cur.uleb()
    return sequences, end


def _entries(cur: _Cursor, offsets: int, address: int,
             sections: Mapping[str, bytes]) -> list[dict[int, object]]:
    """A DWARF 5 directory or file name table: its entry format, then its entries."""
    formats = [(cur.uleb(), cur.uleb()) for _ in range(cur.u(1))]
    return [{content: _form_value(cur, form, offsets, address, sections)
             for content, form in formats} for _ in range(cur.uleb())]


def line_sequences(sections: Mapping[str, bytes],
                   little: bool) -> list[tuple[list[LineRow], int]]:
    """Every sequence of every line table of `.debug_line`."""
    data = sections.get(".debug_line", b"")
    directories = unit_directories(sections, little)
    out: list[tuple[list[LineRow], int]] = []
    at = 0
    while at < len(data):
        found, at = line_table(data, at, little, directories.get(at), sections)
        out += found
    return out


@dataclass(frozen=True)
class Span:
    """Code bytes [start, end) of one row: the source the row names, None when it names none."""
    start: int
    end: int
    source: str | None


def live_spans(sequences: Iterable[tuple[list[LineRow], int]],
               code: list[tuple[int, int]]) -> list[Span]:
    """The rows of the sequences that start in the library's code (`code`, its executable
    sections' address ranges), each up to the next row; sorted, and where two overlap, the bytes
    are the span's that starts first. A sequence that starts outside the code describes a function
    the linker discarded (GNU ld gives it address 0, lld -1)."""
    spans: list[Span] = []
    for rows, end in sequences:
        if not rows or not any(lo <= rows[0].address < hi for lo, hi in code):
            continue
        for n, row in enumerate(rows):
            stop = rows[n + 1].address if n + 1 < len(rows) else end
            if stop > row.address:
                spans.append(Span(row.address, stop, row.source))
    spans.sort(key=lambda span: (span.start, span.end))
    out: list[Span] = []
    reach = -1
    for span in spans:
        start = max(span.start, reach)
        if start < span.end:
            out.append(Span(start, span.end, span.source))
        reach = max(reach, span.end)
    return out


def _section_data(data: bytes, section: elf_facts.Section) -> bytes:
    """A section's bytes, inflated when the linker compressed it (SHF_COMPRESSED with zlib)."""
    raw = elf_facts.section_bytes(data, section)
    if not section.flags & SHF_COMPRESSED:
        return raw
    order = "<" if data[5] == 1 else ">"
    # Elf64_Chdr is type, reserved, size, alignment; Elf32_Chdr type, size, alignment.
    head = order + ("IIQQ" if data[4] == 2 else "III")
    fields = struct.unpack_from(head, raw)
    kind, size = fields[0], fields[-2]
    if kind != ELFCOMPRESS_ZLIB:
        raise DwarfError(f"{section.name} is compressed with type {kind}, which this reader does "
                         f"not inflate (zlib is {ELFCOMPRESS_ZLIB})")
    out = zlib.decompress(raw[struct.calcsize(head):])
    if len(out) != size:
        raise DwarfError(f"{section.name} inflates to {len(out)} bytes, not the {size} it states")
    return out


def code_ranges(sections: Iterable[elf_facts.Section]) -> list[tuple[int, int]]:
    return [(s.addr, s.addr + s.size) for s in sections if s.flags & SHF_EXECINSTR and s.size]


def read_spans(lib: pathlib.Path) -> list[Span]:
    """The line spans of a library's code (`live_spans`), or a DwarfError saying why none."""
    data = lib.read_bytes()
    sections = elf_facts.sections(data)
    dwarf = {s.name: _section_data(data, s) for s in sections if s.name in DWARF_SECTIONS}
    if not dwarf.get(".debug_line"):
        raise DwarfError(f"{lib} has no .debug_line: its line tables were not written or were "
                         f"stripped, so no byte of it names its source")
    return live_spans(line_sequences(dwarf, data[5] == 1), code_ranges(sections))


# ── who wrote a source file ────────────────────────────────────────────────────────────────────

# A file of the standard library, as the toolchain's own build or the rust-src component names it,
# and one of a crate the standard library vendors.
_STD_SOURCE = re.compile(r"(?:^/rustc/[0-9a-f]+|/lib/rustlib/src/rust)/library/(.+)$")
_STD_VENDORED = re.compile(r"^/rust/deps/([A-Za-z0-9_.-]+?)-\d[^/]*/(.+)$")
_MANIFEST_TABLE = re.compile(r"^\s*(\[+)\s*([^\[\]]+?)\s*\]")
_MANIFEST_KEY = re.compile(r"""^\s*(name|path)\s*=\s*["']([^"']+)["']""")


def manifest_crate(text: str) -> tuple[str, str] | None:
    """The crate a Cargo manifest builds as a library, its name and its root file (relative to the
    manifest), or None for a manifest with no [package] (a workspace's)."""
    table: str | None = None
    package = lib_name = None
    lib_root = "src/lib.rs"
    for line in text.splitlines():
        head = _MANIFEST_TABLE.match(line)
        if head:
            # An array of tables (`[[bin]]`) is no table whose keys are read here.
            table = head.group(2) if len(head.group(1)) == 1 else None
            continue
        key = _MANIFEST_KEY.match(line)
        if key is None:
            continue
        if table == "package" and key.group(1) == "name":
            package = key.group(2)
        elif table == "lib" and key.group(1) == "name":
            lib_name = key.group(2)
        elif table == "lib" and key.group(1) == "path":
            lib_root = key.group(2)
    if package is None:
        return None
    return (lib_name or package).replace("-", "_"), lib_root


def module_of_file(rel: str, root_file: str) -> list[str] | None:
    """The module path of the source file `rel`, relative to the directory of the crate's root file
    `root_file`: the root file is the crate, `a/b.rs` and `a/b/mod.rs` are a::b; None for a file
    that is no module (not Rust)."""
    if rel == root_file:
        return []
    if not rel.endswith(".rs"):
        return None
    parts = rel[:-3].split("/")
    return parts[:-1] if parts[-1] == "mod" else parts


def std_owner(path: str) -> str | None:
    """The owner of a file of the standard library or of a crate it vendors, read from its path:
    `.../library/core/src/ptr/mod.rs` is core::ptr, and a crate in a directory of its own below
    `library/` (`stdarch/crates/core_arch/src/..`) is that directory's crate."""
    found = _STD_SOURCE.search(path)
    if found:
        segments = found.group(1).split("/")
        if "src" not in segments[1:]:
            return None
        at = segments.index("src", 1)
        crate, rel = segments[at - 1], "/".join(segments[at + 1:])
    else:
        found = _STD_VENDORED.match(path)
        if found is None or not found.group(2).startswith("src/"):
            return None
        crate, rel = found.group(1), found.group(2)[len("src/"):]
    modules = module_of_file(rel, "lib.rs")
    return None if modules is None else "::".join([crate.replace("-", "_"), *modules])


def mapped_path(path: str, prefixes: build_normalization.Prefixes) -> str:
    """`path` as the build writes it into a binary: under the last of the build's prefix maps
    whose prefix it starts with (build_normalization.py, "The rule")."""
    for src, dst in reversed(build_normalization.mappings(prefixes)):
        if path == src or path.startswith(src + "/"):
            return dst + path[len(src):]
    return path


class RustSources:
    """Who wrote a source file of the wz library, by its path: the crate whose source tree holds it,
    found by the nearest Cargo.toml above it under one of `roots` (a prefix a path can start with
    in the binary, and the directory of this host it stands for), and the module its path in that
    tree names. `checkout` holds `out/` and `crates/`."""

    def __init__(self, roots: Iterable[tuple[str, pathlib.Path]], checkout: pathlib.Path) -> None:
        self.roots = list(dict.fromkeys(roots))
        self.checkout = checkout
        self.manifests: dict[pathlib.Path, tuple[str, pathlib.Path, str] | None] = {}

    def hosts(self, path: str) -> Iterator[tuple[pathlib.Path, pathlib.Path]]:
        """Each file of this host `path` can stand for, with the root it is under."""
        for prefix, root in self.roots:
            if path.startswith(prefix.rstrip("/") + "/"):
                yield root / path[len(prefix.rstrip("/")) + 1:], root

    def manifest(self, directory: pathlib.Path) -> tuple[str, pathlib.Path, str] | None:
        """The crate the manifest in `directory` builds: its name, its source tree and the name of
        its root file; None when the directory has no manifest of a package."""
        if directory not in self.manifests:
            found = None
            file_ = directory / "Cargo.toml"
            if file_.is_file():
                crate = manifest_crate(file_.read_text(encoding="utf-8", errors="replace"))
                if crate is not None:
                    root_file = directory / crate[1]
                    found = (crate[0], root_file.parent, root_file.name)
            self.manifests[directory] = found
        return self.manifests[directory]

    def owner(self, path: str) -> str | None:
        """The module `path` is a file of, or None for a file outside every crate's source tree
        (code a crate includes) and one this host has no manifest above."""
        found = std_owner(path)
        if found is not None:
            return found
        for host, root in self.hosts(path):
            directory = host.parent
            while True:
                crate = self.manifest(directory)
                if crate is not None or directory == root or directory.parent == directory:
                    break
                directory = directory.parent
            if crate is None:
                continue
            name, tree, root_file = crate
            try:
                rel = host.relative_to(tree).as_posix()
            except ValueError:
                return None
            modules = module_of_file(rel, root_file)
            return None if modules is None else "::".join([name, *modules])
        return None

    def out_crate(self, path: str) -> str | None:
        """The crate whose directory under `out/` holds `path`: `out/<dir>` mirrors
        `crates/<dir>`."""
        for host, _ in self.hosts(path):
            try:
                rel = host.relative_to(self.checkout / OUT_TREE)
            except ValueError:
                continue
            if len(rel.parts) > 1:
                crate = self.manifest(self.checkout / "crates" / rel.parts[0])
                if crate is not None:
                    return crate[0]
        return None


def _common_prefix(paths: list[tuple[str, ...]]) -> tuple[str, ...]:
    if not paths:
        return ()
    common = paths[0]
    for path in paths[1:]:
        n = 0
        while n < min(len(common), len(path)) and common[n] == path[n]:
            n += 1
        common = common[:n]
    return common


def source_at(spans: list[Span], starts: list[int], address: int) -> str | None:
    """The source of the span that holds `address`, None when none does or it names none."""
    at = bisect.bisect_right(starts, address) - 1
    if at >= 0 and spans[at].start <= address < spans[at].end:
        return spans[at].source
    return None


def wz_source_owners(spans: list[Span], bodies: Iterable[Body],
                     reader: RustSources) -> dict[str, tuple[str | None, str | None]]:
    """Each source file of the wz library -> its owner and how the owner was read (module doc,
    "Who wrote a byte"): by its path; else by the module path the v0 names of the bodies that begin
    in it share (a body whose names are of several modules, an alias of merged functions, says
    nothing of its file); else by its directory under `out/`; else (None, None)."""
    out: dict[str, tuple[str | None, str | None]] = {}
    for path in sorted({span.source for span in spans if span.source is not None}):
        owner = reader.owner(path)
        out[path] = (owner, BY_PATH) if owner is not None else (None, None)
    starts = [span.start for span in spans]
    modules: dict[str, list[tuple[str, ...]]] = {}
    for body in bodies:
        own = source_at(spans, starts, body.address)
        if own is None or out[own][0] is not None:
            continue
        named = {tuple(owner.split("::")[:-1]) for symbol in body.names for owner in symbol.owners}
        if len(named) == 1:
            modules.setdefault(own, []).append(named.pop())
    for path, (owner, _) in out.items():
        if owner is not None:
            continue
        common = _common_prefix(modules.get(path, []))
        if common:
            out[path] = ("::".join(common), BY_FUNCTIONS)
        elif (crate := reader.out_crate(path)) is not None:
            out[path] = (crate, BY_OUT_TREE)
    return out


def pico_source_owners(spans: list[Span],
                       exports: Iterable[str]) -> dict[str, tuple[str | None, str | None]]:
    """Each source file of the zenoh-pico reference -> its path in the export (`exports`, the
    export's directory as the binary and as this host write it), or the C toolchain's."""
    roots = [e.rstrip("/") + "/" for e in exports]
    out: dict[str, tuple[str | None, str | None]] = {}
    for path in sorted({span.source for span in spans if span.source is not None}):
        rel = next((path[len(root):] for root in roots if path.startswith(root)), None)
        out[path] = (rel if rel is not None else f"{TOOLCHAIN_OWNER}/{path.lstrip('/')}", BY_PATH)
    return out


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
    # (bytes, names) of each body's bytes no line row gives a source, largest first.
    unattributed: list[tuple[int, tuple[str, ...]]] = field(default_factory=list)

    @property
    def unclassified_bytes(self) -> int:
        return sum(size for size, _ in self.unclassified)

    @property
    def unattributed_bytes(self) -> int:
        return sum(size for size, _ in self.unattributed)


@dataclass(frozen=True)
class Body:
    """The names of one address: one body, at its largest size, in `area` (None when no rule
    places it), shown by `lead`, the shortest of its names that are placed in that area."""
    address: int
    size: int
    names: tuple[Symbol, ...]
    area: str | None
    lead: Symbol


def place_bodies(symbols: Iterable[Symbol], rules: Rules,
                 areas: list[str]) -> tuple[list[Body], set[str]]:
    """Each address one body, in the area most of its names are placed in, a tie to the area
    listed first; and the rules that placed a name."""
    by_address: dict[int, list[Symbol]] = {}
    for symbol in symbols:
        by_address.setdefault(symbol.address, []).append(symbol)
    bodies: list[Body] = []
    used: set[str] = set()
    for address in sorted(by_address):
        names = tuple(sorted(by_address[address], key=lambda s: s.name))
        placed: list[str | None] = []
        votes: dict[str, int] = {}
        for symbol in names:
            area, rule = classify(rules, symbol)
            used.update(rule)
            placed.append(area)
            if area is not None:
                votes[area] = votes.get(area, 0) + 1
        winner = min(votes, key=lambda a: (-votes[a], areas.index(a))) if votes else None
        lead = min(zip(names, placed),
                   key=lambda pair: (pair[1] != winner, len(pair[0].name), pair[0].name))[0]
        bodies.append(Body(address, max(s.size for s in names), names, winner, lead))
    return bodies, used


def tally_bodies(bodies: Iterable[Body], used: set[str], areas: list[str]) -> Tally:
    result = Tally({area: 0 for area in areas}, used=set(used))
    for body in bodies:
        result.total += body.size
        if body.area is None:
            result.unclassified.append((body.size, tuple(sorted({s.name for s in body.names}))))
        else:
            result.by_area[body.area] += body.size
    result.unclassified.sort(key=lambda body: (-body[0], body[1]))
    return result


def tally(symbols: Iterable[Symbol], rules: Rules, areas: list[str]) -> Tally:
    """The bytes of each area, each address one body (`place_bodies`)."""
    bodies, used = place_bodies(symbols, rules, areas)
    return tally_bodies(bodies, used, areas)


@dataclass(frozen=True)
class Piece:
    """The bytes of one body from one source: `source` the file the line table names (None for
    bytes it names none for), `owner` who wrote that file, `area` where the rules place them
    (None when none does)."""
    body: Body
    size: int
    source: str | None
    owner: str | None
    area: str | None


def name_area(rules: Rules, body: Body, areas: list[str]) -> tuple[str | None, set[str]]:
    """The area the name rules give a body (the area most of its names are placed in, a tie to the
    area listed first), or None, and the rules that gave it."""
    votes: dict[str, int] = {}
    used: dict[str, set[str]] = {}
    for symbol in body.names:
        base = clone_base(symbol.name)
        for key, pattern, area in rules.names:
            if pattern.search(base):
                votes[area] = votes.get(area, 0) + 1
                used.setdefault(area, set()).add(f"names {key}")
                break
    if not votes:
        return None, set()
    winner = min(votes, key=lambda a: (-votes[a], areas.index(a)))
    return winner, used[winner]


def attribute(bodies: Iterable[Body], spans: list[Span],
              owners: Mapping[str, tuple[str | None, str | None]], rules: Rules,
              areas: list[str]) -> tuple[list[Piece], set[str]]:
    """Each body's bytes by the source the line table gives them (module doc, "Who wrote a byte"):
    a byte of the body's own file goes to the area a name rule gives the body when one does, every
    other byte to the owner rule of its file's owner; a byte of line 0 or of no row is
    unattributed. Returns the pieces and the rules that placed a byte."""
    starts = [span.start for span in spans]
    pieces: list[Piece] = []
    used: set[str] = set()
    for body in bodies:
        own = source_at(spans, starts, body.address)
        named, by_name = name_area(rules, body, areas)
        low, high = body.address, body.address + body.size
        sizes: dict[tuple[str | None, str | None, str | None], int] = {}
        covered = 0
        at = max(bisect.bisect_right(starts, low) - 1, 0)
        while at < len(spans) and spans[at].start < high:
            span = spans[at]
            at += 1
            count = min(span.end, high) - max(span.start, low)
            if count <= 0:
                continue
            covered += count
            if span.source is None:
                key: tuple[str | None, str | None, str | None] = (None, None, None)
            else:
                owner = owners.get(span.source, (None, None))[0]
                if named is not None and span.source == own:
                    used |= by_name
                    key = (span.source, owner, named)
                else:
                    prefix = owner_rule(rules, owner) if owner is not None else None
                    if prefix is not None:
                        used.add(f"owners {prefix}")
                    key = (span.source, owner, rules.owners[prefix] if prefix is not None else None)
            sizes[key] = sizes.get(key, 0) + count
        if covered < body.size:
            sizes[(None, None, None)] = sizes.get((None, None, None), 0) + body.size - covered
        pieces += [Piece(body, count, *key) for key, count in sizes.items()]
    return pieces, used


def piece_label(piece: Piece) -> str:
    """How a piece's source is named in a finding and in --explain: its owner, else its file."""
    if piece.source is None:
        return NO_LINE
    return piece.owner if piece.owner is not None else f"{NO_OWNER} {piece.source}"


def tally_pieces(pieces: Iterable[Piece], used: set[str], areas: list[str]) -> Tally:
    """The bytes of each area by line, the unplaced ones by the owner (or file) that holds them, and
    the unattributed ones by the body that holds them."""
    result = Tally({area: 0 for area in areas}, used=set(used))
    unplaced: dict[str, int] = {}
    unlined: dict[tuple[str, ...], int] = {}
    for piece in pieces:
        result.total += piece.size
        if piece.source is None:
            names = tuple(sorted({s.name for s in piece.body.names}))
            unlined[names] = unlined.get(names, 0) + piece.size
        elif piece.area is None:
            label = piece_label(piece)
            unplaced[label] = unplaced.get(label, 0) + piece.size
        else:
            result.by_area[piece.area] += piece.size
    result.unclassified = sorted(((size, (label,)) for label, size in unplaced.items()),
                                 key=lambda row: (-row[0], row[1]))
    result.unattributed = sorted(((size, names) for names, size in unlined.items()),
                                 key=lambda row: (-row[0], row[1]))
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
    if "unattributed_bytes_at_most" not in table:
        out.append(f"{where} has no unattributed_bytes_at_most (null until a run has read it)")
    else:
        limit = table["unattributed_bytes_at_most"]
        if limit is not None and (type(limit) is not int or limit < 0):
            out.append(f"{where}: unattributed_bytes_at_most is no byte count and not null")
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
    return [f"{side}: {tallied.unclassified_bytes} bytes of text from {len(tallied.unclassified)} "
            f"owner(s) that no rule of {LEDGER.relative_to(ROOT)} places, over the {limit} it "
            f"allows; give each an area by a rule, largest first: {shown}"]


def unattributed_findings(side: str, tallied: Tally, limit: int | None) -> list[str]:
    """The finding for unattributed bytes over the limit, or for a limit not yet filled."""
    where = LEDGER.relative_to(ROOT)
    if limit is None:
        return [f"{side}: unattributed_bytes_at_most of {where} is null: this run reads "
                f"{tallied.unattributed_bytes} bytes of text of no source line, and the limit is "
                f"set from a run of both sides"]
    if tallied.unattributed_bytes <= limit:
        return []
    shown = "; ".join(f"{size} B {' = '.join(names)}"
                      for size, names in tallied.unattributed[:UNCLASSIFIED_NAMED])
    return [f"{side}: {tallied.unattributed_bytes} bytes of text in {len(tallied.unattributed)} "
            f"bodies have no source line (line 0, or no row of the line table), over the {limit} "
            f"{where} allows, so the areas no longer hold the code they are read from; the bodies "
            f"that hold most: {shown}"]


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
    limit = table["unattributed_bytes_at_most"]
    lines.append(f"  size-ledger:   unattributed (no source line): {wz.unattributed_bytes} "
                 f"bytes of wz, {pico.unattributed_bytes} of zenoh-pico, "
                 f"{'no limit yet' if limit is None else f'at most {limit} each'}")
    return lines


# ── what holds an area's bytes: --explain ──────────────────────────────────────────────────────

# The disambiguator `c++filt` prints after a crate name, and the hash a legacy name ends with.
_CRATE_HASH = re.compile(r"(?<=[A-Za-z0-9_])\[[0-9a-f]{1,16}\]")
_LEGACY_HASH = re.compile(r"::h[0-9a-f]{16}$")


def clean_demangled(text: str) -> str:
    """A demangled name without the hashes that differ between builds of the same code."""
    return _LEGACY_HASH.sub("", _CRATE_HASH.sub("", text))


def demangle_names(names: Iterable[str],
                   tool: str = DEMANGLER) -> tuple[dict[str, str], list[str]]:
    """Each name -> its demangled text (`clean_demangled`), and a note when the tool could not be
    read, in which case every name stands for itself."""
    unique = sorted(set(names))
    if not unique:
        return {}, []
    try:
        lines = subprocess.run([tool], input="\n".join(unique) + "\n", capture_output=True,
                               text=True, check=True).stdout.splitlines()
    except (OSError, subprocess.CalledProcessError) as e:
        return {n: n for n in unique}, [f"{tool} could not demangle ({e}), so names are shown "
                                        f"mangled"]
    if len(lines) != len(unique):
        return {n: n for n in unique}, [f"{tool} gave {len(lines)} lines for {len(unique)} names, "
                                        f"so names are shown mangled"]
    return {name: clean_demangled(text) for name, text in zip(unique, lines)}, []


def generic_key(name: str) -> str:
    """A demangled name with every generic argument list removed (`drop_glue::<T>` and `Rc<T>`
    become `drop_glue` and `Rc`), so the copies of one generic function share it. The brackets of
    a qualified path (`<T as Trait>::f`, `<T>::f`) open after no name and are kept; an `->` inside
    a removed list closes nothing."""
    out: list[str] = []
    depth = 0
    i = 0
    while i < len(name):
        c = name[i]
        if depth:
            if name.startswith("->", i):
                i += 2
                continue
            if c == "<":
                depth += 1
            elif c == ">":
                depth -= 1
            i += 1
            continue
        prev = out[-1] if out else ""
        if c == "<" and prev and (prev.isalnum() or prev in "_:"):
            while out and out[-1] == ":":
                out.pop()
            depth = 1
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _ranked(groups: Mapping[str, Mapping[int, int]], key: str) -> list[dict]:
    """Each group's bytes, its bodies and its largest body's bytes in it, largest first; `groups`
    maps a key to the bytes each body (by address) has in it."""
    rows = [{key: k, "bytes": sum(sizes.values()), "bodies": len(sizes),
             "largest": max(sizes.values())} for k, sizes in groups.items()]
    return sorted(rows, key=lambda row: (-row["bytes"], row[key]))


def explain_area(side: str, pieces: Iterable[Piece], demangled: Mapping[str, str],
                 by_symbol: int | None) -> dict:
    """What holds one side's bytes of one area: its owners (a wz module, a zenoh-pico file), its
    bodies by their bytes here, and on the wz side its source files and its generic functions with
    more than one copy; each list whole, largest first. `by_symbol` is what the symbol reading
    gives the area."""
    owners: dict[str, dict[int, int]] = {}
    files: dict[str, dict[int, int]] = {}
    generics: dict[str, dict[int, int]] = {}
    held: dict[int, tuple[Body, dict[str, int]]] = {}
    total = 0
    for piece in pieces:
        total += piece.size
        body = piece.body
        label = piece_label(piece)
        name = demangled.get(body.lead.name, body.lead.name)
        for groups, key in ((owners, label), (files, piece.source or NO_LINE),
                            (generics, generic_key(name))):
            sizes = groups.setdefault(key, {})
            sizes[body.address] = sizes.get(body.address, 0) + piece.size
        by_owner = held.setdefault(body.address, (body, {}))[1]
        by_owner[label] = by_owner.get(label, 0) + piece.size
    symbols = [{"bytes": sum(by_owner.values()), "aliases": len(body.names) - 1,
                "owner": " + ".join(sorted(by_owner, key=lambda k: (-by_owner[k], k))),
                "name": demangled.get(body.lead.name, body.lead.name)}
               for body, by_owner in held.values()]
    symbols.sort(key=lambda row: (-row["bytes"], row["name"]))
    out = {"bytes": total, "by_symbol": by_symbol, "bodies": len(symbols),
           "owners": _ranked(owners, "owner"), "symbols": symbols}
    if side == "wz":
        out["files"] = _ranked(files, "file")
        out["generics"] = [row for row in _ranked(generics, "function") if row["bodies"] > 1]
    return out


def piece_area(piece: Piece) -> str:
    """The area --explain lists a piece under: its own, or the unclassified or the unattributed."""
    if piece.source is None:
        return UNATTRIBUTED_AREA
    return piece.area if piece.area is not None else UNCLASSIFIED_AREA


def symbol_bytes(tallied: Tally, area: str) -> int | None:
    """What the symbol reading gives an area (none for the unattributed, which it has not)."""
    if area == UNCLASSIFIED_AREA:
        return tallied.unclassified_bytes
    if area == UNATTRIBUTED_AREA:
        return None
    return tallied.by_area.get(area)


def explain_report(case_id: str, pin: str, toolchain: str, date: str, areas: list[str],
                   pieces: Mapping[str, list[Piece]], demangled: Mapping[str, str],
                   by_symbol: Mapping[str, Tally],
                   sources: Mapping[str, Mapping[str, tuple[str | None, str | None]]]) -> dict:
    """Each area's explanation on both sides, then the unclassified and the unattributed bytes'
    when there are any, and every source file of each side with its owner, how the owner was read
    and its bytes."""
    report: dict = {"schema": EXPLAIN_SCHEMA, "case": case_id, "pin": pin, "toolchain": toolchain,
                    "date": date, "areas": {}, "sources": {}}
    listed = list(areas) + [extra for extra in (UNCLASSIFIED_AREA, UNATTRIBUTED_AREA)
                            if any(piece_area(p) == extra for side in SIDES for p in pieces[side])]
    for area in listed:
        report["areas"][area] = {
            side: explain_area(side, [p for p in pieces[side] if piece_area(p) == area], demangled,
                               symbol_bytes(by_symbol[side], area))
            for side in SIDES}
    for side in SIDES:
        held: dict[str, int] = {}
        for piece in pieces[side]:
            if piece.source is not None:
                held[piece.source] = held.get(piece.source, 0) + piece.size
        report["sources"][side] = sorted(
            ({"file": path, "owner": owner, "how": how, "bytes": held.get(path, 0)}
             for path, (owner, how) in sources[side].items()),
            key=lambda row: (-row["bytes"], row["file"]))
    return report


def previous_bytes(previous: object, area: str, side: str) -> int | None:
    """An area's bytes on one side in the report a run replaced, or None when it has none."""
    try:
        value = previous["areas"][area][side]["bytes"]
    except (KeyError, TypeError):
        return None
    return value if type(value) is int else None


def fit(text: str, width: int = EXPLAIN_NAME_WIDTH) -> str:
    return text if len(text) <= width else text[:width - 3] + "..."


def explain_table(title: str, rows: list[dict], shown: int, columns: tuple[str, ...],
                  text: Callable[[dict], str]) -> list[str]:
    if not rows:
        return [f"    {title}: none"]
    out = [f"    {title}, the largest {min(shown, len(rows))} of {len(rows)}:",
           "      " + " ".join(f"{c:>8}" for c in columns)]
    for row in rows[:shown]:
        out.append("      " + " ".join(f"{row[c]:>8}" for c in columns) + f"  {fit(text(row))}")
    return out


def explain_lines(report: dict, previous: object) -> list[str]:
    """The head of each list of `report`, each area's bytes against `previous`'s when it has
    them."""
    lines: list[str] = []
    for area, sides in report["areas"].items():
        said = []
        for side, label in (("wz", "wz"), ("pico", "zenoh-pico")):
            now = sides[side]
            before = previous_bytes(previous, area, side)
            delta = "" if before is None else f" ({now['bytes'] - before:+d} since the previous)"
            by_symbol = now.get("by_symbol")
            symbol = ("" if by_symbol is None
                      else f", {by_symbol} B by symbol ({now['bytes'] - by_symbol:+d})")
            said.append(f"{label} {now['bytes']} B in {now['bodies']} bodies{symbol}{delta}")
        lines.append(f"  size-ledger explain: {area}: {', '.join(said)}")
        wz, pico = sides["wz"], sides["pico"]
        lines += explain_table("wz modules", wz["owners"], EXPLAIN_OWNERS,
                               ("bytes", "bodies"), lambda row: row["owner"])
        lines += explain_table("wz source files", wz["files"], EXPLAIN_OWNERS,
                               ("bytes", "bodies"), lambda row: row["file"])
        lines += explain_table("wz bodies (bytes in this area; aliases: the other names of its "
                               "address)",
                               wz["symbols"], EXPLAIN_SYMBOLS, ("bytes", "aliases"),
                               lambda row: f"{row['name']}  [{row['owner']}]")
        lines += explain_table("wz generic functions with more than one copy",
                               wz["generics"], EXPLAIN_GENERICS, ("bytes", "bodies", "largest"),
                               lambda row: row["function"])
        lines += explain_table("zenoh-pico files", pico["owners"], EXPLAIN_FILES,
                               ("bytes", "bodies"), lambda row: row["owner"])
    return lines


def explain_path(case_id: str) -> pathlib.Path:
    return cost.TARGET / EXPLAIN_DIR / f"explain-{case_id}.json"


def write_explain(report: dict, path: pathlib.Path) -> object:
    """Write `report` to `path`, moving the report it replaces to `.previous.json` beside it,
    and return that report (None when there was none or it does not read)."""
    previous = None
    if path.is_file():
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            previous = None
        path.replace(path.with_suffix(".previous.json"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    return previous


# ── reading the case ───────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CaseRead:
    # The symbols of each side's build, whose file without debug information the cost gate
    # measured.
    wz: list[Symbol]
    pico: list[Symbol]
    unread: list[str]
    pin: str
    toolchain: str
    # The line spans of each side's build (`read_spans`).
    spans: Mapping[str, list[Span]]
    # The directory of the zenoh-pico export as the build's line tables and as this host write it.
    pico_export: tuple[str, ...]


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
              prefixes: build_normalization.Prefixes) -> tuple[CaseRead | None, list[str]]:
    """Build the case and its zenoh-pico reference as Layer C1cs does (both are the cost gate's
    builds, so a run after it builds nothing again) and read the symbols and the line spans of
    each build, whose file without debug information is the one the cost gate measured; or say
    why a figure read from them would be none."""
    got = cost.build(case, env, prefixes)
    asked = wz_config.pico_reference(wz_config.load_decl(), cost.case_features(case))
    link, cflags = cost.reference_build(got.link_args)
    ref = cost.pico_reference_build(asked, env, prefixes, link, cflags)
    work, _, _ = cost.pico_reference_tree(asked, env, link, cflags)
    wz_lib = cost.case_build(case, env).lib
    reference = f"{case.id} (its zenoh-pico reference)"
    findings = (cost.purity_findings(case.id, got.leaked) + cost.link_findings(case.id, got)
                + cost.purity_findings(reference, ref.leaked) + cost.link_findings(reference, ref))
    built = object_symbols(work / PICO_TARGET_OBJECTS)
    if not built:
        findings.append(f"{reference}: no object file under {work / PICO_TARGET_OBJECTS}, so no "
                        f"zenoh-pico symbol has a source")
    spans: dict[str, list[Span]] = {}
    for side, subject, lib in (("wz", case.id, wz_lib), ("pico", reference, work / PICO_LIBRARY)):
        try:
            spans[side] = read_spans(lib)
        except (DwarfError, elf_facts.ElfError) as e:
            findings.append(f"{subject}: the line tables of {lib} could not be read: {e}")
    if findings:
        return None, findings
    compiled = {rel for files in built.values() for rel in files if rel.endswith(".c")}
    definitions = pico_definitions(work / "src", compiled)
    wz, unread = wz_symbols(nm_text(wz_lib))
    pico = pico_symbols(nm_text(work / PICO_LIBRARY), definitions, built)
    export = str(work / "src")
    return CaseRead(wz, pico, unread, ref.pin, ref.toolchain, spans,
                    (mapped_path(export, prefixes), export)), []


def rust_roots(prefixes: build_normalization.Prefixes) -> list[tuple[str, pathlib.Path]]:
    """The roots a wz source path can be under: each mapped prefix as the binary writes it and as
    it is on this host."""
    roots: list[tuple[str, pathlib.Path]] = []
    for src, dst in build_normalization.mappings(prefixes):
        roots += [(dst, pathlib.Path(src)), (src, pathlib.Path(src))]
    return roots


def shard_case_ids(shards: int, shard: int) -> list[str]:
    weights = census_shard_plan.read_weights(cost.CASE_WEIGHTS.read_text(encoding="utf-8"))
    notes: list[str] = []
    ids = cost.shard_cases(shards, shard, weights, notes)
    for note in notes:
        print(f"  size-ledger: {note}", file=sys.stderr)
    return ids


def cmd_run(mode: str, shard: tuple[int, int] | None) -> int:
    """`mode` is check, measure or explain; only check grades the rows."""
    measure_only = mode != "check"
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
        cost.strip_tool()
    except (ValueError, RuntimeError) as e:
        print(f"  size-ledger: {e}", file=sys.stderr)
        return 2
    try:
        read, refused = read_case(case, env, prefixes)
    except (subprocess.CalledProcessError, OSError, RuntimeError, elf_facts.ElfError,
            wz_config.PresetError) as e:
        print(f"  size-ledger FAIL: {case.id}: the case or its reference could not be read: {e}",
              file=sys.stderr)
        return 1
    for finding in refused:
        print(f"  size-ledger FAIL: {finding}", file=sys.stderr)
    if read is None:
        return 1
    areas = area_ids(table)
    rules = {side: side_rules(table, side) for side in SIDES}
    placed = {"wz": place_bodies(read.wz, rules["wz"], areas),
              "pico": place_bodies(read.pico, rules["pico"], areas)}
    by_symbol = {side: tally_bodies(*placed[side], areas) for side in SIDES}
    sources = {"wz": wz_source_owners(read.spans["wz"], placed["wz"][0],
                                      RustSources(rust_roots(prefixes), ROOT)),
               "pico": pico_source_owners(read.spans["pico"], read.pico_export)}
    pieces = {side: attribute(placed[side][0], read.spans[side], sources[side], rules[side], areas)
              for side in SIDES}
    wz = tally_pieces(*pieces["wz"], areas)
    pico = tally_pieces(*pieces["pico"], areas)
    print(f"  size-ledger: {case.id}: function bytes by area, each byte by the source its line "
          f"table names, against zenoh-pico {read.pin} as the same build ({read.toolchain}; both "
          f"linked by {linker})")
    for line in table_lines(table, wz, pico):
        print(line)
    notes: list[str] = []
    if read.unread:
        notes.append(f"{len(read.unread)} wz symbol(s) begin _R and do not read as v0, so no "
                     f"owner places them in the symbol reading: "
                     f"{', '.join(read.unread[:UNCLASSIFIED_NAMED])}")
    for side, tallied in (("wz", wz), ("pico", pico)):
        idle = unused_rules(table, side, tallied.used)
        if idle:
            notes.append(f"the {side} rules that placed no byte of this case: {', '.join(idle)}")
    read_by = {how: sum(1 for _, found in sources["wz"].values() if found == how)
               for how in (BY_PATH, BY_FUNCTIONS, BY_OUT_TREE, None)}
    notes.append(f"the owners of the wz source files: {read_by[BY_PATH]} read from their path, "
                 f"{read_by[BY_FUNCTIONS]} from the functions that begin in them, "
                 f"{read_by[BY_OUT_TREE]} from their directory under {OUT_TREE}/, "
                 f"{read_by[None]} not read")
    limit = table["unclassified_bytes_at_most"]
    unlined = table["unattributed_bytes_at_most"]
    findings = (unclassified_findings("wz", wz, limit)
                + unclassified_findings("zenoh-pico", pico, limit)
                + unattributed_findings("wz", wz, unlined)
                + unattributed_findings("zenoh-pico", pico, unlined))
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
              f"zenoh-pico, unclassified text within {limit} bytes and text of no source line "
              f"within {unlined} bytes on each side")
    if mode == "explain":
        rc = max(rc, explain_case(case.id, read, areas, {s: p for s, (p, _) in pieces.items()},
                                  by_symbol, sources, today))
    return rc


def explain_case(case_id: str, read: CaseRead, areas: list[str],
                 pieces: Mapping[str, list[Piece]], by_symbol: Mapping[str, Tally],
                 sources: Mapping[str, Mapping[str, tuple[str | None, str | None]]],
                 date: str) -> int:
    """Print what holds each area's bytes and keep the whole report as JSON (`--explain`)."""
    demangled, notes = demangle_names(p.body.lead.name for p in pieces["wz"])
    for note in notes:
        print(f"  size-ledger: note: {note}")
    report = explain_report(case_id, read.pin, read.toolchain, date, areas, pieces, demangled,
                            by_symbol, sources)
    path = explain_path(case_id)
    try:
        previous = write_explain(report, path)
    except OSError as e:
        print(f"  size-ledger FAIL: the explanation could not be kept at {path}: {e}",
              file=sys.stderr)
        return 1
    for line in explain_lines(report, previous):
        print(line)
    kept = (f", the one it replaced at {path.with_suffix('.previous.json')}"
            if previous is not None else "")
    print(f"  size-ledger: every row of these lists is at {path}{kept}")
    return 0


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

    def _raises(call: Callable[[], object]) -> bool:
        try:
            call()
        except DwarfError:
            return True
        return False

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
        expect("an unattributed limit is a byte count or null, and is stated",
               any("unattributed_bytes_at_most is no byte count" in f
                   for f in broken(lambda t: t.update({"unattributed_bytes_at_most": -1})))
               and any("has no unattributed_bytes_at_most" in f
                       for f in broken(lambda t: t.pop("unattributed_bytes_at_most")))
               and not any("unattributed" in f
                           for f in broken(lambda t: t.update({"unattributed_bytes_at_most": 0})))
               and not any("unattributed" in f for f in broken(
                   lambda t: t.update({"unattributed_bytes_at_most": None}))))
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
               and placed("wz", "_R", "core_arch::x86::sse2") == "language"
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
               and placed("pico", "memcpy", "toolchain/usr/include/x86_64-linux-gnu/bits/"
                          "string_fortified.h") == "language"
               and placed("pico", "_z_arc_slice_elem_clear", "src/api/api.c",
                          "src/net/sample.c") == "language")

    # --explain: the names, the groups and the report.
    expect("a demangled name loses its crate disambiguators and its legacy hash, and keeps a slice",
           clean_demangled("wz_session_core[30a105b5be83598f]::handshake_encode::encode")
           == "wz_session_core::handshake_encode::encode"
           and clean_demangled("core::ptr::drop_in_place::h0123456789abcdef")
           == "core::ptr::drop_in_place"
           and clean_demangled("<[f32]>::len") == "<[f32]>::len")
    expect("every generic argument list is removed and a qualified path's brackets are kept",
           generic_key("core::ptr::drop_glue::<wz_runtime_posix::stream::StreamReader>")
           == "core::ptr::drop_glue"
           and generic_key("<alloc::rc::Rc<wz::IpDriver<A, B>> as wz::Link>::keeps_input")
           == "<alloc::rc::Rc as wz::Link>::keeps_input"
           and generic_key("<alloc::vec::Vec<_, _>>::remove::assert_failed")
           == "<alloc::vec::Vec>::remove::assert_failed"
           and generic_key("<x::each<x::drive::{closure#0}>::{closure#0} as core::ops::function::"
                           "FnOnce<()>>::call_once::{shim:vtable#0}")
           == "<x::each::{closure#0} as core::ops::function::FnOnce>::call_once::{shim:vtable#0}"
           and generic_key("core::ptr::drop_in_place<x::Y>") == "core::ptr::drop_in_place"
           and generic_key("f::<fn(u8) -> u16>::g") == "f::g"
           and generic_key("z_open") == "z_open")
    expect("a demangler that cannot run leaves every name mangled and says so",
           demangle_names(["_Rb", "_Ra", "_Rb"], tool="/nonexistent/wz-no-demangler")[0]
           == {"_Ra": "_Ra", "_Rb": "_Rb"}
           and len(demangle_names(["_Ra"], tool="/nonexistent/wz-no-demangler")[1]) == 1
           and demangle_names([]) == ({}, []))
    shown, shown_used = place_bodies(
        [Symbol(0x10, 4, "z_open", ()), Symbol(0x10, 4, "z_x", ()),
         Symbol(0x10, 4, "_R9", ("a::b",)), Symbol(0x20, 2, "memmove", ()),
         Symbol(0x20, 2, "mm", ())], rules, ["door", "lang", "x", "y"])
    expect("a body is shown by the shortest of its names placed in its area, with its aliases",
           [(b.address, b.area, b.lead.name, len(b.names)) for b in shown]
           == [(0x10, "door", "z_x", 3), (0x20, None, "mm", 2)]
           and shown_used == {"names ^z_", "owners a::b"})
    # The line tables: DWARF 4 and 5 line programs, the units that name their directories.
    def uleb(value: int) -> bytes:
        out = bytearray()
        while True:
            byte, value = value & 0x7F, value >> 7
            out.append(byte | (0x80 if value else 0))
            if not value:
                return bytes(out)

    def sleb(value: int) -> bytes:
        out = bytearray()
        while True:
            byte, value = value & 0x7F, value >> 7
            done = (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40)
            out.append(byte | (0 if done else 0x80))
            if done:
                return bytes(out)

    # The standard opcodes' operand counts, line base -5, line range 14, opcode base 13.
    shape = bytes([1, 1, 1, 0xFB, 14, 13, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1])

    def special(address: int, line: int) -> bytes:
        return bytes([(line + 5) + 14 * address + 13])

    def at(address: int) -> bytes:
        return b"\x00" + uleb(9) + b"\x02" + struct.pack("<Q", address)

    end_sequence = b"\x00\x01\x01"
    v4_head = (shape + b"src\x00/abs/inc\x00\x00"
               + b"lib.rs\x00" + uleb(1) + b"\x00\x00" + b"x.h\x00" + uleb(2) + b"\x00\x00"
               + b"../../out/wz-x/gen.rs\x00" + uleb(1) + b"\x00\x00" + b"\x00")
    v4_program = (at(0x1000) + b"\x04\x02" + b"\x03" + sleb(9) + b"\x01" + special(4, 1)
                  + b"\x04\x01\x03" + sleb(-11) + b"\x02\x04\x01"
                  + b"\x03\x05\x02\x08\x01" + b"\x04\x03" + special(4, 2)
                  + b"\x02\x0c" + end_sequence
                  + at(0) + b"\x01\x02" + uleb(0x2000) + end_sequence)
    v4_body = struct.pack("<HI", 4, len(v4_head)) + v4_head + v4_program
    v4_table = struct.pack("<I", len(v4_body)) + v4_body
    line_str = b"/pico/build\x00/wz/p/src/src\x00"
    v5_head = (shape
               + b"\x01" + uleb(1) + uleb(0x1F) + uleb(2) + struct.pack("<II", 0, 12)
               + b"\x02" + uleb(1) + uleb(0x08) + uleb(2) + uleb(0x0B) + uleb(2)
               + b"api.c\x00\x01" + b"/usr/include/bits/string_fortified.h\x00\x00")
    v5_program = (at(0x3000) + b"\x01" + b"\x04\x00" + special(2, 1) + b"\x02\x06"
                  + end_sequence)
    v5_body = b"\x05\x00\x08\x00" + struct.pack("<I", len(v5_head)) + v5_head + v5_program
    v5_table = struct.pack("<I", len(v5_body)) + v5_body
    abbrev = (uleb(1) + uleb(0x11) + b"\x00" + uleb(0x10) + uleb(0x17) + uleb(0x1B) + uleb(0x08)
              + b"\x00\x00" + uleb(2) + uleb(0x11) + b"\x00" + uleb(0x1B) + uleb(0x1F)
              + uleb(0x10) + uleb(0x17) + b"\x00\x00" + b"\x00")
    unit4 = (struct.pack("<HIB", 4, 0, 8) + uleb(1) + struct.pack("<I", 0)
             + b"/wz/crates/wz-x\x00")
    unit5 = (struct.pack("<HBBI", 5, 1, 8, 0) + uleb(2) + struct.pack("<II", 0, len(v4_table)))
    info = (struct.pack("<I", len(unit4)) + unit4 + struct.pack("<I", len(unit5)) + unit5)
    dwarf = {".debug_line": v4_table + v5_table, ".debug_info": info, ".debug_abbrev": abbrev,
             ".debug_line_str": line_str}
    expect("each unit names its line table's directory, by an inline string or by .debug_line_str",
           unit_directories(dwarf, True) == {0: "/wz/crates/wz-x", len(v4_table): "/pico/build"})
    sequences = line_sequences(dwarf, True)
    expect("a DWARF 4 program reads to rows: a file from its directory, the unit's directory under "
           "a relative one, line 0 to no source, .. resolved",
           [(r.address, r.source, r.line) for r in sequences[0][0]]
           == [(0x1000, "/abs/inc/x.h", 10), (0x1004, "/abs/inc/x.h", 11), (0x1008, None, 0),
               (0x1010, "/wz/crates/wz-x/src/lib.rs", 5),
               (0x1014, "/wz/crates/out/wz-x/gen.rs", 7)]
           and sequences[0][1] == 0x1020
           and [(r.address, r.line) for r in sequences[1][0]] == [(0, 1)]
           and sequences[1][1] == 0x2000)
    expect("a DWARF 5 program numbers its files from 0, the second its first row's by default",
           [(r.address, r.source, r.line) for r in sequences[2][0]]
           == [(0x3000, "/usr/include/bits/string_fortified.h", 1),
               (0x3002, "/wz/p/src/src/api.c", 2)]
           and sequences[2][1] == 0x3008 and len(sequences) == 3)
    spans = live_spans(sequences, [(0x1000, 0x1100), (0x3000, 0x3100)])
    expect("each row runs to the next; a sequence outside the code (a discarded function) is none",
           [(s.start, s.end, s.source) for s in spans]
           == [(0x1000, 0x1004, "/abs/inc/x.h"), (0x1004, 0x1008, "/abs/inc/x.h"),
               (0x1008, 0x1010, None), (0x1010, 0x1014, "/wz/crates/wz-x/src/lib.rs"),
               (0x1014, 0x1020, "/wz/crates/out/wz-x/gen.rs"),
               (0x3000, 0x3002, "/usr/include/bits/string_fortified.h"),
               (0x3002, 0x3008, "/wz/p/src/src/api.c")])
    expect("where two sequences overlap, the bytes are the one's that starts first",
           [(s.start, s.end, s.source) for s in live_spans(
               [([LineRow(0x10, "a", 1)], 0x20), ([LineRow(0x18, "b", 1)], 0x28)], [(0, 0x100)])]
           == [(0x10, 0x20, "a"), (0x20, 0x28, "b")])
    expect("a line table of an unknown version is refused",
           _raises(lambda: line_sequences({".debug_line": struct.pack("<IH", 2, 9)}, True)))
    plain_text = b"line tables"
    packed = (struct.pack("<IIQQ", ELFCOMPRESS_ZLIB, 0, len(plain_text), 1)
              + zlib.compress(plain_text))
    ident = b"\x7fELF\x02\x01" + b"\x00" * 10
    zstd = struct.pack("<IIQQ", 2, 0, 4, 1) + b"xxxx"
    expect("a compressed section is inflated, and one compressed otherwise than zlib refused",
           _section_data(ident + packed, elf_facts.Section(".debug_line", 1, 16, len(packed), 0,
                                                           SHF_COMPRESSED)) == plain_text
           and _raises(lambda: _section_data(ident + zstd, elf_facts.Section(
               ".debug_line", 1, 16, len(zstd), 0, SHF_COMPRESSED))))
    expect("the code is the executable sections, where they are loaded",
           code_ranges([elf_facts.Section(".text", 1, 0, 0x40, 0, SHF_EXECINSTR | 2, 0x1000),
                        elf_facts.Section(".rodata", 1, 0, 0x40, 0, 2, 0x2000),
                        elf_facts.Section(".init", 1, 0, 0, 0, SHF_EXECINSTR | 2, 0x900)])
           == [(0x1000, 0x1040)])

    # Who wrote a source file.
    expect("a manifest names its library's crate and root file, an array of tables none",
           manifest_crate('[package]\nname = "wz-x"\n[lib]\npath = "src/root.rs"\n'
                          '[[bin]]\nname = "other"\npath = "src/main.rs"\n')
           == ("wz_x", "src/root.rs")
           and manifest_crate('[package]\nname = "a-b"\n[lib]\nname = "c_d"\n')
           == ("c_d", "src/lib.rs")
           and manifest_crate('[workspace]\nmembers = ["x"]\n') is None)
    expect("a file's module is its path, mod.rs its directory, the root file the crate",
           module_of_file("a/b.rs", "lib.rs") == ["a", "b"]
           and module_of_file("a/b/mod.rs", "lib.rs") == ["a", "b"]
           and module_of_file("lib.rs", "lib.rs") == [] and module_of_file("x.c", "lib.rs") is None)
    expect("a standard library file is its crate's module, a crate below library/ its own",
           std_owner("/rustc/2d8144b7/library/core/src/ptr/mod.rs") == "core::ptr"
           and std_owner("/rustc/2d8144b7/library/alloc/src/lib.rs") == "alloc"
           and std_owner("/rustc/2d8144b7/library/stdarch/crates/core_arch/src/x86/sse2.rs")
           == "core_arch::x86::sse2"
           and std_owner("/x/lib/rustlib/src/rust/library/core/src/option.rs") == "core::option"
           and std_owner("/rust/deps/compiler_builtins-0.1.160/src/mem/mod.rs")
           == "compiler_builtins::mem"
           and std_owner("/wz/crates/wz-x/src/lib.rs") is None)
    split = build_normalization.Prefixes("/h/w", "/h/w/art", "/h/c")
    expect("a path is mapped as the build maps it, the longer prefix first",
           mapped_path("/h/w/src/a", split) == "/wz/src/a"
           and mapped_path("/h/w/art/b", split) == "/wz/b"
           and mapped_path("/h/c/registry/x", split) == "/cargo/registry/x"
           and mapped_path("/elsewhere/y", split) == "/elsewhere/y")
    with tempfile.TemporaryDirectory() as tmp:
        tree, home = pathlib.Path(tmp) / "tree", pathlib.Path(tmp) / "cargo"
        for manifest, text in (
                (tree / "crates" / "Cargo.toml", '[workspace]\nmembers = []\n'),
                (tree / "crates" / "wz-x" / "Cargo.toml", '[package]\nname = "wz-x"\n'),
                (home / "registry" / "src" / "i" / "hashbrown-0.15.2" / "Cargo.toml",
                 '[package]\nname = "hashbrown"\n')):
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text(text, encoding="utf-8")
        reader = RustSources([("/wz", tree), ("/cargo", home), (str(tree), tree)], tree)
        expect("a source file is the module of the crate whose manifest is above it",
               reader.owner("/wz/crates/wz-x/src/a/b.rs") == "wz_x::a::b"
               and reader.owner("/wz/crates/wz-x/src/lib.rs") == "wz_x"
               and reader.owner(f"{tree}/crates/wz-x/src/k.rs") == "wz_x::k"
               and reader.owner("/cargo/registry/src/i/hashbrown-0.15.2/src/raw/mod.rs")
               == "hashbrown::raw")
        expect("a file outside every source tree has no owner by its path, and out/ names a crate",
               reader.owner("/wz/out/wz-x/gen.rs") is None
               and reader.owner("/wz/crates/wz-x/tests/t.rs") is None
               and reader.owner("/elsewhere/z.rs") is None
               and reader.out_crate("/wz/out/wz-x/gen.rs") == "wz_x"
               and reader.out_crate("/wz/out/gone/gen.rs") is None)
        found_bodies, _ = place_bodies(
            [Symbol(0x10, 8, "_Ra", ("wz_x::inc::gen::f",)),
             Symbol(0x20, 8, "_Rb", ("wz_x::inc::g",)),
             Symbol(0x30, 8, "_Rc", ("wz_x::a::f",)), Symbol(0x30, 8, "_Rd", ("wz_y::b::f",))],
            Rules((), {}, "::"), ["x"])
        owned = wz_source_owners(
            [Span(0x10, 0x18, "/wz/out/wz-x/gen.rs"), Span(0x20, 0x28, "/wz/out/wz-x/gen.rs"),
             Span(0x28, 0x30, "/wz/out/wz-x/other.rs"), Span(0x30, 0x38, "/wz/out/gone/two.rs"),
             Span(0x38, 0x40, "/wz/crates/wz-x/src/a.rs"), Span(0x40, 0x48, None)],
            found_bodies, reader)
        expect("an included file is the module its functions share; one with none, its out/ "
               "directory's crate; an alias body of two modules says nothing",
               owned == {"/wz/out/wz-x/gen.rs": ("wz_x::inc", BY_FUNCTIONS),
                         "/wz/out/wz-x/other.rs": ("wz_x", BY_OUT_TREE),
                         "/wz/out/gone/two.rs": (None, None),
                         "/wz/crates/wz-x/src/a.rs": ("wz_x::a", BY_PATH)})
    expect("a zenoh-pico file is its path in the export, a file outside it the toolchain's",
           pico_source_owners([Span(0, 1, "/wz/p/src/src/api/api.c"),
                               Span(1, 2, "/usr/include/bits/x.h"), Span(2, 3, None)],
                              ("/wz/p/src", "/h/p/src"))
           == {"/wz/p/src/src/api/api.c": ("src/api/api.c", BY_PATH),
               "/usr/include/bits/x.h": ("toolchain/usr/include/bits/x.h", BY_PATH)})

    # Each byte by its source: an inlined helper goes to its own area.
    lrules = Rules(names=(("^z_", re.compile("^z_"), "door"),),
                   owners={"wz_x": "x", "wz_x::k": "k", "wz_d": "door"}, separator="::")
    lareas = ["door", "x", "k"]
    lbodies, _ = place_bodies(
        [Symbol(0x100, 0x40, "z_open", ()), Symbol(0x200, 0x20, "_Ra", ("wz_x::m::f",)),
         Symbol(0x300, 0x10, "_Rb", ("wz_x::g::h",)), Symbol(0x300, 0x10, "_Rc", ("wz_x::g::i",))],
        lrules, lareas)
    lspans = [Span(0x100, 0x110, "/s/doors.rs"), Span(0x110, 0x120, "/s/k.rs"),
              Span(0x120, 0x128, None), Span(0x128, 0x130, "/s/unknown.rs"),
              Span(0x200, 0x220, "/s/m.rs"), Span(0x300, 0x310, "/s/gen.rs")]
    lsources = {"/s/doors.rs": ("wz_x::doors", BY_PATH), "/s/k.rs": ("wz_x::k", BY_PATH),
                "/s/unknown.rs": (None, None), "/s/m.rs": ("wz_x::m", BY_PATH),
                "/s/gen.rs": ("wz_x::g", BY_FUNCTIONS)}
    lpieces, lused = attribute(lbodies, lspans, lsources, lrules, lareas)
    lines_read = tally_pieces(lpieces, lused, lareas)
    by_name = tally(sum((list(b.names) for b in lbodies), []), lrules, lareas)
    expect("an inlined helper's bytes go to its source's area, not to the door it was inlined into",
           lines_read.by_area == {"door": 0x10, "x": 0x20 + 0x10, "k": 0x10}
           and by_name.by_area == {"door": 0x40, "x": 0x30, "k": 0})
    expect("a name rule places the body's own file, even where the owner rule names another area",
           any(p.source == "/s/doors.rs" and p.area == "door" and p.owner == "wz_x::doors"
               for p in lpieces)
           and lused == {"names ^z_", "owners wz_x::k", "owners wz_x"})
    expect("line 0 and bytes no row covers are unattributed, by the body that holds them",
           lines_read.unattributed == [(8 + 0x10, ("z_open",))]
           and lines_read.unattributed_bytes == 0x18)
    expect("a file with no owner is unclassified, named by its file",
           lines_read.unclassified == [(8, (f"{NO_OWNER} /s/unknown.rs",))])
    expect("every byte of every body is counted once, the same total as by symbol",
           lines_read.total == by_name.total == 0x40 + 0x20 + 0x10
           and sum(lines_read.by_area.values()) + lines_read.unclassified_bytes
           + lines_read.unattributed_bytes == lines_read.total)
    expect("unattributed bytes at the limit pass, over it fail naming the bodies, and no limit is "
           "a finding with the reading",
           unattributed_findings("wz", lines_read, 0x18) == []
           and len(over := unattributed_findings("wz", lines_read, 0x17)) == 1
           and "z_open" in over[0]
           and len(unset := unattributed_findings("wz", lines_read, None)) == 1
           and "null" in unset[0] and "24 bytes" in unset[0])

    # --explain: the names, the groups and the report.
    xrules = Rules((), {"wz_x": "x"}, "::")
    xbodies, _ = place_bodies(
        [Symbol(0x10, 40, "_Ra", ("wz_x::m::glue",)), Symbol(0x40, 24, "_Rb", ("wz_x::m::glue",)),
         Symbol(0x60, 100, "_Rc", ("wz_x::n::big",)), Symbol(0x60, 100, "_Rd", ("wz_x::n::big2",)),
         Symbol(0x100, 8, "z_open", ())],
        xrules, ["x"])
    xsources = {"/s/m.rs": ("wz_x::m", BY_PATH), "/s/n.rs": ("wz_x::n", BY_PATH),
                "/s/z.c": (None, None)}
    xpieces, _ = attribute(
        xbodies, [Span(0x10, 0x38, "/s/m.rs"), Span(0x40, 0x58, "/s/m.rs"),
                  Span(0x60, 0x90, "/s/n.rs"), Span(0x90, 0xC4, "/s/m.rs"),
                  Span(0x100, 0x104, "/s/z.c")], xsources, xrules, ["x"])
    xnames = {"_Ra": "wz_x::m::glue::<wz_x::A>", "_Rb": "wz_x::m::glue::<wz_x::B>",
              "_Rc": "wz_x::n::big", "_Rd": "wz_x::n::big2"}
    xwz = explain_area("wz", [p for p in xpieces if piece_area(p) == "x"], xnames, 164)
    expect("the wz owners are modules, largest first, with the bodies that hold their bytes",
           xwz["bytes"] == 164 and xwz["by_symbol"] == 164 and xwz["bodies"] == 3
           and [(o["owner"], o["bytes"], o["bodies"], o["largest"]) for o in xwz["owners"]]
           == [("wz_x::m", 116, 3, 52), ("wz_x::n", 48, 1, 48)]
           and [(f["file"], f["bytes"]) for f in xwz["files"]]
           == [("/s/m.rs", 116), ("/s/n.rs", 48)])
    expect("a wz body is listed by its bytes in the area, with its aliases and its owners",
           [(s["bytes"], s["aliases"], s["owner"], s["name"]) for s in xwz["symbols"]]
           == [(100, 1, "wz_x::m + wz_x::n", "wz_x::n::big"),
               (40, 0, "wz_x::m", "wz_x::m::glue::<wz_x::A>"),
               (24, 0, "wz_x::m", "wz_x::m::glue::<wz_x::B>")])
    expect("the copies of one generic function are one row, and a single copy is none",
           xwz["generics"] == [{"function": "wz_x::m::glue", "bytes": 64, "bodies": 2,
                                "largest": 40}])
    expect("bytes with no owner and bytes with no line are named so",
           explain_area("wz", [p for p in xpieces if piece_area(p) == UNCLASSIFIED_AREA], xnames,
                        None)["owners"][0]["owner"] == f"{NO_OWNER} /s/z.c"
           and explain_area("wz", [p for p in xpieces if piece_area(p) == UNATTRIBUTED_AREA],
                            xnames, None)["owners"][0]["owner"] == NO_LINE)
    prules = Rules((), {"src": "x"}, "/")
    psymbols = [Symbol(0x10, 30, "_z_a", ("src/a.c",)), Symbol(0x30, 12, "_z_b", ("src/b.c",))]
    psources = {"/p/src/a.c": ("src/a.c", BY_PATH), "/p/src/b.c": ("src/b.c", BY_PATH)}
    ppieces, _ = attribute(place_bodies(psymbols, prules, ["x"])[0],
                           [Span(0x10, 0x2E, "/p/src/a.c"), Span(0x30, 0x3C, "/p/src/b.c")],
                           psources, prules, ["x"])
    xpico = explain_area("pico", ppieces, {}, 42)
    expect("the zenoh-pico owners are files, with no file or generic list beside them",
           [(o["owner"], o["bytes"]) for o in xpico["owners"]] == [("src/a.c", 30), ("src/b.c", 12)]
           and "generics" not in xpico and "files" not in xpico)
    xreport = explain_report(
        "c", "p", "cc 1", "2026-11-25", ["x"], {"wz": xpieces, "pico": ppieces}, xnames,
        {"wz": tally(sum((list(b.names) for b in xbodies), []), xrules, ["x"]),
         "pico": tally(psymbols, prules, ["x"])},
        {"wz": xsources, "pico": psources})
    expect("the report explains every area, the unclassified and the unattributed bytes, and every "
           "source with its owner",
           list(xreport["areas"]) == ["x", UNCLASSIFIED_AREA, UNATTRIBUTED_AREA]
           and xreport["areas"][UNCLASSIFIED_AREA]["wz"]["bytes"] == 4
           and xreport["areas"][UNCLASSIFIED_AREA]["wz"]["by_symbol"] == 8
           and xreport["areas"][UNATTRIBUTED_AREA]["wz"]["by_symbol"] is None
           and xreport["areas"][UNATTRIBUTED_AREA]["pico"]["bytes"] == 0
           and xreport["sources"]["wz"][0] == {"file": "/s/m.rs", "owner": "wz_x::m",
                                                "how": BY_PATH, "bytes": 116}
           and xreport["sources"]["wz"][-1] == {"file": "/s/z.c", "owner": None, "how": None,
                                                 "bytes": 4}
           and json.loads(json.dumps(xreport)) == xreport
           and list(explain_report("c", "p", "cc 1", "d", ["x"], {"wz": [], "pico": ppieces},
                                   xnames, {"wz": Tally({"x": 0}), "pico": Tally({"x": 42})},
                                   {"wz": {}, "pico": psources})["areas"]) == ["x"])
    xlines = explain_lines(xreport, {"areas": {"x": {"wz": {"bytes": 200}}}})
    expect("an area's bytes are read beside the symbol reading's and against the previous report's",
           "  size-ledger explain: x: wz 164 B in 3 bodies, 164 B by symbol (+0) (-36 since the "
           "previous), zenoh-pico 42 B in 2 bodies, 42 B by symbol (+0)" in xlines
           and "  size-ledger explain: (unattributed): wz 4 B in 1 bodies, zenoh-pico 0 B in 0 "
               "bodies" in xlines
           and not any("since the previous" in line for line in explain_lines(xreport, None))
           and previous_bytes({"areas": {"x": {"wz": {"bytes": "200"}}}}, "x", "wz") is None)
    expect("a table prints the head of its list and says how long the list is",
           explain_table("t", [{"bytes": 3, "k": "a"}, {"bytes": 2, "k": "b"},
                               {"bytes": 1, "k": "c"}], 2, ("bytes",), lambda r: r["k"])
           == ["    t, the largest 2 of 3:", "         bytes", "             3  a",
               "             2  b"]
           and explain_table("t", [], 2, ("bytes",), lambda r: r["k"]) == ["    t: none"]
           and fit("x" * 200) == "x" * (EXPLAIN_NAME_WIDTH - 3) + "...")
    with tempfile.TemporaryDirectory() as tmp:
        kept_at = pathlib.Path(tmp) / "explain-c.json"
        first = write_explain({"n": 1}, kept_at)
        second = write_explain({"n": 2}, kept_at)
        expect("a report replaces the one before it and keeps it beside it for a diff",
               first is None and second == {"n": 1}
               and json.loads(kept_at.read_text(encoding="utf-8")) == {"n": 2}
               and json.loads(kept_at.with_suffix(".previous.json").read_text(encoding="utf-8"))
               == {"n": 1})

    print(f"  size-ledger selftest: {ok}/{ok + bad} arm(s) pass")
    return 0 if bad == 0 else 1


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in ("--check", "--measure", "--explain", "--selftest") or (
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
    return cmd_run(mode=argv[1][2:], shard=shard)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
