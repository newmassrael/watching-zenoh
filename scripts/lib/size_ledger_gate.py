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

And one feature bundle does not say what the others cost. The ratio of a whole library grows with
its features (by the ceiling's rows, the release client read 0.94 times zenoh-pico on 2026-11-25 and
the cooperative peer 1.26 on 2026-11-26), so a ledger of the smallest client alone holds nothing of
what a feature adds. Each case of the ledger is a feature bundle, every area of each is held, and
`--per-feature` says what each feature adds to each area on both sides.

## What is read, and where it comes from

Each case of capability_cost_gate.py the ledger names (`cases`): the client in its release form,
the cooperative peer, and `pico-api-coop-nostd`, the Linux twin of the Windows release's
like-for-like library, whose features that gate reads from the profile the Windows lane builds the
library from. The cases are defined there and only named here. Each with its zenoh-pico reference,
built by that gate's own functions (`build`, `pico_reference_build`, `pico_reference_tree`) in
its environment (`build_env`): the same commands, the same target directory and the same
reference directory, so in Layer C1cs, after the cost gate built a case, neither is built a second
time. A library that holds a build path, that another linker wrote, or
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

Inlined LANGUAGE RUNTIME code is the exception (owner's ruling, 2026-11-25), by one rule on both
sides. A byte whose line names a file of the runtime of the language it is written in goes to the
file of the innermost call in its inline chain written outside the runtime: the caller. Rust's
runtime is core, alloc, std and the crates they vendor (`/rustc/<hash>/library/..`); C's is the
toolchain's headers (`/usr/include`, a sysroot's or a cross C library's `include`, the
compiler's own `lib/gcc/../include`), where the C library's and libgcc's inline functions are
written. What `ptr::write`, `Option::map` or a slice index inlines into a wz function is that
function's code, as a fortified `memcpy` inlined into a zenoh-pico function is that function's.
Only a runtime function's own body, a function left out of line, keeps its file, and is language
support. A runtime macro expanded in a caller is not in the chain, but the toolchain collapses an
external macro's lines to its call site, so its bytes are the caller's line already.

The chain is the byte's FRAMES, read from `.debug_info`: the function whose code holds it
(DW_TAG_subprogram) and each call inlined into it (DW_TAG_inlined_subroutine), each by its
addresses (DW_AT_low_pc and DW_AT_high_pc, or DW_AT_ranges), an inlined call with the file of the
call (DW_AT_call_file) and each frame with the file its function is declared in (DW_AT_decl_file,
through DW_AT_abstract_origin and DW_AT_specification, in the line table of the unit that states
it, which under LTO can be another unit). The frames of a function the linker discarded are left
out, as its rows are. The walk goes from the innermost inlined call outwards and ends at the
function's own file; a call whose file the table does not name ends it, and the byte keeps its
file. GCC at `-g1` writes the functions and not their inline trees, so a zenoh-pico byte of a
toolchain header goes to the file of the function that holds it.

A byte the line table names no source for, a row of line 0 or a byte no row covers, is the code
of the innermost frame that holds it: the file its function is declared in, the compiler's own code
in a function (drop glue, a closure's shim, a piece of a panic path) being that function's. When
that function is the language runtime's, or no entry declares its file, the byte goes to its
caller by the same walk, and a runtime function's own body keeps the runtime's file. A byte no
frame gives a file (rustc's line tables only write no DW_AT_decl_file on a function) is its body's:
it goes to the area the body's symbols are placed in (the symbol reading below: its names' name
rules, else their owners' rules), else it is unclassified under the owner its names carry, so the
rule that owner lacks is what places it. Only a byte of a body whose names carry no owner and
which no name rule places (a C symbol of an object built without debug information, the C
runtime's start files) is UNATTRIBUTED: counted apart, in no area, and either library's
unattributed bytes over `unattributed_bytes_at_most` fail, naming the bodies that hold most. LLVM
gives line 0 to more code than GCC does, so reading it by its frame, then by its symbol, is what
keeps that difference out of the comparison, and the limit is what keeps the rest from taking
bytes out of wz's areas unseen. `--explain` says per area how many bytes of inlined runtime code,
how many bytes of no source line by their frame and how many by their body's symbols it counts.

The line tables are read from the build's bytes, DWARF 2 to 5, with `.debug_info` giving each
unit's compilation directory, which a relative path is read from. A sequence that starts outside
the library's executable sections is the table of a function the linker discarded (GNU ld writes
its address as 0) and is left out.

wz: the owner of a file is a crate::module path, as an owner rule names it. A file in a crate's
source tree (the directory of its library's root, found by the `Cargo.toml` above it under the
checkout or the cargo home the build normalization maps) is the module its path names: `a/b.rs`
and `a/b/mod.rs` are `crate::a::b`. The standard library's files
(`/rustc/<hash>/library/<crate>/src/..`) and those of the crates it vendors are read the same way
from their paths. A file outside every source tree is code a crate includes (the SCE output under
`out/`): it is the module its own functions are named in, the longest module path the v0 names of
the bodies that begin in it share, and one none of whose functions is a body of its own is the
crate whose directory under `out/` holds it (`out/<dir>` mirrors `crates/<dir>`).

wz's third-party collections are language support as zenoh-pico's are: `heapless` (the bounded
vector and string the no-heap build holds its tables in) is the counterpart of zenoh-pico's
`src/collections`, which its rules place in language, as they place `alloc` and `hashbrown`.

zenoh-pico: the owner of a file is its path in the export of the submodule the reference was built
from (`src/..`, `include/..`). A file outside the export is the C toolchain's,
`toolchain/<its path>`: the compiler's and the C library's headers, whose inline functions are
their callers' where they are inlined (above) and language support where they are left out of line.

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

Each area of each case has a row, with the rule of a row of the pico ceiling (pico_host_ceiling.py,
the one implementation): locked at WIN, or `ratio_at_most`, the ratio of the reading it was set
from rounded up to four places, under the open-debt item it is registered under. A reading over its
row by more than the tolerance fails; one under it by more prints the tighter row to commit; an
area that reads WIN fails until its row is locked, and a locked area reads WIN or fails. A row
whose ratio is null is unfilled and fails with the row this run reads, and a case is added with
every row unfilled: its rows are set from `--measure`'s output, never written by hand. An area
that reads no byte on one side has no ratio and fails: its rules give that side none of its code.
The areas and the rules are the ledger's, one set for every case, so an area means one thing in
every bundle.

## One feature at a time

`--per-feature` steps from the ledger's `base_case` to each other case (or to the cases it names):
for each feature the case names, in its order, that the features before it do not already turn on,
it builds the base case's build (its profile and configuration files) with the features before it
and this one, and zenoh-pico with the switches those features answer (`pico_reference`, the same
derivation as every reference), and reads both by area as `--measure` does. Each step's
additions are printed by area on each side, with wz's addition over zenoh-pico's, then the
features by that excess, most first: a feature that costs wz more than it costs zenoh-pico is
named, and so is the area it costs it in. A feature zenoh-pico has no switch of adds nothing to
zenoh-pico, and says so. A step adds what the features before it make it cost, so the chain's
order is the case's; a build that turns on the same features as a step of another chain is read
once. It grades nothing, and the whole report goes to `size-ledger/per-feature-CASE.json` under the
cost gate's target directory.

## What holds an area's bytes

`--explain` reads the same cases as `--measure` (the same builds, so after a measure it builds
nothing again) and says, for each area, what holds its bytes, and how many bytes the symbol reading
gives it, and how many bytes of inlined language runtime code it counts by their caller's file and
how many bytes of no source line by their frame's: on the wz side the owner modules and the source
files by bytes, the bodies by their bytes in the area with the name each is shown by and how many
other names its address carries, and the generic functions with more than one copy (a demangled
name with every generic argument list removed is one function); on the zenoh-pico side the source
files by bytes. Each owner (a wz module, a zenoh-pico file) also names the bodies that hold its
bytes, by its bytes in each: the largest few in the JSON with the sum of the rest, the largest
three in the tables, so code inlined into another owner's function is found by that function's
name. The unclassified and the unattributed bytes are explained as two areas of their own. The
tables print the head of each list; the whole lists go to `size-ledger/explain-<case>.json`
under the cost gate's target directory, with every source file of each side, its owner and how the
owner was read, and the report it replaces is kept beside it as `explain-<case>.previous.json`, so
two measurements diff.
Names are demangled by `c++filt` (binutils, beside the `nm` this gate reads with), and shown
mangled when it cannot.

## Where it runs

Layer C1cs, as the leg after the cost gate, whose builds it reads; it builds nothing of its own.
With `--shards N --shard K` a case is read only on the shard the cost gate deals it to, and every
shard checks the ledger itself, which needs no build. `--per-feature` builds a library and a
reference for each step, so it is run by hand on one host and in no layer. Layer C0 runs
`--selftest`, which holds the readers, the rules and the ratchet on synthetic input and the
committed ledger to its own rules.

Usage:
    size_ledger_gate.py --check [--shards N --shard K] [ID...]
                               read each case (or the named ones), grade every area against its row
    size_ledger_gate.py --measure [--shards N --shard K] [ID...]
                               read the same and print each table and the rows to commit
    size_ledger_gate.py --explain [--shards N --shard K] [ID...]
                               --measure, then what holds each area's bytes, kept as JSON
    size_ledger_gate.py --per-feature [ID...]
                               step from the base case to each case, one feature at a time
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
from dataclasses import dataclass, field, replace

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
LEDGER_SCHEMA = 3
TABLE_KEYS = frozenset(("about", "schema", "cases", "base_case", "unclassified_bytes_at_most",
                        "unattributed_bytes_at_most", "areas", "rules"))
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
# --per-feature: the report it keeps under the target directory, beside --explain's.
PER_FEATURE_SCHEMA = 1
# --explain: how many rows each of its tables prints (the JSON keeps every row), the width a name
# is cut to there, the tool that demangles, and where the report goes under the target directory.
EXPLAIN_OWNERS = 30
EXPLAIN_SYMBOLS = 40
EXPLAIN_GENERICS = 30
EXPLAIN_FILES = 20
EXPLAIN_NAME_WIDTH = 140
# --explain: how many of an owner's bodies its row in the JSON names, largest first (the rest are
# summed so the row still adds up to the owner's bytes), and how many of them the tables print.
EXPLAIN_OWNER_SYMBOLS = 20
EXPLAIN_OWNER_SYMBOLS_SHOWN = 3
EXPLAIN_SCHEMA = 5
DEMANGLER = "c++filt"
EXPLAIN_DIR = "size-ledger"
UNCLASSIFIED_AREA = "(unclassified)"
UNATTRIBUTED_AREA = "(unattributed)"
# How --explain names the bytes of a body no line row gives a source, and a source with no owner.
NO_LINE = "(no source line)"
# How --explain names bytes of no source line its body's symbols place and no owner of theirs names.
BY_SYMBOL = "(no source line, placed by its symbol)"
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
# The sections the line reader reads: the tables, the units that name their directories and hold
# the functions and their inline trees, the strings either can point into, and the address and
# range tables a frame's addresses are read from.
DWARF_SECTIONS = (".debug_line", ".debug_info", ".debug_abbrev", ".debug_str", ".debug_line_str",
                  ".debug_str_offsets", ".debug_addr", ".debug_ranges", ".debug_rnglists")
DW_TAG_INLINED_SUBROUTINE = 0x1D
DW_TAG_COMPILE_UNIT = 0x11
DW_TAG_SUBPROGRAM = 0x2E
DW_TAG_PARTIAL_UNIT = 0x3C
DW_UT_COMPILE = 1
DW_UT_PARTIAL = 3
DW_AT_STMT_LIST = 0x10
DW_AT_LOW_PC = 0x11
DW_AT_HIGH_PC = 0x12
DW_AT_COMP_DIR = 0x1B
DW_AT_RANGES = 0x55
DW_AT_CALL_FILE = 0x58
DW_AT_DECL_FILE = 0x3A
DW_AT_ABSTRACT_ORIGIN = 0x31
DW_AT_SPECIFICATION = 0x47
DW_AT_STR_OFFSETS_BASE = 0x72
DW_AT_ADDR_BASE = 0x73
DW_AT_RNGLISTS_BASE = 0x74
# The attributes the frame reader keeps of an entry: where its code is, the file of its call, the
# file its function is declared in and the entries that state what it does not.
_FRAME_ATTRIBUTES = frozenset((DW_AT_STMT_LIST, DW_AT_LOW_PC, DW_AT_HIGH_PC, DW_AT_RANGES,
                               DW_AT_CALL_FILE, DW_AT_ADDR_BASE, DW_AT_RNGLISTS_BASE,
                               DW_AT_DECL_FILE, DW_AT_ABSTRACT_ORIGIN, DW_AT_SPECIFICATION))
DW_FORM_ADDR = 0x01
DW_FORM_REF_ADDR = 0x10
# ref1, ref2, ref4, ref8 and ref_udata: an offset from the start of the entry's own unit.
_UNIT_REF_FORMS = frozenset((0x11, 0x12, 0x13, 0x14, 0x15))
DW_FORM_RNGLISTX = 0x23
# addrx, addrx1 to addrx4: an index into the unit's table of .debug_addr.
_ADDRX_FORMS = frozenset((0x1B, 0x29, 0x2A, 0x2B, 0x2C))
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


Abbreviation = tuple[int, bool, list[tuple[int, int, int]]]


def _abbreviations(data: bytes, offset: int) -> dict[int, Abbreviation]:
    """The abbreviation table at `offset` of `.debug_abbrev`: each code -> its tag, whether its
    entry has children, and its (attribute, form, implicit constant) list."""
    cur = _Cursor(data, True, offset)
    table: dict[int, Abbreviation] = {}
    while (code := cur.uleb()) != 0:
        tag = cur.uleb()
        children = cur.u(1) != 0
        attributes: list[tuple[int, int, int]] = []
        while True:
            name, form = cur.uleb(), cur.uleb()
            implicit = cur.sleb() if form == 0x21 else 0
            if name == 0 and form == 0:
                break
            attributes.append((name, form, implicit))
        table[code] = (tag, children, attributes)
    return table


@dataclass(frozen=True)
class _Unit:
    """The header of one unit of `.debug_info`: where it starts and ends, the size of its offsets,
    its version, its kind (DW_UT_*; a unit of DWARF 2 to 4 is a compile unit), the size of its
    addresses, its abbreviation table's offset in `.debug_abbrev` and where its first entry is."""
    at: int
    end: int
    offsets: int
    version: int
    kind: int
    address: int
    abbrev: int
    entries: int


def _units(info: bytes, little: bool) -> Iterator[_Unit]:
    """Each unit of `.debug_info`, in order."""
    at = 0
    while at < len(info):
        cur = _Cursor(info, little, at)
        end, offsets = cur.unit()
        version = cur.u(2)
        kind = DW_UT_COMPILE
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
        yield _Unit(at, end, offsets, version, kind, address, table_at, cur.pos)
        at = end


def _unit_cursor(info: bytes, little: bool, unit: _Unit) -> _Cursor:
    """A cursor at the unit's first entry, which no read takes past the unit."""
    cur = _Cursor(info, little, unit.entries)
    cur.end = unit.end
    return cur


def _shape(tables: dict[int, dict[int, Abbreviation]], abbrev: bytes, unit: _Unit,
           code: int) -> Abbreviation:
    """The abbreviation `code` of the unit's table, read once per table."""
    if unit.abbrev not in tables:
        tables[unit.abbrev] = _abbreviations(abbrev, unit.abbrev)
    if code not in tables[unit.abbrev]:
        raise DwarfError(f"the unit at {unit.at:#x} of .debug_info uses the abbreviation {code}, "
                         f"which its table does not have")
    return tables[unit.abbrev][code]


def unit_directories(sections: Mapping[str, bytes], little: bool) -> dict[int, str]:
    """Each line table's offset in `.debug_line` -> the compilation directory of the unit of
    `.debug_info` that names it (DW_AT_stmt_list, DW_AT_comp_dir), read from each unit's first
    entry."""
    info = sections.get(".debug_info", b"")
    abbrev = sections.get(".debug_abbrev", b"")
    tables: dict[int, dict[int, Abbreviation]] = {}
    out: dict[int, str] = {}
    for unit in _units(info, little):
        cur = _unit_cursor(info, little, unit)
        code = cur.uleb()
        if code:
            values = {name: _form_value(cur, form, unit.offsets, unit.address, sections, implicit)
                      for name, form, implicit in _shape(tables, abbrev, unit, code)[2]}
            directory = values.get(DW_AT_COMP_DIR)
            if isinstance(directory, tuple):
                base = values.get(DW_AT_STR_OFFSETS_BASE)
                directory = (_strx(sections, base, directory[1], unit.offsets, little)
                             if isinstance(base, int) else None)
            stmt = values.get(DW_AT_STMT_LIST)
            if isinstance(stmt, int) and isinstance(directory, str):
                out[stmt] = directory
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


LineSequence = tuple[list[LineRow], int]
FileNames = Callable[[int], "str | None"]


def _no_file(index: int) -> str | None:
    """The file names of a line table with no files."""
    return None


def line_table(data: bytes, at: int, little: bool, base: str | None,
               sections: Mapping[str, bytes]) -> tuple[list[LineSequence], int, FileNames]:
    """The sequences of the line table at `at` of `.debug_line`, each its rows and the address it
    ends at, the offset of the next table, and the table's file names: a file index (a row's, or
    an inlined call's DW_AT_call_file) -> its path, None for an index the table has no file for.
    `base` is the unit's compilation directory."""
    cur = _Cursor(data, little, at)
    end, offsets = cur.unit()
    if end == cur.pos:
        return [], end, _no_file
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
    return sequences, end, source


def _entries(cur: _Cursor, offsets: int, address: int,
             sections: Mapping[str, bytes]) -> list[dict[int, object]]:
    """A DWARF 5 directory or file name table: its entry format, then its entries."""
    formats = [(cur.uleb(), cur.uleb()) for _ in range(cur.u(1))]
    return [{content: _form_value(cur, form, offsets, address, sections)
             for content, form in formats} for _ in range(cur.uleb())]


def line_tables(sections: Mapping[str, bytes],
                little: bool) -> dict[int, tuple[list[LineSequence], FileNames]]:
    """Each line table of `.debug_line` by its offset (a unit's DW_AT_stmt_list): its sequences and
    its file names (`line_table`)."""
    data = sections.get(".debug_line", b"")
    directories = unit_directories(sections, little)
    out: dict[int, tuple[list[LineSequence], FileNames]] = {}
    at = 0
    while at < len(data):
        found, end, names = line_table(data, at, little, directories.get(at), sections)
        out[at] = (found, names)
        at = end
    return out


def line_sequences(sections: Mapping[str, bytes], little: bool) -> list[LineSequence]:
    """Every sequence of every line table of `.debug_line`."""
    return [sequence for found, _ in line_tables(sections, little).values() for sequence in found]


@dataclass(frozen=True)
class Span:
    """Code bytes [start, end) of one row: the source the row names, None when it names none.
    `inlined` is the language runtime file the row names for bytes `to_frames` gave to the
    file of the call that inlined them, which is then `source`; None for bytes it left alone.
    `framed` says the row names no source for these bytes (line 0, or no row) and `source` is
    the file of the frame that holds them (`frame_file`)."""
    start: int
    end: int
    source: str | None
    inlined: str | None = None
    framed: bool = False


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


# ── the frames: functions and their inline trees ───────────────────────────────────────────────


@dataclass(frozen=True)
class Frame:
    """Code bytes [start, end) of one frame: a function's own code (depth 0, DW_TAG_subprogram) or
    a call inlined into it (DW_TAG_inlined_subroutine, depth 1 for a call inlined into the function
    itself). `call` is the file of an inlined call in its caller (DW_AT_call_file; None when the
    unit's line table has no such file, and for depth 0); `origin` the file the frame's function
    is declared in (DW_AT_decl_file, through DW_AT_abstract_origin and DW_AT_specification when the
    entry states none; None when no entry of the chain does)."""
    start: int
    end: int
    depth: int
    call: str | None
    origin: str | None = None


def _number(entry: tuple[int, object], unit: _Unit) -> int:
    if not isinstance(entry[1], int):
        raise DwarfError(f"an attribute of form {entry[0]:#x} in the unit at {unit.at:#x} is no "
                         f"number")
    return entry[1]


class _Places:
    """Where the entries of one unit are: DW_AT_low_pc with DW_AT_high_pc, or DW_AT_ranges, read
    against the unit's base address (its own DW_AT_low_pc) and its tables in `.debug_addr`
    (DW_AT_addr_base) and `.debug_rnglists` (DW_AT_rnglists_base) for DWARF 5, or
    `.debug_ranges` for DWARF 2 to 4."""

    def __init__(self, sections: Mapping[str, bytes], little: bool, unit: _Unit,
                 values: Mapping[int, tuple[int, object]]) -> None:
        self.sections = sections
        self.little = little
        self.unit = unit
        self.addr_base = (_number(values[DW_AT_ADDR_BASE], unit)
                          if DW_AT_ADDR_BASE in values else None)
        self.rnglists_base = (_number(values[DW_AT_RNGLISTS_BASE], unit)
                              if DW_AT_RNGLISTS_BASE in values else None)
        low = values.get(DW_AT_LOW_PC)
        self.base = self.address(low) if low is not None else 0

    def indexed(self, index: int) -> int:
        """The address at `index` of the unit's table in `.debug_addr`."""
        if self.addr_base is None:
            raise DwarfError(f"the unit at {self.unit.at:#x} indexes .debug_addr and names no "
                             f"DW_AT_addr_base")
        size = self.unit.address
        return _Cursor(self.sections.get(".debug_addr", b""), self.little,
                       self.addr_base + index * size).u(size)

    def address(self, entry: tuple[int, object]) -> int:
        value = _number(entry, self.unit)
        return self.indexed(value) if entry[0] in _ADDRX_FORMS else value

    def ranges(self, values: Mapping[int, tuple[int, object]]) -> list[tuple[int, int]]:
        """The address ranges of an entry; none for an entry that states none."""
        low, high = values.get(DW_AT_LOW_PC), values.get(DW_AT_HIGH_PC)
        if low is not None and high is not None:
            start = self.address(low)
            if high[0] == DW_FORM_ADDR or high[0] in _ADDRX_FORMS:
                return [(start, self.address(high))]
            return [(start, start + _number(high, self.unit))]
        listed = values.get(DW_AT_RANGES)
        if listed is None:
            return []
        offset = _number(listed, self.unit)
        if listed[0] == DW_FORM_RNGLISTX:
            if self.rnglists_base is None:
                raise DwarfError(f"the unit at {self.unit.at:#x} indexes .debug_rnglists and "
                                 f"names no DW_AT_rnglists_base")
            at = _Cursor(self.sections.get(".debug_rnglists", b""), self.little,
                         self.rnglists_base + offset * self.unit.offsets)
            offset = self.rnglists_base + at.u(self.unit.offsets)
        if self.unit.version >= 5:
            return self.range_list(offset)
        return self.range_pairs(offset)

    def range_list(self, offset: int) -> list[tuple[int, int]]:
        """A range list of `.debug_rnglists` (DWARF 5, section 7.25)."""
        cur = _Cursor(self.sections.get(".debug_rnglists", b""), self.little, offset)
        size = self.unit.address
        base = self.base
        out: list[tuple[int, int]] = []
        while (kind := cur.u(1)) != 0:  # DW_RLE_end_of_list
            if kind == 1:  # base_addressx
                base = self.indexed(cur.uleb())
            elif kind == 2:  # startx_endx
                start = self.indexed(cur.uleb())
                out.append((start, self.indexed(cur.uleb())))
            elif kind == 3:  # startx_length
                start = self.indexed(cur.uleb())
                out.append((start, start + cur.uleb()))
            elif kind == 4:  # offset_pair
                start = base + cur.uleb()
                out.append((start, base + cur.uleb()))
            elif kind == 5:  # base_address
                base = cur.u(size)
            elif kind == 6:  # start_end
                start = cur.u(size)
                out.append((start, cur.u(size)))
            elif kind == 7:  # start_length
                start = cur.u(size)
                out.append((start, start + cur.uleb()))
            else:
                raise DwarfError(f"the range list at {offset:#x} of .debug_rnglists has the "
                                 f"unknown entry kind {kind:#x}")
        return out

    def range_pairs(self, offset: int) -> list[tuple[int, int]]:
        """A range list of `.debug_ranges` (DWARF 2 to 4): pairs of addresses from the base, a
        pair whose first is the largest address selecting a new base, two zeros ending it."""
        cur = _Cursor(self.sections.get(".debug_ranges", b""), self.little, offset)
        size = self.unit.address
        top = (1 << (8 * size)) - 1
        base = self.base
        out: list[tuple[int, int]] = []
        while True:
            start, end = cur.u(size), cur.u(size)
            if start == 0 and end == 0:
                return out
            if start == top:
                base = end
            else:
                out.append((base + start, base + end))


def _references(values: Mapping[int, tuple[int, object]], unit: _Unit) -> tuple[int, ...]:
    """The offsets in `.debug_info` of the entries an entry's DW_AT_abstract_origin and
    DW_AT_specification name, in that order; a reference of another form (a type signature, a
    supplementary file) names none read here."""
    out: list[int] = []
    for name in (DW_AT_ABSTRACT_ORIGIN, DW_AT_SPECIFICATION):
        entry = values.get(name)
        if entry is None:
            continue
        if entry[0] in _UNIT_REF_FORMS:
            out.append(unit.at + _number(entry, unit))
        elif entry[0] == DW_FORM_REF_ADDR:
            out.append(_number(entry, unit))
    return tuple(out)


def _declared_file(declared: Mapping[int, tuple[str | None, tuple[int, ...]]], entry: int | None,
                   known: dict[int, str | None]) -> str | None:
    """The file the function of the subprogram entry at `entry` is declared in: its own
    DW_AT_decl_file, else that of the entries it refers to, nearest first; None when none states
    one. `known` keeps what was found per entry."""
    if entry is None:
        return None
    if entry not in known:
        seen: set[int] = set()
        todo = [entry]
        found: str | None = None
        while todo and found is None:
            at = todo.pop(0)
            if at in seen or at not in declared:
                continue
            seen.add(at)
            found, refers = declared[at]
            todo += refers
        known[entry] = found
    return known[entry]


def code_frames(sections: Mapping[str, bytes], little: bool, code: list[tuple[int, int]],
                files: Mapping[int, FileNames]) -> list[Frame]:
    """Every frame of the compile units of `.debug_info` whose function has code in the library
    (`code`, its executable sections' ranges; a function the linker discarded has its address
    outside them, as `live_spans` reads): each function's own and each call inlined into it, with
    the file of each call and each declaration read from the line table of the unit that states it
    (`files`, by DW_AT_stmt_list). A function's declaration can be in another unit (an abstract
    instance under LTO), so the files are resolved once every unit is read."""
    info = sections.get(".debug_info", b"")
    abbrev = sections.get(".debug_abbrev", b"")
    tables: dict[int, dict[int, Abbreviation]] = {}
    # Each subprogram entry by its offset: its own declared file and the entries it refers to.
    declared: dict[int, tuple[str | None, tuple[int, ...]]] = {}
    # Each frame as read: its range, its depth, its call's file and the entry that declares it.
    read: list[tuple[int, int, int, str | None, int | None]] = []
    for unit in _units(info, little):
        if unit.kind not in (DW_UT_COMPILE, DW_UT_PARTIAL):
            continue
        cur = _unit_cursor(info, little, unit)
        places: _Places | None = None
        names: FileNames = _no_file
        # Per open entry with children: its depth in an inline tree, and whether its code is live.
        open_: list[tuple[int, bool]] = []
        while cur.pos < unit.end:
            at = cur.pos
            code_ = cur.uleb()
            if code_ == 0:
                if open_:
                    open_.pop()
                continue
            tag, children, attributes = _shape(tables, abbrev, unit, code_)
            values: dict[int, tuple[int, object]] = {}
            for name, form, implicit in attributes:
                value = _form_value(cur, form, unit.offsets, unit.address, sections, implicit)
                if name in _FRAME_ATTRIBUTES:
                    values[name] = (form, value)
            depth, live = open_[-1] if open_ else (0, False)
            if tag in (DW_TAG_COMPILE_UNIT, DW_TAG_PARTIAL_UNIT):
                places = _Places(sections, little, unit, values)
                stmt = values.get(DW_AT_STMT_LIST)
                names = (files[stmt[1]] if stmt is not None and isinstance(stmt[1], int)
                         and stmt[1] in files else _no_file)
                depth, live = 0, False
            elif tag == DW_TAG_SUBPROGRAM:
                decl = values.get(DW_AT_DECL_FILE)
                declared[at] = (names(decl[1]) if decl is not None and isinstance(decl[1], int)
                                else None, _references(values, unit))
                if places is not None:
                    depth = 0
                    ranges = [(start, end) for start, end in places.ranges(values) if end > start]
                    live = any(lo <= start < hi for start, _ in ranges for lo, hi in code)
                    if live:
                        read += [(start, end, 0, None, at) for start, end in ranges]
            elif tag == DW_TAG_INLINED_SUBROUTINE:
                depth += 1
                if live and places is not None:
                    call = values.get(DW_AT_CALL_FILE)
                    where = (names(call[1]) if call is not None and isinstance(call[1], int)
                             else None)
                    origin = _references(values, unit)
                    read += [(start, end, depth, where, origin[0] if origin else None)
                             for start, end in places.ranges(values) if end > start]
            if children:
                open_.append((depth, live))
    known: dict[int, str | None] = {}
    return [Frame(start, end, depth, call, _declared_file(declared, entry, known))
            for start, end, depth, call, entry in read]


Chain = tuple[Frame, ...]


def frame_chains(frames: Iterable[Frame]) -> list[tuple[int, int, Chain]]:
    """The address ranges the frames cover, sorted, none overlapping, each with the frames that
    hold its bytes, the innermost first: within one range the same frames hold every byte."""
    held_by = [frame for frame in frames if frame.end > frame.start]
    opened: dict[int, list[int]] = {}
    closed: dict[int, list[int]] = {}
    for n, frame in enumerate(held_by):
        opened.setdefault(frame.start, []).append(n)
        closed.setdefault(frame.end, []).append(n)
    points = sorted(set(opened) | set(closed))
    held: set[int] = set()
    out: list[tuple[int, int, Chain]] = []
    for at, point in enumerate(points):
        held.difference_update(closed.get(point, ()))
        held.update(opened.get(point, ()))
        if held and at + 1 < len(points):
            chain = tuple(held_by[n] for n in sorted(held, key=lambda n: (-held_by[n].depth, n)))
            out.append((point, points[at + 1], chain))
    return out


def frame_homes(chain: Chain) -> tuple[str | None, ...]:
    """The files the code of a chain (innermost first) is written in, from the innermost caller
    out: the file of each inlined call, then the file of the function the calls are inlined into."""
    return tuple(frame.call if frame.depth else frame.origin for frame in chain)


def caller_file(homes: Iterable[str | None]) -> str | None:
    """The first file of `homes` (innermost first) written outside the language runtime, or None
    when every one is the runtime's (the bytes are of a runtime function's own body) or one is
    unknown before such a file is reached."""
    for home in homes:
        if home is None:
            return None
        if not language_runtime_file(home):
            return home
    return None


def frame_file(chain: Chain) -> str | None:
    """The file of a byte the line table names no source for, held by `chain` (innermost first):
    the file the innermost frame's function is declared in, the compiler's code in a function
    (drop glue, a closure's shim, a panic path's piece) being that function's. A function of the
    language runtime, and one no entry declares a file for, is its caller's (`caller_file`); a
    runtime function's own body keeps its file. None when no file is found."""
    origin = chain[0].origin
    if origin is not None and not language_runtime_file(origin):
        return origin
    caller = caller_file(frame_homes(chain))
    return caller if caller is not None else origin


def _framed(start: int, stop: int, span: Span | None, chain: Chain | None) -> Span | None:
    """Bytes [start, stop) of `span` (None where no row covers them), held by `chain`: a file
    of the language runtime inlined into code written outside it goes to that code's file
    (`caller_file`), and bytes of no source go to their frame's (`frame_file`)."""
    if span is not None and span.source is not None:
        if chain is None or not language_runtime_file(span.source):
            return Span(start, stop, span.source)
        caller = caller_file(frame_homes(chain))
        return (Span(start, stop, caller, span.source) if caller is not None
                else Span(start, stop, span.source))
    home = frame_file(chain) if chain is not None else None
    if home is not None:
        return Span(start, stop, home, framed=True)
    return None if span is None else Span(start, stop, None)


def to_frames(spans: list[Span], frames: Iterable[Frame]) -> list[Span]:
    """`spans` read with the frames that hold their bytes (module doc, "Who wrote a byte"): the
    bytes of a language runtime file inlined into code written outside it go to the file of the
    innermost such call, the line table's file kept in `inlined`; the bytes of line 0 and those
    no row covers go to their frame's file, marked `framed`; the bytes of a runtime function's
    own body keep their file, and bytes no frame holds keep what the line table says. `spans` are
    sorted and none overlaps (`live_spans`)."""
    chains = frame_chains(frames)
    if not chains:
        return spans
    points = sorted({p for span in spans for p in (span.start, span.end)}
                    | {p for start, end, _ in chains for p in (start, end)})
    out: list[Span] = []
    at_span = at_chain = 0
    for start, stop in zip(points, points[1:]):
        while at_span < len(spans) and spans[at_span].end <= start:
            at_span += 1
        while at_chain < len(chains) and chains[at_chain][1] <= start:
            at_chain += 1
        span = (spans[at_span] if at_span < len(spans) and spans[at_span].start <= start
                else None)
        chain = (chains[at_chain][2] if at_chain < len(chains) and chains[at_chain][0] <= start
                 else None)
        piece = _framed(start, stop, span, chain)
        if piece is None:
            continue
        last = out[-1] if out else None
        if (last is not None and last.end == piece.start and last.source == piece.source
                and last.inlined == piece.inlined and last.framed == piece.framed):
            out[-1] = Span(last.start, piece.end, last.source, last.inlined, last.framed)
        else:
            out.append(piece)
    return out


def dwarf_spans(dwarf: Mapping[str, bytes], little: bool,
                code: list[tuple[int, int]]) -> list[Span]:
    """The line spans of a library's code (`live_spans`) read with the frames of its functions
    (`to_frames`): inlined language runtime code goes to its caller's file and code of no source
    line to its frame's, on either side by the same rule."""
    tables = line_tables(dwarf, little)
    spans = live_spans([sequence for found, _ in tables.values() for sequence in found], code)
    files = {at: names for at, (_, names) in tables.items()}
    return to_frames(spans, code_frames(dwarf, little, code, files))


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
    """The line spans of a library's code (`dwarf_spans`), or a DwarfError saying why none."""
    data = lib.read_bytes()
    sections = elf_facts.sections(data)
    dwarf = {s.name: _section_data(data, s) for s in sections if s.name in DWARF_SECTIONS}
    if not dwarf.get(".debug_line"):
        raise DwarfError(f"{lib} has no .debug_line: its line tables were not written or were "
                         f"stripped, so no byte of it names its source")
    return dwarf_spans(dwarf, data[5] == 1, code_ranges(sections))


# ── who wrote a source file ────────────────────────────────────────────────────────────────────

# A file of the standard library, as the toolchain's own build or the rust-src component names it,
# and one of a crate the standard library vendors.
_STD_SOURCE = re.compile(r"(?:^/rustc/[0-9a-f]+|/lib/rustlib/src/rust)/library/(.+)$")
_STD_VENDORED = re.compile(r"^/rust/deps/([A-Za-z0-9_.-]+?)-\d[^/]*/(.+)$")
# A header of a C toolchain: the C library's (`/usr/include`, a sysroot's `usr/include`, a cross C
# library's `<target triple>/include`) and the compiler's own (GCC's
# `lib/gcc/<triple>/<version>/include`, clang's `lib/clang/<version>/include`), where libgcc's
# and the C library's inline functions (the fortified string functions) are written.
_C_TOOLCHAIN_HEADER = re.compile(
    r"(?:^|/)usr/include/"
    r"|/lib/gcc(?:-cross)?/[^/]+/[^/]+/include(?:-fixed)?/"
    r"|/lib/clang/[^/]+/include/"
    r"|/[A-Za-z0-9_]+(?:-[A-Za-z0-9_.]+)*"
    r"-(?:elf|eabi|eabihf|gnu|gnueabi|gnueabihf|musl|musleabi|musleabihf)/include/")
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


def language_runtime_file(path: str) -> bool:
    """Whether `path` is a file of a language's runtime, whose code inlined into a library is
    the caller's (module doc, "Who wrote a byte"): of Rust's standard library (core, alloc, std
    and the crates below `library/`) or of a crate it vendors, as the toolchain's own build names
    it, or a header of a C toolchain."""
    return (_STD_SOURCE.search(path) is not None or _STD_VENDORED.match(path) is not None
            or _C_TOOLCHAIN_HEADER.search(path) is not None)


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
    # Whether these are bytes of the language runtime inlined here and given to the file of the
    # call that inlined them (`to_frames`).
    inlined: bool = False
    # Whether the line table names no source for these bytes and they are given to the file of the
    # frame that holds them (`frame_file`).
    framed: bool = False
    # Whether neither the line table nor a frame names a source for these bytes and they are placed
    # by the body's symbols (`symbol_piece`): `owner` is then a symbol's owner, not a file's.
    symbol_placed: bool = False


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


def symbol_piece(rules: Rules, body: Body, size: int) -> tuple[Piece, set[str]]:
    """The `size` bytes of `body` neither a line nor a frame names a source for (module doc, "Who
    wrote a byte"), and the rules that placed them: in the area the body's symbols are placed in
    (`place_bodies`, its names' name rules, else their owners' rules); else unclassified by the
    owner its names carry, so a rule for that owner places them; else, a body whose names carry no
    owner, unattributed."""
    owners = sorted({owner for symbol in (body.lead, *body.names) for owner in symbol.owners},
                    key=lambda owner: (owner not in body.lead.owners, owner))
    owner = owners[0] if owners else None
    used: set[str] = set()
    if body.area is not None:
        for symbol in body.names:
            area, rule = classify(rules, symbol)
            if area == body.area:
                used.update(rule)
    if body.area is None and owner is None:
        return Piece(body, size, None, None, None), used
    return Piece(body, size, None, owner, body.area, symbol_placed=True), used


def attribute(bodies: Iterable[Body], spans: list[Span],
              owners: Mapping[str, tuple[str | None, str | None]], rules: Rules,
              areas: list[str]) -> tuple[list[Piece], set[str]]:
    """Each body's bytes by the source the line table gives them (module doc, "Who wrote a byte"):
    a byte of the body's own file goes to the area a name rule gives the body when one does, every
    other byte to the owner rule of its file's owner; a byte no span gives a source goes by the
    body's symbols (`symbol_piece`). `spans` are `dwarf_spans`, so the file of inlined language
    runtime code is its caller's and the file of a byte of no source line its frame's. Returns the
    pieces and the rules that placed a byte."""
    starts = [span.start for span in spans]
    pieces: list[Piece] = []
    used: set[str] = set()
    for body in bodies:
        own = source_at(spans, starts, body.address)
        named, by_name = name_area(rules, body, areas)
        low, high = body.address, body.address + body.size
        sizes: dict[tuple[str | None, str | None, str | None, bool, bool], int] = {}
        covered = unsourced = 0
        at = max(bisect.bisect_right(starts, low) - 1, 0)
        while at < len(spans) and spans[at].start < high:
            span = spans[at]
            at += 1
            count = min(span.end, high) - max(span.start, low)
            if count <= 0:
                continue
            covered += count
            if span.source is None:
                unsourced += count
                continue
            moved = span.inlined is not None
            owner = owners.get(span.source, (None, None))[0]
            if named is not None and span.source == own:
                used |= by_name
                key: tuple[str, str | None, str | None, bool, bool] = (
                    span.source, owner, named, moved, span.framed)
            else:
                prefix = owner_rule(rules, owner) if owner is not None else None
                if prefix is not None:
                    used.add(f"owners {prefix}")
                key = (span.source, owner, rules.owners[prefix] if prefix is not None else None,
                       moved, span.framed)
            sizes[key] = sizes.get(key, 0) + count
        pieces += [Piece(body, count, *key) for key, count in sizes.items()]
        unsourced += body.size - covered
        if unsourced:
            piece, placed = symbol_piece(rules, body, unsourced)
            pieces.append(piece)
            used |= placed
    return pieces, used


def piece_label(piece: Piece) -> str:
    """How a piece's source is named in a finding and in --explain: its owner, else its file, else
    how its body's symbols placed it."""
    if piece.owner is not None:
        return piece.owner
    if piece.symbol_placed:
        return BY_SYMBOL
    return NO_LINE if piece.source is None else f"{NO_OWNER} {piece.source}"


def unattributed(piece: Piece) -> bool:
    """Whether no line, no frame and no symbol of its body names who wrote a piece's bytes."""
    return piece.source is None and not piece.symbol_placed


def tally_pieces(pieces: Iterable[Piece], used: set[str], areas: list[str]) -> Tally:
    """The bytes of each area by line, the unplaced ones by the owner (or file) that holds them, and
    the unattributed ones (`unattributed`) by the body that holds them."""
    result = Tally({area: 0 for area in areas}, used=set(used))
    unplaced: dict[str, int] = {}
    unlined: dict[tuple[str, ...], int] = {}
    for piece in pieces:
        result.total += piece.size
        if unattributed(piece):
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


def ledger_cases(table: object) -> dict:
    """The ledger's cases, each id -> its rows by area; empty when it has none that reads."""
    cases = table.get("cases") if isinstance(table, dict) else None
    return cases if isinstance(cases, dict) else {}


def measure_command(case_id: str) -> str:
    """The command that prints a case's rows, which an unfilled row's finding names."""
    return f"{MEASURE} {case_id}"


def rule_findings(table: object, case_ids: Iterable[str]) -> list[str]:
    """What keeps the ledger from being read: its shape, its case, its areas and its rules. Static,
    so every shard and the selftest run it."""
    where = LEDGER.relative_to(ROOT)
    if not isinstance(table, dict):
        return [f"{where} is missing or is no object: the release library's areas are held there"]
    if table.get("schema") != LEDGER_SCHEMA:
        return [f"{where} is not schema {LEDGER_SCHEMA}"]
    out = [f"{where} has the unknown key {key!r}" for key in sorted(set(table) - TABLE_KEYS)]
    cases = table.get("cases")
    known = set(case_ids)
    if not isinstance(cases, dict) or not cases:
        out.append(f"{where}: cases is no object of the cases whose areas it holds")
    else:
        out += [f"{where}: case {case_id!r} is no pico case of capability_cost_gate.py, whose "
                f"builds this gate reads" for case_id in cases if case_id not in known]
        base = table.get("base_case")
        if not isinstance(base, str) or base not in cases:
            out.append(f"{where}: base_case {base!r} is none of its cases: --per-feature steps "
                       f"from it to each other case")
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
    """What keeps every declared area of every case from having exactly one well-formed row. A
    row whose ratio_at_most is null is well formed here (the unfilled form), and the grade refuses
    it."""
    where = LEDGER.relative_to(ROOT)
    ids = area_ids(table)
    out: list[str] = []
    for case_id, rows in ledger_cases(table).items():
        if not isinstance(rows, dict):
            out.append(f"{case_id}: its rows in {where} are no object")
            continue
        out += [f"{case_id}: {area}: no row in {where}: an area is held from the commit that "
                f"declares it, and a case from the commit that adds it; "
                f"{measure_command(case_id)} prints its row" for area in ids if area not in rows]
        for area, row in rows.items():
            if area not in ids:
                out.append(f"{case_id}: {area}: a row in {where} for no declared area")
            else:
                out += [f"{case_id}: {finding}" for finding in row_findings(area, row)]
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
                f"{tallied.unattributed_bytes} bytes of text no line, frame or symbol owner "
                f"places, and the limit is "
                f"set from a run of both sides"]
    if tallied.unattributed_bytes <= limit:
        return []
    shown = "; ".join(f"{size} B {' = '.join(names)}"
                      for size, names in tallied.unattributed[:UNCLASSIFIED_NAMED])
    return [f"{side}: {tallied.unattributed_bytes} bytes of text in {len(tallied.unattributed)} "
            f"bodies have no source line, no frame and no symbol that names an owner or an area, "
            f"over the {limit} {where} allows, so the areas no longer hold the code they are read "
            f"from; the bodies that hold most: {shown}"]


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


def grade_areas(rows: Mapping[str, object], readings: Mapping[str, dict],
                remeasure: str = MEASURE) -> tuple[list[str], list[str]]:
    """The findings and the notes of each area's reading against its well-formed row (one case's
    rows); a missing or malformed row is `row_population_findings`' to name. `remeasure` is the
    command that prints the case's rows."""
    findings: list[str] = []
    notes: list[str] = []
    for area, reading in readings.items():
        row = rows.get(area)
        if not isinstance(row, dict) or row_findings(area, row):
            continue
        found, said = grade_ceiling(area, row, reading, remeasure, table=LEDGER,
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


def table_lines(table: dict, rows: Mapping[str, object], wz: Tally, pico: Tally) -> list[str]:
    """One case's areas against its rows, its total, and its unclassified and unattributed
    bytes."""
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
    lines.append(f"  size-ledger:   unattributed (no source line, frame or symbol owner): "
                 f"{wz.unattributed_bytes} "
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


def owner_symbols(sizes: Mapping[int, int], names: Mapping[int, str],
                  limit: int = EXPLAIN_OWNER_SYMBOLS) -> dict:
    """Which bodies hold an owner's bytes, since a body holds the inlined code of owners besides
    its own: `sizes` maps a body (by address) to the owner's bytes in it, `names` a body to the
    name it is shown by. Gives the name of the body `largest` counts (`largest_symbol`), the `limit` bodies
    that hold the most of the owner's bytes with those bytes, largest first, and the bytes and
    bodies of the rest, so the list and the rest add up to the owner's bytes."""
    rows = sorted(({"symbol": names[address], "bytes": size} for address, size in sizes.items()),
                  key=lambda row: (-row["bytes"], row["symbol"]))
    rest = rows[limit:]
    return {"largest_symbol": rows[0]["symbol"] if rows else None, "symbols": rows[:limit],
            "symbols_rest": sum(row["bytes"] for row in rest), "symbols_rest_bodies": len(rest)}


def explain_area(side: str, pieces: Iterable[Piece], demangled: Mapping[str, str],
                 by_symbol: int | None) -> dict:
    """What holds one side's bytes of one area: its owners (a wz module, a zenoh-pico file), its
    bodies by their bytes here, and on the wz side its source files and its generic functions with
    more than one copy; each list whole, largest first. `by_symbol` is what the symbol reading
    gives the area, `inlined` the bytes of language runtime code inlined into the area's
    functions that are counted in it by the file of the call (`to_frames`), in `inlined_bodies`
    bodies, `framed` the bytes of no source line counted in it by the file of the frame that
    holds them (`frame_file`), in `framed_bodies` bodies, and `symbol_placed` the bytes of no
    source line and no frame counted in it by its body's symbols (`symbol_piece`), in
    `symbol_placed_bodies` bodies. Each owner's row also names the bodies that hold its bytes
    (`owner_symbols`)."""
    owners: dict[str, dict[int, int]] = {}
    files: dict[str, dict[int, int]] = {}
    generics: dict[str, dict[int, int]] = {}
    held: dict[int, tuple[Body, dict[str, int]]] = {}
    total = 0
    inlined: dict[int, int] = {}
    framed: dict[int, int] = {}
    placed: dict[int, int] = {}
    for piece in pieces:
        total += piece.size
        body = piece.body
        if piece.inlined:
            inlined[body.address] = inlined.get(body.address, 0) + piece.size
        if piece.framed:
            framed[body.address] = framed.get(body.address, 0) + piece.size
        if piece.symbol_placed:
            placed[body.address] = placed.get(body.address, 0) + piece.size
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
    names = {address: demangled.get(body.lead.name, body.lead.name)
             for address, (body, _) in held.items()}
    ranked_owners = _ranked(owners, "owner")
    for row in ranked_owners:
        row.update(owner_symbols(owners[row["owner"]], names))
    out = {"bytes": total, "by_symbol": by_symbol, "bodies": len(symbols),
           "inlined": sum(inlined.values()), "inlined_bodies": len(inlined),
           "framed": sum(framed.values()), "framed_bodies": len(framed),
           "symbol_placed": sum(placed.values()), "symbol_placed_bodies": len(placed),
           "owners": ranked_owners, "symbols": symbols}
    if side == "wz":
        out["files"] = _ranked(files, "file")
        out["generics"] = [row for row in _ranked(generics, "function") if row["bodies"] > 1]
    return out


def piece_area(piece: Piece) -> str:
    """The area --explain lists a piece under: its own, or the unclassified or the unattributed."""
    if unattributed(piece):
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


def explain_owner_bodies(title: str, rows: list[dict], owners: int,
                         shown: int = EXPLAIN_OWNER_SYMBOLS_SHOWN) -> list[str]:
    """Under each of the `owners` first rows of `rows` (`explain_area`'s owners), the `shown`
    bodies that hold the most of its bytes, then what its other bodies hold."""
    if not rows:
        return [f"    {title}: none"]
    out = [f"    {title}, the largest {shown} bodies of each of the largest "
           f"{min(owners, len(rows))} of {len(rows)}:"]
    for row in rows[:owners]:
        out.append(f"      {fit(row['owner'])}: {row['bytes']} B in {row['bodies']} bodies")
        listed = row["symbols"][:shown]
        out += [f"      {symbol['bytes']:>8}  {fit(symbol['symbol'])}" for symbol in listed]
        rest = row["bytes"] - sum(symbol["bytes"] for symbol in listed)
        if rest:
            out.append(f"      {rest:>8}  in {row['bodies'] - len(listed)} other bodies")
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
        lines.append(f"    language runtime code inlined into functions and counted here by "
                     f"its caller's file: wz {wz.get('inlined', 0)} B in "
                     f"{wz.get('inlined_bodies', 0)} bodies, zenoh-pico {pico.get('inlined', 0)} "
                     f"B in {pico.get('inlined_bodies', 0)} bodies")
        lines.append(f"    code of no source line counted here by the file of its frame: wz "
                     f"{wz.get('framed', 0)} B in {wz.get('framed_bodies', 0)} bodies, "
                     f"zenoh-pico {pico.get('framed', 0)} B in {pico.get('framed_bodies', 0)} "
                     "bodies")
        lines.append(f"    code of no source line and no frame counted here by its body's symbol: "
                     f"wz {wz.get('symbol_placed', 0)} B in {wz.get('symbol_placed_bodies', 0)} "
                     f"bodies, zenoh-pico {pico.get('symbol_placed', 0)} B in "
                     f"{pico.get('symbol_placed_bodies', 0)} bodies")
        lines += explain_table("wz modules", wz["owners"], EXPLAIN_OWNERS,
                               ("bytes", "bodies"), lambda row: row["owner"])
        lines += explain_owner_bodies("wz modules by the bodies that hold their bytes",
                                      wz["owners"], EXPLAIN_OWNERS)
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
        lines += explain_owner_bodies("zenoh-pico files by the bodies that hold their bytes",
                                      pico["owners"], EXPLAIN_FILES)
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


READ_ERRORS = (subprocess.CalledProcessError, OSError, RuntimeError, elf_facts.ElfError,
               wz_config.PresetError)


@dataclass(frozen=True)
class Counted:
    """A case's bytes read by area: each side's by line (`wz`, `pico`) and by symbol
    (`by_symbol`), the pieces the line reading placed, and the owner of each source file."""
    wz: Tally
    pico: Tally
    pieces: Mapping[str, list[Piece]]
    by_symbol: Mapping[str, Tally]
    sources: Mapping[str, Mapping[str, tuple[str | None, str | None]]]


def count_case(read: CaseRead, table: dict, prefixes: build_normalization.Prefixes) -> Counted:
    """The bytes of each area of a case `read_case` read, by the areas and rules of `table`."""
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
    return Counted(tally_pieces(*pieces["wz"], areas), tally_pieces(*pieces["pico"], areas),
                   {side: listed for side, (listed, _) in pieces.items()}, by_symbol, sources)


def cmd_run(mode: str, shard: tuple[int, int] | None, only: Iterable[str] = ()) -> int:
    """`mode` is check, measure or explain; only check grades the rows. `only` names the cases
    of the ledger to read, every case when it names none."""
    measure_only = mode != "check"
    table = load_ledger()
    blocking = rule_findings(table, pico_case_ids())
    rows_found = [] if blocking else row_population_findings(table)
    for finding in blocking:
        print(f"  size-ledger FAIL: {finding}", file=sys.stderr)
    if blocking or not isinstance(table, dict):
        return 1
    cases = ledger_cases(table)
    named = list(only)
    unknown = [case_id for case_id in named if case_id not in cases]
    if unknown:
        print(f"  size-ledger: no case of {LEDGER.relative_to(ROOT)}: {unknown}", file=sys.stderr)
        return 2
    rc = 0
    for finding in rows_found:
        if measure_only:
            print(f"  size-ledger: note: {finding}")
        else:
            print(f"  size-ledger FAIL: {finding}", file=sys.stderr)
            rc = 1
    chosen = [case_id for case_id in cases if not named or case_id in named]
    if shard is not None:
        try:
            planned = set(shard_case_ids(*shard))
        except (OSError, ValueError) as e:
            print(f"  size-ledger: {cost.CASE_WEIGHTS.name}: {e}", file=sys.stderr)
            return 2
        for case_id in chosen:
            if case_id not in planned:
                print(f"  size-ledger: {case_id} is built on another shard of {shard[0]}; this "
                      f"shard checked the ledger itself")
        chosen = [case_id for case_id in chosen if case_id in planned]
        if not chosen:
            return rc
    try:
        env, prefixes = cost.build_env()
        linker = cost.gnu_ld_version(env)
        cost.strip_tool()
    except (ValueError, RuntimeError) as e:
        print(f"  size-ledger: {e}", file=sys.stderr)
        return 2
    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    by_id = {c.id: c for c in cost.CASES}
    for case_id in chosen:
        rows = cases[case_id] if isinstance(cases[case_id], dict) else {}
        rc = max(rc, run_case(mode, by_id[case_id], rows, table, env, prefixes, linker, today))
    return rc


def run_case(mode: str, case: cost.Case, rows: Mapping[str, object], table: dict,
             env: Mapping[str, str], prefixes: build_normalization.Prefixes, linker: str,
             today: str) -> int:
    """Read one case of the ledger and print its areas and the rows it reads; in check mode grade
    each area against its row of `rows`, and in explain mode say what holds each area's bytes."""
    measure_only = mode != "check"
    try:
        read, refused = read_case(case, env, prefixes)
    except READ_ERRORS as e:
        print(f"  size-ledger FAIL: {case.id}: the case or its reference could not be read: {e}",
              file=sys.stderr)
        return 1
    for finding in refused:
        print(f"  size-ledger FAIL: {finding}", file=sys.stderr)
    if read is None:
        return 1
    areas = area_ids(table)
    counted = count_case(read, table, prefixes)
    wz, pico = counted.wz, counted.pico
    print(f"  size-ledger: {case.id}: function bytes by area, each byte by the source its line "
          f"table names (inlined language runtime code by its caller's, code of no line by its "
          f"frame's, else by its body's symbols), against zenoh-pico "
          f"{read.pin} as the same build ({read.toolchain}; both linked by {linker})")
    for line in table_lines(table, rows, wz, pico):
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
    read_by = {how: sum(1 for _, found in counted.sources["wz"].values() if found == how)
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
    readings, missing = area_readings(areas, wz, pico, read.pin, read.toolchain, today)
    findings += missing
    if not measure_only:
        graded, said = grade_areas(rows, readings, measure_command(case.id))
        findings += graded
        notes += said
    for note in notes:
        print(f"  size-ledger: {case.id}: {note}")
    if readings:
        print(f"  size-ledger: {case.id}: the rows this run reads for its rows in "
              f"{LEDGER.relative_to(ROOT)} (`cases`, {json.dumps(case.id)}; each replaces the "
              f"row of its area):")
        for n, (area, reading) in enumerate(readings.items(), 1):
            row = ceiling_row(reading, row_debt(rows.get(area)))
            print(f"    {format_row(area, row)}{',' if n < len(readings) else ''}")
    rc = 0
    for finding in findings:
        if measure_only:
            print(f"  size-ledger: {case.id}: note: {finding}")
        else:
            print(f"  size-ledger FAIL: {case.id}: {finding}", file=sys.stderr)
            rc = 1
    if rc == 0 and not measure_only:
        print(f"  size-ledger: {case.id}: {len(readings)} area(s) under their rows against "
              f"zenoh-pico, unclassified text within {limit} bytes and text of no source line "
              f"within {unlined} bytes on each side")
    if mode == "explain":
        rc = max(rc, explain_case(case.id, read, areas, counted.pieces, counted.by_symbol,
                                  counted.sources, today))
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


# ── one feature at a time: --per-feature ────────────────────────────────────────────────────────


def feature_steps(start: list[str], target: list[str], enabled: Callable[[list[str]], set[str]]
                  ) -> tuple[list[tuple[str, list[str]]], list[str]]:
    """The chain from the features `start` to those of `target`: each feature of `target`, in
    its order, that the features before it do not already turn on (`enabled`, cargo's resolution
    of a list), with the list its step builds (`start` and every feature added up to it); and the
    features `start` turns on that `target` does not, which every step keeps."""
    current = list(start)
    steps: list[tuple[str, list[str]]] = []
    for feature in target:
        if feature in enabled(current):
            continue
        current = [*current, feature]
        steps.append((feature, current))
    goal = enabled(target)
    return steps, sorted(f for f in enabled(start) if f not in goal)


def side_bytes(tallied: Tally, areas: list[str]) -> dict[str, int]:
    """One side's bytes by area, with its unclassified and its unattributed bytes apart: together
    every byte of its text (`Tally.total`), so what a step adds sums to what it adds in all."""
    out = {area: tallied.by_area[area] for area in areas}
    out[UNCLASSIFIED_AREA] = tallied.unclassified_bytes
    out[UNATTRIBUTED_AREA] = tallied.unattributed_bytes
    return out


def added_bytes(before: Mapping[str, int], after: Mapping[str, int]) -> dict[str, int]:
    """What a step added to each area of one side, negative where it took bytes away."""
    return {key: after[key] - before.get(key, 0) for key in after}


def switch_moves(before: Mapping[str, int], after: Mapping[str, int]) -> list[str]:
    """The zenoh-pico switches a step's reference sets otherwise than the step's before it."""
    return [f"{name} {before.get(name)}->{after[name]}" for name in sorted(after)
            if before.get(name) != after[name]]


@dataclass(frozen=True)
class Step:
    """One build of a chain: the feature it adds (None for the base), the features it builds,
    what else that feature turns on, the switches its zenoh-pico reference is built with, and
    each side's bytes (`side_bytes`)."""
    feature: str | None
    features: tuple[str, ...]
    turns_on: tuple[str, ...]
    switches: Mapping[str, int]
    wz: Mapping[str, int]
    pico: Mapping[str, int]


def per_feature_report(case_id: str, base_id: str, pin: str, toolchain: str, date: str,
                       kept: list[str], steps: list[Step]) -> dict:
    """The chain from `base_id` to `case_id` as JSON, `steps[0]` the base: each step's bytes,
    what it added on each side by area, wz's addition over zenoh-pico's (`excess`), and the
    switches of zenoh-pico it moved."""
    rows = []
    for before, step in zip(steps, steps[1:]):
        wz = added_bytes(before.wz, step.wz)
        pico = added_bytes(before.pico, step.pico)
        rows.append({"feature": step.feature, "features": list(step.features),
                     "turns_on": list(step.turns_on),
                     "switches": switch_moves(before.switches, step.switches),
                     "wz": dict(step.wz), "pico": dict(step.pico), "wz_added": wz,
                     "pico_added": pico, "excess": {key: wz[key] - pico[key] for key in wz}})
    base = steps[0]
    return {"schema": PER_FEATURE_SCHEMA, "case": case_id, "base": base_id, "pin": pin,
            "toolchain": toolchain, "date": date, "kept": list(kept),
            "base_features": list(base.features), "base_wz": dict(base.wz),
            "base_pico": dict(base.pico), "steps": rows}


def ratio_text(wz: int, pico: int) -> str:
    return f"{wz / pico:.4f}" if pico else "-"


def per_feature_lines(report: dict, areas: list[str]) -> list[str]:
    """`report` (`per_feature_report`) as tables: each step's additions by area, then the
    features by how much more each costs wz than zenoh-pico, and the whole chain's ratio."""
    keys = [*areas, UNCLASSIFIED_AREA, UNATTRIBUTED_AREA]
    head = f"  size-ledger per-feature: {report['case']}"
    lines = [f"{head}: from {report['base']} ({', '.join(report['base_features'])}), one feature "
             f"at a time in the order the case names them, each step {report['base']}'s build "
             f"with the features before it and its own, against zenoh-pico {report['pin']} with "
             f"the switches those features answer ({report['toolchain']})"]
    if report["kept"]:
        lines.append(f"{head}: {report['base']} turns on {', '.join(report['kept'])}, which "
                     f"{report['case']} does not; every step keeps them")
    for n, step in enumerate(report["steps"], 1):
        wz, pico, excess = step["wz_added"], step["pico_added"], step["excess"]
        also = f", which turns on {', '.join(step['turns_on'])}" if step["turns_on"] else ""
        moved = (f"zenoh-pico {', '.join(step['switches'])}" if step["switches"]
                 else "zenoh-pico built as before: no switch of its answers it")
        lines.append(f"{head}: step {n} +{step['feature']}{also} ({moved}): "
                     f"wz {sum(wz.values()):+d} B, zenoh-pico {sum(pico.values()):+d} B, "
                     f"wz - zenoh-pico {sum(excess.values()):+d} B")
        lines.append(f"      {'area':<16} {'wz':>9} {'zenoh-pico':>11} {'wz - pico':>10}")
        lines += [f"      {key:<16} {wz[key]:>+9d} {pico[key]:>+11d} {excess[key]:>+10d}"
                  for key in keys if wz[key] or pico[key]]
    lines.append(f"{head}: the features by what each costs wz over what it costs zenoh-pico, "
                 f"most first:")
    lines.append(f"      {'feature':<24} {'wz':>9} {'zenoh-pico':>11} {'wz - pico':>10}  "
                 f"the areas it costs wz most over zenoh-pico in")
    for step in sorted(report["steps"], key=lambda s: (-sum(s["excess"].values()), s["feature"])):
        excess = step["excess"]
        top = sorted((key for key in keys if excess[key] > 0), key=lambda k: (-excess[k], k))
        where = ", ".join(f"{key} {excess[key]:+d}" for key in top[:3]) or "none"
        lines.append(f"      {step['feature']:<24} {sum(step['wz_added'].values()):>+9d} "
                     f"{sum(step['pico_added'].values()):>+11d} {sum(excess.values()):>+10d}  "
                     f"{where}")
    last = report["steps"][-1] if report["steps"] else None
    first_wz, first_pico = sum(report["base_wz"].values()), sum(report["base_pico"].values())
    end_wz = sum(last["wz"].values()) if last else first_wz
    end_pico = sum(last["pico"].values()) if last else first_pico
    lines.append(f"{head}: function bytes, wz against zenoh-pico: {first_wz} against "
                 f"{first_pico} ({ratio_text(first_wz, first_pico)}) at {report['base']}, "
                 f"{end_wz} against {end_pico} ({ratio_text(end_wz, end_pico)}) after the last "
                 f"step")
    return lines


def per_feature_path(case_id: str) -> pathlib.Path:
    return cost.TARGET / EXPLAIN_DIR / f"per-feature-{case_id}.json"


def cmd_per_feature(only: Iterable[str]) -> int:
    """Step from the ledger's base case to each case `only` names (every other case of the
    ledger when it names none) one feature at a time, and print and keep what each feature adds to
    each area on each side (`--per-feature`). It grades nothing: 0 when every step was read, 1
    when one could not be, 2 on a usage error or a host that cannot build."""
    table = load_ledger()
    blocking = rule_findings(table, pico_case_ids())
    for finding in blocking:
        print(f"  size-ledger FAIL: {finding}", file=sys.stderr)
    if blocking or not isinstance(table, dict):
        return 1
    cases = ledger_cases(table)
    named = list(only)
    unknown = [case_id for case_id in named if case_id not in cases]
    if unknown:
        print(f"  size-ledger: no case of {LEDGER.relative_to(ROOT)}: {unknown}", file=sys.stderr)
        return 2
    base_id = table["base_case"]
    targets = [case_id for case_id in (named or list(cases)) if case_id != base_id]
    if not targets:
        print(f"  size-ledger: no case to step to from {base_id}, the ledger's base",
              file=sys.stderr)
        return 2
    by_id = {c.id: c for c in cost.CASES}
    base = by_id[base_id]
    manifest = wz_config.manifest_features(cost.CRATES / base.package / "Cargo.toml")

    def enabled(features: list[str]) -> set[str]:
        return wz_config.enabled_features(manifest, features)

    try:
        env, prefixes = cost.build_env()
        linker = cost.gnu_ld_version(env)
        cost.strip_tool()
        lists = {case_id: cost.feature_list(by_id[case_id]) for case_id in [base_id, *targets]}
    except (ValueError, RuntimeError) as e:
        print(f"  size-ledger: {e}", file=sys.stderr)
        return 2
    defaults = [case_id for case_id, listed in lists.items() if listed is None]
    if defaults:
        print(f"  size-ledger: {', '.join(defaults)} build their crate's default features, which "
              f"no chain of named features reaches", file=sys.stderr)
        return 2
    start = [f for f in lists[base_id].split(",") if f]
    decl = wz_config.load_decl()
    areas = area_ids(table)
    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    # Each build once a run, by the features it turns on: two chains through one set share it.
    measured: dict[frozenset[str], tuple[dict[str, int], dict[str, int], dict[str, int]]] = {}
    origin = {"pin": "", "toolchain": ""}
    print(f"  size-ledger per-feature: every library and zenoh-pico reference is linked by "
          f"{linker}")

    def measure(features: list[str]) -> tuple[dict[str, int], dict[str, int],
                                              dict[str, int]] | None:
        on = frozenset(enabled(features))
        if on not in measured:
            step = replace(base, id="+".join([base.id, *features[len(start):]]),
                           features=",".join(features), features_from=None)
            print(f"  size-ledger per-feature: reading {step.id}")
            try:
                read, refused = read_case(step, env, prefixes)
            except READ_ERRORS as e:
                print(f"  size-ledger FAIL: {step.id}: the build or its reference could not be "
                      f"read: {e}", file=sys.stderr)
                return None
            for finding in refused:
                print(f"  size-ledger FAIL: {finding}", file=sys.stderr)
            if read is None:
                return None
            counted = count_case(read, table, prefixes)
            origin.update(pin=read.pin, toolchain=read.toolchain)
            measured[on] = (wz_config.pico_reference(decl, set(on)), side_bytes(counted.wz, areas),
                            side_bytes(counted.pico, areas))
        return measured[on]

    rc = 0
    for case_id in targets:
        chain, kept = feature_steps(start, [f for f in lists[case_id].split(",") if f], enabled)
        steps: list[Step] = []
        before: set[str] = set()
        for feature, features in [(None, start), *chain]:
            got = measure(features)
            if got is None:
                break
            on = enabled(features)
            also = tuple(sorted(on - before - {feature})) if feature is not None else ()
            steps.append(Step(feature, tuple(features), also, *got))
            before = on
        if len(steps) != len(chain) + 1:
            rc = 1
            continue
        report = per_feature_report(case_id, base_id, origin["pin"], origin["toolchain"], today,
                                    kept, steps)
        path = per_feature_path(case_id)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
        except OSError as e:
            print(f"  size-ledger FAIL: the chain of {case_id} could not be kept at {path}: {e}",
                  file=sys.stderr)
            rc = 1
        for line in per_feature_lines(report, areas):
            print(line)
        print(f"  size-ledger per-feature: {case_id}: every number of these tables is at {path}")
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
    expect("the committed ledger is well formed and names pico cases of the cost gate",
           isinstance(committed, dict) and ledger_findings(committed, cases) == [])
    expect("the committed ledger holds the release client, the cooperative peer and the twin of "
           "the Windows like-for-like library, and steps from the client",
           {"pico-client-coop-nostd", "pico-peer-coop", "pico-api-coop-nostd"}
           <= set(ledger_cases(committed))
           and isinstance(committed, dict)
           and committed.get("base_case") == "pico-client-coop-nostd")
    expect("an unfilled row names the command that prints its case's rows",
           measure_command("c") == f"{MEASURE} c")
    if isinstance(committed, dict) and ledger_cases(committed):
        def broken(change) -> list[str]:
            table = json.loads(json.dumps(committed))
            change(table)
            return ledger_findings(table, cases)

        first = area_ids(committed)[0]
        held = next(iter(ledger_cases(committed)))
        expect("an area of a case without a row is refused, naming the case",
               any("no row" in f and f.startswith(f"{held}: ")
                   for f in broken(lambda t: t["cases"][held].pop(first))))
        expect("a row for no area is refused",
               any("for no declared area" in f
                   for f in broken(lambda t: t["cases"][held].update({"ghost": unfilled}))))
        expect("a case whose rows are no object is refused",
               any("are no object" in f
                   for f in broken(lambda t: t["cases"].update({held: []}))))
        expect("a ledger of no case is refused",
               any("cases is no object" in f for f in broken(lambda t: t.update({"cases": {}}))))
        expect("a base case that is none of its cases is refused",
               any("base_case 'ghost' is none of its cases" in f
                   for f in broken(lambda t: t.update({"base_case": "ghost"})))
               and any("base_case" in f for f in broken(lambda t: t.pop("base_case")))
               and any("base_case" in f for f in broken(lambda t: t.update({"base_case": []}))))
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
            for rows in t["cases"].values():
                rows["lonely"] = unfilled
            t["rules"]["wz"]["owners"]["zz"] = "lonely"

        expect("an area no rule of a side names is refused",
               any("no pico rule names the area 'lonely'" in f for f in broken(lonely)))
        expect("a case that is no pico case of the cost gate is refused",
               any("no pico case" in f
                   for f in broken(lambda t: t["cases"].update({"ghost": {}}))))
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
        expect("the committed wz rules place what the peer and the like-for-like library bring as "
               "zenoh-pico's rules place its counterpart",
               placed("wz", "_R", "wz_ext_pubsub::advanced_publisher::put") == "doors"
               and placed("pico", "ze_declare_advanced_publisher",
                          "src/api/advanced_publisher.c") == "doors"
               and placed("wz", "_R", "wz_session_core::multicast_rx::receive") == "transport"
               and placed("pico", "_z_multicast_recv_t_msg", "src/transport/multicast/rx.c")
               == "transport"
               and placed("wz", "_R", "wz_session_core::join_decode::decode") == "codec"
               and placed("wz", "_R", "wz_session_core::lent_request::encode") == "codec"
               and placed("wz", "_R", "wz_session_core::lent_response::encode") == "codec"
               and placed("wz", "_R", "wz_node_time::node_clock::stamp") == "driver")
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
                   owners={"wz_x": "x", "wz_x::k": "k", "wz_d": "door", "wz_q": "k"},
                   separator="::")
    lareas = ["door", "x", "k"]
    # Bodies no row covers: one no rule places and no owner names, one whose owner no rule
    # places, one whose owner a rule places.
    lbodies, _ = place_bodies(
        [Symbol(0x100, 0x40, "z_open", ()), Symbol(0x200, 0x20, "_Ra", ("wz_x::m::f",)),
         Symbol(0x300, 0x10, "_Rb", ("wz_x::g::h",)), Symbol(0x300, 0x10, "_Rc", ("wz_x::g::i",)),
         Symbol(0x400, 8, "_start_c", ()), Symbol(0x500, 8, "_Rz", ("wz_z::q",)),
         Symbol(0x600, 0x10, "_Rq", ("wz_q::r",))],
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
           lines_read.by_area == {"door": 0x10 + 0x18, "x": 0x20 + 0x10, "k": 0x10 + 0x10}
           and by_name.by_area == {"door": 0x40, "x": 0x30, "k": 0x10})
    expect("a name rule places the body's own file, even where the owner rule names another area",
           any(p.source == "/s/doors.rs" and p.area == "door" and p.owner == "wz_x::doors"
               for p in lpieces)
           and lused == {"names ^z_", "owners wz_x::k", "owners wz_x", "owners wz_q"})
    expect("bytes no line and no frame gives a source go to the area the body's symbols are placed "
           "in, by a name rule or by an owner rule",
           [(p.size, p.area, p.owner, piece_label(p)) for p in lpieces if p.symbol_placed
            and p.area is not None]
           == [(8 + 0x10, "door", None, BY_SYMBOL), (0x10, "k", "wz_q::r", "wz_q::r")]
           and explain_area("wz", [p for p in lpieces if piece_area(p) == "door"], {},
                            None)["symbol_placed"] == 0x18)
    expect("such bytes are unclassified under the owner their symbols carry when no rule places "
           "it, and unattributed only when they carry none, by the body that holds them",
           lines_read.unattributed == [(8, ("_start_c",))]
           and lines_read.unattributed_bytes == 8
           and [piece_area(p) for p in lpieces if p.body.address == 0x400] == [UNATTRIBUTED_AREA]
           and [piece_area(p) for p in lpieces if p.body.address == 0x500] == [UNCLASSIFIED_AREA])
    expect("a file with no owner is unclassified, named by its file",
           lines_read.unclassified == [(8, (f"{NO_OWNER} /s/unknown.rs",)), (8, ("wz_z::q",))])
    expect("every byte of every body is counted once, the same total as by symbol",
           lines_read.total == by_name.total == 0x40 + 0x20 + 0x10 + 8 + 8 + 0x10
           and sum(lines_read.by_area.values()) + lines_read.unclassified_bytes
           + lines_read.unattributed_bytes == lines_read.total)
    expect("unattributed bytes at the limit pass, over it fail naming the bodies, and no limit is "
           "a finding with the reading",
           unattributed_findings("wz", lines_read, 8) == []
           and len(over := unattributed_findings("wz", lines_read, 7)) == 1
           and "_start_c" in over[0]
           and len(unset := unattributed_findings("wz", lines_read, None)) == 1
           and "null" in unset[0] and "8 bytes" in unset[0])

    # Inlined standard library code goes to its caller's file; a library body keeps its own.
    wz_rs, ptr_rs = "/wz/crates/wz-x/src/lib.rs", "/rustc/abc/library/core/src/ptr/mod.rs"
    opt_rs = "/rustc/abc/library/core/src/option.rs"
    fortified = "/usr/include/x86_64-linux-gnu/bits/string_fortified.h"
    expect("a language runtime file is one of Rust's standard library, a crate it vendors or a C "
           "toolchain's header, and no file of a crate or of zenoh-pico",
           language_runtime_file(ptr_rs)
           and language_runtime_file("/x/lib/rustlib/src/rust/library/alloc/src/vec/mod.rs")
           and language_runtime_file("/rust/deps/hashbrown-0.15.2/src/raw/mod.rs")
           and language_runtime_file(fortified)
           and language_runtime_file("/usr/lib/gcc/x86_64-linux-gnu/13/include/stddef.h")
           and language_runtime_file("/opt/a/lib/gcc/arm-none-eabi/13.2.1/include/stdint.h")
           and language_runtime_file("/usr/lib/arm-none-eabi/include/string.h")
           and language_runtime_file("/sysroot/usr/include/string.h")
           and not language_runtime_file(wz_rs)
           and not language_runtime_file("/cargo/registry/src/i/heapless-0.8.0/src/vec.rs")
           and not language_runtime_file("/wz/p/src/include/zenoh-pico/api/types.h")
           and not language_runtime_file("/home/u/zenoh-pico/include/zenoh-pico/config.h")
           and not language_runtime_file("/wz/p/src/src/api/api.c"))

    def q8(value: int) -> bytes:
        return struct.pack("<Q", value)

    def u4(value: int) -> bytes:
        return struct.pack("<I", value)

    # DWARF 4: a unit, a namespace, functions by low_pc and high_pc, calls by both and by ranges.
    abbrev4 = (uleb(1) + uleb(0x11) + b"\x01" + uleb(0x10) + uleb(0x17) + uleb(0x11) + uleb(0x01)
               + b"\x00\x00"
               + uleb(2) + uleb(0x2E) + b"\x01" + uleb(0x11) + uleb(0x01) + uleb(0x12) + uleb(0x06)
               + b"\x00\x00"
               + uleb(3) + uleb(0x1D) + b"\x00" + uleb(0x11) + uleb(0x01) + uleb(0x12) + uleb(0x06)
               + uleb(0x58) + uleb(0x0B) + b"\x00\x00"
               + uleb(4) + uleb(0x1D) + b"\x01" + uleb(0x55) + uleb(0x17) + uleb(0x58) + uleb(0x0B)
               + b"\x00\x00"
               + uleb(5) + uleb(0x39) + b"\x01" + b"\x00\x00" + b"\x00")

    def function(low: int, size: int) -> bytes:
        return uleb(2) + q8(low) + u4(size)

    def call(low: int, size: int, file_: int) -> bytes:
        return uleb(3) + q8(low) + u4(size) + bytes([file_])

    entries4 = (uleb(1) + u4(0) + q8(0) + uleb(5)
                + function(0x1000, 0x40) + call(0x1010, 8, 1)
                + uleb(4) + u4(0) + bytes([1]) + call(0x1018, 8, 3) + b"\x00"
                + call(0x1030, 8, 1) + b"\x00"
                + function(0x1100, 0x20) + call(0x1110, 0x10, 3) + b"\x00"
                + function(0, 0x10) + call(0, 8, 1) + b"\x00"
                + b"\x00" + b"\x00")
    unit_4 = struct.pack("<HIB", 4, 0, 8) + entries4
    ranges4 = q8(2 ** 64 - 1) + q8(0x1000) + q8(0x18) + q8(0x28) + q8(0) + q8(0)
    # DWARF 5: a function by an index into .debug_addr, a call by an index into .debug_rnglists.
    abbrev5 = (uleb(1) + uleb(0x11) + b"\x01" + uleb(0x10) + uleb(0x17) + uleb(0x11) + uleb(0x01)
               + uleb(0x73) + uleb(0x17) + uleb(0x74) + uleb(0x17) + b"\x00\x00"
               + uleb(2) + uleb(0x2E) + b"\x01" + uleb(0x11) + uleb(0x1B) + uleb(0x12) + uleb(0x06)
               + b"\x00\x00"
               + uleb(3) + uleb(0x1D) + b"\x00" + uleb(0x55) + uleb(0x23) + uleb(0x58) + uleb(0x0B)
               + b"\x00\x00" + b"\x00")
    entries5 = (uleb(1) + u4(0) + q8(0) + u4(8) + u4(12)
                + uleb(2) + uleb(0) + u4(0x100) + uleb(3) + uleb(0) + b"\x00" + b"\x00" + b"\x00")
    unit_5 = struct.pack("<HBBI", 5, 1, 8, len(abbrev4)) + entries5
    addr5 = struct.pack("<IHBB", 0, 5, 8, 0) + q8(0x2000) + q8(0x2010)
    rnglists5 = (struct.pack("<IHBBI", 0, 5, 8, 0, 1) + u4(4)
                 + bytes([1]) + uleb(1) + bytes([4]) + uleb(0) + uleb(8)
                 + bytes([3]) + uleb(0) + uleb(4) + b"\x00")
    inline_tree = {".debug_info": struct.pack("<I", len(unit_4)) + unit_4
            + struct.pack("<I", len(unit_5)) + unit_5,
            ".debug_abbrev": abbrev4 + abbrev5, ".debug_ranges": ranges4,
            ".debug_addr": addr5, ".debug_rnglists": rnglists5}
    named = {0: "/wz/crates/wz-y/src/lib.rs", 1: wz_rs, 3: opt_rs}.get
    frames = code_frames(inline_tree, True, [(0x1000, 0x1200), (0x2000, 0x2100)], {0: named})
    wzy_rs = "/wz/crates/wz-y/src/lib.rs"
    expect("each function and each inlined call is read with its depth and its call's file, by "
           "high_pc, by a range list of either version and by an address index; a discarded "
           "function's frames are none",
           [(f.start, f.end, f.depth, f.call, f.origin) for f in frames]
           == [(0x1000, 0x1040, 0, None, None), (0x1010, 0x1018, 1, wz_rs, None),
               (0x1018, 0x1028, 1, wz_rs, None), (0x1018, 0x1020, 2, opt_rs, None),
               (0x1030, 0x1038, 1, wz_rs, None), (0x1100, 0x1120, 0, None, None),
               (0x1110, 0x1120, 1, opt_rs, None), (0x2000, 0x2100, 0, None, None),
               (0x2010, 0x2018, 1, wzy_rs, None), (0x2000, 0x2004, 1, wzy_rs, None)])
    bare_unit = _Unit(0, 0, 4, 5, DW_UT_COMPILE, 8, 0, 0)
    expect("an index into .debug_addr or .debug_rnglists with no base named is refused",
           _raises(lambda: _Places({}, True, bare_unit, {}).address((0x1B, 0)))
           and _raises(lambda: _Places({}, True, bare_unit, {}).ranges(
               {DW_AT_RANGES: (DW_FORM_RNGLISTX, 0)})))
    expect("the frames at an address are its chain, the innermost first, its homes the calls' "
           "files out to the function's own",
           [(start, end, frame_homes(chain)) for start, end, chain in frame_chains(frames[:7])]
           == [(0x1000, 0x1010, (None,)), (0x1010, 0x1018, (wz_rs, None)),
               (0x1018, 0x1020, (opt_rs, wz_rs, None)), (0x1020, 0x1028, (wz_rs, None)),
               (0x1028, 0x1030, (None,)), (0x1030, 0x1038, (wz_rs, None)),
               (0x1038, 0x1040, (None,)), (0x1100, 0x1110, (None,)),
               (0x1110, 0x1120, (opt_rs, None))]
           and caller_file((opt_rs, wz_rs)) == wz_rs and caller_file((opt_rs,)) is None
           and caller_file((None, wz_rs)) is None and caller_file(()) is None)
    homed = to_frames(
        [Span(0x1000, 0x1010, wz_rs), Span(0x1010, 0x1018, ptr_rs), Span(0x1018, 0x1020, ptr_rs),
         Span(0x1020, 0x1028, opt_rs), Span(0x1028, 0x1030, wz_rs), Span(0x1030, 0x1040, ptr_rs),
         Span(0x1100, 0x1110, opt_rs), Span(0x1110, 0x1120, ptr_rs), Span(0x1200, 0x1208, None)],
        frames[:7])
    expect("inlined standard library bytes go to the innermost caller outside it, a body of its "
           "own and its own inlines keep their file, and a span half inlined is split",
           [(s.start, s.end, s.source, s.inlined) for s in homed]
           == [(0x1000, 0x1010, wz_rs, None), (0x1010, 0x1020, wz_rs, ptr_rs),
               (0x1020, 0x1028, wz_rs, opt_rs), (0x1028, 0x1030, wz_rs, None),
               (0x1030, 0x1038, wz_rs, ptr_rs), (0x1038, 0x1040, ptr_rs, None),
               (0x1100, 0x1110, opt_rs, None), (0x1110, 0x1120, ptr_rs, None),
               (0x1200, 0x1208, None, None)]
           and not any(s.framed for s in homed))
    line_head = (shape + b"/wz/crates/wz-x/src\x00\x00"
                 + b"lib.rs\x00" + uleb(1) + b"\x00\x00" + ptr_rs.encode() + b"\x00" + uleb(0)
                 + b"\x00\x00" + b"\x00")
    line_program = (at(0x1000) + special(0, 0) + b"\x04\x02" + special(0x10, 1)
                    + b"\x04\x01" + special(8, 1) + b"\x02\x08" + end_sequence)
    line_body = struct.pack("<HI", 4, len(line_head)) + line_head + line_program
    read_tree = {**inline_tree, ".debug_line": struct.pack("<I", len(line_body)) + line_body}
    expect("a library's spans take the call's file from its unit's line table, and the bytes no "
           "row covers in a call no entry declares a function for go to the call's file",
           [(s.start, s.end, s.source, s.inlined, s.framed)
            for s in dwarf_spans(read_tree, True, [(0x1000, 0x1200)])]
           == [(0x1000, 0x1010, wz_rs, None, False), (0x1010, 0x1018, wz_rs, ptr_rs, False),
               (0x1018, 0x1020, wz_rs, None, False), (0x1020, 0x1028, wz_rs, None, True),
               (0x1030, 0x1038, wz_rs, None, True)])
    # A unit whose entries after its first the frame reader refuses (an unknown abbreviation).
    broken = {**dwarf, ".debug_info": struct.pack("<I", len(unit4) + 1) + unit4 + b"\x7f"
              + struct.pack("<I", len(unit5)) + unit5}
    expect("a library whose functions cannot be read is refused, not read from its lines alone, "
           "and one whose units hold no function is its line spans",
           _raises(lambda: code_frames(broken, True, [(0x1000, 0x1100)], {}))
           and _raises(lambda: dwarf_spans(broken, True, [(0x1000, 0x1100), (0x3000, 0x3100)]))
           and dwarf_spans(dwarf, True, [(0x1000, 0x1100), (0x3000, 0x3100)]) == spans)
    irules = Rules((), {"wz_x": "x", "core": "language"}, "::")
    ibodies, _ = place_bodies([Symbol(0x1000, 0x40, "_Ra", ("wz_x::f",)),
                               Symbol(0x1100, 0x20, "_Rb", ("core::option::g",))],
                              irules, ["x", "language"])
    isources = {wz_rs: ("wz_x", BY_PATH), ptr_rs: ("core::ptr", BY_PATH),
                opt_rs: ("core::option", BY_PATH)}
    ipieces, iused = attribute(ibodies, homed, isources, irules, ["x", "language"])
    iread = tally_pieces(ipieces, iused, ["x", "language"])
    unhomed, _ = attribute(ibodies, [Span(0x1000, 0x1010, wz_rs), Span(0x1010, 0x1028, ptr_rs),
                                     Span(0x1028, 0x1030, wz_rs), Span(0x1030, 0x1040, ptr_rs),
                                     Span(0x1100, 0x1120, opt_rs)],
                           isources, irules, ["x", "language"])
    expect("a wz function's inlined core is in the function's area, a core body's bytes language",
           iread.by_area == {"x": 0x38, "language": 0x28}
           and tally_pieces(unhomed, set(), ["x", "language"]).by_area
           == {"x": 0x18, "language": 0x48})
    ireport = explain_report(
        "c", "p", "cc 1", "d", ["x", "language"], {"wz": ipieces, "pico": []}, {},
        {"wz": tally(sum((list(b.names) for b in ibodies), []), irules, ["x", "language"]),
         "pico": Tally({"x": 0, "language": 0})}, {"wz": isources, "pico": {}})
    ilines = explain_lines(ireport, None)
    expect("--explain says per area how many bytes of inlined standard library code it counts",
           ireport["areas"]["x"]["wz"]["inlined"] == 0x20
           and ireport["areas"]["x"]["wz"]["inlined_bodies"] == 1
           and ireport["areas"]["language"]["wz"]["inlined"] == 0
           and "    language runtime code inlined into functions and counted here by its caller's "
               "file: wz 32 B in 1 bodies, zenoh-pico 0 B in 0 bodies" in ilines
           and "    code of no source line counted here by the file of its frame: wz 0 B in 0 "
               "bodies, zenoh-pico 0 B in 0 bodies" in ilines)

    # Code of no source line by its frame, and a C toolchain header inlined by its caller.
    api_c, helper_rs = "/wz/p/src/src/api/api.c", "/wz/crates/wz-x/src/helper.rs"
    frame_abbrev = (
        uleb(1) + uleb(0x11) + b"\x01" + uleb(0x10) + uleb(0x17) + uleb(0x11) + uleb(0x01)
        + b"\x00\x00"
        + uleb(2) + uleb(0x2E) + b"\x01" + uleb(0x11) + uleb(0x01) + uleb(0x12) + uleb(0x06)
        + uleb(0x3A) + uleb(0x0B) + b"\x00\x00"
        + uleb(3) + uleb(0x2E) + b"\x00" + uleb(0x3A) + uleb(0x0B) + b"\x00\x00"
        + uleb(4) + uleb(0x2E) + b"\x00" + uleb(0x47) + uleb(0x13) + b"\x00\x00"
        + uleb(5) + uleb(0x2E) + b"\x01" + uleb(0x11) + uleb(0x01) + uleb(0x12) + uleb(0x06)
        + uleb(0x31) + uleb(0x13) + b"\x00\x00"
        + uleb(6) + uleb(0x1D) + b"\x00" + uleb(0x11) + uleb(0x01) + uleb(0x12) + uleb(0x06)
        + uleb(0x58) + uleb(0x0B) + uleb(0x31) + uleb(0x13) + b"\x00\x00"
        + uleb(7) + uleb(0x2E) + b"\x01" + uleb(0x11) + uleb(0x01) + uleb(0x12) + uleb(0x06)
        + uleb(0x31) + uleb(0x10) + b"\x00\x00" + b"\x00")
    # A DWARF 4 unit's header is its length, its version, its abbreviations' offset and its
    # address size: 11 bytes, which a unit-relative reference counts from.
    frame_entries = bytearray(uleb(1) + u4(0) + q8(0))

    def put(entry: bytes) -> int:
        offset = 11 + len(frame_entries)
        frame_entries.extend(entry)
        return offset

    decl_wz = put(uleb(3) + bytes([2]))
    decl_helper = put(uleb(3) + bytes([4]))
    decl_opt = put(uleb(3) + bytes([3]))
    spec = put(uleb(4) + u4(decl_wz))
    put(uleb(2) + q8(0x4000) + u4(0x20) + bytes([1])
        + uleb(6) + q8(0x4008) + u4(8) + bytes([1]) + u4(decl_opt) + b"\x00")
    put(uleb(5) + q8(0x4100) + u4(0x10) + u4(spec)
        + uleb(6) + q8(0x4108) + u4(4) + bytes([2]) + u4(decl_helper) + b"\x00")
    put(uleb(7) + q8(0x4200) + u4(0x10) + u4(spec) + b"\x00")
    put(uleb(5) + q8(0x4300) + u4(0x10) + u4(decl_opt) + b"\x00")
    put(uleb(2) + q8(0x4500) + u4(0x10) + bytes([1]) + b"\x00")
    put(uleb(2) + q8(0x4600) + u4(8) + bytes([5]) + b"\x00")
    put(b"\x00")
    frame_unit = struct.pack("<HIB", 4, 0, 8) + bytes(frame_entries)
    frame_tree = {".debug_info": struct.pack("<I", len(frame_unit)) + frame_unit,
                  ".debug_abbrev": frame_abbrev}
    frame_files = {1: api_c, 2: wz_rs, 3: opt_rs, 4: helper_rs, 5: fortified}.get
    read_frames = code_frames(frame_tree, True, [(0x4000, 0x4700)], {0: frame_files})
    expect("a frame's function is declared in its own file, or in the file of the entry its "
           "abstract origin or its specification names, by a unit offset or a section offset",
           [(f.start, f.end, f.depth, f.call, f.origin) for f in read_frames]
           == [(0x4000, 0x4020, 0, None, api_c), (0x4008, 0x4010, 1, api_c, opt_rs),
               (0x4100, 0x4110, 0, None, wz_rs), (0x4108, 0x410C, 1, wz_rs, helper_rs),
               (0x4200, 0x4210, 0, None, wz_rs), (0x4300, 0x4310, 0, None, opt_rs),
               (0x4500, 0x4510, 0, None, api_c), (0x4600, 0x4608, 0, None, fortified)])
    by_frames = to_frames(
        [Span(0x4000, 0x4004, api_c), Span(0x4004, 0x4008, None), Span(0x4008, 0x400C, fortified),
         Span(0x400C, 0x4010, None), Span(0x4100, 0x4110, None), Span(0x4300, 0x4308, None),
         Span(0x4400, 0x4404, None), Span(0x4500, 0x4510, fortified),
         Span(0x4600, 0x4608, fortified)],
        read_frames)
    frame_rows = [(s.start, s.end, s.source, s.inlined, s.framed) for s in by_frames]
    expect("a byte of no source line is its innermost frame's: the function's file, an inlined "
           "function's own file, a runtime function inlined its caller's, a runtime body its own; "
           "a byte no frame holds stays unattributed",
           [row for row in frame_rows if row[3] is None and row[2] != fortified]
           == [(0x4000, 0x4004, api_c, None, False), (0x4004, 0x4008, api_c, None, True),
               (0x400C, 0x4020, api_c, None, True), (0x4100, 0x4108, wz_rs, None, True),
               (0x4108, 0x410C, helper_rs, None, True), (0x410C, 0x4110, wz_rs, None, True),
               (0x4200, 0x4210, wz_rs, None, True), (0x4300, 0x4310, opt_rs, None, True),
               (0x4400, 0x4404, None, None, False)])
    expect("a C toolchain header's code inlined into a zenoh-pico function is the function's, by "
           "the inlined call's file or, with no inline tree, the function's own; a header "
           "function's own body keeps the header",
           [row for row in frame_rows if row[3] is not None or row[2] == fortified]
           == [(0x4008, 0x400C, api_c, fortified, False),
               (0x4500, 0x4510, api_c, fortified, False),
               (0x4600, 0x4608, fortified, None, False)]
           and len(frame_rows) == 12)
    frules = Rules((), {"src": "x", TOOLCHAIN_OWNER: "language"}, "/")
    fbodies, _ = place_bodies([Symbol(0x4000, 0x20, "_z_a", ("src/api/api.c",)),
                               Symbol(0x4500, 0x10, "_z_e", ("src/api/api.c",)),
                               Symbol(0x4600, 8, "__memcpy_chk", ())], frules, ["x", "language"])
    fsources = pico_source_owners(by_frames, ("/wz/p/src",))
    fpieces, fused = attribute(fbodies, by_frames, fsources, frules, ["x", "language"])
    fread = tally_pieces(fpieces, fused, ["x", "language"])
    fx = explain_area("pico", [p for p in fpieces if piece_area(p) == "x"], {}, None)
    expect("zenoh-pico's inlined header code and its code of no line are its functions' area, "
           "and --explain counts both",
           fread.by_area == {"x": 0x30, "language": 8} and fread.unattributed_bytes == 0
           and (fx["inlined"], fx["inlined_bodies"], fx["framed"], fx["framed_bodies"])
           == (0x14, 2, 0x18, 1))

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
    yrules = Rules((), {"wz_y": "y"}, "::")
    ybodies, _ = place_bodies([Symbol(0x10, 20, "_Re", ("wz_y::s::f",)),
                               Symbol(0x40, 64, "_Rf", ("wz_y::s::g",))], yrules, ["y"])
    ypieces, _ = attribute(
        ybodies, [Span(0x10, 0x24, "/s/r.rs"), Span(0x40, 0x4C, "/s/r.rs"),
                  Span(0x4C, 0x80, "/s/s.rs")],
        {"/s/r.rs": ("wz_y::r", BY_PATH), "/s/s.rs": ("wz_y::s", BY_PATH)}, yrules, ["y"])
    ywz = explain_area("wz", [p for p in ypieces if piece_area(p) == "y"],
                       {"_Re": "wz_y::s::f", "_Rf": "wz_y::s::g"}, None)
    yrows = {row["owner"]: row for row in ywz["owners"]}
    expect("an owner split over two bodies names both by its bytes in each, largest first, and "
           "they add up to its bytes",
           [row["owner"] for row in ywz["owners"]] == ["wz_y::s", "wz_y::r"]
           and yrows["wz_y::r"] == {"owner": "wz_y::r", "bytes": 32, "bodies": 2, "largest": 20,
                                    "largest_symbol": "wz_y::s::f",
                                    "symbols": [{"symbol": "wz_y::s::f", "bytes": 20},
                                                {"symbol": "wz_y::s::g", "bytes": 12}],
                                    "symbols_rest": 0, "symbols_rest_bodies": 0}
           and list(yrows["wz_y::r"])[:4] == ["owner", "bytes", "bodies", "largest"]
           and yrows["wz_y::s"]["symbols"] == [{"symbol": "wz_y::s::g", "bytes": 52}]
           and all(sum(s["bytes"] for s in row["symbols"]) + row["symbols_rest"] == row["bytes"]
                   for row in ywz["owners"] + xwz["owners"]))
    expect("an owner's bodies inlined into another owner's body are named by that body",
           [(o["owner"], o["largest_symbol"], [s["bytes"] for s in o["symbols"]])
            for o in xwz["owners"]]
           == [("wz_x::m", "wz_x::n::big", [52, 40, 24]), ("wz_x::n", "wz_x::n::big", [48])])
    many = owner_symbols({i: i + 1 for i in range(EXPLAIN_OWNER_SYMBOLS + 1)},
                         {i: f"s{i:03d}" for i in range(EXPLAIN_OWNER_SYMBOLS + 1)})
    expect("an owner's row names its largest bodies up to the limit and sums the rest",
           owner_symbols({0x10: 7, 0x20: 30, 0x30: 12, 0x40: 7},
                         {0x10: "c", 0x20: "a", 0x30: "b", 0x40: "d"}, 2)
           == {"largest_symbol": "a", "symbols": [{"symbol": "a", "bytes": 30},
                                                  {"symbol": "b", "bytes": 12}],
               "symbols_rest": 14, "symbols_rest_bodies": 2}
           and owner_symbols({0x10: 5, 0x20: 5}, {0x10: "z", 0x20: "y"})["symbols"]
           == [{"symbol": "y", "bytes": 5}, {"symbol": "z", "bytes": 5}]
           and len(many["symbols"]) == EXPLAIN_OWNER_SYMBOLS
           and many["symbols"][0] == {"symbol": f"s{EXPLAIN_OWNER_SYMBOLS:03d}",
                                      "bytes": EXPLAIN_OWNER_SYMBOLS + 1}
           and (many["symbols_rest"], many["symbols_rest_bodies"]) == (1, 1))
    expect("the tables print each owner's largest bodies and what its other bodies hold",
           explain_owner_bodies("t", ywz["owners"], 2, 1)
           == ["    t, the largest 1 bodies of each of the largest 2 of 2:",
               "      wz_y::s: 52 B in 1 bodies", "            52  wz_y::s::g",
               "      wz_y::r: 32 B in 2 bodies", "            20  wz_y::s::f",
               "            12  in 1 other bodies"]
           and explain_owner_bodies("t", ywz["owners"], 1)
           == ["    t, the largest 3 bodies of each of the largest 1 of 2:",
               "      wz_y::s: 52 B in 1 bodies", "            52  wz_y::s::g"]
           and explain_owner_bodies("t", [], 2) == ["    t: none"])
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
    expect("a zenoh-pico file's row names the functions that hold its bytes",
           [(o["largest_symbol"], o["symbols"]) for o in xpico["owners"]]
           == [("_z_a", [{"symbol": "_z_a", "bytes": 30}]),
               ("_z_b", [{"symbol": "_z_b", "bytes": 12}])])
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
           and "    wz modules by the bodies that hold their bytes, the largest "
               f"{EXPLAIN_OWNER_SYMBOLS_SHOWN} bodies of each of the largest 2 of 2:" in xlines
           and "      wz_x::m: 116 B in 3 bodies" in xlines
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

    # --per-feature: the chain, the bytes of a step, and the report.
    graph = {"a": [], "b": ["a"], "c": [], "d": ["c"], "x": []}

    def turned_on(features: list[str]) -> set[str]:
        return wz_config.enabled_features(graph, features)

    expect("a chain adds each feature of the case in its order, past what is already on",
           feature_steps(["a"], ["b", "a", "d", "c"], turned_on)
           == ([("b", ["a", "b"]), ("d", ["a", "b", "d"])], [])
           and feature_steps(["a", "x"], ["b"], turned_on) == ([("b", ["a", "x", "b"])], ["x"])
           and feature_steps(["a"], ["a"], turned_on) == ([], []))
    counted_side = Tally({"x": 5, "y": 0}, total=12, unclassified=[(4, ("o",))],
                         unattributed=[(3, ("n",))])
    expect("a side's bytes by area, with the unclassified and the unattributed apart, are its text",
           side_bytes(counted_side, ["x", "y"])
           == {"x": 5, "y": 0, UNCLASSIFIED_AREA: 4, UNATTRIBUTED_AREA: 3}
           and sum(side_bytes(counted_side, ["x", "y"]).values()) == counted_side.total)
    expect("a step's switches are those it set otherwise than the step before it",
           switch_moves({"Z_A": 0, "Z_B": 1}, {"Z_A": 1, "Z_B": 1}) == ["Z_A 0->1"]
           and switch_moves({"Z_A": 1}, {"Z_A": 1}) == [])

    def bytes_of(x: int, y: int, unplaced: int = 0) -> dict[str, int]:
        return {"x": x, "y": y, UNCLASSIFIED_AREA: unplaced, UNATTRIBUTED_AREA: 0}

    chain = [Step(None, ("a",), (), {"Z_A": 0}, bytes_of(10, 5), bytes_of(8, 5)),
             Step("b", ("a", "b"), ("c",), {"Z_A": 1}, bytes_of(30, 5, 2), bytes_of(12, 6)),
             Step("d", ("a", "b", "d"), (), {"Z_A": 1}, bytes_of(31, 5, 2), bytes_of(12, 6))]
    pf_report = per_feature_report("t", "base", "p", "cc 1", "2026-11-27", [], chain)
    expect("a step adds its bytes over the step before it, on each side and area by area",
           [s["feature"] for s in pf_report["steps"]] == ["b", "d"]
           and pf_report["steps"][0]["wz_added"] == bytes_of(20, 0, 2)
           and pf_report["steps"][0]["pico_added"] == bytes_of(4, 1)
           and pf_report["steps"][0]["excess"] == bytes_of(16, -1, 2)
           and pf_report["steps"][0]["switches"] == ["Z_A 0->1"]
           and pf_report["steps"][1]["switches"] == []
           and json.loads(json.dumps(pf_report)) == pf_report)
    pf_lines = per_feature_lines(pf_report, ["x", "y"])
    ranked_at = next((i for i, line in enumerate(pf_lines) if line.endswith("most first:")), -2)
    expect("the chain is printed step by step and its features most expensive first",
           "  size-ledger per-feature: t: step 1 +b, which turns on c (zenoh-pico Z_A 0->1): "
           "wz +22 B, zenoh-pico +5 B, wz - zenoh-pico +17 B" in pf_lines
           and any(line.startswith("  size-ledger per-feature: t: step 2 +d (zenoh-pico built "
                                   "as before") for line in pf_lines)
           and pf_lines[ranked_at + 2].split()[0] == "b"
           and pf_lines[ranked_at + 2].endswith("x +16, (unclassified) +2")
           and pf_lines[ranked_at + 3].split()[0] == "d"
           and pf_lines[-1].endswith("15 against 13 (1.1538) at base, 38 against 18 (2.1111) "
                                     "after the last step"))

    print(f"  size-ledger selftest: {ok}/{ok + bad} arm(s) pass")
    return 0 if bad == 0 else 1


def main(argv: list[str]) -> int:
    modes = ("--check", "--measure", "--explain", "--per-feature", "--selftest")
    if len(argv) < 2 or argv[1] not in modes or (argv[1] == "--selftest" and len(argv) != 2):
        print(__doc__, file=sys.stderr)
        return 2
    if argv[1] == "--selftest":
        return cmd_selftest()
    parser = argparse.ArgumentParser(prog=f"size_ledger_gate.py {argv[1]}", add_help=False)
    parser.add_argument("--shards", type=int)
    parser.add_argument("--shard", type=int)
    parser.add_argument("ids", nargs="*")
    try:
        args = parser.parse_intermixed_args(argv[2:])
    except SystemExit:
        return 2
    shard = None
    if args.shards is not None or args.shard is not None:
        if argv[1] == "--per-feature":
            print("  size-ledger: --per-feature reads its chains on one host, not on a shard",
                  file=sys.stderr)
            return 2
        if args.shards is None or args.shard is None or not 0 <= args.shard < args.shards:
            print("  size-ledger: give --shards N and --shard K with 0 <= K < N", file=sys.stderr)
            return 2
        shard = (args.shards, args.shard)
    sys.stdout.reconfigure(line_buffering=True)
    if argv[1] == "--per-feature":
        return cmd_per_feature(args.ids)
    return cmd_run(mode=argv[1][2:], shard=shard, only=args.ids)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
