#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2300 (no register item) — EVERY wz-OWN DOOR OF `wz-capi-c` IS DECLARED IN
ITS HEADER, DERIVED, in both directions.

Answers part (다) of item 631 of the unregistered register, which lives OUTSIDE
this repository -- the reason the citation above reads "no register item", the
same position `capi_c_config_surface.py` records for 548 and
`analysis_surface_config_free.py` for 564. The item is named in full below so a
reader grepping for it lands here.

## The item, and why a header needed a gate rather than just writing one

The consumer asked for a header because `git ls-files crates/wz-capi-c` listed
ZERO `.h` files while the crate exported doors they were told to call. Writing
one closes that. It does NOT stay closed: a header is a hand-maintained second
spelling of a symbol list, and the failure mode is silent in the direction that
matters -- a door added in Rust and forgotten here is invisible to every
compiler, because nothing in this tree compiles a C program against this file.
The consumer would discover it as a missing declaration months later, which is
the position they were already in.

So the correspondence is DERIVED from both sides and compared:

  EXPORTED   `#[no_mangle] pub extern "C" fn wz_capi_c_*` across the crate's
             tracked sources. This is what the artifact actually publishes.
  DECLARED   identifiers of that shape appearing in a DECLARATION in the
             header -- read from the C, not from a list here.

Both differences are errors, and they are different errors:

  * EXPORTED - DECLARED is a door a consumer cannot call without writing their
    own `extern`, which is the copy this header exists to remove.
  * DECLARED - EXPORTED is a declaration for a symbol the library does not
    have. That one links, and then fails at load time or -- worse, with lazy
    binding -- at the first call.

## Why only the wz_capi_c_ prefix

The crate's OTHER surface is upstream zenoh-c's: every `z_*` / `zc_*` / `ze_*`
symbol is a drop-in, and upstream's own `zenoh.h` is what declares those. A
second declaration of a drop-in symbol is a second place for the ABI to drift,
which is the whole failure a drop-in exists to avoid, so this header must NOT
redeclare them and this gate must not ask it to. The prefix is what separates
the two surfaces, and it is read from the header's own include guard rather
than chosen here -- see `prefix_of`.

## Both populations must be non-empty

A regex that stopped matching would report perfect correspondence between two
empty sets. Zero exports means the scanner has stopped seeing `#[no_mangle]`;
zero declarations means it has stopped reading the header. Either is a dead
probe reporting the same green as a healthy tree.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

# R2766 (open debt 788) — EVERY C SURFACE, not one.
#
# This gate was written for `wz-capi-c` and its crate and header were
# CONSTANTS, so the identical question went unasked of the other C surface
# this repository publishes. It went unanswered too: a door was added to
# `wz-capi-dissect`, its `extern "C"` compiled, its symbol linked, every lane
# passed, and the header never declared it. A CONSUMER reported that, which
# is the reading that matters -- the predicate existed one crate over and
# nothing applied it here.
#
# A table rather than a second copy of this file: a new C surface is a row,
# and the cost of forgetting the row is that its doors are ungraded, which is
# the same failure one level up. The prefix is DERIVED from each header's
# include guard (see `prefix_of`), so a row states only where to look.
SURFACES = (
    ROOT / "crates" / "wz-capi-c" / "include" / "wz_capi_c.h",
    ROOT / "crates" / "wz-capi-dissect" / "include" / "wz_dissect.h",
)


class Fatal(Exception):
    """A derivation that cannot be made. Never a silent pass."""


def tracked(*globs: str) -> list[pathlib.Path]:
    """Tracked files, so an untracked scratch file can neither satisfy a claim
    nor raise one."""
    out = subprocess.run(
        ["git", "ls-files", "-z", *globs],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [ROOT / p for p in out.split("\0") if p]


def prefix_of(header_text: str, where: str = "the header") -> str:
    """The symbol prefix this header owns, read from its own include guard.

    `WZ_CAPI_C_H` gives `wz_capi_c_`. Taken from the file rather than written
    here so a renamed crate cannot leave this gate aimed at a prefix nothing
    uses -- which would match no symbols and report an empty set as agreement.
    """
    m = re.search(r"^#ifndef\s+([A-Z0-9_]+)_H\s*$", header_text, re.M)
    if m is None:
        raise Fatal(
            f"{where} has no `#ifndef <NAME>_H` guard, so the "
            "prefix this gate compares on cannot be derived. A hardcoded prefix "
            "would match nothing after a rename and report agreement."
        )
    return m.group(1).lower() + "_"


def src_of(header: pathlib.Path) -> str:
    """The tracked source tree whose doors that header declares.

    The crate is the header's own grandparent -- `<crate>/include/<h>.h` -- so
    a SURFACES row states one path and this derives the rest from it.

    R2773 (open debt, hosted red 35558290992) -- extracted so that it has ONE
    definition. R2766 widened `exported` from `(prefix)` to `(prefix, src)` and
    computed this inline at the single call site it could see; `capi_c_abi_pin`
    imports `exported` from here and was still calling it with one argument, so
    Layer C1ch died in a TypeError rather than grading. A second caller needs a
    second copy of this line or a name to call, and a second copy is how the
    two drift apart again.
    """
    return str((header.parent.parent / "src").relative_to(ROOT))


def surface_for(prefix: str) -> pathlib.Path:
    """The SURFACES row that owns `prefix`, by each header's own guard.

    Fatal when none matches rather than returning None: a caller that asked
    for a prefix this tree does not publish has asked the wrong question, and
    an empty answer downstream reads as agreement.
    """
    for header in SURFACES:
        if not header.is_file():
            continue
        if prefix_of(header.read_text(errors="replace"), str(header)) == prefix:
            return header
    raise Fatal(
        f"no C surface in SURFACES owns the prefix `{prefix}`. Either the row "
        "is missing or the header's include guard was renamed; both leave the "
        "caller grading nothing."
    )


def exported(prefix: str, src: str) -> set[str]:
    """Every wz-own symbol the crate publishes.

    `#[no_mangle]` is required on the same item, because that is what makes the
    Rust name the EXPORTED name; a `pub extern "C" fn` without it is mangled and
    no C caller can reach it under this spelling.

    R2766 (open debt 788) — `src` is a PARAMETER now. It was the one crate this
    gate was written for, spelled as a constant, and that constant is why the
    other C surface went ungraded while its header lost a door.
    """
    names: set[str] = set()
    # A DIRECTORY pathspec, which `git ls-files` recurses. A `**/*.rs` glob is
    # NOT the same thing here -- git's pathspec matching left it empty, and an
    # empty file list is what the non-empty check below exists to catch.
    for path in tracked(src):
        if path.suffix != ".rs":
            continue
        text = path.read_text(errors="replace")
        for m in re.finditer(
            r"#\[no_mangle\]\s*(?:#\[[^\]]*\]\s*)*"
            r"pub\s+(?:unsafe\s+)?extern\s+\"C\"\s+fn\s+([A-Za-z0-9_]+)",
            text,
        ):
            if m.group(1).startswith(prefix):
                names.add(m.group(1))
    return names


def declared(header_text: str, prefix: str) -> set[str]:
    """Every wz-own symbol the header DECLARES.

    A declaration is an identifier followed by `(` and terminated by `;` before
    any `{` -- so a mention inside a comment or a name used in prose is not
    counted. Comments are stripped first for that reason: this header explains
    its doors at length and names them while doing so.
    """
    stripped = re.sub(r"/\*.*?\*/", " ", header_text, flags=re.S)
    stripped = re.sub(r"//[^\n]*", " ", stripped)
    names: set[str] = set()
    for m in re.finditer(rf"\b({re.escape(prefix)}[A-Za-z0-9_]*)\s*\(", stripped):
        tail = stripped[m.end() :]
        end = tail.find(";")
        brace = tail.find("{")
        if end != -1 and (brace == -1 or end < brace):
            names.add(m.group(1))
    return names


def run() -> int:
    rc = 0
    graded = 0
    for header in SURFACES:
        rc |= run_one(header)
        graded += 1
    if rc == 0:
        print(f"capi-c-wz-door-header: {graded} C surface(s) graded, both ways")
    return rc


def run_one(HEADER: pathlib.Path) -> int:
    if not HEADER.is_file():
        print(
            f"capi-c-wz-door-header: FAIL -- {HEADER.relative_to(ROOT)} is "
            "missing. Item 631 (다) is what put it there; deleting it puts a "
            "consumer back to writing its own externs.",
            file=sys.stderr,
        )
        return 1

    header_text = HEADER.read_text(errors="replace")
    prefix = prefix_of(header_text, str(HEADER.relative_to(ROOT)))
    have = exported(prefix, src_of(HEADER))
    said = declared(header_text, prefix)

    findings: list[str] = []
    if not have:
        findings.append(
            f"no `{prefix}*` door found in the crate's tracked sources. The "
            "scanner has stopped seeing `#[no_mangle] pub extern \"C\" fn`, so "
            "its agreement with the header means nothing."
        )
    if not said:
        findings.append(
            f"no `{prefix}*` declaration found in {HEADER.relative_to(ROOT)}. "
            "The header reader has stopped working, on the same argument."
        )
    for name in sorted(have - said):
        findings.append(
            f"{name} is EXPORTED but not declared. A consumer calling it has to "
            "write its own extern, which is the copy this header removes."
        )
    for name in sorted(said - have):
        findings.append(
            f"{name} is DECLARED but not exported. That links and then fails at "
            "load, or at the first call under lazy binding."
        )

    if findings:
        print("capi-c-wz-door-header: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        return 1

    print(
        f"capi-c-wz-door-header: OK -- {len(have)} `{prefix}*` door(s), each "
        f"declared in {HEADER.relative_to(ROOT)} and no declaration without one"
    )
    return 0


def selftest() -> int:
    """Drive both directions against text the real files cannot produce.

    The fixture is what the OLD state looked like -- a door with no declaration
    -- plus its mirror, because a gate checked only in the direction its author
    was thinking about is checked in one direction.
    """
    header = """
#ifndef WZ_CAPI_C_H
#define WZ_CAPI_C_H
/* wz_capi_c_in_a_comment_only(size_t) is mentioned here and not declared. */
size_t wz_capi_c_declared_and_exported(void);
size_t wz_capi_c_declared_only(void);
#endif
"""
    prefix = prefix_of(header)
    if prefix != "wz_capi_c_":
        print(f"selftest: prefix_of gave {prefix!r}", file=sys.stderr)
        return 1
    said = declared(header, prefix)
    if said != {"wz_capi_c_declared_and_exported", "wz_capi_c_declared_only"}:
        print(f"selftest: declared() gave {said!r}", file=sys.stderr)
        return 1

    # A body, not a declaration: the `{` arrives before any `;`.
    body = "#ifndef WZ_X_H\nsize_t wz_x_inline(void) { return 0; }\n#endif\n"
    if declared(body, "wz_x_"):
        print("selftest: a function BODY was read as a declaration", file=sys.stderr)
        return 1

    # And the guard requirement, which is what keeps the prefix derived.
    try:
        prefix_of("size_t wz_capi_c_thing(void);\n")
    except Fatal:
        pass
    else:
        print("selftest: a header with no guard was accepted", file=sys.stderr)
        return 1

    print("capi-c-wz-door-header: selftest OK")
    return 0


if __name__ == "__main__":
    try:
        if "--selftest" in sys.argv[1:]:
            sys.exit(selftest())
        sys.exit(run())
    except Fatal as e:
        print(f"capi-c-wz-door-header: FAIL -- {e}", file=sys.stderr)
        sys.exit(1)
