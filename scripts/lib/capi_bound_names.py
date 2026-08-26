#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2120 (no register item) — a PARAMETER NAME that promises a bound has to
say which bound, and the header has to be held to it.

Closes item 467 of the unregistered register, which lives outside this
repository -- hence the citation above, the same way `capi_header_subsumption.py`
does for item 466 and `cdylib_soname_gate.py` for item 521.

## The gap

`wz_dissect_pcap_fields(bytes, len, max_messages_per_flow, out)` reads like a
ceiling and is not one: it trims the OUTPUT after the whole dissection has
already been built, so a caller asking for ten messages still pays for the
file. Item 450 recorded that, R311y933 made the BEHAVIOUR checkable -- the two
arguments leave different marks on the document -- and left the NAME alone,
because renaming it was believed to break a published signature.

That belief was false and item 467 is what it cost. C has no named arguments:
a prototype's parameter name is DOCUMENTATION, not ABI. `nm -D` sees a symbol,
`wz_dissect_abi_version()` returns a number, and neither moves when a
parameter is renamed -- which `capi_abi_pin.py` is the standing proof of, since
it pins both halves and reads neither name. So the rename was always free, and
the misleading name survived a round that had already diagnosed it.

## Why the item's own scope was too small

Item 467 named ONE parameter. Deriving the population from the header rather
than from the item found EIGHT bound-shaped parameters across SEVEN doors, in
THREE disciplines that a reader cannot tell apart by looking:

  * `trims-output`    -- the whole walk is paid for and the DOCUMENT is
                         shortened afterwards; each flow reports `shown` and
                         `omitted`.
  * `work-ceiling`    -- the walk itself is bounded, and what it dropped is
                         reported in `dropped_by_limits`.
  * `buffer-capacity` -- how much room the CALLER's buffer has. The library
                         imposes nothing; `written` says how much was used.

`wz_dissect_live_drain(h, out, cap, written)` is the one the item did not
reach. `cap` reads exactly like a ceiling on the work and is a statement about
the caller's own array.

## What the header must carry, and why a FORM rather than prose

Prose is what item 450 already cost a round for, and R2116 answered that class
by giving the sentence a checkable form. The same shape here: inside the
comment block that precedes a door's own declaration, each bound-shaped
parameter carries

    @bound <parameter> <discipline>

and the discipline is one of the three words above. The name is then held to
the discipline in the direction that misleads:

  * `trims-output` MUST carry the `shown` token. This is item 467 itself: a
    parameter that only shortens the output has to say so, because the reader
    who believes it is a ceiling sizes a live tap by it.
  * `work-ceiling` MUST NOT carry `shown`. It really does bound the walk, and
    saying "shown" would understate it in the other direction.
  * `buffer-capacity` MUST NOT carry `shown` and MUST NOT carry `max`: a
    caller's own array size is not a maximum this library imposes.

## Where the population comes from

Not from a hand-written list of doors -- that is the mistake R2119 paid for in
both directions on a list of keys, and the mistake `cdylib_soname_gate.py`
exists because of. The declarations are parsed out of the published header and
then CERTIFIED BY A REAL C COMPILER: `gcc -aux-info` re-emits every prototype
it parsed, with its return type and its full parameter type list, and this gate
refuses to run unless its own extraction agrees with GCC's, function for
function and type for type. GCC discards parameter NAMES, which is the one
thing wanted here -- so the names are read from a declaration whose boundaries
and arity a compiler has already confirmed, rather than from a regex trusted on
its own word.

A population of zero is a FAIL and never a quiet pass: an absent compiler, an
unreadable header and a header that genuinely declares nothing are the same
exit code otherwise, and this workspace's most expensive recurring defect is a
gate that reports green over an empty population.

## The four ways this reds

  * a bound-shaped parameter with no `@bound` line in its own door's span --
    the reader is not told which of the three it is;
  * an `@bound` line naming a parameter that door does not declare -- a line
    left behind by a signature edit, which is worse than none because it reads
    as current;
  * a discipline whose name marker does not match -- item 467's own defect;
  * an `@bound` line outside every door's span -- a statement that pins
    nothing, refused for the same reason R2116 refuses a floating subsumption
    marker.

## What this deliberately does NOT check

Whether a parameter's declared discipline is TRUE OF THE CODE. That is a claim
about behaviour and it is held by behaviour, in
`wz-capi-dissect`'s `the_cap_and_the_preset_leave_different_marks` test
(R311y933, item 450): the cap shortens the listing and leaves
`dropped_by_limits` alone, the preset moves that group. This gate holds the
NAME to the declared discipline; that test holds the declared discipline to the
library. Stated rather than hidden, because a gate that implied it had checked
the behaviour would be the same false comfort the name itself was.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]

# The published header, overridable so a damage probe can point at a fixture --
# the same affordance `debt_plane_census.py` carries for its register. The
# FAIL paths of a gate are the half nobody exercises, and a fixture is how they
# stop being taken on trust.
HEADER = pathlib.Path(
    os.environ.get(
        "WZ_CAPI_HEADER",
        ROOT / "crates" / "wz-capi-dissect" / "include" / "wz_dissect.h",
    )
)

# A door's own declaration, at column zero, which is how every entry point in
# this header is written. Every return type the header actually uses -- read
# off GCC's re-emission, not guessed.
DECL = re.compile(
    r"^(?:int|void|size_t|uint64_t) (wz_dissect_[a-z_0-9]+)\(", re.M
)

# The one spelling. A form rather than a sentence, so a reader writes the prose
# and the gate reads the fact out of it.
MARKER = re.compile(r"@bound\s+([a-z_0-9]+)\s+([a-z-]+)")

DISCIPLINES = ("trims-output", "work-ceiling", "buffer-capacity")

# A name is BOUND-SHAPED when one of its `_`-separated tokens is one of these.
# Token-wise and not substring-wise on purpose: `len` is not a bound and
# `capture_reread` must not be read as `cap`.
BOUND_TOKENS = frozenset({"max", "limit", "limits", "cap", "bound", "ceiling"})


def fail(message: str) -> None:
    print(f"capi-bound-names: FAIL -- {message}", file=sys.stderr)
    sys.exit(1)


def gcc_prototypes() -> dict[str, list[str]]:
    """Every function the header declares, as GCC parsed it.

    `-aux-info` re-emits a declaration for each function the translation unit
    saw, with its full parameter TYPE list and no parameter names. That is
    precisely the half this gate cannot supply for itself: it certifies the
    extraction below without answering the question being asked.
    """
    compiler = shutil.which("gcc") or shutil.which("cc")
    if compiler is None:
        fail(
            "no C compiler on PATH, so the header's declarations cannot be "
            "certified by a real parser. This gate does not fall back to its "
            "own regex: an uncertified parse is the thing it exists to avoid."
        )
    with tempfile.TemporaryDirectory() as tmp:
        src = pathlib.Path(tmp) / "probe.c"
        info = pathlib.Path(tmp) / "probe.info"
        # By NAME, resolved through -I, so a fixture the override points at is
        # compiled exactly the way the published header is.
        src.write_text(f'#include "{HEADER.name}"\n')
        run = subprocess.run(
            [
                compiler,
                "-aux-info",
                str(info),
                "-c",
                "-o",
                "/dev/null",
                "-I",
                str(HEADER.parent),
                str(src),
            ],
            capture_output=True,
            text=True,
        )
        if run.returncode != 0:
            fail(
                f"the header did not compile, so nothing can be read out of "
                f"it:\n{run.stderr.strip()}"
            )
        if not info.exists():
            fail(
                f"{compiler} accepted -aux-info but wrote no file. That flag "
                f"is GCC's; a compiler that ignores it leaves this gate with "
                f"no certifier, which is a FAIL and not a skip."
            )
        emitted = info.read_text()

    protos: dict[str, list[str]] = {}
    for line in emitted.splitlines():
        m = re.search(r"\b(wz_dissect_[a-z_0-9]+) \((.*)\);\s*$", line)
        if m:
            args = m.group(2).strip()
            protos[m.group(1)] = (
                [] if args == "void" else [a.strip() for a in args.split(",")]
            )
    return protos


def normalise(param_type: str) -> str:
    """A parameter's type, spelled the way GCC re-emits it.

    GCC writes `const unsigned char *` and `char **`; the header writes the
    same tokens with the identifier attached. Collapsing whitespace and
    normalising the `*` spacing is what lets the two be compared literally --
    and a mismatch is a FAIL, so this is deliberately not lenient.
    """
    text = re.sub(r"\s+", " ", param_type).strip()
    text = re.sub(r"\s*\*", " *", text)
    return re.sub(r"\s+", " ", text).strip()


def declarations(text: str) -> list[tuple[str, list[tuple[str, str]], int, int]]:
    """Each door: (symbol, [(type, name)], span_start, span_end).

    The span runs from the end of the PREVIOUS declaration to the end of this
    one, which is exactly the comment block a reader has in front of them when
    they read about that symbol -- the same delimitation R2116 settled on.
    """
    out: list[tuple[str, list[tuple[str, str]], int, int]] = []
    previous = 0
    for m in DECL.finditer(text):
        end = text.find(";", m.end())
        if end < 0:
            fail(f"{m.group(1)}'s declaration is never terminated")
        params: list[tuple[str, str]] = []
        args = text[text.index("(", m.start()) + 1 : text.rindex(")", m.start(), end)]
        if normalise(args) != "void":
            for raw in args.split(","):
                piece = normalise(raw)
                name = re.search(r"([a-z_][a-z_0-9]*)$", piece)
                if name is None:
                    fail(
                        f"{m.group(1)}'s parameter {piece!r} is declared "
                        f"without a name. The name is the documentation this "
                        f"gate reads; an unnamed parameter tells the reader "
                        f"nothing and cannot be held to a discipline."
                    )
                params.append((normalise(piece[: name.start()]), name.group(1)))
        out.append((m.group(1), params, previous, end))
        previous = end
    return out


def bound_shaped(name: str) -> bool:
    return bool(BOUND_TOKENS & set(name.split("_")))


def main() -> int:
    if not HEADER.exists():
        fail(f"the published header is absent at {HEADER}")
    text = HEADER.read_text()

    protos = gcc_prototypes()
    if not protos:
        fail(
            "GCC parsed the header and re-emitted no declaration at all. A "
            "population of zero is not a clean bill: it is a dead probe "
            "wearing one."
        )

    doors = declarations(text)
    if not doors:
        fail(
            "this gate's own extraction found no declaration in a header GCC "
            f"says declares {len(protos)}. The extraction is broken, not the "
            f"header."
        )

    # CERTIFICATION. Every door GCC saw, this gate must have seen, with the
    # same arity and the same types. A regex that silently mis-split a
    # declaration would otherwise go on to read names out of the wrong bytes.
    mine = {symbol: params for symbol, params, _, _ in doors}
    if set(mine) != set(protos):
        fail(
            "this gate and GCC disagree about WHICH functions the header "
            f"declares. Only GCC saw: {sorted(set(protos) - set(mine))}. Only "
            f"this gate saw: {sorted(set(mine) - set(protos))}."
        )
    for symbol, params in sorted(mine.items()):
        theirs = [normalise(t) for t in protos[symbol]]
        ours = [t for t, _ in params]
        if ours != theirs:
            fail(
                f"this gate and GCC disagree about {symbol}'s parameters. "
                f"GCC parsed {theirs}; this gate extracted {ours}. The names "
                f"are not read from an uncertified parse."
            )

    population = [
        (symbol, name)
        for symbol, params, _, _ in doors
        for _, name in params
        if bound_shaped(name)
    ]
    if not population:
        fail(
            f"GCC certified {len(doors)} declarations and not one of them has "
            f"a bound-shaped parameter. That is either a header that no "
            f"longer bounds anything or a token list that has stopped "
            f"matching -- and it must not be reported as compliance."
        )

    problems: list[str] = []
    claimed: set[tuple[int, int]] = set()

    for symbol, params, start, end in doors:
        span = text[start:end]
        names = {name for _, name in params}
        declared: dict[str, str] = {}
        for m in MARKER.finditer(span):
            claimed.add((start + m.start(), start + m.end()))
            parameter, discipline = m.group(1), m.group(2)
            if discipline not in DISCIPLINES:
                problems.append(
                    f"{symbol}: `@bound {parameter} {discipline}` names no "
                    f"known discipline. One of {', '.join(DISCIPLINES)}."
                )
                continue
            if parameter not in names:
                problems.append(
                    f"{symbol}: `@bound {parameter}` names a parameter this "
                    f"door does not declare (it takes "
                    f"{', '.join(sorted(names)) or 'nothing'}). A line left "
                    f"behind by a signature edit reads as current."
                )
                continue
            declared[parameter] = discipline

        for name in sorted(names):
            if not bound_shaped(name):
                continue
            discipline = declared.get(name)
            if discipline is None:
                problems.append(
                    f"{symbol}: `{name}` reads like a bound and the header "
                    f"never says which kind. Add `@bound {name} <"
                    f"{'|'.join(DISCIPLINES)}>` to its comment block."
                )
                continue
            tokens = set(name.split("_"))
            if discipline == "trims-output" and "shown" not in tokens:
                problems.append(
                    f"{symbol}: `{name}` is declared `trims-output` -- the "
                    f"whole walk is paid for and only the document is "
                    f"shortened -- but the name does not say `shown`. This is "
                    f"open-debt item 467 exactly: a reader sizes a live tap "
                    f"by a name that promises a ceiling it does not enforce."
                )
            if discipline == "work-ceiling" and "shown" in tokens:
                problems.append(
                    f"{symbol}: `{name}` is declared `work-ceiling` but says "
                    f"`shown`, which understates it -- this one really does "
                    f"bound the walk."
                )
            if discipline == "buffer-capacity" and (
                "shown" in tokens or "max" in tokens
            ):
                problems.append(
                    f"{symbol}: `{name}` is declared `buffer-capacity` -- the "
                    f"caller's own array -- but its name claims a maximum "
                    f"this library imposes."
                )

    for m in MARKER.finditer(text):
        if (m.start(), m.end()) not in claimed:
            line = text.count("\n", 0, m.start()) + 1
            problems.append(
                f"{HEADER.name}:{line}: `{m.group(0)}` sits outside every "
                f"door's comment block, so it pins nothing. A bound a reader "
                f"can only find by searching is the state item 467 began in."
            )

    if problems:
        print(
            f"capi-bound-names: FAIL -- {len(problems)} problem(s) over "
            f"{len(population)} bound-shaped parameter(s) in {len(doors)} "
            f"GCC-certified declaration(s):",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    print(
        f"capi-bound-names: {len(population)} bound-shaped parameter(s) over "
        f"{len(doors)} GCC-certified declaration(s), each declared and each "
        f"named for its discipline."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
