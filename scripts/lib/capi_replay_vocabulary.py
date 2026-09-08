#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

r"""R2441 (no register item) — the replay ABI names what wz-replay says.

The citation is `no register item` for `debt_plane_census.py`'s reason: the item
this gate answers for -- unregistered open-debt item 693 -- lives in the
agent-memory register outside this repository and has no `debt-` row in the
store, so there is no id here that would resolve. That absence is itself item
454. The round is `Round 2441` in the atomic ledger.

## The defect this gate is for

`wz-capi-replay` exists because a judgement `wz-replay` had already made could
not be CALLED by a consumer that links C, so the consumer made it a second
time. The door closes that. Nothing yet stops it reopening one variant at a
time, and the reopening is silent in a way the compiler cannot see:

  * RUST -> ABI is held by the compiler. `wz-capi-replay` maps every enum with
    an exhaustive `match`, so a variant added upstream stops that crate
    building. Nothing needs to be checked here.
  * ABI -> HEADER is held by NOTHING. A `#define` is text in a file no Rust
    build reads. Add a constant to `wz-capi-replay` and leave `wz_replay.h`
    alone and the tree compiles, links, passes every ABI test, and ships a
    header telling a C consumer that a value they WILL receive does not exist.

`wz-capi-dissect` paid for that exact shape once: two prose lists of the
`payload_decode` states both said "one of five" for the whole round in which a
sixth was added. This is the same gate, one crate over, before the first miss
rather than after it.

## The two populations, and both are DERIVED

Neither is a list anyone wrote down here, because a list written down here is
a list that goes stale in the direction of passing.

**P1 — every variant of every `pub enum` in wz-replay's PLAN half.** The plan
half is derived too: `src/lib.rs` plus every `pub mod` it declares WITHOUT a
`#[cfg(feature = "live")]` above it. So a future enum in `alert.rs` is in this
population by construction, and `live.rs` is out of it for the same reason the
ABI does not link the session runtime.

Each enum must carry a `WZ-ABI-MIRRORS: <Enum> -> <PREFIX>` line in the header
naming its constant prefix, and each variant must have `<PREFIX><SCREAMING>`
defined. There is no exemption clause: an enum the ABI genuinely should not
mirror has to be argued for by editing this rule, which is the point --
`Timing`, `TimingSource`, `Mutation` and `ScheduleError` are all four of them
today, so the rule costs nothing to keep absolute and a fifth enum arriving
would be a decision somebody makes rather than one that happens.

**P2 — the CONSTANT SETS, which must be equal.** Every `pub const WZ_REPLAY_*`
in `wz-capi-replay/src/lib.rs` must be `#define`d in the header, and every
`#define WZ_REPLAY_*` in the header must be a `pub const` in that file. This is
the half that catches the dissect defect directly, and it needs no prefix
declaration in either direction.

One constant is answered by a FUNCTION rather than a `#define`, and it is
recognised structurally rather than listed: a constant whose lowercased name is
an exported function in the header (`WZ_REPLAY_ABI_VERSION` /
`wz_replay_abi_version`) is one a consumer must ASK the artifact for. Baking a
revision into a header is precisely what that function exists to prevent, so it
is not an exemption -- it is the rule that the header must not answer it.

## Why not parse Rust properly

A `syn`-grade parse is not available to a python gate and is not needed: the
shapes read here are `pub enum X {`, a variant line, `pub const NAME`, `#define
NAME` and `type_name function(`. Every one of them is refused by name when it
does not match, and an EMPTY population is a FAILURE rather than a pass -- the
trap this workspace has walked into more than once is a check whose subject
quietly became nothing.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
UPSTREAM = ROOT / "crates" / "wz-replay" / "src"
ABI = ROOT / "crates" / "wz-capi-replay" / "src" / "lib.rs"
HEADER = ROOT / "crates" / "wz-capi-replay" / "include" / "wz_replay.h"

# `pub mod NAME;`, and whether the line above it gates the module on `live`.
MOD = re.compile(r"^\s*pub mod\s+([a-z_][a-z0-9_]*)\s*;", re.M)
LIVE_GATE = re.compile(r'#\s*\[\s*cfg\s*\(\s*feature\s*=\s*"live"\s*\)\s*\]')
PUB_ENUM = re.compile(r"^pub enum\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", re.M)
# A variant opens a line inside the block: a bare name, or one carrying a
# payload. Doc comments, attributes and closing braces do not match.
VARIANT = re.compile(r"^\s{4}([A-Z][A-Za-z0-9_]*)\s*(?:\{|\(|,|$)", re.M)
MIRRORS = re.compile(
    r"WZ-ABI-MIRRORS:\s*([A-Za-z_][A-Za-z0-9_]*)\s*->\s*(WZ_REPLAY_[A-Z0-9_]*)"
)
PUB_CONST = re.compile(r"^pub const\s+(WZ_REPLAY_[A-Z0-9_]+)\s*:", re.M)
DEFINE = re.compile(r"^#define\s+(WZ_REPLAY_[A-Z0-9_]+)\b", re.M)
# The include guard is a `#define` that answers an `#ifndef` of the same name,
# and it is recognised by that PAIRING rather than by its spelling: a gate
# holding a literal `WZ_REPLAY_H` would stop recognising the guard the moment
# the header was renamed, and would then demand a `pub const` for it.
INCLUDE_GUARD = re.compile(
    r"^#\s*ifndef\s+(WZ_REPLAY_[A-Z0-9_]+)\s*\n#\s*define\s+\1\b", re.M
)
# `int32_t wz_replay_thing(` / `size_t wz_replay_thing(` -- the exported doors.
FUNCTION = re.compile(r"^[A-Za-z_][A-Za-z0-9_ *]*\b(wz_replay_[a-z0-9_]+)\s*\(", re.M)


def screaming(variant: str) -> str:
    """`Mutation::FlipBit` -> the FLIP_BIT tail of `WZ_REPLAY_MUTATION_FLIP_BIT`.

    R2446 — the tail is written WITHOUT backticks on purpose. This returns it
    alone and the caller prepends the family prefix, so the bare word is not a
    name in this tree: only the prefixed constant is. `prose_named_identifier_gate`
    resolves a backticked span as itself or as the HEAD of a longer identifier,
    and a tail satisfies neither -- so backticking it sent a reader looking for
    a constant that does not exist. That is the gate's whole subject, and R2441
    tripped it on this very line.
    """
    return re.sub(r"(?<!^)(?=[A-Z])", "_", variant).upper()


def plan_half_sources() -> list[pathlib.Path]:
    """`lib.rs` plus every module it declares that `live` does not gate.

    Derived rather than listed so a module added later is in the population
    without anyone remembering to add it, which is the failure mode a list has.
    """
    lib = UPSTREAM / "lib.rs"
    text = lib.read_text(encoding="utf-8")
    files = [lib]
    for match in MOD.finditer(text):
        # Look back over the attributes and doc comments immediately above the
        # declaration: `#[cfg(feature = "live")]` there is what puts a module
        # in the half this ABI does not link.
        head = text[: match.start()]
        preceding = head.rsplit("\n\n", 1)[-1]
        if LIVE_GATE.search(preceding):
            continue
        candidate = UPSTREAM / f"{match.group(1)}.rs"
        if candidate.exists():
            files.append(candidate)
    return files


def enums_of(path: pathlib.Path) -> dict[str, list[str]]:
    """Every `pub enum` in one file, with its variants in declaration order."""
    text = path.read_text(encoding="utf-8")
    found: dict[str, list[str]] = {}
    for match in PUB_ENUM.finditer(text):
        body_start = match.end()
        depth = 1
        at = body_start
        while at < len(text) and depth:
            if text[at] == "{":
                depth += 1
            elif text[at] == "}":
                depth -= 1
            at += 1
        variants = VARIANT.findall(text[body_start:at])
        found[match.group(1)] = variants
    return found


def main() -> int:
    problems: list[str] = []

    sources = plan_half_sources()
    upstream: dict[str, list[str]] = {}
    for path in sources:
        for name, variants in enums_of(path).items():
            upstream[name] = variants

    # P1 -- the population, and an empty one is a FAILURE. A gate whose subject
    # became nothing reports green forever otherwise, which is the trap this
    # workspace keeps meeting.
    pairs = sum(len(v) for v in upstream.values())
    if not upstream or not pairs:
        problems.append(
            "derived NO enum variants from wz-replay's plan half "
            f"({len(sources)} source file(s) read). This gate's subject is gone "
            "-- either the crate moved or the shapes this reads changed. A "
            "population of zero is a failure, never a pass."
        )

    header = HEADER.read_text(encoding="utf-8")
    abi = ABI.read_text(encoding="utf-8")
    mirrors = dict(MIRRORS.findall(header))
    defines = set(DEFINE.findall(header)) - set(INCLUDE_GUARD.findall(header))
    consts = set(PUB_CONST.findall(abi))
    functions = set(FUNCTION.findall(header))

    for enum, variants in sorted(upstream.items()):
        prefix = mirrors.get(enum)
        if prefix is None:
            problems.append(
                f"wz-replay's plan half declares `pub enum {enum}` and "
                f"{HEADER.name} carries no `WZ-ABI-MIRRORS: {enum} -> ...` "
                "line. Every plan-half enum is mirrored by this ABI; if this "
                "one genuinely must not be, that is a decision to write down "
                "in capi_replay_vocabulary.py rather than a line to leave out."
            )
            continue
        if not variants:
            problems.append(
                f"`pub enum {enum}` parsed with NO variants -- this gate can no "
                "longer read it, so it is not grading it."
            )
        for variant in variants:
            want = f"{prefix}{screaming(variant)}"
            if want not in defines:
                problems.append(
                    f"{enum}::{variant} has no `#define {want}` in "
                    f"{HEADER.name}. A C consumer will receive that value and "
                    "its header does not name it."
                )
            if want not in consts:
                problems.append(
                    f"{enum}::{variant} has no `pub const {want}` in "
                    f"{ABI.name}."
                )

    # P2 -- the two constant sets are equal, in both directions.
    if not consts:
        problems.append(
            f"derived NO `pub const WZ_REPLAY_*` from {ABI}. Population of "
            "zero is a failure."
        )
    if not defines:
        problems.append(
            f"derived NO `#define WZ_REPLAY_*` from {HEADER}. Population of "
            "zero is a failure."
        )
    for name in sorted(consts - defines):
        if name.lower() in functions:
            # Answered by the artifact rather than by the header, which is what
            # that function is for -- a revision baked into a header is a
            # revision that can disagree with the library shipping beside it.
            continue
        problems.append(
            f"{ABI.name} exports `{name}` and {HEADER.name} does not define "
            "it. The header is what a linking product reads, and it is the "
            "only one of the two that ships."
        )
    for name in sorted(defines - consts):
        problems.append(
            f"{HEADER.name} defines `{name}` and {ABI.name} has no such "
            "`pub const`. A header constant with nothing behind it is one a "
            "consumer can compile against and never receive."
        )

    if problems:
        print("capi-replay-vocabulary: FAIL")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print(
        f"capi-replay-vocabulary: OK -- {len(upstream)} plan-half enum(s), "
        f"{pairs} variant(s), {len(consts)} constant(s), mirrored in "
        f"{ABI.name} and {HEADER.name}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
