#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y911 (no register item) -- the dissect LABEL VALUE census.

The register item this answers for is UNREGISTERED item 407, which is not a
`§`-numbered store item and so cannot be cited in the form this lint's own
provenance rule accepts. Named here rather than left out.

## What was missing

`dissect_name_census.py` decides the field NAMES a walker may invent. Nothing
decided the VALUES a `FieldValue::Label` carries. `"Drop"` / `"Block"` /
`"BlockFirst"` and `"BestMatching"` / `"All"` / `"AllComplete"` were literals
typed by hand in the round that added them and confirmed by a test written in
the same round from the same reading -- which is not an adjudicator, it is the
same author twice.

One label already had one: `crate::qos::Priority::name()` is held against
`vendor/zenoh-pico`'s eight-band constants by `qos.rs`'s own test. So the shape
was proven and applied to exactly one of the labels.

## Why zenoh-pico and not the Rust upstream

The Rust reference is a machine-local checkout: `CLAUDE.md` forbids recording
its path here, and a gate that reads a path some clones lack would have to
SKIP -- which this workspace's own rule calls reporting green over an unread
input. `vendor/zenoh-pico` is IN-REPO for every clone, and it spells both value
sets in `include/zenoh-pico/api/constants.h` as numbered enum members. That
makes it an adjudicator every clone can run.

What pico cannot adjudicate is named rather than skipped: it has TWO congestion
states and the wire has three, so `BlockFirst` is declared with its reason and
with the test that pins the divergence.

## The three invariants

    1. every `label(..)` SITE's value expression is decided here     -- a new
       label cannot arrive undecided, which is the half that matters
    2. every LITERAL a decided walker can emit is a pico member, or is
       declared with a reason
    3. no declared exception is STALE -- a value pico has come to spell must
       lose its excuse

## What it does NOT check

Placement: that `congestion` is emitted for the carriers whose type defines it
is `dissect.rs`'s own tests' business (R311y911 narrowed exactly that for the
transport carriers). This census is about VOCABULARY, which is the same
boundary `dissect_name_census.py` draws one level up.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DISSECT = ROOT / "crates" / "wz-session-core" / "src" / "dissect.rs"
PICO_CONSTANTS = ROOT / "vendor" / "zenoh-pico" / "include" / "zenoh-pico" / "api" / "constants.h"

# ── What decides each label site's value ─────────────────────────────────────
#
# Keyed on the VALUE EXPRESSION exactly as it is written at the `label(` call,
# because that is what a reader of the call site sees. A site whose expression
# is not a key here is a FAIL: the point of the table is that adding a label
# forces a decision about where its value comes from.
DECIDED_BY_FUNCTION = {
    # The ONE label that already had an adjudicator, and the pattern the rest
    # of this file generalises: `qos.rs`'s test holds the eight names against
    # pico's `Z_PRIORITY_*` constants.
    # BOTH spellings of the same call, listed rather than normalised: the table
    # is keyed on what a reader sees at the site, and collapsing the two would
    # hide that this workspace writes it two ways.
    "priority.name()": "crate::qos::Priority::name(), pinned to pico's Z_PRIORITY_* by qos.rs",
    "crate::qos::Priority::from_wire(priority as u8).name()": (
        "the same Priority::name(), spelled in full where no local binding exists"
    ),
    # The ext-name vocabulary, decided one level up by the field-name census.
    "name": "crate::ext_name::ext_name(), decided by dissect_name_census.py",
    # R2272 (paying R2270's hosted red) — the two `sn_res` resolutions.
    #
    # BOTH spellings of the call are listed rather than normalised, on the rule
    # the priority rows above already state: the table is keyed on what a reader
    # sees at the site, and collapsing them would hide that the byte is read
    # twice at two different shifts.
    #
    # WHAT PINS IT, measured rather than asserted. The four words are upstream's
    # (zenoh-protocol, core/resolution.rs, Bits::S8..S64) and that file is in the
    # cargo registry, which is machine-local -- a gate reading it would SKIP on
    # every clone that has none, the exact trap the ext_target row above refuses.
    # But this tree ALREADY feeds two of the four to a genuine zenohd as config
    # values: NON_DEFAULT_RESOLUTION = "16bit" and DEFAULT_RESOLUTION = "32bit"
    # in crates/wz-integration-tests/tests/wz_negotiated_axes_zenohd_interop.rs.
    # A rename upstream would make the router reject that config and the lane go
    # red, so those two spellings are pinned ON THE WIRE by a real router.
    #
    # RESIDUE, stated rather than hidden: that is TWO of four -- "8bit" and
    # "64bit" are exercised nowhere -- and the tie between those constants and
    # this function is prose here, not a predicate. Open-debt item 611.
    "sn_res_word(sn_res)": (
        "crate::dissect::sn_res_word, upstream's Bits::S8..S64 vocabulary; "
        '"16bit" and "32bit" are pinned on the wire by a genuine zenohd in '
        "wz_negotiated_axes_zenohd_interop.rs, the other two by nothing (item 611)"
    ),
    "sn_res_word(sn_res >> 2)": (
        "the same sn_res_word at the request-ID shift, same pin and same residue"
    ),
}

# Walkers whose label value is a LITERAL chosen inside the function, with the
# pico enum whose members must spell those literals.
DECIDED_BY_PICO = {
    "congestion": {
        "walker": "read_qos_z64",
        "prefix": "Z_CONGESTION_CONTROL_",
        # Values the wire carries that pico does not name, each with why.
        "extra": {
            "BlockFirst": (
                "upstream's third congestion state (QoSType::F_FLAG alone); pico "
                "has two, and the divergence is pinned by "
                "a_qos_byte_that_blocks_only_the_first_is_read_as_neither_drop_nor_block"
            ),
        },
    },
    "target": {
        "walker": "read_target_z64",
        "prefix": "Z_QUERY_TARGET_",
        "extra": {},
    },
}


def label_sites(src: str) -> list[str]:
    """The value expression of every `label(` call, as written.

    A depth-aware split rather than a comma regex: `priority.name()` carries
    parentheses of its own, and a lazy `[^)]+` stops inside it -- which would
    silently report a DIFFERENT expression than the one at the call site and
    make invariant 1 pass on a name nobody wrote.
    """
    out: list[str] = []
    for m in re.finditer(r"\blabel\(", src):
        # `fn label(` is the DEFINITION, whose third parameter is a type and not
        # a value. Measured: without this the census reported
        # `value: &'static str` as an undecided label value, which is a finding
        # about the regex rather than about the code.
        if src[max(0, m.start() - 3) : m.start()] == "fn ":
            continue
        i = m.end()
        depth = 1
        args: list[str] = []
        cur = ""
        while i < len(src) and depth > 0:
            c = src[i]
            if c in "([":
                depth += 1
            elif c in ")]":
                depth -= 1
                if depth == 0:
                    break
            if c == "," and depth == 1:
                args.append(cur.strip())
                cur = ""
            else:
                cur += c
            i += 1
        args.append(cur.strip())
        if len(args) >= 3:
            out.append(args[2])
    return out


def function_literals(src: str, name: str) -> set[str] | None:
    """Every CamelCase string literal inside `fn name(..)`.

    `None` when the function is absent, which is a FAIL rather than an empty
    set: a table entry naming a walker this file no longer has is the stale
    shape invariant 3 exists for, one level up.
    """
    m = re.search(r"\nfn " + re.escape(name) + r"\(", src)
    if m is None:
        return None
    # The body ends at the first line that is a lone `}` in column 0.
    end = src.find("\n}\n", m.end())
    body = src[m.end() : end if end != -1 else len(src)]
    return set(re.findall(r'"([A-Z][A-Za-z0-9]*)"', body))


def pico_members(header: str, prefix: str) -> set[str]:
    """The CamelCase spelling of every NUMBERED member of one pico enum.

    Numbered only, on purpose: pico's `*_DEFAULT` members are assigned another
    member rather than a literal, so they are aliases and not values. Counting
    one would demand a `Default` label no wire byte produces.
    """
    out: set[str] = set()
    for m in re.finditer(
        r"^\s*" + re.escape(prefix) + r"([A-Z0-9_]+)\s*=\s*\d+\s*,?\s*$",
        header,
        re.M,
    ):
        out.add("".join(part.capitalize() for part in m.group(1).split("_")))
    return out


def main() -> int:
    src = DISSECT.read_text(encoding="utf-8")
    header = PICO_CONSTANTS.read_text(encoding="utf-8")
    failures: list[str] = []

    # Invariant 1 — every label site's value expression is decided.
    decided = set(DECIDED_BY_FUNCTION)
    literal_walkers = {v["walker"] for v in DECIDED_BY_PICO.values()}
    sites = label_sites(src)
    if not sites:
        failures.append("no `label(` site found at all -- this census read nothing")
    for expr in sorted(set(sites)):
        if expr in decided:
            continue
        # A bare identifier bound inside one of the literal walkers.
        if re.fullmatch(r"[a-z_][a-z0-9_]*", expr) and any(
            expr in (function_literals(src, w) or set()) or expr in _bound_names(src, w)
            for w in literal_walkers
        ):
            continue
        failures.append(
            f"the label value `{expr}` is decided nowhere -- add it to "
            "DECIDED_BY_FUNCTION with what pins it, or bind it in a walker "
            "listed in DECIDED_BY_PICO"
        )

    # Invariants 2 and 3 — the literal sets, against pico, both directions.
    checked = 0
    for field, spec in sorted(DECIDED_BY_PICO.items()):
        lits = function_literals(src, spec["walker"])
        if lits is None:
            failures.append(
                f"DECIDED_BY_PICO names walker `{spec['walker']}` for `{field}`, "
                "and this file has no such function -- the table is stale"
            )
            continue
        allowed = pico_members(header, spec["prefix"])
        if not allowed:
            failures.append(
                f"pico's `{spec['prefix']}*` enum yielded NO numbered member, so "
                f"the check on `{field}` would be green over an empty set"
            )
            continue
        for value in sorted(lits - allowed - set(spec["extra"])):
            failures.append(
                f"`{field}` can emit {value!r}, which pico's {spec['prefix']}* does "
                "not spell and which is not declared in `extra` with a reason"
            )
        for value in sorted(set(spec["extra"]) & allowed):
            failures.append(
                f"`{field}`'s {value!r} is declared as having no pico counterpart, "
                "but pico now spells it -- delete the `extra` entry"
            )
        checked += len(lits)

    if failures:
        print("dissect-label-census FAIL:", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(
        f"dissect-label-census: {len(set(sites))} label site(s), "
        f"{len(DECIDED_BY_PICO)} value set(s) adjudicated against vendored "
        f"zenoh-pico, {checked} literal(s) checked, "
        f"{sum(len(v['extra']) for v in DECIDED_BY_PICO.values())} declared "
        "without a pico counterpart"
    )
    return 0


def _bound_names(src: str, walker: str) -> set[str]:
    """The `let` names a walker binds, so a site can name one of them.

    `read_qos_z64` writes `label("congestion", span, congestion)`, so the site's
    expression is an identifier and the literals are one level in. Without this
    the census would demand the literal at the call site, which is the opposite
    of what the code should look like.
    """
    m = re.search(r"\nfn " + re.escape(walker) + r"\(", src)
    if m is None:
        return set()
    end = src.find("\n}\n", m.end())
    body = src[m.end() : end if end != -1 else len(src)]
    return set(re.findall(r"\blet\s+(?:mut\s+)?([a-z_][a-z0-9_]*)", body))


if __name__ == "__main__":
    sys.exit(main())
